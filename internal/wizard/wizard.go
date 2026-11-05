// Package wizard implements `intergate config`: an interactive terminal
// wizard that creates the configuration file and manages subdomains, SSH
// keys and users on the running server through its admin socket.
package wizard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/jgermade/intergate/internal/admin"
	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/names"
	appsettings "github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
)

// Wizard runs the interactive configuration.
type Wizard struct {
	// Path is the configuration file.
	Path string
	// Accessible uses plain line prompts instead of full-screen forms.
	Accessible bool
	In         io.Reader
	Out        io.Writer

	ctx context.Context
}

// Run starts the wizard: the initial setup if there is no configuration
// yet, the main menu otherwise.
func (w *Wizard) Run(ctx context.Context) error {
	w.ctx = ctx
	if w.Out == nil {
		w.Out = os.Stdout
	}
	if w.In == nil && w.Accessible {
		// Each accessible prompt reads through a new buffered scanner, so
		// hand out one line at a time (piped answers would be lost) and
		// notice when input ends (Ctrl-D, or the end of piped answers).
		in := &lineInput{r: os.Stdin}
		w.In = in
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			w.In = ttyInput{in, os.Stdin}
		}
	}
	if _, err := os.Stat(w.Path); errors.Is(err, os.ErrNotExist) {
		w.printf("No configuration at %s yet: let's create one.\n\n", w.Path)
		return w.setup(nil)
	} else if err != nil {
		return err
	}
	return w.menu()
}

func (w *Wizard) printf(format string, args ...any) { fmt.Fprintf(w.Out, format, args...) }

func (w *Wizard) form(groups ...*huh.Group) error {
	f := huh.NewForm(groups...).WithAccessible(w.Accessible).WithOutput(w.Out)
	if !w.Accessible {
		f = f.WithTheme(huh.ThemeCharm())
	}
	if w.In != nil {
		f = f.WithInput(w.In)
	}
	err := f.RunWithContext(w.ctx)
	// Without input, accessible prompts silently take their defaults.
	if in, ok := w.In.(interface{ Ended() bool }); ok && in.Ended() {
		return errInputEnded
	}
	return err
}

func aborted(err error) bool {
	return errors.Is(err, huh.ErrUserAborted) || errors.Is(err, errInputEnded)
}

// errInputEnded means the answers ran out.
var errInputEnded = errors.New("input ended")

// lineInput returns at most one line per Read and remembers when its
// input ended.
type lineInput struct {
	r     io.Reader
	ended bool
}

func (l *lineInput) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if _, err := l.r.Read(p[n : n+1]); err != nil {
			if n > 0 {
				return n, nil
			}
			l.ended = true
			return 0, err
		}
		n++
		if p[n-1] == '\n' {
			break
		}
	}
	return n, nil
}

// Ended reports whether a prompt found no more input.
func (l *lineInput) Ended() bool { return l.ended }

// ttyInput is a lineInput on a terminal. Its Fd lets huh read secrets
// without echoing them.
type ttyInput struct {
	*lineInput
	f *os.File
}

func (t ttyInput) Fd() uintptr { return t.f.Fd() }

// orCurrent accepts an empty answer when the field already has a value: in
// accessible mode an empty line keeps the current value.
func orCurrent(current *string, validate func(string) error) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" && *current != "" {
			return nil
		}
		return validate(s)
	}
}

// passwordInput hides typed secrets where the terminal allows it.
func (w *Wizard) passwordInput() bool {
	if !w.Accessible {
		return true
	}
	_, tty := w.In.(interface{ Fd() uintptr })
	return tty
}

func (w *Wizard) readDoc() (*doc, error) {
	raw, err := os.ReadFile(w.Path)
	if err != nil {
		return nil, err
	}
	return parseDoc(raw)
}

// setup creates or edits the server settings.
func (w *Wizard) setup(d *doc) error {
	isNew := d == nil
	if isNew {
		d, _ = parseDoc(nil)
	}
	var s settings
	s.load(d)
	if isNew {
		s.TLSMode = tlsACME
		s.Passkeys = true
	}
	if s.DataDir == "" {
		s.DataDir = defaultDataDir(w.Path)
	}

	for {
		if err := w.setupForms(&s); err != nil {
			if aborted(err) {
				w.printf("Nothing was saved.\n")
				return nil
			}
			return err
		}
		s.apply(d)
		raw, err := d.bytes()
		if err != nil {
			return err
		}
		if _, err := config.Parse(raw); err != nil && !strings.Contains(err.Error(), "unset environment variables") {
			w.printf("\n✖ This configuration is not valid: %v\n\n", err)
			again := true
			if err := w.form(huh.NewGroup(huh.NewConfirm().Title("Go back and fix it?").Value(&again))); err != nil || !again {
				w.printf("Nothing was saved.\n")
				return nil
			}
			continue
		} else if err != nil {
			w.printf("\nNote: %v.\nSet them in the environment (or %s) before starting intergate.\n", err, envFileFor(w.Path))
		}
		if err := writeFile(w.Path, raw); err != nil {
			return err
		}
		w.saved(&s, isNew)
		return nil
	}
}

func envFileFor(path string) string {
	return strings.TrimSuffix(path, filepath.Ext(path)) + ".env"
}

func (w *Wizard) setupForms(s *settings) error {
	err := w.form(huh.NewGroup(
		huh.NewInput().
			Title("Public URL of the dashboard").
			Description("Tunnels are served on its subdomains, e.g. https://myapp.gate.example.com.\n"+
				"Point both gate.example.com and *.gate.example.com to this server in DNS.").
			Placeholder("https://gate.example.com").
			Value(&s.PublicURL).
			Validate(orCurrent(&s.PublicURL, validateURL)),
		huh.NewSelect[string]().
			Title("Who handles HTTPS?").
			Options(
				huh.NewOption("intergate, with free Let's Encrypt certificates", tlsACME),
				huh.NewOption("intergate, with my own wildcard certificate", tlsFiles),
				huh.NewOption("A reverse proxy in front of intergate (Traefik, Caddy, nginx…)", tlsProxy),
				huh.NewOption("Nobody: plain HTTP, for local development", tlsNone),
			).
			Value(&s.TLSMode),
	).Title("Domain"))
	if err != nil {
		return err
	}
	s.PublicURL = strings.TrimRight(strings.TrimSpace(s.PublicURL), "/")
	switch {
	case s.TLSMode == tlsNone && strings.HasPrefix(s.PublicURL, "https://"):
		s.PublicURL = "http://" + strings.TrimPrefix(s.PublicURL, "https://")
		w.printf("Using %s, since nothing serves HTTPS.\n", s.PublicURL)
	case s.TLSMode != tlsNone && strings.HasPrefix(s.PublicURL, "http://"):
		s.PublicURL = "https://" + strings.TrimPrefix(s.PublicURL, "http://")
		w.printf("Using %s.\n", s.PublicURL)
	}
	s.fillDefaults()

	tls := s.TLSMode == tlsACME || s.TLSMode == tlsFiles
	// Each form only holds the questions that apply: accessible mode asks
	// every field of a form, hidden or not.
	var groups []*huh.Group
	switch s.TLSMode {
	case tlsACME:
		groups = append(groups, huh.NewGroup(
			huh.NewInput().Title("Email for Let's Encrypt").
				Description("Let's Encrypt writes here if a certificate is about to expire.").
				Value(&s.ACMEEmail).Validate(orCurrent(&s.ACMEEmail, validateEmails(true))),
		))
	case tlsFiles:
		groups = append(groups, huh.NewGroup(
			huh.NewInput().Title("Certificate file (PEM)").
				Description("Must cover the dashboard host and *.host.").
				Value(&s.CertFile).Validate(orCurrent(&s.CertFile, required("the certificate file"))),
			huh.NewInput().Title("Private key file (PEM)").
				Value(&s.KeyFile).Validate(orCurrent(&s.KeyFile, required("the key file"))),
		))
	}
	ports := []huh.Field{
		huh.NewInput().Title("HTTP listen address").
			Description(map[bool]string{true: "Redirects to HTTPS and answers Let's Encrypt challenges.", false: "Where the dashboard and tunnels are served."}[tls]).
			Value(&s.HTTPListen).Validate(orCurrent(&s.HTTPListen, validateListen)),
	}
	if tls {
		ports = append(ports, huh.NewInput().Title("HTTPS listen address").
			Value(&s.HTTPSListen).Validate(orCurrent(&s.HTTPSListen, validateListen)))
	}
	ports = append(ports, huh.NewInput().Title("SSH listen address").
		Description("Users connect here with ssh -R. Port 22 is usually taken by the system's own SSH server.").
		Value(&s.SSHListen).Validate(orCurrent(&s.SSHListen, validateListen)))
	groups = append(groups, huh.NewGroup(ports...).Title("Ports"))
	if err := w.form(groups...); err != nil {
		return err
	}
	if !tls {
		s.HTTPSListen = ""
	}

	err = w.form(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Sign-in codes by email").
			Description("Users sign in with a one-time code sent to their email, then can add a passkey.\n"+
				"The dashboard can ask for the SMTP server, and for the owner, through a one-time link.").
			Options(
				huh.NewOption("Set them up in the dashboard, once intergate runs", emailDashboard),
				huh.NewOption("Send them through an SMTP server", emailSMTP),
				huh.NewOption("Write them to the server log (development only)", emailLog),
				huh.NewOption("Disabled (sign in with OAuth only)", emailOff),
			).
			Value(&s.EmailMode),
		huh.NewConfirm().Title("Allow passkeys?").
			Description("Sign in with a fingerprint, face or device PIN. Recommended.").
			Value(&s.Passkeys),
		huh.NewConfirm().Title("Also allow signing in with GitHub?").
			Description("Optional. Accounts are matched by verified email.").
			Value(&s.GitHub),
	).Title("Sign-in"))
	if err != nil {
		return err
	}
	if s.EmailMode == emailOff && !s.GitHub {
		w.printf("With email codes disabled, GitHub sign-in is needed to create accounts.\n")
		s.GitHub = true
	}
	echo := map[bool]huh.EchoMode{true: huh.EchoModePassword, false: huh.EchoModeNormal}[w.passwordInput()]
	groups = nil
	if s.EmailMode == emailSMTP {
		groups = append(groups, huh.NewGroup(
			huh.NewInput().Title("SMTP server").Placeholder("smtp.example.com").
				Value(&s.SMTPHost).Validate(orCurrent(&s.SMTPHost, required("the SMTP server"))),
			huh.NewInput().Title("SMTP port").Value(&s.SMTPPort).Validate(orCurrent(&s.SMTPPort, validatePort)),
			huh.NewSelect[string]().Title("SMTP encryption").Options(
				huh.NewOption("STARTTLS (usually port 587)", "starttls"),
				huh.NewOption("TLS (usually port 465)", "tls"),
				huh.NewOption("None (local relay only)", "none"),
			).Value(&s.SMTPTLS),
			huh.NewInput().Title("SMTP username").Description("Leave empty if the server needs no login.").Value(&s.SMTPUsername),
			huh.NewInput().Title("SMTP password").
				Description("Stored in the configuration file. You can write ${SMTP_PASSWORD} and set it in the environment instead.").
				EchoMode(echo).Value(&s.SMTPPassword),
			huh.NewInput().Title("Sender").Value(&s.EmailFrom).Validate(orCurrent(&s.EmailFrom, validateFrom)),
		).Title("Email delivery"))
	}
	if s.GitHub {
		groups = append(groups, huh.NewGroup(
			huh.NewNote().Title("GitHub OAuth app").Description(
				"Create one at https://github.com/settings/developers with the callback URL\n"+
					s.PublicURL+"/auth/github/callback"),
			huh.NewInput().Title("Client ID").Value(&s.GitHubID).Validate(orCurrent(&s.GitHubID, required("the client ID"))),
			huh.NewInput().Title("Client secret").EchoMode(echo).
				Value(&s.GitHubSecret).Validate(orCurrent(&s.GitHubSecret, required("the client secret"))),
		))
	}
	// Without administrators, the dashboard's setup asks for the owner.
	adminsHelp := "Emails, separated by commas. They can always sign in and see every subdomain."
	if s.EmailMode == emailDashboard {
		adminsHelp += "\nOptional: the dashboard's setup asks for the owner."
	}
	groups = append(groups,
		huh.NewGroup(
			huh.NewInput().Title("Administrators").
				Description(adminsHelp).
				Value(&s.Admins).Validate(orCurrent(&s.Admins, validateEmails(s.EmailMode != emailDashboard))),
			huh.NewInput().Title("Allowed email domains").
				Description("Anyone with a verified email on these domains can sign in, e.g. example.com. Optional.").
				Value(&s.AllowedDomains),
			huh.NewInput().Title("Other allowed emails").Description("Optional, separated by commas.").
				Value(&s.AllowedEmails).Validate(validateEmails(false)),
			huh.NewConfirm().Title("Let anyone with a verified email sign in?").
				Description("Only for a public service: everyone can register subdomains.").
				Value(&s.AllowEveryone),
		).Title("Who can sign in"),
		huh.NewGroup(
			huh.NewInput().Title("Data directory").
				Description("Database, SSH host key and certificates. Relative paths are relative to the configuration file.").
				Value(&s.DataDir).Validate(orCurrent(&s.DataDir, required("the data directory"))),
		).Title("Storage"),
	)
	return w.form(groups...)
}

func validatePort(s string) error {
	return validateListen(":" + strings.TrimSpace(s))
}

func validateFrom(s string) error {
	if _, err := mail.ParseAddress(strings.TrimSpace(s)); err != nil {
		return fmt.Errorf("enter an address like intergate <no-reply@example.com>")
	}
	return nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (w *Wizard) saved(s *settings, isNew bool) {
	w.printf("\n✔ Saved %s\n", w.Path)
	if !isNew {
		if _, err := w.client().Status(w.ctx); err == nil {
			w.printf("Restart intergate to apply the changes (sudo systemctl restart intergate, or intergate stop && intergate start --detached).\n")
		}
		return
	}
	host := s.PublicURL
	if u, err := url.Parse(s.PublicURL); err == nil {
		host = u.Hostname()
	}
	w.printf("\nNext steps:\n")
	if s.TLSMode != tlsNone {
		w.printf("  1. In DNS, point %s and *.%s to this server.\n", host, host)
		if s.TLSMode == tlsACME {
			w.printf("     intergate gets a certificate for each subdomain. For one wildcard certificate instead,\n" +
				"     set up your DNS provider (Cloudflare, Google Cloud DNS, Route 53…) in the dashboard: Admin → DNS.\n")
		}
	} else {
		w.printf("  1. Browsers resolve *.localhost on their own; for other names, point %s and *.%s to this machine.\n", host, host)
	}
	w.printf("  2. Start intergate:\n" +
		"       intergate start                     in the foreground\n" +
		"       intergate start --detached          in the background\n" +
		"       sudo intergate service --install    as a system service (Linux)\n")
	if admins := splitList(s.Admins); s.EmailMode == emailDashboard || len(admins) == 0 {
		w.printf("  3. Finish the setup in the dashboard: open the one-time link intergate writes to its log\n" +
			"     when it starts, or get a new one with `intergate setup-url`.\n")
	} else {
		w.printf("  3. Sign in at %s as %s.\n", s.PublicURL, admins[0])
	}
	w.printf("Run `intergate config` again to manage subdomains, SSH keys and users.\n")
}

func (w *Wizard) client() *admin.Client {
	d, err := w.readDoc()
	if err != nil {
		return admin.NewClient("")
	}
	return admin.NewClient(socketPath(w.Path, d))
}

// socketPath finds the admin socket from the raw configuration, so the
// wizard works even when secrets referenced as ${VAR} are not set here.
func socketPath(cfgPath string, d *doc) string {
	base := filepath.Dir(cfgPath)
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	if s := d.str("admin", "socket"); s != "" {
		return abs(s)
	}
	dir := d.str("data_dir")
	if dir == "" {
		dir = "./data"
	}
	return filepath.Join(abs(dir), "admin.sock")
}

func (w *Wizard) menu() error {
	for {
		d, err := w.readDoc()
		if err != nil {
			return err
		}
		c := admin.NewClient(socketPath(w.Path, d))
		status := "intergate is not running: start it to manage subdomains and users."
		options := []huh.Option[string]{
			huh.NewOption("Subdomains and SSH keys", "subdomains"),
			huh.NewOption("Users", "users"),
			huh.NewOption("Server settings", "settings"),
		}
		if st, err := c.Status(w.ctx); err == nil {
			status = fmt.Sprintf("Running %s · %d subdomains, %d online · %d users", st.DashboardURL, st.Subdomains, st.TunnelsOnline, st.Users)
			// What the dashboard set up, or has yet to.
			if st.Setup {
				status += " · not set up yet"
				options = append(options, huh.NewOption("Link to the dashboard's setup", "setup"))
			}
			if e, err := c.Email(w.ctx); err == nil && e.Source == appsettings.SourceDashboard {
				options = append(options, huh.NewOption("Email delivery (the SMTP password)", "email"))
			}
		} else if !errors.Is(err, admin.ErrNotRunning) {
			status = "Can't reach the server: " + err.Error()
		}
		w.note(status)
		var choice string
		err = w.form(huh.NewGroup(huh.NewSelect[string]().
			Title("intergate — " + w.Path).
			Description(status).
			Options(append(options, huh.NewOption("Exit", "exit"))...).
			Value(&choice)))
		if aborted(err) || choice == "exit" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "subdomains":
			err = w.subdomains(c, d)
		case "users":
			err = w.users(c)
		case "settings":
			err = w.setup(d)
		case "setup":
			err = w.setupLink(c)
		case "email":
			err = w.email(c)
		}
		if err != nil && !aborted(err) {
			w.problem(err)
		}
	}
}

// note prints a select's description in accessible mode, which only
// shows titles.
func (w *Wizard) note(s string) {
	if w.Accessible {
		w.printf("%s\n", s)
	}
}

func (w *Wizard) problem(err error) {
	w.printf("\n✖ %v\n\n", err)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func (w *Wizard) subdomains(c *admin.Client, d *doc) error {
	for {
		list, err := c.Subdomains(w.ctx)
		if err != nil {
			return err
		}
		online := 0
		opts := make([]huh.Option[string], 0, len(list)+2)
		for _, sd := range list {
			state := "○ offline"
			if sd.Tunnel != nil {
				state = "● online "
				online++
			}
			opts = append(opts, huh.NewOption(fmt.Sprintf("%-24s %s  %-8s %s", sd.Name, state, sd.Access, sd.Owner), sd.Name))
		}
		opts = append(opts, huh.NewOption("+ Register a subdomain", "+new"), huh.NewOption("← Back", "+back"))
		pick := "+new"
		if len(list) > 0 {
			pick = list[0].Name
		}
		w.note(fmt.Sprintf("%d registered, %d online", len(list), online))
		err = w.form(huh.NewGroup(huh.NewSelect[string]().
			Title("Subdomains").
			Description(fmt.Sprintf("%d registered, %d online", len(list), online)).
			Options(opts...).Value(&pick)))
		if err != nil || pick == "+back" {
			return err
		}
		if pick == "+new" {
			err = w.createSubdomain(c, d)
		} else {
			err = w.subdomain(c, pick)
		}
		if err != nil && !aborted(err) {
			w.problem(err)
		}
	}
}

func accessOptions() []huh.Option[store.Access] {
	return []huh.Option[store.Access]{
		huh.NewOption("Public: anyone with the URL", store.AccessPublic),
		huh.NewOption("Signed-in users: anyone who can sign in to this intergate", store.AccessUsers),
		huh.NewOption("Private: only the owner, after signing in", store.AccessPrivate),
	}
}

func (w *Wizard) createSubdomain(c *admin.Client, d *doc) error {
	checker := names.NewChecker(d.list("reserved_subdomains"))
	var name, keys string
	owner := ""
	if admins := d.list("auth", "admins"); len(admins) > 0 {
		owner = admins[0]
	}
	access := store.AccessPublic
	err := w.form(huh.NewGroup(
		huh.NewInput().Title("Subdomain").Description("Lowercase letters, digits and hyphens.").
			Validate(func(s string) error { return checker.Check(names.Normalize(s)) }).
			Value(&name),
		huh.NewInput().Title("Owner's email").Description("The account is created if it doesn't exist.").
			Value(&owner).Validate(orCurrent(&owner, validateEmails(true))),
		huh.NewSelect[store.Access]().Title("Who can open it").Options(accessOptions()...).Value(&access),
		huh.NewText().Title("SSH public keys").
			Description("Optional. One per line: the contents of ~/.ssh/id_ed25519.pub or https://github.com/<user>.keys").
			Value(&keys),
	).Title("Register a subdomain"))
	if err != nil {
		return err
	}
	sd, res, err := c.CreateSubdomain(w.ctx, admin.CreateSubdomainRequest{Name: name, Owner: owner, Access: access, Keys: keys})
	if err != nil {
		return err
	}
	w.printf("\n✔ Registered %s for %s with %d SSH key(s).\n", sd.URL, sd.Owner, res.Added)
	for _, p := range res.Problems {
		w.printf("  ! %s\n", p)
	}
	w.sshHint(c, sd.Name)
	return nil
}

func (w *Wizard) sshHint(c *admin.Client, name string) {
	st, err := c.Status(w.ctx)
	if err != nil {
		return
	}
	host, port, _ := strings.Cut(st.SSH, ":")
	cmd := "ssh"
	if port != "22" {
		cmd += " -p " + port
	}
	w.printf("  Connect with: %s -R %s:80:localhost:3000 %s\n\n", cmd, name, host)
}

func (w *Wizard) subdomain(c *admin.Client, name string) error {
	for {
		sd, err := c.Subdomain(w.ctx, name)
		if err != nil {
			return err
		}
		w.printf("\n%s  (%s)\n  owner: %s · access: %s\n", sd.Name, sd.URL, sd.Owner, sd.Access)
		if t := sd.Tunnel; t != nil {
			w.printf("  ● online since %s from %s with key %q · %d requests\n", ago(t.CreatedAt), t.ClientAddr, t.KeyName, t.Requests)
		} else {
			w.printf("  ○ offline\n")
		}
		if len(sd.KeyList) == 0 {
			w.printf("  No SSH keys: nobody can connect.\n")
		}
		for _, k := range sd.KeyList {
			w.printf("  • %-20s %-12s %s  last used %s\n", k.Name, k.Type, k.Fingerprint, ago(k.LastUsedAt))
		}
		w.printf("\n")

		opts := []huh.Option[string]{
			huh.NewOption("Add SSH keys", "addkeys"),
			huh.NewOption("Change who can open it", "access"),
		}
		if len(sd.KeyList) > 0 {
			opts = append(opts, huh.NewOption("Remove an SSH key", "rmkey"))
		}
		if sd.Tunnel != nil {
			opts = append(opts, huh.NewOption("Disconnect the tunnel", "disconnect"))
		}
		opts = append(opts,
			huh.NewOption("Show the ssh command", "cmd"),
			huh.NewOption("Delete this subdomain", "delete"),
			huh.NewOption("← Back", "back"))
		action := "addkeys"
		if err := w.form(huh.NewGroup(huh.NewSelect[string]().Title(sd.Name).Options(opts...).Value(&action))); err != nil || action == "back" {
			return err
		}
		switch action {
		case "addkeys":
			err = w.addKeys(c, sd)
		case "access":
			access := sd.Access
			if err = w.form(huh.NewGroup(huh.NewSelect[store.Access]().Title("Who can open " + sd.Name).Options(accessOptions()...).Value(&access))); err == nil {
				if err = c.SetAccess(w.ctx, sd.Name, access); err == nil {
					w.printf("✔ Access set to %s.\n", access)
				}
			}
		case "rmkey":
			err = w.removeKey(c, sd)
		case "disconnect":
			var done bool
			if done, err = c.Disconnect(w.ctx, sd.Name); err == nil && done {
				w.printf("✔ Disconnected.\n")
			}
		case "cmd":
			w.sshHint(c, sd.Name)
		case "delete":
			var confirm string
			err = w.form(huh.NewGroup(huh.NewInput().
				Title("Type " + sd.Name + " to delete it").
				Description("This closes the tunnel and removes the subdomain and its keys.").
				Value(&confirm)))
			if err == nil {
				if strings.TrimSpace(confirm) != sd.Name {
					w.printf("Not deleted.\n")
					continue
				}
				if err = c.DeleteSubdomain(w.ctx, sd.Name); err == nil {
					w.printf("✔ Deleted %s.\n", sd.Name)
					return nil
				}
			}
		}
		if err != nil && !aborted(err) {
			w.problem(err)
		}
	}
}

func (w *Wizard) addKeys(c *admin.Client, sd *admin.SubdomainDetail) error {
	var keys, name string
	err := w.form(huh.NewGroup(
		huh.NewText().Title("SSH public keys").
			Description("One per line: the contents of ~/.ssh/id_ed25519.pub or https://github.com/<user>.keys").
			Validate(required("a key")).Value(&keys),
		huh.NewInput().Title("Name").Description("Optional, for a single key. Defaults to the key comment.").Value(&name),
	).Title("Add SSH keys to " + sd.Name))
	if err != nil {
		return err
	}
	res, err := c.AddKeys(w.ctx, sd.Name, admin.KeysRequest{Keys: keys, Name: name})
	if err != nil {
		return err
	}
	w.printf("✔ Added %d key(s).\n", res.Added)
	for _, p := range res.Problems {
		w.printf("  ! %s\n", p)
	}
	return nil
}

func (w *Wizard) removeKey(c *admin.Client, sd *admin.SubdomainDetail) error {
	opts := make([]huh.Option[int64], 0, len(sd.KeyList)+1)
	for _, k := range sd.KeyList {
		opts = append(opts, huh.NewOption(fmt.Sprintf("%s  %s", k.Name, k.Fingerprint), k.ID))
	}
	opts = append(opts, huh.NewOption("← Cancel", int64(0)))
	id := sd.KeyList[0].ID
	if err := w.form(huh.NewGroup(huh.NewSelect[int64]().Title("Remove which key?").
		Description("A tunnel open with it is closed at once.").Options(opts...).Value(&id))); err != nil || id == 0 {
		return err
	}
	if err := c.RemoveKey(w.ctx, sd.Name, id); err != nil {
		return err
	}
	w.printf("✔ Key removed.\n")
	return nil
}

func (w *Wizard) users(c *admin.Client) error {
	for {
		list, err := c.Users(w.ctx)
		if err != nil {
			return err
		}
		opts := make([]huh.Option[int64], 0, len(list)+2)
		for _, u := range list {
			var tags []string
			if u.Admin {
				tags = append(tags, "admin")
			}
			if u.Disabled {
				tags = append(tags, "disabled")
			} else if !u.Allowed {
				tags = append(tags, "not allowed by config")
			}
			label := fmt.Sprintf("%-32s %d subdomains · last sign-in %s", u.Email, u.Subdomains, ago(u.LastLoginAt))
			if len(tags) > 0 {
				label += " · " + strings.Join(tags, ", ")
			}
			opts = append(opts, huh.NewOption(label, u.ID))
		}
		const addUser, back = int64(-1), int64(-2)
		opts = append(opts, huh.NewOption("+ Add a user", addUser), huh.NewOption("← Back", back))
		pick := addUser
		if len(list) > 0 {
			pick = list[0].ID
		}
		err = w.form(huh.NewGroup(huh.NewSelect[int64]().Title("Users").
			Description(fmt.Sprintf("%d accounts", len(list))).Options(opts...).Value(&pick)))
		if err != nil || pick == back {
			return err
		}
		if pick == addUser {
			var email string
			if err = w.form(huh.NewGroup(huh.NewInput().Title("Email").
				Description("They sign in with this address (email code, passkey or an OAuth account with the same email).").
				Validate(validateEmails(true)).Value(&email))); err == nil {
				var u *admin.User
				if u, err = c.CreateUser(w.ctx, strings.TrimSpace(email)); err == nil {
					w.printf("✔ Added %s.\n", u.Email)
					if !u.Allowed {
						w.printf("  ! The configuration doesn't allow this address to sign in yet: add it (or its domain) in Server settings.\n")
					}
				}
			}
		} else {
			for _, u := range list {
				if u.ID == pick {
					err = w.user(c, u)
				}
			}
		}
		if err != nil && !aborted(err) {
			w.problem(err)
		}
	}
}

func (w *Wizard) user(c *admin.Client, u admin.User) error {
	verb := "Disable"
	if u.Disabled {
		verb = "Enable"
	}
	ok := false
	err := w.form(huh.NewGroup(huh.NewConfirm().
		Title(fmt.Sprintf("%s %s?", verb, u.Email)).
		Description(map[bool]string{
			false: "They are signed out and their tunnels are closed.",
			true:  "They can sign in again.",
		}[u.Disabled]).Value(&ok)))
	if err != nil || !ok {
		return err
	}
	if err := c.SetUserDisabled(w.ctx, u.ID, !u.Disabled); err != nil {
		return err
	}
	w.printf("✔ %sd %s.\n", verb, u.Email)
	return nil
}
