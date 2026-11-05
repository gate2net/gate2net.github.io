package e2e

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/config"
	appsettings "github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/wizard"
)

// lineReader hands out one line per Read, like a person typing: the
// accessible prompts each wrap the input in a new scanner.
type lineReader struct {
	lines []string
	ended bool
}

func (r *lineReader) Ended() bool { return r.ended }

func (r *lineReader) Read(p []byte) (int, error) {
	if len(r.lines) == 0 {
		r.ended = true
		return 0, io.EOF
	}
	n := copy(p, r.lines[0]+"\n")
	r.lines = r.lines[1:]
	return n, nil
}

func runWizard(t *testing.T, path string, answers ...string) string {
	t.Helper()
	var out bytes.Buffer
	in := &lineReader{lines: answers}
	w := &wizard.Wizard{Path: path, Accessible: true, In: in, Out: &out}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("wizard: %v\n%s", err, out.String())
	}
	if in.ended {
		t.Fatalf("the wizard wanted more answers than given\n%s", out.String())
	}
	if len(in.lines) > 0 {
		t.Fatalf("wizard ended with %d unused answers %q\n%s", len(in.lines), in.lines, out.String())
	}
	return out.String()
}

func TestWizardSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "intergate.yaml")
	out := runWizard(t, path,
		// Domain and HTTPS.
		"https://gate.example.org", "1",
		// Let's Encrypt email, then HTTP, HTTPS and SSH listen addresses.
		"ops@example.org", "", "", "",
		// Email codes over SMTP, passkeys, GitHub too.
		"2", "", "y",
		// SMTP: host, port, encryption, user, password, sender.
		"smtp.example.org", "", "", "mailer", "s3cret", "",
		// GitHub client ID and secret.
		"gh-id", "gh-secret",
		// Admins, allowed domains, other emails, allow everyone.
		"ops@example.org", "example.org", "", "",
		// Data directory.
		"",
	)
	if !strings.Contains(out, "Saved "+path) || !strings.Contains(out, "*.gate.example.org") {
		t.Fatalf("output:\n%s", out)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode: %v %v", fi, err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		raw, _ := os.ReadFile(path)
		t.Fatalf("written config does not load: %v\n%s", err, raw)
	}
	checks := map[string]string{
		cfg.PublicURL:                      "https://gate.example.org",
		cfg.HTTP.Listen:                    ":80",
		cfg.HTTP.TLS.Listen:                ":443",
		cfg.HTTP.TLS.ACME.Email:            "ops@example.org",
		cfg.SSH.Listen:                     ":2222",
		cfg.Auth.Email.SMTP.Host:           "smtp.example.org",
		cfg.Auth.Email.SMTP.TLS:            "starttls",
		cfg.Auth.Email.SMTP.Password:       "s3cret",
		cfg.Auth.Email.From:                "intergate <no-reply@gate.example.org>",
		cfg.Auth.Providers[0].ClientID:     "gh-id",
		cfg.Auth.Providers[0].Type:         "github",
		cfg.Auth.AllowedDomains[0]:         "example.org",
		cfg.DataDir:                        filepath.Join(filepath.Dir(path), "data"),
		strings.Join(cfg.Auth.Admins, ","): "ops@example.org",
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if !cfg.HTTP.TLS.ACME.Enabled || cfg.Auth.Email.SMTP.Port != 587 || !cfg.PasskeysEnabled() {
		t.Errorf("config = %+v", cfg)
	}
}

// TestWizardLeavesSetupToDashboard creates a configuration that leaves
// email delivery and the owner to the dashboard's setup.
func TestWizardLeavesSetupToDashboard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intergate.yaml")
	out := runWizard(t, path,
		"https://gate.example.org", "1",
		"ops@example.org", "", "", "",
		// Email set up in the dashboard (the default), passkeys, no GitHub.
		"", "", "",
		// No admins: the setup asks for the owner.
		"", "", "", "",
		"",
	)
	if !strings.Contains(out, "intergate setup-url") {
		t.Fatalf("output:\n%s", out)
	}
	cfg, err := config.Load(path)
	if err != nil {
		raw, _ := os.ReadFile(path)
		t.Fatalf("written config does not load: %v\n%s", err, raw)
	}
	if cfg.Auth.Email.Enabled() || len(cfg.Auth.Providers) > 0 || !cfg.NobodyAllowed() {
		t.Errorf("auth = %+v", cfg.Auth)
	}
}

// TestWizardEmailPassword moves the SMTP password set up in the dashboard
// to an environment variable, and back.
func TestWizardEmailPassword(t *testing.T) {
	h, checked := newSetupHarness(t)
	ctx := t.Context()
	if err := h.srv.Settings().SaveEmail(ctx, appsettings.Email{Host: "smtp.example.org", Port: 587, TLS: "starttls", Username: "me", From: "intergate <no-reply@gate.test>"}, "s3cret"); err != nil {
		t.Fatal(err)
	}
	h.serveAdminOnce()
	path := filepath.Join(t.TempDir(), "intergate.yaml")
	os.WriteFile(path, h.yaml, 0o600)

	// Not set up yet (no owner): the menu offers a setup link.
	out := runWizard(t, path, "4", "6")
	if !strings.Contains(out, "http://"+domain+"/?setup=") {
		t.Fatalf("setup link:\n%s", out)
	}
	t.Setenv("INTERGATE_TEST_SMTP", "from-env")
	out = runWizard(t, path, "5", "2", "INTERGATE_TEST_SMTP", "6")
	if !strings.Contains(out, "SMTP password: stored in intergate's database") || !strings.Contains(out, "now the environment variable INTERGATE_TEST_SMTP") {
		t.Fatalf("to the environment:\n%s", out)
	}
	if e := h.srv.Settings().Email(); e.PasswordRef != "env:INTERGATE_TEST_SMTP" || e.Sealed != "" {
		t.Errorf("settings = %+v", e)
	}
	if last := (*checked)[len(*checked)-1]; last.Password != "from-env" {
		t.Errorf("checked %+v", last)
	}
	// A password the SMTP server refuses changes nothing.
	out = runWizard(t, path, "5", "1", "wrong", "6")
	if !strings.Contains(out, "refused the password, nothing changed") || h.srv.Settings().Email().PasswordRef == "" {
		t.Fatalf("refused password:\n%s", out)
	}
	runWizard(t, path, "5", "1", "typed", "6")
	if e := h.srv.Settings().Email(); e.PasswordSource() != "stored" {
		t.Errorf("back to stored: %+v", e)
	}
}

func TestWizardManagesRunningServer(t *testing.T) {
	h := newHarness(t)
	h.serveAdmin()
	path := filepath.Join(t.TempDir(), "intergate.yaml")
	os.WriteFile(path, h.yaml, 0o600)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()))) + " wizard-key"

	out := runWizard(t, path,
		"1", // Subdomains
		"1", // + Register a subdomain (the list is empty)
		"wiz", "dev@example.com", "3", key,
		"1", // the new subdomain
		"2", // Change who can open it
		"1", // Public
		"6", // ← Back
		"3", // ← Back
		"4", // Exit
	)
	if !strings.Contains(out, "Registered http://wiz.gate.test for dev@example.com with 1 SSH key(s)") ||
		!strings.Contains(out, "-R wiz:80:localhost:3000") || !strings.Contains(out, "Access set to public") {
		t.Fatalf("output:\n%s", out)
	}
	d, err := h.store.SubdomainByName(t.Context(), "wiz")
	if err != nil || d.OwnerEmail != "dev@example.com" || d.Access != store.AccessPublic || d.Keys != 1 {
		t.Fatalf("subdomain = %+v, %v", d, err)
	}

	// Users: add one, then disable it.
	out = runWizard(t, path,
		"2",                  // Users
		"2",                  // + Add a user (after dev@example.com)
		"newbie@example.com", // email
		"2",                  // newbie
		"2",                  // Disable newbie@example.com
		"y",                  // confirm
		"4",                  // ← Back
		"4",                  // Exit
	)
	u, err := h.store.UserByEmail(t.Context(), "newbie@example.com")
	if err != nil || !u.Disabled {
		t.Fatalf("user = %+v, %v\n%s", u, err, out)
	}
}

// TestWizardAccountKeys adds a key to an account, then to a subdomain and
// to a new one from there, and removes it from the account and with it
// from both.
func TestWizardAccountKeys(t *testing.T) {
	h := newHarness(t)
	h.serveAdmin()
	path := filepath.Join(t.TempDir(), "intergate.yaml")
	os.WriteFile(path, h.yaml, 0o600)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()))) + " laptop"
	ctx := t.Context()

	runWizard(t, path,
		"1", "1", "wiz", "dev@example.com", "1", "", // a subdomain with no keys, and its owner
		"3", "4",
	)
	out := runWizard(t, path,
		"2",     // Users
		"1",     // dev@example.com
		"1",     // Add SSH keys to the account
		key, "", // the key, no name
		"4",      // ← Back (Add, Remove, Disable, Back)
		"3", "4", // ← Back, Exit
	)
	if !strings.Contains(out, "Added 1 key(s) to the account") || !strings.Contains(out, "laptop") || !strings.Contains(out, "on no subdomain") {
		t.Fatalf("add to the account:\n%s", out)
	}

	out = runWizard(t, path,
		"1", "1", // Subdomains, wiz
		"2", // Add a key from dev@example.com's account
		"1", // laptop
		"6", // ← Back (Add, Access, Remove, Command, Delete, Back)
		"3", "4",
	)
	if !strings.Contains(out, "Key added") || !strings.Contains(out, "(account key)") {
		t.Fatalf("add to the subdomain:\n%s", out)
	}
	out = runWizard(t, path,
		"1", "2", "wiz2", "dev@example.com", "1", "", // register another
		"2",      // SSH key from dev@example.com's account: laptop
		"4", "4", // ← Back, Exit
	)
	if !strings.Contains(out, "Registered http://wiz2.gate.test for dev@example.com with 1 SSH key(s)") {
		t.Fatalf("register with it:\n%s", out)
	}
	for _, name := range []string{"wiz", "wiz2"} {
		d, err := h.store.SubdomainByName(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := h.store.KeysBySubdomain(ctx, d.ID)
		if err != nil || len(keys) != 1 || keys[0].UserKeyID == 0 {
			t.Fatalf("%s keys = %+v, %v", name, keys, err)
		}
	}

	out = runWizard(t, path,
		"2", "1", // Users, dev@example.com
		"2", // Remove a key from the account
		"1", // laptop
		"3", // ← Back (Add, Disable, Back)
		"3", "4",
	)
	if !strings.Contains(out, "Key removed, from wiz, wiz2 too") {
		t.Fatalf("remove:\n%s", out)
	}
	for _, name := range []string{"wiz", "wiz2"} {
		if d, err := h.store.SubdomainByName(ctx, name); err != nil || d.Keys != 0 {
			t.Fatalf("%s = %+v, %v", name, d, err)
		}
	}
}

func TestWizardKeepsCommentsAndSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intergate.yaml")
	original := `# Production gate. Ask ops before changing.
public_url: http://localhost:8080
data_dir: ./state
auth:
  admins: [ops@example.com]
  email:
    log_only: true
  providers:
    - id: github
      type: github
      client_id: abc
      client_secret: ${GH_SECRET} # from the vault
`
	os.WriteFile(path, []byte(original), 0o640)
	out := runWizard(t, path,
		"3", // Server settings
		// Keep every answer as it is.
		"", "", // URL, HTTPS
		"", "", // HTTP and SSH listen
		"", "", "", // email mode, passkeys, GitHub
		"", "", // GitHub client ID and secret
		"", "", "", "", // who can sign in
		"",  // data directory
		"4", // Exit
	)
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"# Production gate. Ask ops before changing.", "${GH_SECRET}", "# from the vault", "data_dir: ./state"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("lost %q:\n%s", want, raw)
		}
	}
	if !strings.Contains(out, "GH_SECRET") {
		t.Errorf("no warning about the unset variable:\n%s", out)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode changed to %v", fi.Mode().Perm())
	}
}

func TestWizardStopsWhenInputEnds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intergate.yaml")
	var out bytes.Buffer
	w := &wizard.Wizard{Path: path, Accessible: true, In: &lineReader{lines: []string{"http://localhost:8080"}}, Out: &out}
	done := make(chan error, 1)
	go func() { done <- w.Run(context.Background()) }()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(out.String(), "Nothing was saved") {
			t.Fatalf("err = %v\n%s", err, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wizard did not stop when its input ended")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a configuration was saved from incomplete answers")
	}
}
