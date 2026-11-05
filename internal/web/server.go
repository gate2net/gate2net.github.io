// Package web serves the dashboard on the main host and proxies every
// subdomain to its SSH tunnel.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	texttemplate "text/template"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/dns"
	"github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/manage"
	"github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
	"github.com/jgermade/intergate/internal/wildcard"
)

//go:embed templates ui
var assets embed.FS

// Options configure a Server.
type Options struct {
	Config   *config.Config
	Store    *store.Store
	Registry *tunnel.Registry
	Manage   *manage.Service
	// Settings holds email delivery set up from the dashboard, and the
	// setup itself.
	Settings *settings.Settings
	// Mailer sends sign-in codes. Defaults to the email delivery set up,
	// in the configuration file or from the dashboard.
	Mailer mail.Sender
	// MailerFor sends through email delivery that is not saved yet, to
	// confirm it. Defaults to its SMTP server, or to Mailer when set.
	MailerFor func(config.EmailConfig) mail.Sender
	// Secret signs OAuth state and tunnel access cookies. Keep it stable
	// across restarts so visitors stay signed in to private tunnels.
	Secret []byte
	Logger *slog.Logger
	// HTTPClient talks to OAuth providers. Defaults to a client with a
	// 15 second timeout.
	HTTPClient *http.Client
	// Version is shown in the dashboard's footer.
	Version string
	// HostKey is the SSH host key's fingerprint, for /tunnel.sh.
	HostKey string
	// Wildcard keeps the wildcard certificate, when intergate gets its
	// certificates from Let's Encrypt; DNSEnv is what its DNS providers
	// get.
	Wildcard *wildcard.Manager
	DNSEnv   dns.Env
}

// Server is the HTTP handler for the dashboard and all tunnels.
type Server struct {
	cfg       *config.Config
	store     *store.Store
	registry  *tunnel.Registry
	manage    *manage.Service
	settings  *settings.Settings
	mailer    mail.Sender
	mailerFor func(config.EmailConfig) mail.Sender
	relay     relayChanges
	wildcard  *wildcard.Manager
	dnsEnv    dns.Env
	// wildcardCheck caches whether *.<domain> resolves.
	wildcardCheck wildcardCheck
	// untrusted throttles the warnings about X-Forwarded-For from
	// connections that are not trusted proxies'.
	untrusted throttle
	log       *slog.Logger
	signer    signer
	nonces    *nonceSet
	codes     *codeStore
	webauthn  *webauthn.WebAuthn
	cookies   cookieNames
	providers []provider
	shell     *template.Template
	theme     *template.Template
	tunnelErr *template.Template
	tunnelSh  *texttemplate.Template
	tunnelPs  *texttemplate.Template
	hostKey   string
	ui        map[string]uiFile
	dashboard http.Handler
	proxy     *httputil.ReverseProxy
	version   string
}

type cookieNames struct {
	session, oauth, access, emailLogin, passkey, setup, setupOwner string
}

// New builds the handler.
func New(o Options) (*Server, error) {
	if len(o.Secret) < 32 {
		return nil, errors.New("web: secret must be at least 32 bytes")
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	s := &Server{
		cfg:       o.Config,
		store:     o.Store,
		registry:  o.Registry,
		manage:    o.Manage,
		settings:  o.Settings,
		mailer:    o.Mailer,
		mailerFor: o.MailerFor,
		log:       o.Logger,
		signer:    signer{key: o.Secret},
		nonces:    newNonceSet(),
		codes:     newCodeStore(),
		version:   o.Version,
		hostKey:   o.HostKey,
		wildcard:  o.Wildcard,
		dnsEnv:    o.DNSEnv,
	}
	switch {
	case s.mailerFor != nil:
	case s.mailer != nil:
		s.mailerFor = func(config.EmailConfig) mail.Sender { return o.Mailer }
	default:
		s.mailerFor = func(c config.EmailConfig) mail.Sender { return mail.New(c, s.log) }
	}
	if s.mailer == nil {
		s.mailer = s.settings.Mailer(s.log)
	}
	// The __Host- prefix stops tunnel subdomains, which serve arbitrary
	// content, from planting cookies for the dashboard (or each other).
	prefix := ""
	if s.cfg.Secure() {
		prefix = "__Host-"
	}
	s.cookies = cookieNames{
		session:    prefix + "intergate",
		oauth:      prefix + "intergate-oauth",
		access:     prefix + "intergate-access",
		emailLogin: prefix + "intergate-email",
		passkey:    prefix + "intergate-passkey",
		setup:      prefix + "intergate-setup",
		setupOwner: prefix + "intergate-setup-owner",
	}
	if s.cfg.PasskeysEnabled() {
		wa, err := webauthn.New(&webauthn.Config{
			RPID:          s.cfg.Domain(),
			RPDisplayName: "intergate",
			// Tunnel subdomains may claim this RP ID too, so assertions
			// are only accepted from the dashboard's exact origin.
			RPOrigins: []string{s.cfg.DashboardURL("")},
		})
		if err != nil {
			return nil, fmt.Errorf("web: passkeys: %w", err)
		}
		s.webauthn = wa
	}
	for _, pc := range s.cfg.Auth.Providers {
		redirect := s.cfg.DashboardURL("/auth/" + pc.ID + "/callback")
		switch pc.Type {
		case "github":
			s.providers = append(s.providers, newGitHubProvider(pc, redirect, client))
		case "oidc":
			s.providers = append(s.providers, newOIDCProvider(pc, redirect, client))
		}
	}
	var err error
	if s.shell, err = template.ParseFS(assets, "templates/app.html"); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	if s.theme, err = template.ParseFS(assets, "templates/theme.html"); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	if s.tunnelErr, err = template.ParseFS(assets, "templates/tunnel_error.html"); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	if s.tunnelSh, err = texttemplate.ParseFS(assets, "templates/tunnel.sh"); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	if s.tunnelPs, err = texttemplate.ParseFS(assets, "templates/tunnel.ps1"); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	if s.ui, err = loadUI(); err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	s.dashboard = s.routes()
	s.proxy = s.newProxy()
	return s, nil
}

// ServeHTTP dispatches on the Host header: the dashboard lives on the
// configured domain, tunnels on its direct subdomains.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	domain := s.cfg.Domain()
	switch {
	case host == domain:
		s.dashboard.ServeHTTP(w, r)
	case strings.HasSuffix(host, "."+domain) && !strings.Contains(strings.TrimSuffix(host, "."+domain), "."):
		s.serveTunnel(w, r, strings.TrimSuffix(host, "."+domain))
	case r.URL.Path == "/healthz":
		// Load balancer health checks often use the bare IP as Host.
		w.Write([]byte("ok\n"))
	default:
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ui/", s.serveUI)
	// The design system: its tokens and components on one page.
	mux.HandleFunc("GET /ui/theme/default/{$}", s.handleTheme)
	mux.HandleFunc("GET /ui/theme/default", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/theme/default/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /tunnel.sh", s.handleTunnelScript)
	mux.HandleFunc("GET /tunnel.ps1", s.handleTunnelScript)
	mux.HandleFunc("GET /client.json", s.handleClientInfo)

	// Pages: the same shell for each, and the app draws the one its path
	// names. Signed out, every page is the sign-in form.
	mux.HandleFunc("GET /{$}", s.handleApp)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /account", s.handleApp)
	mux.HandleFunc("GET /subdomains/{name}", s.handleApp)
	mux.HandleFunc("GET /admin", s.handleAdminPage)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		s.pageError(w, r, http.StatusNotFound, "There is no page here.")
	})
	mux.HandleFunc("GET /auth/{provider}/login", s.handleOAuthLogin)
	mux.HandleFunc("GET /auth/{provider}/callback", s.handleOAuthCallback)
	mux.HandleFunc("GET /tunnel-auth", s.handleTunnelAuth)

	// The API the app calls.
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		jsonError(w, http.StatusNotFound, "Not found.")
	})
	// Email delivery can be set up while intergate runs, from the setup.
	mux.Handle("POST /api/login/email", s.sameOrigin(s.withEmail(s.handleEmailLogin)))
	mux.Handle("DELETE /api/login/email", s.sameOrigin(s.withEmail(s.handleEmailCancel)))
	mux.Handle("POST /api/login/code", s.sameOrigin(s.withEmail(s.handleCodeLogin)))
	mux.Handle("POST /api/setup/start", s.setupCall(true, s.handleSetupStart))
	mux.Handle("POST /api/setup/email", s.setupCall(false, s.handleSetupEmail))
	mux.Handle("POST /api/setup/owner", s.setupCall(false, s.handleSetupOwner))
	mux.Handle("DELETE /api/setup/owner", s.setupCall(false, s.handleSetupOwnerCancel))
	mux.Handle("POST /api/setup/owner/code", s.setupCall(false, s.handleSetupOwnerCode))
	if s.webauthn != nil {
		mux.Handle("POST /api/login/passkey/options", s.sameOrigin(s.handlePasskeyLoginOptions))
		mux.Handle("POST /api/login/passkey", s.sameOrigin(s.handlePasskeyLogin))
	}

	user := s.requireUser
	mux.Handle("POST /api/logout", user(s.handleLogout))
	mux.Handle("GET /api/account", user(s.handleAccount))
	mux.Handle("GET /api/account/keys", user(s.handleAccountKeys))
	mux.Handle("POST /api/account/keys", user(s.handleAddAccountKeys))
	mux.Handle("PATCH /api/account/keys/{id}", user(s.handleRenameAccountKey))
	mux.Handle("DELETE /api/account/keys/{id}", user(s.handleDeleteAccountKey))
	if s.webauthn != nil {
		mux.Handle("POST /api/account/passkeys/options", user(s.handlePasskeyRegisterOptions))
		mux.Handle("POST /api/account/passkeys", user(s.handlePasskeyRegister))
		mux.Handle("PATCH /api/account/passkeys/{id}", user(s.handleRenamePasskey))
		mux.Handle("DELETE /api/account/passkeys/{id}", user(s.handleDeletePasskey))
	}
	mux.Handle("GET /api/subdomains", user(s.handleListSubdomains))
	mux.Handle("POST /api/subdomains", user(s.handleCreateSubdomain))
	mux.Handle("GET /api/subdomains/{name}", user(s.handleSubdomain))
	mux.Handle("PATCH /api/subdomains/{name}", user(s.handleUpdateSubdomain))
	mux.Handle("DELETE /api/subdomains/{name}", user(s.handleDeleteSubdomain))
	mux.Handle("POST /api/subdomains/{name}/keys", user(s.handleAddKeys))
	mux.Handle("PATCH /api/subdomains/{name}/keys/{id}", user(s.handleRenameKey))
	mux.Handle("DELETE /api/subdomains/{name}/keys/{id}", user(s.handleDeleteKey))
	mux.Handle("POST /api/subdomains/{name}/disconnect", user(s.handleDisconnect))
	mux.Handle("POST /api/subdomains/{name}/ports", user(s.handleAddPort))
	mux.Handle("PATCH /api/subdomains/{name}/ports/{id}", user(s.handleUpdatePort))
	mux.Handle("DELETE /api/subdomains/{name}/ports/{id}", user(s.handleDeletePort))

	admin := func(h http.HandlerFunc) http.Handler { return s.requireUser(s.requireAdmin(h)) }
	mux.Handle("GET /api/admin/subdomains", admin(s.handleAdminSubdomains))
	mux.Handle("GET /api/admin/users", admin(s.handleAdminUsers))
	mux.Handle("POST /api/admin/users", admin(s.handleAdminCreateUser))
	mux.Handle("PATCH /api/admin/users/{id}", admin(s.handleAdminUpdateUser))
	mux.Handle("DELETE /api/admin/users/{id}", admin(s.handleAdminDeleteUser))
	mux.Handle("GET /api/admin/email", admin(s.handleAdminRelay))
	mux.Handle("POST /api/admin/email", admin(s.relayOwner(s.handleAdminRelayChange)))
	mux.Handle("POST /api/admin/email/confirm", admin(s.relayOwner(s.handleAdminRelayConfirm)))
	mux.Handle("DELETE /api/admin/email/pending", admin(s.relayOwner(s.handleAdminRelayCancel)))
	mux.Handle("GET /api/admin/dns", admin(s.dnsAvailable(s.handleAdminDNS)))
	mux.Handle("PUT /api/admin/dns", admin(s.dnsAvailable(s.dnsOwner(s.handleAdminDNSChange))))
	mux.Handle("DELETE /api/admin/dns", admin(s.dnsAvailable(s.dnsOwner(s.handleAdminDNSDelete))))
	mux.Handle("POST /api/admin/dns/retry", admin(s.dnsAvailable(s.dnsOwner(s.handleAdminDNSRetry))))

	return s.securityHeaders(s.withSession(mux))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp(""))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.cfg.Secure() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const authKey ctxKey = iota

// authInfo is the signed-in user of a dashboard request.
type authInfo struct {
	Session *store.Session
	User    *store.User
	// Role is the effective one, auth.admins included; Admin is set for
	// admins and owners.
	Role  store.Role
	Admin bool
}

func currentAuth(r *http.Request) *authInfo {
	a, _ := r.Context().Value(authKey).(*authInfo)
	return a
}

func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(s.cookies.session); err == nil && c.Value != "" {
			sess, user, err := s.store.SessionByToken(r.Context(), c.Value)
			switch {
			case err == nil && s.cfg.UserAllowed(user.Email, user.Added, string(user.Role)):
				role := store.Role(s.cfg.UserRole(user.Email, string(user.Role)))
				a := &authInfo{Session: sess, User: user, Role: role, Admin: role != store.RoleUser}
				r = r.WithContext(context.WithValue(r.Context(), authKey, a))
			case err != nil && !errors.Is(err, store.ErrNotFound):
				s.log.Error("load session", "err", err)
				if isAPI(r) {
					jsonError(w, http.StatusInternalServerError, msgInternal)
				} else {
					s.pageError(w, r, http.StatusInternalServerError, msgInternal)
				}
				return
			default:
				s.clearCookie(w, s.cookies.session)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireUser answers API calls from anonymous visitors with a 401, and
// checks the origin and CSRF token of calls that change something.
func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := currentAuth(r)
		if a == nil {
			jsonError(w, http.StatusUnauthorized, "Your session has ended. Please sign in again.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
			// Tunnel subdomains are same-site with the dashboard, so SameSite
			// cookies do not stop their pages from calling the API: check
			// both the origin and the session's token.
			if !s.fromDashboard(r) {
				jsonError(w, http.StatusForbidden, "Cross-origin request blocked.")
				return
			}
			token := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(token), []byte(a.Session.CSRFToken)) != 1 {
				jsonError(w, http.StatusForbidden, "Invalid request token. Reload the page and try again.")
				return
			}
		}
		next(w, r)
	})
}

// fromDashboard reports whether a request was sent by a dashboard page,
// going by its Origin (or, for older browsers, Referer) header.
func (s *Server) fromDashboard(r *http.Request) bool {
	origin := s.cfg.DashboardURL("")
	if o := r.Header.Get("Origin"); o != "" {
		return o == origin
	}
	ref := r.Header.Get("Referer")
	return ref == "" || ref == origin || strings.HasPrefix(ref, origin+"/")
}

// sameOrigin guards the sign-in forms and calls, which have no session to
// carry a CSRF token yet.
func (s *Server) sameOrigin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" || !s.fromDashboard(r) {
			jsonError(w, http.StatusForbidden, "Cross-origin request blocked.")
			return
		}
		next(w, r)
	})
}

// clientIP is the visitor's address, for rate limiting and logs.
func (s *Server) clientIP(r *http.Request) string {
	host := peerHost(r)
	if s.trustsForwarded(r, host) {
		// The last entry was added by the proxy we trust.
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	return host
}

// peerHost is the address the request came from: a proxy's, or the
// client's.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// trustsForwarded reports whether X-Forwarded-For from this peer tells the
// client's address: with http.trust_proxy_headers, and from one of the
// trusted_proxies. A header from anyone else is ignored, and logged now and
// then, so a proxy left out of trusted_proxies shows.
func (s *Server) trustsForwarded(r *http.Request, peer string) bool {
	if !s.cfg.HTTP.TrustProxyHeaders {
		return false
	}
	if ip, err := netip.ParseAddr(peer); err == nil && s.cfg.TrustedProxy(ip) {
		return true
	}
	if len(r.Header.Values("X-Forwarded-For")) > 0 && s.untrusted.due(peer) {
		s.log.Warn("X-Forwarded-For ignored: the connection does not come from trusted_proxies", "from", peer)
	}
	return false
}

// throttle tells when to log about a key again: once an hour.
type throttle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (t *throttle) due(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.last == nil || len(t.last) > 1000 {
		t.last = map[string]time.Time{}
	}
	if now.Sub(t.last[key]) < time.Hour {
		return false
	}
	t.last[key] = now
	return true
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a := currentAuth(r); a == nil || !a.Admin {
			jsonError(w, http.StatusNotFound, "Not found.")
			return
		}
		next(w, r)
	}
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) ssh() string {
	if p := s.cfg.SSHPort(); p != 22 {
		return fmt.Sprintf("ssh -p %d", p)
	}
	return "ssh"
}

// sshCommand is the command a user runs to expose localhost:3000. The
// dashboard swaps in the port its user types.
func (s *Server) sshCommand(name string) string {
	return fmt.Sprintf("%s -R %s:80:localhost:3000 %s", s.ssh(), name, s.cfg.SSHHost())
}

// portsCommand is the command that forwards every TCP port of a
// subdomain to its local port, or "" without any.
func (s *Server) portsCommand(name string, list []*store.Port) string {
	cmd := s.ssh()
	n := 0
	for _, p := range list {
		if p.Protocol == store.ProtocolTCP {
			cmd += fmt.Sprintf(" -R %s.%s:0:localhost:%d", p.Name, name, p.LocalPort)
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return cmd + " " + s.cfg.SSHHost()
}

// tunnelCommand runs the intergate client for every port of a subdomain,
// on Linux and macOS or, with windows, in PowerShell; it is "" without any.
func (s *Server) tunnelCommand(name string, list []*store.Port, windows bool) string {
	if len(list) == 0 {
		return ""
	}
	cmd := "curl -fsSL " + s.cfg.DashboardURL("/tunnel.sh") + " | sh -s -- " + name
	if windows {
		cmd = "& ([scriptblock]::Create((irm " + s.cfg.DashboardURL("/tunnel.ps1") + "))) " + name
	}
	for _, p := range list {
		cmd += fmt.Sprintf(" --%s %s=%d", p.Protocol, p.Name, p.LocalPort)
	}
	return cmd
}

// sshServer is HOST:PORT of the SSH endpoint, for the intergate client.
func (s *Server) sshServer() string {
	return net.JoinHostPort(s.cfg.SSHHost(), fmt.Sprint(s.cfg.SSHPort()))
}

// The values written into tunnel.sh between single quotes.
var (
	releaseVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	shellSafe      = regexp.MustCompile(`^[A-Za-z0-9.:+/=\[\]_-]*$`)
)

// handleClientInfo tells the intergate app, given only the dashboard's
// address, where to connect and which host key to expect.
func (s *Server) handleClientInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, struct {
		Server    string `json:"server"`
		HostKey   string `json:"host_key"`
		Domain    string `json:"domain"`
		Dashboard string `json:"dashboard"`
		Version   string `json:"version"`
	}{s.sshServer(), s.hostKey, s.cfg.Domain(), s.cfg.DashboardURL("/"), s.version})
}

// handleTunnelScript serves the script that runs the intergate client
// without installing it, set up for this server: tunnel.sh for Linux and
// macOS, tunnel.ps1 for Windows.
func (s *Server) handleTunnelScript(w http.ResponseWriter, r *http.Request) {
	tmpl, contentType := s.tunnelSh, "text/x-shellscript; charset=utf-8"
	if r.URL.Path == "/tunnel.ps1" {
		tmpl, contentType = s.tunnelPs, "text/plain; charset=utf-8"
	}
	version := s.version
	if !releaseVersion.MatchString(version) {
		version = "" // a build from source: the latest release
	}
	data := struct{ Dashboard, URL, Version, Server, HostKey string }{
		s.cfg.DashboardURL("/"), s.cfg.DashboardURL(r.URL.Path), version, s.sshServer(), s.hostKey,
	}
	if !shellSafe.MatchString(data.Server) || !shellSafe.MatchString(data.HostKey) {
		http.Error(w, "the SSH host can't be written into a script", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		s.log.Error("render "+r.URL.Path, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(buf.Bytes())
}

// localPath returns rd if it is a path on this host, else "/". It stops
// redirects to other sites after login.
func localPath(rd string) string {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return rd
}
