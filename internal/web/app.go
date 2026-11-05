package web

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const msgInternal = "Something went wrong. Please try again."

// csp is the Content-Security-Policy of every dashboard response. The page
// shell adds its nonce: jq79 builds each component's expressions and
// scripts as <script> elements carrying it, so no eval is ever allowed.
func csp(nonce string) string {
	scripts := "'self'"
	if nonce != "" {
		scripts += " 'nonce-" + nonce + "'"
	}
	return "default-src 'none'; script-src " + scripts + "; style-src 'self'; img-src 'self' https: data:; " +
		"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}

func isAPI(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/api/") }

// boot is what the app knows before its first API call, embedded in the
// page as JSON.
type boot struct {
	Version   string     `json:"version"`
	Domain    string     `json:"domain"`
	Email     bool       `json:"email"`
	Passkeys  bool       `json:"passkeys"`
	Providers []bootLink `json:"providers"`
	Limits    bootLimits `json:"limits"`
	TCP       *bootTCP   `json:"tcp"`
	// Wildcard is set when intergate gets its certificates from Let's
	// Encrypt: the Admin page's DNS tab can get a wildcard one.
	Wildcard  bool        `json:"wildcard,omitempty"`
	User      *me         `json:"user"`
	CSRF      string      `json:"csrf,omitempty"`
	EmailFlow string      `json:"email_flow,omitempty"`
	Error     *pageErrMsg `json:"error,omitempty"`
	// Setup is set while intergate is not set up: the page shows the
	// setup instead of anything else.
	Setup *bootSetup `json:"setup,omitempty"`
}

type bootLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type bootLimits struct {
	Subdomains int `json:"subdomains"`
	Keys       int `json:"keys"`
}

// bootTCP describes TCP ports, when the server has them.
type bootTCP struct {
	First    int    `json:"first"`
	Last     int    `json:"last"`
	MaxPorts int    `json:"max_ports"`
	Host     string `json:"host"`
}

// me is the signed-in user.
type me struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url"`
	Admin     bool      `json:"admin"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// pageErrMsg is an error the app shows in place of a page, for requests
// that are not API calls: an OAuth callback, a tunnel sign-in link.
type pageErrMsg struct {
	Status  int    `json:"status"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

func (s *Server) serveApp(w http.ResponseWriter, r *http.Request, status int, perr *pageErrMsg) {
	b := boot{
		Version:   s.version,
		Domain:    s.cfg.Domain(),
		Email:     s.settings.EmailEnabled(),
		Passkeys:  s.webauthn != nil,
		Providers: []bootLink{},
		Limits:    bootLimits{Subdomains: s.cfg.Limits.SubdomainsPerUser, Keys: s.cfg.Limits.KeysPerSubdomain},
		Wildcard:  s.wildcard != nil,
		Error:     perr,
	}
	if s.cfg.TCP.Enabled() {
		first, last := s.cfg.TCP.Range()
		b.TCP = &bootTCP{First: first, Last: last, MaxPorts: s.cfg.TCP.MaxPorts, Host: s.cfg.TCPHost()}
	}
	for _, p := range s.providers {
		b.Providers = append(b.Providers, bootLink{p.Name(), "/auth/" + url.PathEscape(p.ID()) + "/login"})
	}
	if a := currentAuth(r); a != nil {
		u := a.User
		b.User = &me{ID: u.ID, Email: u.Email, Name: u.Name, AvatarURL: u.AvatarURL, Admin: a.Admin, Role: string(a.Role), CreatedAt: u.CreatedAt}
		b.CSRF = a.Session.CSRFToken
	} else if f, ok := s.emailFlow(r); ok {
		b.EmailFlow = f.Email
	}
	setup, err := s.setupState(r)
	if err != nil {
		s.log.Error("setup state", "err", err)
	}
	b.Setup = setup

	page := struct {
		Nonce string
		Boot  boot
	}{newNonce(), b}
	s.servePage(w, s.shell, page.Nonce, page, status)
}

// newNonce is a page's script nonce, new on every response.
func newNonce() string {
	nonce := make([]byte, 18)
	rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(nonce)
}

// servePage renders a page whose scripts carry nonce, with a CSP that
// allows them.
func (s *Server) servePage(w http.ResponseWriter, tmpl *template.Template, nonce string, data any, status int) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		s.log.Error("render page", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp(nonce))
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// handleTheme serves the design system's demo: the theme's tokens and
// every component, with nothing of the app's. It needs no session.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	nonce := newNonce()
	s.servePage(w, s.theme, nonce, struct{ Nonce string }{nonce}, http.StatusOK)
}

func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	s.serveApp(w, r, http.StatusOK, nil)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if currentAuth(r) != nil {
		http.Redirect(w, r, localPath(r.URL.Query().Get("rd")), http.StatusFound)
		return
	}
	s.serveApp(w, r, http.StatusOK, nil)
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if a := currentAuth(r); a != nil && !a.Admin {
		s.pageError(w, r, http.StatusNotFound, "There is no page here.")
		return
	}
	s.serveApp(w, r, http.StatusOK, nil)
}

// pageError answers a page request with the app showing msg.
func (s *Server) pageError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.serveApp(w, r, status, &pageErrMsg{Status: status, Title: http.StatusText(status), Message: msg})
}

// uiFile is a file of the app, kept in memory with its ETag.
type uiFile struct {
	data []byte
	etag string
}

func loadUI() (map[string]uiFile, error) {
	files := map[string]uiFile{}
	err := fs.WalkDir(assets, "ui", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := assets.ReadFile(name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files[strings.TrimPrefix(name, "ui/")] = uiFile{data, `"` + base64.RawURLEncoding.EncodeToString(sum[:12]) + `"`}
		return nil
	})
	return files, err
}

// serveUI serves the app's files. They are revalidated on every load, so
// an upgrade reaches browsers at once and an unchanged file costs a 304.
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/ui/")
	f, ok := s.ui[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("ETag", f.etag)
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(f.data))
}
