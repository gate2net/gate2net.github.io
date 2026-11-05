package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
)

// authPath is reserved on every tunnel host: it receives the hand-off token
// from the dashboard and turns it into an access cookie for that host.
const authPath = "/__intergate/auth"

const (
	handoffTTL   = 2 * time.Minute
	maxAccessTTL = 12 * time.Hour
)

// handoff is a short-lived, single-use token minted by the dashboard for a
// signed-in user who wants to open a protected tunnel.
type handoff struct {
	Host      string `json:"h"`
	SessionID string `json:"s"`
	Nonce     string `json:"n"`
}

// accessGrant is the content of a tunnel host's access cookie. It is only
// valid while the dashboard session it came from is, so signing out of
// the dashboard also signs out of every tunnel.
type accessGrant struct {
	Host      string `json:"h"`
	SessionID string `json:"s"`
}

type proxyCtxKey struct{}

type proxyCtx struct {
	tunnel *tunnel.Tunnel
	start  time.Time
}

func (s *Server) newProxy() *httputil.ReverseProxy {
	proto := s.cfg.Scheme()
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			if s.trustsForwarded(pr.In, peerHost(pr.In)) {
				if prior := pr.In.Header["X-Forwarded-For"]; len(prior) > 0 {
					pr.Out.Header["X-Forwarded-For"] = prior
				}
			}
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
		},
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return req.Context().Value(proxyCtxKey{}).(*proxyCtx).tunnel.Transport().RoundTrip(req)
		}),
		ModifyResponse: func(resp *http.Response) error {
			pc := resp.Request.Context().Value(proxyCtxKey{}).(*proxyCtx)
			logRequest(pc, resp.Request, resp.StatusCode)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			pc := r.Context().Value(proxyCtxKey{}).(*proxyCtx)
			logRequest(pc, r, http.StatusBadGateway)
			if errors.Is(err, context.Canceled) {
				return // the visitor went away
			}
			msg := "The tunnel is connected, but the service behind it did not answer. Is it running?"
			if errors.Is(err, tunnel.ErrClosed) {
				msg = "The tunnel was closed while handling this request."
			}
			s.renderTunnelError(w, http.StatusBadGateway, "Bad gateway", msg)
		},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func logRequest(pc *proxyCtx, r *http.Request, status int) {
	pc.tunnel.Log("%s  %d  %-6s %s  (%s)", time.Now().Format("15:04:05"), status, r.Method,
		truncate(r.URL.RequestURI(), 120), time.Since(pc.start).Round(time.Millisecond))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (s *Server) serveTunnel(w http.ResponseWriter, r *http.Request, name string) {
	if r.URL.Path == authPath {
		s.handleTunnelAuthCallback(w, r, name)
		return
	}
	t := s.registry.Get(name)
	if t == nil {
		if _, err := s.store.SubdomainByName(r.Context(), name); err == nil {
			s.renderOffline(w, name)
		} else {
			s.renderTunnelError(w, http.StatusNotFound, "Not found",
				s.cfg.TunnelHost(name)+" is not registered.")
		}
		return
	}

	if access := t.Access(); access != store.AccessPublic {
		user := s.tunnelVisitor(r, name)
		if user == nil {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				s.renderTunnelError(w, http.StatusUnauthorized, "Sign in required",
					"Open "+s.cfg.TunnelURL(name)+" in your browser to sign in.")
				return
			}
			rd := s.cfg.TunnelURL(name) + r.URL.RequestURI()
			http.Redirect(w, r, s.cfg.DashboardURL("/tunnel-auth?rd="+url.QueryEscape(rd)), http.StatusFound)
			return
		}
		if !canAccess(access, t.OwnerID, user) {
			// Whoever may not open it doesn't learn that it is online.
			s.renderOffline(w, name)
			return
		}
	}

	// The service behind the tunnel must never see intergate's cookies.
	stripCookies(r, s.cookies.access, s.cookies.session, s.cookies.oauth, s.cookies.emailLogin, s.cookies.passkey)
	t.CountRequest()
	ctx := tunnel.WithOrigin(r.Context(), r.RemoteAddr)
	ctx = context.WithValue(ctx, proxyCtxKey{}, &proxyCtx{tunnel: t, start: time.Now()})
	s.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// renderOffline answers as for a subdomain nobody is connected to.
func (s *Server) renderOffline(w http.ResponseWriter, name string) {
	s.renderTunnelError(w, http.StatusBadGateway, "Tunnel offline",
		"Nobody is connected to "+s.cfg.TunnelHost(name)+" right now.")
}

func canAccess(access store.Access, ownerID int64, user *store.User) bool {
	switch access {
	case store.AccessPublic, store.AccessUsers:
		return true
	case store.AccessPrivate:
		return user.ID == ownerID
	}
	return false
}

// tunnelVisitor returns the user behind a valid access cookie, or nil.
func (s *Server) tunnelVisitor(r *http.Request, name string) *store.User {
	c, err := r.Cookie(s.cookies.access)
	if err != nil {
		return nil
	}
	var g accessGrant
	if s.signer.verify("access", c.Value, &g) != nil || g.Host != name {
		return nil
	}
	_, user, err := s.store.SessionByID(r.Context(), g.SessionID)
	if err != nil || !s.cfg.UserAllowed(user.Email, user.Added, string(user.Role)) {
		return nil
	}
	return user
}

func stripCookies(r *http.Request, names ...string) {
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			if part == "" || slices.Contains(names, strings.TrimSpace(name)) {
				continue
			}
			kept = append(kept, part)
		}
	}
	r.Header.Del("Cookie")
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// handleTunnelAuth runs on the dashboard: it sends the signed-in user back
// to a protected tunnel with a hand-off token.
func (s *Server) handleTunnelAuth(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	name, target, ok := s.parseTunnelURL(rd)
	if !ok {
		s.pageError(w, r, http.StatusBadRequest, "Invalid tunnel address.")
		return
	}
	a := currentAuth(r)
	if a == nil {
		http.Redirect(w, r, "/login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	// Every signed-in user gets the hand-off: it only says who they are.
	// The tunnel checks access on each request, and shows those who may
	// not open it the same page as when it is offline.
	token := s.signer.sign("handoff", handoff{Host: name, SessionID: a.Session.ID, Nonce: randomString(16)}, handoffTTL)
	q := url.Values{"token": {token}, "rd": {target.RequestURI()}}
	http.Redirect(w, r, s.cfg.TunnelURL(name)+authPath+"?"+q.Encode(), http.StatusFound)
}

// parseTunnelURL accepts only URLs of tunnels on this intergate.
func (s *Server) parseTunnelURL(raw string) (string, *url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Scheme != s.cfg.Scheme() {
		return "", nil, false
	}
	host := strings.ToLower(u.Host)
	label, _, found := strings.Cut(host, ".")
	if !found || label == "" || s.cfg.TunnelHost(label) != host {
		return "", nil, false
	}
	return label, u, true
}

// handleTunnelAuthCallback runs on the tunnel host and exchanges a hand-off
// token for a host-only access cookie.
func (s *Server) handleTunnelAuthCallback(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	var h handoff
	if s.signer.verify("handoff", r.URL.Query().Get("token"), &h) != nil || h.Host != name {
		s.renderTunnelError(w, http.StatusBadRequest, "Invalid link", "This sign-in link is invalid or has expired.")
		return
	}
	if !s.nonces.use(h.Nonce, time.Now().Add(handoffTTL)) {
		s.renderTunnelError(w, http.StatusBadRequest, "Invalid link", "This sign-in link was already used.")
		return
	}
	sess, _, err := s.store.SessionByID(r.Context(), h.SessionID)
	if err != nil {
		s.renderTunnelError(w, http.StatusUnauthorized, "Signed out", "Your session has ended. Please sign in again.")
		return
	}
	exp := time.Now().Add(maxAccessTTL)
	if sess.ExpiresAt.Before(exp) {
		exp = sess.ExpiresAt
	}
	s.setCookie(w, s.cookies.access, s.signer.signUntil("access", accessGrant{Host: name, SessionID: sess.ID}, exp), exp)
	http.Redirect(w, r, localPath(r.URL.Query().Get("rd")), http.StatusFound)
}

// renderTunnelError writes a self-contained error page on a tunnel host.
func (s *Server) renderTunnelError(w http.ResponseWriter, status int, title, msg string) {
	var buf bytes.Buffer
	err := s.tunnelErr.Execute(&buf, struct {
		Status       int
		Title, Msg   string
		DashboardURL string
	}{status, title, msg, s.cfg.DashboardURL("/")})
	if err != nil {
		s.log.Error("render tunnel error", "err", err)
		http.Error(w, msg, status)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}
