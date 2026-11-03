package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	g2smail "github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
)

// The Admin page's SMTP relay: how intergate sends its emails. Admins see
// it; owners change it, and a change only saves once the owner enters a
// code the new relay delivered to them, so a relay that can't deliver
// never replaces one that can.

// relayView describes the SMTP relay for the Admin page, without its
// password.
type relayView struct {
	// Source is "config" (auth.email in the configuration file),
	// "dashboard" (set up from the dashboard) or "" (none).
	Source   settings.Source `json:"source"`
	Host     string          `json:"host,omitempty"`
	Port     int             `json:"port,omitempty"`
	TLS      string          `json:"tls,omitempty"`
	Username string          `json:"username,omitempty"`
	From     string          `json:"from,omitempty"`
	// LogOnly is auth.email.log_only: codes go to the log.
	LogOnly bool `json:"log_only,omitempty"`
	// Password says where the password comes from: "stored" (encrypted
	// in the database), env:NAME, file:/path, "config" (the configuration
	// file), or "" for none.
	Password string `json:"password,omitempty"`
	// Editable is set for owners when the relay is not the configuration
	// file's.
	Editable bool `json:"editable"`
	// Pending is the address a code that confirms a new relay went to.
	Pending string `json:"pending,omitempty"`
}

// relayChanges are new SMTP relays waiting for the owner who asked for each
// to enter the code it delivered: one per owner, in memory only.
type relayChanges struct {
	mu      sync.Mutex
	pending map[int64]*relayChange
}

type relayChange struct {
	flow    string // the code's flow in Server.codes
	to      string
	change  *settings.Change
	expires time.Time
}

func (c *relayChanges) put(userID int64, rc *relayChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = map[int64]*relayChange{}
	}
	c.pending[userID] = rc
}

func (c *relayChanges) get(userID int64) *relayChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	rc := c.pending[userID]
	if rc != nil && time.Now().After(rc.expires) {
		delete(c.pending, userID)
		return nil
	}
	return rc
}

func (c *relayChanges) drop(userID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, userID)
}

func (s *Server) relayView(a *authInfo) relayView {
	v := relayView{Source: s.settings.EmailSource()}
	switch v.Source {
	case settings.SourceConfig:
		c := s.cfg.Auth.Email
		v.Host, v.Port, v.TLS, v.Username, v.From, v.LogOnly = c.SMTP.Host, c.SMTP.Port, c.SMTP.TLS, c.SMTP.Username, c.From, c.LogOnly
		if c.SMTP.Password != "" {
			v.Password = "config"
		}
	case settings.SourceDashboard:
		e := s.settings.Email()
		v.Host, v.Port, v.TLS, v.Username, v.From, v.Password = e.Host, e.Port, e.TLS, e.Username, e.From, e.PasswordSource()
	}
	if a.Role == store.RoleOwner {
		v.Editable = v.Source != settings.SourceConfig
		if rc := s.relay.get(a.User.ID); rc != nil {
			v.Pending = rc.to
		}
	}
	return v
}

func (s *Server) handleAdminRelay(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.relayView(currentAuth(r)))
}

// relayOwner lets owners through, while the relay is not the
// configuration file's.
func (s *Server) relayOwner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentAuth(r).Role != store.RoleOwner {
			jsonError(w, http.StatusForbidden, "Only owners can change the SMTP relay.")
			return
		}
		if s.settings.EmailSource() == settings.SourceConfig {
			jsonError(w, http.StatusConflict, "The SMTP relay is set in the configuration file (auth.email): change it there.")
			return
		}
		next(w, r)
	}
}

var tlsNames = map[string]string{"starttls": "STARTTLS", "tls": "TLS", "none": "None"}

// handleAdminRelayChange checks a new SMTP relay and sends the owner a
// code through it. Nothing is saved until the code comes back.
func (s *Server) handleAdminRelayChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		TLS      string `json:"tls"`
		Username string `json:"username"`
		Password string `json:"password"`
		From     string `json:"from"`
	}
	if !decode(w, r, &req) {
		return
	}
	a := currentAuth(r)
	if !s.codes.byIP.allow(s.clientIP(r)) || !s.codes.byEmail.allow(a.User.Email) {
		jsonError(w, http.StatusTooManyRequests, "Too many codes requested. Wait a few minutes and try again.")
		return
	}
	e := settings.Email{
		Host:     strings.ToLower(strings.TrimSpace(req.Host)),
		Port:     req.Port,
		TLS:      req.TLS,
		Username: strings.TrimSpace(req.Username),
		From:     strings.TrimSpace(req.From),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	var smtpErr *settings.SMTPError
	var inputErr *settings.InputError
	change, err := s.settings.PrepareEmail(ctx, e, req.Password)
	switch {
	case errors.As(err, &inputErr):
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	case errors.As(err, &smtpErr):
		jsonError(w, http.StatusBadRequest, "The new SMTP relay could not be used: "+strings.TrimPrefix(err.Error(), "smtp: ")+".")
		return
	case err != nil:
		s.internalError(w, "check the SMTP relay", err)
		return
	}

	ttl := s.cfg.Auth.Email.CodeTTL
	code := sixDigits()
	user := e.Username
	if user == "" {
		user = "none"
	}
	msg := g2smail.Code{
		To:      a.User.Email,
		Code:    code,
		Subject: "is your code to change intergate's SMTP relay",
		Heading: "Confirm the new SMTP relay",
		Intro:   "This email came through the new SMTP relay of intergate at " + s.cfg.Domain() + ". Enter the code in its Admin page to save it.",
		Details: [][2]string{
			{"Server", net.JoinHostPort(e.Host, strconv.Itoa(e.Port))},
			{"Encryption", tlsNames[e.TLS]},
			{"User", user},
			{"Sender", e.From},
		},
		TTL:  ttl,
		Note: "If you did not change it, ignore this email: the SMTP relay stays as it was.",
		Site: s.cfg.DashboardURL("/admin"),
	}.Message()
	if err := s.mailerFor(change.Config()).Send(ctx, msg); err != nil {
		s.log.Info("new SMTP relay did not send the code", "host", e.Host, "to", a.User.Email, "err", err)
		jsonError(w, http.StatusBadGateway, "The new SMTP relay took the settings but did not send the code: "+strings.TrimPrefix(err.Error(), "smtp: ")+".")
		return
	}
	flow := randomString(16)
	s.codes.add(flow, code, ttl)
	s.relay.put(a.User.ID, &relayChange{flow: flow, to: a.User.Email, change: change, expires: time.Now().Add(ttl)})
	s.log.Info("new SMTP relay sent a confirmation code", "host", e.Host, "to", a.User.Email)
	writeJSON(w, http.StatusOK, s.relayView(a))
}

// handleAdminRelayConfirm saves the new SMTP relay once its code comes
// back.
func (s *Server) handleAdminRelayConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	a := currentAuth(r)
	rc := s.relay.get(a.User.ID)
	if rc == nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "The code has expired. Check the new SMTP relay again.", Expired: true})
		return
	}
	// A wrong code is a 400, not a 401: the owner is signed in, and the
	// dashboard takes a 401 to mean the session ended, and signs them out.
	switch s.codes.check(rc.flow, strings.Join(strings.Fields(req.Code), "")) {
	case codeWrong:
		jsonError(w, http.StatusBadRequest, "That code is not right. Check the email and try again.")
		return
	case codeExpired:
		s.relay.drop(a.User.ID)
		writeJSON(w, http.StatusBadRequest, apiError{Error: "That code has expired or was tried too many times. Check the new SMTP relay again.", Expired: true})
		return
	}
	s.relay.drop(a.User.ID)
	if err := s.settings.ApplyEmail(r.Context(), rc.change); err != nil {
		s.internalError(w, "save the SMTP relay", err)
		return
	}
	e := rc.change.Email()
	s.log.Info("SMTP relay changed", "host", e.Host, "port", e.Port, "tls", e.TLS, "by", a.User.Email)
	writeJSON(w, http.StatusOK, s.relayView(a))
}

// handleAdminRelayCancel forgets a new SMTP relay waiting for its code.
func (s *Server) handleAdminRelayCancel(w http.ResponseWriter, r *http.Request) {
	s.relay.drop(currentAuth(r).User.ID)
	w.WriteHeader(http.StatusNoContent)
}
