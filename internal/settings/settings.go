// Package settings keeps what is set up from the dashboard rather than in
// the configuration file: email delivery, with its SMTP password sealed
// with the data directory's secret key or read from the environment or a
// file, and the setup that asks for it, opened by a one-time link; and the
// DNS provider of the wildcard certificate, its secrets sealed too.
//
// The configuration file wins: with auth.email (or dns) in it, what is set
// up here is ignored.
package settings

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jgermade/intergate/internal/config"
	g2smail "github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/store"
)

const emailKey = "email"

// Email is email delivery set up from the dashboard.
type Email struct {
	From     string `json:"from"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLS      string `json:"tls"`
	Username string `json:"username,omitempty"`
	// Sealed is the SMTP password, encrypted with the secret key; or
	// PasswordRef says where to read it: env:NAME or file:/path.
	Sealed      string `json:"password,omitempty"`
	PasswordRef string `json:"password_ref,omitempty"`
}

// HasPassword reports whether the server signs in with a password.
func (e *Email) HasPassword() bool { return e.Sealed != "" || e.PasswordRef != "" }

// PasswordSource describes where the password comes from: "stored" (sealed
// in the database), the reference it is read from, or "" for none.
func (e *Email) PasswordSource() string {
	switch {
	case e.PasswordRef != "":
		return e.PasswordRef
	case e.Sealed != "":
		return "stored"
	}
	return ""
}

func (e *Email) smtp(password string) config.SMTPConfig {
	return config.SMTPConfig{Host: e.Host, Port: e.Port, Username: e.Username, Password: password, TLS: e.TLS}
}

// Validate checks e as entered in the setup.
func (e *Email) Validate() error {
	switch {
	case e.Host == "" || strings.ContainsAny(e.Host, " /:@"):
		return inputError("Enter the SMTP server's host name, like smtp.example.com.")
	case e.Port < 1 || e.Port > 65535:
		return inputError("Enter the SMTP server's port, usually 587 (STARTTLS) or 465 (TLS).")
	case e.TLS != "starttls" && e.TLS != "tls" && e.TLS != "none":
		return inputError("Choose STARTTLS, TLS or no encryption.")
	}
	if a, err := mail.ParseAddress(e.From); err != nil || a.Address == "" {
		return inputError("Enter the sender like intergate <no-reply@example.com>.")
	}
	return nil
}

// InputError is a problem with what was entered (or stored), worded for
// whoever entered it.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputError(msg string) error { return &InputError{msg} }

// Source is where email delivery comes from.
type Source string

const (
	// SourceNone: nothing sends sign-in codes.
	SourceNone Source = ""
	// SourceConfig: auth.email in the configuration file.
	SourceConfig Source = "config"
	// SourceDashboard: set up from the dashboard (or the admin socket).
	SourceDashboard Source = "dashboard"
)

// ErrNoEmail is returned when email delivery is needed and not set up.
var ErrNoEmail = errors.New("email delivery is not set up")

// Settings are the settings of a running server.
type Settings struct {
	cfg   *config.Config
	store *store.Store
	aead  cipher.AEAD
	// CheckSMTP tells whether an SMTP server takes a connection and its
	// credentials. mail.Check by default.
	CheckSMTP func(context.Context, config.SMTPConfig) error

	mu    sync.RWMutex
	email *Email
	dns   *DNS
	// dnsAEAD seals the DNS provider's secrets.
	dnsAEAD cipher.AEAD

	setup setup
}

// Open loads the settings from the database. secret is the data
// directory's secret key; the SMTP password is sealed with a key derived
// from it.
func Open(ctx context.Context, cfg *config.Config, st *store.Store, secret []byte) (*Settings, error) {
	aead, err := newAEAD(secret, "intergate settings: smtp password")
	if err != nil {
		return nil, err
	}
	dnsAEAD, err := newAEAD(secret, "intergate settings: dns credentials")
	if err != nil {
		return nil, err
	}
	s := &Settings{cfg: cfg, store: st, aead: aead, dnsAEAD: dnsAEAD, CheckSMTP: g2smail.Check}
	if err := s.loadDNS(ctx); err != nil {
		return nil, err
	}
	raw, err := st.Setting(ctx, emailKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, fmt.Errorf("load settings: %w", err)
	default:
		var e Email
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return nil, fmt.Errorf("load settings: email: %w", err)
		}
		s.email = &e
	}
	return s, nil
}

// EmailSource tells where email delivery comes from.
func (s *Settings) EmailSource() Source {
	if s.cfg.Auth.Email.Enabled() {
		return SourceConfig
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.email != nil {
		return SourceDashboard
	}
	return SourceNone
}

// EmailEnabled reports whether sign-in codes can be sent.
func (s *Settings) EmailEnabled() bool { return s.EmailSource() != SourceNone }

// Email returns a copy of the email delivery set up from the dashboard, or
// nil.
func (s *Settings) Email() *Email {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.email == nil {
		return nil
	}
	e := *s.email
	return &e
}

// EmailConfig resolves what email is sent with, password included.
func (s *Settings) EmailConfig() (config.EmailConfig, error) {
	if s.cfg.Auth.Email.Enabled() {
		return s.cfg.Auth.Email, nil
	}
	e := s.Email()
	if e == nil {
		return config.EmailConfig{}, ErrNoEmail
	}
	password, err := s.password(e)
	if err != nil {
		return config.EmailConfig{}, err
	}
	return config.EmailConfig{From: e.From, CodeTTL: s.cfg.Auth.Email.CodeTTL, SMTP: e.smtp(password)}, nil
}

func (s *Settings) password(e *Email) (string, error) {
	switch {
	case e.PasswordRef != "":
		return ResolvePassword(e.PasswordRef)
	case e.Sealed != "":
		return s.open(e.Sealed)
	}
	return "", nil
}

// Mailer sends through the email delivery set up when it sends.
func (s *Settings) Mailer(log *slog.Logger) g2smail.Sender { return sender{s, log} }

type sender struct {
	s   *Settings
	log *slog.Logger
}

func (m sender) Send(ctx context.Context, msg g2smail.Message) error {
	cfg, err := m.s.EmailConfig()
	if err != nil {
		return err
	}
	return g2smail.New(cfg, m.log).Send(ctx, msg)
}

// SaveEmail checks that the SMTP server of e takes its credentials and
// stores it. An empty password keeps the current one when the server and
// username are the same.
func (s *Settings) SaveEmail(ctx context.Context, e Email, password string) error {
	c, err := s.PrepareEmail(ctx, e, password)
	if err != nil {
		return err
	}
	return s.ApplyEmail(ctx, c)
}

// Change is new email delivery whose SMTP server took its credentials,
// not saved yet.
type Change struct {
	email    Email
	password string
}

// Email returns the new email delivery, its password sealed or referred to.
func (c *Change) Email() Email { return c.email }

// Config is what to send through the new email delivery with.
func (c *Change) Config() config.EmailConfig {
	return config.EmailConfig{From: c.email.From, SMTP: c.email.smtp(c.password)}
}

// PrepareEmail checks e, and that its SMTP server takes its credentials,
// for ApplyEmail to save. An empty password keeps the current one when the
// server and username are the same.
func (s *Settings) PrepareEmail(ctx context.Context, e Email, password string) (*Change, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	e.Sealed, e.PasswordRef = "", ""
	if old := s.Email(); password == "" && old != nil && old.Host == e.Host && old.Username == e.Username {
		e.Sealed, e.PasswordRef = old.Sealed, old.PasswordRef
		var err error
		if password, err = s.password(old); err != nil {
			return nil, err
		}
	} else if password != "" {
		sealed, err := s.seal(password)
		if err != nil {
			return nil, err
		}
		e.Sealed = sealed
	}
	if err := s.CheckSMTP(ctx, e.smtp(password)); err != nil {
		return nil, &SMTPError{err}
	}
	return &Change{email: e, password: password}, nil
}

// ApplyEmail saves a change PrepareEmail checked.
func (s *Settings) ApplyEmail(ctx context.Context, c *Change) error {
	e := c.email
	return s.saveEmail(ctx, &e)
}

// SMTPError is an SMTP server refusing the connection or the credentials.
type SMTPError struct{ Err error }

func (e *SMTPError) Error() string { return e.Err.Error() }
func (e *SMTPError) Unwrap() error { return e.Err }

// SetPassword changes where the SMTP password of the email delivery set up
// from the dashboard comes from: ref "" stores password sealed in the
// database; env:NAME or file:/path reads it from there whenever an email
// is sent. The SMTP server must take the password first: otherwise nothing
// changes.
func (s *Settings) SetPassword(ctx context.Context, ref, password string) error {
	switch s.EmailSource() {
	case SourceConfig:
		return errors.New("email delivery is set in the configuration file (auth.email): change the password there")
	case SourceNone:
		return ErrNoEmail
	}
	e := s.Email()
	if ref != "" {
		var err error
		if password, err = ResolvePassword(ref); err != nil {
			return err
		}
	} else if password == "" {
		return errors.New("enter the password")
	}
	if err := s.CheckSMTP(ctx, e.smtp(password)); err != nil {
		return &SMTPError{err}
	}
	e.Sealed, e.PasswordRef = "", ref
	if ref == "" {
		sealed, err := s.seal(password)
		if err != nil {
			return err
		}
		e.Sealed = sealed
	}
	return s.saveEmail(ctx, e)
}

func (s *Settings) saveEmail(ctx context.Context, e *Email) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.SetSetting(ctx, emailKey, string(raw)); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	s.email = e
	return nil
}

// ResolvePassword reads a password from where ref points: env:NAME, an
// environment variable, or file:/path, a file (its last line break is not
// part of it; Kubernetes, Docker and Vault Agent secrets work as they are).
func ResolvePassword(ref string) (string, error) {
	kind, where, _ := strings.Cut(ref, ":")
	var v string
	switch kind {
	case "env":
		if where == "" {
			return "", errors.New("env: needs a variable name, like env:SMTP_PASSWORD")
		}
		v = os.Getenv(where)
		if v == "" {
			return "", fmt.Errorf("the environment variable %s is not set (in intergate's environment)", where)
		}
	case "file":
		if !filepath.IsAbs(where) {
			return "", errors.New("file: needs an absolute path, like file:/run/secrets/smtp_password")
		}
		b, err := os.ReadFile(where)
		if err != nil {
			return "", fmt.Errorf("read the password: %w", err)
		}
		if v = strings.TrimRight(string(b), "\r\n"); v == "" {
			return "", fmt.Errorf("%s is empty", where)
		}
	default:
		return "", fmt.Errorf("%q is neither env:NAME nor file:/path", ref)
	}
	return v, nil
}

// The password is sealed with AES-GCM; the version prefix leaves room for
// another scheme.
const (
	sealPrefix = "v1:"
	sealAD     = "smtp password"
)

func (s *Settings) seal(plain string) (string, error) { return sealWith(s.aead, sealAD, plain) }

func (s *Settings) open(sealed string) (string, error) {
	plain, err := openWith(s.aead, sealAD, sealed)
	switch {
	case errors.Is(err, errDamaged):
		return "", inputError("The stored SMTP password is damaged: enter it again.")
	case err != nil:
		return "", inputError("The stored SMTP password can't be read with this data directory's secret key: enter it again.")
	}
	return plain, nil
}

var errDamaged = errors.New("damaged")

func sealWith(aead cipher.AEAD, ad, plain string) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, []byte(plain), []byte(ad))
	return sealPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

func openWith(aead cipher.AEAD, ad, sealed string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, sealPrefix))
	n := aead.NonceSize()
	if !strings.HasPrefix(sealed, sealPrefix) || err != nil || len(raw) < n {
		return "", errDamaged
	}
	plain, err := aead.Open(nil, raw[:n], raw[n:], []byte(ad))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// newAEAD returns AES-256-GCM with a key derived from secret for a purpose.
func newAEAD(secret []byte, purpose string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, secret, nil, purpose, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
