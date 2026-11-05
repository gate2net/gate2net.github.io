// Package wildcard keeps one certificate for intergate's domain and all its
// subdomains (gate.example.com and *.gate.example.com), issued by an ACME
// certificate authority such as Let's Encrypt through the DNS-01 challenge:
// a DNS provider (package dns) adds the TXT records the authority looks up.
//
// It works next to autocert's certificates for each host, issued on demand
// with HTTP-01 or TLS-ALPN-01: those keep the dashboard working until the
// wildcard certificate is there, and after a DNS provider is removed.
package wildcard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/jgermade/intergate/internal/dns"
)

// Options configure a Manager.
type Options struct {
	// Domain is the dashboard's host; the certificate covers it and
	// *.Domain.
	Domain string
	// Email is the ACME account's contact.
	Email        string
	DirectoryURL string
	// Dir keeps the ACME account key and the certificate.
	Dir        string
	HTTPClient *http.Client
	Log        *slog.Logger
	// Propagated waits until the zone's nameservers serve TXT values.
	// dns.Propagation(2m) by default.
	Propagated func(ctx context.Context, name string, values []string) error
	// Now is the clock; time.Now by default.
	Now func() time.Time
}

// Provider is the DNS provider the certificate is issued through.
type Provider struct {
	dns.Provider
	// Name is the provider's name, for its status: cloudflare.
	Name string
	// WildcardRecord also points *.Domain at Domain, with a CNAME.
	WildcardRecord bool
}

// Status describes the certificate and its renewal.
type Status struct {
	// Provider is the DNS provider renewals go through, or "".
	Provider string `json:"provider,omitempty"`
	// Issuing is set while a certificate is being issued; Step says what
	// it is doing.
	Issuing bool   `json:"issuing,omitempty"`
	Step    string `json:"step,omitempty"`
	// The certificate, when there is one.
	Names     []string  `json:"names,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	RenewAt   time.Time `json:"renew_at,omitzero"`
	// Error is why the last try failed, and NextTry when it is tried
	// again.
	Error   string    `json:"error,omitempty"`
	ErrorAt time.Time `json:"error_at,omitzero"`
	NextTry time.Time `json:"next_try,omitzero"`
	// Record says what became of the wildcard record, when asked for:
	// "*.gate.example.com → gate.example.com", or why it failed.
	Record      string `json:"record,omitempty"`
	RecordError string `json:"record_error,omitempty"`
}

// Manager issues and renews the certificate.
type Manager struct {
	o       Options
	names   []string
	certPEM string
	keyPEM  string
	wake    chan struct{}

	mu       sync.Mutex
	provider *Provider
	cert     *tls.Certificate
	leaf     *x509.Certificate
	status   Status
	failures int
	// recordDone is set once the wildcard record is in place for the
	// current provider.
	recordDone bool
	cancel     context.CancelFunc
	client     *acme.Client
}

// New loads the certificate kept in o.Dir, if any.
func New(o Options) (*Manager, error) {
	if o.Domain == "" {
		return nil, errors.New("wildcard: no domain")
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Propagated == nil {
		o.Propagated = dns.Propagation(2 * time.Minute)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{
		o:       o,
		names:   []string{o.Domain, "*." + o.Domain},
		certPEM: filepath.Join(o.Dir, o.Domain+".crt"),
		keyPEM:  filepath.Join(o.Dir, o.Domain+".key"),
		wake:    make(chan struct{}, 1),
	}
	if cert, err := tls.LoadX509KeyPair(m.certPEM, m.keyPEM); err == nil {
		if err := m.use(&cert); err != nil {
			o.Log.Warn("ignoring the stored wildcard certificate", "err", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		o.Log.Warn("ignoring the stored wildcard certificate", "err", err)
	}
	return m, nil
}

// use makes cert the one served, if it covers the domain and *.domain.
func (m *Manager) use(cert *tls.Certificate) error {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	for _, n := range m.names {
		if leaf.VerifyHostname(strings.Replace(n, "*", "x", 1)) != nil {
			return fmt.Errorf("it does not cover %s", n)
		}
	}
	cert.Leaf = leaf
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert, m.leaf = cert, leaf
	m.status.Names = leaf.DNSNames
	m.status.Issuer = leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		m.status.Issuer = strings.TrimSpace(leaf.Issuer.Organization[0] + " " + leaf.Issuer.CommonName)
	}
	m.status.NotBefore, m.status.NotAfter = leaf.NotBefore, leaf.NotAfter
	m.status.RenewAt = renewAt(leaf)
	return nil
}

// renewAt is when a certificate is renewed: with a third of its life left,
// 30 days for Let's Encrypt's 90-day certificates.
func renewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
}

// Configure sets the DNS provider certificates are issued through, and
// gets one now if there is none or it is due. nil stops renewals: the
// certificate is served until it expires, and hosts get certificates of
// their own after that.
func (m *Manager) Configure(p *Provider) {
	m.mu.Lock()
	m.provider = p
	m.failures, m.recordDone = 0, false
	m.status.Provider, m.status.Error, m.status.ErrorAt, m.status.NextTry = "", "", time.Time{}, time.Time{}
	m.status.Record, m.status.RecordError = "", ""
	if p != nil {
		m.status.Provider = p.Name
	}
	if m.cancel != nil {
		m.cancel() // a try with the previous provider
	}
	m.mu.Unlock()
	m.poke()
}

// Broken stops renewals because the DNS provider with a name can't be
// used, and says why in the status.
func (m *Manager) Broken(name string, err error) {
	m.Configure(nil)
	m.mu.Lock()
	m.status.Provider, m.status.Error, m.status.ErrorAt = name, "The DNS provider can't be used: "+err.Error(), m.o.Now()
	m.mu.Unlock()
}

// Retry tries again now after a failure.
func (m *Manager) Retry() {
	m.mu.Lock()
	m.status.NextTry = time.Time{}
	m.failures = 0
	m.mu.Unlock()
	m.poke()
}

func (m *Manager) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Status describes the certificate and its renewal.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Names = append([]string(nil), s.Names...)
	return s
}

// Certificate returns the wildcard certificate for a TLS handshake, or nil
// when there is none, it has expired or does not cover the host: the
// caller then falls back to a certificate of the host's own.
func (m *Manager) Certificate(hello *tls.ClientHelloInfo) *tls.Certificate {
	m.mu.Lock()
	cert, leaf := m.cert, m.leaf
	m.mu.Unlock()
	if cert == nil || !m.o.Now().Before(leaf.NotAfter) {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	sub, ok := strings.CutSuffix(host, "."+m.o.Domain)
	if host != m.o.Domain && (!ok || sub == "" || strings.Contains(sub, ".")) {
		return nil
	}
	return cert
}

// Run issues and renews the certificate until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	for {
		due, ok := m.due()
		var timer *time.Timer
		var fire <-chan time.Time
		if ok {
			timer = time.NewTimer(max(0, due.Sub(m.o.Now())))
			fire = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-m.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-fire:
		}
		m.try(ctx)
	}
}

// due returns when to act next, if there is a provider.
func (m *Manager) due() (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider == nil {
		return time.Time{}, false
	}
	now := m.o.Now()
	if !m.status.NextTry.IsZero() {
		return m.status.NextTry, true
	}
	if m.provider.WildcardRecord && !m.recordDone || m.leaf == nil {
		return now, true
	}
	// Twelve hours at most, in case the clock jumps.
	return minTime(m.status.RenewAt, now.Add(12*time.Hour)), true
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// try sets the wildcard record and renews the certificate if they are due.
func (m *Manager) try(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	m.mu.Lock()
	p := m.provider
	if p == nil {
		m.mu.Unlock()
		return
	}
	m.cancel = cancel
	needRecord := p.WildcardRecord && !m.recordDone
	needCert := m.leaf == nil || !m.o.Now().Before(m.status.RenewAt)
	m.status.NextTry = time.Time{}
	m.mu.Unlock()

	var failed error
	if needRecord {
		failed = m.wildcardRecord(ctx, p)
	}
	if needCert {
		m.setStep("Starting")
		cert, err := m.obtain(ctx, p)
		if err == nil {
			err = m.use(cert)
		}
		m.mu.Lock()
		m.status.Issuing, m.status.Step = false, ""
		switch {
		case err == nil:
			m.status.Error, m.status.ErrorAt = "", time.Time{}
			m.o.Log.Info("wildcard certificate issued", "names", strings.Join(m.names, ","), "provider", p.Name, "expires", m.status.NotAfter.Format(time.DateOnly))
		case m.provider == p: // not cancelled by a new provider
			m.status.Error, m.status.ErrorAt = err.Error(), m.o.Now()
			failed = err
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider != p {
		return // reconfigured meanwhile: the next try is the new provider's
	}
	if failed == nil {
		m.failures = 0
		return
	}
	// 5, 10, 20, 40 minutes, then every hour: Let's Encrypt allows 5
	// failed validations of a name an hour.
	m.failures++
	wait := min(5*time.Minute<<min(m.failures-1, 4), time.Hour)
	m.status.NextTry = m.o.Now().Add(wait)
	m.o.Log.Warn("wildcard certificate: will try again", "provider", p.Name, "err", failed, "in", wait)
}

func (m *Manager) setStep(step string) {
	m.mu.Lock()
	m.status.Issuing, m.status.Step = true, step
	m.mu.Unlock()
}

// wildcardRecord points *.domain at the domain: a CNAME, in place of any
// A or AAAA records the name had.
func (m *Manager) wildcardRecord(ctx context.Context, p *Provider) error {
	name := "*." + m.o.Domain
	err := p.Delete(ctx, name, "A")
	if err == nil {
		err = p.Delete(ctx, name, "AAAA")
	}
	if err == nil {
		err = p.Set(ctx, dns.RecordSet{Name: name, Type: "CNAME", TTL: 300, Values: []string{m.o.Domain}})
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.provider != p {
		return nil
	}
	if err != nil {
		err = fmt.Errorf("point %s at %s: %w", name, m.o.Domain, err)
		m.status.Record, m.status.RecordError = "", err.Error()
		return err
	}
	m.recordDone = true
	m.status.Record, m.status.RecordError = name+" → "+m.o.Domain, ""
	m.o.Log.Info("wildcard record set", "name", name, "cname", m.o.Domain)
	return nil
}

// acmeClient returns the ACME client, with its account registered.
func (m *Manager) acmeClient(ctx context.Context) (*acme.Client, error) {
	m.mu.Lock()
	c := m.client
	m.mu.Unlock()
	if c != nil {
		return c, nil
	}
	key, err := loadOrCreateKey(filepath.Join(m.o.Dir, "account.key"))
	if err != nil {
		return nil, fmt.Errorf("ACME account key: %w", err)
	}
	c = &acme.Client{Key: key, DirectoryURL: m.o.DirectoryURL, HTTPClient: m.o.HTTPClient, UserAgent: "intergate"}
	var contact []string
	if m.o.Email != "" {
		contact = []string{"mailto:" + m.o.Email}
	}
	if _, err := c.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("ACME account: %w", err)
	}
	m.mu.Lock()
	m.client = c
	m.mu.Unlock()
	return c, nil
}

// obtain gets a certificate for the domain and *.domain, and stores it.
func (m *Manager) obtain(ctx context.Context, p *Provider) (*tls.Certificate, error) {
	client, err := m.acmeClient(ctx)
	if err != nil {
		return nil, err
	}
	m.setStep("Ordering the certificate")
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.names...))
	if err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	type pending struct {
		authz string
		chal  *acme.Challenge
	}
	var todo []pending
	txt := map[string][]string{}
	for _, u := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue // still valid from an earlier certificate
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("the certificate authority offers no DNS-01 challenge for %s", z.Identifier.Value)
		}
		v, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}
		name := dns.ChallengeName(z.Identifier.Value)
		txt[name] = append(txt[name], v)
		todo = append(todo, pending{z.URI, chal})
	}
	if len(todo) > 0 {
		m.setStep("Adding the challenge's TXT records")
		for name, values := range txt {
			if err := p.Set(ctx, dns.RecordSet{Name: name, Type: "TXT", TTL: 60, Values: values}); err != nil {
				return nil, fmt.Errorf("add the TXT records of %s: %w", name, err)
			}
			defer func() {
				// Cleaned up even when ctx is done.
				cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer cancel()
				if err := p.Delete(cctx, name, "TXT"); err != nil {
					m.o.Log.Warn("remove the challenge's TXT records", "name", name, "err", err)
				}
			}()
		}
		m.setStep("Waiting for the nameservers to serve the TXT records")
		for name, values := range txt {
			if err := m.o.Propagated(ctx, name, values); err != nil {
				return nil, err
			}
		}
		m.setStep("Waiting for the certificate authority to check them")
		for _, t := range todo {
			if _, err := client.Accept(ctx, t.chal); err != nil {
				return nil, fmt.Errorf("challenge: %w", err)
			}
		}
		for _, t := range todo {
			if _, err := client.WaitAuthorization(ctx, t.authz); err != nil {
				return nil, fmt.Errorf("the certificate authority did not accept the challenge: %w", err)
			}
		}
	}
	m.setStep("Getting the certificate")
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: m.o.Domain}, DNSNames: m.names}, key)
	if err != nil {
		return nil, err
	}
	der, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	var chain []byte
	for _, b := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, err
	}
	// The key first: a certificate without its key would not load.
	if err := writeFile(m.keyPEM, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(m.certPEM, chain, 0o644); err != nil {
		return nil, err
	}
	return &cert, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s is not a PEM key", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}
