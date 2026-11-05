package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jgermade/intergate/internal/acmetest"
	"github.com/jgermade/intergate/internal/admin"
	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/dns"
	"github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/server"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/wildcard"
)

// fakeZones are the zones the fakedns provider changes, by the name its
// zone setting gives: each test's own.
var (
	fakeZonesMu sync.Mutex
	fakeZones   = map[string]*acmetest.Zone{}
)

func init() {
	dns.Register(dns.Spec{
		Name:  "fakedns",
		Title: "Fake DNS",
		Help:  "A zone in the test's memory.",
		Fields: []dns.Field{
			{Name: "zone", Title: "Zone", Required: true},
			{Name: "token", Title: "API token", Required: true, Secret: true},
		},
		New: func(o dns.Options, _ dns.Env) (dns.Provider, error) {
			fakeZonesMu.Lock()
			z := fakeZones[o["zone"]]
			fakeZonesMu.Unlock()
			if z == nil {
				return nil, fmt.Errorf("no zone %q", o["zone"])
			}
			if o["token"] != "good" {
				return refusing{}, nil
			}
			return z, nil
		},
	})
}

// refusing is a DNS provider that takes no change.
type refusing struct{}

func (refusing) Set(context.Context, dns.RecordSet) error {
	return errors.New("fakedns: Invalid access token (HTTP 403)")
}
func (refusing) Delete(context.Context, string, string) error {
	return errors.New("fakedns: Invalid access token (HTTP 403)")
}

// tlsHarness runs a whole server, with HTTPS from a fake Let's Encrypt.
type tlsHarness struct {
	t         *testing.T
	ca        *acmetest.Server
	srv       *server.Server
	cfg       *config.Config
	mail      *mailbox
	httpsAddr string
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func newTLSHarness(t *testing.T, extra string) *tlsHarness {
	t.Helper()
	h := &tlsHarness{t: t, ca: acmetest.NewServer(t), mail: &mailbox{ch: make(chan mail.Message, 10)}}
	fakeZonesMu.Lock()
	fakeZones[t.Name()] = h.ca.Zone
	fakeZonesMu.Unlock()
	httpAddr := freeAddr(t)
	h.httpsAddr = freeAddr(t)
	var err error
	h.cfg, err = config.Parse(fmt.Appendf(nil, `
public_url: https://%s
data_dir: %s
http:
  listen: "%s"
  tls:
    listen: "%s"
    acme: {enabled: true, email: admin@example.com, directory_url: "%s"}
ssh: {listen: "%s"}
auth:
  admins: [admin@example.com]
  email: {log_only: true}
%s`, domain, t.TempDir(), httpAddr, h.httpsAddr, h.ca.URL, freeAddr(t), extra))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	h.srv, err = server.New(h.cfg, log, server.Options{Version: "test", Mailer: h.mail, DNSPropagated: h.ca.Zone.Propagated})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
		h.srv.Close()
	})
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		resp, err := http.Get("http://" + httpAddr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not start: %v", err)
		}
	}
	return h
}

// browser is an HTTPS client that trusts the fake Let's Encrypt and finds
// the domain and its subdomains on the server.
func (h *tlsHarness) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.ca.Roots()},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, _ := net.SplitHostPort(addr); host == domain || strings.HasSuffix(host, "."+domain) {
				addr = h.httpsAddr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

// certificate returns the certificate the server shows for a host.
func (h *tlsHarness) certificate(host string) *x509.Certificate {
	h.t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp", h.httpsAddr, &tls.Config{ServerName: host, RootCAs: h.ca.Roots()})
	if err != nil {
		h.t.Fatalf("TLS to %s: %v", host, err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

func (h *tlsHarness) send(c *http.Client, method, path string, body any, csrf string) (*http.Response, string) {
	h.t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, "https://"+domain+path, bytes.NewReader(data))
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", "https://"+domain)
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp, readBody(h.t, resp)
}

// login signs a browser in with an email code, and returns the page's
// boot data.
func (h *tlsHarness) login(c *http.Client, email string) bootData {
	h.t.Helper()
	if resp, body := h.send(c, "POST", "/api/login/email", map[string]string{"email": email, "rd": "/"}, ""); resp.StatusCode != http.StatusOK {
		h.t.Fatalf("request code: %d %s", resp.StatusCode, body)
	}
	if resp, body := h.send(c, "POST", "/api/login/code", map[string]string{"code": h.mail.code(h.t, email)}, ""); resp.StatusCode != http.StatusOK {
		h.t.Fatalf("enter code: %d %s", resp.StatusCode, body)
	}
	_, body := h.send(c, "GET", "/admin", nil, "")
	return parseBoot(h.t, body)
}

// dnsState is the DNS tab as the Admin page gets it.
type dnsState struct {
	Source         string            `json:"source"`
	Provider       string            `json:"provider"`
	Settings       map[string]string `json:"settings"`
	WildcardRecord bool              `json:"wildcard_record"`
	Editable       bool              `json:"editable"`
	By             string            `json:"by"`
	Certificate    wildcard.Status   `json:"certificate"`
	Providers      []struct {
		Name   string `json:"name"`
		Fields []struct {
			Name string `json:"name"`
		} `json:"fields"`
	} `json:"providers"`
}

func TestWildcardCertificateFromTheDashboard(t *testing.T) {
	h := newTLSHarness(t, "")
	ctx := t.Context()

	// Out of the box, the dashboard has a certificate of its own, from
	// HTTP-01 or TLS-ALPN-01.
	if c := h.certificate(domain); !slices.Equal(c.DNSNames, []string{domain}) {
		t.Fatalf("dashboard certificate for %v", c.DNSNames)
	}

	owner, helper := h.browser(), h.browser()
	ownerBoot := h.login(owner, "admin@example.com")
	if !ownerBoot.Wildcard || ownerBoot.User.Role != "owner" {
		t.Fatalf("boot %+v", ownerBoot)
	}
	// A new subdomain gets its certificate as it is registered, before
	// anyone visits it.
	if resp, body := h.send(owner, "POST", "/api/subdomains", map[string]string{"name": "early"}, ownerBoot.CSRF); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, body)
	}
	waitIssued(t, h.ca, "early."+domain)

	u, _ := h.srv.Store().EnsureUser(ctx, "helper@example.com")
	h.srv.Store().SetUserRole(ctx, u.ID, store.RoleAdmin)
	helperBoot := h.login(helper, "helper@example.com")

	resp, body := h.send(owner, "GET", "/api/admin/dns", nil, ownerBoot.CSRF)
	st := decode[dnsState](t, body)
	if resp.StatusCode != http.StatusOK || st.Source != "" || !st.Editable || st.Certificate.Provider != "" {
		t.Fatalf("before: %d %s", resp.StatusCode, body)
	}
	// What runs programs or reads the server's files is not offered.
	for _, p := range st.Providers {
		if p.Name == "exec" {
			t.Error("the exec provider is offered in the dashboard")
		}
		for _, f := range p.Fields {
			if f.Name == "credentials_file" {
				t.Errorf("%s.credentials_file is offered in the dashboard", p.Name)
			}
		}
	}

	good := map[string]any{"provider": "fakedns", "settings": map[string]string{"zone": t.Name(), "token": "good"}, "wildcard_record": true}
	// Admins see it; owners change it.
	if resp, _ := h.send(helper, "PUT", "/api/admin/dns", good, helperBoot.CSRF); resp.StatusCode != http.StatusForbidden {
		t.Errorf("an admin set the DNS provider: %d", resp.StatusCode)
	}
	if resp, body := h.send(helper, "GET", "/api/admin/dns", nil, helperBoot.CSRF); resp.StatusCode != http.StatusOK || decode[dnsState](t, body).Editable {
		t.Errorf("admin view: %d %s", resp.StatusCode, body)
	}

	// Credentials that can't change the zone are not saved.
	bad := map[string]any{"provider": "fakedns", "settings": map[string]string{"zone": t.Name(), "token": "wrong"}}
	resp, body = h.send(owner, "PUT", "/api/admin/dns", bad, ownerBoot.CSRF)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "could not change the zone") || !strings.Contains(body, "Invalid access token") {
		t.Errorf("bad token: %d %s", resp.StatusCode, body)
	}
	exec := map[string]any{"provider": "exec", "settings": map[string]string{"command": "/bin/sh"}}
	if resp, body := h.send(owner, "PUT", "/api/admin/dns", exec, ownerBoot.CSRF); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "configuration file") {
		t.Errorf("exec: %d %s", resp.StatusCode, body)
	}
	if _, body := h.send(owner, "GET", "/api/admin/dns", nil, ownerBoot.CSRF); decode[dnsState](t, body).Source != "" {
		t.Fatalf("a refused provider was saved: %s", body)
	}

	// A provider that works is saved, and the certificate follows.
	resp, body = h.send(owner, "PUT", "/api/admin/dns", good, ownerBoot.CSRF)
	st = decode[dnsState](t, body)
	if resp.StatusCode != http.StatusOK || st.Source != "dashboard" || st.Provider != "fakedns" || st.Settings["token"] != "stored" ||
		st.Settings["zone"] != t.Name() || st.By != "admin@example.com" || !st.WildcardRecord {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	if v := h.ca.Zone.Values("_intergate-check."+domain, "TXT"); len(v) != 0 {
		t.Errorf("the check's record was left: %v", v)
	}
	for deadline := time.Now().Add(15 * time.Second); st.Certificate.NotAfter.IsZero(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no wildcard certificate: %+v", st.Certificate)
		}
		_, body = h.send(owner, "GET", "/api/admin/dns", nil, ownerBoot.CSRF)
		st = decode[dnsState](t, body)
	}
	if c := st.Certificate; c.Error != "" || c.Provider != "fakedns" || !slices.Contains(c.Names, "*."+domain) || c.Record != "*."+domain+" → "+domain {
		t.Errorf("certificate status %+v", c)
	}
	for _, host := range []string{domain, "myapp." + domain, "unregistered." + domain} {
		if c := h.certificate(host); !slices.Equal(c.DNSNames, []string{domain, "*." + domain}) {
			t.Errorf("%s: certificate for %v", host, c.DNSNames)
		}
	}
	if v := h.ca.Zone.Values("*."+domain, "CNAME"); !slices.Equal(v, []string{domain}) {
		t.Errorf("wildcard record %v", v)
	}
	// With it, new subdomains need no certificate of their own.
	issued := len(h.ca.Issued())
	if resp, body := h.send(owner, "POST", "/api/subdomains", map[string]string{"name": "late"}, ownerBoot.CSRF); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.StatusCode, body)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(h.ca.Issued()); n != issued {
		t.Errorf("%d certificates issued for a subdomain the wildcard covers", n-issued)
	}
	// The token is sealed in the database.
	if raw, _ := h.srv.Store().Setting(ctx, "dns"); strings.Contains(raw, `"good"`) {
		t.Errorf("token stored in the clear: %s", raw)
	}
	// `intergate status` tells about it.
	ast, err := admin.NewClient(h.cfg.Admin.Socket).Status(ctx)
	if err != nil || ast.Certificate == nil || ast.Certificate.NotAfter.IsZero() {
		t.Errorf("admin status: %+v %v", ast, err)
	}

	// Removed, the certificate stays until it expires, not renewed.
	resp, body = h.send(owner, "DELETE", "/api/admin/dns", nil, ownerBoot.CSRF)
	st = decode[dnsState](t, body)
	if resp.StatusCode != http.StatusOK || st.Source != "" || st.Certificate.Provider != "" || st.Certificate.NotAfter.IsZero() {
		t.Errorf("remove: %d %s", resp.StatusCode, body)
	}
	if c := h.certificate("myapp." + domain); !slices.Contains(c.DNSNames, "*."+domain) {
		t.Errorf("after removing: certificate for %v", c.DNSNames)
	}
}

// waitIssued waits until the CA has issued a certificate for exactly host.
func waitIssued(t *testing.T, ca *acmetest.Server, host string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		for _, c := range ca.Issued() {
			if slices.Equal(c.DNSNames, []string{host}) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no certificate issued for %s", host)
		}
	}
}

func TestDNSProviderInConfigFile(t *testing.T) {
	h := newTLSHarness(t, fmt.Sprintf("dns:\n  provider: fakedns\n  fakedns:\n    zone: %s\n    token: good\n", t.Name()))
	owner := h.browser()
	boot := h.login(owner, "admin@example.com")
	var st dnsState
	for deadline := time.Now().Add(15 * time.Second); st.Certificate.NotAfter.IsZero(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no wildcard certificate: %+v", st)
		}
		_, body := h.send(owner, "GET", "/api/admin/dns", nil, boot.CSRF)
		st = decode[dnsState](t, body)
	}
	// Shown, not changed; its secrets are not.
	if st.Source != "config" || st.Editable || st.Settings["token"] != "config" || st.WildcardRecord {
		t.Errorf("config view %+v", st)
	}
	if resp, body := h.send(owner, "DELETE", "/api/admin/dns", nil, boot.CSRF); resp.StatusCode != http.StatusConflict {
		t.Errorf("removed the configuration file's provider: %d %s", resp.StatusCode, body)
	}
	if v := h.ca.Zone.Values("*."+domain, "CNAME"); len(v) != 0 {
		t.Errorf("wildcard record without wildcard_record: %v", v)
	}
}

func TestNoDNSTabWithoutACME(t *testing.T) {
	h := newHarness(t)
	c := h.loggedIn("admin@example.com")
	if resp, _ := call(t, c, "GET", "/api/admin/dns", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("DNS tab without ACME: %d", resp.StatusCode)
	}
	if _, boot := page(t, c, "/admin"); boot.Wildcard {
		t.Error("boot offers the DNS tab without ACME")
	}
}
