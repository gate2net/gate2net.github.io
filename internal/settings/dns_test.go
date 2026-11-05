package settings

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDNS(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, _ := open(t, "", st, secret)
	if name, _, _, err := s.DNSProvider(); name != "" || err != nil || s.DNSSource() != SourceNone {
		t.Fatalf("a DNS provider before any: %q %v", name, err)
	}

	// Required settings, and only the provider's.
	var ie *InputError
	if _, err := s.PrepareDNS("cloudflare", map[string]string{}, false, "o@example.com"); !errors.As(err, &ie) || err.Error() != "Enter the API token." {
		t.Errorf("missing token: %v", err)
	}
	if _, err := s.PrepareDNS("cloudflare", map[string]string{"api_token": "t", "token": "x"}, false, ""); !errors.As(err, &ie) {
		t.Errorf("unknown setting: %v", err)
	}
	if _, err := s.PrepareDNS("bind9", nil, false, ""); !errors.As(err, &ie) {
		t.Errorf("unknown provider: %v", err)
	}
	// Nothing that runs a program or reads a file of the server.
	if _, err := s.PrepareDNS("exec", map[string]string{"command": "/bin/sh"}, false, ""); !errors.As(err, &ie) || !strings.Contains(err.Error(), "configuration file") {
		t.Errorf("exec from the dashboard: %v", err)
	}
	if _, err := s.PrepareDNS("gcp", map[string]string{"project": "p", "credentials_file": "/etc/shadow"}, false, ""); !errors.As(err, &ie) {
		t.Errorf("a file from the dashboard: %v", err)
	}

	c, err := s.PrepareDNS("cloudflare", map[string]string{"api_token": " cf-secret ", "zone_id": "z1"}, true, "o@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Options(); o["api_token"] != "cf-secret" || o["zone_id"] != "z1" || !c.WildcardRecord() {
		t.Errorf("change options %v", o)
	}
	if err := s.ApplyDNS(ctx, c); err != nil {
		t.Fatal(err)
	}
	// The token is not stored in the clear.
	raw, _ := st.Setting(ctx, dnsKey)
	if strings.Contains(raw, "cf-secret") || !strings.Contains(raw, `"zone_id":"z1"`) {
		t.Errorf("stored %s", raw)
	}

	// After a restart, it is all there; an empty token keeps the stored one.
	s, _ = open(t, "", st, secret)
	name, opts, wr, err := s.DNSProvider()
	if name != "cloudflare" || opts["api_token"] != "cf-secret" || !wr || err != nil || s.DNSSource() != SourceDashboard {
		t.Fatalf("reloaded: %s %v %v %v", name, opts, wr, err)
	}
	if d := s.DNS(); d.By != "o@example.com" || d.At.IsZero() {
		t.Errorf("saved by %+v", d)
	}
	c, err = s.PrepareDNS("cloudflare", map[string]string{"api_token": "", "zone_id": ""}, false, "")
	if err != nil || c.Options()["api_token"] != "cf-secret" || c.Options()["zone_id"] != "" {
		t.Errorf("kept token: %v %v", c, err)
	}
	// Not for another provider.
	if _, err := s.PrepareDNS("digitalocean", map[string]string{"api_token": ""}, false, ""); err == nil {
		t.Error("a secret carried over to another provider")
	}

	// Another secret key can't read it.
	other, _ := open(t, "", st, strings.Repeat("x", 32))
	if _, _, _, err := other.DNSProvider(); !errors.As(err, &ie) || !strings.Contains(err.Error(), "API token") {
		t.Errorf("other key: %v", err)
	}

	if err := s.DeleteDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if s.DNSSource() != SourceNone {
		t.Error("still set up after DeleteDNS")
	}

	// The configuration file wins.
	t.Setenv("DO_TOKEN", "do-secret")
	s, _ = open(t, "http:\n  tls:\n    acme: {enabled: true}\ndns:\n  provider: digitalocean\n  digitalocean:\n    api_token: ${DO_TOKEN}\n", st, secret)
	if name, opts, _, _ := s.DNSProvider(); name != "digitalocean" || opts["api_token"] != "do-secret" || s.DNSSource() != SourceConfig {
		t.Errorf("config: %s %v", name, opts)
	}
	if _, err := s.PrepareDNS("cloudflare", map[string]string{"api_token": "t"}, false, ""); err == nil {
		t.Error("changed a provider set in the configuration file")
	}
}
