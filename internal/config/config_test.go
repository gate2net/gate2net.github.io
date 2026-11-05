package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const base = `
public_url: https://gate.example.com
ssh:
  listen: ":2222"
auth:
  admins: [Root@Example.com]
  allowed_domains: ["@corp.example"]
  providers:
    - id: github
      type: github
      client_id: id
      client_secret: ${TEST_SECRET}
`

func TestParse(t *testing.T) {
	t.Setenv("TEST_SECRET", "s3cr$t")
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Auth.Providers[0].ClientSecret; got != "s3cr$t" {
		t.Errorf("secret = %q", got)
	}
	if got := cfg.Auth.Providers[0].Name; got != "GitHub" {
		t.Errorf("default provider name = %q", got)
	}
	checks := map[string]string{
		cfg.Domain():                 "gate.example.com",
		cfg.DashboardURL("/x"):       "https://gate.example.com/x",
		cfg.TunnelURL("app"):         "https://app.gate.example.com",
		cfg.SSHHost():                "gate.example.com",
		cfg.Auth.AllowedDomains[0]:   "corp.example",
		cfg.HTTP.Listen:              ":8080",
		cfg.Auth.SessionTTL.String(): "168h0m0s",
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if cfg.SSHPort() != 2222 {
		t.Errorf("SSHPort = %d", cfg.SSHPort())
	}
}

func TestTunnelURLKeepsPort(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cfg, err := Parse([]byte(strings.Replace(base, "https://gate.example.com", "http://localhost:8080", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TunnelURL("app"); got != "http://app.localhost:8080" {
		t.Errorf("TunnelURL = %q", got)
	}
	if cfg.Secure() {
		t.Error("http URL reported as secure")
	}
}

func TestEmailAllowed(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	for email, want := range map[string]bool{
		"root@example.com":     true,
		"ROOT@example.com":     true,
		"dev@corp.example":     true,
		"dev@evilcorp.example": false,
		"dev@corp.example.org": false,
		"":                     false,
	} {
		if got := cfg.EmailAllowed(email); got != want {
			t.Errorf("EmailAllowed(%q) = %v, want %v", email, got, want)
		}
	}
	if !cfg.IsAdmin("root@example.com") || cfg.IsAdmin("dev@corp.example") {
		t.Error("IsAdmin mismatch")
	}
}

func TestParseErrors(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cases := map[string]string{
		"missing env":     strings.Replace(base, "TEST_SECRET", "INTERGATE_UNSET_VAR", 1),
		"unknown field":   base + "bogus: 1\n",
		"ip public_url":   strings.Replace(base, "gate.example.com", "10.0.0.1", 1),
		"path public_url": strings.Replace(base, "gate.example.com", "gate.example.com/x", 1),
		"bad type":        strings.Replace(base, "type: github", "type: saml", 1),
		"tls without https": strings.Replace(base, "https://", "http://", 1) +
			"http:\n  tls:\n    cert_file: a\n    key_file: b\n",
		"tcp not a range":    base + "tcp:\n  ports: lots\n",
		"tcp reversed range": base + "tcp:\n  ports: 30099-30000\n",
		"tcp over http":      base + "tcp:\n  ports: 1-1000\n",
		"tcp too wide":       base + "tcp:\n  ports: 20000-40000\n",
		"tcp no ports":       base + "tcp:\n  ports: 30000-30099\n  max_ports: -1\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestSetupMode checks that a configuration with no sign-in method and
// nobody allowed is valid: the dashboard's setup asks for them.
func TestSetupMode(t *testing.T) {
	cfg, err := Parse([]byte("public_url: https://gate.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.NobodyAllowed() || cfg.Auth.Email.Enabled() || len(cfg.Auth.Providers) > 0 {
		t.Errorf("NobodyAllowed = %v, email = %v", cfg.NobodyAllowed(), cfg.Auth.Email.Enabled())
	}
	t.Setenv("TEST_SECRET", "x")
	if cfg, err := Parse([]byte(base)); err != nil || cfg.NobodyAllowed() {
		t.Errorf("base: NobodyAllowed = %v, %v", cfg != nil && cfg.NobodyAllowed(), err)
	}
	for _, auth := range []string{"admins: [a@example.com]", "allowed_emails: [a@example.com]", "allowed_domains: [example.com]", "allow_everyone: true"} {
		cfg, err := Parse([]byte("public_url: https://gate.example.com\nauth:\n  " + auth + "\n"))
		if err != nil || cfg.NobodyAllowed() {
			t.Errorf("%s: NobodyAllowed = %v, %v", auth, cfg != nil && cfg.NobodyAllowed(), err)
		}
	}
}

func TestTCPPorts(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TCP.Enabled() || cfg.TCP.InRange(30000) {
		t.Error("TCP ports enabled without a range")
	}
	cfg, err = Parse([]byte(base + "tcp:\n  ports: 30000-30099\n"))
	if err != nil {
		t.Fatal(err)
	}
	if first, last := cfg.TCP.Range(); first != 30000 || last != 30099 || cfg.TCP.MaxPorts != 5 {
		t.Errorf("range %d-%d, max %d", first, last, cfg.TCP.MaxPorts)
	}
	if !cfg.TCP.InRange(30099) || cfg.TCP.InRange(30100) {
		t.Error("InRange mismatch")
	}
	if got := cfg.TCPAddress(30042); got != "tcp://gate.example.com:30042" {
		t.Errorf("address = %q", got)
	}
	cfg, _ = Parse([]byte(base + "tcp:\n  ports: \"5000\"\n  public_host: tcp.example.com\n"))
	if first, last := cfg.TCP.Range(); first != 5000 || last != 5000 || cfg.TCPAddress(5000) != "tcp://tcp.example.com:5000" {
		t.Errorf("single port: %d-%d %s", first, last, cfg.TCPAddress(5000))
	}
}

func TestDNS(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	t.Setenv("CF_TOKEN", "cf-secret")
	acme := base + "http:\n  tls:\n    acme: {enabled: true, email: a@example.com}\n"
	cfg, err := Parse([]byte(acme + `dns:
  provider: cloudflare
  wildcard_record: true
  cloudflare:
    api_token: ${CF_TOKEN}
    zone_id: 0123abc
  route53:
    hosted_zone_id: Z1
`))
	if err != nil {
		t.Fatal(err)
	}
	if o := cfg.DNS.Options(); cfg.DNS.Provider != "cloudflare" || o["api_token"] != "cf-secret" || o["zone_id"] != "0123abc" || !cfg.DNS.WildcardRecord {
		t.Errorf("dns %+v", cfg.DNS)
	}
	if cfg.DNS.PropagationTimeout != 2*time.Minute {
		t.Errorf("propagation timeout %s", cfg.DNS.PropagationTimeout)
	}
	cfg, err = Parse([]byte(acme + "dns:\n  nameservers: [ns1.example.net, \"127.0.0.1:8053\", \"::1\"]\n"))
	if err != nil || !slices.Equal(cfg.DNS.Nameservers, []string{"ns1.example.net:53", "127.0.0.1:8053", "[::1]:53"}) {
		t.Errorf("nameservers: %v %v", err, cfg.DNS.Nameservers)
	}
	cfg, err = Parse([]byte(acme))
	if err != nil || cfg.DNS.Provider != "" {
		t.Errorf("no dns: %v %+v", err, cfg.DNS)
	}
	for name, doc := range map[string]string{
		"without acme":     base + "dns:\n  provider: cloudflare\n  cloudflare: {api_token: t}\n",
		"unknown provider": acme + "dns:\n  provider: bind\n",
		"misspelled key":   acme + "dns:\n  provider: cloudflare\n  cloudflare: {api_token: t}\n  cloudfare: {api_token: t}\n",
		"unknown option":   acme + "dns:\n  provider: cloudflare\n  cloudflare: {api_token: t, token: t}\n",
		"missing option":   acme + "dns:\n  provider: cloudflare\n",
		"no provider":      acme + "dns:\n  cloudflare: {api_token: t}\n",
		"bad nameserver":   acme + "dns:\n  nameservers: [\"ns1:http\"]\n",
		"bad timeout":      acme + "dns:\n  provider: cloudflare\n  cloudflare: {api_token: t}\n  propagation_timeout: 1s\n",
		"not a block":      acme + "dns:\n  provider: cloudflare\n  cloudflare: {api_token: t}\n  ttl: 30\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if name == "misspelled key" && !strings.Contains(err.Error(), "dns.cloudfare") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExampleConfig(t *testing.T) {
	t.Setenv("SMTP_PASSWORD", "secret")
	cfg, err := Load("../../intergate.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Auth.Email.Enabled() || !cfg.PasskeysEnabled() || len(cfg.Auth.Providers) != 0 {
		t.Errorf("sign-in methods: email %v, passkeys %v, providers %d", cfg.Auth.Email.Enabled(), cfg.PasskeysEnabled(), len(cfg.Auth.Providers))
	}
}

func TestEnvOnlyInValues(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	if _, err := Parse([]byte("# uses ${NOT_SET_ANYWHERE}\n" + base)); err != nil {
		t.Fatal(err)
	}
}

func TestEnvValues(t *testing.T) {
	t.Setenv("SSH_PORT", "2200")
	doc := strings.Replace(base, "ssh:\n", "ssh:\n  public_port: ${SSH_PORT}\n", 1)
	for _, secret := range []string{"a: b # c 'd\" ${X}", "123456", "true", "  spaced  ", "multi\nline"} {
		t.Setenv("TEST_SECRET", secret)
		cfg, err := Parse([]byte(doc))
		if err != nil {
			t.Errorf("%q: %v", secret, err)
			continue
		}
		if got := cfg.Auth.Providers[0].ClientSecret; got != secret {
			t.Errorf("secret = %q, want %q", got, secret)
		}
		if cfg.SSHPort() != 2200 {
			t.Errorf("port = %d", cfg.SSHPort())
		}
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	dir := t.TempDir()
	path := filepath.Join(dir, "intergate.yaml")
	doc := base + "data_dir: state\nhttp:\n  tls:\n    acme: {enabled: true}\ndns:\n  provider: exec\n  exec:\n    command: hooks/dns.sh\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "state"); cfg.DataDir != want || cfg.Admin.Socket != filepath.Join(want, "admin.sock") {
		t.Errorf("DataDir = %q, socket = %q; want under %q", cfg.DataDir, cfg.Admin.Socket, want)
	}
	if got, want := cfg.DNS.Options()["command"], filepath.Join(dir, "hooks/dns.sh"); got != want {
		t.Errorf("dns.exec.command = %q, want %q", got, want)
	}
}
