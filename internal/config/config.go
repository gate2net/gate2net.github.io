// Package config loads and validates the intergate configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jgermade/intergate/internal/dns"
)

// Config is the top-level configuration.
type Config struct {
	// PublicURL is the external URL of the web dashboard, e.g.
	// https://gate.example.com. Tunnels are served on subdomains of its host:
	// https://<name>.gate.example.com.
	PublicURL string `yaml:"public_url"`
	// DataDir holds the SQLite database, the SSH host key and other state.
	DataDir string `yaml:"data_dir"`

	HTTP   HTTPConfig  `yaml:"http"`
	SSH    SSHConfig   `yaml:"ssh"`
	Auth   AuthConfig  `yaml:"auth"`
	Admin  AdminConfig `yaml:"admin"`
	Limits Limits      `yaml:"limits"`
	TCP    TCPConfig   `yaml:"tcp"`
	DNS    DNSConfig   `yaml:"dns"`

	// ReservedSubdomains are names nobody can register, on top of the
	// built-in list (www, admin, api, ...).
	ReservedSubdomains []string `yaml:"reserved_subdomains"`

	// TrustedProxies are the addresses (IPs or CIDR ranges) the proxies and
	// load balancers in front of intergate connect from. Only they may tell
	// it a client's address: with X-Forwarded-For (http.trust_proxy_headers)
	// or a PROXY protocol header (ssh.proxy_protocol,
	// http.tls.proxy_protocol). Defaults to loopback and private networks.
	TrustedProxies []string `yaml:"trusted_proxies"`

	publicURL *url.URL
	trusted   []netip.Prefix
}

// DefaultTrustedProxies are loopback and private networks: where a proxy on
// the same machine, a container network or a cluster's pods connect from.
var DefaultTrustedProxies = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

// TrustedProxy reports whether a connection from ip may tell intergate a
// client's address.
func (c *Config) TrustedProxy(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range c.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// TrustedProxyRanges returns the trusted proxies as CIDR ranges.
func (c *Config) TrustedProxyRanges() []string {
	out := make([]string, len(c.trusted))
	for i, p := range c.trusted {
		out[i] = p.String()
	}
	return out
}

func (c *Config) parseTrustedProxies() error {
	list := c.TrustedProxies
	if len(list) == 0 {
		list = DefaultTrustedProxies
	}
	c.trusted = nil
	for _, s := range list {
		s = strings.TrimSpace(s)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			ip, ierr := netip.ParseAddr(s)
			if ierr != nil {
				return fmt.Errorf("trusted_proxies: %q is not an IP address or a CIDR range like 10.0.0.0/8", s)
			}
			p = netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())
		}
		c.trusted = append(c.trusted, p.Masked())
	}
	return nil
}

type HTTPConfig struct {
	// Listen is the plain HTTP listen address. When TLS is enabled it only
	// redirects to HTTPS (and answers ACME HTTP-01 challenges).
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
	// TrustProxyHeaders keeps incoming X-Forwarded-For headers, from the
	// trusted_proxies only. Enable it when intergate runs behind a reverse
	// proxy you control.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`
}

type TLSConfig struct {
	Listen string `yaml:"listen"`
	// CertFile and KeyFile point to a certificate valid for both the
	// dashboard host and *.host (a wildcard certificate).
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
	ACME     ACMEConfig `yaml:"acme"`
	// ProxyProtocol expects a PROXY protocol header (v1 or v2) on every
	// HTTPS connection, from a load balancer or a proxy that passes TLS
	// through (Traefik's passthrough), to learn client addresses.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

// Enabled reports whether intergate terminates TLS itself.
func (t TLSConfig) Enabled() bool { return t.ACME.Enabled || t.CertFile != "" }

type ACMEConfig struct {
	// Enabled obtains certificates from Let's Encrypt on demand, for the
	// dashboard host and for every registered subdomain.
	Enabled      bool   `yaml:"enabled"`
	Email        string `yaml:"email"`
	DirectoryURL string `yaml:"directory_url"`
}

// DNSConfig is a DNS provider for the zone of the dashboard's domain:
// intergate gets one Let's Encrypt certificate for the domain and all its
// subdomains through it (with ACME's DNS-01 challenge), instead of one per
// subdomain. Without it, an owner can set one up from the dashboard.
type DNSConfig struct {
	// Provider is cloudflare, gcp, route53, digitalocean or exec.
	Provider string `yaml:"provider"`
	// WildcardRecord also points *.<domain> at the domain, with a CNAME.
	WildcardRecord bool `yaml:"wildcard_record"`
	// PropagationTimeout is how long to wait for the zone's nameservers
	// to serve the challenge's records. Default 2m.
	PropagationTimeout time.Duration `yaml:"propagation_timeout"`
	// Nameservers are asked for the challenge's records instead of the
	// zone's own (found through its NS records): host or host:port.
	Nameservers []string `yaml:"nameservers"`
	// Settings are the providers' settings, each under its name:
	// cloudflare: {api_token: ...}.
	Settings map[string]map[string]string `yaml:",inline"`
}

// Options returns the settings of the chosen provider.
func (d DNSConfig) Options() map[string]string { return d.Settings[d.Provider] }

type SSHConfig struct {
	Listen      string `yaml:"listen"`
	HostKeyFile string `yaml:"host_key_file"`
	// PublicHost and PublicPort are what users type in `ssh -p PORT HOST`.
	// They default to the dashboard host and the listen port.
	PublicHost        string        `yaml:"public_host"`
	PublicPort        int           `yaml:"public_port"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
	// ProxyProtocol expects a PROXY protocol header (v1 or v2) on every
	// SSH connection, e.g. from Traefik or HAProxy, to learn client IPs.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

// TCPConfig gives subdomains raw TCP ports, each forwarded with ssh -R to
// a local service.
type TCPConfig struct {
	// Ports is the public range ports are allocated from, e.g.
	// "30000-30099". Without it, subdomains get no TCP ports.
	Ports string `yaml:"ports"`
	// MaxPorts is how many ports a subdomain can have.
	MaxPorts int `yaml:"max_ports"`
	// ListenHost is the address the ports listen on; all interfaces by
	// default.
	ListenHost string `yaml:"listen_host"`
	// PublicHost is the host in the ports' addresses
	// (tcp://<public_host>:30042). Defaults to the SSH host.
	PublicHost string `yaml:"public_host"`

	first, last int
}

// Enabled reports whether subdomains can have TCP ports.
func (t TCPConfig) Enabled() bool { return t.first != 0 }

// Range returns the first and last public port, or zeros when disabled.
func (t TCPConfig) Range() (first, last int) { return t.first, t.last }

// InRange reports whether port belongs to the public range.
func (t TCPConfig) InRange(port int) bool { return t.first != 0 && port >= t.first && port <= t.last }

func (t *TCPConfig) parse() error {
	if t.Ports == "" {
		return nil
	}
	lo, hi, found := strings.Cut(strings.TrimSpace(t.Ports), "-")
	if !found {
		hi = lo
	}
	first, err1 := strconv.Atoi(strings.TrimSpace(lo))
	last, err2 := strconv.Atoi(strings.TrimSpace(hi))
	switch {
	case err1 != nil || err2 != nil || first < 1 || last > 65535 || first > last:
		return fmt.Errorf("tcp.ports must be a range of ports like 30000-30099, not %q", t.Ports)
	case first <= 443 && last >= 80:
		return errors.New("tcp.ports must not include ports 80 to 443, which tunnels use for HTTP")
	case last-first >= 10000:
		return errors.New("tcp.ports can span at most 10000 ports")
	}
	if t.MaxPorts < 1 {
		return errors.New("tcp.max_ports must be at least 1")
	}
	t.first, t.last = first, last
	return nil
}

type AdminConfig struct {
	// Socket is the Unix socket `intergate config` and `intergate status`
	// use to manage the running server. Defaults to <data_dir>/admin.sock.
	Socket string `yaml:"socket"`
}

type AuthConfig struct {
	SessionTTL time.Duration `yaml:"session_ttl"`
	// AllowEveryone lets any account with a verified email sign in. When
	// false, only AllowedEmails, AllowedDomains and Admins can sign in.
	AllowEveryone  bool     `yaml:"allow_everyone"`
	AllowedEmails  []string `yaml:"allowed_emails"`
	AllowedDomains []string `yaml:"allowed_domains"`
	Admins         []string `yaml:"admins"`

	// Email enables sign-in with a one-time code sent by email.
	Email EmailConfig `yaml:"email"`
	// DisablePasskeys turns off passkey (WebAuthn) sign-in.
	DisablePasskeys bool `yaml:"disable_passkeys"`
	// Providers are optional OAuth sign-in providers.
	Providers []ProviderConfig `yaml:"providers"`
}

type EmailConfig struct {
	// From is the sender, e.g. "intergate <no-reply@gate.example.com>".
	From    string        `yaml:"from"`
	CodeTTL time.Duration `yaml:"code_ttl"`
	SMTP    SMTPConfig    `yaml:"smtp"`
	// LogOnly writes emails to the log instead of sending them. Only for
	// local development: anyone reading the log can sign in.
	LogOnly bool `yaml:"log_only"`
}

// Enabled reports whether email sign-in is configured.
func (e EmailConfig) Enabled() bool { return e.SMTP.Host != "" || e.LogOnly }

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// TLS is "starttls" (default), "tls" (implicit, usually port 465) or
	// "none" (only for a relay on localhost).
	TLS string `yaml:"tls"`
}

type ProviderConfig struct {
	// ID appears in the callback URL: <public_url>/auth/<id>/callback.
	ID string `yaml:"id"`
	// Type is "github" or "oidc".
	Type         string   `yaml:"type"`
	Name         string   `yaml:"name"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`

	// Issuer is the OIDC issuer URL (type oidc).
	Issuer string `yaml:"issuer"`
	// AssumeEmailVerified accepts ID tokens without an email_verified claim.
	// Only enable it for identity providers that verify emails themselves.
	AssumeEmailVerified bool `yaml:"assume_email_verified"`

	// AuthURL, TokenURL and APIURL override the GitHub endpoints, e.g. for
	// GitHub Enterprise Server (type github).
	AuthURL  string `yaml:"auth_url"`
	TokenURL string `yaml:"token_url"`
	APIURL   string `yaml:"api_url"`
}

type Limits struct {
	SubdomainsPerUser    int `yaml:"subdomains_per_user"`
	KeysPerSubdomain     int `yaml:"keys_per_subdomain"`
	TunnelsPerConnection int `yaml:"tunnels_per_connection"`
}

// Load reads the YAML file at path. ${VAR} references are replaced with
// environment variables before parsing, so secrets can stay out of the file.
// Relative paths in the file are resolved against the file's directory.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := parse(raw, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Parse parses and validates a configuration document. Relative paths are
// left as they are, relative to the working directory.
func Parse(raw []byte) (*Config, error) { return parse(raw, "") }

func parse(raw []byte, base string) (*Config, error) {
	// Expand ${VAR} in values only, so comments may mention variables
	// that are not set.
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var missing []string
	expandEnv(&doc, &missing)
	if len(missing) > 0 {
		return nil, fmt.Errorf("config references unset environment variables: %s", strings.Join(missing, ", "))
	}
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.setDefaults()
	if base != "" {
		cfg.resolvePaths(base)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func expandEnv(n *yaml.Node, missing *[]string) {
	if n.Kind == yaml.ScalarNode && envRef.MatchString(n.Value) {
		n.Value = envRef.ReplaceAllStringFunc(n.Value, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				*missing = append(*missing, name)
			}
			return v
		})
		if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 {
			n.Tag = "" // unquoted: resolve the type from the new value
		}
	}
	for _, c := range n.Content {
		expandEnv(c, missing)
	}
}

func (c *Config) setDefaults() {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = ":8080"
	}
	if c.HTTP.TLS.Listen == "" {
		c.HTTP.TLS.Listen = ":8443"
	}
	if c.HTTP.TLS.ACME.DirectoryURL == "" {
		c.HTTP.TLS.ACME.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if c.SSH.Listen == "" {
		c.SSH.Listen = ":2222"
	}
	if c.SSH.KeepaliveInterval == 0 {
		c.SSH.KeepaliveInterval = 30 * time.Second
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = 7 * 24 * time.Hour
	}
	if c.Admin.Socket == "" {
		c.Admin.Socket = filepath.Join(c.DataDir, "admin.sock")
	}
	if c.Auth.Email.CodeTTL == 0 {
		c.Auth.Email.CodeTTL = 10 * time.Minute
	}
	if c.Auth.Email.SMTP.TLS == "" {
		c.Auth.Email.SMTP.TLS = "starttls"
	}
	if c.Auth.Email.SMTP.Port == 0 {
		switch c.Auth.Email.SMTP.TLS {
		case "tls":
			c.Auth.Email.SMTP.Port = 465
		case "none":
			c.Auth.Email.SMTP.Port = 25
		default:
			c.Auth.Email.SMTP.Port = 587
		}
	}
	if c.Limits.SubdomainsPerUser == 0 {
		c.Limits.SubdomainsPerUser = 10
	}
	if c.Limits.KeysPerSubdomain == 0 {
		c.Limits.KeysPerSubdomain = 20
	}
	if c.Limits.TunnelsPerConnection == 0 {
		c.Limits.TunnelsPerConnection = 5
	}
	if c.TCP.MaxPorts == 0 {
		c.TCP.MaxPorts = 5
	}
	if c.DNS.PropagationTimeout == 0 {
		c.DNS.PropagationTimeout = 2 * time.Minute
	}
	for i := range c.Auth.Providers {
		p := &c.Auth.Providers[i]
		if p.Name == "" {
			switch p.Type {
			case "github":
				p.Name = "GitHub"
			default:
				p.Name = p.ID
			}
		}
	}
	c.Auth.AllowedEmails = lowerAll(c.Auth.AllowedEmails)
	c.Auth.AllowedDomains = lowerAll(c.Auth.AllowedDomains)
	c.Auth.Admins = lowerAll(c.Auth.Admins)
}

func (c *Config) resolvePaths(base string) {
	for _, p := range []*string{&c.DataDir, &c.HTTP.TLS.CertFile, &c.HTTP.TLS.KeyFile, &c.SSH.HostKeyFile, &c.Admin.Socket} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	// The DNS providers' files too: dns.exec.command and the like.
	for name, opts := range c.DNS.Settings {
		spec, _ := dns.Lookup(name)
		for _, f := range spec.Fields {
			if v := opts[f.Name]; f.Path && v != "" && !filepath.IsAbs(v) {
				opts[f.Name] = filepath.Join(base, v)
			}
		}
	}
}

var providerID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func (c *Config) validate() error {
	if c.PublicURL == "" {
		return errors.New("public_url is required")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return fmt.Errorf("public_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("public_url must start with http:// or https://")
	}
	if u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return errors.New("public_url must be a bare origin like https://gate.example.com")
	}
	if net.ParseIP(u.Hostname()) != nil {
		return errors.New("public_url must use a hostname, not an IP address: tunnels live on its subdomains")
	}
	u.Path = ""
	u.Host = strings.ToLower(u.Host)
	c.publicURL = u

	tls := c.HTTP.TLS
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		return errors.New("http.tls: cert_file and key_file must be set together")
	}
	if tls.CertFile != "" && tls.ACME.Enabled {
		return errors.New("http.tls: use either cert_file/key_file or acme, not both")
	}
	if tls.Enabled() && u.Scheme != "https" {
		return errors.New("public_url must use https:// when http.tls is enabled")
	}
	if tls.ProxyProtocol && !tls.Enabled() {
		return errors.New("http.tls.proxy_protocol needs http.tls: acme or cert_file and key_file")
	}

	// Without a sign-in method or anyone who may sign in, intergate starts
	// in setup mode: the dashboard asks for them (see package settings).
	if smtp := c.Auth.Email.SMTP; smtp.Host != "" {
		if c.Auth.Email.From == "" {
			return errors.New("auth.email.from is required to send sign-in codes")
		}
		if _, err := mail.ParseAddress(c.Auth.Email.From); err != nil {
			return fmt.Errorf("auth.email.from: %w", err)
		}
		switch smtp.TLS {
		case "starttls", "tls", "none":
		default:
			return errors.New("auth.email.smtp.tls must be starttls, tls or none")
		}
	}
	if c.Auth.Email.CodeTTL < time.Minute || c.Auth.Email.CodeTTL > time.Hour {
		return errors.New("auth.email.code_ttl must be between 1m and 1h")
	}
	seen := map[string]bool{}
	for i, p := range c.Auth.Providers {
		where := fmt.Sprintf("auth.providers[%d]", i)
		if !providerID.MatchString(p.ID) {
			return fmt.Errorf("%s.id must match %s", where, providerID)
		}
		if seen[p.ID] {
			return fmt.Errorf("%s: duplicate id %q", where, p.ID)
		}
		seen[p.ID] = true
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("%s: client_id and client_secret are required", where)
		}
		switch p.Type {
		case "github":
		case "oidc":
			if p.Issuer == "" {
				return fmt.Errorf("%s: issuer is required for oidc providers", where)
			}
		default:
			return fmt.Errorf("%s.type must be github or oidc", where)
		}
	}
	if err := c.validateDNS(); err != nil {
		return err
	}
	if err := c.parseTrustedProxies(); err != nil {
		return err
	}
	return c.TCP.parse()
}

func (c *Config) validateDNS() error {
	d := c.DNS
	for name := range d.Settings {
		if _, ok := dns.Lookup(name); !ok {
			return fmt.Errorf("dns.%s: unknown setting or DNS provider (providers: %s)", name, strings.Join(dns.Names(), ", "))
		}
	}
	if d.PropagationTimeout < 10*time.Second || d.PropagationTimeout > time.Hour {
		return errors.New("dns.propagation_timeout must be between 10s and 1h")
	}
	for i, ns := range d.Nameservers {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			ns = net.JoinHostPort(strings.Trim(ns, "[]"), "53")
		}
		host, port, err := net.SplitHostPort(ns)
		if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("dns.nameservers: %q is not a host or host:port", d.Nameservers[i])
		}
		c.DNS.Nameservers[i] = ns
	}
	if d.Provider == "" {
		if len(d.Settings) > 0 || d.WildcardRecord {
			return errors.New("dns.provider is required with dns settings")
		}
		return nil
	}
	if !c.HTTP.TLS.ACME.Enabled {
		return errors.New("dns: a DNS provider gets intergate a wildcard certificate from Let's Encrypt: enable http.tls.acme")
	}
	if _, ok := dns.Lookup(d.Provider); !ok {
		return fmt.Errorf("dns.provider: unknown DNS provider %q (one of %s)", d.Provider, strings.Join(dns.Names(), ", "))
	}
	if err := dns.Validate(d.Provider, d.Options()); err != nil {
		return fmt.Errorf("dns.%w", err)
	}
	return nil
}

// PasskeysEnabled reports whether users can sign in with passkeys.
func (c *Config) PasskeysEnabled() bool { return !c.Auth.DisablePasskeys }

// Domain is the dashboard host without port; tunnels are its subdomains.
func (c *Config) Domain() string { return c.publicURL.Hostname() }

// Scheme is the scheme of the public URL, "http" or "https".
func (c *Config) Scheme() string { return c.publicURL.Scheme }

// Secure reports whether the public URL uses HTTPS.
func (c *Config) Secure() bool { return c.publicURL.Scheme == "https" }

// DashboardURL returns an absolute URL on the dashboard for path.
func (c *Config) DashboardURL(path string) string {
	return c.publicURL.Scheme + "://" + c.publicURL.Host + path
}

// TunnelHost returns the host (with port, if the public URL has one) that
// serves the given subdomain.
func (c *Config) TunnelHost(name string) string {
	h := name + "." + c.Domain()
	if p := c.publicURL.Port(); p != "" {
		h += ":" + p
	}
	return h
}

// TunnelURL returns the public URL of a subdomain.
func (c *Config) TunnelURL(name string) string {
	return c.publicURL.Scheme + "://" + c.TunnelHost(name)
}

// SSHHost is the host users connect to with ssh.
func (c *Config) SSHHost() string {
	if c.SSH.PublicHost != "" {
		return c.SSH.PublicHost
	}
	return c.Domain()
}

// SSHPort is the port users connect to with ssh.
func (c *Config) SSHPort() int {
	if c.SSH.PublicPort != 0 {
		return c.SSH.PublicPort
	}
	_, p, err := net.SplitHostPort(c.SSH.Listen)
	if err != nil {
		return 22
	}
	n, err := strconv.Atoi(p)
	if err != nil || n == 0 {
		return 22
	}
	return n
}

// TCPHost is the host in TCP ports' addresses.
func (c *Config) TCPHost() string {
	if c.TCP.PublicHost != "" {
		return c.TCP.PublicHost
	}
	return c.SSHHost()
}

// TCPAddress is the public address of a TCP port, e.g.
// tcp://gate.example.com:30042.
func (c *Config) TCPAddress(port int) string { return c.PortAddress("tcp", port) }

// PortAddress is the public address of a port of a protocol, "tcp" or
// "udp": udp://gate.example.com:30043.
func (c *Config) PortAddress(protocol string, port int) string {
	return protocol + "://" + net.JoinHostPort(c.TCPHost(), strconv.Itoa(port))
}

// NobodyAllowed reports whether the configuration lets no one sign in: no
// admins, allowed emails or domains, and not everyone. Only accounts the
// database gives access to can then sign in.
func (c *Config) NobodyAllowed() bool {
	return !c.Auth.AllowEveryone && len(c.Auth.AllowedEmails)+len(c.Auth.AllowedDomains)+len(c.Auth.Admins) == 0
}

// IsAdmin reports whether email belongs to an administrator.
func (c *Config) IsAdmin(email string) bool {
	return contains(c.Auth.Admins, strings.ToLower(email))
}

// EmailAllowed reports whether a user with this (verified) email may sign
// in and keep using intergate.
func (c *Config) EmailAllowed(email string) bool {
	email = strings.ToLower(email)
	if email == "" {
		return false
	}
	if c.Auth.AllowEveryone || c.IsAdmin(email) || contains(c.Auth.AllowedEmails, email) {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	return at >= 0 && contains(c.Auth.AllowedDomains, email[at+1:])
}

// UserRole is an account's role: "owner" for addresses in auth.admins,
// otherwise the one stored for it ("user", "admin" or "owner").
func (c *Config) UserRole(email, stored string) string {
	if c.IsAdmin(email) {
		return "owner"
	}
	if stored == "" {
		return "user"
	}
	return stored
}

// UserAllowed reports whether an account may sign in and keep using
// intergate: the configuration allows its email, or an administrator added
// it or gave it a role.
func (c *Config) UserAllowed(email string, added bool, stored string) bool {
	return added || c.UserRole(email, stored) != "user" || c.EmailAllowed(email)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, strings.TrimPrefix(s, "@"))
		}
	}
	return out
}
