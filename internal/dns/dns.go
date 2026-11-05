// Package dns changes records in the DNS zone of intergate's domain
// through a DNS provider's API: the TXT records of ACME's DNS-01 challenge,
// which get one wildcard certificate for the domain and all its subdomains,
// and the records that point the domain and *.domain at intergate.
//
// Providers are plugins: each one registers a Spec, with the settings it
// takes, from its own file. The exec provider runs a program of the user's,
// for any DNS service without a built-in provider.
package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// RecordSet is every record of one name and type.
type RecordSet struct {
	// Name is fully qualified, without the final dot:
	// _acme-challenge.gate.example.com or *.gate.example.com.
	Name string
	// Type is A, AAAA, CNAME or TXT.
	Type string
	// TTL is in seconds.
	TTL int
	// Values are the records' data: addresses, a host name (CNAME) or
	// unquoted text (TXT).
	Values []string
}

func (rs RecordSet) String() string {
	return fmt.Sprintf("%s %s %s", rs.Name, rs.Type, strings.Join(rs.Values, " "))
}

// Provider changes records through a DNS service's API.
type Provider interface {
	// Set replaces every record of rs.Name and rs.Type with rs.Values.
	Set(ctx context.Context, rs RecordSet) error
	// Delete removes every record of a name and type. There being none is
	// not an error.
	Delete(ctx context.Context, name, typ string) error
}

// Options are a provider's settings, from its block of the configuration:
// dns.cloudflare.api_token and so on.
type Options map[string]string

// Env is what providers get from intergate.
type Env struct {
	// HTTPClient reaches the provider's API.
	HTTPClient *http.Client
	Log        *slog.Logger
}

// Field is one setting a provider takes.
type Field struct {
	// Name is the key in the provider's block: api_token.
	Name string
	// Title and Description are what `intergate config` asks.
	Title       string
	Description string
	Required    bool
	// Secret settings are credentials: the configuration had better take
	// them from the environment, as ${Env}.
	Secret bool
	// Env is the environment variable suggested for a secret.
	Env string
	// Upload settings hold a file's content, such as a key in JSON: the
	// dashboard asks for the file.
	Upload bool
	// ConfigOnly settings point at the server's files: only the
	// configuration file sets them, never the dashboard.
	ConfigOnly bool
	// Path settings are files: a relative path is relative to the
	// configuration file.
	Path bool
}

// Spec describes a provider and builds it.
type Spec struct {
	// Name is what dns.provider takes, and the key of its settings' block.
	Name string
	// Title names the DNS service: Cloudflare.
	Title string
	// Summary says in a few words what it asks for: "An API token".
	Summary string
	// Help says what credentials it needs and where they come from.
	Help   string
	Fields []Field
	// ConfigOnly providers run programs on the server: only the
	// configuration file sets them, never the dashboard.
	ConfigOnly bool
	// Check validates settings beyond required fields, without reaching
	// the provider. Optional.
	Check func(Options) error
	New   func(Options, Env) (Provider, error)
}

var (
	specsMu sync.RWMutex
	specs   = map[string]Spec{}
)

// Register adds a provider. Built-in providers register from their files.
func Register(s Spec) {
	specsMu.Lock()
	defer specsMu.Unlock()
	if _, dup := specs[s.Name]; dup {
		panic("dns: provider " + s.Name + " registered twice")
	}
	specs[s.Name] = s
}

// Providers returns every provider, by name.
func Providers() []Spec {
	specsMu.RLock()
	defer specsMu.RUnlock()
	out := make([]Spec, 0, len(specs))
	for _, s := range specs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns the providers' names, sorted.
func Names() []string {
	var out []string
	for _, s := range Providers() {
		out = append(out, s.Name)
	}
	return out
}

// Lookup returns the provider with a name.
func Lookup(name string) (Spec, bool) {
	specsMu.RLock()
	defer specsMu.RUnlock()
	s, ok := specs[name]
	return s, ok
}

// Validate checks a provider's settings without reaching it.
func Validate(name string, opts Options) error {
	s, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("unknown DNS provider %q (one of %s)", name, strings.Join(Names(), ", "))
	}
	known := map[string]bool{}
	for _, f := range s.Fields {
		known[f.Name] = true
		if f.Required && strings.TrimSpace(opts[f.Name]) == "" {
			return fmt.Errorf("%s.%s is required", name, f.Name)
		}
	}
	for k := range opts {
		if !known[k] {
			var all []string
			for _, f := range s.Fields {
				all = append(all, f.Name)
			}
			return fmt.Errorf("%s has no setting %q (it takes %s)", name, k, strings.Join(all, ", "))
		}
	}
	if s.Check != nil {
		if err := s.Check(opts); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// New builds the provider with a name.
func New(name string, opts Options, env Env) (Provider, error) {
	if err := Validate(name, opts); err != nil {
		return nil, err
	}
	if env.HTTPClient == nil {
		env.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if env.Log == nil {
		env.Log = slog.New(slog.DiscardHandler)
	}
	s, _ := Lookup(name)
	return s.New(opts, env)
}

// ChallengeName is the name of the TXT records of ACME's DNS-01 challenge
// for a domain, and for its wildcard.
func ChallengeName(domain string) string { return "_acme-challenge." + domain }

// Canonical lowercases a name and drops its final dot.
func Canonical(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// zoneCandidates are the zones a name could belong to, the most specific
// first: gate.example.com and example.com for *.gate.example.com or
// _acme-challenge.gate.example.com. Top-level domains are left out.
func zoneCandidates(name string) []string {
	name = strings.TrimPrefix(Canonical(name), "*.")
	labels := strings.Split(name, ".")
	var out []string
	for i := 0; i+1 < len(labels); i++ {
		// _acme-challenge and the like name records, not zones.
		if !strings.HasPrefix(labels[i], "_") {
			out = append(out, strings.Join(labels[i:], "."))
		}
	}
	return out
}

// relative is name relative to its zone, "@" for the apex.
func relative(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

// zoneCache remembers the zone of each name, so the provider is asked once.
type zoneCache struct {
	mu    sync.Mutex
	zones map[string]zone
}

type zone struct {
	ID   string
	Name string
}

// find returns the zone of name: lookup is asked about each candidate,
// the most specific first, and answers ok for the one the account has.
func (c *zoneCache) find(ctx context.Context, name string, lookup func(ctx context.Context, candidate string) (z zone, ok bool, err error)) (zone, error) {
	name = Canonical(name)
	c.mu.Lock()
	z, ok := c.zones[name]
	c.mu.Unlock()
	if ok {
		return z, nil
	}
	for _, cand := range zoneCandidates(name) {
		z, ok, err := lookup(ctx, cand)
		if err != nil {
			return zone{}, err
		}
		if ok {
			if z.Name == "" {
				z.Name = cand
			}
			c.mu.Lock()
			if c.zones == nil {
				c.zones = map[string]zone{}
			}
			c.zones[name] = z
			c.mu.Unlock()
			return z, nil
		}
	}
	return zone{}, fmt.Errorf("no DNS zone of the account holds %s", name)
}

// sameValue reports whether two values of a record type are the same.
func sameValue(typ, a, b string) bool {
	switch typ {
	case "A", "AAAA":
		ia, ib := net.ParseIP(a), net.ParseIP(b)
		return ia != nil && ia.Equal(ib)
	case "TXT":
		return unquoteTXT(a) == unquoteTXT(b)
	default:
		return Canonical(a) == Canonical(b)
	}
}

func containsValue(typ string, list []string, v string) bool {
	for _, x := range list {
		if sameValue(typ, x, v) {
			return true
		}
	}
	return false
}

// quoteTXT writes a TXT value as one RFC 1035 character string. ACME's
// values are base64url, so nothing in them needs escaping; quotes and
// backslashes are escaped all the same.
func quoteTXT(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`
}

// unquoteTXT reads a TXT value an API returns, quoted or not, joining the
// character strings of a long value.
func unquoteTXT(v string) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	var b strings.Builder
	in, esc := false, false
	for _, r := range v {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\' && in:
			esc = true
		case r == '"':
			in = !in
		case in:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fqdn adds the final dot.
func fqdn(name string) string { return Canonical(name) + "." }

// apiError is a provider's answer to a failed call.
type apiError struct {
	Provider string
	Status   int
	Message  string
}

func (e *apiError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s: %s (HTTP %d)", e.Provider, msg, e.Status)
}

// IsNotFound reports whether err is a provider's 404.
func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}
