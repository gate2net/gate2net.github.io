package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jgermade/intergate/internal/dns"
	"github.com/jgermade/intergate/internal/store"
)

const dnsKey = "dns"

// DNS is the DNS provider set up from the dashboard, which intergate gets
// its wildcard certificate through.
type DNS struct {
	Provider string `json:"provider"`
	// Options are the provider's settings but its secrets, which are
	// Sealed with the data directory's secret key.
	Options map[string]string `json:"options,omitempty"`
	Sealed  map[string]string `json:"sealed,omitempty"`
	// WildcardRecord also points *.<domain> at the domain.
	WildcardRecord bool `json:"wildcard_record,omitempty"`
	// By is who saved it, and At when.
	By string    `json:"by,omitempty"`
	At time.Time `json:"at"`
}

func (s *Settings) loadDNS(ctx context.Context) error {
	raw, err := s.store.Setting(ctx, dnsKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("load settings: %w", err)
	}
	var d DNS
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return fmt.Errorf("load settings: dns: %w", err)
	}
	s.dns = &d
	return nil
}

// DNSSource tells where the DNS provider comes from.
func (s *Settings) DNSSource() Source {
	if s.cfg.DNS.Provider != "" {
		return SourceConfig
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dns != nil {
		return SourceDashboard
	}
	return SourceNone
}

// DNS returns a copy of the DNS provider set up from the dashboard, or nil.
func (s *Settings) DNS() *DNS {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dns == nil {
		return nil
	}
	d := *s.dns
	d.Options, d.Sealed = copyMap(d.Options), copyMap(d.Sealed)
	return &d
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// DNSProvider resolves the DNS provider, from the configuration file or
// the dashboard, with its secrets: name is "" when there is none.
func (s *Settings) DNSProvider() (name string, opts dns.Options, wildcardRecord bool, err error) {
	if c := s.cfg.DNS; c.Provider != "" {
		return c.Provider, dns.Options(copyMap(c.Options())), c.WildcardRecord, nil
	}
	d := s.DNS()
	if d == nil {
		return "", nil, false, nil
	}
	opts, err = s.dnsOptions(d)
	return d.Provider, opts, d.WildcardRecord, err
}

func (s *Settings) dnsOptions(d *DNS) (dns.Options, error) {
	opts := dns.Options(copyMap(d.Options))
	if opts == nil {
		opts = dns.Options{}
	}
	for k, sealed := range d.Sealed {
		v, err := openWith(s.dnsAEAD, dnsAD(d.Provider, k), sealed)
		if err != nil {
			return nil, inputError(fmt.Sprintf("The stored %s of the DNS provider can't be read with this data directory's secret key: enter it again.", fieldTitle(d.Provider, k)))
		}
		opts[k] = v
	}
	return opts, nil
}

func dnsAD(provider, field string) string { return "dns " + provider + "." + field }

func fieldTitle(provider, field string) string {
	if spec, ok := dns.Lookup(provider); ok {
		for _, f := range spec.Fields {
			if f.Name == field {
				return lowerFirst(f.Title)
			}
		}
	}
	return field
}

// lowerFirst lowercases a title's first letter, unless it starts an
// acronym: "the project ID", "the API token".
func lowerFirst(s string) string {
	if len(s) > 1 && strings.ToUpper(s[1:2]) == s[1:2] && strings.ToLower(s[1:2]) != s[1:2] {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// DNSChange is a DNS provider not saved yet, with its settings.
type DNSChange struct {
	dns     DNS
	options dns.Options
}

// Provider is the new provider's name.
func (c *DNSChange) Provider() string { return c.dns.Provider }

// Options are its settings, secrets included.
func (c *DNSChange) Options() dns.Options { return copyMap(c.options) }

// WildcardRecord tells whether *.<domain> is to point at the domain.
func (c *DNSChange) WildcardRecord() bool { return c.dns.WildcardRecord }

// PrepareDNS checks a DNS provider's settings, without reaching it, and
// seals its secrets, for ApplyDNS to save. A secret left empty keeps the
// one stored for the same provider.
func (s *Settings) PrepareDNS(provider string, values map[string]string, wildcardRecord bool, by string) (*DNSChange, error) {
	if s.DNSSource() == SourceConfig {
		return nil, inputError("The DNS provider is set in the configuration file (dns): change it there.")
	}
	spec, ok := dns.Lookup(provider)
	if !ok {
		return nil, inputError("Choose a DNS provider.")
	}
	// What runs programs or reads the server's files is the
	// configuration file's to set, not the dashboard's.
	if spec.ConfigOnly {
		return nil, inputError(spec.Title + " can only be set in the configuration file (dns).")
	}
	old := s.DNS()
	var oldOpts dns.Options
	if old != nil && old.Provider == provider {
		var err error
		if oldOpts, err = s.dnsOptions(old); err != nil {
			return nil, err
		}
	}
	d := DNS{Provider: provider, WildcardRecord: wildcardRecord, By: by, At: time.Now().UTC()}
	opts := dns.Options{}
	known := map[string]bool{}
	for _, f := range spec.Fields {
		if f.ConfigOnly {
			continue
		}
		known[f.Name] = true
		v := strings.TrimSpace(values[f.Name])
		if v == "" && f.Secret {
			v = oldOpts[f.Name]
		}
		if v == "" {
			continue
		}
		opts[f.Name] = v
		if f.Secret {
			sealed, err := sealWith(s.dnsAEAD, dnsAD(provider, f.Name), v)
			if err != nil {
				return nil, err
			}
			if d.Sealed == nil {
				d.Sealed = map[string]string{}
			}
			d.Sealed[f.Name] = sealed
		} else {
			if d.Options == nil {
				d.Options = map[string]string{}
			}
			d.Options[f.Name] = v
		}
	}
	for k := range values {
		if !known[k] {
			return nil, inputError(fmt.Sprintf("%s has no setting %q.", spec.Title, k))
		}
	}
	if err := dns.Validate(provider, opts); err != nil {
		return nil, inputError(validationMessage(spec, err))
	}
	return &DNSChange{dns: d, options: opts}, nil
}

// validationMessage words a dns.Validate error for the dashboard.
func validationMessage(spec dns.Spec, err error) string {
	for _, f := range spec.Fields {
		if f.Required && strings.Contains(err.Error(), spec.Name+"."+f.Name+" is required") {
			return "Enter the " + lowerFirst(f.Title) + "."
		}
	}
	msg := strings.TrimPrefix(err.Error(), spec.Name+": ")
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

// ApplyDNS saves a DNS provider PrepareDNS checked.
func (s *Settings) ApplyDNS(ctx context.Context, c *DNSChange) error {
	d := c.dns
	raw, err := json.Marshal(&d)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.SetSetting(ctx, dnsKey, string(raw)); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	s.dns = &d
	return nil
}

// DeleteDNS removes the DNS provider set up from the dashboard.
func (s *Settings) DeleteDNS(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.DeleteSetting(ctx, dnsKey); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	s.dns = nil
	return nil
}
