package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jgermade/intergate/internal/dns"
	"github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/wildcard"
)

// The Admin page's DNS tab: a DNS provider for the zone of the dashboard's
// domain, which intergate gets one wildcard certificate through (ACME's
// DNS-01 challenge) instead of one per subdomain. Admins see it; owners
// change it, and a change only saves once intergate has added and removed
// a record through the provider, so credentials that can't change the zone
// never replace ones that can.

// dnsView describes the DNS provider and the certificate, without secrets.
type dnsView struct {
	// Source is "config" (dns in the configuration file), "dashboard" or
	// "" (none).
	Source   settings.Source `json:"source"`
	Provider string          `json:"provider,omitempty"`
	// ProviderTitle names the DNS service: Cloudflare.
	ProviderTitle string `json:"provider_title,omitempty"`
	// Settings are the provider's settings; secrets only say where they
	// are: "stored" (encrypted in the database) or "config".
	Settings       map[string]string `json:"settings,omitempty"`
	WildcardRecord bool              `json:"wildcard_record"`
	By             string            `json:"by,omitempty"`
	At             time.Time         `json:"at,omitzero"`
	// Editable is set for owners when the provider is not the
	// configuration file's.
	Editable    bool            `json:"editable"`
	Certificate wildcard.Status `json:"certificate"`
	// WildcardResolves tells whether *.<domain> resolves already.
	WildcardResolves bool `json:"wildcard_resolves"`
	// Providers are those the dashboard can set up, for its form.
	Providers []dnsProviderView `json:"providers"`
}

type dnsProviderView struct {
	Name   string         `json:"name"`
	Title  string         `json:"title"`
	Help   string         `json:"help"`
	Fields []dnsFieldView `json:"fields"`
}

type dnsFieldView struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	Upload      bool   `json:"upload,omitempty"`
}

// dashboardProviders lists the providers the dashboard can set up: not
// those that run programs, nor settings that point at the server's files.
func dashboardProviders() []dnsProviderView {
	var out []dnsProviderView
	for _, spec := range dns.Providers() {
		if spec.ConfigOnly {
			continue
		}
		v := dnsProviderView{Name: spec.Name, Title: spec.Title, Help: spec.Help, Fields: []dnsFieldView{}}
		for _, f := range spec.Fields {
			if !f.ConfigOnly {
				v.Fields = append(v.Fields, dnsFieldView{Name: f.Name, Title: f.Title, Description: f.Description, Required: f.Required, Secret: f.Secret, Upload: f.Upload})
			}
		}
		out = append(out, v)
	}
	return out
}

func secretFields(provider string) map[string]bool {
	out := map[string]bool{}
	if spec, ok := dns.Lookup(provider); ok {
		for _, f := range spec.Fields {
			if f.Secret {
				out[f.Name] = true
			}
		}
	}
	return out
}

func (s *Server) dnsView(ctx context.Context, a *authInfo) dnsView {
	v := dnsView{
		Source:           s.settings.DNSSource(),
		Certificate:      s.wildcard.Status(),
		WildcardResolves: s.wildcardResolves(ctx),
		Providers:        dashboardProviders(),
	}
	switch v.Source {
	case settings.SourceConfig:
		c := s.cfg.DNS
		v.Provider, v.WildcardRecord = c.Provider, c.WildcardRecord
		secret := secretFields(c.Provider)
		v.Settings = map[string]string{}
		for k, val := range c.Options() {
			if secret[k] {
				val = "config"
			}
			v.Settings[k] = val
		}
	case settings.SourceDashboard:
		d := s.settings.DNS()
		v.Provider, v.WildcardRecord, v.By, v.At = d.Provider, d.WildcardRecord, d.By, d.At
		v.Settings = map[string]string{}
		for k, val := range d.Options {
			v.Settings[k] = val
		}
		for k := range d.Sealed {
			v.Settings[k] = "stored"
		}
	}
	if spec, ok := dns.Lookup(v.Provider); ok {
		v.ProviderTitle = spec.Title
	}
	if a.Role == store.RoleOwner {
		v.Editable = v.Source != settings.SourceConfig
	}
	return v
}

// wildcardCheck caches whether *.<domain> resolves, for a minute.
type wildcardCheck struct {
	mu      sync.Mutex
	at      time.Time
	resolve bool
}

// wildcardResolves looks up a name no one has registered under the
// domain: it only resolves through a wildcard record.
func (s *Server) wildcardResolves(ctx context.Context) bool {
	c := &s.wildcardCheck
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < time.Minute {
		return c.resolve
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "intergate-check-"+randomString(6)+"."+s.cfg.Domain()+".")
	c.at, c.resolve = time.Now(), err == nil && len(addrs) > 0
	return c.resolve
}

func (s *Server) handleAdminDNS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.dnsView(r.Context(), currentAuth(r)))
}

// dnsOwner lets owners through, while the DNS provider is not the
// configuration file's.
func (s *Server) dnsOwner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentAuth(r).Role != store.RoleOwner {
			jsonError(w, http.StatusForbidden, "Only owners can change the DNS provider.")
			return
		}
		if s.settings.DNSSource() == settings.SourceConfig && r.URL.Path != "/api/admin/dns/retry" {
			jsonError(w, http.StatusConflict, "The DNS provider is set in the configuration file (dns): change it there.")
			return
		}
		next(w, r)
	}
}

// checkRecord is the record intergate adds and removes through a new DNS
// provider before saving it. Subdomains can't start with an underscore,
// so it can't be anybody's.
func (s *Server) checkRecord() string { return "_intergate-check." + s.cfg.Domain() }

// handleAdminDNSChange checks a DNS provider by adding and removing a TXT
// record through it, saves it, and starts getting the wildcard
// certificate.
func (s *Server) handleAdminDNSChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider       string            `json:"provider"`
		Settings       map[string]string `json:"settings"`
		WildcardRecord bool              `json:"wildcard_record"`
	}
	if !decode(w, r, &req) {
		return
	}
	a := currentAuth(r)
	var inputErr *settings.InputError
	change, err := s.settings.PrepareDNS(req.Provider, req.Settings, req.WildcardRecord, a.User.Email)
	switch {
	case errors.As(err, &inputErr):
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.internalError(w, "check the DNS provider", err)
		return
	}
	p, err := dns.New(change.Provider(), change.Options(), s.dnsEnv)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "The DNS provider can't be used: "+err.Error()+".")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	name := s.checkRecord()
	err = p.Set(ctx, dns.RecordSet{Name: name, Type: "TXT", TTL: 60, Values: []string{"intergate checks that it can change this zone"}})
	if err == nil {
		err = p.Delete(ctx, name, "TXT")
	}
	if err != nil {
		s.log.Info("new DNS provider could not change the zone", "provider", change.Provider(), "err", err)
		jsonError(w, http.StatusBadRequest, "intergate could not change the zone of "+s.cfg.Domain()+" with these settings: "+err.Error()+".")
		return
	}
	if err := s.settings.ApplyDNS(r.Context(), change); err != nil {
		s.internalError(w, "save the DNS provider", err)
		return
	}
	s.wildcard.Configure(&wildcard.Provider{Provider: p, Name: change.Provider(), WildcardRecord: change.WildcardRecord()})
	s.log.Info("DNS provider changed", "provider", change.Provider(), "wildcard_record", change.WildcardRecord(), "by", a.User.Email)
	writeJSON(w, http.StatusOK, s.dnsView(r.Context(), a))
}

// handleAdminDNSDelete removes the DNS provider: the certificate is served
// until it expires, and each host gets a certificate of its own again.
func (s *Server) handleAdminDNSDelete(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	if err := s.settings.DeleteDNS(r.Context()); err != nil {
		s.internalError(w, "remove the DNS provider", err)
		return
	}
	s.wildcard.Configure(nil)
	s.log.Info("DNS provider removed", "by", a.User.Email)
	writeJSON(w, http.StatusOK, s.dnsView(r.Context(), a))
}

// handleAdminDNSRetry tries to get the certificate again now.
func (s *Server) handleAdminDNSRetry(w http.ResponseWriter, r *http.Request) {
	s.wildcard.Retry()
	// Let the try start, so the answer shows it.
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline) && !s.wildcard.Status().Issuing; {
		time.Sleep(20 * time.Millisecond)
	}
	writeJSON(w, http.StatusOK, s.dnsView(r.Context(), currentAuth(r)))
}

// dnsAvailable answers 404 when intergate does not get its certificates
// from Let's Encrypt: there is no wildcard certificate to get.
func (s *Server) dnsAvailable(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.wildcard == nil {
			jsonError(w, http.StatusNotFound, "intergate does not get its certificates from Let's Encrypt here (http.tls.acme), so it has no wildcard certificate to get.")
			return
		}
		next(w, r)
	}
}
