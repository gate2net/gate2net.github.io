// Package api holds the JSON shapes that both the dashboard's API and the
// admin socket answer with, and their conversions from stored records, so
// the browser and `intergate config` read the same thing.
package api

import (
	"time"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/ports"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
)

// Subdomain is a registered subdomain and its live tunnel, if any.
type Subdomain struct {
	Name      string        `json:"name"`
	URL       string        `json:"url"`
	Owner     string        `json:"owner"`
	Access    store.Access  `json:"access"`
	Keys      int           `json:"keys"`
	CreatedAt time.Time     `json:"created_at"`
	Tunnel    *tunnel.Stats `json:"tunnel,omitempty"`
	// Ports counts its TCP ports, and PortsOnline those forwarded now.
	Ports       int `json:"ports"`
	PortsOnline int `json:"ports_online"`
}

// NewSubdomain describes d; t is its tunnel, or nil when offline.
func NewSubdomain(cfg *config.Config, d *store.Subdomain, t *tunnel.Stats) Subdomain {
	return Subdomain{
		Name:      d.Name,
		URL:       cfg.TunnelURL(d.Name),
		Owner:     d.OwnerEmail,
		Access:    d.Access,
		Keys:      d.Keys,
		CreatedAt: d.CreatedAt,
		Tunnel:    t,
		Ports:     d.Ports,
	}
}

// Port is a TCP port of a subdomain, and its forward when a client has it
// open.
type Port struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Protocol  store.Protocol `json:"protocol"`
	Port      int            `json:"port"`
	Address   string         `json:"address"`
	Allow     []string       `json:"allow"`
	Preset    string         `json:"preset"`
	LocalPort int            `json:"local_port"`
	CreatedAt time.Time      `json:"created_at"`
	Forward   *ports.Stats   `json:"forward,omitempty"`
}

// NewPort describes p; f is its forward, or nil.
func NewPort(cfg *config.Config, p *store.Port, f *ports.Stats) Port {
	allow := p.Allow
	if allow == nil {
		allow = []string{}
	}
	return Port{
		ID: p.ID, Name: p.Name, Protocol: p.Protocol, Port: p.Port, Address: cfg.PortAddress(string(p.Protocol), p.Port),
		Allow: allow, Preset: p.Preset, LocalPort: p.LocalPort, CreatedAt: p.CreatedAt, Forward: f,
	}
}

// Key is an SSH key authorized on a subdomain.
type Key struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	// FromAccount is set for a key added from an account's keys: it goes
	// when the account's does.
	FromAccount bool `json:"from_account,omitempty"`
}

// NewKey describes k, without the key itself.
func NewKey(k *store.Key) Key {
	return Key{ID: k.ID, Name: k.Name, Type: k.Type(), Fingerprint: k.Fingerprint, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, FromAccount: k.UserKeyID != 0}
}

// NewKeys describes keys; never nil, so it encodes as [].
func NewKeys(keys []*store.Key) []Key {
	out := make([]Key, len(keys))
	for i, k := range keys {
		out[i] = NewKey(k)
	}
	return out
}

// SubdomainDetail is a subdomain with its keys and ports.
type SubdomainDetail struct {
	Subdomain
	KeyList  []Key  `json:"key_list"`
	PortList []Port `json:"port_list"`
}

// User is an account.
type User struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
	Admin    bool   `json:"admin"`
	Role     string `json:"role"`
	// ConfigOwner is set when auth.admins makes the user an owner, which
	// the dashboard cannot change.
	ConfigOwner bool      `json:"config_owner"`
	Allowed     bool      `json:"allowed"`
	Subdomains  int       `json:"subdomains"`
	Passkeys    int       `json:"passkeys"`
	Providers   string    `json:"providers"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// NewUser describes u as an administrator sees it.
func NewUser(cfg *config.Config, u store.UserSummary) User {
	role := cfg.UserRole(u.Email, string(u.Role))
	return User{
		ID: u.ID, Email: u.Email, Name: u.Name, Disabled: u.Disabled,
		Admin: role != "user", Role: role, ConfigOwner: cfg.IsAdmin(u.Email), Allowed: cfg.UserAllowed(u.Email, u.Added, string(u.Role)),
		Subdomains: u.Subdomains, Passkeys: u.Passkeys, Providers: u.Providers, LastLoginAt: u.LastLoginAt,
	}
}

// KeysResult reports keys added in authorized_keys format: how many, and
// why the others were not.
type KeysResult struct {
	Added    int      `json:"added"`
	Problems []string `json:"problems,omitempty"`
}
