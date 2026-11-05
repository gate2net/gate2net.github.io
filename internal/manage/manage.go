// Package manage holds the operations on subdomains, SSH keys and users
// shared by the web dashboard and the admin socket, so both apply them the
// same way, including their effect on live tunnels.
package manage

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/names"
	"github.com/jgermade/intergate/internal/ports"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
)

// Error is a problem the caller can fix. Its message is safe to show.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

// Errorf returns an Error with a formatted message.
func Errorf(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Service applies management operations.
type Service struct {
	cfg      *config.Config
	store    *store.Store
	registry *tunnel.Registry
	ports    *ports.Registry
	names    *names.Checker
	log      *slog.Logger
	// SubdomainCreated, if set, is told about each new subdomain: the
	// server gets its certificate then, rather than on the first visit.
	SubdomainCreated func(name string)
}

// New returns a Service.
func New(cfg *config.Config, st *store.Store, reg *tunnel.Registry, pr *ports.Registry, checker *names.Checker, log *slog.Logger) *Service {
	return &Service{cfg: cfg, store: st, registry: reg, ports: pr, names: checker, log: log}
}

// Tunnel returns the live tunnel of a subdomain, if connected.
func (s *Service) Tunnel(name string) *tunnel.Stats {
	if t := s.registry.Get(name); t != nil {
		st := t.Stats()
		return &st
	}
	return nil
}

// KeysResult reports what happened to a batch of SSH keys.
type KeysResult struct {
	Added    int
	Problems []string
}

// Message summarizes the problems, or "" if there were none.
func (r KeysResult) Message() string { return strings.Join(r.Problems, "; ") }

// CreateSubdomain registers name for owner and authorizes the SSH keys in
// keysText (authorized_keys format). Per-user limits apply unless the
// caller is an administrator.
func (s *Service) CreateSubdomain(ctx context.Context, owner *store.User, name string, access store.Access, keysText string, admin bool, actor string) (*store.Subdomain, KeysResult, error) {
	name = names.Normalize(name)
	if access == "" {
		access = store.AccessPublic
	}
	if !access.Valid() {
		return nil, KeysResult{}, Errorf("unknown access level %q", access)
	}
	if err := s.CheckName(ctx, name); err != nil {
		return nil, KeysResult{}, err
	}
	if !admin {
		owned, err := s.store.SubdomainsByUser(ctx, owner.ID)
		if err != nil {
			return nil, KeysResult{}, err
		}
		if len(owned) >= s.cfg.Limits.SubdomainsPerUser {
			return nil, KeysResult{}, Errorf("you can register at most %d subdomains", s.cfg.Limits.SubdomainsPerUser)
		}
	}
	// Parse keys first, so a typo doesn't leave a half-configured
	// subdomain behind.
	keys, err := ParseKeys(keysText)
	if err != nil {
		return nil, KeysResult{}, err
	}
	d, err := s.store.CreateSubdomain(ctx, owner.ID, name, access)
	if errors.Is(err, store.ErrConflict) {
		return nil, KeysResult{}, Errorf("%s.%s is already taken", name, s.cfg.Domain())
	}
	if err != nil {
		return nil, KeysResult{}, err
	}
	s.log.Info("subdomain created", "subdomain", name, "owner", owner.Email, "by", actor)
	if s.SubdomainCreated != nil {
		s.SubdomainCreated(name)
	}
	res, err := s.addKeys(ctx, d, keys, actor)
	return d, res, err
}

// CheckName reports whether name can be registered right now.
func (s *Service) CheckName(ctx context.Context, name string) error {
	name = names.Normalize(name)
	if err := s.names.Check(name); err != nil {
		return Errorf("%q can't be used: %v", name, err)
	}
	if _, err := s.store.SubdomainByName(ctx, name); err == nil {
		return Errorf("%s.%s is already taken", name, s.cfg.Domain())
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// AddKeys authorizes the keys in text on d. name, if set, names a single
// key instead of its comment.
func (s *Service) AddKeys(ctx context.Context, d *store.Subdomain, text, name, actor string) (KeysResult, error) {
	keys, err := ParseKeys(text)
	if err != nil {
		return KeysResult{}, err
	}
	if len(keys) == 0 {
		return KeysResult{}, Errorf("paste at least one public key")
	}
	if name = strings.TrimSpace(name); name != "" && len(keys) == 1 {
		keys[0].Name = truncate(name, 64)
	}
	return s.addKeys(ctx, d, keys, actor)
}

func (s *Service) addKeys(ctx context.Context, d *store.Subdomain, keys []ParsedKey, actor string) (KeysResult, error) {
	var res KeysResult
	if len(keys) == 0 {
		return res, nil
	}
	existing, err := s.store.KeysBySubdomain(ctx, d.ID)
	if err != nil {
		return res, err
	}
	count := len(existing)
	for _, k := range keys {
		if count >= s.cfg.Limits.KeysPerSubdomain {
			res.Problems = append(res.Problems, fmt.Sprintf("a subdomain can have at most %d keys", s.cfg.Limits.KeysPerSubdomain))
			break
		}
		fp := ssh.FingerprintSHA256(k.Key)
		_, err := s.store.AddKey(ctx, d.ID, k.Name, k.Key)
		switch {
		case errors.Is(err, store.ErrConflict):
			res.Problems = append(res.Problems, fp+" is already registered")
		case err != nil:
			return res, err
		default:
			res.Added++
			count++
			s.log.Info("ssh key added", "subdomain", d.Name, "fingerprint", fp, "by", actor)
		}
	}
	return res, nil
}

// RemoveKey revokes a key and closes the tunnel it opened, if any.
func (s *Service) RemoveKey(ctx context.Context, d *store.Subdomain, keyID int64, actor string) (*store.Key, error) {
	k, err := s.store.DeleteKey(ctx, d.ID, keyID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, Errorf("that key no longer exists")
	}
	if err != nil {
		return nil, err
	}
	s.registry.CloseKey(d.Name, k.ID, "its SSH key was removed")
	s.ports.CloseKey(d.ID, k.ID, "its SSH key was removed")
	s.log.Info("ssh key removed", "subdomain", d.Name, "fingerprint", k.Fingerprint, "by", actor)
	return k, nil
}

// RenameKey changes the name of a key, including on the tunnel it opened.
func (s *Service) RenameKey(ctx context.Context, d *store.Subdomain, keyID int64, name, actor string) (string, error) {
	if name = truncate(strings.TrimSpace(name), 64); name == "" {
		return "", Errorf("the name can't be empty")
	}
	err := s.store.RenameKey(ctx, d.ID, keyID, name)
	if errors.Is(err, store.ErrNotFound) {
		return "", Errorf("that key no longer exists")
	}
	if err != nil {
		return "", err
	}
	s.registry.RenameKey(d.Name, keyID, name)
	s.ports.RenameKey(d.ID, keyID, name)
	s.log.Info("ssh key renamed", "subdomain", d.Name, "key_id", keyID, "name", name, "by", actor)
	return name, nil
}

// SetAccess changes who can reach d, including its live tunnel.
func (s *Service) SetAccess(ctx context.Context, d *store.Subdomain, access store.Access, actor string) error {
	if !access.Valid() {
		return Errorf("unknown access level %q", access)
	}
	if err := s.store.SetSubdomainAccess(ctx, d.ID, access); err != nil {
		return err
	}
	if t := s.registry.Get(d.Name); t != nil {
		t.SetAccess(access)
	}
	s.log.Info("access changed", "subdomain", d.Name, "access", access, "by", actor)
	return nil
}

// Disconnect closes the live tunnel and the forwarded ports of d. It
// reports whether there were any.
func (s *Service) Disconnect(d *store.Subdomain, actor string) bool {
	n := s.ports.CloseSubdomain(d.ID, "disconnected by "+actor)
	if t := s.registry.Get(d.Name); t != nil {
		t.Close("disconnected by " + actor)
		n++
	}
	if n > 0 {
		s.log.Info("tunnel disconnected", "subdomain", d.Name, "by", actor)
	}
	return n > 0
}

// RenameSubdomain gives d a new name, keeping its keys, ports and access.
// Its tunnel and ports close: clients connect again with the new name, and
// the old one becomes free for anyone.
func (s *Service) RenameSubdomain(ctx context.Context, d *store.Subdomain, name, actor string) error {
	name = names.Normalize(name)
	if name == d.Name {
		return Errorf("%s.%s already has that name", name, s.cfg.Domain())
	}
	if err := s.CheckName(ctx, name); err != nil {
		return err
	}
	err := s.store.RenameSubdomain(ctx, d.ID, name)
	if errors.Is(err, store.ErrConflict) {
		return Errorf("%s.%s is already taken", name, s.cfg.Domain())
	}
	if err != nil {
		return err
	}
	old := d.Name
	d.Name = name
	reason := "the subdomain was renamed to " + name
	if t := s.registry.Get(old); t != nil {
		t.Close(reason)
	}
	s.ports.CloseSubdomain(d.ID, reason)
	s.log.Info("subdomain renamed", "subdomain", old, "name", name, "by", actor)
	return nil
}

// DeleteSubdomain removes d and its keys and closes its tunnel.
func (s *Service) DeleteSubdomain(ctx context.Context, d *store.Subdomain, actor string) error {
	if err := s.store.DeleteSubdomain(ctx, d.ID); err != nil {
		return err
	}
	if t := s.registry.Get(d.Name); t != nil {
		t.Close("the subdomain was deleted")
	}
	s.ports.CloseSubdomain(d.ID, "the subdomain was deleted")
	s.log.Info("subdomain deleted", "subdomain", d.Name, "by", actor)
	return nil
}

func validEmail(email string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return Errorf("%q is not an email address", email)
	}
	return nil
}

// CreateUser adds an account that can then sign in with its email, whatever
// auth.allowed_* says. An account that exists but may not sign in, such as
// one the configuration no longer allows, gets that access too.
func (s *Service) CreateUser(ctx context.Context, email, actor string) (*store.User, error) {
	email = store.NormalizeEmail(email)
	if err := validEmail(email); err != nil {
		return nil, err
	}
	u, err := s.store.CreateUser(ctx, email, "")
	if errors.Is(err, store.ErrConflict) {
		if u, err = s.store.UserByEmail(ctx, email); err != nil {
			return nil, err
		}
		if s.cfg.UserAllowed(u.Email, u.Added, string(u.Role)) {
			return nil, Errorf("%s already has an account", email)
		}
	} else if err != nil {
		return nil, err
	}
	if err := s.store.SetUserAdded(ctx, u.ID); err != nil {
		return nil, err
	}
	u.Added = true
	s.log.Info("user added", "email", email, "by", actor)
	return u, nil
}

// AddUser adds an account, as CreateUser does, with a role: users by
// default; admins add users and admins, owners anyone. A role that may not
// be given adds nobody. Addresses in auth.admins are owners whatever it is.
func (s *Service) AddUser(ctx context.Context, email string, role store.Role, actor *store.User, actorRole store.Role) (*store.User, error) {
	if role == "" {
		role = store.RoleUser
	}
	if !role.Valid() {
		return nil, Errorf("unknown role %q", role)
	}
	if role == store.RoleOwner && actorRole != store.RoleOwner {
		return nil, Errorf("only owners can make or change owners")
	}
	u, err := s.CreateUser(ctx, email, actor.Email)
	if err != nil || role == store.RoleUser || s.cfg.IsAdmin(u.Email) {
		return u, err
	}
	if err := s.SetUserRole(ctx, u.ID, role, actor, actorRole); err != nil {
		return nil, err
	}
	u.Role = role
	return u, nil
}

// EnsureUser returns the account for email, creating it if needed.
func (s *Service) EnsureUser(ctx context.Context, email, actor string) (*store.User, error) {
	email = store.NormalizeEmail(email)
	if err := validEmail(email); err != nil {
		return nil, err
	}
	if u, err := s.store.UserByEmail(ctx, email); err == nil {
		return u, nil
	}
	return s.CreateUser(ctx, email, actor)
}

// SetUserDisabled blocks or unblocks a user. Disabling ends their sessions
// and closes their tunnels.
func (s *Service) SetUserDisabled(ctx context.Context, userID int64, disabled bool, actor string) error {
	attached, err := s.store.UserKeyAttachments(ctx, userID)
	if err != nil {
		return err
	}
	err = s.store.SetUserDisabled(ctx, userID, disabled)
	if errors.Is(err, store.ErrNotFound) {
		return Errorf("user not found")
	}
	if err != nil {
		return err
	}
	if disabled {
		for _, t := range s.registry.List() {
			if t.OwnerID == userID {
				t.Close("the owner's account was disabled")
			}
		}
		s.ports.CloseOwner(userID, "the owner's account was disabled")
		// Its keys on others' subdomains too.
		s.closeAttached(attached, "its SSH key's account was disabled")
	}
	s.log.Info("user updated", "user_id", userID, "disabled", disabled, "by", actor)
	return nil
}

// DeleteUser removes an account and everything it owns, and closes its
// tunnels. Someone the configuration allows can sign in again, as a new
// account.
func (s *Service) DeleteUser(ctx context.Context, userID int64, actor string) error {
	attached, err := s.store.UserKeyAttachments(ctx, userID)
	if err != nil {
		return err
	}
	err = s.store.DeleteUser(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return Errorf("user not found")
	}
	if err != nil {
		return err
	}
	for _, t := range s.registry.List() {
		if t.OwnerID == userID {
			t.Close("the owner's account was deleted")
		}
	}
	s.ports.CloseOwner(userID, "the owner's account was deleted")
	s.closeAttached(attached, "its SSH key's account was deleted")
	s.log.Info("user deleted", "user_id", userID, "by", actor)
	return nil
}

// SetUserRole changes the role of another user. Admins manage users and
// admins; only owners make owners or change them, and addresses in
// auth.admins stay owners whatever it is set to.
func (s *Service) SetUserRole(ctx context.Context, userID int64, role store.Role, actor *store.User, actorRole store.Role) error {
	if !role.Valid() {
		return Errorf("unknown role %q", role)
	}
	u, err := s.store.UserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return Errorf("user not found")
	}
	if err != nil {
		return err
	}
	switch {
	case u.ID == actor.ID:
		return Errorf("you can't change your own role")
	case s.cfg.IsAdmin(u.Email):
		return Errorf("%s is an owner in the configuration (auth.admins)", u.Email)
	case actorRole != store.RoleOwner && (u.Role == store.RoleOwner || role == store.RoleOwner):
		return Errorf("only owners can make or change owners")
	}
	if err := s.store.SetUserRole(ctx, userID, role); err != nil {
		return err
	}
	s.log.Info("user updated", "user_id", userID, "role", role, "by", actor.Email)
	return nil
}

// ParsedKey is an SSH public key read from authorized_keys text.
type ParsedKey struct {
	Key  ssh.PublicKey
	Name string
}

// ParseKeys reads public keys in authorized_keys format, one per line, as
// found in ~/.ssh/id_*.pub or https://github.com/<user>.keys.
func ParseKeys(text string) ([]ParsedKey, error) {
	var out []ParsedKey
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, Errorf("line %d is not an SSH public key (paste the contents of a .pub file)", i+1)
		}
		if err := checkKeyStrength(key); err != nil {
			return nil, Errorf("line %d: %v", i+1, err)
		}
		name := strings.TrimSpace(comment)
		if name == "" {
			name = key.Type()
		}
		out = append(out, ParsedKey{Key: key, Name: truncate(name, 64)})
		if len(out) > 100 {
			return nil, Errorf("too many keys at once")
		}
	}
	return out, nil
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n])
	}
	return s
}

func checkKeyStrength(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		ck, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("unreadable RSA key")
		}
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); !ok || rk.N.BitLen() < 2048 {
			return errors.New("RSA keys must have at least 2048 bits")
		}
		return nil
	}
	return fmt.Errorf("%s keys are not supported; use ed25519 (ssh-keygen -t ed25519)", key.Type())
}
