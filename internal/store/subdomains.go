package store

import (
	"context"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Access controls who may reach a subdomain over HTTP.
type Access string

const (
	// AccessPublic lets anyone with the URL in.
	AccessPublic Access = "public"
	// AccessUsers requires signing in to intergate.
	AccessUsers Access = "users"
	// AccessPrivate only lets the subdomain owner in.
	AccessPrivate Access = "private"
)

// Valid reports whether a is a known access level.
func (a Access) Valid() bool {
	return a == AccessPublic || a == AccessUsers || a == AccessPrivate
}

// Subdomain is a name registered by a user. Tunnels can only be opened on
// registered subdomains, with one of their SSH keys.
type Subdomain struct {
	ID         int64
	Name       string
	UserID     int64
	OwnerEmail string
	Access     Access
	CreatedAt  time.Time
	Keys       int
	Ports      int
}

const subdomainQuery = `
	SELECT d.id, d.name, d.user_id, u.email, d.access, d.created_at,
		(SELECT COUNT(*) FROM ssh_keys k WHERE k.subdomain_id = d.id),
		(SELECT COUNT(*) FROM tcp_ports p WHERE p.subdomain_id = d.id)
	FROM subdomains d JOIN users u ON u.id = d.user_id `

func scanSubdomain(row scanner) (*Subdomain, error) {
	var d Subdomain
	var created int64
	if err := row.Scan(&d.ID, &d.Name, &d.UserID, &d.OwnerEmail, &d.Access, &created, &d.Keys, &d.Ports); err != nil {
		return nil, notFound(err)
	}
	d.CreatedAt = fromUnix(created)
	return &d, nil
}

func (s *Store) listSubdomains(ctx context.Context, where string, args ...any) ([]*Subdomain, error) {
	rows, err := s.db.QueryContext(ctx, subdomainQuery+where+` ORDER BY d.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Subdomain
	for rows.Next() {
		d, err := scanSubdomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CreateSubdomain registers name for userID. The name must already be
// validated. It returns ErrConflict if the name is taken.
func (s *Store) CreateSubdomain(ctx context.Context, userID int64, name string, access Access) (*Subdomain, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO subdomains (name, user_id, access, created_at) VALUES (?, ?, ?, ?)`,
		name, userID, access, unix(s.now()))
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.SubdomainByName(ctx, name)
}

// SubdomainByName returns a registered subdomain.
func (s *Store) SubdomainByName(ctx context.Context, name string) (*Subdomain, error) {
	return scanSubdomain(s.db.QueryRowContext(ctx, subdomainQuery+`WHERE d.name = ?`, name))
}

// SubdomainsByUser lists the subdomains a user owns.
func (s *Store) SubdomainsByUser(ctx context.Context, userID int64) ([]*Subdomain, error) {
	return s.listSubdomains(ctx, `WHERE d.user_id = ?`, userID)
}

// AllSubdomains lists every registered subdomain.
func (s *Store) AllSubdomains(ctx context.Context) ([]*Subdomain, error) {
	return s.listSubdomains(ctx, ``)
}

// SetSubdomainAccess changes who can reach the subdomain.
func (s *Store) SetSubdomainAccess(ctx context.Context, id int64, access Access) error {
	res, err := s.db.ExecContext(ctx, `UPDATE subdomains SET access = ? WHERE id = ?`, access, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RenameSubdomain gives a subdomain a new name, which must already be
// validated. It returns ErrConflict if the name is taken.
func (s *Store) RenameSubdomain(ctx context.Context, id int64, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE subdomains SET name = ? WHERE id = ?`, name, id)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSubdomain removes a subdomain and its keys.
func (s *Store) DeleteSubdomain(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM subdomains WHERE id = ?`, id)
	return err
}

// Key is an SSH public key allowed to open tunnels on one subdomain.
type Key struct {
	ID          int64
	SubdomainID int64
	Name        string
	Fingerprint string
	PublicKey   string
	CreatedAt   time.Time
	LastUsedAt  time.Time
	// UserKeyID is the account key this one was added from, or 0.
	UserKeyID int64
}

// Type is the key algorithm, e.g. ssh-ed25519.
func (k *Key) Type() string {
	t, _, _ := strings.Cut(k.PublicKey, " ")
	return t
}

// AddKey authorizes key on a subdomain. It returns ErrConflict if the key
// is already there.
func (s *Store) AddKey(ctx context.Context, subdomainID int64, name string, key ssh.PublicKey) (*Key, error) {
	k := &Key{
		SubdomainID: subdomainID,
		Name:        name,
		Fingerprint: ssh.FingerprintSHA256(key),
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		CreatedAt:   s.now().Truncate(time.Second),
	}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO ssh_keys (subdomain_id, name, fingerprint, public_key, created_at)
		VALUES (?, ?, ?, ?, ?) RETURNING id`,
		k.SubdomainID, k.Name, k.Fingerprint, k.PublicKey, unix(k.CreatedAt)).Scan(&k.ID)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// KeysBySubdomain lists the keys authorized on a subdomain.
func (s *Store) KeysBySubdomain(ctx context.Context, subdomainID int64) ([]*Key, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subdomain_id, name, fingerprint, public_key, created_at, last_used_at, COALESCE(user_key_id, 0)
		FROM ssh_keys WHERE subdomain_id = ? ORDER BY created_at, id`, subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Key
	for rows.Next() {
		var k Key
		var created, used int64
		if err := rows.Scan(&k.ID, &k.SubdomainID, &k.Name, &k.Fingerprint, &k.PublicKey, &created, &used, &k.UserKeyID); err != nil {
			return nil, err
		}
		k.CreatedAt, k.LastUsedAt = fromUnix(created), fromUnix(used)
		out = append(out, &k)
	}
	return out, rows.Err()
}

// DeleteKey removes a key from a subdomain and returns it.
func (s *Store) DeleteKey(ctx context.Context, subdomainID, keyID int64) (*Key, error) {
	var k Key
	var created, used int64
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM ssh_keys WHERE id = ? AND subdomain_id = ?
		RETURNING id, subdomain_id, name, fingerprint, public_key, created_at, last_used_at, COALESCE(user_key_id, 0)`,
		keyID, subdomainID).Scan(&k.ID, &k.SubdomainID, &k.Name, &k.Fingerprint, &k.PublicKey, &created, &used, &k.UserKeyID)
	if err != nil {
		return nil, notFound(err)
	}
	k.CreatedAt, k.LastUsedAt = fromUnix(created), fromUnix(used)
	return &k, nil
}

// RenameKey changes the name of a key on a subdomain.
func (s *Store) RenameKey(ctx context.Context, subdomainID, keyID int64, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE ssh_keys SET name = ? WHERE id = ? AND subdomain_id = ?`, name, keyID, subdomainID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchKey records that a key was just used to open a tunnel.
func (s *Store) TouchKey(ctx context.Context, keyID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE ssh_keys SET last_used_at = ? WHERE id = ?`, unix(s.now()), keyID)
	return err
}

// Grant says that an SSH key may open tunnels on a subdomain.
type Grant struct {
	KeyID       int64
	KeyName     string
	PublicKey   string
	SubdomainID int64
	Subdomain   string
	Access      Access
	OwnerID     int64
	OwnerEmail  string
	OwnerAdded  bool
	OwnerRole   Role
}

// GrantsForKey lists the subdomains the key with this fingerprint may use.
// Subdomains of disabled users are skipped, and so are keys added from the
// account of a disabled user.
func (s *Store) GrantsForKey(ctx context.Context, fingerprint string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT k.id, k.name, k.public_key, d.id, d.name, d.access, u.id, u.email, u.added, u.role
		FROM ssh_keys k
		JOIN subdomains d ON d.id = k.subdomain_id
		JOIN users u ON u.id = d.user_id
		LEFT JOIN user_keys uk ON uk.id = k.user_key_id
		LEFT JOIN users ku ON ku.id = uk.user_id
		WHERE k.fingerprint = ? AND u.disabled = 0 AND (k.user_key_id IS NULL OR ku.disabled = 0)
		ORDER BY d.name`, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.KeyID, &g.KeyName, &g.PublicKey, &g.SubdomainID, &g.Subdomain, &g.Access, &g.OwnerID, &g.OwnerEmail, &g.OwnerAdded, &g.OwnerRole); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
