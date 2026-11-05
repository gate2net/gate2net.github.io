package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// UserKey is an SSH public key of an account, which its owner adds to
// subdomains.
type UserKey struct {
	ID          int64
	UserID      int64
	Name        string
	Fingerprint string
	PublicKey   string
	CreatedAt   time.Time
}

// Type is the key algorithm, e.g. ssh-ed25519.
func (k *UserKey) Type() string {
	t, _, _ := strings.Cut(k.PublicKey, " ")
	return t
}

// Attachment is an account key added to a subdomain.
type Attachment struct {
	UserKeyID   int64
	KeyID       int64
	SubdomainID int64
	Subdomain   string
}

// AddUserKey adds a key to an account. It returns ErrConflict if the
// account has it already.
func (s *Store) AddUserKey(ctx context.Context, userID int64, name string, key ssh.PublicKey) (*UserKey, error) {
	k := &UserKey{
		UserID:      userID,
		Name:        name,
		Fingerprint: ssh.FingerprintSHA256(key),
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		CreatedAt:   s.now().Truncate(time.Second),
	}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO user_keys (user_id, name, fingerprint, public_key, created_at)
		VALUES (?, ?, ?, ?, ?) RETURNING id`,
		k.UserID, k.Name, k.Fingerprint, k.PublicKey, unix(k.CreatedAt)).Scan(&k.ID)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

const userKeyColumns = `id, user_id, name, fingerprint, public_key, created_at`

func scanUserKey(row scanner) (*UserKey, error) {
	var k UserKey
	var created int64
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Fingerprint, &k.PublicKey, &created); err != nil {
		return nil, err
	}
	k.CreatedAt = fromUnix(created)
	return &k, nil
}

// UserKeys lists the keys of an account.
func (s *Store) UserKeys(ctx context.Context, userID int64) ([]*UserKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userKeyColumns+` FROM user_keys WHERE user_id = ? ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserKey
	for rows.Next() {
		k, err := scanUserKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UserKey returns a key of an account.
func (s *Store) UserKey(ctx context.Context, userID, id int64) (*UserKey, error) {
	k, err := scanUserKey(s.db.QueryRowContext(ctx, `SELECT `+userKeyColumns+` FROM user_keys WHERE id = ? AND user_id = ?`, id, userID))
	return k, notFound(err)
}

// RenameUserKey renames a key of an account, and its copies on subdomains.
func (s *Store) RenameUserKey(ctx context.Context, userID, id int64, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE user_keys SET name = ? WHERE id = ? AND user_id = ?`, name, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ssh_keys SET name = ? WHERE user_key_id = ?`, name, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUserKey removes a key from an account and from every subdomain it
// was added to, and returns where it was.
func (s *Store) DeleteUserKey(ctx context.Context, userID, id int64) ([]Attachment, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var found int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM user_keys WHERE id = ? AND user_id = ?`, id, userID).Scan(&found); err != nil {
		return nil, notFound(err)
	}
	attached, err := attachments(ctx, tx, `k.user_key_id = ?`, id)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ssh_keys WHERE user_key_id = ?`, id); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_keys WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return attached, tx.Commit()
}

// AttachUserKey adds an account key to a subdomain. It returns ErrConflict
// if the subdomain has the key already, from the account or not.
func (s *Store) AttachUserKey(ctx context.Context, subdomainID int64, uk *UserKey) (*Key, error) {
	k := &Key{
		SubdomainID: subdomainID,
		Name:        uk.Name,
		Fingerprint: uk.Fingerprint,
		PublicKey:   uk.PublicKey,
		CreatedAt:   s.now().Truncate(time.Second),
		UserKeyID:   uk.ID,
	}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO ssh_keys (subdomain_id, name, fingerprint, public_key, created_at, user_key_id)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		k.SubdomainID, k.Name, k.Fingerprint, k.PublicKey, unix(k.CreatedAt), k.UserKeyID).Scan(&k.ID)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// UserKeyAttachments lists where the keys of an account were added.
func (s *Store) UserKeyAttachments(ctx context.Context, userID int64) ([]Attachment, error) {
	return attachments(ctx, s.db, `k.user_key_id IN (SELECT id FROM user_keys WHERE user_id = ?)`, userID)
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func attachments(ctx context.Context, db querier, where string, args ...any) ([]Attachment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT k.user_key_id, k.id, d.id, d.name FROM ssh_keys k
		JOIN subdomains d ON d.id = k.subdomain_id
		WHERE `+where+` ORDER BY d.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attachment
	for rows.Next() {
		var a Attachment
		if err := rows.Scan(&a.UserKeyID, &a.KeyID, &a.SubdomainID, &a.Subdomain); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
