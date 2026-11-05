package manage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/store"
)

// KeysPerAccount is how many SSH keys an account can have.
const KeysPerAccount = 50

// AddUserKeys adds the keys in text to an account, for its owner to add to
// subdomains. name, if set, names a single key instead of its comment.
func (s *Service) AddUserKeys(ctx context.Context, u *store.User, text, name, actor string) (KeysResult, error) {
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
	existing, err := s.store.UserKeys(ctx, u.ID)
	if err != nil {
		return KeysResult{}, err
	}
	var res KeysResult
	count := len(existing)
	for _, k := range keys {
		if count >= KeysPerAccount {
			res.Problems = append(res.Problems, fmt.Sprintf("an account can have at most %d keys", KeysPerAccount))
			break
		}
		fp := ssh.FingerprintSHA256(k.Key)
		_, err := s.store.AddUserKey(ctx, u.ID, k.Name, k.Key)
		switch {
		case errors.Is(err, store.ErrConflict):
			res.Problems = append(res.Problems, fp+" is already in your account")
		case err != nil:
			return res, err
		default:
			res.Added++
			count++
			s.log.Info("account ssh key added", "user", u.Email, "fingerprint", fp, "by", actor)
		}
	}
	return res, nil
}

// RenameUserKey renames a key of an account, on every subdomain it is on.
func (s *Service) RenameUserKey(ctx context.Context, u *store.User, id int64, name, actor string) (string, error) {
	if name = truncate(strings.TrimSpace(name), 64); name == "" {
		return "", Errorf("the name can't be empty")
	}
	attached, err := s.store.UserKeyAttachments(ctx, u.ID)
	if err != nil {
		return "", err
	}
	err = s.store.RenameUserKey(ctx, u.ID, id, name)
	if errors.Is(err, store.ErrNotFound) {
		return "", Errorf("that key no longer exists")
	}
	if err != nil {
		return "", err
	}
	for _, a := range attached {
		if a.UserKeyID == id {
			s.registry.RenameKey(a.Subdomain, a.KeyID, name)
			s.ports.RenameKey(a.SubdomainID, a.KeyID, name)
		}
	}
	s.log.Info("account ssh key renamed", "user", u.Email, "key_id", id, "name", name, "by", actor)
	return name, nil
}

// RemoveUserKey removes a key from an account and from every subdomain it
// was added to, closing the tunnels and ports it opened.
func (s *Service) RemoveUserKey(ctx context.Context, u *store.User, id int64, actor string) ([]store.Attachment, error) {
	attached, err := s.store.DeleteUserKey(ctx, u.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, Errorf("that key no longer exists")
	}
	if err != nil {
		return nil, err
	}
	s.closeAttached(attached, "its SSH key was removed from its account")
	s.log.Info("account ssh key removed", "user", u.Email, "key_id", id, "subdomains", len(attached), "by", actor)
	return attached, nil
}

// AttachUserKey adds a key of u's account to the subdomain d.
func (s *Service) AttachUserKey(ctx context.Context, d *store.Subdomain, u *store.User, id int64, actor string) (*store.Key, error) {
	uk, err := s.store.UserKey(ctx, u.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, Errorf("that key is not in your account")
	}
	if err != nil {
		return nil, err
	}
	existing, err := s.store.KeysBySubdomain(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	if len(existing) >= s.cfg.Limits.KeysPerSubdomain {
		return nil, Errorf("a subdomain can have at most %d keys", s.cfg.Limits.KeysPerSubdomain)
	}
	k, err := s.store.AttachUserKey(ctx, d.ID, uk)
	if errors.Is(err, store.ErrConflict) {
		return nil, Errorf("%s can already be opened with %s", d.Name, uk.Name)
	}
	if err != nil {
		return nil, err
	}
	s.log.Info("ssh key added", "subdomain", d.Name, "fingerprint", uk.Fingerprint, "from_account", u.Email, "by", actor)
	return k, nil
}

func (s *Service) closeAttached(attached []store.Attachment, why string) {
	for _, a := range attached {
		s.registry.CloseKey(a.Subdomain, a.KeyID, why)
		s.ports.CloseKey(a.SubdomainID, a.KeyID, why)
	}
}
