package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jgermade/intergate/internal/api"
	"github.com/jgermade/intergate/internal/manage"
	"github.com/jgermade/intergate/internal/store"
)

// The account's SSH keys: its owner adds them once, then to any subdomain
// they manage, picking them from a list. A subdomain's copy goes with the
// account's: removed from the account, a key opens nothing anywhere.

// accountKey describes a key of the account, without the key itself.
type accountKey struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	// Subdomains are those it was added to.
	Subdomains []string `json:"subdomains"`
}

func (s *Server) accountKeys(r *http.Request) ([]accountKey, error) {
	u := currentAuth(r).User
	keys, err := s.store.UserKeys(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	attached, err := s.store.UserKeyAttachments(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]accountKey, 0, len(keys))
	for _, k := range keys {
		v := accountKey{ID: k.ID, Name: k.Name, Type: k.Type(), Fingerprint: k.Fingerprint, CreatedAt: k.CreatedAt, Subdomains: []string{}}
		for _, a := range attached {
			if a.UserKeyID == k.ID {
				v.Subdomains = append(v.Subdomains, a.Subdomain)
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) handleAccountKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.accountKeys(r)
	if err != nil {
		s.internalError(w, "list account keys", err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleAddAccountKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keys string `json:"keys"`
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	a := currentAuth(r)
	res, err := s.manage.AddUserKeys(r.Context(), a.User, req.Keys, req.Name, a.User.Email)
	if err != nil {
		s.fail(w, "add account keys", err)
		return
	}
	writeJSON(w, http.StatusOK, api.KeysResult{Added: res.Added, Problems: res.Problems})
}

func (s *Server) handleRenameAccountKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	a := currentAuth(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	name, err := s.manage.RenameUserKey(r.Context(), a.User, id, req.Name, a.User.Email)
	if err != nil {
		s.fail(w, "rename account key", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Server) handleDeleteAccountKey(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	attached, err := s.manage.RemoveUserKey(r.Context(), a.User, id, a.User.Email)
	if err != nil {
		s.fail(w, "remove account key", err)
		return
	}
	from := []string{}
	for _, at := range attached {
		from = append(from, at.Subdomain)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"removed_from": from})
}

// attachAccountKeys adds keys of the signed-in user's account to d, and
// says what could not be.
func (s *Server) attachAccountKeys(r *http.Request, d *store.Subdomain, ids []int64, res *api.KeysResult) error {
	a := currentAuth(r)
	for _, id := range ids {
		_, err := s.manage.AttachUserKey(r.Context(), d, a.User, id, a.User.Email)
		var me *manage.Error
		switch {
		case err == nil:
			res.Added++
		case errors.As(err, &me):
			res.Problems = append(res.Problems, me.Error())
		default:
			return err
		}
	}
	return nil
}
