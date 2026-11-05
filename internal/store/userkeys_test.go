package store

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestUserKeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	alice, _ := s.EnsureUser(ctx, "alice@example.com")
	bob, _ := s.EnsureUser(ctx, "bob@example.com")
	web, _ := s.CreateSubdomain(ctx, alice.ID, "web", AccessPublic)
	api, _ := s.CreateSubdomain(ctx, alice.ID, "api", AccessPublic)
	bobs, _ := s.CreateSubdomain(ctx, bob.ID, "bobs", AccessPublic)

	pub := newKey(t)
	fp := ssh.FingerprintSHA256(pub)
	uk, err := s.AddUserKey(ctx, alice.ID, "laptop", pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUserKey(ctx, alice.ID, "again", pub); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate account key: %v", err)
	}
	if _, err := s.AddUserKey(ctx, bob.ID, "shared", pub); err != nil {
		t.Errorf("the same key on another account: %v", err)
	}
	if got, err := s.UserKey(ctx, bob.ID, uk.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another account's key: %v %v", got, err)
	}

	// Added to subdomains, it opens them; twice on one is refused.
	for _, d := range []*Subdomain{web, api, bobs} {
		k, err := s.AttachUserKey(ctx, d.ID, uk)
		if err != nil || k.UserKeyID != uk.ID || k.Fingerprint != fp {
			t.Fatalf("attach to %s: %+v %v", d.Name, k, err)
		}
	}
	if _, err := s.AttachUserKey(ctx, web.ID, uk); !errors.Is(err, ErrConflict) {
		t.Errorf("attached twice: %v", err)
	}
	grants, _ := s.GrantsForKey(ctx, fp)
	if len(grants) != 3 {
		t.Fatalf("%d grants, want 3", len(grants))
	}
	if keys, _ := s.KeysBySubdomain(ctx, web.ID); len(keys) != 1 || keys[0].UserKeyID != uk.ID {
		t.Errorf("keys of web: %+v", keys)
	}

	// Renamed, its copies follow.
	if err := s.RenameUserKey(ctx, alice.ID, uk.ID, "work laptop"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.KeysBySubdomain(ctx, api.ID); keys[0].Name != "work laptop" {
		t.Errorf("copy not renamed: %q", keys[0].Name)
	}

	// Its owner disabled, it opens nothing, even bob's subdomain.
	s.SetUserDisabled(ctx, alice.ID, true)
	if grants, _ := s.GrantsForKey(ctx, fp); len(grants) != 0 {
		t.Errorf("a disabled account's key grants %d subdomains", len(grants))
	}
	s.SetUserDisabled(ctx, alice.ID, false)

	// Removed, it goes from every subdomain.
	attached, err := s.DeleteUserKey(ctx, alice.ID, uk.ID)
	if err != nil || len(attached) != 3 || attached[0].Subdomain != "api" {
		t.Fatalf("delete: %+v %v", attached, err)
	}
	if grants, _ := s.GrantsForKey(ctx, fp); len(grants) != 0 {
		t.Errorf("%d grants left", len(grants))
	}
	if _, err := s.DeleteUserKey(ctx, alice.ID, uk.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted twice: %v", err)
	}

	// Deleting the account takes its keys off others' subdomains too.
	uk2, _ := s.AddUserKey(ctx, alice.ID, "desktop", newKey(t))
	s.AttachUserKey(ctx, bobs.ID, uk2)
	if a, _ := s.UserKeyAttachments(ctx, alice.ID); len(a) != 1 || a[0].Subdomain != "bobs" {
		t.Errorf("attachments %+v", a)
	}
	if err := s.DeleteUser(ctx, alice.ID); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.KeysBySubdomain(ctx, bobs.ID); len(keys) != 0 {
		t.Errorf("%d keys left on bobs", len(keys))
	}
}
