package e2e

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type accountKeyState struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Subdomains  []string `json:"subdomains"`
}

func TestAccountKeys(t *testing.T) {
	h := newHarness(t)
	alice := h.loggedIn("alice@example.com")
	signer := newSigner(t)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	// A key goes into the account once.
	if resp, body := call(t, alice, "POST", "/api/account/keys", map[string]string{"keys": pub, "name": "laptop"}); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"added":1`) {
		t.Fatalf("add: %d %s", resp.StatusCode, body)
	}
	if _, body := call(t, alice, "POST", "/api/account/keys", map[string]string{"keys": pub}); !strings.Contains(body, "already in your account") {
		t.Errorf("added twice: %s", body)
	}
	_, body := call(t, alice, "GET", "/api/account", nil)
	keys := decode[struct {
		Keys []accountKeyState `json:"keys"`
	}](t, body).Keys
	if len(keys) != 1 || keys[0].Name != "laptop" || len(keys[0].Subdomains) != 0 {
		t.Fatalf("account keys: %s", body)
	}
	id := keys[0].ID

	// Then onto subdomains: as one is registered, and later.
	resp, body := call(t, alice, "POST", "/api/subdomains", map[string]any{"name": "webapp", "account_keys": []int64{id}})
	if resp.StatusCode != http.StatusCreated || !strings.Contains(body, `"added":1`) {
		t.Fatalf("register: %d %s", resp.StatusCode, body)
	}
	call(t, alice, "POST", "/api/subdomains", map[string]any{"name": "two"})
	if resp, body := call(t, alice, "POST", "/api/subdomains/two/keys", map[string]any{"account_key": id}); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"added":1`) {
		t.Fatalf("attach: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, alice, "POST", "/api/subdomains/two/keys", map[string]any{"account_key": id}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already") {
		t.Errorf("attached twice: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, alice, "GET", "/api/subdomains/two", nil)
	if !strings.Contains(body, `"from_account":true`) || !strings.Contains(body, `"name":"laptop"`) {
		t.Errorf("subdomain keys: %s", body)
	}
	_, body = call(t, alice, "GET", "/api/account/keys", nil)
	if got := decode[[]accountKeyState](t, body); len(got) != 1 || strings.Join(got[0].Subdomains, ",") != "two,webapp" {
		t.Errorf("where the key is: %s", body)
	}

	// Nobody else can use the account's keys.
	bob := h.loggedIn("bob@example.com")
	call(t, bob, "POST", "/api/subdomains", map[string]any{"name": "bobs"})
	if resp, body := call(t, bob, "POST", "/api/subdomains/bobs/keys", map[string]any{"account_key": id}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not in your account") {
		t.Errorf("another account's key: %d %s", resp.StatusCode, body)
	}

	// It opens the tunnel; renamed, the subdomains follow.
	c, err := h.dial(signer, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !c.forward(t, "webapp", 80, backend(t)) {
		t.Fatal("forward with the account's key rejected")
	}
	if resp, body := call(t, alice, "PATCH", "/api/account/keys/"+itoa(id), map[string]string{"name": "work laptop"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("rename: %d %s", resp.StatusCode, body)
	}
	if _, body := call(t, alice, "GET", "/api/subdomains/webapp", nil); !strings.Contains(body, `"name":"work laptop"`) {
		t.Errorf("not renamed on the subdomain: %s", body)
	}

	// Removed from the account, it opens nothing anywhere, at once.
	resp, body = call(t, alice, "DELETE", "/api/account/keys/"+itoa(id), nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"removed_from":["two","webapp"]`) {
		t.Fatalf("remove: %d %s", resp.StatusCode, body)
	}
	waitFor(t, func() bool { return h.registry.Get("webapp") == nil })
	if _, body := call(t, alice, "GET", "/api/subdomains/two", nil); !strings.Contains(body, `"key_list":[]`) {
		t.Errorf("key left on two: %s", body)
	}
	if _, err := h.dial(signer, "alice"); err == nil {
		t.Error("the removed key still signs in")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
