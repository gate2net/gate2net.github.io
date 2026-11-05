package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

var b64 = base64.RawURLEncoding

// softAuthenticator is a minimal WebAuthn authenticator (ES256, "none"
// attestation) that always verifies the user.
type softAuthenticator struct {
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	rpID       string
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{key: key, credID: id}
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (a *softAuthenticator) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	var b bytes.Buffer
	b.Write(rp[:])
	b.WriteByte(flags)
	binary.Write(&b, binary.BigEndian, uint32(0)) // signature counter
	b.Write(attested)
	return b.Bytes()
}

// create answers navigator.credentials.create() options.
func (a *softAuthenticator) create(t *testing.T, options []byte, origin string) []byte {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatalf("creation options: %v\n%s", err, options)
	}
	a.rpID = opts.PublicKey.RP.ID
	a.userHandle, _ = b64.DecodeString(opts.PublicKey.User.ID)

	x, y := a.key.PublicKey.X.FillBytes(make([]byte, 32)), a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	var attested bytes.Buffer
	attested.Write(make([]byte, 16)) // AAGUID
	binary.Write(&attested, binary.BigEndian, uint16(len(a.credID)))
	attested.Write(a.credID)
	attested.Write(cose)
	attObj, _ := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(0x45, attested.Bytes()), // UP | UV | AT
	})
	out, _ := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.credID),
		"rawId": b64.EncodeToString(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", opts.PublicKey.Challenge, origin)),
			"attestationObject": b64.EncodeToString(attObj),
		},
		"clientExtensionResults": map[string]any{},
	})
	return out
}

// get answers navigator.credentials.get() options.
func (a *softAuthenticator) get(t *testing.T, options []byte, origin string) []byte {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatalf("assertion options: %v\n%s", err, options)
	}
	cd := clientData("webauthn.get", opts.PublicKey.Challenge, origin)
	ad := a.authData(0x05, nil) // UP | UV
	hash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id":    b64.EncodeToString(a.credID),
		"rawId": b64.EncodeToString(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(a.userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
	return out
}

// postJSON sends a fetch()-style POST from a dashboard page.
func postJSON(t *testing.T, c *http.Client, path string, body []byte, csrf string) (*http.Response, []byte) {
	t.Helper()
	if body == nil {
		body = []byte("{}")
	}
	resp, out := send(t, c, "POST", path, body, csrf)
	return resp, []byte(out)
}

func (h *harness) registerPasskey(c *http.Client, a *softAuthenticator) {
	h.t.Helper()
	_, boot := page(h.t, c, "/account")
	resp, opts := postJSON(h.t, c, "/api/account/passkeys/options", nil, boot.CSRF)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("registration options: %d %s", resp.StatusCode, opts)
	}
	resp, body := postJSON(h.t, c, "/api/account/passkeys?name=Test+key", a.create(h.t, opts, "http://"+domain), boot.CSRF)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"name":"Test key"`) {
		h.t.Fatalf("register passkey: %d %s", resp.StatusCode, body)
	}
}

func TestPasskeys(t *testing.T) {
	h := newHarness(t)
	a := newSoftAuthenticator(t)

	// Register a passkey after signing in with an email code.
	b := h.browser(true)
	h.emailLogin(b, "alice@example.com", "/")
	h.registerPasskey(b, a)
	if _, body := call(t, b, "GET", "/api/account", nil); !strings.Contains(body, `"name":"Test key"`) {
		t.Fatalf("account after registering: %s", body)
	}
	// With a passkey, signing in no longer suggests adding one.
	if next := h.emailLogin(h.browser(true), "alice@example.com", "/x"); next != "/x" {
		t.Errorf("after login with a passkey the app goes to %q", next)
	}
	if a.rpID != domain {
		t.Errorf("RP ID = %q, want %q", a.rpID, domain)
	}

	// Sign in with it from a new browser, without typing an email.
	fresh := h.browser(true)
	resp, opts := postJSON(t, fresh, "/api/login/passkey/options?rd=/account", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login options: %d %s", resp.StatusCode, opts)
	}
	assertion := a.get(t, opts, "http://"+domain)
	resp, body := postJSON(t, fresh, "/api/login/passkey", assertion, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"redirect":"/account"`) {
		t.Fatalf("passkey login: %d %s", resp.StatusCode, body)
	}
	if _, boot := page(t, fresh, "/"); boot.User == nil || boot.User.Email != "alice@example.com" {
		t.Fatal("not signed in after passkey login")
	}

	// The same assertion can't be replayed, even with a fresh ceremony.
	replay := h.browser(true)
	postJSON(t, replay, "/api/login/passkey/options", nil, "")
	if resp, _ := postJSON(t, replay, "/api/login/passkey", assertion, ""); resp.StatusCode == http.StatusOK {
		t.Error("replayed assertion accepted")
	}

	// Assertions made for a tunnel page (which may claim the same RP ID)
	// are refused.
	evil := h.browser(true)
	_, opts = postJSON(t, evil, "/api/login/passkey/options", nil, "")
	if resp, _ := postJSON(t, evil, "/api/login/passkey", a.get(t, opts, "http://evil."+domain), ""); resp.StatusCode == http.StatusOK {
		t.Error("assertion for a tunnel origin accepted")
	}

	// Unknown credentials are refused.
	stranger := newSoftAuthenticator(t)
	stranger.rpID, stranger.userHandle = domain, []byte("nobody")
	s := h.browser(true)
	_, opts = postJSON(t, s, "/api/login/passkey/options", nil, "")
	if resp, _ := postJSON(t, s, "/api/login/passkey", stranger.get(t, opts, "http://"+domain), ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unknown passkey: %d", resp.StatusCode)
	}

	// Registering needs the CSRF token.
	if resp, _ := postJSON(t, b, "/api/account/passkeys/options", nil, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("registration without CSRF token: %d", resp.StatusCode)
	}

	// Disabled users can't sign in with their passkey.
	u, _ := h.store.UserByEmail(t.Context(), "alice@example.com")
	h.store.SetUserDisabled(t.Context(), u.ID, true)
	d := h.browser(true)
	_, opts = postJSON(t, d, "/api/login/passkey/options", nil, "")
	if resp, _ := postJSON(t, d, "/api/login/passkey", a.get(t, opts, "http://"+domain), ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("disabled user's passkey: %d", resp.StatusCode)
	}

	// Removing one. (Disabling ended Alice's sessions: sign in again.)
	h.store.SetUserDisabled(t.Context(), u.ID, false)
	b = h.loggedIn("alice@example.com")
	_, account := call(t, b, "GET", "/api/account", nil)
	id := decode[struct {
		Passkeys []struct {
			ID int64 `json:"id"`
		} `json:"passkeys"`
	}](t, account).Passkeys[0].ID
	other := h.loggedIn("bob@example.com")
	if resp, _ := call(t, other, "DELETE", fmt.Sprintf("/api/account/passkeys/%d", id), nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another user removes the passkey: %d", resp.StatusCode)
	}
	if resp, _ := call(t, b, "DELETE", fmt.Sprintf("/api/account/passkeys/%d", id), nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("remove passkey: %d", resp.StatusCode)
	}
	if _, body := call(t, b, "GET", "/api/account", nil); !strings.Contains(body, `"passkeys":[]`) {
		t.Errorf("account after removing: %s", body)
	}
}

func TestPasskeysCanBeDisabled(t *testing.T) {
	h := newHarness(t, "  disable_passkeys: true")
	b := h.browser(true)
	if _, boot := page(t, b, "/login"); boot.Passkeys {
		t.Error("the sign-in page offers passkeys")
	}
	if resp, _ := postJSON(t, b, "/api/login/passkey/options", nil, ""); resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("passkey endpoint: %d", resp.StatusCode)
	}
	if next := h.emailLogin(b, "alice@example.com", "/"); next != "/" {
		t.Errorf("without passkeys, login should not suggest one (the app goes to %q)", next)
	}
}
