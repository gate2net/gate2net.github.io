package e2e

import (
	"net/http"
	"strings"
	"testing"

	appsettings "github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
)

// relayState is the SMTP relay as the Admin page gets it.
type relayState struct {
	Source   string `json:"source"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLS      string `json:"tls"`
	Password string `json:"password"`
	Editable bool   `json:"editable"`
	Pending  string `json:"pending"`
}

func TestSMTPRelay(t *testing.T) {
	h, checked := newSetupHarness(t)
	ctx := t.Context()
	set := h.srv.Settings()
	if err := set.SaveEmail(ctx, appsettings.Email{Host: "smtp.example.com", Port: 587, TLS: "starttls", Username: "me", From: "intergate <no-reply@gate.test>"}, "old"); err != nil {
		t.Fatal(err)
	}
	for email, role := range map[string]store.Role{"boss@example.org": store.RoleOwner, "helper@example.org": store.RoleAdmin} {
		u, _ := h.store.EnsureUser(ctx, email)
		h.store.SetUserRole(ctx, u.ID, role)
	}
	owner, helper := h.browser(true), h.browser(true)
	h.emailLogin(owner, "boss@example.org", "/")
	h.emailLogin(helper, "helper@example.org", "/")

	// Admins see the relay; only owners may change it.
	resp, body := call(t, helper, "GET", "/api/admin/email", nil)
	if st := decode[relayState](t, body); resp.StatusCode != http.StatusOK || st.Source != "dashboard" || st.Host != "smtp.example.com" || st.Password != "stored" || st.Editable {
		t.Fatalf("admin view: %d %s", resp.StatusCode, body)
	}
	newRelay := map[string]any{"host": "smtp2.example.com", "port": 465, "tls": "tls", "username": "mailer", "password": "n3w", "from": "intergate <gate@example.org>"}
	if resp, _ := call(t, helper, "POST", "/api/admin/email", newRelay); resp.StatusCode != http.StatusForbidden {
		t.Errorf("an admin changed the relay: %d", resp.StatusCode)
	}
	if _, body := call(t, owner, "GET", "/api/admin/email", nil); !decode[relayState](t, body).Editable {
		t.Errorf("owner view: %s", body)
	}

	// The new relay must take its credentials, then deliver a code to the
	// owner; until then nothing changes.
	bad := map[string]any{"host": "smtp2.example.com", "port": 465, "tls": "tls", "username": "mailer", "password": "wrong", "from": "intergate <gate@example.org>"}
	if resp, body := call(t, owner, "POST", "/api/admin/email", bad); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "535") {
		t.Errorf("refused password: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, owner, "POST", "/api/admin/email", newRelay)
	if st := decode[relayState](t, body); resp.StatusCode != http.StatusOK || st.Pending != "boss@example.org" || st.Host != "smtp.example.com" {
		t.Fatalf("propose: %d %s", resp.StatusCode, body)
	}
	if via := <-h.relays; via.SMTP.Host != "smtp2.example.com" || via.SMTP.Port != 465 || via.SMTP.Password != "n3w" || via.From != "intergate <gate@example.org>" {
		t.Errorf("the code went through %+v", via)
	}
	if last := (*checked)[len(*checked)-1]; last.Host != "smtp2.example.com" || last.Password != "n3w" {
		t.Errorf("checked %+v", last)
	}
	code := h.mail.code(t, "boss@example.org")
	if e := set.Email(); e.Host != "smtp.example.com" {
		t.Fatalf("saved before the code: %+v", e)
	}
	if resp, _ := call(t, helper, "POST", "/api/admin/email/confirm", map[string]string{"code": code}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("an admin confirmed: %d", resp.StatusCode)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	// Not a 401, which the dashboard takes for a session that ended.
	if resp, _ := call(t, owner, "POST", "/api/admin/email/confirm", map[string]string{"code": wrong}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong code: %d", resp.StatusCode)
	}
	resp, body = call(t, owner, "POST", "/api/admin/email/confirm", map[string]string{"code": code})
	if st := decode[relayState](t, body); resp.StatusCode != http.StatusOK || st.Host != "smtp2.example.com" || st.TLS != "tls" || st.Pending != "" {
		t.Fatalf("confirm: %d %s", resp.StatusCode, body)
	}
	if cfg, err := set.EmailConfig(); err != nil || cfg.SMTP.Host != "smtp2.example.com" || cfg.SMTP.Password != "n3w" || cfg.SMTP.Username != "mailer" {
		t.Errorf("saved %+v, %v", cfg.SMTP, err)
	}
	if resp, _ := call(t, owner, "POST", "/api/admin/email/confirm", map[string]string{"code": code}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("the code worked twice: %d", resp.StatusCode)
	}

	// An empty password keeps the saved one; a change can be cancelled.
	delete(newRelay, "password")
	newRelay["port"] = 2465
	if resp, body := call(t, owner, "POST", "/api/admin/email", newRelay); resp.StatusCode != http.StatusOK {
		t.Fatalf("propose again: %d %s", resp.StatusCode, body)
	}
	if via := <-h.relays; via.SMTP.Password != "n3w" || via.SMTP.Port != 2465 {
		t.Errorf("kept password: %+v", via.SMTP)
	}
	code = h.mail.code(t, "boss@example.org")
	if resp, _ := call(t, owner, "DELETE", "/api/admin/email/pending", nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("cancel: %d", resp.StatusCode)
	}
	if resp, _ := call(t, owner, "POST", "/api/admin/email/confirm", map[string]string{"code": code}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("confirmed a cancelled change: %d", resp.StatusCode)
	}
	if e := set.Email(); e.Port != 465 {
		t.Errorf("cancelled change saved: %+v", e)
	}
}

// TestSMTPRelayFromConfig checks that the relay of the configuration file
// shows, and can't change from the dashboard.
func TestSMTPRelayFromConfig(t *testing.T) {
	h := newHarness(t)
	owner := h.loggedIn("admin@example.com")
	resp, body := call(t, owner, "GET", "/api/admin/email", nil)
	if st := decode[relayState](t, body); resp.StatusCode != http.StatusOK || st.Source != "config" || st.Editable || !strings.Contains(body, `"log_only":true`) {
		t.Fatalf("view: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, owner, "POST", "/api/admin/email", map[string]any{"host": "smtp.example.com", "port": 587, "tls": "starttls", "from": "a@b.c"}); resp.StatusCode != http.StatusConflict {
		t.Errorf("change over the configuration file: %d", resp.StatusCode)
	}
	if resp, _ := call(t, h.loggedIn("dev@example.com"), "GET", "/api/admin/email", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a user sees the relay: %d", resp.StatusCode)
	}
}
