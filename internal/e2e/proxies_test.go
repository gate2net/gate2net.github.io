package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jgermade/intergate/internal/store"
)

// TestTrustedProxies checks that X-Forwarded-For only tells a client's
// address when it comes from one of the trusted_proxies: the address the
// dashboard sees, and what tunnels pass on to the app.
func TestTrustedProxies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   string
		clientIP string // what the dashboard sees
		appXFF   string // what the app behind the tunnel gets
	}{
		// Loopback is trusted by default: the test's requests come from it.
		{"trusted", "http: {trust_proxy_headers: true}", "198.51.100.7", "198.51.100.7, 127.0.0.1"},
		{"not trusted", "http: {trust_proxy_headers: true}\ntrusted_proxies: [192.0.2.0/24]", "127.0.0.1", "127.0.0.1"},
		{"headers off", "", "127.0.0.1", "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.config)
			_, _, key := h.setup("admin@example.com", "demo", store.AccessPublic)
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, r.Header.Get("X-Forwarded-For"))
			}))
			t.Cleanup(app.Close)
			c, err := h.dial(key, "admin")
			if err != nil {
				t.Fatal(err)
			}
			if !c.forward(t, "demo", 80, app) {
				t.Fatal("forward rejected")
			}

			req, _ := http.NewRequest("GET", "http://demo."+domain+"/", nil)
			req.Header.Set("X-Forwarded-For", "198.51.100.7")
			resp, err := h.browser(false).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if body := readBody(t, resp); body != tc.appXFF {
				t.Errorf("the app got X-Forwarded-For %q, want %q", body, tc.appXFF)
			}

			b := h.loggedIn("admin@example.com")
			req, _ = http.NewRequest("GET", "http://"+domain+"/api/subdomains/demo", nil)
			req.Header.Set("X-Forwarded-For", "198.51.100.7")
			resp, err = b.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body := readBody(t, resp)
			if got := decode[struct {
				ClientIP string `json:"client_ip"`
			}](t, body).ClientIP; got != tc.clientIP {
				t.Errorf("the dashboard sees %q, want %q (%d %s)", got, tc.clientIP, resp.StatusCode, body)
			}
		})
	}
}
