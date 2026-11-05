package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
)

// bootData is what a dashboard page tells the app before it starts.
type bootData struct {
	Email     bool `json:"email"`
	Passkeys  bool `json:"passkeys"`
	Providers []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"providers"`
	User *struct {
		Email string `json:"email"`
		Admin bool   `json:"admin"`
		Role  string `json:"role"`
	} `json:"user"`
	CSRF      string `json:"csrf"`
	EmailFlow string `json:"email_flow"`
	Error     *struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	} `json:"error"`
	Setup    *setupState `json:"setup"`
	Wildcard *struct {
		Provider string `json:"provider"`
		Ready    bool   `json:"ready"`
	} `json:"wildcard"`
}

// setupState is the setup's state, in the page and in the setup's answers.
type setupState struct {
	Email   bool `json:"email"`
	Owner   bool `json:"owner"`
	Session bool `json:"session"`
	SMTP    *struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		TLS      string `json:"tls"`
		Username string `json:"username"`
		From     string `json:"from"`
		Password bool   `json:"password"`
	} `json:"smtp"`
	OwnerFlow string `json:"owner_flow"`
}

var bootRE = regexp.MustCompile(`<script type="application/json" id="boot">(.*?)</script>`)

func parseBoot(t *testing.T, body string) bootData {
	t.Helper()
	m := bootRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no boot data in the page:\n%s", body)
	}
	var b bootData
	if err := json.Unmarshal([]byte(m[1]), &b); err != nil {
		t.Fatalf("boot data %s: %v", m[1], err)
	}
	return b
}

// page loads a dashboard page.
func page(t *testing.T, c *http.Client, path string) (*http.Response, bootData) {
	t.Helper()
	resp, body := get(t, c, "http://"+domain+path)
	return resp, parseBoot(t, body)
}

// send makes an API request the way the app's fetch() does: from the
// dashboard's origin, with csrf as its token when not empty. body is sent
// as JSON, or as is when it is already []byte.
func send(t *testing.T, c *http.Client, method, path string, body any, csrf string) (*http.Response, string) {
	t.Helper()
	return sendFrom(t, c, "http://"+domain, method, path, body, csrf)
}

func sendFrom(t *testing.T, c *http.Client, origin, method, path string, body any, csrf string) (*http.Response, string) {
	t.Helper()
	var data []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		data = b
	default:
		var err error
		if data, err = json.Marshal(b); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(method, "http://"+domain+path, bytes.NewReader(data))
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", origin)
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, readBody(t, resp)
}

// call makes an API request as the signed-in app, with the session's token.
func call(t *testing.T, c *http.Client, method, path string, body any) (*http.Response, string) {
	t.Helper()
	_, b := page(t, c, "/")
	if b.User == nil {
		t.Fatalf("%s %s: not signed in", method, path)
	}
	return send(t, c, method, path, body, b.CSRF)
}

func decode[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}
