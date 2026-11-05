package dns

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeCloudDNS is the part of Cloud DNS's API v1 the provider uses, and
// Google's token endpoint.
type fakeCloudDNS struct {
	mu     sync.Mutex
	rrsets map[string]gcpRRSet // "name type"
	tokens int
}

func (f *fakeCloudDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": msg}})
	}
	if r.URL.Path == "/token" {
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.FormValue("assertion") == "" {
			fail(400, "bad grant")
			return
		}
		f.tokens++
		json.NewEncoder(w).Encode(map[string]any{"access_token": "g-token", "token_type": "Bearer", "expires_in": 3600})
		return
	}
	if r.Header.Get("Authorization") != "Bearer g-token" {
		fail(401, "Request had invalid authentication credentials.")
		return
	}
	const zones = "/dns/v1/projects/proj-1/managedZones"
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == zones:
		var out []map[string]string
		if r.URL.Query().Get("dnsName") == "example.com." {
			out = append(out, map[string]string{"name": "internal", "dnsName": "example.com.", "visibility": "private"},
				map[string]string{"name": "example-com", "dnsName": "example.com.", "visibility": "public"})
		}
		json.NewEncoder(w).Encode(map[string]any{"managedZones": out})
	case r.Method == "POST" && path == zones+"/example-com/rrsets":
		var set gcpRRSet
		json.NewDecoder(r.Body).Decode(&set)
		key := set.Name + " " + set.Type
		if _, dup := f.rrsets[key]; dup {
			fail(409, "already exists")
			return
		}
		f.rrsets[key] = set
		json.NewEncoder(w).Encode(set)
	case strings.HasPrefix(path, zones+"/example-com/rrsets/"):
		name, typ, _ := strings.Cut(strings.TrimPrefix(path, zones+"/example-com/rrsets/"), "/")
		key := name + " " + typ
		cur, ok := f.rrsets[key]
		if !ok {
			fail(404, "The 'parameters.name' resource named '"+name+"' does not exist.")
			return
		}
		switch r.Method {
		case "PATCH":
			json.NewDecoder(r.Body).Decode(&cur)
			f.rrsets[key] = cur
		case "DELETE":
			delete(f.rrsets, key)
		}
		json.NewEncoder(w).Encode(cur)
	default:
		fail(404, "no such method")
	}
}

func (f *fakeCloudDNS) values(name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rrsets[name+". "+typ].Rrdatas
}

func TestGoogleCloudDNS(t *testing.T) {
	f := &fakeCloudDNS{rrsets: map[string]gcpRRSet{
		"gate.example.com. A":   {Name: "gate.example.com.", Type: "A", TTL: 300, Rrdatas: []string{"203.0.113.7"}},
		"*.gate.example.com. A": {Name: "*.gate.example.com.", Type: "A", TTL: 300, Rrdatas: []string{"203.0.113.8"}},
	}}
	env := fakeAPI(t, f)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	sa, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "proj-1",
		"private_key_id": "k1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "intergate@proj-1.iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	file := filepath.Join(t.TempDir(), "sa.json")
	os.WriteFile(file, sa, 0o600)

	// The project comes from the key file.
	p, err := New("gcp", Options{"credentials_file": file}, env)
	if err != nil {
		t.Fatal(err)
	}
	conformance(t, p, f.values)
	if got := f.values("*.gate.example.com", "CNAME"); len(got) != 1 || got[0] != "gate.example.com." {
		t.Errorf("CNAME rrdatas %q", got)
	}
	if f.tokens != 1 {
		t.Errorf("%d tokens fetched, want 1 (reused until it expires)", f.tokens)
	}
	p.Set(context.Background(), RecordSet{Name: "_acme-challenge.gate.example.com", Type: "TXT", TTL: 60, Values: []string{"v1", "v2"}})
	if got := f.values("_acme-challenge.gate.example.com", "TXT"); len(got) != 2 || got[0] != `"v1"` {
		t.Errorf("TXT rrdatas %q", got)
	}

	if _, err := New("gcp", Options{"credentials_file": filepath.Join(t.TempDir(), "missing.json")}, env); err == nil {
		t.Error("missing key file accepted")
	}
	os.WriteFile(file, []byte(`{"hello": 1}`), 0o600)
	if _, err := New("gcp", Options{"credentials_file": file}, env); err == nil || !strings.Contains(err.Error(), "not a Google Cloud credentials file") {
		t.Errorf("bad key file: %v", err)
	}
}
