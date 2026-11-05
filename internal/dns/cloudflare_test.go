package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeCloudflare is the part of Cloudflare's API v4 the provider uses.
type fakeCloudflare struct {
	mu      sync.Mutex
	records map[string]cfRecord
	next    int
	proxied map[string]bool
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, result any) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"success": status < 300, "result": result, "errors": []any{}, "result_info": map[string]int{"page": 1, "total_pages": 1}})
	}
	if r.Header.Get("Authorization") != "Bearer cf-token" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 9109, "message": "Invalid access token"}}})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	switch {
	case r.Method == "GET" && path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			reply(200, []map[string]string{{"id": "z1", "name": "example.com"}})
		} else {
			reply(200, []any{})
		}
	case r.Method == "GET" && path == "/zones/z1/dns_records":
		var out []cfRecord
		for _, rec := range f.records {
			// Like the real API with a wildcard in name: more than asked.
			if (rec.Name == r.URL.Query().Get("name") || strings.HasPrefix(r.URL.Query().Get("name"), "*")) && rec.Type == r.URL.Query().Get("type") {
				out = append(out, rec)
			}
		}
		reply(200, out)
	case r.Method == "POST" && path == "/zones/z1/dns_records":
		var rec cfRecord
		json.NewDecoder(r.Body).Decode(&rec)
		f.next++
		rec.ID = "r" + strconv.Itoa(f.next)
		f.records[rec.ID] = rec
		if rec.Proxied != nil {
			f.proxied[rec.ID] = *rec.Proxied
		}
		reply(200, rec)
	case strings.HasPrefix(path, "/zones/z1/dns_records/"):
		id := strings.TrimPrefix(path, "/zones/z1/dns_records/")
		rec, ok := f.records[id]
		if !ok {
			reply(404, nil)
			return
		}
		switch r.Method {
		case "DELETE":
			delete(f.records, id)
		case "PATCH":
			json.NewDecoder(r.Body).Decode(&rec)
			f.records[id] = rec
		}
		reply(200, rec)
	default:
		reply(404, nil)
	}
}

func (f *fakeCloudflare) values(name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, rec := range f.records {
		if rec.Name == name && rec.Type == typ {
			out = append(out, rec.Content)
		}
	}
	return out
}

func TestCloudflare(t *testing.T) {
	f := &fakeCloudflare{records: map[string]cfRecord{
		"a1": {ID: "a1", Type: "A", Name: "gate.example.com", Content: "203.0.113.7", TTL: 300},
		"a2": {ID: "a2", Type: "A", Name: "*.gate.example.com", Content: "203.0.113.8", TTL: 300},
	}, proxied: map[string]bool{}}
	env := fakeAPI(t, f)
	p, err := New("cloudflare", Options{"api_token": "cf-token"}, env)
	if err != nil {
		t.Fatal(err)
	}
	conformance(t, p, f.values)
	for id, rec := range f.records {
		if rec.Type == "CNAME" && f.proxied[id] {
			t.Error("the wildcard record goes through Cloudflare's proxy")
		}
	}
	// TXT values go quoted, as Cloudflare asks.
	p.Set(context.Background(), RecordSet{Name: "_acme-challenge.gate.example.com", Type: "TXT", TTL: 60, Values: []string{"v"}})
	if got := f.values("_acme-challenge.gate.example.com", "TXT"); len(got) != 1 || got[0] != `"v"` {
		t.Errorf("TXT content %q", got)
	}

	bad, _ := New("cloudflare", Options{"api_token": "wrong"}, env)
	err = bad.Set(context.Background(), RecordSet{Name: "x.gate.example.com", Type: "TXT", TTL: 60, Values: []string{"v"}})
	if err == nil || !strings.Contains(err.Error(), "Invalid access token (9109)") {
		t.Errorf("bad token: %v", err)
	}
	// With the zone ID, no zone lookup.
	byID, _ := New("cloudflare", Options{"api_token": "cf-token", "zone_id": "z1"}, env)
	if err := byID.Delete(context.Background(), "nothing.example.org", "TXT"); err != nil {
		t.Errorf("zone_id: %v", err)
	}
	noZone, _ := New("cloudflare", Options{"api_token": "cf-token"}, env)
	if err := noZone.Delete(context.Background(), "gate.example.org", "TXT"); err == nil || !strings.Contains(err.Error(), "no DNS zone") {
		t.Errorf("unknown zone: %v", err)
	}
}
