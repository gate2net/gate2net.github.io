package dns

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeDigitalOcean is the part of DigitalOcean's API v2 the provider uses.
type fakeDigitalOcean struct {
	mu      sync.Mutex
	records map[int]doRecord
	next    int
}

func (f *fakeDigitalOcean) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"id": "error", "message": msg})
	}
	if r.Header.Get("Authorization") != "Bearer do-token" {
		fail(401, "Unable to authenticate you")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v2")
	switch {
	case path == "/domains/example.com":
		json.NewEncoder(w).Encode(map[string]any{"domain": map[string]string{"name": "example.com"}})
	case path == "/domains/example.com/records" && r.Method == "GET":
		q := r.URL.Query()
		rel := strings.TrimSuffix(strings.TrimSuffix(q.Get("name"), "example.com"), ".")
		if rel == "" {
			rel = "@"
		}
		var out []doRecord
		for _, rec := range f.records {
			if rec.Name == rel && rec.Type == q.Get("type") {
				out = append(out, rec)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"domain_records": out, "links": map[string]any{}})
	case path == "/domains/example.com/records" && r.Method == "POST":
		var rec doRecord
		json.NewDecoder(r.Body).Decode(&rec)
		if strings.HasSuffix(rec.Name, "example.com") {
			fail(422, "Name must be relative to the domain")
			return
		}
		f.next++
		rec.ID = f.next
		f.records[rec.ID] = rec
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
	case strings.HasPrefix(path, "/domains/example.com/records/"):
		id, _ := strconv.Atoi(strings.TrimPrefix(path, "/domains/example.com/records/"))
		rec, ok := f.records[id]
		if !ok {
			fail(404, "The resource you were accessing could not be found.")
			return
		}
		switch r.Method {
		case "DELETE":
			delete(f.records, id)
			w.WriteHeader(204)
			return
		case "PATCH":
			json.NewDecoder(r.Body).Decode(&rec)
			f.records[id] = rec
		}
		json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
	default:
		fail(404, "The resource you were accessing could not be found.")
	}
}

func (f *fakeDigitalOcean) values(name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rel := relative(name, "example.com")
	var out []string
	for _, rec := range f.records {
		if rec.Name == rel && rec.Type == typ {
			out = append(out, rec.Data)
		}
	}
	return out
}

func TestDigitalOcean(t *testing.T) {
	f := &fakeDigitalOcean{records: map[int]doRecord{
		1: {ID: 1, Type: "A", Name: "gate", Data: "203.0.113.7", TTL: 300},
		2: {ID: 2, Type: "A", Name: "*.gate", Data: "203.0.113.8", TTL: 300},
	}, next: 2}
	p, err := New("digitalocean", Options{"api_token": "do-token"}, fakeAPI(t, f))
	if err != nil {
		t.Fatal(err)
	}
	conformance(t, p, f.values)
}
