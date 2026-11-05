package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// redirect sends every request to a test server, whatever its host.
type redirect struct{ target *url.URL }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host, req.Host = r.target.Scheme, r.target.Host, ""
	return http.DefaultTransport.RoundTrip(req)
}

// fakeAPI serves h for the providers of a test.
func fakeAPI(t *testing.T, h http.Handler) Env {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return Env{HTTPClient: &http.Client{Transport: redirect{u}, Timeout: 5 * time.Second}}
}

// conformance runs the changes intergate makes through a provider, and
// checks them with read, which returns what the fake API holds for a name
// and type.
func conformance(t *testing.T, p Provider, read func(name, typ string) []string) {
	t.Helper()
	ctx := context.Background()
	norm := func(typ string, v []string) []string {
		out := []string{}
		for _, x := range v {
			switch typ {
			case "TXT":
				x = unquoteTXT(x)
			default:
				x = Canonical(x)
			}
			out = append(out, x)
		}
		sort.Strings(out)
		return out
	}
	check := func(name, typ string, want ...string) {
		t.Helper()
		if want == nil {
			want = []string{}
		}
		sort.Strings(want)
		if got := norm(typ, read(name, typ)); !slices.Equal(got, want) {
			t.Errorf("%s %s = %q, want %q", name, typ, got, want)
		}
	}
	const chal = "_acme-challenge.gate.example.com"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// The two values of a wildcard certificate's challenge share a name.
	must(p.Set(ctx, RecordSet{Name: chal, Type: "TXT", TTL: 60, Values: []string{"aaa-111", "bbb_222"}}))
	check(chal, "TXT", "aaa-111", "bbb_222")
	must(p.Set(ctx, RecordSet{Name: chal, Type: "TXT", TTL: 60, Values: []string{"bbb_222", "ccc"}}))
	check(chal, "TXT", "bbb_222", "ccc")
	must(p.Set(ctx, RecordSet{Name: chal, Type: "TXT", TTL: 60, Values: []string{"bbb_222", "ccc"}})) // no change
	check(chal, "TXT", "bbb_222", "ccc")
	must(p.Delete(ctx, chal, "TXT"))
	check(chal, "TXT")
	must(p.Delete(ctx, chal, "TXT")) // nothing left: not an error

	// The wildcard record replaces the addresses the name had.
	must(p.Delete(ctx, "*.gate.example.com", "A"))
	check("*.gate.example.com", "A")
	must(p.Set(ctx, RecordSet{Name: "*.gate.example.com", Type: "CNAME", TTL: 300, Values: []string{"gate.example.com"}}))
	check("*.gate.example.com", "CNAME", "gate.example.com")
	// Other records stay.
	check("gate.example.com", "A", "203.0.113.7")
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		err  string
	}{
		{"cloudflare", Options{"api_token": "x"}, ""},
		{"cloudflare", Options{}, "cloudflare.api_token is required"},
		{"cloudflare", Options{"api_token": "x", "token": "y"}, `no setting "token"`},
		{"nope", nil, "unknown DNS provider"},
		{"route53", Options{}, ""},
		{"route53", Options{"access_key_id": "AKID"}, "go together"},
		{"gcp", Options{"project": "p"}, ""},
		{"digitalocean", Options{"api_token": "x"}, ""},
		{"exec", Options{"command": "/bin/true", "timeout": "soon"}, "timeout must be a duration"},
	} {
		err := Validate(tc.name, tc.opts)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("Validate(%s, %v) = %v, want %q", tc.name, tc.opts, err, tc.err)
		}
	}
	if names := Names(); !slices.Equal(names, []string{"cloudflare", "digitalocean", "exec", "gcp", "route53"}) {
		t.Errorf("providers %v", names)
	}
}

func TestZoneCandidates(t *testing.T) {
	got := zoneCandidates("*.Gate.Example.com.")
	if !slices.Equal(got, []string{"gate.example.com", "example.com"}) {
		t.Errorf("zoneCandidates = %v", got)
	}
	if got := zoneCandidates("_acme-challenge.gate.example.com"); !slices.Equal(got, []string{"gate.example.com", "example.com"}) {
		t.Errorf("zoneCandidates = %v", got)
	}
}

func TestTXTQuoting(t *testing.T) {
	for in, want := range map[string]string{
		`"abc"`:         "abc",
		`abc`:           "abc",
		`"ab" "cd"`:     "abcd",
		`"a\"b\\c"`:     `a"b\c`,
		quoteTXT(`x"y`): `x"y`,
	} {
		if got := unquoteTXT(in); got != want {
			t.Errorf("unquoteTXT(%s) = %q, want %q", in, got, want)
		}
	}
}
