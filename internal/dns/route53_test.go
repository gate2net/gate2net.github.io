package dns

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSigV4 checks the signature against the get-vanilla-query case of
// AWS's Signature Version 4 test suite.
func TestSigV4(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/?Param1=value1&Param2=value2", nil)
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	sigV4(req, awsKey{id: "AKIDEXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "Param1=value1&Param2=value2", nil, "us-east-1", "service", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, " +
		"Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization:\n %s\nwant\n %s", got, want)
	}
	// get-vanilla
	req, _ = http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	sigV4(req, awsKey{id: "AKIDEXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "", nil, "us-east-1", "service", now)
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31") {
		t.Errorf("get-vanilla: %s", got)
	}
	if awsEscape("*.a b/~") != "%2A.a%20b%2F~" {
		t.Errorf("awsEscape = %s", awsEscape("*.a b/~"))
	}
}

// fakeRoute53 is the part of Route 53's API the provider uses.
type fakeRoute53 struct {
	mu   sync.Mutex
	sets map[string]r53RecordSet // "name type", names as Route 53 writes them
}

func r53Key(name, typ string) string { return strings.ReplaceAll(fqdn(name), "*", `\052`) + " " + typ }

func (f *fakeRoute53) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status int, code, msg string) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error></ErrorResponse>`, code, msg)
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(auth, "/us-east-1/route53/aws4_request") {
		fail(403, "InvalidClientTokenId", "The security token included in the request is invalid.")
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/2013-04-01/hostedzonesbyname":
		// Sorted by name, starting at dnsname: example.com's zones for
		// gate.example.com too.
		w.Write([]byte(`<ListHostedZonesByNameResponse><HostedZones>
			<HostedZone><Id>/hostedzone/ZPRIVATE</Id><Name>example.com.</Name><Config><PrivateZone>true</PrivateZone></Config></HostedZone>
			<HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone>
			</HostedZones></ListHostedZonesByNameResponse>`))
	case r.Method == "GET" && r.URL.Path == "/2013-04-01/hostedzone/Z1/rrset":
		want := r53Key(r.URL.Query().Get("name"), r.URL.Query().Get("type"))
		var keys []string
		for k := range f.sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// The record set asked for, or the next one.
		var out []r53RecordSet
		for _, k := range keys {
			if k >= want {
				out = append(out, f.sets[k])
				break
			}
		}
		b, _ := xml.Marshal(struct {
			XMLName xml.Name       `xml:"ListResourceRecordSetsResponse"`
			Sets    []r53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
		}{Sets: out})
		w.Write(b)
	case r.Method == "POST" && r.URL.Path == "/2013-04-01/hostedzone/Z1/rrset/":
		var req struct {
			Changes []struct {
				Action string       `xml:"Action"`
				Set    r53RecordSet `xml:"ResourceRecordSet"`
			} `xml:"ChangeBatch>Changes>Change"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Changes) != 1 {
			fail(400, "InvalidInput", "bad request")
			return
		}
		c := req.Changes[0]
		key := r53Key(c.Set.Name, c.Set.Type)
		c.Set.Name = strings.SplitN(key, " ", 2)[0]
		switch c.Action {
		case "UPSERT":
			f.sets[key] = c.Set
		case "DELETE":
			cur, ok := f.sets[key]
			if !ok || cur.TTL != c.Set.TTL || strings.Join(cur.Values, ",") != strings.Join(c.Set.Values, ",") {
				fail(400, "InvalidChangeBatch", "Tried to delete resource record set but it was not found")
				return
			}
			delete(f.sets, key)
		}
		w.Write([]byte(`<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`))
	default:
		fail(404, "NoSuchResource", r.URL.Path)
	}
}

func (f *fakeRoute53) values(name, typ string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets[r53Key(name, typ)].Values
}

func TestRoute53(t *testing.T) {
	f := &fakeRoute53{sets: map[string]r53RecordSet{
		r53Key("gate.example.com", "A"):   {Name: "gate.example.com.", Type: "A", TTL: 300, Values: []string{"203.0.113.7"}},
		r53Key("*.gate.example.com", "A"): {Name: `\052.gate.example.com.`, Type: "A", TTL: 300, Values: []string{"203.0.113.8"}},
	}}
	env := fakeAPI(t, f)
	p, err := New("route53", Options{"access_key_id": "AKID", "secret_access_key": "secret"}, env)
	if err != nil {
		t.Fatal(err)
	}
	conformance(t, p, f.values)

	t.Setenv("AWS_ACCESS_KEY_ID", "OTHER")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	fromEnv, _ := New("route53", Options{"hosted_zone_id": "/hostedzone/Z1"}, env)
	err = fromEnv.Delete(context.Background(), "gate.example.com", "TXT")
	if err == nil || !strings.Contains(err.Error(), "InvalidClientTokenId") {
		t.Errorf("credentials from the environment: %v", err)
	}
	if route53Name(`\052.gate.example.com.`) != "*.gate.example.com" {
		t.Error("route53Name")
	}
}
