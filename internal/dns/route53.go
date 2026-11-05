package dns

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(Spec{
		Name:  "route53",
		Title: "Amazon Route 53",
		Help: "An IAM user or role allowed route53:ListHostedZonesByName, route53:ListResourceRecordSets and\n" +
			"route53:ChangeResourceRecordSets on the hosted zone. Without keys here, AWS_ACCESS_KEY_ID,\n" +
			"AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN are used, then the EC2 instance's role.",
		Fields: []Field{
			{Name: "access_key_id", Title: "Access key ID", Secret: true, Env: "AWS_ACCESS_KEY_ID",
				Description: "Optional: the environment or the EC2 instance's role otherwise."},
			{Name: "secret_access_key", Title: "Secret access key", Secret: true, Env: "AWS_SECRET_ACCESS_KEY"},
			{Name: "session_token", Title: "Session token", Secret: true, Env: "AWS_SESSION_TOKEN",
				Description: "Only for temporary credentials."},
			{Name: "hosted_zone_id", Title: "Hosted zone ID",
				Description: "Optional: found from the domain otherwise."},
		},
		Check: func(o Options) error {
			if (o["access_key_id"] == "") != (o["secret_access_key"] == "") {
				return errors.New("access_key_id and secret_access_key go together")
			}
			return nil
		},
		New: newRoute53,
	})
}

const route53Endpoint = "https://route53.amazonaws.com"

type route53 struct {
	client   *http.Client
	endpoint string
	creds    awsCredentials
	zoneID   string
	zones    zoneCache
	now      func() time.Time
}

func newRoute53(o Options, env Env) (Provider, error) {
	r := &route53{
		client:   env.HTTPClient,
		endpoint: route53Endpoint,
		zoneID:   strings.TrimPrefix(strings.TrimSpace(o["hosted_zone_id"]), "/hostedzone/"),
		now:      time.Now,
	}
	switch {
	case o["access_key_id"] != "":
		r.creds = staticAWS{id: o["access_key_id"], secret: o["secret_access_key"], token: o["session_token"]}
	case os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "":
		r.creds = staticAWS{id: os.Getenv("AWS_ACCESS_KEY_ID"), secret: os.Getenv("AWS_SECRET_ACCESS_KEY"), token: os.Getenv("AWS_SESSION_TOKEN")}
	default:
		r.creds = &instanceRole{base: "http://169.254.169.254", client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{Proxy: nil}, // the metadata service is never behind a proxy
		}}
	}
	return r, nil
}

type awsKey struct{ id, secret, token string }

type awsCredentials interface {
	get(ctx context.Context) (awsKey, error)
}

type staticAWS awsKey

func (s staticAWS) get(context.Context) (awsKey, error) { return awsKey(s), nil }

// instanceRole reads the credentials of an EC2 instance's role from the
// instance metadata service (IMDSv2).
type instanceRole struct {
	base   string
	client *http.Client

	mu      sync.Mutex
	key     awsKey
	expires time.Time
}

func (r *instanceRole) get(ctx context.Context) (awsKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.key.id != "" && time.Until(r.expires) > 5*time.Minute {
		return r.key, nil
	}
	call := func(method, path, token string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, method, r.base+path, nil)
		if err != nil {
			return "", err
		}
		if token == "" {
			req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		} else {
			req.Header.Set("X-aws-ec2-metadata-token", token)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
		}
		return strings.TrimSpace(string(b)), err
	}
	fail := func(err error) (awsKey, error) {
		return awsKey{}, fmt.Errorf("no AWS credentials: set access_key_id and secret_access_key, or run on EC2 with a role (%v)", err)
	}
	token, err := call(http.MethodPut, "/latest/api/token", "")
	if err != nil {
		return fail(err)
	}
	roles, err := call(http.MethodGet, "/latest/meta-data/iam/security-credentials/", token)
	if err != nil {
		return fail(err)
	}
	role, _, _ := strings.Cut(roles, "\n")
	raw, err := call(http.MethodGet, "/latest/meta-data/iam/security-credentials/"+role, token)
	if err != nil {
		return fail(err)
	}
	var c struct {
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		Token           string    `json:"Token"`
		Expiration      time.Time `json:"Expiration"`
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil || c.AccessKeyID == "" {
		return fail(fmt.Errorf("unexpected credentials of role %s", role))
	}
	r.key, r.expires = awsKey{c.AccessKeyID, c.SecretAccessKey, c.Token}, c.Expiration
	return r.key, nil
}

// do signs a request with AWS Signature Version 4 and decodes its XML
// answer into out.
func (r *route53) do(ctx context.Context, method, path string, query [][2]string, body []byte, out any) error {
	key, err := r.creds.get(ctx)
	if err != nil {
		return fmt.Errorf("route53: %w", err)
	}
	sort.Slice(query, func(i, j int) bool { return query[i][0] < query[j][0] })
	var q []string
	for _, kv := range query {
		q = append(q, awsEscape(kv[0])+"="+awsEscape(kv[1]))
	}
	rawQuery := strings.Join(q, "&")
	u := r.endpoint + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/xml")
	}
	sigV4(req, key, rawQuery, body, "us-east-1", "route53", r.now())
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("route53: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("route53: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		xml.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Error.Code + ": " + e.Error.Message)
		if e.Error.Code == "" {
			msg = ""
		}
		return &apiError{Provider: "route53", Status: resp.StatusCode, Message: msg}
	}
	if out != nil {
		if err := xml.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("route53: unexpected answer: %w", err)
		}
	}
	return nil
}

// sigV4 signs req (whose URL already carries rawQuery) for an AWS service.
func sigV4(req *http.Request, key awsKey, rawQuery string, body []byte, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	payload := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(payload[:])
	req.Header.Set("X-Amz-Date", amzDate)
	if key.token != "" {
		req.Header.Set("X-Amz-Security-Token", key.token)
	}
	headers := map[string]string{"host": req.URL.Host}
	for name, v := range req.Header {
		headers[strings.ToLower(name)] = strings.TrimSpace(strings.Join(v, ","))
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, name := range names {
		canonHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{req.Method, path, rawQuery, canonHeaders.String(), signed, payloadHash}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	mac := func(k []byte, s string) []byte {
		h := hmac.New(sha256.New, k)
		h.Write([]byte(s))
		return h.Sum(nil)
	}
	k := mac([]byte("AWS4"+key.secret), day)
	k = mac(k, region)
	k = mac(k, service)
	k = mac(k, "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+key.id+"/"+scope+
		", SignedHeaders="+signed+", Signature="+hex.EncodeToString(mac(k, toSign)))
}

// awsEscape is the URI encoding of Signature Version 4: everything but
// unreserved characters, with upper-case hex.
func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// route53Name reads a name as Route 53 writes it: \052 for the wildcard's
// asterisk, and other characters escaped in octal.
func route53Name(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return Canonical(b.String())
}

func (r *route53) zone(ctx context.Context, name string) (string, error) {
	if r.zoneID != "" {
		return r.zoneID, nil
	}
	z, err := r.zones.find(ctx, name, func(ctx context.Context, cand string) (zone, bool, error) {
		var out struct {
			HostedZones []struct {
				ID      string `xml:"Id"`
				Name    string `xml:"Name"`
				Private bool   `xml:"Config>PrivateZone"`
			} `xml:"HostedZones>HostedZone"`
		}
		if err := r.do(ctx, http.MethodGet, "/2013-04-01/hostedzonesbyname", [][2]string{{"dnsname", cand}, {"maxitems", "10"}}, nil, &out); err != nil {
			return zone{}, false, err
		}
		for _, z := range out.HostedZones {
			if route53Name(z.Name) == cand && !z.Private {
				return zone{ID: strings.TrimPrefix(z.ID, "/hostedzone/"), Name: cand}, true, nil
			}
		}
		return zone{}, false, nil
	})
	return z.ID, err
}

type r53RecordSet struct {
	Name   string   `xml:"Name"`
	Type   string   `xml:"Type"`
	TTL    int      `xml:"TTL"`
	Values []string `xml:"ResourceRecords>ResourceRecord>Value"`
}

// current returns the record set of a name and type, or nil.
func (r *route53) current(ctx context.Context, zoneID, name, typ string) (*r53RecordSet, error) {
	var out struct {
		Sets []r53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	q := [][2]string{{"name", name}, {"type", typ}, {"maxitems", "1"}}
	if err := r.do(ctx, http.MethodGet, "/2013-04-01/hostedzone/"+zoneID+"/rrset", q, nil, &out); err != nil {
		return nil, err
	}
	// The list starts at the name and type, whether or not they exist.
	for _, s := range out.Sets {
		if route53Name(s.Name) == name && s.Type == typ {
			return &s, nil
		}
	}
	return nil, nil
}

func (r *route53) change(ctx context.Context, zoneID, action string, set r53RecordSet) error {
	type change struct {
		Action string       `xml:"Action"`
		Set    r53RecordSet `xml:"ResourceRecordSet"`
	}
	req := struct {
		XMLName xml.Name `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ChangeResourceRecordSetsRequest"`
		Changes []change `xml:"ChangeBatch>Changes>Change"`
	}{Changes: []change{{Action: action, Set: set}}}
	body, err := xml.Marshal(req)
	if err != nil {
		return err
	}
	return r.do(ctx, http.MethodPost, "/2013-04-01/hostedzone/"+zoneID+"/rrset/", nil, append([]byte(xml.Header), body...), nil)
}

func (r *route53) Set(ctx context.Context, rs RecordSet) error {
	name := Canonical(rs.Name)
	zoneID, err := r.zone(ctx, name)
	if err != nil {
		return err
	}
	set := r53RecordSet{Name: fqdn(name), Type: rs.Type, TTL: rs.TTL}
	for _, v := range rs.Values {
		if rs.Type == "TXT" {
			v = quoteTXT(v)
		}
		set.Values = append(set.Values, v)
	}
	if cur, err := r.current(ctx, zoneID, name, rs.Type); err != nil {
		return err
	} else if cur != nil && cur.TTL == rs.TTL && sameValues(rs.Type, cur.Values, rs.Values) {
		return nil
	}
	return r.change(ctx, zoneID, "UPSERT", set)
}

func (r *route53) Delete(ctx context.Context, name, typ string) error {
	name = Canonical(name)
	zoneID, err := r.zone(ctx, name)
	if err != nil {
		return err
	}
	cur, err := r.current(ctx, zoneID, name, typ)
	if err != nil || cur == nil {
		return err
	}
	// A deletion names the record set exactly as it is.
	cur.Name = fqdn(name)
	return r.change(ctx, zoneID, "DELETE", *cur)
}
