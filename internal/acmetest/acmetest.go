// Package acmetest is a certificate authority for tests: just enough of
// ACME (RFC 8555) for golang.org/x/crypto/acme and autocert, with a DNS
// zone in memory that it checks DNS-01 challenges against. HTTP-01 and
// TLS-ALPN-01 challenges pass without being checked.
package acmetest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/jgermade/intergate/internal/dns"
)

// Server is a fake ACME certificate authority.
type Server struct {
	// URL is the directory URL.
	URL string
	// Lifetime of the certificates it issues; 90 days by default.
	Lifetime time.Duration
	// Zone is where DNS-01 challenges are looked up.
	Zone *Zone
	// Now dates the certificates; time.Now by default.
	Now func() time.Time

	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	base  string

	mu       sync.Mutex
	next     int
	accounts map[string]crypto.PublicKey // account URL → key
	byKey    map[string]string           // thumbprint → account URL
	orders   map[string]*order
	authzs   map[string]*authz
	chals    map[string]*chal
	certs    map[string][]byte
	issued   []*x509.Certificate
}

type order struct {
	Status         string           `json:"status"`
	Identifiers    []acme.AuthzID   `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
	Error          *json.RawMessage `json:"error,omitempty"`
	account        string
}

type authz struct {
	Status     string       `json:"status"`
	Identifier acme.AuthzID `json:"identifier"`
	Wildcard   bool         `json:"wildcard,omitempty"`
	Challenges []*chal      `json:"challenges"`
	account    string
}

type chal struct {
	Type   string          `json:"type"`
	URL    string          `json:"url"`
	Token  string          `json:"token"`
	Status string          `json:"status"`
	Error  json.RawMessage `json:"error,omitempty"`
	authz  *authz
}

// NewServer starts a certificate authority, closed when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acmetest CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	s := &Server{
		Lifetime: 90 * 24 * time.Hour,
		Zone:     &Zone{},
		Now:      time.Now,
		ca:       ca,
		caKey:    key,
		accounts: map[string]crypto.PublicKey{},
		byKey:    map[string]string{},
		orders:   map[string]*order{},
		authzs:   map[string]*authz{},
		chals:    map[string]*chal{},
		certs:    map[string][]byte{},
	}
	hs := httptest.NewServer(s)
	t.Cleanup(hs.Close)
	s.base = hs.URL
	s.URL = hs.URL + "/directory"
	return s
}

// Roots trusts the certificates the server issues.
func (s *Server) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.ca)
	return p
}

// Issued returns every certificate issued so far.
func (s *Server) Issued() []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*x509.Certificate(nil), s.issued...)
}

func (s *Server) id(kind string) string {
	s.next++
	return s.base + "/" + kind + "/" + strconv.Itoa(s.next)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", strconv.FormatInt(time.Now().UnixNano(), 36))
	if r.URL.Path == "/directory" {
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce":   s.base + "/nonce",
			"newAccount": s.base + "/account",
			"newOrder":   s.base + "/order",
			"revokeCert": s.base + "/revoke",
			"keyChange":  s.base + "/key-change",
			"meta":       map[string]any{"termsOfService": s.base + "/terms"},
		})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		problem(w, http.StatusMethodNotAllowed, "malformed", "POST only")
		return
	}
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		problem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	var head struct {
		JWK json.RawMessage `json:"jwk"`
		KID string          `json:"kid"`
	}
	ph, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	json.Unmarshal(ph, &head)

	s.mu.Lock()
	defer s.mu.Unlock()
	url := s.base + r.URL.Path
	if r.URL.Path == "/account" {
		s.account(w, head.JWK, payload)
		return
	}
	if _, ok := s.accounts[head.KID]; !ok {
		problem(w, http.StatusUnauthorized, "accountDoesNotExist", "unknown account "+head.KID)
		return
	}
	switch {
	case r.URL.Path == "/order":
		s.newOrder(w, head.KID, payload)
	case strings.HasPrefix(r.URL.Path, "/order/"):
		s.writeOrder(w, http.StatusOK, url)
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		if a := s.authzs[url]; a != nil {
			writeJSON(w, http.StatusOK, a)
		} else {
			problem(w, http.StatusNotFound, "malformed", "no such authorization")
		}
	case strings.HasPrefix(r.URL.Path, "/chall/"):
		s.accept(w, url, head.KID)
	case strings.HasPrefix(r.URL.Path, "/finalize/"):
		s.finalize(w, strings.Replace(url, "/finalize/", "/order/", 1), payload)
	case strings.HasPrefix(r.URL.Path, "/cert/"):
		if c := s.certs[url]; c != nil {
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(c)
		} else {
			problem(w, http.StatusNotFound, "malformed", "no such certificate")
		}
	default:
		problem(w, http.StatusNotFound, "malformed", "no such resource")
	}
}

func (s *Server) account(w http.ResponseWriter, jwk json.RawMessage, payload []byte) {
	pub, err := parseJWK(jwk)
	if err != nil {
		problem(w, http.StatusBadRequest, "badPublicKey", err.Error())
		return
	}
	tp, _ := acme.JWKThumbprint(pub)
	var req struct {
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
		Contact            []string `json:"contact"`
	}
	json.Unmarshal(payload, &req)
	if u, ok := s.byKey[tp]; ok {
		w.Header().Set("Location", u)
		writeJSON(w, http.StatusOK, map[string]any{"status": "valid", "contact": req.Contact})
		return
	}
	if req.OnlyReturnExisting {
		problem(w, http.StatusBadRequest, "accountDoesNotExist", "no account with this key")
		return
	}
	u := s.id("acct")
	s.accounts[u], s.byKey[tp] = pub, u
	w.Header().Set("Location", u)
	writeJSON(w, http.StatusCreated, map[string]any{"status": "valid", "contact": req.Contact})
}

func (s *Server) newOrder(w http.ResponseWriter, account string, payload []byte) {
	var req struct {
		Identifiers []acme.AuthzID `json:"identifiers"`
	}
	json.Unmarshal(payload, &req)
	o := &order{Status: "pending", Identifiers: req.Identifiers, account: account}
	u := s.id("order")
	o.Finalize = strings.Replace(u, "/order/", "/finalize/", 1)
	for _, id := range req.Identifiers {
		a := &authz{Status: "pending", Identifier: acme.AuthzID{Type: id.Type, Value: strings.TrimPrefix(id.Value, "*.")}, account: account}
		a.Wildcard = strings.HasPrefix(id.Value, "*.")
		types := []string{"dns-01"}
		if !a.Wildcard {
			types = append(types, "http-01", "tls-alpn-01")
		}
		for _, typ := range types {
			c := &chal{Type: typ, URL: s.id("chall"), Token: randomToken(), Status: "pending", authz: a}
			s.chals[c.URL] = c
			a.Challenges = append(a.Challenges, c)
		}
		au := s.id("authz")
		s.authzs[au] = a
		o.Authorizations = append(o.Authorizations, au)
	}
	s.orders[u] = o
	s.writeOrder(w, http.StatusCreated, u)
}

func (s *Server) writeOrder(w http.ResponseWriter, status int, u string) {
	o := s.orders[u]
	if o == nil {
		problem(w, http.StatusNotFound, "malformed", "no such order")
		return
	}
	if o.Status == "pending" {
		ready := true
		for _, au := range o.Authorizations {
			switch s.authzs[au].Status {
			case "invalid":
				o.Status = "invalid"
			case "valid":
			default:
				ready = false
			}
		}
		if ready && o.Status == "pending" {
			o.Status = "ready"
		}
	}
	w.Header().Set("Location", u)
	writeJSON(w, status, o)
}

func (s *Server) accept(w http.ResponseWriter, u, account string) {
	c := s.chals[u]
	if c == nil || c.authz.account != account {
		problem(w, http.StatusNotFound, "malformed", "no such challenge")
		return
	}
	if c.Status == "pending" {
		c.Status = "valid"
		if c.Type == "dns-01" {
			want := keyAuthDigest(c.Token, s.accounts[account])
			name := dns.ChallengeName(c.authz.Identifier.Value)
			found := false
			for _, v := range s.Zone.Values(name, "TXT") {
				found = found || v == want
			}
			if !found {
				c.Status = "invalid"
				c.Error, _ = json.Marshal(map[string]string{
					"type":   "urn:ietf:params:acme:error:unauthorized",
					"detail": "no TXT record " + want + " at " + name,
				})
			}
		}
		c.authz.Status = c.Status
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) finalize(w http.ResponseWriter, orderURL string, payload []byte) {
	o := s.orders[orderURL]
	if o == nil {
		problem(w, http.StatusNotFound, "malformed", "no such order")
		return
	}
	if o.Status != "ready" {
		problem(w, http.StatusForbidden, "orderNotReady", "order is "+o.Status)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	json.Unmarshal(payload, &req)
	der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		problem(w, http.StatusBadRequest, "badCSR", err.Error())
		return
	}
	want := map[string]bool{}
	for _, id := range o.Identifiers {
		want[id.Value] = true
	}
	if len(csr.DNSNames) != len(want) {
		problem(w, http.StatusBadRequest, "badCSR", "the CSR's names are not the order's")
		return
	}
	for _, n := range csr.DNSNames {
		if !want[n] {
			problem(w, http.StatusBadRequest, "badCSR", "the order does not have "+n)
			return
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(s.next + 100)),
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    s.Now().Add(-time.Minute),
		NotAfter:     s.Now().Add(s.Lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca, csr.PublicKey, s.caKey)
	if err != nil {
		problem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	cert, _ := x509.ParseCertificate(leaf)
	s.issued = append(s.issued, cert)
	cu := strings.Replace(orderURL, "/order/", "/cert/", 1)
	s.certs[cu] = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.ca.Raw})...)
	// Like Pebble: the certificate is issued after the answer, which says
	// so ("processing") without the Location header RFC 8555 does not
	// ask for here, and the order is valid when asked again.
	answer := *o
	answer.Status = "processing"
	o.Status, o.Certificate = "valid", cu
	writeJSON(w, http.StatusOK, answer)
}

func keyAuthDigest(token string, pub crypto.PublicKey) string {
	tp, _ := acme.JWKThumbprint(pub)
	sum := sha256.Sum256([]byte(token + "." + tp))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func parseJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	var k struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("only P-256 keys, not %s %s", k.Kty, k.Crv)
	}
	x, _ := base64.RawURLEncoding.DecodeString(k.X)
	y, _ := base64.RawURLEncoding.DecodeString(k.Y)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

func randomToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status})
}

// Zone is a DNS zone in memory, and a dns.Provider that changes it.
type Zone struct {
	mu   sync.Mutex
	sets map[string]dns.RecordSet
	// Fail, when set, is returned by every change.
	Fail error
	// Changes counts the changes made.
	Changes int
}

func zoneKey(name, typ string) string { return dns.Canonical(name) + " " + typ }

// Set replaces the records of a name and type.
func (z *Zone) Set(_ context.Context, rs dns.RecordSet) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.Fail != nil {
		return z.Fail
	}
	if z.sets == nil {
		z.sets = map[string]dns.RecordSet{}
	}
	rs.Values = append([]string(nil), rs.Values...)
	z.sets[zoneKey(rs.Name, rs.Type)] = rs
	z.Changes++
	return nil
}

// Delete removes the records of a name and type.
func (z *Zone) Delete(_ context.Context, name, typ string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.Fail != nil {
		return z.Fail
	}
	delete(z.sets, zoneKey(name, typ))
	z.Changes++
	return nil
}

// Values returns the records of a name and type.
func (z *Zone) Values(name, typ string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.sets[zoneKey(name, typ)].Values...)
}

// Propagated is a propagation check for the zone: its records are served
// as soon as they are set.
func (z *Zone) Propagated(_ context.Context, name string, values []string) error {
	got := z.Values(name, "TXT")
	for _, v := range values {
		found := false
		for _, g := range got {
			found = found || g == v
		}
		if !found {
			return fmt.Errorf("acmetest: %s has no TXT %s", name, v)
		}
	}
	return nil
}
