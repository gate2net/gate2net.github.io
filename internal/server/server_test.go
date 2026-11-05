package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/admin"
	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/store"
)

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	httpAddr, sshAddr := freePort(t), freePort(t)
	cfg, err := config.Parse(fmt.Appendf(nil, `
public_url: http://gate.test
data_dir: %s
http: {listen: "%s"}
ssh: {listen: "%s", proxy_protocol: true}
auth:
  admins: [admin@example.com]
  email: {log_only: true}
`, dir, httpAddr, sshAddr))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	// Everything comes up: HTTP, the admin socket and the PID file.
	waitFor(t, func() bool {
		resp, err := http.Get("http://" + httpAddr + "/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	})
	st, err := admin.NewClient(cfg.Admin.Socket).Status(ctx)
	if err != nil || st.Version != "test" {
		t.Fatalf("admin status = %+v, %v", st, err)
	}
	if RunningPID(cfg) != os.Getpid() {
		t.Errorf("RunningPID = %d", RunningPID(cfg))
	}

	// Register a key, then connect through a "proxy" that sends a PROXY
	// protocol header: the tunnel records the original client address.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	u, _ := srv.Store().EnsureUser(ctx, "admin@example.com")
	d, _ := srv.Store().CreateSubdomain(ctx, u.ID, "app", store.AccessPublic)
	srv.Store().AddKey(ctx, d.ID, "k", signer.PublicKey())

	conn, err := net.Dial("tcp", sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	header := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444},
		&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 2222})
	if _, err := header.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	clientCfg := &ssh.ClientConfig{User: "x", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	c, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	ok, _, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"app", 80}))
	if err != nil || !ok {
		t.Fatalf("forward: %v %v", ok, err)
	}
	if tun := srv.Registry().Get("app"); tun == nil || tun.ClientAddr != "203.0.113.7:4444" {
		t.Fatalf("tunnel = %+v", tun)
	}

	// Without the header, connections are refused.
	if _, err := ssh.Dial("tcp", sshAddr, clientCfg); err == nil {
		t.Error("connection without a PROXY header accepted")
	}

	// A second server on the same data directory refuses to start.
	second, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Run(ctx); err == nil {
		t.Error("second server started on the same data directory")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "intergate.pid")); err == nil {
		t.Error("PID file left behind")
	}
	if _, err := os.Stat(cfg.Admin.Socket); err == nil {
		t.Error("admin socket left behind")
	}
}

func TestRunWithCertificateFiles(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"gate.test", "*.gate.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	httpAddr, httpsAddr, sshAddr := freePort(t), freePort(t), freePort(t)
	_, httpsPort, _ := net.SplitHostPort(httpsAddr)
	cfg, err := config.Parse(fmt.Appendf(nil, `
public_url: https://gate.test:%s
data_dir: %s
http:
  listen: "%s"
  tls: {listen: "%s", cert_file: %s/cert.pem, key_file: %s/key.pem}
ssh: {listen: "%s"}
auth:
  admins: [admin@example.com]
  email: {log_only: true}
`, httpsPort, dir, httpAddr, httpsAddr, dir, dir, sshAddr))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	pool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(der)
	pool.AddCert(cert)
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if _, port, _ := net.SplitHostPort(addr); port == "80" {
					addr = httpAddr
				} else {
					addr = httpsAddr
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	var resp *http.Response
	waitFor(t, func() bool {
		resp, err = client.Get("http://app.gate.test/x?y=1")
		return err == nil
	})
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://app.gate.test:"+httpsPort+"/x?y=1" {
		t.Errorf("redirect = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, host := range []string{"gate.test", "app.gate.test"} {
		resp, err := client.Get("https://" + host + ":" + httpsPort + "/login")
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		resp.Body.Close()
		if host == "gate.test" && (resp.StatusCode != 200 || resp.Header.Get("Strict-Transport-Security") == "") {
			t.Errorf("dashboard over HTTPS: %d %v", resp.StatusCode, resp.Header)
		}
	}
}

// TestHTTPSProxyProtocol checks that with http.tls.proxy_protocol the
// client address comes from the PROXY header, as when Traefik passes TLS
// through to intergate.
func TestHTTPSProxyProtocol(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"gate.test", "*.gate.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	httpAddr, httpsAddr, sshAddr := freePort(t), freePort(t), freePort(t)
	cfg, err := config.Parse(fmt.Appendf(nil, `
public_url: https://gate.test
data_dir: %s
http:
  listen: "%s"
  tls: {listen: "%s", cert_file: %s/cert.pem, key_file: %s/key.pem, proxy_protocol: true}
ssh: {listen: "%s"}
auth:
  admins: [admin@example.com]
  email: {log_only: true}
`, dir, httpAddr, httpsAddr, dir, dir, sshAddr))
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	srv, err := New(cfg, slog.New(slog.NewTextHandler(&logs, nil)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	pool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(der)
	pool.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
			if err == nil {
				_, err = proxyproto.HeaderProxyFromAddrs(2,
					&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000},
					&net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 443}).WriteTo(conn)
			}
			return conn, err
		},
	}}
	// An address that may not sign in is logged with the client's.
	waitFor(t, func() bool {
		req, _ := http.NewRequest("POST", "https://gate.test/api/login/email", strings.NewReader(`{"email":"stranger@elsewhere.test"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://gate.test")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return strings.Contains(logs.String(), "may not sign in")
	})
	if !strings.Contains(logs.String(), "ip=203.0.113.9") {
		t.Errorf("client address not taken from the PROXY header:\n%s", logs.String())
	}

	// Without the header, no connection: a proxy that stopped sending it
	// would otherwise make every visitor look like the proxy, sharing one
	// address's limits.
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
		},
	}}
	if resp, err := plain.Get("https://gate.test/login"); err == nil {
		resp.Body.Close()
		t.Errorf("served without a PROXY header: %d", resp.StatusCode)
	}

	if _, err := config.Parse([]byte("public_url: https://gate.test\nhttp:\n  tls: {proxy_protocol: true}\n")); err == nil {
		t.Error("proxy_protocol accepted without TLS")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestAdoptLegacyDatabase(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "gate2sky.db"), []byte("old"), 0o600)
	os.WriteFile(filepath.Join(dir, "gate2sky.db-wal"), []byte("wal"), 0o600)
	if err := adoptLegacyDatabase(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "intergate.db")); string(b) != "old" {
		t.Errorf("intergate.db = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "intergate.db-wal")); string(b) != "wal" {
		t.Errorf("intergate.db-wal = %q", b)
	}
	// An existing intergate.db wins.
	os.WriteFile(filepath.Join(dir, "gate2sky.db"), []byte("older"), 0o600)
	adoptLegacyDatabase(dir)
	if b, _ := os.ReadFile(filepath.Join(dir, "intergate.db")); string(b) != "old" {
		t.Errorf("replaced an existing database: %q", b)
	}

	// gate2net's, the newer name, before gate2sky's.
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "gate2sky.db"), []byte("older"), 0o600)
	os.WriteFile(filepath.Join(dir, "gate2net.db"), []byte("newer"), 0o600)
	if err := adoptLegacyDatabase(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "intergate.db")); string(b) != "newer" {
		t.Errorf("intergate.db = %q, want gate2net's", b)
	}
}
