package wildcard

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jgermade/intergate/internal/acmetest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newManager(t *testing.T, ca *acmetest.Server, dir string, propagated func(context.Context, string, []string) error, clk *clock) *Manager {
	t.Helper()
	m, err := New(Options{
		Domain:       "gate.test",
		Email:        "admin@example.com",
		DirectoryURL: ca.URL,
		Dir:          dir,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Propagated:   propagated,
		Now:          clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return m
}

func waitStatus(t *testing.T, m *Manager, what string, cond func(Status) bool) Status {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		st := m.Status()
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: status %+v", what, st)
		}
	}
}

func hello(name string) *tls.ClientHelloInfo { return &tls.ClientHelloInfo{ServerName: name} }

func TestIssueAndRenew(t *testing.T) {
	ca := acmetest.NewServer(t)
	clk := &clock{t: time.Now()}
	ca.Now = clk.now
	dir := t.TempDir()
	m := newManager(t, ca, dir, ca.Zone.Propagated, clk)
	if m.Certificate(hello("gate.test")) != nil {
		t.Fatal("a certificate before any provider")
	}
	m.Configure(&Provider{Provider: ca.Zone, Name: "test", WildcardRecord: true})
	st := waitStatus(t, m, "issue", func(s Status) bool { return !s.NotAfter.IsZero() && !s.Issuing })
	if !slices.Equal(st.Names, []string{"gate.test", "*.gate.test"}) || st.Error != "" || st.Provider != "test" || !strings.Contains(st.Issuer, "acmetest") {
		t.Fatalf("status %+v", st)
	}
	if want := st.NotAfter.Add(-st.NotAfter.Sub(st.NotBefore) / 3); !st.RenewAt.Equal(want) {
		t.Errorf("renews at %s, want %s", st.RenewAt, want)
	}
	for _, host := range []string{"gate.test", "myapp.gate.test", "MyApp.Gate.Test."} {
		if m.Certificate(hello(host)) == nil {
			t.Errorf("no certificate for %s", host)
		}
	}
	for _, host := range []string{"", "a.b.gate.test", "gate.test.evil", "other.test"} {
		if m.Certificate(hello(host)) != nil {
			t.Errorf("certificate for %q", host)
		}
	}
	// The challenge's records are cleaned up; the wildcard record stays.
	if v := ca.Zone.Values("_acme-challenge.gate.test", "TXT"); len(v) != 0 {
		t.Errorf("TXT records left: %v", v)
	}
	if v := ca.Zone.Values("*.gate.test", "CNAME"); !slices.Equal(v, []string{"gate.test"}) {
		t.Errorf("wildcard record %v", v)
	}
	if st.Record != "*.gate.test → gate.test" {
		t.Errorf("record status %q", st.Record)
	}

	// A restart serves the stored certificate without issuing another.
	again := newManager(t, ca, dir, ca.Zone.Propagated, clk)
	if again.Certificate(hello("x.gate.test")) == nil || len(ca.Issued()) != 1 {
		t.Fatalf("stored certificate not used: %d issued", len(ca.Issued()))
	}
	again.Configure(&Provider{Provider: ca.Zone, Name: "test"})
	time.Sleep(100 * time.Millisecond)
	if n := len(ca.Issued()); n != 1 {
		t.Fatalf("issued %d certificates while the first is fresh", n)
	}

	// Two thirds into its life, it is renewed.
	clk.add(st.RenewAt.Sub(clk.now()) + time.Minute)
	again.Retry()
	waitStatus(t, again, "renew", func(s Status) bool { return s.NotAfter.After(st.NotAfter) && !s.Issuing })
	if n := len(ca.Issued()); n != 2 {
		t.Fatalf("%d certificates issued, want 2", n)
	}

	// Without a provider it is not renewed, and served until it expires.
	again.Configure(nil)
	clk.add(91 * 24 * time.Hour)
	again.Retry()
	time.Sleep(100 * time.Millisecond)
	if n := len(ca.Issued()); n != 2 {
		t.Errorf("renewed without a provider: %d issued", n)
	}
	if again.Certificate(hello("gate.test")) != nil {
		t.Error("expired certificate served")
	}
}

func TestIssueFailures(t *testing.T) {
	ca := acmetest.NewServer(t)
	clk := &clock{t: time.Now()}

	// The provider refuses the change: tried again in 5 minutes.
	zone := &acmetest.Zone{Fail: errors.New("permission denied")}
	m := newManager(t, ca, t.TempDir(), ca.Zone.Propagated, clk)
	m.Configure(&Provider{Provider: zone, Name: "broken"})
	st := waitStatus(t, m, "failure", func(s Status) bool { return s.Error != "" && !s.NextTry.IsZero() })
	if !strings.Contains(st.Error, "permission denied") || st.NextTry.Sub(clk.now()) != 5*time.Minute {
		t.Errorf("status %+v", st)
	}
	if m.Certificate(hello("gate.test")) != nil {
		t.Error("certificate without issuing")
	}

	// The records never reach the certificate authority: it says so.
	lost := &acmetest.Zone{}
	m = newManager(t, ca, t.TempDir(), func(context.Context, string, []string) error { return nil }, clk)
	m.Configure(&Provider{Provider: lost, Name: "lost"})
	st = waitStatus(t, m, "invalid challenge", func(s Status) bool { return s.Error != "" })
	if !strings.Contains(st.Error, "did not accept") || !strings.Contains(st.Error, "no TXT record") {
		t.Errorf("error %q", st.Error)
	}
	// Retry tries again now; a working provider then gets it.
	m.Configure(&Provider{Provider: ca.Zone, Name: "fixed"})
	waitStatus(t, m, "fixed", func(s Status) bool { return !s.NotAfter.IsZero() && s.Error == "" })
}
