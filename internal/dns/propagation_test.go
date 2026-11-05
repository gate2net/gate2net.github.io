package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeNameserver answers TXT queries over UDP with the values it holds,
// authoritatively.
type fakeNameserver struct {
	mu   sync.Mutex
	txt  map[string][]string // fqdn → values
	addr string
}

func newFakeNameserver(t *testing.T) *fakeNameserver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	ns := &fakeNameserver{txt: map[string][]string{}, addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(buf[:n]) != nil || len(msg.Questions) != 1 {
				continue
			}
			q := msg.Questions[0]
			ns.mu.Lock()
			values := ns.txt[strings.ToLower(q.Name.String())]
			ns.mu.Unlock()
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: msg.ID, Response: true, Authoritative: true},
				Questions: msg.Questions,
			}
			if values == nil {
				resp.RCode = dnsmessage.RCodeNameError
			}
			for _, v := range values {
				if q.Type == dnsmessage.TypeTXT {
					resp.Answers = append(resp.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.TXTResource{TXT: []string{v}},
					})
				}
			}
			out, _ := resp.Pack()
			pc.WriteTo(out, from)
		}
	}()
	return ns
}

func (ns *fakeNameserver) set(name string, values ...string) {
	ns.mu.Lock()
	ns.txt[name+"."] = values
	ns.mu.Unlock()
}

func TestWaitForTXT(t *testing.T) {
	old := pollEvery
	pollEvery = 20 * time.Millisecond
	t.Cleanup(func() { pollEvery = old })
	a, b := newFakeNameserver(t), newFakeNameserver(t)
	const name = "_acme-challenge.gate.example.com"
	servers := []string{a.addr, b.addr}

	// One nameserver has the records, the other only one of them.
	a.set(name, "v1", "v2")
	b.set(name, "v1")
	go func() {
		time.Sleep(100 * time.Millisecond)
		b.set(name, "v1", "v2", "old")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := WaitForTXT(ctx, name, []string{"v1", "v2"}, servers); err != nil {
		t.Fatal(err)
	}

	// A nameserver without them holds it up until the deadline.
	ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := WaitForTXT(ctx, "_acme-challenge.other.example.com", []string{"v1"}, servers)
	if err == nil || !strings.Contains(err.Error(), "did not reach every nameserver") {
		t.Errorf("missing records: %v", err)
	}

	// A nameserver that never answers is left out.
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	dead.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := WaitForTXT(ctx, name, []string{"v1"}, []string{deadAddr, a.addr}); err != nil {
		t.Errorf("with an unreachable nameserver: %v", err)
	}
}
