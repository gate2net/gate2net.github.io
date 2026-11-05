package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// pollEvery is how often WaitForTXT asks the nameservers again.
var pollEvery = 4 * time.Second

// Propagation returns a function that waits until the authoritative
// nameservers of a name's zone serve its TXT values, for at most timeout.
// The ACME server queries them itself: asking before they all have the
// records would fail the challenge, and count against its rate limits.
func Propagation(timeout time.Duration) func(ctx context.Context, name string, values []string) error {
	return func(ctx context.Context, name string, values []string) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		servers, err := AuthoritativeServers(ctx, name)
		if err != nil {
			return err
		}
		return WaitForTXT(ctx, name, values, servers)
	}
}

// PropagationAt is Propagation asking these servers (host:port) instead
// of the zone's own nameservers.
func PropagationAt(servers []string, timeout time.Duration) func(ctx context.Context, name string, values []string) error {
	return func(ctx context.Context, name string, values []string) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return WaitForTXT(ctx, name, values, servers)
	}
}

// AuthoritativeServers returns the addresses (host:53) of the nameservers
// of the zone a name belongs to: the NS records of the closest name above
// it that has them.
func AuthoritativeServers(ctx context.Context, name string) ([]string, error) {
	var lastErr error
	for _, cand := range zoneCandidates(name) {
		nss, err := net.DefaultResolver.LookupNS(ctx, cand+".")
		if err != nil || len(nss) == 0 {
			var de *net.DNSError
			if err != nil && !(errors.As(err, &de) && de.IsNotFound) {
				lastErr = err
			}
			continue
		}
		var out []string
		for _, ns := range nss {
			addrs, err := net.DefaultResolver.LookupHost(ctx, ns.Host)
			if err != nil {
				lastErr = err
				continue
			}
			// IPv4 first: not every server reaches IPv6.
			sort.SliceStable(addrs, func(i, j int) bool { return strings.Contains(addrs[j], ":") && !strings.Contains(addrs[i], ":") })
			// One address per nameserver is enough.
			out = append(out, net.JoinHostPort(addrs[0], "53"))
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("find the nameservers of %s: %w", name, lastErr)
	}
	return nil, fmt.Errorf("find the nameservers of %s: no NS records above it", name)
}

// WaitForTXT asks each server for the TXT records of name until all that
// answer serve every value, and at least one does. A server that does not
// answer at all is left out, so one unreachable nameserver (IPv6 only,
// say) does not hold the rest up.
func WaitForTXT(ctx context.Context, name string, values []string, servers []string) error {
	var missing []string
	for {
		missing = missing[:0]
		answered := 0
		for _, srv := range servers {
			got, err := lookupTXTAt(ctx, srv, name)
			var de *net.DNSError
			switch {
			case err == nil:
			case errors.As(err, &de) && de.IsNotFound:
				got = nil
			default:
				continue // no answer
			}
			answered++
			for _, v := range values {
				if !containsValue("TXT", got, v) {
					missing = append(missing, srv)
					break
				}
			}
		}
		if answered > 0 && len(missing) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			if answered == 0 {
				return fmt.Errorf("the nameservers of %s did not answer (%s)", name, strings.Join(servers, ", "))
			}
			return fmt.Errorf("the TXT records of %s did not reach every nameserver in time (still missing on %s)", name, strings.Join(missing, ", "))
		case <-time.After(pollEvery):
		}
	}
}

// lookupTXTAt asks one server for the TXT records of name.
func lookupTXTAt(ctx context.Context, server, name string) ([]string, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, server)
	}}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.LookupTXT(ctx, Canonical(name)+".")
}
