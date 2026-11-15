package api

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// trustedProxies are the addresses of reverse proxies this service sits behind,
// from TRUSTED_PROXIES (comma-separated IPs or CIDRs), the same setting an
// Identity Agent reads. Empty by default: with no proxy in front, every
// forwarding header is written by the caller.
func trustedProxies() []*net.IPNet {
	var out []*net.IPNet
	for _, f := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			if strings.Contains(f, ":") {
				f += "/128"
			} else {
				f += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func isTrustedProxy(ip string, proxies []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range proxies {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// clientIP is the address of the connection, unless that connection is from a
// configured trusted proxy, in which case it is the nearest address in
// X-Forwarded-For that is not itself a trusted proxy. A forwarding header from
// anybody else is ignored: it is whatever the caller chose to write, and
// believing it lets a caller pick a fresh identity for every request, which
// defeats every rate limit and lets a sender be recorded as someone else.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	proxies := trustedProxies()
	if len(proxies) == 0 || !isTrustedProxy(host, proxies) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if !isTrustedProxy(hop, proxies) {
			return hop
		}
	}
	return host
}
