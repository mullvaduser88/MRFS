package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxPing — anything slower than this (or unreachable) is treated as dead and hidden.
const MaxPing = 500

type dnsCache struct {
	mu sync.Mutex
	m  map[string][]net.IP
}

func (c *dnsCache) lookup(ctx context.Context, host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	c.mu.Lock()
	if v, ok := c.m[host]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(cctx, host)
	var ips []net.IP
	if err == nil {
		for _, a := range addrs {
			if a.IP.To4() != nil {
				ips = append(ips, a.IP)
			}
		}
		if len(ips) == 0 {
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
		}
	}
	c.mu.Lock()
	c.m[host] = ips
	c.mu.Unlock()
	return ips
}

// tcpPing measures the TCP handshake time (DNS time is not counted).
// Two attempts, best result wins; -2 if both fail or exceed MaxPing.
func tcpPing(ctx context.Context, dc *dnsCache, host string, port int) (int, net.IP) {
	ips := dc.lookup(ctx, host)
	if len(ips) == 0 {
		return -2, nil
	}
	addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(port))
	best := -2
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			break
		}
		d := net.Dialer{Timeout: time.Duration(MaxPing+50) * time.Millisecond}
		t0 := time.Now()
		c, err := d.DialContext(ctx, "tcp", addr)
		ms := int(time.Since(t0).Milliseconds())
		if err == nil {
			c.Close()
			if ms < 1 {
				ms = 1
			}
			if ms <= MaxPing && (best < 0 || ms < best) {
				best = ms
			}
			if best > 0 && best < 150 {
				break // good enough, don't waste a second probe
			}
		}
	}
	return best, ips[0]
}

// tlsPing measures a full TLS handshake with the server (as a VLESS TLS/Reality client would do).
// Unlike a bare TCP connect it cannot be faked by antivirus / local proxies that accept
// connections instantly, so the number reflects the real distance to the server.
func tlsPing(ctx context.Context, dc *dnsCache, host string, port int, sni string, checkName bool) (int, net.IP) {
	ips := dc.lookup(ctx, host)
	if len(ips) == 0 {
		return -2, nil
	}
	addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(port))
	limit := time.Duration(MaxPing) * time.Millisecond
	cctx, cancel := context.WithTimeout(ctx, limit+100*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	d := net.Dialer{}
	raw, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return -2, ips[0]
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err := tc.HandshakeContext(cctx); err != nil {
		return -2, ips[0]
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) > 0 && isAVIssuer(certs[0].Issuer.String()) {
		mitmSeen.Add(1)
	}
	// plain TLS: Xray verifies the certificate, so a certificate for another name means the
	// server can never work (typical for dead CDN-fronted configs) — treat it as dead right away
	if checkName && sni != "" && len(certs) > 0 && certs[0].VerifyHostname(sni) != nil {
		return -2, ips[0]
	}
	ms := int(time.Since(t0).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	if ms > MaxPing {
		return -2, ips[0]
	}
	return ms, ips[0]
}

// mitmSeen counts TLS answers signed by an antivirus instead of the real server:
// the antivirus decrypts and re-encrypts traffic, which makes VLESS Reality impossible.
var mitmSeen atomic.Int64

var avNames = []string{"kaspersky", "eset", "avast", "avg ", "bitdefender", "dr.web", "drweb", "norton", "mcafee",
	"fortinet", "sophos", "trend micro", "adguard", "zscaler", "check point", "netfilter", "fiddler", "charles"}

func isAVIssuer(issuer string) bool {
	l := strings.ToLower(issuer)
	for _, n := range avNames {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

// PingAll pings servers in parallel and calls onResult for each finished one.
func PingAll(ctx context.Context, list []*Server, workers int, onResult func(s *Server, ms int, ip net.IP), done *int64) {
	dc := &dnsCache{m: map[string][]net.IP{}}
	ch := make(chan *Server)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range ch {
				var ms int
				var ip net.IP
				if s.Kind == "vless" {
					ms, ip = tlsPing(ctx, dc, s.Host, s.Port, s.SNI, s.Type == "tls")
				} else {
					ms, ip = tcpPing(ctx, dc, s.Host, s.Port)
				}
				if ctx.Err() == nil {
					onResult(s, ms, ip)
				}
				atomic.AddInt64(done, 1)
			}
		}()
	}
	for _, s := range list {
		select {
		case ch <- s:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	wg.Wait()
}
