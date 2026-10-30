package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// Local ports (chosen to not clash with Tor Browser 9150 / v2rayN 10808).
const (
	TorSocksPort  = 19050
	TorHTTPPort   = 19080
	TorCtrlPort   = 19051
	XraySocksPort = 10828
	XrayHTTPPort  = 10829
)

func BuildTorrc(bridges []string, transportLines []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SocksPort 127.0.0.1:%d\n", TorSocksPort)
	fmt.Fprintf(&b, "HTTPTunnelPort 127.0.0.1:%d\n", TorHTTPPort)
	b.WriteString("DataDirectory " + filepath.Join("data", "state") + "\n")
	b.WriteString("GeoIPFile " + filepath.Join("data", "geoip") + "\nGeoIPv6File " + filepath.Join("data", "geoip6") + "\n")
	b.WriteString("AvoidDiskWrites 1\nClientOnly 1\n")
	b.WriteString("Log notice stdout\n")
	if len(bridges) > 0 {
		b.WriteString("UseBridges 1\n")
		for _, l := range transportLines {
			b.WriteString(l + "\n")
		}
		for _, br := range bridges {
			b.WriteString("Bridge " + br + "\n")
		}
	}
	return b.String()
}

func BuildXrayConfig(vlessRaw, pinIP string) ([]byte, error) {
	out, err := XrayOutbound(vlessRaw)
	if err != nil {
		return nil, err
	}
	if pinIP != "" {
		if u, e := url.Parse(vlessRaw); e == nil {
			PinAddress(out, pinIP, u.Hostname())
		}
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": XraySocksPort, "protocol": "socks",
				"settings": map[string]any{"udp": true, "auth": "noauth"},
				"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}},
			map[string]any{"tag": "http", "listen": "127.0.0.1", "port": XrayHTTPPort, "protocol": "http",
				"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}},
		},
		"outbounds": []any{out, map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func excludeCIDRs(ips []string) []string {
	out := []string{}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() != nil {
				out = append(out, ip.String()+"/32")
			} else {
				out = append(out, ip.String()+"/128")
			}
		}
	}
	return out
}

// helper processes must never be routed into the tunnel (otherwise traffic loops)
var bypassProcesses = []string{"xray.exe", "tor.exe", "lyrebird.exe", "snowflake-client.exe", "conjure-client.exe",
	"webtunnel-client.exe", "MRFS.exe", "sing-box.exe"}

// BuildSingBoxConfig makes a TUN that sends the whole computer into a local SOCKS proxy.
// directDomains (VLESS server / webtunnel hosts) are resolved outside the tunnel, otherwise
// the proxy would need itself to look up its own server.
func BuildSingBoxConfig(ifName string, socksPort int, isTor bool, directDomains, excludeIPs []string) ([]byte, error) {
	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"process_name": bypassProcesses, "outbound": "direct"},
		map[string]any{"ip_is_private": true, "outbound": "direct"},
	}
	if isTor {
		// Tor carries only TCP; refuse UDP so apps (QUIC in browsers) fall back to TCP immediately
		rules = append(rules, map[string]any{"network": "udp", "action": "reject"})
	}
	dnsRules := []any{}
	if len(directDomains) > 0 {
		dnsRules = append(dnsRules, map[string]any{"domain": directDomains, "server": "local"})
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{
			"rules": dnsRules,
			"servers": []any{
				map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
				map[string]any{"type": "local", "tag": "local"},
			},
			"final":    "remote",
			"strategy": "ipv4_only",
		},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": ifName,
			// the server itself must be reached directly through the real network card
			"route_exclude_address": excludeCIDRs(excludeIPs),
			"address":               []string{"172.19.0.1/30"},
			"mtu":                   9000,
			"auto_route":            true, "strict_route": true, "stack": "mixed",
		}},
		"outbounds": []any{
			map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": socksPort, "version": "5"},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{
			"rules":                   rules,
			"final":                   "proxy",
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
