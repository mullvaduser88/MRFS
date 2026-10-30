package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Server is one Tor bridge or one VLESS config.
type Server struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`    // tor | vless
	Name    string   `json:"name"`    // display name: "Germany #3"
	Country string   `json:"country"` // ISO code (lowercase) for the flag, "" = unknown
	Orig    string   `json:"-"`       // name from the source file (may contain ads) — never shown
	Type    string   `json:"type"`    // obfs4/webtunnel/vanilla/snowflake  or  reality/tls/none
	Net     string   `json:"net"`     // vless transport (tcp/ws/grpc/xhttp/…)
	Host    string   `json:"host"`    // host used for ping
	Port    int      `json:"port"`    // port used for ping
	Ping    int      `json:"ping"`    // ms; -1 = not tested yet; -2 = dead
	Sources []string `json:"-"`
	Raw     string   `json:"-"`
	IP      string   `json:"-"`
	SNI     string   `json:"-"`  // TLS server name used for the TLS ping (vless only)
	Fail    int      `json:"-"`  // failed real connection attempts
	Checked int      `json:"-"`  // real traffic check: 0 = not yet, 1 = works, -1 = no traffic
	Delay   int      `json:"-"`  // real delay through the server, ms
	Exit    string   `json:"-"`  // country where traffic really exits (from the check)
	OK      bool     `json:"ok"` // UI: verified by a real request
}

func idOf(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:8])
}

var pbkRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}=?$`)
var fpRe = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)

// ParseBridge understands lines like
//
//	obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0
//	webtunnel [2001:db8::1]:443 FINGERPRINT url=https://… ver=0.0.3
//	1.2.3.4:9001 FINGERPRINT            (vanilla)
//	snowflake 192.0.2.3:80 FP fingerprint=… url=… front=…
//
// Optional "Bridge " prefix is stripped.
func ParseBridge(line string) *Server {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "Bridge ")
	line = strings.TrimPrefix(line, "bridge ")
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil
	}
	f := strings.Fields(line)
	if len(f) < 1 {
		return nil
	}
	typ := "vanilla"
	addrIdx := 0
	if !strings.ContainsAny(f[0][:1], "0123456789[") {
		typ = strings.ToLower(f[0])
		addrIdx = 1
	}
	switch typ {
	case "vanilla", "obfs4", "webtunnel", "snowflake":
	default:
		return nil // dnstt, meek, conjure… not supported by the bundled transports we rely on
	}
	if len(f) <= addrIdx {
		return nil
	}
	host, portS, err := net.SplitHostPort(f[addrIdx])
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(portS)
	if port <= 0 || port > 65535 || net.ParseIP(host) == nil {
		return nil
	}
	if typ == "vanilla" || typ == "obfs4" {
		if len(f) <= addrIdx+1 || !fpRe.MatchString(f[addrIdx+1]) {
			return nil
		}
	}
	if typ == "obfs4" && !strings.Contains(line, "cert=") {
		return nil
	}
	params := map[string]string{}
	for _, kv := range f[addrIdx+1:] {
		if i := strings.IndexByte(kv, '='); i > 0 {
			params[kv[:i]] = kv[i+1:]
		}
	}
	pingHost, pingPort := host, port
	switch typ {
	case "webtunnel":
		// the IP in a webtunnel line is a placeholder — the real endpoint is the URL
		u, err := url.Parse(params["url"])
		if err != nil || u.Hostname() == "" {
			return nil
		}
		pingHost, pingPort = u.Hostname(), 443
		if p, _ := strconv.Atoi(u.Port()); p > 0 {
			pingPort = p
		}
	case "snowflake":
		// snowflake goes through a domain-fronted broker; measure the front
		front := params["front"]
		if front == "" {
			if fr := params["fronts"]; fr != "" {
				front = strings.Split(fr, ",")[0]
			}
		}
		if front == "" {
			if u, err := url.Parse(params["url"]); err == nil {
				front = u.Hostname()
			}
		}
		if front == "" {
			return nil
		}
		pingHost, pingPort = front, 443
	}
	name := typ + " " + f[addrIdx]
	if typ == "webtunnel" {
		name = "webtunnel " + pingHost
	}
	if typ == "snowflake" {
		name = "snowflake (через " + pingHost + ")"
	}
	norm := strings.Join(f, " ")
	return &Server{ID: "t" + idOf(norm), Kind: "tor", Name: name, Orig: name, Type: typ, Host: pingHost, Port: pingPort,
		Ping: -1, Raw: norm}
}

// ParseVless returns nil for anything that is not a usable vless:// link.
func ParseVless(line string) *Server {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToLower(line), "vless://") {
		return nil
	}
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if host == "" || port <= 0 || port > 65535 || host == "0.0.0.0" || host == "127.0.0.1" || host == "localhost" {
		return nil
	}
	uid := u.User.Username()
	if uid == "" || uid == "00000000-0000-0000-0000-000000000000" {
		return nil
	}
	q := u.Query()
	sec := strings.ToLower(q.Get("security"))
	if sec == "" || sec == "false" {
		sec = "none"
	}
	// plain (unencrypted) VLESS is refused by modern Xray and is unsafe anyway
	if sec != "tls" && sec != "reality" {
		return nil
	}
	if sec == "reality" && !pbkRe.MatchString(q.Get("pbk")) {
		return nil
	}
	// configs that only work with certificate checks disabled are not supported by Xray anymore
	if sec == "tls" && (truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) || truthy(q.Get("allowinsecure"))) {
		return nil
	}
	netw := normNet(q.Get("type"))
	if netw == "" {
		return nil
	}
	name, _ := url.PathUnescape(u.Fragment)
	name = strings.TrimSpace(name)
	if name == "" {
		name = host
	}
	if len([]rune(name)) > 70 {
		name = string([]rune(name)[:70]) + "…"
	}
	// identity = everything except the display name
	idKey := strings.SplitN(line, "#", 2)[0]
	sniV := q.Get("sni")
	if sniV == "" {
		sniV = q.Get("host")
	}
	if sniV == "" && net.ParseIP(host) == nil {
		sniV = host
	}
	return &Server{ID: "v" + idOf(idKey), Kind: "vless", Name: host, Orig: name, SNI: sniV, Type: sec, Net: netw, Host: host, Port: port,
		Ping: -1, Raw: idKey}
}

func normNet(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if i := strings.IndexByte(t, '@'); i >= 0 {
		t = t[:i]
	}
	switch t {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "xhttp", "splithttp":
		return "xhttp"
	case "httpupgrade":
		return "httpupgrade"
	}
	return ""
}

func truthy(s string) bool {
	s = strings.ToLower(s)
	return s == "1" || s == "true" || s == "yes"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// XrayOutbound converts a vless:// link into an Xray outbound object.
func XrayOutbound(raw string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	flow := q.Get("flow")
	if strings.HasPrefix(flow, "xtls-rprx-vision") {
		if strings.Contains(flow, "udp443") {
			flow = "xtls-rprx-vision-udp443"
		} else {
			flow = "xtls-rprx-vision"
		}
	} else {
		flow = ""
	}
	enc := q.Get("encryption")
	if enc == "" {
		enc = "none"
	}
	user := map[string]any{"id": u.User.Username(), "encryption": enc}
	if flow != "" {
		user["flow"] = flow
	}
	netw := normNet(q.Get("type"))
	sec := strings.ToLower(q.Get("security"))
	if sec == "" || sec == "false" {
		sec = "none"
	}
	hostHdr := q.Get("host")
	pathV := q.Get("path")
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}

	stream := map[string]any{"security": sec}
	switch netw {
	case "tcp":
		stream["network"] = "raw"
		if strings.ToLower(q.Get("headerType")) == "http" {
			req := map[string]any{"path": []string{orDefault(pathV, "/")}}
			if hostHdr != "" {
				req["headers"] = map[string]any{"Host": splitList(hostHdr)}
			}
			stream["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		stream["network"] = "ws"
		ws := map[string]any{"path": orDefault(pathV, "/")}
		if hostHdr != "" {
			ws["host"] = hostHdr
		}
		if ed := q.Get("ed"); ed != "" && !strings.Contains(pathV, "ed=") {
			sep := "?"
			if strings.Contains(pathV, "?") {
				sep = "&"
			}
			ws["path"] = orDefault(pathV, "/") + sep + "ed=" + ed
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["network"] = "grpc"
		g := map[string]any{"serviceName": q.Get("serviceName"), "multiMode": strings.ToLower(q.Get("mode")) == "multi"}
		if a := q.Get("authority"); a != "" {
			g["authority"] = a
		}
		stream["grpcSettings"] = g
	case "httpupgrade":
		stream["network"] = "httpupgrade"
		h := map[string]any{"path": orDefault(pathV, "/")}
		if hostHdr != "" {
			h["host"] = hostHdr
		}
		stream["httpupgradeSettings"] = h
	case "xhttp":
		stream["network"] = "xhttp"
		x := map[string]any{"path": orDefault(pathV, "/")}
		if hostHdr != "" {
			x["host"] = hostHdr
		}
		switch m := strings.ToLower(q.Get("mode")); m {
		case "auto", "packet-up", "stream-up", "stream-one":
			x["mode"] = m
		}
		if ex := q.Get("extra"); ex != "" {
			var extra map[string]any
			if json.Unmarshal([]byte(ex), &extra) == nil {
				// drop empty values that would override the link params
				for k, v := range extra {
					if s, ok := v.(string); ok && s == "" {
						delete(extra, k)
					}
				}
				for _, k := range []string{"host", "path", "mode"} {
					if v, ok := extra[k]; ok {
						x[k] = v
						delete(extra, k)
					}
				}
				if len(extra) > 0 {
					x["extra"] = extra
				}
			}
		}
		stream["xhttpSettings"] = x
	default:
		stream["network"] = "raw"
	}

	switch sec {
	case "tls":
		t := map[string]any{}
		sn := sni
		if sn == "" {
			sn = hostHdr
		}
		if sn != "" {
			t["serverName"] = sn
		}
		if fp := q.Get("fp"); fp != "" {
			t["fingerprint"] = fp
		}
		if a := splitList(q.Get("alpn")); len(a) > 0 {
			t["alpn"] = a
		}
		if ech := q.Get("ech"); ech != "" {
			t["echConfigList"] = ech
		}
		stream["tlsSettings"] = t
	case "reality":
		r := map[string]any{"publicKey": q.Get("pbk"), "fingerprint": orDefault(q.Get("fp"), "chrome")}
		if sni != "" {
			r["serverName"] = sni
		}
		if sid := q.Get("sid"); sid != "" {
			r["shortId"] = sid
		}
		if spx := q.Get("spx"); spx != "" {
			r["spiderX"] = spx
		}
		if pqv := q.Get("pqv"); pqv != "" {
			r["mldsa65Verify"] = pqv
		}
		stream["realitySettings"] = r
	}
	return map[string]any{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": u.Hostname(), "port": port, "users": []any{user}}}},
		"streamSettings": stream,
	}, nil
}

// PinAddress makes Xray connect to a fixed IP (so it can be excluded from the TUN routes)
// while keeping the original domain as TLS server name / HTTP host.
func PinAddress(out map[string]any, ip, domain string) {
	vnext := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	vnext["address"] = ip
	if domain == "" || net.ParseIP(domain) != nil {
		return
	}
	st := out["streamSettings"].(map[string]any)
	for _, k := range []string{"tlsSettings", "realitySettings"} {
		if t, ok := st[k].(map[string]any); ok {
			if _, has := t["serverName"]; !has {
				t["serverName"] = domain
			}
		}
	}
	for _, k := range []string{"wsSettings", "xhttpSettings", "httpupgradeSettings"} {
		if t, ok := st[k].(map[string]any); ok {
			if _, has := t["host"]; !has {
				t["host"] = domain
			}
		}
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
