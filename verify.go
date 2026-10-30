package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Real traffic check (like "real delay" in Happ / v2rayN): every candidate gets its own local
// port in ONE Xray process and a real HTTPS request goes through it. Servers that answer the
// TLS ping but do not pass traffic (very common under DPI) are hidden. The request also tells
// the real exit country.

const (
	verifyMax     = 96 // at most this many servers are checked after start
	verifyEnough  = 12 // stop as soon as this many working servers are found
	verifyBatch   = 16 // checked at the same time (moderate: mass connections look like malware to antivirus monitors)
	verifyTimeout = 5 * time.Second
)

var traceURLs = []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace"}

type verifyState struct {
	running atomic.Bool
	done    atomic.Int64
	total   atomic.Int64
}

// VerifyVless checks the fastest VLESS servers once. Skipped while connected.
func (a *App) VerifyVless() {
	if !a.verify.running.CompareAndSwap(false, true) {
		return
	}
	defer a.verify.running.Store(false)
	a.mu.Lock()
	busy := a.conn.Status == "on" || a.conn.Status == "connecting"
	var cands []*Server
	for _, s := range a.servers {
		if s.Kind == "vless" && s.Ping > 0 && s.Checked == 0 {
			cands = append(cands, s)
		}
	}
	a.mu.Unlock()
	if busy {
		a.mu.Lock()
		a.pendingPing = true
		a.mu.Unlock()
		return
	}
	if len(cands) == 0 {
		return
	}
	if err := a.cores.EnsureXray(context.Background(), func(string) {}); err != nil {
		a.logf("Проверка серверов: %v", err)
		return
	}
	// servers that worked recently (even days ago) are checked first, then the fastest by ping
	good := a.loadGood()
	sort.SliceStable(cands, func(i, j int) bool {
		gi, gj := good[cands[i].ID], good[cands[j].ID]
		if gi != gj {
			return gi
		}
		return cands[i].Ping < cands[j].Ping
	})
	if len(cands) > verifyMax {
		cands = cands[:verifyMax]
	}
	a.verify.done.Store(0)
	a.verify.total.Store(int64(len(cands)))
	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.verifyStop = cancel
	a.mu.Unlock()
	defer cancel()
	a.logf("Проверяю %d серверов настоящим запросом…", len(cands))
	t0 := time.Now()
	ok := 0
	checked := 0
	for i := 0; i < len(cands) && ctx.Err() == nil && ok < verifyEnough; i += verifyBatch {
		j := min(i+verifyBatch, len(cands))
		ok += a.verifyBatch(ctx, cands[i:j])
		checked = j
	}
	a.verify.total.Store(int64(checked))
	a.saveGood()
	if ctx.Err() != nil {
		a.logf("Проверка прервана (подключение)")
		return
	}
	a.savePings()
	a.logf("Проверка завершена за %.0f с: интернет идёт через %d из %d проверенных серверов", time.Since(t0).Seconds(), ok, checked)
	if ok == 0 {
		a.logf("Ни один сервер не пропустил трафик. Вероятно, провайдер блокирует такие подключения — попробуйте позже, «Обновить», или режим Tor")
	}
}

func (a *App) verifyBatch(ctx context.Context, list []*Server) int {
	type slot struct {
		s    *Server
		port int
	}
	var slots []slot
	var inb, outb, rules []any
	port := 21800
	for _, s := range list {
		o, err := XrayOutbound(s.Raw)
		if err != nil {
			continue
		}
		for !portFree(port) {
			port++
		}
		tag := fmt.Sprintf("v%d", len(slots))
		o["tag"] = "o" + tag
		outb = append(outb, o)
		inb = append(inb, map[string]any{"tag": "i" + tag, "listen": "127.0.0.1", "port": port, "protocol": "http"})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{"i" + tag}, "outboundTag": "o" + tag})
		slots = append(slots, slot{s, port})
		port++
	}
	if len(slots) == 0 {
		return 0
	}
	cfg, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "warning"},
		"inbounds": inb, "outbounds": outb, "routing": map[string]any{"rules": rules}})
	cmd, err := a.startXray(ctx, "mrfs-check.json", cfg, slots[len(slots)-1].port, false)
	defer a.killProc(cmd)
	if err != nil {
		a.logf("Проверка: Xray не запустился: %v", err)
		return 0
	}
	var wg sync.WaitGroup
	var logged atomic.Int32
	var ok atomic.Int64
	for _, sl := range slots {
		wg.Add(1)
		go func(sl slot) {
			defer wg.Done()
			d, loc, err := traceVia(ctx, sl.port, verifyTimeout)
			if ctx.Err() != nil {
				return
			}
			a.mu.Lock()
			if err == nil {
				sl.s.Checked, sl.s.Delay, sl.s.Exit = 1, int(d.Milliseconds()), loc
				ok.Add(1)
			} else {
				sl.s.Checked = -1
			}
			a.ver++
			a.mu.Unlock()
			// log only after unlocking: logf takes the same lock
			if err != nil && logged.Add(1) <= 3 {
				a.logf("Проверка: %s:%d (%s·%s) — %s", sl.s.Host, sl.s.Port, sl.s.Type, sl.s.Net, shortErr(err))
			}
			a.verify.done.Add(1)
		}(sl)
	}
	wg.Wait()
	return int(ok.Load())
}

// traceVia requests Cloudflare's trace page through a local proxy port:
// returns the delay and the exit country (lowercase ISO code).
func traceVia(ctx context.Context, port int, timeout time.Duration) (time.Duration, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
	var lastErr error
	for _, u := range append(traceURLs, testURLs...) {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		t0 := time.Now()
		resp, err := cl.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		d := time.Since(t0)
		loc := ""
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "loc=") && len(l) == 6 {
				loc = strings.ToLower(l[4:])
			}
		}
		return d, loc, nil
	}
	return 0, "", lastErr
}

func portFree(p int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// good.json remembers servers that passed the real check, for 3 days: they are checked first next time.
func (a *App) loadGood() map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(a.dataDir, "good.json"))
	if err != nil {
		return out
	}
	var m map[string]int64
	if json.Unmarshal(b, &m) != nil {
		return out
	}
	for id, t := range m {
		if time.Since(time.Unix(t, 0)) < 72*time.Hour {
			out[id] = true
		}
	}
	return out
}

func (a *App) saveGood() {
	m := map[string]int64{}
	if b, err := os.ReadFile(filepath.Join(a.dataDir, "good.json")); err == nil {
		json.Unmarshal(b, &m)
	}
	now := time.Now().Unix()
	a.mu.Lock()
	for _, s := range a.servers {
		switch s.Checked {
		case 1:
			m[s.ID] = now
		case -1:
			delete(m, s.ID)
		}
	}
	a.mu.Unlock()
	for id, t := range m {
		if now-t > 72*3600 {
			delete(m, id)
		}
	}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(a.dataDir, "good.json"), b, 0o644)
}
