package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const singBoxVersion = "1.12.12"

// Cores knows where the helper programs (xray, sing-box, tor) live and fetches them when missing.
type Cores struct {
	Root   string // <exe dir>/core
	client func(viaProxy bool) *http.Client
	logf   func(string, ...any)
}

func (c *Cores) XrayDir() string    { return filepath.Join(c.Root, "xray") }
func (c *Cores) SingBoxDir() string { return filepath.Join(c.Root, "sing-box") }
func (c *Cores) TorDir() string     { return filepath.Join(c.Root, "tor") }

func (c *Cores) XrayExe() string    { return filepath.Join(c.XrayDir(), "xray"+exeExt) }
func (c *Cores) SingBoxExe() string { return filepath.Join(c.SingBoxDir(), "sing-box"+exeExt) }
func (c *Cores) TorExe() string     { return filepath.Join(c.TorDir(), "tor", "tor"+exeExt) }

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// download tries direct first, then through the running proxy (useful when github/torproject are blocked).
func (c *Cores) download(ctx context.Context, urls []string, progress func(string)) ([]byte, string, error) {
	var lastErr error
	for _, via := range []bool{false, true} {
		cl := c.client(via)
		if cl == nil {
			continue
		}
		for _, u := range urls {
			progress("Скачивание " + shortURL(u) + map[bool]string{true: " (через прокси)", false: ""}[via])
			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			req.Header.Set("User-Agent", "MRFS/1.0")
			resp, err := cl.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
			resp.Body.Close()
			if resp.StatusCode != 200 {
				lastErr = fmt.Errorf("%s: HTTP %d", shortURL(u), resp.StatusCode)
				continue
			}
			if err != nil {
				lastErr = err
				continue
			}
			return b, u, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("нет доступа")
	}
	return nil, "", lastErr
}

func shortURL(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if len(u) > 60 {
		u = u[:28] + "…" + u[len(u)-28:]
	}
	return u
}

func (c *Cores) EnsureXray(ctx context.Context, progress func(string)) error {
	if exists(c.XrayExe()) {
		return nil
	}
	b, _, err := c.download(ctx, []string{
		"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip",
	}, progress)
	if err != nil {
		return fmt.Errorf("не удалось скачать Xray: %w", err)
	}
	return unzip(b, c.XrayDir(), 0)
}

func (c *Cores) EnsureSingBox(ctx context.Context, progress func(string)) error {
	if exists(c.SingBoxExe()) {
		return nil
	}
	v := singBoxVersion
	b, _, err := c.download(ctx, []string{
		fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-windows-amd64.zip", v, v),
	}, progress)
	if err != nil {
		return fmt.Errorf("не удалось скачать sing-box: %w", err)
	}
	return unzip(b, c.SingBoxDir(), 1) // strip top folder
}

var expertRe = regexp.MustCompile(`https?://[^"'\s]+/tor-expert-bundle-windows-x86_64-[0-9.]+\.tar\.gz`)
var verDirRe = regexp.MustCompile(`href="([0-9]+\.[0-9]+(?:\.[0-9]+)?)/"`)

// EnsureTor installs Tor (expert bundle) into core/tor.
// Order: already installed → copy from a local Tor Browser → download from torproject mirrors.
func (c *Cores) EnsureTor(ctx context.Context, progress func(string)) error {
	if exists(c.TorExe()) {
		return nil
	}
	if src := findTorBrowser(); src != "" {
		progress("Найден Tor Browser — копирую Tor из него")
		if err := copyTorBrowser(src, c.TorDir()); err == nil && exists(c.TorExe()) {
			return nil
		}
	}
	progress("Ищу последнюю версию Tor…")
	var urls []string
	for _, page := range []string{"https://www.torproject.org/download/tor/", "https://tor.eff.org/download/tor/"} {
		if b, _, err := c.download(ctx, []string{page}, func(string) {}); err == nil {
			for _, m := range expertRe.FindAllString(string(b), -1) {
				urls = append(urls, m)
			}
		}
		if len(urls) > 0 {
			break
		}
	}
	if len(urls) == 0 {
		for _, base := range []string{"https://dist.torproject.org/torbrowser/", "https://archive.torproject.org/tor-package-archive/torbrowser/",
			"https://tor.calyxinstitute.org/dist/torbrowser/", "https://tor.eff.org/dist/torbrowser/"} {
			b, _, err := c.download(ctx, []string{base}, func(string) {})
			if err != nil {
				continue
			}
			var vers []string
			for _, m := range verDirRe.FindAllStringSubmatch(string(b), -1) {
				if !strings.Contains(m[1], "a") {
					vers = append(vers, m[1])
				}
			}
			sort.Slice(vers, func(i, j int) bool { return verLess(vers[j], vers[i]) })
			for i := 0; i < len(vers) && i < 3; i++ {
				urls = append(urls, fmt.Sprintf("%s%s/tor-expert-bundle-windows-x86_64-%s.tar.gz", base, vers[i], vers[i]))
			}
			break
		}
	}
	if len(urls) == 0 {
		return fmt.Errorf("сайт torproject.org недоступен. Включите «Быстрое подключение» и повторите — Tor скачается через него, " +
			"либо установите Tor Browser (MRFS возьмёт Tor из него)")
	}
	b, _, err := c.download(ctx, urls, progress)
	if err != nil {
		return fmt.Errorf("не удалось скачать Tor: %w", err)
	}
	progress("Распаковка Tor…")
	if err := untargz(b, c.TorDir()); err != nil {
		return err
	}
	if !exists(c.TorExe()) {
		return fmt.Errorf("в архиве Tor не найден tor.exe")
	}
	return nil
}

func verLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			fmt.Sscan(pa[i], &x)
		}
		if i < len(pb) {
			fmt.Sscan(pb[i], &y)
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func findTorBrowser() string {
	var cands []string
	for _, env := range []string{"USERPROFILE", "OneDrive", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		for _, sub := range []string{"Desktop", "Рабочий стол", "OneDrive/Desktop", "OneDrive/Рабочий стол", "", "Programs"} {
			cands = append(cands, filepath.Join(base, sub, "Tor Browser", "Browser", "TorBrowser"))
		}
	}
	for _, p := range cands {
		if exists(filepath.Join(p, "Tor", "tor.exe")) {
			return p
		}
	}
	return ""
}

// copyTorBrowser reproduces the expert-bundle layout from a Tor Browser install.
func copyTorBrowser(tb, dst string) error {
	if err := copyDir(filepath.Join(tb, "Tor"), filepath.Join(dst, "tor")); err != nil {
		return err
	}
	// Tor Browser keeps transports in Tor/PluggableTransports; the bundle uses tor/pluggable_transports
	pt := filepath.Join(dst, "tor", "PluggableTransports")
	if exists(pt) {
		os.Rename(pt, filepath.Join(dst, "tor", "pluggable_transports"))
	}
	os.MkdirAll(filepath.Join(dst, "data"), 0o755)
	for _, g := range []string{"geoip", "geoip6"} {
		if b, err := os.ReadFile(filepath.Join(tb, "Data", "Tor", g)); err == nil {
			os.WriteFile(filepath.Join(dst, "data", g), b, 0o644)
		}
	}
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(t, b, 0o755)
	})
}

// TransportLines returns ClientTransportPlugin lines relative to the tor root (core/tor).
func (c *Cores) TransportLines() ([]string, map[string]bool) {
	ptDir := filepath.Join(c.TorDir(), "tor", "pluggable_transports")
	rel := filepath.Join("tor", "pluggable_transports") + string(os.PathSeparator)
	supported := map[string]bool{"vanilla": true}
	var lines []string
	if b, err := os.ReadFile(filepath.Join(ptDir, "pt_config.json")); err == nil {
		var cfg struct {
			PluggableTransports map[string]string `json:"pluggableTransports"`
		}
		if json.Unmarshal(b, &cfg) == nil {
			keys := make([]string, 0, len(cfg.PluggableTransports))
			for k := range cfg.PluggableTransports {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				l := strings.ReplaceAll(cfg.PluggableTransports[k], "${pt_path}", rel)
				lines = append(lines, l)
				f := strings.Fields(l)
				if len(f) >= 2 {
					for _, t := range strings.Split(f[1], ",") {
						supported[t] = true
					}
				}
			}
		}
	}
	if len(lines) == 0 {
		if exists(filepath.Join(ptDir, "lyrebird"+exeExt)) {
			lines = append(lines, "ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec "+rel+"lyrebird"+exeExt)
			for _, t := range []string{"obfs4", "webtunnel"} {
				supported[t] = true
			}
		}
		if exists(filepath.Join(ptDir, "snowflake-client"+exeExt)) {
			lines = append(lines, "ClientTransportPlugin snowflake exec "+rel+"snowflake-client"+exeExt)
			supported["snowflake"] = true
		}
	}
	return lines, supported
}

// ---- archive helpers ----

func safeJoin(root, name string, strip int) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if len(parts) <= strip {
		return "", false
	}
	parts = parts[strip:]
	for _, p := range parts {
		if p == ".." {
			return "", false
		}
	}
	return filepath.Join(append([]string{root}, parts...)...), true
}

func unzip(b []byte, dst string, strip int) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	os.RemoveAll(tmp)
	for _, f := range zr.File {
		p, ok := safeJoin(tmp, f.Name, strip)
		if !ok {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(p, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o755); err != nil {
			return err
		}
	}
	os.RemoveAll(dst)
	return os.Rename(tmp, dst)
}

func untargz(b []byte, dst string) error {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	tmp := dst + ".tmp"
	os.RemoveAll(tmp)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		p, ok := safeJoin(tmp, h.Name, 0)
		if !ok {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o755)
			data, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			if err := os.WriteFile(p, data, 0o755); err != nil {
				return err
			}
		}
	}
	os.RemoveAll(dst)
	return os.Rename(tmp, dst)
}
