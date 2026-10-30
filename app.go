package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const AppVersion = "1.0.0"

// how often to check the GitHub repositories for new commits
const UpdateInterval = 10 * time.Minute

type Settings struct {
	Route     string `json:"route"`               // "tun" (весь компьютер) | "proxy" (системный прокси)
	Kind      string `json:"kind"`                // last selected mode: tor | vless
	LastVless string `json:"lastVless,omitempty"` // last server that worked
}

type ConnState struct {
	Status   string `json:"status"` // off | connecting | on | error
	Kind     string `json:"kind"`
	ServerID string `json:"serverId"`
	Server   string `json:"server"`
	Progress int    `json:"progress"`
	Message  string `json:"message"`
	Route    string `json:"route"`
	IP       string `json:"ip"`
	Delay    int    `json:"delay"`
	Warn     string `json:"warn"`
	Since    int64  `json:"since"`
}

type App struct {
	dataDir  string
	cores    *Cores
	geo      *GeoIP
	fetcher  *Fetcher
	settings Settings

	mu            sync.Mutex
	servers       []*Server
	byID          map[string]*Server
	ver           int64 // bumps whenever the server list / pings change
	conn          ConnState
	cancel        context.CancelFunc
	procs         []*exec.Cmd
	proxySet      bool
	proxyPort     int // local HTTP proxy of the live connection (0 = none)
	directDomains []string
	excludeIPs    []string // server IPs that bypass the TUN
	tunCmd        *exec.Cmd
	tunName       string
	pendingPing   bool
	verify        verifyState
	verifyStop    context.CancelFunc
	saved         map[string]savedPing
	logFile       *os.File // data\mrfs.log — the journal, also on disk
	pingFake      bool
	pingAgain     atomic.Bool
	mitm          bool // antivirus decrypts TLS (seen in ping or in Xray log)

	pinging   atomic.Bool
	pingDone  int64
	pingTotal int64
	pingStop  context.CancelFunc

	updating   atomic.Bool
	lastUpdate time.Time
	logs       []string
}

func NewApp(baseDir string) *App {
	a := &App{dataDir: filepath.Join(baseDir, "data"), byID: map[string]*Server{}}
	os.MkdirAll(a.dataDir, 0o755)
	if f, err := os.Create(filepath.Join(a.dataDir, "mrfs.log")); err == nil {
		a.logFile = f
	}
	a.cores = &Cores{Root: filepath.Join(baseDir, "core"), client: a.httpClient, logf: a.logf}
	a.fetcher = NewFetcher(a.dataDir, a.httpClient)
	a.geo = &GeoIP{} // embedded table
	a.settings = Settings{Route: "tun", Kind: "vless"}
	if b, err := os.ReadFile(filepath.Join(a.dataDir, "settings.json")); err == nil {
		json.Unmarshal(b, &a.settings)
	}
	if a.settings.Route != "proxy" {
		a.settings.Route = "tun"
	}
	a.conn = ConnState{Status: "off", Route: a.settings.Route}
	// a crash could have left the system proxy pointing at us
	if exists(filepath.Join(a.dataDir, ".proxy_on")) {
		clearSystemProxy()
		os.Remove(filepath.Join(a.dataDir, ".proxy_on"))
	}
	return a
}

func (a *App) saveSettings() {
	b, _ := json.MarshalIndent(a.settings, "", "  ")
	os.WriteFile(filepath.Join(a.dataDir, "settings.json"), b, 0o644)
}

func (a *App) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 400 {
		a.logs = a.logs[len(a.logs)-400:]
	}
	if a.logFile != nil {
		a.logFile.WriteString(line + "\r\n")
	}
	a.mu.Unlock()
}

// httpClient: direct, or through the local proxy that is currently up (nil if none).
func (a *App) httpClient(viaProxy bool) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 15 * time.Second,
		DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext}
	if viaProxy {
		a.mu.Lock()
		port := a.proxyPort
		a.mu.Unlock()
		if port == 0 {
			return nil
		}
		pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Minute}
}

// ---------- sources & ping ----------

func (a *App) Start() {
	fresh := a.loadPings()
	a.loadServers(false)
	go func() {
		// fresh lists first (usually 2-3 s, at most 8 s), then the one and only automatic ping —
		// otherwise a list update arriving mid-ping restarts it
		a.updateTimeout(false, 8*time.Second, false)
		if fresh {
			a.logf("Использую результаты пинга, сделанного только что")
			a.pingNew()
			go a.VerifyVless()
		} else {
			a.PingAll("")
		}
		t := time.NewTicker(UpdateInterval)
		for range t.C {
			a.update(false)
		}
	}()
}

func (a *App) update(force bool) { a.updateTimeout(force, 5*time.Minute, true) }

func (a *App) updateTimeout(force bool, timeout time.Duration, ping bool) {
	if !a.updating.CompareAndSwap(false, true) {
		return
	}
	defer a.updating.Store(false)
	a.logf("Проверка обновлений в репозиториях…")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	changed := a.fetcher.Update(ctx, force, a.logf)
	a.mu.Lock()
	a.lastUpdate = time.Now()
	empty := len(a.servers) == 0
	a.mu.Unlock()
	if changed || empty || force {
		a.loadServers(ping) // pings only servers that are new in the lists
	} else {
		a.logf("Обновлений нет")
	}
}

// loadServers rebuilds the list from the cache, keeping known pings, and pings everything.
func (a *App) loadServers(ping bool) {
	list := a.fetcher.Servers()
	a.mu.Lock()
	for _, s := range list {
		if old, ok := a.byID[s.ID]; ok {
			s.Ping, s.Fail, s.Country, s.IP = old.Ping, old.Fail, old.Country, old.IP
			s.Checked, s.Delay, s.Exit = old.Checked, old.Delay, old.Exit
		}
	}
	if a.saved != nil {
		for _, s := range list {
			if v, ok := a.saved[s.ID]; ok && s.Ping == -1 {
				s.Ping, s.Country = v.Ping, v.Country
				s.Checked, s.Delay, s.Exit = v.Checked, v.Delay, v.Exit
			}
		}
		a.saved = nil
	}
	a.servers = list
	a.byID = map[string]*Server{}
	for _, s := range list {
		a.byID[s.ID] = s
	}
	a.ver++
	a.mu.Unlock()
	nt, nv := 0, 0
	for _, s := range list {
		if s.Kind == "tor" {
			nt++
		} else {
			nv++
		}
	}
	if len(list) > 0 {
		a.logf("Загружено: %d мостов Tor, %d конфигов VLESS", nt, nv)
	}
	if ping && len(list) > 0 {
		go a.pingNew()
	}
}

// PingAll pings all servers of a kind ("" = all). Dead (>500 ms) ones get hidden.
func (a *App) PingAll(kind string) {
	a.pingWhere(func(s *Server) bool { return kind == "" || s.Kind == kind }, true)
}

// pingNew pings only servers that appeared after a list update (queued if a ping is running).
func (a *App) pingNew() { a.pingWhere(func(s *Server) bool { return s.Ping == -1 }, false) }

func (a *App) pingWhere(match func(*Server) bool, restart bool) {
	// while the whole computer goes through the tunnel, pings would measure the tunnel, not the servers
	a.mu.Lock()
	busy := a.conn.Status == "on" || a.conn.Status == "connecting"
	if busy {
		a.pendingPing = true
	}
	a.mu.Unlock()
	if busy {
		a.logf("Пинг будет выполнен после отключения (во время подключения он неточный)")
		return
	}
	if a.pinging.Load() && !restart {
		a.pingAgain.Store(true) // new servers will be pinged right after the current run
		return
	}
	if a.pingStop != nil && a.pinging.Load() {
		a.pingStop()
		for a.pinging.Load() {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !a.pinging.CompareAndSwap(false, true) {
		return
	}
	defer func() {
		a.pinging.Store(false)
		if a.pingAgain.CompareAndSwap(true, false) {
			go a.pingNew()
		}
	}()
	a.mu.Lock()
	first := a.settings.Kind
	var list []*Server
	for _, s := range a.servers {
		if match(s) {
			list = append(list, s)
		}
	}
	a.mu.Unlock()
	if len(list) == 0 {
		return
	}
	// ping the ones that were good before first, so the top of the list appears quickly
	// the mode currently on screen goes first
	sort.SliceStable(list, func(i, j int) bool {
		if (list[i].Kind == first) != (list[j].Kind == first) {
			return list[i].Kind == first
		}
		return rankPing(list[i].Ping) < rankPing(list[j].Ping)
	})
	atomic.StoreInt64(&a.pingDone, 0)
	atomic.StoreInt64(&a.pingTotal, int64(len(list)))
	ctx, cancel := context.WithCancel(context.Background())
	a.pingStop = cancel
	defer cancel()
	a.logf("Пинг %d серверов…", len(list))
	t0 := time.Now()
	mitmSeen.Store(0)
	onResult := func(s *Server, ms int, ip net.IP) {
		cc := ""
		if ip != nil && s.Type != "snowflake" {
			cc = a.geo.Country(ip)
		}
		if cc == "" && s.Kind == "vless" {
			cc = flagCountry(s.Orig)
		}
		a.mu.Lock()
		s.Ping = ms
		s.Checked = 0 // re-check real traffic after a new ping
		if ip != nil {
			s.IP = ip.String()
		}
		s.Country = strings.ToLower(cc)
		a.ver++
		a.mu.Unlock()
	}
	// VLESS first; the real traffic check starts right after it, while Tor bridges are still pinged
	var vl, rest []*Server
	for _, s := range list {
		if s.Kind == "vless" {
			vl = append(vl, s)
		} else {
			rest = append(rest, s)
		}
	}
	for _, g := range [][]*Server{vl, rest} {
		if len(g) == 0 || ctx.Err() != nil {
			continue
		}
		PingAll(ctx, g, 128, onResult, &a.pingDone)
		if g[0].Kind == "vless" && ctx.Err() == nil {
			go a.VerifyVless()
		}
	}
	alive := 0
	for _, s := range list {
		if s.Ping > 0 {
			alive++
		}
	}
	// pings of 1-3 ms to servers on other continents are physically impossible:
	// something on this computer (antivirus web protection, another VPN) answers instead of the servers
	tiny := 0
	for _, s := range list {
		if s.Ping > 0 && s.Ping <= 3 {
			tiny++
		}
	}
	a.mu.Lock()
	a.pingFake = alive > 20 && tiny*2 > alive
	a.mitm = mitmSeen.Load() > 3
	fake := a.pingFake
	a.mu.Unlock()
	if a.mitm && ctx.Err() == nil {
		a.logf("ВНИМАНИЕ: антивирус подменяет сертификаты защищённых соединений (найдено у %d серверов). С такой проверкой VLESS не работает — отключите в антивирусе «Проверку защищённых соединений» или добавьте xray.exe в исключения", mitmSeen.Load())
	}
	if fake && ctx.Err() == nil {
		a.logf("ВНИМАНИЕ: почти у всех серверов пинг 1–3 мс — соединения перехватывает антивирус или другой VPN. Пинг неточный; отключите другой VPN или добавьте MRFS в исключения антивируса")
	}
	if ctx.Err() == nil {
		a.savePings()
		a.logf("Пинг завершён за %.0f с: отвечают %d из %d (порог %d мс)", time.Since(t0).Seconds(), alive, len(list), MaxPing)
	}
}

type savedPing struct {
	Ping    int    `json:"p"`
	Country string `json:"c,omitempty"`
	Checked int    `json:"k,omitempty"`
	Delay   int    `json:"d,omitempty"`
	Exit    string `json:"e,omitempty"`
}

func (a *App) savePings() {
	a.mu.Lock()
	m := map[string]savedPing{}
	for _, s := range a.servers {
		if s.Ping != -1 {
			m[s.ID] = savedPing{s.Ping, s.Country, s.Checked, s.Delay, s.Exit}
		}
	}
	a.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"time": time.Now().Unix(), "items": m})
	os.WriteFile(filepath.Join(a.dataDir, "pings.json"), b, 0o644)
}

// loadPings restores the last ping results; returns true if they are fresh (< 10 min).
func (a *App) loadPings() bool {
	b, err := os.ReadFile(filepath.Join(a.dataDir, "pings.json"))
	if err != nil {
		return false
	}
	var v struct {
		Time  int64                `json:"time"`
		Items map[string]savedPing `json:"items"`
	}
	if json.Unmarshal(b, &v) != nil || time.Since(time.Unix(v.Time, 0)) > 10*time.Minute {
		return false
	}
	a.saved = v.Items
	return len(v.Items) > 0
}

func rankPing(p int) int {
	if p > 0 {
		return p
	}
	if p == -1 {
		return 10000
	}
	return 20000
}

// ---------- API for the UI ----------

type StateDTO struct {
	Ver        int64          `json:"ver"`
	Conn       ConnState      `json:"conn"`
	Pinging    bool           `json:"pinging"`
	PingDone   int64          `json:"pingDone"`
	PingTotal  int64          `json:"pingTotal"`
	Updating   bool           `json:"updating"`
	LastUpdate string         `json:"lastUpdate"`
	Sources    []RepoStatus   `json:"sources"`
	Counts     map[string]int `json:"counts"`
	Settings   Settings       `json:"settings"`
	Admin      bool           `json:"admin"`
	Version    string         `json:"version"`
	TorReady   bool           `json:"torReady"`
	PingFake   bool           `json:"pingFake"`
	Mitm       bool           `json:"mitm"`
	Verifying  bool           `json:"verifying"`
	VerDone    int64          `json:"verDone"`
	VerTotal   int64          `json:"verTotal"`
}

func (a *App) State() StateDTO {
	a.mu.Lock()
	defer a.mu.Unlock()
	counts := map[string]int{}
	for _, s := range a.servers {
		if s.Country == "ru" {
			continue
		}
		counts[s.Kind+"_all"]++
		if s.Ping > 0 {
			counts[s.Kind+"_alive"]++
		}
	}
	lu := ""
	if !a.lastUpdate.IsZero() {
		lu = a.lastUpdate.Format("15:04")
	}
	return StateDTO{Ver: a.ver, Conn: a.conn, Pinging: a.pinging.Load(), PingDone: atomic.LoadInt64(&a.pingDone),
		PingTotal: atomic.LoadInt64(&a.pingTotal), Updating: a.updating.Load(), LastUpdate: lu,
		Sources: a.fetcher.Status(), Counts: counts, Settings: a.settings, Admin: isAdmin(), Version: AppVersion,
		TorReady: exists(a.cores.TorExe()), PingFake: a.pingFake, Mitm: a.mitm,
		Verifying: a.verify.running.Load(), VerDone: a.verify.done.Load(), VerTotal: a.verify.total.Load()}
}

// Servers returns only working servers (ping ≤ 500 ms), fastest first,
// named "<Country> #<n>" instead of the (often advertising) names from the lists.
func (a *App) Servers(kind string) []Server {
	a.mu.Lock()
	defer a.mu.Unlock()
	var alive []*Server
	for _, s := range a.servers {
		if s.Kind != kind || s.Ping <= 0 || s.Checked < 0 {
			continue // dead, or no traffic in the real check
		}
		if country(s) == "ru" {
			continue // Russian servers are never shown (by real exit country when known)
		}
		alive = append(alive, s)
	}
	// stable numbering inside each country
	sort.Slice(alive, func(i, j int) bool { return alive[i].ID < alive[j].ID })
	num := map[string]int{}
	for _, s := range alive {
		label := countryNames[strings.ToUpper(country(s))]
		if s.Type == "snowflake" {
			label = "Snowflake"
		} else if label == "" {
			label = "Unknown"
		}
		num[label]++
		s.Name = fmt.Sprintf("%s #%d", label, num[label])
	}
	out := make([]Server, 0, len(alive))
	for _, s := range alive {
		c := *s
		c.Country = country(s)
		if s.Checked == 1 {
			c.OK, c.Ping = true, s.Delay // show the real delay
		}
		out = append(out, c)
	}
	// servers that really passed traffic go first, fastest on top
	sort.Slice(out, func(i, j int) bool {
		if out[i].OK != out[j].OK {
			return out[i].OK
		}
		return out[i].Ping < out[j].Ping
	})
	return out
}

func country(s *Server) string {
	if s.Checked == 1 && s.Exit != "" {
		return s.Exit
	}
	return s.Country
}

func (a *App) Logs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.logs...)
}

func (a *App) SetRoute(r string) {
	if r != "proxy" {
		r = "tun"
	}
	a.mu.Lock()
	a.settings.Route = r
	if a.conn.Status == "off" || a.conn.Status == "error" {
		a.conn.Route = r
	}
	a.mu.Unlock()
	a.saveSettings()
}

func (a *App) SetKind(k string) {
	a.mu.Lock()
	a.settings.Kind = k
	a.mu.Unlock()
	a.saveSettings()
}

func (a *App) Refresh() { go a.update(true) }

// ---------- connect / disconnect ----------

func (a *App) setConn(fn func(c *ConnState)) {
	a.mu.Lock()
	fn(&a.conn)
	a.mu.Unlock()
}

func (a *App) Connect(kind, id string) {
	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.cancel = cancel
	if a.verifyStop != nil {
		a.verifyStop()
	}
	a.conn = ConnState{Status: "connecting", Kind: kind, Route: a.settings.Route, Message: "Подготовка…"}
	a.mu.Unlock()
	go func() {
		// fetch missing programs first — while the old connection (if any) is still up,
		// so a blocked torproject.org can be reached through it
		progress := func(m string) { a.setConn(func(c *ConnState) { c.Message = m }) }
		var err error
		if kind == "tor" {
			err = a.cores.EnsureTor(ctx, progress)
		} else {
			err = a.cores.EnsureXray(ctx, progress)
		}
		if err == nil && a.settings.Route == "tun" && isAdmin() {
			if e := a.cores.EnsureSingBox(ctx, progress); e != nil {
				a.logf("%v", e)
			}
		}
		if ctx.Err() != nil {
			return
		}
		a.stopAll()
		if err != nil {
			a.logf("Ошибка: %v", err)
			a.setConn(func(c *ConnState) { c.Status = "error"; c.Message = err.Error(); c.Progress = 0 })
			return
		}
		if kind == "tor" {
			err = a.connectTor(ctx, id)
		} else {
			err = a.connectVless(ctx, id)
		}
		if ctx.Err() != nil {
			return // cancelled by the user
		}
		if err != nil {
			a.logf("Ошибка: %v", err)
			a.stopAll()
			a.setConn(func(c *ConnState) { c.Status = "error"; c.Message = err.Error(); c.Progress = 0 })
			return
		}
		// check the server itself before touching the system routes
		var preOK bool
		var preDelay time.Duration
		if kind == "vless" {
			a.setConn(func(c *ConnState) { c.Progress = 70; c.Message = "Проверяю сервер…" })
			d, e := testProxy(ctx, XrayHTTPPort, 8*time.Second)
			preOK, preDelay = e == nil, d
			a.mu.Lock()
			if s := a.byID[a.conn.ServerID]; s != nil {
				if preOK {
					s.Checked, s.Delay = 1, int(d.Milliseconds())
				} else {
					s.Checked = -1
				}
				a.ver++
			}
			a.mu.Unlock()
			go a.saveGood()
			if e != nil {
				a.logf("Сервер не пропускает трафик (%s) — выберите другой сервер", shortErr(e))
			} else {
				a.logf("Сервер работает, задержка %d мс", d.Milliseconds())
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err := a.applyRoute(ctx, kind); err != nil {
			a.logf("Ошибка маршрутизации: %v", err)
			a.stopAll()
			a.setConn(func(c *ConnState) { c.Status = "error"; c.Message = err.Error() })
			return
		}
		a.mu.Lock()
		a.proxyPort = XrayHTTPPort
		if kind == "tor" {
			a.proxyPort = TorHTTPPort
		}
		a.mu.Unlock()
		a.setConn(func(c *ConnState) {
			c.Status = "on"
			c.Progress = 100
			c.Since = time.Now().Unix()
			c.Message = "Подключено"
		})
		a.mu.Lock()
		a.ver++
		a.mu.Unlock()
		if kind == "vless" {
			a.setConn(func(c *ConnState) {
				if preOK {
					c.Delay = int(preDelay.Milliseconds())
				} else {
					c.Warn = "Сервер не отвечает — выберите другой"
				}
			})
			if preOK && a.State().Conn.Route == "tun" {
				go a.verifyTun(ctx)
			}
		}
		go a.detectIP(kind)
		go a.savePings()
	}()
}

// ConnectWhenReady waits until the first ping found working servers, then connects.
func (a *App) ConnectWhenReady(kind, id string) {
	for i := 0; i < 120; i++ {
		if a.State().Counts[kind+"_alive"] >= 3 || (i > 10 && !a.pinging.Load()) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	a.Connect(kind, id)
}

func (a *App) Disconnect() {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.mu.Unlock()
	a.stopAll()
	a.setConn(func(c *ConnState) { *c = ConnState{Status: "off", Route: a.settings.Route} })
	a.mu.Lock()
	pending := a.pendingPing
	a.pendingPing = false
	a.mu.Unlock()
	if pending {
		go func() { a.pingNew(); a.VerifyVless() }()
	}
}

func (a *App) stopAll() {
	a.mu.Lock()
	procs := a.procs
	a.procs = nil
	proxy := a.proxySet
	a.proxySet = false
	a.tunCmd = nil
	a.proxyPort = 0
	a.mu.Unlock()
	if proxy {
		clearSystemProxy()
		os.Remove(filepath.Join(a.dataDir, ".proxy_on"))
	}
	// stop in reverse order: tun first, then cores
	for i := len(procs) - 1; i >= 0; i-- {
		waitExit(procs[i])
	}
}

// startProc runs a helper hidden; every output line goes to onLine (and to the log if keep(line)).
func (a *App) startProc(name string, dir string, onLine func(string), args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	hideWindow(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("не удалось запустить %s: %w", name, err)
	}
	attachToJob(cmd)
	a.mu.Lock()
	a.procs = append(a.procs, cmd)
	a.mu.Unlock()
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if onLine != nil {
				onLine(sc.Text())
			}
		}
	}()
	done := make(chan struct{})
	procDone.Store(cmd, done)
	started := time.Now()
	go func() {
		err := cmd.Wait()
		pw.Close()
		close(done)
		if _, ours := killedByUs.Load(cmd); !ours {
			// it stopped by itself: crashed, bad config, or killed by an antivirus
			a.logf("%s остановился сам через %.1f с (%v). Если это повторяется — его останавливает антивирус", name, time.Since(started).Seconds(), err)
		}
		killedByUs.Delete(cmd)
	}()
	return cmd, nil
}

func alive(cmd *exec.Cmd) bool {
	if v, ok := procDone.Load(cmd); ok {
		select {
		case <-v.(chan struct{}):
			return false
		default:
			return true
		}
	}
	return false
}

// waitExit kills a helper and waits (up to 5 s) until it is really gone, so its ports are free.
var killedByUs sync.Map

func waitExit(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	killedByUs.Store(cmd, true)
	cmd.Process.Kill()
	if v, ok := procDone.Load(cmd); ok {
		select {
		case <-v.(chan struct{}):
		case <-time.After(5 * time.Second):
		}
		procDone.Delete(cmd)
	}
}

func tunUp(name string) bool { _, err := net.InterfaceByName(name); return err == nil }

var procDone sync.Map // *exec.Cmd -> chan struct{} closed when the process exits

var bootRe = regexp.MustCompile(`Bootstrapped (\d+)%[^:]*: ?(.*)`)

func (a *App) pickTorBridges(id string, supported map[string]bool) ([]*Server, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var good []*Server
	for _, s := range a.servers {
		if s.Kind == "tor" && s.Ping > 0 && supported[s.Type] && s.Country != "ru" {
			good = append(good, s)
		}
	}
	// obfs4/webtunnel first: plain (vanilla) Tor is easy to detect and block
	weight := func(s *Server) int {
		switch s.Type {
		case "webtunnel", "obfs4":
			return s.Ping
		case "snowflake":
			return s.Ping + 2000
		}
		return s.Ping + 1000
	}
	sort.Slice(good, func(i, j int) bool { return weight(good[i]) < weight(good[j]) })
	var chosen []*Server
	if s := a.byID[id]; s != nil && s.Country != "ru" {
		if !supported[s.Type] {
			return nil, fmt.Errorf("установленный Tor не поддерживает мосты типа %s", s.Type)
		}
		chosen = append(chosen, s)
	}
	// add backups: Tor tries them all and keeps the ones that work
	for _, s := range good {
		if len(chosen) >= 8 {
			break
		}
		if len(chosen) > 0 && s.ID == chosen[0].ID {
			continue
		}
		chosen = append(chosen, s)
	}
	if len(chosen) == 0 {
		return nil, errors.New("нет рабочих мостов — нажмите «Обновить» или «Пинг»")
	}
	return chosen, nil
}

func (a *App) connectTor(ctx context.Context, id string) error {
	progress := func(m string) { a.setConn(func(c *ConnState) { c.Message = m }) }
	ptLines, supported := a.cores.TransportLines()
	bridges, err := a.pickTorBridges(id, supported)
	if err != nil {
		return err
	}
	a.setConn(func(c *ConnState) { c.ServerID = bridges[0].ID; c.Server = bridges[0].Name })
	var lines, domains []string
	for _, b := range bridges {
		lines = append(lines, b.Raw)
		domains = append(domains, bridgeDomains(b.Raw)...)
	}
	var ips []string
	for _, b := range bridges {
		if net.ParseIP(b.Host) != nil {
			ips = append(ips, b.Host)
		} else if b.IP != "" {
			ips = append(ips, b.IP)
		}
	}
	a.mu.Lock()
	a.directDomains = domains
	a.excludeIPs = ips
	a.mu.Unlock()
	a.logf("Tor: использую %d мостов (основной: %s)", len(bridges), bridges[0].Name)
	torrc := BuildTorrc(lines, ptLines)
	os.MkdirAll(filepath.Join(a.cores.TorDir(), "data", "state"), 0o755)
	if err := os.WriteFile(filepath.Join(a.cores.TorDir(), "torrc"), []byte(torrc), 0o644); err != nil {
		return err
	}
	progress("Запуск Tor…")
	boot := make(chan int, 16)
	cmd, err := a.startProc("Tor", a.cores.TorDir(), func(l string) {
		if m := bootRe.FindStringSubmatch(l); m != nil {
			p, _ := strconv.Atoi(m[1])
			a.setConn(func(c *ConnState) { c.Progress = p; c.Message = "Tor: " + torStage(p, m[2]) })
			select {
			case boot <- p:
			default:
			}
		}
		if strings.Contains(l, "[warn]") || strings.Contains(l, "[err]") || strings.Contains(l, "Bootstrapped") {
			a.logf("tor: %s", trimTorLog(l))
		}
	}, a.cores.TorExe(), "-f", "torrc")
	if err != nil {
		return err
	}
	deadline := time.After(180 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p := <-boot:
			if p >= 100 {
				return nil
			}
		case <-deadline:
			return errors.New("Tor не смог подключиться за 3 минуты. Попробуйте другой мост (лучше webtunnel или obfs4) или нажмите «Пинг»")
		case <-time.After(time.Second):
			if !alive(cmd) {
				return errors.New("Tor неожиданно завершился — подробности в журнале")
			}
		}
	}
}

// bridgeDomains lists hostnames a bridge line needs (webtunnel URL, snowflake broker/front…).
func bridgeDomains(line string) []string {
	var out []string
	for _, kv := range strings.Fields(line) {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		k, v := kv[:i], kv[i+1:]
		switch k {
		case "url", "ampcache":
			if u, err := url.Parse(v); err == nil && u.Hostname() != "" && net.ParseIP(u.Hostname()) == nil {
				out = append(out, u.Hostname())
			}
		case "front", "fronts":
			for _, f := range strings.Split(v, ",") {
				if f != "" && net.ParseIP(f) == nil {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

func torStage(p int, msg string) string {
	switch {
	case p < 10:
		return "соединение с мостом…"
	case p < 50:
		return "загрузка каталога сети…"
	case p < 90:
		return "построение цепочки…"
	case p < 100:
		return "почти готово…"
	}
	return "готово"
}

func trimTorLog(l string) string {
	if i := strings.Index(l, "["); i >= 0 {
		return l[i:]
	}
	return l
}

// testProxy makes a real request through the local HTTP proxy.
// URLs used to check that a server really carries traffic
var testURLs = []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}

func testProxy(ctx context.Context, port int, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	cl := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
	var lastErr error
	for _, u := range testURLs {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		t0 := time.Now()
		resp, err := cl.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		// any real HTTP answer from the far side means traffic flows through the server
		return time.Since(t0), nil
	}
	return 0, lastErr
}

func (a *App) startXray(ctx context.Context, file string, cfg []byte, waitPort int, quiet bool) (*exec.Cmd, error) {
	if err := os.WriteFile(filepath.Join(a.cores.XrayDir(), file), cfg, 0o644); err != nil {
		return nil, err
	}
	var logged atomic.Int32
	cmd, err := a.startProc("Xray", a.cores.XrayDir(), func(l string) {
		if strings.Contains(l, "received real certificate") || strings.Contains(l, "certificate signed by unknown authority") {
			a.mu.Lock()
			a.mitm = a.mitm || strings.Contains(l, "received real certificate")
			a.mu.Unlock()
		}
		if strings.Contains(l, "[Warning]") && (strings.Contains(l, "deprecated") || strings.Contains(l, "started")) {
			return
		}
		if !quiet && (strings.Contains(l, "[Error]") || strings.Contains(l, "[Warning]") || strings.Contains(l, "Failed")) && logged.Add(1) <= 3 {
			if i := strings.Index(l, "] "); i > 0 && i < 40 {
				l = l[i+2:]
			}
			a.logf("xray: %s", l)
		}
	}, a.cores.XrayExe(), "run", "-c", file)
	if err != nil {
		return nil, err
	}
	// wait for the HTTP inbound
	for i := 0; i < 60; i++ {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", waitPort), 200*time.Millisecond); err == nil {
			c.Close()
			return cmd, nil
		}
		if !alive(cmd) {
			return cmd, errors.New("Xray не запустился — возможно, его заблокировал антивирус. Добавьте папку MRFS в доверенные программы")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return cmd, errors.New("Xray не открыл локальный порт")
}

func (a *App) killProc(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	waitExit(cmd)
	a.mu.Lock()
	for i, p := range a.procs {
		if p == cmd {
			a.procs = append(a.procs[:i], a.procs[i+1:]...)
			break
		}
	}
	a.mu.Unlock()
}

// connectVless connects straight to the chosen server (or the fastest one if none is chosen)
// — no pre-checks. Whether traffic flows is checked afterwards and only shown, never blocks.
func (a *App) connectVless(ctx context.Context, id string) error {
	s := a.byIDCopy(id)
	if s == nil {
		if all := a.Servers("vless"); len(all) > 0 {
			s = &all[0]
		}
	}
	if s == nil {
		return errors.New("нет серверов — нажмите «Обновить»")
	}
	a.setConn(func(c *ConnState) {
		c.ServerID, c.Server, c.Progress = s.ID, s.Name, 50
		c.Message = "Подключаюсь к " + s.Name + "…"
	})
	// resolve the server now (before the TUN exists) and pin that IP
	ip := s.Host
	if net.ParseIP(ip) == nil {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(rctx, s.Host)
		cancel()
		ip = ""
		for _, ad := range addrs {
			if ad.IP.To4() != nil {
				ip = ad.IP.String()
				break
			}
		}
		if ip == "" && len(addrs) > 0 {
			ip = addrs[0].IP.String()
		}
		if ip == "" {
			return fmt.Errorf("не удалось найти адрес сервера %s: %v", s.Name, err)
		}
	}
	cfg, err := BuildXrayConfig(s.Raw, ip)
	if err != nil {
		return fmt.Errorf("не удалось разобрать конфиг сервера: %w", err)
	}
	a.mu.Lock()
	a.directDomains = nil
	a.excludeIPs = []string{ip}
	a.settings.LastVless = s.ID
	a.mu.Unlock()
	a.saveSettings()
	if _, err := a.startXray(ctx, "mrfs.json", cfg, XrayHTTPPort, false); err != nil {
		return err
	}
	a.logf("VLESS: подключено к «%s» (%s · %s)", s.Name, s.Type, s.Net)
	return nil
}

// verifyTun: the server worked before the TUN was switched on; if it stops working with the
// TUN (another VPN / antivirus adapter in the way), fall back to the system proxy automatically.
func (a *App) verifyTun(ctx context.Context) {
	_, err := testProxy(ctx, XrayHTTPPort, 8*time.Second)
	if ctx.Err() != nil || err == nil {
		if err == nil {
			a.logf("Проверка режима «Весь компьютер»: OK")
		}
		return
	}
	a.logf("С режимом «Весь компьютер» трафик не идёт (%s) — переключаюсь на «Системный прокси»", shortErr(err))
	a.mu.Lock()
	cmd := a.tunCmd
	a.tunCmd = nil
	a.mu.Unlock()
	a.killProc(cmd)
	if err := setSystemProxy(fmt.Sprintf("127.0.0.1:%d", XrayHTTPPort)); err == nil {
		os.WriteFile(filepath.Join(a.dataDir, ".proxy_on"), []byte("1"), 0o644)
		a.mu.Lock()
		a.proxySet = true
		a.mu.Unlock()
	}
	a.setConn(func(c *ConnState) {
		c.Route = "proxy"
		c.Warn = "«Весь компьютер» не заработал на этом ПК — включён системный прокси"
	})
	go a.detectIP("vless")
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		s = s[len(s)-90:]
	}
	return s
}

func (a *App) byIDCopy(id string) *Server {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s := a.byID[id]; s != nil {
		c := *s
		return &c
	}
	return nil
}

// markBad hides a server that answered ping but could not carry traffic.
func (a *App) markBad(id string) {
	a.mu.Lock()
	if s := a.byID[id]; s != nil {
		s.Fail++
		s.Ping = -2
		a.ver++
	}
	a.mu.Unlock()
}

// applyRoute sends the whole computer through the connection.
func (a *App) applyRoute(ctx context.Context, kind string) error {
	route := a.settings.Route
	if route == "tun" && !isAdmin() {
		a.logf("Нет прав администратора — использую системный прокси")
		route = "proxy"
	}
	if route == "tun" {
		a.setConn(func(c *ConnState) { c.Message = "Включаю режим «Весь компьютер»…" })
		err := a.startTun(ctx, kind)
		if err == nil {
			a.setConn(func(c *ConnState) { c.Route = "tun" })
			return nil
		}
		a.logf("TUN не запустился (%v) — переключаюсь на системный прокси", err)
		route = "proxy"
	}
	// system proxy: browsers and most apps. For Tor we put Xray in front as an HTTP proxy.
	if kind == "tor" {
		cfg, _ := json.MarshalIndent(map[string]any{
			"log": map[string]any{"loglevel": "warning"},
			"inbounds": []any{map[string]any{"tag": "http", "listen": "127.0.0.1", "port": XrayHTTPPort, "protocol": "http"},
				map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": XraySocksPort, "protocol": "socks",
					"settings": map[string]any{"udp": false}}},
			"outbounds": []any{map[string]any{"tag": "tor", "protocol": "socks", "settings": map[string]any{
				"servers": []any{map[string]any{"address": "127.0.0.1", "port": TorSocksPort}}}}},
		}, "", "  ")
		if err := a.cores.EnsureXray(ctx, func(string) {}); err != nil {
			return err
		}
		if cmd, err := a.startXray(ctx, "mrfs.json", cfg, XrayHTTPPort, false); err != nil {
			a.killProc(cmd)
			return err
		}
	}
	if err := setSystemProxy(fmt.Sprintf("127.0.0.1:%d", XrayHTTPPort)); err != nil {
		return fmt.Errorf("не удалось включить системный прокси: %w", err)
	}
	os.WriteFile(filepath.Join(a.dataDir, ".proxy_on"), []byte("1"), 0o644)
	a.mu.Lock()
	a.proxySet = true
	a.mu.Unlock()
	a.setConn(func(c *ConnState) { c.Route = "proxy" })
	a.logf("Системный прокси включён: 127.0.0.1:%d", XrayHTTPPort)
	return nil
}

func (a *App) startTun(ctx context.Context, kind string) error {
	if err := a.cores.EnsureSingBox(ctx, func(m string) { a.setConn(func(c *ConnState) { c.Message = m }) }); err != nil {
		return err
	}
	port := XraySocksPort
	if kind == "tor" {
		port = TorSocksPort
	}
	a.mu.Lock()
	dd, ex := a.directDomains, a.excludeIPs
	// a fresh adapter name each time: Windows may still hold the previous one for a moment
	a.tunName = fmt.Sprintf("MRFS-%d", time.Now().UnixNano()%100000)
	name := a.tunName
	a.mu.Unlock()
	cfg, err := BuildSingBoxConfig(name, port, kind == "tor", dd, ex)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.cores.SingBoxDir(), "mrfs.json"), cfg, 0o644); err != nil {
		return err
	}
	var fatal atomic.Value
	var nlog atomic.Int32
	cmd, err := a.startProc("sing-box", a.cores.SingBoxDir(), func(l string) {
		if strings.Contains(l, "FATAL") || ((strings.Contains(l, "ERROR") || strings.Contains(l, "WARN")) && nlog.Add(1) <= 8) {
			if i := strings.Index(l, " ERROR "); i > 0 {
				l = l[i+1:]
			}
			a.logf("tun: %s", l)
		}
		if strings.Contains(l, "FATAL") {
			fatal.Store(l)
		}
	}, a.cores.SingBoxExe(), "run", "-c", "mrfs.json", "-D", ".", "--disable-color")
	if err != nil {
		return err
	}
	// give the adapter time to come up (Windows can take ~10 s on first creation)
	up := false
	for i := 0; i < 100; i++ {
		time.Sleep(200 * time.Millisecond)
		if !alive(cmd) || fatal.Load() != nil {
			a.killProc(cmd)
			if f, ok := fatal.Load().(string); ok {
				return errors.New(f)
			}
			return errors.New("процесс завершился")
		}
		if tunUp(name) {
			up = true
			break
		}
	}
	if !up {
		a.killProc(cmd)
		return errors.New("виртуальный адаптер не появился")
	}
	time.Sleep(700 * time.Millisecond) // routes settle
	a.mu.Lock()
	a.tunCmd = cmd
	a.mu.Unlock()
	a.logf("Режим «Весь компьютер» включён (TUN)")
	return nil
}

func (a *App) detectIP(kind string) {
	cl := a.httpClient(true)
	if cl == nil {
		return
	}
	cl.Timeout = 20 * time.Second
	u := "https://api.ipify.org"
	if kind == "tor" {
		u = "https://check.torproject.org/api/ip"
	}
	resp, err := cl.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	ip := strings.TrimSpace(string(b))
	if kind == "tor" {
		var v struct {
			IsTor bool
			IP    string
		}
		if json.Unmarshal(b, &v) == nil && v.IP != "" {
			ip = v.IP
			if v.IsTor {
				ip += " (Tor ✓)"
			}
		}
	}
	if len(ip) > 60 || ip == "" {
		return
	}
	a.setConn(func(c *ConnState) {
		if c.Status == "on" {
			c.IP = ip
		}
	})
	a.logf("Внешний IP: %s", ip)
}

func (a *App) Shutdown() {
	a.savePings()
	if a.pingStop != nil {
		a.pingStop()
	}
	a.Disconnect()
}
