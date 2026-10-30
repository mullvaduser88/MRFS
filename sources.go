package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Repo describes one GitHub repository (or a folder inside it) we pull data from.
type Repo struct {
	Owner, Name, Branch string
	Dir                 string         // folder inside the repo ("" = root)
	Match               *regexp.Regexp // which files in the folder to take
	Fallback            []string       // file list to use if the GitHub API is unavailable
	Kind                string         // "tor" or "vless"
}

func (r Repo) Key() string { return r.Owner + "/" + r.Name + "/" + r.Dir }

var Repos = []Repo{
	{Owner: "igareck", Name: "vpn-configs-for-russia", Branch: "main", Dir: "TOR-BRIDGES", Kind: "tor",
		Match:    regexp.MustCompile(`(?i)\.txt$`),
		Fallback: []string{"TOR_BRIDGES_ALL.txt"}},
	{Owner: "Delta-Kronecker", Name: "Tor-Bridges-Collector", Branch: "main", Dir: "bridge", Kind: "tor",
		Match: regexp.MustCompile(`(?i)^(obfs4|webtunnel|vanilla|snowflake)(_tested|_72h)?\.txt$`),
		Fallback: []string{"obfs4.txt", "obfs4_tested.txt", "obfs4_72h.txt", "webtunnel.txt", "webtunnel_tested.txt",
			"webtunnel_72h.txt", "vanilla.txt", "vanilla_tested.txt", "vanilla_72h.txt", "snowflake.txt"}},
	{Owner: "zieng2", Name: "wl", Branch: "main", Dir: "", Kind: "vless",
		Match:    regexp.MustCompile(`(?i)^vless.*\.txt$`),
		Fallback: []string{"vless.txt", "vless_lite.txt", "vless_universal.txt"}},
	{Owner: "aviamastersgh", Name: "vpn-free-russia", Branch: "main", Dir: "", Kind: "vless",
		Match:    regexp.MustCompile(`(?i)configs.*\.txt$`),
		Fallback: []string{"verified_configs.txt", "ru_configs.txt", "all_configs.txt"}},
	{Owner: "terik21", Name: "HiddifySubs-VlessKeys", Branch: "main", Dir: "", Kind: "vless",
		Match:    regexp.MustCompile(`^(main|WhiteKeys\d*|WLTest)$`),
		Fallback: []string{"main", "WhiteKeys", "WhiteKeys2"}},
}

// RepoStatus is shown in the UI.
type RepoStatus struct {
	Repo    string `json:"repo"`
	Commit  string `json:"commit"`
	Files   int    `json:"files"`
	Items   int    `json:"items"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Checked string `json:"checked"`
	Changed string `json:"changed"`
}

type repoCache struct {
	Commit  string            `json:"commit"`
	Files   map[string]string `json:"files"` // file name -> content
	Changed time.Time         `json:"changed"`
}

type Fetcher struct {
	dir    string
	client func(viaProxy bool) *http.Client
	mu     sync.Mutex
	cache  map[string]*repoCache
	status map[string]*RepoStatus
}

func NewFetcher(dataDir string, client func(viaProxy bool) *http.Client) *Fetcher {
	f := &Fetcher{dir: filepath.Join(dataDir, "cache"), client: client,
		cache: map[string]*repoCache{}, status: map[string]*RepoStatus{}}
	os.MkdirAll(f.dir, 0o755)
	for _, r := range Repos {
		var c repoCache
		if b, err := os.ReadFile(f.cacheFile(r)); err == nil && json.Unmarshal(b, &c) == nil {
			f.cache[r.Key()] = &c
		}
	}
	return f
}

func (f *Fetcher) cacheFile(r Repo) string {
	h := sha1.Sum([]byte(r.Key()))
	return filepath.Join(f.dir, r.Owner+"_"+r.Name+"_"+hex.EncodeToString(h[:4])+".json")
}

// get tries a direct request first, then through the running proxy (if connected).
func (f *Fetcher) get(ctx context.Context, url string, accept string) ([]byte, error) {
	b, err := f.get1(ctx, f.client(false), url, accept)
	if err != nil && ctx.Err() == nil {
		if pc := f.client(true); pc != nil {
			if b2, err2 := f.get1(ctx, pc, url, accept); err2 == nil {
				return b2, nil
			}
		}
	}
	return b, err
}

func (f *Fetcher) get1(ctx context.Context, cl *http.Client, url string, accept string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "MRFS/1.0")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// latestCommit asks GitHub for the head commit of the branch (several mirrors).
func (f *Fetcher) latestCommit(ctx context.Context, r Repo) (string, error) {
	b, err := f.get(ctx, fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", r.Owner, r.Name, r.Branch),
		"application/vnd.github.sha")
	if err == nil && len(b) >= 40 && !strings.HasPrefix(string(b), "{") {
		return strings.TrimSpace(string(b))[:40], nil
	}
	// jsDelivr knows the latest commit too
	b2, err2 := f.get(ctx, fmt.Sprintf("https://data.jsdelivr.com/v1/packages/gh/%s/%s/resolved?specifier=%s", r.Owner, r.Name, r.Branch), "")
	if err2 == nil {
		var v struct{ Version string }
		if json.Unmarshal(b2, &v) == nil && len(v.Version) >= 7 {
			return v.Version, nil
		}
	}
	if err == nil {
		err = fmt.Errorf("unexpected response")
	}
	return "", err
}

// listFiles returns the files to download and whether the list is authoritative (came from GitHub).
func (f *Fetcher) listFiles(ctx context.Context, r Repo, ref string) ([]string, bool) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", r.Owner, r.Name, r.Dir, ref)
	b, err := f.get(ctx, url, "application/vnd.github+json")
	if err == nil {
		var items []struct{ Name, Type string }
		if json.Unmarshal(b, &items) == nil {
			var out []string
			for _, it := range items {
				if it.Type == "file" && r.Match.MatchString(it.Name) {
					out = append(out, it.Name)
				}
			}
			if len(out) > 0 {
				sort.Strings(out)
				return out, true
			}
		}
	}
	return r.Fallback, false
}

func (f *Fetcher) fetchFile(ctx context.Context, r Repo, ref, name string) ([]byte, error) {
	p := name
	if r.Dir != "" {
		p = path.Join(r.Dir, name)
	}
	urls := []string{
		fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", r.Owner, r.Name, ref, p),
		fmt.Sprintf("https://cdn.jsdelivr.net/gh/%s/%s@%s/%s", r.Owner, r.Name, ref, p),
		fmt.Sprintf("https://github.com/%s/%s/raw/%s/%s", r.Owner, r.Name, ref, p),
	}
	var lastErr error
	for _, u := range urls {
		c, cancel := context.WithTimeout(ctx, 60*time.Second)
		b, err := f.get(c, u, "")
		cancel()
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Update checks every repo; returns true if anything changed. force re-downloads files.
func (f *Fetcher) Update(ctx context.Context, force bool, logf func(string, ...any)) bool {
	changed := false
	var wg sync.WaitGroup
	var cm sync.Mutex
	for _, r := range Repos {
		wg.Add(1)
		go func(r Repo) {
			defer wg.Done()
			if f.updateRepo(ctx, r, force, logf) {
				cm.Lock()
				changed = true
				cm.Unlock()
			}
		}(r)
	}
	wg.Wait()
	return changed
}

func (f *Fetcher) updateRepo(ctx context.Context, r Repo, force bool, logf func(string, ...any)) bool {
	key := r.Key()
	f.mu.Lock()
	old := f.cache[key]
	st := f.status[key]
	if st == nil {
		st = &RepoStatus{Repo: r.Owner + "/" + r.Name + "/" + r.Dir}
		f.status[key] = st
	}
	f.mu.Unlock()
	setStatus := func(fn func(*RepoStatus)) { f.mu.Lock(); fn(st); f.mu.Unlock() }
	setStatus(func(s *RepoStatus) { s.Checked = time.Now().Format("15:04:05") })

	commit, err := f.latestCommit(ctx, r)
	ref := commit
	if err != nil {
		ref = r.Branch // cannot learn commit — fetch the branch head and compare contents
	}
	if err == nil && old != nil && old.Commit == commit && !force && len(old.Files) > 0 {
		setStatus(func(s *RepoStatus) { s.OK = true; s.Error = ""; s.Commit = short(commit) })
		return false
	}
	files, exact := f.listFiles(ctx, r, ref)
	nc := &repoCache{Commit: commit, Files: map[string]string{}}
	if old != nil && !exact {
		// without the real file list keep everything we had; fresh downloads overwrite it
		for k, v := range old.Files {
			nc.Files[k] = v
		}
	}
	var errs []string
	got := 0
	for _, name := range files {
		b, e := f.fetchFile(ctx, r, ref, name)
		if e != nil {
			errs = append(errs, name+": "+e.Error())
			if old != nil && old.Files[name] != "" {
				nc.Files[name] = old.Files[name]
			}
			continue
		}
		got++
		nc.Files[name] = string(b)
	}
	if got == 0 {
		if old != nil {
			nc = old // nothing downloaded — keep the cached copy untouched
		}
		msg := strings.Join(errs, "; ")
		if err != nil {
			msg = err.Error() + "; " + msg
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		setStatus(func(s *RepoStatus) {
			s.OK = false
			s.Error = msg
			if old != nil {
				s.Commit, s.Files = short(old.Commit), len(old.Files)
				if !old.Changed.IsZero() {
					s.Changed = old.Changed.Format("02.01 15:04")
				}
			}
		})
		logf("Источник %s недоступен (используется сохранённая копия): %s", st.Repo, msg)
		return false
	}
	isChanged := old == nil || !sameFiles(old.Files, nc.Files)
	if isChanged {
		nc.Changed = time.Now()
	} else {
		nc.Changed = old.Changed
	}
	if commit == "" && old != nil {
		nc.Commit = old.Commit
	}
	f.mu.Lock()
	f.cache[key] = nc
	st.OK, st.Error, st.Commit, st.Files = true, strings.Join(errs, "; "), short(nc.Commit), len(nc.Files)
	if !nc.Changed.IsZero() {
		st.Changed = nc.Changed.Format("02.01 15:04")
	}
	f.mu.Unlock()
	if b, e := json.Marshal(nc); e == nil {
		os.WriteFile(f.cacheFile(r), b, 0o644)
	}
	if isChanged {
		logf("Источник %s обновлён (%d файлов)", st.Repo, len(nc.Files))
	}
	return isChanged
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// Servers parses everything that is currently cached.
func (f *Fetcher) Servers() []*Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]*Server{}
	var out []*Server
	for _, r := range Repos {
		c := f.cache[r.Key()]
		if c == nil {
			continue
		}
		names := make([]string, 0, len(c.Files))
		for n := range c.Files {
			names = append(names, n)
		}
		sort.Strings(names)
		count := 0
		for _, n := range names {
			src := r.Owner + "/" + r.Name
			for _, line := range strings.Split(c.Files[n], "\n") {
				var s *Server
				if r.Kind == "tor" {
					s = ParseBridge(line)
				} else {
					s = ParseVless(line)
				}
				if s == nil {
					continue
				}
				count++
				if prev, ok := seen[s.ID]; ok {
					if !contains(prev.Sources, src) {
						prev.Sources = append(prev.Sources, src)
					}
					continue
				}
				s.Sources = []string{src}
				seen[s.ID] = s
				out = append(out, s)
			}
		}
		st := f.status[r.Key()]
		if st == nil {
			st = &RepoStatus{Repo: r.Owner + "/" + r.Name + "/" + r.Dir, OK: true, Commit: short(c.Commit), Files: len(c.Files)}
			if !c.Changed.IsZero() {
				st.Changed = c.Changed.Format("02.01 15:04")
			}
			f.status[r.Key()] = st
		}
		st.Items = count
	}
	return out
}

func (f *Fetcher) Status() []RepoStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []RepoStatus
	for _, r := range Repos {
		if st := f.status[r.Key()]; st != nil {
			out = append(out, *st)
		} else {
			out = append(out, RepoStatus{Repo: r.Owner + "/" + r.Name + "/" + r.Dir})
		}
	}
	return out
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
