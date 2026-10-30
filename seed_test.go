package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSeed builds the bundled offline cache from local git clones (SEED_SRC/<owner>_<repo>).
func TestSeed(t *testing.T) {
	src, out := os.Getenv("SEED_SRC"), os.Getenv("SEED_OUT")
	if src == "" || out == "" {
		t.Skip()
	}
	f := NewFetcher(out, nil)
	for _, r := range Repos {
		root := filepath.Join(src, r.Owner+"_"+r.Name)
		sha, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
		ents, _ := os.ReadDir(filepath.Join(root, r.Dir))
		c := &repoCache{Commit: strings.TrimSpace(string(sha)), Files: map[string]string{}, Changed: time.Now()}
		for _, e := range ents {
			if !e.IsDir() && r.Match.MatchString(e.Name()) {
				b, _ := os.ReadFile(filepath.Join(root, r.Dir, e.Name()))
				c.Files[e.Name()] = string(b)
			}
		}
		b, _ := json.Marshal(c)
		os.WriteFile(f.cacheFile(r), b, 0o644)
		t.Logf("%s: %d files @%s", r.Key(), len(c.Files), short(c.Commit))
	}
}
