//go:build !windows

package main

// Headless test harness (the real app is Windows-only):
//   go run . <workdir>   — fetches sources, pings, prints the fastest servers.
import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	app := NewApp(dir)
	app.Start()
	for {
		time.Sleep(2 * time.Second)
		st := app.State()
		if lg := app.Logs(); len(lg) > 0 {
			fmt.Println("   last log:", lg[len(lg)-1])
		}
		fmt.Printf("updating=%v pinging=%v %d/%d counts=%v\n", st.Updating, st.Pinging, st.PingDone, st.PingTotal, st.Counts)
		if !st.Updating && !st.Pinging && st.PingTotal > 0 && st.PingDone == st.PingTotal {
			break
		}
	}
	for _, k := range []string{"tor", "vless"} {
		l := app.Servers(k)
		fmt.Printf("== %s: %d working\n", k, len(l))
		for i := 0; i < len(l) && i < 5; i++ {
			fmt.Printf("  %4d ms  %-10s %s\n", l[i].Ping, l[i].Type, l[i].Name)
		}
	}
	if os.Getenv("TEST_CONNECT") != "" {
		app.Connect("vless", "")
		for i := 0; i < 120; i++ {
			time.Sleep(time.Second)
			c := app.State().Conn
			if c.Status != "connecting" {
				fmt.Printf("CONNECT RESULT: %+v\n", c)
				break
			}
		}
		app.Shutdown()
	}
	if out := os.Getenv("MOCK_OUT"); out != "" {
		b, _ := json.Marshal(map[string]any{"tor": app.Servers("tor"), "vless": app.Servers("vless"), "state": app.State(), "logs": app.Logs()})
		os.WriteFile(out, b, 0o644)
	}
	for _, s := range app.fetcher.Status() {
		fmt.Printf("%+v\n", s)
	}
	for _, l := range app.Logs() {
		fmt.Println(l)
	}
}
