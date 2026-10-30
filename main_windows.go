//go:build windows

package main

import (
	_ "embed"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

//go:embed ui/index.html
var indexHTML string

//go:embed ui/flags.json
var flagsJSON string

//go:embed ui/logo.png
var logoPNG []byte

func init() { runtime.LockOSThread() }

func msgBox(text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("MRFS")
	windows.MessageBox(0, t, c, windows.MB_OK|windows.MB_ICONWARNING)
}

func main() {
	name, _ := windows.UTF16PtrFromString("Local\\MRFS_MoleRouter_single")
	// a just-elevated copy may start while the old one is still closing — wait a little
	var mutex windows.Handle
	for i := 0; ; i++ {
		h, err := windows.CreateMutex(nil, false, name)
		if err != windows.ERROR_ALREADY_EXISTS {
			mutex = h
			break
		}
		windows.CloseHandle(h)
		if i > 30 || len(os.Args) < 2 || os.Args[1] != "--connect" {
			msgBox("MRFS уже запущен.")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	exe, _ := os.Executable()
	base := filepath.Dir(exe)

	app := NewApp(base)
	app.logf("MRFS %s запущен", AppVersion)
	if !isAdmin() {
		app.logf("Запущено без прав администратора — режим «Весь компьютер» недоступен, будет системный прокси")
	}
	app.Start()
	defer app.Shutdown()
	// started by "restart as administrator" — continue the connection the user asked for
	if len(os.Args) >= 3 && os.Args[1] == "--connect" && isAdmin() {
		kind, id := os.Args[2], ""
		if len(os.Args) >= 4 {
			id = os.Args[3]
		}
		go app.ConnectWhenReady(kind, id)
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     os.Getenv("MRFS_DEBUG") != "",
		AutoFocus: true,
		DataPath:  filepath.Join(base, "data", "webview"),
		WindowOptions: webview2.WindowOptions{
			Title:  "MRFS — Mole Router Fast and Secure",
			Width:  1180,
			Height: 780,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		msgBox("Не найден компонент Microsoft Edge WebView2 Runtime.\n\n" +
			"Скачайте его с https://go.microsoft.com/fwlink/p/?LinkId=2124703 , установите и запустите MRFS снова.")
		return
	}
	defer w.Destroy()
	w.SetSize(980, 640, webview2.HintMin)

	w.Bind("mrfsState", func() StateDTO { return app.State() })
	w.Bind("mrfsServers", func(kind string) []Server { return app.Servers(kind) })
	w.Bind("mrfsLogs", func() []string { return app.Logs() })
	w.Bind("mrfsPing", func(kind string) { go app.PingAll(kind) })
	w.Bind("mrfsRefresh", func() { app.Refresh() })
	w.Bind("mrfsConnect", func(kind, id string) { app.Connect(kind, id) })
	w.Bind("mrfsDisconnect", func() { go app.Disconnect() })
	w.Bind("mrfsSetRoute", func(r string) { app.SetRoute(r) })
	w.Bind("mrfsSetKind", func(k string) { app.SetKind(k) })
	// elevate only when the user turns on "whole computer" mode
	w.Bind("mrfsElevate", func(kind, id string) bool {
		verb, _ := windows.UTF16PtrFromString("runas")
		file, _ := windows.UTF16PtrFromString(exe)
		args, _ := windows.UTF16PtrFromString("--connect " + kind + " " + id)
		windows.CloseHandle(mutex)
		if err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_SHOWNORMAL); err != nil {
			mutex, _ = windows.CreateMutex(nil, false, name) // user pressed "No"
			return false
		}
		go w.Dispatch(func() { w.Terminate() })
		return true
	})
	w.Bind("mrfsOpen", func(u string) {
		if len(u) > 8 && u[:8] == "https://" {
			p, _ := windows.UTF16PtrFromString(u)
			o, _ := windows.UTF16PtrFromString("open")
			windows.ShellExecute(0, o, p, nil, nil, windows.SW_SHOWNORMAL)
		}
	})

	// tray: closing the window hides it; "Выход" in the tray menu quits
	hwnd := uintptr(w.Window())
	t := NewTray(hwnd)
	defer t.Remove()
	t.isConnected = func() bool { st := app.State().Conn.Status; return st == "on" || st == "connecting" }
	t.onDisconect = func() { go app.Disconnect() }
	t.onConnect = func() {
		st := app.State()
		if st.Settings.Route == "tun" && !st.Admin {
			t.Show() // needs the elevation prompt from the window
			return
		}
		app.Connect(st.Settings.Kind, "")
	}
	w.Bind("mrfsQuit", func() { t.Quit() })
	go func() {
		last := ""
		for {
			time.Sleep(time.Second)
			c := app.State().Conn
			tip := "MRFS — не подключено"
			switch c.Status {
			case "connecting":
				tip = "MRFS — подключение…"
			case "on":
				mode := "Быстрое"
				if c.Kind == "tor" {
					mode = "Tor"
				}
				tip = "MRFS — подключено (" + mode + ")\n" + c.Server
			case "error":
				tip = "MRFS — ошибка подключения"
			}
			if tip != last {
				if c.Status == "on" && strings.HasPrefix(last, "MRFS — подключение") && !windowVisible(hwnd) {
					t.Balloon("MRFS: подключено", c.Server)
				}
				last = tip
				t.SetTip(tip)
			}
		}
	}()

	page := strings.Replace(indexHTML, "/*FLAGS*/{}", flagsJSON, 1)
	page = strings.ReplaceAll(page, "LOGO_SRC", "data:image/png;base64,"+base64.StdEncoding.EncodeToString(logoPNG))
	w.SetHtml(page)
	w.Run()
}
