//go:build windows

package main

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// System-tray support: the close button hides the window to the tray,
// "Выход" in the tray menu really quits.

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	shell32              = windows.NewLazySystemDLL("shell32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	procSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProc   = user32.NewProc("CallWindowProcW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procLoadImage        = user32.NewProc("LoadImageW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procPostMessage      = user32.NewProc("PostMessageW")
	procIsWindowVisible  = user32.NewProc("IsWindowVisible")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
	procRegisterWinMsg   = user32.NewProc("RegisterWindowMessageW")
)

const (
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmNull        = 0x0000
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmTray        = 0x8000 + 1 // WM_APP+1
	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nifMessage    = 0x1
	nifIcon       = 0x2
	nifTip        = 0x4
	nifInfo       = 0x10
	niifUser      = 0x4
	swHide        = 0
	swShow        = 5
	swRestore     = 9
	mfString      = 0x0
	mfSeparator   = 0x800
	mfGrayed      = 0x1
	tpmReturnCmd  = 0x100
	tpmRightAlign = 0x8
	gwlpWndProc   = ^uintptr(3) // -4
)

const (
	cmdOpen = 1001 + iota
	cmdConnect
	cmdDisconnect
	cmdQuit
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

type Tray struct {
	hwnd        uintptr
	oldProc     uintptr
	nid         notifyIconData
	mu          sync.Mutex
	quitting    bool
	hintShown   bool
	taskbarMsg  uintptr
	onQuit      func()
	onConnect   func()
	onDisconect func()
	isConnected func() bool
}

var tray *Tray

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)-1]
		u = append(u, 0)
	}
	copy(dst, u)
}

func NewTray(hwnd uintptr) *Tray {
	t := &Tray{hwnd: hwnd}
	tray = t
	hinst, _, _ := procGetModuleHandle.Call(0)
	// icon resource #1 (embedded by go-winres), small size
	icon, _, _ := procLoadImage.Call(hinst, 1, 1 /*IMAGE_ICON*/, 32, 32, 0)
	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))
	t.nid.HWnd = hwnd
	t.nid.UID = 1
	t.nid.UFlags = nifMessage | nifIcon | nifTip
	t.nid.UCallbackMessage = wmTray
	t.nid.HIcon = icon
	copyUTF16(t.nid.SzTip[:], "MRFS — не подключено")
	procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))
	name, _ := windows.UTF16PtrFromString("TaskbarCreated")
	t.taskbarMsg, _, _ = procRegisterWinMsg.Call(uintptr(unsafe.Pointer(name)))
	// subclass the webview window to catch close + tray messages
	t.oldProc, _, _ = procSetWindowLongPtr.Call(hwnd, gwlpWndProc, windows.NewCallback(trayWndProc))
	return t
}

func (t *Tray) SetTip(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.quitting {
		return
	}
	t.nid.SzTip = [128]uint16{}
	copyUTF16(t.nid.SzTip[:], s)
	t.nid.UFlags = nifMessage | nifIcon | nifTip
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
}

func (t *Tray) Balloon(title, text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.nid
	n.UFlags = nifInfo
	copyUTF16(n.SzInfoTitle[:], title)
	copyUTF16(n.SzInfo[:], text)
	n.DwInfoFlags = niifUser
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&n)))
}

func (t *Tray) Remove() {
	t.mu.Lock()
	t.quitting = true
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
	t.mu.Unlock()
}

func (t *Tray) Show() {
	procShowWindow.Call(t.hwnd, swShow)
	procShowWindow.Call(t.hwnd, swRestore)
	procSetForeground.Call(t.hwnd)
}

func (t *Tray) Quit() {
	t.mu.Lock()
	t.quitting = true
	t.mu.Unlock()
	procPostMessage.Call(t.hwnd, wmClose, 0, 0)
}

func (t *Tray) menu() {
	m, _, _ := procCreatePopupMenu.Call()
	add := func(flags uintptr, id int, text string) {
		p, _ := windows.UTF16PtrFromString(text)
		procAppendMenu.Call(m, flags, uintptr(id), uintptr(unsafe.Pointer(p)))
	}
	add(mfString, cmdOpen, "Открыть MRFS")
	if t.isConnected != nil && t.isConnected() {
		add(mfString, cmdDisconnect, "Отключить")
	} else {
		add(mfString, cmdConnect, "Подключить (лучший сервер)")
	}
	procAppendMenu.Call(m, mfSeparator, 0, 0)
	add(mfString, cmdQuit, "Выход")
	var pt struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForeground.Call(t.hwnd) // required so the menu closes when clicking elsewhere
	cmd, _, _ := procTrackPopupMenu.Call(m, tpmReturnCmd|tpmRightAlign, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	procPostMessage.Call(t.hwnd, wmNull, 0, 0)
	procDestroyMenu.Call(m)
	switch int(cmd) {
	case cmdOpen:
		t.Show()
	case cmdConnect:
		if t.onConnect != nil {
			t.onConnect()
		}
	case cmdDisconnect:
		if t.onDisconect != nil {
			t.onDisconect()
		}
	case cmdQuit:
		t.Quit()
	}
}

func trayWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	t := tray
	switch {
	case msg == wmClose:
		t.mu.Lock()
		q := t.quitting
		first := !t.hintShown
		t.hintShown = true
		t.mu.Unlock()
		if !q {
			procShowWindow.Call(hwnd, swHide)
			if first {
				go t.Balloon("MRFS работает в трее", "Окно свёрнуто, соединение не разорвано. Чтобы выйти — правой кнопкой по значку → Выход.")
			}
			return 0
		}
	case msg == wmTray:
		switch lp & 0xffff {
		case wmLButtonUp, wmLButtonDbl:
			t.Show()
		case wmRButtonUp:
			t.menu()
		}
		return 0
	case t.taskbarMsg != 0 && msg == t.taskbarMsg:
		// Explorer restarted — put the icon back
		procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))
	}
	r, _, _ := procCallWindowProc.Call(t.oldProc, hwnd, msg, wp, lp)
	return r
}

func windowVisible(hwnd uintptr) bool {
	r, _, _ := procIsWindowVisible.Call(hwnd)
	return r != 0
}
