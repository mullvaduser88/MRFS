//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const exeExt = ".exe"

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// ---- job object: helpers die together with MRFS, even if it crashes ----

var job windows.Handle

func init() {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(h)
		return
	}
	job = h
}

func attachToJob(cmd *exec.Cmd) {
	if job == 0 || cmd.Process == nil {
		return
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(ph)
	windows.AssignProcessToJobObject(job, ph)
}

// ---- system proxy (WinINet) ----

var (
	wininet            = windows.NewLazySystemDLL("wininet.dll")
	internetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

const internetKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func refreshProxy() {
	internetSetOptionW.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	internetSetOptionW.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

func setSystemProxy(hostport string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("ProxyServer", hostport); err != nil {
		return err
	}
	k.SetStringValue("ProxyOverride", "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>")
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	refreshProxy()
	return nil
}

func clearSystemProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	k.SetDWordValue("ProxyEnable", 0)
	refreshProxy()
	return nil
}
