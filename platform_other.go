//go:build !windows

package main

import "os/exec"

const exeExt = ""

func hideWindow(cmd *exec.Cmd)             {}
func setSystemProxy(hostport string) error { return nil }
func clearSystemProxy() error              { return nil }
func isAdmin() bool                        { return true }
func attachToJob(cmd *exec.Cmd)            {}
