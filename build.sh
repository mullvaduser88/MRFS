#!/bin/sh
# Сборка MRFS.exe (можно на Linux/macOS/Windows с Go 1.24+)
set -e
go install github.com/tc-hib/go-winres@latest
go-winres make --in winres/winres.json --arch amd64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-H windowsgui" -o MRFS.exe .
echo "Готово: MRFS.exe. Положите рядом папку core (xray, sing-box) — или программа скачает их сама."
