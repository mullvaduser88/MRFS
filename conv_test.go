package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"testing"
)

func TestConv(t *testing.T) {
	src := os.Getenv("GEO_SRC")
	if src == "" {
		t.Skip()
	}
	g := &GeoIP{path: src}
	g.load()
	var m []ipRange
	for _, r := range g.ranges {
		if n := len(m); n > 0 && m[n-1].cc == r.cc && m[n-1].end+1 == r.start {
			m[n-1].end = r.end
			continue
		}
		m = append(m, r)
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, 9)
	b := make([]byte, 10)
	for _, r := range m {
		binary.BigEndian.PutUint32(b, r.start)
		binary.BigEndian.PutUint32(b[4:], r.end)
		copy(b[8:], r.cc)
		zw.Write(b)
	}
	zw.Close()
	os.WriteFile("geo4.bin.gz", buf.Bytes(), 0644)
	t.Log(len(g.ranges), len(m), buf.Len())
}
