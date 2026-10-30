package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

// GeoIP: offline IP -> country lookup using Xray's bundled geoip.dat
// (protobuf: GeoIPList{ repeated GeoIP entry=1 }, GeoIP{ string country_code=1; repeated CIDR cidr=2 },
//  CIDR{ bytes ip=1; uint32 prefix=2 }).

type ipRange struct {
	start, end uint32
	cc         string
}

type GeoIP struct {
	once   sync.Once
	path   string
	ranges []ipRange
}

func varint(b []byte) (uint64, int) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return x, i + 1
		}
	}
	return 0, 0
}

// fields walks one protobuf message, calling fn for every length-delimited/varint field.
func fields(b []byte, fn func(num int, val []byte, v uint64)) error {
	for len(b) > 0 {
		key, n := varint(b)
		if n == 0 {
			return errors.New("bad varint")
		}
		b = b[n:]
		num, typ := int(key>>3), key&7
		switch typ {
		case 0:
			v, n := varint(b)
			if n == 0 {
				return errors.New("bad varint")
			}
			fn(num, nil, v)
			b = b[n:]
		case 2:
			l, n := varint(b)
			if n == 0 || int(l) > len(b)-n {
				return errors.New("bad length")
			}
			fn(num, b[n:n+int(l)], 0)
			b = b[n+int(l):]
		case 5:
			b = b[4:]
		case 1:
			b = b[8:]
		default:
			return errors.New("bad wire type")
		}
	}
	return nil
}

//go:embed geodata/geo4.bin.gz
var geo4gz []byte

// loadEmbedded reads the compact table built from v2fly/geoip (start u32, end u32, 2-letter code).
func (g *GeoIP) loadEmbedded() bool {
	zr, err := gzip.NewReader(bytes.NewReader(geo4gz))
	if err != nil {
		return false
	}
	data, err := io.ReadAll(zr)
	if err != nil || len(data)%10 != 0 {
		return false
	}
	rs := make([]ipRange, 0, len(data)/10)
	for i := 0; i < len(data); i += 10 {
		rs = append(rs, ipRange{binary.BigEndian.Uint32(data[i:]), binary.BigEndian.Uint32(data[i+4:]), string(data[i+8 : i+10])})
	}
	g.ranges = rs
	return len(rs) > 0
}

func (g *GeoIP) load() {
	if g.path == "" && g.loadEmbedded() {
		return
	}
	data, err := os.ReadFile(g.path)
	if err != nil {
		return
	}
	var rs []ipRange
	fields(data, func(num int, entry []byte, _ uint64) {
		if num != 1 {
			return
		}
		var cc string
		var cidrs [][]byte
		fields(entry, func(n int, v []byte, _ uint64) {
			switch n {
			case 1:
				cc = strings.ToUpper(string(v))
			case 2:
				cidrs = append(cidrs, v)
			}
		})
		if len(cc) != 2 { // skip special lists (private, cloudflare, google…)
			return
		}
		for _, c := range cidrs {
			var ip []byte
			var prefix uint64
			fields(c, func(n int, v []byte, x uint64) {
				if n == 1 {
					ip = v
				} else if n == 2 {
					prefix = x
				}
			})
			if len(ip) != 4 || prefix > 32 {
				continue
			}
			s := binary.BigEndian.Uint32(ip)
			mask := uint32(0)
			if prefix < 32 {
				mask = 0xffffffff >> prefix
			}
			s &^= mask
			rs = append(rs, ipRange{s, s | mask, cc})
		}
	})
	sort.Slice(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
	g.ranges = rs
}

// Country returns the ISO code for an IPv4 address ("" if unknown).
func (g *GeoIP) Country(ip net.IP) string {
	g.once.Do(g.load)
	v4 := ip.To4()
	if v4 == nil || len(g.ranges) == 0 {
		return ""
	}
	x := binary.BigEndian.Uint32(v4)
	i := sort.Search(len(g.ranges), func(i int) bool { return g.ranges[i].start > x }) - 1
	// ranges may nest (more specific inside larger) — scan back a little
	for k := i; k >= 0 && k > i-64; k-- {
		if r := g.ranges[k]; r.start <= x && x <= r.end {
			return r.cc
		}
	}
	return ""
}

// flagCountry extracts a country from a flag emoji in a config name (fallback only).
func flagCountry(name string) string {
	var cc []rune
	for _, r := range name {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			cc = append(cc, 'A'+(r-0x1F1E6))
			if len(cc) == 2 {
				return string(cc)
			}
		} else {
			cc = cc[:0]
		}
	}
	return ""
}
