// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ip2asn parses the export files from iptoasn.com.
package ip2asn

/*
TODO: identify various Cloud-specific ranges?

AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
GCP: see https://gist.github.com/n0531m/f3714f6ad6ef738a3b0a, basically:

    $ dig txt _cloud-netblocks.googleusercontent.com +short | tr " " "\n" | grep include | cut -f 2 -d :
    _cloud-netblocks1.googleusercontent.com
    _cloud-netblocks2.googleusercontent.com
    ...
    $ dig txt _cloud-netblocks1.googleusercontent.com +short
    "v=spf1 include:_cloud-netblocks6.googleusercontent.com include:_cloud-netblocks7.googleusercontent.com ip6:2600:1900::/35 ip4:8.34.208.0/20 ip4:8.35.192.0/21 ip4:8.35.200.0/23 ip4:23.236.48.0/20 ip4:23.251.128.0/19 ip4:34.64.0.0/11 ip4:34.96.0.0/14 ?all"
    ...

*/

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"

	"go4.org/mem"
)

type Map struct {
	asName    map[int]string
	asCountry map[int]string
	recs      []rec
}

type rec struct {
	startIP, endIP netip.Addr
	asn            int
}

func OpenFile(filename string) (*Map, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return OpenReader(f)
}

func OpenReader(r io.Reader) (*Map, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err != nil {
		return nil, err
	}
	if string(magic) == "\x1f\x8b" {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		br = bufio.NewReader(zr)
	}
	m := &Map{
		asName:    map[int]string{},
		asCountry: map[int]string{},
	}
	for {
		line, err := br.ReadSlice('\n')
		if err == io.EOF {
			return m, nil
		}
		if err != nil {
			return nil, err
		}
		var startIPB, endIPB, asnB, country, desc []byte
		if err := parseTSV(line, &startIPB, &endIPB, &asnB, &country, &desc); err != nil {
			return nil, err
		}
		if string(desc) == "Not routed" {
			continue
		}
		as64, err := mem.ParseInt(mem.B(asnB), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bogus ASN %q for line %q", asnB, line)
		}
		as := int(as64)
		if _, ok := m.asName[as]; !ok {
			m.asName[as] = string(desc)
			m.asCountry[as] = string(country)
		}

		startIP, err := netip.ParseAddr(string(startIPB)) // TODO: add ParseIPBytes
		if err != nil {
			return nil, fmt.Errorf("bogus IP %q for line %q", startIPB, line)
		}
		endIP, err := netip.ParseAddr(string(endIPB)) // TODO: add ParseIPBytes
		if err != nil {
			return nil, fmt.Errorf("bogus IP %q for line %q", endIPB, line)
		}
		m.recs = append(m.recs, rec{startIP, endIP, as})
	}
}

func parseTSV(line []byte, dsts ...*[]byte) error {
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	for i, dst := range dsts {
		last := i == len(dsts)-1
		tab := bytes.IndexByte(line, '\t')
		if tab == -1 && !last {
			return fmt.Errorf("short line: %q", line)
		}
		if tab != -1 {
			*dst, line = line[:tab], line[tab+1:]
		} else {
			*dst = line
		}
	}
	return nil
}

func (m *Map) ASName(as int) string    { return m.asName[as] }
func (m *Map) ASCountry(as int) string { return m.asCountry[as] }

// ASofIP returns 0 on unknown.
func (m *Map) ASofIP(ip netip.Addr) int {
	cand := sort.Search(len(m.recs), func(i int) bool {
		return ip.Less(m.recs[i].startIP)
	})
	return m.recIndexHasIP(cand-1, ip)
}

// recIndexHasIP returns the AS number of m.rec[i] if i is in range and
// the record contains the given IP address.
func (m *Map) recIndexHasIP(i int, ip netip.Addr) (as int) {
	if i < 0 {
		return 0
	}
	rec := &m.recs[i]
	if rec.endIP.Less(ip) {
		return 0
	}
	if ip.Less(rec.startIP) {
		return 0
	}
	return rec.asn
}
