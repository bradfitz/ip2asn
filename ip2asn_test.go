package ip2asn

import (
	"flag"
	"net/http"
	"strings"
	"testing"

	"inet.af/netaddr"
)

func TestParse(t *testing.T) {
	m, err := OpenReader(strings.NewReader(subset))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip   string
		want int
	}{
		{"1.0.64.0", 18144},
		{"1.0.65.0", 18144},
		{"1.0.127.255", 18144},
		{"1.0.17.1", 0},
		{"2c0f:ffc8:ffff:ffff:ffff:ffff:ffff:fffe", 22355},
	}
	for _, tt := range tests {
		ip, err := netaddr.ParseIP(tt.ip)
		if err != nil {
			t.Fatal(err)
		}
		got := m.ASofIP(ip)
		if got != tt.want {
			t.Errorf("%v = %v; want %v", tt.ip, got, tt.want)
		}
	}
}

const googASN = 15169

var testFull = flag.Bool("test-full-from-network", false, "download https://iptoasn.com/data/ip2asn-combined.tsv.gz and parse it")

func TestParseNetwork(t *testing.T) {
	if !*testFull {
		t.Skip("skipping without --test-full-from-network")
	}
	res, err := http.Get("https://iptoasn.com/data/ip2asn-combined.tsv.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	m, err := OpenReader(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	ip, _ := netaddr.ParseIP("8.8.8.8")
	got := m.ASofIP(ip)
	if got != googASN {
		t.Errorf("got %v; want %v", got, googASN)
	}
}

var testFile = flag.String("test-file", "", "optional file name to parse")

func TestParseFile(t *testing.T) {
	if *testFile == "" {
		t.Skip("skipping without --test-file")
	}
	m, err := OpenFile(*testFile)
	if err != nil {
		t.Fatal(err)
	}
	ip, _ := netaddr.ParseIP("8.8.8.8")
	got := m.ASofIP(ip)
	if got != googASN {
		t.Errorf("got %v; want %v", got, googASN)
	}
}

const subset = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET - Cloudflare, Inc.
1.0.1.0	1.0.3.255	0	None	Not routed
1.0.4.0	1.0.7.255	56203	AU	GTELECOM-AUSTRALIA Gtelecom-AUSTRALIA
1.0.8.0	1.0.15.255	0	None	Not routed
1.0.16.0	1.0.16.255	2519	JP	VECTANT ARTERIA Networks Corporation
1.0.17.0	1.0.63.255	0	None	Not routed
1.0.64.0	1.0.127.255	18144	JP	AS-ENECOM Energia Communications,Inc.
1.0.128.0	1.0.133.255	23969	TH	TOT-NET TOT Public Company Limited
1.0.134.0	1.0.194.255	23969	TH	TOT-NET TOT Public Company Limited
1.0.195.0	1.0.221.255	23969	TH	TOT-NET TOT Public Company Limited
1.0.222.0	1.0.255.255	23969	TH	TOT-NET TOT Public Company Limited
1.1.0.0	1.1.0.255	0	None	Not routed
1.1.1.0	1.1.1.0	13335	US	CLOUDFLARENET - Cloudflare, Inc.
1.1.1.1	1.1.1.1	7497	CN	CSTNET-AS-AP Computer Network Information Center
1.1.1.2	1.1.1.255	13335	US	CLOUDFLARENET - Cloudflare, Inc.
1.1.2.0	1.1.5.255	0	None	Not routed
1.1.6.0	1.1.6.255	138449	HK	SYUNET-AS-AP SIANG YU SCIENCE AND TECHNOLOGY LIMITED
1.1.7.0	1.1.7.255	0	None	Not routed
1.1.8.0	1.1.8.255	4134	CN	CHINANET-BACKBONE No.31,Jin-rong Street
1.1.9.0	1.1.19.255	0	None	Not routed
2c0f:ff30::	2c0f:ff30:ffff:ffff:ffff:ffff:ffff:ffff	37334	ZA	ARC
2c0f:ff31::	2c0f:ff3f:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:ff40::	2c0f:ff7f:ffff:ffff:ffff:ffff:ffff:ffff	10474	ZA	OPTINET
2c0f:ff80::	2c0f:ff80:ffff:ffff:ffff:ffff:ffff:ffff	327698	ZA	BInfraco
2c0f:ff81::	2c0f:ff8f:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:ff90::	2c0f:ff90:ffff:ffff:ffff:ffff:ffff:ffff	15808	KE	ACCESSKENYA-KE ACCESSKENYA GROUP LTD is an ISP serving
2c0f:ff91::	2c0f:ff9f:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:ffa0::	2c0f:ffa0:ffff:ffff:ffff:ffff:ffff:ffff	37273	UG	BCS
2c0f:ffa1::	2c0f:ffc7:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:ffc8::	2c0f:ffc8:ffff:ffff:ffff:ffff:ffff:ffff	22355	ZA	FROGFOOT
2c0f:ffc9::	2c0f:ffcf:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:ffd0::	2c0f:ffd0:ffff:ffff:ffff:ffff:ffff:ffff	36968	ZA	ECN-AS1
2c0f:ffd1::	2c0f:ffd7:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:ffd8::	2c0f:ffd8:ffff:ffff:ffff:ffff:ffff:ffff	33762	ZA	WBS
2c0f:ffd9::	2c0f:ffef:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
2c0f:fff0::	2c0f:fff0:ffff:ffff:ffff:ffff:ffff:ffff	37125	NG	Layer3-
2c0f:fff1::	fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
fe00::	febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
fec0::	ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe	0	None	Not routed
ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff	ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff	0	None	Not routed
`
