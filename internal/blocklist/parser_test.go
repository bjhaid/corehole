package blocklist

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPlainParserParse(t *testing.T) {
	input := `
# comment
Bad.Example.
0.0.0.0 ads.example tracker.example # inline comment
:: ipv6.example
*.Suffix.Example.
bad_domain.example
bad example
192.0.2.1
`

	got, err := NewParser().Parse(context.Background(), strings.NewReader(input), "test-source")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []Entry{
		{Domain: "bad.example", Kind: EntryExact, Source: "test-source"},
		{Domain: "ads.example", Kind: EntryExact, Source: "test-source"},
		{Domain: "tracker.example", Kind: EntryExact, Source: "test-source"},
		{Domain: "ipv6.example", Kind: EntryExact, Source: "test-source"},
		{Domain: "suffix.example", Kind: EntrySuffix, Source: "test-source"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPlainParserParseStevenBlackHostsSample(t *testing.T) {
	input, err := os.ReadFile("testdata/stevenblack_hosts_sample.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	got, err := NewParser().Parse(context.Background(), strings.NewReader(string(input)), "stevenblack-sample")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	domains := make(map[string]Entry)
	for _, entry := range got {
		domains[entry.Domain] = entry
	}

	for _, domain := range []string{
		"ad-assets.futurecdn.net",
		"ck.getcookiestxt.com",
		"webmail-who-int.000webhostapp.com",
		"ns6.0pendns.org",
		"www.analytics.247sports.com",
		"multi-one.example",
		"multi-two.example",
		"crlf-one.example",
		"scoped-ipv6.example",
	} {
		entry, ok := domains[domain]
		if !ok {
			t.Fatalf("expected parsed domain %q in %#v", domain, got)
		}
		if entry.Kind != EntryExact || entry.Source != "stevenblack-sample" {
			t.Fatalf("entry for %q = %#v, want exact entry from fixture source", domain, entry)
		}
	}

	for _, domain := range []string{
		"localhost",
		"localhost.localdomain",
		"local",
		"broadcasthost",
		"ip6-localhost",
		"ip6-loopback",
		"ip6-localnet",
		"0.0.0.0",
		"bad_domain.example",
		"bad..example",
		"-bad.example",
	} {
		if _, ok := domains[domain]; ok {
			t.Fatalf("unexpected parsed domain %q in %#v", domain, got)
		}
	}
}

func TestPlainParserParseCRLFHostsFile(t *testing.T) {
	input := "0.0.0.0 crlf-one.example\r\n0.0.0.0\tcrlf-two.example  crlf-three.example # inline\r\n\r\n"

	got, err := NewParser().Parse(context.Background(), strings.NewReader(input), "crlf-source")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []Entry{
		{Domain: "crlf-one.example", Kind: EntryExact, Source: "crlf-source"},
		{Domain: "crlf-two.example", Kind: EntryExact, Source: "crlf-source"},
		{Domain: "crlf-three.example", Kind: EntryExact, Source: "crlf-source"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeEntryDomain(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantDomain string
		wantKind   EntryKind
		wantOK     bool
	}{
		{name: "lowercase and trailing dot", raw: "Example.COM.", wantDomain: "example.com", wantKind: EntryExact, wantOK: true},
		{name: "wildcard suffix", raw: "*.Example.COM.", wantDomain: "example.com", wantKind: EntrySuffix, wantOK: true},
		{name: "empty", raw: "   ", wantOK: false},
		{name: "empty wildcard", raw: "*.", wantOK: false},
		{name: "underscore", raw: "bad_domain.example", wantOK: false},
		{name: "slash", raw: "bad.example/path", wantOK: false},
		{name: "empty label", raw: "bad..example", wantOK: false},
		{name: "leading hyphen", raw: "-bad.example", wantOK: false},
		{name: "ip literal", raw: "192.0.2.1", wantOK: false},
		{name: "localhost alias", raw: "localhost", wantOK: false},
		{name: "localhost localdomain alias", raw: "localhost.localdomain", wantOK: false},
		{name: "broadcast alias", raw: "broadcasthost", wantOK: false},
		{name: "ipv6 local alias", raw: "ip6-localhost", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDomain, gotKind, gotOK := normalizeEntryDomain(tt.raw)
			if gotOK != tt.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tt.wantOK)
			}
			if !gotOK {
				return
			}
			if gotDomain != tt.wantDomain || gotKind != tt.wantKind {
				t.Fatalf("normalizeEntryDomain(%q) = (%q, %q), want (%q, %q)", tt.raw, gotDomain, gotKind, tt.wantDomain, tt.wantKind)
			}
		})
	}
}
