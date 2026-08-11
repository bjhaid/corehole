package coredns

import (
	"strings"
	"testing"

	"github.com/bjhaid/corehole/internal/config"
)

func TestCorefileUsesCoreDNSZonePortSyntax(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Listen = ":1053"

	got := Corefile(cfg)
	if !strings.HasPrefix(got, ".:1053 {\n") {
		t.Fatalf("Corefile() prefix = %q", got)
	}
	if strings.Contains(got, ". :1053") {
		t.Fatalf("Corefile() contains invalid separated zone/listen syntax: %q", got)
	}
}

func TestCorefileUsesConfiguredCacheSettings(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.CacheSuccessTTL = 3600
	cfg.DNS.CacheDenialTTL = 30
	cfg.DNS.CacheSuccessCapacity = 65536
	cfg.DNS.CacheDenialCapacity = 4096
	cfg.DNS.CachePrefetchAmount = 7
	cfg.DNS.CachePrefetchDuration = 90
	cfg.DNS.CachePrefetchPercent = 20

	got := Corefile(cfg)
	want := "    cache {\n        success 65536 3600\n        denial 4096 30\n        prefetch 7 90s 20%\n    }\n"
	if !strings.Contains(got, want) {
		t.Fatalf("Corefile() = %q, want configured cache block %q", got, want)
	}
}

func TestCorefileOmitsCacheWhenTTLIsZero(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.CacheTTL = 0
	cfg.DNS.CacheSuccessTTL = 0
	cfg.DNS.CacheDenialTTL = 0

	got := Corefile(cfg)
	if strings.Contains(got, "    cache ") {
		t.Fatalf("Corefile() = %q, want cache directive omitted", got)
	}
}

func TestCorefileEnablesVerboseLoggingAtDebugLevel(t *testing.T) {
	cfg := config.Default()
	cfg.Logging.Level = config.LoggingLevelDebug

	got := Corefile(cfg)
	if !strings.Contains(got, "    log\n") {
		t.Fatalf("Corefile() = %q, want query log directive", got)
	}
	if !strings.Contains(got, "    errors {\n        stacktrace\n    }\n") {
		t.Fatalf("Corefile() = %q, want errors stacktrace block", got)
	}
}

func TestCorefileUsesJSONQueryLogFormatWhenConfigured(t *testing.T) {
	cfg := config.Default()
	cfg.Logging.Level = config.LoggingLevelDebug
	cfg.Logging.Format = config.LoggingFormatJSON

	got := Corefile(cfg)
	for _, want := range []string{
		`log . "{\"component\":\"coredns\"`,
		`\"msg\":\"dns_query\"`,
		`\"name\":\"{name}\"`,
		`\"rcode\":\"{rcode}\"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Corefile() = %q, want JSON query log fragment %q", got, want)
		}
	}
}

func TestCorefileUsesErrorLoggingWithoutQueryLogByDefault(t *testing.T) {
	cfg := config.Default()

	got := Corefile(cfg)
	if !strings.Contains(got, "    errors\n") {
		t.Fatalf("Corefile() = %q, want errors directive", got)
	}
	if strings.Contains(got, "    log\n") {
		t.Fatalf("Corefile() = %q, want query log omitted", got)
	}
	if strings.Contains(got, "stacktrace") {
		t.Fatalf("Corefile() = %q, want stacktrace omitted", got)
	}
}

func TestCorefileHonorsResolverProtocols(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Resolvers = []config.Resolver{{
		Name:          "quad9",
		Address:       "9.9.9.9:853",
		Protocol:      "tls",
		TLSServerName: "dns.quad9.net",
		Enabled:       true,
	}, {
		Name:     "cloudflare-doh",
		Address:  "1.1.1.1",
		Protocol: "https",
		Enabled:  true,
	}}

	got := Corefile(cfg)
	want := "    forward . tls://9.9.9.9%dns.quad9.net:853 https://1.1.1.1\n"
	if !strings.Contains(got, want) {
		t.Fatalf("Corefile() = %q, want %q", got, want)
	}
}

func TestCorefileHonorsTCPResolverProtocol(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Resolvers = []config.Resolver{{
		Name:     "tcp-upstream",
		Address:  "9.9.9.9:53",
		Protocol: "tcp",
		Enabled:  true,
	}}

	got := Corefile(cfg)
	want := "    forward . 9.9.9.9:53 {\n        force_tcp\n    }\n"
	if !strings.Contains(got, want) {
		t.Fatalf("Corefile() = %q, want %q", got, want)
	}
}

func TestCorefileReflectsUpdatedUpstreamResolvers(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Resolvers = []config.Resolver{{
		Name:     "disabled-default",
		Address:  "1.1.1.1:53",
		Protocol: "udp",
		Enabled:  false,
	}, {
		Name:     "quad9",
		Address:  "9.9.9.9:53",
		Protocol: "udp",
		Enabled:  true,
	}}

	got := Corefile(cfg)
	if !strings.Contains(got, "    forward . 9.9.9.9:53\n") {
		t.Fatalf("Corefile() = %q, want updated quad9 forward", got)
	}
	if strings.Contains(got, "1.1.1.1:53") {
		t.Fatalf("Corefile() = %q, want disabled default omitted", got)
	}
}

func TestCorefileAddsConditionalForwardingBeforeDefaultForward(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.ConditionalForwarding = config.ConditionalForwarding{
		Enabled:  true,
		Domain:   "lan",
		Resolver: "192.168.1.1:53",
	}

	got := Corefile(cfg)
	conditional := "    forward lan 192.168.1.1:53\n"
	defaultForward := "    forward . 1.1.1.1:53\n"
	if !strings.Contains(got, conditional) {
		t.Fatalf("Corefile() = %q, want conditional forwarding directive", got)
	}
	if strings.Index(got, conditional) > strings.Index(got, defaultForward) {
		t.Fatalf("Corefile() = %q, want conditional forwarding before default forward", got)
	}
}

func TestCorefileAddsRewriteRulesBeforeDefaultForward(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Rewrites = []config.RewriteRule{{
		Enabled:    true,
		Mode:       "stop",
		Field:      "name",
		Match:      "suffix",
		From:       ".home.arpa.",
		To:         ".lan.",
		AnswerMode: "auto",
	}, {
		Enabled: true,
		Mode:    "continue",
		Field:   "type",
		From:    "ANY",
		To:      "HINFO",
	}, {
		Enabled:   true,
		Mode:      "continue",
		Field:     "rcode",
		Match:     "regex",
		From:      "(.*)\\.example\\.",
		RCodeFrom: "SERVFAIL",
		RCodeTo:   "NOERROR",
	}, {
		Enabled: false,
		Field:   "name",
		From:    "disabled.example.",
		To:      "example.",
	}}

	got := Corefile(cfg)
	for _, want := range []string{
		"    rewrite stop name suffix .home.arpa. .lan. answer auto\n",
		"    rewrite continue type ANY HINFO\n",
		"    rewrite continue rcode regex (.*)\\.example\\. SERVFAIL NOERROR\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Corefile() = %q, want rewrite %q", got, want)
		}
		if strings.Index(got, want) > strings.Index(got, "    forward . 1.1.1.1:53\n") {
			t.Fatalf("Corefile() = %q, want rewrite before forward", got)
		}
	}
	if strings.Contains(got, "disabled.example") {
		t.Fatalf("Corefile() = %q, want disabled rewrite omitted", got)
	}
}

func TestCorefileOmitsDNSSECPluginByDefault(t *testing.T) {
	cfg := config.Default()

	got := Corefile(cfg)
	if strings.Contains(got, "corehole_dnssec") {
		t.Fatalf("Corefile() = %q, want upstream dnssec plugin omitted", got)
	}
	if strings.Contains(got, "    dnssec") {
		t.Fatalf("Corefile() = %q, must not use CoreDNS authoritative dnssec plugin", got)
	}
}

func TestCorefileEnablesDNSSECUpstreamModeBeforeForward(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.DNSSEC.Enabled = true
	cfg.DNS.DNSSEC.Mode = config.DNSSECModeUpstream

	got := Corefile(cfg)
	dnssecDirective := "    corehole_dnssec upstream\n"
	forwardDirective := "    forward . 1.1.1.1:53\n"
	if !strings.Contains(got, dnssecDirective) {
		t.Fatalf("Corefile() = %q, want upstream dnssec directive", got)
	}
	if strings.Contains(got, "    dnssec") {
		t.Fatalf("Corefile() = %q, must not use CoreDNS authoritative dnssec plugin", got)
	}
	if strings.Index(got, dnssecDirective) > strings.Index(got, forwardDirective) {
		t.Fatalf("Corefile() = %q, want upstream dnssec before default forward", got)
	}
}
