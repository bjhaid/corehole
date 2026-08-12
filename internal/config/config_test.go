package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bjhaid/corehole/internal/blocklist"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
)

func TestDefaultEnablesBundledBlocking(t *testing.T) {
	cfg := Default()

	if !cfg.Blocking.Bundled {
		t.Fatal("default blocking.bundled = false, want true")
	}
	if cfg.Blocking.Response != coreholedns.BlockingResponseNullIP {
		t.Fatalf("default blocking.response = %q, want null-ip", cfg.Blocking.Response)
	}
}

func TestDefaultDNSListenUsesStandardPort(t *testing.T) {
	cfg := Default()

	if cfg.DNS.Listen != ":53" {
		t.Fatalf("default dns.listen = %q, want :53", cfg.DNS.Listen)
	}
	if cfg.DNS.CacheSuccessTTL != 3600 {
		t.Fatalf("default dns.cache_success_ttl = %d, want 3600", cfg.DNS.CacheSuccessTTL)
	}
	if cfg.DNS.CacheDenialTTL != 30 {
		t.Fatalf("default dns.cache_denial_ttl = %d, want 30", cfg.DNS.CacheDenialTTL)
	}
	if cfg.DNS.CacheSuccessCapacity != 32768 {
		t.Fatalf("default dns.cache_success_capacity = %d, want 32768", cfg.DNS.CacheSuccessCapacity)
	}
	if cfg.DNS.CacheDenialCapacity != 4096 {
		t.Fatalf("default dns.cache_denial_capacity = %d, want 4096", cfg.DNS.CacheDenialCapacity)
	}
	if cfg.DNS.CachePrefetchAmount != 5 ||
		cfg.DNS.CachePrefetchDuration != 60 ||
		cfg.DNS.CachePrefetchPercent != 10 {
		t.Fatalf("default cache prefetch = %d/%d/%d, want 5/60/10", cfg.DNS.CachePrefetchAmount, cfg.DNS.CachePrefetchDuration, cfg.DNS.CachePrefetchPercent)
	}
	if cfg.DNS.DNSSEC.Enabled {
		t.Fatal("default dns.dnssec.enabled = true, want false")
	}
	if cfg.DNS.DNSSEC.Mode != DNSSECModeOff {
		t.Fatalf("default dns.dnssec.mode = %q, want off", cfg.DNS.DNSSEC.Mode)
	}
	if cfg.Logging.Level != LoggingLevelInfo {
		t.Fatalf("default logging.level = %q, want info", cfg.Logging.Level)
	}
	if cfg.Logging.Format != LoggingFormatText {
		t.Fatalf("default logging.format = %q, want text", cfg.Logging.Format)
	}
}

func TestLoadCanDisableBundledBlocking(t *testing.T) {
	t.Cleanup(func() {
		blocklist.SetBundledDefault(true)
	})

	path := filepath.Join(t.TempDir(), "corehole.yaml")
	if err := os.WriteFile(path, []byte(`
dns:
  listen: ":1053"
  resolvers:
    - name: cloudflare
      address: "1.1.1.1:53"
      protocol: udp
      enabled: true
admin:
  listen: "127.0.0.1:8080"
storage:
  path: "./corehole.db"
blocking:
  response: nxdomain
  bundled: false
  blocklists: []
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Blocking.Bundled {
		t.Fatal("blocking.bundled = true, want false")
	}
	if cfg.DNS.Listen != ":1053" {
		t.Fatalf("dns.listen = %q, want YAML override :1053", cfg.DNS.Listen)
	}
	if blocklist.BundledDefaultEnabled() {
		t.Fatal("blocklist bundled default = true, want false")
	}
}

func TestLoadMapsLegacyCacheTTLToSplitTTLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corehole.yaml")
	if err := os.WriteFile(path, []byte(`
dns:
  listen: ":1053"
  cache_ttl: 0
  cache_success_capacity: 0
  cache_denial_capacity: 0
  resolvers:
    - name: cloudflare
      address: "1.1.1.1:53"
      protocol: udp
      enabled: true
admin:
  listen: "127.0.0.1:8080"
storage:
  path: "./corehole.db"
blocking:
  response: nxdomain
  bundled: true
  blocklists: []
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DNS.CacheEnabled() {
		t.Fatalf("cache enabled = true, want legacy cache_ttl: 0 to disable cache: %#v", cfg.DNS)
	}
}

func TestValidateRejectsUnsupportedResolverProtocol(t *testing.T) {
	cfg := Default()
	cfg.DNS.Resolvers[0].Protocol = "quic"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want unsupported resolver protocol error")
	}
}

func TestValidateRejectsMixedTCPResolvers(t *testing.T) {
	cfg := Default()
	cfg.DNS.Resolvers = append(cfg.DNS.Resolvers, Resolver{
		Name:     "tcp-upstream",
		Address:  "9.9.9.9:53",
		Protocol: "tcp",
		Enabled:  true,
	})

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want mixed tcp resolver error")
	}
}

func TestValidateConditionalForwarding(t *testing.T) {
	cfg := Default()
	cfg.DNS.ConditionalForwarding.Enabled = true
	cfg.DNS.ConditionalForwarding.Domain = "lan"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want missing conditional resolver error")
	}

	cfg.DNS.ConditionalForwarding.Resolver = "192.168.1.1:53"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateAllowsZeroCacheTTL(t *testing.T) {
	cfg := Default()
	cfg.DNS.CacheTTL = 0
	cfg.DNS.CacheSuccessTTL = 0
	cfg.DNS.CacheDenialTTL = 0
	cfg.DNS.CacheSuccessCapacity = 0
	cfg.DNS.CacheDenialCapacity = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsCacheTTLAboveCoreDNSMax(t *testing.T) {
	cfg := Default()
	cfg.DNS.CacheSuccessTTL = MaxCacheSuccessTTL + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want high success ttl error")
	}

	cfg = Default()
	cfg.DNS.CacheDenialTTL = MaxCacheDenialTTL + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want high denial ttl error")
	}

	cfg = Default()
	cfg.DNS.CacheSuccessTTL = 0
	cfg.DNS.CacheDenialTTL = 0
	cfg.DNS.CacheTTL = MaxCacheDenialTTL + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want high legacy ttl error")
	}
}

func TestValidateRejectsUnsupportedCachePrefetch(t *testing.T) {
	cfg := Default()
	cfg.DNS.CachePrefetchAmount = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want negative prefetch amount error")
	}

	cfg = Default()
	cfg.DNS.CachePrefetchPercent = 101
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want high prefetch percent error")
	}
}

func TestValidateRejectsTooSmallCacheCapacity(t *testing.T) {
	cfg := Default()
	cfg.DNS.CacheSuccessCapacity = 512

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want small success cache capacity error")
	}

	cfg = Default()
	cfg.DNS.CacheDenialCapacity = 512
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want small denial cache capacity error")
	}
}

func TestValidateRewriteRules(t *testing.T) {
	cfg := Default()
	cfg.DNS.Rewrites = []RewriteRule{{
		Enabled:    true,
		Mode:       "stop",
		Field:      "name",
		Match:      "regex",
		From:       "(.*)\\.home\\.arpa\\.",
		To:         "{1}.lan.",
		AnswerMode: "auto",
	}, {
		Enabled: true,
		Mode:    "continue",
		Field:   "type",
		From:    "ANY",
		To:      "HINFO",
	}, {
		Enabled: true,
		Mode:    "continue",
		Field:   "ttl",
		Match:   "suffix",
		From:    ".example.",
		To:      "30-300",
	}, {
		Enabled:   true,
		Mode:      "continue",
		Field:     "rcode",
		Match:     "suffix",
		From:      ".example.",
		RCodeFrom: "SERVFAIL",
		RCodeTo:   "NOERROR",
	}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateRejectsInvalidRewriteRules(t *testing.T) {
	tests := []struct {
		name string
		rule RewriteRule
	}{
		{name: "unsupported field", rule: RewriteRule{Enabled: true, Field: "edns0", From: "x", To: "y"}},
		{name: "bad regex", rule: RewriteRule{Enabled: true, Field: "name", Match: "regex", From: "(", To: "example."}},
		{name: "bad type", rule: RewriteRule{Enabled: true, Field: "type", From: "BOGUS", To: "A"}},
		{name: "bad ttl", rule: RewriteRule{Enabled: true, Field: "ttl", Match: "exact", From: "example.", To: "300-30"}},
		{name: "bad rcode", rule: RewriteRule{Enabled: true, Field: "rcode", Match: "exact", From: "example.", RCodeFrom: "BOGUS", RCodeTo: "NOERROR"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.DNS.Rewrites = []RewriteRule{tt.rule}
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want rewrite validation error")
			}
		})
	}
}

func TestValidateRejectsUnsupportedLoggingConfig(t *testing.T) {
	cfg := Default()
	cfg.Logging.Level = "trace"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want unsupported logging level error")
	}

	cfg = Default()
	cfg.Logging.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want unsupported logging format error")
	}
}

func TestValidateDNSSECUpstreamMode(t *testing.T) {
	cfg := Default()
	cfg.DNS.DNSSEC.Enabled = true
	cfg.DNS.DNSSEC.Mode = DNSSECModeUpstream

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if got := cfg.DNS.DNSSEC.EffectiveMode(); got != DNSSECModeUpstream {
		t.Fatalf("EffectiveMode() = %q, want upstream", got)
	}
}

func TestValidateDNSSECDefaultsEnabledModeToUpstream(t *testing.T) {
	cfg := Default()
	cfg.DNS.DNSSEC.Enabled = true
	cfg.DNS.DNSSEC.Mode = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if got := cfg.DNS.DNSSEC.EffectiveMode(); got != DNSSECModeUpstream {
		t.Fatalf("EffectiveMode() = %q, want upstream", got)
	}
}

func TestValidateRejectsUnsupportedDNSSECMode(t *testing.T) {
	cfg := Default()
	cfg.DNS.DNSSEC.Enabled = true
	cfg.DNS.DNSSEC.Mode = "local"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want unsupported dnssec mode error")
	}
}

func TestValidateRejectsContradictoryDNSSECConfig(t *testing.T) {
	cfg := Default()
	cfg.DNS.DNSSEC.Enabled = false
	cfg.DNS.DNSSEC.Mode = DNSSECModeUpstream

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want contradictory dnssec config error")
	}
}
