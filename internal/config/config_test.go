package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bjhaid/corehole/internal/blocklist"
)

func TestDefaultEnablesBundledBlocking(t *testing.T) {
	cfg := Default()

	if !cfg.Blocking.Bundled {
		t.Fatal("default blocking.bundled = false, want true")
	}
}

func TestDefaultDNSListenUsesStandardPort(t *testing.T) {
	cfg := Default()

	if cfg.DNS.Listen != ":53" {
		t.Fatalf("default dns.listen = %q, want :53", cfg.DNS.Listen)
	}
	if cfg.DNS.CacheTTL != 30 {
		t.Fatalf("default dns.cache_ttl = %d, want 30", cfg.DNS.CacheTTL)
	}
	if cfg.DNS.CacheSuccessCapacity != 32768 {
		t.Fatalf("default dns.cache_success_capacity = %d, want 32768", cfg.DNS.CacheSuccessCapacity)
	}
	if cfg.DNS.CacheDenialCapacity != 4096 {
		t.Fatalf("default dns.cache_denial_capacity = %d, want 4096", cfg.DNS.CacheDenialCapacity)
	}
	if cfg.DNS.DNSSEC.Enabled {
		t.Fatal("default dns.dnssec.enabled = true, want false")
	}
	if cfg.DNS.DNSSEC.Mode != DNSSECModeOff {
		t.Fatalf("default dns.dnssec.mode = %q, want off", cfg.DNS.DNSSEC.Mode)
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
	cfg.DNS.CacheSuccessCapacity = 0
	cfg.DNS.CacheDenialCapacity = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
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
