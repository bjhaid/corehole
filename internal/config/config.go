package config

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/bjhaid/corehole/internal/blocklist"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DNS      DNSConfig      `yaml:"dns" json:"dns"`
	Admin    AdminConfig    `yaml:"admin" json:"admin"`
	Storage  StorageConfig  `yaml:"storage" json:"storage"`
	Blocking BlockingConfig `yaml:"blocking" json:"blocking"`
}

type DNSConfig struct {
	Listen                string                `yaml:"listen" json:"listen"`
	Resolvers             []Resolver            `yaml:"resolvers" json:"resolvers"`
	CacheTTL              int                   `yaml:"cache_ttl" json:"cache_ttl"`
	DNSSEC                DNSSECConfig          `yaml:"dnssec" json:"dnssec"`
	ConditionalForwarding ConditionalForwarding `yaml:"conditional_forwarding" json:"conditional_forwarding"`
}

type DNSSECMode string

const (
	DNSSECModeOff      DNSSECMode = "off"
	DNSSECModeUpstream DNSSECMode = "upstream"
)

type DNSSECConfig struct {
	Enabled bool       `yaml:"enabled" json:"enabled"`
	Mode    DNSSECMode `yaml:"mode" json:"mode"`
}

type Resolver struct {
	Name          string `yaml:"name" json:"name"`
	Address       string `yaml:"address" json:"address"`
	Protocol      string `yaml:"protocol" json:"protocol"`
	TLSServerName string `yaml:"tls_server_name,omitempty" json:"tls_server_name,omitempty"`
	Enabled       bool   `yaml:"enabled" json:"enabled"`
}

type ConditionalForwarding struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	Domain        string `yaml:"domain" json:"domain"`
	Resolver      string `yaml:"resolver" json:"resolver"`
	Protocol      string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	TLSServerName string `yaml:"tls_server_name,omitempty" json:"tls_server_name,omitempty"`
}

type AdminConfig struct {
	Listen string `yaml:"listen" json:"listen"`
}

type StorageConfig struct {
	Path string `yaml:"path" json:"path"`
}

type BlockingConfig struct {
	Response   coreholedns.BlockingResponse `yaml:"response" json:"response"`
	Bundled    bool                         `yaml:"bundled" json:"bundled"`
	Paused     bool                         `yaml:"paused" json:"paused"`
	PauseUntil string                       `yaml:"pause_until,omitempty" json:"pause_until,omitempty"`
	Blocklists []string                     `yaml:"blocklists" json:"blocklists"`
}

func Default() Config {
	return Config{
		DNS: DNSConfig{
			CacheTTL: 30,
			Listen:   ":53",
			DNSSEC: DNSSECConfig{
				Enabled: false,
				Mode:    DNSSECModeOff,
			},
			Resolvers: []Resolver{{
				Name:     "cloudflare",
				Address:  "1.1.1.1:53",
				Protocol: "udp",
				Enabled:  true,
			}},
		},
		Admin: AdminConfig{
			Listen: "127.0.0.1:8080",
		},
		Storage: StorageConfig{
			Path: "corehole.db",
		},
		Blocking: BlockingConfig{
			Response: coreholedns.BlockingResponseNXDOMAIN,
			Bundled:  true,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		applyBlocklistRuntimeConfig(cfg)
		return cfg, nil
	}
	if err != nil {
		return Config{}, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	applyBlocklistRuntimeConfig(cfg)
	return cfg, nil
}

func applyBlocklistRuntimeConfig(cfg Config) {
	blocklist.SetBundledDefault(cfg.Blocking.Bundled)
}

func (c Config) Validate() error {
	if c.DNS.Listen == "" {
		return errors.New("dns.listen is required")
	}
	if c.Admin.Listen == "" {
		return errors.New("admin.listen is required")
	}
	if c.Storage.Path == "" {
		return errors.New("storage.path is required")
	}
	if c.DNS.CacheTTL < 0 {
		return errors.New("dns.cache_ttl must be 0 or greater")
	}
	if err := c.DNS.DNSSEC.Validate(); err != nil {
		return err
	}
	enabledResolver := false
	enabledTCPResolver := false
	enabledNonTCPResolver := false
	for _, resolver := range c.DNS.Resolvers {
		if resolver.Enabled {
			enabledResolver = true
			if resolver.Address == "" {
				return errors.New("enabled resolver address is required")
			}
			if !validCorefileToken(resolver.Address) {
				return errors.New("enabled resolver address must not contain whitespace or braces")
			}
			protocol := normalizedResolverProtocol(resolver.Protocol)
			if !supportedResolverProtocol(protocol) {
				return errors.New("enabled resolver protocol must be udp, tcp, tls, https, dns, or empty")
			}
			if protocol == "tcp" {
				enabledTCPResolver = true
			} else {
				enabledNonTCPResolver = true
			}
			if resolver.TLSServerName != "" && !validCorefileToken(resolver.TLSServerName) {
				return errors.New("resolver tls_server_name must not contain whitespace or braces")
			}
		}
	}
	if !enabledResolver {
		return errors.New("at least one resolver must be enabled")
	}
	if enabledTCPResolver && enabledNonTCPResolver {
		return errors.New("tcp resolvers cannot be mixed with udp, tls, https, dns, or empty-protocol resolvers")
	}
	if c.DNS.ConditionalForwarding.Enabled {
		if c.DNS.ConditionalForwarding.Domain == "" {
			return errors.New("dns.conditional_forwarding.domain is required when enabled")
		}
		if c.DNS.ConditionalForwarding.Resolver == "" {
			return errors.New("dns.conditional_forwarding.resolver is required when enabled")
		}
		if !validCorefileToken(c.DNS.ConditionalForwarding.Domain) {
			return errors.New("dns.conditional_forwarding.domain must not contain whitespace or braces")
		}
		if !validCorefileToken(c.DNS.ConditionalForwarding.Resolver) {
			return errors.New("dns.conditional_forwarding.resolver must not contain whitespace or braces")
		}
		protocol := normalizedResolverProtocol(c.DNS.ConditionalForwarding.Protocol)
		if !supportedResolverProtocol(protocol) {
			return errors.New("dns.conditional_forwarding.protocol must be udp, tcp, tls, https, dns, or empty")
		}
		if c.DNS.ConditionalForwarding.TLSServerName != "" && !validCorefileToken(c.DNS.ConditionalForwarding.TLSServerName) {
			return errors.New("dns.conditional_forwarding.tls_server_name must not contain whitespace or braces")
		}
	}
	if c.Blocking.Response == "" {
		return errors.New("blocking.response is required")
	}
	switch c.Blocking.Response {
	case coreholedns.BlockingResponseNXDOMAIN, coreholedns.BlockingResponseNullIP, coreholedns.BlockingResponseRefused:
	default:
		return errors.New("blocking.response must be nxdomain, null-ip, or refused")
	}
	if c.Blocking.PauseUntil != "" {
		if _, err := time.Parse(time.RFC3339Nano, c.Blocking.PauseUntil); err != nil {
			if _, err := time.Parse(time.RFC3339, c.Blocking.PauseUntil); err != nil {
				return errors.New("blocking.pause_until must be an RFC3339 timestamp")
			}
		}
	}
	return nil
}

func (d DNSSECConfig) Validate() error {
	mode := d.NormalizedMode()
	switch mode {
	case "", DNSSECModeOff, DNSSECModeUpstream:
	default:
		return errors.New("dns.dnssec.mode must be off, upstream, or empty")
	}
	if d.Enabled {
		if mode == DNSSECModeOff {
			return errors.New("dns.dnssec.mode must be upstream when dns.dnssec.enabled is true")
		}
		return nil
	}
	if mode == DNSSECModeUpstream {
		return errors.New("dns.dnssec.enabled must be true when dns.dnssec.mode is upstream")
	}
	return nil
}

func (d DNSSECConfig) EffectiveMode() DNSSECMode {
	if !d.Enabled {
		return DNSSECModeOff
	}
	mode := d.NormalizedMode()
	if mode == "" {
		return DNSSECModeUpstream
	}
	return mode
}

func (d DNSSECConfig) NormalizedMode() DNSSECMode {
	return DNSSECMode(strings.ToLower(strings.TrimSpace(string(d.Mode))))
}

func normalizedResolverProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func supportedResolverProtocol(protocol string) bool {
	switch protocol {
	case "", "udp", "tcp", "tls", "https", "dns":
		return true
	default:
		return false
	}
}

func validCorefileToken(value string) bool {
	return !strings.ContainsAny(value, " \t\r\n{}")
}
