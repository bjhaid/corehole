package config

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bjhaid/corehole/internal/blocklist"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DNS      DNSConfig      `yaml:"dns" json:"dns"`
	Admin    AdminConfig    `yaml:"admin" json:"admin"`
	Storage  StorageConfig  `yaml:"storage" json:"storage"`
	Blocking BlockingConfig `yaml:"blocking" json:"blocking"`
	Logging  LoggingConfig  `yaml:"logging" json:"logging"`
}

type DNSConfig struct {
	Listen                string                `yaml:"listen" json:"listen"`
	Resolvers             []Resolver            `yaml:"resolvers" json:"resolvers"`
	CacheTTL              int                   `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`
	CacheSuccessTTL       int                   `yaml:"cache_success_ttl" json:"cache_success_ttl"`
	CacheDenialTTL        int                   `yaml:"cache_denial_ttl" json:"cache_denial_ttl"`
	CacheSuccessCapacity  int                   `yaml:"cache_success_capacity" json:"cache_success_capacity"`
	CacheDenialCapacity   int                   `yaml:"cache_denial_capacity" json:"cache_denial_capacity"`
	CachePrefetchAmount   int                   `yaml:"cache_prefetch_amount" json:"cache_prefetch_amount"`
	CachePrefetchDuration int                   `yaml:"cache_prefetch_duration" json:"cache_prefetch_duration"`
	CachePrefetchPercent  int                   `yaml:"cache_prefetch_percent" json:"cache_prefetch_percent"`
	DNSSEC                DNSSECConfig          `yaml:"dnssec" json:"dnssec"`
	ConditionalForwarding ConditionalForwarding `yaml:"conditional_forwarding" json:"conditional_forwarding"`
	Rewrites              []RewriteRule         `yaml:"rewrites" json:"rewrites"`
}

type RewriteRule struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Mode       string `yaml:"mode" json:"mode"`
	Field      string `yaml:"field" json:"field"`
	Match      string `yaml:"match,omitempty" json:"match,omitempty"`
	From       string `yaml:"from" json:"from"`
	To         string `yaml:"to,omitempty" json:"to,omitempty"`
	RCodeFrom  string `yaml:"rcode_from,omitempty" json:"rcode_from,omitempty"`
	RCodeTo    string `yaml:"rcode_to,omitempty" json:"rcode_to,omitempty"`
	AnswerMode string `yaml:"answer_mode,omitempty" json:"answer_mode,omitempty"`
	AnswerFrom string `yaml:"answer_from,omitempty" json:"answer_from,omitempty"`
	AnswerTo   string `yaml:"answer_to,omitempty" json:"answer_to,omitempty"`
	Comment    string `yaml:"comment,omitempty" json:"comment,omitempty"`
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

type LoggingLevel string

const (
	LoggingLevelDebug LoggingLevel = "debug"
	LoggingLevelInfo  LoggingLevel = "info"
	LoggingLevelWarn  LoggingLevel = "warn"
	LoggingLevelError LoggingLevel = "error"
)

type LoggingFormat string

const (
	LoggingFormatText LoggingFormat = "text"
	LoggingFormatJSON LoggingFormat = "json"
)

type LoggingConfig struct {
	Level  LoggingLevel  `yaml:"level" json:"level"`
	Format LoggingFormat `yaml:"format" json:"format"`
}

func Default() Config {
	return Config{
		DNS: DNSConfig{
			CacheSuccessTTL:       MaxCacheSuccessTTL,
			CacheDenialTTL:        DefaultCacheDenialTTL,
			CacheSuccessCapacity:  32768,
			CacheDenialCapacity:   4096,
			CachePrefetchAmount:   5,
			CachePrefetchDuration: 60,
			CachePrefetchPercent:  10,
			Listen:                ":53",
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
			Response: coreholedns.BlockingResponseNullIP,
			Bundled:  true,
		},
		Logging: LoggingConfig{
			Level:  LoggingLevelInfo,
			Format: LoggingFormatText,
		},
	}
}

const (
	MaxCacheSuccessTTL      = 3600
	MaxCacheDenialTTL       = 1800
	DefaultCacheDenialTTL   = 30
	MinCacheCapacity        = 1024
	MaxCachePrefetchPercent = 100
)

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
	normalizeLegacyCacheConfig(&cfg, b)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	applyBlocklistRuntimeConfig(cfg)
	return cfg, nil
}

func applyBlocklistRuntimeConfig(cfg Config) {
	blocklist.SetBundledDefault(cfg.Blocking.Bundled)
}

func normalizeLegacyCacheConfig(cfg *Config, payload []byte) {
	if cfg == nil ||
		!bytes.Contains(payload, []byte("cache_ttl")) ||
		bytes.Contains(payload, []byte("cache_success_ttl")) ||
		bytes.Contains(payload, []byte("cache_denial_ttl")) {
		return
	}
	cfg.DNS.CacheSuccessTTL = cfg.DNS.CacheTTL
	cfg.DNS.CacheDenialTTL = cfg.DNS.CacheTTL
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
	if !supportedLoggingLevel(c.Logging.Level) {
		return errors.New("logging.level must be debug, info, warn, warning, error, or empty")
	}
	if !supportedLoggingFormat(c.Logging.Format) {
		return errors.New("logging.format must be text, json, or empty")
	}
	if c.DNS.CacheTTL < 0 {
		return errors.New("dns.cache_ttl must be 0 or greater")
	}
	if c.DNS.CacheTTL > MaxCacheDenialTTL {
		return errors.New("dns.cache_ttl must be 1800 or less")
	}
	if c.DNS.EffectiveCacheSuccessTTL() < 0 {
		return errors.New("dns.cache_success_ttl must be 0 or greater")
	}
	if c.DNS.EffectiveCacheDenialTTL() < 0 {
		return errors.New("dns.cache_denial_ttl must be 0 or greater")
	}
	if c.DNS.EffectiveCacheSuccessTTL() > MaxCacheSuccessTTL {
		return errors.New("dns.cache_success_ttl must be 3600 or less")
	}
	if c.DNS.EffectiveCacheDenialTTL() > MaxCacheDenialTTL {
		return errors.New("dns.cache_denial_ttl must be 1800 or less")
	}
	if c.DNS.CachePrefetchAmount < 0 {
		return errors.New("dns.cache_prefetch_amount must be 0 or greater")
	}
	if c.DNS.CachePrefetchDuration < 0 {
		return errors.New("dns.cache_prefetch_duration must be 0 or greater")
	}
	if c.DNS.CachePrefetchPercent < 0 || c.DNS.CachePrefetchPercent > MaxCachePrefetchPercent {
		return errors.New("dns.cache_prefetch_percent must be between 0 and 100")
	}
	if c.DNS.CacheEnabled() {
		if c.DNS.EffectiveCacheSuccessTTL() == 0 {
			return errors.New("dns.cache_success_ttl must be greater than 0 when cache is enabled")
		}
		if c.DNS.EffectiveCacheDenialTTL() == 0 {
			return errors.New("dns.cache_denial_ttl must be greater than 0 when cache is enabled")
		}
		if c.DNS.CacheSuccessCapacity < MinCacheCapacity {
			return errors.New("dns.cache_success_capacity must be at least 1024 when cache is enabled")
		}
		if c.DNS.CacheDenialCapacity < MinCacheCapacity {
			return errors.New("dns.cache_denial_capacity must be at least 1024 when cache is enabled")
		}
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
	for _, rewrite := range c.DNS.Rewrites {
		if err := rewrite.Validate(); err != nil {
			return err
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

func (r RewriteRule) Validate() error {
	if !r.Enabled {
		return nil
	}
	if !supportedRewriteMode(r.EffectiveMode()) {
		return errors.New("dns.rewrites[].mode must be stop, continue, or empty")
	}
	field := strings.ToLower(strings.TrimSpace(r.Field))
	switch field {
	case "name":
		return r.validateNameRewrite()
	case "type":
		return r.validateTypeRewrite()
	case "ttl":
		return r.validateTTLRewrite()
	case "rcode":
		return r.validateRCodeRewrite()
	default:
		return errors.New("dns.rewrites[].field must be name, type, ttl, or rcode")
	}
}

func (r RewriteRule) EffectiveMode() string {
	mode := strings.ToLower(strings.TrimSpace(r.Mode))
	if mode == "" {
		return "stop"
	}
	return mode
}

func (r RewriteRule) EffectiveMatch() string {
	match := strings.ToLower(strings.TrimSpace(r.Match))
	if match == "" {
		return "exact"
	}
	return match
}

func (r RewriteRule) validateNameRewrite() error {
	if err := validateRewriteMatch(r.EffectiveMatch()); err != nil {
		return err
	}
	if err := validateRewriteToken("dns.rewrites[].from", r.From); err != nil {
		return err
	}
	if err := validateRewriteToken("dns.rewrites[].to", r.To); err != nil {
		return err
	}
	if err := validateRewriteRegex(r.EffectiveMatch(), r.From); err != nil {
		return err
	}
	answerMode := strings.ToLower(strings.TrimSpace(r.AnswerMode))
	switch answerMode {
	case "", "none":
		return nil
	case "auto":
		return nil
	case "name", "value":
		if err := validateRewriteToken("dns.rewrites[].answer_from", r.AnswerFrom); err != nil {
			return err
		}
		if err := validateRewriteToken("dns.rewrites[].answer_to", r.AnswerTo); err != nil {
			return err
		}
		return validateRewriteRegex("regex", r.AnswerFrom)
	default:
		return errors.New("dns.rewrites[].answer_mode must be none, auto, name, or value")
	}
}

func (r RewriteRule) validateTypeRewrite() error {
	if _, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(r.From))]; !ok {
		return errors.New("dns.rewrites[].from must be a DNS record type for type rewrites")
	}
	if _, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(r.To))]; !ok {
		return errors.New("dns.rewrites[].to must be a DNS record type for type rewrites")
	}
	return nil
}

func (r RewriteRule) validateTTLRewrite() error {
	if err := validateRewriteMatch(r.EffectiveMatch()); err != nil {
		return err
	}
	if err := validateRewriteToken("dns.rewrites[].from", r.From); err != nil {
		return err
	}
	if err := validateRewriteRegex(r.EffectiveMatch(), r.From); err != nil {
		return err
	}
	if !validTTLRewriteValue(strings.TrimSpace(r.To)) {
		return errors.New("dns.rewrites[].to must be TTL seconds or a MIN-MAX TTL range for ttl rewrites")
	}
	return nil
}

func (r RewriteRule) validateRCodeRewrite() error {
	if err := validateRewriteMatch(r.EffectiveMatch()); err != nil {
		return err
	}
	if err := validateRewriteToken("dns.rewrites[].from", r.From); err != nil {
		return err
	}
	if err := validateRewriteRegex(r.EffectiveMatch(), r.From); err != nil {
		return err
	}
	if !validRCodeRewriteValue(r.RCodeFrom) {
		return errors.New("dns.rewrites[].rcode_from must be a supported DNS RCODE")
	}
	if !validRCodeRewriteValue(r.RCodeTo) {
		return errors.New("dns.rewrites[].rcode_to must be a supported DNS RCODE")
	}
	return nil
}

func supportedRewriteMode(mode string) bool {
	return mode == "stop" || mode == "continue"
}

func validateRewriteMatch(match string) error {
	switch match {
	case "exact", "prefix", "suffix", "substring", "regex":
		return nil
	default:
		return errors.New("dns.rewrites[].match must be exact, prefix, suffix, substring, regex, or empty")
	}
}

func validateRewriteRegex(match string, pattern string) error {
	if match != "regex" {
		return nil
	}
	if len(pattern) > 10000 {
		return errors.New("dns.rewrites[].from regex must be 10000 characters or fewer")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return errors.New("dns.rewrites[].from regex must compile")
	}
	return nil
}

func validateRewriteToken(field string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New(field + " is required")
	}
	if value == "{" || value == "}" {
		return errors.New(field + " must not be a Corefile block delimiter")
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return errors.New(field + " must not contain whitespace")
		}
	}
	return nil
}

func validTTLRewriteValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) == 1 {
		return validTTLNumber(parts[0])
	}
	if len(parts) != 2 || (parts[0] == "" && parts[1] == "") {
		return false
	}
	if parts[0] != "" && !validTTLNumber(parts[0]) {
		return false
	}
	if parts[1] != "" && !validTTLNumber(parts[1]) {
		return false
	}
	if parts[0] != "" && parts[1] != "" && mustAtoi(parts[0]) > mustAtoi(parts[1]) {
		return false
	}
	return true
}

func validTTLNumber(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func mustAtoi(value string) int {
	n := 0
	for _, r := range value {
		n = n*10 + int(r-'0')
	}
	return n
}

func validRCodeRewriteValue(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	if _, ok := dns.StringToRcode[value]; ok {
		return true
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	code := mustAtoi(value)
	_, ok := dns.RcodeToString[code]
	return ok
}

func (c DNSConfig) CacheEnabled() bool {
	return c.EffectiveCacheSuccessTTL() > 0 || c.EffectiveCacheDenialTTL() > 0
}

func (c DNSConfig) EffectiveCacheSuccessTTL() int {
	if c.CacheSuccessTTL > 0 || c.CacheDenialTTL > 0 {
		return c.CacheSuccessTTL
	}
	return c.CacheTTL
}

func (c DNSConfig) EffectiveCacheDenialTTL() int {
	if c.CacheSuccessTTL > 0 || c.CacheDenialTTL > 0 {
		return c.CacheDenialTTL
	}
	return c.CacheTTL
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

func (l LoggingConfig) EffectiveLevel() LoggingLevel {
	switch strings.ToLower(strings.TrimSpace(string(l.Level))) {
	case string(LoggingLevelDebug):
		return LoggingLevelDebug
	case string(LoggingLevelWarn), "warning":
		return LoggingLevelWarn
	case string(LoggingLevelError):
		return LoggingLevelError
	default:
		return LoggingLevelInfo
	}
}

func (l LoggingConfig) EffectiveFormat() LoggingFormat {
	switch strings.ToLower(strings.TrimSpace(string(l.Format))) {
	case string(LoggingFormatJSON):
		return LoggingFormatJSON
	default:
		return LoggingFormatText
	}
}

func (d DNSSECConfig) NormalizedMode() DNSSECMode {
	return DNSSECMode(strings.ToLower(strings.TrimSpace(string(d.Mode))))
}

func supportedLoggingLevel(level LoggingLevel) bool {
	switch strings.ToLower(strings.TrimSpace(string(level))) {
	case "", string(LoggingLevelDebug), string(LoggingLevelInfo), string(LoggingLevelWarn), "warning", string(LoggingLevelError):
		return true
	default:
		return false
	}
}

func supportedLoggingFormat(format LoggingFormat) bool {
	switch strings.ToLower(strings.TrimSpace(string(format))) {
	case "", string(LoggingFormatText), string(LoggingFormatJSON):
		return true
	default:
		return false
	}
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
