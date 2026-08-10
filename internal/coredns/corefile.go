package coredns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/bjhaid/corehole/internal/config"
)

func Corefile(cfg config.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s {\n", zoneAddress(cfg.DNS.Listen))
	b.WriteString("    errors\n")
	b.WriteString("    metadata\n")
	b.WriteString("    corehole\n")
	if cfg.DNS.CacheTTL > 0 {
		fmt.Fprintf(&b, "    cache %d {\n", cfg.DNS.CacheTTL)
		fmt.Fprintf(&b, "        success %d %d\n", cfg.DNS.CacheSuccessCapacity, cfg.DNS.CacheTTL)
		fmt.Fprintf(&b, "        denial %d %d\n", cfg.DNS.CacheDenialCapacity, cfg.DNS.CacheTTL)
		b.WriteString("    }\n")
	}
	if cfg.DNS.DNSSEC.EffectiveMode() == config.DNSSECModeUpstream {
		b.WriteString("    corehole_dnssec upstream\n")
	}
	if cfg.DNS.ConditionalForwarding.Enabled {
		writeForward(&b, cfg.DNS.ConditionalForwarding.Domain, []forwardResolver{{
			Address:       cfg.DNS.ConditionalForwarding.Resolver,
			Protocol:      cfg.DNS.ConditionalForwarding.Protocol,
			TLSServerName: cfg.DNS.ConditionalForwarding.TLSServerName,
			Enabled:       true,
		}})
	}
	writeForward(&b, ".", forwardResolversFromConfig(cfg.DNS.Resolvers))
	b.WriteString("}\n")
	return b.String()
}

type forwardResolver struct {
	Address       string
	Protocol      string
	TLSServerName string
	Enabled       bool
}

func forwardResolversFromConfig(resolvers []config.Resolver) []forwardResolver {
	forwardResolvers := make([]forwardResolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		forwardResolvers = append(forwardResolvers, forwardResolver{
			Address:       resolver.Address,
			Protocol:      resolver.Protocol,
			TLSServerName: resolver.TLSServerName,
			Enabled:       resolver.Enabled,
		})
	}
	return forwardResolvers
}

func writeForward(b *strings.Builder, from string, resolvers []forwardResolver) {
	b.WriteString("    forward ")
	b.WriteString(from)
	forceTCP := false
	for _, resolver := range resolvers {
		if !resolver.Enabled {
			continue
		}
		if resolverProtocol(resolver.Protocol) == "tcp" {
			forceTCP = true
		}
		fmt.Fprintf(b, " %s", resolverTarget(resolver))
	}
	if forceTCP {
		b.WriteString(" {\n")
		b.WriteString("        force_tcp\n")
		b.WriteString("    }\n")
		return
	}
	b.WriteString("\n")
}

func resolverTarget(resolver forwardResolver) string {
	if strings.Contains(resolver.Address, "://") {
		return resolver.Address
	}
	switch resolverProtocol(resolver.Protocol) {
	case "tls":
		return "tls://" + tlsTarget(resolver.Address, resolver.TLSServerName)
	case "https":
		return "https://" + resolver.Address
	case "dns":
		return "dns://" + resolver.Address
	default:
		return resolver.Address
	}
}

func resolverProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func tlsTarget(address string, serverName string) string {
	if serverName == "" || strings.Contains(address, "%") {
		return address
	}
	if strings.HasPrefix(address, "[") {
		closing := strings.Index(address, "]")
		if closing > 0 {
			return address[:closing] + "%" + serverName + address[closing:]
		}
	}
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		return net.JoinHostPort(host+"%"+serverName, port)
	}
	if addr, err := netip.ParseAddr(address); err == nil && addr.Is6() {
		return "[" + address + "%" + serverName + "]"
	}
	return address + "%" + serverName
}

func zoneAddress(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "." + listen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return ".:" + listen
	}
	if host == "" {
		return ".:" + port
	}
	return ".:" + port
}
