package blocklist

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"strings"
)

type PlainParser struct{}

func NewParser() Parser {
	return PlainParser{}
}

func (PlainParser) Parse(ctx context.Context, r io.Reader, source string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries = append(entries, parseLine(scanner.Text(), source)...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseLine(line string, source string) []Entry {
	if beforeComment, _, ok := strings.Cut(line, "#"); ok {
		line = beforeComment
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}

	start := 0
	if isHostsAddress(fields[0]) {
		start = 1
	}
	if start >= len(fields) {
		return nil
	}
	if start == 0 && len(fields) != 1 {
		return nil
	}

	entries := make([]Entry, 0, len(fields)-start)
	for _, field := range fields[start:] {
		domain, kind, ok := normalizeEntryDomain(field)
		if !ok {
			continue
		}
		entries = append(entries, Entry{
			Domain: domain,
			Kind:   kind,
			Source: source,
		})
	}
	return entries
}

func normalizeEntryDomain(raw string) (string, EntryKind, bool) {
	domain := normalizeDomainText(raw)
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
		if !validBlocklistDomain(domain) {
			return "", "", false
		}
		return domain, EntrySuffix, true
	}
	if !validBlocklistDomain(domain) {
		return "", "", false
	}
	return domain, EntryExact, true
}

func normalizeDomain(raw string) (string, bool) {
	domain := normalizeDomainText(raw)
	if !validDomain(domain) {
		return "", false
	}
	return domain, true
}

func normalizeDomainText(raw string) string {
	domain := strings.ToLower(strings.TrimSpace(raw))
	return strings.TrimRight(domain, ".")
}

func isHostsAddress(field string) bool {
	if _, err := netip.ParseAddr(field); err == nil {
		return true
	}
	if addr, _, ok := strings.Cut(field, "%"); ok {
		if _, err := netip.ParseAddr(addr); err == nil {
			return true
		}
	}
	return false
}

func validBlocklistDomain(domain string) bool {
	return validDomain(domain) && !isLocalHostsAlias(domain)
}

func isLocalHostsAlias(domain string) bool {
	switch domain {
	case "localhost",
		"localhost.localdomain",
		"localhost6",
		"localhost6.localdomain6",
		"local",
		"broadcasthost",
		"ip6-localhost",
		"ip6-loopback",
		"ip6-localnet",
		"ip6-mcastprefix",
		"ip6-allnodes",
		"ip6-allrouters",
		"ip6-allhosts":
		return true
	default:
		return false
	}
}

func validDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
}
