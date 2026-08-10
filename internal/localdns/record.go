package localdns

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypePTR   RecordType = "PTR"

	DefaultTTL uint32 = 300
	MaxTTL     uint32 = 604800
)

var (
	ErrInvalidRecord = errors.New("invalid local dns record")
	ErrNotFound      = errors.New("local dns record not found")
)

type Record struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Type      RecordType `json:"type"`
	Value     string     `json:"value"`
	TTL       uint32     `json:"ttl"`
	Enabled   bool       `json:"enabled"`
	Comment   string     `json:"comment"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type RecordInput struct {
	Name    string     `json:"name"`
	Type    RecordType `json:"type"`
	Value   string     `json:"value"`
	TTL     uint32     `json:"ttl"`
	Enabled *bool      `json:"enabled,omitempty"`
	Comment string     `json:"comment"`
}

func NewRecord(input RecordInput) (Record, error) {
	normalized, err := NormalizeInput(input)
	if err != nil {
		return Record{}, err
	}
	return Record{
		Name:    normalized.Name,
		Type:    normalized.Type,
		Value:   normalized.Value,
		TTL:     normalized.TTL,
		Enabled: normalized.enabled(),
		Comment: normalized.Comment,
	}, nil
}

func NormalizeInput(input RecordInput) (RecordInput, error) {
	recordType := RecordType(strings.ToUpper(strings.TrimSpace(string(input.Type))))
	if recordType == "" {
		return RecordInput{}, fmt.Errorf("%w: type is required", ErrInvalidRecord)
	}

	name, err := normalizeDomainName(input.Name)
	if err != nil {
		return RecordInput{}, fmt.Errorf("%w: invalid name", ErrInvalidRecord)
	}

	value := strings.TrimSpace(input.Value)
	switch recordType {
	case TypeA:
		value, err = normalizeIPValue(value, false)
	case TypeAAAA:
		value, err = normalizeIPValue(value, true)
	case TypeCNAME:
		value, err = normalizeDomainName(value)
	case TypePTR:
		if !isPTRName(name) {
			return RecordInput{}, fmt.Errorf("%w: ptr name must be under in-addr.arpa or ip6.arpa", ErrInvalidRecord)
		}
		value, err = normalizeDomainName(value)
	default:
		return RecordInput{}, fmt.Errorf("%w: unsupported type", ErrInvalidRecord)
	}
	if err != nil {
		return RecordInput{}, err
	}

	if input.TTL == 0 {
		input.TTL = DefaultTTL
	}
	if input.TTL > MaxTTL {
		return RecordInput{}, fmt.Errorf("%w: ttl out of range", ErrInvalidRecord)
	}

	return RecordInput{
		Name:    name,
		Type:    recordType,
		Value:   value,
		TTL:     input.TTL,
		Enabled: input.Enabled,
		Comment: strings.TrimSpace(input.Comment),
	}, nil
}

func (i RecordInput) enabled() bool {
	if i.Enabled == nil {
		return true
	}
	return *i.Enabled
}

func normalizeDomainName(name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	if !validDomainName(name) {
		return "", fmt.Errorf("%w: invalid domain name", ErrInvalidRecord)
	}
	return name, nil
}

func validDomainName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeIPValue(value string, wantIPv6 bool) (string, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("%w: invalid ip value", ErrInvalidRecord)
	}
	if wantIPv6 && !addr.Is6() {
		return "", fmt.Errorf("%w: AAAA value must be IPv6", ErrInvalidRecord)
	}
	if !wantIPv6 && !addr.Is4() {
		return "", fmt.Errorf("%w: A value must be IPv4", ErrInvalidRecord)
	}
	return addr.String(), nil
}

func isPTRName(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")
}

func fqdn(name string) string {
	return strings.TrimSuffix(name, ".") + "."
}
