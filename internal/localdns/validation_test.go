package localdns

import (
	"errors"
	"testing"
)

func TestValidateRecordInput(t *testing.T) {
	enabled := false
	record, err := NewRecord(RecordInput{
		Name:    "Host.Example.",
		Type:    "a",
		Value:   "192.0.2.1",
		Enabled: &enabled,
	})
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if record.Name != "host.example" || record.Type != TypeA || record.Value != "192.0.2.1" || record.TTL != DefaultTTL || record.Enabled {
		t.Fatalf("record = %#v", record)
	}
}

func TestValidateRecordInputRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		input RecordInput
	}{
		{
			name:  "bad domain",
			input: RecordInput{Name: "-bad.example", Type: TypeA, Value: "192.0.2.1"},
		},
		{
			name:  "ipv6 for A",
			input: RecordInput{Name: "host.example", Type: TypeA, Value: "2001:db8::1"},
		},
		{
			name:  "ipv4 for AAAA",
			input: RecordInput{Name: "host.example", Type: TypeAAAA, Value: "192.0.2.1"},
		},
		{
			name:  "bad cname target",
			input: RecordInput{Name: "alias.example", Type: TypeCNAME, Value: "bad_target.example"},
		},
		{
			name:  "ptr outside reverse domain",
			input: RecordInput{Name: "host.example", Type: TypePTR, Value: "host.example"},
		},
		{
			name:  "bad ptr target",
			input: RecordInput{Name: "10.2.0.192.in-addr.arpa", Type: TypePTR, Value: "_host.example"},
		},
		{
			name:  "ttl too large",
			input: RecordInput{Name: "host.example", Type: TypeA, Value: "192.0.2.1", TTL: MaxTTL + 1},
		},
		{
			name:  "unsupported type",
			input: RecordInput{Name: "host.example", Type: "TXT", Value: "hello"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewRecord(tt.input); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("NewRecord() error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}
