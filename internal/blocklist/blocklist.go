package blocklist

import (
	"context"
	"io"

	coredns "github.com/bjhaid/corehole/internal/dns"
)

type EntryKind string

const (
	EntryExact  EntryKind = "exact"
	EntrySuffix EntryKind = "suffix"
	EntryRegex  EntryKind = "regex"
)

type Entry struct {
	Domain string
	Kind   EntryKind
	Allow  bool
	Source string
}

type Parser interface {
	Parse(ctx context.Context, r io.Reader, source string) ([]Entry, error)
}

type EntrySource interface {
	Entries(ctx context.Context) ([]Entry, error)
}

type Matcher interface {
	coredns.Decider
}
