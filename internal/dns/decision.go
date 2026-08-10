package dns

import (
	"context"
	"net/netip"
	"time"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

type BlockingResponse string

const (
	BlockingResponseNXDOMAIN BlockingResponse = "nxdomain"
	BlockingResponseNullIP   BlockingResponse = "null-ip"
	BlockingResponseRefused  BlockingResponse = "refused"
)

type Query struct {
	Name      string
	Type      uint16
	ClientIP  netip.Addr
	Timestamp time.Time
}

type Decision struct {
	Action      Action
	Reason      string
	RuleID      int64
	BlocklistID int64
}

type Decider interface {
	Decide(ctx context.Context, q Query) Decision
}
