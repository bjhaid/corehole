package coreplugin

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	coreholeaudit "github.com/bjhaid/corehole/internal/audit"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const pluginName = "corehole"

type Handler struct {
	Next plugin.Handler
}

type LocalResolver interface {
	Resolve(ctx context.Context, r *dns.Msg) (*dns.Msg, bool, error)
}

func (h Handler) Name() string { return pluginName }

func (h Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	started := time.Now()
	state := request.Request{W: w, Req: r}
	query := toQuery(state, started)

	if response, ok, err := Current().ResolveLocal(ctx, r); err != nil {
		Current().Audit().Record(ctx, coreholeaudit.Event{
			Timestamp:    started,
			ClientIP:     query.ClientIP,
			QueryName:    query.Name,
			QueryType:    query.Type,
			Action:       coreholedns.ActionAllow,
			Reason:       "local dns lookup failed",
			Response:     dns.RcodeToString[dns.RcodeServerFailure],
			Duration:     time.Since(started),
			CacheStatus:  "bypass",
			RetryCount:   -1,
			ForwardError: err.Error(),
		})
		return dns.RcodeServerFailure, err
	} else if ok {
		_ = w.WriteMsg(response)
		Current().Audit().Record(ctx, coreholeaudit.Event{
			Timestamp:   started,
			ClientIP:    query.ClientIP,
			QueryName:   query.Name,
			QueryType:   query.Type,
			Action:      coreholedns.ActionAllow,
			Reason:      "local dns match",
			Response:    dns.RcodeToString[response.Rcode],
			Duration:    time.Since(started),
			CacheStatus: "bypass",
			RetryCount:  -1,
		})
		return response.Rcode, nil
	}

	decision := Current().Decide(ctx, query)

	if decision.Action == coreholedns.ActionBlock {
		rcode, response := writeBlockedResponse(w, r, Current().BlockingResponse())
		Current().Audit().Record(ctx, coreholeaudit.Event{
			Timestamp:   started,
			ClientIP:    query.ClientIP,
			QueryName:   query.Name,
			QueryType:   query.Type,
			Action:      decision.Action,
			Reason:      decision.Reason,
			RuleID:      decision.RuleID,
			BlocklistID: decision.BlocklistID,
			Response:    response,
			Duration:    time.Since(started),
			CacheStatus: "bypass",
			RetryCount:  -1,
		})
		return rcode, nil
	}

	forwardStarted := time.Now()
	rcode, err := plugin.NextOrFailure(pluginName, h.Next, ctx, w, r)
	forwardDuration := time.Since(forwardStarted)
	upstream := metadataValue(ctx, "forward/upstream")
	forwardError := ""
	if err != nil {
		forwardError = err.Error()
	}
	Current().Audit().Record(ctx, coreholeaudit.Event{
		Timestamp:       started,
		ClientIP:        query.ClientIP,
		QueryName:       query.Name,
		QueryType:       query.Type,
		Action:          coreholedns.ActionAllow,
		Reason:          decision.Reason,
		RuleID:          decision.RuleID,
		BlocklistID:     decision.BlocklistID,
		Response:        dns.RcodeToString[rcode],
		Duration:        time.Since(started),
		Upstream:        upstream,
		CacheStatus:     cacheStatus(Current().CacheEnabled(), upstream, err),
		ForwardDuration: forwardDuration,
		RetryCount:      -1,
		ForwardError:    forwardError,
	})
	return rcode, err
}

func metadataValue(ctx context.Context, label string) string {
	valueFunc := metadata.ValueFunc(ctx, label)
	if valueFunc == nil {
		return ""
	}
	return valueFunc()
}

func cacheStatus(cacheEnabled bool, upstream string, err error) string {
	if !cacheEnabled {
		return "disabled"
	}
	if upstream != "" {
		return "miss"
	}
	if err == nil {
		return "hit"
	}
	return "unknown"
}

func toQuery(state request.Request, now time.Time) coreholedns.Query {
	var client netip.Addr
	if host, _, err := net.SplitHostPort(state.W.RemoteAddr().String()); err == nil {
		client, _ = netip.ParseAddr(host)
	}
	return coreholedns.Query{
		Name:      state.QName(),
		Type:      state.QType(),
		ClientIP:  client,
		Timestamp: now,
	}
}

func writeBlockedResponse(w dns.ResponseWriter, r *dns.Msg, mode coreholedns.BlockingResponse) (int, string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch mode {
	case coreholedns.BlockingResponseRefused:
		m.Rcode = dns.RcodeRefused
	case coreholedns.BlockingResponseNullIP:
		addNullAnswers(m, r)
	default:
		m.Rcode = dns.RcodeNameError
	}

	_ = w.WriteMsg(m)
	return m.Rcode, dns.RcodeToString[m.Rcode]
}

func addNullAnswers(m *dns.Msg, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: q.Qclass, Ttl: 0},
			A:   net.IPv4(0, 0, 0, 0),
		})
	case dns.TypeAAAA:
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: q.Qclass, Ttl: 0},
			AAAA: net.IPv6zero,
		})
	default:
		m.Rcode = dns.RcodeNameError
	}
}

type Runtime struct {
	decider       atomic.Value
	audit         atomic.Value
	mode          atomic.Value
	localResolver atomic.Value
	cacheEnabled  atomic.Bool
}

func NewRuntime() *Runtime {
	rt := &Runtime{}
	rt.SetDecider(AllowAll{})
	rt.SetAudit(coreholeaudit.NoopSink{})
	rt.SetBlockingResponse(coreholedns.BlockingResponseNXDOMAIN)
	rt.SetLocalResolver(nil)
	rt.SetCacheEnabled(false)
	return rt
}

func (r *Runtime) SetDecider(decider coreholedns.Decider) {
	if decider == nil {
		decider = AllowAll{}
	}
	r.decider.Store(deciderHolder{decider: decider})
}

func (r *Runtime) Decide(ctx context.Context, q coreholedns.Query) coreholedns.Decision {
	return r.decider.Load().(deciderHolder).decider.Decide(ctx, q)
}

func (r *Runtime) SetAudit(sink coreholeaudit.Sink) {
	if sink == nil {
		sink = coreholeaudit.NoopSink{}
	}
	r.audit.Store(auditHolder{sink: sink})
}

func (r *Runtime) Audit() coreholeaudit.Sink {
	return r.audit.Load().(auditHolder).sink
}

func (r *Runtime) SetBlockingResponse(mode coreholedns.BlockingResponse) {
	if mode == "" {
		mode = coreholedns.BlockingResponseNXDOMAIN
	}
	r.mode.Store(mode)
}

func (r *Runtime) BlockingResponse() coreholedns.BlockingResponse {
	return r.mode.Load().(coreholedns.BlockingResponse)
}

func (r *Runtime) SetLocalResolver(resolver LocalResolver) {
	r.localResolver.Store(localResolverHolder{resolver: resolver})
}

func (r *Runtime) ResolveLocal(ctx context.Context, msg *dns.Msg) (*dns.Msg, bool, error) {
	resolver := r.localResolver.Load().(localResolverHolder).resolver
	if resolver == nil {
		return nil, false, nil
	}
	return resolver.Resolve(ctx, msg)
}

func (r *Runtime) SetCacheEnabled(enabled bool) {
	r.cacheEnabled.Store(enabled)
}

func (r *Runtime) CacheEnabled() bool {
	return r.cacheEnabled.Load()
}

type AllowAll struct{}

func (AllowAll) Decide(context.Context, coreholedns.Query) coreholedns.Decision {
	return coreholedns.Decision{Action: coreholedns.ActionAllow}
}

type deciderHolder struct {
	decider coreholedns.Decider
}

type auditHolder struct {
	sink coreholeaudit.Sink
}

type localResolverHolder struct {
	resolver LocalResolver
}

var runtime = NewRuntime()

func Current() *Runtime {
	return runtime
}
