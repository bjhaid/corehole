package coredns

import (
	"context"
	"fmt"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const dnssecUpstreamPluginName = "corehole_dnssec"

func init() {
	insertDirectiveBefore(dnssecUpstreamPluginName, "forward")
	plugin.Register(dnssecUpstreamPluginName, setupDNSSECUpstream)
}

type dnssecUpstreamHandler struct {
	Next plugin.Handler
}

func (h dnssecUpstreamHandler) Name() string { return dnssecUpstreamPluginName }

func (h dnssecUpstreamHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	upstream, clientRequestedDNSSEC, clientRequestedAD := upstreamDNSSECRequest(r)
	writer := dnssecUpstreamResponseWriter{
		ResponseWriter:        w,
		clientRequestedDNSSEC: clientRequestedDNSSEC,
		clientRequestedAD:     clientRequestedAD,
	}
	return plugin.NextOrFailure(dnssecUpstreamPluginName, h.Next, ctx, writer, upstream)
}

func setupDNSSECUpstream(c *caddy.Controller) error {
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 || args[0] != "upstream" {
			return plugin.Error(dnssecUpstreamPluginName, fmt.Errorf("mode must be upstream"))
		}
		if c.NextBlock() {
			return plugin.Error(dnssecUpstreamPluginName, c.ArgErr())
		}
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return dnssecUpstreamHandler{Next: next}
	})
	return nil
}

type dnssecUpstreamResponseWriter struct {
	dns.ResponseWriter
	clientRequestedDNSSEC bool
	clientRequestedAD     bool
}

func (w dnssecUpstreamResponseWriter) WriteMsg(msg *dns.Msg) error {
	if msg == nil {
		return w.ResponseWriter.WriteMsg(nil)
	}
	response := msg
	if !w.clientRequestedDNSSEC || !w.clientRequestedAD {
		response = msg.Copy()
	}
	if !w.clientRequestedDNSSEC {
		stripDNSSECRecords(response)
		clearDO(response)
	}
	if !w.clientRequestedAD && !w.clientRequestedDNSSEC {
		response.AuthenticatedData = false
	}
	return w.ResponseWriter.WriteMsg(response)
}

func upstreamDNSSECRequest(r *dns.Msg) (*dns.Msg, bool, bool) {
	clientRequestedDNSSEC := clientRequestsDNSSEC(r)
	clientRequestedAD := r.AuthenticatedData

	upstream := r.Copy()
	upstream.CheckingDisabled = false
	upstream.AuthenticatedData = true
	if opt := upstream.IsEdns0(); opt != nil {
		opt.SetDo()
		if opt.UDPSize() < 1232 {
			opt.SetUDPSize(1232)
		}
	} else {
		upstream.SetEdns0(1232, true)
	}
	return upstream, clientRequestedDNSSEC, clientRequestedAD
}

func clientRequestsDNSSEC(r *dns.Msg) bool {
	if opt := r.IsEdns0(); opt != nil {
		if opt.Do() {
			return true
		}
	}
	for _, question := range r.Question {
		if isDNSSECProofRecord(question.Qtype) {
			return true
		}
	}
	return false
}

func stripDNSSECRecords(msg *dns.Msg) {
	msg.Answer = stripDNSSECRRSet(msg.Answer)
	msg.Ns = stripDNSSECRRSet(msg.Ns)
	msg.Extra = stripDNSSECExtra(msg.Extra)
}

func stripDNSSECRRSet(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	filtered := rrs[:0]
	for _, rr := range rrs {
		if rr == nil || isDNSSECProofRecord(rr.Header().Rrtype) {
			continue
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

func stripDNSSECExtra(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	filtered := rrs[:0]
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == dns.TypeOPT || !isDNSSECProofRecord(rr.Header().Rrtype) {
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

func isDNSSECProofRecord(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
		return true
	default:
		return false
	}
}

func clearDO(msg *dns.Msg) {
	if opt := msg.IsEdns0(); opt != nil {
		opt.SetDo(false)
	}
}

func insertDirectiveBefore(name, before string) {
	for _, directive := range dnsserver.Directives {
		if directive == name {
			return
		}
	}
	for i, directive := range dnsserver.Directives {
		if directive == before {
			next := append([]string{}, dnsserver.Directives[:i]...)
			next = append(next, name)
			next = append(next, dnsserver.Directives[i:]...)
			dnsserver.Directives = next
			return
		}
	}
	dnsserver.Directives = append(dnsserver.Directives, name)
}
