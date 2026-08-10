package coredns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSSECUpstreamSetsDOAndADTowardUpstream(t *testing.T) {
	next := &capturingDNSSECNext{response: dnssecTestResponse(true)}
	writer := &capturingDNSSECResponseWriter{}
	req := dnssecTestRequest()

	rcode, err := (dnssecUpstreamHandler{Next: next}).ServeDNS(context.Background(), writer, req)
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("ServeDNS() rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
	if next.request == nil {
		t.Fatal("upstream request was not captured")
	}
	if opt := next.request.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatalf("upstream request OPT = %#v, want DO set", opt)
	}
	if !next.request.AuthenticatedData {
		t.Fatal("upstream request AD = false, want true to request validation status")
	}
	if next.request.CheckingDisabled {
		t.Fatal("upstream request CD = true, want false so trusted upstream validates")
	}
	if req.IsEdns0() != nil {
		t.Fatal("original request was mutated with EDNS0")
	}
}

func TestDNSSECUpstreamStripsDNSSECDataForBasicClients(t *testing.T) {
	next := &capturingDNSSECNext{response: dnssecTestResponse(true)}
	writer := &capturingDNSSECResponseWriter{}

	_, err := (dnssecUpstreamHandler{Next: next}).ServeDNS(context.Background(), writer, dnssecTestRequest())
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	if writer.msg == nil {
		t.Fatal("response was not written")
	}
	if writer.msg.AuthenticatedData {
		t.Fatal("response AD = true, want cleared for clients that did not request DNSSEC/AD")
	}
	if opt := writer.msg.IsEdns0(); opt != nil && opt.Do() {
		t.Fatal("response DO = true, want cleared for clients that did not request DNSSEC")
	}
	assertNoRRType(t, writer.msg.Answer, dns.TypeRRSIG)
	assertNoRRType(t, writer.msg.Ns, dns.TypeNSEC)
}

func TestDNSSECUpstreamPreservesDNSSECDataForDNSSECClients(t *testing.T) {
	next := &capturingDNSSECNext{response: dnssecTestResponse(true)}
	writer := &capturingDNSSECResponseWriter{}
	req := dnssecTestRequest()
	req.SetEdns0(4096, true)
	req.AuthenticatedData = true

	_, err := (dnssecUpstreamHandler{Next: next}).ServeDNS(context.Background(), writer, req)
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	if writer.msg == nil {
		t.Fatal("response was not written")
	}
	if !writer.msg.AuthenticatedData {
		t.Fatal("response AD = false, want preserved for DNSSEC-aware client")
	}
	if opt := writer.msg.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatalf("response OPT = %#v, want DO preserved", opt)
	}
	assertHasRRType(t, writer.msg.Answer, dns.TypeRRSIG)
	assertHasRRType(t, writer.msg.Ns, dns.TypeNSEC)
}

func TestDNSSECUpstreamPreservesExplicitDNSSECRecordQueries(t *testing.T) {
	next := &capturingDNSSECNext{response: dnssecTestResponse(true)}
	writer := &capturingDNSSECResponseWriter{}
	req := dnssecTestRequest()
	req.Question[0].Qtype = dns.TypeRRSIG

	_, err := (dnssecUpstreamHandler{Next: next}).ServeDNS(context.Background(), writer, req)
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	assertHasRRType(t, writer.msg.Answer, dns.TypeRRSIG)
}

func dnssecTestRequest() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	return req
}

func dnssecTestResponse(authenticated bool) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(dnssecTestRequest())
	resp.AuthenticatedData = authenticated
	resp.SetEdns0(4096, true)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeA,
			SignerName:  "example.com.",
		},
	}
	resp.Ns = []dns.RR{
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "next.example.com.",
		},
	}
	return resp
}

type capturingDNSSECNext struct {
	request  *dns.Msg
	response *dns.Msg
}

func (n *capturingDNSSECNext) Name() string { return "capture" }

func (n *capturingDNSSECNext) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.request = r.Copy()
	response := n.response.Copy()
	if len(r.Question) > 0 {
		response.Question = append([]dns.Question(nil), r.Question...)
	}
	if err := w.WriteMsg(response); err != nil {
		return dns.RcodeServerFailure, err
	}
	return response.Rcode, nil
}

type capturingDNSSECResponseWriter struct {
	msg *dns.Msg
}

func (w *capturingDNSSECResponseWriter) LocalAddr() net.Addr              { return testDNSSECAddr("local") }
func (w *capturingDNSSECResponseWriter) RemoteAddr() net.Addr             { return testDNSSECAddr("remote") }
func (w *capturingDNSSECResponseWriter) WriteMsg(msg *dns.Msg) error      { w.msg = msg; return nil }
func (w *capturingDNSSECResponseWriter) Write(buf []byte) (int, error)    { return len(buf), nil }
func (w *capturingDNSSECResponseWriter) Close() error                     { return nil }
func (w *capturingDNSSECResponseWriter) TsigStatus() error                { return nil }
func (w *capturingDNSSECResponseWriter) TsigTimersOnly(bool)              {}
func (w *capturingDNSSECResponseWriter) Hijack()                          {}
func (w *capturingDNSSECResponseWriter) Msg() *dns.Msg                    { return w.msg }
func (w *capturingDNSSECResponseWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *capturingDNSSECResponseWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *capturingDNSSECResponseWriter) SetTsigSecret(map[string]string)  {}
func (w *capturingDNSSECResponseWriter) SetReply(*dns.Msg)                {}
func (w *capturingDNSSECResponseWriter) SetLocalAddress(net.Addr)         {}
func (w *capturingDNSSECResponseWriter) SetRemoteAddress(net.Addr)        {}

type testDNSSECAddr string

func (a testDNSSECAddr) Network() string { return "test" }
func (a testDNSSECAddr) String() string  { return string(a) }

func assertNoRRType(t *testing.T, rrs []dns.RR, rrtype uint16) {
	t.Helper()
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype {
			t.Fatalf("found RR type %d in %v, want absent", rrtype, rrs)
		}
	}
}

func assertHasRRType(t *testing.T, rrs []dns.RR, rrtype uint16) {
	t.Helper()
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype {
			return
		}
	}
	t.Fatalf("RR type %d absent from %v", rrtype, rrs)
}
