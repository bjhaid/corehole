package localdns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSResolverAnswersLocalRecords(t *testing.T) {
	resolver := NewStaticResolver([]Record{
		{Name: "host.example", Type: TypeA, Value: "192.0.2.10", TTL: 120, Enabled: true},
		{Name: "host.example", Type: TypeAAAA, Value: "2001:db8::10", TTL: 180, Enabled: true},
		{Name: "10.2.0.192.in-addr.arpa", Type: TypePTR, Value: "host.example", TTL: 240, Enabled: true},
	})

	a := resolve(t, resolver, "host.example.", dns.TypeA)
	if len(a.Answer) != 1 {
		t.Fatalf("A answer length = %d, want 1", len(a.Answer))
	}
	arec, ok := a.Answer[0].(*dns.A)
	if !ok || !arec.A.Equal(net.IPv4(192, 0, 2, 10)) || arec.Hdr.Ttl != 120 {
		t.Fatalf("A answer = %#v", a.Answer[0])
	}

	aaaa := resolve(t, resolver, "HOST.EXAMPLE.", dns.TypeAAAA)
	if len(aaaa.Answer) != 1 {
		t.Fatalf("AAAA answer length = %d, want 1", len(aaaa.Answer))
	}
	aaaarec, ok := aaaa.Answer[0].(*dns.AAAA)
	if !ok || !aaaarec.AAAA.Equal(net.ParseIP("2001:db8::10")) || aaaarec.Hdr.Name != "host.example." {
		t.Fatalf("AAAA answer = %#v", aaaa.Answer[0])
	}

	ptr := resolve(t, resolver, "10.2.0.192.in-addr.arpa.", dns.TypePTR)
	if len(ptr.Answer) != 1 {
		t.Fatalf("PTR answer length = %d, want 1", len(ptr.Answer))
	}
	ptrrec, ok := ptr.Answer[0].(*dns.PTR)
	if !ok || ptrrec.Ptr != "host.example." || ptrrec.Hdr.Ttl != 240 {
		t.Fatalf("PTR answer = %#v", ptr.Answer[0])
	}
}

func TestDNSResolverAnswersCNAMEChain(t *testing.T) {
	resolver := NewStaticResolver([]Record{
		{Name: "alias.example", Type: TypeCNAME, Value: "host.example", TTL: 60, Enabled: true},
		{Name: "host.example", Type: TypeA, Value: "192.0.2.10", TTL: 120, Enabled: true},
	})

	msg := resolve(t, resolver, "alias.example.", dns.TypeA)
	if len(msg.Answer) != 2 {
		t.Fatalf("answer length = %d, want CNAME and A", len(msg.Answer))
	}
	cname, ok := msg.Answer[0].(*dns.CNAME)
	if !ok || cname.Hdr.Name != "alias.example." || cname.Target != "host.example." || cname.Hdr.Ttl != 60 {
		t.Fatalf("CNAME answer = %#v", msg.Answer[0])
	}
	arec, ok := msg.Answer[1].(*dns.A)
	if !ok || !arec.A.Equal(net.IPv4(192, 0, 2, 10)) || arec.Hdr.Name != "host.example." {
		t.Fatalf("A answer = %#v", msg.Answer[1])
	}
}

func TestDNSResolverIgnoresDisabledAndMisses(t *testing.T) {
	resolver := NewStaticResolver([]Record{
		{Name: "disabled.example", Type: TypeA, Value: "192.0.2.30", TTL: 120, Enabled: false},
	})

	req := new(dns.Msg)
	req.SetQuestion("disabled.example.", dns.TypeA)
	if _, ok, err := resolver.Resolve(context.Background(), req); err != nil || ok {
		t.Fatalf("disabled Resolve() ok=%v err=%v, want miss", ok, err)
	}

	req.SetQuestion("missing.example.", dns.TypeA)
	if _, ok, err := resolver.Resolve(context.Background(), req); err != nil || ok {
		t.Fatalf("missing Resolve() ok=%v err=%v, want miss", ok, err)
	}
}

func resolve(t *testing.T, resolver *DNSResolver, name string, qtype uint16) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	msg, ok, err := resolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !ok {
		t.Fatal("Resolve() ok = false, want true")
	}
	if msg.Rcode != dns.RcodeSuccess || !msg.Authoritative {
		t.Fatalf("response rcode=%d authoritative=%v", msg.Rcode, msg.Authoritative)
	}
	return msg
}
