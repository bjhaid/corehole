package coreplugin

import (
	"context"
	"net"
	"testing"
	"time"

	coreholeaudit "github.com/bjhaid/corehole/internal/audit"
	coreholedns "github.com/bjhaid/corehole/internal/dns"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/miekg/dns"
)

func TestHandlerBlocksCurrentRuntimeDeciderWithNXDOMAIN(t *testing.T) {
	runtime := Current()
	runtime.SetDecider(blockAdzerk{})
	runtime.SetAudit(coreholeaudit.NoopSink{})
	runtime.SetBlockingResponse(coreholedns.BlockingResponseNXDOMAIN)
	runtime.SetLocalResolver(nil)
	t.Cleanup(func() {
		runtime.SetDecider(AllowAll{})
		runtime.SetAudit(coreholeaudit.NoopSink{})
		runtime.SetBlockingResponse(coreholedns.BlockingResponseNXDOMAIN)
		runtime.SetLocalResolver(nil)
	})

	req := new(dns.Msg)
	req.SetQuestion("adzerk.com.", dns.TypeA)
	w := &recordingResponseWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}}

	rcode, err := Handler{}.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("ServeDNS() rcode = %s, want NXDOMAIN", dns.RcodeToString[rcode])
	}
	if w.msg == nil {
		t.Fatal("ServeDNS() did not write a response")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("response rcode = %s, want NXDOMAIN", dns.RcodeToString[w.msg.Rcode])
	}
}

func TestHandlerBlocksCurrentRuntimeDeciderWithDefaultNullIP(t *testing.T) {
	runtime := Current()
	runtime.SetDecider(blockAdzerk{})
	runtime.SetAudit(coreholeaudit.NoopSink{})
	runtime.SetBlockingResponse("")
	runtime.SetLocalResolver(nil)
	t.Cleanup(func() {
		runtime.SetDecider(AllowAll{})
		runtime.SetAudit(coreholeaudit.NoopSink{})
		runtime.SetBlockingResponse(coreholedns.BlockingResponseNullIP)
		runtime.SetLocalResolver(nil)
	})

	req := new(dns.Msg)
	req.SetQuestion("adzerk.com.", dns.TypeA)
	w := &recordingResponseWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}}

	rcode, err := Handler{}.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("ServeDNS() rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
	if w.msg == nil {
		t.Fatal("ServeDNS() did not write a response")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(w.msg.Answer))
	}
	answer, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", w.msg.Answer[0])
	}
	if !answer.A.Equal(net.IPv4(0, 0, 0, 0)) {
		t.Fatalf("answer A = %s, want 0.0.0.0", answer.A)
	}
}

func TestHandlerAuditsForwardDiagnosticsFromMetadata(t *testing.T) {
	runtime := Current()
	sink := &recordingAuditSink{}
	runtime.SetDecider(AllowAll{})
	runtime.SetAudit(sink)
	runtime.SetBlockingResponse(coreholedns.BlockingResponseNXDOMAIN)
	runtime.SetLocalResolver(nil)
	runtime.SetCacheEnabled(true)
	t.Cleanup(func() {
		runtime.SetDecider(AllowAll{})
		runtime.SetAudit(coreholeaudit.NoopSink{})
		runtime.SetBlockingResponse(coreholedns.BlockingResponseNXDOMAIN)
		runtime.SetLocalResolver(nil)
		runtime.SetCacheEnabled(false)
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	w := &recordingResponseWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}}

	rcode, err := Handler{Next: upstreamMetadataNext{upstream: "1.1.1.1:53"}}.ServeDNS(metadata.ContextWithMetadata(context.Background()), w, req)
	if err != nil {
		t.Fatalf("ServeDNS() error = %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("ServeDNS() rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
	if sink.event.Upstream != "1.1.1.1:53" ||
		sink.event.CacheStatus != "miss" ||
		sink.event.ForwardDuration <= 0 ||
		sink.event.RetryCount != -1 ||
		sink.event.ForwardError != "" {
		t.Fatalf("audit event diagnostics = %#v", sink.event)
	}
}

func TestRuntimePauseBlockingAllowsBlockedDomain(t *testing.T) {
	runtime := NewRuntime()
	runtime.SetDecider(blockAdzerk{})
	runtime.PauseBlocking(time.Time{})

	decision := runtime.Decide(context.Background(), coreholedns.Query{
		Name:      "adzerk.com.",
		Timestamp: time.Now(),
	})
	if decision.Action != coreholedns.ActionAllow {
		t.Fatalf("decision action = %s, want allow", decision.Action)
	}
	if decision.Reason != "blocking paused indefinitely" {
		t.Fatalf("decision reason = %q, want blocking paused indefinitely", decision.Reason)
	}
}

func TestRuntimeExpiredPauseFallsBackToDecider(t *testing.T) {
	runtime := NewRuntime()
	runtime.SetDecider(blockAdzerk{})
	runtime.PauseBlocking(time.Now().Add(-time.Second))

	decision := runtime.Decide(context.Background(), coreholedns.Query{
		Name:      "adzerk.com.",
		Timestamp: time.Now(),
	})
	if decision.Action != coreholedns.ActionBlock {
		t.Fatalf("decision action = %s, want block", decision.Action)
	}
	if runtime.BlockingPause().Enabled {
		t.Fatal("expired pause still enabled")
	}
}

type blockAdzerk struct{}

func (blockAdzerk) Decide(_ context.Context, q coreholedns.Query) coreholedns.Decision {
	if q.Name == "adzerk.com." {
		return coreholedns.Decision{Action: coreholedns.ActionBlock, Reason: "test block"}
	}
	return coreholedns.Decision{Action: coreholedns.ActionAllow, Reason: "test allow"}
}

type recordingResponseWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func (w *recordingResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1053}
}

func (w *recordingResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *recordingResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	return nil
}

func (w *recordingResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (w *recordingResponseWriter) Close() error {
	return nil
}

func (w *recordingResponseWriter) TsigStatus() error {
	return nil
}

func (w *recordingResponseWriter) TsigTimersOnly(bool) {}

func (w *recordingResponseWriter) Hijack() {}

type upstreamMetadataNext struct {
	upstream string
}

func (n upstreamMetadataNext) Name() string { return "test_next" }

func (n upstreamMetadataNext) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	metadata.SetValueFunc(ctx, "forward/upstream", func() string {
		return n.upstream
	})
	response := new(dns.Msg)
	response.SetReply(r)
	if err := w.WriteMsg(response); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

type recordingAuditSink struct {
	event coreholeaudit.Event
}

func (s *recordingAuditSink) Record(_ context.Context, event coreholeaudit.Event) {
	s.event = event
}

func (s *recordingAuditSink) Close(context.Context) error { return nil }
