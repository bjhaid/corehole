package localdns

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const maxCNAMEChain = 8

type Source interface {
	ListEnabled(ctx context.Context) ([]Record, error)
}

type DNSResolver struct {
	source Source
	index  map[string][]Record
}

func NewDNSResolver(source Source) *DNSResolver {
	return &DNSResolver{source: source}
}

func NewStaticResolver(records []Record) *DNSResolver {
	return &DNSResolver{index: indexRecords(records)}
}

func (r *DNSResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, bool, error) {
	if r == nil || (r.source == nil && r.index == nil) || req == nil || len(req.Question) == 0 {
		return nil, false, nil
	}

	q := req.Question[0]
	if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
		return nil, false, nil
	}

	name, err := normalizeDomainName(q.Name)
	if err != nil {
		return nil, false, nil
	}

	index := r.index
	if index == nil {
		records, err := r.source.ListEnabled(ctx)
		if err != nil {
			return nil, false, err
		}
		index = indexRecords(records)
	}

	res := new(dns.Msg)
	res.SetReply(req)
	res.Authoritative = true

	answered := answerName(res, q, index, name)
	if !answered {
		return nil, false, nil
	}
	return res, true, nil
}

func answerName(res *dns.Msg, q dns.Question, index map[string][]Record, name string) bool {
	current := name
	seen := make(map[string]struct{})
	addedAny := false

	for depth := 0; depth < maxCNAMEChain; depth++ {
		if _, ok := seen[current]; ok {
			return addedAny
		}
		seen[current] = struct{}{}

		records := index[current]
		addedDirect := addMatchingAnswers(res, q, records, current)
		if addedDirect {
			return true
		}

		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA && q.Qtype != dns.TypeANY {
			return addedAny
		}

		cname, ok := firstCNAME(records)
		if !ok {
			return addedAny
		}

		res.Answer = append(res.Answer, cnameRR(q, cname))
		addedAny = true
		current = cname.Value
	}
	return addedAny
}

func addMatchingAnswers(res *dns.Msg, q dns.Question, records []Record, owner string) bool {
	added := false
	for _, record := range records {
		if !recordMatchesQuestion(record, q.Qtype) {
			continue
		}
		rr := rrForRecord(q, record, owner)
		if rr == nil {
			continue
		}
		res.Answer = append(res.Answer, rr)
		added = true
	}
	return added
}

func recordMatchesQuestion(record Record, qtype uint16) bool {
	if qtype == dns.TypeANY {
		return true
	}
	switch record.Type {
	case TypeA:
		return qtype == dns.TypeA
	case TypeAAAA:
		return qtype == dns.TypeAAAA
	case TypeCNAME:
		return qtype == dns.TypeCNAME
	case TypePTR:
		return qtype == dns.TypePTR
	default:
		return false
	}
}

func rrForRecord(q dns.Question, record Record, owner string) dns.RR {
	switch record.Type {
	case TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{Name: fqdn(owner), Rrtype: dns.TypeA, Class: q.Qclass, Ttl: record.TTL},
			A:   net.ParseIP(record.Value).To4(),
		}
	case TypeAAAA:
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fqdn(owner), Rrtype: dns.TypeAAAA, Class: q.Qclass, Ttl: record.TTL},
			AAAA: net.ParseIP(record.Value).To16(),
		}
	case TypeCNAME:
		return cnameRR(q, record)
	case TypePTR:
		return &dns.PTR{
			Hdr: dns.RR_Header{Name: fqdn(owner), Rrtype: dns.TypePTR, Class: q.Qclass, Ttl: record.TTL},
			Ptr: fqdn(record.Value),
		}
	default:
		return nil
	}
}

func cnameRR(q dns.Question, record Record) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: fqdn(record.Name), Rrtype: dns.TypeCNAME, Class: q.Qclass, Ttl: record.TTL},
		Target: fqdn(record.Value),
	}
}

func firstCNAME(records []Record) (Record, bool) {
	for _, record := range records {
		if record.Type == TypeCNAME {
			return record, true
		}
	}
	return Record{}, false
}

func indexRecords(records []Record) map[string][]Record {
	index := make(map[string][]Record)
	for _, record := range records {
		if !record.Enabled {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(record.Name), ".")
		index[name] = append(index[name], record)
	}
	return index
}
