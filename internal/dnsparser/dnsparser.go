package dnsparser

import (
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"passivednsgo/internal/config"
	"passivednsgo/internal/dnsstrings"
)

type SevenTuple struct {
	proto int
	qid   uint16
	src   string
	dst   string
	sport int // Changed from string
	dport int // Changed from string
	vlan  uint16
}

type DNSQnR struct {
	query  layers.DNS
	answer layers.DNS
	flow   SevenTuple
	qseen  bool
	aseen  bool
	qts    time.Time
	ats    time.Time
}

type DNSQoR struct {
	flow SevenTuple
	dns  layers.DNS
	ts   time.Time
}

type PDNS struct {
	Query  string     `json:"query,omitempty"`
	Qtype  string     `json:"qtype,omitempty"`
	Answer string     `json:"answer,omitempty"`
	Atype  string     `json:"atype,omitempty"`
	Qid    uint16     `json:"qid,omitempty"`
	Rc     string     `json:"rc,omitempty"`
	Ttl    uint32     `json:"ttl,omitempty"`
	Cnt    int        `json:"cnt,omitempty"`
	Fts    *time.Time `json:"fts,omitempty"`
	Lts    *time.Time `json:"lts,omitempty"`
	Pts    *time.Time `json:"pts,omitempty"`
	Src    string     `json:"src_ip"`
	Sport  int        `json:"src_port"` // Changed from string
	Dst    string     `json:"dst_ip"`
	Dport  int        `json:"dst_port"` // Changed from string
	Proto  int        `json:"proto"`
	Vlan   uint16     `json:"vlan"`
	Qtm    float64    `json:"qtm,omitempty"`
}

type cxtdb struct {
	cxt map[string]DNSQnR
	m   sync.RWMutex
}

type dnsdb struct {
	Key map[string]PDNS
	M   sync.RWMutex
}

type Parser struct {
	UnidirectionalChan chan DNSQoR
	BidirectionalChan  chan DNSQnR
	LogChan            chan PDNS
	cxt                cxtdb
	Cachedb            dnsdb
	wg                 *sync.WaitGroup
}

func NewParser(wg *sync.WaitGroup, uniChan chan DNSQoR, biChan chan DNSQnR, logChan chan PDNS) *Parser {
	return &Parser{
		UnidirectionalChan: uniChan,
		BidirectionalChan:  biChan,
		LogChan:            logChan,
		cxt:                cxtdb{cxt: make(map[string]DNSQnR)},
		Cachedb:            dnsdb{Key: make(map[string]PDNS)},
		wg:                 wg,
	}
}

// Updated signature: sport and dport are now int
func (p *Parser) ParseDNS(timestamp time.Time, vlan uint16, src string, sport int, dst string, dport int, proto int, dns layers.DNS) {
	if dns.OpCode != layers.DNSOpCodeQuery {
		return
	}

	if dns.Questions == nil {
		return
	}

	var tmpflow SevenTuple
	tmpflow.proto = proto
	tmpflow.qid = dns.ID
	tmpflow.src = src
	tmpflow.dst = dst
	tmpflow.sport = sport
	tmpflow.dport = dport
	tmpflow.vlan = vlan

	if config.C.Unidir {
		p.UnidirectionalChan <- DNSQoR{
			flow: tmpflow,
			dns:  dns,
			ts:   timestamp,
		}
		return
	}

	var ukey string
	if dns.QR { // Response from server
		// Updated format string to use %d for ports
		ukey = fmt.Sprintf("%d%d%d%d%s%s%d", dns.ID, proto, dport, sport, dst, src, vlan)
		tmpflow.src, tmpflow.dst = dst, src
		tmpflow.sport, tmpflow.dport = dport, sport
	} else { // Request from client
		// Updated format string to use %d for ports
		ukey = fmt.Sprintf("%d%d%d%d%s%s%d", dns.ID, proto, sport, dport, src, dst, vlan)
	}

	p.cxt.m.RLock()
	dnspair, exists := p.cxt.cxt[ukey]
	p.cxt.m.RUnlock()

	if exists {
		if dns.QR {
			dnspair.aseen = true
			dnspair.answer = dns
			dnspair.ats = timestamp
		} else {
			dnspair.qseen = true
			dnspair.query = dns
			dnspair.qts = timestamp
		}

		if dnspair.aseen && dnspair.qseen {
			if dnspair.query.Questions != nil {
				p.BidirectionalChan <- dnspair
				p.cxt.m.Lock()
				delete(p.cxt.cxt, ukey)
				p.cxt.m.Unlock()
			}
		}
	} else {
		p.cxt.m.Lock()
		if dns.QR {
			p.cxt.cxt[ukey] = DNSQnR{
				answer: dns,
				ats:    timestamp,
				flow:   tmpflow,
				aseen:  true,
			}
		} else {
			p.cxt.cxt[ukey] = DNSQnR{
				query: dns,
				qts:   timestamp,
				flow:  tmpflow,
				qseen: true,
			}
		}
		p.cxt.m.Unlock()
	}
}

func (p *Parser) Unidirectional() {
	defer p.wg.Done()
	slog.Info("Unidirectional Routine Started...")
	for entry := range p.UnidirectionalChan {
		dns := entry.dns
		now := time.Now()

		pdns := PDNS{
			Qid:   dns.ID,
			Src:   entry.flow.src,
			Sport: entry.flow.sport, // int assignment
			Dport: entry.flow.dport, // int assignment
			Dst:   entry.flow.dst,
			Proto: entry.flow.proto,
			Vlan:  entry.flow.vlan,
			Pts:   &now,
		}

		if dns.QR {
			pdns.Rc = dnsstrings.DNSResponseCodeString(dns.ResponseCode)
			for _, answer := range dns.Answers {
				pdns.Ttl = answer.TTL
				pdns.Atype = dnsstrings.DNSTypeString(answer.Type)

				if dns.ResponseCode == layers.DNSResponseCodeNoErr {
					pdns.Answer = dnsstrings.DNSResourceRecordString(answer)
				} else {
					pdns.Answer = string(answer.Name)
				}
				p.LogChan <- pdns
			}
		} else {
			if len(dns.Questions) > 0 {
				pdns.Query = string(dns.Questions[0].Name)
				pdns.Qtype = dnsstrings.DNSTypeString(dns.Questions[0].Type)
				p.LogChan <- pdns
			}
		}
	}
	slog.Info("Unidirectional Routine Stopped")
}

func (p *Parser) Bidirectional() {
	defer p.wg.Done()
	slog.Info("Bidirectional Routine Started...")
	printTimeOffset, err := time.ParseDuration("-" + config.C.Printtime)
	if err != nil {
		slog.Error("Failed to parse Printtime", "error", err)
		return
	}

	for entry := range p.BidirectionalChan {
		currentTimestamp := time.Now()
		adjustedTimestamp := currentTimestamp.Add(printTimeOffset)

		tsDiff := math.Abs(entry.ats.Sub(entry.qts).Seconds())
		if tsDiff > 9223370000 {
			tsDiff = 9223372037 - tsDiff
		}

		isErrorResponse := entry.answer.ResponseCode != 0
		questionName := strings.ToLower(string(entry.query.Questions[0].Name))
		questionType := dnsstrings.DNSTypeString(entry.query.Questions[0].Type)
		responseCode := dnsstrings.DNSResponseCodeString(entry.answer.ResponseCode)

		createPDNS := func(answer string, answerType string, ttl uint32) PDNS {
			return PDNS{
				Query:  questionName,
				Answer: answer,
				Atype:  answerType,
				Rc:     responseCode,
				Ttl:    ttl,
				Cnt:    1,
				Fts:    &entry.qts,
				Lts:    &entry.ats,
				Qid:    entry.flow.qid,
				Src:    entry.flow.src,
				Sport:  entry.flow.sport, // int assignment
				Dport:  entry.flow.dport, // int assignment
				Dst:    entry.flow.dst,
				Proto:  entry.flow.proto,
				Vlan:   entry.flow.vlan,
				Qtm:    tsDiff,
				Pts:    &currentTimestamp,
			}
		}

		if isErrorResponse {
			pdnsRecord := createPDNS(responseCode, questionType, 0)
			if config.C.Cache {
				cacheKey := questionName + ":" + questionType + ":" + responseCode
				p.processCacheEntry(cacheKey, pdnsRecord, adjustedTimestamp)
			} else {
				p.LogChan <- pdnsRecord
			}

		} else {
			for _, answer := range entry.answer.Answers {
				answerStr := dnsstrings.DNSResourceRecordString(answer)
				answerType := dnsstrings.DNSTypeString(answer.Type)
				ttl := answer.TTL

				pdnsRecord := createPDNS(answerStr, answerType, ttl)

				if config.C.Cache {
					cacheKey := questionName + ":" + answerType + ":" + answerStr
					p.processCacheEntry(cacheKey, pdnsRecord, adjustedTimestamp)
				} else {
					p.LogChan <- pdnsRecord
				}
			}
		}
	}
	p.FlushDB()
	slog.Info("Bidirectional Routine Stopped")
}

func (p *Parser) processCacheEntry(cacheKey string, pdnsRecord PDNS, adjustedTimestamp time.Time) {
	p.Cachedb.M.RLock()
	cachedEntry, exists := p.Cachedb.Key[cacheKey]
	p.Cachedb.M.RUnlock()

	if exists {
		pdnsRecord.Cnt = cachedEntry.Cnt + 1
		pdnsRecord.Fts = cachedEntry.Fts
		pdnsRecord.Pts = cachedEntry.Pts

		if pdnsRecord.Ttl < cachedEntry.Ttl {
			pdnsRecord.Ttl = cachedEntry.Ttl
		}

		if cachedEntry.Pts.Before(adjustedTimestamp) {
			now := time.Now()
			pdnsRecord.Pts = &now
			p.LogChan <- pdnsRecord
		}
	} else {
		p.LogChan <- pdnsRecord
	}

	p.Cachedb.M.Lock()
	p.Cachedb.Key[cacheKey] = pdnsRecord
	p.Cachedb.M.Unlock()
}

func (p *Parser) FlushDB() {
	p.Cachedb.M.RLock()
	slog.Debug("Flushing CacheDB", "count", len(p.Cachedb.Key))

	for ukey, pdns := range p.Cachedb.Key {
		p.Cachedb.M.RUnlock()
		p.Cachedb.M.Lock()
		delete(p.Cachedb.Key, ukey)
		p.Cachedb.M.Unlock()
		p.Cachedb.M.RLock()

		p.LogChan <- pdns
	}
	p.Cachedb.M.RUnlock()
}

func (p *Parser) DBMaintenance(stopChan <-chan bool) {
	defer p.wg.Done()
	slog.Info("DBMaintenance Routine Started...")

	cachetime, err := time.ParseDuration("-" + config.C.Cachetime)
	if err != nil {
		slog.Error("Failed to parse Cachetime", "error", err)
		return
	}

	cxttimeout, err := time.ParseDuration("-" + config.C.CXTtimeout)
	if err != nil {
		slog.Error("Failed to parse CXTtimeout", "error", err)
		return
	}

	cleanTimer := time.NewTicker(time.Minute)
	defer cleanTimer.Stop()

	for {
		select {
		case <-cleanTimer.C:
			// 1. Clean CacheDB
			ts := time.Now().Add(cachetime)
			tsn := time.Now()
			p.Cachedb.M.RLock()
			for ukey, pdns := range p.Cachedb.Key {
				if pdns.Lts.Before(ts) {
					p.Cachedb.M.RUnlock()
					p.Cachedb.M.Lock()
					delete(p.Cachedb.Key, ukey)
					p.Cachedb.M.Unlock()
					p.Cachedb.M.RLock()

					pdns.Pts = &tsn
					p.LogChan <- pdns
				}
			}
			p.Cachedb.M.RUnlock()

			// 2. Clean ContextDB
			ts = time.Now().Add(cxttimeout)
			p.cxt.m.RLock()
			for ukey, dnscxt := range p.cxt.cxt {
				if dnscxt.qts.Before(ts) || dnscxt.ats.Before(ts) {
					p.cxt.m.RUnlock()
					p.cxt.m.Lock()
					delete(p.cxt.cxt, ukey)
					p.cxt.m.Unlock()
					p.cxt.m.RLock()
				}
			}
			p.cxt.m.RUnlock()

		case <-stopChan:
			slog.Info("Shutting down DBMaintenance...")
			p.FlushDB()
			return
		}
	}
}
