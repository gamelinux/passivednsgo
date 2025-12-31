package dnsparser

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"passivednsgo/internal/config"
)

type SevenTuple struct {
	proto int
	qid   uint16
	src   string
	dst   string
	sport int
	dport int
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
	Answer []string   `json:"answer,omitempty"`
	Atype  string     `json:"atype,omitempty"`
	Qid    uint16     `json:"qid,omitempty"`
	Rc     string     `json:"rc,omitempty"`
	Ttl    uint32     `json:"ttl,omitempty"`
	Cnt    int        `json:"cnt,omitempty"`
	Fts    *time.Time `json:"fts,omitempty"`
	Lts    *time.Time `json:"lts,omitempty"`
	Pts    *time.Time `json:"pts,omitempty"`
	Src    string     `json:"src_ip"`
	Sport  int        `json:"src_port"`
	Dst    string     `json:"dst_ip"`
	Dport  int        `json:"dst_port"`
	Proto  int        `json:"proto"`
	Vlan   uint16     `json:"vlan"`
	Qtm    float64    `json:"qtm,omitempty"`
}

type CacheEntry struct {
	Record     PDNS
	LastSeen   time.Time
	PrintedCnt int
}

type cxtdb struct {
	cxt map[string]DNSQnR
	m   sync.RWMutex
}

type dnsdb struct {
	Key map[string]*CacheEntry
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
		Cachedb:            dnsdb{Key: make(map[string]*CacheEntry)},
		wg:                 wg,
	}
}

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
	if dns.QR {
		ukey = fmt.Sprintf("%d%d%d%d%s%s%d", dns.ID, proto, dport, sport, dst, src, vlan)
		tmpflow.src, tmpflow.dst = dst, src
		tmpflow.sport, tmpflow.dport = dport, sport
	} else {
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

func formatAnswer(ans layers.DNSResourceRecord) (string, string) {
	var ansStr string
	var ansType string

	ansType = ans.Type.String()

	switch ans.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		ansStr = ans.IP.String()
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		ansStr = string(ans.CNAME)
		if ansStr == "" {
			ansStr = string(ans.NS)
		}
		if ansStr == "" {
			ansStr = string(ans.PTR)
		}
	case layers.DNSTypeMX:
		ansStr = fmt.Sprintf("%d %s", ans.MX.Preference, string(ans.MX.Name))
	case layers.DNSTypeTXT:
		var parts []string
		for _, b := range ans.TXTs {
			parts = append(parts, string(b))
		}
		ansStr = strings.Join(parts, "")
	case layers.DNSTypeSOA:
		ansStr = fmt.Sprintf("%s %s %d", string(ans.SOA.MName), string(ans.SOA.RName), ans.SOA.Serial)
	default:
		if len(ans.Data) > 0 {
			ansStr = fmt.Sprintf("DATA[%d bytes]", len(ans.Data))
		}
	}
	return ansStr, ansType
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
			Sport: entry.flow.sport,
			Dport: entry.flow.dport,
			Dst:   entry.flow.dst,
			Proto: entry.flow.proto,
			Vlan:  entry.flow.vlan,
			Pts:   &now,
		}

		if dns.QR {
			pdns.Rc = dns.ResponseCode.String()

			var answers []string
			var lastType string
			var lastTtl uint32

			for _, answer := range dns.Answers {
				str, t := formatAnswer(answer)
				if str != "" {
					answers = append(answers, str)
				}
				lastType = t
				lastTtl = answer.TTL
			}

			pdns.Answer = answers
			pdns.Atype = lastType
			pdns.Ttl = lastTtl

			if len(answers) == 0 && dns.ResponseCode != layers.DNSResponseCodeNoErr {
				pdns.Answer = []string{dns.ResponseCode.String()}
			}

			p.LogChan <- pdns
		} else {
			if len(dns.Questions) > 0 {
				pdns.Query = string(dns.Questions[0].Name)
				pdns.Qtype = dns.Questions[0].Type.String()
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
		questionType := entry.query.Questions[0].Type.String()
		responseCode := entry.answer.ResponseCode.String()

		createPDNS := func(answers []string, answerType string, ttl uint32) PDNS {
			return PDNS{
				Query:  questionName,
				Qtype:  questionType,
				Answer: answers,
				Atype:  answerType,
				Rc:     responseCode,
				Ttl:    ttl,
				Cnt:    1,
				Fts:    &entry.qts,
				Lts:    &entry.ats,
				Qid:    entry.flow.qid,
				Src:    entry.flow.src,
				Sport:  entry.flow.sport,
				Dport:  entry.flow.dport,
				Dst:    entry.flow.dst,
				Proto:  entry.flow.proto,
				Vlan:   entry.flow.vlan,
				Qtm:    tsDiff,
				Pts:    &currentTimestamp,
			}
		}

		if isErrorResponse {
			pdnsRecord := createPDNS([]string{}, questionType, 0)
			if config.C.Cache {
				cacheKey := questionName + ":" + questionType + ":" + responseCode
				p.processCacheEntry(cacheKey, pdnsRecord, adjustedTimestamp)
			} else {
				p.LogChan <- pdnsRecord
			}

		} else {
			var answers []string
			var lastTtl uint32
			var lastType string

			for _, answer := range entry.answer.Answers {
				ansStr, ansType := formatAnswer(answer)
				if ansStr != "" {
					answers = append(answers, ansStr)
					lastType = ansType
					lastTtl = answer.TTL
				}
			}
			if len(answers) > 0 {
				sort.Strings(answers)

				pdnsRecord := createPDNS(answers, lastType, lastTtl)

				if config.C.Cache {
					joinedAnswers := strings.Join(answers, ",")
					cacheKey := fmt.Sprintf("%s|%s|%s|%s|%d|%d",
						questionName, lastType, joinedAnswers,
						pdnsRecord.Dst, pdnsRecord.Dport, pdnsRecord.Proto)

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
	p.Cachedb.M.Lock()
	defer p.Cachedb.M.Unlock()

	entry, exists := p.Cachedb.Key[cacheKey]

	if exists {
		entry.Record.Cnt++
		entry.Record.Lts = pdnsRecord.Lts

		// FIXED: Update the Source IP/Port to the latest one we saw
		entry.Record.Src = pdnsRecord.Src
		entry.Record.Sport = pdnsRecord.Sport

		entry.LastSeen = time.Now()
	} else {
		p.LogChan <- pdnsRecord
		p.Cachedb.Key[cacheKey] = &CacheEntry{
			Record:     pdnsRecord,
			LastSeen:   time.Now(),
			PrintedCnt: 1,
		}
	}
}

func (p *Parser) FlushDB() {
	p.Cachedb.M.Lock()
	defer p.Cachedb.M.Unlock()

	slog.Debug("Flushing CacheDB", "count", len(p.Cachedb.Key))

	for ukey, entry := range p.Cachedb.Key {
		delta := entry.Record.Cnt - entry.PrintedCnt
		if delta > 0 {
			outRecord := entry.Record
			outRecord.Cnt = delta
			now := time.Now()
			outRecord.Pts = &now
			p.LogChan <- outRecord
		}
		delete(p.Cachedb.Key, ukey)
	}
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

	cleanTimer := time.NewTicker(time.Second * 5)
	defer cleanTimer.Stop()

	for {
		select {
		case <-cleanTimer.C:
			ts := time.Now().Add(cachetime)
			tsn := time.Now()

			p.Cachedb.M.Lock()
			for ukey, entry := range p.Cachedb.Key {
				if entry.LastSeen.Before(ts) {
					delta := entry.Record.Cnt - entry.PrintedCnt
					if delta > 0 {
						outRecord := entry.Record
						outRecord.Cnt = delta
						outRecord.Pts = &tsn
						p.LogChan <- outRecord
					}
					delete(p.Cachedb.Key, ukey)
				}
			}
			p.Cachedb.M.Unlock()

			ts = time.Now().Add(cxttimeout)
			var cxtKeysToDelete []string

			p.cxt.m.RLock()
			for ukey, dnscxt := range p.cxt.cxt {
				if dnscxt.qts.Before(ts) || dnscxt.ats.Before(ts) {
					cxtKeysToDelete = append(cxtKeysToDelete, ukey)
				}
			}
			p.cxt.m.RUnlock()

			if len(cxtKeysToDelete) > 0 {
				p.cxt.m.Lock()
				for _, k := range cxtKeysToDelete {
					delete(p.cxt.cxt, k)
				}
				p.cxt.m.Unlock()
			}

		case <-stopChan:
			slog.Info("Shutting down DBMaintenance...")
			p.FlushDB()
			return
		}
	}
}
