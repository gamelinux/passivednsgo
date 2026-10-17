package dnsparser

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/gopacket/layers"
	"passivednsgo/internal/config"
	"passivednsgo/internal/dnsstrings" // ADDED IMPORT
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

// PDNSTime is UTC with exactly six fractional digits and a Z suffix.
type PDNSTime time.Time

func (t PDNSTime) MarshalJSON() ([]byte, error) {
	formatted := time.Time(t).UTC().Format("2006-01-02T15:04:05.000000Z")
	return []byte(`"` + formatted + `"`), nil
}

// Qtm is seconds with exactly six digits after the decimal.
type Qtm float64

func (q Qtm) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%.6f", float64(q))), nil
}

type PDNS struct {
	Query  string   `json:"query"`
	Qtype  string   `json:"qtype"`
	Answer []string `json:"answer"`
	Atype  string   `json:"atype"`
	Qid    uint16   `json:"qid"`
	Rc     string   `json:"rc"`
	Ttl    uint32   `json:"ttl"`
	Cnt    int      `json:"cnt"`
	Fts    PDNSTime `json:"fts"`
	Lts    PDNSTime `json:"lts"`
	Pts    PDNSTime `json:"pts"`
	Src    string   `json:"src_ip"`
	Sport  int      `json:"src_port"`
	Dst    string   `json:"dst_ip"`
	Dport  int      `json:"dst_port"`
	Proto  int      `json:"proto"`
	Vlan   uint16   `json:"vlan"`
	Qtm    Qtm      `json:"qtm"`
}

type CacheEntry struct {
	Record      PDNS
	LastSeen    time.Time
	LastPrinted time.Time
	PrintedCnt  int
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

		// dnspair is a copy. Write it back, or a retried query keeps
		// the first timestamp and qtm is too large.
		ready := dnspair.aseen && dnspair.qseen && dnspair.query.Questions != nil
		if ready {
			p.BidirectionalChan <- dnspair
		}
		p.cxt.m.Lock()
		if ready {
			delete(p.cxt.cxt, ukey)
		} else {
			p.cxt.cxt[ukey] = dnspair
		}
		p.cxt.m.Unlock()
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

func stripDot(s string) string {
	if len(s) > 1 && strings.HasSuffix(s, ".") {
		return s[:len(s)-1]
	}
	return s
}

func charStrings(data []byte) string {
	var b strings.Builder
	for pos := 0; pos < len(data); {
		n := int(data[pos])
		pos++
		if pos+n > len(data) {
			break
		}
		b.Write(data[pos : pos+n])
		pos += n
	}
	return b.String()
}

func uncompressedName(data []byte) (string, bool) {
	var b strings.Builder
	pos := 0
	for pos < len(data) {
		n := int(data[pos])
		pos++
		if n == 0 {
			if b.Len() == 0 {
				return ".", true
			}
			return b.String(), true
		}
		if n&0xc0 == 0xc0 {
			return "", false
		}
		if pos+n > len(data) {
			return "", false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(data[pos : pos+n])
		pos += n
	}
	return "", false
}

func formatAnswer(ans layers.DNSResourceRecord) (string, string) {
	var ansStr string
	ansType := dnsstrings.DNSTypeString(ans.Type)

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
		ansStr = stripDot(ansStr)
	case layers.DNSType(39): // DNAME
		if name, ok := uncompressedName(ans.Data); ok {
			ansStr = name
		} else if len(ans.Data) > 0 {
			ansStr = fmt.Sprintf("DATA[%d bytes]", len(ans.Data))
		}
	case layers.DNSTypeMX:
		ansStr = fmt.Sprintf("%d %s", ans.MX.Preference, stripDot(string(ans.MX.Name)))
	case layers.DNSTypeTXT:
		var parts []string
		for _, b := range ans.TXTs {
			parts = append(parts, string(b))
		}
		ansStr = strings.Join(parts, "")
	case layers.DNSType(99): // SPF
		ansStr = charStrings(ans.Data)
	case layers.DNSTypeSOA:
		ansStr = fmt.Sprintf("%s %s %d", stripDot(string(ans.SOA.MName)), stripDot(string(ans.SOA.RName)), ans.SOA.Serial)
	case layers.DNSTypeSRV:
		ansStr = fmt.Sprintf("%d %d %d %s", ans.SRV.Priority, ans.SRV.Weight, ans.SRV.Port, stripDot(string(ans.SRV.Name)))
	case layers.DNSType(dnsstrings.DNSTypeHTTPS), layers.DNSType(dnsstrings.DNSTypeSVCB):
		ansStr = parseHTTPSRecord(ans.Data)
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
			Qid:    dns.ID,
			Src:    entry.flow.src,
			Sport:  entry.flow.sport,
			Dport:  entry.flow.dport,
			Dst:    entry.flow.dst,
			Proto:  entry.flow.proto,
			Vlan:   entry.flow.vlan,
			Pts:    PDNSTime(now),
			Answer: []string{},
		}

		if dns.QR {
			pdns.Rc = dnsstrings.DNSResponseCodeString(dns.ResponseCode)

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

			if answers == nil {
				answers = []string{}
			}
			pdns.Answer = answers
			pdns.Atype = lastType
			pdns.Ttl = lastTtl

			if len(answers) == 0 && dns.ResponseCode != layers.DNSResponseCodeNoErr {
				pdns.Answer = []string{pdns.Rc} // Log the RC code as answer on error
			}

			p.LogChan <- pdns
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

	for entry := range p.BidirectionalChan {
		currentTimestamp := time.Now()

		tsDiff := math.Abs(entry.ats.Sub(entry.qts).Seconds())
		if tsDiff > 9223370000 {
			tsDiff = 9223372037 - tsDiff
		}

		isErrorResponse := entry.answer.ResponseCode != 0
		questionName := stripDot(string(entry.query.Questions[0].Name))
		questionType := dnsstrings.DNSTypeString(entry.query.Questions[0].Type)

		responseCode := dnsstrings.DNSResponseCodeString(entry.answer.ResponseCode)

		createPDNS := func(answers []string, answerType string, ttl uint32) PDNS {
			if answers == nil {
				answers = []string{}
			}
			return PDNS{
				Query:  questionName,
				Qtype:  questionType,
				Answer: answers,
				Atype:  answerType,
				Rc:     responseCode,
				Ttl:    ttl,
				Cnt:    1,
				Fts:    PDNSTime(entry.qts),
				Lts:    PDNSTime(entry.ats),
				Qid:    entry.flow.qid,
				Src:    entry.flow.src,
				Sport:  entry.flow.sport,
				Dport:  entry.flow.dport,
				Dst:    entry.flow.dst,
				Proto:  entry.flow.proto,
				Vlan:   entry.flow.vlan,
				Qtm:    Qtm(tsDiff),
				Pts:    PDNSTime(currentTimestamp),
			}
		}

		if isErrorResponse {
			// On error (NXDOMAIN), use QuestionType as AType (Standard practice)
			pdnsRecord := createPDNS([]string{}, questionType, 0)

			if config.C.Cache {
				cacheKey := questionName + ":" + questionType + ":" + responseCode
				p.processCacheEntry(cacheKey, pdnsRecord)
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
					cacheKey := questionName + ":" + lastType + ":" + joinedAnswers
					p.processCacheEntry(cacheKey, pdnsRecord)
				} else {
					p.LogChan <- pdnsRecord
				}
			}
		}
	}
	p.FlushDB()
	slog.Info("Bidirectional Routine Stopped")
}

func (p *Parser) processCacheEntry(cacheKey string, pdnsRecord PDNS) {
	p.Cachedb.M.Lock()
	defer p.Cachedb.M.Unlock()

	entry, exists := p.Cachedb.Key[cacheKey]

	if exists {
		entry.Record.Cnt++
		entry.Record.Lts = pdnsRecord.Lts
		entry.Record.Src = pdnsRecord.Src
		entry.Record.Sport = pdnsRecord.Sport
		entry.Record.Dst = pdnsRecord.Dst
		entry.Record.Dport = pdnsRecord.Dport
		entry.Record.Proto = pdnsRecord.Proto
		entry.Record.Vlan = pdnsRecord.Vlan
		entry.Record.Qid = pdnsRecord.Qid
		entry.Record.Qtm = pdnsRecord.Qtm

		if pdnsRecord.Ttl > entry.Record.Ttl {
			entry.Record.Ttl = pdnsRecord.Ttl
		}

		entry.LastSeen = time.Now()
	} else {
		p.LogChan <- pdnsRecord
		p.Cachedb.Key[cacheKey] = &CacheEntry{
			Record:      pdnsRecord,
			LastSeen:    time.Now(),
			LastPrinted: time.Now(),
			PrintedCnt:  1,
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
			outRecord.Pts = PDNSTime(now)
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

	printDuration, err := time.ParseDuration(config.C.Printtime)
	if err != nil {
		slog.Error("Failed to parse Printtime", "error", err)
		return
	}

	cxttimeout, err := time.ParseDuration("-" + config.C.CXTtimeout)
	if err != nil {
		slog.Error("Failed to parse CXTtimeout", "error", err)
		return
	}

	checkInterval, err := time.ParseDuration(config.C.CheckInterval)
	if err != nil {
		slog.Error("Failed to parse CheckInterval", "error", err)
		checkInterval = 5 * time.Second
	}

	cleanTimer := time.NewTicker(checkInterval)
	defer cleanTimer.Stop()

	for {
		select {
		case <-cleanTimer.C:
			evictionThreshold := time.Now().Add(cachetime)
			now := time.Now()

			p.Cachedb.M.Lock()

			for ukey, entry := range p.Cachedb.Key {
				if entry.LastSeen.Before(evictionThreshold) {
					delta := entry.Record.Cnt - entry.PrintedCnt
					if delta > 0 {
						outRecord := entry.Record
						outRecord.Cnt = delta
						outRecord.Pts = PDNSTime(now)
						p.LogChan <- outRecord
					}
					delete(p.Cachedb.Key, ukey)
					continue
				}

				timeSincePrint := now.Sub(entry.LastPrinted)
				if timeSincePrint > printDuration {
					delta := entry.Record.Cnt - entry.PrintedCnt
					if delta > 0 {
						outRecord := entry.Record
						outRecord.Cnt = delta
						outRecord.Pts = PDNSTime(now)
						p.LogChan <- outRecord
						entry.PrintedCnt = entry.Record.Cnt
						entry.LastPrinted = now
					}
				}
			}
			p.Cachedb.M.Unlock()

			ts := time.Now().Add(cxttimeout)
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

func svcKeyName(key uint16) string {
	switch key {
	case 0:
		return "mandatory"
	case 1:
		return "alpn"
	case 2:
		return "no-default-alpn"
	case 3:
		return "port"
	case 4:
		return "ipv4hint"
	case 5:
		return "ech"
	case 6:
		return "ipv6hint"
	case 7:
		return "dohpath"
	default:
		return fmt.Sprintf("key%d", key)
	}
}

func svcEscape(val []byte, quoteSpace bool) string {
	quote := false
	if quoteSpace {
		for _, c := range val {
			if unicode.IsSpace(rune(c)) {
				quote = true
				break
			}
		}
	}
	var b strings.Builder
	if quote {
		b.WriteByte('"')
	}
	for _, c := range val {
		if c == '"' || c == '\\' || (quoteSpace && c == ',') {
			b.WriteByte('\\')
			b.WriteByte(c)
		} else if c == '\t' || (c >= 0x20 && c < 0x7f) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\%03d", c)
		}
	}
	if quote {
		b.WriteByte('"')
	}
	return b.String()
}

func svcAlpn(val []byte) string {
	quote := false
	for p := 0; p < len(val); {
		n := int(val[p])
		p++
		if p+n > len(val) {
			break
		}
		for _, c := range val[p : p+n] {
			if unicode.IsSpace(rune(c)) {
				quote = true
			}
		}
		p += n
	}
	var b strings.Builder
	if quote {
		b.WriteByte('"')
	}
	first := true
	for p := 0; p < len(val); {
		n := int(val[p])
		p++
		if p+n > len(val) {
			break
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		for _, c := range val[p : p+n] {
			if c == '"' || c == '\\' || c == ',' {
				b.WriteByte('\\')
				b.WriteByte(c)
			} else if c == '\t' || (c >= 0x20 && c < 0x7f) {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "\\%03d", c)
			}
		}
		p += n
	}
	if quote {
		b.WriteByte('"')
	}
	return b.String()
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	pos := 0
	priority := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	target, ok := uncompressedName(data[pos:])
	if !ok {
		return ""
	}
	// Walk the same name so the parameter offset is right.
	for pos < len(data) {
		n := int(data[pos])
		pos++
		if n == 0 {
			break
		}
		if n&0xc0 == 0xc0 || pos+n > len(data) {
			return ""
		}
		pos += n
	}

	parts := []string{fmt.Sprintf("%d %s", priority, target)}
	for pos+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[pos : pos+2])
		valLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+valLen > len(data) {
			break
		}
		val := data[pos : pos+valLen]
		pos += valLen
		name := svcKeyName(key)
		if valLen == 0 {
			parts = append(parts, name)
			continue
		}
		var rendered string
		switch key {
		case 0: // mandatory
			var keys []string
			for i := 0; i+2 <= len(val); i += 2 {
				keys = append(keys, svcKeyName(binary.BigEndian.Uint16(val[i:i+2])))
			}
			rendered = strings.Join(keys, ",")
		case 1:
			rendered = svcAlpn(val)
		case 3:
			if len(val) == 2 {
				rendered = fmt.Sprintf("%d", binary.BigEndian.Uint16(val))
			}
		case 4:
			if len(val)%4 == 0 {
				var ips []string
				for i := 0; i < len(val); i += 4 {
					ips = append(ips, net.IP(val[i:i+4]).String())
				}
				rendered = strings.Join(ips, ",")
			}
		case 5:
			rendered = base64.StdEncoding.EncodeToString(val)
		case 6:
			if len(val)%16 == 0 {
				var ips []string
				for i := 0; i < len(val); i += 16 {
					ips = append(ips, net.IP(val[i:i+16]).String())
				}
				rendered = strings.Join(ips, ",")
			}
		default:
			rendered = svcEscape(val, true)
		}
		if rendered == "" {
			continue
		}
		parts = append(parts, name+"="+rendered)
	}
	return strings.Join(parts, " ")
}
