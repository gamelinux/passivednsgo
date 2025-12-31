package dnsparser

import (
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"passivednsgo/internal/config"
)

// setupTestConfig initializes the global config with safe defaults for testing
func setupTestConfig() {
	config.C = &config.Config{
		Unidir:    false,
		Cache:     false,
		Printtime: "1s",
		Cachetime: "1s",
	}
}

func TestParseDNS_Correlation(t *testing.T) {
	setupTestConfig()

	// 1. Setup Channels and Parser
	var wg sync.WaitGroup
	uniChan := make(chan DNSQoR, 10)
	biChan := make(chan DNSQnR, 10)
	logChan := make(chan PDNS, 10)

	parser := NewParser(&wg, uniChan, biChan, logChan)

	// 2. Define standard test data
	tsStart := time.Now()
	vlan := uint16(10)
	srcIP := "192.168.1.50"
	dstIP := "8.8.8.8"
	srcPort := 40000
	dstPort := 53
	proto := 17 // UDP
	txID := uint16(12345)

	// 3. Create a Query Packet (Mock)
	dnsQuery := layers.DNS{
		ID:           txID,
		QR:           false, // Query
		OpCode:       layers.DNSOpCodeQuery,
		Questions:    []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA}},
		ResponseCode: 0,
	}

	parser.ParseDNS(tsStart, vlan, srcIP, srcPort, dstIP, dstPort, proto, dnsQuery)

	parser.cxt.m.RLock()
	if len(parser.cxt.cxt) != 1 {
		t.Errorf("Expected 1 entry in context DB, got %d", len(parser.cxt.cxt))
	}
	parser.cxt.m.RUnlock()

	// 5. Create a Response Packet (Mock)
	tsEnd := tsStart.Add(50 * time.Millisecond)
	dnsResponse := layers.DNS{
		ID:           txID,
		QR:           true, // Response
		OpCode:       layers.DNSOpCodeQuery,
		Questions:    []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA}},
		Answers:      []layers.DNSResourceRecord{{Name: []byte("example.com"), Type: layers.DNSTypeA, IP: []byte{1, 2, 3, 4}, TTL: 300}},
		ResponseCode: 0,
	}

	parser.ParseDNS(tsEnd, vlan, dstIP, dstPort, srcIP, srcPort, proto, dnsResponse)

	// 7. Verify correlation
	select {
	case entry := <-biChan:
		if entry.query.ID != txID {
			t.Errorf("Expected Transaction ID %d, got %d", txID, entry.query.ID)
		}
		if entry.flow.src != srcIP {
			t.Errorf("Expected Source IP %s, got %s", srcIP, entry.flow.src)
		}
	default:
		t.Fatal("Failed to correlate Query and Response: No entry in BidirectionalChan")
	}

	parser.cxt.m.RLock()
	if len(parser.cxt.cxt) != 0 {
		t.Errorf("Context DB should be empty after correlation, has %d entries", len(parser.cxt.cxt))
	}
	parser.cxt.m.RUnlock()
}

func TestBidirectional_Processing(t *testing.T) {
	setupTestConfig()
	config.C.Cache = false

	var wg sync.WaitGroup
	uniChan := make(chan DNSQoR, 10)
	biChan := make(chan DNSQnR, 10)
	logChan := make(chan PDNS, 10)

	parser := NewParser(&wg, uniChan, biChan, logChan)

	wg.Add(1)
	go parser.Bidirectional()

	flow := SevenTuple{
		proto: 17,
		qid:   999,
		src:   "10.0.0.1",
		dst:   "1.1.1.1",
		sport: 3000,
		dport: 53,
		vlan:  5,
	}

	ts := time.Now()
	pair := DNSQnR{
		flow:  flow,
		qts:   ts,
		ats:   ts.Add(100 * time.Millisecond),
		query: layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte("google.com"), Type: layers.DNSTypeA}}},
		answer: layers.DNS{
			ResponseCode: 0,
			Answers: []layers.DNSResourceRecord{
				{Name: []byte("google.com"), Type: layers.DNSTypeA, IP: []byte{8, 8, 8, 8}, TTL: 120},
			},
		},
	}

	biChan <- pair
	close(biChan)

	wg.Wait()

	select {
	case pdns := <-logChan:
		if pdns.Query != "google.com" {
			t.Errorf("Expected Query google.com, got %s", pdns.Query)
		}
		if pdns.Sport != 3000 {
			t.Errorf("Expected Sport 3000, got %d", pdns.Sport)
		}

		// Check for JSON Array format
		if len(pdns.Answer) == 0 || pdns.Answer[0] != "8.8.8.8" {
			t.Errorf("Expected Answer [8.8.8.8], got %v", pdns.Answer)
		}

		if pdns.Qtm < 0.09 || pdns.Qtm > 0.11 {
			t.Errorf("Latency calculation off. Expected ~0.1, got %f", pdns.Qtm)
		}
	default:
		t.Fatal("No PDNS record generated")
	}
}

func TestCache_Deduplication(t *testing.T) {
	setupTestConfig()
	config.C.Cache = true // Enable Cache!

	var wg sync.WaitGroup
	uniChan := make(chan DNSQoR, 10)
	biChan := make(chan DNSQnR, 10)
	logChan := make(chan PDNS, 100) // Large buffer to hold sequential messages

	parser := NewParser(&wg, uniChan, biChan, logChan)

	wg.Add(1)
	go parser.Bidirectional()

	flow := SevenTuple{proto: 17, src: "1.2.3.4", sport: 123, dst: "5.6.7.8", dport: 53}
	q := layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte("cached.com"), Type: layers.DNSTypeA}}}
	a := layers.DNS{ResponseCode: 0, Answers: []layers.DNSResourceRecord{{Name: []byte("cached.com"), Type: layers.DNSTypeA, IP: []byte{1, 1, 1, 1}, TTL: 300}}}

	pair := DNSQnR{flow: flow, query: q, answer: a, qts: time.Now(), ats: time.Now()}

	// Send SAME record 3 times
	biChan <- pair // Packet 1: Immediate Log (Cnt=1), Cache Printed=1, Total=1
	biChan <- pair // Packet 2: Cache Update -> Total=2
	biChan <- pair // Packet 3: Cache Update -> Total=3

	close(biChan) // Triggers FlushDB -> Delta = Total(3) - Printed(1) = 2. Emits Cnt=2.
	wg.Wait()

	// Step 1: Check for Immediate Output (Cnt=1)
	select {
	case pdns := <-logChan:
		if pdns.Cnt != 1 {
			t.Errorf("First packet should have Count 1 (Immediate), got %d", pdns.Cnt)
		}
	default:
		t.Fatal("Expected immediate output for first packet, got nothing")
	}

	// Step 2: Check for Flushed Output (Cnt=2)
	// We sent 3 total. We printed 1. The remaining delta is 2.
	select {
	case pdns := <-logChan:
		if pdns.Cnt != 2 {
			t.Errorf("Flushed packet should have aggregated Count 2 (Delta), got %d", pdns.Cnt)
		}
	default:
		t.Fatal("Expected flushed aggregated packet (Delta), got nothing")
	}
}
