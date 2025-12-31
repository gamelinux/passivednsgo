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
		Unidir:        false,
		Cache:         false,
		Printtime:     "1s",
		Cachetime:     "1s",
		CXTtimeout:    "1s",
		CheckInterval: "1s",
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

func TestCache_Aggregation_DifferentIPs(t *testing.T) {
	// THIS TEST VERIFIES THE NEW "GENERAL CACHE" LOGIC
	setupTestConfig()
	config.C.Cache = true

	var wg sync.WaitGroup
	uniChan := make(chan DNSQoR, 10)
	biChan := make(chan DNSQnR, 10)
	logChan := make(chan PDNS, 100)

	parser := NewParser(&wg, uniChan, biChan, logChan)

	wg.Add(1)
	go parser.Bidirectional()

	// Data Setup
	q := layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte("general.com"), Type: layers.DNSTypeA}}}
	a := layers.DNS{ResponseCode: 0, Answers: []layers.DNSResourceRecord{{Name: []byte("general.com"), Type: layers.DNSTypeA, IP: []byte{1, 1, 1, 1}, TTL: 300}}}

	// Packet 1: User A
	flow1 := SevenTuple{proto: 17, src: "10.0.0.1", sport: 1001, dst: "8.8.8.8", dport: 53}
	pair1 := DNSQnR{flow: flow1, query: q, answer: a, qts: time.Now(), ats: time.Now()}

	// Packet 2: User B (Different IP/Port, SAME Query/Answer)
	flow2 := SevenTuple{proto: 17, src: "192.168.0.55", sport: 9999, dst: "8.8.8.8", dport: 53}
	pair2 := DNSQnR{flow: flow2, query: q, answer: a, qts: time.Now(), ats: time.Now()}

	// Send Packet 1 -> Should print immediately (Count 1)
	biChan <- pair1

	// Send Packet 2 -> Should NOT print, but increment cache count to 2
	// AND update the Source IP in the cache to 192.168.0.55
	biChan <- pair2

	close(biChan) // Triggers Flush
	wg.Wait()

	// --- Verification ---

	// 1. First Output (Immediate)
	select {
	case pdns := <-logChan:
		if pdns.Cnt != 1 {
			t.Errorf("Packet 1: Expected Count 1, got %d", pdns.Cnt)
		}
		if pdns.Src != "10.0.0.1" {
			t.Errorf("Packet 1: Expected Src 10.0.0.1, got %s", pdns.Src)
		}
	default:
		t.Fatal("Packet 1: No output received")
	}

	// 2. Second Output (Flush/Delta)
	select {
	case pdns := <-logChan:
		// We expect the Delta (Total 2 - Printed 1 = 1)
		// But crucial check: Did the Source IP update to the latest packet?
		if pdns.Cnt != 1 {
			t.Errorf("Packet 2 (Flush): Expected Delta Count 1, got %d", pdns.Cnt)
		}
		if pdns.Src != "192.168.0.55" {
			t.Errorf("Packet 2 (Flush): Expected Source IP to update to 192.168.0.55, got %s", pdns.Src)
		}
	default:
		t.Fatal("Packet 2 (Flush): No output received")
	}
}

func TestCache_Heartbeat(t *testing.T) {
	// Tests the Heartbeat logic by manipulating the timestamp manually
	setupTestConfig()
	config.C.Cache = true
	config.C.Printtime = "1s" // Short heartbeat

	var wg sync.WaitGroup
	uniChan := make(chan DNSQoR, 10)
	biChan := make(chan DNSQnR, 10)
	logChan := make(chan PDNS, 100)

	parser := NewParser(&wg, uniChan, biChan, logChan)

	// Don't run the full bidirectional routine to avoid race conditions with our manual manipulation
	// We will manually invoke the cache logic

	// 1. Create Entry
	pdns := PDNS{Query: "heartbeat.com", Cnt: 1} // simplified

	// 2. Insert into Cache (First seen)
	cacheKey := "test-key"
	parser.processCacheEntry(cacheKey, pdns) // Logs 1, Printed=1

	// Consume the first log
	<-logChan

	// 3. Update Cache (Traffic continues)
	parser.processCacheEntry(cacheKey, pdns) // Count=2, Printed=1
	parser.processCacheEntry(cacheKey, pdns) // Count=3, Printed=1

	// 4. Hack the "LastPrinted" time to simulate 2 hours passing
	parser.Cachedb.M.Lock()
	entry := parser.Cachedb.Key[cacheKey]
	entry.LastPrinted = time.Now().Add(-2 * time.Hour) // Way past PrintTime (1s)
	parser.Cachedb.M.Unlock()

	// 5. Run DBMaintenance manually once
	// We need a stopper channel
	stop := make(chan bool)
	go func() {
		time.Sleep(100 * time.Millisecond)
		stop <- true
	}()

	wg.Add(1)
	parser.DBMaintenance(stop)

	// 6. Verify we got the Heartbeat Log
	select {
	case log := <-logChan:
		// We had 3 total, printed 1. Delta is 2.
		if log.Cnt != 2 {
			t.Errorf("Heartbeat: Expected Delta Count 2, got %d", log.Cnt)
		}
	default:
		t.Fatal("Heartbeat: Expected log entry after maintenance, got none")
	}
}
