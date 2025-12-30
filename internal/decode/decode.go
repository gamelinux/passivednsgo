package decode

import (
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"

	"passivednsgo/internal/capture"
	"passivednsgo/internal/common"
	"passivednsgo/internal/dnsparser"
	"passivednsgo/internal/reassembler"
)

func DecodePacket(wg *sync.WaitGroup, id int, packetChan <-chan *capture.PacketObject, reassembleChan chan common.TcpStreamData, parser *dnsparser.Parser) {
	defer wg.Done()

	// Initialize decoder
	var vlan layers.Dot1Q
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	parserLayer := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &vlan, &eth, &ip4, &ip6, &udp, &tcp, &dns)
	decoded := []gopacket.LayerType{}
	var objects int64 = 0

	// Reassembling TCP Streams
	reassembleTimer := time.NewTicker(time.Minute)
	defer reassembleTimer.Stop()

	streamFactory := &reassembler.TcpStreamFactory{Out: reassembleChan}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesPerConnection = 0
	assembler.MaxBufferedPagesTotal = 0

	slog.Debug("Decode Routine Started", "id", id)

	for {
		select {
		// 1. Process Raw Packets
		case po, open := <-packetChan:
			if !open {
				// Packet Source is done. Flush assembler and exit.
				assembler.FlushAll()
				slog.Debug("Decode Routine Stopping", "id", id)
				return
			}
			objects++
			packet := po.Packet
			if err := parserLayer.DecodeLayers(packet, &decoded); err != nil {
				// slog.Debug("Could not decode initial layers", "id", id)
			}
			parserLayer.DecodeLayers(packet, &decoded)

			var VlanID uint16
			var SrcIP, DstIP string
			var NetFlow gopacket.Flow
			var FoundNetLayer bool

			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeDot1Q:
					VlanID = vlan.VLANIdentifier
					streamFactory.VLANID = VlanID
				case layers.LayerTypeIPv6:
					SrcIP = ip6.SrcIP.String()
					DstIP = ip6.DstIP.String()
					FoundNetLayer = true
					NetFlow = ip6.NetworkFlow()
				case layers.LayerTypeIPv4:
					SrcIP = ip4.SrcIP.String()
					DstIP = ip4.DstIP.String()
					NetFlow = ip4.NetworkFlow()
					FoundNetLayer = true
				case layers.LayerTypeTCP:
					if FoundNetLayer {
						assembler.AssembleWithTimestamp(NetFlow, &tcp, po.Timestamp)
					}
				case layers.LayerTypeUDP:
					if FoundNetLayer {
						dnsLayer := &layers.DNS{}
						p := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dnsLayer)
						var dnsDecoded []gopacket.LayerType
						err := p.DecodeLayers(udp.Payload, &dnsDecoded)
						if err == nil {
							// FIX: Pass ints directly
							SrcPort := int(udp.SrcPort)
							DstPort := int(udp.DstPort)
							parser.ParseDNS(po.Timestamp, VlanID, SrcIP, SrcPort, DstIP, DstPort, 17, *dnsLayer)
						}
					}
				}
			}

		// 2. Periodic Flushing
		case <-reassembleTimer.C:
			assembler.FlushOlderThan(time.Now().Add(time.Second * -60))
		}
	}
}

// Separate routine to handle the shared reassembly channel
func ProcessReassembledStreams(wg *sync.WaitGroup, reassembleChan <-chan common.TcpStreamData, parser *dnsparser.Parser) {
	defer wg.Done()
	slog.Info("TCP Stream Processor Started")

	for tcpData := range reassembleChan {
		if len(tcpData.Data) >= 6 {
			src, dst := tcpData.NetFlow.Endpoints()
			sport, dport := tcpData.Transport.Endpoints()

			// Convert Endpoint string to Int
			srcPortInt, _ := strconv.Atoi(sport.String())
			dstPortInt, _ := strconv.Atoi(dport.String())

			dnsLayer := &layers.DNS{}
			var dnsDecoded []gopacket.LayerType
			p := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dnsLayer)
			err := p.DecodeLayers(tcpData.Data, &dnsDecoded)
			if err == nil {
				parser.ParseDNS(tcpData.Timestamp, tcpData.VLANID, src.String(), srcPortInt, dst.String(), dstPortInt, 6, *dnsLayer)
			}
		}
	}
	slog.Info("TCP Stream Processor Stopped")
}
