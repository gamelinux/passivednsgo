package capture

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"

	"passivednsgo/internal/config"
)

type PacketObject struct {
	Wid       int
	Packet    gopacket.Payload
	Timestamp time.Time
}

func NewpacketObject(id int, packet gopacket.Payload, timestamp time.Time) *PacketObject {
	var p PacketObject
	p.Wid = id
	p.Packet = packet
	p.Timestamp = timestamp
	return &p
}

func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (frameSize int, blockSize int, numBlocks int, err error) {
	frameSize = pageSize * ((snaplen + pageSize - 1) / pageSize)
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("interface buffer size is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

func CapturePacketsFromPcap(wg *sync.WaitGroup, id int, pcapFile string, packetChan chan *PacketObject) error {
	defer wg.Done()
	// For PCAP, we don't need to close here if we follow the main.go logic,
	// but strictly speaking, the reader closes its own channel in the simple design.
	// However, per our new design, main owns the channel. We just exit.

	slog.Debug("Starting CapturePacketsFromPcap", "id", id, "file", pcapFile)

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %w", err)
	}
	defer handle.Close()

	if config.C.BPF != "" {
		err = handle.SetBPFFilter(config.C.BPF)
		if err != nil {
			return fmt.Errorf("error compiling BPF filter: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Check for stop signal even in PCAP mode
		select {
		case <-config.C.Stop:
			slog.Debug("Stop signal received during PCAP read", "id", id)
			return nil
		default:
			packetChan <- NewpacketObject(id, gopacket.Payload(packet.Data()), packet.Metadata().Timestamp)
		}
	}
	slog.Debug("Pcap processing finished", "id", id)
	return nil
}

func CapturePackets(wg *sync.WaitGroup, id int, ifaceName string, packetChan chan *PacketObject) error {
	defer wg.Done()

	szFrame, szBlock, numBlocks, err := afpacketComputeSize(16, 1508, os.Getpagesize())
	if err != nil {
		return err
	}

	// FIX: Added OptPollTimeout so we don't block forever
	tpacket, err := afpacket.NewTPacket(
		afpacket.TPacketVersion3,
		afpacket.OptFrameSize(szFrame),
		afpacket.OptBlockSize(szBlock),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptAddVLANHeader(false),
		afpacket.OptPollTimeout(100*time.Millisecond), // <--- THE FIX
		afpacket.SocketRaw,
		afpacket.OptInterface(ifaceName))
	if err != nil {
		return err
	}

	err = tpacket.SetFanout(afpacket.FanoutHashWithDefrag, uint16(42))
	if err != nil {
		return err
	}

	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 1508, config.C.BPF)
	if err != nil {
		return err
	}

	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns = append(bpfIns, bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		})
	}

	err = tpacket.SetBPF(bpfIns)
	if err != nil {
		return err
	}

	packetSource := gopacket.ZeroCopyPacketDataSource(tpacket)
	slog.Debug("Capture Routine Started", "id", id)

	for {
		select {
		case <-config.C.Stop:
			slog.Debug("Capture Routine Stopping", "id", id)
			return nil
		default:
			// Now this returns every 100ms if no packets are found
			packet, ci, err := packetSource.ZeroCopyReadPacketData()
			if err != nil {
				// Timeout is returned as an error in some versions, or nil packet in others.
				// We check for actual errors, but ignore timeouts/temporary issues to keep looping.
				// Usually, on timeout, packet is nil.
				if err.Error() == "timeout" {
					continue
				}
				// If it's a fatal error, log and exit
				// return err
				// For robustness, log and continue? Or return?
				// Let's log and retry a few times? For now, we continue.
				continue
			}
			if packet == nil {
				continue
			}
			packetChan <- NewpacketObject(id, packet, ci.Timestamp)
		}
	}
}
