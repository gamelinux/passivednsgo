package reassembler

import (
	"encoding/binary"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"passivednsgo/internal/common"
)

type TcpStreamFactory struct {
	VLANID uint16
	Out    chan common.TcpStreamData // Dependency Injection
}

type tcpStream struct {
	net, transport      gopacket.Flow
	vlanID              uint16
	r                   tcpreader.ReaderStream
	bytes, packets      int64
	outOfOrder, skipped int64
	start, end          time.Time
	sawStart, sawEnd    bool
	out                 chan common.TcpStreamData // Local Ref
}

func (factory *TcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &tcpStream{
		net:       net,
		transport: transport,
		vlanID:    factory.VLANID,
		start:     time.Now(),
		out:       factory.Out, // Pass the channel down
	}
	s.end = s.start
	return s
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Seen.Before(s.end) {
			s.outOfOrder++
		} else {
			s.end = reassembly.Seen
		}
		s.bytes += int64(len(reassembly.Bytes))
		s.packets++
		if reassembly.Skip > 0 {
			s.skipped += int64(reassembly.Skip)
		}
		s.sawStart = s.sawStart || reassembly.Start
		s.sawEnd = s.sawEnd || reassembly.End

		if len(reassembly.Bytes) > 2 && len(reassembly.Bytes) >= int(binary.BigEndian.Uint16(reassembly.Bytes[:2]))+2 {
			s.out <- common.TcpStreamData{
				Data:      reassembly.Bytes[2 : int(binary.BigEndian.Uint16(reassembly.Bytes[:2]))+2],
				NetFlow:   s.net,
				Transport: s.transport,
				Len:       int(len(reassembly.Bytes)),
				VLANID:    s.vlanID,
				Timestamp: reassembly.Seen,
			}
		}
	}
}

func (s *tcpStream) ReassemblyComplete() {
	// Optional logging could go here if you re-add the import.
}
