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

// Same ceiling as passivedns TCP_STREAM_MAX.
const tcpStreamMax = 65537

type tcpStream struct {
	net, transport      gopacket.Flow
	vlanID              uint16
	r                   tcpreader.ReaderStream
	bytes, packets      int64
	outOfOrder, skipped int64
	start, end          time.Time
	sawStart, sawEnd    bool
	out                 chan common.TcpStreamData // Local Ref
	buf                 []byte                    // Length-prefixed DNS bytes still waiting
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

		// A gap cannot continue the previous message. The new bytes may
		// start another one, which is how passivedns resyncs.
		if reassembly.Skip > 0 {
			s.buf = nil
		}
		s.take(reassembly.Bytes, reassembly.Seen)
	}
}

// take appends one contiguous chunk and emits every complete DNS message.
// A message may span chunks. More than one message may share a chunk.
func (s *tcpStream) take(chunk []byte, seen time.Time) {
	if len(chunk) == 0 {
		return
	}
	if len(chunk) > tcpStreamMax || len(s.buf) > tcpStreamMax-len(chunk) {
		s.buf = nil
		return
	}
	s.buf = append(s.buf, chunk...)
	for len(s.buf) >= 2 {
		mlen := int(binary.BigEndian.Uint16(s.buf[:2]))
		if mlen < 12 || mlen+2 > tcpStreamMax {
			s.buf = nil
			return
		}
		if len(s.buf) < mlen+2 {
			return
		}
		msg := make([]byte, mlen)
		copy(msg, s.buf[2:mlen+2])
		rest := make([]byte, len(s.buf)-(mlen+2))
		copy(rest, s.buf[mlen+2:])
		s.buf = rest
		s.out <- common.TcpStreamData{
			Data:      msg,
			NetFlow:   s.net,
			Transport: s.transport,
			Len:       mlen,
			VLANID:    s.vlanID,
			Timestamp: seen,
		}
	}
}

func (s *tcpStream) ReassemblyComplete() {
	// Optional logging could go here if you re-add the import.
}
