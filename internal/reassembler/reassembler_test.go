package reassembler

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket/tcpassembly"
	"passivednsgo/internal/common"
)

func frame(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:], payload)
	return out
}

func collect(s *tcpStream) []common.TcpStreamData {
	var got []common.TcpStreamData
	for {
		select {
		case msg := <-s.out:
			got = append(got, msg)
		default:
			return got
		}
	}
}

func TestSplitMessage(t *testing.T) {
	payload := bytes.Repeat([]byte{0x21}, 40)
	framed := frame(payload)
	s := &tcpStream{out: make(chan common.TcpStreamData, 2)}
	s.Reassembled([]tcpassembly.Reassembly{{
		Bytes: framed[:9],
		Seen:  time.Unix(10, 0),
	}})
	if len(collect(s)) != 0 {
		t.Fatal("partial message was emitted")
	}
	s.Reassembled([]tcpassembly.Reassembly{{
		Bytes: framed[9:],
		Seen:  time.Unix(11, 0),
	}})
	got := collect(s)
	if len(got) != 1 || !bytes.Equal(got[0].Data, payload) {
		t.Fatalf("got %d messages", len(got))
	}
	if !got[0].Timestamp.Equal(time.Unix(11, 0)) {
		t.Fatal("timestamp is not the chunk that finished the message")
	}
}

func TestTwoMessagesOneChunk(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 12)
	b := bytes.Repeat([]byte{0x02}, 16)
	s := &tcpStream{out: make(chan common.TcpStreamData, 2)}
	s.Reassembled([]tcpassembly.Reassembly{{
		Bytes: append(frame(a), frame(b)...),
		Seen:  time.Unix(20, 0),
	}})
	got := collect(s)
	if len(got) != 2 || !bytes.Equal(got[0].Data, a) || !bytes.Equal(got[1].Data, b) {
		t.Fatalf("got %d messages", len(got))
	}
}

func TestGapDropsPartial(t *testing.T) {
	payload := bytes.Repeat([]byte{0x33}, 24)
	framed := frame(payload)
	s := &tcpStream{out: make(chan common.TcpStreamData, 2)}
	s.Reassembled([]tcpassembly.Reassembly{{
		Bytes: framed[:6],
		Seen:  time.Unix(30, 0),
	}})
	// The skipped bytes invalidate the partial message. This chunk is a new one.
	s.Reassembled([]tcpassembly.Reassembly{{
		Bytes: framed,
		Skip:  10,
		Seen:  time.Unix(31, 0),
	}})
	got := collect(s)
	if len(got) != 1 || !bytes.Equal(got[0].Data, payload) {
		t.Fatalf("got %d messages", len(got))
	}
}
