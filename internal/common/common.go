package common

import (
	"time"

	"github.com/google/gopacket"
)

type TcpStreamData struct {
	Data      []byte
	NetFlow   gopacket.Flow
	Transport gopacket.Flow
	Len       int
	VLANID    uint16
	Timestamp time.Time
}
