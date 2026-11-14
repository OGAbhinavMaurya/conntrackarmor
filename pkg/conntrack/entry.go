package conntrack

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// IP Protocol numbers
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// Tuple4 represents a network 4-tuple.
type Tuple4 struct {
	SrcIP   net.IP `json:"src_ip"`
	DstIP   net.IP `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   uint8  `json:"proto"`
}

func (t Tuple4) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (proto %d)", t.SrcIP, t.SrcPort, t.DstIP, t.DstPort, t.Proto)
}

// Entry represents a single tracked connection in the Netfilter conntrack table.
type Entry struct {
	Origin     Tuple4        `json:"origin"`
	Reply      Tuple4        `json:"reply"`
	Proto      string        `json:"proto"`
	State      string        `json:"state,omitempty"` // TCP state: ESTABLISHED, TIME_WAIT, etc.
	TimeoutSec uint32        `json:"timeout_sec"`     // Remaining seconds until kernel eviction
	ExpiresIn  time.Duration `json:"expires_in"`
	Mark       uint32        `json:"mark,omitempty"`
	ID         uint32        `json:"id,omitempty"`
}

func (e *Entry) ProtocolName() string {
	if e.Proto != "" {
		return strings.ToLower(e.Proto)
	}
	switch e.Origin.Proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return fmt.Sprintf("proto-%d", e.Origin.Proto)
	}
}

// IsDNS returns true if the connection targets or originates from port 53.
func (e *Entry) IsDNS() bool {
	return e.Origin.DstPort == 53 || e.Origin.SrcPort == 53 ||
		e.Reply.SrcPort == 53 || e.Reply.DstPort == 53
}

// IsTerminalTCP returns true if a TCP session is in a closing or dead state.
func (e *Entry) IsTerminalTCP() bool {
	if e.ProtocolName() != "tcp" {
		return false
	}
	s := strings.ToUpper(e.State)
	return s == "TIME_WAIT" || s == "CLOSE" || s == "LAST_ACK" || s == "CLOSING" || s == "FIN_WAIT"
}

// IsActiveTCP returns true if the TCP session is established.
func (e *Entry) IsActiveTCP() bool {
	if e.ProtocolName() != "tcp" {
		return false
	}
	return strings.ToUpper(e.State) == "ESTABLISHED"
}

// IsStaleUDP checks if a UDP conntrack entry has persisted past a threshold.
// In the kernel, TimeoutSec decreases from maxTimeout (default 30s) towards 0.
// Elapsed age = maxTimeout - TimeoutSec.
func (e *Entry) IsStaleUDP(olderThanSec uint32, maxTimeoutSec uint32) bool {
	if e.ProtocolName() != "udp" {
		return false
	}
	if maxTimeoutSec == 0 {
		maxTimeoutSec = 30
	}
	// If remaining timeout is small, it has survived longer than olderThanSec
	if e.TimeoutSec > maxTimeoutSec {
		return false
	}
	elapsed := maxTimeoutSec - e.TimeoutSec
	return elapsed >= olderThanSec
}
