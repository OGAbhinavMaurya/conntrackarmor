package conntrack

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// CTNETLINK Attribute types (CTA_*)
const (
	CTAUnspec       uint16 = 0
	CTATupleOrig    uint16 = 1
	CTATupleReply   uint16 = 2
	CTAStatus       uint16 = 3
	CTAProtoInfo    uint16 = 4
	CTATimeout      uint16 = 7
	CTAMark         uint16 = 8
	CTAId           uint16 = 12
	CTATupleIP      uint16 = 1
	CTATupleProto   uint16 = 2
	CTAIPV4Src      uint16 = 1
	CTAIPV4Dst      uint16 = 2
	CTAIPV6Src      uint16 = 3
	CTAIPV6Dst      uint16 = 4
	CTAProtoNum     uint16 = 1
	CTAProtoSrcPort uint16 = 2
	CTAProtoDstPort uint16 = 3
	CTAProtoTCP     uint16 = 1
	CTAProtoTCPState uint16 = 1
)

var tcpStateNames = map[uint8]string{
	1: "SYN_SENT",
	2: "SYN_RECV",
	3: "ESTABLISHED",
	4: "FIN_WAIT",
	5: "CLOSE_WAIT",
	6: "LAST_ACK",
	7: "TIME_WAIT",
	8: "CLOSE",
	9: "SYN_SENT2",
}

// TLV represents a parsed Netlink attribute header and payload.
type TLV struct {
	Type  uint16
	Value []byte
}

// ParseTLVs decodes consecutive 4-byte aligned Netlink attributes.
func ParseTLVs(b []byte) ([]TLV, error) {
	var attrs []TLV
	for len(b) >= 4 {
		attrLen := binary.LittleEndian.Uint16(b[0:2])
		attrType := binary.LittleEndian.Uint16(b[2:4]) & 0x7FFF // Strip nested flag

		if attrLen < 4 {
			return nil, fmt.Errorf("invalid TLV length %d", attrLen)
		}
		if int(attrLen) > len(b) {
			break
		}

		payload := b[4:attrLen]
		attrs = append(attrs, TLV{Type: attrType, Value: payload})

		// 4-byte alignment
		aligned := (int(attrLen) + 3) &^ 3
		if aligned > len(b) {
			break
		}
		b = b[aligned:]
	}
	return attrs, nil
}

// DecodeNetlinkEntry decodes a Netlink CTNETLINK message into an Entry.
func DecodeNetlinkEntry(payload []byte) (*Entry, error) {
	// Skip 4-byte nfgenmsg if present at the start of payload
	if len(payload) >= 4 && (payload[0] == 0 || payload[0] == 2 || payload[0] == 10) && payload[1] == 0 {
		payload = payload[4:]
	}

	attrs, err := ParseTLVs(payload)
	if err != nil {
		return nil, err
	}

	entry := &Entry{}

	for _, attr := range attrs {
		switch attr.Type {
		case CTATupleOrig:
			entry.Origin = decodeTuple(attr.Value)
			entry.Proto = entry.Origin.protoName()
		case CTATupleReply:
			entry.Reply = decodeTuple(attr.Value)
		case CTATimeout:
			if len(attr.Value) >= 4 {
				entry.TimeoutSec = binary.BigEndian.Uint32(attr.Value)
				entry.ExpiresIn = time.Duration(entry.TimeoutSec) * time.Second
			}
		case CTAProtoInfo:
			entry.State = decodeProtoInfo(attr.Value)
		case CTAId:
			if len(attr.Value) >= 4 {
				entry.ID = binary.BigEndian.Uint32(attr.Value)
			}
		case CTAMark:
			if len(attr.Value) >= 4 {
				entry.Mark = binary.BigEndian.Uint32(attr.Value)
			}
		}
	}

	return entry, nil
}

func decodeTuple(b []byte) Tuple4 {
	var t Tuple4
	attrs, err := ParseTLVs(b)
	if err != nil {
		return t
	}

	for _, attr := range attrs {
		switch attr.Type {
		case CTATupleIP:
			ipAttrs, _ := ParseTLVs(attr.Value)
			for _, ia := range ipAttrs {
				switch ia.Type {
				case CTAIPV4Src, CTAIPV6Src:
					t.SrcIP = net.IP(ia.Value)
				case CTAIPV4Dst, CTAIPV6Dst:
					t.DstIP = net.IP(ia.Value)
				}
			}
		case CTATupleProto:
			protoAttrs, _ := ParseTLVs(attr.Value)
			for _, pa := range protoAttrs {
				switch pa.Type {
				case CTAProtoNum:
					if len(pa.Value) >= 1 {
						t.Proto = pa.Value[0]
					}
				case CTAProtoSrcPort:
					if len(pa.Value) >= 2 {
						t.SrcPort = binary.BigEndian.Uint16(pa.Value)
					}
				case CTAProtoDstPort:
					if len(pa.Value) >= 2 {
						t.DstPort = binary.BigEndian.Uint16(pa.Value)
					}
				}
			}
		}
	}

	return t
}

func decodeProtoInfo(b []byte) string {
	attrs, err := ParseTLVs(b)
	if err != nil {
		return ""
	}
	for _, a := range attrs {
		if a.Type == CTAProtoTCP {
			tcpAttrs, _ := ParseTLVs(a.Value)
			for _, ta := range tcpAttrs {
				if ta.Type == CTAProtoTCPState && len(ta.Value) >= 1 {
					stateNum := ta.Value[0]
					if name, ok := tcpStateNames[stateNum]; ok {
						return name
					}
				}
			}
		}
	}
	return ""
}

func (t Tuple4) protoName() string {
	switch t.Proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return strconv.Itoa(int(t.Proto))
	}
}

// ParseConntrackText parses traditional /proc/net/nf_conntrack text dumps.
// Format example:
// ipv4     2 udp      17 28 src=10.244.0.5 dst=10.96.0.10 sport=41234 dport=53 [UNREPLIED] src=10.96.0.10 dst=10.244.0.5 sport=53 dport=41234 mark=0
func ParseConntrackText(r io.Reader) ([]*Entry, error) {
	var entries []*Entry
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		e := &Entry{}
		// Look for protocol (tcp, udp, icmp)
		for _, f := range fields {
			lower := strings.ToLower(f)
			if lower == "tcp" || lower == "udp" || lower == "icmp" {
				e.Proto = lower
				break
			}
		}

		// Look for timeout (numeric field before src=)
		for i, f := range fields {
			if strings.HasPrefix(f, "src=") && i > 0 {
				if sec, err := strconv.ParseUint(fields[i-1], 10, 32); err == nil {
					e.TimeoutSec = uint32(sec)
					e.ExpiresIn = time.Duration(sec) * time.Second
				}
				break
			}
		}

		// Look for TCP states
		for _, f := range fields {
			s := strings.ToUpper(f)
			if _, ok := tcpStateNamesInverse[s]; ok {
				e.State = s
				break
			}
		}

		// Parse origin and reply tuples
		isReply := false
		for _, f := range fields {
			if strings.HasPrefix(f, "src=") {
				ip := net.ParseIP(strings.TrimPrefix(f, "src="))
				if !isReply {
					e.Origin.SrcIP = ip
				} else {
					e.Reply.SrcIP = ip
				}
			} else if strings.HasPrefix(f, "dst=") {
				ip := net.ParseIP(strings.TrimPrefix(f, "dst="))
				if !isReply {
					e.Origin.DstIP = ip
				} else {
					e.Reply.DstIP = ip
				}
			} else if strings.HasPrefix(f, "sport=") {
				port, _ := strconv.ParseUint(strings.TrimPrefix(f, "sport="), 10, 16)
				if !isReply {
					e.Origin.SrcPort = uint16(port)
				} else {
					e.Reply.SrcPort = uint16(port)
				}
			} else if strings.HasPrefix(f, "dport=") {
				port, _ := strconv.ParseUint(strings.TrimPrefix(f, "dport="), 10, 16)
				if !isReply {
					e.Origin.DstPort = uint16(port)
					isReply = true // Next src/dst is reply
				} else {
					e.Reply.DstPort = uint16(port)
				}
			}
		}

		entries = append(entries, e)
	}

	return entries, scanner.Err()
}

var tcpStateNamesInverse = map[string]uint8{
	"SYN_SENT":    1,
	"SYN_RECV":    2,
	"ESTABLISHED": 3,
	"FIN_WAIT":    4,
	"CLOSE_WAIT":  5,
	"LAST_ACK":    6,
	"TIME_WAIT":   7,
	"CLOSE":       8,
	"CLOSING":     8,
}

// EncodeTupleTLV creates the nested TLV attribute byte buffer for origin or reply tuple.
func EncodeTupleTLV(attrType uint16, t Tuple4) []byte {
	buf := new(bytes.Buffer)

	// IP nested TLV
	ipBuf := new(bytes.Buffer)
	if src4 := t.SrcIP.To4(); src4 != nil {
		writeTLV(ipBuf, CTAIPV4Src, src4)
	} else if len(t.SrcIP) == 16 {
		writeTLV(ipBuf, CTAIPV6Src, t.SrcIP)
	}
	if dst4 := t.DstIP.To4(); dst4 != nil {
		writeTLV(ipBuf, CTAIPV4Dst, dst4)
	} else if len(t.DstIP) == 16 {
		writeTLV(ipBuf, CTAIPV6Dst, t.DstIP)
	}

	// Proto nested TLV
	protoBuf := new(bytes.Buffer)
	writeTLV(protoBuf, CTAProtoNum, []byte{t.Proto})
	srcPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(srcPortBytes, t.SrcPort)
	writeTLV(protoBuf, CTAProtoSrcPort, srcPortBytes)
	dstPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dstPortBytes, t.DstPort)
	writeTLV(protoBuf, CTAProtoDstPort, dstPortBytes)

	// Outer tuple nested TLV
	writeNestedTLV(buf, CTATupleIP, ipBuf.Bytes())
	writeNestedTLV(buf, CTATupleProto, protoBuf.Bytes())

	out := new(bytes.Buffer)
	writeNestedTLV(out, attrType, buf.Bytes())
	return out.Bytes()
}

func writeTLV(buf *bytes.Buffer, attrType uint16, val []byte) {
	length := uint16(4 + len(val))
	binary.Write(buf, binary.LittleEndian, length)
	binary.Write(buf, binary.LittleEndian, attrType)
	buf.Write(val)
	// 4-byte padding
	pad := (4 - (len(val) % 4)) % 4
	for i := 0; i < pad; i++ {
		buf.WriteByte(0)
	}
}

func writeNestedTLV(buf *bytes.Buffer, attrType uint16, val []byte) {
	// Nested flag is bit 15 (0x8000)
	length := uint16(4 + len(val))
	binary.Write(buf, binary.LittleEndian, length)
	binary.Write(buf, binary.LittleEndian, attrType|0x8000)
	buf.Write(val)
	pad := (4 - (len(val) % 4)) % 4
	for i := 0; i < pad; i++ {
		buf.WriteByte(0)
	}
}
