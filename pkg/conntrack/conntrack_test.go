package conntrack

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSysctlMock(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conntrack_sysctl_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_count"), []byte("25000\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_max"), []byte("100000\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_buckets"), []byte("32768\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_udp_timeout"), []byte("30\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_tcp_timeout_time_wait"), []byte("120\n"), 0644)

	m, err := ReadSysctl(tmpDir)
	if err != nil {
		t.Fatalf("ReadSysctl failed: %v", err)
	}

	if m.Count != 25000 || m.Max != 100000 {
		t.Errorf("count/max mismatch: got %d/%d, want 25000/100000", m.Count, m.Max)
	}
	if m.UtilizationRatio != 25.0 {
		t.Errorf("expected 25.0%% utilization, got %f", m.UtilizationRatio)
	}
	if m.AvailableSlots != 75000 {
		t.Errorf("expected 75000 available slots, got %d", m.AvailableSlots)
	}
}

func TestEncodeDecodeTLV(t *testing.T) {
	tup := Tuple4{
		SrcIP:   net.ParseIP("10.244.1.15"),
		DstIP:   net.ParseIP("10.96.0.10"),
		SrcPort: 52140,
		DstPort: 53,
		Proto:   ProtoUDP,
	}

	tlvBytes := EncodeTupleTLV(CTATupleOrig, tup)
	if len(tlvBytes) == 0 {
		t.Fatal("encoded TLV is empty")
	}

	// Wrap with mock nfgenmsg
	fullPayload := append([]byte{0, 0, 0, 0}, tlvBytes...)
	entry, err := DecodeNetlinkEntry(fullPayload)
	if err != nil {
		t.Fatalf("DecodeNetlinkEntry failed: %v", err)
	}

	if !entry.Origin.SrcIP.Equal(tup.SrcIP) {
		t.Errorf("SrcIP mismatch: got %s, want %s", entry.Origin.SrcIP, tup.SrcIP)
	}
	if !entry.Origin.DstIP.Equal(tup.DstIP) {
		t.Errorf("DstIP mismatch: got %s, want %s", entry.Origin.DstIP, tup.DstIP)
	}
	if entry.Origin.SrcPort != tup.SrcPort || entry.Origin.DstPort != tup.DstPort {
		t.Errorf("ports mismatch: got %d:%d, want %d:%d", entry.Origin.SrcPort, entry.Origin.DstPort, tup.SrcPort, tup.DstPort)
	}
	if entry.Origin.Proto != ProtoUDP {
		t.Errorf("proto mismatch: got %d, want %d", entry.Origin.Proto, ProtoUDP)
	}
	if !entry.IsDNS() {
		t.Errorf("expected entry to be identified as DNS")
	}
}

func TestParseConntrackText(t *testing.T) {
	sample := `ipv4 2 udp 17 28 src=10.244.0.5 dst=10.96.0.10 sport=41234 dport=53 [UNREPLIED] src=10.96.0.10 dst=10.244.0.5 sport=53 dport=41234
ipv4 2 tcp 6 118 TIME_WAIT src=192.168.1.100 dst=93.184.216.34 sport=55000 dport=443 src=93.184.216.34 dst=192.168.1.100 sport=443 dport=55000 [ASSURED]
ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=8080 dport=45000 src=10.0.0.2 dst=10.0.0.1 sport=45000 dport=8080 [ASSURED]
`

	entries, err := ParseConntrackText(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("ParseConntrackText failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	eUDP := entries[0]
	if eUDP.ProtocolName() != "udp" || !eUDP.IsDNS() {
		t.Errorf("expected UDP DNS entry: %+v", eUDP)
	}
	if !eUDP.IsStaleUDP(2, 30) {
		t.Errorf("expected UDP entry with 28s remaining of 30s to be stale >= 2s")
	}

	eTW := entries[1]
	if !eTW.IsTerminalTCP() {
		t.Errorf("expected TIME_WAIT to be terminal TCP")
	}
	if eTW.IsActiveTCP() {
		t.Errorf("TIME_WAIT must not be active TCP")
	}

	eEst := entries[2]
	if !eEst.IsActiveTCP() {
		t.Errorf("expected ESTABLISHED to be active TCP")
	}
	if eEst.IsTerminalTCP() {
		t.Errorf("ESTABLISHED must not be terminal TCP")
	}
}
