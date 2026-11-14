package sentry

import (
	"net"
	"testing"
	"time"

	"github.com/OGAbhinavMaurya/conntrackarmor/pkg/conntrack"
)

func TestEvaluate_Healthy(t *testing.T) {
	m := &conntrack.SysctlMetrics{
		Count:            10000,
		Max:              100000,
		UtilizationRatio: 10.0,
		AvailableSlots:   90000,
		UDPTimeoutSec:    30,
	}

	diag := Evaluate(m, nil, 0.0, 75.0)
	if diag.Level != LevelHealthy {
		t.Errorf("expected LevelHealthy, got %s", diag.Level)
	}
	if diag.TimeToExhaustion != "stable" {
		t.Errorf("expected stable time to exhaustion, got %s", diag.TimeToExhaustion)
	}
}

func TestEvaluate_Critical(t *testing.T) {
	m := &conntrack.SysctlMetrics{
		Count:            85000,
		Max:              100000,
		UtilizationRatio: 85.0,
		AvailableSlots:   15000,
		UDPTimeoutSec:    30,
	}

	diag := Evaluate(m, nil, 0.0, 75.0)
	if diag.Level != LevelCritical {
		t.Errorf("expected LevelCritical, got %s", diag.Level)
	}
	if len(diag.Issues) == 0 {
		t.Errorf("expected issues reported for critical utilization")
	}
	if diag.Remediation == "" {
		t.Errorf("expected remediation action provided")
	}
}

func TestEvaluate_VelocityProjection(t *testing.T) {
	m := &conntrack.SysctlMetrics{
		Count:            60000,
		Max:              100000,
		UtilizationRatio: 60.0,
		AvailableSlots:   40000,
		UDPTimeoutSec:    30,
	}

	// 1,000 entries per second fill rate -> 40,000 / 1,000 = 40 seconds to exhaustion
	diag := Evaluate(m, nil, 1000.0, 75.0)
	if diag.Level != LevelCritical { // Projected <= 60s triggers Critical
		t.Errorf("expected LevelCritical due to low time-to-exhaustion, got %s", diag.Level)
	}
	if diag.TimeToExhaustSec != 40.0 {
		t.Errorf("expected 40.0s time to exhaust, got %f", diag.TimeToExhaustSec)
	}
}

func TestShouldReap_SafetyInvariant(t *testing.T) {
	// Established active TCP stream must NEVER be reaped
	established := &conntrack.Entry{
		Origin: conntrack.Tuple4{
			SrcIP:   net.ParseIP("10.0.0.1"),
			DstIP:   net.ParseIP("10.0.0.2"),
			SrcPort: 5432,
			DstPort: 48120,
			Proto:   conntrack.ProtoTCP,
		},
		Proto: "tcp",
		State: "ESTABLISHED",
	}

	optsAll := ReapOptions{Proto: "all"}
	if ShouldReap(established, optsAll, 30) {
		t.Fatal("SAFETY VIOLATION: Established TCP connection marked for reaping under proto=all")
	}

	optsTCP := ReapOptions{Proto: "tcp"}
	if ShouldReap(established, optsTCP, 30) {
		t.Fatal("SAFETY VIOLATION: Established TCP connection marked for reaping under proto=tcp")
	}
}

func TestShouldReap_StaleUDP(t *testing.T) {
	staleDNS := &conntrack.Entry{
		Origin: conntrack.Tuple4{
			SrcIP:   net.ParseIP("10.244.1.5"),
			DstIP:   net.ParseIP("10.96.0.10"),
			SrcPort: 41234,
			DstPort: 53,
			Proto:   conntrack.ProtoUDP,
		},
		Proto:      "udp",
		TimeoutSec: 10, // 30 - 10 = 20s elapsed >= 2s threshold
	}

	opts := ReapOptions{Proto: "udp", OlderThan: 2 * time.Second, Port: 53}
	if !ShouldReap(staleDNS, opts, 30) {
		t.Errorf("expected stale UDP DNS entry to match reap filter")
	}

	// Port mismatch
	optsOtherPort := ReapOptions{Proto: "udp", Port: 8080}
	if ShouldReap(staleDNS, optsOtherPort, 30) {
		t.Errorf("port mismatch must not be reaped")
	}
}

func TestShouldReap_TerminalTCP(t *testing.T) {
	timeWait := &conntrack.Entry{
		Origin: conntrack.Tuple4{
			SrcIP:   net.ParseIP("10.244.1.5"),
			DstIP:   net.ParseIP("93.184.216.34"),
			SrcPort: 50123,
			DstPort: 443,
			Proto:   conntrack.ProtoTCP,
		},
		Proto: "tcp",
		State: "TIME_WAIT",
	}

	opts := ReapOptions{Proto: "tcp", State: "timewait"}
	if !ShouldReap(timeWait, opts, 30) {
		t.Errorf("expected TIME_WAIT TCP entry to match reap filter")
	}
}

func TestExecuteReap(t *testing.T) {
	entries := []*conntrack.Entry{
		{
			Origin: conntrack.Tuple4{SrcIP: net.ParseIP("10.0.0.1"), DstPort: 53, Proto: conntrack.ProtoUDP},
			Proto:  "udp", TimeoutSec: 5,
		},
		{
			Origin: conntrack.Tuple4{SrcIP: net.ParseIP("10.0.0.2"), DstPort: 443, Proto: conntrack.ProtoTCP},
			Proto:  "tcp", State: "ESTABLISHED",
		},
		{
			Origin: conntrack.Tuple4{SrcIP: net.ParseIP("10.0.0.3"), DstPort: 80, Proto: conntrack.ProtoTCP},
			Proto:  "tcp", State: "TIME_WAIT",
		},
	}

	opts := ReapOptions{Proto: "all", OlderThan: 2 * time.Second, DryRun: true}
	res, err := ExecuteReap(entries, opts, 30, nil)
	if err != nil {
		t.Fatalf("ExecuteReap failed: %v", err)
	}

	if res.ScannedCount != 3 {
		t.Errorf("expected 3 scanned, got %d", res.ScannedCount)
	}
	if res.MatchedCount != 2 { // UDP DNS and TIME_WAIT matched; ESTABLISHED skipped
		t.Errorf("expected 2 matched, got %d", res.MatchedCount)
	}
	if res.ReapedCount != 0 {
		t.Errorf("dry run must have 0 reaped count, got %d", res.ReapedCount)
	}

	// Live execution test with mock deleter
	deleted := 0
	deleter := func(e *conntrack.Entry) error {
		deleted++
		return nil
	}
	opts.DryRun = false
	resLive, err := ExecuteReap(entries, opts, 30, deleter)
	if err != nil {
		t.Fatalf("ExecuteReap live failed: %v", err)
	}
	if resLive.ReapedCount != 2 || deleted != 2 {
		t.Errorf("expected 2 reaped entries, got %d (deleted: %d)", resLive.ReapedCount, deleted)
	}
}
