package sentry

import (
	"fmt"
	"time"

	"github.com/OGAbhinavMaurya/conntrackarmor/pkg/conntrack"
)

// Level represents table capacity risk.
type Level string

const (
	LevelHealthy   Level = "HEALTHY"
	LevelWarning   Level = "WARNING"
	LevelCritical  Level = "CRITICAL"
	LevelExhausted Level = "EXHAUSTED"
)

// ProtocolBreakdown summarizes active entries by protocol.
type ProtocolBreakdown struct {
	TCPCount         int `json:"tcp_count"`
	TCPEstablished   int `json:"tcp_established"`
	TCPTerminal      int `json:"tcp_terminal"` // TIME_WAIT, CLOSE, LAST_ACK
	UDPCount         int `json:"udp_count"`
	UDPDNSCount      int `json:"udp_dns_count"`
	UDPStaleDNSCount int `json:"udp_stale_dns_count"`
	ICMPCount        int `json:"icmp_count"`
	OtherCount       int `json:"other_count"`
}

// Diagnosis summarizes conntrack table health, fill velocity, and time to exhaustion.
type Diagnosis struct {
	Level             Level             `json:"level"`
	Capacity          int64             `json:"capacity"`
	ActiveEntries     int64             `json:"active_entries"`
	AvailableSlots    int64             `json:"available_slots"`
	UtilizationRatio  float64           `json:"utilization_pct"`
	FillVelocityPerSec float64          `json:"fill_velocity_per_sec"`
	TimeToExhaustion  string            `json:"time_to_exhaustion"`
	TimeToExhaustSec  float64           `json:"time_to_exhaust_sec,omitempty"`
	Breakdown         ProtocolBreakdown `json:"breakdown"`
	Issues            []string          `json:"issues,omitempty"`
	Remediation       string            `json:"remediation,omitempty"`
}

// Evaluate analyzes sysctl metrics and scanned entries to produce a capacity diagnosis.
func Evaluate(m *conntrack.SysctlMetrics, entries []*conntrack.Entry, velocity float64, threshold float64) *Diagnosis {
	diag := &Diagnosis{
		Capacity:           m.Max,
		ActiveEntries:      m.Count,
		AvailableSlots:     m.AvailableSlots,
		UtilizationRatio:   m.UtilizationRatio,
		FillVelocityPerSec: velocity,
		Level:              LevelHealthy,
	}

	if threshold <= 0 {
		threshold = 75.0
	}

	// Calculate time-to-exhaustion
	if velocity > 0 && m.AvailableSlots > 0 {
		sec := float64(m.AvailableSlots) / velocity
		diag.TimeToExhaustSec = sec
		diag.TimeToExhaustion = fmt.Sprintf("%.1fs", sec)
	} else if m.AvailableSlots <= 0 {
		diag.TimeToExhaustion = "0s (table full)"
	} else {
		diag.TimeToExhaustion = "stable"
	}

	// Analyze entry breakdown
	var bd ProtocolBreakdown
	for _, e := range entries {
		switch e.ProtocolName() {
		case "tcp":
			bd.TCPCount++
			if e.IsActiveTCP() {
				bd.TCPEstablished++
			} else if e.IsTerminalTCP() {
				bd.TCPTerminal++
			}
		case "udp":
			bd.UDPCount++
			if e.IsDNS() {
				bd.UDPDNSCount++
				if e.IsStaleUDP(2, uint32(m.UDPTimeoutSec)) {
					bd.UDPStaleDNSCount++
				}
			}
		case "icmp":
			bd.ICMPCount++
		default:
			bd.OtherCount++
		}
	}
	diag.Breakdown = bd

	// Determine risk level
	if m.UtilizationRatio >= 95.0 || m.AvailableSlots <= 0 {
		diag.Level = LevelExhausted
		diag.Issues = append(diag.Issues,
			"Conntrack table is full or at immediate exhaustion risk.",
			"Kernel is or will soon be silently dropping packets ('table full, dropping packet').")
		diag.Remediation = "Run 'conntrackarmor reap --proto udp --older-than 2s' to surgically reclaim slots immediately."
	} else if m.UtilizationRatio >= threshold || (velocity > 0 && diag.TimeToExhaustSec > 0 && diag.TimeToExhaustSec <= 60) {
		diag.Level = LevelCritical
		diag.Issues = append(diag.Issues,
			fmt.Sprintf("Table capacity is at %.1f%% (threshold: %.1f%%).", m.UtilizationRatio, threshold))
		if diag.TimeToExhaustSec > 0 && diag.TimeToExhaustSec <= 60 {
			diag.Issues = append(diag.Issues,
				fmt.Sprintf("Time to table exhaustion is critically low: %s.", diag.TimeToExhaustion))
		}
		diag.Remediation = "Run 'conntrackarmor reap --proto udp --older-than 2s' to relieve capacity pressure."
	} else if m.UtilizationRatio >= 50.0 || (velocity > 0 && diag.TimeToExhaustSec > 0 && diag.TimeToExhaustSec <= 300) {
		diag.Level = LevelWarning
		diag.Issues = append(diag.Issues,
			fmt.Sprintf("Table capacity is elevated at %.1f%%.", m.UtilizationRatio))
		if diag.TimeToExhaustSec > 0 && diag.TimeToExhaustSec <= 300 {
			diag.Issues = append(diag.Issues,
				fmt.Sprintf("Time to table exhaustion projected at %s.", diag.TimeToExhaustion))
		}
	}

	return diag
}

// SampleDoctor samples conntrack metrics over an interval to compute fill velocity and diagnosis.
func SampleDoctor(sysctlDir string, sampleDuration time.Duration, threshold float64) (*Diagnosis, error) {
	m1, err := conntrack.ReadSysctl(sysctlDir)
	if err != nil {
		return nil, err
	}

	velocity := 0.0
	if sampleDuration > 0 {
		time.Sleep(sampleDuration)
		m2, err := conntrack.ReadSysctl(sysctlDir)
		if err != nil {
			return nil, err
		}
		delta := float64(m2.Count - m1.Count)
		velocity = delta / sampleDuration.Seconds()
		m1 = m2
	}

	// Dump entries via netlink if available
	entries, _ := conntrack.DumpEntries()

	return Evaluate(m1, entries, velocity, threshold), nil
}
