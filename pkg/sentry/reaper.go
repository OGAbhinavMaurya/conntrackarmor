package sentry

import (
	"errors"
	"strings"
	"time"

	"github.com/OGAbhinavMaurya/conntrackarmor/pkg/conntrack"
)

// ReapOptions configures the surgical pruning filter.
type ReapOptions struct {
	Proto     string        // "udp", "tcp", or "all"
	OlderThan time.Duration // minimum age (e.g. 2s)
	Port      uint16        // optional port filter (e.g. 53)
	State     string        // TCP state filter ("timewait", "close", "terminal")
	DryRun    bool          // preview without executing deletion
}

// ReapResult summarizes the surgical pruning outcome.
type ReapResult struct {
	ScannedCount int            `json:"scanned_count"`
	MatchedCount int            `json:"matched_count"`
	ReapedCount  int            `json:"reaped_count"`
	DryRun       bool           `json:"dry_run"`
	ByProtocol   map[string]int `json:"by_protocol"`
	DurationMs   float64        `json:"duration_ms"`
}

// ShouldReap applies surgical filter rules and strict safety invariants to determine if an entry should be purged.
func ShouldReap(e *conntrack.Entry, opts ReapOptions, maxUDPTimeoutSec uint32) bool {
	// Strict safety invariant: never reap active established TCP connections
	if e.IsActiveTCP() {
		return false
	}

	proto := e.ProtocolName()
	filterProto := strings.ToLower(opts.Proto)
	if filterProto != "" && filterProto != "all" && filterProto != proto {
		return false
	}

	// Port filter
	if opts.Port > 0 {
		if e.Origin.SrcPort != opts.Port && e.Origin.DstPort != opts.Port &&
			e.Reply.SrcPort != opts.Port && e.Reply.DstPort != opts.Port {
			return false
		}
	}

	// Protocol-specific pruning criteria
	switch proto {
	case "udp":
		olderThanSec := uint32(opts.OlderThan.Seconds())
		if olderThanSec == 0 {
			olderThanSec = 2 // default to 2s
		}
		return e.IsStaleUDP(olderThanSec, maxUDPTimeoutSec)

	case "tcp":
		if !e.IsTerminalTCP() {
			return false
		}
		if opts.State != "" && opts.State != "all" {
			targetState := strings.ToUpper(opts.State)
			if targetState == "TIMEWAIT" || targetState == "TIME_WAIT" {
				return strings.ToUpper(e.State) == "TIME_WAIT"
			}
			if targetState == "CLOSE" {
				return strings.ToUpper(e.State) == "CLOSE"
			}
		}
		return true

	default:
		return false
	}
}

// ExecuteReap scans entries, evaluates surgical filters, and invokes deleter for matched entries.
func ExecuteReap(entries []*conntrack.Entry, opts ReapOptions, maxUDPTimeoutSec uint32, deleter func(*conntrack.Entry) error) (*ReapResult, error) {
	if len(entries) == 0 {
		return &ReapResult{ByProtocol: make(map[string]int)}, nil
	}

	start := time.Now()
	res := &ReapResult{
		ScannedCount: len(entries),
		DryRun:       opts.DryRun,
		ByProtocol:   make(map[string]int),
	}

	for _, e := range entries {
		if ShouldReap(e, opts, maxUDPTimeoutSec) {
			res.MatchedCount++
			proto := e.ProtocolName()
			res.ByProtocol[proto]++

			if !opts.DryRun && deleter != nil {
				if err := deleter(e); err != nil {
					// Log error or continue non-fatally
					continue
				}
				res.ReapedCount++
			}
		}
	}

	res.DurationMs = float64(time.Since(start).Microseconds()) / 1000.0
	return res, nil
}

// ValidateReapOptions validates filter parameters before execution.
func ValidateReapOptions(opts ReapOptions) error {
	p := strings.ToLower(opts.Proto)
	if p != "" && p != "udp" && p != "tcp" && p != "all" {
		return errors.New("protocol must be 'udp', 'tcp', or 'all'")
	}
	return nil
}
