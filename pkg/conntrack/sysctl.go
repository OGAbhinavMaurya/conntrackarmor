package conntrack

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultSysctlPath is the Linux kernel procfs directory for netfilter conntrack parameters.
const DefaultSysctlPath = "/proc/sys/net/netfilter"

// SysctlMetrics represents kernel conntrack table capacity and active count.
type SysctlMetrics struct {
	Count            int64   `json:"count"`
	Max              int64   `json:"max"`
	Buckets          int64   `json:"buckets"`
	UDPTimeoutSec    int64   `json:"udp_timeout_sec"`
	TCPTimeWaitSec   int64   `json:"tcp_timewait_sec"`
	UtilizationRatio float64 `json:"utilization_pct"`
	AvailableSlots   int64   `json:"available_slots"`
}

// ReadSysctl extracts conntrack capacity metrics from procfs.
func ReadSysctl(dir string) (*SysctlMetrics, error) {
	if dir == "" {
		dir = DefaultSysctlPath
	}

	count, err := readIntFile(filepath.Join(dir, "nf_conntrack_count"))
	if err != nil {
		return nil, fmt.Errorf("reading nf_conntrack_count: %w", err)
	}

	maxLimit, err := readIntFile(filepath.Join(dir, "nf_conntrack_max"))
	if err != nil {
		return nil, fmt.Errorf("reading nf_conntrack_max: %w", err)
	}

	buckets, _ := readIntFile(filepath.Join(dir, "nf_conntrack_buckets"))
	udpTimeout, _ := readIntFile(filepath.Join(dir, "nf_conntrack_udp_timeout"))
	tcpTimeWait, _ := readIntFile(filepath.Join(dir, "nf_conntrack_tcp_timeout_time_wait"))

	if udpTimeout <= 0 {
		udpTimeout = 30
	}
	if tcpTimeWait <= 0 {
		tcpTimeWait = 120
	}

	utilization := 0.0
	if maxLimit > 0 {
		utilization = (float64(count) / float64(maxLimit)) * 100.0
	}

	avail := maxLimit - count
	if avail < 0 {
		avail = 0
	}

	return &SysctlMetrics{
		Count:            count,
		Max:              maxLimit,
		Buckets:          buckets,
		UDPTimeoutSec:    udpTimeout,
		TCPTimeWaitSec:   tcpTimeWait,
		UtilizationRatio: utilization,
		AvailableSlots:   avail,
	}, nil
}

func readIntFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	valStr := strings.TrimSpace(string(data))
	return strconv.ParseInt(valStr, 10, 64)
}
