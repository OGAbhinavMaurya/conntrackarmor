package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/OGAbhinavMaurya/conntrackarmor/pkg/conntrack"
	"github.com/OGAbhinavMaurya/conntrackarmor/pkg/sentry"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "reap":
		if err := runReap(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Printf("conntrackarmor %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`conntrackarmor: Linux Netfilter conntrack table exhaustion sentry and surgical pruner

Usage:
  conntrackarmor doctor [flags]   Inspect table capacity, fill velocity, and projected exhaustion
  conntrackarmor reap [flags]     Surgically prune expired UDP and terminal TCP connections
  conntrackarmor version          Display version information

Flags for 'doctor':
  --sysctl-path string   Path to netfilter procfs directory (default "/proc/sys/net/netfilter")
  --sample duration      Measurement interval for velocity calculation (e.g. 1s, 2s; default 0s)
  --threshold float      Utilization percentage threshold to flag as critical (default 75.0)
  --json                 Output assessment in JSON format

Flags for 'reap':
  --proto string         Target protocol to prune: udp, tcp, all (default "udp")
  --older-than duration  Minimum entry age threshold (default 2s)
  --port int             Target network port filter (e.g. 53 for DNS)
  --state string         TCP connection state filter (e.g. timewait, close, all)
  --dry-run              Calculate and display matched entries without deleting them
  --json                 Output results in JSON format
`)
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	sysctlPath := fs.String("sysctl-path", conntrack.DefaultSysctlPath, "Procfs path")
	sample := fs.Duration("sample", 0, "Sampling interval")
	threshold := fs.Float64("threshold", 75.0, "Utilization threshold percentage")
	jsonOut := fs.Bool("json", false, "Output in JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	diag, err := sentry.SampleDoctor(*sysctlPath, *sample, *threshold)
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(diag)
	}

	fmt.Printf("Conntrack Table Health: [%s]\n", diag.Level)
	fmt.Printf("  Capacity:          %d max entries\n", diag.Capacity)
	fmt.Printf("  Active Entries:    %d (%.1f%% utilized)\n", diag.ActiveEntries, diag.UtilizationRatio)
	fmt.Printf("  Available Slots:   %d\n", diag.AvailableSlots)

	if *sample > 0 {
		fmt.Printf("  Fill Velocity:     %+.1f entries/sec (over %s sample)\n", diag.FillVelocityPerSec, *sample)
		fmt.Printf("  Time to Full:      %s\n", diag.TimeToExhaustion)
	}

	fmt.Printf("\nProtocol Breakdown:\n")
	fmt.Printf("  - TCP Total:       %d (established: %d, terminal: %d)\n",
		diag.Breakdown.TCPCount, diag.Breakdown.TCPEstablished, diag.Breakdown.TCPTerminal)
	fmt.Printf("  - UDP Total:       %d (DNS port 53: %d, stale DNS >=2s: %d)\n",
		diag.Breakdown.UDPCount, diag.Breakdown.UDPDNSCount, diag.Breakdown.UDPStaleDNSCount)
	fmt.Printf("  - ICMP / Other:    %d\n", diag.Breakdown.ICMPCount+diag.Breakdown.OtherCount)

	if len(diag.Issues) > 0 {
		fmt.Println("\nDetected Issues:")
		for _, issue := range diag.Issues {
			fmt.Printf("  ! %s\n", issue)
		}
	}

	if diag.Remediation != "" {
		fmt.Printf("\nRemediation:\n  %s\n", diag.Remediation)
	}

	return nil
}

func runReap(args []string) error {
	fs := flag.NewFlagSet("reap", flag.ContinueOnError)
	proto := fs.String("proto", "udp", "Target protocol: udp, tcp, all")
	olderThan := fs.Duration("older-than", 2*time.Second, "Minimum entry age threshold")
	port := fs.Int("port", 0, "Target port filter")
	state := fs.String("state", "", "TCP state filter")
	dryRun := fs.Bool("dry-run", false, "Preview deletions without applying")
	jsonOut := fs.Bool("json", false, "Output in JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := sentry.ReapOptions{
		Proto:     *proto,
		OlderThan: *olderThan,
		Port:      uint16(*port),
		State:     *state,
		DryRun:    *dryRun,
	}

	if err := sentry.ValidateReapOptions(opts); err != nil {
		return err
	}

	// Dump entries from kernel
	entries, err := conntrack.DumpEntries()
	if err != nil {
		return fmt.Errorf("reading conntrack entries: %w", err)
	}

	sysctlMetrics, _ := conntrack.ReadSysctl("")
	maxTimeout := uint32(30)
	if sysctlMetrics != nil && sysctlMetrics.UDPTimeoutSec > 0 {
		maxTimeout = uint32(sysctlMetrics.UDPTimeoutSec)
	}

	result, err := sentry.ExecuteReap(entries, opts, maxTimeout, conntrack.DeleteEntry)
	if err != nil {
		return fmt.Errorf("reaping entries: %w", err)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Surgical Conntrack Pruning Result:\n")
	fmt.Printf("  Scanned:       %d active entries\n", result.ScannedCount)
	fmt.Printf("  Matched:       %d entries\n", result.MatchedCount)
	if *dryRun {
		fmt.Printf("  Mode:          Dry run (zero entries deleted)\n")
	} else {
		fmt.Printf("  Reaped:        %d entries deleted\n", result.ReapedCount)
	}
	fmt.Printf("  Duration:      %.2f ms\n", result.DurationMs)

	if len(result.ByProtocol) > 0 {
		fmt.Println("\nPurged Breakdown by Protocol:")
		for p, count := range result.ByProtocol {
			fmt.Printf("  - %s: %d\n", p, count)
		}
	}

	return nil
}
