package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorCLI(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "conntrack_main_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_count"), []byte("1200\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_max"), []byte("65536\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "nf_conntrack_buckets"), []byte("16384\n"), 0644)

	err = runDoctor([]string{"--sysctl-path", tmpDir})
	if err != nil {
		t.Fatalf("runDoctor failed: %v", err)
	}
}
