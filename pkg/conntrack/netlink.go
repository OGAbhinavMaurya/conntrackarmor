package conntrack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
)

const (
	NetlinkNetfilter    = 12 // NETLINK_NETFILTER
	NFNLSubsysCTNetlink = 1  // NFNL_SUBSYS_CTNETLINK
	IPCTNLMsgCTGet      = 1
	IPCTNLMsgCTDelete   = 2

	// Kernel Netlink message types
	NLMsgTypeCTGet    = (NFNLSubsysCTNetlink << 8) | IPCTNLMsgCTGet    // 257
	NLMsgTypeCTDelete = (NFNLSubsysCTNetlink << 8) | IPCTNLMsgCTDelete // 258

	// Netlink message flags
	NLMFRequest = 0x1
	NLMFMulti   = 0x2
	NLMFAck     = 0x4
	NLMFDump    = 0x300 // NLM_F_ROOT | NLM_F_MATCH

	NLMsgDone  = 3
	NLMsgError = 2
)

// DumpEntries queries the Linux kernel via ctnetlink and returns all active conntrack entries.
func DumpEntries() ([]*Entry, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, NetlinkNetfilter)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("opening netlink socket (requires CAP_NET_ADMIN / root privileges): %w", err)
		}
		return nil, fmt.Errorf("opening netlink socket: %w", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("binding netlink socket: %w", err)
	}

	// Send NLM_F_REQUEST | NLM_F_DUMP
	reqBuf := new(bytes.Buffer)
	// nlmsghdr placeholder (16 bytes)
	reqHdr := syscall.NlMsghdr{
		Len:   uint32(16 + 4), // nlmsghdr + nfgenmsg
		Type:  NLMsgTypeCTGet,
		Flags: NLMFRequest | NLMFDump,
		Seq:   1,
		Pid:   uint32(os.Getpid()),
	}
	binary.Write(reqBuf, binary.LittleEndian, reqHdr)

	// nfgenmsg (4 bytes): family=AF_UNSPEC(0), version=0, res_id=0
	reqBuf.Write([]byte{0, 0, 0, 0})

	if err := syscall.Sendto(fd, reqBuf.Bytes(), 0, sa); err != nil {
		return nil, fmt.Errorf("sending dump request to netlink: %w", err)
	}

	var entries []*Entry
	recvBuf := make([]byte, 65536)

	for {
		nr, _, err := syscall.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			return nil, fmt.Errorf("receiving netlink data: %w", err)
		}
		if nr < 16 {
			break
		}

		rawMsgs := recvBuf[:nr]
		done := false

		for len(rawMsgs) >= 16 {
			hdrLen := binary.LittleEndian.Uint32(rawMsgs[0:4])
			hdrType := binary.LittleEndian.Uint16(rawMsgs[4:6])

			if hdrLen < 16 || int(hdrLen) > len(rawMsgs) {
				break
			}

			if hdrType == NLMsgDone {
				done = true
				break
			}
			if hdrType == NLMsgError {
				if len(rawMsgs) >= 20 {
					errno := int32(binary.LittleEndian.Uint32(rawMsgs[16:20]))
					if errno != 0 {
						return nil, fmt.Errorf("netlink returned error code %d", errno)
					}
				}
				done = true
				break
			}

			payload := rawMsgs[16:hdrLen]
			entry, err := DecodeNetlinkEntry(payload)
			if err == nil && entry != nil && entry.Origin.SrcIP != nil {
				entries = append(entries, entry)
			}

			// Align to 4 bytes
			aligned := (int(hdrLen) + 3) &^ 3
			if aligned > len(rawMsgs) {
				break
			}
			rawMsgs = rawMsgs[aligned:]
		}

		if done {
			break
		}
	}

	return entries, nil
}

// DeleteEntry instructs the kernel to delete a conntrack entry via origin tuple matching.
func DeleteEntry(e *Entry) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, NetlinkNetfilter)
	if err != nil {
		return fmt.Errorf("opening netlink socket for delete: %w", err)
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return err
	}

	tupleTLV := EncodeTupleTLV(CTATupleOrig, e.Origin)

	reqBuf := new(bytes.Buffer)
	totalLen := uint32(16 + 4 + len(tupleTLV))
	reqHdr := syscall.NlMsghdr{
		Len:   totalLen,
		Type:  NLMsgTypeCTDelete,
		Flags: NLMFRequest | NLMFAck,
		Seq:   2,
		Pid:   uint32(os.Getpid()),
	}
	binary.Write(reqBuf, binary.LittleEndian, reqHdr)
	// nfgenmsg
	reqBuf.Write([]byte{0, 0, 0, 0})
	reqBuf.Write(tupleTLV)

	if err := syscall.Sendto(fd, reqBuf.Bytes(), 0, sa); err != nil {
		return fmt.Errorf("sending delete request: %w", err)
	}

	// Read ACK
	respBuf := make([]byte, 1024)
	nr, _, err := syscall.Recvfrom(fd, respBuf, 0)
	if err != nil {
		return fmt.Errorf("receiving delete response: %w", err)
	}
	if nr >= 20 {
		errno := int32(binary.LittleEndian.Uint32(respBuf[16:20]))
		if errno < 0 {
			return fmt.Errorf("kernel returned error for delete: %w", syscall.Errno(-errno))
		}
	}

	return nil
}
