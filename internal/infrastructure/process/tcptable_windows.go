//go:build windows

package process

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetExtendedTcpTable is not in x/sys/windows; from System32 only, like every
// DLL the elevated app loads
var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// ErrConnNotFound: the IPv4 TCP table has no live connection with the given
// endpoints
var ErrConnNotFound = errors.New("no such TCP connection")

const (
	afINET                      = 2
	tcpTableOwnerPIDConnections = 4  // TCP_TABLE_OWNER_PID_CONNECTIONS: every state but LISTEN
	mibTCPStateTimeWait         = 11 // MIB_TCP_STATE_TIME_WAIT: no owner any more (PID 0)
	tcpRowOwnerPIDSize          = 24 // MIB_TCPROW_OWNER_PID: six DWORDs
)

// ConnOwnerPID returns the ID of the process that owns the IPv4 TCP
// connection with this local and remote endpoint. Asked from the other end
// of a connection this app made — local = the port it connected to, remote =
// its own address — it names the process behind it: who really listens on a
// loopback port, which a successful bind does not prove (another program may
// have bound the same port as well). Already true before that process has
// accepted the connection: a queued one is listed under the listener's PID.
// IPv4 only; to a caller checking an owner, ErrConnNotFound (a connection
// gone, or one only the IPv6 table would list) means "not the expected one".
func ConnOwnerPID(local, remote netip.AddrPort) (uint32, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return 0, fmt.Errorf("connection owner of %v -> %v: IPv4 only", local, remote)
	}
	table, err := tcpTable()
	if err != nil {
		return 0, err
	}
	return connOwner(table, local, remote)
}

// tcpTable returns the raw MIB_TCPTABLE_OWNER_PID of the IPv4 connections
func tcpTable() ([]byte, error) {
	size := uint32(16 << 10)
	for range 8 {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, afINET, tcpTableOwnerPIDConnections, 0)
		switch err := windows.Errno(r); err {
		case 0:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += size/8 + 1024 // size is the need now; the table may grow until the next call
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", err)
		}
	}
	return nil, errors.New("GetExtendedTcpTable: the table keeps growing")
}

// connOwner finds the connection local -> remote in a MIB_TCPTABLE_OWNER_PID:
// a DWORD count, then rows of state, local address, local port, remote
// address, remote port, owner PID. Addresses are in network byte order, and
// so are ports — in the low 16 bits of their DWORD, whose upper half may hold
// anything.
func connOwner(table []byte, local, remote netip.AddrPort) (uint32, error) {
	if len(table) < 4 {
		return 0, errors.New("GetExtendedTcpTable: short answer")
	}
	n := uint64(binary.LittleEndian.Uint32(table))
	if 4+n*tcpRowOwnerPIDSize > uint64(len(table)) {
		return 0, errors.New("GetExtendedTcpTable: truncated answer")
	}
	var (
		owner uint32
		found bool
	)
	for i := range int(n) {
		row := table[4+i*tcpRowOwnerPIDSize : 4+(i+1)*tcpRowOwnerPIDSize]
		if binary.LittleEndian.Uint32(row[0:]) == mibTCPStateTimeWait {
			continue
		}
		if rowEndpoint(row[4:12]) != local || rowEndpoint(row[12:20]) != remote {
			continue
		}
		pid := binary.LittleEndian.Uint32(row[20:])
		// One connection per pair of endpoints; two owners would mean the
		// table is not what this reads it as — no answer then
		if found && pid != owner {
			return 0, fmt.Errorf("connection %v -> %v: two owners (%d, %d)", local, remote, owner, pid)
		}
		owner, found = pid, true
	}
	if !found {
		return 0, ErrConnNotFound
	}
	return owner, nil
}

// rowEndpoint decodes an address DWORD followed by a port DWORD
func rowEndpoint(b []byte) netip.AddrPort {
	addr := netip.AddrFrom4([4]byte(b[0:4]))
	port := uint16(b[4])<<8 | uint16(b[5])
	return netip.AddrPortFrom(addr, port)
}
