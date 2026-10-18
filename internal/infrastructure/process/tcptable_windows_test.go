//go:build windows

package process

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
)

// A table built by hand: the byte order of addresses and ports, what the
// upper half of a port DWORD may carry, a TIME_WAIT leftover without owner,
// and both ends of one loopback connection
func TestConnOwnerReadsTheTable(t *testing.T) {
	lo, lo2 := [4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 2}
	row := func(state uint32, la [4]byte, lp uint16, ra [4]byte, rp uint16, pid uint32) []byte {
		b := make([]byte, tcpRowOwnerPIDSize)
		binary.LittleEndian.PutUint32(b[0:], state)
		copy(b[4:8], la[:])
		b[8], b[9], b[10], b[11] = byte(lp>>8), byte(lp), 0xAB, 0xCD // network order, then garbage
		copy(b[12:16], ra[:])
		b[16], b[17], b[18], b[19] = byte(rp>>8), byte(rp), 0xEF, 0x12
		binary.LittleEndian.PutUint32(b[20:], pid)
		return b
	}
	table := func(rows ...[]byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(len(rows)))
		for _, r := range rows {
			b = append(b, r...)
		}
		return b
	}
	const established = 5
	api := netip.MustParseAddrPort("127.0.0.1:50123")
	us := netip.MustParseAddrPort("127.0.0.1:61000")
	tbl := table(
		row(mibTCPStateTimeWait, lo, 50123, lo, 61000, 0), // an earlier connection of the pair
		row(established, lo, 61000, lo, 50123, 111),       // this end
		row(established, lo, 50123, lo2, 61000, 333),      // another remote address
		row(established, lo, 0xCBC3, lo, 61000, 444),      // the API port byte-swapped
		row(established, lo, 50123, lo, 61000, 222),       // the other end
	)

	if pid, err := connOwner(tbl, api, us); err != nil || pid != 222 {
		t.Fatalf("other end: %d, %v; want 222", pid, err)
	}
	if pid, err := connOwner(tbl, us, api); err != nil || pid != 111 {
		t.Fatalf("this end: %d, %v; want 111", pid, err)
	}
	if _, err := connOwner(tbl, api, netip.MustParseAddrPort("127.0.0.1:61001")); !errors.Is(err, ErrConnNotFound) {
		t.Fatalf("missing connection: %v, want ErrConnNotFound", err)
	}

	two := table(row(established, lo, 50123, lo, 61000, 222), row(established, lo, 50123, lo, 61000, 555))
	if _, err := connOwner(two, api, us); err == nil {
		t.Fatal("two owners of one connection accepted")
	}
	truncated := tbl[:len(tbl)-1]
	if _, err := connOwner(truncated, api, us); err == nil {
		t.Fatal("truncated table accepted")
	}
	if _, err := connOwner([]byte{1, 0}, api, us); err == nil {
		t.Fatal("short table accepted")
	}
}

// The real table, on a listener of this process: the other end of a
// connection names the process that listens — already before it accepted
// the connection (the prober checks right after its dial)
func TestConnOwnerPIDOfOwnListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	api := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	us := c.LocalAddr().(*net.TCPAddr).AddrPort()
	own := uint32(os.Getpid())

	if pid, err := ConnOwnerPID(api, us); err != nil || pid != own {
		t.Fatalf("before Accept: ConnOwnerPID(%v, %v) = %d, %v; want %d", api, us, pid, err, own)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if pid, err := ConnOwnerPID(api, us); err != nil || pid != own {
		t.Fatalf("after Accept: ConnOwnerPID(%v, %v) = %d, %v; want %d", api, us, pid, err, own)
	}
	if pid, err := ConnOwnerPID(us, api); err != nil || pid != own {
		t.Fatalf("this end: ConnOwnerPID(%v, %v) = %d, %v; want %d", us, api, pid, err, own)
	}
	// IPv4 in IPv6 clothing, as a dual-stack address may come
	mapped := netip.AddrPortFrom(netip.AddrFrom16(api.Addr().As16()), api.Port())
	if pid, err := ConnOwnerPID(mapped, us); err != nil || pid != own {
		t.Fatalf("mapped address: %d, %v", pid, err)
	}

	if _, err := ConnOwnerPID(api, netip.AddrPortFrom(us.Addr(), 1)); !errors.Is(err, ErrConnNotFound) {
		t.Fatalf("no such connection: %v, want ErrConnNotFound", err)
	}
	v6 := netip.MustParseAddrPort("[::1]:443")
	if _, err := ConnOwnerPID(v6, us); err == nil || errors.Is(err, ErrConnNotFound) {
		t.Fatalf("IPv6 endpoint: %v, want a refusal", err)
	}
}
