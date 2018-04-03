package main

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

const IP6T_SO_ORIGINAL_DST = 80

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn *net.TCPConn) (net.TCPAddr, *os.File, error) {
	f, err := conn.File()
	if err != nil {
		return net.TCPAddr{}, f, err
	}

	fd := int(f.Fd())

	var addr syscall.RawSockaddrInet6
	size := uint32(unsafe.Sizeof(addr))
	err = getsockopt(int(fd), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, unsafe.Pointer(&addr), &size)
	if err != nil {
		return net.TCPAddr{}, f, err
	}

	var ip net.IP

	ip = addr.Addr[:]

	return net.TCPAddr{IP: ip, Port: int(addr.Port)}, f, nil
}

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}
