//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	tcpUserTimeout = 18
	tcpKeepIdle    = 4
	tcpKeepIntvl   = 5
	tcpKeepCnt     = 6
	ipTransparent  = 19
)

func setTCPTimeouts(tc *net.TCPConn, userTimeoutS, idleS, intvlS, cnt int) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, userTimeoutS*1000)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, idleS)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, intvlS)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, cnt)
	})
}

func listenTransparentTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipTransparent, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

func originalDst(conn *net.TCPConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	const soOriginalDst = 80
	var out string
	var serr error
	err = raw.Control(func(fd uintptr) {
		var addr syscall.RawSockaddrInet4
		sz := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			uintptr(syscall.SOL_IP), uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&sz)), 0)
		if errno != 0 {
			serr = errno
			return
		}
		if addr.Family != syscall.AF_INET {
			serr = fmt.Errorf("unexpected family %d", addr.Family)
			return
		}
		port := int((addr.Port&0xff)<<8 | addr.Port>>8)
		ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3]).String()
		out = net.JoinHostPort(ip, strconv.Itoa(port))
	})
	if err != nil {
		return "", err
	}
	if serr != nil {
		return "", serr
	}
	if out == "" {
		return "", errors.New("empty original dst")
	}
	return out, nil
}
