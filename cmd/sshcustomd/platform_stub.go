//go:build !linux

package main

import (
	"errors"
	"net"
)

func setTCPTimeouts(tc *net.TCPConn, _, _, _, _ int) {}

func listenTransparentTCP(addr string) (net.Listener, error) {
	return nil, errors.New("transparent proxy requires Linux")
}

func originalDst(conn *net.TCPConn) (string, error) {
	return "", errors.New("original dst requires Linux")
}
