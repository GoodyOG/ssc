//go:build !linux

package udpgw

import (
	"context"
	"net"
)

// Stub types for non-Linux platforms (Windows, macOS — development only).
// The real implementation is in udpgw.go (linux).

type Config struct {
	ListenAddr string
}

type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

type Server struct{}

func NewServer(cfg Config, dialer Dialer) *Server { return &Server{} }
func (s *Server) Serve(ctx context.Context, serverUDPGWAddr string) error {
	return nil
}
func (s *Server) Shutdown() {}

type Stats struct {
	ActiveFlows int
}

func (s *Server) GetStats() Stats { return Stats{} }
