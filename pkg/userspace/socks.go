package userspace

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	socksVersion            = 0x05
	socksCmdConnect         = 0x01
	socksRepSuccess         = 0x00
	socksRepGeneralFail     = 0x01
	socksRepNotAllowed      = 0x02
	socksRepNetworkFail     = 0x03
	socksRepHostFail        = 0x04
	socksRepCmdUnsupported  = 0x07
	socksRepAddrUnsupported = 0x08
)

// ServeSOCKS exposes the userspace stack through a minimal SOCKS5 CONNECT
// proxy. The listener stops when the context is canceled or an unrecoverable
// error occurs.
func (s *Stack) ServeSOCKS(ctx context.Context, addr string) error {
	if s == nil {
		return fmt.Errorf("userspace: stack not initialized")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("userspace: socks listen: %w", err)
	}
	defer ln.Close()

	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-s.Done():
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return fmt.Errorf("userspace: socks accept: %w", err)
		}
		go s.handleSOCKSConn(ctx, conn)
	}
}

func (s *Stack) handleSOCKSConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := s.readSOCKSHello(conn); err != nil {
		s.logger.Warnf("userspace: socks hello failed: %s", err)
		return
	}
	target, atyp, err := s.readSOCKSRequest(conn)
	if err != nil {
		s.logger.Warnf("userspace: socks request failed: %s", err)
		s.replySOCKS(conn, socksRepGeneralFail, atyp)
		return
	}
	remote, err := s.DialContext(ctx, "tcp", target)
	if err != nil {
		s.logger.Warnf("userspace: socks dial %s failed: %s", target, err)
		s.replySOCKS(conn, socksRepHostFail, atyp)
		return
	}
	defer remote.Close()
	if err := s.replySOCKS(conn, socksRepSuccess, atyp); err != nil {
		s.logger.Warnf("userspace: socks reply failed: %s", err)
		return
	}
	s.bridgeConnections(ctx, conn, remote)
}

func (s *Stack) readSOCKSHello(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return fmt.Errorf("unsupported version %d", header[0])
	}
	methodCount := int(header[1])
	if methodCount == 0 {
		return fmt.Errorf("no auth methods provided")
	}
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	_, err := conn.Write([]byte{socksVersion, 0x00})
	return err
}

func (s *Stack) readSOCKSRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socksVersion {
		return "", header[3], fmt.Errorf("unsupported version %d", header[0])
	}
	if header[1] != socksCmdConnect {
		return "", header[3], fmt.Errorf("unsupported command %d", header[1])
	}
	atyp := header[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", atyp, err
		}
		host = net.IP(addr).String()
	case 0x03: // Domain name
		var lengthBuf [1]byte
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			return "", atyp, err
		}
		hostBytes := make([]byte, int(lengthBuf[0]))
		if _, err := io.ReadFull(conn, hostBytes); err != nil {
			return "", atyp, err
		}
		host = string(hostBytes)
	case 0x04:
		return "", atyp, fmt.Errorf("ipv6 addresses not supported")
	default:
		return "", atyp, fmt.Errorf("unknown address type %d", atyp)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", atyp, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), atyp, nil
}

func (s *Stack) replySOCKS(conn net.Conn, rep byte, atyp byte) error {
	if atyp == 0 {
		atyp = 0x01
	}
	response := []byte{
		socksVersion,
		rep,
		0x00,
		atyp,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	_, err := conn.Write(response)
	return err
}

func (s *Stack) bridgeConnections(ctx context.Context, left, right net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			left.Close()
			right.Close()
		})
	}
	stopper := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-stopper:
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(left, right)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		io.Copy(right, left)
		closeBoth()
	}()
	wg.Wait()
	close(stopper)
}
