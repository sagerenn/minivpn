package userspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/ooni/minivpn/internal/model"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	channelDepth = 1024
	defaultMTU   = 1500
)

// Stack bridges the OpenVPN tunnel with a gVisor TCP/IP stack so we can run
// entirely in userspace.
type Stack struct {
	logger model.Logger
	tun    net.Conn

	endpoint *channel.Endpoint
	stack    *stack.Stack
	nicID    tcpip.NICID

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mtu uint32
}

// New creates a Stack instance that immediately starts moving packets between
// the OpenVPN tunnel and the gVisor network stack.
func New(ctx context.Context, logger model.Logger, tunConn net.Conn, localIP, remoteIP net.IP, mask net.IPMask) (*Stack, error) {
	if tunConn == nil {
		return nil, errors.New("userspace: nil tunnel connection")
	}
	local := localIP.To4()
	remote := remoteIP.To4()
	if local == nil || remote == nil {
		return nil, errors.New("userspace: only IPv4 addresses are supported")
	}
	prefixLen := 32
	if mask != nil {
		if ones, _ := mask.Size(); ones != 0 {
			prefixLen = ones
		}
	}
	localAddr := tcpip.AddrFrom4Slice(local)
	remoteAddr := tcpip.AddrFrom4Slice(remote)

	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})

	linkEP := channel.New(channelDepth, defaultMTU, "")
	nicID := tcpip.NICID(1)
	if err := ipStack.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("userspace: create NIC: %s", err)
	}
	if err := ipStack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   localAddr,
			PrefixLen: prefixLen,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("userspace: add local address: %s", err)
	}
	ipStack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
			Gateway:     remoteAddr,
		},
	})

	stackCtx, cancel := context.WithCancel(ctx)
	us := &Stack{
		logger:   logger,
		tun:      tunConn,
		endpoint: linkEP,
		stack:    ipStack,
		nicID:    nicID,
		ctx:      stackCtx,
		cancel:   cancel,
		mtu:      defaultMTU,
	}
	us.startPumpers()
	return us, nil
}

// Close stops the stack and tears down the underlying tunnel connection.
func (s *Stack) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	s.endpoint.Close()
	s.tun.Close()
	s.wg.Wait()
	return nil
}

// Done returns a channel that is closed when the stack shuts down.
func (s *Stack) Done() <-chan struct{} {
	if s == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.ctx.Done()
}

// DialContext opens a TCP or UDP connection using the userspace stack. The
// address must include a port (e.g., "1.1.1.1:80").
func (s *Stack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if s == nil {
		return nil, errors.New("userspace: stack not initialized")
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("userspace: invalid address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, lookErr := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if lookErr != nil {
			return nil, fmt.Errorf("userspace: resolve %s: %w", host, lookErr)
		}
		for _, candidate := range ips {
			if v4 := candidate.To4(); v4 != nil {
				ip = v4
				break
			}
		}
		if ip == nil {
			return nil, fmt.Errorf("userspace: no IPv4 address for %s", host)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("userspace: invalid port %q", portStr)
	}
	fullAddr := tcpip.FullAddress{
		NIC:  s.nicID,
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}
	switch network {
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, s.stack, fullAddr, ipv4.ProtocolNumber)
	case "udp", "udp4":
		return gonet.DialUDP(s.stack, nil, &fullAddr, ipv4.ProtocolNumber)
	default:
		return nil, fmt.Errorf("userspace: unsupported network %q", network)
	}
}

func (s *Stack) startPumpers() {
	s.wg.Add(2)
	go s.pumpTunToStack()
	go s.pumpStackToTun()
}

func (s *Stack) pumpTunToStack() {
	defer s.wg.Done()
	buf := make([]byte, s.mtu)
	for {
		if err := s.ctx.Err(); err != nil {
			return
		}
		n, err := s.tun.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				s.cancel()
				return
			}
			s.logger.Warnf("userspace: tun read error: %s", err)
			s.cancel()
			return
		}
		if n == 0 {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		proto := detectProtocol(data)
		if proto != header.IPv4ProtocolNumber {
			s.logger.Warnf("userspace: dropping unsupported IP version %d", proto)
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		s.endpoint.InjectInbound(proto, packet)
		packet.DecRef()
	}
}

func (s *Stack) pumpStackToTun() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		packet := s.endpoint.ReadContext(s.ctx)
		if packet.IsNil() {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}
		view := packet.ToView()
		payload := append([]byte(nil), view.AsSlice()...)
		view.Release()
		packet.DecRef()
		if len(payload) == 0 {
			continue
		}
		if _, err := s.tun.Write(payload); err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				s.logger.Warnf("userspace: tun write error: %s", err)
			}
			s.cancel()
			return
		}
	}
}

func detectProtocol(pkt []byte) tcpip.NetworkProtocolNumber {
	if len(pkt) == 0 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		return header.IPv4ProtocolNumber
	case 6:
		return header.IPv6ProtocolNumber
	default:
		return 0
	}
}
