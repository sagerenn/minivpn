package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Doridian/water"
	"github.com/apex/log"
	"github.com/jackpal/gateway"

	"github.com/ooni/minivpn/extras/ping"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/pkg/config"
	"github.com/ooni/minivpn/pkg/tracex"
	"github.com/ooni/minivpn/pkg/tunnel"
	"github.com/ooni/minivpn/pkg/userspace"
)

func runCmd(binaryPath string, args ...string) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.WithError(err).Warn("error running /sbin/ip")
	}
}

func runIP(args ...string) {
	runCmd("/sbin/ip", args...)
}

func runRoute(args ...string) {
	runCmd("/sbin/route", args...)
}

func resolveRemoteWithCustomDNS(ctx context.Context, cfg *cmdConfig, vpncfg *config.Config) error {
	if cfg.remoteDNS == "" {
		return nil
	}
	remoteHost := vpncfg.OpenVPNOptions().Remote
	if remoteHost == "" {
		return fmt.Errorf("remote host not configured")
	}
	if net.ParseIP(remoteHost) != nil {
		return nil
	}
	targetDNS := cfg.remoteDNS
	if !strings.Contains(targetDNS, ":") {
		targetDNS = net.JoinHostPort(targetDNS, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, targetDNS)
		},
	}
	ips, err := resolver.LookupIP(ctx, "ip4", remoteHost)
	if err != nil {
		return fmt.Errorf("lookup %s via %s: %w", remoteHost, targetDNS, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("lookup %s via %s returned no IPv4 addresses", remoteHost, targetDNS)
	}
	resolved := ips[0].String()
	vpncfg.Logger().Infof("remote host %s resolved to %s via %s", remoteHost, resolved, targetDNS)
	vpncfg.OpenVPNOptions().Remote = resolved
	return nil
}

type cmdConfig struct {
	configPath     string
	doPing         bool
	doTrace        bool
	skipRoute      bool
	userspace      bool
	userspaceSocks string
	remoteDNS      string
	timeout        int
}

func main() {
	log.SetLevel(log.DebugLevel)

	cfg := &cmdConfig{}
	flag.StringVar(&cfg.configPath, "config", "", "config file to load")
	flag.BoolVar(&cfg.doPing, "ping", false, "if true, do ping and exit (for testing)")
	flag.BoolVar(&cfg.doTrace, "trace", false, "if true, do a trace of the handshake and exit (for testing)")
	flag.BoolVar(&cfg.skipRoute, "skip-route", false, "if true, exit without setting routes (for testing)")
	flag.BoolVar(&cfg.userspace, "userspace", false, "use the gVisor stack instead of the kernel TUN device")
	flag.StringVar(&cfg.userspaceSocks, "userspace-socks", "", "SOCKS5 listen address for --userspace (e.g. 127.0.0.1:1080)")
	flag.StringVar(&cfg.remoteDNS, "remote-dns", "", "resolve remote hostnames using this DNS server (ip[:port]) before connecting")
	flag.IntVar(&cfg.timeout, "timeout", 60, "timeout in seconds (default=60)")
	flag.Parse()

	if cfg.configPath == "" {
		fmt.Println("[error] need config path")
		os.Exit(1)
	}
	if cfg.userspaceSocks != "" && !cfg.userspace {
		fmt.Println("[error] --userspace-socks requires --userspace")
		os.Exit(1)
	}
	if cfg.userspace && cfg.doPing {
		fmt.Println("[error] --ping cannot be combined with --userspace")
		os.Exit(1)
	}
	if cfg.userspace && cfg.skipRoute {
		fmt.Println("[error] --skip-route cannot be combined with --userspace")
		os.Exit(1)
	}

	log.SetHandler(NewHandler(os.Stderr))
	log.SetLevel(log.DebugLevel)

	opts := []config.Option{
		config.WithConfigFile(cfg.configPath),
		config.WithLogger(log.Log),
	}

	start := time.Now()

	var tracer *tracex.Tracer
	if cfg.doTrace {
		tracer = tracex.NewTracer(start)
		opts = append(opts, config.WithHandshakeTracer(tracer))
		defer func() {
			trace := tracer.Trace()
			jsonData, err := json.MarshalIndent(trace, "", "  ")
			runtimex.PanicOnError(err, "cannot serialize trace")
			fileName := fmt.Sprintf("handshake-trace-%s.json", time.Now().Format("2006-01-02-15:05:00"))
			os.WriteFile(fileName, jsonData, 0644)
			fmt.Println("trace written to", fileName)
		}()
	}

	// The TLS will expire in 60 seconds by default, but we can pass
	// a shorter timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.timeout)*time.Second)
	defer cancel()

	// create config from the passed options
	vpncfg := config.NewConfig(opts...)
	if err := resolveRemoteWithCustomDNS(ctx, cfg, vpncfg); err != nil {
		log.WithError(err).Fatal("remote DNS resolution failed")
	}

	// create a vpn tun Device
	tun, err := tunnel.Start(ctx, &net.Dialer{}, vpncfg)
	if err != nil {
		log.WithError(err).Error("init error")
		return
	}
	log.Infof("Local IP: %s\n", tun.LocalAddr())
	log.Infof("Gateway:  %s\n", tun.RemoteAddr())

	fmt.Println("initialization-sequence-completed")
	fmt.Printf("elapsed: %v\n", time.Since(start))

	if cfg.doTrace {
		return
	}

	if cfg.userspace {
		if err := runUserspaceMode(cfg, vpncfg, tun); err != nil {
			log.WithError(err).Fatal("userspace mode error")
		}
		return
	}

	if cfg.doPing {
		pinger := ping.New("8.8.8.8", tun)
		count := 5
		pinger.Count = count

		err = pinger.Run(context.Background())
		if err != nil {
			pinger.PrintStats()
			log.WithError(err).Fatal("ping error")
		}
		pinger.PrintStats()
		os.Exit(0)
	}

	if cfg.skipRoute {
		os.Exit(0)
	}

	// create a tun interface on the OS
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	runtimex.PanicOnError(err, "unable to open tun interface")

	// TODO: investigate what's the maximum working MTU, additionally get it from flag.
	MTU := 1420
	iface.SetMTU(MTU)

	localAddr := tun.LocalAddr().String()
	remoteAddr := tun.RemoteAddr().String()
	netMask := tun.NetMask()

	// discover local gateway IP, we need it to add a route to our remote via our network gw
	defaultGatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		log.Warn("could not discover default gateway IP, routes might be broken")
	}
	defaultInterfaceIP, err := gateway.DiscoverInterface()
	if err != nil {
		log.Warn("could not discover default route interface IP, routes might be broken")
	}
	defaultInterface, err := getInterfaceByIP(defaultInterfaceIP.String())
	if err != nil {
		log.Warn("could not get default route interface, routes might be broken")
	}

	if defaultGatewayIP != nil && defaultInterface != nil {
		log.Infof("route add %s gw %v dev %s", vpncfg.Remote().IPAddr, defaultGatewayIP, defaultInterface.Name)
		runRoute("add", vpncfg.Remote().IPAddr, "gw", defaultGatewayIP.String(), defaultInterface.Name)
	}

	// we want the network CIDR for setting up the routes
	network := &net.IPNet{
		IP:   net.ParseIP(localAddr).Mask(netMask),
		Mask: netMask,
	}

	// configure the interface and bring it up
	runIP("addr", "add", localAddr, "dev", iface.Name())
	runIP("link", "set", "dev", iface.Name(), "up")
	runRoute("add", remoteAddr, "gw", localAddr)
	runRoute("add", "-net", network.String(), "dev", iface.Name())
	runIP("route", "add", "default", "via", remoteAddr, "dev", iface.Name())

	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := iface.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			tun.Write(packet[:n])
		}
	}()
	go func() {
		for {
			packet := make([]byte, 2000)
			n, err := tun.Read(packet)
			if err != nil {
				log.WithError(err).Fatal("error reading from tun")
			}
			iface.Write(packet[:n])
		}
	}()
	select {}
}

func runUserspaceMode(cfg *cmdConfig, vpncfg *config.Config, tunConn *tunnel.TUN) error {
	localIP := net.ParseIP(tunConn.LocalAddr().String())
	if localIP == nil {
		return fmt.Errorf("userspace: invalid local address %s", tunConn.LocalAddr())
	}
	remoteIP := net.ParseIP(tunConn.RemoteAddr().String())
	if remoteIP == nil {
		return fmt.Errorf("userspace: invalid gateway address %s", tunConn.RemoteAddr())
	}
	stackCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stack, err := userspace.New(stackCtx, vpncfg.Logger(), tunConn, localIP, remoteIP, tunConn.NetMask())
	if err != nil {
		return err
	}
	defer stack.Close()

	if cfg.userspaceSocks != "" {
		go func() {
			if err := stack.ServeSOCKS(stackCtx, cfg.userspaceSocks); err != nil {
				log.WithError(err).Warn("userspace SOCKS server stopped")
			}
		}()
		log.Infof("SOCKS5 proxy listening on %s", cfg.userspaceSocks)
	} else {
		log.Warn("userspace stack active without SOCKS proxy; set --userspace-socks to expose it")
	}

	log.Info("userspace stack ready; press Ctrl+C to exit")
	<-stack.Done()
	return fmt.Errorf("userspace stack terminated")
}
