package landiscover

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/user/uulink/pkg/logging"
)

// FormatMessage creates the Minecraft LAN discovery broadcast string.
func FormatMessage(motd string, port int) string {
	return fmt.Sprintf("[MOTD]%s[/MOTD][AD]%d[/AD]", motd, port)
}

// Service broadcasts Minecraft LAN discovery packets so local game clients
// can automatically discover the forwarded game server.
type Service struct {
	motd     string
	port     int
	interval time.Duration
	done     chan struct{}
	wg       sync.WaitGroup
}

// Start initiates periodic LAN discovery broadcasts for Minecraft.
func Start(motd string, port int, interval time.Duration) (*Service, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid lan discovery port: %d", port)
	}
	if motd == "" {
		motd = "Minecraft Server via uulink"
	}
	if interval <= 0 {
		interval = 1500 * time.Millisecond
	}

	s := &Service{
		motd:     motd,
		port:     port,
		interval: interval,
		done:     make(chan struct{}),
	}

	s.wg.Add(1)
	go s.loop()
	return s, nil
}

// Stop terminates the broadcast service.
func (s *Service) Stop() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	s.wg.Wait()
}

func (s *Service) loop() {
	defer s.wg.Done()

	payload := []byte(FormatMessage(s.motd, s.port))

	targets := []string{
		"224.0.2.60:4445",      // standard Minecraft IPv4 multicast
		"255.255.255.255:4445", // IPv4 local broadcast
		"127.0.0.1:4445",       // loopback broadcast fallback
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		logging.Debugf("[lan-discover] failed to bind UDP socket: %v", err)
		return
	}
	defer conn.Close()

	resolvedAddrs := make([]net.Addr, 0, len(targets))
	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp4", target)
		if err == nil {
			resolvedAddrs = append(resolvedAddrs, addr)
		}
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	logging.Infof("[lan-discover] Minecraft LAN discovery broadcasting on port %d (motd: %q)", s.port, s.motd)

	send := func() {
		for _, addr := range resolvedAddrs {
			_, _ = conn.WriteTo(payload, addr)
		}
	}

	send()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			send()
		}
	}
}
