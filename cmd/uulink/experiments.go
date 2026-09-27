//go:build experiments

// Protocol experiments from the reverse-engineering phase. They are excluded
// from normal builds; compile with -tags experiments to get the -pck-sweep and
// -mixkcp flags back.

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
	"github.com/wsyzxjn/uulink/pkg/tunnel/mixkcp"
	"github.com/wsyzxjn/uulink/pkg/tunnel/mixsend"
)

var experimentMixKCPFrame string

// bindExperimentFlags adds the experiment switches to a controller command.
func bindExperimentFlags(fs *flag.FlagSet) {
	fs.BoolVar(experimentPCKSweep, "pck-sweep", false, debugUsagePrefix+"sweep PCK.V3 channels with CONNECT frames after setup")
	fs.BoolVar(experimentMixKCP, "mixkcp", false, debugUsagePrefix+"replay an explicitly supplied complete UDP datagram (requires -mixkcp-frame)")
	fs.StringVar(&experimentMixKCPFrame, "mixkcp-frame", "", debugUsagePrefix+"file containing a complete encoded mix-kcp datagram")
}

// startPCKSweep replicates the observed channel setup and probes which PCK
// logical channel accepts port-mapping frames. It is intentionally isolated
// from the normal controller path because it is a protocol experiment.
func startPCKSweep(p *peer.Peer, rule tunnel.Rule, ruleID string) {
	ready := make(chan struct{})
	var once sync.Once
	p.OnBinaryChannelOpen(func() {
		once.Do(func() { close(ready) })
	})

	go func() {
		<-ready
		time.Sleep(500 * time.Millisecond)
		logging.Debugf("[pck] replicating channel setup")
		for _, kind := range []uint64{1, 2} {
			if err := p.SendSignalPB(tunnel.BuildSessionSetup(kind)); err != nil {
				logging.Errorf("[pck] setup %d error: %v", kind, err)
			}
		}
		time.Sleep(300 * time.Millisecond)
		for _, channel := range []uint32{3, 4} {
			if err := p.SendSignalPB(tunnel.BuildRegistration(channel)); err != nil {
				logging.Errorf("[pck] reg %d error: %v", channel, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
		for channel := uint32(0); channel <= 20; channel++ {
			frame, err := tunnel.BuildConnectPCK(channel, ruleID, "1", rule.TargetHost, rule.TargetPort)
			if err != nil {
				logging.Errorf("[pck] build CONNECT error: %v", err)
				continue
			}
			if err := p.SendSignalPB(frame); err != nil {
				logging.Errorf("[pck] target chan %d send error: %v", channel, err)
				continue
			}
			logging.Debugf("[pck] CONNECT sent on target chan %d", channel)
			time.Sleep(2 * time.Second)
		}
		logging.Debugf("[pck] sweep done")
	}()
}

// validateExperimentFlags rejects incomplete probes before creating a room.
func validateExperimentFlags() error {
	if !*experimentMixKCP {
		return nil
	}
	if experimentMixKCPFrame == "" {
		return fmt.Errorf("-mixkcp requires -mixkcp-frame; encrypted datagrams cannot be synthesized from plaintext")
	}
	_, err := readMixKCPFrame(experimentMixKCPFrame)
	return err
}

func readMixKCPFrame(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65508))
	if err != nil {
		return nil, err
	}
	if len(data) > 65507 {
		return nil, fmt.Errorf("mix-kcp datagram exceeds UDP payload limit")
	}
	if _, err := mixkcp.ParseFrame(data); err != nil {
		return nil, err
	}
	return data, nil
}

// startMixKCPProbe replays a caller-provided encoded frame. A structural reply
// is logged without claiming an undocumented first-byte value means SYN_ACK.
func startMixKCPProbe(p *peer.Peer) {
	wire, err := readMixKCPFrame(experimentMixKCPFrame)
	if err != nil {
		logging.Errorf("[mixkcp] frame: %v", err)
		return
	}
	p.OnICEConnected(func() {
		peerAddr := firstHostCandidate(p.RemoteCandidates())
		if peerAddr == nil {
			logging.Errorf("[mixkcp] no UDP host candidate")
			return
		}
		sender, err := mixsend.NewSender(peerAddr)
		if err != nil {
			logging.Errorf("[mixkcp] sender: %v", err)
			return
		}
		defer sender.Close()
		if err := sender.SendFrame(wire); err != nil {
			logging.Errorf("[mixkcp] send: %v", err)
			return
		}
		sender.SetReadDeadline(time.Now().Add(10 * time.Second))
		frame, err := sender.ReceivePMFrame()
		if err != nil {
			logging.Debugf("[mixkcp] receive: %v", err)
			return
		}
		logging.Debugf("[mixkcp] received datagram: first_byte=%#x payload_bytes=%d", frame.Cmd, len(frame.Payload))
	})
}

// firstHostCandidate extracts a UDP host candidate address from remote ICE
// candidates, preferring the LAN path used by the mix-kcp experiment.
func firstHostCandidate(candidates []string) *net.UDPAddr {
	for _, candidate := range candidates {
		if !strings.Contains(candidate, " typ host") || strings.Contains(candidate, " tcp ") {
			continue
		}
		parts := strings.Fields(candidate)
		if len(parts) < 6 {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(parts[4], parts[5]))
		if err == nil {
			return addr
		}
	}
	return nil
}
