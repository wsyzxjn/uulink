package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/user/uulink/pkg/logging"
	"github.com/user/uulink/pkg/peer"
	"github.com/user/uulink/pkg/tunnel"
	"github.com/user/uulink/pkg/tunnel/mixsend"
)

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

// startMixKCPProbe sends the observed raw PM frame format over mix-kcp after
// ICE connects. It does not participate in the normal tunnel data path.
func startMixKCPProbe(p *peer.Peer, rule tunnel.Rule, ruleID string) {
	p.OnICEConnected(func() {
		peerAddr := firstHostCandidate(p.RemoteCandidates())
		if peerAddr == nil {
			logging.Errorf("[mixkcp] no host candidate from remote, cannot send")
			return
		}
		sender, err := mixsend.NewSender(peerAddr)
		if err != nil {
			logging.Errorf("[mixkcp] sender: %v", err)
			return
		}
		defer sender.Close()
		logging.Debugf("[mixkcp] sending CONNECT to %s (rule %s, target %s:%d)",
			peerAddr, ruleID, rule.TargetHost, rule.TargetPort)

		payload := base64.StdEncoding.EncodeToString(
			[]byte(fmt.Sprintf(`{"version":1,"target_port":%d,"target_host":"%s"}`, rule.TargetPort, rule.TargetHost)),
		)
		connectJSON := fmt.Sprintf(
			`{"seq":"6","timestamp":"%d","portMappingFrame":{"sessionId":"1","ruleId":"%s","streamId":"1","payload":"%s"}}`,
			time.Now().Unix(), ruleID, payload,
		)
		if err := sender.SendPMFrame(0x43, []byte(connectJSON)); err != nil {
			logging.Errorf("[mixkcp] send CONNECT: %v", err)
			return
		}
		logging.Debugf("[mixkcp] CONNECT frame sent (%d bytes)", len(connectJSON))

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			sender.SetReadDeadline(deadline)
			frame, err := sender.ReceivePMFrame()
			if err != nil {
				logging.Debugf("[mixkcp] no SYN_ACK received within deadline: %v", err)
				return
			}
			logging.Debugf("[mixkcp] inbound frame cmd=%#x", frame.Cmd)
			if frame.Cmd == 0x5d {
				logging.Debugf("[mixkcp] SYN_ACK-like frame received")
			}
		}
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
