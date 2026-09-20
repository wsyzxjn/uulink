//go:build !experiments

package main

import (
	"flag"

	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// The protocol experiments are compiled in with -tags experiments; without
// the tag their flags are not registered, so these are never reached.

func bindExperimentFlags(*flag.FlagSet) {}

func startPCKSweep(*peer.Peer, tunnel.Rule, string) {}

func startMixKCPProbe(*peer.Peer, tunnel.Rule, string) {}
