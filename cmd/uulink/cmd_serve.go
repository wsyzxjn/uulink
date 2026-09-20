package main

import (
	"context"
	"flag"

	"github.com/wsyzxjn/uulink/pkg/api"
)

// serve exposes this account's device: it registers the device as controllable,
// creates a room, and answers controllers that run `uulink connect -device`.

type serveOptions struct {
	mapping  mappingFlags
	policy   policyFlags
	sessions sessionFlags
	roomFile string
}

func serveCommand() *command {
	opts := &serveOptions{}
	return &command{
		name:    "serve",
		summary: "Expose this device to controllers of the same account",
		long: `Requires a logged-in config (see 'uulink login'). Mapping flags declare
listeners on this side that reach services on the controller; without them the
process only accepts the controller's inbound mappings, subject to the security
policy flags.`,
		bind: func(fs *flag.FlagSet) {
			opts.mapping.bind(fs)
			opts.policy.bind(fs)
			opts.sessions.bind(fs)
			fs.StringVar(&opts.roomFile, "room-file", "", debugUsagePrefix+"write the room connection info to this file for a same-host controller")
		},
		run: func(g *globalOptions) error {
			cfg, err := loadConfig(g, false)
			if err != nil {
				return err
			}
			rules, err := opts.mapping.rules(cfg)
			if err != nil {
				return err
			}
			policy, err := opts.policy.policy(cfg)
			if err != nil {
				return err
			}
			sessions, err := opts.sessions.resolve(cfg)
			if err != nil {
				return err
			}
			client := api.NewClient(cfg)
			return recoverTunnel(func(ctx context.Context) error {
				return doServe(ctx, client, cfg, rules, opts.roomFile, policy, sessions.target)
			})
		},
	}
}
