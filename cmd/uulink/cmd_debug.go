package main

import "github.com/wsyzxjn/uulink/pkg/api"

// debug holds the same-host smoke tests from the reverse-engineering phase.
// The group is hidden from the command listing but always available.

func debugCommand() *command {
	return &command{
		name:    "debug",
		summary: "Same-host debugging helpers",
		hidden:  true,
		sub: []*command{
			{
				name:    "guest-test",
				summary: "Create a guest identity and share, then join it both ways (smoke test)",
				run: func(g *globalOptions) error {
					cfg, err := loadConfig(g, false)
					if err != nil {
						return err
					}
					return doGuestTest(api.NewClient(cfg))
				},
			},
		},
	}
}
