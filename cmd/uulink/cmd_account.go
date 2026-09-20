package main

import (
	"flag"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
)

// Account commands: login, refresh-login, list, whoami.

type loginOptions struct {
	interactive bool
	mobile      string
	countryCode string
	timeout     time.Duration
}

func loginCommand() *command {
	opts := &loginOptions{}
	return &command{
		name:    "login",
		summary: "Log in to a UU Remote account and save the credentials to the config file",
		long: `By default a QR-code login link is printed; open or scan it with the UU Remote
mobile app. Use -mobile to log in with an SMS verification code instead, or
-interactive to choose at a prompt. A missing config file is created, and the
device is registered with UU Remote on first use.`,
		bind: func(fs *flag.FlagSet) {
			fs.BoolVar(&opts.interactive, "interactive", false, "choose the login method at a prompt (QR code or SMS code)")
			fs.StringVar(&opts.mobile, "mobile", "", "mobile phone number for SMS verification-code login")
			fs.StringVar(&opts.countryCode, "country-code", "+86", "country code for the mobile number")
			fs.DurationVar(&opts.timeout, "timeout", 5*time.Minute, "how long to wait for the QR-code login to be confirmed")
		},
		run: func(g *globalOptions) error {
			cfg, err := loadConfig(g, true)
			if err != nil {
				return err
			}
			client := api.NewClient(cfg)
			switch {
			case opts.interactive:
				return doInteractiveLogin(client, cfg, g.configPath, opts.timeout, opts.countryCode)
			case opts.mobile != "":
				return doMobileLogin(client, cfg, g.configPath, opts.countryCode, opts.mobile)
			default:
				return doLoginQRCode(client, cfg, g.configPath, opts.timeout)
			}
		},
	}
}

func refreshLoginCommand() *command {
	var timeout time.Duration
	return &command{
		name:    "refresh-login",
		summary: "Check the saved login and run the QR-code login again only if it expired",
		bind: func(fs *flag.FlagSet) {
			fs.DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for the QR-code login to be confirmed")
		},
		run: func(g *globalOptions) error {
			cfg, err := loadConfig(g, true)
			if err != nil {
				return err
			}
			return doRefreshLogin(api.NewClient(cfg), cfg, g.configPath, timeout)
		},
	}
}

func listCommand() *command {
	return &command{
		name:    "list",
		summary: "List the devices registered under the account and their online status",
		run: func(g *globalOptions) error {
			cfg, err := loadConfig(g, false)
			if err != nil {
				return err
			}
			return doListDevices(api.NewClient(cfg))
		},
	}
}

func whoamiCommand() *command {
	return &command{
		name:    "whoami",
		summary: "Show the user the saved credentials belong to",
		run: func(g *globalOptions) error {
			cfg, err := loadConfig(g, false)
			if err != nil {
				return err
			}
			return doUserInfo(api.NewClient(cfg))
		},
	}
}
