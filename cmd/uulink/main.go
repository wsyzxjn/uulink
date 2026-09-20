// uulink - standalone UU Remote client for port forwarding.
//
// The binary is organized as subcommands (uulink <command> [flags]); see
// commands() for the tree.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/wsyzxjn/uulink/pkg/logging"
)

// DefaultConfigURL can be baked into a client build so it runs without
// arguments: go build -ldflags="-X main.DefaultConfigURL=https://example.com/room.json"
// A bare invocation then behaves like `uulink connect --config-url <URL>`.
var DefaultConfigURL string

// Protocol experiments are compiled in with -tags experiments, which also
// registers their flags on the controller commands (see experiments.go). In a
// normal build these stay false and the flags do not exist.
var (
	experimentPCKSweep = new(bool)
	experimentMixKCP   = new(bool)
)

// debugUsagePrefix marks a flag as a same-host debugging aid. Such flags work
// in every build but are only listed by -help-debug, so the normal help output
// matches the documented command set.
const debugUsagePrefix = "[debug] "

// globalOptions are accepted before the command name and by every command.
type globalOptions struct {
	configPath string
	logLevel   string
	// stdout receives command output such as the version or device list.
	stdout io.Writer
}

func (g *globalOptions) bind(fs *flag.FlagSet) {
	// Bound with the current values as defaults so `uulink -config x serve`
	// and `uulink serve -config x` both work.
	fs.StringVar(&g.configPath, "config", g.configPath, "path to the config file")
	fs.StringVar(&g.logLevel, "log-level", g.logLevel, "log level: debug, info, warn, or error")
}

// command is one node of the command tree. Leaf commands bind their flags and
// run; group commands (share, debug) only hold subcommands.
type command struct {
	name    string
	summary string
	// args is the usage hint printed after the command name.
	args string
	// long is an optional paragraph printed under the usage line.
	long string
	// hidden keeps a command out of the listings; it still runs.
	hidden bool
	bind   func(fs *flag.FlagSet)
	run    func(g *globalOptions) error
	sub    []*command
}

func commands() []*command {
	return []*command{
		loginCommand(),
		refreshLoginCommand(),
		listCommand(),
		whoamiCommand(),
		serveCommand(),
		connectCommand(),
		shareCommand(),
		versionCommand(),
		debugCommand(),
	}
}

// usageError reports a mistake in the command line. main exits with status 2
// for it, which lets supervisors tell misconfiguration from runtime failures.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

func main() {
	err := run(os.Args[1:], os.Stdout)
	switch {
	case err == nil:
	case errors.As(err, new(*usageError)):
		fmt.Fprintf(os.Stderr, "uulink: %v\n", err)
		os.Exit(2)
	default:
		logging.Errorf("%v", err)
		os.Exit(1)
	}
}

// run parses args and executes the selected command. stdout receives help
// text and command output.
func run(args []string, stdout io.Writer) error {
	g := &globalOptions{configPath: "config.json", logLevel: "info", stdout: stdout}
	root := flag.NewFlagSet("uulink", flag.ContinueOnError)
	root.SetOutput(io.Discard)
	g.bind(root)
	showVersion := root.Bool("version", false, "print version information and exit")
	root.BoolVar(showVersion, "v", false, "print version information and exit (shorthand)")
	if err := root.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printRootUsage(stdout, root)
			return nil
		}
		return usageErrorf("%w (see 'uulink help')", err)
	}
	if *showVersion {
		fmt.Fprintln(stdout, formatVersion())
		return nil
	}

	rest := root.Args()
	if len(rest) == 0 {
		if DefaultConfigURL != "" {
			// A distributed zero-argument client: connect with the baked URL.
			rest = []string{"connect"}
		} else {
			printRootUsage(stdout, root)
			return usageErrorf("no command given")
		}
	}

	if rest[0] == "help" {
		if len(rest) == 1 {
			printRootUsage(stdout, root)
			return nil
		}
		cmd, path, err := findCommand(commands(), rest[1:])
		if err != nil {
			return err
		}
		printCommandUsage(stdout, cmd, path, false)
		return nil
	}

	cmd, path, err := findCommand(commands(), rest)
	if err != nil {
		return err
	}
	cmdArgs := rest[len(path):]
	if cmd.run == nil {
		printCommandUsage(stdout, cmd, path, false)
		if len(cmdArgs) > 0 {
			return usageErrorf("unknown %s command %q", strings.Join(path, " "), cmdArgs[0])
		}
		return usageErrorf("%s needs a subcommand", strings.Join(path, " "))
	}

	fs := flag.NewFlagSet("uulink "+strings.Join(path, " "), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.bind(fs)
	if cmd.bind != nil {
		cmd.bind(fs)
	}
	helpDebug := fs.Bool("help-debug", false, "list the debugging flags as well and exit")
	if err := fs.Parse(cmdArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCommandUsage(stdout, cmd, path, false)
			return nil
		}
		return usageErrorf("%s: %w", strings.Join(path, " "), err)
	}
	if *helpDebug {
		printCommandUsage(stdout, cmd, path, true)
		return nil
	}
	if fs.NArg() > 0 {
		return usageErrorf("%s: unexpected argument %q", strings.Join(path, " "), fs.Arg(0))
	}

	level, err := logging.ParseLevel(g.logLevel)
	if err != nil {
		return usageErrorf("parse log level: %w", err)
	}
	logging.SetLevel(level)
	return cmd.run(g)
}

// findCommand resolves a command path such as ["share", "join"], returning
// the leaf (or group) and the consumed path.
func findCommand(tree []*command, args []string) (*command, []string, error) {
	if len(args) == 0 {
		return nil, nil, usageErrorf("no command given")
	}
	var path []string
	var current *command
	for len(args) > 0 {
		var match *command
		for _, candidate := range tree {
			if candidate.name == args[0] {
				match = candidate
				break
			}
		}
		if match == nil {
			if current == nil {
				return nil, nil, usageErrorf("unknown command %q (see 'uulink help')", args[0])
			}
			if current.run == nil {
				return nil, nil, usageErrorf("unknown %s command %q (see 'uulink help %s')", strings.Join(path, " "), args[0], strings.Join(path, " "))
			}
			break
		}
		current = match
		path = append(path, args[0])
		args = args[1:]
		if len(match.sub) == 0 {
			break
		}
		tree = match.sub
	}
	return current, path, nil
}

func printRootUsage(w io.Writer, root *flag.FlagSet) {
	fmt.Fprintf(w, "uulink - TCP port forwarding over the UU Remote P2P network\n\n")
	fmt.Fprintf(w, "Usage:\n  uulink <command> [flags]\n\nCommands:\n")
	printCommandList(w, commands(), "")
	fmt.Fprintf(w, "\nGlobal flags (accepted before the command and by every command):\n")
	printFlags(w, root, false, func(name string) bool { return name == "config" || name == "log-level" })
	fmt.Fprintf(w, "\nRun 'uulink help <command>' for the flags of a command, or\n'uulink <command> -help-debug' to include the same-host debugging flags.\n")
	if DefaultConfigURL != "" {
		fmt.Fprintf(w, "\nThis build connects to %s when run without arguments.\n", DefaultConfigURL)
	}
}

func printCommandList(w io.Writer, cmds []*command, prefix string) {
	width := 0
	for _, c := range cmds {
		if !c.hidden && len(prefix+c.name) > width {
			width = len(prefix + c.name)
		}
	}
	for _, c := range cmds {
		if c.hidden {
			continue
		}
		fmt.Fprintf(w, "  %-*s  %s\n", width, prefix+c.name, c.summary)
	}
}

func printCommandUsage(w io.Writer, cmd *command, path []string, includeDebug bool) {
	name := "uulink " + strings.Join(path, " ")
	if cmd.run == nil {
		fmt.Fprintf(w, "Usage:\n  %s <command> [flags]\n\n%s\n\nCommands:\n", name, cmd.summary)
		printCommandList(w, cmd.sub, "")
		fmt.Fprintf(w, "\nRun 'uulink help %s <command>' for details.\n", strings.Join(path, " "))
		return
	}
	args := cmd.args
	if args == "" {
		args = "[flags]"
	}
	fmt.Fprintf(w, "Usage:\n  %s %s\n\n%s\n", name, args, cmd.summary)
	if cmd.long != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimSpace(cmd.long))
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	g := &globalOptions{configPath: "config.json", logLevel: "info"}
	g.bind(fs)
	if cmd.bind != nil {
		cmd.bind(fs)
	}
	fmt.Fprintf(w, "\nFlags:\n")
	printFlags(w, fs, false, nil)
	if includeDebug {
		fmt.Fprintf(w, "\nDebugging flags:\n")
		printFlags(w, fs, true, nil)
	}
}

// printFlags lists the flags of fs, either the documented ones or the ones
// marked with debugUsagePrefix. only, when set, further restricts the names.
func printFlags(w io.Writer, fs *flag.FlagSet, debug bool, only func(string) bool) {
	var flags []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) {
		if only != nil && !only(f.Name) {
			return
		}
		if f.Name == "v" || f.Name == "help-debug" {
			return
		}
		if strings.HasPrefix(f.Usage, debugUsagePrefix) != debug {
			return
		}
		flags = append(flags, f)
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	for _, f := range flags {
		name, usage := flag.UnquoteUsage(f)
		usage = strings.TrimPrefix(usage, debugUsagePrefix)
		line := "  -" + f.Name
		if name != "" {
			line += " " + name
		}
		fmt.Fprintf(w, "%s\n    \t%s", line, usage)
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" {
			fmt.Fprintf(w, " (default %s)", f.DefValue)
		}
		fmt.Fprintln(w)
	}
}

func versionCommand() *command {
	return &command{
		name:    "version",
		summary: "Print version, commit, build date, and platform",
		run: func(g *globalOptions) error {
			_, err := fmt.Fprintln(g.stdout, formatVersion())
			return err
		},
	}
}
