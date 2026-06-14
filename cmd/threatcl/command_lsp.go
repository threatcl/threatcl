package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/lsp"

	"github.com/tliron/commonlog"
	// Register the simple commonlog backend so log output has somewhere to go.
	// It writes to stderr (or a file), never stdout — stdout is the LSP transport.
	_ "github.com/tliron/commonlog/simple"
)

// LSPCommand runs threatcl as a Language Server over stdio. It mirrors
// MCPCommand: another stdio server where stdout carries the protocol and must
// stay free of any incidental output.
type LSPCommand struct {
	*GlobalCmdOptions
	specCfg   *spec.ThreatmodelSpecConfig
	flagStdio bool
	flagLog   string
}

func (c *LSPCommand) Help() string {
	helpText := `
Usage: threatcl lsp [options]

  Run a Language Server (LSP) for threatcl over stdio.

  The server provides diagnostics, completion, hover, document symbols, and
  formatting for threatcl HCL threat models. It is intended to be launched by an
  editor's LSP client (see docs/lsp.md for Neovim/Helix/VS Code wiring), not run
  directly.

  stdout carries the LSP protocol; log output goes to stderr or the -log file.

Options:

 -config=<file>
   Optional config file. Note: in this version the language server uses the
   built-in spec enum defaults; a -config override does not yet affect
   diagnostics or completion.

 -log=<file>
   Optional log file for server diagnostics. Without it, logs go to stderr.

 -stdio
   Communicate over stdio (default and only transport).

`
	return strings.TrimSpace(helpText)
}

func (c *LSPCommand) Run(args []string) int {
	flagSet := c.GetFlagset("lsp")
	flagSet.BoolVar(&c.flagStdio, "stdio", true, "Communicate over stdio (default and only transport)")
	flagSet.StringVar(&c.flagLog, "log", "", "Optional log file for server diagnostics")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		if err := c.specCfg.LoadSpecConfigFile(c.flagConfig); err != nil {
			c.errPrint(fmt.Sprintf("Error: %s\n", err))
			return 1
		}
	}

	// Configure logging to stderr (logFile == nil) or a file — never stdout.
	var logFile *string
	if c.flagLog != "" {
		logFile = &c.flagLog
	}
	commonlog.Configure(1, logFile)

	srv := lsp.NewServer(c.specCfg)
	if err := srv.RunStdio(); err != nil {
		c.errPrint(fmt.Sprintf("server error: %v\n", err))
		return 1
	}
	return 0
}

func (c *LSPCommand) Synopsis() string {
	return "Run a Language Server (LSP) over stdio"
}

func (c *LSPCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
		"-log":    complete.PredictFiles("*"),
		"-stdio":  complete.PredictNothing,
	}
}

func (c *LSPCommand) errPrint(msg string) {
	fmt.Fprintf(os.Stderr, "[threatcl-lsp] %s", msg)
}
