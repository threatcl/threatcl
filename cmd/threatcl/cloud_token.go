package main

import (
	"strings"

	"github.com/mitchellh/cli"
)

type CloudTokenCommand struct {
}

func (c *CloudTokenCommand) Help() string {
	helpText := `
Usage: threatcl cloud token <subcommand>

	Manage authentication tokens for ThreatCL Cloud.

	Tokens are scoped to organizations. You can have multiple tokens for
	different organizations and switch between them.

Subcommands:

	list       List all stored tokens
	add        Add a token manually (e.g., generated via web interface)
	remove     Remove a token for a specific organization
	default    Get or set the default organization

Examples:

	# List all tokens
	threatcl cloud token list

	# Add a token manually
	threatcl cloud token add

	# Set the default organization
	threatcl cloud token default <org-id>

	# Remove a token
	threatcl cloud token remove <org-id>

`
	return strings.TrimSpace(helpText)
}

func (c *CloudTokenCommand) Run(args []string) int {
	return cli.RunResultHelp
}

func (c *CloudTokenCommand) Synopsis() string {
	return "Manage authentication tokens"
}
