package main

import (
	"strings"

	"github.com/mitchellh/cli"
)

type CloudCommand struct {
}

func (c *CloudCommand) Help() string {
	helpText := `
Usage: threatcl cloud <subcommand>

	This command is used to interact with ThreatCL Cloud services

`
	return strings.TrimSpace(helpText)
}

func (c *CloudCommand) Run(args []string) int {
	return cli.RunResultHelp
}

func (c *CloudCommand) Synopsis() string {
	return "Interact with ThreatCL Cloud services"
}

// defaultAPIBaseURL is the default API base URL for the threatcl cloud service
const defaultAPIBaseURL = "https://beta-api.threatcl.com"
