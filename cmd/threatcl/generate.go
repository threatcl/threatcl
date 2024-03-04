package main

import (
	"strings"

	"github.com/mitchellh/cli"
)

type GenerateCommand struct {
}

func (c *GenerateCommand) Help() string {
	helpText := `
Usage: threatcl generate <subcommand>

	This command is used to generate threatcl output

`

	return strings.TrimSpace(helpText)
}

func (c *GenerateCommand) Run(args []string) int {

	return cli.RunResultHelp
}

func (c *GenerateCommand) Synopsis() string {
	return "Generate an HCL Threat Model"
}
