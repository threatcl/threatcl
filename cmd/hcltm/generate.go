package main

import (
	"strings"

	"github.com/mitchellh/cli"
)

type GenerateCommand struct {
}

func (c *GenerateCommand) Help() string {
	helpText := `
Usage: hcltm generate <subcommand>

	This command is used to generate HCL output

`

	return strings.TrimSpace(helpText)
}

func (c *GenerateCommand) Run(args []string) int {

	return cli.RunResultHelp
}

func (c *GenerateCommand) Synopsis() string {
	return "Generate an HCL Threat Model"
}
