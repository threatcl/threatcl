package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/xntrik/hcltm/pkg/spec"
)

type GenerateBoilerplateCommand struct {
	*GlobalCmdOptions
	specCfg *spec.ThreatmodelSpecConfig
	flagOut string
}

func (c *GenerateBoilerplateCommand) Help() string {
	helpText := `
Usage: hcltm generate boilerplate [options]

  Outputs a generic HCL threatmodel that you can edit later.

Options:

 -config=<file>
   Optional config file

 -out=<file>
   Path on the local disk to write the HCL file to. If not set (default), the
   HCL output will be written to STDOUT

`
	return strings.TrimSpace(helpText)
}

func (c *GenerateBoilerplateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("generate boilerplate")
	flagSet.StringVar(&c.flagOut, "out", "", "Where to output HCL file (if empty, write to STDOUT)")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	var f *os.File

	if c.flagOut != "" {
		// Looks like we want to write to a file

		// Check if it exists already
		_, err := os.Stat(c.flagOut)
		if !os.IsNotExist(err) {
			fmt.Printf("You're trying to write to '%s', which already exists..\n", c.flagOut)
			return 1
		}

		f, err = os.Create(c.flagOut)
		if err != nil {
			fmt.Printf("Error creating file '%s'\n", err)
			return 1
		}

		defer f.Close()
	}

	outString, err := parseBoilerplateTemplate(c.specCfg)
	if err != nil {
		fmt.Printf("Error parsing template: %s\n", err)
		return 1
	}

	if c.flagOut == "" {
		fmt.Printf("%s\n", outString)
	} else {
		_, err = f.WriteString(outString)
		if err != nil {
			fmt.Printf("Error writing to file: %s\n", err)
			return 1
		}
		fmt.Printf("Successfully wrote to '%s'\n", c.flagOut)
	}

	return 0

}

func (c *GenerateBoilerplateCommand) Synopsis() string {
	return "Generate a generic HCL threatmodel that you can edit later"
}
