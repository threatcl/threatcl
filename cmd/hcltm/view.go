package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/xntrik/hcltm/pkg/spec"
)

type ViewCommand struct {
	*GlobalCmdOptions
	specCfg    *spec.ThreatmodelSpecConfig
	flagRawOut bool
	testEnv    bool
}

func (c *ViewCommand) Help() string {
	helpText := `
Usage: hcltm view [options] <files>

  View HCL files (as specified by <files>) and output some
	information about the threatmodels

Options:

 -config=<file>
   Optional config file

 -debug
   If set, will output debugging information.

 -raw
   If set, will raw markdown instead of formatted

`
	return strings.TrimSpace(helpText)
}

func (c *ViewCommand) Run(args []string) int {

	flagSet := c.GetFlagset("view")
	flagSet.BoolVar(&c.flagRawOut, "raw", false, "Output raw markdown")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	mdBuffer := new(strings.Builder)

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide a filename\n")
		return 1
	} else {

		// Find all the .hcl files we're going to parse
		HCLFiles := findHclFiles(flagSet.Args())

		// Parse all the identified .hcl files
		for _, file := range HCLFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseHCLFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {
				tmBuffer, err := tm.RenderMarkdown(spec.TmMDTemplate)
				if err != nil {
					fmt.Println(err)
					return 1
				}

				_, err = io.Copy(mdBuffer, tmBuffer)
				if err != nil {
					fmt.Printf("Failed to copy threatmodel buffer to markdown buffer: %s", err)
					return 1
				}
			}
		}
	}
	if c.flagRawOut {
		fmt.Println(mdBuffer.String())
		return 0
	} else {
		var mdRenderer *glamour.TermRenderer
		var err error
		if !c.testEnv {
			mdRenderer, err = glamour.NewTermRenderer(
				// detect background color and pick either the default dark or light theme
				glamour.WithAutoStyle(),
				// wrap output at specific width
				glamour.WithWordWrap(80),
			)
		} else {
			// For some reason we can't use the WithAutoStyle() in `go test`
			// It causes Go to hang
			mdRenderer, err = glamour.NewTermRenderer(
				// wrap output at specific width
				glamour.WithWordWrap(80),
			)
		}
		if err != nil {
			return 1
		}
		out, err := mdRenderer.Render(mdBuffer.String())
		if err != nil {
			return 1
		}
		fmt.Println(out)
		return 0
	}
}

func (c *ViewCommand) Synopsis() string {
	return "View existing HCL Threatmodel file(s)"
}
