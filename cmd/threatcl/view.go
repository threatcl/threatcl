package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/threatcl/spec"
)

type ViewCommand struct {
	*GlobalCmdOptions
	specCfg    *spec.ThreatmodelSpecConfig
	flagRawOut bool
	testEnv    bool
}

func (c *ViewCommand) Help() string {
	helpText := `
Usage: threatcl view [options] <files>

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

func (c *ViewCommand) Execute(args []string) (string, error) {
	mdBuffer := new(strings.Builder)

	// Find all the .hcl files we're going to parse
	AllFiles := findAllFiles(args)

	// Parse all the identified .hcl files
	for _, file := range AllFiles {
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err := tmParser.ParseFile(file, false)
		if err != nil {
			return "", fmt.Errorf("error parsing %s: %s", file, err)
		}

		for _, tm := range tmParser.GetWrapped().Threatmodels {
			tmBuffer, err := tm.RenderMarkdown(spec.TmMDTemplate)
			if err != nil {
				return "", err
			}

			_, err = io.Copy(mdBuffer, tmBuffer)
			if err != nil {
				return "", fmt.Errorf("failed to copy threatmodel buffer to markdown buffer: %s", err)
			}
		}
	}

	return mdBuffer.String(), nil

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

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide a filename\n")
		return 1
	}

	output, err := c.Execute(flagSet.Args())
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	if c.flagRawOut {
		fmt.Println(output)
		return 0
	} else {
		// out, err := mdRenderer.Render(output)
		out, err := c.RenderMd(output)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}
		fmt.Println(out)
		return 0
	}
}

func (c *ViewCommand) RenderMd(md string) (string, error) {
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
		return "", err
	}
	out, err := mdRenderer.Render(md)
	if err != nil {
		return "", err
	}

	return out, nil

}

func (c *ViewCommand) Synopsis() string {
	return "View existing HCL Threatmodel file(s)"
}
