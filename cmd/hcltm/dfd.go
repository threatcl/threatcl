package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/xntrik/hcltm/pkg/spec"
)

type DfdCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagOutDir    string
	flagOverwrite bool
}

func (c *DfdCommand) Help() string {
	helpText := `
Usage: hcltm dfd [options] -outdir=<directory> <files>

  Generate Data Flow Diagram PNG files from existing Threat model HCL files
	(as specified by <files>) 

 -outdir=<directory>
   Directory to output PNG files. Will create directory if it doesn't exist.
   Must be set

Options:

 -config=<file>
   Optional config file

 -overwrite

`
	return strings.TrimSpace(helpText)
}

func (c *DfdCommand) Run(args []string) int {

	flagSet := c.GetFlagset("dfd")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output PNG files. Will create directory if it doesn't exist. Must be set")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files in the outdir. Defaults to false")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if c.flagOutDir == "" {
		fmt.Println("You must set an -outdir")
		return 1
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide file(s)\n\n")
		fmt.Println(c.Help())
		return 1
	} else {

		// We use outfiles to generate a list of output files to validate whether
		// we're overwriting them or not.
		outfiles := []string{}

		// Find all the .hcl files we're going to parse
		HCLFiles := findHclFiles(flagSet.Args())

		// Parse all the identified .hcl files - just to determine output files
		for _, file := range HCLFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseHCLFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {

				if tm.DataFlowDiagram != nil {
					outfile := outfilePath(c.flagOutDir, tm.Name, file, ".png")

					outfiles = append(outfiles, outfile)
				}

			}
		}

		// Validating existing files - if we're not overwriting
		if !c.flagOverwrite {
			for _, outfile := range outfiles {
				_, err := os.Stat(outfile)
				if !os.IsNotExist(err) {
					fmt.Printf("'%s' already exists\n", outfile)
					return 1
				}
			}
		}

		if len(outfiles) == 0 {
			fmt.Printf("No Data Flow Diagrams found in provided HCL files\n")
			return 1
		}

		err := createOrValidateFolder(c.flagOutDir, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		for _, file := range HCLFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseHCLFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {
				if tm.DataFlowDiagram != nil {
					err = tm.GenerateDfdPng(outfilePath(c.flagOutDir, tm.Name, file, ".png"))
					if err != nil {
						fmt.Printf("Error generating DFD: %s\n", err)
						return 1
					}

					fmt.Printf("Successfully created '%s'\n", outfilePath(c.flagOutDir, tm.Name, file, ".png"))
				}
			}
		}

	}

	return 0
}

func (c *DfdCommand) Synopsis() string {
	return "Generate Data Flow Diagram PNG files from existing HCL threatmodel file(s)"
}
