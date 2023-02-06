package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/xntrik/hcltm/pkg/spec"
)

type DfdCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagOutDir    string
	flagOutFile   string
	flagOverwrite bool
	flagDot       bool
	flagSVG       bool
}

func (c *DfdCommand) Help() string {
	helpText := `
Usage: hcltm dfd [options] -outdir=<directory> <files>

  Generate Data Flow Diagram PNG or DOT files from existing Threat model HCL files
	(as specified by <files>) 

 -outdir=<directory>
   Directory to output files. Will create directory if it doesn't exist.
   Either this, or -out, must be set

 -out=<filename>.<png|dot|svg>
   Name of output file. Only the first discovered data_flow_diagram will be
   converted. You must set the extension to png,dot or svg depending on the mode.
   Either this, or -outdir, must be set

 -dot
   Outputs Graphviz DOT instead. If -out or -outdir is provided files will be
   generated. If neither -out or -outdir is set, then the DOT file will be
   echoed to STDOUT.

 -svg
   Outputs SVG instead of PNG


Options:

 -config=<file>
   Optional config file

 -overwrite

`
	return strings.TrimSpace(helpText)
}

func (c *DfdCommand) Run(args []string) int {

	flagSet := c.GetFlagset("dfd")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output files. Will create directory if it doesn't exist. Either this, or -out, must be set")
	flagSet.StringVar(&c.flagOutFile, "out", "", "Name of output file. Either this, or -outdir, must be set")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files in the outdir. Defaults to false")
	flagSet.BoolVar(&c.flagDot, "dot", false, "Whether to output raw Graphviz DOT")
	flagSet.BoolVar(&c.flagSVG, "svg", false, "Whether to output SVG")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if c.flagOutDir == "" && c.flagOutFile == "" && c.flagDot == false {
		fmt.Printf("You must set an -outdir or -out or -dot\n\n")
		fmt.Println(c.Help())
		return 1
	}

	if c.flagOutDir != "" && c.flagOutFile != "" {
		fmt.Printf("You must sent an -outdir or -out, but not both\n\n")
		fmt.Println(c.Help())
		return 1
	}

	if c.flagDot {
		if c.flagOutFile != "" && filepath.Ext(c.flagOutFile) != ".dot" {
			fmt.Printf("-out flag must end in .dot\n\n")
			fmt.Println(c.Help())
			return 1
		}
	} else if c.flagSVG {
		if c.flagOutFile != "" && filepath.Ext(c.flagOutFile) != ".svg" {
			fmt.Printf("-out flag must end in .svg\n\n")
			fmt.Println(c.Help())
			return 1
		}
	} else {
		if c.flagOutFile != "" && filepath.Ext(c.flagOutFile) != ".png" {
			fmt.Printf("-out flag must end in .png\n\n")
			fmt.Println(c.Help())
			return 1
		}
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
		AllFiles := findAllFiles(flagSet.Args())

		// Parse all the identified .hcl files - just to determine output files
		for _, file := range AllFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {

				if len(tm.DataFlowDiagrams) > 0 {
					fileExt := ".png"
					if c.flagDot {
						fileExt = ".dot"
					} else if c.flagSVG {
						fileExt = ".svg"
					}
					for _, adfd := range tm.DataFlowDiagrams {
						outfile := outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), file, fileExt)

						outfiles = append(outfiles, outfile)
					}
				}
			}
		}

		spew.Dump(outfiles)

		if c.flagOutFile != "" {
			outfiles = []string{c.flagOutFile}
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

		if c.flagOutDir != "" {
			err := createOrValidateFolder(c.flagOutDir, c.flagOverwrite)
			if err != nil {
				fmt.Printf("%s\n", err)
				return 1
			}
		}

		for _, file := range AllFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {
				// if tm.DataFlowDiagram != nil {
				for _, adfd := range tm.DataFlowDiagrams {
					if c.flagDot {
						dot, err := adfd.GenerateDot(tm.Name)
						if err != nil {
							fmt.Printf("Error generating DOT: %s\n", c.flagOutFile)
							return 1
						}
						if c.flagOutFile != "" {
							f, err := os.Create(c.flagOutFile)
							if err != nil {
								fmt.Printf("Error creating file %s: %s\n", c.flagOutFile, err)
								return 1
							}
							defer f.Close()

							_, err = f.WriteString(dot)
							if err != nil {
								fmt.Printf("Error writing DOT file to %s: %s\n", c.flagOutFile, err)
								return 1
							}

							fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
							return 0

						} else if c.flagOutDir != "" {
							f, err := os.Create(outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), file, ".dot"))
							if err != nil {
								fmt.Printf("Error creating file %s: %s\n", outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), file, ".dot"), err)
								return 1
							}
							defer f.Close()

							_, err = f.WriteString(dot)
							if err != nil {
								fmt.Printf("Error writing DOT file to %s: %s\n", outfilePath(c.flagOutDir, tm.Name, file, ".dot"), err)
								return 1
							}

							fmt.Printf("Successfully created '%s'\n", outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), file, ".dot"))
						} else {
							fmt.Printf("%s\n", dot)
							break
						}
					} else if c.flagOutFile != "" {
						if c.flagSVG {
							err = tm.GenerateDfdSvg(c.flagOutFile)
						} else {
							err = tm.GenerateDfdPng(c.flagOutFile)
						}
						if err != nil {
							fmt.Printf("Error generating DFD: %s\n", err)
							return 1
						}

						fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
						return 0
					} else {
						if c.flagSVG {
							err = tm.GenerateDfdSvg(outfilePath(c.flagOutDir, tm.Name, file, ".svg"))
						} else {
							err = tm.GenerateDfdPng(outfilePath(c.flagOutDir, tm.Name, file, ".png"))
						}
						if err != nil {
							fmt.Printf("Error generating DFD: %s\n", err)
							return 1
						}
						if c.flagSVG {
							fmt.Printf("Successfully created '%s'\n", outfilePath(c.flagOutDir, tm.Name, file, ".svg"))
						} else {
							fmt.Printf("Successfully created '%s'\n", outfilePath(c.flagOutDir, tm.Name, file, ".png"))
						}
					}
				}
			}
		}

	}

	return 0
}

func (c *DfdCommand) Synopsis() string {
	return "Generate Data Flow Diagram PNG or DOT files from existing HCL threatmodel file(s)"
}
