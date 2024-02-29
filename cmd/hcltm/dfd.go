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
	flagOutFile   string
	flagOverwrite bool
	flagFormat    string
	flagStdout    bool
	flagIndex     int
}

func (c *DfdCommand) Help() string {
	helpText := `
Usage: hcltm dfd [options] -outdir=<directory> <files>

  Generate Data Flow Diagram PNG or DOT files from existing Threat model HCL files
	(as specified by <files>) 

 -outdir=<directory>
   Directory to output files. Will create directory if it doesn't exist.
   Either this, or -out, must be set

 -out=<filename>
   Name of output file. Only the first discovered data_flow_diagram will be
   converted.
   Either this, or -outdir, must be set

 -format=<png|dot|svg>
   Output format. If not set, defaults to png.

 -stdout
   If the format is dot, you can output directly to STDOUT

Options:

 -config=<file>
   Optional config file

 -overwrite

`
	return strings.TrimSpace(helpText)
}

func (c *DfdCommand) extractDfd(allFiles []string, index int) (*spec.DataFlowDiagram, string, error) {
	for _, file := range allFiles {
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err := tmParser.ParseFile(file, false)
		if err != nil {
			return nil, "", fmt.Errorf("Error parsing %s: %s\n", file, err)
		}

		for _, tm := range tmParser.GetWrapped().Threatmodels {

			if len(tm.DataFlowDiagrams) > 0 {
				for idx, adfd := range tm.DataFlowDiagrams {
					if idx+1 == index {
						return adfd, tm.Name, nil
					}
				}
			}
		}
	}
	return nil, "", fmt.Errorf("No DFD found with that index")
}

func (c *DfdCommand) genDfdPng(allFiles []string, index int, filepath string) error {

	adfd, tmName, err := c.extractDfd(allFiles, index)
	if err != nil {
		return err
	}

	err = adfd.GenerateDfdPng(filepath, tmName)
	if err != nil {
		return err
	}
	return nil

}

func (c *DfdCommand) genDfdSvg(allFiles []string, index int, filepath string) error {

	adfd, tmName, err := c.extractDfd(allFiles, index)
	if err != nil {
		return err
	}

	err = adfd.GenerateDfdSvg(filepath, tmName)
	if err != nil {
		return err
	}
	return nil

}

func (c *DfdCommand) fetchDfd(allFiles []string, index int) (string, error) {
	adfd, tmName, err := c.extractDfd(allFiles, index)
	if err != nil {
		return "", err
	}

	dot, err := adfd.GenerateDot(tmName)
	if err != nil {
		return "", err
	}

	return dot, nil
}

func (c *DfdCommand) Run(args []string) int {

	flagSet := c.GetFlagset("dfd")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output files. Will create directory if it doesn't exist. Either this, or -out, must be set")
	flagSet.StringVar(&c.flagOutFile, "out", "", "Name of output file. Either this, or -outdir, must be set")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files in the outdir. Defaults to false")
	flagSet.BoolVar(&c.flagStdout, "stdout", false, "If format is dot, you can send to stdout")
	flagSet.StringVar(&c.flagFormat, "format", "png", "Format of output files. png, dot, or svg")
	flagSet.IntVar(&c.flagIndex, "index", 0, "index")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if c.flagOutDir == "" && c.flagOutFile == "" && c.flagStdout == false && c.flagFormat != "dot" {
		fmt.Printf("You must set an -outdir or -out. Or set the format to PNG and enable -stdout\n\n")
		fmt.Println(c.Help())
		return 1
	}

	if c.flagOutDir != "" && c.flagOutFile != "" {
		fmt.Printf("You must sent an -outdir or -out, but not both\n\n")
		fmt.Println(c.Help())
		return 1
	}

	// Check that flagFormat is one of png, svg or dot
	switch c.flagFormat {
	case "png", "svg", "dot":
	default:
		fmt.Printf("-format must be png, dot or svg\n\n")
		fmt.Println(c.Help())
		return 1
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide file(s)\n\n")
		fmt.Println(c.Help())
		return 1
	}

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
				// we don't need to do this format check anymore

				// we do need to check if we're outputing to a directory or not.
				// If a directory, we can output multiple DFDs, otherwise, we need to prompt them for another parameter - i.e.
				// which dfd to draw
				fileExt := fmt.Sprintf(".%s", c.flagFormat)
				for _, adfd := range tm.DataFlowDiagrams {
					outfile := outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), file, fileExt)

					outfiles = append(outfiles, outfile)
				}
			}
		}
	}

	if len(outfiles) == 0 {
		fmt.Printf("No DFDs found\n\n")
		return 1
	}

	// Now we have a set of DFDs and some options to parse, namely
	// Is this a stdout + dot file?
	// - Then we can only handle 1 file
	//   If there _is_ only 1 file, easy, alternatively
	// - Ask them to select an index
	// Is this outputting a single file?
	// - Then we can only handle 1 file
	//   If there _is_ only 1 file, easy, alternatively
	// - Ask them to select an index
	//		* don't forget overwriting
	// Is this outputting to a directory?
	// - Then we can handle 1 or more files
	//    * don't forget overwriting

	switch {

	// We're going to print DOT output to the Stdout
	case c.flagStdout == true && c.flagFormat == "dot":
		switch {
		case len(outfiles) != 1 && c.flagIndex == 0:
			fmt.Printf("You're trying to print DOT to Stdout, but there's too many DFDs\n\n")
			fmt.Printf("Run the command again and provide an -index=n flag\n\n")
			for idx, outfile := range outfiles {
				fmt.Printf("%d: %s\n", idx+1, outfile)
			}
			return 1
		case len(outfiles) != 1 && (c.flagIndex > len(outfiles) || c.flagIndex < 1):
			fmt.Printf("Index provided is inaccurate\n")
			return 1
		case len(outfiles) == 1:
			dot, err := c.fetchDfd(AllFiles, 1)
			if err != nil {
				fmt.Printf("Error fetching DFD for output: %s\n", err)
				return 1
			}
			fmt.Printf("%s\n", dot)
			return 0
		default:
			dot, err := c.fetchDfd(AllFiles, c.flagIndex)
			if err != nil {
				fmt.Printf("Error fetching DFD for output: %s\n", err)
				return 1
			}
			fmt.Printf("%s\n", dot)
			return 0
		}

	// We're going to output a single file
	case c.flagOutFile != "" && c.flagOutDir == "":
		err := fileExistenceCheck([]string{c.flagOutFile}, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		switch {
		case len(outfiles) != 1 && c.flagIndex == 0:
			fmt.Printf("You're trying to save a single file, but there's too many DFDs\n\n")
			fmt.Printf("Run the command again and provide an -index=n flag\n\n")
			for idx, outfile := range outfiles {
				fmt.Printf("%d: %s\n", idx+1, outfile)
			}
			return 1
		case len(outfiles) != 1 && (c.flagIndex > len(outfiles) || c.flagIndex < 1):
			fmt.Printf("Index provided is inaccurate\n")
			return 1
		case len(outfiles) == 1:
			// there's only a single DFD, let's just save that one

			// a new switch depending on the output format
			switch {
			case c.flagFormat == "dot":
				dot, err := c.fetchDfd(AllFiles, 1)
				if err != nil {
					fmt.Printf("Error fetching DFD for output: %s\n", err)
					return 1
				}
				f, err := os.Create(c.flagOutFile)
				if err != nil {
					fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
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
			case c.flagFormat == "png":
				err := c.genDfdPng(AllFiles, 1, c.flagOutFile)
				if err != nil {
					fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
					return 1
				}

				fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
				return 0
			case c.flagFormat == "svg":
				err := c.genDfdSvg(AllFiles, 1, c.flagOutFile)
				if err != nil {
					fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
					return 1
				}

				fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
				return 0
			default:
				fmt.Printf("Invalid -format. You set '%s'\n", c.flagFormat)
				return 1
			}

		default:
			// there's multiple DFDs, but they've selected a valid index, let's save
			// that one

			// a new switch depending on the output format
			switch {
			case c.flagFormat == "dot":
				dot, err := c.fetchDfd(AllFiles, c.flagIndex)
				if err != nil {
					fmt.Printf("Error fetching DFD for output: %s\n", err)
					return 1
				}
				f, err := os.Create(c.flagOutFile)
				if err != nil {
					fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
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
			case c.flagFormat == "png":
				err := c.genDfdPng(AllFiles, c.flagIndex, c.flagOutFile)
				if err != nil {
					fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
					return 1
				}

				fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
				return 0
			case c.flagFormat == "svg":
				err := c.genDfdSvg(AllFiles, c.flagIndex, c.flagOutFile)
				if err != nil {
					fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
					return 1
				}

				fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
				return 0
			default:
				fmt.Printf("Invalid -format. You set '%s'\n", c.flagFormat)
				return 1
			}
		}

	// We're going to output a full directory
	case c.flagOutDir != "" && c.flagOutFile == "":

		// Check if there are any files, and whether we're handling
		// overwriting correctly
		err := fileExistenceCheck(outfiles, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		// so far so good, let's create the folder
		err = createOrValidateFolder(c.flagOutDir, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		// Now we do the full iteration for file saving
		for _, file := range AllFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {
				for _, adfd := range tm.DataFlowDiagrams {

					currentOutpath := outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), file, fmt.Sprintf(".%s", c.flagFormat))

					// Now we switch on the output format
					switch {
					case c.flagFormat == "dot":
						dot, err := adfd.GenerateDot(tm.Name)
						if err != nil {
							fmt.Printf("Error generating dot: %s\n", err)
							return 1
						}

						f, err := os.Create(currentOutpath)
						if err != nil {
							fmt.Printf("Error creating file: %s: %s\n", currentOutpath, err)
							return 1
						}
						defer f.Close()

						_, err = f.WriteString(dot)
						if err != nil {
							fmt.Printf("Error writing DOT file to %s: %s\n", currentOutpath, err)
							return 1
						}

						fmt.Printf("Successfully created '%s'\n", currentOutpath)

					case c.flagFormat == "png":

						err := adfd.GenerateDfdPng(currentOutpath, tm.Name)
						if err != nil {
							fmt.Printf("Error writing PNG file to %s: %s\n", currentOutpath, err)
							return 1
						}

						fmt.Printf("Successfully created '%s'\n", currentOutpath)

					case c.flagFormat == "svg":

						err := adfd.GenerateDfdSvg(currentOutpath, tm.Name)
						if err != nil {
							fmt.Printf("Error writing PNG file to %s: %s\n", currentOutpath, err)
							return 1
						}

						fmt.Printf("Successfully created '%s'\n", currentOutpath)
					default:
						fmt.Printf("Invalid -format. You set '%s'\n", c.flagFormat)
						return 1
					}
				}
			}
		}

		return 0

	default:
		fmt.Printf("An error has occurred\n")
		return 1
	}

}

func (c *DfdCommand) Synopsis() string {
	return "Generate Data Flow Diagram PNG or DOT files from existing HCL threatmodel file(s)"
}
