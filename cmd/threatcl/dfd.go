package main

import (
	"fmt"
	"strings"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/tmloader"
)

type DfdCommand struct {
	*GlobalCmdOptions
	specCfg           *spec.ThreatmodelSpecConfig
	flagOutDir        string
	flagOutFile       string
	flagOverwrite     bool
	flagFormat        string
	flagStdout        bool
	flagIndex         int
	flagProtocolStyle string
	renderOpts        spec.DfdRenderOptions
}

func (c *DfdCommand) Help() string {
	helpText := `
Usage: threatcl dfd [options] -outdir=<directory> <files>

  Generate Data Flow Diagram files from existing Threat model HCL files
	(as specified by <files>)

 -outdir=<directory>
   Directory to output files. Will create directory if it doesn't exist.
   Either this, or -out, must be set

 -out=<filename>
   Name of output file. Only the first discovered data_flow_diagram will be
   converted.
   Either this, or -outdir, must be set

 -format=<png|dot|svg|mermaid|d2>
   Output format. If not set, defaults to png.

 -stdout
   If the format is a text format (dot, mermaid, d2), you can output
   directly to STDOUT

 -protocol-style=<label|color|both|none>
   How to render the optional 'protocol' attribute on DFD flows.
   - label: append " (protocol)" to the flow label (default)
   - color: color each flow's edge by protocol and emit a legend
   - both:  combine label and color
   - none:  ignore the protocol attribute entirely

Options:

 -config=<file>
   Optional config file

 -overwrite

`
	return strings.TrimSpace(helpText)
}

func (c *DfdCommand) extractDfd(models []tmloader.LoadedModel, index int) (*spec.DataFlowDiagram, string, error) {
	for _, lm := range models {
		tm := lm.TM

		if len(tm.DataFlowDiagrams) > 0 {
			for idx, adfd := range tm.DataFlowDiagrams {
				if idx+1 == index {
					return adfd, tm.Name, nil
				}
			}
		}
	}
	return nil, "", fmt.Errorf("no DFD found with that index")
}

func (c *DfdCommand) genDfdPng(models []tmloader.LoadedModel, index int, filepath string) error {

	adfd, tmName, err := c.extractDfd(models, index)
	if err != nil {
		return err
	}

	err = adfd.GenerateDfdPng(filepath, tmName, c.renderOpts)
	if err != nil {
		return err
	}
	return nil

}

func (c *DfdCommand) genDfdSvg(models []tmloader.LoadedModel, index int, filepath string) error {

	adfd, tmName, err := c.extractDfd(models, index)
	if err != nil {
		return err
	}

	err = adfd.GenerateDfdSvg(filepath, tmName, c.renderOpts)
	if err != nil {
		return err
	}
	return nil

}

// writeSingle saves the DFD at the given index to c.flagOutFile using the
// configured output format.
func (c *DfdCommand) writeSingle(models []tmloader.LoadedModel, index int) int {
	switch {
	case isTextFormat(c.flagFormat):
		text, err := c.fetchDfd(models, index, c.flagFormat)
		if err != nil {
			fmt.Printf("Error fetching DFD for output: %s\n", err)
			return 1
		}
		if err := writeStringToFile(c.flagOutFile, text); err != nil {
			fmt.Printf("Error writing %s file to %s: %s\n", strings.ToUpper(c.flagFormat), c.flagOutFile, err)
			return 1
		}
	case c.flagFormat == "png":
		if err := c.genDfdPng(models, index, c.flagOutFile); err != nil {
			fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
			return 1
		}
	case c.flagFormat == "svg":
		if err := c.genDfdSvg(models, index, c.flagOutFile); err != nil {
			fmt.Printf("Error creating file: %s: %s\n", c.flagOutFile, err)
			return 1
		}
	default:
		fmt.Printf("Invalid -format. You set '%s'\n", c.flagFormat)
		return 1
	}

	fmt.Printf("Successfully created '%s'\n", c.flagOutFile)
	return 0
}

// isTextFormat reports whether the format produces textual output that can be
// written verbatim to a file or stdout (as opposed to a binary image format).
func isTextFormat(format string) bool {
	switch format {
	case "dot", "mermaid", "d2":
		return true
	}
	return false
}

func parseProtocolStyle(s string) (spec.ProtocolStyle, error) {
	switch s {
	case "", "label":
		return spec.ProtocolStyleLabel, nil
	case "none":
		return spec.ProtocolStyleNone, nil
	case "color":
		return spec.ProtocolStyleColor, nil
	case "both":
		return spec.ProtocolStyleBoth, nil
	}
	return 0, fmt.Errorf("-protocol-style must be label, color, both, or none")
}

func (c *DfdCommand) fetchDfd(models []tmloader.LoadedModel, index int, format string) (string, error) {
	adfd, tmName, err := c.extractDfd(models, index)
	if err != nil {
		return "", err
	}

	return generateText(adfd, tmName, format, c.renderOpts)
}

// generateText dispatches to the appropriate spec generator for textual
// formats (dot, mermaid, d2).
func generateText(adfd *spec.DataFlowDiagram, tmName, format string, opts spec.DfdRenderOptions) (string, error) {
	switch format {
	case "dot":
		return adfd.GenerateDot(tmName, opts)
	case "mermaid":
		return adfd.GenerateMermaid(tmName, opts)
	case "d2":
		return adfd.GenerateD2(tmName, opts)
	}
	return "", fmt.Errorf("unsupported text format: %s", format)
}

func (c *DfdCommand) Run(args []string) int {

	flagSet := c.GetFlagset("dfd")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output files. Will create directory if it doesn't exist. Either this, or -out, must be set")
	flagSet.StringVar(&c.flagOutFile, "out", "", "Name of output file. Either this, or -outdir, must be set")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files in the outdir. Defaults to false")
	flagSet.BoolVar(&c.flagStdout, "stdout", false, "If format is dot, you can send to stdout")
	flagSet.StringVar(&c.flagFormat, "format", "png", "Format of output files. png, dot, svg, mermaid, or d2")
	flagSet.IntVar(&c.flagIndex, "index", 0, "index")
	flagSet.StringVar(&c.flagProtocolStyle, "protocol-style", "label", "Protocol rendering style for DFD flows: label, color, both, or none. Defaults to label.")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if c.flagOutDir == "" && c.flagOutFile == "" && !c.flagStdout && !isTextFormat(c.flagFormat) {
		fmt.Printf("You must set an -outdir or -out. Or set the format to a text format (dot, mermaid, d2) and enable -stdout\n\n")
		fmt.Println(c.Help())
		return 1
	}

	if c.flagOutDir != "" && c.flagOutFile != "" {
		fmt.Printf("You must sent an -outdir or -out, but not both\n\n")
		fmt.Println(c.Help())
		return 1
	}

	// Check that flagFormat is one of the supported formats
	switch c.flagFormat {
	case "png", "svg", "dot", "mermaid", "d2":
	default:
		fmt.Printf("-format must be png, dot, svg, mermaid or d2\n\n")
		fmt.Println(c.Help())
		return 1
	}

	ps, err := parseProtocolStyle(c.flagProtocolStyle)
	if err != nil {
		fmt.Printf("%s\n\n", err)
		fmt.Println(c.Help())
		return 1
	}
	c.renderOpts = spec.DfdRenderOptions{ProtocolStyle: ps}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide file(s)\n\n")
		fmt.Println(c.Help())
		return 1
	}

	// We use outfiles to generate a list of output files to validate whether
	// we're overwriting them or not.
	outfiles := []string{}

	// Parse all discovered files as one set (cross-file `extends` resolves).
	res, err := tmloader.LoadSet(c.specCfg, flagSet.Args())
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}
	models := res.Models

	// Walk the parsed models - just to determine output files
	for _, lm := range models {
		tm := lm.TM

		if len(tm.DataFlowDiagrams) > 0 {
			// we don't need to do this format check anymore

			// we do need to check if we're outputing to a directory or not.
			// If a directory, we can output multiple DFDs, otherwise, we need to prompt them for another parameter - i.e.
			// which dfd to draw
			fileExt := fmt.Sprintf(".%s", c.flagFormat)
			for _, adfd := range tm.DataFlowDiagrams {
				outfile := outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), lm.File, fileExt)

				outfiles = append(outfiles, outfile)
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

	// We're going to print text output to the Stdout
	case c.flagStdout && isTextFormat(c.flagFormat):
		switch {
		case len(outfiles) != 1 && c.flagIndex == 0:
			fmt.Printf("You're trying to print %s to Stdout, but there's too many DFDs\n\n", strings.ToUpper(c.flagFormat))
			fmt.Printf("Run the command again and provide an -index=n flag\n\n")
			for idx, outfile := range outfiles {
				fmt.Printf("%d: %s\n", idx+1, outfile)
			}
			return 1
		case len(outfiles) != 1 && (c.flagIndex > len(outfiles) || c.flagIndex < 1):
			fmt.Printf("Index provided is inaccurate\n")
			return 1
		case len(outfiles) == 1:
			text, err := c.fetchDfd(models, 1, c.flagFormat)
			if err != nil {
				fmt.Printf("Error fetching DFD for output: %s\n", err)
				return 1
			}
			fmt.Printf("%s\n", text)
			return 0
		default:
			text, err := c.fetchDfd(models, c.flagIndex, c.flagFormat)
			if err != nil {
				fmt.Printf("Error fetching DFD for output: %s\n", err)
				return 1
			}
			fmt.Printf("%s\n", text)
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
			return c.writeSingle(models, 1)

		default:
			// there's multiple DFDs, but they've selected a valid index, let's save
			// that one
			return c.writeSingle(models, c.flagIndex)
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
		for _, lm := range models {
			tm := lm.TM
			{
				for _, adfd := range tm.DataFlowDiagrams {

					currentOutpath := outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, adfd.Name), lm.File, fmt.Sprintf(".%s", c.flagFormat))

					// Now we switch on the output format
					switch {
					case isTextFormat(c.flagFormat):
						text, err := generateText(adfd, tm.Name, c.flagFormat, c.renderOpts)
						if err != nil {
							fmt.Printf("Error generating %s: %s\n", c.flagFormat, err)
							return 1
						}

						if err := writeStringToFile(currentOutpath, text); err != nil {
							fmt.Printf("Error writing %s file to %s: %s\n", strings.ToUpper(c.flagFormat), currentOutpath, err)
							return 1
						}

						fmt.Printf("Successfully created '%s'\n", currentOutpath)

					case c.flagFormat == "png":

						err := adfd.GenerateDfdPng(currentOutpath, tm.Name, c.renderOpts)
						if err != nil {
							fmt.Printf("Error writing PNG file to %s: %s\n", currentOutpath, err)
							return 1
						}

						fmt.Printf("Successfully created '%s'\n", currentOutpath)

					case c.flagFormat == "svg":

						err := adfd.GenerateDfdSvg(currentOutpath, tm.Name, c.renderOpts)
						if err != nil {
							fmt.Printf("Error writing SVG file to %s: %s\n", currentOutpath, err)
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

func (c *DfdCommand) AutocompleteArgs() complete.Predictor { return predictHCLOrJSON }
func (c *DfdCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":         predictHCL,
		"-outdir":         complete.PredictDirs("*"),
		"-format":         complete.PredictSet("png", "dot", "svg", "mermaid", "d2"),
		"-protocol-style": complete.PredictSet("label", "color", "both", "none"),
	}
}
