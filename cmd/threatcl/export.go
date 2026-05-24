package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
)

// ExportCommand struct defines the "threatcl export" commands
type ExportCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagFormat    string
	flagOutput    string
	flagTemplate  string
	flagOverwrite bool
}

// Help is the help output for the "threatcl export" command
func (e *ExportCommand) Help() string {
	helpText := `
Usage: threatcl export [options] <files>

  Export provided HCL threat models into other formats

Options:

 -config=<file>
   Optional config file

 -format=<json|otm|hcl>

 -template=<file>
   Optional overridden template file to use for md output

 -output=<file>
   Optional filename to output to. 

 -overwrite

`
	return strings.TrimSpace(helpText)
}

// Run executes the "threatcl export" logic
func (e *ExportCommand) Run(args []string) int {
	flagSet := e.GetFlagset("export")
	flagSet.StringVar(&e.flagFormat, "format", "json", "Format of output. json, hcl, or otm. Defaults to json")
	flagSet.StringVar(&e.flagOutput, "output", "", "Name of output file. If not set, will output to STDOUT")
	flagSet.StringVar(&e.flagTemplate, "template", "", "Optional overridden template file to use for md output")
	flagSet.BoolVar(&e.flagOverwrite, "overwrite", false, "Overwrite existing file. Defaults to false")
	flagSet.Parse(args)

	if e.flagConfig != "" {
		err := e.specCfg.LoadSpecConfigFile(e.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide a filename\n")
		return 1
	} else {
		// Find all the .hcl files we're going to parse
		AllFiles := findAllFiles(flagSet.Args())
		var AllTms []spec.Threatmodel

		var tmParser *spec.ThreatmodelParser

		// Parse all the identified .hcl files
		for _, file := range AllFiles {
			tmParser = spec.NewThreatmodelParser(e.specCfg)
			err := tmParser.ParseFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			AllTms = append(AllTms, tmParser.GetWrapped().Threatmodels...)

		}

		outputString, err := renderThreatmodels(AllTms, tmParser, e.flagFormat, e.flagTemplate)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		if e.flagOutput == "" {
			fmt.Printf("%s\n", outputString)
		} else {
			err := fileExistenceCheck([]string{e.flagOutput}, e.flagOverwrite)
			if err != nil {
				fmt.Printf("%s\n", err)
				return 1
			}

			f, err := os.Create(e.flagOutput)
			if err != nil {
				fmt.Printf("Error creating file: %s: %s\n", e.flagOutput, err)
				return 1
			}
			defer f.Close()

			_, err = f.WriteString(outputString)
			if err != nil {
				fmt.Printf("Error writing output to %s: %s\n", e.flagOutput, err)
				return 1
			}
			fmt.Printf("Successfully wrote '%s'\n", e.flagOutput)
		}
	}
	return 0
}

// Synopsis returns the synopsis for the "threatcl export" command
func (e *ExportCommand) Synopsis() string {
	return "Export threat models into other formats"
}

func (c *ExportCommand) AutocompleteArgs() complete.Predictor { return predictHCLOrJSON }
func (c *ExportCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":    predictHCL,
		"-format":    complete.PredictSet("json", "otm", "hcl"),
		"-output":    complete.PredictFiles("*"),
		"-template":  predictTpl,
	}
}
