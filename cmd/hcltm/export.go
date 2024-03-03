package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/threatcl/go-otm/pkg/otm"
	"github.com/xntrik/hcltm/pkg/spec"
)

// ExportCommand struct defines the "hcltm export" commands
type ExportCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagFormat    string
	flagOutput    string
	flagOverwrite bool
}

// Help is the help output for the "hcltm export" command
func (e *ExportCommand) Help() string {
	helpText := `
Usage: hcltm export [options] <files>

  Export provided HCL threat models into other formats

Options:

 -config=<file>
   Optional config file

 -format=<json|otm>

 -output=<file>
   Optional filename to output to. 

 -overwrite

`
	return strings.TrimSpace(helpText)
}

// Run executes the "hcltm export" logic
func (e *ExportCommand) Run(args []string) int {
	flagSet := e.GetFlagset("export")
	flagSet.StringVar(&e.flagFormat, "format", "json", "Format of output. json, or otm. Defaults to json")
	flagSet.StringVar(&e.flagOutput, "output", "", "Name of output file. If not set, will output to STDOUT")
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

		// Parse all the identified .hcl files
		for _, file := range AllFiles {
			tmParser := spec.NewThreatmodelParser(e.specCfg)
			err := tmParser.ParseFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {
				AllTms = append(AllTms, tm)
			}

		}

		var outputString string

		switch e.flagFormat {
		case "json":

			tmJson, err := json.Marshal(AllTms)
			if err != nil {
				fmt.Printf("Error parsing into json: %s\n", err)
				return 1
			}

			outputString = string(tmJson)

		case "otm":
			allOtms := []otm.OtmSchemaJson{}
			for _, tm := range AllTms {
				tmOtm, err := tm.RenderOtm()
				if err != nil {
					fmt.Printf("Error parsing into otm: %s\n", err)
					return 1
				}

				allOtms = append(allOtms, tmOtm)
			}

			var otmJson []byte
			var err error

			if len(AllTms) > 1 {
				otmJson, err = json.Marshal(allOtms)
				if err != nil {
					fmt.Printf("Error parsing into otm: %s\n", err)
					return 1
				}
			} else if len(AllTms) == 1 {
				otmJson, err = json.Marshal(allOtms[0])
				if err != nil {
					fmt.Printf("Error parsing into otm: %s\n", err)
					return 1
				}
			}

			outputString = string(otmJson)

		default:

			fmt.Printf("Incorrect -format option\n")
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

// Synopsis returns the synopsis for the "hcltm export" command
func (e *ExportCommand) Synopsis() string {
	return "Export threat models into other formats"
}
