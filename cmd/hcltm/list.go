package main

import (
	"fmt"
	"strings"

	"github.com/ryanuber/columnize"
	"github.com/xntrik/hcltm/pkg/spec"
)

type ListCommand struct {
	*GlobalCmdOptions
	specCfg      *spec.ThreatmodelSpecConfig
	flagFields   string
	flagNoHeader bool
}

func (c *ListCommand) Help() string {
	helpText := `
Usage: hcltm list [options] <files>

  List Threatmodels from selected HCL files (as specified by <files>)

Options:

 -config=<file>
   Optional config file

 -fields=<fields>
   Comma-separated list of fields to list. Fields include 'number', 'file',
   'threatmodel', 'assetcount', 'threatcount', 'usecasecount', 'tpdcount', 'exclusioncount', 'size', 'internetfacing',
   'newinitiative' and 'author'.
   If not set, defaults to 'number,file,threatmodel,author'

 -noheader
   If set, will not print the header

`
	return strings.TrimSpace(helpText)
}

func (c *ListCommand) Run(args []string) int {

	flagSet := c.GetFlagset("list")
	flagSet.StringVar(&c.flagFields, "fields", "", "Comma-separated list of fields for list. Fields include 'number', 'file', 'threatmodel', 'assetcount', 'threatcount', 'usecasecount','tpdcount', 'exclusioncount', 'size', 'internetfacing', 'newinitiative' and 'author'.")
	flagSet.BoolVar(&c.flagNoHeader, "noheader", false, "If set, will not print the header")
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
	} else {

		output := []string{}

		availableFlagFields := []string{
			"Number",
			"File",
			"Threatmodel",
			"Author",
			"AssetCount",
			"ThreatCount",
			"TPDCount",
			"Size",
			"Internetfacing",
			"Newinitiative",
			"Usecasecount",
			"Exclusioncount",
		}

		// flagFields := make(map[string]interface{})
		flagFields := []string{}

		// Set default flagFields
		if c.flagFields == "" {
			flagFields = append(flagFields, "Number")
			flagFields = append(flagFields, "File")
			flagFields = append(flagFields, "Threatmodel")
			flagFields = append(flagFields, "Author")
		} else {
			// We need to parse provided fields for listing
			selectedFields := strings.Split(c.flagFields, ",")
			for _, selectedField := range selectedFields {
				for _, availableFlagField := range availableFlagFields {
					if strings.ToLower(availableFlagField) == strings.ToLower(selectedField) {
						flagFields = append(flagFields, availableFlagField)
					}
				}
			}
		}

		if !c.flagNoHeader {
			// Build the header
			headerString := ""
			for _, flagField := range flagFields {
				if headerString != "" {
					headerString = headerString + " | "
				}
				switch flagField {
				case "Number":
					headerString = headerString + "#"
				case "AssetCount":
					headerString = headerString + "Information Asset Count"
				case "ThreatCount":
					headerString = headerString + "Threat Count"
				case "Usecasecount":
					headerString = headerString + "Use Case Count"
				case "TPDCount":
					headerString = headerString + "Third Party Dep Count"
				case "Exclusioncount":
					headerString = headerString + "Exclusion Count"
				case "Internetfacing":
					headerString = headerString + "Internet Facing"
				case "Newinitiative":
					headerString = headerString + "New Initiative"
				default:
					headerString = headerString + flagField
				}
			}

			output = append(output, headerString)
		}

		tmCount := 1

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
				bodyString := ""
				for _, flagField := range flagFields {
					if bodyString != "" {
						bodyString = bodyString + " | "
					}

					switch flagField {
					case "Number":
						bodyString = bodyString + fmt.Sprintf("%d", tmCount)
					case "File":
						bodyString = bodyString + file
					case "Threatmodel":
						bodyString = bodyString + tm.Name
					case "Author":
						bodyString = bodyString + tm.Author
					case "AssetCount":
						bodyString = bodyString + fmt.Sprintf("%d", len(tm.InformationAssets))
					case "ThreatCount":
						bodyString = bodyString + fmt.Sprintf("%d", len(tm.Threats))
					case "Usecasecount":
						bodyString = bodyString + fmt.Sprintf("%d", len(tm.UseCases))
					case "TPDCount":
						bodyString = bodyString + fmt.Sprintf("%d", len(tm.ThirdPartyDependencies))
					case "Exclusioncount":
						bodyString = bodyString + fmt.Sprintf("%d", len(tm.Exclusions))
					case "Size":
						if tm.Attributes != nil {
							bodyString = bodyString + tm.Attributes.InitiativeSize
						} else {
							bodyString = bodyString + "-"
						}
					case "Internetfacing":
						if tm.Attributes != nil {
							bodyString = bodyString + fmt.Sprintf("%t", tm.Attributes.InternetFacing)
						} else {
							bodyString = bodyString + "-"
						}
					case "Newinitiative":
						if tm.Attributes != nil {
							bodyString = bodyString + fmt.Sprintf("%t", tm.Attributes.NewInitiative)
						} else {
							bodyString = bodyString + "-"
						}
					}
				}

				output = append(output, bodyString)
				tmCount = tmCount + 1
			}
		}

		colOut := columnize.SimpleFormat(output)
		fmt.Println(colOut)
	}

	return 0
}

func (c *ListCommand) Synopsis() string {
	return "List Threatmodels found in HCL file(s)"
}
