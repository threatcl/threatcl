package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclwrite"
	tf "github.com/hashicorp/terraform-json"
	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/pkg/terraform"
)

type TerraformCommand struct {
	*GlobalCmdOptions
	specCfg                   *spec.ThreatmodelSpecConfig
	flagStdin                 bool
	flagDefaultClassification string
	flagAddToExisting         string
	flagTfCollectionJson      string
	flagTmName                string
}

type TerraformJsonMode int

const (
	UnknownMode TerraformJsonMode = iota
	PlanMode
	StateMode
)

func (c *TerraformCommand) Help() string {
	helpText := `
Usage: threatcl terraform <files>

  Parse output from 'terraform show -json' (as specified by <files>)

Options:

 -config=<file>
   Optional config file

 -stdin
   If set, will expect input to be piped in

 -default-classification=<string>
   If set, will assign the provided classification to output information_asset

 -add-to-existing=<hcl file>
   If set, will add the generated information_assets into the provided file. 
   This will not overwrite the provided <hcl file>

 -tm-name=<string>
   If -add-to-existing, this is used to specify a particular TM to target.

 -tf-collection=<json file>
   If set, use this to define the terraform json resources to parse

`
	return strings.TrimSpace(helpText)
}

func (c *TerraformCommand) Run(args []string) int {
	flagSet := c.GetFlagset("terraform")
	flagSet.BoolVar(&c.flagStdin, "stdin", false, "If set, will expect input to be piped in")
	flagSet.StringVar(&c.flagDefaultClassification, "default-classification", "", "If set, will provide a default information_classification for all assets")
	flagSet.StringVar(&c.flagAddToExisting, "add-to-existing", "", "If set, will add assets to this threat model")
	flagSet.StringVar(&c.flagTmName, "tm-name", "", "If set, and using add-to-existing, targets a specific threat model")
	flagSet.StringVar(&c.flagTfCollectionJson, "tf-collection", "", "If set, use this to define the terraform json resources to parse")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	tfCollectionJson := ""

	if c.flagTfCollectionJson != "" {
		// User has specified a custom json file to use instead of the pre
		// defined terraform resources to parse
		info, err := os.Stat(c.flagTfCollectionJson)
		if os.IsNotExist(err) {
			fmt.Printf("Could not find tf-collection file. '%s'", c.flagTfCollectionJson)
			return 1
		}

		if info.IsDir() {
			fmt.Printf("tf-collection can't be set to a directory. '%s'", c.flagTfCollectionJson)
			return 1
		}

		readJson, err := ioutil.ReadFile(c.flagTfCollectionJson)
		if err != nil {
			fmt.Printf("Error opening tf-collection json file: %s\n", err)
			return 1
		}

		tfCollectionJson = string(readJson)
	}

	tmParser := spec.NewThreatmodelParser(c.specCfg)
	var tm spec.Threatmodel

	if c.flagAddToExisting != "" {
		err := tmParser.ParseFile(c.flagAddToExisting, false)
		if err != nil {
			fmt.Printf("Error parsing provided <hcl file>: %s\n", err)
			return 1
		}
		if len(tmParser.GetWrapped().Threatmodels) == 0 {
			fmt.Printf("Need at least 1 threat model\n")
			return 1
		}
		if len(tmParser.GetWrapped().Threatmodels) > 1 {
			foundExisting := false
			errMsg := "This <hcl file> contains multiple models, select one with the -tm-name=<string> flag\n\nmodels:\n"
			for _, individualTm := range tmParser.GetWrapped().Threatmodels {
				if c.flagTmName == individualTm.Name {
					tm = individualTm
					foundExisting = true
					break
				}
				errMsg += fmt.Sprintf("%s\n", individualTm.Name)
			}

			if !foundExisting {
				fmt.Print(errMsg)
				return 1
			}
		} else {
			tm = tmParser.GetWrapped().Threatmodels[0]
		}

	}

	var in []byte
	var mode TerraformJsonMode = UnknownMode

	if c.flagStdin {
		// Try and parse STDIN
		reader := bufio.NewReader(os.Stdin)
		var output []rune
		for {
			input, _, err := reader.ReadRune()
			if err != nil && err == io.EOF {
				break
			}
			output = append(output, input)
		}

		in = []byte(string(output))
	} else {

		if len(flagSet.Args()) == 0 {
			fmt.Printf("Please provide <files> or -stdin\n")
			return 1
		} else {

			var err error
			in, err = ioutil.ReadFile(flagSet.Args()[0])
			if err != nil {
				fmt.Printf("Error reading file: %s\n", err)
				return 1
			}
		}
	}

	p := tf.Plan{}
	s := tf.State{}

	err := p.UnmarshalJSON(in)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %s\n", err)
		return 1
	}

	err = p.Validate()
	if err != nil {
		fmt.Printf("Error validating JSON: %s\n", err)
		return 1
	}

	if p.PlannedValues != nil {
		mode = PlanMode
	} else {
		err := s.UnmarshalJSON(in)
		if err != nil {
			fmt.Printf("Error unmarshalling JSON: %s\n", err)
			return 1
		}

		err = s.Validate()
		if err != nil {
			fmt.Printf("Error validating JSON: %s\n", err)
			return 1
		}

		if s.Values != nil {
			mode = StateMode
		}
	}

	tfc := terraform.NewCollection(&tfCollectionJson)

	switch mode {
	case PlanMode:
		for _, r := range p.PlannedValues.RootModule.Resources {
			provName := strings.Split(r.Type, "_")
			if len(provName) > 1 {
				if prov, exists := tfc[provName[0]]; exists {
					if res, ok := prov.Resources[r.Type]; ok {
						tmAsset := spec.InformationAsset{
							Name:   fmt.Sprintf("%s %s", r.Type, r.Name),
							Source: "terraform plan",
						}

						if c.flagDefaultClassification != "" {
							tmAsset.InformationClassification = c.flagDefaultClassification
						}

						for _, attr := range res.Attributes {
							if attrVal, attrExists := r.AttributeValues[attr]; attrExists && attrVal != nil {
								if len(tmAsset.Description) > 0 {
									tmAsset.Description = fmt.Sprintf("%s, %s: %s", tmAsset.Description, attr, attrVal)
								} else {
									tmAsset.Description = fmt.Sprintf("%s: %s", attr, attrVal)
								}
							}
						}

						if c.flagAddToExisting != "" {
							tm.InformationAssets = append(tm.InformationAssets, &tmAsset)

						} else {
							err = c.out(&tmAsset, os.Stdout)
							if err != nil {
								fmt.Printf("Error writing out: %s\n", err)
								return 1
							}
						}
					}
				}
			}
		}

	case StateMode:
		for _, r := range s.Values.RootModule.Resources {
			provName := strings.Split(r.Type, "_")
			if len(provName) > 1 {
				if prov, exists := tfc[provName[0]]; exists {
					if res, ok := prov.Resources[r.Type]; ok {
						tmAsset := spec.InformationAsset{
							Name:   fmt.Sprintf("%s %s", r.Type, r.Name),
							Source: "terraform state",
						}

						if c.flagDefaultClassification != "" {
							tmAsset.InformationClassification = c.flagDefaultClassification
						}

						for _, attr := range res.Attributes {
							if attrVal, attrExists := r.AttributeValues[attr]; attrExists && attrVal != nil {
								if len(tmAsset.Description) > 0 {
									tmAsset.Description = fmt.Sprintf("%s, %s: %s", tmAsset.Description, attr, attrVal)
								} else {
									tmAsset.Description = fmt.Sprintf("%s: %s", attr, attrVal)
								}
							}
						}

						if c.flagAddToExisting != "" {
							tm.InformationAssets = append(tm.InformationAssets, &tmAsset)

						} else {
							err = c.out(&tmAsset, os.Stdout)
							if err != nil {
								fmt.Printf("Error writing out: %s\n", err)
								return 1
							}
						}
					}
				}
			}
		}

	case UnknownMode:
		fmt.Printf("Unknown mode\n")
		return 1
	default:
		fmt.Printf("Unknown mode\n")
		return 1
	}

	if c.flagAddToExisting != "" {
		newTm := spec.NewThreatmodelParser(c.specCfg)
		err = newTm.AddTMAndWrite(tm, os.Stdout, false)
		if err != nil {
			fmt.Printf("Error writing out: %s\n", err)
			return 1
		}

	}

	return 0
}

func (c *TerraformCommand) out(asset *spec.InformationAsset, out *os.File) error {
	w := bufio.NewWriter(out)
	defer w.Flush()
	hclOut := hclwrite.NewEmptyFile()
	block := gohcl.EncodeAsBlock(asset, "information_asset")
	hclOut.Body().AppendBlock(block)
	_, err := w.Write(hclOut.Bytes())
	if err != nil {
		return fmt.Errorf("Error writing out: %s\n", err)
	}
	return nil
}

func (c *TerraformCommand) Synopsis() string {
	return "Parse output from 'terraform show -json'"
}
