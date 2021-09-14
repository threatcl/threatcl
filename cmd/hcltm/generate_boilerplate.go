package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/xntrik/hcltm/pkg/spec"
)

const (
	BoilerplateTemplate = `// To cater for multiple spec versions we specify this in our HCL files
spec_version = "{{.SpecVersion}}"

// You can include variables outside your threatmodel blocks

variable "variable_name" {
  value = "Variable text here"
}

// To use this, simply swap in a text attribute for var.variable_name

// There may be multiple threatmodel blocks in a single file, but their names must be unique

threatmodel "threatmodel name" {
  // The description is optional
  description = "A description of the system being assessed"

  // The link is optional
  link = "https://link/to/docs"

  // The diagram_link is optional
  // If it ends in .jpg or .png then it'll be embedded in the resultant dashboard

  // If a diagram_link isn't set, but the threatmodel includes a
  // data_flow_diagram, this will be automatically generated and included
  // when running hcltm dashboard

  diagram_link = "https://link/to/diagram"

  // the author attribute is required
  author = "@xntrik"

  // created_at and updated_at are optional integer, UNIX time stamps
  created_at = 1594033151
  updated_at = 1594033160

  // the attributes block is optional, but recommended

  attributes {
    new_initiative = "true" // boolean
    internet_facing = "true" // boolean

    // initiative_size must be one of '{{.InitiativeSizeOptions}}'
    initiative_size = "{{.DefaultInitiativeSize}}"
  }

  // Each threatmodel may contain a number of information_assets
  // the names must be unique per threatmodel though

  information_asset "cred store" {
    // The description is optional
    description = "This is where creds are stored"

    // information_classification must be one of '{{.InfoClassificationOptions}}'
    information_classification = "{{.DefaultInfoClassification}}"
  }

  information_asset "special sauce" {
    // Here is how you can refer to your variables set above
    description = var.variable_name
    information_classification = "{{.DefaultInfoClassification}}"
  }

  // Each threatmodel may contain a number of usecases

  usecase {
    // The description is required
    // Similar to threats, the description may also use multiline entries too
    description = "Users access data from the system"
  }

  // Each threatmodel may contain a number of exclusions

  exclusion {
    // The description is required
    // Similar to threats, the description may also use multiline entries too
    description = "Crypto operations are offloaded to a KMS"
  }

  // Each threatmodel may contain a number of third party dependencies

  third_party_dependency "dependency name" {
    // The description is required, and may use multiline entries
    description = "What the depencency is used for"

    // The following boolean attributes are optional and will default to false if unset
    saas = "true"
    paying_customer = "true"
    open_source = "false"
    infrastructure = "false"

    // The uptime dependency is required, and must be one of {{.UptimeDeps}}
    // This specifies the impact to our system if the depencency is unavailable
    uptime_dependency = "{{.DefaultUptimeDep}}"

    // Uptime notes are optional
    uptime_notes = "If this depencency goes down users can't login"
  }

  // Each threatmodel may contain a number of threats

  threat {
    // The description is required
    description = "System is compromised by hackers"

    // The impact is an optional array of potential impact values
    // The available values are '{{.ImpactTypes}}'
    impacts = [{{.ImpactTypesOut}}]

    // The control is optional, and allows the author to capture controls
    // or circumstances that may reduce the likelihood of impact of the threat
    control = "We require 2FA for access"

    // The stride is an optional array of STRIDE elements that apply to this threat
    // The available values are:
    // {{.StrideElements}}
    stride = [{{.StrideElementsOut}}]

    // The information_asset_refs are an optional array of information_assets
    // the elements must much existing information_assets - as above
    information_asset_refs = ["cred store"]
  }

  // You can import an external .hcl file that includes control descriptions
  // Remember to do this at the threatmodel block level

  // An example of what may be in controls.hcl:
  //
  // spec_version = "{{.SpecVersion}}"
  // component "control" "control_name" {
  //   description = "A control that can be used in multiple places"
  // }

  imports = ["controls.hcl"]

  threat {

    // To reference the above component
    control = import.control.control_name.description

    description = <<EOT
Descriptions may be a multi-line entry as well.

For example, this is still part of the threat description
EOT
  }

  // Each threatmodel may contain a single data_flow_diagram
  // The data_flow_diagram is a HCL representation of a data flow diagram
  // You can read more about security DFDs here https://docs.microsoft.com/en-us/learn/modules/tm-create-a-threat-model-using-foundational-data-flow-diagram-elements/

  data_flow_diagram {

    // All blocks must have unique names
    // That means that a process, data_store, or external_element can't all
    // be named "foo"

    process "update data" {}

    // All these elements may include an optional trust_zone
    // Trust Zones are used to define trust boundaries

    process "update password" {
      trust_zone = "secure zone"
    }

    data_store "password db" {
      trust_zone = "secure zone"
    }

    external_element "user" {}

    // To connect any of the above elements, you use a flow block
    // Flow blocks can have the same name, but their from and to fields
    // must be unique

    flow "https" {
      from = "user"
      to = "update data"
    }

    flow "https" {
      from = "user"
      to = "update password"
    }

    flow "tcp" {
      from = "update password"
      to = "password db"
    }
  }
}
`
)

type boilerplate struct {
	SpecVersion               string
	InitiativeSizeOptions     string
	DefaultInitiativeSize     string
	InfoClassificationOptions string
	DefaultInfoClassification string
	ImpactTypes               string
	ImpactTypesOut            string
	StrideElements            string
	StrideElementsOut         string
	UptimeDeps                string
	DefaultUptimeDep          string
}

type GenerateBoilerplateCommand struct {
	*GlobalCmdOptions
	specCfg *spec.ThreatmodelSpecConfig
	flagOut string
}

func (c *GenerateBoilerplateCommand) Help() string {
	helpText := `
Usage: hcltm generate boilerplate [options]

  Outputs a generic HCL threatmodel that you can edit later.

Options:

 -config=<file>
   Optional config file

 -out=<file>
   Path on the local disk to write the HCL file to. If not set (default), the
   HCL output will be written to STDOUT

`
	return strings.TrimSpace(helpText)
}

func (c *GenerateBoilerplateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("generate boilerplate")
	flagSet.StringVar(&c.flagOut, "out", "", "Where to output HCL file (if empty, write to STDOUT)")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	var f *os.File

	if c.flagOut != "" {
		// Looks like we want to write to a file

		// Check if it exists already
		_, err := os.Stat(c.flagOut)
		if os.IsExist(err) {
			fmt.Printf("You're trying to write to '%s', which already exists..\n", c.flagOut)
			return 1
		}

		f, err = os.Create(c.flagOut)
		if err != nil {
			fmt.Printf("Error creating file '%s'\n", err)
			return 1
		}

		defer f.Close()
	}

	bp := boilerplate{
		SpecVersion:               c.specCfg.Version,
		InitiativeSizeOptions:     strings.Join(c.specCfg.InitiativeSizes, ", "),
		DefaultInitiativeSize:     c.specCfg.DefaultInitiativeSize,
		InfoClassificationOptions: strings.Join(c.specCfg.InfoClassifications, ", "),
		DefaultInfoClassification: c.specCfg.DefaultInfoClassification,
		ImpactTypes:               strings.Join(c.specCfg.ImpactTypes, ", "),
		ImpactTypesOut:            fmt.Sprintf("\"%s\"", strings.Join(c.specCfg.ImpactTypes, "\", \"")),
		StrideElements:            strings.Join(c.specCfg.STRIDE, "\n    // "),
		StrideElementsOut:         fmt.Sprintf("\"%s\"", strings.Join(c.specCfg.STRIDE, "\", \"")),
		UptimeDeps:                fmt.Sprintf("\"%s\"", strings.Join(c.specCfg.UptimeDepClassifications, "\", \"")),
		DefaultUptimeDep:          c.specCfg.DefaultUptimeDepClassification,
	}
	tmpl, err := template.New("BPTemplate").Parse(BoilerplateTemplate)
	if err != nil {
		fmt.Printf("Error parsing template: %s\n", err)
		return 1
	}

	if c.flagOut == "" {
		err = tmpl.Execute(os.Stdout, bp)
		if err != nil {
			fmt.Printf("Error writing to stdout: %s\n", err)
			return 1
		}
	} else {
		err = tmpl.Execute(f, bp)
		if err != nil {
			fmt.Printf("Error writing to file: %s\n", err)
			return 1
		}
		fmt.Printf("Successfully wrote to '%s'\n", c.flagOut)
	}

	return 0

}

func (c *GenerateBoilerplateCommand) Synopsis() string {
	return "Generate a generic HCL threatmodel that you can edit later"
}
