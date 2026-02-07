package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/threatcl/spec"
)

const (
	NewInitiativeOptionText      = "New initiative"
	ExistingInitiativeOptionText = "Change to an existing system"
)

type GenerateInteractiveCommand struct {
	*GlobalCmdOptions
	specCfg *spec.ThreatmodelSpecConfig
	flagOut string
}

func (c *GenerateInteractiveCommand) Help() string {
	helpText := `
Usage: threatcl generate interactive [options]

  Interactively prompts you to answer some questions. Responses are then used
  to output a HCL threatmodel.

Options:

 -config=<file>
   Optional config file

 -debug
   If set, will output debugging information.

 -out=<file>
   Path on the local disk to write the HCL file to. If not set (default), the
   HCL output will be written to STDOUT

`

	return strings.TrimSpace(helpText)
}

// It might be nice to eventually make this dynamic, perhaps pulling
// questions etc from a template file
func (c *GenerateInteractiveCommand) Run(args []string) int {

	flagSet := c.GetFlagset("generate interactive")
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
		if !os.IsNotExist(err) {
			fmt.Printf("You're trying to write to '%s' file, which already exists..\n", c.flagOut)
			return 1
		}

		f, err = os.Create(c.flagOut)
		if err != nil {
			fmt.Printf("Error creating file '%s'\n", err)
			return 1
		}

		defer f.Close()
	}

	tmParser := spec.NewThreatmodelParser(c.specCfg)

	// Overview questions
	fmt.Println("Welcome to threatcl, first we'll get a brief overview of the initiative you want to assess...")

	var overviewQs = []*survey.Question{
		{
			Name: "name",
			Prompt: &survey.Input{
				Message: "Threatmodel Name:",
				Help:    "Give this threatmodel a name, such as the project name or component",
			},
			Validate: survey.Required,
		},
		{
			Name: "description",
			Prompt: &survey.Input{
				Message: "Describe the scope of the threat model (optional):",
				Help:    "At a high level, describe the scope of what we want to threat model",
			},
		},
		{
			Name:   "link",
			Prompt: &survey.Input{Message: "Provide a link to a ticket, PR or doc (optional):"},
		},
		{
			Name:   "diagramlink",
			Prompt: &survey.Input{Message: "Provide a link to a diagram (optional):"},
		},
		{
			Name:     "author",
			Prompt:   &survey.Input{Message: "Provide your name or github handle:"},
			Validate: survey.Required,
		},
	}

	time_now := time.Now().Unix()

	tm := spec.Threatmodel{
		CreatedAt: time_now,
		UpdatedAt: time_now,
	}

	overviewAnswers := struct {
		Name        string
		Description string
		Link        string
		Diagramlink string
		Author      string
	}{}

	err := survey.Ask(overviewQs, &overviewAnswers)

	// we set these fields here in case we have to handle an Interrupt
	tm.Name = overviewAnswers.Name
	tm.Description = overviewAnswers.Description
	tm.Link = overviewAnswers.Link
	tm.DiagramLink = overviewAnswers.Diagramlink
	tm.Author = overviewAnswers.Author

	if err != nil {
		if err == terminal.InterruptErr {
			if c.flagOut != "" {
				fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
			} else {
				fmt.Printf("Interrupted - outputting what we can\n")
			}
			outerr := c.out(tmParser, tm, f)
			if outerr != nil {
				fmt.Printf("%s\n", outerr)
			}
		} else {
			fmt.Println(err.Error())
		}
		return 1
	}

	// err = tmParser.ValidateTm(&tm)
	err = tm.ValidateTm(tmParser)
	if err != nil {
		fmt.Printf("Error validating TM: %s\n", err)
		return 1
	}

	// Attribute questions
	fmt.Printf("\nPlease provide us a few more attributes related to the initiative...\n")

	var attributeQs = []*survey.Question{
		{
			Name: "newinitiative",
			Prompt: &survey.Select{
				Message: "Is this a new initiative, or a change to an existing system?",
				Options: []string{ExistingInitiativeOptionText, NewInitiativeOptionText},
			},
		},
		{
			Name: "internetfacing",
			Prompt: &survey.Select{
				Message: "Does this initiative face the Internet?",
				Options: []string{"No", "Yes"},
				Help:    "Knowing if a system is exposed to the Internet can be helpful in understanding threats and exposures",
			},
		},
		{
			Name: "initiativesize",
			Prompt: &survey.Select{
				Message: "How big is the initiative? (an estimate is fine)",
				Options: c.specCfg.InitiativeSizes,
				Default: c.specCfg.DefaultInitiativeSize,
				Help:    "Large and therefore complicated systems may introduce more risks",
			},
		},
	}

	attributeAnswers := struct {
		Newinitiative  string
		Internetfacing string
		Initiativesize string
	}{}

	err = survey.Ask(attributeQs, &attributeAnswers)

	if attributeAnswers.Newinitiative == NewInitiativeOptionText {
		attributeAnswers.Newinitiative = "Yes"
	} else {
		attributeAnswers.Newinitiative = "No"
	}

	tmAttr := spec.Attribute{
		NewInitiative:  prettyBoolFromString(attributeAnswers.Newinitiative),
		InternetFacing: prettyBoolFromString(attributeAnswers.Internetfacing),
		InitiativeSize: attributeAnswers.Initiativesize,
	}

	tm.Attributes = &tmAttr
	if err != nil {
		if err == terminal.InterruptErr {
			if c.flagOut != "" {
				fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
			} else {
				fmt.Printf("Interrupted - outputting what we can\n")
			}
			outerr := c.out(tmParser, tm, f)
			if outerr != nil {
				fmt.Printf("%s\n", outerr)
			}
		} else {
			fmt.Println(err.Error())
		}
		return 1
	}

	// err = tmParser.ValidateTm(&tm)
	err = tm.ValidateTm(tmParser)
	if err != nil {
		fmt.Printf("Error validating TM: %s\n", err)
		return 1
	}

	continueQ := &survey.Select{
		Message: "Would you like to add an Information Asset?",
		Options: []string{"Yes", "No"},
		Help:    "An Information Asset is any sort of sensitive information that the system interacts with or stores, and which could impact us if disclosed or tampered with",
	}

	for {
		continueA := ""
		err = survey.AskOne(continueQ, &continueA)
		if err != nil {
			if err == terminal.InterruptErr {
				if c.flagOut != "" {
					fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
				} else {
					fmt.Printf("Interrupted - outputting what we can\n")
				}
				outerr := c.out(tmParser, tm, f)
				if outerr != nil {
					fmt.Printf("%s\n", outerr)
				}
			} else {
				fmt.Println(err.Error())
			}
			return 1
		}

		continueQ.Message = "Would you like to add another Information Asset?"

		if continueA == "No" {
			fmt.Println()
			break
		} else {
			var iaQs = []*survey.Question{
				{
					Name: "ianame",
					Prompt: &survey.Input{
						Message: "[Asset] Name:",
						Help:    "For example, 'credential store'",
					},
					Validate: survey.Required,
				},
				{
					Name:   "iadescription",
					Prompt: &survey.Input{Message: "[Asset] Description (optional):"},
				},
				{
					Name: "iaclassification",
					Prompt: &survey.Select{
						Message: "[Asset] Info Classification:",
						Options: c.specCfg.InfoClassifications,
						Default: c.specCfg.DefaultInfoClassification,
					},
				},
			}

			iaAnswers := struct {
				Ianame           string
				Iadescription    string
				Iaclassification string
			}{}

			err = survey.Ask(iaQs, &iaAnswers)

			infoAsset := spec.InformationAsset{
				Name:                      iaAnswers.Ianame,
				Description:               iaAnswers.Iadescription,
				InformationClassification: iaAnswers.Iaclassification,
			}

			if c.infoAssetExists(&tm, iaAnswers.Ianame) {
				fmt.Printf("An Information Asset by that name already exists, not adding\n\n")
				// don't ask me why I need to print two lines here
			} else {
				tm.InformationAssets = append(tm.InformationAssets, &infoAsset)
			}

			if err != nil {
				if err == terminal.InterruptErr {
					if c.flagOut != "" {
						fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
					} else {
						fmt.Printf("Interrupted - outputting what we can\n")
					}
					outerr := c.out(tmParser, tm, f)
					if outerr != nil {
						fmt.Printf("%s\n", outerr)
					}
				} else {
					fmt.Println(err.Error())
				}
				return 1
			}

			// err = tmParser.ValidateTm(&tm)
			err = tm.ValidateTm(tmParser)
			if err != nil {
				fmt.Printf("Error validating TM: %s\n", err)
				return 1
			}

			fmt.Println() // for formatting reasons apparently
		}
	}

	continueQ.Message = "Would you like to add a Use Case?"
	continueQ.Help = "A Use Case is a means to describe how something or someone may interact with the system"

	for {
		continueA := ""
		err = survey.AskOne(continueQ, &continueA)
		if err != nil {
			if err == terminal.InterruptErr {
				if c.flagOut != "" {
					fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
				} else {
					fmt.Printf("Interrupted - outputting what we can\n")
				}
				outerr := c.out(tmParser, tm, f)
				if outerr != nil {
					fmt.Printf("%s\n", outerr)
				}
			} else {
				fmt.Println(err.Error())
			}
			return 1
		}

		continueQ.Message = "Would you like to add another Use Case?"

		if continueA == "No" {
			fmt.Println()
			break
		} else {
			var ucQ = []*survey.Question{
				{
					Name: "ucdescription",
					Prompt: &survey.Input{
						Message: "[Use Case] Description:",
						Help:    "For example, 'A user submits credit cards to the system'",
					},
					Validate: survey.Required,
				},
			}

			ucAnswer := struct {
				Ucdescription string
			}{}

			err = survey.Ask(ucQ, &ucAnswer)

			uc := spec.UseCase{
				Description: ucAnswer.Ucdescription,
			}

			tm.UseCases = append(tm.UseCases, &uc)
			if err != nil {
				if err == terminal.InterruptErr {
					if c.flagOut != "" {
						fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
					} else {
						fmt.Printf("Interrupted - outputting what we can\n")
					}
					outerr := c.out(tmParser, tm, f)
					if outerr != nil {
						fmt.Printf("%s\n", outerr)
					}
				} else {
					fmt.Println(err.Error())
				}
				return 1
			}

			// err = tmParser.ValidateTm(&tm)
			err = tm.ValidateTm(tmParser)
			if err != nil {
				fmt.Printf("Error validating TM: %s\n", err)
				return 1
			}

			fmt.Println() // for formatting reasons apparently
		}
	}

	continueQ.Message = "Would you like to add an Exclusion?"
	continueQ.Help = "An Exclusion is a means to describe something that is explicitly excluded from this threat model"

	for {
		continueA := ""
		err = survey.AskOne(continueQ, &continueA)
		if err != nil {
			if err == terminal.InterruptErr {
				if c.flagOut != "" {
					fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
				} else {
					fmt.Printf("Interrupted - outputting what we can\n")
				}
				outerr := c.out(tmParser, tm, f)
				if outerr != nil {
					fmt.Printf("%s\n", outerr)
				}
			} else {
				fmt.Println(err.Error())
			}
			return 1
		}

		continueQ.Message = "Would you like to add another Exclusion?"

		if continueA == "No" {
			fmt.Println()
			break
		} else {
			var exclQ = []*survey.Question{
				{
					Name: "excldescription",
					Prompt: &survey.Input{
						Message: "[Exclusion] Description:",
						Help:    "For example, 'The auth system is external'",
					},
					Validate: survey.Required,
				},
			}

			exclAnswer := struct {
				Excldescription string
			}{}

			err = survey.Ask(exclQ, &exclAnswer)

			excl := spec.Exclusion{
				Description: exclAnswer.Excldescription,
			}

			tm.Exclusions = append(tm.Exclusions, &excl)
			if err != nil {
				if err == terminal.InterruptErr {
					if c.flagOut != "" {
						fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
					} else {
						fmt.Printf("Interrupted - outputting what we can\n")
					}
					outerr := c.out(tmParser, tm, f)
					if outerr != nil {
						fmt.Printf("%s\n", outerr)
					}
				} else {
					fmt.Println(err.Error())
				}
				return 1
			}

			// err = tmParser.ValidateTm(&tm)
			err = tm.ValidateTm(tmParser)
			if err != nil {
				fmt.Printf("Error validating TM: %s\n", err)
				return 1
			}

			fmt.Println() // for formatting reasons apparently
		}
	}

	continueQ.Message = "Would you like to add a Threat Scenario?"
	continueQ.Help = "A Threat Scenario is a description of something bad that could happen to impact this system - i.e. what could go wrong?"

	for {
		continueA := ""
		err = survey.AskOne(continueQ, &continueA)
		if err != nil {
			if err == terminal.InterruptErr {
				if c.flagOut != "" {
					fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
				} else {
					fmt.Printf("Interrupted - outputting what we can\n")
				}
				outerr := c.out(tmParser, tm, f)
				if outerr != nil {
					fmt.Printf("%s\n", outerr)
				}
			} else {
				fmt.Println(err.Error())
			}
			return 1
		}

		continueQ.Message = "Would you like to add another Threat Scenario?"

		if continueA == "No" {
			fmt.Println()
			break
		} else {
			var tQs = []*survey.Question{
				{
					Name: "tname",
					Prompt: &survey.Input{
						Message: "[Threat] Name:",
						Help:    "A unique name for this threat. For example, 'User Impersonation via Stolen Credentials'",
					},
					Validate: survey.Required,
				},
				{
					Name: "tdescription",
					Prompt: &survey.Input{
						Message: "[Threat] Description:",
						Help:    "For example, 'An attacker is able to impersonate a user and access their information'",
					},
					Validate: survey.Required,
				},
				{
					Name: "timpacttypes",
					Prompt: &survey.MultiSelect{
						Message: "[Threat] Impact Type(s):",
						Options: c.specCfg.ImpactTypes,
					},
				},
				{
					Name: "tcontrol",
					Prompt: &survey.Input{
						Message: "[Threat] Control (optional):",
						Help:    "For example, 'Authentication requires 2FA'",
					},
				},
			}

			tAnswers := struct {
				Tname        string
				Tdescription string
				Timpacttypes []string
				Tcontrol     string
			}{}

			err = survey.Ask(tQs, &tAnswers)

			t := spec.Threat{
				Name:        tAnswers.Tname,
				Description: tAnswers.Tdescription,
				ImpactType:  tAnswers.Timpacttypes,
				Control:     tAnswers.Tcontrol,
			}

			tm.Threats = append(tm.Threats, &t)
			if err != nil {
				if err == terminal.InterruptErr {
					if c.flagOut != "" {
						fmt.Printf("Interrupted - writing what we can to %s\n", c.flagOut)
					} else {
						fmt.Printf("Interrupted - outputting what we can\n")
					}
					outerr := c.out(tmParser, tm, f)
					if outerr != nil {
						fmt.Printf("%s\n", outerr)
					}
				} else {
					fmt.Println(err.Error())
				}
				return 1
			}

			// err = tmParser.ValidateTm(&tm)
			err = tm.ValidateTm(tmParser)
			if err != nil {
				fmt.Printf("Error validating TM: %s\n", err)
				return 1
			}

			fmt.Println()
		}
	}

	err = c.out(tmParser, tm, f)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}
	return 0
}

func (c *GenerateInteractiveCommand) out(tmParser *spec.ThreatmodelParser, tm spec.Threatmodel, out *os.File) error {
	if c.flagOut == "" {
		err := tmParser.AddTMAndWrite(tm, os.Stdout, c.flagDebug)
		if err != nil {
			return fmt.Errorf("error writing to stdout: %s", err)
		}
	} else {
		err := tmParser.AddTMAndWrite(tm, out, c.flagDebug)
		if err != nil {
			return fmt.Errorf("error writing model to HCL file: %s", err)
		}
	}
	return nil
}

func (c *GenerateInteractiveCommand) Synopsis() string {
	return "Interactively generate a HCL threatmodel"
}

func (c *GenerateInteractiveCommand) infoAssetExists(tm *spec.Threatmodel, iaName string) bool {
	if tm.InformationAssets != nil {
		for _, ia := range tm.InformationAssets {
			if ia.Name == iaName {
				return true
			}
		}
	}
	return false
}
