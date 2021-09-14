package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/xntrik/hcltm/pkg/spec"
)

type tmListEntryType struct {
	Name           string
	File           string
	Hover          string
	Author         string
	NewInitiative  string
	InternetFacing string
	Size           string
}

type DashboardCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagOutDir    string
	flagOverwrite bool
	flagNoDfd     bool
}

func (c *DashboardCommand) Help() string {
	helpText := `
Usage: hcltm dashboard [options] -outdir=<directory> <files>

  Generate markdown files from existing Threat model HCL files (as specified
  by <files>) 

 -outdir=<directory>
   Directory to output MD files. Will create directory if it doesn't exist.
   Must be set

Options:

 -config=<file>
   Optional config file

 -overwrite

 -nodfd

`
	return strings.TrimSpace(helpText)
}

func (c *DashboardCommand) Run(args []string) int {

	flagSet := c.GetFlagset("dashboard")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output MD files. Will create directory if it doesn't exist. Must be set")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files in the outdir. Defaults to false")
	flagSet.BoolVar(&c.flagNoDfd, "nodfd", false, "Do not include generated DFD images. Defaults to false")
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

		err := createOrValidateFolder(c.flagOutDir, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}
		fmt.Printf("Created the '%s' directory\n", c.flagOutDir)

		// We use outfiles to generate a list of output files to validate whether
		// we're overwriting them or not.
		outfiles := []string{
			fmt.Sprintf("%s/dashboard.md", c.flagOutDir),
		}

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
				outfile := outfilePath(c.flagOutDir, tm.Name, file, ".md")

				outfiles = append(outfiles, outfile)

				if !c.flagNoDfd && tm.DataFlowDiagram != nil {
					outfiles = append(outfiles, outfilePath(c.flagOutDir, tm.Name, file, ".png"))
				}

			}
		}

		// Validating existing files - if we're not overwriting
		if !c.flagOverwrite {
			for _, outfile := range outfiles {
				_, err = os.Stat(outfile)
				if !os.IsNotExist(err) {
					fmt.Printf("'%s' already exists\n", outfile)
					return 1
				}
			}
		} else {
			fmt.Printf("Writing dashboard markdown files to '%s' and overwriting existing files\n", c.flagOutDir)
		}

		// Now we parse the files again, but actually process them and create MD files
		// @TODO Fix the race condition (or TOCTOU problem)

		tmList := []tmListEntryType{}

		for _, file := range HCLFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseHCLFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			for _, tm := range tmParser.GetWrapped().Threatmodels {

				// First we check if there are any DFDs
				if !c.flagNoDfd && tm.DataFlowDiagram != nil {
					dfdPath := outfilePath(c.flagOutDir, tm.Name, file, ".png")
					err = tm.GenerateDfdPng(dfdPath)
					if err != nil {
						fmt.Printf("Error generating DFD: %s\n", err)
						return 1
					}

					fmt.Printf("Successfully wrote to '%s'\n", dfdPath)

					// Now we set the tm diagram to this file
					// if it's currently unset
					if tm.DiagramLink == "" {
						tm.DiagramLink = filepath.Base(dfdPath)
					}

				}

				tmBuffer, err := tm.RenderMarkdown(spec.TmMDTemplate)
				if err != nil {
					fmt.Println(err)
					return 1
				}

				outfile := outfilePath(c.flagOutDir, tm.Name, file, ".md")

				f, err := os.Create(outfile)
				if err != nil {
					fmt.Printf("Error creating file: '%s'\n", err)
					return 1
				}
				defer f.Close()

				_, err = io.Copy(f, tmBuffer)
				if err != nil {
					fmt.Printf("Error writing to file: %s\n", err)
					return 1
				}

				fmt.Printf("Successfully wrote to '%s'\n", outfile)

				// Now we add it to the dashboard.md tmList

				tmListEntry := tmListEntryType{
					Name:           tm.Name,
					File:           filepath.Base(outfile),
					Hover:          "",
					Author:         tm.Author,
					NewInitiative:  "-",
					InternetFacing: "-",
					Size:           "-",
				}

				hover := ""

				if tm.UpdatedAt != 0 && tm.CreatedAt != 0 {
					hover = hover + fmt.Sprintf("Created: %s, Updated: %s. ", unixToTime(tm.CreatedAt), unixToTime(tm.UpdatedAt))
				}

				hover = hover + strings.Replace(tm.Description, "\n", " ", -1)

				hoverRunes := []rune(hover)
				if len(hoverRunes) > 199 {
					hover = string(hoverRunes[0:195]) + "..."
				}
				tmListEntry.Hover = hover

				if tm.Attributes != nil {
					if tm.Attributes.NewInitiative {
						tmListEntry.NewInitiative = "Yes"
					} else {
						tmListEntry.NewInitiative = "No"
					}

					if tm.Attributes.InternetFacing {
						tmListEntry.InternetFacing = "Yes"
					} else {
						tmListEntry.InternetFacing = "No"
					}

					tmListEntry.Size = tm.Attributes.InitiativeSize
				}

				tmList = append(tmList, tmListEntry)
			}
		}

		sort.Slice(tmList, func(i, j int) bool {
			return tmList[i].Name < tmList[j].Name
		})

		// Now we create the dashboard.md file

		tmpl, err := template.New("DashboardTemplate").Parse(spec.TmDashboardTemplate)
		if err != nil {
			fmt.Printf("Error parsing template: %s\n", err)
			return 1
		}

		f, err := os.Create(c.flagOutDir + "/dashboard.md")
		if err != nil {
			fmt.Printf("Error creating dashboard file: %s\n", err)
			return 1
		}
		defer f.Close()

		err = tmpl.Execute(f, tmList)
		if err != nil {
			fmt.Printf("Error writing to dashboard file: %s\n", err)
			return 1
		}

		fmt.Printf("Successfully wrote to '%s/dashboard.md'\n", c.flagOutDir)

	}

	return 0
}

func unixToTime(unixtime int64) string {
	utime := time.Unix(unixtime, 0)
	return utime.Format("2006-01-02")
}

func (c *DashboardCommand) Synopsis() string {
	return "Generate markdown files from existing HCL threatmodel file(s)"
}
