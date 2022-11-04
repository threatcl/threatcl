package main

import (
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	HasDfd         string
}

// DashboardCommand struct defines the "hcltm dashboard" commands
type DashboardCommand struct {
	*GlobalCmdOptions
	specCfg                 *spec.ThreatmodelSpecConfig
	flagOutDir              string
	flagOutExt              string
	flagOverwrite           bool
	flagNoDfd               bool
	flagDashboardTemplate   string
	flagThreatmodelTemplate string
	flagDashboardFilename   string
	flagDashboardHTML       bool
}

// Help is the help output for "hcltm dashboard"
func (c *DashboardCommand) Help() string {
	helpText := `
Usage: hcltm dashboard [options] -outdir=<directory> <files>

  Generate markdown files from existing Threat model HCL files (as specified
  by <files>) 

 -outdir=<directory>
   Directory to output rendered files. Will create directory if it doesn't
   exist. Must be set

Options:

 -config=<file>
   Optional config file

 -overwrite

 -out-ext=<ext>
   Extension to use for files produced by the text templates.

 -nodfd

 -dashboard-template=<file>

 -dashboard-filename=<filename>

 -dashboard-html

 -threatmodel-template=<file>

`
	return strings.TrimSpace(helpText)
}

// Run executes "hcltm dashboard" logic
func (c *DashboardCommand) Run(args []string) int {

	flagSet := c.GetFlagset("dashboard")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output MD files. Will create directory if it doesn't exist. Must be set")
	flagSet.StringVar(&c.flagOutExt, "out-ext", "md", "Extension to use in filenames produced by the text templates.")
	flagSet.StringVar(&c.flagDashboardTemplate, "dashboard-template", "", "Template file to override the default dashboard index file")
	flagSet.StringVar(&c.flagDashboardFilename, "dashboard-filename", "dashboard", "Instead of writing dashboard.md, write to <filename>.md")
	flagSet.StringVar(&c.flagThreatmodelTemplate, "threatmodel-template", "", "Template file to override the default threatmodel.md file(s)")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files in the outdir. Defaults to false")
	flagSet.BoolVar(&c.flagNoDfd, "nodfd", false, "Do not include generated DFD images. Defaults to false")
	flagSet.BoolVar(&c.flagDashboardHTML, "dashboard-html", false, "Render as HTML instead of text. Implies --out-ext=html.")
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

	err := validateFilename(c.flagDashboardFilename)
	if err != nil {
		fmt.Printf("Error with -dashboard-filename: %s\n", err)
		return 1
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide file(s)\n\n")
		fmt.Println(c.Help())
		return 1
	}

	outExt := c.flagOutExt
	if c.flagDashboardHTML {
		outExt = "html"
	}

	// Parse the dashboard-index template first before creating folders

	dashboardTemplate := ""

	if c.flagDashboardTemplate != "" {
		// User has specified a replacement dashboard file
		info, err := os.Stat(c.flagDashboardTemplate)
		if os.IsNotExist(err) {
			fmt.Printf("Could not find dashboard-template file. '%s'", c.flagDashboardTemplate)
			return 1
		}

		if info.IsDir() {
			fmt.Printf("dashboard-template can't be set to a directory. '%s'", c.flagDashboardTemplate)
			return 1
		}

		readTemplate, err := ioutil.ReadFile(c.flagDashboardTemplate)
		if err != nil {
			fmt.Printf("Error opening dashboard template file: %s\n", err)
			return 1
		}

		dashboardTemplate = string(readTemplate)
	} else {
		dashboardTemplate = spec.TmDashboardTemplate
	}

	dashboardTemplateParsed, err := template.New("DashboardTemplate").Parse(dashboardTemplate)
	if err != nil {
		fmt.Printf("Error parsing template: %s\n", err)
		return 1
	}

	// Parse the threatmodel.md template second before creating folders

	tmTemplate := ""

	if c.flagThreatmodelTemplate != "" {
		// User has specified a replacement threatmodel file
		info, err := os.Stat(c.flagThreatmodelTemplate)
		if os.IsNotExist(err) {
			fmt.Printf("Could not find threatmodel-template file. '%s'", c.flagThreatmodelTemplate)
			return 1
		}

		if info.IsDir() {
			fmt.Printf("threatmodel-template can't be set to a directory. '%s'", c.flagThreatmodelTemplate)
			return 1
		}

		readTemplate, err := ioutil.ReadFile(c.flagThreatmodelTemplate)
		if err != nil {
			fmt.Printf("Error opening threatmodel template file: %s\n", err)
			return 1
		}

		tmTemplate = string(readTemplate)
	} else {
		tmTemplate = spec.TmMDTemplate
	}

	_, err = spec.ParseTMTemplate(tmTemplate)
	if err != nil {
		fmt.Printf("Error parsing template: %s\n", err)
		return 1
	}

	err = createOrValidateFolder(c.flagOutDir, c.flagOverwrite)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}
	fmt.Printf("Created the '%s' directory\n", c.flagOutDir)

	// We use outfiles to generate a list of output files to validate whether
	// we're overwriting them or not.
	outfiles := []string{
		fmt.Sprintf("%s/%s.%s", c.flagOutDir, c.flagDashboardFilename, outExt),
	}

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
			outfile := outfilePath(c.flagOutDir, tm.Name, file, fmt.Sprintf(".%s", outExt))

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

	for _, file := range AllFiles {
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err := tmParser.ParseFile(file, false)
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

			// tmBuffer, err := tm.RenderMarkdown(spec.TmMDTemplate)
			tmBuffer, err := tm.RenderMarkdown(tmTemplate)
			if err != nil {
				fmt.Println(err)
				return 1
			}

			outfile := outfilePath(c.flagOutDir, tm.Name, file, fmt.Sprintf(".%s", outExt))

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

			// Now we add it to the dashboard-index tmList

			tmListEntry := tmListEntryType{
				Name:           tm.Name,
				File:           filepath.Base(outfile),
				Hover:          "",
				Author:         tm.Author,
				NewInitiative:  "-",
				InternetFacing: "-",
				Size:           "-",
				HasDfd:         "-",
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

			if tm.DataFlowDiagram != nil {
				tmListEntry.HasDfd = "Yes"
			}

			tmList = append(tmList, tmListEntry)
		}
	}

	sort.Slice(tmList, func(i, j int) bool {
		return tmList[i].Name < tmList[j].Name
	})

	// Now we create the dashboard-index file

	f, err := os.Create(c.flagOutDir + fmt.Sprintf("/%s.%s", c.flagDashboardFilename, outExt))
	if err != nil {
		fmt.Printf("Error creating dashboard file: %s\n", err)
		return 1
	}
	defer f.Close()

	err = dashboardTemplateParsed.Execute(f, tmList)
	if err != nil {
		fmt.Printf("Error writing to dashboard file: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully wrote to '%s/%s.%s'\n", c.flagOutDir, c.flagDashboardFilename, outExt)

	return 0
}

func unixToTime(unixtime int64) string {
	utime := time.Unix(unixtime, 0)
	return utime.Format("2006-01-02")
}

// Synopsis returns the synopsis for the "hcltm dashboard" command
func (c *DashboardCommand) Synopsis() string {
	return "Generate markdown files from existing HCL threatmodel file(s)"
}
