package main

import (
	"fmt"
	"strings"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
)

type MermaidCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagOutDir    string
	flagOutFile   string
	flagOverwrite bool
	flagStdout    bool
	flagIndex     int
}

func (c *MermaidCommand) Help() string {
	helpText := `
Usage: threatcl mermaid [options] <files>

  Output the raw mermaid source from 'mermaid' blocks in existing Threat
  model HCL files (as specified by <files>).

  Unlike the 'dfd' command, this does not render diagrams - it emits the
  verbatim mermaid content so it can be piped into other rendering tools
  (such as mmdc / mermaid-cli).

  By default the mermaid source is printed to STDOUT. If you provide -out
  or -outdir it is written to a file (or files) instead.

 -outdir=<directory>
   Directory to output files. Will create directory if it doesn't exist.
   One .mmd file is written per mermaid block.

 -out=<filename>
   Name of output file. Only a single mermaid block is written. If there
   are multiple, provide an -index=n flag to select one.

 -stdout
   Print the mermaid source to STDOUT. This is the default when neither
   -out nor -outdir is set.

 -index=<n>
   When there are multiple mermaid blocks and you're outputting to STDOUT
   or a single -out file, select which one (1-based).

Options:

 -config=<file>
   Optional config file

 -overwrite

`
	return strings.TrimSpace(helpText)
}

// mermaidEntry pairs a parsed mermaid diagram with its owning threat model
// name and source file, so we can build a stable, globally-indexed list.
type mermaidEntry struct {
	tmName  string
	diagram *spec.MermaidDiagram
	file    string
}

// collectMermaids parses every file and returns all mermaid blocks in the
// order they're discovered, along with the matching output file paths.
func (c *MermaidCommand) collectMermaids(allFiles []string) ([]mermaidEntry, []string, error) {
	entries := []mermaidEntry{}
	outfiles := []string{}

	for _, file := range allFiles {
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err := tmParser.ParseFile(file, false)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing %s: %s", file, err)
		}

		for _, tm := range tmParser.GetWrapped().Threatmodels {
			for _, m := range tm.MermaidDiagrams {
				entries = append(entries, mermaidEntry{
					tmName:  tm.Name,
					diagram: m,
					file:    file,
				})
				outfile := outfilePath(c.flagOutDir, fmt.Sprintf("%s_%s", tm.Name, m.Name), file, ".mmd")
				outfiles = append(outfiles, outfile)
			}
		}
	}

	return entries, outfiles, nil
}

// mermaidSource normalises a mermaid block's content to end with exactly one
// trailing newline, so output pipes cleanly into other tools.
func mermaidSource(content string) string {
	return strings.TrimRight(content, "\n") + "\n"
}

// printTooMany lists every discovered mermaid block so the user can pick one
// with -index.
func printTooMany(entries []mermaidEntry, destination string) {
	fmt.Printf("You're trying to %s, but there's too many mermaid diagrams\n\n", destination)
	fmt.Printf("Run the command again and provide an -index=n flag\n\n")
	for idx, e := range entries {
		fmt.Printf("%d: %s_%s\n", idx+1, e.tmName, e.diagram.Name)
	}
}

// writeMermaidFile writes a single mermaid block to path.
func (c *MermaidCommand) writeMermaidFile(path, content string) int {
	if err := writeStringToFile(path, mermaidSource(content)); err != nil {
		fmt.Printf("Error writing mermaid file to %s: %s\n", path, err)
		return 1
	}

	fmt.Printf("Successfully created '%s'\n", path)
	return 0
}

func (c *MermaidCommand) Run(args []string) int {

	flagSet := c.GetFlagset("mermaid")
	flagSet.StringVar(&c.flagOutDir, "outdir", "", "Directory to output files. Will create directory if it doesn't exist.")
	flagSet.StringVar(&c.flagOutFile, "out", "", "Name of output file.")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite existing files. Defaults to false")
	flagSet.BoolVar(&c.flagStdout, "stdout", false, "Print the mermaid source to stdout. Default when no -out or -outdir is set")
	flagSet.IntVar(&c.flagIndex, "index", 0, "index")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if c.flagOutDir != "" && c.flagOutFile != "" {
		fmt.Printf("You must set an -outdir or -out, but not both\n\n")
		fmt.Println(c.Help())
		return 1
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide file(s)\n\n")
		fmt.Println(c.Help())
		return 1
	}

	// stdout is the default destination when neither -out nor -outdir is set.
	toStdout := c.flagStdout || (c.flagOutDir == "" && c.flagOutFile == "")

	// Find all the .hcl/.json files we're going to parse
	AllFiles := findAllFiles(flagSet.Args())

	entries, outfiles, err := c.collectMermaids(AllFiles)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	if len(entries) == 0 {
		fmt.Printf("No mermaid diagrams found\n\n")
		return 1
	}

	switch {

	// Print mermaid source to Stdout
	case toStdout:
		switch {
		case len(entries) == 1:
			fmt.Print(mermaidSource(entries[0].diagram.Content))
			return 0
		case c.flagIndex == 0:
			printTooMany(entries, "print mermaid to Stdout")
			return 1
		case c.flagIndex < 1 || c.flagIndex > len(entries):
			fmt.Printf("Index provided is inaccurate\n")
			return 1
		default:
			fmt.Print(mermaidSource(entries[c.flagIndex-1].diagram.Content))
			return 0
		}

	// Output a single file
	case c.flagOutFile != "":
		err := fileExistenceCheck([]string{c.flagOutFile}, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		switch {
		case len(entries) == 1:
			return c.writeMermaidFile(c.flagOutFile, entries[0].diagram.Content)
		case c.flagIndex == 0:
			printTooMany(entries, "save a single file")
			return 1
		case c.flagIndex < 1 || c.flagIndex > len(entries):
			fmt.Printf("Index provided is inaccurate\n")
			return 1
		default:
			return c.writeMermaidFile(c.flagOutFile, entries[c.flagIndex-1].diagram.Content)
		}

	// Output a full directory
	case c.flagOutDir != "":
		err := fileExistenceCheck(outfiles, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		err = createOrValidateFolder(c.flagOutDir, c.flagOverwrite)
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		for idx, e := range entries {
			if rc := c.writeMermaidFile(outfiles[idx], e.diagram.Content); rc != 0 {
				return rc
			}
		}

		return 0

	default:
		fmt.Printf("An error has occurred\n")
		return 1
	}
}

func (c *MermaidCommand) Synopsis() string {
	return "Output raw mermaid source from 'mermaid' blocks in existing HCL threatmodel file(s)"
}

func (c *MermaidCommand) AutocompleteArgs() complete.Predictor { return predictHCLOrJSON }
func (c *MermaidCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config": predictHCL,
		"-outdir": complete.PredictDirs("*"),
	}
}
