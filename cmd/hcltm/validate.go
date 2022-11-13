package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xntrik/hcltm/pkg/spec"
)

type ValidateCommand struct {
	*GlobalCmdOptions
	specCfg       *spec.ThreatmodelSpecConfig
	flagStdin     bool
	flagStdinJson bool
}

func (c *ValidateCommand) Help() string {
	helpText := `
Usage: hcltm validate <files>

  Validate HCL files (as specified by <files>)

Options:

 -config=<file>
   Optional config file

 -stdin
   If set, will expect a HCL file to be piped in

 -stdinjson
   If set, will expect a JSON file to be piped in

`
	return strings.TrimSpace(helpText)
}

func (c *ValidateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("validate")
	flagSet.BoolVar(&c.flagStdin, "stdin", false, "If set, will expect a HCL file to be piped in")
	flagSet.BoolVar(&c.flagStdinJson, "stdinjson", false, "If set, will expect a JSON file to be piped in")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	if c.flagStdin && c.flagStdinJson {
		fmt.Printf("You can't -stdin and -stdinjson at the same time\n")
		return 1
	}

	if c.flagStdin || c.flagStdinJson {
		// Try and parse STDIN
		info, err := os.Stdin.Stat()
		if err != nil {
			fmt.Printf("Error parsing STDIN: %s\n", err)
			return 1
		}

		if info.Mode()&os.ModeCharDevice != 0 || info.Size() <= 0 {
			fmt.Printf("Trying to parse STDIN but didn't receive any data\n")
			return 1
		}

		reader := bufio.NewReader(os.Stdin)
		var output []rune
		for {
			input, _, err := reader.ReadRune()
			if err != nil && err == io.EOF {
				break
			}
			output = append(output, input)
		}

		in := []byte(string(output))

		tmParser := spec.NewThreatmodelParser(c.specCfg)
		if c.flagStdin {
			err = tmParser.ParseHCLRaw(in)
		} else {
			err = tmParser.ParseJSONRaw(in)
		}

		if err != nil {
			if c.flagStdin {
				fmt.Printf("Error parsing HCL stdin: %s\n", err)
			} else {
				fmt.Printf("Error parsing JSON stdin: %s\n", err)
			}
			return 1
		}

		// Constraint check
		_, err = spec.VersionConstraints(tmParser.GetWrapped(), true)
		if err != nil {
			fmt.Printf("Error checking constraints: %s\n", err)
			return 1
		}

		tmCount := len(tmParser.GetWrapped().Threatmodels)

		fmt.Printf("Validated %d threatmodels\n", tmCount)

		return 0
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide <files> or -stdin or -stdinjson\n")
		return 1
	} else {

		AllFiles := findAllFiles(args)

		fileCount := 0
		tmCount := 0

		for _, file := range AllFiles {
			tmParser := spec.NewThreatmodelParser(c.specCfg)
			err := tmParser.ParseFile(file, false)
			if err != nil {
				fmt.Printf("Error parsing %s: %s\n", file, err)
				return 1
			}

			// Constraint check
			constraintMsg, err := spec.VersionConstraints(tmParser.GetWrapped(), false)
			if err != nil {
				fmt.Printf("Error checking constraints: %s\n", err)
				return 1
			}

			if constraintMsg != "" {
				fmt.Printf("%s Found in %s\n", constraintMsg, file)
			}

			fileCount = fileCount + 1
			tmCount = tmCount + len(tmParser.GetWrapped().Threatmodels)
		}

		fmt.Printf("Validated %d threatmodels in %d files\n", tmCount, fileCount)

	}

	return 0
}

func (c *ValidateCommand) Synopsis() string {
	return "Validate existing HCL Threatmodel file(s)"
}
