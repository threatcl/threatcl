package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/invariants"
	"github.com/threatcl/threatcl/internal/tmloader"
)

type ValidateCommand struct {
	*GlobalCmdOptions
	specCfg        *spec.ThreatmodelSpecConfig
	flagStdin      bool
	flagStdinJson  bool
	flagInvariants string
}

func (c *ValidateCommand) Help() string {
	helpText := `
Usage: threatcl validate <files>

  Validate HCL files (as specified by <files>)

Options:

 -config=<file>
   Optional config file

 -invariants=<file>
   Optional HCL file of invariant blocks to evaluate against the validated
   threat models. Invariant violations of severity "error" fail validation.

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
	flagSet.StringVar(&c.flagInvariants, "invariants", "", "Optional HCL file of invariants to evaluate against the threat models")
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

	var invs []*invariants.Invariant
	if c.flagInvariants != "" {
		var err error
		invs, err = invariants.ParseFile(c.flagInvariants)
		if err != nil {
			fmt.Printf("Error parsing invariants file %s: %s\n", c.flagInvariants, err)
			return 1
		}
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

		if invs != nil {
			return c.runInvariants(invs, wrappedModels(tmParser.GetWrapped(), "STDIN"))
		}

		return 0
	}

	if len(flagSet.Args()) == 0 {
		fmt.Printf("Please provide <files> or -stdin or -stdinjson\n")
		return 1
	} else {

		// Parse all discovered files as one set so cross-file `extends`
		// resolves and model names/ids are unique across the whole set.
		res, err := tmloader.LoadSet(c.specCfg, flagSet.Args())
		if err != nil {
			fmt.Printf("%s\n", err)
			return 1
		}

		// Constraint check over each parsed source (the HCL set, then each
		// JSON file). The messages name the offending threat model.
		for _, w := range res.Wrapped {
			constraintMsg, err := spec.VersionConstraints(w, false)
			if err != nil {
				fmt.Printf("Error checking constraints: %s\n", err)
				return 1
			}

			if constraintMsg != "" {
				fmt.Printf("%s\n", constraintMsg)
			}
		}

		models := make([]*invariants.Model, 0, len(res.Models))
		for _, lm := range res.Models {
			models = append(models, &invariants.Model{TM: lm.TM, File: lm.File})
		}

		fmt.Printf("Validated %d threatmodels in %d files\n", len(res.Models), len(res.Files))

		if invs != nil {
			return c.runInvariants(invs, models)
		}

	}

	return 0
}

// wrappedModels pairs each threat model in a parsed file with its source, for
// invariant violation reporting.
func wrappedModels(wrapped *spec.ThreatmodelWrapped, source string) []*invariants.Model {
	models := make([]*invariants.Model, 0, len(wrapped.Threatmodels))
	for i := range wrapped.Threatmodels {
		models = append(models, &invariants.Model{
			TM:   &wrapped.Threatmodels[i],
			File: source,
		})
	}
	return models
}

// runInvariants evaluates invariants against the validated models and prints
// the outcome. Only error-severity violations make validation fail.
func (c *ValidateCommand) runInvariants(invs []*invariants.Invariant, models []*invariants.Model) int {
	report, err := invariants.Evaluate(invs, models)
	if err != nil {
		fmt.Printf("Error evaluating invariants: %s\n", err)
		return 1
	}

	for _, ex := range report.Exemptions {
		fmt.Printf("Invariant '%s' exempts threatmodel '%s' (%s): %s\n",
			ex.Invariant.Name, ex.Model.TM.Name, ex.Model.File, ex.Justification)
	}

	for _, v := range report.Violations {
		where := fmt.Sprintf("threatmodel '%s'", v.Model.TM.Name)
		if v.ItemKind != "threatmodel" {
			where = fmt.Sprintf("%s '%s' in %s", v.ItemKind, v.ItemName, where)
		}
		fmt.Printf("Invariant violation [%s] '%s': %s (%s): %s\n",
			v.Invariant.Severity, v.Invariant.Name, where, v.Model.File, v.Message)
	}

	errCount := report.ErrorCount()
	fmt.Printf("Checked %d invariants against %d threatmodels: %d errors, %d warnings, %d exemptions\n",
		report.Invariants, report.Models, errCount, report.WarningCount(), len(report.Exemptions))

	if errCount > 0 {
		return 1
	}
	return 0
}

func (c *ValidateCommand) Synopsis() string {
	return "Validate existing HCL Threatmodel file(s)"
}

func (c *ValidateCommand) AutocompleteArgs() complete.Predictor { return predictHCLOrJSON }
func (c *ValidateCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":     predictHCL,
		"-invariants": predictHCL,
	}
}
