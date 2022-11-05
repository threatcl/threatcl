package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"

	shellquote "github.com/kballard/go-shellquote"
	"github.com/xntrik/hcltm/pkg/spec"
)

const (
	InteractiveEditorDraft = `spec_version = "0.1.3"

threatmodel "threatmodel_name" {
  description = "Describe your threat model. Refer to https://github.com/xntrik/hcltm/blob/main/spec.hcl for the full spec"

  author = "your_name"

  usecase {
    description = "Use cases here"
  }

  threat {
    description = "Something bad here"
    impacts = ["Confidentiality"]
    control = "Something to help"
  }
}
`
)

type GenerateInteractiveEditorCommand struct {
	*GlobalCmdOptions
	specCfg             *spec.ThreatmodelSpecConfig
	flagOut             string
	flagFullBoilerplate bool
	flagValidate        bool
}

func (c *GenerateInteractiveEditorCommand) Help() string {
	helpText := `
Usage: hcltm generate interactive editor [options]

  Prepares a skeleton threatmodel using your system's $EDITOR.

Options:

 -config=<file>
   Optional config file

 -out=<file>
   Path on the local disk to write the HCL file to. If not set (default), the
   HCL output will be written to STDOUT

 -fullboilerplate
   Populate the skeleton threatmodel with the full boilerplate

 -validate
   Perform validation of the file after it's created. Will still write the
   file, but will output error messages to STDERR and return error codes.

`

	return strings.TrimSpace(helpText)
}

func (c *GenerateInteractiveEditorCommand) Run(args []string) int {

	flagSet := c.GetFlagset("generate interactive editor")
	flagSet.StringVar(&c.flagOut, "out", "", "Where to output HCL file (if empty, write to STDOUT)")
	flagSet.BoolVar(&c.flagFullBoilerplate, "fullboilerplate", false, "Use the full boilerplate")
	flagSet.BoolVar(&c.flagValidate, "validate", false, "Validate the output HCL")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return 1
		}
	}

	var f *os.File // This is used for the final output

	// Setup the shells editor
	editor := "vim"
	if runtime.GOOS == "windows" {
		editor = "notepad"
	}
	if visual := os.Getenv("VISUAL"); visual != "" {
		editor = visual
	} else if osEditor := os.Getenv("EDITOR"); osEditor != "" {
		editor = osEditor
	}

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

	tmpfile, err := ioutil.TempFile("", "tmp.*.hcl")
	if err != nil {
		fmt.Printf("Error creating temp file: %s\n", err)
		return 1
	}
	defer os.Remove(tmpfile.Name())

	if c.flagFullBoilerplate {
		outString, err := parseBoilerplateTemplate(c.specCfg)
		if err != nil {
			fmt.Printf("Error preparing boilerplate: %s\n", err)
			return 1
		}
		_, err = tmpfile.WriteString(outString)
	} else {
		_, err = tmpfile.WriteString(InteractiveEditorDraft)
	}
	if err != nil {
		fmt.Printf("Error writing to tempfile: %s\n", err)
		return 1
	}

	err = tmpfile.Close()
	if err != nil {
		fmt.Printf("Error closing temp file: %s\n", err)
		return 1
	}

	cmdargs, err := shellquote.Split(editor)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	cmdargs = append(cmdargs, tmpfile.Name())

	cmd := exec.Command(cmdargs[0], cmdargs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error running command: %s\n", err)
		return 1
	}

	tmpIn, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		fmt.Printf("Error reading tmp file back in: %s\n", err)
		return 1
	}

	if c.flagOut == "" {
		fmt.Printf("%s\n", string(tmpIn))
	} else {
		_, err := f.WriteString(string(tmpIn))
		if err != nil {
			fmt.Printf("Error writing to the target file: %s\n", err)
			return 1
		}
		fmt.Printf("Successfully wrote to '%s'\n", c.flagOut)
	}

	if c.flagValidate {
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err = tmParser.ParseHCLRaw(tmpIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error validating TM: %s\n", err)
			return 1
		}
	}

	return 0
}

func (c *GenerateInteractiveEditorCommand) Synopsis() string {
	return "Interactively generate a HCL threatmodel using your $EDITOR"
}
