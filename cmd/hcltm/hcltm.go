package main

import (
	"fmt"

	"github.com/xntrik/hcltm/pkg/spec"
	"github.com/xntrik/hcltm/version"

	"github.com/mitchellh/cli"
)

func Run(args []string) int {

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		fmt.Printf("Can't parse the config file. Error message: %s\n", err)
		return 1
	}

	if cfg == nil {
		// Unsure how we'd get here
		fmt.Printf("Spec Config file was empty?\n")
		return 1
	}

	// initialize global command flag options
	globalCmdOptions := &GlobalCmdOptions{}

	// define all the commands
	Commands := map[string]cli.CommandFactory{
		"dashboard": func() (cli.Command, error) {
			return &DashboardCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"validate": func() (cli.Command, error) {
			return &ValidateCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"view": func() (cli.Command, error) {
			return &ViewCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"list": func() (cli.Command, error) {
			return &ListCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"generate": func() (cli.Command, error) {
			return &GenerateCommand{}, nil
		},
		"generate interactive": func() (cli.Command, error) {
			return &GenerateInteractiveCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"generate interactive editor": func() (cli.Command, error) {
			return &GenerateInteractiveEditorCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"generate boilerplate": func() (cli.Command, error) {
			return &GenerateBoilerplateCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"dfd": func() (cli.Command, error) {
			return &DfdCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
	}

	cli := &cli.CLI{
		Name:         "hcltm",
		Version:      version.GetVersion(),
		Args:         args,
		Commands:     Commands,
		Autocomplete: true,
	}

	exitCode, err := cli.Run()

	if err != nil {
		fmt.Printf("Error running cli: '%s'\n", err)
		return 1
	}

	return exitCode
}
