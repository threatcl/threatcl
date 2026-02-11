package main

import (
	"fmt"

	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/version"

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
		"mcp": func() (cli.Command, error) {
			return &MCPCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"terraform": func() (cli.Command, error) {
			return &TerraformCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"export": func() (cli.Command, error) {
			return &ExportCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"server": func() (cli.Command, error) {
			return &ServerCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"query": func() (cli.Command, error) {
			return &QueryCommand{
				GlobalCmdOptions: globalCmdOptions,
				specCfg:          cfg,
			}, nil
		},
		"cloud": func() (cli.Command, error) {
			return &CloudCommand{}, nil
		},
		"cloud login": func() (cli.Command, error) {
			return &CloudLoginCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud logout": func() (cli.Command, error) {
			return &CloudLogoutCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud token": func() (cli.Command, error) {
			return &CloudTokenCommand{}, nil
		},
		"cloud token list": func() (cli.Command, error) {
			return &CloudTokenListCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud token add": func() (cli.Command, error) {
			return &CloudTokenAddCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud token remove": func() (cli.Command, error) {
			return &CloudTokenRemoveCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud token default": func() (cli.Command, error) {
			return &CloudTokenDefaultCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud whoami": func() (cli.Command, error) {
			return &CloudWhoamiCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud threatmodels": func() (cli.Command, error) {
			return &CloudThreatmodelsCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud threatmodel": func() (cli.Command, error) {
			return &CloudThreatmodelCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud threatmodel versions": func() (cli.Command, error) {
			return &CloudThreatmodelVersionsCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud threatmodel delete": func() (cli.Command, error) {
			return &CloudThreatmodelDeleteCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud threatmodel update-status": func() (cli.Command, error) {
			return &CloudThreatmodelUpdateStatusCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud upload": func() (cli.Command, error) {
			return &CloudUploadCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
				specCfg: cfg,
			}, nil
		},
		"cloud create": func() (cli.Command, error) {
			return &CloudCreateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
				specCfg: cfg,
			}, nil
		},
		"cloud search": func() (cli.Command, error) {
			return &CloudSearchCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud validate": func() (cli.Command, error) {
			return &CloudValidateCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
				specCfg: cfg,
			}, nil
		},
		"cloud push": func() (cli.Command, error) {
			return &CloudPushCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
				specCfg: cfg,
			}, nil
		},
		"cloud view": func() (cli.Command, error) {
			return &CloudViewCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
				specCfg: cfg,
			}, nil
		},
		"cloud library": func() (cli.Command, error) {
			return &CloudLibraryCommand{}, nil
		},
		"cloud library folders": func() (cli.Command, error) {
			return &CloudLibraryFoldersCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library folder": func() (cli.Command, error) {
			return &CloudLibraryFolderCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library threats": func() (cli.Command, error) {
			return &CloudLibraryThreatsCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library threat": func() (cli.Command, error) {
			return &CloudLibraryThreatCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library threat-ref": func() (cli.Command, error) {
			return &CloudLibraryThreatRefCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library controls": func() (cli.Command, error) {
			return &CloudLibraryControlsCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library control": func() (cli.Command, error) {
			return &CloudLibraryControlCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library control-ref": func() (cli.Command, error) {
			return &CloudLibraryControlRefCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library stats": func() (cli.Command, error) {
			return &CloudLibraryStatsCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library export": func() (cli.Command, error) {
			return &CloudLibraryExportCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
		"cloud library import": func() (cli.Command, error) {
			return &CloudLibraryImportCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: globalCmdOptions,
				},
			}, nil
		},
	}

	cli := &cli.CLI{
		Name:         "threatcl",
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
