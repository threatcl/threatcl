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

	// base returns a CloudCommandBase wired with the shared global options.
	// Used by every cloud subcommand to avoid repeating the struct literal.
	base := func() CloudCommandBase {
		return CloudCommandBase{GlobalCmdOptions: globalCmdOptions}
	}

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
		"mermaid": func() (cli.Command, error) {
			return &MermaidCommand{
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
		"lsp": func() (cli.Command, error) {
			return &LSPCommand{
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

		// Cloud commands. Parent/grouping commands carry no shared state;
		// leaf commands embed base() and optionally the spec config.
		"cloud": func() (cli.Command, error) {
			return &CloudCommand{}, nil
		},
		"cloud login": func() (cli.Command, error) {
			return &CloudLoginCommand{CloudCommandBase: base()}, nil
		},
		"cloud logout": func() (cli.Command, error) {
			return &CloudLogoutCommand{CloudCommandBase: base()}, nil
		},
		"cloud token": func() (cli.Command, error) {
			return &CloudTokenCommand{}, nil
		},
		"cloud token list": func() (cli.Command, error) {
			return &CloudTokenListCommand{CloudCommandBase: base()}, nil
		},
		"cloud token add": func() (cli.Command, error) {
			return &CloudTokenAddCommand{CloudCommandBase: base()}, nil
		},
		"cloud token remove": func() (cli.Command, error) {
			return &CloudTokenRemoveCommand{CloudCommandBase: base()}, nil
		},
		"cloud token default": func() (cli.Command, error) {
			return &CloudTokenDefaultCommand{CloudCommandBase: base()}, nil
		},
		"cloud whoami": func() (cli.Command, error) {
			return &CloudWhoamiCommand{CloudCommandBase: base()}, nil
		},
		"cloud threatmodels": func() (cli.Command, error) {
			return &CloudThreatmodelsCommand{CloudCommandBase: base()}, nil
		},
		"cloud threatmodel": func() (cli.Command, error) {
			return &CloudThreatmodelCommand{CloudCommandBase: base()}, nil
		},
		"cloud threatmodel versions": func() (cli.Command, error) {
			return &CloudThreatmodelVersionsCommand{CloudCommandBase: base()}, nil
		},
		"cloud threatmodel delete": func() (cli.Command, error) {
			return &CloudThreatmodelDeleteCommand{CloudCommandBase: base()}, nil
		},
		"cloud threatmodel update-status": func() (cli.Command, error) {
			return &CloudThreatmodelUpdateStatusCommand{CloudCommandBase: base()}, nil
		},
		"cloud export": func() (cli.Command, error) {
			return &CloudExportCommand{CloudCommandBase: base(), specCfg: cfg}, nil
		},
		"cloud upload": func() (cli.Command, error) {
			return &CloudUploadCommand{CloudCommandBase: base(), specCfg: cfg}, nil
		},
		"cloud create": func() (cli.Command, error) {
			return &CloudCreateCommand{CloudCommandBase: base(), specCfg: cfg}, nil
		},
		"cloud search": func() (cli.Command, error) {
			return &CloudSearchCommand{CloudCommandBase: base()}, nil
		},
		"cloud validate": func() (cli.Command, error) {
			return &CloudValidateCommand{CloudCommandBase: base(), specCfg: cfg}, nil
		},
		"cloud push": func() (cli.Command, error) {
			return &CloudPushCommand{CloudCommandBase: base(), specCfg: cfg}, nil
		},
		"cloud view": func() (cli.Command, error) {
			return &CloudViewCommand{CloudCommandBase: base(), specCfg: cfg}, nil
		},
		"cloud library": func() (cli.Command, error) {
			return &CloudLibraryCommand{}, nil
		},
		"cloud library folders": func() (cli.Command, error) {
			return &CloudLibraryFoldersCommand{CloudCommandBase: base()}, nil
		},
		"cloud library folder": func() (cli.Command, error) {
			return &CloudLibraryFolderCommand{CloudCommandBase: base()}, nil
		},
		"cloud library threats": func() (cli.Command, error) {
			return &CloudLibraryThreatsCommand{CloudCommandBase: base()}, nil
		},
		"cloud library threat": func() (cli.Command, error) {
			return &CloudLibraryThreatCommand{CloudCommandBase: base()}, nil
		},
		"cloud library threat-ref": func() (cli.Command, error) {
			return &CloudLibraryThreatRefCommand{CloudCommandBase: base()}, nil
		},
		"cloud library controls": func() (cli.Command, error) {
			return &CloudLibraryControlsCommand{CloudCommandBase: base()}, nil
		},
		"cloud library control": func() (cli.Command, error) {
			return &CloudLibraryControlCommand{CloudCommandBase: base()}, nil
		},
		"cloud library control-ref": func() (cli.Command, error) {
			return &CloudLibraryControlRefCommand{CloudCommandBase: base()}, nil
		},
		"cloud library assets": func() (cli.Command, error) {
			return &CloudLibraryAssetsCommand{CloudCommandBase: base()}, nil
		},
		"cloud library asset": func() (cli.Command, error) {
			return &CloudLibraryAssetCommand{CloudCommandBase: base()}, nil
		},
		"cloud library asset-ref": func() (cli.Command, error) {
			return &CloudLibraryAssetRefCommand{CloudCommandBase: base()}, nil
		},
		"cloud library stats": func() (cli.Command, error) {
			return &CloudLibraryStatsCommand{CloudCommandBase: base()}, nil
		},
		"cloud library export": func() (cli.Command, error) {
			return &CloudLibraryExportCommand{CloudCommandBase: base()}, nil
		},
		"cloud library import": func() (cli.Command, error) {
			return &CloudLibraryImportCommand{CloudCommandBase: base()}, nil
		},
		"cloud policies": func() (cli.Command, error) {
			return &CloudPoliciesCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy": func() (cli.Command, error) {
			return &CloudPolicyCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy create": func() (cli.Command, error) {
			return &CloudPolicyCreateCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy update": func() (cli.Command, error) {
			return &CloudPolicyUpdateCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy delete": func() (cli.Command, error) {
			return &CloudPolicyDeleteCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy validate": func() (cli.Command, error) {
			return &CloudPolicyValidateCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy evaluate": func() (cli.Command, error) {
			return &CloudPolicyEvaluateCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy evaluations": func() (cli.Command, error) {
			return &CloudPolicyEvaluationsCommand{CloudCommandBase: base()}, nil
		},
		"cloud policy evaluation": func() (cli.Command, error) {
			return &CloudPolicyEvaluationCommand{CloudCommandBase: base()}, nil
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
