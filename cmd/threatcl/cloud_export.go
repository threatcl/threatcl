package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/posener/complete"
	"github.com/threatcl/spec"
)

type CloudExportCommand struct {
	CloudCommandBase
	specCfg                *spec.ThreatmodelSpecConfig
	flagOrgId              string
	flagModelId            string
	flagFormat             string
	flagOutput             string
	flagTemplate           string
	flagOverwrite          bool
	flagKeepBackend        bool
	flagIncludeRecommended bool
}

func (c *CloudExportCommand) Help() string {
	helpText := `
Usage: threatcl cloud export -model-id=<modelId_or_slug> [options]

  Export a threat model from ThreatCL Cloud, resolving every library
  reference (threats, controls, and information assets) into a
  fully-hydrated artifact.

  Unlike 'threatcl cloud threatmodel -download', which writes the raw
  HCL stored in the cloud, this command fetches each referenced
  threat/control/information-asset from the cloud library and inlines
  its description, STRIDE, impacts, implementation guidance, risk
  reduction, information classification, and source before rendering.
  The result is a standalone, portable artifact suitable for sharing
  with reviewers who cannot reach the cloud library.

Options:

 -model-id=<modelId_or_slug>
   Required. The threat model ID or slug to export.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses THREATCL_CLOUD_ORG
   env var or the default organization from your token store.

 -format=<json|otm|hcl|md>
   Output format. Defaults to json.

 -output=<file>
   Optional filename to write to. If not set, output is written to STDOUT.

 -template=<file>
   Optional overridden template file to use for md output.

 -overwrite
   When -output is set, overwrite the file if it already exists.

 -keep-backend
   Preserve the 'backend "threatcl-cloud"' block in the exported output.
   By default the backend block is stripped so the export is portable.

 -include-recommended
   Pull each referenced threat's library-recommended controls into the
   exported model. Off by default.

 -config=<file>
   Optional config file.
` + cloudEnvVarHelp()
	return strings.TrimSpace(helpText)
}

func (c *CloudExportCommand) Synopsis() string {
	return "Export a cloud threat model with library refs resolved"
}

func (c *CloudExportCommand) AutocompleteFlags() complete.Flags {
	return complete.Flags{
		"-config":   predictHCL,
		"-format":   complete.PredictSet("json", "otm", "hcl", "md"),
		"-output":   complete.PredictFiles("*"),
		"-template": predictTpl,
	}
}

func (c *CloudExportCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud export")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagModelId, "model-id", "", "Threat model ID or slug (required)")
	flagSet.StringVar(&c.flagFormat, "format", "json", "Output format: json, otm, hcl, md")
	flagSet.StringVar(&c.flagOutput, "output", "", "Output file (default: STDOUT)")
	flagSet.StringVar(&c.flagTemplate, "template", "", "Optional template file for md output")
	flagSet.BoolVar(&c.flagOverwrite, "overwrite", false, "Overwrite the output file if it exists")
	flagSet.BoolVar(&c.flagKeepBackend, "keep-backend", false, "Preserve the backend block in output")
	flagSet.BoolVar(&c.flagIncludeRecommended, "include-recommended", false, "Include library-recommended controls")
	flagSet.Parse(args)

	if c.flagModelId == "" {
		fmt.Fprintf(os.Stderr, "Error: -model-id is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud export -help' for usage information.\n")
		return 1
	}

	if c.flagConfig != "" {
		if err := c.specCfg.LoadSpecConfigFile(c.flagConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %s\n", err)
			return 1
		}
	}

	client, _, err := c.newCloudClient(c.flagOrgId, 30*time.Second)
	if err != nil {
		return c.handleTokenError(err)
	}

	if _, err := client.FetchThreatModel(c.flagModelId); err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching threat model: %s\n", err)
		return 1
	}

	// Check the output file before doing any network work for the heavy parts.
	if c.flagOutput != "" {
		if err := fileExistenceCheck([]string{c.flagOutput}, c.flagOverwrite); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return 1
		}
	}

	hclBytes, err := client.DownloadContent(client.DownloadModelURL(c.flagModelId))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading threat model file: %s\n", err)
		return 1
	}

	// Inject empty descriptions for ref-only threats/controls so the spec
	// parser will accept the file. Local descriptions, if any, are preserved.
	processed := preprocessHCLForControls(hclBytes)
	processed = preprocessHCLForThreats(processed)
	// This HCL was downloaded from the cloud; strip remote-fetch directives so
	// parsing it cannot drive go-getter requests from this machine (SSRF/LFI).
	processed = stripRemoteFetchDirectives(processed)

	tmpDir, err := os.MkdirTemp("", "threatcl-cloud-export-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temporary directory: %s\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	tmpFilePath := filepath.Join(tmpDir, c.flagModelId+".hcl")
	if err := os.WriteFile(tmpFilePath, processed, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing temporary file: %s\n", err)
		return 1
	}

	// The fetched content may be a single segment of a multi-file model whose
	// extends target lives in another segment; parse file-faithfully so an
	// unresolved extends is not an error.
	tmParser := spec.NewThreatmodelParser(c.specCfg)
	tmParser.SetSkipExtendsResolution(true)
	if err := tmParser.ParseFile(tmpFilePath, false); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing threat model: %s\n", err)
		return 1
	}

	wrapped := tmParser.GetWrapped()

	threatRefs := extractThreatRefs(wrapped)
	threatItems := map[string]*threatLibraryItem{}
	if len(threatRefs) > 0 {
		fetched, err := client.FetchThreatLibraryItemsByRefs(threatRefs, c.flagIncludeRecommended)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving threat library refs: %s\n", err)
			return 1
		}
		for _, item := range fetched {
			if item != nil {
				threatItems[item.ReferenceID] = item
			}
		}
		var missing []string
		for _, ref := range threatRefs {
			if threatItems[ref] == nil {
				missing = append(missing, ref)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: unresolved threat refs: %s\n", strings.Join(missing, ", "))
		}
	}

	controlRefs := extractControlRefs(wrapped)
	controlItems := map[string]*controlLibraryItem{}
	if len(controlRefs) > 0 {
		fetched, err := client.FetchControlLibraryItemsByRefs(controlRefs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving control library refs: %s\n", err)
			return 1
		}
		for _, item := range fetched {
			if item != nil {
				controlItems[item.ReferenceID] = item
			}
		}
		var missing []string
		for _, ref := range controlRefs {
			if controlItems[ref] == nil {
				missing = append(missing, ref)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: unresolved control refs: %s\n", strings.Join(missing, ", "))
		}
	}

	assetRefs := extractInformationAssetRefs(wrapped)
	assetItems := map[string]*informationAssetLibraryItem{}
	if len(assetRefs) > 0 {
		fetched, err := client.FetchInformationAssetLibraryItemsByRefs(assetRefs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving information asset library refs: %s\n", err)
			return 1
		}
		for _, item := range fetched {
			if item != nil {
				assetItems[item.ReferenceID] = item
			}
		}
		var missing []string
		for _, ref := range assetRefs {
			if assetItems[ref] == nil {
				missing = append(missing, ref)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: unresolved information asset refs: %s\n", strings.Join(missing, ", "))
		}
	}

	hydrateLibraryRefs(wrapped, threatItems, controlItems, assetItems, c.flagIncludeRecommended)

	if !c.flagKeepBackend {
		wrapped.Backends = nil
	}

	outputString, err := renderThreatmodels(wrapped.Threatmodels, tmParser, c.flagFormat, c.flagTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	if c.flagOutput == "" {
		fmt.Printf("%s\n", outputString)
		return 0
	}

	f, err := os.Create(c.flagOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file %s: %s\n", c.flagOutput, err)
		return 1
	}
	defer f.Close()

	if _, err := f.WriteString(outputString); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output to %s: %s\n", c.flagOutput, err)
		return 1
	}

	fmt.Printf("Successfully wrote '%s'\n", c.flagOutput)
	return 0
}
