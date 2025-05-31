package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/threatcl/spec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type MCPCommand struct {
	*GlobalCmdOptions
	specCfg *spec.ThreatmodelSpecConfig
	flagDir string
}

func (c *MCPCommand) Help() string {
	helpText := `
Usage: threatcl mcp [options]

  Model Context Protocol (MCP) server for threatcl

  The MCP server will use the provided directory as the root for searching
  and manipulating HCL threatcl files.

Options:

 -config=<file>
   Optional config file

 -dir=<path>
   Directory path to use as root for searching and manipulating HCL files

`
	return strings.TrimSpace(helpText)
}

func (c *MCPCommand) Run(args []string) int {
	flagSet := c.GetFlagset("mcp")
	flagSet.StringVar(&c.flagDir, "dir", "", "Directory path to use as root for searching and manipulating HCL files")
	flagSet.Parse(args)

	if c.flagConfig != "" {
		err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
		if err != nil {
			c.errPrint(fmt.Sprintf("Error: %s\n", err))
			return 1
		}
	}

	// Initialize MCP server
	mcpserver := server.NewMCPServer(
		"threatlcl-mcp",
		"0.0.1",
		// server.WithResourceCapabilities(true, true),
	)

	// Add tools that don't depend on flagDir
	mcpserver.AddResource(mcp.NewResource("threatcl://static/spec",
		"Threatcl HCL Specificiation",
		mcp.WithMIMEType("text/plain"),
	), c.handleShowSpecResource)

	mcpserver.AddTool(mcp.NewTool(
		"view_threatcl_hcl_spec_resource",
		mcp.WithDescription("View the raw hcl contents of the threatcl specification, with an embedded resource. Some MCP Clients may not support embedded resources, in which case use the view_threatcl_hcl_spec tool instead."),
	), c.handleViewSpecToolResource)

	mcpserver.AddTool(mcp.NewTool(
		"view_threatcl_hcl_spec",
		mcp.WithDescription("View the raw hcl contents of the threatcl specification, this will return it as a text string, not an embedded resource."),
	), c.handleViewSpecTool)

	mcpserver.AddTool(mcp.NewTool(
		"validate_tm_string",
		mcp.WithDescription("Validate a threatcl threat model by providing the raw hcl string"),
		mcp.WithString("hcl",
			mcp.Description("The threatcl string to validate"),
		),
	), c.handleValidateTmString)

	mcpserver.AddTool(mcp.NewTool(
		"view_tm_string",
		mcp.WithDescription("View the markdown of a threatcl threat model by providing the raw hcl string"),
		mcp.WithString("hcl",
			mcp.Description("The threatcl string to view"),
		),
	), c.handleViewTmString)

	mcpserver.AddTool(mcp.NewTool(
		"view_dfd_png_from_tm_string",
		mcp.WithDescription("View the png of a specific data flow diagram of a threatcl threat model by providing the raw hcl string"),
		mcp.WithString("hcl",
			mcp.Description("The threatcl string, including the data flow diagram, to then render the png of"),
		),
	), c.handlePngDfdViewFromTmString)

	// Only add directory-dependent tools if flagDir is set
	if c.flagDir != "" {
		absPath, err := c.validatePath(c.flagDir)
		if err != nil {
			c.errPrint(fmt.Sprintf("Error: %s\n", err))
			return 1
		}

		c.errPrint(fmt.Sprintf("Threatcl MCP server started - using directory: %s\n", absPath))

		mcpserver.AddTool(mcp.NewTool(
			"list_all_tms",
			mcp.WithDescription("Get a listing of all the threatcl threat models, and their files, located within the directory set by the -dir flag"),
		), c.handleListTms)

		mcpserver.AddTool(mcp.NewTool(
			"list_all_tms_with_cols",
			mcp.WithDescription("Get a detailed listing of all the threatcl threat models, and their files, located within the directory set by the -dir flag. This tool allows you to specify what columns are displayed, for instance: file, author, threatmodel, threatcount, internetfacing."),
			mcp.WithString("columns",
				mcp.Description("The columns you want to list against each threat model. Is expected to be a comma-separated list of values from this set: number, threatmodel, author, file, threatcount, internetfacing, assetcount, usecasecount, tpdcount, exclusioncount, size, newinitiative, dfd."),
			),
		), c.handleListTmsWithCustomCols)

		mcpserver.AddTool(mcp.NewTool(
			"view_tm",
			mcp.WithDescription("View the markdown of a threatcl threat model file, located within the directory set by the -dir flag. This tool requires you provide the threatcl file."),
			mcp.WithString("file",
				mcp.Description("The threatcl file to view"),
			),
		), c.handleViewTmFile)

		mcpserver.AddTool(mcp.NewTool(
			"view_tm_hcl",
			mcp.WithDescription("View the raw hcl contents of a threatcl threat model file, located within the directory set by the -dir flag. This tool requires you provide the threatcl file."),
			mcp.WithString("file",
				mcp.Description("The threatcl file to view the raw version of"),
			),
		), c.handleViewTmFileRaw)

		mcpserver.AddTool(mcp.NewTool(
			"validate_tm_file",
			mcp.WithDescription("Validate a threatcl threat model file, located within the directory set by the -dir flag"),
			mcp.WithString("file",
				mcp.Description("The threatcl file to validate"),
			),
		), c.handleValidateTmFile)

		mcpserver.AddTool(mcp.NewTool(
			"write_tm_file",
			mcp.WithDescription("Write a threatcl threat model to a file, located within the directory set by the -dir flag. If you want to write to a different location, you should leverage other MCP tools."),
			mcp.WithString("filename",
				mcp.Description("The filename to write the threatcl threat model to"),
			),
			mcp.WithString("hcl",
				mcp.Description("The threatcl string to write to the file"),
			),
			mcp.WithString("format",
				mcp.Description("The format to write the file in. Options are 'hcl' (default) or 'otm'"),
			),
		), c.handleWriteTmFile)

		mcpserver.AddTool(mcp.NewTool(
			"write_dfd_png_file",
			mcp.WithDescription("Write a DFD PNG to a file, located within the directory set by the -dir flag. If you want to write to a different location, you should leverage other MCP tools."),
			mcp.WithString("filename",
				mcp.Description("The filename to write the DFD PNG to"),
			),
			mcp.WithString("hcl",
				mcp.Description("The threatcl string to write to the file"),
			),
		), c.handleWriteDfdPngFile)
	} else {
		c.errPrint("Threatcl MCP server started - no directory specified. Only non-filesystem tools are available.\n")
	}

	if err := server.ServeStdio(mcpserver); err != nil {
		c.errPrint(fmt.Sprintf("Server error: %v\n", err))
	}

	return 0
}

func (c *MCPCommand) handleListTms(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Listing all threatcl models in: %s\n\n", c.flagDir))

	// Build the ListCommand so we can execute it and handle the output
	cfg, _ := spec.LoadSpecConfig()
	global := &GlobalCmdOptions{}

	lc := &ListCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}

	output, err := lc.Execute([]string{c.flagDir})
	if err != nil {
		return nil, fmt.Errorf("error executing list command: %w", err)
	}

	for _, line := range output {
		result.WriteString(fmt.Sprintf("%s\n", line))
	}

	return mcp.NewToolResultText(result.String()), nil
}

func (c *MCPCommand) handleListTmsWithCustomCols(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var result strings.Builder

	cols, ok := req.Params.Arguments["columns"].(string)
	if !ok {
		cols = "number,file,threatmodel,author"
		result.WriteString(fmt.Sprintf("Listing all threatcl models in %s using the default columns of file, threatmodel and author\n\n", c.flagDir))
	} else {
		result.WriteString(fmt.Sprintf("Listing all threatcl models in: %s with custom cols: %s\n\n", c.flagDir, cols))
	}

	// Build the ListCommand so we can execute it and handle the output
	cfg, _ := spec.LoadSpecConfig()
	global := &GlobalCmdOptions{}

	lc := &ListCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
		flagFields:       cols,
	}

	output, err := lc.Execute([]string{c.flagDir})
	if err != nil {
		return nil, fmt.Errorf("error executing list command: %w", err)
	}

	for _, line := range output {
		result.WriteString(fmt.Sprintf("%s\n", line))
	}

	return mcp.NewToolResultText(result.String()), nil
}

func (c *MCPCommand) handleViewTmString(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tmString, ok := req.Params.Arguments["hcl"].(string)
	if !ok {
		return nil, fmt.Errorf("hcl must be a string")
	}

	cfg, _ := spec.LoadSpecConfig()
	tmParser := spec.NewThreatmodelParser(cfg)
	err := tmParser.ParseHCLRaw([]byte(tmString))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error parsing string: %s", err)), nil
	}

	mdBuffer := new(strings.Builder)

	tmBuffer, err := tmParser.GetWrapped().Threatmodels[0].RenderMarkdown(spec.TmMDTemplate)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error rendering markdown: %s", err)), nil
	}

	_, err = io.Copy(mdBuffer, tmBuffer)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error copying buffer: %s", err)), nil
	}

	return mcp.NewToolResultText(mdBuffer.String()), nil

}

func (c *MCPCommand) handlePngDfdViewFromTmString(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tmString, ok := req.Params.Arguments["hcl"].(string)
	if !ok {
		return nil, fmt.Errorf("hcl must be a string")
	}

	cfg, _ := spec.LoadSpecConfig()
	tmParser := spec.NewThreatmodelParser(cfg)
	err := tmParser.ParseHCLRaw([]byte(tmString))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error parsing string: %s", err)), nil
	}

	dfd := tmParser.GetWrapped().Threatmodels[0].DataFlowDiagrams[0]
	tmName := tmParser.GetWrapped().Threatmodels[0].Name

	pngBytes, err := dfd.GenerateDfdPngBytes(tmName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error generating dfd png bytes: %s", err)), nil
	}

	// Base64 encode the PNG bytes
	base64Bytes := base64.StdEncoding.EncodeToString(pngBytes)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.ImageContent{
				Type:     "image",
				Data:     base64Bytes,
				MIMEType: "image/png",
			},
		},
	}, nil
}

func (c *MCPCommand) handleViewTmFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {

	var result strings.Builder

	file, ok := req.Params.Arguments["file"].(string)
	if !ok {
		return nil, fmt.Errorf("file must be a string")
	}

	validFile, err := c.validateTmFilePath(file)
	if err != nil {
		return nil, fmt.Errorf("error in TM file path: %w", err)
	}

	cfg, _ := spec.LoadSpecConfig()
	global := &GlobalCmdOptions{}

	vc := &ViewCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
		flagRawOut:       true,
	}

	// Read and return file contents
	// contents, err := os.ReadFile(validFile)
	contents, err := vc.Execute([]string{validFile})
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	result.WriteString(string(contents))
	return mcp.NewToolResultText(result.String()), nil
}

func (c *MCPCommand) handleViewTmFileRaw(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var result strings.Builder

	file, ok := req.Params.Arguments["file"].(string)
	if !ok {
		return nil, fmt.Errorf("file must be a string")
	}

	validFile, err := c.validateTmFilePath(file)
	if err != nil {
		return nil, fmt.Errorf("error in TM file path: %w", err)
	}

	// Read and return file contents
	contents, err := os.ReadFile(validFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	result.WriteString(string(contents))
	return mcp.NewToolResultText(result.String()), nil

}

func (c *MCPCommand) handleValidateTmFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {

	file, ok := req.Params.Arguments["file"].(string)
	if !ok {
		return nil, fmt.Errorf("file must be a string")
	}

	validFile, err := c.validateTmFilePath(file)
	if err != nil {
		return nil, fmt.Errorf("error in TM file path: %w", err)
	}

	cfg, _ := spec.LoadSpecConfig()
	tmParser := spec.NewThreatmodelParser(cfg)
	err = tmParser.ParseFile(validFile, false)
	if err != nil {
		// return nil, fmt.Errorf("error parsing file: %w", err)
		return mcp.NewToolResultError(fmt.Sprintf("error parsing file: %s", err)), nil
	}

	tmCount := len(tmParser.GetWrapped().Threatmodels)

	return mcp.NewToolResultText(fmt.Sprintf("Validated %d threat models in file: %s\n", tmCount, validFile)), nil

}

func (c *MCPCommand) handleValidateTmString(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {

	hclstring, ok := req.Params.Arguments["hcl"].(string)
	if !ok {
		return nil, fmt.Errorf("file must be a string")
	}

	cfg, _ := spec.LoadSpecConfig()
	tmParser := spec.NewThreatmodelParser(cfg)
	err := tmParser.ParseHCLRaw([]byte(hclstring))
	if err != nil {
		// return nil, fmt.Errorf("error parsing string: %w", err)
		return mcp.NewToolResultError(fmt.Sprintf("error parsing string: %s", err)), nil
	}

	tmCount := len(tmParser.GetWrapped().Threatmodels)

	return mcp.NewToolResultText(fmt.Sprintf("Validated %d threat models in string\n", tmCount)), nil

}

func (c *MCPCommand) validateTmFilePath(inpath string) (string, error) {
	// before we try and build the path, let's first check if they provided a full path
	if c.isPathInCfg(inpath) {
		return inpath, nil
	} else {

		file := strings.TrimPrefix(inpath, string(filepath.Separator))
		rootFolder := strings.TrimSuffix(c.flagDir, string(filepath.Separator))
		fullPath, err := filepath.Abs(filepath.Join(rootFolder, file))
		if err != nil {
			return "", err
		}

		// Validate the path is within configured directory
		if !c.isPathInCfg(fullPath) {
			return "", fmt.Errorf("file path %s is not within configured directory", fullPath)
		}

		return fullPath, nil
	}
}

func (c *MCPCommand) isPathInCfg(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	if !strings.HasSuffix(absPath, string(filepath.Separator)) {
		if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
			absPath = filepath.Dir(absPath) + string(filepath.Separator)
		} else {
			absPath = absPath + string(filepath.Separator)
		}
	}

	if strings.HasPrefix(absPath, c.flagDir) {
		return true
	}

	return false
}

func (c *MCPCommand) getBoilerplateSpec() (string, error) {
	cfg, _ := spec.LoadSpecConfig()
	spec, err := parseBoilerplateTemplate(cfg)
	if err != nil {
		return "", err
	}

	return spec, nil
}

func (c *MCPCommand) handleViewSpecTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	spec, err := c.getBoilerplateSpec()
	if err != nil {
		return nil, err
	}

	return mcp.NewToolResultText(spec), nil
}

func (c *MCPCommand) handleShowSpecResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {

	spec, err := c.getBoilerplateSpec()
	if err != nil {
		return nil, err
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "threatcl://static/spec",
			MIMEType: "text/plain",
			Text:     spec,
		},
	}, nil
}

func (c *MCPCommand) handleViewSpecToolResource(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	resourceReq := mcp.ReadResourceRequest{
		Params: struct {
			URI       string                 `json:"uri"`
			Arguments map[string]interface{} `json:"arguments,omitempty"`
		}{
			URI: "threatcl://static/spec",
		},
	}
	spec, err := c.handleShowSpecResource(ctx, resourceReq)
	if err != nil {
		return nil, err
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.EmbeddedResource{
				Type:     "resource",
				Resource: spec[0],
			},
		},
	}, nil
}

func (c *MCPCommand) handleWriteTmFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {

	filename, ok := req.Params.Arguments["filename"].(string)
	if !ok {
		return nil, fmt.Errorf("filename must be a string")
	}

	hclString, ok := req.Params.Arguments["hcl"].(string)
	if !ok {
		return nil, fmt.Errorf("hcl must be a string")
	}

	validFile, err := c.validateTmFilePath(filename)
	if err != nil {
		return nil, fmt.Errorf("error in TM file path: %w", err)
	}

	// Validate the HCL string before writing
	cfg, _ := spec.LoadSpecConfig()
	tmParser := spec.NewThreatmodelParser(cfg)
	err = tmParser.ParseHCLRaw([]byte(hclString))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error parsing string: %s", err)), nil
	}

	// Get the format parameter, default to "hcl" if not specified
	format, _ := req.Params.Arguments["format"].(string)
	if format == "" {
		format = "hcl"
	}

	var contentToWrite []byte
	switch format {
	case "hcl":
		contentToWrite = []byte(hclString)
	case "otm":
		// Convert to OTM format
		tm := tmParser.GetWrapped().Threatmodels[0]
		tmOtm, err := tm.RenderOtm()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error converting to OTM: %s", err)), nil
		}
		otmJson, err := json.Marshal(tmOtm)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error marshaling OTM: %s", err)), nil
		}
		contentToWrite = otmJson
	default:
		return mcp.NewToolResultError(fmt.Sprintf("unsupported format: %s", format)), nil
	}

	// only write the file if it doesn't exist
	if _, err := os.Stat(validFile); os.IsNotExist(err) {
		writeErr := os.WriteFile(validFile, contentToWrite, 0644)
		if writeErr != nil {
			return nil, fmt.Errorf("error writing file: %w", writeErr)
		}
	} else {
		return nil, fmt.Errorf("file already exists: %s", validFile)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Wrote threat model to file: %s\n", validFile)), nil
}

func (c *MCPCommand) handleWriteDfdPngFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filename, ok := req.Params.Arguments["filename"].(string)
	if !ok {
		return nil, fmt.Errorf("filename must be a string")
	}

	hclString, ok := req.Params.Arguments["hcl"].(string)
	if !ok {
		return nil, fmt.Errorf("hcl must be a string")
	}

	validFile, err := c.validateTmFilePath(filename)
	if err != nil {
		return nil, fmt.Errorf("error in TM file path: %w", err)
	}

	// Parse the HCL string to get the DFD
	cfg, _ := spec.LoadSpecConfig()
	tmParser := spec.NewThreatmodelParser(cfg)
	err = tmParser.ParseHCLRaw([]byte(hclString))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error parsing string: %s", err)), nil
	}

	dfd := tmParser.GetWrapped().Threatmodels[0].DataFlowDiagrams[0]
	tmName := tmParser.GetWrapped().Threatmodels[0].Name

	// Generate the PNG bytes
	pngBytes, err := dfd.GenerateDfdPngBytes(tmName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error generating dfd png bytes: %s", err)), nil
	}

	// only write the file if it doesn't exist
	if _, err := os.Stat(validFile); os.IsNotExist(err) {
		writeErr := os.WriteFile(validFile, pngBytes, 0644)
		if writeErr != nil {
			return nil, fmt.Errorf("error writing file: %w", writeErr)
		}
	} else {
		return nil, fmt.Errorf("file already exists: %s", validFile)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Wrote DFD PNG to file: %s\n", validFile)), nil
}

func (c *MCPCommand) Synopsis() string {
	return "Model Context Protocol (MCP) server for threatcl"
}

func (c *MCPCommand) errPrint(msg string) {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	fmt.Fprintf(os.Stderr, "[%s threatcl-mcp] %s", timestamp, msg)
}

func (c *MCPCommand) validatePath(inPath string) (string, error) {
	// Convert to absolute path
	absPath, err := filepath.Abs(inPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Check if path exists and is a directory
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("directory does not exist: %s", absPath)
		}
		return "", fmt.Errorf("failed to access directory: %w", err)
	}

	if !fileInfo.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", absPath)
	}

	return absPath, nil
}
