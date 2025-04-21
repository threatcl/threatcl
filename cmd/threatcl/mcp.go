package main

import (
	"context"
	"errors"
	"fmt"
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

	if c.flagDir == "" {
		c.errPrint("Please provide a directory path using the -dir flag\n")
		return 1
	}

	absPath, err := c.validatePath(c.flagDir)
	if err != nil {
		c.errPrint(fmt.Sprintf("Error: %s\n", err))
		return 1
	}

	c.errPrint(fmt.Sprintf("Threatcl MCP server started - using directory: %s\n", absPath))

	mcpserver := server.NewMCPServer(
		"threatlcl-mcp",
		"0.0.1",
		// server.WithResourceCapabilities(true, true),
	)

	// tool := mcp.NewTool("hello_world",
	// 	mcp.WithDescription("Returns a greeting message."),
	// 	mcp.WithString("name",
	// 		mcp.Required(),
	// 		mcp.Description("Name of the person to greet."),
	// 	),
	// )

	// mcpserver.AddTool(tool, c.helloHandler)

	mcpserver.AddTool(mcp.NewTool(
		"list_all_tms",
		mcp.WithDescription("Get a listing of all the threatcl threat models, and their files, located within our specific directory"),
	), c.handleListTms)

	mcpserver.AddTool(mcp.NewTool(
		"list_all_tms_with_cols",
		mcp.WithDescription("Get a detailed listing of all the threatcl threat models, and their files, located within our specific directory. This tool allows you to specify what columns are displayed, for instance: file, author, threatmodel, threatcount, internetfacing."),
		mcp.WithString("columns",
			mcp.Description("The columns you want to list against each threat model. Is expected to be a comma-separated list of values from this set: number, threatmodel, author, file, threatcount, internetfacing, assetcount, usecasecount, tpdcount, exclusioncount, size, newinitiative, dfd."),
		),
	), c.handleListTmsWithCustomCols)

	if err := server.ServeStdio(mcpserver); err != nil {
		c.errPrint(fmt.Sprintf("Server error: %v\n", err))
	}

	return 0
}

func (c *MCPCommand) helloHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, ok := req.Params.Arguments["name"].(string)
	if !ok {
		return nil, errors.New("name must be a string")
	}

	return mcp.NewToolResultText(fmt.Sprintf("Hello, %s, from threatcl!", name)), nil
}

func (c *MCPCommand) resourceHandler(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := req.Params.URI

	if !strings.HasPrefix(uri, "hcltm://") {
		return nil, fmt.Errorf("unsupported URI scheme: %s", uri)
	}

	path := strings.TrimPrefix(uri, "hcltm://")

	c.errPrint(path)
	return nil, nil

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
