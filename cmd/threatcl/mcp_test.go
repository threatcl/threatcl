package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/zenizh/go-capturer"
)

func testMCPCommand(tb testing.TB) *MCPCommand {
	tb.Helper()

	d, err := os.MkdirTemp("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &MCPCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestMCPRun(t *testing.T) {
	cases := []struct {
		name      string
		dirFlag   string
		exp       []string
		invertexp bool
		code      int
	}{
		{
			"no_directory",
			"",
			[]string{
				"Threatcl MCP server started - no directory specified",
				"Only non-filesystem tools are available",
			},
			false,
			0,
		},
		{
			"with_directory",
			"TEMP_DIR_PLACEHOLDER",
			[]string{
				"Threatcl MCP server started - using directory:",
			},
			false,
			0,
		},
		{
			"invalid_directory",
			"./nonexistent",
			[]string{
				"directory does not exist",
			},
			false,
			1,
		},
	}

	tempDir, err := os.MkdirTemp("", "mcp_test_withdir")
	if err != nil {
		t.Fatalf("Error creating temp dir: %s", err)
	}
	defer os.RemoveAll(tempDir)
	os.WriteFile(filepath.Join(tempDir, "dummy.hcl"), []byte("threatmodel \"dummy\" { author = \"x\" }"), 0644)

	for i, tc := range cases {
		if tc.name == "with_directory" {
			cases[i].dirFlag = tempDir
			cases[i].exp = append(cases[i].exp, filepath.Base(tempDir))
		}
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testMCPCommand(t)

			var code int
			out := capturer.CaptureStderr(func() {
				args := []string{}
				if tc.dirFlag != "" {
					args = append(args, "-dir="+tc.dirFlag)
				}
				code = cmd.Run(args)
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			if !tc.invertexp {
				for _, exp := range tc.exp {
					if !strings.Contains(out, exp) {
						t.Errorf("Expected %s to contain %s", out, exp)
					}
				}
			} else {
				for _, exp := range tc.exp {
					if strings.Contains(out, exp) {
						t.Errorf("Was not expecting %s to contain %s", out, exp)
					}
				}
			}
		})
	}
}

func TestMCPToolHandlers(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		args     map[string]interface{}
		exp      string
		hasError bool
	}{
		{
			"validate_tm_string_valid",
			"validate_tm_string",
			map[string]interface{}{
				"hcl": "threatmodel \"test\" {\n  author = \"test\"\n}\n",
			},
			"Validated 1 threat models in string",
			false,
		},
		{
			"validate_tm_string_invalid",
			"validate_tm_string",
			map[string]interface{}{
				"hcl": "invalid hcl",
			},
			"error parsing string",
			true,
		},
		{
			"view_spec",
			"view_threatcl_hcl_spec",
			nil,
			"threatmodel",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testMCPCommand(t)

			var result *mcp.CallToolResult
			var err error

			switch tc.tool {
			case "validate_tm_string":
				result, err = cmd.handleValidateTmString(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "validate_tm_string",
						Arguments: tc.args,
					},
				})
			case "view_threatcl_hcl_spec":
				result, err = cmd.handleViewSpecTool(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "view_threatcl_hcl_spec",
					},
				})
			}

			if tc.hasError {
				if err == nil && (result == nil || !result.IsError) {
					t.Error("Expected error but got none")
				}
				var errMsg string
				if err != nil {
					errMsg = err.Error()
				} else if result != nil && len(result.Content) > 0 {
					if textContent, ok := result.Content[0].(mcp.TextContent); ok {
						errMsg = textContent.Text
					}
				}
				if !strings.Contains(errMsg, tc.exp) {
					t.Errorf("Expected error to contain %s, got %s", tc.exp, errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result.Content) == 0 {
					t.Error("Expected content in result")
				}
				if textContent, ok := result.Content[0].(mcp.TextContent); ok {
					if !strings.Contains(textContent.Text, tc.exp) {
						t.Errorf("Expected result to contain %s, got %s", tc.exp, textContent.Text)
					}
				} else {
					t.Error("Expected TextContent in result")
				}
			}
		})
	}
}

func TestMCPDirectoryTools(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	// Create a test threat model file
	testFile := filepath.Join(d, "test.hcl")
	err = os.WriteFile(testFile, []byte("threatmodel \"test\" {\n  author = \"test\"\n}\n"), 0644)
	if err != nil {
		t.Fatalf("Error creating test file: %s", err)
	}

	cmd := testMCPCommand(t)
	cmd.flagDir = d

	cases := []struct {
		name     string
		tool     string
		args     map[string]interface{}
		exp      string
		hasError bool
	}{
		{
			"list_all_tms",
			"list_all_tms",
			nil,
			"test.hcl",
			false,
		},
		{
			"validate_tm_file",
			"validate_tm_file",
			map[string]interface{}{
				"file": "test.hcl",
			},
			"Validated 1 threat models in file",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			var result *mcp.CallToolResult
			var err error

			switch tc.tool {
			case "list_all_tms":
				result, err = cmd.handleListTms(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "list_all_tms",
					},
				})
			case "validate_tm_file":
				result, err = cmd.handleValidateTmFile(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "validate_tm_file",
						Arguments: tc.args,
					},
				})
			}

			if tc.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("Expected error to contain %s, got %s", tc.exp, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result.Content) == 0 {
					t.Error("Expected content in result")
				}
				if textContent, ok := result.Content[0].(mcp.TextContent); ok {
					if !strings.Contains(textContent.Text, tc.exp) {
						t.Errorf("Expected result to contain %s, got %s", tc.exp, textContent.Text)
					}
				} else {
					t.Error("Expected TextContent in result")
				}
			}
		})
	}
}

func TestMCPAdditionalTools(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	// Create a test threat model file
	testFile := filepath.Join(d, "test.hcl")
	err = os.WriteFile(testFile, []byte("threatmodel \"test\" {\n  author = \"test\"\n}\n"), 0644)
	if err != nil {
		t.Fatalf("Error creating test file: %s", err)
	}

	cmd := testMCPCommand(t)
	cmd.flagDir = d

	cases := []struct {
		name     string
		tool     string
		args     map[string]interface{}
		exp      string
		hasError bool
	}{
		{
			"list_all_tms_with_cols",
			"list_all_tms_with_cols",
			map[string]interface{}{
				"columns": "file,threatmodel,author",
			},
			"test.hcl",
			false,
		},
		{
			"view_tm",
			"view_tm",
			map[string]interface{}{
				"file": "test.hcl",
			},
			"# test\n\nAuthor: test",
			false,
		},
		{
			"view_tm_hcl",
			"view_tm_hcl",
			map[string]interface{}{
				"file": "test.hcl",
			},
			"threatmodel",
			false,
		},
		{
			"view_tm_string",
			"view_tm_string",
			map[string]interface{}{
				"hcl": "threatmodel \"string_test\" {\n  author = \"test_author\"\n}\n",
			},
			"# string_test\n\nAuthor: test_author",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			var result *mcp.CallToolResult
			var err error

			switch tc.tool {
			case "list_all_tms_with_cols":
				result, err = cmd.handleListTmsWithCustomCols(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "list_all_tms_with_cols",
						Arguments: tc.args,
					},
				})
			case "view_tm":
				result, err = cmd.handleViewTmFile(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "view_tm",
						Arguments: tc.args,
					},
				})
			case "view_tm_hcl":
				result, err = cmd.handleViewTmFileRaw(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "view_tm_hcl",
						Arguments: tc.args,
					},
				})
			case "view_tm_string":
				result, err = cmd.handleViewTmString(context.Background(), mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "view_tm_string",
						Arguments: tc.args,
					},
				})
			}

			if tc.hasError {
				if err == nil && (result == nil || !result.IsError) {
					t.Error("Expected error but got none")
				}
				var errMsg string
				if err != nil {
					errMsg = err.Error()
				} else if result != nil && len(result.Content) > 0 {
					if textContent, ok := result.Content[0].(mcp.TextContent); ok {
						errMsg = textContent.Text
					}
				}
				if !strings.Contains(errMsg, tc.exp) {
					t.Errorf("Expected error to contain %s, got %s", tc.exp, errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result.Content) == 0 {
					t.Error("Expected content in result")
				}
				if textContent, ok := result.Content[0].(mcp.TextContent); ok {
					if !strings.Contains(textContent.Text, tc.exp) {
						t.Errorf("Expected result to contain %s, got %s", tc.exp, textContent.Text)
					}
				} else {
					t.Error("Expected TextContent in result")
				}
			}
		})
	}
}

func TestMCPShowSpecResource(t *testing.T) {
	cmd := testMCPCommand(t)
	result, err := cmd.handleShowSpecResource(context.Background(), mcp.ReadResourceRequest{
		Params: struct {
			URI       string                 `json:"uri"`
			Arguments map[string]interface{} `json:"arguments,omitempty"`
		}{
			URI: "threatcl://static/spec",
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("Expected resource contents in result")
	}
	if textResource, ok := result[0].(mcp.TextResourceContents); ok {
		if !strings.Contains(textResource.Text, "threatmodel") {
			t.Errorf("Expected result to contain 'threatmodel', got %s", textResource.Text)
		}
	} else {
		t.Error("Expected TextResourceContents in result")
	}
}

func TestMCPViewSpecToolResource(t *testing.T) {
	cmd := testMCPCommand(t)
	result, err := cmd.handleViewSpecToolResource(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "view_spec_tool_resource",
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("Expected content in result")
	}
	if embedded, ok := result.Content[0].(mcp.EmbeddedResource); ok {
		if textResource, ok := embedded.Resource.(mcp.TextResourceContents); ok {
			if !strings.Contains(textResource.Text, "threatmodel") {
				t.Errorf("Expected result to contain 'threatmodel', got %s", textResource.Text)
			}
		} else {
			t.Error("Expected TextResourceContents in embedded resource")
		}
	} else {
		t.Error("Expected EmbeddedResource in result")
	}
}

func TestMCPWriteTmFile(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMCPCommand(t)
	cmd.flagDir = d

	filename := "newtm.hcl"
	hclString := "threatmodel \"new\" {\n  author = \"author\"\n}\n"

	// First write should succeed
	result, err := cmd.handleWriteTmFile(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "write_tm_file",
			Arguments: map[string]interface{}{
				"filename": filename,
				"hcl":      hclString,
			},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil || len(result.Content) == 0 {
		t.Fatal("Expected content in result")
	}
	if textContent, ok := result.Content[0].(mcp.TextContent); ok {
		if !strings.Contains(textContent.Text, filename) {
			t.Errorf("Expected result to mention filename, got %s", textContent.Text)
		}
	} else {
		t.Error("Expected TextContent in result")
	}

	// Check file exists and content matches
	written, err := os.ReadFile(filepath.Join(d, filename))
	if err != nil {
		t.Fatalf("Expected file to be written: %v", err)
	}
	if string(written) != hclString {
		t.Errorf("File content mismatch: got %q, want %q", string(written), hclString)
	}

	// Second write should fail (file already exists)
	_, err = cmd.handleWriteTmFile(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "write_tm_file",
			Arguments: map[string]interface{}{
				"filename": filename,
				"hcl":      hclString,
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Error("Expected error about file already existing")
	}
}

func TestMCPPngDfdViewFromTmString(t *testing.T) {
	cmd := testMCPCommand(t)

	hclString := `threatmodel "test_dfd" {
  author = "test_author"
  description = "Test DFD"

  data_flow_diagram {
    external_element "Google Analytics" {}

    process "Client" {
      trust_zone = "Browser"
    }

    flow "https" {
      from = "Client"
      to = "Google Analytics"
    }

    process "Web Server" {
      trust_zone = "AWS"
    }

    data_store "Logs" {
      trust_zone = "AWS"
    }

    flow "TCP" {
      from = "Web Server"
      to = "Logs"
    }
  }
}`

	result, err := cmd.handlePngDfdViewFromTmString(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "png_dfd_view_from_tm_string",
			Arguments: map[string]interface{}{
				"hcl": hclString,
			},
		},
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(result.Content) == 0 {
		t.Fatal("Expected content in result")
	}

	if imageContent, ok := result.Content[0].(mcp.ImageContent); ok {
		if imageContent.Type != "image" {
			t.Errorf("Expected Type to be 'image', got %s", imageContent.Type)
		}
		if imageContent.MIMEType != "image/png" {
			t.Errorf("Expected MIMEType to be 'image/png', got %s", imageContent.MIMEType)
		}
		if imageContent.Data == "" {
			t.Error("Expected non-empty base64 data")
		}
	} else {
		t.Error("Expected ImageContent in result")
	}
}

func TestMCPWriteDfdPngFile(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMCPCommand(t)
	cmd.flagDir = d

	filename := "test_dfd.png"
	hclString := `threatmodel "test_dfd" {
  author = "test_author"
  description = "Test DFD"

  data_flow_diagram {
    external_element "Google Analytics" {}

    process "Client" {
      trust_zone = "Browser"
    }

    flow "https" {
      from = "Client"
      to = "Google Analytics"
    }

    process "Web Server" {
      trust_zone = "AWS"
    }

    data_store "Logs" {
      trust_zone = "AWS"
    }

    flow "TCP" {
      from = "Web Server"
      to = "Logs"
    }
  }
}`

	// First write should succeed
	result, err := cmd.handleWriteDfdPngFile(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "write_dfd_png_file",
			Arguments: map[string]interface{}{
				"filename": filename,
				"hcl":      hclString,
			},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil || len(result.Content) == 0 {
		t.Fatal("Expected content in result")
	}
	if textContent, ok := result.Content[0].(mcp.TextContent); ok {
		if !strings.Contains(textContent.Text, filename) {
			t.Errorf("Expected result to mention filename, got %s", textContent.Text)
		}
	} else {
		t.Error("Expected TextContent in result")
	}

	// Check file exists and is a valid PNG
	written, err := os.ReadFile(filepath.Join(d, filename))
	if err != nil {
		t.Fatalf("Expected file to be written: %v", err)
	}
	if len(written) == 0 {
		t.Error("Expected non-empty PNG file")
	}
	// Check PNG magic number
	if len(written) < 8 || string(written[0:8]) != "\x89PNG\r\n\x1a\n" {
		t.Error("Expected valid PNG file format")
	}

	// Second write should fail (file already exists)
	_, err = cmd.handleWriteDfdPngFile(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "write_dfd_png_file",
			Arguments: map[string]interface{}{
				"filename": filename,
				"hcl":      hclString,
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Error("Expected error about file already existing")
	}
}
