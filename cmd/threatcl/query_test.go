package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testQueryCommand(tb testing.TB) *QueryCommand {
	tb.Helper()

	d, err := os.MkdirTemp("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	tb.Cleanup(func() {
		os.RemoveAll(d)
	})

	global := &GlobalCmdOptions{}

	return &QueryCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestQueryCommand_ValidateFlags(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		expected string
		code     int
	}{
		{
			name:     "missing_dir",
			args:     []string{"-query", "{ stats { totalThreats } }"},
			expected: "Error: -dir flag is required",
			code:     1,
		},
		{
			name:     "missing_query_and_file",
			args:     []string{"-dir", "./examples"},
			expected: "Error: either -query or -file must be provided",
			code:     1,
		},
		{
			name:     "both_query_and_file",
			args:     []string{"-dir", "./examples", "-query", "{ stats }", "-file", "query.graphql"},
			expected: "Error: -query and -file are mutually exclusive",
			code:     1,
		},
		{
			name:     "invalid_directory",
			args:     []string{"-dir", "/nonexistent/path", "-query", "{ stats }"},
			expected: "Error: Directory '/nonexistent/path' does not exist",
			code:     1,
		},
		{
			name:     "printing examples",
			args:     []string{"-examples"},
			expected: "Examples",
			code:     0,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testQueryCommand(t)

			var code int

			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tc.args)
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			if !strings.Contains(out, tc.expected) {
				t.Errorf("Expected output to contain %q, got %q", tc.expected, out)
			}
		})
	}
}

func TestQueryCommand_BasicQuery(t *testing.T) {
	cmd := testQueryCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-query", "{ stats { totalThreatModels } }",
			"-output", "compact",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d\nOutput: %s", code, out)
	}

	// Parse JSON output
	var result map[string]interface{}
	err := json.Unmarshal([]byte(out), &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %s\nOutput: %s", err, out)
	}

	// Check for data field
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'data' field in response, got: %v", result)
	}

	// Check for stats field
	stats, ok := data["stats"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'stats' field in data, got: %v", data)
	}

	// Check for totalThreatModels field (should exist even if 0)
	if _, ok := stats["totalThreatModels"]; !ok {
		t.Errorf("Expected 'totalThreatModels' field in stats, got: %v", stats)
	}
}

func TestQueryCommand_QueryFromFile(t *testing.T) {
	// Create a temporary query file
	tmpFile, err := os.CreateTemp("", "query-*.graphql")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write a query to the file
	query := "{ stats { totalThreatModels totalThreats } }"
	if _, err := tmpFile.WriteString(query); err != nil {
		t.Fatalf("Failed to write to temp file: %s", err)
	}
	tmpFile.Close()

	cmd := testQueryCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-file", tmpFile.Name(),
			"-output", "compact",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d\nOutput: %s", code, out)
	}

	// Parse JSON output
	var result map[string]interface{}
	err = json.Unmarshal([]byte(out), &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %s\nOutput: %s", err, out)
	}

	// Verify we have data
	if _, ok := result["data"]; !ok {
		t.Errorf("Expected 'data' field in response, got: %v", result)
	}
}

func TestQueryCommand_InvalidQueryFile(t *testing.T) {
	cmd := testQueryCommand(t)

	var code int

	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-file", "/nonexistent/query.graphql",
		})
	})

	if code != 1 {
		t.Errorf("Expected code 1, got: %d", code)
	}

	if !strings.Contains(out, "Error reading query file") {
		t.Errorf("Expected error about reading query file, got: %s", out)
	}
}

func TestQueryCommand_OutputFormats(t *testing.T) {
	cases := []struct {
		name   string
		format string
	}{
		{"pretty", "pretty"},
		{"json", "json"},
		{"compact", "compact"},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testQueryCommand(t)

			var code int

			out := capturer.CaptureStdout(func() {
				code = cmd.Run([]string{
					"-dir", "./testdata",
					"-query", "{ stats { totalThreatModels } }",
					"-output", tc.format,
				})
			})

			if code != 0 {
				t.Errorf("Code did not equal 0: %d\nOutput: %s", code, out)
			}

			// All formats should produce valid JSON
			var result map[string]interface{}
			err := json.Unmarshal([]byte(out), &result)
			if err != nil {
				t.Errorf("Failed to parse JSON output: %s\nOutput: %s", err, out)
			}

			// Pretty and json formats should have indentation (contain newlines)
			if tc.format == "pretty" || tc.format == "json" {
				if !strings.Contains(out, "\n") {
					t.Errorf("Expected %s format to contain newlines", tc.format)
				}
			}
		})
	}
}

func TestQueryCommand_InvalidOutputFormat(t *testing.T) {
	cmd := testQueryCommand(t)

	var code int

	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-query", "{ stats { totalThreatModels } }",
			"-output", "invalid",
		})
	})

	if code != 1 {
		t.Errorf("Expected code 1, got: %d", code)
	}

	if !strings.Contains(out, "invalid output format") {
		t.Errorf("Expected error about invalid output format, got: %s", out)
	}
}

func TestQueryCommand_WithVariables(t *testing.T) {
	cmd := testQueryCommand(t)

	var code int

	// Simple query that should work even if no matching model exists
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-query", `query GetModel($name: String!) { threatModel(name: $name) { name } }`,
			"-vars", `{"name": "tm1"}`,
			"-output", "compact",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d\nOutput: %s", code, out)
	}

	// Parse JSON output
	var result map[string]interface{}
	err := json.Unmarshal([]byte(out), &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %s\nOutput: %s", err, out)
	}

	// Check for data field
	if _, ok := result["data"]; !ok {
		t.Errorf("Expected 'data' field in response, got: %v", result)
	}
}

func TestQueryCommand_InvalidVariables(t *testing.T) {
	cmd := testQueryCommand(t)

	var code int

	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-query", "{ stats { totalThreatModels } }",
			"-vars", "invalid json",
		})
	})

	if code != 1 {
		t.Errorf("Expected code 1, got: %d", code)
	}

	if !strings.Contains(out, "Error parsing variables") {
		t.Errorf("Expected error about parsing variables, got: %s", out)
	}
}

func TestQueryCommand_InvalidGraphQL(t *testing.T) {
	cmd := testQueryCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-dir", "./testdata",
			"-query", "{ invalid_field }",
			"-output", "compact",
		})
	})

	// GraphQL errors should still return code 1
	if code != 1 {
		t.Errorf("Expected code 1 for GraphQL errors, got: %d", code)
	}

	// Parse JSON output - should still be valid JSON with errors field
	var result map[string]interface{}
	err := json.Unmarshal([]byte(out), &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %s\nOutput: %s", err, out)
	}

	// Check for errors field
	errors, ok := result["errors"]
	if !ok {
		t.Errorf("Expected 'errors' field in response for invalid query, got: %v", result)
	}

	// Errors should be an array with at least one error
	if errArray, ok := errors.([]interface{}); !ok || len(errArray) == 0 {
		t.Errorf("Expected 'errors' to be a non-empty array, got: %v", errors)
	}
}

func TestQueryCommand_Synopsis(t *testing.T) {
	cmd := testQueryCommand(t)

	synopsis := cmd.Synopsis()
	if synopsis == "" {
		t.Error("Expected non-empty synopsis")
	}

	if !strings.Contains(synopsis, "GraphQL") {
		t.Errorf("Expected synopsis to mention GraphQL, got: %s", synopsis)
	}
}

func TestQueryCommand_Help(t *testing.T) {
	cmd := testQueryCommand(t)

	help := cmd.Help()
	if help == "" {
		t.Error("Expected non-empty help text")
	}

	// Check that help text contains important information
	expectedContent := []string{
		"Usage:",
		"-dir",
		"-query",
		"-file",
		"-vars",
		"-output",
	}

	for _, content := range expectedContent {
		if !strings.Contains(help, content) {
			t.Errorf("Expected help text to contain %q", content)
		}
	}
}
