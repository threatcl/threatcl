package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func genInteractiveTestCommand(tb testing.TB) *GenerateInteractiveCommand {
	tb.Helper()

	d := tb.TempDir()

	_ = os.Setenv("HOME", d)
	_ = os.Setenv("USERPROFILE", d)

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		tb.Fatalf("Error loading spec config: %s", err)
	}

	return &GenerateInteractiveCommand{
		GlobalCmdOptions: &GlobalCmdOptions{},
		specCfg:          cfg,
	}
}

func TestGenInteractiveHelp(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	help := cmd.Help()
	if !strings.Contains(help, "Usage: threatcl generate interactive") {
		t.Errorf("Expected help to contain usage string, got: %s", help)
	}
	if !strings.Contains(help, "-out=<file>") {
		t.Errorf("Expected help to document the -out flag, got: %s", help)
	}
}

func TestGenInteractiveSynopsis(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	synopsis := cmd.Synopsis()
	if synopsis != "Interactively generate a HCL threatmodel" {
		t.Errorf("Unexpected synopsis: %s", synopsis)
	}
}

func TestGenInteractiveAutocompleteFlags(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	flags := cmd.AutocompleteFlags()

	for _, expected := range []string{"-config", "-out"} {
		if _, ok := flags[expected]; !ok {
			t.Errorf("Expected autocomplete flags to include %s", expected)
		}
	}

	if len(flags) != 2 {
		t.Errorf("Expected 2 autocomplete flags, got %d", len(flags))
	}
}

func TestGenInteractiveInfoAssetExists(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	tests := []struct {
		name     string
		tm       *spec.Threatmodel
		iaName   string
		expected bool
	}{
		{
			name:     "nil information assets",
			tm:       &spec.Threatmodel{},
			iaName:   "anything",
			expected: false,
		},
		{
			name: "asset exists",
			tm: &spec.Threatmodel{
				InformationAssets: []*spec.InformationAsset{
					{Name: "credential store"},
					{Name: "user data"},
				},
			},
			iaName:   "user data",
			expected: true,
		},
		{
			name: "asset does not exist",
			tm: &spec.Threatmodel{
				InformationAssets: []*spec.InformationAsset{
					{Name: "credential store"},
				},
			},
			iaName:   "missing asset",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cmd.infoAssetExists(tc.tm, tc.iaName)
			if got != tc.expected {
				t.Errorf("infoAssetExists(%q) = %v, expected %v", tc.iaName, got, tc.expected)
			}
		})
	}
}

func genInteractiveTestTm() spec.Threatmodel {
	return spec.Threatmodel{
		Name:   "test threatmodel",
		Author: "test-author",
	}
}

func TestGenInteractiveOutStdout(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	tmParser := spec.NewThreatmodelParser(cmd.specCfg)
	tm := genInteractiveTestTm()

	var err error
	out := capturer.CaptureStdout(func() {
		err = cmd.out(tmParser, tm, nil)
	})

	if err != nil {
		t.Fatalf("Error writing threatmodel to stdout: %s", err)
	}

	if !strings.Contains(out, "threatmodel \"test threatmodel\"") {
		t.Errorf("Expected stdout to contain the threatmodel block, got: %s", out)
	}

	if !strings.Contains(out, "test-author") {
		t.Errorf("Expected stdout to contain the author, got: %s", out)
	}
}

func TestGenInteractiveOutFile(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	outFile := filepath.Join(t.TempDir(), "out.hcl")
	cmd.flagOut = outFile

	f, err := os.Create(outFile)
	if err != nil {
		t.Fatalf("Error creating out file: %s", err)
	}
	defer f.Close()

	tmParser := spec.NewThreatmodelParser(cmd.specCfg)
	tm := genInteractiveTestTm()

	err = cmd.out(tmParser, tm, f)
	if err != nil {
		t.Fatalf("Error writing threatmodel to file: %s", err)
	}

	contents, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Error reading out file: %s", err)
	}

	if !strings.Contains(string(contents), "threatmodel \"test threatmodel\"") {
		t.Errorf("Expected file to contain the threatmodel block, got: %s", string(contents))
	}
}

func TestGenInteractiveRunBrokenConfig(t *testing.T) {
	tests := []struct {
		name       string
		configFile func(t *testing.T) string
	}{
		{
			name: "non-existent config file",
			configFile: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "does-not-exist.hcl")
			},
		},
		{
			name: "invalid config file",
			configFile: func(t *testing.T) string {
				cfgFile := filepath.Join(t.TempDir(), "broken.hcl")
				if err := os.WriteFile(cfgFile, []byte("not valid hcl {{{{"), 0o644); err != nil {
					t.Fatalf("Error writing broken config: %s", err)
				}
				return cfgFile
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := genInteractiveTestCommand(t)

			var code int
			out := capturer.CaptureStdout(func() {
				code = cmd.Run([]string{
					fmt.Sprintf("-config=%s", tc.configFile(t)),
					"-out=/this/should/not/be/reached.hcl",
				})
			})

			if code != 1 {
				t.Errorf("Code did not equal 1: %d", code)
			}

			if !strings.Contains(out, "Error:") {
				t.Errorf("Expected %s to contain %s", out, "Error:")
			}
		})
	}
}

func TestGenInteractiveRunOutExists(t *testing.T) {
	cmd := genInteractiveTestCommand(t)

	existing := filepath.Join(t.TempDir(), "existing.hcl")
	if err := os.WriteFile(existing, []byte("already here"), 0o644); err != nil {
		t.Fatalf("Error creating existing file: %s", err)
	}

	var code int
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", existing),
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "which already exists") {
		t.Errorf("Expected %s to contain %s", out, "which already exists")
	}
}
