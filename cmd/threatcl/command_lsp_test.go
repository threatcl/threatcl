package main

import (
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

func testLSPCommand(tb testing.TB) *LSPCommand {
	tb.Helper()

	d, err := os.MkdirTemp("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)
	_ = os.Setenv("USERPROFILE", d)

	cfg, _ := spec.LoadSpecConfig()

	tb.Cleanup(func() { os.RemoveAll(d) })

	return &LSPCommand{
		GlobalCmdOptions: &GlobalCmdOptions{},
		specCfg:          cfg,
	}
}

func TestLSPSynopsis(t *testing.T) {
	c := testLSPCommand(t)
	got := c.Synopsis()
	if !strings.Contains(got, "Language Server") {
		t.Errorf("Synopsis() = %q, want it to mention 'Language Server'", got)
	}
}

func TestLSPHelp(t *testing.T) {
	c := testLSPCommand(t)
	help := c.Help()
	for _, want := range []string{"threatcl lsp", "-config", "-log", "-stdio", "stdio"} {
		if !strings.Contains(help, want) {
			t.Errorf("Help() missing %q", want)
		}
	}
}

func TestLSPAutocompleteFlags(t *testing.T) {
	c := testLSPCommand(t)
	flags := c.AutocompleteFlags()
	for _, want := range []string{"-config", "-log", "-stdio"} {
		if _, ok := flags[want]; !ok {
			t.Errorf("AutocompleteFlags() missing %q", want)
		}
	}
}

// TestLSPRunBadConfig exercises the Run path up to (but not into) the blocking
// stdio server: a -config pointing at a missing file must fail with exit code 1
// before the server starts.
func TestLSPRunBadConfig(t *testing.T) {
	c := testLSPCommand(t)
	code := c.Run([]string{"-config", "/nonexistent/threatcl/config.hcl"})
	if code != 1 {
		t.Errorf("Run with bad -config = %d, want 1", code)
	}
}
