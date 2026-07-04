package main

import (
	"os"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func threatclRunTestSetup(tb testing.TB) {
	tb.Helper()

	d := tb.TempDir()

	_ = os.Setenv("HOME", d)
	_ = os.Setenv("USERPROFILE", d)
}

func TestThreatclRunVersion(t *testing.T) {
	threatclRunTestSetup(t)

	var code int
	out := capturer.CaptureOutput(func() {
		code = Run([]string{"--version"})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if strings.TrimSpace(out) == "" {
		t.Error("Expected version output, got nothing")
	}
}

func TestThreatclRunUnknownCommand(t *testing.T) {
	threatclRunTestSetup(t)

	var code int
	out := capturer.CaptureOutput(func() {
		code = Run([]string{"not-a-real-command"})
	})

	if code != 127 {
		t.Errorf("Code did not equal 127: %d", code)
	}

	if !strings.Contains(out, "Usage: threatcl") {
		t.Errorf("Expected %s to contain %s", out, "Usage: threatcl")
	}
}

func TestThreatclRunCommandsRegistered(t *testing.T) {
	threatclRunTestSetup(t)

	// Running a parent/grouping command with no subcommand returns
	// RunResultHelp inside the CLI, which surfaces as exit code 1 with
	// the command's help text. This exercises the command registry
	// wiring in Run without ever reaching an interactive prompt.
	tests := []struct {
		name         string
		args         []string
		helpContains string
	}{
		{
			name:         "generate",
			args:         []string{"generate"},
			helpContains: "Usage: threatcl generate <subcommand>",
		},
		{
			name:         "cloud",
			args:         []string{"cloud"},
			helpContains: "Usage: threatcl cloud <subcommand>",
		},
		{
			name:         "cloud token",
			args:         []string{"cloud", "token"},
			helpContains: "Usage: threatcl cloud token <subcommand>",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			out := capturer.CaptureOutput(func() {
				code = Run(tc.args)
			})

			if code != 1 {
				t.Errorf("Code did not equal 1: %d", code)
			}

			if !strings.Contains(out, tc.helpContains) {
				t.Errorf("Expected %s to contain %s", out, tc.helpContains)
			}
		})
	}
}

func TestThreatclRunHelpListsCommands(t *testing.T) {
	threatclRunTestSetup(t)

	var code int
	out := capturer.CaptureOutput(func() {
		code = Run([]string{"--help"})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	for _, expected := range []string{"validate", "generate", "cloud", "dashboard", "list", "view"} {
		if !strings.Contains(out, expected) {
			t.Errorf("Expected help output to list the %q command, got: %s", expected, out)
		}
	}
}
