package main

import (
	"strings"
	"testing"

	"github.com/mitchellh/cli"
)

func TestCommandWrappers(t *testing.T) {
	tests := []struct {
		name             string
		command          cli.Command
		helpContains     string
		expectedSynopsis string
	}{
		{
			name:             "cloud",
			command:          &CloudCommand{},
			helpContains:     "Usage: threatcl cloud <subcommand>",
			expectedSynopsis: "Interact with ThreatCL Cloud services",
		},
		{
			name:             "cloud token",
			command:          &CloudTokenCommand{},
			helpContains:     "Usage: threatcl cloud token <subcommand>",
			expectedSynopsis: "Manage authentication tokens",
		},
		{
			name:             "generate",
			command:          &GenerateCommand{},
			helpContains:     "Usage: threatcl generate <subcommand>",
			expectedSynopsis: "Generate an HCL Threat Model",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			help := tc.command.Help()
			if help == "" {
				t.Error("Expected non-empty help")
			}
			if !strings.Contains(help, tc.helpContains) {
				t.Errorf("Expected help to contain %q, got: %s", tc.helpContains, help)
			}

			synopsis := tc.command.Synopsis()
			if synopsis != tc.expectedSynopsis {
				t.Errorf("Expected synopsis %q, got %q", tc.expectedSynopsis, synopsis)
			}

			code := tc.command.Run([]string{})
			if code != cli.RunResultHelp {
				t.Errorf("Expected Run to return cli.RunResultHelp (%d), got %d", cli.RunResultHelp, code)
			}
		})
	}
}
