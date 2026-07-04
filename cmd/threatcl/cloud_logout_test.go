package main

import (
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func cloudLogoutTestCommand(t testing.TB, k *mockKeyringService, f *mockFileSystemService) *CloudLogoutCommand {
	t.Helper()

	return &CloudLogoutCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       newMockHTTPClient(),
			keyringSvc:       k,
			fsSvc:            f,
		},
	}
}

func TestCloudLogoutRun(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(t *testing.T, k *mockKeyringService)
		args           []string
		expectedCode   int
		expectedOuts   []string
		expectedTokens int // -1 to skip the store check
	}{
		{
			name:           "default logout with no tokens",
			setup:          func(t *testing.T, k *mockKeyringService) {},
			args:           []string{},
			expectedCode:   0,
			expectedOuts:   []string{"No tokens to remove."},
			expectedTokens: 0,
		},
		{
			name: "default logout with single token",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Org One")
			},
			args:           []string{},
			expectedCode:   0,
			expectedOuts:   []string{"Logged out from organization: Org One (org-one)"},
			expectedTokens: 0,
		},
		{
			name: "default logout with implicit default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
				})
			},
			args:           []string{},
			expectedCode:   0,
			expectedOuts:   []string{"Logged out from organization: Org One (org-one)"},
			expectedTokens: 0,
		},
		{
			name: "default logout with multiple orgs and no default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:           []string{},
			expectedCode:   1,
			expectedOuts:   []string{"multiple organizations configured but no default set"},
			expectedTokens: 2,
		},
		{
			name: "default logout only removes default org",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-two", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:           []string{},
			expectedCode:   0,
			expectedOuts:   []string{"Logged out from organization: Org Two (org-two)"},
			expectedTokens: 1,
		},
		{
			name: "logout specific org",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:           []string{"-org-id=org-two"},
			expectedCode:   0,
			expectedOuts:   []string{"Logged out from organization: Org Two (org-two)"},
			expectedTokens: 1,
		},
		{
			name: "logout specific org without org name",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: ""},
				})
			},
			args:           []string{"-org-id=org-one"},
			expectedCode:   0,
			expectedOuts:   []string{"Logged out from organization: org-one\n"},
			expectedTokens: 0,
		},
		{
			name: "logout unknown org",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Org One")
			},
			args:           []string{"-org-id=missing-org"},
			expectedCode:   1,
			expectedOuts:   []string{"no token found for organization missing-org"},
			expectedTokens: 1,
		},
		{
			name: "logout all removes every token",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:         []string{"-all"},
			expectedCode: 0,
			expectedOuts: []string{
				"Removed 2 token(s). You are now logged out from all organizations.",
			},
			expectedTokens: 0,
		},
		{
			name:           "logout all with no tokens",
			setup:          func(t *testing.T, k *mockKeyringService) {},
			args:           []string{"-all"},
			expectedCode:   0,
			expectedOuts:   []string{"No tokens to remove."},
			expectedTokens: 0,
		},
		{
			name:           "old token format returns error",
			setup:          func(t *testing.T, k *mockKeyringService) { tokenCmdTestSeedOldFormat(t, k) },
			args:           []string{},
			expectedCode:   1,
			expectedOuts:   []string{"token format has changed"},
			expectedTokens: -1,
		},
		{
			name:           "old token format with all flag returns error",
			setup:          func(t *testing.T, k *mockKeyringService) { tokenCmdTestSeedOldFormat(t, k) },
			args:           []string{"-all"},
			expectedCode:   1,
			expectedOuts:   []string{"Error retrieving tokens", "token format has changed"},
			expectedTokens: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()
			tt.setup(t, keyringSvc)

			cmd := cloudLogoutTestCommand(t, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			for _, want := range tt.expectedOuts {
				if !strings.Contains(out, want) {
					t.Errorf("expected output to contain %q, got %q", want, out)
				}
			}

			if tt.expectedTokens >= 0 {
				tokens, _, err := listTokens(keyringSvc, fsSvc)
				if err != nil {
					t.Fatalf("unexpected error listing tokens: %v", err)
				}
				if len(tokens) != tt.expectedTokens {
					t.Errorf("expected %d token(s) remaining, got %d", tt.expectedTokens, len(tokens))
				}
			}
		})
	}
}

func TestCloudLogoutHelpAndSynopsis(t *testing.T) {
	cmd := &CloudLogoutCommand{}

	if !strings.Contains(cmd.Help(), "threatcl cloud logout") {
		t.Errorf("expected help to contain usage line, got %q", cmd.Help())
	}
	if cmd.Synopsis() == "" {
		t.Error("expected non-empty synopsis")
	}
}
