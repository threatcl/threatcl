package main

import (
	"flag"
	"strings"
	"testing"
)

// The client-side rules mirror the server's, so a bad value fails locally
// with a clear message rather than as a 400 invalid_git_attribution.
func TestNormalizeGitAttribution(t *testing.T) {
	tests := []struct {
		name    string
		in      gitAttribution
		want    gitAttribution
		wantErr string
	}{
		{
			name: "nothing supplied is the zero value",
			in:   gitAttribution{},
			want: gitAttribution{},
		},
		{
			name: "whitespace-only fields count as nothing supplied",
			in:   gitAttribution{Name: "  ", Email: "\t", CommitSHA: " "},
			want: gitAttribution{},
		},
		{
			name: "bare email alone is enough",
			in:   gitAttribution{Email: "jane@example.com"},
			want: gitAttribution{Email: "jane@example.com"},
		},
		{
			name: "all three fields pass through trimmed",
			in:   gitAttribution{Name: " Jane Doe ", Email: " jane@example.com ", CommitSHA: " abc1234 "},
			want: gitAttribution{Name: "Jane Doe", Email: "jane@example.com", CommitSHA: "abc1234"},
		},
		{
			name: "display-name form is reduced to the bare address",
			in:   gitAttribution{Email: "Jane Doe <jane@example.com>"},
			want: gitAttribution{Name: "Jane Doe", Email: "jane@example.com"},
		},
		{
			name: "display name does not override an explicit name",
			in:   gitAttribution{Name: "J. Doe", Email: "Jane Doe <jane@example.com>"},
			want: gitAttribution{Name: "J. Doe", Email: "jane@example.com"},
		},
		{
			name: "angle-addr without a display name is reduced to the bare address",
			in:   gitAttribution{Email: "<jane@example.com>"},
			want: gitAttribution{Email: "jane@example.com"},
		},
		{
			name: "forge no-reply addresses are ordinary valid addresses",
			in:   gitAttribution{Email: "12345678+jane@users.noreply.github.com"},
			want: gitAttribution{Email: "12345678+jane@users.noreply.github.com"},
		},
		{
			name: "full 40-hex SHA is accepted",
			in:   gitAttribution{Email: "jane@example.com", CommitSHA: "0123456789abcdef0123456789abcdef01234567"},
			want: gitAttribution{Email: "jane@example.com", CommitSHA: "0123456789abcdef0123456789abcdef01234567"},
		},
		{
			name: "upper-case hex SHA is accepted",
			in:   gitAttribution{Email: "jane@example.com", CommitSHA: "ABCDEF1"},
			want: gitAttribution{Email: "jane@example.com", CommitSHA: "ABCDEF1"},
		},
		{
			name: "64-hex SHA-256 commit id is accepted",
			in:   gitAttribution{Email: "jane@example.com", CommitSHA: strings.Repeat("ab", 32)},
			want: gitAttribution{Email: "jane@example.com", CommitSHA: strings.Repeat("ab", 32)},
		},
		{
			name:    "name without email is an error, not a partial send",
			in:      gitAttribution{Name: "Jane Doe"},
			wantErr: "-git-author-email (or THREATCL_GIT_AUTHOR_EMAIL) is required",
		},
		{
			name:    "sha without email is an error",
			in:      gitAttribution{CommitSHA: "abc1234"},
			wantErr: "-git-author-email (or THREATCL_GIT_AUTHOR_EMAIL) is required",
		},
		{
			name:    "email without an @ is rejected",
			in:      gitAttribution{Email: "jane"},
			wantErr: `invalid git author email "jane"`,
		},
		{
			name:    "email with a bare display name and no angle brackets is rejected",
			in:      gitAttribution{Email: "Jane Doe jane@example.com"},
			wantErr: "invalid git author email",
		},
		{
			name:    "email over 254 characters is rejected",
			in:      gitAttribution{Email: strings.Repeat("a", 250) + "@example.com"},
			wantErr: "git author email is too long (max 254 characters)",
		},
		{
			name:    "name over 255 characters is rejected",
			in:      gitAttribution{Name: strings.Repeat("n", 256), Email: "jane@example.com"},
			wantErr: "git author name is too long (max 255 characters)",
		},
		{
			name:    "SHA shorter than 7 characters is rejected",
			in:      gitAttribution{Email: "jane@example.com", CommitSHA: "abc123"},
			wantErr: "invalid git commit SHA: must be 7 to 64 hexadecimal characters",
		},
		{
			name:    "SHA longer than 64 characters is rejected",
			in:      gitAttribution{Email: "jane@example.com", CommitSHA: strings.Repeat("a", 65)},
			wantErr: "invalid git commit SHA",
		},
		{
			name:    "non-hex SHA is rejected",
			in:      gitAttribution{Email: "jane@example.com", CommitSHA: "abc123g"},
			wantErr: "invalid git commit SHA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeGitAttribution(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (result %+v)", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				if got != (gitAttribution{}) {
					t.Errorf("expected zero attribution on error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// resolve must take each field from its flag first and its environment
// variable second, per field, and must never consult anything else.
func TestGitAttributionFlagsResolve(t *testing.T) {
	tests := []struct {
		name    string
		flags   gitAttributionFlags
		env     map[string]string
		want    gitAttribution
		wantErr string
	}{
		{
			name: "nothing set sends nothing",
			want: gitAttribution{},
		},
		{
			name:  "flags alone",
			flags: gitAttributionFlags{name: "Jane", email: "jane@example.com", sha: "abc1234"},
			want:  gitAttribution{Name: "Jane", Email: "jane@example.com", CommitSHA: "abc1234"},
		},
		{
			name: "environment alone",
			env: map[string]string{
				envGitAuthorName:  "CI Jane",
				envGitAuthorEmail: "ci@example.com",
				envGitCommitSHA:   "deadbee",
			},
			want: gitAttribution{Name: "CI Jane", Email: "ci@example.com", CommitSHA: "deadbee"},
		},
		{
			name:  "flags win over environment field by field",
			flags: gitAttributionFlags{email: "flag@example.com"},
			env: map[string]string{
				envGitAuthorName:  "Env Name",
				envGitAuthorEmail: "env@example.com",
				envGitCommitSHA:   "0000000",
			},
			want: gitAttribution{Name: "Env Name", Email: "flag@example.com", CommitSHA: "0000000"},
		},
		{
			name:    "name from environment without an email is still an error",
			env:     map[string]string{envGitAuthorName: "Env Name"},
			wantErr: "-git-author-email (or THREATCL_GIT_AUTHOR_EMAIL) is required",
		},
		{
			name:    "malformed environment value fails locally",
			env:     map[string]string{envGitAuthorEmail: "not-an-email"},
			wantErr: "invalid git author email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsSvc := newMockFileSystemService()
			for k, v := range tt.env {
				fsSvc.setEnv(k, v)
			}
			flags := tt.flags
			got, err := flags.resolve(fsSvc)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The flags register under the documented names and parse into the struct.
func TestGitAttributionFlagsAddFlags(t *testing.T) {
	var flags gitAttributionFlags
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.addFlags(flagSet)

	err := parseFlags(flagSet, []string{
		"-git-author-name=Jane Doe",
		"-git-author-email=jane@example.com",
		"-git-commit-sha=abc1234",
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	want := gitAttributionFlags{name: "Jane Doe", email: "jane@example.com", sha: "abc1234"}
	if flags != want {
		t.Errorf("got %+v, want %+v", flags, want)
	}
}

// The shared help text must name every flag and env var, and must say the
// values are never read from the local repo - that is a billing guarantee.
func TestCloudGitAttributionHelp(t *testing.T) {
	opts := cloudGitAttributionOptionsHelp()
	for _, want := range []string{
		"-git-author-email=<email>",
		"-git-author-name=<name>",
		"-git-commit-sha=<sha>",
		"never read from the local git repository",
		envGitAuthorEmail,
	} {
		if !strings.Contains(opts, want) {
			t.Errorf("expected options help to contain %q", want)
		}
	}

	env := cloudGitAttributionEnvHelp()
	for _, want := range []string{envGitAuthorEmail, envGitAuthorName, envGitCommitSHA} {
		if !strings.Contains(env, want) {
			t.Errorf("expected env help to contain %q", want)
		}
	}
}
