package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalCmdOptions(t *testing.T) {
	cmd := &GlobalCmdOptions{}
	fs := cmd.GetFlagset("test")

	if fs == nil {
		t.Error("Something went wrong with getting the flagset")
	}
}

// newPermuteFlagset builds a flagset carrying one of each flag shape the
// permuter has to reason about: a string flag, a bool flag, and the global
// -config/-debug pair.
func newPermuteFlagset(modelId *string, jsonOut *bool) *flag.FlagSet {
	cmd := &GlobalCmdOptions{}
	fs := cmd.GetFlagset("test")
	fs.SetOutput(io.Discard)
	fs.StringVar(modelId, "model-id", "", "Threat model ID or slug")
	fs.BoolVar(jsonOut, "json", false, "Output as JSON")
	return fs
}

func TestPermuteArgs(t *testing.T) {
	cases := []struct {
		name       string
		in         []string
		wantFlags  []string
		wantPosArg []string
	}{
		{
			name:       "flags before positionals is unchanged",
			in:         []string{"-model-id=abc", "-json", "file.hcl"},
			wantFlags:  []string{"-model-id=abc", "-json"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "flags after positionals are hoisted",
			in:         []string{"file.hcl", "-model-id=abc", "-json"},
			wantFlags:  []string{"-model-id=abc", "-json"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "flags interspersed with positionals",
			in:         []string{"a.hcl", "-model-id=abc", "b.hcl", "-json", "c.hcl"},
			wantFlags:  []string{"-model-id=abc", "-json"},
			wantPosArg: []string{"a.hcl", "b.hcl", "c.hcl"},
		},
		{
			name:       "space separated flag value travels with its flag",
			in:         []string{"file.hcl", "-model-id", "abc"},
			wantFlags:  []string{"-model-id", "abc"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "bool flag doesn't swallow the next positional",
			in:         []string{"-json", "file.hcl"},
			wantFlags:  []string{"-json"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "double dash flags are handled too",
			in:         []string{"file.hcl", "--model-id", "abc"},
			wantFlags:  []string{"--model-id", "abc"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "terminator makes everything after it positional",
			in:         []string{"-json", "--", "-weird-name.hcl", "-model-id=abc"},
			wantFlags:  []string{"-json"},
			wantPosArg: []string{"-weird-name.hcl", "-model-id=abc"},
		},
		{
			name:       "bare dash is positional",
			in:         []string{"-", "-json"},
			wantFlags:  []string{"-json"},
			wantPosArg: []string{"-"},
		},
		{
			name:       "unknown flag is left for the flag package",
			in:         []string{"file.hcl", "-nope"},
			wantFlags:  []string{"-nope"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "trailing flag with a missing value doesn't panic",
			in:         []string{"file.hcl", "-model-id"},
			wantFlags:  []string{"-model-id"},
			wantPosArg: []string{"file.hcl"},
		},
		{
			name:       "no args",
			in:         []string{},
			wantFlags:  []string{},
			wantPosArg: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var modelId string
			var jsonOut bool
			fs := newPermuteFlagset(&modelId, &jsonOut)

			want := tc.wantFlags
			if len(tc.wantPosArg) > 0 {
				want = append(append(append([]string{}, tc.wantFlags...), "--"), tc.wantPosArg...)
			}

			got := permuteArgs(fs, tc.in)
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("permuteArgs(%v) = %v, want %v", tc.in, got, want)
			}
		})
	}
}

func TestParseFlagsOrderIndependence(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"flags first", []string{"-model-id=abc", "-json", "file.hcl"}},
		{"flags last", []string{"file.hcl", "-model-id=abc", "-json"}},
		{"flags either side", []string{"-json", "file.hcl", "-model-id=abc"}},
		{"space separated value last", []string{"file.hcl", "-json", "-model-id", "abc"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var modelId string
			var jsonOut bool
			fs := newPermuteFlagset(&modelId, &jsonOut)

			if err := parseFlags(fs, tc.args); err != nil {
				t.Fatalf("parseFlags(%v) errored: %s", tc.args, err)
			}

			if modelId != "abc" {
				t.Errorf("-model-id = %q, want \"abc\"", modelId)
			}
			if !jsonOut {
				t.Error("-json was not set")
			}
			if got := fs.Args(); len(got) != 1 || got[0] != "file.hcl" {
				t.Errorf("positional args = %v, want [file.hcl]", got)
			}
		})
	}
}

// parseFlags must keep a positional that looks like a flag positional, so
// long as the caller marked it with the terminator.
func TestParseFlagsTerminatedPositional(t *testing.T) {
	var modelId string
	var jsonOut bool
	fs := newPermuteFlagset(&modelId, &jsonOut)

	if err := parseFlags(fs, []string{"-json", "--", "-oddly-named.hcl"}); err != nil {
		t.Fatalf("parseFlags errored: %s", err)
	}

	if !jsonOut {
		t.Error("-json was not set")
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "-oddly-named.hcl" {
		t.Errorf("positional args = %v, want [-oddly-named.hcl]", got)
	}
}

func TestParseFlagsUnknownFlagAfterPositional(t *testing.T) {
	var modelId string
	var jsonOut bool
	cmd := &GlobalCmdOptions{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&cmd.flagDebug, "debug", false, "Enable debug output")
	fs.StringVar(&cmd.flagConfig, "config", "", "Optional config file")
	fs.StringVar(&modelId, "model-id", "", "Threat model ID or slug")
	fs.BoolVar(&jsonOut, "json", false, "Output as JSON")

	// Previously this silently became a second positional argument.
	if err := parseFlags(fs, []string{"file.hcl", "-nope"}); err == nil {
		t.Error("expected an error for an undefined flag, got none")
	}
}

func TestFindAllFiles(t *testing.T) {
	in := []string{
		"./testdata/tm1.hcl",
		"./testdata/tm2.hcl",
		"./testdata/tm1.json",
	}

	out := findAllFiles(in)

	if len(out) != 3 {
		t.Errorf("There should be three files")
	}

	out = findAllFiles([]string{"./testdata/"})

	if len(out) != 8 {
		t.Errorf("There should be eight files")
	}
}

func TestConfigFileLocation(t *testing.T) {
	d := t.TempDir()
	_ = os.Setenv("HOME", d)
	_ = os.Setenv("USERPROFILE", d)
	f, err := configFileLocation()

	if err != nil {
		t.Errorf("Error getting cfg location: %s", err)
	}

	expected := filepath.Join(d, ".hcltmrc")
	if f != expected {
		t.Errorf("%s didn't equal '%s'", f, expected)
	}

}

func TestNonExistingConfigFileLocation(t *testing.T) {
	_ = os.Setenv("HOME", "")
	_ = os.Setenv("USERPROFILE", "")
	_, err := configFileLocation()

	if err != nil && !strings.Contains(err.Error(), "can't find home directory") {
		t.Errorf("Unusal error handling a non-existent cfg location: %s", err)
	}

}

func TestPrettyBoolFromString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  bool
	}{
		{
			"Yes",
			"Yes",
			true,
		},
		{
			"No",
			"No",
			false,
		},
		{
			"yes",
			"yes",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if prettyBoolFromString(tc.in) != tc.exp {
				t.Errorf("%s did not equal %t", tc.in, tc.exp)
			}
		})
	}
}

func TestPrettyBool(t *testing.T) {
	cases := []struct {
		name string
		in   bool
		exp  string
	}{
		{
			"true",
			true,
			"Yes",
		},
		{
			"false",
			false,
			"No",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if prettyBool(tc.in) != tc.exp {
				t.Errorf("%t did not equal %s", tc.in, tc.exp)
			}
		})
	}
}

func TestValidFilename(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		expectError bool
	}{
		{
			"valid",
			"valid",
			false,
		},
		{
			"in.valid",
			"in.valid",
			true,
		},
		{
			"with-slash",
			"/no",
			true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateFilename(tc.in)
			if tc.expectError && err == nil {
				t.Errorf("Expected error... from input '%s'", tc.in)
			}

			if !tc.expectError && err != nil {
				t.Errorf("Did not expect error: %s", err)
			}
		})
	}
}
