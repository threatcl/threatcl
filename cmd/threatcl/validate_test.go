package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testValidateCommand(tb testing.TB) *ValidateCommand {
	tb.Helper()

	d, err := os.MkdirTemp("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)
	_ = os.Setenv("USERPROFILE", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &ValidateCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestValidateRunEmpty(t *testing.T) {
	cmd := testValidateCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Please provide <files> or -stdin or -stdinjson") {
		t.Errorf("Expected %s to contain %s", out, "Please provide <files> or -stdin or -stdinjson")
	}
}

func TestValidateRunTooManyStdin(t *testing.T) {
	cmd := testValidateCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-stdin",
			"-stdinjson",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "You can't -stdin and -stdinjson at the same time") {
		t.Errorf("Expected %s to contain %s", out, "You can't -stdin and -stdinjson at the same time")
	}
}

func TestValidateRun(t *testing.T) {

	cases := []struct {
		name      string
		in        string
		exp       string
		invertexp bool
		code      int
		flags     string
	}{
		{
			"validate_one_file",
			"./testdata/tm1.hcl",
			"Validated 2 threatmodels in 1 files",
			false,
			0,
			"",
		},
		{
			"validate_dir",
			"./testdata/",
			"Validated 10 threatmodels in 8 files",
			false,
			0,
			"",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testValidateCommand(t)

			var code int

			out := capturer.CaptureStdout(func() {
				code = cmd.Run([]string{
					tc.flags,
					tc.in,
				})
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			if !tc.invertexp {
				if !strings.Contains(out, tc.exp) {
					t.Errorf("Expected %s to contain %s", out, tc.exp)
				}
			} else {
				if strings.Contains(out, tc.exp) {
					t.Errorf("Was not expecting %s to contain %s", out, tc.exp)
				}
			}
		})
	}
}

func writeInvariantsFile(tb testing.TB, content string) string {
	tb.Helper()

	path := filepath.Join(tb.TempDir(), "invariants.hcl")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		tb.Fatal(err)
	}
	return path
}

func TestValidateInvariants(t *testing.T) {
	cases := []struct {
		name       string
		invariants string
		exp        []string
		code       int
	}{
		{
			"invariants_pass",
			`invariant "has_author" {
  target    = "threatmodel"
  condition = item.author != ""
}`,
			[]string{"Checked 1 invariants against 2 threatmodels: 0 errors, 0 warnings, 0 exemptions"},
			0,
		},
		{
			"invariants_error_violation",
			`invariant "threats_have_controls" {
  description = "Every threat must have at least one control"
  target      = "threat"
  condition   = length(item.controls) > 0
}`,
			[]string{
				"Invariant violation [error] 'threats_have_controls': threat 'multi line threat' in threatmodel 'tm1 one' (./testdata/tm1.hcl): Every threat must have at least one control",
				"2 errors, 0 warnings, 0 exemptions",
			},
			1,
		},
		{
			"invariants_warning_only",
			`invariant "threats_have_controls" {
  severity  = "warning"
  target    = "threat"
  condition = length(item.controls) > 0
}`,
			[]string{"Invariant violation [warning]", "0 errors, 2 warnings, 0 exemptions"},
			0,
		},
		{
			"invariants_exemption",
			`invariant "models_have_threats" {
  target    = "threatmodel"
  condition = length(item.threats) > 0

  exemption {
    model         = threatmodel["tm tm1 two"]
    justification = "Attribute-only model; tracked in SEC-1"
  }
}`,
			[]string{
				"Invariant 'models_have_threats' exempts threatmodel 'tm tm1 two' (./testdata/tm1.hcl): Attribute-only model; tracked in SEC-1",
				"0 errors, 0 warnings, 1 exemptions",
			},
			0,
		},
		{
			"invariants_when_filter",
			`invariant "internet_facing_documents_assets" {
  target    = "threatmodel"
  when      = item.attributes.internet_facing
  condition = length(item.information_assets) > 0
}`,
			[]string{"0 errors, 0 warnings, 0 exemptions"},
			0,
		},
		{
			"invariants_error_message_interpolation",
			`invariant "models_have_threats" {
  target        = "threatmodel"
  condition     = length(item.threats) > 0
  error_message = "threatmodel '${item.name}' documents no threats"
}`,
			[]string{"threatmodel 'tm tm1 two' documents no threats"},
			1,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testValidateCommand(t)
			invFile := writeInvariantsFile(t, tc.invariants)

			var code int

			out := capturer.CaptureStdout(func() {
				code = cmd.Run([]string{
					"-invariants=" + invFile,
					"./testdata/tm1.hcl",
				})
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			for _, exp := range tc.exp {
				if !strings.Contains(out, exp) {
					t.Errorf("Expected %s to contain %s", out, exp)
				}
			}
		})
	}
}

func TestValidateInvariantsFileErrors(t *testing.T) {
	cases := []struct {
		name       string
		invariants string // written to a temp file unless empty
		file       string // used verbatim when set
		exp        string
	}{
		{
			"invalid_invariants_file",
			`invariant "x" {
  target    = "nope"
  condition = true
}`,
			"",
			"Error parsing invariants file",
		},
		{
			"missing_invariants_file",
			"",
			"./testdata/no-such-invariants.hcl",
			"Error parsing invariants file",
		},
		{
			"broken_expression",
			`invariant "x" {
  target    = "threatmodel"
  condition = item.nonexistent_attribute == ""
}`,
			"",
			"Error evaluating invariants",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testValidateCommand(t)

			invFile := tc.file
			if invFile == "" {
				invFile = writeInvariantsFile(t, tc.invariants)
			}

			var code int

			out := capturer.CaptureStdout(func() {
				code = cmd.Run([]string{
					"-invariants=" + invFile,
					"./testdata/tm1.hcl",
				})
			})

			if code != 1 {
				t.Errorf("Code did not equal 1: %d", code)
			}

			if !strings.Contains(out, tc.exp) {
				t.Errorf("Expected %s to contain %s", out, tc.exp)
			}
		})
	}
}

func TestValidateInvariantsStdin(t *testing.T) {
	cmd := testValidateCommand(t)
	invFile := writeInvariantsFile(t, `
invariant "models_have_threats" {
  target    = "threatmodel"
  condition = length(item.threats) > 0
}`)

	var code int

	out := capturer.CaptureStdout(func() {
		content, err := os.ReadFile("./testdata/tm1.hcl")
		if err != nil {
			t.Fatal(err)
		}
		tmpFile, err := os.CreateTemp("", "example")
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(content); err != nil {
			t.Fatal(err)
		}

		if _, err := tmpFile.Seek(0, 0); err != nil {
			t.Fatal(err)
		}

		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		os.Stdin = tmpFile

		code = cmd.Run([]string{
			"-stdin",
			"-invariants=" + invFile,
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "threatmodel 'tm tm1 two' (STDIN)") {
		t.Errorf("Expected %s to contain a violation attributed to STDIN", out)
	}
}

func TestValidateStdin(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		exp       string
		invertexp bool
		code      int
		flags     string
	}{
		{
			"valid_stdin",
			"./testdata/tm1.hcl",
			"Validated 2 threatmodels",
			false,
			0,
			"-stdin",
		},
		{
			"valid_stdin_json",
			"./testdata/tm1.json",
			"Validated 2 threatmodels",
			false,
			0,
			"-stdinjson",
		},
		{
			"empty_stdin",
			"",
			"didn't receive any data",
			false,
			1,
			"-stdin",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testValidateCommand(t)

			var code int

			out := capturer.CaptureStdout(func() {
				var content []byte
				var err error
				if tc.in != "" {
					content, err = os.ReadFile(tc.in)
					if err != nil {
						t.Fatal(err)
					}
				}
				tmpFile, err := os.CreateTemp("", "example")
				if err != nil {
					t.Fatal(err)
				}

				defer os.Remove(tmpFile.Name())

				if _, err := tmpFile.Write(content); err != nil {
					t.Fatal(err)
				}

				if _, err := tmpFile.Seek(0, 0); err != nil {
					t.Fatal(err)
				}

				oldStdin := os.Stdin
				defer func() { os.Stdin = oldStdin }()

				os.Stdin = tmpFile

				code = cmd.Run([]string{
					tc.flags,
				})
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			if !tc.invertexp {
				if !strings.Contains(out, tc.exp) {
					t.Errorf("Expected %s to contain %s", out, tc.exp)
				}
			} else {
				if strings.Contains(out, tc.exp) {
					t.Errorf("Was not expecting %s to contain %s", out, tc.exp)
				}
			}
		})
	}
}
