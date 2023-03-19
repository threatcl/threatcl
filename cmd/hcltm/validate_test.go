package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/xntrik/hcltm/pkg/spec"

	"github.com/kami-zh/go-capturer"
)

func testValidateCommand(tb testing.TB) *ValidateCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

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
			"Validated 8 threatmodels in 6 files",
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
					content, err = ioutil.ReadFile(tc.in)
					if err != nil {
						t.Fatal(err)
					}
				}
				tmpFile, err := ioutil.TempFile("", "example")
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
