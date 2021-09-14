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

	if !strings.Contains(out, "Please provide <files> or -stdin") {
		t.Errorf("Expected %s to contain %s", out, "Please provide <files> or -stdin")
	}
}

// @TODO: @xntrik we should also test STDIN
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
			"Validated 5 threatmodels in 3 files",
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
