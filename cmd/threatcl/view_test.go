package main

import (
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testViewCommand(tb testing.TB) *ViewCommand {
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

	return &ViewCommand{
		specCfg:          cfg,
		GlobalCmdOptions: global,
		testEnv:          true,
	}
}

func TestViewRunEmpty(t *testing.T) {
	cmd := testViewCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Please provide a filename") {
		t.Errorf("Expected %s to contain %s", out, "Please provide a filename")
	}
}

func TestViewRun(t *testing.T) {

	cases := []struct {
		name      string
		in        string
		exp       string
		invertexp bool
		code      int
		flags     string
	}{
		{
			"view_one_file",
			"./testdata/tm1.hcl",
			"This is some arbitrary text",
			false,
			0,
			"",
		},
		{
			"view_one_file_raw",
			"./testdata/tm1.hcl",
			"This is some arbitrary text",
			false,
			0,
			"-raw",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testViewCommand(t)

			var code int

			out := capturer.CaptureOutput(func() {
				// _ = os.Setenv("TERM", "color")
				_ = os.Setenv("GLAMOUR_STYLE", "Notty")
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
