package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/xntrik/hcltm/pkg/spec"

	"github.com/kami-zh/go-capturer"
)

func TestTfRunEmpty(t *testing.T) {
	cmd := testTfCommand(t)

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

func TestTfRunNoFile(t *testing.T) {
	cmd := testTfCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{"nofile"})
	})

	if code != 1 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "no such file") {
		t.Errorf("Expected %s to contain %s", out, "no such file")
	}
}

func TestTfRunStdin(t *testing.T) {

	cases := []struct {
		name      string
		in        string
		exp       []string
		invertexp bool
		code      int
		flags     string
	}{
		{
			"aws_s3_plan",
			"./testdata/aws_s3/aws_s3.plan-json",
			[]string{
				"information_asset \"aws_s3_bucket b\"",
				"bucket: my-tf-test-bucket",
				"terraform plan"},
			false,
			0,
			"-stdin",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testTfCommand(t)

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

				if tc.flags == "" {
					code = cmd.Run([]string{
						tc.in,
					})
				} else {

					code = cmd.Run([]string{
						tc.flags,
						tc.in,
					})
				}
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			if !tc.invertexp {
				for _, exp := range tc.exp {
					if !strings.Contains(out, exp) {
						t.Errorf("Expected %s to contain %s", out, exp)
					}
				}
			} else {
				for _, exp := range tc.exp {
					if strings.Contains(out, exp) {
						t.Errorf("Was not expecting %s to contain %s", out, exp)
					}
				}
			}
		})
	}

}

func TestTfRun(t *testing.T) {

	cases := []struct {
		name      string
		in        string
		exp       []string
		invertexp bool
		code      int
		flags     string
	}{
		{
			"aws_s3_plan",
			"./testdata/aws_s3/aws_s3.plan-json",
			[]string{
				"information_asset \"aws_s3_bucket b\"",
				"bucket: my-tf-test-bucket",
				"terraform plan"},
			false,
			0,
			"",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testTfCommand(t)

			var code int

			out := capturer.CaptureStdout(func() {
				if tc.flags == "" {
					code = cmd.Run([]string{
						tc.in,
					})
				} else {

					code = cmd.Run([]string{
						tc.flags,
						tc.in,
					})
				}
			})

			if code != tc.code {
				t.Errorf("Code did not equal %d: %d", tc.code, code)
			}

			if !tc.invertexp {
				for _, exp := range tc.exp {
					if !strings.Contains(out, exp) {
						t.Errorf("Expected %s to contain %s", out, exp)
					}
				}
			} else {
				for _, exp := range tc.exp {
					if strings.Contains(out, exp) {
						t.Errorf("Was not expecting %s to contain %s", out, exp)
					}
				}
			}
		})
	}

}

func testTfCommand(tb testing.TB) *TerraformCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &TerraformCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}
