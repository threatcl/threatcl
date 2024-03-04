package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testListCommand(tb testing.TB) *ListCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &ListCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestListRunEmpty(t *testing.T) {
	cmd := testListCommand(t)

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

func TestListRun(t *testing.T) {

	cases := []struct {
		name      string
		in        string
		exp       string
		invertexp bool
		code      int
		flags     string
	}{
		{
			"list_one_file",
			"./testdata/tm1.hcl",
			"tm tm1 two",
			false,
			0,
			"",
		},
		{
			"no-header",
			"./testdata/",
			"#  File",
			true,
			0,
			"-noheader",
		},
		{
			"list_dir",
			"./testdata/",
			"testdata/tm2",
			false,
			0,
			"",
		},
		{
			"list_size",
			"./testdata/tm1.hcl",
			"Small",
			false,
			0,
			"-fields=size",
		},
		{
			"list_assetcount",
			"./testdata/tm1.hcl",
			"Asset Count",
			false,
			0,
			"-fields=assetcount",
		},
		{
			"list_threatcount",
			"./testdata/tm1.hcl",
			"Threat Count",
			false,
			0,
			"-fields=threatcount",
		},
		{
			"list_usecasecount",
			"./testdata/tm1.hcl",
			"Use Case Count",
			false,
			0,
			"-fields=usecasecount",
		},
		{
			"list_tpdcount",
			"./testdata/tm1.hcl",
			"Third Party Dep Count",
			false,
			0,
			"-fields=tpdcount",
		},
		{
			"list_internetfacing",
			"./testdata/tm1.hcl",
			"Internet Facing",
			false,
			0,
			"-fields=internetfacing",
		},
		{
			"list_newinitiative",
			"./testdata/tm1.hcl",
			"New Initiative",
			false,
			0,
			"-fields=newinitiative",
		},
		{
			"list_size_noheader",
			"./testdata/tm1.hcl",
			"Size",
			true,
			0,
			"-fields=size -noheader",
		},
		{
			"list_exclusion_count",
			"./testdata/tm1.hcl",
			"2",
			false,
			0,
			"-fields=exclusioncount",
		},
		{
			"valid_dfd_exists",
			"./testdata/tm3.hcl",
			"1",
			false,
			0,
			"-fields=dfd",
		},
		{
			"no_valid_dfd_exists",
			"./testdata/tm1.hcl",
			"0",
			false,
			0,
			"-fields=dfd",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cmd := testListCommand(t)

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
