package main

import (
	"os"
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

func TestFindHclFiles(t *testing.T) {
	in := []string{
		"./testdata/tm1.hcl",
		"./testdata/tm2.hcl",
	}

	out := findHclFiles(in)

	if len(out) != 2 {
		t.Errorf("There should be two files")
	}

	out = findHclFiles([]string{"./testdata/"})

	if len(out) != 3 {
		t.Errorf("There should be three files")
	}
}

func TestConfigFileLocation(t *testing.T) {
	_ = os.Setenv("HOME", "/tmp/")
	f, err := configFileLocation()

	if err != nil {
		t.Errorf("Error getting cfg location: %s", err)
	}

	if f != "/tmp/.hcltmrc" {
		t.Errorf("%s didn't equal '/tmp/.hcltmrc'", f)
	}

}

func TestNonExistingConfigFileLocation(t *testing.T) {
	_ = os.Setenv("HOME", "")
	_, err := configFileLocation()

	if err != nil && !strings.Contains(err.Error(), "Can't find home directory") {
		t.Errorf("Unusal error handling a non-existant cfg location: %s", err)
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
