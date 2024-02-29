package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/xntrik/hcltm/pkg/spec"

	"github.com/kami-zh/go-capturer"
)

func testExportCommand(tb testing.TB) *ExportCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &ExportCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestExportNoArg(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Please provide a filename") {
		t.Errorf("%s did not contain %s", out, "Please provide a filename")
	}
}

func TestExportStdout(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "This is some arbitrary text") {
		t.Errorf("%s did not contain %s", out, "This is some arbitrary text")
	}
}

func TestExportBadFormat(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=bladdhg",
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Incorrect -format option") {
		t.Errorf("%s did not contain %s", out, "Incorrect -format option")
	}
}

func TestExportBadOverwrite(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	_, err = os.Create(fmt.Sprintf("%s/out.json", d))
	if err != nil {
		t.Fatalf("Error creating existing file: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-output=%s/out.json", d),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "out.json' already exists") {
		t.Errorf("%s did not contain %s", out, "out.json' already exists")
	}
}

func TestExportOtm(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=otm",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "This is some arbitrary text") {
		t.Errorf("%s did not contain %s", out, "This is some arbitrary text")
	}

}

func TestExportOtmSingle(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=otm",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "This is some arbitrary text") {
		t.Errorf("%s did not contain %s", out, "This is some arbitrary text")
	}

}

func TestExportGoodOverwrite(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	_, err = os.Create(fmt.Sprintf("%s/out.json", d))
	if err != nil {
		t.Fatalf("Error creating existing file: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testExportCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-output=%s/out.json", d),
			"-overwrite",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully wrote") {
		t.Errorf("%s did not contain %s", out, "Successfully wrote")
	}

	fileIn, err := ioutil.ReadFile(fmt.Sprintf("%s/out.json", d))
	if err != nil {
		t.Errorf("Error opening json file %s/out.json: %s", d, err)
	}

	if !strings.Contains(string(fileIn), "This is some arbitrary text") {
		t.Errorf("%s did not contain %s", string(fileIn), "This is some arbitrary text")
	}
}
