package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testGenBoilerplateCommand(tb testing.TB) *GenerateBoilerplateCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &GenerateBoilerplateCommand{
		specCfg:          cfg,
		GlobalCmdOptions: global,
	}
}

func TestGenBoilerplateStdout(t *testing.T) {
	cmd := testGenBoilerplateCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "There may be multiple threatmodel") {
		t.Errorf("Expected %s to contain %s", out, "There may be multiple threatmodel")
	}
}

func TestGenBoilerplateFileoutExisting(t *testing.T) {
	cmd := testGenBoilerplateCommand(t)

	var code int

	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err)
	}
	defer os.Remove(f.Name())

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", f.Name()),
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	// out, err := ioutil.ReadFile(f.Name())
	// if err != nil {
	// 	t.Fatalf("Error reading boilerplate file: %s", err)
	// }

	// if !strings.Contains(string(out), "There may be multiple threatmodel") {
	// 	t.Errorf("Expected %s to contain %s", out, "There may be multiple threatmodel")
	// }

	if !strings.Contains(out, "which already exists") {
		t.Errorf("Expected %s to contains %s", out, "which already exists")
	}
}

func TestGenBoilerplateFileout(t *testing.T) {
	cmd := testGenBoilerplateCommand(t)

	var code int

	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating temp dir: %s", err)
	}
	defer os.RemoveAll(d)

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s/out.hcl", d),
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully wrote to '%s/out.hcl", d)) {
		t.Errorf("Expected %s to contains %s", out, fmt.Sprintf("Successfully wrote to '%s/out.hcl", d))
	}

	hclFile, err := ioutil.ReadFile(fmt.Sprintf("%s/out.hcl", d))
	if err != nil {
		t.Fatalf("Error reading boilerplate file: %s", err)
	}

	if !strings.Contains(string(hclFile), "There may be multiple threatmodel") {
		t.Errorf("Expected %s to contain %s", string(hclFile), "There may be multiple threatmodel")
	}
}
