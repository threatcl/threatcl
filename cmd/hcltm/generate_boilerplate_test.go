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

func TestGenBoilerplateFileout(t *testing.T) {
	cmd := testGenBoilerplateCommand(t)

	var code int

	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file: %s", err)
	}
	defer os.Remove(f.Name())

	code = cmd.Run([]string{
		fmt.Sprintf("-out=%s", f.Name()),
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	out, err := ioutil.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("Error reading boilerplate file: %s", err)
	}

	if !strings.Contains(string(out), "There may be multiple threatmodel") {
		t.Errorf("Expected %s to contain %s", out, "There may be multiple threatmodel")
	}
}
