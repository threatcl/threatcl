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
