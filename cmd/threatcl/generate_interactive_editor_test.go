package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testGenInteractiveEditorCommand(tb testing.TB) *GenerateInteractiveEditorCommand {
	tb.Helper()

	d, err := os.MkdirTemp("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)
	_ = os.Setenv("USERPROFILE", d)
	_ = os.Setenv("EDITOR", "cat")

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &GenerateInteractiveEditorCommand{
		specCfg:          cfg,
		GlobalCmdOptions: global,
	}
}

func TestGenIntEditorStdout(t *testing.T) {
	cmd := testGenInteractiveEditorCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Describe your threat model.") {
		t.Errorf("Expected %s to contain %s", out, "Describe your threat model.")
	}
}

func TestGenIntEditorStdoutBoiler(t *testing.T) {
	cmd := testGenInteractiveEditorCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-fullboilerplate",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "You can include variables outside your threatmodel blocks") {
		t.Errorf("Expected %s to contain %s", out, "You can include variables outside your threatmodel blocks")
	}
}

func TestGenIntEditorStdoutValidate(t *testing.T) {
	cmd := testGenInteractiveEditorCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-validate",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Describe your threat model.") {
		t.Errorf("Expected %s to contain %s", out, "Describe your threat model.")
	}
}

func TestGenIntEditorFileoutExisting(t *testing.T) {
	cmd := testGenInteractiveEditorCommand(t)

	var code int

	f, err := os.CreateTemp("", "")
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

	if !strings.Contains(out, "which already exists") {
		t.Errorf("Expected %s to contains %s", out, "which already exists")
	}
}

func TestGenIntEditorFileout(t *testing.T) {
	cmd := testGenInteractiveEditorCommand(t)

	var code int

	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating temp dir: %s", err)
	}
	defer os.RemoveAll(d)

	outFile := filepath.Join(d, "out.hcl")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully wrote to '%s", outFile)) {
		t.Errorf("Expected %s to contains %s", out, fmt.Sprintf("Successfully wrote to '%s", outFile))
	}

	hclFile, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Error reading file: %s", err)
	}

	if !strings.Contains(string(hclFile), "Describe your threat model.") {
		t.Errorf("Expected %s to contain %s", string(hclFile), "Describe your threat model.")
	}
}

// @TODO: How do I do this?
// func TestGenIntEditorStdoutValidateFail(t *testing.T) {
// 	cmd := testGenInteractiveEditorCommand(t)
//
// 	var code int
//
// 	out := capturer.CaptureStdout(func() {
// 		code = cmd.Run([]string{
// 			"-validate",
// 		})
// 	})
//
// 	if code != 0 {
// 		t.Errorf("Code did not equal 0: %d", code)
// 	}
//
// 	if !strings.Contains(out, "Describe your threat model.") {
// 		t.Errorf("Expected %s to contain %s", out, "Describe your threat model.")
// 	}
// }
