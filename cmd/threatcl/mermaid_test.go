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

func testMermaidCommand(tb testing.TB) *MermaidCommand {
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

	return &MermaidCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestMermaidStdout(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"./testdata/tm_mermaid.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "sequenceDiagram") {
		t.Errorf("%s did not contain %s", out, "sequenceDiagram")
	}

	if !strings.Contains(out, "Auth-->>App: token") {
		t.Errorf("%s did not contain %s", out, "Auth-->>App: token")
	}

	// We don't render or wrap the content, so there should be no
	// "Successfully created" chatter mixed into the piped source.
	if strings.Contains(out, "Successfully created") {
		t.Errorf("stdout output should not contain creation chatter: %s", out)
	}
}

func TestMermaidStdoutExplicitFlag(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-stdout",
			"./testdata/tm_mermaid.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "sequenceDiagram") {
		t.Errorf("%s did not contain %s", out, "sequenceDiagram")
	}
}

func TestMermaidStdoutMultipleNoIndex(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"./testdata/tm_mermaid_multi.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "there's too many mermaid diagrams") {
		t.Errorf("%s did not contain %s", out, "there's too many mermaid diagrams")
	}

	if !strings.Contains(out, "1: mermaid multi_Login sequence") {
		t.Errorf("%s did not contain the diagram listing", out)
	}
}

func TestMermaidStdoutMultipleInvalidIndex(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-index=100",
			"./testdata/tm_mermaid_multi.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Index provided is inaccurate") {
		t.Errorf("%s did not contain %s", out, "Index provided is inaccurate")
	}
}

func TestMermaidStdoutMultipleValidIndex(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-index=2",
			"./testdata/tm_mermaid_multi.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "stateDiagram-v2") {
		t.Errorf("%s did not contain %s", out, "stateDiagram-v2")
	}

	// The first diagram should not leak into a single-index selection.
	if strings.Contains(out, "sequenceDiagram") {
		t.Errorf("%s should not contain the unselected diagram", out)
	}
}

func TestMermaidOutFile(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMermaidCommand(t)

	outFile := filepath.Join(d, "out.mmd")

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"./testdata/tm_mermaid.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	contents, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Error opening mermaid: %s", err)
	}

	if !strings.Contains(string(contents), "sequenceDiagram") {
		t.Errorf("mermaid output missing 'sequenceDiagram': %s", contents)
	}

	// Output should end with exactly one trailing newline for clean piping.
	if !strings.HasSuffix(string(contents), "token\n") {
		t.Errorf("mermaid output should end with a single trailing newline: %q", string(contents))
	}
}

func TestMermaidOutFileMultipleNoIndex(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", filepath.Join(d, "out.mmd")),
			"./testdata/tm_mermaid_multi.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "there's too many mermaid diagrams") {
		t.Errorf("%s did not contain %s", out, "there's too many mermaid diagrams")
	}
}

func TestMermaidOutFileMultipleValidIndex(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMermaidCommand(t)

	outFile := filepath.Join(d, "out.mmd")

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-index=2",
			"./testdata/tm_mermaid_multi.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	contents, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Error opening mermaid: %s", err)
	}

	if !strings.Contains(string(contents), "stateDiagram-v2") {
		t.Errorf("mermaid output missing 'stateDiagram-v2': %s", contents)
	}
}

func TestMermaidOutDir(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"./testdata/tm_mermaid_multi.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	one, err := os.ReadFile(filepath.Join(d, "out", "tm_mermaid_multi-mermaidmultiloginsequence.mmd"))
	if err != nil {
		t.Fatalf("Error opening first mermaid file: %s", err)
	}
	if !strings.Contains(string(one), "sequenceDiagram") {
		t.Errorf("first mermaid file missing 'sequenceDiagram': %s", one)
	}

	two, err := os.ReadFile(filepath.Join(d, "out", "tm_mermaid_multi-mermaidmultistatemachine.mmd"))
	if err != nil {
		t.Fatalf("Error opening second mermaid file: %s", err)
	}
	if !strings.Contains(string(two), "stateDiagram-v2") {
		t.Errorf("second mermaid file missing 'stateDiagram-v2': %s", two)
	}
}

func TestMermaidOutDirOverwrite(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}
	defer os.RemoveAll(d)

	cmd := testMermaidCommand(t)

	args := []string{
		fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
		"./testdata/tm_mermaid.hcl",
	}

	var code int
	_ = capturer.CaptureStdout(func() {
		code = cmd.Run(args)
	})
	if code != 0 {
		t.Fatalf("first run code did not equal 0: %d", code)
	}

	// Re-running without -overwrite should fail because the file exists.
	cmd = testMermaidCommand(t)
	out := capturer.CaptureStdout(func() {
		code = cmd.Run(args)
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "already exists") {
		t.Errorf("%s did not contain %s", out, "already exists")
	}

	// With -overwrite it should succeed.
	cmd = testMermaidCommand(t)
	out = capturer.CaptureStdout(func() {
		code = cmd.Run(append([]string{"-overwrite"}, args...))
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}
}

func TestMermaidNoFile(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Please provide file(s)") {
		t.Errorf("%s did not contain %s", out, "Please provide file(s)")
	}
}

func TestMermaidNoMermaid(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "No mermaid diagrams found") {
		t.Errorf("%s did not contain %s", out, "No mermaid diagrams found")
	}
}

func TestMermaidBothOut(t *testing.T) {
	cmd := testMermaidCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-out=out.mmd",
			"-outdir=outdir",
			"./testdata/tm_mermaid.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "but not both") {
		t.Errorf("%s did not contain %s", out, "but not both")
	}
}
