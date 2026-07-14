package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
)

func testDfdCommand(tb testing.TB) *DfdCommand {
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

	return &DfdCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestDfd(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	f, err := os.Open(filepath.Join(d, "out", "tm3-tm3onelegacydfd.png"))
	if err != nil {
		t.Fatalf("Error opening png: %s", err)
	}

	buffer := make([]byte, 512)
	_, err = f.Read(buffer)
	if err != nil {
		t.Fatalf("Error reading png: %s", err)
	}

	if http.DetectContentType(buffer) != "image/png" {
		t.Errorf("The output file isn't a png, it's a '%s'", http.DetectContentType(buffer))
	}

}

func TestDfdSvg(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"-format=svg",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	f, err := os.Open(filepath.Join(d, "out", "tm3-tm3onelegacydfd.svg"))
	if err != nil {
		t.Fatalf("Error opening svg: %s", err)
	}

	buffer := make([]byte, 512)
	_, err = f.Read(buffer)
	if err != nil {
		t.Fatalf("Error reading svg: %s", err)
	}

	if http.DetectContentType(buffer) != "text/xml; charset=utf-8" {
		t.Errorf("The output file isn't a svg, it's a '%s'", http.DetectContentType(buffer))
	}

}

func TestDfdDot(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"-format=dot",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}
	t.Logf("out: %s", out)

	_, err = os.Open(filepath.Join(d, "out", "tm3-tm3onelegacydfd.dot"))
	if err != nil {
		t.Fatalf("Error opening dot: %s", err)
	}
}

func TestDfdDotStdout(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=dot",
			"-stdout",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "label=\"tm3 one_Legacy DFD\"") {
		t.Errorf("%s did not contain %s", out, "label=\"tm3 one_Legacy DFD\"")
	}
}

func TestDfdDotStdoutMultipleNoIndex(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=dot",
			"-stdout",
			"./testdata/tm5.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "there's too many DFDs") {
		t.Errorf("%s did not contain %s", out, "there's too many DFDs")
	}
}

func TestDfdDotStdoutMultipleInvalidIndex(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=dot",
			"-stdout",
			"-index=100",
			"./testdata/tm5.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Index provided is inaccurate") {
		t.Errorf("%s did not contain %s", out, "Index provided is inaccurate")
	}
}

func TestDfdDotStdoutMutipleValidIndex(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=dot",
			"-stdout",
			"-index=2",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "label=\"tm5 one_Legacy DFD\"") {
		t.Errorf("%s did not contain %s", out, "label=\"tm5 one_Legacy DFD\"")
	}
}

func TestDfdOverwrite(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d),
			"-overwrite",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	f, err := os.Open(filepath.Join(d, "tm3-tm3onelegacydfd.png"))
	if err != nil {
		t.Fatalf("Error opening png: %s", err)
	}

	buffer := make([]byte, 512)
	_, err = f.Read(buffer)
	if err != nil {
		t.Fatalf("Error reading png: %s", err)
	}

	if http.DetectContentType(buffer) != "image/png" {
		t.Errorf("The output file isn't a png, it's a '%s'", http.DetectContentType(buffer))
	}

}

func TestDfdExistingDir(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d),
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "won't overwrite content") {
		t.Errorf("%s did not contain %s", out, "won't overwrite content")
	}

}

func TestDfdNoFile(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d),
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Please provide file") {
		t.Errorf("%s did not contain %s", out, "Please provide file")
	}

}

func TestDfdNoDfd(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "No DFDs found") {
		t.Errorf("%s did not contain %s", out, "No DFDs found")
	}

}

func TestDfdMissingOut(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "You must set an -outdir or -out") {
		t.Errorf("%s did not contain %s", out, "You must set an -outdir or -out")
	}

}

func TestDfdInvalidFormat(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-outdir=outdir",
			"-format=blap",
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "format must be png, dot, svg, mermaid or d2") {
		t.Errorf("%s did not contain %s", out, "format must be png, dot, svg, mermaid or d2")
	}

}

func TestDfdBothOut(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-outdir=boop",
			"-out=blep",
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "You must sent an -outdir or -out, but not both") {
		t.Errorf("%s did not contain %s", out, "You must sent an -outdir or -out, but not both")
	}

}

// func TestDfdOutWrongExt(t *testing.T) {
// 	cmd := testDfdCommand(t)
//
// 	var code int
//
// 	out := capturer.CaptureStdout(func() {
// 		code = cmd.Run([]string{
// 			"-out=blep.beep",
// 			"./testdata/tm3.hcl",
// 		})
// 	})
//
// 	if code != 1 {
// 		t.Errorf("Code did not equal 1: %d", code)
// 	}
//
// 	if !strings.Contains(out, "-out flag must end in .png") {
// 		t.Errorf("%s did not contain %s", out, "-out flag must end in .png")
// 	}
//
// }
//
// func TestDfdOutWrongExtSvg(t *testing.T) {
// 	cmd := testDfdCommand(t)
//
// 	var code int
//
// 	out := capturer.CaptureStdout(func() {
// 		code = cmd.Run([]string{
// 			"-format=svg",
// 			"-out=blep.beep",
// 			"./testdata/tm3.hcl",
// 		})
// 	})
//
// 	if code != 1 {
// 		t.Errorf("Code did not equal 1: %d", code)
// 	}
//
// 	if !strings.Contains(out, "-out flag must end in .svg") {
// 		t.Errorf("%s did not contain %s", out, "-out flag must end in .svg")
// 	}
//
// }
//
// func TestDfdOutWrongExtDot(t *testing.T) {
// 	cmd := testDfdCommand(t)
//
// 	var code int
//
// 	out := capturer.CaptureStdout(func() {
// 		code = cmd.Run([]string{
// 			"-dot",
// 			"-out=blep.beep",
// 			"./testdata/tm3.hcl",
// 		})
// 	})
//
// 	if code != 1 {
// 		t.Errorf("Code did not equal 1: %d", code)
// 	}
//
// 	if !strings.Contains(out, "-out flag must end in .dot") {
// 		t.Errorf("%s did not contain %s", out, "-out flag must end in .dot")
// 	}
//
// }

func TestDfdFoundExisting(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	_, err = os.Create(filepath.Join(d, "out.png"))
	if err != nil {
		t.Fatalf("Error creating existing file: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.png")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("'%s' already exists", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("'%s' already exists", outFile))
	}

}

func TestDfdSuccessfulOut(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.png")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}

}

func TestDfdUnSuccessfulOutMultiple(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", filepath.Join(d, "out.png")),
			"./testdata/tm5.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "there's too many DFDs") {
		t.Errorf("%s did not contain %s", out, "there's too many DFDs")
	}
}

func TestDfdUnSuccessfulOutMultipleInvalidIndex(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", filepath.Join(d, "out.png")),
			"-index=100",
			"./testdata/tm5.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Index provided is inaccurate") {
		t.Errorf("%s did not contain %s", out, "Index provided is inaccurate")
	}
}

func TestDfdSuccessfulOutMultiple(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.png")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-index=2",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}

}

func TestDfdSuccessfulOutDotMultiple(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.dot")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-index=2",
			"-format=dot",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}

}

func TestDfdSuccessfulOutSvgMultiple(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.svg")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-index=2",
			"-format=svg",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}

}

func TestDfdSuccessfulOutSvg(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.svg")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-format=svg",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}

}

func TestDfdMermaid(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"-format=mermaid",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	contents, err := os.ReadFile(filepath.Join(d, "out", "tm3-tm3onelegacydfd.mermaid"))
	if err != nil {
		t.Fatalf("Error opening mermaid: %s", err)
	}

	if !strings.Contains(string(contents), "flowchart LR") {
		t.Errorf("mermaid output missing 'flowchart LR': %s", contents)
	}
}

func TestDfdMermaidStdout(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=mermaid",
			"-stdout",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "flowchart LR") {
		t.Errorf("%s did not contain %s", out, "flowchart LR")
	}
}

func TestDfdMermaidStdoutMultipleNoIndex(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=mermaid",
			"-stdout",
			"./testdata/tm5.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "there's too many DFDs") {
		t.Errorf("%s did not contain %s", out, "there's too many DFDs")
	}
}

func TestDfdSuccessfulOutMermaid(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.mermaid")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-format=mermaid",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}
}

func TestDfdD2(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", filepath.Join(d, "out")),
			"-format=d2",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	contents, err := os.ReadFile(filepath.Join(d, "out", "tm3-tm3onelegacydfd.d2"))
	if err != nil {
		t.Fatalf("Error opening d2: %s", err)
	}

	if !strings.Contains(string(contents), "direction: right") {
		t.Errorf("d2 output missing 'direction: right': %s", contents)
	}
}

func TestDfdD2Stdout(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=d2",
			"-stdout",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "direction: right") {
		t.Errorf("%s did not contain %s", out, "direction: right")
	}
}

func TestDfdSuccessfulOutD2(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.d2")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-format=d2",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}
}

func TestDfdProtocolStyleValid(t *testing.T) {
	styles := []string{"label", "color", "both", "none"}
	for _, style := range styles {
		t.Run(style, func(t *testing.T) {
			cmd := testDfdCommand(t)

			var code int

			out := capturer.CaptureStdout(func() {
				code = cmd.Run([]string{
					"-format=dot",
					"-stdout",
					fmt.Sprintf("-protocol-style=%s", style),
					"./testdata/tm3.hcl",
				})
			})

			if code != 0 {
				t.Errorf("Code did not equal 0 for style=%s: %d", style, code)
			}

			if !strings.Contains(out, "digraph") {
				t.Errorf("style=%s output missing 'digraph': %s", style, out)
			}
		})
	}
}

func TestDfdProtocolStyleInvalid(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=dot",
			"-stdout",
			"-protocol-style=bogus",
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "-protocol-style must be label, color, both, or none") {
		t.Errorf("%s did not contain expected validation error", out)
	}
}

func TestDfdProtocolStyleDefault(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-format=dot",
			"-stdout",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "digraph") {
		t.Errorf("%s did not contain 'digraph'", out)
	}
}

func TestDfdSuccessfulOutDot(t *testing.T) {
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	outFile := filepath.Join(d, "out.dot")
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s", outFile),
			"-format=dot",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s'", outFile)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s'", outFile))
	}

}
