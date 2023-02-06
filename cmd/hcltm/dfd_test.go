package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/xntrik/hcltm/pkg/spec"

	"github.com/kami-zh/go-capturer"
)

func testDfdCommand(tb testing.TB) *DfdCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &DfdCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestDfd(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s/out", d),
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Successfully created") {
		t.Errorf("%s did not contain %s", out, "Successfully created")
	}

	f, err := os.Open(fmt.Sprintf("%s/out/tm3-tm2one.png", d))
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

func TestDfdDot(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s/out", d),
			"-dot",
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

	_, err = os.Open(fmt.Sprintf("%s/out/tm3-tm2onelegacydfd.dot", d))
	if err != nil {
		t.Fatalf("Error opening dot: %s", err)
	}
}

func TestDfdOverwrite(t *testing.T) {
	d, err := ioutil.TempDir("", "")
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

	f, err := os.Open(fmt.Sprintf("%s/tm3-tm2one.png", d))
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
	d, err := ioutil.TempDir("", "")
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

	if !strings.Contains(out, "Won't overwrite content") {
		t.Errorf("%s did not contain %s", out, "Won't overwrite content")
	}

}

func TestDfdNoFile(t *testing.T) {
	d, err := ioutil.TempDir("", "")
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
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s/out", d),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "No Data Flow Diagrams found in provided HCL files") {
		t.Errorf("%s did not contain %s", out, "No Data Flow Diagrams found in provided HCL files")
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

func TestDfdOutWrongExt(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-out=blep.beep",
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "-out flag must end in .png") {
		t.Errorf("%s did not contain %s", out, "-out flag must end in .png")
	}

}

func TestDfdOutWrongExtSvg(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-svg",
			"-out=blep.beep",
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "-out flag must end in .svg") {
		t.Errorf("%s did not contain %s", out, "-out flag must end in .svg")
	}

}

func TestDfdOutWrongExtDot(t *testing.T) {
	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-dot",
			"-out=blep.beep",
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "-out flag must end in .dot") {
		t.Errorf("%s did not contain %s", out, "-out flag must end in .dot")
	}

}

func TestDfdFoundExisting(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	_, err = os.Create(fmt.Sprintf("%s/out.png", d))
	if err != nil {
		t.Fatalf("Error creating existing file: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s/out.png", d),
			"./testdata/tm3.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("'%s/out.png' already exists", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("'%s/out.png' already exists", d))
	}

}

func TestDfdSuccessfulOut(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s/out.png", d),
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s/out.png'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s/out.png'", d))
	}

}

func TestDfdSuccessfulOutSvg(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s/out.svg", d),
			"-svg",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s/out.svg'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s/out.svg'", d))
	}

}

func TestDfdSuccessfulOutDot(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creatig tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDfdCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-out=%s/out.dot", d),
			"-dot",
			"./testdata/tm3.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s/out.dot'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s/out.dot'", d))
	}

}
