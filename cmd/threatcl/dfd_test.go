package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"

	"github.com/zenizh/go-capturer"
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

	f, err := os.Open(fmt.Sprintf("%s/out/tm3-tm2onelegacydfd.png", d))
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

	f, err := os.Open(fmt.Sprintf("%s/out/tm3-tm2onelegacydfd.svg", d))
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

	_, err = os.Open(fmt.Sprintf("%s/out/tm3-tm2onelegacydfd.dot", d))
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

	if !strings.Contains(out, "label=\"tm2 one_Legacy DFD\"") {
		t.Errorf("%s did not contain %s", out, "label=\"tm2 one_Legacy DFD\"")
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

	if !strings.Contains(out, "label=\"tm2 one_Legacy DFD\"") {
		t.Errorf("%s did not contain %s", out, "label=\"tm2 one_Legacy DFD\"")
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

	f, err := os.Open(fmt.Sprintf("%s/tm3-tm2onelegacydfd.png", d))
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

	if !strings.Contains(out, "won't overwrite content") {
		t.Errorf("%s did not contain %s", out, "won't overwrite content")
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

	if !strings.Contains(out, "format must be png, dot or svg") {
		t.Errorf("%s did not contain %s", out, "format must be png, dot or svg")
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

func TestDfdUnSuccessfulOutMultiple(t *testing.T) {
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
			"-index=2",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s/out.png'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s/out.png'", d))
	}

}

func TestDfdSuccessfulOutDotMultiple(t *testing.T) {
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
			"-index=2",
			"-format=dot",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s/out.dot'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s/out.dot'", d))
	}

}

func TestDfdSuccessfulOutSvgMultiple(t *testing.T) {
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
			"-index=2",
			"-format=svg",
			"./testdata/tm5.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully created '%s/out.svg'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Successfully created '%s/out.svg'", d))
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
			"-format=svg",
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
			"-format=dot",
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
