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
