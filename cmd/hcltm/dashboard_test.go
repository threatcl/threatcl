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

func testDashboardCommand(tb testing.TB) *DashboardCommand {
	tb.Helper()

	d, err := ioutil.TempDir("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	defer os.RemoveAll(d)

	global := &GlobalCmdOptions{}

	return &DashboardCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestDashboardMissingOutdir(t *testing.T) {
	cmd := testDashboardCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "You must set an -outdir") {
		t.Errorf("Expected %s to contain %s", out, "You must set an -outdir")
	}
}

func TestDashboardMissingfiles(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDashboardCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d),
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Usage: hcltm dashboard") {
		t.Errorf("Expected %s to contain %s", out, "Usage: hcltm dashboard")
	}
}

func TestDashboard(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDashboardCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s/out", d),
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Created the '%s/out' directory", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Created the '%s/out' directory", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/out/dashboard.md", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "tm1-tm1one.md") {
		t.Errorf("Expected %s to contain %s", dbfile, "tm1-tm1one.md")
	}

}

func TestDashboardWithDfd(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDashboardCommand(t)

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

	if !strings.Contains(out, fmt.Sprintf("Created the '%s/out' directory", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Created the '%s/out' directory", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/out/dashboard.md", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "tm3-tm2one.md") {
		t.Errorf("Expected %s to contain %s", dbfile, "tm3-tm2one.md")
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

func TestDashboardOverwrite(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDashboardCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d),
			"-overwrite",
			"./testdata/tm2.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Writing dashboard markdown files to '%s' and overwriting existing files", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Writing dashboard markdown files to '%s' and overwriting existing files", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/dashboard.md", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "tm2-tm2one.md") {
		t.Errorf("Expected %s to contain %s", dbfile, "tm2-tm2one.md")
	}

}

func TestDashboardExistingDir(t *testing.T) {
	d, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Error creating tmp dir: %s", err)
	}

	defer os.RemoveAll(d)

	cmd := testDashboardCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Won't overwrite content in the") {
		t.Errorf("%s did not contain %s", out, "Won't overwrite content in the")
	}

}

func TestDashboardExistingFile(t *testing.T) {
	d, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating tmp file: %s", err)
	}

	defer os.Remove(d.Name())

	cmd := testDashboardCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			fmt.Sprintf("-outdir=%s", d.Name()),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "You're trying to output to a file that exists") {
		t.Errorf("%s did not contain %s", out, "You're trying to output to a file that exists")
	}

}
