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

	if !strings.Contains(out, "Usage: threatcl dashboard") {
		t.Errorf("Expected %s to contain %s", out, "Usage: threatcl dashboard")
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

func TestDashboardCustomExtension(t *testing.T) {
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
			"-out-ext=rst",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Created the '%s/out' directory", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Created the '%s/out' directory", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/out/dashboard.rst", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "tm1-tm1one.rst") {
		t.Errorf("Expected %s to contain %s", dbfile, "tm1-tm1one.rst")
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

	if !strings.Contains(out, "won't overwrite content in the") {
		t.Errorf("%s did not contain %s", out, "won't overwrite content in the")
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

	if !strings.Contains(out, "you're trying to output to a file that exists") {
		t.Errorf("%s did not contain %s", out, "you're trying to output to a file that exists")
	}

}

func TestDashboardDbTemplateNA(t *testing.T) {
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
			"-dashboard-template=dne.tpl",
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Could not find dashboard-template file") {
		t.Errorf("%s did not contain %s", out, "Could not find dashboard-template file")
	}
}

func TestDashboardDbTemplateExistingDir(t *testing.T) {
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
			fmt.Sprintf("-dashboard-template=%s", d),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "dashboard-template can't be set to a directory") {
		t.Errorf("%s did not contain %s", out, "dashboard-template can't be set to a directory")
	}
}

func TestDashboardDbTemplate(t *testing.T) {
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
			"-dashboard-template=./testdata/db.tpl",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Created the '%s'", d)) {
		t.Errorf("%s did not contains %s", out, fmt.Sprintf("Created the '%s'", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/dashboard.md", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "HCLTM Custom Dashboard") {
		t.Errorf("Expected %s to contain %s", dbfile, "HCLTM Custom Dashboard")
	}

}

func TestDashboardDbBrokenTemplate(t *testing.T) {
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
			"-dashboard-template=./testdata/db-broken.tpl",
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "unclosed action started at DashboardTemplate:11") {
		t.Errorf("%s did not contains %s", out, "unclosed action started at DashboardTemplate:11")
	}
}

func TestDashboardTmTemplateNA(t *testing.T) {
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
			"-threatmodel-template=dne.tpl",
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Could not find threatmodel-template file") {
		t.Errorf("%s did not contain %s", out, "Could not find threatmodel-template file")
	}
}

func TestDashboardTmTemplateExistingDir(t *testing.T) {
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
			fmt.Sprintf("-threatmodel-template=%s", d),
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "threatmodel-template can't be set to a directory") {
		t.Errorf("%s did not contain %s", out, "threatmodel-template can't be set to a directory")
	}
}

func TestDashboardTmTemplate(t *testing.T) {
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
			"-threatmodel-template=./testdata/tm.tpl",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Created the '%s'", d)) {
		t.Errorf("%s did not contains %s", out, fmt.Sprintf("Created the '%s'", d))
	}

	tmfile, err := ioutil.ReadFile(fmt.Sprintf("%s/tm1-tmtm1two.md", d))
	if err != nil {
		t.Fatalf("Error opening tm file: %s", err)
	}

	if !strings.Contains(string(tmfile), "CUSTOM TM THEME") {
		t.Errorf("Expected %s to contain %s", tmfile, "CUSTOM TM THEME")
	}

}

func TestDashboardTmBrokenTemplate(t *testing.T) {
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
			"-threatmodel-template=./testdata/tm-broken.tpl",
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, "Error parsing template: template: TMTemplate:3") {
		t.Errorf("%s did not contains %s", out, "Error parsing template: template: TMTemplate:3")
	}
}

func TestDashboardInvalidDashboardfile(t *testing.T) {
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
			"-dashboard-filename=./testdata",
			"./testdata/tm1.hcl",
		})
	})

	if code != 1 {
		t.Errorf("Code did not equal 1: %d", code)
	}

	if !strings.Contains(out, "Error with -dashboard-filename") {
		t.Errorf("%s did not contains %s", out, "Error with -dashboard-filename")
	}

}

func TestDashboardValidDashboardfile(t *testing.T) {
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
			"-dashboard-filename=index",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Created the '%s'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Created the '%s'", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/index.md", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "# HCLTM Dashboard") {
		t.Errorf("Expected %s to contain %s", dbfile, "# HCLTM Dashboard")
	}

}

func TestDashboardValidHtmlfile(t *testing.T) {
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
			"-dashboard-filename=index",
			"-dashboard-html",
			"./testdata/tm1.hcl",
		})
	})

	if code != 0 {
		t.Errorf("Code did not equal 0: %d", code)
	}

	if !strings.Contains(out, fmt.Sprintf("Created the '%s'", d)) {
		t.Errorf("%s did not contain %s", out, fmt.Sprintf("Created the '%s'", d))
	}

	dbfile, err := ioutil.ReadFile(fmt.Sprintf("%s/index.html", d))
	if err != nil {
		t.Fatalf("Error opening dashboard file: %s", err)
	}

	if !strings.Contains(string(dbfile), "HCLTM Dashboard") {
		t.Errorf("Expected %s to contain %s", dbfile, "HCLTM Dashboard")
	}

}
