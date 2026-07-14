package tmloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

// writeTMFile writes content to name inside dir and returns the full path.
func writeTMFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadSetCrossFileExtends verifies that a model can `extends` a parent
// declared in a different file - impossible under per-file parsing, where each
// file's own parser errors on the missing target. It also checks that each
// resolved model is attributed back to the file that declared it, even when the
// child is discovered before the parent.
func TestLoadSetCrossFileExtends(t *testing.T) {
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("load spec config: %v", err)
	}

	dir := t.TempDir()
	// "child.hcl" sorts before "parent.hcl", so discovery yields the child
	// first - exercising order-independent extends resolution.
	writeTMFile(t, dir, "child.hcl", `
spec_version = "0.5.2"

threatmodel "Child Model" {
  id = "child"
  extends = "parent"
  author = "@test"
}
`)
	writeTMFile(t, dir, "parent.hcl", `
spec_version = "0.5.2"

threatmodel "Parent Model" {
  id = "parent"
  author = "@test"

  threat "threaty threat" {
    description = "threaty threat"
    control = "controlly control"
    stride = ["Spoofing", "Elevation of privilege"]
    information_asset_refs = []
  }
}
`)

	res, err := LoadSet(cfg, []string{dir})
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}

	origin := map[string]string{}
	byName := map[string]*spec.Threatmodel{}
	for _, lm := range res.Models {
		origin[lm.TM.Name] = filepath.Base(lm.File)
		byName[lm.TM.Name] = lm.TM
	}

	child, ok := byName["Child Model"]
	if !ok {
		t.Fatalf("Child Model not in result: %v", res.Models)
	}
	if len(child.Threats) != 1 {
		t.Errorf("child should inherit 1 threat from parent via extends, got %d", len(child.Threats))
	}
	if origin["Child Model"] != "child.hcl" {
		t.Errorf("Child Model attributed to %q, want child.hcl", origin["Child Model"])
	}
	if origin["Parent Model"] != "parent.hcl" {
		t.Errorf("Parent Model attributed to %q, want parent.hcl", origin["Parent Model"])
	}
}

// TestLoadSetDuplicateNameError verifies that the same model name across two
// files is a parse error (the set enforces uniqueness) and that the error names
// both offending files.
func TestLoadSetDuplicateNameError(t *testing.T) {
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("load spec config: %v", err)
	}

	dir := t.TempDir()
	model := `
spec_version = "0.5.2"

threatmodel "Same Name" {
  author = "@test"
}
`
	writeTMFile(t, dir, "a.hcl", model)
	writeTMFile(t, dir, "b.hcl", model)

	_, err = LoadSet(cfg, []string{dir})
	if err == nil {
		t.Fatal("expected duplicate-name error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"Same Name", "a.hcl", "b.hcl"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message should mention %q; got:\n%s", want, msg)
		}
	}
}

func TestFindFiles(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p string) {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "a.hcl"))
	write(filepath.Join(dir, "b.json"))
	write(filepath.Join(dir, "ignore.txt"))
	write(filepath.Join(sub, "c.hcl"))

	got := FindFiles([]string{dir})

	var hcl, jsonc, txt int
	for _, f := range got {
		switch filepath.Ext(f) {
		case ".hcl":
			hcl++
		case ".json":
			jsonc++
		case ".txt":
			txt++
		}
	}
	if hcl != 2 {
		t.Errorf("hcl files = %d, want 2 (incl. recursion): %v", hcl, got)
	}
	if jsonc != 1 {
		t.Errorf("json files = %d, want 1: %v", jsonc, got)
	}
	if txt != 0 {
		t.Errorf(".txt should be excluded, got %v", got)
	}
	// HCL files should come before JSON files.
	if len(got) == 3 && filepath.Ext(got[len(got)-1]) != ".json" {
		t.Errorf("expected JSON last, got order %v", got)
	}
}

func TestFindFilesSkipsNonexistent(t *testing.T) {
	got := FindFiles([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if len(got) != 0 {
		t.Errorf("nonexistent path should yield no files, got %v", got)
	}
}

func TestFindFilesExplicitFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "one.hcl")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := FindFiles([]string{p})
	if len(got) != 1 || got[0] != p {
		t.Errorf("explicit file = %v, want [%s]", got, p)
	}
}

// TestLoadExamples exercises discovery + parse against the repo's real examples.
func TestLoadExamples(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "examples")
	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("examples directory not found")
	}

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("load spec config: %v", err)
	}
	// examples/tm3.hcl imports a remote control library; spec v0.5.1 requires
	// opting in to remote imports.
	cfg.AllowRemoteImports = true

	models, err := Load(cfg, []string{examplesDir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(models) == 0 {
		t.Error("expected at least one threat model from examples")
	}
	for _, m := range models {
		if m == nil {
			t.Error("nil threat model in Load result")
		}
	}
}
