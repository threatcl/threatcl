package tmloader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/threatcl/spec"
)

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
