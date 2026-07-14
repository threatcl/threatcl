package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

const preflightRootHCL = `spec_version = "0.6.0"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "App" {
  id = "app"
  author = "test@example.com"
  description = "Root segment"
}
`

const preflightChildHCL = `spec_version = "0.6.0"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "App Frontend" {
  id = "app.frontend"
  extends = "app"
  author = "test@example.com"
  description = "Frontend segment"
}
`

// writePreflightFiles writes each name->content pair into a temp dir and
// returns the dir and the full path of each file in input order.
func writePreflightFiles(t *testing.T, files map[string]string, order ...string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(order))
	for _, name := range order {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(files[name]), 0600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
		paths = append(paths, p)
	}
	return dir, paths
}

func preflightSpecCfg(t *testing.T) *spec.ThreatmodelSpecConfig {
	t.Helper()
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}
	return cfg
}

func TestPreflightLocalSet(t *testing.T) {
	tests := []struct {
		name        string
		files       map[string]string
		target      string
		siblings    []string
		expectedErr string
	}{
		{
			name: "valid root plus child passes",
			files: map[string]string{
				"root.hcl":     preflightRootHCL,
				"frontend.hcl": preflightChildHCL,
			},
			target:   "frontend.hcl",
			siblings: []string{"root.hcl"},
		},
		{
			name: "unknown extends target fails",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"frontend.hcl": strings.Replace(preflightChildHCL,
					`extends = "app"`, `extends = "missing"`, 1),
			},
			target:      "frontend.hcl",
			siblings:    []string{"root.hcl"},
			expectedErr: "extends references unknown threat model id 'missing'",
		},
		{
			name: "duplicate threatmodel names fail",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"frontend.hcl": strings.Replace(preflightChildHCL,
					`threatmodel "App Frontend"`, `threatmodel "App"`, 1),
			},
			target:      "frontend.hcl",
			siblings:    []string{"root.hcl"},
			expectedErr: "duplicate found",
		},
		{
			name: "reserved id segment fails",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"frontend.hcl": strings.Replace(preflightChildHCL,
					`id = "app.frontend"`, `id = "app.threats"`, 1),
			},
			target:      "frontend.hcl",
			siblings:    []string{"root.hcl"},
			expectedErr: "reserved segment",
		},
		{
			name: "child without a root file fails",
			files: map[string]string{
				"frontend.hcl": preflightChildHCL,
				"backend.hcl": strings.NewReplacer(
					`id = "app.frontend"`, `id = "app.backend"`,
					`threatmodel "App Frontend"`, `threatmodel "App Backend"`,
				).Replace(preflightChildHCL),
			},
			target:      "frontend.hcl",
			siblings:    []string{"backend.hcl"},
			expectedErr: "declare the root id on the model's default file first",
		},
		{
			name: "two roots fail",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"other.hcl": strings.NewReplacer(
					`id = "app"`, `id = "other"`,
					`threatmodel "App"`, `threatmodel "Other"`,
				).Replace(preflightRootHCL),
			},
			target:      "root.hcl",
			siblings:    []string{"other.hcl"},
			expectedErr: "exactly one root",
		},
		{
			name: "sibling without id fails",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"frontend.hcl": strings.Replace(preflightChildHCL,
					"  id = \"app.frontend\"\n  extends = \"app\"\n", "", 1),
			},
			target:      "root.hcl",
			siblings:    []string{"frontend.hcl"},
			expectedErr: "must declare a dotted id beneath the root id",
		},
		{
			name: "id not beneath root fails",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"frontend.hcl": strings.Replace(preflightChildHCL,
					`id = "app.frontend"`, `id = "elsewhere.frontend"`, 1),
			},
			target:      "frontend.hcl",
			siblings:    []string{"root.hcl"},
			expectedErr: "not beneath the model root id",
		},
		{
			name: "backend threatmodel disagreement fails",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
				"frontend.hcl": strings.Replace(preflightChildHCL,
					`threatmodel = "my-tm"`, `threatmodel = "other-tm"`, 1),
			},
			target:      "frontend.hcl",
			siblings:    []string{"root.hcl"},
			expectedErr: "backend blocks disagree on threatmodel",
		},
		{
			name: "more than one threatmodel per file fails",
			files: map[string]string{
				"root.hcl": preflightRootHCL + `
threatmodel "Extra" {
  author = "test@example.com"
  description = "Extra"
}
`,
				"frontend.hcl": preflightChildHCL,
			},
			target:      "frontend.hcl",
			siblings:    []string{"root.hcl"},
			expectedErr: "must contain exactly one threat model",
		},
		{
			name: "single file with no siblings passes",
			files: map[string]string{
				"root.hcl": preflightRootHCL,
			},
			target: "root.hcl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order := append([]string{tt.target}, tt.siblings...)
			dir, _ := writePreflightFiles(t, tt.files, order...)

			var siblings []string
			for _, s := range tt.siblings {
				siblings = append(siblings, filepath.Join(dir, s))
			}

			err := preflightLocalSet(filepath.Join(dir, tt.target), siblings, preflightSpecCfg(t))

			if tt.expectedErr == "" {
				if err != nil {
					t.Fatalf("expected preflight to pass, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedErr)
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error containing %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestExpandPreflightGlob(t *testing.T) {
	dir, paths := writePreflightFiles(t, map[string]string{
		"frontend.hcl": preflightChildHCL,
		"root.hcl":     preflightRootHCL,
	}, "frontend.hcl", "root.hcl")
	target := paths[0]

	// A JSON file in the same dir must be ignored (the set parser is HCL-only).
	if err := os.WriteFile(filepath.Join(dir, "notes.json"), []byte(`{}`), 0600); err != nil {
		t.Fatalf("failed to write json file: %v", err)
	}

	siblings, err := expandPreflightGlob(target, filepath.Join(dir, "*"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(siblings) != 1 || filepath.Base(siblings[0]) != "root.hcl" {
		t.Errorf("expected only root.hcl (target and non-hcl excluded), got %v", siblings)
	}

	if _, err := expandPreflightGlob(target, filepath.Join(dir, "nope-*.hcl")); err == nil {
		t.Error("expected error for glob matching no files")
	} else if !strings.Contains(err.Error(), "matched no files") {
		t.Errorf("expected 'matched no files' error, got %q", err.Error())
	}
}

func TestMultiFileHint(t *testing.T) {
	tests := []struct {
		name     string
		tm       spec.Threatmodel
		expected string
	}{
		{
			name:     "dotted id hints",
			tm:       spec.Threatmodel{Name: "App Frontend", Id: "app.frontend"},
			expected: `id "app.frontend"`,
		},
		{
			name:     "extends without id hints",
			tm:       spec.Threatmodel{Name: "App Frontend", Extends: "app"},
			expected: `extends "app"`,
		},
		{
			name: "plain model no hint",
			tm:   spec.Threatmodel{Name: "App"},
		},
		{
			name: "un-dotted id no hint",
			tm:   spec.Threatmodel{Name: "App", Id: "app"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := &spec.ThreatmodelWrapped{Threatmodels: []spec.Threatmodel{tt.tm}}
			hint := multiFileHint(wrapped)
			if tt.expected == "" {
				if hint != "" {
					t.Errorf("expected no hint, got %q", hint)
				}
				return
			}
			if !strings.Contains(hint, tt.expected) {
				t.Errorf("expected hint containing %q, got %q", tt.expected, hint)
			}
		})
	}
}
