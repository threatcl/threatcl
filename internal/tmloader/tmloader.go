// Package tmloader is the single seam for turning a set of paths (files or
// directories) into parsed threat models. Both the long-running cache
// (internal/cache, used by the server and query commands) and the one-shot CLI
// commands (view, dfd, mermaid, export, dashboard, list, validate) discover and
// parse threat model files — previously each had its own copy of the file-walk
// logic. Concentrating discovery (FindFiles) and parsing (Load) here means the
// rules for "what counts as a threat model file" and "how a file becomes a set
// of threat models" live in one place.
package tmloader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/threatcl/spec"
)

// FindFiles expands a list of paths (files or directories) into the set of
// threat model source files (.hcl and .json). Directories are walked
// recursively. Paths that don't exist are skipped. HCL files are returned
// before JSON files, preserving the previous cmd/threatcl ordering.
func FindFiles(paths []string) []string {
	out := findByExt(paths, ".hcl")
	out = append(out, findByExt(paths, ".json")...)
	return out
}

func findByExt(paths []string, ext string) []string {
	out := []string{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if filepath.Ext(p) == ext {
				out = append(out, p)
			}
			continue
		}
		// Recurse into directories, skipping entries we can't walk.
		_ = filepath.Walk(p, func(path string, wi os.FileInfo, werr error) error {
			if werr != nil {
				return nil
			}
			if !wi.IsDir() && filepath.Ext(path) == ext {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}

// Load discovers every threat model source under paths and parses each one,
// returning the combined set of threat models. A parse failure on any file
// stops the load and returns an error naming that file (matching the cache's
// previous behavior). The returned slice preserves file-discovery order.
func Load(specCfg *spec.ThreatmodelSpecConfig, paths []string) ([]*spec.Threatmodel, error) {
	var models []*spec.Threatmodel
	for _, file := range FindFiles(paths) {
		wrapped, err := ParseFile(specCfg, file)
		if err != nil {
			return nil, fmt.Errorf("error loading %s: %w", file, err)
		}
		for i := range wrapped.Threatmodels {
			models = append(models, &wrapped.Threatmodels[i])
		}
	}
	return models, nil
}

// ParseFile parses a single threat model file into its wrapped representation.
func ParseFile(specCfg *spec.ThreatmodelSpecConfig, path string) (*spec.ThreatmodelWrapped, error) {
	parser := spec.NewThreatmodelParser(specCfg)
	if err := parser.ParseFile(path, false); err != nil {
		return nil, err
	}
	wrapped := parser.GetWrapped()
	if wrapped == nil {
		return nil, fmt.Errorf("no threat models found in %s", path)
	}
	return wrapped, nil
}
