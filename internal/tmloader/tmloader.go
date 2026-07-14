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
	"sort"
	"strings"

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

// LoadedModel pairs a resolved threat model with the file it was declared in.
type LoadedModel struct {
	TM   *spec.Threatmodel
	File string
}

// SetResult is the outcome of LoadSet: every resolved model tagged with its
// origin file, the discovered file list, the parser that holds the merged HCL
// set (for HCL round-trip export), and the wrapped results (HCL set first, then
// one per JSON file) needed for version-constraint checks.
type SetResult struct {
	Models    []LoadedModel
	Files     []string
	HCLParser *spec.ThreatmodelParser
	Wrapped   []*spec.ThreatmodelWrapped
}

// LoadSet discovers every threat model source under paths and parses the .hcl
// files as ONE set (via spec.ParseHCLRawSet) so that cross-file `extends`
// inheritance resolves and model names/ids are unique across the whole set.
// Each .json file is parsed individually — the spec set parser is HCL-only — so
// JSON files stay independent, matching prior behavior.
//
// Every returned model is tagged with the file that declared it, so callers
// that name outputs after the source file (dfd, mermaid) or print a File column
// (list) keep working. A duplicate name/id across the HCL set is a parse error;
// the error is enriched with a per-file breakdown of the collision.
func LoadSet(specCfg *spec.ThreatmodelSpecConfig, paths []string) (*SetResult, error) {
	files := FindFiles(paths)
	res := &SetResult{Files: files}

	// Split discovered files: HCL files are parsed together as a set, JSON
	// files individually.
	var hclInputs []spec.NamedInput
	var jsonFiles []string
	for _, f := range files {
		if filepath.Ext(f) == ".json" {
			jsonFiles = append(jsonFiles, f)
			continue
		}
		content, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", f, err)
		}
		hclInputs = append(hclInputs, spec.NamedInput{Name: f, Content: content})
	}

	// The HCL set parser is always created (even with no HCL inputs) so the
	// "hcl" export format always has a parser to encode from.
	hclParser := spec.NewThreatmodelParser(specCfg)
	res.HCLParser = hclParser

	if len(hclInputs) > 0 {
		if err := hclParser.ParseHCLRawSet(hclInputs); err != nil {
			return nil, enrichSetError(err, specCfg, hclInputs)
		}
		res.Wrapped = append(res.Wrapped, hclParser.GetWrapped())

		// Attribute each resolved model back to its source file.
		origins := hclOrigins(specCfg, hclInputs)
		wrapped := hclParser.GetWrapped()
		for i := range wrapped.Threatmodels {
			tm := &wrapped.Threatmodels[i]
			res.Models = append(res.Models, LoadedModel{TM: tm, File: origins[tm.Name]})
		}
	}

	// JSON files: independent parses (no cross-file set semantics).
	for _, jf := range jsonFiles {
		jp := spec.NewThreatmodelParser(specCfg)
		if err := jp.ParseFile(jf, false); err != nil {
			return nil, fmt.Errorf("error parsing %s: %w", jf, err)
		}
		jw := jp.GetWrapped()
		res.Wrapped = append(res.Wrapped, jw)
		for i := range jw.Threatmodels {
			res.Models = append(res.Models, LoadedModel{TM: &jw.Threatmodels[i], File: jf})
		}
	}

	return res, nil
}

// hclOrigins maps each threat model name to the HCL file that declares it. Each
// input is parsed on its own with extends resolution disabled, so a model that
// extends a parent in another file parses cleanly and we still learn its name.
// Because the authoritative set parse enforces unique names, a name maps back to
// exactly one file. Best-effort: an input that fails to parse in isolation is
// skipped (the set parse has already succeeded, so those models simply carry an
// empty File).
func hclOrigins(specCfg *spec.ThreatmodelSpecConfig, inputs []spec.NamedInput) map[string]string {
	origins := map[string]string{}
	for _, in := range inputs {
		p := spec.NewThreatmodelParser(specCfg)
		p.SetSkipExtendsResolution(true)
		if err := p.ParseHCLRaw(in.Content); err != nil {
			continue
		}
		w := p.GetWrapped()
		for i := range w.Threatmodels {
			origins[w.Threatmodels[i].Name] = in.Name
		}
	}
	return origins
}

// enrichSetError augments a set-parse error with a per-file breakdown when the
// failure is a duplicate name/id across inputs — the raw spec error names the
// offending model but not which files collide. Non-duplicate errors are wrapped
// unchanged.
func enrichSetError(err error, specCfg *spec.ThreatmodelSpecConfig, inputs []spec.NamedInput) error {
	if !strings.Contains(err.Error(), "duplicate") {
		return fmt.Errorf("error parsing threat model set: %w", err)
	}

	names := map[string][]string{}
	ids := map[string][]string{}
	for _, in := range inputs {
		p := spec.NewThreatmodelParser(specCfg)
		p.SetSkipExtendsResolution(true)
		if perr := p.ParseHCLRaw(in.Content); perr != nil {
			continue
		}
		w := p.GetWrapped()
		for i := range w.Threatmodels {
			tm := &w.Threatmodels[i]
			names[tm.Name] = append(names[tm.Name], in.Name)
			if tm.Id != "" {
				ids[tm.Id] = append(ids[tm.Id], in.Name)
			}
		}
	}

	var b strings.Builder
	// TrimRight drops the multierror's trailing blank lines so the breakdown
	// below reads as one message.
	fmt.Fprintf(&b, "error parsing threat model set: %s", strings.TrimRight(err.Error(), "\n"))
	b.WriteString("\n\nEach threat model must have a unique name and id when files are parsed together as a set.")
	dupLines := append(duplicateLines("name", names), duplicateLines("id", ids)...)
	if len(dupLines) > 0 {
		b.WriteString("\nDuplicates found:")
		for _, l := range dupLines {
			b.WriteString("\n  - " + l)
		}
	}
	return fmt.Errorf("%s", b.String())
}

// duplicateLines returns a sorted "kind \"value\" in: fileA, fileB" line for
// each value declared in more than one file.
func duplicateLines(kind string, m map[string][]string) []string {
	var out []string
	for value, fileList := range m {
		if len(fileList) > 1 {
			out = append(out, fmt.Sprintf("%s %q in: %s", kind, value, strings.Join(fileList, ", ")))
		}
	}
	sort.Strings(out)
	return out
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
