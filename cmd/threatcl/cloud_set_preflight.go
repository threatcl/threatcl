package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/threatcl/spec"
)

// expandPreflightGlob expands a -with glob into the sibling files for a local
// set preflight. The target file itself is excluded (it is always part of the
// set), as are non-.hcl matches (the cloud set parser is HCL-only). A glob
// that matches nothing is an error so a typo doesn't silently skip the
// preflight the user asked for.
func expandPreflightGlob(targetPath, pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid -with glob %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("-with glob %q matched no files", pattern)
	}

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", targetPath, err)
	}

	var siblings []string
	for _, m := range matches {
		if filepath.Ext(m) != ".hcl" {
			continue
		}
		absMatch, err := filepath.Abs(m)
		if err != nil {
			continue
		}
		if absMatch == absTarget {
			continue
		}
		siblings = append(siblings, m)
	}
	sort.Strings(siblings)
	return siblings, nil
}

// preflightLocalSet parses the target file together with its sibling segment
// files as ONE spec parsed set (spec.ParseHCLRawSet), mirroring the
// validation the server runs when it assembles an uploaded file with the
// model's other current segments: cross-file extends resolution, threatmodel
// name/id uniqueness, reserved id segments, the cloud namespace shape (one
// un-dotted root id; every other file's id strictly beneath it), and
// backend-block agreement. Real file paths are used as input names so a
// relative `including`/import resolves. Best-effort local feedback only —
// the server stays authoritative (it validates against the segments it
// actually stores, which the local set may not fully mirror).
func preflightLocalSet(targetPath string, siblings []string, specCfg *spec.ThreatmodelSpecConfig) error {
	files := append([]string{targetPath}, siblings...)

	type member struct {
		path string
		id   string
	}
	members := make([]member, 0, len(files))
	inputs := make([]spec.NamedInput, 0, len(files))
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}
		// Same ref-only control/threat preprocessing the server applies to
		// each segment before set validation.
		processed := preprocessHCLForControls(content)
		processed = preprocessHCLForThreats(processed)

		// File-faithful identity parse, matching the server's per-file pass:
		// learn each file's declared id and enforce one threatmodel per file.
		p := spec.NewThreatmodelParser(specCfg)
		p.SetSkipExtendsResolution(true)
		if err := p.ParseHCLRaw(processed); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		w := p.GetWrapped()
		if len(w.Threatmodels) != 1 {
			return fmt.Errorf("%s: a cloud model file must contain exactly one threat model, found %d", f, len(w.Threatmodels))
		}
		members = append(members, member{path: f, id: w.Threatmodels[0].Id})
		inputs = append(inputs, spec.NamedInput{Name: f, Content: processed})
	}

	// Cloud namespace shape: a multi-file model has exactly one root file
	// declaring an un-dotted id, and every other file's id sits strictly
	// beneath it.
	if len(members) > 1 {
		rootID, rootPath := "", ""
		for _, m := range members {
			if m.id != "" && !strings.Contains(m.id, ".") {
				if rootID != "" {
					return fmt.Errorf("both %s (id %q) and %s (id %q) declare un-dotted root ids - a multi-file model has exactly one root (default) file", rootPath, rootID, m.path, m.id)
				}
				rootID, rootPath = m.id, m.path
			}
		}
		if rootID == "" {
			for _, m := range members {
				if strings.Contains(m.id, ".") {
					return fmt.Errorf("%s declares child id %q but no file in the set declares the model's un-dotted root id - declare the root id on the model's default file first", m.path, m.id)
				}
			}
			return fmt.Errorf("a multi-file model requires ids: declare an un-dotted root id on the default file and a dotted id beneath it on each other file")
		}
		for _, m := range members {
			if m.path == rootPath {
				continue
			}
			if m.id == "" {
				return fmt.Errorf("%s declares no id - each additional file of a multi-file model must declare a dotted id beneath the root id %q (e.g. %q)", m.path, rootID, rootID+".frontend")
			}
			if !strings.HasPrefix(m.id, rootID+".") {
				return fmt.Errorf("%s declares id %q, which is not beneath the model root id %q", m.path, m.id, rootID)
			}
		}
	}

	// One spec parsed set: extends resolution (unknown targets, cycles),
	// threatmodel name and id uniqueness, and reserved id segments — exactly
	// what the server's set validation enforces via the same parser.
	setParser := spec.NewThreatmodelParser(specCfg)
	if err := setParser.ParseHCLRawSet(inputs); err != nil {
		return err
	}

	// Backend agreement: blocks are optional per file, but every declared
	// organization and threatmodel address must match.
	var org, tmShort string
	for _, b := range setParser.GetWrapped().Backends {
		if b == nil {
			continue
		}
		if b.BackendOrg != "" {
			if org == "" {
				org = b.BackendOrg
			} else if org != b.BackendOrg {
				return fmt.Errorf("backend blocks disagree on organization (%q vs %q) - all files of a model must address the same backend", org, b.BackendOrg)
			}
		}
		if b.BackendTMShort != "" {
			if tmShort == "" {
				tmShort = b.BackendTMShort
			} else if tmShort != b.BackendTMShort {
				return fmt.Errorf("backend blocks disagree on threatmodel (%q vs %q) - all files of a model must address the same backend", tmShort, b.BackendTMShort)
			}
		}
	}

	return nil
}

// runSetPreflight expands the -with glob and runs the local set preflight,
// printing the outcome. Returns false when the preflight failed and the
// command should exit non-zero.
func runSetPreflight(targetPath, withGlob string, specCfg *spec.ThreatmodelSpecConfig) bool {
	siblings, err := expandPreflightGlob(targetPath, withGlob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		return false
	}
	if err := preflightLocalSet(targetPath, siblings, specCfg); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Local set preflight failed: %s\n", err)
		return false
	}
	fmt.Printf("✓ Local set preflight passed (%d files)\n", 1+len(siblings))
	return true
}

// multiFileHint returns a one-line hint when the parsed file looks like one
// segment of a multi-file model (dotted id or extends) and no local set
// preflight was requested. Empty when the file is a plain single-file model.
func multiFileHint(wrapped *spec.ThreatmodelWrapped) string {
	if wrapped == nil || len(wrapped.Threatmodels) != 1 {
		return ""
	}
	tm := wrapped.Threatmodels[0]
	if tm.Extends == "" && !strings.Contains(tm.Id, ".") {
		return ""
	}
	reason := fmt.Sprintf("id %q", tm.Id)
	if tm.Id == "" {
		reason = fmt.Sprintf("extends %q", tm.Extends)
	}
	return fmt.Sprintf("threat model %s looks like one segment of a multi-file model; the server validates it against the model's other segments. Pass -with=<glob> to preflight the whole set locally.", reason)
}
