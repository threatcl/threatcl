package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/threatcl/spec"
)

// runCloudValidateDiff downloads the current cloud version of the threat model
// HCL, prints a semantic/structural summary of how it differs from the local
// file, then prints a colored unified (git-style) text diff.
//
// Orientation throughout: the cloud version is the "from" side and the local
// file is the "to" side, matching the git-style "these are my local changes"
// mental model. So additions ("+") are content present in the local file but not
// in the cloud version, removals ("-") are cloud-only, and "~" marks entities
// present in both but changed.
func runCloudValidateDiff(
	client *CloudClient,
	modelIdOrSlug, filePath string,
	localWrapped *spec.ThreatmodelWrapped,
	specCfg *spec.ThreatmodelSpecConfig,
) error {
	// Re-read the raw local bytes (the same content validateThreatModel hashed).
	localRaw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading local file: %w", err)
	}

	// Download the current cloud HCL. URL shape matches 'cloud export'.
	cloudRaw, err := client.DownloadContent(client.DownloadModelURL(modelIdOrSlug))
	if err != nil {
		return fmt.Errorf("downloading cloud version: %w", err)
	}

	fmt.Println()
	fmt.Println("Differences between local file and the latest cloud version:")
	fmt.Println()

	// 1) Semantic/structural summary first (best effort: a parse failure on the
	// cloud side must not stop us from rendering the raw text diff below).
	fmt.Println("Structural summary:")
	cloudWrapped, parseErr := parseCloudHCL(cloudRaw, modelIdOrSlug, specCfg)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "⚠ Warning: could not parse cloud version for semantic diff: %s\n", parseErr)
	} else {
		summary := semanticDiff(localWrapped, cloudWrapped)
		if len(summary) == 0 {
			fmt.Println("  (no structural differences; only formatting or whitespace differs)")
		} else {
			for _, line := range summary {
				fmt.Println("  " + line)
			}
		}
	}
	fmt.Println()

	// 2) Unified text diff second. The cloud version is the "from" side and the
	// local file the "to" side, so "+" lines are your local additions.
	fmt.Println("Unified diff (cloud vs local):")
	diffText, derr := unifiedColorDiff(
		string(cloudRaw), string(localRaw),
		"cloud/"+modelIdOrSlug, filepath.Base(filePath),
	)
	if derr != nil {
		return fmt.Errorf("rendering unified diff: %w", derr)
	}
	fmt.Print(diffText)

	return nil
}

// parseCloudHCL preprocesses and parses downloaded cloud HCL into a wrapped
// threat model, using the same ref-injection + temp-file dance as 'cloud
// export' (see cloud_export.go).
func parseCloudHCL(raw []byte, modelId string, specCfg *spec.ThreatmodelSpecConfig) (*spec.ThreatmodelWrapped, error) {
	processed := preprocessHCLForControls(raw)
	processed = preprocessHCLForThreats(processed)
	// This HCL was downloaded from the cloud; strip remote-fetch directives so
	// parsing it cannot drive go-getter requests from this machine (SSRF/LFI).
	processed = stripRemoteFetchDirectives(processed)

	tmpDir, err := os.MkdirTemp("", "threatcl-validate-diff-")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	safeName := strings.ReplaceAll(modelId, string(os.PathSeparator), "_")
	if safeName == "" {
		safeName = "cloud-threatmodel"
	}
	tmpFilePath := filepath.Join(tmpDir, safeName+".hcl")
	if err := os.WriteFile(tmpFilePath, processed, 0600); err != nil {
		return nil, fmt.Errorf("writing temp file: %w", err)
	}

	tmParser := spec.NewThreatmodelParser(specCfg)
	if err := tmParser.ParseFile(tmpFilePath, false); err != nil {
		return nil, fmt.Errorf("parsing cloud HCL: %w", err)
	}
	return tmParser.GetWrapped(), nil
}

// unifiedColorDiff returns a git-style unified diff of a (from) vs b (to),
// colored for the terminal. fatih/color sets color.NoColor based on whether
// stdout is a TTY and whether NO_COLOR is set, so coloring auto-disables when
// piped or captured (which keeps output deterministic under test).
func unifiedColorDiff(a, b, fromFile, toFile string) (string, error) {
	ud := difflib.UnifiedDiff{
		A:        difflib.SplitLines(a),
		B:        difflib.SplitLines(b),
		FromFile: fromFile,
		ToFile:   toFile,
		Context:  3,
	}
	raw, err := difflib.GetUnifiedDiffString(ud)
	if err != nil {
		return "", err
	}
	if raw == "" {
		return "  (no textual differences)\n", nil
	}

	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	var out strings.Builder
	for _, line := range strings.SplitAfter(raw, "\n") {
		if line == "" {
			continue
		}
		body, nl := line, ""
		if strings.HasSuffix(body, "\n") {
			body, nl = body[:len(body)-1], "\n"
		}
		// Check the "+++"/"---" file headers BEFORE the single-char "+"/"-"
		// cases, otherwise the headers get miscolored.
		switch {
		case strings.HasPrefix(body, "+++"), strings.HasPrefix(body, "---"):
			out.WriteString(body)
		case strings.HasPrefix(body, "@@"):
			out.WriteString(cyan.Sprint(body))
		case strings.HasPrefix(body, "+"):
			out.WriteString(green.Sprint(body))
		case strings.HasPrefix(body, "-"):
			out.WriteString(red.Sprint(body))
		default:
			out.WriteString(body)
		}
		out.WriteString(nl)
	}
	return out.String(), nil
}

// semanticDiff walks two wrapped threat models and returns a sorted, concise
// list of structural differences. Orientation: "+" present in local not cloud,
// "-" present in cloud not local, "~" present in both but changed.
func semanticDiff(local, cloud *spec.ThreatmodelWrapped) []string {
	out := diffThreatmodels(local, cloud)
	sort.Strings(out)
	return out
}

// diffCollections matches two slices by identity key and returns lines for
// added (local-only), removed (cloud-only), and changed entries. keyFn extracts
// the identity key (return "" to skip an item), label formats the entity
// description, and changed compares a matched pair and returns a parenthesized
// suffix (or "" if unchanged).
func diffCollections[T any](
	local, cloud []T,
	keyFn func(T) string,
	label func(key string) string,
	changed func(localItem, cloudItem T) string,
) []string {
	lm := make(map[string]T, len(local))
	for _, it := range local {
		if k := keyFn(it); k != "" {
			lm[k] = it
		}
	}
	cm := make(map[string]T, len(cloud))
	for _, it := range cloud {
		if k := keyFn(it); k != "" {
			cm[k] = it
		}
	}

	var lines []string
	for k, lItem := range lm {
		if cItem, ok := cm[k]; ok {
			if suffix := changed(lItem, cItem); suffix != "" {
				lines = append(lines, fmt.Sprintf("~ %s %s", label(k), suffix))
			}
		} else {
			lines = append(lines, fmt.Sprintf("+ %s", label(k)))
		}
	}
	for k := range cm {
		if _, ok := lm[k]; !ok {
			lines = append(lines, fmt.Sprintf("- %s", label(k)))
		}
	}
	return lines
}

func diffThreatmodels(local, cloud *spec.ThreatmodelWrapped) []string {
	var lTMs, cTMs []spec.Threatmodel
	if local != nil {
		lTMs = local.Threatmodels
	}
	if cloud != nil {
		cTMs = cloud.Threatmodels
	}

	lByName := make(map[string]*spec.Threatmodel, len(lTMs))
	for i := range lTMs {
		lByName[lTMs[i].Name] = &lTMs[i]
	}
	cByName := make(map[string]*spec.Threatmodel, len(cTMs))
	for i := range cTMs {
		cByName[cTMs[i].Name] = &cTMs[i]
	}

	var lines []string

	for name := range lByName {
		if _, ok := cByName[name]; !ok {
			lines = append(lines, fmt.Sprintf("+ threat model %q", name))
		}
	}
	for name := range cByName {
		if _, ok := lByName[name]; !ok {
			lines = append(lines, fmt.Sprintf("- threat model %q", name))
		}
	}

	for name, lTM := range lByName {
		cTM, ok := cByName[name]
		if !ok {
			continue
		}
		lines = append(lines, diffThreatmodelChildren(name, lTM, cTM)...)
	}

	return lines
}

func diffThreatmodelChildren(tmName string, l, c *spec.Threatmodel) []string {
	var lines []string

	// Threat-model-level scalar fields.
	if s := tmScalarChangedSuffix(l, c); s != "" {
		lines = append(lines, fmt.Sprintf("~ threat model %q %s", tmName, s))
	}

	// Threats (identity = Name).
	lines = append(lines, diffCollections(
		l.Threats, c.Threats,
		threatKey,
		func(k string) string { return fmt.Sprintf("threat %q (in %q)", k, tmName) },
		threatChangedSuffix,
	)...)

	// Controls nested in threats present on both sides.
	lThreats := make(map[string]*spec.Threat, len(l.Threats))
	for _, t := range l.Threats {
		if t != nil {
			lThreats[t.Name] = t
		}
	}
	for _, ct := range c.Threats {
		if ct == nil {
			continue
		}
		lt, ok := lThreats[ct.Name]
		if !ok {
			continue
		}
		lines = append(lines, diffCollections(
			lt.Controls, ct.Controls,
			controlKey,
			func(k string) string { return fmt.Sprintf("control %q (in threat %q)", k, ct.Name) },
			controlChangedSuffix,
		)...)
	}

	// Information assets (identity = Name).
	lines = append(lines, diffCollections(
		l.InformationAssets, c.InformationAssets,
		func(a *spec.InformationAsset) string {
			if a == nil {
				return ""
			}
			return a.Name
		},
		func(k string) string { return fmt.Sprintf("information asset %q (in %q)", k, tmName) },
		iaChangedSuffix,
	)...)

	// Use cases (identity = Description).
	lines = append(lines, diffCollections(
		l.UseCases, c.UseCases,
		func(u *spec.UseCase) string {
			if u == nil {
				return ""
			}
			return u.Description
		},
		func(k string) string { return fmt.Sprintf("use case %q (in %q)", truncate(k, 60), tmName) },
		func(_, _ *spec.UseCase) string { return "" },
	)...)

	// Exclusions (identity = Description).
	lines = append(lines, diffCollections(
		l.Exclusions, c.Exclusions,
		func(e *spec.Exclusion) string {
			if e == nil {
				return ""
			}
			return e.Description
		},
		func(k string) string { return fmt.Sprintf("exclusion %q (in %q)", truncate(k, 60), tmName) },
		func(_, _ *spec.Exclusion) string { return "" },
	)...)

	// Third-party dependencies (identity = Name).
	lines = append(lines, diffCollections(
		l.ThirdPartyDependencies, c.ThirdPartyDependencies,
		func(d *spec.ThirdPartyDependency) string {
			if d == nil {
				return ""
			}
			return d.Name
		},
		func(k string) string { return fmt.Sprintf("third-party dependency %q (in %q)", k, tmName) },
		tpdChangedSuffix,
	)...)

	// Data flow diagrams (identity = Name).
	lines = append(lines, diffCollections(
		l.DataFlowDiagrams, c.DataFlowDiagrams,
		func(d *spec.DataFlowDiagram) string {
			if d == nil {
				return ""
			}
			return d.Name
		},
		func(k string) string { return fmt.Sprintf("data flow diagram %q (in %q)", k, tmName) },
		dfdChangedSuffix,
	)...)

	return lines
}

func threatKey(t *spec.Threat) string {
	if t == nil {
		return ""
	}
	return t.Name
}

func controlKey(c *spec.Control) string {
	if c == nil {
		return ""
	}
	return c.Name
}

func changedSuffix(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return "(" + strings.Join(fields, ", ") + " changed)"
}

func tmScalarChangedSuffix(l, c *spec.Threatmodel) string {
	if l == nil || c == nil {
		return ""
	}
	var f []string
	if l.Description != c.Description {
		f = append(f, "description")
	}
	if l.Author != c.Author {
		f = append(f, "author")
	}
	if l.Link != c.Link {
		f = append(f, "link")
	}
	if l.DiagramLink != c.DiagramLink {
		f = append(f, "diagram_link")
	}
	return changedSuffix(f)
}

func threatChangedSuffix(l, c *spec.Threat) string {
	if l == nil || c == nil {
		return ""
	}
	var f []string
	if l.Description != c.Description {
		f = append(f, "description")
	}
	if l.Control != c.Control {
		f = append(f, "control")
	}
	if !sameStringSet(l.ImpactType, c.ImpactType) {
		f = append(f, "impacts")
	}
	if !sameStringSet(l.Stride, c.Stride) {
		f = append(f, "stride")
	}
	if !sameStringSet(l.InformationAssetRefs, c.InformationAssetRefs) {
		f = append(f, "information_asset_refs")
	}
	if l.Ref != c.Ref {
		f = append(f, "ref")
	}
	return changedSuffix(f)
}

func controlChangedSuffix(l, c *spec.Control) string {
	if l == nil || c == nil {
		return ""
	}
	var f []string
	if l.Description != c.Description {
		f = append(f, "description")
	}
	if l.Implemented != c.Implemented {
		f = append(f, "implemented")
	}
	if l.ImplementationNotes != c.ImplementationNotes {
		f = append(f, "implementation_notes")
	}
	if l.RiskReduction != c.RiskReduction {
		f = append(f, "risk_reduction")
	}
	if l.Ref != c.Ref {
		f = append(f, "ref")
	}
	return changedSuffix(f)
}

func iaChangedSuffix(l, c *spec.InformationAsset) string {
	if l == nil || c == nil {
		return ""
	}
	var f []string
	if l.Description != c.Description {
		f = append(f, "description")
	}
	if l.InformationClassification != c.InformationClassification {
		f = append(f, "information_classification")
	}
	if l.Source != c.Source {
		f = append(f, "source")
	}
	return changedSuffix(f)
}

func tpdChangedSuffix(l, c *spec.ThirdPartyDependency) string {
	if l == nil || c == nil {
		return ""
	}
	var f []string
	if l.Description != c.Description {
		f = append(f, "description")
	}
	if l.Saas != c.Saas {
		f = append(f, "saas")
	}
	if l.PayingCustomer != c.PayingCustomer {
		f = append(f, "paying_customer")
	}
	if l.OpenSource != c.OpenSource {
		f = append(f, "open_source")
	}
	if l.UptimeDependency != c.UptimeDependency {
		f = append(f, "uptime_dependency")
	}
	if l.UptimeNotes != c.UptimeNotes {
		f = append(f, "uptime_notes")
	}
	if l.Infrastructure != c.Infrastructure {
		f = append(f, "infrastructure")
	}
	return changedSuffix(f)
}

func dfdChangedSuffix(l, c *spec.DataFlowDiagram) string {
	if l == nil || c == nil {
		return ""
	}
	var f []string
	if len(l.Processes) != len(c.Processes) {
		f = append(f, "processes")
	}
	if len(l.ExternalElements) != len(c.ExternalElements) {
		f = append(f, "external_elements")
	}
	if len(l.DataStores) != len(c.DataStores) {
		f = append(f, "data_stores")
	}
	if len(l.Flows) != len(c.Flows) {
		f = append(f, "flows")
	}
	if len(l.TrustZones) != len(c.TrustZones) {
		f = append(f, "trust_zones")
	}
	return changedSuffix(f)
}

// sameStringSet reports whether a and b contain the same strings, ignoring
// order (the spec preserves declaration order, but HCL list order is not
// meaningful for these fields).
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
