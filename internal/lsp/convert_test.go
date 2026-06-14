package lsp

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/threatcl/spec/lang"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

func TestToCompletionItems_Kinds(t *testing.T) {
	cands := []lang.Candidate{
		{Label: "threatmodel", Detail: "block name", Doc: "doc", InsertText: "threatmodel \"${1:name}\" {\n\t$0\n}", Kind: lang.CandidateKindSnippet},
		{Label: "author", Detail: "string, required", Doc: "who", InsertText: "author = ", Kind: lang.CandidateKindField},
		{Label: "high", Detail: "value of likelihood", Kind: lang.CandidateKindEnumMember},
		{Label: "spec_version", Kind: lang.CandidateKindKeyword},
	}
	items := toCompletionItems(cands)
	if len(items) != len(cands) {
		t.Fatalf("got %d items, want %d", len(items), len(cands))
	}

	wantKinds := []protocol.CompletionItemKind{
		protocol.CompletionItemKindSnippet,
		protocol.CompletionItemKindField,
		protocol.CompletionItemKindEnumMember,
		protocol.CompletionItemKindKeyword,
	}
	for i, want := range wantKinds {
		if items[i].Kind == nil {
			t.Errorf("item %d: Kind is nil", i)
			continue
		}
		if *items[i].Kind != want {
			t.Errorf("item %d: Kind = %d, want %d", i, *items[i].Kind, want)
		}
	}

	// Snippet candidate -> InsertTextFormat Snippet.
	if items[0].InsertTextFormat == nil || *items[0].InsertTextFormat != protocol.InsertTextFormatSnippet {
		t.Errorf("snippet item: InsertTextFormat = %v, want Snippet", items[0].InsertTextFormat)
	}
	// Field candidate -> InsertTextFormat PlainText.
	if items[1].InsertTextFormat == nil || *items[1].InsertTextFormat != protocol.InsertTextFormatPlainText {
		t.Errorf("field item: InsertTextFormat = %v, want PlainText", items[1].InsertTextFormat)
	}
	// Enum member has no InsertText -> InsertTextFormat omitted, label is inserted.
	if items[2].InsertText != nil {
		t.Errorf("enum item: InsertText = %v, want nil", items[2].InsertText)
	}
	if items[2].InsertTextFormat != nil {
		t.Errorf("enum item: InsertTextFormat = %v, want nil", items[2].InsertTextFormat)
	}

	// Doc maps to Markdown MarkupContent.
	mc, ok := items[0].Documentation.(protocol.MarkupContent)
	if !ok {
		t.Fatalf("snippet item: Documentation type = %T, want MarkupContent", items[0].Documentation)
	}
	if mc.Kind != protocol.MarkupKindMarkdown || mc.Value != "doc" {
		t.Errorf("snippet item: Documentation = %+v, want Markdown 'doc'", mc)
	}

	// Detail maps through.
	if items[1].Detail == nil || *items[1].Detail != "string, required" {
		t.Errorf("field item: Detail = %v, want 'string, required'", items[1].Detail)
	}
}

func TestToHover(t *testing.T) {
	src := []byte("threatmodel \"x\" {}\n")
	h := &lang.Hover{
		Contents: "**author** (string, required)",
		Range:    hcl.Range{Start: hcl.Pos{Byte: 0}, End: hcl.Pos{Byte: 11}},
	}
	got := toHover(src, h)
	mc, ok := got.Contents.(protocol.MarkupContent)
	if !ok {
		t.Fatalf("Contents type = %T, want MarkupContent", got.Contents)
	}
	if mc.Kind != protocol.MarkupKindMarkdown {
		t.Errorf("MarkupContent.Kind = %q, want markdown", mc.Kind)
	}
	if mc.Value != h.Contents {
		t.Errorf("MarkupContent.Value = %q, want %q", mc.Value, h.Contents)
	}
	if got.Range == nil {
		t.Fatal("Range is nil")
	}
	if got.Range.Start.Character != 0 || got.Range.End.Character != 11 {
		t.Errorf("Range = %+v, want chars 0..11", got.Range)
	}
}

func TestToDocumentSymbols_RecursionAndKinds(t *testing.T) {
	src := []byte("threatmodel \"M\" {\n  threat \"t\" {}\n}\n")
	syms := []lang.Symbol{
		{
			Name:           "M",
			Detail:         "threatmodel",
			Kind:           lang.SymbolKindNamespace,
			Range:          hcl.Range{Start: hcl.Pos{Byte: 0}, End: hcl.Pos{Byte: len(src)}},
			SelectionRange: hcl.Range{Start: hcl.Pos{Byte: 0}, End: hcl.Pos{Byte: 11}},
			Children: []lang.Symbol{
				{
					Name:   "t",
					Detail: "threat",
					Kind:   lang.SymbolKindStruct,
					Range:  hcl.Range{Start: hcl.Pos{Byte: 20}, End: hcl.Pos{Byte: 32}},
				},
			},
		},
	}
	got := toDocumentSymbols(src, syms)
	if len(got) != 1 {
		t.Fatalf("got %d symbols, want 1", len(got))
	}
	if got[0].Kind != protocol.SymbolKindNamespace {
		t.Errorf("root Kind = %d, want Namespace", got[0].Kind)
	}
	if got[0].Detail == nil || *got[0].Detail != "threatmodel" {
		t.Errorf("root Detail = %v, want threatmodel", got[0].Detail)
	}
	if len(got[0].Children) != 1 {
		t.Fatalf("got %d children, want 1", len(got[0].Children))
	}
	if got[0].Children[0].Kind != protocol.SymbolKindStruct {
		t.Errorf("child Kind = %d, want Struct", got[0].Children[0].Kind)
	}
	if got[0].Children[0].Name != "t" {
		t.Errorf("child Name = %q, want t", got[0].Children[0].Name)
	}
}

func TestToLSPDiagnostics_SeverityMessageRange(t *testing.T) {
	src := []byte("threatmodel \"x\" {}\n")
	rng := hcl.Range{Start: hcl.Pos{Byte: 0}, End: hcl.Pos{Byte: 11}}
	diags := hcl.Diagnostics{
		{Severity: hcl.DiagError, Summary: "Bad thing", Detail: "more detail", Subject: rng.Ptr()},
		{Severity: hcl.DiagWarning, Summary: "Soft thing", Subject: rng.Ptr()},
	}
	got := toLSPDiagnostics(src, diags)
	if len(got) != 2 {
		t.Fatalf("got %d diagnostics, want 2", len(got))
	}

	if got[0].Severity == nil || *got[0].Severity != protocol.DiagnosticSeverityError {
		t.Errorf("diag 0 severity = %v, want Error", got[0].Severity)
	}
	if got[0].Message != "Bad thing\nmore detail" {
		t.Errorf("diag 0 message = %q, want 'Bad thing\\nmore detail'", got[0].Message)
	}
	if got[0].Source == nil || *got[0].Source != diagnosticSource {
		t.Errorf("diag 0 source = %v, want %q", got[0].Source, diagnosticSource)
	}
	if got[0].Range.End.Character != 11 {
		t.Errorf("diag 0 range end char = %d, want 11", got[0].Range.End.Character)
	}

	if got[1].Severity == nil || *got[1].Severity != protocol.DiagnosticSeverityWarning {
		t.Errorf("diag 1 severity = %v, want Warning", got[1].Severity)
	}
	if got[1].Message != "Soft thing" {
		t.Errorf("diag 1 message = %q, want 'Soft thing'", got[1].Message)
	}
}

// TestToLSPDiagnostics_NilSubject guards the regression where a position-less
// diagnostic (Subject == nil, which lang sorts first) must map to a zero range
// rather than panic.
func TestToLSPDiagnostics_NilSubject(t *testing.T) {
	src := []byte("threatmodel \"x\" {}\n")
	diags := hcl.Diagnostics{
		{Severity: hcl.DiagError, Summary: "position-less", Subject: nil},
	}
	got := toLSPDiagnostics(src, diags)
	if len(got) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(got))
	}
	zero := protocol.Range{
		Start: protocol.Position{Line: 0, Character: 0},
		End:   protocol.Position{Line: 0, Character: 0},
	}
	if got[0].Range != zero {
		t.Errorf("nil-subject diag range = %+v, want zero range", got[0].Range)
	}
}

func TestFullDocumentEdit(t *testing.T) {
	src := []byte("a\nbb\nccc")
	edit := fullDocumentEdit(src, "formatted")
	if edit.Range.Start.Line != 0 || edit.Range.Start.Character != 0 {
		t.Errorf("edit start = %+v, want (0,0)", edit.Range.Start)
	}
	// EOF of "a\nbb\nccc" is line 2, char 3.
	if edit.Range.End.Line != 2 || edit.Range.End.Character != 3 {
		t.Errorf("edit end = %+v, want (2,3)", edit.Range.End)
	}
	if edit.NewText != "formatted" {
		t.Errorf("edit NewText = %q, want 'formatted'", edit.NewText)
	}
}
