package lsp

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/threatcl/spec/lang"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// diagnosticSource badges every diagnostic so editors can attribute them to
// threatcl rather than another HCL language server sharing the buffer.
const diagnosticSource = "threatcl"

// toCompletionItems maps neutral lang.Candidates onto LSP completion items.
// Block scaffolds (CandidateKindSnippet) carry LSP snippet placeholders, so
// their InsertTextFormat is Snippet; everything else inserts as plain text.
func toCompletionItems(cands []lang.Candidate) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(cands))
	for _, c := range cands {
		kind := completionItemKind(c.Kind)
		item := protocol.CompletionItem{
			Label: c.Label,
			Kind:  &kind,
		}
		if c.Detail != "" {
			detail := c.Detail
			item.Detail = &detail
		}
		if c.Doc != "" {
			item.Documentation = protocol.MarkupContent{
				Kind:  protocol.MarkupKindMarkdown,
				Value: c.Doc,
			}
		}
		if c.InsertText != "" {
			insertText := c.InsertText
			item.InsertText = &insertText
			format := protocol.InsertTextFormatPlainText
			if c.Kind == lang.CandidateKindSnippet {
				format = protocol.InsertTextFormatSnippet
			}
			item.InsertTextFormat = &format
		}
		items = append(items, item)
	}
	return items
}

func completionItemKind(k lang.CandidateKind) protocol.CompletionItemKind {
	switch k {
	case lang.CandidateKindKeyword:
		return protocol.CompletionItemKindKeyword
	case lang.CandidateKindField:
		return protocol.CompletionItemKindField
	case lang.CandidateKindEnumMember:
		return protocol.CompletionItemKindEnumMember
	case lang.CandidateKindSnippet:
		return protocol.CompletionItemKindSnippet
	default:
		return protocol.CompletionItemKindText
	}
}

// toHover maps a lang.Hover (Markdown contents + byte range) onto an LSP Hover.
func toHover(src []byte, h *lang.Hover) *protocol.Hover {
	rng := byteRangeToLSP(src, h.Range)
	return &protocol.Hover{
		Contents: protocol.MarkupContent{
			Kind:  protocol.MarkupKindMarkdown,
			Value: h.Contents,
		},
		Range: &rng,
	}
}

// toDocumentSymbols recursively maps the lang symbol outline onto LSP
// DocumentSymbols, converting both ranges from byte offsets.
func toDocumentSymbols(src []byte, syms []lang.Symbol) []protocol.DocumentSymbol {
	out := make([]protocol.DocumentSymbol, 0, len(syms))
	for _, s := range syms {
		ds := protocol.DocumentSymbol{
			Name:           s.Name,
			Kind:           symbolKind(s.Kind),
			Range:          byteRangeToLSP(src, s.Range),
			SelectionRange: byteRangeToLSP(src, s.SelectionRange),
		}
		if s.Detail != "" {
			detail := s.Detail
			ds.Detail = &detail
		}
		if len(s.Children) > 0 {
			ds.Children = toDocumentSymbols(src, s.Children)
		}
		out = append(out, ds)
	}
	return out
}

func symbolKind(k lang.SymbolKind) protocol.SymbolKind {
	switch k {
	case lang.SymbolKindNamespace:
		return protocol.SymbolKindNamespace
	case lang.SymbolKindStruct:
		return protocol.SymbolKindStruct
	case lang.SymbolKindField:
		return protocol.SymbolKindField
	default:
		return protocol.SymbolKindStruct
	}
}

// toLSPDiagnostics maps hcl.Diagnostics onto LSP diagnostics. Position-less
// diagnostics (Subject == nil, which lang sorts first) get a zero range —
// (0,0)-(0,0) — so they still surface at the top of the file rather than
// crashing the converter.
func toLSPDiagnostics(src []byte, diags hcl.Diagnostics) []protocol.Diagnostic {
	out := make([]protocol.Diagnostic, 0, len(diags))
	for _, d := range diags {
		severity := diagnosticSeverity(d.Severity)
		source := diagnosticSource
		var rng protocol.Range
		if d.Subject != nil {
			rng = byteRangeToLSP(src, *d.Subject)
		}
		out = append(out, protocol.Diagnostic{
			Range:    rng,
			Severity: &severity,
			Source:   &source,
			Message:  diagnosticMessage(d),
		})
	}
	return out
}

func diagnosticSeverity(s hcl.DiagnosticSeverity) protocol.DiagnosticSeverity {
	switch s {
	case hcl.DiagError:
		return protocol.DiagnosticSeverityError
	case hcl.DiagWarning:
		return protocol.DiagnosticSeverityWarning
	default:
		// Unknown severities badge as warnings rather than silently dropping.
		return protocol.DiagnosticSeverityWarning
	}
}

// diagnosticMessage joins an hcl diagnostic's Summary and Detail into a single
// LSP message, keeping whichever parts are present.
func diagnosticMessage(d *hcl.Diagnostic) string {
	switch {
	case d.Summary != "" && d.Detail != "":
		return d.Summary + "\n" + d.Detail
	case d.Detail != "":
		return d.Detail
	default:
		return d.Summary
	}
}

// fullDocumentEdit builds a single TextEdit replacing the whole document from
// (0,0) to EOF with newText — the shape an editor's format-on-save expects.
func fullDocumentEdit(src []byte, newText string) protocol.TextEdit {
	return protocol.TextEdit{
		Range: protocol.Range{
			Start: protocol.Position{Line: 0, Character: 0},
			End:   byteOffsetToLSPPosition(src, len(src)),
		},
		NewText: newText,
	}
}
