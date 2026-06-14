package lsp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/version"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg, _ := spec.LoadSpecConfig()
	return NewServer(cfg)
}

// captureContext returns a glsp.Context whose Notify appends every
// publishDiagnostics payload to the returned slice pointer.
func captureContext() (*glsp.Context, *[]protocol.PublishDiagnosticsParams) {
	var captured []protocol.PublishDiagnosticsParams
	ctx := &glsp.Context{
		Notify: func(method string, params any) {
			if method == protocol.ServerTextDocumentPublishDiagnostics {
				if p, ok := params.(protocol.PublishDiagnosticsParams); ok {
					captured = append(captured, p)
				}
			}
		},
	}
	return ctx, &captured
}

func TestInitializeCapabilities(t *testing.T) {
	s := newTestServer(t)
	ctx, _ := captureContext()

	raw, err := s.initialize(ctx, &protocol.InitializeParams{})
	if err != nil {
		t.Fatalf("initialize returned error: %v", err)
	}
	result, ok := raw.(protocol.InitializeResult)
	if !ok {
		t.Fatalf("initialize result type = %T, want InitializeResult", raw)
	}

	caps := result.Capabilities

	// Full text sync with open/close.
	sync, ok := caps.TextDocumentSync.(*protocol.TextDocumentSyncOptions)
	if !ok {
		t.Fatalf("TextDocumentSync type = %T, want *TextDocumentSyncOptions", caps.TextDocumentSync)
	}
	if sync.OpenClose == nil || !*sync.OpenClose {
		t.Error("TextDocumentSync.OpenClose not advertised")
	}
	if sync.Change == nil || *sync.Change != protocol.TextDocumentSyncKindFull {
		t.Errorf("TextDocumentSync.Change = %v, want Full", sync.Change)
	}

	// Four providers.
	if caps.CompletionProvider == nil {
		t.Error("CompletionProvider not advertised")
	}
	if hp, ok := caps.HoverProvider.(bool); !ok || !hp {
		t.Errorf("HoverProvider = %v, want true", caps.HoverProvider)
	}
	if dsp, ok := caps.DocumentSymbolProvider.(bool); !ok || !dsp {
		t.Errorf("DocumentSymbolProvider = %v, want true", caps.DocumentSymbolProvider)
	}
	if dfp, ok := caps.DocumentFormattingProvider.(bool); !ok || !dfp {
		t.Errorf("DocumentFormattingProvider = %v, want true", caps.DocumentFormattingProvider)
	}

	// ServerInfo.
	if result.ServerInfo == nil {
		t.Fatal("ServerInfo is nil")
	}
	if result.ServerInfo.Name != serverName {
		t.Errorf("ServerInfo.Name = %q, want %q", result.ServerInfo.Name, serverName)
	}
	if result.ServerInfo.Version == nil || *result.ServerInfo.Version != version.GetVersion() {
		t.Errorf("ServerInfo.Version = %v, want %q", result.ServerInfo.Version, version.GetVersion())
	}
}

func TestDidOpenPublishesDiagnostics(t *testing.T) {
	s := newTestServer(t)
	ctx, captured := captureContext()

	src, err := os.ReadFile(filepath.Join("testdata", "invalid-enum.hcl"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	uri := protocol.DocumentUri("file:///invalid-enum.hcl")

	err = s.didOpen(ctx, &protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{URI: uri, Text: string(src), Version: 1},
	})
	if err != nil {
		t.Fatalf("didOpen returned error: %v", err)
	}

	if len(*captured) != 1 {
		t.Fatalf("got %d publishDiagnostics notifications, want 1", len(*captured))
	}
	pub := (*captured)[0]
	if pub.URI != uri {
		t.Errorf("published URI = %q, want %q", pub.URI, uri)
	}
	if len(pub.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic for invalid-enum fixture")
	}

	// The invalid risk likelihood ("extremely_high") is a hard error.
	hasError := false
	for _, d := range pub.Diagnostics {
		if d.Severity != nil && *d.Severity == protocol.DiagnosticSeverityError {
			hasError = true
		}
	}
	if !hasError {
		t.Error("expected an Error-severity diagnostic for the invalid risk likelihood")
	}

	// The document should be in the store.
	if _, ok := s.docs.get(uri); !ok {
		t.Error("document not stored after didOpen")
	}
}

func TestDidChangeAndClose(t *testing.T) {
	s := newTestServer(t)
	ctx, captured := captureContext()
	uri := protocol.DocumentUri("file:///doc.hcl")

	// Open with valid content (no diagnostics expected).
	valid, err := os.ReadFile(filepath.Join("testdata", "valid.hcl"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if err := s.didOpen(ctx, &protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{URI: uri, Text: string(valid), Version: 1},
	}); err != nil {
		t.Fatalf("didOpen: %v", err)
	}

	// Change to invalid content.
	invalid, err := os.ReadFile(filepath.Join("testdata", "invalid-enum.hcl"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if err := s.didChange(ctx, &protocol.DidChangeTextDocumentParams{
		TextDocument: protocol.VersionedTextDocumentIdentifier{
			TextDocumentIdentifier: protocol.TextDocumentIdentifier{URI: uri},
			Version:                2,
		},
		ContentChanges: []any{
			protocol.TextDocumentContentChangeEventWhole{Text: string(invalid)},
		},
	}); err != nil {
		t.Fatalf("didChange: %v", err)
	}

	// The latest notification (from didChange) should carry diagnostics.
	last := (*captured)[len(*captured)-1]
	if len(last.Diagnostics) == 0 {
		t.Error("expected diagnostics after change to invalid content")
	}
	// Stored text should be the updated content.
	if got, _ := s.docs.get(uri); string(got) != string(invalid) {
		t.Error("stored text not updated after didChange")
	}

	// Close clears diagnostics and drops the document.
	if err := s.didClose(ctx, &protocol.DidCloseTextDocumentParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: uri},
	}); err != nil {
		t.Fatalf("didClose: %v", err)
	}
	closed := (*captured)[len(*captured)-1]
	if len(closed.Diagnostics) != 0 {
		t.Errorf("didClose published %d diagnostics, want 0 (cleared)", len(closed.Diagnostics))
	}
	if _, ok := s.docs.get(uri); ok {
		t.Error("document still stored after didClose")
	}
}

func TestHandlersOnMissingDocument(t *testing.T) {
	s := newTestServer(t)
	ctx, _ := captureContext()
	uri := protocol.DocumentUri("file:///missing.hcl")

	comp, err := s.completion(ctx, &protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: uri},
		},
	})
	if err != nil || comp != nil {
		t.Errorf("completion on missing doc = (%v, %v), want (nil, nil)", comp, err)
	}

	hov, err := s.hover(ctx, &protocol.HoverParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: uri},
		},
	})
	if err != nil || hov != nil {
		t.Errorf("hover on missing doc = (%v, %v), want (nil, nil)", hov, err)
	}
}

func TestHandlersOnValidDocument(t *testing.T) {
	s := newTestServer(t)
	ctx, _ := captureContext()
	uri := protocol.DocumentUri("file:///valid.hcl")

	valid, err := os.ReadFile(filepath.Join("testdata", "valid.hcl"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if err := s.didOpen(ctx, &protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{URI: uri, Text: string(valid), Version: 1},
	}); err != nil {
		t.Fatalf("didOpen: %v", err)
	}

	// Document symbols should surface the threatmodel block.
	raw, err := s.documentSymbol(ctx, &protocol.DocumentSymbolParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: uri},
	})
	if err != nil {
		t.Fatalf("documentSymbol: %v", err)
	}
	syms, ok := raw.([]protocol.DocumentSymbol)
	if !ok {
		t.Fatalf("documentSymbol result type = %T, want []DocumentSymbol", raw)
	}
	if len(syms) == 0 {
		t.Fatal("expected at least one document symbol")
	}
	if syms[0].Kind != protocol.SymbolKindNamespace {
		t.Errorf("top symbol kind = %d, want Namespace (threatmodel)", syms[0].Kind)
	}

	// Formatting an already-canonical document should produce no edits.
	edits, err := s.formatting(ctx, &protocol.DocumentFormattingParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: uri},
	})
	if err != nil {
		t.Fatalf("formatting: %v", err)
	}
	if edits != nil {
		t.Errorf("formatting canonical doc returned %d edits, want none", len(edits))
	}
}

func TestUriToFilename(t *testing.T) {
	cases := map[string]string{
		"file:///home/x/model.hcl":  "/home/x/model.hcl",
		"file:///home/x/my%20m.hcl": "/home/x/my m.hcl",
		"/already/a/path.hcl":       "/already/a/path.hcl",
	}
	for uri, want := range cases {
		if got := uriToFilename(uri); got != want {
			t.Errorf("uriToFilename(%q) = %q, want %q", uri, got, want)
		}
	}
}
