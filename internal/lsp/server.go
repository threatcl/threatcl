// Package lsp implements the Language Server Protocol layer for threatcl. It is
// a thin translation shell: all language intelligence (parsing, diagnostics,
// completion, hover, symbols, formatting) lives in github.com/threatcl/spec/lang
// and speaks only Go and hashicorp/hcl types. This package converts those
// neutral results to and from LSP protocol types (see convert.go and
// position.go) and wires them to a glsp stdio server.
package lsp

import (
	"net/url"
	"strings"

	"github.com/threatcl/spec"
	"github.com/threatcl/spec/lang"
	"github.com/threatcl/threatcl/version"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
	"github.com/tliron/glsp/server"
)

const serverName = "threatcl-lsp"

// Server is a threatcl language server bound to a glsp protocol handler.
type Server struct {
	// specCfg is retained for a future config-aware schema (lang.SchemaWithConfig);
	// the lang surface shipped in this version is config-blind, so it is unused
	// today. See docs/lsp.md "Known limitations".
	specCfg *spec.ThreatmodelSpecConfig
	docs    *store
	handler protocol.Handler
}

// NewServer constructs a server. specCfg may be nil; it is not consulted by the
// language layer in this version.
func NewServer(specCfg *spec.ThreatmodelSpecConfig) *Server {
	s := &Server{
		specCfg: specCfg,
		docs:    newStore(),
	}
	s.handler = protocol.Handler{
		Initialize:                 s.initialize,
		Initialized:                s.initialized,
		Shutdown:                   s.shutdown,
		SetTrace:                   s.setTrace,
		TextDocumentDidOpen:        s.didOpen,
		TextDocumentDidChange:      s.didChange,
		TextDocumentDidClose:       s.didClose,
		TextDocumentCompletion:     s.completion,
		TextDocumentHover:          s.hover,
		TextDocumentDocumentSymbol: s.documentSymbol,
		TextDocumentFormatting:     s.formatting,
	}
	return s
}

// RunStdio serves the protocol over stdin/stdout, blocking until the client
// disconnects. stdout is the transport, so nothing in this package writes to it.
func (s *Server) RunStdio() error {
	srv := server.NewServer(&s.handler, serverName, false)
	return srv.RunStdio()
}

// initialize advertises the server's capabilities. It starts from glsp's
// auto-derived capabilities (which fill in providers for the registered
// callbacks) and overrides the text sync to full-document — glsp defaults
// change sync to incremental, which v1 does not implement.
func (s *Server) initialize(ctx *glsp.Context, params *protocol.InitializeParams) (any, error) {
	capabilities := s.handler.CreateServerCapabilities()

	openClose := true
	change := protocol.TextDocumentSyncKindFull
	capabilities.TextDocumentSync = &protocol.TextDocumentSyncOptions{
		OpenClose: &openClose,
		Change:    &change,
	}

	ver := version.GetVersion()
	return protocol.InitializeResult{
		Capabilities: capabilities,
		ServerInfo: &protocol.InitializeResultServerInfo{
			Name:    serverName,
			Version: &ver,
		},
	}, nil
}

func (s *Server) initialized(ctx *glsp.Context, params *protocol.InitializedParams) error {
	return nil
}

func (s *Server) shutdown(ctx *glsp.Context) error {
	return nil
}

func (s *Server) setTrace(ctx *glsp.Context, params *protocol.SetTraceParams) error {
	return nil
}

// didOpen records the document and publishes its initial diagnostics.
func (s *Server) didOpen(ctx *glsp.Context, params *protocol.DidOpenTextDocumentParams) error {
	text := []byte(params.TextDocument.Text)
	s.docs.set(params.TextDocument.URI, text, params.TextDocument.Version)
	s.publishDiagnostics(ctx, params.TextDocument.URI, text, params.TextDocument.Version)
	return nil
}

// didChange replaces the stored document. Under full sync the client sends the
// whole document each time, so the last content change is the new full text.
func (s *Server) didChange(ctx *glsp.Context, params *protocol.DidChangeTextDocumentParams) error {
	if len(params.ContentChanges) == 0 {
		return nil
	}
	text, ok := wholeText(params.ContentChanges[len(params.ContentChanges)-1])
	if !ok {
		return nil
	}
	s.docs.set(params.TextDocument.URI, text, params.TextDocument.Version)
	s.publishDiagnostics(ctx, params.TextDocument.URI, text, params.TextDocument.Version)
	return nil
}

// didClose drops the document and clears its diagnostics (an empty list tells
// the editor to remove any badges it was showing).
func (s *Server) didClose(ctx *glsp.Context, params *protocol.DidCloseTextDocumentParams) error {
	s.docs.delete(params.TextDocument.URI)
	ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, protocol.PublishDiagnosticsParams{
		URI:         params.TextDocument.URI,
		Diagnostics: []protocol.Diagnostic{},
	})
	return nil
}

// publishDiagnostics runs the language layer over text and pushes the result.
func (s *Server) publishDiagnostics(ctx *glsp.Context, uri protocol.DocumentUri, text []byte, version int32) {
	diags := lang.Diagnostics(uriToFilename(uri), text)
	v := uint32(version)
	ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, protocol.PublishDiagnosticsParams{
		URI:         uri,
		Version:     &v,
		Diagnostics: toLSPDiagnostics(text, diags),
	})
}

// wholeText extracts the full document text from a content change. With full
// text sync glsp delivers a TextDocumentContentChangeEventWhole; a range-less
// incremental event is also treated as whole text for resilience.
func wholeText(change any) ([]byte, bool) {
	switch c := change.(type) {
	case protocol.TextDocumentContentChangeEventWhole:
		return []byte(c.Text), true
	case protocol.TextDocumentContentChangeEvent:
		if c.Range == nil {
			return []byte(c.Text), true
		}
		return nil, false
	default:
		return nil, false
	}
}

// uriToFilename derives a filesystem-ish filename from a document URI, for use
// as the cosmetic filename in hcl diagnostic ranges. A non-file URI is returned
// as-is.
func uriToFilename(uri protocol.DocumentUri) string {
	if strings.HasPrefix(uri, "file://") {
		if u, err := url.Parse(uri); err == nil && u.Path != "" {
			return u.Path
		}
		return strings.TrimPrefix(uri, "file://")
	}
	return uri
}
