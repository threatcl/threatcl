package lsp

import (
	"bytes"

	"github.com/hashicorp/hcl/v2"
	"github.com/threatcl/spec/lang"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// Each feature handler is the same shape: fetch the document text, run the
// pure language layer over it at the (converted) cursor position, and map the
// neutral result back to LSP types. All the real logic is in lang/ and in the
// pure mappers in convert.go and position.go.

func (s *Server) completion(ctx *glsp.Context, params *protocol.CompletionParams) (any, error) {
	src, ok := s.docs.get(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	pf, _ := lang.ParseSource(uriToFilename(params.TextDocument.URI), src)
	off := lspPositionToByteOffset(src, params.Position)
	return toCompletionItems(lang.CompletionsAt(pf, hcl.Pos{Byte: off})), nil
}

func (s *Server) hover(ctx *glsp.Context, params *protocol.HoverParams) (*protocol.Hover, error) {
	src, ok := s.docs.get(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	pf, _ := lang.ParseSource(uriToFilename(params.TextDocument.URI), src)
	off := lspPositionToByteOffset(src, params.Position)
	h := lang.HoverAt(pf, hcl.Pos{Byte: off})
	if h == nil {
		return nil, nil
	}
	return toHover(src, h), nil
}

func (s *Server) documentSymbol(ctx *glsp.Context, params *protocol.DocumentSymbolParams) (any, error) {
	src, ok := s.docs.get(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	pf, _ := lang.ParseSource(uriToFilename(params.TextDocument.URI), src)
	return toDocumentSymbols(src, lang.Symbols(pf)), nil
}

// formatting returns a single full-document edit. On broken syntax lang.Format
// returns the source unchanged alongside error diagnostics; in that case (and
// when formatting is a no-op) we return no edits so the editor leaves the buffer
// untouched.
func (s *Server) formatting(ctx *glsp.Context, params *protocol.DocumentFormattingParams) ([]protocol.TextEdit, error) {
	src, ok := s.docs.get(params.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	out, diags := lang.Format(uriToFilename(params.TextDocument.URI), src)
	if diags.HasErrors() || bytes.Equal(out, src) {
		return nil, nil
	}
	return []protocol.TextEdit{fullDocumentEdit(src, string(out))}, nil
}
