package lsp

import (
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// LSP positions are (0-based line, 0-based UTF-16 code-unit column); hcl works
// in byte offsets. glsp's protocol_3_16 predates positionEncoding negotiation
// (an LSP 3.17 feature), so we cannot ask the client for utf-8 — we must
// convert. These two functions are the only place that conversion happens, and
// they are pure so they can be exhaustively tested (see position_test.go).

// lspPositionToByteOffset converts an LSP (line, utf16-character) position into
// a byte offset into src. Out-of-range positions clamp: a line past EOF returns
// len(src); a character past the line's end returns that line's end (matching
// the LSP rule that an over-long character defaults back to the line length).
func lspPositionToByteOffset(src []byte, pos protocol.Position) int {
	// Walk to the byte offset where the target line begins.
	line := 0
	lineStart := 0
	for i := 0; i < len(src) && line < int(pos.Line); i++ {
		if src[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	if line < int(pos.Line) {
		// Requested line is past the end of the document.
		return len(src)
	}

	// Advance from the line start by pos.Character UTF-16 code units.
	off := lineStart
	units := 0
	for off < len(src) && units < int(pos.Character) {
		if src[off] == '\n' {
			// End of line reached before consuming all requested characters.
			break
		}
		r, size := utf8.DecodeRune(src[off:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte: treat it as one unit so we keep making progress.
			off++
			units++
			continue
		}
		u := utf16Len(r)
		if units+u > int(pos.Character) {
			// pos.Character lands inside a surrogate pair; stop before this rune.
			break
		}
		units += u
		off += size
	}
	return off
}

// byteOffsetToLSPPosition converts a byte offset into src into an LSP
// (line, utf16-character) position. byteOff is clamped to [0, len(src)].
func byteOffsetToLSPPosition(src []byte, byteOff int) protocol.Position {
	if byteOff < 0 {
		byteOff = 0
	}
	if byteOff > len(src) {
		byteOff = len(src)
	}

	// Locate the start of the line containing byteOff.
	line := 0
	lineStart := 0
	for i := 0; i < byteOff; i++ {
		if src[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}

	// Count UTF-16 code units from the line start up to byteOff.
	character := 0
	for off := lineStart; off < byteOff; {
		r, size := utf8.DecodeRune(src[off:])
		if r == utf8.RuneError && size == 1 {
			character++
			off++
			continue
		}
		if off+size > byteOff {
			// byteOff falls inside a multi-byte rune; stop at the boundary.
			break
		}
		character += utf16Len(r)
		off += size
	}

	return protocol.Position{Line: uint32(line), Character: uint32(character)}
}

// byteRangeToLSP maps an hcl.Range (byte offsets) onto an LSP Range.
func byteRangeToLSP(src []byte, r hcl.Range) protocol.Range {
	return protocol.Range{
		Start: byteOffsetToLSPPosition(src, r.Start.Byte),
		End:   byteOffsetToLSPPosition(src, r.End.Byte),
	}
}

// utf16Len returns how many UTF-16 code units encode r: 2 for an astral
// (outside-the-BMP) rune, 1 for everything else.
func utf16Len(r rune) int {
	if r >= 0x10000 {
		return 2
	}
	return 1
}
