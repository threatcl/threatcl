package lsp

import (
	"testing"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// mixed is one line covering each UTF-16 width class:
//
//	a   U+0061  1 byte  / 1 UTF-16 unit   bytes 0      char 0
//	é   U+00E9  2 bytes / 1 UTF-16 unit   bytes 1..2   char 1
//	世  U+4E16  3 bytes / 1 UTF-16 unit   bytes 3..5   char 2
//	😀  U+1F600 4 bytes / 2 UTF-16 units  bytes 6..9   char 3..4
//	b   U+0062  1 byte  / 1 UTF-16 unit   bytes 10     char 5
//
// 11 bytes total; EOF is byte 11 / char 6.
const mixed = "aé世😀b"

func TestByteOffsetToLSPPosition_Mixed(t *testing.T) {
	src := []byte(mixed)
	cases := []struct {
		byteOff  int
		wantLine uint32
		wantChar uint32
		named    string
	}{
		{0, 0, 0, "start/a"},
		{1, 0, 1, "é"},
		{3, 0, 2, "世"},
		{6, 0, 3, "😀"},
		{10, 0, 5, "b (after astral's 2 units)"},
		{11, 0, 6, "EOF"},
	}
	for _, tc := range cases {
		got := byteOffsetToLSPPosition(src, tc.byteOff)
		if got.Line != tc.wantLine || got.Character != tc.wantChar {
			t.Errorf("byteOffsetToLSPPosition(%d) [%s] = (%d,%d), want (%d,%d)",
				tc.byteOff, tc.named, got.Line, got.Character, tc.wantLine, tc.wantChar)
		}
	}
}

func TestLSPPositionToByteOffset_Mixed(t *testing.T) {
	src := []byte(mixed)
	cases := []struct {
		char     uint32
		wantByte int
		named    string
	}{
		{0, 0, "start/a"},
		{1, 1, "é"},
		{2, 3, "世"},
		{3, 6, "😀"},
		{4, 6, "inside surrogate pair -> clamp to rune start"},
		{5, 10, "b"},
		{6, 11, "EOF"},
		{99, 11, "past line end -> clamp to line end"},
	}
	for _, tc := range cases {
		got := lspPositionToByteOffset(src, protocol.Position{Line: 0, Character: tc.char})
		if got != tc.wantByte {
			t.Errorf("lspPositionToByteOffset(line 0, char %d) [%s] = %d, want %d",
				tc.char, tc.named, got, tc.wantByte)
		}
	}
}

func TestPosition_MultiLine(t *testing.T) {
	// "ab\ncé": a(0) b(1) \n(2) c(3) é(4..5), EOF=6.
	src := []byte("ab\ncé")

	byteToPos := []struct {
		byteOff int
		line    uint32
		char    uint32
	}{
		{0, 0, 0},
		{1, 0, 1},
		{2, 0, 2}, // the newline byte still reports on line 0
		{3, 1, 0},
		{4, 1, 1},
		{6, 1, 2}, // EOF
	}
	for _, tc := range byteToPos {
		got := byteOffsetToLSPPosition(src, tc.byteOff)
		if got.Line != tc.line || got.Character != tc.char {
			t.Errorf("byteOffsetToLSPPosition(%d) = (%d,%d), want (%d,%d)",
				tc.byteOff, got.Line, got.Character, tc.line, tc.char)
		}
	}

	posToByte := []struct {
		line uint32
		char uint32
		want int
	}{
		{0, 0, 0},
		{1, 0, 3},
		{1, 1, 4},
		{1, 2, 6},
		{1, 9, 6}, // char past line end clamps to line end
		{5, 0, 6}, // line past EOF clamps to len(src)
	}
	for _, tc := range posToByte {
		got := lspPositionToByteOffset(src, protocol.Position{Line: tc.line, Character: tc.char})
		if got != tc.want {
			t.Errorf("lspPositionToByteOffset(%d,%d) = %d, want %d", tc.line, tc.char, got, tc.want)
		}
	}
}

// TestRoundTrip walks every rune boundary of a multibyte, multi-line document
// and asserts byte -> position -> byte returns the original offset.
func TestRoundTrip(t *testing.T) {
	src := []byte("spec_version = \"0.4.0\"\n# café 世界 😀\nthreatmodel \"x\" {}\n")

	// Collect rune-boundary byte offsets (plus EOF).
	var boundaries []int
	for i := 0; i <= len(src); {
		boundaries = append(boundaries, i)
		if i == len(src) {
			break
		}
		_, size := utf8.DecodeRune(src[i:])
		i += size
	}

	for _, off := range boundaries {
		pos := byteOffsetToLSPPosition(src, off)
		got := lspPositionToByteOffset(src, pos)
		if got != off {
			t.Errorf("round-trip failed: byte %d -> (%d,%d) -> byte %d",
				off, pos.Line, pos.Character, got)
		}
	}
}

func TestByteRangeToLSP(t *testing.T) {
	src := []byte("aé世😀b")
	r := hcl.Range{
		Start: hcl.Pos{Byte: 1},  // é
		End:   hcl.Pos{Byte: 10}, // b
	}
	got := byteRangeToLSP(src, r)
	if got.Start.Character != 1 || got.End.Character != 5 {
		t.Errorf("byteRangeToLSP = start char %d end char %d, want 1 and 5",
			got.Start.Character, got.End.Character)
	}
}
