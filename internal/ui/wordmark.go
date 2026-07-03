package ui

import (
	"fmt"
	"io"
	"strings"
)

// The CRENEL wordmark is a brutalist block-letter logotype whose TOP EDGE is
// CRENELLATED: a row of merlons (solid blocks) standing on a parapet, with
// crenel gaps between them. The mark therefore literally IS a battlement —
// fusing the logo, the name, and the product's default-deny idea ("a solid wall
// with deliberate gaps you choose to open").

// block is the full-block rune the wordmark is drawn with.
const block = '█'

// wordmarkText is the word the mark spells. Sourced once so the layout math and
// the SVG generator never disagree about it.
const wordmarkText = "CRENEL"

// glyphs is a 5x5 brutalist block font for the wordmark letters. Authored with
// '#'/' ' so the source stays legible; rendered with the full block.
var glyphs = map[rune][]string{
	'C': {"#####", "#    ", "#    ", "#    ", "#####"},
	'R': {"#### ", "#   #", "#### ", "#  # ", "#   #"},
	'E': {"#####", "#    ", "###  ", "#    ", "#####"},
	'N': {"#   #", "##  #", "# # #", "#  ##", "#   #"},
	'L': {"#    ", "#    ", "#    ", "#    ", "#####"},
}

// WordmarkRows returns the wordmark as a slice of equal-width rows of '█' and
// ' ' (no trailing-space trimming, so columns line up for both the ANSI renderer
// and the SVG generator). Row 0 is the crenellated merlon band, row 1 the solid
// parapet it stands on, and rows 2.. the CRENEL block letters.
func WordmarkRows() []string {
	// Assemble the five letter rows with single-space gaps between letters.
	letterRows := make([]string, 5)
	for i := 0; i < 5; i++ {
		parts := make([]string, 0, len(wordmarkText))
		for _, r := range wordmarkText {
			parts = append(parts, strings.ReplaceAll(glyphs[r][i], "#", string(block)))
		}
		letterRows[i] = strings.Join(parts, " ")
	}
	width := len([]rune(letterRows[0]))

	// Crenellated top: merlons three cells wide standing on a solid parapet,
	// separated by two-cell crenel gaps (period 5 across the full width).
	var merlon, parapet strings.Builder
	for x := 0; x < width; x++ {
		parapet.WriteRune(block)
		if x%5 < 3 {
			merlon.WriteRune(block)
		} else {
			merlon.WriteRune(' ')
		}
	}

	rows := make([]string, 0, 7)
	rows = append(rows, merlon.String(), parapet.String())
	rows = append(rows, letterRows...)
	return rows
}

// WriteWordmark renders the crenellated wordmark in the brand green (or plain,
// when color is disabled), each row prefixed by indent.
func (st Style) WriteWordmark(w io.Writer, indent string) {
	for _, row := range WordmarkRows() {
		fmt.Fprintf(w, "%s%s\n", indent, st.Bold(Safe, strings.TrimRight(row, " ")))
	}
}
