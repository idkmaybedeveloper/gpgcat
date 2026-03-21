package main

import (
	"fmt"
	"strconv"
	"strings"
)

/*
 * ansi escape code generator for pgp keys
 * https://en.wikipedia.org/wiki/ANSI_escape_code
 */

const (
	esc       = "\x1b["
	reset     = esc + "0m"
	clearLine = esc + "K"
	cursorUp  = esc + "F"
	clearDown = esc + "J"
)

/* parseColors parses comma-separated ANSI 256-color codes */
func parseColors(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	colors := make([]int, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		c, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid color: %s", p)
		}
		if c < 0 || c > 255 {
			return nil, fmt.Errorf("color out of range (0-255): %d", c)
		}
		colors = append(colors, c)
	}

	return colors, nil
}

/* generateColorBars creates ansi escape sequences */
func generateColorBars(colors []int, message string) []byte {
	var buf strings.Builder

	buf.WriteString(cursorUp)
	buf.WriteString(clearDown)

	for _, color := range colors {
		buf.WriteString(fmt.Sprintf("%s48;5;%dm", esc, color))
		buf.WriteString(clearLine)
		buf.WriteByte('\n')
	}

	buf.WriteString(reset)
	buf.WriteString(clearLine)
	buf.WriteByte('\n')
	buf.WriteString(message)
	buf.WriteByte('\n')

	return []byte(buf.String())
}

/* generatePlainText creates a simple plaintext payload */
func generatePlainText(message string) []byte {
	var buf strings.Builder

	buf.WriteString(cursorUp)
	buf.WriteString(clearDown)
	buf.WriteString(message)
	buf.WriteByte('\n')

	return []byte(buf.String())
}

/* generateCustomANSI creates payload with ansi codes */
func generateCustomANSI(ansiCode, message string) []byte {
	var buf strings.Builder

	buf.WriteString(cursorUp)
	buf.WriteString(clearDown)
	buf.WriteString(ansiCode)
	buf.WriteString(message)
	buf.WriteString(reset)
	buf.WriteByte('\n')

	return []byte(buf.String())
}
