package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

/*
 * vanity base64 for pgp keys
 *
 * makes the first line of armor contain readable text like:
 * y47+BF78/0000/0000/0000++lexi+re/pgp++meow/mrrp/beep/boop++49016
 *
 * base64 charset: A-Za-z0-9+/
 * every 3 bytes -> 4 base64 chars
 */

const b64LineLen = 64

/* validB64Char checks if char is valid in base64 */
func validB64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/'
}

/* validateVanity checks if string can be used in base64 */
func validateVanity(s string) error {
	for i, c := range []byte(s) {
		if !validB64Char(c) {
			return fmt.Errorf("invalid char '%c' at pos %d (use A-Za-z0-9+/ only)", c, i)
		}
	}
	if len(s) > b64LineLen-8 {
		return fmt.Errorf("too long (max %d chars)", b64LineLen-8)
	}
	return nil
}

/* buildVanityLine creates 64-char base64 string with vanity text */
func buildVanityLine(vanity string) string {
	var sb strings.Builder

	/* header area (will be overwritten by packet header) */
	sb.WriteString("y47+")

	/* padding before vanity */
	remaining := b64LineLen - 4 - len(vanity) - 4
	padBefore := remaining / 2
	padAfter := remaining - padBefore

	for i := range padBefore {
		sb.WriteByte("0+/"[i%3])
	}

	sb.WriteString(vanity)

	for i := range padAfter {
		sb.WriteByte("+/0"[i%3])
	}

	sb.WriteString("0000")

	line := sb.String()
	if len(line) < b64LineLen {
		line += strings.Repeat("A", b64LineLen-len(line))
	} else if len(line) > b64LineLen {
		line = line[:b64LineLen]
	}

	return line
}

/*
 * buildVanityPacket creates literal data packet with vanity base64
 *
 * packet body structure:
 * [mode:1] [namelen:1] [name:N] [timestamp:4] [data:...]
 *
 * we stuff vanity junk into a fake "name" field, then append real payload
 */
func buildVanityPacket(vanity string, payload []byte) ([]byte, error) {
	if err := validateVanity(vanity); err != nil {
		return nil, err
	}

	line := buildVanityLine(vanity)

	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("invalid vanity line: %w", err)
	}

	/*
	 * decoded = 48 bytes from first b64 line
	 * we need to structure it as valid literal data body:
	 * byte 0-1: packet header (cb + len) - we'll fix
	 * byte 2:   mode (0xFE)
	 * byte 3:   namelen (N)
	 * byte 4 to 4+N: name (junk)
	 * next 4:   timestamp
	 * rest:     we don't use, goes to payload
	 *
	 * lets use namelen=38 so name takes most of the vanity junk
	 * then timestamp, then payload starts
	 */

	junkForName := 38 // bytes 4-41 = name (38 bytes)
	// bytes 42-45 = timestamp (4 bytes)
	// bytes 46-47 = start of data (2 bytes from vanity)

	/* build packet manually */
	var buf []byte

	/* header */
	buf = append(buf, 0xcb) // ctb tag 11
	buf = append(buf, 0x00) // length placeholder

	/* body: mode */
	buf = append(buf, 0xFE)

	/* body: namelen + name (vanity junk) */
	buf = append(buf, byte(junkForName))
	buf = append(buf, decoded[4:4+junkForName]...) // use decoded bytes as name

	/* body: timestamp */
	buf = append(buf, 0x34, 0xD3, 0x4D, 0x34)

	/* body: actual data (ansi payload) */
	buf = append(buf, payload...)

	/* fix length */
	bodyLen := len(buf) - 2
	if bodyLen >= 192 {
		return nil, fmt.Errorf("payload too long (%d bytes, max 191)", bodyLen)
	}
	buf[1] = byte(bodyLen)

	return buf, nil
}
