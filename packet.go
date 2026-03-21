package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

/*
 * openpgp literal data packet (tag 11) builder
 * ref: rfc 4880 5.9: https://www.rfc-editor.org/rfc/rfc4880#section-5.9
 *
 * Packet structure:
 * [header] [body]
 *
 * body:
 * 1 byte:  mode ('b' binary, 't' text, 'u' utf8, 0xFE custom)
 * 1 byte:  filename length
 * N bytes: filename
 * 4 bytes: timestamp (big endian)
 * rest:    literal data
 */

func buildLiteralDataPacket(data []byte) []byte {
	var buf bytes.Buffer

	body := new(bytes.Buffer)
	body.WriteByte(0xFE)                       // mode (ignored by gpg)
	body.WriteByte(4)                          // filename len
	body.WriteString("meow")                   // filename
	body.Write([]byte{0x34, 0xD3, 0x4D, 0x34}) // timestamp
	body.Write(data)

	bodyBytes := body.Bytes()
	bodyLen := len(bodyBytes)

	/* header: CTB = 0xC0 | tag = 0xCB (new format, tag 11) */
	buf.WriteByte(0xCB)

	/* length encoding (new format, rfc 4880 4.2.2) */
	switch {
	case bodyLen < 192:
		buf.WriteByte(byte(bodyLen))
	case bodyLen < 8384:
		bodyLen -= 192
		buf.WriteByte(byte((bodyLen >> 8) + 192))
		buf.WriteByte(byte(bodyLen & 0xFF))
	default:
		buf.WriteByte(0xFF)
		buf.WriteByte(byte(bodyLen >> 24))
		buf.WriteByte(byte(bodyLen >> 16))
		buf.WriteByte(byte(bodyLen >> 8))
		buf.WriteByte(byte(bodyLen))
	}

	buf.Write(bodyBytes)
	return buf.Bytes()
}

/* dearmor strips ascii armor, returns raw packet bytes */
func dearmor(armored string) ([]byte, error) {
	var b64 []string
	inBody := false

	for _, line := range strings.Split(armored, "\n") {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "-----BEGIN"):
			inBody = true
		case strings.HasPrefix(line, "-----END"):
			inBody = false
		case !inBody:
			/* skip preamble */
		case strings.Contains(line, ":"):
			/* skip armor headers (Version:, Comment:, etc.) */
		case line == "":
			/* skip blank lines */
		case strings.HasPrefix(line, "="):
			/* skip crc checksum */
		default:
			b64 = append(b64, line)
		}
	}

	return base64.StdEncoding.DecodeString(strings.Join(b64, ""))
}

/* armor wraps raw packet bytes in ASCII armor */
func armor(data []byte, blockType string) string {
	var buf strings.Builder

	buf.WriteString(fmt.Sprintf("-----BEGIN %s-----\n\n", blockType))

	/* b64, split into 64-char lines */
	b64 := base64.StdEncoding.EncodeToString(data)
	for i := 0; i < len(b64); i += 64 {
		end := min(i+64, len(b64))
		buf.WriteString(b64[i:end])
		buf.WriteByte('\n')
	}

	/* crc-24 checksum (RFC 4880 P6.1) */
	crc := crc24(data)
	crcBytes := []byte{byte(crc >> 16), byte(crc >> 8), byte(crc)}
	buf.WriteByte('=')
	buf.WriteString(base64.StdEncoding.EncodeToString(crcBytes))
	buf.WriteByte('\n')

	buf.WriteString(fmt.Sprintf("-----END %s-----\n", blockType))
	return buf.String()
}

/* crc24 calculates openpgp crc24 (RFC 4880 P6.1) */
func crc24(data []byte) uint32 {
	const init, poly = 0xB704CE, 0x1864CFB

	crc := uint32(init)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= poly
			}
		}
	}
	return crc & 0xFFFFFF
}

/* prependToKey adds literal data packet before the key packets */
func prependToKey(keyData, payload []byte) []byte {
	packet := buildLiteralDataPacket(payload)
	return append(packet, keyData...)
}

func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
