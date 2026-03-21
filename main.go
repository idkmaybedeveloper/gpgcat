package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

/*
 * how it works:
 * 1. openpgp allows "literal data packets" (tag 11) in the stream
 * 2. when gpg encounters one, it outputs the raw data to stdout
 * 3. we prepend such a packet containing ansi codes + text
 * 4. terminal renders the colors, then gpg shows key info
 */

func main() {
	colors := flag.String("c", "", "color stripes (comma-separated 256-color codes)")
	message := flag.String("m", "", "message to display")
	customANSI := flag.String("ansi", "", "raw ansi escape sequence")
	inputFile := flag.String("i", "", "input file (default: stdin)")
	outputFile := flag.String("o", "", "output file (default: stdout)")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `gpgcat - embed messages into pgp public keys

USAGE
  gpgcat [options] < key.asc > modified.asc
  gpg --export -a KEYID | gpgcat [options] > fancy.asc

OPTIONS
`)
		flag.PrintDefaults()

		fmt.Fprint(os.Stderr, `
EXAMPLES
  # bi flag (magenta, magenta, purple, blue, blue)
  gpgcat -c "161, 161, 93, 21, 21" -m "bip boop" < key.asc

  # Just a message
  gpgcat -m "meow :3" < key.asc

  # custom ansi (blink + red text)
  gpgcat -ansi "\e[5;31m" -m "idk alert" < key.asc

  # verify it works
  cat out.asc | gpg

COLORS
  us 256 color codes (0-255). each color = one stripe
  reference: https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit

NOTE
  Use 'cat key.asc | gpg' (pipe), not 'gpg key.asc' (file arg)
  the latter doesnt output literal data to terminal...
`)
	}

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	/* open input */
	var input io.Reader = os.Stdin
	if *inputFile != "" {
		f, err := os.Open(*inputFile)
		if err != nil {
			logger.Error("failed to open input", "file", *inputFile, "err", err)
			os.Exit(1)
		}
		defer f.Close()
		input = f
	}

	/* read n dearmor key */
	armoredKey, err := readAll(input)
	if err != nil {
		logger.Error("failed to read input", "err", err)
		os.Exit(1)
	}

	keyData, err := dearmor(string(armoredKey))
	if err != nil {
		logger.Error("failed to dearmor key", "err", err)
		os.Exit(1)
	}

	/* build payload */
	if *message == "" {
		*message = "meow :3"
	}

	var payload []byte
	switch {
	case *customANSI != "":
		ansi := strings.ReplaceAll(*customANSI, "\\x1b", "\x1b")
		ansi = strings.ReplaceAll(ansi, "\\e", "\x1b")
		payload = generateCustomANSI(ansi, *message)

	case *colors != "":
		colorList, err := parseColors(*colors)
		if err != nil {
			logger.Error("invalid colors", "err", err)
			os.Exit(1)
		}
		payload = generateColorBars(colorList, *message)

	default:
		payload = generatePlainText(*message)
	}

	/* prepend literal data packet and re-armor */
	modified := prependToKey(keyData, payload)
	armored := armor(modified, "PGP PUBLIC KEY BLOCK")

	/* write output */
	var output io.Writer = os.Stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			logger.Error("failed to create output", "file", *outputFile, "err", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	}

	if _, err := fmt.Fprint(output, armored); err != nil {
		logger.Error("failed to write output", "err", err)
		os.Exit(1)
	}

	if *outputFile != "" {
		logger.Info("done", "output", *outputFile)
	}
}
