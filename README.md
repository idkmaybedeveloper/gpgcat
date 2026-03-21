# gpgcat

embed custom messages and art into PGP public keys

when someone runs `cat yourkey.asc | gpg`, theyll see your message before the key info

```
$ cat fancy.asc | gpg
     <- colored stripe
     <- colored stripe
     <- ...
meow :3
pub   ed25519 2023-02-01 [SCA]
      7E63DA22964F4E9B1FF547E1BF78000000000000
uid           You <you@example.com>
```

## inst

```bash
go install code.wejust.rest/lain/gpgcat@latest
```

or... build from source:
```bash
go build -o gpgcat .
```

## usage!!

```bash
# vanity base64 line + message
gpgcat -v "++lain++meow++" -m "mreow" < key.asc > fancy.asc

# color stripes + message
gpgcat -c "161,161,93,21,21" -m "bip boop" < key.asc

# just text
gpgcat -m "meow :3" < key.asc > fancy.asc

# from gpg directly
gpg --export -a YOUR_KEY_ID | gpgcat -v "uwu" -m "hi" > fancy.asc
```

## vanity

`-v` embeds readable text in the first base64 line:
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

yzj+Ju/0+/0+/0+/0+/0+/0+/++lain++meow+++/0+/0+/0+/0+/0+/NNNNNBtb
                           ^^^^^^^^^^^^^^
```

only A-Za-z0-9+/ allowed (base64 charset)

## colors

256 color codes (0-255), comma-sep. each = one horizontal stripe

ref: https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit

## how it works???

openpgp format allows "literal data packets" (tag 11) anywhere in the
packet stream. when gpg reads one from stdin, it outputs the raw bytes
to stdout. we prepend such a packet containing ansi escape codes +
your message. the key itself remains valid and importable

## IMPORTANT!!!

use `cat key.asc | gpg` (pipe), not `gpg key.asc` (file argument).
only the pipe method outputs literal data to terminal
