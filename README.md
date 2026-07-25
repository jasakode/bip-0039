# bip-0039

A native Go implementation of the Bitcoin BIP-0039 specification with full support for official wordlists, mnemonic generation, seed derivation, and validation against the official BIP-0039 test vectors.

## Features

- Native Go implementation (no CGO)
- Cryptographically secure entropy generation (`crypto/rand`)
- Generate BIP-0039 mnemonics
- Recover entropy from a mnemonic
- Derive a 512-bit seed using PBKDF2-HMAC-SHA512
- Embedded official BIP-0039 wordlists
- Unicode NFKD normalization
- Official checksum validation
- Official BIP-0039 test vectors
- Zero runtime asset dependencies

## Installation

```bash
go get github.com/jasakode/bip-0039
```

## Quick Start

### Generate a Mnemonic

```go
package main

import (
	"fmt"
	"log"

	bip0039 "github.com/jasakode/bip-0039"
)

func main() {
	entropy, err := bip0039.NewEntropy(256)
	if err != nil {
		log.Fatal(err)
	}

	mnemonic, err := bip0039.NewMnemonic(entropy, bip0039.LangEnglish)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(mnemonic)
}
```

---

### Recover Entropy

```go
entropy, err := bip0039.MnemonicToEntropy(
	mnemonic,
	bip0039.LangEnglish,
)
if err != nil {
	log.Fatal(err)
}
```

---

### Generate Seed

```go
seed := bip0039.MnemonicToSeed(
	mnemonic,
	"my passphrase",
)

fmt.Printf("%x\n", seed)
```

---

### Using Another Language

```go
mnemonic, err := bip0039.NewMnemonic(
	entropy,
	bip0039.LangJapanese,
)
```

Supported languages:

- English
- Japanese
- Korean
- Spanish
- Chinese (Simplified)
- Chinese (Traditional)
- French
- Italian
- Czech
- Portuguese

## Credits & Wordlists License

This project embeds the official BIP-0039 wordlists published by the Bitcoin project.

Source:

https://github.com/bitcoin/bips/tree/master/bip-0039

The original wordlists are licensed under **CC0 1.0 Universal (Public Domain)**.

## Running Tests

```bash
go test -v ./...
```

The test suite validates the implementation against the official BIP-0039 reference vectors.

## License

MIT License

Copyright (c) 2026 PT Anak Karya Kita