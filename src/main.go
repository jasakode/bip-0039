//go:build js && wasm

// Package main provides the WebAssembly entrypoint for the BIP-0039 library.
package main

import (
	"syscall/js"

	bip0039 "github.com/jasakode/bip-0039"
)

func generateMnemonic(this js.Value, args []js.Value) any {
	entropy, err := bip0039.NewEntropy(256)
	if err != nil {
		return js.ValueOf(err.Error())
	}

	mnemonic, err := bip0039.NewMnemonic(entropy, bip0039.LangEnglish)
	if err != nil {
		return js.ValueOf(err.Error())
	}

	return js.ValueOf(mnemonic)
}

func main() {
	fn := js.FuncOf(generateMnemonic)
	defer fn.Release()

	js.Global().Set("generateMnemonic", fn)

	select {}
}
