//go:build js && wasm

// Package main provides the WebAssembly entrypoint for the BIP-0039 library.
package main

import (
	"syscall/js"
)

func generateMnemonic(this js.Value, args []js.Value) any {
	return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}

func main() {
	js.Global().Set(
		"bip39",
		js.ValueOf(map[string]any{
			"generateMnemonic": js.FuncOf(generateMnemonic),
		}),
	)

	select {}
}
