package main

/*
#include <stdint.h>
*/
import "C"

import (
	"unsafe"

	bip0039 "github.com/jasakode/bip-0039"
)

//export bip0039_new_entropy
func bip0039_new_entropy(
	bitSize C.int,
	out *C.uchar,
	outLen C.int,
) C.int {
	entropy, err := bip0039.NewEntropy(int(bitSize))
	if err != nil {
		return -1
	}

	if int(outLen) < len(entropy) {
		return -2
	}

	buffer := unsafe.Slice((*byte)(unsafe.Pointer(out)), len(entropy))

	copy(buffer, entropy)

	return C.int(len(entropy))
}

//export bip0039_new_mnemonic
func bip0039_new_mnemonic(
	entropy *C.uchar,
	entropyLen C.int,
	lang C.int,
	out *C.char,
	outLen C.int,
) C.int {

	if entropy == nil || entropyLen <= 0 {
		return -1
	}

	if out == nil || outLen <= 0 {
		return -2
	}

	entropyBytes := unsafe.Slice(
		(*byte)(unsafe.Pointer(entropy)),
		int(entropyLen),
	)

	mnemonic, err := bip0039.NewMnemonic(
		entropyBytes,
		bip0039.Language(lang),
	)

	if err != nil {
		return -3
	}

	// C string membutuhkan null terminator.
	required := len(mnemonic) + 1

	// Buffer terlalu kecil.
	if int(outLen) < required {
		return -4
	}

	output := unsafe.Slice(
		(*byte)(unsafe.Pointer(out)),
		required,
	)

	copy(output, mnemonic)
	output[len(mnemonic)] = 0

	return C.int(len(mnemonic))
}

//export bip0039_mnemonic_to_entropy
func bip0039_mnemonic_to_entropy(
	mnemonic *C.char,
	lang C.int,
	out *C.uchar,
	outLen C.int,
) C.int {

	if mnemonic == nil {
		return -1
	}

	if out == nil || outLen <= 0 {
		return -2
	}

	// Convert C string → Go string.
	mnemonicString := C.GoString(mnemonic)

	entropy, err := bip0039.MnemonicToEntropy(
		mnemonicString,
		bip0039.Language(lang),
	)

	if err != nil {
		return -3
	}

	if int(outLen) < len(entropy) {
		return -4
	}

	output := unsafe.Slice(
		(*byte)(unsafe.Pointer(out)),
		len(entropy),
	)

	copy(output, entropy)

	return C.int(len(entropy))
}

//export bip0039_mnemonic_to_seed
func bip0039_mnemonic_to_seed(
	mnemonic *C.char,
	passphrase *C.char,
	out *C.uchar,
	outLen C.int,
) C.int {

	if mnemonic == nil {
		return -1
	}

	if out == nil || outLen < 64 {
		return -2
	}

	mnemonicString := C.GoString(mnemonic)

	passphraseString := ""

	if passphrase != nil {
		passphraseString = C.GoString(passphrase)
	}

	seed := bip0039.MnemonicToSeed(
		mnemonicString,
		passphraseString,
	)

	output := unsafe.Slice(
		(*byte)(unsafe.Pointer(out)),
		64,
	)

	copy(output, seed)

	return 64
}

func main() {}
