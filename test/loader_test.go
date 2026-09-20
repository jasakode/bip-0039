package test

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestLoadBIP0039(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	soPath := filepath.Join(
		root,
		"..",
		"share",
		"libbip0039.so",
	)

	if _, err := os.Stat(soPath); err != nil {
		t.Fatalf(
			"shared library not found: %s",
			soPath,
		)
	}

	handle, errMessage := loadLibrary(soPath)

	if handle == nil {
		t.Fatalf(
			"failed to load %s: %s",
			soPath,
			errMessage,
		)
	}

	t.Cleanup(func() {
		if err := closeLibrary(handle); err != nil {
			t.Errorf("failed to close library: %v", err)
		}
	})

	t.Logf("loaded: %s", soPath)
}

func TestBIP0039Symbols(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	soPath := filepath.Join(
		root,
		"..",
		"share",
		"libbip0039.so",
	)

	handle, errMessage := loadLibrary(soPath)

	if handle == nil {
		t.Fatalf(
			"failed to load %s: %s",
			soPath,
			errMessage,
		)
	}

	t.Cleanup(func() {
		closeLibrary(handle)
	})

	symbols := []string{
		"bip0039_new_entropy",
		"bip0039_new_mnemonic",
		"bip0039_mnemonic_to_entropy",
		"bip0039_mnemonic_to_seed",
	}

	for _, name := range symbols {
		t.Run(name, func(t *testing.T) {
			symbol, errMessage := loadSymbol(
				handle,
				name,
			)

			if symbol == nil {
				t.Fatalf(
					"symbol %s not found: %s",
					name,
					errMessage,
				)
			}

			t.Logf(
				"found %s at %p",
				name,
				unsafe.Pointer(symbol),
			)
		})
	}
}
