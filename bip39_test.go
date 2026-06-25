// package bip0039_test

// import (
// 	"encoding/hex"
// 	"fmt"
// 	"testing"

// 	bip0039 "github.com/jasakode/bip-0039"
// )

// // Struktur data untuk menampung satu test case
// type testVector struct {
// 	entropyHex string
// 	mnemonic   string
// 	passphrase string
// 	seedHex    string
// }

// // Data diambil langsung dari official Bitcoin BIP-0039 test vectors
// var officialVectors = []testVector{
// 	{
// 		entropyHex: "00000000000000000000000000000000",
// 		mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
// 		passphrase: "",
// 		seedHex:    "c55257674ed39fa340b175d3b6007ee14f15bb22dcf2e83a4d5143b4e6b908d0023c03741d8e355de575b119157b313f345db28d820d1dfd00d46d2918550afd",
// 	},
// 	{
// 		entropyHex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
// 		mnemonic:   "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
// 		passphrase: "TREZOR",
// 		seedHex:    "559085660f38b16e45070ffb08a6552da9be154cf4f1ebfc53d102e3b2e3160e1df59ec0ff71221b66df8734f2d3381a179268fdf2208e9cc9810f443be12678",
// 	},
// }

// func TestVector(t *testing.T) {
// 	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
// 	entropy, err := bip0039.MnemonicToEntropy(mnemonic, bip0039.LangEnglish)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	ne, err := hex.DecodeString("00000000000000000000000000000000")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	mm, err := bip0039.NewMnemonic(ne, bip0039.LangEnglish)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	fmt.Println(hex.EncodeToString(entropy))
// 	fmt.Println(mm)
// }

// func TestEntropy(t *testing.T) {
// 	entropy, err := bip0039.NewEntropy(256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	fmt.Println(hex.EncodeToString(entropy))
// }

// func TestMnemonic(t *testing.T) {
// 	entropy, err := bip0039.NewEntropy(256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	mnemonic, err := bip0039.NewMnemonic(entropy, bip0039.LangEnglish)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	fmt.Println(hex.EncodeToString(entropy))
// 	fmt.Println(mnemonic)
// }

// // go test -v -run=TestEntropy

package bip0039_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"

	bip0039 "github.com/jasakode/bip-0039" // Sesuaikan dengan path modul Anda
)

type Vector map[string][][4]string

// TestNewEntropy validasi penolakan bitSize yang tidak sesuai standar BIP-39
func TestNewEntropy(t *testing.T) {
	tests := []struct {
		name    string
		bitSize int
		wantErr error
	}{
		{"Valid 128 bits", 128, nil},
		{"Valid 256 bits", 256, nil},
		{"Too short 96 bits", 96, bip0039.ErrEntropyTooShort},
		{"Too long 512 bits", 512, bip0039.ErrEntropyTooLong},
		{"Not multiple of 32", 130, bip0039.ErrEntropyNotMultipleOf32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy, err := bip0039.NewEntropy(tt.bitSize)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(entropy) != tt.bitSize/8 {
				t.Fatalf("expected entropy length %d bytes, got %d", tt.bitSize/8, len(entropy))
			}
		})
	}
}

// Fungsi pembantu internal test untuk men-decode Base58 tanpa library eksternal tambahan
func base58Decode(input string) []byte {
	b58Alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	answer := big.NewInt(0)
	scratch := big.NewInt(0)

	for i := 0; i < len(input); i++ {
		idx := -1
		for j := 0; j < 58; j++ {
			if input[i] == b58Alphabet[j] {
				idx = j
				break
			}
		}
		if idx == -1 {
			return nil
		}
		scratch.SetInt64(int64(idx))
		answer.Mul(answer, big.NewInt(58))
		answer.Add(answer, scratch)
	}

	// Tambahkan kembali padding prefix '1' (nilai 0 dalam Base58) jika ada di string asli
	payload := answer.Bytes()
	var numZeros int
	for i := 0; i < len(input) && input[i] == b58Alphabet[0]; i++ {
		numZeros++
	}

	result := make([]byte, numZeros+len(payload))
	copy(result[numZeros:], payload)
	return result
}

// TestMnemonicToEntropyValidation menguji deteksi galat checksum atau kata cacat
func TestMnemonicToEntropyValidation(t *testing.T) {
	// Mnemonic dengan checksum sengaja dirusak (kata terakhir diganti dari 'about' menjadi 'abandon')
	invalidMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"

	_, err := bip0039.MnemonicToEntropy(invalidMnemonic, bip0039.LangEnglish)
	if err == nil {
		t.Fatal("expected error for invalid checksum, but got nil")
	}

	// Mnemonic dengan kata yang tidak terdaftar di Wordlist
	unknownWordMnemonic := "jasakode abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	_, err = bip0039.MnemonicToEntropy(unknownWordMnemonic, bip0039.LangEnglish)
	if err == nil {
		t.Fatal("expected error for unknown word, but got nil")
	}

	// Mnemonic dengan jumlah kata tidak baku (hanya 11 kata)
	shortMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	_, err = bip0039.MnemonicToEntropy(shortMnemonic, bip0039.LangEnglish)
	if err == nil {
		t.Fatal("expected error for invalid word count, but got nil")
	}
}

// TestMultiLanguage menguji konsistensi pemuatan wordlist multibahasa
func TestMultiLanguage(t *testing.T) {
	languages := []bip0039.Language{
		bip0039.LangChineseSimplified,
		bip0039.LangChineseTraditional,
		bip0039.LangCzech,
		bip0039.LangEnglish,
		bip0039.LangFrench,
		bip0039.LangItalian,
		bip0039.LangJapanese,
		bip0039.LangKorean,
		bip0039.LangPortuguese,
		bip0039.LangSpanish,
	}

	entropy, err := hex.DecodeString("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f") // 128-bit acak
	if err != nil {
		t.Fatal(err)
	}

	for _, lang := range languages {
		t.Run(string(rune(lang)), func(t *testing.T) {
			// Buat mnemonic dalam bahasa target
			mnemonic, err := bip0039.NewMnemonic(entropy, lang)
			if err != nil {
				t.Fatalf("failed to create mnemonic for language %d: %v", lang, err)
			}

			// Kembalikan ke entropi semula
			recovered, err := bip0039.MnemonicToEntropy(mnemonic, lang)
			if err != nil {
				t.Fatalf("failed to parse mnemonic back for language %d: %v", lang, err)
			}

			if !bytes.Equal(recovered, entropy) {
				t.Fatalf("entropy mismatch for language %d", lang)
			}
		})
	}
}

func TestVectorBIP39(t *testing.T) {
	var vectors Vector
	file, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if err := json.Unmarshal(file, &vectors); err != nil {
		t.Fatalf("failed: %v", err)
	}

	for k := range vectors {
		var lang bip0039.Language
		switch k {
		case "english":
			lang = bip0039.LangEnglish
		case "chinese_simplified":
			lang = bip0039.LangChineseSimplified
		case "chinese_traditional":
			lang = bip0039.LangChineseTraditional
		case "czech":
			lang = bip0039.LangCzech
		case "french":
			lang = bip0039.LangFrench
		case "italian":
			lang = bip0039.LangItalian
		case "japanese":
			lang = bip0039.LangJapanese
		case "korean":
			lang = bip0039.LangKorean
		case "portuguese":
			lang = bip0039.LangPortuguese
		case "spanish":
			lang = bip0039.LangSpanish
		case "russian":
			continue
		case "turkish":
			continue
		}
		for i := range vectors[k] {
			hexEntropy := vectors[k][i][0]
			expectedMnemonic := vectors[k][i][1]
			expectedSeedHex := vectors[k][i][2]
			expectedPrivateKeyHex := vectors[k][i][3]

			passphrase := "TREZOR"

			entropyBytes, err := hex.DecodeString(hexEntropy)
			if err != nil {
				t.Fatal(err)
			}

			// 1. Ambil mnemonic dari fungsi Anda
			mnemonic, err := bip0039.NewMnemonic(entropyBytes, lang)
			if err != nil {
				t.Fatalf("failed to generate mnemonic: %v", err)
			}

			if mnemonic != expectedMnemonic {
				fmt.Println("expected :", expectedMnemonic)
				fmt.Println("result   :", mnemonic)
				t.Fatalf("Invailid mnemonic %v", lang)
			}

			// 2. Turunkan menjadi seed 512-bit
			seed := bip0039.MnemonicToSeed(mnemonic, passphrase)

			// ==========================================
			// VERIFIKASI SEED TERHADAP expectedSeedHex
			// ==========================================
			seedHex := hex.EncodeToString(seed)
			if seedHex != expectedSeedHex {
				t.Errorf("seed mismatch\nexpected: %s\ngot: %s", expectedSeedHex, seedHex)
			}

			// 3. Eksekusi fungsi bip0032 yang baru disatukan
			masterKey, err := bip0039.NewMasterKey(seed)
			if err != nil {
				t.Fatalf("failed to create master key: %v", err)
			}

			// ==========================================
			// VERIFIKASI MASTER KEY TERHADAP xprv
			// ==========================================
			// Kita decode string Base58Check 'expectedPrivateKeyHex' secara manual
			// di dalam test ini untuk mencocokkan isi biner Private Key & Chain Code-nya.
			decodedB58 := base58Decode(expectedPrivateKeyHex)
			if len(decodedB58) < 82 { // 78 byte payload + 4 byte checksum = 82
				t.Fatalf("invalid expected xprv Base58 string length")
			}

			// Berdasarkan spesifikasi standardisasi BIP-32:
			// Byte [0:4]   = Version bytes
			// Byte [4]     = Depth
			// Byte [5:9]   = Parent fingerprint
			// Byte [9:13]  = Child number
			// Byte [13:45] = Chain Code (32 bytes)
			// Byte [45]    = Padding 0x00 (Khusus Private Key)
			// Byte [46:78] = Private Key (32 bytes)
			expectedChainCode := decodedB58[13:45]
			expectedPrivateKey := decodedB58[46:78]

			// Cek Validasi Private Key Mentah
			if !bytes.Equal(masterKey.PrivateKey, expectedPrivateKey) {
				t.Errorf("master private key bytes mismatch\nexpected: %x\ngot: %x", expectedPrivateKey, masterKey.PrivateKey)
			}

			// Cek Validasi Chain Code Mentah
			if !bytes.Equal(masterKey.ChainCode, expectedChainCode) {
				t.Errorf("master chain code bytes mismatch\nexpected: %x\ngot: %x", expectedChainCode, masterKey.ChainCode)
			}
		}
	}

}
