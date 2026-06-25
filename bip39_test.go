package bip0039_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
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

// MasterKey menyimpan komponen utama dari Hierarchical Deterministic (HD) Wallet Master Node.
type MasterKey struct {
	PrivateKey []byte // 32 byte
	ChainCode  []byte // 32 byte
}

var ErrInvalidSeedLen = errors.New("seed length must be between 16 and 64 bytes")

// NewMasterKey mengambil seed (dari BIP-39) dan menghasilkan Master Key berdasarkan spesifikasi BIP-32.
// Seluruh proses derivasi dan validasi kurva secp256k1 ditangani langsung di dalam satu fungsi ini.
func NewMasterKey(seed []byte) (*MasterKey, error) {
	// 1. Validasi standar BIP-32: Ukuran seed harus di antara 128 hingga 512 bit (16 - 64 bytes)
	if len(seed) < 16 || len(seed) > 64 {
		return nil, ErrInvalidSeedLen
	}

	// 2. Siapkan HMAC-SHA512 dengan key khusus "Bitcoin seed"
	hmacKey := []byte("Bitcoin seed")
	mac := hmac.New(sha512.New, hmacKey)
	mac.Write(seed)
	i := mac.Sum(nil) // Menghasilkan 64 byte data (I)

	// 3. Pecah hasil menjadi dua bagian (masing-masing 32 byte)
	il := i[:32] // I_L (Left) -> Calon Private Key
	ir := i[32:] // I_R (Right) -> Chain Code

	// 4. VALIDASI KEAMANAN KRIPTOGRAFI (Kurva secp256k1)

	// A. Validasi IsZero: Pastikan I_L tidak bernilai 0 semua
	isZero := true
	for _, v := range il {
		if v != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return nil, errors.New("illegal master private key generated: key is zero")
	}

	// B. Validasi Curve Order: Pastikan I_L < Orde Kurva N
	curveOrderHex := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	n := new(big.Int)
	n.SetString(curveOrderHex, 16)

	k := new(big.Int)
	k.SetBytes(il)

	if k.Cmp(n) >= 0 {
		return nil, errors.New("illegal master private key generated: key is greater than or equal to curve order")
	}

	// 5. Lolos semua validasi, kembalikan objek MasterKey
	return &MasterKey{
		PrivateKey: il,
		ChainCode:  ir,
	}, nil
}

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
			masterKey, err := NewMasterKey(seed)
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
