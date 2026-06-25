package bip0039

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"math/big"
)

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
