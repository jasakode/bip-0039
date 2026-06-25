package bip0039

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

//go:embed wordlists/chinese_simplified.txt
var chinese_simplified string

//go:embed wordlists/chinese_traditional.txt
var chinese_traditional string

//go:embed wordlists/czech.txt
var czech string

//go:embed wordlists/english.txt
var english string

//go:embed wordlists/french.txt
var french string

//go:embed wordlists/italian.txt
var italian string

//go:embed wordlists/japanese.txt
var japanese string

//go:embed wordlists/korean.txt
var korean string

//go:embed wordlists/portuguese.txt
var portuguese string

//go:embed wordlists/spanish.txt
var spanish string

// Language merepresentasikan tipe data kustom untuk mengidentifikasi bahasa pendukung BIP-39.
type Language int

// Wordlist adalah array statis dengan kapasitas tepat 2048 kata sesuai spesifikasi standar BIP-39.
type Wordlist [2048]string

// Daftar konstanta bahasa resmi yang didukung oleh spesifikasi BIP-39.
const (
	LangChineseSimplified Language = iota
	LangChineseTraditional
	LangCzech
	LangEnglish
	LangFrench
	LangItalian
	LangJapanese
	LangKorean
	LangPortuguese
	LangSpanish
)

var (
	// ErrEntropyTooShort dipicu jika ukuran bit kurang dari 128 bit.
	ErrEntropyTooShort = errors.New("entropy bit size is too short: minimum is 128 bits")

	// ErrEntropyTooLong dipicu jika ukuran bit melebihi 256 bit.
	ErrEntropyTooLong = errors.New("entropy bit size is too long: maximum is 256 bits")

	// ErrEntropyNotMultipleOf32 dipicu jika ukuran bit bukan kelipatan 32.
	ErrEntropyNotMultipleOf32 = errors.New("entropy bit size must be a multiple of 32")

	// ErrInvalidWordlistCount dipicu ketika file aset teks wordlist tidak memiliki tepat 2048 kata.
	ErrInvalidWordlistCount = errors.New("invalid wordlist: total processed words must be exactly 2048")

	// ErrUnsupportedLanguage dipicu jika tipe bahasa yang diminta tidak terdaftar atau tidak didukung.
	ErrUnsupportedLanguage = errors.New("unsupported language")

	// ErrBitStringLength dipicu ketika panjang teks biner yang akan dikonversi bukan merupakan kelipatan 8.
	ErrBitStringLength = errors.New("bit string length must be a multiple of 8")
)

// loadedWordlists bertindak sebagai cache memori global untuk menyimpan kamus kata yang sudah matang hasil parsing.
var loadedWordlists map[Language]Wordlist

func init() {
	loadedWordlists = make(map[Language]Wordlist)

	// Daftarkan semua berkas bahasa mentah untuk diproses satu kali saat inisialisasi package
	languages := map[Language]string{
		LangChineseSimplified:  chinese_simplified,
		LangChineseTraditional: chinese_traditional,
		LangCzech:              czech,
		LangEnglish:            english,
		LangFrench:             french,
		LangItalian:            italian,
		LangJapanese:           japanese,
		LangKorean:             korean,
		LangPortuguese:         portuguese,
		LangSpanish:            spanish,
	}

	for lang, rawData := range languages {
		wl, err := parse(rawData, lang)
		if err != nil {
			panic(err) // Menghentikan startup aplikasi jika terdapat aset internal wordlist yang cacat
		}
		loadedWordlists[lang] = wl
	}
}

// parse mengubah data string mentah dari berkas teks wordlist menjadi tipe Wordlist [2048]string.
// Fungsi ini aman digunakan lintas platform karena memanfaatkan strings.Fields untuk memotong whitespace dan CRLF Windows.
func parse(data string, lang Language) (Wordlist, error) {
	var wl Wordlist
	words := strings.Fields(data)

	index := 0
	for _, word := range words {
		if index >= 2048 {
			break
		}

		cleanedWord := strings.TrimSpace(word)
		if cleanedWord == "" {
			continue
		}

		wl[index] = cleanedWord
		index++
	}

	// Validasi kepatuhan total kata standar BIP-39
	if index != 2048 {
		return wl, fmt.Errorf("%w (language: %d, loaded: %d/2048)", ErrInvalidWordlistCount, lang, index)
	}

	return wl, nil
}

// getWordlist mengambil data Wordlist yang telah dimuat di memori berdasarkan tipe bahasa yang dipilih.
// Operasi ini berjalan dengan efisiensi waktu O(1).
func getWordlist(lang Language) (Wordlist, error) {
	wl, found := loadedWordlists[lang]
	if !found {
		return Wordlist{}, ErrUnsupportedLanguage
	}
	return wl, nil
}

// bytesToBits mengonversi slice byte menjadi representasi string biner yang berisi karakter '0' dan '1'.
func bytesToBits(bytes []byte) string {
	var sb strings.Builder
	for _, b := range bytes {
		fmt.Fprintf(&sb, "%08b", b)
	}
	return sb.String()
}

// decimalToBits mengonversi nilai desimal integer (indeks kata) menjadi string biner sepanjang tepat 11-bit
func decimalToBits(num int) string {
	return fmt.Sprintf("%011b", num)
}

// bitsToBytes mengonversi deretan string biner (kelipatan 8 bit) kembali menjadi bentuk kepingan slice byte asli.
func bitsToBytes(bits string) ([]byte, error) {
	if len(bits)%8 != 0 {
		return nil, ErrBitStringLength
	}

	bytes := make([]byte, len(bits)/8)
	for i := range bytes {
		var b byte
		for j := 0; j < 8; j++ {
			b <<= 1
			if bits[i*8+j] == '1' {
				b |= 1
			}
		}
		bytes[i] = b
	}
	return bytes, nil
}

// bitsToDecimal mengonversi potongan string biner 11-karakter menjadi nilai indeks desimal integer (0 hingga 2047).
func bitsToDecimal(bits string) int {
	var result int
	for i := 0; i < len(bits); i++ {
		result <<= 1
		if bits[i] == '1' {
			result |= 1
		}
	}
	return result
}

// validateBitSize memeriksa apakah ukuran bit entropi yang dimasukkan memenuhi standar spesifikasi BIP-39.
// Ukuran yang valid wajib berada di rentang 128 hingga 256 bit serta merupakan kelipatan dari 32.
func validateBitSize(bitSize int) error {
	if bitSize < 128 {
		return ErrEntropyTooShort
	}
	if bitSize > 256 {
		return ErrEntropyTooLong
	}
	if bitSize%32 != 0 {
		return ErrEntropyNotMultipleOf32
	}
	return nil
}

// NewEntropy menghasilkan slice byte berisi data acak (entropi) yang aman secara kriptografi (CSPRNG)
// berdasarkan ukuran bitSize yang diminta. Parameter bitSize yang valid meliputi 128, 160, 192, 224, atau 256.
func NewEntropy(bitSize int) ([]byte, error) {
	if err := validateBitSize(bitSize); err != nil {
		return nil, err
	}

	expectedBytes := bitSize / 8
	entropy := make([]byte, expectedBytes)

	n, err := rand.Read(entropy)
	if err != nil {
		return nil, err
	}

	if n != expectedBytes {
		return nil, fmt.Errorf("entropy short read: expected %d bytes, got %d", expectedBytes, n)
	}

	return entropy, nil
}

// NewMnemonic mengubah potongan data entropi acak menjadi jajaran frasa kata mnemonic standar BIP-39
// sesuai dengan bahasa yang ditentukan di parameter lang.
func NewMnemonic(entropy []byte, lang Language) (string, error) {
	entropyBitLen := len(entropy) * 8
	if entropyBitLen < 128 || entropyBitLen > 256 || entropyBitLen%32 != 0 {
		return "", fmt.Errorf("invalid entropy length: must be between 128 and 256 bits and multiple of 32")
	}

	words, err := getWordlist(lang)
	if err != nil {
		return "", err
	}

	// Hitung SHA-256 untuk diekstrak menjadi bit checksum tambahan
	hash := sha256.Sum256(entropy)
	checksumBitLen := entropyBitLen / 32

	entropyBits := bytesToBits(entropy)
	hashBits := bytesToBits(hash[:])

	// Gabungkan bit biner entropi utama dengan pecahan bit checksum di bagian ekornya
	combinedBits := entropyBits + hashBits[:checksumBitLen]

	// Memecah setiap kelompok 11-bit menjadi representasi indeks kata kamus
	var mnemonicWords []string
	for i := 0; i < len(combinedBits); i += 11 {
		bitGroup := combinedBits[i : i+11]
		index := bitsToDecimal(bitGroup)
		mnemonicWords = append(mnemonicWords, words[index])
	}

	// PENTING: Tentukan delimiter berdasarkan standar BIP-39
	// Khusus bahasa Jepang menggunakan spasi ideografik (\u3000)
	joinSeparator := " "
	if lang == LangJapanese { // Sesuaikan nama konstanta/enum LangJapanese di package Anda
		joinSeparator = "\u3000"
	}

	return strings.Join(mnemonicWords, joinSeparator), nil
}

// MnemonicToEntropy melakukan dekonstruksi balik dari kalimat frasa mnemonic untuk memulihkan data entropi biner asli.
// Fungsi ini juga melakukan validasi ketat terhadap integritas checksum untuk mendeteksi adanya salah ketik (typo) pada kata.
func MnemonicToEntropy(mnemonic string, lang Language) ([]byte, error) {
	words, err := getWordlist(lang)
	if err != nil {
		return nil, err
	}

	// Membangun peta indeks terbalik (inverted index map) untuk mempercepat pencarian kata menjadi O(1)
	wordMap := make(map[string]int, len(words))
	for idx, word := range words {
		wordMap[word] = idx
	}

	mnemonicWords := strings.Fields(strings.TrimSpace(mnemonic))
	wordCount := len(mnemonicWords)

	if wordCount < 12 || wordCount > 24 || wordCount%3 != 0 {
		return nil, fmt.Errorf("invalid mnemonic word count: %d", wordCount)
	}

	var combinedBits strings.Builder
	for _, word := range mnemonicWords {
		idx, found := wordMap[word]
		if !found {
			return nil, fmt.Errorf("word '%s' is not in the wordlist for this language", word)
		}
		combinedBits.WriteString(decimalToBits(idx))
	}
	allBits := combinedBits.String()

	totalBits := len(allBits)
	checksumBitLen := totalBits / 33
	entropyBitLen := totalBits - checksumBitLen

	entropyBits := allBits[:entropyBitLen]
	checksumBits := allBits[entropyBitLen:]

	entropy, err := bitsToBytes(entropyBits)
	if err != nil {
		return nil, err
	}

	// Hitung ulang hash dari entropi yang terekstrak untuk verifikasi checksum
	hash := sha256.Sum256(entropy)
	hashBits := bytesToBits(hash[:])
	expectedChecksumBits := hashBits[:checksumBitLen]

	if checksumBits != expectedChecksumBits {
		return nil, fmt.Errorf("invalid mnemonic checksum: verification failed")
	}

	return entropy, nil
}

// MnemonicToSeed memproses string mnemonic beserta passphrase tambahan menggunakan algoritma PBKDF2 (SHA-512, 2048 iterasi)
// untuk memproduksi nilai kunci 512-bit (64-byte) Seed Key. Fungsi ini menormalisasi string ke bentuk UTF-8 NFKD sesuai aturan regulasi BIP-39.
func MnemonicToSeed(mnemonic string, passphrase string) []byte {
	// Bersihkan variasi spasi berlebih antar sistem operasi termasuk spasi ideografik Jepang (\u3000)
	normalized := strings.ReplaceAll(mnemonic, "\u3000", " ")
	words := strings.Fields(normalized)
	cleanedMnemonic := strings.Join(words, " ")

	// Wajib dilakukan normalisasi Unicode NFKD agar representasi biner teks beraksen/non-ASCII bersifat identik secara global
	nfkdMnemonic := norm.NFKD.String(cleanedMnemonic)
	nfkdSalt := norm.NFKD.String("mnemonic" + passphrase)

	// Eksekusi fungsi pembentukan kunci berbasis password (PBKDF2)
	seed := pbkdf2.Key([]byte(nfkdMnemonic), []byte(nfkdSalt), 2048, 64, sha512.New)

	return seed
}
