package bip0039

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"

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

// Language identifies a supported BIP-39 language used for mnemonic
// generation, validation, and entropy conversion.
type Language int

// Wordlist represents the complete BIP-39 wordlist for a specific language.
// Each wordlist contains exactly 2,048 words, where each word occupies a
// fixed index defined by the BIP-39 specification. These indices are used
// to map between 11-bit values and mnemonic words during encoding and decoding.
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
	// ErrEntropyTooShort indicates that the requested entropy size is less than
	// the minimum allowed size of 128 bits.
	ErrEntropyTooShort = errors.New("entropy bit size is too short: minimum is 128 bits")

	// ErrEntropyTooLong indicates that the requested entropy size exceeds the
	// maximum allowed size of 256 bits.
	ErrEntropyTooLong = errors.New("entropy bit size is too long: maximum is 256 bits")

	// ErrEntropyNotMultipleOf32 indicates that the entropy size is not a
	// multiple of 32 bits, as required by the BIP-39 specification.
	ErrEntropyNotMultipleOf32 = errors.New("entropy bit size must be a multiple of 32")

	// ErrInvalidWordlistCount indicates that a loaded BIP-39 wordlist does not
	// contain exactly 2,048 words.
	ErrInvalidWordlistCount = errors.New("invalid wordlist: total processed words must be exactly 2048")

	// ErrUnsupportedLanguage indicates that the specified language is not
	// supported by this package.
	ErrUnsupportedLanguage = errors.New("unsupported language")

	// ErrBitStringLength indicates that a bit string cannot be converted to
	// bytes because its length is not a multiple of 8 bits.
	ErrBitStringLength = errors.New("bit string length must be a multiple of 8")
)

var (
	// loadedWordlists caches parsed and validated BIP-39 wordlists, indexed by language.
	loadedWordlists map[Language]Wordlist

	// loadedWordlistsOnce ensures the wordlist cache is initialized only once.
	loadedWordlistsOnce sync.Once

	// loadedWordlistsInitErr stores the result of the wordlist cache
	// initialization. It is returned on every call to initLoadedWordlists,
	// ensuring consistent error reporting after sync.Once has executed.
	loadedWordlistsInitErr error
)

// parse converts the raw contents of an embedded BIP-39 wordlist into a
// Wordlist. It normalizes whitespace using strings.Fields, making it
// platform-independent and compatible with Unix (LF) and Windows (CRLF)
// line endings.
//
// The returned wordlist is validated to ensure it contains exactly 2,048
// words, as required by the BIP-39 specification.
func parse(data string, lang Language) (Wordlist, error) {
	var wl Wordlist
	words := strings.Fields(data)

	index := 0
	for _, word := range words {
		if index >= len(wl) {
			break
		}

		cleanedWord := strings.TrimSpace(word)
		if cleanedWord == "" {
			continue
		}

		wl[index] = cleanedWord
		index++
	}

	if index != len(wl) {
		return wl, fmt.Errorf(
			"%w (language: %d, loaded: %d/%d)",
			ErrInvalidWordlistCount,
			lang,
			index,
			len(wl),
		)
	}

	return wl, nil
}

// initLoadedWordlists initializes the in-memory cache of embedded BIP-39
// wordlists. Each wordlist is parsed and validated before being stored.
//
// The cache is initialized only once and reused for all subsequent lookups.
// An error is returned if any embedded wordlist fails validation.
func initLoadedWordlists() error {
	loadedWordlistsOnce.Do(func() {
		loadedWordlists = make(map[Language]Wordlist)

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
		for lang, data := range languages {
			wl, err := parse(data, lang)
			if err != nil {
				loadedWordlistsInitErr = err
				return
			}
			loadedWordlists[lang] = wl
		}
	})

	return loadedWordlistsInitErr
}

// getWordlist returns the parsed BIP-39 wordlist for the specified language.
// The wordlist cache is initialized on first use. If the language is not
// supported, ErrUnsupportedLanguage is returned.
//
// Lookup is performed in constant time, O(1).
func getWordlist(lang Language) (Wordlist, error) {
	if err := initLoadedWordlists(); err != nil {
		return Wordlist{}, err
	}

	wl, found := loadedWordlists[lang]
	if !found {
		return Wordlist{}, ErrUnsupportedLanguage
	}

	return wl, nil
}

// bytesToBits converts a byte slice into its binary string representation.
// Each byte is encoded as an 8-bit binary value, producing a string
// consisting only of the characters '0' and '1'.
func bytesToBits(bytes []byte) string {
	var sb strings.Builder
	sb.Grow(len(bytes) * 8)

	for _, b := range bytes {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}

	return sb.String()
}

// decimalToBits converts an integer into its 11-bit binary string
// representation. The output is left-padded with zeros to always produce
// exactly 11 bits, as required by the BIP-39 specification.
func decimalToBits(num int) string {
	var bits [11]byte
	for i := 10; i >= 0; i-- {
		if num&(1<<uint(10-i)) != 0 {
			bits[i] = '1'
		} else {
			bits[i] = '0'
		}
	}
	return string(bits[:])
}

// bitsToBytes converts a binary string into its corresponding byte slice.
// The input must consist only of '0' and '1' characters, and its length
// must be a multiple of 8 bits.
func bitsToBytes(bits string) ([]byte, error) {
	if len(bits)%8 != 0 {
		return nil, ErrBitStringLength
	}

	bytes := make([]byte, len(bits)/8)

	for i := range bytes {
		var b byte

		for j := 0; j < 8; j++ {
			b <<= 1

			switch bits[i*8+j] {
			case '1':
				b |= 1
			case '0':
				// Do nothing.
			default:
				return nil, fmt.Errorf("invalid bit character %q at index %d", bits[i*8+j], i*8+j)
			}
		}

		bytes[i] = b
	}

	return bytes, nil
}

// bitsToDecimal converts an 11-bit binary string into its corresponding
// integer value. In BIP-39, the returned value represents a word index
// in the range 0 to 2,047.
func bitsToDecimal(bits string) (int, error) {
	var result int

	for i := 0; i < len(bits); i++ {
		result <<= 1

		switch bits[i] {
		case '1':
			result |= 1
		case '0':
			// Do nothing.
		default:
			return 0, fmt.Errorf("invalid bit character %q at index %d", bits[i], i)
		}
	}

	return result, nil
}

// validateBitSize verifies that an entropy size complies with the BIP-39
// specification. A valid entropy size must be between 128 and 256 bits,
// inclusive, and be a multiple of 32 bits.
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

// NewEntropy generates a cryptographically secure random entropy of the
// specified size using crypto/rand. Valid entropy sizes are 128, 160, 192,
// 224, and 256 bits, as defined by the BIP-39 specification.
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

// NewMnemonic converts entropy into a BIP-39 mnemonic phrase using the
// specified language. The entropy must be 128, 160, 192, 224, or 256 bits,
// as defined by the BIP-39 specification.
//
// The lang parameter selects one of the supported official BIP-39 wordlists,
// such as English, Japanese, Korean, Spanish, French, Italian, Czech,
// Portuguese, Chinese (Simplified), or Chinese (Traditional).
func NewMnemonic(entropy []byte, lang Language) (string, error) {
	const wordBitSize = 11

	entropyBitLen := len(entropy) * 8
	if err := validateBitSize(entropyBitLen); err != nil {
		return "", err
	}

	wordlist, err := getWordlist(lang)
	if err != nil {
		return "", err
	}

	// BIP-39 appends the first ENT/32 bits of the SHA-256 hash as the checksum.
	checksumBitLen := entropyBitLen / 32
	hash := sha256.Sum256(entropy)

	combinedBits := bytesToBits(entropy) + bytesToBits(hash[:])[:checksumBitLen]

	mnemonic := make([]string, 0, len(combinedBits)/wordBitSize)

	for i := 0; i < len(combinedBits); i += wordBitSize {
		index, err := bitsToDecimal(combinedBits[i : i+wordBitSize])
		if err != nil {
			return "", err
		}

		mnemonic = append(mnemonic, wordlist[index])
	}

	separator := " "
	if lang == LangJapanese {
		// Japanese mnemonics use the ideographic space (U+3000) as the word separator.
		separator = "\u3000"
	}

	return strings.Join(mnemonic, separator), nil
}

// MnemonicToEntropy converts a BIP-39 mnemonic phrase back into its original
// entropy using the specified language. The mnemonic checksum is verified
// according to the BIP-39 specification before the entropy is returned.
//
// The lang parameter specifies which official BIP-39 wordlist to use.
func MnemonicToEntropy(mnemonic string, lang Language) ([]byte, error) {
	const wordBitSize = 11

	wordlist, err := getWordlist(lang)
	if err != nil {
		return nil, err
	}

	// Build a reverse lookup table for constant-time word index lookups.
	wordMap := make(map[string]int, len(wordlist))
	for index, word := range wordlist {
		wordMap[word] = index
	}

	mnemonicWords := strings.Fields(strings.TrimSpace(mnemonic))
	wordCount := len(mnemonicWords)

	if wordCount < 12 || wordCount > 24 || wordCount%3 != 0 {
		return nil, fmt.Errorf("invalid mnemonic word count: %d", wordCount)
	}

	var combinedBits strings.Builder
	combinedBits.Grow(wordCount * wordBitSize)

	for _, word := range mnemonicWords {
		index, found := wordMap[word]
		if !found {
			return nil, fmt.Errorf("word %q is not in the selected wordlist", word)
		}

		combinedBits.WriteString(decimalToBits(index))
	}

	bits := combinedBits.String()

	totalBitLen := len(bits)
	checksumBitLen := totalBitLen / 33
	entropyBitLen := totalBitLen - checksumBitLen

	entropy, err := bitsToBytes(bits[:entropyBitLen])
	if err != nil {
		return nil, err
	}

	// Verify the checksum defined by the BIP-39 specification.
	hash := sha256.Sum256(entropy)
	expectedChecksum := bytesToBits(hash[:])[:checksumBitLen]

	if bits[entropyBitLen:] != expectedChecksum {
		return nil, fmt.Errorf("invalid mnemonic checksum")
	}

	return entropy, nil
}

// MnemonicToSeed processes a mnemonic string along with an optional passphrase using the PBKDF2 algorithm (SHA-512, 2048 iterations)
// to generate a 512-bit (64-byte) Seed Key. This function normalizes the input strings into UTF-8 NFKD format according to the BIP-39 specification.
func MnemonicToSeed(mnemonic string, passphrase string) []byte {
	// Normalize excessive whitespace variations across operating systems, including the Japanese ideographic space (\u3000)
	normalized := strings.ReplaceAll(mnemonic, "\u3000", " ")
	words := strings.Fields(normalized)
	cleanedMnemonic := strings.Join(words, " ")

	// Unicode NFKD normalization is required to ensure identical binary representation for accented and non-ASCII text globally
	nfkdMnemonic := norm.NFKD.String(cleanedMnemonic)
	nfkdSalt := norm.NFKD.String("mnemonic" + passphrase)

	// Execute the password-based key derivation function (PBKDF2)
	seed := pbkdf2.Key([]byte(nfkdMnemonic), []byte(nfkdSalt), 2048, 64, sha512.New)

	return seed
}
