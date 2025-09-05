package passphrase

import (
	"fmt"
	"strings"

	"github.com/gyffwrap/cryptolib/internal/diceword"
)

type DiceEncryptResult struct {
	Payload   string   // hasil Encrypt PPResult
	DiceWords []string // kata-kata yang digunakan sebagai passphrase
}

func EncryptWithDiceWord(plaintext []byte, lang string, count int) (*DiceEncryptResult, error) {
	// 1. Ambil kata random dari diceword sesuai bahasa dan jumlah
	words, err := diceword.DiceWords(lang, count)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dice words: %w", err)
	}

	// 2. Gabungkan menjadi passphrase
	passphrase := strings.Join(words, "-")

	// 3. Encrypt plaintext menggunakan passphrase
	args := &Args{
		Passphrase: passphrase,
		ByteCode:   32, // default AES-256
	}

	ppResult, err := Encrypt(plaintext, args)
	if err != nil {
		return nil, fmt.Errorf("encrypt with dice words: %w", err)
	}

	// 4. Return wrapped result
	return &DiceEncryptResult{
		Payload:   ppResult.Payload,
		DiceWords: words,
	}, nil
}
