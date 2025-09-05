package diceword

import (
	_ "embed"
	"errors"
	"strings"
)

//go:embed bank/en.txt
var enWordBank string

//go:embed bank/id.txt
var idWordBank string

// WordsBank returns a slice of words for the given language ("en" or "id").
func WordsBank(lang string) ([]string, error) {
	var raw string

	switch lang {
	case "en":
		raw = enWordBank
	case "id":
		raw = idWordBank
	default:
		return nil, errors.New("unsupported language: must be 'en' or 'id'")
	}

	lines := strings.Split(raw, "\n")
	words := make([]string, 0, len(lines))

	for _, line := range lines {
		word := strings.TrimSpace(line)
		if word != "" { // skip empty lines
			words = append(words, word)
		}
	}

	return words, nil
}
