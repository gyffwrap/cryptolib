package diceword

import (
	"errors"
	"math/rand"
)

// DiceWords returns `count` random words from the given language bank ("en" or "id").
func DiceWords(lang string, count int) ([]string, error) {
	words, err := WordsBank(lang)
	if err != nil {
		return nil, err
	}

	if count > len(words) {
		return nil, errors.New("count exceeds word bank size")
	}

	// Copy slice for shuffling
	shuffled := make([]string, len(words))
	copy(shuffled, words)

	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// Return the first `count` words
	return shuffled[:count], nil
}
