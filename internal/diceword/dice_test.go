package diceword

import (
	"testing"
)

func TestDiceWords(t *testing.T) {

	tests := []struct {
		lang    string
		count   int
		wantErr bool
	}{
		{"en", 15, false},
		{"id", 10, false},
		{"xx", 3, true},      // invalid language
		{"en", 999999, true}, // request lebih besar dari word bank
	}

	for _, tt := range tests {
		words, err := DiceWords(tt.lang, tt.count)

		if tt.wantErr {
			if err == nil {
				t.Errorf("DiceWords(%q, %d) expected error, got none", tt.lang, tt.count)
			} else {
				t.Logf("DiceWords(%q, %d) correctly returned error: %v", tt.lang, tt.count, err)
			}
		} else {
			if err != nil {
				t.Errorf("DiceWords(%q, %d) unexpected error: %v", tt.lang, tt.count, err)
			}
			if len(words) != tt.count {
				t.Errorf("DiceWords(%q, %d) expected %d words, got %d",
					tt.lang, tt.count, tt.count, len(words))
			}
			t.Logf("DiceWords(%q, %d) generated: %v", tt.lang, tt.count, words)
		}
	}
}

func BenchmarkDiceWords(b *testing.B) {

	for b.Loop() {
		_, err := DiceWords("en", 10)
		if err != nil {
			b.Fatalf("DiceWords benchmark failed: %v", err)
		}
	}
}
