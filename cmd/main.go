package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Make sure the folder internal/bank exists
	bankDir := "internal/diceword/bank"
	if err := os.MkdirAll(bankDir, 0755); err != nil {
		fmt.Printf("Failed to create bank folder: %v\n", err)
		return
	}

	reader := bufio.NewReader(os.Stdin)

	// Choose file
	var fileName string
	for {
		fmt.Print("Enter file name (id.txt or en.txt): ")
		input, _ := reader.ReadString('\n')
		fileName = strings.TrimSpace(input)
		if fileName == "id.txt" || fileName == "en.txt" {
			break
		}
		fmt.Println("File must be 'id.txt' or 'en.txt'")
	}

	filePath := filepath.Join(bankDir, fileName)

	// Open file (create if not exists)
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// Read existing words
	existingWords := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			existingWords[line] = true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	fmt.Println("Enter new words (can be multiple, separated by commas or spaces):")
	for {
		fmt.Print("> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		// Remove quotes and split words
		line = strings.ReplaceAll(line, "\"", "")
		words := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})

		newCount := 0
		for _, word := range words {
			word = strings.TrimSpace(word)
			if len(word) < 4 {
				fmt.Printf("Word '%s' is too short, skipped\n", word)
				continue
			}
			if existingWords[word] {
				continue
			}

			// Append to file
			if _, err := file.Seek(0, 2); err != nil { // 2 = SeekEnd
				fmt.Printf("Failed to move pointer to the end of the file: %v\n", err)
				continue
			}
			if _, err := file.WriteString(word + "\n"); err != nil {
				fmt.Printf("Failed to write word: %v\n", err)
				continue
			}

			existingWords[word] = true
			newCount++
		}

		fmt.Printf("%d new words added. Total words now: %d\n", newCount, len(existingWords))
	}

	fmt.Println("Done.")
}
