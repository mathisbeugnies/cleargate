package main

import (
	"cleargate/pkg/watermark"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: cleargate-decode \"suspicious text\"")
		os.Exit(1)
	}

	text := os.Args[1]
	encoder := watermark.NewEncoder()

	userID, timestamp, err := encoder.Decode(text)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	tm := time.Unix(timestamp, 0)
	fmt.Println("=== CLEARGATE WATERMARK DETECTED ===")
	fmt.Printf("Source User ID: %s\n", userID)
	fmt.Printf("Timestamp:      %s\n", tm.Format(time.RFC3339))
	fmt.Println("====================================")
}
