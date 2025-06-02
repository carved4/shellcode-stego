package embed

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
	
	"github.com/bogem/id3v2" // For MP3 ID3 tag manipulation
	"github.com/pdfcpu/pdfcpu/pkg/api" // For PDF manipulation
)

var MAGIC_HEADER = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

// Format represents the supported file formats for embedding shellcode
type Format int

const (
	FormatPNG Format = iota
	FormatJPEG
	FormatMP3
	FormatPDF
)

func EmbedPE(filePath, pePath, outputPath string) error {
	// Read the original file
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Detect file format
	format, err := detectFormat(fileData, filePath)
	if err != nil {
		return fmt.Errorf("unsupported file format: %v", err)
	}

	// Read the PE file
	peData, err := ioutil.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("failed to read PE file: %v", err)
	}

	var outputData []byte
	var err2 error
	
	// Embed the PE based on format
	switch format {
	case FormatPNG, FormatJPEG:
		outputData, err2 = embedPEInImage(bytes.NewReader(fileData), peData, format)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into image: %v", err2)
		}
		
		// Verify the output is still a valid image
		if !isValidFile(outputData, format) {
			return fmt.Errorf("output is not valid - embedding failed")
		}
		
	case FormatMP3:
		outputData, err2 = embedPEInMP3(filePath, peData, outputPath)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into MP3: %v", err2)
		}
		
		// For MP3, we've already written the file in embedPEInMP3
		fmt.Printf("Embedded %d bytes of PE data into MP3 ID3 tag\n", len(peData))
		return nil
		
	case FormatPDF:
		outputData, err2 = embedPEInPDF(filePath, peData, outputPath)
		if err2 != nil {
			return fmt.Errorf("failed to embed PE into PDF: %v", err2)
		}
		
		// For PDF, we've already written the file in embedPEInPDF
		fmt.Printf("Embedded %d bytes of PE data into PDF metadata\n", len(peData))
		return nil
	}
	
	// Write the output for non-MP3 formats
	if err := ioutil.WriteFile(outputPath, outputData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}
	
	formatName := "PNG"
	if format == FormatJPEG {
		formatName = "JPEG"
	}
	fmt.Printf("Embedded %d bytes of PE data into %s\n", len(peData), formatName)
	return nil
}

// detectFormat determines the file format from file extension and content
func detectFormat(fileData []byte, filePath string) (Format, error) {
	// First try by file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".png":
		if isValidPNG(fileData) {
			return FormatPNG, nil
		}
	case ".jpg", ".jpeg":
		if isValidJPEG(fileData) {
			return FormatJPEG, nil
		}
	case ".mp3":
		// Basic check for MP3 header
		if len(fileData) > 3 && (bytes.Equal(fileData[:3], []byte("ID3")) || bytes.Equal(fileData[:2], []byte{0xFF, 0xFB})) {
			return FormatMP3, nil
		}
	case ".pdf":
		// Basic check for PDF header
		if len(fileData) > 4 && bytes.Equal(fileData[:4], []byte("%PDF")) {
			return FormatPDF, nil
		}
	}

	// Try to detect by content
	if isValidPNG(fileData) {
		return FormatPNG, nil
	}
	if isValidJPEG(fileData) {
		return FormatJPEG, nil
	}
	// Basic check for MP3 header
	if len(fileData) > 3 && (bytes.Equal(fileData[:3], []byte("ID3")) || bytes.Equal(fileData[:2], []byte{0xFF, 0xFB})) {
		return FormatMP3, nil
	}
	// Basic check for PDF header
	if len(fileData) > 4 && bytes.Equal(fileData[:4], []byte("%PDF")) {
		return FormatPDF, nil
	}

	return FormatPNG, fmt.Errorf("unsupported file format (supported: PNG, JPEG, MP3, PDF)")
}

// embedPEInImage embeds PE bytes into an image using LSB steganography
func embedPEInImage(imgReader io.Reader, peBytes []byte, format Format) ([]byte, error) {
	// Decode the image
	var img image.Image
	var err error

	switch format {
	case FormatPNG:
		img, err = png.Decode(imgReader)
	case FormatJPEG:
		img, err = jpeg.Decode(imgReader)
	default:
		return nil, fmt.Errorf("unsupported format")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %v", err)
	}

	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	// Create a new RGBA image from the original
	newImg := image.NewRGBA(bounds)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			newImg.Set(x, y, img.At(x, y))
		}
	}

	// Prepare the data to embed: magic header + size + PE bytes
	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)
	
	// Write the size of PE bytes as uint32
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)
	
	// Write the actual PE bytes
	dataBuffer.Write(peBytes)
	
	dataToEmbed := dataBuffer.Bytes()

	// Check if we have enough pixels to embed the data
	totalPixels := width * height
	totalBitsNeeded := len(dataToEmbed) * 8
	if totalBitsNeeded > totalPixels*3 { // 3 channels (RGB), we skip alpha
		return nil, fmt.Errorf("image too small to embed %d bytes of data (need %d pixels, have %d)", len(peBytes), totalBitsNeeded/3, totalPixels)
	}

	// Embed the data using LSB steganography
	dataIndex := 0
	bitIndex := 0

	for y := 0; y < height && dataIndex < len(dataToEmbed); y++ {
		for x := 0; x < width && dataIndex < len(dataToEmbed); x++ {
			pixel := newImg.RGBAAt(x, y)
			
			// Embed in R, G, B channels (skip Alpha to avoid transparency issues)
			channels := [](*uint8){&pixel.R, &pixel.G, &pixel.B}
			
			for _, channel := range channels {
				if dataIndex >= len(dataToEmbed) {
					break
				}
				
				// Get the bit to embed
				bit := (dataToEmbed[dataIndex] >> (7 - bitIndex)) & 1
				
				// Clear the LSB and set our bit
				*channel = (*channel & 0xFE) | bit
				
				bitIndex++
				if bitIndex == 8 {
					bitIndex = 0
					dataIndex++
				}
			}
			
			newImg.SetRGBA(x, y, pixel)
		}
	}

	// Encode the new image to bytes
	var buf bytes.Buffer
	switch format {
	case FormatPNG:
		err = png.Encode(&buf, newImg)
	case FormatJPEG:
		// Use high quality for JPEG to minimize artifacts
		err = jpeg.Encode(&buf, newImg, &jpeg.Options{Quality: 95})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encode image: %v", err)
	}

	return buf.Bytes(), nil
}

// isValidPNG checks if the provided bytes represent a valid PNG image
func isValidPNG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := png.Decode(reader)
	return err == nil
}

// isValidJPEG checks if the provided bytes represent a valid JPEG image
func isValidJPEG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := jpeg.Decode(reader)
	return err == nil
}

// isValidFile checks if the provided bytes represent a valid file of the specified format
func isValidFile(data []byte, format Format) bool {
	switch format {
	case FormatPNG:
		return isValidPNG(data)
	case FormatJPEG:
		return isValidJPEG(data)
	case FormatMP3:
		// Basic check for MP3 header
		return len(data) > 3 && (bytes.Equal(data[:3], []byte("ID3")) || bytes.Equal(data[:2], []byte{0xFF, 0xFB}))
	case FormatPDF:
		// Basic check for PDF header
		return len(data) > 4 && bytes.Equal(data[:4], []byte("%PDF"))
	default:
		return false
	}
} 

// embedPEInMP3 embeds PE bytes into an MP3 file's ID3 tag
func embedPEInMP3(mp3Path string, peBytes []byte, outputPath string) ([]byte, error) {
	// First, copy the original MP3 file to the output path
	originalData, err := ioutil.ReadFile(mp3Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read original MP3 file: %v", err)
	}
	
	// Write to the output path
	if err := ioutil.WriteFile(outputPath, originalData, 0644); err != nil {
		return nil, fmt.Errorf("failed to create output MP3 file: %v", err)
	}
	
	// Open the newly created output file to add tags
	tag, err := id3v2.Open(outputPath, id3v2.Options{Parse: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open output MP3 file: %v", err)
	}
	defer tag.Close()

	// Prepare the data to embed: magic header + size + PE bytes
	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)
	
	// Write the size of PE bytes as uint32
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)
	
	// Write the actual PE bytes
	dataBuffer.Write(peBytes)
	
	dataToEmbed := dataBuffer.Bytes()
	
	// Convert to base64 to ensure it's text-safe for ID3 tags
	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(dataToEmbed)))
	base64.StdEncoding.Encode(base64Data, dataToEmbed)
	
	// Add the data to a COMM tag (Comment)
	commentFrame := id3v2.CommentFrame{
		Encoding:    id3v2.EncodingUTF8,
		Language:    "eng",
		Description: "STEGO",
		Text:        string(base64Data),
	}
	tag.AddCommentFrame(commentFrame)

	// Save the file with the new tag
	if err = tag.Save(); err != nil {
		return nil, fmt.Errorf("failed to save MP3 with embedded data: %v", err)
	}

	// Read the output file to return its bytes
	outputData, err := ioutil.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %v", err)
	}

	return outputData, nil
}

// embedPEInPDF embeds PE bytes into a PDF file's metadata
func embedPEInPDF(pdfPath string, peBytes []byte, outputPath string) ([]byte, error) {
	// First, copy the original PDF file to the output path
	originalData, err := ioutil.ReadFile(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read original PDF file: %v", err)
	}
	
	// Write to the output path
	if err := ioutil.WriteFile(outputPath, originalData, 0644); err != nil {
		return nil, fmt.Errorf("failed to create output PDF file: %v", err)
	}
	
	// Prepare the data to embed: magic header + size + PE bytes
	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)
	
	// Write the size of PE bytes as uint32
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)
	
	// Write the actual PE bytes
	dataBuffer.Write(peBytes)
	
	dataToEmbed := dataBuffer.Bytes()
	
	// Convert to base64 to ensure it's text-safe for PDF metadata
	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(dataToEmbed)))
	base64.StdEncoding.Encode(base64Data, dataToEmbed)
	
	// Create PDF configuration - using nil for default configuration
	
	// Add the data to PDF metadata as custom property
	properties := map[string]string{
		"STEGO": string(base64Data),
	}
	
	// Add metadata to the PDF
	err = api.AddPropertiesFile(outputPath, outputPath, properties, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to add metadata to PDF: %v", err)
	}
	
	// Read the output file to return its bytes
	outputData, err := ioutil.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %v", err)
	}
	
	return outputData, nil
}