package pkg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"io"
)

// Magic header to identify our embedded data
var MAGIC_HEADER = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

// EmbedPEInPNG embeds PE bytes into a PNG image using LSB steganography
func EmbedPEInPNG(imgReader io.Reader, peBytes []byte) ([]byte, error) {
	// Decode the PNG image
	img, err := png.Decode(imgReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PNG: %v", err)
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
		return nil, fmt.Errorf("image too small to embed %d bytes of data", len(peBytes))
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
	err = png.Encode(&buf, newImg)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PNG: %v", err)
	}

	return buf.Bytes(), nil
}

// ExtractPEFromPNG extracts embedded PE bytes from a PNG image
func ExtractPEFromPNG(imgReader io.Reader) ([]byte, error) {
	// Decode the PNG image
	img, err := png.Decode(imgReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PNG: %v", err)
	}

	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	// Convert to RGBA for consistent pixel access
	rgbaImg := image.NewRGBA(bounds)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			rgbaImg.Set(x, y, img.At(x, y))
		}
	}

	// Extract the embedded data
	var extractedBits []uint8
	
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixel := rgbaImg.RGBAAt(x, y)
			
			// Extract from R, G, B channels
			channels := []uint8{pixel.R, pixel.G, pixel.B}
			
			for _, channel := range channels {
				// Extract the LSB
				bit := channel & 1
				extractedBits = append(extractedBits, bit)
			}
		}
	}

	// Convert bits to bytes
	var extractedBytes []byte
	for i := 0; i < len(extractedBits); i += 8 {
		if i+7 >= len(extractedBits) {
			break
		}
		
		var b uint8
		for j := 0; j < 8; j++ {
			b |= extractedBits[i+j] << (7 - j)
		}
		extractedBytes = append(extractedBytes, b)
	}

	// Check for magic header
	if len(extractedBytes) < len(MAGIC_HEADER)+4 {
		return nil, fmt.Errorf("insufficient data extracted")
	}

	if !bytes.Equal(extractedBytes[:len(MAGIC_HEADER)], MAGIC_HEADER) {
		return nil, fmt.Errorf("magic header not found - no embedded PE data")
	}

	// Extract the size
	sizeBytes := extractedBytes[len(MAGIC_HEADER):len(MAGIC_HEADER)+4]
	peSize := binary.LittleEndian.Uint32(sizeBytes)

	// Extract the PE bytes
	dataStart := len(MAGIC_HEADER) + 4
	if len(extractedBytes) < dataStart+int(peSize) {
		return nil, fmt.Errorf("insufficient PE data extracted")
	}

	peBytes := extractedBytes[dataStart:dataStart+int(peSize)]
	
	return peBytes, nil
}

// IsValidPNG checks if the provided bytes represent a valid PNG image
func IsValidPNG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := png.Decode(reader)
	return err == nil
}

// decodePNG is a helper function to decode PNG from reader
func decodePNG(reader io.Reader) (image.Image, error) {
	return png.Decode(reader)
} 