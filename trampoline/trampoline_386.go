//go:build windows && 386
// +build windows,386

package trampoline

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createTrampoline creates a trampoline to call the original function using a long jump.
func (hook *TrampolineHook) createTrampoline(targetFunc uintptr) (uintptr, error) {

	// Save the original bytes to preserve the original function
	trampoline := make([]byte, 5) // Use long jump size instead of short jump
	copy(trampoline, unsafe.Slice((*byte)(unsafe.Pointer(targetFunc)), len(trampoline)))

	codeCave, _ := windows.VirtualAlloc(0, uintptr(len(trampoline)+5), 0x1000|0x2000, syscall.PAGE_EXECUTE_READWRITE)
	if codeCave == 0 {
		return 0, errors.New("bad code cave")
	}

	// Add a jump back to the rest of the original function
	originalAddr := (targetFunc + 5) - (codeCave + 5)
	jmpBack := []byte{
		0xE9, // MOV RAX, immediate
	}
	jmpBack = append(jmpBack, toBytes(uint64(originalAddr), 4)...)

	trampoline = append(trampoline, jmpBack...)

	for i := 0; i < len(trampoline); i++ {
		*(*byte)(unsafe.Pointer(codeCave + uintptr(i))) = trampoline[i]
	}

	return codeCave, nil
}

func (hook *TrampolineHook) jmpHook(targetFunc, newFunc uintptr) (uintptr, error) {
	// Calculate the distance between the target function and new function
	relAddress := int64(newFunc) - (int64(targetFunc) + int64(shortJumpSize))

	jmpInstruction := []byte{
		0xE9,
	}
	jmpInstruction = append(jmpInstruction, toBytes(uint64(relAddress), 4)...)

	// Short jump is possible
	trampoline, err := hook.createTrampoline(targetFunc)
	if err != nil {
		return 0, fmt.Errorf("failed to create trampoline: %w", err)
	}

	if err := writeMemory(targetFunc, jmpInstruction); err != nil {
		return 0, fmt.Errorf("failed to apply short jump: %w", err)
	}

	return trampoline, nil
}
