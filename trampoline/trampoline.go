package trampoline

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// JMP instruction opcodes
	shortJumpSize = 5  // Short jump size
	longJumpSize  = 13 // Long jump size (x64 RIP-relative addressing)
)

type TrampolineHook struct {
	Src        uintptr
	Dst        uintptr
	Trampoline uintptr
}

// writeMemory writes the given bytes to the specified address.
func writeMemory(address uintptr, data []byte) error {
	// Change the memory protection to allow writing
	var oldProtect uint32
	if err := windows.VirtualProtect(address, uintptr(len(data)), 0x40, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect failed: %w", err)
	}

	// Write the bytes to memory
	copy(unsafe.Slice((*byte)(unsafe.Pointer(address)), len(data)), data)

	// Restore the original memory protection
	if err := windows.VirtualProtect(address, uintptr(len(data)), oldProtect, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect failed to restore: %w", err)
	}

	return nil
}

// toBytes converts a 64-bit integer to a little-endian byte slice.
func toBytes(value uint64, size int) []byte {
	bytes := make([]byte, size)
	for i := 0; i < size; i++ {
		bytes[i] = byte(value >> (i * 8))
	}
	return bytes
}

// NewHook creates a new trampoline hook, replacing the original function with the new function.
func NewHook(original uintptr, hookFunc interface{}) *TrampolineHook {
	hooker := syscall.NewCallback(hookFunc)

	hook := &TrampolineHook{
		Src: original,
		Dst: hooker,
	}
	trampoline, err := hook.jmpHook(original, hooker)
	if err != nil {
		panic(err)
	}
	hook.Trampoline = trampoline
	return hook
}
