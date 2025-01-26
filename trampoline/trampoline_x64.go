//go:build amd64
// +build amd64

package trampoline

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type SystemInfo struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

func (hook *TrampolineHook) getFunctionLength(funcAddress unsafe.Pointer) int {
	length := 0
	for {
		// Cast the function address to a pointer to the current offset
		addr := unsafe.Pointer(uintptr(funcAddress) + uintptr(length))
		value := *(*uint32)(addr) // Read 4 bytes as uint32

		// Check for the 0xCCCCCCCC marker
		if value == 0xCCCCCCCC {
			break
		}
		length += 4 // Increment by 4 bytes since we're reading uint32
	}
	return length
}

func (hook *TrampolineHook) allocNearAddress(targetAddr uintptr) uintptr {
	var sysInfo SystemInfo
	hook.getSystemInfo(&sysInfo)

	pageSize := uintptr(sysInfo.PageSize)
	startAddr := targetAddr & ^(pageSize - 1) // Round down to the nearest page boundary
	minAddr := uintptr(startAddr - 0x7FFFFF00)
	if minAddr < sysInfo.MinimumApplicationAddress {
		minAddr = sysInfo.MinimumApplicationAddress
	}
	maxAddr := uintptr(startAddr + 0x7FFFFF00)
	if maxAddr > sysInfo.MaximumApplicationAddress {
		maxAddr = sysInfo.MaximumApplicationAddress
	}

	startPage := startAddr - (startAddr % pageSize)
	pageOffset := uintptr(1)

	for {
		byteOffset := pageOffset * pageSize
		highAddr := startPage + byteOffset
		var lowAddr uintptr
		if startPage > byteOffset {
			lowAddr = startPage - byteOffset
		}

		needsExit := highAddr > maxAddr && lowAddr < minAddr

		if highAddr < maxAddr {
			outAddr, _ := windows.VirtualAlloc(highAddr, pageSize, 0x1000|0x2000, syscall.PAGE_EXECUTE_READWRITE)
			if outAddr != 0 {
				return outAddr
			}
		}

		if lowAddr > minAddr {
			outAddr, _ := windows.VirtualAlloc(lowAddr, pageSize, 0x1000|0x2000, syscall.PAGE_EXECUTE_READWRITE)
			if outAddr != 0 {
				return outAddr
			}
		}

		pageOffset++

		if needsExit {
			break
		}
	}

	return 0
}

// jmpHook sets a jump hook on the target function and allows the replacement
// function to call the original one.
func (hook *TrampolineHook) jmpHook(targetFunc, newFunc uintptr) (uintptr, error) {
	// Calculate the distance between the target function and new function
	offset := int64(newFunc) - (int64(targetFunc) + int64(shortJumpSize))

	// Check if a short jump is possible, otherwise, use a long jump
	if offset < int64(-0x7FFF_FFFF) || offset > int64(0x7FFF_FFFF) {
		// Long jump required
		trampoline, err := hook.createTrampoline(targetFunc)
		if err != nil {
			return 0, fmt.Errorf("failed to create trampoline: %w", err)
		}
		if err := hook.applyLongJump(targetFunc, newFunc); err != nil {
			return 0, fmt.Errorf("failed to apply long jump: %w", err)
		}
		return trampoline, nil
	}

	// Short jump is possible
	trampoline, err := hook.createTrampoline(targetFunc)
	if err != nil {
		return 0, fmt.Errorf("failed to create trampoline: %w", err)
	}
	if err := hook.applyShortJump(targetFunc, newFunc); err != nil {
		return 0, fmt.Errorf("failed to apply short jump: %w", err)
	}
	return trampoline, nil
}

// createTrampoline creates a trampoline to call the original function using a long jump.
func (hook *TrampolineHook) createTrampoline(targetFunc uintptr) (uintptr, error) {

	// Save the original bytes to preserve the original function
	trampoline := make([]byte, 5) // Use long jump size instead of short jump
	copy(trampoline, unsafe.Slice((*byte)(unsafe.Pointer(targetFunc)), len(trampoline)))

	codeCave := hook.allocNearAddress(targetFunc)
	if codeCave == 0 {
		return 0, errors.New("bad code cave")
	}

	// Add a jump back to the rest of the original function
	originalAddr := targetFunc + 5
	jmpBack := []byte{
		0x49, 0xBA, // MOV RAX, immediate
	}
	jmpBack = append(jmpBack, toBytes(uint64(originalAddr), 8)...)
	jmpBack = append(jmpBack, 0x41, 0xFF, 0xE2) // JMP RAX

	trampoline = append(trampoline, jmpBack...)

	for i := 0; i < len(trampoline); i++ {
		*(*byte)(unsafe.Pointer(codeCave + uintptr(i))) = trampoline[i]
	}

	return codeCave, nil
}

// applyShortJump applies a short jump from targetFunc to newFunc.
func (hook *TrampolineHook) applyShortJump(targetFunc, newFunc uintptr) error {
	offset := int32(newFunc - (targetFunc + uintptr(shortJumpSize)))
	jmpBytes := append([]byte{0xE9}, toBytes(uint64(offset), 4)...)
	return writeMemory(targetFunc, jmpBytes)
}

// applyLongJump applies a long jump from targetFunc to newFunc.
func (hook *TrampolineHook) applyLongJump(targetFunc, newFunc uintptr) error {
	jmpBytes := []byte{
		0x49, 0xBA, // MOV RAX, immediate
	}
	jmpBytes = append(jmpBytes, toBytes(uint64(newFunc), 8)...)
	jmpBytes = append(jmpBytes, 0x41, 0xFF, 0xE2) // JMP RAX

	relayFunction := hook.allocNearAddress(targetFunc)
	if relayFunction == 0 {
		return errors.New("bad relay function")
	}

	if err := writeMemory(relayFunction, jmpBytes); err != nil {
		return err
	}

	movInstruct := []byte{
		0xE9, // MOV RAX, immediate
	}

	relAddress := relayFunction - (targetFunc + 5)
	movInstruct = append(movInstruct, toBytes(uint64(relAddress), 4)...)

	return writeMemory(targetFunc, movInstruct)
}

// allocateExecMemory allocates executable memory.
func (hook *TrampolineHook) alloc(size uintptr) (uintptr, error) {
	addr, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAlloc").Call(
		0,
		size,
		0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
		0x40,          // PAGE_EXECUTE_READWRITE
	)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAlloc failed: %w", err)
	}
	return addr, nil
}

func (hook *TrampolineHook) isFarJump(from, to uintptr) bool {
	if to >= from {
		return (to - from) > uintptr(0x7fff0000)
	} else {
		return (from - to) > uintptr(0x7fff0000)
	}
}
func (hook *TrampolineHook) getSystemInfo(sysInfo *SystemInfo) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetSystemInfo := kernel32.NewProc("GetSystemInfo")
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(sysInfo)))
}
