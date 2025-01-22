# gohooker - function ptr hooking in go!

A pure go x86/x64 compatible trampoline hook for stdlib functions\
Hook functions from pointers, windows api, dll & more!

## Installation

```console
go get github.com/0xffffa/gohooker
```

## Usage

```go
package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/0xffffa/gohooker"
	"github.com/0xffffa/gohooker/trampoline"
)

type MessageBoxW func(hWnd syscall.Handle, lpText, lpCaption *uint16, uType uint) int

func main() {
	dll, err := syscall.LoadDLL("user32.dll")
	if err != nil {
		panic(err)
	}
	targetProc, err := dll.FindProc("MessageBoxW")
	if err != nil {
		panic(err)
	}

	targetFuncAddr := targetProc.Addr()
	target := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

	if r, _, err := target.Call(0, wstrUPtr("Before Hook"), wstrUPtr("Before Hook"), 0); r == 0 && err != nil {
		panic(err)
	}

	var trampHook *trampoline.TrampolineHook
	trampHook = gohooker.NewHook(targetFuncAddr, func(hWnd syscall.Handle, lpText, lpCaption *uint16, uType uint) int {
		fmt.Println("Hooker called man", trampHook.Trampoline)
		return trampoline.WrapFunction[MessageBoxW](trampHook.Trampoline).(MessageBoxW)(hWnd, wstrPtr("Yep this the hooked body with MY function"), wstrPtr("And this is the Title"), uType)
	})

	if r, _, err := target.Call(0, wstrUPtr("MessageBoxW"), wstrUPtr("MessageBoxW"), 0); r == 0 && err != nil {
		panic(err)
	}
}

func wstrUPtr(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}

func wstrPtr(str string) *uint16 {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return ptr
}
```
