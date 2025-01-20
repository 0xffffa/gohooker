package gohooker

import "github.com/0xffffa/gohooker/trampoline"

func NewHook(original uintptr, hookFunc interface{}) *trampoline.TrampolineHook {
	return trampoline.NewHook(original, hookFunc)
}
