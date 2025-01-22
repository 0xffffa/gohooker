package trampoline

import (
	"reflect"
	"strings"
	"syscall"
)

func WrapFunction[T any](funcAddress uintptr) interface{} {
	fn := *(new(T))

	if reflect.TypeOf(fn).Kind() != reflect.Func {
		panic("non function tried to wraped?")
	}

	funcType := reflect.TypeOf(fn)

	// Create a closure with the same parameters and return types
	return reflect.MakeFunc(funcType, func(args []reflect.Value) []reflect.Value {
		numOut := funcType.NumOut()
		if numOut > 1 {
			panic("too many return values")
		}

		var syscallArgs []uintptr

		for _, arg := range args {
			if arg.Kind() == reflect.Pointer {
				syscallArgs = append(syscallArgs, arg.Pointer())
			} else if strings.Contains(strings.ToLower(arg.String()), "uint") {
				syscallArgs = append(syscallArgs, uintptr(arg.Uint()))
			} else if strings.Contains(strings.ToLower(arg.String()), "int") {
				syscallArgs = append(syscallArgs, uintptr(arg.Int()))
			} else {
				if strings.Contains(strings.ToLower(arg.Type().Kind().String()), "uint") {
					syscallArgs = append(syscallArgs, uintptr(arg.Uint()))
				} else if strings.Contains(strings.ToLower(arg.Type().Kind().String()), "int") {
					syscallArgs = append(syscallArgs, uintptr(arg.Int()))
				} else {
					panic("unknown arg type")
				}
			}
		}

		ret, _, _ := syscall.SyscallN(
			funcAddress,
			syscallArgs...,
		)

		var returnValues []reflect.Value
		if numOut == 1 {
			returnType := funcType.Out(0)
			if !strings.Contains(strings.ToLower(returnType.String()), "int") {
				panic("not int return type")
			}

			val := reflect.New(returnType)
			val.Elem().SetInt(int64(ret))

			returnValues = append(returnValues, val.Elem())
		}

		return returnValues
	}).Interface()
}
