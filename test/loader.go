package test

/*
#include <dlfcn.h>
#include <stdlib.h>

static void* load_library(const char* path) {
	return dlopen(path, RTLD_NOW);
}

static void* load_symbol(void* handle, const char* name) {
	return dlsym(handle, name);
}

static const char* load_error(void) {
	return dlerror();
}

static int close_library(void* handle) {
	return dlclose(handle);
}
*/
import "C"

import (
	"unsafe"
)

func loadLibrary(path string) (unsafe.Pointer, string) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	handle := C.load_library(cPath)

	if handle == nil {
		err := C.load_error()

		if err == nil {
			return nil, "unknown dlopen error"
		}

		return nil, C.GoString(err)
	}

	return unsafe.Pointer(handle), ""
}

func loadSymbol(handle unsafe.Pointer, name string) (unsafe.Pointer, string) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	symbol := C.load_symbol(handle, cName)

	if symbol == nil {
		err := C.load_error()

		if err == nil {
			return nil, "unknown dlsym error"
		}

		return nil, C.GoString(err)
	}

	return unsafe.Pointer(symbol), ""
}

func closeLibrary(handle unsafe.Pointer) error {
	result := C.close_library(handle)

	if result != 0 {
		err := C.load_error()

		if err != nil {
			return &dlError{
				message: C.GoString(err),
			}
		}

		return &dlError{
			message: "unknown dlclose error",
		}
	}

	return nil
}

type dlError struct {
	message string
}

func (e *dlError) Error() string {
	return e.message
}
