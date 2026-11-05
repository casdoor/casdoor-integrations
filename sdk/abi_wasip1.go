// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build wasip1

package sdk

import "unsafe"

// buffers handed to Casdoor, kept here so the garbage collector leaves them alone until Casdoor frees them
var pinned = map[uint32][]byte{}

func pin(buf []byte) uint32 {
	if len(buf) == 0 {
		buf = make([]byte, 1)[:0]
	}
	ptr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf[:1]))))
	pinned[ptr] = buf
	return ptr
}

//go:wasmexport casdoor_alloc
func casdoorAlloc(size uint32) uint32 {
	return pin(make([]byte, size))
}

//go:wasmexport casdoor_free
func casdoorFree(ptr uint32) {
	delete(pinned, ptr)
}

// casdoor_call takes a JSON call Casdoor wrote into a buffer from casdoor_alloc and returns where the JSON result is,
// as the pointer in the high 32 bits and the length in the low 32 bits. Casdoor frees both buffers.
//
//go:wasmexport casdoor_call
func casdoorCall(ptr uint32, size uint32) uint64 {
	input := pinned[ptr][:size]
	output := handle(input)
	return uint64(pin(output))<<32 | uint64(len(output))
}

//go:wasmimport casdoor fetch
func casdoorFetch(ptr unsafe.Pointer, size uint32) uint32

//go:wasmimport casdoor read_result
func casdoorReadResult(ptr unsafe.Pointer)

//go:wasmimport casdoor log
func casdoorLog(ptr unsafe.Pointer, size uint32)

func hostFetch(input []byte) []byte {
	size := casdoorFetch(unsafe.Pointer(unsafe.SliceData(input)), uint32(len(input)))
	output := make([]byte, size)
	if size > 0 {
		casdoorReadResult(unsafe.Pointer(unsafe.SliceData(output)))
	}
	return output
}

func hostLog(message string) {
	if message == "" {
		return
	}
	casdoorLog(unsafe.Pointer(unsafe.StringData(message)), uint32(len(message)))
}
