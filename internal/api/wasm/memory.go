package wasm

import "unsafe"

// UnmanagedVector is a structure that mimics a Rust Option<Vec<u8>> type for
// FFI compatibility. It holds a pointer to the array, along with its length and capacity.
//
// WARNING: Using UnmanagedVector involves manipulating raw pointers and low-level memory
// operations. Make sure to follow the guidelines and best practices for using `unsafe`.
type UnmanagedVector struct {
	// IsNone is true if this should be treated as Option::None
	IsNone bool
	// Ptr points to the array data
	Ptr unsafe.Pointer
	// Len is the number of elements in the array
	Len uint32
	// Cap is the number of elements that can be held in the allocated memory
	Cap uint32
}

// ByteSliceView is a structure for providing a read-only view into a Go byte slice.
//
// WARNING: Be cautious about the lifetime of the slice that you're getting a view into.
// Make sure it lives as long as this view, or you could encounter undefined behavior.
type ByteSliceView struct {
	// IsNil is true if the slice is nil
	IsNil bool
	// Ptr points to the slice data
	Ptr unsafe.Pointer
	// Len is the number of elements in the slice
	Len uint64
}

// MakeView creates a ByteSliceView from a Go byte slice. The returned view provides
// read-only access to the slice data.
//
// WARNING: Ensure that the slice outlives this view to avoid undefined behavior.
func MakeView(s []byte) ByteSliceView {
	if s == nil {
		return ByteSliceView{IsNil: true, Ptr: nil, Len: 0}
	}

	if len(s) == 0 {
		return ByteSliceView{IsNil: false, Ptr: nil, Len: 0}
	}

	return ByteSliceView{
		IsNil: false,
		Ptr:   unsafe.Pointer(&s[0]),
		Len:   uint64(len(s)),
	}
}

// NewUnmanagedVector creates an UnmanagedVector from a Go byte slice.
//
// WARNING: This function exposes raw pointers to Go-managed data. Ensure that the
// data lives long enough and consider using runtime.KeepAlive to prolong the life
// of the data.
func NewUnmanagedVector(data []byte) UnmanagedVector {
	if data == nil {
		return UnmanagedVector{IsNone: true, Ptr: nil, Len: 0, Cap: 0}
	}

	if len(data) == 0 {
		return UnmanagedVector{IsNone: false, Ptr: nil, Len: 0, Cap: 0}
	}

	return UnmanagedVector{
		IsNone: false,
		Ptr:    unsafe.Pointer(&data[0]),
		Len:    uint32(len(data)),
		Cap:    uint32(cap(data)),
	}
}

// CopyAndDestroyUnmanagedVector creates a Go byte slice from an UnmanagedVector
// and "destroys" the vector to prevent further use.
//
// WARNING: This function performs a copy operation and you should be cautious
// about the UnmanagedVector's life cycle. After this operation, you should not
// use the original UnmanagedVector.
func CopyAndDestroyUnmanagedVector(v UnmanagedVector) []byte {
	if v.IsNone {
		return nil
	}

	if v.Len == 0 {
		return []byte{}
	}

	// Copying bytes back to a Go slice
	out := make([]byte, v.Len)
	src := (*[1 << 30]byte)(v.Ptr)[:v.Len:v.Len] // similar to C.GoBytes
	copy(out, src)

	// "Destroy" or zero out UnmanagedVector (since there's no explicit destruction)
	v.Ptr = nil
	v.Len = 0
	v.Cap = 0

	return out
}

// Compile this code as a Go WebAssembly (Wasm) module for use in Web environments.
// Always be cautious of the data's lifetime and the rules of using `unsafe` when sharing data across boundaries.
