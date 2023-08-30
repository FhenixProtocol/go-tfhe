package wasm

import (
	_ "unsafe" // for go:linkname
)

//go:wasmimport env get_version
func hostGetVersion() uint32

func LibTfheVersion() uint32 {
	return hostGetVersion()
}
