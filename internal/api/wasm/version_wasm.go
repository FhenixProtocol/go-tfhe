package wasm

import (
	_ "unsafe" // for go:linkname
)

//go:wasmimport env get_version
func hostGetVersion() uint32 {
	return 0
}

func LibTfheVersion() uint32 {
	return hostGetVersion()
}
