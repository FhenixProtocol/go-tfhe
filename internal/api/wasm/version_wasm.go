package wasm

import (
	_ "unsafe" // for go:linkname
)

//go:wasmimport env get_version
func hostGetVersion() string {
	return "0"
}

func LibTfheVersion() string {
	return hostGetVersion()
}
