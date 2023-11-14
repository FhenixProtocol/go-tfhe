//go:build linux && !muslc && amd64

package amd64

// #cgo LDFLAGS: -Wl,-rpath,${SRCDIR} -L${SRCDIR} -ltfhe_wrapper.x86_64
import "C"
