//go:build !linux && muslc

package amd64

// #cgo LDFLAGS: -Wl,-rpath,${SRCDIR} -L${SRCDIR} -ltfhe_wrapper
import "C"
