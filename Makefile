.PHONY: all build build-rust build-go test

# Builds the Rust library libtfhe_wrapper
BUILDERS_PREFIX := ghcr.io/scrtlabs/tfhe-builder
# Contains a full Go dev environment in order to run Go tests on the built library
ALPINE_TESTER := ghcr.io/scrtlabs/tfhe-builder-alpine:0.0.1

USER_ID := $(shell id -u)
USER_GROUP = $(shell id -g)
GO_ROOT = $(shell go env GOROOT)

GOARCH=arm64
ifeq ($(shell uname --hardware-platform), x86_64)
	GOARCH=amd64
endif

SHARED_LIB_SRC = "" # File name of the shared library as created by the Rust build system
SHARED_LIB_DST = "amd64/" # File name of the shared library that we store
ifeq ($(OS),Windows_NT)
	SHARED_LIB_SRC = wasmvm.dll
	SHARED_LIB_DST = wasmvm.dll
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		SHARED_LIB_SRC = libtfhe_wrapper.so
#		SHARED_LIB_DST = libtfhe_wrapper.$(shell rustc --print cfg | grep target_arch | cut  -d '"' -f 2).so
                SHARED_LIB_DST = libtfhe_wrapper.so
		TARGET_RUST_DIR = target
		RUST_TARGET =
	endif
	ifeq ($(UNAME_S),Darwin)
		SHARED_LIB_SRC = libtfhe_wrapper.dylib
		SHARED_LIB_DST = libtfhe_wrapper.dylib
		TARGET_RUST_DIR = target/aarch64-apple-darwin
		RUST_TARGET = --target aarch64-apple-darwin
		GOARCH=darwin
	endif
endif

all: build test merge-wasm

test-filenames:
	echo $(SHARED_LIB_DST)
	echo $(SHARED_LIB_SRC)

build: build-rust build-go

build-rust: build-rust-release

# Use debug build for quick testing.
# In order to use "--features backtraces" here we need a Rust nightly toolchain, which we don't have by default
build-rust-debug:
	(cd libtfhe-wrapper && cargo build ${RUST_TARGET})
	cp libtfhe-wrapper/${TARGET_RUST_DIR}/debug/$(SHARED_LIB_SRC) internal/api/$(SHARED_LIB_DST)
	make update-bindings

# use release build to actually ship - smaller and much faster
#
# See https://github.com/CosmWasm/wasmvm/issues/222#issuecomment-880616953 for two approaches to
# enable stripping through cargo (if that is desired).
build-rust-release:
	(cd libtfhe-wrapper && cargo build --release ${RUST_TARGET})
	cp libtfhe-wrapper/${TARGET_RUST_DIR}/release/$(SHARED_LIB_SRC) internal/api/amd64/$(SHARED_LIB_DST)
	make update-bindings
	@ #this pulls out ELF symbols, 80% size reduction!

build-go:
	# go build ./...
	go build -o build/main ./cmd/

test:
	# Use package list mode to include all subdirectores. The -count=1 turns off caching.
	RUST_BACKTRACE=1 GOARCH=${GOARCH} go test -v -count=1 $(TEST_PARAMS) ./...

test-safety:
	# Use package list mode to include all subdirectores. The -count=1 turns off caching.
	GODEBUG=cgocheck=2 go test -race -v -count=1 ./...

# Creates a release build in a containerized build environment of the static library for Alpine Linux (.a)
release-build-alpine:
	rm -rf libtfhe-wrapper/target/release
	# build the muslc *.a file
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd)/libtfhe-wrapper:/code $(BUILDERS_PREFIX)-alpine:0.0.1
	cp libtfhe-wrapper/artifacts/libtfhe_wrapper_muslc.a internal/api
	cp libtfhe-wrapper/artifacts/libtfhe_wrapper_muslc.aarch64.a internal/api
	rustup target add aarch64-unknown-linux-musl
	make update-bindings

# Creates a release build in a containerized build environment of the shared library for glibc Linux (.so)
release-build-linux:
	rm -rf libtfhe_wrapper/target/release
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd)/libtfhe-wrapper:/code $(BUILDERS_PREFIX)-centos7
	cp libtfhe_wrapper/artifacts/libtfhe_wrapper.x86_64.so internal/api
	cp libtfhe_wrapper/artifacts/libtfhe_wrapper.aarch64.so internal/api
	make update-bindings

# Creates a release build in a containerized build environment of the shared library for macOS (.dylib)
release-build-macos:
	rm -rf libtfhe_wrapper/target/x86_64-apple-darwin/release
	rm -rf libtfhe_wrapper/target/aarch64-apple-darwin/release
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd)/libtfhe-wrapper:/code $(BUILDERS_PREFIX)-cross build_macos.sh
	cp libtfhe_wrapper/artifacts/libtfhe_wrapper.dylib internal/api
	make update-bindings

# Creates a release build in a containerized build environment of the static library for macOS (.a)
release-build-macos-static:
	rm -rf libtfhe_wrapper/target/x86_64-apple-darwin/release
	rm -rf libtfhe_wrapper/target/aarch64-apple-darwin/release
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd)/libtfhe-wrapper:/code $(BUILDERS_PREFIX)-cross build_macos_static.sh
	cp libtfhe_wrapper/artifacts/libtfhe_wrapperstatic_darwin.a internal/api/amd64/libtfhe_wrapperstatic_darwin.a
	make update-bindings

# Creates a release build in a containerized build environment of the shared library for Windows (.dll)
release-build-windows:
	rm -rf libtfhe_wrapper/target/release
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd)/libtfhe-wrapper:/code $(BUILDERS_PREFIX)-cross build_windows.sh
	cp libtfhe_wrapper/target/x86_64-pc-windows-gnu/release/tfhe_wrapper.dll internal/api/amd64
	make update-bindings

update-bindings:
# After we build libtfhe_wrapper, we have to copy the generated bindings for Go code to use.
# We cannot use symlinks as those are not reliably resolved by `go get` (https://github.com/CosmWasm/wasmvm/pull/235).
	cp libtfhe-wrapper/bindings.h internal/api/amd64

release-build:
	# Write like this because those must not run in parallel
	make release-build-alpine
	make release-build-linux
	make release-build-macos
	make release-build-windows

build-static-muslc:
# See "2. If you really need CGO, but not netcgo" in https://dubo-dubon-duponey.medium.com/a-beginners-guide-to-cross-compiling-static-cgo-pie-binaries-golang-1-16-792eea92d5aa
# See also https://github.com/rust-lang/rust/issues/78919 for why we need -Wl,-z,muldefs
	go build -ldflags "-linkmode=external -extldflags '-Wl,-z,muldefs -static'" -tags muslc \
	  -o ./main ./cmd/

test-alpine: release-build-alpine
# try running go tests using this lib with muslc
	# docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd):/mnt/testrun -w /mnt/testrun $(ALPINE_TESTER) go build -tags muslc ./...
# Use package list mode to include all subdirectores. The -count=1 turns off caching.
	# docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd):/mnt/testrun -w /mnt/testrun $(ALPINE_TESTER) go test -tags muslc -count=1 ./...

	@# Build a Go demo binary called ./demo that links the static library from the previous step.
	@# Whether the result is a statically linked or dynamically linked binary is decided by `go build`
	@# and it's a bit unclear how this is decided. We use `file` to see what we got.
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd):/mnt/testrun -w /mnt/testrun $(ALPINE_TESTER) make build-static-muslc
	docker run --rm -u $(USER_ID):$(USER_GROUP) -v $(shell pwd):/mnt/testrun -w /mnt/testrun $(ALPINE_TESTER) file ./main

	@# Run the demo binary on Alpine machines
	@# See https://de.wikipedia.org/wiki/Alpine_Linux#Versionen for supported versions
	docker run --rm --read-only -v $(shell pwd):/mnt/testrun -w /mnt/testrun alpine:3.15 ./main version

.PHONY: format
format:
	find . -name '*.go' -type f | xargs gofumpt -w -s
	find . -name '*.go' -type f | xargs misspell -w

.PHONY: clippy
clippy:
	cd libtfhe-wrapper && cargo clippy

.PHONY: wasm-go
wasm-go:
	GOOS=js GOARCH=wasm go build -o build/main.wasm ./wasm-cmd/

.PHONY: wasm-rust
wasm-rust:
	cd libtfhe-wrapper && rustup target add wasm32-unknown-unknown && cargo build --release --examples --target wasm32-unknown-unknown --no-default-features --features=wasm32
	mkdir -p build
	cp libtfhe-wrapper/target/wasm32-unknown-unknown/release/examples/wasm.wasm build/rust.wasm

.PHONY: wasm-all
wasm-all: wasm-go wasm-rust

.PHONY: start-web-server
start-web-server:
	cp builder/web-wasm-test.html build/test.html
	cp "${GO_ROOT}/misc/wasm/wasm_exec.js" build/
	cd build && goexec 'http.ListenAndServe(`localhost:8082`, http.FileServer(http.Dir(`.`)))'

.PHONY: merge-wasm
merge-wasm: wasm-all
	wasm-merge --enable-reference-types --enable-multimemory --enable-bulk-memory build/main.wasm main build/rust.wasm env -o build/merged.wasm

.PHONY: lior
lior:
	./lior.sh
