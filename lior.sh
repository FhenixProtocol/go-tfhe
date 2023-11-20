#!/bin/bash

make wasm-rust

wasm-opt -Oz build/rust.wasm -o build/rust-optimized.wasm

mv build/rust-optimized.wasm build/rust.wasm

wasm2wat build/rust.wasm |
 awk -F '[ ()]' '/banana/{banana=1; print; print "  (start "$8")"} {if(banana==1){banana=0}else{print}}' > build/rust.wat

# make start-web-server