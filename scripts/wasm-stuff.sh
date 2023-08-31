#!/usr/bin/env bash

cd /tmp && wget https://github.com/WebAssembly/binaryen/releases/download/version_114/binaryen-version_114-x86_64-linux.tar.gz

tar -xvf /tmp/binaryen-version_114-x86_64-linux.tar.gz -C /tmp/

sudo cp /tmp/binaryen-version_114/bin/wasm* /usr/bin/

go install github.com/shurcooL/goexec@latest
