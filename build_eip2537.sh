#!/bin/bash
git clone https://github.com/sean-sn/blst_eip2537
cd blst_eip2537
./build.sh
cd go
go mod init github.com/sean-sn/blst_eip2537/go
cd ../..
mkdir -p eip2537/test_vectors
cp -r blst_eip2537/test_vectors/* eip2537/test_vectors/

