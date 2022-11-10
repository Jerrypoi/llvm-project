#!/usr/bin/env sh

cd build || exit


cp ../SFI_benchmark/*.cpp ./

clang -S -emit-llvm heap_access.cpp
./bin/opt -enable-new-pm=0 -load lib/LLVMSFI.dylib -sfi --enable-sfi-loadchecks --enable-sfi-svachecks heap_access.ll -S -o heap_access_new.ll

clang heap_access.ll -o heap_access
clang heap_access_new.ll -o heap_access_new

echo "Running pure heap access benchmark"
./heap_access

echo "Running SFI-guarded heap access benchmark"
./heap_access_new


clang -S -emit-llvm stack_access.cpp
./bin/opt -enable-new-pm=0 -load lib/LLVMSFI.dylib -sfi --enable-sfi-loadchecks --enable-sfi-svachecks stack_access.ll -S -o stack_access_new.ll

clang stack_access.ll -o stack_access
clang stack_access_new.ll -o stack_access_new

echo "Running pure stack access benchmark"
./stack_access

echo "Running SFI-guarded stack access benchmark"
./stack_access_new



