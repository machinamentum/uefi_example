# Simple, Easy-Setup UEFI example

Originally based on the gist found at https://gist.github.com/machinamentum/62d9f438ac427c88c2dbe6dafaf1e80b

This time, with fancy build scripts written in plain C to quickly setup a working build and testing environment.

## First Time Setup - Mac Users

Run `./easy-mac-setup.sh` to fetch OVMF, gnu-efi, and LLVM toolchain.

## First Time Setup - Linux Users

Run `./easy-linux-setup.sh` to fetch OVMF, gnu-efi, and LLVM toolchain.

## Build

Run `./build.sh`

## Run (Qemu)

Install QEMU by means of choice, then run `./run.sh`. Expects qemu-system-x86_64 in system path.
