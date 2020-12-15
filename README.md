Linux Injector
==============

## Shared library injector for Linux written in Rust using the ptrace system call.

Prerequisites
=============
* [Nightly Rust with Cargo (For inline assembly)](https://rustup.rs/)

Build Instructions
==================

1. `git clone https://github.com/x64architecture/linux-injector-rs.git`
2. `cd linux-injector-rs/library_loader`
3. `cargo build`
4. `cd ..`
5. `cd linux-injector-rs/test_library`
6. `cargo build`
7. `cd ..`
8. `cd linux-injector-rs/test_program`
9. `cargo build`
