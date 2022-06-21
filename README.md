# Filecoin Proofs FFI

> C and CGO bindings for Filecoin's Rust libraries

## Building

To build and install libfilcrypto, its header file and pkg-config manifest, run:

```shell
make
```

To optionally authenticate with GitHub for assets download (to increase API limits)
set `GITHUB_TOKEN` to personal access token.

If no precompiled static library is available for your operating system, the
build tooling will attempt to compile a static library from local Rust sources.

### Forcing Local Build

To opt out of downloading precompiled assets, set `FFI_BUILD_FROM_SOURCE=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 make
```

To allow portable building of the `blst` dependency, set `FFI_USE_BLST_PORTABLE=1`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_BLST_PORTABLE=1 make
```

By default, a 'gpu' option is used in the proofs library.  This feature is also used in FFI unless explicitly disabled.  To disable building with the 'gpu' dependency, set `FFI_USE_GPU=0`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_BLST=1 FFI_USE_GPU=0 make
```

By default, a 'multicore-sdr' option is used in the proofs library.  This feature is also used in FFI unless explicitly disabled.  To disable building with the 'multicore-sdr' dependency, set `FFI_USE_MULTICORE_SDR=0`:

```shell
rm .install-filcrypto \
    ; make clean \
    ; FFI_BUILD_FROM_SOURCE=1 FFI_USE_MULTICORE_SDR=0 make
```

## Updating rust-fil-proofs (via rust-filecoin-proofs-api)

If rust-fil-proofs has changed from commit X to Y and you wish to get Y into
the filecoin-ffi project, you need to do a few things:

1. Update the rust-filecoin-proofs-api [Cargo.toml][1] file to point to Y
2. Run `cd rust && cargo update -p "filecoin-proofs-api"` from the root of the filecoin-ffi project
3. After the previous step alters your Cargo.lock file, commit and push

## go get

`go get` needs some additional steps in order to work as expected.

Get the source, add this repo as a submodule to your repo, build it and point to it:

```shell
$ go get github.com/nilfoundation/filecoin-ffi
$ git submodule add https://github.com/nilfoundation/filecoin-ffi.git extern/filecoin-ffi
$ make -C extern/filecoin-ffi
$ go mod edit -replace=github.com/nilfoundation/filecoin-ffi=./extern/filecoin-ffi
```

## Updating CGO Bindings

The CGO bindings are generated using [c-for-go](https://github.com/xlab/c-for-go)
and committed to Git. To generate bindings yourself, install the c-for-go
binary, ensure that it's on your path, and then run `make cgo-gen`. CI builds
will fail if generated CGO diverges from what's checked into Git.

## License

MIT or Apache 2.0
