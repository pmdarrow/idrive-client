# IDrive client in Rust

An independent, MIT-licensed **IDrive Backup client written in Rust**, available as a command-line tool and an embeddable library. It authenticates directly, lists directories, creates folders, uploads new files, and restores files with checksum verification. It runs without the proprietary IDrive utility.

Use the async Rust API directly or integrate the C interface into applications written in Swift, Go, Python, or other languages. A Swift adapter and an XCFramework build script are included for native iOS and macOS apps. Go and Python can use the same C interface through `cgo` and `ctypes`/`cffi`; dedicated wrappers for those languages are not included.

The client supports **IDrive Backup legacy accounts without deduplication**. Deduplicated accounts, delta updates, upload resume, version selection, deletion, and synchronization scheduling are not implemented. Uploading over an existing incremental basis returns an unsupported-operation error; use a new remote filename.

## Build and use

Build with Rust 1.94. The included `.cargo/config.toml` enables the AES crate's ARM hardware backend, with runtime detection and a software fallback. Build from this project directory. When consuming this crate from another Rust workspace, carry over the `aes_armv8` target rustflag; dependency-local Cargo configuration does not propagate to the parent workspace.

```sh
cargo build --release --features ffi --lib
cargo test --release --all-features
```

Native apps pass credentials directly to the Rust client or C ABI. The Swift adapter dispatches file operations to a background queue; create the session on a background task because authentication blocks. The app owns the interface, lifecycle, and credential storage.

For development and manual transfers, build the CLI with `cargo build --release --bin idrive-rs`. It takes credential JSON on stdin: `{"username":"...","password":"...","private_key":null}`. Supply it from your application or password manager. Credentials are never command-line arguments and are retained only in memory.

Commands:

```text
idrive-rs discover
idrive-rs handshake
idrive-rs list /
idrive-rs mkdir /my-folder
idrive-rs upload /local/photo.jpg /my-folder/photo.jpg
idrive-rs download /my-folder/photo.jpg /local/restored.jpg
```

Downloads refuse to overwrite local files. They are verified in a temporary file, synced, and published atomically. Cancelled or failed file downloads remove their temporary output. Remote paths must be absolute; traversal and control characters are rejected. Native I/O has a 60-second I/O timeout, and login has a 30-second limit.

The optional 1Password helper reads one selected item once and caches it in its process. It does not save credentials. Interactive mode lets you issue several commands without repeating the item read:

```sh
python3 examples/with_1password.py --account ACCOUNT_ID --vault Personal --item ITEM_ID --interactive
```

## Benchmarking

Build the optional `idrive-bench` tool:

```sh
cargo build --release --features benchmark --bin idrive-bench
```

```text
idrive-bench FIXTURE REMOTE_DIRECTORY LOCAL_OUTPUT [REPEATS] [CONCURRENCIES_CSV] [JOBS]
```

Like the main CLI, it accepts credential JSON on stdin. To supply credentials
with 1Password:

```sh
python3 examples/with_1password.py --account ACCOUNT_ID --item ITEM_ID \
  --binary target/release/idrive-bench -- \
  /local/random.bin /unique-benchmark-folder /local/restores 3 1,2,4,8,16 16
```

The benchmark emits JSON Lines and checks every restored file with SHA-256.
Defaults are three repetitions, concurrency levels `1,2,4,8`, and eight files per
sample. Use a unique remote directory for generated fixtures; remote files remain
after the run. Successful local downloads are removed after each wave. Failed
waves are retried with fresh remote filenames, and failures are recorded in the
JSON Lines output.

## Formatting and linting

Install the toolchain components once with `rustup component add rustfmt clippy`.
Run these commands from the project directory:

```sh
cargo fmt --all                 # format Rust sources with rustfmt.toml
cargo fmt --all -- --check      # check formatting without editing files
cargo lint                     # Clippy: every target and feature; warnings fail
bash scripts/check.sh          # formatting plus Clippy, including the portable codec
```

`cargo lint` is defined in `.cargo/config.toml`. The check script also runs Clippy
with default features disabled to cover the codec without the native client.

## Rust applications

```rust,no_run
use idrive_core::{Client, Credentials};
use std::path::Path;

let client = Client::login(Credentials::new(username, password, None)).await?;
let entries = client.list("/").await?;
client.mkdir("/new-folder").await?;
client.upload(Path::new("photo.jpg"), "/new-folder/photo.jpg").await?;
client.download("/new-folder/photo.jpg", Path::new("restored.jpg")).await?;
```

`Client` clones share credentials and a bounded transfer semaphore. The default allows sixteen concurrent transfers; `Client::login_with_parallelism(credentials, n)` supports 1–32. Call several methods concurrently to fill those slots. `download_to` accepts an asynchronous writer for streaming integration; its caller must discard previously written bytes if final verification fails. Uploads sample the first block and enable fast zlib compression when it saves space; incompressible files use the raw encrypted path. Local file buffering is bounded at 1 MiB per direction, plus protocol buffers and restore metadata (four bytes per block, capped at one million blocks).

## macOS and iOS

Build the `ffi` feature and use [include/idrive.h](include/idrive.h) and [examples/IDrive.swift](examples/IDrive.swift). The C ABI owns a runtime and authenticated client; calls can run concurrently from background queues. Each returned JSON string must be freed once. Close the client after all calls finish.

On Apple Silicon macOS, build an XCFramework for macOS ARM64, iOS ARM64, and the iOS ARM64 simulator:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
bash scripts/build-xcframework.sh
```

The script writes `dist/IdriveCore.xcframework`. Pass an output path as its first argument to choose another destination; existing output directories are not overwritten. Add the XCFramework and `libiconv.tbd` to the Xcode app target.

## Go, Python, and other languages

Build with `cargo build --release --features ffi --lib` and use the C interface in
[include/idrive.h](include/idrive.h). On macOS, this produces
`target/release/libidrive_core.a` for static linking and
`target/release/libidrive_core.dylib` for dynamic loading.

| Language | Integration |
|---|---|
| Go | Use `cgo` to call the C functions and wrap the opaque client handle. |
| Python | Load the shared library with `ctypes` or `cffi` and declare the C function signatures. |
| Other languages | Use the language's C interoperability or foreign function interface. |

The interface accepts UTF-8 JSON for credentials and operations, and returns JSON
results. Calls block; schedule them appropriately for the host application.
Free each returned string with `idrive_string_free`, and close the client only
after all concurrent calls finish.

## Compatibility and limitations

[Protocol notes](docs/protocol.md) describe the wire format and compatibility references.

The service's legacy protocol uses AES-ECB and MD4 over raw TCP port 443, with no TLS server authentication. Default data encryption derives its key from the username. Compatibility with private-key accounts is unverified. The restore block-table cap limits files to approximately 30.5 GiB. Cancellation or network failure during an upload can leave remote partial state; upload recovery and resumable transfers are not implemented.

No proprietary client is needed at runtime or included in this source tree. This project is not affiliated with IDrive.
