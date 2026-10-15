# Legacy IDrive Backup protocol

This document describes the native protocol for IDrive Backup legacy accounts without deduplication. IDrive e2/S3 uses a separate API.

## Compatibility reference

The protocol reference is the `idevsutil` utility in the [official IDrive Linux package](https://www.idrivedownloads.com/downloads/linux/download-for-linux/linux-bin/idriveforlinux.bin). The `idevsutil_dedup` utility uses a separate protocol variant.

Reference release: 1.0.2.11, 19 September 2024.

| Binary | SHA-256 |
|---|---|
| Linux x86-64 standard utility | `1a826c857d99eb953e49e05f4617d1b33777a1e82f23404a373b5caf80ebc1d7` |
| Linux ARM64 standard utility | `49ca810dc192d011b9b9041927e02bb13b8c29cac985f1930a189c06335b8c5f` |

The golden vectors in [tests/vendor_vectors.rs](../tests/vendor_vectors.rs) use synthetic inputs and output from the official ARM64 utility to check wire compatibility.

## Discovery and authentication

HTTPS POST `https://evs.idrive.com/cgi-bin/get_idevs_server_ip.pl` with URL-encoded `username` and `password` returns nested XML login attributes. The client uses `cmdUtilServerDNS` to select the native endpoint. Its hostname must be a valid subdomain of `idrive.com`; redirects are disabled and response size is bounded.

The native endpoint uses raw TCP on port 443 without TLS. Control parameters and data use the legacy encryption described below, without server authentication or authenticated encryption. Default encryption derives the data key from the account username.

1. Send `eb6ab2a3` + encoded `@IDEVSD: 29[<username>:<machine>:-1` + newline.
2. Read `@IDEVSD: 29` + newline.
3. Send `eb6ab2a3` + encoded `ibackup` + newline.
4. Receive `@IDEVSD: AUTHREQD <challenge>`.
5. Write little-endian operation i32, encrypted login byte count i32, and login ciphertext.
6. Write email flag i32 on the first envelope. An email login can return a zero canonical-name length (retain the original name), or a length and canonical name followed by a second login envelope, without another email flag.
7. Read control lines through `@IDEVSD: OK`. `@IDEVSD KEY TYPE: DEFAULT` identifies default data-key behavior.

Normal login plaintext:

```
<user> <password_challenge_hash> <private_hash_or_empty> 4e6b7b2b-0218-4f7f-9c45-578aa67ecf72 stream <default_hash>
```

The empty private hash leaves two spaces. Challenge hashes are unpadded standard Base64 of MD4(`LE32(0) || first || second`). The password hash uses password/challenge. The default hash uses canonical username/username. Compatibility with private-key accounts is unverified.

## Cipher and framing

The greeting keyword and challenge are both `740428cc4e4f430`. Login/control traffic after the challenge uses the challenge as both keyword and challenge.

- Salt: first eight bytes of MD5(keyword).
- Key: OpenSSL EVP_BytesToKey-compatible MD5 with two iterations, 32 bytes.
- Recurrence: `D_i = MD5(MD5(D_(i-1) || challenge || salt))`, with an empty initial digest.
- Encryption: AES-256 ECB, zero-pad the final partial block, no added block for exact alignment.
- Encoded command: `<ciphertext_length>:0-<ciphertext>`, then Base64 without `=`. Replace `/` with `)`; `+` is unchanged.
- Each command argument is encoded separately and newline terminated. A final empty line ends arguments.
- One signed i32 startup status follows. Zero **and negative values** mean success; a positive value is an error-body length.
- File operations then read a checksum seed using the long-integer format.

All ordinary integers are little-endian. A long integer is one nonnegative i32 when it fits; otherwise i32(-1) followed by an i64.

Multiplexed input starts after the seed: a four-byte header has 24 bits of payload length and an 8-bit channel. Channel 7 carries data, 8 carries errors, and 9 carries informational messages. Input has size and I/O-time limits.

## Metadata

Auth-list operation 21 uses these arguments:

```
--server --sender --auth-list2 --xml-output -vnr --list-only
-B32768 --timeout=700 --inplace . ibackup/<path>
```

Send an empty filter list (i32 zero). Each file starts with rsync-style flag bits; bit 2 indicates an extended flag byte. A zero byte ends the list. Bit 0x20 includes a shared filename-prefix length. Filename suffixes are zlib-compressed and encrypted with the login key, preceded by encrypted and compressed lengths. Metadata includes file length, versions and thumbnail information for auth-list, directory status, conditional modification time and mode. Service listing names are enclosed in brackets; only that outer service wrapper is removed.

## Upload

Upload login operation: 9. The server arguments use `--server --xml-output -vtrR -B32768 --timeout=900 --inplace . ibackup/<parent>/`.

The client sends a file-list entry containing encrypted filename, size, source/version field, modification time and regular-file mode. End the file list with a zero byte and an i32 I/O status. Send i32(-1) to skip the vendor's optional calibration transfer, then consume its `eb6ab2a3` acknowledgement through the multiplexed stream.

The server requests an index, item flags, and basis checksums. This version supports new-file transfers; a nonempty incremental basis table is rejected. It does not implement delta updates or upload resume.

The data stream includes a version, encrypted canonical username, checksum seed, and literal encrypted blocks of at most 32 KiB. Data keys derive from the default username or supplied private key. Auto compression samples the first block; if compression saves at least 1/16 of its size, subsequent blocks use fast zlib compression. Otherwise blocks remain uncompressed before encryption.

For files larger than one block, each literal includes offsets, original/compressed/encrypted lengths, signed-byte rolling checksum, version, and seeded MD4 checksums of plaintext and ciphertext. Smaller files carry the compression/padding adjustment directly. Positive compression lengths select zlib; zero or negative values select raw padded data. End with a zero token and MD4 of the low 32-bit seed followed by all ciphertext. Consume the three phase markers and final generator completion.

## Restore

Restore login operation: 0. Arguments use `--sender --add-progress -vtrR --files-from=- --from0` with the ordinary server options. Send an empty filter list. File selection uses encrypted/compressed filename strings with NUL delimiters. **Send the final NUL terminator as its own compressed/encrypted packet**, matching the reference client's EOF framing.

Read the ordinary file list, request the selected regular-file index, send item flags 0xa000 and zero local basis status, and send three phase markers. The server returns the index/flags, checksum seed, block table, compression lengths, encrypted literal tokens, zero terminator and whole-file MD4. Validate block bounds, exact file size and final ciphertext checksum.

File downloads are written to a temporary file beside the destination, verified and synced, then published with no overwrite. Dropping or failing the operation removes its temporary file. `download_to` is a streaming API: the caller owns rollback of anything already written if final verification fails.

## Performance measurement

`idrive-bench` divides known file bytes by monotonic elapsed time and checks every restored file with SHA-256. Timing includes connection setup and completion; discovery, fixture generation, and post-transfer SHA-256 verification are excluded.

The reference utility's transfer-test functions scale the displayed rates: `calculate_transfer_uprate` adds 50%, and `calculate_transfer_downrate` multiplies by four. Those values are not directly comparable to bytes-per-second measurements.
