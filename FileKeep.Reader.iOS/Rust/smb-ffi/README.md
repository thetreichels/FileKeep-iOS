# smb-ffi

C ABI bridge for the `smb2` crate (pinned `=0.43.0`), so the FileKeep iOS
app can browse SMB shares from C# via P/Invoke (`[LibraryImport]`).

## Build

CI builds the static library per target (never committed):

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
```

Local check (host target, catches type/signature errors):

```sh
cargo check
```

## FFI surface (`fk_smb_*`, see src/lib.rs for the full contract)

| Function | Purpose |
|---|---|
| `fk_smb_connect(server, user, pass, domain)` | Connect + authenticate; returns an opaque handle (NULL on failure). |
| `fk_smb_list_shares(handle)` | JSON array of share names (malloc'd string). |
| `fk_smb_connect_share(handle, share)` | Connect to a share; returns an `FK_*` code. |
| `fk_smb_list_dir(handle, path)` | JSON array of `{"name","is_dir","size"}` (malloc'd string). |
| `fk_smb_download_file(handle, path, dest, progress_cb)` | Stream to a temp file; progress callback, cancel, reconnect+resume. |
| `fk_smb_reconnect(handle)` | Reconnect a dropped session + re-connect its share. |
| `fk_smb_disconnect(handle)` | Free the handle; drops the client and zeroes the password copy. |
| `fk_smb_free_string(ptr)` | Free a string from list_shares / list_dir. |
| `fk_smb_last_error()` / `fk_smb_last_error_code()` | Last error message / stable `FK_*` code. |

Error codes: 0 ok; 1 AuthRequired; 2 SigningRequired; 3 AccessDenied;
4 NotFound; 5 ConnectionLost; 6 TimedOut; 7 SessionExpired;
8 GuestSessionRefused (check credentials); 9 SignatureInvalid;
10 NegotiateValidationFailed; 11 InvalidName; 12 TooLarge; 13 Cancelled;
14 Io; 15 InvalidArgument; 99 Other.

## Notes

- One shared multi-thread tokio runtime (`LazyLock`); every FFI call is
  `block_on`. Downloads stream to disk with `FileDownload` + checkpoint
  resume — never `read_file` (it loads the whole file into RAM).
- Paths are forward slashes, share-root-relative; names are not
  pre-sanitized (the crate auto-maps illegal SMB2 characters).
- The `smb2` crate stores the password in memory for reconnect; the FFI
  layer's own copy is zeroed on disconnect.
