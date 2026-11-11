//! C ABI bridge for the `smb2` crate (pinned `=0.43.0`), so the FileKeep
//! iOS app can browse SMB shares from C# via P/Invoke (`[LibraryImport]`).
//!
//! Design notes:
//! - The crate is async (tokio). Every FFI call runs its operation on ONE
//!   shared multi-thread tokio runtime (`RUNTIME`, a `LazyLock`) via
//!   `block_on`, so the C# side sees plain blocking calls. Never create a
//!   runtime per call (100-1000x slower) and never `block_on` re-entrantly
//!   on the same thread. The runtime is created lazily on first use; its
//!   worker threads live for the process lifetime.
//! - A connected server is an opaque handle: `Box::into_raw(Session)`.
//!   The session holds the `SmbClient`, the currently connected `Tree`
//!   (share), the share name (for re-connect after a reconnect), and a
//!   password copy that is zeroed when the handle is freed. All calls on
//!   one handle serialize through the session's `Mutex`, which is held
//!   for the whole operation (including `block_on`).
//! - Strings crossing the boundary are UTF-8, NUL-terminated, allocated
//!   with `CString::into_raw`; the caller frees them with
//!   `fk_smb_free_string`. Directory listings and share lists cross as
//!   one malloc'd UTF-8 JSON string (serde_json): shares
//!   `["Share1","Share2"]`; entries
//!   `[{"name":"photos","is_dir":true,"size":0}, ...]`.
//! - Downloads NEVER load a file into RAM: they stream with
//!   `FileDownload` straight to a temp file the C# side names, with a
//!   `DownloadCheckpoint` and resume after reconnect. A GB-scale .kfb
//!   would otherwise get the app jetsam-killed. Progress is reported
//!   through a C# callback (return non-zero to cancel). On cancel or
//!   fatal failure the partial file is deleted.
//! - Every fallible function returns a stable int code (0 = ok, see the
//!   `FK_*` constants — mirrored in C#) and stores a human-readable
//!   message in thread-local storage, readable via `fk_smb_last_error`
//!   (and its code via `fk_smb_last_error_code`). `ErrorKind` has 27
//!   variants and is `#[non_exhaustive]`; unknown kinds map to `FK_OTHER`.
//!   Guest refusal means a wrong password on a map-to-guest server, so
//!   its message says to check the credentials. Errors surface loudly in
//!   the UI; nothing fails silently.
//! - No `extern "C"` function is allowed to unwind: each body runs inside
//!   `catch_unwind` and a panic becomes a plain error return.
//! - Paths are forward slashes, share-root-relative (e.g. `"projects/"`).
//!   Names are NOT pre-sanitized — the crate auto-maps SMB2-illegal
//!   characters through a private-use-area scheme; sanitizing first would
//!   double-map.
//! - Backgrounding: raw TCP sockets die when iOS suspends the app — no
//!   background downloads. On `ConnectionLost`/`SessionExpired` the
//!   download heals itself: `reconnect()`, re-connect the share, resume
//!   from the checkpoint (up to 3 reconnects). DNS is never retried in a
//!   tight loop; the connect deadline governs.

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

use smb2::{ClientConfig, DownloadCheckpoint, ErrorKind, FileDownload, SmbClient, Tree};

/// Stable error codes. Mirrored in C# (`SmbErrorCode`); do not renumber.
pub const FK_OK: c_int = 0;
pub const FK_AUTH_REQUIRED: c_int = 1;
pub const FK_SIGNING_REQUIRED: c_int = 2;
pub const FK_ACCESS_DENIED: c_int = 3;
pub const FK_NOT_FOUND: c_int = 4;
pub const FK_CONNECTION_LOST: c_int = 5;
pub const FK_TIMED_OUT: c_int = 6;
pub const FK_SESSION_EXPIRED: c_int = 7;
pub const FK_GUEST_REFUSED: c_int = 8;
pub const FK_SIGNATURE_INVALID: c_int = 9;
pub const FK_NEGOTIATE_FAILED: c_int = 10;
pub const FK_INVALID_NAME: c_int = 11;
pub const FK_TOO_LARGE: c_int = 12;
pub const FK_CANCELLED: c_int = 13;
pub const FK_IO: c_int = 14;
pub const FK_INVALID_ARGUMENT: c_int = 15;
pub const FK_OTHER: c_int = 99;

/// Timeout for connect + each operation (LAN; first connect can be slow).
const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Reconnect attempts inside one download before giving up.
const MAX_RECONNECTS: u32 = 3;
/// Uploads rewrite the whole file per attempt, so one retry (not
/// three) is the safe bound for a dropped connection.
const MAX_UPLOAD_RECONNECTS: u32 = 1;

/// Progress callback supplied by the C# side: invoked after each chunk
/// with (bytes_downloaded, total_bytes). Return non-zero to cancel the
/// download. Must be quick and must NOT call back into the FFI (the
/// session mutex is held while it runs).
pub type ProgressCallback = Option<unsafe extern "C" fn(downloaded: u64, total: u64) -> c_int>;

/// One shared tokio runtime for all FFI calls. Created lazily on first
/// use; C# never calls from inside a tokio context, so `block_on` is safe.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("smb-ffi: failed to create tokio runtime")
    })
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    runtime().block_on(future)
}

// Thread-local last error: a stable code plus a message. Valid until the
// next FFI call on the same thread; the C# side copies both immediately
// after a failure.
thread_local! {
    static LAST_ERROR_CODE: Cell<c_int> = Cell::new(FK_OK);
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_error(code: c_int, msg: &str) {
    LAST_ERROR_CODE.with(|c| c.set(code));
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() =
            CString::new(msg).unwrap_or_else(|_| CString::new("error (unprintable)").unwrap());
    });
}

fn clear_error() {
    set_error(FK_OK, "");
}

/// Map a crate error to a stable code + message. `GuestSessionRefused`
/// means a wrong password on a map-to-guest server, so say so plainly.
fn map_smb_error(e: &smb2::Error) -> (c_int, String) {
    let kind = e.kind();
    let code = match kind {
        ErrorKind::AuthRequired => FK_AUTH_REQUIRED,
        ErrorKind::SigningRequired => FK_SIGNING_REQUIRED,
        ErrorKind::AccessDenied => FK_ACCESS_DENIED,
        ErrorKind::NotFound => FK_NOT_FOUND,
        ErrorKind::ConnectionLost => FK_CONNECTION_LOST,
        ErrorKind::TimedOut => FK_TIMED_OUT,
        ErrorKind::SessionExpired => FK_SESSION_EXPIRED,
        ErrorKind::GuestSessionRefused => FK_GUEST_REFUSED,
        ErrorKind::SignatureInvalid => FK_SIGNATURE_INVALID,
        ErrorKind::NegotiateValidationFailed => FK_NEGOTIATE_FAILED,
        ErrorKind::InvalidName => FK_INVALID_NAME,
        ErrorKind::TooLarge => FK_TOO_LARGE,
        ErrorKind::Cancelled => FK_CANCELLED,
        ErrorKind::Io => FK_IO,
        _ => FK_OTHER,
    };
    let mut msg = e.to_string();
    if kind == ErrorKind::GuestSessionRefused {
        msg.push_str(" — check the username and password");
    }
    (code, msg)
}

fn set_error_from_smb(e: &smb2::Error) -> (c_int, String) {
    let (code, msg) = map_smb_error(e);
    set_error(code, &msg);
    (code, msg)
}

/// A password copy owned by the FFI layer, zeroed when the session is
/// freed. The crate keeps its own copy inside `SmbClient` for reconnect;
/// that copy is freed (not zeroed) when the client is dropped. This buffer
/// is the part the FFI layer can zero.
struct ZeroedBytes(Vec<u8>);

impl Drop for ZeroedBytes {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

struct SessionState {
    client: SmbClient,
    tree: Option<Tree>,
    share_name: Option<String>,
    /// Never read — its only purpose is the zero-on-drop side effect.
    #[allow(dead_code)]
    password: ZeroedBytes,
}

/// Opaque handle: `Box::into_raw(Session)`. The mutex serializes all
/// calls on one handle and is held for the whole operation.
pub struct Session {
    state: Mutex<SessionState>,
}

/// Resolve a handle to its session. NULL becomes an invalid-argument error.
unsafe fn session(handle: *mut Session) -> Result<&'static Session, (c_int, String)> {
    if handle.is_null() {
        return Err((FK_INVALID_ARGUMENT, "null SMB session handle".to_string()));
    }
    Ok(unsafe { &*handle })
}

/// Read a NUL-terminated UTF-8 C string. NULL becomes an error; invalid
/// UTF-8 is lossy-converted rather than failing the call.
unsafe fn c_str_to_string(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null string argument".to_string());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    Ok(cstr.to_string_lossy().into_owned())
}

/// Run `f`, converting a panic into an error return instead of unwinding
/// across the FFI boundary.
fn guarded<T, F>(on_panic: T, f: F) -> T
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => {
            set_error(FK_OTHER, "smb-ffi: internal error (panic)");
            on_panic
        }
    }
}

/// Connect to an SMB server and authenticate.
///
/// `server` is a hostname or IP, with an optional `:port` (default 445).
/// `domain` may be empty (local account). Returns an opaque session
/// handle (NULL on failure — read `fk_smb_last_error` for the reason).
/// Free it with `fk_smb_disconnect`, which also drops the stored
/// password.
#[no_mangle]
pub extern "C" fn fk_smb_connect(
    server: *const c_char,
    username: *const c_char,
    password: *const c_char,
    domain: *const c_char,
) -> *mut Session {
    guarded(std::ptr::null_mut(), || {
        clear_error();
        let server = match unsafe { c_str_to_string(server) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return std::ptr::null_mut();
            }
        };
        let username = match unsafe { c_str_to_string(username) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return std::ptr::null_mut();
            }
        };
        let password = match unsafe { c_str_to_string(password) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return std::ptr::null_mut();
            }
        };
        let domain = match unsafe { c_str_to_string(domain) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return std::ptr::null_mut();
            }
        };
        let addr = if server.contains(':') {
            server
        } else {
            format!("{server}:445")
        };
        let config = ClientConfig {
            addr,
            timeout: std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
            username,
            password: password.clone(),
            domain,
            auto_reconnect: false,
            ..Default::default()
        };
        match block_on(SmbClient::connect(config)) {
            Ok(client) => {
                let session = Session {
                    state: Mutex::new(SessionState {
                        client,
                        tree: None,
                        share_name: None,
                        password: ZeroedBytes(password.into_bytes()),
                    }),
                };
                Box::into_raw(Box::new(session))
            }
            Err(e) => {
                set_error_from_smb(&e);
                std::ptr::null_mut()
            }
        }
    })
}

/// List the disk shares on the connected server (admin shares ending in
/// `$` are excluded by the crate). Returns a JSON array of share names
/// as a malloc'd UTF-8 string (free with `fk_smb_free_string`), or NULL
/// on failure.
#[no_mangle]
pub extern "C" fn fk_smb_list_shares(handle: *mut Session) -> *mut c_char {
    guarded(std::ptr::null_mut(), || {
        clear_error();
        let session = match unsafe { session(handle) } {
            Ok(s) => s,
            Err((code, msg)) => {
                set_error(code, &msg);
                return std::ptr::null_mut();
            }
        };
        let mut state = match session.state.lock() {
            Ok(g) => g,
            Err(_) => {
                set_error(FK_OTHER, "session mutex poisoned");
                return std::ptr::null_mut();
            }
        };
        match block_on(state.client.list_shares()) {
            Ok(shares) => {
                let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
                match serde_json::to_string(&names) {
                    Ok(json) => CString::new(json)
                        .map(|s| s.into_raw())
                        .unwrap_or_else(|_| {
                            set_error(FK_IO, "share list is not valid UTF-8");
                            std::ptr::null_mut()
                        }),
                    Err(e) => {
                        set_error(FK_IO, &e.to_string());
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                set_error_from_smb(&e);
                std::ptr::null_mut()
            }
        }
    })
}

/// Connect to a share on the server. Replaces any previously connected
/// share (it is disconnected first). Returns `FK_OK` on success, another
/// `FK_*` code on failure.
#[no_mangle]
pub extern "C" fn fk_smb_connect_share(handle: *mut Session, share: *const c_char) -> c_int {
    guarded(FK_OTHER, || {
        clear_error();
        let share = match unsafe { c_str_to_string(share) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return FK_INVALID_ARGUMENT;
            }
        };
        let session = match unsafe { session(handle) } {
            Ok(s) => s,
            Err((code, msg)) => {
                set_error(code, &msg);
                return code;
            }
        };
        let mut state = match session.state.lock() {
            Ok(g) => g,
            Err(_) => {
                set_error(FK_OTHER, "session mutex poisoned");
                return FK_OTHER;
            }
        };
        // Disconnect any previous share first; a failure here is not
        // fatal — the old tree is dropped either way.
        if let Some(old) = state.tree.take() {
            let _ = block_on(state.client.disconnect_share(&old));
        }
        match block_on(state.client.connect_share(&share)) {
            Ok(tree) => {
                state.tree = Some(tree);
                state.share_name = Some(share);
                FK_OK
            }
            Err(e) => {
                let (code, _) = set_error_from_smb(&e);
                code
            }
        }
    })
}

/// List a directory on the connected share. `path` is relative to the
/// share root ("" for the root, "folder/sub" for a subfolder). Returns a
/// JSON array of `{"name","is_dir","size"}` objects as a malloc'd UTF-8
/// string (free with `fk_smb_free_string`), or NULL on failure.
#[no_mangle]
pub extern "C" fn fk_smb_list_dir(handle: *mut Session, path: *const c_char) -> *mut c_char {
    guarded(std::ptr::null_mut(), || {
        clear_error();
        let path = match unsafe { c_str_to_string(path) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return std::ptr::null_mut();
            }
        };
        let session = match unsafe { session(handle) } {
            Ok(s) => s,
            Err((code, msg)) => {
                set_error(code, &msg);
                return std::ptr::null_mut();
            }
        };
        let mut state = match session.state.lock() {
            Ok(g) => g,
            Err(_) => {
                set_error(FK_OTHER, "session mutex poisoned");
                return std::ptr::null_mut();
            }
        };
        // Reborrow as a plain &mut so the client's and the tree's borrows
        // split (they would conflict through the MutexGuard's DerefMut).
        let state: &mut SessionState = &mut *state;
        let Some(tree) = state.tree.as_mut() else {
            set_error(
                FK_INVALID_ARGUMENT,
                "no share connected — call fk_smb_connect_share first",
            );
            return std::ptr::null_mut();
        };
        match block_on(state.client.list_directory(tree, &path)) {
            Ok(entries) => {
                let items: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "name": e.name,
                            "is_dir": e.is_directory,
                            "size": e.size,
                        })
                    })
                    .collect();
                match serde_json::to_string(&items) {
                    Ok(json) => CString::new(json)
                        .map(|s| s.into_raw())
                        .unwrap_or_else(|_| {
                            set_error(FK_IO, "directory listing is not valid UTF-8");
                            std::ptr::null_mut()
                        }),
                    Err(e) => {
                        set_error(FK_IO, &e.to_string());
                        std::ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                set_error_from_smb(&e);
                std::ptr::null_mut()
            }
        }
    })
}

/// One segment of a streaming download: open (fresh, or resume from a
/// checkpoint) and drain chunks into `file` until done, interrupted by a
/// dropped connection, or failed.
enum DrainOutcome {
    Done(u64),
    Interrupted(Option<DownloadCheckpoint>, u64),
}

async fn drain_download(
    dl: &mut FileDownload<'_>,
    file: &mut tokio::fs::File,
    mut written: u64,
    progress: ProgressCallback,
) -> Result<DrainOutcome, (c_int, String)> {
    use tokio::io::AsyncWriteExt;
    loop {
        match dl.next_chunk().await {
            Some(Ok(chunk)) => {
                file.write_all(&chunk)
                    .await
                    .map_err(|e| (FK_IO, format!("failed writing temp file: {e}")))?;
                written += chunk.len() as u64;
                if let Some(cb) = progress {
                    // SAFETY: cb is a valid function pointer supplied by C#
                    // (or None). It must not call back into the FFI.
                    let cancel = unsafe { cb(written, dl.size()) };
                    if cancel != 0 {
                        return Err((FK_CANCELLED, "download cancelled".to_string()));
                    }
                }
            }
            Some(Err(e)) => {
                let kind = e.kind();
                if kind == ErrorKind::ConnectionLost || kind == ErrorKind::SessionExpired {
                    return Ok(DrainOutcome::Interrupted(dl.checkpoint(), written));
                }
                return Err(map_smb_error(&e));
            }
            None => return Ok(DrainOutcome::Done(written)),
        }
    }
}

async fn download_segment(
    state: &mut SessionState,
    path: &str,
    checkpoint: Option<&DownloadCheckpoint>,
    file: &mut tokio::fs::File,
    written: u64,
    progress: ProgressCallback,
) -> Result<DrainOutcome, (c_int, String)> {
    // Split the client's and the tree's borrows up front (they would
    // conflict through a single &mut SessionState in one expression).
    let SessionState { client, tree, .. } = state;
    match checkpoint {
        Some(cp) => {
            let tree = tree
                .as_mut()
                .ok_or((FK_INVALID_ARGUMENT, "no share connected".to_string()))?;
            let mut dl = client
                .resume_download(tree, cp)
                .await
                .map_err(|e| map_smb_error(&e))?;
            drain_download(&mut dl, file, written, progress).await
        }
        None => {
            let tree = tree
                .as_ref()
                .ok_or((FK_INVALID_ARGUMENT, "no share connected".to_string()))?;
            let mut dl = client
                .download(tree, path)
                .await
                .map_err(|e| map_smb_error(&e))?;
            drain_download(&mut dl, file, written, progress).await
        }
    }
}

/// Heal a dropped session: reconnect the client, then re-connect the
/// share it had. The tree from the dead session is invalid and replaced.
async fn heal_session(state: &mut SessionState) -> Result<(), (c_int, String)> {
    state
        .client
        .reconnect()
        .await
        .map_err(|e| map_smb_error(&e))?;
    let share = state
        .share_name
        .clone()
        .ok_or((FK_INVALID_ARGUMENT, "no share connected".to_string()))?;
    let tree = state
        .client
        .connect_share(&share)
        .await
        .map_err(|e| map_smb_error(&e))?;
    state.tree = Some(tree);
    Ok(())
}

/// Stream a whole file from the connected share straight to `dest_path`
/// (a temp file the C# side names), with progress, cancel, and
/// reconnect+resume from a checkpoint. Returns `FK_OK` on success;
/// another `FK_*` code on failure. On cancel or fatal failure the partial
/// file is deleted, so no corrupt temp file lingers.
#[no_mangle]
pub extern "C" fn fk_smb_download_file(
    handle: *mut Session,
    path: *const c_char,
    dest_path: *const c_char,
    progress: ProgressCallback,
) -> c_int {
    guarded(FK_OTHER, || {
        clear_error();
        let path = match unsafe { c_str_to_string(path) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return FK_INVALID_ARGUMENT;
            }
        };
        let dest_path = match unsafe { c_str_to_string(dest_path) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return FK_INVALID_ARGUMENT;
            }
        };
        let session = match unsafe { session(handle) } {
            Ok(s) => s,
            Err((code, msg)) => {
                set_error(code, &msg);
                return code;
            }
        };
        let mut state = match session.state.lock() {
            Ok(g) => g,
            Err(_) => {
                set_error(FK_OTHER, "session mutex poisoned");
                return FK_OTHER;
            }
        };
        let code = block_on(download_to_file(&mut state, &path, &dest_path, progress));
        match code {
            Ok(_) => FK_OK,
            Err((code, msg)) => {
                set_error(code, &msg);
                let _ = std::fs::remove_file(&dest_path);
                code
            }
        }
    })
}

async fn download_to_file(
    state: &mut SessionState,
    path: &str,
    dest: &str,
    progress: ProgressCallback,
) -> Result<u64, (c_int, String)> {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| (FK_IO, format!("cannot create temp file: {e}")))?;
    let mut written: u64 = 0;
    let mut checkpoint: Option<DownloadCheckpoint> = None;
    let mut reconnects: u32 = 0;
    loop {
        match download_segment(state, path, checkpoint.as_ref(), &mut file, written, progress).await
        {
            Ok(DrainOutcome::Done(total)) => {
                file.flush()
                    .await
                    .map_err(|e| (FK_IO, format!("failed flushing temp file: {e}")))?;
                return Ok(total);
            }
            Ok(DrainOutcome::Interrupted(cp, w)) => {
                written = w;
                reconnects += 1;
                if reconnects > MAX_RECONNECTS {
                    return Err((
                        FK_CONNECTION_LOST,
                        "connection lost (reconnects exhausted)".to_string(),
                    ));
                }
                if cp.is_none() && written == 0 {
                    // Nothing delivered yet — restart from scratch.
                    checkpoint = None;
                    file = tokio::fs::File::create(dest)
                        .await
                        .map_err(|e| (FK_IO, format!("cannot recreate temp file: {e}")))?;
                    written = 0;
                } else {
                    checkpoint = cp;
                    // The file already holds `written` bytes; make sure
                    // the write position matches the resume offset.
                    file.seek(std::io::SeekFrom::Start(written))
                        .await
                        .map_err(|e| (FK_IO, format!("failed seeking temp file: {e}")))?;
                }
                heal_session(state).await?;
            }
            Err((code, msg)) => {
                // The open itself failed on a dropped connection before any
                // chunk arrived: heal and retry from scratch.
                if (code == FK_CONNECTION_LOST || code == FK_SESSION_EXPIRED)
                    && written == 0
                    && reconnects < MAX_RECONNECTS
                {
                    reconnects += 1;
                    file = tokio::fs::File::create(dest)
                        .await
                        .map_err(|e| (FK_IO, format!("cannot recreate temp file: {e}")))?;
                    written = 0;
                    checkpoint = None;
                    heal_session(state).await?;
                    continue;
                }
                return Err((code, msg));
            }
        }
    }
}

/// Upload `len` bytes at `data` to `path` on the connected share,
/// creating or overwriting it. Returns `FK_OK` on success; another
/// `FK_*` code on failure. A dropped connection is healed and the
/// upload retried once from the start.
#[no_mangle]
pub extern "C" fn fk_smb_upload_file(
    handle: *mut Session,
    path: *const c_char,
    data: *const u8,
    len: usize,
) -> c_int {
    guarded(FK_OTHER, || {
        clear_error();
        if data.is_null() && len > 0 {
            set_error(FK_INVALID_ARGUMENT, "null data argument");
            return FK_INVALID_ARGUMENT;
        }
        let path = match unsafe { c_str_to_string(path) } {
            Ok(s) => s,
            Err(e) => {
                set_error(FK_INVALID_ARGUMENT, &e);
                return FK_INVALID_ARGUMENT;
            }
        };
        let session = match unsafe { session(handle) } {
            Ok(s) => s,
            Err((code, msg)) => {
                set_error(code, &msg);
                return code;
            }
        };
        // A zero-length upload never touches `data` (from_raw_parts
        // with a NULL pointer would be UB even for len 0).
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }
        };
        let mut state = match session.state.lock() {
            Ok(g) => g,
            Err(_) => {
                set_error(FK_OTHER, "session mutex poisoned");
                return FK_OTHER;
            }
        };
        match block_on(upload_to_file(&mut state, &path, bytes)) {
            Ok(_) => FK_OK,
            Err((code, msg)) => {
                set_error(code, &msg);
                code
            }
        }
    })
}

/// Upload `data` to `path` on the connected share (smb2 `write_file`:
/// create or overwrite). A dropped connection is healed and the whole
/// file rewritten once; anything else fails with its mapped FK_* code.
async fn upload_to_file(
    state: &mut SessionState,
    path: &str,
    data: &[u8],
) -> Result<u64, (c_int, String)> {
    let mut reconnects: u32 = 0;
    loop {
        // Disjoint field borrows: `tree` from state.tree, the client
        // call from state.client — no destructure needed.
        let tree = match state.tree.as_ref() {
            Some(t) => t,
            None => return Err((FK_INVALID_ARGUMENT, "no share connected".to_string())),
        };
        match state.client.write_file(tree, path, data).await {
            Ok(written) => return Ok(written),
            Err(e) => {
                let (code, msg) = map_smb_error(&e);
                if (code == FK_CONNECTION_LOST || code == FK_SESSION_EXPIRED)
                    && reconnects < MAX_UPLOAD_RECONNECTS
                {
                    reconnects += 1;
                    heal_session(state).await?;
                    continue;
                }
                return Err((code, msg));
            }
        }
    }
}

/// Reconnect a dropped session in place and re-connect its share.
/// Returns `FK_OK` on success, another `FK_*` code on failure. Use after
/// `ConnectionLost`/`SessionExpired` on a listing; downloads heal
/// themselves.
#[no_mangle]
pub extern "C" fn fk_smb_reconnect(handle: *mut Session) -> c_int {
    guarded(FK_OTHER, || {
        clear_error();
        let session = match unsafe { session(handle) } {
            Ok(s) => s,
            Err((code, msg)) => {
                set_error(code, &msg);
                return code;
            }
        };
        let mut state = match session.state.lock() {
            Ok(g) => g,
            Err(_) => {
                set_error(FK_OTHER, "session mutex poisoned");
                return FK_OTHER;
            }
        };
        match block_on(heal_session(&mut state)) {
            Ok(()) => FK_OK,
            Err((code, msg)) => {
                set_error(code, &msg);
                code
            }
        }
    })
}

/// Disconnect a session and free its handle. Drops the client (and the
/// password it stores for reconnect) and zeroes the FFI layer's password
/// copy. Returns `FK_OK` on success, `FK_INVALID_ARGUMENT` for a NULL or
/// unknown handle.
#[no_mangle]
pub extern "C" fn fk_smb_disconnect(handle: *mut Session) -> c_int {
    guarded(FK_OTHER, || {
        clear_error();
        if handle.is_null() {
            set_error(FK_INVALID_ARGUMENT, "null SMB session handle");
            return FK_INVALID_ARGUMENT;
        }
        unsafe {
            let _ = Box::from_raw(handle);
        }
        FK_OK
    })
}

/// Free a string returned by `fk_smb_list_shares` / `fk_smb_list_dir`.
/// NULL is a no-op.
#[no_mangle]
pub extern "C" fn fk_smb_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// The last error message on this thread, as a NUL-terminated UTF-8
/// string. Never NULL (empty when no error). Valid until the next FFI
/// call on the same thread — copy it immediately.
#[no_mangle]
pub extern "C" fn fk_smb_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| cell.borrow().as_ptr())
}

/// The stable code (`FK_*`) for the last error on this thread.
#[no_mangle]
pub extern "C" fn fk_smb_last_error_code() -> c_int {
    LAST_ERROR_CODE.with(|c| c.get())
}
