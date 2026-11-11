using System.Runtime.InteropServices;

namespace FileKeep.Reader.iOS.Core.Smb;

/// <summary>
/// Raw P/Invoke surface for the Rust smb-ffi static library
/// (FileKeep.Reader.iOS/Rust/smb-ffi, crate `smb2` pinned =0.43.0).
/// Source-generated marshalling ([LibraryImport], AOT/trim-clean);
/// no reflection anywhere on this boundary. Every call blocks the
/// calling thread inside Rust (one shared tokio runtime, block_on),
/// so the wrapper in SmbBrowser always calls from Task.Run.
/// </summary>
internal static partial class SmbNative
{
	/// <summary>
	/// Progress callback for downloads: received and total bytes.
	/// Return 0 to continue, non-zero to cancel the download.
	/// </summary>
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	internal delegate int SmbProgressCallback(ulong received, ulong total, nint userData);

	/// <summary>Connect + authenticate. Returns an opaque session handle, or NULL on failure.</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial nint fk_smb_connect(string server, string username, string password, string? domain);

	/// <summary>Share names as one malloc'd UTF-8 JSON array of strings. NULL on failure.</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial nint fk_smb_list_shares(nint handle);

	/// <summary>Connect to a share on an open session. Returns an FK_* code (0 = ok).</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial int fk_smb_connect_share(nint handle, string share);

	/// <summary>Directory entries as one malloc'd UTF-8 JSON array of {name, is_dir, size}. NULL on failure.</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial nint fk_smb_list_dir(nint handle, string path);

	/// <summary>
	/// Stream a file to <paramref name="dest"/> (a local temp path).
	/// The callback fires per chunk; returning non-zero cancels and the
	/// partial file is deleted. Returns an FK_* code (0 = ok).
	/// </summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial int fk_smb_download_file(
		nint handle, string path, string dest, SmbProgressCallback callback, nint userData);

	/// <summary>
	/// Upload <paramref name="len"/> bytes at <paramref name="data"/>
	/// to <paramref name="path"/> on the connected share, creating or
	/// overwriting it. Returns an FK_* code (0 = ok).
	/// </summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial int fk_smb_upload_file(nint handle, string path, nint data, ulong len);

	/// <summary>Reconnect a dropped session and re-connect its share. Returns an FK_* code (0 = ok).</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial int fk_smb_reconnect(nint handle);

	/// <summary>Free the session; drops the client and zeroes the FFI layer's password copy.</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial void fk_smb_disconnect(nint handle);

	/// <summary>Free a string returned by list_shares / list_dir.</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial void fk_smb_free_string(nint str);

	/// <summary>Last error message for the calling thread. Valid until the next FFI call on that thread; copy it immediately.</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial nint fk_smb_last_error();

	/// <summary>Last error's stable FK_* code for the calling thread (0 = ok).</summary>
	[LibraryImport("__Internal", StringMarshalling = StringMarshalling.Utf8)]
	internal static partial int fk_smb_last_error_code();
}
