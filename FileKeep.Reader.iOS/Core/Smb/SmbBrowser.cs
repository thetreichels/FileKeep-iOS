using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Maui.Storage;

namespace FileKeep.Reader.iOS.Core.Smb;

/// <summary>
/// An SMB failure, carrying the FFI layer's stable FK_* code plus the
/// message. The message is read on the FFI thread immediately after
/// the failing call (the last-error storage is thread-local), so it
/// is always the error for this operation, never a stale one.
/// </summary>
public sealed class SmbException : Exception
{
	/// <summary>Stable FK_* code: 0 ok, 1 AuthRequired, 2 SigningRequired, 3 AccessDenied, 4 NotFound, 5 ConnectionLost, 6 TimedOut, 7 SessionExpired, 8 GuestSessionRefused, 9 SignatureInvalid, 10 NegotiateValidationFailed, 11 InvalidName, 12 TooLarge, 13 Cancelled, 14 Io, 15 InvalidArgument, 99 Other.</summary>
	public int Code { get; }

	public SmbException(int code, string message) : base(message)
	{
		Code = code;
	}
}

/// <summary>
/// One entry from list_dir: the Rust layer's JSON uses snake_case
/// field names, so each property is pinned with JsonPropertyName.
/// </summary>
public sealed class SmbDirEntry
{
	[JsonPropertyName("name")]
	public string Name { get; set; } = "";
	[JsonPropertyName("is_dir")]
	public bool IsDir { get; set; }
	[JsonPropertyName("size")]
	public ulong Size { get; set; }
}

/// <summary>A remembered server (Preferences only — never the password).</summary>
public sealed class SmbServerEntry
{
	public string Server { get; set; } = "";
	public string Username { get; set; } = "";
}

/// <summary>
/// An authenticated SMB session: one native handle, one server.
/// Every FFI call runs on a background thread (Task.Run) because the
/// Rust side blocks the calling thread in block_on. Dispose frees
/// the handle, which drops the client and zeroes the FFI layer's
/// password copy.
/// </summary>
public sealed class SmbSession : IDisposable
{
	private sealed class SmbHandle : SafeHandle
	{
		public SmbHandle() : base(IntPtr.Zero, ownsHandle: true)
		{
		}

		public override bool IsInvalid => handle == IntPtr.Zero;

		public void Set(nint ptr) => SetHandle(ptr);

		protected override bool ReleaseHandle()
		{
			SmbNative.fk_smb_disconnect(handle);
			return true;
		}
	}

	private readonly SmbHandle _handle;

	private SmbSession(SmbHandle handle)
	{
		_handle = handle;
	}

	public void Dispose() => _handle.Dispose();

	/// <summary>Connect + authenticate. The domain is optional (null = the crate default, an empty domain); home workgroup shares do not need it.</summary>
	public static Task<SmbSession> ConnectAsync(string server, string username, string password, string? domain = null)
	{
		return Task.Run(() =>
		{
			nint handle = SmbNative.fk_smb_connect(server, username, password, domain);
			if (handle == IntPtr.Zero)
				throw LastError();
			var safe = new SmbHandle();
			safe.Set(handle);
			return new SmbSession(safe);
		});
	}

	/// <summary>Disk share names on the server (srvsvc enumeration). Throws SmbException when the server refuses to enumerate — the caller falls back to a typed share name.</summary>
	public Task<IReadOnlyList<string>> ListSharesAsync()
	{
		return Task.Run(() =>
		{
			nint ptr = SmbNative.fk_smb_list_shares(_handle.DangerousGetHandle());
			if (ptr == IntPtr.Zero)
				throw LastError();
			try
			{
				string json = Marshal.PtrToStringUTF8(ptr) ?? "[]";
				return (IReadOnlyList<string>)(JsonSerializer.Deserialize(json, SmbJsonContext.Default.ListString) ?? new List<string>());
			}
			finally
			{
				SmbNative.fk_smb_free_string(ptr);
			}
		});
	}

	/// <summary>Connect to a share on this session (replaces any previously connected share).</summary>
	public Task ConnectShareAsync(string share)
	{
		return Task.Run(() =>
		{
			int code = SmbNative.fk_smb_connect_share(_handle.DangerousGetHandle(), share);
			ThrowIfFailed(code);
		});
	}

	/// <summary>
	/// Entries of a directory. <paramref name="path"/> is forward
	/// slashes, share-root-relative ("" = the share root). Names are
	/// NOT pre-sanitized — the crate auto-maps illegal SMB2 characters.
	/// </summary>
	public Task<IReadOnlyList<SmbDirEntry>> ListDirectoryAsync(string path)
	{
		return Task.Run(() =>
		{
			nint ptr = SmbNative.fk_smb_list_dir(_handle.DangerousGetHandle(), path);
			if (ptr == IntPtr.Zero)
				throw LastError();
			try
			{
				string json = Marshal.PtrToStringUTF8(ptr) ?? "[]";
				return (IReadOnlyList<SmbDirEntry>)(JsonSerializer.Deserialize(json, SmbJsonContext.Default.ListSmbDirEntry) ?? new List<SmbDirEntry>());
			}
			finally
			{
				SmbNative.fk_smb_free_string(ptr);
			}
		});
	}

	/// <summary>
	/// Stream a file to <paramref name="localPath"/> (a temp file).
	/// Progress reports (received, total) bytes; cancelling the token
	/// aborts the download and the partial file is deleted by the Rust
	/// side. A dropped connection is reconnected and resumed from the
	/// checkpoint automatically (up to 3 attempts).
	/// </summary>
	public Task DownloadFileAsync(string remotePath, string localPath, IProgress<(long Received, long Total)>? progress = null, CancellationToken ct = default)
	{
		return Task.Run(() =>
		{
			SmbNative.SmbProgressCallback callback = (received, total, _) =>
			{
				progress?.Report(((long)received, (long)total));
				return ct.IsCancellationRequested ? 1 : 0;
			};
			int code = SmbNative.fk_smb_download_file(_handle.DangerousGetHandle(), remotePath, localPath, callback, IntPtr.Zero);
			if (code == 13) // FK_CANCELLED
				throw new OperationCanceledException(ct);
			ThrowIfFailed(code);
		}, ct);
	}

	/// <summary>Reconnect a dropped session and re-connect its share. (The download path already does this internally; this is for a failed listing the caller wants to retry.)</summary>
	public Task ReconnectAsync()
	{
		return Task.Run(() =>
		{
			int code = SmbNative.fk_smb_reconnect(_handle.DangerousGetHandle());
			ThrowIfFailed(code);
		});
	}

	/// <summary>Read the thread-local last error. MUST be called on the FFI thread, immediately after the failing call.</summary>
	private static SmbException LastError()
	{
		int code = SmbNative.fk_smb_last_error_code();
		nint ptr = SmbNative.fk_smb_last_error();
		string message = ptr == IntPtr.Zero ? "SMB error" : (Marshal.PtrToStringUTF8(ptr) ?? "SMB error");
		if (code == 8) // GuestSessionRefused: on Samba with map-to-guest a wrong password presents as a guest refusal.
			message += " Check the username and password.";
		return new SmbException(code, message);
	}

	private static void ThrowIfFailed(int code)
	{
		if (code != 0)
			throw LastError();
	}
}

/// <summary>
/// The smb:// URL form used for vault rows and for reopening an SMB
/// bundle: smb://server/share/path/to/file.kfb (forward slashes,
/// share-root-relative path). The server may carry a port
/// (host:445); bare IPv6 literals are not supported in v1.
/// </summary>
public static class SmbUrl
{
	public static string Format(string server, string share, string path)
	{
		path = (path ?? "").Trim('/');
		return string.IsNullOrEmpty(path)
			? $"smb://{server}/{share}/"
			: $"smb://{server}/{share}/{path}";
	}

	public static bool TryParse(string url, out string server, out string share, out string path)
	{
		server = "";
		share = "";
		path = "";
		if (string.IsNullOrWhiteSpace(url))
			return false;
		if (!url.StartsWith("smb://", StringComparison.OrdinalIgnoreCase))
			return false;
		string rest = url.Substring("smb://".Length).Trim('/');
		string[] parts = rest.Split('/');
		if (parts.Length < 2 || string.IsNullOrEmpty(parts[0]) || string.IsNullOrEmpty(parts[1]))
			return false;
		server = parts[0];
		share = parts[1];
		path = parts.Length > 2 ? string.Join("/", parts, 2, parts.Length - 2) : "";
		return true;
	}
}

/// <summary>
/// Remembered servers (Preferences, server + username only) and
/// per-server passwords (Keychain via SecureStorage, never in
/// Preferences). Best-effort: a storage failure never breaks a
/// connect — the user just re-types the password next time.
/// </summary>
public static class SmbCredentials
{
	private const string ServersKey = "smb_servers_v1";
	private const int MaxServers = 10;

	public static List<SmbServerEntry> LoadServers()
	{
		try
		{
			string json = Preferences.Get(ServersKey, "");
			if (string.IsNullOrWhiteSpace(json))
				return new List<SmbServerEntry>();
			return JsonSerializer.Deserialize(json, SmbJsonContext.Default.ListSmbServerEntry) ?? new List<SmbServerEntry>();
		}
		catch
		{
			return new List<SmbServerEntry>();
		}
	}

	public static void RememberServer(string server, string username)
	{
		try
		{
			var list = LoadServers();
			list.RemoveAll(s => string.Equals(s.Server, server, StringComparison.OrdinalIgnoreCase));
			list.Insert(0, new SmbServerEntry { Server = server, Username = username });
			if (list.Count > MaxServers)
				list.RemoveRange(MaxServers, list.Count - MaxServers);
			Preferences.Set(ServersKey, JsonSerializer.Serialize(list, SmbJsonContext.Default.ListSmbServerEntry));
		}
		catch
		{
			// Best-effort; a storage failure must never break a connect.
		}
	}

	public static void ForgetServer(string server)
	{
		try
		{
			var list = LoadServers();
			list.RemoveAll(s => string.Equals(s.Server, server, StringComparison.OrdinalIgnoreCase));
			Preferences.Set(ServersKey, JsonSerializer.Serialize(list, SmbJsonContext.Default.ListSmbServerEntry));
		}
		catch
		{
		}
		_ = SecureStorage.Remove(PasswordKey(server));
	}

	public static async Task<string?> GetPasswordAsync(string server)
	{
		try
		{
			return await SecureStorage.GetAsync(PasswordKey(server));
		}
		catch
		{
			return null;
		}
	}

	public static async Task SavePasswordAsync(string server, string password)
	{
		try
		{
			await SecureStorage.SetAsync(PasswordKey(server), password);
		}
		catch
		{
			// Best-effort; the user re-types it next time.
		}
	}

	private static string PasswordKey(string server)
	{
		var sb = new StringBuilder("smb_password_");
		foreach (char c in server.ToLowerInvariant())
			sb.Append(char.IsLetterOrDigit(c) || c == '.' || c == '-' ? c : '_');
		return sb.ToString();
	}
}
