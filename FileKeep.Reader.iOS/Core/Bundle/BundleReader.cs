using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FileKeep.Core;

namespace FileKeep.Reader.iOS.Core.Bundle;

/// <summary>
/// Reads "FileKeep offline bundle v1" packages (DESIGN.md §3).
/// Reference implementation — to be upstreamed to FileKeep.Core when the
/// desktop exporter is built, so both platforms share one implementation.
/// The crypto primitives (PBKDF2, AES-GCM) come from FileKeep.Core; only
/// the bundle framing lives here for now.
/// </summary>
public sealed class BundleReader : IDisposable
{
	public const string ExpectedFormat = "FileKeep offline bundle v1";
	private static readonly byte[] Magic = Encoding.ASCII.GetBytes("FKBO");

	private readonly byte[] _bundleBytes;
	private readonly BundleHeader _header;
	private byte[]? _dek; // zeroed on Dispose
	private bool _disposed;

	private BundleReader(byte[] bundleBytes, BundleHeader header)
	{
		_bundleBytes = bundleBytes;
		_header = header;
	}

	public IReadOnlyList<BundleFileEntry> Files => _header.Files;
	public bool RequiresTotp => _header.Totp?.Required == true;
	public bool HasPassphraseWrap => _header.Wraps.Any(w => w.Type == "passphrase");
	public bool HasYubiKeyWrap => _header.Wraps.Any(w => w.Type == "yubikey-hmac-sha1");

	/// <summary>
	/// Opens a bundle with the export passphrase. Throws
	/// <see cref="InvalidDataException"/> for a malformed bundle and
	/// <see cref="CryptographicException"/> for a wrong passphrase.
	/// </summary>
	public static BundleReader OpenWithPassphrase(byte[] bundleBytes, string passphrase)
	{
		ArgumentNullException.ThrowIfNull(bundleBytes);
		ArgumentException.ThrowIfNullOrEmpty(passphrase);

		var (header, wrap, salt, iterations) = GetPassphraseWrap(bundleBytes);
		byte[] kek = KeyDerivation.DeriveKey(passphrase, salt, iterations);
		try
		{
			return FinishOpen(bundleBytes, header, wrap, kek);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(kek);
		}
	}

	/// <summary>
	/// Opens a bundle with the export passphrase as a <c>char[]</c> (the
	/// native secure prompt's buffer). Derives the identical key as the
	/// <c>string</c> overload (UTF-8). The passphrase buffer is zeroed
	/// before return.
	/// </summary>
	public static BundleReader OpenWithPassphrase(byte[] bundleBytes, char[] passphrase)
	{
		ArgumentNullException.ThrowIfNull(bundleBytes);
		ArgumentNullException.ThrowIfNull(passphrase);
		if (passphrase.Length == 0)
			throw new ArgumentException("Passphrase must not be empty.", nameof(passphrase));

		var (header, wrap, salt, iterations) = GetPassphraseWrap(bundleBytes);
		byte[] kek;
		try
		{
			kek = Rfc2898DeriveBytes.Pbkdf2(
				passphrase, salt, iterations, HashAlgorithmName.SHA512, KeyDerivation.KeySizeBytes);
		}
		finally
		{
			Array.Clear(passphrase);
		}
		try
		{
			return FinishOpen(bundleBytes, header, wrap, kek);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(kek);
		}
	}

	private static (BundleHeader Header, BundleWrap Wrap, byte[] Salt, int Iterations) GetPassphraseWrap(
		byte[] bundleBytes)
	{
		var parsed = ParseHeader(bundleBytes);
		var header = parsed.Header;
		BundleWrap wrap = header.Wraps.FirstOrDefault(w => w.Type == "passphrase")
			?? throw new InvalidDataException(
				"This bundle has no passphrase wrap — it may require a YubiKey.");

		byte[] salt = Convert.FromBase64String(wrap.SaltB64
			?? throw new InvalidDataException("Passphrase wrap is missing its salt."));
		int iterations = wrap.Iterations
			?? throw new InvalidDataException("Passphrase wrap is missing its iteration count.");
		return (header, wrap, salt, iterations);
	}

	private static BundleReader FinishOpen(
		byte[] bundleBytes, BundleHeader header, BundleWrap wrap, byte[] kek)
	{
		byte[] dek = UnwrapDek(wrap, kek);
		var reader = new BundleReader(bundleBytes, header);
		reader._dek = dek;
		return reader;
	}

	/// <summary>
	/// Opens a bundle directly from a DEK (Face ID unlock path — the DEK
	/// came out of the Keychain). The reader clones the DEK; the caller
	/// zeroes its own copy.
	/// </summary>
	public static BundleReader OpenWithDek(byte[] bundleBytes, byte[] dek)
	{
		ArgumentNullException.ThrowIfNull(bundleBytes);
		ArgumentNullException.ThrowIfNull(dek);
		if (dek.Length != KeyDerivation.KeySizeBytes)
			throw new ArgumentException($"DEK must be {KeyDerivation.KeySizeBytes} bytes.", nameof(dek));

		var parsed = ParseHeader(bundleBytes);
		var reader = new BundleReader(bundleBytes, parsed.Header);
		reader._dek = (byte[])dek.Clone();
		return reader;
	}

	/// <summary>
	/// Returns a copy of the session DEK (for Keychain enrollment after a
	/// passphrase unlock). The caller zeroes the copy when done.
	/// </summary>
	public byte[] GetDekCopy()
	{
		ThrowIfDisposed();
		if (_dek is null)
			throw new InvalidOperationException("Bundle is not unlocked.");
		return (byte[])_dek.Clone();
	}

	/// <summary>
	/// Opens a bundle with a YubiKey-derived KEK (slice 4: the 20-byte
	/// HMAC-SHA1 response is composed into the KEK per DESIGN.md §3.2).
	/// </summary>
	public static BundleReader OpenWithYubiKey(byte[] bundleBytes, byte[] yubiKeyKek)
	{
		ArgumentNullException.ThrowIfNull(bundleBytes);
		ArgumentNullException.ThrowIfNull(yubiKeyKek);

		BundleHeader header;
		{
			var parsed = ParseHeader(bundleBytes);
			header = parsed.Header;
		}
		BundleWrap wrap = header.Wraps.FirstOrDefault(w => w.Type == "yubikey-hmac-sha1")
			?? throw new InvalidDataException("This bundle has no YubiKey wrap.");
		byte[] dek = UnwrapDek(wrap, yubiKeyKek);
		var reader = new BundleReader(bundleBytes, header);
		reader._dek = dek;
		return reader;
	}

	/// <summary>
	/// Decrypts one file's bytes. Only the opened file is ever
	/// materialized; the bundle is never fully decrypted.
	/// </summary>
	public byte[] OpenFile(BundleFileEntry file)
	{
		ThrowIfDisposed();
		ArgumentNullException.ThrowIfNull(file);
		if (_dek is null)
			throw new InvalidOperationException("Bundle is not unlocked.");

		if (file.Offset < 0 || file.Length < ChunkCrypto.TagSizeBytes ||
			file.Offset + file.Length > _bundleBytes.Length)
			throw new InvalidDataException("File entry points outside the bundle.");

		byte[] nonce = Convert.FromBase64String(file.NonceB64);
		if (nonce.Length != ChunkCrypto.NonceSizeBytes)
			throw new InvalidDataException("File entry has a bad nonce.");

		byte[] segment = _bundleBytes.AsSpan((int)file.Offset, (int)file.Length).ToArray();
		try
		{
			return AesGcmDecrypt(_dek, nonce, segment);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(segment);
		}
	}

	/// <summary>Decrypts the TOTP secret (slice 5). Null when the bundle
	/// carries none.</summary>
	public byte[]? GetTotpSecret()
	{
		ThrowIfDisposed();
		if (_dek is null)
			throw new InvalidOperationException("Bundle is not unlocked.");
		if (_header.Totp is null)
			return null;
		byte[] nonce = Convert.FromBase64String(_header.Totp.NonceB64);
		byte[] data = Convert.FromBase64String(_header.Totp.SecretB64);
		return AesGcmDecrypt(_dek, nonce, data);
	}

	private static (BundleHeader Header, int HeaderEnd) ParseHeader(byte[] bundleBytes)
	{
		if (bundleBytes.Length < 8 || !bundleBytes.AsSpan(0, 4).SequenceEqual(Magic))
			throw new InvalidDataException("Not a FileKeep bundle (bad magic).");

		int headerLength = BitConverter.ToInt32(bundleBytes, 4);
		if (!BitConverter.IsLittleEndian)
			headerLength = System.Net.IPAddress.NetworkToHostOrder(headerLength);
		if (headerLength <= 0 || 8 + headerLength > bundleBytes.Length)
			throw new InvalidDataException("Bundle header length is invalid.");

		BundleHeader? header;
		try
		{
			header = JsonSerializer.Deserialize<BundleHeader>(
				bundleBytes.AsSpan(8, headerLength));
		}
		catch (JsonException ex)
		{
			throw new InvalidDataException("Bundle header is not valid JSON.", ex);
		}
		if (header is null)
			throw new InvalidDataException("Bundle header is empty.");
		if (!string.Equals(header.Format, ExpectedFormat, StringComparison.Ordinal))
			throw new InvalidDataException(
				$"Unsupported bundle format '{header.Format}' — refusing rather than garbling.");

		foreach (BundleWrap wrap in header.Wraps)
		{
			if (wrap.Type is not ("passphrase" or "yubikey-hmac-sha1"))
				throw new InvalidDataException(
					$"Unknown bundle wrap type '{wrap.Type}' — refusing fail-closed.");
		}
		if (header.Wraps.Count == 0)
			throw new InvalidDataException("Bundle has no key wraps.");

		foreach (BundleFileEntry file in header.Files)
		{
			if (string.IsNullOrWhiteSpace(file.Path))
				throw new InvalidDataException("Bundle has a file with no path.");
		}

		return (header, 8 + headerLength);
	}

	private static byte[] UnwrapDek(BundleWrap wrap, byte[] kek)
	{
		byte[] nonce = Convert.FromBase64String(wrap.NonceB64);
		if (nonce.Length != ChunkCrypto.NonceSizeBytes)
			throw new InvalidDataException("Wrap has a bad nonce.");
		byte[] data = Convert.FromBase64String(wrap.DataB64);
		byte[] dek = AesGcmDecrypt(kek, nonce, data);
		if (dek.Length != KeyDerivation.KeySizeBytes)
		{
			CryptographicOperations.ZeroMemory(dek);
			throw new InvalidDataException("Unwrapped key has the wrong size.");
		}
		return dek;
	}

	/// <summary>data = ciphertext || tag.</summary>
	private static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] data)
	{
		if (data.Length < ChunkCrypto.TagSizeBytes)
			throw new InvalidDataException("Ciphertext is too short.");
		byte[] plaintext = new byte[data.Length - ChunkCrypto.TagSizeBytes];
		try
		{
			using var gcm = new AesGcm(key, ChunkCrypto.TagSizeBytes);
			gcm.Decrypt(nonce,
				data.AsSpan(0, plaintext.Length),
				data.AsSpan(plaintext.Length, ChunkCrypto.TagSizeBytes),
				plaintext);
			return plaintext;
		}
		catch
		{
			CryptographicOperations.ZeroMemory(plaintext);
			throw;
		}
	}

	private void ThrowIfDisposed()
	{
		if (_disposed)
			throw new ObjectDisposedException(nameof(BundleReader));
	}

	public void Dispose()
	{
		if (_disposed)
			return;
		_disposed = true;
		if (_dek is not null)
		{
			CryptographicOperations.ZeroMemory(_dek);
			_dek = null;
		}
		// The bundle bytes may contain the header only; file plaintext
		// is never stored here (OpenFile returns it to the caller).
	}
}
