using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FileKeep.Core;

namespace FileKeep.Reader.iOS.Core.Bundle;

/// <summary>
/// Rebuilds a bundle's bytes after files are added, updated, or removed.
/// The DEK and the key wraps are reused unchanged — only the file manifest
/// and the ciphertext segments are regenerated. Every file gets a fresh
/// nonce; the caller supplies plaintext and this class encrypts.
/// </summary>
public static class BundleWriter
{
	private static readonly byte[] Magic = Encoding.ASCII.GetBytes("FKBO");

	/// <summary>
	/// Builds fresh bundle bytes from the existing header (format + wraps),
	/// the session DEK, and the complete new file list.
	/// </summary>
	public static byte[] Rebuild(BundleHeader header, byte[] dek, IReadOnlyList<(string Path, byte[] Plaintext)> files)
	{
		ArgumentNullException.ThrowIfNull(header);
		ArgumentNullException.ThrowIfNull(dek);
		ArgumentNullException.ThrowIfNull(files);
		if (dek.Length != KeyDerivation.KeySizeBytes)
			throw new ArgumentException($"DEK must be {KeyDerivation.KeySizeBytes} bytes.", nameof(dek));

		// Encrypt each file with a fresh nonce.
		var segments = new List<byte[]>(files.Count);
		var entries = new List<BundleFileEntry>(files.Count);
		foreach (var (path, plaintext) in files)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("File path must not be empty.", nameof(files));
			ArgumentNullException.ThrowIfNull(plaintext);

			byte[] nonce = RandomNumberGenerator.GetBytes(ChunkCrypto.NonceSizeBytes);
			byte[] ciphertext = AesGcmEncrypt(dek, nonce, plaintext);
			segments.Add(ciphertext);
			entries.Add(new BundleFileEntry
			{
				Path = path,
				Size = plaintext.Length,
				ModifiedUtc = DateTimeOffset.UtcNow,
				NonceB64 = Convert.ToBase64String(nonce),
				Offset = 0, // patched below
				Length = ciphertext.Length,
			});
		}

		var newHeader = new BundleHeader
		{
			Format = BundleReader.ExpectedFormat,
			Wraps = header.Wraps,
			Totp = header.Totp,
			Files = entries,
		};

		// Offsets are absolute from bundle start and depend on the serialized
		// header length; iterate to a fixed point (converges in 1-2 passes).
		var offsets = new long[entries.Count];
		byte[] blob = Array.Empty<byte>();
		for (int pass = 0; pass < 5; pass++)
		{
			for (int i = 0; i < entries.Count; i++)
				entries[i].Offset = offsets[i];
			byte[] headerJson = JsonSerializer.SerializeToUtf8Bytes(newHeader);
			blob = new byte[8 + headerJson.Length + TotalLength(segments)];
			Encoding.ASCII.GetBytes("FKBO").CopyTo(blob, 0);
			BitConverter.GetBytes(headerJson.Length).CopyTo(blob, 4);
			headerJson.CopyTo(blob, 8);

			long pos = 8 + headerJson.Length;
			bool stable = true;
			for (int i = 0; i < segments.Count; i++)
			{
				if (offsets[i] != pos)
					stable = false;
				offsets[i] = pos;
				segments[i].CopyTo(blob, (int)pos);
				pos += segments[i].Length;
			}
			if (stable)
				break;
		}

		return blob;
	}

	private static long TotalLength(List<byte[]> segments)
	{
		long total = 0;
		foreach (var s in segments)
			total += s.Length;
		return total;
	}

	private static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext)
	{
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[ChunkCrypto.TagSizeBytes];
		using var gcm = new AesGcm(key, ChunkCrypto.TagSizeBytes);
		gcm.Encrypt(nonce, plaintext, ciphertext, tag);
		byte[] out_ = new byte[ciphertext.Length + tag.Length];
		ciphertext.CopyTo(out_, 0);
		tag.CopyTo(out_, ciphertext.Length);
		CryptographicOperations.ZeroMemory(ciphertext);
		return out_;
	}
}
