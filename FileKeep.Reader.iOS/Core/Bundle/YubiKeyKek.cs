using System.Security.Cryptography;
using System.Text;

namespace FileKeep.Reader.iOS.Core.Bundle;

/// <summary>
/// Derives the bundle DEK-wrapping KEK from a YubiKey HMAC-SHA1
/// challenge-response (DESIGN.md §3.2).
///
/// Contract — must match FileKeep.Core when it grows the v2 bundle
/// export, so a bundle wrapped on Windows opens on iOS and vice versa:
///   KEK = HKDF-SHA256(ikm: 20-byte response,
///                      salt: "FileKeep-YubiKey-KEK-v1",
///                      info: "bundle-dek-wrap",
///                      length: 32)
/// This reuses the desktop YubiKeyCrypto's salt and HKDF construction
/// with a bundle-specific info string, so the same key + challenge can
/// never produce a KEK that collides with the desktop's
/// passphrase-wrap KEKs.
/// </summary>
public static class YubiKeyKek
{
	public static byte[] Derive(byte[] hmacResponse)
	{
		if (hmacResponse is null || hmacResponse.Length != 20)
			throw new ArgumentException(
				"HMAC-SHA1 response must be 20 bytes.", nameof(hmacResponse));
		return HKDF.DeriveKey(
			HashAlgorithmName.SHA256,
			hmacResponse,
			32,
			Encoding.ASCII.GetBytes("FileKeep-YubiKey-KEK-v1"),
			Encoding.ASCII.GetBytes("bundle-dek-wrap"));
	}
}
