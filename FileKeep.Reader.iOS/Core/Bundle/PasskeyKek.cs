using System.Security.Cryptography;
using System.Text;

namespace FileKeep.Reader.iOS.Core.Bundle;

/// <summary>
/// Derives the bundle DEK-wrapping KEK from a passkey PRF output.
///
/// Contract — must match FileKeep.Core when it grows the passkey
/// bundle export, so a bundle wrapped on Windows opens on iOS and
/// vice versa:
///   KEK = HKDF-SHA256(ikm: 32-byte PRF output,
///                      salt: "FileKeep-Passkey-KEK-v1",
///                      info: "bundle-dek-wrap",
///                      length: 32)
/// The PRF output is deterministic per (credential, salt), so the
/// same passkey + the wrap's prf_salt_b64 reproduces this KEK on
/// any device holding the credential.
/// </summary>
public static class PasskeyKek
{
	public static byte[] Derive(byte[] prfOutput)
	{
		if (prfOutput is null || prfOutput.Length != 32)
			throw new ArgumentException(
				"PRF output must be 32 bytes.", nameof(prfOutput));
		return HKDF.DeriveKey(
			HashAlgorithmName.SHA256,
			prfOutput,
			32,
			Encoding.ASCII.GetBytes("FileKeep-Passkey-KEK-v1"),
			Encoding.ASCII.GetBytes("bundle-dek-wrap"));
	}
}
