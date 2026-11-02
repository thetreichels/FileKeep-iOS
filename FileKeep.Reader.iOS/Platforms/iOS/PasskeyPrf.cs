using System.Security.Cryptography;
using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Passkey unlock via the WebAuthn PRF extension.
/// STUB: The iOS 18 PRF APIs (ASAuthorizationPublicKeyCredentialPrf*Input)
/// are not yet in the .NET iOS bindings. This compiles but reports
/// unavailable until the bindings catch up or we P/Invoke directly.
/// The bundle format already reserves the "passkey-prf" wrap type.
/// </summary>
public static class PasskeyPrf
{
	public sealed class Result
	{
		public byte[]? Kek { get; init; }
		public string? Error { get; init; }
		public byte[]? PrfSalt { get; init; }
	}

	/// <summary>False until the PRF bindings are available.</summary>
	public static bool IsAvailable() => false;

	public static Task<Result> RegisterAsync()
	{
		return Task.FromResult(new Result { Error = "Passkey PRF not yet available in this build." });
	}

	public static Task<Result> AuthenticateAsync(byte[] prfSalt)
	{
		ArgumentNullException.ThrowIfNull(prfSalt);
		return Task.FromResult(new Result { Error = "Passkey PRF not yet available in this build." });
	}

	/// <summary>Derives the 32-byte KEK from the 32-byte PRF output (for when bindings land).</summary>
	public static byte[] DeriveKek(byte[] prfOutput)
	{
		ArgumentNullException.ThrowIfNull(prfOutput);
		if (prfOutput.Length != 32)
			throw new ArgumentException("PRF output must be 32 bytes.", nameof(prfOutput));
		// HKDF-SHA256(prfOutput, salt="FileKeep-Passkey-KEK-v1", info="bundle-dek-wrap")
		using var hmac = new HMACSHA256("FileKeep-Passkey-KEK-v1"u8.ToArray());
		byte[] prk = hmac.ComputeHash(prfOutput);
		using var hmac2 = new HMACSHA256(prk);
		byte[] info = "bundle-dek-wrap"u8.ToArray();
		byte[] t = new byte[info.Length + 1];
		Array.Copy(info, t, info.Length);
		t[info.Length] = 0x01;
		byte[] okm = hmac2.ComputeHash(t);
		byte[] kek = new byte[32];
		Array.Copy(okm, kek, 32);
		CryptographicOperations.ZeroMemory(prk);
		CryptographicOperations.ZeroMemory(okm);
		return kek;
	}
}
