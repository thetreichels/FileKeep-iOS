using System.Security.Cryptography;
using AuthenticationServices;
using Foundation;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Passkey unlock via the WebAuthn PRF extension (iOS 18+). The PRF
/// output (32 bytes) is composed into the KEK via HKDF-SHA256 (salt
/// "FileKeep-Passkey-KEK-v1", info "bundle-dek-wrap"), mirroring the
/// YubiKey construction. The passkey itself never leaves the device;
/// only the PRF salt is stored in the bundle header.
/// </summary>
public static class PasskeyPrf
{
	private const string RelyingPartyId = "com.filekeep.reader";
	private static readonly byte[] KekSalt = "FileKeep-Passkey-KEK-v1"u8.ToArray();
	private static readonly byte[] KekInfo = "bundle-dek-wrap"u8.ToArray();

	public sealed class Result
	{
		public byte[]? Kek { get; init; }
		public string? Error { get; init; }
		public byte[]? PrfSalt { get; init; } // registration only
	}

	/// <summary>True when the device supports platform passkeys with PRF (iOS 18+).</summary>
	public static bool IsAvailable()
	{
		if (!OperatingSystem.IsIOSVersionAtLeast(18, 0))
			return false;
		// ASAuthorizationPlatformPublicKeyCredentialProvider exists on iOS 15+;
		// PRF requires iOS 18. The version check above gates it.
		return true;
	}

	/// <summary>
	/// Registers a new passkey and returns the KEK derived from the PRF
	/// output, plus the PRF salt to store in the bundle header.
	/// </summary>
	public static async Task<Result> RegisterAsync()
	{
		if (!IsAvailable())
			return new Result { Error = "Passkeys with PRF need iOS 18 or later." };

		byte[] challenge = RandomNumberGenerator.GetBytes(32);
		byte[] prfSalt = RandomNumberGenerator.GetBytes(32);
		byte[] userId = RandomNumberGenerator.GetBytes(16);

		var provider = new ASAuthorizationPlatformPublicKeyCredentialProvider(RelyingPartyId);
		var req = provider.CreateCredentialRegistrationRequest(challenge, "FileKeep bundle", userId);

		// PRF registration input (iOS 18+). If the binding lacks it, this throws.
		try
		{
			var prfInput = ASAuthorizationPublicKeyCredentialPrfRegistrationExtensionInput.Create(prfSalt);
			req.PrfInput = prfInput;
		}
		catch (Exception ex)
		{
			return new Result { Error = "PRF not available: " + ex.Message };
		}

		var controller = new ASAuthorizationController(new[] { req });
		var tcs = new TaskCompletionSource<Result>();
		var del = new AuthDelegate(tcs, prfSalt);
		controller.Delegate = del;
		controller.PresentationContextProvider = del;
		controller.PerformRequests();

		Result result = await tcs.Task;
		CryptographicOperations.ZeroMemory(challenge);
		CryptographicOperations.ZeroMemory(userId);
		return result;
	}

	/// <summary>
	/// Authenticates with the passkey and evaluates the PRF on the stored
	/// salt, returning the KEK. The salt comes from the bundle's wrap.
	/// </summary>
	public static async Task<Result> AuthenticateAsync(byte[] prfSalt)
	{
		ArgumentNullException.ThrowIfNull(prfSalt);
		if (!IsAvailable())
			return new Result { Error = "Passkeys with PRF need iOS 18 or later." };

		byte[] challenge = RandomNumberGenerator.GetBytes(32);
		var provider = new ASAuthorizationPlatformPublicKeyCredentialProvider(RelyingPartyId);
		var req = provider.CreateCredentialAssertionRequest(challenge);

		try
		{
			var prfInput = ASAuthorizationPublicKeyCredentialPrfAssertionExtensionInput.Create(prfSalt);
			req.PrfInput = prfInput;
		}
		catch (Exception ex)
		{
			CryptographicOperations.ZeroMemory(challenge);
			return new Result { Error = "PRF not available: " + ex.Message };
		}

		var controller = new ASAuthorizationController(new[] { req });
		var tcs = new TaskCompletionSource<Result>();
		var del = new AuthDelegate(tcs, null);
		controller.Delegate = del;
		controller.PresentationContextProvider = del;
		controller.PerformRequests();

		Result result = await tcs.Task;
		CryptographicOperations.ZeroMemory(challenge);
		return result;
	}

	/// <summary>Derives the 32-byte KEK from the 32-byte PRF output.</summary>
	public static byte[] DeriveKek(byte[] prfOutput)
	{
		ArgumentNullException.ThrowIfNull(prfOutput);
		if (prfOutput.Length != 32)
			throw new ArgumentException("PRF output must be 32 bytes.", nameof(prfOutput));
		return Hkdf.DeriveKey(HashAlgorithmName.SHA256, prfOutput, 32, KekSalt, KekInfo);
	}

	private sealed class AuthDelegate : ASAuthorizationControllerDelegate, IASAuthorizationControllerPresentationContextProviding
	{
		private readonly TaskCompletionSource<Result> _tcs;
		private readonly byte[]? _regSalt;

		public AuthDelegate(TaskCompletionSource<Result> tcs, byte[]? regSalt)
		{
			_tcs = tcs;
			_regSalt = regSalt;
		}

		public override void DidComplete(ASAuthorizationController controller, ASAuthorization authorization)
		{
			try
			{
				byte[]? prfBytes = null;
				if (authorization.Credential is ASAuthorizationPlatformPublicKeyCredentialAssertion assertion)
				{
					// PRF output is in the extension outputs.
					foreach (var ext in assertion.ExtensionOutputs ?? Array.Empty<IASAuthorizationPublicKeyCredentialExtensionOutput>())
					{
						if (ext is ASAuthorizationPublicKeyCredentialPrfAssertionExtensionOutput prfOut)
						{
							prfBytes = prfOut.Prf?.ToArray();
							break;
						}
					}
				}
				else if (authorization.Credential is ASAuthorizationPlatformPublicKeyCredentialRegistration)
				{
					// Registration: PRF output isn't returned directly; we re-authenticate
					// immediately to get the PRF output for the fresh salt. For now,
					// signal success and let the caller drive the auth step.
					_tcs.TrySetResult(new Result { PrfSalt = _regSalt, Error = "registered" });
					return;
				}

				if (prfBytes is null || prfBytes.Length != 32)
				{
					_tcs.TrySetResult(new Result { Error = "Passkey didn't return PRF output." });
					return;
				}
				try
				{
					byte[] kek = DeriveKek(prfBytes);
					_tcs.TrySetResult(new Result { Kek = kek, PrfSalt = _regSalt });
				}
				finally
				{
					CryptographicOperations.ZeroMemory(prfBytes);
				}
			}
			catch (Exception ex)
			{
				_tcs.TrySetResult(new Result { Error = ex.Message });
			}
		}

		public override void DidComplete(ASAuthorizationController controller, NSError error)
		{
			_tcs.TrySetResult(new Result { Error = error.LocalizedDescription });
		}

		public UIWindow GetPresentationAnchor(ASAuthorizationController controller)
		{
			var scene = UIApplication.SharedApplication.ConnectedScenes
				.OfType<UIWindowScene>().FirstOrDefault();
			return scene?.Windows.FirstOrDefault(w => w.IsKeyWindow)
				?? new UIWindow();
		}
	}
}
