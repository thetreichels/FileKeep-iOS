using AuthenticationServices;
using Foundation;
using ObjCRuntime;
using System.Security.Cryptography;
using System.Text;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Passkey PRF (WebAuthn pseudo-random function) over the platform
/// authenticator (iCloud Keychain), iOS 18+.
///
/// A passkey's PRF extension deterministically derives a 32-byte
/// output from (credential, salt). The bundle stores the salt
/// (prf_salt_b64) and the credential ID; the same passkey + salt
/// reproduces the same output on any synced device, so the output
/// feeds HKDF into the bundle KEK (see <see cref="Core.Bundle.PasskeyKek"/>).
///
/// The .NET iOS bindings (10.0.103) do NOT expose the PRF types
/// (ASAuthorizationPublicKeyCredentialPRF*), so this class drives
/// them through the ObjC runtime: the provider, requests, and
/// controller come from the bound AuthenticationServices API, and
/// only the PRF input objects and the `prf` property go through
/// objc_msgSend. The ObjC shapes below were verified against real
/// code that calls them (Chromium's iCloud Keychain implementation
/// and react-native-passkeys), not written from memory:
///   - ASAuthorizationPublicKeyCredentialPRFRegistrationInputValues
///     initWithSaltInput1:saltInput2:
///   - ASAuthorizationPublicKeyCredentialPRFRegistrationInput
///     +checkForSupport, -initWithInputValues:
///   - ASAuthorizationPublicKeyCredentialPRFAssertionInputValues
///     initWithSaltInput1:saltInput2:
///   - ASAuthorizationPublicKeyCredentialPRFAssertionInput
///     -initWithInputValues:perCredentialInputValues:
///   - request.prf (setter setPrf:), credential.prf, .isSupported,
///     .first, .second.
///
/// Every handle created here is checked for null and every failure
/// reports loudly — a missing PRF result must never silently
/// produce a bundle that can't unlock.
///
/// Honest limit: the app must be signed with the Associated Domains
/// entitlement (webcredentials:treichel.co) for the ceremony to run.
/// A free personal-team provisioning profile cannot carry it, so on
/// the sideloaded build the ceremony fails with "not configured"
/// until the paid Apple Developer account exists. The code is ready;
/// the signing is not.
/// </summary>
public static class PasskeyPrf
{
	/// <summary>Relying-party domain passkeys are created under.</summary>
	public const string RelyingPartyId = "treichel.co";

	/// <summary>PRF outputs are always 32 bytes.</summary>
	public const int PrfOutputSizeBytes = 32;

	/// <summary>Result of creating a passkey with PRF enabled.</summary>
	public sealed record CreateResult(byte[]? CredentialId, byte[]? PrfOutput, string? Error, bool Cancelled);

	/// <summary>Result of evaluating PRF on an existing passkey.</summary>
	public sealed record EvaluateResult(byte[]? PrfOutput, string? Error, bool Cancelled);

	private sealed record CeremonyOutcome(byte[]? CredentialId, byte[]? PrfOutput, string? Error, bool Cancelled);

	private sealed class Ceremony
	{
		public required ASAuthorizationController Controller { get; init; }
		public required ControllerDelegate Delegate { get; init; }
		public required TaskCompletionSource<CeremonyOutcome> Completion { get; init; }
	}

	private static Ceremony? s_current;

	/// <summary>
	/// Whether this device can do PRF at all: iOS 18+ on a real
	/// device. The simulator has no authenticator. Anything else is
	/// decided by the ceremony itself, which fails loudly.
	/// </summary>
	public static bool IsAvailable()
	{
		if (!UIDevice.CurrentDevice.CheckSystemVersion(18, 0))
			return false;
		if (Runtime.Arch == Arch.SIMULATOR)
			return false;
		return true;
	}

	/// <summary>
	/// Creates a platform passkey for treichel.co with PRF enabled on
	/// <paramref name="prfSalt"/> (32 bytes). Returns the new
	/// credential ID and the first PRF output — the registration
	/// ceremony evaluates the salt immediately, so the KEK input is
	/// available without a second ceremony. The caller owns both
	/// buffers and must zero the PRF output after deriving the KEK.
	/// Fails loudly (never a silent partial) when PRF isn't actually
	/// enabled on the created credential.
	/// </summary>
	public static Task<CreateResult> CreateCredentialAsync(byte[] prfSalt)
	{
		var tcs = new TaskCompletionSource<CeremonyOutcome>();
		if (prfSalt is null || prfSalt.Length != PrfOutputSizeBytes)
		{
			tcs.SetResult(new CeremonyOutcome(null, null, "PRF salt must be 32 bytes.", false));
			return ToCreateResultAsync(tcs.Task);
		}
		if (!IsAvailable())
		{
			tcs.SetResult(new CeremonyOutcome(null, null, "Passkeys need iOS 18 or later on a real device.", false));
			return ToCreateResultAsync(tcs.Task);
		}
		if (s_current is not null)
		{
			tcs.SetResult(new CeremonyOutcome(null, null, "A passkey request is already running.", false));
			return ToCreateResultAsync(tcs.Task);
		}
		try
		{
			byte[] challenge = RandomNumberGenerator.GetBytes(32);
			byte[] userId = Encoding.UTF8.GetBytes("filekeep");
			using var challengeData = NSData.FromArray(challenge);
			using var userIdData = NSData.FromArray(userId);
			using var saltData = NSData.FromArray(prfSalt);

			var provider = new ASAuthorizationPlatformPublicKeyCredentialProvider(RelyingPartyId);
			var request = provider.CreateCredentialRegistrationRequest(challengeData, "FileKeep", userIdData);

			// Attach the PRF input: evaluating the salt at creation both
			// enables PRF on the credential and returns the first output.
			IntPtr prfInput = CreateRegistrationPrfInput(saltData.Handle);
			Messaging.void_objc_msgSend_IntPtr(request.Handle, Selector.GetHandle("setPrf:"), prfInput);
			Messaging.void_objc_msgSend(prfInput, Selector.GetHandle("release"));

			var controller = new ASAuthorizationController(new[] { request });
			var del = new ControllerDelegate(tcs);
			controller.Delegate = del;
			controller.PresentationContextProvider = del;
			s_current = new Ceremony { Controller = controller, Delegate = del, Completion = tcs };
			PerformOnMainThread(controller);
		}
		catch (Exception ex)
		{
			s_current = null;
			tcs.TrySetResult(new CeremonyOutcome(null, null, "Passkey failed: " + ex.Message, false));
		}
		return ToCreateResultAsync(tcs.Task);
	}

	/// <summary>
	/// Evaluates PRF on the passkey identified by
	/// <paramref name="credentialId"/> with <paramref name="prfSalt"/>
	/// (32 bytes). Targeted assertion: only that credential is offered.
	/// Returns the 32-byte PRF output; the caller owns it and must
	/// zero it after deriving the KEK.
	/// </summary>
	public static Task<EvaluateResult> EvaluatePrfAsync(byte[] credentialId, byte[] prfSalt)
	{
		var tcs = new TaskCompletionSource<CeremonyOutcome>();
		if (credentialId is null || credentialId.Length == 0 ||
			prfSalt is null || prfSalt.Length != PrfOutputSizeBytes)
		{
			tcs.SetResult(new CeremonyOutcome(null, null, "Passkey wrap is missing its credential ID or salt.", false));
			return ToEvaluateResultAsync(tcs.Task);
		}
		if (!IsAvailable())
		{
			tcs.SetResult(new CeremonyOutcome(null, null, "Passkeys need iOS 18 or later on a real device.", false));
			return ToEvaluateResultAsync(tcs.Task);
		}
		if (s_current is not null)
		{
			tcs.SetResult(new CeremonyOutcome(null, null, "A passkey request is already running.", false));
			return ToEvaluateResultAsync(tcs.Task);
		}
		try
		{
			byte[] challenge = RandomNumberGenerator.GetBytes(32);
			using var challengeData = NSData.FromArray(challenge);
			using var saltData = NSData.FromArray(prfSalt);
			using var credentialIdData = NSData.FromArray(credentialId);

			var provider = new ASAuthorizationPlatformPublicKeyCredentialProvider(RelyingPartyId);
			var request = provider.CreateCredentialAssertionRequest(challengeData);

			var descriptor = new ASAuthorizationPublicKeyCredentialDescriptor(credentialIdData);
			request.AllowedCredentials = new[] { descriptor };

			IntPtr prfInput = CreateAssertionPrfInput(saltData.Handle);
			Messaging.void_objc_msgSend_IntPtr(request.Handle, Selector.GetHandle("setPrf:"), prfInput);
			Messaging.void_objc_msgSend(prfInput, Selector.GetHandle("release"));

			var controller = new ASAuthorizationController(new[] { request });
			var del = new ControllerDelegate(tcs);
			controller.Delegate = del;
			controller.PresentationContextProvider = del;
			s_current = new Ceremony { Controller = controller, Delegate = del, Completion = tcs };
			PerformOnMainThread(controller);
		}
		catch (Exception ex)
		{
			s_current = null;
			tcs.TrySetResult(new CeremonyOutcome(null, null, "Passkey failed: " + ex.Message, false));
		}
		return ToEvaluateResultAsync(tcs.Task);
	}

	private static async Task<CreateResult> ToCreateResultAsync(Task<CeremonyOutcome> task)
	{
		CeremonyOutcome o = await task.ConfigureAwait(false);
		return new CreateResult(o.CredentialId, o.PrfOutput, o.Error, o.Cancelled);
	}

	private static async Task<EvaluateResult> ToEvaluateResultAsync(Task<CeremonyOutcome> task)
	{
		CeremonyOutcome o = await task.ConfigureAwait(false);
		return new EvaluateResult(o.PrfOutput, o.Error, o.Cancelled);
	}

	private static void PerformOnMainThread(ASAuthorizationController controller)
	{
		if (Microsoft.Maui.ApplicationModel.MainThread.IsMainThread)
			controller.PerformRequests();
		else
			Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() => controller.PerformRequests());
	}

	/// <summary>
	/// Builds a registration PRF input for one salt. Returns a +1
	/// reference; the caller releases it after setPrf: retains it.
	/// </summary>
	private static IntPtr CreateRegistrationPrfInput(IntPtr saltDataHandle)
	{
		IntPtr valuesClass = Class.GetHandle("ASAuthorizationPublicKeyCredentialPRFRegistrationInputValues");
		if (valuesClass == IntPtr.Zero)
			throw new InvalidOperationException("This iOS version has no PRF registration API.");
		IntPtr valuesAlloc = Messaging.IntPtr_objc_msgSend(valuesClass, Selector.GetHandle("alloc"));
		IntPtr values = Messaging.IntPtr_objc_msgSend_IntPtr_IntPtr(valuesAlloc,
			Selector.GetHandle("initWithSaltInput1:saltInput2:"), saltDataHandle, IntPtr.Zero);
		if (values == IntPtr.Zero)
			throw new InvalidOperationException("Couldn't build the PRF input values.");
		try
		{
			IntPtr inputClass = Class.GetHandle("ASAuthorizationPublicKeyCredentialPRFRegistrationInput");
			if (inputClass == IntPtr.Zero)
				throw new InvalidOperationException("This iOS version has no PRF registration API.");
			IntPtr inputAlloc = Messaging.IntPtr_objc_msgSend(inputClass, Selector.GetHandle("alloc"));
			IntPtr input = Messaging.IntPtr_objc_msgSend_IntPtr(inputAlloc,
				Selector.GetHandle("initWithInputValues:"), values);
			if (input == IntPtr.Zero)
				throw new InvalidOperationException("Couldn't build the PRF input.");
			return input;
		}
		finally
		{
			// initWithInputValues: retained the values; drop our +1.
			Messaging.void_objc_msgSend(values, Selector.GetHandle("release"));
		}
	}

	/// <summary>
	/// Builds an assertion PRF input for one salt (eval mode).
	/// Returns a +1 reference; the caller releases it after setPrf:
	/// retains it. The per-credential map is empty — the credential
	/// is already targeted via allowedCredentials.
	/// </summary>
	private static IntPtr CreateAssertionPrfInput(IntPtr saltDataHandle)
	{
		IntPtr valuesClass = Class.GetHandle("ASAuthorizationPublicKeyCredentialPRFAssertionInputValues");
		if (valuesClass == IntPtr.Zero)
			throw new InvalidOperationException("This iOS version has no PRF assertion API.");
		IntPtr valuesAlloc = Messaging.IntPtr_objc_msgSend(valuesClass, Selector.GetHandle("alloc"));
		IntPtr values = Messaging.IntPtr_objc_msgSend_IntPtr_IntPtr(valuesAlloc,
			Selector.GetHandle("initWithSaltInput1:saltInput2:"), saltDataHandle, IntPtr.Zero);
		if (values == IntPtr.Zero)
			throw new InvalidOperationException("Couldn't build the PRF input values.");
		try
		{
			IntPtr inputClass = Class.GetHandle("ASAuthorizationPublicKeyCredentialPRFAssertionInput");
			if (inputClass == IntPtr.Zero)
				throw new InvalidOperationException("This iOS version has no PRF assertion API.");
			IntPtr inputAlloc = Messaging.IntPtr_objc_msgSend(inputClass, Selector.GetHandle("alloc"));
			using var emptyPerCredential = new NSMutableDictionary();
			IntPtr input = Messaging.IntPtr_objc_msgSend_IntPtr_IntPtr(inputAlloc,
				Selector.GetHandle("initWithInputValues:perCredentialInputValues:"), values, emptyPerCredential.Handle);
			if (input == IntPtr.Zero)
				throw new InvalidOperationException("Couldn't build the PRF input.");
			return input;
		}
		finally
		{
			// initWithInputValues:perCredentialInputValues: retained
			// the values; drop our +1.
			Messaging.void_objc_msgSend(values, Selector.GetHandle("release"));
		}
	}

	private static void ClearCurrent(ControllerDelegate del)
	{
		if (s_current is not null && ReferenceEquals(s_current.Delegate, del))
			s_current = null;
	}

	/// <summary>
	/// Reads the credential out of a completed authorization: the
	/// credential ID plus the PRF output. Registration also reports
	/// whether PRF is supported — a created credential without PRF
	/// would be unrecoverable, so that fails loudly here.
	/// </summary>
	private static CeremonyOutcome ReadAuthorization(ASAuthorization authorization)
	{
		if (authorization.Credential is ASAuthorizationPlatformPublicKeyCredentialRegistration reg)
		{
			byte[]? credentialId = reg.CredentialID?.ToArray();
			if (credentialId is null || credentialId.Length == 0)
				return new CeremonyOutcome(null, null, "Passkey didn't return a credential ID.", false);
			(byte[]? prf, string? prfError) = ReadRegistrationPrf(reg);
			if (prf is null)
				return new CeremonyOutcome(null, null, prfError, false);
			return new CeremonyOutcome(credentialId, prf, null, false);
		}
		if (authorization.Credential is ASAuthorizationPlatformPublicKeyCredentialAssertion ass)
		{
			(byte[]? prf, string? prfError) = ReadAssertionPrf(ass);
			if (prf is null)
				return new CeremonyOutcome(null, null, prfError, false);
			byte[]? credentialId = ass.CredentialID?.ToArray();
			return new CeremonyOutcome(credentialId, prf, null, false);
		}
		return new CeremonyOutcome(null, null, "Passkey returned an unexpected credential type.", false);
	}

	private static (byte[]? PrfOutput, string? Error) ReadRegistrationPrf(
		ASAuthorizationPlatformPublicKeyCredentialRegistration credential)
	{
		IntPtr prfHandle = Messaging.IntPtr_objc_msgSend(credential.Handle, Selector.GetHandle("prf"));
		if (prfHandle == IntPtr.Zero)
			return (null, "Passkey didn't return a PRF result — PRF may not be enabled on this credential.");
		bool supported = Messaging.bool_objc_msgSend(prfHandle, Selector.GetHandle("isSupported"));
		if (!supported)
			return (null, "This passkey doesn't support PRF.");
		return ReadPrfFirst(prfHandle);
	}

	private static (byte[]? PrfOutput, string? Error) ReadAssertionPrf(
		ASAuthorizationPlatformPublicKeyCredentialAssertion credential)
	{
		IntPtr prfHandle = Messaging.IntPtr_objc_msgSend(credential.Handle, Selector.GetHandle("prf"));
		if (prfHandle == IntPtr.Zero)
			return (null, "Passkey didn't return a PRF result.");
		return ReadPrfFirst(prfHandle);
	}

	private static (byte[]? PrfOutput, string? Error) ReadPrfFirst(IntPtr prfHandle)
	{
		IntPtr firstHandle = Messaging.IntPtr_objc_msgSend(prfHandle, Selector.GetHandle("first"));
		if (firstHandle == IntPtr.Zero)
			return (null, "Passkey didn't return a PRF output.");
		byte[] first = Runtime.GetNSObject<NSData>(firstHandle).ToArray();
		if (first.Length != PrfOutputSizeBytes)
			return (null, "Passkey returned a bad PRF output.");
		return (first, null);
	}

	/// <summary>
	/// Controller delegate + presentation provider, kept alive by
	/// s_current until the ceremony completes exactly once.
	/// Mirrors the NfcYubiKey session-delegate pattern.
	/// </summary>
	private sealed class ControllerDelegate : ASAuthorizationControllerDelegate,
		IASAuthorizationControllerPresentationContextProviding
	{
		private readonly TaskCompletionSource<CeremonyOutcome> _tcs;
		private int _done;

		public ControllerDelegate(TaskCompletionSource<CeremonyOutcome> tcs)
		{
			_tcs = tcs;
		}

		public override void DidCompleteWithAuthorization(ASAuthorizationController controller, ASAuthorization authorization)
		{
			if (Interlocked.Exchange(ref _done, 1) != 0)
				return;
			try
			{
				_tcs.TrySetResult(ReadAuthorization(authorization));
			}
			catch (Exception ex)
			{
				_tcs.TrySetResult(new CeremonyOutcome(null, null, "Passkey failed: " + ex.Message, false));
			}
			finally
			{
				ClearCurrent(this);
			}
		}

		public override void DidCompleteWithError(ASAuthorizationController controller, NSError error)
		{
			if (Interlocked.Exchange(ref _done, 1) != 0)
				return;
			try
			{
				int code = (int)error.Code;
				if (code == 1001) // user cancelled
					_tcs.TrySetResult(new CeremonyOutcome(null, null, null, true));
				else if (code == 4004) // not configured (no associated domain)
					_tcs.TrySetResult(new CeremonyOutcome(null, null,
						"Passkeys aren't set up for treichel.co yet — the app isn't associated with the domain.", false));
				else
					_tcs.TrySetResult(new CeremonyOutcome(null, null,
						"Passkey failed: " + (error.LocalizedDescription ?? "unknown error"), false));
			}
			finally
			{
				ClearCurrent(this);
			}
		}

		public UIWindow GetPresentationAnchor(ASAuthorizationController controller)
		{
			var window = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController()?.View?.Window
				?? UIApplication.SharedApplication.KeyWindow;
			if (window is null)
				throw new InvalidOperationException("No window to present the passkey sheet from.");
			return window;
		}
	}
}
