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
/// The .NET iOS bindings DO expose the PRF types (since iOS 18 /
/// .NET 9): ASAuthorizationPublicKeyCredentialPrf* input/output
/// classes, the `Prf` property on the platform requests and on the
/// platform credentials, and ASAuthorizationPlatformPublicKeyCredentialDescriptor.
/// This class uses those bound types directly — no ObjC-runtime
/// message dispatch, no internal `Messaging` class. (An earlier
/// version of this file drove PRF through objc_msgSend because the
/// bindings were believed not to expose it; that was wrong, and CI
/// #201 proved it — the bindings have had the PRF surface since the
/// release/9.0.1xx branch.)
///
/// The one exception: ASAuthorization exposes its credential only as
/// an internal handle in the bindings, so the completed credential
/// is read through the public NSObject `performSelector:` for the
/// `credential` getter, then matched with `is` against the bound
/// platform credential classes.
///
/// Every failure reports loudly — a missing PRF result must never
/// silently produce a bundle that can't unlock.
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

	/// <summary>
	/// How long a ceremony may run before it is declared dead. The
	/// system never answers when the app isn't associated with the
	/// domain (missing Associated Domains entitlement), and without a
	/// timeout the await hangs forever with no error.
	/// </summary>
	private static readonly TimeSpan CeremonyTimeout = TimeSpan.FromSeconds(60);

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
		ControllerDelegate? del = null;
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
			// The request retains the input; the controller retains the
			// request for the life of the ceremony.
			request.Prf = CreateRegistrationPrfInput(saltData);

			var controller = new ASAuthorizationController(new[] { request });
			del = new ControllerDelegate(tcs);
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
		return ToCreateResultAsync(WaitForCeremonyAsync(tcs.Task, del));
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
		ControllerDelegate? del = null;
		try
		{
			byte[] challenge = RandomNumberGenerator.GetBytes(32);
			using var challengeData = NSData.FromArray(challenge);
			using var saltData = NSData.FromArray(prfSalt);
			using var credentialIdData = NSData.FromArray(credentialId);

			var provider = new ASAuthorizationPlatformPublicKeyCredentialProvider(RelyingPartyId);
			var request = provider.CreateCredentialAssertionRequest(challengeData);

			var descriptor = new ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialIdData);
			request.PlatformAllowedCredentials = new[] { descriptor };

			// Attach the PRF input for eval mode. The request retains
			// the input; the controller retains the request.
			request.Prf = CreateAssertionPrfInput(saltData);

			var controller = new ASAuthorizationController(new[] { request });
			del = new ControllerDelegate(tcs);
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
		return ToEvaluateResultAsync(WaitForCeremonyAsync(tcs.Task, del));
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

	/// <summary>
	/// Awaits a ceremony outcome, failing loudly if the system never
	/// answers within <see cref="CeremonyTimeout"/>. On timeout the
	/// current ceremony is cleared so a stuck request doesn't block
	/// later attempts; a late delegate callback stays harmless (the
	/// delegate's single-completion flag + TrySetResult ignore it).
	/// </summary>
	private static async Task<CeremonyOutcome> WaitForCeremonyAsync(
		Task<CeremonyOutcome> task, ControllerDelegate? del)
	{
		Task completed = await Task.WhenAny(task, Task.Delay(CeremonyTimeout)).ConfigureAwait(false);
		if (completed == task)
			return await task.ConfigureAwait(false);
		if (del is not null)
			ClearCurrent(del);
		return new CeremonyOutcome(null, null,
			"Passkey didn't respond — the system never answered the request. " +
			"This happens when the app isn't associated with treichel.co (missing Associated Domains entitlement).", false);
	}

	private static void PerformOnMainThread(ASAuthorizationController controller)
	{
		if (Microsoft.Maui.ApplicationModel.MainThread.IsMainThread)
			controller.PerformRequests();
		else
			Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() => controller.PerformRequests());
	}

	/// <summary>
	/// Builds a registration PRF input for one salt, using the bound
	/// PRF types (iOS 18+). The request retains the input.
	/// </summary>
	private static ASAuthorizationPublicKeyCredentialPrfRegistrationInput CreateRegistrationPrfInput(NSData saltData)
	{
		var values = new ASAuthorizationPublicKeyCredentialPrfAssertionInputValues(saltData, null);
		return new ASAuthorizationPublicKeyCredentialPrfRegistrationInput(values);
	}

	/// <summary>
	/// Builds an assertion PRF input for one salt (eval mode), using
	/// the bound PRF types (iOS 18+). The per-credential map is nil —
	/// the credential is already targeted via allowedCredentials. The
	/// request retains the input.
	/// </summary>
	private static ASAuthorizationPublicKeyCredentialPrfAssertionInput CreateAssertionPrfInput(NSData saltData)
	{
		var values = new ASAuthorizationPublicKeyCredentialPrfAssertionInputValues(saltData, null);
		return new ASAuthorizationPublicKeyCredentialPrfAssertionInput(values, null);
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
		// ASAuthorization exposes its credential only as an internal
		// handle in the bindings, so read it through the public
		// NSObject performSelector: for the `credential` getter.
		// The returned object is the platform registration or
		// assertion credential; the `is` checks below match it.
		NSObject? credentialObj = authorization.PerformSelector(new Selector("credential"));
		if (credentialObj is ASAuthorizationPlatformPublicKeyCredentialRegistration reg)
		{
			byte[]? credentialId = reg.CredentialId?.ToArray();
			if (credentialId is null || credentialId.Length == 0)
				return new CeremonyOutcome(null, null, "Passkey didn't return a credential ID.", false);
			(byte[]? prf, string? prfError) = ReadRegistrationPrf(reg);
			if (prf is null)
				return new CeremonyOutcome(null, null, prfError, false);
			return new CeremonyOutcome(credentialId, prf, null, false);
		}
		if (credentialObj is ASAuthorizationPlatformPublicKeyCredentialAssertion ass)
		{
			(byte[]? prf, string? prfError) = ReadAssertionPrf(ass);
			if (prf is null)
				return new CeremonyOutcome(null, null, prfError, false);
			byte[]? credentialId = ass.CredentialId?.ToArray();
			return new CeremonyOutcome(credentialId, prf, null, false);
		}
		return new CeremonyOutcome(null, null, "Passkey returned an unexpected credential type.", false);
	}

	private static (byte[]? PrfOutput, string? Error) ReadRegistrationPrf(
		ASAuthorizationPlatformPublicKeyCredentialRegistration credential)
	{
		ASAuthorizationPublicKeyCredentialPrfRegistrationOutput? prf = credential.Prf;
		if (prf is null)
			return (null, "Passkey didn't return a PRF result — PRF may not be enabled on this credential.");
		if (!prf.IsSupported)
			return (null, "This passkey doesn't support PRF.");
		return ReadPrfFirst(prf.First);
	}

	private static (byte[]? PrfOutput, string? Error) ReadAssertionPrf(
		ASAuthorizationPlatformPublicKeyCredentialAssertion credential)
	{
		ASAuthorizationPublicKeyCredentialPrfAssertionOutput? prf = credential.Prf;
		if (prf is null)
			return (null, "Passkey didn't return a PRF result.");
		return ReadPrfFirst(prf.First);
	}

	private static (byte[]? PrfOutput, string? Error) ReadPrfFirst(NSData? first)
	{
		if (first is null)
			return (null, "Passkey didn't return a PRF output.");
		byte[] bytes = first.ToArray();
		if (bytes.Length != PrfOutputSizeBytes)
			return (null, "Passkey returned a bad PRF output.");
		return (bytes, null);
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

		public override void DidComplete(ASAuthorizationController controller, ASAuthorization authorization)
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

		public override void DidComplete(ASAuthorizationController controller, NSError error)
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
