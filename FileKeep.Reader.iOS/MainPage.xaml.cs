using System.Security.Cryptography;
using System.Text;
using FileKeep.Core;
using FileKeep.Reader.iOS.Core.Bundle;
using FileKeep.Reader.iOS.Core.Recents;
using FileKeep.Reader.iOS.Core.Session;
#if IOS
using FileKeep.Reader.iOS.Platforms.iOS;
using Foundation;
using UIKit;
#endif

namespace FileKeep.Reader.iOS;

/// <summary>
/// FileKeep secure workspace: open a bundle (Files or HTTP), unlock
/// (Face ID / YubiKey / passphrase), read, create, update, and delete
/// files behind the DEK veil, then save back or upload the re-encrypted
/// bundle. Plaintext lives in memory only; the HTTP server sees ciphertext.
/// </summary>
public partial class MainPage : ContentPage
{
#if IOS
	private AudioPlayer? _audioPlayer;
	private NSUrl? _sourceFileUrl; // Files pick source, for save-back
	private string? _sourceHttpUrl; // HTTP download source, for upload-back
	private readonly Dictionary<string, byte[]> _modified = new(); // path -> new plaintext
	private readonly HashSet<string> _deleted = new();
	private bool _isReadOnly;
	private bool _isNewBundle;
	private readonly List<BundleWrap> _pendingWraps = new();
	private string? _editingPath;
	private Editor? _textEditor;
	private string? _textEditorOriginal;
	private string _currentBadgeMethod = "Layered";
	private string _currentBookmarkB64 = "";
#endif

	public MainPage()
	{
		InitializeComponent();
		VersionLabel.Text = "v" + Microsoft.Maui.ApplicationModel.AppInfo.Current.VersionString;
#if IOS
		UpdateDirtyUi();
#endif
		SessionManager.Instance.Locked += (_, _) =>
			Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
			{
				ResetPreviewUi();
				ShowVault();
			});
		ShowVault();
	}

	private async void OnOpenClicked(object? sender, EventArgs e)
	{
#if !IOS
		await DisplayAlert("Not supported", "Bundle opening needs iOS.", "OK");
		return;
#else
		CloseReader();
		await OpenFromPickerAsync();
#endif
	}

#if IOS
	private async void OnDownloadClicked(object? sender, EventArgs e)
	{
		CloseReader();
		string? url = await DisplayPromptAsync("Download bundle", "HTTPS URL of the .kfb file:");
		if (string.IsNullOrWhiteSpace(url))
			return;
		url = url.Trim();
		if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
		    !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
		{
			StatusLabel.Text = "URL must start with http:// or https://.";
			StatusLabel.TextColor = StatusColor("StatusError", "#F1707B");
			SyncVaultStatus();
			return;
		}

		await DownloadAndOpenAsync(url);
	}

	private async void OnNewClicked(object? sender, EventArgs e)
	{
#if !IOS
		await DisplayAlert("Not supported", "Bundle creation needs iOS.", "OK");
		return;
#else
		CloseReader();

		// Step 1: Pick methods.
		var methods = await NewBundlePicker.PickMethodsAsync();
		if (methods is null || methods.Count == 0)
			return; // user cancelled

		// Step 2: AND or OR?
		bool requireAll = false;
		if (methods.Count > 1)
		{
			bool? andOr = await NewBundlePicker.AskAndOrAsync(methods.Count);
			if (andOr is null)
				return; // user cancelled
			requireAll = andOr.Value;
		}

		// Step 3: Set up each method, collect KEKs and wrap metadata.
		// Tuples: (type, kek, salt, iterations, slot, challenge,
		// prfSalt, credentialId).
		StatusLabel.Text = "Setting up unlock methods…";
		var wrapInfos = new List<(string Type, byte[] Kek, byte[]? Salt, int? Iterations, int? Slot, byte[]? Challenge, byte[]? PrfSalt, byte[]? CredentialId)>();
		try
		{
			foreach (var method in methods)
			{
				if (method == "passphrase")
				{
					char[]? passphrase = await NewBundlePicker.PromptNewPassphraseAsync();
					if (passphrase is null)
						return; // user cancelled
					byte[] salt = RandomNumberGenerator.GetBytes(32);
					const int iterations = 600000;
					byte[] kek;
					try
					{
						kek = await Task.Run(() => Rfc2898DeriveBytes.Pbkdf2(
							passphrase, salt, iterations, HashAlgorithmName.SHA512, KeyDerivation.KeySizeBytes));
					}
					finally
					{
						Array.Clear(passphrase);
					}
					wrapInfos.Add(("passphrase", kek, salt, iterations, null, null, null, null));
				}
				else if (method == "yubikey-hmac-sha1")
				{
					// Generate a fresh challenge for this bundle.
					byte[] challenge = RandomNumberGenerator.GetBytes(32);
					int slot = 2;
					StatusLabel.Text = "Tap your YubiKey…";
					var result = await NfcYubiKey.GetKekAsync(slot, challenge);
					if (result.Kek is null)
					{
						StatusLabel.Text = result.Error ?? "YubiKey didn't respond.";
						CryptographicOperations.ZeroMemory(challenge);
						return;
					}
					wrapInfos.Add(("yubikey-hmac-sha1", result.Kek, null, null, slot, challenge, null, null));
				}
				else if (method == "passkey-prf")
				{
					// Fresh 32-byte PRF salt. The ceremony enables PRF
					// on the new passkey and evaluates the salt right
					// away, returning the 32-byte PRF output directly.
					byte[] prfSalt = RandomNumberGenerator.GetBytes(32);
					StatusLabel.Text = "Use your passkey…";
					PasskeyPrf.CreateResult pk = await PasskeyPrf.CreateCredentialAsync(prfSalt);
					if (pk.PrfOutput is null || pk.CredentialId is null)
					{
						StatusLabel.Text = pk.Error ?? (pk.Cancelled
							? "Passkey creation cancelled."
							: "Passkey setup failed.");
						return;
					}
					byte[] kek = PasskeyKek.Derive(pk.PrfOutput);
					// PRF output is single-use key material — zero it
					// as soon as the KEK is derived.
					CryptographicOperations.ZeroMemory(pk.PrfOutput);
					wrapInfos.Add(("passkey-prf", kek, null, null, null, null, prfSalt, pk.CredentialId));
				}
			}

			// Step 4: Generate DEK and create wraps.
			StatusLabel.Text = "Creating bundle…";
			byte[] dek = RandomNumberGenerator.GetBytes(KeyDerivation.KeySizeBytes);
			try
			{
				var wraps = new List<BundleWrap>();
				if (requireAll && wrapInfos.Count > 1)
				{
					// AND: split DEK into shares, wrap each share.
					byte[][] shares = DekSharing.Split(dek, wrapInfos.Count);
					try
					{
						for (int i = 0; i < wrapInfos.Count; i++)
						{
							var (type, kek, salt, iterations, slot, challenge, prfSalt, credentialId) = wrapInfos[i];
							var wrap = BundleReader.CreateWrap(
								type, kek, shares[i],
								mode: "and", group: "g1",
								salt: salt, iterations: iterations,
								slot: slot, challenge: challenge,
								prfSalt: prfSalt, credentialId: credentialId,
								rpId: type == "passkey-prf" ? PasskeyPrf.RelyingPartyId : null);
							wraps.Add(wrap);
						}
					}
					finally
					{
						foreach (var s in shares)
							CryptographicOperations.ZeroMemory(s);
					}
				}
				else
				{
					// OR: each wrap holds the full DEK.
					foreach (var (type, kek, salt, iterations, slot, challenge, prfSalt, credentialId) in wrapInfos)
					{
						var wrap = BundleReader.CreateWrap(
							type, kek, dek,
							salt: salt, iterations: iterations,
							slot: slot, challenge: challenge,
							prfSalt: prfSalt, credentialId: credentialId,
							rpId: type == "passkey-prf" ? PasskeyPrf.RelyingPartyId : null);
						wraps.Add(wrap);
					}
				}

				// Step 5: Build the bundle and open it.
				var header = new BundleHeader
				{
					Format = BundleReader.ExpectedFormat,
					Wraps = wraps,
					Files = new List<BundleFileEntry>(),
				};
				byte[] bundleBytes = await Task.Run(() =>
					BundleWriter.Rebuild(header, dek, Array.Empty<(string, byte[])>()));

				var reader = BundleReader.OpenWithDek(bundleBytes, dek);
				CryptographicOperations.ZeroMemory(bundleBytes);

				// Open in the session as a new unsaved bundle.
				SessionManager.Instance.Open(reader);
				_sourceFileUrl = null;
				_sourceHttpUrl = null;
				_isReadOnly = false;
				_isNewBundle = true;
				_modified.Clear();
				_deleted.Clear();
				_pendingWraps.Clear();
				RefreshFileList();
				UpdateDirtyUi();
				StatusLabel.Text = "New bundle created — add files, then Save.";
				ShowBundle();
			}
			finally
			{
				CryptographicOperations.ZeroMemory(dek);
			}
		}
		finally
		{
			foreach (var (_, kek, _, _, _, challenge, _, _) in wrapInfos)
			{
				CryptographicOperations.ZeroMemory(kek);
				if (challenge is not null)
					CryptographicOperations.ZeroMemory(challenge);
			}
		}
#endif
	}


	/// <summary>
	/// Checks if a Files URL (local or SMB) is writable. SMB shares with
	/// read-only permissions report false, and the workspace opens read-only.
	/// </summary>
	private static bool IsUrlWritable(NSUrl? url)
	{
		if (url?.Path is null)
			return false;
		bool scoped = url.StartAccessingSecurityScopedResource();
		try
		{
			return NSFileManager.DefaultManager.IsWritableFile(url.Path);
		}
		catch
		{
			return false;
		}
		finally
		{
			if (scoped)
				url.StopAccessingSecurityScopedResource();
		}
	}

	private async Task OpenBundleBytesAsync(byte[] bytes)
	{
		// The bundle fingerprint keys the Face ID enrollment: one DEK per
		// bundle, so each package unlocks independently.
		string fingerprint = Convert.ToHexString(SHA256.HashData(bytes));

		BundleReader? reader = await TryUnlockAsync(bytes, fingerprint);
		if (reader is null)
		{
			// Unlock failed or was cancelled: the vault list is still
			// showing, so mirror the reason there, in the error color.
			StatusLabel.TextColor = StatusColor("StatusError", "#F1707B");
			SyncVaultStatus();
			return;
		}

		SessionManager.Instance.Open(reader);
		_modified.Clear();
		_deleted.Clear();
		_pendingWraps.Clear();
		_isNewBundle = false;
		_editingPath = null;
		RefreshFileList();
		UpdateDirtyUi();
		// Badge from the header only (no extra unlock), then record the
		// bundle in the vault list and switch to the bundle view.
		_currentBadgeMethod = RecentBundleStore.BadgeMethodFor(bytes);
		_currentBookmarkB64 = CreateBookmark(_sourceFileUrl);
		RecordCurrentBundle();
		ShowBundle();
	}
#endif

#if IOS
	/// <summary>
	/// Unlock cascade: Face ID (enrolled DEK) → YubiKey NFC (when the
	/// bundle carries a YubiKey wrap; NFC failure is reported loudly
	/// and falls through) → typed passphrase. Returns null when the
	/// user cancels; every failure path zeroes <paramref name="bytes"/>
	/// before returning.
	/// </summary>
	private async Task<BundleReader?> TryUnlockAsync(byte[] bytes, string fingerprint)
	{
		// Layered unlock: if the bundle has multiple unlock options (OR methods
		// or AND groups), let the user pick. Otherwise use the classic cascade.
		if (BundleReader.TryGetLayers(bytes, out var orWraps, out var andGroups))
		{
			int totalOptions = orWraps.Count + andGroups.Count;
			if (totalOptions > 1)
			{
				return await UnlockWithLayerChoiceAsync(bytes, fingerprint, orWraps, andGroups);
			}
			// Single AND group: go straight to the group flow.
			if (andGroups.Count == 1)
			{
				var groupWraps = andGroups.Values.First();
				return await UnlockAndGroupAsync(bytes, fingerprint, groupWraps);
			}
			// Single OR wrap: fall through to the classic cascade below,
			// which handles Face ID + the one method.
		}

		byte[]? dek = TryFaceIdUnlock(fingerprint);
		if (dek is not null)
		{
			try
			{
				return BundleReader.OpenWithDek(bytes, dek);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(dek);
			}
		}

		// Passkey is offered whenever the bundle carries a passkey
		// wrap, before the YubiKey offer. A passkey-only bundle has
		// no passphrase fallback: a failed passkey attempt ends the
		// cascade (the status text already explains why). Multi-wrap
		// bundles route through the LayerPicker above, not here.
		if (BundleReader.TryGetPasskeyWrap(bytes, out BundleWrap? pkWrap) && pkWrap is not null)
		{
			BundleReader? pkReader = await UnlockWithPasskeyAsync(bytes, pkWrap);
			if (pkReader is not null)
			{
				EnrollFaceId(fingerprint, pkReader);
				return pkReader;
			}
			return null; // passkey failed; status text explains why
		}

		BundleWrap? ykWrap = null;
		// YubiKey is offered whenever the bundle carries a YubiKey wrap.
		// If this device can't do NFC, GetYubiKeyKekAsync reports it
		// loudly and the flow falls through to the passphrase.
		bool offerYubiKey = BundleReader.TryGetYubiKeyWrap(bytes, out ykWrap) && ykWrap is not null;
		if (offerYubiKey)
		{
			bool? choice = await SecurePrompt.PickUnlockMethodAsync();
			if (choice is null)
			{
				CryptographicOperations.ZeroMemory(bytes);
				return null; // user cancelled
			}
			if (choice == true && ykWrap is not null)
			{
				BundleReader? ykReader = await UnlockWithYubiKeyAsync(bytes, ykWrap);
				if (ykReader is not null)
				{
					EnrollFaceId(fingerprint, ykReader);
					return ykReader;
				}
				// NFC didn't complete — fall through to the passphrase.
			}
		}

		char[]? passphrase = await SecurePrompt.PromptAsync("Unlock bundle", "Export passphrase:");
		if (passphrase is null || passphrase.Length == 0)
		{
			if (passphrase is not null)
				Array.Clear(passphrase);
			CryptographicOperations.ZeroMemory(bytes);
			return null; // user cancelled
		}
		try
		{
			// The char[] overload zeroes the passphrase buffer itself.
			var reader = await Task.Run(() => BundleReader.OpenWithPassphrase(bytes, passphrase));
			EnrollFaceId(fingerprint, reader);
			return reader;
		}
		catch (CryptographicException)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Wrong passphrase.";
			return null;
		}
		catch (Exception ex)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
	}

	/// <summary>
	/// Layered unlock: shows the picker, then unlocks via the chosen
	/// standalone method or AND group.
	/// </summary>
	private async Task<BundleReader?> UnlockWithLayerChoiceAsync(
		byte[] bytes,
		string fingerprint,
		IReadOnlyList<BundleWrap> orWraps,
		IReadOnlyDictionary<string, IReadOnlyList<BundleWrap>> andGroups)
	{
		var choice = await Platforms.iOS.LayerPicker.PickLayerAsync(orWraps, andGroups);
		if (choice is null)
		{
			CryptographicOperations.ZeroMemory(bytes);
			return null; // user cancelled
		}

		if (choice.IsAndGroup && choice.AndWraps is not null)
		{
			return await UnlockAndGroupAsync(bytes, fingerprint, choice.AndWraps);
		}

		if (choice.OrWrap is not null)
		{
			return await UnlockSingleWrapAsync(bytes, fingerprint, choice.OrWrap);
		}

		CryptographicOperations.ZeroMemory(bytes);
		return null;
	}

	/// <summary>
	/// Unlocks via a single standalone (OR) wrap.
	/// </summary>
	private async Task<BundleReader?> UnlockSingleWrapAsync(
		byte[] bytes, string fingerprint, BundleWrap wrap)
	{
		// Face ID shortcut: if enrolled, try it first for any unlock.
		byte[]? dek = TryFaceIdUnlock(fingerprint);
		if (dek is not null)
		{
			try { return BundleReader.OpenWithDek(bytes, dek); }
			finally { CryptographicOperations.ZeroMemory(dek); }
		}

		// For a single OR wrap, use the direct open methods which handle
			// the KEK derivation internally.
		// Delegate to the existing type-specific methods. These find the
		// wrap by type, which is fine for OR wraps (each holds the full DEK).
		if (string.Equals(wrap.Type, "yubikey-hmac-sha1", StringComparison.OrdinalIgnoreCase))
		{
			var reader = await UnlockWithYubiKeyAsync(bytes, wrap);
			if (reader is not null)
				EnrollFaceId(fingerprint, reader);
			return reader;
		}

		if (string.Equals(wrap.Type, "passkey-prf", StringComparison.OrdinalIgnoreCase))
		{
			var reader = await UnlockWithPasskeyAsync(bytes, wrap);
			if (reader is not null)
				EnrollFaceId(fingerprint, reader);
			return reader;
		}

		// Default to passphrase flow.
		char[]? passphrase = await SecurePrompt.PromptAsync("Unlock bundle", "Export passphrase:");
		if (passphrase is null || passphrase.Length == 0)
		{
			if (passphrase is not null)
				Array.Clear(passphrase);
			CryptographicOperations.ZeroMemory(bytes);
			return null;
		}
		try
		{
			var reader = await Task.Run(() => BundleReader.OpenWithPassphrase(bytes, passphrase));
			EnrollFaceId(fingerprint, reader);
			return reader;
		}
		catch (CryptographicException)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Wrong passphrase.";
			return null;
		}
		catch (Exception ex)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
		// Note: OpenWithPassphrase clears the passphrase buffer.
	}

	/// <summary>
	/// AND-group unlock: walks through each method in the group, collecting
	/// KEKs, then combines the shares to reconstruct the DEK.
	/// </summary>
	private async Task<BundleReader?> UnlockAndGroupAsync(
		byte[] bytes,
		string fingerprint,
		IReadOnlyList<BundleWrap> groupWraps)
	{
		var shares = new List<(BundleWrap Wrap, byte[] Kek)>();
		try
		{
			for (int i = 0; i < groupWraps.Count; i++)
			{
				var wrap = groupWraps[i];
				StatusLabel.Text = $"Step {i + 1} of {groupWraps.Count}: " +
					Platforms.iOS.LayerPicker.DescribeWrap(wrap) + "…";
				byte[]? kek = await GetKekForWrapAsync(wrap);
				if (kek is null)
				{
					CryptographicOperations.ZeroMemory(bytes);
					StatusLabel.Text = "Unlock cancelled.";
					return null; // user cancelled
				}
				shares.Add((wrap, kek));
			}
			var reader = BundleReader.OpenWithAndShares(bytes, shares.AsReadOnly());
			EnrollFaceId(fingerprint, reader);
			StatusLabel.Text = "Bundle unlocked.";
			return reader;
		}
		catch (CryptographicException)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "One of the methods failed — check each step and try again.";
			return null;
		}
		catch (Exception ex)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
		finally
		{
			foreach (var (_, kek) in shares)
				CryptographicOperations.ZeroMemory(kek);
		}
	}

	/// <summary>
	/// Gets the KEK for a single wrap by prompting the user for that
	/// method. Returns null if the user cancels. The caller owns the
	/// returned buffer and must zero it after use.
	/// </summary>
	private async Task<byte[]?> GetKekForWrapAsync(BundleWrap wrap)
	{
		return wrap.Type switch
		{
			"passphrase" => await GetPassphraseKekAsync(wrap),
			"yubikey-hmac-sha1" => await GetYubiKeyKekAsync(wrap),
			"passkey-prf" => await GetPasskeyKekAsync(wrap),
			_ => null, // unsupported method
		};
	}

	private async Task<byte[]?> GetPassphraseKekAsync(BundleWrap wrap)
	{
		char[]? passphrase = await SecurePrompt.PromptAsync(
			"Unlock bundle", "Export passphrase:");
		if (passphrase is null || passphrase.Length == 0)
		{
			if (passphrase is not null)
				Array.Clear(passphrase);
			return null; // user cancelled
		}
		try
		{
			return await Task.Run(() => BundleReader.DerivePassphraseKek(wrap, passphrase));
		}
		catch
		{
			return null;
		}
		// Note: DerivePassphraseKek clears the passphrase buffer.
	}

	private async Task<byte[]?> GetYubiKeyKekAsync(BundleWrap wrap)
	{
		if (!NfcYubiKey.IsAvailable())
		{
			StatusLabel.Text = "YubiKey NFC is not available on this device.";
			return null;
		}
		int slot = wrap.Slot ?? 2;
		byte[] challenge;
		try
		{
			challenge = Convert.FromBase64String(wrap.ChallengeB64
				?? throw new InvalidDataException("YubiKey wrap is missing its challenge."));
		}
		catch
		{
			StatusLabel.Text = "YubiKey wrap is missing its challenge.";
			return null;
		}
		try
		{
			var result = await NfcYubiKey.GetKekAsync(slot, challenge);
			if (result.Kek is null)
			{
				StatusLabel.Text = result.Error ?? "YubiKey didn't respond. Try again.";
				return null;
			}
			// GetKekAsync returns the derived KEK directly.
			return result.Kek;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "YubiKey failed: " + ex.Message;
			return null;
		}
	}

	private async Task<byte[]?> GetPasskeyKekAsync(BundleWrap wrap)
	{
		if (!PasskeyPrf.IsAvailable())
		{
			StatusLabel.Text = "Passkeys need iOS 18 or later on this device.";
			return null;
		}
		if (wrap.RpId is not null &&
			!string.Equals(wrap.RpId, PasskeyPrf.RelyingPartyId, StringComparison.OrdinalIgnoreCase))
		{
			StatusLabel.Text = "This bundle's passkey belongs to a different domain.";
			return null;
		}
		byte[] prfSalt;
		byte[] credentialId;
		try
		{
			prfSalt = Convert.FromBase64String(wrap.PrfSaltB64
				?? throw new InvalidDataException("Passkey wrap is missing its PRF salt."));
			credentialId = Convert.FromBase64String(wrap.CredentialIdB64
				?? throw new InvalidDataException("Passkey wrap is missing its credential ID."));
		}
		catch
		{
			StatusLabel.Text = "Passkey wrap is missing its salt or credential ID.";
			return null;
		}
		try
		{
			PasskeyPrf.EvaluateResult result = await PasskeyPrf.EvaluatePrfAsync(credentialId, prfSalt);
			if (result.Cancelled)
				return null; // user cancelled
			if (result.PrfOutput is null)
			{
				StatusLabel.Text = result.Error ?? "Passkey didn't respond. Try again.";
				return null;
			}
			try
			{
				// EvaluatePrfAsync returns the derived KEK's input;
				// derive the KEK and zero the PRF output immediately.
				return PasskeyKek.Derive(result.PrfOutput);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(result.PrfOutput);
			}
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Passkey failed: " + ex.Message;
			return null;
		}
	}

	/// <summary>
	/// YubiKey path: NFC challenge-response against the wrap's slot and
	/// challenge, KEK per DESIGN.md §3.2, open the bundle. Returns null
	/// when the scan is cancelled or the key doesn't answer (status text
	/// explains why); the caller then falls back to the passphrase.
	/// </summary>
	private async Task<BundleReader?> UnlockWithYubiKeyAsync(byte[] bytes, BundleWrap ykWrap)
	{
		int slot = ykWrap.Slot ?? 2;
		byte[] challenge;
		try
		{
			challenge = Convert.FromBase64String(ykWrap.ChallengeB64 ??
				throw new InvalidDataException("YubiKey wrap is missing its challenge."));
		}
		catch (Exception ex) when (ex is InvalidDataException || ex is FormatException)
		{
			StatusLabel.Text = "YubiKey wrap is missing its challenge.";
			return null;
		}

		NfcYubiKey.Result result;
		try
		{
			result = await NfcYubiKey.GetKekAsync(slot, challenge);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(challenge);
		}
		if (result.Kek is null)
		{
			StatusLabel.Text = result.Error ?? "YubiKey scan cancelled.";
			return null;
		}
		try
		{
			byte[] kek = result.Kek;
			try
			{
				return await Task.Run(() => BundleReader.OpenWithYubiKey(bytes, kek));
			}
			finally
			{
				CryptographicOperations.ZeroMemory(kek);
			}
		}
		catch (CryptographicException)
		{
			StatusLabel.Text = "This YubiKey didn't open the bundle (wrong key or slot).";
			return null;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
	}

	/// <summary>
	/// Passkey path: PRF assertion against the wrap's credential ID
	/// and salt, KEK per PasskeyKek, open the bundle. Returns null
	/// when the ceremony is cancelled or the passkey doesn't answer
	/// (status text explains why). Mirrors UnlockWithYubiKeyAsync.
	/// </summary>
	private async Task<BundleReader?> UnlockWithPasskeyAsync(byte[] bytes, BundleWrap pkWrap)
	{
		byte[]? kek = await GetPasskeyKekAsync(pkWrap);
		if (kek is null)
			return null; // cancelled or failed; status text explains why
		try
		{
			try
			{
				return await Task.Run(() => BundleReader.OpenWithPasskey(bytes, kek));
			}
			finally
			{
				CryptographicOperations.ZeroMemory(kek);
			}
		}
		catch (CryptographicException)
		{
			StatusLabel.Text = "This passkey didn't open the bundle.";
			return null;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
	}
#endif

	
#if IOS
	/// <summary>
	/// Face ID path: read the enrolled DEK out of the Keychain (iOS prompts
	/// for Face ID on the read). Returns null when the bundle was never
	/// enrolled, biometrics are unavailable, or the user cancels — the
	/// caller then falls back to the passphrase. A stale enrollment
	/// (biometrics changed since) is dropped so the next open re-enrolls.
	/// </summary>
	private static byte[]? TryFaceIdUnlock(string fingerprint)
	{
		if (!BiometricKeychain.CanUseBiometrics() || !BiometricKeychain.IsEnrolled(fingerprint))
			return null;
		byte[]? dek = BiometricKeychain.TryReadDek(fingerprint);
		if (dek is null)
		{
			BiometricKeychain.DeleteDek(fingerprint);
			BiometricKeychain.UnmarkEnrolled(fingerprint);
		}
		return dek;
	}

	/// <summary>
	/// Stores this bundle's DEK in the Keychain under a biometric access
	/// control so the next open can use Face ID. Silent no-op when the
	/// device can't do biometrics (simulator).
	/// </summary>
	private static void EnrollFaceId(string fingerprint, BundleReader reader)
	{
		if (!BiometricKeychain.CanUseBiometrics())
			return;
		byte[] dek = reader.GetDekCopy();
		try
		{
			if (BiometricKeychain.StoreDek(fingerprint, dek))
				BiometricKeychain.MarkEnrolled(fingerprint);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(dek);
		}
	}
#endif

#if IOS
	/// <summary>
	/// Rebuilds the visible file list from the reader plus pending
	/// modifications (added/updated/deleted). The bundle itself is
	/// untouched until Save.
	/// </summary>
	private void RefreshFileList()
	{
		if (!SessionManager.Instance.IsOpen)
		{
			FilesView.ItemsSource = null;
			return;
		}
		var reader = SessionManager.Instance.Reader;
		var list = new List<BundleFileEntry>();
		foreach (var f in reader.Files)
		{
			if (_deleted.Contains(f.Path))
				continue;
			list.Add(f);
		}
		// Added files aren't in the reader yet; show placeholders.
		foreach (var path in _modified.Keys)
		{
			if (!list.Any(f => f.Path == path))
				list.Add(new BundleFileEntry { Path = path, Size = _modified[path].Length, ModifiedUtc = DateTimeOffset.UtcNow });
		}
		FilesView.ItemsSource = list;
		var reader2 = SessionManager.Instance.Reader;
		StatusLabel.Text = $"{list.Count} file(s)" +
			(reader2.RequiresTotp ? " — TOTP required (slice 5)" : "") +
			(IsDirty ? " • modified" : "");
	}

	private bool IsDirty => _modified.Count > 0 || _deleted.Count > 0 || _pendingWraps.Count > 0;

	private void UpdateDirtyUi()
	{
		SaveButton.IsVisible = IsDirty && !_isReadOnly;
		UploadButton.IsVisible = SessionManager.Instance.IsOpen && !_isReadOnly;
		AddFileButton.IsVisible = SessionManager.Instance.IsOpen;
	}
#endif

	private void OnFileSelected(object? sender, SelectionChangedEventArgs e)
	{
		if (!SessionManager.Instance.IsOpen ||
			e.CurrentSelection.FirstOrDefault() is not BundleFileEntry entry)
			return;
		SessionManager.Instance.Touch();
#if IOS
		// Resolve plaintext: modified version wins, else decrypt.
		byte[] plaintext;
		if (_modified.TryGetValue(entry.Path, out byte[]? mod))
		{
			plaintext = (byte[])mod.Clone();
		}
		else
		{
			try
			{
				plaintext = SessionManager.Instance.Reader.OpenFile(entry);
			}
			catch (Exception ex)
			{
				PreviewContainer.Content = new Label { Text = "Couldn't decrypt file: " + ex.Message };
				FilesView.SelectedItem = null;
				return;
			}
		}
		try
		{
			SetPreview(entry.Path, plaintext);
		}
		finally
		{
			// Text editor keeps its own copy; others are done with it.
			if (!IsTextExtension(Path.GetExtension(entry.Path).ToLowerInvariant()))
				CryptographicOperations.ZeroMemory(plaintext);
		}
#else
		PreviewContainer.Content = new Label { Text = "Preview needs iOS." };
#endif
		FilesView.SelectedItem = null;
	}

#if IOS
	private static bool IsTextExtension(string ext) => ext is
		".txt" or ".md" or ".json" or ".xml" or ".csv" or ".log" or ".yaml" or ".yml";

	/// <summary>
	/// Routes a decrypted file to its renderer. Text files open in an
	/// editable view (the secure workspace); everything else previews.
	/// </summary>
	private void SetPreview(string path, byte[] plaintext)
	{
		_audioPlayer?.Dispose();
		_audioPlayer = null;
		_editingPath = null;
		_textEditor = null;

		var ext = Path.GetExtension(path).ToLowerInvariant();
		var fileName = Path.GetFileName(path);

		// Header card with file name + actions
		var header = new HorizontalStackLayout { Spacing = 8 };
		var title = new Label { Text = fileName, FontAttributes = FontAttributes.Bold, VerticalOptions = LayoutOptions.Center };
		header.Children.Add(title);
		if (!_isReadOnly)
		{
			var delete = new Button { Text = "Delete", FontSize = 13 };
			delete.Clicked += (_, _) => OnDeleteFile(path);
			header.Children.Add(delete);
		}

		View body;
		if (IsTextExtension(ext))
		{
			body = CreateTextEditor(path, plaintext);
		}
		else if (IsAudioExtension(ext))
		{
			var (audioView, player) = CreateAudioPreview(fileName, plaintext);
			_audioPlayer = player;
			body = audioView;
		}
		else
		{
			body = ext switch
			{
				".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp"
					or ".tif" or ".tiff" or ".heic" or ".heif" or ".webp" => ImageViewer.Create(plaintext),
				".pdf" => PdfViewer.Create(plaintext),
				".mp4" or ".mov" or ".m4v" => VideoViewer.Create(plaintext, VideoViewer.MimeForExtension(ext)),
				".docx" or ".xlsx" or ".pptx" or ".doc" or ".xls" or ".ppt" => CreateOfficePlaceholder(path, plaintext),
				_ => CreateHexViewer(plaintext),
			};
		}

		var card = new Frame
		{
			Content = body,
			CornerRadius = 12,
			Padding = 12,
			HasShadow = false,
			BackgroundColor = Color.FromArgb("#2b2b2b"),
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		var layout = new VerticalStackLayout { Spacing = 8 };
		layout.Children.Add(header);
		layout.Children.Add(card);
		PreviewContainer.Content = layout;
	}

	/// <summary>
	/// Read-only text view for HTTP sources (no editing).
	/// </summary>
	private static View CreateTextViewer(byte[] plaintext)
	{
		string text;
		try { text = Encoding.UTF8.GetString(plaintext); }
		catch { return CreateHexViewer(plaintext); }
		var label = new Label { Text = text, FontFamily = "Courier" };
		return new ScrollView { Content = label, VerticalOptions = LayoutOptions.FillAndExpand };
	}

	/// <summary>
	/// Editable text view. Edits stay in memory; Save stages them for the
	/// next bundle rebuild (the veil: re-encrypted with the session DEK).
	/// </summary>
	private View CreateTextEditor(string path, byte[] plaintext)
	{
		string text;
		try { text = Encoding.UTF8.GetString(plaintext); }
		catch { text = "(not valid UTF-8 — showing hex)"; return CreateHexViewer(plaintext); }

		_editingPath = path;
		_textEditorOriginal = text;
		var editor = new Editor
		{
			Text = text,
			FontFamily = "Courier",
			VerticalOptions = LayoutOptions.FillAndExpand,
			AutoSize = EditorAutoSizeOption.Disabled,
		};
		_textEditor = editor;

		var save = new Button { Text = "Save changes", IsVisible = false };
		var cancel = new Button { Text = "Discard", IsVisible = false };
		editor.TextChanged += (_, _) =>
		{
			bool dirty = editor.Text != _textEditorOriginal;
			save.IsVisible = dirty;
			cancel.IsVisible = dirty;
		};
		save.Clicked += (_, _) =>
		{
			byte[] newBytes = Encoding.UTF8.GetBytes(editor.Text ?? "");
			// Zero the old modified buffer if replacing.
			if (_modified.TryGetValue(path, out byte[]? old))
				CryptographicOperations.ZeroMemory(old);
			_modified[path] = newBytes;
			_textEditorOriginal = editor.Text;
			save.IsVisible = false;
			cancel.IsVisible = false;
			RefreshFileList();
			UpdateDirtyUi();
			StatusLabel.Text = "Staged — tap Save bundle to write.";
		};
		cancel.Clicked += (_, _) =>
		{
			editor.Text = _textEditorOriginal;
		};

		var buttons = new HorizontalStackLayout { Spacing = 8 };
		buttons.Children.Add(save);
		buttons.Children.Add(cancel);

		var layout = new VerticalStackLayout { Spacing = 8 };
		var scroll = new ScrollView
		{
			Content = editor,
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		layout.Children.Add(scroll);
		layout.Children.Add(buttons);
		return layout;
	}

	/// <summary>
	/// Hex viewer: offset gutter, hex bytes, ASCII sidebar. Monospace,
	/// scrollable, in the card style.
	/// </summary>
	private static View CreateHexViewer(byte[] plaintext)
	{
		const int perRow = 16;
		const int cap = 64 * 1024; // 64KB cap
		int len = Math.Min(plaintext.Length, cap);
		var sb = new StringBuilder();
		for (int i = 0; i < len; i += perRow)
		{
			sb.Append($"{i:X8}  ");
			int rowLen = Math.Min(perRow, len - i);
			for (int j = 0; j < perRow; j++)
			{
				if (j < rowLen)
					sb.Append($"{plaintext[i + j]:X2} ");
				else
					sb.Append("   ");
				if (j == 7) sb.Append(' ');
			}
			sb.Append(" |");
			for (int j = 0; j < rowLen; j++)
			{
				char c = (char)plaintext[i + j];
				sb.Append(char.IsControl(c) ? '.' : c);
			}
			sb.AppendLine("|");
		}
		if (plaintext.Length > cap)
			sb.AppendLine($"… ({plaintext.Length - cap:N0} more bytes, capped at 64KB)");

		var label = new Label
		{
			Text = sb.ToString(),
			FontFamily = "Courier",
			FontSize = 12,
		};
		return new ScrollView
		{
			Content = label,
			VerticalOptions = LayoutOptions.FillAndExpand,
			Orientation = ScrollOrientation.Both,
		};
	}

	private void OnDeleteFile(string path)
	{
		if (!SessionManager.Instance.IsOpen || _isReadOnly)
			return;
		SessionManager.Instance.Touch();
		_deleted.Add(path);
		if (_modified.TryGetValue(path, out byte[]? old))
		{
			CryptographicOperations.ZeroMemory(old);
			_modified.Remove(path);
		}
		if (_editingPath == path)
		{
			_editingPath = null;
			_textEditor = null;
		}
		RefreshFileList();
		UpdateDirtyUi();
		PreviewContainer.Content = new Label
		{
			Text = "File staged for deletion — tap Save bundle to write.",
			HorizontalOptions = LayoutOptions.Center,
			VerticalOptions = LayoutOptions.Center,
		};
	}

	private async void OnAddFileClicked(object? sender, EventArgs e)
	{
		if (!SessionManager.Instance.IsOpen)
			return;
		if (_isReadOnly)
		{
			StatusLabel.Text = "This bundle is read-only.";
			StatusLabel.TextColor = StatusColor("StatusWarn", "#F7B955");
			return;
		}
		SessionManager.Instance.Touch();
		string choice = await DisplayActionSheet("Add file", "Cancel", null, "Photo", "Video", "File");
		if (string.IsNullOrEmpty(choice) || choice == "Cancel")
			return;
		StatusLabel.Text = "Choose a file to add…";
		byte[]? bytes;
		string? name;
		try
		{
			if (choice == "Photo" || choice == "Video")
				(bytes, name) = await PickMediaAsync(choice == "Photo");
			else
				(bytes, name) = await BundleOpener.PickImportFileAsync();
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Import failed: " + ex.Message;
			return;
		}
		if (bytes is null || name is null)
			return; // cancelled
		if (_modified.TryGetValue(name, out byte[]? old))
			CryptographicOperations.ZeroMemory(old);
		_modified[name] = bytes; // ownership transferred
		_deleted.Remove(name);
		RefreshFileList();
		UpdateDirtyUi();
		StatusLabel.Text = $"Staged {name} — tap Save bundle to write.";
	}

	/// <summary>
	/// Picks a single photo or video from the photo library via MAUI
	/// MediaPicker (PHPicker-backed on iOS: no permission prompt, no
	/// Info.plist usage description needed). Returns (bytes, filename),
	/// or (null, null) if the user cancelled. MediaPicker is single-pick
	/// only — one photo or one video per Add action.
	/// </summary>
	private static async Task<(byte[]? Bytes, string? Name)> PickMediaAsync(bool photo)
	{
		FileResult? result = photo
			? await Microsoft.Maui.Media.MediaPicker.Default.PickPhotoAsync()
			: await Microsoft.Maui.Media.MediaPicker.Default.PickVideoAsync();
		if (result is null)
			return (null, null);
		string name = string.IsNullOrWhiteSpace(result.FileName)
			? (photo ? "photo.jpg" : "video.mov")
			: result.FileName;
		using Stream stream = await result.OpenReadAsync();
		using var ms = new MemoryStream();
		await stream.CopyToAsync(ms);
		return (ms.ToArray(), name);
	}

	/// <summary>
	/// Rebuilds the bundle with all staged changes and writes it back to
	/// the source (Files URL or HTTP PUT). The new bytes are fully
	/// re-encrypted — the veil holds.
	/// </summary>
	private async void OnSaveClicked(object? sender, EventArgs e)
	{
		if (!SessionManager.Instance.IsOpen || !IsDirty || _isReadOnly)
			return;
		SessionManager.Instance.Touch();
		var reader = SessionManager.Instance.Reader;

		StatusLabel.Text = "Rebuilding bundle…";
		byte[] newBundle;
		try
		{
			newBundle = await Task.Run(() =>
			{
				byte[] dek = reader.GetDekCopy();
				try
				{
					var files = new List<(string Path, byte[] Plaintext)>();
					foreach (var entry in reader.Files)
					{
						if (_deleted.Contains(entry.Path))
							continue;
						if (_modified.TryGetValue(entry.Path, out byte[]? mod))
							files.Add((entry.Path, mod));
						else
							files.Add((entry.Path, reader.OpenFile(entry)));
					}
					foreach (var kv in _modified)
					{
						if (!files.Any(f => f.Path == kv.Key))
							files.Add((kv.Key, kv.Value));
					}
					var header = reader.GetHeaderSnapshot();
					header.Wraps.AddRange(_pendingWraps);
					byte[] built = BundleWriter.Rebuild(header, dek, files);
					// Zero decrypted buffers we allocated (modified stay staged until cleared below).
					foreach (var f in files)
					{
						if (!_modified.ContainsKey(f.Path))
							CryptographicOperations.ZeroMemory(f.Plaintext);
					}
					return built;
				}
				finally
				{
					CryptographicOperations.ZeroMemory(dek);
				}
			});
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Rebuild failed: " + ex.Message;
			return;
		}

		// Write back.
		bool wroteToKnownSource = false;
		try
		{
			if (_sourceFileUrl is not null)
			{
				bool ok = BundleOpener.WriteBack(_sourceFileUrl, newBundle);
				StatusLabel.Text = ok ? "Saved." : "Couldn't write back to the file.";
				wroteToKnownSource = ok;
			}
			else if (_sourceHttpUrl is not null)
			{
				using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
				using var resp = await http.PutAsync(_sourceHttpUrl, new ByteArrayContent(newBundle));
				StatusLabel.Text = resp.IsSuccessStatusCode ? "Uploaded." : $"Upload failed: {(int)resp.StatusCode}.";
				wroteToKnownSource = resp.IsSuccessStatusCode;
			}
			else if (_isNewBundle)
			{
				// New bundle: let the user pick where to save it.
				bool saved = await BundleOpener.ExportBundleAsync(newBundle);
				if (saved)
				{
					StatusLabel.Text = "Saved.";
					_isNewBundle = false;
				}
				else
				{
					StatusLabel.Text = "Save cancelled.";
					return;
				}
			}
			else
			{
				StatusLabel.Text = "No destination — use Upload to send it somewhere.";
				return;
			}
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Write failed: " + ex.Message;
			return;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(newBundle);
		}

		// Clear staged state; re-open the new bytes so the veil continues.
		foreach (var kv in _modified)
			CryptographicOperations.ZeroMemory(kv.Value);
		_modified.Clear();
		_deleted.Clear();
		_pendingWraps.Clear();
		_isNewBundle = false;
		_editingPath = null;
		RefreshFileList();
		UpdateDirtyUi();
		// A save back to a known source refreshes the vault row (count/date).
		// A share-sheet export reports no destination, so it can't be recorded.
		if (wroteToKnownSource)
			RecordCurrentBundle();
	}

	private async void OnUploadClicked(object? sender, EventArgs e)
	{
		if (!SessionManager.Instance.IsOpen)
			return;
		SessionManager.Instance.Touch();
		string? url = await DisplayPromptAsync("Upload bundle", "HTTPS URL to PUT the encrypted bundle to:",
			initialValue: _sourceHttpUrl ?? "");
		if (string.IsNullOrWhiteSpace(url))
			return;
		url = url.Trim();

		// Build current bytes (with staged changes if any).
		byte[] bundleBytes;
		var reader = SessionManager.Instance.Reader;
		try
		{
			bundleBytes = await Task.Run(() =>
			{
				if (!IsDirty)
				{
					// No changes: upload the original bytes. We don't keep them;
					// rebuild from the reader (identical output for unmodified files).
					byte[] dek = reader.GetDekCopy();
					try
					{
						var files = new List<(string Path, byte[] Plaintext)>();
						foreach (var entry in reader.Files)
							files.Add((entry.Path, reader.OpenFile(entry)));
						var h1 = reader.GetHeaderSnapshot(); h1.Wraps.AddRange(_pendingWraps);
						byte[] built = BundleWriter.Rebuild(h1, dek, files);
						foreach (var f in files)
							CryptographicOperations.ZeroMemory(f.Plaintext);
						return built;
					}
					finally { CryptographicOperations.ZeroMemory(dek); }
				}
				// Has staged changes: same path as Save.
				byte[] dek2 = reader.GetDekCopy();
				try
				{
					var files = new List<(string Path, byte[] Plaintext)>();
					foreach (var entry in reader.Files)
					{
						if (_deleted.Contains(entry.Path))
							continue;
						files.Add(_modified.TryGetValue(entry.Path, out byte[]? mod)
							? (entry.Path, mod)
							: (entry.Path, reader.OpenFile(entry)));
					}
					foreach (var kv in _modified)
						if (!files.Any(f => f.Path == kv.Key))
							files.Add((kv.Key, kv.Value));
					var h2 = reader.GetHeaderSnapshot(); h2.Wraps.AddRange(_pendingWraps);
					byte[] built = BundleWriter.Rebuild(h2, dek2, files);
					foreach (var f in files)
						if (!_modified.ContainsKey(f.Path))
							CryptographicOperations.ZeroMemory(f.Plaintext);
					return built;
				}
				finally { CryptographicOperations.ZeroMemory(dek2); }
			});
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Build failed: " + ex.Message;
			return;
		}

		try
		{
			using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
			using var resp = await http.PutAsync(url, new ByteArrayContent(bundleBytes));
			StatusLabel.Text = resp.IsSuccessStatusCode ? "Uploaded." : $"Upload failed: {(int)resp.StatusCode}.";
			StatusLabel.TextColor = StatusColor(resp.IsSuccessStatusCode ? "StatusOk" : "StatusError", resp.IsSuccessStatusCode ? "#6CCB5F" : "#F1707B");
			if (resp.IsSuccessStatusCode)
				_sourceHttpUrl = url;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Upload failed: " + ex.Message;
			StatusLabel.TextColor = StatusColor("StatusError", "#F1707B");
		}
		finally
		{
			CryptographicOperations.ZeroMemory(bundleBytes);
		}
	}

	private static bool IsAudioExtension(string ext) => ext is
		".mp3" or ".m4a" or ".wav" or ".caf" or ".aac" or ".aiff";

	private static (View View, AudioPlayer Player) CreateAudioPreview(string fileName, byte[] audioData)
	{
		// Cloned: playback is deferred to the Play tap, after the caller zeroes its buffer.
		var copy = (byte[])audioData.Clone();
		var player = new AudioPlayer();
		var status = new Label { Text = fileName, HorizontalOptions = LayoutOptions.Center };
		var play = new Button { Text = "Play" };
		var stop = new Button { Text = "Stop" };
		play.Clicked += (_, _) =>
		{
			if (!player.Play(copy))
				status.Text = "Couldn't play this audio.";
		};
		stop.Clicked += (_, _) => player.Stop();

		var card = new Frame
		{
			CornerRadius = 12,
			Padding = 16,
			HasShadow = false,
			BackgroundColor = Color.FromArgb("#2b2b2b"),
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		var buttons = new HorizontalStackLayout { Spacing = 12, HorizontalOptions = LayoutOptions.Center };
		buttons.Children.Add(play);
		buttons.Children.Add(stop);
		var layout = new VerticalStackLayout { Spacing = 12, VerticalOptions = LayoutOptions.Center };
		layout.Children.Add(status);
		layout.Children.Add(buttons);
		card.Content = layout;
		return (card, player);
	}

	private static View CreateOfficePlaceholder(string path, byte[] plaintext)
	{
		// Cloned: export is deferred to the Export tap, after the caller zeroes its buffer.
		var copy = (byte[])plaintext.Clone();
		var fileName = Path.GetFileName(path);
		var ext = Path.GetExtension(path).ToLowerInvariant();

		var info = new Label
		{
			Text = $"{fileName}\n{plaintext.Length:N0} bytes\n\nThis file type can't be previewed in the app. Export it to open elsewhere.",
			HorizontalOptions = LayoutOptions.Center,
			HorizontalTextAlignment = TextAlignment.Center,
		};
		var export = new Button { Text = "Export…", HorizontalOptions = LayoutOptions.Center };
		export.Clicked += (_, _) => ShareService.Export(fileName, copy, ShareService.UtiForExtension(ext));

		var card = new Frame
		{
			CornerRadius = 12,
			Padding = 16,
			HasShadow = false,
			BackgroundColor = Color.FromArgb("#2b2b2b"),
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		var layout = new VerticalStackLayout { Spacing = 16, VerticalOptions = LayoutOptions.Center };
		layout.Children.Add(info);
		layout.Children.Add(export);
		card.Content = layout;
		return card;
	}
#endif

	private static string CreateTextOrHexPreview(byte[] plaintext)
	{
		try
		{
			var preview = Encoding.UTF8.GetString(plaintext);
			if (preview.Any(char.IsControl) && !preview.Any(c => c is '\r' or '\n' or '\t'))
				throw new DecoderFallbackException();
			if (preview.Length > 2000)
				preview = preview[..2000] + "…";
			return preview;
		}
		catch
		{
			return "Binary file — " + plaintext.Length + " bytes. " +
				"First bytes: " + Convert.ToHexString(plaintext, 0, Math.Min(32, plaintext.Length));
		}
	}

	private void ResetPreviewUi()
	{
		FilesView.ItemsSource = null;
#if IOS
		_audioPlayer?.Dispose();
		_audioPlayer = null;
		_sourceFileUrl = null;
		_sourceHttpUrl = null;
		foreach (var kv in _modified)
			CryptographicOperations.ZeroMemory(kv.Value);
		_modified.Clear();
		_deleted.Clear();
		_pendingWraps.Clear();
		_isNewBundle = false;
		_editingPath = null;
		_textEditor = null;
		_currentBadgeMethod = "Layered";
		_currentBookmarkB64 = "";
#endif
		PreviewContainer.Content = new Label { Text = "Select a file to preview.", HorizontalOptions = LayoutOptions.Center, VerticalOptions = LayoutOptions.Center };
		StatusLabel.Text = "No bundle open.";
		StatusLabel.TextColor = StatusColor("TextSecondary", "#A7A7A7");
#if IOS
		UpdateDirtyUi();
#endif
	}

	private void CloseReader()
	{
		SessionManager.Instance.Lock();
		ResetPreviewUi();
		ShowVault();
	}

	/// <summary>
	/// Vault view switching: exactly one of the four views is visible.
	/// </summary>
	private void ShowVault()
	{
		VaultView.IsVisible = true;
		BundleView.IsVisible = false;
		ActivityView.IsVisible = false;
		SettingsView.IsVisible = false;
		LoadRecents(VaultSearchBar.Text);
		SetActiveTab(VaultTabButton);
		SyncVaultStatus();
	}

	private void ShowBundle()
	{
		VaultView.IsVisible = false;
		BundleView.IsVisible = true;
		ActivityView.IsVisible = false;
		SettingsView.IsVisible = false;
		SetActiveTab(VaultTabButton);
	}

	private void ShowActivity()
	{
		VaultView.IsVisible = false;
		BundleView.IsVisible = false;
		ActivityView.IsVisible = true;
		SettingsView.IsVisible = false;
		SetActiveTab(ActivityTabButton);
	}

	private void ShowSettings()
	{
		VaultView.IsVisible = false;
		BundleView.IsVisible = false;
		ActivityView.IsVisible = false;
		SettingsView.IsVisible = true;
		SetActiveTab(SettingsTabButton);
	}

	private void SetActiveTab(Button active)
	{
		foreach (var button in new[] { VaultTabButton, ActivityTabButton, NewTabButton, SettingsTabButton })
		{
			bool isActive = button == active;
			// Windows dark parity: the active nav item is brand blue text
			// on the #2d2d2d active-nav background; inactive items are
			// secondary text on transparent.
			button.TextColor = isActive ? Color.FromArgb("#0067C0") : Color.FromArgb("#A7A7A7");
			button.BackgroundColor = isActive ? Color.FromArgb("#2D2D2D") : Colors.Transparent;
			button.FontAttributes = isActive ? FontAttributes.Bold : FontAttributes.None;
		}
	}

	/// <summary>
	/// The bundle view's status is the vault's status while the vault is
	/// showing (e.g. an unlock failure after tapping a row) — text and color.
	/// </summary>
	private void SyncVaultStatus()
	{
		VaultStatusLabel.Text = StatusLabel.Text;
		VaultStatusLabel.TextColor = StatusLabel.TextColor;
	}

	/// <summary>
	/// Windows dark status colors (App.xaml StatusOk/StatusError/StatusWarn),
	/// with the matching hex as fallback. Never used for method badges —
	/// those keep the red/blue/purple color-wheel scheme.
	/// </summary>
	private static Color StatusColor(string key, string fallback)
	{
		if (Application.Current?.Resources.TryGetValue(key, out object? value) == true &&
			value is Color color)
		{
			return color;
		}
		return Color.FromArgb(fallback);
	}

	private void LoadRecents(string? filter = null)
	{
		var recents = RecentBundleStore.Load();
		VaultSubtitleLabel.Text = recents.Count == 1
			? "1 bundle · Encrypted & offline"
			: $"{recents.Count} bundles · Encrypted & offline";
		if (!string.IsNullOrWhiteSpace(filter))
		{
			string f = filter.Trim();
			recents = recents
				.Where(r => r.Name.Contains(f, StringComparison.OrdinalIgnoreCase))
				.ToList();
		}
		VaultListView.ItemsSource = recents;
	}

	private void OnSearchTextChanged(object? sender, TextChangedEventArgs e)
	{
		LoadRecents(e.NewTextValue);
	}

	/// <summary>
	/// Leaving an open bundle for another tab discards staged changes, so
	/// confirm first when dirty. Returns false when the user stays.
	/// </summary>
	private async Task<bool> ConfirmLeaveBundleAsync()
	{
		if (!BundleView.IsVisible)
			return true;
#if IOS
		if (IsDirty)
		{
			return await DisplayAlert("Discard changes?",
				"You have unsaved changes. Leave this bundle and discard them?",
				"Discard", "Stay");
		}
#endif
		return true;
	}

	private async void OnVaultTabClicked(object? sender, EventArgs e)
	{
		if (!BundleView.IsVisible)
		{
			ShowVault();
			return;
		}
		if (!await ConfirmLeaveBundleAsync())
			return;
		CloseReader();
	}

	private async void OnActivityTabClicked(object? sender, EventArgs e)
	{
		if (BundleView.IsVisible)
		{
			if (!await ConfirmLeaveBundleAsync())
				return;
			CloseReader();
		}
		ShowActivity();
	}

	private async void OnSettingsTabClicked(object? sender, EventArgs e)
	{
		if (BundleView.IsVisible)
		{
			if (!await ConfirmLeaveBundleAsync())
				return;
			CloseReader();
		}
		ShowSettings();
	}

#if IOS
	/// <summary>
	/// Vault row tap: reopen through the existing open path. HTTP rows
	/// re-download; Files rows resolve their security-scoped bookmark
	/// (or fall back to the stored path) and open the bytes.
	/// </summary>
	private async void OnRecentSelected(object? sender, SelectionChangedEventArgs e)
	{
		if (e.CurrentSelection.FirstOrDefault() is not RecentBundle recent)
			return;
		VaultListView.SelectedItem = null;
		await OpenRecentAsync(recent);
	}

	private async Task OpenRecentAsync(RecentBundle recent)
	{
		CloseReader();
		if (recent.IsHttp)
		{
			await DownloadAndOpenAsync(recent.Source);
			return;
		}

		byte[]? bytes = null;
		NSUrl? url = ResolveBookmark(recent.BookmarkB64);
		if (url is null && !string.IsNullOrEmpty(recent.Source))
			url = NSUrl.FromFilename(recent.Source);
		if (url is not null)
		{
			try
			{
				bool scoped = url.StartAccessingSecurityScopedResource();
				try
				{
					using NSData? data = NSData.FromUrl(url);
					bytes = data?.ToArray();
				}
				finally
				{
					if (scoped)
						url.StopAccessingSecurityScopedResource();
				}
			}
			catch
			{
				bytes = null;
			}
		}
		if (bytes is null || bytes.Length == 0)
		{
			// Access expired (bookmark stale, file moved): fall back to
			// the picker — the existing open path — instead of faking it.
			VaultStatusLabel.Text = "Can't reopen that file — access expired. Pick it again.";
			VaultStatusLabel.TextColor = StatusColor("StatusError", "#F1707B");
			await OpenFromPickerAsync();
			return;
		}

		_sourceFileUrl = url;
		_sourceHttpUrl = null;
		// SMB shares (via Files) are editable only if the user has write permission.
		_isReadOnly = !IsUrlWritable(_sourceFileUrl);
		await OpenBundleBytesAsync(bytes);
	}

	/// <summary>
	/// The Files picker path, shared by the Open bundle button and by
	/// vault rows whose stored access expired.
	/// </summary>
	private async Task OpenFromPickerAsync()
	{
		byte[]? bytes;
		try
		{
			bytes = await BundleOpener.PickBundleAsync();
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Picker failed: " + ex.Message;
			StatusLabel.TextColor = StatusColor("StatusError", "#F1707B");
			SyncVaultStatus();
			return;
		}
		if (bytes is null)
			return; // user cancelled

		_sourceFileUrl = BundleOpener.LastPickedUrl;
		_sourceHttpUrl = null;
		// SMB shares (via Files) are editable only if the user has write permission.
		_isReadOnly = !IsUrlWritable(_sourceFileUrl);
		await OpenBundleBytesAsync(bytes);
	}

	/// <summary>
	/// The HTTP download path, shared by the From URL button and by
	/// vault rows for HTTP bundles (HTTP sources are read-only).
	/// </summary>
	private async Task DownloadAndOpenAsync(string url)
	{
		StatusLabel.Text = "Downloading…";
		SyncVaultStatus();
		byte[] bytes;
		try
		{
			using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
			bytes = await http.GetByteArrayAsync(url);
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Download failed: " + ex.Message;
			StatusLabel.TextColor = StatusColor("StatusError", "#F1707B");
			SyncVaultStatus();
			return;
		}

		_sourceFileUrl = null;
		_sourceHttpUrl = url;
		_isReadOnly = true; // HTTP sources are read-only
		await OpenBundleBytesAsync(bytes);
	}

	/// <summary>
	/// Records the currently open bundle in the vault list (newest first).
	/// No-op for unsaved new bundles: with no source there is nothing
	/// reopenable to record; they enter the list on their first save.
	/// </summary>
	private void RecordCurrentBundle()
	{
		string? name;
		string? source;
		bool isHttp;
		if (_sourceHttpUrl is not null)
		{
			isHttp = true;
			source = _sourceHttpUrl;
			name = DisplayNameFromUrl(_sourceHttpUrl);
		}
		else if (_sourceFileUrl?.Path is not null)
		{
			isHttp = false;
			source = _sourceFileUrl.Path;
			name = DisplayNameFromFile(_sourceFileUrl.LastPathComponent);
		}
		else
		{
			return;
		}
		var reader = SessionManager.Instance.Reader;
		int count = reader.Files.Count;
		DateTimeOffset modified = count > 0
			? reader.Files.Max(f => f.ModifiedUtc)
			: DateTimeOffset.UtcNow;
		RecentBundleStore.Record(new RecentBundle
		{
			Name = name,
			Source = source,
			IsHttp = isHttp,
			BookmarkB64 = _currentBookmarkB64,
			BadgeMethod = _currentBadgeMethod,
			FileCount = count,
			ModifiedUtc = modified,
		});
	}

	private static string DisplayNameFromFile(string? fileName)
	{
		if (string.IsNullOrEmpty(fileName))
			return "Bundle";
		if (fileName.EndsWith(".kfb", StringComparison.OrdinalIgnoreCase))
			fileName = fileName[..^4];
		return fileName;
	}

	private static string DisplayNameFromUrl(string url)
	{
		try
		{
			string last = url.TrimEnd('/').Split('/').Last();
			if (last.EndsWith(".kfb", StringComparison.OrdinalIgnoreCase))
				last = last[..^4];
			return string.IsNullOrEmpty(last) ? url : last;
		}
		catch
		{
			return url;
		}
	}

	/// <summary>
	/// Captures a security-scoped bookmark for a picked Files URL so the
	/// vault row can reopen it across launches. "" when it can't be made.
	/// </summary>
	private static string CreateBookmark(NSUrl? url)
	{
		if (url is null)
			return "";
		try
		{
			using NSData? data = url.CreateBookmarkData(
				NSUrlBookmarkCreationOptions.WithSecurityScope, null, null, out NSError err);
			if (data is null || err is not null)
				return "";
			return Convert.ToBase64String(data.ToArray());
		}
		catch
		{
			return "";
		}
	}

	/// <summary>
	/// Resolves a stored bookmark back to a security-scoped URL. Null
	/// when the bookmark is missing, stale, or unresolvable — the caller
	/// then falls back to the stored path and, failing that, the picker.
	/// </summary>
	private static NSUrl? ResolveBookmark(string bookmarkB64)
	{
		if (string.IsNullOrEmpty(bookmarkB64))
			return null;
		try
		{
			byte[] raw = Convert.FromBase64String(bookmarkB64);
			using var data = NSData.FromArray(raw);
			NSUrl? url = NSUrl.FromBookmarkData(data,
				NSUrlBookmarkResolutionOptions.WithSecurityScope, null,
				out bool stale, out NSError err);
			if (url is null || err is not null || stale)
				return null;
			return url;
		}
		catch
		{
			return null;
		}
	}
#endif
}
