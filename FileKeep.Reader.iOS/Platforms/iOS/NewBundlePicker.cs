using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Picker for new bundle creation: which unlock methods to use,
/// and whether multiple methods are AND-linked or standalone OR.
/// </summary>
public static class NewBundlePicker
{
	/// <summary>
	/// Asks which methods to use for the new bundle. Returns the list
	/// of method types (e.g. ["passphrase", "yubikey-hmac-sha1",
	/// "passkey-prf"]), or null if the user cancels. Always returns
	/// at least one method. Passphrase and YubiKey are always offered;
	/// if this device can't do NFC, the YubiKey setup fails loudly at
	/// tap time instead of the option being silently hidden. Passkey
	/// is offered only when this device can do PRF (iOS 18+, real
	/// device) — a passkey created without PRF could never unlock, so
	/// that option is hidden instead of failing at tap time.
	/// </summary>
	public static async Task<List<string>?> PickMethodsAsync()
	{
		var methods = new List<string>();

		// Passphrase: always offered.
		bool? usePassphrase = await AskYesNoAsync(
			"New bundle", "Use a passphrase to unlock?");
		if (usePassphrase is null)
			return null; // cancelled
		if (usePassphrase == true)
			methods.Add("passphrase");

		// YubiKey: always offered. If NFC is unavailable here, the
		// tap-time setup reports it (GetKekAsync) instead of hiding
		// the option — a method the bundle supports is never hidden.
		bool? useYubiKey = await AskYesNoAsync(
			"New bundle", "Use a YubiKey to unlock?");
		if (useYubiKey is null)
			return null; // cancelled
		if (useYubiKey == true)
			methods.Add("yubikey-hmac-sha1");

		// Passkey: offered only when this device can do PRF.
		if (PasskeyPrf.IsAvailable())
		{
			bool? usePasskey = await AskYesNoAsync(
				"New bundle", "Use a passkey to unlock?");
			if (usePasskey is null)
				return null; // cancelled
			if (usePasskey == true)
				methods.Add("passkey-prf");
		}

		if (methods.Count == 0)
		{
			// User declined all methods - they must pick at least one.
			await ShowMessageAsync("New bundle", "Pick at least one unlock method.");
			return await PickMethodsAsync();
		}

		return methods;
	}

	/// <summary>
	/// Asks whether multiple methods should be AND-linked (all required)
	/// or standalone OR (any one unlocks). Returns true for AND.
	/// </summary>
	public static Task<bool?> AskAndOrAsync(int methodCount)
	{
		var tcs = new TaskCompletionSource<bool?>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		var sheet = UIAlertController.Create(
			"Link methods",
			$"You picked {methodCount} methods. Require all of them together, or is any one enough?",
			UIAlertControllerStyle.ActionSheet);
		sheet.AddAction(UIAlertAction.Create(
			"All required (AND)", UIAlertActionStyle.Default, _ => tcs.TrySetResult(true)));
		sheet.AddAction(UIAlertAction.Create(
			"Any one is enough (OR)", UIAlertActionStyle.Default, _ => tcs.TrySetResult(false)));
		sheet.AddAction(UIAlertAction.Create(
			"Cancel", UIAlertActionStyle.Cancel, _ => tcs.TrySetResult(null)));

		if (sheet.PopoverPresentationController is not null && presenter.View is not null)
		{
			sheet.PopoverPresentationController.SourceView = presenter.View;
			var b = presenter.View.Bounds;
			sheet.PopoverPresentationController.SourceRect =
				new CoreGraphics.CGRect(b.Width / 2, b.Height / 2, 0, 0);
		}

		presenter.PresentViewController(sheet, true, null);
		return tcs.Task;
	}

	private static Task<bool?> AskYesNoAsync(string title, string message)
	{
		var tcs = new TaskCompletionSource<bool?>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		var alert = UIAlertController.Create(title, message, UIAlertControllerStyle.Alert);
		alert.AddAction(UIAlertAction.Create("Yes", UIAlertActionStyle.Default,
			_ => tcs.TrySetResult(true)));
		alert.AddAction(UIAlertAction.Create("No", UIAlertActionStyle.Default,
			_ => tcs.TrySetResult(false)));
		alert.AddAction(UIAlertAction.Create("Cancel", UIAlertActionStyle.Cancel,
			_ => tcs.TrySetResult(null)));

		if (alert.PopoverPresentationController is not null && presenter.View is not null)
		{
			alert.PopoverPresentationController.SourceView = presenter.View;
			var b = presenter.View.Bounds;
			alert.PopoverPresentationController.SourceRect =
				new CoreGraphics.CGRect(b.Width / 2, b.Height / 2, 0, 0);
		}

		presenter.PresentViewController(alert, true, null);
		return tcs.Task;
	}

	private static Task ShowMessageAsync(string title, string message)
	{
		var tcs = new TaskCompletionSource<bool>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(false);
			return tcs.Task;
		}

		var alert = UIAlertController.Create(title, message, UIAlertControllerStyle.Alert);
		alert.AddAction(UIAlertAction.Create("OK", UIAlertActionStyle.Default,
			_ => tcs.TrySetResult(true)));

		if (alert.PopoverPresentationController is not null && presenter.View is not null)
		{
			alert.PopoverPresentationController.SourceView = presenter.View;
			var b = presenter.View.Bounds;
			alert.PopoverPresentationController.SourceRect =
				new CoreGraphics.CGRect(b.Width / 2, b.Height / 2, 0, 0);
		}

		presenter.PresentViewController(alert, true, null);
		return tcs.Task;
	}

	/// <summary>
	/// Prompts for a new passphrase twice and confirms they match.
	/// Returns null if the user cancels or they don't match.
	/// </summary>
	public static async Task<char[]?> PromptNewPassphraseAsync()
	{
		char[]? first = await SecurePrompt.PromptAsync("New bundle", "Enter passphrase:");
		if (first is null || first.Length == 0)
		{
			if (first is not null)
				Array.Clear(first);
			return null;
		}

		char[]? second = await SecurePrompt.PromptAsync("New bundle", "Confirm passphrase:");
		if (second is null || second.Length == 0)
		{
			Array.Clear(first);
			if (second is not null)
				Array.Clear(second);
			return null;
		}

		bool match = first.Length == second.Length;
		if (match)
		{
			for (int i = 0; i < first.Length; i++)
			{
				if (first[i] != second[i])
				{
					match = false;
					break;
				}
			}
		}
		Array.Clear(second);

		if (!match)
		{
			Array.Clear(first);
			await ShowMessageAsync("New bundle", "Passphrases don't match. Try again.");
			return await PromptNewPassphraseAsync();
		}

		return first;
	}
}
