using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Native secure passphrase prompt. Uses the platform's secure text entry
/// (bullets, no autocorrection), which handles typing, paste, and
/// autofill reliably. On Open the text is copied into a caller-owned
/// `char[]` and the field is cleared immediately; the caller must use
/// and then clear the buffer (BundleReader's `char[]` overload also
/// clears it defensively).
///
/// This replaces MAUI's `DisplayPromptAsync`, whose returned `string`
/// cannot be wiped. Honest residual: the `NSString` exists inside the
/// text field while the prompt is up, and the OS keyboard could in
/// principle cache keystrokes — autocorrection and autocapitalization
/// are disabled to shrink that surface.
/// </summary>
public static class SecurePrompt
{
	/// <summary>
	/// Shows the prompt. Returns the typed passphrase as a `char[]`, or
	/// null when the user cancels. The caller owns the buffer.
	/// </summary>
	public static Task<char[]?> PromptAsync(string title, string message)
	{
		var tcs = new TaskCompletionSource<char[]?>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		UITextField? field = null;
		var alert = UIAlertController.Create(title, message, UIAlertControllerStyle.Alert);
		alert.AddTextField(tf =>
		{
			field = tf;
			tf.SecureTextEntry = true;
			tf.AutocorrectionType = UITextAutocorrectionType.No;
			tf.AutocapitalizationType = UITextAutocapitalizationType.None;
		});
		alert.AddAction(UIAlertAction.Create("Cancel", UIAlertActionStyle.Cancel, _ =>
		{
			if (field is not null)
				field.Text = string.Empty;
			tcs.TrySetResult(null);
		}));
		alert.AddAction(UIAlertAction.Create("Open", UIAlertActionStyle.Default, _ =>
		{
			char[] result = field?.Text?.ToCharArray() ?? Array.Empty<char>();
			if (field is not null)
				field.Text = string.Empty;
			tcs.TrySetResult(result);
		}));

		// iPad requires a popover anchor or presenting an alert crashes.
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
	/// Action sheet offering the YubiKey NFC path vs. the typed passphrase.
	/// Returns true for YubiKey, false for passphrase, null when the user
	/// cancels.
	/// </summary>
	public static Task<bool?> PickUnlockMethodAsync()
	{
		var tcs = new TaskCompletionSource<bool?>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		var sheet = UIAlertController.Create(
			"Unlock bundle", "This bundle has a YubiKey wrap.", UIAlertControllerStyle.ActionSheet);
		sheet.AddAction(UIAlertAction.Create(
			"Use YubiKey", UIAlertActionStyle.Default, _ => tcs.TrySetResult(true)));
		sheet.AddAction(UIAlertAction.Create(
			"Type passphrase", UIAlertActionStyle.Default, _ => tcs.TrySetResult(false)));
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
}
