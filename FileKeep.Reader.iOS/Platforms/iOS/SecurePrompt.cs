using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Native secure passphrase prompt. The secret is captured keystroke by
/// keystroke into a `char[]` buffer; the text field itself only ever holds
/// bullet characters, so no `NSString` with the passphrase ever exists.
/// The buffer is handed to the caller, who must use and then clear it
/// (BundleReader's `char[]` overload also clears it defensively).
///
/// This replaces MAUI's `DisplayPromptAsync`, whose returned `string`
/// cannot be wiped and which offers no secure-entry field here.
/// Honest residual: the bullet `NSString`s are not secret, and the OS
/// keyboard could in principle cache keystrokes — autocorrection and
/// autocapitalization are disabled to shrink that surface.
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

		var buffer = new List<char>();
		var alert = UIAlertController.Create(title, message, UIAlertControllerStyle.Alert);
		alert.AddTextField(tf =>
		{
			tf.AutocorrectionType = UITextAutocorrectionType.No;
			tf.AutocapitalizationType = UITextAutocapitalizationType.None;
			tf.ShouldChangeCharacters = (textField, range, replacement) =>
			{
				if (replacement.Length == 0)
				{
					// Backspace.
					if (buffer.Count > 0)
						buffer.RemoveAt(buffer.Count - 1);
				}
				else
				{
					buffer.AddRange(replacement);
				}
				// The field shows bullets only; the secret lives in `buffer`.
				textField.Text = new string('•', buffer.Count);
				return false;
			};
		});
		alert.AddAction(UIAlertAction.Create("Cancel", UIAlertActionStyle.Cancel, _ =>
		{
			buffer.Clear();
			tcs.TrySetResult(null);
		}));
		alert.AddAction(UIAlertAction.Create("Open", UIAlertActionStyle.Default, _ =>
		{
			var result = buffer.ToArray();
			buffer.Clear();
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
}
