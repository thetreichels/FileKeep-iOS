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

			// Eye toggle: show/hide the passphrase on demand.
			var eye = UIButton.FromType(UIButtonType.Custom);
			eye.Frame = new CoreGraphics.CGRect(0, 0, 32, 32);
			eye.SetImage(UIImage.GetSystemImage("eye"), UIControlState.Normal);
			eye.TintColor = UIColor.SystemGray;
			eye.TouchUpInside += (_, _) =>
			{
				// Toggling SecureTextEntry can wipe the text; save/restore it.
				string? current = tf.Text;
				tf.SecureTextEntry = !tf.SecureTextEntry;
				tf.Text = string.Empty;
				tf.Text = current;
				eye.SetImage(UIImage.GetSystemImage(
					tf.SecureTextEntry ? "eye" : "eye.slash"), UIControlState.Normal);
			};
			tf.RightView = eye;
			tf.RightViewMode = UITextFieldViewMode.Always;
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

/// <summary>
/// A user's choice in the layered unlock picker. Either a standalone
/// OR wrap (unlocks alone) or an AND group (all wraps required together).
/// </summary>
public sealed record LayerChoice
{
	/// <summary>Set when the user picked a standalone OR method.</summary>
	public FileKeep.Reader.iOS.Core.Bundle.BundleWrap? OrWrap { get; init; }

	/// <summary>Set when the user picked an AND group.</summary>
	public string? AndGroupKey { get; init; }

	/// <summary>The wraps in the chosen AND group (null for OR choices).</summary>
	public IReadOnlyList<FileKeep.Reader.iOS.Core.Bundle.BundleWrap>? AndWraps { get; init; }

	public bool IsAndGroup => AndGroupKey is not null;
}

public static class LayerPicker
{
	/// <summary>
	/// Shows the layered unlock picker. OR wraps appear as individual
	/// options ("alone is enough"); AND groups appear as a single option
	/// labeled with how many methods are required ("BOTH REQUIRED",
	/// "ALL THREE REQUIRED", etc.). Returns null when the user cancels.
	/// </summary>
	public static Task<LayerChoice?> PickLayerAsync(
		IReadOnlyList<FileKeep.Reader.iOS.Core.Bundle.BundleWrap> orWraps,
		IReadOnlyDictionary<string, IReadOnlyList<FileKeep.Reader.iOS.Core.Bundle.BundleWrap>> andGroups)
	{
		var tcs = new TaskCompletionSource<LayerChoice?>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		var sheet = UIAlertController.Create(
			"Unlock bundle", "Choose how to unlock:", UIAlertControllerStyle.ActionSheet);

		// Standalone OR methods: each unlocks alone.
		foreach (var wrap in orWraps)
		{
			string label = DescribeWrap(wrap) + " — alone is enough";
			var w = wrap; // capture
			sheet.AddAction(UIAlertAction.Create(label, UIAlertActionStyle.Default,
				_ => tcs.TrySetResult(new LayerChoice { OrWrap = w })));
		}

		// AND groups: all methods in the group are required.
		foreach (var kv in andGroups)
		{
			string required = kv.Value.Count switch
			{
				2 => "BOTH REQUIRED",
				3 => "ALL THREE REQUIRED",
				_ => $"ALL {kv.Value.Count} REQUIRED",
			};
			string methods = string.Join(" + ", kv.Value.Select(DescribeWrap));
			string label = $"{methods} — {required}";
			var key = kv.Key;
			var wraps = kv.Value;
			sheet.AddAction(UIAlertAction.Create(label, UIAlertActionStyle.Default,
				_ => tcs.TrySetResult(new LayerChoice { AndGroupKey = key, AndWraps = wraps })));
		}

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

	/// <summary>Human-readable name for a wrap type.</summary>
	public static string DescribeWrap(FileKeep.Reader.iOS.Core.Bundle.BundleWrap wrap)
	{
		return wrap.Type switch
		{
			"passphrase" => "Passphrase",
			"yubikey-hmac-sha1" => "YubiKey",
			"passkey-prf" => "Passkey",
			_ => wrap.Type,
		};
	}
}
}
