using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS;

[Register("AppDelegate")]
public class AppDelegate : MauiUIApplicationDelegate
{
	protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();

	public override bool OpenUrl(UIApplication app, NSUrl url, NSDictionary options)
	{
		_ = OpenUrlAsync(url);
		return true;
	}

	/// <summary>
	/// Receives .kfb files opened from other apps (Files, Mail, Safari share
	/// sheet). Reads the security-scoped URL the same way BundleOpener does,
	/// then hands the bytes to the share-sheet open path on MainPage, which
	/// reuses the full unlock flow (Face ID / passkey / YubiKey / passphrase,
	/// layered picker) and records the bundle in recents.
	/// </summary>
	private static async Task OpenUrlAsync(NSUrl url)
	{
		byte[]? bytes = null;
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
				if (scoped) url.StopAccessingSecurityScopedResource();
			}
		}
		catch { return; }
		if (bytes is null) return;

		// Route to MainPage on the UI thread; MainPage owns the unlock prompt.
		await Microsoft.Maui.ApplicationModel.MainThread.InvokeOnMainThreadAsync(async () =>
		{
			if (Microsoft.Maui.Controls.Application.Current?.MainPage is MainPage page)
				await page.OpenSharedBundleAsync(url, bytes);
		});
	}
}
