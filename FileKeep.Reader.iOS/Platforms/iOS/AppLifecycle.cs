using FileKeep.Reader.iOS.Core.Session;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// App background/foreground handling, wired via MAUI lifecycle events
/// (MauiProgram). The blank overlay kills the app-switcher snapshot
/// (Apple's recommended approach); locking wipes the DEK from memory.
/// Both happen on resign-active, so no plaintext or key material
/// survives backgrounding.
/// </summary>
public static class AppLifecycle
{
	private static UIView? _blankOverlay;

	public static void OnResignActive(UIWindow? window)
	{
		if (_blankOverlay is null && window is not null)
		{
			_blankOverlay = new UIView(window.Bounds) { BackgroundColor = UIColor.Black };
			window.AddSubview(_blankOverlay);
		}
		SessionManager.Instance.Lock();
	}

	public static void OnActivated()
	{
		_blankOverlay?.RemoveFromSuperview();
		_blankOverlay?.Dispose();
		_blankOverlay = null;
	}
}
