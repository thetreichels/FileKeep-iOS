using FileKeep.Reader.iOS.Core.Session;
using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS;

[Register("AppDelegate")]
public class AppDelegate : MauiUIApplicationDelegate
{
	private UIView? _blankOverlay;

	protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();

	public override void WillResignActive(UIApplication application)
	{
		// Blank overlay kills the app-switcher snapshot (Apple's recommended
		// approach); locking wipes the DEK from memory. Both happen here, so
		// no plaintext or key material survives backgrounding.
		if (_blankOverlay is null && Window is not null)
		{
			_blankOverlay = new UIView(Window.Bounds) { BackgroundColor = UIColor.Black };
			Window.AddSubview(_blankOverlay);
		}
		SessionManager.Instance.Lock();
	}

	public override void DidBecomeActive(UIApplication application)
	{
		_blankOverlay?.RemoveFromSuperview();
		_blankOverlay?.Dispose();
		_blankOverlay = null;
	}
}
