using Foundation;
using UIKit;
using UniformTypeIdentifiers;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Opens a bundle file from any source via the iOS document picker.
///
/// Open mode (never Import): the bundle is read through the
/// security-scoped URL straight to memory. Import mode would copy the
/// file into the app sandbox — pointless for an opaque blob and one
/// more place it lingers.
/// </summary>
public static class BundleOpener
{
	// UIDocumentPickerViewController.Delegate is weak; keep the active
	// delegate alive for the life of the pick.
	private static PickerDelegate? _activeDelegate;

	public static Task<byte[]?> PickBundleAsync()
	{
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController()
			?? throw new InvalidOperationException("No view controller to present the picker from.");

		var tcs = new TaskCompletionSource<byte[]?>();
		var picker = new UIDocumentPickerViewController(
			new[] { UTType.Item.Identifier }, UIDocumentPickerMode.Open);
		_activeDelegate = new PickerDelegate(tcs, () => _activeDelegate = null);
		picker.Delegate = _activeDelegate;
		presenter.PresentViewController(picker, true, null);
		return tcs.Task;
	}

	private sealed class PickerDelegate : UIDocumentPickerDelegate
	{
		private readonly TaskCompletionSource<byte[]?> _tcs;
		private readonly Action _done;

		public PickerDelegate(TaskCompletionSource<byte[]?> tcs, Action done)
		{
			_tcs = tcs;
			_done = done;
		}

		public override void DidPickDocument(UIDocumentPickerViewController controller, NSUrl[] urls)
		{
			try
			{
				NSUrl? url = urls.FirstOrDefault();
				if (url is null)
				{
					_tcs.TrySetResult(null);
					return;
				}
				bool scoped = url.StartAccessingSecurityScopedResource();
				try
				{
					using NSData? data = NSData.FromUrl(url);
					_tcs.TrySetResult(data?.ToArray());
				}
				finally
				{
					if (scoped)
						url.StopAccessingSecurityScopedResource();
				}
			}
			catch (Exception ex)
			{
				_tcs.TrySetException(ex);
			}
			finally
			{
				_done();
			}
		}

		public override void WasCancelled(UIDocumentPickerViewController controller)
		{
			try { _tcs.TrySetResult(null); }
			finally { _done(); }
		}
	}
}
