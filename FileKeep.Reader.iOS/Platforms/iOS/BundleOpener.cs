using Foundation;
using UIKit;
using UniformTypeIdentifiers;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Secure-workspace extensions: track the picked URL for save-back,
/// import files for adding to a bundle, and write rebuilt bundles back.
/// </summary>
public static class BundleOpener
{
	// UIDocumentPickerViewController.Delegate is weak; keep the active
	// delegate alive for the life of the pick.
	private static UIDocumentPickerDelegate? _activeDelegate;

	/// <summary>The URL of the last picked bundle (for save-back). Null for HTTP sources.</summary>
	public static NSUrl? LastPickedUrl { get; private set; }

	public static Task<byte[]?> PickBundleAsync()
	{
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController()
			?? throw new InvalidOperationException("No view controller to present the picker from.");

		var tcs = new TaskCompletionSource<byte[]?>();
		var picker = new UIDocumentPickerViewController(
			new[] { "public.item" }, UIDocumentPickerMode.Open);
		_activeDelegate = new PickerDelegate(tcs, () => _activeDelegate = null);
		picker.Delegate = _activeDelegate;
		presenter.PresentViewController(picker, true, null);
		return tcs.Task;
	}

	/// <summary>
	/// Picks a file to import into the bundle. Returns (bytes, filename).
	/// Uses Import mode so the source stays untouched.
	/// </summary>
	public static Task<(byte[]? Bytes, string? Name)> PickImportFileAsync()
	{
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController()
			?? throw new InvalidOperationException("No view controller to present the picker from.");

		var tcs = new TaskCompletionSource<(byte[]?, string?)>();
		var picker = new UIDocumentPickerViewController(
			new[] { "public.item" }, UIDocumentPickerMode.Import);
		_activeDelegate = new ImportDelegate(tcs, () => _activeDelegate = null);
		picker.Delegate = _activeDelegate;
		presenter.PresentViewController(picker, true, null);
		return tcs.Task;
	}

	/// <summary>
	/// Writes rebuilt bundle bytes back to a Files URL. Returns false on failure.
	/// </summary>
	public static bool WriteBack(NSUrl url, byte[] bytes)
	{
		ArgumentNullException.ThrowIfNull(url);
		ArgumentNullException.ThrowIfNull(bytes);
		bool scoped = url.StartAccessingSecurityScopedResource();
		try
		{
			using var data = NSData.FromArray(bytes);
			NSError? err;
			return data.Save(url, true, out err);
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

	/// <summary>
	/// Presents the iOS document picker in export mode so the user can
	/// save bundle bytes to Files (or another destination). Returns true
	/// if the user completed the export, false if they cancelled.
	/// </summary>
	public static Task<bool> ExportBundleAsync(byte[] bundleBytes)
	{
		var tcs = new TaskCompletionSource<bool>();
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter is null)
		{
			tcs.SetResult(false);
			return tcs.Task;
		}

		// Write to a temp file for the share sheet.
		string tempPath = System.IO.Path.Combine(
			System.IO.Path.GetTempPath(), $"bundle-{Guid.NewGuid():N}.kfb");
		try
		{
			System.IO.File.WriteAllBytes(tempPath, bundleBytes);
		}
		catch
		{
			tcs.SetResult(false);
			return tcs.Task;
		}

		var url = Foundation.NSUrl.FromFilename(tempPath);
		var activity = new UIKit.UIActivityViewController(new Foundation.NSObject[] { url }, null);
		activity.CompletionWithItemsHandler = (_, completed, _, _) =>
		{
			try { System.IO.File.Delete(tempPath); } catch { }
			tcs.TrySetResult(completed);
		};

		if (activity.PopoverPresentationController is not null && presenter.View is not null)
		{
			activity.PopoverPresentationController.SourceView = presenter.View;
			var b = presenter.View.Bounds;
			activity.PopoverPresentationController.SourceRect =
				new CoreGraphics.CGRect(b.Width / 2, b.Height / 2, 0, 0);
		}

		presenter.PresentViewController(activity, true, null);
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
			controller.DismissViewController(true, null);
			try
			{
				NSUrl? url = urls.FirstOrDefault();
				if (url is null)
				{
					_tcs.TrySetResult(null);
					return;
				}
				LastPickedUrl = url;
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
			controller.DismissViewController(true, null);
			try { _tcs.TrySetResult(null); }
			finally { _done(); }
		}
	}

	private sealed class ImportDelegate : UIDocumentPickerDelegate
	{
		private readonly TaskCompletionSource<(byte[]?, string?)> _tcs;
		private readonly Action _done;

		public ImportDelegate(TaskCompletionSource<(byte[]?, string?)> tcs, Action done)
		{
			_tcs = tcs;
			_done = done;
		}

		public override void DidPickDocument(UIDocumentPickerViewController controller, NSUrl[] urls)
		{
			controller.DismissViewController(true, null);
			try
			{
				NSUrl? url = urls.FirstOrDefault();
				if (url is null)
				{
					_tcs.TrySetResult((null, null));
					return;
				}
				bool scoped = url.StartAccessingSecurityScopedResource();
				try
				{
					using NSData? data = NSData.FromUrl(url);
					string name = url.LastPathComponent ?? "imported.bin";
					_tcs.TrySetResult((data?.ToArray(), name));
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
			controller.DismissViewController(true, null);
			try { _tcs.TrySetResult((null, null)); }
			finally { _done(); }
		}
	}
}
