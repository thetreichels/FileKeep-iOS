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
	/// save bundle bytes to a Files location of their choosing. Returns
	/// the URL the user saved to, or null if they cancelled. Export mode
	/// copies the temp file to the picked location; the copy is verified
	/// by length and written directly if the system left it behind.
	/// </summary>
	public static Task<NSUrl?> SaveBundleAsAsync(byte[] bundleBytes, string fileName)
	{
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		var tcs = new TaskCompletionSource<NSUrl?>();
		if (presenter is null)
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		// Write to a temp file under the bundle's own name so the picker
		// shows the right filename.
		string tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), fileName);
		try
		{
			System.IO.File.WriteAllBytes(tempPath, bundleBytes);
		}
		catch
		{
			tcs.SetResult(null);
			return tcs.Task;
		}

		var url = Foundation.NSUrl.FromFilename(tempPath);
		var picker = new UIDocumentPickerViewController(url, UIDocumentPickerMode.ExportToService);
		_activeDelegate = new ExportDelegate(tcs, () => _activeDelegate = null, tempPath, bundleBytes.Length);
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

	/// <summary>
	/// Export-mode delegate for SaveBundleAsAsync. Reports the URL the
	/// user picked and verifies the export copy landed: export mode
	/// normally copies the temp file itself, but if the destination is
	/// missing or short the bytes are written directly.
	/// </summary>
	private sealed class ExportDelegate : UIDocumentPickerDelegate
	{
		private readonly TaskCompletionSource<NSUrl?> _tcs;
		private readonly Action _done;
		private readonly string _tempPath;
		private readonly long _expectedLength;

		public ExportDelegate(TaskCompletionSource<NSUrl?> tcs, Action done, string tempPath, long expectedLength)
		{
			_tcs = tcs;
			_done = done;
			_tempPath = tempPath;
			_expectedLength = expectedLength;
		}

		public override void DidPickDocument(UIDocumentPickerViewController controller, NSUrl url)
		{
			controller.DismissViewController(true, null);
			try
			{
				string path = url.Path ?? string.Empty;
				bool complete = false;
				try { complete = new System.IO.FileInfo(path).Length == _expectedLength; }
				catch { }
				if (!complete)
				{
					// The system left the destination behind — write the
					// bytes directly. _tempPath still holds them.
					try
					{
						byte[] bytes = System.IO.File.ReadAllBytes(_tempPath);
						using var data = Foundation.NSData.FromArray(bytes);
						data.Save(url, true);
					}
					catch { }
				}
				_tcs.TrySetResult(url);
			}
			finally
			{
				try { System.IO.File.Delete(_tempPath); } catch { }
				_done();
			}
		}

		public override void WasCancelled(UIDocumentPickerViewController controller)
		{
			controller.DismissViewController(true, null);
			try { _tcs.TrySetResult(null); }
			finally
			{
				try { System.IO.File.Delete(_tempPath); } catch { }
				_done();
			}
		}
	}
}
