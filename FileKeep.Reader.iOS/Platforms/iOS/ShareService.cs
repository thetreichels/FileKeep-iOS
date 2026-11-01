using CoreGraphics;
using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Explicit export through the iOS share sheet.
/// Export is the only path by which plaintext leaves the app.
/// </summary>
public static class ShareService
{
	public static void Export(string fileName, byte[] data, string uti)
	{
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter?.View is null)
			return;

		// Write to a temp file with the proper filename so the share
		// sheet shows the right name and type. This is the explicit
		// export path — the user chose to share, so a temp file is
		// acceptable. Deleted immediately after the sheet dismisses.
		var tempPath = System.IO.Path.Combine(
			System.IO.Path.GetTempPath(),
			fileName);
		
		try
		{
			System.IO.File.WriteAllBytes(tempPath, data);
			using var url = NSUrl.FromFilename(tempPath);
			var sheet = new UIActivityViewController(new NSObject[] { url }, null);

			// iPad requires a popover anchor or presenting crashes.
			if (sheet.PopoverPresentationController is not null)
			{
				sheet.PopoverPresentationController.SourceView = presenter.View;
				var b = presenter.View.Bounds;
				sheet.PopoverPresentationController.SourceRect = new CGRect(b.Width / 2, b.Height / 2, 0, 0);
			}

			sheet.CompletionWithItemsHandler = (activityType, completed, returnedItems, error) =>
			{
				try { System.IO.File.Delete(tempPath); } catch { }
			};

			presenter.PresentViewController(sheet, true, null);
		}
		catch
		{
			try { System.IO.File.Delete(tempPath); } catch { }
		}
	}

	public static string UtiForExtension(string ext) => ext switch
	{
		".docx" => "org.openxmlformats.wordprocessingml.document",
		".xlsx" => "org.openxmlformats.spreadsheetml.sheet",
		".pptx" => "org.openxmlformats.presentationml.presentation",
		".doc" => "com.microsoft.word.doc",
		".xls" => "com.microsoft.excel.xls",
		".ppt" => "com.microsoft.powerpoint.ppt",
		_ => "public.data",
	};
}
