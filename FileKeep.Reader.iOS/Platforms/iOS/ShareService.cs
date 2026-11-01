using CoreGraphics;
using Foundation;
using UIKit;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Explicit export through the iOS share sheet. Memory-only: the NSData is
/// built from in-memory bytes and nothing is written to disk by us. Export
/// is the only path by which plaintext leaves the app.
/// </summary>
public static class ShareService
{
	public static void Export(string fileName, byte[] data, string uti)
	{
		var presenter = Microsoft.Maui.ApplicationModel.Platform.GetCurrentUIViewController();
		if (presenter?.View is null)
			return;

		var nsData = NSData.FromArray(data);
		var item = new ExportItemSource(nsData, fileName, uti);
		var sheet = new UIActivityViewController(new NSObject[] { item }, null);

		// iPad requires a popover anchor or presenting crashes.
		if (sheet.PopoverPresentationController is not null)
		{
			sheet.PopoverPresentationController.SourceView = presenter.View;
			var b = presenter.View.Bounds;
			sheet.PopoverPresentationController.SourceRect = new CGRect(b.Width / 2, b.Height / 2, 0, 0);
		}

		presenter.PresentViewController(sheet, true, null);
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

	private sealed class ExportItemSource : UIActivityItemSource
	{
		private readonly NSData _data;
		private readonly string _fileName;
		private readonly string _uti;

		public ExportItemSource(NSData data, string fileName, string uti)
		{
			_data = data;
			_fileName = fileName;
			_uti = uti;
		}

		public override NSObject GetPlaceholderItem() => _data;

		public override NSObject GetItemForActivity(UIActivityViewController activityViewController, NSString activityType)
			=> _data;

		public override string GetSubjectForActivity(UIActivityViewController activityViewController, NSString activityType)
			=> _fileName;

		public override string[] GetDataTypeIdentifiersForActivity(UIActivityViewController activityViewController, NSString activityType)
			=> new[] { _uti };
	}
}
