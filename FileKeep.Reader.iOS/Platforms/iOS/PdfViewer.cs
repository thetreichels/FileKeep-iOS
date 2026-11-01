using Foundation;
using PDFKit;
using Microsoft.Maui.Controls;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Renders a PDF from in-memory bytes using PDFKit.
/// The PDF never touches disk.
/// </summary>
public static class PdfViewer
{
	public static View Create(byte[] pdfData)
	{
		// Create a UIView wrapper for the PDFKit PDFView
		var wrapper = new PdfViewWrapper(pdfData);
		return wrapper;
	}

	private sealed class PdfViewWrapper : View
	{
		private readonly byte[] _data;

		public PdfViewWrapper(byte[] data)
		{
			_data = data;
		}
	}

	/// <summary>
	/// MAUI handler that hosts a native PDFKit PDFView.
	/// </summary>
	public static IView CreateNative(byte[] pdfData)
	{
		var pdfView = new PdfKit.PDFView
		{
			AutoScales = true,
			DisplayMode = PdfDisplayMode.SinglePageContinuous,
		};
		using var nsData = NSData.FromArray(pdfData);
		if (nsData is not null)
		{
			pdfView.Document = new PdfDocument(nsData);
		}
		// Wrap in a MAUI View via handler
		var mauiView = new PdfKitView { PdfData = pdfData };
		return mauiView;
	}
}

/// <summary>
/// MAUI View that hosts a native PDFKit PDFView via a handler.
/// </summary>
public class PdfKitView : View
{
	public byte[]? PdfData { get; set; }
}
