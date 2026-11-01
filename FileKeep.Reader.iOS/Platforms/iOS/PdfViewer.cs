using Microsoft.Maui.Controls;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Renders a PDF from in-memory bytes using a WebView with a data URI.
/// The PDF never touches disk.
/// </summary>
public static class PdfViewer
{
	public static View Create(byte[] pdfData)
	{
		var base64 = Convert.ToBase64String(pdfData);
		var webView = new WebView
		{
			VerticalOptions = LayoutOptions.FillAndExpand,
			HorizontalOptions = LayoutOptions.FillAndExpand,
		};
		webView.Source = new HtmlWebViewSource
		{
			Html = $"<!DOCTYPE html><html><body style='margin:0;'>" +
			       $"<embed src='data:application/pdf;base64,{base64}' " +
			       $"type='application/pdf' width='100%' height='100%' />" +
			       $"</body></html>"
		};
		return webView;
	}
}
