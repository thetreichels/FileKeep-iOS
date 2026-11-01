using Microsoft.Maui.Controls;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Plays video from in-memory bytes in a WebView data URI.
/// Pure MAUI, memory-only — the same approach as PdfViewer.
/// </summary>
public static class VideoViewer
{
	public static View Create(byte[] videoData, string mimeType)
	{
		var base64 = Convert.ToBase64String(videoData);
		var webView = new WebView
		{
			VerticalOptions = LayoutOptions.FillAndExpand,
			HorizontalOptions = LayoutOptions.FillAndExpand,
		};
		webView.Source = new HtmlWebViewSource
		{
			Html = "<!DOCTYPE html><html><body style='margin:0;background:#000;'>" +
			       $"<video controls playsinline style='width:100%;height:100%;' src='data:{mimeType};base64,{base64}'></video>" +
			       "</body></html>"
		};
		return webView;
	}

	public static string MimeForExtension(string ext) => ext switch
	{
		".mov" => "video/quicktime",
		".m4v" => "video/x-m4v",
		_ => "video/mp4",
	};
}
