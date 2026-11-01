using Microsoft.Maui.Controls;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Renders an image from in-memory bytes in a MAUI Image view.
/// The bytes are cloned into the view's stream: the caller's buffer is
/// zeroed after routing, and the view owns its copy. Nothing touches disk.
/// </summary>
public static class ImageViewer
{
	public static View Create(byte[] imageData)
	{
		var copy = (byte[])imageData.Clone();
		return new ScrollView
		{
			Content = new Image
			{
				Source = ImageSource.FromStream(() => new MemoryStream(copy)),
				Aspect = Aspect.AspectFit,
				VerticalOptions = LayoutOptions.FillAndExpand,
				HorizontalOptions = LayoutOptions.FillAndExpand,
			},
		};
	}
}
