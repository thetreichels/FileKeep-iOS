using System.Security.Cryptography;
using System.Text;
using FileKeep.Reader.iOS.Core.Bundle;
#if IOS
using FileKeep.Reader.iOS.Platforms.iOS;
#endif

namespace FileKeep.Reader.iOS;

/// <summary>
/// Slice 1 UI: open a bundle, unlock with the passphrase, list files,
/// decrypt one file on tap. Slice 2: in-app preview rendering — images,
/// PDF, audio and video render from memory; Office docs export through
/// the share sheet; everything else falls back to text-or-hex.
/// </summary>
public partial class MainPage : ContentPage
{
	private BundleReader? _reader;
#if IOS
	private AudioPlayer? _audioPlayer;
#endif

	public MainPage()
	{
		InitializeComponent();
	}

	private async void OnOpenClicked(object? sender, EventArgs e)
	{
#if !IOS
		await DisplayAlert("Not supported", "Bundle opening needs iOS.", "OK");
		return;
#else
		CloseReader();

		byte[]? bytes;
		try
		{
			bytes = await BundleOpener.PickBundleAsync();
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Picker failed: " + ex.Message;
			return;
		}
		if (bytes is null)
			return; // user cancelled

		string? passphrase = await DisplayPromptAsync(
			"Unlock", "Export passphrase:", "Open", "Cancel",
			maxLength: 256, keyboard: Keyboard.Text, initialValue: "");
		if (string.IsNullOrEmpty(passphrase))
			return;

		BundleReader reader;
		try
		{
			// The passphrase string is MAUI's; zeroing it is not
			// possible — slice 3 replaces this prompt with a natively
			// wiped secure entry. The derived keys are zeroed.
			reader = await Task.Run(() => BundleReader.OpenWithPassphrase(bytes, passphrase));
		}
		catch (CryptographicException)
		{
			StatusLabel.Text = "Wrong passphrase.";
			CryptographicOperations.ZeroMemory(bytes);
			return;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			CryptographicOperations.ZeroMemory(bytes);
			return;
		}

		_reader = reader;
		FilesView.ItemsSource = reader.Files;
		StatusLabel.Text = $"{reader.Files.Count} file(s)" +
			(reader.RequiresTotp ? " — TOTP required (slice 5)" : "") +
			(reader.HasYubiKeyWrap ? " — YubiKey wrap present (slice 4)" : "");
#endif
	}

	private void OnFileSelected(object? sender, SelectionChangedEventArgs e)
	{
		if (_reader is null || e.CurrentSelection.FirstOrDefault() is not BundleFileEntry entry)
			return;
		try
		{
			byte[] plaintext = _reader.OpenFile(entry);
			try
			{
#if IOS
				SetPreview(entry.Path, plaintext);
#else
				PreviewContainer.Content = new Label { Text = CreateTextOrHexPreview(plaintext) };
#endif
			}
			finally
			{
				CryptographicOperations.ZeroMemory(plaintext);
			}
		}
		catch (Exception ex)
		{
			PreviewContainer.Content = new Label { Text = "Couldn't decrypt file: " + ex.Message };
		}
		FilesView.SelectedItem = null;
	}

#if IOS
	/// <summary>
	/// Routes a decrypted file to its in-app renderer by extension.
	/// Every renderer works from memory only. The caller's buffer is
	/// zeroed on return, so anything deferred (audio playback, export)
	/// clones the bytes it must keep.
	/// </summary>
	private void SetPreview(string path, byte[] plaintext)
	{
		_audioPlayer?.Dispose();
		_audioPlayer = null;

		var ext = Path.GetExtension(path).ToLowerInvariant();

		if (IsAudioExtension(ext))
		{
			var (audioView, player) = CreateAudioPreview(Path.GetFileName(path), plaintext);
			_audioPlayer = player;
			PreviewContainer.Content = audioView;
			return;
		}

		PreviewContainer.Content = ext switch
		{
			".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp"
				or ".tif" or ".tiff" or ".heic" or ".heif" or ".webp" => ImageViewer.Create(plaintext),
			".pdf" => PdfViewer.Create(plaintext),
			".mp4" or ".mov" or ".m4v" => VideoViewer.Create(plaintext, VideoViewer.MimeForExtension(ext)),
			".docx" or ".xlsx" or ".pptx" or ".doc" or ".xls" or ".ppt" => CreateOfficePlaceholder(path, plaintext),
			_ => new ScrollView { Content = new Label { Text = CreateTextOrHexPreview(plaintext), FontFamily = "Courier" } },
		};
	}

	private static bool IsAudioExtension(string ext) => ext is
		".mp3" or ".m4a" or ".wav" or ".caf" or ".aac" or ".aiff";

	private static (View View, AudioPlayer Player) CreateAudioPreview(string fileName, byte[] audioData)
	{
		// Cloned: playback is deferred to the Play tap, after the caller zeroes its buffer.
		var copy = (byte[])audioData.Clone();
		var player = new AudioPlayer();
		var status = new Label { Text = fileName, HorizontalOptions = LayoutOptions.Center };
		var play = new Button { Text = "Play" };
		var stop = new Button { Text = "Stop" };
		play.Clicked += (_, _) =>
		{
			if (!player.Play(copy))
				status.Text = "Couldn't play this audio.";
		};
		stop.Clicked += (_, _) => player.Stop();

		var buttons = new HorizontalStackLayout
		{
			Spacing = 12,
			HorizontalOptions = LayoutOptions.Center,
		};
		buttons.Children.Add(play);
		buttons.Children.Add(stop);

		var layout = new VerticalStackLayout
		{
			Spacing = 12,
			VerticalOptions = LayoutOptions.Center,
		};
		layout.Children.Add(status);
		layout.Children.Add(buttons);
		return (layout, player);
	}

	private static View CreateOfficePlaceholder(string path, byte[] plaintext)
	{
		// Cloned: export is deferred to the Export tap, after the caller zeroes its buffer.
		var copy = (byte[])plaintext.Clone();
		var fileName = Path.GetFileName(path);
		var ext = Path.GetExtension(path).ToLowerInvariant();

		var info = new Label
		{
			Text = $"{fileName}\n{plaintext.Length:N0} bytes\n\nThis file type can't be previewed in the app. Export it to open elsewhere.",
			HorizontalOptions = LayoutOptions.Center,
			HorizontalTextAlignment = TextAlignment.Center,
		};
		var export = new Button { Text = "Export…", HorizontalOptions = LayoutOptions.Center };
		export.Clicked += (_, _) => ShareService.Export(fileName, copy, ShareService.UtiForExtension(ext));

		var layout = new VerticalStackLayout
		{
			Spacing = 16,
			VerticalOptions = LayoutOptions.Center,
		};
		layout.Children.Add(info);
		layout.Children.Add(export);
		return layout;
	}
#endif

	private static string CreateTextOrHexPreview(byte[] plaintext)
	{
		try
		{
			var preview = Encoding.UTF8.GetString(plaintext);
			if (preview.Any(char.IsControl) && !preview.Any(c => c is '\r' or '\n' or '\t'))
				throw new DecoderFallbackException();
			if (preview.Length > 2000)
				preview = preview[..2000] + "…";
			return preview;
		}
		catch
		{
			return "Binary file — " + plaintext.Length + " bytes. " +
				"First bytes: " + Convert.ToHexString(plaintext, 0, Math.Min(32, plaintext.Length));
		}
	}

	private void CloseReader()
	{
		_reader?.Dispose();
		_reader = null;
#if IOS
		_audioPlayer?.Dispose();
		_audioPlayer = null;
#endif
		FilesView.ItemsSource = null;
		PreviewContainer.Content = new Label { Text = "Select a file to preview.", HorizontalOptions = LayoutOptions.Center, VerticalOptions = LayoutOptions.Center };
		StatusLabel.Text = "No bundle open.";
	}
}
