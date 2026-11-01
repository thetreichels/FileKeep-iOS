using System.Security.Cryptography;
using System.Text;
using FileKeep.Reader.iOS.Core.Bundle;
#if IOS
using FileKeep.Reader.iOS.Platforms.iOS;
#endif

namespace FileKeep.Reader.iOS;

/// <summary>
/// Slice 2: render text, images, PDFs, and audio in-memory.
/// Other file types show metadata with Export and View-hex actions.
/// </summary>
public partial class MainPage : ContentPage
{
	private BundleReader? _reader;
	private byte[]? _currentFileBytes;
	private string? _currentFileName;
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
			// Clear previous preview and zero old bytes
			ClearPreview();
			
			byte[] plaintext = _reader.OpenFile(entry);
			_currentFileBytes = plaintext;
			_currentFileName = System.IO.Path.GetFileName(entry.Path);
			
			var fileType = GetFileType(entry.Path);
			switch (fileType)
			{
				case FileType.Text:
					ShowTextPreview(plaintext);
					break;
				case FileType.Image:
					ShowImagePreview(plaintext);
					break;
#if IOS
				case FileType.Pdf:
					ShowPdfPreview(plaintext);
					break;
				case FileType.Audio:
					ShowAudioPlayer(plaintext, _currentFileName);
					break;
#endif
				default:
					ShowFileMetadata(entry);
					break;
			}
		}
		catch (Exception ex)
		{
			ShowError("Couldn't decrypt file: " + ex.Message);
		}
		FilesView.SelectedItem = null;
	}

	private enum FileType { Text, Image, Pdf, Audio, Other }

	private static FileType GetFileType(string path)
	{
		var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
		return ext switch
		{
			".txt" or ".md" or ".markdown" or ".json" or ".xml" or ".csv" or
			".log" or ".yaml" or ".yml" or ".ini" or ".cfg" or ".conf" => FileType.Text,
			".jpg" or ".jpeg" or ".png" or ".gif" or ".heic" or ".heif" or
			".bmp" or ".tiff" or ".tif" or ".webp" => FileType.Image,
			".pdf" => FileType.Pdf,
			".mp3" or ".m4a" or ".wav" or ".aac" or ".ogg" or ".flac" => FileType.Audio,
			_ => FileType.Other,
		};
	}

	private void ShowTextPreview(byte[] data)
	{
		string text;
		try
		{
			text = Encoding.UTF8.GetString(data);
			// If it looks like binary, fall back to metadata view
			if (text.Any(char.IsControl) && !text.Any(c => c is '\r' or '\n' or '\t'))
				throw new DecoderFallbackException();
			if (text.Length > 50000)
				text = text[..50000] + "\n… (truncated)";
		}
		catch
		{
			// Not valid text — treat as "other"
			if (_reader is not null && _currentFileName is not null)
			{
				// Find the entry to show metadata
				var entry = _reader.Files.FirstOrDefault(f => 
					System.IO.Path.GetFileName(f.Path) == _currentFileName);
				if (entry is not null)
				{
					ShowFileMetadata(entry);
					return;
				}
			}
			ShowError("Could not render as text.");
			return;
		}

		var scrollView = new ScrollView();
		var label = new Label
		{
			Text = text,
			FontFamily = "monospace",
			FontSize = 13,
		};
		scrollView.Content = label;
		PreviewContainer.Content = scrollView;
	}

	private void ShowImagePreview(byte[] data)
	{
		try
		{
			var image = new Image
			{
				Source = ImageSource.FromStream(() => new MemoryStream(data)),
				Aspect = Aspect.AspectFit,
			};
			var scrollView = new ScrollView { Content = image };
			PreviewContainer.Content = scrollView;
		}
		catch (Exception ex)
		{
			ShowError("Couldn't render image: " + ex.Message);
		}
	}

#if IOS
	private void ShowPdfPreview(byte[] data)
	{
		try
		{
			var pdfView = PdfViewer.Create(data);
			PreviewContainer.Content = pdfView;
		}
		catch (Exception ex)
		{
			ShowError("Couldn't render PDF: " + ex.Message);
		}
	}

	private void ShowAudioPlayer(byte[] data, string fileName)
	{
		try
		{
			_audioPlayer?.Dispose();
			_audioPlayer = new AudioPlayer();
			
			var layout = new VerticalStackLayout { Spacing = 12, Padding = 20 };
			layout.Add(new Label { Text = fileName, FontAttributes = FontAttributes.Bold });
			
			var playButton = new Button { Text = "▶ Play" };
			var stopButton = new Button { Text = "⏹ Stop", IsEnabled = false };
			
			playButton.Clicked += (s, e) =>
			{
				if (_audioPlayer.Play(data))
				{
					playButton.IsEnabled = false;
					stopButton.IsEnabled = true;
				}
			};
			stopButton.Clicked += (s, e) =>
			{
				_audioPlayer.Stop();
				playButton.IsEnabled = true;
				stopButton.IsEnabled = false;
			};
			
			layout.Add(playButton);
			layout.Add(stopButton);
			layout.Add(new Label { 
				Text = "Audio plays from memory. Nothing is written to disk.",
				FontSize = 12,
				TextColor = Colors.Gray
			});
			
			PreviewContainer.Content = layout;
		}
		catch (Exception ex)
		{
			ShowError("Couldn't play audio: " + ex.Message);
		}
	}
#endif

	private void ShowFileMetadata(BundleFileEntry entry)
	{
		var fileName = System.IO.Path.GetFileName(entry.Path);
		var layout = new VerticalStackLayout { Spacing = 12, Padding = 20 };
		
		layout.Add(new Label { 
			Text = fileName, 
			FontAttributes = FontAttributes.Bold,
			FontSize = 16
		});
		layout.Add(new Label { Text = $"{entry.Size:N0} bytes" });
		layout.Add(new Label { Text = $"Modified: {entry.ModifiedUtc:yyyy-MM-dd HH:mm} UTC" });
		layout.Add(new Label { 
			Text = "This file type can't be previewed in-memory. Export to view, or inspect the raw bytes as hex.",
			FontSize = 13,
			TextColor = Colors.Gray
		});
		
		var exportButton = new Button { Text = "Export…" };
		exportButton.Clicked += OnExportClicked;
		
		var hexButton = new Button { Text = "View hex" };
		hexButton.Clicked += OnViewHexClicked;
		
		layout.Add(exportButton);
		layout.Add(hexButton);
		
		PreviewContainer.Content = layout;
	}

	private async void OnExportClicked(object? sender, EventArgs e)
	{
		if (_currentFileBytes is null || _currentFileName is null)
			return;
		
		// Explicit export: user chose to write plaintext to disk.
		// Write to temp, share, then delete.
		var tempPath = System.IO.Path.Combine(
			FileSystem.CacheDirectory, 
			_currentFileName);
		
		try
		{
			await File.WriteAllBytesAsync(tempPath, _currentFileBytes);
			await Share.Default.RequestAsync(new ShareFileRequest
			{
				Title = "Export " + _currentFileName,
				File = new ShareFile(tempPath),
			});
		}
		catch (Exception ex)
		{
			await DisplayAlert("Export failed", ex.Message, "OK");
		}
		finally
		{
			try { File.Delete(tempPath); } catch { }
		}
	}

	private void OnViewHexClicked(object? sender, EventArgs e)
	{
		if (_currentFileBytes is null)
			return;
		
		var data = _currentFileBytes;
		var sb = new StringBuilder();
		const int bytesPerLine = 16;
		const int maxBytes = 8192; // Limit hex view to 8KB
		
		int length = Math.Min(data.Length, maxBytes);
		for (int i = 0; i < length; i += bytesPerLine)
		{
			sb.Append($"{i:X8}  ");
			int lineLen = Math.Min(bytesPerLine, length - i);
			for (int j = 0; j < lineLen; j++)
				sb.Append($"{data[i + j]:X2} ");
			sb.AppendLine();
		}
		if (data.Length > maxBytes)
			sb.AppendLine($"… ({data.Length - maxBytes:N0} more bytes)");
		
		var scrollView = new ScrollView();
		var label = new Label
		{
			Text = sb.ToString(),
			FontFamily = "monospace",
			FontSize = 11,
		};
		scrollView.Content = label;
		PreviewContainer.Content = scrollView;
	}

	private void ShowError(string message)
	{
		PreviewContainer.Content = new Label
		{
			Text = message,
			TextColor = Colors.Red,
			HorizontalOptions = LayoutOptions.Center,
			VerticalOptions = LayoutOptions.Center,
		};
	}

	private void ClearPreview()
	{
#if IOS
		_audioPlayer?.Stop();
		_audioPlayer?.Dispose();
		_audioPlayer = null;
#endif
		if (_currentFileBytes is not null)
		{
			CryptographicOperations.ZeroMemory(_currentFileBytes);
			_currentFileBytes = null;
		}
		_currentFileName = null;
		PreviewContainer.Content = new Label
		{
			Text = "Select a file to preview.",
			HorizontalOptions = LayoutOptions.Center,
			VerticalOptions = LayoutOptions.Center,
		};
	}

	private void CloseReader()
	{
		ClearPreview();
		_reader?.Dispose();
		_reader = null;
		FilesView.ItemsSource = null;
		StatusLabel.Text = "No bundle open.";
	}
}
