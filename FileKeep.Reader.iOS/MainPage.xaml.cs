using System.Security.Cryptography;
using System.Text;
using FileKeep.Reader.iOS.Core.Bundle;
using FileKeep.Reader.iOS.Core.Session;
#if IOS
using FileKeep.Reader.iOS.Platforms.iOS;
#endif

namespace FileKeep.Reader.iOS;

/// <summary>
/// Slice 1 UI: open a bundle, unlock, list files, decrypt one file on tap.
/// Slice 2: in-app preview rendering. Slice 3: unlock session — Face ID
/// via the Keychain after the first passphrase unlock, native secure
/// passphrase entry, 1-hour idle expiry, wipe on background.
/// </summary>
public partial class MainPage : ContentPage
{
#if IOS
	private AudioPlayer? _audioPlayer;
#endif

	public MainPage()
	{
		InitializeComponent();
		SessionManager.Instance.Locked += (_, _) =>
			Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(ResetPreviewUi);
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

		// The bundle fingerprint keys the Face ID enrollment: one DEK per
		// bundle, so each package unlocks independently.
		string fingerprint = Convert.ToHexString(SHA256.HashData(bytes));

		BundleReader reader;
		byte[]? dek = TryFaceIdUnlock(fingerprint);
		if (dek is not null)
		{
			try
			{
				reader = BundleReader.OpenWithDek(bytes, dek);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(dek);
			}
		}
		else
		{
			char[]? passphrase = await SecurePrompt.PromptAsync("Unlock bundle", "Export passphrase:");
			if (passphrase is null || passphrase.Length == 0)
			{
				if (passphrase is not null)
					Array.Clear(passphrase);
				CryptographicOperations.ZeroMemory(bytes);
				return; // user cancelled
			}
			try
			{
				// The char[] overload zeroes the passphrase buffer itself.
				reader = await Task.Run(() => BundleReader.OpenWithPassphrase(bytes, passphrase));
			}
			catch (CryptographicException)
			{
				CryptographicOperations.ZeroMemory(bytes);
				StatusLabel.Text = "Wrong passphrase.";
				return;
			}
			catch (Exception ex)
			{
				CryptographicOperations.ZeroMemory(bytes);
				StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
				return;
			}
			EnrollFaceId(fingerprint, reader);
		}

		SessionManager.Instance.Open(reader);
		FilesView.ItemsSource = reader.Files;
		StatusLabel.Text = $"{reader.Files.Count} file(s)" +
			(reader.RequiresTotp ? " — TOTP required (slice 5)" : "") +
			(reader.HasYubiKeyWrap ? " — YubiKey wrap present (slice 4)" : "");
#endif
	}

#if IOS
	/// <summary>
	/// Face ID path: read the enrolled DEK out of the Keychain (iOS prompts
	/// for Face ID on the read). Returns null when the bundle was never
	/// enrolled, biometrics are unavailable, or the user cancels — the
	/// caller then falls back to the passphrase. A stale enrollment
	/// (biometrics changed since) is dropped so the next open re-enrolls.
	/// </summary>
	private static byte[]? TryFaceIdUnlock(string fingerprint)
	{
		if (!BiometricKeychain.CanUseBiometrics() || !BiometricKeychain.IsEnrolled(fingerprint))
			return null;
		byte[]? dek = BiometricKeychain.TryReadDek(fingerprint);
		if (dek is null)
		{
			BiometricKeychain.DeleteDek(fingerprint);
			BiometricKeychain.UnmarkEnrolled(fingerprint);
		}
		return dek;
	}

	/// <summary>
	/// Stores this bundle's DEK in the Keychain under a biometric access
	/// control so the next open can use Face ID. Silent no-op when the
	/// device can't do biometrics (simulator).
	/// </summary>
	private static void EnrollFaceId(string fingerprint, BundleReader reader)
	{
		if (!BiometricKeychain.CanUseBiometrics())
			return;
		byte[] dek = reader.GetDekCopy();
		try
		{
			if (BiometricKeychain.StoreDek(fingerprint, dek))
				BiometricKeychain.MarkEnrolled(fingerprint);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(dek);
		}
	}
#endif

	private void OnFileSelected(object? sender, SelectionChangedEventArgs e)
	{
		if (!SessionManager.Instance.IsOpen ||
			e.CurrentSelection.FirstOrDefault() is not BundleFileEntry entry)
			return;
		SessionManager.Instance.Touch();
		var reader = SessionManager.Instance.Reader;
		try
		{
			byte[] plaintext = reader.OpenFile(entry);
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

	private void ResetPreviewUi()
	{
		FilesView.ItemsSource = null;
#if IOS
		_audioPlayer?.Dispose();
		_audioPlayer = null;
#endif
		PreviewContainer.Content = new Label { Text = "Select a file to preview.", HorizontalOptions = LayoutOptions.Center, VerticalOptions = LayoutOptions.Center };
		StatusLabel.Text = "No bundle open.";
	}

	private void CloseReader()
	{
		SessionManager.Instance.Lock();
		ResetPreviewUi();
	}
}
