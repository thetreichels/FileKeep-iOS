using System.Security.Cryptography;
using System.Text;
using FileKeep.Reader.iOS.Core.Bundle;
#if IOS
using FileKeep.Reader.iOS.Platforms.iOS;
#endif

namespace FileKeep.Reader.iOS;

/// <summary>
/// Slice 1 UI: open a bundle, unlock with the passphrase, list files,
/// decrypt one file on tap (preview only — full rendering is slice 2).
/// </summary>
public partial class MainPage : ContentPage
{
	private BundleReader? _reader;

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
			maxLength: 256, keyboard: Keyboard.Text, initialValue: "", isPassword: true);
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
				// Slice 1 preview: text if it looks like text, else hex.
				// Full rendering (images, PDF, media) is slice 2.
				string preview;
				try
				{
					preview = Encoding.UTF8.GetString(plaintext);
					if (preview.Any(char.IsControl) && !preview.Any(c => c is '\r' or '\n' or '\t'))
						throw new DecoderFallbackException();
					if (preview.Length > 2000)
						preview = preview[..2000] + "…";
				}
				catch
				{
					preview = "Binary file — " + plaintext.Length + " bytes. " +
						"First bytes: " + Convert.ToHexString(plaintext, 0, Math.Min(32, plaintext.Length));
				}
				PreviewLabel.Text = preview;
			}
			finally
			{
				CryptographicOperations.ZeroMemory(plaintext);
			}
		}
		catch (Exception ex)
		{
			PreviewLabel.Text = "Couldn't decrypt file: " + ex.Message;
		}
		FilesView.SelectedItem = null;
	}

	private void CloseReader()
	{
		_reader?.Dispose();
		_reader = null;
		FilesView.ItemsSource = null;
		PreviewLabel.Text = "";
		StatusLabel.Text = "No bundle open.";
	}
}
