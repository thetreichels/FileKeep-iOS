using System.Security.Cryptography;
using System.Text;
using FileKeep.Reader.iOS.Core.Bundle;
using FileKeep.Reader.iOS.Core.Session;
#if IOS
using FileKeep.Reader.iOS.Platforms.iOS;
using Foundation;
using UIKit;
#endif

namespace FileKeep.Reader.iOS;

/// <summary>
/// FileKeep secure workspace: open a bundle (Files or HTTP), unlock
/// (Face ID / YubiKey / passphrase), read, create, update, and delete
/// files behind the DEK veil, then save back or upload the re-encrypted
/// bundle. Plaintext lives in memory only; the HTTP server sees ciphertext.
/// </summary>
public partial class MainPage : ContentPage
{
#if IOS
	private AudioPlayer? _audioPlayer;
	private NSUrl? _sourceFileUrl; // Files pick source, for save-back
	private string? _sourceHttpUrl; // HTTP download source, for upload-back
	private readonly Dictionary<string, byte[]> _modified = new(); // path -> new plaintext
	private readonly HashSet<string> _deleted = new();
	private bool _isReadOnly;
	private readonly List<BundleWrap> _pendingWraps = new();
	private string? _editingPath;
	private Editor? _textEditor;
	private string? _textEditorOriginal;
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

		_sourceFileUrl = BundleOpener.LastPickedUrl;
		_sourceHttpUrl = null;
		// SMB shares (via Files) are editable only if the user has write permission.
		_isReadOnly = !IsUrlWritable(_sourceFileUrl);
		await OpenBundleBytesAsync(bytes);
#endif
	}

#if IOS
	private async void OnDownloadClicked(object? sender, EventArgs e)
	{
		CloseReader();
		string? url = await DisplayPromptAsync("Download bundle", "HTTPS URL of the .kfb file:");
		if (string.IsNullOrWhiteSpace(url))
			return;
		url = url.Trim();
		if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
		    !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
		{
			StatusLabel.Text = "URL must start with http:// or https://.";
			return;
		}

		StatusLabel.Text = "Downloading…";
		byte[] bytes;
		try
		{
			using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
			bytes = await http.GetByteArrayAsync(url);
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Download failed: " + ex.Message;
			return;
		}

		_sourceFileUrl = null;
		_sourceHttpUrl = url;
		_isReadOnly = true; // HTTP sources are read-only
		await OpenBundleBytesAsync(bytes);
	}

	/// <summary>
	/// Checks if a Files URL (local or SMB) is writable. SMB shares with
	/// read-only permissions report false, and the workspace opens read-only.
	/// </summary>
	private static bool IsUrlWritable(NSUrl? url)
	{
		if (url?.Path is null)
			return false;
		bool scoped = url.StartAccessingSecurityScopedResource();
		try
		{
			return NSFileManager.DefaultManager.IsWritableFile(url.Path);
		}
		catch
		{
			return false;
		}
		finally
		{
			if (scoped)
				url.StopAccessingSecurityScopedResource();
		}
	}

	private async Task OpenBundleBytesAsync(byte[] bytes)
	{
		// The bundle fingerprint keys the Face ID enrollment: one DEK per
		// bundle, so each package unlocks independently.
		string fingerprint = Convert.ToHexString(SHA256.HashData(bytes));

		BundleReader? reader = await TryUnlockAsync(bytes, fingerprint);
		if (reader is null)
			return; // user cancelled, or the error is already on screen

		SessionManager.Instance.Open(reader);
		_modified.Clear();
		_deleted.Clear();
		_pendingWraps.Clear();
		_editingPath = null;
		RefreshFileList();
		UpdateDirtyUi();
	}
#endif

#if IOS
	/// <summary>
	/// Unlock cascade: Face ID (enrolled DEK) → YubiKey NFC (when the
	/// bundle carries a YubiKey wrap and this device can do NFC) →
	/// typed passphrase. Returns null when the user cancels; every
	/// failure path zeroes <paramref name="bytes"/> before returning.
	/// </summary>
	private async Task<BundleReader?> TryUnlockAsync(byte[] bytes, string fingerprint)
	{
		byte[]? dek = TryFaceIdUnlock(fingerprint);
		if (dek is not null)
		{
			try
			{
				return BundleReader.OpenWithDek(bytes, dek);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(dek);
			}
		}

		BundleWrap? ykWrap = null;
		bool offerYubiKey = NfcYubiKey.IsAvailable() &&
			BundleReader.TryGetYubiKeyWrap(bytes, out ykWrap) && ykWrap is not null;
		if (offerYubiKey)
		{
			bool? choice = await SecurePrompt.PickUnlockMethodAsync();
			if (choice is null)
			{
				CryptographicOperations.ZeroMemory(bytes);
				return null; // user cancelled
			}
			if (choice == true && ykWrap is not null)
			{
				BundleReader? ykReader = await UnlockWithYubiKeyAsync(bytes, ykWrap);
				if (ykReader is not null)
				{
					EnrollFaceId(fingerprint, ykReader);
					return ykReader;
				}
				// NFC didn't complete — fall through to the passphrase.
			}
		}

		char[]? passphrase = await SecurePrompt.PromptAsync("Unlock bundle", "Export passphrase:");
		if (passphrase is null || passphrase.Length == 0)
		{
			if (passphrase is not null)
				Array.Clear(passphrase);
			CryptographicOperations.ZeroMemory(bytes);
			return null; // user cancelled
		}
		try
		{
			// The char[] overload zeroes the passphrase buffer itself.
			var reader = await Task.Run(() => BundleReader.OpenWithPassphrase(bytes, passphrase));
			EnrollFaceId(fingerprint, reader);
			return reader;
		}
		catch (CryptographicException)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Wrong passphrase.";
			return null;
		}
		catch (Exception ex)
		{
			CryptographicOperations.ZeroMemory(bytes);
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
	}

	/// <summary>
	/// YubiKey path: NFC challenge-response against the wrap's slot and
	/// challenge, KEK per DESIGN.md §3.2, open the bundle. Returns null
	/// when the scan is cancelled or the key doesn't answer (status text
	/// explains why); the caller then falls back to the passphrase.
	/// </summary>
	private async Task<BundleReader?> UnlockWithYubiKeyAsync(byte[] bytes, BundleWrap ykWrap)
	{
		int slot = ykWrap.Slot ?? 2;
		byte[] challenge;
		try
		{
			challenge = Convert.FromBase64String(ykWrap.ChallengeB64 ??
				throw new InvalidDataException("YubiKey wrap is missing its challenge."));
		}
		catch (Exception ex) when (ex is InvalidDataException || ex is FormatException)
		{
			StatusLabel.Text = "YubiKey wrap is missing its challenge.";
			return null;
		}

		NfcYubiKey.Result result;
		try
		{
			result = await NfcYubiKey.GetKekAsync(slot, challenge);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(challenge);
		}
		if (result.Kek is null)
		{
			StatusLabel.Text = result.Error ?? "YubiKey scan cancelled.";
			return null;
		}
		try
		{
			byte[] kek = result.Kek;
			try
			{
				return await Task.Run(() => BundleReader.OpenWithYubiKey(bytes, kek));
			}
			finally
			{
				CryptographicOperations.ZeroMemory(kek);
			}
		}
		catch (CryptographicException)
		{
			StatusLabel.Text = "This YubiKey didn't open the bundle (wrong key or slot).";
			return null;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Couldn't open bundle: " + ex.Message;
			return null;
		}
	}
#endif

	
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

#if IOS
	/// <summary>
	/// Rebuilds the visible file list from the reader plus pending
	/// modifications (added/updated/deleted). The bundle itself is
	/// untouched until Save.
	/// </summary>
	private void RefreshFileList()
	{
		if (!SessionManager.Instance.IsOpen)
		{
			FilesView.ItemsSource = null;
			return;
		}
		var reader = SessionManager.Instance.Reader;
		var list = new List<BundleFileEntry>();
		foreach (var f in reader.Files)
		{
			if (_deleted.Contains(f.Path))
				continue;
			list.Add(f);
		}
		// Added files aren't in the reader yet; show placeholders.
		foreach (var path in _modified.Keys)
		{
			if (!list.Any(f => f.Path == path))
				list.Add(new BundleFileEntry { Path = path, Size = _modified[path].Length, ModifiedUtc = DateTimeOffset.UtcNow });
		}
		FilesView.ItemsSource = list;
		var reader2 = SessionManager.Instance.Reader;
		StatusLabel.Text = $"{list.Count} file(s)" +
			(reader2.RequiresTotp ? " — TOTP required (slice 5)" : "") +
			(IsDirty ? " • modified" : "");
	}

	private bool IsDirty => _modified.Count > 0 || _deleted.Count > 0 || _pendingWraps.Count > 0;

	private void UpdateDirtyUi()
	{
		SaveButton.IsVisible = IsDirty && !_isReadOnly;
		UploadButton.IsVisible = SessionManager.Instance.IsOpen && !_isReadOnly;
		AddFileButton.IsVisible = SessionManager.Instance.IsOpen;
	}
#endif

	private void OnFileSelected(object? sender, SelectionChangedEventArgs e)
	{
		if (!SessionManager.Instance.IsOpen ||
			e.CurrentSelection.FirstOrDefault() is not BundleFileEntry entry)
			return;
		SessionManager.Instance.Touch();
#if IOS
		// Resolve plaintext: modified version wins, else decrypt.
		byte[] plaintext;
		if (_modified.TryGetValue(entry.Path, out byte[]? mod))
		{
			plaintext = (byte[])mod.Clone();
		}
		else
		{
			try
			{
				plaintext = SessionManager.Instance.Reader.OpenFile(entry);
			}
			catch (Exception ex)
			{
				PreviewContainer.Content = new Label { Text = "Couldn't decrypt file: " + ex.Message };
				FilesView.SelectedItem = null;
				return;
			}
		}
		try
		{
			SetPreview(entry.Path, plaintext);
		}
		finally
		{
			// Text editor keeps its own copy; others are done with it.
			if (!IsTextExtension(Path.GetExtension(entry.Path).ToLowerInvariant()))
				CryptographicOperations.ZeroMemory(plaintext);
		}
#else
		PreviewContainer.Content = new Label { Text = "Preview needs iOS." };
#endif
		FilesView.SelectedItem = null;
	}

#if IOS
	private static bool IsTextExtension(string ext) => ext is
		".txt" or ".md" or ".json" or ".xml" or ".csv" or ".log" or ".yaml" or ".yml";

	/// <summary>
	/// Routes a decrypted file to its renderer. Text files open in an
	/// editable view (the secure workspace); everything else previews.
	/// </summary>
	private void SetPreview(string path, byte[] plaintext)
	{
		_audioPlayer?.Dispose();
		_audioPlayer = null;
		_editingPath = null;
		_textEditor = null;

		var ext = Path.GetExtension(path).ToLowerInvariant();
		var fileName = Path.GetFileName(path);

		// Header card with file name + actions
		var header = new HorizontalStackLayout { Spacing = 8 };
		var title = new Label { Text = fileName, FontAttributes = FontAttributes.Bold, VerticalOptions = LayoutOptions.Center };
		header.Children.Add(title);
		if (!_isReadOnly)
		{
			var delete = new Button { Text = "Delete", FontSize = 13 };
			delete.Clicked += (_, _) => OnDeleteFile(path);
			header.Children.Add(delete);
		}

		View body;
		if (IsTextExtension(ext))
		{
			body = CreateTextEditor(path, plaintext);
		}
		else if (IsAudioExtension(ext))
		{
			var (audioView, player) = CreateAudioPreview(fileName, plaintext);
			_audioPlayer = player;
			body = audioView;
		}
		else
		{
			body = ext switch
			{
				".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp"
					or ".tif" or ".tiff" or ".heic" or ".heif" or ".webp" => ImageViewer.Create(plaintext),
				".pdf" => PdfViewer.Create(plaintext),
				".mp4" or ".mov" or ".m4v" => VideoViewer.Create(plaintext, VideoViewer.MimeForExtension(ext)),
				".docx" or ".xlsx" or ".pptx" or ".doc" or ".xls" or ".ppt" => CreateOfficePlaceholder(path, plaintext),
				_ => CreateHexViewer(plaintext),
			};
		}

		var card = new Frame
		{
			Content = body,
			CornerRadius = 12,
			Padding = 12,
			HasShadow = false,
			BackgroundColor = Color.FromArgb("#242424"),
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		var layout = new VerticalStackLayout { Spacing = 8 };
		layout.Children.Add(header);
		layout.Children.Add(card);
		PreviewContainer.Content = layout;
	}

	/// <summary>
	/// Read-only text view for HTTP sources (no editing).
	/// </summary>
	private static View CreateTextViewer(byte[] plaintext)
	{
		string text;
		try { text = Encoding.UTF8.GetString(plaintext); }
		catch { return CreateHexViewer(plaintext); }
		var label = new Label { Text = text, FontFamily = "Courier" };
		return new ScrollView { Content = label, VerticalOptions = LayoutOptions.FillAndExpand };
	}

	/// <summary>
	/// Editable text view. Edits stay in memory; Save stages them for the
	/// next bundle rebuild (the veil: re-encrypted with the session DEK).
	/// </summary>
	private View CreateTextEditor(string path, byte[] plaintext)
	{
		string text;
		try { text = Encoding.UTF8.GetString(plaintext); }
		catch { text = "(not valid UTF-8 — showing hex)"; return CreateHexViewer(plaintext); }

		_editingPath = path;
		_textEditorOriginal = text;
		var editor = new Editor
		{
			Text = text,
			FontFamily = "Courier",
			VerticalOptions = LayoutOptions.FillAndExpand,
			AutoSize = EditorAutoSizeOption.Disabled,
		};
		_textEditor = editor;

		var save = new Button { Text = "Save changes", IsVisible = false };
		var cancel = new Button { Text = "Discard", IsVisible = false };
		editor.TextChanged += (_, _) =>
		{
			bool dirty = editor.Text != _textEditorOriginal;
			save.IsVisible = dirty;
			cancel.IsVisible = dirty;
		};
		save.Clicked += (_, _) =>
		{
			byte[] newBytes = Encoding.UTF8.GetBytes(editor.Text ?? "");
			// Zero the old modified buffer if replacing.
			if (_modified.TryGetValue(path, out byte[]? old))
				CryptographicOperations.ZeroMemory(old);
			_modified[path] = newBytes;
			_textEditorOriginal = editor.Text;
			save.IsVisible = false;
			cancel.IsVisible = false;
			RefreshFileList();
			UpdateDirtyUi();
			StatusLabel.Text = "Staged — tap Save bundle to write.";
		};
		cancel.Clicked += (_, _) =>
		{
			editor.Text = _textEditorOriginal;
		};

		var buttons = new HorizontalStackLayout { Spacing = 8 };
		buttons.Children.Add(save);
		buttons.Children.Add(cancel);

		var layout = new VerticalStackLayout { Spacing = 8 };
		var scroll = new ScrollView
		{
			Content = editor,
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		layout.Children.Add(scroll);
		layout.Children.Add(buttons);
		return layout;
	}

	/// <summary>
	/// Hex viewer: offset gutter, hex bytes, ASCII sidebar. Monospace,
	/// scrollable, in the card style.
	/// </summary>
	private static View CreateHexViewer(byte[] plaintext)
	{
		const int perRow = 16;
		const int cap = 64 * 1024; // 64KB cap
		int len = Math.Min(plaintext.Length, cap);
		var sb = new StringBuilder();
		for (int i = 0; i < len; i += perRow)
		{
			sb.Append($"{i:X8}  ");
			int rowLen = Math.Min(perRow, len - i);
			for (int j = 0; j < perRow; j++)
			{
				if (j < rowLen)
					sb.Append($"{plaintext[i + j]:X2} ");
				else
					sb.Append("   ");
				if (j == 7) sb.Append(' ');
			}
			sb.Append(" |");
			for (int j = 0; j < rowLen; j++)
			{
				char c = (char)plaintext[i + j];
				sb.Append(char.IsControl(c) ? '.' : c);
			}
			sb.AppendLine("|");
		}
		if (plaintext.Length > cap)
			sb.AppendLine($"… ({plaintext.Length - cap:N0} more bytes, capped at 64KB)");

		var label = new Label
		{
			Text = sb.ToString(),
			FontFamily = "Courier",
			FontSize = 12,
		};
		return new ScrollView
		{
			Content = label,
			VerticalOptions = LayoutOptions.FillAndExpand,
			Orientation = ScrollOrientation.Both,
		};
	}

	private void OnDeleteFile(string path)
	{
		if (!SessionManager.Instance.IsOpen || _isReadOnly)
			return;
		SessionManager.Instance.Touch();
		_deleted.Add(path);
		if (_modified.TryGetValue(path, out byte[]? old))
		{
			CryptographicOperations.ZeroMemory(old);
			_modified.Remove(path);
		}
		if (_editingPath == path)
		{
			_editingPath = null;
			_textEditor = null;
		}
		RefreshFileList();
		UpdateDirtyUi();
		PreviewContainer.Content = new Label
		{
			Text = "File staged for deletion — tap Save bundle to write.",
			HorizontalOptions = LayoutOptions.Center,
			VerticalOptions = LayoutOptions.Center,
		};
	}

	private async void OnAddFileClicked(object? sender, EventArgs e)
	{
		try
		{
			StatusLabel.Text = "DIAG: handler entered";
			if (!SessionManager.Instance.IsOpen)
			{
				StatusLabel.Text = "DIAG: IsOpen=false, silent return";
				return;
			}
			StatusLabel.Text = "DIAG: IsOpen=true";
			if (_isReadOnly)
			{
				StatusLabel.Text = "This bundle is read-only.";
				return;
			}
			StatusLabel.Text = "DIAG: calling Touch";
			SessionManager.Instance.Touch();
			StatusLabel.Text = "Choose a file to add…";
		byte[]? bytes;
		string? name;
		try
		{
			(bytes, name) = await BundleOpener.PickImportFileAsync();
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Import failed: " + ex.Message;
			return;
		}
		if (bytes is null || name is null)
			return; // cancelled
		if (_modified.TryGetValue(name, out byte[]? old))
			CryptographicOperations.ZeroMemory(old);
		_modified[name] = bytes; // ownership transferred
		_deleted.Remove(name);
		RefreshFileList();
		UpdateDirtyUi();
		StatusLabel.Text = $"Staged {name} — tap Save bundle to write.";
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "DIAG: outer catch: " + ex.Message;
		}
	}

	/// <summary>
	/// Rebuilds the bundle with all staged changes and writes it back to
	/// the source (Files URL or HTTP PUT). The new bytes are fully
	/// re-encrypted — the veil holds.
	/// </summary>
	private async void OnSaveClicked(object? sender, EventArgs e)
	{
		if (!SessionManager.Instance.IsOpen || !IsDirty || _isReadOnly)
			return;
		SessionManager.Instance.Touch();
		var reader = SessionManager.Instance.Reader;

		StatusLabel.Text = "Rebuilding bundle…";
		byte[] newBundle;
		try
		{
			newBundle = await Task.Run(() =>
			{
				byte[] dek = reader.GetDekCopy();
				try
				{
					var files = new List<(string Path, byte[] Plaintext)>();
					foreach (var entry in reader.Files)
					{
						if (_deleted.Contains(entry.Path))
							continue;
						if (_modified.TryGetValue(entry.Path, out byte[]? mod))
							files.Add((entry.Path, mod));
						else
							files.Add((entry.Path, reader.OpenFile(entry)));
					}
					foreach (var kv in _modified)
					{
						if (!files.Any(f => f.Path == kv.Key))
							files.Add((kv.Key, kv.Value));
					}
					var header = reader.GetHeaderSnapshot();
					header.Wraps.AddRange(_pendingWraps);
					byte[] built = BundleWriter.Rebuild(header, dek, files);
					// Zero decrypted buffers we allocated (modified stay staged until cleared below).
					foreach (var f in files)
					{
						if (!_modified.ContainsKey(f.Path))
							CryptographicOperations.ZeroMemory(f.Plaintext);
					}
					return built;
				}
				finally
				{
					CryptographicOperations.ZeroMemory(dek);
				}
			});
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Rebuild failed: " + ex.Message;
			return;
		}

		// Write back.
		try
		{
			if (_sourceFileUrl is not null)
			{
				bool ok = BundleOpener.WriteBack(_sourceFileUrl, newBundle);
				StatusLabel.Text = ok ? "Saved." : "Couldn't write back to the file.";
			}
			else if (_sourceHttpUrl is not null)
			{
				using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
				using var resp = await http.PutAsync(_sourceHttpUrl, new ByteArrayContent(newBundle));
				StatusLabel.Text = resp.IsSuccessStatusCode ? "Uploaded." : $"Upload failed: {(int)resp.StatusCode}.";
			}
			else
			{
				StatusLabel.Text = "No destination — use Upload to send it somewhere.";
				return;
			}
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Write failed: " + ex.Message;
			return;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(newBundle);
		}

		// Clear staged state; re-open the new bytes so the veil continues.
		foreach (var kv in _modified)
			CryptographicOperations.ZeroMemory(kv.Value);
		_modified.Clear();
		_deleted.Clear();
		_pendingWraps.Clear();
		_editingPath = null;
		RefreshFileList();
		UpdateDirtyUi();
	}

	private async void OnUploadClicked(object? sender, EventArgs e)
	{
		if (!SessionManager.Instance.IsOpen)
			return;
		SessionManager.Instance.Touch();
		string? url = await DisplayPromptAsync("Upload bundle", "HTTPS URL to PUT the encrypted bundle to:",
			initialValue: _sourceHttpUrl ?? "");
		if (string.IsNullOrWhiteSpace(url))
			return;
		url = url.Trim();

		// Build current bytes (with staged changes if any).
		byte[] bundleBytes;
		var reader = SessionManager.Instance.Reader;
		try
		{
			bundleBytes = await Task.Run(() =>
			{
				if (!IsDirty)
				{
					// No changes: upload the original bytes. We don't keep them;
					// rebuild from the reader (identical output for unmodified files).
					byte[] dek = reader.GetDekCopy();
					try
					{
						var files = new List<(string Path, byte[] Plaintext)>();
						foreach (var entry in reader.Files)
							files.Add((entry.Path, reader.OpenFile(entry)));
						var h1 = reader.GetHeaderSnapshot(); h1.Wraps.AddRange(_pendingWraps);
						byte[] built = BundleWriter.Rebuild(h1, dek, files);
						foreach (var f in files)
							CryptographicOperations.ZeroMemory(f.Plaintext);
						return built;
					}
					finally { CryptographicOperations.ZeroMemory(dek); }
				}
				// Has staged changes: same path as Save.
				byte[] dek2 = reader.GetDekCopy();
				try
				{
					var files = new List<(string Path, byte[] Plaintext)>();
					foreach (var entry in reader.Files)
					{
						if (_deleted.Contains(entry.Path))
							continue;
						files.Add(_modified.TryGetValue(entry.Path, out byte[]? mod)
							? (entry.Path, mod)
							: (entry.Path, reader.OpenFile(entry)));
					}
					foreach (var kv in _modified)
						if (!files.Any(f => f.Path == kv.Key))
							files.Add((kv.Key, kv.Value));
					var h2 = reader.GetHeaderSnapshot(); h2.Wraps.AddRange(_pendingWraps);
					byte[] built = BundleWriter.Rebuild(h2, dek2, files);
					foreach (var f in files)
						if (!_modified.ContainsKey(f.Path))
							CryptographicOperations.ZeroMemory(f.Plaintext);
					return built;
				}
				finally { CryptographicOperations.ZeroMemory(dek2); }
			});
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Build failed: " + ex.Message;
			return;
		}

		try
		{
			using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
			using var resp = await http.PutAsync(url, new ByteArrayContent(bundleBytes));
			StatusLabel.Text = resp.IsSuccessStatusCode ? "Uploaded." : $"Upload failed: {(int)resp.StatusCode}.";
			if (resp.IsSuccessStatusCode)
				_sourceHttpUrl = url;
		}
		catch (Exception ex)
		{
			StatusLabel.Text = "Upload failed: " + ex.Message;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(bundleBytes);
		}
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

		var card = new Frame
		{
			CornerRadius = 12,
			Padding = 16,
			HasShadow = false,
			BackgroundColor = Color.FromArgb("#242424"),
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		var buttons = new HorizontalStackLayout { Spacing = 12, HorizontalOptions = LayoutOptions.Center };
		buttons.Children.Add(play);
		buttons.Children.Add(stop);
		var layout = new VerticalStackLayout { Spacing = 12, VerticalOptions = LayoutOptions.Center };
		layout.Children.Add(status);
		layout.Children.Add(buttons);
		card.Content = layout;
		return (card, player);
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

		var card = new Frame
		{
			CornerRadius = 12,
			Padding = 16,
			HasShadow = false,
			BackgroundColor = Color.FromArgb("#242424"),
			VerticalOptions = LayoutOptions.FillAndExpand,
		};
		var layout = new VerticalStackLayout { Spacing = 16, VerticalOptions = LayoutOptions.Center };
		layout.Children.Add(info);
		layout.Children.Add(export);
		card.Content = layout;
		return card;
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
		_sourceFileUrl = null;
		_sourceHttpUrl = null;
		foreach (var kv in _modified)
			CryptographicOperations.ZeroMemory(kv.Value);
		_modified.Clear();
		_deleted.Clear();
		_pendingWraps.Clear();
		_editingPath = null;
		_textEditor = null;
#endif
		PreviewContainer.Content = new Label { Text = "Select a file to preview.", HorizontalOptions = LayoutOptions.Center, VerticalOptions = LayoutOptions.Center };
		StatusLabel.Text = "No bundle open.";
#if IOS
		UpdateDirtyUi();
#endif
	}

	private void CloseReader()
	{
		SessionManager.Instance.Lock();
		ResetPreviewUi();
	}
}
