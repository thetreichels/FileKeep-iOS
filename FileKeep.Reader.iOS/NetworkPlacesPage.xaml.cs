using FileKeep.Reader.iOS.Core.Recents;
using FileKeep.Reader.iOS.Core.Smb;
using Microsoft.Maui.Storage;

namespace FileKeep.Reader.iOS;

/// <summary>
/// Browse SMB shares in-app ("Network places"): server entry +
/// remembered servers + subnet scan → shares → folders → .kfb files
/// only → tap a bundle to stream-download it to a temp file and hand
/// the bytes back to MainPage, which opens them through the existing
/// bundle open flow. Modal page (MainPage is not in a NavigationPage).
///
/// Discovery is a subnet scan for TCP 445 (SmbDiscovery, ported from
/// the desktop recovery wizard): no Bonjour, no WS-Discovery, no new
/// entitlement. A found host fills the server field and connects the
/// same way a remembered server does; shares then enumerate over the
/// authenticated session (srvsvc) as before. SMB bundles are editable:
/// Save writes back through this same browser in save mode
/// (NetworkPlacesPage.ForSave), which uploads the rebuilt encrypted
/// bundle bytes to the picked share and folder. The password lives in
/// the Keychain (SecureStorage), never in Preferences.
/// </summary>
public partial class NetworkPlacesPage : ContentPage
{
	private sealed class SmbBrowseItem
	{
		public required string Name { get; set; }
		public required bool IsDir { get; set; }
		public required ulong Size { get; set; }
		public required string IconData { get; set; }
		public string SizeText => IsHost
			? (Name == HostAddress ? "SMB server" : HostAddress)
			: IsDir ? "Folder" : FormatSize(Size);
		/// <summary>True for a scanned host row (pre-connect): tapping it picks the server.</summary>
		public bool IsHost { get; set; }
		public string HostAddress { get; set; } = "";
	}

	private readonly TaskCompletionSource<(byte[] Bytes, string SmbUrl)?> _selection = new();
	private readonly TaskCompletionSource<string?> _saveSelection = new();

	// Save mode: the page uploads bytes instead of downloading them.
	private bool _saveMode;
	private string _saveFileName = "";
	private byte[] _saveBytes = Array.Empty<byte>();

	private SmbSession? _session;
	private string _server = "";
	private string? _share; // null = listing shares
	private string _path = ""; // share-root-relative, "" = share root
	private bool _gone;
	private int _inFlight;
	private CancellationTokenSource? _downloadCts;
	private CancellationTokenSource? _scanCts;

	/// <summary>
	/// <paramref name="smbUrl"/> pre-fills the server (and the
	/// remembered username) when reopening an SMB bundle whose saved
	/// sign-in expired — the user just types the password and taps
	/// Connect. Null for a fresh browse.
	/// </summary>
	public NetworkPlacesPage(string? smbUrl = null)
	{
		InitializeComponent();
		RefreshSavedServers();
		if (smbUrl is not null && SmbUrl.TryParse(smbUrl, out string server, out _, out _))
		{
			ServerEntry.Text = server;
			string? username = SmbCredentials.LoadServers()
				.FirstOrDefault(s => string.Equals(s.Server, server, StringComparison.OrdinalIgnoreCase))?.Username;
			if (!string.IsNullOrEmpty(username))
				UsernameEntry.Text = username;
		}
	}

	/// <summary>
	/// The chosen bundle's bytes + its smb:// URL, or null when the
	/// user closed the page without choosing one.
	/// </summary>
	public Task<(byte[] Bytes, string SmbUrl)?> WaitForSelectionAsync() => _selection.Task;

	/// <summary>
	/// Builds the page in save mode: the user picks a share + folder
	/// and the page uploads <paramref name="bytes"/> there under
	/// <paramref name="fileName"/> (the current bundle name).
	/// </summary>
	public static NetworkPlacesPage ForSave(string fileName, byte[] bytes)
	{
		var page = new NetworkPlacesPage();
		page._saveMode = true;
		page._saveFileName = fileName;
		page._saveBytes = bytes;
		page.SaveFileEntry.Text = fileName;
		page.SaveFileEntry.IsVisible = true;
		page.BrowseHintLabel.Text = "Pick a folder and tap Save here — or tap a bundle name to reuse it.";
		return page;
	}

	/// <summary>
	/// The smb:// URL the bundle was saved to, or null when the user
	/// closed the page without saving.
	/// </summary>
	public Task<string?> WaitForSaveAsync() => _saveSelection.Task;

	protected override void OnDisappearing()
	{
		base.OnDisappearing();
		_gone = true;
		_downloadCts?.Cancel();
		_scanCts?.Cancel();
		_selection.TrySetResult(null);
		_saveSelection.TrySetResult(null);
		DisposeSessionIfGone();
	}

	private async void OnCloseClicked(object? sender, EventArgs e)
	{
		await Navigation.PopModalAsync();
	}

	private void RefreshSavedServers()
	{
		var servers = SmbCredentials.LoadServers();
		SavedServersLabel.IsVisible = servers.Count > 0;
		SavedServersPicker.IsVisible = servers.Count > 0;
		SavedServersPicker.ItemsSource = servers;
		SavedServersPicker.ItemDisplayBinding = new Binding("Server");
	}

	private async void OnSavedServerSelected(object? sender, EventArgs e)
	{
		if (SavedServersPicker.SelectedItem is not SmbServerEntry entry)
			return;
		SavedServersPicker.SelectedItem = null;
		await PickServerAsync(entry.Server);
	}

	/// <summary>
	/// Fill the server field from a saved or scanned server; when the
	/// password is in the Keychain, connect straight away, otherwise
	/// the user types the password and taps Connect.
	/// </summary>
	private async Task PickServerAsync(string server)
	{
		ServerEntry.Text = server;
		string username = SmbCredentials.LoadServers()
			.FirstOrDefault(s => string.Equals(s.Server, server, StringComparison.OrdinalIgnoreCase))?.Username ?? "";
		UsernameEntry.Text = username;
		string? password = await SmbCredentials.GetPasswordAsync(server);
		if (password is null)
		{
			// No saved password: the user types it, then taps Connect.
			PasswordEntry.Text = "";
			PasswordEntry.Focus();
			return;
		}
		PasswordEntry.Text = password;
		await ConnectAsync(server, username, password);
	}

	/// <summary>
	/// Scan the local subnet for SMB hosts and list them as rows: tap
	/// one to pick that server. Progress runs in the status label;
	/// the scan is cancellable.
	/// </summary>
	private async void OnScanClicked(object? sender, EventArgs e)
	{
		_scanCts?.Cancel();
		var cts = new CancellationTokenSource();
		_scanCts = cts;
		ScanButton.IsEnabled = false;
		CancelScanButton.IsVisible = true;
		SetStatus("Scanning this network…", isError: false);
		try
		{
			// Progress<T> was created on the UI thread, so Report
			// marshals back to it.
			var progress = new Progress<(int Done, int Total)>(p =>
				SetStatus($"Scanning this network… {p.Done} of {p.Total}", isError: false));
			IReadOnlyList<SmbDiscovery.DiscoveredHost> hosts =
				await new SmbDiscovery().DiscoverAsync(progress, cts.Token);
			if (_gone)
				return;
			if (hosts.Count == 0)
			{
				SetStatus("No SMB servers found on this network.", isError: false);
				return;
			}
			PathLabel.Text = "Found on this network";
			BackButton.IsVisible = _share is not null;
			SaveHereButton.IsVisible = _saveMode && _share is not null;
			BrowseView.ItemsSource = hosts.Select(h => new SmbBrowseItem
			{
				Name = h.HostName ?? h.HostAddress,
				IsDir = false,
				Size = 0,
				IconData = RecentBundleStore.IconServerData,
				IsHost = true,
				HostAddress = h.HostAddress,
			}).ToList();
			SetStatus($"{hosts.Count} SMB server{(hosts.Count == 1 ? "" : "s")} found — tap one to connect.", isError: false);
		}
		catch (OperationCanceledException)
		{
			SetStatus("Scan cancelled.", isError: false);
		}
		catch (Exception ex)
		{
			SetStatus("Scan failed: " + ex.Message, isError: true);
		}
		finally
		{
			ScanButton.IsEnabled = true;
			CancelScanButton.IsVisible = false;
			cts.Dispose();
			if (_scanCts == cts)
				_scanCts = null;
		}
	}

	private void OnCancelScanClicked(object? sender, EventArgs e)
	{
		_scanCts?.Cancel();
	}

	private async void OnConnectClicked(object? sender, EventArgs e)
	{
		string server = ServerEntry.Text?.Trim() ?? "";
		string username = UsernameEntry.Text?.Trim() ?? "";
		string password = PasswordEntry.Text ?? "";
		if (string.IsNullOrEmpty(server))
		{
			SetStatus("Enter a server name or IP address.", isError: true);
			return;
		}
		await ConnectAsync(server, username, password);
	}

	private async Task ConnectAsync(string server, string username, string password)
	{
		ConnectButton.IsEnabled = false;
		SetStatus("Connecting…", isError: false);
		try
		{
			SmbSession session = await TrackAsync(() => SmbSession.ConnectAsync(server, username, password));
			if (_gone)
			{
				// The page went away mid-connect: free the new session
				// now instead of leaving it for the finalizer.
				session.Dispose();
				return;
			}
			_session?.Dispose();
			_session = session;
			_server = server;
			_share = null;
			_path = "";
			SmbCredentials.RememberServer(server, username);
			await SmbCredentials.SavePasswordAsync(server, password);
			RefreshSavedServers();
			SetStatus("", isError: false);
			await ShowSharesAsync();
		}
		catch (Exception ex)
		{
			SetStatus("Connection failed: " + ex.Message, isError: true);
		}
		finally
		{
			ConnectButton.IsEnabled = true;
		}
	}

	private async Task ShowSharesAsync()
	{
		if (_session is null)
			return;
		List<string> shares;
		try
		{
			shares = (await TrackAsync(() => _session.ListSharesAsync())).ToList();
			shares.Sort(StringComparer.OrdinalIgnoreCase);
		}
		catch (Exception ex)
		{
			// Enumeration refused (or empty below): fall back to a typed
			// share name instead of leaving the user stuck.
			shares = new List<string>();
			SetStatus("Could not list shares: " + ex.Message, isError: true);
		}
		if (shares.Count == 0)
		{
			string? share = await DisplayPromptAsync("Share name",
				"This server did not list its shares. Type the share name:");
			if (string.IsNullOrWhiteSpace(share))
			{
				SetStatus("No shares listed — type the share name to continue.", isError: true);
				return;
			}
			await OpenShareAsync(share.Trim());
			return;
		}
		PathLabel.Text = $"{_server} — shares";
		BackButton.IsVisible = false;
		SaveHereButton.IsVisible = false; // No folder picked yet in save mode.
		BrowseView.ItemsSource = shares.Select(s => new SmbBrowseItem
		{
			Name = s,
			IsDir = true,
			Size = 0,
			IconData = RecentBundleStore.IconFolderData,
		}).ToList();
	}

	private async Task OpenShareAsync(string share)
	{
		if (_session is null)
			return;
		try
		{
			await TrackAsync(() => _session.ConnectShareAsync(share));
			_share = share;
			_path = "";
			await ShowDirectoryAsync("");
		}
		catch (Exception ex)
		{
			SetStatus("Could not open share: " + ex.Message, isError: true);
		}
	}

	private async Task ShowDirectoryAsync(string path)
	{
		if (_session is null || _share is null)
			return;
		IReadOnlyList<SmbDirEntry> entries;
		try
		{
			entries = await TrackAsync(() => _session.ListDirectoryAsync(path));
		}
		catch (Exception ex)
		{
			SetStatus("Could not list this folder: " + ex.Message, isError: true);
			return;
		}
		SetStatus("", isError: false);
		PathLabel.Text = SmbUrl.Format(_server, _share, path);
		BackButton.IsVisible = true;
		SaveHereButton.IsVisible = _saveMode; // Inside a share: a save target exists.
		var items = entries
			.Where(en => en.IsDir || en.Name.EndsWith(".kfb", StringComparison.OrdinalIgnoreCase))
			.OrderByDescending(en => en.IsDir)
			.ThenBy(en => en.Name, StringComparer.OrdinalIgnoreCase)
			.Select(en => new SmbBrowseItem
			{
				Name = en.Name,
				IsDir = en.IsDir,
				Size = en.Size,
				IconData = en.IsDir ? RecentBundleStore.IconFolderData : RecentBundleStore.IconLockData,
			})
			.ToList();
		BrowseView.ItemsSource = items;
	}

	private async void OnBrowseSelected(object? sender, SelectionChangedEventArgs e)
	{
		if (e.CurrentSelection.FirstOrDefault() is not SmbBrowseItem item)
			return;
		BrowseView.SelectedItem = null;
		if (item.IsHost)
		{
			// Scanned host row: pick that server (connects the same
			// way a remembered server does).
			await PickServerAsync(item.HostAddress);
			return;
		}
		if (_share is null)
		{
			// Listing shares: the row is a share name.
			await OpenShareAsync(item.Name);
			return;
		}
		if (item.IsDir)
		{
			_path = JoinPath(_path, item.Name);
			await ShowDirectoryAsync(_path);
			return;
		}
		if (_saveMode)
		{
			// Save mode: tapping a bundle reuses its name for the
			// save instead of downloading it.
			SaveFileEntry.Text = item.Name;
			return;
		}
		await DownloadAndReturnAsync(item);
	}

	/// <summary>
	/// Save mode: uploads the bytes to the current folder under the
	/// name in the filename entry, confirming an overwrite against
	/// the current directory listing, then hands the smb:// URL back
	/// to MainPage and closes.
	/// </summary>
	private async void OnSaveHereClicked(object? sender, EventArgs e)
	{
		if (_session is null || _share is null)
			return;
		string fileName = SaveFileEntry.Text?.Trim() ?? "";
		if (string.IsNullOrEmpty(fileName))
		{
			SetStatus("Enter a filename to save as.", isError: true);
			return;
		}
		if (!fileName.EndsWith(".kfb", StringComparison.OrdinalIgnoreCase))
			fileName += ".kfb";
		string remotePath = JoinPath(_path, fileName);
		// Overwrite check against the current directory listing
		// (best-effort: the listing can be stale).
		bool exists = BrowseView.ItemsSource is IEnumerable<SmbBrowseItem> items &&
			items.Any(i => !i.IsDir && string.Equals(i.Name, fileName, StringComparison.OrdinalIgnoreCase));
		if (exists)
		{
			bool replace = await DisplayAlert("Replace file?",
				$"{fileName} already exists in this folder. Replace it?", "Replace", "Cancel");
			if (!replace)
				return;
		}
		SaveHereButton.IsEnabled = false;
		SetStatus($"Saving {fileName}…", isError: false);
		try
		{
			await TrackAsync(() => _session.UploadFileAsync(remotePath, _saveBytes));
			if (_gone)
				return;
			_saveSelection.TrySetResult(SmbUrl.Format(_server, _share, remotePath));
			await Navigation.PopModalAsync();
		}
		catch (Exception ex)
		{
			SetStatus("Save failed: " + ex.Message, isError: true);
		}
		finally
		{
			SaveHereButton.IsEnabled = true;
		}
	}

	private async void OnBackClicked(object? sender, EventArgs e)
	{
		if (_share is null)
			return;
		if (!string.IsNullOrEmpty(_path))
		{
			_path = ParentPath(_path);
			await ShowDirectoryAsync(_path);
			return;
		}
		_share = null;
		_path = "";
		await ShowSharesAsync();
	}

	private async Task DownloadAndReturnAsync(SmbBrowseItem item)
	{
		if (_session is null || _share is null)
			return;
		string remotePath = JoinPath(_path, item.Name);
		string smbUrl = SmbUrl.Format(_server, _share, remotePath);
		string temp = Path.Combine(FileSystem.CacheDirectory, "smb-" + Guid.NewGuid().ToString("N") + ".kfb");
		_downloadCts = new CancellationTokenSource();
		DownloadProgress.IsVisible = true;
		DownloadProgress.Progress = 0;
		DownloadStatusLabel.IsVisible = true;
		DownloadStatusLabel.Text = $"Downloading {item.Name}…";
		CancelDownloadButton.IsVisible = true;
		try
		{
			// Progress<T> was created on the UI thread, so Report
			// marshals back to it; the callback itself runs on the
			// FFI pool thread and just reports + checks cancellation.
			var progress = new Progress<(long Received, long Total)>(p =>
			{
				DownloadProgress.Progress = p.Total > 0 ? (double)p.Received / p.Total : 0;
				DownloadStatusLabel.Text = $"Downloading {item.Name} — {FormatSize(p.Received)} of {FormatSize(p.Total)}";
			});
			await TrackAsync(() => _session.DownloadFileAsync(remotePath, temp, progress, _downloadCts.Token));
			// The existing open flow takes bytes, so the streamed temp
			// file is read here (same as the HTTP path) and deleted.
			byte[] bytes = await File.ReadAllBytesAsync(temp);
			if (_gone)
				return;
			_selection.TrySetResult((bytes, smbUrl));
			await Navigation.PopModalAsync();
		}
		catch (OperationCanceledException)
		{
			SetStatus("Download cancelled.", isError: false);
		}
		catch (Exception ex)
		{
			SetStatus("Download failed: " + ex.Message, isError: true);
		}
		finally
		{
			_downloadCts?.Dispose();
			_downloadCts = null;
			DownloadProgress.IsVisible = false;
			DownloadStatusLabel.IsVisible = false;
			CancelDownloadButton.IsVisible = false;
			try
			{
				File.Delete(temp);
			}
			catch
			{
				// Temp cleanup is best-effort.
			}
		}
	}

	private void OnCancelDownloadClicked(object? sender, EventArgs e)
	{
		_downloadCts?.Cancel();
	}

	/// <summary>
	/// Counts an in-flight FFI operation so the session is only
	/// disposed once nothing is using its native handle (the
	/// disconnect would otherwise block on the session mutex, or
	/// free a handle a download is still using).
	/// </summary>
	private async Task<T> TrackAsync<T>(Func<Task<T>> op)
	{
		Interlocked.Increment(ref _inFlight);
		try
		{
			return await op();
		}
		finally
		{
			Interlocked.Decrement(ref _inFlight);
			DisposeSessionIfGone();
		}
	}

	private async Task TrackAsync(Func<Task> op)
	{
		Interlocked.Increment(ref _inFlight);
		try
		{
			await op();
		}
		finally
		{
			Interlocked.Decrement(ref _inFlight);
			DisposeSessionIfGone();
		}
	}

	private void DisposeSessionIfGone()
	{
		if (_gone && _inFlight == 0)
		{
			_session?.Dispose();
			_session = null;
		}
	}

	private void SetStatus(string text, bool isError)
	{
		StatusLabel.Text = text;
		StatusLabel.TextColor = StatusColor(isError ? "StatusError" : "TextSecondary",
			isError ? "#F1707B" : "#A7A7A7");
	}

	private static Color StatusColor(string key, string fallback)
	{
		if (Application.Current?.Resources.TryGetValue(key, out object? value) == true &&
			value is Color color)
		{
			return color;
		}
		return Color.FromArgb(fallback);
	}

	private static string JoinPath(string parent, string name) =>
		string.IsNullOrEmpty(parent) ? name : parent + "/" + name;

	private static string ParentPath(string path)
	{
		int slash = path.LastIndexOf('/');
		return slash < 0 ? "" : path.Substring(0, slash);
	}

	private static string FormatSize(ulong bytes) =>
		bytes switch
		{
			< 1024 => $"{bytes} B",
			< 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
			< 1024UL * 1024 * 1024 => $"{bytes / 1024.0 / 1024:0.#} MB",
			_ => $"{bytes / 1024.0 / 1024 / 1024:0.#} GB",
		};

	private static string FormatSize(long bytes) => FormatSize((ulong)Math.Max(0, bytes));
}
