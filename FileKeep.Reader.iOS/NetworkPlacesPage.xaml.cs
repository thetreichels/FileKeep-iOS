using FileKeep.Reader.iOS.Core.Recents;
using FileKeep.Reader.iOS.Core.Smb;
using Microsoft.Maui.Storage;

namespace FileKeep.Reader.iOS;

/// <summary>
/// Browse SMB shares in-app ("Network places"): server entry +
/// remembered servers → shares → folders → .kfb files only → tap a
/// bundle to stream-download it to a temp file and hand the bytes
/// back to MainPage, which opens them through the existing bundle
/// open flow. Modal page (MainPage is not in a NavigationPage).
///
/// v1 scope: manual server entry + remembered servers; no Bonjour
/// discovery. SMB bundles open read-only (like HTTP). The password
/// lives in the Keychain (SecureStorage), never in Preferences.
/// </summary>
public partial class NetworkPlacesPage : ContentPage
{
	private sealed class SmbBrowseItem
	{
		public required string Name { get; set; }
		public required bool IsDir { get; set; }
		public required ulong Size { get; set; }
		public required string IconData { get; set; }
		public string SizeText => IsDir ? "Folder" : FormatSize(Size);
	}

	private readonly TaskCompletionSource<(byte[] Bytes, string SmbUrl)?> _selection = new();

	private SmbSession? _session;
	private string _server = "";
	private string? _share; // null = listing shares
	private string _path = ""; // share-root-relative, "" = share root
	private bool _gone;
	private int _inFlight;
	private CancellationTokenSource? _downloadCts;

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

	protected override void OnDisappearing()
	{
		base.OnDisappearing();
		_gone = true;
		_downloadCts?.Cancel();
		_selection.TrySetResult(null);
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
		ServerEntry.Text = entry.Server;
		UsernameEntry.Text = entry.Username;
		string? password = await SmbCredentials.GetPasswordAsync(entry.Server);
		if (password is null)
		{
			// No saved password: the user types it, then taps Connect.
			PasswordEntry.Text = "";
			PasswordEntry.Focus();
			return;
		}
		PasswordEntry.Text = password;
		await ConnectAsync(entry.Server, entry.Username, password);
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
		await DownloadAndReturnAsync(item);
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
