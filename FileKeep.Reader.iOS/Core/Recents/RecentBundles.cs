using System.Text.Json;
using FileKeep.Reader.iOS.Core.Bundle;

namespace FileKeep.Reader.iOS.Core.Recents;

/// <summary>
/// One row of the "My Bundles" vault list: a bundle the user opened or
/// saved, with its lock-method badge and its content icon derived from
/// the header at record time (no unlocking needed to show either).
/// </summary>
public sealed class RecentBundle
{
	public string Name { get; set; } = "";
	/// <summary>Files: full file path. HTTP: the URL. SMB: the smb:// URL. "" when never saved.</summary>
	public string Source { get; set; } = "";
	public bool IsHttp { get; set; }
	/// <summary>True for an SMB bundle (Source is an smb:// URL). Re-downloads with the remembered sign-in.</summary>
	public bool IsSmb { get; set; }
	/// <summary>
	/// Security-scoped bookmark (base64) for a Files bundle, so tapping
	/// the row can reopen it across launches. "" when none was captured
	/// (HTTP sources, or an older entry recorded without one).
	/// </summary>
	public string BookmarkB64 { get; set; } = "";
	/// <summary>"Passphrase", "YubiKey", "Passkey", or "Layered".</summary>
	public string BadgeMethod { get; set; } = "Layered";
	/// <summary>
	/// Row icon Path Data (26x26 space, 1.9pt stroke), derived from the
	/// bundle's file types at record time. Defaults to the lock so rows
	/// recorded by earlier versions (deserialized without this field)
	/// still show an icon.
	/// </summary>
	public string IconData { get; set; } = RecentBundleStore.IconLockData;
	public int FileCount { get; set; }
	public DateTimeOffset ModifiedUtc { get; set; }

	public string FileCountText => FileCount == 1 ? "1 file" : $"{FileCount} files";
	public string ModifiedText => ModifiedUtc.ToLocalTime().ToString("MMM d, yyyy");

	/// <summary>
	/// Badge text color on the white pill: the color-wheel merging idea,
	/// red + blue = purple, in vivid hues obvious at a glance. The purple
	/// is deliberately far from the blue so the mix reads immediately.
	/// Passkey is vivid green, distinct from all three.
	/// </summary>
	public Color BadgeColor => BadgeMethod switch
	{
		"Passphrase" => Color.FromArgb("#FF0000"),
		"YubiKey" => Color.FromArgb("#0066FF"),
		"Passkey" => Color.FromArgb("#00CC00"),
		_ => Color.FromArgb("#AF00FF"),
	};
}

/// <summary>
/// Persists the vault list in MAUI Preferences as a JSON list, newest first.
/// Best-effort: a storage failure must never break an open/save flow.
/// </summary>
public static class RecentBundleStore
{
	private const string Key = "recent_bundles_v1";
	private const int MaxItems = 30;

	public static List<RecentBundle> Load()
	{
		try
		{
			string json = Microsoft.Maui.Storage.Preferences.Get(Key, "");
			if (string.IsNullOrWhiteSpace(json))
				return new List<RecentBundle>();
			return JsonSerializer.Deserialize<List<RecentBundle>>(json) ?? new List<RecentBundle>();
		}
		catch
		{
			return new List<RecentBundle>();
		}
	}

	public static void Record(RecentBundle item)
	{
		var list = Load();
		if (!string.IsNullOrEmpty(item.Source))
			list.RemoveAll(r => r.Source == item.Source);
		list.Insert(0, item);
		if (list.Count > MaxItems)
			list.RemoveRange(MaxItems, list.Count - MaxItems);
		try
		{
			Microsoft.Maui.Storage.Preferences.Set(Key, JsonSerializer.Serialize(list));
		}
		catch
		{
			// Recents are best-effort; ignore storage failures.
		}
	}

	/// <summary>
	/// Derives the badge method from the bundle header only (no unlock):
	/// exactly one OR wrap of type passphrase → Passphrase; exactly one
	/// OR wrap of type yubikey-hmac-sha1 → YubiKey; exactly one OR wrap
	/// of type passkey-prf → Passkey; anything else (multiple options,
	/// AND groups, or an unreadable header) → Layered.
	/// </summary>
	public static string BadgeMethodFor(byte[] bundleBytes)
	{
		if (BundleReader.TryGetLayers(bundleBytes, out var orWraps, out var andGroups) &&
			andGroups.Count == 0 && orWraps.Count == 1)
		{
			string type = orWraps[0].Type;
			if (string.Equals(type, "passphrase", StringComparison.OrdinalIgnoreCase))
				return "Passphrase";
			if (string.Equals(type, "yubikey-hmac-sha1", StringComparison.OrdinalIgnoreCase))
				return "YubiKey";
			if (string.Equals(type, "passkey-prf", StringComparison.OrdinalIgnoreCase))
				return "Passkey";
		}
		return "Layered";
	}

	/// <summary>
	/// Row icon Path Data, in 26x26 space (1.9pt stroke, round caps and
	/// joins), matching the tab-bar vector icons. One per content
	/// category; the lock is also the fallback for unreadable rows.
	/// </summary>
	public const string IconLockData = "M 9.75,13 L 9.75,8.94 A 3.25,4.6 0 0 1 13,4.33 A 3.25,4.6 0 0 1 16.25,8.94 L 16.25,13 M 9.75,13 L 16.25,13 A 2.17,2.17 0 0 1 18.42,15.17 L 18.42,19.5 A 2.17,2.17 0 0 1 16.25,21.67 L 9.75,21.67 A 2.17,2.17 0 0 1 7.58,19.5 L 7.58,15.17 A 2.17,2.17 0 0 1 9.75,13 Z";
	public const string IconPhotoData = "M 7,7 L 19,7 A 2,2 0 0 1 21,9 L 21,17 A 2,2 0 0 1 19,19 L 7,19 A 2,2 0 0 1 5,17 L 5,9 A 2,2 0 0 1 7,7 Z M 7,10.5 A 2,2 0 0 1 9,8.5 A 2,2 0 0 1 11,10.5 A 2,2 0 0 1 9,12.5 A 2,2 0 0 1 7,10.5 Z M 5,19 L 9.5,13.5 L 12,16 L 15,12.5 L 21,19";
	public const string IconFolderData = "M 4,9 L 9,9 L 10.5,6 L 15.5,6 L 17,9 L 22,9 L 22,18 A 2,2 0 0 1 20,20 L 6,20 A 2,2 0 0 1 4,18 Z";
	public const string IconServerData = "M 4,5 L 22,5 L 22,17 L 4,17 Z M 10,21 L 16,21 M 13,17 L 13,21";
	public const string IconLayersData = "M 13,4.75 L 21,8.25 L 13,11.75 L 5,8.25 Z M 13,9.5 L 21,13.0 L 13,16.5 L 5,13.0 Z M 13,14.25 L 21,17.75 L 13,21.25 L 5,17.75 Z";

	/// <summary>
	/// Row icon for an open bundle, from its file list (no unlock
	/// needed): the file extensions are grouped into categories — media
	/// (photos and videos as one type), documents, anything else
	/// ("other", including audio). Exactly one category present → that
	/// category's icon; two or more → the stacked-layers "mixed" icon;
	/// no files → the lock.
	/// </summary>
	public static string IconDataForFiles(IEnumerable<BundleFileEntry> files)
	{
		var kinds = new HashSet<string>(StringComparer.Ordinal);
		foreach (BundleFileEntry file in files)
			kinds.Add(CategoryFor(file.Path));
		if (kinds.Count > 1)
			return IconLayersData;
		if (kinds.Count == 1)
		{
			if (kinds.Contains("media"))
				return IconPhotoData;
			if (kinds.Contains("documents"))
				return IconFolderData;
		}
		return IconLockData;
	}

	private static string CategoryFor(string path)
	{
		string ext = Path.GetExtension(path ?? string.Empty).ToLowerInvariant();
		return ext switch
		{
			".jpg" or ".jpeg" or ".png" or ".gif" or ".webp" or ".heic" or ".heif" or ".bmp" or ".tif" or ".tiff" or ".svg"
				or ".mp4" or ".mov" or ".m4v" or ".avi" or ".mkv" or ".webm" => "media",
			".pdf" or ".doc" or ".docx" or ".xls" or ".xlsx" or ".ppt" or ".pptx" or ".txt" or ".md" or ".csv" or ".rtf" or ".odt" or ".ods" or ".odp" => "documents",
			_ => "other",
		};
	}
}
