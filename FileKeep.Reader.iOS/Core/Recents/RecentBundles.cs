using System.Text.Json;
using FileKeep.Reader.iOS.Core.Bundle;

namespace FileKeep.Reader.iOS.Core.Recents;

/// <summary>
/// One row of the "My Bundles" vault list: a bundle the user opened or
/// saved, with its lock-method badge derived from the header at record
/// time (no unlocking needed to show the badge).
/// </summary>
public sealed class RecentBundle
{
	public string Name { get; set; } = "";
	/// <summary>Files: full file path. HTTP: the URL. "" when never saved.</summary>
	public string Source { get; set; } = "";
	public bool IsHttp { get; set; }
	/// <summary>
	/// Security-scoped bookmark (base64) for a Files bundle, so tapping
	/// the row can reopen it across launches. "" when none was captured
	/// (HTTP sources, or an older entry recorded without one).
	/// </summary>
	public string BookmarkB64 { get; set; } = "";
	/// <summary>"Passphrase", "YubiKey", or "Layered".</summary>
	public string BadgeMethod { get; set; } = "Layered";
	public int FileCount { get; set; }
	public DateTimeOffset ModifiedUtc { get; set; }

	public string FileCountText => FileCount == 1 ? "1 file" : $"{FileCount} files";
	public string ModifiedText => ModifiedUtc.ToLocalTime().ToString("MMM d, yyyy");

	/// <summary>
	/// Badge text color on the white pill: the color-wheel merging idea,
	/// red + blue = purple, in vivid hues obvious at a glance. The purple
	/// is deliberately far from the blue so the mix reads immediately.
	/// </summary>
	public Color BadgeColor => BadgeMethod switch
	{
		"Passphrase" => Color.FromArgb("#FF0000"),
		"YubiKey" => Color.FromArgb("#0066FF"),
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
	/// OR wrap of type yubikey-hmac-sha1 → YubiKey; anything else
	/// (multiple options, AND groups, or an unreadable header) → Layered.
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
		}
		return "Layered";
	}
}
