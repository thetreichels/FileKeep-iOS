using Foundation;
using LocalAuthentication;
using Security;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Face ID convenience unlock, backed by the iOS Keychain.
///
/// First open of a bundle takes the typed export passphrase; the unwrapped
/// DEK is then stored as a generic-password item gated by a biometric
/// access control (`BiometryCurrentSet`, `WhenUnlockedThisDeviceOnly`,
/// device-only, never synced). Later opens read the DEK straight out of
/// the Keychain — iOS presents the Face ID prompt itself on read.
///
/// MAUI's SecureStorage is string-only with no SecAccessControl, so this
/// wrapper exists instead (~the research-stage plan, as built).
///
/// A non-sensitive enrollment marker (bundle fingerprints) lives in
/// NSUserDefaults so we only trigger a Face ID prompt for bundles the
/// user actually enrolled. If biometrics change, `BiometryCurrentSet`
/// invalidates the item: the read fails, we drop the stale enrollment,
/// and the next open falls back to the passphrase and re-enrolls.
/// </summary>
public static class BiometricKeychain
{
	private const string Service = "com.filekeep.reader.dek";
	private const string EnrolledKey = "com.filekeep.reader.enrolledBundles";

	/// <summary>Whether this device can do a biometric unlock right now.</summary>
	public static bool CanUseBiometrics()
	{
		using var ctx = new LAContext();
		return ctx.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out _);
	}

	public static bool IsEnrolled(string fingerprint)
	{
		var arr = NSUserDefaults.StandardUserDefaults.StringArrayForKey(EnrolledKey);
		return arr?.Contains(fingerprint) == true;
	}

	public static void MarkEnrolled(string fingerprint)
	{
		var defaults = NSUserDefaults.StandardUserDefaults;
		var list = (defaults.StringArrayForKey(EnrolledKey) ?? Array.Empty<string>()).ToList();
		if (!list.Contains(fingerprint))
		{
			list.Add(fingerprint);
			using var arr = NSArray.FromStrings(list.ToArray());
			defaults.SetValueForKey(arr, new NSString(EnrolledKey));
		}
	}

	public static void UnmarkEnrolled(string fingerprint)
	{
		var defaults = NSUserDefaults.StandardUserDefaults;
		var list = (defaults.StringArrayForKey(EnrolledKey) ?? Array.Empty<string>()).ToList();
		if (list.Remove(fingerprint))
		{
			using var arr = NSArray.FromStrings(list.ToArray());
			defaults.SetValueForKey(arr, new NSString(EnrolledKey));
		}
	}

	/// <summary>
	/// Stores a copy of the DEK under a biometric access control.
	/// Returns false when the device can't make the access control
	/// (e.g. simulator) — the caller then simply doesn't enroll.
	/// </summary>
	public static bool StoreDek(string fingerprint, byte[] dek)
	{
		// No static Create in this binding — the constructor calls
		// SecAccessControlCreateWithFlags and yields a zero handle on failure
		// (e.g. no biometry enrolled).
		SecAccessControl access;
		try
		{
			access = new SecAccessControl(
				SecAccessible.WhenUnlockedThisDeviceOnly,
				SecAccessControlCreateFlags.BiometryCurrentSet);
		}
		catch
		{
			return false;
		}
		if (access.Handle == IntPtr.Zero)
			return false;

		using (access)
		{
			var query = new SecRecord(SecKind.GenericPassword)
			{
				Service = Service,
				Account = fingerprint,
			};
			// Drop any stale entry (re-wrap after a previous enrollment).
			SecKeyChain.Remove(query);

			using var data = NSData.FromArray(dek);
			var record = new SecRecord(SecKind.GenericPassword)
			{
				Service = Service,
				Account = fingerprint,
				ValueData = data,
				Accessible = SecAccessible.WhenUnlockedThisDeviceOnly,
				AccessControl = access,
			};
			return SecKeyChain.Add(record) == SecStatusCode.Success;
		}
	}

	/// <summary>
	/// Reads the DEK. iOS presents the Face ID prompt on read because of
	/// the item's access control. Returns null when there is no item, the
	/// user cancels, or biometrics changed (item invalidated).
	/// </summary>
	public static byte[]? TryReadDek(string fingerprint)
	{
		var query = new SecRecord(SecKind.GenericPassword)
		{
			Service = Service,
			Account = fingerprint,
		};
		// The data comes back as the return value; the out param is the status.
		var data = SecKeyChain.QueryAsData(query, false, out var status);
		if (status != SecStatusCode.Success || data is null)
			return null;
		try
		{
			return data.ToArray();
		}
		finally
		{
			data.Dispose();
		}
	}

	public static void DeleteDek(string fingerprint)
	{
		SecKeyChain.Remove(new SecRecord(SecKind.GenericPassword)
		{
			Service = Service,
			Account = fingerprint,
		});
	}
}
