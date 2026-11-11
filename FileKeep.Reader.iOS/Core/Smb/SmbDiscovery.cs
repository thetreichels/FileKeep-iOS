using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace FileKeep.Reader.iOS.Core.Smb;

/// <summary>
/// Discovers SMB hosts on the local network, ported from the desktop
/// recovery wizard's SmbDiscovery (FileKeep.Core, commit 9182793):
///
/// 1. Enumerate local IPv4 interfaces and compute their subnets.
/// 2. Probe TCP 445 (SMB) on every address in each subnet, in parallel.
///
/// Unlike the desktop version this stops at hosts: share enumeration
/// needs credentials, and on iOS it happens after connect through the
/// existing Rust FFI (SmbSession.ListSharesAsync, srvsvc). A found
/// host is handed to NetworkPlacesPage, which fills the server field
/// and connects the same way a remembered server does.
///
/// No multicast, no Bonjour, no new entitlement — plain TCP connects
/// on the LAN the app already talks SMB on.
/// </summary>
public sealed class SmbDiscovery
{
	public sealed record DiscoveredHost(
		string HostAddress,
		string? HostName);

	private readonly Action<string>? _log;

	public SmbDiscovery(Action<string>? log = null)
	{
		_log = log;
	}

	/// <summary>
	/// Scans local subnets for SMB hosts. <paramref name="progress"/>
	/// receives (hostsScanned, hostsTotal). Only scans subnets with a
	/// prefix length of /20 or longer (scanning anything larger would
	/// take unreasonable time; a /16 has 65k hosts).
	/// </summary>
	public async Task<IReadOnlyList<DiscoveredHost>> DiscoverAsync(
		IProgress<(int Done, int Total)>? progress = null,
		CancellationToken cancellationToken = default)
	{
		var targets = GetScanTargets().ToList();
		_log?.Invoke($"SMB discovery: scanning {targets.Count} addresses.");
		int done = 0;
		var smbHosts = new ConcurrentBag<IPAddress>();

		// Probe port 445 in parallel batches.
		var options = new ParallelOptions
		{
			MaxDegreeOfParallelism = 64,
			CancellationToken = cancellationToken,
		};
		await Parallel.ForEachAsync(targets, options, async (ip, ct) =>
		{
			if (await IsSmbPortOpenAsync(ip, ct))
				smbHosts.Add(ip);
			int d = Interlocked.Increment(ref done);
			if (d % 16 == 0) progress?.Report((d, targets.Count));
		});
		progress?.Report((targets.Count, targets.Count));

		var results = new List<DiscoveredHost>();
		foreach (IPAddress ip in smbHosts.OrderBy(a => a.ToString(), StringComparer.Ordinal))
		{
			cancellationToken.ThrowIfCancellationRequested();
			string addr = ip.ToString();
			string? hostName = await TryResolveHostnameAsync(ip, cancellationToken);
			results.Add(new DiscoveredHost(addr, hostName));
		}
		_log?.Invoke($"SMB discovery: {results.Count} SMB host(s) found.");
		return results;
	}

	/// <summary>
	/// All IPv4 host addresses in local subnets (/20 or smaller), excluding
	/// the local addresses themselves, network, and broadcast.
	/// </summary>
	internal static IEnumerable<IPAddress> GetScanTargets()
	{
		foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
		{
			if (nic.OperationalStatus != OperationalStatus.Up)
				continue;
			if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
				continue;
			var props = nic.GetIPProperties();
			foreach (var unicast in props.UnicastAddresses)
			{
				if (unicast.Address.AddressFamily != AddressFamily.InterNetwork)
					continue;
				if (unicast.IPv4Mask is null)
					continue;
				int prefix = MaskToPrefix(unicast.IPv4Mask);
				if (prefix < 20)
					continue; // too big to scan (/16 = 65k hosts)
				uint mask = ToUInt32(unicast.IPv4Mask);
				uint addr = ToUInt32(unicast.Address);
				uint network = addr & mask;
				uint broadcast = network | ~mask;
				for (uint host = network + 1; host < broadcast; host++)
				{
					if (host == addr)
						continue;
					yield return new IPAddress(BitConverter.GetBytes(host).Reverse().ToArray());
				}
			}
		}
	}

	private static async Task<bool> IsSmbPortOpenAsync(IPAddress ip, CancellationToken ct)
	{
		using var client = new TcpClient();
		try
		{
			using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
			using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
			await client.ConnectAsync(ip, 445, linked.Token);
			return true;
		}
		catch
		{
			return false;
		}
	}

	/// <summary>
	/// Best-effort reverse lookup (1s cap): a home LAN usually has no
	/// local DNS, so most hosts come back as their IP address.
	/// </summary>
	private static async Task<string?> TryResolveHostnameAsync(IPAddress ip, CancellationToken ct)
	{
		try
		{
			using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
			using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
			var entry = await Dns.GetHostEntryAsync(ip.ToString(), linked.Token);
			string name = entry.HostName;
			int dot = name.IndexOf('.');
			return dot > 0 ? name[..dot] : name;
		}
		catch
		{
			return null;
		}
	}

	private static int MaskToPrefix(IPAddress mask)
	{
		uint m = ToUInt32(mask);
		int prefix = 0;
		while ((m & 0x80000000) != 0) { prefix++; m <<= 1; }
		return prefix;
	}

	private static uint ToUInt32(IPAddress ip)
	{
		byte[] b = ip.GetAddressBytes();
		return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
	}
}
