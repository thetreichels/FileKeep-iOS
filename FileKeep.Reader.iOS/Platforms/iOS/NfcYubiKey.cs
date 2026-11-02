using CoreNFC;
using FileKeep.Reader.iOS.Core.Bundle;
using Foundation;
using System.Security.Cryptography;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// YubiKey challenge-response over NFC (slice 4).
///
/// Sends two APDUs against the YubiKey OTP applet and turns the 20-byte
/// HMAC-SHA1 response into the bundle KEK per DESIGN.md §3.2. The raw
/// response never leaves this class — callers get the derived KEK and
/// must zero it after use.
///
/// APDUs (Yubico's documented OTP-applet protocol):
///   SELECT     00 A4 04 00 07 A0 00 00 05 27 20 01      -> 90 00
///   CHALLENGE  00 01 <P1> 00 <Lc> <challenge, 1..64B>  -> 20B HMAC-SHA1 + 90 00
/// P1 = 0x30 (slot 1) / 0x38 (slot 2). 6A82 on SELECT means the key
/// exposes no OTP applet on its NFC interface.
///
/// User contract: program the slot for HMAC-SHA1 (ykman) with touch and
/// OTP enabled on the NFC interface. Requires a real iPhone — the
/// simulator has no NFC, so the UI gates on <see cref="IsAvailable"/>.
///
/// All CoreNFC API shapes below were verified against the dotnet/macios
/// binding sources (corenfc.cs), not written from memory: the session
/// invalidates via <c>InvalidateSession()</c>, the APDU class is
/// <c>NFCIso7816Apdu</c>, and the lifecycle event is
/// <c>OnResignActivation</c>.
/// </summary>
public static class NfcYubiKey
{
	/// <summary>Result of an NFC unlock attempt.</summary>
	public sealed record Result(byte[]? Kek, string? Error);

	private static SessionDelegate? s_current;

	public static bool IsAvailable()
	{
		return NFCTagReaderSession.ReadingAvailable;
	}

	/// <summary>
	/// Runs the NFC challenge-response for <paramref name="slot"/> (1 or 2)
	/// and returns the 32-byte bundle KEK, or a null KEK with an error
	/// message when the user cancels or the key doesn't answer. The caller
	/// owns the KEK buffer and must zero it after use.
	/// </summary>
	public static Task<Result> GetKekAsync(int slot, byte[] challenge)
	{
		var tcs = new TaskCompletionSource<Result>();
		if (slot is not (1 or 2))
		{
			tcs.SetResult(new Result(null, "YubiKey slot must be 1 or 2."));
			return tcs.Task;
		}
		if (challenge is null || challenge.Length == 0 || challenge.Length > 64)
		{
			tcs.SetResult(new Result(null, "YubiKey challenge must be 1-64 bytes."));
			return tcs.Task;
		}
		if (!IsAvailable())
		{
			tcs.SetResult(new Result(null, "This device can't do NFC."));
			return tcs.Task;
		}

		var del = new SessionDelegate(slot, (byte[])challenge.Clone(), tcs);
		s_current = del; // kept alive until DidInvalidate clears it
		del.Begin();
		return tcs.Task;
	}

	private sealed class SessionDelegate : NFCTagReaderSessionDelegate
	{
		private readonly int _slot;
		private readonly byte[] _challenge;
		private readonly TaskCompletionSource<Result> _tcs;
		private readonly NFCTagReaderSession _session;
		private int _done;

		public SessionDelegate(int slot, byte[] challenge, TaskCompletionSource<Result> tcs)
		{
			_slot = slot;
			_challenge = challenge;
			_tcs = tcs;
			_session = new NFCTagReaderSession(NFCPollingOption.Iso14443, this, null);
		}

		public void Begin()
		{
			_session.AlertMessage = "Hold your YubiKey near the top of the iPhone.";
			_session.BeginSession();
		}

		public override void DidBecomeActive(NFCTagReaderSession session)
		{
		}

		public override void DidDetectTags(NFCTagReaderSession session, INFCTag[] tags)
		{
			var iso = tags.Length > 0 ? tags[0].AsNFCIso7816Tag : null;
			if (iso is null)
			{
				Fail("That tag isn't a YubiKey.");
				return;
			}
			session.ConnectTo(tags[0], error =>
			{
				if (error is not null)
				{
					Fail("Couldn't connect to the YubiKey.");
					return;
				}
				SendSelect(iso);
			});
		}

		private void SendSelect(INFCIso7816Tag iso)
		{
			using var selectBytes = NSData.FromArray(new byte[]
			{
				0x00, 0xA4, 0x04, 0x00, 0x07,
				0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
			});
			var apdu = new NFCIso7816Apdu(selectBytes);
			iso.SendCommand(apdu, (_, sw1, sw2, _) =>
			{
				if (sw1 == 0x6A && sw2 == 0x82)
				{
					Fail("YubiKey not recognized — enable OTP on its NFC interface.");
					return;
				}
				if (sw1 != 0x90 || sw2 != 0x00)
				{
					Fail("The YubiKey didn't answer.");
					return;
				}
				SendChallenge(iso);
			});
		}

		private void SendChallenge(INFCIso7816Tag iso)
		{
			byte p1 = _slot == 1 ? (byte)0x30 : (byte)0x38;
			using var cdata = NSData.FromArray(_challenge);
			var apdu = new NFCIso7816Apdu(0x00, 0x01, p1, 0x00, cdata, 0);
			iso.SendCommand(apdu, (response, sw1, sw2, _) =>
			{
				byte[]? resp = response?.ToArray();
				try
				{
					if (sw1 != 0x90 || sw2 != 0x00 || resp is null || resp.Length != 20)
					{
						Fail("The YubiKey didn't answer the challenge.");
						return;
					}
					byte[] kek = YubiKeyKek.Derive(resp);
					Succeed(kek);
				}
				finally
				{
					if (resp is not null)
						CryptographicOperations.ZeroMemory(resp);
					CryptographicOperations.ZeroMemory(_challenge);
				}
			});
		}

		private void Succeed(byte[] kek)
		{
			if (Interlocked.Exchange(ref _done, 1) == 0)
			{
				_session.AlertMessage = "Unlocked.";
				_session.InvalidateSession();
				_tcs.TrySetResult(new Result(kek, null));
			}
			else
			{
				CryptographicOperations.ZeroMemory(kek);
			}
		}

		private void Fail(string message)
		{
			if (Interlocked.Exchange(ref _done, 1) == 0)
			{
				_session.InvalidateSession(message);
				_tcs.TrySetResult(new Result(null, message));
			}
		}

		public override void DidInvalidate(NFCTagReaderSession session, NSError error)
		{
			// User cancelled (or the session ended on its own): report
			// cancellation only if nothing already completed.
			if (Interlocked.Exchange(ref _done, 1) == 0)
				_tcs.TrySetResult(new Result(null, null));
			CryptographicOperations.ZeroMemory(_challenge);
			if (ReferenceEquals(s_current, this))
				s_current = null;
		}
	}
}
