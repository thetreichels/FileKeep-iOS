using FileKeep.Reader.iOS.Core.Bundle;

namespace FileKeep.Reader.iOS.Core.Session;

/// <summary>
/// Owns the unlocked bundle session: the live <see cref="BundleReader"/>
/// plus the lock policy. Same model as the desktop app — the session
/// lapses after 1 hour idle, and locking disposes the reader (which
/// zeroes the DEK). Thread-safe; the <see cref="Locked"/> event fires on
/// whatever thread triggered the lock, so UI subscribers must marshal to
/// the main thread themselves.
/// </summary>
public sealed class SessionManager : IDisposable
{
	public static SessionManager Instance { get; } = new SessionManager();

	private static readonly TimeSpan IdleExpiry = TimeSpan.FromHours(1);

	private readonly object _gate = new();
	private BundleReader? _reader;
	private Timer? _idleTimer;
	private bool _disposed;

	/// <summary>Fired when an open session locks (idle expiry or explicit).</summary>
	public event EventHandler? Locked;

	private SessionManager() { }

	public bool IsOpen
	{
		get { lock (_gate) return !_disposed && _reader is not null; }
	}

	public BundleReader Reader
	{
		get
		{
			lock (_gate)
			{
				return _reader ?? throw new InvalidOperationException("No open session.");
			}
		}
	}

	public void Open(BundleReader reader)
	{
		ArgumentNullException.ThrowIfNull(reader);
		lock (_gate)
		{
			ThrowIfDisposed();
			CloseLocked();
			_reader = reader;
			ResetTimerLocked();
		}
	}

	/// <summary>Call on every user interaction with the open bundle.</summary>
	public void Touch()
	{
		lock (_gate)
		{
			if (_disposed || _reader is null)
				return;
			ResetTimerLocked();
		}
	}

	/// <summary>
	/// Locks the session now. Fires <see cref="Locked"/> only when a
	/// session was actually open.
	/// </summary>
	public void Lock()
	{
		EventHandler? handler = null;
		lock (_gate)
		{
			if (_disposed)
				return;
			if (CloseLocked())
				handler = Locked;
		}
		handler?.Invoke(this, EventArgs.Empty);
	}

	/// <summary>Returns true when a session was actually closed.</summary>
	private bool CloseLocked()
	{
		_idleTimer?.Dispose();
		_idleTimer = null;
		bool had = _reader is not null;
		_reader?.Dispose();
		_reader = null;
		return had;
	}

	private void ResetTimerLocked()
	{
		_idleTimer?.Dispose();
		_idleTimer = new Timer(_ => Lock(), null, IdleExpiry, Timeout.InfiniteTimeSpan);
	}

	private void ThrowIfDisposed()
	{
		if (_disposed)
			throw new ObjectDisposedException(nameof(SessionManager));
	}

	public void Dispose()
	{
		lock (_gate)
		{
			if (_disposed)
				return;
			_disposed = true;
			CloseLocked();
		}
	}
}
