using AVFoundation;
using Foundation;

namespace FileKeep.Reader.iOS.Platforms.iOS;

/// <summary>
/// Plays audio from in-memory bytes using AVAudioPlayer.
/// The audio never touches disk.
/// </summary>
public sealed class AudioPlayer : IDisposable
{
	private AVAudioPlayer? _player;
	private bool _disposed;

	public bool Play(byte[] audioData)
	{
		Stop();
		try
		{
			using var nsData = NSData.FromArray(audioData);
			if (nsData is null)
				return false;
			
			NSError? error;
			_player = AVAudioPlayer.FromData(nsData, out error);
			if (_player is null || error is not null)
				return false;
			
			_player.PrepareToPlay();
			return _player.Play();
		}
		catch
		{
			return false;
		}
	}

	public void Stop()
	{
		try
		{
			if (_player?.Playing == true)
				_player.Stop();
		}
		catch { }
	}

	public void Dispose()
	{
		if (_disposed)
			return;
		_disposed = true;
		Stop();
		_player?.Dispose();
		_player = null;
	}
}
