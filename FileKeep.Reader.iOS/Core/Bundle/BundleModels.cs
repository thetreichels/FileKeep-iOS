using System.Text.Json.Serialization;

namespace FileKeep.Reader.iOS.Core.Bundle;

/// <summary>
/// "FileKeep offline bundle v1" header DTOs. The header itself is NOT
/// encrypted (it carries only salts, nonces, wrapped keys, and the file
/// manifest with offsets) — every sensitive byte is inside AES-256-GCM.
/// Filenames live only here, never in plaintext on disk.
/// </summary>
public sealed class BundleHeader
{
	[JsonPropertyName("format")]
	public string Format { get; set; } = "";

	[JsonPropertyName("wraps")]
	public List<BundleWrap> Wraps { get; set; } = new();

	[JsonPropertyName("totp")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public BundleTotp? Totp { get; set; }

	[JsonPropertyName("files")]
	public List<BundleFileEntry> Files { get; set; } = new();
}

/// <summary>
/// One way to unwrap the bundle's DEK. Each wrap independently yields
/// the same 32-byte DEK. Types: "passphrase", "yubikey-hmac-sha1",
/// "passkey-prf".
/// Value equality: two wraps are the same unlock method when their
/// identity fields match. The nonce/ciphertext (NonceB64/DataB64) are
/// deliberately excluded — they are fresh randomness per creation, not
/// identity. Equality is what lets <see cref="BundleReader.OpenWithAndShares"/>
/// match a wrap from one header parse against the wraps of another parse
/// of the same bundle; without it every AND unlock fails on reference
/// equality ("Wrap is not from this bundle").
/// </summary>
public sealed class BundleWrap : IEquatable<BundleWrap>
{
	[JsonPropertyName("type")]
	public string Type { get; set; } = "";

	// Passphrase wrap only.
	[JsonPropertyName("salt_b64")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? SaltB64 { get; set; }

	[JsonPropertyName("iterations")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public int? Iterations { get; set; }

	// YubiKey wrap only.
	[JsonPropertyName("slot")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public int? Slot { get; set; }

	// YubiKey wrap only: the 32-byte challenge the exporter sent to the
	// key. The reader replays it to get the same HMAC-SHA1 response.
	[JsonPropertyName("challenge_b64")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? ChallengeB64 { get; set; }

	// Passkey wrap only: the 32-byte PRF salt. The reader evaluates the
	// PRF extension on this salt to get the same 32-byte output.
	[JsonPropertyName("prf_salt_b64")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? PrfSaltB64 { get; set; }

	// Passkey wrap only: the credential ID of the passkey to assert
	// against, and the relying-party domain it was created under.
	// The reader targets this exact credential.
	[JsonPropertyName("credential_id_b64")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? CredentialIdB64 { get; set; }

	[JsonPropertyName("rp_id")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? RpId { get; set; }

	// Layering: "or" (default) — any OR wrap unlocks alone.
	// "and" — this wrap holds one XOR share; all wraps in the same
	// Group are required to reconstruct the DEK.
	[JsonPropertyName("mode")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? Mode { get; set; }

	[JsonPropertyName("group")]
	[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
	public string? Group { get; set; }

	// All wraps: AES-256-GCM(nonce, DEK) = data (ciphertext || tag).
	[JsonPropertyName("nonce_b64")]
	public string NonceB64 { get; set; } = "";

	[JsonPropertyName("data_b64")]
	public string DataB64 { get; set; } = "";

	public bool Equals(BundleWrap? other)
	{
		if (other is null)
			return false;
		if (ReferenceEquals(this, other))
			return true;
		return string.Equals(Type, other.Type, StringComparison.Ordinal)
			&& string.Equals(Mode, other.Mode, StringComparison.Ordinal)
			&& string.Equals(Group, other.Group, StringComparison.Ordinal)
			&& string.Equals(SaltB64, other.SaltB64, StringComparison.Ordinal)
			&& Iterations == other.Iterations
			&& Slot == other.Slot
			&& string.Equals(ChallengeB64, other.ChallengeB64, StringComparison.Ordinal)
			&& string.Equals(PrfSaltB64, other.PrfSaltB64, StringComparison.Ordinal)
			&& string.Equals(CredentialIdB64, other.CredentialIdB64, StringComparison.Ordinal)
			&& string.Equals(RpId, other.RpId, StringComparison.Ordinal);
	}

	public override bool Equals(object? obj) => Equals(obj as BundleWrap);

	public override int GetHashCode()
	{
		var hash = new HashCode();
		hash.Add(Type, StringComparer.Ordinal);
		hash.Add(Mode, StringComparer.Ordinal);
		hash.Add(Group, StringComparer.Ordinal);
		hash.Add(SaltB64, StringComparer.Ordinal);
		hash.Add(Iterations);
		hash.Add(Slot);
		hash.Add(ChallengeB64, StringComparer.Ordinal);
		hash.Add(PrfSaltB64, StringComparer.Ordinal);
		hash.Add(CredentialIdB64, StringComparer.Ordinal);
		hash.Add(RpId, StringComparer.Ordinal);
		return hash.ToHashCode();
	}
}

public sealed class BundleTotp
{
	[JsonPropertyName("required")]
	public bool Required { get; set; }

	// TOTP secret, AES-256-GCM under the DEK (never in the clear).
	[JsonPropertyName("secret_b64")]
	public string SecretB64 { get; set; } = "";

	[JsonPropertyName("nonce_b64")]
	public string NonceB64 { get; set; } = "";
}

public sealed class BundleFileEntry
{
	[JsonPropertyName("path")]
	public string Path { get; set; } = "";

	[JsonPropertyName("size")]
	public long Size { get; set; }

	[JsonPropertyName("modified_utc")]
	public DateTimeOffset ModifiedUtc { get; set; }

	[JsonPropertyName("nonce_b64")]
	public string NonceB64 { get; set; } = "";

	// Absolute byte offset of this file's ciphertext segment from the
	// start of the bundle file; Length covers ciphertext + 16-byte tag.
	[JsonPropertyName("offset")]
	public long Offset { get; set; }

	[JsonPropertyName("length")]
	public long Length { get; set; }
}
