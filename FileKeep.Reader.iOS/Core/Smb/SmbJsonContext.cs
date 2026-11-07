using System.Text.Json.Serialization;

namespace FileKeep.Reader.iOS.Core.Smb;

/// <summary>
/// Source-generated JSON context for the SMB boundary (trim-clean,
/// reflection-free). The Rust FFI layer returns listings as JSON
/// strings; remembered servers are stored in Preferences as JSON.
/// </summary>
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(List<SmbDirEntry>))]
[JsonSerializable(typeof(List<SmbServerEntry>))]
internal sealed partial class SmbJsonContext : JsonSerializerContext
{
}
