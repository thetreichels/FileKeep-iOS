# FileKeep Reader (iOS)

Companion app for [FileKeep](https://github.com/thetreichels/FileKeep):
opens encrypted stealth-folder bundles on iPhone. Stealth folders only —
this is a reader, not a backup app.

**Status:** design phase. See [DESIGN.md](DESIGN.md) for the full design.

## What it does

- Opens FileKeep offline bundle files (`.fkbundle`) from any source via
  the iOS document picker (iCloud Drive, On My iPhone, USB sticks in
  Files, AirDrop, downloads).
- Unlocks by export passphrase, YubiKey HMAC-SHA1 challenge-response
  over NFC, and/or TOTP; Face ID convenience unlock via the Keychain.
- Decrypts to memory only and renders files in-app. The only way
  plaintext leaves the phone is explicit export through the share sheet.

## Structure

```
FileKeep.Reader.iOS/          # .NET MAUI iOS head (net10.0-ios)
  Platforms/iOS/              # NFC, Keychain, picker, rendering, lockdown
external/FileKeep/            # git submodule, pinned to a FileKeep release
```

`FileKeep.Core` (envelope, AES-GCM, PBKDF2, JSON) is referenced as-is
from the submodule — single-sourced, never reimplemented. See
DESIGN.md §4.

## Building

Requires .NET 10 SDK and a Mac build host for the iOS target.
Details once the first slice lands.

## License

FileKeep Commercial License — see [LICENSE](LICENSE).
Copyright © 2026 J. Treichel. All rights reserved.
