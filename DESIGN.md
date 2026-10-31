# FileKeep Reader (iOS) — Design

Date: 2026-10-31. Status: design, pre-work. No code yet.

## 1. What it is

One MAUI iOS app — **FileKeep Reader** — that opens encrypted FileKeep
offline packages on iPhone. Stealth folders only. It is not a backup app:
no jobs, no scheduler, no Usenet, no destinations.

The loop: on the laptop, FileKeep exports a folder to a **self-contained
encrypted bundle**; the bundle file is saved anywhere (iCloud Drive, USB
stick, AirDrop, download); on the iPhone, FileKeep Reader opens it from
the document picker, unlocks it, and renders files — decrypting to memory
only. The only way plaintext leaves the phone is explicit export through
the share sheet.

Non-goals: whole-device backup, scheduled/background operation, writing
back to the bundle, the desktop dashboard, browser access.

## 2. Decisions made (Joel)

- 2026-10-30: scope is stealth folders only, not the full backup app.
- 2026-10-30: the bundle opens from **any** source via the document
  picker — no iCloud Drive / CloudKit lock-in, no sync engine.
- 2026-10-30: unlock is the export passphrase on first open, then Face ID
  via the Keychain (device-only, biometric-gated; a newly enrolled
  biometric falls back to passphrase).
- 2026-10-30: TOTP as the v1 second factor (software-only); YubiKey
  challenge-response over NFC verified as the hardware path (KeePassium
  ships it; same HMAC-SHA1 as desktop; no MFi needed for NFC).
- 2026-10-30: new repo `thetreichels/FileKeep-iOS` (proprietary-commercial
  license), FileKeep.Core shared as a pinned git submodule.
- 2026-10-30: MAUI, not Swift — the app references FileKeep.Core
  directly, so the envelope, crypto, and format stay single-sourced.

## 3. Package format: self-contained bundle (v2)

The existing export envelope (v1) is **manifest-only**: file list, chunk
references, and a location pointer (SMB/USB) — no file data. An iPhone
cannot use it standalone; it would need the original share or stick, and
it would need the vault content key on top of the export passphrase (the
two-secret problem from the slice 3 brief).

The iPhone bundle is therefore a new, self-contained format. One secret
(passphrase, optionally + YubiKey and/or TOTP) opens everything. v1
manifest packages stay as-is for the desktop USB reader; nothing is
replaced.

### 3.1 Layout

Single file: a JSON header followed by raw ciphertext segments.

```
[4-byte magic "FKBO"][4-byte header length][header JSON][ciphertext segments...]
```

Header JSON (snake_case):

```json
{
  "format": "FileKeep offline bundle v1",
  "wraps": [
    {"type": "passphrase", "salt_b64": "...", "iterations": 600000,
     "nonce_b64": "...", "data_b64": "<DEK wrapped under PBKDF2-HMAC-SHA512 KEK>"},
    {"type": "yubikey-hmac-sha1", "slot": 2,
     "nonce_b64": "...", "data_b64": "<DEK wrapped under YubiKey KEK>"}
  ],
  "totp": {"required": true, "secret_b64": "<encrypted under DEK>"},
  "files": [
    {"path": "docs/notes.txt", "size": 48210,
     "modified_utc": "2026-10-30T12:00:00Z",
     "nonce_b64": "...", "offset": 1234, "length": 48226}
  ]
}
```

- **DEK**: fresh random 256-bit data-encryption key per bundle.
- File bytes are AES-256-GCM under the DEK (fresh 12-byte nonce per
  file); ciphertext is appended after the header. `offset` is the
  absolute byte offset of the segment from the start of the bundle
  file; `length` covers ciphertext + 16-byte tag.
  No chunking or dedup inside the bundle — it is a portable artifact,
  not storage.
- `wraps`: each entry unwraps to the same DEK. Absent `yubikey` entry =
  passphrase-only. Unknown wrap types refuse fail-closed; a bundle with
  no usable wrap refuses.
- `totp`: optional. When present and `required`, the reader demands a
  current code after the DEK is unwrapped, before showing anything. The
  secret itself is encrypted under the DEK (never in the clear).
- Filenames live only inside the encrypted header. The bundle file on
  disk is opaque.

### 3.2 YubiKey KEK composition (to finalize in FileKeep.Core)

The 20-byte HMAC-SHA1 response must become a 256-bit KEK identically on
Windows and iOS. Recommended:

```
KEK_yk = SHA-256("FileKeep-yubikey-wrap-v1" || response)
```

then AES-256-GCM-wrap the DEK under KEK_yk (same wrap shape as the
desktop's YubiKeyCrypto.Wrap). This must be defined once in
FileKeep.Core and shared — KeePassXC's composite-key convention is the
template if this shape needs a second opinion. The response is zeroed
immediately after use.

### 3.3 Why not reuse the v1 manifest package

- It carries no file data; the iPhone would need SMB/USB access to the
  original location per file.
- It needs two secrets on the reader (export passphrase + vault content
  key). The bundle needs one (+ optional second factors), and the vault
  secret never touches the phone.

## 4. App architecture

```
FileKeep-iOS/
  FileKeep.Reader.iOS/          # MAUI iOS head (net10.0-ios)
    Platforms/iOS/
      NfcChallengeResponse.cs   # CoreNFC: 2-APDU challenge-response
      KeychainAccess.cs         # SecAccessControl + biometry wrapper
      BundleOpener.cs           # document picker, security-scoped read
      MemoryRenderer.cs         # in-app rendering from byte[]
      SessionLock.cs            # idle timer, background wipe, overlay
    Views/                      # package list, unlock, file browser, viewer
  external/FileKeep/            # git submodule, pinned to release commit
  # ProjectReference: external/FileKeep/src/FileKeep.Core/FileKeep.Core.csproj
```

FileKeep.Core is referenced **as-is**: OfflineExportEnvelope's crypto
helpers (PBKDF2, AES-GCM), the JSON source-generation context, hashing.
No Core changes are needed for v1 of the reader except §3.2 (the YubiKey
KEK composition), which belongs in Core so both platforms share it.

Verified platform facts (research 2026-10-31):
- iOS AES-GCM supports 12-byte nonces / 16-byte tags — Core already uses
  exactly these. No change needed.
- Rfc2898DeriveBytes (HMAC-SHA512, 600k) works on iOS; expect ~0.5–2s,
  run off the UI thread, benchmark on device.
- A plain net10.0 library is not trimmed by default on iOS; keep the
  source-generated System.Text.Json (already in use).
- CoreNFC is bound in .NET iOS (NFCTagReaderSession, ISO 7816,
  SendCommand). No .NET YubiKit binding exists or is needed.
- MAUI SecureStorage is string-only with no biometric ACL — the custom
  Keychain wrapper (§5.3) is required regardless.

## 5. The seven platform pieces

### 5.1 Open
One `UIDocumentPickerViewController` in **Open** mode (never Import —
Import copies the bundle into the sandbox). Read bytes via the
security-scoped `NSUrl` straight to memory (memory-map the bundle;
decrypt per file on demand). Covers iCloud Drive, On My iPhone, USB
sticks in Files, AirDrop-saved files. iPad needs popover presentation.

### 5.2 Unlock: passphrase
PBKDF2-HMAC-SHA512, 600k iterations, 32-byte salt from the header →
KEK → unwrap DEK → verify by decrypting the header. Wrong passphrase
fails closed on the GCM tag. Off the UI thread.

### 5.3 Unlock: Face ID ("remember me")
After a successful passphrase unlock, offer Face ID: store the
passphrase in the Keychain as a generic-password item with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and a
`SecAccessControl` of `biometryCurrentSet`. Subsequent opens read it
behind a biometric prompt; a newly enrolled biometric invalidates the
item and falls back to the passphrase. `NSFaceIDUsageDescription`
required. The Keychain holds the *passphrase*, never file contents.

### 5.4 Unlock: YubiKey over NFC
Hand-rolled, two APDUs over CoreNFC (`NFCTagReaderSession`,
ISO 7816):
1. `00 A4 04 00 07 A0 00 00 05 27 20 01` — select the OTP applet
   (this AID goes in the `iso7816.select-identifiers` entitlement).
2. `00 01 <P1> 00 <Lc> <challenge>` — P1 `0x30` (slot 1) /
   `0x38` (slot 2); challenge 1–64 bytes; response is the 20-byte
   HMAC-SHA1 + `9000`.

User contract (shown at export and in-app): program slot 2 for
HMAC-SHA1, keep the OTP application enabled on the NFC interface
(otherwise the select fails `6A82`). Incompatible: Security Key and
Bio series (no challenge-response). No MFi / Yubico whitelisting for
the NFC path. NFC is device-only — the simulator has none, so this
piece is untestable without a physical key and iPhone.

### 5.5 Second factor: TOTP
v1 second factor, software-only. At export, FileKeep shows the QR and
offers "store on YubiKey" (writes the secret to the key's OATH applet
over USB from the laptop). The secret is stored encrypted under the
DEK in the bundle header. After the DEK unwraps, the reader requires
a current 6-digit code before revealing the file list. The desktop
reader honors the same gate (FileKeep already has TOTP verification).
A code from the key is indistinguishable from a code from an app.

### 5.6 Read (render)
Decrypted file bytes stay in memory; render from the byte array:
images (`UIImage.LoadFromData`), PDF (`PdfKit.PdfDocument` over
`NSData`), text, audio/video via an `AVAssetResourceLoaderDelegate`
serving the buffer behind a custom URL scheme. Office documents
(docx/xlsx/pptx) have no in-memory renderer — they go straight to the
export path. Only the opened file is ever decrypted; the bundle is
never fully materialized.

### 5.7 Lockdown (forensic checklist)
- On `WillResignActive`: add a blank overlay (kills the app-switcher
  snapshot — Apple's recommended approach) and zero all key and
  plaintext buffers (`byte[]`, never `string`).
- Session: same model as desktop — first unlock opens the session,
  1-hour idle expiry, relock wipes keys; reopening the app starts
  locked.
- Screenshot taken (`ObserveUserDidTakeScreenshot`) → warn and lock.
  Screen recording (`UIScreen.CapturedDidChange`) → warn/lock.
  Detection is post-event only; it reacts, it cannot prevent.
- No thumbnails, no recents, no CoreSpotlight indexing, no
  `UIDocumentBrowserViewController` — simply never use them, and never
  write plaintext to disk.

### 5.8 Export
The one sanctioned exit: share sheet, user picks the destination.
Plaintext exists on the phone only from this action.

## 6. Desktop export side (FileKeep)

New export target: **"Offline bundle (iPhone)"**. Flow: pick a stealth
folder → choose passphrase (+ optional YubiKey wrap: touch the key on
the laptop; + optional TOTP: show QR / store-on-key) → FileKeep
re-encrypts the folder's files under a fresh DEK into the §3.1
container → writes the `.fk bundle` file wherever the user points it
(iCloud Drive folder, USB stick, desktop). The GUI does the export;
only verification reads may use other channels (testing law holds).

## 7. Store / distribution

- Entitlements: CoreNFC (`com.apple.developer.nfc.readersession.formats`
  = TAG), `NFCReaderUsageDescription`, `iso7816.select-identifiers` =
  `[A000000527200101]`, `NSFaceIDUsageDescription`.
- `ITSAppUsesNonExemptEncryption = false` (standard AES/PBKDF2 via OS
  crypto is exempt; also clears the TestFlight prompt).
- No review friction found beyond standard privacy strings (research).
- Legal caveat (unverified): year-end BIS self-classification report
  might apply — counsel's call.
- Installing on Joel's iPhone long-term needs an Apple Developer
  account ($99/yr) for TestFlight/App Store; free sideloading expires
  every 7 days.

## 8. Open items before / during work

1. §3.2 YubiKey KEK composition — finalize in FileKeep.Core.
2. Physical NFC tap test (key + iPhone; simulator impossible).
3. PBKDF2 600k timing benchmark on a real iPhone.
4. Mac build host for MAUI iOS builds (still to sort).
5. Apple Developer account for TestFlight.

## 9. Work slices

1. Core submodule reference + bundle open + passphrase unlock (the
   walking skeleton; proves the whole path).
2. In-app rendering (§5.6).
3. Face ID / Keychain (§5.3) + session lock (§5.7).
4. YubiKey NFC (§5.4) + §3.2 in Core.
5. TOTP second factor (§5.5).
6. Lockdown/export polish, TestFlight.

Slice 1 is the proof the architecture holds; everything else stacks on
it. No slice starts before the repo exists.
