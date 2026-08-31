# Clipperd

Seamless clipboard sync between iPhone and Linux over your local network — no cloud, no account, no data leaving your LAN.

Works like Apple's Universal Clipboard, but for Linux. Copy on your iPhone, paste on Linux (and vice versa) with a single tap.

## How it works

A small daemon runs on Linux and exposes a local HTTPS endpoint. Two iOS Shortcuts talk to it — one to push your iPhone clipboard to Linux, one to pull the Linux clipboard to your iPhone. Everything is encrypted with TLS and protected by a per-device secret token.

```
iPhone (iOS Shortcuts)
    │  HTTPS POST → push clipboard to Linux
    │  HTTPS GET  ← pull clipboard from Linux
    ▼
clipperd daemon (Rust)
    ├── axum HTTPS server  (port 7171)
    ├── clipboard watcher  (Wayland + X11)
    └── self-signed TLS    (rcgen)
```

## Features

- Text, images, URLs, and files
- Bidirectional sync
- Wayland and X11 support (auto-detected)
- Self-signed TLS with a per-device CA — no external certificate authority
- 256-bit random auth token
- Runs as a systemd user service
- Zero cloud dependency

## Requirements

**Linux**
- Rust 1.75+
- Wayland compositor with `wl-data-control` support, or X11 with `xclip`
- `notify-send` for desktop notifications (optional)

**iPhone**
- iOS 13+
- Shortcuts app (built-in)

## Installation

```bash
git clone https://github.com/SevcikMichal/clipperd
cd clipperd
cargo build --release
cp target/release/clipperd ~/.local/bin/
```

## Setup

Run setup to generate keys and pair your iPhone:

```bash
clipperd setup
```

On first run this will:
1. Generate a self-signed CA and server certificate
2. Generate a secret auth token
3. Print a QR code and start a temporary setup server

If config already exists, `clipperd setup` reuses the existing keys and token and just starts the setup server again — useful if you need to re-install the certificate or shortcuts on a new device.

Then on your iPhone:

1. Scan the QR code — Safari opens the setup page
2. Tap **Install Certificate** and follow the prompts
3. Go to **Settings → General → About → Certificate Trust Settings** and enable full trust for **Clipperd CA**
4. Follow the on-screen instructions to build the two Shortcuts

> **Note:** The setup server only runs while `clipperd setup` is active and serves only on your local network. Stop it with Ctrl+C once pairing is complete.

## Running the daemon

```bash
clipperd run
```

Or install as a systemd user service so it starts automatically:

```bash
cp systemd/clipperd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now clipperd
```

## Usage

Assign the two Shortcuts to **Back Tap** for fastest access:

**Settings → Accessibility → Touch → Back Tap**

| Shortcut | Direction | Suggested trigger |
|---|---|---|
| Clipperd Send | iPhone → Linux | Double tap |
| Clipperd Get | Linux → iPhone | Triple tap |

One tap syncs the clipboard in under a second.

## CLI reference

```
clipperd setup    Generate keys (first run) and start the pairing wizard
clipperd run      Run the clipboard sync daemon
clipperd status   Show configuration and certificate info
```

Options for `setup`:
```
--port <PORT>            Port to listen on (default: 7171)
--bind-ip <IP>           IP the daemon and setup server bind to, and that the
                         iPhone connects to. Defaults to the auto-detected LAN
                         IP. Also embedded in the server certificate.
--cert-name <NAME>       Certificate identity (repeatable). Sets the cert CN and
                         adds each name as an extra SAN. May be a hostname or an
                         IP. Defaults to the detected LAN IP when omitted.
```

> `--bind-ip` replaces the old `--bind-all` flag and rejects `0.0.0.0` (there is
> no single connection address for your iPhone). Re-running setup with either
> flag regenerates the certificate but keeps your existing token, so iOS
> Shortcuts don't need to be rebuilt.

## Configuration

Your credentials live in `~/.config/clipperd/config.toml` (mode `0600`),
including the auth token, TLS key, and certificate. A number of fields are
optional so you can keep secrets in separate files if you prefer:

```toml
# Base settings
port = 7171                 # TCP port (default)

# Where to bind. Omit to auto-detect the LAN IP.
bind_ip = "192.168.1.50"

# TLS identity. Omit to fall back to the detected LAN IP.
cert_names = ["mybox.lan", "other.lan"]

# Auth token: either inline...
token = "hex-token-string"
# ...or read from a file (trimmed). If both are set, the file wins.
token_file = "/run/secrets/clipperd_api_token"

# Private key: either inline...  (omitted on a file-backed setup)
key_pem = "-----BEGIN PRIVATE KEY----- ..."
# ...or read from a PKCS#8 PEM file. If both are set, the file wins.
key_pem_file = "/run/secrets/clipperd_server.key"
```

Relative paths for `token_file` and `key_pem_file` resolve against
`~/.config/clipperd/`. Externalized tokens and keys are read-only: clipperd
never writes to those files and never rotates an externalized token. A path that
is configured but unreadable is a hard startup error rather than a silent
fallback to the inline value.

## Security

- All traffic is **TLS 1.3 encrypted** — the token and clipboard contents are never sent in plaintext
- The auth token is **256 bits of random entropy** — not guessable
- Token comparison uses **constant-time equality** to prevent timing attacks
- The daemon binds to your **LAN IP only** by default — not exposed to the internet
- Config and keys are stored at `~/.config/clipperd/config.toml` with **mode 0600**
- No data ever touches a third-party server

The setup page briefly displays your auth token over plain HTTP so you can copy it into Shortcuts. Run `setup` only on a network you trust, and stop it once pairing is done.

## Supported content types

| Type | iPhone → Linux | Linux → iPhone |
|---|---|---|
| Plain text | ✓ | ✓ |
| URLs | ✓ | ✓ |
| Images (PNG/JPEG) | ✓ | ✓ |
| Files | ✓ (saved to ~/Downloads) | — |

## License

MIT
