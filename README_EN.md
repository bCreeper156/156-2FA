# 156-2FA · A Local-First Dynamic Verification Code Tool

A local-first 2FA tool featuring multi-user support, an Argon2id-based password system, and TOTP dynamic verification code capabilities.

- **Backend**: Python; handles local login verification, decryption, TOTP calculation, and launching the local HTTP service.
- **Interface**: Pure HTML/CSS/JS embedded within a `pywebview` desktop window; responsible only for displaying verification codes and countdowns (**no external browser used**).
- **Data**: Each user maintains their own encrypted JSON vault.
- **User System**: Local user table (`data/users.json`); passwords are stored solely as **Argon2id** hashes—plaintext passwords are never written to disk or exposed to the browser.

---

## Core Principles

- Passwords are entered in the **login window**; after Argon2id verification, they exist only in program memory and are cleared upon program exit.
- Account data is stored locally as **AES-GCM encrypted JSON**; the `secret` field is never written to disk in plaintext.
- The frontend **does not handle passwords** or access **plaintext secrets**; it only receives the calculated verification codes.
- The main interface runs in a **pywebview desktop window** and does not invoke the system browser.
- By default the local service listens only on `127.0.0.1` using a **random port** (30000–60000); the listen IP and port can be customized in "Settings → Connection & API" (validated before applying).
- Frontend and backend are separated: the backend only exposes REST endpoints under `/api/*`, while the frontend is static and can connect to the local service or a remote API.
- The current data source (local `IP:Port` or remote address) and logged-in user are displayed in the top-left corner.
- Password hash verification is performed even if the username does not exist, preventing username enumeration via response timing analysis. ---

## Installation and Execution

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Dependencies:
- `pywebview` — Login / Main interface window
- `cryptography` — AES-GCM encryption/decryption
- `argon2-cffi` — Argon2id password hashing and key derivation
- `opencv-python` / `Pillow` / `numpy` — QR code decoding

### 2. Launch

```bash
python main.py              # desktop mode (same as: python main.py gui)
python main.py serve        # server mode: headless, serves the REST API
python main.py --help       # full argument list
```

First run: The login window automatically switches to "Create First Account"; enter a username and password (at least 8 characters) to proceed.
Subsequent runs: Select/enter username + password to log in.

Startup process:

1. **User login window** appears (pywebview): Log in if an account exists, or create the first account.
2. Argon2id verifies the password → Decrypts the user's encrypted vault and starts a local HTTP service (on a random port).
3. The program **creates a new main window within the same pywebview process** and loads the verification code page, while closing the login window; 
The top-left corner of the main interface displays `127.0.0.1:port` and the current username.
4. Clicking "Switch User" on the settings page returns you to the login window to switch accounts (data for each account is independent).
5. Closing the main window → Service stops, and passwords/keys in memory are cleared.

> No need to set environment variables for the master password anymore; the early `TOTP_MASTER_PASS` mechanism has been removed
> (resetting the program also cleans up any residual old values ​​of this variable in the system).

> The entire interface runs within the pywebview window; the system browser will not pop up.
> If the runtime environment lacks graphical dependencies preventing window creation, the program automatically falls back to "console login + system browser" mode.

---

## Data Files

Default data root directory: `data/` (use the `TOTP_DATA_FILE` environment variable to specify a different directory or file location). ```
data/
├── users.json              # User table: username + Argon2id password hash + vault ID
├── vaults/
│   └── <vaultId>.json      # Encrypted vault specific to each user
└── webview/                # UI preferences (themes, etc.); contains no cryptographic keys
```

User table structure:

```json
{
"version": 1,
"users": [
{
"username": "alice",
"password": "$argon2id$v=19$m=65536,t=3,p=4$...",
"vaultId": "9f2c...",
"createdAt": "2026-09-12T08:00:00Z",
"lastLoginAt": "2026-09-12T09:30:00Z"
}
]
}
```

> `vaultId` is a random identifier used as the vault filename; thus, usernames can contain non-ASCII characters (e.g., Chinese) without affecting file paths.
> Plaintext passwords are not stored in the user table; only the Argon2id PHC hash string is kept.

Encrypted vault file structure:

```json
{
"version": 2,
"encrypted": true,
"kdf": "argon2id",
"kdfParams": { "timeCost": 3, "memoryCost": 65536, "parallelism": 4, "hashLen": 32 },
"salt": "base64-encoded salt",
"iv": "base64-encoded initialization vector",
"data": "AES-GCM encrypted ciphertext"
}
```

> Upgrade note: Legacy single-user `data/vault.json` files (derived via PBKDF2) remain readable.
> Upon logging in to the new version with the same password for the first time, the application attempts to adopt the legacy file as the current user's vault,
> re-encrypts it using Argon2id, and subsequently deletes the old file. > The program generates a `.2fa-state.json` file in its own directory to record the **current and historically used** data root directories:
> The latest `TOTP_DATA_FILE` always takes precedence; previously set directories are no longer treated as the current directory (deprecated),
> but their records are retained so they can be cleaned up when the program is "reset."

Decrypted account array:

```json
[
{
"id": 1,
"name": "GitHub",
"secret": "JBSWY3DPEHPK3PXP",
"issuer": "GitHub",
"createdAt": "2026-09-11T21:00:00Z",
"algorithm": "SHA1",
"digits": 6,
"period": 30
}
]
```

- `id`: A unique numeric identifier used for deletion, editing, and sorting.
- `name`: A user-friendly label/name.
- `secret`: The TOTP secret key, stored in **encrypted format**.
- `issuer` / `createdAt`: Optional fields used for display and sorting.

---

## Features

- Displays the account list, current 6-digit verification code, and remaining time in seconds.
- Auto-refreshes every 30 seconds with a circular countdown progress indicator.
- Click the verification code or the copy button to copy it to the clipboard.
- Search and filter accounts by `name` or `issuer`.
- Add accounts manually or import them from **QR code images** or **otpauth links**.
- Edit or delete accounts by `id`.
- Theme and appearance settings (`settings.html`).
- Multi-user support: A local user table stores usernames and Argon2id password hashes; each user has an independent encrypted vault.
Users can "switch accounts" on the settings page; accounts are unlocked individually at runtime and remain invisible to one another.
- Program reset: Clicking "Reset and Exit" on the settings page—followed by a confirmation step—deletes **all users**, their data, and interface preferences, then closes the program, returning it to its initial state. - Deletion process employs a "multiple retries + pending-cleanup flag" mechanism: even if files are locked or WebView2 writes the cache directory back upon exit, the cleanup will be completed automatically upon the next startup, ensuring the data directory is thoroughly removed; additionally, it clears `TOTP_MASTER_PASS` artifacts left by earlier versions (from the current process, Windows user/system-level variables, or *nix shell configurations). If `TOTP_DATA_FILE` has been modified multiple times, the reset operation deletes **all historical data directories**, leaving no account data behind at old paths.
- Data Export/Import: Export encrypted backups (`.json`) or plaintext otpauth data (`.txt`), and perform batch restoration from these files; supports both **merge/append** (deduplicating by key) and **overwrite all** modes.
- UI notifications consistently use the built-in Toast component (`web/toast.js`) instead of native `alert` or `confirm` dialogs. ---

## Frontend / Backend Separation

The backend (`server.py`) only serves REST endpoints under `/api/*`; the frontend (`web/`) is static
and communicates with it over HTTP:

```
┌────────────────┐   HTTP /api/*   ┌──────────────────┐
│  web/index.html│ ───────────────▶│  Python backend   │
│  web/api.js    │◀─────────────── │  server.py        │
└────────────────┘   JSON responses└──────────────────┘
  static assets,      REST API + vault data
  hostable anywhere
```

- Every frontend request goes through `ApiClient` (`web/api.js`): local sessions use the relative
  path `/api`, while remote mode targets `http(s)://host:port` with `Authorization: Bearer <token>`.
- Connection settings live in `data/server.json` (see `apiconfig.py`) and are shared by the desktop
  shell and the browser fallback.
- The API is self-describing via `openapi.py`: `/api/openapi.json` (OpenAPI 3.1) and `/api/docs` (HTML).

**API documentation (Chinese)**: [`docs/API.md`](docs/API.md)

### Custom listen IP and port

"Settings → Connection & API" changes the local listen address. Saving applies it safely instead of
breaking the app:

1. **Validate first** — the address must resolve and belong to this machine; the port must be in
   1–65535 and free (Windows `SO_REUSEADDR` allows double binding, so a `connect` probe plus
   `SO_EXCLUSIVEADDRUSE` double-check are used).
2. **Then start** — the configuration is written only after the new address is really listening.
3. **Roll back on failure** — the previous address is restored (including the reset callback) with a
   message that can be shown directly to the user.
4. Unchanged settings do not restart the service; when the address changes, the shell reloads the
   page with the fresh session token.

If a stored port is occupied during startup, the program falls back to a usable port and updates the
configuration instead of failing to start.

### Connecting to a remote API

Run the server on the machine that holds the data:

```bash
python main.py serve --host 0.0.0.0 --port 8765 --token <token>
```

In the desktop client, open "Settings → Connection & API", choose **Remote API**, fill in the address
and token, and use **Test Connection** first. A separately hosted frontend can also be pointed at the
backend with a URL parameter:

```
http://frontend-host/index.html?api=http://192.168.1.9:8765&apiToken=<token>
```

> Use remote mode only on trusted networks or behind an HTTPS reverse proxy.

---

## Security Design

| Item | Implementation |
| --- | --- |
| User Password | Entered only in the login window; stored only in program memory after Argon2id verification |
| Password Storage | Argon2id PHC hash (`m=65536, t=3, p=4`, random salt); automatic re-hashing if parameters become outdated |
| Username Enumeration Protection | Performs a hash check even if the username does not exist to equalize response times |
| Key Derivation | Argon2id with random salt; parameters saved with the file to allow for seamless upgrades |
| Data Encryption | AES-256-GCM (authenticated encryption; tamper detection supported) |
| Service Listening | Binds to `127.0.0.1` on a random port by default; custom IP/port is validated (ownership + availability) before it takes effect |
| UI Host | pywebview desktop window; does not launch the system web browser |
| Origin Verification | Validates `Host` and `Origin` headers to prevent calls from other web pages or DNS rebinding attacks |
| Frontend Isolation | Frontend receives only the verification code and current username; does not receive secrets or passwords |
| Remote Access | Remote calls are allowed only after an `accessToken` is configured explicitly (Bearer token + CORS); disabled by default |
| Self-describing API | `/api/openapi.json` and `/api/docs` are read-only and expose no account data |
| Export/Backup | Backup files are encrypted with the user's password for safe storage; exported `otpauth` text is plaintext and requires secure handling by the user |
| Cleanup on Exit | Clears passwords and keys from memory upon closing the main window or receiving a Ctrl+C signal |

> Security Boundary: This tool assumes the host computer is a trusted device. If the computer has been compromised by an attacker, no local tool can guarantee the security of the keys. ---

## Project Structure

```
156--2FA/
├── main.py              # Main program: data root, login window, desktop/server orchestration
├── server.py            # HTTP service and REST endpoints (backend)
├── apiconfig.py         # Connection config: listen address, port, remote API and tokens
├── openapi.py           # OpenAPI 3.1 spec (single source of truth for the API docs)
├── users.py             # Local multi-user accounts (user table + Argon2id password verification)
├── storage.py           # Encrypted data repository (Vault)
├── crypto_utils.py      # Argon2id password hashing/key derivation & AES-GCM encryption/decryption
├── totp_utils.py        # TOTP / HOTP calculation
├── qr_utils.py          # QR code decoding and otpauth URI parsing
├── requirements.txt     # Python dependencies
├── docs/
│   └── API.md           # API documentation (Chinese)
├── web/                 # Frontend (static, hostable standalone)
│   ├── index.html       # Main page for displaying verification codes
│   ├── login.html       # User login / registration window
│   ├── splash.html      # Splash window (loading progress bar)
│   ├── settings.html    # Theme, connection & API, user switching, program reset
│   ├── apidocs.html     # API documentation page (served at /api/docs)
│   ├── api.js           # Unified API client (local / remote data source)
│   ├── toast.js         # Site-wide toast notification component
│   └── fonts/           # Self-hosted Material Symbols icon font (works offline)
└── data/                # User table, per-user vaults and server.json (generated at runtime)
```

---

## Packaging

- Windows: Run `Windows其他版本用户使用这个.bat`
- Linux / macOS: Run `Linux用户和Mac OS用户使用这个.sh`

The packaged output is located in `dist/2FA-Tool` (or `2FA-Tool.exe` on Windows).

---

## Future Extensions

- Multi-device support: Sync encrypted JSON to a user-hosted server.
- Batch import: Compatibility with common authenticator export formats.
- Export backups: One-click export of encrypted JSON for personal safekeeping.
- Account Management: Interface operations such as changing passwords and deleting specific users.

---

## License

MIT License · Copyright (c) 2026