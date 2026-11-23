# Blackbox Share

Blackbox Share is a small file server for Windows. It gives you one simple page to upload files, download files, share text, and copy links that work on your local network.

The app runs in the Windows system tray, uses port **1962**, and stores files in a folder you choose. Its interface uses a warm, light theme and supports large uploads with progress feedback.

## Features

- **Upload and download:** Drag files into the page or choose them from your device.
- **Progress feedback:** Track upload progress in the dashboard. Downloads are streamed directly by the browser, which manages their progress without loading the complete file into page memory.
- **Large-file transfers:** Uploads stream to disk and downloads stream to the browser, avoiding loading the whole file into memory. Files up to 20 GiB are supported. Interrupted uploads retry automatically up to three times. Concurrent transfers queue automatically and low disk space is detected before filling the drive.
- **Live file updates:** Open dashboards check for new files every four seconds and update without a manual refresh.
- **Search and filters:** Find files by name, type, visibility, date, or size.
- **LAN download links:** Any visitor can copy a download link that uses the server's local network IP address.
- **Shared text:** Any visitor can add and copy text snippets. Cards show a short preview, while copy keeps the full text.
- **Private files:** Admins can hide files from the public list and block public downloads.
- **System tray:** Open the dashboard or exit from the tray menu. The release build does not open a command window.
- **Windows startup:** Automatic launch at Windows sign-in is enabled on first run. Admin settings can turn it off or back on.
- **Single-file release:** GitHub Actions builds one standalone Windows x64 executable.

## Download and install

1. Open the project's **Releases** page on GitHub.
2. Download `Blackbox-Share-Windows-x64.exe` from the latest release.
3. Save the executable in a folder where you want to keep it.
4. Run it. The first run asks you to choose a folder for shared files.
5. Your browser opens the dashboard at `http://127.0.0.1:1962`.

Keep the executable in the same place after enabling Windows startup. The startup entry points to that path.

> [!NOTE]
> Windows may ask whether to allow network access. Allow access on **Private networks** if you want other devices on your home or work LAN to connect.

## Use the app

### Upload and download files

1. Open the dashboard.
2. Drop files into the upload area or choose files.
3. Use search, filters, and sort options to find a file.
4. Select **Download** to save a file to your device.
5. Select **Copy LAN link** to copy a direct download URL for another device on the same network.

Files are public by default. Sign in as admin to mark a file private. A private file does not appear in the public list, and an unauthenticated download request returns a not-found response.

### Share text

The Share Text section is open to all visitors on the LAN. Add a title and paste or type the text, then select **Save text**. Select a card to copy its full text. The card preview is shortened only for display.

Any visitor can add text. Only the admin can delete saved text. The app stores snippets in `share-texts.json` in the selected folder.

### Admin access

Select **Admin login** to manage private files, delete shared text, and change startup settings.

There is **no built-in admin password**. On the host PC, open `http://127.0.0.1:1962`, click **Set up admin**, and choose your own password (at least 8 characters). You only need to do this once. Existing installations upgrading from a hardcoded-password build need to complete this one-time setup; the old password no longer works. The new admin password is stored as an Argon2 password hash in the per-user config, not in the executable.

**Upload and download require no account or password.** The admin password is only for the optional private-file switch, shared-text deletion, and Windows startup settings. Files marked private remain accessible only to the logged-in admin. Leave files public for frictionless local sharing.

### Use it from another device

On the host computer, find the LAN address printed by the app or copy a LAN link from a file card. On another device connected to the same network, open that address in a browser.

The app listens on `0.0.0.0:1962`. Windows Firewall must allow inbound traffic on port `1962` for private networks. Devices on guest Wi-Fi or separate VLANs may not be able to reach each other.

> [!IMPORTANT]
> LAN links are meant for devices on the same trusted network. The server uses plain HTTP, not HTTPS. Do not forward port `1962` to the public internet or share sensitive files over an untrusted network. A public IP, router port forwarding, and firewall rules alone do not make the service secure.

## System tray and startup

The Windows release starts without a command window and creates a tray icon. Right-click the icon to open the dashboard or exit the app. The browser opens when the server starts.

The app enables **Launch with Windows** on its first run and creates a hidden VBScript entry in your Windows Startup folder. It starts when your Windows account signs in (not before the Windows sign-in screen). Sign in as admin to turn the setting off or back on. Keep the executable at its current path. If you move the executable, turn startup off and on again to update the saved path.

## Storage and configuration

The first run asks you to choose a shared folder. The app remembers that folder in your user configuration. Uploads stream to hidden temporary files and are renamed into place only after completion, so interrupted transfers do not appear as finished files. The folder stores shared files and these data files:

| File | Purpose |
| --- | --- |
| `share-texts.json` | Shared text snippets |
| `.blackbox-share.json` | Private-file flags |
| `config.json` | Saved folder path, startup options and Argon2 admin password hash, stored in the user's app config directory rather than the shared folder |

Do not delete the JSON files if you want to keep their settings and shared text. Back up the shared folder and your per-user app config to keep your data safe. If privacy metadata is corrupted or inaccessible, the server refuses to start instead of accidentally publishing previously private files. Text data is also loaded strictly to avoid silently losing snippets.

## Build from source

You need the stable Rust toolchain and a Windows build environment. Install Rust from [rustup.rs](https://rustup.rs/).

Run these commands from the project folder:

```powershell
cargo run
```

This starts the app in development mode. A console may be visible in debug builds.

To build a Windows release executable locally:

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release --target x86_64-pc-windows-msvc
```

The executable is written to:

```text
target/x86_64-pc-windows-msvc/release/blackbox-share.exe
```

The Windows tray icon uses Windows-only dependencies. The release workflow builds on `windows-latest`, embeds the HTML page at compile time, and publishes the executable as a single release asset.

## Automatic GitHub releases

The workflow in `.github/workflows/windows-release.yml` builds a Windows x64 executable and publishes it to a public GitHub Release.

To publish a version, push a tag such as `v1.0.0`:

```powershell
git add .
git commit -m "Prepare release"
git push origin main
git tag v1.0.0
git push origin v1.0.0
```

You can also run **Actions → Windows Release → Run workflow**. A manual run can use a tag name or create a `manual-N` tag automatically. The repository workflow needs `contents: write` permission to publish releases.

## Project layout

```text
.
├── .github/workflows/windows-release.yml  # Windows build and release
├── src/main.rs                            # Rust server, API, tray, startup
├── web/index.html                         # Embedded dashboard and frontend
├── Cargo.toml                             # Rust dependencies and build setup
├── scripts/flesch_kincaid.rb              # README reading-level check
└── README.md                              # Project guide
```

## Troubleshooting

- **The page does not open:** Open `http://127.0.0.1:1962` manually. Check that another app is not using port `1962`.
- **Another device cannot connect:** Confirm both devices use the same LAN and allow port `1962` through Windows Firewall on private networks.
- **A large upload is interrupted:** The app retries temporary connection failures up to three times. A retry starts that file again; it does not resume from the exact byte where the connection stopped. Check that the shared drive has enough free space and keep the host computer awake during transfers.
- **A new file is not visible immediately:** The dashboard checks for changes every four seconds. Use the Refresh button for an immediate check.
- **A link does not work on another device:** Make sure the device is on the same network and that the host computer is still running Blackbox Share. The host's LAN IP can change when the router reconnects.
- **The app is missing from the tray:** Check the hidden-icons area near the Windows clock. Restart the app if the icon is not there.
- **Startup no longer works:** The executable may have moved. Turn off **Launch with Windows**, then turn it on again.
- **The release build fails:** Open the failed run in GitHub Actions and read the first build error. Check that the workflow has write access to repository contents.

## Contributing

Issues and pull requests are welcome. Please describe the change, include steps to test it, and keep the app focused on simple local file sharing. Test Windows-specific changes on Windows before opening a pull request.

## License

No license file is included yet. Add a `LICENSE` file before redistributing this project if you want to grant others clear reuse rights.

## Credits

Made by [Jelofen1962](https://github.com/Jelofen1962).

## Version 1.1.0 reliability changes

- Preserves the password-free LAN file upload and public download experience.
- First-run localhost-only admin password setup replaces the previously hardcoded password.
- Locks admin sessions to a real 12-hour lifetime and limits repeated failed admin login attempts only.
- Prevents casing-based private-file access on Windows and excludes symlinks/reparse points from the shared library.
- Fails closed on unreadable/corrupted private-file metadata; no automatic reset to public.
- Writes privacy settings, shared text, and app configuration with temporary files and atomic replacement. In-memory changes happen only after successful storage.
- Limits JSON request sizes independently of the 20 GiB streaming upload route.
- Preserves at least 256 MiB available storage during uploads, and queues up to three simultaneous server-side transfers.
- Publishes uploads atomically without overwriting an existing file (including same-name races). Uses Win32 MoveFileW on Windows to work with removable drives.
- Removes stale temporary upload files older than 24 hours on startup.
- Hides internal shared-text data from the regular file browser and prevents users from overwriting its filename.
- Displays errors for Windows port conflicts and tray initialization issues.
- Adds Rust regression tests and runs them in the Windows release workflow.

The service is designed for **trusted LANs only**. HTTP is kept intentionally for simple local sharing. Do not expose port 1962 directly to the public internet. A guest can upload public files without login; this is by design.
