# Blackbox Share v1.2.0

Blackbox Share is a lightweight Windows LAN file manager and sharing dashboard. It runs as a single Rust executable in the Windows system tray, on port **1962**, serving a local-first browser UI. Public uploads, downloads, file organization, and snippets **do not require accounts or passwords**. Optional administrator login is used only for private-file visibility and Windows autostart settings.

## What's new

- **Folders:** Browse, create, rename, move, and delete files or directories. Drag existing rows onto other folders or breadcrumbs to move them.
- **Folder uploads:** Select a directory using the Folder button (Chromium-based browsers) or drag a directory onto the upload area. Hierarchy is preserved. Empty directories without files are not necessarily transmitted by browsers.
- **Bulk file operations:** Select multiple items and delete, move, or download a ZIP (including nested folders). ZIPs are generated in a temporary file and streamed to the browser, without buffering the entire archive in page memory. Building a ZIP requires temporary drive space up to the archive size.
- **Previews:** Images, PDFs, and browser-compatible videos can be previewed inline; other files are downloadable.
- **QR links:** File, folder and dashboard QR codes are generated using an Apache-2.0-licensed library embedded in the executable. No external website or QR service is needed.
- **No application per-file upload-size cap:** Browser uploads are split into 4 MiB chunks, written to disk, and can resume after a connection interruption while the server and browser session remain running. A retry probes the saved byte offset. The legacy `/api/upload` also accepts streamed files without a per-file size cap. Available disk space and filesystem constraints still apply.
- **Transfer center:** Pause, resume, cancel, transfer speed, per-file progress and estimated time remaining for web-app uploads. Downloads use the browser's download manager; the server supports HTTP Range requests to enable resumable downloads where supported by the client.
- **Live updates:** Server-sent events update open dashboards after file and snippet changes. Native filesystem notifications also pick up edits made outside the app, with a short debounce.
- **Dashboard:** Disk free/used capacity, file/folder counts, active upload status and recently active web dashboard devices. Devices are detected from presence heartbeats and are not intended to be a complete network scan.
- **Dark mode:** Persistent local preference, designed to work without external fonts.
- **Shared text editor:** Add, copy, edit and delete snippets. All snippets remain shared across devices and persisted atomically.
- **Periodic cleanup:** Abandoned chunk uploads and legacy temporary uploads are cleaned periodically after 24 hours.

## Running it

1. Install [Rust](https://rustup.rs/) with Windows MSVC toolchain, or build the standalone Windows x64 binary using the included GitHub Actions workflow.
2. Run `cargo run` from the repository root for development, or run the release EXE.
3. On first run choose the shared folder. Open `http://127.0.0.1:1962` on the host PC, or the displayed LAN URL from another device.
4. Use **↑ Files** for individual files, **↑ Folder** for directories, or drag/drop files/folders into the upload area.
5. Open a folder by clicking its name. Use **•••** for rename, move and delete, or use selection checkboxes for bulk actions.

To build the release binary:

```powershell
cargo test
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release --target x86_64-pc-windows-msvc
```

The resulting executable is `target/x86_64-pc-windows-msvc/release/blackbox-share.exe`. GitHub Actions tests and builds a Windows executable on tags and manual runs.

## LAN sharing and administrator options

Normal local operations never ask for a login. Anyone who can access the server on your trusted LAN can upload, download, create folders, rename, move, delete files and edit shared texts. This is intentional to maximize usability on a personal, trusted network.

For optional **private** files and Windows **Launch with Windows** settings, click Admin. The first administrator password must be created on the host PC at `http://127.0.0.1:1962`, and has a minimum length of eight characters. Privacy metadata is stored in `.blackbox-share.json`; shared texts are in `share-texts.json`. Settings are saved under the user's BlackboxShare configuration directory. The app does not expose these metadata files through its file browser.

**Do not expose this server to the internet or untrusted LANs.** It uses HTTP and intentionally allows unrestricted file management for connected devices, including deletion. Network isolation and operating-system firewall rules are your responsibility.

## Technical notes and limitations

- Files are uploaded in 4 MiB requests (each request has a 16 MiB body-size guard), but **there is no overall application file-size cap**. Chunk state lives in server memory and is retained while the app runs; restarting the browser loses its file selection and restarting the server discards in-memory resumable sessions. Incomplete hidden files are removed during cleanup.
- Bulk ZIP creation uses temporary storage in the shared folder. It uses stored/uncompressed ZIP entries, including ZIP64 for very large files; some older ZIP tools may not support ZIP64. For very large batches, individual downloads are more efficient.
- The browser's own download UI manages download pause and cancellation; the app's transfer queue controls uploads.
- Folder upload supports modern Chromium browsers best. Browser restrictions may prevent uploading completely empty folders.
- Image, PDF and video preview support depends on the formats understood by each browser.
- The active-device list shows recent **dashboard browser sessions**, not all connected IPs or background downloads.
- Private files are available only to a logged-in admin. Files are public by default, and ordinary LAN transfers stay password-free.
- This source package was syntax-checked on its JavaScript files. **A fresh Rust build and full Windows integration test have not been run in the authoring environment.** The GitHub Actions Windows workflow runs Rust tests before publishing a build.

See `CHANGES-v1.2.0.md` for new endpoints, testing and the remaining nonblocking limitations.
