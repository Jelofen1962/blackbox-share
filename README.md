# Blackbox Share

A minimal black-and-white Rust file server with an HTML/CSS/JS interface.

## Run

1. Install Rust from https://rustup.rs/
2. From this folder, run:

   ```powershell
   cargo run --release
   ```

3. On first launch, choose the folder used for uploads and downloads.
4. Open `http://127.0.0.1:1962`. Keep the terminal window open while the server is running. The selected folder is saved in your user config, so the folder picker only appears the first time (or if that folder is missing).

The server binds to `0.0.0.0:1962`, so other devices on your LAN can use `http://YOUR-LAN-IP:1962`.

## Admin

Password: `Amir1962$#`

Admin can mark files private and copy direct download links. Private files are hidden from the public listing and direct unauthenticated downloads return 404. Private-file metadata is stored in `.blackbox-share.json` inside the selected folder. Shared text snippets are stored in `share-texts.json` in the selected folder. Only the admin can add or delete snippets; all visitors can click a snippet card to copy its full, untruncated text. Cards visually clamp previews to four lines, while clipboard copy includes the complete text.

## Dashboard features

- Premium light theme in coffee, mauve-bark, almond, and seashell tones.
- Upload progress bar with per-file and queue progress; downloads display progress when the server reports a content length.
- File filters for images, documents, video, audio, archives, private, and public files.
- Default sort is newest modified file first; sorting options also include oldest, name, and size.
- DM Sans interface typography with Playfair Display headings when internet access is available; system font fallbacks are included.

## Start with Windows

Sign in as admin, then enable **Launch with Windows** at the bottom of the page. This creates a per-user Startup script that starts the server when you sign in and opens the local page. Disable the same switch to remove it. The selected storage folder is remembered in your user config.

## Internet sharing

A generated link uses the address in the browser's address bar. To share outside your LAN, you need a reachable public IP/domain and router port-forwarding for TCP 1962, plus an OS firewall rule. Many ISPs use CGNAT, which prevents direct port forwarding. **This starter uses plain HTTP**, so do not expose it to the public internet with sensitive files or passwords; use a VPN or HTTPS/reverse proxy for internet-facing use.

## Notes

- Upload size limit: 1 GB per file.
- Duplicate filenames are rejected.
- File names containing path separators and hidden dotfiles are rejected.
- Uploads are public by default. Sign in and mark sensitive files private.
- The chosen folder is remembered between launches; files, private flags, and Share Text snippets persist.
- Admin session cookies are HttpOnly and SameSite=Strict, but this is a small local utility, not a hardened internet-facing service.
