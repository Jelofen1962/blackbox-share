# Blackbox Share 1.1.0 · reliability and LAN safety update

## Regular sharing stays simple

- Public file uploads and downloads are still accessible to anyone on your trusted LAN, without login, approval, passwords, or additional clicks.
- Admin-only settings continue to require an admin session. There is no longer a shared password in the source code.

## P0 / P1 fixes included

1. Private-file download authorization uses a case-exact real directory entry and rejects filesystem links.
2. Malformed or unreadable privacy metadata and shared-text metadata now prevent startup instead of silently replacing previous data with an empty collection.
3. Administrator password is set once on the host PC and is stored as an Argon2 hash. No hardcoded password remains.
4. Admin sessions expire server-side after 12 hours. Failed admin logins are throttled for 60 seconds per IP after six attempts.
5. JSON routes have a separate 512 KiB body limit. The streaming upload route still has a 20 GiB per-request cap plus multipart overhead.
6. Free disk is checked during upload, retaining a 256 MiB reserve, and the server automatically queues uploads above three parallel transfers.
7. File publication avoids overwrites even in concurrent identical-filename uploads. Windows uses non-replacing MoveFileW, including on removable drives.
8. Privacy, text, and app configuration writes use same-directory temporary files and atomic replacement; in-memory state changes only after persistence succeeds.
9. Temporary abandoned upload files older than 24 hours are removed on startup.
10. Internal shared text files are hidden in the normal browser and protected against uploads using the same filename.
11. Port conflicts and system-tray initialization failures now give clearer feedback on Windows.
12. Windows release workflow now runs Rust regression tests before creating the executable. Browser JavaScript syntax was checked with Node.js.

## Intentional local-network choices and remaining limitations

- Plain HTTP remains on purpose; there is no mandatory HTTPS or authenticated public download/upload. Do not expose the service to the internet or to untrusted LAN users.
- The optional **Private** flag still requires admin login to download those specific files. All normal/public files stay password-free.
- No full device management, DNS-rebinding policy, or account-based upload quota has been added, to preserve LAN convenience. The disk-space reserve is a local safety check, not an authentication gate.
- Retry starts a file over; true resumable chunks, cancellation, and download range support are separate feature work, not included here.
- Filesystem and browser code have not been run in the Windows release environment in this delivery. The GitHub workflow runs the included Rust tests before compiling the Windows executable.
