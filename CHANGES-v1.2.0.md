# Blackbox Share v1.2.0 change log

## Backend

- Path-safe nested directory listing and file operations: `/api/tree`, `/api/folder`, `/api/manage`.
- Resumable 4 MiB multipart chunk transfer endpoints: `POST /api/chunks`, `GET /api/chunks?id=...`, `POST /api/chunks/cancel`. Upload size is bounded only by storage/filesystem capacity, not the application's file size constant.
- HTTP range/partial responses and inline preview support at `/download/*name`.
- Auth-checked private metadata for nested file paths: `/api/private-path`.
- Bulk ZIP generation and streaming: `/api/zip?paths=<encoded JSON array>`.
- Server-sent events: `/api/events`, plus native filesystem watching.
- Device presence and disk dashboard: `/api/presence`, `/api/dashboard`.
- Shared text editing: `/api/texts/edit`.
- Periodic cleanup of abandoned uploads older than 24h; retained existing atomic settings/metadata writes.

## Frontend

- New responsive local-first dashboard; system fonts and embedded QR library.
- Folder browser, breadcrumbs, file selection, folder uploads, previews and QR codes.
- Pause/resume/cancel controls, byte progress, transfer speed and ETA for uploads.
- Bulk delete, bulk move and streamed ZIP downloads.
- Live updates, connected dashboard sessions, storage statistics and dark mode.
- Editable shared text snippets.

## Validation

- `node --check web/app.js`
- `node --check web/qr.js`
- QR code generated with the bundled offline JS library in Node.
- Rust test cases added for nested-path traversal and old functionality retained. Actual Rust compilation and Windows integration tests remain necessary.

## Known limitations

- Download control (pause/cancel) remains in the **browser download manager**, not in the web application's upload queue. Server-side single-range support is implemented.
- Browser reload or server restart cannot automatically recover the user-selected File objects for interrupted uploads. Network interruptions while the tab and server remain running are retried and resumed.
- Browser OS permissions may prevent preserving empty folders in directory uploads.
- ZIPs consume temporary storage roughly equal to the downloaded content.
- Active devices are browser heartbeats, not a low-level socket/OS connection list.
- Security hardening, HTTPS, and user account requirements were intentionally not introduced for public file transfers.
