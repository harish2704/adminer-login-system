# Changelog

## [Unreleased]

- Initial public release.

## 0.1.0 — 2026-07-15

### Added

- **Vault authentication**: bcrypt-protected login against an embedded SQLite3 vault with per-user access control.
- **TOTP two-factor**: optional time-based one-time password enrollment and verification (SHA1, 30 s window, 6 digits).
- **Server selection UI**: radio-button table of authorised servers after vault login.
- **SSH tunneling**: automatic local port forwarding for non-public servers via `ssh -N -L` with PID lifecycle management (`pgrep -f`, `proc_open` array mode, `sshpass` fallback).
- **Encrypted vault**: AES-256-CBC encryption of stored database passwords using a user-provided master key.
- **Session-based state routing**: lightweight SQLite state database (`adminer-login-system-state.db`) to satisfy Adminer's requirement for an active database connection during vault/interstitial pages.
- **Logout**: tunnel teardown and session cleanup on explicit logout.
- **Audit logging**: structured JSON logging with secret redaction.
- **CLI tools**: `bin/seed.php` for interactive admin user creation, `bin/totp.php` for TOTP code calculation.
- **Constructor redirect**: GET requests with an active vault session but no server selected are redirected to `?login-system=enroll-totp` (first login) or `?login-system=select-server`.

### Fixed

- **Custom page rendering**: moved from `homepage()` to `headers()` hook because `connect.inc.php` intercepts "no database selected" requests and exits before `index.php` dispatches to `db.inc.php` (where `homepage()` would fire).
- **Session writes after `stop_session()`**: added `session_start()`/`session_write_close()` pairs in `connectToServer()` since `auth.inc.php` calls `stop_session(true)`, which closes the session before our hooks run.
- **Credentials for SQLite state DB**: `credentials()` returns empty password (`''`) for the state database because the SQLite driver rejects non-empty passwords.
- **Session token persistence**: `$_SESSION["token"]` is explicitly set in `handleVaultLogin()` to ensure it is available for subsequent GET requests.

### Known Limitations

- **SQLite driver ignores server parameter**: SQLite connects to `:memory:` regardless of the server value passed, so remote-host entries are unsupported with this driver. Use MySQL, PostgreSQL, or other network-capable drivers for production.
- **No web UI for vault management**: users, servers, and permissions must be managed via `sqlite3` CLI or the `bin/seed.php` tool.
- **SSH password auth**: unsupported; use key-based auth or `~/.ssh/config` to handle bastion authentication.
