# Changelog

## [Unreleased]

### Added

- **Step-by-step login flow**: login is now split into four sequential steps: (1) username + password, (2) TOTP verification, (3) server selection, (4) connect. TOTP is no longer embedded in the Adminer login form.
- **`verify-totp` page**: standalone TOTP verification page between password auth and server selection, shown when a user has TOTP enrolled.
- **`authenticateUsernamePassword()`**: password-only validation method in Authenticator, separate from the combined password+TOTP `authenticate()` method.
- **`adminer_login_system_totp_verified` session flag**: tracks whether TOTP has been verified in the current session, preventing bypass of step 2.

### Changed

- **Login form**: removed TOTP code field from the Adminer login form (`loginFormField()` hook). The form now matches the standard Adminer login appearance.
- **`handleVaultLogin()`**: validates username + password only (via `authenticateUsernamePassword()`), then redirects to `verify-totp` (if enrolled) or `enroll-totp` (if not). No longer completes Adminer login or sets `$_POST` for state DB.
- **Constructor GET redirect**: respects `adminer_login_system_totp_verified` flag — redirects to `verify-totp` when TOTP is enrolled but not yet verified.
- **`renderEnrollTotp()`**: sets `totp_verified = true` after successful enrollment before redirecting to server selection.
- **Logout**: clears `adminer_login_system_totp_verified` session flag.

## 0.2.0 — 2026-07-15

### Added

- **Super admin role**: `role` column on `users` table (`'admin'` or `'user'`), stored in session on login.
- **Admin UI**: management interface for super admins (visible via "Admin" nav link), with pages for users, servers, and access management.
- **User CRUD**: list, add, edit, and delete vault users with username, password (bcrypt), and role selection.
- **Server CRUD**: list, add, edit, and delete database server entries with full SSH tunnel configuration. Database passwords are AES-256-CBC encrypted at rest.
- **Access matrix**: checkbox grid (users × servers) to grant or revoke server access, saved in one submission.
- **Admin dashboard**: overview page with counts of users, servers, and access mappings.
- **Last admin protection**: prevents deleting the last admin user; also prevents admins from deleting their own account.
- **Tunnel cleanup**: active SSH tunnels are killed before a server is deleted.
- **`menuActions()` hook**: "Admin" navigation link only visible to super admins.
- **`bin/seed.php --no-admin`**: flag to create non-admin users via CLI.

### Fixed

- **No web UI for vault management** — resolved with the new admin interface.

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
