# Adminer Login System Plugin

A vault-based authentication and server selection plugin for [Adminer](https://www.adminer.org/).

## Features

- Vault login with bcrypt-protected passwords
- TOTP two-factor authentication
- Encrypted database credentials at rest (AES-256-CBC)
- Per-user server access control
- Optional SSH tunnel support for private servers
- JSON audit logging
- CLI seed and TOTP tools

## Installation

1. Copy this directory next to your Adminer installation.
2. Create an `adminer-plugins.php` file alongside `adminer.php`:

```php
<?php
require_once __DIR__ . '/externals/adminer-login-system/adminer-login-system.php';

return [
	new AdminerLoginSystem(
		__DIR__ . '/externals/adminer-login-system/login-vault.db',
		'your-random-master-key',
		true,
		__DIR__ . '/externals/adminer-login-system/login-system.log'
	),
];
```

3. Run the seed tool to create the vault and first admin user:

```sh
php externals/adminer-login-system/bin/seed.php
```

4. Open Adminer and log in with the vault username, vault password, and TOTP code.

## CLI Tools

### Seed vault and create admin user

```sh
php bin/seed.php [db-file] [master-key]
```

### Print current TOTP code

```sh
php bin/totp.php <username> [db-file] [master-key]
```

## Security Notes

- Keep the master key secret and store it outside version control.
- Back up `login-vault.db`; losing the database or master key means losing access to stored credentials.
- Use strong SSH keys for tunnel auth instead of passwords where possible.
