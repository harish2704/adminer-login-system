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
	new Adminer\AdminerLoginSystem(
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

## Adding servers and access

Servers and user-to-server access mappings are managed manually (web UI is planned for later). Insert rows directly into the SQLite vault, e.g. with `sqlite3 login-vault.db`:

```sql
-- public MySQL server
INSERT INTO servers (name, hostname, port, db_type, db_username, db_password, is_public)
VALUES ('Production MySQL', 'db.example.com', 3306, 'mysql', 'dbuser', 'ENCRYPTED_PASSWORD', 1);

-- private PostgreSQL server reached through a bastion
INSERT INTO servers (name, hostname, port, db_type, db_username, db_password, is_public, ssh_host, ssh_port, ssh_user, ssh_private_key_path)
VALUES ('Private Postgres', 'pg.internal', 5432, 'pgsql', 'dbuser', 'ENCRYPTED_PASSWORD', 0, 'bastion.example.com', 22, 'sshuser', '/path/to/id_rsa');

-- grant the admin user access to both servers
INSERT INTO user_servers (user_id, server_id) VALUES (1, 1), (1, 2);
```

`db_password` must be the value produced by `Crypto::encrypt()` using your master key. For a one-off encryption you can use a small PHP snippet:

```php
require_once 'src/Logger.php';
require_once 'src/Crypto.php';
$crypto = new Crypto('your-master-key', new Logger(false, ''));
echo $crypto->encrypt('plain-db-password');
```

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
