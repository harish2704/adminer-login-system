<?php

require_once __DIR__ . '/../src/Logger.php';
require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/Totp.php';

$username = $argv[1] ?? null;
$dbFile = $argv[2] ?? __DIR__ . '/../login-vault.db';
$masterKey = $argv[3] ?? null;

if ($username === null) {
	fwrite(STDERR, "Usage: php bin/totp.php <username> [db-file] [master-key]\n");
	exit(1);
}

$logger = new Logger(false, __DIR__ . '/../login-system.log');
$database = new Database($dbFile, $logger);
$totp = new Totp($logger);

$stmt = $database->prepare('SELECT username, totp_secret FROM users WHERE username = :username');
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$result = $stmt->execute();
$user = $result->fetchArray(SQLITE3_ASSOC);

if (!$user) {
	fwrite(STDERR, "User not found.\n");
	exit(1);
}

if (empty($user['totp_secret'])) {
	fwrite(STDERR, "User has no TOTP secret enrolled.\n");
	exit(1);
}

$code = $totp->code($user['totp_secret']);
$remaining = $totp->secondsRemaining();

echo "TOTP code for {$user['username']}: $code ($remaining seconds remaining)\n";
