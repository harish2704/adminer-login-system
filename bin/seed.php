<?php

require_once __DIR__ . '/../src/Logger.php';
require_once __DIR__ . '/../src/Database.php';

$dbFile = $argv[1] ?? __DIR__ . '/../login-vault.db';
$masterKey = $argv[2] ?? null;

if ($masterKey === null) {
	fwrite(STDERR, "Usage: php bin/seed.php [db-file] [master-key]\n");
	exit(1);
}

$logger = new Logger(false, __DIR__ . '/../login-system.log');
$database = new Database($dbFile, $logger);

$username = readline('Admin username: ');
$password = readline('Admin password: ');

if ($username === '' || $password === '') {
	fwrite(STDERR, "Username and password are required.\n");
	exit(1);
}

$stmt = $database->prepare('SELECT id FROM users WHERE username = :username');
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$result = $stmt->execute();

if ($result->fetchArray(SQLITE3_ASSOC)) {
	fwrite(STDERR, "User already exists.\n");
	exit(1);
}

$hash = password_hash($password, PASSWORD_BCRYPT);
$stmt = $database->prepare('INSERT INTO users (username, password_hash, created_at) VALUES (:username, :hash, :created_at)');
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
$stmt->bindValue(':created_at', time(), SQLITE3_INTEGER);

if ($stmt->execute() === false) {
	fwrite(STDERR, "Failed to create user.\n");
	exit(1);
}

echo "Created admin user: $username\n";
