<?php

/**
 * SQLite3 abstraction for the login vault.
 */
class Database
{
	/** @var SQLite3 */
	private $db;

	/** @var Logger */
	private $logger;

	/**
	 * @param string $dbFile
	 * @param Logger $logger
	 * @throws RuntimeException
	 */
	public function __construct(string $dbFile, Logger $logger)
	{
		$this->logger = $logger;
		$this->logger->entry('Database::__construct', ['db_file' => $dbFile]);

		$dir = dirname($dbFile);
		if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
			throw new RuntimeException("Failed to create database directory: $dir");
		}

		$this->db = new SQLite3($dbFile);
		$this->db->busyTimeout(5000);
		$this->db->exec('PRAGMA foreign_keys = ON;');
		$this->createSchema();

		$this->logger->exit_('Database::__construct');
	}

	/**
	 * @return void
	 */
	private function createSchema(): void
	{
		$this->logger->entry('Database::createSchema');

		$this->db->exec('CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			enrolled_at INTEGER,
			created_at INTEGER NOT NULL DEFAULT (strftime(\'%s\', \'now\'))
		);');

		$this->db->exec('CREATE TABLE IF NOT EXISTS servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			hostname TEXT NOT NULL,
			port INTEGER NOT NULL,
			db_type TEXT NOT NULL,
			db_username TEXT NOT NULL,
			db_password TEXT NOT NULL,
			is_public INTEGER NOT NULL DEFAULT 1,
			ssh_host TEXT,
			ssh_port INTEGER DEFAULT 22,
			ssh_user TEXT,
			ssh_password TEXT,
			ssh_private_key_path TEXT,
			mapped_local_port INTEGER,
			ssh_pid INTEGER,
			last_connected_at INTEGER
		);');

		$this->db->exec('CREATE TABLE IF NOT EXISTS user_servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			UNIQUE(user_id, server_id)
		);');

		$this->logger->exit_('Database::createSchema');
	}

	/**
	 * @param string $sql
	 * @return SQLite3Stmt
	 */
	public function prepare(string $sql): SQLite3Stmt
	{
		return $this->db->prepare($sql);
	}

	/**
	 * @param string $sql
	 * @return SQLite3Result|false
	 */
	public function query(string $sql)
	{
		return $this->db->query($sql);
	}

	/**
	 * @param string $sql
	 * @return bool
	 */
	public function exec(string $sql): bool
	{
		return $this->db->exec($sql);
	}

	/**
	 * @return int
	 */
	public function lastInsertRowID(): int
	{
		return $this->db->lastInsertRowID();
	}

	/**
	 * @param string $value
	 * @return string
	 */
	public function escapeString(string $value): string
	{
		return $this->db->escapeString($value);
	}

	/**
	 * @return void
	 */
	public function close(): void
	{
		$this->db->close();
	}
}
