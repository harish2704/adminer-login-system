<?php

/**
 * Admin CRUD operations for users, servers, and access management.
 */
class AdminManager
{
	/** @var Database */
	private $database;

	/** @var Crypto */
	private $crypto;

	/** @var Logger */
	private $logger;

	/** @var Authenticator */
	private $authenticator;

	/** @var ServerManager */
	private $serverManager;

	/** @var SshTunnel */
	private $sshTunnel;

	/** @var ?int */
	private $currentUserId;

	/**
	 * @param Database $database
	 * @param Crypto $crypto
	 * @param Logger $logger
	 * @param Authenticator $authenticator
	 * @param ServerManager $serverManager
	 * @param SshTunnel $sshTunnel
	 * @param ?int $currentUserId
	 */
	public function __construct(
		Database $database,
		Crypto $crypto,
		Logger $logger,
		Authenticator $authenticator,
		ServerManager $serverManager,
		SshTunnel $sshTunnel,
		?int $currentUserId = null
	) {
		$this->database = $database;
		$this->crypto = $crypto;
		$this->logger = $logger;
		$this->authenticator = $authenticator;
		$this->serverManager = $serverManager;
		$this->sshTunnel = $sshTunnel;
		$this->currentUserId = $currentUserId;
	}

	// ---------------------------------------------------------------
	// Users
	// ---------------------------------------------------------------

	/**
	 * @return array
	 */
	public function listUsers(): array
	{
		return $this->authenticator->listUsers();
	}

	/**
	 * @param int $id
	 * @return array|null
	 */
	public function getUser(int $id): ?array
	{
		return $this->authenticator->getUserById($id);
	}

	/**
	 * @param string $username
	 * @param string $password
	 * @param string $role
	 * @return int
	 */
	public function createUser(string $username, string $password, string $role): int
	{
		$this->logger->entry('AdminManager::createUser', ['username' => $username, 'role' => $role]);

		$hash = password_hash($password, PASSWORD_DEFAULT);
		$stmt = $this->database->prepare('INSERT INTO users (username, password_hash, role) VALUES (:username, :hash, :role)');
		$stmt->bindValue(':username', $username, SQLITE3_TEXT);
		$stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
		$stmt->bindValue(':role', $role, SQLITE3_TEXT);
		$stmt->execute();

		$id = $this->database->lastInsertRowID();

		$this->logger->log('Admin created user', ['user_id' => $id, 'username' => $username, 'role' => $role]);
		return $id;
	}

	/**
	 * @param int $id
	 * @param array $data keys: username, password (optional, empty = keep), role
	 * @return bool
	 */
	public function updateUser(int $id, array $data): bool
	{
		$this->logger->entry('AdminManager::updateUser', ['user_id' => $id]);

		if ($data['password'] !== '') {
			$hash = password_hash($data['password'], PASSWORD_DEFAULT);
			$stmt = $this->database->prepare('UPDATE users SET username = :username, password_hash = :hash, role = :role WHERE id = :id');
			$stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
		} else {
			$stmt = $this->database->prepare('UPDATE users SET username = :username, role = :role WHERE id = :id');
		}

		$stmt->bindValue(':username', $data['username'], SQLITE3_TEXT);
		$stmt->bindValue(':role', $data['role'], SQLITE3_TEXT);
		$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
		$result = $stmt->execute();

		$this->logger->log('Admin updated user', ['user_id' => $id, 'username' => $data['username'], 'role' => $data['role']]);
		return $result !== false;
	}

	/**
	 * @param int $id
	 * @return bool
	 */
	public function deleteUser(int $id): bool
	{
		$this->logger->entry('AdminManager::deleteUser', ['user_id' => $id]);

		if ($id === $this->currentUserId) {
			$this->logger->log('Admin cannot delete self', ['user_id' => $id], 'warning');
			return false;
		}

		if ($this->authenticator->isLastAdmin()) {
			$this->logger->log('Cannot delete last admin user', ['user_id' => $id], 'warning');
			return false;
		}

		$stmt = $this->database->prepare('DELETE FROM users WHERE id = :id');
		$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
		$result = $stmt->execute();

		$this->logger->log('Admin deleted user', ['user_id' => $id]);
		return $result !== false;
	}

	// ---------------------------------------------------------------
	// Servers
	// ---------------------------------------------------------------

	/**
	 * @return array
	 */
	public function listServers(): array
	{
		return $this->serverManager->listServers();
	}

	/**
	 * @param int $id
	 * @return array|null
	 */
	public function getServer(int $id): ?array
	{
		return $this->serverManager->getServer($id);
	}

	/**
	 * @param array $data
	 * @return int
	 */
	public function createServer(array $data): int
	{
		$this->logger->entry('AdminManager::createServer', ['name' => $data['name'] ?? '']);

		$encrypted = $this->crypto->encrypt($data['db_password']);

		$stmt = $this->database->prepare('INSERT INTO servers (name, hostname, port, db_type, db_username, db_password, is_public, ssh_host, ssh_port, ssh_user, ssh_password, ssh_private_key_path)
			VALUES (:name, :hostname, :port, :db_type, :db_username, :db_password, :is_public, :ssh_host, :ssh_port, :ssh_user, :ssh_password, :ssh_private_key_path)');

		$stmt->bindValue(':name', $data['name'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':hostname', $data['hostname'], SQLITE3_TEXT);
		$stmt->bindValue(':port', (int) $data['port'], SQLITE3_INTEGER);
		$stmt->bindValue(':db_type', $data['db_type'], SQLITE3_TEXT);
		$stmt->bindValue(':db_username', $data['db_username'], SQLITE3_TEXT);
		$stmt->bindValue(':db_password', $encrypted, SQLITE3_TEXT);
		$stmt->bindValue(':is_public', !empty($data['is_public']) ? 1 : 0, SQLITE3_INTEGER);
		$stmt->bindValue(':ssh_host', $data['ssh_host'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':ssh_port', $data['ssh_port'] !== '' ? (int) $data['ssh_port'] : null, $data['ssh_port'] !== '' ? SQLITE3_INTEGER : SQLITE3_NULL);
		$stmt->bindValue(':ssh_user', $data['ssh_user'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':ssh_password', $data['ssh_password'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':ssh_private_key_path', $data['ssh_private_key_path'] ?? '', SQLITE3_TEXT);
		$stmt->execute();

		$id = $this->database->lastInsertRowID();

		$this->logger->log('Admin created server', ['server_id' => $id, 'hostname' => $data['hostname']]);
		return $id;
	}

	/**
	 * @param int $id
	 * @param array $data
	 * @return bool
	 */
	public function updateServer(int $id, array $data): bool
	{
		$this->logger->entry('AdminManager::updateServer', ['server_id' => $id]);

		$dbPassword = $data['db_password'];
		if ($dbPassword !== '') {
			$dbPassword = $this->crypto->encrypt($dbPassword);
			$stmt = $this->database->prepare('UPDATE servers SET name = :name, hostname = :hostname, port = :port, db_type = :db_type,
				db_username = :db_username, db_password = :db_password, is_public = :is_public,
				ssh_host = :ssh_host, ssh_port = :ssh_port, ssh_user = :ssh_user, ssh_password = :ssh_password,
				ssh_private_key_path = :ssh_private_key_path WHERE id = :id');
			$stmt->bindValue(':db_password', $dbPassword, SQLITE3_TEXT);
		} else {
			$stmt = $this->database->prepare('UPDATE servers SET name = :name, hostname = :hostname, port = :port, db_type = :db_type,
				db_username = :db_username, is_public = :is_public,
				ssh_host = :ssh_host, ssh_port = :ssh_port, ssh_user = :ssh_user, ssh_password = :ssh_password,
				ssh_private_key_path = :ssh_private_key_path WHERE id = :id');
		}

		$stmt->bindValue(':name', $data['name'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':hostname', $data['hostname'], SQLITE3_TEXT);
		$stmt->bindValue(':port', (int) $data['port'], SQLITE3_INTEGER);
		$stmt->bindValue(':db_type', $data['db_type'], SQLITE3_TEXT);
		$stmt->bindValue(':db_username', $data['db_username'], SQLITE3_TEXT);
		$stmt->bindValue(':is_public', !empty($data['is_public']) ? 1 : 0, SQLITE3_INTEGER);
		$stmt->bindValue(':ssh_host', $data['ssh_host'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':ssh_port', $data['ssh_port'] !== '' ? (int) $data['ssh_port'] : null, $data['ssh_port'] !== '' ? SQLITE3_INTEGER : SQLITE3_NULL);
		$stmt->bindValue(':ssh_user', $data['ssh_user'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':ssh_password', $data['ssh_password'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':ssh_private_key_path', $data['ssh_private_key_path'] ?? '', SQLITE3_TEXT);
		$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
		$result = $stmt->execute();

		$this->logger->log('Admin updated server', ['server_id' => $id]);
		return $result !== false;
	}

	/**
	 * @param int $id
	 * @return bool
	 */
	public function deleteServer(int $id): bool
	{
		$this->logger->entry('AdminManager::deleteServer', ['server_id' => $id]);

		$server = $this->serverManager->getServer($id);
		if ($server && !empty($server['ssh_pid'])) {
			$this->sshTunnel->killProcess((int) $server['ssh_pid']);
			$this->logger->log('Killed tunnel before server deletion', ['server_id' => $id, 'pid' => $server['ssh_pid']]);
		}

		$stmt = $this->database->prepare('DELETE FROM servers WHERE id = :id');
		$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
		$result = $stmt->execute();

		$this->logger->log('Admin deleted server', ['server_id' => $id]);
		return $result !== false;
	}

	// ---------------------------------------------------------------
	// Access management
	// ---------------------------------------------------------------

	/**
	 * Returns the access matrix as user_id => [server_id, ...].
	 * @return array
	 */
	public function getUserServers(): array
	{
		$this->logger->entry('AdminManager::getUserServers');

		$result = $this->database->query('SELECT user_id, server_id FROM user_servers ORDER BY user_id, server_id');
		$map = [];
		while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
			$uid = (int) $row['user_id'];
			$sid = (int) $row['server_id'];
			if (!isset($map[$uid])) {
				$map[$uid] = [];
			}
			$map[$uid][] = $sid;
		}

		$this->logger->exit_('AdminManager::getUserServers');
		return $map;
	}

	/**
	 * Replace all server access for a user with the given set.
	 * @param int $userId
	 * @param array $serverIds
	 * @return bool
	 */
	public function setUserServers(int $userId, array $serverIds): bool
	{
		$this->logger->entry('AdminManager::setUserServers', ['user_id' => $userId, 'server_count' => count($serverIds)]);

		$stmtDel = $this->database->prepare('DELETE FROM user_servers WHERE user_id = :user_id');
		$stmtDel->bindValue(':user_id', $userId, SQLITE3_INTEGER);
		$stmtDel->execute();

		$stmtIns = $this->database->prepare('INSERT INTO user_servers (user_id, server_id) VALUES (:user_id, :server_id)');
		foreach ($serverIds as $serverId) {
			$stmtIns->bindValue(':user_id', $userId, SQLITE3_INTEGER);
			$stmtIns->bindValue(':server_id', (int) $serverId, SQLITE3_INTEGER);
			$stmtIns->execute();
		}

		$this->logger->log('Admin updated user server access', ['user_id' => $userId, 'server_ids' => $serverIds]);
		return true;
	}

	// ---------------------------------------------------------------
	// Validation
	// ---------------------------------------------------------------

	/**
	 * @param array $data
	 * @param int|null $excludeId
	 * @return array
	 */
	public function validateUser(array $data, ?int $excludeId = null): array
	{
		$errors = [];

		$username = trim($data['username'] ?? '');
		if ($username === '') {
			$errors[] = 'Username is required.';
		} elseif (!preg_match('/^[a-zA-Z0-9_\-\.@]{1,255}$/', $username)) {
			$errors[] = 'Username can only contain letters, numbers, and the characters _ - . @.';
		}

		$password = $data['password'] ?? '';
		$isNew = $excludeId === null;
		if ($isNew && $password === '') {
			$errors[] = 'Password is required for new users.';
		}

		$role = $data['role'] ?? '';
		if (!in_array($role, ['admin', 'user'], true)) {
			$errors[] = 'Role must be "admin" or "user".';
		}

		// Check unique username (exclude current user on edit)
		if ($excludeId !== null) {
			$stmt = $this->database->prepare('SELECT COUNT(*) AS cnt FROM users WHERE username = :username AND id != :exclude_id');
			$stmt->bindValue(':exclude_id', $excludeId, SQLITE3_INTEGER);
		} else {
			$stmt = $this->database->prepare('SELECT COUNT(*) AS cnt FROM users WHERE username = :username');
		}
		$stmt->bindValue(':username', $username, SQLITE3_TEXT);
		$result = $stmt->execute();
		$row = $result->fetchArray(SQLITE3_ASSOC);
		if ($row && (int) $row['cnt'] > 0) {
			$errors[] = 'Username is already taken.';
		}

		return $errors;
	}

	/**
	 * @param array $data
	 * @return array
	 */
	public function validateServer(array $data): array
	{
		$errors = [];

		if (trim($data['hostname'] ?? '') === '') {
			$errors[] = 'Hostname is required.';
		}

		$port = $data['port'] ?? '';
		if ($port === '' || (int) $port < 1 || (int) $port > 65535) {
			$errors[] = 'Port must be a number between 1 and 65535.';
		}

		$validTypes = ['server', 'pgsql', 'sqlite', 'mssql', 'oracle', 'firebird', 'simpledb', 'mongo', 'elastic', 'clickhouse'];
		if (!in_array($data['db_type'] ?? '', $validTypes, true)) {
			$errors[] = 'Database type is not valid.';
		}

		if (trim($data['db_username'] ?? '') === '') {
			$errors[] = 'Database username is required.';
		}

		return $errors;
	}
}
