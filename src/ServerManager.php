<?php

/**
 * Server listing and access control.
 */
class ServerManager
{
	/** @var Database */
	private $database;

	/** @var Crypto */
	private $crypto;

	/** @var Logger */
	private $logger;

	/**
	 * @param Database $database
	 * @param Crypto $crypto
	 * @param Logger $logger
	 */
	public function __construct(Database $database, Crypto $crypto, Logger $logger)
	{
		$this->database = $database;
		$this->crypto = $crypto;
		$this->logger = $logger;
		$this->logger->entry('ServerManager::__construct');
		$this->logger->exit_('ServerManager::__construct');
	}

	/**
	 * @param int $userId
	 * @return array
	 */
	public function listServersForUser(int $userId): array
	{
		$this->logger->entry('ServerManager::listServersForUser', ['user_id' => $userId]);

		$stmt = $this->database->prepare('SELECT s.* FROM servers s
			INNER JOIN user_servers us ON us.server_id = s.id
			WHERE us.user_id = :user_id
			ORDER BY s.name, s.hostname');
		$stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
		$result = $stmt->execute();

		$servers = [];
		while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
			$servers[] = $row;
		}

		$this->logger->exit_('ServerManager::listServersForUser', ['count' => count($servers)]);
		return $servers;
	}

	/**
	 * @param int $serverId
	 * @param int $userId
	 * @return array|null
	 */
	public function getServerForUser(int $serverId, int $userId): ?array
	{
		$this->logger->entry('ServerManager::getServerForUser', ['server_id' => $serverId, 'user_id' => $userId]);

		$stmt = $this->database->prepare('SELECT s.* FROM servers s
			INNER JOIN user_servers us ON us.server_id = s.id
			WHERE s.id = :server_id AND us.user_id = :user_id');
		$stmt->bindValue(':server_id', $serverId, SQLITE3_INTEGER);
		$stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
		$result = $stmt->execute();
		$server = $result->fetchArray(SQLITE3_ASSOC);

		$this->logger->exit_('ServerManager::getServerForUser', ['found' => $server !== false]);
		return $server ?: null;
	}

	/**
	 * @param array $server
	 * @return array
	 * @throws RuntimeException
	 */
	public function decryptCredentials(array $server): array
	{
		$this->logger->entry('ServerManager::decryptCredentials', ['server_id' => $server['id']]);
		$password = $this->crypto->decrypt($server['db_password']);
		$this->logger->exit_('ServerManager::decryptCredentials');
		return [
			'db_username' => $server['db_username'],
			'db_password' => $password,
		];
	}

	/**
	 * @param int $serverId
	 * @param int|null $localPort
	 * @param int|null $pid
	 * @return bool
	 */
	public function updateTunnel(int $serverId, ?int $localPort, ?int $pid): bool
	{
		$this->logger->entry('ServerManager::updateTunnel', ['server_id' => $serverId, 'local_port' => $localPort, 'pid' => $pid]);

		$stmt = $this->database->prepare('UPDATE servers SET mapped_local_port = :port, ssh_pid = :pid, last_connected_at = :now WHERE id = :id');
		$stmt->bindValue(':port', $localPort, $localPort === null ? SQLITE3_NULL : SQLITE3_INTEGER);
		$stmt->bindValue(':pid', $pid, $pid === null ? SQLITE3_NULL : SQLITE3_INTEGER);
		$stmt->bindValue(':now', time(), SQLITE3_INTEGER);
		$stmt->bindValue(':id', $serverId, SQLITE3_INTEGER);
		$result = $stmt->execute() !== false;

		$this->logger->exit_('ServerManager::updateTunnel', ['result' => $result]);
		return $result;
	}

	/**
	 * @return array
	 */
	public function listActiveTunnels(): array
	{
		$this->logger->entry('ServerManager::listActiveTunnels');

		$result = $this->database->query('SELECT id, ssh_pid, mapped_local_port FROM servers WHERE ssh_pid IS NOT NULL AND mapped_local_port IS NOT NULL');
		$tunnels = [];
		while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
			$tunnels[] = $row;
		}

		$this->logger->exit_('ServerManager::listActiveTunnels', ['count' => count($tunnels)]);
		return $tunnels;
	}
}
