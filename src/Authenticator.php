<?php

/**
 * Vault user authentication.
 */
class Authenticator
{
	/** @var Database */
	private $database;

	/** @var Totp */
	private $totp;

	/** @var Logger */
	private $logger;

	/**
	 * @param Database $database
	 * @param Totp $totp
	 * @param Logger $logger
	 */
	public function __construct(Database $database, Totp $totp, Logger $logger)
	{
		$this->database = $database;
		$this->totp = $totp;
		$this->logger = $logger;
		$this->logger->entry('Authenticator::__construct');
		$this->logger->exit_('Authenticator::__construct');
	}

	/**
	 * @param string $username
	 * @param string $password
	 * @param string $otp
	 * @return array|null
	 */
	public function authenticate(string $username, string $password, string $otp): ?array
	{
		$this->logger->entry('Authenticator::authenticate', ['username' => $username]);

		$stmt = $this->database->prepare('SELECT id, username, password_hash, totp_secret FROM users WHERE username = :username');
		$stmt->bindValue(':username', $username, SQLITE3_TEXT);
		$result = $stmt->execute();
		$user = $result->fetchArray(SQLITE3_ASSOC);

		if (!$user || !password_verify($password, $user['password_hash'])) {
			$this->logger->log('Authentication failed: invalid username or password', ['username' => $username], 'warning');
			return null;
		}

		if ($user['totp_secret'] !== null && $user['totp_secret'] !== '') {
			if (!$this->totp->verify($user['totp_secret'], $otp)) {
				$this->logger->log('Authentication failed: invalid TOTP', ['username' => $username], 'warning');
				return null;
			}
		} elseif ($otp !== '') {
			$this->logger->log('Authentication failed: TOTP provided but not enrolled', ['username' => $username], 'warning');
			return null;
		}

		$this->logger->exit_('Authenticator::authenticate', ['username' => $username, 'user_id' => $user['id']]);
		return $user;
	}

	/**
	 * @param int $userId
	 * @return array|null
	 */
	public function getUserById(int $userId): ?array
	{
		$this->logger->entry('Authenticator::getUserById', ['user_id' => $userId]);

		$stmt = $this->database->prepare('SELECT id, username, password_hash, totp_secret, enrolled_at FROM users WHERE id = :id');
		$stmt->bindValue(':id', $userId, SQLITE3_INTEGER);
		$result = $stmt->execute();
		$user = $result->fetchArray(SQLITE3_ASSOC);

		$this->logger->exit_('Authenticator::getUserById', ['found' => $user !== false]);
		return $user ?: null;
	}

	/**
	 * @param int $userId
	 * @param string $secret
	 * @return bool
	 */
	public function enrollTotp(int $userId, string $secret): bool
	{
		$this->logger->entry('Authenticator::enrollTotp', ['user_id' => $userId]);

		$stmt = $this->database->prepare('UPDATE users SET totp_secret = :secret, enrolled_at = :enrolled_at WHERE id = :id');
		$stmt->bindValue(':secret', $secret, SQLITE3_TEXT);
		$stmt->bindValue(':enrolled_at', time(), SQLITE3_INTEGER);
		$stmt->bindValue(':id', $userId, SQLITE3_INTEGER);
		$result = $stmt->execute() !== false;

		$this->logger->exit_('Authenticator::enrollTotp', ['result' => $result]);
		return $result;
	}
}
