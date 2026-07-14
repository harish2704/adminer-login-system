<?php

/**
 * Encrypt and decrypt database passwords with a master key.
 */
class Crypto
{
	/** @var string */
	private $key;

	/** @var Logger */
	private $logger;

	/**
	 * @param string $masterKey
	 * @param Logger $logger
	 */
	public function __construct(string $masterKey, Logger $logger)
	{
		$this->logger = $logger;
		$this->logger->entry('Crypto::__construct');
		$this->key = hash('sha256', $masterKey, true);
		$this->logger->exit_('Crypto::__construct');
	}

	/**
	 * @param string $plaintext
	 * @return string
	 * @throws RuntimeException
	 */
	public function encrypt(string $plaintext): string
	{
		$this->logger->entry('Crypto::encrypt');
		$iv = random_bytes(16);
		$ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);

		if ($ciphertext === false) {
			throw new RuntimeException('Encryption failed');
		}

		$result = base64_encode($iv . $ciphertext);
		$this->logger->exit_('Crypto::encrypt');
		return $result;
	}

	/**
	 * @param string $ciphertext
	 * @return string
	 * @throws RuntimeException
	 */
	public function decrypt(string $ciphertext): string
	{
		$this->logger->entry('Crypto::decrypt');
		$raw = base64_decode($ciphertext, true);

		if ($raw === false || strlen($raw) < 16) {
			throw new RuntimeException('Invalid ciphertext');
		}

		$iv = substr($raw, 0, 16);
		$encrypted = substr($raw, 16);
		$plaintext = openssl_decrypt($encrypted, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);

		if ($plaintext === false) {
			throw new RuntimeException('Decryption failed');
		}

		$this->logger->exit_('Crypto::decrypt');
		return $plaintext;
	}
}
