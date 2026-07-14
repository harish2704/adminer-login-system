<?php

/**
 * JSON logging wrapper around error_log().
 */
class Logger
{
	/** @var bool */
	private $enabled;

	/** @var string */
	private $logFile;

	/**
	 * @param bool $enabled
	 * @param string $logFile
	 */
	public function __construct(bool $enabled, string $logFile)
	{
		$this->enabled = $enabled;
		$this->logFile = $logFile;
		$this->log('Logger initialized', [], 'info');
	}

	/**
	 * @param string $message
	 * @param array $context
	 * @param string $level
	 * @param bool $includeStackTrace
	 * @return void
	 */
	public function log(string $message, array $context = [], string $level = 'info', bool $includeStackTrace = false): void
	{
		if (!$this->enabled) {
			return;
		}

		$redacted = $this->redact($context);
		$entry = [
			'timestamp' => date('c'),
			'level' => $level,
			'message' => $message,
			'context' => $redacted,
		];

		if ($level === 'error' || $includeStackTrace) {
			$entry['stack_trace'] = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
		}

		$line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		error_log($line . "\n", 3, $this->logFile);
	}

	/**
	 * @param string $message
	 * @param array $context
	 * @return void
	 */
	public function entry(string $message, array $context = []): void
	{
		$this->log($message, $context, 'info');
	}

	/**
	 * @param string $message
	 * @param array $context
	 * @return void
	 */
	public function exit_(string $message, array $context = []): void
	{
		$this->log($message, $context, 'info');
	}

	/**
	 * @param array $context
	 * @return array
	 */
	private function redact(array $context): array
	{
		$redactedKeys = [
			'password',
			'db_password',
			'totp_secret',
			'ssh_password',
			'masterKey',
			'private_key',
			'private_key_contents',
		];

		foreach ($context as $key => $value) {
			if (is_array($value)) {
				$context[$key] = $this->redact($value);
			} elseif (is_string($key) && in_array(strtolower($key), array_map('strtolower', $redactedKeys), true)) {
				$context[$key] = '***REDACTED***';
			} elseif (is_string($value) && preg_match('/BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY/', $value)) {
				$context[$key] = '***REDACTED PRIVATE KEY***';
			}
		}

		return $context;
	}
}
