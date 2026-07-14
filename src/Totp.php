<?php

/**
 * Time-based One-Time Password generation and verification.
 */
class Totp
{
	/** @var int */
	private $digits = 6;

	/** @var int */
	private $period = 30;

	/** @var Logger */
	private $logger;

	/**
	 * @param Logger $logger
	 */
	public function __construct(Logger $logger)
	{
		$this->logger = $logger;
		$this->logger->entry('Totp::__construct');
		$this->logger->exit_('Totp::__construct');
	}

	/**
	 * @return string
	 * @throws Exception
	 */
	public function generateSecret(): string
	{
		$this->logger->entry('Totp::generateSecret');
		$secret = base32_encode(random_bytes(20));
		$this->logger->exit_('Totp::generateSecret');
		return $secret;
	}

	/**
	 * @param string $secret
	 * @param string $code
	 * @param int $window
	 * @return bool
	 */
	public function verify(string $secret, string $code, int $window = 1): bool
	{
		$this->logger->entry('Totp::verify', ['window' => $window]);
		$timeSlice = floor(time() / $this->period);

		for ($i = -$window; $i <= $window; $i++) {
			if ($this->code($secret, $timeSlice + $i) === $code) {
				$this->logger->exit_('Totp::verify', ['result' => true]);
				return true;
			}
		}

		$this->logger->exit_('Totp::verify', ['result' => false]);
		return false;
	}

	/**
	 * @param string $secret
	 * @param int|null $timeSlice
	 * @return string
	 */
	public function code(string $secret, ?int $timeSlice = null): string
	{
		$this->logger->entry('Totp::code');

		if ($timeSlice === null) {
			$timeSlice = floor(time() / $this->period);
		}

		$secret = base32_decode($secret);
		$time = pack('N*', 0) . pack('N*', $timeSlice);
		$hmac = hash_hmac('sha1', $time, $secret, true);
		$offset = ord(substr($hmac, -1)) & 0x0F;
		$binary = (ord($hmac[$offset]) & 0x7F) << 24 |
			(ord($hmac[$offset + 1]) & 0xFF) << 16 |
			(ord($hmac[$offset + 2]) & 0xFF) << 8 |
			(ord($hmac[$offset + 3]) & 0xFF);
		$otp = $binary % (10 ** $this->digits);
		$result = str_pad((string) $otp, $this->digits, '0', STR_PAD_LEFT);

		$this->logger->exit_('Totp::code');
		return $result;
	}

	/**
	 * @return int
	 */
	public function secondsRemaining(): int
	{
		return $this->period - (time() % $this->period);
	}
}

if (!function_exists('base32_encode')) {
	/**
	 * @param string $data
	 * @return string
	 */
	function base32_encode(string $data): string
	{
		$map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$binary = '';
		foreach (str_split($data) as $char) {
			$binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
		}

		$output = '';
		for ($i = 0; $i < strlen($binary); $i += 5) {
			$chunk = str_pad(substr($binary, $i, 5), 5, '0', STR_PAD_RIGHT);
			$output .= $map[bindec($chunk)];
		}

		return $output;
	}
}

if (!function_exists('base32_decode')) {
	/**
	 * @param string $data
	 * @return string
	 */
	function base32_decode(string $data): string
	{
		$map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$binary = '';
		foreach (str_split(strtoupper($data)) as $char) {
			$pos = strpos($map, $char);
			if ($pos === false) {
				continue;
			}
			$binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
		}

		$output = '';
		for ($i = 0; $i + 8 <= strlen($binary); $i += 8) {
			$output .= chr(bindec(substr($binary, $i, 8)));
		}

		return $output;
	}
}
