<?php
namespace Adminer;

require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/Database.php';
require_once __DIR__ . '/src/Crypto.php';
require_once __DIR__ . '/src/Totp.php';
require_once __DIR__ . '/src/Authenticator.php';
require_once __DIR__ . '/src/ServerManager.php';
require_once __DIR__ . '/src/SshTunnel.php';

/**
 * Vault-based login system plugin for Adminer.
 */
class AdminerLoginSystem extends Plugin
{
	/** @var Database */
	private $database;

	/** @var Logger */
	private $logger;

	/** @var Crypto */
	private $crypto;

	/** @var Totp */
	private $totp;

	/** @var Authenticator */
	private $authenticator;

	/** @var ServerManager */
	private $serverManager;

	/** @var SshTunnel */
	private $sshTunnel;

	/**
	 * @param string $dbFile
	 * @param string $masterKey
	 * @param bool $loggingEnabled
	 * @param string $logFile
	 */
	function __construct(
		string $dbFile = __DIR__ . '/login-vault.db',
		string $masterKey = '',
		bool $loggingEnabled = false,
		string $logFile = __DIR__ . '/login-system.log'
	) {
		if ($masterKey === '') {
			throw new \RuntimeException('AdminerLoginSystem: master key is required');
		}

		$this->logger = new \Logger($loggingEnabled, $logFile);
		$this->logger->entry('AdminerLoginSystem::__construct', ['db_file' => $dbFile]);

		$this->database = new \Database($dbFile, $this->logger);
		$this->crypto = new \Crypto($masterKey, $this->logger);
		$this->totp = new \Totp($this->logger);
		$this->authenticator = new \Authenticator($this->database, $this->totp, $this->logger);
		$this->serverManager = new \ServerManager($this->database, $this->crypto, $this->logger);
		$this->sshTunnel = new \SshTunnel($this->serverManager, $this->logger);

		$this->handleLogout();
		$this->logger->exit_('AdminerLoginSystem::__construct');
	}

	/**
	 * @param string $name
	 * @param string $heading
	 * @param string $value
	 * @return string
	 */
	function loginFormField($name, $heading, $value)
	{
		$this->logger->entry('AdminerLoginSystem::loginFormField', ['name' => $name]);

		if ($name === 'password') {
			$value .= "<tr><th>Vault password</th><td>" . $heading . "</td></tr>\n";
			$value .= "<tr><th>TOTP code</th><td><input name=\"auth[otp]\" value=\"\" autocomplete=\"off\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\"></td></tr>\n";
			$value .= "<input type=\"hidden\" name=\"auth[login_system]\" value=\"1\">\n";
		}

		$this->logger->exit_('AdminerLoginSystem::loginFormField');
		return $value;
	}

	/**
	 * @param string $login
	 * @param string $password
	 * @return string|true
	 */
	function login($login, $password)
	{
		$this->logger->entry('AdminerLoginSystem::login', ['login' => $login]);

		if (empty($_POST["auth"]["login_system"])) {
			$this->logger->exit_('AdminerLoginSystem::login', ['handled' => false]);
			return true;
		}

		$otp = $_POST["auth"]["otp"] ?? '';
		$user = $this->authenticator->authenticate($login, $password, $otp);

		if ($user === null) {
			$this->logger->log('Login rejected', ['login' => $login], 'warning');
			$this->logger->exit_('AdminerLoginSystem::login', ['result' => 'invalid credentials']);
			return 'Invalid vault username, password, or TOTP code.';
		}

		$_SESSION["adminer_login_system_user_id"] = (int) $user['id'];
		$_SESSION["adminer_login_system_username"] = $user['username'];

		if (empty($user['totp_secret'])) {
			redirect("?login-system=enroll-totp");
		}

		redirect("?login-system=select-server");
	}

	/**
	 * @return array
	 */
	function credentials()
	{
		$this->logger->entry('AdminerLoginSystem::credentials');

		if (!empty($_SESSION["adminer_login_system_server"])) {
			$server = $_SESSION["adminer_login_system_server"];
			$this->logger->exit_('AdminerLoginSystem::credentials', ['server_id' => $server['id']]);
			return [$server['host'], $server['db_username'], $server['db_password']];
		}

		$this->logger->exit_('AdminerLoginSystem::credentials', ['default' => true]);
		return [SERVER, $_GET["username"], get_password()];
	}

	/**
	 * @return void
	 */
	function headers()
	{
		$this->logger->entry('AdminerLoginSystem::headers');

		if (empty($_GET["login-system"])) {
			$this->logger->exit_('AdminerLoginSystem::headers', ['handled' => false]);
			return;
		}

		if (!verify_token()) {
			$this->logger->log('CSRF token verification failed', [], 'error');
			redirect('');
		}

		$action = $_GET["login-system"];
		page_header($action === 'select-server' ? 'Select database server' : 'Enroll TOTP');

		if ($action === 'enroll-totp') {
			$this->renderEnrollTotp();
		} elseif ($action === 'select-server') {
			$this->renderSelectServer();
		} else {
			echo '<p class="error">Unknown login system action.</p>';
		}

		page_footer();
		exit;
	}

	/**
	 * @return void
	 */
	private function renderEnrollTotp(): void
	{
		$this->logger->entry('AdminerLoginSystem::renderEnrollTotp');

		$userId = $this->requireUser();
		$user = $this->authenticator->getUserById($userId);

		if ($user && !empty($user['totp_secret']) && !empty($user['enrolled_at'])) {
			redirect("?login-system=select-server");
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['totp_secret']) && !empty($_POST['totp_code'])) {
			$secret = $_POST['totp_secret'];
			$code = $_POST['totp_code'];

			if ($this->totp->verify($secret, $code)) {
				$this->authenticator->enrollTotp($userId, $secret);
				$this->logger->log('TOTP enrolled', ['user_id' => $userId]);
				redirect("?login-system=select-server");
			} else {
				echo '<p class="error">Invalid verification code.</p>';
			}
		}

		$secret = $this->totp->generateSecret();
		$username = $_SESSION["adminer_login_system_username"] ?? 'user';
		$issuer = 'Adminer';
		$label = $issuer . ':' . $username;
		$otpauth = 'otpauth://totp/' . rawurlencode($label) . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer);

		echo '<h2>Enroll two-factor authentication</h2>';
		echo '<p>Scan the QR code with your authenticator app, then enter the current 6-digit code to verify.</p>';
		echo '<form action="" method="post">';
		echo input_token();
		echo '<input type="hidden" name="totp_secret" value="' . h($secret) . '">';
		echo '<div id="qrcode"></div>';
		echo '<p><label>Verification code: <input name="totp_code" inputmode="numeric" pattern="[0-9]*" maxlength="6" required></label></p>';
		echo '<p><input type="submit" value="Verify and enable"></p>';
		echo '</form>';
		echo '<p>Manual secret: <code>' . h($secret) . '</code></p>';
		echo '<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>';
		echo '<script>new QRCode(document.getElementById("qrcode"), { text: ' . json_encode($otpauth) . ', width: 200, height: 200 });</script>';

		$this->logger->exit_('AdminerLoginSystem::renderEnrollTotp');
	}

	/**
	 * @return void
	 */
	private function renderSelectServer(): void
	{
		$this->logger->entry('AdminerLoginSystem::renderSelectServer');

		$userId = $this->requireUser();

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['server_id'])) {
			$serverId = (int) $_POST['server_id'];
			$server = $this->serverManager->getServerForUser($serverId, $userId);

			if ($server === null) {
				echo '<p class="error">Server not found or access denied.</p>';
			} else {
				$this->connectToServer($server);
			}
		}

		$servers = $this->serverManager->listServersForUser($userId);

		echo '<h2>Select database server</h2>';

		if (empty($servers)) {
			echo '<p>No servers are available for your account.</p>';
		} else {
			echo '<form action="" method="post">';
			echo input_token();
			echo '<table cellspacing="0">';
			echo '<thead><tr><th></th><th>Name</th><th>Type</th><th>Host</th><th>Port</th></tr></thead><tbody>';

			foreach ($servers as $server) {
				echo '<tr>';
				echo '<td><input type="radio" name="server_id" value="' . h($server['id']) . '" required></td>';
				echo '<td>' . h($server['name']) . '</td>';
				echo '<td>' . h($server['db_type']) . '</td>';
				echo '<td>' . h($server['hostname']) . '</td>';
				echo '<td>' . h($server['port']) . '</td>';
				echo '</tr>';
			}

			echo '</tbody></table>';
			echo '<p><input type="submit" value="Connect"></p>';
			echo '</form>';
		}

		$this->logger->exit_('AdminerLoginSystem::renderSelectServer');
	}

	/**
	 * @param array $server
	 * @return void
	 */
	private function connectToServer(array $server): void
	{
		$this->logger->entry('AdminerLoginSystem::connectToServer', ['server_id' => $server['id']]);

		$credentials = $this->serverManager->decryptCredentials($server);
		$vendor = $server['db_type'];
		$hostname = $server['hostname'];
		$port = (int) $server['port'];

		if (!(int) $server['is_public']) {
			$server = $this->sshTunnel->ensureTunnel($server);
			$hostname = '127.0.0.1';
			$port = (int) $server['mapped_local_port'];
		}

		$serverHost = $hostname . ':' . $port;
		set_password($vendor, $serverHost, $credentials['db_username'], $credentials['db_password']);

		$_SESSION["adminer_login_system_server"] = [
			'id' => $server['id'],
			'host' => $serverHost,
			'db_username' => $credentials['db_username'],
			'db_password' => $credentials['db_password'],
		];

		$this->logger->log('Server selected', ['server_id' => $server['id'], 'host' => $serverHost]);
		redirect(auth_url($vendor, $serverHost, $credentials['db_username'], ''));
	}

	/**
	 * @return int
	 */
	private function requireUser(): int
	{
		$userId = $_SESSION["adminer_login_system_user_id"] ?? 0;
		if (!$userId) {
			redirect('');
		}
		return (int) $userId;
	}

	/**
	 * @return void
	 */
	private function handleLogout(): void
	{
		$this->logger->entry('AdminerLoginSystem::handleLogout');

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['logout']) && verify_token()) {
			$userId = $_SESSION["adminer_login_system_user_id"] ?? null;

			if ($userId !== null) {
				foreach ($this->serverManager->listActiveTunnels() as $tunnel) {
					if (!empty($tunnel['ssh_pid'])) {
						$this->sshTunnel->killProcess((int) $tunnel['ssh_pid']);
						$this->serverManager->updateTunnel((int) $tunnel['id'], null, null);
					}
				}
				unset($_SESSION["adminer_login_system_user_id"]);
				unset($_SESSION["adminer_login_system_username"]);
				unset($_SESSION["adminer_login_system_server"]);
				$this->logger->log('User logged out', ['user_id' => $userId]);
			}
		}

		$this->logger->exit_('AdminerLoginSystem::handleLogout');
	}
}
