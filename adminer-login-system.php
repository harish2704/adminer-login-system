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

		$this->handleVaultLogin();
		$this->handleLogout();

		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			$userId = isset($_SESSION["adminer_login_system_user_id"]) ? $_SESSION["adminer_login_system_user_id"] : 0;
			$hasServer = !empty($_SESSION["adminer_login_system_server"]);
			if ($userId && !$hasServer && !isset($_GET["login-system"])) {
				$user = $this->authenticator->getUserById((int) $userId);
				$action = ($user && empty($user['totp_secret'])) ? 'enroll-totp' : 'select-server';
				$this->logger->log('Redirecting to login-system page', ['action' => $action, 'userId' => $userId]);
				$uri = $_SERVER["REQUEST_URI"];
				$sep = (strpos($uri, '?') === false) ? '?' : '&';
				redirect($uri . $sep . 'login-system=' . urlencode($action));
			}
		}

		$this->logger->exit_('AdminerLoginSystem::__construct');
	}

	/**
	 * @return void
	 */
	private function handleVaultLogin(): void
	{
		if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST["auth"]["login_system"])) {
			return;
		}

		$this->logger->entry('AdminerLoginSystem::handleVaultLogin');

		$username = isset($_POST["auth"]["username"]) ? (string) $_POST["auth"]["username"] : '';
		$password = isset($_POST["auth"]["password"]) ? (string) $_POST["auth"]["password"] : '';
		$otp = isset($_POST["auth"]["otp"]) ? (string) $_POST["auth"]["otp"] : '';

		$user = $this->authenticator->authenticate($username, $password, $otp);

		if ($user === null) {
			$this->logger->log('Vault login rejected', ['username' => $username], 'warning');
			$_SESSION["adminer_login_system_error"] = 'Invalid vault username, password, or TOTP code.';
			redirect('?username=' . urlencode($username));
		}

		$_SESSION["adminer_login_system_user_id"] = (int) $user['id'];
		$_SESSION["adminer_login_system_username"] = $user['username'];
		$_SESSION["token"] = rand(1, 1e6);
		$this->logger->log('Vault login accepted', ['user_id' => $user['id'], 'username' => $username]);

		// Satisfy Adminer's requirement for a database connection by routing through
		// a lightweight SQLite state database in the current working directory.
		$stateDb = $this->ensureStateDb();
		$_POST["auth"]["driver"] = 'sqlite';
		$_POST["auth"]["server"] = $stateDb;
		$_POST["auth"]["db"] = '';

		$this->logger->exit_('AdminerLoginSystem::handleVaultLogin');
	}

	/**
	 * @return string
	 */
	private function ensureStateDb(): string
	{
		$filename = 'adminer-login-system-state.db';
		$path = getcwd() . '/' . $filename;

		if (!file_exists($path)) {
			@$tmp = new \SQLite3($path);
			if ($tmp) {
				@$tmp->exec('CREATE TABLE IF NOT EXISTS _adminer_login_system_state (x INTEGER)');
				$tmp->close();
			}
		}

		return $filename;
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

		$result = $heading . $value;

		if ($name === 'driver') {
			if (!empty($_SESSION["adminer_login_system_error"])) {
				$result = '<tr><td colspan=2><p class="error">' . h($_SESSION["adminer_login_system_error"]) . '</p></td></tr>' . "\n" . $result;
				unset($_SESSION["adminer_login_system_error"]);
			}
		} elseif ($name === 'password') {
			$result .= "<tr><th>TOTP code<td><input name=\"auth[otp]\" value=\"\" autocomplete=\"off\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\"></tr>\n";
			$result .= "<input type=\"hidden\" name=\"auth[login_system]\" value=\"1\">\n";
		}

		$this->logger->exit_('AdminerLoginSystem::loginFormField');
		return $result;
	}

	/**
	 * @param string $login
	 * @param string $password
	 * @return mixed
	 */
	function login($login, $password)
	{
		$this->logger->entry('AdminerLoginSystem::login', ['login' => $login]);

		if (!empty($_SESSION["adminer_login_system_user_id"])) {
			$this->logger->exit_('AdminerLoginSystem::login', ['result' => 'vault session active']);
			return true;
		}

		$this->logger->exit_('AdminerLoginSystem::login', ['handled' => false]);
		return null;
	}

	/**
	 * @return array|null
	 */
	function credentials()
	{
		$this->logger->entry('AdminerLoginSystem::credentials');

		if (!empty($_SESSION["adminer_login_system_server"])) {
			$server = $_SESSION["adminer_login_system_server"];
			$this->logger->exit_('AdminerLoginSystem::credentials', ['server_id' => $server['id']]);
			return [$server['host'], $server['db_username'], $server['db_password']];
		}

		if (!empty($_SESSION["adminer_login_system_user_id"])) {
			$stateDb = $this->ensureStateDb();
			$this->logger->exit_('AdminerLoginSystem::credentials', ['state_db' => $stateDb]);
			return [$stateDb, '', ''];
		}

		$this->logger->exit_('AdminerLoginSystem::credentials', ['default' => true]);
		return null;
	}

	/**
	 * @return void
	 */
	function headers()
	{
		$userId = isset($_SESSION["adminer_login_system_user_id"]) ? $_SESSION["adminer_login_system_user_id"] : 0;
		$hasServer = !empty($_SESSION["adminer_login_system_server"]);
		if (!$userId || $hasServer) {
			return;
		}

		$action = isset($_GET["login-system"]) ? $_GET["login-system"] : '';
		if (!$action) {
			return;
		}

		$this->logger->entry('AdminerLoginSystem::headers (rendering)');

		// Output minimal HTML page with custom content
		// HTTP headers already sent by page_headers(), just output HTML
		?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo h($action === 'enroll-totp' ? 'Enroll TOTP' : 'Select server'); ?> - Adminer</title>
<link rel="stylesheet" href="../adminer/static/default.css">
<link rel='stylesheet' media='(prefers-color-scheme: dark)' href='../adminer/static/dark.css'>
<body class="ltr">
<div id="content">
<?php
		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !verify_token()) {
			echo '<p class="error">Invalid CSRF token.</p>';
		} elseif ($action === 'enroll-totp') {
			$this->renderEnrollTotp();
		} elseif ($action === 'select-server') {
			$this->renderSelectServer();
		} else {
			echo '<p class="error">Unknown login system action.</p>';
		}
?>
</div>
</body>
</html>
<?php
		$this->logger->exit_('AdminerLoginSystem::headers (rendering)');
		exit;
	}

	/**
	 * @return bool
	 */
	function homepage(): bool
	{
		$this->logger->entry('AdminerLoginSystem::homepage');
		if (!empty($_SESSION["adminer_login_system_server"])) {
			$this->logger->exit_('AdminerLoginSystem::homepage', ['handled' => false, 'reason' => 'real_server_selected']);
			return true;
		}
		if (!empty($_SESSION["adminer_login_system_user_id"])) {
			$this->logger->exit_('AdminerLoginSystem::homepage', ['handled' => true, 'reason' => 'vault_no_server']);
			return false;
		}
		$this->logger->exit_('AdminerLoginSystem::homepage', ['handled' => false, 'reason' => 'no_vault']);
		return true;
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
			redirect(ME . 'login-system=select-server');
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['totp_secret']) && !empty($_POST['totp_code'])) {
			$secret = $_POST['totp_secret'];
			$code = $_POST['totp_code'];

			if ($this->totp->verify($secret, $code)) {
				$this->authenticator->enrollTotp($userId, $secret);
				$this->logger->log('TOTP enrolled', ['user_id' => $userId]);
				redirect(ME . 'login-system=select-server');
			} else {
				echo '<p class="error">Invalid verification code.</p>';
			}
		}

		$secret = $this->totp->generateSecret();
		$username = isset($_SESSION["adminer_login_system_username"]) ? $_SESSION["adminer_login_system_username"] : 'user';
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
		session_start();
		set_password($vendor, $serverHost, $credentials['db_username'], $credentials['db_password']);
		$_SESSION["adminer_login_system_server"] = [
			'id' => $server['id'],
			'host' => $serverHost,
			'db_username' => $credentials['db_username'],
			'db_password' => $credentials['db_password'],
		];
		session_write_close();

		$this->logger->log('Server selected', ['server_id' => $server['id'], 'host' => $serverHost]);
		redirect(auth_url($vendor, $serverHost, $credentials['db_username'], ''));
	}

	/**
	 * @return int
	 */
	private function requireUser(): int
	{
		$userId = isset($_SESSION["adminer_login_system_user_id"]) ? $_SESSION["adminer_login_system_user_id"] : 0;
		if (!$userId) {
			redirect(ME);
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
			$userId = isset($_SESSION["adminer_login_system_user_id"]) ? $_SESSION["adminer_login_system_user_id"] : null;
			$serverId = isset($_SESSION["adminer_login_system_server"]['id']) ? $_SESSION["adminer_login_system_server"]['id'] : null;

			if ($userId !== null) {
				if ($serverId !== null) {
					$server = $this->serverManager->getServerForUser((int) $serverId, (int) $userId);
					if ($server !== null && !empty($server['ssh_pid'])) {
						$this->sshTunnel->killProcess((int) $server['ssh_pid']);
						$this->serverManager->updateTunnel((int) $server['id'], null, null);
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
