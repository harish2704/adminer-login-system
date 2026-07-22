<?php
namespace Adminer;

require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/Database.php';
require_once __DIR__ . '/src/Crypto.php';
require_once __DIR__ . '/src/Totp.php';
require_once __DIR__ . '/src/Authenticator.php';
require_once __DIR__ . '/src/ServerManager.php';
require_once __DIR__ . '/src/SshTunnel.php';
require_once __DIR__ . '/src/AdminManager.php';

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

	/** @var AdminManager */
	private $adminManager;

	/** @var array */
	private $adminErrors = [];

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

		$currentUserId = isset($_SESSION["adminer_login_system_user_id"]) ? (int) $_SESSION["adminer_login_system_user_id"] : null;
		$this->adminManager = new \AdminManager($this->database, $this->crypto, $this->logger, $this->authenticator, $this->serverManager, $this->sshTunnel, $currentUserId);

		$this->handleVaultLogin();
		$this->handleLogout();

		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			$userId = isset($_SESSION["adminer_login_system_user_id"]) ? $_SESSION["adminer_login_system_user_id"] : 0;
			$hasServer = !empty($_SESSION["adminer_login_system_server"]);
			if ($userId && !$hasServer && !isset($_GET["login-system"])) {
				$user = $this->authenticator->getUserById((int) $userId);
				if ($user && empty($user['totp_secret'])) {
					$action = 'enroll-totp';
				} elseif (empty($_SESSION["adminer_login_system_totp_verified"])) {
					$action = 'verify-totp';
				} else {
					$action = 'select-server';
				}
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

		$user = $this->authenticator->authenticateUsernamePassword($username, $password);

		if ($user === null) {
			$this->logger->log('Vault login rejected', ['username' => $username], 'warning');
			$_SESSION["adminer_login_system_error"] = 'Invalid vault username or password.';
			redirect('?username=' . urlencode($username));
		}

		$_SESSION["adminer_login_system_user_id"] = (int) $user['id'];
		$_SESSION["adminer_login_system_username"] = $user['username'];
		$_SESSION["adminer_login_system_role"] = $user['role'] ?? 'user';
		$_SESSION["token"] = rand(1, 1e6);
		$this->logger->log('Vault login accepted', ['user_id' => $user['id'], 'username' => $username]);

		// Redirect to TOTP or enrollment page (use ? not ME since ME is not defined in constructor)
		if (!empty($user['totp_secret'])) {
			$this->logger->exit_('AdminerLoginSystem::handleVaultLogin', ['redirect' => 'verify-totp']);
			redirect('?login-system=verify-totp');
		} else {
			$this->logger->exit_('AdminerLoginSystem::handleVaultLogin', ['redirect' => 'enroll-totp']);
			redirect('?login-system=enroll-totp');
		}
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
		// Admin pages for super admins (renders standalone HTML with Adminer CSS)
		if ($this->isSuperAdmin() && isset($_GET["login-system-admin"])) {
			$this->logger->entry('AdminerLoginSystem::headers (admin page)');
			$page = isset($_GET["page"]) ? $_GET["page"] : 'dashboard';

			if ($_SERVER['REQUEST_METHOD'] === 'POST' && !verify_token()) {
				$pageTitle = 'Error';
				?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo h($pageTitle); ?> - Adminer</title>
<link rel="stylesheet" href="../adminer/static/default.css">
<link rel='stylesheet' media='(prefers-color-scheme: dark)' href='../adminer/static/dark.css'>
<body class="ltr">
<div id="content">
<p class="error">Invalid CSRF token.</p>
</div>
</body>
</html>
<?php
				$this->logger->exit_('AdminerLoginSystem::headers (admin page)');
				exit;
			}

			$pageTitle = 'Admin: ' . ucfirst(str_replace('_', ' ', $page));
			?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo h($pageTitle); ?> - Adminer</title>
<link rel="stylesheet" href="../adminer/static/default.css">
<link rel='stylesheet' media='(prefers-color-scheme: dark)' href='../adminer/static/dark.css'>
<body class="ltr">
<div id="content">
<p class="links"><a href="<?php echo h(substr(ME, 0, -1)); ?>">« Back to Adminer</a></p>
<h2><?php echo h($pageTitle); ?></h2>
<?php
			if ($_SERVER['REQUEST_METHOD'] === 'POST') {
				$this->handleAdminPost($page);
			}

			$this->renderAdminPage($page);
?>
</div>
</body>
</html>
<?php
			$this->logger->exit_('AdminerLoginSystem::headers (admin page)');
			exit;
		}

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
<title><?php echo h($action === 'verify-totp' ? 'Verify TOTP' : ($action === 'enroll-totp' ? 'Enroll TOTP' : 'Select server')); ?> - Adminer</title>
<link rel="stylesheet" href="../adminer/static/default.css">
<link rel='stylesheet' media='(prefers-color-scheme: dark)' href='../adminer/static/dark.css'>
<body class="ltr">
<div id="content">
<?php if ($this->isSuperAdmin()) { ?>
<p class="links"><a href="?login-system-admin=">Admin</a></p>
<?php } ?>
<?php
		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !verify_token()) {
			echo '<p class="error">Invalid CSRF token.</p>';
		} elseif ($action === 'verify-totp') {
			$this->renderVerifyTotp();
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
	private function renderVerifyTotp(): void
	{
		$this->logger->entry('AdminerLoginSystem::renderVerifyTotp');

		$userId = $this->requireUser();
		$user = $this->authenticator->getUserById($userId);

		if ($user === null || empty($user['totp_secret'])) {
			redirect(ME . 'login-system=enroll-totp');
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['totp_code'])) {
			$code = $_POST['totp_code'];
			if ($this->totp->verify($user['totp_secret'], $code)) {
				$_SESSION["adminer_login_system_totp_verified"] = true;
				$this->logger->log('TOTP verified', ['user_id' => $userId]);
				redirect('?login-system=select-server');
			} else {
				echo '<p class="error">Invalid TOTP code.</p>';
			}
		}

		echo '<h2>Two-factor authentication</h2>';
		echo '<p>Enter the 6-digit code from your authenticator app.</p>';
		echo '<form action="" method="post">';
		echo input_token();
		echo '<p><label>Verification code: <input name="totp_code" inputmode="numeric" pattern="[0-9]*" maxlength="6" required autofocus></label></p>';
		echo '<p><input type="submit" value="Verify"></p>';
		echo '</form>';

		$this->logger->exit_('AdminerLoginSystem::renderVerifyTotp');
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
			redirect('?login-system=select-server');
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['totp_secret']) && !empty($_POST['totp_code'])) {
			$secret = $_POST['totp_secret'];
			$code = $_POST['totp_code'];

			if ($this->totp->verify($secret, $code)) {
				$this->authenticator->enrollTotp($userId, $secret);
				$_SESSION["adminer_login_system_totp_verified"] = true;
				$this->logger->log('TOTP enrolled', ['user_id' => $userId]);
				redirect('?login-system=select-server');
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
			$isAdmin = $this->isSuperAdmin();
			echo '<form action="" method="post">';
			echo input_token();
			echo '<table cellspacing="0">';
			echo '<thead><tr><th></th><th>Name</th>' . ($isAdmin ? '<th>Type</th><th>Host</th><th>Port</th>' : '') . '</tr></thead><tbody>';

			foreach ($servers as $server) {
				echo '<tr>';
				echo '<td><input type="radio" name="server_id" value="' . h($server['id']) . '" required></td>';
				echo '<td>' . h($server['name']) . '</td>';
				if ($isAdmin) {
					echo '<td>' . h($server['db_type']) . '</td>';
					echo '<td>' . h($server['hostname']) . '</td>';
					echo '<td>' . h($server['port']) . '</td>';
				}
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
	 * @return bool
	 */
	private function isSuperAdmin(): bool
	{
		return !empty($_SESSION["adminer_login_system_role"]) && $_SESSION["adminer_login_system_role"] === 'admin';
	}

	/**
	 * @param array $actions
	 * @param string $missing
	 * @return array
	 */
	function menuActions($actions, $missing)
	{
		if ($this->isSuperAdmin()) {
			$link = preg_replace('~\b(db|ns|select|edit|create|table|sql|dump|schema|privileges|processlist|variables|status|user|call|foreign|view|event|procedure|sequence|type|check|trigger|indexes|database|scheme|script)=[^&]*&~', '', ME);
			$link .= 'login-system-admin=';
			$actions[] = '<a href="' . h($link) . '"' . bold(isset($_GET["login-system-admin"])) . '>Admin</a>';
		}
		return $actions;
	}

	// ---------------------------------------------------------------
	// Admin UI: dispatch
	// ---------------------------------------------------------------

	/**
	 * @param string $page
	 * @return void
	 */
	private function handleAdminPost(string $page): void
	{
		switch ($page) {
			case 'users':
			case 'user_form':
				$this->handleAdminUserPost();
				break;
			case 'servers':
			case 'server_form':
				$this->handleAdminServerPost();
				break;
			case 'access':
				$this->handleAdminAccessPost();
				break;
		}
	}

	/**
	 * @param string $page
	 * @return void
	 */
	private function renderAdminPage(string $page): void
	{
		switch ($page) {
			case 'users':
				$this->renderAdminUsersPage();
				break;
			case 'user_form':
				$this->renderAdminUserForm(isset($_GET["id"]) ? (int) $_GET["id"] : null, []);
				break;
			case 'servers':
				$this->renderAdminServersPage();
				break;
			case 'server_form':
				$this->renderAdminServerForm(isset($_GET["id"]) ? (int) $_GET["id"] : null, []);
				break;
			case 'access':
				$this->renderAdminAccessPage();
				break;
			default:
				$this->renderAdminDashboardPage();
		}
	}

	// ---------------------------------------------------------------
	// Admin UI: POST handlers
	// ---------------------------------------------------------------

	/**
	 * @return void
	 */
	private function handleAdminUserPost(): void
	{
		$action = isset($_POST['admin_action']) ? $_POST['admin_action'] : '';

		if ($action === 'create') {
			$data = [
				'username' => isset($_POST['username']) ? $_POST['username'] : '',
				'password' => isset($_POST['password']) ? $_POST['password'] : '',
				'role' => isset($_POST['role']) ? $_POST['role'] : 'user',
			];
			$errors = $this->adminManager->validateUser($data);
			if (empty($errors)) {
				$this->adminManager->createUser($data['username'], $data['password'], $data['role']);
				redirect(ME . 'login-system-admin&page=users', 'User created.');
			}
			$this->adminErrors = $errors;
			return;
		}

		if ($action === 'update') {
			$id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
			if (!$id) {
				redirect(ME . 'login-system-admin&page=users', 'Invalid user ID.');
			}
			$data = [
				'username' => isset($_POST['username']) ? $_POST['username'] : '',
				'password' => isset($_POST['password']) ? $_POST['password'] : '',
				'role' => isset($_POST['role']) ? $_POST['role'] : 'user',
			];
			$errors = $this->adminManager->validateUser($data, $id);
			if (empty($errors)) {
				$this->adminManager->updateUser($id, $data);
				redirect(ME . 'login-system-admin&page=users', 'User updated.');
			}
			$this->adminErrors = $errors;
			return;
		}

		if ($action === 'delete') {
			$id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
			if (!$id) {
				redirect(ME . 'login-system-admin&page=users', 'Invalid user ID.');
			}
			$deleted = $this->adminManager->deleteUser($id);
			if ($deleted) {
				redirect(ME . 'login-system-admin&page=users', 'User deleted.');
			}
			redirect(ME . 'login-system-admin&page=users', 'Cannot delete the last admin user.');
		}
	}

	/**
	 * @return void
	 */
	private function handleAdminServerPost(): void
	{
		$action = isset($_POST['admin_action']) ? $_POST['admin_action'] : '';

		if ($action === 'create') {
			$data = [
				'name' => isset($_POST['name']) ? $_POST['name'] : '',
				'hostname' => isset($_POST['hostname']) ? $_POST['hostname'] : '',
				'port' => isset($_POST['port']) ? $_POST['port'] : '',
				'db_type' => isset($_POST['db_type']) ? $_POST['db_type'] : '',
				'db_username' => isset($_POST['db_username']) ? $_POST['db_username'] : '',
				'db_password' => isset($_POST['db_password']) ? $_POST['db_password'] : '',
				'is_public' => !empty($_POST['is_public']),
				'ssh_host' => isset($_POST['ssh_host']) ? $_POST['ssh_host'] : '',
				'ssh_port' => isset($_POST['ssh_port']) ? $_POST['ssh_port'] : '',
				'ssh_user' => isset($_POST['ssh_user']) ? $_POST['ssh_user'] : '',
				'ssh_password' => isset($_POST['ssh_password']) ? $_POST['ssh_password'] : '',
				'ssh_private_key_path' => isset($_POST['ssh_private_key_path']) ? $_POST['ssh_private_key_path'] : '',
			];
			$errors = $this->adminManager->validateServer($data);
			if (empty($errors)) {
				$this->adminManager->createServer($data);
				redirect(ME . 'login-system-admin&page=servers', 'Server created.');
			}
			$this->adminErrors = $errors;
			return;
		}

		if ($action === 'update') {
			$id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
			if (!$id) {
				redirect(ME . 'login-system-admin&page=servers', 'Invalid server ID.');
			}
			$data = [
				'name' => isset($_POST['name']) ? $_POST['name'] : '',
				'hostname' => isset($_POST['hostname']) ? $_POST['hostname'] : '',
				'port' => isset($_POST['port']) ? $_POST['port'] : '',
				'db_type' => isset($_POST['db_type']) ? $_POST['db_type'] : '',
				'db_username' => isset($_POST['db_username']) ? $_POST['db_username'] : '',
				'db_password' => isset($_POST['db_password']) ? $_POST['db_password'] : '',
				'is_public' => !empty($_POST['is_public']),
				'ssh_host' => isset($_POST['ssh_host']) ? $_POST['ssh_host'] : '',
				'ssh_port' => isset($_POST['ssh_port']) ? $_POST['ssh_port'] : '',
				'ssh_user' => isset($_POST['ssh_user']) ? $_POST['ssh_user'] : '',
				'ssh_password' => isset($_POST['ssh_password']) ? $_POST['ssh_password'] : '',
				'ssh_private_key_path' => isset($_POST['ssh_private_key_path']) ? $_POST['ssh_private_key_path'] : '',
			];
			$errors = $this->adminManager->validateServer($data);
			if (empty($errors)) {
				$this->adminManager->updateServer($id, $data);
				redirect(ME . 'login-system-admin&page=servers', 'Server updated.');
			}
			$this->adminErrors = $errors;
			return;
		}

		if ($action === 'delete') {
			$id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
			if (!$id) {
				redirect(ME . 'login-system-admin&page=servers', 'Invalid server ID.');
			}
			$this->adminManager->deleteServer($id);
			redirect(ME . 'login-system-admin&page=servers', 'Server deleted.');
		}
	}

	/**
	 * @return void
	 */
	private function handleAdminAccessPost(): void
	{
		$assignments = isset($_POST['access']) && is_array($_POST['access']) ? $_POST['access'] : [];

		// Build map: user_id => [server_ids]
		$userServers = [];
		foreach ($assignments as $key => $val) {
			$parts = explode('_', $key);
			if (count($parts) === 2) {
				$userId = (int) $parts[0];
				$serverId = (int) $parts[1];
				if (!isset($userServers[$userId])) {
					$userServers[$userId] = [];
				}
				$userServers[$userId][] = $serverId;
			}
		}

		// Get all users and servers to rebuild full matrix
		$users = $this->adminManager->listUsers();
		$servers = $this->adminManager->listServers();

		foreach ($users as $user) {
			$uid = (int) $user['id'];
			$selectedIds = isset($userServers[$uid]) ? $userServers[$uid] : [];
			$this->adminManager->setUserServers($uid, $selectedIds);
		}

		redirect(ME . 'login-system-admin&page=access', 'Access permissions updated.');
	}

	// ---------------------------------------------------------------
	// Admin UI: rendering
	// ---------------------------------------------------------------

	/**
	 * @param string $page
	 * @return never
	 */
	private function renderAdminDashboardPage(): void
	{
		$userCount = count($this->adminManager->listUsers());
		$serverCount = count($this->adminManager->listServers());
		$accessCount = count($this->database->query('SELECT COUNT(*) AS cnt FROM user_servers')->fetchArray(SQLITE3_ASSOC) ?: []);

		echo '<p>Welcome to the Adminer Login System administration panel.</p>';
		echo '<div id="admin-stats" style="display:flex;gap:1em;margin:1em 0;">';
		echo '<div style="flex:1;padding:1em;border:1px solid #ccc;border-radius:4px;text-align:center;"><strong>' . h($userCount) . '</strong><br><a href="' . h(ME) . 'login-system-admin&page=users">Users</a></div>';
		echo '<div style="flex:1;padding:1em;border:1px solid #ccc;border-radius:4px;text-align:center;"><strong>' . h($serverCount) . '</strong><br><a href="' . h(ME) . 'login-system-admin&page=servers">Servers</a></div>';
		echo '<div style="flex:1;padding:1em;border:1px solid #ccc;border-radius:4px;text-align:center;"><strong>' . h($accessCount) . '</strong><br><a href="' . h(ME) . 'login-system-admin&page=access">Access mappings</a></div>';
		echo '</div>';

		echo '<h3>Quick links</h3>';
		echo '<ul>';
		echo '<li><a href="' . h(ME) . 'login-system-admin&page=user_form">Add new user</a></li>';
		echo '<li><a href="' . h(ME) . 'login-system-admin&page=server_form">Add new server</a></li>';
		echo '</ul>';
	}

	/**
	 * @return void
	 */
	private function renderAdminUsersPage(): void
	{
		$users = $this->adminManager->listUsers();
		$currentUserId = isset($_SESSION["adminer_login_system_user_id"]) ? (int) $_SESSION["adminer_login_system_user_id"] : 0;

		echo '<h2>Users</h2>';
		echo '<p><a href="' . h(ME) . 'login-system-admin&page=user_form" class="button">+ Add User</a></p>';

		if (empty($users)) {
			echo '<p>No users found.</p>';
			return;
		}

		echo '<table cellspacing="0">';
		echo '<thead><tr><th>Username</th><th>Role</th><th>TOTP</th><th>Created</th><th>Actions</th></tr></thead><tbody>';

		foreach ($users as $user) {
			$isSelf = (int) $user['id'] === $currentUserId;
			$totpStatus = (!empty($user['totp_secret']) && !empty($user['enrolled_at'])) ? 'Yes' : 'No';
			$editLink = h(ME) . 'login-system-admin&page=user_form&id=' . $user['id'];
			echo '<tr>';
			echo '<td>' . h($user['username']) . ($isSelf ? ' <em>(you)</em>' : '') . '</td>';
			echo '<td>' . h($user['role']) . '</td>';
			echo '<td>' . $totpStatus . '</td>';
			echo '<td>' . ($user['created_at'] ? h(date('Y-m-d', (int) $user['created_at'])) : '') . '</td>';
			echo '<td>';
			echo '<form action="' . h(ME) . 'login-system-admin&page=users" method="post" style="display:inline">';
			echo input_token();
			echo '<input type="hidden" name="id" value="' . $user['id'] . '">';
			echo '<a href="' . $editLink . '">Edit</a>';
			echo ' | ';
			echo '<input type="hidden" name="admin_action" value="delete">';
			echo '<input type="submit" value="Delete" onclick="return confirm(\'Are you sure you want to delete user ' . h($user['username']) . '?\')">';
			echo '</form>';
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
	}

	/**
	 * @param int|null $id
	 * @param array $errors
	 * @return void
	 */
	private function renderAdminUserForm(?int $id = null, array $errors = []): void
	{
		$isEdit = $id !== null;
		$user = $isEdit ? $this->adminManager->getUser($id) : null;
		$action = $isEdit ? 'update' : 'create';
		$title = $isEdit ? 'Edit user: ' . h($user['username'] ?? '') : 'Add user';

		echo '<h2>' . $title . '</h2>';

		$allErrors = !empty($errors) ? $errors : $this->adminErrors;
		if (!empty($allErrors)) {
			foreach ($allErrors as $error) {
				echo '<p class="error">' . h($error) . '</p>';
			}
		}

		$formPage = $isEdit ? 'user_form&id=' . $id : 'user_form';
		echo '<form action="' . h(ME) . 'login-system-admin&page=' . $formPage . '" method="post">';
		echo input_token();
		echo '<input type="hidden" name="admin_action" value="' . $action . '">';
		if ($isEdit) {
			echo '<input type="hidden" name="id" value="' . $id . '">';
		}

		echo '<table cellspacing="0" class="layout">';
		echo '<tr><th>Username<td><input name="username" value="' . h($user['username'] ?? '') . '" required maxlength="255">';
		echo '<tr><th>Password<td><input name="password" type="password"' . ($isEdit ? ' placeholder="Leave blank to keep current"' : ' required') . '>';
		if ($isEdit) {
			echo '<br><small>Leave blank to keep current password.</small>';
		}
		echo '<tr><th>Role<td><select name="role">';
		echo '<option value="user"' . (($user['role'] ?? '') === 'user' ? ' selected' : '') . '>User</option>';
		echo '<option value="admin"' . (($user['role'] ?? '') === 'admin' ? ' selected' : '') . '>Admin</option>';
		echo '</select>';
		echo '</table>';
		echo '<p><input type="submit" value="' . ($isEdit ? 'Save' : 'Create') . '">';
		echo ' <a href="' . h(ME) . 'login-system-admin&page=users">Cancel</a></p>';
		echo '</form>';
	}

	/**
	 * @return void
	 */
	private function renderAdminServersPage(): void
	{
		$servers = $this->adminManager->listServers();

		echo '<h2>Servers</h2>';
		echo '<p><a href="' . h(ME) . 'login-system-admin&page=server_form" class="button">+ Add Server</a></p>';

		if (empty($servers)) {
			echo '<p>No servers found.</p>';
			return;
		}

		echo '<table cellspacing="0">';
		echo '<thead><tr><th>Name</th><th>Type</th><th>Host</th><th>Port</th><th>Public</th><th>SSH</th><th>Actions</th></tr></thead><tbody>';

		foreach ($servers as $server) {
			$public = !empty($server['is_public']) ? 'Yes' : 'No';
			$ssh = (!empty($server['ssh_host'])) ? 'Yes' : 'No';
			$editLink = h(ME) . 'login-system-admin&page=server_form&id=' . $server['id'];
			echo '<tr>';
			echo '<td>' . h($server['name']) . '</td>';
			echo '<td>' . h($server['db_type']) . '</td>';
			echo '<td>' . h($server['hostname']) . '</td>';
			echo '<td>' . h($server['port']) . '</td>';
			echo '<td>' . $public . '</td>';
			echo '<td>' . $ssh . '</td>';
			echo '<td>';
			echo '<form action="' . h(ME) . 'login-system-admin&page=servers" method="post" style="display:inline">';
			echo input_token();
			echo '<input type="hidden" name="id" value="' . $server['id'] . '">';
			echo '<a href="' . $editLink . '">Edit</a>';
			echo ' | ';
			echo '<input type="hidden" name="admin_action" value="delete">';
			echo '<input type="submit" value="Delete" onclick="return confirm(\'Are you sure you want to delete server ' . h($server['name']) . '?\')">';
			echo '</form>';
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
	}

	/**
	 * @param int|null $id
	 * @param array $errors
	 * @return void
	 */
	private function renderAdminServerForm(?int $id = null, array $errors = []): void
	{
		$isEdit = $id !== null;
		$server = $isEdit ? $this->adminManager->getServer($id) : null;
		$action = $isEdit ? 'update' : 'create';
		$title = $isEdit ? 'Edit server: ' . h($server['name'] ?? '') : 'Add server';

		echo '<h2>' . $title . '</h2>';

		$allErrors = !empty($errors) ? $errors : $this->adminErrors;
		if (!empty($allErrors)) {
			foreach ($allErrors as $error) {
				echo '<p class="error">' . h($error) . '</p>';
			}
		}

		$formPage = $isEdit ? 'server_form&id=' . $id : 'server_form';
		echo '<form action="' . h(ME) . 'login-system-admin&page=' . $formPage . '" method="post">';
		echo input_token();
		echo '<input type="hidden" name="admin_action" value="' . $action . '">';
		if ($isEdit) {
			echo '<input type="hidden" name="id" value="' . $id . '">';
		}

		echo '<table cellspacing="0" class="layout">';
		echo '<tr><th>Name<td><input name="name" value="' . h($server['name'] ?? '') . '">';
		echo '<tr><th>Database type<td><select name="db_type">';
		$types = ['server' => 'MySQL', 'pgsql' => 'PostgreSQL', 'sqlite' => 'SQLite', 'mssql' => 'MSSQL', 'oracle' => 'Oracle', 'firebird' => 'Firebird', 'mongo' => 'MongoDB', 'elastic' => 'Elasticsearch'];
		foreach ($types as $val => $label) {
			$selected = ($server['db_type'] ?? 'server') === $val ? ' selected' : '';
			echo '<option value="' . $val . '"' . $selected . '>' . h($label) . '</option>';
		}
		echo '</select>';
		echo '<tr><th>Hostname<td><input name="hostname" value="' . h($server['hostname'] ?? '') . '" required>';
		echo '<tr><th>Port<td><input name="port" value="' . h($server['port'] ?? '') . '" required type="number" min="1" max="65535">';
		echo '<tr><th>Database username<td><input name="db_username" value="' . h($server['db_username'] ?? '') . '" required>';
		echo '<tr><th>Database password<td><input name="db_password" type="password"' . ($isEdit ? ' placeholder="Leave blank to keep current"' : ' required') . '>';
		if ($isEdit) {
			echo '<br><small>Leave blank to keep current encrypted password.</small>';
		}
		echo '<tr><th>Public<td><label><input type="checkbox" name="is_public" value="1"' . (!empty($server['is_public']) ? ' checked' : '') . '> Public (no SSH tunnel)</label>';
		echo '<tr><th colspan=2><hr><strong>SSH Tunnel</strong> <small>(leave empty if not needed)</small>';
		echo '<tr><th>SSH host<td><input name="ssh_host" value="' . h($server['ssh_host'] ?? '') . '">';
		echo '<tr><th>SSH port<td><input name="ssh_port" value="' . h($server['ssh_port'] ?? '22') . '" type="number" min="1" max="65535">';
		echo '<tr><th>SSH user<td><input name="ssh_user" value="' . h($server['ssh_user'] ?? '') . '">';
		echo '<tr><th>SSH password<td><input name="ssh_password" type="password" value="' . h($server['ssh_password'] ?? '') . '">';
		echo '<tr><th>SSH key path<td><input name="ssh_private_key_path" value="' . h($server['ssh_private_key_path'] ?? '') . '">';
		echo '</table>';
		echo '<p><input type="submit" value="' . ($isEdit ? 'Save' : 'Create') . '">';
		echo ' <a href="' . h(ME) . 'login-system-admin&page=servers">Cancel</a></p>';
		echo '</form>';
	}

	/**
	 * @return void
	 */
	private function renderAdminAccessPage(): void
	{
		$users = $this->adminManager->listUsers();
		$servers = $this->adminManager->listServers();
		$userServers = $this->adminManager->getUserServers();

		echo '<h2>Access Management</h2>';
		echo '<p>Grant or revoke server access for each user.</p>';

		if (empty($users) || empty($servers)) {
			echo '<p>Create users and servers first to manage access.</p>';
			return;
		}

		echo '<form action="' . h(ME) . 'login-system-admin&page=access" method="post">';
		echo input_token();

		echo '<table cellspacing="0">';
		echo '<thead><tr><th>User</th>';
		foreach ($servers as $server) {
			echo '<th>' . h($server['name'] ?: $server['hostname']) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ($users as $user) {
			$uid = (int) $user['id'];
			$hasAccess = isset($userServers[$uid]) ? $userServers[$uid] : [];
			echo '<tr>';
			echo '<td>' . h($user['username']) . '</td>';
			foreach ($servers as $server) {
				$sid = (int) $server['id'];
				$checked = in_array($sid, $hasAccess, true) ? ' checked' : '';
				echo '<td style="text-align:center"><input type="checkbox" name="access[' . $uid . '_' . $sid . ']" value="1"' . $checked . '></td>';
			}
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '<p><input type="submit" value="Save access permissions"></p>';
		echo '</form>';
	}

	// ---------------------------------------------------------------
	// Logout
	// ---------------------------------------------------------------

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
				unset($_SESSION["adminer_login_system_totp_verified"]);
				$this->logger->log('User logged out', ['user_id' => $userId]);
			}
		}

		$this->logger->exit_('AdminerLoginSystem::handleLogout');
	}
}
