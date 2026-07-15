<?php

/**
 * SSH tunnel lifecycle.
 */
class SshTunnel
{
	/** @var ServerManager */
	private $serverManager;

	/** @var Logger */
	private $logger;

	/**
	 * @param ServerManager $serverManager
	 * @param Logger $logger
	 */
	public function __construct(ServerManager $serverManager, Logger $logger)
	{
		$this->serverManager = $serverManager;
		$this->logger = $logger;
		$this->logger->entry('SshTunnel::__construct');
		$this->logger->exit_('SshTunnel::__construct');
	}

	/**
	 * @param array $server
	 * @return array Server row updated with mapped_local_port
	 * @throws RuntimeException
	 */
	public function ensureTunnel(array $server): array
	{
		$this->logger->entry('SshTunnel::ensureTunnel', ['server_id' => $server['id']]);

		$remoteHost = $server['hostname'];
		$remotePort = (int) $server['port'];
		$existingPid = $server['ssh_pid'] ? (int) $server['ssh_pid'] : null;

		if ($existingPid !== null) {
			$alivePid = $this->findTunnelPid($remoteHost, $remotePort);
			if ($alivePid === $existingPid) {
				$localPort = $server['mapped_local_port'] ? (int) $server['mapped_local_port'] : null;
				if ($localPort !== null) {
					$this->logger->exit_('SshTunnel::ensureTunnel', ['reused' => true, 'local_port' => $localPort, 'pid' => $existingPid]);
					return array_merge($server, ['mapped_local_port' => $localPort]);
				}
			}

			$this->logger->log('Stale tunnel detected, clearing', ['server_id' => $server['id'], 'stored_pid' => $existingPid, 'alive_pid' => $alivePid], 'warning');
			$this->killProcess($existingPid);
			$this->serverManager->updateTunnel((int) $server['id'], null, null);
		}

		$localPort = $this->findFreePort();
		$cmd = $this->buildCommand($server, $localPort);
		$pid = $this->spawn($cmd);

		if (!$this->waitForPort($localPort, 10)) {
			$this->killProcess($pid);
			throw new RuntimeException('SSH tunnel failed to open within 10 seconds');
		}

		$this->serverManager->updateTunnel((int) $server['id'], $localPort, $pid);

		$this->logger->exit_('SshTunnel::ensureTunnel', ['local_port' => $localPort, 'pid' => $pid]);
		return array_merge($server, ['mapped_local_port' => $localPort, 'ssh_pid' => $pid]);
	}

	/**
	 * @param array $server
	 * @param int $localPort
	 * @return string
	 */
	public function buildCommand(array $server, int $localPort): string
	{
		$this->logger->entry('SshTunnel::buildCommand', ['server_id' => $server['id'], 'local_port' => $localPort]);

		$remoteHost = escapeshellarg($server['hostname']);
		$remotePort = (int) $server['port'];
		$sshHost = escapeshellarg($server['ssh_host']);
		$sshUser = $server['ssh_user'] ? escapeshellarg($server['ssh_user']) : null;
		$sshPort = $server['ssh_port'] ? (int) $server['ssh_port'] : 22;
		$keyPath = $server['ssh_private_key_path'] ? escapeshellarg($server['ssh_private_key_path']) : null;
		$sshPassword = $server['ssh_password'];

		$hostSpec = $sshUser ? $sshUser . '@' . $sshHost : $sshHost;
		$options = '-o BatchMode=no -o ExitOnForwardFailure=yes';

		if ($keyPath !== null) {
			$options .= ' -i ' . $keyPath;
		}

		if ($sshPort !== 22) {
			$options .= ' -p ' . $sshPort;
		}

		$base = "ssh -N -L {$localPort}:{$remoteHost}:{$remotePort} {$options} {$hostSpec}";

		if ($sshPassword !== null && $sshPassword !== '' && $this->hasSshpass()) {
			$base = "sshpass -p " . escapeshellarg($sshPassword) . " {$base}";
		}

		$this->logger->exit_('SshTunnel::buildCommand');
		return $base;
	}

	/**
	 * @param string $cmd
	 * @return int
	 */
	public function spawn(string $cmd): int
	{
		$this->logger->entry('SshTunnel::spawn', ['cmd' => $cmd]);

		$full = "nohup {$cmd} > /dev/null 2>&1 & echo $!";
		exec($full, $output, $exitCode);

		if ($exitCode !== 0 || empty($output[0]) || !ctype_digit($output[0])) {
			throw new RuntimeException('Failed to spawn SSH tunnel');
		}

		$pid = (int) $output[0];
		$this->logger->exit_('SshTunnel::spawn', ['pid' => $pid]);
		return $pid;
	}

	/**
	 * @param string $remoteHost
	 * @param int $remotePort
	 * @return int|null
	 */
	public function findTunnelPid(string $remoteHost, int $remotePort): ?int
	{
		$this->logger->entry('SshTunnel::findTunnelPid', ['remote_host' => $remoteHost, 'remote_port' => $remotePort]);
		$pattern = "{$remoteHost}:{$remotePort}";

		$proc = proc_open(['pgrep', '-f', $pattern], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (!is_resource($proc)) {
			$this->logger->exit_('SshTunnel::findTunnelPid', ['found' => false, 'reason' => 'proc_open failed']);
			return null;
		}

		$output = stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($proc);

		$pids = array_filter(array_map('trim', explode("\n", $output)), 'ctype_digit');

		foreach ($pids as $pid) {
			$pid = (int) $pid;
			$cmdline = @file_get_contents("/proc/{$pid}/cmdline");
			if ($cmdline !== false && strpos($cmdline, 'ssh') !== false) {
				$this->logger->exit_('SshTunnel::findTunnelPid', ['found' => true, 'pid' => $pid]);
				return $pid;
			}
		}

		$this->logger->exit_('SshTunnel::findTunnelPid', ['found' => false, 'candidates' => count($pids)]);
		return null;
	}

	/**
	 * @param int $pid
	 * @return bool
	 */
	public function isProcessAlive(int $pid): bool
	{
		$this->logger->entry('SshTunnel::isProcessAlive', ['pid' => $pid]);
		$alive = posix_kill($pid, 0);
		$this->logger->exit_('SshTunnel::isProcessAlive', ['alive' => $alive]);
		return $alive;
	}

	/**
	 * @param int $pid
	 * @return void
	 */
	public function killProcess(int $pid): void
	{
		$this->logger->entry('SshTunnel::killProcess', ['pid' => $pid]);
		posix_kill($pid, SIGTERM);
		usleep(500000);
		if ($this->isProcessAlive($pid)) {
			posix_kill($pid, SIGKILL);
		}
		$this->logger->exit_('SshTunnel::killProcess');
	}

	/**
	 * @param int $localPort
	 * @param int $timeoutSeconds
	 * @return bool
	 */
	public function waitForPort(int $localPort, int $timeoutSeconds): bool
	{
		$this->logger->entry('SshTunnel::waitForPort', ['local_port' => $localPort, 'timeout' => $timeoutSeconds]);

		$end = time() + $timeoutSeconds;
		while (time() < $end) {
			$connection = @fsockopen('127.0.0.1', $localPort, $errno, $errstr, 1);
			if ($connection !== false) {
				fclose($connection);
				$this->logger->exit_('SshTunnel::waitForPort', ['open' => true]);
				return true;
			}
			usleep(250000);
		}

		$this->logger->exit_('SshTunnel::waitForPort', ['open' => false]);
		return false;
	}

	/**
	 * @return int
	 * @throws RuntimeException
	 */
	public function findFreePort(): int
	{
		$this->logger->entry('SshTunnel::findFreePort');

		$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
		if ($socket === false) {
			throw new RuntimeException('Failed to create socket');
		}

		socket_bind($socket, '127.0.0.1', 0);
		$addr = '';
		$port = 0;
		socket_getsockname($socket, $addr, $port);
		socket_close($socket);

		if ($port < 1024) {
			return $this->findFreePort();
		}

		$this->logger->exit_('SshTunnel::findFreePort', ['port' => $port]);
		return $port;
	}

	/**
	 * @return bool
	 */
	public function hasSshpass(): bool
	{
		$this->logger->entry('SshTunnel::hasSshpass');
		$has = (bool) shell_exec('command -v sshpass');
		$this->logger->exit_('SshTunnel::hasSshpass', ['has' => $has]);
		return $has;
	}
}
