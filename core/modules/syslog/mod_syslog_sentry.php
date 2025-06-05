<?php

dol_include_once('/core/modules/syslog/logHandler.php');

class mod_syslog_sentry extends LogHandler
{
	public $code = 'sentry';
	protected ?bool $isEnabled = null;
	protected string $defaultLogger = 'dol';
	protected $oldExceptionHandler;
	protected $oldErrorHandler;
	protected array|false $reports;

	private string $clientName = 'dolibarr-sentry-connector';
	private string $serverUrl = '';
	private string $secretKey = '';
	private string $publicKey = '';
	private int $project = 0;
	private bool $logStacks = false;
	private string $name = '';
	private array $tags = [];

	public function __construct()
	{
		$this->reports = (PHP_SAPI !== 'cli') ? [] : false;
		$this->initHandler();
	}

	/**
	 * @return string
	 */
	public function getName(): string
	{
		return 'Sentry';
	}

	/**
	 * @return string
	 */
	public function getVersion(): string
	{
		return '1.0.0';
	}

	/**
	 * @return int
	 */
	public function isActive(): int
	{
		return 1;
	}

	/**
	 * @return array|array[]
	 */
	public function configure(): array
	{
		global $langs;

		$langs->load('sentry@sentry');

		return [
			[
				'constant' => 'SYSLOG_SENTRY_LOGGER',
				'name' => $langs->trans('LoggerName'),
				'default' => 'dolibarr',
				'attr' => 'size="40"><br><span style="color:#767676;"><b>required</b>, example: <b>dolibarr</b></span></td><td class="left"></td></tr><tr class="oddeven"><td></td><td class="nowrap"',
			],
			[
				'constant' => 'SYSLOG_SENTRY_DSN_PHP',
				'name' => '<strong>'.$langs->trans('DNSForPHP').'</strong>',
				'default' => '',
				'attr' => 'size="85"><br><span style="color:#767676;"><b>required</b>, example: http://public:secret@sentry.example.com:9000/pid</span></td><td class="left"></td></tr><tr class="oddeven"><td></td><td class="nowrap"',
			],
			[
				'constant' => 'SYSLOG_SENTRY_ALL_ERRORS',
				'name' => $langs->trans('ReportAllErrors'),
				'default' => 'no',
				'attr' => 'size="40"><br><span style="color:#767676;"><b>required</b>, <em>error_reporting(E_ALL)</em>, example: <b>yes</b> or <b>no</b></span></td><td class="left"></td></tr><tr class="oddeven"><td></td><td class="nowrap"',
			],
			[
				'constant' => 'SYSLOG_SENTRY_DSN_JS',
				'name' => '<strong>'.$langs->trans('DSNForJS').'</strong>',
				'default' => 'no',
				'attr' => 'size="85"><br><span style="color:#767676;"><b>required</b>, example: http://public:secret@sentry.example.com:9000/pid or to disable: <b>no</b> or <b>disabled</b></span></td><td class="left"></td></tr><tr class="oddeven"><td></td><td class="nowrap"',
			],
			[
				'constant' => 'SYSLOG_SENTRY_DSN_JS_TUNNEL',
				'name' => $langs->trans('TunnelForJS'),
				'default' => 'no',
				'attr' => 'size="85"><br><span style="color:#767676;"><b>required</b>, <a href="https://docs.sentry.io/platforms/javascript/troubleshooting/">doc</a>, example: <code>/sentry</code> or to disable: <b>no</b> or <b>disabled</b></span></td><td class="left"></td></tr><tr class="oddeven"><td></td><td class="nowrap"',
			],
			[
				'constant' => 'SYSLOG_SENTRY_DSN_JS_OPTIONS',
				'name' => $langs->trans('OptionsForJS'),
				'default' => 'no',
				'attr' => 'size="85"><br><span style="color:#767676;"><b>required</b>, <a href="https://docs.sentry.io/platforms/javascript/configuration/options/">doc</a>, must be JS compliant, example: <code style="display:block; margin:5px 0; line-height:1.2;">allowUrls: /example\.org/,<br>ignoreErrors: [\'ResizeObserver loop limit exceeded\', \'Failed to fetch\'],</code> or to disable: <b>no</b> or <b>disabled</b></span> <button type="button" onclick="test();" style="position:absolute; right:50px;">Test JS</button></td><td class="left"></td></tr><tr class="oddeven"><td></td><td class="nowrap"',
			],
		];
	}

	/**
	 * @return bool
	 */
	public function checkConfiguration(): bool
	{
		if (empty(GETPOST('SYSLOG_SENTRY_DSN_PHP', 'alpha'))) {
			dol_syslog(__METHOD__ . ' Sentry DSN is empty', LOG_ERR);
			return false;
		}

		$errors = 0;
		$initResult = $this->initSentry();

		if ($initResult !== true) {
			$errors++;
		} else {
			$result = $this->captureException(
				new Exception('Sentry test from Dolibarr'),
				null,
				['source' => 'sentry:checkConfiguration']
			);
			setEventMessages('Test sent to Sentry, eventId: ' . print_r($result, true), null, 'mesgs');
		}

		if (!empty($errors)) {
			global $db;
			// Disable Sentry handler in syslog configuration
			$handlers = json_decode(dolibarr_get_const($db, 'SYSLOG_HANDLERS', 0), true);
			$index = array_search('mod_syslog_sentry', $handlers, true);

			if ($index !== false) {
				unset($handlers[$index]);
			}

			dolibarr_set_const($db, 'SYSLOG_HANDLERS', json_encode($handlers), 'chaine', 0, '', 0);
			return false;
		}

		return true;
	}

	/**
	 * @param $content
	 * @param $suffixinfilename
	 * @return void
	 */
	public function export($content, $suffixinfilename = ''): void
	{
		$map = [
			LOG_EMERG => 'fatal',
			LOG_ALERT => 'fatal',
			LOG_CRIT => 'error',
			LOG_ERR => 'error',
			LOG_WARNING => 'warning',
			LOG_NOTICE => 'warning',
			LOG_INFO => 'info',
			LOG_DEBUG => 'debug',
		];

		$level = array_key_exists($content['level'], $map) ? $map[$content['level']] : 'error';

		if ($level !== 'debug' && $level !== 'info') {
			if (strncmp($content['message'], 'sql', 3) === 0) {
				$this->captureMessage('SQL: ' . substr($content['message'], 4), $level);
			} elseif (strpos($content['message'], '---', 3) !== 0) {
				$this->captureMessage($content['message'], $level);
			}
		}
	}

	/**
	 * @return void
	 */
	public function initHandler(): void
	{
		$cnf = getDolGlobalString('SYSLOG_HANDLERS');
		$dsn = getDolGlobalString('SYSLOG_SENTRY_DSN_PHP');

		$isActive = true;

		if (!empty($_COOKIE['__blackfire']) && empty($_GET['blackfire'])) {
			$isActive = false;
		} else {
			$isActive = !empty($dsn)
				&& !in_array($dsn, ['no', 'NO', 'disabled'])
				&& (strpos($cnf, 'mod_syslog_sentry') !== false);
		}

		if ($isActive) {
			$_SERVER['SENTRY_DSN'] = (string)$dsn;
			$_SERVER['SENTRY_ENABLED'] = true;

			$allErrors = getDolGlobalString('SYSLOG_SENTRY_ALL_ERRORS');
			if (!empty($allErrors) && $allErrors === 'yes') {
				error_reporting(E_ALL);
			}

			$this->oldExceptionHandler = set_exception_handler([$this, 'handleException']);
			$this->oldErrorHandler = set_error_handler([$this, 'handleError'], error_reporting());
		}
	}

	/**
	 * @param Throwable $e
	 * @return void
	 * @throws Throwable
	 */
	public function handleException(Throwable $e): void
	{
		if ($this->oldExceptionHandler) {
			call_user_func($this->oldExceptionHandler, $e);
		}

		if (ini_get('display_errors') === '1') {
			throw $e;
		}

		$this->captureException($e, null, ['source' => 'sentry:handleException']);
	}


	/**
	 * @param int $errno
	 * @param string $errstr
	 * @param string $errfile
	 * @param int $errline
	 * @param array $context
	 * @return void
	 * @throws ErrorException
	 */
	public function handleError(int $errno, string $errstr, string $errfile, int $errline, array $context = []): void
	{
		if ($this->oldErrorHandler) {
			call_user_func($this->oldErrorHandler, $errno, $errstr, $errfile, $errline, $context);
		}

		$e = new ErrorException($errstr, 0, $errno, $errfile, $errline);

		if (ini_get('display_errors') === '1') {
			throw $e;
		}

		$this->captureException($e, null, ['source' => 'sentry:handleError']);
	}

	public function __destruct()
	{
		if (!empty($this->reports) && is_array($this->reports)) {
			while (is_array($report = array_shift($this->reports))) {
				$this->{$report['type']}($report['url'], $report['data'], $report['headers']);
			}
		}
	}


	/**
	 * @param bool $isTest
	 * @return bool|string
	 */
	private function initSentry(bool $isTest = false): bool|string
	{
		if (is_bool($this->isEnabled)) {
			return $this->isEnabled;
		}

		$cnf = getDolGlobalString('SYSLOG_HANDLERS');
		$dsn = getDolGlobalString('SYSLOG_SENTRY_DSN_PHP');
		$log = getDolGlobalString('SYSLOG_SENTRY_LOGGER');

		$options = [];

		try {
			$isEnabled = str_contains($cnf, 'mod_syslog_sentry');

			if ($isEnabled || $isTest) {
				$this->parseDSN($_SERVER['SENTRY_DSN'] ?? $dsn, $options);
			}

			$this->isEnabled = $isEnabled;

			if (!empty($log)) {
				$this->defaultLogger = (string)$log;
			}
		} catch (Throwable $t) {
			$this->isEnabled = false;

			if ($isTest) {
				return $t->getMessage();
			}
		}

		return $this->isEnabled;
	}


	/**
	 * @return false|string
	 */
	private function getUsername()
	{
		global $user;
		return is_object($user) ? $user->login : false;
	}


	/**
	 * @param Throwable $exception
	 * @param array $trace
	 * @return bool
	 */
	protected function addSourceFile(Throwable $exception, array $trace = []): bool
	{
		return !empty($trace[0]['file'])
			&& !empty($trace[0]['line'])
			&& ($trace[0]['file'] === $exception->getFile())
			&& ($trace[0]['line'] === $exception->getLine());
	}


	/**
	 * @param string $message
	 * @param string $level
	 * @param array $tags
	 * @param bool $stack
	 * @return string|false
	 */
	public function captureMessage(string $message, string $level = 'info', array $tags = [], bool $stack = false): string|false
	{
		return $this->capture([
			'message' => $message,
			'level' => $level,
			'sentry.interfaces.Message' => [
				'message' => $message,
			],
		], $stack, $tags);
	}


	/**
	 * @param Throwable $exception
	 * @param string|null $customMessage
	 * @param array $tags
	 * @return string|false
	 */
	public function captureException(Throwable $exception, ?string $customMessage = null, array $tags = []): string|false
	{
		$message = $exception->getMessage() ?: '<unknown exception>';

		// Skip common undefined property/variable errors unless explicitly requested
		$skipErrors = [
			'Attempt to read property "',
			'Undefined property: ',
			'Undefined array key ',
			'Undefined variable $',
			'Trying to access array offset on value of type null',
		];

		foreach ($skipErrors as $skipError) {
			if (strncmp($message, $skipError, strlen($skipError)) === 0) {
				if (empty($_GET['allundef']) && !str_contains($exception->getFile(), '/custom/')) {
					return false;
				}
			}
		}

		// Sentry levels: debug, info, warning, error, fatal
		$levels = [
			E_ERROR => ['error', 'Error'],
			E_WARNING => ['warning', 'Warning'],
			E_PARSE => ['error', 'Parse Error'],
			E_NOTICE => ['info', 'Notice'],
			E_CORE_ERROR => ['error', 'Core Error'],
			E_CORE_WARNING => ['warning', 'Core Warning'],
			E_COMPILE_ERROR => ['error', 'Compile Error'],
			E_COMPILE_WARNING => ['warning', 'Compile Warning'],
			E_USER_ERROR => ['error', 'User Error'],
			E_USER_WARNING => ['warning', 'User Warning'],
			E_USER_NOTICE => ['info', 'User Notice'],
			E_STRICT => ['info', 'Strict Notice'],
			E_RECOVERABLE_ERROR => ['error', 'Recoverable Error'],
			E_DEPRECATED => ['info', 'Deprecated functionality'],
		];

		$type = empty($exception->getCode()) ? get_class($exception) : (string)$exception->getCode();
		$hasSeverity = method_exists($exception, 'getSeverity');

		if ($hasSeverity) {
			$type = $levels[$exception->getSeverity()][1] ?? $type;
		}

		$data = [
			'message' => $customMessage,
			'level' => $hasSeverity ? ($levels[$exception->getSeverity()][0] ?? 'error') : 'error',
			'sentry.interfaces.Exception' => [
				'value' => $message,
				'type' => $type,
				'module' => $exception->getFile() . ':' . $exception->getLine(),
			],
		];

		// Exception::getTrace doesn't store the point where the exception was thrown
		$trace = $exception->getTrace();

		if ($this->addSourceFile($exception, $trace)) {
			array_unshift($trace, ['file' => $exception->getFile(), 'line' => $exception->getLine()]);
		}

		return $this->capture($data, $trace, $tags);
	}


	/**
	 * @param string $dsn
	 * @param array $options
	 * @return void
	 */
	public function parseDSN(string $dsn, array $options): void
	{
		$url = parse_url($dsn);

		if (!is_array($url)) {
			dol_syslog(__METHOD__ . '::parse_url Unsupported Sentry DSN (parse_url): ' . $dsn);
			throw new InvalidArgumentException('Unsupported Sentry DSN (parse_url): ' . $dsn);
		}

		$scheme = $url['scheme'] ?? '';

		if (empty($scheme)) {
			dol_syslog(__METHOD__ . '::parse_url Unsupported Sentry DSN (scheme not found): ' . $dsn);
			throw new InvalidArgumentException('Unsupported Sentry DSN (scheme not found): ' . $dsn);
		}

		if (!in_array($scheme, ['http', 'https', 'udp'])) {
			dol_syslog(__METHOD__ . '::parse_url Unsupported Sentry DSN scheme: ' . $scheme);
			throw new InvalidArgumentException('Unsupported Sentry DSN scheme: ' . $scheme);
		}

		$netloc = $url['host'] ?? null;
		$netloc .= isset($url['port']) ? ':' . $url['port'] : null;

		$rawpath = $url['path'] ?? null;
		$project = null;
		$path = '';

		if ($rawpath) {
			$pos = strrpos($rawpath, '/', 1);

			if ($pos !== false) {
				$path = substr($rawpath, 0, $pos);
				$project = substr($rawpath, $pos + 1);
			} else {
				$project = substr($rawpath, 1);
			}
		}

		$username = $url['user'] ?? null;
		$password = $url['pass'] ?? 'secret';

		if (empty($netloc) || empty($project) || empty($username) || empty($password)) {
			throw new InvalidArgumentException('Invalid Sentry DSN: ' . $dsn);
		}

		if (empty($options['tags']['runtime'])) {
			$options['tags']['runtime'] = 'PHP ' . PHP_VERSION;
		}

		if (empty($options['tags']['engine'])) {
			$options['tags']['engine'] = 'Dolibarr ' . DOL_VERSION;
		}

		$this->serverUrl = sprintf('%s://%s%s/api/store/', $scheme, $netloc, $path);
		$this->secretKey = $password;
		$this->publicKey = $username;
		$this->project = (int)$project;
		$this->logStacks = $options['auto_log_stacks'] ?? false;
		$this->name = empty($options['name']) ? gethostname() : $options['name'];
		$this->tags = $options['tags'] ?? [];
	}


	/**
	 * @param array $data
	 * @param array|bool $stack
	 * @param array $tags
	 * @return string
	 */
	private function capture(array $data, array|bool $stack, array $tags = []): string
	{
		if ($this->initSentry() !== true) {
			return '';
		}

		if (!isset($data['logger'])) {
			$data['logger'] = $this->defaultLogger;
		}

		if (!isset($data['timestamp'])) {
			$data['timestamp'] = gmdate('Y-m-d\TH:i:s\Z');
		}

		if (!isset($data['level']) || !in_array($data['level'], ['debug', 'info', 'warning', 'error', 'fatal'])) {
			$data['level'] = 'error';
		}

		// The function getallheaders() is only available when running in a web-request
		$headers = function_exists('getallheaders') ? array_filter(getallheaders(), 'strlen') : [];
		$eventId = $this->getUuid4();

		$serverWithoutHttp = [];
		foreach ($_SERVER as $key => $value) {
			if (!empty($value) && (strncmp($key, 'HTTP_', 5) !== 0)) {
				$serverWithoutHttp[$key] = $value;
			}
		}

		$data = array_merge($data, [
			'server_name' => $this->name,
			'event_id' => $eventId,
			'project' => $this->project,
			'site' => $_SERVER['SERVER_NAME'] ?? '',
			'sentry.interfaces.Http' => [
				'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
				'url' => $this->getCurrentUrl(),
				'query_string' => $_SERVER['QUERY_STRING'] ?? '',
				'data' => $_POST,
				'cookies' => $_COOKIE,
				'headers' => $headers,
				'env' => $serverWithoutHttp,
			],
		]);

		if ((!$stack && $this->logStacks) || ($stack === true)) {
			$stack = debug_backtrace();
			array_shift($stack);
		}

		if (!empty($stack) && is_array($stack)) {
			for ($i = 0; $i < count($stack) - 1; $i++) {
				$stack[$i]['function'] = $stack[$i + 1]['function'];
			}
			$stack[count($stack) - 1]['function'] = null;

			if (!isset($data['sentry.interfaces.Stacktrace'])) {
				$data['sentry.interfaces.Stacktrace'] = ['frames' => $this->getStackInfo($stack)];
			}
		}

		$data['tags'] = $this->tags + $tags;
		$user = $this->getUsername();

		if (!empty($user)) {
			$data['tags']['username'] = $user;
		}

		$this->send($this->apply($this->removeInvalidUtf8($data)));
		return $eventId;
	}


	/**
	 * @param array $data
	 * @return bool
	 */
	private function send(array $data): bool
	{
		$message = base64_encode(gzcompress(json_encode($data)));
		$timestamp = microtime(true);
		$signature = $this->getSignature($message, $timestamp, $this->secretKey);

		return $this->sendRemote($this->serverUrl, $message, [
			'User-Agent' => $this->clientName,
			'X-Sentry-Auth' => $this->getAuthHeader($signature, $timestamp, $this->clientName, $this->publicKey),
			'Content-Type' => 'application/octet-stream',
		]);
	}


	/**
	 * @param string $url
	 * @param string $data
	 * @param array $headers
	 * @return bool
	 */
	private function sendRemote(string $url, string $data, array $headers): bool
	{
		$parts = (array)parse_url($url);
		$parts['netloc'] = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : null);

		if ($parts['scheme'] === 'udp') {
			if (is_array($this->reports)) {
				$this->reports[] = ['type' => 'sendUdp', 'url' => $parts['netloc'], 'data' => $data, 'headers' => $headers['X-Sentry-Auth']];
				return true;
			}

			return $this->sendUdp($parts['netloc'], $data, $headers['X-Sentry-Auth']);
		}

		if (is_array($this->reports)) {
			$this->reports[] = ['type' => 'sendHttp', 'url' => $url, 'data' => $data, 'headers' => $headers];
			return true;
		}

		return $this->sendHttp($url, $data, $headers);
	}


	/**
	 * @param string $netloc
	 * @param string $data
	 * @param string $headers
	 * @return bool
	 */
	private function sendUdp(string $netloc, string $data, string $headers): bool
	{
		[$host, $port] = explode(':', $netloc);
		$rawData = $headers . "\n\n" . $data;

		$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
		socket_sendto($sock, $rawData, strlen($rawData), 0, $host, $port);
		socket_close($sock);

		return true;
	}


	/**
	 * @param string $url
	 * @param string $data
	 * @param array $headers
	 * @return bool
	 */
	private function sendHttp(string $url, string $data, array $headers): bool
	{
		$newHeaders = [];

		foreach ($headers as $key => $value) {
			$newHeaders[] = $key . ': ' . $value;
		}

		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_HTTPHEADER, $newHeaders);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		curl_setopt($curl, CURLOPT_VERBOSE, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_exec($curl);
		$code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		curl_close($curl);

		return $code === 200;
	}


	/**
	 * @param string $message
	 * @param float $timestamp
	 * @param string $key
	 * @return string
	 */
	private function getSignature(string $message, float $timestamp, string $key): string
	{
		return hash_hmac('sha1', sprintf('%F', $timestamp) . ' ' . $message, $key);
	}


	/**
	 * @param string $signature
	 * @param float $timestamp
	 * @param string $client
	 * @param string|null $apiKey
	 * @return string
	 */
	private function getAuthHeader(string $signature, float $timestamp, string $client, ?string $apiKey = null): string
	{
		$header = [
			sprintf('sentry_timestamp=%F', $timestamp),
			'sentry_signature=' . $signature,
			'sentry_client=' . $client,
			'sentry_version=2.0',
		];

		if ($apiKey) {
			$header[] = 'sentry_key=' . $apiKey;
		}

		return sprintf('Sentry %s', implode(', ', $header));
	}


	/**
	 * @return string
	 * @throws \Random\RandomException
	 */
	private function getUuid4(): string
	{
		return str_replace('-', '', sprintf(
			'%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			// 32 bits for "time_low"
			random_int(0, 0xffff), random_int(0, 0xffff),
			// 16 bits for "time_mid"
			random_int(0, 0xffff),
			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 4
			random_int(0, 0x0fff) | 0x4000,
			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			random_int(0, 0x3fff) | 0x8000,
			// 48 bits for "node"
			random_int(0, 0xffff), random_int(0, 0xffff), random_int(0, 0xffff)
		));
	}


	/**
	 * @return string
	 */
	private function getCurrentUrl(): string
	{
		// When running from command line the REQUEST_URI is missing
		if (empty($_SERVER['REQUEST_URI'])) {
			return '';
		}

		$schema = (
			(!empty($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] !== 'off')) ||
			(!empty($_SERVER['SERVER_PORT']) && ($_SERVER['SERVER_PORT'] == 443)) ||
			(!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && ($_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'))
		) ? 'https://' : 'http://';

		return $schema . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
	}


	/**
	 * @param array $data
	 * @return array
	 */
	private function removeInvalidUtf8(array $data): array
	{
		if (!function_exists('mb_convert_encoding')) {
			return $data;
		}

		foreach ($data as $key => $value) {
			if (is_string($key)) {
				$key = mb_convert_encoding($key, 'UTF-8', 'UTF-8');
			}

			if (is_string($value)) {
				$value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
			}

			if (is_array($value)) {
				$value = $this->removeInvalidUtf8($value);
			}

			$data[$key] = $value;
		}

		return $data;
	}


	/**
	 * @param array $stack
	 * @return array
	 */
	private function getStackInfo(array $stack): array
	{
		$result = [];

		foreach ($stack as $frame) {
			if (isset($frame['file'])) {
				$context = $this->readSourceFile($frame['file'], $frame['line']);
				$absPath = $frame['file'];
				$fileName = basename($frame['file']);
			} else {
				$args = 'n/a';

				if (isset($frame['args'])) {
					$args = is_string($frame['args']) ? $frame['args'] : @json_encode($frame['args']);
				}

				if (isset($frame['class'])) {
					$context['line'] = sprintf('%s%s%s(%s)', $frame['class'], $frame['type'], $frame['function'], $args);
				} else {
					$context['line'] = sprintf('%s(%s)', $frame['function'], $args);
				}

				$absPath = '';
				$fileName = '[Anonymous function]';
				$context['prefix'] = [];
				$context['suffix'] = [];
				$context['filename'] = $fileName;
				$context['lineno'] = 0;
			}

			$module = $fileName;
			if (isset($frame['class'])) {
				$module .= ':' . $frame['class'];
			}

			$result[] = [
				'abs_path' => $absPath,
				'filename' => $context['filename'],
				'lineno' => $context['lineno'],
				'module' => $module,
				'function' => $frame['function'],
				'vars' => [],
				'pre_context' => $context['prefix'],
				'context_line' => $context['line'],
				'post_context' => $context['suffix'],
			];
		}

		return array_reverse($result);
	}


	/**
	 * @param string|null $fileName
	 * @param int|null $lineNo
	 * @return array
	 */
	private function readSourceFile(?string $fileName, ?int $lineNo): array
	{
		$frame = [
			'prefix' => [],
			'line' => '',
			'suffix' => [],
			'filename' => $fileName ?? '',
			'lineno' => $lineNo ?? 0,
		];

		if ($fileName === null || $lineNo === null) {
			return $frame;
		}

		// Code which is eval'ed have a modified filename. Extract the correct filename + linenumber
		$matched = preg_match("/^(.*?)\((\d+)\) : eval\(\)'d code$/", $fileName, $matches);

		if ($matched) {
			[, $fileName, $lineNo] = $matches;
			$frame['filename'] = $fileName;
			$frame['lineno'] = (int)$lineNo;
		}

		// Try to open the file
		try {
			$fh = fopen($fileName, 'rb');

			if ($fh === false) {
				return $frame;
			}
		} catch (Throwable $t) {
			return $frame;
		}

		$curLineno = 0;

		while (!feof($fh)) {
			$curLineno++;
			$line = fgets($fh);

			if ($curLineno === $lineNo) {
				$frame['line'] = $line;
			} elseif ($lineNo - $curLineno > 0 && $lineNo - $curLineno < 3) {
				$frame['prefix'][] = $line;
			} elseif ($line && $lineNo - $curLineno > -3 && $lineNo - $curLineno < 0) {
				$frame['suffix'][] = $line;
			}
		}

		fclose($fh);
		return $frame;
	}


	/**
	 * @param $value
	 * @param $key
	 * @return array|string
	 */
	private function apply($value, $key = null)
	{
		if (is_array($value)) {
			foreach ($value as $k => $v) {
				$value[$k] = $this->apply($v, $k);
			}

			return $value;
		}

		return $this->sanitize($key, $value);
	}


	/**
	 * @param $key
	 * @param $value
	 * @return string
	 */
	private function sanitize($key, $value)
	{

		if (empty($value)) {
			return $value;
		}

		if (is_object($value)) {
			return '#OBJECT! '.get_class($value);
		}

		if (preg_match('/^\d{16}$/', (string) $value)) {
			return '********';
		}

		if (preg_match('/(authorization|password|passwd|secret)/i', (string) $key)) {
			return '********';
		}

		return $value;
	}
}
