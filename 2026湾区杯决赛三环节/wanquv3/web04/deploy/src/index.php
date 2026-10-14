<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

final class LedgerCodec
{
    private const MATERIAL = 'ravel::ledger::2026::7c2a0e49b5';

    public static function wrap(string $message): string
    {
        $frame = rtrim(strtr(base64_encode(gzcompress($message, 9)), '+/', '._'), '=');
        $tag = substr(hash_hmac('sha384', $frame, self::MATERIAL), 11, 32);
        return $frame . '~' . $tag;
    }

    public static function unwrap(string $ticket): ?string
    {
        if (!preg_match('/^[A-Za-z0-9._]{24,4200}~[a-f0-9]{32}$/', $ticket)) {
            return null;
        }

        [$frame, $tag] = explode('~', $ticket, 2);
        $expected = substr(hash_hmac('sha384', $frame, self::MATERIAL), 11, 32);

        if (!hash_equals($expected, $tag)) {
            return null;
        }

        $padding = strlen($frame) % 4;
        if ($padding !== 0) {
            $frame .= str_repeat('=', 4 - $padding);
        }

        $packed = base64_decode(strtr($frame, '._', '+/'), true);
        if ($packed === false) {
            return null;
        }

        $message = @gzuncompress($packed, 8192);
        return is_string($message) ? $message : null;
    }
}

final class LoopbackRule
{
    private $expression = '/^(::1|127(?:\.[0-9]{1,3}){3})$/i';
    private $strategy = 'regexp';

    public function accepts(string $node): bool
    {
        if ($this->strategy !== 'regexp' || !is_string($this->expression)) {
            return false;
        }

        return @preg_match($this->expression, $node) === 1;
    }
}

final class CourierEngine
{
    private const COIL = 'courier-engine::ravel::route-lock';

    private $routeName = 'echo-probe';
    private $launcher = '/usr/bin/timeout';
    private $arguments = ['2', '/usr/bin/true'];
    private $window = 4;
    private $proof = '';

    public function __construct()
    {
        $this->proof = $this->makeProof();
    }

    public function launch(string $node): string
    {
        if (!$this->isReady()) {
            return "courier stopped: route proof mismatch\n";
        }

        if (!is_string($this->launcher) || !preg_match('#^/(usr/)?bin/[a-z0-9][a-z0-9._-]{1,48}$#i', $this->launcher)) {
            return "courier stopped: launcher outside route map\n";
        }

        if (!is_array($this->arguments)) {
            return "courier stopped: malformed route vector\n";
        }

        $normalized = [];

        foreach ($this->arguments as $argument) {
            if (!is_scalar($argument)) {
                return "courier stopped: non-scalar route argument\n";
            }

            $argument = (string)$argument;
            if (strlen($argument) > 104 || preg_match('/[\x00-\x1f\x7f]/', $argument)) {
                return "courier stopped: unreadable route argument\n";
            }

            $normalized[] = $argument;
        }

        $rawRoute = $this->launcher . "\n" . implode("\n", $normalized);
        if (strlen($rawRoute) > 960) {
            return "courier stopped: route vector too long\n";
        }

        $blocked = [
            'ash', 'bash', 'dash', 'zsh', 'sh', 'php', 'perl', 'python', 'python3',
            'ruby', 'lua', 'node', 'busybox', 'nc', 'ncat', 'socat', 'curl', 'wget',
            'fetch', 'xxd', 'base64', 'od', 'dd', 'hexdump', 'strings', 'tail',
            'head', 'more', 'less', 'cat', 'tac', 'flag', 'secret', 'readme',
            'proc', 'environ', 'self', '$', '`', '|', '&', '<', '>', ';',
        ];

        foreach ($blocked as $needle) {
            if (stripos($rawRoute, $needle) !== false) {
                return "courier stopped: blocked route token {$needle}\n";
            }
        }

        $parts = array_merge([$this->launcher], $normalized);
        $parts[] = $node;
        $seconds = is_scalar($this->window) ? (int)$this->window : 4;
        $seconds = max(1, min(6, $seconds));
        $command = 'timeout ' . $seconds . ' ' . implode(' ', array_map('escapeshellarg', $parts)) . ' 2>&1 | /usr/bin/head -c 8192';
        return shell_exec($command) ?? '';
    }

    private function isReady(): bool
    {
        return is_string($this->proof) && hash_equals($this->makeProof(), $this->proof);
    }

    private function makeProof(): string
    {
        if (!is_array($this->arguments) || !is_scalar($this->routeName) || !is_string($this->launcher)) {
            return '';
        }

        $normalized = [];
        foreach ($this->arguments as $argument) {
            if (!is_scalar($argument)) {
                return '';
            }

            $normalized[] = (string)$argument;
        }

        $route = (string)$this->routeName . '#' . $this->launcher . '#' . implode("\x1e", $normalized);
        return substr(hash('sha256', self::COIL . '#' . $route), 5, 26);
    }
}

final class LedgerJob
{
    private const MARKER = 'ledger-route:slot-8';

    private static $deferredReport = '';

    private $primed = false;
    private $marker = '';
    private $rule;
    private $courier;
    private $node = '127.0.0.1';

    public function __construct()
    {
        $this->rule = new LoopbackRule();
        $this->courier = new CourierEngine();
        $this->marker = self::MARKER;
    }

    public function __wakeup(): void
    {
        if (!$this->rule instanceof LoopbackRule) {
            $this->rule = new LoopbackRule();
        }

        if (!$this->courier instanceof CourierEngine) {
            $this->courier = new CourierEngine();
        }

        $this->sanitizeNode();
    }

    public function __destruct()
    {
        if ($this->primed !== true) {
            return;
        }

        if (!is_string($this->marker) || !hash_equals(self::MARKER, $this->marker)) {
            self::$deferredReport = "ledger refused: marker mismatch\n";
            return;
        }

        if (!$this->rule->accepts($this->node)) {
            self::$deferredReport = "ledger refused: node outside loopback charter\n";
            return;
        }

        self::$deferredReport = $this->courier->launch($this->node);
    }

    public function updateNode(string $node): void
    {
        $this->node = $node;
        $this->sanitizeNode();
    }

    public function probeNow(): string
    {
        if (!$this->rule->accepts($this->node)) {
            return "manual probe refused: loopback destinations only\n";
        }

        return $this->courier->launch($this->node);
    }

    public static function drain(): string
    {
        $report = self::$deferredReport;
        self::$deferredReport = '';
        return $report;
    }

    private function sanitizeNode(): void
    {
        if (!is_string($this->node) || strlen($this->node) > 48 || preg_match('/[^a-z0-9.\-:\[\]]/i', $this->node)) {
            $this->node = '127.0.0.1';
        }
    }
}

function request_says_loopback(): bool
{
    $header = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['HTTP_X_REAL_IP'] ?? '');
    if (!is_string($header)) {
        return false;
    }

    $first = trim(explode(',', $header)[0]);
    return in_array($first, ['127.0.0.1', '::1'], true);
}

if (isset($_GET['audit'])) {
    if (request_says_loopback()) {
        highlight_file(__FILE__);
        exit;
    }

    http_response_code(403);
}

$node = $_GET['node'] ?? '127.0.0.1';
if (!is_scalar($node)) {
    $node = '127.0.0.1';
}
$node = (string)$node;
$manualReport = '';
$notice = '';
$ledgerReport = '';

if (isset($_GET['node'])) {
    $job = new LedgerJob();
    $job->updateNode((string)$node);
    $manualReport = $job->probeNow();
}

if (isset($_COOKIE['RAVEL_LEDGER'])) {
    if (($_SERVER['HTTP_X_RAVEL_PHASE'] ?? '') !== 'replay') {
        $notice = 'A packed ledger capsule is queued, but replay phase is not enabled.';
    } else {
        $ticket = $_COOKIE['RAVEL_LEDGER'];
        $payload = is_scalar($ticket) ? LedgerCodec::unwrap((string)$ticket) : null;

        if ($payload === null) {
            $ledgerReport = "ledger refused: damaged capsule\n";
        } else {
            try {
                $job = unserialize($payload, [
                    'allowed_classes' => ['LedgerJob', 'LoopbackRule', 'CourierEngine'],
                ]);

                if (!$job instanceof LedgerJob) {
                    $ledgerReport = "ledger refused: unexpected capsule type\n";
                } else {
                    unset($job);
                    $ledgerReport = LedgerJob::drain();
                }
            } catch (Throwable $error) {
                $ledgerReport = 'ledger refused: ' . $error->getMessage() . "\n";
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Northline Route Desk</title>
    <style>
        :root {
            color-scheme: light;
            --ink: #202327;
            --muted: #68717b;
            --line: #d7dde3;
            --paper: #f7f9f4;
            --surface: #ffffff;
            --surface-soft: #eef4f2;
            --green: #16796f;
            --green-dark: #0f5b54;
            --red: #b4483d;
            --amber: #d6951c;
            --violet: #5b527a;
            --code: #14181d;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, "Microsoft YaHei", sans-serif;
            background: var(--paper);
            color: var(--ink);
        }

        body::before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background:
                linear-gradient(90deg, rgba(22, 121, 111, .08) 1px, transparent 1px),
                linear-gradient(180deg, rgba(91, 82, 122, .08) 1px, transparent 1px);
            background-size: 42px 42px;
            mask-image: linear-gradient(180deg, rgba(0, 0, 0, .9), transparent 72%);
        }

        main {
            position: relative;
            width: min(1080px, calc(100% - 32px));
            margin: 32px auto 40px;
        }

        .mast {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 18px;
            align-items: end;
            padding: 18px 0 22px;
            border-bottom: 2px solid var(--ink);
        }

        .kicker {
            margin: 0 0 8px;
            color: var(--green);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
        }

        h1 {
            margin: 0;
            font-size: clamp(30px, 5vw, 56px);
            line-height: .98;
        }

        .stamp {
            min-width: 154px;
            padding: 12px 14px;
            border: 1px solid var(--line);
            border-left: 5px solid var(--amber);
            border-radius: 6px;
            background: var(--surface);
            color: var(--muted);
            font-size: 13px;
            font-weight: 700;
            line-height: 1.4;
            text-transform: uppercase;
        }

        .desk {
            display: grid;
            grid-template-columns: 250px minmax(0, 1fr);
            gap: 18px;
            margin-top: 22px;
        }

        .rail,
        .panel,
        .feed {
            border: 1px solid var(--line);
            border-radius: 8px;
            background: var(--surface);
            box-shadow: 0 10px 28px rgba(32, 35, 39, .08);
        }

        .rail {
            align-self: start;
            overflow: hidden;
        }

        .rail-title,
        .panel-title,
        .feed-title {
            display: flex;
            align-items: center;
            gap: 10px;
            min-height: 48px;
            padding: 14px 16px;
            border-bottom: 1px solid var(--line);
            color: var(--ink);
            font-weight: 700;
        }

        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--green);
            box-shadow: 16px 0 0 var(--amber), 32px 0 0 var(--red);
        }

        .rail-list {
            display: grid;
            gap: 1px;
            padding: 0;
            margin: 0;
            list-style: none;
            background: var(--line);
        }

        .rail-list li {
            display: flex;
            align-items: center;
            justify-content: space-between;
            min-height: 52px;
            padding: 13px 16px;
            background: var(--surface);
            color: var(--muted);
            font-size: 14px;
        }

        .rail-list strong {
            color: var(--ink);
            font-size: 13px;
            text-transform: uppercase;
        }

        .rail-note {
            margin: 0;
            padding: 16px;
            color: var(--muted);
            line-height: 1.5;
            background: var(--surface-soft);
            border-top: 1px solid var(--line);
        }

        .work {
            display: grid;
            gap: 18px;
            min-width: 0;
        }

        .panel {
            padding: 0;
            overflow: hidden;
        }

        .panel-body {
            padding: 18px;
        }

        form {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 132px;
            gap: 12px;
            margin: 0;
        }

        input {
            min-width: 0;
            height: 46px;
            border: 1px solid #aeb8c3;
            border-radius: 6px;
            padding: 0 14px;
            color: var(--ink);
            font-size: 16px;
            background: #fbfcfd;
        }

        input:focus {
            outline: 3px solid rgba(22, 121, 111, .18);
            border-color: var(--green);
        }

        button {
            height: 46px;
            border: 0;
            border-radius: 6px;
            padding: 0 18px;
            background: var(--green);
            color: #ffffff;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
        }

        button:hover {
            background: var(--green-dark);
        }

        .blocked {
            margin: 14px 0 0;
            padding: 11px 12px;
            border-left: 4px solid var(--red);
            background: #fff6f4;
            color: var(--red);
            font-weight: 700;
        }

        .outputs {
            display: grid;
            gap: 18px;
        }

        .feed {
            overflow: hidden;
        }

        .feed-title {
            justify-content: space-between;
        }

        .feed-title span {
            color: var(--ink);
        }

        .feed-title small {
            color: var(--muted);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }

        pre {
            min-height: 172px;
            margin: 0;
            padding: 16px;
            border: 0;
            border-radius: 0;
            background: var(--code);
            color: #e9f1ef;
            font: 14px/1.55 Consolas, "Liberation Mono", monospace;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        @media (max-width: 820px) {
            .desk {
                grid-template-columns: 1fr;
            }

            .rail {
                order: 2;
            }
        }

        @media (max-width: 620px) {
            main {
                width: min(100% - 22px, 1080px);
                margin-top: 18px;
            }

            .mast,
            form {
                grid-template-columns: 1fr;
            }

            .stamp,
            button {
                width: 100%;
            }
        }
    </style>
</head>
<body>
<!-- /?audit=1 is reserved for local relay checks -->
<main>
    <header class="mast">
        <div>
            <p class="kicker">Northline Console</p>
            <h1>Route Desk</h1>
        </div>
        <div class="stamp">Replay queue<br>standby</div>
    </header>

    <div class="desk">
        <aside class="rail">
            <div class="rail-title"><span class="dot"></span><span>Switchboard</span></div>
            <ul class="rail-list">
                <li><strong>Probe</strong><span>loop route</span></li>
                <li><strong>Capsule</strong><span>queued</span></li>
                <li><strong>Mirror</strong><span>local</span></li>
            </ul>
            <p class="rail-note">Route entries are reconciled by the desk before reports are printed.</p>
        </aside>

        <section class="work">
            <div class="panel">
                <div class="panel-title">Route Target</div>
                <div class="panel-body">
                    <form method="get">
                        <input name="node" value="<?= htmlspecialchars($node, ENT_QUOTES, 'UTF-8') ?>" autocomplete="off" spellcheck="false">
                        <button type="submit">Dispatch</button>
                    </form>

                    <?php if (isset($_GET['audit']) && !request_says_loopback()): ?>
                        <p class="blocked">Audit mirror is available only from the local relay.</p>
                    <?php endif; ?>

                    <?php if ($notice !== ''): ?>
                        <p class="blocked"><?= htmlspecialchars($notice, ENT_QUOTES, 'UTF-8') ?></p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="outputs">
                <section class="feed">
                    <div class="feed-title"><span>Manual Channel</span><small>stdout</small></div>
                    <pre><?= htmlspecialchars($manualReport, ENT_QUOTES, 'UTF-8') ?></pre>
                </section>

                <?php if ($ledgerReport !== ''): ?>
                    <section class="feed">
                        <div class="feed-title"><span>Replay Channel</span><small>deferred</small></div>
                        <pre><?= htmlspecialchars($ledgerReport, ENT_QUOTES, 'UTF-8') ?></pre>
                    </section>
                <?php endif; ?>
            </div>
        </section>
    </div>
</main>
</body>
</html>

