<?php
session_start();

$ftp_server = '';
$ftp_user   = '';
$ftp_pass   = '';
$connected  = false;
$msg        = '';
$msg_type   = '';
$msg_tag    = 'p';
$items      = '';
$conn       = null;

/* ---------------- 断开连接 ---------------- */
if (isset($_GET['disconnect'])) {
    $_SESSION = array();
    session_destroy();
    header('Location: ftp.php');
    exit;
}

/* ---------------- 连接 FTP ---------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ftp_server'])) {
    $ftp_server = $_POST['ftp_server'];
    $ftp_user   = isset($_POST['ftp_user']) ? $_POST['ftp_user'] : '';
    $ftp_pass   = isset($_POST['ftp_pass']) ? $_POST['ftp_pass'] : '';

    $conn = @ftp_connect($ftp_server, 21, 10);
    if ($conn && @ftp_login($conn, $ftp_user, $ftp_pass)) {
        ftp_pasv($conn, true);
        $_SESSION['ftp_server'] = $ftp_server;
        $_SESSION['ftp_user']   = $ftp_user;
        $_SESSION['ftp_pass']   = $ftp_pass;
        $connected = true;
        $msg       = "\xE2\x9C\x85 已连接到 " . $ftp_server . "，用户：" . $ftp_user;
        $msg_type  = 'success';
        $msg_tag   = 'div';
    } else {
        $msg      = "\xE2\x9D\x8C 连接失败，请检查服务器地址与账号密码";
        $msg_type = 'error';
    }
} elseif (isset($_SESSION['ftp_server'])) {
    $ftp_server = $_SESSION['ftp_server'];
    $ftp_user   = $_SESSION['ftp_user'];
    $ftp_pass   = $_SESSION['ftp_pass'];

    $conn = @ftp_connect($ftp_server, 21, 10);
    if ($conn && @ftp_login($conn, $ftp_user, $ftp_pass)) {
        ftp_pasv($conn, true);
        $connected = true;
    } else {
        $_SESSION = array();
        $msg      = "\xE2\x9D\x8C 会话已失效，请重新连接";
        $msg_type = 'error';
    }
}

/* ---------------- 当前目录（默认 FTP 根目录） ---------------- */
$dir    = isset($_GET['dir']) ? $_GET['dir'] : '.';
$prefix = ($dir === '.' || $dir === '') ? '' : rtrim($dir, '/') . '/';

if ($connected) {
    /* 上传：字段名固定为 upload，目标是当前列出的目录 */
    if (isset($_FILES['upload']) && $_FILES['upload']['error'] === UPLOAD_ERR_OK
        && is_uploaded_file($_FILES['upload']['tmp_name'])) {
        $name   = basename($_FILES['upload']['name']);
        $target = $prefix . $name;
        if (@ftp_put($conn, $target, $_FILES['upload']['tmp_name'], FTP_BINARY)) {
            $msg      = "\xE2\x9C\x85 文件 " . $name . " 上传成功";
            $msg_type = 'success';
        } else {
            $msg      = "\xE2\x9D\x8C 文件上传失败";
            $msg_type = 'error';
        }
    }

    /* 下载：从 FTP 服务器读取文件并直接回显内容 */
    if (isset($_GET['download'])) {
        $remote = $_GET['download'];
        $tmp    = tempnam(sys_get_temp_dir(), 'ftpd');
        if (ftp_get($conn, $tmp, $remote, FTP_BINARY)) {
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($remote) . '"');
            readfile($tmp);
            unlink($tmp);
            exit;
        }
        @unlink($tmp);
        $msg      = "\xE2\x9D\x8C 下载失败，请检查权限或文件名";
        $msg_type = 'error';
    }

    /* 列目录 */
    $files = ftp_nlist($conn, $dir === '' ? '.' : $dir);
    if (is_array($files)) {
        foreach ($files as $f) {
            $name = basename($f);
            if ($name === '.' || $name === '..') {
                continue;
            }
            $full = $prefix . $name;
            if (@ftp_chdir($conn, $full)) {
                /* 是目录 */
                $items .= "<li><a href='?dir=" . urlencode($full) . "'>" . htmlspecialchars($full) . "</a>";
                ftp_chdir($conn, $dir);
                $items .= "</li>";
            } else {
                /* 是文件 */
                $items .= "<li>" . htmlspecialchars($full)
                        . " [<a href='?download=" . urlencode('/' . $full) . "'>下载</a>]</li>";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PHP FTP 网页工具</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f2f4f8; margin:0; padding:20px;}
        h2 { margin:0; }
        form { margin-bottom:20px; background:#fff; padding:15px; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.1);}
        input[type="text"], input[type="password"], input[type="file"] { padding:6px 8px; margin:5px 0; width:250px; border:1px solid #ccc; border-radius:4px;}
        button { background:#4CAF50; color:#fff; padding:6px 14px; border:none; border-radius:4px; cursor:pointer;}
        button:hover { background:#45a049;}
        ul { list-style:none; padding:0; }
        li { background:#fff; margin:5px 0; padding:8px 12px; border-radius:6px; box-shadow:0 1px 3px rgba(0,0,0,0.08);}
        a { text-decoration:none; color:#007BFF;}
        a:hover { text-decoration:underline;}
        .msg { margin:10px 0; padding:8px 12px; border-radius:6px;}
        .success { background:#d4edda; color:#155724;}
        .error { background:#f8d7da; color:#721c24;}
        .directory { font-weight:bold; color:#333;}
        .topbar { background:#4CAF50; color:#fff; padding:12px 20px; margin:-20px -20px 20px -20px; border-bottom:4px solid #388E3C; display:flex; justify-content:space-between; align-items:center;}
        .disconnect { background:#f44336; padding:6px 12px; border-radius:4px; color:#fff; text-decoration:none;}
        .disconnect:hover { background:#d32f2f;}
    </style>
</head>
<body>
<div class="topbar">
    <h2>PHP FTP 网页工具</h2>
    <?php if ($connected) { echo '<a class="disconnect" href="?disconnect=1">断开连接</a>'; } ?>
    </div>

<form method="post">
    <label>FTP 服务器：
        <input type="text" name="ftp_server" value="<?php echo htmlspecialchars($ftp_server); ?>" required>
    </label><br><br>
    <label>用户名：
        <input type="text" name="ftp_user" value="<?php echo htmlspecialchars($ftp_user); ?>" required>
    </label><br><br>
    <label>密码：
        <input type="password" name="ftp_pass" value="<?php echo htmlspecialchars($ftp_pass); ?>">
    </label><br><br>
    <button type="submit">连接 FTP</button>
</form>

<?php
if ($msg !== '') {
    echo "<" . $msg_tag . " class='msg " . $msg_type . "'>" . htmlspecialchars($msg) . "</" . $msg_tag . ">\n";
}
if ($connected) {
?>
    <h3>当前目录: <span class="directory"><?php echo htmlspecialchars($dir); ?></span></h3>

    <!-- 上传文件表单 -->
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="upload" required>
        <button type="submit">上传</button>
    </form>

    <ul>
    <?php echo $items; ?>    </ul>
<?php
}
?>
</body>
</html>
