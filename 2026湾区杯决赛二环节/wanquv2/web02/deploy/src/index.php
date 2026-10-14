<?php
// 文件管理系统 —— 登录入口
// 复现自 2026 湾区杯决赛 环节二 web02（原始实现）
session_start();

$error = '';
$posted_user = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $posted_user = isset($_POST['user'])   ? $_POST['user']   : '';
    $passwd      = isset($_POST['passwd']) ? $_POST['passwd'] : '';

    // 硬编码弱口令
    if ($posted_user === 'user' && $passwd === '123') {
        // 登录成功 —— 原题逻辑：302 到 /demo.php
        header('Location: /demo.php');
        exit;
    }
    $error = '用户名或密码错误';
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <!-- user/123 -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理系统</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        body {
            background-color: #f5f5f5;
            padding: 20px;
        }
        .login-box {
            max-width: 420px;
            margin: 80px auto;
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .login-box h1 {
            font-size: 1.5rem;
            margin-bottom: 24px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h1><i class="fas fa-folder-open me-2"></i>文件管理系统</h1>
        <?php if ($error !== ''): ?>
            <div class="alert alert-danger py-2"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <form method="post" action="index.php">
            <div class="mb-3">
                <label class="form-label" for="user">用户名</label>
                <input type="text" class="form-control" id="user" name="user" value="<?php echo htmlspecialchars($posted_user, ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>
            <div class="mb-3">
                <label class="form-label" for="passwd">密码</label>
                <input type="password" class="form-control" id="passwd" name="passwd" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">登录</button>
        </form>
    </div>
</body>
</html>
