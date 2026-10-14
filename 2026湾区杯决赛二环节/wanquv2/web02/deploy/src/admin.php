<?php
// admin.php —— 真正的「文件管理系统」后台
// 复现自 2026 湾区杯决赛 环节二 web02（原始实现）
//   * HTTP Basic Auth（弱口令 admin:admin123）
//   * 上传：扩展名白名单 jpg/jpeg/png/zip + 内容嗅探必须与扩展名一致
//     - 图片走 finfo + getimagesize
//     - zip 走魔数 PK\x03\x04
//     - 目标文件名过 basename() 且只允许 [A-Za-z0-9._-]
//     - 落到 /var/www/uploads/，不自动解压；该目录已禁用 PHP 解析
//   * ?delete=<path> 完全未过滤：$dir . $_GET['delete'] 递归删除（只能破坏，读不出数据）

$AUTH_USER = 'admin';
$AUTH_PASS = 'admin123';

$auth_user = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
$auth_pass = isset($_SERVER['PHP_AUTH_PW'])   ? $_SERVER['PHP_AUTH_PW']   : '';

if ($auth_user !== $AUTH_USER || $auth_pass !== $AUTH_PASS) {
    header('WWW-Authenticate: Basic realm="File Management System"');
    http_response_code(401);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Authentication required';
    exit;
}

$UPLOAD_DIR   = '/var/www/uploads';
$ALLOWED_EXT  = array('jpg', 'jpeg', 'png', 'zip');
$message      = '';
$message_type = 'success';

function h($s) {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

// ---------------------------------------------------------------------------
// 递归删除：与原题一致 —— 目录递归 rmdir，文件 unlink；路径不做任何过滤。
// ---------------------------------------------------------------------------
function rrmdir($path) {
    if (is_dir($path) && !is_link($path)) {
        $items = @scandir($path);
        if ($items !== false) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
                rrmdir($path . '/' . $item);
            }
        }
        @rmdir($path);          // rmdir('/var/www/html')  /  rmdir('/var/www/uploads/..')
    } else {
        @unlink($path);
    }
}

// ---------------------------------------------------------------------------
// ?delete= —— 完全未过滤（原题如此）："/var/www/uploads/" . $_GET['delete']
// ---------------------------------------------------------------------------
if (isset($_GET['delete'])) {
    $delete_target = '/var/www/uploads/' . $_GET['delete'];
    rrmdir($delete_target);
    $message      = '已删除: ' . $delete_target;
    $message_type = 'warning';
}

// ---------------------------------------------------------------------------
// 上传处理
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $f = $_FILES['file'];

    if (!isset($f['error']) || is_array($f['error'])) {
        $message      = '上传参数非法';
        $message_type = 'danger';
    } elseif ($f['error'] !== UPLOAD_ERR_OK) {
        $message      = '上传失败，错误码: ' . $f['error'];
        $message_type = 'danger';
    } else {
        // basename() 处理，去掉任何目录成分
        $orig = basename($f['name']);

        if (!preg_match('/^[A-Za-z0-9._-]+$/', $orig)) {
            $message      = '上传失败：文件名只允许字母、数字、点、下划线、连字符';
            $message_type = 'danger';
        } elseif (!preg_match('/\.([A-Za-z0-9]+)$/', $orig, $m)) {
            $message      = '上传失败：文件必须有扩展名';
            $message_type = 'danger';
        } elseif (!in_array(strtolower($m[1]), $ALLOWED_EXT, true)) {
            $message      = '上传失败：只允许 ' . implode(' / ', $ALLOWED_EXT) . ' 格式';
            $message_type = 'danger';
        } else {
            $ext = strtolower($m[1]);
            $ok  = false;

            // 内容嗅探：必须与扩展名一致
            $mime = '';
            if (class_exists('finfo')) {
                $fi = @finfo_open(FILEINFO_MIME_TYPE);
                if ($fi) {
                    $mime = @finfo_file($fi, $f['tmp_name']);
                    @finfo_close($fi);
                }
            }

            if ($ext === 'jpg' || $ext === 'jpeg') {
                $ok = ($mime === 'image/jpeg') && (@getimagesize($f['tmp_name']) !== false);
            } elseif ($ext === 'png') {
                $ok = ($mime === 'image/png') && (@getimagesize($f['tmp_name']) !== false);
            } elseif ($ext === 'zip') {
                $sig = @file_get_contents($f['tmp_name'], false, null, 0, 4);
                $ok  = ($sig === "PK\x03\x04" || $sig === "PK\x05\x06");
            }

            if (!$ok) {
                $message      = '上传失败：文件内容与扩展名不匹配（检测类型: ' . h($mime) . '）';
                $message_type = 'danger';
            } else {
                $dest = $UPLOAD_DIR . '/' . $orig;
                if (@move_uploaded_file($f['tmp_name'], $dest)) {
                    @chmod($dest, 0644);
                    $message = '上传成功: ' . $orig;
                    // 原题：压缩包不自动解压
                } else {
                    $message      = '上传失败：写入 ' . $UPLOAD_DIR . ' 出错';
                    $message_type = 'danger';
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 文件列表（服务端渲染进 <tbody>）
// ---------------------------------------------------------------------------
$files = array();
if (is_dir($UPLOAD_DIR)) {
    $names = @scandir($UPLOAD_DIR);
    if ($names !== false) {
        foreach ($names as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $p = $UPLOAD_DIR . '/' . $name;
            if (!is_file($p)) {
                continue;
            }
            $files[] = array(
                'name'  => $name,
                'size'  => @filesize($p),
                'mtime' => @filemtime($p),
            );
        }
    }
}

function human_size($bytes) {
    if ($bytes === false || $bytes === null) {
        return '未知';
    }
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    if ($bytes < 1024 * 1024) {
        return round($bytes / 1024, 1) . ' KB';
    }
    return round($bytes / 1024 / 1024, 2) . ' MB';
}

function file_icon($name) {
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if ($ext === 'zip') {
        return 'fa-file-archive';
    }
    if (in_array($ext, array('jpg', 'jpeg', 'png'), true)) {
        return 'fa-file-image';
    }
    return 'fa-file';
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理系统</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        .file-icon {
            width: 24px;
            margin-right: 8px;
        }
        .file-size {
            white-space: nowrap;
        }
        .action-buttons .btn {
            margin-right: 5px;
        }
        .upload-area {
            border: 2px dashed #ccc;
            padding: 30px;
            text-align: center;
            margin-bottom: 20px;
            cursor: pointer;
            transition: all 0.3s;
            border-radius: 8px;
            background-color: #f8f9fa;
        }
        .upload-area:hover {
            border-color: #0d6efd;
            background-color: rgba(13, 110, 253, 0.05);
        }
        #fileInfo p {
            word-break: break-all;
            margin: 10px 0;
            padding: 8px;
            background-color: #f1f1f1;
            border-radius: 4px;
        }
        #changeFile {
            margin-top: 10px;
        }
        .card-header {
            font-weight: bold;
        }
        .table th {
            font-weight: 600;
        }
        .user-info {
            position: absolute;
            top: 20px;
            right: 20px;
            display: flex;
            align-items: center;
        }
        .container {
            position: relative;
            padding-top: 60px;
            background-color: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
            margin-top: 30px;
            margin-bottom: 30px;
        }
        body {
            background-color: #f5f5f5;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h1 class="mb-4"><i class="fas fa-folder-open me-2"></i>文件管理系统</h1>
        <?php if ($message !== ''): ?>
            <div class="alert alert-<?php echo h($message_type); ?> py-2"><?php echo h($message); ?></div>
        <?php endif; ?>

        
        <!-- 功能区 -->
        <div class="card mb-4 shadow-sm">
            <div class="card-header bg-primary text-white">
                <i class="fas fa-tools me-2"></i> 功能区
            </div>
            <div class="card-body">
                <!-- 搜索功能 -->
                <div class="row mb-3">
                    <div class="col-md-6">
                        <div class="input-group">
                            <input type="text" id="searchInput" class="form-control" placeholder="搜索文件...">
                            <button class="btn btn-outline-primary" type="button" id="searchButton">
                                <i class="fas fa-search me-1"></i> 搜索
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- 上传功能 -->
                <form method="post" enctype="multipart/form-data" class="mb-4">
                    <div class="upload-area" id="uploadArea">
                        <div id="uploadContent">
                            <i class="fas fa-cloud-upload-alt fa-3x mb-3 text-muted"></i>
                            <p class="text-muted">点击或拖拽文件到此处上传</p>
                            <input type="file" name="file" id="fileInput" class="d-none">
                            <button type="button" class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                                <i class="fas fa-upload me-1"></i> 选择文件
                            </button>
                        </div>
                        <div id="fileInfo" class="d-none">
                            <i class="fas fa-file-alt fa-3x mb-3 text-primary"></i>
                            <p id="fileName" class="fw-bold"></p>
                            <button type="button" class="btn btn-outline-danger btn-sm" id="changeFile">
                                <i class="fas fa-exchange-alt me-1"></i> 更换文件
                            </button>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-check me-1"></i> 确认上传
                    </button>
                                    </form>
                
                            </div>
        </div>
        
        <!-- 文件列表 -->
        <div class="card shadow-sm">
            <div class="card-header bg-success text-white">
                <i class="fas fa-list me-2"></i> 文件列表
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-striped table-hover mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Name</th>
                                <th>Size</th>
                                <th>Modified</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
<?php if (count($files) === 0): ?>
    <tr>
        <td colspan="4" class="text-center py-4">没有文件</td>
    </tr>
<?php else: ?>
<?php foreach ($files as $item): ?>
    <tr>
        <td><i class="fas <?php echo file_icon($item['name']); ?> file-icon"></i><?php echo h($item['name']); ?></td>
        <td class="file-size"><?php echo human_size($item['size']); ?></td>
        <td><?php echo $item['mtime'] ? date('Y-m-d H:i:s', $item['mtime']) : '-'; ?></td>
        <td class="action-buttons">
            <a class="btn btn-sm btn-primary" href="download.php?file=<?php echo urlencode($item['name']); ?>"><i class="fas fa-download me-1"></i>下载</a>
            <a class="btn btn-sm btn-danger" href="?delete=<?php echo urlencode($item['name']); ?>" onclick="return confirm('确认删除该文件？');"><i class="fas fa-trash me-1"></i>删除</a>
        </td>
    </tr>
<?php endforeach; ?>
<?php endif; ?>
</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script src="js/bootstrap.bundle.min.js"></script>
    <script>
        // 文件选择后的处理
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const file = this.files[0];
            if (file) {
                document.getElementById('uploadContent').classList.add('d-none');
                document.getElementById('fileInfo').classList.remove('d-none');
                document.getElementById('fileName').textContent = file.name;
            }
        });

        // 更换文件按钮
        document.getElementById('changeFile').addEventListener('click', function() {
            document.getElementById('fileInput').value = '';
            document.getElementById('uploadContent').classList.remove('d-none');
            document.getElementById('fileInfo').classList.add('d-none');
        });

        // 拖拽上传
        const uploadArea = document.getElementById('uploadArea');
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#0d6efd';
            uploadArea.style.backgroundColor = 'rgba(13, 110, 253, 0.1)';
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = '#ccc';
            uploadArea.style.backgroundColor = '';
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#ccc';
            uploadArea.style.backgroundColor = '';
            
            const fileInput = document.getElementById('fileInput');
            fileInput.files = e.dataTransfer.files;
            
            // 触发change事件
            const event = new Event('change');
            fileInput.dispatchEvent(event);
        });

        // 搜索功能
        document.getElementById('searchButton').addEventListener('click', function() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const fileName = row.querySelector('td:first-child').textContent.toLowerCase();
                if (fileName.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>
