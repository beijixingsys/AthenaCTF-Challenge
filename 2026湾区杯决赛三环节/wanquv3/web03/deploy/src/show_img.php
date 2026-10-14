<?php
if(!isset($_GET['img_url'])){
    die("no");
}
$img_url = base64_decode($_GET['img_url']);

// 关键字黑名单（php，大小写不敏感）—— 实测它比字符黑名单更早命中：
// ftp://127.0.0.1/show_img_v1.0.php -> 你想干嘛（12B），而 a_b -> 不要这样子哦（18B）
if (stripos($img_url, "php") !== false) {
    die("你想干嘛");
}

// 危险字符黑名单（保持原版逐字符 strpos 的判定方式；下划线只在这一层被拦）
$blacklist = array(
    "'", "\"", ";", "|", "&", "`", "\$", "(", ")", "{", "}", "<", ">",
    " ", "\t", "\n", "\r", "?", "%", "#", "\\", "=", "*", "!", "-", "_",
    ",", "+", "[", "]"
);
foreach ($blacklist as $c) {
    if (strpos($img_url, $c) !== false) {
        die("不要这样子哦");
    }
}

// 允许 HTTP 与本机 FTP。FTP 必须配合 parse_url 的本地 host 白名单；
// 这让第二个 FTP 应用上传到 pub/ 的 .phtml 能被 wget 拉进 temp_img 并由 Apache 执行。
// 外部主机、其他协议仍由下方 host/scheme 检查拒绝。
if (stripos($img_url, "http://") !== 0 && stripos($img_url, "ftp://") !== 0) {
    die("目前只能加载本地图库……");
}

// 解题链：FTP 匿名上传 /pub/shell.phtml -> 本接口用 wget 下载到 temp_img/ -> Apache 执行并读 /flag。

// 只允许加载本地图库（parse_url 的 host 白名单）
$host = parse_url($img_url, PHP_URL_HOST);
if ($host !== '127.0.0.1' && $host !== 'localhost') {
    die("目前只能加载本地图库……");
}

$path = parse_url($img_url, PHP_URL_PATH);
$img_name = pathinfo($path, PATHINFO_BASENAME);

system("wget  -P temp_img  '".$img_url."'");
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>图片展示</title>
    <style>
        :root {
            --primary-color: #4a6baf;
            --secondary-color: #6c757d;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            color: #333;
        }
        
        header {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 0;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            margin: 0;
            font-size: 2.2em;
            font-weight: 500;
        }
        
        .container {
            flex: 1;
            width: 90%;
            max-width: 900px;
            margin: 30px auto;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        
        .image-container {
            width: 100%;
            max-width: 800px;
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            margin-bottom: 30px;
        }
        
        .image-container img {
            width: 100%;
            height: auto;
            display: block;
        }
        
        .back-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            color: white;
            padding: 12px 30px;
            border-radius: 50px;
            cursor: pointer;
            font-size: 1.1em;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-decoration: none;
            display: inline-block;
            margin-top: 20px;
        }
        
        .back-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
        }
        
        .back-btn:active {
            transform: translateY(1px);
        }
        
        .image-info {
            background-color: white;
            width: 100%;
            max-width: 800px;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            margin-bottom: 30px;
        }
        
        .image-info h2 {
            color: var(--primary-color);
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        
        footer {
            width: 100%;
            background-color: #2c3e50;
            color: white;
            text-align: center;
            padding: 15px 0;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 1.8em;
            }
            
            .container {
                width: 95%;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>图片展示</h1>
    </header>
    
    <div class="container">
        
        <div class="image-container">
            <img src="temp_img/<?=$img_name;?>" alt="展示图片">
        </div>
        
        <a href="index.html" class="back-btn">返回首页</a>
    </div>
    
    <footer>
        © 2025 图片导航系统
    </footer>
</body>
</html>
