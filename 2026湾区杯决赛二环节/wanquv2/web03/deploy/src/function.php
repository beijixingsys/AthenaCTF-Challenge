<?php
/**
 * round2 web03 "i like escape" · /var/www/html/function.php
 *
 * 反序列化 gadget：没有任何 allowed_classes 白名单，魔术方法直接干危险事。
 *
 *   class FILE  : __destruct() → echo file_get_contents($filename)      ← 任意文件读
 *   class Date  : __destruct() → system($cmd)                            ← 命令执行
 *   class Users : 正常的登录对象（index.php 会 serialize 它）
 *   class admin : 持有 root 属性；把 root 设成 Date 对象即可触发 RCE 链
 *
 * 利用形态（由 algorithm.php 的 cookie 伪造把对象塞进 unserialize）：
 *   任意读：O:4:"FILE":1:{s:8:"filename";s:5:"/flag";}
 *   RCE   ：O:5:"admin":2:{s:5:"admin";N;s:4:"root";O:4:"Date":1:{s:3:"cmd";s:N:"...";}}
 */

class FILE
{
    public $filename;

    public function __construct($filename = '')
    {
        $this->filename = $filename;
    }

    public function __destruct()
    {
        // ★ 任意文件读：$filename 完全来自反序列化数据
        if ($this->filename) {
            echo @file_get_contents($this->filename);
        }
    }
}

class Date
{
    public $cmd;

    public function __construct($cmd = '')
    {
        $this->cmd = $cmd;
    }

    public function __destruct()
    {
        // ★ 命令执行
        if ($this->cmd) {
            system($this->cmd);
        }
    }
}

class Users
{
    private $username;
    private $passwd;
    public $status = 'False';

    public function __construct($username, $passwd, $status = 'True')
    {
        $this->username = $username;
        $this->passwd = $passwd;
        $this->status = $status;
    }

    public function isLogin()
    {
        return $this->status === 'True';
    }
}

class admin
{
    public $admin;
    public $root;

    /**
     * 链条说明：admin 本身不做危险操作，它的作用只是持有 $root。
     * 当反序列化生成的 admin 对象被销毁时，PHP 会连带销毁它持有的
     * Date 对象 → Date::__destruct() → system($cmd)。
     * 这就是 payload 里写 `admin -> root(Date)` 的原因。
     */
    public function __destruct()
    {
        // 无操作：真正的执行落在 Date::__destruct()
    }
}
