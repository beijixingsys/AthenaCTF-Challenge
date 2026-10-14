<?php
/**
 * round2 web03 "i like escape" · /var/www/html/algorithm.php
 *
 * ★ 本题核心考点文件：自研"加密"会话 cookie。
 *
 * 密文格式（外层）:  base64( base64($ct) . '::' . bin2hex($iv) )
 *
 * 关键性质（出题人故意留下的破绽）:
 *   1) 使用 STREAM 模式，且 **不做 PKCS#7 填充**（OPENSSL_ZERO_PADDING）：
 *          strlen($ct) === strlen($pt)          ← 密文长度恒等于明文长度
 *      这不是 CBC：CBC 一定带 PKCS#7（长度会向上取整到 16 的倍数）。
 *   2) ★ 必须是 **OFB/CTR** 而不能是 CFB：
 *          OFB/CTR 的 keystream 只由 (key, iv) 决定，与明文/密文**都无关**
 *              ct = pt XOR ks        →   ks = pt XOR ct
 *          而 CFB 的 keystream 反馈的是**密文**，一旦伪造的密文比原密文短，
 *          第 1 个分组之后的 keystream 就与原样本不同（实测：伪造 49 字节时
 *          前 16 字节正确、之后全是乱码）。
 *          ⇒ 只有 OFB/CTR 才能做到"已知明文恢复 keystream 后可伪造任意等长明文"。
 *   3) 没有 MAC / 没有 HMAC → 密文可任意伪造（无完整性保护）。
 *
 * 攻击者路径：POST username=<64 个已知字符> 到 index.php，index.php 用一个
 * 加密预言机把 serialize(new Users($username,$passwd,'True')) 加密后回吐在
 * Set-Cookie 里 —— 明文完全可预测 ⇒ 直接恢复 164 字节 keystream。
 */

class Cipher
{
    /** 会话密钥（比赛环境为 config.php 内硬编码的随机串，此处为等价重建值） */
    private $key = 'i_like_escape_2026';

    /** 分组大小：stream 模式下只用于展示，不参与填充 */
    private $block_size = 16;

    /** 初始化向量长度 */
    private $iv_size = 16;

    /**
     * ★ 流模式算法名：必须是 OFB 或 CTR（keystream 与明文/密文无关）。
     * 用 CFB 会让"已知明文恢复 keystream"在短 payload 上失效，见文件头说明。
     */
    private $algorithm = 'aes-128-ofb';

    public function getIvSize()
    {
        return $this->iv_size;
    }

    /**
     * 加密：返回 base64($ct) . '::' . bin2hex($iv)
     *
     * 注意 OPENSSL_ZERO_PADDING | OPENSSL_RAW_DATA：
     *   - ZERO_PADDING 让 openssl 不再追加 PKCS#7
     *   - 因此 strlen($ct) === strlen($pt)（流模式 + 无填充的必然结果）
     */
    public function encrypt($plaintext)
    {
        $iv = openssl_random_pseudo_bytes($this->iv_size);
        $ct = openssl_encrypt(
            $plaintext,
            $this->algorithm,
            $this->key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        return base64_encode($ct) . '::' . bin2hex($iv);
    }

    /**
     * 解密：输入 base64($ct) . '::' . hex(iv)
     *   容错：允许 base64 缺少 '=' 填充（外层 base64 会把 '=' 变 %3D，且内层
     *   padding 常在字符串拼接/URL 编码过程里被吃掉）
     */
    public function decrypt($payload)
    {
        if (strpos($payload, '::') === false) {
            return false;
        }
        list($ct_b64, $iv_hex) = explode('::', $payload, 2);

        $ct_b64 = trim($ct_b64);
        $ct_b64 .= str_repeat('=', (4 - strlen($ct_b64) % 4) % 4);
        $ct = base64_decode($ct_b64, true);
        $iv = @hex2bin(trim($iv_hex));

        if ($ct === false || $iv === false || strlen($iv) !== $this->iv_size) {
            return false;
        }

        $pt = openssl_decrypt(
            $ct,
            $this->algorithm,
            $this->key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        return $pt === false ? false : $pt;
    }
}
