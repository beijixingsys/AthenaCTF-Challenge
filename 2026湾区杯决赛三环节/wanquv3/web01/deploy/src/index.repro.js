/**
 * round3 web01 · **复现用变体**（原版见 ../attachments/index.js，字节完全一致）
 *
 * 为什么需要变体：原版 index.js 里同时有
 *      const internalApp = express();
 *      internalApp.get('/secret', ...); internalApp.listen(3456);
 * 即外网 router 与内网 app **在同一进程**、只监听回环 —— 在单容器复现里
 * 要么内网服务不可达，要么与 internal.js 抢 3456 端口（实测 EADDRINUSE）。
 *
 * 本变体只做两处等价改动，**漏洞语义零改动**：
 *   1) 删掉 internalApp 那段（交给 internal.js，listen 127.0.0.1:3456）
 *   2) /secret 的 body 由 "flag_is_here" 改成读 FLAG_FILE
 * 白名单、/hint、axios 发请求等全部与原版逐字一致。
 */
const { Router } = require('express');
var express = require('express');
var router = express.Router();
const axios = require('axios');
const { parse } = require('cookie');
const fs = require('fs');


router.get('/', async (req, res) => {
    try {
        const url = req.query.url;
        const parsedUrl = new URL(url);
        if (parsedUrl.hostname.endsWith('.baidu.com')) {
            const { data } = await axios.get(url, { timeout: 3000 });
            res.send(data);
        } else {
            res.status(400).send("Invalid URL<!--endsWith('.baidu.com')-->");
        }
    } catch (e) {
        console.log(e);
        res.status(400).send('Could not access, check the url param plz');
    }
});

router.get('/hint', async (req, res) => {
    res.send("hint is here, and port 3456 have good thing<br \>" + 
    "<!--the libuv version is:" + process.versions.uv + "-->" +
   "<!--the node version is:" + process.versions.node + "-->" + "and if you are really sure about the answer, then maybe you could try more times~")
});

module.exports = router;
