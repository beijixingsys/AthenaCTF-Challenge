/**
 * round3 web01 · 内网 Express（非下发源码，按原题行为重建）
 *
 * 原题 index.js 里 `internalApp.listen(3456)` 只监听回环，/secret 返回 "flag_is_here"。
 * 重建版把 flag 从 /flag 读出后返回，使本地部署可以直接验证利用链。
 * 除 flag 来源外，路由与监听行为与原题一致。
 */
const express = require('express');
const fs = require('fs');

const FLAG_FILE = process.env.FLAG_FILE || '/flag';
const internalApp = express();

internalApp.get('/secret', (req, res) => {
  let flag = 'flag_is_here';
  try {
    flag = fs.readFileSync(FLAG_FILE, 'utf8').trim();
  } catch (e) {
    console.log('[internal] read flag failed:', e.message);
  }
  res.send(flag);
});

// 注意：原题只监听回环（127.0.0.1）——这正是本题"只能从容器内部访问"的前提。
internalApp.listen(3456, '127.0.0.1', () => {
  console.log('[internal] express listening on 127.0.0.1:3456');
});
