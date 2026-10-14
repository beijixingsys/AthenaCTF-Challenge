/**
 * round3 web01 · 部署用外壳（非比赛源码）
 *
 * 原题只下发 index.js（Express Router），外壳由主办方提供。这里补一个最小外壳，
 * 使 `GET /?url=` 与 `GET /hint` 都落在根路径上（与比赛容器实测行为一致）。
 *
 * 用法: node server.js [port]     # 默认 3000，对外暴露
 */
const express = require('express');
// 用复现变体（原版 index.js 自带 internalApp.listen(3456)，单容器里会抢端口，
// 见 index.repro.js 顶部说明；附件原版逐字节保留在 ../attachments/index.js）
const router = require('./index.repro');

const app = express();
app.use('/', router);

const PORT = parseInt(process.argv[2] || process.env.PORT || '3000', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[outer] express listening on 0.0.0.0:${PORT}`);
  console.log(`[outer] node=${process.versions.node} libuv=${process.versions.uv}`);
});
