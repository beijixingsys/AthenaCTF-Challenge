# round3 web01 · Express SSRF（node 17.9.1 / libuv 1.43.0 / port 3456）
#
# 原题容器的 node 版本为 17.9.1（/hint 泄露），libuv 1.43.0。
# 本地复现用 node:18-alpine（原因：17-alpine 不在本机镜像缓存里，且本题利用链
# **不依赖** node 具体版本 —— 白名单是 WHATWG URL 语义，绕过完全靠 DNS）。
# 如需完全对齐版本，把 FROM 换成 node:17.9-alpine 即可。
FROM node:18-alpine

WORKDIR /app

# 第三方依赖（express / axios / cookie）
COPY src/package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# 原题下发的 index.js（归档用，不含在本容器执行）+ 复现变体 index.repro.js
# + 部署外壳 server.js + 内网 internal.js
COPY src/index.js src/index.repro.js src/server.js src/internal.js ./

# flag 注入方式：默认 /flag；可用环境变量 FLAG_FILE 指向别处
COPY flag /flag
RUN chmod 444 /flag

ENV PORT=3000
ENV FLAG_FILE=/flag
EXPOSE 3000

# 外网 app（0.0.0.0:3000） + 内网 app（127.0.0.1:3456）同容器
CMD ["sh", "-c", "node internal.js & exec node server.js"]
