# 题目名称：release_control_tower  (Release Control Tower)
# 基础镜像选择依据：纯 Python WSGI 服务，无系统级依赖 -> python:3.11-slim 体积小、启动快
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5006 \
    DB_PATH=/app/data/release_control_tower.db

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ /app/
RUN mkdir -p /app/data

# ---------------------------------------------------------------------------
# Flag 存储路径声明
#   * 运行期旗标：环境变量 FLAG（平台 FlagServer 每轮刷新并重启容器）
#   * 回退文件   ：/flag 或 /flag.txt（格式 flag{...}）
# 服务启动时将旗标写入受限 fixture 业务记录（详见 README 的 Flag 机制章节）
# ---------------------------------------------------------------------------
ENV FLAG=""

EXPOSE 5006
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD curl -fsS http://127.0.0.1:5006/health || exit 1

CMD ["python", "-u", "/app/app.py"]
