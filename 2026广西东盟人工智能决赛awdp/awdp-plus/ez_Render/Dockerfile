# 题目名称：ez_Render  (Jinja2 模板预览服务)
# 基础镜像选择依据：Flask + Jinja2，pip 依赖 -> python:3.11-slim
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PORT=5008 RENDER_FLAG_FILE=/tmp/flag.txt
RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY src/ /app/

# Flag 存储路径：/tmp/flag.txt（服务启动时写入 FLAG 环境变量内容）
# 轮次刷新：平台每轮更新 FLAG 并重启容器，/tmp/flag.txt 随之更新
ENV FLAG=""

EXPOSE 5008
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5008/health',timeout=3)" || exit 1

CMD ["python", "-u", "/app/app.py"]
