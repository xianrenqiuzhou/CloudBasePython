FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制代码
COPY main.py .

# 暴露服务端口（云托管平台会读取此端口配置探针）
EXPOSE 8000

# 通过环境变量 PORT 支持云托管平台动态端口注入
ENV PORT=8000

# 启动命令
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}
