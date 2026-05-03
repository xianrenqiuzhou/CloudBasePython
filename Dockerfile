# 使用官方 Python 运行时作为基础镜像
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖（SQLite 需要）
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 设置 pip 镜像源（加速下载）
RUN pip config set global.index-url https://mirrors.cloud.tencent.com/pypi/simple/ \
    && pip config set global.trusted-host mirrors.cloud.tencent.com

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建数据目录（SQLite 持久化）
RUN mkdir -p /app/data

# 暴露端口（CloudBase Run 默认 8080）
EXPOSE 8080

# 环境变量
ENV PORT=8080
ENV DB_DIR=/app/data
ENV ALLOW_ORIGINS=*

# 启动命令
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
