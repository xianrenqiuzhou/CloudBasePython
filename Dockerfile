# 使用官方 Python 轻量级镜像（alpine 版本体积小，冷启动快）
FROM python:3-alpine

# 设置时区为上海（您的业务场景需要）
RUN apk add tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo Asia/Shanghai > /etc/timezone

# 设置工作目录
ENV APP_HOME /app
WORKDIR $APP_HOME

# 拷贝项目文件
COPY . .

# 环境变量配置
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DB_PATH=/app/mms_users.db

# 安装依赖（使用腾讯云镜像源加速）
RUN pip config set global.index-url http://mirrors.cloud.tencent.com/pypi/simple && \
    pip config set global.trusted-host mirrors.cloud.tencent.com && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 暴露端口（必须与云托管控制台配置的端口一致）
EXPOSE 80

# 使用 uvicorn 启动 FastAPI（生产环境推荐）
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]