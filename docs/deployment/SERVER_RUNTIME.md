# 服务器最小部署

这里负责把完整开发项目导出为可独立上传的服务器运行包。

```bash
python run.py build-runtime
cd deployment/server_runtime
python verify_manifest.py
cp .env.example .env
docker compose up -d --build
```

默认使用 Docker 官方 Python 基础镜像，`apt-get` 只读取阿里云 Debian 与
Debian Security 镜像，Python 依赖只读取阿里云 PyPI。服务器只有旧版 Compose 时，
把上面的 `docker compose` 换成 `docker-compose`。

`api` 服务同时提供生产运维控制台，默认访问 `http://127.0.0.1:8000/`。远程开放前
必须设置 Dashboard 账号密码，并用安全组限制管理端口来源。

生成目录 `server_runtime/` 约 7.4 MiB，只包含实时防护与在线检测所需文件，并自带
Dockerfile、Compose、环境变量示例和 SHA-256 校验。完整部署说明见
完整接入方式见 [`SERVER_INTEGRATION.md`](SERVER_INTEGRATION.md)。
