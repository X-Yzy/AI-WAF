# 现有服务器快速接入

## 推荐拓扑

```text
用户 / 负载均衡 / TLS 终止
          |
          v
WAD 前置代理 :8081  --检测并记录/阻断-->  原业务服务器 :3000
```

业务代码无需引用 Python 包，也无需调用检测 API。只需让原服务器保留在内网端口，
把对外入口或现有 Nginx/Apache/IIS 的上游改成 WAD 代理。

## 最快启动

先在开发机执行 `python run.py build-runtime`，然后只上传
`deployment/server_runtime/`。以下命令均在这个最小包中执行，假设原业务仍在
`http://127.0.0.1:3000`：

```bash
python -m src.proxy \
  --backend http://127.0.0.1:3000 \
  --host 0.0.0.0 --port 8081 \
  --mode monitor --fail-policy closed
```

检查代理：

```bash
curl http://127.0.0.1:8081/_wad/health
curl http://127.0.0.1:8081/
```

确认正常业务、登录、上传和 API 都能通过，并观察 `runtime/proxy_access.jsonl`。完成
误报评估后，把 `--mode monitor` 改为 `--mode block`。

## Nginx 已有 HTTPS 入口

让 Nginx 继续处理证书，只把 `proxy_pass` 指向 WAD。可复制同目录 `nginx.conf` 中的
`location`。推荐链路：Nginx :443 → WAD :8081 → 业务 :3000。Nginx 会先缓冲并解码
chunked 请求，适合上传和常规 Web API。

## Apache

启用 `proxy`、`proxy_http`、`headers` 模块后使用 `apache.conf`。推荐链路：Apache
:443 → WAD :8081 → 原应用端口。不要让 WAD 的 backend 指回 Apache 同一监听端口，
否则会形成代理循环。

## IIS

安装 URL Rewrite 与 ARR，把站点反向代理目标设为 `http://127.0.0.1:8081`，原应用
改绑到另一个仅本机可访问端口，例如 3000；WAD 的 `--backend` 设置为
`http://127.0.0.1:3000`。先启用 monitor，再切 block。

## Docker

业务运行在宿主机 3000 端口时：

```bash
python run.py build-runtime
cd deployment/server_runtime
cp .env.example .env
docker compose up -d --build
```

服务器只有 Compose v1 时使用 `docker-compose up -d --build`。默认构建源均为国内
可访问地址：Docker Hub、阿里云 Debian/安全更新镜像和阿里云 PyPI。

代理入口为宿主机 8081。Linux 服务器默认对代理使用 host network，因此能访问只监听
`127.0.0.1:3000` 的原业务；在线检测 API 仍在桥接网络中，并仅映射宿主
`127.0.0.1:8000`。该端口根路径同时提供生产运维控制台。远程开放时设置强随机
`WAD_DASHBOARD_PASSWORD`，并在安全组中限制管理员来源。Docker Desktop 需要先启用
host networking。

如果只需要实时防护而不需要独立 API，可执行 `docker compose up -d --build proxy`，
只加载一个模型进程。镜像构建需要代理时，只在 `.env` 临时设置 `HTTP_PROXY` 和
`HTTPS_PROXY`；Docker Hub 不可达时用 `PYTHON_IMAGE` 指向可信镜像代理或服务器缓存。

## Linux 常驻服务

复制 `wad-proxy.service.example` 到 `/etc/systemd/system/wad-proxy.service`，按最小包
安装目录、运行用户和 backend 修改后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wad-proxy
sudo systemctl status wad-proxy
```

模板默认只监听 `127.0.0.1:8081`，由同机 Nginx/Apache 对外提供 TLS，运行目录只允许
写入 `runtime/`。

## 模式和故障策略

| 配置 | 行为 | 建议 |
|---|---|---|
| `monitor` | 检出攻击仍转发，并添加 `X-WAD-Monitor-Verdict: attack` | 首次接入 |
| `block` | 检出攻击立即返回 403 | 观察期完成后 |
| `fail-closed` | 检测器异常返回 503 | 登录、管理、支付等高安全入口 |
| `fail-open` | 检测器异常仍转发 | 可用性优先且有其他防护的入口 |

默认最大请求体为 1 MiB，可用 `--max-body-mb` 调整。直接代理支持严格校验和限长的
chunked 请求；Nginx/Apache/IIS 仍建议启用请求缓冲，以统一生产链路行为。

## 上线检查清单

1. 原业务只监听内网或 127.0.0.1，防止绕过 WAD 直接访问。
2. 先 monitor 观察正常业务，至少覆盖登录、搜索、上传和管理操作。
3. 确认 `/_wad/health` 返回 `status=ok`，再让负载均衡加入节点。
4. 使用真实业务正常流量复核误报率，再切换 block。
5. 限制 `runtime/proxy_access.jsonl` 权限并配置轮转；日志不记录 query 值和请求体。
6. TLS 放在 Nginx/Apache/IIS/负载均衡处理，WAD 与业务走受控内网。
7. 对高可用部署运行至少两个 WAD 实例，由现有负载均衡做健康检查和摘除。
