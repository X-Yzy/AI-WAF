# 真实 WAF 基准部署

此目录只用于离线防御对比实验，不属于服务器在线防护运行包。

## 环境前提

真实产品对比必须使用正在运行的 Docker 引擎和 Docker Compose 插件。仅安装 Python
依赖不能执行本实验。开始前应确保以下命令成功：

```bash
docker version
docker compose version
```

Windows/macOS 使用 Docker Desktop；Linux 使用 Docker Engine。SafeLine 首次配置还
需要本机 Edge 或 Chrome。模型训练、独立评测和消融实验不依赖 Docker。

## 目录

| 路径 | 用途 |
|---|---|
| `compose.yml` | 固定 ModSecurity 3.0.16 + OWASP CRS 4.28.0 |
| `proof_backend.py` | 返回随机令牌到达证明的只读后端 |
| `openappsec/` | 固定 unified Agent、NGINX 和 prevent 本地策略 |
| `safeline/` | 固定 SafeLine CE 七容器栈和自动站点配置 |

## 手工启动

在第一个终端启动证明后端：

```bash
python deployment/waf_benchmark/proof_backend.py --host 0.0.0.0 --port 18081
```

其他终端分别启动两个外部产品：

```bash
python deployment/waf_benchmark/openappsec/start.py --port 18083
python deployment/waf_benchmark/safeline/start.py --port 18082 --management-port 19443
```

两个启动器使用官方不可变镜像摘要，并把状态保存到
`runtime/waf_products/openappsec` 和 `runtime/waf_products/safeline`。
SafeLine 首次配置需要本机 Edge 或 Chrome；Selenium 已在项目依赖中固定。管理端口只
绑定 `127.0.0.1`，产品测试端点同样只绑定回环地址。

创建项目根目录 `.env`：

```dotenv
WAD_SAFELINE_URL=http://127.0.0.1:18082
WAD_SAFELINE_VERSION=9.3.11
WAD_OPENAPPSEC_URL=http://127.0.0.1:18083
WAD_OPENAPPSEC_VERSION=1.1.35-open-source
```

运行全部产品对比：

```bash
python run.py compare-waf
```

正式评测必须覆盖 34,721 条记录，且候选状态为 `evaluated`、
`included_in_ranking=true`。5xx/超时绝不按阻断计分。详细方法与最终结果见
`doc/experiments/REAL_WAF_COMPARISON.md`。
