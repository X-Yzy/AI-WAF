# 检测核心模块

本目录包含 HTTP 解析、混淆还原、规则检测、模型融合、API 和可视化后台，
是线上推理服务的核心代码。

## 检测链路

```text
完整 HTTP 请求
  -> parser：拆分 path/query/header/cookie/body
  -> L1-Raw：保留编码和协议结构证据
  -> L0：严格无害短输入快速放行
  -> normalizer：多层解码、Unicode 和字符串结构还原
  -> engine：高置信规则拦截
  -> extractor：38 维统计、结构和混淆特征
  -> LightGBM + 字符 n-gram LR 融合
  -> verdict / confidence / layer / evidence / elapsed_ms
```

## 文件职责

| 文件 | 作用 |
|---|---|
| `runtime_api.py` | 纯服务器 FastAPI：单载荷、完整 HTTP、批量检测与统计 |
| `app.py` | 本地完整应用包装器，在纯 API 上挂载 Dashboard 和演示页 |
| `dashboard.py` | 数据可视化和白名单后台任务管理 |
| `parser.py` | URL、Body、Header、Cookie 与协议歧义解析 |
| `normalizer.py` | URL、HTML、Base64、Hex、Unicode、JS/JSON 等迭代还原 |
| `extractor.py` | 生成固定顺序的 38 维模型特征 |
| `engine.py` | 高置信静态规则层 |
| `pipeline.py` | L1/L0、规则、上下文与双模型融合总管线 |
| `obfuscator.py` | 供 API 和生成器使用的混淆变换 |
| `proxy.py` | 现有服务器通用前置反向代理 |
| `settings.py` | 项目路径、阈值和运行配置 |
| `cache.py` | 特征结果缓存 |
| `rules/` | SQLi、XSS、命令注入 YAML 规则定义 |

## 真实 WAF 产品对比

对照实验不再使用本目录内的关键词画像。`../training/compare_real_waf.py`
会启动官方固定版本 ModSecurity + OWASP CRS Docker 产品，通过真实 HTTP 请求和
后端到达证明判定阻断结果。方法、版本、配置与复现命令见
`docs/experiments/REAL_WAF_COMPARISON.md`。

## 关键安全设计

1. 原文高危规则先于归一化，避免 CRLF、SSI 等证据在清理时丢失。
2. 快速放行会检查敏感参数名、编码痕迹、结构字符和原文规则。
3. 缺少任一生产模型时 API 返回 503，不使用残缺管线静默服务。
4. HTTP 请求体限制为 1 MiB，并检查 CL/TE 歧义和重复 Content-Length。
5. API JSON、命令行和后台任务日志统一使用 UTF-8。
6. 可视化任务接口只允许预定义工作流，同一时间最多运行一个任务。

本地启动完整服务：

```bash
python run.py serve
```

命令应从项目根目录执行。

服务器不要启动 `src.app`，也不需要上传完整项目。先执行
`python run.py build-runtime`，只上传 `deployment/server_runtime/`，再启动：

```bash
uvicorn src.runtime_api:app --host 127.0.0.1 --port 8000
python -m src.proxy --backend http://127.0.0.1:3000 --port 8081 --mode monitor
```

## 代理兼容与误报边界

代理保留用户实际访问的 Host，并改写 Location 以及 HTML、CSS、JavaScript、JSON、
XML 以及其他未压缩响应中指向 Docker 内部上游的地址。访问目录/path 不作为代理层
封禁依据；query、body、header、cookie 仍执行完整规则与模型检测。

## 接入现有业务服务器

```bash
python -m src.proxy --backend http://127.0.0.1:3000 --port 8081 --mode monitor
```

代理会加载 `models/current/` 唯一最终模型，完整保留 HTTP 方法和请求体。支持 monitor
观察、block 阻断、fail-open/fail-closed、JSONL 安全日志和 `/_wad/health`。生产接入
拓扑及 Nginx/Apache/IIS/Docker 模板见 `docs/deployment/SERVER_INTEGRATION.md`。
