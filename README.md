# 针对混淆逃逸的 Web 攻击动态检测系统

这是可脱离原始工作目录独立训练、评测、演示和部署的最终项目。
`data/organized` 是完整数据集的物理副本，`models/current` 是通过
验证的正式模型，服务器最小包不依赖训练代码或外部数据目录。

完整说明见 [文档索引](docs/README.md)。大型 JSONL 数据通过 Git LFS 管理，
克隆完整数据前请先安装并启用 Git LFS。

## 项目结构

```text
AI-WAF/
├─ src/                  检测核心、API、代理和可视化服务
├─ payload_generator/    混淆载荷命令行工具
├─ training/             训练、评测和真实 WAF 对比
├─ experiments/ablation/ 消融实验及结果
├─ data/                 原始、增强、验证和完整 organized 数据集
├─ models/current/       当前正式模型、清单和评测报告
├─ demo/                 本地可视化前端
├─ deployment/           运行包、服务器配置和 WAF 基准环境
├─ tests/                自动化测试与交付验收
├─ tools/                模型和项目维护脚本
└─ docs/                 系统、数据、实验和部署文档
```

日常使用只需关注 `run.py`、`src/`、`models/current/` 和 `docs/`；
训练或复现实验时再进入 `training/`、`experiments/` 与 `data/`。

## 环境与本地界面

环境要求按任务区分：

| 任务 | Python 环境 | Docker |
|---|---|---|
| 训练、自动化测试、独立评测、消融实验、本地界面 | Python 3.12+ 及 `requirements.txt` | 不需要 |
| ModSecurity、SafeLine、open-appsec 真实产品同集对比 | Python 3.12+ 及 `requirements.txt` | **必须，且 Docker 引擎必须处于运行状态** |
| `python run.py all` 完整流程 | Python 3.12+ 及 `requirements.txt` | **必须** |

SafeLine 首次自动配置还需要本机安装 Edge 或 Chrome。Docker 只用于真实产品对比和容器化
部署；模型训练、独立评测与消融实验可直接在 Python 环境运行。

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python run.py ui
```

访问 `http://127.0.0.1:8000`。可使用 `--host` 和 `--port` 修改监听地址，例如 `python run.py ui --host 0.0.0.0 --port 9000`。本地界面只负责实验与展示，不包含
代理监控、线上告警和monitor/block控制。

## 使用完整数据重新训练

```bash
python training/train_final.py \
  --data-root data/organized \
  --output-dir models/candidate
```

训练默认写入候选目录，不自动覆盖正式模型。最终策略使用256,856条
正常样本和25,569条攻击样本；23种字段攻击类型全部覆盖，22种完整
保留，仅XSS由12,918条按原始组限量为8,000条。

字符模型采用2至5元组、140,000维词表和逻辑回归C=6；与LightGBM
按0.70/0.30融合，正式阈值为0.34495921。

## 评测

```bash
python training/evaluate_candidate_pipeline.py \
  --model-dir models/current \
  --data-root data/organized \
  --output runtime/pipeline_evaluation.json
```

- 模型独立测试：Precision 99.3259%，Recall 99.2079%，F1 99.2669%，FPR 0.0528%。
- 完整检测链路：Precision 99.0476%，Recall 98.8515%，F1 98.9495%，FPR 0.0745%。
- 完整链路时延：P99 1.27536 ms、吞吐 1,201.488 条/秒，满足题目单请求不超过10 ms。

## 真实 WAF 产品对比

最终可视化报告包含四个完成同集评测的系统：

| 系统 | 版本 | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|
| 最终 AI-WAF | 当前正式模型 | 99.0476% | 98.8515% | 98.9495% | 0.0745% |
| ModSecurity + OWASP CRS | 3.0.16 + 4.28.0 | 40.1990% | 52.7921% | 45.6429% | 6.1592% |
| open-appsec 社区版 | 1.1.35-open-source | 30.1199% | 76.5941% | 43.2372% | 13.9365% |
| SafeLine 社区版 | 9.3.11 | 92.4107% | 57.3861% | 70.8038% | 0.3696% |

四个系统均使用相同的 34,721 条 organized 独立测试记录。真实 WAF 通过
HTTP 反向代理执行，只有受控 4xx 且没有随机后端证明头才算阻断；5xx、超时和协议错误
不算检出。真实产品列包含 HTTP、代理和后端证明开销，不能与进程内模型延迟直接比较。

四个系统的指标来自 2026-08-01 15:44:00（Asia/Shanghai）完成的本次全量同集实测。
最终 AI-WAF 与三款真实 WAF 均使用当前 `models/current` 和相同测试集重新执行。

### 复现三个真实 WAF

该实验不能在纯 Python 环境完成。先启动 Docker Desktop（Windows/macOS）或 Docker
Engine（Linux），确认 `docker version` 与 `docker compose version` 均成功，再运行统一
入口；程序会自动启动证明后端、ModSecurity、SafeLine 和 open-appsec：

```bash
python run.py compare-waf
```

SafeLine 首次创建站点会使用 Selenium 驱动本机 Edge 或 Chrome 的正常管理页面；
`requirements.txt` 已固定 Selenium 版本，系统仍需安装其中一种浏览器。两个启动器把产品
状态保存到 `runtime/waf_products`，重复执行会复用已配置站点。open-appsec 固定
prevent 策略，SafeLine 固定官方七容器社区版栈。

评测器每 1,000 条原子保存进度。重新点击时只有数据清单、模型、镜像和产品版本签名
全部一致才会继续；任一签名变化都会自动从头执行。只有真实身份、正常放行、SQL 注入
阻断和全部 34,721 条记录都通过，产品才进入排名。任何效果优于当前
模型的产品也会保留，不做选择性排除。完整身份、状态码、混淆/原始召回及分类型结果见
`models/current/waf_comparison.json`，随交付保留的完整实测报告位于
`models/current/waf_comparison.last_verified.json`。

未连接到 Docker 引擎、任一产品未就绪或任一全量回放未完成时，`compare-waf` 和
`all` 都会失败，不会把部分结果发布为正式报告。

## Docker 完整实验平台

根目录镜像是可现场训练的完整实验镜像，包含 organized 数据、训练/评测代码、测试、
生成器、界面和正式模型。默认使用 Docker 官方 Python 基础镜像以及阿里云
APT/PyPI 源：

```bash
docker compose up -d --build api
```

在线检测 API 位于 `http://127.0.0.1:18089`。需要点击“完整流程”时使用前文的
`python run.py ui` 并访问 `http://127.0.0.1:8000`；该宿主入口能够自动控制
ModSecurity、SafeLine 和 open-appsec，Docker API 容器不暴露宿主 Docker 控制权。
生产服务器请使用下方独立的最小运行包。

## 服务器部署

```bash
python deployment/build_runtime_bundle.py
python deployment/server_runtime/verify_manifest.py
```

仅上传 `deployment/server_runtime`。服务器只加载正式模型，不包含数据、
生成器、训练、本地界面和测试。

示例部署在服务器的docker项目中：

```
WAD_PROXY_BACKEND=http://127.0.0.1:8080 WAD_PROXY_MODE=monitor WAD_PROXY_PORT=8081 docker compose -f compose.yml up -d --build
```

开启在公网上可访问

```
WAD_API_BIND=0.0.0.0 WAD_API_PORT=8000 WAD_DASHBOARD_USERNAME=admin WAD_DASHBOARD_PASSWORD='替换为你的强密码' docker compose -f compose.yml up -d --force-recreate api
```



完整项目中也可以直接启动：

```bash
python -m uvicorn src.runtime_api:app --host 127.0.0.1 --port 8000
python -m src.proxy --backend http://127.0.0.1:3000 \
  --host 127.0.0.1 --port 8081 --mode monitor
```

## 独立交付验收

```bash
python tools/verify_delivery.py
python run.py test
```

验收会检查十个板块、完整数据文件数与字节数、LFS占位文件、模型哈希、
服务器包哈希和关键入口。
