# 多个真实 WAF 产品对比实验

## 最终对照组

项目不使用关键词模拟器冒充 WAF。当前正式报告包含：

| 键 | 产品身份 | 固定来源 |
|---|---|---|
| `modsecurity_crs_4_28_0` | ModSecurity 3.0.16 + OWASP CRS 4.28.0 | `owasp/modsecurity-crs:4.28.0-nginx-202607160307` |
| `openappsec_ce` | open-appsec 1.1.35-open-source | 官方 unified Agent 镜像，prevent 本地策略 |
| `safeline_ce` | SafeLine CE 9.3.11 | 官方七容器社区版 Compose 栈 |

镜像 RepoDigest、产品版本、配置、冒烟门禁和运行状态都写入
`models/current/waf_comparison.json`。官方项目：

- <https://owasp.org/www-project-modsecurity/>
- <https://github.com/coreruleset/modsecurity-crs-docker>
- <https://github.com/openappsec/openappsec>
- <https://github.com/chaitin/SafeLine>

## 公平判定

最终模型和三个产品使用相同的 organized 独立测试记录、标签、顺序与已知重复排除规则：

- 测试记录：34,721；
- 正常：32,196；
- 攻击：2,525；
- 原始攻击：1,168；
- 混淆攻击：1,357。

每条记录按 `param_location` 转成 query、body、header、cookie、path 或 multipart
filename 请求。判定规则为：

- `2xx/3xx` 且有 `X-WAD-Benchmark-Backend: reached`：真实放行；
- 受控 `4xx` 且没有证明头：真实阻断；
- `5xx`、超时、连接错误、截断的非阻断响应：基础设施异常，有界重试，不算检出；
- 产品生成的阻断页正文即使截断，只要响应头已经给出受控阻断状态且无证明头，仍按真实
  阻断处理，随后关闭连接。

开始全量记录前必须通过双冒烟门禁：两条正常请求均到达后端，固定 SQL 注入探针在最多
30 次非评测预热内被阻断。评测记录不参与预热。每 1,000 条写入带数据清单、版本和端点
摘要的原子检查点；断点签名不一致时拒绝续跑。ModSecurity 容器恢复时复用同一个宿主
证明后端和端口，避免 Docker Desktop 在新端口建立阶段产生瞬时 502；新容器启动最多
尝试3次，每次失败原因都写入 `product_execution.startup_failures`，不会计为产品阻断。

## 2026-08-01 本次完整实测结果

| 系统 | Precision | Recall | F1 | FPR | P99 |
|---|---:|---:|---:|---:|---:|
| 最终 AI-WAF | 99.0476% | 98.8515% | 98.9495% | 0.0745% | 2.28114 ms |
| ModSecurity + CRS | 40.1990% | 52.7921% | 45.6429% | 6.1592% | 4.11742 ms |
| open-appsec | 30.1199% | 76.5941% | 43.2372% | 13.9365% | 23.80960 ms |
| SafeLine | 92.4107% | 57.3861% | 70.8038% | 0.3696% | 17.80368 ms |

原始/混淆攻击召回率：

| 系统 | 原始攻击 | 混淆攻击 |
|---|---:|---:|
| 最终 AI-WAF | 98.8014% | 98.8946% |
| ModSecurity + CRS | 88.4418% | 22.1076% |
| open-appsec | 92.8938% | 62.5645% |
| SafeLine | 61.9863% | 53.4267% |

三项真实产品结果都保留。没有产品的同集 F1 超过最终模型；这只是本次固定数据、版本和
配置下的结果，不代表产品的一般能力。延迟口径不同，报告固定
`fairness.latency_directly_comparable=false`。

三款产品结果由 2026-08-01 15:44:00（Asia/Shanghai）完成的本次真实 HTTP 全量实验
产生；最终 AI-WAF 行按当前 `models/current` 在完全相同的 34,721 条记录上重新计算。
AI-WAF 的 P99 是本次对比进程内检测链路时延，不能与产品 HTTP 链路时延直接比较。

## 复现

1. 启动证明后端：

   ```bash
   python deployment/waf_benchmark/proof_backend.py --host 0.0.0.0 --port 18081
   ```

2. 启动两个外部产品：

   ```bash
   python deployment/waf_benchmark/safeline/start.py --port 18082 --management-port 19443
   python deployment/waf_benchmark/openappsec/start.py --port 18083
   ```

3. 在 `.env` 同时声明端点和实际版本：

   ```dotenv
   WAD_SAFELINE_URL=http://127.0.0.1:18082
   WAD_SAFELINE_VERSION=9.3.11
   WAD_OPENAPPSEC_URL=http://127.0.0.1:18083
   WAD_OPENAPPSEC_VERSION=1.1.35-open-source
   ```

4. 运行：

   ```bash
   python run.py compare-waf
   ```

真实 WAF 对比必须使用正在运行的 Docker 引擎；开始前先确认 `docker version` 和
`docker compose version` 成功。未配置、身份不完整、门禁失败或未完成全部记录时不生成
效果指标，`compare-waf` 与 `all` 均直接失败。只有四个系统完成全部记录和身份门禁后，
才会更新 `waf_comparison.json` 与 `waf_comparison.last_verified.json`。

模型训练、自动化测试和独立评测可分别在纯 Python 环境执行，它们不等同于真实产品
对比，也不会生成新的产品排名。
