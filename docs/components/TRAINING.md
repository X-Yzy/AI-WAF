# 训练、测试与验证

本目录提供最终模型训练、独立评测、数据审计和真实 WAF 产品公平对比脚本。所有正式流程
建议通过项目根目录的 `run.py` 调用。

## 一条命令完整复现

```bash
python run.py all
```

固定执行顺序：数据校验 → 模型训练 → pytest → 独立验证 → WAF 同集对比。训练、测试和
独立验证任一阶段返回非零状态后立即停止。真实产品阶段是完整流程的强制步骤，因此
`all` 必须在 Docker 引擎运行时执行；缺少 Docker 或任一产品未就绪时流程直接失败，
不会发布部分对比结果。

不需要真实产品对比时，可以分别运行 `train`、`test` 和 `evaluate`，这三个命令不依赖
Docker。独立消融实验位于 `experiments/ablation/`，同样只需要 Python 环境。

## 文件职责

| 文件 | 作用 |
|---|---|
| `train_final.py` | 正式可迁移训练入口，生成 LightGBM、字符模型和报告 |
| `train_final_impl.py` | 组级采样、模型训练及验证集运行点选择 |
| `train_organized_full.py` | organized 数据加载、去重、特征和文本输入公共实现 |
| `search_sampling_strategy.py` | 当前组级采样、二分类指标和运行点算法 |
| `evaluate_candidate_pipeline.py` | 正式独立测试集、分类召回和 P99 评测 |
| `compare_real_waf.py` | 最终模型与官方 ModSecurity + OWASP CRS 同集实测 |
| `real_waf.py` | 固定镜像、真实 HTTP 判定、检查点和可审计恢复适配器 |
| `compare_external_wafs.py` | SafeLine 与 open-appsec 全量同集评测 |
| `external_waf.py` | 外部反向代理产品身份、冒烟和 HTTP 判定适配器 |
| `audit_data.py` | 快速/深度数据清单审计 |
| `validate_dataset.py` | 单个数据文件格式验证 |
| `evaluate_scanner_sequences.py` | 扫描器与合法自动化序列的合成回放评测 |


## 常用命令

| 命令 | 输出 |
|---|---|
| `python run.py train` | `models/current/` 最终模型及训练报告 |
| `python run.py test` | pytest 回归和集成结果 |
| `python run.py evaluate` | `models/current/pipeline_evaluation.json` |
| `python run.py compare-waf` | `models/current/waf_comparison.json` 和页面图表 |
| `python run.py evaluate-scanners` | 扫描器序列请求级与会话级回放结果 |
| `python run.py audit-coverage` | 重建 61 类数据/运行时覆盖矩阵并深度审计 |
| `python run.py collect-external-data` | 下载锁定公网快照，标准化后重建并深度审计统一视图 |
| `python run.py collect-deserialization-data` | 重建一条一机制的 gadget/CVE 反序列化数据并深度审计 |
| `python run.py all` | 完整复现结果 |

`api_context_sequences/`、`protocol_sequences/` 与 `llm_context_sequences/` 被明确排除在
单字段模型之外；有这些数据不等于当前 HTTP/1.1 代理已实现应用授权、HTTP/2、
WebSocket 帧或 LLM 输出/工具调用控制。

正式入口只读取 `data/organized`。公共加载器统一执行字段级资格检查、已知跨来源重复排除、
分区内精确去重和跨分区泄漏门禁，训练、独立评测、WAF 对比及消融实验不再各自修改筛选
函数。外部来源、反序列化和现代攻击记录已经由 organized 清单统一承载。

## 当前核心结果

以下数值来自当前正式模型和完整 organized 独立测试集；以
`models/current/*.json` 中的机器可读报告为准。

| 项目 | 结果 |
|---|---:|
| 最终完整链路召回率 | 98.8515% |
| 最终完整链路精确率 | 99.0476% |
| 最终完整链路 F1 | 98.9495% |
| 最终完整链路误报率 | 0.0745% |
| P99 时延 | 1.27536 ms |
| 吞吐量 | 1,201.488 条/秒 |
| 外部来源召回率 | 98.7896%（1,061 / 1,074） |

同集真实产品实验中，官方 ModSecurity 3.0.16 + OWASP CRS 4.28.0 的召回率为
52.7921%、F1 为 45.6429%、误报率为 6.1592%；最终 AI-WAF 分别为
98.8515%、98.9495% 和 0.0745%。真实产品对原始攻击召回 88.4418%，对混淆攻击
召回 22.1076%。完整方法见 `docs/experiments/REAL_WAF_COMPARISON.md`。

三款产品指标来自 34,721 条全量真实 HTTP 回放；最终 AI-WAF 按当前模型在相同记录上
计算。复现实验必须启动 Docker，并通过 `python run.py compare-waf` 执行全部产品。中断后
只允许从数据、模型、镜像和产品版本签名完全一致的原子检查点继续。

## 公平性要求

- 不使用测试集重新选择阈值。
- 修改文本特征数量或依赖版本后必须重新训练。
- 提交指标时同时报告数据来源、切分方法、字段级和请求级结果。
- WAF 对照必须实际运行固定摘要的官方产品，不能回退为关键词模拟器。
- 产品效果使用同记录、同标签；延迟因一个是进程内推理、一个是真实 HTTP 反向代理，
  只按各自口径报告，不宣称纯引擎延迟可直接比较。
