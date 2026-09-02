# 自动化测试

本目录覆盖归一化、HTTP 解析、协议边界、模型管线、混淆生成器、可视化后台和
真实 WAF 产品实验约束。

```bash
python run.py test
```

| 文件 | 范围 |
|---|---|
| `test_regressions.py` | 编码、语义边界和高风险规则回归 |
| `test_integration.py` | 模型加载、生成器和端到端检测 |
| `test_runtime_api.py` | 在线检测、批量检测和 HTTP 请求检测 API |
| `test_demo_ui.py` / `test_ops_dashboard.py` | 本地可视化工作台与服务器运维面板 |
| `test_organized_dataset.py` | organized 清单、分层、来源追溯与混淆记录 |
| `test_real_waf.py` | 官方产品身份、HTTP 请求映射与真实报告约束 |
| `test_proxy.py` | 正常服务器转发、方法保留、攻击阻断和健康检查 |
| `test_final_delivery.py` / `test_run_entrypoint.py` | 交付物完整性与项目命令入口 |
| `run_full_benchmark.py` | organized 全量字段数据归一化、特征契约与正式模型冒烟基准 |

测试不会重新训练模型。涉及训练数据或模型变化时，应额外运行 `python run.py all`。

## 全量基准

```bash
python tests/run_full_benchmark.py
```

该入口逐条读取 `data/organized` 中所有符合正式训练策略的字段级
原始/混淆攻击记录，检查 UTF-8 JSONL、归一化性能和 38 维特征输出；
同时通过公开 `DetectionPipeline` 加载 `models/current` 的 LightGBM 与字符模型，
校验特征顺序并执行代表性推理。脚本只读，不重新训练，也不写入模型或报告。

数据或模型位于其他目录时可显式指定：

```bash
python tests/run_full_benchmark.py --data-root <organized目录> --model-dir <模型目录>
```

也可使用 `WAD_ORGANIZED_ROOT` 和 `WAD_MODEL_ROOT` 环境变量。完整独立测试集的
精确率、召回率、误报率与分位时延仍由 `python run.py evaluate` 产生，
该基准不重复生成正式评测报告。
