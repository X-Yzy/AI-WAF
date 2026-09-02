# 模型训练完整流程

## 当前数据依赖

“模型与训练 → 完整流程”只使用最终独立交付中的 `data/organized`。
启动前会快速核验：

- `manifest.json`、`taxonomy.json`
- `normal/manifest.json`、`attack/manifest.json`
- 588 个清单内数据文件是否存在、是否位于 organized 目录内、字节数是否一致
- 639,984 条总记录、正常/攻击总量、65 个攻击家族和表示总量是否一致
- 需要模型的阶段同时检查两个模型文件、元数据与 38 维特征顺序

完整流程不再依赖已由 organized 物理副本统一承载的
`all_original_obfuscated`、`normal_traffic`、`external_traffic` 或
`external_deserialization` 旧目录。

## 阶段顺序

```bash
python run.py all --min-recall 0.95
```

按顺序执行：

1. 完整数据加载、组级采样和模型训练
2. 单元与集成测试
3. organized 独立测试集完整链路评测
4. 自动启动并校验三款真实 WAF，在相同记录上完成 HTTP 产品对比
5. 重建并验证模型产物 SHA-256 清单

训练报告统一写入 `training_results.json`，评测报告统一写入
`pipeline_evaluation.json`；`waf_comparison.json` 记录本次产品实验状态，
随项目交付的完整产品实测报告不会因未运行或部分运行而被覆盖。

真实 WAF 阶段需要本机 Docker 引擎。首次运行会拉取固定版本官方镜像
`owasp/modsecurity-crs:4.28.0-nginx-202607160307`，报告会保存实际镜像
SHA-256 摘要、阻断配置、HTTP 状态统计和请求载体映射。未连接 Docker 时不会回退到
关键词模拟器，也不会生成虚构指标；`all` 和 `compare-waf` 会直接失败。产品身份、
冒烟门禁、全量记录或四系统完整性任一项不满足时，都不会发布正式报告。

当前模型使用 140,000 维字符词表和 0.34495921 阈值；完整链路 Precision 为
99.0476%、Recall 为 98.8515%、F1 为 98.9495%、FPR 为 0.0745%，P99 为
1.27536 ms，吞吐量为 1,201.488 条/秒。

## 外部来源召回率

外部来源召回率不是用总体召回率代替，而是按独立测试记录中的
`_organized.source_dataset` 重新聚合。当前定义包含：

- `external_traffic/*`
- `external_deserialization/*`
- `modern_attack_traffic`

当前正式模型结果：

- 外部来源攻击记录：1,074
- 正确检出：1,061
- 召回率：98.7896%

详细分来源结果位于
`models/current/pipeline_evaluation.json` 的 `source_recall`；
聚合结果位于 `external_sources`。本地结果页优先显示
`external_sources.recall`。
