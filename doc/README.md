# AI-WAF 文档

根目录 [README](../README.md) 提供安装、运行和项目总览。本目录只保留公开源码仓库需要的
设计、数据、训练、测试、实验和部署说明；比赛附件与内部交付记录不进入 GitHub 仓库。

## 使用与设计

- [系统设计](SYSTEM_DESIGN.md)
- [完整工作流](FULL_WORKFLOW.md)
- [模型说明](MODEL.md)
- [测试报告](TEST_REPORT.md)
- [GitHub 上传说明](GITHUB_UPLOAD.md)

## 模块说明

- [检测核心](components/DETECTION_CORE.md)
- [训练与验证](components/TRAINING.md)
- [载荷生成器](components/PAYLOAD_GENERATOR.md)
- [可视化控制台](components/DEMO.md)
- [自动化测试](components/TESTS.md)

## 数据、实验与部署

- [数据目录概览](data/OVERVIEW.md)与[完整数据手册](data/DATASET_GUIDE.md)
- [消融实验](experiments/ABLATION_STUDY.md)与[真实 WAF 对比](experiments/REAL_WAF_COMPARISON.md)
- [服务器运行包](deployment/SERVER_RUNTIME.md)、[现有服务器接入](deployment/SERVER_INTEGRATION.md)和[WAF 基准环境](deployment/WAF_BENCHMARK.md)
