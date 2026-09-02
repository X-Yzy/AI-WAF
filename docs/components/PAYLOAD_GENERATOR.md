# 恶意载荷混淆生成器

生成器只变换字符串，不发送网络请求，也不执行生成的载荷。它用于产生可复现的编码、
空白、注释、大小写、实体和字符串拼接变种。

列出全部策略：

```bash
python -m payload_generator.cli --list
```

固定随机种子生成 5 个变种：

```bash
python -m payload_generator.cli "' OR 1=1 --" --count 5 --seed 42
```

指定策略：

```bash
python -m payload_generator.cli "<svg onload=alert(1)>" \
  --strategy html_entity_encode --strategy url_encode_double --count 3
```

为统一视图中的全部原始攻击逐条生成可追溯变体，并自动重建/审计数据视图：

```bash
python3 run.py generate-all-obfuscations
```

默认每条原始攻击生成一条变体；可用 `--variants-per-original 2` 调整。批量生成结果位于
`data/all_original_obfuscated/generated/`。完整请求、上下文、协议和 LLM 内容只生成规范
序列化表示的编码，用于归一化鲁棒性测试，不会被当成新的字段级 payload。

策略实现复用 `src/obfuscator.py`。新增策略后需在 `tests/test_integration.py` 增加确定性、
去重和归一化回归测试。
