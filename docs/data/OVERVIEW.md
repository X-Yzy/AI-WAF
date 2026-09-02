# 数据集目录

本目录保存训练、测试和验证使用的全部数据。训练代码按原始载荷/内容家族进行分组，
同一攻击的混淆变种不会跨越训练集和测试集。

| 子目录 | 内容 | 当前规模 |
|---|---|---:|
| `normal_traffic/` | 普通字段、难负样本和传统/现代完整正常 HTTP 请求 | 300,000 |
| `modern_attack_traffic/` | 近期 CVE HTTP 字段、完整请求与 CISA KEV 在野利用元数据 | 913 |
| `specialized_traffic/` | 字段、API、协议、LLM 和扫描器专项数据 | 1,523 |
| `enriched_traffic/` | 22 类成对难负样本与编码变体；按对比组稳定切分 | 2,762 |
| `lab_captures/` | fixture、Juice Shop、WebGoat、VAmPI 四源隔离靶场真实 HTTP 请求 | 1,427 |
| `external_traffic/` | 多个独立公网项目的字段、完整请求、CRS 与 LLM 回归语料 | 261,618 |
| `external_deserialization/` | PHP/Java/.NET/Python gadget、marshaller/格式入口与 Nuclei 反序列化 CVE；无编码扩增 | 269（260 个独立单位） |
| `organized/` | 全部带标签数据的 normal/attack 分类视图；攻击继续按类型和数据层分类 | 639,984 |
| `coverage/` | 数据、运行时与非 WAF 控制边界的漏洞覆盖矩阵 | 61 个家族 |
| `attack_traffic/` | 22 类攻击的混淆变种 | 9,040 |
| `all_original_obfuscated/` | 统一视图中全部原始攻击的一对一可追溯混淆派生集 | 59,583 |
| `raw_attack_traffic/` | 未混淆攻击载荷和原始来源文件 | 2,260 |
| `augmented/` | 针对已知边界的定向增强样本 | 以目录文件为准 |
| `validation/` | 语义边界、分层混淆和示例验证集 | 以目录文件为准 |
| `archives/` | 旧 ZIP 已删除，仅保留边界说明 | 不读取 |

## 防止数据泄漏

- 攻击数据按原始载荷指纹形成 `group_id` 后再切分。
- 正常数据按场景和模板家族留出，不只按随机 ID 切分。
- `attack_type` 和标签派生字段不会作为分类器输入。
- fuzzdb 来源保留为外部评测，不混入最终训练来源。
- 测试集不参与词表统计、阈值选择或数据增强。
- 最新漏洞样本按 `cve_id` 形成 `group_id`，同一 CVE 的所有字段只属于一个集合。
- 对比式增强的攻击编码与正常对照共享 `group_id`，同组只属于一个集合。
- BOLA、Mass Assignment、GraphQL 复杂度等上下文标签不进入单字段模型。
- 扫描器数据按完整会话分组，User-Agent 只能作为组合证据，不能单独作为恶意标签依据。
- 靶场捕获按 campaign 分组切分；请求级标签不会复制给请求中的每一个普通字段。
- 外部字段按内容哈希切分，并剔除与现有语料重合的 291 个同标签内容和 15 个冲突标签内容。
- ECML/CSIC 原始测试分区和 OWASP CRS 规则回归样本只进入 `evaluation`，不回灌��练。

## 数据审计

```bash
python run.py validate-data
python run.py validate-data --deep
python run.py organize-data
python run.py generate-all-obfuscations
python run.py collect-external-data --offline
python run.py collect-deserialization-data --offline
```

`organize-data` 不移动原始数据，而是重建 `organized/normal/<data_level>/`、
`organized/attack/original/<attack_type>/` 与
`organized/attack/obfuscated/<attack_type>/` JSONL 视图。深度审计会解析全部源数据目录和
统一派生视图，并核对清单声明数量、哈希、原始/混淆归档和分组边界。各子目录的数据格式、
来源、处理口径和精确统计见 `organized/README.md`。
