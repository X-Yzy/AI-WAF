# AI-WAF 数据集来源、结构与生成器说明

本文只说明三项内容：数据集来自哪里、数据如何组织、各生成器负责什么。模型训练方式、
检测指标、审计结果和部署方式不在本文范围内。

## 一、数据集来源

### 1. 来源类别

项目中的数据分为四类：

1. **外部公开数据**：从公开项目或公开基准取得，固定上游版本并保留 URL、commit、许可证
   和文件哈希。
2. **隔离靶场捕获**：在本机或隔离容器中向明确授权的易受攻击应用发送请求，经采集代理
   转发、接收响应、脱敏后导出。
3. **项目合成与回归数据**：使用固定 seed 的生成器构造正常流量、专项攻击/正常对照、
   上下文序列和语义边界样本。
4. **派生数据**：从已有攻击记录生成的编码或混淆表示。派生记录保留原始记录关系，不能
   作为新的独立攻击来源计数。

### 2. 外部公开数据来源

| 逻辑数据集 | 上游来源 | 本地位置 | 内容与用途 |
|---|---|---|---|
| `raw_attack_traffic` | PayloadsAllTheThings、fuzzdb | `data/raw_attack_traffic/` | SQLi、XSS、命令注入、路径穿越、XXE、SSRF、反序列化等公开攻击载荷；保留上游原文件、来源 URL、版本和许可证。 |
| `modern_attack_traffic` | ProjectDiscovery Nuclei Templates；CISA Known Exploited Vulnerabilities | `data/modern_attack_traffic/` | 离线解析近期 CVE HTTP 模板，提取包含明确攻击原语的字段和完整请求；CISA KEV 只提供在野利用优先级元数据。模板不会被执行。 |
| `external_traffic/payloads` | grananqvist Machine-Learning WAF Dataset | `data/external_traffic/generated/payloads/` | 独立公开的正常字段以及 XSS、SQLi、命令和路径类攻击字段。 |
| `external_traffic/requests` | ECML/PKDD 2007、CSIC 2010，经公开 GPL-3.0 汇编仓库取得 | `data/external_traffic/generated/requests/` | 脱敏流量与靶场生成的完整正常/异常 HTTP 请求；上游测试分区保留为独立评测数据。 |
| `external_traffic/crs_requests` | OWASP Core Rule Set regression tests | `data/external_traffic/generated/crs_requests/` | 带规则期望的完整攻击请求和经过保守筛选的正常难负例。 |
| `external_traffic/gap_payloads` | PayloadBox CSV Injection、HTTP Protocol Injection | `data/external_traffic/generated/gap_payloads/` | CSV 公式、CRLF、Host/Header、HPP、HTTP/2 和协议注入等稀缺类型。 |
| `external_traffic/smuggling_requests` | PayloadBox HTTP Request Smuggling Payloads | `data/external_traffic/generated/smuggling_requests/` | CL.TE、TE.CL、TE.TE、HTTP/2 desync 等完整请求走私样本。 |
| `external_traffic/llm_benchmark` | PIArena InjecAgent | `data/external_traffic/generated/llm_benchmark/` | 用户任务、受污染工具响应、攻击目标和预期危害组成的 LLM 间接注入评测上下文。 |
| `external_deserialization/gadget_fields` | PHPGGC、JexBoss、ysoserial、marshalsec、ysoserial.net，以及项目内 Python 格式生成器 | `data/external_deserialization/generated/gadget_fields/` | PHP、Java、.NET、Python 的规范 gadget、marshaller 或序列化格式入口；一个上游机制只保留一个规范对象，不用编码副本增加独立样本数。 |
| `external_deserialization/cve_requests` | ProjectDiscovery Nuclei Templates | `data/external_deserialization/generated/cve_requests/` | 携带明确序列化对象的完整 CVE HTTP 请求，只作为请求级评测样本。 |

外部数据的精确上游 URL、commit/release、许可证、原始归档 SHA-256 和本地输出哈希不在本文
重复抄写，以各数据目录的 `manifest.json`、`sources.lock.json` 和 `source_snapshots/` 为准。
其中：

- PayloadsAllTheThings、fuzzdb 原文件位于各攻击类型的 `original_files/`。
- Nuclei、CISA KEV 和其他外部项目的锁定快照位于对应的 `source_snapshots/`。
- 带来源锁和 SHA-256 的 `source_snapshots/` 用于离线溯源，不作为第二份带标签训练数据
  纳入统一视图；`data/archives/` 中无清单引用的旧 ZIP 重复副本已删除。
- ECML/CSIC 的原始测试分区、OWASP CRS 回归数据和外部完整请求保持 evaluation 边界，
  不因重新整理而自动成为训练数据。

### 3. 隔离靶场数据来源

| 靶场标识 | 来源 | 本地数据位置 | 形成方式 |
|---|---|---|---|
| `127.0.0.1:19082` | 项目内惰性本机 fixture | `data/lab_captures/generated/` | 只在回环地址运行的安全测试目标，用于验证采集链路和标签格式。 |
| `juice-shop:3000` | OWASP Juice Shop | `data/lab_captures/generated/` | 在隔离容器中发送带明确标签的测试请求，由本地采集代理转发并记录。 |
| `webgoat:8080` | OWASP WebGoat | `data/lab_captures/generated/` | 在隔离容器中生成授权攻击/正常请求，按 campaign 导出。 |
| `vampi:5000` | VAmPI（Vulnerable API） | `data/lab_captures/generated/` | 使用锁定镜像和一次性数据库生成 API 授权、身份、资源消耗等请求。 |

采集代理会对常见凭据请求头、敏感查询参数和 JSON secret 字段脱敏。项目精简后已删除
靶场、采集工具和原始捕获，只保留 `data/lab_captures/generated/` 中经过脱敏、去重并由
manifest 固定哈希的定稿导出，避免原始捕获和导出文件重复计数。

### 4. 项目合成与回归数据来源

| 逻辑数据集 | 本地位置 | 形成方式 | 内容 |
|---|---|---|---|
| `normal_traffic/payload_level` | `data/normal_traffic/generated/payload_level/` | 固定 seed 的正常数据生成器 | 搜索词、表单、查询参数、JSON/XML 字段、文件名、URL、认证头等正常字段。 |
| `normal_traffic/http_requests` | `data/normal_traffic/generated/http_requests/` | 固定 seed 的正常数据生成器 | 搜索、登录、订单、评论、上传元数据等传统完整正常 HTTP 请求。 |
| `normal_traffic/modern_http_requests` | `data/normal_traffic/generated/modern_http_requests/` | 固定 seed 的正常数据生成器 | GraphQL、OAuth/OIDC、WebAuthn、Webhook、gRPC-Web、WebSocket、SSE 和云原生正常请求。 |
| `normal_traffic/hard_negatives` | `data/normal_traffic/generated/hard_negatives/` | 固定 seed 的正常数据生成器 | 包含 SQL、HTML、Shell、路径和模板术语，但语义正常的安全技术文本。 |
| `specialized_traffic/payloads` | `data/specialized_traffic/generated/payloads/` | 专项防御数据生成器 | 反序列化、原型污染、NoSQL、JNDI、XXE、请求走私、HPP、上传等字段攻击和正常难负例。 |
| `specialized_traffic/api_context_sequences` | `data/specialized_traffic/generated/api_context_sequences/` | 专项上下文生成器 | BOLA/BFLA、Mass Assignment、OAuth、GraphQL、鉴权、竞态和业务流程上下文。 |
| `specialized_traffic/high_value_context_sequences` | `data/specialized_traffic/generated/high_value_context_sequences/` | 成对上下文生成器 | API 授权、身份、缓存、GraphQL、WebSocket、gRPC 和业务流程的攻击/正常对照。 |
| `specialized_traffic/protocol_sequences` | `data/specialized_traffic/generated/protocol_sequences/` | 协议序列生成器 | HTTP/2 伪头、Rapid Reset、WebSocket 帧和消息预算事件。 |
| `specialized_traffic/llm_context_sequences` | `data/specialized_traffic/generated/llm_context_sequences/` | LLM 上下文生成器 | 直接/间接 Prompt Injection、RAG/工具注入、Prompt 外泄和敏感输出对照。 |
| `specialized_traffic/scanner_sequences` | `data/specialized_traffic/generated/scanner_sequences/` | 扫描序列生成器 | Nuclei、sqlmap、Nikto、ffuf、Gobuster、dirsearch、ZAP、Wapiti 行为序列和正常自动化对照。 |
| `enriched_traffic` | `data/enriched_traffic/generated/` | 固定 seed 的对比式字段生成器 | 攻击原语、编码变体和正常近邻组成的对比组；整个组使用同一 split。 |
| `augmented` | `data/augmented/` | 定向人工/程序增强 | SQLi 大小写、路径上下文、JWT 等已知检测边界的补充记录。 |
| `validation` | `data/validation/` | 独立回归与语义边界设计 | 基础/中度/重度混淆、语义边界和格式回归样本。 |

项目合成数据用于覆盖格式、协议边界和难负例，不代表真实生产流量的自然概率分布。

### 5. 派生数据来源

| 逻辑数据集 | 原始输入 | 本地位置 | 派生含义 |
|---|---|---|---|
| `obfuscated_attack_traffic` | `data/raw_attack_traffic/*/source_records.json` | `data/attack_traffic/` | 早期 22 类公开 payload 的编码、大小写、空白、注释和语法变体；同一原始 payload 的变体保持家族关系。 |
| `all_original_obfuscated` | `data/organized/attack/original/` | `data/all_original_obfuscated/generated/` | 对统一视图中的每条原始攻击调用混淆生成器，默认一条原始记录对应一条确定性变体；继承原数据层和 split。 |
| `organized` | 所有明确带 `label=0/1` 的权威数据目录 | `data/organized/` | 非破坏性统一派生视图；按正常/攻击、原始/混淆、攻击类型、数据层和 split 重新分片。 |

派生记录不是新的独立采集来源。`original_id`、`original_organized_id`、原始内容、来源文件、
策略链和生成 seed 用于把它们与原始攻击绑定。

## 二、数据集结构

### 1. 权威数据与统一视图

```text
data/
├── normal_traffic/                 # 项目生成的正常字段和完整请求
├── raw_attack_traffic/             # 公开原始攻击 payload 与上游原文件
├── attack_traffic/                 # 早期公开 payload 的混淆派生
├── all_original_obfuscated/        # 全部原始攻击的一对一混淆派生
├── modern_attack_traffic/          # 近期 CVE/Nuclei 与 CISA KEV 元数据
├── specialized_traffic/            # 字段、API、协议、LLM、扫描器专项数据
├── enriched_traffic/               # 对比式攻击、编码和正常近邻
├── external_traffic/               # 外部字段、完整请求、CRS、协议、LLM 数据
├── external_deserialization/       # 独立 gadget、格式入口和反序列化 CVE
├── lab_captures/                   # 隔离靶场脱敏导出
├── augmented/                      # 定向增强
├── validation/                     # 回归与语义边界
├── archives/                       # 旧重复 ZIP 已删除，仅保留 README
├── coverage/                       # 数据/运行时覆盖边界元数据
└── organized/                      # 可重建的统一视图
```

`organized/` 不是替代原始目录的唯一副本。各来源目录仍然是权威输入；组织器删除并重建
`organized/` 时不会移动或覆盖来源数据。

### 2. 统一视图目录

```text
data/organized/
├── README.md                       # 自动生成的来源和数量说明
├── manifest.json                   # 总清单、来源、分片、哈希和内容审计
├── taxonomy.json                   # attack_type 到 CWE/OWASP/CVE 的映射
├── normal/
│   ├── manifest.json
│   └── <data_level>/
│       └── <split>.jsonl
└── attack/
    ├── manifest.json
    ├── original/
    │   ├── manifest.json
    │   └── <attack_type>/
    │       ├── manifest.json
    │       └── <data_level>/<split>.jsonl
    └── obfuscated/
        ├── manifest.json
        └── <attack_type>/
            ├── manifest.json
            └── <data_level>/<split>.jsonl
```

目录含义：

- `normal/`：`label=0` 的正常记录。
- `attack/original/`：没有显式项目内混淆派生证据的攻击。这里的“原始”不等于全部都是
  网络抓包原文，也包括完整 CVE 请求、靶场请求、上下文、协议事件和规范序列化对象。
- `attack/obfuscated/`：能够追溯原始内容和变换方式的显式派生记录。
- `<attack_type>`：规范攻击类型，例如 `sqli`、`xss`、`deser`、`ssrf`、`api_bola`。
- `<data_level>`：记录的语义层级。
- `<split>`：数据用途边界。

### 3. 数据层

| `data_level` | 记录含义 | 主要内容字段 | 字段模型适用性 |
|---|---|---|---|
| `field` | 单个字段或攻击载荷 | `payload`、`obfuscated_payload` | 仅在 `_organized.payload_model_eligible=true` 时可作为字段模型候选。 |
| `request` | 完整 HTTP 请求 | `raw_request`，或 `method/url/headers/body` | 请求标签不能自动复制给请求中的每个普通字段。 |
| `context` | 身份、会话、授权或多请求上下文 | `raw_request`、`observed_context`、`principal_role` | 需要上下文检测，不进入单字段模型。 |
| `protocol` | HTTP/2、WebSocket 等协议事件/序列 | `protocol_event` | 需要网关协议状态，不进入单字段模型。 |
| `llm_context` | LLM 对话、工具响应或输出上下文 | `conversation`、`observed_context` | 需要 LLM 专用安全层，不进入单字段模型。 |

### 4. 数据划分

| `split` | 含义 |
|---|---|
| `train` | 可用于训练的数据。 |
| `validation` | 阈值、模型选择或训练过程验证数据。 |
| `test` | 训练完成后的保留测试数据。 |
| `evaluation` | 独立外部、完整请求、CRS、CVE 或回归评测数据，不回灌训练。 |
| `unspecified` | 上游没有声明可安全复用的划分，使用前必须单独制定分组策略。 |

已有 `split`、`group_id`、`content_group_id`、CVE、框架或 campaign 边界应保持不变。同一
原始攻击及其混淆派生继承相同 split，避免原始/编码变体跨训练和测试集合。

### 5. 通用记录字段

来源记录的字段因数据层不同而变化，但通常包含：

```json
{
  "id": "来源内稳定 ID",
  "label": 1,
  "attack_type": "sqli",
  "attack_subtype": "具体子类型",
  "source": "来源名称",
  "source_url": "上游 URL",
  "source_version": "commit 或 release",
  "source_license": "许可证",
  "group_id": "防止同家族跨 split 的分组 ID",
  "split": "train",
  "exclude_from_payload_model": false
}
```

统一视图不会删除来源字段，而是增加 `_organized`：

```json
{
  "_organized": {
    "id": "organized_...",
    "source_file": "data/.../dataset.json",
    "source_record_index": 1,
    "source_dataset": "逻辑来源名称",
    "data_level": "field",
    "split": "train",
    "content_sha256": "内容指纹",
    "record_sha256": "标签、类型、层级和内容指纹",
    "payload_model_eligible": true,
    "attack_representation": "original",
    "attack_representation_basis": "归档依据"
  }
}
```

正常记录没有攻击表示字段。攻击记录的 `attack_representation` 为 `original` 或
`obfuscated`。

### 6. 混淆派生记录字段

通过生成器产生的记录还包含：

```json
{
  "original_id": "原始来源 ID",
  "original_organized_id": "原始统一视图 ID",
  "original_payload": "原始内容或规范序列化表示",
  "obfuscated_payload": "混淆内容",
  "original_content_sha256": "原始内容指纹",
  "obfuscated_content_sha256": "混淆内容指纹",
  "original_source_file": "原始来源文件",
  "original_source_record_index": 1,
  "original_source_dataset": "原始逻辑数据集",
  "obfuscation_chain": ["url_encode_double"],
  "obfuscation_depth": 1,
  "decoder_requirements": ["url_decode", "url_decode"],
  "generation_seed": 20260725,
  "is_encoding_variant": true,
  "equivalence_scope": "explicit-decoder-required"
}
```

非字段内容的混淆是其规范序列化表示的编码，使用
`equivalence_scope=serialized-representation-only`，并保留
`exclude_from_payload_model=true`；它用于测试解码和归一化能力，不宣称结果仍是可以直接
回放的协议对象。

### 7. 清单和哈希

各主要数据目录使用 `manifest.json` 描述：

- 数据集名称、来源版本和生成参数；
- 总记录数以及按标签、类型、数据层和 split 的分布；
- 每个输出文件的记录数、字节数和 SHA-256；
- 上游归档、快照或来源文件的 SHA-256；
- 独立样本、派生样本、分组和排除规则。

使用数据时，机器可读数量和文件哈希以 `manifest.json` 为准；`README.md` 用于解释语义。

## 三、生成器功能

### 1. 正常流量生成器

文件：`data/normal_traffic/generate_normal_dataset.py`

功能：

- 使用固定 seed 生成正常字段、传统 HTTP 请求、现代 HTTP 请求和安全技术文本难负例；
- 为记录设置稳定 ID、来源场景、split 和必要的请求级排除标记；
- 生成 `data/normal_traffic/generated/manifest.json` 和各类 JSON 数据文件；
- 不访问网络。

命令：

```bash
python3 data/normal_traffic/generate_normal_dataset.py
```

### 2. 近期 CVE 数据构建器

文件：`data/modern_attack_traffic/build_dataset.py`

功能：

- 读取锁定的 ProjectDiscovery Nuclei HTTP 模板；
- 只提取包含明确攻击原语的字段或完整请求，不把产品路径和版本探测直接标成攻击；
- 使用 CVE ID 形成分组并生成稳定 split；
- 合并 CISA KEV 元数据作为优先级信息；
- 只离线解析模板，不执行模板、不访问模板目标；
- `--refresh` 模式可更新锁定公开来源，默认可以使用本地快照。

命令：

```bash
python3 run.py refresh-cve-data
```

### 3. 专项安全数据生成器

文件：`data/specialized_traffic/generate_specialized_dataset.py`

功能：

- 生成反序列化、原型污染、NoSQL、JNDI、XXE、走私、HPP、上传等字段数据；
- 生成 API 授权、业务流程和高价值上下文正负对照；
- 生成 HTTP/2、WebSocket 协议序列；
- 生成直接/间接 LLM 注入、工具参数注入、Prompt 外泄和敏感输出上下文；
- 生成漏洞扫描器行为序列和正常自动化对照；
- 为上下文、协议和 LLM 数据设置字段模型排除标记；
- 不发送生成内容。

命令：

```bash
python3 run.py generate-specialized-data
```

### 4. 对比式字段生成器

文件：`data/enriched_traffic/generate_enriched_dataset.py`

功能：

- 为多类攻击定义不同语义原语；
- 为每个原语产生 raw、URL、双层 URL 等攻击表示和正常近邻；
- 使用共同 `group_id` 将攻击及其近邻绑定；
- 先按组分配 split，再输出组内记录，避免编码变体跨集合；
- 使用固定 seed，离线生成。

命令：

```bash
python3 data/enriched_traffic/generate_enriched_dataset.py
```

### 5. 外部公开流量构建器

文件：`data/external_traffic/build_external_dataset.py`

功能：

- 下载或读取已锁定的外部公开数据快照；
- 标准化字段、完整请求、CRS、协议走私和 LLM 上下文格式；
- 保留上游来源、版本和许可证；
- 按规范内容哈希去重，并排除与内部数据重复或跨标签冲突的字段；
- 保留外部测试/evaluation 边界；
- 输出按来源和 split 分类的 JSON 文件及 manifest。

离线重建：

```bash
python3 run.py collect-external-data --offline
```

更新锁定来源：

```bash
python3 run.py collect-external-data --refresh
```

### 6. 独立反序列化数据构建器

文件：`data/external_deserialization/build_dataset.py`

功能：

- 从 PHPGGC、JexBoss、ysoserial、marshalsec、ysoserial.net 和 Python 格式生成器建立规范对象；
- 将 gadget chain、marshaller/格式入口或独立 CVE 作为独立单位；
- 每个独立机制只保留一个规范表示，不生成 Base64、URL、Hex 副本来增加独立数量；
- 按框架、依赖家族或 CVE 分组，避免同一机制跨 split；
- 生成携带明确序列化载体的完整 CVE 请求；
- 支持只使用已锁定本地快照的离线构建。

命令：

```bash
python3 run.py collect-deserialization-data --offline
```

### 7. 靶场数据保留边界

靶场、采集与导出工具以及原始捕获已经从精简项目中删除。仓库只保留
`data/lab_captures/generated/` 下的定稿数据和 manifest，用于完整请求/序列评测与来源审计；
这些请求继续排除在单字段模型之外。当前项目不能重新执行靶场采集。

### 8. 单载荷混淆生成器

相关文件：

```text
src/obfuscator.py
payload_generator/cli.py
```

功能：

- 编码：单层/双层 URL、HTML Entity、Base64、Hex、Unicode Escape；
- 结构：SQL/JavaScript 注释、空白填充、大小写变化；
- 等价替换：SQL CHAR/CONCAT/Hex、JavaScript 包装；
- 特定技术：路径编码、命令字符串混淆；
- 组合：随机组合、多层递归和常见攻击表示组合；
- 接受固定 seed、策略列表、变体数和最大层数；
- 只转换字符串，不执行、不解码、不反序列化、不发送结果。

命令示例：

```bash
python3 -m payload_generator.cli "' OR 1=1 --" --count 5 --seed 42
```

### 9. 全部原始攻击批量混淆生成器

文件：`data/all_original_obfuscated/build_dataset.py`

输入：`data/organized/attack/original/`

输出：`data/all_original_obfuscated/generated/`

功能：

- 逐条读取全部原始攻击，不只处理早期公开 payload；
- 调用 `src.obfuscator.generate` 生成确定性编码变体；
- 默认每条原始记录生成一条派生记录；
- 保留原始 organized ID、来源文件/序号、原始内容、策略链、解码要求和生成 seed；
- 继承原数据层和 split；
- 对非 ASCII 内容使用 UTF-8 Base64 或 Hex，避免错误的多字节 URL 编码；
- 在生成前加载正常数据内容指纹，若候选结果与正常内容冲突，则确定性切换策略；
- 非字段内容按规范序列化表示编码，并继续排除在字段模型之外；
- 把派生数量与独立原始单位分开记录。

命令：

```bash
python3 run.py generate-all-obfuscations
```

调整每条原始记录的派生数：

```bash
python3 run.py generate-all-obfuscations --variants-per-original 2 --seed 20260725
```

### 10. 统一数据组织器

文件：`data/organize_dataset.py`

功能：

- 扫描项目中所有明确带 `label=0/1` 的权威 JSON 数据；
- 根据内容结构识别 `field/request/context/protocol/llm_context`；
- 根据记录声明和文件名保留 split；
- 正常记录写入 `organized/normal/`；
- 攻击记录按 `original/obfuscated`、`attack_type`、数据层和 split 写入独立 JSONL；
- 保留原记录字段并添加 `_organized` 溯源信息；
- 生成总 manifest、正常/攻击 manifest、原始/混淆 manifest、每个攻击类型 manifest、
  taxonomy 和自动 README；
- 记录输入/输出文件的数量、字节数和 SHA-256；
- 不移动、不覆盖来源数据。

命令：

```bash
python3 run.py organize-data
```

### 11. 覆盖矩阵生成器

文件：`data/coverage/build_coverage_matrix.py`

功能：

- 汇总每个漏洞家族的数据覆盖状态；
- 区分字段检测、请求/上下文数据、协议序列、运行时控制和 WAF 范围外控制；
- 生成 `data/coverage/coverage_matrix.json`；
- 不生成新的攻击样本，也不把存在数据误写为已经具备运行时防御能力。

命令：

```bash
python3 run.py audit-coverage
```
