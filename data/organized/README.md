# 统一整理数据集

本目录是项目全部带标签数据的**非破坏性派生视图**，由
`python3 data/organize_dataset.py`（或 `python3 run.py organize-data`）生成。
原始 JSON 数据仍保存在各来源目录，本目录不移动、不覆盖原始数据。下列数量全部由
本次生成的 `manifest.json` 自动写入；以后扩充数据并重建时会同步更新。

## 总体规模

| 指标 | 数量 |
|---|---:|
| 全部记录 | **639,984** |
| 正常记录（`label=0`） | **509,811** |
| 攻击记录（`label=1`） | **130,173** |
| 原始/非显式混淆攻击 | **59,583** |
| 显式混淆派生攻击 | **70,590** |
| 攻击类型 | **65** |
| JSONL 分片 | **588** |

这里的“记录”可能是字段、完整请求或上下文/协议序列，不能全部当作字段级 payload。
此外，公开原始载荷及其混淆派生变体会分别计数，因此总记录数不等于独立攻击原语数。
这里的“原始攻击”严格表示**没有显式混淆派生证据**，包括公开原始 payload、CVE 请求、
授权靶场请求、协议/上下文攻击和规范序列化对象；不保证每条都是网络抓包原文。只有能追溯
到原值和变换方式的记录才进入 `attack/obfuscated/`。二进制序列化对象唯一的 Base64 HTTP
载体属于规范传输格式，不会在 `is_encoding_variant=false` 时被误判为混淆。

## 数据来源与数量

| 来源数据集 | 原始位置 | 形成方式/上游来源 | 数据内容 | 正常 | 攻击 | 合计 |
|---|---|---|---|---:|---:|---:|
| `normal_traffic/payload_level` | `data/normal_traffic/generated/payload_level/` | 本项目生成器（固定 seed） | 普通表单、查询、JSON/XML、文件名、URL、认证头等合法字段级负样本 | 200,000 | 0 | **200,000** |
| `normal_traffic/http_requests` | `data/normal_traffic/generated/http_requests/` | 本项目生成器（固定 seed） | 搜索、登录、订单、评论、上传元数据等传统完整正常 HTTP 请求 | 50,000 | 0 | **50,000** |
| `normal_traffic/modern_http_requests` | `data/normal_traffic/generated/modern_http_requests/` | 本项目生成器（固定 seed） | GraphQL、OAuth/OIDC、WebAuthn、Webhook、gRPC-Web、WebSocket、SSE、云原生等现代正常请求 | 30,000 | 0 | **30,000** |
| `normal_traffic/hard_negatives` | `data/normal_traffic/generated/hard_negatives/` | 本项目生成器（固定 seed） | 含 SQL、HTML、Shell、路径、模板等安全技术文本的合法难负样本 | 20,000 | 0 | **20,000** |
| `raw_attack_traffic` | `data/raw_attack_traffic/*/source_records.json` | PayloadsAllTheThings、fuzzdb | 22 类公开未混淆攻击载荷；保留来源 URL、版本、许可证与原文件 | 0 | 2,260 | **2,260** |
| `obfuscated_attack_traffic` | `data/attack_traffic/*/dataset_obfuscated.json` | 本项目混淆生成器，派生自 raw_attack_traffic | 原始攻击载荷的编码、大小写和语法等变体；与原载荷按家族绑定 | 0 | 9,040 | **9,040** |
| `all_original_obfuscated` | `data/all_original_obfuscated/generated/` | 本项目混淆生成器，逐条派生自统一视图中的全部原始攻击 | 每条原始攻击至少一条确定性编码变体；继承数据层和 split，非字段表示不进入字段模型 | 0 | 59,583 | **59,583** |
| `modern_attack_traffic` | `data/modern_attack_traffic/generated/` | ProjectDiscovery Nuclei Templates；CISA KEV 作为优先级元数据 | 离线解析 2024—2026 年 CVE 模板后提取的明确攻击字段和完整请求；未执行模板或探测公网目标 | 0 | 913 | **913** |
| `specialized_traffic/payloads` | `data/specialized_traffic/generated/payloads/` | 本项目专项生成器 | 反序列化、原型污染、NoSQL、JNDI、XXE、请求走私、HPP、上传等正负字段样本 | 84 | 372 | **456** |
| `specialized_traffic/api_context_sequences` | `data/specialized_traffic/generated/api_context_sequences/` | 本项目专项生成器 | BOLA/BFLA、Mass Assignment、OAuth、GraphQL、缓存、鉴权、竞态和业务流程等上下文序列 | 43 | 94 | **137** |
| `specialized_traffic/high_value_context_sequences` | `data/specialized_traffic/generated/high_value_context_sequences/` | 本项目高价值上下文生成器（成对正负对照） | API 授权、身份、缓存、GraphQL、WebSocket、gRPC 和业务流程的多场景上下文对照 | 324 | 324 | **648** |
| `specialized_traffic/protocol_sequences` | `data/specialized_traffic/generated/protocol_sequences/` | 本项目专项生成器 | HTTP/2 伪头与 Rapid Reset、WebSocket 帧和消息预算等协议序列 | 16 | 46 | **62** |
| `specialized_traffic/llm_context_sequences` | `data/specialized_traffic/generated/llm_context_sequences/` | 本项目专项生成器 | 直接/间接 Prompt Injection、RAG/工具注入、Prompt 外泄和敏感输出正负上下文 | 20 | 20 | **40** |
| `specialized_traffic/scanner_sequences` | `data/specialized_traffic/generated/scanner_sequences/` | 本项目专项生成器 | Nuclei、sqlmap、Nikto、ffuf、Gobuster、dirsearch、ZAP、Wapiti 扫描序列及正常对照 | 60 | 120 | **180** |
| `enriched_traffic` | `data/enriched_traffic/generated/` | 本项目对比式字段生成器（固定 seed） | 22 类字段攻击的分组编码变体与成对正常难负样本；同组不跨训练/验证/测试 | 704 | 2,058 | **2,762** |
| `external_traffic/payloads` | `data/external_traffic/generated/payloads/` | grananqvist Machine-Learning WAF Dataset（MIT，锁定提交） | 独立公开正常、XSS、SQLi、命令/路径字段；按内容哈希去重和切分 | 100,479 | 8,768 | **109,247** |
| `external_traffic/requests` | `data/external_traffic/generated/requests/` | ECML/PKDD 2007、CSIC 2010（经 GPL-3.0 汇编仓库获取） | 脱敏真实流量与靶场生成的完整正常/攻击 HTTP 请求；原始测试分区仅作评测 | 107,006 | 40,175 | **147,181** |
| `external_traffic/crs_requests` | `data/external_traffic/generated/crs_requests/` | OWASP Core Rule Set regression tests（Apache-2.0，锁定提交） | 带明确规则期望的完整攻击请求和保守筛选的正常难负例；仅作独立评测 | 471 | 3,729 | **4,200** |
| `external_traffic/gap_payloads` | `data/external_traffic/generated/gap_payloads/` | PayloadBox CSV 与 HTTP Protocol Injection（MIT，锁定提交） | 补充 CSV 公式、CRLF、缓存/Host 头、HPP、HTTP/2 与走私字段；上下文类排除出字段模型 | 0 | 205 | **205** |
| `external_traffic/smuggling_requests` | `data/external_traffic/generated/smuggling_requests/` | PayloadBox HTTP Request Smuggling Payloads（MIT，锁定提交） | 独立完整 CL.TE、TE.CL、TE.TE、HTTP/2 desync 等请求；仅作 evaluation | 0 | 275 | **275** |
| `external_traffic/llm_benchmark` | `data/external_traffic/generated/llm_benchmark/` | PIArena InjecAgent（MIT，锁定提交） | 预构建的用户任务、污染工具响应、攻击目标与预期危害组合；仅作 LLM evaluation | 0 | 510 | **510** |
| `external_deserialization/gadget_fields` | `data/external_deserialization/generated/gadget_fields/` | PHPGGC、JexBoss、ysoserial、marshalsec、ysoserial.net 与 Python 生成器（来源和许可证锁定） | 每个上游 gadget、marshaller 或格式入口只保留一个规范对象；按框架/依赖家族切分，不生成编码变体 | 0 | 226 | **226** |
| `external_deserialization/cve_requests` | `data/external_deserialization/generated/cve_requests/` | ProjectDiscovery Nuclei Templates（MIT，锁定提交） | 带明确序列化对象载体的独立 CVE 完整请求；仅作 evaluation，不进入字段模型 | 0 | 43 | **43** |
| `lab_captures` | `data/lab_captures/generated/` | 隔离本机 fixture、OWASP Juice Shop v18.0.0、OWASP WebGoat v2025.3 | 经采集代理实际转发、响应、脱敏并导出的完整 HTTP 请求；按 campaign 分组 | 548 | 879 | **1,427** |
| `augmented` | `data/augmented/*.json` | 本项目定向人工/程序增强 | 针对 SQLi 大小写、路径上下文、JWT 等已知检测边界的补充样本 | 15 | 52 | **67** |
| `validation` | `data/validation/*.json` | 本项目独立回归与语义边界集 | 基础/中度/重度混淆、语义边界和格式示例；统一视图中标为 evaluation | 41 | 481 | **522** |
| **合计** |  |  |  | **509,811** | **130,173** | **639,984** |

### 公开来源和版本边界

- `raw_attack_traffic` 的公开原始攻击载荷来自 PayloadsAllTheThings 和 fuzzdb；
  精确 commit/version、URL 与许可证见 `../raw_attack_traffic/manifest.json` 及该目录许可证文件。
- `modern_attack_traffic` 来自锁定版本的 ProjectDiscovery Nuclei HTTP 模板；CISA KEV
  只提供在野利用优先级元数据。精确模板版本、归档 SHA-256、KEV 目录版本和筛选审计见
  `../modern_attack_traffic/generated/manifest.json`。模板仅离线解析，没有执行或向公网发请求。
- `external_traffic` 来自多个锁定提交：MIT 的 grananqvist ML-WAF、PayloadBox 与 PIArena、
  经 GPL-3.0 汇编仓库取得的 ECML/PKDD 2007 与 CSIC 2010，以及 Apache-2.0 的 OWASP CRS。
  精确 URL、提交、许可证说明和哈希见 `../external_traffic/generated/manifest.json`。
  ECML/CSIC 原始测试分区与全部 CRS 规则标签只用于 evaluation。
- 正常流量和 specialized 五组是本项目使用固定 seed 生成的合成数据，用于覆盖格式与边界，
  不代表生产业务的自然分布；上线前仍需用经授权、脱敏的真实业务流量校准。
- `augmented` 与 `validation` 是项目本地定向增强和回归资料，不是独立的公网采集语料。
- `all_original_obfuscated` 是从全部原始攻击逐条生成的派生表示，不是新的独立攻击样本。
  字段载荷可用于解码鲁棒性训练/评测；请求、上下文、协议和 LLM 的编码表示只用于
  表示层归一化测试，并继续排除在单字段模型之外。

### 隔离靶场捕获来源

`lab_captures` 是通过回环采集代理实际发送并获得后端响应的请求，不是只拼接出来的字符串。
敏感请求头、查询参数和 JSON secret 字段在采集时脱敏；所有靶场请求均排除在单字段模型之外。

| `lab_target` | 靶场 | 记录数 |
|---|---|---:|
| `127.0.0.1:19082` | 本机惰性 fixture | 336 |
| `juice-shop:3000` | OWASP Juice Shop v18.0.0 | 339 |
| `vampi:5000` | VAmPI（Vulnerable API，镜像摘要锁定） | 416 |
| `webgoat:8080` | OWASP WebGoat v2025.3 | 336 |
| **合计** |  | **1,427** |

## 按数据层统计

| 数据层 | 含义 | 正常 | 攻击 | 合计 |
|---|---|---:|---:|---:|
| `field` | 字段/载荷 | 321,323 | 36,723 | **358,046** |
| `request` | 完整 HTTP 请求 | 188,085 | 91,462 | **279,547** |
| `context` | 请求、身份或会话上下文 | 367 | 836 | **1,203** |
| `protocol` | 协议事件/序列 | 16 | 92 | **108** |
| `llm_context` | LLM 对话/输出上下文 | 20 | 1,060 | **1,080** |
| **合计** |  | **509,811** | **130,173** | **639,984** |

`context`、`protocol`、`llm_context` 以及标记为不适用的完整请求依赖身份、会话、协议状态
或模型上下文，不应降级复制成单字段恶意标签。是否可用于字段模型以每条记录的
`_organized.payload_model_eligible` 为准。

## 数据划分数量

| split | 正常 | 攻击 | 合计 |
|---|---:|---:|---:|
| `train` | 382,093 | 20,422 | **402,515** |
| `validation` | 40,350 | 2,906 | **43,256** |
| `test` | 40,339 | 3,058 | **43,397** |
| `evaluation` | 47,014 | 90,123 | **137,137** |
| `unspecified` | 15 | 13,664 | **13,679** |
| **合计** | **509,811** | **130,173** | **639,984** |

`evaluation` 主要是 `data/validation/` 独立回归资料；`unspecified` 表示原数据没有声明
可复用划分，不能在正式实验中把它随机拆开后同时用于训练和测试。已有 split 和 group/campaign
边界应保持不变，避免同一原始载荷、CVE 或靶场 campaign 跨集合泄漏。

## 攻击类型及数量

以下数量是所有来源合并后的 `label=1` 记录数。英文名称和标准映射同时保存在
`taxonomy.json`，每类目录下的 `manifest.json` 还列出该类的数据层/split 分片。

| attack_type | 名称 | CWE / OWASP / CVE 映射 | 原始/非显式混淆 | 显式混淆 | 合计 |
|---|---|---|---:|---:|---:|
| `api_bfla` | Broken function-level authorization | `API5:2023` | 25 | 25 | **50** |
| `api_bola` | Broken object-level authorization / IDOR | `API1:2023` | 36 | 36 | **72** |
| `api_content_type_confusion` | API content-type parser confusion | `CWE-444` | 13 | 13 | **26** |
| `api_mass_assignment` | API mass assignment | `CWE-915` | 25 | 25 | **50** |
| `api_open_redirect` | API open redirect | `CWE-601` | 13 | 13 | **26** |
| `api_proto` | Prototype pollution | `CWE-1321` | 74 | 168 | **242** |
| `api_resource_consumption` | API resource consumption | `API4:2023` | 85 | 85 | **170** |
| `api_viewstate_integrity` | ViewState integrity failure | `CWE-345` | 13 | 13 | **26** |
| `business_flow_abuse` | Business-flow abuse | `API6:2023` | 24 | 24 | **48** |
| `cache_deception` | Web cache deception | `CWE-525` | 13 | 13 | **26** |
| `cache_poisoning` | Web cache poisoning | `CWE-444` | 17 | 17 | **34** |
| `cmdi` | OS command injection | `CWE-78` | 3,478 | 4,212 | **7,690** |
| `codei` | Code and expression injection | `CWE-94` | 1,730 | 2,101 | **3,831** |
| `cors_policy` | CORS policy abuse | `CWE-942` | 13 | 13 | **26** |
| `credential_stuffing` | Credential stuffing | `CWE-307` | 80 | 80 | **160** |
| `crlf` | CRLF / response splitting | `CWE-93` | 178 | 431 | **609** |
| `csrf` | Cross-site request forgery | `CWE-352` | 13 | 13 | **26** |
| `csv_formula` | Spreadsheet formula injection | `CWE-1236` | 119 | 119 | **238** |
| `deser` | Unsafe deserialization | `CWE-502` | 415 | 738 | **1,153** |
| `fmtst` | Format string injection | `CWE-134` | 60 | 224 | **284** |
| `fupl` | Unrestricted file upload | `CWE-434` | 144 | 456 | **600** |
| `graphql_complexity` | GraphQL complexity abuse | `CWE-400` | 13 | 13 | **26** |
| `graphql_introspection` | GraphQL schema discovery | `CWE-200` | 13 | 13 | **26** |
| `grpc_reflection` | gRPC reflection enumeration | `CWE-200` | 20 | 20 | **40** |
| `host_header_poisoning` | Host-header poisoning | `CWE-640` | 17 | 17 | **34** |
| `hpp` | HTTP parameter pollution | `CWE-235` | 85 | 199 | **284** |
| `hsmug` | HTTP request smuggling | `CWE-444` | 428 | 614 | **1,042** |
| `http2_pseudo_header_ambiguity` | HTTP/2 pseudo-header ambiguity | `CWE-444` | 8 | 8 | **16** |
| `http2_rapid_reset` | HTTP/2 Rapid Reset | `CVE-2023-44487` | 32 | 32 | **64** |
| `jndi` | JNDI lookup injection | `CWE-917` | 36 | 36 | **72** |
| `json_patch_authz` | JSON Patch property authorization | `CWE-915` | 13 | 13 | **26** |
| `jwt` | JWT implementation attacks | `CWE-347` | 112 | 257 | **369** |
| `ldap` | LDAP injection | `CWE-90` | 2,356 | 2,581 | **4,937** |
| `lfi` | Local file inclusion | `CWE-98` | 303 | 1,186 | **1,489** |
| `llm_direct_prompt_injection` | Direct LLM prompt injection | `OWASP LLM01` | 4 | 4 | **8** |
| `llm_indirect_rag_injection` | Indirect RAG prompt injection | `OWASP LLM01` | 514 | 514 | **1,028** |
| `llm_prompt_exfiltration` | LLM prompt exfiltration | `OWASP LLM02` | 4 | 4 | **8** |
| `llm_sensitive_output_disclosure` | LLM sensitive output disclosure | `OWASP LLM02` | 4 | 4 | **8** |
| `llm_tool_argument_injection` | LLM tool argument injection | `OWASP LLM06` | 4 | 4 | **8** |
| `logi` | Log injection / forging | `CWE-117` | 69 | 271 | **340** |
| `method_override` | HTTP method override bypass | `CWE-650` | 17 | 17 | **34** |
| `mfa_otp_abuse` | MFA / OTP guessing | `CWE-307` | 22 | 22 | **44** |
| `multipart_attack` | Malformed multipart request attack | `CWE-20` | 20 | 20 | **40** |
| `nosql` | NoSQL injection | `CWE-943` | 125 | 391 | **516** |
| `oauth_redirect` | OAuth redirect abuse | `CWE-601` | 13 | 13 | **26** |
| `oredir` | Open redirect | `CWE-601` | 203 | 1,003 | **1,206** |
| `protocol_violation` | HTTP protocol violation | `CWE-20` | 213 | 213 | **426** |
| `ptrav` | Path traversal | `CWE-22` | 2,955 | 3,848 | **6,803** |
| `race_condition` | Race condition / replay | `CWE-362` | 20 | 20 | **40** |
| `saml_signature_wrapping` | SAML signature wrapping | `CWE-347` | 13 | 13 | **26** |
| `scanner` | Vulnerability scanner behaviour | `CWE-799` | 125 | 125 | **250** |
| `scanner_probe` | Vulnerability scanner probes | `CWE-799` | 156 | 156 | **312** |
| `session_fixation` | Session fixation | `CWE-384` | 55 | 55 | **110** |
| `sqli` | SQL injection | `CWE-89` | 4,865 | 5,832 | **10,697** |
| `ssi` | Server-side include injection | `CWE-97` | 1,981 | 2,406 | **4,387** |
| `ssrf` | Server-side request forgery | `CWE-918` | 370 | 1,271 | **1,641** |
| `ssti` | Server-side template injection | `CWE-1336` | 291 | 1,187 | **1,478** |
| `upload` | Malicious upload request | `CWE-434` | 36 | 36 | **72** |
| `web_anomaly` | Mixed anomalous web request | `mixed/unspecified` | 25,065 | 25,065 | **50,130** |
| `webhook_replay` | Webhook signature / replay abuse | `CWE-294` | 16 | 16 | **32** |
| `websocket_cswh` | Cross-site WebSocket hijacking | `CWE-346` | 13 | 13 | **26** |
| `websocket_frame_validation` | WebSocket frame attacks | `CWE-20` | 8 | 8 | **16** |
| `xpath` | XPath injection | `CWE-643` | 2,330 | 2,459 | **4,789** |
| `xss` | Cross-site scripting | `CWE-79` | 9,806 | 10,747 | **20,553** |
| `xxe` | XML external entity injection | `CWE-611` | 262 | 1,045 | **1,307** |
| **合计（65 类）** |  |  | **59,583** | **70,590** | **130,173** |

## 原始与混淆处理口径

| 来源数据集 | 原始/非显式混淆 | 显式混淆 | 攻击合计 |
|---|---:|---:|---:|
| `all_original_obfuscated` | 0 | 59,583 | **59,583** |
| `augmented` | 52 | 0 | **52** |
| `enriched_traffic` | 704 | 1,354 | **2,058** |
| `external_deserialization/cve_requests` | 43 | 0 | **43** |
| `external_deserialization/gadget_fields` | 226 | 0 | **226** |
| `external_traffic/crs_requests` | 3,729 | 0 | **3,729** |
| `external_traffic/gap_payloads` | 205 | 0 | **205** |
| `external_traffic/llm_benchmark` | 510 | 0 | **510** |
| `external_traffic/payloads` | 8,768 | 0 | **8,768** |
| `external_traffic/requests` | 40,175 | 0 | **40,175** |
| `external_traffic/smuggling_requests` | 275 | 0 | **275** |
| `lab_captures` | 879 | 0 | **879** |
| `modern_attack_traffic` | 913 | 0 | **913** |
| `obfuscated_attack_traffic` | 0 | 9,040 | **9,040** |
| `raw_attack_traffic` | 2,260 | 0 | **2,260** |
| `specialized_traffic/api_context_sequences` | 94 | 0 | **94** |
| `specialized_traffic/high_value_context_sequences` | 324 | 0 | **324** |
| `specialized_traffic/llm_context_sequences` | 20 | 0 | **20** |
| `specialized_traffic/payloads` | 62 | 310 | **372** |
| `specialized_traffic/protocol_sequences` | 46 | 0 | **46** |
| `specialized_traffic/scanner_sequences` | 120 | 0 | **120** |
| `validation` | 178 | 303 | **481** |
| **合计** | **59,583** | **70,590** | **130,173** |

判定顺序和处理方式：

1. `data/attack_traffic/*/dataset_obfuscated.json` 全部归入显式混淆；记录保留
   `original_id`、`original_payload`、`obfuscation_chain`、深度和解码要求。
2. `data/all_original_obfuscated/generated/` 对统一视图的每条原始攻击生成至少一条
   确定性派生记录，保留原始 organized ID、来源文件、原始内容、策略链和解码要求。
3. `enriched_traffic` 中 `variant=url/double_url` 的攻击对归入显式混淆，`variant=raw`
   归入原始；同一 `group_id` 不跨训练、验证和测试集合。
4. `specialized_traffic/payloads` 中 `encoding!=raw` 且有 `decoded_payload` 的记录归入
   显式混淆；`encoding=raw` 保留在原始目录。
5. `validation` 中 ID 明确包含 `_obf_` 或 `_combo_` 的回归样本归入显式混淆；其他
   独立语义边界和公开样本归入原始。
6. 其余来源若没有可审计的派生字段，统一归入原始/非显式混淆，不根据字符串外观猜测。
   这样不会把攻击者原生编码、完整请求或二进制对象的规范 Base64 载体错误改写成派生数据。
7. 所有记录原字段均保留，只增加 `_organized` 溯源信息；不去重、不改标签、不把请求/
   上下文/协议序列降级成字段 payload。输入和输出 SHA-256 均记录在 `manifest.json`。

## 目录和记录格式

```text
organized/
├── README.md
├── manifest.json                 # 总量、来源、层级、split、哈希和审计
├── taxonomy.json                 # 攻击类型名称与标准映射
├── normal/
│   ├── manifest.json
│   └── <data_level>/<split>.jsonl
└── attack/
    ├── manifest.json
    ├── original/                 # 原始/非显式混淆攻击
    │   ├── manifest.json
    │   └── <attack_type>/<data_level>/<split>.jsonl
    └── obfuscated/               # 有明确派生证据的混淆攻击
        ├── manifest.json
        └── <attack_type>/<data_level>/<split>.jsonl
```

JSONL 使用 UTF-8 编码，每行是一条完整 JSON 记录，适合流式读取。原记录字段被保留，
并额外加入 `_organized`：

| 字段 | 含义 |
|---|---|
| `id` | 由来源文件和原记录序号生成的稳定整理视图 ID |
| `source_file` | 项目根目录相对路径，定位原始 JSON 文件 |
| `source_record_index` | 原 JSON 数组中的 1 基序号 |
| `source_dataset` | 本 README 来源表使用的逻辑数据集名称 |
| `data_level` | `field` / `request` / `context` / `protocol` / `llm_context` |
| `split` | `train` / `validation` / `test` / `evaluation` / `unspecified` |
| `content_sha256` | 数据层和内容的 SHA-256，用于内容重复与跨标签冲突检查 |
| `record_sha256` | 标签、攻击类型、数据层和内容的 SHA-256 |
| `payload_model_eligible` | 是否允许作为当前单字段 payload 模型候选输入 |
| `attack_representation` | 攻击记录的 `original` / `obfuscated` 归档结果 |
| `attack_representation_basis` | 本次归档采用的可审计判定依据 |

## 纳入、排除与审计

纳入范围是生成器 `input_files()` 找到且每条记录具有明确 `label=0/1` 的 JSON 数组。
统一视图保留合法的内容重复，不会静默去重或改变标签；所有输入文件和输出 JSONL 的
记录数、字节数与 SHA-256 均在 `manifest.json` 中。当前内容审计结果：

| 审计项 | 数量 |
|---|---:|
| 唯一内容指纹 | 638,660 |
| 唯一“标签 + 类型 + 内容”指纹 | 638,752 |
| 正常/攻击跨标签内容冲突 | **0** |

明确排除：

- `data/attack_traffic/_all (duplicate aggregate)`；
- `data/archives (source archives, not labelled records)`；
- `data/modern_attack_traffic/source_snapshots (metadata, not labelled records)`；
- `data/external_traffic/source_snapshots (pinned public source snapshots, not duplicate labelled records)`；
- `data/external_deserialization/source_snapshots (pinned source archives and canonical one-per-gadget derivations)`；
- `lab/captures raw JSONL (same requests are represented by the redacted generated export)`；

## 重建和验证

```bash
python3 run.py organize-data
python3 run.py validate-data --deep
```

不要直接维护本 README 中的数字：`organize-data` 会删除并重建整个 `data/organized/`，
README、总清单、分类清单和 JSONL 会一起重新生成。若只需机器可读的精确统计和文件哈希，
以同目录 `manifest.json` 为准。

## 使用边界

数据集中存在某类样本，只表示该类已有训练/评测资料，**不等于当前部署的运行时已经能够
完整防御该漏洞**。BOLA/BFLA、业务流程、竞态、协议攻击、LLM 安全等类别需要身份、会话、
限速、网关协议状态或专用安全层；模型效果仍须用独立测试集、时间外数据和授权生产流量验证。
本数据集只用于授权防御、隔离靶场、训练和评测。
