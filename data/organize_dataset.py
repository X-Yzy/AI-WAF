#!/usr/bin/env python3
"""Build a non-destructive normal/attack view of every labelled repository dataset.

The original datasets remain authoritative and untouched.  This script streams
their records into JSONL shards under ``data/organized`` while retaining source
provenance, split, data level and model-scope metadata.  Complete-request,
sequence, protocol and LLM labels are never converted into field labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DEFAULT_OUTPUT = DATA / "organized"
VALID_SPLITS = {"train", "validation", "test", "evaluation", "unspecified"}
VALID_DATA_LEVELS = {"field", "request", "context", "protocol", "llm_context"}


TAXONOMY = {
    "api_bfla": ("Broken function-level authorization", "API5:2023"),
    "api_bola": ("Broken object-level authorization / IDOR", "API1:2023"),
    "api_content_type_confusion": ("API content-type parser confusion", "CWE-444"),
    "api_mass_assignment": ("API mass assignment", "CWE-915"),
    "api_open_redirect": ("API open redirect", "CWE-601"),
    "api_proto": ("Prototype pollution", "CWE-1321"),
    "api_resource_consumption": ("API resource consumption", "API4:2023"),
    "api_viewstate_integrity": ("ViewState integrity failure", "CWE-345"),
    "business_flow_abuse": ("Business-flow abuse", "API6:2023"),
    "cache_deception": ("Web cache deception", "CWE-525"),
    "cache_poisoning": ("Web cache poisoning", "CWE-444"),
    "cmdi": ("OS command injection", "CWE-78"),
    "codei": ("Code and expression injection", "CWE-94"),
    "cors_policy": ("CORS policy abuse", "CWE-942"),
    "credential_stuffing": ("Credential stuffing", "CWE-307"),
    "crlf": ("CRLF / response splitting", "CWE-93"),
    "csrf": ("Cross-site request forgery", "CWE-352"),
    "csv_formula": ("Spreadsheet formula injection", "CWE-1236"),
    "deser": ("Unsafe deserialization", "CWE-502"),
    "fmtst": ("Format string injection", "CWE-134"),
    "fupl": ("Unrestricted file upload", "CWE-434"),
    "graphql_complexity": ("GraphQL complexity abuse", "CWE-400"),
    "graphql_introspection": ("GraphQL schema discovery", "CWE-200"),
    "grpc_reflection": ("gRPC reflection enumeration", "CWE-200"),
    "host_header_poisoning": ("Host-header poisoning", "CWE-640"),
    "hpp": ("HTTP parameter pollution", "CWE-235"),
    "hsmug": ("HTTP request smuggling", "CWE-444"),
    "http2_pseudo_header_ambiguity": ("HTTP/2 pseudo-header ambiguity", "CWE-444"),
    "http2_rapid_reset": ("HTTP/2 Rapid Reset", "CVE-2023-44487"),
    "jndi": ("JNDI lookup injection", "CWE-917"),
    "json_patch_authz": ("JSON Patch property authorization", "CWE-915"),
    "jwt": ("JWT implementation attacks", "CWE-347"),
    "ldap": ("LDAP injection", "CWE-90"),
    "lfi": ("Local file inclusion", "CWE-98"),
    "llm_direct_prompt_injection": ("Direct LLM prompt injection", "OWASP LLM01"),
    "llm_indirect_rag_injection": ("Indirect RAG prompt injection", "OWASP LLM01"),
    "llm_prompt_exfiltration": ("LLM prompt exfiltration", "OWASP LLM02"),
    "llm_sensitive_output_disclosure": ("LLM sensitive output disclosure", "OWASP LLM02"),
    "llm_tool_argument_injection": ("LLM tool argument injection", "OWASP LLM06"),
    "logi": ("Log injection / forging", "CWE-117"),
    "method_override": ("HTTP method override bypass", "CWE-650"),
    "multipart_attack": ("Malformed multipart request attack", "CWE-20"),
    "mfa_otp_abuse": ("MFA / OTP guessing", "CWE-307"),
    "nosql": ("NoSQL injection", "CWE-943"),
    "oauth_redirect": ("OAuth redirect abuse", "CWE-601"),
    "oredir": ("Open redirect", "CWE-601"),
    "ptrav": ("Path traversal", "CWE-22"),
    "protocol_violation": ("HTTP protocol violation", "CWE-20"),
    "race_condition": ("Race condition / replay", "CWE-362"),
    "saml_signature_wrapping": ("SAML signature wrapping", "CWE-347"),
    "scanner": ("Vulnerability scanner behaviour", "CWE-799"),
    "scanner_probe": ("Vulnerability scanner probes", "CWE-799"),
    "session_fixation": ("Session fixation", "CWE-384"),
    "sqli": ("SQL injection", "CWE-89"),
    "ssi": ("Server-side include injection", "CWE-97"),
    "ssrf": ("Server-side request forgery", "CWE-918"),
    "ssti": ("Server-side template injection", "CWE-1336"),
    "upload": ("Malicious upload request", "CWE-434"),
    "webhook_replay": ("Webhook signature / replay abuse", "CWE-294"),
    "websocket_cswh": ("Cross-site WebSocket hijacking", "CWE-346"),
    "websocket_frame_validation": ("WebSocket frame attacks", "CWE-20"),
    "web_anomaly": ("Mixed anomalous web request", "mixed/unspecified"),
    "xpath": ("XPath injection", "CWE-643"),
    "xss": ("Cross-site scripting", "CWE-79"),
    "xxe": ("XML external entity injection", "CWE-611"),
}


SOURCE_DOCUMENTATION = {
    "normal_traffic/payload_level": (
        "`data/normal_traffic/generated/payload_level/`",
        "本项目生成器（固定 seed）",
        "普通表单、查询、JSON/XML、文件名、URL、认证头等合法字段级负样本",
    ),
    "normal_traffic/http_requests": (
        "`data/normal_traffic/generated/http_requests/`",
        "本项目生成器（固定 seed）",
        "搜索、登录、订单、评论、上传元数据等传统完整正常 HTTP 请求",
    ),
    "normal_traffic/modern_http_requests": (
        "`data/normal_traffic/generated/modern_http_requests/`",
        "本项目生成器（固定 seed）",
        "GraphQL、OAuth/OIDC、WebAuthn、Webhook、gRPC-Web、WebSocket、SSE、云原生等现代正常请求",
    ),
    "normal_traffic/hard_negatives": (
        "`data/normal_traffic/generated/hard_negatives/`",
        "本项目生成器（固定 seed）",
        "含 SQL、HTML、Shell、路径、模板等安全技术文本的合法难负样本",
    ),
    "raw_attack_traffic": (
        "`data/raw_attack_traffic/*/source_records.json`",
        "PayloadsAllTheThings、fuzzdb",
        "22 类公开未混淆攻击载荷；保留来源 URL、版本、许可证与原文件",
    ),
    "obfuscated_attack_traffic": (
        "`data/attack_traffic/*/dataset_obfuscated.json`",
        "本项目混淆生成器，派生自 raw_attack_traffic",
        "原始攻击载荷的编码、大小写和语法等变体；与原载荷按家族绑定",
    ),
    "all_original_obfuscated": (
        "`data/all_original_obfuscated/generated/`",
        "本项目混淆生成器，逐条派生自统一视图中的全部原始攻击",
        "每条原始攻击至少一条确定性编码变体；继承数据层和 split，非字段表示不进入字段模型",
    ),
    "modern_attack_traffic": (
        "`data/modern_attack_traffic/generated/`",
        "ProjectDiscovery Nuclei Templates；CISA KEV 作为优先级元数据",
        "离线解析 2024—2026 年 CVE 模板后提取的明确攻击字段和完整请求；未执行模板或探测公网目标",
    ),
    "specialized_traffic/payloads": (
        "`data/specialized_traffic/generated/payloads/`",
        "本项目专项生成器",
        "反序列化、原型污染、NoSQL、JNDI、XXE、请求走私、HPP、上传等正负字段样本",
    ),
    "specialized_traffic/api_context_sequences": (
        "`data/specialized_traffic/generated/api_context_sequences/`",
        "本项目专项生成器",
        "BOLA/BFLA、Mass Assignment、OAuth、GraphQL、缓存、鉴权、竞态和业务流程等上下文序列",
    ),
    "specialized_traffic/high_value_context_sequences": (
        "`data/specialized_traffic/generated/high_value_context_sequences/`",
        "本项目高价值上下文生成器（成对正负对照）",
        "API 授权、身份、缓存、GraphQL、WebSocket、gRPC 和业务流程的多场景上下文对照",
    ),
    "specialized_traffic/protocol_sequences": (
        "`data/specialized_traffic/generated/protocol_sequences/`",
        "本项目专项生成器",
        "HTTP/2 伪头与 Rapid Reset、WebSocket 帧和消息预算等协议序列",
    ),
    "specialized_traffic/llm_context_sequences": (
        "`data/specialized_traffic/generated/llm_context_sequences/`",
        "本项目专项生成器",
        "直接/间接 Prompt Injection、RAG/工具注入、Prompt 外泄和敏感输出正负上下文",
    ),
    "specialized_traffic/scanner_sequences": (
        "`data/specialized_traffic/generated/scanner_sequences/`",
        "本项目专项生成器",
        "Nuclei、sqlmap、Nikto、ffuf、Gobuster、dirsearch、ZAP、Wapiti 扫描序列及正常对照",
    ),
    "enriched_traffic": (
        "`data/enriched_traffic/generated/`",
        "本项目对比式字段生成器（固定 seed）",
        "22 类字段攻击的分组编码变体与成对正常难负样本；同组不跨训练/验证/测试",
    ),
    "external_traffic/payloads": (
        "`data/external_traffic/generated/payloads/`",
        "grananqvist Machine-Learning WAF Dataset（MIT，锁定提交）",
        "独立公开正常、XSS、SQLi、命令/路径字段；按内容哈希去重和切分",
    ),
    "external_traffic/requests": (
        "`data/external_traffic/generated/requests/`",
        "ECML/PKDD 2007、CSIC 2010（经 GPL-3.0 汇编仓库获取）",
        "脱敏真实流量与靶场生成的完整正常/攻击 HTTP 请求；原始测试分区仅作评测",
    ),
    "external_traffic/crs_requests": (
        "`data/external_traffic/generated/crs_requests/`",
        "OWASP Core Rule Set regression tests（Apache-2.0，锁定提交）",
        "带明确规则期望的完整攻击请求和保守筛选的正常难负例；仅作独立评测",
    ),
    "external_traffic/gap_payloads": (
        "`data/external_traffic/generated/gap_payloads/`",
        "PayloadBox CSV 与 HTTP Protocol Injection（MIT，锁定提交）",
        "补充 CSV 公式、CRLF、缓存/Host 头、HPP、HTTP/2 与走私字段；上下文类排除出字段模型",
    ),
    "external_traffic/smuggling_requests": (
        "`data/external_traffic/generated/smuggling_requests/`",
        "PayloadBox HTTP Request Smuggling Payloads（MIT，锁定提交）",
        "独立完整 CL.TE、TE.CL、TE.TE、HTTP/2 desync 等请求；仅作 evaluation",
    ),
    "external_traffic/llm_benchmark": (
        "`data/external_traffic/generated/llm_benchmark/`",
        "PIArena InjecAgent（MIT，锁定提交）",
        "预构建的用户任务、污染工具响应、攻击目标与预期危害组合；仅作 LLM evaluation",
    ),
    "external_deserialization/gadget_fields": (
        "`data/external_deserialization/generated/gadget_fields/`",
        "PHPGGC、JexBoss、ysoserial、marshalsec、ysoserial.net 与 Python 生成器（来源和许可证锁定）",
        "每个上游 gadget、marshaller 或格式入口只保留一个规范对象；按框架/依赖家族切分，不生成编码变体",
    ),
    "external_deserialization/cve_requests": (
        "`data/external_deserialization/generated/cve_requests/`",
        "ProjectDiscovery Nuclei Templates（MIT，锁定提交）",
        "带明确序列化对象载体的独立 CVE 完整请求；仅作 evaluation，不进入字段模型",
    ),
    "lab_captures": (
        "`data/lab_captures/generated/`",
        "隔离本机 fixture、OWASP Juice Shop v18.0.0、OWASP WebGoat v2025.3",
        "经采集代理实际转发、响应、脱敏并导出的完整 HTTP 请求；按 campaign 分组",
    ),
    "augmented": (
        "`data/augmented/*.json`",
        "本项目定向人工/程序增强",
        "针对 SQLi 大小写、路径上下文、JWT 等已知检测边界的补充样本",
    ),
    "validation": (
        "`data/validation/*.json`",
        "本项目独立回归与语义边界集",
        "基础/中度/重度混淆、语义边界和格式示例；统一视图中标为 evaluation",
    ),
}

SOURCE_ORDER = tuple(SOURCE_DOCUMENTATION)
LEVEL_DOCUMENTATION = {
    "field": "字段/载荷",
    "request": "完整 HTTP 请求",
    "context": "请求、身份或会话上下文",
    "protocol": "协议事件/序列",
    "llm_context": "LLM 对话/输出上下文",
}
LEVEL_ORDER = tuple(LEVEL_DOCUMENTATION)
SPLIT_ORDER = ("train", "validation", "test", "evaluation", "unspecified")
LAB_TARGET_NAMES = {
    "127.0.0.1:19082": "本机惰性 fixture",
    "juice-shop:3000": "OWASP Juice Shop v18.0.0",
    "webgoat:8080": "OWASP WebGoat v2025.3",
    "vampi:5000": "VAmPI（Vulnerable API，镜像摘要锁定）",
}


def fmt_count(value: int) -> str:
    return f"{value:,}"


def build_readme(manifest: dict, taxonomy: dict) -> str:
    """Render human-readable documentation from the generated manifest."""
    labels = manifest["label_counts"]
    source_counts = manifest["source_dataset_counts"]
    source_labels = manifest["source_label_counts"]
    level_counts = manifest["data_level_counts"]
    split_counts = manifest["split_counts"]
    representation_counts = manifest["attack_representation_counts"]
    representation_types = manifest["attack_representation_type_counts"]
    representation_sources = manifest["attack_representation_source_counts"]
    audit = manifest["content_audit"]
    lines = [
        "# 统一整理数据集",
        "",
        "本目录是项目全部带标签数据的**非破坏性派生视图**，由",
        "`python3 data/organize_dataset.py`（或 `python3 run.py organize-data`）生成。",
        "原始 JSON 数据仍保存在各来源目录，本目录不移动、不覆盖原始数据。下列数量全部由",
        "本次生成的 `manifest.json` 自动写入；以后扩充数据并重建时会同步更新。",
        "",
        "## 总体规模",
        "",
        "| 指标 | 数量 |",
        "|---|---:|",
        f"| 全部记录 | **{fmt_count(manifest['total_records'])}** |",
        f"| 正常记录（`label=0`） | **{fmt_count(labels['normal'])}** |",
        f"| 攻击记录（`label=1`） | **{fmt_count(labels['attack'])}** |",
        f"| 原始/非显式混淆攻击 | **{fmt_count(representation_counts['original'])}** |",
        f"| 显式混淆派生攻击 | **{fmt_count(representation_counts['obfuscated'])}** |",
        f"| 攻击类型 | **{fmt_count(manifest['attack_families'])}** |",
        f"| JSONL 分片 | **{fmt_count(len(manifest['artifacts']))}** |",
        "",
        "这里的“记录”可能是字段、完整请求或上下文/协议序列，不能全部当作字段级 payload。",
        "此外，公开原始载荷及其混淆派生变体会分别计数，因此总记录数不等于独立攻击原语数。",
        "这里的“原始攻击”严格表示**没有显式混淆派生证据**，包括公开原始 payload、CVE 请求、",
        "授权靶场请求、协议/上下文攻击和规范序列化对象；不保证每条都是网络抓包原文。只有能追溯",
        "到原值和变换方式的记录才进入 `attack/obfuscated/`。二进制序列化对象唯一的 Base64 HTTP",
        "载体属于规范传输格式，不会在 `is_encoding_variant=false` 时被误判为混淆。",
        "",
        "## 数据来源与数量",
        "",
        "| 来源数据集 | 原始位置 | 形成方式/上游来源 | 数据内容 | 正常 | 攻击 | 合计 |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    ordered_sources = list(SOURCE_ORDER) + sorted(set(source_counts) - set(SOURCE_ORDER))
    for source in ordered_sources:
        if source not in source_counts:
            continue
        location, origin, description = SOURCE_DOCUMENTATION.get(
            source, ("见 `_organized.source_file`", "未登记", "未登记来源数据")
        )
        by_label = source_labels.get(source, {})
        lines.append(
            f"| `{source}` | {location} | {origin} | {description} | "
            f"{fmt_count(by_label.get('normal', 0))} | {fmt_count(by_label.get('attack', 0))} | "
            f"**{fmt_count(source_counts[source])}** |"
        )
    lines.extend([
        f"| **合计** |  |  |  | **{fmt_count(labels['normal'])}** | "
        f"**{fmt_count(labels['attack'])}** | **{fmt_count(manifest['total_records'])}** |",
        "",
        "### 公开来源和版本边界",
        "",
        "- `raw_attack_traffic` 的公开原始攻击载荷来自 PayloadsAllTheThings 和 fuzzdb；",
        "  精确 commit/version、URL 与许可证见 `../raw_attack_traffic/manifest.json` 及该目录许可证文件。",
        "- `modern_attack_traffic` 来自锁定版本的 ProjectDiscovery Nuclei HTTP 模板；CISA KEV",
        "  只提供在野利用优先级元数据。精确模板版本、归档 SHA-256、KEV 目录版本和筛选审计见",
        "  `../modern_attack_traffic/generated/manifest.json`。模板仅离线解析，没有执行或向公网发请求。",
        "- `external_traffic` 来自多个锁定提交：MIT 的 grananqvist ML-WAF、PayloadBox 与 PIArena、",
        "  经 GPL-3.0 汇编仓库取得的 ECML/PKDD 2007 与 CSIC 2010，以及 Apache-2.0 的 OWASP CRS。",
        "  精确 URL、提交、许可证说明和哈希见 `../external_traffic/generated/manifest.json`。",
        "  ECML/CSIC 原始测试分区与全部 CRS 规则标签只用于 evaluation。",
        "- 正常流量和 specialized 五组是本项目使用固定 seed 生成的合成数据，用于覆盖格式与边界，",
        "  不代表生产业务的自然分布；上线前仍需用经授权、脱敏的真实业务流量校准。",
        "- `augmented` 与 `validation` 是项目本地定向增强和回归资料，不是独立的公网采集语料。",
        "- `all_original_obfuscated` 是从全部原始攻击逐条生成的派生表示，不是新的独立攻击样本。",
        "  字段载荷可用于解码鲁棒性训练/评测；请求、上下文、协议和 LLM 的编码表示只用于",
        "  表示层归一化测试，并继续排除在单字段模型之外。",
        "",
        "### 隔离靶场捕获来源",
        "",
        "`lab_captures` 是通过回环采集代理实际发送并获得后端响应的请求，不是只拼接出来的字符串。",
        "敏感请求头、查询参数和 JSON secret 字段在采集时脱敏；所有靶场请求均排除在单字段模型之外。",
        "",
        "| `lab_target` | 靶场 | 记录数 |",
        "|---|---|---:|",
    ])
    for target, count in manifest.get("lab_target_counts", {}).items():
        lines.append(f"| `{target}` | {LAB_TARGET_NAMES.get(target, target)} | {fmt_count(count)} |")
    if manifest.get("lab_target_counts"):
        lines.append(
            f"| **合计** |  | **{fmt_count(sum(manifest['lab_target_counts'].values()))}** |"
        )
    lines.extend([
        "",
        "## 按数据层统计",
        "",
        "| 数据层 | 含义 | 正常 | 攻击 | 合计 |",
        "|---|---|---:|---:|---:|",
    ])
    all_levels = list(LEVEL_ORDER) + sorted(
        (set(level_counts["normal"]) | set(level_counts["attack"])) - set(LEVEL_ORDER)
    )
    for level in all_levels:
        normal = level_counts["normal"].get(level, 0)
        attack = level_counts["attack"].get(level, 0)
        if normal + attack:
            lines.append(
                f"| `{level}` | {LEVEL_DOCUMENTATION.get(level, level)} | {fmt_count(normal)} | "
                f"{fmt_count(attack)} | **{fmt_count(normal + attack)}** |"
            )
    lines.extend([
        f"| **合计** |  | **{fmt_count(labels['normal'])}** | **{fmt_count(labels['attack'])}** | "
        f"**{fmt_count(manifest['total_records'])}** |",
        "",
        "`context`、`protocol`、`llm_context` 以及标记为不适用的完整请求依赖身份、会话、协议状态",
        "或模型上下文，不应降级复制成单字段恶意标签。是否可用于字段模型以每条记录的",
        "`_organized.payload_model_eligible` 为准。",
        "",
        "## 数据划分数量",
        "",
        "| split | 正常 | 攻击 | 合计 |",
        "|---|---:|---:|---:|",
    ])
    for split in SPLIT_ORDER:
        normal = split_counts["normal"].get(split, 0)
        attack = split_counts["attack"].get(split, 0)
        lines.append(
            f"| `{split}` | {fmt_count(normal)} | {fmt_count(attack)} | "
            f"**{fmt_count(normal + attack)}** |"
        )
    lines.extend([
        f"| **合计** | **{fmt_count(labels['normal'])}** | **{fmt_count(labels['attack'])}** | "
        f"**{fmt_count(manifest['total_records'])}** |",
        "",
        "`evaluation` 主要是 `data/validation/` 独立回归资料；`unspecified` 表示原数据没有声明",
        "可复用划分，不能在正式实验中把它随机拆开后同时用于训练和测试。已有 split 和 group/campaign",
        "边界应保持不变，避免同一原始载荷、CVE 或靶场 campaign 跨集合泄漏。",
        "",
        "## 攻击类型及数量",
        "",
        "以下数量是所有来源合并后的 `label=1` 记录数。英文名称和标准映射同时保存在",
        "`taxonomy.json`，每类目录下的 `manifest.json` 还列出该类的数据层/split 分片。",
        "",
        "| attack_type | 名称 | CWE / OWASP / CVE 映射 | 原始/非显式混淆 | 显式混淆 | 合计 |",
        "|---|---|---|---:|---:|---:|",
    ])
    for family, count in manifest["attack_type_counts"].items():
        item = taxonomy[family]
        lines.append(
            f"| `{family}` | {item['title']} | `{item['standard']}` | "
            f"{fmt_count(representation_types['original'].get(family, 0))} | "
            f"{fmt_count(representation_types['obfuscated'].get(family, 0))} | "
            f"**{fmt_count(count)}** |"
        )
    lines.extend([
        f"| **合计（{fmt_count(manifest['attack_families'])} 类）** |  |  | "
        f"**{fmt_count(representation_counts['original'])}** | "
        f"**{fmt_count(representation_counts['obfuscated'])}** | "
        f"**{fmt_count(labels['attack'])}** |",
        "",
        "## 原始与混淆处理口径",
        "",
        "| 来源数据集 | 原始/非显式混淆 | 显式混淆 | 攻击合计 |",
        "|---|---:|---:|---:|",
    ])
    attack_sources = sorted(
        set(representation_sources.get("original", {}))
        | set(representation_sources.get("obfuscated", {}))
    )
    for source in attack_sources:
        original = representation_sources.get("original", {}).get(source, 0)
        obfuscated = representation_sources.get("obfuscated", {}).get(source, 0)
        lines.append(
            f"| `{source}` | {fmt_count(original)} | {fmt_count(obfuscated)} | "
            f"**{fmt_count(original + obfuscated)}** |"
        )
    lines.extend([
        f"| **合计** | **{fmt_count(representation_counts['original'])}** | "
        f"**{fmt_count(representation_counts['obfuscated'])}** | "
        f"**{fmt_count(labels['attack'])}** |",
        "",
        "判定顺序和处理方式：",
        "",
        "1. `data/attack_traffic/*/dataset_obfuscated.json` 全部归入显式混淆；记录保留",
        "   `original_id`、`original_payload`、`obfuscation_chain`、深度和解码要求。",
        "2. `data/all_original_obfuscated/generated/` 对统一视图的每条原始攻击生成至少一条",
        "   确定性派生记录，保留原始 organized ID、来源文件、原始内容、策略链和解码要求。",
        "3. `enriched_traffic` 中 `variant=url/double_url` 的攻击对归入显式混淆，`variant=raw`",
        "   归入原始；同一 `group_id` 不跨训练、验证和测试集合。",
        "4. `specialized_traffic/payloads` 中 `encoding!=raw` 且有 `decoded_payload` 的记录归入",
        "   显式混淆；`encoding=raw` 保留在原始目录。",
        "5. `validation` 中 ID 明确包含 `_obf_` 或 `_combo_` 的回归样本归入显式混淆；其他",
        "   独立语义边界和公开样本归入原始。",
        "6. 其余来源若没有可审计的派生字段，统一归入原始/非显式混淆，不根据字符串外观猜测。",
        "   这样不会把攻击者原生编码、完整请求或二进制对象的规范 Base64 载体错误改写成派生数据。",
        "7. 所有记录原字段均保留，只增加 `_organized` 溯源信息；不去重、不改标签、不把请求/",
        "   上下文/协议序列降级成字段 payload。输入和输出 SHA-256 均记录在 `manifest.json`。",
        "",
        "## 目录和记录格式",
        "",
        "```text",
        "organized/",
        "├── README.md",
        "├── manifest.json                 # 总量、来源、层级、split、哈希和审计",
        "├── taxonomy.json                 # 攻击类型名称与标准映射",
        "├── normal/",
        "│   ├── manifest.json",
        "│   └── <data_level>/<split>.jsonl",
        "└── attack/",
        "    ├── manifest.json",
        "    ├── original/                 # 原始/非显式混淆攻击",
        "    │   ├── manifest.json",
        "    │   └── <attack_type>/<data_level>/<split>.jsonl",
        "    └── obfuscated/               # 有明确派生证据的混淆攻击",
        "        ├── manifest.json",
        "        └── <attack_type>/<data_level>/<split>.jsonl",
        "```",
        "",
        "JSONL 使用 UTF-8 编码，每行是一条完整 JSON 记录，适合流式读取。原记录字段被保留，",
        "并额外加入 `_organized`：",
        "",
        "| 字段 | 含义 |",
        "|---|---|",
        "| `id` | 由来源文件和原记录序号生成的稳定整理视图 ID |",
        "| `source_file` | 项目根目录相对路径，定位原始 JSON 文件 |",
        "| `source_record_index` | 原 JSON 数组中的 1 基序号 |",
        "| `source_dataset` | 本 README 来源表使用的逻辑数据集名称 |",
        "| `data_level` | `field` / `request` / `context` / `protocol` / `llm_context` |",
        "| `split` | `train` / `validation` / `test` / `evaluation` / `unspecified` |",
        "| `content_sha256` | 数据层和内容的 SHA-256，用于内容重复与跨标签冲突检查 |",
        "| `record_sha256` | 标签、攻击类型、数据层和内容的 SHA-256 |",
        "| `payload_model_eligible` | 是否允许作为当前单字段 payload 模型候选输入 |",
        "| `attack_representation` | 攻击记录的 `original` / `obfuscated` 归档结果 |",
        "| `attack_representation_basis` | 本次归档采用的可审计判定依据 |",
        "",
        "## 纳入、排除与审计",
        "",
        "纳入范围是生成器 `input_files()` 找到且每条记录具有明确 `label=0/1` 的 JSON 数组。",
        "统一视图保留合法的内容重复，不会静默去重或改变标签；所有输入文件和输出 JSONL 的",
        "记录数、字节数与 SHA-256 均在 `manifest.json` 中。当前内容审计结果：",
        "",
        "| 审计项 | 数量 |",
        "|---|---:|",
        f"| 唯一内容指纹 | {fmt_count(audit['unique_content_fingerprints'])} |",
        f"| 唯一“标签 + 类型 + 内容”指纹 | {fmt_count(audit['unique_label_type_content_records'])} |",
        f"| 正常/攻击跨标签内容冲突 | **{fmt_count(audit['cross_label_content_conflicts'])}** |",
        "",
        "明确排除：",
        "",
    ])
    lines.extend(f"- `{item}`；" for item in manifest["excluded"])
    lines.extend([
        "",
        "## 重建和验证",
        "",
        "```bash",
        "python3 run.py organize-data",
        "python3 run.py validate-data --deep",
        "```",
        "",
        "不要直接维护本 README 中的数字：`organize-data` 会删除并重建整个 `data/organized/`，",
        "README、总清单、分类清单和 JSONL 会一起重新生成。若只需机器可读的精确统计和文件哈希，",
        "以同目录 `manifest.json` 为准。",
        "",
        "## 使用边界",
        "",
        "数据集中存在某类样本，只表示该类已有训练/评测资料，**不等于当前部署的运行时已经能够",
        "完整防御该漏洞**。BOLA/BFLA、业务流程、竞态、协议攻击、LLM 安全等类别需要身份、会话、",
        "限速、网关协议状态或专用安全层；模型效果仍须用独立测试集、时间外数据和授权生产流量验证。",
        "本数据集只用于授权防御、隔离靶场、训练和评测。",
        "",
    ])
    return "\n".join(lines)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_array(path: Path) -> list[dict]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError(f"expected a JSON array: {path}")
    if any(not isinstance(item, dict) for item in value):
        raise ValueError(f"non-object record in: {path}")
    return value


def input_files() -> list[Path]:
    patterns = (
        "normal_traffic/generated/*/dataset_*.json",
        "raw_attack_traffic/*/source_records.json",
        "attack_traffic/*/dataset_obfuscated.json",
        "all_original_obfuscated/generated/*/dataset_all_original_obfuscated_*.json",
        "modern_attack_traffic/generated/dataset_modern_attack_*.json",
        "specialized_traffic/generated/*/dataset_*.json",
        "enriched_traffic/generated/dataset_enriched_*.json",
        "lab_captures/generated/dataset_lab_capture_*.json",
        "external_traffic/generated/*/dataset_external_*.json",
        "external_deserialization/generated/*/dataset_external_deser_*.json",
        "augmented/*.json",
        "validation/*.json",
    )
    result: list[Path] = []
    for pattern in patterns:
        result.extend(sorted(DATA.glob(pattern)))
    # attack_traffic/_all is a convenience duplicate of the per-family files.
    return sorted({path for path in result if "_all" not in path.parts})


def source_dataset(path: Path) -> str:
    relative = path.relative_to(DATA)
    if relative.parts[0] == "normal_traffic":
        return f"normal_traffic/{relative.parts[2]}"
    if relative.parts[0] == "raw_attack_traffic":
        return "raw_attack_traffic"
    if relative.parts[0] == "attack_traffic":
        return "obfuscated_attack_traffic"
    if relative.parts[0] == "all_original_obfuscated":
        return "all_original_obfuscated"
    if relative.parts[0] == "modern_attack_traffic":
        return "modern_attack_traffic"
    if relative.parts[0] == "specialized_traffic":
        return f"specialized_traffic/{relative.parts[2]}"
    if relative.parts[0] == "enriched_traffic":
        return "enriched_traffic"
    if relative.parts[0] == "lab_captures":
        return "lab_captures"
    if relative.parts[0] == "external_traffic":
        return f"external_traffic/{relative.parts[2]}"
    if relative.parts[0] == "external_deserialization":
        return f"external_deserialization/{relative.parts[2]}"
    return relative.parts[0]


def infer_split(path: Path, record: dict) -> str:
    declared = str(record.get("split", "")).lower()
    if declared in VALID_SPLITS:
        return declared
    if path.relative_to(DATA).parts[0] == "validation":
        return "evaluation"
    name = path.stem.lower()
    for value in ("validation", "train", "test"):
        if re.search(rf"(?:^|_){value}(?:_|$)", name):
            return value
    return "unspecified"


def data_level(record: dict) -> str:
    declared = str(record.get("data_level", "")).lower()
    if declared in VALID_DATA_LEVELS:
        return declared
    if "protocol_event" in record:
        return "protocol"
    if "conversation" in record:
        return "llm_context"
    scope = str(record.get("detection_scope", ""))
    if scope in {"authorization_or_request_sequence", "llm_conversation_or_output"}:
        return "context"
    if record.get("raw_request") is not None or "url" in record or "method" in record:
        return "request"
    return "field"


def content_material(record: dict, level: str) -> str:
    if record.get("is_encoding_variant") is True and record.get("obfuscated_payload") is not None:
        return str(record["obfuscated_payload"])
    if level == "field":
        return str(record.get("obfuscated_payload") or record.get("payload") or "")
    if level == "request":
        raw = record.get("raw_request")
        if raw:
            return str(raw)
        return json.dumps({
            "method": record.get("method", "GET"),
            "url": record.get("url", "/"),
            "headers": record.get("headers", {}),
            "body": record.get("body", ""),
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if level == "protocol":
        return json.dumps(record.get("protocol_event"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if level == "llm_context":
        return json.dumps(record.get("conversation"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return json.dumps({
        "request": record.get("raw_request"),
        "context": record.get("observed_context"),
        "role": record.get("principal_role"),
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def safe_type(value: str) -> str:
    result = re.sub(r"[^a-z0-9_.-]+", "_", value.strip().lower()).strip("._-")
    if not result or result in {"normal", "unknown", "missing"}:
        raise ValueError(f"invalid attack type for positive record: {value!r}")
    return result


def attack_representation(record: dict, dataset: str) -> tuple[str, str]:
    """Classify attacks without mistaking canonical transports for obfuscation.

    ``obfuscated`` is reserved for records with explicit derivation provenance.
    Everything else is ``original`` in the sense of "not explicitly derived by
    this project's obfuscation pipeline"; it does not imply packet-capture data.
    """
    if dataset == "obfuscated_attack_traffic":
        return "obfuscated", "dedicated_obfuscated_attack_dataset"
    if dataset == "all_original_obfuscated":
        return "obfuscated", "all_original_generated_variant"
    if record.get("is_encoding_variant") is True:
        return "obfuscated", "explicit_is_encoding_variant"
    if (
        dataset == "enriched_traffic"
        and record.get("pair_role") == "attack"
        and str(record.get("variant", "raw")).lower() not in {"", "raw", "original"}
    ):
        return "obfuscated", "contrastive_non_raw_variant"
    if (
        dataset == "specialized_traffic/payloads"
        and record.get("decoded_payload") is not None
        and str(record.get("encoding", "raw")).lower() not in {"", "raw"}
    ):
        return "obfuscated", "specialized_non_raw_encoding"
    if dataset == "validation" and re.search(
        r"(?:^|_)(?:obf|combo)(?:_|$)", str(record.get("id", "")).lower()
    ):
        return "obfuscated", "validation_obfuscation_id"
    return "original", "no_explicit_obfuscation_derivation"


class Writers:
    def __init__(self, root: Path):
        self.root = root
        self.handles = {}
        self.counts = Counter()

    def write(self, relative: Path, record: dict) -> None:
        path = self.root / relative
        if path not in self.handles:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.handles[path] = path.open("w", encoding="utf-8", newline="\n")
        self.handles[path].write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.counts[relative.as_posix()] += 1

    def close(self) -> None:
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()


def main() -> None:
    parser = argparse.ArgumentParser(description="Organize all labelled datasets into normal/attack folders")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == DATA or DATA not in output.parents:
        raise SystemExit("output must be a child of the project data directory")
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)

    files = input_files()
    writers = Writers(temporary)
    total_counts = Counter()
    source_counts = Counter()
    source_label_counts: dict[str, Counter] = defaultdict(Counter)
    lab_target_counts = Counter()
    attack_counts = Counter()
    attack_representation_counts = Counter()
    attack_representation_type_counts: dict[str, Counter] = defaultdict(Counter)
    attack_representation_source_counts: dict[str, Counter] = defaultdict(Counter)
    attack_representation_level_counts: dict[str, Counter] = defaultdict(Counter)
    attack_representation_split_counts: dict[str, Counter] = defaultdict(Counter)
    attack_classification_basis_counts = Counter()
    level_counts = {"normal": Counter(), "attack": Counter()}
    split_counts = {"normal": Counter(), "attack": Counter()}
    representation_family_shards: dict[tuple[str, str], Counter] = defaultdict(Counter)
    content_labels: dict[str, int] = {}
    content_conflicts: set[str] = set()
    record_fingerprints: set[str] = set()
    input_audit = {}
    invalid = []

    try:
        for path in files:
            values = read_array(path)
            relative_source = path.relative_to(ROOT).as_posix()
            dataset = source_dataset(path)
            input_audit[relative_source] = {"records": len(values), "sha256": sha256_file(path)}
            for index, original in enumerate(values, 1):
                label = original.get("label")
                if label not in {0, 1}:
                    invalid.append(f"{relative_source}:{index}: invalid label {label!r}")
                    continue
                level = data_level(original)
                split = infer_split(path, original)
                bucket = "normal" if label == 0 else "attack"
                attack_type = "normal" if label == 0 else safe_type(str(original.get("attack_type", "")))
                material = content_material(original, level)
                if not material:
                    invalid.append(f"{relative_source}:{index}: empty {level} material")
                    continue
                content_hash = hashlib.sha256(f"{level}\0{material}".encode("utf-8", errors="replace")).hexdigest()
                previous_label = content_labels.setdefault(content_hash, int(label))
                if previous_label != label:
                    content_conflicts.add(content_hash)
                record_hash = hashlib.sha256(f"{label}\0{attack_type}\0{level}\0{material}".encode("utf-8", errors="replace")).hexdigest()
                record_fingerprints.add(record_hash)
                organized_id = hashlib.sha256(f"{relative_source}:{index}".encode()).hexdigest()
                item = dict(original)
                item["label"] = int(label)
                item["attack_type"] = attack_type
                organized_metadata = {
                    "id": f"organized_{organized_id[:24]}",
                    "source_file": relative_source,
                    "source_record_index": index,
                    "source_dataset": dataset,
                    "data_level": level,
                    "split": split,
                    "content_sha256": content_hash,
                    "record_sha256": record_hash,
                    "payload_model_eligible": bool(
                        level == "field"
                        and not original.get("exclude_from_payload_model", False)
                        and path.relative_to(DATA).parts[0] != "validation"
                    ),
                }
                if bucket == "attack":
                    representation, representation_basis = attack_representation(original, dataset)
                    organized_metadata["attack_representation"] = representation
                    organized_metadata["attack_representation_basis"] = representation_basis
                item["_organized"] = organized_metadata
                if bucket == "normal":
                    shard = Path("normal") / level / f"{split}.jsonl"
                else:
                    shard = (
                        Path("attack") / representation / attack_type / level / f"{split}.jsonl"
                    )
                    attack_counts[attack_type] += 1
                    attack_representation_counts[representation] += 1
                    attack_representation_type_counts[representation][attack_type] += 1
                    attack_representation_source_counts[representation][dataset] += 1
                    attack_representation_level_counts[representation][level] += 1
                    attack_representation_split_counts[representation][split] += 1
                    attack_classification_basis_counts[representation_basis] += 1
                    representation_family_shards[(representation, attack_type)][
                        f"{level}/{split}"
                    ] += 1
                writers.write(shard, item)
                total_counts[bucket] += 1
                source_counts[dataset] += 1
                source_label_counts[dataset][bucket] += 1
                if dataset == "lab_captures":
                    lab_target_counts[str(original.get("lab_target", "unspecified"))] += 1
                level_counts[bucket][level] += 1
                split_counts[bucket][split] += 1
    finally:
        writers.close()

    if invalid:
        shutil.rmtree(temporary)
        raise SystemExit("\n".join(invalid[:20]))

    artifacts = {}
    for relative, count in sorted(writers.counts.items()):
        path = temporary / relative
        artifacts[relative] = {"records": count, "bytes": path.stat().st_size, "sha256": sha256_file(path)}

    for representation in ("original", "obfuscated"):
        for family, count in sorted(attack_representation_type_counts[representation].items()):
            title, standard = TAXONOMY.get(
                family, (family.replace("_", " ").title(), "unmapped")
            )
            document = {
                "representation": representation,
                "attack_type": family,
                "title": title,
                "standard": standard,
                "records": count,
                "shards": dict(sorted(
                    representation_family_shards[(representation, family)].items()
                )),
            }
            (temporary / "attack" / representation / family / "manifest.json").write_text(
                json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
        representation_manifest = {
            "label": 1,
            "representation": representation,
            "records": attack_representation_counts[representation],
            "families": len(attack_representation_type_counts[representation]),
            "by_attack_type": dict(sorted(
                attack_representation_type_counts[representation].items()
            )),
            "by_source_dataset": dict(sorted(
                attack_representation_source_counts[representation].items()
            )),
            "by_data_level": dict(sorted(
                attack_representation_level_counts[representation].items()
            )),
            "by_split": dict(sorted(
                attack_representation_split_counts[representation].items()
            )),
        }
        (temporary / "attack" / representation / "manifest.json").write_text(
            json.dumps(representation_manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    normal_manifest = {
        "label": 0,
        "records": total_counts["normal"],
        "by_data_level": dict(sorted(level_counts["normal"].items())),
        "by_split": dict(sorted(split_counts["normal"].items())),
    }
    (temporary / "normal" / "manifest.json").write_text(
        json.dumps(normal_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    attack_manifest = {
        "label": 1,
        "records": total_counts["attack"],
        "families": len(attack_counts),
        "by_attack_type": dict(sorted(attack_counts.items())),
        "by_data_level": dict(sorted(level_counts["attack"].items())),
        "by_split": dict(sorted(split_counts["attack"].items())),
        "by_representation": dict(sorted(attack_representation_counts.items())),
        "classification_basis_counts": dict(sorted(attack_classification_basis_counts.items())),
        "representation_policy": {
            "original": (
                "attack record without explicit obfuscation-derivation provenance; this does not "
                "necessarily mean raw packet capture"
            ),
            "obfuscated": (
                "record explicitly derived by an obfuscation/encoding pipeline with traceable "
                "source metadata"
            ),
            "canonical_transport_exception": (
                "Base64 used as the sole canonical HTTP carrier for a binary serialization is "
                "not classified as obfuscation when is_encoding_variant=false"
            ),
        },
    }
    (temporary / "attack" / "manifest.json").write_text(
        json.dumps(attack_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    taxonomy = {
        family: {"title": TAXONOMY.get(family, (family.replace("_", " ").title(), "unmapped"))[0],
                 "standard": TAXONOMY.get(family, ("", "unmapped"))[1]}
        for family in sorted(attack_counts)
    }
    (temporary / "taxonomy.json").write_text(
        json.dumps(taxonomy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    manifest = {
        "dataset": "AI-WAF-Organized-View-v2",
        "format": "UTF-8 JSONL; one source record per line with _organized provenance",
        "total_records": sum(total_counts.values()),
        "label_counts": {"normal": total_counts["normal"], "attack": total_counts["attack"]},
        "attack_families": len(attack_counts),
        "attack_type_counts": dict(sorted(attack_counts.items())),
        "attack_representation_counts": dict(sorted(attack_representation_counts.items())),
        "attack_representation_type_counts": {
            key: dict(sorted(value.items()))
            for key, value in sorted(attack_representation_type_counts.items())
        },
        "attack_representation_source_counts": {
            key: dict(sorted(value.items()))
            for key, value in sorted(attack_representation_source_counts.items())
        },
        "attack_classification_basis_counts": dict(sorted(
            attack_classification_basis_counts.items()
        )),
        "source_dataset_counts": dict(sorted(source_counts.items())),
        "source_label_counts": {
            key: dict(sorted(value.items())) for key, value in sorted(source_label_counts.items())
        },
        "lab_target_counts": dict(sorted(lab_target_counts.items())),
        "data_level_counts": {
            key: dict(sorted(value.items())) for key, value in level_counts.items()
        },
        "split_counts": {
            key: dict(sorted(value.items())) for key, value in split_counts.items()
        },
        "content_audit": {
            "unique_content_fingerprints": len(content_labels),
            "unique_label_type_content_records": len(record_fingerprints),
            "cross_label_content_conflicts": len(content_conflicts),
            "interpretation": "conflicts are retained for review because context/documentation may legitimately change a label",
        },
        "input_artifacts": input_audit,
        "artifacts": artifacts,
        "excluded": [
            "data/attack_traffic/_all (legacy duplicate aggregate; removed and ignored if recreated)",
            "data/archives (source archives, not labelled records)",
            "data/modern_attack_traffic/source_snapshots (metadata, not labelled records)",
            "data/external_traffic/source_snapshots (pinned public source snapshots, not duplicate labelled records)",
            "data/external_deserialization/source_snapshots (pinned source archives and canonical one-per-gadget derivations)",
            "unretained raw lab capture JSONL (the redacted generated export is retained)",
        ],
        "safety": "original datasets are untouched; context/request/protocol labels are not converted to field labels",
    }
    (temporary / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (temporary / "README.md").write_text(build_readme(manifest, taxonomy), encoding="utf-8")

    if output.exists():
        shutil.rmtree(output)
    temporary.replace(output)
    print(json.dumps({
        "output": str(output),
        "total": manifest["total_records"],
        "normal": total_counts["normal"],
        "attack": total_counts["attack"],
        "original_attack": attack_representation_counts["original"],
        "obfuscated_attack": attack_representation_counts["obfuscated"],
        "attack_families": len(attack_counts),
        "jsonl_shards": len(artifacts),
        "content_conflicts": len(content_conflicts),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
