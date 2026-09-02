"""
L1 Rule Engine — AC 自动机 + 正则匹配

在级联管线中承担第一层快速筛选（< 1ms）。
只做高精度匹配：宁可漏报，不可误报。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 规则数据结构
# ---------------------------------------------------------------------------

class Rule:
    """单条检测规则"""
    def __init__(self, rule_id: str, pattern: str, attack_type: str,
                 severity: str = "high", description: str = ""):
        self.id = rule_id
        self.pattern = pattern
        self.attack_type = attack_type
        self.severity = severity
        self.description = description
        self._compiled = re.compile(pattern, re.IGNORECASE)

    def match(self, text: str) -> bool:
        """返回 True 表示命中"""
        return bool(self._compiled.search(text))


class RuleSet:
    """一组规则（按攻击类型分组）"""
    def __init__(self, name: str):
        self.name = name
        self.rules: list[Rule] = []

    def add(self, rule: Rule):
        self.rules.append(rule)

    def match_any(self, text: str) -> tuple[bool, list[Rule]]:
        """返回 (是否有命中, 命中的规则列表)"""
        hits = [r for r in self.rules if r.match(text)]
        return len(hits) > 0, hits

    def __len__(self):
        return len(self.rules)


# ---------------------------------------------------------------------------
# 内置精简规则（完整规则从 YAML 加载）
# ---------------------------------------------------------------------------

def _builtin_sqli_rules() -> RuleSet:
    rs = RuleSet("sqli")
    rs.add(Rule("sqli_union", r"\bUNION\s+(ALL\s+)?SELECT\b", "sqli", "high"))
    rs.add(Rule("sqli_or_tautology", r"'\s*OR\s+['\d]+=['\d]+", "sqli", "high"))
    rs.add(Rule("sqli_and_tautology", r"'\s*AND\s+['\d]+=['\d]+", "sqli", "high"))
    number = r"(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?"
    rs.add(Rule("sqli_sleep", rf"\bSLEEP\s*\(\s*{number}\s*\)", "sqli", "high"))
    rs.add(Rule("sqli_pg_sleep", rf"\bPG_SLEEP\s*\(\s*{number}\s*\)", "sqli", "high"))
    rs.add(Rule("sqli_waitfor", r"\bWAITFOR\s+DELAY\s+['\"]\d{1,2}:\d{2}:\d{2}(?:\.\d+)?['\"]", "sqli", "high"))
    rs.add(Rule("sqli_benchmark", r"\bBENCHMARK\s*\(.*,.*\)", "sqli", "high"))
    rs.add(Rule("sqli_extractvalue", r"\bEXTRACTVALUE\s*\(.*,.*\)", "sqli", "high"))
    rs.add(Rule("sqli_updatexml", r"\bUPDATEXML\s*\(.*,.*\)", "sqli", "high"))
    rs.add(Rule("sqli_drop_table", r"\bDROP\s+TABLE\b", "sqli", "high"))
    rs.add(Rule("sqli_into_outfile", r"\bINTO\s+(OUTFILE|DUMPFILE)\b", "sqli", "high"))
    rs.add(Rule("sqli_information_schema", r"\bINFORMATION_SCHEMA\b", "sqli", "medium"))
    return rs


def _builtin_xss_rules() -> RuleSet:
    rs = RuleSet("xss")
    rs.add(Rule("xss_script_open", r"<\s*script[^>]*>", "xss", "medium"))
    # <script src=...> with external source is a direct XSS vector
    rs.add(Rule("xss_script_src", r"<\s*script[^>]*\bsrc\s*=\s*[\"'][^\"']+[\"']", "xss", "high"))
    rs.add(Rule("xss_onerror", r"\bonerror\s*=", "xss", "high"))
    rs.add(Rule("xss_onload", r"\bonload\s*=", "xss", "high"))
    rs.add(Rule("xss_javascript_uri", r"javascript\s*:", "xss", "high"))
    rs.add(Rule("xss_img_onerror", r"<\s*img[^>]+onerror", "xss", "high"))
    rs.add(Rule("xss_svg_onload", r"<\s*svg[^>]*onload", "xss", "high"))
    rs.add(Rule("xss_alert", r"\balert\s*\(.*\)", "xss", "medium"))
    rs.add(Rule("xss_document_cookie", r"document\.cookie", "xss", "high"))
    return rs


def _builtin_cmdi_rules() -> RuleSet:
    rs = RuleSet("cmdi")
    rs.add(Rule("cmdi_pipe_cmd", r"\|\s*(cat|ls|id|whoami|uname|dir|type)", "cmdi", "high"))
    rs.add(Rule("cmdi_semicolon_cmd", r";\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python)", "cmdi", "high"))
    rs.add(Rule("cmdi_backtick", r"`\s*(?:cat|ls|id|whoami|uname|dir|type|curl|wget|bash|sh|python)(?:\s+[^`]*)?`", "cmdi", "high"))
    rs.add(Rule("cmdi_dollar_subshell", r"\$\([^)]+\)", "cmdi", "high"))
    rs.add(Rule("cmdi_dev_null", r">\s*/dev/null", "cmdi", "medium"))
    return rs


def _builtin_jwt_rules() -> RuleSet:
    rs = RuleSet("jwt")
    # Empty signature segment: header.payload. (including embedded/wrapped form)
    rs.add(Rule("jwt_empty_signature", r"(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{10,}={0,2}\.[A-Za-z0-9_-]{2,}={0,2}\.(?=$|[\s&\"'])", "jwt", "high"))
    rs.add(Rule("jwt_alg_none_json", r'"alg"\s*:\s*"none"', "jwt", "high"))
    rs.add(Rule("jwt_alg_none_b64", r"eyJhbGciOiJub25l", "jwt", "high"))
    return rs


def _builtin_protocol_rules() -> RuleSet:
    """Protocol/structural rules: XXE, SSI, code injection, CRLF, upload, LFI and NoSQL."""
    rs = RuleSet("protocol")
    rs.add(Rule("xxe_external_entity", r"<!ENTITY\s+\S+\s+(?:SYSTEM|PUBLIC)", "xxe", "high"))
    rs.add(Rule("xxe_parameter_entity", r"<!ENTITY\s+%\s+\S+\s+(?:SYSTEM|PUBLIC)", "xxe", "high"))
    rs.add(Rule("ssi_exec", r"<!--\s*#(?:exec|include)\b", "ssi", "high"))
    rs.add(Rule("codei_system_call", r"\b(?:system|exec|passthru|shell_exec)\s*\([^)]+", "codei", "high"))
    rs.add(Rule("crlf_percent_encoded", r"%(?:0[dD]|0[aA])", "crlf", "medium"))
    rs.add(Rule("log4shell_jndi", r"\$\{jndi:", "log4j", "high"))
    rs.add(Rule("format_write", r"%[0-9]*\$?n", "fmtst", "high"))
    rs.add(Rule("format_sequence", r"(%[0-9]*\$?[spxXdn]){3,}", "fmtst", "medium"))
    rs.add(Rule("dangerous_upload_extension", r"\.(?:php[3-8]?|phtml|phar|aspx?|jspx?|war|cgi|pl)\b", "fupl", "medium"))
    rs.add(Rule("lfi_stream_wrapper", r"\b(?:php|data|expect|file|glob|phar|zip|compress\.zlib|ogg)://", "lfi", "medium"))
    rs.add(Rule("nosql_operator_object", r'\$(?:ne|where|regex|gt|gte|lt|lte|in|nin|or|and|not|exists|type|mod|text|search|eq|size|all|elemMatch|comment)\b', "nosql", "medium"))
    return rs


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    L1 规则引擎。

    用法:
        engine = RuleEngine()
        verdict, hits = engine.check(payload, normalized_text)
        # verdict ∈ {"attack", "benign", "uncertain"}
    """

    def __init__(self):
        self.rulesets: dict[str, RuleSet] = {}
        self._load_builtin()

    def _load_builtin(self):
        """加载内置规则（精简版，YAML 规则可通过 add_ruleset 扩展）"""
        self.rulesets["sqli"] = _builtin_sqli_rules()
        self.rulesets["xss"] = _builtin_xss_rules()
        self.rulesets["cmdi"] = _builtin_cmdi_rules()
        self.rulesets["jwt"] = _builtin_jwt_rules()
        self.rulesets["protocol"] = _builtin_protocol_rules()

    def add_ruleset(self, rs: RuleSet):
        self.rulesets[rs.name] = rs

    @property
    def total_rules(self) -> int:
        return sum(len(rs) for rs in self.rulesets.values())

    def check(self, normalized_text: str, confusion_converged: bool = True,
              confusion_depth: int = 0) -> tuple[str, list[Rule]]:
        """
        对归一化后的文本做规则匹配。

        参数:
          normalized_text: 归一化器输出的还原文本
          confusion_converged: 归一化是否收敛
          confusion_depth: 混淆层数

        返回:
          ("attack" | "benign" | "uncertain", 命中的规则列表)
        """
        all_hits: list[Rule] = []
        for rs in self.rulesets.values():
            _, hits = rs.match_any(normalized_text)
            all_hits.extend(hits)

        # 判定逻辑
        high_severity = [r for r in all_hits if r.severity == "high"]
        if len(high_severity) >= 1:
            return "attack", all_hits

        if len(all_hits) == 0:
            # A rule engine can prove a high-confidence attack, but absence of
            # a signature cannot prove benignness. Always let the classifier
            # evaluate no-hit inputs; otherwise novel syntax bypasses L2/L3.
            return "uncertain", []

        # 仅命中 medium/low 且 < 2 条 → 不确定，交给 L2
        return "uncertain", all_hits
