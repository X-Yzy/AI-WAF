"""
特征提取器 / Feature Extractor

输入：(raw_payload: str, restored_text: str, meta: ConfusionMeta)
输出：np.ndarray of shape (38,) — 38 维融合特征向量

三类特征：
  ① 原始层 12 维 — 直接从原始 payload 提取，不依赖归一化器
  ② 还原层 14 维 — 依赖归一化器输出的 restored_text
  ③ 过程层 12 维 — 依赖归一化过程的 ConfusionMeta

任何输入都不抛异常。无法计算的维度填 0.0。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Optional

import numpy as np

from .normalizer import ConfusionMeta


# ===========================================================================
# 第①类：原始层特征（12 维）— 直接从原始 payload 计算
# ===========================================================================

def _f01_payload_byte_len(raw: str) -> float:
    """原始字节长度"""
    return float(len(raw.encode('utf-8', errors='replace')))


def _f02_digit_ratio(raw: str) -> float:
    """数字占比"""
    if not raw:
        return 0.0
    return sum(1 for c in raw if c.isdigit()) / len(raw)


def _f03_alpha_ratio(raw: str) -> float:
    """字母占比"""
    if not raw:
        return 0.0
    return sum(1 for c in raw if c.isalpha()) / len(raw)


def _f04_special_char_ratio(raw: str) -> float:
    """特殊符号占比：' \" ; < > ( ) / \\ % | & ` * ? $ !"""
    special = set("'\";<>()/\\%|&`*?$!")
    if not raw:
        return 0.0
    return sum(1 for c in raw if c in special) / len(raw)


def _f05_upper_lower_ratio(raw: str) -> float:
    """
    大小写比：大写字母数 / (小写字母数 + 1)。
    值 > 2 通常表示异常的大小写交替（混淆行为）。
    """
    uppers = sum(1 for c in raw if c.isupper())
    lowers = sum(1 for c in raw if c.islower())
    return uppers / max(lowers, 1)


def _f06_shannon_entropy(raw: str) -> float:
    """原始 payload 的 Shannon 熵"""
    if not raw:
        return 0.0
    n = len(raw)
    freq = {}
    for ch in raw:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in freq.values())


_URL_ENCODED_RE = re.compile(r'%[0-9a-fA-F]{2}')

def _f07_url_encoded_char_ratio(raw: str) -> float:
    """%XX 模式占比"""
    if not raw:
        return 0.0
    matches = _URL_ENCODED_RE.findall(raw)
    return len(matches) * 3 / max(len(raw), 1)  # 每个 %XX 占 3 字符


_HTML_ENTITY_RE = re.compile(r'&#?[a-zA-Z0-9]+;')

def _f08_html_entity_count(raw: str) -> float:
    """HTML 实体计数（&#... / &lt; / &gt; 等）"""
    return float(len(_HTML_ENTITY_RE.findall(raw)))


_COMMENT_PATTERN_RE = re.compile(r'/\*.*?\*/|/\*!.*?\*/|<!--.*?-->|//[^\n]*')

def _f09_comment_pattern_count(raw: str) -> float:
    """注释模式计数（/**/ / /*!*/ / <!-- --> / //）"""
    return float(len(_COMMENT_PATTERN_RE.findall(raw)))


def _f10_max_token_len(raw: str) -> float:
    """最长连续非分隔 token 长度"""
    tokens = re.split(r'[\s\'"<>()\[\]{},;:]+', raw)
    return float(max((len(t) for t in tokens), default=0))


def _f11_whitespace_ratio(raw: str) -> float:
    """空白字符占比"""
    if not raw:
        return 0.0
    return sum(1 for c in raw if c in ' \t\n\r') / len(raw)


def _f12_non_printable_ratio(raw: str) -> float:
    """不可打印字符占比"""
    if not raw:
        return 0.0
    return sum(1 for c in raw if not c.isprintable() and c not in '\n\r\t') / len(raw)


# ===========================================================================
# 第②类：还原层特征（14 维）— 依赖归一化器输出的 restored_text
# ===========================================================================

# SQL 关键字（大小写无关匹配）
SQL_KEYWORDS_RE = re.compile(
    r'\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|'
    r'EXECUTE|DECLARE|WHERE|FROM|HAVING|GROUP\s+BY|ORDER\s+BY|'
    r'INTO\s+OUTFILE|LOAD_FILE|INFORMATION_SCHEMA|SLEEP|BENCHMARK)\b',
    re.IGNORECASE
)
SQL_FUNCTION_RE = re.compile(
    r'\b(EXTRACTVALUE|UPDATEXML|EXP|FLOOR|RAND|CONVERT|'
    r'SUBSTRING|MID|LEFT|RIGHT|ASCII|ORD|CHAR|HEX|UNHEX|'
    r'CONCAT|GROUP_CONCAT|LOAD_FILE|WAITFOR)\b',
    re.IGNORECASE
)

def _f13_sql_keyword_hits(restored: str) -> float:
    """SQL 关键字命中数"""
    return float(len(SQL_KEYWORDS_RE.findall(restored)) +
                 len(SQL_FUNCTION_RE.findall(restored)))


XSS_KEYWORDS_RE = re.compile(
    r'\b(script|onerror|onload|onfocus|onmouseover|onclick|oninput|'
    r'onblur|onchange|onsubmit|alert|confirm|prompt|eval|document\.cookie|'
    r'window\.location|innerHTML|outerHTML)\b',
    re.IGNORECASE
)
XSS_TAG_RE = re.compile(
    r'<(script|img|svg|iframe|video|audio|details|marquee|body|input|'
    r'style|link|object|embed|frame|frameset|applet|meta)',
    re.IGNORECASE
)

def _f14_xss_keyword_hits(restored: str) -> float:
    """XSS 关键字/标签命中数"""
    return float(len(XSS_KEYWORDS_RE.findall(restored)) +
                 len(XSS_TAG_RE.findall(restored)))


CMDI_KEYWORDS_RE = re.compile(
    r'\b(system|exec|cmd|popen|passthru|shell_exec|os\.system|'
    r'subprocess|child_process|Runtime\.getRuntime|ProcessBuilder|'
    r'popen|fork|spawn|execve)\b',
    re.IGNORECASE
)

def _f15_cmdi_keyword_hits(restored: str) -> float:
    """命令注入关键字命中数"""
    return float(len(CMDI_KEYWORDS_RE.findall(restored)))


SSTI_PATTERN_RE = re.compile(r'\{\{.*?\}\}|\$\{.*?\}|<%\s*=.*?%>|#\{.*?\}|'
                              r'<\#.*?>|\{\%.*?\%\}|\{\#.*?\#\}')

def _f16_ssti_pattern_hits(restored: str) -> float:
    """SSTI 模板模式命中数"""
    return float(len(SSTI_PATTERN_RE.findall(restored)))


TRAVERSAL_RE = re.compile(r'\.\./|\.\.\\|\.\.%2f|\.\.%5c', re.IGNORECASE)

def _f17_path_traversal_hits(restored: str) -> float:
    """路径穿越 ../ / ..\\  命中数"""
    return float(len(TRAVERSAL_RE.findall(restored)))


DB_FUNC_RE = re.compile(
    r'\b(SLEEP|BENCHMARK|EXTRACTVALUE|UPDATEXML|EXP|FLOOR|RAND|'
    r'WAITFOR\s+DELAY|pg_sleep|DBMS_PIPE\.RECEIVE_MESSAGE)\b',
    re.IGNORECASE
)

def _f18_database_function_hits(restored: str) -> float:
    """数据库危险函数命中数"""
    return float(len(DB_FUNC_RE.findall(restored)))


def _f19_sql_structure_score(restored: str) -> float:
    """
    SQL 语法结构完整度评分（0-1）。
    检查是否包含典型 SQL 注入的完整结构元素。
    """
    score = 0.0
    # 引号
    if "'" in restored:
        score += 0.2
    # 注释符
    if re.search(r'--|#|/\*', restored):
        score += 0.15
    # 布尔操作符
    if re.search(r'\b(AND|OR|NOT)\b', restored, re.IGNORECASE):
        score += 0.2
    # 关键字
    if SQL_KEYWORDS_RE.search(restored):
        score += 0.25
    # 括号结构
    if '(' in restored and ')' in restored:
        score += 0.1
    # 等号
    if '=' in restored:
        score += 0.1
    return min(score, 1.0)


def _f20_xss_structure_score(restored: str) -> float:
    """
    XSS/HTML/JS 结构完整度评分（0-1）。
    """
    score = 0.0
    # 尖括号
    if '<' in restored and '>' in restored:
        score += 0.3
    # 事件处理器或危险标签
    if XSS_TAG_RE.search(restored) or XSS_KEYWORDS_RE.search(restored):
        score += 0.3
    # JS URI 协议
    if re.search(r'javascript\s*:', restored, re.IGNORECASE):
        score += 0.2
    # 引号中的 JS 代码
    if "'" in restored or '"' in restored:
        score += 0.1
    # 括号（函数调用）
    if '(' in restored:
        score += 0.1
    return min(score, 1.0)


def _f21_balanced_quote_ratio(restored: str) -> float:
    """引号成对程度。返回 1.0 表示完全成对，< 1.0 表示不平衡（攻击信号）。"""
    single = restored.count("'")
    double = restored.count('"')
    if single % 2 == 0 and double % 2 == 0:
        return 1.0
    if single % 2 == 0 and double % 2 != 0:
        return 0.5
    if single % 2 != 0 and double % 2 == 0:
        return 0.5
    return 0.0


def _f22_balanced_paren_ratio(restored: str) -> float:
    """括号成对程度。"""
    open_p = restored.count('(')
    close_p = restored.count(')')
    if open_p == close_p:
        return 1.0
    if open_p == 0 and close_p == 0:
        return 1.0
    return min(open_p, close_p) / max(max(open_p, close_p), 1)


def _f23_token_entropy(restored: str) -> float:
    """还原文本中 token 级别的熵值"""
    tokens = re.split(r'[\s\'"<>()\[\]{},;:]+', restored)
    tokens = [t for t in tokens if t]
    if not tokens:
        return 0.0
    n = len(tokens)
    freq = Counter(tokens)
    return -sum(c / n * math.log2(c / n) for c in freq.values())


def _f24_max_keyword_density(restored: str) -> float:
    """
    最密集关键词区域密度：滑动窗口（50 字符）中关键词占比的最大值。
    """
    if not restored or len(restored) < 10:
        return 0.0
    window = 50
    max_density = 0.0
    lower = restored.lower()
    for i in range(0, len(lower) - 10, 10):
        chunk = lower[i:i + window]
        hits = len(SQL_KEYWORDS_RE.findall(chunk)) + len(XSS_KEYWORDS_RE.findall(chunk)) + len(CMDI_KEYWORDS_RE.findall(chunk))
        density = hits / max(len(chunk), 1)
        max_density = max(max_density, density)
    return max_density


SENSITIVE_PATH_RE = re.compile(
    r'(/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|C:\\Windows|'
    r'C:\\WINNT|/var/log|/root/|/home/\w+/\.ssh)',
    re.IGNORECASE
)

def _f25_sensitive_path_hits(restored: str) -> float:
    """敏感路径命中数"""
    return float(len(SENSITIVE_PATH_RE.findall(restored)))


INTERNAL_IP_RE = re.compile(
    r'\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})\b'
)

def _f26_ip_addr_hits(restored: str) -> float:
    """内网 IP 地址命中数"""
    return float(len(INTERNAL_IP_RE.findall(restored)))


# ===========================================================================
# 第③类：过程层特征（12 维）— 从 ConfusionMeta 直接映射
# ===========================================================================

def _f27_decode_depth(meta: ConfusionMeta) -> float:
    return float(meta.decode_depth)

def _f28_len_before_after_ratio(meta: ConfusionMeta) -> float:
    if meta.len_after == 0:
        return 1.0
    return meta.len_before / max(meta.len_after, 1)

def _f29_entropy_delta(meta: ConfusionMeta) -> float:
    """原始熵 - 还原后熵（>0 说明混淆降低了熵）"""
    return meta.entropy_before - meta.entropy_after

def _f30_converged(meta: ConfusionMeta) -> float:
    return 1.0 if meta.converged else 0.0

def _f31_decode_steps_attempted(meta: ConfusionMeta) -> float:
    return float(meta.decode_steps_attempted)

def _f32_successful_decode_steps(meta: ConfusionMeta) -> float:
    return float(meta.successful_decode_steps)

def _f33_url_decode_layers(meta: ConfusionMeta) -> float:
    return float(meta.url_decode_layers)

def _f34_base64_decode_success(meta: ConfusionMeta) -> float:
    return 1.0 if meta.base64_decode_success else 0.0

def _f35_comment_blocks_removed(meta: ConfusionMeta) -> float:
    return float(meta.comment_blocks_removed)

def _f36_concat_patterns_removed(meta: ConfusionMeta) -> float:
    return float(meta.concat_patterns_removed)

def _f37_whitespace_normalized(meta: ConfusionMeta) -> float:
    return 1.0 if meta.whitespace_normalized else 0.0

def _f38_payload_grew(meta: ConfusionMeta) -> float:
    return 1.0 if meta.payload_grew else 0.0


# ===========================================================================
# 聚合函数
# ===========================================================================

# 38 个特征函数，按顺序排列
_FEATURE_FUNCTIONS_RAW = [
    _f01_payload_byte_len,
    _f02_digit_ratio,
    _f03_alpha_ratio,
    _f04_special_char_ratio,
    _f05_upper_lower_ratio,
    _f06_shannon_entropy,
    _f07_url_encoded_char_ratio,
    _f08_html_entity_count,
    _f09_comment_pattern_count,
    _f10_max_token_len,
    _f11_whitespace_ratio,
    _f12_non_printable_ratio,
]

_FEATURE_FUNCTIONS_RESTORED = [
    _f13_sql_keyword_hits,
    _f14_xss_keyword_hits,
    _f15_cmdi_keyword_hits,
    _f16_ssti_pattern_hits,
    _f17_path_traversal_hits,
    _f18_database_function_hits,
    _f19_sql_structure_score,
    _f20_xss_structure_score,
    _f21_balanced_quote_ratio,
    _f22_balanced_paren_ratio,
    _f23_token_entropy,
    _f24_max_keyword_density,
    _f25_sensitive_path_hits,
    _f26_ip_addr_hits,
]

_FEATURE_FUNCTIONS_META = [
    _f27_decode_depth,
    _f28_len_before_after_ratio,
    _f29_entropy_delta,
    _f30_converged,
    _f31_decode_steps_attempted,
    _f32_successful_decode_steps,
    _f33_url_decode_layers,
    _f34_base64_decode_success,
    _f35_comment_blocks_removed,
    _f36_concat_patterns_removed,
    _f37_whitespace_normalized,
    _f38_payload_grew,
]

ALL_FEATURES = _FEATURE_FUNCTIONS_RAW + _FEATURE_FUNCTIONS_RESTORED + _FEATURE_FUNCTIONS_META

# 特征名称（用于调试和报告）
FEATURE_NAMES = [
    # ① 原始层
    "payload_byte_len", "digit_ratio", "alpha_ratio", "special_char_ratio",
    "upper_lower_ratio", "shannon_entropy", "url_encoded_char_ratio",
    "html_entity_count", "comment_pattern_count", "max_token_len",
    "whitespace_ratio", "non_printable_ratio",
    # ② 还原层
    "sql_keyword_hits", "xss_keyword_hits", "cmdi_keyword_hits",
    "ssti_pattern_hits", "path_traversal_hits", "database_function_hits",
    "sql_structure_score", "xss_structure_score", "balanced_quote_ratio",
    "balanced_paren_ratio", "token_entropy", "max_keyword_density",
    "sensitive_path_hits", "ip_addr_hits",
    # ③ 过程层
    "decode_depth", "len_before_after_ratio", "entropy_delta",
    "converged", "decode_steps_attempted", "successful_decode_steps",
    "url_decode_layers", "base64_decode_success", "comment_blocks_removed",
    "concat_patterns_removed", "whitespace_normalized", "payload_grew",
]

assert len(ALL_FEATURES) == 38, f"Expected 38 features, got {len(ALL_FEATURES)}"
assert len(FEATURE_NAMES) == 38, f"Expected 38 names, got {len(FEATURE_NAMES)}"


def extract(raw_payload: str, restored_text: str, meta: ConfusionMeta) -> np.ndarray:
    """
    特征提取主入口。

    输入：原始 payload + 归一化还原文本 + 混淆元数据
    输出：(38,) 维 numpy float 数组

    任何输入都不抛异常。无法计算的维度填 0.0。
    """
    features = np.zeros(38, dtype=np.float32)

    # 第①类：原始层（12 维）
    for i, fn in enumerate(_FEATURE_FUNCTIONS_RAW):
        try:
            features[i] = fn(raw_payload)
        except Exception:
            features[i] = 0.0

    # 第②类：还原层（14 维）
    restored = restored_text if restored_text else ""
    for j, fn in enumerate(_FEATURE_FUNCTIONS_RESTORED):
        try:
            features[12 + j] = fn(restored)
        except Exception:
            features[12 + j] = 0.0

    # 第③类：过程层（12 维）
    for k, fn in enumerate(_FEATURE_FUNCTIONS_META):
        try:
            features[26 + k] = fn(meta)
        except Exception:
            features[26 + k] = 0.0

    # 清理 NaN / Inf
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

    return features


def extract_with_names(raw_payload: str, restored_text: str,
                       meta: ConfusionMeta) -> dict[str, float]:
    """
    带特征名称的输出（用于调试、演示、可视化）。
    """
    vec = extract(raw_payload, restored_text, meta)
    return {FEATURE_NAMES[i]: float(vec[i]) for i in range(38)}
