"""
载荷净化器 / Payload Normalizer

输入：原始 payload 字符串（可能包含多层混淆）
输出：(restored_text, ConfusionMeta)

职责：
  1. 尽最大努力还原混淆文本 → 为第②类特征（还原层）提供输入
  2. 记录还原过程的每一步 → 为第③类特征（过程层）提供数据
  3. 归一化失败时不抛异常，返回原始字符串 + meta.converged=False

支持的解码器（与数据集中出现的 decoder_requirements 对齐）：
  - URL 解码（单层 + 递归双层）
  - Base64 解码（标准 / urlsafe / urlsafe_nopad）
  - HTML 实体解码（命名 / 十进制 / 十六进制）
  - Unicode 转义解码（\\uXXXX / \\UXXXXXXXX）
  - Hex 字节解码
  - 结构还原（SQL 注释去除 / 空白规范化 / 路径规范化）
"""

from __future__ import annotations

import base64
import html
import math
import re
import string
from urllib.parse import unquote
import unicodedata
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# ConfusionMeta
# ---------------------------------------------------------------------------

@dataclass
class ConfusionMeta:
    """混淆过程元数据 —— 第③类特征的输入"""

    # 归一化是否收敛（达到不动点，即连续两轮输出相同）
    converged: bool = False

    # 编解码计数
    decode_depth: int = 0               # 循环解码的总轮数（直到收敛或超过 max_iter）
    decode_steps_attempted: int = 0     # 尝试过的解码步骤总数
    successful_decode_steps: int = 0    # 成功执行的解码步骤数

    # 各解码器独立计数
    url_decode_layers: int = 0          # URL 解码层数（含双层递归）
    base64_decode_attempted: bool = False
    base64_decode_success: bool = False
    html_entity_count: int = 0          # 替换的 HTML 实体数量
    unicode_escape_count: int = 0       # \\uXXXX 解码次数
    hex_decode_attempted: bool = False
    hex_decode_success: bool = False
    js_string_decode_attempted: bool = False
    js_string_decode_success: bool = False
    json_unicode_decode_attempted: bool = False
    json_unicode_decode_success: bool = False

    # 结构还原计数
    comment_blocks_removed: int = 0     # SQL/JS 注释块移除数
    concat_patterns_removed: int = 0    # 字符串拼接消除数
    whitespace_normalized: bool = False # 是否执行了空白规范化
    path_normalized: bool = False       # 是否执行了路径规范化

    # 长度与熵
    len_before: int = 0
    len_after: int = 0
    entropy_before: float = 0.0
    entropy_after: float = 0.0
    payload_grew: bool = False          # 解码后是否膨胀

    # 原始字符串保留
    original_payload: str = ""


# ---------------------------------------------------------------------------
# 熵值计算
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """计算字符串的 Shannon 熵"""
    if not s:
        return 0.0
    n = len(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in freq.values())


# ---------------------------------------------------------------------------
# 判断函数：字符串是否"看起来像"某种编码
# ---------------------------------------------------------------------------

_URL_ENCODED_RE = re.compile(r'%[0-9a-fA-F]{2}')

def _looks_url_encoded(s: str) -> bool:
    """判断字符串是否包含 URL 编码模式（%XX），且占比足够高"""
    matches = _URL_ENCODED_RE.findall(s)
    if not matches:
        return False
    # 至少 2 个 %XX 或占非空白字符的 10%+
    ratio = len(matches) / max(len(re.sub(r'\s', '', s)), 1)
    return len(matches) >= 2 or ratio >= 0.1

def _looks_base64(s: str) -> bool:
    """
    判断字符串是否"看起来像" Base64。
    条件：仅含 Base64 字符集，长度合规，且有一定长度。

    Base64 编码规则：3 字节 → 4 字符。因此无填充时：
      - 1 字节输入 → 2 字符 (mod 4 = 2)
      - 2 字节输入 → 3 字符 (mod 4 = 3)
      - 3 字节输入 → 4 字符 (mod 4 = 0)
    唯一不合法的无填充长度是 mod 4 = 1。
    """
    s_clean = s.strip()
    if len(s_clean) < 8 or any(ch.isspace() for ch in s_clean):
        return False
    # 允许标准 Base64 和 URL-safe Base64 的字符集
    valid = set(string.ascii_letters + string.digits + '+/=-_')
    if not set(s_clean).issubset(valid):
        return False
    # 去除尾部 = 后，长度 mod 4 不应为 1
    stripped = s_clean.rstrip('=')
    if len(stripped) % 4 == 1:
        return False
    # Short plain identifiers are much more common than unpadded Base64.
    # Require either an encoding marker or enough length/entropy.
    has_marker = any(ch in s_clean for ch in "+/=_-")
    if not has_marker and (len(s_clean) < 24 or _shannon_entropy(s_clean) < 3.5):
        return False
    return True

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

def _looks_hex(s: str) -> bool:
    """判断纯 hex 字符串"""
    s_clean = s.strip()
    return len(s_clean) >= 8 and len(s_clean) % 2 == 0 and bool(_HEX_RE.match(s_clean))

_UNICODE_ESCAPE_RE = re.compile(r'\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}')

def _looks_unicode_escaped(s: str) -> bool:
    return bool(_UNICODE_ESCAPE_RE.search(s))

_HTML_ENTITY_RE = re.compile(r'&(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);')

def _looks_html_entity(s: str) -> bool:
    return bool(_HTML_ENTITY_RE.search(s))

_JS_STRING_ESCAPE_RE = re.compile(r'\\(?:[\\\'\"nrt0bfvx]|u[0-9a-fA-F]{4})')

def _looks_js_string_escaped(s: str) -> bool:
    return bool(_JS_STRING_ESCAPE_RE.search(s))

_JSON_UNICODE_RE = re.compile(r'\\u[0-9a-fA-F]{4}')

def _looks_json_unicode(s: str) -> bool:
    return bool(_JSON_UNICODE_RE.search(s))


# ---------------------------------------------------------------------------
# 解码器函数
# ---------------------------------------------------------------------------

def _try_url_decode(s: str) -> tuple[str, int]:
    """
    递归 URL 解码直到稳定。
    返回：(decoded_text, layers_applied)
    layers_applied=0 表示无变化。
    """
    layers = 0
    prev = s
    max_layers = 3  # 最多递归 3 层，防止无限循环
    for _ in range(max_layers):
        try:
            # Python 的 unquote 不会抛异常，但可能产生无效 UTF-8
            decoded = _safe_unquote(prev)
        except Exception:
            break
        if decoded == prev:
            break
        prev = decoded
        layers += 1
    return prev, layers


def _safe_unquote(s: str) -> str:
    """UTF-8 aware percent decoding; malformed sequences are preserved safely."""
    return unquote(s, encoding="utf-8", errors="replace")


def _try_base64_decode(s: str) -> tuple[Optional[str], bool]:
    """
    尝试 Base64 解码（标准 + URL-safe + 无填充）。
    返回：(decoded_text_or_None, success)

    策略：
      1. 生成候选编码（原始 / URL-safe→标准转换 / 补齐填充）
      2. 用 validate=True 严格解码，检查可打印率 > 70%
      3. 宽松模式兜底
      4. 如果解码后熵值降低 > 0.5，额外加分
    """
    if not _looks_base64(s):
        return None, False

    # 生成候选编码
    candidates = []

    # 候选 1：原始字符串
    candidates.append(s.strip())

    # 候选 2：URL-safe → 标准转换
    if '-' in s or '_' in s:
        candidates.append(s.replace('-', '+').replace('_', '/'))

    # 候选 3：补齐缺失的填充
    for i in range(len(candidates)):
        c = candidates[i]
        missing = (4 - len(c) % 4) % 4
        if missing:
            candidates.append(c + '=' * missing)
        # 也尝试去掉填充的版本
        stripped = c.rstrip('=')
        if stripped != c:
            candidates.append(stripped)

    # 去重
    candidates = list(dict.fromkeys(candidates))

    best_text = None
    best_score = 0.0  # 0~1，越高越好

    for c in candidates:
        for validate_flag in [True, False]:
            try:
                decoded_bytes = base64.b64decode(c, validate=validate_flag)
                # Random session identifiers often happen to use the Base64
                # alphabet. Binary/non-UTF-8 output must not be treated as text.
                decoded = decoded_bytes.decode('utf-8', errors='strict')
                if not decoded.strip():
                    continue
                # 可打印字符比例
                printable = sum(1 for ch in decoded if ch.isprintable() or ch in '\n\r\t')
                ratio = printable / max(len(decoded), 1)
                if ratio < 0.65:
                    continue
                # Accept short/flat encodings only when decoding reveals
                # an unambiguous attack primitive. Prevents false B64 triggering
                # on ordinary opaque session tokens / CSRF nonces.
                if re.search(
                    r"(?is)(?:\b(?:sleep|pg_sleep|benchmark)\s*\(|"
                    r"\bunion\s+(?:all\s+)?select\b|<\s*(?:script|svg|img)\b|"
                    r"(?:^|[;&|])\s*(?:cat|id|whoami|curl|wget|bash|sh)\b|"
                    r"\{\{[^{}]+\}\}|\.\.[/\\]|<!doctype|<!entity|"
                    r"(?:127\.0\.0\.1|169\.254\.169\.254|metadata\.google\.internal)|"
                    r"(?:(?:%(?:\d+\$|\d+)?[spxXdn])){3,})",
                    decoded,
                ):
                    return decoded, True
                # 解码后熵值降低是强信号
                ent_before = _shannon_entropy(s)
                ent_after = _shannon_entropy(decoded)
                ent_bonus = max(0, (ent_before - ent_after) / max(ent_before, 0.01)) * 0.3
                score = ratio * 0.7 + ent_bonus
                if score > best_score:
                    best_score = score
                    best_text = decoded
                if score > 0.85:
                    return best_text, True
            except Exception:
                continue

    if best_text is not None and best_score > 0.72:
        return best_text, True
    return None, False  # Clean failure; avoid leaking partial decodes.


def _try_html_entity_decode(s: str) -> tuple[str, int]:
    """
    解码 HTML 实体。
    返回：(decoded_text, entity_count)
    """
    count = len(_HTML_ENTITY_RE.findall(s))
    if count == 0:
        return s, 0
    decoded = html.unescape(s)
    return decoded, count if decoded != s else 0


def _try_unicode_escape_decode(s: str) -> tuple[str, int]:
    """
    解码 \\uXXXX / \\UXXXXXXXX 转义。
    """
    count = len(_UNICODE_ESCAPE_RE.findall(s))
    if count == 0:
        return s, 0

    def _replace(m):
        try:
            return chr(int(m.group()[2:], 16))
        except (ValueError, OverflowError):
            return m.group()

    decoded = _UNICODE_ESCAPE_RE.sub(_replace, s)
    return decoded, count if decoded != s else 0


def _try_hex_decode(s: str) -> tuple[str, bool]:
    """尝试 hex → bytes → UTF-8 解码"""
    if not _looks_hex(s):
        return s, False
    try:
        decoded = bytes.fromhex(s).decode('utf-8', errors='strict')
        printable = sum(1 for ch in decoded if ch.isprintable() or ch in '\n\r\t')
        ratio = printable / max(len(decoded), 1)
        return decoded, ratio > 0.7
    except Exception:
        return s, False


def _try_js_string_decode(s: str) -> tuple[str, bool]:
    """
    尝试解码 JavaScript 风格的字符串转义。
    """
    if not _JS_STRING_ESCAPE_RE.search(s):
        return s, False
    try:
        # 使用 unicode_escape codec（类似 Python 的字符串转义）
        decoded = s.encode('latin-1', errors='replace').decode('unicode_escape', errors='replace')
        return decoded, decoded != s
    except Exception:
        return s, False


def _try_json_unicode_decode(s: str) -> tuple[str, bool]:
    """解码 JSON 风格的 \\uXXXX"""
    if not _JSON_UNICODE_RE.search(s):
        return s, False

    def _replace(m):
        try:
            return chr(int(m.group()[2:], 16))
        except (ValueError, OverflowError):
            return m.group()

    decoded = _JSON_UNICODE_RE.sub(_replace, s)
    return decoded, decoded != s


# Unicode security: NFKC plus zero-width/bidi control removal.
_SECURITY_IGNORABLES_RE = re.compile(
    "[­͏؜᠎​-‏‪-‮"
    "⁠-⁤⁦-⁯﻿]"
)


def _normalize_unicode_security(s: str) -> tuple[str, bool]:
    """Apply NFKC and strip invisible controls (zero-width, bidi, soft-hyphen).

    NFKC folds full-width ASCII (``ＳＥＬＥＣＴ`` → ``SELECT``).
    Removing zero-width/bidi prevents signature splitting and UI spoofing.
    """
    normalized = unicodedata.normalize("NFKC", s)
    normalized = _SECURITY_IGNORABLES_RE.sub("", normalized)
    return normalized, normalized != s


# ---------------------------------------------------------------------------
# 结构还原函数
# ---------------------------------------------------------------------------

_SQL_INLINE_COMMENT_RE = re.compile(r'/\*!?\d*\s*(.*?)\s*\*/', re.DOTALL)
_SQL_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)

def _remove_sql_comments(s: str) -> tuple[str, int]:
    """移除 SQL 内联注释（/**/ 和 /*!NNNNN*/），记录移除数量"""
    count = 0

    # 先处理 /*!...*/ （versioned comments — 保留内容）
    def _versioned_repl(m):
        nonlocal count
        inner = m.group(1)
        if inner.strip():
            count += 1
            return inner
        count += 1
        return ''

    result = _SQL_INLINE_COMMENT_RE.sub(_versioned_repl, s)

    # 再处理普通 /**/
    def _counted_repl(m):
        nonlocal count
        count += 1
        return ''

    result = _SQL_COMMENT_RE.sub(_counted_repl, result)
    return result, count


_JAVA_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
_HTML_COMMENT_RE = re.compile(r'<!--.*?-->', re.DOTALL)
_LINE_COMMENT_RE = re.compile(r'(?<!:)//[^\n\r]*')

def _remove_general_comments(s: str) -> tuple[str, int]:
    """移除通用注释（JS //、HTML <!-- -->、Java /* */）"""
    count = 0

    def _repl(m):
        nonlocal count
        count += 1
        return ''

    s = _LINE_COMMENT_RE.sub(_repl, s)
    s = _HTML_COMMENT_RE.sub(_repl, s)
    s = _JAVA_COMMENT_RE.sub(_repl, s)
    return s, count


_STRING_CONCAT_RE = re.compile(r"('[^']*')\s*\+\s*('[^']*')")
_SQL_CONCAT_RE = re.compile(r"CONCAT\s*\(\s*('[^']*')\s*,\s*('[^']*')\s*\)", re.IGNORECASE)
_PIPE_CONCAT_RE = re.compile(r"('[^']*')\s*\|\|\s*('[^']*')")

def _remove_string_concat(s: str) -> tuple[str, int]:
    """消除字符串拼接模式"""
    count = 0

    def _simple_repl(m):
        nonlocal count
        count += 1
        left = m.group(1).strip("'")
        right = m.group(2).strip("'")
        return f"'{left}{right}'"

    s, n = _STRING_CONCAT_RE.subn(_simple_repl, s)
    count += n
    s, n = _SQL_CONCAT_RE.subn(_simple_repl, s)
    count += n
    s, n = _PIPE_CONCAT_RE.subn(_simple_repl, s)
    count += n
    return s, count


_MULTI_SPACE_RE = re.compile(r'[ \t]+')
_MULTI_NEWLINE_RE = re.compile(r'[\n\r]{2,}')

def _normalize_whitespace(s: str) -> tuple[str, bool]:
    """
    空白字符规范化：
    - 压缩连续空格/tab 为单个空格
    - 压缩连续（2+）换行为单个换行
    - 保留首尾结构（不 strip）
    """
    result = _MULTI_SPACE_RE.sub(' ', s)
    result = _MULTI_NEWLINE_RE.sub('\n', result)
    changed = result != s
    return result, changed


_DOTDOT_PATH_RE = re.compile(r'\.\.?/')

def _normalize_path(s: str) -> tuple[str, bool]:
    """
    路径规范化：
    - 将 \\ 替换为 /
    - 折叠 /./ 和 /../ 段
    - 处理 ....// 等价于 ../ 的混淆变种
    - 处理冗余斜杠 // → /
    """
    result = s.replace('\\', '/')

    # 冗余斜杠
    result = re.sub(r'/{2,}', '/', result)

    # 折叠 /./ → /
    prev = None
    while prev != result:
        prev = result
        result = result.replace('/./', '/')

    # 折叠 /<segment>/../ → /（但不折叠 /../ — .. 自身不能被折叠）
    prev = None
    while prev != result:
        prev = result
        result = re.sub(r'/(?!\.\.(/|$))[^/]+/\.\./', '/', result)

    # "..../" 变种（= "../" 的混淆形式，某些文件系统将多余的点折叠）
    # 递归替换直到稳定
    prev = None
    while prev != result:
        prev = result
        result = re.sub(r'\.\.\.\./', '../', result)

    # 去掉尾部 /.
    result = re.sub(r'/\.$', '/', result)

    changed = result != s
    return result, changed


# ---------------------------------------------------------------------------
# 归一化器主入口
# ---------------------------------------------------------------------------

# 解码步骤定义：(名称, 函数, 是否需要使用"试探"策略)
DECODE_PIPELINE = [
    # Unicode security normalization first: fold fullwidth and strip controls.
    # zero-width/bidi before any encoding-based normalization
    ('unicode_security',    _normalize_unicode_security, False),
    ('url_decode',          _try_url_decode,          True),
    ('hex_decode',          _try_hex_decode,          True),
    ('base64_decode',       _try_base64_decode,       True),
    ('unicode_escape',      _try_unicode_escape_decode, True),
    ('html_entity',         _try_html_entity_decode,  True),
]

STRUCTURE_PIPELINE = [
    ('normalize_path',      _normalize_path),       # 先折叠路径中的 //，避免被 general_comments 误判为 JS 注释
    ('sql_comments',        _remove_sql_comments),
    ('general_comments',    _remove_general_comments),
    ('string_concat',       _remove_string_concat),
    ('normalize_whitespace',_normalize_whitespace),
]


def normalize(payload: str, max_iterations: int = 5,
              param_location: str = "query") -> tuple[str, ConfusionMeta]:
    """
    归一化器主入口。

    输入：原始 payload 字符串（可能含多层混淆）
    输出：(best_effort_restored_text, ConfusionMeta)

    算法：
      1. 计算原始熵值
      2. 循环：依次尝试所有解码器 + 结构还原
      3. 直到本轮无任何变化（收敛）或达到 max_iterations
      4. 计算还原后熵值
      5. 返回结果

    归一化失败时不抛异常，返回原始字符串 + meta.converged=False。
    """
    meta = ConfusionMeta(
        original_payload=payload,
        len_before=len(payload),
        entropy_before=_shannon_entropy(payload),
    )

    current = payload
    prev_global = None
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        meta.decode_depth = iteration
        round_changed = False

        # --- 阶段 1：解码 ---
        for name, fn, is_heuristic in DECODE_PIPELINE:
            meta.decode_steps_attempted += 1
            try:
                if is_heuristic:
                    # 根据函数不同签名处理
                    if name == 'base64_decode':
                        result, success = fn(current)
                        meta.base64_decode_attempted = True
                        if success and result and result != current:
                            meta.successful_decode_steps += 1
                            meta.base64_decode_success = True
                            current = result
                            round_changed = True
                        elif result and result != current:
                            # 弱信号：也接受
                            current = result
                            round_changed = True
                    elif name in ('url_decode',):
                        result, layers = fn(current)
                        if layers > 0:
                            meta.successful_decode_steps += 1
                            meta.url_decode_layers += layers
                            current = result
                            round_changed = True
                    elif name in ('unicode_escape',):
                        result, count = fn(current)
                        if count > 0:
                            meta.successful_decode_steps += 1
                            meta.unicode_escape_count += count
                            current = result
                            round_changed = True
                    elif name in ('html_entity',):
                        result, count = fn(current)
                        if count > 0:
                            meta.successful_decode_steps += 1
                            meta.html_entity_count += count
                            current = result
                            round_changed = True
                    elif name in ('hex_decode',):
                        meta.hex_decode_attempted = True
                        result, success = fn(current)
                        if success and result != current:
                            meta.successful_decode_steps += 1
                            meta.hex_decode_success = True
                            current = result
                            round_changed = True
                else:
                    result, changed = fn(current)
                    if changed:
                        meta.successful_decode_steps += 1
                        current = result
                        round_changed = True
            except Exception:
                continue

        # --- 阶段 2：结构还原 ---
        for name, fn in STRUCTURE_PIPELINE:
            try:
                # Structural transforms are context-sensitive.  Applying path
                # folding and comment removal to every header/token corrupts
                # legitimate URLs, JSON and documentation text.
                if name == 'normalize_path' and not (
                    param_location == 'path'
                    or re.search(r'(?i)(?:\.\.[/\\]|%2e%2e|%252e)', current)
                ):
                    continue
                if name == 'sql_comments' and '/*' not in current:
                    continue
                if name == 'general_comments' and not any(
                    marker in current for marker in ('<!--', '/*', '//')
                ):
                    continue
                if name == 'general_comments' and re.match(r'^[a-z][a-z0-9+.-]*://', current, re.I):
                    continue
                result, info = fn(current)
                changed = info if isinstance(info, bool) else (info > 0)
                if changed:
                    if name == 'sql_comments' or name == 'general_comments':
                        meta.comment_blocks_removed += info if isinstance(info, int) else 1
                    elif name == 'string_concat':
                        meta.concat_patterns_removed += info if isinstance(info, int) else 1
                    elif name == 'normalize_whitespace':
                        meta.whitespace_normalized = True
                    elif name == 'normalize_path':
                        meta.path_normalized = True
                    current = result
                    round_changed = True
            except Exception:
                continue

        # 检查全局收敛
        if current == prev_global:
            meta.converged = True
            break
        prev_global = current

        if not round_changed:
            meta.converged = True
            break

    # --- 最终：计算还原后指标 ---
    meta.len_after = len(current)
    meta.entropy_after = _shannon_entropy(current)
    meta.payload_grew = meta.len_after > meta.len_before

    if meta.len_before > 0:
        meta.len_before = meta.len_before  # already set

    return current, meta


# ---------------------------------------------------------------------------
# 便捷函数：从数据集的 JSON 记录中提取归一化结果
# ---------------------------------------------------------------------------

def normalize_from_record(record: dict, max_iterations: int = 5) -> tuple[str, ConfusionMeta]:
    """
    从 source_records.json 或 dataset_obfuscated.json 的记录中提取 payload 并归一化。
    自动处理两种格式：
      - source_records: 使用 record['payload']
      - dataset_obfuscated: 使用 record['obfuscated_payload']（如果存在），否则 record['payload']
    """
    # 优先用 obfuscated_payload（generated 数据集）
    payload = record.get('obfuscated_payload') or record.get('payload', '')
    return normalize(payload, max_iterations, str(record.get('param_location', 'query')))
