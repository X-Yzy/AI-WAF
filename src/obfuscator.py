"""
混淆载荷生成器 / Payload Obfuscator

用途：
  1. 训练数据增强 — 每个 epoch 对正样本做在线混淆
  2. 测试集构建   — 对原始测试样本施加固定策略，构建分层难度测试集
  3. 对抗训练     — 生成当前模型最易漏报的对抗样本

7 类 19 种混淆策略：
  编码混淆 (6): url_encode_full, url_encode_double, html_entity_encode,
                 base64_encode, hex_encode, unicode_escape
  结构混淆 (4): sql_comment_insert, js_comment_insert, whitespace_fill,
                 case_randomize
  等价替换 (4): sql_char_encode, sql_concat_split, sql_hex_encode,
                 js_eval_wrap
  组合混淆 (3): mixed_random, layered_recursive, mimic_real_attack
  特定技术混淆 (2): path_encoding, command_obfuscation
"""

from __future__ import annotations

import base64
import html
import random
import re
import string
from typing import Callable, Optional

# ===========================================================================
# 策略注册表
# ===========================================================================

STRATEGIES: dict[str, Callable[[str], str]] = {}
STRATEGY_CATEGORIES: dict[str, list[str]] = {
    "encoding": [],
    "structural": [],
    "equivalence": [],
    "composite": [],
    "specific": [],
}


def _register(category: str, name: str):
    """装饰器：注册混淆策略"""
    def decorator(fn: Callable[[str], str]) -> Callable[[str], str]:
        STRATEGIES[name] = fn
        STRATEGY_CATEGORIES[category].append(name)
        return fn
    return decorator


# ===========================================================================
# 编码混淆 (6)
# ===========================================================================

@_register("encoding", "url_encode_full")
def obf_url_encode_full(payload: str) -> str:
    """全部字符 URL 编码（%XX）"""
    return ''.join(f'%{ord(c):02X}' if c not in ' \n\r\t' else c for c in payload)


@_register("encoding", "url_encode_double")
def obf_url_encode_double(payload: str) -> str:
    """双层 URL 编码"""
    first = obf_url_encode_full(payload)
    return ''.join(f'%{ord(c):02X}' if c == '%' else c for c in first)


@_register("encoding", "html_entity_encode")
def obf_html_entity_encode(payload: str) -> str:
    """HTML 实体编码：将特殊字符替换为 &#XX; 或命名实体"""
    result = []
    entity_map = {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'}
    for c in payload:
        if c in entity_map:
            result.append(entity_map[c])
        elif c.isprintable() and ord(c) > 127:
            result.append(f'&#{ord(c)};')
        else:
            result.append(c)
    return ''.join(result)


@_register("encoding", "base64_encode")
def obf_base64_encode(payload: str) -> str:
    """Base64 编码，随机选择标准/URL-safe/无填充"""
    b = payload.encode('utf-8', errors='replace')
    variants = [
        lambda: base64.b64encode(b).decode(),
        lambda: base64.urlsafe_b64encode(b).decode(),
    ]
    encoded = random.choice(variants)()
    if random.random() < 0.3:
        encoded = encoded.rstrip('=')
    return encoded


@_register("encoding", "hex_encode")
def obf_hex_encode(payload: str) -> str:
    """十六进制字节编码"""
    return payload.encode('utf-8', errors='replace').hex()


@_register("encoding", "unicode_escape")
def obf_unicode_escape(payload: str) -> str:
    """Unicode \\uXXXX 转义编码"""
    result = []
    for c in payload:
        if ord(c) > 127 or c in '<>"\';&|`':
            result.append(f'\\u{ord(c):04x}')
        else:
            result.append(c)
    return ''.join(result)


# ===========================================================================
# 结构混淆 (4)
# ===========================================================================

@_register("structural", "sql_comment_insert")
def obf_sql_comment_insert(payload: str) -> str:
    """
    在 SQL 关键字中间插入内联注释。
    例如 SELECT → /**/SEL/**/ECT
    """
    sql_keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'WHERE', 'FROM',
                    'HAVING', 'ORDER', 'GROUP', 'INTO', 'AND', 'OR', 'NOT']
    result = payload
    for kw in sorted(sql_keywords, key=len, reverse=True):
        pattern = re.compile(re.escape(kw), re.IGNORECASE)

        def _repl(m, kw=kw):
            w = m.group()
            if len(w) < 3:
                return w
            pos = random.randint(1, len(w) - 1)
            comment = random.choice(['/**/', '/*!*/', '/**_**/'])
            return w[:pos] + comment + w[pos:]

        result = pattern.sub(_repl, result)
    return result


@_register("structural", "js_comment_insert")
def obf_js_comment_insert(payload: str) -> str:
    """在 JS/XSS payload 中插入注释或换行"""
    if '<script>' in payload.lower() or '<script ' in payload.lower():
        # 在 script 标签内部插入单行注释 //
        payload = re.sub(
            r'(<script[^>]*>)',
            r'\1\n//',
            payload,
            flags=re.IGNORECASE
        )
    # 在敏感函数名中插入换行
    for kw in ['alert', 'eval', 'confirm', 'prompt', 'fetch']:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        if pattern.search(payload):
            payload = pattern.sub(f'{kw[:2]}\n{kw[2:]}', payload, count=1)
    return payload


@_register("structural", "whitespace_fill")
def obf_whitespace_fill(payload: str) -> str:
    """在关键字之间随机插入空格/Tab/换行"""
    # 在特定位置插入空白
    positions = [' ', '\t', '\n', '  ', ' \t']
    result = list(payload)

    # 在运算符和关键字符前后插入空白
    inject_points = [m.start() for m in re.finditer(r'[=\-+|&;(){}\[\]]', payload)]
    offset = 0
    for pt in sorted(inject_points):
        if random.random() < 0.4:
            ws = random.choice(positions)
            result.insert(pt + offset, ws)
            offset += len(ws)

    return ''.join(result)


@_register("structural", "case_randomize")
def obf_case_randomize(payload: str) -> str:
    """对字母字符随机变换大小写"""
    result = []
    for c in payload:
        if c.isalpha() and random.random() < 0.6:
            result.append(c.upper() if c.islower() else c.lower())
        else:
            result.append(c)
    return ''.join(result)


# ===========================================================================
# 语义等价替换 (4)
# ===========================================================================

@_register("equivalence", "sql_char_encode")
def obf_sql_char_encode(payload: str) -> str:
    """
    将 SQL 中的字符串字面量替换为 CHAR() 函数调用。
    例如 'abc' → CHAR(97,98,99)
    """
    def _char_repl(m):
        s = m.group(1)
        codes = ','.join(str(ord(c)) for c in s)
        return f'CHAR({codes})'

    # 匹配引号内的字符串
    result = re.sub(r"'([^']*)'", _char_repl, payload)
    return result


@_register("equivalence", "sql_concat_split")
def obf_sql_concat_split(payload: str) -> str:
    """
    将字符串拆分为 CONCAT() 调用。
    例如 'SELECT' → CONCAT('SE','LECT')
    """
    def _concat_repl(m):
        s = m.group(1)
        if len(s) < 3:
            return m.group(0)
        pos = random.randint(1, len(s) - 1)
        return f'CONCAT(\'{s[:pos]}\',\'{s[pos:]}\')'

    result = re.sub(r"'([^']{3,})'", _concat_repl, payload)
    return result


@_register("equivalence", "sql_hex_encode")
def obf_sql_hex_encode(payload: str) -> str:
    """
    将 SQL 中的字符串字面量替换为 0x 前缀的十六进制。
    """
    def _hex_repl(m):
        s = m.group(1)
        return f'0x{s.encode().hex()}'

    result = re.sub(r"'([^']*)'", _hex_repl, payload)
    return result


@_register("equivalence", "js_eval_wrap")
def obf_js_eval_wrap(payload: str) -> str:
    """
    将 JS 代码包裹在 eval(String.fromCharCode(...)) 中。
    仅当 payload 包含明显的 JS 函数调用时适用。
    """
    js_match = re.search(r'(alert|eval|prompt|confirm|fetch)\s*\(', payload, re.IGNORECASE)
    if not js_match:
        return payload

    def _wrap(m):
        inner = m.group(0)
        codes = ','.join(str(ord(c)) for c in inner)
        return f'eval(String.fromCharCode({codes}))'

    # 只包裹找到的 JS 调用
    result = re.sub(r'(alert|eval|prompt|confirm)\s*\([^)]*\)', _wrap, payload,
                    flags=re.IGNORECASE)
    return result


# ===========================================================================
# 特定技术混淆 (2)
# ===========================================================================

@_register("specific", "path_encoding")
def obf_path_encoding(payload: str) -> str:
    """
    路径穿越专用混淆：
    - ../ → %2e%2e%2f / ..%252f / ....//
    - \\ → %5c
    """
    variants = [
        lambda s: s.replace('../', '%2e%2e%2f').replace('..\\', '%2e%2e%5c'),
        lambda s: s.replace('../', '..%252f').replace('..\\', '..%255c'),
        lambda s: s.replace('../', '....//').replace('..\\', '....\\\\'),
        lambda s: s.replace('/', '%2f').replace('\\', '%5c'),
    ]
    for fn in variants:
        candidate = fn(payload)
        if candidate != payload:
            return candidate
    return payload


@_register("specific", "command_obfuscation")
def obf_command_obfuscation(payload: str) -> str:
    """
    命令注入专用混淆：
    - 空格替换为 ${IFS} / <>/ \t
    - 插入单引号（ca't / c'a't）
    """
    if ' ' in payload:
        payload = payload.replace(' ', random.choice(['${IFS}', '\t', '  ']))
    # 在命令名中插入单引号
    for cmd in ['cat', 'ls', 'id', 'whoami', 'uname', 'curl', 'wget', 'ping']:
        if cmd in payload.lower():
            pos = payload.lower().index(cmd)
            actual = payload[pos:pos+len(cmd)]
            split = random.randint(1, len(actual) - 1)
            payload = payload[:pos] + actual[:split] + "'" + actual[split:] + payload[pos+len(actual):]
            break
    return payload


# ===========================================================================
# 组合混淆 (3)
# ===========================================================================

@_register("composite", "mixed_random")
def obf_mixed_random(payload: str) -> str:
    """从所有编码+结构+等价策略中随机选 2-4 种，依次叠加"""
    pool = (
        STRATEGY_CATEGORIES["encoding"] +
        STRATEGY_CATEGORIES["structural"] +
        STRATEGY_CATEGORIES["equivalence"]
    )
    n = random.randint(2, min(4, len(pool)))
    chosen = random.sample(pool, k=n)
    result = payload
    for name in chosen:
        try:
            result = STRATEGIES[name](result)
        except Exception:
            continue
    return result


@_register("composite", "layered_recursive")
def obf_layered_recursive(payload: str) -> str:
    """
    多层递归混淆：编码 → 结构混淆 → 再编码 的套娃。
    模拟真实攻击中的多层嵌套混淆。
    """
    result = payload

    # 第一层：编码
    enc1 = random.choice(STRATEGY_CATEGORIES["encoding"])
    result = STRATEGIES[enc1](result)

    # 第二层：结构混淆（在编码后的文本上）
    if random.random() < 0.5:
        struct = random.choice(STRATEGY_CATEGORIES["structural"])
        result = STRATEGIES[struct](result)

    # 第三层：再编码
    enc2 = random.choice([e for e in STRATEGY_CATEGORIES["encoding"] if e != enc1])
    result = STRATEGIES[enc2](result)

    return result


@_register("composite", "mimic_real_attack")
def obf_mimic_real_attack(payload: str) -> str:
    """
    模拟真实攻击链中的混淆模式，与 generated_datasets 中的 hybrid/specific
    配置对齐。权重偏向实际攻击中常见的组合。
    """
    # 解码器要求与等价域标记取自数据集的设计
    # normalization-layer-dependent → 轻度 URL 编码/空白/大小写
    # explicit-decoder-required → Base64/Hex
    # parser-or-runtime-dependent → 特定技术混淆

    scope = random.choices(
        ["normalization", "explicit", "parser"],
        weights=[0.5, 0.34, 0.16],
        k=1
    )[0]

    if scope == "normalization":
        # URL 编码 + 可选的大小写/空白
        result = obf_url_encode_full(payload) if random.random() < 0.6 else obf_url_encode_double(payload)
        if random.random() < 0.3:
            result = obf_case_randomize(result)
        if random.random() < 0.3:
            result = obf_whitespace_fill(result)
    elif scope == "explicit":
        result = random.choice([obf_base64_encode, obf_hex_encode])(payload)
        if random.random() < 0.4:
            result = obf_url_encode_full(result)
    else:
        result = random.choice([obf_path_encoding, obf_command_obfuscation])(payload)
        if random.random() < 0.5:
            result = obf_sql_comment_insert(result)

    return result


# ===========================================================================
# 顶层接口
# ===========================================================================

def generate(payload: str,
             strategies: Optional[list[str]] = None,
             count: int = 1,
             max_layers: int = 3) -> list[str]:
    """
    生成 N 个混淆变种。

    参数：
      payload:    原始攻击 payload
      strategies: 指定策略名列表。为 None 或空时从所有策略中随机选取。
      count:      生成的变种数量
      max_layers: 每个变种最多叠加的策略层数

    返回：list[str]，长度为 count 的混淆变种列表
    """
    if strategies is None or len(strategies) == 0:
        pool = list(STRATEGIES.keys())
    else:
        pool = [s for s in strategies if s in STRATEGIES]

    if not pool:
        return [payload]

    results = []
    for _ in range(count):
        result = payload
        layers = random.randint(1, min(max_layers, len(pool)))
        chosen = random.sample(pool, k=layers)
        for name in chosen:
            try:
                result = STRATEGIES[name](result)
            except Exception:
                continue
        results.append(result)

    return results


def generate_online(payload: str) -> str:
    """
    训练时在线增强用：随机选 1-4 种策略，随机层数，返回 1 个变种。
    偏向保留语义的混淆模式。
    """
    # 训练时优先选择 normalization-layer 级别的混淆（不影响攻击语义的）
    # 以避免过多 explicit-decoder 级别的变种导致模型过拟合于特定编码
    categories = STRATEGY_CATEGORIES
    pool = (
        categories["encoding"][:3] +    # URL / HTML entity
        categories["structural"] +      # 注释插入 / 大小写 / 空白
        categories["equivalence"][:2]   # CHAR encode / CONCAT split
    )
    n = random.randint(1, 4)
    chosen = random.sample(pool, min(n, len(pool)))

    result = payload
    for name in chosen:
        try:
            result = STRATEGIES[name](result)
        except Exception:
            continue
    return result


def list_strategies() -> dict[str, list[str]]:
    """列出所有注册的策略，按类别分组"""
    return {k: list(v) for k, v in STRATEGY_CATEGORIES.items()}
