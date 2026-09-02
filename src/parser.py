"""
HTTP 请求解析器

输入：原始 HTTP 请求（字符串或分段）
输出：拆解后的参数列表，每个参数标注 (name, value, param_location)

支持的格式：
  - 完整 HTTP 请求文本（GET /path?q=xxx HTTP/1.1\\r\\nHeader: val\\r\\n\\r\\nbody）
  - 单独的 query string（key1=val1&key2=val2）
  - 单独的 JSON body
  - 单独的 URL 路径
"""

from __future__ import annotations

import re
import json as json_mod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse


@dataclass
class ParsedParam:
    """解析后的单个参数"""
    name: str               # 参数名（如 "q", "username", "User-Agent"）
    value: str              # 参数值（原始字符串，未解码）
    location: str           # query | body | header | cookie | path
    index: int = 0          # 在同类参数中的序号

    @property
    def display(self) -> str:
        return f"[{self.location}] {self.name}={self.value[:80]}"


@dataclass
class ParsedRequest:
    """解析后的 HTTP 请求"""
    method: str = ""
    path: str = ""
    query_string: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_raw: str = ""
    body_form: dict[str, str] = field(default_factory=dict)
    body_multipart: list[tuple[str, str]] = field(default_factory=list)
    body_json: Optional[dict] = None
    cookies: dict[str, str] = field(default_factory=dict)

    def all_params(self) -> list[ParsedParam]:
        """提取所有参数值，每个值标注位置"""
        params: list[ParsedParam] = []

        # --- query 参数 ---
        for i, (name, values) in enumerate(parse_qs(self.query_string, keep_blank_values=True).items()):
            for j, v in enumerate(values):
                params.append(ParsedParam(name=name, value=v, location="query", index=i))

        # --- body form 参数 ---
        for i, (name, value) in enumerate(self.body_form.items()):
            params.append(ParsedParam(name=name, value=value, location="body", index=i))

        # --- multipart/form-data fields and filenames ---
        for i, (name, value) in enumerate(self.body_multipart):
            params.append(ParsedParam(name=name, value=value, location="body", index=i))

        # --- body JSON: 递归提取所有叶子值 ---
        if self.body_json is not None:
            for leaf in _extract_json_leaves(self.body_json, ""):
                params.append(ParsedParam(name=leaf[0], value=str(leaf[1]), location="body", index=len(params)))

        # --- body raw (非 form/JSON 时，整段当作一个 body 值) ---
        if (
            self.body_raw.strip()
            and not self.body_form
            and not self.body_multipart
            and self.body_json is None
        ):
            params.append(ParsedParam(name="body", value=self.body_raw.strip(), location="body", index=0))

        # --- header 值 ---
        routine_headers = {
            "host", "accept", "accept-language", "accept-encoding",
            "connection", "content-length", "content-type", "cache-control",
            "pragma", "upgrade-insecure-requests",
            # Browser navigation metadata is a URL, not an application input.
            # Treating its path (for example /admin/set.php) as an uploaded
            # filename creates systematic false positives in reverse-proxy mode.
            "origin", "referer", "referrer",
        }
        for i, (name, value) in enumerate(self.headers.items()):
            lower_name = name.lower()
            if lower_name == "cookie" or lower_name in routine_headers or lower_name.startswith("sec-fetch-"):
                continue
            params.append(ParsedParam(name=name, value=value, location="header", index=i))

        # --- cookie 值 ---
        for i, (name, value) in enumerate(self.cookies.items()):
            params.append(ParsedParam(name=name, value=value, location="cookie", index=i))

        # --- URL 路径段 ---
        path_clean = self.path.strip("/")
        if path_clean:
            # Preserve the complete path for traversal and SSRF detection.
            params.append(ParsedParam(name="path", value=self.path, location="path", index=0))
            for i, segment in enumerate(path_clean.split("/")):
                if segment:
                    params.append(ParsedParam(name=f"path_seg_{i}", value=segment, location="path", index=i + 1))

        return params


def _extract_json_leaves(obj, prefix: str) -> list[tuple[str, str]]:
    """递归提取 JSON 对象中的所有叶子值"""
    leaves = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            leaves.extend(_extract_json_leaves(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            leaves.extend(_extract_json_leaves(v, key))
    else:
        leaves.append((prefix, str(obj)))
    return leaves


# ===================================================================
# 解析器
# ===================================================================

_HTTP_REQUEST_LINE = re.compile(
    r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT)\s+(.+?)\s+HTTP/\d\.\d',
    re.IGNORECASE,
)
_HEADER_LINE = re.compile(r'^([\w-]+):\s*(.*)$')


def _parse_multipart(body: str, content_type: str) -> list[tuple[str, str]]:
    """Extract browser form fields without treating MIME framing as payload."""

    boundary_match = re.search(
        r'\bboundary\s*=\s*(?:"([^"]+)"|([^;\s]+))',
        content_type,
        re.IGNORECASE,
    )
    if not boundary_match:
        return []
    boundary = boundary_match.group(1) or boundary_match.group(2)
    if not boundary or len(boundary) > 200 or any(char in boundary for char in "\r\n"):
        return []

    fields: list[tuple[str, str]] = []
    delimiter = f"--{boundary}"
    for raw_part in body.split(delimiter)[1:]:
        part = raw_part.lstrip("\r\n")
        if not part or part.startswith("--"):
            continue
        head, separator, value = part.partition("\n\n")
        if not separator:
            continue
        value = value.rstrip("\r\n")
        headers: dict[str, str] = {}
        for line in head.replace("\r\n", "\n").split("\n"):
            match = _HEADER_LINE.match(line.strip())
            if match:
                headers[match.group(1).lower()] = match.group(2).strip()

        disposition = headers.get("content-disposition", "")
        if not re.match(r"(?i)^form-data(?:;|$)", disposition):
            continue
        name_match = re.search(r'(?i)(?:^|;)\s*name="([^"]*)"', disposition)
        if not name_match or not name_match.group(1):
            continue
        name = name_match.group(1)
        filename_match = re.search(
            r'(?i)(?:^|;)\s*filename="([^"]*)"', disposition
        )
        if filename_match:
            filename = filename_match.group(1)
            if filename:
                fields.append((f"{name}.filename", filename))
            # Binary file bytes are not interpreted as a form field. Filename
            # and HTTP upload metadata remain available to upload rules.
            continue
        fields.append((name, value))
    return fields


def parse_http(raw: str) -> ParsedRequest:
    """
    解析完整 HTTP 请求文本。

    输入示例:
        GET /search?q=test&page=1 HTTP/1.1
        Host: example.com
        User-Agent: Mozilla/5.0
        Cookie: session=abc123; lang=zh

        {"filter":{"category":"books"}}

    返回: ParsedRequest（包含所有参数拆解）
    """
    req = ParsedRequest()
    lines = raw.replace("\r\n", "\n").split("\n")

    # --- 请求行 ---
    if lines:
        m = _HTTP_REQUEST_LINE.match(lines[0])
        if m:
            req.method = m.group(1).upper()
            full_path = m.group(2)
            parsed = urlparse(full_path)
            req.path = unquote(parsed.path)
            req.query_string = parsed.query or ""
        elif "=" in lines[0] and "HTTP/" not in lines[0]:
            # 纯 query string
            req.query_string = lines[0]
        else:
            # 可能是纯 path 或 body
            req.path = lines[0]

    # --- Header 和 body 分界 ---
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        m = _HEADER_LINE.match(line)
        if m:
            name = m.group(1).strip()
            value = m.group(2).strip()
            req.headers[name] = value
            # 提取 Cookie
            if name.lower() == "cookie":
                req.cookies = _parse_cookie(value)

    # --- Body ---
    if body_start and body_start < len(lines):
        req.body_raw = "\n".join(lines[body_start:])

    # --- 解析 body ---
    if req.body_raw:
        content_type = next(
            (
                value for name, value in req.headers.items()
                if name.lower() == "content-type"
            ),
            "",
        )
        if content_type.lower().startswith("multipart/form-data"):
            req.body_multipart = _parse_multipart(req.body_raw, content_type)

        # 尝试 JSON
        if not req.body_multipart and not content_type.lower().startswith("multipart/form-data"):
            try:
                req.body_json = json_mod.loads(req.body_raw)
            except (json_mod.JSONDecodeError, ValueError):
                pass

        # 尝试 form-urlencoded
        if (
            req.body_json is None
            and not content_type.lower().startswith("multipart/form-data")
            and "=" in req.body_raw
            and "{" not in req.body_raw
        ):
            try:
                req.body_form = {k: v[0] for k, v in parse_qs(req.body_raw, keep_blank_values=True).items()}
            except Exception:
                pass

    return req


def parse_quick(payload: str, param_location: str = "query") -> list[ParsedParam]:
    """
    快速解析：用户直接输入参数值（非完整 HTTP 报文）。

    这是 /detect API 的默认路径——用户只需传 payload 字符串 + 参数位置。
    """
    return [ParsedParam(name="value", value=payload, location=param_location, index=0)]


def parse_auto(text: str) -> list[ParsedParam]:
    """
    自动判断输入类型并解析：
      - 包含 "HTTP/" → 完整 HTTP 请求
      - 包含 "?" 和 "=" → query string
      - 包含 "{...}" → JSON body
      - 其他 → 当作单个参数值
    """
    text = text.strip()

    # 完整 HTTP 请求
    if _HTTP_REQUEST_LINE.match(text):
        return parse_http(text).all_params()

    # Query string
    if "=" in text and "HTTP/" not in text and "\n" not in text:
        req = ParsedRequest(query_string=text)
        return req.all_params()

    # JSON body
    if text.startswith("{") or text.startswith("["):
        try:
            data = json_mod.loads(text)
            req = ParsedRequest(body_json=data)
            return req.all_params()
        except (json_mod.JSONDecodeError, ValueError):
            pass

    # Fallback: 当作单个参数值
    return parse_quick(text, "query")


# ===================================================================
# Cookie 解析
# ===================================================================

def _parse_cookie(cookie_header: str) -> dict[str, str]:
    """解析 Cookie 头 → {name: value}"""
    cookies = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
        else:
            cookies[part] = ""
    return cookies
