#!/usr/bin/env python3
"""Build a provenance-rich, recent-CVE Web field and full-request dataset.

The builder parses public ProjectDiscovery Nuclei HTTP templates offline.  It
never executes a template or sends a request to a template target.  CISA KEV is
used only as prioritisation metadata.  A record is emitted only when a request
field contains an explicit attack primitive; product/version probes and
context-only authentication checks are deliberately excluded from ML labels.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import itertools
import json
import re
import shutil
import tarfile
import tempfile
import urllib.request
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import yaml
except ModuleNotFoundError:  # 普通训练/测试不应被可选的数据刷新依赖阻断。
    yaml = None


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "generated"
LOCK_FILE = Path(__file__).resolve().parent / "sources.lock.json"
KEV_SNAPSHOT = Path(__file__).resolve().parent / "source_snapshots" / "cisa_kev.json"
GITHUB_LATEST = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "AI-WAF-defensive-dataset-builder/1.0"
SEVERITY_ORDER = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def require_yaml():
    if yaml is None:
        raise RuntimeError(
            "刷新近期 CVE 数据需要 PyYAML；请执行 "
            "`python -m pip install PyYAML==6.0.3`。"
        )
    return yaml


# Patterns intentionally require a concrete exploit primitive.  They do not
# classify a product path, version string, or external URL as malicious by
# itself.  The template's tags are an additional gate for ambiguous primitives.
SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sqli", re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|['\"]\s*(?:or|and)\s+(?:['\"\d]|true|false)|\b(?:sleep|pg_sleep|benchmark|waitfor|extractvalue|updatexml)\s*\(|\b(?:drop\s+table|into\s+(?:out|dump)file|load_file\s*\())", re.I | re.S)),
    ("xss", re.compile(r"(?:<\s*(?:script|svg|img|iframe|body|input|details|video)\b|\bon\w+\s*=|javascript\s*:|document\.cookie|data:text/html)", re.I | re.S)),
    ("ssti", re.compile(r"(?:\{\{[^{}]{1,500}\}\}|\$\{[^{}]{1,500}\}|<%=?[^%]{1,500}%>|__class__|\.class\.forname)", re.I | re.S)),
    ("ptrav", re.compile(r"(?:\.\.[/\\]|%2e%2e|%252e|/etc/(?:passwd|shadow)|windows[/\\]system32)", re.I)),
    ("xxe", re.compile(r"(?:<!doctype|<!entity|\bsystem\s+[\"'](?:file|https?):|%\s*\w+\s*;)", re.I | re.S)),
    ("ssrf", re.compile(r"(?:(?:127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal|localhost)|(?:file|gopher|dict)://|https?://\[(?:::1|0:0:0:0:0:0:0:1)\])", re.I)),
    ("nosql", re.compile(r"(?:\$(?:ne|gt|gte|lt|lte|where|regex|nin)\b|\{\s*[\"']?\$(?:ne|where|regex))", re.I)),
    ("ldap", re.compile(r"(?:\(\s*[|&!]\s*\(|\([^)]*=\*\)|\*\)\(|\)\(\|)", re.I)),
    ("crlf", re.compile(r"(?:%0d|%0a|\\r|\\n|\r|\n)", re.I)),
    ("deser", re.compile(r"(?:rO0AB|O:\d+:\"|a:\d+:\{|aced0005|gASV|marshal\.loads|yaml\.load|node-serialize)", re.I)),
    ("jwt", re.compile(r"(?:\"alg\"\s*:\s*\"none\"|eyJhbGciOiJub25l|\"kid\"\s*:\s*\"[^\"]*(?:\.\.|/etc/|/root/|localhost|127\.0\.0\.1))", re.I)),
    ("ssi", re.compile(r"<!--\s*#(?:exec|include|echo|config|set)\b", re.I)),
    ("hsmug", re.compile(r"(?:transfer-encoding\s*:\s*(?:chunked|x)|content-length\s*:\s*\d+[\s\S]{0,160}transfer-encoding|0\r?\n\r?\n(?:get|post)\s+/)", re.I)),
    ("fupl", re.compile(r"(?:\.(?:php\d*|phtml|phar|asp|aspx|jsp|jspx|war|htaccess)(?:[.\s]|$)|<\?(?:php|=))", re.I)),
)

COMMAND = re.compile(
    r"(?:\$\(|`[^`]+`|(?:^|\s|[;&|])(?:cat|id|whoami|uname|curl|wget|nc|bash|sh|powershell|cmd)(?:\s|$)|\$\{?ifs\}?|runtime\.getruntime|processbuilder)",
    re.I | re.S,
)
COMMAND_TAGS = {"rce", "cmdi", "command-injection", "code-injection", "os-command-injection"}
CODE_EXEC = re.compile(
    r"(?:runtime\.getruntime\s*\(|java\.lang\.runtime|getruntime\(\)|processbuilder|class\.forname\s*\(|create\s+alias\b)",
    re.I | re.S,
)
TYPE_TAGS = {
    "sqli": {"sqli", "sql-injection"}, "xss": {"xss"},
    "ssti": {"ssti", "template-injection"},
    "ptrav": {"lfi", "file-read", "path-traversal", "traversal"},
    "xxe": {"xxe"}, "ssrf": {"ssrf"}, "nosql": {"nosqli", "nosql"},
    "ldap": {"ldap"}, "crlf": {"crlf", "header-injection"},
    "deser": {"deserialization", "deser"}, "jwt": {"jwt"},
    "ssi": {"ssi"}, "hsmug": {"request-smuggling", "smuggling"},
    "fupl": {"file-upload", "upload"},
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_payload(value: str) -> str:
    """Leakage fingerprint form; decoding is for grouping, not model input."""
    from urllib.parse import unquote

    restored = value.strip()
    for _ in range(2):
        decoded = unquote(restored)
        if decoded == restored:
            break
        restored = decoded
    return re.sub(r"\s+", " ", restored).strip().lower()


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def latest_release() -> dict:
    payload = json.loads(fetch(GITHUB_LATEST))
    return {
        "version": str(payload["tag_name"]),
        "published_at": str(payload["published_at"]),
        "archive_url": str(payload["tarball_url"]),
    }


def load_lock() -> dict:
    if not LOCK_FILE.is_file():
        return {}
    value = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid source lock: {LOCK_FILE}")
    return value


def safe_extract(archive: bytes, destination: Path) -> Path:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = bundle.getmembers()
        root = destination.resolve()
        for member in members:
            target = (destination / member.name).resolve()
            if root != target and root not in target.parents:
                raise ValueError(f"unsafe archive member: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"archive links are not accepted: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"archive special files are not accepted: {member.name}")
        # Paths and links were validated above; omit Python 3.12's ``filter``
        # argument so the project remains compatible with its Python 3.10 floor.
        bundle.extractall(destination, members=members)
    children = [item for item in destination.iterdir() if item.is_dir()]
    if len(children) != 1:
        raise ValueError("unexpected Nuclei archive layout")
    return children[0]


def split_for(group: str) -> str:
    fraction = int(hashlib.sha256(f"modern-cve:{group}".encode()).hexdigest()[:13], 16) / float(0xFFFFFFFFFFFFF)
    return "train" if fraction < 0.75 else ("validation" if fraction < 0.87 else "test")


def tags_of(info: dict) -> set[str]:
    raw = info.get("tags", "")
    values = raw if isinstance(raw, list) else str(raw).split(",")
    return {str(value).strip().lower() for value in values if str(value).strip()}


def classification_of(info: dict) -> dict:
    value = info.get("classification") or {}
    return value if isinstance(value, dict) else {}


def scalar_values(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))][:3]
    if isinstance(value, (str, int, float)):
        return [str(value)]
    return []


def variable_sets(request: dict) -> list[dict[str, str]]:
    payloads = request.get("payloads") or {}
    if not isinstance(payloads, dict):
        return [{}]
    names, choices = [], []
    for name, value in payloads.items():
        options = scalar_values(value)
        if options:
            names.append(str(name))
            choices.append(options)
    if not names:
        return [{}]
    return [dict(zip(names, values)) for values in itertools.islice(itertools.product(*choices), 6)]


def render(value: str, variables: dict[str, str]) -> str:
    replacements = {
        "BaseURL": "https://target.example.test", "RootURL": "https://target.example.test",
        "Hostname": "target.example.test", "Host": "target.example.test",
        "Scheme": "https", "Port": "443",
    } | variables
    for name, replacement in replacements.items():
        value = value.replace("{{" + name + "}}", replacement)
    # Preserve unknown DSL expressions as visible tokens but remove runtime-only
    # random helpers so they cannot dominate character features.
    value = re.sub(r"\{\{(?:rand_base|rand_text|rand_int|to_lower|to_upper)[^{}]*\}\}", "sample", value, flags=re.I)
    # Nuclei's own variables and DSL wrappers are transport placeholders, not
    # SSTI payloads.  Collapse them while retaining literal expressions such as
    # ``{{7*7}}`` or ``{{config.items()}}`` that are actually sent to a target.
    for _ in range(3):
        value = re.sub(r"\{\{[A-Za-z_][\w.-]*\([^{}]*\)\}\}", "sample", value)
        value = re.sub(r"\{\{[A-Za-z_][\w.-]*\}\}", "sample", value)
    return value


def raw_requests(request: dict) -> Iterable[str]:
    variables = variable_sets(request)
    raw = request.get("raw") or []
    if isinstance(raw, str):
        raw = [raw]
    for template in raw if isinstance(raw, list) else []:
        if isinstance(template, str):
            for values in variables:
                yield render(template, values).strip()

    methods = request.get("method", "GET")
    methods = methods if isinstance(methods, list) else [methods]
    paths = request.get("path") or []
    paths = paths if isinstance(paths, list) else [paths]
    headers = request.get("headers") or {}
    body = request.get("body", "")
    if not isinstance(headers, dict):
        headers = {}
    for method, path, values in itertools.islice(itertools.product(methods, paths, variables), 12):
        if not isinstance(path, str):
            continue
        target = render(path, values).replace("https://target.example.test", "") or "/"
        lines = [f"{str(method).upper()} {target} HTTP/1.1", "Host: target.example.test"]
        lines.extend(f"{key}: {render(str(value), values)}" for key, value in headers.items())
        yield "\r\n".join(lines) + "\r\n\r\n" + render(str(body or ""), values)


def parse_fields(raw: str) -> list[tuple[str, str, str]]:
    """Small self-contained HTTP field parser for dataset construction."""
    from urllib.parse import parse_qsl, unquote, urlsplit

    raw = raw.replace("\r\n", "\n").strip()
    head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return []
    match = re.match(r"^[A-Z]+\s+(\S+)", lines[0], re.I)
    target = match.group(1) if match else "/"
    parsed = urlsplit(target)
    fields: list[tuple[str, str, str]] = []
    if parsed.path and parsed.path != "/":
        fields.append(("path", unquote(parsed.path), "path"))
    fields.extend((name, value, "query") for name, value in parse_qsl(parsed.query, keep_blank_values=True))
    content_type = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "content-type":
            content_type = value.strip().lower()
        elif name.strip().lower() not in {"host", "accept", "content-length", "user-agent"}:
            fields.append((name.strip(), value.strip(), "header"))
    if body.strip():
        if "json" in content_type or body.lstrip().startswith(("{", "[")):
            try:
                parsed_body = json.loads(body)
                def leaves(value: object, prefix: str = "") -> Iterable[tuple[str, str, str]]:
                    if isinstance(value, dict):
                        for key, child in value.items():
                            yield from leaves(child, f"{prefix}.{key}" if prefix else str(key))
                    elif isinstance(value, list):
                        for index, child in enumerate(value):
                            yield from leaves(child, f"{prefix}[{index}]")
                    else:
                        yield prefix or "body", str(value), "body"
                fields.extend(leaves(parsed_body))
            except (json.JSONDecodeError, ValueError):
                fields.append(("body", body.strip(), "body"))
        elif "x-www-form-urlencoded" in content_type:
            fields.extend((name, value, "body") for name, value in parse_qsl(body, keep_blank_values=True))
        else:
            fields.append(("body", body.strip(), "body"))
    return fields


def classify(value: str, tags: set[str], location: str | None = None) -> tuple[str, str] | None:
    if not value or len(value) > 8192:
        return None
    matches: list[tuple[str, str]] = []
    for attack_type, pattern in SIGNALS:
        if pattern.search(value):
            expected = TYPE_TAGS.get(attack_type, set())
            # A server endpoint ending in upload.php is not itself an uploaded
            # executable.  File-upload positives must come from body/query/
            # filename fields, never merely from the request route.
            if attack_type == "fupl" and location == "path":
                continue
            matches.append((attack_type, f"cve_{attack_type}"))
            # Prefer a syntactic match that agrees with the template taxonomy.
            if tags & expected:
                return attack_type, f"cve_{attack_type}"
    if CODE_EXEC.search(value) and tags & COMMAND_TAGS:
        return "codei", "cve_code_execution"
    if COMMAND.search(value) and tags & COMMAND_TAGS:
        return "cmdi", "cve_command_execution"
    # These structures are sufficiently explicit to stand alone.  Contextual
    # primitives (SSTI braces, traversal, upload and CRLF) need tag agreement.
    for attack_type, subtype in matches:
        if attack_type in {"sqli", "xss", "xxe", "deser", "nosql", "ldap", "ssrf"}:
            return attack_type, subtype
    return None


def cve_id_of(document: dict, path: Path) -> str:
    info = document.get("info") or {}
    classification = classification_of(info if isinstance(info, dict) else {})
    value = classification.get("cve-id") or document.get("id") or path.stem
    if isinstance(value, list):
        value = value[0] if value else path.stem
    match = re.search(r"CVE-\d{4}-\d{4,}", str(value), re.I)
    return match.group(0).upper() if match else path.stem.upper()


def load_kev(payload: bytes) -> tuple[dict[str, dict], dict]:
    document = json.loads(payload)
    entries = {}
    for item in document.get("vulnerabilities", []):
        if isinstance(item, dict) and item.get("cveID"):
            entries[str(item["cveID"]).upper()] = item
    metadata = {
        "catalog_version": document.get("catalogVersion"),
        "date_released": document.get("dateReleased"),
        "count": document.get("count", len(entries)),
        "sha256": sha256_bytes(payload),
    }
    return entries, metadata


def normalized_raw_request(value: str) -> str:
    """Canonicalize an offline-rendered template request without executing it."""
    from urllib.parse import urlsplit

    text = value.replace("\r\n", "\n").strip()
    head, separator, body = text.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return ""
    match = re.match(r"^([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?$", lines[0], re.I)
    if match:
        method, target = match.groups()
        parsed = urlsplit(target)
        if parsed.scheme and parsed.netloc:
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
        lines[0] = f"{method.upper()} {target} HTTP/1.1"
    if not any(line.lower().startswith("host:") for line in lines[1:]):
        lines.insert(1, "Host: target.example.test")
    return "\r\n".join(lines) + "\r\n\r\n" + (body if separator else "")


def build(templates: Path, kev: dict[str, dict], years: set[int], min_severity: str,
          max_per_cve: int, max_requests_per_cve: int, max_records: int,
          source: dict) -> tuple[list[dict], dict]:
    yaml_parser = require_yaml()
    records: list[dict] = []
    stats = Counter()
    field_by_cve: Counter[str] = Counter()
    request_by_cve: Counter[str] = Counter()
    seen_fields: set[str] = set()
    seen_requests: set[str] = set()
    emitted_cves: set[str] = set()
    cve_root = templates / "http" / "cves"
    files = [path for year in sorted(years) for path in (cve_root / str(year)).glob("*.yaml")]
    for path in sorted(files):
        stats["templates_seen"] += 1
        try:
            document = yaml_parser.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml_parser.YAMLError):
            stats["templates_invalid"] += 1
            continue
        if not isinstance(document, dict):
            stats["templates_invalid"] += 1
            continue
        info = document.get("info") or {}
        if not isinstance(info, dict):
            continue
        severity = str(info.get("severity", "unknown")).lower()
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER[min_severity]:
            stats["templates_below_severity"] += 1
            continue
        cve_id = cve_id_of(document, path)
        tags = tags_of(info)
        classification = classification_of(info)
        http = document.get("http") or []
        http = http if isinstance(http, list) else [http]
        emitted_before = len(records)
        for request_index, request in enumerate(http):
            if not isinstance(request, dict):
                continue
            for request_text in raw_requests(request):
                classified_fields = []
                for name, value, location in parse_fields(request_text):
                    result = classify(value, tags, location)
                    if result:
                        classified_fields.append((name, value, location, *result))
                if not classified_fields:
                    continue

                # Preserve one complete offline-rendered request whenever at
                # least one contained field has an explicit attack primitive.
                # This is request-level evidence and is never eligible for the
                # context-free payload model.
                normalized_request = normalized_raw_request(request_text)
                request_content = hashlib.sha256(
                    ("request\0" + canonical_payload(normalized_request)).encode()
                ).hexdigest()
                if (
                    normalized_request
                    and request_content not in seen_requests
                    and request_by_cve[cve_id] < max_requests_per_cve
                    and len(records) < max_records
                ):
                    primary_name, primary_value, primary_location, attack_type, subtype = classified_fields[0]
                    kev_item = kev.get(cve_id, {})
                    request_fingerprint = hashlib.sha256(normalized_request.encode()).hexdigest()
                    request_number = request_by_cve[cve_id] + 1
                    records.append({
                        "id": f"modernreq_{cve_id.lower()}_{request_number:03d}",
                        "raw_request": normalized_request,
                        # Retained for schema compatibility and quick inspection;
                        # raw_request determines this record's data level.
                        "payload": primary_value, "label": 1,
                        "attack_type": attack_type, "attack_subtype": f"{subtype}_full_request",
                        "param_location": "request", "param_name": primary_name,
                        "attack_primitives": [
                            {
                                "name": name, "location": location,
                                "attack_type": kind, "attack_subtype": child_subtype,
                                "payload_sha256": hashlib.sha256(value.encode()).hexdigest(),
                            }
                            for name, value, location, kind, child_subtype in classified_fields
                        ],
                        "source": "ProjectDiscovery-Nuclei-Templates",
                        "source_url": f"https://github.com/projectdiscovery/nuclei-templates/blob/{source['version']}/{path.relative_to(templates).as_posix()}",
                        "source_path": path.relative_to(templates).as_posix(),
                        "source_version": source["version"],
                        "source_archive_sha256": source["archive_sha256"],
                        "payload_sha256": hashlib.sha256(primary_value.encode()).hexdigest(),
                        "request_sha256": request_fingerprint,
                        "content_group_id": f"modern-request-content:{request_content}",
                        "cve_id": cve_id,
                        "cwe_ids": classification.get("cwe-id", []),
                        "cvss_score": classification.get("cvss-score"),
                        "severity": severity,
                        "template_name": str(info.get("name", "")),
                        "template_tags": sorted(tags),
                        "known_exploited": bool(kev_item),
                        "kev_date_added": kev_item.get("dateAdded"),
                        "kev_vendor": kev_item.get("vendorProject"),
                        "kev_product": kev_item.get("product"),
                        "label_confidence": "high",
                        "label_basis": "offline-rendered public active-detection request containing an explicit attack primitive",
                        "group_id": f"modern-cve:{cve_id}",
                        "split": split_for(cve_id),
                        "request_index": request_index,
                        "detection_scope": "complete_http_request",
                        "exclude_from_payload_model": True,
                        "execution_safe": True,
                    })
                    seen_requests.add(request_content)
                    request_by_cve[cve_id] += 1
                    emitted_cves.add(cve_id)
                    stats["request_records"] += 1

                for name, value, location, attack_type, subtype in classified_fields:
                    fingerprint = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
                    content_group = hashlib.sha256(canonical_payload(value).encode()).hexdigest()
                    if content_group in seen_fields:
                        stats["records_global_content_duplicate"] += 1
                        continue
                    if field_by_cve[cve_id] >= max_per_cve or len(records) >= max_records:
                        continue
                    seen_fields.add(content_group)
                    kev_item = kev.get(cve_id, {})
                    item = {
                        "id": f"modern_{cve_id.lower()}_{field_by_cve[cve_id] + 1:03d}",
                        "payload": value, "label": 1,
                        "attack_type": attack_type, "attack_subtype": subtype,
                        "param_location": location, "param_name": name,
                        "source": "ProjectDiscovery-Nuclei-Templates",
                        "source_url": f"https://github.com/projectdiscovery/nuclei-templates/blob/{source['version']}/{path.relative_to(templates).as_posix()}",
                        "source_path": path.relative_to(templates).as_posix(),
                        "source_version": source["version"],
                        "source_archive_sha256": source["archive_sha256"],
                        "payload_sha256": fingerprint,
                        "content_group_id": f"modern-content:{content_group}",
                        "cve_id": cve_id,
                        "cwe_ids": classification.get("cwe-id", []),
                        "cvss_score": classification.get("cvss-score"),
                        "severity": severity,
                        "template_name": str(info.get("name", "")),
                        "template_tags": sorted(tags),
                        "known_exploited": bool(kev_item),
                        "kev_date_added": kev_item.get("dateAdded"),
                        "kev_vendor": kev_item.get("vendorProject"),
                        "kev_product": kev_item.get("product"),
                        "label_confidence": "high",
                        "label_basis": "public active-detection template plus explicit request-field attack primitive",
                        "group_id": f"modern-cve:{cve_id}",
                        "split": split_for(cve_id),
                        "request_index": request_index,
                    }
                    records.append(item)
                    field_by_cve[cve_id] += 1
                    emitted_cves.add(cve_id)
                    stats["field_records"] += 1
                    if len(records) >= max_records:
                        break
                if len(records) >= max_records:
                    break
            if len(records) >= max_records:
                break
        if len(records) == emitted_before:
            stats["templates_context_only_or_no_signal"] += 1
        else:
            stats["templates_emitted"] += 1
        if len(records) >= max_records:
            stats["max_records_reached"] = 1
            break
    stats["records"] = len(records)
    stats["cves"] = len(emitted_cves)
    all_by_cve = {
        cve: field_by_cve[cve] + request_by_cve[cve]
        for cve in sorted(emitted_cves)
    }
    return records, {
        **dict(stats),
        "records_by_cve": all_by_cve,
        "field_records_by_cve": dict(sorted(field_by_cve.items())),
        "request_records_by_cve": dict(sorted(request_by_cve.items())),
    }


def write_output(output: Path, records: list[dict], stats: dict, sources: dict,
                 years: set[int], min_severity: str) -> dict:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    split_counts = {}
    artifacts = {}
    for split in ("train", "validation", "test"):
        values = [item for item in records if item["split"] == split]
        artifact = output / f"dataset_modern_attack_{split}.json"
        artifact.write_text(
            json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        split_counts[split] = len(values)
        artifacts[artifact.name] = sha256_bytes(artifact.read_bytes())
    manifest = {
        "dataset": "Recent-CVE-HTTP-Fields-and-Requests-v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "authorized defensive Web attack detection",
        "format": "JSON array / UTF-8",
        "years": sorted(years), "minimum_severity": min_severity,
        "total_records": len(records), "splits": split_counts,
        "artifacts": artifacts,
        "attack_type_counts": dict(sorted(Counter(item["attack_type"] for item in records).items())),
        "data_level_counts": dict(sorted(Counter(
            "request" if item.get("raw_request") else "field" for item in records
        ).items())),
        "known_exploited_records": sum(bool(item["known_exploited"]) for item in records),
        "sources": sources, "filter_audit": stats,
        "leakage_control": "all fields and complete requests sharing a CVE ID use one deterministic split; field and request contents are globally deduplicated within their data level",
        "safety": "templates were parsed offline; no template was executed and no target request was sent",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build recent-CVE defensive request-field dataset")
    parser.add_argument("--templates-dir", type=Path, help="existing nuclei-templates checkout (offline mode)")
    parser.add_argument("--kev-file", type=Path, help="existing CISA KEV JSON (offline mode)")
    parser.add_argument("--refresh", action="store_true", help="resolve the current latest Nuclei release and update source lock")
    parser.add_argument("--years", nargs="+", type=int, default=[date.today().year - 2, date.today().year - 1, date.today().year])
    parser.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="medium")
    parser.add_argument("--max-per-cve", type=int, default=12)
    parser.add_argument("--max-requests-per-cve", type=int, default=6)
    parser.add_argument("--max-records", type=int, default=4000)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.max_per_cve < 1 or args.max_records < 1:
        raise SystemExit("--max-per-cve and --max-records must be positive")
    if args.refresh and (args.templates_dir or args.kev_file):
        raise SystemExit("--refresh cannot be combined with offline source arguments")
    lock = load_lock()
    release = latest_release() if args.refresh or not lock.get("nuclei_templates") else dict(lock["nuclei_templates"])
    if args.templates_dir:
        templates = args.templates_dir.resolve()
        archive_sha = "offline-directory"
        archive_url = release.get("archive_url", "offline-directory")
        temporary = None
    else:
        archive_url = str(release["archive_url"])
        archive = fetch(archive_url)
        archive_sha = sha256_bytes(archive)
        expected = release.get("archive_sha256")
        if expected and expected != archive_sha:
            raise SystemExit(f"source archive hash mismatch: expected {expected}, got {archive_sha}")
        temporary = tempfile.TemporaryDirectory(prefix="ai-waf-nuclei-")
        templates = safe_extract(archive, Path(temporary.name))

    if args.kev_file:
        kev_payload = args.kev_file.read_bytes()
    elif args.refresh or not KEV_SNAPSHOT.is_file():
        kev_payload = fetch(KEV_URL)
        if args.refresh:
            KEV_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
            KEV_SNAPSHOT.write_bytes(kev_payload)
    else:
        kev_payload = KEV_SNAPSHOT.read_bytes()
        expected_kev = (lock.get("cisa_kev") or {}).get("sha256")
        if expected_kev and sha256_bytes(kev_payload) != expected_kev:
            raise SystemExit("CISA KEV snapshot hash does not match sources.lock.json")
    kev, kev_meta = load_kev(kev_payload)
    source = {
        "version": str(release.get("version", "offline")),
        "published_at": release.get("published_at"),
        "archive_url": archive_url,
        "archive_sha256": archive_sha,
        "license": "MIT",
    }
    records, stats = build(
        templates, kev, set(args.years), args.min_severity,
        args.max_per_cve, args.max_requests_per_cve, args.max_records, source,
    )
    sources = {"nuclei_templates": source, "cisa_kev": {"url": KEV_URL, **kev_meta}}
    manifest = write_output(args.output, records, stats, sources, set(args.years), args.min_severity)
    if args.refresh:
        LOCK_FILE.write_text(json.dumps(sources, ensure_ascii=False, indent=2), encoding="utf-8")
    if temporary is not None:
        temporary.cleanup()
    print(json.dumps({"output": str(args.output), "records": len(records), "cves": stats["cves"], "splits": manifest["splits"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
