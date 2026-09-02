#!/usr/bin/env python3
"""Generate leakage-resistant contrastive field data for the payload model.

The generator is deliberately offline and inert: strings are written to JSON,
never sent to a target or evaluated.  Every semantic group contains attack
encodings and a benign near-neighbour, and the whole group is assigned to one
split.  This makes the generated count a useful measure of diversity instead
of allowing encoded copies to leak across train/validation/test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "data" / "enriched_traffic" / "generated"
SEED = 20260724
SOURCE = "Synthetic-Contrastive-WAF-Fields-v1"
SPLITS = ("train", "validation", "test")


# Each family has multiple semantic primitives.  ``n`` is retained in both the
# attack and control record so a model cannot use the synthetic identifier as a
# shortcut for the label.
ATTACK_TEMPLATES: dict[str, tuple[str, ...]] = {
    "sqli": (
        "' OR {v}={v}--", "' UNION ALL SELECT username,password FROM users_{n}--",
        "1 AND SLEEP({d})", "1'; SELECT SLEEP({d})--",
        "' AND extractvalue(1,concat(0x7e,user()))--", "1 INTO OUTFILE '/tmp/inert_{n}'",
    ),
    "xss": (
        "<svg onload=alert({v})>", "<img src=x onerror=alert({v})>",
        "<script>document.cookie</script>", "javascript:alert({v})",
        "<details open ontoggle=alert({v})>", "data:text/html,<script>alert({v})</script>",
    ),
    "cmdi": (
        "; id", "| whoami", "&& uname -a", "$(cat /etc/hostname)",
        "`id`", "x; curl http://127.0.0.1/inert_{n}",
    ),
    "ssti": (
        "{{{v}*{v}}}", "${{{v}*{v}}}", "<%= {v}*{v} %>",
        "#{{{v}*{v}}}", "{{{{ ''.__class__ }}}}",
        "${{T(java.lang.Class).forName('java.lang.String')}}",
    ),
    "ptrav": (
        "../../etc/passwd", "..\\..\\Windows\\System32\\config\\SAM",
        "....//....//etc/shadow", "%2e%2e/%2e%2e/etc/passwd",
        "..%252f..%252fetc%252fpasswd", "/var/www/app/../../../etc/passwd",
    ),
    "lfi": (
        "php://filter/convert.base64-encode/resource=index.php", "file:///etc/passwd",
        "data://text/plain,inert_{n}", "../../proc/self/environ",
        "expect://id", "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    ),
    "xxe": (
        '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        '<!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1/inert_{n}">]><x>&e;</x>',
        '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/>',
        '<!DOCTYPE x [<!ENTITY % p SYSTEM "file:///tmp/inert_{n}">%p;]><x/>',
    ),
    "ssrf": (
        "http://127.0.0.1:{port}/admin", "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/", "gopher://127.0.0.1:{port}/_inert",
        "file:///etc/hosts", "http://[::1]:{port}/internal/{n}",
    ),
    "nosql": (
        '{"username":{"$ne":null}}', '{"age":{"$gt":{v}}}',
        '{"name":{"$regex":".*"}}', '{"$where":"return true"}',
        "user[$nin][]=guest", "filter[$gte]={v}",
    ),
    "ldap": (
        "*)(uid=*))(|(uid=*", "(|(uid=user_{n})(uid=admin))", "(&(cn=*)(|(uid=*)))",
        "*)(objectClass=*)", "(!(|(uid=guest)(uid=user_{n})))", "admin)(|(password=*))",
    ),
    "xpath": (
        "' or '1'='1", '" or "1"="1', "' and count(//user)>0 and '1'='1",
        "//user[position()={v}]", "//*[local-name()='user']", "//account[role='admin']",
    ),
    "crlf": (
        "ok%0d%0aX-Inert-{n}: injected", "next%0aSet-Cookie: inert={v}",
        "value\\r\\nX-Trace: forged-{n}", "page%250d%250aLocation:%20/inert_{n}",
    ),
    "codei": (
        "eval('inert_{n}')", "system('id')", "__import__('os').system('id')",
        "Runtime.getRuntime().exec('id')", "new ProcessBuilder('id').start()",
        "<?php echo 'inert_{n}'; ?>",
    ),
    "logi": (
        "ok%0aWARN forged_event_{n}=true", "user\\r\\nrole=admin_{n}",
        "${{jndi:ldap://127.0.0.1/inert_{n}}}", "value%0d%0aX-Log-Level: debug_{n}",
    ),
    "fmtst": (
        "%08x.%08x.%08x", "%p-%p-%p-%p", "AAAA%{v}$n", "%s%s%s%s%n",
        "%1$x.%2$x.%3$x", "inert_{n}-%n",
    ),
    "fupl": (
        "avatar_{n}.php", "image_{n}.phtml", "shell_{n}.aspx.", "module_{n}.jspx",
        "archive_{n}.war", "Content-Type: application/x-php\r\n\r\n<?php echo 'inert'; ?>",
    ),
    "deser": (
        "rO0ABXNyAAlJbmVydF8{n}", 'O:8:"InertObj":1:{s:2:"id";i:{v};}',
        "aced00057372000b496e6572744f626a{n}", "gASVCwAAAAAAAACMB2luZXJ0Xz{n}",
        "!!python/object:inert.Type {{value: {v}}}", '{"@type":"inert.ProcessBuilder","id":{v}}',
    ),
    "api_proto": (
        '{"__proto__":{"isAdmin":true,"marker":{v}}}',
        '{"constructor":{"prototype":{"role":"admin_{n}"}}}',
        "__proto__[polluted]=inert_{n}", "constructor[prototype][flag]=inert_{n}",
    ),
    "jwt": (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyX3tu fSJ9.",
        '{"alg":"none","typ":"JWT","marker":{v}}',
        '{"kid":"../../etc/passwd","marker":{v}}',
        '{"jku":"https://attacker.invalid/jwks_{n}.json"}',
        "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    ),
    "ssi": (
        '<!--#exec cmd="id" -->', '<!--#include virtual="/inert_{n}" -->',
        '<!--#echo var="DOCUMENT_NAME" -->', '<!--#set var="marker" value="{n}" -->',
    ),
    "hpp": (
        "?role=user&role=admin_{n}", "?id={v}&id={v2}", "?safe=1%26is_admin%3dtrue",
        "?user=guest;admin=true", "?mode=view&mode=delete_{n}",
    ),
    "hsmug": (
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /inert_{n} HTTP/1.1",
        "Transfer-Encoding: xchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nPOST /inert_{n}",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nGET /inert_{n}",
    ),
}


NORMAL_TEMPLATES: dict[str, tuple[str, ...]] = {
    "sqli": ("SQL review {n}: bind SELECT parameters", "order status is ready for item {v}"),
    "xss": ("HTML tutorial {n}: use &lt;script&gt; only in a sandbox", "SVG icon asset-{n}.svg"),
    "cmdi": ("runbook {n}: the id command requires operator approval", "shell documentation section {v}"),
    "ssti": ("template guide {n}: variables use escaped delimiters", "invoice expression example {v}"),
    "ptrav": ("backup path /srv/archive/{n}/report.txt", "Windows\\System32 compatibility note {n}"),
    "lfi": ("PHP stream documentation chapter {n}", "local file picker item_{n}.txt"),
    "xxe": ("XML security guide {n}: external entities are disabled", "<!DOCTYPE note><note>safe-{n}</note>"),
    "ssrf": ("https://docs.example.test/network/{n}", "metadata service security note {n}"),
    "nosql": ("MongoDB $ne operator documentation example {n}", '{"filter":"price greater than {v}"}'),
    "ldap": ("LDAP filter documentation section {n}", "directory search user_{n}"),
    "xpath": ("XPath count() tutorial section {n}", "XML node position {v}"),
    "crlf": ("HTTP CRLF prevention checklist {n}", "line one and line two note {n}"),
    "codei": ("Python eval safety review {n}", "code sample identifier inert_{n}"),
    "logi": ("log forging prevention note {n}", "WARN is a documented severity {n}"),
    "fmtst": ("printf format guide: %s and %08x example {n}", "percent complete: {v}%"),
    "fupl": ("avatar_{n}.png", "upload policy blocks executable extension example {n}"),
    "deser": ("serialization migration note {n}", '{"type":"invoice","id":{v}}'),
    "api_proto": ("JavaScript prototype guide {n}", '{"profile":{"nickname":"user_{n}"}}'),
    "jwt": ("JWT algorithm migration guide {n}", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.synthetic{n}"),
    "ssi": ("SSI hardening guide {n}: exec directives are disabled", "include documentation {n}"),
    "hpp": ("parameter policy {n}: duplicate keys are rejected", "?page={v}&size=20"),
    "hsmug": ("HTTP framing guide {n}: reject conflicting length headers", "Content-Length: {v}"),
}


LOCATION = {
    "ptrav": "path", "lfi": "path", "fupl": "filename", "jwt": "cookie",
    "xxe": "body", "codei": "body", "deser": "body", "api_proto": "body",
    "hsmug": "header", "crlf": "header", "logi": "body", "ssi": "body",
}


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def split_groups(attack_type: str, groups: int) -> dict[int, str]:
    """Stratified deterministic 75/12.5/12.5 assignment inside each family."""
    ranked = sorted(
        range(groups),
        key=lambda index: digest_text(f"{SEED}:{attack_type}:{index}"),
    )
    train_end = int(groups * 0.75)
    validation_end = train_end + (groups - train_end) // 2
    result = {}
    for position, index in enumerate(ranked):
        result[index] = (
            "train" if position < train_end
            else "validation" if position < validation_end
            else "test"
        )
    return result


def format_template(template: str, index: int) -> str:
    # Remove the deliberate space in a JWT template after formatting.  Keeping
    # it in source avoids an opaque, accidental-looking credential-like token.
    values = {
        "{n}": f"{index:03d}",
        "{v}": str(index % 9 + 1),
        "{v2}": str((index * 7) % 97 + 10),
        "{d}": str(index % 5 + 1),
        "{port}": str(8000 + index % 100),
    }
    result = template
    # Replace longer names first (``{v2}`` before ``{v}``).  Unlike str.format,
    # this leaves JSON/XML/template-language braces untouched.
    for marker in ("{port}", "{v2}", "{n}", "{v}", "{d}"):
        result = result.replace(marker, values[marker])
    return result.replace("X3tu fS", f"X3{index:03d}")


def encoded_variants(payload: str) -> tuple[tuple[str, str], ...]:
    candidates = (
        ("raw", payload),
        ("url", quote(payload, safe="")),
        ("double_url", quote(quote(payload, safe=""), safe="")),
    )
    result = []
    seen = set()
    for name, value in candidates:
        if value not in seen:
            result.append((name, value))
            seen.add(value)
    return tuple(result)


def attach_shared_marker(attack_type: str, payload: str, marker: str) -> str:
    """Make each group content-unique while retaining a realistic field shape.

    The same marker is present in the paired normal record, so it cannot become
    a label shortcut.  Syntax-aware placement also avoids creating duplicates
    that could otherwise appear in different splits when a template has no
    variable operand.
    """
    if attack_type == "sqli":
        return f"{payload} /*{marker}*/"
    if attack_type in {"xss", "xxe", "ssi"}:
        return f"{payload}<!--{marker}-->"
    if attack_type == "cmdi":
        return f"{payload} # {marker}"
    if attack_type in {"ptrav", "lfi"}:
        return f"{payload.rstrip('/')}?trace={marker}"
    if attack_type == "ssrf":
        return f"{payload}#{marker}"
    if attack_type in {"nosql", "deser", "api_proto", "jwt"} and payload.startswith("{"):
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(value, dict):
                value["waf_group"] = marker
                return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if attack_type == "ldap":
        return f"(&({marker}=1){payload})"
    if attack_type == "xpath":
        return f"({payload}) and '{marker}'='{marker}'"
    if attack_type in {"crlf", "logi"}:
        return f"{payload}%0aX-WAF-Group: {marker}"
    if attack_type == "codei":
        return f"{payload} /*{marker}*/"
    if attack_type == "fupl":
        return f"{payload}.{marker}"
    if attack_type == "hpp":
        return f"{payload}&waf_group={marker}"
    if attack_type == "hsmug":
        return f"X-WAF-Group: {marker}\r\n{payload}"
    return f"{payload} {marker}"


def build_records(groups_per_family: int) -> list[dict]:
    records: list[dict] = []
    for attack_type in sorted(ATTACK_TEMPLATES):
        split_map = split_groups(attack_type, groups_per_family)
        attack_templates = ATTACK_TEMPLATES[attack_type]
        normal_templates = NORMAL_TEMPLATES[attack_type]
        location = LOCATION.get(attack_type, "query")
        for index in range(groups_per_family):
            group_id = f"contrastive:{attack_type}:{index:03d}"
            split = split_map[index]
            marker = f"waf_group_{index:03d}"
            attack = attach_shared_marker(
                attack_type,
                format_template(attack_templates[index % len(attack_templates)], index),
                marker,
            )
            normal = (
                format_template(normal_templates[index % len(normal_templates)], index)
                + f" [{marker}]"
            )
            for variant, payload in encoded_variants(attack):
                records.append({
                    "id": f"contrast_{attack_type}_{index:03d}_attack_{variant}",
                    "payload": payload,
                    "decoded_payload": attack,
                    "label": 1,
                    "attack_type": attack_type,
                    "attack_subtype": f"contrastive_{attack_type}",
                    "param_location": location,
                    "param_name": "request_value",
                    "source": SOURCE,
                    "group_id": group_id,
                    "content_group_id": f"contrast-content:{digest_text(payload)}",
                    "split": split,
                    "pair_role": "attack",
                    "variant": variant,
                    "label_confidence": "high",
                    "label_basis": "explicit inert attack primitive paired with a benign near-neighbour",
                    "execution_safe": True,
                })
            records.append({
                "id": f"contrast_{attack_type}_{index:03d}_normal",
                "payload": normal,
                "decoded_payload": normal,
                "label": 0,
                "attack_type": "normal",
                "attack_subtype": f"hard_negative_{attack_type}",
                "param_location": "body" if location in {"header", "filename"} else location,
                "param_name": "documentation_or_business_value",
                "source": SOURCE,
                "group_id": group_id,
                "content_group_id": f"contrast-content:{digest_text(normal)}",
                "split": split,
                "pair_role": "normal_control",
                "paired_attack_type": attack_type,
                "hard_negative": True,
                "label_confidence": "high",
                "label_basis": "benign documentation or business value paired by synthetic marker",
                "execution_safe": True,
            })
    return records


def write_json(path: Path, values: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_quality_report(records: list[dict], groups_per_family: int) -> dict:
    ids = [str(item["id"]) for item in records]
    contents = [str(item["content_group_id"]) for item in records]
    group_splits: dict[str, set[str]] = defaultdict(set)
    content_splits: dict[str, set[str]] = defaultdict(set)
    group_labels: dict[str, set[int]] = defaultdict(set)
    family_split_groups: dict[str, dict[str, set[str]]] = {
        family: {split: set() for split in SPLITS} for family in ATTACK_TEMPLATES
    }
    variant_counts = Counter()
    for item in records:
        group = str(item["group_id"])
        split = str(item["split"])
        family = str(item.get("paired_attack_type") or item["attack_type"])
        group_splits[group].add(split)
        content_splits[str(item["content_group_id"])].add(split)
        group_labels[group].add(int(item["label"]))
        family_split_groups[family][split].add(group)
        variant_counts[str(item.get("variant", "normal_control"))] += 1

    expected_group_counts = {
        "train": int(groups_per_family * 0.75),
        "validation": (groups_per_family - int(groups_per_family * 0.75)) // 2,
    }
    expected_group_counts["test"] = (
        groups_per_family - expected_group_counts["train"] - expected_group_counts["validation"]
    )
    family_group_counts = {
        family: {split: len(values) for split, values in split_groups.items()}
        for family, split_groups in sorted(family_split_groups.items())
    }

    checks = {
        "unique_ids": len(ids) == len(set(ids)),
        "unique_content_fingerprints": len(contents) == len(set(contents)),
        "groups_stay_in_one_split": all(len(values) == 1 for values in group_splits.values()),
        "contents_stay_in_one_split": all(len(values) == 1 for values in content_splits.values()),
        "every_group_has_attack_and_normal": all(values == {0, 1} for values in group_labels.values()),
        "every_family_has_expected_split_groups": all(
            counts == expected_group_counts for counts in family_group_counts.values()
        ),
        "all_records_are_inert": all(item.get("execution_safe") is True for item in records),
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "records": len(records),
        "unique_ids": len(set(ids)),
        "unique_content_fingerprints": len(set(contents)),
        "contrastive_groups": len(group_splits),
        "cross_split_group_duplicates": sum(len(values) > 1 for values in group_splits.values()),
        "cross_split_content_duplicates": sum(len(values) > 1 for values in content_splits.values()),
        "groups_missing_paired_label": sum(values != {0, 1} for values in group_labels.values()),
        "expected_family_split_group_counts": expected_group_counts,
        "family_split_group_counts": family_group_counts,
        "base_template_counts": {
            family: {
                "attack": len(ATTACK_TEMPLATES[family]),
                "normal": len(NORMAL_TEMPLATES[family]),
            }
            for family in sorted(ATTACK_TEMPLATES)
        },
        "variant_counts": dict(sorted(variant_counts.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate contrastive AI-WAF field data")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--groups-per-family", type=int, default=32)
    args = parser.parse_args()
    if args.groups_per_family < 16:
        raise SystemExit("--groups-per-family must be at least 16 for useful stratified splits")

    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    records = build_records(args.groups_per_family)
    quality = build_quality_report(records, args.groups_per_family)
    if quality["status"] != "PASS":
        raise RuntimeError("generated dataset failed quality checks: " + json.dumps(quality["checks"]))
    split_counts = Counter()
    label_counts = Counter()
    family_counts: dict[str, Counter] = defaultdict(Counter)
    artifacts = {}
    for split in SPLITS:
        values = [item for item in records if item["split"] == split]
        path = output / f"dataset_enriched_{split}.json"
        write_json(path, values)
        split_counts[split] = len(values)
        for item in values:
            label_counts[str(item["label"])] += 1
            family = item["attack_type"] if item["label"] else item["paired_attack_type"]
            family_counts[family]["attack" if item["label"] else "normal"] += 1

    quality_path = output / "quality_report.json"
    write_json(quality_path, quality)
    for path in sorted(output.glob("dataset_enriched_*.json")) + [quality_path]:
        artifacts[path.name] = sha256_file(path)

    unique_contents = {item["content_group_id"] for item in records}
    groups = {item["group_id"] for item in records}
    manifest = {
        "dataset": SOURCE,
        "seed": SEED,
        "format": "JSON array / UTF-8",
        "total_records": len(records),
        "contrastive_groups": len(groups),
        "groups_per_family": args.groups_per_family,
        "attack_families": len(ATTACK_TEMPLATES),
        "label_counts": dict(sorted(label_counts.items())),
        "splits": dict(split_counts),
        "family_counts": {key: dict(value) for key, value in sorted(family_counts.items())},
        "unique_content_fingerprints": len(unique_contents),
        "group_policy": "attack encodings and their benign control always share one split",
        "safety": "offline inert string generation only; no payload is executed or sent",
        "artifacts": artifacts,
    }
    write_json(output / "manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
