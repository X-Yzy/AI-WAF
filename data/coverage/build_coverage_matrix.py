#!/usr/bin/env python3
"""Build the explicit data/runtime vulnerability coverage matrix."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(__file__).resolve().parent / "coverage_matrix.json"


def item(family: str, category: str, data_status: str, runtime_status: str,
         layer: str, standards: list[str], note: str) -> dict:
    return {
        "family": family, "category": category,
        "data_status": data_status, "runtime_status": runtime_status,
        "detection_layer": layer, "standards": standards, "note": note,
    }


ENTRIES = [
    item("SQL injection", "injection", "covered", "covered", "field rules + ML", ["CWE-89", "OWASP A03"], "traditional, obfuscated, API variable and recent-CVE samples"),
    item("Cross-site scripting", "injection", "covered", "covered", "field rules + ML", ["CWE-79", "OWASP A03"], "reflected input patterns; DOM-only sinks still need response/client analysis"),
    item("OS command injection / Shellshock", "injection", "covered", "covered", "field rules + ML", ["CWE-78", "CWE-77"], "includes shell operators, Shellshock and recent CVEs"),
    item("Code and expression injection", "injection", "covered", "covered", "field rules + ML", ["CWE-94", "CWE-917"], "SpEL, OGNL, MVEL, Java Runtime and ProcessBuilder"),
    item("Server-side template injection", "injection", "covered", "covered", "field rules + ML", ["CWE-1336"], "Jinja-like, FreeMarker and Velocity forms"),
    item("NoSQL injection", "injection", "covered", "covered", "field rules + ML", ["CWE-943", "API8:2023"], "Mongo-style operators and API JSON"),
    item("LDAP injection", "injection", "covered", "covered", "field rules + ML", ["CWE-90"], "filter escaping and recent CVEs"),
    item("XPath injection", "injection", "covered", "covered", "field rules + ML", ["CWE-643"], "boolean and count expressions"),
    item("XXE / XInclude", "injection", "covered", "covered", "field rules + ML", ["CWE-611"], "DOCTYPE, external entities and XInclude"),
    item("SSI injection", "injection", "covered", "covered", "field rules + ML", ["CWE-97"], "exec/include directives"),
    item("CRLF, response splitting and log forging", "injection", "covered", "covered", "field rules + ML", ["CWE-93", "CWE-117"], "encoded newlines require injected visible content"),
    item("JNDI lookup injection", "injection", "covered", "covered", "field rules + ML", ["CWE-917"], "JNDI lookup syntax including Log4Shell-style fields"),
    item("Prototype pollution", "api_input", "covered", "covered_after_retrain", "field ML", ["CWE-1321"], "__proto__ and constructor.prototype with hard negatives"),
    item("Unsafe deserialization", "api_input", "covered", "covered_after_retrain", "field ML", ["CWE-502", "OWASP A08"], "Java, PHP, .NET, Python, YAML, Node, Ruby, Hessian and Kryo"),
    item("Path traversal / LFI / archive Zip Slip", "file_path", "covered", "covered", "field rules + ML", ["CWE-22", "CWE-23"], "encoded traversal, wrappers and archive member names"),
    item("Malicious file upload / polyglot metadata", "file_path", "covered", "partial", "field rules + ML", ["CWE-434"], "extensions, .htaccess and SVG; binary malware scanning is separate"),
    item("SSRF", "server_side_request", "covered", "covered", "field rules + ML", ["CWE-918", "OWASP A10", "API7:2023"], "metadata, loopback, IPv6 and non-HTTP schemes"),
    item("Open redirect", "server_side_request", "covered_context", "not_enforced", "application policy", ["CWE-601"], "requires per-application redirect allowlist"),
    item("HTTP parameter pollution", "http_protocol", "covered", "covered", "field rules + ML", ["CWE-235"], "duplicate and encoded parameters"),
    item("HTTP/1 request smuggling CL.TE / TE.CL", "http_protocol", "covered", "partial", "edge parser + field model", ["CWE-444"], "proxy rejects ambiguous lengths/chunked direct input; upstream differential testing still required"),
    item("HTTP/2 request smuggling / pseudo-header ambiguity", "http_protocol", "covered_sequence", "gateway_required", "HTTP/2 gateway", ["CWE-444"], "paired structured frame sequences exist; current Python proxy terminates HTTP/1.1 only"),
    item("HTTP/2 Rapid Reset / protocol DoS", "http_protocol", "covered_sequence", "gateway_required", "load balancer", ["CVE-2023-44487"], "rapid open/reset and benign cancellation sequences exist; mitigation still belongs at an HTTP/2-capable edge"),
    item("HTTP content-type / parser differential", "http_protocol", "covered_context", "not_enforced", "edge/application parser contract", ["CWE-444", "CWE-436"], "label depends on whether edge and application parse the same bytes differently"),
    item("JWT implementation attacks", "authentication", "covered", "covered", "field rules + ML", ["CWE-347", "API2:2023"], "alg none, kid traversal and key URL patterns; signature validation remains in the app"),
    item("Credential stuffing and MFA/OTP guessing", "authentication", "covered_context", "not_enforced", "identity rate/graph layer", ["CWE-307", "API2:2023"], "requires account, challenge, source and time aggregation"),
    item("CSRF", "authentication", "covered_context", "not_enforced", "application/session policy", ["CWE-352"], "requires cookie auth, Origin/SameSite and token validation context"),
    item("OAuth/OIDC redirect and flow abuse", "authentication", "covered_context", "not_enforced", "identity policy", ["CWE-601", "API2:2023"], "exact registered redirect, issuer, state, nonce and PKCE checks"),
    item("SAML assertion/signature wrapping", "authentication", "covered_context", "not_enforced", "identity XML signature policy", ["CWE-347"], "the application must consume the exact uniquely signed assertion after schema validation"),
    item("Webhook signature validation and replay", "authentication", "covered_context", "not_enforced", "signature + freshness + idempotency", ["CWE-345", "CWE-294"], "requires provider-specific canonicalization, timestamp freshness and event-id state"),
    item("Session fixation", "authentication", "covered_context", "not_enforced", "application session lifecycle", ["CWE-384"], "requires comparing session identity before and after authentication"),
    item("BOLA / IDOR", "authorization", "covered_context", "not_enforced", "application authorization", ["API1:2023", "CWE-639"], "same request can be legal for support and illegal for an ordinary user"),
    item("Broken function-level authorization", "authorization", "covered_context", "not_enforced", "application authorization", ["API5:2023", "CWE-862"], "role and effective route required"),
    item("Mass assignment / property and JSON Patch authorization", "authorization", "covered_context", "not_enforced", "schema + authorization", ["API3:2023", "CWE-915"], "server-managed fields and JSON Pointer paths require caller-aware allowlists"),
    item("HTTP method override authorization bypass", "authorization", "covered_context", "not_enforced", "effective-method policy", ["CWE-650"], "must authorize the effective method after override resolution"),
    item("GraphQL alias/depth complexity", "resource_abuse", "covered_context", "not_enforced", "GraphQL AST budget", ["CWE-400", "API4:2023"], "requires parsed operation cost, not keyword matching"),
    item("API batch/resource consumption", "resource_abuse", "covered_context", "partial", "body size + application quota", ["API4:2023", "CWE-770"], "proxy caps bytes; cardinality and computational cost remain application-specific"),
    item("Business-flow automation", "business_logic", "covered_context", "not_enforced", "business state machine", ["API6:2023"], "inventory reservation and checkout completion context"),
    item("Race conditions / replay", "business_logic", "covered_context", "not_enforced", "transaction/idempotency layer", ["CWE-362"], "requires concurrent outcome and idempotency state"),
    item("CSV/spreadsheet formula injection", "business_logic", "covered_context", "not_enforced", "export encoder", ["CWE-1236"], "danger arises only when a stored value reaches spreadsheet export"),
    item("Cache poisoning / Host-forwarding trust", "cache_proxy", "covered_context", "not_enforced", "cache-key + trusted-proxy policy", ["CWE-444", "CWE-345"], "requires observed cache key and response variation"),
    item("Host-header password-reset poisoning", "cache_proxy", "covered_context", "not_enforced", "canonical-origin application policy", ["CWE-640", "CWE-346"], "request Host alone is insufficient; generated absolute links must be compared with configured origin"),
    item("Web cache deception", "cache_proxy", "covered_context", "not_enforced", "routing + cache policy", ["CWE-525"], "requires proof that private content was cached"),
    item("CORS misconfiguration", "browser_policy", "covered_context", "not_enforced", "response-header policy", ["CWE-942"], "request Origin alone is not malicious; response ACAO/credentials required"),
    item("Cross-site WebSocket hijacking", "websocket", "covered_context", "handshake_partial", "Origin + session policy", ["CWE-346"], "handshake data covered; frame payload and per-message authorization remain gaps"),
    item("WebSocket frame attacks", "websocket", "covered_sequence", "not_enforced", "WebSocket message gateway", ["CWE-20"], "paired fragmentation, masking, control-frame and budget events exist; current reverse proxy does not parse post-upgrade frames"),
    item("gRPC reflection enumeration", "grpc", "covered_context", "not_enforced", "gRPC gateway policy", ["CWE-200"], "synthetic sequences present"),
    item("gRPC protobuf field attacks", "grpc", "partial", "not_enforced", "descriptor-aware protobuf parser", ["CWE-20"], "opaque binary messages need service descriptors"),
    item("Vulnerability scanner behaviour", "reconnaissance", "covered_sequence", "covered", "stateful scanner detector", ["CWE-799"], "eight scanner families plus benign automation controls"),
    item("API inventory / deprecated endpoint and GraphQL schema discovery", "reconnaissance", "covered_context", "partial", "inventory + scanner behaviour", ["API9:2023"], "route and GraphQL introspection examples exist; authoritative deployment inventory remains external"),
    item("Unsafe consumption of third-party APIs", "supply_chain", "partial", "not_enforced", "egress schema and trust policy", ["API10:2023"], "SSRF/deserialization fields covered; provider trust and response validation are application concerns"),
    item("Vulnerable/outdated components", "supply_chain", "recent_cve_metadata", "not_remediated_by_waf", "asset/SBOM scanner", ["OWASP A06"], "CVE templates improve virtual patching but do not replace upgrades"),
    item("Software supply-chain integrity", "supply_chain", "outside_request_waf", "not_enforced", "CI/CD signing and provenance", ["OWASP A08"], "verify artifacts, dependencies and deployment provenance"),
    item("TLS/cryptographic failures", "configuration", "outside_request_waf", "not_enforced", "TLS terminator + application", ["OWASP A02"], "cipher, certificate, key storage and password hashing are not request payload properties"),
    item("Missing security headers / clickjacking", "configuration", "outside_request_waf", "not_enforced", "response policy", ["CWE-1021", "OWASP A05"], "CSP, HSTS and frame-ancestors require response inspection"),
    item("Sensitive data exposure in responses", "response", "outside_request_waf", "not_enforced", "response DLP/schema", ["CWE-200", "API3:2023"], "current WAF request model does not inspect response semantics"),
    item("Malware in uploaded binaries", "file_content", "outside_request_waf", "not_enforced", "AV/CDR/sandbox", ["CWE-434"], "filename/MIME metadata are insufficient for binary malware verdicts"),
    item("Compression/ZIP bombs", "denial_of_service", "partial", "body_size_only", "streaming decompression budget", ["CWE-409"], "byte limits exist; decompressed ratio and archive entry budgets are not implemented"),
    item("ReDoS and algorithmic complexity", "denial_of_service", "covered_context", "not_enforced", "sink-aware time budget", ["CWE-1333"], "a regex-looking string is not malicious without a vulnerable sink"),
    item("Memory corruption in native services", "native_exploit", "recent_cve_metadata", "not_generalizable", "patching/EDR/IPS", ["CWE-787", "CWE-125"], "generic payload ML cannot reliably virtual-patch arbitrary binary parsers"),
    item("LLM prompt/tool injection", "ai_application", "covered_context", "not_enforced", "LLM-specific policy and tool sandbox", ["OWASP LLM01", "OWASP LLM06"], "paired direct, indirect retrieval, prompt-exfiltration and tool-argument traces exist; runtime still requires conversation policy and tool capability controls"),
    item("LLM sensitive-information disclosure", "ai_application", "covered_context", "not_enforced", "LLM output DLP", ["OWASP LLM02"], "paired synthetic-canary output traces exist; request-only proxy still cannot enforce output policy"),
]


def main() -> None:
    specialized = json.loads((ROOT / "data" / "specialized_traffic" / "generated" / "manifest.json").read_text(encoding="utf-8"))
    modern = json.loads((ROOT / "data" / "modern_attack_traffic" / "generated" / "manifest.json").read_text(encoding="utf-8"))
    lab_captures = json.loads((ROOT / "data" / "lab_captures" / "generated" / "manifest.json").read_text(encoding="utf-8"))
    result = {
        "matrix_version": 1,
        "entries": ENTRIES,
        "summary": {
            "families": len(ENTRIES),
            "by_data_status": dict(sorted(Counter(item["data_status"] for item in ENTRIES).items())),
            "by_runtime_status": dict(sorted(Counter(item["runtime_status"] for item in ENTRIES).items())),
            "specialized_records": specialized.get("total_records"),
            "lab_capture_records": lab_captures.get("total_records"),
            "recent_cve_records": modern.get("total_records"),
        },
        "interpretation": {
            "covered": "representative data exists; production effectiveness still requires external validation",
            "covered_context": "paired context/session data exists but must not enter the context-free payload model",
            "gap": "no adequate dataset/runtime detector in this repository yet",
            "outside_request_waf": "control belongs to response, application, identity, asset, CI/CD or infrastructure layers",
        },
    }
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
