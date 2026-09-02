"""
级联检测管线 / Cascade Detection Pipeline

将归一化器、特征提取器、高置信规则、LightGBM 与字符 n-gram 模型
串联成最终检测链路。

检测逻辑：
  L1 (规则引擎)  < 1ms  → 命中高严重规则 → 直接判 attack
                          → 无命中 + 无混淆 → 直接判 benign
                          → 不确定 → 进入 L2

  L2 (LightGBM + 字符 n-gram) → 使用元数据中的权重和阈值融合判定

性能目标：P99 < 10ms
"""

from __future__ import annotations

import base64
import pickle
import json
import math
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote

import numpy as np

from .normalizer import normalize, ConfusionMeta
from .extractor import extract, extract_with_names
from .engine import RuleEngine, Rule
from .cache import FeatureCache


@dataclass
class DetectionResult:
    """检测结果"""
    verdict: str                  # "benign" | "attack"
    confidence: float             # 0.0 ~ 1.0
    layer: str                    # "L0" | "L1" | "L2" | "L2+Text"
    payload: str                  # 原始输入（截断至前 200 字符）
    normalized: str               # 归一化后的文本（截断）
    confusion_meta: dict          # ConfusionMeta 摘要
    features: dict[str, float]    # 38 维特征值
    rule_hits: list[str]          # L1 命中的规则 ID
    l2_score: Optional[float]     # LightGBM 输出概率
    l3_score: Optional[float]     # 字符 n-gram 文本模型输出概率（兼容 API 字段名）
    elapsed_ms: float             # 总耗时（毫秒）


class DetectionPipeline:
    """
    检测管线。

    用法:
        pipeline = DetectionPipeline()
        pipeline.load_lgbm("models/current/lgbm_v4.pkl")
        pipeline.load_text_model("models/current/text_lr_v4.pkl")

        result = pipeline.detect("' OR 1=1 --", param_location="query")
        print(result.verdict, result.confidence, result.layer)
    """

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.lgbm_model = None
        self.text_model = None
        self.cache = FeatureCache(maxsize=10000)
        self._l2_threshold_high = 0.85
        self._l2_threshold_low = 0.15
        self._feature_weight = 1.0
        self._text_weight = 0.0

    # ---- 模型加载 ----

    def load_lgbm(self, path: str):
        """加载 LightGBM 模型（pickle 格式）"""
        with open(path, "rb") as f:
            self.lgbm_model = pickle.load(f)
        meta_path = Path(path).with_suffix(".meta.json")
        if meta_path.exists():
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            thresholds = metadata.get("thresholds", {})
            self._l2_threshold_high = float(thresholds.get("high", self._l2_threshold_high))
            self._l2_threshold_low = float(thresholds.get("low", self._l2_threshold_low))
            fusion = metadata.get("fusion", {})
            self._feature_weight = float(fusion.get("feature_weight", self._feature_weight))
            self._text_weight = float(fusion.get("text_weight", self._text_weight))

    def load_text_model(self, path: str):
        """Load the final character n-gram context model."""
        with open(path, "rb") as handle:
            self.text_model = pickle.load(handle)
        # ── sklearn ≥1.6 compatibility: model trained on newer sklearn lacks
        # `multi_class` in state, but 1.6 predict_proba still reads it ──
        try:
            lr = self.text_model.steps[-1][1]
            if not hasattr(lr, "multi_class"):
                lr.multi_class = "deprecated"
        except Exception:
            pass

    # ---- 检测入口 ----

    def detect(self, payload: str, param_location: str = "query",
               param_name: str = "value") -> DetectionResult:
        """
        对单条 HTTP 参数执行全链路检测。

        参数:
          payload: HTTP 参数值字符串
          param_location: 参数位置（query/body/header/cookie/path）

        返回: DetectionResult
        """
        import time
        t0 = time.perf_counter()

        # Raw high-confidence signatures form the terminal L1-Raw block.
        # Normalization may consume evidence (%0d%0a→controls, SSI comments
        # removed), so high-confidence raw + encoded hits must be terminal.
        raw_verdict, raw_hits = self.rule_engine.check(payload, True, 0)
        encoded_hits = self._encoded_high_risk_rules(payload, param_location)
        if raw_verdict == "attack" or encoded_hits:
            restored, meta = normalize(payload, param_location=param_location)
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="attack", confidence=0.99, layer="L1-Raw",
                payload=payload[:200], normalized=restored[:200],
                confusion_meta=self._meta_summary(meta),
                features=extract_with_names(payload, restored, meta),
                rule_hits=[rule.id for rule in raw_hits] + encoded_hits,
                l2_score=None, l3_score=None, elapsed_ms=elapsed,
            )
        if self._is_obviously_benign(payload, param_location, param_name):
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="benign", confidence=0.999, layer="L0",
                payload=payload[:200], normalized=payload[:200],
                confusion_meta={
                    "decode_depth": 0, "converged": True,
                    "url_decode_layers": 0, "base64_decode_success": False,
                    "len_before_after_ratio": 1.0, "entropy_delta": 0.0,
                },
                features={}, rule_hits=[], l2_score=None, l3_score=None,
                elapsed_ms=elapsed,
            )

        # 检查缓存
        cache_key = (payload, param_location, param_name)
        cached = self.cache.get(cache_key)
        if cached is not None:
            restored, meta, features = cached
        else:
            # ① 归一化
            restored, meta = normalize(payload, param_location=param_location)
            # ② 特征提取
            features = extract(payload, restored, meta)
            self.cache.put(cache_key, (restored, meta, features))

        # ③ L1 规则引擎
        l1_verdict, rule_hits = self.rule_engine.check(
            restored, meta.converged, meta.decode_depth
        )

        rule_hit_ids = [r.id for r in rule_hits]
        l2_score = None
        l3_score = None
        layer = "L1"

        if l1_verdict == "attack":
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="attack", confidence=0.99, layer="L1",
                payload=payload[:200], normalized=restored[:200],
                confusion_meta=self._meta_summary(meta),
                features=extract_with_names(payload, restored, meta),
                rule_hits=rule_hit_ids,
                l2_score=None, l3_score=None, elapsed_ms=elapsed,
            )

        # Contextual attack rules (SSRF/redirect/path/fupload) run AFTER
        # L1 normalized but BEFORE security-discussion guard. The guard must
        # not release a real external redirect or SSRF target.
        context_hits = self._contextual_attack_rules(payload, restored, param_location, param_name)
        if context_hits:
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="attack", confidence=0.99, layer="L1-Context",
                payload=payload[:200], normalized=restored[:200],
                confusion_meta=self._meta_summary(meta),
                features=extract_with_names(payload, restored, meta),
                rule_hits=rule_hit_ids + context_hits,
                l2_score=None, l3_score=None, elapsed_ms=elapsed,
            )

        # Human-authored documentation and forum questions often mention the
        # same keywords as attacks.  A keyword-only model cannot distinguish
        # ``sleep()`` (a function reference) from ``sleep(1.1)`` (an
        # executable delay expression).  Apply this narrow context guard only
        # after high-confidence attack rules have had the first opportunity to
        # reject the value.
        if self._is_security_discussion(payload, restored, param_location, param_name):
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="benign", confidence=0.995, layer="L0-Context",
                payload=payload[:200], normalized=restored[:200],
                confusion_meta=self._meta_summary(meta),
                features=extract_with_names(payload, restored, meta),
                rule_hits=rule_hit_ids,
                l2_score=None, l3_score=None, elapsed_ms=elapsed,
            )

        # L0 high-precision benign fast path. This is deliberately narrow:
        # structured/encoded values and security-sensitive parameter names
        # always continue to the statistical + text models.
        if self._is_obviously_benign(payload, param_location, param_name):
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="benign", confidence=0.999, layer="L0",
                payload=payload[:200], normalized=restored[:200],
                confusion_meta=self._meta_summary(meta),
                features=extract_with_names(payload, restored, meta),
                rule_hits=rule_hit_ids,
                l2_score=None, l3_score=None, elapsed_ms=elapsed,
            )

        if l1_verdict == "benign":
            elapsed = (time.perf_counter() - t0) * 1000
            return DetectionResult(
                verdict="benign", confidence=0.99, layer="L1",
                payload=payload[:200], normalized=restored[:200],
                confusion_meta=self._meta_summary(meta),
                features=extract_with_names(payload, restored, meta),
                rule_hits=rule_hit_ids,
                l2_score=None, l3_score=None, elapsed_ms=elapsed,
            )

        # ④ L2 LightGBM
        if self.lgbm_model is not None:
            if hasattr(self.lgbm_model, "booster_"):
                l2_score = float(self.lgbm_model.booster_.predict(features.reshape(1, -1))[0])
            elif hasattr(self.lgbm_model, "predict_proba"):
                l2_score = float(self.lgbm_model.predict_proba(features.reshape(1, -1))[0, 1])
            elif hasattr(self.lgbm_model, "decision_function"):
                decision = float(self.lgbm_model.decision_function(features.reshape(1, -1))[0])
                l2_score = 1.0 / (1.0 + math.exp(-decision))
            else:
                l2_score = float(self.lgbm_model.predict(features.reshape(1, -1))[0])
            layer = "L2"
            decision_score = l2_score
            if self.text_model is not None:
                # 最终文本模型只使用载荷及其归一化结果，不读取真实标签或攻击类型。
                context_text = f"{payload} __normalized__ {restored}"
                text_score = float(self.text_model.predict_proba([context_text])[0, 1])
                l3_score = text_score
                decision_score = self._feature_weight * l2_score + self._text_weight * text_score
                layer = "L2+Text"

            # Headers/cookies contain many opaque tokens. Require stronger
            # evidence there to control request-level false positives.
            high_threshold = max(self._l2_threshold_high, 0.95) if param_location in {"header", "cookie"} else self._l2_threshold_high
            low_threshold = min(self._l2_threshold_low, 0.05) if param_location in {"header", "cookie"} else self._l2_threshold_low

            if decision_score >= high_threshold:
                elapsed = (time.perf_counter() - t0) * 1000
                return DetectionResult(
                    verdict="attack", confidence=decision_score, layer=layer,
                    payload=payload[:200], normalized=restored[:200],
                    confusion_meta=self._meta_summary(meta),
                    features=extract_with_names(payload, restored, meta),
                    rule_hits=rule_hit_ids,
                    l2_score=l2_score, l3_score=l3_score, elapsed_ms=elapsed,
                )

            if decision_score <= low_threshold:
                elapsed = (time.perf_counter() - t0) * 1000
                return DetectionResult(
                    verdict="benign", confidence=1 - decision_score, layer=layer,
                    payload=payload[:200], normalized=restored[:200],
                    confusion_meta=self._meta_summary(meta),
                    features=extract_with_names(payload, restored, meta),
                    rule_hits=rule_hit_ids,
                    l2_score=l2_score, l3_score=l3_score, elapsed_ms=elapsed,
                )

        # Fallback: use the calibrated
        # decision threshold instead of returning a value later counted as benign.
        elapsed = (time.perf_counter() - t0) * 1000
        if l2_score is None:
            final_verdict, final_conf = "uncertain", 0.5
        else:
            decision_score = (
                self._feature_weight * l2_score + self._text_weight * l3_score
                if l3_score is not None and self.text_model is not None else l2_score
            )
            decision_threshold = (
                max(self._l2_threshold_high, 0.95)
                if param_location in {"header", "cookie"}
                else self._l2_threshold_high
            )
            final_verdict = "attack" if decision_score >= decision_threshold else "benign"
            final_conf = max(decision_score, 1 - decision_score)
        return DetectionResult(
            verdict=final_verdict, confidence=final_conf, layer=layer,
            payload=payload[:200], normalized=restored[:200],
            confusion_meta=self._meta_summary(meta),
            features=extract_with_names(payload, restored, meta),
            rule_hits=rule_hit_ids,
            l2_score=l2_score, l3_score=l3_score, elapsed_ms=elapsed,
        )

    # ---- 内部方法 ----

    # Pre-compiled hot-path regex (avoid per-call compilation)
    _RE_NUMBER = re.compile(r"[+-]?\d+(?:\.\d+)?")
    _RE_CONTROL_CHARS = re.compile(r"[<>'\"%\r\n`]")
    _RE_PLAIN_TEXT = re.compile(r"[\w\-.\u3400-\u9fff ]{1,128}", re.UNICODE)

    @staticmethod
    def _is_obviously_benign(payload: str, location: str, name: str) -> bool:
        value = payload.strip()
        if not value or len(value) > 256:
            return False
        suspicious_names = {
            "url", "uri", "redirect", "redirect_url", "return", "return_url",
            "next", "continue", "callback", "file", "path", "template", "cmd",
            "command", "exec", "query", "sql", "xml", "filename", "upload",
            "log", "message",
        }
        if name.lower() in suspicious_names:
            return False
        low = value.lower()
        if low in {"true", "false", "null", "none", "asc", "desc", "zh-cn", "en-us"}:
            return True
        if DetectionPipeline._RE_NUMBER.fullmatch(value):
            return True
        # Conventional browser agents without control/markup characters.
        if location == "header" and value.startswith("Mozilla/5.0") and not DetectionPipeline._RE_CONTROL_CHARS.search(value):
            return True
        # Plain human text/identifiers only. Dots are allowed, but traversal is not.
        if (".." not in value
                and DetectionPipeline._RE_PLAIN_TEXT.fullmatch(value)
                and (" " in value or len(value) <= 6)):
            return True
        return False

    @staticmethod
    def _is_security_discussion(payload: str, restored: str,
                                location: str, name: str) -> bool:
        """Recognize non-executable security/database questions conservatively.

        This is intentionally not a generic keyword whitelist.  It requires a
        human-text field, a multilingual discussion marker, multiple technical
        terms (or an empty function reference), and no executable attack
        structure.  High-confidence L1 rules run before this method.
        """
        if location not in {"body", "query"}:
            return False
        text_fields = {
            "content", "question", "comment", "description", "title",
            "message", "body", "text", "post", "query", "q",
        }
        if name.lower() not in text_fields:
            return False

        text = f"{payload}\n{restored}".lower()
        if len(text) > 4096:
            return False

        discussion_markers = (
            # Chinese / English
            "怎么", "如何", "什么", "区别", "用法", "函数", "教程", "文档", "示例", "解释",
            "how ", "what ", "difference", " use ", "function", "tutorial", "documentation", "example", "explain",
            # Japanese / Korean
            "違い", "使い", "使用", "方法", "教え", "何です", "차이", "사용", "방법", "무엇",
            # Spanish / French / German / Portuguese
            "diferencia", "cómo", "como ", "usar", "función", "ejemplo",
            "différence", "comment ", "utiliser", "fonction", "exemple",
            "unterschied", "wie ", "verwenden", "funktion", "beispiel",
            "diferença", "função",
            # Russian / Arabic
            "разниц", "как ", "использов", "функц", "пример",
            "الفرق", "كيف", "استخدام", "دالة", "مثال",
        )
        if not any(marker in text for marker in discussion_markers):
            return False

        # These shapes are executable or carry an active exploitation
        # primitive.  A polite/question-like wrapper must never neutralize it.
        dangerous_shapes = (
            r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*[^\s)]",
            r"\bunion\s+(?:all\s+)?select\b",
            r"(?:'|\")\s*(?:or|and)\s+[^\r\n]{0,40}(?:=|like)\s*[^\r\n]{0,40}(?:--|#|/\*)?",
            r"\b(?:or|and)\s+\d+\s*=\s*\d+",
            r"<\s*(?:script|iframe|svg|img)\b",
            r"\bon\w+\s*=|javascript\s*:",
            r"(?:^|\s)[;&|]{1,2}\s*(?:cat|id|whoami|curl|wget|bash|sh|powershell|cmd)\b",
            r"\$\(|`[^`]+`|\.\.[/\\]|%0d|%0a|\{\{|\$\{",
        )
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in dangerous_shapes):
            return False

        terms = re.findall(
            r"\b(?:select|join|union|insert|update|delete|where|script|iframe|"
            r"onload|onerror|curl|wget|base64|jwt|hs256|rs256|sleep|benchmark|"
            r"sql|xss|csrf|xxe|ssti)\b",
            text,
            re.IGNORECASE,
        )
        empty_function_reference = bool(re.search(
            r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*\)", text, re.IGNORECASE
        ))
        return empty_function_reference or len(set(term.lower() for term in terms)) >= 2

    # ── Contextual and encoded high-risk rules ────────────────────────

    @staticmethod
    def _contextual_attack_rules(payload: str, restored: str,
                                 location: str, name: str) -> list[str]:
        """Context-dependent attack detection (SSRF/redirect/upload/path traversal).

        These rules rely on real HTTP field names — they MUST NOT use
        synthetic names derived from labels to avoid label leakage.
        """
        value = restored.strip()
        lower = value.lower()
        field = name.lower()
        hits: list[str] = []
        redirect_fields = {
            "redirect", "redirect_url", "return", "return_url", "next",
            "continue", "callback", "url", "uri",
        }
        if field in redirect_fields and re.match(
            r"(?i)^(?://|https?://|\\\\|%2f%2f|%5c%5c)", payload.strip()
        ):
            hits.append("context_external_redirect")

        ssrf_fields = {"url", "uri", "endpoint", "target", "host", "callback", "webhook"}
        if field in ssrf_fields and (
            re.search(r"(?i)(?:^|[/@])(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254)(?:[:/]|$)", lower)
            or "metadata.google.internal" in lower
            or re.match(r"(?i)^(?:file|gopher|dict)://", lower)
        ):
            hits.append("context_ssrf_target")

        if (location == "path" or field in {"file", "filename", "path", "template"}) and re.search(
            r"(?i)(?:\.\.[/\\]|%2e%2e|%252e)", payload
        ):
            hits.append("context_path_traversal")

        if field in {"file", "filename", "upload", "attachment"} and re.search(
            r"(?i)\.(?:php\d*|phtml|phar|aspx?|jspx?|war)(?:[.\s]|$)", lower
        ):
            hits.append("context_dangerous_upload")

        if location in {"query", "header", "cookie"} and re.search(
            r"[\r\n]|\\r\\n|\\n\\r", restored
        ):
            hits.append("context_control_character_injection")
        return hits

    @staticmethod
    def _encoded_high_risk_rules(payload: str, location: str) -> list[str]:
        """Short Base64/URL-encoded dangerous primitives before lossy normalization.

        Short Base64 like ``JTBkJTBh`` (%0d%0a) is normally skipped by the
        general normalizer. This peels a few layers only when the decoded
        result is an unambiguous CRLF or repeated format-string primitive.
        """
        candidates = [payload]
        compact = payload.strip()
        if (8 <= len(compact) <= 8192
                and re.fullmatch(r"[A-Za-z0-9_+\-/]+={0,2}", compact)):
            try:
                padded = compact + "=" * ((4 - len(compact) % 4) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="strict")
                candidates.append(decoded)
            except Exception:
                pass
        expanded = []
        for candidate in candidates:
            current = candidate
            for _ in range(3):
                expanded.append(current)
                decoded = unquote(current, encoding="utf-8", errors="replace")
                if decoded == current:
                    break
                current = decoded

        hits: list[str] = []
        for candidate in expanded:
            if location in {"query", "header", "cookie"} and re.search(
                r"(?i)(?:%0d|%0a|\\r\\n|\\n\\r|[\r\n])", candidate
            ):
                hits.append("encoded_control_character_injection")
                break
        for candidate in expanded:
            if re.search(r"(?:%(?:\d+\$|\d+)?[spxXdn]){3,}", candidate):
                hits.append("encoded_format_string")
                break
        return hits

    @staticmethod
    def _meta_summary(meta: ConfusionMeta) -> dict:
        return {
            "decode_depth": meta.decode_depth,
            "converged": meta.converged,
            "url_decode_layers": meta.url_decode_layers,
            "base64_decode_success": meta.base64_decode_success,
            "len_before_after_ratio": (
                meta.len_before / max(meta.len_after, 1) if meta.len_after else 1.0
            ),
            "entropy_delta": meta.entropy_before - meta.entropy_after,
        }
