from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from src.engine import RuleEngine
from src.normalizer import normalize
from src.parser import parse_auto, parse_http
from src.pipeline import DetectionPipeline
from src.settings import MODEL_ROOT
from training.search_sampling_strategy import operating_point


ROOT = Path(__file__).resolve().parents[1]


def test_operating_point_can_reach_high_recall_below_old_threshold_floor():
    labels = np.asarray([0, 0, 1, 1], dtype=np.int32)
    probabilities = np.asarray([0.10, 0.20, 0.35, 0.90], dtype=np.float64)

    point = operating_point(
        labels,
        probabilities,
        probabilities,
        np.asarray(["normal", "normal", "sqli", "sqli"]),
        np.asarray(["normal", "normal", "original", "original"]),
        min_recall=1.0,
        max_fpr=0.0,
    )

    assert 0.30 <= point["threshold"] < 0.40
    assert point["recall"] == 1.0
    assert point["fpr"] == 0.0


@pytest.fixture(scope="module")
def detector() -> DetectionPipeline:
    pipeline = DetectionPipeline()
    pipeline.load_lgbm(str(MODEL_ROOT / "lgbm_v4.pkl"))
    pipeline.load_text_model(str(MODEL_ROOT / "text_lr_v4.pkl"))
    return pipeline


@pytest.mark.parametrize("payload", ["sleep(1.1)", "SLEEP(0.5)", "sleep(.5)", "sleep(1e0)", "pg_sleep(0.25)"])
def test_decimal_delay_rules(payload: str):
    restored, meta = normalize(payload)
    verdict, hits = RuleEngine().check(restored, meta.converged, meta.decode_depth)
    assert verdict == "attack"
    assert hits


def test_no_rule_hit_is_not_automatically_benign():
    restored, meta = normalize("previously unseen syntax")
    verdict, _ = RuleEngine().check(restored, meta.converged, meta.decode_depth)
    assert verdict == "uncertain"


def test_utf8_percent_decode_and_url_preservation():
    restored, _ = normalize("%E4%B8%AD%E6%96%87")
    assert restored == "中文"
    url = "https://docs.example.test/api/v1/search?q=sleep"
    restored_url, _ = normalize(url, param_location="header")
    assert restored_url == url


def test_cookie_is_not_detected_twice():
    parsed = parse_http("GET / HTTP/1.1\r\nHost: example.test\r\nCookie: session=abc123; theme=dark\r\n\r\n")
    params = parsed.all_params()
    assert sum(p.location == "cookie" for p in params) == 2
    assert not any(p.location == "header" and p.name.lower() == "cookie" for p in params)


@pytest.mark.parametrize("payload,location", [
    ("hello world", "query"),
    ("hello", "query"),
    ("SELECT name FROM products WHERE id = ?", "body"),
    ("The worker will sleep for 1.1 seconds before continuing.", "body"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "header"),
    ("https://docs.example.test/api/v1/search?q=sleep", "header"),
    ("eyJzdWIiOiJ1c2VyLTEiLCJzY29wZSI6InByb2ZpbGU6cmVhZCJ9", "cookie"),
])
def test_known_normal_regressions(detector: DetectionPipeline, payload: str, location: str):
    assert detector.detect(payload, location).verdict == "benign"


@pytest.mark.parametrize("payload,location", [
    ("sleep(1.1)", "query"),
    ("%73%6c%65%65%70%28%31%2e%31%29", "query"),
    ("' OR 1=1 --", "query"),
    ("<img src=x onerror=alert(1)>", "body"),
    # 手工对抗门禁将可执行外部脚本标签视为攻击；与正式独立评测保持一致。
    ('<script src="/assets/app.js"></script>', "body"),
    ("; cat /etc/passwd", "query"),
])
def test_known_attack_regressions(detector: DetectionPipeline, payload: str, location: str):
    assert detector.detect(payload, location).verdict == "attack"


def test_normal_http_request_does_not_compound_false_positives(detector: DetectionPipeline):
    raw = (
        "POST /api/search?q=hello%20world&page=2 HTTP/1.1\r\n"
        "Host: api.example.test\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Cookie: session=abc123; theme=dark\r\n\r\n"
        '{"title":"weekly report","active":true}'
    )
    results = [detector.detect(p.value, p.location, p.name).verdict
               for p in parse_auto(raw) if p.location != "path"]
    assert results
    assert "attack" not in results


def test_attack_inside_http_request_is_detected(detector: DetectionPipeline):
    raw = "GET /search?q=sleep%281.1%29 HTTP/1.1\r\nHost: example.test\r\n\r\n"
    results = [detector.detect(p.value, p.location, p.name).verdict for p in parse_auto(raw)]
    assert "attack" in results


def test_redirect_uses_parameter_context(detector: DetectionPipeline):
    assert detector.detect("//3627734734", "query", "redirect").verdict == "attack"


def test_jwt_empty_signature_detected(detector: DetectionPipeline):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ."
    assert detector.detect(token, "header", "Authorization").verdict == "attack"


def test_chinese_sql_discussion_is_benign(detector: DetectionPipeline):
    text = "SELECT 和 JOIN 的区别是什么？UNION 怎么用？"
    result = detector.detect(text, "body", "content")
    assert result.verdict == "benign", {
        "layer": result.layer,
        "feature_score": result.l2_score,
        "text_score": result.l3_score,
        "rules": result.rule_hits,
    }


@pytest.mark.parametrize("location,name", [
    ("query", "value"),
    ("body", "value"),
    ("query", "q"),
    ("body", "content"),
])
def test_short_chinese_sql_discussion_is_benign_for_batch_defaults(
    detector: DetectionPipeline, location: str, name: str
):
    result = detector.detect("SELECT 和 JOIN 的区别是什么？  ", location, name)
    assert result.verdict == "benign"
    assert result.layer == "L0-Context"


@pytest.mark.parametrize("payload", [
    "SELECT 和 JOIN 的区别是什么？ UNION SELECT password FROM users",
    "SELECT 和 JOIN 的区别是什么？ sleep(1.1)",
    "SELECT 和 JOIN 的区别是什么？ <script>alert(1)</script>",
    "SELECT 和 JOIN 的区别是什么？; DROP TABLE users",
])
def test_batch_default_context_does_not_hide_executable_attacks(
    detector: DetectionPipeline, payload: str
):
    assert detector.detect(payload, "query", "value").verdict == "attack"


@pytest.mark.parametrize("text", [
    "SELECT と JOIN の違いは何ですか？ UNION はどう使いますか？",
    "SELECT와 JOIN의 차이점은 무엇인가요? UNION은 어떻게 사용하나요?",
    "¿Cuál es la diferencia entre SELECT y JOIN? ¿Cómo se usa UNION?",
    "Quelle est la différence entre SELECT et JOIN ? Comment utiliser UNION ?",
    "Was ist der Unterschied zwischen SELECT und JOIN? Wie nutzt man UNION?",
    "В чем разница между SELECT и JOIN? Как использовать UNION?",
    "ما الفرق بين SELECT و JOIN؟ كيف يتم استخدام UNION؟",
    "Qual é a diferença entre SELECT e JOIN? Como usar UNION?",
])
def test_multilingual_sql_discussions_are_benign(detector: DetectionPipeline, text: str):
    assert detector.detect(text, "body", "content").verdict == "benign"


def test_attack_inside_multilingual_context_is_detected(detector: DetectionPipeline):
    text = '{"language":"es","pregunta":"Revise esta entrada","contenido":"sleep(1.1)"}'
    assert detector.detect(text, "body", "content").verdict == "attack"


def test_empty_sleep_function_in_chinese_discussion_is_benign(detector: DetectionPipeline):
    text = "SELECT 和 JOIN 那么sleep()函数怎么使用"
    result = detector.detect(text, "body", "content")
    assert result.verdict == "benign", {
        "layer": result.layer,
        "feature_score": result.l2_score,
        "text_score": result.l3_score,
        "rules": result.rule_hits,
    }
    assert result.layer == "L0-Context"


def test_empty_sleep_function_in_full_http_request_is_benign(detector: DetectionPipeline):
    raw = (
        "POST /forum HTTP/1.1\r\n"
        "Host: dev.com\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"content":"SELECT 和 JOIN 那么sleep()函数怎么使用"}'
    )
    results = [detector.detect(p.value, p.location, p.name) for p in parse_auto(raw)]
    assert results
    assert not [r for r in results if r.verdict == "attack"]


@pytest.mark.parametrize("text", [
    "请问 sleep(1.1) 函数怎么使用？",
    "How should I use sleep(1.1) in this tutorial?",
    "¿Cómo se usa sleep(1.1)?",
    "sleep(1.1) の使い方を教えてください。",
])
def test_executable_delay_is_not_hidden_by_discussion_context(
    detector: DetectionPipeline, text: str
):
    assert detector.detect(text, "body", "content").verdict == "attack"


def test_union_select_is_not_hidden_by_discussion_context(detector: DetectionPipeline):
    assert detector.detect(
        "UNION SELECT 怎么使用？", "body", "content"
    ).verdict == "attack"


def test_rule_gray_zone_really_enters_both_statistical_models(
    detector: DetectionPipeline,
):
    payload = "zxqv_2026_"
    restored, meta = normalize(payload)
    rule_verdict, _ = RuleEngine().check(
        restored,
        meta.converged,
        meta.decode_depth,
    )
    assert rule_verdict == "uncertain"

    result = detector.detect(payload, "query", "value")
    assert result.layer == "L2+Text"
    assert result.l2_score is not None
    assert result.l3_score is not None
    assert result.verdict in {"attack", "benign"}

