"""Scanner behaviour must use sequences, not a spoofable header alone."""

from src.scanner_detector import ScannerBehaviorDetector


def test_scanner_user_agent_alone_does_not_block():
    detector = ScannerBehaviorDetector()
    decision = detector.observe("client", "/", "Nuclei - Open-source project", now=1)
    assert not decision.verdict
    assert decision.score == 1


def test_known_probe_sequence_is_detected():
    detector = ScannerBehaviorDetector()
    first = detector.observe("client", "/.env", "Mozilla/5.0", now=1)
    second = detector.observe("client", "/.git/config", "Mozilla/5.0", now=2)
    assert not first.verdict
    assert second.verdict
    assert "multiple_known_probe_routes" in second.signals


def test_ffuf_style_path_diversity_needs_combined_evidence():
    detector = ScannerBehaviorDetector()
    decision = None
    for index in range(10):
        decision = detector.observe("client", f"/word-{index}", "ffuf/2.1.0", now=index / 10)
    assert decision is not None and not decision.verdict
    # One actual probe route combines with the existing UA + burst evidence.
    decision = detector.observe("client", "/server-status", "ffuf/2.1.0", now=2)
    assert decision.verdict


def test_legitimate_crawler_and_monitoring_sequences_stay_benign():
    detector = ScannerBehaviorDetector()
    for index in range(20):
        decision = detector.observe(
            "crawler", f"/articles/{index}", "ExampleSearchBot/2.0", now=index / 10
        )
    assert not decision.verdict
    for index in range(30):
        decision = detector.observe(
            "monitor", ("/healthz", "/readyz", "/metrics")[index % 3],
            "Normal-monitoring/2.0", now=index / 10,
        )
    assert not decision.verdict


def test_window_expiry_and_client_isolation():
    detector = ScannerBehaviorDetector(window_seconds=5)
    detector.observe("a", "/.env", now=0)
    expired = detector.observe("a", "/normal", now=10)
    other = detector.observe("b", "/.git/config", now=10)
    assert not expired.verdict and expired.probe_count == 0
    assert not other.verdict and other.probe_count == 1
