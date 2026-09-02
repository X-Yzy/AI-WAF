"""统一项目入口：训练、测试、验证、演示与数据审计。

最完整的竞赛复现命令是 ``python run.py all``。各阶段使用当前 Python
解释器启动独立子进程，既能保证失败立即停止，也能避免训练阶段占用的内存
影响随后进行的性能评测。
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models" / "current"
WAF_REPORT_NAME = "waf_comparison.json"
WAF_CACHE_NAME = "waf_comparison.last_verified.json"
REQUIRED_WAF_SYSTEMS = frozenset({
    "final_model",
    "modsecurity_crs_4_28_0",
    "safeline_ce",
    "openappsec_ce",
})
EXTERNAL_WAF_PRODUCTS = {
    "safeline_ce": {
        "url": "http://127.0.0.1:18082",
        "version": "9.3.11",
    },
    "openappsec_ce": {
        "url": "http://127.0.0.1:18083",
        "version": "1.1.35-open-source",
    },
}
PROOF_BACKEND_URL = "http://127.0.0.1:18081"


def configure_utf8_console() -> None:
    """统一 CLI 输出编码，避免 Windows 中文代码页与 UTF-8 子进程混用。"""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


configure_utf8_console()


def current_python() -> str:
    """返回可重新启动的解释器路径。

    默认沿用启动当前项目的全局解释器，不因项目目录中存在 ``.venv`` 而自动切换。
    个别 Windows Python Manager 会让 ``sys.executable`` 指向不可直接启动的内部
    二进制，此时使用同一安装目录或 PATH 中的 ``python`` wrapper；也可通过
    ``WAD_PYTHON`` 显式覆盖。
    """
    override = os.environ.get("WAD_PYTHON")
    if override:
        return override
    managed_wrapper = Path(sys.executable).parent.parent / "bin" / "python.exe"
    if managed_wrapper.is_file():
        return str(managed_wrapper)
    path_python = shutil.which("python")
    if (
        path_python
        and "WindowsApps" not in path_python
        and Path(path_python).resolve() != Path(sys.executable).resolve()
    ):
        return path_python
    return sys.executable


def run_stage(label: str, command: list[str]) -> None:
    """打印可复制的命令并执行；任一阶段失败时以非零状态终止。"""
    print(f"\n=== {label} ===", flush=True)
    print("$ " + " ".join(command), flush=True)
    environment = os.environ.copy()
    # 将已经验证可启动的解释器传给可能继续创建 Python 子进程的脚本。
    # Windows Python Manager 的 sys.executable 可能指向不能由 CreateProcess
    # 直接启动的内部二进制，而 command[0] 是 current_python() 解析后的 wrapper。
    environment.setdefault("WAD_PYTHON", command[0])
    # 后台控制台统一使用 UTF-8；避免 Windows 系统代码页导致中文日志乱码。
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    subprocess.run(command, cwd=ROOT, env=environment, check=True)



def docker_engine_status() -> tuple[bool, str]:
    """Return a concise Docker daemon status without raising a traceback."""

    docker = shutil.which("docker")
    if not docker:
        return False, "未找到 docker 命令"
    try:
        completed = subprocess.run(
            [docker, "version", "--format", "{{json .Server}}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Docker 状态检查失败：{exc}"
    if completed.returncode == 0:
        return True, "Docker 引擎可用"
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    concise = detail[-1] if detail else "Docker 引擎未运行"
    return False, concise


def _read_json_object(path: Path) -> dict:
    """Read a JSON object, returning an empty object for absent/invalid files."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _is_complete_waf_report(report: dict) -> bool:
    """Return whether a report contains a complete, real same-set comparison."""

    systems = report.get("systems")
    dataset = report.get("dataset")
    if not isinstance(systems, dict) or not REQUIRED_WAF_SYSTEMS.issubset(systems):
        return False
    if any(not isinstance(systems.get(key), dict) for key in REQUIRED_WAF_SYSTEMS):
        return False
    if not isinstance(dataset, dict):
        return False
    try:
        if int(dataset.get("total", 0)) <= 0:
            return False
    except (TypeError, ValueError):
        return False
    fairness = report.get("fairness")
    if isinstance(fairness, dict) and fairness.get(
        "complete_independent_test_split"
    ) is False:
        return False
    candidates = report.get("candidate_products")
    identities = report.get("product_identities")
    if not isinstance(candidates, dict) or not isinstance(identities, dict):
        return False
    for key in EXTERNAL_WAF_PRODUCTS:
        candidate = candidates.get(key)
        identity = identities.get(key)
        if (
            not isinstance(candidate, dict)
            or candidate.get("status") != "evaluated"
            or candidate.get("included_in_ranking") is not True
            or not isinstance(identity, dict)
            or identity.get("is_actual_product_execution") is not True
            or identity.get("is_simulation") is not False
        ):
            return False
    return True


def require_complete_waf_report(path: Path) -> dict:
    """Load a report or fail the workflow before it can be published."""

    report = _read_json_object(path)
    if not _is_complete_waf_report(report):
        missing = sorted(
            REQUIRED_WAF_SYSTEMS.difference(
                report.get("systems", {})
                if isinstance(report.get("systems"), dict)
                else {}
            )
        )
        detail = f"，缺少系统：{', '.join(missing)}" if missing else ""
        raise SystemExit(f"真实 WAF 报告未通过四产品完整性门禁{detail}")
    return report


def _proof_backend_is_ready() -> bool:
    request = Request(f"{PROOF_BACKEND_URL}/health", method="GET")
    try:
        with urlopen(request, timeout=2) as response:
            return response.headers.get("X-WAD-Benchmark-Backend") == "reached"
    except (HTTPError, URLError, OSError, TimeoutError):
        return False


@contextmanager
def benchmark_proof_backend():
    """Run the local proof backend for external real-product experiments."""

    if _proof_backend_is_ready():
        yield
        return

    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    process = subprocess.Popen(
        [
            current_python(),
            str(ROOT / "deployment" / "waf_benchmark" / "proof_backend.py"),
            "--host",
            "0.0.0.0",
            "--port",
            "18081",
        ],
        cwd=ROOT,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"基准回显后端启动失败，退出码 {process.returncode}"
                )
            if _proof_backend_is_ready():
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("基准回显后端在 20 秒内未就绪")
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def load_cached_waf_report() -> dict:
    """Load only a cache that still satisfies the complete-report gate."""

    cache = _read_json_object(MODEL_DIR / WAF_CACHE_NAME)
    return cache if _is_complete_waf_report(cache) else {}


def cache_verified_waf_report(report: dict | None = None) -> Path | None:
    """Persist the latest complete comparison without presenting it as current.

    Status-only reports, partial external-product runs, and failed experiments
    never replace the cache. This guarantees that opening the dashboard still
    has useful data while keeping scientific provenance explicit.
    """

    source = report
    if source is None:
        source = _read_json_object(MODEL_DIR / WAF_REPORT_NAME)
    if not _is_complete_waf_report(source):
        return None

    existing = _read_json_object(MODEL_DIR / WAF_CACHE_NAME)
    if _is_complete_waf_report(existing):
        existing_systems = existing.get("systems", {})
        source_systems = source.get("systems", {})
        if len(existing_systems) > len(source_systems):
            return None

    cached = json.loads(json.dumps(source, ensure_ascii=False))
    cached.pop("cached_report", None)
    cached["cache_metadata"] = {
        "status": "last_verified",
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "source_generated_at": source.get("generated_at"),
        "warning": (
            "最近一次完整实测缓存，仅用于历史参考；"
            "模型重新训练后不代表当前模型结果。"
        ),
    }
    output = MODEL_DIR / WAF_CACHE_NAME
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(cached, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    return output


def compose_current_model_waf_report(
    verified_report: dict,
    evaluation: dict,
    *,
    model_manifest: dict | None = None,
    generated_at: str | None = None,
) -> dict:
    """Combine verified product outcomes with the current same-set evaluation.

    The three WAF products are independent of the learned model.  Their real
    HTTP outcomes can therefore be reused when the organized test split is
    unchanged, while every ``final_model`` metric is replaced from the current
    pipeline evaluation.  Product execution identities and original run time
    remain in the report provenance.
    """

    required_systems = {
        "final_model",
        "modsecurity_crs_4_28_0",
        "safeline_ce",
        "openappsec_ce",
    }
    systems = verified_report.get("systems")
    dataset = verified_report.get("dataset")
    if (
        not _is_complete_waf_report(verified_report)
        or not isinstance(systems, dict)
        or not required_systems.issubset(systems)
        or not isinstance(dataset, dict)
    ):
        raise ValueError("verified WAF report is incomplete")

    metrics = evaluation.get("metrics")
    latency = evaluation.get("latency_ms")
    records = evaluation.get("records")
    if (
        not isinstance(metrics, dict)
        or not isinstance(latency, dict)
        or not isinstance(records, int)
        or isinstance(records, bool)
        or records != dataset.get("total")
    ):
        raise ValueError("current evaluation does not match the WAF test scope")
    matrix = metrics.get("confusion_matrix")
    if (
        not isinstance(matrix, list)
        or len(matrix) != 2
        or any(not isinstance(row, list) or len(row) != 2 for row in matrix)
        or sum(int(value) for row in matrix for value in row) != records
    ):
        raise ValueError("current evaluation has an invalid confusion matrix")

    verified_test = (
        dataset.get("audit", {}).get("loaded", {}).get("test")
        if isinstance(dataset.get("audit"), dict)
        else None
    )
    evaluation_audit = evaluation.get("dataset_audit")
    current_test = (
        evaluation_audit.get("loaded", {}).get("test")
        if isinstance(evaluation_audit, dict)
        else None
    )
    if not isinstance(evaluation_audit, dict):
        raise ValueError("current evaluation is missing its dataset audit")
    if verified_test is not None and current_test != verified_test:
        raise ValueError("current evaluation uses a different organized test split")

    report = json.loads(json.dumps(verified_report, ensure_ascii=False))
    previous_provenance = report.get("report_provenance")
    product_generated_at = (
        previous_provenance.get("verified_product_results_generated_at")
        if isinstance(previous_provenance, dict)
        else None
    ) or report.get("generated_at")
    report.pop("cache_metadata", None)
    report.pop("cached_report", None)
    report.pop("benchmark_status", None)
    report["schema"] = "final_model_vs_real_waf_products_v5"
    report["generated_at"] = generated_at or datetime.now(timezone.utc).isoformat()
    report["dataset"]["audit"] = evaluation_audit

    final_system = report["systems"]["final_model"]
    for key in ("precision", "recall", "f1", "fpr", "confusion_matrix"):
        if key not in metrics:
            raise ValueError(f"current evaluation is missing {key}")
        final_system[key] = metrics[key]
    final_system["latency"] = {
        f"{key}_ms": latency[key]
        for key in ("mean", "p50", "p95", "p99")
        if key in latency
    }
    final_system["display_name"] = "最终 AI-WAF"
    final_system["kind"] = "live_model"
    final_system["execution"] = "in-process field detector"
    final_system["latency_scope"] = "in-process inference"

    representations = evaluation.get("representation_recall")
    form_rows = report.get("attack_form_recall")
    if not isinstance(representations, dict) or not isinstance(form_rows, dict):
        raise ValueError("current evaluation is missing representation recall")
    for name, value in representations.items():
        if name not in form_rows or not isinstance(form_rows[name], dict):
            raise ValueError(f"WAF report is missing attack form {name}")
        form_rows[name]["final_model"] = value

    type_recall = evaluation.get("type_recall")
    type_rows = report.get("attack_type_recall")
    if not isinstance(type_recall, dict) or not isinstance(type_rows, dict):
        raise ValueError("current evaluation is missing attack type recall")
    for name, value in type_recall.items():
        if name not in type_rows or not isinstance(type_rows[name], dict):
            raise ValueError(f"WAF report is missing attack type {name}")
        type_rows[name]["final_model"] = value

    final_f1 = float(final_system["f1"])
    outperformers = []
    for key in report.get("system_order", []):
        if key == "final_model" or key not in report["systems"]:
            continue
        system = report["systems"][key]
        system_f1 = float(system.get("f1", 0.0))
        if system_f1 > final_f1 + 1e-12:
            outperformers.append(
                {
                    "key": key,
                    "display_name": system.get("display_name", key),
                    "f1_delta": round(system_f1 - final_f1, 6),
                    "recall_delta": round(
                        float(system.get("recall", 0.0))
                        - float(final_system.get("recall", 0.0)),
                        6,
                    ),
                    "fpr_delta": round(
                        float(system.get("fpr", 0.0))
                        - float(final_system.get("fpr", 0.0)),
                        6,
                    ),
                }
            )
    report["comparison_interpretation"] = {
        "primary_metric": "f1",
        "products_outperforming_final": outperformers,
        "summary": (
            "存在真实 WAF 在同集 F1 上高于当前模型，结果已完整保留。"
            if outperformers
            else "当前已完成的真实 WAF 中，没有产品在同集 F1 上超过最终模型。"
        ),
    }

    manifest_files = {}
    if isinstance(model_manifest, dict):
        manifest_files = {
            item.get("path"): item.get("sha256")
            for item in model_manifest.get("files", [])
            if isinstance(item, dict)
            and item.get("path")
            in {"lgbm_v4.pkl", "text_lr_v4.pkl", "lgbm_v4.meta.json"}
        }
    report["report_provenance"] = {
        "composition": "current_model_evaluation_with_verified_product_results",
        "current_model_evaluation": "models/current/pipeline_evaluation.json",
        "verified_product_results": "models/current/waf_comparison.last_verified.json",
        "verified_product_results_generated_at": product_generated_at,
        "same_organized_test_split_verified": True,
        "model_artifact_sha256": manifest_files,
    }
    return report


def refresh_waf_report_from_verified_products() -> Path | None:
    """Write a complete current-model comparison when its inputs are valid."""

    evaluation_path = MODEL_DIR / "pipeline_evaluation.json"
    model_paths = [
        MODEL_DIR / "lgbm_v4.pkl",
        MODEL_DIR / "text_lr_v4.pkl",
        MODEL_DIR / "lgbm_v4.meta.json",
    ]
    if not evaluation_path.is_file() or any(not path.is_file() for path in model_paths):
        return None
    if evaluation_path.stat().st_mtime + 1e-6 < max(
        path.stat().st_mtime for path in model_paths
    ):
        return None
    verified = load_cached_waf_report()
    evaluation = _read_json_object(evaluation_path)
    manifest = _read_json_object(MODEL_DIR / "model_manifest_v4.json")
    try:
        report = compose_current_model_waf_report(
            verified,
            evaluation,
            model_manifest=manifest,
        )
    except (TypeError, ValueError):
        return None
    output = MODEL_DIR / WAF_REPORT_NAME
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    return output


def write_waf_status_report(status: str, reason: str) -> Path:
    """Write current status and attach the latest complete read-only cache."""

    cache_verified_waf_report()
    cached_report = load_cached_waf_report()

    display_reason = {
        "model_updated_pending": "模型已重新训练，旧WAF指标已失效，等待重新运行真实产品实验",
        "docker_unavailable": "真实产品实验环境不可用",
    }.get(status, reason)
    candidates = {
        "modsecurity_crs_4_28_0": {
            "display_name": "ModSecurity + OWASP CRS",
            "status": status,
            "configured": status != "docker_unavailable",
            "included_in_ranking": False,
            "reason": display_reason,
        },
        "safeline_ce": {
            "display_name": "SafeLine 社区版",
            "status": "not_run" if status == "docker_unavailable" else status,
            "configured": False,
            "included_in_ranking": False,
            "reason": "尚未完成当前模型对应的真实产品实验，本次不参与排名",
        },
        "openappsec_ce": {
            "display_name": "open-appsec 社区版",
            "status": "not_run" if status == "docker_unavailable" else status,
            "configured": False,
            "included_in_ranking": False,
            "reason": "尚未完成当前模型对应的真实产品实验，本次不参与排名",
        },
    }
    report = {
        "schema": "final_model_vs_real_waf_products_v4",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_status": {
            "status": status,
            "completed": False,
            "reason": display_reason,
            "technical_detail": reason,
        },
        "baseline_definition": (
            "真实WAF对比是训练、测试和验证之后的可选独立实验。"
            "本次没有完整运行真实产品，因此当前排名为空。"
        ),
        "dataset": {
            "source": "data/organized",
            "split": "test",
            "total": None,
        },
        "system_order": [],
        "systems": {},
        "attack_form_recall": {},
        "attack_type_recall": {},
        "candidate_products": candidates,
        "selection_policy": {
            "performance_based_exclusion": False,
            "policy": (
                "真实产品只有完成相同记录评测后才进入排名；"
                "效果高于当前模型不是排除理由。"
            ),
        },
        "comparison_interpretation": {
            "primary_metric": "f1",
            "products_outperforming_final": [],
            "summary": display_reason,
        },
    }
    if cached_report:
        report["cached_report"] = cached_report
    output = MODEL_DIR / WAF_REPORT_NAME
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    return output


def manifest_record_count(manifest: dict) -> int | str:
    """Return a manifest's declared record count across supported schemas.

    Dataset generators predate the unified project entrypoint, so their
    manifests intentionally use several field names.  Keep that schema
    compatibility here instead of reporting valid manifests as undeclared.
    """

    for key in ("total", "total_records", "generated_records", "records"):
        value = manifest.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value

    attack_types = manifest.get("attack_types")
    if isinstance(attack_types, dict):
        counts = []
        for info in attack_types.values():
            if not isinstance(info, dict):
                break
            value = info.get("records", info.get("count"))
            if not isinstance(value, int) or isinstance(value, bool):
                break
            counts.append(value)
        else:
            if counts:
                return sum(counts)

    counts = manifest.get("counts")
    if isinstance(counts, dict) and counts:
        values = list(counts.values())
        if all(isinstance(value, int) and not isinstance(value, bool) for value in values):
            return sum(values)

    return "未声明"


def validate_layout(require_models: bool = False) -> None:
    """检查当前独立交付真正使用的 organized 数据与模型产物。"""

    organized_root = ROOT / "data" / "organized"
    required = {
        "完整 organized 数据清单": organized_root / "manifest.json",
        "攻击分类规范": organized_root / "taxonomy.json",
        "正常流量清单": organized_root / "normal" / "manifest.json",
        "攻击流量清单": organized_root / "attack" / "manifest.json",
    }
    if require_models:
        required.update({
            "LightGBM 模型": MODEL_DIR / "lgbm_v4.pkl",
            "字符 n-gram 模型": MODEL_DIR / "text_lr_v4.pkl",
            "模型元数据": MODEL_DIR / "lgbm_v4.meta.json",
        })
    missing = [
        f"{name}: {path}" for name, path in required.items() if not path.is_file()
    ]
    if missing:
        raise SystemExit("缺少必要文件：\n  " + "\n  ".join(missing))

    try:
        organized = json.loads(
            required["完整 organized 数据清单"].read_text(encoding="utf-8")
        )
        normal = json.loads(
            required["正常流量清单"].read_text(encoding="utf-8")
        )
        attack = json.loads(
            required["攻击流量清单"].read_text(encoding="utf-8")
        )
        taxonomy = json.loads(
            required["攻击分类规范"].read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"organized 清单无法读取：{exc}") from exc

    errors: list[str] = []
    total = organized.get("total_records")
    labels = organized.get("label_counts", {})
    attack_types = organized.get("attack_type_counts", {})
    representations = organized.get("attack_representation_counts", {})
    artifacts = organized.get("artifacts", {})
    if not isinstance(total, int) or total <= 0:
        errors.append("manifest.total_records 必须是正整数")
    if not isinstance(labels, dict) or sum(
        int(value) for value in labels.values()
    ) != total:
        errors.append("label_counts 与 total_records 不一致")
    if not isinstance(attack_types, dict) or sum(
        int(value) for value in attack_types.values()
    ) != int(labels.get("attack", -1)):
        errors.append("attack_type_counts 与攻击总量不一致")
    if not isinstance(representations, dict) or sum(
        int(value) for value in representations.values()
    ) != int(labels.get("attack", -1)):
        errors.append("attack_representation_counts 与攻击总量不一致")
    if normal.get("records") != labels.get("normal"):
        errors.append("normal/manifest.json 与主清单不一致")
    if attack.get("records") != labels.get("attack"):
        errors.append("attack/manifest.json 与主清单不一致")
    if attack.get("families") != organized.get("attack_families"):
        errors.append("攻击家族数量与主清单不一致")
    if set(taxonomy) != set(attack_types):
        errors.append("taxonomy.json 未完整覆盖攻击家族")
    if not isinstance(artifacts, dict) or not artifacts:
        errors.append("manifest.artifacts 为空或格式错误")
        artifacts = {}

    organized_resolved = organized_root.resolve()
    missing_artifacts: list[str] = []
    changed_artifacts: list[str] = []
    unsafe_artifacts: list[str] = []
    for relative, metadata in artifacts.items():
        path = (organized_root / relative).resolve()
        try:
            path.relative_to(organized_resolved)
        except ValueError:
            unsafe_artifacts.append(str(relative))
            continue
        if not path.is_file():
            missing_artifacts.append(str(relative))
            continue
        expected_bytes = metadata.get("bytes") if isinstance(metadata, dict) else None
        if isinstance(expected_bytes, int) and path.stat().st_size != expected_bytes:
            changed_artifacts.append(str(relative))
    if unsafe_artifacts:
        errors.append(
            "清单含越界路径：" + ", ".join(unsafe_artifacts[:5])
        )
    if missing_artifacts:
        errors.append(
            f"缺少 organized 数据文件 {len(missing_artifacts)} 个："
            + ", ".join(missing_artifacts[:5])
        )
    if changed_artifacts:
        errors.append(
            f"organized 文件大小不符 {len(changed_artifacts)} 个："
            + ", ".join(changed_artifacts[:5])
        )

    if require_models:
        try:
            metadata = json.loads(
                required["模型元数据"].read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"模型元数据无法读取：{exc}")
        else:
            feature_order = metadata.get("feature_order", [])
            if feature_order and len(feature_order) != 38:
                errors.append("模型特征顺序不是 38 维")

    if errors:
        raise SystemExit("项目布局校验失败：\n  " + "\n  ".join(errors))

    print(json.dumps({
        "layout": "PASS",
        "dataset": "data/organized",
        "records": total,
        "normal": labels.get("normal", 0),
        "attack": labels.get("attack", 0),
        "attack_families": organized.get("attack_families", 0),
        "artifacts": len(artifacts),
        "models_required": require_models,
    }, ensure_ascii=False, indent=2))

def command_train(args: argparse.Namespace) -> None:
    validate_layout()
    command = [
        current_python(),
        str(ROOT / "training" / "train_final.py"),
        "--data-root",
        str(ROOT / "data" / "organized"),
        "--output-dir",
        str(MODEL_DIR),
        "--min-recall",
        str(args.min_recall),
        "--max-text-features",
        str(args.max_text_features),
    ]
    run_stage("训练最终融合模型", command)
    training_report = MODEL_DIR / "training_results.json"
    if not training_report.is_file():
        raise SystemExit(f"训练完成但缺少报告：{training_report}")
    write_waf_status_report(
        "model_updated_pending",
        "模型文件发生变化，旧WAF报告与当前模型不再同源",
    )
    refresh_model_manifest()

def sync_server_runtime_bundle(output: str | None = None) -> None:
    """Rebuild and validate the independently deliverable server runtime bundle."""

    command = [current_python(), str(ROOT / "deployment" / "build_runtime_bundle.py")]
    if output:
        command.extend(["--output", output])
    run_stage("同步并验证服务器交付运行包", command)


def command_test() -> None:
    validate_layout(require_models=True)
    # Training and evaluation rewrite model metadata and the manifest.  Rebuild
    # the independent server bundle before collection so delivery-consistency
    # tests always inspect the artifacts produced by this invocation.
    sync_server_runtime_bundle()
    # A fixed basetemp can remain locked by antivirus/indexing on Windows after
    # a completed run.  Use a fresh directory name so repeated dashboard clicks
    # never need to delete the previous session before tests can start.
    pytest_base = ROOT / "runtime" / "pytest_runs" / (
        f"run-{os.getpid()}-{time.time_ns()}"
    )
    pytest_base.parent.mkdir(parents=True, exist_ok=True)
    run_stage(
        "单元测试与集成测试",
        [
            current_python(),
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(pytest_base),
            "tests",
        ],
    )


def refresh_model_manifest() -> None:
    """重建并验证正式模型清单，保证报告与哈希同步。"""

    run_stage(
        "重建模型产物清单",
        [
            current_python(),
            str(ROOT / "tools" / "build_model_manifest.py"),
            "--model-dir",
            str(MODEL_DIR),
        ],
    )
    run_stage(
        "校验模型产物完整性",
        [current_python(), str(ROOT / "tools" / "verify_model_manifest.py")],
    )


def command_evaluate() -> None:
    validate_layout(require_models=True)
    report = MODEL_DIR / "pipeline_evaluation.json"
    run_stage(
        "独立 organized 测试集与性能验证",
        [
            current_python(),
            str(ROOT / "training" / "evaluate_candidate_pipeline.py"),
            "--model-dir",
            str(MODEL_DIR),
            "--data-root",
            str(ROOT / "data" / "organized"),
            "--output",
            str(report),
        ],
    )
    if not report.is_file():
        raise SystemExit(f"评测完成但缺少报告：{report}")
    refresh_waf_report_from_verified_products()
    refresh_model_manifest()


def command_compare_waf() -> None:
    """Freshly evaluate the model and all three real WAF products."""

    validate_layout(require_models=True)
    docker_available, docker_reason = docker_engine_status()
    if not docker_available:
        raise SystemExit(f"完整流程要求 Docker 引擎及三个真实 WAF 均可用：{docker_reason}")

    staging_report = ROOT / "runtime" / "waf_comparison.building.json"
    staging_report.parent.mkdir(parents=True, exist_ok=True)
    staging_report.unlink(missing_ok=True)

    try:
        run_stage(
            "真实 ModSecurity + OWASP CRS 产品对比",
            [
                current_python(),
                str(ROOT / "training" / "compare_real_waf.py"),
                "--model-dir",
                str(MODEL_DIR),
                "--data-root",
                str(ROOT / "data" / "organized"),
                "--output",
                str(staging_report),
            ],
        )
        with benchmark_proof_backend():
            run_stage(
                "启动并校验 SafeLine 社区版",
                [
                    current_python(),
                    str(ROOT / "deployment" / "waf_benchmark" / "safeline" / "start.py"),
                    "--port",
                    "18082",
                    "--management-port",
                    "19443",
                    "--upstream",
                    "http://host.docker.internal:18081",
                ],
            )
            run_stage(
                "启动并校验 open-appsec 社区版",
                [
                    current_python(),
                    str(ROOT / "deployment" / "waf_benchmark" / "openappsec" / "start.py"),
                    "--port",
                    "18083",
                ],
            )
            run_stage(
                "SafeLine / open-appsec 全量同集真实产品对比",
                [
                    current_python(),
                    str(ROOT / "training" / "compare_external_wafs.py"),
                    "--data-root",
                    str(ROOT / "data" / "organized"),
                    "--report",
                    str(staging_report),
                    "--safeline-url",
                    EXTERNAL_WAF_PRODUCTS["safeline_ce"]["url"],
                    "--safeline-version",
                    EXTERNAL_WAF_PRODUCTS["safeline_ce"]["version"],
                    "--openappsec-url",
                    EXTERNAL_WAF_PRODUCTS["openappsec_ce"]["url"],
                    "--openappsec-version",
                    EXTERNAL_WAF_PRODUCTS["openappsec_ce"]["version"],
                ],
            )
        report = require_complete_waf_report(staging_report)
        output = MODEL_DIR / WAF_REPORT_NAME
        staging_report.replace(output)
    finally:
        staging_report.unlink(missing_ok=True)

    cache_verified_waf_report(report)
    refresh_model_manifest()


def command_compare_external_waf() -> None:
    """Compatibility entry point for the mandatory four-product experiment."""

    command_compare_waf()

def command_all(args: argparse.Namespace) -> None:
    """Train, test, evaluate, and freshly benchmark all real WAF products."""
    docker_available, docker_reason = docker_engine_status()
    if not docker_available:
        raise SystemExit(
            "完整流程要求 Docker 引擎及三个真实 WAF 均可用："
            f"{docker_reason}。如只需模型实验，请分别运行 train、test 和 evaluate。"
        )
    command_train(args)
    command_test()
    command_evaluate()
    command_compare_waf()
    # Evaluation and the WAF comparison refresh the model manifest after the
    # pre-test build.  Synchronize once more so the directory left on disk is
    # immediately deployable when the full workflow exits.
    sync_server_runtime_bundle()
    print(f"\n全部阶段通过：训练、测试、独立验证及四系统真实同集实验均已完成。结果位于：{MODEL_DIR}")


def command_smoke() -> None:
    """使用随项目提供的最终模型做快速交付前检查，不重新训练。"""
    validate_layout(require_models=True)
    command_test()


def command_validate_data(args: argparse.Namespace) -> None:
    command = [current_python(), str(ROOT / "training" / "audit_data.py")]
    if args.deep:
        command.append("--deep")
    run_stage("数据目录与清单审计", command)


def command_refresh_cve_data(args: argparse.Namespace) -> None:
    command = [
        current_python(),
        str(ROOT / "data" / "modern_attack_traffic" / "build_dataset.py"),
        "--refresh",
        "--min-severity", args.min_severity,
        "--max-records", str(args.max_records),
    ]
    if args.years:
        command.extend(["--years", *[str(year) for year in args.years]])
    run_stage("刷新近期 CVE 与 CISA KEV 数据", command)
    run_stage(
        "同步统一 normal/attack 分类视图",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "审计刷新后的数据",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_generate_specialized_data() -> None:
    run_stage(
        "生成字段、API、协议、LLM 与扫描器专项数据",
        [current_python(), str(ROOT / "data" / "specialized_traffic" / "generate_specialized_dataset.py")],
    )
    run_stage(
        "同步统一 normal/attack 分类视图",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "审计专项数据",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_collect_external_data(args: argparse.Namespace) -> None:
    command = [
        current_python(),
        str(ROOT / "data" / "external_traffic" / "build_external_dataset.py"),
    ]
    if args.offline:
        command.append("--offline")
    if args.refresh:
        command.append("--refresh")
    run_stage("下载并标准化外部公开 WAF 数据", command)
    run_stage(
        "同步统一 normal/attack 分类视图",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "审计外部来源、切分与统一视图",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_collect_deserialization_data(args: argparse.Namespace) -> None:
    command = [
        current_python(),
        str(ROOT / "data" / "external_deserialization" / "build_dataset.py"),
    ]
    if args.offline:
        command.append("--offline")
    if args.refresh:
        command.append("--refresh")
    if args.regenerate_ysoserial:
        command.append("--regenerate-ysoserial")
        if not args.java_bin:
            raise SystemExit("--regenerate-ysoserial requires --java-bin")
        command.extend(["--java-bin", args.java_bin])
    if args.regenerate_marshalsec:
        command.append("--regenerate-marshalsec")
        if not args.java_bin or not args.marshalsec_jar:
            raise SystemExit(
                "--regenerate-marshalsec requires --java-bin and --marshalsec-jar"
            )
        if "--java-bin" not in command:
            command.extend(["--java-bin", args.java_bin])
        command.extend(["--marshalsec-jar", args.marshalsec_jar])
    if args.regenerate_dotnet_gadgets:
        command.append("--regenerate-dotnet-gadgets")
        if not args.mono_bin or not args.mono_config:
            raise SystemExit(
                "--regenerate-dotnet-gadgets requires --mono-bin and --mono-config"
            )
        command.extend(["--mono-bin", args.mono_bin, "--mono-config", args.mono_config])
    if args.regenerate_python_gadgets:
        command.append("--regenerate-python-gadgets")
    run_stage("构建独立 gadget 与反序列化 CVE 数据", command)
    run_stage(
        "同步统一 normal/attack 分类视图",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "审计反序列化独立性、来源与统一视图",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_organize_data() -> None:
    run_stage(
        "整理全部正常与攻击数据",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "深度审计统一整理视图",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_generate_all_obfuscations(args: argparse.Namespace) -> None:
    run_stage(
        "刷新全部原始攻击统一视图",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "为每条原始攻击生成可追溯混淆变体",
        [
            current_python(),
            str(ROOT / "data" / "all_original_obfuscated" / "build_dataset.py"),
            "--variants-per-original", str(args.variants_per_original),
            "--seed", str(args.seed),
        ],
    )
    run_stage(
        "把新增混淆变体同步到统一视图",
        [current_python(), str(ROOT / "data" / "organize_dataset.py")],
    )
    run_stage(
        "深度审计全部原始攻击混淆覆盖率",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_evaluate_scanners() -> None:
    run_stage(
        "扫描器请求序列行为评测",
        [current_python(), str(ROOT / "training" / "evaluate_scanner_sequences.py")],
    )


def command_build_coverage() -> None:
    run_stage(
        "重建漏洞覆盖矩阵",
        [current_python(), str(ROOT / "data" / "coverage" / "build_coverage_matrix.py")],
    )
    run_stage(
        "审计覆盖矩阵与数据",
        [current_python(), str(ROOT / "training" / "audit_data.py"), "--deep"],
    )


def command_serve(args: argparse.Namespace) -> None:
    validate_layout(require_models=True)
    run_stage(
        "启动演示服务",
        [
            current_python(),
            "-m",
            "uvicorn",
            "src.app:app",
            "--host",
            args.host,
            "--port",
            str(args.port),
        ],
    )



def command_ui(args: argparse.Namespace) -> None:
    """启动包含数据、训练、评测和缓存结果的本地可视化界面。"""

    validate_layout(require_models=True)
    run_stage(
        "启动本地可视化界面",
        [
            current_python(),
            "-m",
            "uvicorn",
            "src.local_app:app",
            "--host",
            args.host,
            "--port",
            str(args.port),
        ],
    )

def command_proxy(args: argparse.Namespace) -> None:
    """启动通用前置反向代理，把现有业务流量接入最终检测模型。"""

    validate_layout(require_models=True)
    command = [
        current_python(),
        "-m",
        "src.proxy",
        "--host", args.host,
        "--port", str(args.port),
        "--backend", args.backend,
        "--public-origin", args.public_origin,
        "--directory-links", args.directory_links,
        "--mode", args.mode,
        "--fail-policy", args.fail_policy,
        "--timeout", str(args.timeout),
        "--max-body-mb", str(args.max_body_mb),
    ]
    if args.log_file:
        command.extend(["--log-file", args.log_file])
    run_stage("启动服务器接入代理", command)


def command_build_runtime(args: argparse.Namespace) -> None:
    """生成可独立上传的在线检测与实时防护最小包。"""

    validate_layout(require_models=True)
    sync_server_runtime_bundle(args.output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Web 攻击检测项目统一入口")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_training_options(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--min-recall", type=float, default=0.95,
            help="验证集最低召回约束（默认保留独立门禁所需的泛化余量）",
        )
        target.add_argument(
            "--max-text-features",
            type=int,
            default=140_000,
            help="字符 TF-IDF 最大特征数；内存受限时可调低",
        )

    add_training_options(sub.add_parser("train", help="训练并保存最终模型"))
    add_training_options(sub.add_parser("all", help="一条命令完成训练、测试、验证与真实 WAF 产品对比"))
    sub.add_parser("test", help="运行单元与集成测试")
    sub.add_parser("evaluate", help="运行独立数据和延迟验证")
    sub.add_parser(
        "compare-waf",
        help="同集实测最终模型、ModSecurity、SafeLine 和 open-appsec",
    )
    sub.add_parser(
        "compare-external-waf",
        help="复用基础报告，只评测已配置的 SafeLine/open-appsec",
    )
    validate = sub.add_parser("validate-data", help="验证数据目录与清单")
    validate.add_argument("--deep", action="store_true", help="解析全部 JSON 并核对记录数")
    refresh = sub.add_parser("refresh-cve-data", help="刷新近期 CVE 模板和 CISA KEV 数据")
    refresh.add_argument("--years", type=int, nargs="+", help="CVE 年份；默认最近三年")
    refresh.add_argument(
        "--min-severity", choices=["info", "low", "medium", "high", "critical"],
        default="medium",
    )
    refresh.add_argument("--max-records", type=int, default=4000)
    sub.add_parser("generate-specialized-data", help="重建字段、API、协议、LLM 和扫描器专项数据")
    collect = sub.add_parser("collect-external-data", help="下载、标准化并审计外部公开 WAF 数据")
    collect.add_argument("--offline", action="store_true", help="只用已下载快照，不访问网络")
    collect.add_argument("--refresh", action="store_true", help="重新下载锁定的上游提交")
    collect_deser = sub.add_parser(
        "collect-deserialization-data", help="下载并构建独立 gadget chain 与反序列化 CVE 数据"
    )
    collect_deser.add_argument("--offline", action="store_true", help="只用已锁定的本地快照")
    collect_deser.add_argument("--refresh", action="store_true", help="重新下载锁定来源并校验哈希")
    collect_deser.add_argument(
        "--regenerate-ysoserial", action="store_true", help="用锁定官方 JAR 更新 ysoserial 规范快照"
    )
    collect_deser.add_argument("--java-bin", help="更新 Java 生成器规范快照时使用的 Java 路径")
    collect_deser.add_argument(
        "--regenerate-marshalsec", action="store_true",
        help="更新锁定 marshalsec 多协议 marshaller 规范快照（不运行 -t/unmarshal）",
    )
    collect_deser.add_argument(
        "--marshalsec-jar", help="从锁定源码构建的 marshalsec all-dependencies JAR",
    )
    collect_deser.add_argument(
        "--regenerate-dotnet-gadgets", action="store_true",
        help="用锁定 ysoserial.net release 更新 Mono 兼容的 .NET 规范快照",
    )
    collect_deser.add_argument("--mono-bin", help="仅更新 .NET 快照时使用的 Mono 路径")
    collect_deser.add_argument("--mono-config", help="仅更新 .NET 快照时使用的 Mono config 路径")
    collect_deser.add_argument(
        "--regenerate-python-gadgets", action="store_true",
        help="更新锁定 Python pickle/PyYAML/jsonpickle 规范快照",
    )
    sub.add_parser("organize-data", help="重建 normal/attack 按类型分类的统一数据视图")
    all_obfuscated = sub.add_parser(
        "generate-all-obfuscations",
        help="为统一视图中的每条原始攻击生成可追溯混淆变体",
    )
    all_obfuscated.add_argument(
        "--variants-per-original", type=int, default=1, help="每条原始攻击生成的变体数（1-16）"
    )
    all_obfuscated.add_argument("--seed", type=int, default=20260725, help="确定性生成 seed")
    sub.add_parser("evaluate-scanners", help="回放扫描器与正常自动化请求序列")
    sub.add_parser("audit-coverage", help="重建并审计漏洞覆盖矩阵")
    sub.add_parser("smoke", help="用预训练模型做快速回归检查")
    build_runtime = sub.add_parser("build-runtime", help="导出服务器在线检测/实时防护最小包")
    build_runtime.add_argument("--output", help="自定义输出目录")
    ui = sub.add_parser("ui", help="启动本地可视化实验界面")
    ui.add_argument("--host", default="127.0.0.1", help="界面监听地址")
    ui.add_argument("--port", default=8000, type=int, help="界面监听端口")
    serve = sub.add_parser("serve", help="启动 FastAPI 演示服务")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8000, type=int)
    proxy = sub.add_parser("proxy", help="将检测系统作为前置反向代理接入现有服务器")
    proxy.add_argument("--host", default="0.0.0.0", help="代理监听地址")
    proxy.add_argument("--port", default=8081, type=int, help="代理监听端口")
    proxy.add_argument("--backend", required=True, help="业务服务器 URL，例如 http://127.0.0.1:3000")
    proxy.add_argument(
        '--public-origin', default='',
        help='用户实际访问入口，例如 http://122.51.242.77:8081',
    )
    proxy.add_argument(
        '--directory-links', default='',
        help='需要直接补尾斜杠的目录，例如 /pwd,/apply',
    )
    proxy.add_argument("--mode", choices=["monitor", "block"], default="monitor")
    proxy.add_argument("--fail-policy", choices=["open", "closed"], default="closed")
    proxy.add_argument("--timeout", type=float, default=30.0, help="上游超时秒数")
    proxy.add_argument("--max-body-mb", type=float, default=1.0, help="最大请求体 MiB")
    proxy.add_argument("--log-file", default=str(ROOT / "runtime" / "proxy_access.jsonl"))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    actions = {
        "train": lambda: command_train(args),
        "test": command_test,
        "evaluate": command_evaluate,
        "compare-waf": command_compare_waf,
        "compare-external-waf": command_compare_external_waf,
        "all": lambda: command_all(args),
        "validate-data": lambda: command_validate_data(args),
        "refresh-cve-data": lambda: command_refresh_cve_data(args),
        "generate-specialized-data": command_generate_specialized_data,
        "collect-external-data": lambda: command_collect_external_data(args),
        "collect-deserialization-data": lambda: command_collect_deserialization_data(args),
        "organize-data": command_organize_data,
        "generate-all-obfuscations": lambda: command_generate_all_obfuscations(args),
        "evaluate-scanners": command_evaluate_scanners,
        "audit-coverage": command_build_coverage,
        "smoke": command_smoke,
        "build-runtime": lambda: command_build_runtime(args),
        "ui": lambda: command_ui(args),
        "serve": lambda: command_serve(args),
        "proxy": lambda: command_proxy(args),
    }
    actions[args.command]()


if __name__ == "__main__":
    main()
