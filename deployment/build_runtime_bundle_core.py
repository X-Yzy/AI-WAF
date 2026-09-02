#!/usr/bin/env python3
"""导出无需完整项目即可运行的服务器最小包。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT_ROOT = ROOT / "deployment"
DEFAULT_OUTPUT = DEPLOYMENT_ROOT / "server_runtime"

RUNTIME_MODULES = (
    "__init__.py",
    "settings.py",
    "cache.py",
    "engine.py",
    "extractor.py",
    "normalizer.py",
    "parser.py",
    "pipeline.py",
    "scanner_detector.py",
    "proxy.py",
    "ops_dashboard.py",
    "runtime_api.py",
)
RUNTIME_ASSETS = ("ops_dashboard.html",)
DEPLOYMENT_SCRIPTS = ("start_monitor_proxy.cmd",)
MODEL_FILES = (
    "lgbm_v4.pkl",
    "text_lr_v4.pkl",
    "lgbm_v4.meta.json",
    "model_manifest_v4.json",
)
FORBIDDEN_PARTS = {
    "data", "training", "tests", "lab", "payload_generator", "demo",
    "dashboard.py", "obfuscator.py", "waf_profiles.py", "run.py",
    "training_results.json", "pipeline_evaluation.json", "waf_comparison.json",
}

README = """# WAD 最小服务器运行包

此目录由 `python run.py build-runtime` 自动生成，只包含在线检测 API、实时防护
代理、服务器运维控制台、最终模型和运行依赖。它不依赖原项目的数据集、训练代码、
测试、载荷生成器或本地训练后台，可以把本目录单独上传到服务器。

## Docker Compose（推荐）

服务器只需上传本目录，不需要完整项目。复制环境配置后启动在线 API 和实时防护代理：

```bash
cp .env.example .env
# 编辑 .env：至少确认 WAD_PROXY_BACKEND 和 WAD_PROXY_MODE
docker compose up -d --build
# 旧版独立 Compose 命令使用：docker-compose up -d --build
docker compose ps
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8081/_wad/health
```

运维控制台与检测 API 共用端口，默认地址 `http://127.0.0.1:8000/`。需要远程访问时，
设置 `WAD_API_BIND=0.0.0.0`、`WAD_DASHBOARD_USERNAME` 和强随机
`WAD_DASHBOARD_PASSWORD`，并在安全组中只允许管理员来源访问 API 端口。

Linux 服务器上的代理使用 host network，因此默认 backend
`http://127.0.0.1:3000` 可以保护只监听宿主回环地址的原业务。若原业务也是容器，推荐
将业务端口仅发布到宿主 `127.0.0.1`，再把 backend 指向这个宿主端口。Docker Desktop
需要先启用 host networking；未启用时请使用宿主可达地址并调整 Compose 网络模式。

只需要实时防护、不对外提供检测 API 时可执行 `docker compose up -d --build proxy`，
这样只启动一个模型进程，减少内存占用。切换阻断前先保持 `WAD_PROXY_MODE=monitor`。

运行包默认使用 Docker 官方 Python 基础镜像，并通过阿里云 PyPI、
Debian 和 Debian Security 镜像安装依赖；可在 `.env`
中用 `PYTHON_IMAGE`、`PIP_INDEX_URL`、`APT_MIRROR` 和
`APT_SECURITY_MIRROR` 覆盖。如果构建还需要 HTTP 代理，只在服务器 `.env` 中临时设置 `HTTP_PROXY` 和
`HTTPS_PROXY`；这些值被 `.dockerignore` 排除，不会复制进镜像。

## 不使用 Docker

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --index-url https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt
uvicorn src.runtime_api:app --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
```

## 接入现有业务服务器

先以 monitor 模式接入，确认误报情况后再改成 block：

```bash
python -m src.proxy --backend http://127.0.0.1:3000 \\
  --host 127.0.0.1 --port 8081 --mode monitor --fail-policy closed
curl http://127.0.0.1:8081/_wad/health
```

生产环境通常使用 Nginx/Apache 处理 TLS，再转发到 8081。访问日志默认写入
`runtime/proxy_access.jsonl`。

## 完整性验证

```bash
python verify_manifest.py
```

详细部署、监控、Docker、systemd 和回滚说明见完整项目中的
`docs/deployment/SERVER_RUNTIME.md`。
"""

VERIFY_SCRIPT = '''#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
errors = []
for item in manifest["files"]:
    path = root / item["path"]
    if not path.is_file():
        errors.append(f"missing: {item['path']}")
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item["sha256"] or path.stat().st_size != item["bytes"]:
        errors.append(f"changed: {item['path']}")
if errors:
    raise SystemExit("runtime bundle verification FAILED\\n" + "\\n".join(errors))
print(f"runtime bundle verification PASS: {len(manifest['files'])} files")
'''


def _copy_checked(source: Path, target: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"缺少运行时必要文件：{source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _manifest(stage: Path) -> dict:
    files = []
    for path in sorted(item for item in stage.rglob("*") if item.is_file()):
        relative = path.relative_to(stage).as_posix()
        files.append({
            "path": relative,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    return {
        "format": "wad-runtime-bundle-v1",
        "entrypoints": {
            "online_detection": "uvicorn src.runtime_api:app --host 127.0.0.1 --port 8000",
            "realtime_protection": "python -m src.proxy --backend http://127.0.0.1:3000 --mode monitor",
            "operations_dashboard": "http://127.0.0.1:8000/",
        },
        "file_count": len(files),
        "total_bytes": sum(item["bytes"] for item in files),
        "files": files,
        "excluded": sorted(FORBIDDEN_PARTS),
    }


def restartable_python() -> str:
    """返回能够再次创建子进程的 Python 启动器。

    Microsoft Store/Python Manager 安装的解释器可能把 ``sys.executable``
    报告为 ``pythoncore-*/python.exe``。该内部文件可以运行当前进程，却不能
    直接交给 Windows ``CreateProcess``，需要改用同级 ``bin/python.exe``
    wrapper。由统一入口启动时，``WAD_PYTHON`` 会直接传入已经解析的路径。
    """

    override = os.environ.get("WAD_PYTHON")
    if override:
        return override

    managed_wrapper = Path(sys.executable).parent.parent / "bin" / "python.exe"
    if managed_wrapper.is_file():
        return str(managed_wrapper)

    return sys.executable


def _validate(stage: Path) -> None:
    bad = []
    for path in stage.rglob("*"):
        if any(part in FORBIDDEN_PARTS for part in path.relative_to(stage).parts):
            bad.append(path.relative_to(stage).as_posix())
    if bad:
        raise RuntimeError("最小包混入本地开发文件：" + ", ".join(bad))

    python = restartable_python()
    # 保留 SystemRoot、PATH 等 Windows 创建进程和 Python Manager wrapper
    # 所需的系统环境，只覆盖隔离验证需要的变量。
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(stage),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    env.setdefault("WAD_PYTHON", python)
    check = (
        "import src.runtime_api as api; import src.proxy; "
        "assert api.pipeline.lgbm_model is not None; "
        "assert api.pipeline.text_model is not None; "
        "print('isolated runtime import PASS')"
    )
    subprocess.run(
        [python, "-c", check], cwd=stage, env=env,
        check=True, text=True,
    )


def build(output: Path) -> dict:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = output.with_name(output.name + ".building")
    backup = output.with_name(output.name + ".previous")
    shutil.rmtree(stage, ignore_errors=True)
    shutil.rmtree(backup, ignore_errors=True)
    stage.mkdir()
    try:
        for name in RUNTIME_MODULES:
            _copy_checked(ROOT / "src" / name, stage / "src" / name)
        for name in RUNTIME_ASSETS:
            _copy_checked(ROOT / "src" / name, stage / "src" / name)
        for name in DEPLOYMENT_SCRIPTS:
            _copy_checked(DEPLOYMENT_ROOT / name, stage / name)
        for name in MODEL_FILES:
            _copy_checked(ROOT / "models" / "current" / name, stage / "models" / "current" / name)
        _copy_checked(DEPLOYMENT_ROOT / "requirements-runtime.txt", stage / "requirements.txt")
        _copy_checked(DEPLOYMENT_ROOT / "runtime.env.example", stage / ".env.example")
        _copy_checked(DEPLOYMENT_ROOT / "Dockerfile.runtime", stage / "Dockerfile")
        _copy_checked(DEPLOYMENT_ROOT / "compose.bundle.yml", stage / "compose.yml")
        _copy_checked(DEPLOYMENT_ROOT / "dockerignore.runtime", stage / ".dockerignore")
        (stage / "runtime").mkdir()
        (stage / "runtime" / "README.md").write_text(
            "# Runtime output\n\nProxy JSONL logs are written here.\n", encoding="utf-8"
        )
        (stage / "README.md").write_text(README, encoding="utf-8")
        (stage / "verify_manifest.py").write_text(VERIFY_SCRIPT, encoding="utf-8")
        _validate(stage)
        manifest = _manifest(stage)
        (stage / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if output.exists():
            output.rename(backup)
        stage.rename(output)
        shutil.rmtree(backup, ignore_errors=True)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        if backup.exists() and not output.exists():
            backup.rename(output)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifest = build(args.output)
    print(json.dumps({
        "status": "PASS",
        "output": str(args.output.resolve()),
        "file_count": manifest["file_count"] + 1,
        "payload_bytes": manifest["total_bytes"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
