"""项目路径与运行时配置。

所有路径都以 ``result`` 项目根目录为基准，因此命令可从任意工作目录执行。
环境变量仅用于部署时覆盖默认位置，不参与训练标签或检测逻辑。
"""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(os.environ.get("WAD_DATA_ROOT", PROJECT_ROOT / "data")).resolve()
MODEL_ROOT = Path(os.environ.get("WAD_MODEL_ROOT", PROJECT_ROOT / "models" / "current")).resolve()
RUNTIME_ROOT = Path(os.environ.get("WAD_RUNTIME_ROOT", PROJECT_ROOT / "runtime")).resolve()

NORMAL_DATA_ROOT = DATA_ROOT / "normal_traffic" / "generated"
ATTACK_DATA_ROOT = DATA_ROOT / "attack_traffic"
RAW_ATTACK_DATA_ROOT = DATA_ROOT / "raw_attack_traffic"
MODERN_ATTACK_DATA_ROOT = DATA_ROOT / "modern_attack_traffic" / "generated"
SPECIALIZED_DATA_ROOT = DATA_ROOT / "specialized_traffic" / "generated"
LAB_CAPTURE_DATA_ROOT = DATA_ROOT / "lab_captures" / "generated"
EXTERNAL_TRAFFIC_DATA_ROOT = DATA_ROOT / "external_traffic" / "generated"
EXTERNAL_DESERIALIZATION_DATA_ROOT = DATA_ROOT / "external_deserialization" / "generated"
ORGANIZED_DATA_ROOT = DATA_ROOT / "organized"
AUGMENTED_DATA_ROOT = DATA_ROOT / "augmented"
VALIDATION_DATA_ROOT = DATA_ROOT / "validation"
DEMO_ROOT = PROJECT_ROOT / "demo"


def ensure_runtime_dirs() -> None:
    """创建仅在运行时写入的目录；导入模块本身不产生文件。"""
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
