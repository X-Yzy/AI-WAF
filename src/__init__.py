"""Web 攻击检测包的轻量公共接口。

采用惰性导入，避免仅使用解析器或载荷生成器时就加载 NumPy、LightGBM、PyTorch
等较重依赖。首次访问相应符号时才导入其实现模块。
"""

from __future__ import annotations

from importlib import import_module


__version__ = "0.4.0"

_EXPORTS = {
    "normalize": (".normalizer", "normalize"),
    "normalize_from_record": (".normalizer", "normalize_from_record"),
    "ConfusionMeta": (".normalizer", "ConfusionMeta"),
    "extract": (".extractor", "extract"),
    "extract_with_names": (".extractor", "extract_with_names"),
    "FEATURE_NAMES": (".extractor", "FEATURE_NAMES"),
    "generate": (".obfuscator", "generate"),
    "generate_online": (".obfuscator", "generate_online"),
    "list_strategies": (".obfuscator", "list_strategies"),
    "RuleEngine": (".engine", "RuleEngine"),
    "Rule": (".engine", "Rule"),
    "RuleSet": (".engine", "RuleSet"),
    "DetectionPipeline": (".pipeline", "DetectionPipeline"),
    "DetectionResult": (".pipeline", "DetectionResult"),
    "FeatureCache": (".cache", "FeatureCache"),
    "PROJECT_ROOT": (".settings", "PROJECT_ROOT"),
    "DATA_ROOT": (".settings", "DATA_ROOT"),
    "MODEL_ROOT": (".settings", "MODEL_ROOT"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    """按需解析公共符号，并缓存到模块全局命名空间。"""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = _EXPORTS[name]
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value

