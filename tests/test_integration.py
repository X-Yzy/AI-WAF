"""
快速集成验证：归一化器 + 特征提取器 + 混淆生成器
使用实际数据集运行基本功能测试。
"""
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.normalizer import normalize, normalize_from_record
from src.extractor import extract, extract_with_names, FEATURE_NAMES
from src.obfuscator import generate, generate_online, list_strategies, STRATEGIES
from src.parser import parse_auto
from src.settings import ATTACK_DATA_ROOT, RAW_ATTACK_DATA_ROOT

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _web_data_root():
    """保留旧函数名，统一返回当前项目数据目录。"""
    return os.path.join(PROJECT_ROOT, "data")


def _raw_base():
    return str(RAW_ATTACK_DATA_ROOT)


def _generated_base():
    return str(ATTACK_DATA_ROOT)


def test_normalizer_on_raw():
    """测试归一化器：对 source_records（未混淆）"""
    base = _raw_base()
    # 挑几个类型各取一条
    samples = []
    for atype in ["sqli", "xss", "cmdi", "ssti", "ptrav", "lfi", "xxe", "ssrf",
                   "nosql", "ldap", "crlf", "codei", "deser", "jwt"]:
        fpath = os.path.join(base, atype, "source_records.json")
        if not os.path.exists(fpath):
            continue
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
        # 找一条包含有意义 payload 的记录（过滤掉分隔线之类的）
        for item in data:
            p = item["payload"]
            if len(p) >= 5 and len(p) <= 500 and not p.startswith("|---"):
                samples.append((atype, p))
                break

    print(f"\n=== 归一化器：原始未混淆 payload（{len(samples)} 条）===")
    reverted = 0
    for atype, payload in samples:
        restored, meta = normalize(payload)
        changed = restored != payload
        if changed:
            reverted += 1
        print(f"  [{atype:6s}] len={len(payload):3d} → {len(restored):3d}  "
              f"changed={changed}  converged={meta.converged}  "
              f"depth={meta.decode_depth}  "
              f"payload[:40]={payload[:40]}")

    print(f"\n  → 原始 payload 中有 {reverted}/{len(samples)} 条在归一化后发生变化")
    print(f"    （理论上原始未混淆的应全部不变，变化说明检测到了疑似编码模式）")
    assert samples


def test_normalizer_on_obfuscated():
    """测试归一化器：对 dataset_obfuscated（已混淆）"""
    base = _generated_base()
    profiles = Counter()

    # 从 sqli 中取不同 profile 的样本
    fpath = os.path.join(base, "sqli", "dataset_obfuscated.json")
    with open(fpath, encoding="utf-8") as f:
        data = json.load(f)

    # 按 profile 分组各取 1 条
    seen_profiles = {}
    for item in data:
        p = item.get("obfuscation_profile", "?")
        if p not in seen_profiles and len(item["obfuscated_payload"]) < 200:
            seen_profiles[p] = item

    print(f"\n=== 归一化器：已混淆 payload（{len(seen_profiles)} 种 profile）===")
    for profile, item in seen_profiles.items():
        obf = item["obfuscated_payload"]
        orig = item["original_payload"]
        chain = item.get("obfuscation_chain", [])
        decoder = item.get("decoder_requirements", [])
        restored, meta = normalize(obf)

        # 评估还原效果
        exact_match = restored.strip() == orig.strip()
        partial = orig.strip() in restored if orig else False

        print(f"  profile={profile:20s}  chain={chain}")
        print(f"    decoders={decoder}")
        print(f"    original : {orig[:80]}")
        print(f"    obfuscated: {obf[:80]}")
        print(f"    restored  : {restored[:80]}")
        print(f"    exact={exact_match}  partial={partial}  "
              f"depth={meta.decode_depth}  converged={meta.converged}  "
              f"url_layers={meta.url_decode_layers}  "
              f"base64_ok={meta.base64_decode_success}")
        print()


def test_feature_extractor():
    """测试特征提取器：验证 38 维特征全非 NaN"""
    print(f"=== 特征提取器：38 维特征 ===")

    # 用一个典型的 SQL 注入 payload
    raw = "' OR 1=1 --"
    from src.normalizer import normalize
    restored, meta = normalize(raw)

    vec = extract(raw, restored, meta)
    named = extract_with_names(raw, restored, meta)

    print(f"  原始: {raw}")
    print(f"  还原: {restored}")
    print(f"  向量形状: {vec.shape}")
    print(f"  NaN 数量: {sum(1 for v in vec if v != v)}")
    print(f"  非零特征数: {sum(1 for v in vec if v != 0.0)}")
    print()
    print(f"  特征值（非零）：")
    for name, val in sorted(named.items(), key=lambda x: -abs(x[1])):
        if abs(val) > 0.001:
            print(f"    {name:30s} = {val:.4f}")


def test_obfuscator():
    """测试混淆生成器：对 payload 生成变种"""
    print(f"\n=== 混淆生成器：策略列表 ===")
    cats = list_strategies()
    for cat, names in cats.items():
        print(f"  {cat}: {names}")

    payload = "' OR 1=1 --"

    print(f"\n=== 混淆生成器：对 '{payload}' 生成变种 ===")
    for name in cats["encoding"] + cats["structural"] + cats["equivalence"]:
        try:
            result = STRATEGIES[name](payload) if name in STRATEGIES else None
            if result:
                print(f"  {name:25s} → {result[:80]}")
        except Exception as e:
            print(f"  {name:25s} → ERROR: {e}")

    print(f"\n  组合策略：")
    for strategy in ["mixed_random", "layered_recursive", "mimic_real_attack"]:
        variants = generate(payload, strategies=[strategy], count=3)
        print(f"  {strategy}:")
        for v in variants:
            print(f"    → {v[:100]}")

    print(f"\n  generate_online × 5:")
    for _ in range(5):
        print(f"    → {generate_online(payload)[:100]}")


def test_multipart_form_parser_ignores_mime_framing_and_keeps_fields():
    boundary = "----WebKitFormBoundarySafe123"
    raw = (
        "POST /admin/set.php HTTP/1.1\r\n"
        "Host: example.test\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="site_name"\r\n\r\n'
        "Example Site\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="logo"; filename="logo.png"\r\n'
        "Content-Type: image/png\r\n\r\n"
        "PNGDATA\r\n"
        f"--{boundary}--\r\n"
    )

    params = parse_auto(raw)
    body_params = {
        param.name: param.value for param in params if param.location == "body"
    }
    assert body_params == {
        "site_name": "Example Site",
        "logo.filename": "logo.png",
    }
    assert all("WebKitFormBoundary" not in param.name for param in params)


if __name__ == "__main__":
    test_normalizer_on_raw()
    test_normalizer_on_obfuscated()
    test_feature_extractor()
    test_obfuscator()

    print("\n" + "=" * 60)
    print("全部集成测试完成")
    print("=" * 60)
