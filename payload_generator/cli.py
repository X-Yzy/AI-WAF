"""恶意载荷混淆生成器命令行入口。

该工具只变换用户显式提供的字符串，不发起网络请求，也不执行生成结果。
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.obfuscator import generate, list_strategies


def main() -> None:
    parser = argparse.ArgumentParser(description="生成攻击载荷的混淆测试变种")
    parser.add_argument("payload", nargs="?", help="需要变换的原始载荷")
    parser.add_argument("--strategy", action="append", default=[], help="策略名，可重复指定")
    parser.add_argument("--count", type=int, default=5, help="生成数量")
    parser.add_argument("--max-layers", type=int, default=3, help="每条变种的最大叠加层数")
    parser.add_argument("--seed", type=int, default=42, help="随机种子，保证结果可复现")
    parser.add_argument("--list", action="store_true", help="列出全部可用策略")
    args = parser.parse_args()

    if args.list:
        print(json.dumps(list_strategies(), ensure_ascii=False, indent=2))
        return
    if not args.payload:
        parser.error("请提供 payload，或使用 --list 查看策略")
    if args.count < 1 or args.max_layers < 1:
        parser.error("--count 和 --max-layers 必须大于 0")

    random.seed(args.seed)
    variants = generate(args.payload, args.strategy, args.count, args.max_layers)
    print(json.dumps({"input": args.payload, "variants": variants}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
