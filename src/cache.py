"""
特征缓存 / Feature Cache

LRU 缓存，避免对同一 payload 重复执行归一化 + 特征提取。

用途：API 服务场景下，相同的 payload 可能被多次提交（正常用户重复请求、
      攻击者批量扫描），缓存命中时跳过归一化和特征提取，直接返回特征向量。
"""

from __future__ import annotations

from collections import OrderedDict
from threading import RLock
from typing import Any, Optional


class FeatureCache:
    """固定容量的 LRU 缓存，带命中率统计"""

    def __init__(self, maxsize: int = 20000):
        self.maxsize = maxsize
        self._cache: OrderedDict[Any, Any] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._lock = RLock()

    def get(self, key: Any) -> Optional[Any]:
        """获取缓存值，命中时将其移到末尾（最近使用）"""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return None

    def put(self, key: Any, value: Any):
        """存入缓存，超容时淘汰最久未使用的条目"""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self.maxsize:
                    self._cache.popitem(last=False)
                self._cache[key] = value

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """缓存命中率"""
        with self._lock:
            total = self._hits + self._misses
            return self._hits / total if total > 0 else 0.0
