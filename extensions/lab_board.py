# -*- coding: utf-8 -*-
"""分析黑板：跨 run_js 持久化的分析记忆。

父进程对象，只保存可序列化数据；方法只收发原始类型/dict，便于经 RPC 暴露。
随 EngineSession 创建/重建：换二进制即换黑板。
"""
import json
import os
import time
from uuid import uuid4

DEFAULT_LIMITS = {
    "entities": 5000,
    "artifact_max_chars": 2_000_000,
}

_KINDS = ("target", "finding", "trace", "path", "hypothesis", "patch")


class LabBoardError(RuntimeError):
    pass


class LabBoardOverflow(LabBoardError):
    pass


def cap_list(seq, limit):
    seq = list(seq or [])
    return seq[: int(limit)], len(seq) > int(limit)


class AnalysisBoard:
    def __init__(self, session_id=None, limits=None, artifact_dir="artifacts"):
        self.session_id = session_id or uuid4().hex
        self.limits = dict(DEFAULT_LIMITS)
        if limits:
            self.limits.update({k: int(v) for k, v in limits.items()})
        self.artifact_dir = artifact_dir
        self._seq = 0
        self._items = {kind: {} for kind in _KINDS}
        # SPEC 总量语义：overflow 按"全部 kind 的实体总数"判定，而非单个 kind；
        # _total 始终等于各 kind 记录数之和（_put/delete/clear/load_snapshot 共同维护）。
        self._total = 0
        self.overflow = False

    def _next_id(self, kind):
        self._seq += 1
        return f"{kind}-{self._seq:05d}"

    def _put(self, kind, item):
        if self._total >= self.limits["entities"]:
            self.overflow = True
            raise LabBoardOverflow(
                f"blackboard entity limit reached: {self.limits['entities']}")
        # 单 kind 兜底上限（总量的 10 倍）：防某个 kind 无限膨胀挤占其余 kind 的空间，
        # 正常分析流程远达不到，仅作 sanity 防线。
        if len(self._items[kind]) >= self.limits["entities"] * 10:
            self.overflow = True
            raise LabBoardOverflow(
                f"blackboard {kind} limit reached: {self.limits['entities'] * 10}")
        record = dict(item or {})
        record["id"] = record.get("id") or self._next_id(kind)
        # 保留调用方传入的语义 kind（如 finding 类型），仅在缺省时回落到实体 kind
        record.setdefault("kind", kind)
        record["created_at"] = time.time()
        record["session_id"] = self.session_id
        self._items[kind][record["id"]] = record
        self._total += 1
        return dict(record)

    def add_target(self, **fields):
        return self._put("target", fields)

    def add_finding(self, kind, ea, text, evidence=None, severity="info",
                    action=None, target_id=None):
        return self._put("finding", {"kind": str(kind), "ea": int(ea), "text": str(text),
                                     "evidence": dict(evidence or {}),
                                     "severity": str(severity), "action": action,
                                     "target_id": target_id})

    def add_trace(self, **fields):
        return self._put("trace", fields)

    def add_path(self, **fields):
        return self._put("path", fields)

    def add_hypothesis(self, **fields):
        return self._put("hypothesis", fields)

    def add_patch(self, **fields):
        return self._put("patch", fields)

    def get(self, kind, item_id):
        item = self._items.get(kind, {}).get(str(item_id))
        if item is None:
            raise LabBoardError(f"not found: {kind}/{item_id}")
        return dict(item)

    def list(self, kind, where=None, limit=200, **kw):
        # 额外关键字参数等价于 where 过滤条件
        where = dict(where or {})
        if kw:
            where.update(kw)
        out = []
        for item in self._items.get(kind, {}).values():
            if all(item.get(k) == v for k, v in where.items()):
                out.append(dict(item))
        return out[: int(limit)]

    def attach(self, kind, item_id, **fields):
        item = self._items.get(kind, {}).get(str(item_id))
        if item is None:
            raise LabBoardError(f"not found: {kind}/{item_id}")
        item.update(fields)
        return dict(item)

    def delete(self, kind, item_id):
        removed = self._items.get(kind, {}).pop(str(item_id), None)
        if removed is not None:
            self._total -= 1
            return True
        return False

    def clear(self, kind=None):
        if kind is None:
            for k in _KINDS:
                self._items[k] = {}
            self._total = 0
            self.overflow = False
            return
        self._total -= len(self._items[kind])
        self._items[kind] = {}
        # 清掉单一 kind 后 overflow 是否解除取决于剩余总量是否仍触顶
        self.overflow = self._total >= self.limits["entities"]

    def counts(self):
        return {k: len(v) for k, v in self._items.items()}

    def summary(self):
        return {"session_id": self.session_id, "counts": self.counts(),
                "overflow": self.overflow, "limits": dict(self.limits)}

    def save_snapshot(self, path):
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {"session_id": self.session_id, "saved_at": time.time(),
                   "items": {k: list(v.values()) for k, v in self._items.items()}}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        return {"ok": True, "path": path, "counts": self.counts()}

    def load_snapshot(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        self.clear()
        for kind, items in (payload.get("items") or {}).items():
            if kind not in self._items:
                continue
            for item in items:
                record = dict(item)
                if "id" not in record:
                    record["id"] = self._next_id(kind)
                self._items[kind][record["id"]] = record
        # 推进 ID 序列越过所有已加载 ID 中最大的数字后缀，防止后续 add_* 重新生成
        # 已占用的 ID 而静默覆盖已加载记录；无法解析数字后缀的 ID 不参与推进。
        for records in self._items.values():
            for item_id in records:
                suffix = str(item_id).rsplit("-", 1)[-1]
                if suffix.isdigit():
                    self._seq = max(self._seq, int(suffix))
        # 总量与 overflow 从加载后的真实记录数重建，保持 _put/delete/clear 的不变量
        self._total = sum(len(records) for records in self._items.values())
        self.overflow = self._total >= self.limits["entities"]
        return {"ok": True, "path": path, "counts": self.counts()}

    def artifact(self, name, content):
        content = str(content)
        if len(content) > self.limits["artifact_max_chars"]:
            raise LabBoardError("artifact too large")
        os.makedirs(self.artifact_dir, exist_ok=True)
        safe = "".join(c for c in str(name) if c.isalnum() or c in "._-") or "artifact"
        path = os.path.join(self.artifact_dir, f"{int(time.time())}-{safe}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return {"ok": True, "path": path, "chars": len(content)}
