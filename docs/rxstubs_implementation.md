# rxstubs 实施说明

## 目标

让 JS 沙箱承担 stub 语义层和控制层，Python 端继续承担底层模拟引擎、IDA 写回、angr/claripy/z3 适配。

第一阶段聚焦 concrete 模拟场景：

- JS 侧提供 `SymbolStub`、`StubRegistry`、`StubContext`、调用约定、Qiling backend、Android/JNI profile。
- Python 端只补最小桥接：JS 模块加载、Qiling 内存/寄存器 helper、地址 hook helper。
- angr/z3 暂不直接 JS 化，后续通过 declarative behavior spec 交给 Python 执行。

## 当前项目实施条件

项目已具备以下基础：

- `sandbox/vm.py` 已有 `require(name)` 注入点。
- `sandbox/registry.py` 已有统一对象注册表。
- `sandbox/bridge.py` 已支持 Python 对象、JS callback、bytes、dict/list、大整数编组。
- `extensions/qiling_ext.py` 已提供 `create/create_from/run/get_reg/set_reg/mem_read/mem_write/map_mem/alloc` 等 concrete 模拟能力。
- `extensions/angr_ext.py` 已有动态 `SimProcedure` 雏形。
- `extensions/z3_ext.py` 已有 z3py 门面。
- `headless_ida_mcp_server/ida_facade.py` 已支持注释、重命名、patch 暂存和提交。

## 阶段 1：JS concrete stub framework

新增 `require('rxstubs')`，提供：

- `SymbolStub`
- `StubRegistry`
- `StubContext`
- `AArch64CC`
- `QilingBackend`
- `AndroidPolicy`
- `ObjectStore`
- `installStubDispatcher`
- `installFakeJNIEnv`
- 常用 libc/JNI stub

优先覆盖：

- `strlen`
- `strcmp`
- `memcpy`
- `memset`
- `__system_property_get`
- `JNIEnv.FindClass`
- `JNIEnv.GetStaticFieldID`
- `JNIEnv.SetStaticObjectField`
- `JNIEnv.ExceptionCheck`
- `JNIEnv.ExceptionClear`
- `JNIEnv.DeleteLocalRef`

## 阶段 2：Qiling helper 增强

在 `QilingFacade` 中补充：

- `hook_address(ql, addr, callback)`
- `read_ptr(ql, addr, bits=64, endian='little')`
- `write_ptr(ql, addr, value, bits=64, endian='little')`
- `read_cstring(ql, addr, max_len=4096)`
- `write_cstring(ql, addr, text)`
- `map_stub_region(ql, base, size, arch='arm64')`

第一阶段可以先用 `hook_code` 分发；`hook_address` 用于减少高频指令回调。

## 阶段 3：IDA 写回集成

把 `StubContext.logger`、`AndroidPolicy.staticFields`、`ObjectStore.dump()` 格式化成注释，通过 `require('ida').set_comment()` 或 `set_decompiler_comment()` 暂存写回。

## 阶段 4：angr declarative bridge

JS 侧只注册行为描述：

```js
registry.registerDeclarative('strlen', {
  behavior: 'strlen',
  argc: 1,
  maxLen: 256
});
```

Python 端用通用 `SimProcedure` 解释 behavior spec，避免 JS 直接处理 claripy AST。

## 阶段 5：z3 JSON DSL

JS 侧构造 JSON DSL，Python 端翻译到 z3py/claripy。跨语言边界只传 JSON，不传 Python AST 对象。

## 验证策略

- 新增不依赖 IDA 的 `test_rxstubs.py`。
- 先验证 JS 模块加载、registry、ObjectStore、policy、字符串 helper。
- 再验证 Qiling x86/x64/arm64 helper。
- 最后用真实 IDA 场景验证注释写回。