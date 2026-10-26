# -*- coding: utf-8 -*-
"""rxstubs JS 模块的离线验证。"""

import pytest

pytestmark = [pytest.mark.qiling, pytest.mark.slow, pytest.mark.sandbox]

from extensions import register
from sandbox import vm
from sandbox.registry import registry

_PASS = 0
_FAIL = 0


def check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  [PASS] {name}")
    else:
        _FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def result_of(out: str):
    return out.rsplit("=> ", 1)[-1]


def run(name, code, cond_fn, expect_desc=""):
    out = vm.run_js(code)
    res = result_of(out)
    print(f"[{name}]")
    print("   ", out.replace("\n", " | "))
    check(name, cond_fn(res), f"got {res} (want {expect_desc})")
    return res


def main():
    register(registry)

    run("require rxstubs",
        "var r = require('rxstubs'); '' + (typeof r.SymbolStub) + '/' + (typeof r.StubRegistry);",
        lambda r: r == "function/function", "function/function")

    run("registry symbol/address",
        "var r = require('rxstubs'); var reg = new r.StubRegistry({base: 0x77000000});"
        "var s = new r.StrlenStub(); reg.registerSymbol('strlen', s);"
        "var a = reg.allocStubAddress(s); '' + a + '/' + (reg.getByAddress(a) === s) + '/' + reg.describe().symbols[0];",
        lambda r: r == "1996488704/true/strlen", "1996488704/true/strlen")

    run("object store dump",
        "var r = require('rxstubs'); var o = new r.ObjectStore();"
        "var h = o.newObject({type:'jclass', name:'A'}); var d = o.dump();"
        "'' + h + '/' + d['0x' + h.toString(16)].name;",
        lambda r: r == "1895825408/A", "1895825408/A")

    run("android policy",
        "var r = require('rxstubs'); var p = new r.AndroidPolicy({defaultClassExists:false, classes:{A:true}, systemProperties:{k:'v'}});"
        "'' + p.classExists('A') + '/' + p.classExists('B') + '/' + p.getSystemProperty('k');",
        lambda r: r == "true/false/v", "true/false/v")

    run("qiling cstring helpers",
        "var q = require('qiling'); var r = require('rxstubs'); var ql = q.create('90');"
        "var ctx = new r.StubContext({backend: new r.QilingBackend(q), ql: ql});"
        "var a = ctx.malloc(0x100); ctx.writeCString(a, 'hello'); ctx.readCString(a);",
        lambda r: r == "hello", "hello")

    run("qiling pointer helpers",
        "var q = require('qiling'); var ql = q.create('90'); var a = q.alloc(ql, 0x100);"
        "q.write_ptr(ql, a, 0x12345678, 64, 'little'); '0x' + q.read_ptr(ql, a, 64, 'little').toString(16);",
        lambda r: r == "0x12345678", "0x12345678")

    run("fake JNIEnv FindClass direct invoke",
        "var q = require('qiling'); var r = require('rxstubs');"
        "var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry({base: 0x77000000});"
        "var policy = new r.AndroidPolicy({classes:{'java/lang/String':true}});"
        "var objects = new r.ObjectStore(); var logger = [];"
        "var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry, policy:policy, objects:objects, logger:logger});"
        "r.installAndroidJniProfile(registry);"
        "var envInfo = r.installFakeJNIEnv(ctx, registry, {findClassOffset:0x30});"
        "var name = ctx.malloc(0x100); ctx.writeCString(name, 'java/lang/String');"
        "q.set_regs(ql, {x0: envInfo.env, x1: name, lr: q.code_base(ql)});"
        "registry.getByName('JNIEnv.FindClass').invoke(ctx);"
        "var ret = q.get_reg(ql, 'x0'); var meta = objects.get(ret);"
        "'' + logger[0].name + '/' + meta.name + '/' + (q.get_reg(ql, 'pc') == q.code_base(ql));",
        lambda r: r == "JNI FindClass/java/lang/String/true", "JNI FindClass/java/lang/String/true")

    run("extended JNI string and method stubs",
        "var q = require('qiling'); var r = require('rxstubs'); var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry(); r.installAndroidJniProfile(registry); var objects = new r.ObjectStore(); var logger = [];"
        "var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry, objects:objects, logger:logger});"
        "var clazz = objects.newObject({type:'jclass', name:'A'}); var name = ctx.malloc(0x20); var sig = ctx.malloc(0x20); ctx.writeCString(name, 'foo'); ctx.writeCString(sig, '()Ljava/lang/String;');"
        "q.set_regs(ql, {x1:clazz, x2:name, x3:sig}); registry.getByName('JNIEnv.GetMethodID').invoke(ctx); var mid = q.get_reg(ql, 'x0');"
        "var text = ctx.malloc(0x20); ctx.writeCString(text, 'hello'); q.set_regs(ql, {x1:text}); registry.getByName('JNIEnv.NewStringUTF').invoke(ctx); var js = q.get_reg(ql, 'x0');"
        "q.set_regs(ql, {x1:js}); registry.getByName('JNIEnv.GetStringUTFLength').invoke(ctx); var len = q.get_reg(ql, 'x0');"
        "q.set_regs(ql, {x1:js}); registry.getByName('JNIEnv.GetStringUTFChars').invoke(ctx); var chars = q.get_reg(ql, 'x0');"
        "'' + objects.get(mid).method + '/' + objects.get(js).value + '/' + len + '/' + ctx.readCString(chars);",
        lambda r: r == "foo/hello/5/hello", "foo/hello/5/hello")

    run("JNI static object field roundtrip",
        "var q = require('qiling'); var r = require('rxstubs'); var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry(); r.installAndroidJniProfile(registry); var objects = new r.ObjectStore(); var policy = new r.AndroidPolicy();"
        "var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry, objects:objects, policy:policy});"
        "var clazz = objects.newObject({type:'jclass', name:'A'}); var name = ctx.malloc(0x20); var sig = ctx.malloc(0x20); ctx.writeCString(name, 'field'); ctx.writeCString(sig, 'Ljava/lang/Object;');"
        "q.set_regs(ql, {x1:clazz, x2:name, x3:sig}); registry.getByName('JNIEnv.GetStaticFieldID').invoke(ctx); var fid = q.get_reg(ql, 'x0');"
        "var value = objects.newObject({type:'jobject', name:'V'}); q.set_regs(ql, {x1:clazz, x2:fid, x3:value}); registry.getByName('JNIEnv.SetStaticObjectField').invoke(ctx);"
        "q.set_regs(ql, {x1:clazz, x2:fid}); registry.getByName('JNIEnv.GetStaticObjectField').invoke(ctx); '' + objects.get(q.get_reg(ql, 'x0')).name;",
        lambda r: r == "V", "V")

    run("fake JNIEnv extended slots",
        "var q = require('qiling'); var r = require('rxstubs'); var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry({base:0x77000000}); var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry});"
        "r.installAndroidJniProfile(registry); var envInfo = r.installFakeJNIEnv(ctx, registry, {getMethodIDOffset:0x108, newStringUTFOffset:0x538});"
        "var getMethodID = q.read_ptr(ql, envInfo.table + 0x108, 64, 'little'); var newStringUTF = q.read_ptr(ql, envInfo.table + 0x538, 64, 'little');"
        "'' + registry.getByAddress(getMethodID).name + '/' + registry.getByAddress(newStringUTF).name;",
        lambda r: r == "JNIEnv.GetMethodID/JNIEnv.NewStringUTF", "JNIEnv.GetMethodID/JNIEnv.NewStringUTF")

    run("dispatcher records current address",
        "var q = require('qiling'); var r = require('rxstubs');"
        "var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry({base:q.code_base(ql)}); var logger = [];"
        "var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry, logger:logger});"
        "var stub = new r.StrlenStub(); var ptr = ctx.malloc(0x100); ctx.writeCString(ptr, 'abcd');"
        "var addr = registry.allocStubAddress(stub); q.set_regs(ql, {x0:ptr, lr:q.code_base(ql)+0x40});"
        "r.installStubDispatcher(ql, ctx, registry, {qiling:q}); q.run(ql, {count:1});"
        "'' + logger[0].ea + '/' + logger[0].addr + '/' + logger[0].callsiteEa + '/' + logger[0].name;",
        lambda r: r == "18870272/18870272/18870332/strlen", "18870272/18870272/18870332/strlen")

    run("common libc profile stubs",
        "var q = require('qiling'); var r = require('rxstubs'); var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry(); r.installLibcProfile(registry); var logger = [];"
        "var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry, logger:logger});"
        "var a = ctx.malloc(0x100); var b = ctx.malloc(0x100); var c = ctx.malloc(0x100);"
        "ctx.writeCString(a, 'hello world'); ctx.writeCString(b, 'world');"
        "q.set_regs(ql, {x0:a, x1:b}); registry.getByName('strstr').invoke(ctx); var strstrRet = q.get_reg(ql, 'x0') - a;"
        "q.set_regs(ql, {x0:a, x1:b, x2:3}); registry.getByName('strncmp').invoke(ctx); var strncmpRet = q.get_reg(ql, 'x0');"
        "q.set_regs(ql, {x0:c, x1:b}); registry.getByName('strcpy').invoke(ctx); var copied = ctx.readCString(c);"
        "q.set_regs(ql, {x0:c, x1:a, x2:5}); registry.getByName('strncpy').invoke(ctx); var copiedN = ctx.readMem(c, 6);"
        "q.set_regs(ql, {x0:0x20}); registry.getByName('malloc').invoke(ctx); var mallocRet = q.get_reg(ql, 'x0') != 0;"
        "q.set_regs(ql, {x0:c}); registry.getByName('free').invoke(ctx);"
        "'' + strstrRet + '/' + strncmpRet + '/' + copied + '/' + r.util.bytesToHex(copiedN) + '/' + mallocRet + '/' + logger[logger.length-1].name;",
        lambda r: r == "6/18446744073709551615/world/68656c6c6f00/true/free", "6/18446744073709551615/world/68656c6c6f00/true/free")

    run("android log print stub",
        "var q = require('qiling'); var r = require('rxstubs'); var ql = q.create('c0035fd6', {arch:'arm64', os:'linux'});"
        "var registry = new r.StubRegistry(); r.installLibcProfile(registry); var logger = [];"
        "var ctx = new r.StubContext({backend:new r.QilingBackend(q), ql:ql, registry:registry, logger:logger});"
        "var tag = ctx.malloc(0x20); var fmt = ctx.malloc(0x40); ctx.writeCString(tag, 'RX'); ctx.writeCString(fmt, 'value=%d');"
        "q.set_regs(ql, {x0:4, x1:tag, x2:fmt}); registry.getByName('__android_log_print').invoke(ctx);"
        "'' + q.get_reg(ql, 'x0') + '/' + logger[0].name + '/' + logger[0].text;",
        lambda r: r == "8/__android_log_print/[RX] value=%d", "8/__android_log_print/[RX] value=%d")

    run("stage log comments",
        "var r = require('rxstubs'); var logger = [{name:'strlen', args:['abcd'], ret:4, ea:0x401000}];"
        "var staged = []; var ida = {set_comment:function(ea, text, repeatable){staged.push({ea:ea,text:text,repeatable:repeatable}); return staged[staged.length-1];}};"
        "var out = r.stageLogComments(logger, ida, {prefix:'rx'});"
        "'' + out.length + '/' + out[0].ea + '/' + out[0].text.replace(' => ', ' -> ') + '/' + out[0].repeatable;",
        lambda r: r == "1/4198400/rx: strlen(\"abcd\") -> 4/false", "1/4198400/rx: strlen(\"abcd\") -> 4/false")

    run("stage log comments prefers callsite",
        "var r = require('rxstubs'); var logger = [{name:'strlen', args:['abcd'], ret:4, callsiteEa:0x400800, ea:0x77000000, addr:0x77000000}];"
        "var ida = {set_comment:function(ea, text, repeatable){return {ea:ea,text:text,repeatable:repeatable};}};"
        "var out = r.stageLogComments(logger, ida, {prefix:'rx'}); '' + out[0].ea + '/' + out[0].text.replace(' => ', ' -> ');",
        lambda r: r == "4196352/rx: strlen(\"abcd\") -> 4", "4196352/rx: strlen(\"abcd\") -> 4")

    run("declarative registry export",
        "var r = require('rxstubs'); var reg = new r.StubRegistry();"
        "reg.registerDeclarative('foo', {aliases:['bar'], argc:2, behavior:'return_arg', index:1});"
        "var out = reg.exportDeclarative(); out[0].argc = 9;"
        "'' + reg.getDeclarative('bar').name + '/' + reg.getDeclarative('foo').argc + '/' + reg.listDeclarative().length + '/' + reg.describe().declarative[0];",
        lambda r: r == "foo/2/1/foo", "foo/2/1/foo")

    run("libc declarative profile",
        "var r = require('rxstubs'); var reg = new r.StubRegistry(); r.installLibcDeclarativeProfile(reg);"
        "var specs = reg.exportDeclarative({names:['memcpy', 'free']});"
        "'' + specs.length + '/' + reg.getDeclarative('memcpy').behavior + '/' + reg.getDeclarative('free').value;",
        lambda r: r == "2/memcpy/0", "2/memcpy/0")

    assert _FAIL == 0


@pytest.mark.qiling
@pytest.mark.slow
@pytest.mark.sandbox
def test_rxstubs():
    global _PASS, _FAIL
    _PASS = 0
    _FAIL = 0
    main()


if __name__ == "__main__":
    main()
