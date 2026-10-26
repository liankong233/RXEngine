(function () {
  function toInt(value) {
    if (typeof value === 'string') {
      if (value.indexOf('0x') === 0 || value.indexOf('0X') === 0) return parseInt(value, 16);
      return parseInt(value, 10);
    }
    return value || 0;
  }

  function byteToHex(value) {
    var s = (value & 0xff).toString(16);
    return s.length === 1 ? '0' + s : s;
  }

  function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += byteToHex(bytes[i]);
    return out;
  }

  function hexToBytes(hex) {
    var out = [];
    hex = String(hex || '');
    for (var i = 0; i + 1 < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
    return out;
  }

  function stringToBytes(text, nul) {
    var out = [];
    text = String(text || '');
    for (var i = 0; i < text.length; i++) out.push(text.charCodeAt(i) & 0xff);
    if (nul !== false) out.push(0);
    return out;
  }

  function bytesToString(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  }

  function compareStrings(a, b, n) {
    if (n != null) {
      a = String(a).substr(0, n);
      b = String(b).substr(0, n);
    }
    if (a === b) return 0;
    return a < b ? -1 : 1;
  }

  function formatValue(value) {
    if (value == null) return 'null';
    if (typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (typeof value === 'object' && value.name) return String(value.name);
    return JSON.stringify(value);
  }

  function formatCallLog(item) {
    var args = [];
    for (var i = 0; i < (item.args || []).length; i++) args.push(formatValue(item.args[i]));
    return String(item.name || item.kind || 'stub') + '(' + args.join(', ') + ') => ' + formatValue(item.ret);
  }

  function logCommentEa(item) {
    if (item.callsiteEa != null) return item.callsiteEa;
    if (item.callsite != null) return item.callsite;
    if (item.ea != null) return item.ea;
    return item.addr;
  }

  function stageLogComments(logger, ida, opts) {
    opts = opts || {};
    var prefix = opts.prefix == null ? 'rxstubs' : String(opts.prefix);
    var repeatable = !!opts.repeatable;
    var changes = [];
    for (var i = 0; i < (logger || []).length; i++) {
      var item = logger[i] || {};
      var ea = logCommentEa(item);
      if (ea == null) continue;
      var text = item.text == null ? formatCallLog(item) : String(item.text);
      changes.push(ida.set_comment(toInt(ea), prefix ? prefix + ': ' + text : text, repeatable));
    }
    return changes;
  }

  function cloneSpec(spec) {
    var out = {};
    spec = spec || {};
    for (var k in spec) out[k] = spec[k];
    if (spec.aliases) out.aliases = spec.aliases.slice ? spec.aliases.slice() : [spec.aliases];
    return out;
  }

  class SymbolStub {
    constructor(opts) {
      opts = opts || {};
      this.name = opts.name || this.constructor.name;
      this.aliases = opts.aliases || [];
      this.argc = opts.argc == null ? null : opts.argc;
      this.kind = opts.kind || 'callback';
    }

    match(name) {
      if (name === this.name) return true;
      return this.aliases.indexOf(name) >= 0;
    }

    invoke(ctx) {
      throw new Error(this.name + '.invoke not implemented');
    }

    describe() {
      return { name: this.name, aliases: this.aliases, argc: this.argc, kind: this.kind };
    }
  }

  class StubRegistry {
    constructor(opts) {
      opts = opts || {};
      this.byName = {};
      this.byAddr = {};
      this.vtables = {};
      this.declarative = {};
      this.nextStubAddr = opts.base || 0x77000000;
      this.stubStride = opts.stride || 0x100;
    }

    registerSymbol(name, stub) {
      this.byName[String(name)] = stub;
      return stub;
    }

    registerAddress(addr, stub) {
      this.byAddr[String(toInt(addr))] = stub;
      return stub;
    }

    registerDeclarative(name, spec) {
      name = String(name);
      spec = cloneSpec(spec);
      spec.name = spec.name || name;
      spec.kind = 'declarative';
      spec.aliases = spec.aliases || [];
      this.declarative[name] = spec;
      this.byName[name] = spec;
      for (var i = 0; i < spec.aliases.length; i++) this.byName[String(spec.aliases[i])] = spec;
      return spec;
    }

    getDeclarative(name) {
      var spec = this.byName[String(name)] || null;
      return spec && spec.kind === 'declarative' ? spec : null;
    }

    listDeclarative() {
      var out = [];
      for (var name in this.declarative) out.push(this.declarative[name]);
      return out;
    }

    exportDeclarative(opts) {
      opts = opts || {};
      var specs = this.listDeclarative();
      if (opts.names) {
        var allow = {};
        for (var i = 0; i < opts.names.length; i++) allow[String(opts.names[i])] = true;
        specs = specs.filter(function (spec) { return !!allow[spec.name]; });
      }
      return specs.map(function (spec) { return cloneSpec(spec); });
    }

    allocStubAddress(stub) {
      var addr = this.nextStubAddr;
      this.nextStubAddr += this.stubStride;
      this.registerAddress(addr, stub);
      return addr;
    }

    registerVtableSlot(vtableName, offset, stub) {
      vtableName = String(vtableName);
      if (!this.vtables[vtableName]) this.vtables[vtableName] = {};
      this.vtables[vtableName][String(toInt(offset))] = stub;
      return stub;
    }

    getByAddress(addr) {
      return this.byAddr[String(toInt(addr))] || null;
    }

    getByName(name) {
      return this.byName[String(name)] || null;
    }

    describe() {
      var names = [];
      var addrs = [];
      for (var n in this.byName) names.push(n);
      for (var a in this.byAddr) addrs.push(a);
      return { symbols: names, addresses: addrs, declarative: Object.keys(this.declarative) };
    }
  }

  class AndroidPolicy {
    constructor(opts) {
      opts = opts || {};
      this.classes = opts.classes || {};
      this.systemProperties = opts.systemProperties || {};
      this.staticFields = [];
      this.jniException = false;
      this.defaultClassExists = opts.defaultClassExists == null ? true : !!opts.defaultClassExists;
    }

    classExists(name) {
      if (Object.prototype.hasOwnProperty.call(this.classes, name)) return !!this.classes[name];
      return this.defaultClassExists;
    }

    getSystemProperty(key) {
      return this.systemProperties[key] || '';
    }
  }

  class ObjectStore {
    constructor(base) {
      this.next = base || 0x71000000;
      this.objects = {};
    }

    newObject(meta) {
      var handle = this.next;
      this.next += 0x10;
      this.objects[String(handle)] = meta || {};
      return handle;
    }

    get(handle) {
      return this.objects[String(toInt(handle))] || null;
    }

    delete(handle) {
      delete this.objects[String(toInt(handle))];
    }

    dump() {
      var out = {};
      for (var k in this.objects) out['0x' + toInt(k).toString(16)] = this.objects[k];
      return out;
    }
  }

  class AArch64CC {
    constructor() {
      this.argRegs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'];
    }

    getArg(ctx, i) {
      if (i < this.argRegs.length) return ctx.readReg(this.argRegs[i]);
      var sp = ctx.readReg('sp');
      return ctx.backend.readPtr(ctx, sp + (i - this.argRegs.length) * 8, 64, 'little');
    }

    setReturn(ctx, value) {
      ctx.writeReg('x0', value || 0);
    }

    returnFromCall(ctx) {
      var lr = ctx.readReg('lr');
      ctx.writeReg('pc', lr);
    }
  }

  class QilingBackend {
    constructor(qilingFacade) {
      this.qiling = qilingFacade || require('qiling');
    }

    readReg(ctx, name) {
      return toInt(this.qiling.get_reg(ctx.ql, name));
    }

    writeReg(ctx, name, value) {
      this.qiling.set_reg(ctx.ql, name, value || 0);
    }

    readMem(ctx, addr, size) {
      return hexToBytes(this.qiling.mem_read(ctx.ql, addr, size));
    }

    writeMem(ctx, addr, data) {
      if (typeof data === 'string') this.qiling.mem_write(ctx.ql, addr, data);
      else this.qiling.mem_write(ctx.ql, addr, data);
    }

    readU8(ctx, addr) {
      var b = this.readMem(ctx, addr, 1);
      return b.length ? b[0] : 0;
    }

    readPtr(ctx, addr, bits, endian) {
      bits = bits || 64;
      endian = endian || 'little';
      if (this.qiling.read_ptr) return toInt(this.qiling.read_ptr(ctx.ql, addr, bits, endian));
      var size = bits / 8;
      var b = this.readMem(ctx, addr, size);
      var value = 0;
      if (endian === 'big') {
        for (var i = 0; i < b.length; i++) value = value * 256 + b[i];
      } else {
        for (var j = b.length - 1; j >= 0; j--) value = value * 256 + b[j];
      }
      return value;
    }

    writePtr(ctx, addr, value, bits, endian) {
      bits = bits || 64;
      endian = endian || 'little';
      if (this.qiling.write_ptr) return this.qiling.write_ptr(ctx.ql, addr, value, bits, endian);
      var size = bits / 8;
      var bytes = [];
      value = toInt(value);
      for (var i = 0; i < size; i++) {
        bytes.push(value & 0xff);
        value = Math.floor(value / 256);
      }
      if (endian === 'big') bytes.reverse();
      this.writeMem(ctx, addr, bytes);
    }

    malloc(ctx, size, tag) {
      return toInt(this.qiling.alloc(ctx.ql, size));
    }
  }

  class StubContext {
    constructor(opts) {
      opts = opts || {};
      this.backend = opts.backend;
      this.ql = opts.ql;
      this.registry = opts.registry;
      this.policy = opts.policy || new AndroidPolicy();
      this.objects = opts.objects || new ObjectStore();
      this.logger = opts.logger || [];
      this.cc = opts.cc || new AArch64CC();
    }

    arg(i) { return this.cc.getArg(this, i); }
    ret(value) { this.cc.setReturn(this, value || 0); this.cc.returnFromCall(this); }
    retVoid() { this.ret(0); }
    readReg(name) { return this.backend.readReg(this, name); }
    writeReg(name, value) { return this.backend.writeReg(this, name, value); }
    readMem(addr, size) { return this.backend.readMem(this, addr, size); }
    writeMem(addr, data) { return this.backend.writeMem(this, addr, data); }
    readU8(addr) { return this.backend.readU8(this, addr); }
    readPtr(addr, bits, endian) { return this.backend.readPtr(this, addr, bits, endian); }
    writePtr(addr, value, bits, endian) { return this.backend.writePtr(this, addr, value, bits, endian); }

    readCString(addr, maxLen) {
      maxLen = maxLen || 4096;
      var out = [];
      for (var i = 0; i < maxLen; i++) {
        var b = this.readU8(addr + i);
        if (b === 0) break;
        out.push(b);
      }
      return bytesToString(out);
    }

    writeCString(addr, text) {
      this.writeMem(addr, stringToBytes(text, true));
    }

    malloc(size, tag) { return this.backend.malloc(this, size, tag || ''); }

    logCall(name, args, ret, extra) {
      extra = extra || {};
      var item = { kind: 'call', name: name, args: args || [], ret: ret == null ? null : ret, extra: extra };
      if (this.currentEa != null) item.ea = this.currentEa;
      if (this.currentAddr != null) item.addr = this.currentAddr;
      if (this.currentCallsiteEa != null) item.callsiteEa = this.currentCallsiteEa;
      if (this.currentCallsite != null) item.callsite = this.currentCallsite;
      if (extra.ea != null) item.ea = extra.ea;
      if (extra.addr != null) item.addr = extra.addr;
      if (extra.callsiteEa != null) item.callsiteEa = extra.callsiteEa;
      if (extra.callsite != null) item.callsite = extra.callsite;
      if (extra.text != null) item.text = extra.text;
      this.logger.push(item);
    }

    withCurrentAddress(addr, fn, meta) {
      meta = meta || {};
      var oldEa = this.currentEa;
      var oldAddr = this.currentAddr;
      var oldCallsiteEa = this.currentCallsiteEa;
      var oldCallsite = this.currentCallsite;
      this.currentEa = toInt(addr);
      this.currentAddr = toInt(addr);
      this.currentCallsiteEa = meta.callsiteEa == null ? null : toInt(meta.callsiteEa);
      this.currentCallsite = meta.callsite == null ? null : toInt(meta.callsite);
      try {
        return fn();
      } finally {
        this.currentEa = oldEa;
        this.currentAddr = oldAddr;
        this.currentCallsiteEa = oldCallsiteEa;
        this.currentCallsite = oldCallsite;
      }
    }
  }

  class StrlenStub extends SymbolStub {
    constructor() { super({ name: 'strlen', argc: 1 }); }
    invoke(ctx) {
      var s = ctx.readCString(ctx.arg(0));
      ctx.logCall('strlen', [s], s.length);
      ctx.ret(s.length);
    }
  }

  class StrcmpStub extends SymbolStub {
    constructor() { super({ name: 'strcmp', argc: 2 }); }
    invoke(ctx) {
      var a = ctx.readCString(ctx.arg(0));
      var b = ctx.readCString(ctx.arg(1));
      var ret = compareStrings(a, b, null);
      ctx.logCall('strcmp', [a, b], ret);
      ctx.ret(ret);
    }
  }

  class StrncmpStub extends SymbolStub {
    constructor() { super({ name: 'strncmp', argc: 3 }); }
    invoke(ctx) {
      var a = ctx.readCString(ctx.arg(0));
      var b = ctx.readCString(ctx.arg(1));
      var n = ctx.arg(2);
      var ret = compareStrings(a, b, n);
      ctx.logCall('strncmp', [a, b, n], ret);
      ctx.ret(ret);
    }
  }

  class StrstrStub extends SymbolStub {
    constructor() { super({ name: 'strstr', argc: 2 }); }
    invoke(ctx) {
      var haystackPtr = ctx.arg(0);
      var needlePtr = ctx.arg(1);
      var haystack = ctx.readCString(haystackPtr);
      var needle = ctx.readCString(needlePtr);
      var index = haystack.indexOf(needle);
      var ret = index < 0 ? 0 : haystackPtr + index;
      ctx.logCall('strstr', [haystack, needle], ret);
      ctx.ret(ret);
    }
  }

  class StrcpyStub extends SymbolStub {
    constructor() { super({ name: 'strcpy', argc: 2 }); }
    invoke(ctx) {
      var dst = ctx.arg(0);
      var src = ctx.arg(1);
      var text = ctx.readCString(src);
      ctx.writeCString(dst, text);
      ctx.logCall('strcpy', [dst, text], dst);
      ctx.ret(dst);
    }
  }

  class StrncpyStub extends SymbolStub {
    constructor() { super({ name: 'strncpy', argc: 3 }); }
    invoke(ctx) {
      var dst = ctx.arg(0);
      var src = ctx.arg(1);
      var n = ctx.arg(2);
      var text = ctx.readCString(src, n);
      var data = stringToBytes(text.substr(0, n), false);
      while (data.length < n) data.push(0);
      ctx.writeMem(dst, data);
      ctx.logCall('strncpy', [dst, text, n], dst);
      ctx.ret(dst);
    }
  }

  class MallocStub extends SymbolStub {
    constructor() { super({ name: 'malloc', argc: 1 }); }
    invoke(ctx) {
      var size = ctx.arg(0);
      var ret = ctx.malloc(size, 'malloc');
      ctx.logCall('malloc', [size], ret);
      ctx.ret(ret);
    }
  }

  class FreeStub extends SymbolStub {
    constructor() { super({ name: 'free', argc: 1 }); }
    invoke(ctx) {
      var ptr = ctx.arg(0);
      ctx.logCall('free', [ptr], null);
      ctx.retVoid();
    }
  }

  class MemcpyStub extends SymbolStub {
    constructor() { super({ name: 'memcpy', argc: 3 }); }
    invoke(ctx) {
      var dst = ctx.arg(0), src = ctx.arg(1), size = ctx.arg(2);
      var data = ctx.readMem(src, size);
      ctx.writeMem(dst, data);
      ctx.logCall('memcpy', [dst, src, size], dst);
      ctx.ret(dst);
    }
  }

  class MemsetStub extends SymbolStub {
    constructor() { super({ name: 'memset', argc: 3 }); }
    invoke(ctx) {
      var dst = ctx.arg(0), value = ctx.arg(1) & 0xff, size = ctx.arg(2);
      var data = [];
      for (var i = 0; i < size; i++) data.push(value);
      ctx.writeMem(dst, data);
      ctx.logCall('memset', [dst, value, size], dst);
      ctx.ret(dst);
    }
  }

  class SystemPropertyGetStub extends SymbolStub {
    constructor() { super({ name: '__system_property_get', argc: 2 }); }
    invoke(ctx) {
      var key = ctx.readCString(ctx.arg(0));
      var out = ctx.arg(1);
      var value = ctx.policy.getSystemProperty(key);
      ctx.writeCString(out, value);
      ctx.logCall('__system_property_get', [key], value.length, { value: value });
      ctx.ret(value.length);
    }
  }

  class AndroidLogPrintStub extends SymbolStub {
    constructor() { super({ name: '__android_log_print', argc: 3 }); }
    invoke(ctx) {
      var prio = ctx.arg(0);
      var tag = ctx.readCString(ctx.arg(1));
      var fmt = ctx.readCString(ctx.arg(2));
      ctx.logCall('__android_log_print', [prio, tag, fmt], fmt.length, { text: '[' + tag + '] ' + fmt });
      ctx.ret(fmt.length);
    }
  }

  class JniFindClassStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.FindClass', argc: 2 }); }
    invoke(ctx) {
      var className = ctx.readCString(ctx.arg(1));
      var exists = ctx.policy.classExists(className);
      var ret = 0;
      if (exists) ret = ctx.objects.newObject({ type: 'jclass', name: className });
      else ctx.policy.jniException = true;
      ctx.logCall('JNI FindClass', [className], ret, { exists: exists });
      ctx.ret(ret);
    }
  }

  class JniGetStaticFieldIDStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetStaticFieldID', argc: 4 }); }
    invoke(ctx) {
      var clazz = ctx.arg(1);
      var name = ctx.readCString(ctx.arg(2));
      var sig = ctx.readCString(ctx.arg(3));
      var clazzMeta = ctx.objects.get(clazz);
      var fieldId = ctx.objects.newObject({ type: 'jfieldID', class: clazzMeta ? clazzMeta.name : null, field: name, sig: sig });
      ctx.logCall('JNI GetStaticFieldID', [clazzMeta, name, sig], fieldId);
      ctx.ret(fieldId);
    }
  }

  class JniGetMethodIDStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetMethodID', argc: 4 }); }
    invoke(ctx) {
      var clazzMeta = ctx.objects.get(ctx.arg(1));
      var name = ctx.readCString(ctx.arg(2));
      var sig = ctx.readCString(ctx.arg(3));
      var methodId = ctx.objects.newObject({ type: 'jmethodID', static: false, class: clazzMeta ? clazzMeta.name : null, method: name, sig: sig });
      ctx.logCall('JNI GetMethodID', [clazzMeta, name, sig], methodId);
      ctx.ret(methodId);
    }
  }

  class JniGetStaticMethodIDStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetStaticMethodID', argc: 4 }); }
    invoke(ctx) {
      var clazzMeta = ctx.objects.get(ctx.arg(1));
      var name = ctx.readCString(ctx.arg(2));
      var sig = ctx.readCString(ctx.arg(3));
      var methodId = ctx.objects.newObject({ type: 'jmethodID', static: true, class: clazzMeta ? clazzMeta.name : null, method: name, sig: sig });
      ctx.logCall('JNI GetStaticMethodID', [clazzMeta, name, sig], methodId);
      ctx.ret(methodId);
    }
  }

  class JniNewStringUTFStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.NewStringUTF', argc: 2 }); }
    invoke(ctx) {
      var text = ctx.readCString(ctx.arg(1));
      var ret = ctx.objects.newObject({ type: 'jstring', value: text, name: text });
      ctx.logCall('JNI NewStringUTF', [text], ret);
      ctx.ret(ret);
    }
  }

  class JniGetStringUTFCharsStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetStringUTFChars', argc: 3 }); }
    invoke(ctx) {
      var meta = ctx.objects.get(ctx.arg(1));
      var text = meta && meta.value != null ? String(meta.value) : '';
      var ptr = ctx.malloc(text.length + 1, 'GetStringUTFChars');
      ctx.writeCString(ptr, text);
      ctx.logCall('JNI GetStringUTFChars', [meta], ptr);
      ctx.ret(ptr);
    }
  }

  class JniReleaseStringUTFCharsStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.ReleaseStringUTFChars', argc: 3 }); }
    invoke(ctx) { ctx.logCall('JNI ReleaseStringUTFChars', [ctx.arg(1), ctx.arg(2)], null); ctx.retVoid(); }
  }

  class JniGetStringUTFLengthStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetStringUTFLength', argc: 2 }); }
    invoke(ctx) {
      var meta = ctx.objects.get(ctx.arg(1));
      var text = meta && meta.value != null ? String(meta.value) : '';
      ctx.logCall('JNI GetStringUTFLength', [meta], text.length);
      ctx.ret(text.length);
    }
  }

  class JniGetObjectClassStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetObjectClass', argc: 2 }); }
    invoke(ctx) {
      var meta = ctx.objects.get(ctx.arg(1));
      var name = meta && (meta.class || meta.name) || 'java/lang/Object';
      var ret = ctx.objects.newObject({ type: 'jclass', name: name });
      ctx.logCall('JNI GetObjectClass', [meta], ret);
      ctx.ret(ret);
    }
  }

  class JniGetStaticObjectFieldStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.GetStaticObjectField', argc: 3 }); }
    invoke(ctx) {
      var fieldMeta = ctx.objects.get(ctx.arg(2));
      var ret = 0;
      for (var i = ctx.policy.staticFields.length - 1; i >= 0; i--) {
        var item = ctx.policy.staticFields[i];
        if (!fieldMeta || (item.class === fieldMeta.class && item.field === fieldMeta.field && item.sig === fieldMeta.sig)) { ret = item.value || 0; break; }
      }
      ctx.logCall('JNI GetStaticObjectField', [fieldMeta], ret);
      ctx.ret(ret);
    }
  }

  class JniNewGlobalRefStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.NewGlobalRef', argc: 2 }); }
    invoke(ctx) { var handle = ctx.arg(1); ctx.logCall('JNI NewGlobalRef', [handle], handle); ctx.ret(handle); }
  }

  class JniDeleteGlobalRefStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.DeleteGlobalRef', argc: 2 }); }
    invoke(ctx) { ctx.logCall('JNI DeleteGlobalRef', [ctx.arg(1)], null); ctx.retVoid(); }
  }

  class JniSetStaticObjectFieldStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.SetStaticObjectField', argc: 4 }); }
    invoke(ctx) {
      var clazzMeta = ctx.objects.get(ctx.arg(1));
      var fieldMeta = ctx.objects.get(ctx.arg(2));
      var value = ctx.arg(3);
      var valueMeta = ctx.objects.get(value);
      ctx.policy.staticFields.push({
        class: fieldMeta && fieldMeta.class || clazzMeta && clazzMeta.name || null,
        field: fieldMeta && fieldMeta.field || null,
        sig: fieldMeta && fieldMeta.sig || null,
        value: value,
        valueMeta: valueMeta
      });
      ctx.logCall('JNI SetStaticObjectField', [clazzMeta, fieldMeta, valueMeta], null);
      ctx.retVoid();
    }
  }

  class JniExceptionCheckStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.ExceptionCheck', argc: 1 }); }
    invoke(ctx) { ctx.logCall('JNI ExceptionCheck', [], ctx.policy.jniException ? 1 : 0); ctx.ret(ctx.policy.jniException ? 1 : 0); }
  }

  class JniExceptionClearStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.ExceptionClear', argc: 1 }); }
    invoke(ctx) { ctx.policy.jniException = false; ctx.logCall('JNI ExceptionClear', [], null); ctx.retVoid(); }
  }

  class JniDeleteLocalRefStub extends SymbolStub {
    constructor() { super({ name: 'JNIEnv.DeleteLocalRef', argc: 2 }); }
    invoke(ctx) { var handle = ctx.arg(1); ctx.objects.delete(handle); ctx.logCall('JNI DeleteLocalRef', [handle], null); ctx.retVoid(); }
  }

  function installLibcProfile(registry) {
    registry.registerSymbol('strlen', new StrlenStub());
    registry.registerSymbol('strcmp', new StrcmpStub());
    registry.registerSymbol('strncmp', new StrncmpStub());
    registry.registerSymbol('strstr', new StrstrStub());
    registry.registerSymbol('strcpy', new StrcpyStub());
    registry.registerSymbol('strncpy', new StrncpyStub());
    registry.registerSymbol('malloc', new MallocStub());
    registry.registerSymbol('free', new FreeStub());
    registry.registerSymbol('memcpy', new MemcpyStub());
    registry.registerSymbol('memset', new MemsetStub());
    registry.registerSymbol('__system_property_get', new SystemPropertyGetStub());
    registry.registerSymbol('__android_log_print', new AndroidLogPrintStub());
    return registry;
  }

  function installLibcDeclarativeProfile(registry) {
    registry.registerDeclarative('strlen', { argc: 1, behavior: 'strlen', args: ['ptr'] });
    registry.registerDeclarative('strcmp', { argc: 2, behavior: 'strcmp', args: ['ptr', 'ptr'] });
    registry.registerDeclarative('strncmp', { argc: 3, behavior: 'strncmp', args: ['ptr', 'ptr', 'size'] });
    registry.registerDeclarative('strstr', { argc: 2, behavior: 'strstr', args: ['ptr', 'ptr'] });
    registry.registerDeclarative('strcpy', { argc: 2, behavior: 'strcpy', args: ['dst', 'src'] });
    registry.registerDeclarative('strncpy', { argc: 3, behavior: 'strncpy', args: ['dst', 'src', 'size'] });
    registry.registerDeclarative('memcpy', { argc: 3, behavior: 'memcpy', args: ['dst', 'src', 'size'], returns: 'arg0' });
    registry.registerDeclarative('memset', { argc: 3, behavior: 'memset', args: ['dst', 'value', 'size'], returns: 'arg0' });
    registry.registerDeclarative('malloc', { argc: 1, behavior: 'malloc', args: ['size'] });
    registry.registerDeclarative('free', { argc: 1, behavior: 'return_const', args: ['ptr'], value: 0 });
    registry.registerDeclarative('__system_property_get', { argc: 2, behavior: 'return_const', args: ['key', 'value'], value: 0 });
    registry.registerDeclarative('__android_log_print', { argc: 3, behavior: 'return_const', args: ['prio', 'tag', 'fmt'], value: 0 });
    return registry;
  }

  function installAndroidJniProfile(registry) {
    registry.registerSymbol('JNIEnv.FindClass', new JniFindClassStub());
    registry.registerSymbol('JNIEnv.GetMethodID', new JniGetMethodIDStub());
    registry.registerSymbol('JNIEnv.GetStaticMethodID', new JniGetStaticMethodIDStub());
    registry.registerSymbol('JNIEnv.GetStaticFieldID', new JniGetStaticFieldIDStub());
    registry.registerSymbol('JNIEnv.GetStaticObjectField', new JniGetStaticObjectFieldStub());
    registry.registerSymbol('JNIEnv.SetStaticObjectField', new JniSetStaticObjectFieldStub());
    registry.registerSymbol('JNIEnv.NewStringUTF', new JniNewStringUTFStub());
    registry.registerSymbol('JNIEnv.GetStringUTFChars', new JniGetStringUTFCharsStub());
    registry.registerSymbol('JNIEnv.ReleaseStringUTFChars', new JniReleaseStringUTFCharsStub());
    registry.registerSymbol('JNIEnv.GetStringUTFLength', new JniGetStringUTFLengthStub());
    registry.registerSymbol('JNIEnv.GetObjectClass', new JniGetObjectClassStub());
    registry.registerSymbol('JNIEnv.NewGlobalRef', new JniNewGlobalRefStub());
    registry.registerSymbol('JNIEnv.DeleteGlobalRef', new JniDeleteGlobalRefStub());
    registry.registerSymbol('JNIEnv.ExceptionCheck', new JniExceptionCheckStub());
    registry.registerSymbol('JNIEnv.ExceptionClear', new JniExceptionClearStub());
    registry.registerSymbol('JNIEnv.DeleteLocalRef', new JniDeleteLocalRefStub());
    return registry;
  }

  function installFakeJNIEnv(ctx, registry, opts) {
    opts = opts || {};
    var envPtr = ctx.malloc(opts.envSize || 0x100, 'JNIEnv*');
    var tablePtr = ctx.malloc(opts.tableSize || 0x1000, 'JNIEnv functions');
    ctx.writePtr(envPtr, tablePtr, 64, 'little');

    function install(offset, name) {
      var stub = registry.getByName(name);
      if (!stub) throw new Error('missing JNI stub: ' + name);
      var addr = registry.allocStubAddress(stub);
      ctx.writePtr(tablePtr + offset, addr, 64, 'little');
      return addr;
    }

    install(opts.findClassOffset == null ? 0x30 : opts.findClassOffset, 'JNIEnv.FindClass');
    install(opts.getMethodIDOffset == null ? 0x108 : opts.getMethodIDOffset, 'JNIEnv.GetMethodID');
    install(opts.getStaticMethodIDOffset == null ? 0x388 : opts.getStaticMethodIDOffset, 'JNIEnv.GetStaticMethodID');
    install(opts.getStaticFieldIDOffset == null ? 0x480 : opts.getStaticFieldIDOffset, 'JNIEnv.GetStaticFieldID');
    install(opts.getStaticObjectFieldOffset == null ? 0x490 : opts.getStaticObjectFieldOffset, 'JNIEnv.GetStaticObjectField');
    install(opts.setStaticObjectFieldOffset == null ? 0x4d0 : opts.setStaticObjectFieldOffset, 'JNIEnv.SetStaticObjectField');
    install(opts.newStringUTFOffset == null ? 0x538 : opts.newStringUTFOffset, 'JNIEnv.NewStringUTF');
    install(opts.getStringUTFLengthOffset == null ? 0x540 : opts.getStringUTFLengthOffset, 'JNIEnv.GetStringUTFLength');
    install(opts.getStringUTFCharsOffset == null ? 0x548 : opts.getStringUTFCharsOffset, 'JNIEnv.GetStringUTFChars');
    install(opts.releaseStringUTFCharsOffset == null ? 0x550 : opts.releaseStringUTFCharsOffset, 'JNIEnv.ReleaseStringUTFChars');
    install(opts.getObjectClassOffset == null ? 0xf8 : opts.getObjectClassOffset, 'JNIEnv.GetObjectClass');
    install(opts.newGlobalRefOffset == null ? 0xa8 : opts.newGlobalRefOffset, 'JNIEnv.NewGlobalRef');
    install(opts.deleteGlobalRefOffset == null ? 0xb0 : opts.deleteGlobalRefOffset, 'JNIEnv.DeleteGlobalRef');
    install(opts.exceptionCheckOffset == null ? 0x6e0 : opts.exceptionCheckOffset, 'JNIEnv.ExceptionCheck');
    install(opts.exceptionClearOffset == null ? 0x88 : opts.exceptionClearOffset, 'JNIEnv.ExceptionClear');
    install(opts.deleteLocalRefOffset == null ? 0xb8 : opts.deleteLocalRefOffset, 'JNIEnv.DeleteLocalRef');
    return { env: envPtr, table: tablePtr };
  }

  function inferCallsite(ctx, opts) {
    opts = opts || {};
    if (opts.callsiteEa != null) return toInt(opts.callsiteEa);
    if (opts.callsite != null) return toInt(opts.callsite);
    if (opts.inferCallsiteFromLr === false) return null;
    var lr = 0;
    try { lr = ctx.readReg('lr'); } catch (e) { return null; }
    if (!lr) return null;
    return lr - (opts.callInsnSize == null ? 4 : toInt(opts.callInsnSize));
  }

  function installStubDispatcher(ql, ctx, registry, opts) {
    opts = opts || {};
    var qiling = opts.qiling || require('qiling');
    if (qiling.hook_address && opts.useHookAddress) {
      var desc = registry.describe();
      for (var i = 0; i < desc.addresses.length; i++) {
        (function (addr) {
          qiling.hook_address(ql, addr, function () {
            var stub = registry.getByAddress(addr);
            var callsite = inferCallsite(ctx, opts);
            if (stub) ctx.withCurrentAddress(addr, function () { stub.invoke(ctx); }, { callsiteEa: callsite });
          });
        })(toInt(desc.addresses[i]));
      }
      return;
    }
    ql.hook_code(function (_ql, addr, size) {
      var stub = registry.getByAddress(addr);
      if (!stub) return;
      try {
        var callsite = inferCallsite(ctx, opts);
        ctx.withCurrentAddress(addr, function () { stub.invoke(ctx); }, { callsiteEa: callsite });
      } catch (e) {
        ctx.logger.push({ kind: 'stub_error', addr: addr, error: String(e) });
        throw e;
      }
    });
  }

  return {
    SymbolStub: SymbolStub,
    StubRegistry: StubRegistry,
    StubContext: StubContext,
    AArch64CC: AArch64CC,
    QilingBackend: QilingBackend,
    AndroidPolicy: AndroidPolicy,
    ObjectStore: ObjectStore,
    StrlenStub: StrlenStub,
    StrcmpStub: StrcmpStub,
    StrncmpStub: StrncmpStub,
    StrstrStub: StrstrStub,
    StrcpyStub: StrcpyStub,
    StrncpyStub: StrncpyStub,
    MallocStub: MallocStub,
    FreeStub: FreeStub,
    MemcpyStub: MemcpyStub,
    MemsetStub: MemsetStub,
    SystemPropertyGetStub: SystemPropertyGetStub,
    AndroidLogPrintStub: AndroidLogPrintStub,
    JniFindClassStub: JniFindClassStub,
    JniGetMethodIDStub: JniGetMethodIDStub,
    JniGetStaticMethodIDStub: JniGetStaticMethodIDStub,
    JniGetStaticFieldIDStub: JniGetStaticFieldIDStub,
    JniGetStaticObjectFieldStub: JniGetStaticObjectFieldStub,
    JniSetStaticObjectFieldStub: JniSetStaticObjectFieldStub,
    JniNewStringUTFStub: JniNewStringUTFStub,
    JniGetStringUTFCharsStub: JniGetStringUTFCharsStub,
    JniReleaseStringUTFCharsStub: JniReleaseStringUTFCharsStub,
    JniGetStringUTFLengthStub: JniGetStringUTFLengthStub,
    JniGetObjectClassStub: JniGetObjectClassStub,
    JniNewGlobalRefStub: JniNewGlobalRefStub,
    JniDeleteGlobalRefStub: JniDeleteGlobalRefStub,
    JniExceptionCheckStub: JniExceptionCheckStub,
    JniExceptionClearStub: JniExceptionClearStub,
    JniDeleteLocalRefStub: JniDeleteLocalRefStub,
    installLibcProfile: installLibcProfile,
    installLibcDeclarativeProfile: installLibcDeclarativeProfile,
    installAndroidJniProfile: installAndroidJniProfile,
    installFakeJNIEnv: installFakeJNIEnv,
    installStubDispatcher: installStubDispatcher,
    stageLogComments: stageLogComments,
    formatCallLog: formatCallLog,
    util: { toInt: toInt, hexToBytes: hexToBytes, bytesToHex: bytesToHex, stringToBytes: stringToBytes, bytesToString: bytesToString }
  };
})()