'use strict'

const binding = require('./binding.js')

const _moduleCache = new Map()
const _instanceCache = new Map()

// Parse a WASM binary and return a Set of export names whose return type
// includes externref (0x6f).  These exports return JS objects via the extMap
// slot index, so the export wrapper must look up the real value after calling.
// Parse WASM binary and return info about externref-returning functions.
// Returns { returnExports: Set<name>, returnImportKeys: Set<"mod.fn"> }
function _wasmExternrefInfo (data) {
  function leb (pos) {
    let r = 0, s = 0
    while (true) {
      const b = data[pos++]
      r |= (b & 0x7f) << s; s += 7
      if (!(b & 0x80)) return { v: r, p: pos }
    }
  }

  const sections = {}
  let p = 8
  while (p < data.length) {
    const id = data[p++]
    const sl = leb(p); p = sl.p
    if (!(id in sections)) sections[id] = { s: p, e: p + sl.v }
    p += sl.v
  }

  const empty = { returnExports: new Set(), returnImportKeys: new Set(), importParamInfo: new Map(), importTotalParams: new Map(), extrefInitSlots: 4 }
  if (!sections[1] || !sections[2] || !sections[3] || !sections[7]) return empty

  // Type section: record return-externref flag AND which param positions are externref
  p = sections[1].s
  let r = leb(p); p = r.p
  const typeHasExtRefRet = []
  const typeExtRefParams = []  // per-type: array of param indices typed as externref
  const typeParamCounts = []   // per-type: total param count
  for (let i = 0; i < r.v; i++) {
    p++  // 0x60 func marker
    const np = leb(p); p = np.p
    const extParams = []
    for (let j = 0; j < np.v; j++) { if (data[p++] === 0x6f) extParams.push(j) }
    typeExtRefParams.push(extParams)
    typeParamCounts.push(np.v)
    const nr = leb(p); p = nr.p
    let hasExt = false
    for (let j = 0; j < nr.v; j++) { if (data[p++] === 0x6f) hasExt = true }
    typeHasExtRefRet.push(hasExt)
  }

  // Import section: collect externref-returning import keys and param info per import
  p = sections[2].s
  r = leb(p); p = r.p
  const dec = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null
  const returnImportKeys = new Set()
  const importParamInfo = new Map()  // import key → array of externref param positions
  const importTotalParams = new Map()  // import key → total param count
  let numImports = 0
  for (let i = 0; i < r.v; i++) {
    let s2 = leb(p); p = s2.p
    const mod = dec ? dec.decode(data.subarray(p, p + s2.v)) : data.slice(p, p + s2.v).toString('utf8')
    p += s2.v
    s2 = leb(p); p = s2.p
    const fn = dec ? dec.decode(data.subarray(p, p + s2.v)) : data.slice(p, p + s2.v).toString('utf8')
    p += s2.v
    const kind = data[p++]
    if (kind === 0) {
      s2 = leb(p); p = s2.p
      if (typeHasExtRefRet[s2.v]) returnImportKeys.add(mod + '.' + fn)
      importParamInfo.set(mod + '.' + fn, typeExtRefParams[s2.v] || [])
      importTotalParams.set(mod + '.' + fn, typeParamCounts[s2.v] || 0)
      numImports++
    } else if (kind === 1) {
      p++  // elem type
      s2 = leb(p); p = s2.p; const fl = s2.v
      s2 = leb(p); p = s2.p  // min
      if (fl & 1) { s2 = leb(p); p = s2.p }  // max
    } else if (kind === 2) {
      s2 = leb(p); p = s2.p; const fl = s2.v
      s2 = leb(p); p = s2.p  // min
      if (fl & 1) { s2 = leb(p); p = s2.p }  // max
    } else if (kind === 3) {
      p += 2  // valtype + mutability
      while (data[p] !== 0x0b) p++; p++  // init expr
    }
  }

  // Function section: type index for each internal function
  p = sections[3].s
  r = leb(p); p = r.p
  const funcTypes = []
  for (let i = 0; i < r.v; i++) { const ft = leb(p); p = ft.p; funcTypes.push(ft.v) }

  // Export section: collect names of externref-returning exports and locate
  // __wbindgen_init_externref_table so we can parse its body below.
  p = sections[7].s
  r = leb(p); p = r.p
  const returnExports = new Set()
  let initExtrefTableFuncIdx = -1
  for (let i = 0; i < r.v; i++) {
    const nl = leb(p); p = nl.p
    const nm = dec ? dec.decode(data.subarray(p, p + nl.v)) : data.slice(p, p + nl.v).toString('utf8')
    p += nl.v
    const kind = data[p++]
    const idx = leb(p); p = idx.p
    if (kind === 0) {
      if (nm === '__wbindgen_init_externref_table') initExtrefTableFuncIdx = idx.v - numImports
      const ci = idx.v - numImports
      if (ci >= 0 && ci < funcTypes.length) {
        const ti = funcTypes[ci]
        if (ti < typeHasExtRefRet.length && typeHasExtRefRet[ti]) returnExports.add(nm)
      }
    }
  }

  // Code section (10): scan __wbindgen_init_externref_table's body for i32.const
  // opcodes to find the highest slot index it sets — _extNextIdx starts just above it.
  // Handles opcodes expected in this simple function; falls back to 4 if not found.
  let extrefInitSlots = 4
  if (initExtrefTableFuncIdx >= 0 && sections[10]) {
    p = sections[10].s
    const nc = leb(p); p = nc.p
    for (let i = 0; i < nc.v; i++) {
      const bs = leb(p); p = bs.p
      const bodyEnd = p + bs.v
      if (i === initExtrefTableFuncIdx) {
        const nloc = leb(p); p = nloc.p
        for (let j = 0; j < nloc.v; j++) { const cnt = leb(p); p = cnt.p; p++ }
        let maxIdx = -1
        while (p < bodyEnd) {
          const op = data[p++]
          if (op === 0x41) { const v = leb(p); p = v.p; if (v.v > maxIdx) maxIdx = v.v }
          else if (op === 0x26) { const ti = leb(p); p = ti.p }  // table.set: skip table idx
          else if (op === 0xd0) { p++ }  // ref.null: skip heap type byte
          else if (op === 0xfb) { const sub = leb(p); p = sub.p }  // GC prefix: skip subopcode
          else if (op === 0x0b) { break }  // end
        }
        if (maxIdx >= 0) extrefInitSlots = maxIdx + 1
        break
      }
      p = bodyEnd
    }
  }

  return { returnExports, returnImportKeys, importParamInfo, importTotalParams, extrefInitSlots }
}

function _fingerprint(buf) {
  return buf.length + ':' + buf.slice(0, 64).toString('hex')
}

class Module {
  constructor (bytes) {
    let buf
    if (bytes instanceof ArrayBuffer) {
      buf = Buffer.from(bytes)
    } else if (ArrayBuffer.isView(bytes)) {
      buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    } else {
      buf = bytes
    }

    const key = _fingerprint(buf)
    console.log('[wasm3] Module len=' + buf.length + ' key=' + key.slice(0, 20) + ((_moduleCache.has(key)) ? ' CACHED' : ' MISS'))
    
    if (_moduleCache.has(key)) {
      const entry = _moduleCache.get(key)
      this._handle = entry.handle
      this._wasm3ExternrefInfo = entry.externrefInfo
      this._key = key
      return
    }

    // Parse externref type info once per unique module.
    this._wasm3ExternrefInfo = _wasmExternrefInfo(buf)

    const ab = (buf.byteOffset === 0 && buf.byteLength === buf.buffer.byteLength)
      ? buf.buffer
      : buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)

    console.log('[wasm3] moduleNew start')
    this._handle = binding.moduleNew(ab)
    console.log('[wasm3] moduleNew done')
    this._key = key
    _moduleCache.set(key, { handle: this._handle, externrefInfo: this._wasm3ExternrefInfo })
  }
}

class Instance {
  constructor (wasmModule, imports, options) {
    const key = wasmModule._key
    const ioNudge = options?.ioNudge

    if (key && _instanceCache.has(key)) {
      console.log('[wasm3] Instance CACHED key=' + (key || '').slice(0, 20))
      const cachedExports = _instanceCache.get(key).exports
      this.exports = { ...cachedExports, __wbindgen_start: () => {} }
      return
    }

    // ── Externref polyfill state ─────────────────────────────────────────────
    // Declared early so both import wrappers and export wrappers share the same
    // store.  wasm-bindgen with --reference-types passes JS values as native
    // externref; wasm3 maps externref→i32, so we maintain a JS-side Map keyed
    // by i32 index.
    //
    // Direction 1 (JS→WASM arg): a non-numeric export arg is stored here;
    //   the i32 index is forwarded to wasm3 instead of the raw JS object.
    // Direction 2 (WASM→JS import arg): an i32 import arg that exists in the
    //   map is replaced with the stored JS object before calling the import fn.
    const _extMap = new Map()
    const _registry = new FinalizationRegistry((idx) => {
      _extMap.delete(idx)
      // If we need to inform the native side, we could call binding.extvalFree(_instHandle, idx)
    })
    
    let _extNextIdx = wasmModule._wasm3ExternrefInfo.extrefInitSlots
    // Dedicated non-zero sentinel for undefined export args.  Not stored in _extMap
    // so _resolveExtref returns the integer, but wasm3's local.get bug corrupts it
    // to 0 → _extMap.get(0) = undefined (set by __wbindgen_init_externref_table). ✓
    const _extUndefinedSlot = _extNextIdx++
    let _traceAllImports = false  // activated after queueMicrotask fires to trace closure body
    let _inCallExport = 0
    const _pendingMicrotasks = []
    let _instHandle = null  // set after instanceNew; used by _resolveExtref
    let _prevMemBuf = null  // previous buffer returned by binding.getMemory

    // Resolve a wasm3 externref slot to the actual JS value.
    // First tries _extMap (JS-allocated slots), then falls back to
    // ext_vals (WASM table.set slots) via binding.extvalGet — one level
    // of indirection for slots allocated by __externref_table_alloc.
    function _resolveExtref (slot) {
      if (_extMap.has(slot)) return _extMap.get(slot)
      if (_instHandle !== null) {
        const inner = binding.extvalGet(_instHandle, slot)
        if (inner > 0 && _extMap.has(inner)) return _extMap.get(inner)
      }
      return slot
    }

    let _isFlushing = false
    function _flushPendingMicrotasks() {
      if (_pendingMicrotasks.length === 0 || _isFlushing) return
      _isFlushing = true
      try {
        console.log('[wasm3] flushing ' + _pendingMicrotasks.length + ' deferred microtask(s)')
        while (_pendingMicrotasks.length > 0) {
          const cb = _pendingMicrotasks.shift()
          try { cb() } catch (e) { console.log('[wasm3] microtask error: ' + e) }
        }
      } finally {
        _isFlushing = false
      }
    }

    // ── Import wrapping ──────────────────────────────────────────────────────
    // Set of "mod.fn" keys whose WASM return type is externref.  For these,
    // ALL return values (strings, numbers, booleans, objects…) must be stored
    // in _extMap and the slot index returned to wasm3, because wasm3 will use
    // the returned i32 as an externref handle for subsequent calls.
    const _extRefRetImportKeys = (wasmModule._wasm3ExternrefInfo || {}).returnImportKeys || new Set()
    // Map of "mod.fn" → number[] of param positions typed as externref.
    // Used to resolve ONLY those positions through _extMap, leaving genuine i32
    // params untouched even when their value collides with an extMap slot index.
    const _extRefParamInfo = (wasmModule._wasm3ExternrefInfo || {}).importParamInfo || new Map()
    const _importTotalParams = (wasmModule._wasm3ExternrefInfo || {}).importTotalParams || new Map()

    const _importCounts = {}
    const _wrappedImports = {}
    for (const [mod, fns] of Object.entries(imports || {})) {
      _wrappedImports[mod] = {}
      for (const [fn, f] of Object.entries(fns)) {
        if (typeof f !== 'function') { _wrappedImports[mod][fn] = f; continue }
        const k = mod + '.' + fn
        _importCounts[k] = 0
        const _fnBase = fn.replace(/_[0-9a-f]{16}$/, '')
        const _fnNparams = _importTotalParams.get(k) || 0
        const _isVerbose = _fnBase === '__wbg___wbindgen_is_undefined' ||
          (_fnBase === '__wbg_queueMicrotask' && _fnNparams === 2) ||
          _fnBase.startsWith('__wbg_static_accessor_')
        _wrappedImports[mod][fn] = (...args) => {
          const n = ++_importCounts[k]
          if (n === 1 || _traceAllImports) console.log('[wasm3] import ' + k + ' n=' + n + (_traceAllImports ? ' rawArgs=' + JSON.stringify(args) : ''))
          if (_isVerbose) console.log('[wasm3-v] ' + fn + ' rawArgs=' + JSON.stringify(args) + ' extMap[' + args[0] + ']=' + String(_extMap.get(args[0])) + ' _extNextIdx=' + _extNextIdx)
          // Refresh WASM memory buffer before every import call so that
          // memory.grow ops that occurred inside WASM (before calling back
          // into JS) invalidate the stale cached DataView/Uint8Array.
          if (_instHandle !== null) {
            const _mb = binding.getMemory(_instHandle)
            if (_mb.byteLength !== _prevMemBuf?.byteLength) {
              console.log('[wasm3] mem@import grow detected: ' + (_prevMemBuf ? _prevMemBuf.byteLength : 0) + ' -> ' + _mb.byteLength)
              _prevMemBuf = _mb
            }
          }
          let resolvedArgs = args  // hoisted so catch block can log it
          try {
            // Resolve externref args: only resolve params at positions the WASM
            // type declares as externref.  Genuine i32 params are left untouched
            // even if their value collides with an occupied _extMap slot.
            const _extrefPositions = _extRefParamInfo.get(k)
            resolvedArgs = _extrefPositions
              ? args.map((a, i) => _extrefPositions.includes(i) ? _resolveExtref(a) : a)
              : args.map(a => typeof a === 'number' ? _resolveExtref(a) : a)
            // Log any import that gets arg=0 — likely the wasm3 local.get bug.
            if (!_isVerbose && args.some(a => a === 0)) {
              console.log('[wasm3-bug] ' + fn + ' n=' + n + ' rawArgs=' + JSON.stringify(args))
            }
            if (_isVerbose) console.log('[wasm3-v] ' + fn + ' resolved[0]=' + typeof resolvedArgs[0] + ':' + String(resolvedArgs[0]))
            // wasm3 externref propagation bug: local.get after ref.is_null (i32.eqz)
            // returns 0 instead of the saved slot index.  When the SELF/WINDOW/GLOBAL
            // accessor family receives undefined as arg0, fall back to globalThis so
            // queueMicrotask and similar property lookups still work.
            if (resolvedArgs[0] === undefined || resolvedArgs[0] === null) {
              if (_fnBase === '__wbg_queueMicrotask') {
                // arg0 is corrupted (wasm3 local.get bug) regardless of how many args
                // wasm3 actually passed — fall back to globalThis.queueMicrotask so
                // the import doesn't throw "Cannot read properties of undefined".
                const qm = globalThis.queueMicrotask
                console.log('[wasm3] queueMicrotask fallback to globalThis, type=' + typeof qm)
                if (typeof qm === 'function') {
                  const idx = _extNextIdx++
                  _extMap.set(idx, qm)
                  if (qm && (typeof qm === 'object' || typeof qm === 'function')) _registry.register(qm, idx)
                  return idx
                }
                return 0
              }
              if (_fnBase === '__wbg___wbindgen_is_undefined') {
                // wasm3 bug gave us slot 0, but the real externref was a valid
                // JS object (e.g. self/window).  Return 0 (false = NOT undefined)
                // so WASM stays on the "object is valid" code path.  Our
                // property-getter fallbacks handle the corrupted slot separately.
                return 0
              }
            }
            // Intercept queueMicrotask(cb) — wrap the callback (last arg, whether
            // this is the 1-param global form or 2-param self.queueMicrotask form)
            // to activate trace mode so all imports inside the closure are logged.
            if (_fnBase === '__wbg_queueMicrotask') {
              const rawCbIdx = args[args.length - 1]
              const rawCb = resolvedArgs[resolvedArgs.length - 1]
              console.log('[wasm3] queueMicrotask intercept: cbIdx=' + rawCbIdx + ' typeof cb=' + typeof rawCb + ' inCallExport=' + _inCallExport)
              if (_inCallExport > 0 && typeof rawCb === 'function') {
                console.log('[wasm3] queueMicrotask DEFERRED (depth=' + _inCallExport + ')')
                const deferredCb = (...a) => {
                  console.log('[wasm3] deferred microtask fired — enabling trace')
                  _traceAllImports = true
                  try { return rawCb(...a) }
                  finally { _traceAllImports = false; console.log('[wasm3] deferred microtask done — trace off') }
                }
                _pendingMicrotasks.push(deferredCb)
                return undefined
              }
              const wrappedCb = typeof rawCb === 'function'
                ? (...cbArgs) => {
                    console.log('[wasm3] queueMicrotask fired — enabling trace')
                    _traceAllImports = true
                    try { return rawCb(...cbArgs) }
                    finally { _traceAllImports = false; console.log('[wasm3] queueMicrotask done — trace off') }
                  }
                : rawCb
              const wrappedIdx = _extNextIdx++
              _extMap.set(wrappedIdx, wrappedCb)
              if (wrappedCb && (typeof wrappedCb === 'object' || typeof wrappedCb === 'function')) _registry.register(wrappedCb, wrappedIdx)
              // Replace last arg (the callback) with the wrapped version; keep any
              // leading args (e.g. the self object for the 2-param variant) intact.
              const actualResolvedArgs = [...resolvedArgs.slice(0, -1), wrappedCb]
              let ret = f(...actualResolvedArgs)
              if (_extRefRetImportKeys.has(k)) {
                if (ret === null || ret === undefined) return 0
                if (typeof ret === 'number' && _extMap.has(ret)) return ret
                const idx = _extNextIdx++; _extMap.set(idx, ret); if (ret && (typeof ret === 'object' || typeof ret === 'function')) _registry.register(ret, idx); return idx
              }
              if (typeof ret === 'boolean') return ret ? 1 : 0
              if (ret !== null && ret !== undefined && (typeof ret === 'object' || typeof ret === 'function' || typeof ret === 'symbol')) {
                const idx = _extNextIdx++; _extMap.set(idx, ret); if (ret && (typeof ret === 'object' || typeof ret === 'function')) _registry.register(ret, idx); return idx
              }
              return ret
            }
            // __wbg_call_* is used by wasm-bindgen to invoke JS callbacks from
            // inside a WASM execution. wasm-bindgen closures (makeMutClosure AND
            // Closure::once) call back into WASM via their invoke export, causing a
            // nested m3_CallV from runtime->stack base that corrupts the parent
            // frame. They must be deferred until depth returns to 0.
            // Named JS functions (Symbol.iterator, array methods, Promise resolvers)
            // return values WASM uses synchronously and never re-enter WASM — call
            // them directly. Discriminator: wasm-bindgen closures are always
            // anonymous (fnVal.name === ''); named functions are JS methods/builtins.
            if (_fnBase === '__wbg_call' && (_fnNparams >= 2 || args.length >= 2) && _inCallExport > 0) {
              const fnVal = resolvedArgs[0]
              const thisVal = resolvedArgs[1] === undefined ? _extMap.get(0) : resolvedArgs[1]
              const callArgs = resolvedArgs.slice(2)
              const fnDesc = typeof fnVal === 'function' ? (fnVal.name || 'anon-fn') : String(fnVal)
              console.log('[wasm3] __wbg_call intercept: fnType=' + typeof fnVal + ' fnName=' + fnDesc + ' nargs=' + resolvedArgs.length + ' depth=' + _inCallExport)
              if (typeof fnVal === 'function' && typeof fnVal._wbg_cb_unref === 'function') {
                const deferredCb = () => {
                  console.log('[wasm3] deferred __wbg_call firing: ' + fnDesc)
                  _traceAllImports = true
                  try { fnVal.call(thisVal, ...callArgs) }
                  catch (e) { console.log('[wasm3] deferred __wbg_call threw: ' + e) }
                  finally {
                    _traceAllImports = false
                    if (ioNudge) ioNudge()
                  }
                }
                _pendingMicrotasks.push(deferredCb)
                console.log('[wasm3] __wbg_call DEFERRED (depth=' + _inCallExport + ')')
                return 0
              }
            }
            let ret = f(...resolvedArgs)
            if (_isVerbose) console.log('[wasm3-v] ' + fn + ' ret=' + typeof ret + ':' + String(ret))
            // For imports whose WASM type declares externref return, ALL values
            // (including strings, numbers, symbols) must be stored in _extMap.
            if (_extRefRetImportKeys.has(k)) {
              if (ret === null || ret === undefined) return 0
              // If already an extMap slot index (e.g. returned by addToExternrefTable0),
              // return it directly — don't double-wrap.
              if (typeof ret === 'number' && _extMap.has(ret)) return ret
              const idx = _extNextIdx++; _extMap.set(idx, ret); if (ret && (typeof ret === 'object' || typeof ret === 'function')) _registry.register(ret, idx); return idx
            }
            // wasm-bindgen JS functions return native booleans for i32 bool results
            // but wasm3's bridge calls js_get_value_int32() which fails on booleans.
            // Convert here so the C bridge receives a numeric 0 or 1.
            if (typeof ret === 'boolean') return ret ? 1 : 0
            // wasm-bindgen sometimes returns raw JS objects/functions for externref
            // returns instead of going through addToExternrefTable0 (which would
            // return an integer).  Store them in _extMap so the C bridge gets an
            // i32 index it can round-trip back to the real value.
            if (ret !== null && ret !== undefined &&
                (typeof ret === 'object' || typeof ret === 'function' || typeof ret === 'symbol')) {
              const idx = _extNextIdx++
              _extMap.set(idx, ret)
              if (ret && (typeof ret === 'object' || typeof ret === 'function')) _registry.register(ret, idx)
              return idx
            }
            return ret
          } catch (e) {
            const _mb2 = _instHandle !== null ? binding.getMemory(_instHandle) : null
            console.log('[wasm3] import ERROR ' + k + ': ' + (e && e.message) + ' rawArgs=' + JSON.stringify(args) + ' resolved=' + JSON.stringify(resolvedArgs.map(a => typeof a === 'object' ? '[obj]' : typeof a === 'function' ? '[fn]' : String(a))) + ' memLen=' + (_mb2 ? _mb2.byteLength : '?') + ' detached=' + (_mb2 ? _mb2.detached : '?'))
            throw e
          }
        }
      }
    }

    console.log('[wasm3] instanceNew start')
    const result = binding.instanceNew(wasmModule._handle, _wrappedImports)
    _instHandle = result.handle
    console.log('[wasm3] instanceNew done')

    const exports = {}

    for (const [name, kind] of Object.entries(result.exportsMap)) {
      if (kind === 0 /* function */) {
        const exportName = name
        exports[exportName] = (...args) => {
          if (_traceAllImports) console.log('[wasm3] export ' + exportName + ' start args=' + JSON.stringify(args.map(a => typeof a === 'object' ? '[obj]' : typeof a === 'function' ? '[fn]' : String(a))) + ' depth=' + _inCallExport)
          // Guard: handleError() in reticle_bg.js catches import exceptions and
          // calls wasm.__wbindgen_exn_store() to store the error for Rust's ?
          // operator. That triggers a nested m3_CallV which always restarts from
          // runtime->stack base, corrupting the parent execution's stack frame.
          // Skip the nested call; the import handler returns undefined (→ 0),
          // so WASM takes the "no error" path instead of trapping.
          if (_inCallExport > 0 && exportName === '__wbindgen_exn_store') {
            return undefined
          }

          if (exportName === '__wbindgen_start') {
            console.log('[wasm3] __wbindgen_start call start')
          }

          // Convert non-numeric JS args to i32 externref slot indices.
          // null → 0 (WebAssembly null externref; ref.is_null returns true).
          // undefined → fresh non-zero slot (NOT stored in _extMap): ref.is_null
          //   returns false (correct — undefined is not the null externref).  The
          //   wasm3 local.get bug after ref.is_null corrupts the slot index to 0,
          //   so WASM ends up doing _extMap.get(0) which __wbindgen_init_externref_table
          //   set to undefined — the right value.  Any other JS value gets a real slot.
          const hasNonNumber = args.some(a => typeof a !== 'number' && typeof a !== 'bigint')
          let callArgs = args
          if (hasNonNumber) {
            if (args.some(a => a !== null && a !== undefined && typeof a !== 'number' && typeof a !== 'bigint')) {
              console.log('[wasm3] invoke args raw: ' + exportName + ' → ' + args.map(a => typeof a === 'function' ? '[fn]' : typeof a === 'object' ? '[obj]' : String(a)).join(', '))
            }
            callArgs = args.map(a => {
              if (typeof a === 'number' || typeof a === 'bigint') return a
              if (a === null) return 0
              if (a === undefined) return _extUndefinedSlot  // non-zero; wasm3 bug → 0 → _extMap[0]=undefined ✓
              const idx = _extNextIdx++
              _extMap.set(idx, a)
              if (a && (typeof a === 'object' || typeof a === 'function')) _registry.register(a, idx)
              console.log('[wasm3] externref store: ' + exportName + ' arg → idx=' + idx + ' type=' + typeof a)
              return idx
            })
          }

          // Proactively check for memory.grow so that wasm-bindgen's cachedUint8ArrayMemory0
          // gets invalidated before WASM runs.
          if (_instHandle !== null) {
            const _mb = binding.getMemory(_instHandle)
            if (_mb.byteLength !== _prevMemBuf?.byteLength) {
              console.log('[wasm3] mem@export grow detected: ' + (_prevMemBuf ? _prevMemBuf.byteLength : 0) + ' -> ' + _mb.byteLength)
              _prevMemBuf = _mb
            }
          }

          let r
          _inCallExport++
          try {
            r = binding.callExport(result.handle, exportName, callArgs)
          } catch (e) {
            _inCallExport--
            if (_inCallExport === 0) {
              _flushPendingMicrotasks()
              if (typeof ioNudge === 'function') { console.log('[wasm3] ioNudge (err)'); ioNudge() }
            }
            console.log('[wasm3] callExport ERROR: ' + exportName + ' => ' + (e && e.message) + ' callArgs=' + JSON.stringify(callArgs))
            throw e
          }
          _inCallExport--
          if (_inCallExport === 0) {
            _flushPendingMicrotasks()
            if (typeof ioNudge === 'function') { console.log('[wasm3] ioNudge'); ioNudge() }
          }
          if (exportName === '__wbindgen_start') {
            const summary = Object.entries(_importCounts).filter(([,n]) => n > 0).map(([k,n]) => k + '=' + n).join(', ')
            console.log('[wasm3] __wbindgen_start call done; import calls: ' + (summary || '(none)'))
          }
          // Exports returning externref come back as an i32 slot index.
          // Look up the real JS value so callers get the actual object (e.g.
          // the Promise from clientbuilder_build, not an integer).
          if (typeof r === 'number' && wasmModule._wasm3ExternrefInfo.returnExports.has(exportName)) {
            const extVal = _resolveExtref(r)
            console.log('[wasm3] externref-return: ' + exportName + ' slot=' + r + ' resolved=' + typeof extVal)
            return extVal
          }
          return r
        }
      } else if (kind === 1 /* table */) {
        const instanceHandle = result.handle
        exports[name] = {
          get (idx) { return binding.tableGet(instanceHandle, idx) },
          set (idx, val) { binding.tableSet(instanceHandle, idx, val) },
          grow (n) { return binding.tableGrow(instanceHandle, n) },
          get length () { return binding.tableSize(instanceHandle) },
        }
      } else if (kind === 2 /* memory */) {
        const instanceHandle = result.handle
        exports[name] = { get buffer () { return binding.getMemory(instanceHandle) } }
      }
    }

    // Wire up import re-exports.
    for (const [exportName, { module: mod, name: fn }] of Object.entries(result.importReexports || {})) {
      const importFn = _wrappedImports[mod]?.[fn]
      if (typeof importFn === 'function') {
        console.log('[wasm3] import-reexport wired: ' + exportName + ' → ' + mod + '.' + fn)
        exports[exportName] = importFn
      } else {
        console.log('[wasm3] import-reexport MISSING: ' + exportName + ' → ' + mod + '.' + fn)
      }
    }

    // ── Externref table polyfill ─────────────────────────────────────────────
    // Replace the wasm-bindgen externref table exports with a pure-JS Map so
    // that addToExternrefTable0 / takeFromExternrefTable0 store real JS values.
    for (const tblName of ['__wbindgen_externrefs', '__wbindgen_export_2']) {
      if (tblName in exports && exports[tblName] && typeof exports[tblName].set === 'function') {
        const orig = exports[tblName]
        exports[tblName] = {
          get (idx) { return _resolveExtref(idx) },
          set (idx, val) { _extMap.set(idx, val) },
          grow (n) { return orig.grow(n) },
          get length () { return orig.length },
        }
        console.log('[wasm3] externref table polyfill installed for ' + tblName)
      }
    }

    // Replace __externref_table_alloc / __externref_table_dealloc with pure-JS
    // implementations.  The WASM versions call table.grow (stub returns -1) and
    // table.size (stub returns 0), causing an unreachable panic.
    exports.__externref_table_alloc = () => _extNextIdx++
    exports.__externref_table_dealloc = (idx) => { _extMap.delete(idx) }
    console.log('[wasm3] __externref_table_alloc/dealloc polyfills installed')

    this.exports = exports

    if (key) _instanceCache.set(key, this)
  }
}

module.exports = { Module, Instance }
