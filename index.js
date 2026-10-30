'use strict'

const binding = require('./binding.js')

const PREFIX = '[bare-wasm3]'
const _debug = process.env.BW3_DEBUG === '1'
function _log (msg) { if (_debug) console.log(msg) }

/* Fingerprint: sample this many bytes from the start of the WASM binary */
const FINGERPRINT_SAMPLE_BYTES = 64
/* Log display: truncate fingerprint key to this many chars */
const FINGERPRINT_LOG_LEN = 20
/* Externref keys: 0 = ref.null, 1-3 fixed primitives, the rest index _extMap. */
const EXT_KEY_NULL = 0
const EXT_KEY_UNDEFINED = 1
const EXT_KEY_TRUE = 2
const EXT_KEY_FALSE = 3
const EXT_KEY_FIRST_FREE = 4
/* wasm-bindgen appends a 16-char hex hash suffix to mangled import names */
const WBINDGEN_SUFFIX_RE = /_[0-9a-f]{16}$/
/* Suffix of wasm-bindgen 0.2.121+ closure shim export names. */
const WBINDGEN_CLOSURE_PREFIX = '___convert__closures_____invoke___'
/* Export kind codes returned by binding.instanceNew exportsMap */
const EXPORT_KIND_FUNCTION = 0
const EXPORT_KIND_TABLE    = 1
const EXPORT_KIND_MEMORY   = 2
/* memory.grow from JS is unsupported — wasm3 manages memory internally */
const MEMORY_GROW_UNSUPPORTED = -1
/* WASM binary value/section codes used by _exportParamTypes */
const WASM_VT_I32 = 0x7f
const WASM_VT_I64 = 0x7e
const WASM_VT_EXTERNREF = 0x6f
const WASM_FUNCTYPE = 0x60
const WASM_SEC_TYPE = 1
const WASM_SEC_IMPORT = 2
const WASM_SEC_FUNCTION = 3
const WASM_SEC_EXPORT = 7

const _moduleCache = new Map()

function _fingerprint(buf) {
  return buf.length + ':' + buf.slice(0, FINGERPRINT_SAMPLE_BYTES).toString('hex')
}

/* JSON.stringify that survives BigInt (i64) values, for error logs only. */
function _safeJson (v) {
  try { return JSON.stringify(v, (k, x) => typeof x === 'bigint' ? x.toString() + 'n' : x) } catch { return '?' }
}

/* Raw param types per export (C reports externref as i32); null if unparseable. */
function _exportParamTypes (buf) {
  try {
    let p = 8
    const leb = (end) => {
      let v = 0, s = 0, b
      do {
        if (p >= end) throw new Error('truncated')
        b = buf[p++]
        if (s < 32) v |= (b & 0x7f) << s
        s += 7
      } while (b & 0x80)
      return v >>> 0
    }
    const skipLimits = (end) => { const flags = buf[p++]; leb(end); if (flags & 1) leb(end) }
    const types = []
    const funcTypes = []
    const out = new Map()
    while (p < buf.length) {
      const id = buf[p++]
      const size = leb(buf.length)
      const end = p + size
      if (end > buf.length) return null
      if (id === WASM_SEC_TYPE) {
        for (let n = leb(end); n > 0; n--) {
          if (buf[p++] !== WASM_FUNCTYPE) return null
          const params = []
          for (let np = leb(end); np > 0; np--) params.push(buf[p++])
          const nr = leb(end)
          p += nr
          types.push(params)
        }
      } else if (id === WASM_SEC_IMPORT) {
        for (let n = leb(end); n > 0; n--) {
          for (let field = 0; field < 2; field++) { const len = leb(end); p += len }
          const kind = buf[p++]
          if (kind === 0) funcTypes.push(types[leb(end)])
          else if (kind === 1) { p++; skipLimits(end) }
          else if (kind === 2) skipLimits(end)
          else if (kind === 3) p += 2
          else if (kind === 4) { p++; leb(end) }
          else return null
        }
      } else if (id === WASM_SEC_FUNCTION) {
        for (let n = leb(end); n > 0; n--) funcTypes.push(types[leb(end)])
      } else if (id === WASM_SEC_EXPORT) {
        for (let n = leb(end); n > 0; n--) {
          const len = leb(end)
          const name = buf.toString('utf8', p, p + len)
          p += len
          const kind = buf[p++]
          const idx = leb(end)
          if (kind === 0 && funcTypes[idx]) out.set(name, funcTypes[idx])
        }
      }
      p = end
    }
    return out
  } catch {
    return null
  }
}

class Module {
  constructor (bytes, options) {
    let buf
    if (bytes instanceof ArrayBuffer) {
      buf = Buffer.from(bytes)
    } else if (ArrayBuffer.isView(bytes)) {
      buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    } else {
      buf = bytes
    }

    let useCache = options?.cache !== false
    const key = _fingerprint(buf)
    _log(PREFIX + ' Module len=' + buf.length + ' key=' + key.slice(0, FINGERPRINT_LOG_LEN) + (useCache ? ' cache=on' : ''))

    /* Fingerprint only samples the head; compare full bytes. */
    if (useCache && _moduleCache.has(key) && !_moduleCache.get(key).bytes.equals(buf)) {
      _log(PREFIX + ' Module fingerprint collision, not caching')
      useCache = false
    }

    if (useCache && _moduleCache.has(key)) {
      const entry = _moduleCache.get(key)
      this._handle = entry.handle
      this._meta = entry.meta
      this._exportParams = entry.exportParams
      this._key = key
      this._cached = true
      _log(PREFIX + ' Module CACHED')
      return
    }

    const ab = (buf.byteOffset === 0 && buf.byteLength === buf.buffer.byteLength)
      ? buf.buffer
      : buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)

    _log(PREFIX + ' moduleNew start')
    this._handle = binding.moduleNew(ab)
    this._meta = binding.moduleMeta(this._handle)
    this._exportParams = _exportParamTypes(buf)
    _log(PREFIX + ' moduleNew done')
    this._key = key
    this._cached = false
    if (useCache) {
      _moduleCache.set(key, { handle: this._handle, meta: this._meta, exportParams: this._exportParams, bytes: Buffer.from(ab) })
      this._cached = true
    }
  }

  dispose () {
    if (this._handle == null) return
    if (this._cached) _moduleCache.delete(this._key)
    binding.moduleFree(this._handle)
    this._handle = null
  }
}

class Instance {
  constructor (wasmModule, imports, options) {
    const key = wasmModule._key
    const ioNudge = options?.ioNudge

    // ── Type metadata from C-side moduleMeta (needed BEFORE import wrapping) ──
    const _meta = wasmModule._meta || {}
    const _returnExports = new Set(_meta.returnExports || [])
    const _extRefRetImportKeys = new Set(_meta.returnImportKeys || [])
    const _extRefParamInfo = new Map()
    const _importTotalParams = new Map()
    if (_meta.importParamInfo) {
      for (const [key, info] of Object.entries(_meta.importParamInfo)) {
        _extRefParamInfo.set(key, info.extrefParams || [])
        _importTotalParams.set(key, info.totalParams || 0)
      }
    }

    // ── Externref state ──────────────────────────────────────────────────────
    /* key -> JS value; unreferenced keys are swept after the outermost export call. */
    const _extMap = new Map()
    const _extFreeKeys = []
    let _extNextKey = EXT_KEY_FIRST_FREE
    let _extStoredSinceSweep = false

    let _traceAllImports = false
    let _inCallExport = 0
    let _instHandle = null
    let _prevMemBuf = null

    function _checkMemoryGrow (where) {
      if (_instHandle === null) return
      const mb = binding.getMemory(_instHandle)
      if (!mb) return
      if (mb.byteLength !== _prevMemBuf?.byteLength) {
        _log(PREFIX + ' mem@' + where + ' grow detected: ' + (_prevMemBuf ? _prevMemBuf.byteLength : 0) + ' -> ' + mb.byteLength)
        _prevMemBuf = mb
      }
    }

    function _resolveExtref (key) {
      if (key === EXT_KEY_NULL) return null
      if (key === EXT_KEY_UNDEFINED) return undefined
      if (key === EXT_KEY_TRUE) return true
      if (key === EXT_KEY_FALSE) return false
      return _extMap.get(key)
    }

    /* JS value -> externref key handed to wasm */
    function _toExtref (a) {
      if (a === null) return EXT_KEY_NULL
      if (a === undefined) return EXT_KEY_UNDEFINED
      if (a === true) return EXT_KEY_TRUE
      if (a === false) return EXT_KEY_FALSE
      return _extStore(a)
    }

    function _extStore (val) {
      const key = _extFreeKeys.length > 0 ? _extFreeKeys.pop() : _extNextKey++
      _extMap.set(key, val)
      _extStoredSinceSweep = true
      return key
    }

    /* Free keys no longer in the table. Only safe at call depth 0. */
    function _extSweep () {
      if (!_extStoredSinceSweep || _instHandle === null) return
      _extStoredSinceSweep = false
      const live = new Set(binding.tableKeys(_instHandle))
      for (const key of _extMap.keys()) {
        if (!live.has(key)) { _extMap.delete(key); _extFreeKeys.push(key) }
      }
    }

    // ── Import wrapping ──────────────────────────────────────────────────────
    const _importCounts = {}
    const _wrappedImports = {}
    for (const [mod, fns] of Object.entries(imports || {})) {
      _wrappedImports[mod] = {}
      for (const [fn, f] of Object.entries(fns)) {
        if (typeof f !== 'function') { _wrappedImports[mod][fn] = f; continue }
        const k = mod + '.' + fn
        _importCounts[k] = 0
        const _fnBase = fn.replace(WBINDGEN_SUFFIX_RE, '')
        const _isVerbose = _fnBase === '__wbg___wbindgen_is_undefined' ||
          _fnBase === '__wbg_queueMicrotask' ||
          _fnBase.startsWith('__wbg_static_accessor_')
        _wrappedImports[mod][fn] = (...args) => {
          const n = ++_importCounts[k]
          if (n === 1 || _traceAllImports) _log(PREFIX + ' import ' + k + ' n=' + n + (_traceAllImports ? ' rawArgs=' + JSON.stringify(args) : ''))
          if (_isVerbose) _log(PREFIX + ' ' + fn + ' rawArgs=' + JSON.stringify(args) + ' extMap[' + args[0] + ']=' + String(_extMap.get(args[0])))
          _checkMemoryGrow('import')
          let resolvedArgs = args
          try {
            const _extrefPositions = _extRefParamInfo.get(k)
            resolvedArgs = _extrefPositions
              ? args.map((a, i) => _extrefPositions.includes(i) ? _resolveExtref(a) : a)
              : args.map(a => typeof a === 'number' ? _resolveExtref(a) : a)
            if (!_isVerbose && args.some(a => a === 0)) {
              _log(PREFIX + ' ' + fn + ' n=' + n + ' rawArgs=' + JSON.stringify(args))
            }
            if (_isVerbose) _log(PREFIX + ' ' + fn + ' resolved[0]=' + typeof resolvedArgs[0] + ':' + String(resolvedArgs[0]))
            let ret = f(...resolvedArgs)
            if (_isVerbose) _log(PREFIX + ' ' + fn + ' ret=' + typeof ret + ':' + String(ret))
            if (_extRefRetImportKeys.has(k)) {
              /* Externref result: a number here is a value, not a key. */
              return _toExtref(ret)
            }
            if (typeof ret === 'boolean') return ret ? 1 : 0
            if (ret !== null && ret !== undefined &&
                (typeof ret === 'object' || typeof ret === 'function' || typeof ret === 'symbol')) {
              return _extStore(ret)
            }
            return ret
          } catch (e) {
            const _mb2 = _instHandle !== null ? binding.getMemory(_instHandle) : null
            console.log(PREFIX + ' import ERROR ' + k + ': ' + (e && e.message) + ' rawArgs=' + _safeJson(args) + ' resolved=' + _safeJson(resolvedArgs.map(a => typeof a === 'object' ? '[obj]' : typeof a === 'function' ? '[fn]' : String(a))) + ' memLen=' + (_mb2 ? _mb2.byteLength : '?') + ' detached=' + (_mb2 ? _mb2.detached : '?'))
            throw e
          }
        }
      }
    }

    _log(PREFIX + ' instanceNew start')
    const result = binding.instanceNew(wasmModule._handle, _wrappedImports)
    _instHandle = result.handle
    _log(PREFIX + ' instanceNew done')

    /* Exports whose first result is externref. */
    for (const name of Object.keys(result.externrefResultExports || {})) _returnExports.add(name)

    /* Closure shims, matched by suffix so a different crate hash still resolves. */
    const _closureShims = new Set()
    const _closureShimsBySuffix = new Map()
    for (const [suffix, name] of Object.entries(result.closureExports || {})) {
      _closureShims.add(name)
      _closureShimsBySuffix.set(suffix, name)
    }
    if (_closureShims.size > 0) _log(PREFIX + ' closure shims: ' + _closureShims.size)

    const exports = {}

    /* Runs before the sweep so a returned externref still resolves. */
    function _exportResult (exportName, r) {
      if (_debug && exportName === '__wbindgen_start') {
        const summary = Object.entries(_importCounts).filter(([,n]) => n > 0).map(([k,n]) => k + '=' + n).join(', ')
        _log(PREFIX + ' __wbindgen_start call done; import calls: ' + (summary || '(none)'))
      }
      if (typeof r === 'number' && _returnExports.has(exportName)) {
        const extVal = _resolveExtref(r)
        _log(PREFIX + ' externref-return: ' + exportName + ' key=' + r + ' resolved=' + typeof extVal)
        return extVal
      }
      if (Array.isArray(r)) {
        /* Multi-value: only a leading externref is resolved. */
        const out = Array.from(r)
        if (_returnExports.has(exportName)) out[0] = _resolveExtref(out[0])
        return out
      }
      return r
    }

    /* Resolve unknown closure shim names by suffix. */
    const _resolveClosureShim = (name) => {
      if (typeof name !== 'string' || !name.includes(WBINDGEN_CLOSURE_PREFIX)) return null
      return _closureShimsBySuffix.get(name.slice(name.indexOf(WBINDGEN_CLOSURE_PREFIX) + WBINDGEN_CLOSURE_PREFIX.length)) || null
    }

    for (const [name, kind] of Object.entries(result.exportsMap)) {
      if (kind === EXPORT_KIND_FUNCTION) {
        const exportName = name
        const paramTypes = wasmModule._exportParams ? wasmModule._exportParams.get(exportName) : undefined
        exports[exportName] = (...args) => {
          if (_traceAllImports) _log(PREFIX + ' export ' + exportName + ' start args=' + JSON.stringify(args.map(a => typeof a === 'object' ? '[obj]' : typeof a === 'function' ? '[fn]' : String(a))) + ' depth=' + _inCallExport)
          if (exportName === '__wbindgen_start') {
            _log(PREFIX + ' __wbindgen_start call start')
          }

          let callArgs = args
          if (paramTypes) {
            /* externref params take any value; numeric ones use ToNumber/ToInt32. */
            for (let i = 0; i < paramTypes.length; i++) {
              const a = args[i]
              const t = paramTypes[i]
              let v = a
              if (t === WASM_VT_EXTERNREF) v = _toExtref(a)
              else if (typeof a !== 'number' && typeof a !== 'bigint' && t !== WASM_VT_I64) v = t === WASM_VT_I32 ? Number(a) | 0 : Number(a)
              if (v !== a || i >= args.length) {
                if (callArgs === args) callArgs = args.slice()
                callArgs[i] = v
              }
            }
          } else if (args.some(a => typeof a !== 'number' && typeof a !== 'bigint')) {
            if (args.some(a => a !== null && a !== undefined && typeof a !== 'number' && typeof a !== 'bigint')) {
              _log(PREFIX + ' invoke args raw: ' + exportName + ' → ' + args.map(a => typeof a === 'function' ? '[fn]' : typeof a === 'object' ? '[obj]' : String(a)).join(', '))
            }
            callArgs = args.map(a => {
              if (typeof a === 'number' || typeof a === 'bigint') return a
              const idx = _toExtref(a)
              _log(PREFIX + ' externref store: ' + exportName + ' arg → idx=' + idx + ' type=' + typeof a)
              return idx
            })
          }

          _checkMemoryGrow('export')

          let r
          _inCallExport++
          try {
            if (_closureShims.has(exportName)) {
              r = binding.callExport(_instHandle, exportName, [exportName, ...callArgs], true)
            } else {
              r = binding.callExport(_instHandle, exportName, callArgs)
            }
          } catch (e) {
            _inCallExport--
            _checkMemoryGrow('export-ret')
            if (_inCallExport === 0) {
              _extSweep()
              if (typeof ioNudge === 'function') { _log(PREFIX + ' ioNudge (err)'); ioNudge() }
            }
            console.log(PREFIX + ' callExport ERROR: ' + exportName + ' => ' + (e && e.message) + ' callArgs=' + _safeJson(callArgs))
            throw e
          }
          _inCallExport--
          /* Memory may have moved: detach the stale buffer. */
          _checkMemoryGrow('export-ret')
          const out = _exportResult(exportName, r)
          if (_inCallExport === 0) {
            _extSweep()
            if (typeof ioNudge === 'function') { _log(PREFIX + ' ioNudge'); ioNudge() }
          }
          return out
        }
      } else if (kind === EXPORT_KIND_TABLE) {
        /* The externref table stores keys; JS reads and writes values. */
        exports[name] = {
          get (idx) {
            const key = binding.tableGet(_instHandle, idx)
            if (key === undefined) throw new RangeError('table index out of bounds')
            return _resolveExtref(key)
          },
          set (idx, val) { binding.tableSet(_instHandle, idx, _toExtref(val)) },
          grow (n, init) {
            const old = binding.tableGrow(_instHandle, n)
            /* JS API default for externref is undefined. */
            const key = _toExtref(init)
            if (old !== -1 && key !== EXT_KEY_NULL) {
              for (let i = old; i < old + n; i++) binding.tableSet(_instHandle, i, key)
            }
            return old
          },
          get length () { return binding.tableSize(_instHandle) },
        }
      } else if (kind === EXPORT_KIND_MEMORY) {
        exports[name] = {
          get buffer () { return binding.getMemory(_instHandle) },
          grow (pages) {
            _log(PREFIX + ' memory.grow(' + pages + ') called from JS; wasm3 grows memory internally')
            return MEMORY_GROW_UNSUPPORTED
          },
        }
      }
    }

    // Wire up import re-exports.
    for (const [exportName, { module: mod, name: fn }] of Object.entries(result.importReexports || {})) {
      const importFn = _wrappedImports[mod]?.[fn]
      if (typeof importFn === 'function') {
        _log(PREFIX + ' import-reexport wired: ' + exportName + ' → ' + mod + '.' + fn)
        exports[exportName] = importFn
      } else {
        console.log(PREFIX + ' import-reexport MISSING: ' + exportName + ' → ' + mod + '.' + fn)
      }
    }

    this.closureShims = _closureShimsBySuffix
    this.exports = new Proxy(exports, {
      get (target, prop, receiver) {
        if (typeof prop === 'string' && !(prop in target) && prop.includes(WBINDGEN_CLOSURE_PREFIX)) {
          const shim = _resolveClosureShim(prop)
          if (shim) return target[shim]
        }
        return Reflect.get(target, prop, receiver)
      },
      has (target, prop) {
        if (typeof prop === 'string' && !(prop in target) && prop.includes(WBINDGEN_CLOSURE_PREFIX)) {
          return _resolveClosureShim(prop) !== null
        }
        return Reflect.has(target, prop)
      },
    })
    this._instHandle = _instHandle

    // Diagnostic: check for WASM imports not provided by JS
    if (key) {
      const _allImportKeys = new Set()
      for (const [mod, fns] of Object.entries(_wrappedImports)) {
        for (const fn of Object.keys(fns)) {
          if (typeof _wrappedImports[mod][fn] === 'function') _allImportKeys.add(mod + '.' + fn)
        }
      }
      const _wasmImportKeys = new Set(_extRefParamInfo.keys())
      const _missing = [..._wasmImportKeys].filter(k => !_allImportKeys.has(k))
      if (_missing.length > 0) {
        console.log(PREFIX + ' MISSING IMPORTS (' + _missing.length + '): ' + _missing.join(', '))
      } else {
        _log(PREFIX + ' All imports linked OK (' + _allImportKeys.size + ' JS -> ' + _wasmImportKeys.size + ' WASM)')
      }
    }
  }

  dispose () {
    if (this._instHandle == null) return
    binding.instanceFree(this._instHandle)
    this._instHandle = null
  }
}

module.exports = { Module, Instance }
