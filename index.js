'use strict'

const binding = require('./binding.js')

const PREFIX = '[bare-wasm3]'
const _debug = process.env.BW3_DEBUG === '1'
function _log (msg) { if (_debug) console.log(msg) }

/* Fingerprint: sample this many bytes from the start of the WASM binary */
const FINGERPRINT_SAMPLE_BYTES = 64
/* Log display: truncate fingerprint key to this many chars */
const FINGERPRINT_LOG_LEN = 20
/* wasm-bindgen reserves slots 0-3 (undefined, null, true, false) */
const WBINDGEN_RESERVED_SLOTS = 4
/* wasm-bindgen slot 0 is always undefined */
const WBINDGEN_SLOT_UNDEFINED = 0
/* Max externref slot index — stays within WASM i32 range */
const EXT_SLOT_MAX = 0x7FFFFFFF
/* wasm-bindgen appends a 16-char hex hash suffix to mangled import names */
const WBINDGEN_SUFFIX_RE = /_[0-9a-f]{16}$/
/* queueMicrotask has exactly 2 params in wasm-bindgen's calling convention */
const WBINDGEN_QUEUE_MICROTASK_PARAMS = 2
/* __wbg_call needs at least 2 params (fn, this) */
const WBINDGEN_CALL_MIN_PARAMS = 2
/* Export kind codes returned by binding.instanceNew exportsMap */
const EXPORT_KIND_FUNCTION = 0
const EXPORT_KIND_TABLE    = 1
const EXPORT_KIND_MEMORY   = 2
/* table.grow returns this uint32 value on failure (== -1 as i32) */
const EXT_GROW_FAIL = 0xFFFFFFFF
/* memory.grow from JS is unsupported — wasm3 manages memory internally */
const MEMORY_GROW_UNSUPPORTED = -1

const _moduleCache = new Map()

function _fingerprint(buf) {
  return buf.length + ':' + buf.slice(0, FINGERPRINT_SAMPLE_BYTES).toString('hex')
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

    const useCache = options?.cache !== false
    const key = _fingerprint(buf)
    _log(PREFIX + ' Module len=' + buf.length + ' key=' + key.slice(0, FINGERPRINT_LOG_LEN) + (useCache ? ' cache=on' : ''))

    if (useCache && _moduleCache.has(key)) {
      const entry = _moduleCache.get(key)
      this._handle = entry.handle
      this._meta = entry.meta
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
    _log(PREFIX + ' moduleNew done')
    this._key = key
    this._cached = false
    if (useCache) {
      _moduleCache.set(key, { handle: this._handle, meta: this._meta })
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

    // ── Externref polyfill state ─────────────────────────────────────────────
    const _extMap = new Map()
    const _EXT_TOMBSTONE = Symbol('ext-tombstone')
    const _deallocdSlots = new Set()
    const _registry = new FinalizationRegistry((idx) => {
      if (_deallocdSlots.has(idx)) {
        _deallocdSlots.delete(idx)
        return
      }
      _extMap.set(idx, _EXT_TOMBSTONE)
    })

    let _extNextIdx = _meta.extrefInitSlots || WBINDGEN_RESERVED_SLOTS
    const _extUndefinedSlot = _extNextIdx++
    let _traceAllImports = false
    let _inCallExport = 0
    const _pendingMicrotasks = []
    let _instHandle = null
    let _prevMemBuf = null

    function _resolveExtref (slot) {
      if (_extMap.has(slot)) {
        const v = _extMap.get(slot)
        return v === _EXT_TOMBSTONE ? undefined : v
      }
      if (_instHandle !== null) {
        const inner = binding.extvalGet(_instHandle, slot)
        if (inner > 0 && _extMap.has(inner)) {
          const v2 = _extMap.get(inner)
          return v2 === _EXT_TOMBSTONE ? undefined : v2
        }
      }
      return undefined
    }

    function _extStore (val) {
      let idx
      if (_deallocdSlots.size > 0) {
        idx = _deallocdSlots.values().next().value
        _deallocdSlots.delete(idx)
      } else {
        if (_extNextIdx >= EXT_SLOT_MAX) return 0
        idx = _extNextIdx++
      }
      _extMap.set(idx, val)
      if (val && (typeof val === 'object' || typeof val === 'function')) _registry.register(val, idx)
      return idx
    }

    let _isFlushing = false
    function _flushPendingMicrotasks() {
      if (_pendingMicrotasks.length === 0 || _isFlushing) return
      _isFlushing = true
      try {
        _log(PREFIX + ' flushing ' + _pendingMicrotasks.length + ' deferred microtask(s)')
        while (_pendingMicrotasks.length > 0) {
          const cb = _pendingMicrotasks.shift()
          try { cb() } catch (e) { console.log(PREFIX + ' microtask error: ' + e) }
        }
      } finally {
        _isFlushing = false
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
          (_fnBase === '__wbg_queueMicrotask' && _importTotalParams.get(k) === WBINDGEN_QUEUE_MICROTASK_PARAMS) ||
          _fnBase.startsWith('__wbg_static_accessor_')
        _wrappedImports[mod][fn] = (...args) => {
          const n = ++_importCounts[k]
          if (n === 1 || _traceAllImports) _log(PREFIX + ' import ' + k + ' n=' + n + (_traceAllImports ? ' rawArgs=' + JSON.stringify(args) : ''))
          if (_isVerbose) _log(PREFIX + ' ' + fn + ' rawArgs=' + JSON.stringify(args) + ' extMap[' + args[0] + ']=' + String(_extMap.get(args[0])) + ' _extNextIdx=' + _extNextIdx)
          if (_instHandle !== null) {
            const _mb = binding.getMemory(_instHandle)
            if (_mb.byteLength !== _prevMemBuf?.byteLength) {
              _log(PREFIX + ' mem@import grow detected: ' + (_prevMemBuf ? _prevMemBuf.byteLength : 0) + ' -> ' + _mb.byteLength)
              _prevMemBuf = _mb
            }
          }
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
            if (resolvedArgs[0] === undefined || resolvedArgs[0] === null) {
              if (_fnBase === '__wbg_queueMicrotask') {
                const qm = globalThis.queueMicrotask
                _log(PREFIX + ' queueMicrotask fallback to globalThis, type=' + typeof qm)
                if (typeof qm === 'function') {
                  return _extStore(qm)
                }
                return 0
              }
              if (_fnBase === '__wbg___wbindgen_is_undefined') {
                return 0
              }
            }
            if (_fnBase === '__wbg_queueMicrotask') {
              const rawCbIdx = args[args.length - 1]
              const rawCb = resolvedArgs[resolvedArgs.length - 1]
              _log(PREFIX + ' queueMicrotask intercept: cbIdx=' + rawCbIdx + ' typeof cb=' + typeof rawCb + ' inCallExport=' + _inCallExport)
              if (_inCallExport > 0 && typeof rawCb === 'function') {
                _log(PREFIX + ' queueMicrotask DEFERRED (depth=' + _inCallExport + ')')
                const deferredCb = (...a) => {
                  _log(PREFIX + ' deferred microtask fired — enabling trace')
                  _traceAllImports = true
                  try { return rawCb(...a) }
                  finally { _traceAllImports = false; _log(PREFIX + ' deferred microtask done — trace off') }
                }
                _pendingMicrotasks.push(deferredCb)
                return undefined
              }
              const wrappedCb = typeof rawCb === 'function'
                ? (...cbArgs) => {
                    _log(PREFIX + ' queueMicrotask fired — enabling trace')
                    _traceAllImports = true
                    try { return rawCb(...cbArgs) }
                    finally { _traceAllImports = false; _log(PREFIX + ' queueMicrotask done — trace off') }
                  }
                : rawCb
              _extStore(wrappedCb)
              const actualResolvedArgs = [...resolvedArgs.slice(0, -1), wrappedCb]
              let ret = f(...actualResolvedArgs)
              if (_extRefRetImportKeys.has(k)) {
                if (ret === null || ret === undefined) return 0
                if (typeof ret === 'number' && _extMap.has(ret)) return ret
                return _extStore(ret)
              }
              if (typeof ret === 'boolean') return ret ? 1 : 0
              if (ret !== null && ret !== undefined && (typeof ret === 'object' || typeof ret === 'function' || typeof ret === 'symbol')) {
                return _extStore(ret)
              }
              return ret
            }
            if (_fnBase === '__wbg_call' && (_importTotalParams.get(k) >= WBINDGEN_CALL_MIN_PARAMS || args.length >= WBINDGEN_CALL_MIN_PARAMS) && _inCallExport > 0) {
              const fnVal = resolvedArgs[0]
              const thisVal = resolvedArgs[1] === undefined ? _extMap.get(WBINDGEN_SLOT_UNDEFINED) : resolvedArgs[1]
              const callArgs = resolvedArgs.slice(2)
              const fnDesc = typeof fnVal === 'function' ? (fnVal.name || 'anon-fn') : String(fnVal)
              _log(PREFIX + ' __wbg_call intercept: fnType=' + typeof fnVal + ' fnName=' + fnDesc + ' nargs=' + resolvedArgs.length + ' depth=' + _inCallExport)
              if (typeof fnVal === 'function' && typeof fnVal._wbg_cb_unref === 'function') {
                const deferredCb = () => {
                  _log(PREFIX + ' deferred __wbg_call firing: ' + fnDesc)
                  _traceAllImports = true
                  try { fnVal.call(thisVal, ...callArgs) }
                  catch (e) { _log(PREFIX + ' deferred __wbg_call threw: ' + e) }
                  finally {
                    _traceAllImports = false
                    if (ioNudge) ioNudge()
                  }
                }
                _pendingMicrotasks.push(deferredCb)
                _log(PREFIX + ' __wbg_call DEFERRED (depth=' + _inCallExport + ')')
                return 0
              }
            }
            let ret = f(...resolvedArgs)
            if (_isVerbose) _log(PREFIX + ' ' + fn + ' ret=' + typeof ret + ':' + String(ret))
            if (_extRefRetImportKeys.has(k)) {
              if (ret === null || ret === undefined) return 0
              if (typeof ret === 'number' && _extMap.has(ret)) return ret
              return _extStore(ret)
            }
            if (typeof ret === 'boolean') return ret ? 1 : 0
            if (ret !== null && ret !== undefined &&
                (typeof ret === 'object' || typeof ret === 'function' || typeof ret === 'symbol')) {
              return _extStore(ret)
            }
            return ret
          } catch (e) {
            const _mb2 = _instHandle !== null ? binding.getMemory(_instHandle) : null
            console.log(PREFIX + ' import ERROR ' + k + ': ' + (e && e.message) + ' rawArgs=' + JSON.stringify(args) + ' resolved=' + JSON.stringify(resolvedArgs.map(a => typeof a === 'object' ? '[obj]' : typeof a === 'function' ? '[fn]' : String(a))) + ' memLen=' + (_mb2 ? _mb2.byteLength : '?') + ' detached=' + (_mb2 ? _mb2.detached : '?'))
            throw e
          }
        }
      }
    }

    _log(PREFIX + ' instanceNew start')
    const result = binding.instanceNew(wasmModule._handle, _wrappedImports)
    _instHandle = result.handle
    _log(PREFIX + ' instanceNew done')

    const exports = {}

    for (const [name, kind] of Object.entries(result.exportsMap)) {
      if (kind === EXPORT_KIND_FUNCTION) {
        const exportName = name
        exports[exportName] = (...args) => {
          if (_traceAllImports) _log(PREFIX + ' export ' + exportName + ' start args=' + JSON.stringify(args.map(a => typeof a === 'object' ? '[obj]' : typeof a === 'function' ? '[fn]' : String(a))) + ' depth=' + _inCallExport)
          if (_inCallExport > 0 && exportName === '__wbindgen_exn_store') {
            return undefined
          }

          if (exportName === '__wbindgen_start') {
            _log(PREFIX + ' __wbindgen_start call start')
          }

          const hasNonNumber = args.some(a => typeof a !== 'number' && typeof a !== 'bigint')
          let callArgs = args
          if (hasNonNumber) {
            if (args.some(a => a !== null && a !== undefined && typeof a !== 'number' && typeof a !== 'bigint')) {
              _log(PREFIX + ' invoke args raw: ' + exportName + ' → ' + args.map(a => typeof a === 'function' ? '[fn]' : typeof a === 'object' ? '[obj]' : String(a)).join(', '))
            }
            callArgs = args.map(a => {
              if (typeof a === 'number' || typeof a === 'bigint') return a
              if (a === null) return 0
              if (a === undefined) return _extUndefinedSlot
              const idx = _extStore(a)
              _log(PREFIX + ' externref store: ' + exportName + ' arg → idx=' + idx + ' type=' + typeof a)
              return idx
            })
          }

          if (_instHandle !== null) {
            const _mb = binding.getMemory(_instHandle)
            if (_mb.byteLength !== _prevMemBuf?.byteLength) {
              _log(PREFIX + ' mem@export grow detected: ' + (_prevMemBuf ? _prevMemBuf.byteLength : 0) + ' -> ' + _mb.byteLength)
              _prevMemBuf = _mb
            }
          }

          let r
          _inCallExport++
          try {
            r = binding.callExport(_instHandle, exportName, callArgs)
          } catch (e) {
            _inCallExport--
            if (_inCallExport === 0) {
              _flushPendingMicrotasks()
              if (typeof ioNudge === 'function') { _log(PREFIX + ' ioNudge (err)'); ioNudge() }
            }
            console.log(PREFIX + ' callExport ERROR: ' + exportName + ' => ' + (e && e.message) + ' callArgs=' + JSON.stringify(callArgs))
            throw e
          }
          _inCallExport--
          if (_inCallExport === 0) {
            _flushPendingMicrotasks()
            if (typeof ioNudge === 'function') { _log(PREFIX + ' ioNudge'); ioNudge() }
          }
          if (_debug && exportName === '__wbindgen_start') {
            const summary = Object.entries(_importCounts).filter(([,n]) => n > 0).map(([k,n]) => k + '=' + n).join(', ')
            _log(PREFIX + ' __wbindgen_start call done; import calls: ' + (summary || '(none)'))
          }
          if (typeof r === 'number' && _returnExports.has(exportName)) {
            const extVal = _resolveExtref(r)
            _log(PREFIX + ' externref-return: ' + exportName + ' slot=' + r + ' resolved=' + typeof extVal)
            return extVal
          }
          return r
        }
      } else if (kind === EXPORT_KIND_TABLE) {
        exports[name] = {
          get (idx) { return binding.tableGet(_instHandle, idx) },
          set (idx, val) { binding.tableSet(_instHandle, idx, val) },
          grow (n) { return binding.tableGrow(_instHandle, n) },
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

    // ── Externref table polyfill ─────────────────────────────────────────────
    for (const tblName of ['__wbindgen_externrefs', '__wbindgen_export_2']) {
      if (tblName in exports && exports[tblName] && typeof exports[tblName].set === 'function') {
        const orig = exports[tblName]
        exports[tblName] = {
          get (idx) { return _resolveExtref(idx) },
          set (idx, val) { _extMap.set(idx, val) },
          grow (n) { return orig.grow(n) },
          get length () { return orig.length },
        }
        _log(PREFIX + ' externref table polyfill installed for ' + tblName)
      }
    }

    // Replace __externref_table_alloc / __externref_table_dealloc with pure-JS
    exports.__externref_table_alloc = () => {
      if (_deallocdSlots.size > 0) {
        const idx = _deallocdSlots.values().next().value
        _deallocdSlots.delete(idx)
        return idx
      }
      if (_extNextIdx >= EXT_SLOT_MAX) return EXT_GROW_FAIL
      return _extNextIdx++
    }
    exports.__externref_table_dealloc = (idx) => {
      _extMap.delete(idx)
      _deallocdSlots.add(idx)
    }
    _log(PREFIX + ' __externref_table_alloc/dealloc polyfills installed')

    this.exports = exports
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
