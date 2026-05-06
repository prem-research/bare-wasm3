/**
 * bare-wasm3 — WebAssembly polyfill for Bare
 *
 * Exposes three JS functions:
 *   moduleNew(wasmBuf)          → opaque ArrayBuffer handle
 *   instanceNew(moduleHandle, importsObj) → { handle, exportsMap, memoryBuffer }
 *   callExport(instanceHandle, name, argsArray) → JS value
 *
 * The imports object follows the WebAssembly.Instance convention:
 *   { "wbg": { "__wbindgen_string_new": fn, ... } }
 *
 * libjs API NOTE: function names follow js.h conventions; verify against the
 * actual header if a build error occurs (e.g. js_create_int32 vs js_create_uint32).
 */

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <bare.h>
#include <js.h>
#include <wasm3.h>
#include "m3_env.h"   /* M3Runtime internals: memory.numPages, memory.pageSize */

/* ─── limits ──────────────────────────────────────────────────────────────── */

#define BW3_MAX_IMPORTS  512
#define BW3_MAX_EXPORTS  512
#define BW3_MAX_FN_ARGS   16
#define BW3_MAX_TYPES    512
#define BW3_STACK_SIZE   (512 * 1024)
#define BW3_EXT_TABLE_CAP 8192  /* externref table capacity (slots) */

/* ─── LEB128 ──────────────────────────────────────────────────────────────── */

static uint32_t
leb_u32 (const uint8_t **p, const uint8_t *end) {
  uint32_t v = 0;
  int s = 0;
  while (*p < end) {
    uint8_t b = *(*p)++;
    v |= (uint32_t)(b & 0x7f) << s;
    if (!(b & 0x80)) break;
    s += 7;
  }
  return v;
}

/* ─── WASM value type → wasm3 signature character ────────────────────────── */

static char
vt_sig (uint8_t vt) {
  switch (vt) {
    case 0x7f: return 'i'; /* i32 */
    case 0x7e: return 'I'; /* i64 */
    case 0x7d: return 'f'; /* f32 */
    case 0x7c: return 'F'; /* f64 */
    case 0x6f: return 'i'; /* externref → i32 (slot index) */
    case 0x70: return 'i'; /* funcref → i32 (function index) */
    default:   return '?';
  }
}

/* ─── WASM binary metadata ────────────────────────────────────────────────── */

typedef struct {
  char    module[64];
  char    name[128];
  char    sig[32];          /* wasm3 signature, e.g. "v(ii)" */
  int     num_params;
  int     num_results;
  uint8_t param_types[BW3_MAX_FN_ARGS];
  uint8_t result_types[4];
} bw3_import_desc_t;

typedef struct {
  char    name[128];
  uint8_t kind;             /* 0=func, 1=table, 2=memory, 3=global */
  /* Set when this func export re-exports an import (func_index < num_imports). */
  bool    is_import_reexport;
  char    import_module[64];
  char    import_name[128];
} bw3_export_desc_t;

typedef struct {
  int     num_params;
  int     num_results;
  uint8_t types[32];        /* param types then result types */
} bw3_functype_t;

typedef struct {
  bw3_functype_t    ftypes[BW3_MAX_TYPES];
  int               ftype_count;
  bw3_import_desc_t imports[BW3_MAX_IMPORTS];
  int               import_count;
  bw3_export_desc_t exports[BW3_MAX_EXPORTS];
  int               export_count;
} bw3_wasm_meta_t;

static int
parse_wasm_meta (const uint8_t *wasm, size_t len, bw3_wasm_meta_t *out) {
  memset(out, 0, sizeof(*out));
  if (len < 8 || memcmp(wasm, "\0asm", 4) != 0) return -1;

  const uint8_t *p = wasm + 8;
  const uint8_t *end = wasm + len;

  /* locate sections */
  const uint8_t *type_sec = NULL, *import_sec = NULL, *export_sec = NULL;
  size_t type_sz = 0, import_sz = 0, export_sz = 0;

  while (p < end) {
    uint8_t id = *p++;
    uint32_t sz = leb_u32(&p, end);
    if (id == 1) { type_sec = p; type_sz = sz; }
    if (id == 2) { import_sec = p; import_sz = sz; }
    if (id == 7) { export_sec = p; export_sz = sz; }
    p += sz;
  }

  /* parse type section */
  if (type_sec) {
    const uint8_t *tp = type_sec, *te = type_sec + type_sz;
    int tc = (int)leb_u32(&tp, te);
    if (tc > BW3_MAX_TYPES) tc = BW3_MAX_TYPES;
    for (int i = 0; i < tc && tp < te; i++) {
      if (*tp++ != 0x60) break;
      int np = (int)leb_u32(&tp, te);
      out->ftypes[i].num_params = np;
      for (int j = 0; j < np && j < (int)sizeof(out->ftypes[i].types) && tp < te; j++)
        out->ftypes[i].types[j] = *tp++;
      for (int j = np; j < np; j++) if (tp < te) tp++;  /* skip overflow */
      int nr = (int)leb_u32(&tp, te);
      out->ftypes[i].num_results = nr;
      for (int j = 0; j < nr && np + j < (int)sizeof(out->ftypes[i].types) && tp < te; j++)
        out->ftypes[i].types[np + j] = *tp++;
      out->ftype_count = i + 1;
    }
  }

  /* parse import section */
  if (import_sec) {
    const uint8_t *ip = import_sec, *ie = import_sec + import_sz;
    int ic = (int)leb_u32(&ip, ie);
    int fc = 0;

    for (int i = 0; i < ic && ip < ie && fc < BW3_MAX_IMPORTS; i++) {
      /* module name */
      int mlen = (int)leb_u32(&ip, ie);
      int mcap = mlen < 63 ? mlen : 63;
      memcpy(out->imports[fc].module, ip, mcap);
      out->imports[fc].module[mcap] = 0;
      ip += mlen;

      /* field name */
      int nlen = (int)leb_u32(&ip, ie);
      int ncap = nlen < 127 ? nlen : 127;
      memcpy(out->imports[fc].name, ip, ncap);
      out->imports[fc].name[ncap] = 0;
      ip += nlen;

      uint8_t kind = *ip++;

      if (kind == 0) { /* function */
        int tidx = (int)leb_u32(&ip, ie);
        if (tidx < out->ftype_count) {
          bw3_functype_t *ft = &out->ftypes[tidx];
          int np = ft->num_params;
          int nr = ft->num_results;
          out->imports[fc].num_params  = np;
          out->imports[fc].num_results = nr;
          for (int j = 0; j < np && j < BW3_MAX_FN_ARGS; j++)
            out->imports[fc].param_types[j] = ft->types[j];
          for (int j = 0; j < nr && j < 4; j++)
            out->imports[fc].result_types[j] = ft->types[np + j];

          /* build wasm3 signature */
          char *sig = out->imports[fc].sig;
          *sig++ = (nr > 0) ? vt_sig(ft->types[np]) : 'v';
          *sig++ = '(';
          for (int j = 0; j < np; j++) *sig++ = vt_sig(ft->types[j]);
          *sig++ = ')';
          *sig   = 0;
        } else {
          strcpy(out->imports[fc].sig, "v()");
        }
        fc++;

      } else if (kind == 1) { /* table: reftype + limits */
        ip++;
        uint8_t flags = *ip++;
        leb_u32(&ip, ie);
        if (flags & 1) leb_u32(&ip, ie);
      } else if (kind == 2) { /* memory: limits */
        uint8_t flags = *ip++;
        leb_u32(&ip, ie);
        if (flags & 1) leb_u32(&ip, ie);
      } else if (kind == 3) { /* global: valtype + mutability */
        ip++; ip++;
      }
    }
    out->import_count = fc;
  }

  /* parse export section */
  if (export_sec) {
    const uint8_t *ep = export_sec, *ee = export_sec + export_sz;
    int ec = (int)leb_u32(&ep, ee);
    if (ec > BW3_MAX_EXPORTS) ec = BW3_MAX_EXPORTS;
    for (int i = 0; i < ec && ep < ee; i++) {
      int nlen = (int)leb_u32(&ep, ee);
      int ncap = nlen < 127 ? nlen : 127;
      memcpy(out->exports[i].name, ep, ncap);
      out->exports[i].name[ncap] = 0;
      ep += nlen;
      out->exports[i].kind = *ep++;
      uint32_t func_index = leb_u32(&ep, ee);
      /* Detect re-exports of imported functions: if the export's function index
       * falls within the import range, wasm3 won't tag it via export_name and
       * m3_FindFunction will fail. We capture the original import identity so
       * the JS layer can wire it directly to the JS import function. */
      if (out->exports[i].kind == 0 &&
          (int)func_index < out->import_count) {
        out->exports[i].is_import_reexport = true;
        strncpy(out->exports[i].import_module,
                out->imports[func_index].module, 63);
        out->exports[i].import_module[63] = 0;
        strncpy(out->exports[i].import_name,
                out->imports[func_index].name, 127);
        out->exports[i].import_name[127] = 0;
      }
      out->export_count = i + 1;
    }
  }

  return 0;
}

/* ─── Module handle ───────────────────────────────────────────────────────── */

typedef struct {
  uint8_t        *wasm_bytes;  /* pointer into pinned JS buffer — no copy */
  size_t          wasm_len;
  bw3_wasm_meta_t meta;
  js_ref_t       *js_buf_ref;  /* persistent ref keeps the JS buffer alive */
  js_env_t       *env;
} bw3_module_t;

/* ─── Instance state ──────────────────────────────────────────────────────── */

typedef struct bw3_instance bw3_instance_t;

typedef struct {
  js_env_t          *env;
  js_ref_t          *fn_ref;
  bw3_import_desc_t *desc;   /* back-pointer into inst->mod->meta.imports[i] */
  bw3_instance_t    *inst;
} bw3_bridge_t;

/* Externref table context — layout must match bw3_ext_ctx_ops_t in m3_exec.h. */
typedef struct {
  uint32_t  ext_size;   /* logical size (number of live slots) */
  uint32_t  ext_cap;    /* allocated capacity */
  uint32_t *ext_vals;   /* slot values (indices into JS _extMap) */
} bw3_ext_ctx_t;

struct bw3_instance {
  IM3Environment  m3env;
  IM3Runtime      m3rt;
  IM3Module       m3mod;
  js_env_t       *env;
  bw3_module_t   *mod;       /* back-pointer (not owned) */
  bw3_bridge_t    bridges[BW3_MAX_IMPORTS];
  int             bridge_count;
  bool            js_exc_pending;
  /* Cached memory ArrayBuffer — same object while base pointer hasn't changed.
   * This matches real WebAssembly.Memory semantics: .buffer identity is stable
   * until memory.grow, allowing wasm-bindgen's cache checks to work correctly. */
  js_ref_t       *mem_ref;        /* persistent reference to current memory buffer */
  uint8_t        *mem_base;       /* last known linear memory base pointer */
  uint32_t        mem_size_cached;/* size of cached buffer (detect in-place grows) */
  /* Externref table (reference types proposal).
   * userdata = &ext_ctx so the new ops (op_ExtTableGrow/Set/Get) can reach it.
   * ext_vals stores i32 values written by WASM table.set 1 (these are _extMap
   * indices that JS can resolve via wasm.__wbindgen_externrefs.get / _extMap). */
  bw3_ext_ctx_t   ext_ctx;
  uint32_t        ext_vals[BW3_EXT_TABLE_CAP];  /* slot → i32 value */
  js_ref_t       *ext_refs[BW3_EXT_TABLE_CAP];  /* slot → persistent JS ref (legacy) */
};

/* ─── Import bridge: wasm3 → JS ──────────────────────────────────────────── */

static const void *
bw3_import_bridge (IM3Runtime runtime, IM3ImportContext ctx, uint64_t *sp, void *mem) {
  bw3_bridge_t      *br   = (bw3_bridge_t *)ctx->userdata;
  js_env_t          *env  = br->env;
  bw3_import_desc_t *desc = br->desc;
  int err;

  int np = desc->num_params;
  int nr = desc->num_results;

  /* Args start after the return slot(s) */
  uint64_t *arg_sp = sp + nr;

  /* Debug: print raw stack for key imports */
  bool _dbg = (strcmp(desc->name, "__wbg_static_accessor_SELF_24f78b6d23f286ea") == 0 ||
               strcmp(desc->name, "__wbg___wbindgen_is_undefined_c0cca72b82b86f4d") == 0 ||
               strcmp(desc->name, "__wbg_queueMicrotask_abaf92f0bd4e80a4") == 0);
  if (_dbg) {
    fprintf(stderr, "[bw3-c] %s np=%d nr=%d sp[0]=0x%016llx sp[1]=0x%016llx sp[2]=0x%016llx\n",
            desc->name, np, nr,
            (unsigned long long)sp[0],
            (unsigned long long)sp[1],
            (unsigned long long)sp[2]);
    for (int _i = 0; _i < np; _i++) {
      fprintf(stderr, "[bw3-c]   arg[%d] raw=0x%016llx i32=%d\n", _i,
              (unsigned long long)arg_sp[_i], *(int32_t*)&arg_sp[_i]);
    }
    fflush(stderr);
  }

  /* Convert WASM stack args → JS values */
  js_value_t *js_args[BW3_MAX_FN_ARGS];
  for (int i = 0; i < np && i < BW3_MAX_FN_ARGS; i++) {
    switch (desc->param_types[i]) {
      case 0x7f: { /* i32 */
        int32_t v = *(int32_t *)&arg_sp[i];
        err = js_create_int32(env, v, &js_args[i]);
        assert(err == 0);
        break;
      }
      case 0x7e: { /* i64 */
        int64_t v = *(int64_t *)&arg_sp[i];
        err = js_create_int64(env, v, &js_args[i]);
        assert(err == 0);
        break;
      }
      case 0x7d: { /* f32 */
        float v;
        memcpy(&v, &arg_sp[i], sizeof(float));
        err = js_create_double(env, (double)v, &js_args[i]);
        assert(err == 0);
        break;
      }
      case 0x7c: { /* f64 */
        double v;
        memcpy(&v, &arg_sp[i], sizeof(double));
        err = js_create_double(env, v, &js_args[i]);
        assert(err == 0);
        break;
      }
      case 0x6f: { /* externref — pass raw i32; JS wrapper resolves via _extMap */
        int32_t v = *(int32_t *)&arg_sp[i];
        err = js_create_int32(env, v, &js_args[i]);
        assert(err == 0);
        break;
      }
      default: {
        err = js_get_undefined(env, &js_args[i]);
        assert(err == 0);
        break;
      }
    }
  }

  /* Retrieve the JS function */
  js_value_t *fn;
  err = js_get_reference_value(env, br->fn_ref, &fn);
  assert(err == 0);

  js_value_t *recv;
  err = js_get_undefined(env, &recv);
  assert(err == 0);

  /* Call JS import function */
  js_value_t *result = NULL;
  err = js_call_function(env, recv, fn, (size_t)np, js_args, &result);
  if (err != 0) {
    br->inst->js_exc_pending = true;
    return "js_exception";
  }

  /* Write return value into WASM stack slot */
  if (nr > 0 && result != NULL) {
    switch (desc->result_types[0]) {
      case 0x7f: { /* i32 */
        int32_t v = 0;
        js_get_value_int32(env, result, &v);
        *(int32_t *)&sp[0] = v;
        break;
      }
      case 0x7e: { /* i64 */
        int64_t v = 0;
        js_get_value_int64(env, result, &v);
        *(int64_t *)&sp[0] = v;
        break;
      }
      case 0x7d: { /* f32 */
        double d = 0;
        js_get_value_double(env, result, &d);
        float f = (float)d;
        memcpy(&sp[0], &f, sizeof(float));
        break;
      }
      case 0x7c: { /* f64 */
        double v = 0;
        js_get_value_double(env, result, &v);
        memcpy(&sp[0], &v, sizeof(double));
        break;
      }
      case 0x6f: { /* externref — JS returns i32 index into _extMap */
        int32_t v = 0;
        js_get_value_int32(env, result, &v);
        *(int32_t *)&sp[0] = v;
        if (_dbg) fprintf(stderr, "[bw3-c]   return externref: wrote i32=%d to sp[0]=0x%p (sp[0] now=0x%016llx)\n",
                          v, (void*)&sp[0], (unsigned long long)sp[0]);
        fflush(stderr);
        break;
      }
    }
  }

  return m3Err_none;
}

/* ─── JS binding functions ────────────────────────────────────────────────── */

/**
 * moduleNew(wasmBuffer: Buffer) → ArrayBuffer (opaque handle)
 *
 * Validates the WASM magic, pins the JS buffer via a persistent reference
 * (no copy — wasm3 stores raw pointers into the original bytes), parses
 * metadata, and returns a pointer-sized ArrayBuffer handle.
 */
static js_value_t *
bw3_module_new (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uint8_t *wasm_data;
  size_t   wasm_len;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&wasm_data, &wasm_len);
  if (err != 0) {
    err = js_throw_error(env, NULL, "moduleNew: argument must be an ArrayBuffer/Buffer");
    assert(err == 0);
    return NULL;
  }

  bw3_module_t *mod = (bw3_module_t *)calloc(1, sizeof(bw3_module_t));
  if (!mod) {
    err = js_throw_error(env, NULL, "moduleNew: out of memory");
    assert(err == 0);
    return NULL;
  }

  /* Pin the JS buffer so its backing memory stays valid for the module's
   * lifetime. This avoids a 3–4 MB malloc+memcpy peak that would OOM on
   * constrained worklet processes when the audio file is also in memory. */
  js_ref_t *buf_ref;
  err = js_create_reference(env, argv[0], 1, &buf_ref);
  if (err != 0) {
    free(mod);
    err = js_throw_error(env, NULL, "moduleNew: out of memory");
    assert(err == 0);
    return NULL;
  }

  mod->wasm_bytes = wasm_data;
  mod->wasm_len   = wasm_len;
  mod->js_buf_ref = buf_ref;
  mod->env        = env;

  if (parse_wasm_meta(mod->wasm_bytes, mod->wasm_len, &mod->meta) != 0) {
    js_delete_reference(env, buf_ref);
    free(mod);
    err = js_throw_error(env, NULL, "moduleNew: invalid WASM binary");
    assert(err == 0);
    return NULL;
  }

  /* Store pointer in an ArrayBuffer so GC keeps it alive.
   * Lifetime: the JS caller must hold this handle alive during instanceNew. */
  js_value_t *handle;
  uintptr_t  *slot;
  err = js_create_arraybuffer(env, sizeof(uintptr_t), (void **)&slot, &handle);
  assert(err == 0);
  *slot = (uintptr_t)mod;

  return handle;
}

/**
 * instanceNew(moduleHandle, importsObj)
 *   → { handle: ArrayBuffer, exportsMap: {name→kind}, memoryBuffer: ArrayBuffer }
 *
 * Creates a wasm3 runtime, links all imports as raw C callbacks that call back
 * into the provided JS functions, and instantiates the module.
 */
static js_value_t *
bw3_instance_new (js_env_t *env, js_callback_info_t *info) {
  int err;
  M3Result m3err;

  size_t argc = 2;
  js_value_t *argv[2];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  /* Recover bw3_module_t pointer */
  uintptr_t *mod_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&mod_slot, NULL);
  if (err != 0) {
    err = js_throw_error(env, NULL, "instanceNew: invalid module handle");
    assert(err == 0);
    return NULL;
  }
  bw3_module_t *mod = (bw3_module_t *)(uintptr_t)*mod_slot;

  js_value_t *imports_arg = argv[1];

  /* Allocate instance */
  bw3_instance_t *inst = (bw3_instance_t *)calloc(1, sizeof(bw3_instance_t));
  if (!inst) {
    err = js_throw_error(env, NULL, "instanceNew: out of memory");
    assert(err == 0);
    return NULL;
  }
  inst->env = env;
  inst->mod = mod;
  inst->js_exc_pending = false;

  /* wasm3 setup */
  inst->m3env = m3_NewEnvironment();
  if (!inst->m3env) {
    free(inst);
    err = js_throw_error(env, NULL, "instanceNew: m3_NewEnvironment failed");
    assert(err == 0);
    return NULL;
  }

  inst->ext_ctx.ext_size = 0;   /* __wbindgen_init_externref_table will grow(4) */
  inst->ext_ctx.ext_cap  = BW3_EXT_TABLE_CAP;
  inst->ext_ctx.ext_vals = inst->ext_vals;
  inst->m3rt = m3_NewRuntime(inst->m3env, BW3_STACK_SIZE, &inst->ext_ctx);
  if (!inst->m3rt) {
    m3_FreeEnvironment(inst->m3env);
    free(inst);
    err = js_throw_error(env, NULL, "instanceNew: m3_NewRuntime failed");
    assert(err == 0);
    return NULL;
  }

  m3err = m3_ParseModule(inst->m3env, &inst->m3mod,
                         mod->wasm_bytes, (uint32_t)mod->wasm_len);
  if (m3err) {
    m3_FreeRuntime(inst->m3rt);
    m3_FreeEnvironment(inst->m3env);
    free(inst);
    err = js_throw_error(env, NULL, m3err);
    assert(err == 0);
    return NULL;
  }

  m3err = m3_LoadModule(inst->m3rt, inst->m3mod);
  if (m3err) {
    m3_FreeRuntime(inst->m3rt);
    m3_FreeEnvironment(inst->m3env);
    free(inst);
    err = js_throw_error(env, NULL, m3err);
    assert(err == 0);
    return NULL;
  }

  /* Link imports: for each function import, find the JS function in importsObj
   * and register a raw wasm3 callback that calls it. */
  bw3_wasm_meta_t *meta = &mod->meta;
  inst->bridge_count = 0;

  for (int i = 0; i < meta->import_count; i++) {
    bw3_import_desc_t *desc = &meta->imports[i];

    /* Get importsObj[module_name] */
    js_value_t *module_obj;
    err = js_get_named_property(env, imports_arg, desc->module, &module_obj);
    if (err != 0) continue;

    /* Get importsObj[module_name][func_name] */
    js_value_t *fn;
    err = js_get_named_property(env, module_obj, desc->name, &fn);
    if (err != 0) continue;

    /* Check it's callable */
    bool is_fn = false;
    js_is_function(env, fn, &is_fn);
    if (!is_fn) continue;

    /* Persistent reference so the function survives across WASM calls */
    int bi = inst->bridge_count;
    err = js_create_reference(env, fn, 1, &inst->bridges[bi].fn_ref);
    assert(err == 0);

    inst->bridges[bi].env  = env;
    inst->bridges[bi].desc = desc;
    inst->bridges[bi].inst = inst;
    inst->bridge_count++;

    /* Register with wasm3.  Errors for unresolved imports are non-fatal;
     * wasm3 will trap only if the WASM actually calls a missing import. */
    m3_LinkRawFunctionEx(inst->m3mod, desc->module, desc->name,
                         desc->sig, bw3_import_bridge, &inst->bridges[bi]);
  }

  /* Do NOT call __wbindgen_start here.
   * It is a regular wasm-bindgen export, NOT the WASM start-section function.
   * m3_LoadModule already handles the WASM start section automatically.
   * The JS glue code (reticle_main.js line 1982) calls wasm.__wbindgen_start()
   * explicitly after instantiation — running it here would execute it twice,
   * blocking the thread for the entire wasm3-interpreted cost twice over. */

  /* Eagerly compile all WASM functions to M3Code now, while imports are fully
   * linked.  Without this, wasm3 compiles each function on its first call
   * (lazy), blocking the JS thread for unpredictable durations mid-request.
   * Paying the cost once here moves it to instanceNew (SDK init), where the
   * caller already expects a one-time setup delay.  Errors are non-fatal:
   * uncompiled functions will still trap on first call, and the patched wasm3
   * we ship supports all opcodes in reticle_bg.wasm. */
  m3err = m3_CompileModule(inst->m3mod);
  if (m3err) {
    /* Log but continue — partial compilation is still better than none. */
    fprintf(stderr, "[bare-wasm3] m3_CompileModule warning: %s\n", m3err);
  }

  /* ── Build return value ────────────────────────────────────────────────── */

  /* Instance handle (pointer stored in ArrayBuffer) */
  js_value_t *inst_handle;
  uintptr_t  *inst_slot;
  err = js_create_arraybuffer(env, sizeof(uintptr_t), (void **)&inst_slot, &inst_handle);
  assert(err == 0);
  *inst_slot = (uintptr_t)inst;

  /* exportsMap: { name: kind } */
  js_value_t *exports_map;
  err = js_create_object(env, &exports_map);
  assert(err == 0);

  for (int i = 0; i < meta->export_count; i++) {
    js_value_t *kind_val;
    err = js_create_uint32(env, meta->exports[i].kind, &kind_val);
    assert(err == 0);
    err = js_set_named_property(env, exports_map, meta->exports[i].name, kind_val);
    assert(err == 0);
  }

  /* importReexports: { exportName: { module, name } }
   * Exports that point at imported functions — wasm3 cannot find these via
   * m3_FindFunction, so the JS layer must wire them to the JS import directly. */
  js_value_t *import_reexports;
  err = js_create_object(env, &import_reexports);
  assert(err == 0);

  for (int i = 0; i < meta->export_count; i++) {
    if (!meta->exports[i].is_import_reexport) continue;
    js_value_t *entry;
    err = js_create_object(env, &entry);
    assert(err == 0);
    js_value_t *mod_str, *name_str;
    err = js_create_string_utf8(env, meta->exports[i].import_module,
                                strlen(meta->exports[i].import_module), &mod_str);
    assert(err == 0);
    err = js_create_string_utf8(env, meta->exports[i].import_name,
                                strlen(meta->exports[i].import_name), &name_str);
    assert(err == 0);
    err = js_set_named_property(env, entry, "module", mod_str);
    assert(err == 0);
    err = js_set_named_property(env, entry, "name", name_str);
    assert(err == 0);
    err = js_set_named_property(env, import_reexports,
                                meta->exports[i].name, entry);
    assert(err == 0);
  }

  /* Pack into result object.  memoryBuffer is intentionally omitted here;
   * the JS layer uses the getMemory() getter to get a properly cached,
   * identity-stable ArrayBuffer that matches WebAssembly.Memory semantics. */
  js_value_t *result_obj;
  err = js_create_object(env, &result_obj);
  assert(err == 0);

  err = js_set_named_property(env, result_obj, "handle", inst_handle);
  assert(err == 0);
  err = js_set_named_property(env, result_obj, "exportsMap", exports_map);
  assert(err == 0);
  err = js_set_named_property(env, result_obj, "importReexports", import_reexports);
  assert(err == 0);

  return result_obj;
}

/**
 * callExport(instanceHandle, name: string, args: any[]) → any
 *
 * Calls a WASM export function by name with the provided JS arguments.
 * Converts between JS values and wasm3 typed values.
 */
static js_value_t *
bw3_call_export (js_env_t *env, js_callback_info_t *info) {
  int err;
  M3Result m3err;

  size_t argc = 3;
  js_value_t *argv[3];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  /* Instance handle */
  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) {
    err = js_throw_error(env, NULL, "callExport: invalid instance handle");
    assert(err == 0);
    return NULL;
  }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  /* Function name */
  size_t name_len = 0;
  err = js_get_value_string_utf8(env, argv[1], NULL, 0, &name_len);
  assert(err == 0);
  utf8_t *fn_name = (utf8_t *)malloc(name_len + 1);
  err = js_get_value_string_utf8(env, argv[1], fn_name, name_len + 1, &name_len);
  assert(err == 0);
  fn_name[name_len] = 0;

  /* Find the wasm3 function */
  IM3Function fn;
  m3err = m3_FindFunction(&fn, inst->m3rt, (const char *)fn_name);
  free(fn_name);
  if (m3err) {
    err = js_throw_error(env, NULL, m3err);
    assert(err == 0);
    return NULL;
  }

  /* Args array: argv[2] is a JS Array */
  uint32_t js_argc = 0;
  js_get_array_length(env, argv[2], &js_argc);  /* 0 if not an array */

  uint32_t wasm_argc = m3_GetArgCount(fn);
  uint32_t wasm_retc = m3_GetRetCount(fn);

  /* Read JS args → typed WASM values */
  int32_t  i32v[BW3_MAX_FN_ARGS];
  int64_t  i64v[BW3_MAX_FN_ARGS];
  float    f32v[BW3_MAX_FN_ARGS];
  double   f64v[BW3_MAX_FN_ARGS];
  const void *arg_ptrs[BW3_MAX_FN_ARGS];

  uint32_t n = wasm_argc < (uint32_t)BW3_MAX_FN_ARGS ? wasm_argc : (uint32_t)BW3_MAX_FN_ARGS;
  for (uint32_t i = 0; i < n; i++) {
    js_value_t *el;
    js_get_element(env, argv[2], i, &el);
    M3ValueType vt = m3_GetArgType(fn, i);
    switch (vt) {
      case c_m3Type_i32:
        js_get_value_int32(env, el, &i32v[i]);
        arg_ptrs[i] = &i32v[i];
        break;
      case c_m3Type_i64:
        js_get_value_int64(env, el, &i64v[i]);
        arg_ptrs[i] = &i64v[i];
        break;
      case c_m3Type_f32: {
        double d = 0;
        js_get_value_double(env, el, &d);
        f32v[i] = (float)d;
        arg_ptrs[i] = &f32v[i];
        break;
      }
      case c_m3Type_f64:
        js_get_value_double(env, el, &f64v[i]);
        arg_ptrs[i] = &f64v[i];
        break;
      default:
        i32v[i] = 0;
        arg_ptrs[i] = &i32v[i];
        break;
    }
  }

  /* Call */
  inst->js_exc_pending = false;
  m3err = m3_Call(fn, n, arg_ptrs);

  if (m3err) {
    if (inst->js_exc_pending) {
      inst->js_exc_pending = false;
      return NULL; /* exception already pending in env */
    }
    err = js_throw_error(env, NULL, m3err);
    assert(err == 0);
    return NULL;
  }

  /* Return value(s) */
  if (wasm_retc == 0) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  uint32_t nr = wasm_retc < (uint32_t)BW3_MAX_FN_ARGS ? wasm_retc : (uint32_t)BW3_MAX_FN_ARGS;
  int32_t  ret_i32v[BW3_MAX_FN_ARGS]; memset(ret_i32v, 0, sizeof(ret_i32v));
  int64_t  ret_i64v[BW3_MAX_FN_ARGS]; memset(ret_i64v, 0, sizeof(ret_i64v));
  float    ret_f32v[BW3_MAX_FN_ARGS]; memset(ret_f32v, 0, sizeof(ret_f32v));
  double   ret_f64v[BW3_MAX_FN_ARGS]; memset(ret_f64v, 0, sizeof(ret_f64v));
  const void *ret_ptrs[BW3_MAX_FN_ARGS];

  for (uint32_t i = 0; i < nr; i++) {
    M3ValueType vt = m3_GetRetType(fn, i);
    switch (vt) {
      case c_m3Type_i32: ret_ptrs[i] = &ret_i32v[i]; break;
      case c_m3Type_i64: ret_ptrs[i] = &ret_i64v[i]; break;
      case c_m3Type_f32: ret_ptrs[i] = &ret_f32v[i]; break;
      case c_m3Type_f64: ret_ptrs[i] = &ret_f64v[i]; break;
      default:           ret_ptrs[i] = &ret_i32v[i]; break;
    }
  }
  m3_GetResults(fn, nr, ret_ptrs);

  if (wasm_retc == 1) {
    M3ValueType rt = m3_GetRetType(fn, 0);
    js_value_t *ret_val;
    switch (rt) {
      case c_m3Type_i32: js_create_int32(env, ret_i32v[0], &ret_val);             break;
      case c_m3Type_i64: js_create_int64(env, ret_i64v[0], &ret_val);             break;
      case c_m3Type_f32: js_create_double(env, (double)ret_f32v[0], &ret_val);    break;
      case c_m3Type_f64: js_create_double(env, ret_f64v[0], &ret_val);            break;
      default:           js_get_undefined(env, &ret_val);                          break;
    }
    return ret_val;
  }

  /* Multi-return: return JS Array matching WebAssembly.Instance semantics */
  js_value_t *arr;
  js_create_array_with_length(env, nr, &arr);
  for (uint32_t i = 0; i < nr; i++) {
    M3ValueType vt = m3_GetRetType(fn, i);
    js_value_t *el;
    switch (vt) {
      case c_m3Type_i32: js_create_int32(env, ret_i32v[i], &el);             break;
      case c_m3Type_i64: js_create_int64(env, ret_i64v[i], &el);             break;
      case c_m3Type_f32: js_create_double(env, (double)ret_f32v[i], &el);    break;
      case c_m3Type_f64: js_create_double(env, ret_f64v[i], &el);            break;
      default:           js_get_undefined(env, &el);                          break;
    }
    js_set_element(env, arr, i, el);
  }
  return arr;
}

/**
 * getMemory(instanceHandle) → ArrayBuffer
 *
 * Returns the current linear memory ArrayBuffer, caching the object so that
 * wasm-bindgen's identity-based cache checks work correctly.
 *
 * Real WebAssembly.Memory semantics: `memory.buffer` returns the SAME
 * ArrayBuffer until `memory.grow` is called, at which point a new one is
 * returned (and the old one is detached).  We match this by tracking the
 * wasm3 base pointer and only creating a new JS object when it changes.
 *
 * Two wasm-bindgen cache patterns are therefore handled correctly:
 *   • `buffer === 0` check: old view still has byteLength > 0 until the
 *     base pointer changes and we swap to a new external buffer.
 *   • `buf !== wasm.memory.buffer` check: stable identity while no grow,
 *     new identity after grow → cache is invalidated exactly when needed.
 */
static js_value_t *
bw3_get_memory (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  uint32_t mem_size = 0;
  uint8_t *mem_ptr  = m3_GetMemory(inst->m3rt, &mem_size, 0);
  if (!mem_ptr || mem_size == 0) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  /* m3_GetMemory reads mallocated->length, but numPages*pageSize may diverge if
   * ResizeMemory updated numPages but the header's length field was stale.
   * Take the maximum so the returned buffer is always large enough. */
  {
    uint32_t pages_size = inst->m3rt->memory.numPages * (uint32_t)inst->m3rt->memory.pageSize;
    if (pages_size > mem_size) {
      fprintf(stderr, "[bw3] getMemory: mallocated->length=%u < numPages*pageSize=%u, using pages_size\n",
              mem_size, pages_size);
      mem_size = pages_size;
    }
  }

  /* Return cached ArrayBuffer if the wasm3 base pointer AND size haven't changed.
   * Checking size is essential for in-place memory.grow (iOS/mmap: same pointer,
   * larger size) — without it the cached ArrayBuffer would be stale but undetected. */
  if (mem_ptr == inst->mem_base && mem_size == inst->mem_size_cached && inst->mem_ref != NULL) {
    js_value_t *cached;
    err = js_get_reference_value(env, inst->mem_ref, &cached);
    if (err == 0 && cached != NULL) return cached;
  }

  /* Base pointer changed (memory.grow) or first call — allocate a new
   * external ArrayBuffer pointing directly at wasm3's linear memory.
   * Detach the old ArrayBuffer first so that wasm-bindgen's byteLength===0
   * cache check fires and it picks up the new, larger buffer. */
  if (inst->mem_ref != NULL) {
    js_value_t *old_buf;
    if (js_get_reference_value(env, inst->mem_ref, &old_buf) == 0 && old_buf != NULL) {
      js_detach_arraybuffer(env, old_buf);
    }
    js_delete_reference(env, inst->mem_ref);
    inst->mem_ref  = NULL;
    inst->mem_base = NULL;
  }

  js_value_t *mem_buf;
  err = js_create_external_arraybuffer(env, mem_ptr, mem_size, NULL, NULL, &mem_buf);
  if (err != 0) {
    /* Fallback: copy into a regular ArrayBuffer.  Writes from JS imports
     * won't propagate to WASM memory, but at least we won't crash. */
    void *copy;
    err = js_create_arraybuffer(env, mem_size, &copy, &mem_buf);
    assert(err == 0);
    memcpy(copy, mem_ptr, mem_size);
  }

  /* Pin the new buffer with a persistent reference so GC keeps it alive and
   * so we can return the same object on subsequent calls. */
  err = js_create_reference(env, mem_buf, 1, &inst->mem_ref);
  if (err == 0) { inst->mem_base = mem_ptr; inst->mem_size_cached = mem_size; }

  return mem_buf;
}

/* ─── Externref table JS bindings ─────────────────────────────────────────── */

/* tableSet(instHandle, idx: u32, val: any) → undefined
 * Stores a persistent JS reference in the externref table at slot `idx`. */
static js_value_t *
bw3_table_set (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 3;
  js_value_t *argv[3];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) { js_throw_error(env, NULL, "tableSet: bad handle"); return NULL; }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  uint32_t idx = 0;
  js_get_value_uint32(env, argv[1], &idx);
  if (idx >= BW3_EXT_TABLE_CAP) {
    js_throw_error(env, NULL, "tableSet: index out of range");
    return NULL;
  }

  /* Delete old reference if present */
  if (inst->ext_refs[idx]) {
    js_delete_reference(env, inst->ext_refs[idx]);
    inst->ext_refs[idx] = NULL;
  }

  /* Skip storing if value is null or undefined */
  bool is_null = false, is_undef = false;
  js_is_null(env, argv[2], &is_null);
  js_is_undefined(env, argv[2], &is_undef);
  if (!is_null && !is_undef) {
    js_ref_t *ref;
    err = js_create_reference(env, argv[2], 1, &ref);
    assert(err == 0);
    inst->ext_refs[idx] = ref;
  }

  js_value_t *undef;
  js_get_undefined(env, &undef);
  return undef;
}

/* tableGet(instHandle, idx: u32) → any
 * Returns the JS value stored at externref table slot `idx`. */
static js_value_t *
bw3_table_get (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 2;
  js_value_t *argv[2];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) { js_throw_error(env, NULL, "tableGet: bad handle"); return NULL; }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  uint32_t idx = 0;
  js_get_value_uint32(env, argv[1], &idx);
  if (idx >= BW3_EXT_TABLE_CAP || !inst->ext_refs[idx]) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  js_value_t *val;
  err = js_get_reference_value(env, inst->ext_refs[idx], &val);
  assert(err == 0);
  return val;
}

/* tableGrow(instHandle, n: u32) → u32 (old size, or 0xFFFFFFFF on failure)
 * Grows the externref table by `n` slots and returns the previous size. */
static js_value_t *
bw3_table_grow (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 2;
  js_value_t *argv[2];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) { js_throw_error(env, NULL, "tableGrow: bad handle"); return NULL; }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  uint32_t n = 0;
  js_get_value_uint32(env, argv[1], &n);

  uint32_t old_size = inst->ext_ctx.ext_size;
  js_value_t *ret;
  if (old_size + n > inst->ext_ctx.ext_cap) {
    err = js_create_int32(env, -1, &ret);
  } else {
    inst->ext_ctx.ext_size += n;
    err = js_create_uint32(env, old_size, &ret);
  }
  assert(err == 0);
  return ret;
}

/* tableSize(instHandle) → u32
 * Returns the current logical size of the externref table. */
static js_value_t *
bw3_table_size (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) { js_throw_error(env, NULL, "tableSize: bad handle"); return NULL; }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  js_value_t *ret;
  err = js_create_uint32(env, inst->ext_ctx.ext_size, &ret);
  assert(err == 0);
  return ret;
}

/* extvalGet(instHandle, idx: u32) → u32
 * Returns inst->ext_vals[idx] — the i32 externref slot index stored by WASM
 * table.set instructions (op_ExtTableSet).  JS uses this to resolve externref
 * args that live in wasm3's internal ext_vals table but not in _extMap. */
static js_value_t *
bw3_extval_get (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 2;
  js_value_t *argv[2];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  uintptr_t *inst_slot;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&inst_slot, NULL);
  if (err != 0) { js_throw_error(env, NULL, "extvalGet: bad handle"); return NULL; }
  bw3_instance_t *inst = (bw3_instance_t *)(uintptr_t)*inst_slot;

  uint32_t idx = 0;
  js_get_value_uint32(env, argv[1], &idx);

  js_value_t *ret;
  if (idx >= BW3_EXT_TABLE_CAP) {
    js_get_undefined(env, &ret);
  } else {
    err = js_create_uint32(env, inst->ext_vals[idx], &ret);
    assert(err == 0);
  }
  return ret;
}

/* ─── Module init ─────────────────────────────────────────────────────────── */

static js_value_t *
bw3_exports (js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

  V("moduleNew",    bw3_module_new)
  V("instanceNew",  bw3_instance_new)
  V("callExport",   bw3_call_export)
  V("getMemory",    bw3_get_memory)
  V("tableSet",     bw3_table_set)
  V("tableGet",     bw3_table_get)
  V("tableGrow",    bw3_table_grow)
  V("extvalGet",    bw3_extval_get)
  V("tableSize",    bw3_table_size)

#undef V

  return exports;
}

BARE_MODULE(bare_wasm3, bw3_exports)
