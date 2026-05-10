/**
 * bare-wasm3 — WebAssembly polyfill for Bare
 *
 * Exposes three JS functions:
 *   moduleNew(wasmBuf)          → u32 handle ID
 *   instanceNew(moduleHandle, importsObj) → { handle: u32, exportsMap, memoryBuffer }
 *   callExport(instanceHandle, name, argsArray) → JS value
 *
 * The imports object follows the WebAssembly.Instance convention:
 *   { "wbg": { "__wbindgen_string_new": fn, ... } }
 *
 * libjs API NOTE: function names follow js.h conventions; verify against the
 * actual header if a build error occurs (e.g. js_create_int32 vs js_create_uint32).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <bare.h>
#include <js.h>
#include <wasm3.h>
#include "m3_env.h"   /* M3Runtime internals: memory.numPages, memory.pageSize */

/* ─── limits ──────────────────────────────────────────────────────────────── */

#define BW3_MAX_FN_ARGS    16
#define BW3_STACK_SIZE    (512 * 1024)
#define BW3_HANDLE_INVALID 0xFFFFFFFF

/* Magic constants for handle validation — prevents raw-pointer forgery  */
#define BW3_MODULE_MAGIC   0xB7000001
#define BW3_INSTANCE_MAGIC 0xB7000002

/*
 * Handle table: maps 32-bit opaque IDs → C pointers.
 *
 * Instead of exposing raw pointers through ArrayBuffer handles (which an
 * attacker could forge), all public APIs accept a u32 handle ID.  The C
 * side resolves it through an internal table that stores the pointer and
 * magic.  The table is indexed by the low bits of the handle; the high
 * bits carry a generation counter to prevent use-after-free.
 */
#define BW3_HANDLE_TABLE_BITS 8
#define BW3_HANDLE_TABLE_SIZE (1 << BW3_HANDLE_TABLE_BITS)
#define BW3_HANDLE_GEN_SHIFT  BW3_HANDLE_TABLE_BITS
#define BW3_HANDLE_GEN_MASK   0x00FFFFFF

typedef struct {
  void     *ptr;
  uint32_t  magic;
  uint8_t   gen;         /* generation for this slot */
} bw3_handle_slot_t;

static bw3_handle_slot_t bw3_module_slots  [BW3_HANDLE_TABLE_SIZE];
static bw3_handle_slot_t bw3_instance_slots [BW3_HANDLE_TABLE_SIZE];
static uint8_t           bw3_module_next_gen [BW3_HANDLE_TABLE_SIZE];
static uint8_t           bw3_instance_next_gen [BW3_HANDLE_TABLE_SIZE];

static uint32_t
bw3_handle_alloc (bw3_handle_slot_t *slots, uint8_t *gens, void *ptr, uint32_t magic) {
  for (int i = 0; i < BW3_HANDLE_TABLE_SIZE; i++) {
    if (slots[i].ptr == NULL) {
      uint8_t gen = gens[i];
      if (gen == 0) gen = 1;  /* gen 0 means "never used" */
      slots[i].ptr   = ptr;
      slots[i].magic = magic;
      slots[i].gen   = gen;
      gens[i]        = (uint8_t)(gen + 1);
      if (gens[i] == 0) gens[i] = 1;
      return ((uint32_t)gen << BW3_HANDLE_GEN_SHIFT) | (uint32_t)i;
    }
  }
  return BW3_HANDLE_INVALID;
}

static void *
bw3_handle_resolve (bw3_handle_slot_t *slots, uint32_t handle, uint32_t expected_magic) {
  uint32_t idx = handle & (BW3_HANDLE_TABLE_SIZE - 1);
  uint32_t gen = (handle >> BW3_HANDLE_GEN_SHIFT) & BW3_HANDLE_GEN_MASK;
  bw3_handle_slot_t *s = &slots[idx];
  if (s->ptr == NULL || s->gen != (uint8_t)gen || s->magic != expected_magic)
    return NULL;
  return s->ptr;
}

static void
bw3_handle_free (bw3_handle_slot_t *slots, uint32_t handle) {
  uint32_t idx = handle & (BW3_HANDLE_TABLE_SIZE - 1);
  slots[idx].ptr   = NULL;
  slots[idx].magic = 0;
}

/* Return error helper: throw JS error and return NULL in one step */
#define BW3_THROW(msg) do { \
  int _e = js_throw_error(env, NULL, msg); \
  (void)_e; \
  return NULL; \
} while(0)

/* Check a js_* API call result, throw on failure */
#define BW3_CHECK(x, msg) do { \
  if ((x) != 0) BW3_THROW(msg); \
} while(0)

/* Debug logging — calls JS console.log so output appears in BareKit console.
 * One-shot: looks up console.log, calls it, then discards all refs. */
static void _bw3_dbg_log(js_env_t *env, const char *msg) {
  js_value_t *global, *console, *log_fn;
  if (js_get_global(env, &global) != 0) return;
  if (js_get_named_property(env, global, "console", &console) != 0) return;
  if (js_get_named_property(env, console, "log", &log_fn) != 0) return;
  js_value_t *str;
  if (js_create_string_utf8(env, (const utf8_t *)msg, strlen(msg), &str) != 0) return;
  js_value_t *undef;
  js_get_undefined(env, &undef);
  js_value_t *args[1] = { str };
  js_call_function(env, undef, log_fn, 1, args, NULL);
}

#define BW3_PREFIX "[bare-wasm3]"

#ifndef BW3_DBG_ENABLED
#define BW3_DBG_ENABLED 0
#endif
#if BW3_DBG_ENABLED
#define BW3_DBG(fmt, ...) do { \
  char _bw3_buf[512]; \
  snprintf(_bw3_buf, sizeof(_bw3_buf), BW3_PREFIX " " fmt, ##__VA_ARGS__); \
  _bw3_dbg_log(env, _bw3_buf); \
} while(0)
#else
#define BW3_DBG(fmt, ...) do {} while(0)
#endif

/* ─── LEB128 ──────────────────────────────────────────────────────────────── */

static uint32_t
leb_u32 (const uint8_t **p, const uint8_t *end) {
  uint32_t v = 0;
  int s = 0;
  while (*p < end) {
    uint8_t b = *(*p)++;
    if (s < 32) v |= (uint32_t)(b & 0x7f) << s;
    if (!(b & 0x80)) break;
    s += 7;
    if (s >= 32) break; /* u32 LEB128 is at most 5 bytes; avoid shift UB */
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
  bool    is_import_reexport;
  char    import_module[64];
  char    import_name[128];
  bool    is_externref_return; /* true if the function's first result is externref */
} bw3_export_desc_t;

typedef struct {
  int     num_params;
  int     num_results;
  uint8_t types[32];        /* param types then result types */
} bw3_functype_t;

typedef struct {
  bw3_functype_t    *ftypes;    /* heap-allocated; length = ftype_count */
  int                ftype_count;
  bw3_import_desc_t *imports;   /* heap-allocated; length = import_count */
  int                import_count;
  bw3_export_desc_t *exports;   /* heap-allocated; length = export_count */
  int                export_count;
  int                extref_init_slots;  /* max slot index + 1 used by __wbindgen_init_externref_table */
} bw3_wasm_meta_t;

static void
bw3_wasm_meta_free (bw3_wasm_meta_t *meta) {
  free(meta->ftypes);  meta->ftypes  = NULL;
  free(meta->imports); meta->imports = NULL;
  free(meta->exports); meta->exports = NULL;
}

static int
parse_wasm_meta (js_env_t *env, const uint8_t *wasm, size_t len, bw3_wasm_meta_t *out) {
  /* func_types: heap-allocated so large WASM binaries (Rust/TLS) with thousands of
   * functions don't overflow the cap and miss externref-return exports. */
  int *func_types = NULL;
  int  func_type_count = 0;

  memset(out, 0, sizeof(*out));
  if (len < 8 || memcmp(wasm, "\0asm", 4) != 0) return -1;

  const uint8_t *p = wasm + 8;
  const uint8_t *end = wasm + len;
  BW3_DBG("parse_wasm_meta: len=%zu", len);

  /* locate sections */
  const uint8_t *type_sec = NULL, *import_sec = NULL, *func_sec = NULL, *export_sec = NULL;
  const uint8_t *code_sec = NULL;
  size_t type_sz = 0, import_sz = 0, func_sz = 0, export_sz = 0, code_sz = 0;

  while (p < end) {
    uint8_t id = *p++;
    uint32_t sz = leb_u32(&p, end);
    if (sz > (size_t)(end - p)) break; /* malformed: section overflows binary */
    if (id == 1)  { type_sec = p;   type_sz = sz; }
    if (id == 2)  { import_sec = p; import_sz = sz; }
    if (id == 3)  { func_sec  = p;  func_sz  = sz; }
    if (id == 7)  { export_sec = p; export_sz = sz; }
    if (id == 10) { code_sec = p;   code_sz  = sz; }
    p += sz;
  }

  /* parse type section */
  if (type_sec) {
    const uint8_t *tp = type_sec, *te = type_sec + type_sz;
    int tc = (int)leb_u32(&tp, te);
    if (tc > 0) out->ftypes = (bw3_functype_t *)calloc((size_t)tc, sizeof(bw3_functype_t));
    if (out->ftypes) {
      for (int i = 0; i < tc && tp < te; i++) {
        if (tp >= te || *tp++ != 0x60) break;
        int np = (int)leb_u32(&tp, te);
        out->ftypes[i].num_params = np;
        for (int j = 0; j < np && j < (int)sizeof(out->ftypes[i].types) && tp < te; j++)
          out->ftypes[i].types[j] = *tp++;
        for (int j = (int)sizeof(out->ftypes[i].types); j < np && tp < te; j++) tp++;  /* skip overflow params */
        int nr = (int)leb_u32(&tp, te);
        out->ftypes[i].num_results = nr;
        for (int j = 0; j < nr && np + j < (int)sizeof(out->ftypes[i].types) && tp < te; j++)
          out->ftypes[i].types[np + j] = *tp++;
        /* skip result types that didn't fit in the array */
        { int nr_s = np < (int)sizeof(out->ftypes[i].types) ? (int)sizeof(out->ftypes[i].types) - np : 0;
          for (int j = nr_s < nr ? nr_s : nr; j < nr && tp < te; j++) tp++; }
        out->ftype_count = i + 1;
      }
    }
    BW3_DBG("parse_wasm_meta: parsed %d types", out->ftype_count);
  }

  /* parse import section */
  if (import_sec) {
    const uint8_t *ip = import_sec, *ie = import_sec + import_sz;
    int ic = (int)leb_u32(&ip, ie);
    int fc = 0;
    /* Allocate upper bound (ic entries); actual count may be less since only
     * function imports are stored — table/memory/global are skipped. */
    if (ic > 0) out->imports = (bw3_import_desc_t *)calloc((size_t)ic, sizeof(bw3_import_desc_t));

    for (int i = 0; i < ic && ip < ie; i++) {
      /* module name */
      uint32_t mlen = leb_u32(&ip, ie);
      if (mlen > (uint32_t)(ie - ip)) break; /* truncated binary */
      int mcap = mlen < 63 ? (int)mlen : 63;
      if (out->imports) { memcpy(out->imports[fc].module, ip, mcap); out->imports[fc].module[mcap] = 0; }
      ip += mlen;

      /* field name */
      uint32_t nlen = leb_u32(&ip, ie);
      if (nlen > (uint32_t)(ie - ip)) break;
      int ncap = nlen < 127 ? (int)nlen : 127;
      if (out->imports) { memcpy(out->imports[fc].name, ip, ncap); out->imports[fc].name[ncap] = 0; }
      ip += nlen;

      uint8_t kind = *ip++;

      if (kind == 0) { /* function */
        int tidx = (int)leb_u32(&ip, ie);
        if (out->imports) {
          if (tidx < out->ftype_count) {
            bw3_functype_t *ft = &out->ftypes[tidx];
            int np = ft->num_params;
            int nr = ft->num_results;
            out->imports[fc].num_params  = np;
            out->imports[fc].num_results = nr;
            for (int j = 0; j < np && j < BW3_MAX_FN_ARGS; j++)
              out->imports[fc].param_types[j] = ft->types[j];
            for (int j = 0; j < nr && j < 4 && np + j < (int)sizeof(ft->types); j++)
              out->imports[fc].result_types[j] = ft->types[np + j];

            /* build wasm3 signature — sig[32]: 1 ret + 1 '(' + params + 1 ')' + 1 NUL */
            char *sig = out->imports[fc].sig;
            char *sig_end = sig + sizeof(out->imports[fc].sig) - 1; /* reserve NUL */
            *sig++ = (nr > 0 && np < (int)sizeof(ft->types)) ? vt_sig(ft->types[np]) : 'v';
            if (sig < sig_end) *sig++ = '(';
            int np_sig = np < (int)sizeof(ft->types) ? np : (int)sizeof(ft->types);
            for (int j = 0; j < np_sig && sig < sig_end - 1; j++)
              *sig++ = vt_sig(ft->types[j]);
            if (sig < sig_end) *sig++ = ')';
            *sig = 0;
          } else {
            strcpy(out->imports[fc].sig, "v()");
          }
          fc++;
        }

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
    BW3_DBG("parse_wasm_meta: parsed %d imports (total entries=%d)", out->import_count, ic);
  }

  /* parse function section: type index per non-import function.
   * Allocate from heap — Rust WASM binaries routinely have 2000-8000+ functions,
   * far more than any static cap would handle without a large stack allocation. */
  if (func_sec) {
    const uint8_t *fp = func_sec, *fe = func_sec + func_sz;
    int fc = (int)leb_u32(&fp, fe);
    if (fc > 0) {
      func_types = (int *)malloc((size_t)fc * sizeof(int));
      if (func_types) {
        for (int i = 0; i < fc && fp < fe; i++)
          func_types[func_type_count++] = (int)leb_u32(&fp, fe);
      }
      /* If malloc fails, func_type_count stays 0: externref-return detection is
       * disabled (graceful degradation — callers get raw i32 instead of resolved
       * externrefs, which causes visible JS errors rather than a silent crash). */
    }
  }

  /* parse export section */
  int init_externref_func_idx = -1; /* code-section index of __wbindgen_init_externref_table */
  if (export_sec) {
    const uint8_t *ep = export_sec, *ee = export_sec + export_sz;
    int ec = (int)leb_u32(&ep, ee);
    if (ec > 0) out->exports = (bw3_export_desc_t *)calloc((size_t)ec, sizeof(bw3_export_desc_t));
    if (out->exports) for (int i = 0; i < ec && ep < ee; i++) {
      uint32_t nlen = leb_u32(&ep, ee);
      if (nlen > (uint32_t)(ee - ep)) break;
      int ncap = nlen < 127 ? (int)nlen : 127;
      memcpy(out->exports[i].name, ep, ncap);
      out->exports[i].name[ncap] = 0;
      ep += nlen;
      if (ep >= ee) break;
      out->exports[i].kind = *ep++;
      uint32_t func_index = leb_u32(&ep, ee);
      out->exports[i].is_import_reexport   = false;
      out->exports[i].is_externref_return   = false;
      if (out->exports[i].kind == 0) {
        if (strcmp(out->exports[i].name, "__wbindgen_init_externref_table") == 0)
          init_externref_func_idx = (int)func_index - out->import_count;
        if (out->imports && func_index < (uint32_t)out->import_count) {
          /* Re-export of an import: wasm3 won't find it via m3_FindFunction */
          out->exports[i].is_import_reexport = true;
          strncpy(out->exports[i].import_module,
                  out->imports[func_index].module, 63);
          out->exports[i].import_module[63] = 0;
          strncpy(out->exports[i].import_name,
                  out->imports[func_index].name, 127);
          out->exports[i].import_name[127] = 0;
        } else {
          /* Non-import function: check if it returns externref */
          int fi = (int)func_index - out->import_count;
          if (fi < func_type_count) {
            int ti = func_types[fi];
            if (ti >= 0 && ti < out->ftype_count) {
              bw3_functype_t *ft = &out->ftypes[ti];
              int np = ft->num_params;
              if (ft->num_results > 0 && np < (int)sizeof(ft->types) &&
                  ft->types[np] == 0x6f)
                out->exports[i].is_externref_return = true;
            }
          }
        }
      }
      out->export_count = i + 1;
    }
    BW3_DBG("parse_wasm_meta: parsed %d exports", out->export_count);
  }

  /* Scan code section for __wbindgen_init_externref_table to find max slot index */
  out->extref_init_slots = 4; /* default */
  if (code_sec && init_externref_func_idx >= 0 && init_externref_func_idx < func_type_count) {
    const uint8_t *cp = code_sec, *ce = code_sec + code_sz;
    int body_count = (int)leb_u32(&cp, ce);
    for (int i = 0; i < body_count && cp < ce; i++) {
      uint32_t body_sz = leb_u32(&cp, ce);
      const uint8_t *body_end = cp + body_sz;
      if (body_end > ce) break;
      if (i == init_externref_func_idx) {
        /* skip local declarations */
        int nloc = (int)leb_u32(&cp, ce);
        for (int j = 0; j < nloc && cp < body_end; j++) {
          leb_u32(&cp, ce);
          cp++; /* valtype */
        }
        /* scan instructions: find max i32.const value */
        int max_idx = -1;
        while (cp < body_end) {
          uint8_t op = *cp++;
          if (op == 0x41) { /* i32.const */
            int cv = (int)leb_u32(&cp, ce);
            if (cv > max_idx) max_idx = cv;
          } else if (op == 0x0b) { /* end */
            break;
          } else if (op == 0xd0) { /* ref.null */
            cp++;
          } else if (op == 0xfb) { /* misc prefix */
            leb_u32(&cp, ce);
          } else if (op == 0x26) { /* memory.size/grow */
            leb_u32(&cp, ce);
          }
        }
        if (max_idx >= 0) out->extref_init_slots = max_idx + 1;
        break;
      }
      cp = body_end;
    }
    BW3_DBG("parse_wasm_meta: extref_init_slots=%d", out->extref_init_slots);
  }

  BW3_DBG("parse_wasm_meta: done, types=%d imports=%d exports=%d",
          out->ftype_count, out->import_count, out->export_count);
  free(func_types);
  return 0;
}

/* ─── Module handle ───────────────────────────────────────────────────────── */

typedef struct {
  uint32_t        magic;        /* BW3_MODULE_MAGIC */
  uint8_t        *wasm_bytes;   /* pointer into pinned JS buffer — no copy */
  size_t          wasm_len;
  bw3_wasm_meta_t meta;
  js_ref_t       *js_buf_ref;   /* persistent ref keeps the JS buffer alive */
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

/* Tombstone: installed for imports that could not be linked to a JS function.
 * Allows m3_CompileModule to succeed; traps with a named error if called. */
typedef struct {
  bw3_import_desc_t *desc;
  bw3_instance_t    *inst;
  char              *msg; /* heap-allocated on install; NULL until then */
} bw3_tombstone_t;

static uint32_t bw3_ext_grow (void *ctx, uint32_t n);

/* Externref table context — layout must match bw3_ext_ctx_ops_t in m3_exec.h. */
typedef struct {
  uint32_t  ext_size;   /* logical size (number of live slots) */
  uint32_t  ext_cap;    /* allocated capacity */
  uint32_t *ext_vals;   /* slot values (indices into JS _extMap) */
  uint32_t (*grow_fn)(void *ctx, uint32_t n);
} bw3_ext_ctx_t;

struct bw3_instance {
  uint32_t        magic;       /* BW3_INSTANCE_MAGIC */
  IM3Environment  m3env;
  IM3Runtime      m3rt;
  IM3Module       m3mod;
  js_env_t       *env;
  bw3_module_t   *mod;         /* back-pointer (not owned) */
  bw3_bridge_t   *bridges;     /* heap-allocated; length = mod->meta.import_count */
  int             bridge_count;
  bw3_tombstone_t *tombstones; /* heap-allocated; length = mod->meta.import_count */
  int             tombstone_count;
  bool            js_exc_pending;
  /* Cached memory ArrayBuffer */
  js_ref_t       *mem_ref;
  uint8_t        *mem_base;
  uint32_t        mem_size_cached;
  /* Externref table — heap-allocated, grows on demand */
  bw3_ext_ctx_t   ext_ctx;
  uint32_t       *ext_vals;
  js_ref_t       **ext_refs;
};

/* ─── Handle validation ─────────────────────────────────────────────────── */

static bw3_module_t *
bw3_validate_module (js_env_t *env, js_value_t *handle_val) {
  uint32_t v = 0;
  if (js_get_value_uint32(env, handle_val, &v) != 0) return NULL;
  if (v == BW3_HANDLE_INVALID) return NULL;
  return (bw3_module_t *)bw3_handle_resolve(bw3_module_slots, v, BW3_MODULE_MAGIC);
}

static bw3_instance_t *
bw3_validate_instance (js_env_t *env, js_value_t *handle_val) {
  uint32_t v = 0;
  if (js_get_value_uint32(env, handle_val, &v) != 0) return NULL;
  if (v == BW3_HANDLE_INVALID) return NULL;
  return (bw3_instance_t *)bw3_handle_resolve(bw3_instance_slots, v, BW3_INSTANCE_MAGIC);
}

/* ─── Tombstone bridge: traps with a named error for unlinked imports ─────── */

static const void *
bw3_tombstone_bridge (IM3Runtime runtime, IM3ImportContext ctx, uint64_t *sp, void *mem) {
  (void)runtime; (void)mem;
  bw3_tombstone_t   *ts   = (bw3_tombstone_t *)ctx->userdata;
  bw3_import_desc_t *desc = ts->desc;
  js_env_t          *env  = ts->inst->env;
  ts->inst->js_exc_pending = true;
  for (int i = 0; i < desc->num_results; i++) sp[i] = 0;
  BW3_DBG("tombstone fired: %s.%s", desc->module, desc->name);
  return ts->msg ? ts->msg : BW3_PREFIX " tombstone: unknown import";
}

/* ─── Import bridge: wasm3 → JS ──────────────────────────────────────────── */

static const void *
bw3_import_bridge (IM3Runtime runtime, IM3ImportContext ctx, uint64_t *sp, void *mem) {
  (void)runtime; (void)mem;
  bw3_bridge_t      *br   = (bw3_bridge_t *)ctx->userdata;
  js_env_t          *env  = br->env;
  bw3_import_desc_t *desc = br->desc;
  int err;

  int np = desc->num_params;
  int nr = desc->num_results;

  BW3_DBG("import_bridge: %s.%s np=%d nr=%d", desc->module, desc->name, np, nr);

  /* Args start after the return slot(s) */
  uint64_t *arg_sp = sp + nr;

  /* Convert WASM stack args → JS values */
  js_value_t *js_args[BW3_MAX_FN_ARGS];
  for (int i = 0; i < np && i < BW3_MAX_FN_ARGS; i++) {
    switch (desc->param_types[i]) {
      case 0x7f: { /* i32 */
        int32_t v = *(int32_t *)&arg_sp[i];
        err = js_create_int32(env, v, &js_args[i]);
        if (err != 0) return "js_exception";
        break;
      }
      case 0x7e: { /* i64 */
        int64_t v = *(int64_t *)&arg_sp[i];
        err = js_create_int64(env, v, &js_args[i]);
        if (err != 0) return "js_exception";
        break;
      }
      case 0x7d: { /* f32 */
        float v;
        memcpy(&v, &arg_sp[i], sizeof(float));
        err = js_create_double(env, (double)v, &js_args[i]);
        if (err != 0) return "js_exception";
        break;
      }
      case 0x7c: { /* f64 */
        double v;
        memcpy(&v, &arg_sp[i], sizeof(double));
        err = js_create_double(env, v, &js_args[i]);
        if (err != 0) return "js_exception";
        break;
      }
      case 0x6f: { /* externref — pass raw i32; JS wrapper resolves via _extMap */
        int32_t v = *(int32_t *)&arg_sp[i];
        err = js_create_int32(env, v, &js_args[i]);
        if (err != 0) return "js_exception";
        break;
      }
      default: {
        err = js_get_undefined(env, &js_args[i]);
        if (err != 0) return "js_exception";
        break;
      }
    }
  }

  /* Retrieve the JS function */
  js_value_t *fn;
  err = js_get_reference_value(env, br->fn_ref, &fn);
  if (err != 0) return "js_exception";

  js_value_t *recv;
  err = js_get_undefined(env, &recv);
  if (err != 0) return "js_exception";

  /* Call JS import function */
  js_value_t *result = NULL;
  size_t np_call = (np < BW3_MAX_FN_ARGS) ? (size_t)np : (size_t)BW3_MAX_FN_ARGS;
  err = js_call_function(env, recv, fn, np_call, js_args, &result);
  if (err != 0) {
    BW3_DBG("import_bridge: %s.%s js_call_function FAILED", desc->module, desc->name);
    br->inst->js_exc_pending = true;
    return "js_exception";
  }

  /* Write return value into WASM stack slot; zero it if JS returned nothing */
  if (nr > 0) {
    if (result == NULL) { sp[0] = 0; }
    else switch (desc->result_types[0]) {
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
      case 0x6f: { /* externref */
        int32_t v = 0;
        js_get_value_int32(env, result, &v);
        *(int32_t *)&sp[0] = v;
        break;
      }
      default: sp[0] = 0; break;
    } /* end switch */
  }

  BW3_DBG("import_bridge: %s.%s call OK, nr=%d", desc->module, desc->name, nr);
  return m3Err_none;
}

/* ─── JS binding functions ────────────────────────────────────────────────── */

/**
 * moduleNew(wasmBuffer: Buffer) → u32 (opaque handle ID)
 *
 * Validates the WASM magic, pins the JS buffer via a persistent reference
 * (no copy — wasm3 stores raw pointers into the original bytes), parses
 * metadata, and returns a u32 handle ID.
 */
static js_value_t *
bw3_module_new (js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  if (err != 0) return NULL;

  uint8_t *wasm_data;
  size_t   wasm_len;
  err = js_get_arraybuffer_info(env, argv[0], (void **)&wasm_data, &wasm_len);
  if (err != 0) BW3_THROW("moduleNew: argument must be an ArrayBuffer/Buffer");

  BW3_DBG("moduleNew: start, buflen=%zu", wasm_len);

  bw3_module_t *mod = (bw3_module_t *)calloc(1, sizeof(bw3_module_t));
  if (!mod) BW3_THROW("moduleNew: out of memory");

  /* Pin the JS buffer so its backing memory stays valid for the module's
   * lifetime. This avoids a 3–4 MB malloc+memcpy peak that would OOM on
   * constrained worklet processes when the audio file is also in memory. */
  js_ref_t *buf_ref;
  err = js_create_reference(env, argv[0], 1, &buf_ref);
  if (err != 0) {
    free(mod);
    BW3_THROW("moduleNew: failed to pin buffer");
  }

  mod->magic      = BW3_MODULE_MAGIC;
  mod->wasm_bytes = wasm_data;
  mod->wasm_len   = wasm_len;
  mod->js_buf_ref = buf_ref;
  mod->env        = env;

  if (parse_wasm_meta(env, mod->wasm_bytes, mod->wasm_len, &mod->meta) != 0) {
    js_delete_reference(env, buf_ref);
    free(mod);
    BW3_THROW("moduleNew: invalid WASM binary");
  }

  uint32_t hid = bw3_handle_alloc(bw3_module_slots, bw3_module_next_gen, mod, BW3_MODULE_MAGIC);
  if (hid == BW3_HANDLE_INVALID) {
    bw3_wasm_meta_free(&mod->meta);
    js_delete_reference(env, buf_ref);
    free(mod);
    BW3_THROW("moduleNew: too many active modules");
  }

  /* Return the opaque u32 handle ID */
  js_value_t *handle;
  err = js_create_uint32(env, hid, &handle);
  if (err != 0) {
    bw3_handle_free(bw3_module_slots, hid);
    bw3_wasm_meta_free(&mod->meta);
    js_delete_reference(env, buf_ref);
    free(mod);
    BW3_THROW("moduleNew: failed to create handle");
  }

  BW3_DBG("moduleNew: done, handle=%u", hid);
  return handle;
}

/**
 * moduleMeta(moduleHandle: u32) → { returnExports: string[], returnImportKeys: string[], importParamInfo: object }
 *
 * Returns the import/export type metadata parsed during moduleNew.
 * Must be called BEFORE instanceNew so import wrappers can use the metadata
 * during m3_LoadModule.
 */
static js_value_t *
bw3_module_meta (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  if (err != 0) return NULL;

  bw3_module_t *mod = bw3_validate_module(env, argv[0]);
  if (!mod) BW3_THROW("moduleMeta: invalid module handle");

  bw3_wasm_meta_t *meta = &mod->meta;

  /* returnExports */
  js_value_t *return_exports_arr;
  err = js_create_array_with_length(env, 0, &return_exports_arr);
  if (err != 0) BW3_THROW("moduleMeta: out of memory");

  for (int i = 0; i < meta->export_count; i++) {
    if (!meta->exports[i].is_externref_return) continue;
    js_value_t *name_str;
    err = js_create_string_utf8(env, (const utf8_t *)meta->exports[i].name,
                                strlen(meta->exports[i].name), &name_str);
    if (err != 0) BW3_THROW("moduleMeta: string create failed");
    uint32_t arr_len;
    js_get_array_length(env, return_exports_arr, &arr_len);
    js_set_element(env, return_exports_arr, arr_len, name_str);
  }

  /* returnImportKeys + importParamInfo */
  js_value_t *return_import_keys_arr;
  err = js_create_array_with_length(env, 0, &return_import_keys_arr);
  if (err != 0) BW3_THROW("moduleMeta: out of memory");

  js_value_t *import_param_info_obj;
  err = js_create_object(env, &import_param_info_obj);
  if (err != 0) BW3_THROW("moduleMeta: out of memory");

  for (int i = 0; i < meta->import_count; i++) {
    bw3_import_desc_t *desc = &meta->imports[i];

    char key[194];
    {
      size_t ml = strlen(desc->module);
      size_t nl = strlen(desc->name);
      if (ml + 1 + nl >= 192) continue;
    }
    snprintf(key, sizeof(key), "%s.%s", desc->module, desc->name);

    /* returnImportKeys */
    if (desc->num_results > 0 && desc->result_types[0] == 0x6f) {
      js_value_t *key_str;
      err = js_create_string_utf8(env, (const utf8_t *)key, strlen(key), &key_str);
      if (err != 0) BW3_THROW("moduleMeta: string create failed");
      uint32_t arr_len;
      js_get_array_length(env, return_import_keys_arr, &arr_len);
      js_set_element(env, return_import_keys_arr, arr_len, key_str);
    }

    /* importParamInfo */
    js_value_t *param_entry;
    err = js_create_object(env, &param_entry);
    if (err != 0) BW3_THROW("moduleMeta: out of memory");

    js_value_t *extref_pos_arr;
    err = js_create_array_with_length(env, 0, &extref_pos_arr);
    if (err != 0) BW3_THROW("moduleMeta: out of memory");

    for (int j = 0; j < desc->num_params && j < BW3_MAX_FN_ARGS; j++) {
      if (desc->param_types[j] == 0x6f) {
        js_value_t *pos;
        err = js_create_uint32(env, (uint32_t)j, &pos);
        if (err != 0) BW3_THROW("moduleMeta: out of memory");
        uint32_t arr_len;
        js_get_array_length(env, extref_pos_arr, &arr_len);
        js_set_element(env, extref_pos_arr, arr_len, pos);
      }
    }

    js_value_t *total_val;
    err = js_create_uint32(env, (uint32_t)desc->num_params, &total_val);
    if (err != 0) BW3_THROW("moduleMeta: out of memory");
    js_set_named_property(env, param_entry, "totalParams", total_val);
    js_set_named_property(env, param_entry, "extrefParams", extref_pos_arr);
    js_set_named_property(env, import_param_info_obj, key, param_entry);
  }

  /* Pack result */
  js_value_t *result_obj;
  err = js_create_object(env, &result_obj);
  if (err != 0) BW3_THROW("moduleMeta: out of memory");
  js_set_named_property(env, result_obj, "returnExports", return_exports_arr);
  js_set_named_property(env, result_obj, "returnImportKeys", return_import_keys_arr);
  js_set_named_property(env, result_obj, "importParamInfo", import_param_info_obj);

  /* extrefInitSlots: max slot index + 1 used by init_externref_table */
  js_value_t *slots_val;
  err = js_create_uint32(env, (uint32_t)meta->extref_init_slots, &slots_val);
  if (err != 0) BW3_THROW("moduleMeta: out of memory");
  js_set_named_property(env, result_obj, "extrefInitSlots", slots_val);

  return result_obj;
}

/**
 * instanceNew(moduleHandle: u32, importsObj)
 *   → { handle: u32, exportsMap: {name→kind}, memoryBuffer: ArrayBuffer }
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
  if (err != 0) return NULL;

  /* Recover and validate bw3_module_t pointer */
  bw3_module_t *mod = bw3_validate_module(env, argv[0]);
  if (!mod) BW3_THROW("instanceNew: invalid module handle");

  BW3_DBG("instanceNew: start, mod=%p types=%d imports=%d exports=%d",
          (void*)mod, mod->meta.ftype_count, mod->meta.import_count, mod->meta.export_count);

  js_value_t *imports_arg = argv[1];

  /* Allocate instance */
  bw3_instance_t *inst = (bw3_instance_t *)calloc(1, sizeof(bw3_instance_t));
  if (!inst) BW3_THROW("instanceNew: out of memory");
  inst->magic = BW3_INSTANCE_MAGIC;
  inst->env   = env;
  inst->mod   = mod;
  inst->js_exc_pending = false;

  int import_cap = mod->meta.import_count;
  if (import_cap > 0) {
    inst->bridges    = (bw3_bridge_t    *)calloc((size_t)import_cap, sizeof(bw3_bridge_t));
    inst->tombstones = (bw3_tombstone_t *)calloc((size_t)import_cap, sizeof(bw3_tombstone_t));
    if (!inst->bridges || !inst->tombstones) {
      free(inst->bridges);
      free(inst->tombstones);
      free(inst);
      BW3_THROW("instanceNew: out of memory for import tables");
    }
  }

  /* wasm3 setup */
  inst->m3env = m3_NewEnvironment();
  if (!inst->m3env) {
    free(inst->bridges); free(inst->tombstones); free(inst);
    BW3_THROW("instanceNew: m3_NewEnvironment failed");
  }

  uint32_t ext_init_cap = (uint32_t)mod->meta.extref_init_slots;
  if (ext_init_cap < 256) ext_init_cap = 256;
  inst->ext_vals = (uint32_t *)calloc(ext_init_cap, sizeof(uint32_t));
  inst->ext_refs = (js_ref_t **)calloc(ext_init_cap, sizeof(js_ref_t *));
  if (!inst->ext_vals || !inst->ext_refs) {
    free(inst->ext_vals); free(inst->ext_refs);
    m3_FreeEnvironment(inst->m3env);
    free(inst->bridges); free(inst->tombstones); free(inst);
    BW3_THROW("instanceNew: out of memory for externref table");
  }
  inst->ext_ctx.ext_size = 0;
  inst->ext_ctx.ext_cap  = ext_init_cap;
  inst->ext_ctx.ext_vals = inst->ext_vals;
  inst->ext_ctx.grow_fn  = bw3_ext_grow;
  inst->m3rt = m3_NewRuntime(inst->m3env, BW3_STACK_SIZE, &inst->ext_ctx);
  if (!inst->m3rt) {
    m3_FreeEnvironment(inst->m3env);
    free(inst->bridges); free(inst->tombstones); free(inst);
    BW3_THROW("instanceNew: m3_NewRuntime failed");
  }

  if (mod->wasm_len > UINT32_MAX) {
    m3_FreeRuntime(inst->m3rt);
    m3_FreeEnvironment(inst->m3env);
    free(inst->bridges); free(inst->tombstones); free(inst);
    BW3_THROW("instanceNew: WASM binary too large");
  }
  m3err = m3_ParseModule(inst->m3env, &inst->m3mod,
                         mod->wasm_bytes, (uint32_t)mod->wasm_len);
  if (m3err) {
    m3_FreeRuntime(inst->m3rt);
    m3_FreeEnvironment(inst->m3env);
    free(inst->bridges); free(inst->tombstones); free(inst);
    BW3_THROW(m3err);
  }

  BW3_DBG("instanceNew: m3_ParseModule OK");
  m3err = m3_LoadModule(inst->m3rt, inst->m3mod);
  if (m3err) {
    m3_FreeRuntime(inst->m3rt);
    m3_FreeEnvironment(inst->m3env);
    free(inst->bridges); free(inst->tombstones); free(inst);
    BW3_THROW(m3err);
  }
  BW3_DBG("instanceNew: m3_LoadModule OK");

  /* Link imports: for each function import, find the JS function in importsObj
   * and register a raw wasm3 callback.  If the JS function is missing or the
   * signature is rejected by wasm3, install a tombstone so m3_CompileModule
   * succeeds and any accidental call produces a named error instead of the
   * generic "missing imported function" trap. */
  bw3_wasm_meta_t *meta = &mod->meta;
  inst->bridge_count    = 0;
  inst->tombstone_count = 0;

  for (int i = 0; i < meta->import_count; i++) {
    bw3_import_desc_t *desc = &meta->imports[i];

    /* Resolve JS function */
    bool is_fn = false;
    js_value_t *fn = NULL;
    {
      js_value_t *module_obj;
      if (js_get_named_property(env, imports_arg, desc->module, &module_obj) == 0)
        if (js_get_named_property(env, module_obj, desc->name, &fn) == 0)
          js_is_function(env, fn, &is_fn);
    }

    bool linked = false;

    if (is_fn) {
      int bi = inst->bridge_count;
      if (js_create_reference(env, fn, 1, &inst->bridges[bi].fn_ref) == 0) {
        inst->bridges[bi].env  = env;
        inst->bridges[bi].desc = desc;
        inst->bridges[bi].inst = inst;
        inst->bridge_count++;

        M3Result link_err = m3_LinkRawFunctionEx(inst->m3mod, desc->module, desc->name,
                                desc->sig, bw3_import_bridge, &inst->bridges[bi]);
        if (!link_err) {
          BW3_DBG("instanceNew: linked '%s.%s' sig=%s", desc->module, desc->name, desc->sig);
          linked = true;
        } else {
          BW3_DBG("instanceNew: link FAILED '%s.%s' sig=%s: %s",
                  desc->module, desc->name, desc->sig, link_err);
          js_delete_reference(env, inst->bridges[bi].fn_ref);
          inst->bridge_count--;
        }
      }
    }

    if (!linked) {
      int ti = inst->tombstone_count;
      inst->tombstones[ti].desc = desc;
      inst->tombstones[ti].inst = inst;
      inst->tombstones[ti].msg  = (char *)malloc(256);
      if (inst->tombstones[ti].msg)
        snprintf(inst->tombstones[ti].msg, 256,
                 BW3_PREFIX " tombstone: %s.%s (sig=%s)", desc->module, desc->name, desc->sig);
      M3Result ts_err = m3_LinkRawFunctionEx(inst->m3mod, desc->module, desc->name,
                            desc->sig, bw3_tombstone_bridge, &inst->tombstones[ti]);
      if (!ts_err) {
        inst->tombstone_count++;
        BW3_DBG("instanceNew: tombstoned '%s.%s' sig=%s", desc->module, desc->name, desc->sig);
      } else {
        if (inst->tombstones[ti].msg) { free(inst->tombstones[ti].msg); inst->tombstones[ti].msg = NULL; }
        BW3_DBG("instanceNew: tombstone FAILED '%s.%s' sig=%s: %s",
                desc->module, desc->name, desc->sig, ts_err);
      }
    }
  }

  BW3_DBG("instanceNew: linked %d/%d imports (%d tombstoned)",
          inst->bridge_count, meta->import_count, inst->tombstone_count);

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
    BW3_DBG("m3_CompileModule ERROR: %s", m3err);
  } else {
    BW3_DBG("m3_CompileModule OK (%d imports linked)", inst->bridge_count);
  }

  /* ── Pack return value ────────────────────────────────────────────────── */

  /* Instance handle (u32 ID from handle table) */
  uint32_t inst_hid = BW3_HANDLE_INVALID;
  inst_hid = bw3_handle_alloc(bw3_instance_slots, bw3_instance_next_gen, inst, BW3_INSTANCE_MAGIC);
  if (inst_hid == BW3_HANDLE_INVALID) goto build_fail;
  js_value_t *inst_handle;
  err = js_create_uint32(env, inst_hid, &inst_handle);
  if (err != 0) { bw3_handle_free(bw3_instance_slots, inst_hid); goto build_fail; }

  /* exportsMap: { name: kind } */
  js_value_t *exports_map;
  err = js_create_object(env, &exports_map);
  if (err != 0) goto build_fail;

  for (int i = 0; i < meta->export_count; i++) {
    js_value_t *kind_val;
    err = js_create_uint32(env, meta->exports[i].kind, &kind_val);
    if (err != 0) goto build_fail;
    err = js_set_named_property(env, exports_map, meta->exports[i].name, kind_val);
    if (err != 0) goto build_fail;
  }

  /* importReexports: { exportName: { module, name } } */
  js_value_t *import_reexports;
  err = js_create_object(env, &import_reexports);
  if (err != 0) goto build_fail;

  for (int i = 0; i < meta->export_count; i++) {
    if (!meta->exports[i].is_import_reexport) continue;
    js_value_t *entry;
    err = js_create_object(env, &entry);
    if (err != 0) goto build_fail;
    js_value_t *mod_str, *name_str;
    err = js_create_string_utf8(env, (const utf8_t *)meta->exports[i].import_module,
                                strlen(meta->exports[i].import_module), &mod_str);
    if (err != 0) goto build_fail;
    err = js_create_string_utf8(env, (const utf8_t *)meta->exports[i].import_name,
                                strlen(meta->exports[i].import_name), &name_str);
    if (err != 0) goto build_fail;
    err = js_set_named_property(env, entry, "module", mod_str);
    if (err != 0) goto build_fail;
    err = js_set_named_property(env, entry, "name", name_str);
    if (err != 0) goto build_fail;
    err = js_set_named_property(env, import_reexports,
                                meta->exports[i].name, entry);
    if (err != 0) goto build_fail;
  }

  js_value_t *result_obj;
  err = js_create_object(env, &result_obj);
  if (err != 0) goto build_fail;

  err = js_set_named_property(env, result_obj, "handle", inst_handle);
  if (err != 0) goto build_fail;
  err = js_set_named_property(env, result_obj, "exportsMap", exports_map);
  if (err != 0) goto build_fail;
  err = js_set_named_property(env, result_obj, "importReexports", import_reexports);
  if (err != 0) goto build_fail;

  return result_obj;

build_fail:
  /* Tear down the fully-constructed instance on result-packaging failure */
  {
    /* Release the handle-table slot if it was allocated */
    if (inst_hid != BW3_HANDLE_INVALID) bw3_handle_free(bw3_instance_slots, inst_hid);
    if (inst->mem_ref) {
      js_value_t *old_buf;
      if (js_get_reference_value(env, inst->mem_ref, &old_buf) == 0 && old_buf)
        js_detach_arraybuffer(env, old_buf);
      js_delete_reference(env, inst->mem_ref);
    }
    for (int i = 0; i < inst->bridge_count; i++)
      if (inst->bridges[i].fn_ref) js_delete_reference(env, inst->bridges[i].fn_ref);
    for (int i = 0; i < inst->tombstone_count; i++)
      if (inst->tombstones[i].msg) { free(inst->tombstones[i].msg); inst->tombstones[i].msg = NULL; }
    for (uint32_t i = 0; i < inst->ext_ctx.ext_cap; i++)
      if (inst->ext_refs[i]) js_delete_reference(env, inst->ext_refs[i]);
    free(inst->ext_refs);
    free(inst->ext_vals);
    if (inst->m3rt)  m3_FreeRuntime(inst->m3rt);
    if (inst->m3env) m3_FreeEnvironment(inst->m3env);
    free(inst->bridges);
    free(inst->tombstones);
    free(inst);
  }
  BW3_THROW("instanceNew: failed to build result object");
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
  if (err != 0) return NULL;

  /* Instance handle — validate magic */
  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) BW3_THROW("callExport: invalid instance handle");

  /* Function name */
  size_t name_len = 0;
  BW3_CHECK(js_get_value_string_utf8(env, argv[1], NULL, 0, &name_len),
    "callExport: failed to get export name");
  utf8_t *fn_name = (utf8_t *)malloc(name_len + 1);
  if (!fn_name) BW3_THROW("callExport: out of memory");
  if (js_get_value_string_utf8(env, argv[1], fn_name, name_len + 1, &name_len) != 0) {
    free(fn_name);
    BW3_THROW("callExport: failed to read export name");
  }
  fn_name[name_len] = 0;

  IM3Function fn;
  m3err = m3_FindFunction(&fn, inst->m3rt, (const char *)fn_name);

  // Save the name for error messages before freeing
  char export_name_saved[128];
  strncpy(export_name_saved, (const char *)fn_name, 127);
  export_name_saved[127] = 0;
  free(fn_name);

  if (m3err) BW3_THROW(m3err);

  uint32_t wasm_argc = m3_GetArgCount(fn);
  uint32_t wasm_retc = m3_GetRetCount(fn);

  BW3_DBG("callExport: fn=%s argc_wasm=%d retc=%d", export_name_saved, wasm_argc, wasm_retc);

  /* Read JS args → typed WASM values */
  int32_t  i32v[BW3_MAX_FN_ARGS];
  int64_t  i64v[BW3_MAX_FN_ARGS];
  float    f32v[BW3_MAX_FN_ARGS];
  double   f64v[BW3_MAX_FN_ARGS];
  const void *arg_ptrs[BW3_MAX_FN_ARGS];

  uint32_t n = wasm_argc < (uint32_t)BW3_MAX_FN_ARGS ? wasm_argc : (uint32_t)BW3_MAX_FN_ARGS;
  for (uint32_t i = 0; i < n; i++) {
    js_value_t *el = NULL;
    if (js_get_element(env, argv[2], i, &el) != 0 || el == NULL) {
      i32v[i] = 0; arg_ptrs[i] = &i32v[i]; continue;
    }
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
  BW3_DBG("callExport: m3_Call → %s", m3err ? m3err : "OK");

  if (m3err) {
    if (inst->js_exc_pending) {
      inst->js_exc_pending = false;
      return NULL;
    }
    char errbuf[320];
    snprintf(errbuf, sizeof(errbuf), "%s: %s", export_name_saved, m3err);
    BW3_THROW(errbuf);
  }

  /* Return value(s) */
  if (wasm_retc == 0) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  uint32_t nr = wasm_retc < (uint32_t)BW3_MAX_FN_ARGS ? wasm_retc : (uint32_t)BW3_MAX_FN_ARGS;
  int32_t  ret_i32v[BW3_MAX_FN_ARGS];
  int64_t  ret_i64v[BW3_MAX_FN_ARGS];
  float    ret_f32v[BW3_MAX_FN_ARGS];
  double   ret_f64v[BW3_MAX_FN_ARGS];
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
  if (err != 0) return NULL;

  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

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
      BW3_DBG("getMemory: mallocated->length=%u < numPages*pageSize=%u, using pages_size",
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
    if (err != 0) {
      js_value_t *undef;
      js_get_undefined(env, &undef);
      return undef;
    }
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
  if (err != 0) return NULL;

  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) BW3_THROW("tableSet: invalid instance handle");

  uint32_t idx = 0;
  js_get_value_uint32(env, argv[1], &idx);
  if (idx >= inst->ext_ctx.ext_cap || idx >= inst->ext_ctx.ext_size) {
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
    if (err == 0) inst->ext_refs[idx] = ref;
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
  if (err != 0) return NULL;

  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) BW3_THROW("tableGet: invalid instance handle");

  uint32_t idx = 0;
  js_get_value_uint32(env, argv[1], &idx);
  if (idx >= inst->ext_ctx.ext_cap || !inst->ext_refs[idx]) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  js_value_t *val;
  err = js_get_reference_value(env, inst->ext_refs[idx], &val);
  if (err != 0) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }
  return val;
}

/* Called by the wasm3 op_ExtTableGrow ops via the grow_fn function pointer.
 * ctx is bw3_ext_ctx_t *; recover bw3_instance_t via container_of. */
static uint32_t
bw3_ext_grow (void *vctx, uint32_t n) {
  bw3_ext_ctx_t *ctx = (bw3_ext_ctx_t *)vctx;
  bw3_instance_t *inst = (bw3_instance_t *)((char *)ctx - offsetof(bw3_instance_t, ext_ctx));
  uint32_t old = ctx->ext_size;
  uint32_t new_end = old + n;
  if (new_end < old) return (uint32_t)(-1); /* overflow */
  if (new_end <= ctx->ext_cap) {
    for (uint32_t i = old; i < new_end; i++) inst->ext_vals[i] = 0;
    ctx->ext_size = new_end;
    return old;
  }
  uint32_t new_cap = ctx->ext_cap * 2;
  if (new_cap < new_end) new_cap = new_end;
  uint32_t  *new_vals = (uint32_t  *)realloc(inst->ext_vals, new_cap * sizeof(uint32_t));
  js_ref_t **new_refs = (js_ref_t **)realloc(inst->ext_refs, new_cap * sizeof(js_ref_t *));
  if (!new_vals || !new_refs) { free(new_vals); free(new_refs); return (uint32_t)(-1); }
  memset(new_vals + ctx->ext_cap, 0, (new_cap - ctx->ext_cap) * sizeof(uint32_t));
  memset(new_refs + ctx->ext_cap, 0, (new_cap - ctx->ext_cap) * sizeof(js_ref_t *));
  inst->ext_vals   = new_vals;
  inst->ext_refs   = new_refs;
  ctx->ext_cap     = new_cap;
  ctx->ext_vals    = new_vals;
  ctx->ext_size    = new_end;
  return old;
}

/* tableGrow(instHandle, n: u32) → u32 (old size, or 0xFFFFFFFF on failure)
 * Grows the externref table by `n` slots and returns the previous size. */
static js_value_t *
bw3_table_grow (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 2;
  js_value_t *argv[2];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  if (err != 0) return NULL;

  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) BW3_THROW("tableGrow: invalid instance handle");

  uint32_t n = 0;
  js_get_value_uint32(env, argv[1], &n);

  uint32_t old_size = bw3_ext_grow(&inst->ext_ctx, n);
  js_value_t *ret;
  if (old_size == (uint32_t)(-1))
    err = js_create_int32(env, -1, &ret);
  else
    err = js_create_uint32(env, old_size, &ret);
  if (err != 0) BW3_THROW("tableGrow: failed to create result");
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
  if (err != 0) return NULL;

  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) BW3_THROW("tableSize: invalid instance handle");

  js_value_t *ret;
  err = js_create_uint32(env, inst->ext_ctx.ext_size, &ret);
  if (err != 0) BW3_THROW("tableSize: failed to create result");
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
  if (err != 0) return NULL;

  bw3_instance_t *inst = bw3_validate_instance(env, argv[0]);
  if (!inst) BW3_THROW("extvalGet: invalid instance handle");

  uint32_t idx = 0;
  js_get_value_uint32(env, argv[1], &idx);

  js_value_t *ret;
  if (idx >= inst->ext_ctx.ext_cap) {
    js_get_undefined(env, &ret);
  } else {
    err = js_create_uint32(env, inst->ext_vals[idx], &ret);
    if (err != 0) { js_get_undefined(env, &ret); return ret; }
  }
  return ret;
}

/* ─── Cleanup ─────────────────────────────────────────────────────────────── */

/**
 * moduleFree(moduleHandle: u32) → undefined
 *
 * Releases a module: unpins the JS buffer and frees the bw3_module_t.
 * After this call the handle is invalid and must not be used.
 */
static js_value_t *
bw3_module_free (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  if (err != 0) return NULL;

  uint32_t handle_val = 0;
  if (js_get_value_uint32(env, argv[0], &handle_val) != 0 || handle_val == BW3_HANDLE_INVALID) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  bw3_module_t *mod = (bw3_module_t *)bw3_handle_resolve(bw3_module_slots, handle_val, BW3_MODULE_MAGIC);
  if (!mod) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  /* Free the handle-table slot first so no concurrent use can succeed */
  bw3_handle_free(bw3_module_slots, handle_val);

  /* Invalidate magic so any racing code that already got the pointer traps */
  mod->magic = 0;

  if (mod->js_buf_ref) js_delete_reference(env, mod->js_buf_ref);
  bw3_wasm_meta_free(&mod->meta);
  free(mod);

  js_value_t *undef;
  js_get_undefined(env, &undef);
  return undef;
}

/**
 * instanceFree(instanceHandle: u32) → undefined
 *
 * Tears down a wasm3 instance: frees bridges, memory references, runtime,
 * environment, and the bw3_instance_t itself.  Handle is invalidated.
 */
static js_value_t *
bw3_instance_free (js_env_t *env, js_callback_info_t *info) {
  int err;
  size_t argc = 1;
  js_value_t *argv[1];
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  if (err != 0) return NULL;

  uint32_t handle_val = 0;
  if (js_get_value_uint32(env, argv[0], &handle_val) != 0 || handle_val == BW3_HANDLE_INVALID) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  bw3_instance_t *inst = (bw3_instance_t *)bw3_handle_resolve(bw3_instance_slots, handle_val, BW3_INSTANCE_MAGIC);
  if (!inst) {
    js_value_t *undef;
    js_get_undefined(env, &undef);
    return undef;
  }

  /* Free the handle-table slot so no concurrent use can succeed */
  bw3_handle_free(bw3_instance_slots, handle_val);

  /* Invalidate magic so any racing code that already got the pointer traps */
  inst->magic = 0;

  /* Detach memory buffer so stale JS references see byteLength === 0 */
  if (inst->mem_ref) {
    js_value_t *old_buf;
    if (js_get_reference_value(env, inst->mem_ref, &old_buf) == 0 && old_buf)
      js_detach_arraybuffer(env, old_buf);
    js_delete_reference(env, inst->mem_ref);
    inst->mem_ref = NULL;
  }

  /* Free bridge function references */
  for (int i = 0; i < inst->bridge_count; i++) {
    if (inst->bridges[i].fn_ref) {
      js_delete_reference(env, inst->bridges[i].fn_ref);
      inst->bridges[i].fn_ref = NULL;
    }
  }

  /* Free tombstone message strings */
  for (int i = 0; i < inst->tombstone_count; i++) {
    if (inst->tombstones[i].msg) {
      free(inst->tombstones[i].msg);
      inst->tombstones[i].msg = NULL;
    }
  }

  /* Free externref table JS references */
  for (uint32_t i = 0; i < inst->ext_ctx.ext_cap; i++) {
    if (inst->ext_refs[i]) {
      js_delete_reference(env, inst->ext_refs[i]);
      inst->ext_refs[i] = NULL;
    }
  }
  free(inst->ext_refs);
  free(inst->ext_vals);

  if (inst->m3rt)  m3_FreeRuntime(inst->m3rt);
  if (inst->m3env) m3_FreeEnvironment(inst->m3env);

  free(inst->bridges);
  free(inst->tombstones);
  free(inst);

  js_value_t *undef;
  js_get_undefined(env, &undef);
  return undef;
}

/* ─── Module init ─────────────────────────────────────────────────────────── */

static js_value_t *
bw3_exports (js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    if (js_create_function(env, name, -1, fn, NULL, &val) == 0) \
      js_set_named_property(env, exports, name, val); \
  }

  V("moduleMeta",   bw3_module_meta)
  V("moduleNew",    bw3_module_new)
  V("instanceNew",  bw3_instance_new)
  V("moduleFree",   bw3_module_free)
  V("instanceFree", bw3_instance_free)
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
