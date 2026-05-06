#!/usr/bin/env python3
"""Apply WebAssembly Reference Types patches to wasm3 v0.5.0 sources."""
import os, sys

BASE = os.path.dirname(os.path.abspath(__file__))
BUILD_DIRS = ["build/ios-arm64", "build/ios-arm64-simulator"]

# ──────────────────────────────────────────────────────────────────────────────
# m3_core.c – NormalizeType: accept externref(17) and funcref(16) as i32
# ──────────────────────────────────────────────────────────────────────────────
CORE_OLD = """\
    if (type == 0x40)
        type = c_m3Type_none;
    else if (type < c_m3Type_i32 or type > c_m3Type_f64)
        result = m3Err_invalidTypeId;"""

CORE_NEW = """\
    if (type == 0x40)
        type = c_m3Type_none;
    else if (type == 16 || type == 17)  /* funcref/externref -- treat as i32 handle */
        type = c_m3Type_i32;
    else if (type < c_m3Type_i32 or type > c_m3Type_f64)
        result = m3Err_invalidTypeId;"""

# ──────────────────────────────────────────────────────────────────────────────
# m3_compile.c – helpers inserted before Compile_Unreachable
# ──────────────────────────────────────────────────────────────────────────────
COMPILE_HELPERS = """\
/* Forward declarations for reference-types helpers */
static M3Result Compile_Operator (IM3Compilation o, m3opcode_t i_opcode);
M3Result        Compile_Select   (IM3Compilation o, m3opcode_t i_opcode);

/* typed select (0x1C): read+discard type vector, behave as plain select */
M3Result  Compile_SelectTyped  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 numTypes;
_   (ReadLEB_u32 (& numTypes, & o->wasm, o->wasmEnd));
    for (u32 i = 0; i < numTypes; i++) {
        i8 t;
_       (ReadLEB_i7 (& t, & o->wasm, o->wasmEnd));
    }
    return Compile_Select (o, 0x1b);
_catch: return result;
}

/* ref.null / ref.is_null / ref.func — push opaque i32 zero; good enough for load */
M3Result  Compile_RefNull  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    i8 reftype;
_   (ReadLEB_i7 (& reftype, & o->wasm, o->wasmEnd));
    (void)reftype;
_   (PushConst (o, 0, c_m3Type_i32));
_catch: return result;
}

M3Result  Compile_RefIsNull  (IM3Compilation o, m3opcode_t i_opcode)
{
    return Compile_Operator (o, 0x45);  /* reuse i32.eqz */
}

M3Result  Compile_RefFunc  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 funcIdx;
_   (ReadLEB_u32 (& funcIdx, & o->wasm, o->wasmEnd));
    (void)funcIdx;
_   (PushConst (o, 0, c_m3Type_i32));
_catch: return result;
}

"""

TABLE_STUBS = """\
/* table.get $t (0x25): for externref table (t==1) look up ext_vals; otherwise identity */
M3Result  Compile_TableGet  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 tableIdx;
_   (ReadLEB_u32 (& tableIdx, & o->wasm, o->wasmEnd));
    if (tableIdx == 1) {
        bw3_ext_ctx_ops_t *ctx = (bw3_ext_ctx_ops_t *)o->runtime->userdata;
        bool inReg   = IsStackTopInRegister (o);
        u16  idxSlot = inReg ? 0 : GetStackTopSlotNumber (o);
_       (Pop (o));
        IM3Operation op = inReg ? op_ExtTableGet_r : op_ExtTableGet_s;
_       (EmitOp (o, op));
        EmitPointer (o, ctx);
        if (!inReg) EmitSlotOffset (o, (i32)idxSlot);
_       (PushAllocatedSlotAndEmit (o, c_m3Type_i32));
    }
_catch: return result;
}

/* table.set $t (0x26): for externref table (t==1) store to ext_vals; otherwise discard */
M3Result  Compile_TableSet  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 tableIdx;
_   (ReadLEB_u32 (& tableIdx, & o->wasm, o->wasmEnd));
    if (tableIdx == 1) {
        bw3_ext_ctx_ops_t *ctx = (bw3_ext_ctx_ops_t *)o->runtime->userdata;
        /* Stack: [idx, ref]  ref is TOS */
        bool refInReg = IsStackTopInRegister (o);
        u16  refSlot  = refInReg ? 0 : GetStackTopSlotNumber (o);
_       (Pop (o));  /* pop ref */
        u16  idxSlot  = GetStackTopSlotNumber (o);
_       (Pop (o));  /* pop idx */
        IM3Operation op = refInReg ? op_ExtTableSet_rs : op_ExtTableSet_ss;
_       (EmitOp (o, op));
        EmitPointer (o, ctx);
        EmitSlotOffset (o, (i32)idxSlot);
        if (!refInReg) EmitSlotOffset (o, (i32)refSlot);
    } else {
_       (Pop (o));
_       (Pop (o));
    }
_catch: return result;
}

"""

TABLE_OPCODE_OLD = """\
    M3OP_RESERVED,  M3OP_RESERVED, M3OP_RESERVED,                                                       // 0x25 - 0x27"""

TABLE_OPCODE_OLD_HEAD = """\
    M3OP_RESERVED,  M3OP_RESERVED, M3OP_RESERVED,                                                       // 0x25...0x27"""

TABLE_OPCODE_NEW = """\
    M3OP( "table.get", 0, i_32,   d_emptyOpList, Compile_TableGet ),  // 0x25
    M3OP( "table.set",-2, none,  d_emptyOpList, Compile_TableSet ),  // 0x26
    M3OP_RESERVED,                                                     // 0x27"""

COMPILE_UNREACHABLE_ANCHOR = "M3Result  Compile_Unreachable  (IM3Compilation o, m3opcode_t i_opcode)"

# ──────────────────────────────────────────────────────────────────────────────
# Opcode table: typed select 0x1C
# ──────────────────────────────────────────────────────────────────────────────
SELECT_OLD = '''\
    M3OP( "select",             -2, any,    d_emptyOpList,                      Compile_Select  ),      // 0x1b

    M3OP_RESERVED,  M3OP_RESERVED, M3OP_RESERVED, M3OP_RESERVED,                                        // 0x1c - 0x1f'''

SELECT_NEW = '''\
    M3OP( "select",             -2, any,    d_emptyOpList,                      Compile_Select  ),      // 0x1b
    M3OP( "select t*",          -2, any,    d_emptyOpList,                      Compile_SelectTyped ),  // 0x1c
    M3OP_RESERVED,  M3OP_RESERVED, M3OP_RESERVED,                                                       // 0x1d - 0x1f'''

# ──────────────────────────────────────────────────────────────────────────────
# Opcode table: ref.null / ref.is_null / ref.func (0xD0-0xD2)
# ──────────────────────────────────────────────────────────────────────────────
EXTEND32_OLD = '''\
    M3OP( "i64.extend32_s",      0,  i_64,   d_unaryOpList (i64, Extend32_s),       NULL    ),          // 0xc4

# ifdef DEBUG // for codepage logging.'''

EXTEND32_NEW = '''\
    M3OP( "i64.extend32_s",      0,  i_64,   d_unaryOpList (i64, Extend32_s),       NULL    ),          // 0xc4

    /* reference types proposal */
    [0xd0] = M3OP( "ref.null",    1, i_32,   d_emptyOpList,  Compile_RefNull   ),  // 0xd0
    [0xd1] = M3OP( "ref.is_null", 0, i_32,   d_emptyOpList,  Compile_RefIsNull ),  // 0xd1
    [0xd2] = M3OP( "ref.func",    1, i_32,   d_emptyOpList,  Compile_RefFunc   ),  // 0xd2

# ifdef DEBUG // for codepage logging.'''


# ──────────────────────────────────────────────────────────────────────────────
# m3_compile.c – FC-prefix table ops (0x0C-0x11) stubs + opcode table extension
# ──────────────────────────────────────────────────────────────────────────────
FC_OPSTABLE_ANCHOR = "const M3OpInfo c_operationsFC [] ="

FC_TABLE_STUBS = """\
/* FC-prefix table ops (0x0C-0x11) — reference types proposal stubs */
M3Result  Compile_FCTableInit  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 elemIdx, tableIdx;
_   (ReadLEB_u32 (& elemIdx,  & o->wasm, o->wasmEnd));
_   (ReadLEB_u32 (& tableIdx, & o->wasm, o->wasmEnd));
    (void)elemIdx; (void)tableIdx;
_   (Pop (o)); _   (Pop (o)); _   (Pop (o));
_catch: return result;
}

M3Result  Compile_FCElemDrop  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 elemIdx;
_   (ReadLEB_u32 (& elemIdx, & o->wasm, o->wasmEnd));
    (void)elemIdx;
_catch: return result;
}

M3Result  Compile_FCTableCopy  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 dstIdx, srcIdx;
_   (ReadLEB_u32 (& dstIdx, & o->wasm, o->wasmEnd));
_   (ReadLEB_u32 (& srcIdx, & o->wasm, o->wasmEnd));
    (void)dstIdx; (void)srcIdx;
_   (Pop (o)); _   (Pop (o)); _   (Pop (o));
_catch: return result;
}

M3Result  Compile_FCTableGrow  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 tableIdx;
_   (ReadLEB_u32 (& tableIdx, & o->wasm, o->wasmEnd));
    if (tableIdx == 1) {
        bw3_ext_ctx_ops_t *ctx = (bw3_ext_ctx_ops_t *)o->runtime->userdata;
        /* Stack: [init_val, n]  n is TOS */
        bool nInReg = IsStackTopInRegister (o);
        u16  nSlot  = nInReg ? 0 : GetStackTopSlotNumber (o);
_       (Pop (o));  /* pop n */
_       (Pop (o));  /* pop init_val (discard) */
        IM3Operation op = nInReg ? op_ExtTableGrow_r : op_ExtTableGrow_s;
_       (EmitOp (o, op));
        EmitPointer (o, ctx);
        if (!nInReg) EmitSlotOffset (o, (i32)nSlot);
_       (PushAllocatedSlotAndEmit (o, c_m3Type_i32));
    } else {
_       (Pop (o)); _   (Pop (o));
_       (PushConst (o, (u64)(u32)(-1), c_m3Type_i32));
    }
_catch: return result;
}

M3Result  Compile_FCTableSize  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 tableIdx;
_   (ReadLEB_u32 (& tableIdx, & o->wasm, o->wasmEnd));
    if (tableIdx == 1) {
        bw3_ext_ctx_ops_t *ctx = (bw3_ext_ctx_ops_t *)o->runtime->userdata;
_       (EmitOp (o, op_ExtTableSize));
        EmitPointer (o, ctx);
_       (PushAllocatedSlotAndEmit (o, c_m3Type_i32));
    } else {
_       (PushConst (o, 0, c_m3Type_i32));
    }
_catch: return result;
}

M3Result  Compile_FCTableFill  (IM3Compilation o, m3opcode_t i_opcode)
{
    M3Result result = m3Err_none;
    u32 tableIdx;
_   (ReadLEB_u32 (& tableIdx, & o->wasm, o->wasmEnd));
    (void)tableIdx;
_   (Pop (o)); _   (Pop (o)); _   (Pop (o));
_catch: return result;
}

"""

FC_OPS_OLD = """\
    M3OP( "memory.copy",            0,  none,   d_emptyOpList,                           Compile_Memory_CopyFill ), // 0x0a
    M3OP( "memory.fill",            0,  none,   d_emptyOpList,                           Compile_Memory_CopyFill ), // 0x0b


# ifdef DEBUG
    M3OP( "termination", 0, c_m3Type_unknown ) // for find_operation_info
# endif
};"""

FC_OPS_NEW = """\
    M3OP( "memory.copy",            0,  none,   d_emptyOpList,                           Compile_Memory_CopyFill ), // 0x0a
    M3OP( "memory.fill",            0,  none,   d_emptyOpList,                           Compile_Memory_CopyFill ), // 0x0b

    /* reference types table operations */
    M3OP_F( "table.init",           0,  none,   d_emptyOpList,  Compile_FCTableInit  ),  // 0x0c
    M3OP_F( "elem.drop",            0,  none,   d_emptyOpList,  Compile_FCElemDrop   ),  // 0x0d
    M3OP_F( "table.copy",           0,  none,   d_emptyOpList,  Compile_FCTableCopy  ),  // 0x0e
    M3OP_F( "table.grow",           0,  i_32,   d_emptyOpList,  Compile_FCTableGrow  ),  // 0x0f
    M3OP_F( "table.size",           0,  i_32,   d_emptyOpList,  Compile_FCTableSize  ),  // 0x10
    M3OP_F( "table.fill",           0,  none,   d_emptyOpList,  Compile_FCTableFill  ),  // 0x11


# ifdef DEBUG
    M3OP( "termination", 0, c_m3Type_unknown ) // for find_operation_info
# endif
};"""


def patch_fc_table_ops(path):
    with open(path) as f:
        src = f.read()
    if "Compile_FCTableInit" in src:
        print(f"  [fc-table-ops] already applied in {os.path.basename(path)}")
        return
    if FC_OPSTABLE_ANCHOR not in src:
        print(f"  [fc-table-ops] anchor not found — skipping {os.path.basename(path)}", file=sys.stderr)
        return
    src = src.replace(FC_OPSTABLE_ANCHOR, FC_TABLE_STUBS + FC_OPSTABLE_ANCHOR, 1)
    with open(path, 'w') as f:
        f.write(src)
    print(f"  [fc-table-stubs] patched {os.path.basename(path)}")
    patch(path, FC_OPS_OLD, FC_OPS_NEW, "fc-table-opcodes-0x0c")


def patch(path, old, new, label):
    with open(path) as f:
        src = f.read()
    if old not in src:
        if new.split('\n')[0] in src or label + " already applied" in src:
            print(f"  [{label}] already applied in {os.path.basename(path)}")
        else:
            print(f"  [{label}] ANCHOR NOT FOUND in {os.path.basename(path)} — skipping", file=sys.stderr)
        return
    with open(path, 'w') as f:
        f.write(src.replace(old, new, 1))
    print(f"  [{label}] patched {os.path.basename(path)}")


def patch_compile_helpers(path):
    with open(path) as f:
        src = f.read()
    # Fix stale helpers that used the wrong op_Const_i32 identifier
    if "op_Const_i32" in src:
        src = src.replace(
            "_   (PushRegister (o, c_m3Type_i32));\n_   (EmitOp (o, op_Const_i32));\n    EmitPointer (o, (void*)(uintptr_t)0);",
            "_   (PushConst (o, 0, c_m3Type_i32));"
        )
        with open(path, 'w') as f:
            f.write(src)
        print(f"  [helpers-fixup] fixed op_Const_i32 in {os.path.basename(path)}")
    if "Compile_SelectTyped" in src:
        # Also add table stubs if missing
        if "Compile_TableGet" not in src:
            with open(path) as f:
                src = f.read()
            src = src.replace(COMPILE_UNREACHABLE_ANCHOR,
                              TABLE_STUBS + COMPILE_UNREACHABLE_ANCHOR, 1)
            with open(path, 'w') as f:
                f.write(src)
            print(f"  [table-stubs] patched {os.path.basename(path)}")
        else:
            print(f"  [helpers] already applied in {os.path.basename(path)}")
        return
    if COMPILE_UNREACHABLE_ANCHOR not in src:
        print(f"  [helpers] anchor not found — skipping {os.path.basename(path)}", file=sys.stderr)
        return
    src = src.replace(COMPILE_UNREACHABLE_ANCHOR,
                      COMPILE_HELPERS + TABLE_STUBS + COMPILE_UNREACHABLE_ANCHOR, 1)
    with open(path, 'w') as f:
        f.write(src)
    print(f"  [helpers] patched {os.path.basename(path)}")


# ──────────────────────────────────────────────────────────────────────────────
# m3_parse.c – ParseSection_Import: skip table import bytes to keep parser in sync
# ──────────────────────────────────────────────────────────────────────────────
PARSE_TABLE_IMPORT_OLD = """\
            case d_externalKind_table:
//                  result = ParseType_Table (& i_bytes, i_end);
                break;"""

PARSE_TABLE_IMPORT_NEW = """\
            case d_externalKind_table:
            {
                /* skip table element type (reftype) + limits so parser stays in sync */
                i8 refType; u8 flag; u32 limits;
_               (ReadLEB_i7 (& refType, & i_bytes, i_end));
_               (ReadLEB_u7 (& flag,    & i_bytes, i_end));
_               (ReadLEB_u32(& limits,  & i_bytes, i_end));
                if (flag & 1) { _  (ReadLEB_u32(& limits, & i_bytes, i_end)); }
            }
            break;"""


# ──────────────────────────────────────────────────────────────────────────────
# m3_exec.h – bw3 externref table ops appended before d_m3EndExternC
# ──────────────────────────────────────────────────────────────────────────────
EXEC_EXT_OPS = """\
/* ── bw3 externref table ops ────────────────────────────────────────────────
 * Layout must match bw3_ext_ctx_t in binding.c.
 * Immediates layout:
 *   ExtTableGrow_r  : [ctx*] [out_slot]
 *   ExtTableGrow_s  : [ctx*] [n_slot] [out_slot]
 *   ExtTableSize    : [ctx*] [out_slot]
 *   ExtTableGet_r   : [ctx*] [out_slot]
 *   ExtTableGet_s   : [ctx*] [idx_slot] [out_slot]
 *   ExtTableSet_rs  : [ctx*] [idx_slot]          (ref = _r0)
 *   ExtTableSet_ss  : [ctx*] [idx_slot] [ref_slot]
 */
typedef struct { uint32_t ext_size; uint32_t ext_cap; uint32_t *ext_vals; } bw3_ext_ctx_ops_t;

d_m3Op(ExtTableGrow_r)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    uint32_t n   = (uint32_t)_r0;
    uint32_t old = ctx->ext_size;
    uint32_t res = (old + n <= ctx->ext_cap) ? (ctx->ext_size = old + n, old) : (uint32_t)(-1);
    slot(uint32_t) = res;
    nextOp();
}

d_m3Op(ExtTableGrow_s)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    uint32_t n   = slot(uint32_t);
    uint32_t old = ctx->ext_size;
    uint32_t res = (old + n <= ctx->ext_cap) ? (ctx->ext_size = old + n, old) : (uint32_t)(-1);
    slot(uint32_t) = res;
    nextOp();
}

d_m3Op(ExtTableSize)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    slot(uint32_t) = ctx->ext_size;
    nextOp();
}

d_m3Op(ExtTableGet_r)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    uint32_t idx = (uint32_t)_r0;
    uint32_t ref = (idx < ctx->ext_size) ? ctx->ext_vals[idx] : 0;
    slot(uint32_t) = ref;
    nextOp();
}

d_m3Op(ExtTableGet_s)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    uint32_t idx = slot(uint32_t);
    uint32_t ref = (idx < ctx->ext_size) ? ctx->ext_vals[idx] : 0;
    slot(uint32_t) = ref;
    nextOp();
}

d_m3Op(ExtTableSet_rs)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    uint32_t idx = slot(uint32_t);
    uint32_t ref = (uint32_t)_r0;
    if (idx < ctx->ext_cap) ctx->ext_vals[idx] = ref;
    nextOp();
}

d_m3Op(ExtTableSet_ss)
{
    bw3_ext_ctx_ops_t *ctx = immediate(bw3_ext_ctx_ops_t *);
    uint32_t idx = slot(uint32_t);
    uint32_t ref = slot(uint32_t);
    if (idx < ctx->ext_cap) ctx->ext_vals[idx] = ref;
    nextOp();
}

"""

EXEC_END_ANCHOR = "d_m3EndExternC\n\n#endif // m3_exec_h"


def patch_exec_ops(path):
    with open(path) as f:
        src = f.read()
    if "ExtTableGrow_r" in src:
        print(f"  [exec-ext-ops] already applied in {os.path.basename(path)}")
        return
    if EXEC_END_ANCHOR not in src:
        print(f"  [exec-ext-ops] anchor not found — skipping {os.path.basename(path)}", file=sys.stderr)
        return
    with open(path, 'w') as f:
        f.write(src.replace(EXEC_END_ANCHOR, EXEC_EXT_OPS + EXEC_END_ANCHOR, 1))
    print(f"  [exec-ext-ops] patched {os.path.basename(path)}")


for build_dir in BUILD_DIRS:
    src_dir = os.path.join(BASE, build_dir,
                           "_deps/github+wasm3+wasm3-src/source")
    core    = os.path.join(src_dir, "m3_core.c")
    compile = os.path.join(src_dir, "m3_compile.c")

    if not os.path.exists(core):
        print(f"Skipping {build_dir} (not yet generated)")
        continue

    parse  = os.path.join(src_dir, "m3_parse.c")
    m3exec = os.path.join(src_dir, "m3_exec.h")

    print(f"Patching {build_dir} ...")
    patch(core,    CORE_OLD,     CORE_NEW,    "NormalizeType")
    patch(parse,   PARSE_TABLE_IMPORT_OLD, PARSE_TABLE_IMPORT_NEW, "table-import-skip")
    patch_compile_helpers(compile)
    patch(compile, SELECT_OLD,   SELECT_NEW,   "typed-select-0x1c")
    patch(compile, TABLE_OPCODE_OLD,      TABLE_OPCODE_NEW, "table-opcodes-0x25")
    patch(compile, TABLE_OPCODE_OLD_HEAD, TABLE_OPCODE_NEW, "table-opcodes-0x25")
    patch(compile, EXTEND32_OLD, EXTEND32_NEW, "ref-opcodes-0xd0")
    patch_fc_table_ops(compile)
    patch_exec_ops(m3exec)

print("Done.")
