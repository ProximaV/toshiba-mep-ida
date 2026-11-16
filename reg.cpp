#pragma warning ( disable : 4146)
#include "mep.hpp"
#include <idd.hpp>
#include <typeinf.hpp>

int data_id;


//------------------------------------------------------------------------
static bool idaapi can_have_type(const op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:
    case o_reg:
    case o_near:
      return 0;
//    case o_phrase: can have type because of ASI or 0 struct offsets
  }
  return 1;
}

//--------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t /*code*/, va_list)
{
    return 0;
}

//--------------------------------------------------------------------------

// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void*, int msgid, va_list)
{
    if (msgid == processor_t::ev_get_procmod)
        return size_t(SET_MODULE_DATA(mep_t));
    return 0;
}

void mep_t::set_repeat_loop(ea_t tail_ea, ea_t rpb_ea, bool is_erepeat)
{
  if ( tail_ea == BADADDR || rpb_ea == BADADDR )
    return;
  uval_t encoded = (rpb_ea & ~uval_t(1)) | (is_erepeat ? 1 : 0);
  helper.altset(tail_ea, encoded, 'R');
}

bool mep_t::get_repeat_loop(ea_t tail_ea, ea_t *p_rpb_ea, bool *p_is_erepeat) const
{
  uval_t encoded = helper.altval(tail_ea, 'R');
  if ( encoded == 0 )
    return false;
  if ( p_rpb_ea != nullptr )
    *p_rpb_ea = ea_t(encoded & ~uval_t(1));
  if ( p_is_erepeat != nullptr )
    *p_is_erepeat = (encoded & 1) != 0;
  return true;
}

static int mep_resolve_reg_idx(const char *const *reg_names, int regs_num, const char *regname)
{
  if ( reg_names == nullptr || regname == nullptr || *regname == '\0' )
    return -1;

  auto find_exact = [&](const char *target) -> int
  {
    for ( int i = 0; i < regs_num; i++ )
    {
      if ( reg_names[i] != nullptr && strieq(reg_names[i], target) )
        return i;
    }
    return -1;
  };

  // 1. Exact canonical match in ph.reg_names (note: skip index 0 "h-pc" unless asked explicitly)
  int idx = find_exact(regname);
  if ( idx >= 0 )
  {
    if ( idx == 0 )
    {
      int pc_idx = find_exact("$pc");
      if ( pc_idx >= 0 )
        return pc_idx;
    }
    return idx;
  }

  // 2. Explicit GPR / CSR aliases
  struct reg_alias_t
  {
    const char *alias;
    const char *canonical;
  };
  static const reg_alias_t kRegAliases[] =
  {
    { "h-pc",      "$pc"  },
    { "r0",        "$0"   }, { "$r0",  "$0"  },
    { "r1",        "$1"   }, { "$r1",  "$1"  },
    { "r2",        "$2"   }, { "$r2",  "$2"  },
    { "r3",        "$3"   },
    { "r4",        "$4"   }, { "$r4",  "$4"  },
    { "r5",        "$5"   }, { "$r5",  "$5"  },
    { "r6",        "$6"   }, { "$r6",  "$6"  },
    { "r7",        "$7"   }, { "$r7",  "$7"  },
    { "r8",        "$8"   }, { "$r8",  "$8"  },
    { "fp",        "$8"   }, { "$fp",  "$8"  },
    { "r9",        "$9"   },
    { "r10",       "$10"  },
    { "r11",       "$11"  },
    { "r12",       "$12"  }, { "$r12", "$12" },
    { "r13",       "$tp"  }, { "$r13", "$tp" },
    { "r14",       "$gp"  }, { "$r14", "$gp" },
    { "r15",       "$sp"  }, { "$r15", "$sp" },
    { "$h-csr-3",  "$r3"  },
    { "$h-csr-9",  "$r9"  },
    { "$h-csr-10", "$r10" },
    { "$h-csr-11", "$r11" },
    { "$h-csr-29", "$r29" },
    { "$h-csr-30", "$r30" },
    { "$h-csr-31", "$r31" },
  };
  for ( size_t i = 0; i < qnumber(kRegAliases); i++ )
  {
    if ( strieq(kRegAliases[i].alias, regname) )
    {
      int aliased = find_exact(kRegAliases[i].canonical);
      if ( aliased >= 0 )
        return aliased;
    }
  }

  // 3. Bare names without leading '$' (e.g. "pc", "sp", "ivb", "ier")
  for ( int i = 0; i < regs_num; i++ )
  {
    const char *rn = reg_names[i];
    if ( rn != nullptr && rn[0] == '$' && strieq(rn + 1, regname) )
      return i;
  }
  return -1;
}

ssize_t idaapi mep_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;

  switch ( msgid )
  {
    case processor_t::ev_init:
      helper.create("$ mep");
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      inf_set_be(false);       // Set a little endian mode of the IDA kernel
      break;

    case processor_t::ev_term:
      unhook_event_listener(HT_IDB, &idb_listener);
      clr_module_data(data_id);
      break;

    case processor_t::ev_privrange_changed:
      helper.create("$ mep");
      break;

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return mep_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return mep_emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    case processor_t::ev_can_have_type:
      {
        const op_t *op = va_arg(va, const op_t *);
        return can_have_type(*op) ? 1 : -1;
      }

    case processor_t::ev_setup_til:
      {
        inf_set_cc_id(COMP_GNU);
        inf_set_cc_cm(CM_N32_F48 | CM_CC_CDECL);
        inf_set_cc_defalign(4);
        inf_set_cc_size_i(4);
        inf_set_cc_size_b(1);
        inf_set_cc_size_e(4);
        inf_set_cc_size_s(2);
        inf_set_cc_size_l(4);
        inf_set_cc_size_ll(8);
        inf_set_cc_size_ldbl(8);
        add_til("gnucmn", ADDTIL_DEFAULT);
        return 1;
      }

    case processor_t::ev_max_ptr_size:
      return 4;

    case processor_t::ev_calc_cdecl_purged_bytes:
      return 0;

    case processor_t::ev_get_cc_regs:
      {
        callregs_t *callregs = va_arg(va, callregs_t *);
        callcnv_t cc = va_arg(va, callcnv_t);
        static const int mep_argregs[] = {
          MEP_REG_R1, MEP_REG_R2, MEP_REG_R3, MEP_REG_R4, -1
        };
        callregs->set(ARGREGS_INDEPENDENT, mep_argregs, nullptr);
        return 1;
      }

    case processor_t::ev_calc_retloc:
      {
        argloc_t *retloc = va_arg(va, argloc_t *);
        const tinfo_t *type = va_arg(va, const tinfo_t *);
        cm_t cc = va_arg(va, cm_t);
        if ( type->is_void() )
          return 1;
        size_t size = type->get_size();
        if ( size == BADSIZE || size == 0 )
          return -1;
        if ( size <= 4 )
          retloc->set_reg1(MEP_REG_R0);
        else if ( size <= 8 )
          retloc->set_reg2(MEP_REG_R0, MEP_REG_R1);
        else
          return -1;
        return 1;
      }

    case processor_t::ev_calc_arglocs:
      {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        if ( !fti->rettype.is_void() )
        {
          size_t retsize = fti->rettype.get_size();
          if ( retsize != BADSIZE && retsize > 0 )
          {
            if ( retsize <= 4 )
              fti->retloc.set_reg1(MEP_REG_R0);
            else if ( retsize <= 8 )
              fti->retloc.set_reg2(MEP_REG_R0, MEP_REG_R1);
          }
        }
        static const int argregs[] = {
          MEP_REG_R1, MEP_REG_R2, MEP_REG_R3, MEP_REG_R4
        };
        const int num_argregs = qnumber(argregs);
        int r = 0; // argreg index

        size_t retsize = fti->rettype.get_size();
        if ( retsize != BADSIZE && retsize > 8 )
          r++; // struct return pointer in $1

        sval_t spoff = 0;
        for ( size_t i = 0; i < fti->size(); ++i )
        {
          funcarg_t &fa = (*fti)[i];
          size_t size = fa.type.get_size();
          if ( size == BADSIZE || size == 0 )
            return -1;
          int nregs = (int(size) + 3) / 4;
          if ( r + nregs <= num_argregs && nregs <= 2 )
          {
            if ( nregs == 1 )
              fa.argloc.set_reg1(argregs[r]);
            else
              fa.argloc.set_reg2(argregs[r], argregs[r + 1]);
            r += nregs;
          }
          else
          {
            r = num_argregs;
            spoff = align_up(spoff, 4);
            fa.argloc.set_stkoff(spoff);
            spoff += align_up(sval_t(size), 4);
          }
        }
        fti->stkargs = spoff;
        return 1;
      }

    case processor_t::ev_is_call_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        uint32 feature = insn->get_canon_feature(ph);
        return (feature & CF_CALL) != 0 ? 1 : -1;
      }

    case processor_t::ev_is_ret_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        if ( insn->itype == MEP_INSN_RET
          || insn->itype == MEP_INSN_RETI
          || insn->itype == MEP_INSN_DRET )
          return 1;
        if ( insn->itype == MEP_INSN_JMP && insn->Op1.type == o_reg && insn->Op1.reg == MEP_REG_LP )
          return 1;
        return -1;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *op);
        return 1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        return (pfn != nullptr && create_func_frame(pfn->start_ea)) ? 1 : 0;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        qnotused(pfn);
        *frsize = 0; // MeP stores return address in $lp, not on stack at call
        return 1;
      }

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return mep_is_switch(si, *insn) ? 1 : -1;
      }

    case processor_t::ev_loader_elf_machine:
      {
        linput_t *li = va_arg(va, linput_t *);
        int machine_type = va_arg(va, int);
        const char **p_procname = va_arg(va, const char **);
        (void)li; // unused variable
        if ( machine_type == 0xF00D )
        {
          *p_procname = "MeP";
          code = 0xF00D;
        }
      }
      break;

    case processor_t::ev_next_exec_insn:
      {
        ea_t *target                      = va_arg(va, ea_t *);
        ea_t ea                           = va_arg(va, ea_t);
        int tid                           = va_arg(va, int);
        processor_t::regval_getter_t *getreg = va_arg(va, processor_t::regval_getter_t *);
        const regval_t *regvalues         = va_arg(va, const regval_t *);
        qnotused(tid);
        if ( target == nullptr || getreg == nullptr || regvalues == nullptr )
          return 0;
        insn_t ins;
        if ( decode_insn(&ins, ea) <= 0 )
          return 0;
        ea_t next_ea = ea + ins.size;
        auto reg32 = [&](int reg_idx) -> uint32
        {
          if ( reg_idx < 0 || reg_idx >= ph.regs_num || ph.reg_names[reg_idx] == nullptr )
            return 0;
          return (uint32)getreg(ph.reg_names[reg_idx], regvalues).ival;
        };
        switch ( ins.itype )
        {
          case MEP_INSN_BRA:
          case MEP_INSN_JMP24:
          case MEP_INSN_BSR12:
          case MEP_INSN_BSR24:
          case MEP_INSN_BSRV:
            if ( ins.Op1.type == o_near )
              next_ea = ins.Op1.addr;
            break;
          case MEP_INSN_JMP:
          case MEP_INSN_JSR:
          case MEP_INSN_JSRV:
            if ( ins.Op1.type == o_near )
              next_ea = ins.Op1.addr;
            else if ( ins.Op1.type == o_reg )
              next_ea = (ea_t)(reg32(ins.Op1.reg) & ~1u);
            break;
          case MEP_INSN_RET:
            next_ea = (ea_t)(getreg("$lp", regvalues).ival & ~1ULL);
            break;
          case MEP_INSN_RETI:
            {
              uint64 psw = getreg("$psw", regvalues).ival;
              next_ea = (ea_t)(getreg((psw & (1u << 2)) ? "$npc" : "$epc", regvalues).ival & ~1ULL);
            }
            break;
          case MEP_INSN_DRET:
            next_ea = (ea_t)(getreg("$depc", regvalues).ival & ~1ULL);
            break;
          case MEP_INSN_BEQZ:
            if ( reg32(ins.Op1.reg) == 0 )
              next_ea = ins.Op2.addr;
            break;
          case MEP_INSN_BNEZ:
            if ( reg32(ins.Op1.reg) != 0 )
              next_ea = ins.Op2.addr;
            break;
          case MEP_INSN_BEQI:
            if ( reg32(ins.Op1.reg) == (uint32)ins.Op2.value )
              next_ea = ins.Op3.addr;
            break;
          case MEP_INSN_BNEI:
            if ( reg32(ins.Op1.reg) != (uint32)ins.Op2.value )
              next_ea = ins.Op3.addr;
            break;
          case MEP_INSN_BLTI:
            if ( (int32)reg32(ins.Op1.reg) < (int32)ins.Op2.value )
              next_ea = ins.Op3.addr;
            break;
          case MEP_INSN_BGEI:
            if ( (int32)reg32(ins.Op1.reg) >= (int32)ins.Op2.value )
              next_ea = ins.Op3.addr;
            break;
          case MEP_INSN_BEQ:
            if ( reg32(ins.Op1.reg) == reg32(ins.Op2.reg) )
              next_ea = ins.Op3.addr;
            break;
          case MEP_INSN_BNE:
            if ( reg32(ins.Op1.reg) != reg32(ins.Op2.reg) )
              next_ea = ins.Op3.addr;
            break;
          default:
            {
              uint64 rpb = getreg("$rpb", regvalues).ival;
              uint64 rpe = getreg("$rpe", regvalues).ival;
              uint64 rpc = getreg("$rpc", regvalues).ival;
              if ( (rpe & ~1ULL) != 0 && ea == (ea_t)(rpe & ~1ULL) )
              {
                if ( (rpe & 1ULL) != 0 || rpc > 1 )
                  next_ea = (ea_t)(rpb & ~1ULL);
              }
            }
            break;
        }
        *target = next_ea;
        return 1;
      }

    case processor_t::ev_calc_step_over:
      {
        ea_t *target = va_arg(va, ea_t *);
        ea_t ip      = va_arg(va, ea_t);
        if ( target == nullptr || ip == BADADDR )
          return 0;
        insn_t ins;
        if ( decode_insn(&ins, ip) > 0
          && (ins.itype == MEP_INSN_BSR12
           || ins.itype == MEP_INSN_BSR24
           || ins.itype == MEP_INSN_JSR
           || ins.itype == MEP_INSN_BSRV
           || ins.itype == MEP_INSN_JSRV
           || ins.itype == MEP_INSN_SWI) )
        {
          *target = ip + ins.size;
          return 1;
        }
        *target = BADADDR;
        return 1;
      }

    case processor_t::ev_get_idd_opinfo:
      {
        idd_opinfo_t *opinf                  = va_arg(va, idd_opinfo_t *);
        ea_t ea                              = va_arg(va, ea_t);
        int n                                = va_arg(va, int);
        int thread_id                        = va_arg(va, int);
        processor_t::regval_getter_t *getreg = va_arg(va, processor_t::regval_getter_t *);
        const regval_t *regvalues            = va_arg(va, const regval_t *);
        qnotused(thread_id);
        if ( opinf == nullptr )
          return 0;
        opinf->ea = BADADDR;
        opinf->debregidx = -1;
        opinf->modified = false;
        opinf->value.ival = 0;
        opinf->value_size = 4;
        insn_t ins;
        if ( decode_insn(&ins, ea) <= 0 || n < 0 || n >= UA_MAXOP )
          return 0;
        const op_t &op = ins.ops[n];
        if ( op.type == o_void )
          return 0;

        auto map_idd_reg = [&](int reg_idx, const char **out_name, int *out_dbg_idx) -> bool
        {
          if ( reg_idx >= REGS_HW_H_GPR_BASE && reg_idx < REGS_HW_H_GPR_BASE + 16 )
          {
            *out_dbg_idx = reg_idx - REGS_HW_H_GPR_BASE;
            *out_name = ph.reg_names[reg_idx];
            return *out_name != nullptr;
          }
          if ( reg_idx >= REGS_HW_H_CSR_BASE && reg_idx < REGS_HW_H_CSR_BASE + 32 )
          {
            static const char *const kCsrDbgNames[32] =
            {
              "$pc",  "$lp",  "$sar", "$r3",  "$rpb", "$rpe", "$rpc", "$hi",
              "$lo",  "$r9",  "$r10", "$r11", "$mb0", "$me0", "$mb1", "$me1",
              "$psw", "$id",  "$tmp", "$epc", "$exc", "$cfg", "$vid", "$npc",
              "$dbg", "$depc","$opt", "$rcfg","$ccfg","$r29", "$r30", "$r31",
            };
            const int csr_idx = reg_idx - REGS_HW_H_CSR_BASE;
            *out_dbg_idx = 16 + csr_idx;
            *out_name = kCsrDbgNames[csr_idx];
            return true;
          }
          if ( reg_idx == REGS_HW_H_PC_BASE )
          {
            *out_dbg_idx = 16;
            *out_name = "$pc";
            return true;
          }
          return false;
        };

        switch ( op.type )
        {
          case o_reg:
            {
              const char *rname = nullptr;
              int dbg_idx = -1;
              if ( map_idd_reg(op.reg, &rname, &dbg_idx) )
              {
                opinf->debregidx = dbg_idx;
                if ( getreg != nullptr && regvalues != nullptr )
                  opinf->value = getreg(rname, regvalues);
                return 1;
              }
              if ( op.reg < ph.regs_num && ph.reg_names[op.reg] != nullptr && getreg != nullptr && regvalues != nullptr )
              {
                opinf->value = getreg(ph.reg_names[op.reg], regvalues);
                return 1;
              }
            }
            break;
          case o_near:
          case o_mem:
            opinf->ea = op.addr;
            return 1;
          case o_imm:
            opinf->value.ival = op.value;
            return 1;
          case o_displ:
            {
              const char *rname = nullptr;
              int dbg_idx = -1;
              if ( map_idd_reg(op.reg, &rname, &dbg_idx) && getreg != nullptr && regvalues != nullptr )
              {
                uint32 base = (uint32)getreg(rname, regvalues).ival;
                opinf->ea = (ea_t)(base + (int32)op.addr);
                return 1;
              }
              if ( op.reg < ph.regs_num && ph.reg_names[op.reg] != nullptr && getreg != nullptr && regvalues != nullptr )
              {
                uint32 base = (uint32)getreg(ph.reg_names[op.reg], regvalues).ival;
                opinf->ea = (ea_t)(base + (int32)op.addr);
                return 1;
              }
            }
            break;
          default:
            break;
        }
        return 0;
      }

    case processor_t::ev_str2reg:
      {
        const char *regname = va_arg(va, const char *);
        int idx = mep_resolve_reg_idx(ph.reg_names, ph.regs_num, regname);
        return idx >= 0 ? (idx + 1) : 0;
      }

    case processor_t::ev_get_reg_info:
      {
        const char **main_regname = va_arg(va, const char **);
        bitrange_t *bitrange      = va_arg(va, bitrange_t *);
        const char *regname       = va_arg(va, const char *);
        int idx = mep_resolve_reg_idx(ph.reg_names, ph.regs_num, regname);
        if ( idx < 0 )
          return -1;
        if ( main_regname != nullptr )
          *main_regname = ph.reg_names[idx];
        if ( bitrange != nullptr )
          *bitrange = bitrange_t(0, 32);
        return 1;
      }

    default:
      break;
  }

  return code;
}

//--------------------------------------------------------------------------

static const asm_t mepasm =
{
  ASH_HEXF3 | ASO_OCTF1 | ASB_BINF3,
  0,
  "MeP assembler",
  0,
  NULL,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter (no char consts)
  "\\\"'",      // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".dword",     // dword  (4 bytes)
  ".qword",     // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",       // Equ
  NULL,         // seg prefix
//  preline, NULL, operdim,
  NULL, NULL, NULL,
  NULL,
  NULL,
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  0, 0,     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};

static const asm_t *const asms[] = { &mepasm, NULL };

//-----------------------------------------------------------------------
static const uchar retcode_1[] = { 0x02, 0x70 }; // ret
static const uchar retcode_2[] = { 0x12, 0x70 }; // reti

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, NULL }
};

//--------------------------------------------------------------------------

#define FAMILY "Toshiba MeP family:"
static const char *const shnames[] = { "MeP", NULL };
static const char *const lnames[]  = { FAMILY"Toshiba MeP C5 media engine", NULL };

//--------------------------------------------------------------------------

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

#define PLFM_MEP 0xF00D
#include "reg.hpp"

processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_MEP,               // id
                          // flag
  PR_USE32
  |PR_DEFSEG32
  |PRN_HEX
  |PR_WORD_INS
//  |PR_BINMEM
  |PR_RNAMESOK          // can use register names for byte names
  |PR_SEGTRANS          // segment translation is supported (codeSeg)
  |PR_SGROTHER          // the segment registers don't contain
                        // the segment selectors, something else
  |PR_TYPEINFO,         // the processor module supports type information
                          // flag2
  0,                      // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,
  qnumber(RegNames),    // number of registers

  qnumber(RegNames)-2,qnumber(RegNames)-1, // first, last
  0,                    // size of a segment register
  qnumber(RegNames)-2,qnumber(RegNames)-1, // virtual CS,DS

  NULL,                 // No known code start sequences
  retcodes,             // 'Return' instruction codes

  0, MEP_INSN_LAST,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  MEP_INSN_RET,         // Icode of return instruction. It is ok to give any of possible return instructions
};
