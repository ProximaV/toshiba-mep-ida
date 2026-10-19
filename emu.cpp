/* MEP IDP instructions emulator

   Upgraded for IDA Pro 9.4 SDK and cross-referenced against the
   Toshiba MeP-c4 Media Embedded Processor Architecture Specification
   (DSAE0020861).
*/

#pragma warning ( disable : 4146 )
#include "mep.hpp"

//----------------------------------------------------------------------
// Resolve global base register symbols ($gp / $tp) if defined in the IDB
static bool find_global_base_symbol(int reg, uval_t *p_val)
{
  if ( reg == MEP_REG_GP )
  {
    static const char *const gp_names[] = { "_gp", "__gp", "_sda_base_", "__sda_base" };
    for ( size_t i = 0; i < qnumber(gp_names); ++i )
    {
      ea_t ea = get_name_ea(BADADDR, gp_names[i]);
      if ( ea != BADADDR )
      {
        *p_val = (uint32)ea;
        return true;
      }
    }
  }
  else if ( reg == MEP_REG_TP )
  {
    static const char *const tp_names[] = { "_tp", "__tp", "_tda_base_", "__tda_base" };
    for ( size_t i = 0; i < qnumber(tp_names); ++i )
    {
      ea_t ea = get_name_ea(BADADDR, tp_names[i]);
      if ( ea != BADADDR )
      {
        *p_val = (uint32)ea;
        return true;
      }
    }
  }
  return false;
}

//----------------------------------------------------------------------
// Scan backwards within the current basic block / function to determine
// the constant 32-bit value held in `reg` prior to executing `ea`.
// If the value came directly from a `movh` instruction, `*p_movh_ea` is
// set to the address of that `movh` instruction.
bool mep_t::find_reg_value(ea_t ea, int reg, uval_t *p_val, ea_t *p_movh_ea, int max_steps)
{
  if ( p_movh_ea != nullptr )
    *p_movh_ea = BADADDR;

  if ( reg == MEP_REG_SP || reg == MEP_REG_FP )
    return false;

  ea_t func_start = get_func_start(ea);
  ea_t cur_ea = ea;

  for ( int step = 0; step < max_steps && cur_ea != BADADDR; ++step )
  {
    if ( func_start != BADADDR && cur_ea <= func_start )
      break;

    // Stop if cur_ea is the target of a non-fallthrough code reference
    if ( step > 0 )
    {
      xrefblk_t xb;
      bool has_branch_in = false;
      for ( bool ok = xb.first_to(cur_ea, XREF_FAR); ok; ok = xb.next_to() )
      {
        if ( xb.iscode )
        {
          has_branch_in = true;
          break;
        }
      }
      if ( has_branch_in )
        break;
    }

    insn_t prev;
    ea_t prev_ea = decode_prev_insn(&prev, cur_ea);
    if ( prev_ea == BADADDR )
      break;
    cur_ea = prev_ea;

    uint32 feature = prev.get_canon_feature(ph);
    if ( (feature & CF_STOP) != 0 )
      break;

    // Check instructions that write to `reg`
    switch ( prev.itype )
    {
      case MEP_INSN_MOVI8:
      case MEP_INSN_MOVI16:
        if ( prev.Op1.reg == reg )
        {
          if ( prev.Op2.type == o_mem )
            *p_val = (uint32)prev.Op2.addr;
          else
            *p_val = (uint32)(int32)(int16)prev.Op2.value;
          return true;
        }
        break;

      case MEP_INSN_MOVU16:
        if ( prev.Op1.reg == reg )
        {
          if ( prev.Op2.type == o_mem )
            *p_val = (uint32)prev.Op2.addr;
          else
            *p_val = (uint32)(prev.Op2.value & 0xFFFF);
          return true;
        }
        break;

      case MEP_INSN_MOVU24:
        if ( prev.Op1.reg == reg )
        {
          if ( prev.Op2.type == o_mem )
            *p_val = (uint32)prev.Op2.addr;
          else
            *p_val = (uint32)(prev.Op2.value & 0xFFFFFF);
          return true;
        }
        break;

      case MEP_INSN_MOVH:
        if ( prev.Op1.reg == reg )
        {
          // Note: ana.cpp stores (f_16u16 << 16) in Op2.value when o_imm.
          // If Op2 was already converted to o_mem by refinfo, read the raw
          // upper 16-bit immediate from the second halfword of the instruction.
          uint32 hi = (prev.Op2.type == o_imm)
                    ? (uint32)prev.Op2.value
                    : ((uint32)get_word(prev.ea + 2) << 16);
          *p_val = hi;
          if ( p_movh_ea != nullptr )
            *p_movh_ea = prev.ea;
          return true;
        }
        break;

      case MEP_INSN_MOV:
        if ( prev.Op1.reg == reg && prev.Op2.type == o_reg )
        {
          reg = prev.Op2.reg;
          if ( reg == MEP_REG_SP || reg == MEP_REG_FP )
            return false;
          continue;
        }
        break;

      case MEP_INSN_ADD3X:
        if ( prev.Op1.reg == reg )
        {
          if ( prev.Op3.type == o_mem )
          {
            *p_val = (uint32)prev.Op3.addr;
            return true;
          }
          uval_t base_val = 0;
          if ( find_reg_value(prev.ea, prev.Op2.reg, &base_val, nullptr, max_steps - step - 1) )
          {
            int16 simm16 = (prev.Op3.type == o_imm)
                         ? (int16)prev.Op3.value
                         : (int16)get_word(prev.ea + 2);
            *p_val = (uint32)(base_val + (int32)simm16);
            return true;
          }
          return false;
        }
        break;

      case MEP_INSN_OR3:
        if ( prev.Op1.reg == reg )
        {
          if ( prev.Op3.type == o_mem )
          {
            *p_val = (uint32)prev.Op3.addr;
            return true;
          }
          uval_t base_val = 0;
          if ( find_reg_value(prev.ea, prev.Op2.reg, &base_val, nullptr, max_steps - step - 1) )
          {
            uint16 uimm16 = (prev.Op3.type == o_imm)
                          ? (uint16)prev.Op3.value
                          : (uint16)get_word(prev.ea + 2);
            *p_val = (uint32)(base_val | uimm16);
            return true;
          }
          return false;
        }
        break;

      case MEP_INSN_ADD:
        if ( prev.Op1.reg == reg && prev.Op2.type == o_imm )
        {
          uval_t base_val = 0;
          if ( find_reg_value(prev.ea, reg, &base_val, nullptr, max_steps - step - 1) )
          {
            *p_val = (uint32)(base_val + (int32)prev.Op2.value);
            return true;
          }
          return false;
        }
        break;

      default:
        break;
    }

    // Stop if `prev` clobbers `reg`
    if ( (feature & CF_CHG1) != 0 && prev.Op1.type == o_reg && prev.Op1.reg == reg )
      return false;
    if ( (feature & CF_CHG2) != 0 && prev.Op2.type == o_reg && prev.Op2.reg == reg )
      return false;
    if ( (feature & CF_CHG3) != 0 && prev.Op3.type == o_reg && prev.Op3.reg == reg )
      return false;

    // Calls clobber caller-saved registers $0..$4 and $lp
    if ( (feature & CF_CALL) != 0 )
    {
      if ( (reg >= MEP_REG_R0 && reg <= MEP_REG_R4) || reg == MEP_REG_LP )
        return false;
    }
  }

  return find_global_base_symbol(reg, p_val);
}

//----------------------------------------------------------------------
// Recognize Toshiba MeP switch/jump table idioms before an indirect `jmp $rm`
bool mep_t::mep_is_switch(switch_info_t *si, const insn_t &insn)
{
  if ( insn.itype != MEP_INSN_JMP || insn.Op1.type != o_reg )
    return false;

  // Match pattern:
  //   sl2ad3  $0, $idx, $base
  //   movu24  $tmp, #jt_addr   (or movh + add3 / or3)
  //   lh / lw $rm, ($0)
  //   add     $rm, $tmp
  //   jmp     $rm
  insn_t prev;
  if ( decode_prev_insn(&prev, insn.ea) == BADADDR )
    return false;

  if ( prev.itype != MEP_INSN_ADD )
    return false;

  int jump_reg = insn.Op1.reg;
  if ( prev.Op1.reg != jump_reg )
    return false;
  int jt_addr_reg = prev.Op2.reg;

  if ( decode_prev_insn(&prev, prev.ea) == BADADDR )
    return false;

  if ( prev.itype == MEP_INSN_LH )
    si->flags |= SWI_SIGNED | SWI_ELBASE | SWI_V32;
  else if ( prev.itype == MEP_INSN_LHU )
    si->flags |= SWI_ELBASE | SWI_V32;
  else if ( prev.itype == MEP_INSN_LW )
    si->flags |= SWI_SIGNED | SWI_ELBASE | SWI_J32 | SWI_V32;
  else
    return false;

  if ( prev.Op1.reg != jump_reg || prev.Op2.reg != MEP_REG_R0 )
    return false;

  ea_t load_ea = prev.ea;
  if ( decode_prev_insn(&prev, load_ea) == BADADDR )
    return false;

  ea_t jt_addr = BADADDR;
  if ( prev.itype == MEP_INSN_MOVU24 && prev.Op1.reg == jt_addr_reg )
  {
    jt_addr = (prev.Op2.type == o_mem) ? prev.Op2.addr : ea_t(prev.Op2.value);
    if ( decode_prev_insn(&prev, prev.ea) == BADADDR )
      return false;
  }
  else
  {
    uval_t resolved_jt = 0;
    if ( !find_reg_value(load_ea, jt_addr_reg, &resolved_jt) )
      return false;
    jt_addr = (ea_t)resolved_jt;
    // Step back over the address synthesis instructions to find sl1ad3/sl2ad3
    while ( prev.itype != MEP_INSN_SL2AD3 && prev.itype != MEP_INSN_SL1AD3 )
    {
      if ( decode_prev_insn(&prev, prev.ea) == BADADDR )
        return false;
    }
  }

  if ( prev.itype != MEP_INSN_SL2AD3 && prev.itype != MEP_INSN_SL1AD3 )
    return false;

  int reg_a = prev.Op2.reg;
  int reg_b = prev.Op3.reg;
  if ( reg_a > MEP_REG_R12 || reg_b > MEP_REG_R12 )
    return false;

  int idx_reg = (reg_a == jt_addr_reg) ? reg_b : reg_a;
  ea_t sl_ea = prev.ea;

  // Walk backwards to find the bounds check:
  //   sltu3 $0, $idx, #ncases   (or slt3 / blti / bgei)
  //   beqz  $0, default_label
  ea_t search_ea = sl_ea;
  ea_t defjump = BADADDR;
  int ncases = 0;
  int lowcase = 0;
  ea_t startea = sl_ea;

  for ( int i = 0; i < 12; ++i )
  {
    if ( decode_prev_insn(&prev, search_ea) == BADADDR )
      break;
    search_ea = prev.ea;

    if ( (prev.itype == MEP_INSN_BEQZ || prev.itype == MEP_INSN_BNEZ) && defjump == BADADDR )
    {
      defjump = prev.Op2.addr;
    }
    else if ( (prev.itype == MEP_INSN_SLTU3I || prev.itype == MEP_INSN_SLT3I)
           && prev.Op2.reg == idx_reg
           && prev.Op3.type == o_imm )
    {
      ncases = (int)prev.Op3.value;
      startea = prev.ea;
      // Check if preceded by `add $idx, -lowcase`
      insn_t prev2;
      if ( decode_prev_insn(&prev2, prev.ea) != BADADDR )
      {
        if ( prev2.itype == MEP_INSN_ADD && prev2.Op1.reg == idx_reg && prev2.Op2.type == o_imm )
        {
          lowcase = -(int)(int32)prev2.Op2.value;
          startea = prev2.ea;
        }
        else if ( prev2.itype == MEP_INSN_ADD3X
               && prev2.Op1.reg == idx_reg
               && prev2.Op2.reg == idx_reg
               && prev2.Op3.type == o_imm )
        {
          lowcase = -(int)(int16)prev2.Op3.value;
          startea = prev2.ea;
        }
      }
      break;
    }
    else if ( prev.itype == MEP_INSN_BGEI && prev.Op1.reg == idx_reg && prev.Op2.type == o_imm )
    {
      defjump = prev.Op3.addr;
      ncases = (int)prev.Op2.value;
      startea = prev.ea;
      break;
    }
  }

  if ( ncases <= 0 || jt_addr == BADADDR )
    return false;

  si->ncases = ushort(ncases);
  si->jumps = jt_addr;
  si->elbase = jt_addr;
  si->lowcase = lowcase;
  si->startea = startea;
  if ( defjump != BADADDR )
    si->defjump = defjump;
  si->set_expr(idx_reg, dt_dword);
  return true;
}

//----------------------------------------------------------------------
// Stack pointer tracking and frame creation
void mep_t::trace_sp(ea_t func_ea, const insn_t &insn)
{
  if ( func_ea == BADADDR )
    return;

  switch ( insn.itype )
  {
    case MEP_INSN_ADD:
      if ( insn.Op1.reg == MEP_REG_SP && insn.Op2.type == o_imm )
      {
        sval_t delta = (int32)insn.Op2.value;
        add_func_auto_stkpnt(func_ea, insn.ea + insn.size, delta);
      }
      break;

    case MEP_INSN_ADD3X:
      if ( insn.Op1.reg == MEP_REG_SP
        && insn.Op2.reg == MEP_REG_SP
        && insn.Op3.type == o_imm )
      {
        sval_t delta = (int16)insn.Op3.value;
        add_func_auto_stkpnt(func_ea, insn.ea + insn.size, delta);
      }
      break;

    case MEP_INSN_SUB:
      if ( insn.Op1.reg == MEP_REG_SP && insn.Op2.type == o_reg )
      {
        uval_t val = 0;
        if ( find_reg_value(insn.ea, insn.Op2.reg, &val) )
          add_func_auto_stkpnt(func_ea, insn.ea + insn.size, -(sval_t)(int32)val);
      }
      break;

    default:
      break;
  }
}

bool mep_t::create_func_frame(ea_t func_ea)
{
  if ( func_ea == BADADDR )
    return false;

  ea_t ea = func_ea;
  sval_t frsize = 0;
  ushort regsize = 0;
  bool uses_fp = false;

  for ( int i = 0; i < 10; ++i )
  {
    insn_t insn;
    if ( decode_insn(&insn, ea) == 0 )
      break;

    if ( insn.itype == MEP_INSN_ADD
      && insn.Op1.reg == MEP_REG_SP
      && insn.Op2.type == o_imm
      && (int32)insn.Op2.value < 0 )
    {
      frsize += -(int32)insn.Op2.value;
    }
    else if ( insn.itype == MEP_INSN_ADD3X
           && insn.Op1.reg == MEP_REG_SP
           && insn.Op2.reg == MEP_REG_SP
           && insn.Op3.type == o_imm
           && (int16)insn.Op3.value < 0 )
    {
      frsize += -(int16)insn.Op3.value;
    }
    else if ( (insn.itype == MEP_INSN_SW_SP || (insn.itype == MEP_INSN_SW16 && insn.Op3.reg == MEP_REG_SP))
           && (insn.Op1.reg == MEP_REG_LP || insn.Op1.reg == MEP_REG_FP || (insn.Op1.reg >= MEP_REG_R5 && insn.Op1.reg <= MEP_REG_R12)) )
    {
      regsize += 4;
    }
    else if ( (insn.itype == MEP_INSN_MOV && insn.Op1.reg == MEP_REG_FP && insn.Op2.reg == MEP_REG_SP)
           || (insn.itype == MEP_INSN_ADD3I && insn.Op1.reg == MEP_REG_FP && insn.Op2.reg == MEP_REG_SP) )
    {
      uses_fp = true;
    }

    uint32 feature = insn.get_canon_feature(ph);
    if ( (feature & (CF_STOP | CF_CALL | CF_JUMP)) != 0 )
      break;

    ea += insn.size;
  }

  if ( frsize <= 0 )
    return false;

  if ( regsize > frsize )
    regsize = 0;

  uint64 flags = FUNC_FRAME | (uses_fp ? FUNC_BOTTOMBP : 0);
  set_func_flag(func_ea, flags);
  return add_frame_ea(func_ea, frsize - regsize, regsize, 0);
}

int mep_t::is_sp_based(const insn_t &insn, const op_t & /*op*/) const
{
  if ( insn.Op3.type == o_reg && insn.Op3.reg == MEP_REG_FP )
    return OP_SP_ADD | OP_FP_BASED;
  return OP_SP_ADD | OP_SP_BASED;
}

//----------------------------------------------------------------------
// Helper to set refinfo without truncating REFINFO_* flags
static void set_mep_refinfo(
        ea_t ea,
        int n,
        uint32 type_and_flags,
        ea_t target,
        ea_t base = 0,
        adiff_t tdelta = 0)
{
  refinfo_t ri;
  ri.init(type_and_flags, base, target, tdelta);
  set_refinfo_ex(ea, n, &ri);
}

//----------------------------------------------------------------------
// Apply HIGH16 / LOW16 reference info to a `movh` + `add3x`/`or3`/`*16` pair
static void apply_hi_lo_pair(
        ea_t movh_ea,
        const insn_t &lo_insn,
        int lo_op_idx,
        ea_t target,
        dref_t lo_dref,
        uint32 extra_flags = 0)
{
  if ( !is_mapped(target) )
    return;

  refinfo_t ri_hi;
  if ( !get_refinfo(&ri_hi, movh_ea, 1) )
  {
    set_mep_refinfo(movh_ea, 1, REF_HIGH16 | extra_flags, target);
    auto_mark(movh_ea, AU_USED);
  }
  add_dref(movh_ea, target, dr_O);

  refinfo_t ri_lo;
  if ( !get_refinfo(&ri_lo, lo_insn.ea, lo_op_idx) )
  {
    set_mep_refinfo(lo_insn.ea, lo_op_idx, REF_LOW16 | extra_flags, target);
    auto_mark(lo_insn.ea, AU_USED);
  }
  lo_insn.add_dref(target, lo_insn.ops[lo_op_idx].offb, lo_dref);
}

//----------------------------------------------------------------------
// Helper to determine whether an instruction is a memory store (vs load)
static bool is_store_insn(uint16 itype)
{
  switch ( itype )
  {
    case MEP_INSN_SB:
    case MEP_INSN_SH:
    case MEP_INSN_SW:
    case MEP_INSN_SW_SP:
    case MEP_INSN_SB_TP:
    case MEP_INSN_SH_TP:
    case MEP_INSN_SW_TP:
    case MEP_INSN_SB16:
    case MEP_INSN_SH16:
    case MEP_INSN_SW16:
    case MEP_INSN_SW24:
    case MEP_INSN_SWCP:
    case MEP_INSN_SMCP:
    case MEP_INSN_SWCPI:
    case MEP_INSN_SMCPI:
    case MEP_INSN_SWCP16:
    case MEP_INSN_SMCP16:
    case MEP_INSN_BSETM:
    case MEP_INSN_BCLRM:
    case MEP_INSN_BNOTM:
    case MEP_INSN_TAS:
    case MEP_INSN_CASB3:
    case MEP_INSN_CASH3:
    case MEP_INSN_CASW3:
      return true;
    default:
      return false;
  }
}

//----------------------------------------------------------------------
// Main instruction emulator
int mep_t::mep_emu(const insn_t &insn)
{
  uint32 feature = insn.get_canon_feature(ph);
  bool flow = ((feature & CF_STOP) == 0);
  flags64_t F = get_flags(insn.ea);

  // Mark immediate operands and create user-specified offset xrefs
  for ( int i = 0; i < UA_MAXOP; ++i )
  {
    const op_t &op = insn.ops[i];
    if ( op.type == o_void )
      break;
    if ( op.type == o_imm )
    {
      set_immd(insn.ea);
      if ( op_adds_xrefs(F, i) )
        insn.add_off_drefs(op, dr_O, OOFW_IMM | OOF_SIGNED);
    }
  }

  switch ( insn.itype )
  {
    //------------------------------------------------------------------
    // Unconditional direct branches / jumps
    //------------------------------------------------------------------
    case MEP_INSN_BRA:
    case MEP_INSN_JMP24:
      insn.add_cref(insn.Op1.addr, insn.Op1.offb, fl_JN);
      flow = false;
      break;

    //------------------------------------------------------------------
    // Indirect jump: jmp $rm
    //------------------------------------------------------------------
    case MEP_INSN_JMP:
      {
        flow = false;
        switch_info_t si;
        if ( get_switch_info(&si, insn.ea) <= 0 )
        {
          uval_t target = 0;
          if ( find_reg_value(insn.ea, insn.Op1.reg, &target) && is_mapped(target & ~uval_t(1)) )
            insn.add_cref(target & ~uval_t(1), insn.Op1.offb, fl_JN);
          else
            remember_problem(PR_JUMP, insn.ea);
        }
      }
      break;

    //------------------------------------------------------------------
    // Conditional branches (2-operand: Op2 = target)
    //------------------------------------------------------------------
    case MEP_INSN_BEQZ:
    case MEP_INSN_BNEZ:
    case MEP_INSN_BCPEQ:
    case MEP_INSN_BCPNE:
    case MEP_INSN_BCPAT:
    case MEP_INSN_BCPAF:
      insn.add_cref(insn.Op2.addr, insn.Op2.offb, fl_JN);
      break;

    //------------------------------------------------------------------
    // Conditional branches (3-operand: Op3 = target)
    //------------------------------------------------------------------
    case MEP_INSN_BEQI:
    case MEP_INSN_BNEI:
    case MEP_INSN_BLTI:
    case MEP_INSN_BGEI:
    case MEP_INSN_BEQ:
    case MEP_INSN_BNE:
      insn.add_cref(insn.Op3.addr, insn.Op3.offb, fl_JN);
      break;

    //------------------------------------------------------------------
    // Direct subroutine calls: bsr12, bsr24, bsrv
    //------------------------------------------------------------------
    case MEP_INSN_BSR12:
    case MEP_INSN_BSR24:
    case MEP_INSN_BSRV:
      {
        ea_t target = insn.Op1.addr & ~ea_t(1);
        insn.add_cref(target, insn.Op1.offb, fl_CN);
        if ( !func_does_return(target) )
          flow = false;
      }
      break;

    //------------------------------------------------------------------
    // Indirect subroutine calls: jsr $rm, jsrv $rm
    //------------------------------------------------------------------
    case MEP_INSN_JSR:
    case MEP_INSN_JSRV:
      {
        uval_t target = 0;
        if ( find_reg_value(insn.ea, insn.Op1.reg, &target) && is_mapped(target & ~uval_t(1)) )
        {
          ea_t call_ea = ea_t(target & ~uval_t(1));
          insn.add_cref(call_ea, insn.Op1.offb, fl_CF);
          if ( !func_does_return(call_ea) )
            flow = false;
        }
        else
        {
          remember_problem(PR_JUMP, insn.ea);
        }
      }
      break;

    //------------------------------------------------------------------
    // Zero-overhead hardware loops: repeat $rn, rpe_target / erepeat rpe_target
    // Per MeP-c4 Spec (p. 158, 199):
    //   rpb <- PC + 4
    //   rpe <- target & ~1  (or | 1 for erepeat)
    // When PC[31:1] == rpe[31:1], hardware branches back to rpb.
    // Note: Some assemblers encode rpe_target as the label immediately
    // following the last loop instruction; if rpe_target is an unconditional
    // return/jump or outside the loop, also check the preceding instruction.
    //------------------------------------------------------------------
    case MEP_INSN_REPEAT:
    case MEP_INSN_EREPEAT:
      {
        bool is_erepeat = (insn.itype == MEP_INSN_EREPEAT);
        const op_t &targ_op = is_erepeat ? insn.Op1 : insn.Op2;
        ea_t rpb_ea = insn.ea + insn.size;
        ea_t rpe_ea = targ_op.addr & ~ea_t(1);

        // Add an offset reference to rpe_ea so IDA creates a label there
        // and out_print_address renders the loop-end symbol cleanly.
        insn.add_dref(rpe_ea, targ_op.offb, dr_O);

        // Determine the loop tail instruction:
        // Per the MeP architecture specification, RPE is the address of the
        // last instruction in the loop body, which cannot be a branch/ret.
        // However, if a toolchain emitted RPE as the address just past the
        // last loop instruction (e.g. pointing to a `ret` or `bra`), fall
        // back to the preceding instruction.
        ea_t tail_ea = rpe_ea;
        insn_t rpe_insn;
        if ( decode_insn(&rpe_insn, rpe_ea) > 0 )
        {
          uint32 rpe_feat = rpe_insn.get_canon_feature(ph);
          if ( (rpe_feat & (CF_STOP | CF_JUMP)) != 0 && rpe_ea > rpb_ea )
          {
            ea_t prev_ea = prev_not_tail(rpe_ea);
            if ( prev_ea != BADADDR && prev_ea >= rpb_ea )
              tail_ea = prev_ea;
          }
        }

        if ( tail_ea >= rpb_ea )
        {
          set_repeat_loop(tail_ea, rpb_ea, is_erepeat);
          auto_mark(tail_ea, AU_USED);
        }
      }
      break;

    //------------------------------------------------------------------
    // 24-bit absolute address instructions: sw24, lw24, movu24
    //------------------------------------------------------------------
    case MEP_INSN_SW24:
      insn.add_dref(insn.Op2.addr, insn.Op2.offb, dr_W);
      break;

    case MEP_INSN_LW24:
      insn.add_dref(insn.Op2.addr, insn.Op2.offb, dr_R);
      break;

    case MEP_INSN_MOVU24:
      if ( insn.Op2.type == o_mem )
        insn.add_dref(insn.Op2.addr, insn.Op2.offb, dr_O);
      break;

    //------------------------------------------------------------------
    // High-halfword load: movh $rn, $uimm16
    //------------------------------------------------------------------
    case MEP_INSN_MOVH:
      if ( insn.Op2.type == o_mem )
        insn.add_dref(insn.Op2.addr, insn.Op2.offb, dr_O);
      break;

    //------------------------------------------------------------------
    // 3-operand add / bitwise-or with 16-bit immediate:
    //   add3 $rn, $rm, $simm16  (MEP_INSN_ADD3X)
    //   or3  $rn, $rm, $uimm16  (MEP_INSN_OR3)
    // Used to complete 32-bit addresses started by `movh` or to compute
    // stack/global-pointer offsets.
    //------------------------------------------------------------------
    case MEP_INSN_ADD3X:
      if ( insn.Op3.type == o_mem )
      {
        insn.add_dref(insn.Op3.addr, insn.Op3.offb, dr_O);
      }
      else if ( (insn.Op2.reg == MEP_REG_SP || insn.Op2.reg == MEP_REG_FP)
             && insn.Op1.reg != MEP_REG_SP )
      {
        if ( may_create_stkvars() && !is_defarg(F, 2) )
        {
          ea_t func_ea = get_func_start(insn.ea);
          if ( func_ea != BADADDR && (get_func_flags(func_ea) & FUNC_FRAME) != 0 )
          {
            sval_t disp = (int16)insn.Op3.value;
            if ( insn.create_stkvar(insn.Op3, disp, 0) )
              op_stkvar(insn.ea, 2);
          }
        }
      }
      else if ( insn.Op2.reg != MEP_REG_SP && insn.Op2.reg != MEP_REG_FP )
      {
        uval_t base_val = 0;
        ea_t movh_ea = BADADDR;
        if ( find_reg_value(insn.ea, insn.Op2.reg, &base_val, &movh_ea) )
        {
          ea_t target = (uint32)(base_val + (int32)(int16)insn.Op3.value);
          if ( movh_ea != BADADDR )
          {
            apply_hi_lo_pair(movh_ea, insn, 2, target, dr_O, REFINFO_SIGNEDOP);
          }
          else if ( is_mapped(target) )
          {
            set_mep_refinfo(insn.ea, 2, REF_OFF32 | REFINFO_SIGNEDOP, target, base_val, 0);
            insn.add_dref(target, insn.Op3.offb, dr_O);
            auto_mark(insn.ea, AU_USED);
          }
        }
      }
      break;

    case MEP_INSN_OR3:
      if ( insn.Op3.type == o_mem )
      {
        insn.add_dref(insn.Op3.addr, insn.Op3.offb, dr_O);
      }
      else
      {
        uval_t base_val = 0;
        ea_t movh_ea = BADADDR;
        if ( find_reg_value(insn.ea, insn.Op2.reg, &base_val, &movh_ea) && movh_ea != BADADDR )
        {
          ea_t target = (uint32)(base_val | (uint16)insn.Op3.value);
          apply_hi_lo_pair(movh_ea, insn, 2, target, dr_O);
        }
      }
      break;

    //------------------------------------------------------------------
    // SP-relative add: add3 $rn, $sp, $uimm7a4
    //------------------------------------------------------------------
    case MEP_INSN_ADD3I:
      if ( insn.Op1.reg != MEP_REG_SP && may_create_stkvars() && !is_defarg(F, 2) )
      {
        ea_t func_ea = get_func_start(insn.ea);
        if ( func_ea != BADADDR && (get_func_flags(func_ea) & FUNC_FRAME) != 0 )
        {
          sval_t disp = (sval_t)insn.Op3.value;
          if ( insn.create_stkvar(insn.Op3, disp, 0) )
            op_stkvar(insn.ea, 2);
        }
      }
      break;

    //------------------------------------------------------------------
    // SP-relative word load/store: sw $rn, udisp7a4($sp), lw $rn, udisp7a4($sp)
    //------------------------------------------------------------------
    case MEP_INSN_SW_SP:
    case MEP_INSN_LW_SP:
      if ( may_create_stkvars() && !is_defarg(F, 1) )
      {
        ea_t func_ea = get_func_start(insn.ea);
        if ( func_ea != BADADDR && (get_func_flags(func_ea) & FUNC_FRAME) != 0 )
        {
          sval_t disp = (sval_t)insn.Op2.value;
          if ( insn.create_stkvar(insn.Op2, disp, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, 1);
        }
      }
      break;

    //------------------------------------------------------------------
    // TP-relative loads/stores: sb/sh/sw/lb/lh/lw/lbu/lhu $rn3, udisp7*($tp)
    //------------------------------------------------------------------
    case MEP_INSN_SB_TP:
    case MEP_INSN_SH_TP:
    case MEP_INSN_SW_TP:
    case MEP_INSN_LB_TP:
    case MEP_INSN_LH_TP:
    case MEP_INSN_LW_TP:
    case MEP_INSN_LBU_TP:
    case MEP_INSN_LHU_TP:
      {
        dref_t dref = is_store_insn(insn.itype) ? dr_W : dr_R;
        if ( insn.Op2.type == o_mem )
        {
          insn.add_dref(insn.Op2.addr, insn.Op2.offb, dref);
        }
        else
        {
          uval_t tp_val = 0;
          if ( find_reg_value(insn.ea, MEP_REG_TP, &tp_val) )
          {
            ea_t target = (uint32)(tp_val + (uint32)insn.Op2.value);
            if ( is_mapped(target) )
            {
              set_mep_refinfo(insn.ea, 1, REF_OFF32, target, tp_val, 0);
              insn.add_dref(target, insn.Op2.offb, dref);
              auto_mark(insn.ea, AU_USED);
            }
          }
        }
      }
      break;

    //------------------------------------------------------------------
    // 16-bit signed displacement loads/stores:
    //   sb16, sh16, sw16, lb16, lh16, lw16, lbu16, lhu16 $rn, sdisp16($rm)
    //------------------------------------------------------------------
    case MEP_INSN_SB16:
    case MEP_INSN_SH16:
    case MEP_INSN_SW16:
    case MEP_INSN_LB16:
    case MEP_INSN_LH16:
    case MEP_INSN_LW16:
    case MEP_INSN_LBU16:
    case MEP_INSN_LHU16:
      {
        dref_t dref = is_store_insn(insn.itype) ? dr_W : dr_R;
        if ( insn.Op2.type == o_mem )
        {
          insn.add_dref(insn.Op2.addr, insn.Op2.offb, dref);
        }
        else if ( insn.Op3.reg == MEP_REG_SP || insn.Op3.reg == MEP_REG_FP )
        {
          if ( may_create_stkvars() && !is_defarg(F, 1) )
          {
            ea_t func_ea = get_func_start(insn.ea);
            if ( func_ea != BADADDR && (get_func_flags(func_ea) & FUNC_FRAME) != 0 )
            {
              sval_t disp = (int16)insn.Op2.value;
              if ( insn.create_stkvar(insn.Op2, disp, STKVAR_VALID_SIZE) )
                op_stkvar(insn.ea, 1);
            }
          }
        }
        else
        {
          uval_t base_val = 0;
          ea_t movh_ea = BADADDR;
          if ( find_reg_value(insn.ea, insn.Op3.reg, &base_val, &movh_ea) )
          {
            ea_t target = (uint32)(base_val + (int32)(int16)insn.Op2.value);
            if ( movh_ea != BADADDR )
            {
              apply_hi_lo_pair(movh_ea, insn, 1, target, dref, REFINFO_SIGNEDOP);
            }
            else if ( is_mapped(target) )
            {
              set_mep_refinfo(insn.ea, 1, REF_OFF32 | REFINFO_SIGNEDOP, target, base_val, 0);
              insn.add_dref(target, insn.Op2.offb, dref);
              auto_mark(insn.ea, AU_USED);
            }
          }
        }
      }
      break;

    //------------------------------------------------------------------
    // Coprocessor 16-bit displacement loads/stores:
    //   swcp16, lwcp16, smcp16, lmcp16 $crn, sdisp16($rm)
    //------------------------------------------------------------------
    case MEP_INSN_SWCP16:
    case MEP_INSN_LWCP16:
    case MEP_INSN_SMCP16:
    case MEP_INSN_LMCP16:
      {
        dref_t dref = is_store_insn(insn.itype) ? dr_W : dr_R;
        uval_t base_val = 0;
        ea_t movh_ea = BADADDR;
        if ( find_reg_value(insn.ea, insn.Op3.reg, &base_val, &movh_ea) )
        {
          ea_t target = (uint32)(base_val + (int32)(int16)insn.Op2.value);
          if ( is_mapped(target) )
            insn.add_dref(target, insn.Op2.offb, dref);
        }
      }
      break;

    //------------------------------------------------------------------
    // Register-indirect loads/stores:
    //   sb, sh, sw, lb, lh, lw, lbu, lhu $rn, ($rm)
    //   swcp, lwcp, smcp, lmcp, swcpi, lwcpi, smcpi, lmcpi $crn, ($rm[+])
    //   bsetm, bclrm, bnotm, btstm ($rm), $uimm3
    //   tas $rn, ($rm)
    //   casb3, cash3, casw3 $rl, $rn, ($rm)
    //------------------------------------------------------------------
    case MEP_INSN_SB:
    case MEP_INSN_SH:
    case MEP_INSN_SW:
    case MEP_INSN_LB:
    case MEP_INSN_LH:
    case MEP_INSN_LW:
    case MEP_INSN_LBU:
    case MEP_INSN_LHU:
    case MEP_INSN_SWCP:
    case MEP_INSN_LWCP:
    case MEP_INSN_SMCP:
    case MEP_INSN_LMCP:
    case MEP_INSN_SWCPI:
    case MEP_INSN_LWCPI:
    case MEP_INSN_SMCPI:
    case MEP_INSN_LMCPI:
    case MEP_INSN_TAS:
      {
        uval_t addr = 0;
        if ( find_reg_value(insn.ea, insn.Op2.reg, &addr) && is_mapped(addr) )
        {
          dref_t dref = is_store_insn(insn.itype) ? dr_W : dr_R;
          insn.add_dref(addr, insn.Op2.offb, dref);
          if ( insn.itype == MEP_INSN_TAS )
            insn.add_dref(addr, insn.Op2.offb, dr_R);
        }
      }
      break;

    case MEP_INSN_BSETM:
    case MEP_INSN_BCLRM:
    case MEP_INSN_BNOTM:
    case MEP_INSN_BTSTM:
      {
        uval_t addr = 0;
        if ( find_reg_value(insn.ea, insn.Op1.reg, &addr) && is_mapped(addr) )
        {
          insn.add_dref(addr, insn.Op1.offb, dr_R);
          if ( insn.itype != MEP_INSN_BTSTM )
            insn.add_dref(addr, insn.Op1.offb, dr_W);
        }
      }
      break;

    case MEP_INSN_CASB3:
    case MEP_INSN_CASH3:
    case MEP_INSN_CASW3:
      {
        uval_t addr = 0;
        if ( find_reg_value(insn.ea, insn.Op3.reg, &addr) && is_mapped(addr) )
        {
          insn.add_dref(addr, insn.Op3.offb, dr_R);
          insn.add_dref(addr, insn.Op3.offb, dr_W);
        }
      }
      break;

    default:
      break;
  }

  // Handle hardware zero-overhead loop tail (`repeat` / `erepeat`)
  ea_t rpb_ea = BADADDR;
  bool is_erepeat = false;
  if ( get_repeat_loop(insn.ea, &rpb_ea, &is_erepeat) )
  {
    insn.add_cref(rpb_ea, 0, fl_JN);
    if ( is_erepeat )
      flow = false;
  }

  // Add normal fallthrough execution flow
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  // Trace stack pointer modifications
  ea_t func_ea = get_func_start(insn.ea);
  if ( may_trace_sp() && func_ea != BADADDR )
  {
    if ( !recalc_func_spd_for_basic_block(func_ea, insn.ea) )
      trace_sp(func_ea, insn);
  }

  return 1;
}
