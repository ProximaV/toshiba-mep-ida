/* MEP IDP hardware defines

THIS FILE IS (mostly) MACHINE GENERATED WITH CGEN.

Copyright 1996-2010 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#ifndef __MEP_HPP
#define __MEP_HPP

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <problems.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <kernwin.hpp>
#include <frame.hpp>
#include "ins.hpp"
#include "../idaidp.hpp"

/*
// Current processor in the module
// It must be exported
//idaman processor_t ida_module_data LPH;

void idaapi out_insn(outctx_t &ctx);
bool idaapi out_opnd(outctx_t &ctx, const op_t &x);

// use this define if the default out_mnem() is good enough
#define DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(CTXNAME)      \
  void idaapi out_insn(outctx_t &ctx)                   \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    p->out_insn();                                      \
  }                                                     \
  bool idaapi out_opnd(outctx_t &ctx, const op_t &x)    \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    return p->out_operand(x);                           \
  }
*/

/* needed for cgen.h */
#define CGEN_ARCH mep
#define CGEN_SYM(s) mep##_cgen_##s

/* for referring to operand type in cmd */
#define cgen_optype specval_shorts.low

/* Offsets for register names by cgen hw name */

#define REGS_HW_H_PC_BASE 0
#define REGS_HW_H_GPR_BASE 1
#define REGS_HW_H_CSR_BASE 17
#define REGS_HW_H_CR64_BASE 49
#define REGS_HW_H_CR64_W_BASE 81
#define REGS_HW_H_CR_BASE 113
#define REGS_HW_H_CCR_BASE 145
#define REGS_HW_H_CCR_W_BASE 209
#define REGS_HW_H_CR_IVC2_BASE 273
#define REGS_HW_H_CCR_IVC2_BASE 337
#define REGS_COUNT 369

enum mep_reg_t
{
  MEP_REG_R0  = REGS_HW_H_GPR_BASE + 0,
  MEP_REG_R1  = REGS_HW_H_GPR_BASE + 1,
  MEP_REG_R2  = REGS_HW_H_GPR_BASE + 2,
  MEP_REG_R3  = REGS_HW_H_GPR_BASE + 3,
  MEP_REG_R4  = REGS_HW_H_GPR_BASE + 4,
  MEP_REG_R5  = REGS_HW_H_GPR_BASE + 5,
  MEP_REG_R6  = REGS_HW_H_GPR_BASE + 6,
  MEP_REG_R7  = REGS_HW_H_GPR_BASE + 7,
  MEP_REG_R8  = REGS_HW_H_GPR_BASE + 8,
  MEP_REG_FP  = REGS_HW_H_GPR_BASE + 8,  // $8 is $fp in MeP ABI
  MEP_REG_R9  = REGS_HW_H_GPR_BASE + 9,
  MEP_REG_R10 = REGS_HW_H_GPR_BASE + 10,
  MEP_REG_R11 = REGS_HW_H_GPR_BASE + 11,
  MEP_REG_R12 = REGS_HW_H_GPR_BASE + 12,
  MEP_REG_TP  = REGS_HW_H_GPR_BASE + 13, // $13 / $tp (Tiny Data Pointer)
  MEP_REG_GP  = REGS_HW_H_GPR_BASE + 14, // $14 / $gp (Global/Small Data Pointer)
  MEP_REG_SP  = REGS_HW_H_GPR_BASE + 15, // $15 / $sp (Stack Pointer)

  MEP_REG_PC   = REGS_HW_H_CSR_BASE + 0,
  MEP_REG_LP   = REGS_HW_H_CSR_BASE + 1,
  MEP_REG_SAR  = REGS_HW_H_CSR_BASE + 2,
  MEP_REG_RPB  = REGS_HW_H_CSR_BASE + 4,
  MEP_REG_RPE  = REGS_HW_H_CSR_BASE + 5,
  MEP_REG_RPC  = REGS_HW_H_CSR_BASE + 6,
  MEP_REG_HI   = REGS_HW_H_CSR_BASE + 7,
  MEP_REG_LO   = REGS_HW_H_CSR_BASE + 8,
  MEP_REG_MB0  = REGS_HW_H_CSR_BASE + 11,
  MEP_REG_ME0  = REGS_HW_H_CSR_BASE + 12,
  MEP_REG_MB1  = REGS_HW_H_CSR_BASE + 13,
  MEP_REG_ME1  = REGS_HW_H_CSR_BASE + 14,
  MEP_REG_PSW  = REGS_HW_H_CSR_BASE + 15,
  MEP_REG_ID   = REGS_HW_H_CSR_BASE + 16,
  MEP_REG_TMP  = REGS_HW_H_CSR_BASE + 17,
  MEP_REG_EPC  = REGS_HW_H_CSR_BASE + 18,
  MEP_REG_EXC  = REGS_HW_H_CSR_BASE + 19,
  MEP_REG_CFG  = REGS_HW_H_CSR_BASE + 20,
  MEP_REG_NPC  = REGS_HW_H_CSR_BASE + 22,
  MEP_REG_DBG  = REGS_HW_H_CSR_BASE + 23,
  MEP_REG_DEPC = REGS_HW_H_CSR_BASE + 24,
  MEP_REG_OPT  = REGS_HW_H_CSR_BASE + 25,
  MEP_REG_RCFG = REGS_HW_H_CSR_BASE + 26,
  MEP_REG_CCFG = REGS_HW_H_CSR_BASE + 27,
};
/* Hardware attribute indices.  */

/* Enum declaration for cgen_hw attrs.  */
typedef enum cgen_hw_attr {
  CGEN_HW_VIRTUAL, CGEN_HW_CACHE_ADDR, CGEN_HW_PC, CGEN_HW_PROFILE
 , CGEN_HW_IS_FLOAT, CGEN_HW_END_BOOLS, CGEN_HW_START_NBOOLS = 31, CGEN_HW_MACH
 , CGEN_HW_ISA, CGEN_HW_END_NBOOLS
} CGEN_HW_ATTR;

/* Number of non-boolean elements in cgen_hw_attr.  */
#define CGEN_HW_NBOOL_ATTRS (CGEN_HW_END_NBOOLS - CGEN_HW_START_NBOOLS - 1)

/* cgen_hw attribute accessor macros.  */
#define CGEN_ATTR_CGEN_HW_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_HW_MACH-CGEN_HW_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_HW_ISA_VALUE(attrs) ((attrs)->nonbool[CGEN_HW_ISA-CGEN_HW_START_NBOOLS-1].bitset)
#define CGEN_ATTR_CGEN_HW_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_HW_CACHE_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_CACHE_ADDR)) != 0)
#define CGEN_ATTR_CGEN_HW_PC_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_PC)) != 0)
#define CGEN_ATTR_CGEN_HW_PROFILE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_PROFILE)) != 0)
#define CGEN_ATTR_CGEN_HW_IS_FLOAT_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_IS_FLOAT)) != 0)

/* Enum declaration for mep hardware types.  */
typedef enum cgen_hw_type {
  HW_H_MEMORY, HW_H_SINT, HW_H_UINT, HW_H_ADDR
 , HW_H_IADDR, HW_H_PC, HW_H_GPR, HW_H_CSR
 , HW_H_CR64, HW_H_CR64_W, HW_H_CR, HW_H_CCR
 , HW_H_CCR_W, HW_H_CR_IVC2, HW_H_CCR_IVC2, HW_MAX
} CGEN_HW_TYPE;

#define MAX_HW ((int) HW_MAX)

/* Operand attribute indices.  */

/* Enum declaration for cgen_operand attrs.  */
typedef enum cgen_operand_attr {
  CGEN_OPERAND_VIRTUAL, CGEN_OPERAND_PCREL_ADDR, CGEN_OPERAND_ABS_ADDR, CGEN_OPERAND_SIGN_OPT
 , CGEN_OPERAND_SIGNED, CGEN_OPERAND_NEGATIVE, CGEN_OPERAND_RELAX, CGEN_OPERAND_SEM_ONLY
 , CGEN_OPERAND_RELOC_IMPLIES_OVERFLOW, CGEN_OPERAND_END_BOOLS, CGEN_OPERAND_START_NBOOLS = 31, CGEN_OPERAND_MACH
 , CGEN_OPERAND_ISA, CGEN_OPERAND_CDATA, CGEN_OPERAND_ALIGN, CGEN_OPERAND_END_NBOOLS
} CGEN_OPERAND_ATTR;

/* Number of non-boolean elements in cgen_operand_attr.  */
#define CGEN_OPERAND_NBOOL_ATTRS (CGEN_OPERAND_END_NBOOLS - CGEN_OPERAND_START_NBOOLS - 1)

/* cgen_operand attribute accessor macros.  */
#define CGEN_ATTR_CGEN_OPERAND_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_OPERAND_MACH-CGEN_OPERAND_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_OPERAND_ISA_VALUE(attrs) ((attrs)->nonbool[CGEN_OPERAND_ISA-CGEN_OPERAND_START_NBOOLS-1].bitset)
#define CGEN_ATTR_CGEN_OPERAND_CDATA_VALUE(attrs) ((attrs)->nonbool[CGEN_OPERAND_CDATA-CGEN_OPERAND_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_OPERAND_ALIGN_VALUE(attrs) ((attrs)->nonbool[CGEN_OPERAND_ALIGN-CGEN_OPERAND_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_OPERAND_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_PCREL_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_PCREL_ADDR)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_ABS_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_ABS_ADDR)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SIGN_OPT_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SIGN_OPT)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SIGNED_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SIGNED)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_NEGATIVE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_NEGATIVE)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_RELAX_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_RELAX)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SEM_ONLY_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SEM_ONLY)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_RELOC_IMPLIES_OVERFLOW_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_RELOC_IMPLIES_OVERFLOW)) != 0)

/* Enum declaration for mep operand types.  */
typedef enum cgen_operand_type {
  MEP_OPERAND_PC, MEP_OPERAND_R0, MEP_OPERAND_RN, MEP_OPERAND_RM
 , MEP_OPERAND_RL, MEP_OPERAND_RN3, MEP_OPERAND_RMA, MEP_OPERAND_RNC
 , MEP_OPERAND_RNUC, MEP_OPERAND_RNS, MEP_OPERAND_RNUS, MEP_OPERAND_RNL
 , MEP_OPERAND_RNUL, MEP_OPERAND_RN3C, MEP_OPERAND_RN3UC, MEP_OPERAND_RN3S
 , MEP_OPERAND_RN3US, MEP_OPERAND_RN3L, MEP_OPERAND_RN3UL, MEP_OPERAND_LP
 , MEP_OPERAND_SAR, MEP_OPERAND_HI, MEP_OPERAND_LO, MEP_OPERAND_MB0
 , MEP_OPERAND_ME0, MEP_OPERAND_MB1, MEP_OPERAND_ME1, MEP_OPERAND_PSW
 , MEP_OPERAND_EPC, MEP_OPERAND_EXC, MEP_OPERAND_NPC, MEP_OPERAND_DBG
 , MEP_OPERAND_DEPC, MEP_OPERAND_OPT, MEP_OPERAND_R1, MEP_OPERAND_TP
 , MEP_OPERAND_SP, MEP_OPERAND_TPR, MEP_OPERAND_SPR, MEP_OPERAND_CSRN
 , MEP_OPERAND_CSRN_IDX, MEP_OPERAND_CRN64, MEP_OPERAND_CRN, MEP_OPERAND_CRNX64
 , MEP_OPERAND_CRNX, MEP_OPERAND_CCRN, MEP_OPERAND_CCCC, MEP_OPERAND_PCREL8A2
 , MEP_OPERAND_PCREL12A2, MEP_OPERAND_PCREL17A2, MEP_OPERAND_PCREL24A2, MEP_OPERAND_PCABS24A2
 , MEP_OPERAND_SDISP16, MEP_OPERAND_SIMM16, MEP_OPERAND_UIMM16, MEP_OPERAND_CODE16
 , MEP_OPERAND_UDISP2, MEP_OPERAND_UIMM2, MEP_OPERAND_SIMM6, MEP_OPERAND_SIMM8
 , MEP_OPERAND_ADDR24A4, MEP_OPERAND_CODE24, MEP_OPERAND_CALLNUM, MEP_OPERAND_UIMM3
 , MEP_OPERAND_UIMM4, MEP_OPERAND_UIMM5, MEP_OPERAND_UDISP7, MEP_OPERAND_UDISP7A2
 , MEP_OPERAND_UDISP7A4, MEP_OPERAND_UIMM7A4, MEP_OPERAND_UIMM24, MEP_OPERAND_CIMM4
 , MEP_OPERAND_CIMM5, MEP_OPERAND_CDISP10, MEP_OPERAND_CDISP10A2, MEP_OPERAND_CDISP10A4
 , MEP_OPERAND_CDISP10A8, MEP_OPERAND_ZERO, MEP_OPERAND_RL5, MEP_OPERAND_CDISP12
 , MEP_OPERAND_C5RMUIMM20, MEP_OPERAND_C5RNMUIMM24, MEP_OPERAND_CP_FLAG, MEP_OPERAND_CROC
 , MEP_OPERAND_CRQC, MEP_OPERAND_CRPC, MEP_OPERAND_IVC_X_6_1, MEP_OPERAND_IVC_X_6_2
 , MEP_OPERAND_IVC_X_6_3, MEP_OPERAND_IMM3P4, MEP_OPERAND_IMM3P9, MEP_OPERAND_IMM4P8
 , MEP_OPERAND_IMM5P7, MEP_OPERAND_IMM6P6, MEP_OPERAND_IMM8P4, MEP_OPERAND_SIMM8P4
 , MEP_OPERAND_IMM3P5, MEP_OPERAND_IMM3P12, MEP_OPERAND_IMM4P4, MEP_OPERAND_IMM4P10
 , MEP_OPERAND_IMM5P8, MEP_OPERAND_IMM5P3, MEP_OPERAND_IMM6P2, MEP_OPERAND_IMM5P23
 , MEP_OPERAND_IMM3P25, MEP_OPERAND_IMM8P0, MEP_OPERAND_SIMM8P0, MEP_OPERAND_SIMM8P20
 , MEP_OPERAND_IMM8P20, MEP_OPERAND_CROP, MEP_OPERAND_CRQP, MEP_OPERAND_CRPP
 , MEP_OPERAND_IVC_X_0_2, MEP_OPERAND_IVC_X_0_3, MEP_OPERAND_IVC_X_0_4, MEP_OPERAND_IVC_X_0_5
 , MEP_OPERAND_IMM16P0, MEP_OPERAND_SIMM16P0, MEP_OPERAND_IVC2RM, MEP_OPERAND_IVC2CRN
 , MEP_OPERAND_IVC2CCRN, MEP_OPERAND_IVC2C3CCRN, MEP_OPERAND_MAX
} CGEN_OPERAND_TYPE;

/* Number of operands types.  */
#define MAX_OPERANDS 122

/* Maximum number of operands referenced by any insn.  */
#define MAX_OPERAND_INSTANCES 6

/* cgen.h must be included after all that decls */
#include "cgen.h"

/* IDP exports */

DECLARE_PROC_LISTENER(idb_listener_t, struct mep_t);

struct mep_t : public procmod_t
{
    netnode helper;
    idb_listener_t idb_listener = idb_listener_t(*this);

    virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
    bool mep_is_switch(switch_info_t *si, const insn_t &insn);
    int mep_ana(insn_t *_insn);
    int mep_emu(const insn_t &insn);

    bool find_reg_value(ea_t ea, int reg, uval_t *p_val, ea_t *p_movh_ea = nullptr, int max_steps = 32);
    void trace_sp(ea_t func_ea, const insn_t &insn);
    bool create_func_frame(ea_t func_ea);
    int is_sp_based(const insn_t &insn, const op_t &op) const;

    void set_repeat_loop(ea_t tail_ea, ea_t rpb_ea, bool is_erepeat);
    bool get_repeat_loop(ea_t tail_ea, ea_t *p_rpb_ea, bool *p_is_erepeat) const;
};

extern int data_id;

#endif

