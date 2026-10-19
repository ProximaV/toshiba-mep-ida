#pragma warning ( disable : 4146)
#include "mep.hpp"

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

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *op);
        return 1;
      }

    case processor_t::ev_create_function_frame:
      {
        ea_t func_ea = va_arg(va, ea_t);
        return create_func_frame(func_ea) ? 1 : 0;
      }

    case processor_t::ev_get_function_retsize:
      {
        int *frsize = va_arg(va, int *);
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
  |PR_SGROTHER,         // the segment registers don't contain
                        // the segment selectors, something else
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
