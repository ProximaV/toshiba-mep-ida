import ida_bytes
import ida_ida
import ida_idp
import ida_nalt
import ida_ua
import ida_xref
import idautils

MAX_REGISTERS = 369


def sign_extend_16(val):
    val &= 0xFFFF
    return val - 0x10000 if (val & 0x8000) else val


def set_mep_refinfo(ea, op_idx, reftype_flags, target, base=0, tdelta=0):
    ri = ida_nalt.refinfo_t()
    ri.init(reftype_flags, base, target, tdelta)
    ida_nalt.set_refinfo_ex(ea, op_idx, ri)


def find_pairs():
    ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()
    movh = [None] * MAX_REGISTERS

    mem_store_mnems = {"sb", "sh", "sw"}
    mem_load_mnems = {"lb", "lh", "lw", "lbu", "lhu"}

    while ea < max_ea:
        insn = idautils.DecodeInstruction(ea)
        if insn:
            mnem = insn.get_canon_mnem()
            reg1 = insn.Op1.reg
            reg2 = insn.Op2.reg
            val1 = insn.Op2.value
            val2 = insn.Op3.value
            size = insn.size

            if mnem == "movh" and insn.Op2.type == ida_ua.o_imm:
                # Note: ana.cpp already shifts the 16-bit immediate left by 16 in Op2.value
                hi_val = val1 if (val1 > 0xFFFF) else (val1 << 16)
                movh[reg1] = (hi_val & 0xFFFFFFFF, insn.ea)
            elif mnem in ("add3", "or3") and insn.Op3.type == ida_ua.o_imm and movh[reg2] is not None:
                hi_val, movh_ea = movh[reg2]
                if mnem == "add3":
                    target = (hi_val + sign_extend_16(val2)) & 0xFFFFFFFF
                    flags_lo = ida_nalt.REF_LOW16 | ida_nalt.REFINFO_SIGNEDOP
                    flags_hi = ida_nalt.REF_HIGH16 | ida_nalt.REFINFO_SIGNEDOP
                else:
                    target = (hi_val | (val2 & 0xFFFF)) & 0xFFFFFFFF
                    flags_lo = ida_nalt.REF_LOW16
                    flags_hi = ida_nalt.REF_HIGH16

                print(f"Found {mnem} pointer pair to {target:#x} at {insn.ea:#x} (movh at {movh_ea:#x})")
                ida_xref.add_dref(insn.ea, target, ida_xref.dr_O)
                ida_xref.add_dref(movh_ea, target, ida_xref.dr_O)
                set_mep_refinfo(insn.ea, 2, flags_lo, target)
                set_mep_refinfo(movh_ea, 1, flags_hi, target)
                if reg1 == reg2:
                    movh[reg1] = None
            elif (mnem in mem_store_mnems or mnem in mem_load_mnems) and insn.size == 4:
                base_reg = insn.Op3.reg
                if insn.Op2.type == ida_ua.o_imm and movh[base_reg] is not None:
                    hi_val, movh_ea = movh[base_reg]
                    target = (hi_val + sign_extend_16(val1)) & 0xFFFFFFFF
                    dref_type = ida_xref.dr_W if mnem in mem_store_mnems else ida_xref.dr_R
                    print(f"Found {mnem} memory pair to {target:#x} at {insn.ea:#x} (movh at {movh_ea:#x})")
                    ida_xref.add_dref(insn.ea, target, dref_type)
                    ida_xref.add_dref(movh_ea, target, ida_xref.dr_O)
                    set_mep_refinfo(insn.ea, 1, ida_nalt.REF_LOW16 | ida_nalt.REFINFO_SIGNEDOP, target)
                    set_mep_refinfo(movh_ea, 1, ida_nalt.REF_HIGH16 | ida_nalt.REFINFO_SIGNEDOP, target)
                if mnem in mem_load_mnems and reg1 < MAX_REGISTERS:
                    movh[reg1] = None

            feature = insn.get_canon_feature()
            if (feature & ida_idp.CF_CHG1) and insn.Op1.type == ida_ua.o_reg and mnem != "movh":
                if reg1 < MAX_REGISTERS:
                    movh[reg1] = None
            if feature & (ida_idp.CF_STOP | ida_idp.CF_CALL):
                movh = [None] * MAX_REGISTERS
        else:
            size = 2
        ea += size


def main():
    print("Finding all MeP address pairs...")
    find_pairs()
    print("Done.")


if __name__ == "__main__":
    main()
