#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This is sample of security migration that implement by instrumenting.
called Return Address Verifier(RAV), the part of CFI(Control Flow Integrity).

"""


import binascii
from keystone import *
from capstone import *


code_rva = 0
simple_instrument_code_rva = 0


def simple_instrument_error_handler(pe_instrument, pe_manager, fn_rva):
    """
    add error handler, in this case it is a message box.

    Args:
        pe_instrument(:obj:`PEInstrument`) : instrumentation for PE.
        pe_manager(:obj:`PEManager`) : file manager for PE.
        fn_rva(int): relative address of function at import address table.
    """
    global code_rva
    fn_va = pe_manager.get_abs_va_from_rva(fn_rva)

    allocation = pe_instrument.falloc(0x1000)
    caption = "Zigzi"
    text = "Failed to Verifying Return Address."

    allocation_va = allocation.get_va()
    caption_start_pos = 0
    text_start_pos = 0x100
    allocation[caption_start_pos:len(caption)] = caption
    allocation[text_start_pos:len(text)] = text

    code = ("push 0;"   # UINT    uType
            "push {};"   # LPCTSTR lpCaption,
            "push {};"   # LPCTSTR lpText,
            "push 0;"   # HWND    hWnd
            "call [{}];").format(allocation_va + caption_start_pos,
                                 allocation_va + text_start_pos,
                                 fn_va)
    code_rva = pe_instrument.append_code(code)

    # TODO : need a way for does not calculate the relocation address directly.
    pe_manager.register_rva_to_relocation(code_rva
                                          + 3   # push 0; push
                                          )
    pe_manager.register_rva_to_relocation(code_rva
                                          + 3   # push 0; push
                                          + 5   # lpCaption;push
                                          )
    pe_manager.register_rva_to_relocation(code_rva
                                          + 3   # push 0; push
                                          + 5   # lpCaption;push
                                          + 4   # lptext
                                          + 2   # push 0;
                                          + 2   # call
                                          )


def simple_instrument_return_address_at_after_branch(instruction):
    code = ("prefetch [{0}]".format(instruction.address
                                    + instruction.size
                                    + 0x1000))
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hex_code)
        return encoding, count
    except KsError as ex:
        print("ERROR: %s" % ex)
    return None, 0


def simple_instrument_return_address_verifier_at_pre_return(instruction):
    global code_rva
    code = (
        "push ecx;"             # store value 
        "mov ecx, [esp+4];"     # load return address to ecx
        "cmp [ecx+3], ecx;"     # compare return address with RAV
        "jne {};"       # if not equal, jump to error handler
        "pop ecx;"              # recover value
    ).format(code_rva - instruction.address - 0x1000
             + 0xF  # instruction size till end of instruction.
             )
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hex_code)
        return encoding, count
    except KsError as ex:
        print("ERROR: %s" % ex)
    return None, 0
