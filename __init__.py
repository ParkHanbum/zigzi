#!/usr/bin/python
# -*- coding: utf-8 -*-
"""zigzi, Platform independent binary instrumentation module.


Copyright (c) 2016-2017 hanbum park <kese111@gmail.com>

All rights reserved.

For detailed copyright information see the file COPYING in the root of the
distribution archive.

"""


import argparse
from PEInstrument import *
from PEAnalyzeTool import *
from PEManager import *
from keystone import *
from DataSegment import *


code_rva = 0


def simple_return_address_save_function_call_instrument(instruction):
    global code_rva
    code_zero_rva = code_rva - 0x1000
    instruction_zero_rva = instruction.address
    instruction_end_rva = instruction_zero_rva + instruction.size
    # 5 mean instrumented code size.
    code = "CALL {:d}".format(code_zero_rva - instruction_end_rva + 5)
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hex_code)
        return encoding, count
    except KsError as ex:
        print("ERROR: %s" % ex)
    return None, 0


def simple_return_address_save_function():
    global code_rva
    allocation = pe_instrument.falloc(0x1000)
    code = ("push eax;push ebx;"    # save register
            "mov eax, [{0}];"       # get shadow stack counter
            "inc eax;"              # increase shadow stack counter
            ""                      # get return address from stack
            "mov [{0}], eax;"       # save return address 
            "pop ebx;pop eax;"      # restore register
            "ret;"                  # return
            ).format(allocation.get_va() + 4)
    code_rva = pe_instrument.append_code(code)
    code_abs_va = pe_manager.get_abs_va_from_rva(code_rva)
    allocation[0:4] = code_abs_va

    # TODO : need a way for does not calculate the relocation address directly.
    pe_manager.register_rva_to_relocation(code_rva + 1 + 1)
    pe_manager.register_rva_to_relocation(code_rva + 7 + 1)


def simple_indirect_branch_counting_function_call_instrument(instruction):
    global code_rva
    code_zero_rva = code_rva - 0x1000
    instruction_zero_rva = instruction.address
    # 5 mean instrumented code size.
    code = "CALL {:d}".format(code_zero_rva - instruction_zero_rva + 5)
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hex_code)
        return encoding, count
    except KsError as ex:
        print("ERROR: %s" % ex)
    return None, 0


def simple_indirect_branch_counting_function_instrument():
    global code_rva
    allocation = pe_instrument.falloc(0x1000)
    code = ("push eax;"
            "mov eax, [{0}];"
            "inc eax;"
            "mov [{0}], eax;"
            "pop eax;"
            "ret;").format(allocation.get_va() + 4)
    code_rva = pe_instrument.append_code(code)
    code_abs_va = pe_manager.get_abs_va_from_rva(code_rva)
    allocation[0:4] = code_abs_va

    # TODO : need a way for does not calculate the relocation address directly.
    pe_manager.register_rva_to_relocation(code_rva + 1 + 1)
    pe_manager.register_rva_to_relocation(code_rva + 7 + 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser("zigzi")
    parser.add_argument("file",
                        help="filename include its absolute path.",
                        type=str)
    args = parser.parse_args()
    filename = args.file
    if not os.path.isfile(filename):
        parser.print_help()
        exit()
    pe_manager = PEManager(filename)
    # set new instrumentation
    pe_instrument = PEInstrument(pe_manager)
    simple_indirect_branch_counting_function_instrument()
    """
    pe_instrument.register_pre_indirect_branch(
        simple_indirect_branch_counting_function_call_instrument
    )
    """
    # need bug fix
    pe_instrument.register_after_indirect_branch(
        simple_return_address_save_function_call_instrument
    )

    pe_instrument.do_instrument()
    # TODO : change to avoid duplicate processing.
    # do not double adjustment for file, it break file layout.
    # pe_manager.adjust_file_layout()
    output_filename = filename[:-4] + "_after_test.exe"
    pe_manager.writefile(output_filename)

# C:\work\python\zigzi\tests\simple_echo_server.exe
