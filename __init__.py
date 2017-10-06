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
from SampleReturnVerifier import *
from SampleBranchCounter import *
from WindowAPIHelper import *

code_rva = 0


def do_indirect_branch_counting(pe_instrument, pe_manager):
    simple_indirect_branch_counting_function_instrument(pe_instrument, pe_manager)

    pe_instrument.register_pre_indirect_branch(
        simple_indirect_branch_counting_function_call_instrument
    )


def do_return_address_verifier(pe_instrument, pe_manager, fn_rva):
    simple_instrument_error_handler(pe_instrument, pe_manager, fn_rva)
    pe_instrument.register_after_relative_branch(
        simple_instrument_return_address_at_after_branch
    )
    pe_instrument.register_after_indirect_branch(
        simple_instrument_return_address_at_after_branch
    )
    pe_instrument.register_pre_return(
        simple_instrument_return_address_verifier_at_pre_return
    )
    pe_instrument.do_instrument()

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
    # add api
    window_api_helper = WindowAPIHelper(pe_manager)
    message_box_fn_rva = window_api_helper.add_message_box()
    # set new instrumentation
    pe_instrument = PEInstrument(pe_manager)
    do_return_address_verifier(pe_instrument, pe_manager, message_box_fn_rva)
    # do_indirect_branch_counting(pe_instrument, pe_manager)

    # TODO : change to avoid duplicate processing.
    # do not double adjustment for file, it break file layout.
    # pe_manager.adjust_file_layout()
    output_filename = filename[:-4] + "_after_test.exe"
    pe_manager.writefile(output_filename)
    pe_instrument.save_instruction_log("init_final_instructions.log")
# C:\work\python\zigzi\tests\simple_echo_server.exe
