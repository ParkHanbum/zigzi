"""Zigzi, Platform independent binary instrumentation module.


Copyright (c) 2016-2017 hanbum park <kese111@gmail.com>

All rights reserved.

For detailed copyright information see the file COPYING in the root of the
distribution archive.

"""


import argparse
from PEInstrument import *
from PEAnalyzeTool import *
from keystone import *


def instrument_example(instruction):
    code = "MOV EAX, EAX"
    hexacode = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hexacode)
        return encoding, count
    except KsError as ex:
        print("ERROR: %s" % ex)
    return None, 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser("Zigzi")
    parser.add_argument("file",
                        help="filename include its absolute path.",
                        type=str)
    args = parser.parse_args()

    filename = args.file
    output_filename = filename[:-4] + "_test.exe"

    if not os.path.isfile(filename):
        parser.print_help()
        exit()
    pei = PEInstrument(filename)
    pei.instrument_at_indirect_instruction(instrument_example)
    pei.writefile(output_filename)
