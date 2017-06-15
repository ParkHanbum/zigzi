
from PEManager import *
from PEInstrument import *
from PEAnalyzeTool import *
from keystone import *
from Stack import *
from Heap import *
from capstone import *

def instrument_example(instruction):
    code = "MOV EAX, EAX"
    hexacode = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hexacode)
        return (encoding, count)
    except KsError as e:
        print("ERROR: %s" % e)
    return (None, 0)

if __name__ == '__main__':
    shadow_stack_address = 0x4200000
    # code = "MOV EAX, [{}]".format(shadow_stack_address)
    code_mnemonic = "CALL"
    code_op_str = "0x425202"
    code = code_mnemonic + " " + code_op_str
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        encoding, count = ks.asm(hex_code)
        print(encoding, count)
        for instruction in cs.disasm(bytearray(encoding), 0x0):
            print("{:s}\t{:s}".format(instruction.mnemonic, instruction.op_str))
    except KsError as e:
        print("ERROR: %s" % e)


