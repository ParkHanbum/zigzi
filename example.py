
from PEUtil import *
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
        return (encoding, count)
    except KsError as e:
        print("ERROR: %s" % e)
    return (None, 0)

if __name__ == '__main__':
    """
    filename = "c:\\work\\firefox.exe"
    pei = PEInstrument(filename)
    log_file = open('c:\\work\\origin_dis.log', 'w')
    instructions = pei.getInstructions()
    for address, inst in instructions:
        log_file.write("[0x%x] %s\t%s\n" %(inst.address, inst.mnemonic, inst.op_str))

    filename = "c:\\work\\firefox_test.exe"
    pei = PEInstrument(filename)
    log_file = open('c:\\work\\instrumented_dis.log', 'w')
    instructions = pei.getInstructions()
    for address, inst in instructions:
        log_file.write("[0x%x] %s\t%s\n" % (inst.address, inst.mnemonic, inst.op_str))
    """

    filename = "c:\\work\\firefox.exe"
    pei = PEInstrument(filename)
    pei.instrument_at_indirect_instruction(instrument_example)
    pei.writefile('c:\\work\\firefox_test.exe')
