
from PEUtil import *
from PEInstrument import *
from PEAnalyzeTool import *
from keystone import *


def test(instruction):
    instruction_types = ['FC_CALL', 'FC_UND_BRANCH', 'FC_CND_BRANCH']
    operand = instruction.operands[0]
    # code = "PUSH eax;PUSH {:s};POP eax;POP eax".format(operand)
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
    filename = "C:\\work\\sample.exe"
    pei = PEInstrument(filename)
    pei.instrument_redirect_controlflow_instruction(test)
    pei.writefile('c:\\work\\sample_test.exe')

    filename = "c:\\work\\firefox.exe"
    pei = PEInstrument(filename)
    pei.instrument_redirect_controlflow_instruction(test)
    pei.writefile('c:\\work\\firefox_test.exe')
