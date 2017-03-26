from PEUtil import *
from PEAnalyzeTool import *
from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_32)

def test(instruction):
    operand = instruction.operands[0]
    code = binascii.hexlify("PUSH {:s};".format(operand)).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(code)
        # print("%s = %s (number of statements: %u)" % (code, encoding, count))
        return (encoding, count)
    except KsError as e:
        print("ERROR: %s" % e)
    return (None, 0)

if __name__ == '__main__':
    #peutil = PEUtil.PEUtil("C:\\Program Files (x86)\\Mozilla Firefox\\crashreporter.exe")
    peutil = PEUtil.PEUtil('C:\\Program Files (x86)\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe')
    execute_section = peutil.get_executable_section()
    execute_section_data = peutil.get_section_raw_data(execute_section)
    entry_point_va = peutil.get_entry_point_va()

    peanalyzer = PEAnalyzer(execute_section, execute_section_data, entry_point_va)
    #peanalyzer.gen_control_flow_graph()
    #peanalyzer.save_cfg("C:\\work\\cfg.test", peutil.get_pe_name())

    pei = PEInstrument(execute_section_data)
    # pei.logging('c:\\work\\log.txt')
    pei.instrument_redirect_control_flow_inst(test)
    pei.disassembly_log('c:\\work\\disassembly.log')
