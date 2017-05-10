
from PEUtil import *
from PEInstrument import *
from PEAnalyzeTool import *
from keystone import *


def test(instruction):
    instruction_types = ['FC_CALL', 'FC_UND_BRANCH', 'FC_CND_BRANCH']
    operand = instruction.operands[0]
    #code = "PUSH eax;PUSH {:s};POP eax;POP eax".format(operand)
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
    # peutil = PEUtil.PEUtil("C:\\Program Files (x86)\\Mozilla Firefox\\crashreporter.exe")
    # peutil = PEUtil.PEUtil("C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe")
    peutil = PEUtil.PEUtil('c:\\work\\PEview.exe')
    execute_section = peutil.get_executable_section()
    execute_section_data = peutil.get_section_raw_data(execute_section)
    entry_point_va = peutil.get_entry_point_va()
    peanalyzer = PEAnalyzer(execute_section, execute_section_data, entry_point_va)
    peanalyzer.gen_control_flow_graph()
    peanalyzer.save_cfg("C:\\work\\cfg.test", peutil.get_pe_name())
    """
    # need handle for non-relocation executable. referencing self code section statically.
    # filename = 'c:\\work\\PEview.exe'
    # need handle for memory error.
    # filename = "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    # filename = "c:\\work\\pexplorer.exe"
    # need handle for export
    filename = "c:\\work\\firefox.exe"


    pei = PEInstrument(filename)
    # pei.logging('c:\\work\\log.txt')
    # pei.disassembly_logging('c:\\work\\disassembly.log')
    pei.instrument_redirect_controlflow_instruction(test)
    # pei.disassembly_logging('c:\\work\\disassembly_adjust.log')
    # pei.instrument_log('c:\\work\\instrument.log')
    pei.writefile('c:\\work\\test.exe')

    """
    new_section = peutil.create_new_section(execute_section_data)
    print "entry point : {:x}".format(entry_point_va)
    peutil.setentrypoint(entry_point_va)
    peutil.write('c:\\work\\test.exe')
    """
