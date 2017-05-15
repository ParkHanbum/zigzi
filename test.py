from PEInstrument import *
from PEAnalyzeTool import *

def get_disassemble_list1(filename):
    dis_list = []
    peutil = PEUtil.PEUtil(filename)
    execute_section = peutil.get_executable_section()
    execute_section_data = peutil.get_section_raw_data(execute_section)
    hexacode = binascii.hexlify(execute_section_data).decode('hex')
    disassemble = distorm3.Decompose(0x1000, hexacode, distorm3.Decode32Bits)
    """ for firefox
    for el in disassemble:
        if not (0x507d < el.address < 0x50a0):
            dis_list.append(el)
    """
    return peutil, dis_list

def get_disassemble_list2(filename):
    dis_list = []
    peutil = PEUtil.PEUtil(filename)
    execute_section = peutil.get_executable_section()
    execute_section_data = peutil.get_section_raw_data(execute_section)
    hexacode = binascii.hexlify(execute_section_data).decode('hex')
    disassemble = distorm3.Decompose(0x1000, hexacode, distorm3.Decode32Bits)
    """ for firefox
    for el in disassemble:
        # 00405217
        if not(0x5217 < el.address < 0x523a):
            dis_list.append(el)
    """
    return peutil, dis_list

def checkAdjustedValue(dst_dis, dst_peutil, src_dis, src_peutil):
    if len(dst_dis.operands) > 0:
        for index in xrange(len(dst_dis.operands)):
            dst_operand = dst_dis.operands[index]
            src_operand = src_dis.operands[index]
            dst_value = 0
            src_value = 0
            if 0x401000 < dst_operand.value < 0x800000:
                dst_value = dst_peutil.PE.get_dword_at_rva(dst_operand.value - 0x400000)
                src_value = src_peutil.PE.get_dword_at_rva(src_operand.value - 0x400000)

            elif dst_operand.value > 0:
                dst_value = dst_peutil.PE.get_dword_at_rva(dst_operand.value)
                src_value = src_peutil.PE.get_dword_at_rva(src_operand.value)

            elif 0x401000 < dst_operand.disp < 0x800000:
                dst_value = dst_peutil.PE.get_dword_at_rva(dst_operand.disp - 0x400000)
                src_value = src_peutil.PE.get_dword_at_rva(src_operand.disp - 0x400000)

            elif dst_operand.disp > 0:
                dst_value = dst_peutil.PE.get_dword_at_rva(dst_operand.disp)
                src_value = src_peutil.PE.get_dword_at_rva(src_operand.disp)

            if dst_value != src_value:
                print "[0x{:x}]{}\t0x{:x}\t[0x{:x}]{}\t0x{:x}".format(dst_dis.address, dst_el, dst_value,
                                                                      src_dis.address, src_el, src_value)

if __name__ == '__main__':
    src_file = "c:\\work\\sample.exe"
    dst_file = "c:\\work\\sample_test.exe"

    src_pei = PEInstrument(src_file)
    dst_pei = PEInstrument(dst_file)
    src_disassemble = src_pei.get_instructions()
    dst_disassemble = dst_pei.get_instructions()

    dst_index = 0
    src_index = 0
    for index in xrange(len(dst_disassemble)):
        try:
            dst_dis_address, dst_dis = dst_disassemble[dst_index]
            src_dis_address, src_dis = src_disassemble[src_index]
        except:
            break
        dst_el = "{}".format(dst_dis)
        src_el = "{}".format(src_dis)

        if dst_el == 'MOV EAX, EAX':
            # print "0x{:x}".format(dst_dis.address)
            dst_index += 1
            continue

        if dst_el != src_el:
            if dst_dis.mnemonic == src_dis.mnemonic:
                # checkAdjustedValue(dst_dis, dst_peutil, src_dis, src_peutil)
                print "ADJUSTED\t[0x{:x}]{}\t[0x{:x}]{}".format(dst_dis.address, dst_el, src_dis.address, src_el)

            else:
                print "ERROR\t[0x{:x}]{}\t[0x{:x}]{}".format(dst_dis.address, dst_el, src_dis.address, src_el)
        dst_index += 1
        src_index += 1

