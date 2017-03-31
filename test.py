import pefile
import distorm3
import PEUtil
import binascii

peutil = PEUtil.PEUtil('c:\\work\\PEview.exe')
execute_section = peutil.get_executable_section()
execute_section_data_1 = peutil.get_section_raw_data(execute_section)

peutil = PEUtil.PEUtil('c:\\work\\test2.exe')
execute_section = peutil.get_executable_section()
execute_section_data_2 = peutil.get_section_raw_data(execute_section)
file1 = distorm3.Decompose(0x0,
                           binascii.hexlify(execute_section_data_1).decode('hex'),
                           distorm3.Decode32Bits,
                           distorm3.DF_NONE)
file2 = distorm3.Decompose(0x0,
                           binascii.hexlify(execute_section_data_2).decode('hex'),
                           distorm3.Decode32Bits,
                           distorm3.DF_NONE)
file1_inst_map = {}
file2_inst_map = {}
for inst in file1:
    file1_inst_map[inst.address] = inst
for inst in file2:
    file2_inst_map[inst.address] = inst

file1_index = 0
file2_index = 0

good_adjust = 0
instructionTypes = ['FC_CALL', 'FC_UND_BRANCH', 'FC_CND_BRANCH']

for i in range(len(file1)):
    file1_el = file1[file1_index]
    file2_el = file2[file2_index]

    if not file1_el.mnemonic == file2_el.mnemonic:
        if file2[file2_index].mnemonic == "PUSH" and \
                        file2[file2_index+1].mnemonic == "PUSH" and \
                        file2[file2_index+2].mnemonic == "POP" and \
                        file2[file2_index+3].mnemonic == "POP" and \
                        file2[file2_index+4].mnemonic == file1_el.mnemonic:
            file2_index += 4
        else:
            print "file1 : {} {:x}\tfile2 : {} {:x}\n" \
                .format(file1_index, file1_el.address, file2_index, file2_el.address)
            break

    if file1_el.flowControl in instructionTypes \
            and file2_el.flowControl in instructionTypes \
            and file1_el.flowControl == file2_el.flowControl:
        if execute_section_data_1[file1_el.operands[0].value] \
                == execute_section_data_2[file2_el.operands[0].value]:
            good_adjust += 1
        else:
            print "NOT MATCH : {:x}  {:x}".format(file1_el.address, file2_el.address)
    file1_index += 1
    file2_index += 1
print "good adjust {}".format(good_adjust)

