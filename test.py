import pefile
import distorm3
import PEUtil
import binascii
import operator
import struct

filename = "C:\\work\\check_pefile.exe"
pefile = pefile.PE(filename)
peutil = PEUtil.PEUtil(filename)

basereloc_va = 0
basereloc_size = 0
'IMAGE_DIRECTORY_ENTRY_SECURITY'
for index in range(len(peutil.PE.OPTIONAL_HEADER.DATA_DIRECTORY)):
    directory = peutil.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    if directory.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
        peutil.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress = 0
        peutil.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size = 0

peutil.write('c:\\work\\uncertified_firefox.exe')

for entry in peutil.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
    if entry.name == 'IMAGE_DIRECTORY_ENTRY_BASERELOC':
        basereloc_va = entry.VirtualAddress
        basereloc_size = entry.Size

section = peutil.get_section_by_va(basereloc_va)
reloc_raw = peutil.PE.__data__[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
reloc_blocks = {}
dword_size = 4
word_size = 2
block_raw = 0
while True:
    if block_raw >= basereloc_size:
        break
    block_rva = struct.unpack('I', reloc_raw[block_raw:block_raw+dword_size])[0]
    block_raw += dword_size
    block_size = struct.unpack('I', reloc_raw[block_raw:block_raw+dword_size])[0]
    block_raw += dword_size
    block_end = block_raw - dword_size*2 + block_size
    entries = []
    for index in range(block_size / word_size):
        entry = struct.unpack('H', reloc_raw[block_raw:block_raw+word_size])[0]
        entries.append((entry, block_raw))
        block_raw += word_size
        if block_raw >= block_end:
            break
    reloc_blocks[block_rva] = entries

reloc_blocks = peutil.get_reloc_map()
sorted_map = sorted(reloc_blocks.items(),
                    key=operator.itemgetter(0))
for block_rva, reloc_block in sorted_map:
    for (entry, block_raw) in reloc_block:
        print "BLOCK[{:x}]\t{:x}\toffset:{:x}".format(block_rva, entry, block_raw)


"""
sorted_map = sorted(reloc_blocks.items(),
                    key=operator.itemgetter(0))
for block_rva, reloc_block in sorted_map:
    for (entry, block_raw) in reloc_block:
        print "BLOCK[{:x}]\t{:x}\toffset:{:x}".format(block_rva, entry-0x3000, block_raw+section.PointerToRawData)
"""

"""
sorted_map = sorted(map.items(),
                    key=operator.itemgetter(0))

for (address, entry) in sorted_map:
    print "[0x{:x}] 0x{:x} {}".format(entry[0], entry[1], entry[2])

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

"""