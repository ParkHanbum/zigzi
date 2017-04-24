from pefile import *
import distorm3
import PEUtil
import binascii
import operator
import struct
import shutil

filename = "C:\\work\\firefox.exe"
peutil = PEUtil.PEUtil(filename)
imagebase = peutil.PE.OPTIONAL_HEADER.ImageBase

peutil.PE.sections[0].Misc_VirtualSize = 136640
pINT = peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pINT
peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pINT = pINT + 0x1000
pIAT = peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pIAT
peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pIAT = pIAT + 0x1000
peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pBoundIAT += 0x1000
peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.phmod += 0x1000
peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.szName += 0x1000

for importdata in peutil.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].imports:
    iat = importdata.struct_iat
    ilt = importdata.struct_table
    iat.AddressOfData += 0x1000
    iat.ForwarderString += 0x1000
    iat.Function += 0x1000
    iat.Ordinal += 0x1000
    ilt.AddressOfData += 0x1000
    ilt.ForwarderString += 0x1000
    ilt.Function += 0x1000
    ilt.Ordinal += 0x1000


for entry in peutil.PE.DIRECTORY_ENTRY_IMPORT:
    entry.struct.Characteristics += 0x1000
    entry.struct.FirstThunk += 0x1000
    entry.struct.Name += 0x1000
    entry.struct.OriginalFirstThunk += 0x1000

    for importdata in entry.imports:
        ilt = importdata.struct_table
        ilt.AddressOfData += 0x1000
        ilt.ForwarderString += 0x1000
        ilt.Function += 0x1000
        ilt.Ordinal += 0x1000

        iat = importdata.struct_iat
        if iat:
            iat.AddressOfData += 0x1000
            iat.ForwarderString += 0x1000
            iat.Function += 0x1000
            iat.Ordinal += 0x1000
        else:
            origin_iat_rva = importdata.address - imagebase
            # name_rva = peutil.PE.get_dword_at_rva(origin_iat_rva)

            name = peutil.PE.get_data(
                origin_iat_rva,
                Structure(peutil.PE.__IMAGE_THUNK_DATA_format__).sizeof())
            # peutil.PE.set_dword_at_rva(origin_iat_rva, name_rva + 0x1000)
            thunk_data = peutil.PE.__unpack_data__(
                peutil.PE.__IMAGE_THUNK_DATA_format__, name,
                file_offset=peutil.PE.get_offset_from_rva(origin_iat_rva))
            thunk_data.AddressOfData += 0x1000
            thunk_data.ForwarderString += 0x1000
            thunk_data.Function += 0x1000
            thunk_data.Ordinal += 0x1000
            importdata.struct_iat = thunk_data

peutil.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions += 0x1000
peutil.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals += 0x1000
export_addressofname = peutil.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames
peutil.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames = export_addressofname + 0x1000
peutil.PE.DIRECTORY_ENTRY_EXPORT.struct.Name += 0x1000

for index in xrange(len(peutil.PE.DIRECTORY_ENTRY_EXPORT.symbols)):
    entry_name_rva = export_addressofname + (index*4)
    name_rva = peutil.PE.get_dword_at_rva(entry_name_rva)
    name_rva += 0x1000
    peutil.PE.set_dword_at_rva(entry_name_rva, name_rva)

for rsrc_entries in peutil.PE.DIRECTORY_ENTRY_RESOURCE.entries:
    for rsrc_directory_entry in rsrc_entries.directory.entries:
        for rsrc_entry_directory_entry in rsrc_directory_entry.directory.entries:
            print "0x{:x}".format(rsrc_entry_directory_entry.data.struct.OffsetToData)
            rsrc_entry_directory_entry.data.struct.OffsetToData += 0x1000

peutil.write("c:\\work\\_test_pe.exe")

"""
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