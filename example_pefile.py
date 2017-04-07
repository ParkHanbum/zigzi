import pefile
import distorm3
import binascii
import operator

def is_hex(s):
    try:
        int(s, 0)
        return True
    except ValueError:
        return False


MAX_INST_SEARCH = 6
text_start_va = 0
text_end_va = 0
text_rel_offset = 0
pe = pefile.PE('C:\\Program Files (x86)\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe')
openfile = open('C:\\Program Files (x86)\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe', 'rb')

call_log_file = open("call_log", "w")
jump_log_file = open("jump_log", "w")
inst_log_file = open("inst_log", "w")
rela_log_file = open("rela_log", "w")
unre_log_file = open("unre_log", "w")
relocated_log_file = open("relocated_log", "w")

img_start_va = pe.OPTIONAL_HEADER.ImageBase
img_end_va = img_start_va + pe.OPTIONAL_HEADER.SizeOfImage

for section in pe.sections:
    print (section.Name
           , hex(section.PointerToRawData), hex(section.SizeOfRawData)
           , hex(section.VirtualAddress), hex(section.Misc_VirtualSize)
           , hex(section.Characteristics))
    if (section.Name.startswith(".text")):
        text_start_va = section.VirtualAddress
        text_end_va = section.Misc_VirtualSize
        text_rel_offset = text_start_va - section.PointerToRawData
        text_start_raw = section.PointerToRawData
        text_size = section.SizeOfRawData

openfile.seek(text_start_raw)
read_hex = openfile.read(text_size)
read_str = binascii.hexlify(read_hex)

decode_call_map = {}
decode_jump_map = {}
decode_map = {}
for (offset, size, instruction, hexdump) in distorm3.Decode(0x0000, read_str.decode('hex'), distorm3.Decode32Bits):
    # print("0x%x:\t%s" % (offset, instruction))
    inst_log_file.write("[0x%x] %-30s\t%s\n" % (offset, instruction, hexdump))
    decode_map[offset] = instruction
    if instruction.startswith('CALL'):
        decode_call_map[offset] = (instruction, hexdump)
    if instruction.startswith('JMP'):
        decode_jump_map[offset] = (instruction, hexdump)


print "=================[call map]===================="
sorted_decode_call_map = sorted(decode_call_map.items(), key=operator.itemgetter(0))
for offset, (instruction, hexdump) in sorted_decode_call_map:
    call_log_file.write("[0x%x] %-30s\t%s\n" % (offset, instruction, hexdump))
    # print ("[0x%x] %s" % (offset, instruction))

print "=================[jump map]===================="
sorted_decode_jump_map = sorted(decode_jump_map.items(), key=operator.itemgetter(0))
for offset, (instruction, hexdump) in sorted_decode_jump_map:
    jump_log_file.write("[0x%x] %-30s\t%s\n" % (offset, instruction, hexdump))
    # print ("[0x%x] %s" % (offset, instruction))

print "=================[rela map]===================="
RELOC_DIR_COUNT = 0
RELOC_ENT_COUNT = 0
CHUNK_COUNT = 0
RELA_MAP = {}
relocated_map = {}
for entry in pe.DIRECTORY_ENTRY_BASERELOC:
    RELOC_DIR_COUNT += 1
    for el in entry.entries:
        RELOC_ENT_COUNT += 1
        inst_search = 0
        domore = True
        while domore:
            inst_search += 1
            address = el.rva - inst_search

            if el.type == 0:
                domore = False
                break
            if inst_search > 6:
                domore = False
                RELA_MAP[address] = [el.rva, address, "\t", el.type]
                # rela_log_file.write("[0x%x] 0x%x : \t EXCEPT\n" % (el.rva, address))
                # print ("[0x%x] 0x%x : \t EXCEPT" % (el.rva, address))
                break

            decode_value = decode_map.get(address-0x1000, "none")
            if not decode_value.startswith("none"):
                domore = False
                RELA_MAP[address] = [el.rva, address, decode_value, el.type]
                # rela_log_file.write("[0x%x] 0x%x : \t%s\tTYPE : %d\n" % (el.rva, address, decode_value, el.type))

                if address in decode_jump_map:
                    relocated_map[address] = decode_jump_map.pop(address)
                if address in decode_call_map:
                    relocated_map[address] = decode_call_map.pop(address)

                # print ("[0x%x] 0x%x : \t%s\tTYPE : %d" % (el.rva, address, decode_value, el.type))
                break

print ("RELOC_DIR_COUNT = %d\tRELOC_ENT_COUNT = %d\tCHUNK_COUNT = %d\t"
       % (RELOC_DIR_COUNT, RELOC_ENT_COUNT, CHUNK_COUNT))

print "============ unrelocated ============="
print "jump case"
sorted_decode_jump_map = sorted(decode_jump_map.items(), key=operator.itemgetter(0))
for (key, (inst, hexdump)) in sorted_decode_jump_map:
    unre_log_file.write("[0x%x] %-30s\t%s\n" % (key, inst, hexdump))
    # print ("[0x%x] %s" % (key, inst))

print "============ callcase ============="
print "call case"
sorted_decode_call_map = sorted(decode_call_map.items(), key=operator.itemgetter(0))
for (key, (inst, hexdump)) in sorted_decode_call_map:
    unre_log_file.write("[0x%x] %-30s\t%s\n" % (key, inst, hexdump))
    # print ("[0x%x] %s" % (key, inst))

print "============ relocated ============="
sorted_relocated_map = sorted(relocated_map.items(), key=operator.itemgetter(0))
for (key, inst) in sorted_relocated_map:
    relocated_log_file.write("[0x%x] %s\n" % (key, inst))

print "============ RELOCATION MAP ============="
sorted_RELA_MAP = sorted(RELA_MAP.items(), key=operator.itemgetter(0))
for (key, value) in sorted_RELA_MAP:
    # print ("[0x%x] 0x%x : \t%s\tTYPE : %d\n" % (dict[0], dict[1], dict[2], dict[3]))
    rela_log_file.write("[0x%x] 0x%x : \t%s\tTYPE : %d\n" % (value[0], value[1], value[2], value[3]))

"""
RELOC_DIR_COUNT = 0
RELOC_ENT_COUNT = 0
CHUNK_COUNT = 0

for entry in pe.DIRECTORY_ENTRY_BASERELOC:
    RELOC_DIR_COUNT += 1
    for el in entry.entries:
        RELOC_ENT_COUNT += 1
        domore = True
        inst_search = 0
        while domore and inst_search < MAX_INST_SEARCH:
            inst_search += 1
            decode_start = el.rva - text_rel_offset - inst_search
            try:
                openfile.seek(decode_start)
                read_hex = openfile.read(10)
                read_str = binascii.hexlify(read_hex)
            except IOError as ioe:
                print ioe
                print "inst_search : %d\t" % inst_search
                print "decode_start : %d\t" % decode_start
                exit()

            for chunk in md.disasm(read_hex, el.rva):
                if is_hex(chunk.op_str):
                    operand_value = int(chunk.op_str, 0)
                    if operand_value > text_start_va and operand_value < img_end_va:
                        print("0x%x:\t%s\t%s" % (chunk.address - inst_search, chunk.mnemonic, chunk.op_str))
                        CHUNK_COUNT += 1
                        domore = False

                        read_str = binascii.hexlify(read_hex)
                        for (offset, size, instruction, hexdump) in \
                                distorm3.Decode(0, read_str.decode('hex'), distorm3.Decode32Bits):
                            print("0x%x:\t%s" % (offset, instruction))
                            break

                        break
                    else:
                        print("[unbound] 0x%x:\t%s\t%s" % (chunk.address - inst_search, chunk.mnemonic, chunk.op_str))
                        domore = False

                        read_str = binascii.hexlify(read_hex)
                        for (offset, size, instruction, hexdump) in \
                                distorm3.Decode(0, read_str.decode('hex'), distorm3.Decode32Bits):
                            print("[unbound] 0x%x:\t%s" % (offset, instruction))
                            break

                        break
                break
print ("RELOC_DIR_COUNT = %d\tRELOC_ENT_COUNT = %d\tCHUNK_COUNT = %d"
       % (RELOC_DIR_COUNT, RELOC_ENT_COUNT, CHUNK_COUNT))
"""

"""
decode_start = el.rva - text_rel_offset - 1
openfile.seek(decode_start)
read_hex = openfile.read(15)
read_str = binascii.hexlify(read_hex)

for i in md.disasm(read_hex, 0x0):
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
"""

"""
for (offset, size, instruction, hexdump) in distorm3.Decode(0, read_str.decode('hex'), distorm3.Decode32Bits):
    print("0x%x:\t%s" % (offset, instruction))
"""

"""
for entry in pe.DIRECTORY_ENTRY_BASERELOC:
    for el in entry.entries:
        #print "type : " + hex(el.type) + " base_rva : " + hex(el.base_rva) + " rva : " + hex(el.rva)
        #if el.rva >= text_start_va and el.rva <= text_end_va:
        decode_start = el.rva - text_rel_offset - 1
        openfile.seek(decode_start)
        read_hex = openfile.read(15)
        read_str = binascii.hexlify(read_hex)
        print ("=====================[%x]========================" % el.rva)
        for i in md.disasm(read_hex, 0x0):
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        print "==========================================================="
        read_str = binascii.hexlify(read_hex)
        for (offset, size, instruction, hexdump) in distorm3.Decode(0, read_str.decode('hex'), distorm3.Decode32Bits):
            print("0x%x:\t%s" % (offset, instruction))
        print "==========================================================="
"""

