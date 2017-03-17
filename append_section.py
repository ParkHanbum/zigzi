import copy
import pefile
import distorm3
import binascii
import sys
from keystone import *

class PEEditor(object):
    fast_load = True

    def __init__(self, name):
        self.PE_name = name
        pe_file = open(name, 'rb')
        pe_file_bytes = bytearray(pe_file.read())
        self.PE = pefile.PE(None, pe_file_bytes, self.fast_load)

    def get_section_headers(self):
        return self.PE.sections

    def print_section(self, section):
        print (section.Name, hex(section.VirtualAddress),
               hex(section.Misc_VirtualSize), section.SizeOfRawData,
               hex(section.get_file_offset())
               )

    def create_new_section_header(self):
        new_section = pefile.SectionStructure(self.PE.__IMAGE_SECTION_HEADER_format__, self.PE)
        new_section.Name = '.new\x00\x00\x00\x00'
        return new_section

    def clone_section_header(self, section):
        clone_section = copy.copy(section)
        return clone_section

    def append_section_to_PE(self, section):
        self.PE.__structures__.append(section)

    def get_file_data(self):
        return self.PE.__data__

    def get_aligned_offset(self, offset):
        file_align = self.PE.OPTIONAL_HEADER.FileAlignment
        v = offset % file_align
        if v > 0:
            return (offset - v) + file_align
        return offset

    def create_new_section(self, data):
        orig_data_len = len(self.PE.__data__)
        aligned_orig_data_len = self.get_aligned_offset(orig_data_len)
        data_len = len(data)
        aligned_data_len = self.get_aligned_offset(data_len)
        # make space
        space = bytearray((aligned_orig_data_len+aligned_data_len) - orig_data_len)
        self.PE.__data__[orig_data_len:aligned_orig_data_len+aligned_data_len] = space
        # Fill space with data
        self.PE.__data__[aligned_orig_data_len:aligned_orig_data_len+aligned_data_len] = data
        self.create_new_section_header(aligned_orig_data_len, aligned_data_len)

    def create_new_section_header(self, point_to_raw, size_of_raw):
        new_section = self.clone_section_header(self.PE.sections[0])
        new_section.SizeOfRawData = size_of_raw
        new_section.PointerToRawData = point_to_raw
        self.append_section_to_PE(new_section)

    def get_section_raw_data(self, section_hdr):
        start_offset = section_hdr.PointerToRawData
        size = section_hdr.SizeOfRawData
        data = bytearray(pee.PE.__data__[start_offset:start_offset+size])
        return data

    def get_entry_point_va(self):
        return self.PE.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_executable_section(self):
        for curr_section in self.get_section_headers():
            if curr_section.Characteristics & 0x20000000:
                return curr_section


class BasicBlock(object):

    def __init__(self, start_va, size, element):
        self.start_va = start_va
        self.size = size
        self.element = element
        self.end_va = start_va + size


class CFGener(object):
    # OPERAND TYPES
    OPERAND_NONE = ""
    OPERAND_IMMEDIATE = "Immediate"
    OPERAND_REGISTER = "Register"
    # the operand is a memory address
    OPERAND_ABSOLUTE_ADDRESS = "AbsoluteMemoryAddress"  # The address calculated is absolute
    OPERAND_MEMORY = "AbsoluteMemory"  # The address calculated uses registers expression
    OPERAND_FAR_MEMORY = "FarMemory"  # like absolute but with selector/segment specified too

    def handle_FC_NONE(self, basic_block):
        return 0

    def handle_FC_CALL(self, basic_block):
        """
        handle kinds of CALL instruction.
        ex) CALL, CALL FAR.
        :param BasicBlock: @type BasicBlock
        :return:
        """
        basic_block_elems = basic_block.element
        operands = basic_block_elems[-1].operands

        if len(operands) > 1:
            return True

        operand = operands[0]

        # fin when operand is reg cause redirect
        if operand.type == CFGener.OPERAND_REGISTER:
            handled = False

        if operand.type == CFGener.OPERAND_IMMEDIATE:
            operand_value = operand.value
            self.create_basic_block(operand_value + basic_block.start_va)
            handled = True

        if operand.type == CFGener.OPERAND_ABSOLUTE_ADDRESS:
            handled = False

        # after call branching, parsing next
        self.create_basic_block(basic_block.end_va)
        return handled

    def handle_FC_RET(self, basic_block):
        """
        handle kinds of RET instruction.
        ex) RET, IRET, RETF.
        :param BasicBlock: @type BasicBlock
        :return: always return True cause RET is notice that end of decoding.
        """
        return True

    def handle_FC_SYS(self, basic_block):
        """
        handle kinds of SYS instruction.
        ex) SYSCALL, SYSRET, SYSENTER, SYSEXIT.
        :param basic_block: @type BasicBlock
        :return:
        """
        return 0

    def handle_FC_UNC_BRANCH(self, basic_block):
        """
        handle kinds of Unconditional Branch instructions
        ex) JMP, JMP FAR.
        :param basic_block: @type BasicBlock
        :return:
        """
        basic_block_elems = basic_block.element
        operands = basic_block_elems[-1].operands

        if len(operands) > 1:
            return True

        operand = operands[0]

        # fin when operand is reg cause redirect
        if operand.type == CFGener.OPERAND_REGISTER:
            # it handled
            return True

        if operand.type == CFGener.OPERAND_IMMEDIATE:
            operand_value = operand.value
            self.create_basic_block(operand_value + basic_block.start_va)
            return True

        return False

    def handle_FC_CND_BRANCH(self, basic_block):
        """
        handle kinds of Contional Branch instructions
        ex) JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        :param basic_block: @type BasicBlock
        :return:
        """
        basic_block_elems = basic_block.element
        operands = basic_block_elems[-1].operands

        if len(operands) > 1:
            return True

        operand = operands[0]

        # fin when operand is reg cause redirect
        if operand.type == CFGener.OPERAND_REGISTER:
            # it handled
            return True

        if operand.type == CFGener.OPERAND_IMMEDIATE:
            operand_value = operand.value
            self.create_basic_block(operand_value + basic_block.start_va)
            return True

        return False

    def handle_flow_control(self, new_basic_block):
        """Dispatch method"""
        method_name = 'handle_' + str(new_basic_block.element[-1].flowControl)
        # Get the method from 'self'. Default to a lambda.
        method = getattr(self, method_name, lambda: "nothing")
        # Call the method as we return it
        return method(new_basic_block)

    def __init__(self, PEEditor):
        self.PEE = PEEditor
        self.MAX_DECODE_SIZE = 50
        self.basic_blocks = {}

    def gen_control_flow_graph(self):
        self.execute_section = self.PEE.get_executable_section()
        self.execute_section_data = self.PEE.get_section_raw_data(execute_section)
        self.execute_section_va = execute_section.VirtualAddress
        self.entry_point_va = pee.get_entry_point_va()
        self.create_basic_block(self.entry_point_va - self.execute_section_va)

    def create_basic_block(self, start_va):
        start_rva = start_va
        basic_block = distorm3.Decompose(0x0,
                                         binascii.hexlify(
                                             section_data[start_rva:start_rva+self.MAX_DECODE_SIZE])
                                         .decode('hex'),
                                         distorm3.Decode32Bits,
                                         distorm3.DF_STOP_ON_FLOW_CONTROL)
        basic_block_size = 0
        for el in basic_block:
            basic_block_size += el.size

        new_basic_block = BasicBlock(start_rva, basic_block_size, basic_block)
        self.basic_blocks[start_rva] = new_basic_block
        self.handle_flow_control(new_basic_block)

    def print_cfg(self):
        for addr, bblock in self.basic_blocks.items():
            print("BASIC BLOCK [0x{:08x}]".format(addr + self.execute_section_va))
            for inst in bblock.element:
                print("[0x{:08x}] {:30s}".format(addr + self.execute_section_va + inst.address, inst))

if __name__ == '__main__':
    sys.setrecursionlimit(100000)
    print sys.getrecursionlimit()
    pee = PEEditor('C:\\Program Files (x86)\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe')

    for curr_section in pee.get_section_headers():
        if curr_section.Characteristics & 0x20000000:
            execute_section = curr_section

    section_data = pee.get_section_raw_data(execute_section)
    execute_section_va = execute_section.VirtualAddress
    entry_point_va = pee.get_entry_point_va()
    #data = bytearray(pee.PE.__data__[1024:1162752])
    cfgener = CFGener(pee)
    cfgener.gen_control_flow_graph()
    cfgener.print_cfg()



    """
    entry_point_rva = entry_point_va - execute_section_va
    basic_block = distorm3.Decompose(0x1000,
                                     binascii.hexlify(
                                         section_data[entry_point_rva:entry_point_rva+pee.MAX_DECODE_SIZE])
                                     .decode('hex'),
                                     distorm3.Decode32Bits,
                                     distorm3.DF_STOP_ON_FLOW_CONTROL)
    print basic_block
    """

    """
    FlowControlHandler = {
        "FC_NONE"   : handle_FC_NONE,
        "FC_CALL"   : handle_FC_CALL,
        "FC_RET"    : handle_FC_RET,
        "FC_SYS"    : handle_FC_SYS,
        "FC_UNC_BRANCH" : handle_FC_UNC_BRANCH,

    }
    """

    """
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(b"mov eax, eax")
    asm_inserted_count = 0
    for (offset, size, instruction, hexdump) \
            in distorm3.Decode(0x0, binascii.hexlify(section_data).decode('hex'), distorm3.Decode32Bits):
        if instruction.startswith('CALL EBX'):
            print("%.8x: %-32s %s" % (offset, hexdump, instruction))
            # for test CALL EBX
            # if hexdump == 'ffd3':
            if (asm_inserted_count > 0): break
            for instr in reversed(encoding):
                section_data.insert(offset+(asm_inserted_count*2), instr)
            asm_inserted_count += 1
            print ("%.8x:" % (offset+(asm_inserted_count*2))) + binascii.hexlify(section_data[offset+(asm_inserted_count*2)-2:offset+(asm_inserted_count*2)+2])

    pee.create_new_section(section_data)
    pee.PE.write('c:\\work\\test_editor3.exe')
    """
