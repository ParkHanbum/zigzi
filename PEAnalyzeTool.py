#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEAnalyzeTool, Analyze Portable Executable that Windows Executable Format Tool
"""

__author__ = 'ParkHanbum'
__version__ = '2017.3.28'
__contact__ = 'kese111@gmail.com'

import copy
import binascii
import sys
import Queue
import os.path
from threading import Thread
import threading
import operator
import pydotplus
import pefile
import distorm3
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

class CFGener(object):
    # OPERAND TYPES
    OPERAND_NONE = ""
    OPERAND_IMMEDIATE = "Immediate"
    OPERAND_REGISTER = "Register"
    # the operand is a memory address
    OPERAND_ABSOLUTE_ADDRESS = "AbsoluteMemoryAddress"  # The address calculated is absolute
    OPERAND_MEMORY = "AbsoluteMemory"  # The address calculated uses registers expression
    OPERAND_FAR_MEMORY = "FarMemory"  # like absolute but with selector/segment specified too

    def handle_FC_NONE(self, basic_block_size, inst):
        return 0

    def handle_FC_CALL(self, basic_block_size, inst):
        """
        handle kinds of CALL instruction.
        ex) CALL, CALL FAR.
        :param BasicBlock: @type BasicBlock
        :return:
        """
        handled = True
        operands = inst.operands

        if len(operands) > 1:
            return True

        operand = operands[0]

        # fin when operand is reg cause redirect
        if operand.type == CFGener.OPERAND_REGISTER:
            handled = False

        if operand.type == CFGener.OPERAND_IMMEDIATE:
            operand_value = operand.value
            if operand_value < 0:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            else:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            #self.create_basic_block(operand_value + basic_block.start_va)
            self.direct_control_flow[inst.address] = branch_va
            self.assign_new_branch(branch_va)
            handled = True

        if operand.type == CFGener.OPERAND_ABSOLUTE_ADDRESS:
            handled = False

        self.assign_new_branch(inst.address+inst.size)
        return handled

    def handle_FC_RET(self, basic_block_size, inst):
        """
        handle kinds of RET instruction.
        ex) RET, IRET, RETF.
        :param BasicBlock: @type BasicBlock
        :return: always return True cause RET is notice that end of decoding.
        """
        return True

    def handle_FC_SYS(self, basic_block_size, inst):
        """
        handle kinds of SYS instruction.
        ex) SYSCALL, SYSRET, SYSENTER, SYSEXIT.
        :param basic_block: @type BasicBlock
        :return:
        """
        return True

    def handle_FC_UNC_BRANCH(self, basic_block_size, inst):
        """
        handle kinds of Unconditional Branch instructions
        ex) JMP, JMP FAR.
        :param basic_block: @type BasicBlock
        :return:
        """
        handled = True
        operands = inst.operands

        if len(operands) > 1:
            return True

        operand = operands[0]

        # fin when operand is reg cause redirect
        if operand.type == CFGener.OPERAND_REGISTER:
            handled = False

        if operand.type == CFGener.OPERAND_IMMEDIATE:
            operand_value = operand.value
            if operand_value < 0:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            else:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            # self.create_basic_block(operand_value + basic_block.start_va)
            self.direct_control_flow[inst.address] = branch_va
            self.assign_new_branch(branch_va)
            handled = True

        if operand.type == CFGener.OPERAND_ABSOLUTE_ADDRESS:
            handled = False

        self.assign_new_branch(inst.address + inst.size)
        return handled

    def handle_FC_CND_BRANCH(self, basic_block_size, inst):
        """
        handle kinds of Contional Branch instructions
        ex) JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        :param basic_block: @type BasicBlock
        :return:
        """
        return self.handle_FC_UNC_BRANCH(basic_block_size, inst)

    def handle_flow_control(self, basic_block_size, inst):
        """Dispatch method"""
        try:
            method_name = 'handle_' + str(inst.flowControl)
            method = getattr(self, method_name)
            if callable(method):
                # Call the method as we return it
                return method(basic_block_size, inst)
            else:
                print "error?"

        except IndexError:
            print "===== [INDEX ERROR] ====="
            # self.print_basic_block(new_basic_block.start_va, new_basic_block)
            return False
        except AttributeError:
            # self.print_basic_block(new_basic_block.start_va, new_basic_block)
            return False

    def __init__(self, PEEditor):
        self.PEE = PEEditor
        self.MAX_DECODE_SIZE = 200
        self.basic_blocks = {}
        self.direct_control_flow = {}
        self.queue = Queue.Queue()
        self.execute_section = self.PEE.get_executable_section()
        self.execute_section_data = self.PEE.get_section_raw_data(self.execute_section)
        self.execute_section_va = self.execute_section.VirtualAddress
        self.entry_point_va = self.PEE.get_entry_point_va()
        self.lock = threading.Lock()

        # initialize pydotplus
        self.dot = pydotplus.graphviz.Dot(prog='test', format='dot')
        node = pydotplus.graphviz.Node(name='node', shape='record')
        self.dot.add_node(node)

    def assign_new_branch(self, va):
        self.lock.acquire()
        if not(va in self.basic_blocks):
            self.basic_blocks[va] = 0
            #print("Assign va : {:x}".format(va))
            self.queue.put(va)
        self.lock.release()

    def gen_control_flow_graph(self):
        # self.create_basic_block(self.entry_point_va - self.execute_section_va)
        # assignment entry point to work
        self.assign_new_branch(self.entry_point_va - self.execute_section_va)
        self.worker()
        """
        max_process_num = multiprocessing.cpu_count()
        threads = []
        for i in range(max_process_num):
            t = Thread(target=self.worker)
            threads.append(t)
            t.start()

        for x in threads:
            x.join()
        """
        print "all thread is done"

    def worker(self):
        MAX_IDLE_TIME = 1000
        IDLE_TIME = 0
        while True:
            if IDLE_TIME > MAX_IDLE_TIME:
                break
            if not self.queue.empty():
                IDLE_TIME = 0
                branch_addr = self.queue.get()
                #self.create_basic_block(branch_addr)
                t = Thread(target=self.create_basic_block, args=[branch_addr])
                t.start()
                t.join()
            else:
                IDLE_TIME += 1

    def create_basic_block(self, start_va):
        start_rva = start_va
        basic_block = distorm3.Decompose(0x0,
                                         binascii.hexlify(
                                             section_data[start_rva:start_rva+self.MAX_DECODE_SIZE])
                                         .decode('hex'),
                                         distorm3.Decode32Bits,
                                         distorm3.DF_STOP_ON_FLOW_CONTROL)
        try:
            if len(basic_block) >= 1:
                basic_block_size = 0
                for inst in basic_block:
                    basic_block_size += inst.size
                    inst.address += start_rva
                    self.basic_blocks[inst.address] = inst
                self.handle_flow_control(basic_block_size, basic_block[-1])
            else:
                self.remove_basic_block(start_rva)
                print("Cannot Parse Addr [0x{:x}]").format(start_rva)
        except IndexError:
            self.remove_basic_block(start_rva)
            print IndexError

    def remove_basic_block(self, va):
        if va in self.basic_blocks:
            del self.basic_blocks[va]

    def print_cfg(self):
        for addr, bblock in self.basic_blocks.items():
            self.print_basic_block(addr, bblock)

    def print_basic_block(self, addr, bblock):
        print("BASIC BLOCK [0x{:x}]".format(addr + self.execute_section_va))
        for inst in bblock.element:
            print("[0x{:08x}] {:s}".format(addr + self.execute_section_va + inst.address, inst))

    def save_cfg(self, save_path):
        basicblock_map = {}
        basicblock_els = []
        sorted_basic_blocks = sorted(self.basic_blocks.items(), key=operator.itemgetter(0))
        first_inst = (sorted_basic_blocks[0])[1]
        basicblock = BasicBlock()
        next_inst_addr = first_inst.address + first_inst.size
        basicblock_els.append(first_inst.address)
        basicblock.append(first_inst)
        del sorted_basic_blocks[0]
        for addr, inst in sorted_basic_blocks:
            if inst.address != next_inst_addr:
                self.dot.add_node(basicblock.toDotNode())
                for n in basicblock_els:
                    basicblock_map[n] = basicblock.get_va()
                basicblock_els = []
                basicblock = BasicBlock()
            basicblock_els.append(inst.address)
            basicblock.append(inst)
            next_inst_addr = inst.address + inst.size
        sorted_dcfg_item = sorted(self.direct_control_flow.items(), key=operator.itemgetter(0))
        for start_va, branch_va in sorted_dcfg_item:
            if (start_va in basicblock_map) and (branch_va in basicblock_map):
                basicblock_va = basicblock_map[start_va]
                src_va = ("loc_0x{:x}:loc_0x{:x}").format(basicblock_va, start_va)
                basicblock_va = basicblock_map[branch_va]
                dst_va = ("loc_0x{:x}:loc_0x{:x}").format(basicblock_va, branch_va)
                edge = pydotplus.graphviz.Edge(src=src_va, dst=dst_va)
                self.dot.add_edge(edge)
        self.dot.write(save_path)
        self.dot.write_svg(save_path+".svg")
        print "Done"

    """
    def save_basic_blocks(self, save_path):
        path_bblock = os.path.abspath(os.path.join(save_path, "BasicBlocks.txt"))
        path_cfg = os.path.abspath(os.path.join(save_path, "CFG.txt"))
        save_file = open(path_bblock, "w")
        save_cfg_file = open(path_cfg, "w")

        sorted_basic_blocks = sorted(self.basic_blocks.items(), key=operator.itemgetter(0))
        for addr, bblock in sorted_basic_blocks:
            save_file.write("BASIC BLOCK [0x{:08x}] \n".format(addr + self.execute_section_va))
            try:
                for inst in bblock.element:
                    save_file.write("[0x{:08x}] {:30s} \n".format(addr + self.execute_section_va + inst.address, inst))
            except AttributeError:
                print bblock

        sorted_dcfg_item = sorted(self.direct_control_flow.items(), key=operator.itemgetter(0))
        for start_va, branch_va in sorted_dcfg_item:
            save_cfg_file.write("0x{:08x} ->  0x{:08x}\n".format(start_va + self.execute_section_va,
                                                                 branch_va + self.execute_section_va))
    """


class BasicBlock(object):

    def __init__(self):
        self.basicblock = {}
        self.start_va = sys.maxint

    def append(self, inst):
        self.basicblock[inst.address] = inst
        if self.start_va > inst.address:
            self.start_va = inst.address

    def get_va(self):
        return self.start_va

    def toDotNode(self):
        sorted_basic_blocks = sorted(self.basicblock.items(), key=operator.itemgetter(0))
        label = "{"
        for addr, inst in sorted_basic_blocks:
            label += "{"
            label += ("<loc_0x{:x}>loc_0x{:x}").format(inst.address, inst.address)
            label += "|"
            label += ("{:s}").format(inst)
            label += "}"
            label += "|"
        label = label[:-1]
        label += "}"
        node = pydotplus.graphviz.Node(name=("loc_0x{:x}").format(self.start_va), label=label)
        return node


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
    #cfgener.print_cfg()
    #cfgener.save_basic_blocks("C:\\work")
    cfgener.save_cfg("C:\\work\\cfg.test")