#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEAnalyzeTool, Analyze tool for PE that Windows Portable Executable Format
"""

__author__ = 'ParkHanbum'
__version__ = '2017.3.28'
__contact__ = 'kese111@gmail.com'

import Queue
import struct
import binascii
import operator
import sys
import threading
import distorm3
import pydotplus
import PEUtil
import array
from threading import Thread
from keystone import *


class PEAnalyzer(object):
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
        if operand.type == PEAnalyzer.OPERAND_REGISTER:
            handled = False

        if operand.type == PEAnalyzer.OPERAND_IMMEDIATE:
            operand_value = operand.value
            if operand_value < 0:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            else:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            #self.create_basic_block(operand_value + basic_block.start_va)
            self.direct_control_flow[inst.address] = branch_va
            self.assignNewBranch(branch_va)
            handled = True

        if operand.type == PEAnalyzer.OPERAND_ABSOLUTE_ADDRESS:
            handled = False

        self.assignNewBranch(inst.address + inst.size)
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
        if operand.type == PEAnalyzer.OPERAND_REGISTER:
            handled = False

        if operand.type == PEAnalyzer.OPERAND_IMMEDIATE:
            operand_value = operand.value
            if operand_value < 0:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            else:
                branch_va = inst.address + inst.size + operand_value - basic_block_size
            # self.create_basic_block(operand_value + basic_block.start_va)
            self.direct_control_flow[inst.address] = branch_va
            self.assignNewBranch(branch_va)
            handled = True

        if operand.type == PEAnalyzer.OPERAND_ABSOLUTE_ADDRESS:
            handled = False

        self.assignNewBranch(inst.address + inst.size)
        return handled

    def handle_FC_CND_BRANCH(self, basic_block_size, inst):
        """
        handle kinds of Contional Branch instructions
        ex) JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        :param basic_block: @type BasicBlock
        :return:
        """
        return self.handle_FC_UNC_BRANCH(basic_block_size, inst)

    def handleConrolFlow(self, basic_block_size, inst):
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

    def __init__(self, execute_section, execute_section_data, entry_point_va):
        self.MAX_DECODE_SIZE = 200
        self.inst_map = {}
        self.direct_control_flow = {}
        self.queue = Queue.Queue()
        self.execute_section = execute_section
        self.execute_section_data = execute_section_data
        self.entry_point_va = entry_point_va
        self.execute_section_va = self.execute_section.VirtualAddress
        self.lock = threading.Lock()

    def assignNewBranch(self, va):
        self.lock.acquire()
        if not(va in self.inst_map):
            self.inst_map[va] = 0
            #print("Assign va : {:x}".format(va))
            self.queue.put(va)
        self.lock.release()

    def genControlFlowGraph(self):
        # self.create_basic_block(self.entry_point_va - self.execute_section_va)
        # assignment entry point to work
        self.assignNewBranch(self.entry_point_va - self.execute_section_va)
        self.parser()

    def parser(self):
        MAX_IDLE_TIME = 1000
        IDLE_TIME = 0
        while True:
            if IDLE_TIME > MAX_IDLE_TIME:
                break
            if not self.queue.empty():
                IDLE_TIME = 0
                branch_addr = self.queue.get()
                #self.create_basic_block(branch_addr)
                t = Thread(target=self.parse, args=[branch_addr])
                t.start()
                t.join()
            else:
                IDLE_TIME += 1

    def parse(self, start_va):
        start_rva = start_va
        basic_block = distorm3.Decompose(0x0,
                                         binascii.hexlify(
                                             self.execute_section_data[start_rva:start_rva+self.MAX_DECODE_SIZE])
                                         .decode('hex'),
                                         distorm3.Decode32Bits,
                                         distorm3.DF_STOP_ON_FLOW_CONTROL)
        try:
            if len(basic_block) >= 1:
                basic_block_size = 0
                for inst in basic_block:
                    basic_block_size += inst.size
                    inst.address += start_rva
                    self.inst_map[inst.address] = inst
                self.handleConrolFlow(basic_block_size, basic_block[-1])
            else:
                self.removeInstructionFromMap(start_rva)
                print("Cannot Parse Addr [0x{:x}]").format(start_rva)
        except IndexError:
            self.removeInstructionFromMap(start_rva)
            print IndexError

    def removeInstructionFromMap(self, va):
        if va in self.inst_map:
            del self.inst_map[va]

    def save_cfg(self, save_path, name=None):
        # initialize pydotplus
        if name is None:
            dot = pydotplus.graphviz.Dot(prog='test', format='dot')
        else:
            dot = pydotplus.graphviz.Dot(prog=name, format='dot')
        node = pydotplus.graphviz.Node(name='node', shape='record')
        dot.add_node(node)

        basicblock_map = {}
        basicblock_els = []
        sorted_basic_blocks = sorted(self.inst_map.items(), key=operator.itemgetter(0))
        first_inst = (sorted_basic_blocks[0])[1]
        basicblock = BasicBlock()
        next_inst_addr = first_inst.address + first_inst.size
        basicblock_els.append(first_inst.address)
        basicblock.append(first_inst)
        del sorted_basic_blocks[0]
        for addr, inst in sorted_basic_blocks:
            if inst.address != next_inst_addr:
                dot.add_node(basicblock.toDotNode())
                for n in basicblock_els:
                    basicblock_map[n] = basicblock.getStartAddress()
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
                dot.add_edge(edge)
        dot.write(save_path)
        dot.write_svg(save_path+".svg")
        print "Done"


class BasicBlock(object):

    def __init__(self):
        self.basicblock = {}
        self.start_va = sys.maxint

    def append(self, inst):
        self.basicblock[inst.address] = inst
        if self.start_va > inst.address:
            self.start_va = inst.address

    def getStartAddress(self):
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


class PEInstrument(object):
    INSTRUMENT_BEFORE = 1
    INSTRUMENT_AFTER = 2

    def __init__(self, execute_data):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.execute_data = execute_data
        self.instruction_map = {}
        self.instrument_map = {}
        self.disassembly = []
        self.disassemble()
        self.overflowed_instrument = False
        self.overflowed_instrument_map = {}

    def disassemble(self):
        self.disassembly = distorm3.Decompose(
            0x0,
            binascii.hexlify(self.execute_data).decode('hex'),
            distorm3.Decode32Bits,
            distorm3.DF_NONE)
        self.instruction_map.clear()
        for inst in self.disassembly:
            self.instruction_map[inst.address] = inst

    def getdata(self):
        return self.execute_data

    def get_instrumented_map(self):
        return self.instrument_map

    def instrument_redirect_controlflow_instruction(self, command, position=None):
        instructionTypes = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']
        # instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH', 'FC_RET']
        instrumentTotalAmount = 0
        for inst in self.disassembly:
            cf = inst.flowControl
            if cf in instructionTypes:
                if self.is_redirect(inst):
                    result = self.instrument(command, inst, instrumentTotalAmount)
                    instrumentTotalAmount += result
        print "INSTRUMENT TOTAL AMOUNT {:d}".format(instrumentTotalAmount)
        self.disassemble()
        self.adjust_instrumented_layout()
        # TODO : adjust relocation

    def instrument_by_mnemonics(self, command, mnemonics=[], position=None):
        instrumentTotalAmount = 0
        if not mnemonics:
            print "Mnemonic is empty\n"
            return

        for inst in self.disassembly:
            if inst.mnemonic in mnemonics:
                result = self.instrument(command, inst, instrumentTotalAmount)
                instrumentTotalAmount += result
        print "INSTRUMENT TOTAL AMOUNT {:d}".format(instrumentTotalAmount)
        self.disassemble()

    def instrument(self, command, instruction, total_count=0):
        instrument_size = 0
        instrument_inst, count = command(instruction)
        if count > 0:
            instrument_size = len(instrument_inst)
            # put instrument instruction to execute_section_data
            offset = instruction.address + total_count
            self.execute_data[offset:offset] = instrument_inst
            self.instrument_map[offset] = len(instrument_inst)
        return instrument_size

    def get_instrumented_size(self, inst):
        inst_address = inst.address
        inst_destiny = inst.operands[0].value
        block_instrumented_size = 0
        if inst_address <= inst_destiny:
            sorted_instrument_map = sorted(self.instrument_map.items(),
                                           key=operator.itemgetter(0))
            for instrument_address, instrument_size in sorted_instrument_map:
                if instrument_address > inst_destiny:
                    break
                if inst_address < instrument_address <= inst_destiny:
                    instrumented_size = instrument_size
                    block_instrumented_size += instrumented_size
                    inst_destiny += instrumented_size
        else:
            sorted_instrument_map = sorted(self.instrument_map.items(),
                                           key=operator.itemgetter(0),
                                           reverse=True)
            for instrument_address, instrument_size in sorted_instrument_map:
                # inst_destiny can be instrumented instruction.
                # cause subtract instrument_size from inst_destiny
                if inst_destiny - instrument_size <= instrument_address < inst_address:
                    if instrument_address < inst_destiny - instrument_size:
                        break
                    instrumented_size = instrument_size
                    block_instrumented_size += instrumented_size
                    inst_destiny -= instrumented_size
        return block_instrumented_size

    def adjust_instrumented_layout(self):
        self.disassemble()
        sorted_instruction_map = sorted(self.instruction_map.items(),
                                        key=operator.itemgetter(0))
        logfile = open('c:\\work\\adjust.log', 'a')
        for inst_address, inst in sorted_instruction_map:
            if inst.flowControl in ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']:
                log = []
                if not self.is_redirect(inst):
                    total_instrumented_size = \
                        self.get_instrumented_size(inst)
                    # adjust operand value
                    if total_instrumented_size > 0:
                        log.append("[0x{:x}] {:s}\n".format(inst.address, inst))
                        operand_size = inst.operands[0].size / 8
                        instruction_size = inst.size - operand_size
                        operand_start = inst_address + instruction_size
                        operand_end = inst_address + inst.size
                        if operand_size == 8:
                            fmt = 'l'
                        elif operand_size == 4:
                            fmt = 'i'
                        elif operand_size == 2:
                            fmt = 'h'
                        elif operand_size == 1:
                            fmt = 'b'
                        operand_value \
                            = struct.unpack(fmt,
                                            self.execute_data[operand_start:operand_end])[0]
                        log.append("\torigin operand value : {:x}\n".format(operand_value))
                        if operand_value > 0:
                            adjusted_operand_value = \
                                operand_value + total_instrumented_size
                        else:
                            adjusted_operand_value = \
                                operand_value - total_instrumented_size
                        log.append("\tadjust operand value : {:x}\n"
                                   .format(adjusted_operand_value))
                        try:
                            self.execute_data[operand_start:operand_end] \
                                = struct.pack(fmt, adjusted_operand_value)
                        except:
                            self.overflowed_instrument = True
                            self.overflowed_instrument_map[inst_address] = (inst, adjusted_operand_value)
                            log.append("operand value size overflowed {:x}\n".format(operand_value))
                logfile.write(''.join(log))
        has_overflowed_inst = self.handle_overflow_instrument()
        if has_overflowed_inst:
            self.disassemble()
            self.adjust_instrumented_layout()

    def handle_overflow_instrument(self):
        total_instrument_size = 0
        self.disassemble()
        self.instrument_map.clear()
        if not self.overflowed_instrument:
            return False
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        index = 1
        sorted_instrument_map = sorted(self.overflowed_instrument_map.items(),
                                       key=operator.itemgetter(0))
        for (inst_address, (inst, adjusted_operand_value)) in sorted_instrument_map:
            inst_address += total_instrument_size
            print "[{}] overflowed instrument instruction : [0x{:x}] {:s}  {:x} => {}" \
                .format(index, inst_address, inst,
                        inst.operands[0].value, adjusted_operand_value)
            index += 1
            # TODO : fix constant 6 to increased opcode, operand size
            code = "{:s} {}".format(inst.mnemonic, adjusted_operand_value + 6)
            hexacode = binascii.hexlify(code).decode('hex')
            try:
                # Initialize engine in X86-32bit mode
                encoding, count = ks.asm(hexacode)
                print "{:s}".format(encoding)
                # patch
                self.execute_data[inst_address:inst_address+inst.size] = encoding
                instrumented_size = len(encoding)
                print "writed : {:s}".format(
                    binascii.hexlify(
                        self.execute_data[inst_address:inst_address+instrumented_size]))
                # save increased opcode, operand size for adjust again
                increased_size = instrumented_size - inst.size
                self.instrument_map[inst_address] = increased_size
                total_instrument_size += increased_size
            except KsError as e:
                print("ERROR: %s" % e)

        self.overflowed_instrument = False
        self.overflowed_instrument_map.clear()
        return True

    def is_redirect(self, inst):
        instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']
        cf = inst.flowControl
        if cf in instruction_types:
            operands = inst.operands
            if len(operands) > 0:
                operand = operands[0]
                if operand.type == 'AbsoluteMemoryAddress' or operand.type == 'Register' \
                        or operand.type == 'AbsoluteMemory':
                    return True
        return False

    def logging(self, path):
        log = open(path, 'w')
        # monitoring instruction
        instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH', 'FC_RET', 'FC_INT']
        result = ''
        for (key, inst) in self.instruction_map.items():
            cf = inst.flowControl
            operands = inst.operands
            if cf in instruction_types:
                result += '[0x{:05x}]'.format(inst.address)
                if len(operands) > 0:
                    operand = operands[0]
                    if operand.type == 'AbsoluteMemoryAddress':
                        result += '{:>10s}\t'.format('AbsoluteMemoryAddr')
                    elif operand.type == 'AbsoluteMemory':
                        result += '{:>10s}\t'.format('AbsoluteMemory')
                    elif operand.type == 'Immediate':
                        result += '{:>10s}\t'.format('Immediate')
                    elif operand.type == 'Register':
                        result += '{:>10s}\t'.format('Register')
                    else:
                        result += 'Type{:s}\t{:s}\t'.format(operand.type, operand)
                else:
                    result += '{:>10s}\t'.format('NoneOperand')
                result += '{:>10s}\t'.format(cf)
                result += '{:s}\n'.format(inst)
        log.write(result)

    def disassembly_logging(self, path):
        log = open(path, 'w')
        self.disassemble()
        for inst in self.disassembly:
            log.write("[0x{:x}] {:s}\n".format(inst.address, inst))

    def instrument_log(self, path):
        log = open(path, 'w')
        sorted_instrument_map = sorted(self.instrument_map.items(),
                                       key=operator.itemgetter(0))
        for instrument_address, instrument_inst in sorted_instrument_map:
            log.write("[0x{:x}] {:d}\n".format(instrument_address, instrument_inst))
