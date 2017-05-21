#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEInstrument, support instrumentation feature for window executable binary format(PE).
"""

import struct
import binascii
import distorm3
import operator
import os.path
import copy

from PEUtil import *
from keystone import *
from Disassembler import *


class PEInstrument(object):
    _INSTRUMENT_BEFORE = 1
    _INSTRUMENT_AFTER = 2

    def __init__(self, filename):
        self.peutil = PEUtil(filename)
        self.entry_point_va = self.peutil.getEntryPointVA()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)

        execute_section = self.peutil.getExecutableSection()
        execute_section_data = self.peutil.getSectionRawData(execute_section)
        self.Disassembler = Disassembler(execute_section_data)

        # save histroy of instrument for relocation
        self.instrumentHistoryMap = {}
        self.instrumentMap = {}
        self.overflowedInstrument = False
        self.overflowedInstrumentMap = {}

        self.instrument_log_file = open('c:\\work\\instrument.log', 'w')

    def writefile(self, filename):
        """
        write to file that has PE format.

        :param filename: Filename represent absolute filepath that include with filename
        :return:
            None
        """
        cumulative = 0
        sorted_instrument_map = sorted(self.instrumentHistoryMap.items(),
                                       key=operator.itemgetter(0))
        log = open("c:\\work\\instrumentmap.log", 'w')
        for address, size in sorted_instrument_map:
            cumulative += size
            log.write("[0x{:x}]\t{:x}\t{:d}\n".format(address, size, cumulative))
        self.peutil.setInstrumentor(self)
        self.adjustFileLayout()
        self.peutil.write(filename)

    def getInstrumentedMap(self):
        return self.instrumentHistoryMap

    def getInstructions(self):
        """get disassembled instructions.
        Instructions excluding data that exist in the text section.

        :return:
            list: tuple that contain instruction address, instruction
        """
        instructions = self.Disassembler.getDisassembleMap()
        relocation_map = self.peutil.getRelocationMap()
        sorted_relocation_map = sorted(relocation_map.items(),
                                       key=operator.itemgetter(0))
        for address, el in sorted_relocation_map:
            for size in xrange(4):
                relocation_address = address - 0x1000 + size
                if relocation_address in instructions:
                    print "Found : [RELOCA] 0x{:x} 0x{:x}\t[INS] {}".format(address, relocation_address, instructions[relocation_address])
                    del instructions[relocation_address]
        sorted_instructions = sorted(instructions.items(),
                                     key=operator.itemgetter(0))
        return sorted_instructions

    def instrumentRedirectControlflowInstruction(self, command, position=None):
        """instrument instruction when reached instruction that has control flow as redirect.

        :param command: A user-defined function that returns an instrument instruction.
        :param position: The position to be instrumented by the command.
        :return:
            None
        """
        instructionTypes = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']
        # instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH', 'FC_RET']
        instrumentTotalAmount = 0
        instructions = self.getInstructions()
        for address, inst in instructions:
            cf = inst.flowControl
            if cf in instructionTypes:
                if self.isRedirect(inst):
                    result = self.instrument(command, inst, instrumentTotalAmount)
                    instrumentTotalAmount += result

        print "INSTRUMENT TOTAL AMOUNT {:d}".format(instrumentTotalAmount)
        self.adjustInstrumentedLayout()

    def instrument(self, command, instruction, total_count=0):
        """
        The instrument passes the instruction to the user function.
        When the user function is finished and the instruction to be instrumented is returned,
        the instruction is inserted at the position of the current instruction.
        As a result, the position of the current instruction is pushed backward by the size of the inserted instruction.
        :param command: User function to return instruction to be instrumented
        :param instruction: Instruction to be passed to the user function.
        :param total_count: total count of instrumented
        :return:
            int : size of instrumented instructions.
        """

        instrument_size = 0
        instrument_inst, count = command(instruction)
        if count > 0:
            instrument_size = len(instrument_inst)
            # put instrument instruction to execute_section_data
            offset = instruction.address + total_count
            self.Disassembler.setInstructionAtOffset(offset, instrument_inst)
            self.instrumentMap[offset] = len(instrument_inst)
            self.instrument_log_file.write("[0x{:x}]\t{}\n".format(instruction.address, instruction))
        return instrument_size

    def getInstrumentedSize(self, inst):
        """
        Calculate the instrumented size from the current address to the branch target.

        :param inst: branch instruction that has relatively operand value
        :return:
            int : size of instrumented size.
        """
        inst_address = inst.address
        inst_destiny = inst.operands[0].value
        block_instrumented_size = 0
        if inst_address <= inst_destiny:
            sorted_instrument_map = sorted(self.instrumentMap.items(),
                                           key=operator.itemgetter(0))
            for instrument_address, instrument_size in sorted_instrument_map:
                if instrument_address > inst_destiny:
                    break
                if inst_address < instrument_address <= inst_destiny:
                    instrumented_size = instrument_size
                    block_instrumented_size += instrumented_size
                    inst_destiny += instrumented_size
        else:
            sorted_instrument_map = sorted(self.instrumentMap.items(),
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

    def adjustFileLayout(self):
        """
        adjust PE layout. keep order.
        must do adjust first, and section modificate after.
        :return:
        """
        self.adjustEntryPoint()
        if self.peutil.isRelocable():
            print "[=========== RELOCATION ADJUST =============]"
            self.adjustRelocation()
        self.adjustExecutableSection()
        self.peutil.adjustImport(self.getInstrumentSize())

    def adjustEntryPoint(self):
        entry_va = self.peutil.getEntryPointVA()
        instrument_size = self.getInstrumentSizeWithVector(entry_va - 0x1000)
        # instrument_size = self.get_instrument_size_until(entry_va)
        self.peutil.setEntryPoint(entry_va + instrument_size)

    def getInstrumentSizeUntil(self, va):
        sorted_instruction_map = sorted(self.instrumentHistoryMap.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            if address < va:
                instrumented_size += size
            else:
                break
        return instrumented_size

    def getInstrumentSizeFromUntilWithBase(self, base, until_va):
        va = until_va - base
        return self.getInstrumentSizeUntil(va)

    def getInstrumentSizeWithRange(self, start, end):
        sorted_instruction_map = sorted(self.instrumentHistoryMap.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            if address > end:
                break
            if start < address < end:
                instrumented_size += size
        return instrumented_size

    def getInstrumentSizeWithVector(self, va):
        sorted_instruction_map = sorted(self.instrumentHistoryMap.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            if address < va:
                instrumented_size += size
                va += size
            else:
                break
        return instrumented_size

    def getInstrumentSize(self):
        sorted_instruction_map = sorted(self.instrumentHistoryMap.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            instrumented_size += size
        return instrumented_size

    def adjustExecutableSection(self):
        execute_data = self.Disassembler.getCode()
        self.peutil.appendDataToExecution(execute_data)

    def adjustInstrumentedLayout(self):
        """
        Adjusts the binary layout that has changed due to the address
        and the relatively operand of the instruction being changed during
        the instrumenting.
        :return:
        """
        instructionsList = self.Disassembler.getDisassembleList()
        if not self.peutil.isRelocable():
            for inst_address, inst in instructionsList:
                if inst.flowControl in ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']:
                    self.adjustRelativeBranches(inst)
                else:
                    # Temporary, adjust reference of text-section.
                    self.adjustReferences(inst)
        else:
            for inst_address, inst in instructionsList:
                if inst.flowControl in ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']:
                    self.adjustRelativeBranches(inst)

        if self.overflowedInstrument:
            overflowed_inst_handled = self.handleOverflowInstrument()
            if overflowed_inst_handled:
                self.adjustInstrumentedLayout()

    def adjustRelativeBranches(self, inst):
        """
        adjust instruction's operand value.
        Because the instructions calculate the address to branch relatively from the current position,
        it is necessary to apply the offset value changed by the instrument.

        :param inst: branch instruction that has relatively operand value
        :return:
        """
        if not hasattr(self, 'adjust_log'):
            self.adjust_log = open('c:\\work\\adjust.log', 'w')

        log = []
        if not self.isRedirect(inst):
            total_instrumented_size = self.getInstrumentedSize(inst)
            # adjust operand value
            if total_instrumented_size > 0:
                log.append("[0x{:x}] {:s}\n".format(inst.address, inst))
                operand_size = inst.operands[0].size / 8
                instruction_size = inst.size - operand_size
                operand_start = inst.address + instruction_size
                operand_end = inst.address + inst.size
                operand_value = self.Disassembler.getDataFromOffsetWithFormat(operand_start, operand_end)
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
                    self.Disassembler.setDataAtOffsetWithFormat(operand_start, operand_end, adjusted_operand_value)
                except:
                    self.overflowedInstrument = True
                    self.overflowedInstrumentMap[inst.address] = (inst, adjusted_operand_value)
                    log.append("operand value size overflowed {:x}\n".format(operand_value))
        self.adjust_log.write(''.join(log))

    def adjustReferences(self, inst):
        """
        when PE file has no relocation section, we can not make perfect adjustments.
        need some guess of type for static value in code.
        :param inst: instruction to adjust.
        :return:
            None
        """
        operand_size = len(inst.operands)
        if operand_size > 0:
            target_operand_index = 0
            inst_size = 0
            for index in range(operand_size):
                if 0x401000 < inst.operands[index].value < 0x409110:
                    print "[{:x}]\t{:s}".format(inst.address, inst)
                    for i in range(index):
                        operand = inst.operands[i]
                        if operand.type == 'AbsoluteMemoryAddress':
                            # TODO : AbsoluteMemory
                            target_operand_index = 0
                        elif operand.type == 'Register':
                            # TODO : AbsoluteMemory
                            target_operand_index = 0
                        elif operand.type == 'AbsoluteMemory':
                            # TODO : AbsoluteMemory
                            if operand.base == None:
                                target_operand_index += 0
                            # dispSize / 8
                            target_operand_index += (operand.dispSize / 8)
                        # ex) MOV [EBX-0x30], 0x401032
                        elif operand.type == 'AbsoluteMemoryAddress':
                            # if base is None then index increase one cause that mean register
                            if operand.base == None:
                                target_operand_index += 0
                            # dispSize / 8
                            target_operand_index += (operand.dispSize / 8)
                        elif operand.type == 'FarMemory':
                            # TODO : FarMemory
                            target_operand_index = 0
                        inst_size = inst.size - target_operand_index - (inst.operands[index].size / 8)
                        print "0x{:x}".format(
                            self.Disassembler.getDataFromOffsetWithFormat(
                                inst.address + target_operand_index + inst_size,
                                inst.address + inst.size)
                        )

    def adjustRelocation(self):
        structures_relocation_block = {}
        structures_relocation_entries = {}
        log = open('c:\\work\\relocation_before.txt', 'w')
        overflow_log = open('c:\\work\\relocation_overflowed.txt', 'w')
        block_va = -1
        for entry in self.peutil.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if block_va > 0:
                    structures_relocation_entries[block_va].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                block_va = entry.VirtualAddress
                structures_relocation_block[block_va] = entry
                structures_relocation_entries[block_va] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"

        """
        TODO:
        #1
        If the virtual address of the relocation block exceeds the range of the text section,
        the virtual address of the relocation block is increased by the amount of movement of the section.
        If there is an entry that has moved to the next block due to the size instrumented
        in the previous relocation block, it must be processed.

        #2
        it can cause exception what address of next block is not exist.
        next block address is not sequential increase
        """
        sorted_relocation_block = sorted(structures_relocation_block.items(), key=operator.itemgetter(0))
        sections = self.peutil.getSectionHeaders()
        section_start = sections[1].VirtualAddress
        structures_relocation_block.clear()
        for index, (block_va, block) in enumerate(sorted_relocation_block):
            # first, adjust other block besides text section
            # The cause, relocation factor can be added to the next block.
            if block_va >= section_start:
                # 0x1000 mean increased size of section va.
                self.peutil.PE.__structures__[self.peutil.PE.__structures__.index(block)].VirtualAddress += 0x1000

        block_va = -1
        for entry in self.peutil.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if block_va > 0:
                    structures_relocation_entries[block_va].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                block_va = entry.VirtualAddress
                structures_relocation_block[block_va] = entry
                structures_relocation_entries[block_va] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"

        sorted_relocation_block = sorted(structures_relocation_block.items(), key=operator.itemgetter(0))
        for index, (block_va, block) in enumerate(sorted_relocation_block):
            log.write("{}\n".format(block))
            if block_va < section_start:
                for entry in structures_relocation_entries[block_va]:
                    log.write("{}\n".format(entry))
                    if entry.Data == 0:
                        continue
                    entry_rva = entry.Data & 0x0fff
                    entry_type = entry.Data & 0xf000
                    # 0x1000 mean virtual address of first section that text section.
                    entry_va = block_va + entry_rva
                    instrumented_size = self.getInstrumentSizeWithVector(entry_va - 0x1000)
                    entry_rva += instrumented_size

                    # move entry to appropriate block
                    if entry_rva >= 0x1000:
                        overflow_log.write("[0x{:x}]\t0x{:x}\n".format(block_va, entry_rva))
                        self.peutil.PE.__structures__.remove(entry)
                        self.peutil.PE.__structures__[self.peutil.PE.__structures__.index(block)].SizeOfBlock -= 2
                        appropriate_block_va = (entry_rva & 0xf000) + block_va
                        entry.Data = (entry_rva & 0xfff) + entry_type

                        # if appropriate block address is exist.
                        if appropriate_block_va in structures_relocation_block:
                            appropriate_block_index = \
                                self.peutil.PE.__structures__.index(structures_relocation_block[appropriate_block_va])
                        else:
                            # create new relocation block with appropriate_block_va
                            next_block_va, next_block = sorted_relocation_block[index+1]
                            next_block_index = self.peutil.PE.__structures__.index(next_block)
                            new_block = copy.deepcopy(next_block)
                            new_block.SizeOfBlock = 8
                            new_block.VirtualAddress = appropriate_block_va
                            appropriate_block_index = next_block_index-1
                            structures_relocation_block[appropriate_block_va] = new_block
                            self.peutil.PE.__structures__.insert(appropriate_block_index, new_block)
                        self.peutil.PE.__structures__[appropriate_block_index].SizeOfBlock += 2
                        self.peutil.PE.__structures__.insert(appropriate_block_index+1, entry)
                    else:
                        entry.Data = entry_rva + entry_type

        """
        structures has owned offset.
        so, if modify position or order of structures element then must fix offset of structures element.
        """
        log.close()
        log = open('c:\\work\\relocation_after.txt', 'w')
        file_offset = 0
        for entry in self.peutil.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                entry.set_file_offset(file_offset)
                file_offset += 2
                log.write("{}\tfileoffset:[0x{}]\n".format(entry, file_offset))
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                if file_offset == 0:
                    file_offset = entry.get_file_offset()
                entry.set_file_offset(file_offset)
                file_offset += 8
                log.write("{}\tfileoffset:[0x{}]\n".format(entry, file_offset))
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                log.write("{}\n".format(entry))

    def handleOverflowInstrument(self):
        """
        extend the size of the operand if exceed the range of operand values while instrument.
        :return:
            bool :
        """
        total_instrument_size = 0
        # self.instrument_map.clear()
        handled_overflowed_map = {}
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        index = 1
        sorted_instrument_map = sorted(self.overflowedInstrumentMap.items(),
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
                self.Disassembler.setInstructionAtOffset(inst_address, encoding)
                instrumented_size = len(encoding)
                print "writed : {:s}".format(binascii.hexlify(self.Disassembler.getDataAtOffset(inst_address, inst_address+inst.size)))
                # save increased opcode, operand size for adjust again
                increased_size = instrumented_size - inst.size
                handled_overflowed_map[inst_address] = increased_size
                total_instrument_size += increased_size
            except KsError as e:
                print("ERROR: %s" % e)

        if not self.instrumentHistoryMap:
            self.saveInstrumentHistory(self.instrumentMap, handled_overflowed_map)
        else:
            self.saveInstrumentHistory(self.instrumentHistoryMap, handled_overflowed_map)
        self.instrumentMap = handled_overflowed_map
        self.overflowedInstrument = False
        self.overflowedInstrumentMap.clear()
        return True

    def mergeAdjustMapWithPrev(self, prevAdjustMap, adjustMap):
        """Merging previous adjust map with later adjust map

        :param prevAdjustMap: dict: previous adjust map.
        :param adjustMap: dict: later adjust map.
        :return:
            dict : adjusted instrumented map.
        """
        adjusted_map = {}
        sortedPrevAdjustMap = sorted(prevAdjustMap.items(),
                                     key=operator.itemgetter(0))
        sortedAdjustMap = sorted(adjustMap.items(),
                                 key=operator.itemgetter(0))

        for instrumented_address, instrumented_size in sortedPrevAdjustMap:
            adjust_instrument_address = instrumented_address
            for overflowed_address, increased_size in sortedAdjustMap:
                if overflowed_address < instrumented_address:
                    adjust_instrument_address += increased_size
            adjusted_map[adjust_instrument_address] = instrumented_size

        for overflowed_address, increased_size in sortedAdjustMap:
            if increased_size > 0:
                adjusted_map[overflowed_address] = increased_size
        return adjusted_map

    def saveInstrumentHistory(self, instrumented_map, handled_overflowed_map):
        adjusted_map = self.mergeAdjustMapWithPrev(instrumented_map, handled_overflowed_map)
        # adjusted_map.update(handled_overflowed_map)
        self.instrumentHistoryMap = adjusted_map

    def isRedirect(self, inst):
        """
        Returns true or false if the branch type of the instruction is redirect.
        :param inst: instruction
        :return:
            bool : True or False
        """
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
