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

    def __init__(self, filename):
        self.peutil = PEUtil(filename)
        self.entryPointVA = self.peutil.getEntryPointVA()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)

        executeSection = self.peutil.getExecutableSection()
        executeSectionData = self.peutil.getSectionRawData(executeSection)
        self.Disassembler = Disassembler(executeSectionData)

        # save histroy of instrument for relocation
        self.instrumentHistoryMap = {}
        self.instrumentMap = {}
        self.overflowedInstrument = False
        self.overflowedInstrumentMap = {}
        self.log = None
        self.count4log = 1

    def writefile(self, filename):
        """
        write to file that has PE format.

        :param filename: Filename represent absolute filepath that include with filename
        :return:
            None
        """
        self.Disassembler.finish()
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
        relocation_map = self.peutil.getRelocationMap()
        sortedRelocationMap = sorted(relocation_map.items(), key=operator.itemgetter(0))
        instructions = self.Disassembler.getDisassembleMap()
        relocationList = []
        if len(self.instrumentHistoryMap) > 0:
            for index, (address, el) in enumerate(sortedRelocationMap):
                increasedSize = self.getInstrumentSizeWithVector(address - 0x1000)
                relocationList.append(address - 0x1000 + increasedSize)
        else:
            for index, (address, el) in enumerate(sortedRelocationMap):
                relocationList.append(address - 0x1000)

        for address in relocationList:
            for size in xrange(4):
                relocationAddress = address + size
                if relocationAddress in instructions:
                    del instructions[relocationAddress]
        sorted_instructions = sorted(instructions.items(), key=operator.itemgetter(0))
        return sorted_instructions

    def instrumentRedirectControlflowInstruction(self, command, position=None):
        """instrument instruction when reached instruction that has control flow as redirect.

        :param command: A user-defined function that returns an instrument instruction.
        :param position: The position to be instrumented by the command.
        :return:
            None
        """

        log = open('c:\\work\\' + str(self.count4log) + '_instrument.log', 'w')
        self.count4log += 1
        instrumentTotalAmount = 0
        instructions = self.getInstructions()
        for address, inst in instructions:
            try:
                if self.Disassembler.isIndirectBranch(inst):
                    log.write('[0x{:x}]\t[0x{:x}]\t{:s}\t{:s}\n'.format(inst.address - instrumentTotalAmount,
                                                                        inst.address, inst.mnemonic, inst.op_str))
                    result = self.instrument(command, inst, instrumentTotalAmount)
                    instrumentTotalAmount += result
            except:
                pass
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
            self.Disassembler.instrument(offset, instrument_inst)
            self.instrumentMap[offset] = len(instrument_inst)
            self.instrumentHistoryMap[offset] = len(instrument_inst)
        return instrument_size

    def getInstrumentedSize(self, instruction):
        """
        Calculate the instrumented size from the current address to the branch target.

        :param instruction: branch instruction that has relatively operand value
        :return:
            int : size of instrumented size.
        """
        instAddress = instruction.address
        instDestiny = instruction.operands[0].imm
        blockInstrumentSize = 0
        if instAddress <= instDestiny:
            sortedInstrumentMap = sorted(self.instrumentMap.items(),
                                         key=operator.itemgetter(0))
            for instrumentAddress, instrumentSize in sortedInstrumentMap:
                if instrumentAddress > instDestiny:
                    break
                if instAddress < instrumentAddress <= instDestiny:
                    instrumentedSize = instrumentSize
                    blockInstrumentSize += instrumentedSize
                    instDestiny += instrumentedSize
        else:
            sortedInstrumentMap = sorted(self.instrumentMap.items(),
                                         key=operator.itemgetter(0),
                                         reverse=True)
            for instrumentAddress, instrumentSize in sortedInstrumentMap:
                # instDestiny can be instrumented instruction.
                # cause subtract instrumentSize from instDestiny
                if instDestiny - instrumentSize <= instrumentAddress < instAddress:
                    if instrumentAddress < instDestiny - instrumentSize:
                        break
                    instrumentedSize = instrumentSize
                    blockInstrumentSize += instrumentedSize
                    instDestiny -= instrumentedSize
        return blockInstrumentSize

    def adjustFileLayout(self):
        """
        adjust PE layout. keep order.
        must do adjust first, and section modificate after.
        :return:
        """



    def getInstrumentSizeWithVector(self, va):
        sortedInstructionMap = sorted(self.instrumentHistoryMap.items(),
                                      key=operator.itemgetter(0))
        instrumentedSize = 0
        for address, size in sortedInstructionMap:
            if address < va:
                instrumentedSize += size
                va += size
            else:
                break
        return instrumentedSize

    def getInstrumentSize(self):
        sortedInstructionMap = sorted(self.instrumentHistoryMap.items(),
                                      key=operator.itemgetter(0))
        instrumentedSize = 0
        for address, size in sortedInstructionMap:
            instrumentedSize += size
        return instrumentedSize

    def getCode(self):
        return self.Disassembler.getCode()

    def adjustInstrumentedLayout(self):
        """
        Adjusts the binary layout that has changed due to the address
        and the relatively operand of the instruction being changed during
        the instrumenting.
        :return:
        """
        # instructions = self.Disassembler.getDisassembleList()
        instructions = self.getInstructions()
        if not self.peutil.isRelocable():
            print "Not Support PE without relocation, yet."
            exit()
        else:
            self.log = open('c:\\work\\' + str(self.count4log) + '_adjustDirectBranches.log', 'w')
            self.count4log += 1
            for instAddress, instruction in instructions:
                if self.Disassembler.isDirectBranch(instruction):
                    adjustedValue = self.adjustDirectBranches(instruction)
            self.log.flush()
            self.log.close()
        if self.overflowedInstrument:
            overflowedInstHandled = self.handleOverflowInstrument()
            if overflowedInstHandled:
                self.adjustInstrumentedLayout()
        elif not self.instrumentHistoryMap:
            self.instrumentHistoryMap = self.instrumentMap

    def adjustDirectBranches(self, instruction):
        """
        adjust instruction's operand value.
        Because the instructions calculate the address to branch relatively from the current position,
        it is necessary to apply the offset value changed by the instrument.

        :param instruction: branch instruction that has relatively operand value
        :return:
        """
        adjustedOperandValue = 0
        instrumentedSizeUntil = self.getInstrumentedSize(instruction)
        # adjust operand value
        if instrumentedSizeUntil > 0:
            operandSize = instruction.operands[0].size
            instructionSize = instruction.size
            if instructionSize == 2:
                operandStart = instruction.address + 1
                operandEnd = instruction.address + 2
            elif instructionSize == 6:
                operandStart = instruction.address + 2
                operandEnd = instruction.address + 6
            else:
                operandStart = instruction.address + instructionSize - operandSize
                operandEnd = instruction.address + instructionSize

            try:
                operandValue = self.Disassembler.getDataFromOffsetWithFormat(operandStart, operandEnd)
            except:
                print "[except]====================================================="
                print "[0x%08x]\t%s 0x%x\t\tINS:%d\tOPS:%d\tOPSTART:%x\tOPEND:%x\t%x" % (instruction.address,
                                                                                         instruction.mnemonic,
                                                                                         instruction.operands[0].imm,
                                                                                         instructionSize, operandSize,
                                                                                         operandStart, operandEnd,
                                                                                         operandValue)
                exit()
            if operandValue > 0:
                adjustedOperandValue = operandValue + instrumentedSizeUntil
            else:
                adjustedOperandValue = operandValue - instrumentedSizeUntil
            try:
                self.Disassembler.setDataAtOffsetWithFormat(operandStart, operandEnd, adjustedOperandValue)
                self.log.write("[0x{:04x}]\t{:s}\t{:s}\t{:x}\t{:x}\n".format(instruction.address, instruction.mnemonic,
                                                                             instruction.op_str, operandValue,
                                                                             adjustedOperandValue))
            except:
                self.overflowedInstrument = True
                self.overflowedInstrumentMap[instruction.address] = \
                    (instruction, (operandValue, adjustedOperandValue, instrumentedSizeUntil))
                self.log.write("\t[OVERFLOWED] [0x{:04x}]\t{:s}\t{:s}\t{:x}\t{:x}\n".format(instruction.address,
                                                                                            instruction.mnemonic,
                                                                                            instruction.op_str,
                                                                                            operandValue,
                                                                                            adjustedOperandValue))
        return adjustedOperandValue

    def handleOverflowInstrument(self):
        """
        extend the size of the operand if exceed the range of operand values while instrument.
        :return:
            bool :
        """
        log = open('c:\\work\\' + str(self.count4log) + '_handleOverflowInstrument.log', 'w')
        self.count4log += 1
        totalInstrumentSize = 0
        # self.instrument_map.clear()
        handledOverflowedMap = {}
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        sortedInstrumentMap = sorted(self.overflowedInstrumentMap.items(),
                                     key=operator.itemgetter(0))
        for index, (instAddress, (instruction, (operandValue, adjustedOperandValue, instrumentedSizeUntil))) \
                in enumerate(sortedInstrumentMap):
            instAddress += totalInstrumentSize
            print "[{}] overflowed instrument instruction : [0x{:x}] {:s}  {} ========[{}]==========> {}" \
                .format(index, instAddress, instruction.mnemonic, operandValue,
                        instrumentedSizeUntil, adjustedOperandValue)

            log.write("[0x{:x}] {:s} {}\t {} ========[{}]==========> {}\n".format(instruction.address,
                                                                                  instruction.mnemonic,
                                                                                  instruction.op_str,
                                                                                  operandValue,
                                                                                  instrumentedSizeUntil,
                                                                                  adjustedOperandValue))
            """
            The formula for determining the operand value of a branch instruction in x86:
            [Destination.Address - Instruction.Address - Instruction.size]

            in this case, the operand value overflowed while we adjust direct branches operands.
            that mean, 1 byte of operand size is too small for adjusted operand value.
            cause we expand operand size to 4byte.

            instruction size increase to 5byte or 6byte.
            according in formula of determining operand value, The keystone adjusts the operand value when it compiled.

            the keystone is based on the address at which the instruction ends,

            like this,
            ks.asm('jmp 140') = [233, 135, 0, 0, 0]

            but since the value we pass is based on the start address of the instruction,
            it corrects the value of operand in the case of a postive branch.

            In the case of a negative branch,
            the base address is the starting address of the instruction, so do not change it.
            """

            # adding 2 is to change the base of operand value to the start address of the instruction.
            code = "{:s} {}".format(instruction.mnemonic, adjustedOperandValue + 2)
            log.write("\t"+code+"\n")
            hexacode = binascii.hexlify(code).decode('hex')
            try:
                # Initialize engine in X86-32bit mode
                encoding, count = ks.asm(hexacode)
                instrumented_size = len(encoding)
                if instrumented_size == 5:
                    if adjustedOperandValue > 0:
                        encoding[1] += 4
                    else:
                        encoding[1] += 0
                elif instrumented_size == 6:
                    if adjustedOperandValue > 0:
                        encoding[1] += 4
                    else:
                        encoding[1] += 0
                else:
                    print "ERROR"

                # patch
                self.Disassembler.setInstructionAtOffset(instAddress, instAddress + instruction.size, encoding)
                # save increased opcode, operand size for adjust again
                increasedSize = instrumented_size - instruction.size
                handledOverflowedMap[instAddress] = increasedSize
                totalInstrumentSize += increasedSize
                log.write("\t\t{} : {:d}\n".format(encoding, increasedSize))
            except KsError as e:
                print("ERROR: %s" % e)

        if not self.instrumentHistoryMap:
            self.saveInstrumentHistory(self.instrumentMap, handledOverflowedMap)
        else:
            self.saveInstrumentHistory(self.instrumentHistoryMap, handledOverflowedMap)
        self.instrumentMap = handledOverflowedMap
        self.overflowedInstrument = False
        self.overflowedInstrumentMap.clear()

        log.flush()
        log.close()
        return True

    def mergeAdjustMapWithPrev(self, prevAdjustMap, adjustMap):
        """Merging previous adjust map with later adjust map

        :param prevAdjustMap: dict: previous adjust map.
        :param adjustMap: dict: later adjust map.
        :return:
            dict : adjusted instrumented map.
        """
        adjustedMap = {}
        sortedPrevAdjustMap = sorted(prevAdjustMap.items(),
                                     key=operator.itemgetter(0))
        sortedAdjustMap = sorted(adjustMap.items(),
                                 key=operator.itemgetter(0))

        for instrumentedAddress, instrumentedSize in sortedPrevAdjustMap:
            adjustInstrumentAddress = instrumentedAddress
            for overflowedAddress, increasedSize in sortedAdjustMap:
                if overflowedAddress < instrumentedAddress:
                    adjustInstrumentAddress += increasedSize
            adjustedMap[adjustInstrumentAddress] = instrumentedSize

        for overflowedAddress, increasedSize in sortedAdjustMap:
            if increasedSize > 0:
                adjustedMap[overflowedAddress] = increasedSize
        return adjustedMap

    def saveInstrumentHistory(self, instrumented_map, handledOverflowedMap):
        adjusted_map = self.mergeAdjustMapWithPrev(instrumented_map, handledOverflowedMap)
        # adjusted_map.update(handled_overflowed_map)
        self.instrumentHistoryMap = adjusted_map

