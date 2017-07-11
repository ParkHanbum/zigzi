#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
DIsassembler for disassemble base on disassembler engine distorm3
"""

__author__ = 'ParkHanbum'
__version__ = '2017.5.10'
__contact__ = 'kese111@gmail.com'

import struct
import binascii
import operator
import distorm3
import os
from capstone import *

# OPERAND TYPES
_OPERAND_NONE = ""
_OPERAND_IMMEDIATE = "Immediate"
_OPERAND_REGISTER = "Register"
# the operand is a memory address
_OPERAND_ABSOLUTE_ADDRESS = "AbsoluteMemoryAddress"  # The address calculated is absolute
_OPERAND_MEMORY = "AbsoluteMemory"  # The address calculated uses registers expression
_OPERAND_FAR_MEMORY = "FarMemory"  # like absolute but with selector/segment specified too


class Disassembler(object):

    def __init__(self, code):
        self.code = code
        self.dataChunkList = []
        self.instructionsMap = {}
        self.instructionsList = []
        self.instrumentMap = {}
        self._codeNeedHandled = True
        self._instructionsListNeedHandled = True
        self._instructionsMapNeedHandled = True
        self.writeLog = open(os.path.join(os.getcwd(), "writelog.txt"), 'w')

        # initiation disassembler
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self.disassembler.skipdata = True
        self.disassembler.detail = True

    def setCode(self, code):
        self.code = code
        self.disassemble()

    def getCode(self):
        return self.code

    def getCodeSize(self):
        return len(self.code)

    def isCodeNeedHandled(self):
        return self._codeNeedHandled

    def codeHandled(self):
        self._codeNeedHandled = False

    def codeNeedHandled(self):
        self._codeNeedHandled = True
        self.disassembleMapNeedHandled()

    def isDisassembleMapNeedHandled(self):
        return self._instructionsMapNeedHandled

    def disassembleMapHandled(self):
        self._instructionsMapNeedHandled = False

    def disassembleMapNeedHandled(self):
        self._instructionsMapNeedHandled = True
        self.disassembleListNeedHandled()

    def isDisassembleListNeedHandled(self):
        return self._instructionsListNeedHandled

    def disassembleListHandled(self):
        self._instructionsListNeedHandled = False

    def disassembleListNeedHandled(self):
        self._instructionsListNeedHandled = True

    def getDisassembleMap(self):
        if self.isCodeNeedHandled():
            self.disassemble()
        return self.instructionsMap

    def getDisassembleList(self):
        if self.isDisassembleListNeedHandled():
            disassembleMap = self.getDisassembleMap()
            sorted_instructions = sorted(disassembleMap.items(),
                                         key=operator.itemgetter(0))
            self.instructionsList = sorted_instructions
        return self.instructionsList

    def getDwordFromOffset(self, offset, offset_end):
        return self.getDataFromOffsetWithFormat(offset, offset_end)

    def getFormatFromSize(self, size):
        if size == 8:
            fmt = 'l'
        elif size == 4:
            fmt = 'i'
        elif size == 2:
            fmt = 'h'
        elif size == 1:
            fmt = 'b'
        else:
            print "ERROR"
            exit()
        return fmt

    def getFormatFromSizeLE(self, size):
        if size == 8:
            fmt = '<l'
        elif size == 4:
            fmt = '<i'
        elif size == 2:
            fmt = '<h'
        elif size == 1:
            fmt = '<b'
        else:
            print "ERROR"
            exit()
        return fmt

    def getDataFromOffsetWithFormat(self, offset, offset_end):
        size = offset_end - offset
        return struct.unpack(self.getFormatFromSize(size), self.code[offset:offset_end])[0]

    def getDataAtOffset(self, offset, offset_end):
        return self.code[offset:offset_end]

    def disassemble(self):
        if not self.code:
            return 0
        self.instructionsMap.clear()
        del self.instructionsList[:]
        instructions = self.disassembler.disasm(binascii.hexlify(self.code).decode('hex'), 0x0)
        for instruction in instructions:
            self.instructionsMap[instruction.address] = instruction
        self.codeHandled()
        self.disassembleMapHandled()

    def instrument(self, offset, instrumented_instruction):
        self.writeLog.write('[0] [0x{:05x}]\t{}\n'.format(offset, instrumented_instruction))
        self.code[offset:offset] = instrumented_instruction
        self.codeNeedHandled()

    def setInstructionAtOffset(self, offset, offset_end, instruction):
        self.writeLog.write('[1] [0x{:05x}]\t{} \t{} \n'.format(offset, self.code[offset:offset_end], instruction))
        self.code[offset:offset_end] = instruction
        self.codeNeedHandled()

    def setDataAtOffsetWithFormat(self, offset, offset_end, data):
        size = offset_end - offset
        fmt = self.getFormatFromSize(size)
        self.writeLog.write('[2] [0x{:05x}]\t{} \t{} \n'.format(offset,
                                                                struct.unpack(fmt, self.code[offset:offset_end]),
                                                                data))
        self.code[offset:offset_end] = struct.pack(fmt, data)
        self.codeNeedHandled()

    def setDataChunkList(self, chunkList):
        self.dataChunkList = chunkList

    def isIndirectBranch(self, instruction):
        if hasattr(instruction, "groups"):
            for group in instruction.groups:
                if group == CS_GRP_INDIRECT_BRANCH:
                    return True
        return False

    def isDirectBranch(self, instruction):
        if hasattr(instruction, "groups"):
            for group in instruction.groups:
                if group == CS_GRP_BRANCH:
                    return True
        return False

    def finish(self):
        self.writeLog.flush()
        self.writeLog.close()
