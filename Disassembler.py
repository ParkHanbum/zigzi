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
        self.instructionsMap = {}
        self.instructionsList = []
        self._codeNeedHandled = True
        self._instructionsListNeedHandled = True
        self._instructionsMapNeedHandled = True
        self.disassemble()

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
        instructionsList = distorm3.Decompose(
            0x0,
            binascii.hexlify(self.code).decode('hex'),
            distorm3.Decode32Bits,
            distorm3.DF_NONE)
        for inst in instructionsList:
            self.instructionsMap[inst.address] = inst
        self.codeHandled()
        self.disassembleMapHandled()

    def removeDisassembleElementByRange(self, start, range):
        for position in xrange(range):
            if (start + position) in self.instructionsMap:
                del self.instructionsMap[(start + position)]
                self.disassembleListNeedHandled()

    def setInstructionAtOffset(self, offset, instrumented_instruction):
        self.code[offset:offset] = instrumented_instruction
        self.codeNeedHandled()

    def setDataAtOffset(self, offset, offset_end, instruction):
        self.code[offset:offset_end] = instruction
        self.codeNeedHandled()

    def setDataAtOffsetWithFormat(self, offset, offset_end, data):
        size = offset_end - offset
        fmt = self.getFormatFromSizeLE(size)
        self.code[offset:offset_end] = struct.pack(fmt, data)
        self.codeNeedHandled()
