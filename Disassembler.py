#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Disassembler engine for disassemble and instrumentation base on Capstone
disassemble engine.

"""

__author__ = 'ParkHanbum'
__version__ = '2017.5.10'
__contact__ = 'kese111@gmail.com'

import struct
import binascii
import operator
import os
from capstone import *


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
        self.writeLog = open(os.path.join(os.getcwd(), "write.log"), 'w')

        # initiation disassembler
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self.disassembler.skipdata = True
        self.disassembler.detail = True

    def set_code(self, code):
        self.code = code
        self.disassemble()

    def get_code(self):
        return self.code

    def get_code_size(self):
        return len(self.code)

    def is_need_handle_code(self):
        return self._codeNeedHandled

    def need_handle_code(self):
        self._codeNeedHandled = False

    def code_handle(self):
        self._codeNeedHandled = True
        self.disassemble_dict_handle()

    def is_need_handle_disassemble_dict(self):
        return self._instructionsMapNeedHandled

    def need_handled_disassemble_dict(self):
        self._instructionsMapNeedHandled = False

    def disassemble_dict_handle(self):
        self._instructionsMapNeedHandled = True
        self.disassemble_list_handle()

    def is_need_handle_disassemble_list(self):
        return self._instructionsListNeedHandled

    def need_handle_disassemble_list(self):
        self._instructionsListNeedHandled = False

    def disassemble_list_handle(self):
        self._instructionsListNeedHandled = True

    def get_disassemble_dict(self):
        if self.is_need_handle_code():
            self.disassemble()
        return self.instructionsMap

    def get_disassemble_list(self):
        if self.is_need_handle_disassemble_list():
            disassembleMap = self.get_disassemble_dict()
            sorted_instructions = sorted(disassembleMap.items(),
                                         key=operator.itemgetter(0))
            self.instructionsList = sorted_instructions
        return self.instructionsList

    def get_dword_from_offset(self, offset, offset_end):
        return self.get_data_from_offset_with_format(offset, offset_end)

    def get_format_from_size(self, size):
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

    def get_format_from_size_little_endian(self, size):
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

    def get_data_from_offset_with_format(self, offset, offset_end):
        size = offset_end - offset
        return struct.unpack(self.get_format_from_size(size),
                             self.code[offset:offset_end])[0]

    def get_data_at_offset(self, offset, offset_end):
        return self.code[offset:offset_end]

    def disassemble(self):
        if not self.code:
            return 0
        self.instructionsMap.clear()
        del self.instructionsList[:]
        instructions = \
            self.disassembler.disasm(binascii.hexlify(self.code).decode('hex'),
                                     0x0)
        for instruction in instructions:
            self.instructionsMap[instruction.address] = instruction
        self.need_handle_code()
        self.need_handled_disassemble_dict()

    def instrument(self, offset, instrumented_instruction):
        self.writeLog.write(
            '[0] [0x{:05x}]\t{}\n'.format(offset, instrumented_instruction))
        self.code[offset:offset] = instrumented_instruction
        self.code_handle()

    def set_instruction_at_offset(self, offset, offset_end, instruction):
        self.writeLog.write(
            '[1] [0x{:05x}]\t{} \t{} \n'.format(offset,
                                                self.code[offset:offset_end],
                                                instruction))
        self.code[offset:offset_end] = instruction
        self.code_handle()

    def set_data_at_offset_with_format(self, offset, offset_end, data):
        size = offset_end - offset
        fmt = self.get_format_from_size(size)
        unpack_data = struct.unpack(fmt, self.code[offset:offset_end])
        self.writeLog.write('[2] [0x{:05x}]\t{} \t{} \n'.format(offset,
                                                                unpack_data,
                                                                data))
        self.code[offset:offset_end] = struct.pack(fmt, data)
        self.code_handle()

    def is_indirect_branch(self, instruction):
        """
        Check whether it is a indirect branch instruction.

        Args:
            instruction(instruction): instruction for check.
        Returns:
            bool : True if instruction is indirect branch, False otherwise.
        """
        if hasattr(instruction, "groups"):
            for group in instruction.groups:
                if group == CS_GRP_INDIRECT_BRANCH:
                    return True
        return False

    def is_direct_branch(self, instruction):
        """
        Check whether it is a direct branch instruction.

        Args:
            instruction(instruction): instruction for check.
        Returns:
            bool : True if instruction is direct branch, False otherwise.
        """
        if hasattr(instruction, "groups"):
            for group in instruction.groups:
                if group == CS_GRP_BRANCH:
                    return True
        return False

    def finish(self):
        self.writeLog.flush()
        self.writeLog.close()
