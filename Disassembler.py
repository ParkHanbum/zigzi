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
        self.instructions_map = {}
        self.instructions = []
        self.need_handle_disassemble_list_update = False
        self.need_handle_code_update = False
        self.disassemble()

    def code_updated(self):
        self.need_handle_code_update = True

    def is_code_updated(self):
        return self.need_handle_code_update

    def disassemble_list_updated(self):
        self.need_handle_disassemble_list_update = True

    def is_disassemble_list_changed(self):
        return self.need_handle_disassemble_list_update

    def disassemble(self):
        if not self.code:
            return 0
        del self.instructions[:]
        self.instructions = distorm3.Decompose(
            0x0,
            binascii.hexlify(self.code).decode('hex'),
            distorm3.Decode32Bits,
            distorm3.DF_NONE)
        for inst in self.instructions:
            self.instructions_map[inst.address] = inst
        self.disassemble_list_updated()

    def get_disassemble_map(self):
        if self.is_code_updated():
            self.disassemble()
            return self.instructions_map

    def get_disassemble_list(self):
        if self.is_disassemble_list_changed():
            inst_list = []
            sorted_inst_map = sorted(self.instructions_map.items(),
                                     key=operator.itemgetter(0))
            for (address, inst) in sorted_inst_map:
                inst_list.append(inst)
            self.instructions = inst_list
            return self.instructions
        else:
            return self.instructions

    def remove_analysis(self, va, size):
        for index in xrange(size):
            if (va + index) in self.instructions_map:
                del self.instructions_map[(va + index)]
                self.is_disassemble_list_changed()

    def set_code(self, code):
        self.code = code
        self.disassemble()

    def set_instruction_at_offset(self, offset, instrumented_instruction):
        self.code[offset:offset] = instrumented_instruction
        self.code_updated()

    def get_dword_from_offset(self, offset, offset_end):
        return self.get_data_from_offset(offset, offset_end)

    def get_fmt_from_size(self, size):
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

    def get_data_from_offset(self, offset, offset_end):
        size = offset_end - offset
        return struct.unpack(self.get_fmt_from_size(size), self.code[offset:offset_end])[0]

    def set_data_at_offset(self, offset, offset_end, data):
        size = offset_end - offset
        fmt = self.get_fmt_from_size(size)
        self.code[offset:offset_end] = struct.pack(fmt, data)

    def get_code(self):
        return self.code

    def get_code_size(self):
        return len(self.code)

    def get_sorted_disassemble_map(self):
        disassemble_map = self.get_disassemble_map()
        sorted_disassemble_map = sorted(disassemble_map.items(),
                                        key=operator.itemgetter(0))
        return sorted_disassemble_map

