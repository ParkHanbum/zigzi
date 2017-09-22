#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Disassembler engine for disassemble and instrumentation base on Capstone
disassemble engine.

"""


import struct
import os
from Log import LoggerFactory


class CodeManager(object):

    def __init__(self, code, rva):
        self.code = code
        self.rva = rva
        self.log = LoggerFactory().get_new_logger("Instrument.log")
        self._code_need_handled = True

    def __del__(self):
        self.log.fin()

    def get_base_rva(self):
        return self.rva

    def get_dword_from_offset(self, offset, offset_end):
        return self.get_data_from_offset_with_format(offset, offset_end)

    def get_data_from_offset_with_format(self, offset, offset_end):
        size = offset_end - offset
        return struct.unpack(self.get_format_from_size(size),
                             self.code[offset:offset_end])[0]

    def get_data_at_offset(self, offset, offset_end):
        return self.code[offset:offset_end]

    def instrument(self, offset, instrument_instruction):
        self.log.log(
            '[0] [0x{:05x}]\t{}\n'.format(offset, instrument_instruction))
        self.code[offset:offset] = instrument_instruction
        self.need_code_handle()

    def instrument_with_replace(self, offset, origin_instruction_size,
                                instrument_instruction):
        self.log.log(
            '[0] [0x{:05x}]\t{}\n'.format(offset, instrument_instruction))
        self.code[offset:origin_instruction_size] = instrument_instruction
        self.need_code_handle()

    def instrument_at_last(self, instrument_instruction):
        offset = len(self.code) - 1
        self.log.log("[LAST]")
        self.instrument(offset, instrument_instruction)
        return offset

    def set_instruction_at_offset(self, offset, offset_end, instruction):
        self.log.log(
            '[1] [0x{:05x}]\t{} \t{} \n'.format(offset,
                                                self.code[offset:offset_end],
                                                instruction))
        self.code[offset:offset_end] = instruction
        self.need_code_handle()

    def set_data_at_offset_with_format(self, offset, offset_end, data):
        size = offset_end - offset
        fmt = self.get_format_from_size(size)
        unpack_data = struct.unpack(fmt, self.code[offset:offset_end])
        self.log.log('[2] [0x{:05x}]\t{} \t{} \n'.format(offset,
                                                         unpack_data,
                                                         data))
        self.code[offset:offset_end] = struct.pack(fmt, data)
        self.need_code_handle()

    def get_code(self):
        return self.code

    def is_need_code_handle(self):
        return self._code_need_handled

    def code_handled(self):
        self._code_need_handled = False

    def need_code_handle(self):
        self._code_need_handled = True

    @staticmethod
    def get_format_from_size(size):
        if size == 8:
            fmt = 'q'
        elif size == 4:
            fmt = 'i'
        elif size == 2:
            fmt = 'h'
        elif size == 1:
            fmt = 'b'
        else:
            fmt = None
        return fmt

    @staticmethod
    def get_format_from_size_little_endian(size):
        if size == 8:
            fmt = '<l'
        elif size == 4:
            fmt = '<i'
        elif size == 2:
            fmt = '<h'
        elif size == 1:
            fmt = '<b'
        else:
            fmt = None
            print("ERROR")
            exit()
        return fmt

    def get_data_from_rva(self, rva, length):
        zero_relative_rva = rva - self.rva
        data = self.get_data_at_offset(zero_relative_rva,
                                       zero_relative_rva + length)
        return data

