#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Disassembler engine for disassemble and instrumentation base on Capstone
disassemble engine.

"""


import binascii
import operator
import os
from capstone import *
from Log import LoggerFactory


class Disassembler(object):

    def __init__(self, _code_manager):
        self.code_manager = _code_manager
        self.instructions_dict = {}
        self.instructions_list = []
        self._code_need_handled = True
        self._instructions_list_need_handled = True
        self._instruction_dict_need_handled = True
        self.Logger = LoggerFactory()

        # initiation disassembler
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self.disassembler.skipdata = True
        self.disassembler.detail = True

    def __del__(self):
        pass

    def is_need_handle_disassemble_dict(self):
        return self._instruction_dict_need_handled

    def need_handled_disassemble_dict(self):
        self._instruction_dict_need_handled = False

    def disassemble_dict_handle(self):
        self._instruction_dict_need_handled = True
        self.disassemble_list_handle()

    def is_need_handle_disassemble_list(self):
        return self._instructions_list_need_handled

    def need_handle_disassemble_list(self):
        self._instructions_list_need_handled = False

    def disassemble_list_handle(self):
        self._instructions_list_need_handled = True

    def get_disassemble_dict(self):
        if self.code_manager.is_need_code_handle():
            self.disassemble()
        return self.instructions_dict

    def get_disassemble_list(self):
        if self.is_need_handle_disassemble_list():
            disassemble_dict = self.get_disassemble_dict()
            sorted_instructions = sorted(disassemble_dict.items(),
                                         key=operator.itemgetter(0))
            self.instructions_list = sorted_instructions
        return self.instructions_list

    def disassemble(self):
        if not self.code_manager:
            return 0
        self.instructions_dict.clear()
        del self.instructions_list[:]
        instructions = \
            self.disassembler.disasm(
                binascii.hexlify(self.code_manager.get_code()).decode('hex'),
                0x0
            )
        for instruction in instructions:
            self.instructions_dict[instruction.address] = instruction
        self.code_manager.code_handled()
        self.need_handled_disassemble_dict()

    @staticmethod
    def is_indirect_branch(instruction):
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

    @staticmethod
    def is_direct_branch(instruction):
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
