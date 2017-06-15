#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEInstrument
support instrumentation feature for window executable binary format(PE).
"""


from PEManager import *
from keystone import *
from Disassembler import *
from CodeManager import *
import DataSegment
from Log import LoggerFactory


class PEInstrument(object):

    def __init__(self, pe_manager):
        if not isinstance(pe_manager, PEManager):
            print("YOU MUST set up PE Manager")
            exit()
        self.pe_manager = pe_manager
        self.pe_manager.set_instrument(self)
        self.entryPointVA = self.pe_manager.get_entry_point_rva()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

        execute_section = self.pe_manager.get_text_section()
        execute_section_data = \
            self.pe_manager.get_section_raw_data(execute_section)
        self.code_manager = CodeManager(execute_section_data,
                                        execute_section.VirtualAddress)
        self.disassembler = Disassembler(self.code_manager)

        # save history of instrument for relocation
        self.instrument_pos_dict = {}
        self.current_instrument_pos_dict = {}
        self.overflowed_instrument_dict = {}
        self.log = None
        # variable for handle overflow
        self.overflowed = False

    @classmethod
    def from_filename(cls, filename):
        pe_util = PEManager(filename)
        return cls(pe_util)

    def get_peutil(self):
        return self.pe_manager

    def is_instrument_overflow_occurred(self):
        return self.overflowed

    def instrument_overflow_handled(self):
        self.overflowed = False

    def instrument_overflow_occurred(self):
        self.overflowed = True

    def writefile(self, filename):
        """
        write to file that has PE format.

        Args:
            filename(str)
                Filename represent absolute filepath that include with filename
        """
        self.pe_manager.writefile(filename)

    def get_instrumented_pos(self):
        return self.instrument_pos_dict

    def get_instructions(self):
        """
        get disassembled instructions. Instructions excluding data that
        exist in the text section.

        Returns:
            list: tuple that contain instruction address, instruction
        """
        relocation_dict = self.pe_manager.get_relocation()
        sorted_relocation = sorted(relocation_dict.items(),
                                   key=operator.itemgetter(0))
        instructions = self.disassembler.get_disassemble_dict()
        relocation_list = []
        if len(self.instrument_pos_dict) > 0:
            for index, (address, el) in enumerate(sorted_relocation):
                increased_size = self.get_instrumented_vector_size(address
                                                                   - 0x1000)
                relocation_list.append(address - 0x1000 + increased_size)
        else:
            for index, (address, el) in enumerate(sorted_relocation):
                relocation_list.append(address - 0x1000)

        for address in relocation_list:
            for size in range(4):
                relocation_address_range = address + size
                if relocation_address_range in instructions:
                    del instructions[relocation_address_range]
        sorted_instructions = sorted(instructions.items(),
                                     key=operator.itemgetter(0))
        return sorted_instructions

    def instrument_pre_indirect_branch(self, command, position=None):
        """
        instrument instruction when reached instruction that has control flow as
        redirect.

        Args:
            command(function)
                A user-defined function that returns an instrument instruction.
            position
                The position to be instrumented by the command.
        """
        self.log = LoggerFactory().get_new_logger("Instrument.log")
        instrument_total = 0
        instructions = self.get_instructions()
        for address, inst in instructions:
            try:
                if self.disassembler.is_indirect_branch(inst):
                    self.log.log('[0x{:x}]\t[0x{:x}]\t{:s}\t{:s}\n'
                                 .format(inst.address + instrument_total,
                                         inst.address, inst.mnemonic,
                                         inst.op_str))
                    result = self.instrument(command, inst, instrument_total)
                    instrument_total += result
            except:
                print("ERROR WHILE INSTRUMENT")
                exit()
        self.adjust_instruction_layout()

    def instrument(self, command, instruction, total_count=0):
        """
        The instrument passes the instruction to the user function. When
        the user function is finished and the instruction to be instrumented
        is returned, the instruction is inserted at the position of the current
        instruction. As a result, the position of the current instruction is
        pushed backward by the size of the inserted instruction.

        Args:
            command(function)
                User function to return instruction to be instrumented
            instruction(instruction)
                Instruction to be passed to the user function.
            total_count(int)
                total count of instrumented
        Returns:
            int : size of instrumented instructions.
        """
        instrument_size = 0
        instrument_inst, count = command(instruction)
        if count > 0:
            instrument_size = len(instrument_inst)
            # put instrument instruction to execute_section_data
            offset = instruction.address + total_count
            self.code_manager.instrument(offset, instrument_inst)
            self.current_instrument_pos_dict[offset] = len(instrument_inst)
            self.instrument_pos_dict[offset] = len(instrument_inst)
        return instrument_size

    def get_instrumented_size(self, instruction):
        """
        Calculate the instrumented size from the current address to the branch
        target. use this when instrumented thing is applied to disassembled one.
        but if not applied instrumented thing, then use method the
        get_instrumented_size_with_vector.

        Args:
            instruction(instrution):
                branch instruction that has relatively operand value
        Returns:
            int : size of instrumented until instruction's address.
        """
        instruction_address = instruction.address
        instruction_destiny = instruction.operands[0].imm
        instrument_size_till_destiny = 0
        if instruction_address <= instruction_destiny:
            sorted_instrument = sorted(self.current_instrument_pos_dict.items(),
                                       key=operator.itemgetter(0))
            for instrument_address, instrument_size in sorted_instrument:
                if instrument_address > instruction_destiny:
                    break
                if (instruction_address
                        < instrument_address <= instruction_destiny):
                    instrumented_size = instrument_size
                    instrument_size_till_destiny += instrumented_size
                    instruction_destiny += instrumented_size
        else:
            sorted_instrument = sorted(self.current_instrument_pos_dict.items(),
                                       key=operator.itemgetter(0),
                                       reverse=True)
            for instrument_address, instrument_size in sorted_instrument:
                # instruction_destiny can be instrumented instruction.
                # cause subtract instrument_size from instruction_destiny
                if (instruction_destiny - instrument_size
                        <= instrument_address < instruction_address):
                    if instrument_address \
                            < instruction_destiny - instrument_size:
                        break
                    instrumented_size = instrument_size
                    instrument_size_till_destiny += instrumented_size
                    instruction_destiny -= instrumented_size
        return instrument_size_till_destiny

    def get_instrumented_vector_size(self, rva, instrument_pos_dict=None):
        """
        Calculate the instrumented size until virtual address that argumented.
        if not applied instrumented thing, to disssembled one, use this.

        Args:
            rva(int): virtual address for calculate on.
            instrument_pos_dict(dict) : dict contains instruments position.
        Returns:
            int
                instrumented size until argument virtual address with
                increasing of instrumented size.
        """
        if instrument_pos_dict is None:
            instrument_pos_dict = self.instrument_pos_dict
        sorted_instrument = sorted(instrument_pos_dict.items(),
                                   key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instrument:
            if address <= rva:
                instrumented_size += size
                rva += size
            else:
                break
        return instrumented_size

    def get_instrumented_total_size(self):
        """
        Total size of instrument.

        Returns:
            int
        """
        sorted_instrument = sorted(self.instrument_pos_dict.items(),
                                   key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instrument:
            instrumented_size += size
        return instrumented_size

    def get_code(self):
        """
        get codes that working on.

        Returns:
            bytearray : text section's data.
        """
        return self.code_manager.get_code()

    def adjust_instruction_layout(self):
        """
        Adjusts the binary layout that has changed due to the address
        and the relatively operand of the instruction being changed during
        the instrumenting.
        """
        # instructions = self.Disassembler.getDisassembleList()
        instructions = self.get_instructions()
        if not self.pe_manager.is_possible_relocation():
            print("Not Support PE without relocation, yet.")
            exit()
        else:
            self.log = \
                LoggerFactory().get_new_logger("AdjustDirectBranches.log")
            for instAddress, instruction in instructions:
                if self.disassembler.is_direct_branch(instruction):
                    self.adjust_direct_branches(instruction)
            self.log.fin()
        if self.is_instrument_overflow_occurred():
            overflowed_inst_handled = self.handle_overflowed_instrument()
            if overflowed_inst_handled:
                self.adjust_instruction_layout()
            else:
                print("ERROR WHILE HANDLE OVERFLOW")
                exit()

    def adjust_direct_branches(self, instruction):
        """
        adjust instruction's operand value. Because the instructions calculate
        the address to branch relatively from the current position, it is
        necessary to apply the offset value changed by the instrument.

        Args:
            instruction(instruction):
                branch instruction that has relatively operand value
        """
        operand_value = 0
        adjusted_operand_value = 0
        instrumented_size_till = self.get_instrumented_size(instruction)
        # adjust operand value
        if instrumented_size_till > 0:
            operand_size = instruction.operands[0].size
            instruction_size = instruction.size
            if instruction_size == 2:
                operand_start = instruction.address + 1
                operand_end = instruction.address + 2
            elif instruction_size == 6:
                operand_start = instruction.address + 2
                operand_end = instruction.address + 6
            else:
                operand_start = instruction.address + instruction_size \
                                - operand_size
                operand_end = instruction.address + instruction_size

            self.log.log("[{:d}]\t".format(instruction_size))
            try:
                operand_value = \
                    self.code_manager.get_data_from_offset_with_format(
                        operand_start,
                        operand_end
                    )
            except:
                print ("[except]============================================")
                print ("[0x%08x]\t%s 0x%x\t\tINS:%d\tOPS:%d\tOP START:%x\t"
                       "OP END:%x".format(instruction.address,
                                          instruction.mnemonic,
                                          instruction.operands[0].imm,
                                          instruction_size, operand_size,
                                          operand_start, operand_end,
                                          operand_value
                                          )
                       )
                exit()
            if operand_value > 0:
                adjusted_operand_value = operand_value + instrumented_size_till
            else:
                adjusted_operand_value = operand_value - instrumented_size_till
            try:
                self.code_manager.set_data_at_offset_with_format(
                    operand_start,
                    operand_end,
                    adjusted_operand_value
                )

                set_value = \
                    self.code_manager.get_data_from_offset_with_format(
                        operand_start,
                        operand_end
                    )

                if adjusted_operand_value != set_value:
                    print("ERROR WHILE ADJUST DIRECT BRANCH")
                    exit()
                self.log.log("[0x{:04x}]\t{:s}\t{:s}\t{:x}\t{:x}\n"
                             .format(instruction.address,
                                     instruction.mnemonic,
                                     instruction.op_str, operand_value,
                                     adjusted_operand_value))
            except:
                self.instrument_overflow_occurred()
                self.overflowed_instrument_dict[instruction.address] = \
                    (instruction,
                     (operand_value, adjusted_operand_value,
                      instrumented_size_till)
                     )
                self.log.log(
                    "\t[OVERFLOWED] [0x{:04x}]\t{:s}\t{:s}\t{:x}\t{:x}\n"
                        .format(instruction.address, instruction.mnemonic,
                                instruction.op_str, operand_value,
                                adjusted_operand_value))
        return adjusted_operand_value

    def handle_overflowed_instrument(self):
        """
        extend the size of the operand if exceed the range of operand values
        while instrument.

        Returns:
            bool
        """
        self.log = \
            LoggerFactory().get_new_logger("HandleOverflowInstrument.log")
        total_instrument_size = 0
        # self.instrument_map.clear()
        handled_overflowed_pos_dict = {}
        sorted_instrument = sorted(self.overflowed_instrument_dict.items(),
                                   key=operator.itemgetter(0))
        for index, \
            (instruction_address,
             (instruction,
              (operand_value, adjusted_operand_value, instrumented_size_till)
              )
             ) in enumerate(sorted_instrument):
            instruction_address += total_instrument_size
            print ("[{}] overflowed instrument instruction : [0x{:x}] {:s}  "
                   "{} ========[{}]==========> {}"
                   .format(index, instruction_address, instruction.mnemonic,
                           operand_value, instrumented_size_till,
                           adjusted_operand_value))

            self.log.log("[0x{:x}] {:s} {}\t {} ========[{}]==========> {}\n"
                         .format(instruction.address, instruction.mnemonic,
                                 instruction.op_str, operand_value,
                                 instrumented_size_till,
                                 adjusted_operand_value))
            """
            The formula for determining the operand value of a branch
            instruction in x86:
            [Destination.Address - Instruction.Address - Instruction.size]

            in this case, the operand value overflowed while we adjust direct
            branches operands. that mean, 1 byte of operand size is too small
            for adjusted operand value. cause we expand operand size to 4byte.

            instruction size increase to 5byte or 6byte. according in formula of
            determining operand value, The keystone adjusts the operand value
            when it compiled.

            the keystone is based on the address at which the instruction ends,

            like this,
            ks.asm('jmp 140') = [233, 135, 0, 0, 0]

            but since the value we pass is based on the start address of the
            instruction, it corrects the value of operand in the case of a
            postive branch.

            In the case of a negative branch, the base address is the starting
            address of the instruction, so do not change it.
            """

            # adding 2 is to change the base of operand value to the
            # start address of the instruction.
            code = "{:s} {}".format(instruction.mnemonic,
                                    adjusted_operand_value + 2)

            hex_code = binascii.hexlify(code).decode('hex')

            try:
                encoding, count = self.ks.asm(hex_code)
                for inst in self.cs.disasm(bytearray(encoding),
                                           instruction_address):
                    self.log.log("\t" + code + "\t"
                                 + inst.mnemonic + " "
                                 + inst.op_str + "\n")
                instrumented_size = len(encoding)
                if instrumented_size == 5:
                    if adjusted_operand_value > 0:
                        encoding[1] += 3
                    else:
                        encoding[1] += 0
                elif instrumented_size == 6:
                    if adjusted_operand_value > 0:
                        encoding[2] += 4
                    else:
                        encoding[2] += 0
                else:
                    print("ERROR")

                # patch
                self.code_manager.set_instruction_at_offset(instruction_address,
                                                            instruction_address
                                                            + instruction.size,
                                                            encoding)
                # save increased opcode, operand size for adjust again
                increased_size = instrumented_size - instruction.size
                handled_overflowed_pos_dict[instruction_address] \
                    = increased_size
                total_instrument_size += increased_size
                self.log.log("\t\t{} : {:d}\n".format(encoding,
                                                      increased_size))
            except KsError as ex:
                print("ERROR: %s" % ex)
                exit()

        self.save_instrument_history(self.instrument_pos_dict,
                                     handled_overflowed_pos_dict)
        self.current_instrument_pos_dict = handled_overflowed_pos_dict
        self.overflowed_instrument_dict.clear()
        self.instrument_overflow_handled()
        self.log.fin()
        return True

    def merge_adjust_pos_with_prev(self, prev_adjust_dict, adjust_dict):
        """
        Merging previous adjust map with later adjust map

        Args:
            prev_adjust_dict(dict): previous adjust map.
            adjust_dict(dict): later adjust map.

        Returns:
            dict : adjusted instrumented map.
        """
        self.log = LoggerFactory().get_new_logger("AdjustingMerge.log")
        adjusted_dict = {}
        sorted_prev_adjust_dict = sorted(prev_adjust_dict.items(),
                                         key=operator.itemgetter(0))
        sorted_adjust_dict = sorted(adjust_dict.items(),
                                    key=operator.itemgetter(0))

        adjust_dict_index = 0
        current_total_increased_size = 0
        next_total_increased_size = 0
        next_adjust_address, next_increased_size = \
            sorted_adjust_dict[adjust_dict_index]
        next_total_increased_size += next_increased_size
        total_instrument_size = 0
        for instrumented_address, instrumented_size in sorted_prev_adjust_dict:
            adjust_instrument_address = instrumented_address
            adjust_instrument_address += current_total_increased_size
            while adjust_instrument_address > next_adjust_address \
                    and len(sorted_adjust_dict) > adjust_dict_index:
                # save current persistent
                current_adjust_address = next_adjust_address
                current_increased_size = next_increased_size
                current_total_increased_size = next_total_increased_size

                adjust_dict_index += 1
                if len(sorted_adjust_dict) > adjust_dict_index:
                    # load next persistent
                    next_adjust_address, next_increased_size = \
                        sorted_adjust_dict[adjust_dict_index]
                    if current_adjust_address in adjusted_dict:
                        self.log.log("[OVERLAPPING]\t")
                    adjust_instrument_address += next_increased_size
                    next_total_increased_size += next_increased_size
                else:
                    print("TEST")

                # append instrument address by overflow
                adjusted_dict[current_adjust_address] = current_increased_size
                self.log.log("[0x{:x}]\t{:d}\t==[OVERFLOW]==>\t{:d}"
                             "\t{:d}\t[0x{:x}]\n"
                             .format(current_adjust_address,
                                     current_increased_size,
                                     current_total_increased_size,
                                     next_total_increased_size,
                                     next_adjust_address))

            self.log.log("[0x{:x}] + {:d} = [0x{:x}] + {:d} = [0x{:x}]\n"
                         .format(instrumented_address - total_instrument_size,
                                 total_instrument_size,
                                 instrumented_address,
                                 current_total_increased_size,
                                 adjust_instrument_address
                                 ))
            total_instrument_size += instrumented_size
            adjusted_dict[adjust_instrument_address] = instrumented_size
        return adjusted_dict

    def save_instrument_history(self, instrumented_pos_dict,
                                handled_overflowed_pos_dict):
        adjusted_dict = \
            self.merge_adjust_pos_with_prev(instrumented_pos_dict,
                                            handled_overflowed_pos_dict)
        self.instrument_pos_dict = adjusted_dict

    def append_code(self, _code):
        """
        append code to last of code section.

        Args:
            _code(str) : assembly code that append to last of code section.

        Returns:
            rva(int) : relative address of code that appended
        """
        _pad_size = 3
        pad = ";nop;" * _pad_size
        code = pad + _code + pad
        encoding, count = self.ks.asm(code)
        code_offset = self.code_manager.instrument_at_last(encoding)
        code_rva = self.code_manager.get_base_rva() + code_offset + _pad_size
        return code_rva

    def falloc(self, size):
        """
        get allocated memory space from data segment.

        Args:
            size(int): size of space that allocate.

        Returns:
            DataSegment(DataSegment): DataSegment that represent for allocation.
        """
        data_chunk = DataSegment.Chunk(self.pe_manager, size)
        return data_chunk
