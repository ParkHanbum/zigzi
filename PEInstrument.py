#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEInstrument
support instrumentation feature for window executable binary format(PE).
"""


from PEUtil import *
from keystone import *
from Disassembler import *


class PEInstrument(object):

    def __init__(self, filename):
        self.peutil = PEUtil(filename)
        self.entryPointVA = self.peutil.get_entry_point_rva()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)

        execute_section = self.peutil.get_text_section()
        execute_section_data = self.peutil.get_section_raw_data(execute_section)
        self.Disassembler = Disassembler(execute_section_data)

        # save histroy of instrument for relocation
        self.instrument_pos_dict = {}
        self.current_instrument_pos_dict = {}
        self.overflowed_instrument_dict = {}
        self.log = None
        self.count4log = 1
        # variable for handle overflow
        self.overflowed = False

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
        self.Disassembler.finish()
        self.peutil.set_instrumentor(self)
        self.peutil.write(filename)

    def get_instrumented_pos(self):
        return self.instrument_pos_dict

    def get_instructions(self):
        """
        get disassembled instructions. Instructions excluding data that
        exist in the text section.

        Returns:
            list: tuple that contain instruction address, instruction
        """
        relocation_dict = self.peutil.get_relocation()
        sorted_relocation = sorted(relocation_dict.items(),
                                   key=operator.itemgetter(0))
        instructions = self.Disassembler.get_disassemble_dict()
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

    def instrument_at_indirect_instruction(self, command, position=None):
        """
        instrument instruction when reached instruction that has control flow as
        redirect.

        Args:
            command(function)
                A user-defined function that returns an instrument instruction.
            position
                The position to be instrumented by the command.
        """
        log = open('c:\\work\\' + str(self.count4log) + '_instrument.log', 'w')
        self.count4log += 1
        instrument_total = 0
        instructions = self.get_instructions()
        for address, inst in instructions:
            try:
                if self.Disassembler.is_indirect_branch(inst):
                    log.write('[0x{:x}]\t[0x{:x}]\t{:s}\t{:s}\n'
                              .format(inst.address - instrument_total,
                                      inst.address, inst.mnemonic, inst.op_str))
                    result = self.instrument(command, inst,
                                             instrument_total)
                    instrument_total += result
            except:
                pass
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
            self.Disassembler.instrument(offset, instrument_inst)
            self.current_instrument_pos_dict[offset] = len(instrument_inst)
            self.instrument_pos_dict[offset] = len(instrument_inst)
        return instrument_size

    def get_instrumented_size(self, instruction):
        """
        Calculate the instrumented size from the current address to the branch
        target. use this when instrumented thing is applied to disassembled one.
        but if not applied instrumented thing,
        then use getInstrumentedSizeWithVector.

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

    def get_instrumented_vector_size(self, va):
        """
        Calculate the instrumented size until virtual address that argumented.
        if not applied instrumented thing, to disssembled one, use this.

        Args:
            va(int): virtual address for calculate on.

        Returns:
            int
                instrumented size until argument virtual address with
                increasing of instrumented size.
        """
        sorted_instrument = sorted(self.instrument_pos_dict.items(),
                                   key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instrument:
            if address < va:
                instrumented_size += size
                va += size
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
        return self.Disassembler.get_code()

    def adjust_instruction_layout(self):
        """
        Adjusts the binary layout that has changed due to the address
        and the relatively operand of the instruction being changed during
        the instrumenting.
        """
        # instructions = self.Disassembler.getDisassembleList()
        instructions = self.get_instructions()
        if not self.peutil.is_possible_relocation():
            print("Not Support PE without relocation, yet.")
            exit()
        else:
            self.log = open('c:\\work\\' + str(self.count4log) +
                            '_adjustDirectBranches.log', 'w')
            self.count4log += 1
            for instAddress, instruction in instructions:
                if self.Disassembler.is_direct_branch(instruction):
                    adjustedValue = self.adjust_direct_branches(instruction)
            self.log.flush()
            self.log.close()
        if self.is_instrument_overflow_occurred():
            overflowed_inst_handled = self.handle_overflowed_instrument()
            if overflowed_inst_handled:
                self.adjust_instruction_layout()
            else:
                print("ERROR WHILE HANDLE OVERFLOW")
                exit()
        elif not self.instrument_pos_dict:
            self.instrument_pos_dict = self.current_instrument_pos_dict

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

            try:
                operand_value = self.Disassembler \
                    .get_data_from_offset_with_format(operand_start,
                                                      operand_end)
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
                self.Disassembler \
                    .set_data_at_offset_with_format(operand_start,
                                                    operand_end,
                                                    adjusted_operand_value)
                self.log.write("[0x{:04x}]\t{:s}\t{:s}\t{:x}\t{:x}\n"
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
                self.log.write(
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
        log = open('c:\\work\\' + str(self.count4log)
                   + '_handleOverflowInstrument.log', 'w')
        self.count4log += 1
        total_instrument_size = 0
        # self.instrument_map.clear()
        handled_overflowed_pos_dict = {}
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
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

            log.write("[0x{:x}] {:s} {}\t {} ========[{}]==========> {}\n"
                      .format(instruction.address, instruction.mnemonic,
                              instruction.op_str, operand_value,
                              instrumented_size_till, adjusted_operand_value))
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
            log.write("\t"+code+"\n")
            hex_code = binascii.hexlify(code).decode('hex')
            try:
                # Initialize engine in X86-32bit mode
                encoding, count = ks.asm(hex_code)
                instrumented_size = len(encoding)
                if instrumented_size == 5:
                    if adjusted_operand_value > 0:
                        encoding[1] += 4
                    else:
                        encoding[1] += 0
                elif instrumented_size == 6:
                    if adjusted_operand_value > 0:
                        encoding[1] += 4
                    else:
                        encoding[1] += 0
                else:
                    print("ERROR")

                # patch
                self.Disassembler.set_instruction_at_offset(instruction_address,
                                                            instruction_address
                                                            + instruction.size,
                                                            encoding)
                # save increased opcode, operand size for adjust again
                increased_size = instrumented_size - instruction.size
                handled_overflowed_pos_dict[instruction_address] \
                    = increased_size
                total_instrument_size += increased_size
                log.write("\t\t{} : {:d}\n".format(encoding, increased_size))
            except KsError as ex:
                print("ERROR: %s" % ex)

        if not self.instrument_pos_dict:
            self.save_instrument_history(self.current_instrument_pos_dict,
                                         handled_overflowed_pos_dict)
        else:
            self.save_instrument_history(self.instrument_pos_dict,
                                         handled_overflowed_pos_dict)
        self.current_instrument_pos_dict = handled_overflowed_pos_dict
        self.overflowed_instrument_dict.clear()
        self.instrument_overflow_handled()
        log.flush()
        log.close()
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
        adjusted_dict = {}
        sorted_prev_adjust_dict = sorted(prev_adjust_dict.items(),
                                         key=operator.itemgetter(0))
        sorted_adjust_dict = sorted(adjust_dict.items(),
                                    key=operator.itemgetter(0))

        for instrumentedAddress, instrumentedSize in sorted_prev_adjust_dict:
            adjust_instrument_address = instrumentedAddress
            for overflowedAddress, increasedSize in sorted_adjust_dict:
                if overflowedAddress < instrumentedAddress:
                    adjust_instrument_address += increasedSize
            adjusted_dict[adjust_instrument_address] = instrumentedSize

        for overflowedAddress, increasedSize in sorted_adjust_dict:
            if increasedSize > 0:
                adjusted_dict[overflowedAddress] = increasedSize
        return adjusted_dict

    def save_instrument_history(self, instrumented_pos_dict,
                                handled_overflowed_pos_dict):
        adjusted_dict = \
            self.merge_adjust_pos_with_prev(instrumented_pos_dict,
                                            handled_overflowed_pos_dict)
        self.instrument_pos_dict = adjusted_dict
