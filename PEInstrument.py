import struct
import binascii
import distorm3
import operator
from PEUtil import *
from keystone import *
import os.path


class PEInstrument(object):
    _INSTRUMENT_BEFORE = 1
    _INSTRUMENT_AFTER = 2

    def __init__(self, filename):
        self.peutil = PEUtil(filename)
        execute_section = self.peutil.get_executable_section()
        execute_section_data = self.peutil.get_section_raw_data(execute_section)
        self.entry_point_va = self.peutil.get_entry_point_va()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.execute_data = execute_section_data
        self.instruction_map = {}

        # save histroy of instrument for relocation
        self.instrument_history_map = {}
        self.instrument_map = {}
        self.disassembly = []
        self.disassemble()
        self.overflowed_instrument = False
        self.overflowed_instrument_map = {}


    def writefile(self, filename):
        """
        write to file that has PE format.

        :param filename: Filename represent absolute filepath that include with filename
        :return:
        """
        self.peutil.set_instrumentor(self)
        self.adjust_PE_layout()
        self.peutil.write(filename)

    def disassemble(self):
        """
        disassemble binary and mapping disassembled data. after clearing previous data.
        :return:
        """
        del self.disassembly[:]
        self.disassembly = distorm3.Decompose(
            0x0,
            binascii.hexlify(self.execute_data).decode('hex'),
            distorm3.Decode32Bits,
            distorm3.DF_NONE)
        self.instruction_map.clear()
        for inst in self.disassembly:
            self.instruction_map[inst.address] = inst

    def getdata(self):
        return self.execute_data

    def get_instrumented_map(self):
        return self.instrument_map

    def instrument_redirect_controlflow_instruction(self, command, position=None):
        instructionTypes = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']
        # instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH', 'FC_RET']
        instrumentTotalAmount = 0
        for inst in self.disassembly:
            cf = inst.flowControl
            if cf in instructionTypes:
                if self.isredirect(inst):
                    result = self.instrument(command, inst, instrumentTotalAmount)
                    instrumentTotalAmount += result

        print "INSTRUMENT TOTAL AMOUNT {:d}".format(instrumentTotalAmount)
        self.disassemble()
        self.adjust_instrumented_layout()

    def instrument_by_mnemonics(self, command, mnemonics=[], position=None):
        instrumentTotalAmount = 0
        if not mnemonics:
            print "Mnemonic is empty\n"
            return

        for inst in self.disassembly:
            if inst.mnemonic in mnemonics:
                result = self.instrument(command, inst, instrumentTotalAmount)
                instrumentTotalAmount += result
        print "INSTRUMENT TOTAL AMOUNT {:d}".format(instrumentTotalAmount)
        self.disassemble()

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
        """
        instrument_size = 0
        instrument_inst, count = command(instruction)
        if count > 0:
            instrument_size = len(instrument_inst)
            # put instrument instruction to execute_section_data
            offset = instruction.address + total_count
            self.execute_data[offset:offset] = instrument_inst
            self.instrument_map[offset] = len(instrument_inst)
        return instrument_size

    def get_instrumented_size(self, inst):
        """
        Calculate the instrumented size from the current address to the branch target.

        :param inst: branch instruction that has relatively operand value
        :return:
        """
        inst_address = inst.address
        inst_destiny = inst.operands[0].value
        block_instrumented_size = 0
        if inst_address <= inst_destiny:
            sorted_instrument_map = sorted(self.instrument_map.items(),
                                           key=operator.itemgetter(0))
            for instrument_address, instrument_size in sorted_instrument_map:
                if instrument_address > inst_destiny:
                    break
                if inst_address < instrument_address <= inst_destiny:
                    instrumented_size = instrument_size
                    block_instrumented_size += instrumented_size
                    inst_destiny += instrumented_size
        else:
            sorted_instrument_map = sorted(self.instrument_map.items(),
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

    def adjust_PE_layout(self):
        """
        adjust PE layout. keep order.
        must do adjust first, and section modificate after.
        :return:
        """
        self.adjust_entry_point()
        if self.peutil.isrelocable():
            self.adjust_relocation()
        self.adjust_executable_section()
        self.peutil.adjust_import(self.get_instrument_size())

    def adjust_entry_point(self):
        entry_va = self.peutil.get_entry_point_va()
        instrument_size = self.get_instrument_size_with_vector(entry_va - 0x1000)
        # instrument_size = self.get_instrument_size_until(entry_va)
        self.peutil.setentrypoint(entry_va + instrument_size)

    def get_instrument_size_until(self, va):
        sorted_instruction_map = sorted(self.instrument_history_map.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            if address < va:
                instrumented_size += size
            else:
                break
        return instrumented_size

    def get_instrument_size_from_until_with_base(self, base, until_va):
        va = until_va - base
        return self.get_instrument_size_until(va)

    def get_instrument_size_with_range(self, start, end):
        sorted_instruction_map = sorted(self.instrument_history_map.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            if address > end:
                break
            if start < address < end:
                instrumented_size += size
        return instrumented_size

    def get_instrument_size_with_vector(self, va):
        sorted_instruction_map = sorted(self.instrument_history_map.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            if address < va:
                instrumented_size += size
                va += size
            else:
                break
        return instrumented_size

    def get_instrument_size(self):
        sorted_instruction_map = sorted(self.instrument_history_map.items(),
                                        key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instruction_map:
            instrumented_size += size
        return instrumented_size

    def adjust_executable_section(self):
        execute_data = self.getdata()
        self.peutil.append_data_to_execution(execute_data)

    def adjust_instrumented_layout(self):
        """
        Adjusts the binary layout that has changed due to the address
        and the relatively operand of the instruction being changed during
        the instrumenting.
        :return:
        """
        self.disassemble()
        sorted_instruction_map = sorted(self.instruction_map.items(),
                                        key=operator.itemgetter(0))

        if not self.peutil.isrelocable():
            for inst_address, inst in sorted_instruction_map:
                if inst.flowControl in ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']:
                    self.adjust_relative_branches(inst)
                else:
                    # Temporary, adjust reference of text-section.
                    self.adjust_references(inst)
        else:
            for inst_address, inst in sorted_instruction_map:
                if inst.flowControl in ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']:
                    self.adjust_relative_branches(inst)

        if self.overflowed_instrument:
            overflowed_inst_handled = self.handle_overflow_instrument()
            if overflowed_inst_handled:
                self.disassemble()
                self.adjust_instrumented_layout()

    def adjust_relative_branches(self, inst):
        """
        adjust instruction's operand value.
        Because the instructions calculate the address to branch relatively from the current position,
        it is necessary to apply the offset value changed by the instrument.

        :param inst: branch instruction that has relatively operand value
        :return:
        """
        logfile = open('c:\\work\\adjust.log', 'a')
        log = []
        if not self.isredirect(inst):
            total_instrumented_size = \
                self.get_instrumented_size(inst)
            # adjust operand value
            if total_instrumented_size > 0:
                log.append("[0x{:x}] {:s}\n".format(inst.address, inst))
                operand_size = inst.operands[0].size / 8
                instruction_size = inst.size - operand_size
                operand_start = inst.address + instruction_size
                operand_end = inst.address + inst.size
                if operand_size == 8:
                    fmt = 'l'
                elif operand_size == 4:
                    fmt = 'i'
                elif operand_size == 2:
                    fmt = 'h'
                elif operand_size == 1:
                    fmt = 'b'
                operand_value \
                    = struct.unpack(fmt,
                                    self.execute_data[operand_start:operand_end])[0]
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
                    self.execute_data[operand_start:operand_end] \
                        = struct.pack(fmt, adjusted_operand_value)
                except:
                    self.overflowed_instrument = True
                    self.overflowed_instrument_map[inst.address] = (inst, adjusted_operand_value)
                    log.append("operand value size overflowed {:x}\n".format(operand_value))
        logfile.write(''.join(log))

    def adjust_references(self, inst):
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
                            struct.unpack("i",
                                          self.execute_data[
                                          inst.address + target_operand_index + inst_size
                                          :inst.address + inst.size])[0]
                        )

    def adjust_relocation(self):
        structures_relocation_block = {}
        structures_relocation_entries = {}
        log = open('c:\\work\\after_relocation.txt', 'w')
        block_va = -1
        for entry in self.peutil.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if block_va > 0:
                    structures_relocation_entries[block_va].append(entry)
                    # log.write("{}\n".format(entry))
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                block_va = entry.VirtualAddress
                structures_relocation_block[block_va] = entry
                structures_relocation_entries[block_va] = []
                # log.write("{}\n".format(entry))
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
        (text_section, text_section_end) = self.peutil.get_executable_range_va()
        sorted_relocation_block = sorted(structures_relocation_block.items(), key=operator.itemgetter(0))
        for index, (block_va, block) in enumerate(sorted_relocation_block):
            log.write("{}\n".format(block))
            if block_va < text_section_end:
                for entry in structures_relocation_entries[block_va]:
                    log.write("{}\n".format(entry))
                    if entry.Data == 0:
                        continue
                    entry_rva = entry.Data & 0x0fff
                    entry_type = entry.Data & 0xf000
                    # 0x1000 mean virtual address of first section that text section.
                    entry_va = block_va + entry_rva
                    instrumented_size = self.get_instrument_size_from_until_with_base(0x1000, entry_va)
                    entry_rva += instrumented_size

                    # move entry to appropriate block
                    if entry_rva >= 0x1000:
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
                            new_block = next_block
                            new_block.SizeOfBlock = 0
                            new_block.VirtualAddress = appropriate_block_va
                            appropriate_block_index = next_block_index-1
                            self.peutil.PE.__structures__.insert(appropriate_block_index, new_block)
                        self.peutil.PE.__structures__[appropriate_block_index].SizeOfBlock += 2
                        self.peutil.PE.__structures__.insert(appropriate_block_index+1, entry)
                    else:
                        entry.Data = entry_rva + entry_type
            else:
                # 0x1000 mean increased size of section va.
                self.peutil.PE.__structures__[self.peutil.PE.__structures__.index(block)].VirtualAddress += 0x1000

        log = open('c:\\work\\after_relocation.txt', 'w')

        """
        structures has owned offset.
        so, if modify position or order of structures element then must fix offset of structures element.
        """
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

    def get_adjusted_relocation_map(self, relocation_map):
        sorted_relocation_map = sorted(relocation_map.items(),
                                       key=operator.itemgetter(0))
        sorted_instrument_history_map = sorted(self.instrument_history_map.items(),
                                               key=operator.itemgetter(0))

        adjusted_relocation_map = {}
        executable_section_va_end = self.peutil.get_executable_range_va()[1]
        executable_section_end = len(self.execute_data)
        if executable_section_end < executable_section_va_end:
            executable_section_end = executable_section_va_end

        for (reloc_block_va, reloc_block) in sorted_relocation_map:
            adjusted_relocation_map[reloc_block_va] = []
            for (reloc_rva, reloc_raw) in reloc_block:
                if reloc_rva == reloc_block_va:
                    continue
                # finish when reach end of executable section
                if executable_section_end < reloc_block_va:
                    adjusted_relocation_map.pop(reloc_block_va, None)
                    return adjusted_relocation_map
                # TODO : fix this assumption
                reloc_rva -= 0x1000
                total_instrument_size = 0
                for instrumented_address, size in sorted_instrument_history_map:
                    if instrumented_address < reloc_rva:
                        total_instrument_size += size
                    else:
                        break
                adjusted_reloc_rva = reloc_rva + 0x1000 + total_instrument_size
                adjusted_relocation_map[reloc_block_va].append((adjusted_reloc_rva, reloc_raw))
                # adjusted_relocation_map[reloc_block_va] = (adjusted_reloc_rva, reloc_raw)
        return adjusted_relocation_map

    def handle_overflow_instrument(self):
        """
        extend the size of the operand if exceed the range of operand values while instrument.
        :return:
        """
        self.disassemble()
        total_instrument_size = 0
        # self.instrument_map.clear()
        handled_overflowed_map = {}
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        index = 1
        sorted_instrument_map = sorted(self.overflowed_instrument_map.items(),
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
                self.execute_data[inst_address:inst_address+inst.size] = encoding
                instrumented_size = len(encoding)
                print "writed : {:s}".format(
                    binascii.hexlify(
                        self.execute_data[inst_address:inst_address+instrumented_size]))
                # save increased opcode, operand size for adjust again
                increased_size = instrumented_size - inst.size
                handled_overflowed_map[inst_address] = increased_size
                total_instrument_size += increased_size
            except KsError as e:
                print("ERROR: %s" % e)

        if not self.instrument_history_map:
            self.save_instrument_history(self.instrument_map, handled_overflowed_map)
        else:
            self.save_instrument_history(self.instrument_history_map, handled_overflowed_map)
        self.instrument_map = handled_overflowed_map
        self.overflowed_instrument = False
        self.overflowed_instrument_map.clear()
        return True

    def adjust_address_by(self, adjust_to_map, adjust_by_map):
        """

        :param adjust_to_map: dict type.
        :param adjust_by_map: dict type.
        :return: adjusted instrumented history map.
        """

        for i in xrange(100):
            fname = 'c:\\work\\tomap{:d}.log'.format(i)
            if not os.path.exists(fname):
                tomap = open(fname, 'w')
                break

        for i in xrange(100):
            fname = 'c:\\work\\bymap{:d}.log'.format(i)
            if not os.path.exists(fname):
                bymap = open(fname, 'w')
                break

        for i in xrange(100):
            fname = 'c:\\work\\adjustmap{:d}.log'.format(i)
            if not os.path.exists(fname):
                adjustmap = open(fname, 'w')
                break

        adjusted_map = {}
        sorted_adjust_to_map = sorted(adjust_to_map.items(),
                                      key=operator.itemgetter(0))
        sorted_adjust_by_map = sorted(adjust_by_map.items(),
                                      key=operator.itemgetter(0))

        for instrumented_address, instrumented_size in sorted_adjust_to_map:
            adjust_instrument_address = instrumented_address
            for overflowed_address, increased_size in sorted_adjust_by_map:
                if overflowed_address < instrumented_address:
                    adjust_instrument_address += increased_size
            adjusted_map[adjust_instrument_address] = instrumented_size

        for overflowed_address, increased_size in sorted_adjust_by_map:
            if increased_size > 0:
                adjusted_map[overflowed_address] = increased_size

        sorted_adjusted_map = sorted(adjusted_map.items(),
                                      key=operator.itemgetter(0))

        print '===================[LOGGING]=============================='
        for address, size in sorted_adjusted_map:
            adjustmap.write('[0x{:x}]\t{}\n'.format(address, size))
        for instrumented_address, instrumented_size in sorted_adjust_to_map:
            tomap.write('[0x{:x}]\t{}\n'.format(instrumented_address, instrumented_size))
        for overflowed_address, increased_size in sorted_adjust_by_map:
            bymap.write('[0x{:x}]\t{}\n'.format(overflowed_address, increased_size))

        return adjusted_map

    def save_instrument_history(self, instrumented_map, handled_overflowed_map):
        adjusted_map = self.adjust_address_by(instrumented_map, handled_overflowed_map)
        # adjusted_map.update(handled_overflowed_map)
        self.instrument_history_map = adjusted_map
        """
        if not self.instrument_history_map:
            self.instrument_history_map = adjusted_map
        else:
            adjust_history_map = self.adjust_address_by(self.instrument_history_map, handled_overflowed_map)
            for address, size in adjusted_map.iteritems():
                if address in adjust_history_map:
                    adjust_history_map[address] = size
                    print "this situation maybe not good [0x{:x}] {:d}".format(address, size)
                else:
                    adjust_history_map[address] = size
            self.instrument_history_map = adjust_history_map
        """

    def isredirect(self, inst):
        """
        Returns true or false if the branch type of the instruction is redirect.
        :param inst: instruction
        :return: True or False
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

    def logging(self, path):
        log = open(path, 'w')
        # monitoring instruction
        instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH', 'FC_RET', 'FC_INT']
        result = ''
        for (key, inst) in self.instruction_map.items():
            cf = inst.flowControl
            operands = inst.operands
            if cf in instruction_types:
                result += '[0x{:05x}]'.format(inst.address)
                if len(operands) > 0:
                    operand = operands[0]
                    if operand.type == 'AbsoluteMemoryAddress':
                        result += '{:>10s}\t'.format('AbsoluteMemoryAddr')
                    elif operand.type == 'AbsoluteMemory':
                        result += '{:>10s}\t'.format('AbsoluteMemory')
                    elif operand.type == 'Immediate':
                        result += '{:>10s}\t'.format('Immediate')
                    elif operand.type == 'Register':
                        result += '{:>10s}\t'.format('Register')
                    else:
                        result += 'Type{:s}\t{:s}\t'.format(operand.type, operand)
                else:
                    result += '{:>10s}\t'.format('NoneOperand')
                result += '{:>10s}\t'.format(cf)
                result += '{:s}\n'.format(inst)
        log.write(result)

    def disassembly_logging(self, path):
        log = open(path, 'w')
        self.disassemble()
        for inst in self.disassembly:
            log.write("[0x{:x}] {:s}\n".format(inst.address, inst))

    def instrument_log(self, path):
        log = open(path, 'w')
        sorted_instrument_map = sorted(self.instrument_map.items(),
                                       key=operator.itemgetter(0))
        for instrument_address, instrument_inst in sorted_instrument_map:
            log.write("[0x{:x}] {:d}\n".format(instrument_address, instrument_inst))
