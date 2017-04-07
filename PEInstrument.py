import struct
import binascii
import distorm3
import operator
from keystone import *


class PEInstrument(object):
    INSTRUMENT_BEFORE = 1
    INSTRUMENT_AFTER = 2

    def __init__(self, execute_data):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.execute_data = execute_data
        self.instruction_map = {}
        self.instrument_map = {}
        self.disassembly = []
        self.disassemble()
        self.overflowed_instrument = False
        self.overflowed_instrument_map = {}

    def disassemble(self):
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
                if self.is_redirect(inst):
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

    def adjust_instrumented_layout(self):
        self.disassemble()
        sorted_instruction_map = sorted(self.instruction_map.items(),
                                        key=operator.itemgetter(0))
        for inst_address, inst in sorted_instruction_map:
            if inst.flowControl in ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']:
                self.adjust_instrument(inst)
            else:
                # Temporary, adjust reference of text-section.
                self.adjust_references(inst)
                self.adjust_relocation(inst)
        has_overflowed_inst = self.handle_overflow_instrument()
        if has_overflowed_inst:
            self.disassemble()
            self.adjust_instrumented_layout()

    def adjust_instrument(self, inst):
        logfile = open('c:\\work\\adjust.log', 'a')
        log = []
        if not self.is_redirect(inst):
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

    # TODO : handle relocation
    def adjust_relocation(self, inst):
        return 0

    def handle_overflow_instrument(self):
        total_instrument_size = 0
        self.disassemble()
        self.instrument_map.clear()
        if not self.overflowed_instrument:
            return False
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
                self.instrument_map[inst_address] = increased_size
                total_instrument_size += increased_size
            except KsError as e:
                print("ERROR: %s" % e)

        self.overflowed_instrument = False
        self.overflowed_instrument_map.clear()
        return True

    def is_redirect(self, inst):
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
