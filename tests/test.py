"""
test class for zigzi
"""


from PEInstrument import *
from keystone import *
from PEManager import *
from capstone.x86 import *
import os
import unittest


# code_mnemonic = "and"
# code_op_str = "dx, 0xffff"
code_mnemonic = "and"
code_op_str = "edx, 0x7fffffff"
code = code_mnemonic + " " + code_op_str


def instrument_test(instruction):
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hex_code)
        return encoding, count
    except KsError as e:
        print("ERROR: %s" % e)
    return None, 0


class Tests(unittest.TestCase):
    # default setting
    _Image_Base_ = 0x400000
    _Adjust_Size_ = 0x1000

    def __init__(self, *args, **kwargs):
        """
        in test case, each test will execute __init__ method.
        so if you want common initializing at each test, do it here.
        """
        super(Tests, self).__init__(*args, **kwargs)

    def setUp(self):
        """
        This method will execute at init time each test case like init method.
        so if you want common initializing at each test, do it here.
        """
        print("THIS IS SETUP")
        self.src_instrument = PEInstrument.from_filename(self.src_filename)
        self.dst_instrument = PEInstrument.from_filename(self.dst_filename)

    def tearDown(self):
        """
        This method will execute when each test case end.
        so if you want common destroy at each test case, do it here.
        """
        print("THIS IS TEARDOWN")

    @classmethod
    def setUpClass(cls):
        """
        This method execute once at test class initializing.
        so if you want common initializing at each test class, do it here.
        """
        print("THIS IS setUpClass")
        path = os.getcwd()
        cls.code_log = open(os.path.join(path, "tests", "codelog.log"), 'w')
        cls.reloc_log = open(os.path.join(path, "tests", "reloclog.log"), 'w')
        cls.src_filename = os.path.join(path, "tests", "firefox.exe")
        cls.dst_filename = os.path.join(path, "tests", "firefox_test.exe")
        # cls.src_filename = os.path.join(path, "tests", "sample.exe")
        # cls.dst_filename = os.path.join(path, "tests", "sample_test.exe")
        # cls.src_filename = os.path.join(path, "tests", "simple_echo_server.exe")
        # cls.dst_filename = os.path.join(path, "tests", "simple_echo_server_test.exe")
        src_instrument = PEInstrument.from_filename(cls.src_filename)
        src_instrument.register_pre_indirect_branch(instrument_test)
        src_instrument.do_instrument()
        src_instrument.writefile(cls.dst_filename)
        cls.instrumented_dict = src_instrument.get_instrumented_pos()

        src_pe_manager = PEManager(cls.src_filename)
        dst_pe_manager = PEManager(cls.dst_filename)
        dst_data_section = dst_pe_manager.get_data_section()
        src_data_section = src_pe_manager.get_data_section()
        cls._Adjust_Size_ = dst_data_section.VirtualAddress \
                            - src_data_section.VirtualAddress
        cls._Image_Base_ = src_pe_manager.PE.OPTIONAL_HEADER.ImageBase

    @classmethod
    def tearDownClass(cls):
        """
        This method execute once at test class closing.
        so if you want common destroying at each test class, do it here.
        """
        print("THIS IS tearDownClass")


    def test_export_function(self):
        test_fail_flag = False
        log = ""
        src_instrument = self.src_instrument
        dst_instrument = self.dst_instrument
        src_util = src_instrument.get_pe_manager()
        dst_util = dst_instrument.get_pe_manager()
        if not hasattr(src_util.PE, "DIRECTORY_ENTRY_EXPORT"):
            print("THIS BINARY HAS NOT EXPORT.")
            return True
        src_export_entry = src_util.PE.DIRECTORY_ENTRY_EXPORT
        dst_export_entry = dst_util.PE.DIRECTORY_ENTRY_EXPORT
        src_export_entry_struct = src_export_entry.struct
        dst_export_entry_struct = dst_export_entry.struct
        src_fn_rva = []
        dst_fn_rva = []

        for index in range(len(src_export_entry.symbols)):
            entry_fn_rva = src_export_entry_struct.AddressOfFunctions \
                           + (index * 4)
            fn_rva = src_util.PE.get_dword_at_rva(entry_fn_rva)
            src_fn_rva.append(fn_rva)

        for index in range(len(dst_export_entry.symbols)):
            entry_fn_rva = dst_export_entry_struct.AddressOfFunctions \
                           + (index * 4)
            fn_rva = dst_util.PE.get_dword_at_rva(entry_fn_rva)
            dst_fn_rva.append(fn_rva)

        if len(src_fn_rva) != len(dst_fn_rva):
            log += "Export function length is not matched\n"

        test_fail_flag = True
        for index in range(len(src_fn_rva)):
            src_rva = src_fn_rva[index]
            dst_rva = dst_fn_rva[index]
            if not self.compare_bytes(src_rva, dst_rva, 4):
                test_fail_flag = False
                log += "{:x} {:x}\n".format(src_rva, dst_rva)
        if not test_fail_flag:
            self.fail(log)

    def test_relocation(self):
        test_fail_flag = False
        src_instrument = self.src_instrument
        dst_instrument = self.dst_instrument
        src_manager = src_instrument.get_pe_manager()
        dst_manager = dst_instrument.get_pe_manager()
        src_relocation_dict = src_manager.get_relocation()
        dst_relocation_dict = dst_manager.get_relocation()

        src_execute_start, src_execute_end = \
            src_manager.get_text_section_virtual_address_range()
        dst_execute_start, dst_execute_end = \
            dst_manager.get_text_section_virtual_address_range()
        src_execute_start += self._Image_Base_
        src_execute_end += self._Image_Base_
        dst_execute_start += self._Image_Base_
        dst_execute_end += self._Image_Base_

        sorted_src_reloc_dict = sorted(src_relocation_dict.items(),
                                       key=operator.itemgetter(0))
        sorted_dst_reloc_dict = sorted(dst_relocation_dict.items(),
                                       key=operator.itemgetter(0))

        src_relocation_length = len(src_relocation_dict.keys())
        dst_relocation_length = len(dst_relocation_dict.keys())

        if src_relocation_length == dst_relocation_length:
            print("RELOCATION DIRECTORY LENGTH IS SAME")

        for index in range(len(sorted_src_reloc_dict)):
            src_reloc_el = sorted_src_reloc_dict[index]
            dst_reloc_el = sorted_dst_reloc_dict[index]
            src_reloc_address = int(src_reloc_el[0])
            src_reloc = src_reloc_el[1]
            dst_reloc_address = int(dst_reloc_el[0])
            dst_reloc = dst_reloc_el[1]
            src_reloc_data = int(src_manager.PE.get_dword_at_rva(src_reloc_address))
            dst_reloc_data = int(dst_manager.PE.get_dword_at_rva(dst_reloc_address))

            self.reloc_log.write(
                "[{:04x}]\t[0x{:x}][0x{:x}][{}]\t[0x{:x}][0x{:x}][{}]\n"
                    .format(index, src_reloc_address, src_reloc_data, src_reloc,
                            dst_reloc_address, dst_reloc_data, dst_reloc))
            if src_execute_start < src_reloc_data < src_execute_end \
                    and dst_execute_start < dst_reloc_data < dst_execute_end:
                dst_rva = dst_reloc_data - self._Image_Base_ - 0x1000
                src_rva = src_reloc_data - self._Image_Base_ - 0x1000
                instrumented_size = \
                    self.getInstrumentedSizeUntil(dst_rva,
                                                  self.instrumented_dict)
                dst_rva -= instrumented_size
                if dst_rva != src_rva:
                    self.reloc_log.write("\t[FAILED] ==> [0x{:x}]\t{:x}\t"
                                         "expected [0x{:x}] but [0x{:x}]\n"
                                         .format(src_rva, instrumented_size,
                                                 src_rva + instrumented_size,
                                                 dst_rva))
                    test_fail_flag = True
            elif src_execute_end < src_reloc_data and dst_execute_end < dst_reloc_data:
                if src_reloc_data + self._Adjust_Size_ != dst_reloc_data:
                    self.reloc_log.write("\t[FAILED] ==> [0x{:x}]\t[0x{:x}]\n"
                                         .format(src_reloc_data, dst_reloc_data))
                    test_fail_flag = True

        if test_fail_flag:
            self.fail("RELOCATION ADJUST FAILED")

    def test_codes(self):
        src_instrument = self.src_instrument
        dst_instrument = self.dst_instrument
        src_disassemble = src_instrument.get_instructions()
        dst_disassemble = dst_instrument.get_instructions()
        execute_start, execute_end = \
            src_instrument.get_pe_manager()\
            .get_text_section_virtual_address_range()
        src_size = execute_end - execute_start
        execute_start, execute_end = \
            dst_instrument.get_pe_manager()\
            .get_text_section_virtual_address_range()
        dst_size = execute_end - execute_start

        dst_index = 0
        src_index = 0
        for index in range(len(dst_disassemble)):
            try:
                dst_inst_address, dst_inst = dst_disassemble[dst_index]
                src_inst_address, src_inst = src_disassemble[src_index]
                if dst_inst_address >= dst_size \
                        or src_inst_address >= src_size:
                    break
            except:
                self.fail("Something wrong when disassemble codes")

            self.log_code(dst_inst, src_inst)
            dst_str = self.inst_to_str(dst_inst)
            src_str = self.inst_to_str(src_inst)

            if dst_str == code:
                dst_index += 1
                continue

            if dst_str != src_str:
                if(dst_inst.mnemonic == src_inst.mnemonic
                   and len(dst_inst.operands) == len(src_inst.operands)):
                    if not(self.checkCompareInstruction(dst_inst, src_inst)):
                        find_match = False
                        for dst_search_depth in range(6):
                            if find_match:
                                break
                            for srcSearchDepth in range(6):
                                dst_search_addr, dst_dis_search = \
                                    dst_disassemble[dst_index + dst_search_depth]
                                src_search_addr, src_dis_search = \
                                    src_disassemble[src_index + srcSearchDepth]

                                if self.checkCompareInstruction(dst_dis_search,
                                                                src_dis_search):
                                    self.log_code(dst_inst, src_inst)
                                    for search_depth \
                                            in range(dst_search_depth + 1):
                                        addr, dst_dis_search = \
                                            dst_disassemble[dst_index
                                                            + search_depth]
                                        self.log_code(dst_inst=dst_dis_search)
                                    for search_depth in range(srcSearchDepth+1):
                                        addr, src_dis_search = \
                                            src_disassemble[
                                                src_index + search_depth
                                                ]
                                        self.log_code(src_inst=src_dis_search)
                                    dst_index += dst_search_depth
                                    src_index += srcSearchDepth
                                    find_match = True

                        if find_match == False:
                            self.log_code(dst_inst, src_inst)
                            # assert False

                        """    
                        print("[TESTCODE]\t[0x{:x}]{:s}{:s}\t[0x{:x}]{:s}{:s}"
                              .format(dst_inst.address,
                                      dst_inst.mnemonic, dst_inst.op_str,
                                      src_dis.address,
                                      src_dis.mnemonic, src_dis.op_str))
                        assert False
                        """

                else:
                    find_match = False
                    for dst_search_depth in range(6):
                        if find_match:
                            break
                        for srcSearchDepth in range(6):
                            dst_search_addr, dst_dis_search = \
                                dst_disassemble[dst_index + dst_search_depth]
                            src_search_addr, src_dis_search = \
                                src_disassemble[src_index + srcSearchDepth]

                            if self.checkCompareInstruction(dst_dis_search,
                                                            src_dis_search):

                                print("[DIFF MNEMONIC] ====================")
                                for search_depth in range(dst_search_depth + 1):
                                    addr, dst_dis_search = \
                                        dst_disassemble[dst_index
                                                        + search_depth]
                                    self.log_code(dst_inst=dst_dis_search)

                                for search_depth in range(srcSearchDepth + 1):
                                    addr, src_dis_search = \
                                        src_disassemble[src_index + search_depth]
                                    self.log_code(src_inst=src_dis_search)
                                dst_index += dst_search_depth
                                src_index += srcSearchDepth
                                find_match = True

                    if not find_match:
                        self.log_code(dst_inst, src_inst)
            dst_index += 1
            src_index += 1

    def log_code(self, dst_inst=None, src_inst=None, prev_str=None,
                 next_str=None):

        if prev_str is not None:
            self.code_log.write(prev_str + "\n")
        if src_inst is None and dst_inst is not None:
            self.code_log.write("[DESTINY] ==> [0x{:04x}]\t{:35s}\n"
                                .format(dst_inst.address,
                                        self.inst_to_str(dst_inst))
                                )
        elif src_inst is not None and dst_inst is None:
            self.code_log.write("\t\t\t\t\t\t\t\t\t\t\t\t"
                                "[SOURCE] ==> [0x{:04x}]\t{:35s}\n"
                                .format(src_inst.address,
                                        self.inst_to_str(src_inst))
                                )
        else:
            self.code_log.write("[0x{:04x}]\t{:35s}\t[0x{:04x}]\t{:35s}\n"
                                .format(dst_inst.address,
                                        self.inst_to_str(dst_inst),
                                        src_inst.address,
                                        self.inst_to_str(src_inst))
                                )
        if next_str is not None:
            self.code_log.write(next_str + "\n")

    def checkDirectJmp(self, dst_inst, src_inst):
        result = False
        src_jmp_target = src_inst.operands[0].imm
        dst_jmp_target = dst_inst.operands[0].imm
        if(dst_jmp_target - src_jmp_target
           == self.getInstrumentedSizeUntil(dst_jmp_target,
                                            self.instrumented_dict)
           ):
            result = True
        return result

    def checkIndirectJmp(self, dst_inst, src_inst):
        return self.checkCompareOperands(dst_inst.operands, src_inst.operands)

    def checkCompareOperands(self, dst_operands, src_operands):
        result = False
        if len(dst_operands) == len(src_operands):
            for index in range(len(dst_operands)):
                dst_operand = dst_operands[index]
                src_operand = src_operands[index]
                if dst_operand.type == X86_OP_REG \
                        and src_operand.type == X86_OP_REG:
                    if dst_operand.reg == src_operand.reg:
                        result = True
                elif dst_operand.type == X86_OP_IMM \
                        and src_operand.type == X86_OP_IMM:
                    if dst_operand.imm == src_operand.imm \
                            or ((dst_operand.imm - src_operand.imm)
                                    == self._Adjust_Size_):
                        result = True
                    elif ((dst_operand.imm - src_operand.imm)
                            == self.getInstrumentedSizeUntil(dst_operand.imm
                                                             - 0x401000,
                                                             self.instrumented_dict)
                          ):
                        result = True
                    else:
                        result = False
                elif dst_operand.type == X86_OP_MEM \
                        and src_operand.type == X86_OP_MEM:
                    if dst_operand.mem.segment != 0:
                        if dst_operand.mem.segment != src_operand.mem.segment:
                            return False
                    if dst_operand.mem.base != 0:
                        if dst_operand.mem.base != src_operand.mem.base:
                            return False
                    if dst_operand.mem.index != 0:
                        if dst_operand.mem.index != src_operand.mem.index:
                            return False
                    if dst_operand.mem.scale != 1:
                        if not (dst_operand.mem.scale == src_operand.mem.scale):
                            return False
                    if dst_operand.mem.disp != 0:
                        if not (dst_operand.mem.disp == src_operand.mem.disp):
                            if not (dst_operand.mem.disp - src_operand.mem.disp
                                        == self._Adjust_Size_):
                                return False
                    result = True
                else:
                    result = False
        return result

    def checkCompareInstruction(self, dst_inst, src_inst):
        if dst_inst.mnemonic == src_inst.mnemonic \
                and dst_inst.op_str == src_inst.op_str:
            result = True
        elif dst_inst.groups == src_inst.groups:
            if self.dst_instrument.disassembler.is_relative_branch(dst_inst):
                result = self.checkDirectJmp(dst_inst, src_inst)
            elif self.dst_instrument.disassembler.is_indirect_branch(dst_inst):
                result = self.checkIndirectJmp(dst_inst, src_inst)
            else:
                result = self.checkCompareOperands(dst_inst.operands,
                                                   src_inst.operands)
        else:
            result = False
        return result

    @staticmethod
    def getInstrumentedSizeUntil(rva, instrument_dict):
        sorted_instrumented_dict = sorted(instrument_dict.items(),
                                          key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in sorted_instrumented_dict:
            if address < rva:
                instrumented_size += size
            else:
                break
        return instrumented_size

    @staticmethod
    def inst_to_str(instruction):
        return instruction.mnemonic + " " + instruction.op_str

    def compare_bytes(self, src_rva, dst_rva, length):
        src_data = \
            self.src_instrument.code_manager.get_data_from_rva(src_rva, length)
        dst_data = \
            self.dst_instrument.code_manager.get_data_from_rva(dst_rva, length)

        if src_data == dst_data:
            return True

        return False


def setUpModule():
    """
    This function will run before create test class instance.
    """
    print("THIS IS setUpModule")


def tearDownModule():
    """
    This function will run after test case closed.
    """
    print("THIS IS tearDownModule")

if __name__ == '__main__':
    unittest.main()
