from PEInstrument import *
from keystone import *
import os
import unittest


def instrument(instruction):
    code = "MOV EAX, EAX"
    hexacode = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hexacode)
        return (encoding, count)
    except KsError as e:
        print("ERROR: %s" % e)
    return (None, 0)


class Tests(unittest.TestCase):
    _Branch_Instruction_Types_ = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']
    _Adjust_Size_ = 0x1000

    def setUp(self):
        self.src_filename = os.path.join(os.getcwd(), "tests", "sample.exe")
        self.dst_filename = os.path.join(os.getcwd(), "tests", "sample_test.exe")
        src_pei = PEInstrument(self.src_filename)
        src_pei.instrumentRedirectControlflowInstruction(instrument)
        src_pei.writefile(self.dst_filename)
        self.instrumented_map = src_pei.getInstrumentedMap()

    def tearDown(self):
        try:
            os.remove(self.dst_filename)
        except:
            pass

    def test_codes(self):
        self.src_pei = PEInstrument(self.src_filename)
        self.dst_pei = PEInstrument(self.dst_filename)
        src_pei = self.src_pei
        dst_pei = self.dst_pei
        src_disassemble = src_pei.getInstructions()
        dst_disassemble = dst_pei.getInstructions()
        execute_start, execute_end = src_pei.peutil.getExecutableVirtualAddressRange()
        src_size = execute_end - execute_start
        execute_start, execute_end = dst_pei.peutil.getExecutableVirtualAddressRange()
        dst_size = execute_end - execute_start

        dst_index = 0
        src_index = 0
        for index in xrange(len(dst_disassemble)):
            try:
                dst_dis_address, dst_dis = dst_disassemble[dst_index]
                src_dis_address, src_dis = src_disassemble[src_index]
                if dst_dis_address >= dst_size or src_dis_address >= src_size:
                    break
            except:
                self.fail("Something wrong when disassemble codes")
            dst_el = str(dst_dis)
            src_el = str(src_dis)
            if dst_el == 'MOV EAX, EAX' and src_el != 'MOV EAX, EAX':
                # print "0x{:x}".format(dst_dis.address)
                dst_index += 1
                continue
            if dst_el != src_el:
                if dst_dis.mnemonic == src_dis.mnemonic and len(dst_dis.operands) == len(src_dis.operands):
                    if not(self.checkCompareInstruction(dst_dis, src_dis)):
                        print "{}\t{}".format(src_dis, dst_dis)
                        # self.assertTrue(self.checkCompareInstruction(dst_dis, src_dis), msg="NO!!!!")
                else:
                    assert False, "ERROR\t[0x{:x}]{}\t[0x{:x}]{}".format(dst_dis.address, dst_el,
                                                                         src_dis.address, src_el)
            dst_index += 1
            src_index += 1

    def checkDirectJmp(self, dst_dis, src_dis):
        result = False
        src_jmp_target = src_dis.operands[0].value
        dst_jmp_target = dst_dis.operands[0].value
        if dst_jmp_target - src_jmp_target == self.getInstrumentedSizeUntil(dst_jmp_target):
            result = True
        return result

    def checkRedirectJmp(self, dst_dis, src_dis):
        result = False
        dst_operand = dst_dis.operands[0]
        src_operand = src_dis.operands[0]

        if (dst_operand.value + dst_operand.disp) - (src_operand.value + src_operand.disp) == 0x1000:
            result = True
        elif (dst_operand.value + dst_operand.disp) - (src_operand.value + src_operand.disp) \
                == self.getInstrumentedSizeUntil(dst_operand.value + dst_operand.disp - 0x401000):
            result = True
        else:
            result = False
        return result

    def checkCompareInstruction(self, dst_dis, src_dis):
        result = False
        if str(dst_dis) == str(src_dis):
            result = True
        elif dst_dis.flowControl == src_dis.flowControl \
                and (dst_dis.flowControl in self._Branch_Instruction_Types_):
            if self.dst_pei.isRedirect(dst_dis):
                result = self.checkRedirectJmp(dst_dis, src_dis)
            else:
                result = self.checkDirectJmp(dst_dis, src_dis)
        else:
            for index in xrange(len(dst_dis.operands)):
                dst_operand = dst_dis.operands[index]
                src_operand = src_dis.operands[index]
                dst_str = "{}".format(dst_operand)
                src_str = "{}".format(src_operand)
                if dst_str == src_str:
                    continue
                else:
                    if (dst_operand.value + dst_operand.disp) - (src_operand.value + src_operand.disp) == 0x1000:
                        result = True
                    elif (dst_operand.value + dst_operand.disp) - (src_operand.value + src_operand.disp) \
                            == self.getInstrumentedSizeUntil(dst_operand.value + dst_operand.disp - 0x401000):
                        result = True
                    else:
                        result = False
        return result

    def getInstrumentedSizeUntil(self, va):
        if not hasattr(self, 'sorted_instrumented_map'):
            self.sorted_instrumented_map = sorted(self.instrumented_map.items(),
                                                  key=operator.itemgetter(0))
        instrumented_size = 0
        for address, size in self.sorted_instrumented_map:
            if address < va:
                instrumented_size += size
            else:
                break
        return instrumented_size

if __name__ == '__main__':
    unittest.main()
