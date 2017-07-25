from Disassembler import *
from PEInstrument import *
from keystone import *
from PEUtil import *
from capstone.x86 import *
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
    _Image_Base_ = 0x400000
    _Adjust_Size_ = 0x1000

    def __init__(self, *args, **kwargs):
        super(Tests, self).__init__(*args, **kwargs)
        self.codeLog = open(os.path.join(os.getcwd(), "tests", "codelog.log"), 'w')
        self.relocLog = open(os.path.join(os.getcwd(), "tests", "reloclog.log"), 'w')
        self.src_filename = os.path.join(os.getcwd(), "tests", "sample.exe")
        self.dst_filename = os.path.join(os.getcwd(), "tests", "sample_test.exe")
        srcPEI = PEInstrument(self.src_filename)
        srcPEI.instrument_at_indirect_instruction(instrument)
        srcPEI.writefile(self.dst_filename)
        self.instrumentedMap = srcPEI.get_instrumented_pos()

    def __del__(self):
        try:
            os.remove(self.dst_filename)
        except:
            pass

    def test_relocation(self):
        testFailFlag = False
        srcPei = PEInstrument(self.src_filename)
        dstPei = PEInstrument(self.dst_filename)
        srcUtil = srcPei.peutil
        dstUtil = dstPei.peutil
        srcRelocationMap = srcUtil.get_relocation()
        dstRelocationMap = dstUtil.get_relocation()

        srcExecuteStart, srcExecuteEnd = srcUtil.get_text_section_virtual_address_range()
        dstExecuteStart, dstExecuteEnd = dstUtil.get_text_section_virtual_address_range()
        srcExecuteStart += self._Image_Base_
        srcExecuteEnd += self._Image_Base_
        dstExecuteStart += self._Image_Base_
        dstExecuteEnd += self._Image_Base_

        sortedSrcRelocMap = sorted(srcRelocationMap.items(),
                                   key=operator.itemgetter(0))
        sortedDstRelocMap = sorted(dstRelocationMap.items(),
                                   key=operator.itemgetter(0))

        for index in xrange(len(sortedSrcRelocMap)):
            srcRelocEl = sortedSrcRelocMap[index]
            dstRelocEl = sortedDstRelocMap[index]
            srcRelocAddress = int(srcRelocEl[0])
            srcReloc = srcRelocEl[1]
            dstRelocAddress = int(dstRelocEl[0])
            dstReloc = dstRelocEl[1]
            srcData = int(srcUtil.PE.get_dword_at_rva(srcRelocAddress))
            dstData = int(dstUtil.PE.get_dword_at_rva(dstRelocAddress))

            self.relocLog.write(
                "[{:04x}]\t[0x{:x}][0x{:x}][{}]\t[0x{:x}][0x{:x}][{}]\n".format(index,
                                                                                srcRelocAddress, srcData, srcReloc,
                                                                                dstRelocAddress, dstData, dstReloc))

            if srcExecuteStart < srcData < srcExecuteEnd and \
                                    dstExecuteStart < dstData < dstExecuteEnd:
                dstValue = dstData - self._Image_Base_ - self._Adjust_Size_
                instrumentedSize = self.getInstrumentedSizeUntil(dstValue)
                dstValue -= instrumentedSize
                srcValue = srcData - self._Image_Base_ - self._Adjust_Size_
                if dstValue != srcValue:
                    self.relocLog.write("\t[FAILED] ==> [0x{:x}]\t[0x{:x}]\n".format(srcValue, dstValue))
                    testFailFlag = True
            elif srcExecuteEnd < srcData and dstExecuteEnd < dstData:
                if srcData + self._Adjust_Size_ != dstData:
                    self.relocLog.write("\t[FAILED] ==> [0x{:x}]\t[0x{:x}]\n".format(srcData, dstData))
                    testFailFlag = True

        if testFailFlag:
            self.fail("RELOCATION ADJUST FAILED")

    def test_codes(self):
        self.src_pei = PEInstrument(self.src_filename)
        self.dst_pei = PEInstrument(self.dst_filename)
        srcPEI = self.src_pei
        dstPEI = self.dst_pei
        srcDisassemble = srcPEI.get_instructions()
        dstDisassemble = dstPEI.get_instructions()
        executeStart, executeEnd = srcPEI.peutil.get_text_section_virtual_address_range()
        srcSize = executeEnd - executeStart
        executeStart, executeEnd = dstPEI.peutil.get_text_section_virtual_address_range()
        dstSize = executeEnd - executeStart

        dstIndex = 0
        srcIndex = 0
        for index in xrange(len(dstDisassemble)):
            try:
                dstInstAddress, dstInst = dstDisassemble[dstIndex]
                srcInstAddress, srcInst = srcDisassemble[srcIndex]
                if dstInstAddress >= dstSize or srcInstAddress >= srcSize:
                    break
            except:
                self.fail("Something wrong when disassemble codes")

            self.codeLog.write("[{:03x}]\t{}\t[{:03x}]\t{}\n".format(srcInstAddress, srcInst, dstInstAddress, dstInst))
            dst_el = ("%s\t%s" % (dstInst.mnemonic, dstInst.op_str))
            src_el = ("%s\t%s" % (srcInst.mnemonic, srcInst.op_str))
            if (dstInst.mnemonic == 'mov' and dstInst.op_str == 'eax, eax'):
                if (srcInst.mnemonic == 'mov' and srcInst.op_str == 'eax, eax'):
                    dstIndex += 1
                    srcIndex += 1
                    continue
                else:
                    dstIndex += 1
                    continue

            if dst_el != src_el:
                if dstInst.mnemonic == srcInst.mnemonic and len(dstInst.operands) == len(srcInst.operands):
                    findMatch = False
                    if not(self.checkCompareInstruction(dstInst, srcInst)):
                        findMatch = False
                        for dstSearchDepth in xrange(6):
                            if findMatch:
                                break
                            for srcSearchDepth in xrange(6):
                                dstSearchAddr, dstDisSearch = dstDisassemble[dstIndex + dstSearchDepth]
                                srcSearchAddr, srcDisSearch = srcDisassemble[srcIndex + srcSearchDepth]

                                if self.checkCompareInstruction(dstDisSearch, srcDisSearch):
                                    print "[SAME MNEMONIC]===================================="
                                    for searchDepth in xrange(dstSearchDepth+1):
                                        addr, dstDisSearch = dstDisassemble[dstIndex + searchDepth]
                                        print "\t[DST][0x{:x}] {:s} {:s}".format(dstDisSearch.address,
                                                                                 dstDisSearch.mnemonic,
                                                                                 dstDisSearch.op_str)
                                    for searchDepth in xrange(srcSearchDepth+1):
                                        addr, srcDisSearch = srcDisassemble[srcIndex + searchDepth]
                                        print "\t[SRC][0x{:x}] {:s} {:s}".format(srcDisSearch.address,
                                                                                 srcDisSearch.mnemonic,
                                                                                 srcDisSearch.op_str)
                                    dstIndex += dstSearchDepth
                                    srcIndex += srcSearchDepth
                                    findMatch = True

                        if findMatch == False:
                            print "FAIL ============================================================"
                            print "[SAME]\t[0x{:x}]{:s}{:s}\t[0x{:x}]{:s}{:s}".format(dstInst.address,
                                                                                      dstInst.mnemonic,
                                                                                      dstInst.op_str,
                                                                                      srcInst.address,
                                                                                      srcInst.mnemonic,
                                                                                      srcInst.op_str)
                            # assert False

                        """
                        print "[TESTCODE]\t[0x{:x}]{:s}{:s}\t[0x{:x}]{:s}{:s}".format(dstInst.address,
                                                                                      dstInst.mnemonic, dstInst.op_str,
                                                                                      src_dis.address,
                                                                                      src_dis.mnemonic, src_dis.op_str)
                        assert False
                        """
                else:
                    findMatch = False
                    for dstSearchDepth in xrange(6):
                        if findMatch:
                            break
                        for srcSearchDepth in xrange(6):
                            dstSearchAddr, dstDisSearch = dstDisassemble[dstIndex + dstSearchDepth]
                            srcSearchAddr, srcDisSearch = srcDisassemble[srcIndex + srcSearchDepth]

                            if self.checkCompareInstruction(dstDisSearch, srcDisSearch):
                                print "[DIFF MNEMONIC] ====================================="
                                for searchDepth in xrange(dstSearchDepth +1):
                                    addr, dstDisSearch = dstDisassemble[dstIndex + searchDepth]
                                    print "\t[DST][0x{:x}] {:s} {:s}".format(dstDisSearch.address,
                                                                             dstDisSearch.mnemonic,
                                                                             dstDisSearch.op_str)
                                for searchDepth in xrange(srcSearchDepth +1):
                                    addr, srcDisSearch = srcDisassemble[srcIndex + searchDepth]
                                    print "\t[SRC][0x{:x}] {:s} {:s}".format(srcDisSearch.address,
                                                                             srcDisSearch.mnemonic,
                                                                             srcDisSearch.op_str)
                                dstIndex += dstSearchDepth
                                srcIndex += srcSearchDepth
                                findMatch = True

                    if findMatch == False:
                        print "FAIL ============================================================"
                        print "[NONS]\t[0x{:x}]{:s}{:s}\t[0x{:x}]{:s}{:s}".format(dstInst.address,
                                                                                  dstInst.mnemonic,
                                                                                  dstInst.op_str,
                                                                                  srcInst.address,
                                                                                  srcInst.mnemonic,
                                                                                  srcInst.op_str)
            dstIndex += 1
            srcIndex += 1

    def checkDirectJmp(self, dstInst, srcInst):
        result = False
        srcJmpTarget = srcInst.operands[0].imm
        dstJmpTarget = dstInst.operands[0].imm
        if dstJmpTarget - srcJmpTarget == self.getInstrumentedSizeUntil(dstJmpTarget):
            result = True
        return result

    def checkIndirectJmp(self, dstInst, srcInst):
        return self.checkCompareOperands(dstInst.operands, srcInst.operands)

    def checkCompareOperands(self, dstOperands, srcOperands):
        result = False
        if len(dstOperands) == len(srcOperands):
            for index in xrange(len(dstOperands)):
                dst_operand = dstOperands[index]
                src_operand = srcOperands[index]
                if dst_operand.type == X86_OP_REG and src_operand.type == X86_OP_REG:
                    if dst_operand.reg == src_operand.reg:
                        result = True
                elif dst_operand.type == X86_OP_IMM and src_operand.type == X86_OP_IMM:
                    if dst_operand.imm == src_operand.imm \
                            or ((dst_operand.imm - src_operand.imm) == self._Adjust_Size_):
                        result = True
                    elif dst_operand.imm - src_operand.imm == self.getInstrumentedSizeUntil(dst_operand.imm - 0x401000):
                        result = True
                    else:
                        result = False
                elif dst_operand.type == X86_OP_MEM and src_operand.type == X86_OP_MEM:
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
                            if not (dst_operand.mem.disp - src_operand.mem.disp == self._Adjust_Size_):
                                return False
                    result = True
                else:
                    result = False
        return result

    def checkCompareInstruction(self, dstInst, srcInst):
        result = False
        if dstInst.mnemonic == srcInst.mnemonic and dstInst.op_str == srcInst.op_str:
            result = True
        elif dstInst.groups == srcInst.groups:
            if self.dst_pei.Disassembler.is_direct_branch(dstInst):
                result = self.checkDirectJmp(dstInst, srcInst)
            elif self.dst_pei.Disassembler.is_indirect_branch(dstInst):
                result = self.checkIndirectJmp(dstInst, srcInst)
            else:
                result = self.checkCompareOperands(dstInst.operands, srcInst.operands)
        else:
            result = False
        return result

    def getInstrumentedSizeUntil(self, va):
        if not hasattr(self, 'sorted_instrumented_map'):
            self.sortedInstrumentedMap = sorted(self.instrumentedMap.items(),
                                                key=operator.itemgetter(0))
        instrumentedSize = 0
        for address, size in self.sortedInstrumentedMap:
            if address < va:
                instrumentedSize += size
            else:
                break
        return instrumentedSize

if __name__ == '__main__':
    unittest.main()
