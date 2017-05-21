import pefile
import distorm3
import PEUtil
import binascii
from capstone import *

peutil = PEUtil.PEUtil('c:\\work\\firefox.exe')
execute_section = peutil.getExecutableSection()
execute_section_data = peutil.getSectionRawData(execute_section)
hexacode = binascii.hexlify(execute_section_data).decode('hex')

# distorm3_log = open("c:\\work\\distorm3_disassemble.log", "w")
distorm3_redirect_branches = {}
instrs = []
for inst in distorm3.Decompose(0x0, hexacode, distorm3.Decode32Bits):
    # distorm3_log.write("[0x{:x}]\t{:s}\n".format(inst.address, inst))
    instrs.append(inst)
    instruction_types = ['FC_CALL', 'FC_UNC_BRANCH', 'FC_CND_BRANCH']
    cf = inst.flowControl
    if cf in instruction_types:
        operands = inst.operands
        if len(operands) > 0:
            operand = operands[0]
            if operand.type == 'AbsoluteMemoryAddress' or operand.type == 'Register' \
                    or operand.type == 'AbsoluteMemory' or operand.type == 'Immediate':
                distorm3_redirect_branches[inst.address] = inst
for el in instrs:
    if 0 < el.address < 100:
        instrs.remove(el)
print "END"
"""
capstone_log = open("c:\\work\\capstone_disassemble.log", "w")
capstone_branch_log = open("c:\\work\\capstone_branch.log", "w")
offset = 0
capstone_redirect_branches = {}
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
while True:
    if offset > len(hexacode):
        break
    try:
        insn = md.disasm(hexacode[offset:offset+10], offset, 1).next()
        capstone_log.write("[0x{:x}]\t{:s}\t{:s}\n".format(insn.address, insn.mnemonic, insn.op_str))
        offset += insn.size
        if insn.address == 0x128:
            log = ""
            operands = insn.operands
            for i in operands:
                if i.type == CS_OP_REG:
                    log = ("{:s}\toperands{:d}.type:REG={:s}\tsize={:d}\n".format(log, c, insn.reg_name(i.reg), i.size))
                elif i.type == CS_OP_IMM:
                    log = ("{:s}\toperands{:d}.type:IMM=0x{:x}\tsize={:d}\n".format(log, c, i.imm, i.size))
                elif i.type == CS_OP_MEM:
                    log = ("{:s}\toperands{:d}.type:MEM\tsize={:d}\n".format(log, c, i.size))
                    if i.mem.segment != 0:
                        log = ("{:s}\t\toperands{:d}.mem.segment:REG={:s}\n".format(log, c, insn.reg_name(i.mem.segment)))
                    if i.mem.base != 0:
                        "in '[0x94]:	call	dword ptr [edi + 0x4c]' base is edi"
                        log = ("{:s}\t\toperands{:d}.mem.base: REG={:s}\n".format(log, c, insn.reg_name(i.mem.base)))
                    if i.mem.index != 0:
                        "in '[0x37a5]:	call	dword ptr [ecx*4 + 0x40d1b0]' index is ecx"
                        log = ("{:s}\t\toperands{:d}.mem.index:REG={:s}\n".format(log, c, insn.reg_name(i.mem.index)))
                    if i.mem.scale != 1:
                        "in '[0x37a5]:	call	dword ptr [ecx*4 + 0x40d1b0]' scale is 4"
                        '[0x37a5]:	call	dword ptr [ecx*4 + 0x40d1b0]	call	operands0.type: MEM'
                        log = ("{:s}\t\toperands{:d}.mem.scale:{:d}\n".format(log, c, i.mem.scale))
                    if i.mem.disp != 0:
                        "in '[0xf]:	call	dword ptr [0x414324]' disp is 0x414324"
                        log = ("{:s}\t\toperands{:d}.mem.disp: 0x{:x}\n".format(log, c, i.mem.disp))

        if len(insn.groups) > 0:
            log = ""
            for group_index in range(len(insn.groups)):
                log = ("[0x{:x}]:\t{:s}\t{:s}".format(insn.address, insn.mnemonic, insn.op_str))
                if insn.groups[group_index] == CS_GRP_JUMP or insn.groups[group_index] == CS_GRP_CALL\
                        or True:
                    log = "{:s}\t{}\n".format(log, insn.group_name(insn.groups[group_index]))
                    if len(insn.operands) > 0:
                        c = -1
                        for i in insn.operands:
                            c += 1
                            if insn.address == 0x128:
                                print insn
                            if 0x401000 < i.value.imm < 0x409110:
                                print i.value.imm
                            if i.type == CS_OP_REG:
                                log = ("{:s}\toperands{:d}.type: REG = {:s}\n".format(log, c, insn.reg_name(i.reg)))
                            elif i.type == CS_OP_IMM:
                                log = ("{:s}\toperands{:d}.type: IMM = 0x{:x}\n".format(log, c, i.imm))
                            elif i.type == CS_OP_MEM:
                                log = ("{:s}\toperands{:d}.type: MEM\n".format(log, c))
                                if i.mem.segment != 0:
                                    log = ("{:s}\t\toperands{:d}.mem.segment:REG={:s}\n".format(log, c, insn.reg_name(i.mem.segment)))
                                if i.mem.base != 0:
                                    "in '[0x94]:	call	dword ptr [edi + 0x4c]' base is edi"
                                    log = ("{:s}\t\toperands{:d}.mem.base: REG={:s}\n".format(log, c, insn.reg_name(i.mem.base)))
                                if i.mem.index != 0:
                                    "in '[0x37a5]:	call	dword ptr [ecx*4 + 0x40d1b0]' index is ecx"
                                    log = ("{:s}\t\toperands{:d}.mem.index:REG={:s}\n".format(log, c, insn.reg_name(i.mem.index)))
                                if i.mem.scale != 1:
                                    "in '[0x37a5]:	call	dword ptr [ecx*4 + 0x40d1b0]' scale is 4"
                                    '[0x37a5]:	call	dword ptr [ecx*4 + 0x40d1b0]	call	operands0.type: MEM'
                                    log = ("{:s}\t\toperands{:d}.mem.scale:{:d}\n".format(log, c, i.mem.scale))
                                if i.mem.disp != 0:
                                    "in '[0xf]:	call	dword ptr [0x414324]' disp is 0x414324"
                                    log = ("{:s}\t\toperands{:d}.mem.disp: 0x{:x}\n".format(log, c, i.mem.disp))
                    capstone_branch_log.write(log)
                    capstone_redirect_branches[insn.address] = log
                        #print log
    except:
        #print("Handle invalied instruction exception")
        offset += 1

for (key, value) in distorm3_redirect_branches.items():
    if key in capstone_redirect_branches:
        print "SAME"
    else:
        print "[0x{:x}]\t{:s}".format(key, value)
"""