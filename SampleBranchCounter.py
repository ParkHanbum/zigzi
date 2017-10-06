
import binascii
from keystone import *
from capstone import *


code_rva = 0


def simple_indirect_branch_counting_function_instrument(pe_instrument, pe_manager):
    global code_rva
    allocation = pe_instrument.falloc(0x1000)
    code = ("push eax;"
            "mov eax, [{0}];"
            "inc eax;"
            "mov [{0}], eax;"
            "pop eax;"
            "ret;").format(allocation.get_va() + 4)
    code_rva = pe_instrument.append_code(code)
    code_abs_va = pe_manager.get_abs_va_from_rva(code_rva)
    allocation[0:4] = code_abs_va

    # TODO : need a way for does not calculate the relocation address directly.
    pe_manager.register_rva_to_relocation(code_rva + 1 + 1)
    pe_manager.register_rva_to_relocation(code_rva + 7 + 1)


def simple_indirect_branch_counting_function_call_instrument(instruction):
    global code_rva
    code_zero_rva = code_rva - 0x1000
    instruction_zero_rva = instruction.address
    # 5 mean instrumented code size.
    code = "CALL {:d}".format(code_zero_rva - instruction_zero_rva + 5)
    hex_code = binascii.hexlify(code).decode('hex')
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(hex_code)
        return encoding, count
    except KsError as ex:
        print("ERROR: %s" % ex)
    return None, 0
