
from PEManager import *
from pefile import *
import operator


class WindowAPIHelper(object):

    _ORDINAL_MASK_ = 0x80000000
    _COMMON_FUNCTIONS_ = {
        'USER32.DLL': {
            'MessageBoxA': 0x085A
        }
    }

    _IMPORT_ADDRESS_TABLE_RVA_ = 0x0
    _IMPORT_LOOKUP_TABLE_RVA_ = 0x1000
    _IMPORT_DESCRIPTOR_TABLE_RVA_ = 0x2000

    def __init__(self, pe_manager):
        """
        A class to help instrument the API provided by Windows.

        Args:
            pe_manager(PEManager) : target PEManager to append new imports.
        """
        self.pe = pe_manager

    def add_message_box(self):
        """
        add MessageBoxA window API to PE File.

        Returns:
            int : relative address of message box Api located in iat.
        """
        dll_name = "user32.dll"
        api_name = "MessageBoxA"
        self.pe.enable_patch_import()
        user32 = self.pe.add_library(dll_name)
        user32.add_entry(api_name)
        fn_rva = self.pe.predict_function_rva(dll_name, api_name)
        self.pe.register_api_list(dll_name, api_name,
                                  self.pe.get_abs_va_from_rva(fn_rva))
        return fn_rva
