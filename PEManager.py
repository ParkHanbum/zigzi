#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEManager, Utility for parsing and modifying PE.
"""

import copy
import operator
import lief
from pefile import *
from Log import LoggerFactory
from struct import pack, unpack


class PEManager(object):
    """
    PEManager
    """
    def __init__(self, filename):
        """
        construct a new PEManager

        Args:
            filename (str) : file name with absolute file path.
        """
        self.PEName = filename
        pe_file = open(filename, 'r+b')
        pe_data = mmap.mmap(pe_file.fileno(), 0, access=mmap.ACCESS_COPY)
        self.pe = lief.PE.parse(filename)
        self.pe_origin = lief.PE.parse(filename)
        self.builder = lief.PE.Builder(self.pe)
        self.PEOrigin = PE(None, data=pe_data, fast_load=False)
        self.pefile = PE(None, data=pe_data, fast_load=False)
        self._IMAGE_BASE_ = self.pefile.OPTIONAL_HEADER.ImageBase
        self.instrument = None
        self.log = None
        self.origin_sections = {}
        self.api_list = {}
        self.api_rva = []

    def _append_section_to_file(self, section):
        """
        append section to file structure.

        Args:
            section(:obj:`Section`) : section that append to file
        """
        self.pefile.sections.append(section)
        self.pefile.__structures__.append(section)

    def _get_file_data(self):
        """
        get data of file

        Returns:
            :obj:`bytearray` : bytearray type data of file
        """
        return self.pefile.__data__

    def _get_aligned_offset(self, offset):
        """
        Align offset with file alignment

        Args:
            offset(int) : offset of file

        Returns:
            int : aligned offset
        """
        file_align = self._get_offset_alignment()
        v = offset % file_align
        if v > 0:
            return (offset - v) + file_align
        return offset

    def _get_aligned_rva(self, rva):
        """
        get aligned virtual address from argument.

        Args:
            rva(int): virtual address for align
        Returns:
            int : aligned virtual address
        """
        aligned_va = self._get_section_alignment()
        v = rva % aligned_va
        if v > 0:
            return (rva - v) + aligned_va
        return rva

    def _append_data_to_file(self, data):
        """
        append data to file.

        Args:
            data(bytearray) : data for append that bytearray type.
        Returns:
            :obj:`tuple`: tuple containing:
                aligned_orig_data_len(int) : file data length that aligned.\n
                aligned_data_len(int) : argument data length that aligned.
        """
        orig_data_len = len(self._get_file_data())
        aligned_orig_data_len = self._get_aligned_offset(orig_data_len)
        data_len = len(data)
        aligned_data_len = self._get_aligned_offset(data_len)
        # make null space for data.
        space = bytearray((aligned_orig_data_len + aligned_data_len)
                          - orig_data_len)
        self.pefile.set_bytes_at_offset(orig_data_len - 1, bytes(space))
        # Fill space with data
        self.pefile.set_bytes_at_offset(aligned_orig_data_len, bytes(data))
        return aligned_orig_data_len, aligned_data_len

    def _get_offset_alignment(self):
        return self.pe.optional_header.file_alignment

    def _get_section_alignment(self):
        """
        get section alignment.

        Returns:
            int : section alignment
        """
        return self.pe.optional_header.section_alignment

    def _set_entry_point(self, entry_va):
        """
        Set up entry point of file

        Args:
            entry_va (int): virtual address of entry point
        """
        self.pe.optional_header.addressof_entrypoint = entry_va

    def _adjust_file(self):
        pass
        # self._remove_certification()
        # self._adjust_file_layout()
        # self.pefile.merge_modified_section_data()
        # self.pefile.OPTIONAL_HEADER.SizeOfImage = self._get_image_size()
        # self.pefile.OPTIONAL_HEADER.CheckSum = 0
        # self.pefile.OPTIONAL_HEADER.CheckSum = self.pefile.generate_checksum()

    def _get_relocation_from_structures(self):
        """
        get relocation elements from file structures that not parsed yet.

        Returns:
            :obj:`dict`: Dict containing:
                int : relative address of relocation block. \n
                :obj:`list` : list of relocation entry. :obj:`list` containing:
                    - :obj:`Structure` : IMAGE_BASE_RELOCATION_ENTRY
        Examples:
            { Relocation block address : [Relocation Entry]}
        """
        structures_relocation_block = {}
        structures_relocation_entries = {}
        block_va = -1
        for entry in self.pefile.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if block_va > 0:
                    structures_relocation_entries[block_va].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                block_va = entry.VirtualAddress
                structures_relocation_block[block_va] = entry
                structures_relocation_entries[block_va] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"
        return structures_relocation_entries

    def _adjust_file_layout(self):
        """
        adjust broken file layout while instrumentation.
        """
        # adjust that before section adjusting
        self._adjust_entry_point()
        self._adjust_executable_section()
        # section adjusting
        self._adjust_section()
        # adjust that after section adjusting
        self._adjust_optional_header()
        self._adjust_data_directories()

    def _adjust_section(self):
        """
        instrumentation or modification can increase size of section.
        as a result, section's area can overlapped.
        that is why we need to relocate section without overlapped area.
        """
        for section in self.pe.sections:
            self.origin_sections[section.name] = section.virtual_address

        for index in range(len(self.pe.sections) - 1):
            src_section = self.pe.sections[index]
            src_offset = src_section.offset
            src_size = src_section.size
            src_offset_end = src_offset + src_size
            src_virtual_size = src_section.virtual_size
            src_va = src_section.virtual_address
            src_va_end = src_va + src_virtual_size

            dst_section = self.pe.sections[index + 1]
            dst_offset = dst_section.offset
            dst_size = dst_section.size
            dst_offset_end = dst_offset + dst_size
            dst_virtual_size = dst_section.virtual_size
            dst_va = dst_section.virtual_address
            dst_va_end = dst_va + dst_virtual_size

            if dst_va < src_va_end:
                print("adjust virtual address")
                adjusted_section_rva = dst_va + (src_va_end - dst_va)
                adjusted_section_rva = self._get_aligned_rva(adjusted_section_rva)
                dst_section.virtual_address = adjusted_section_rva
                increase_size = adjusted_section_rva - dst_va
                print("0x{:x}\t0x{:x}\t0x{:x}".
                      format(dst_va, increase_size, adjusted_section_rva))

            if dst_offset < src_offset_end:
                print("adjust offset")
                adjusted_section_offset = dst_offset + (src_offset_end - dst_offset)
                adjusted_section_offset = self._get_aligned_offset(adjusted_section_offset)
                dst_section.offset = adjusted_section_offset
                increase_size = adjusted_section_offset - dst_offset
                print("0x{:x}\t0x{:x}\t0x{:x}".
                      format(dst_offset, increase_size,
                             adjusted_section_offset))

    def _adjust_optional_header(self):
        """
        while instrumentation, it can change position of pointer recoreded in
        Optional header. for that reason that we need adjust this.
        """
        """ is this necessary?
        # adjust base of data
        if hasattr(self.PEOrigin.OPTIONAL_HEADER, 'BaseOfData'):
            base_of_data = self.PEOrigin.OPTIONAL_HEADER.BaseOfData
            for index in range(len(self.PEOrigin.sections)):
                section = self.PEOrigin.sections[index]
                if (section.VirtualAddress
                        <= base_of_data
                        < (section.VirtualAddress + section.Misc_VirtualSize)):
                    base_of_data_section_rva = base_of_data \
                                               - section.VirtualAddress
                    adjusted_section = self.pefile.sections[index]
                    self.pefile.OPTIONAL_HEADER.BaseOfData = \
                        adjusted_section.VirtualAddress \
                        + base_of_data_section_rva
        """
        """ 
        Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and 
        SizeOfUninitializedData of the optional header.
        """

        optional_hdr = self.pe.optional_header
        optional_hdr.sizeof_image = (
            self.pe.sections[len(self.pe.sections) - 1].virtual_size +
            self.pe.sections[len(self.pe.sections) - 1].size
        )

        optional_hdr.sizeof_code = 0
        optional_hdr.sizeof_initialized_data = 0
        optional_hdr.sizeof_uninitialized_data = 0

        # Recalculating the sizes by iterating over every section and checking
        # if the appropriate characteristics are set.
        for section in self.pe.sections:
            # 0x00000020
            if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE):
                # Section contains code.
                optional_hdr.sizeof_code += section.size
            # 0x00000040
            if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA):
                # Section contains initialized data.
                optional_hdr.sizeof_initialized_data += section.size
            # 0x00000080
            if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA):
                # Section contains uninitialized data.
                optional_hdr.sizeof_uninitialized_data += section.size

    def _adjust_data_directories(self):
        """
        adjust element of data directories.
        """
        directory_adjust_fn = {
            lief.PE.DATA_DIRECTORY.ARCHITECTURE: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.CLR_RUNTIME_HEADER: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.DEBUG: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.EXCEPTION_TABLE: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.GLOBAL_PTR: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.IAT: self._not_implement_yet_,
            lief.PE.DATA_DIRECTORY.BASE_RELOCATION_TABLE: self._adjust_relocation,
            # lief.PE.DATA_DIRECTORY.BOUND_IMPORT: self._adjust_bound_imports,
            # lief.PE.DATA_DIRECTORY.DELAY_IMPORT_DESCRIPTOR: self._adjust_delay_import,
            # lief.PE.DATA_DIRECTORY.IMPORT_TABLE: self._adjust_import,
            lief.PE.DATA_DIRECTORY.LOAD_CONFIG_TABLE: self._adjust_load_config,
            # lief.PE.DATA_DIRECTORY.RESOURCE_TABLE: self._adjust_resource,
            # lief.PE.DATA_DIRECTORY.TLS_TABLE: self._adjust_TLS,
        }

        for data_directory in self.pe.data_directories:
            if data_directory.has_section:
                section_cnt_data_directory = data_directory.section
                if section_cnt_data_directory.name in self.origin_sections:
                    origin_virtual_address = \
                        self.origin_sections[section_cnt_data_directory.name]
                    adjust_virtual_address = \
                        section_cnt_data_directory.virtual_address
                    if data_directory.type in directory_adjust_fn:
                        # adjust data directory elements.
                        entry = directory_adjust_fn[data_directory.type]
                        entry(data_directory, origin_virtual_address,
                              adjust_virtual_address)
                    data_directory.rva += (adjust_virtual_address
                                           - origin_virtual_address)

    def _not_implement_yet_(self, directory,
                            origin_cnt_section_rva,
                            adjust_cnt_section_rva):
        print("[{}] THIS DATA DIRECTORY IS NOT SUPPORT YET."
              .format(directory.type))

    def _adjust_load_config(self, directory,
                            origin_cnt_section_rva,
                            adjust_cnt_section_rva):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        rva = directory.rva
        increase_size = adjust_cnt_section_rva - origin_cnt_section_rva

        # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680328(v=vs.85).aspx
        size = self.pe.get_content_from_virtual_address(rva, 4)
        time = self.pe.get_content_from_virtual_address(rva + 0x4, 4)
        version = self.pe.get_content_from_virtual_address(rva + 0x8, 4)
        global_flags_clear = self.pe.get_content_from_virtual_address(rva + 0xC, 4)
        global_flags_set = self.pe.get_content_from_virtual_address(rva + 0x10, 4)
        critical_section_default_timeout = self.pe.get_content_from_virtual_address(rva + 0x14, 4)
        decommit_free_block_threshold = self.pe.get_content_from_virtual_address(rva + 0x18, 4)
        decommit_total_free_threshold = self.pe.get_content_from_virtual_address(rva + 0x1C, 4)
        Lock_Prefix_Table_VA = self.pe.get_content_from_virtual_address(rva + 0x20, 4)
        Maximum_Allocation_Size = self.pe.get_content_from_virtual_address(rva + 0x24, 4)
        VIrtual_Memory_Threshold = self.pe.get_content_from_virtual_address(rva + 0x28, 4)
        Process_Heap_Flags = self.pe.get_content_from_virtual_address(rva + 0x2C, 4)
        Process_Affinity_Mask = self.pe.get_content_from_virtual_address(rva + 0x30, 4)
        CSD_Version = self.pe.get_content_from_virtual_address(rva + 0x34, 4)
        Edit_List_VA = self.pe.get_content_from_virtual_address(rva + 0x38, 4)

        SecurityCookie = self.pe.get_content_from_virtual_address(rva + 0x3C, 4)
        SecurityCookie = unpack("<i", bytearray(SecurityCookie))[0]
        if SecurityCookie > 0:
            self.pe.patch_address(rva + 0x3C, SecurityCookie + increase_size)
        SEHandlerTable = self.pe.get_content_from_virtual_address(rva + 0x40, 4)
        SEHandlerTable = unpack("<i", bytearray(SEHandlerTable))[0]
        if SEHandlerTable > 0:
            self.pe.patch_address(rva + 0x40, SEHandlerTable + increase_size)
        SEHandlerCount = self.pe.get_content_from_virtual_address(rva + 0x44, 4)
        SEHandlerCount = unpack("<i", bytearray(SEHandlerCount))[0]
        if SEHandlerCount > 0:
            self.pe.patch_address(rva + 0x48, SEHandlerCount + increase_size)
        return 0

    def _adjust_directories(self, data_directories, origin_section_start,
                            adjust_section_start, origin_section_end,
                            adjust_section_end):
        """
        adjust directories Virtual address.

        Args:
            data_directories(:obj:`list`): data directories in PE file.
            origin_section_start(Int) : start virtual address of section.
            adjust_section_start(int) : start virtual address of adjust section.
            origin_section_end(int) : last virtual address of section.
            adjust_section_end(int) : last virtual address of adjust section.
        """
        directory_adjust = {
            # 'IMAGE_DIRECTORY_ENTRY_IMPORT': self._adjust_import,
            # 'IMAGE_DIRECTORY_ENTRY_DEBUG': self.adjustDebug,
            # 'IMAGE_DIRECTORY_ENTRY_TLS': self._adjust_TLS,
            # 'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG': self._adjust_load_config,
            # 'IMAGE_DIRECTORY_ENTRY_EXPORT': self._adjust_export,
            # 'IMAGE_DIRECTORY_ENTRY_RESOURCE': self._adjust_resource,
            # 'IMAGE_DIRECTORY_ENTRY_BASERELOC': self._adjust_relocation,
            # 'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT': self._adjust_delay_import,
            # 'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT': self._adjust_bound_imports,
            # 'IMAGE_DIRECTORY_ENTRY_IAT': self._adjust_iat,
        }

        remove_list = []
        increased_size = adjust_section_start - origin_section_start
        for directory in data_directories:
            if (origin_section_start
                    <= directory.VirtualAddress
                    < origin_section_end):
                print("{} <= {} < {}, {}"
                      .format(origin_section_start,
                              directory.VirtualAddress,
                              origin_section_end,
                              directory.name))
                index = self.pefile.OPTIONAL_HEADER.DATA_DIRECTORY.index(directory)
                self.pefile.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress \
                    = directory.VirtualAddress + increased_size
                try:
                    if directory.name in directory_adjust:
                        entry = directory_adjust[directory.name]
                        entry(directory, directory.VirtualAddress,
                              directory.Size, increased_size)
                except IndexError as e:
                    print("===== [INDEX ERROR] =====")
                    print(e)
                    exit()
                remove_list.append(directory)
        for el in remove_list:
            data_directories.remove(el)
        return data_directories

    def _remove_certification(self):
        """
        set zero to certification data directory of pe file.
        """
        for index in range(len(self.pefile.OPTIONAL_HEADER.DATA_DIRECTORY)):
            directory = self.pefile.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            if directory.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                directory.VirtualAddress = 0
                directory.Size = 0

    def _adjust_relocation(self, directory,
                           origin_cnt_section_rva,
                           adjust_cnt_section_rva):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_BASERELOC
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        increase_size = adjust_cnt_section_rva - origin_cnt_section_rva
        self.enable_rebuild_relocation()
        self._adjust_relocation_entries(increase_size)
        self._adjust_relocation_target(increase_size)

    def _get_dword_at_rva(self, rva):
        value = self.pe.get_content_from_virtual_address(rva, 4)
        return unpack("<i", bytearray(value))[0]

    def _adjust_relocation_target(self, increase_size):
        self.log = LoggerFactory().get_new_logger("adjust_relocation_target.log")
        for index, section in enumerate(self.pe_origin.sections):
            if index == 0:
                code_section_rva = section.virtual_address
                code_section_end = code_section_rva + section.size
            if index == 1:
                other_section_rva = section.virtual_address
        last_section = self.pe.sections[len(self.pe.sections) - 1]
        other_section_end = last_section.virtual_address + last_section.size
        imagebase = self.get_image_base()
        code_section_va = code_section_rva + imagebase
        code_section_end += imagebase
        other_section_va = other_section_rva + imagebase
        other_section_end += imagebase

        self.log.log("CODE_SECTION RANGE : {:x} ~ {:x}\n"
                 .format(code_section_va, code_section_end))
        self.log.log("OTHER_SECTION RANGE : {:x} ~ {:x}\n"
                 .format(other_section_va, other_section_end))

        for relocation in self.pe.relocations:
            relocation_rva = relocation.virtual_address
            for relocation_entry in relocation.entries:
                entry_rva = relocation_rva + relocation_entry.position
                relocation_target = self._get_dword_at_rva(entry_rva)
                if code_section_va <= relocation_target < code_section_end:
                    # relocation target value belong code section
                    self.log.log("code section : {:x}\n".format(relocation_target))
                    instrumented_size = \
                        self.get_instrument() \
                            .get_instrumented_vector_size(relocation_target
                                                          - self._IMAGE_BASE_
                                                          - 0x1000)
                    relocation_target += instrumented_size
                    self.pe.patch_address(entry_rva, relocation_target, 4)
                    check = self._get_dword_at_rva(entry_rva)
                    self.log.log("\tPatch : {:x}\t{:x} => {:x}\n"
                             .format(entry_rva, relocation_target, check))
                elif other_section_va <= relocation_target < other_section_end:
                    # relocation target value belong other section
                    self.log.log("other section : {:x}\n".format(relocation_target))
                    relocation_target += increase_size
                    if relocation_target in self.api_list:
                        self._register_api_address(entry_rva)
                        continue
                    self.pe.patch_address(entry_rva, relocation_target, 4)
                    check = self._get_dword_at_rva(entry_rva)
                    self.log.log("\tPatch : {:x}\t{:x} => {:x}\n"
                                 .format(entry_rva, relocation_target, check))
                else:
                    # check value for debug.
                    self.log.log("[0x{:x}] does not belong section: {:x}\n"
                             .format(entry_rva, relocation_target))
        self.log.fin()

    def _adjust_TLS(self, directory,
                    origin_cnt_section_rva,
                    adjust_cnt_section_rva):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_TLS
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        increase_size = adjust_cnt_section_rva - origin_cnt_section_rva
        directory_tls = lief.PE.TLS
        if directory_tls.addressof_callbacks > 0:
            directory_tls.addressof_callbacks += increase_size
        if directory_tls.addressof_index > 0:
            directory_tls.addressof_index += increase_size
        # TODO : addressof_raw_data is tuple contain start, end
        if directory_tls.addressof_raw_data > 0:
            directory_tls.addressof_raw_data += increase_size
        if directory_tls.addressof_raw_data > 0:
            directory_tls.addressof_raw_data += increase_size
        return 0

    def _adjust_iat(self, directory, rva, size, increase_size):
        pass

    def _adjust_bound_imports(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        return 0

    def _adjust_delay_import(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        first_import_entry = self.pefile.DIRECTORY_ENTRY_DELAY_IMPORT[0]

        first_import_entry.struct.pINT = \
            first_import_entry.struct.pINT + increase_size
        first_import_entry.struct.pIAT = \
            first_import_entry.struct.pIAT + increase_size

        first_import_entry.struct.pBoundIAT += increase_size
        first_import_entry.struct.phmod += increase_size
        first_import_entry.struct.szName += increase_size

        for import_data in first_import_entry.imports:
            iat = import_data.struct_iat
            ilt = import_data.struct_table
            address = iat.AddressOfData
            instrumented_size = \
                self.get_instrument() \
                    .get_instrumented_vector_size(address
                                                  - self._IMAGE_BASE_
                                                  - increase_size)
            iat.AddressOfData += instrumented_size
            iat.ForwarderString += instrumented_size
            iat.Function += instrumented_size
            iat.Ordinal += instrumented_size
            ilt.AddressOfData += increase_size
            ilt.ForwarderString += increase_size
            ilt.Function += increase_size
            ilt.Ordinal += increase_size

    def _adjust_import(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_IMPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        import_structures = self.get_import_structures()
        for entry in import_structures:
            if entry.name == 'IMAGE_IMPORT_DESCRIPTOR':
                if entry.OriginalFirstThunk > 0:
                    entry.OriginalFirstThunk += increase_size
                if entry.Characteristics > 0:
                    entry.Characteristics += increase_size
                if entry.FirstThunk > 0:
                    entry.FirstThunk += increase_size
                if entry.Name > 0:
                    entry.Name += increase_size
            elif entry.name == 'IMAGE_THUNK_DATA':
                if entry.Ordinal & 0x80000000:
                    # This is Ordinal import
                    pass
                else:
                    if entry.AddressOfData > 0:
                        entry.AddressOfData += increase_size
                    if entry.ForwarderString > 0:
                        entry.ForwarderString += increase_size
                    if entry.Function > 0:
                        entry.Function += increase_size

    def _adjust_export(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_EXPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        self.log = LoggerFactory().get_new_logger("AdjustExport.log")
        export_entry = self.pefile.DIRECTORY_ENTRY_EXPORT
        export_entry_struct = export_entry.struct
        export_entry_struct.AddressOfFunctions += increase_size
        export_entry_struct.AddressOfNameOrdinals += increase_size
        export_entry_struct.AddressOfNames += increase_size
        export_entry_struct.Name += increase_size
        instrument_size = 0

        for index in range(len(export_entry.symbols)):
            entry_name_rva = export_entry_struct.AddressOfNames + (index * 4)
            name_rva = self.pefile.get_dword_at_rva(entry_name_rva)
            name_rva += increase_size
            self.set_dword_at_rva(entry_name_rva, name_rva)
            entry_fn_rva = export_entry_struct.AddressOfFunctions + (index * 4)
            fn_rva = self.pefile.get_dword_at_rva(entry_fn_rva)

            # when export RVA belong other section.
            if self.PEOrigin.sections[1].VirtualAddress <= fn_rva:
                self.log.log("[OTHER]\t")
                instrument_size = self.pefile.sections[1].VirtualAddress \
                                  - self.PEOrigin.sections[1].VirtualAddress

            # when export RVA belong code section.
            if self.PEOrigin.sections[0].VirtualAddress \
                    <= fn_rva \
                    < self.PEOrigin.sections[1].VirtualAddress:
                self.log.log("[CODE]\t")
                instrument_size = self.get_instrument() \
                    .get_instrumented_vector_size(fn_rva - 0x1000)
            self.set_dword_at_rva(entry_fn_rva, fn_rva + instrument_size)
            self.log.log("{:x}\t{:x}\n".format(fn_rva, instrument_size))

    def _adjust_resource(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_RESOURCE
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        for rsrc_entries in self.pefile.DIRECTORY_ENTRY_RESOURCE.entries:
            for rsrc_directory_entry in rsrc_entries.directory.entries:
                for rsrc_directory_el in rsrc_directory_entry.directory.entries:
                    rsrc_directory_el.data.struct.OffsetToData += increase_size

    def _adjust_entry_point(self):
        """
        adjust entry point of file
        """
        entry_va = self.get_entry_point_va()
        instrument_size = \
            self.get_instrument() \
                .get_instrumented_vector_size(entry_va - 0x1000)
        self._set_entry_point(entry_va + instrument_size)

    def _adjust_executable_section(self):
        """
        create new section and append modified code data.
        """
        code_data = self.get_instrument().get_code()
        self.pe.sections[0].virtual_size = (len(code_data))
        self.pe.sections[0].sizeof_raw_data = (len(code_data))
        self.pe.sections[0].content = code_data

    def _get_relocation_directories(self):
        """
        get relocation directories with its include elements.

        Returns:
            :obj:`tuple`: tuple containing:
                :obj:`dict` : relocation blocks
                    - block address(int) : address of block
                    - block entry(:obj:`Structure`) : IMAGE_BASE_RELOCATION
                :obj:`dict` : relocation entry
                    - block address(int) : The block address to which the entry belongs
                    - relocation entry(:obj:`Structure`) : IMAGE_BASE_RELOCATION_ENTRY
        """
        relocation_blocks = {}
        relocation_entries = {}
        block_va = -1
        for entry in self.pefile.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if block_va > 0:
                    relocation_entries[block_va].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                block_va = entry.VirtualAddress
                relocation_blocks[block_va] = entry
                relocation_entries[block_va] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"
        return relocation_blocks, relocation_entries

    def _adjust_relocation_offset(self):
        """
        structures has owned offset.
        so, if modify position or order of structures element
        then must fix offset of structures element.
        """
        file_offset = 0
        for entry in self.pefile.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                entry.set_file_offset(file_offset)
                file_offset += 2
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                if file_offset == 0:
                    file_offset = entry.get_file_offset()
                entry.set_file_offset(file_offset)
                file_offset += 8
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                'DIRECTORY_ENTRY_BASERELOC'

    def _get_structure_from_rva(self, rva):
        """
        Find the structure located in rva.

        Args:
            rva(int) : relative address.

        Returns:
            :obj:`Structure` : structure that has located in rva.
        """
        result = None
        offset = self.pefile.get_physical_by_rva(rva)
        if not offset:
            print("ERROR UNBOUNDED RVA")
            exit()
        for structure in self.pefile.__structures__:
            structure_offset = structure.get_file_offset()
            if offset == structure_offset:
                result = structure
                break
        return result

    def _adjust_relocation_entries(self, increase_size):
        """
        adjust relocation directories and its entries.
        """
        self.log = LoggerFactory().get_new_logger("adjust_relocation_entries.log")
        relocation_rva = []
        # TODO : current working with relocation is only support type 3
        for relocation in self.pe.relocations:
            for relocation_entry in relocation.entries:
                if relocation_entry.position > 0:
                    entry_rva = relocation_entry.position \
                                + relocation.virtual_address
                    relocation_rva.append(entry_rva)

        adjusted_relocation_rva = []
        for rva in relocation_rva:
            adjusted_relocation_rva.append(
                self._adjust_relocation_rva(rva, increase_size)
            )

        build_relocation = {}
        for rva in adjusted_relocation_rva:
            relocation_block_rva = rva & 0xfffff000
            if not (relocation_block_rva in build_relocation):
                # if relocation does not exist then make relocation first.
                relocation_block_new = lief.PE.Relocation()
                relocation_block_new.virtual_address = relocation_block_rva
                build_relocation[relocation_block_rva] = relocation_block_new
            # append rva as relocation entry to relocation.
            relocation_entry = self.gen_relocation_entry_from_rva(rva)
            build_relocation[relocation_block_rva].add_entry(relocation_entry)

        self.pe.remove_all_relocations()
        for rva, relocation in build_relocation.items():
            self.pe.add_relocation(relocation)

    def gen_relocation_entry_from_rva(self, rva):
        relocation_position = rva & 0xfff
        relocation_entry_new = lief.PE.RelocationEntry()
        relocation_entry_new.type = lief.PE.RELOCATIONS_BASE_TYPES(3)
        relocation_entry_new.position = relocation_position
        return relocation_entry_new

    def _get_code_section_end(self):
        (rva, rva_end) = self.get_text_section_virtual_address_range()
        return rva_end

    def _adjust_relocation_rva(self, relocation_rva, increase_size):
        code_section_end = self._get_code_section_end()
        # we assume that first section virtual address is 0x1000
        instrumented_size = self.get_instrument() \
            .get_instrumented_vector_size(relocation_rva - 0x1000)

        if relocation_rva + instrumented_size <= code_section_end:
            # if code section include relocation rva.
            self.log.log("[CODE] original entry rva : [0x{:x}]\t"
                         "adjusted entry rva : [0x{:x}]\t"
                         "instrumented size ; 0x{:x}\n"
                         .format(relocation_rva,
                                 relocation_rva + instrumented_size,
                                 instrumented_size)
                         )
            relocation_rva += instrumented_size
        else:
            # otherwise, relocation rva not belong code section.
            self.log.log("[OTHER] original entry rva : [0x{:x}]\t"
                         "adjusted entry rva : [0x{:x}]\t"
                         "instrumented size ; 0x{:x}\n"
                         .format(relocation_rva,
                                 relocation_rva + increase_size,
                                 increase_size)
                         )
            relocation_rva += increase_size
        return relocation_rva

    def _relocation_entry_move_to_appropriate_block(self, entry, block,
                                                    increase_size):
        """
        move relocation entry to appropriate relocation block.

        Args:
            entry(Structure) : IMAGE_BASE_RELOCATION_ENTRY
            block(Structure) : IMAGE_BASE_RELOCATION
            increase_size(int) : size to move the entry
        """
        pe_structure = self.pefile.__structures__
        # we assume first section is text section.
        # code section's address end that increased by instrument.
        instrumented_code_section_end = self.pefile.sections[0].VirtualAddress \
                                        + self.pefile.sections[0].Misc_VirtualSize
        entry_data = entry.Data & 0x0fff
        entry_type = entry.Data & 0xf000
        block_va = block.VirtualAddress
        entry_rva = block_va + entry_data

        # we assume that first section virtual address is 0x1000
        instrumented_size = self.get_instrument() \
            .get_instrumented_vector_size(entry_rva - 0x1000)
        if entry_rva + instrumented_size <= instrumented_code_section_end:
            self.log.log("[INFO] original entry rva : [0x{:x}]\t"
                         "adjusted entry rva : [0x{:x}]\t"
                         "entry data : 0x{:x}\t"
                         "instrumented size ; 0x{:x}\n"
                         .format(entry_data + block_va,
                                 entry_rva + instrumented_size,
                                 entry_data, instrumented_size))
            # if entry RVA is overflowed (over 0x1000)
            # then move entry to appropriate block
            entry_data += instrumented_size
            if entry_data >= 0x1000:
                pe_structure.remove(entry)
                pe_structure[pe_structure.index(block)].SizeOfBlock -= 2
                self.register_rva_to_relocation(entry_data + block_va)
            else:
                entry.Data = entry_data + entry_type
        else:
            entry_data += increase_size
            pe_structure.remove(entry)
            pe_structure[pe_structure.index(block)].SizeOfBlock -= 2
            self.register_rva_to_relocation(entry_data + block_va)
            self.log.log("[OTHER] original entry rva : [0x{:x}]\t"
                         "adjusted entry rva : [0x{:x}]\t"
                         "entry data : 0x{:x}\t"
                         "instrumented size ; 0x{:x}\n"
                         .format(entry_rva, entry_data + block_va,
                                 entry_data, increase_size))

    def _gen_new_relocation_block(self, block_rva):
        """
        generate new relocation block that cover rva.
        Args:
            block_rva: relative address that has covered by new block.

        Returns:
            int : index of generated block.
        """
        pe_structure = self.pefile.__structures__
        (relocation_blocks, relocation_entries) \
            = self._get_relocation_directories()
        sorted_relocation_blocks = sorted(relocation_blocks.items(),
                                          key=operator.itemgetter(0))
        for _block_rva, _block in sorted_relocation_blocks:
            if _block_rva > block_rva:
                break
        next_block_index = pe_structure.index(_block)
        new_block = copy.deepcopy(_block)
        new_block.SizeOfBlock = 8
        new_block.VirtualAddress = block_rva
        block_index = next_block_index
        relocation_blocks[block_rva] = new_block
        pe_structure.insert(block_index, new_block)
        return block_index

    def _gen_new_relocation_entry(self, rva):
        """
        Create a relocation entry for rva.

        Args:
            rva(int) : relative address.

        Returns:
            :obj:`Structure` : IMAGE_BASE_RELOCATION_ENTRY
        """
        structure = Structure(self.pefile.__IMAGE_BASE_RELOCATION_ENTRY_format__)
        setattr(structure, "Data", (rva & 0xfff) + 0x3000)
        return structure

    def _append_relocation_entry_to_block(self, entry, block_index):
        """
        append relocation entry to appropriate relocation block.

        Args:
            entry(Structure) : entry to be append.
            block_index(int) : index of block.
        """
        pe_structure = self.pefile.__structures__
        _block_size = pe_structure[block_index].SizeOfBlock
        if (_block_size - 8) > 0:
            block_entry_count = (_block_size - 8) / 2
            pe_structure.insert(block_index + block_entry_count + 1, entry)
        else:
            pe_structure.insert(block_index + 1, entry)
        pe_structure[block_index].SizeOfBlock += 2

    @staticmethod
    def _get_cloned_section_header(section):
        """
        make clone section from argument and return it.

        Args:
            section(:obj:`Section`) : section that need clone

        Returns:
            :obj:`Section` : cloned section from argument
        """
        clone_section = copy.copy(section)
        return clone_section

    def _create_new_executable_section(self, data):
        """
        Create new executable section with given data.

        Args:
            data(bytearray) : Raw point of new section
        """
        size_of_data = len(data)
        (pointToRaw, sizeOfRaw) = self._append_data_to_file(data)
        # TODO : Fixed the assumption that the first section is a text section.
        section = self.pefile.sections[0]
        section.SizeOfRawData = sizeOfRaw
        section.PointerToRawData = pointToRaw
        section.Misc_VirtualSize = size_of_data
        section.Misc_PhysicalAddress = size_of_data
        section.Misc = size_of_data
        # self.PE.OPTIONAL_HEADER.SizeOfCode = size_of_data

    def set_instrument(self, instrumentor):
        """
        set up instrument

        Args:
            instrumentor(:obj:`PEInstrument`) : instrument of this file
        """
        self.instrument = instrumentor

    def get_instrument(self):
        """
        get instrument of current file

        Returns:
            :obj:`PEInstrument` : instrument of current file util
        """
        return self.instrument

    def adjust_relocation_data_in_scope(self, start, end, increase_size):
        """
        Adjust the values of data belonging to a specific scope.

        Args:
            start(int) : start of scope.
            end(int) : end of scope.
            increase_size(int): the size to be adjust.
        """
        for relocation_block in self.pe.relocations:
            for relocation_entry in relocation_block.entries:
                relocation_rva = relocation_block.virtual_address \
                                 + relocation_entry.position
                value = \
                    self.pe.get_content_from_virtual_address(relocation_rva, 4)
                if ((start + self._IMAGE_BASE_)
                        <= value
                        < (end + self._IMAGE_BASE_)):
                    self.pe.patch_address(relocation_rva, value + increase_size)

    def get_last_section(self):
        return self.pe.sections[len(self.pe.sections) - 1]

    def create_new_data_section(self, data, name):
        """
        Create a new data section and add it to the last section.

        Args:
            data(bytearray) : data for append to section.
            name(str) : name of section.

        Returns:
            :obj:`Section` : new section that created.
        """
        if len(name) > 8:
            print("[EXCEPTION] SECTION NAME MUST LESS THEN 8 CHARACTER")
            exit()

        section_last = self.get_last_section()
        section_last_rva = section_last.virtual_address \
                           + section_last.virtual_size
        section_new_rva = self._get_aligned_rva(section_last_rva)
        section_new = lief.PE.Section(name)
        section_new.content = data
        section_new.virtual_address = section_new_rva    # choose by lief
        section_new.characteristics = \
            lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA \
            | lief.PE.SECTION_CHARACTERISTICS.MEM_READ
        self.pe.add_section(section_new)
        return section_new

    def set_bytes_at_rva(self, rva, bytes):
        self.pe.patch_address(rva, bytes)

    def set_dword_at_rva(self, rva, dword):
        """
        set dword at rva.

        Args:
            rva(int) : relative address.
            dword(int) : 4-bytes int value.
        """
        self.pe.patch_address(rva, dword)

    def get_data_from_rva(self, rva, size):
        return self.pe.get_content_from_virtual_address(rva, size)

    def get_section_raw_data(self, section):
        """
        get raw data from section header

        Args:
            section(Section) : section header that
        Returns:
            :obj:`bytearray` : data that section contain.
        """
        offset = section.PointerToRawData
        size = section.SizeOfRawData
        data = bytearray(self._get_file_data()[offset:offset + size])
        return data

    def get_entry_point_va(self):
        """
        get Entry point virtual address of file

        Returns:
            int : entry point virtual address
        """
        return self.pe.optional_header.addressof_entrypoint

    def get_text_section_virtual_address_range(self):
        """
        get Virtual address range of text section

        Returns:
            :obj:`tuple` : tuple containing :
                - int : the start address of section. \n
                - int : the end address of section.
        """
        executable_section = self.get_text_section()
        va_size = executable_section.size
        va = executable_section.virtual_address
        return va, va + va_size

    def get_text_section(self):
        """
        get text section.

        Returns:
            :obj:`section` : Text section.
        """
        code_rva = self.pe.optional_header.baseof_code
        code_section = self.pe.section_from_rva(code_rva)
        return code_section

    def get_relocation(self):
        """
        get relocation elements.

        Returns:
            :obj:`dict` : Dict containing:
                int : address of relocation block\n
                :obj:`list` : relocation block info. list containing:
                    - int : relative address of relocation element.
                    - int : address of relocation element.
                    - int : type that represented by int.
        """
        relocation_dict = {}
        for relocation in self.pe.relocations:
            entries = []
            for relocation_entry in relocation.entries:
                entries.append(relocation_entry)
            relocation_dict[relocation.virtual_address] = entries
        return relocation_dict

    def get_import_structures(self):
        """
        get import lists of pe file.

        Returns:
            :obj:`list` : containing structures of import :
                :obj:`Structure`: IMAGE_IMPORT_DESCRIPTOR or IMAGE_THUNK_DATA
        """
        imports_start_index = 0
        imports_end_index = 0

        for index, structure in enumerate(self.pefile.__structures__):
            if ((structure.name == 'IMAGE_IMPORT_DESCRIPTOR')
                    == (structure.name == 'IMAGE_THUNK_DATA')):
                if imports_start_index > 0:
                    imports_end_index = index
                    break
            else:
                if imports_start_index == 0:
                    imports_start_index = index
        return self.pefile.__structures__[imports_start_index:imports_end_index]

    def get_imports_range_in_structures(self):
        """
        start and end index of import at structures.

        Returns:
            :obj:`tuple` : tuple containing:
                - int : start index of import at structures.
                - int : last index of import at structures.
        """
        imports_start_index = 0
        imports_end_index = 0

        for index, structure in enumerate(self.pefile.__structures__):
            if ((structure.name == 'IMAGE_IMPORT_DESCRIPTOR')
                    == (structure.name == 'IMAGE_THUNK_DATA')):
                if imports_start_index > 0:
                    imports_end_index = index
                    break
            else:
                if imports_start_index == 0:
                    imports_start_index = index
        return imports_start_index, imports_end_index

    def get_data_section(self):
        """
        get data section of PE.

        Returns:
            :obj:`Section` : data section of PE.
        """
        data_section = \
            self.get_section_belong_rva(self.pefile.OPTIONAL_HEADER.BaseOfData)
        return data_section

    def get_data_directory_address_range(self, entry_name):
        """
        Gets the scope of the data directory with the given name as an argument.

        Args:
            entry_name(str) : name of data directory to find.

        Returns:
            :obj:`tuple` : tuple containing :
                - int : Virtual address of data directory.
                - int : Size of data directory.
        """
        for entry in self.pefile.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == entry_name:
                return entry.VirtualAddress, entry.Size

    def get_abs_va_from_rva(self, rva):
        """
        get absolute virtual address from rva that argument.

        Args:
            rva(int) : relative address to be calculate.

        Returns:
            int : absolute address from rva.
        """
        return self.pe.optional_header.imagebase + rva

    def get_image_base(self):
        """
        get address of image base.

        Returns:
            int : virtual address of image base.
        """
        return self.pe.optional_header.imagebase

    def get_import_descriptor_address_range(self):
        """
        Gets the scope of the import descriptor.

        Returns:
            :obj:`tuple` :
                - int : Virtual address of import descriptor.
                - int : Size of import data descriptor.
        """
        return self.get_data_directory_address_range('IMAGE_DIRECTORY_ENTRY_IMPORT')

    def get_import_address_table_address_range(self):
        """
        Gets the scope of the import address table.

        Returns:
            :obj:`tuple` :
                - int : Virtual address of import address table.
                - int : Size of import data address table.
        """
        return self.get_data_directory_address_range('IMAGE_DIRECTORY_ENTRY_IAT')

    def get_section_belong_rva(self, rva):
        """
        Find the section containing rva.

        Args:
            rva(int) : rva for find section.

        Returns:
            :obj:`Section` : the Section to which the given relative address as argument belongs.
        """
        return self.pe.section_from_rva(rva)

    def get_bytes_at_offset(self, offset_start, offset_stop):
        return self.pefile.__data__[offset_start:offset_stop]

    def gen_new_empty_import_descriptor(self):
        """
        generate new import descriptor that has empty.

        Returns:
            :obj:`Structure` : IMPORT_DESCRIPTOR
        """
        structure = Structure(self.pefile.__IMAGE_IMPORT_DESCRIPTOR_format__)
        return structure

    def gen_new_empty_import_thunk(self):
        """
        generate new import descriptor that has empty.

        Returns:
            :obj:`Structure` : IMPORT_THUNK
        """
        structure = Structure(self.pefile.__IMAGE_THUNK_DATA_format__)
        return structure

    def is_relocatable(self):
        """
        Verify that the file can be relocated.

        Returns:
            bool : True if relocation possible, False otherwise.
        """
        return self.pe.has_relocations

    def register_rva_to_relocation(self, rva):
        """
        append rva to relocation list.
        if appropriate block is not exist, then append it after make new block.

        Args:
            rva(int) : relative address for relocating.
        """
        block_rva = rva & 0xfffff000
        position = rva & 0x00000fff

        relocation_entry_new = None
        for relocation in self.pe.relocations:
            if relocation.virtual_address == block_rva:
                relocation_entry_new = lief.PE.RelocationEntry()
                relocation_entry_new.type = lief.PE.RELOCATIONS_BASE_TYPES.HIGHLOW
                relocation_entry_new.position = position
                relocation.add_entry(relocation_entry_new)

        if relocation_entry_new is None:
            relocation_entry_new = lief.PE.RelocationEntry()
            relocation_entry_new.type = lief.PE.RELOCATIONS_BASE_TYPES.HIGHLOW
            relocation_entry_new.position = position
            relocation_block_new = lief.PE.Relocation()
            relocation_block_new.virtual_address = block_rva
            relocation_block_new.add_entry(relocation_entry_new)
            self.pe.add_relocation(relocation_block_new)

    def writefile(self, file_path):
        """
        write instrumented & modified file data to file.

        Args:
            file_path (str) : file path with absolute path.
        """
        self._adjust_file_layout()
        self.builder.build()
        self.adjust_register_api()
        self.disable_patch_import()
        self.disable_rebuild_relocation()
        self.builder.build()
        self.builder.write(file_path)

    def writefile_without_adjust(self, file_path):
        """
        write file data to file.

        Args:
            file_path(str) : file name with its absolute path.
        """
        self.builder.build()
        self.builder.write(file_path)

    def enable_patch_import(self):
        self.builder.build_imports(True).patch_imports(True)

    def disable_patch_import(self):
        self.builder.build_imports(False).patch_imports(False)

    def enable_rebuild_relocation(self):
        self.builder.build_relocations(True)

    def disable_rebuild_relocation(self):
        self.builder.build_relocations(False)

    def add_library(self, lib_name):
        return self.pe.add_library(lib_name)

    def predict_function_rva(self, lib_name, fn_name):
        return self.pe.predict_function_rva(lib_name, fn_name)

    def _register_api_address(self, entry_rva):
        self.api_rva.append(entry_rva)

    def register_api_list(self, dll_name, api_name, fn_va):
        self.api_list[fn_va] = (dll_name, api_name)

    def adjust_register_api(self):
        for entry_rva in self.api_rva:
            bound_api_rva = self._get_dword_at_rva(entry_rva)
            if bound_api_rva in self.api_list:
                (dll_name, api_name) = self.api_list[bound_api_rva]
                api_rva = self.predict_function_rva(dll_name, api_name)
                self.pe.patch_address(entry_rva,
                                      self.get_abs_va_from_rva(api_rva)
                                      - 0x1000,
                                      4)
