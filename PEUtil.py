#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEUtil, Utility for parsing and modifying PE.
"""

import copy
import operator
from pefile import *


class PEUtil(object):
    def __init__(self, filename):
        """
        creator of PEUtil

        Args:
            filename (str) : file name with absolute file path.
        """
        self.PEName = filename
        pe_file = open(filename, 'r+b')
        pe_data = mmap.mmap(pe_file.fileno(), 0, access=mmap.ACCESS_COPY)
        self.PEOrigin = PE(None, data=pe_data, fast_load=False)
        self.PE = PE(None, data=pe_data, fast_load=False)
        self._IMAGE_BASE_ = self.PE.OPTIONAL_HEADER.ImageBase
        self.instrumentor = None

    def set_instrumentor(self, instrumentor):
        """
        set up instrumentor

        Args:
            instrumentor (instrumentor) : instrumentor of this file
        """
        self.instrumentor = instrumentor

    def get_instrumentor(self):
        """
        get instrumentor of current file

        Returns:
            (instrumentor) : instrumentor of current file util

        """
        return self.instrumentor

    def get_cloned_section_header(self, section):
        """
        make clone section from argument and return it.

        Args:
            section(section) : section that need clone

        Returns:
            (section) : cloned section from argument
        """
        clone_section = copy.copy(section)
        return clone_section

    def append_section_to_file(self, section):
        """
        append section to file structure.

        Args:
            section(section) : section that append to file
        """
        self.PE.sections.append(section)
        self.PE.__structures__.append(section)

    def get_file_data(self):
        """
        get data of file

        Returns:
            (bytearray) : bytearray type data of file
        """
        return self.PE.__data__

    def get_aligned_offset(self, offset):
        """
        Align offset with file alignment

        Args:
            offset(int) : offset of file

        Returns:
            int : aligned offset
        """
        file_align = self.PE.OPTIONAL_HEADER.FileAlignment
        v = offset % file_align
        if v > 0:
            return (offset - v) + file_align
        return offset

    def get_aligned_rva(self, va):
        """
        get aligned virtual address from argument.

        Args:
            va(int): virtual address for align
        Returns:
            int : aligned virtual address
        """
        aligned_va = self.get_section_alignment()
        v = va % aligned_va
        if v > 0:
            return (va - v) + aligned_va
        return va

    def append_data_to_file(self, data):
        """
        append Data to file.

        Args:
            data(bytearray) : data for append that bytearray type.
        Returns:
            (tuple): tuple containing:
                aligned_orig_data_len (int) : file data length that aligned
                aligned_data_len (int) : argument data length that aligned
        """
        orig_data_len = len(self.get_file_data())
        aligned_orig_data_len = self.get_aligned_offset(orig_data_len)
        data_len = len(data)
        aligned_data_len = self.get_aligned_offset(data_len)
        # make null space for data.
        space = bytearray((aligned_orig_data_len + aligned_data_len)
                          - orig_data_len + 1)
        self.PE.set_bytes_at_offset(orig_data_len - 1, bytes(space))
        # Fill space with data
        self.PE.set_bytes_at_offset(aligned_orig_data_len, bytes(data))
        return aligned_orig_data_len, aligned_data_len

    def create_new_executable_section(self, data):
        """
        Create new executable section with given data.

        Args:
            data(bytearray) : Raw point of new section
        """
        size_of_data = len(data)
        (pointToRaw, sizeOfRaw) = self.append_data_to_file(data)
        # TODO : Fixed the assumption that the first section is a text section.
        section = self.PE.sections[0]
        section.SizeOfRawData = sizeOfRaw
        section.PointerToRawData = pointToRaw
        section.Misc_VirtualSize = size_of_data
        section.Misc_PhysicalAddress = size_of_data
        section.Misc = size_of_data
        self.PE.OPTIONAL_HEADER.SizeOfCode = size_of_data

    def get_section_raw_data(self, section):
        """
        get raw data from section header

        Args:
            section(section) : section header that
        Returns:
            (bytearray) : data that section contain.
        """
        offset = section.PointerToRawData
        size = section.SizeOfRawData
        data = bytearray(self.get_file_data()[offset:offset + size])
        return data

    def get_entry_point_rva(self):
        """
        get Entry point virtual address of file

        Returns:
            int : entry point virtual address
        """
        return self.PE.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_text_section_virtual_address_range(self):
        """
        get Virtual address range of text section

        Returns:
            tuple.
                a tuple containing section's start and end pair.
                ( start, end )
        """
        executable_section = self.get_text_section()
        va_size = executable_section.Misc_VirtualSize
        va = executable_section.VirtualAddress
        return va, va + va_size

    def get_text_section(self):
        """
        get text section.

        Returns:
            (section) : Text section.
        """
        for currentSection in self.PE.sections:
            if currentSection.Characteristics & 0x20000000:
                return currentSection

    def get_section_alignment(self):
        """
        get section alignment.

        Returns:
            int : section alignment
        """
        return self.PE.OPTIONAL_HEADER.SectionAlignment

    def set_entry_point(self, entry_va):
        """
        Set up entry point of file

        Args:
            entry_va (int): virtual address of entry point
        """
        self.PE.OPTIONAL_HEADER.AddressOfEntryPoint = entry_va

    def write(self, file_path):
        """
        write instrumented & modified file data to file.

        Args:
            file_path (str) : file path with absolute path.
        """
        self.remove_certification()
        self.adjust_file_layout()
        self.PE.merge_modified_section_data()
        self.PE.OPTIONAL_HEADER.SizeOfImage = self.get_image_size()
        self.PE.OPTIONAL_HEADER.CheckSum = 0
        self.PE.OPTIONAL_HEADER.CheckSum = self.PE.generate_checksum()
        self.PE.write(file_path)

    def get_image_size(self):
        """
        last section's end represent that Image size.

        Returns:
            int : Image size.
        """
        section = self.PE.sections[-1]
        va = section.VirtualAddress
        size = section.Misc_VirtualSize
        return self.get_aligned_rva(va + size)

    def get_relocation(self):
        """
        get relocation elements.

        Returns:
            dict : Dict with a List containing the following items.
                - RVA(int) : address of relocation element.
                - Address(int) : address of relocation element.
                - Type(int) : type that represented by int.
        Examples:
            { Relocation block address : [RVA, Address, Type]}
        """
        relocation = {}
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            for entry in self.PE.DIRECTORY_ENTRY_BASERELOC:
                for el in entry.entries:
                    if el.struct.Data == 0:
                        continue
                    address = el.rva
                    relocation[address] = [el.rva, address, el.type]
        return relocation

    def get_relocation_from_structures(self):
        """
        get relocation elements from file structures that not parsed yet.

        Returns:
            dict
                containing relocation blocks.
                list : relocation entry
        Examples:
            { Relocation block address : [Relocation Entry]}
        """
        structures_relocation_block = {}
        structures_relocation_entries = {}
        block_va = -1
        for entry in self.PE.__structures__:
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

    def is_possible_relocation(self):
        """
        Verify that the file can be relocated.

        Returns:
            bool : True if relocation possible, False otherwise.
        """
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            return True
        return False

    def adjust_file_layout(self):
        """
        adjust broken file layout while instrumentation.
        """
        # adjust that before section adjusting
        self.adjust_entry_point()
        self.adjust_executable_section()
        # self.adjustRelocationDirectories()
        # section adjusting
        self.adjust_section()
        # adjust that after section adjusting
        self.adjust_optional_header()
        self.adjust_data_directories()

    def adjust_section(self):
        """
        instrumentation or modification can increase size of section.
        as a result, section's area can overlapped.
        that is why we need to relocate section without overlapped area.
        """
        for index in range(len(self.PE.sections) - 1):
            src_section = self.PE.sections[index]
            virtual_size = src_section.Misc_VirtualSize
            src_va = src_section.VirtualAddress
            src_va_end = src_va + virtual_size

            dst_section = self.PE.sections[index + 1]
            if src_va <= dst_section.VirtualAddress < src_va_end:
                print("adjust virtual address")
                section_va = dst_section.VirtualAddress
                adjusted_section_va = section_va + (src_va_end - section_va)
                adjusted_section_va = self.get_aligned_rva(adjusted_section_va)
                dst_section.VirtualAddress = adjusted_section_va
                src_section.next_section_virtual_address = adjusted_section_va

    def adjust_optional_header(self):
        """
        while instrumentation, it can change position of pointer recoreded in
        Optional header. for that reason that we need adjust this.
        """
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
                    adjusted_section = self.PE.sections[index]
                    self.PE.OPTIONAL_HEADER.BaseOfData = \
                        adjusted_section.VirtualAddress \
                        + base_of_data_section_rva

    def adjust_data_directories(self):
        """
        adjust element of data directories.
        """
        sections = self.PE.sections
        origin_sections = self.PEOrigin.sections
        data_directories = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY

        for index in range(len(sections)):
            section = sections[index]
            origin_section = origin_sections[index]
            data_directories = \
                self.adjust_directories(data_directories,
                                        origin_section.VirtualAddress,
                                        section.VirtualAddress,
                                        origin_section.Misc_VirtualSize,
                                        section.Misc_VirtualSize)

    def adjust_directories(self, data_directories, section_origin_va,
                           section_adjusted_va, origin_section_size,
                           adjusted_section_size):
        directory_adjust = {
            'IMAGE_DIRECTORY_ENTRY_IMPORT': self.adjust_import,
            # 'IMAGE_DIRECTORY_ENTRY_DEBUG': self.adjustDebug,
            'IMAGE_DIRECTORY_ENTRY_TLS': self.adjust_TLS,
            'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG': self.adjust_load_config,
            'IMAGE_DIRECTORY_ENTRY_EXPORT': self.adjust_export,
            'IMAGE_DIRECTORY_ENTRY_RESOURCE': self.adjust_resource,
            'IMAGE_DIRECTORY_ENTRY_BASERELOC': self.adjust_relocation,
            'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT': self.adjust_delay_import,
            'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT': self.adjust_bound_imports
        }

        remove_list = []
        increased_size = section_adjusted_va - section_origin_va
        for directory in data_directories:
            if (section_origin_va
                    <= directory.VirtualAddress
                    < (section_origin_va + origin_section_size)):
                index = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY.index(directory)
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress \
                    = directory.VirtualAddress + increased_size
                try:
                    if directory.name in directory_adjust:
                        entry = directory_adjust[directory.name]
                        entry(directory, directory.VirtualAddress,
                              directory.Size, increased_size)
                except IndexError:
                    print("===== [INDEX ERROR] =====")
                    return False
                remove_list.append(directory)
        for el in remove_list:
            data_directories.remove(el)
        return data_directories

    def remove_certification(self):
        """
        Remove cerfication of file
        """
        for index in range(len(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY)):
            directory = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            if directory.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                directory.VirtualAddress = 0
                directory.Size = 0

    def adjust_relocation(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_BASERELOC"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        self.adjust_relocation_directories()
        log = open(os.path.join(os.getcwd(), 'peutil_adjust_reloc.log'), 'w')
        relocation_dict = self.get_relocation_from_structures()
        # TODO : fix assume that first section is text.
        sections = self.PEOrigin.sections
        execute_section_start = sections[0].VirtualAddress
        execute_section_end = (execute_section_start
                               + sections[0].Misc_VirtualSize)
        other_section_start = sections[1].VirtualAddress
        other_section_end = (sections[-1:][0].VirtualAddress
                             + sections[-1:][0].Misc_VirtualSize)
        sorted_relocation_dict = sorted(relocation_dict.items(),
                                        key=operator.itemgetter(0))
        for block_va, entries in sorted_relocation_dict:
            for entry in entries:
                if entry.Data == 0x0:
                    continue
                address = (entry.Data & 0xfff) + block_va
                value = self.PE.get_dword_at_rva(address)
                if ((execute_section_start + self._IMAGE_BASE_)
                        <= value
                        < (execute_section_end + self._IMAGE_BASE_)):
                    instrumented_size = \
                        self.get_instrumentor() \
                            .get_instrumented_vector_size(value
                                                          - self._IMAGE_BASE_
                                                          - increase_size)
                    self.set_dword_at_rva(address, value + instrumented_size)
                    log.write("[IF] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                              .format(address, value,
                                      self.PE.get_dword_at_rva(address),
                                      instrumented_size))
                elif ((other_section_start + self._IMAGE_BASE_)
                        <= value
                        < (other_section_end + self._IMAGE_BASE_)):
                    self.set_dword_at_rva(address, value + increase_size)
                    log.write("[ELIF] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                              .format(address, value,
                                      self.PE.get_dword_at_rva(address),
                                      increase_size))
                else:
                    log.write("[ELSE] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                              .format(address, value,
                                      self.PE.get_dword_at_rva(address),
                                      increase_size))

    def adjust_load_config(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        size = self.PE.get_dword_at_rva(rva)
        time = self.PE.get_dword_at_rva(rva + 0x4)
        version = self.PE.get_dword_at_rva(rva + 0x8)
        global_flags_clear = self.PE.get_dword_at_rva(rva + 0xC)
        global_flags_set = self.PE.get_dword_at_rva(rva + 0x10)
        critical_section_default_timeout = self.PE.get_dword_at_rva(rva + 0x14)
        decommit_free_block_threshold = self.PE.get_dword_at_rva(rva + 0x18)
        decommit_total_free_threshold = self.PE.get_dword_at_rva(rva + 0x1C)
        Lock_Prefix_Table_VA = self.PE.get_dword_at_rva(rva + 0x20)
        Maximum_Allocation_Size = self.PE.get_dword_at_rva(rva + 0x24)
        VIrtual_Memory_Threshold = self.PE.get_dword_at_rva(rva + 0x28)
        Process_Heap_Flags = self.PE.get_dword_at_rva(rva + 0x2C)
        Process_Affinity_Mask = self.PE.get_dword_at_rva(rva + 0x30)
        CSD_Version = self.PE.get_dword_at_rva(rva + 0x34)
        Edit_List_VA = self.PE.get_dword_at_rva(rva + 0x38)

        directory_load_config = self.PE.DIRECTORY_ENTRY_LOAD_CONFIG
        if directory_load_config.struct.SecurityCookie > 0x0:
            directory_load_config.struct.SecurityCookie += increase_size
        if directory_load_config.struct.SEHandlerTable > 0x0:
            directory_load_config.struct.SEHandlerTable += increase_size
        if directory_load_config.struct.GuardCFCheckFunctionPointer > 0x0:
            directory_load_config.struct.GuardCFCheckFunctionPointer \
                += increase_size
        # Security_Cookie_VA = self.PE.get_dword_at_rva(rva + 0x3C)
        # self.setDwordAtRVA(rva + 0x3C, Security_Cookie_VA + increase_size)
        # SE_Handler_Table_VA = self.PE.get_dword_at_rva(rva + 0x40)
        # self.setDwordAtRVA(rva + 0x40, SE_Handler_Table_VA + increase_size)
        SE_Handler_Count = self.PE.get_dword_at_rva(rva + 0x44)
        return 0

    def adjust_debug(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_DEBUG"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        return 0

    def adjust_TLS(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_TLS"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        directory_tls = self.PE.DIRECTORY_ENTRY_TLS
        if directory_tls.struct.AddressOfCallBacks > 0:
            directory_tls.struct.AddressOfCallBacks \
                += increase_size
        if directory_tls.struct.AddressOfIndex > 0:
            directory_tls.struct.AddressOfIndex \
                += increase_size
        if directory_tls.struct.EndAddressOfRawData > 0:
            directory_tls.struct.EndAddressOfRawData \
                += increase_size
        if directory_tls.struct.StartAddressOfRawData > 0:
            directory_tls.struct.StartAddressOfRawData += increase_size
        return 0

    def adjust_bound_imports(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        return 0

    def adjust_delay_import(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        first_import_entry = self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0]

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
                self.get_instrumentor() \
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

    # def adjustImport(self):
    def adjust_import(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has thunk_data "IMAGE_DIRECTORY_ENTRY_IMPORT"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        for importIndex in range(len(self.PE.DIRECTORY_ENTRY_IMPORT)):
            import_entry = self.PE.DIRECTORY_ENTRY_IMPORT[importIndex]
            import_entry.struct.Characteristics += 0x1000
            import_entry.struct.FirstThunk += 0x1000
            import_entry.struct.Name += 0x1000
            import_entry.struct.OriginalFirstThunk += 0x1000
            for entry_index in range(len(import_entry.imports)):
                import_entry_element = import_entry.imports[entry_index]
                iat = import_entry_element.struct_iat
                import_entry_element.struct_table.AddressOfData += 0x1000
                import_entry_element.struct_table.ForwarderString += 0x1000
                import_entry_element.struct_table.Function += 0x1000
                import_entry_element.struct_table.Ordinal += 0x1000
                if iat:
                    # if import entry element has IAT then just adjusting.
                    import_entry_element.struct_iat.AddressOfData += 0x1000
                    import_entry_element.struct_iat.ForwarderString += 0x1000
                    import_entry_element.struct_iat.Function += 0x1000
                    import_entry_element.struct_iat.Ordinal += 0x1000
                else:
                    # if import entry element has not IAT, create new iat.
                    iat_va = import_entry_element.address \
                             - self.PE.OPTIONAL_HEADER.ImageBase \
                             + 0x1000
                    iat_size = \
                        Structure(self.PE.__IMAGE_THUNK_DATA_format__).sizeof()
                    # read data from import entry element
                    thunk_data = self.PE.get_data(iat_va, iat_size)
                    # create new IAT from data that import entry element's
                    new_iat = self.PE.__unpack_data__(
                        self.PE.__IMAGE_THUNK_DATA_format__, thunk_data,
                        file_offset=self.PE.get_offset_from_rva(iat_va))
                    # adjust new entry
                    new_iat.AddressOfData += 0x1000
                    new_iat.ForwarderString += 0x1000
                    new_iat.Function += 0x1000
                    new_iat.Ordinal += 0x1000
                    # set new IAT to import entry element.
                    import_entry_element.struct_iat = new_iat

    def adjust_export(self, directory, rva, size, increaseSize):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_EXPORT"
            rva: current directory address
            size: current directory size
            increaseSize: increased size of section that directory included
        """
        export_entry = self.PE.DIRECTORY_ENTRY_EXPORT
        export_entry_struct = export_entry.struct
        export_entry_struct.AddressOfFunctions += increaseSize
        export_entry_struct.AddressOfNameOrdinals += increaseSize
        export_entry_struct.AddressOfNames += increaseSize
        export_entry_struct.Name += increaseSize
        instrument_size = 0

        for index in range(len(export_entry.symbols)):
            entry_name_rva = export_entry_struct.AddressOfNames + (index * 4)
            name_rva = self.PE.get_dword_at_rva(entry_name_rva)
            name_rva += increaseSize
            self.set_dword_at_rva(entry_name_rva, name_rva)
            entry_fn_rva = export_entry_struct.AddressOfFunctions + (index * 4)
            fn_rva = self.PE.get_dword_at_rva(entry_fn_rva)

            # when export RVA belong other section.
            if self.PEOrigin.sections[1].VirtualAddress <= fn_rva:
                instrument_size = self.PE.sections[1].VirtualAddress \
                                  - self.PEOrigin.sections[1].VirtualAddress

            # when export RVA belong code section.
            if self.PEOrigin.sections[0].VirtualAddress \
                    <= fn_rva \
                    < self.PEOrigin.sections[1].VirtualAddress:
                instrument_size = self.get_instrumentor() \
                    .get_instrumented_vector_size(fn_rva - increaseSize)
            self.set_dword_at_rva(entry_fn_rva, fn_rva + instrument_size)

    def adjust_resource(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_RESOURCE"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        for rsrc_entries in self.PE.DIRECTORY_ENTRY_RESOURCE.entries:
            for rsrc_directory_entry in rsrc_entries.directory.entries:
                for rsrc_directory_el in rsrc_directory_entry.directory.entries:
                    rsrc_directory_el.data.struct.OffsetToData += increase_size

    def set_dword_at_rva(self, rva, dword):
        return self.PE.set_dword_at_rva(rva, dword)

    def get_section_belong_rva(self, sections, rva):
        for section in sections:
            if section.VirtualAddress \
                    <= rva \
                    < section.VirtualAddress + section.Misc_VirtualSize:
                return section

        return None

    def is_executable_section(self, section):
        """
        Whether the section is an executable.

        Args:
            section(section): Section to check
        Returns:
            bool : true if executable, false otherwise
        """
        if section.Characteristics & 0x20000000:
            return True
        return False

    def adjust_entry_point(self):
        """
        adjust entry point of file
        """
        entry_va = self.get_entry_point_rva()
        instrument_size = \
            self.get_instrumentor() \
                .get_instrumented_vector_size(entry_va - 0x1000)
        self.set_entry_point(entry_va + instrument_size)

    def adjust_executable_section(self):
        """
        create new section and append modified code data.
        """
        code_data = self.get_instrumentor().get_code()
        self.create_new_executable_section(code_data)

    def get_relocation_directories(self):
        """
        get relocation directories with its include elements.

        Returns:
            tuple : 2-Dict with relocation entries and blocks.
        """
        relocation_blocks = {}
        relocation_entries = {}
        block_va = -1
        for entry in self.PE.__structures__:
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

    def adjust_relocation_directories(self):
        """
        adjust relocation directories and its elements.
        """
        (relocationBlocks, relocationEntries) = \
            self.get_relocation_directories()
        sorted_relocation_blocks = sorted(relocationBlocks.items(),
                                          key=operator.itemgetter(0))
        sections = self.PEOrigin.sections
        # we assume first section is text section.
        pe_structure = self.PE.__structures__
        second_section_va = sections[1].VirtualAddress
        for index, (block_va, block) in enumerate(sorted_relocation_blocks):
            # first, adjust other block besides text section
            if block_va >= second_section_va:
                # 0x1000 mean increased size of section.
                pe_structure[pe_structure.index(block)].VirtualAddress += 0x1000

            # next, adjust relocation element in text section.
            elif block_va < second_section_va:
                for entry in relocationEntries[block_va]:
                    if entry.Data == 0:
                        continue
                    entry_data = entry.Data & 0x0fff
                    entry_type = entry.Data & 0xf000
                    entry_va = block_va + entry_data
                    # we assume that first section virtual address is 0x1000
                    instrumented_size = \
                        self.get_instrumentor() \
                            .get_instrumented_vector_size(entry_va - 0x1000)
                    entry_data += instrumented_size

                    # if entry RVA is overflowed (over 0x1000)
                    # move entry to appropriate block
                    if entry_data >= 0x1000:
                        pe_structure.remove(entry)
                        pe_structure[pe_structure.index(block)].SizeOfBlock -= 2
                        appropriate_block_va = (entry_data & 0xf000) + block_va
                        entry.Data = (entry_data & 0xfff) + entry_type

                        # if appropriate block address is exist.
                        if appropriate_block_va in relocationBlocks:
                            appropriate_block_index = \
                                pe_structure.index(
                                    relocationBlocks[appropriate_block_va]
                                )
                        else:
                            # create new relocation block
                            next_block_va, next_block = \
                                sorted_relocation_blocks[index + 1]
                            next_block_index = pe_structure.index(next_block)
                            new_block = copy.deepcopy(next_block)
                            new_block.SizeOfBlock = 8
                            new_block.VirtualAddress = appropriate_block_va
                            appropriate_block_index = next_block_index - 1
                            relocationBlocks[appropriate_block_va] = new_block
                            pe_structure.insert(appropriate_block_index,
                                                new_block)

                        pe_structure[appropriate_block_index].SizeOfBlock += 2
                        pe_structure.insert(appropriate_block_index + 1, entry)
                    else:
                        entry.Data = entry_data + entry_type
        self.adjust_relocation_offset()

    def adjust_relocation_offset(self):
        """
        structures has owned offset.
        so, if modify position or order of structures element
        then must fix offset of structures element.
        """
        file_offset = 0
        for entry in self.PE.__structures__:
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
