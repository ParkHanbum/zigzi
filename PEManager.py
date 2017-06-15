#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEManager, Utility for parsing and modifying PE.
"""

import copy
import operator

from pefile import *
from Log import LoggerFactory


class PEManager(object):

    def __init__(self, filename):
        """
        creator of PEManager

        Args:
            filename (str) : file name with absolute file path.
        """
        self.PEName = filename
        pe_file = open(filename, 'r+b')
        pe_data = mmap.mmap(pe_file.fileno(), 0, access=mmap.ACCESS_COPY)
        self.PEOrigin = PE(None, data=pe_data, fast_load=False)
        self.PE = PE(None, data=pe_data, fast_load=False)
        self._IMAGE_BASE_ = self.PE.OPTIONAL_HEADER.ImageBase
        self.instrument = None
        self.log = None

    def set_instrument(self, instrumentor):
        """
        set up instrument

        Args:
            (instrument) : instrument of this file
        """
        self.instrument = instrumentor

    def get_instrument(self):
        """
        get instrument of current file

        Returns:
            (instrument) : instrument of current file util

        """
        return self.instrument

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
        append data to file.

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
                          - orig_data_len)
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
        # self.PE.OPTIONAL_HEADER.SizeOfCode = size_of_data

    def create_new_data_section(self, data, name):
        if len(name) > 8:
            print("[EXCEPTION] SECTION NAME MUST LESS THEN 8 CHARACTER")
            exit()
        size_of_data = len(data)
        (pointToRaw, sizeOfRaw) = self.append_data_to_file(data)
        section = self.get_cloned_section_header(self.get_data_section())
        section.Name = name
        section.SizeOfRawData = sizeOfRaw
        section.PointerToRawData = pointToRaw
        section.Misc_VirtualSize = size_of_data
        section.Misc_PhysicalAddress = size_of_data
        section.Misc = size_of_data
        # section.Characteristics = (1 << 31) + (1 << 30) + (1 << 6)
        characteristics = \
            SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] \
            | SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] \
            | SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']
        section.Characteristics = characteristics
        section.next_section_virtual_address = None
        last_section = self.PE.sections[-1]
        rva_end = last_section.VirtualAddress + last_section.Misc_VirtualSize
        section.VirtualAddress = self.get_aligned_rva(rva_end)
        last_section_last_offset = \
            last_section.get_file_offset() + last_section.sizeof()
        section.set_file_offset(last_section_last_offset)
        self.PE.FILE_HEADER.NumberOfSections += 1
        self.append_section_to_file(section)
        return section

    def get_section_raw_data(self, section):
        """
        get raw data from section header

        Args:
            section(section) : section header that
        Returns:
            data(bytearray) : data that section contain.
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

    def _adjust_file(self):
        self._remove_certification()
        self.adjust_file_layout()
        self.PE.merge_modified_section_data()
        self.PE.OPTIONAL_HEADER.SizeOfImage = self.get_image_size()
        self.PE.OPTIONAL_HEADER.CheckSum = 0
        self.PE.OPTIONAL_HEADER.CheckSum = self.PE.generate_checksum()

    def writefile(self, file_path):
        """
        write instrumented & modified file data to file.

        Args:
            file_path (str) : file path with absolute path.
        """
        self.adjust_file_layout()
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
        self._adjust_entry_point()
        self._adjust_executable_section()
        # self.adjustRelocationDirectories()
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
        for index in range(len(self.PE.sections) - 1):
            src_section = self.PE.sections[index]
            virtual_size = src_section.Misc_VirtualSize
            src_va = src_section.VirtualAddress
            src_va_end = src_va + virtual_size

            dst_section = self.PE.sections[index + 1]
            if dst_section.VirtualAddress < src_va_end:
                print("adjust virtual address")
                section_va = dst_section.VirtualAddress
                adjusted_section_va = section_va + (src_va_end - section_va)
                adjusted_section_va = self.get_aligned_rva(adjusted_section_va)
                dst_section.VirtualAddress = adjusted_section_va
                src_section.next_section_virtual_address = adjusted_section_va

    def _adjust_optional_header(self):
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

        """ 
        Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and 
        SizeOfUninitializedData of the optional header.
        """
        optional_hdr = self.PE.OPTIONAL_HEADER
        optional_hdr.SizeOfImage = (
            self.PE.sections[-1].VirtualAddress +
            self.PE.sections[-1].Misc_VirtualSize
        )

        optional_hdr.SizeOfCode = 0
        optional_hdr.SizeOfInitializedData = 0
        optional_hdr.SizeOfUninitializedData = 0

        # Recalculating the sizes by iterating over every section and checking
        # if the appropriate characteristics are set.
        for section in self.PE.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                optional_hdr.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                optional_hdr.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                optional_hdr.SizeOfUninitializedData += section.SizeOfRawData

    def _adjust_data_directories(self):
        """
        adjust element of data directories.
        """
        sections = self.PE.sections
        origin_sections = self.PEOrigin.sections
        data_directories = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY

        for index in range(len(origin_sections)):
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

    def _remove_certification(self):
        """
        Remove certification of file
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
            rva: current directory reloc_rva
            size: current directory size
            increase_size: increased size of section that directory included
        """
        self.adjust_relocation_directories(increase_size)
        self.log = LoggerFactory().get_new_logger("AdjustRelocation2nd.log")
        relocation_dict = self.get_relocation_from_structures()
        # TODO : fix assume that first section is text.
        origin_sections = self.PEOrigin.sections
        target_sections = self.PE.sections
        execute_section_start = origin_sections[0].VirtualAddress
        execute_section_end = (execute_section_start
                               + origin_sections[0].Misc_VirtualSize)
        other_section_start = origin_sections[1].VirtualAddress
        other_section_end = (target_sections[-1:][0].VirtualAddress
                             + target_sections[-1:][0].Misc_VirtualSize)
        sorted_relocation_dict = sorted(relocation_dict.items(),
                                        key=operator.itemgetter(0))
        for block_va, entries in sorted_relocation_dict:
            for entry in entries:
                if entry.Data == 0x0:
                    continue
                reloc_rva = (entry.Data & 0xfff) + block_va
                value = self.PE.get_dword_at_rva(reloc_rva)
                if ((execute_section_start + self._IMAGE_BASE_)
                        <= value
                        < (execute_section_end + self._IMAGE_BASE_)):
                    instrumented_size = \
                        self.get_instrument() \
                            .get_instrumented_vector_size(value
                                                          - self._IMAGE_BASE_
                                                          - 0x1000)

                    structure = self.get_structure_from_rva(reloc_rva)
                    if structure is not None:
                        structure.AddressOfData = value + instrumented_size
                        # actually effect
                        structure.ForwarderString = value + instrumented_size
                        structure.Function = value + instrumented_size
                        structure.Ordinal = value + instrumented_size
                        """
                        origin = structure.__pack__()
                        temp = structure.AddressOfData
                        structure.AddressOfData = value + instrumented_size
                        if origin == structure.__pack__():
                            print("1")
                        structure.AddressOfData = temp

                        temp = structure.ForwarderString
                        structure.ForwarderString = value + instrumented_size
                        if origin == structure.__pack__():
                            print("2")
                        structure.ForwarderString = temp

                        temp = structure.Function
                        structure.Function = value + instrumented_size
                        if origin == structure.__pack__():
                            print("3")
                        structure.Function = temp

                        temp = structure.Ordinal
                        structure.Ordinal = value + instrumented_size
                        if origin == structure.__pack__():
                            print("4")
                        structure.Ordinal = temp
                        """

                    self.set_dword_at_rva(reloc_rva, value + instrumented_size)
                    self.log.log("[IF] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                                 .format(reloc_rva, value,
                                         self.PE.get_dword_at_rva(reloc_rva),
                                         instrumented_size))
                elif ((other_section_start + self._IMAGE_BASE_)
                          <= value
                          < (other_section_end + self._IMAGE_BASE_)):
                    self.set_dword_at_rva(reloc_rva, value + increase_size)
                    self.log.log(
                        "[ELIF] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                            .format(reloc_rva, value,
                                    self.PE.get_dword_at_rva(reloc_rva),
                                    increase_size)
                    )
                else:
                    try:
                        self.log.log(
                            "[ELSE] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                                .format(reloc_rva, value,
                                        self.PE.get_dword_at_rva(reloc_rva),
                                        increase_size)
                        )
                    except ValueError:
                        print("=================[ERROR]===================")
                        print(
                            "\t[ELSE] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                                .format(reloc_rva, value,
                                        self.PE.get_dword_at_rva(reloc_rva),
                                        increase_size)
                        )
                        exit()

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
            import_entry.struct.Characteristics += increase_size
            import_entry.struct.FirstThunk += increase_size
            import_entry.struct.Name += increase_size
            import_entry.struct.OriginalFirstThunk += increase_size
            for entry_index in range(len(import_entry.imports)):
                import_entry_element = import_entry.imports[entry_index]
                iat = import_entry_element.struct_iat
                import_entry_element.struct_table.AddressOfData += increase_size
                import_entry_element.struct_table.ForwarderString \
                    += increase_size
                import_entry_element.struct_table.Function += increase_size
                import_entry_element.struct_table.Ordinal += increase_size
                if iat:
                    # if import entry element has IAT then just adjusting.
                    import_entry_element.struct_iat.AddressOfData \
                        += increase_size
                    import_entry_element.struct_iat.ForwarderString \
                        += increase_size
                    import_entry_element.struct_iat.Function += increase_size
                    import_entry_element.struct_iat.Ordinal += increase_size
                else:
                    # if import entry element has not IAT, create new iat.
                    iat_va = import_entry_element.address \
                             - self.PE.OPTIONAL_HEADER.ImageBase \
                             + increase_size
                    iat_size = \
                        Structure(self.PE.__IMAGE_THUNK_DATA_format__).sizeof()
                    # read data from import entry element
                    thunk_data = self.PE.get_data(iat_va, iat_size)
                    # create new IAT from data that import entry element's
                    new_iat = self.PE.__unpack_data__(
                        self.PE.__IMAGE_THUNK_DATA_format__, thunk_data,
                        file_offset=self.PE.get_offset_from_rva(iat_va))
                    # adjust new entry
                    new_iat.AddressOfData += increase_size
                    new_iat.ForwarderString += increase_size
                    new_iat.Function += increase_size
                    new_iat.Ordinal += increase_size
                    # set new IAT to import entry element.
                    import_entry_element.struct_iat = new_iat

    def adjust_export(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory: directory that has name "IMAGE_DIRECTORY_ENTRY_EXPORT"
            rva: current directory address
            size: current directory size
            increase_size: increased size of section that directory included
        """
        self.log = LoggerFactory().get_new_logger("AdjustExport.log")
        export_entry = self.PE.DIRECTORY_ENTRY_EXPORT
        export_entry_struct = export_entry.struct
        export_entry_struct.AddressOfFunctions += increase_size
        export_entry_struct.AddressOfNameOrdinals += increase_size
        export_entry_struct.AddressOfNames += increase_size
        export_entry_struct.Name += increase_size
        instrument_size = 0

        for index in range(len(export_entry.symbols)):
            entry_name_rva = export_entry_struct.AddressOfNames + (index * 4)
            name_rva = self.PE.get_dword_at_rva(entry_name_rva)
            name_rva += increase_size
            self.set_dword_at_rva(entry_name_rva, name_rva)
            entry_fn_rva = export_entry_struct.AddressOfFunctions + (index * 4)
            fn_rva = self.PE.get_dword_at_rva(entry_fn_rva)

            # when export RVA belong other section.
            if self.PEOrigin.sections[1].VirtualAddress <= fn_rva:
                self.log.log("[OTHER]\t")
                instrument_size = self.PE.sections[1].VirtualAddress \
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

    def get_data_section(self):
        data_section = \
            self.get_section_belong_rva(self.PE.sections,
                                        self.PE.OPTIONAL_HEADER.BaseOfData)
        return data_section

    def _adjust_entry_point(self):
        """
        adjust entry point of file
        """
        entry_va = self.get_entry_point_rva()
        instrument_size = \
            self.get_instrument() \
                .get_instrumented_vector_size(entry_va - 0x1000)
        self.set_entry_point(entry_va + instrument_size)

    def _adjust_executable_section(self):
        """
        create new section and append modified code data.
        """
        code_data = self.get_instrument().get_code()
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

    def get_abs_va_from_offset(self, offset):
        rva = self.PE.get_rva_from_offset(offset)
        return self.get_abs_va_from_rva(rva)

    def get_abs_va_from_rva(self, rva):
        """
        get absolute virtual address from rva that argument.

        Args:
            rva(int) : relative address to be calculate.

        Returns:
            ava(int) : absolute address of rva.
        """
        return self.PE.OPTIONAL_HEADER.ImageBase + rva

    @staticmethod
    def get_section_belong_rva(sections, rva):
        for section in sections:
            if section.VirtualAddress \
                    <= rva \
                    < section.VirtualAddress + section.Misc_VirtualSize:
                return section
        return None

    @staticmethod
    def is_executable_section(section):
        """
        Whether the section is an executable.

        Args:
            section(section): Section to check
        Returns:
            bool : true if executable, false otherwise
        """
        if section.Characteristics \
                & SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
            return True
        return False

    @staticmethod
    def get_cloned_section_header(section):
        """
        make clone section from argument and return it.

        Args:
            section(section) : section that need clone

        Returns:
            (section) : cloned section from argument
        """
        clone_section = copy.copy(section)
        return clone_section

    def get_structure_from_rva(self, rva):
        result = None
        offset = self.PE.get_physical_by_rva(rva)
        if not offset:
            print("ERROR UNBOUNDED RVA")
            exit()
        for structure in self.PE.__structures__:
            structure_offset = structure.get_file_offset()
            if offset == structure_offset:
                result = structure
        return result

    def get_bytes_at_offset(self, offset_start, offset_stop):
        return self.PE.__data__[offset_start:offset_stop]

    def adjust_relocation_directories(self, increase_size):
        """
        adjust relocation directories and its elements.
        """
        self.log = LoggerFactory().get_new_logger("AdjustRelocation1st.log")

        sections = self.PEOrigin.sections
        pe_structure = self.PE.__structures__
        # we assume first section is text section.
        second_section_va = sections[1].VirtualAddress

        (relocationBlocks, relocationEntries) = \
            self.get_relocation_directories()
        sorted_relocation_blocks = sorted(relocationBlocks.items(),
                                          key=operator.itemgetter(0))
        for index, (block_va, block) in enumerate(sorted_relocation_blocks):
            # first, adjust other block besides text section
            if block_va >= second_section_va:
                # increase_size mean increased size of section.
                pe_structure[pe_structure.index(block)].VirtualAddress \
                    += increase_size

        (relocationBlocks, relocationEntries) = \
            self.get_relocation_directories()
        sorted_relocation_blocks = sorted(relocationBlocks.items(),
                                          key=operator.itemgetter(0))
        for index, (block_va, block) in enumerate(sorted_relocation_blocks):
            # next, adjust relocation element in text section.
            if block_va < second_section_va:
                for entry in relocationEntries[block_va]:
                    if entry.Data == 0:
                        continue
                    entry_data = entry.Data & 0x0fff
                    entry_type = entry.Data & 0xf000
                    entry_rva = block_va + entry_data
                    # we assume that first section virtual address is 0x1000
                    instrumented_size = \
                        self.get_instrument() \
                            .get_instrumented_vector_size(entry_rva - 0x1000)
                    self.log.log("[INFO] original entry rva : [0x{:x}]\t"
                                 "adjusted entry rva : [0x{:x}]\t"
                                 "entry data : 0x{:x}\t"
                                 "instrumented size ; 0x{:x}\n"
                                 .format(entry_rva,
                                         entry_rva + instrumented_size,
                                         entry_data,
                                         instrumented_size)
                                 )
                    entry_data += instrumented_size
                    # if entry RVA is overflowed (over 0x1000)
                    # move entry to appropriate block
                    if entry_data >= 0x1000:
                        pe_structure.remove(entry)
                        pe_structure[pe_structure.index(block)].SizeOfBlock -= 2
                        appropriate_block_va = (entry_data & 0xf000) + block_va
                        entry.Data = (entry_data & 0xfff) + entry_type
                        self.log.log("\t=====> entry rva : [0x{:x}]\t"
                                     "appopriate block : 0x{:x}\t"
                                     "entry data : 0x{:x}\n"
                                     .format(entry_rva,
                                             appropriate_block_va,
                                             entry_data)
                                     )
                        # if appropriate block address is exist.
                        if appropriate_block_va in relocationBlocks:
                            appropriate_block_index = \
                                pe_structure.index(
                                    relocationBlocks[appropriate_block_va]
                                )
                        else:
                            # create new relocation block
                            for _block_rva, _block \
                                    in sorted_relocation_blocks[index:]:
                                if _block_rva > appropriate_block_va:
                                    break
                            next_block_index = pe_structure.index(_block)
                            new_block = copy.deepcopy(_block)
                            new_block.SizeOfBlock = 8
                            new_block.VirtualAddress = appropriate_block_va
                            appropriate_block_index = next_block_index
                            relocationBlocks[appropriate_block_va] = new_block
                            pe_structure.insert(appropriate_block_index,
                                                new_block)

                        _block_size = \
                            pe_structure[appropriate_block_index].SizeOfBlock
                        if (_block_size - 8) > 0:
                            block_el_count = (_block_size - 8) / 2
                            pe_structure.insert(appropriate_block_index
                                                + block_el_count + 1, entry)
                        else:
                            pe_structure.insert(appropriate_block_index + 1,
                                                entry)
                        pe_structure[appropriate_block_index].SizeOfBlock += 2
                    else:
                        entry.Data = entry_data + entry_type
        self.adjust_relocation_offset()

    def register_rva_to_relocation(self, rva):
        """
        append rva to relocation list.

        Args:
            rva(int) : relative address for relocating.
        """
        block_rva = rva & 0xfffff000
        entry_rva = rva & 0xfff
        pe_structure = self.PE.__structures__

        (relocationBlocks, relocationEntries) = \
            self.get_relocation_directories()

        sorted_relocation_blocks = sorted(relocationBlocks.items(),
                                          key=operator.itemgetter(0))

        if block_rva in relocationBlocks:
            block_index = pe_structure.index(relocationBlocks[block_rva])
        else:
            block_index = self.gen_new_relocation_block(block_rva)
        # TODO : make new entry and append to Block
        entry = self.gen_new_relocation_entry(rva)
        self.append_relocation_entry_to_block(entry, block_index)

    def gen_new_relocation_block(self, block_rva):
        pe_structure = self.PE.__structures__
        (relocation_blocks, relocation_entries) \
            = self.get_relocation_directories()
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

    def gen_new_relocation_entry(self, rva):
        structure = Structure(self.PE.__IMAGE_BASE_RELOCATION_ENTRY_format__)
        setattr(structure, "Data", (rva & 0xfff) + 0x3000)
        return structure

    def append_relocation_entry_to_block(self, entry, block_index):
        pe_structure = self.PE.__structures__
        _block_size = pe_structure[block_index].SizeOfBlock
        if (_block_size - 8) > 0:
            block_entry_count = (_block_size - 8) / 2
            pe_structure.insert(block_index + block_entry_count + 1, entry)
        else:
            pe_structure.insert(block_index + 1, entry)
        pe_structure[block_index].SizeOfBlock += 2
