#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEManager, Utility for parsing and modifying PE.
"""

import copy
import operator

from pefile import *
from Log import LoggerFactory


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
        self.PEOrigin = PE(None, data=pe_data, fast_load=False)
        self.PE = PE(None, data=pe_data, fast_load=False)
        self._IMAGE_BASE_ = self.PE.OPTIONAL_HEADER.ImageBase
        self.instrument = None
        self.log = None
        self.section_prev_adjust = None

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

    def append_section_to_file(self, section):
        """
        append section to file structure.

        Args:
            section(:obj:`Section`) : section that append to file
        """
        self.PE.sections.append(section)
        self.PE.__structures__.append(section)

    def get_file_data(self):
        """
        get data of file

        Returns:
            :obj:`bytearray` : bytearray type data of file
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
            :obj:`tuple`: tuple containing:
                aligned_orig_data_len(int) : file data length that aligned.\n
                aligned_data_len(int) : argument data length that aligned.
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
            section(Section) : section header that
        Returns:
            :obj:`bytearray` : data that section contain.
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
            :obj:`tuple` : tuple containing :
                - int : the start address of section. \n
                - int : the end address of section.
        """
        executable_section = self.get_text_section()
        va_size = executable_section.Misc_VirtualSize
        va = executable_section.VirtualAddress
        return va, va + va_size

    def get_text_section(self):
        """
        get text section.

        Returns:
            :obj:`section` : Text section.
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

    def writefile_without_adjust(self, file_path):
        """
        write file data to file.

        Args:
            file_path(str) : file name with its absolute path.
        """
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
            :obj:`dict` : Dict containing:
                int : address of relocation block\n
                :obj:`list` : relocation block info. list containing:
                    - int : relative address of relocation element.
                    - int : address of relocation element.
                    - int : type that represented by int.
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

    def get_import_structures(self):
        """
        get import lists of pe file.

        Returns:
            :obj:`list` : containing structures of import :
                :obj:`Structure`: IMAGE_IMPORT_DESCRIPTOR or IMAGE_THUNK_DATA
        """
        imports_start_index = 0
        imports_end_index = 0

        for index, structure in enumerate(self.PE.__structures__):
            if ((structure.name == 'IMAGE_IMPORT_DESCRIPTOR')
                    == (structure.name == 'IMAGE_THUNK_DATA')):
                if imports_start_index > 0:
                    imports_end_index = index
                    break
            else:
                if imports_start_index == 0:
                    imports_start_index = index
        return self.PE.__structures__[imports_start_index:imports_end_index]

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

        for index, structure in enumerate(self.PE.__structures__):
            if ((structure.name == 'IMAGE_IMPORT_DESCRIPTOR')
                    == (structure.name == 'IMAGE_THUNK_DATA')):
                if imports_start_index > 0:
                    imports_end_index = index
                    break
            else:
                if imports_start_index == 0:
                    imports_start_index = index
        return imports_start_index, imports_end_index

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
        self.section_prev_adjust = copy.deepcopy(self.PE.sections)
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
        origin_sections = self.section_prev_adjust
        data_directories = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY

        for index in range(len(origin_sections)):
            section = sections[index]
            origin_section = origin_sections[index]
            origin_section_start = origin_section.VirtualAddress
            if index + 1 < len(origin_sections):
                origin_section_end = origin_sections[index + 1].VirtualAddress
            else:
                origin_section_end = origin_section.VirtualAddress + \
                                     origin_section.Misc_VirtualSize
            data_directories = \
                self.adjust_directories(data_directories,
                                        origin_section_start,
                                        section.VirtualAddress,
                                        origin_section_end,
                                        section.Misc_VirtualSize)

    def adjust_directories(self, data_directories, origin_section_start,
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
            'IMAGE_DIRECTORY_ENTRY_IMPORT': self.adjust_import,
            # 'IMAGE_DIRECTORY_ENTRY_DEBUG': self.adjustDebug,
            'IMAGE_DIRECTORY_ENTRY_TLS': self.adjust_TLS,
            'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG': self.adjust_load_config,
            'IMAGE_DIRECTORY_ENTRY_EXPORT': self.adjust_export,
            'IMAGE_DIRECTORY_ENTRY_RESOURCE': self.adjust_resource,
            'IMAGE_DIRECTORY_ENTRY_BASERELOC': self.adjust_relocation,
            'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT': self.adjust_delay_import,
            'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT': self.adjust_bound_imports,
            'IMAGE_DIRECTORY_ENTRY_IAT': self.adjust_iat,
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
                index = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY.index(directory)
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress \
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
        for index in range(len(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY)):
            directory = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            if directory.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                directory.VirtualAddress = 0
                directory.Size = 0

    def adjust_relocation(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_BASERELOC
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
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
                    self.log.log("[1] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                                 .format(reloc_rva, value,
                                         self.PE.get_dword_at_rva(reloc_rva),
                                         instrumented_size))
                elif ((other_section_start + self._IMAGE_BASE_)
                        <= value
                        < (other_section_end + self._IMAGE_BASE_)):
                    self.set_dword_at_rva(reloc_rva, value + increase_size)
                    self.log.log(
                        "[2] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                            .format(reloc_rva, value,
                                    self.PE.get_dword_at_rva(reloc_rva),
                                    increase_size)
                    )
                else:
                    try:
                        self.log.log(
                            "[3] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n"
                                .format(reloc_rva, value,
                                        self.PE.get_dword_at_rva(reloc_rva),
                                        increase_size)
                        )
                    except ValueError as e:
                        print("=================[ERROR]===================")
                        print(e)
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
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
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
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_DEBUG
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        return 0

    def adjust_TLS(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_TLS
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
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

    def adjust_iat(self, directory, rva, size, increase_size):
        pass

    def adjust_bound_imports(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        return 0

    def adjust_delay_import(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
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

    def adjust_export(self, directory, rva, size, increase_size):
        """
        adjust relocation directory's elements.

        Args:
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_EXPORT
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
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
            directory(:obj:`Structure`): IMAGE_DIRECTORY_ENTRY_RESOURCE
            rva(int): current directory's relative virtual address.
            size(int): current directory's size.
            increase_size(int): increased size of section that directory included.
        """
        for rsrc_entries in self.PE.DIRECTORY_ENTRY_RESOURCE.entries:
            for rsrc_directory_entry in rsrc_entries.directory.entries:
                for rsrc_directory_el in rsrc_directory_entry.directory.entries:
                    rsrc_directory_el.data.struct.OffsetToData += increase_size

    def set_dword_at_rva(self, rva, dword):
        """
        set dword at rva.

        Args:
            rva(int) : relative address.
            dword(bytes) : 4-bytes type value.
        """
        return self.PE.set_dword_at_rva(rva, dword)

    def get_data_section(self):
        """
        get data section of PE.

        Returns:
            :obj:`Section` : data section of PE.
        """
        data_section = \
            self.get_section_belong_rva(self.PE.OPTIONAL_HEADER.BaseOfData)
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
        """
        calculate absolute virtual address from offset.

        Args:
            offset(int) : offset of file.

        Returns:
            int : absolute address to match offset.
        """
        rva = self.PE.get_rva_from_offset(offset)
        return self.get_abs_va_from_rva(rva)

    def get_abs_va_from_rva(self, rva):
        """
        get absolute virtual address from rva that argument.

        Args:
            rva(int) : relative address to be calculate.

        Returns:
            int : absolute address from rva.
        """
        return self.PE.OPTIONAL_HEADER.ImageBase + rva

    def get_image_base(self):
        """
        get address of image base.

        Returns:
            int : virtual address of image base.
        """
        return self.PE.OPTIONAL_HEADER.ImageBase

    def get_structure_from_rva(self, rva):
        """
        Find the structure located in rva.

        Args:
            rva(int) : relative address.

        Returns:
            :obj:`Structure` : structure that has located in rva.
        """
        result = None
        offset = self.PE.get_physical_by_rva(rva)
        if not offset:
            print("ERROR UNBOUNDED RVA")
            exit()
        for structure in self.PE.__structures__:
            structure_offset = structure.get_file_offset()
            if offset == structure_offset:
                result = structure
                break
        return result

    def get_bytes_at_offset(self, offset_start, offset_stop):
        return self.PE.__data__[offset_start:offset_stop]

    def adjust_relocation_directories(self, increase_size):
        """
        adjust relocation directories and its elements.
        """
        self.log = LoggerFactory().get_new_logger("AdjustRelocation1st.log")
        relocation_blocks, relocation_entries = \
            self.get_relocation_directories()
        sorted_relocation_blocks = sorted(relocation_blocks.items(),
                                          key=operator.itemgetter(0))
        for index, (block_va, block) in enumerate(sorted_relocation_blocks):
            for entry in relocation_entries[block_va]:
                if entry.Data == 0:
                    continue
                self.relocation_entry_move_to_appropriate_block(entry, block,
                                                                increase_size)
        self.adjust_relocation_offset()

    def relocation_entry_move_to_appropriate_block(self, entry, block,
                                                   increase_size):
        """
        move relocation entry to appropriate relocation block.

        Args:
            entry(Structure) : IMAGE_BASE_RELOCATION_ENTRY
            block(Structure) : IMAGE_BASE_RELOCATION
            increase_size(int) : size to move the entry
        """
        pe_structure = self.PE.__structures__
        # we assume first section is text section.
        # code section's address end that increased by instrument.
        instrumented_code_section_end = self.PE.sections[0].VirtualAddress \
                                        + self.PE.sections[0].Misc_VirtualSize
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

    def register_rva_to_relocation(self, rva):
        """
        append rva to relocation list.
        if appropriate block is not exist, then append it after make new block.

        Args:
            rva(int) : relative address for relocating.
        """
        block_rva = rva & 0xfffff000
        pe_structure = self.PE.__structures__

        (relocationBlocks, relocationEntries) = \
            self.get_relocation_directories()

        if block_rva in relocationBlocks:
            block_index = pe_structure.index(relocationBlocks[block_rva])
        else:
            block_index = self.gen_new_relocation_block(block_rva)
        entry = self.gen_new_relocation_entry(rva)
        self.append_relocation_entry_to_block(entry, block_index)

    def gen_new_relocation_block(self, block_rva):
        """
        generate new relocation block that cover rva.
        Args:
            block_rva: relative address that has covered by new block.

        Returns:
            int : index of generated block.
        """
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

    def gen_new_empty_import_descriptor(self):
        """
        generate new import descriptor that has empty.

        Returns:
            :obj:`Structure` : IMPORT_DESCRIPTOR
        """
        structure = Structure(self.PE.__IMAGE_IMPORT_DESCRIPTOR_format__)
        return structure

    def gen_new_empty_import_thunk(self):
        """
        generate new import descriptor that has empty.

        Returns:
            :obj:`Structure` : IMPORT_THUNK
        """
        structure = Structure(self.PE.__IMAGE_THUNK_DATA_format__)
        return structure

    def get_new_empty_thunk(self):
        """
        generate new empty thunk.

        Returns:
            :obj:`Structure` : IMPORT_THUNK
        """
        structure = Structure(self.PE.__IMAGE_THUNK_DATA_format__)
        return structure

    def gen_new_relocation_entry(self, rva):
        """
        Create a relocation entry for rva.

        Args:
            rva(int) : relative address.

        Returns:
            :obj:`Structure` : IMAGE_BASE_RELOCATION_ENTRY
        """
        structure = Structure(self.PE.__IMAGE_BASE_RELOCATION_ENTRY_format__)
        setattr(structure, "Data", (rva & 0xfff) + 0x3000)
        return structure

    def append_relocation_entry_to_block(self, entry, block_index):
        """
        append relocation entry to appropriate relocation block.

        Args:
            entry(Structure) : entry to be append.
            block_index(int) : index of block.
        """
        pe_structure = self.PE.__structures__
        _block_size = pe_structure[block_index].SizeOfBlock
        if (_block_size - 8) > 0:
            block_entry_count = (_block_size - 8) / 2
            pe_structure.insert(block_index + block_entry_count + 1, entry)
        else:
            pe_structure.insert(block_index + 1, entry)
        pe_structure[block_index].SizeOfBlock += 2

    def get_section_belong_rva(self, rva):
        """
        Find the section containing rva.

        Args:
            rva(int) : rva for find section.

        Returns:
            :obj:`Section` : the Section to which the given relative address as argument belongs.
        """
        sections = self.PE.sections
        for section in sections:
            if section.VirtualAddress \
                    <= rva \
                    < section.VirtualAddress + section.Misc_VirtualSize:
                return section
        return None

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
        for entry in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == entry_name:
                return entry.VirtualAddress, entry.Size

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

    @staticmethod
    def is_executable_section(section):
        """
        Whether the section is an executable.

        Args:
            section(Section): Section to check
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
            section(:obj:`Section`) : section that need clone

        Returns:
            :obj:`Section` : cloned section from argument
        """
        clone_section = copy.copy(section)
        return clone_section

    def adjust_data_in_range(self, start, end, increase_size):
        """
        Adjust the values of data belonging to a specific range.

        Args:
            start(int) : start of range.
            end(int) : end of range.
            increase_size(int): the size to be adjust.
        """
        relocation_dict = self.get_relocation_from_structures()
        sorted_relocation_dict = sorted(relocation_dict.items(),
                                        key=operator.itemgetter(0))
        for block_va, entries in sorted_relocation_dict:
            for entry in entries:
                if entry.Data == 0x0:
                    continue
                relocation_rva = (entry.Data & 0xfff) + block_va
                value = self.PE.get_dword_at_rva(relocation_rva)
                if ((start + self._IMAGE_BASE_)
                        <= value
                        < (end + self._IMAGE_BASE_)):
                    self.set_dword_at_rva(relocation_rva, value + increase_size)
                    print("{:x}\t{:x}\t{:x}".format(relocation_rva, value,
                                                    increase_size))
