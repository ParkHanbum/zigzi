#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEUtil, Utility for parsing and modifying PE.
"""

import mmap
import copy
import struct
import operator
from pefile import *
import distorm3
import binascii


_DWORD_SIZE = 4
_WORD_SIZE = 2


class PEUtil(object):

    def __init__(self, name):
        self.PE_name = name
        pe_file = open(name, 'r+b')
        pe_file_bytes = bytearray(pe_file.read())
        fast_load = False
        pe_data = mmap.mmap(pe_file.fileno(), 0, access=mmap.ACCESS_COPY)
        self.PE_ORIGIN = PE(None, data=pe_data, fast_load=False)
        self.PE = PE(None, data=pe_data, fast_load=False)
        # self.PE.full_load()
        # self.PE = pefile.PE(name)
        self.instrumentor = None

    def set_instrumentor(self, instrumentor):
        self.instrumentor = instrumentor

    def get_instrumentor(self):
        return self.instrumentor

    def get_pe_name(self):
        return self.PE_name

    def get_section_headers(self):
        return self.PE.sections

    def print_section(self, section):
        print (section.Name, hex(section.VirtualAddress),
               hex(section.Misc_VirtualSize), section.SizeOfRawData,
               hex(section.get_file_offset())
               )

    def clone_section_header(self, section):
        clone_section = copy.copy(section)
        return clone_section

    def append_section_to_PE(self, section):
        self.PE.sections.append(section)
        self.PE.__structures__.append(section)

    def get_file_data(self):
        return self.PE.__data__

    def get_aligned_offset(self, offset):
        file_align = self.PE.OPTIONAL_HEADER.FileAlignment
        v = offset % file_align
        if v > 0:
            return (offset - v) + file_align
        return offset

    def get_aligned_va(self, va):
        aligned_va = self.get_section_align()
        v = va % aligned_va
        if v > 0:
            return (va - v) + aligned_va
        return va

    def append_data_to_PE(self, data):
        orig_data_len = len(self.PE.__data__)
        aligned_orig_data_len = self.get_aligned_offset(orig_data_len)
        data_len = len(data)
        aligned_data_len = self.get_aligned_offset(data_len)
        # make null space for data.
        space = bytearray((aligned_orig_data_len+aligned_data_len) - orig_data_len + 1)
        self.PE.set_bytes_at_offset(orig_data_len - 1, bytes(space))
        #self.PE.__data__[orig_data_len:aligned_orig_data_len+aligned_data_len] = space
        # Fill space with data
        self.PE.set_bytes_at_offset(aligned_orig_data_len, bytes(data))
        #self.PE.__data__[aligned_orig_data_len:aligned_orig_data_len+aligned_data_len] = data
        return aligned_orig_data_len, aligned_data_len

    def create_new_section_header(self, point_to_raw, size_of_raw):
        # TODO : We assume that the new section to be created is a copy of the 0th section, text section.
        new_section = self.clone_section_header(self.PE.sections[0])
        new_section.SizeOfRawData = size_of_raw
        new_section.PointerToRawData = point_to_raw
        new_section.Misc_VirtualSize = self.get_aligned_va(size_of_raw)
        new_section.Misc_PhysicalAddress = self.get_aligned_va(size_of_raw)
        new_section.Misc = self.get_aligned_va(size_of_raw)
        self.PE.OPTIONAL_HEADER.SizeOfCode = new_section.Misc_VirtualSize
        #self.PE.OPTIONAL_HEADER.SizeOfImage = point_to_raw + size_of_raw
        self.append_section_to_PE(new_section)
        return new_section

    def create_new_section_and_append_data(self, data):
        (point_to_raw, size_of_raw) = self.append_data_to_PE(data)
        return self.create_new_section_header(point_to_raw, size_of_raw)

    def create_new_execution_section(self, point_to_raw, size_of_raw, size_of_data):
        # TODO : We assume that the new section to be created is a copy of the 0th section, text section.
        self.PE.sections[0].SizeOfRawData = size_of_raw
        self.PE.sections[0].PointerToRawData = point_to_raw
        self.PE.sections[0].Misc_VirtualSize = size_of_data
        self.PE.sections[0].Misc_PhysicalAddress = size_of_data
        self.PE.sections[0].Misc = size_of_data
        self.PE.OPTIONAL_HEADER.SizeOfCode = size_of_data
        # self.PE.OPTIONAL_HEADER.SizeOfImage = point_to_raw + size_of_raw

    def append_data_to_execution(self, data):
        size_of_data = len(data)
        (point_to_raw, size_of_raw) = self.append_data_to_PE(data)
        self.create_new_execution_section(point_to_raw, size_of_raw, size_of_data)

    def get_section_raw_data(self, section_hdr):
        start_offset = section_hdr.PointerToRawData
        size = section_hdr.SizeOfRawData
        data = bytearray(self.PE.__data__[start_offset:start_offset+size])
        return data

    def get_section_by_name(self, section_name):
        for section in self.PE.sections:
            if section.Name == section_name:
                return section

    def get_section_by_va(self, section_va):
        for section in self.PE.sections:
            if section.VirtualAddress == section_va:
                return section

    def get_entry_point_va(self):
        return self.PE.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_entry_point_rva(self, entry_va):
        for curr_section in self.get_section_headers():
            if curr_section.contains_rva(entry_va):
                return entry_va - curr_section.VirtualAddress

    def get_executable_range_va(self):
        executable_section = self.get_executable_section()
        va_size = executable_section.Misc_VirtualSize
        va = executable_section.VirtualAddress
        return va, va + va_size

    def get_executable_section(self):
        for curr_section in self.get_section_headers():
            if curr_section.Characteristics & 0x20000000:
                return curr_section

    def get_section_align(self):
        return self.PE.OPTIONAL_HEADER.SectionAlignment

    def setentrypoint(self, entry_va):
        self.PE.OPTIONAL_HEADER.AddressOfEntryPoint = entry_va

    def write(self, path):
        self.uncerfication()
        self.adjust_PE_layout()
        self.PE.merge_modified_section_data()
        self.PE.OPTIONAL_HEADER.SizeOfImage = self.get_image_size()
        self.PE.OPTIONAL_HEADER.CheckSum = 0
        self.PE.OPTIONAL_HEADER.CheckSum = self.PE.generate_checksum()
        self.PE.write(path)

    def get_image_size(self):
        section = self.PE.sections[-1]
        va = section.VirtualAddress
        size = section.Misc_VirtualSize
        return self.get_aligned_va(va + size)

    def get_relocation_map(self):
        relocation_map = {}
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            for entry in self.PE.DIRECTORY_ENTRY_BASERELOC:
                for el in entry.entries:
                    if el.struct.Data == 0:
                        continue
                    address = el.rva
                    relocation_map[address] = [el.rva, address, el.type]
        return relocation_map

    def get_relocation_map_from_structure(self):
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

    def isrelocable(self):
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            return True
        return False

    def get_reloc_map(self):
        """
        [temporary]
        get relocation map
        :return: dictionary include relocation information with file offset
        """
        basereloc_va = 0
        basereloc_size = 0
        for entry in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == 'IMAGE_DIRECTORY_ENTRY_BASERELOC':
                basereloc_va = entry.VirtualAddress
                basereloc_size = entry.Size
        section = self.get_section_by_va(basereloc_va)
        reloc_raw_data = self.PE.__data__[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        reloc_blocks = {}
        block_raw_pointer = 0
        while True:
            if block_raw_pointer >= basereloc_size:
                break
            block_rva = struct.unpack('I', reloc_raw_data[block_raw_pointer:block_raw_pointer + _DWORD_SIZE])[0]
            block_raw_pointer += _DWORD_SIZE
            block_size = struct.unpack('I', reloc_raw_data[block_raw_pointer:block_raw_pointer + _DWORD_SIZE])[0]
            block_raw_pointer += _DWORD_SIZE
            block_end = block_raw_pointer - _DWORD_SIZE * 2 + block_size
            entries = []
            for index in range(block_size / _WORD_SIZE):
                entry = struct.unpack('H', reloc_raw_data[block_raw_pointer:block_raw_pointer + _WORD_SIZE])[0]
                # assume type is 3 IMAGE_REL_BASED_HIGHLOW
                if entry > 0:
                    entry -= 0x3000
                entries.append((block_rva+entry, section.PointerToRawData+block_raw_pointer))
                block_raw_pointer += _WORD_SIZE
                if block_raw_pointer >= block_end:
                    break
            reloc_blocks[block_rva] = entries

        return reloc_blocks

    def set_section_header(self, section_name, size_of_raw=0, pointer_to_raw=0,
                           virtual_address=0, virtual_size=0):
        for i in range(len(self.PE.sections)):
            if self.PE.sections[i].Name == section_name:
                if size_of_raw > 0:
                    self.PE.sections[i].Misc_PhysicalAddress = \
                        self.get_aligned_offset(size_of_raw)
                if pointer_to_raw > 0:
                    self.PE.sections[i].PointerToRawData = pointer_to_raw
                if virtual_address > 0:
                    self.PE.sections[i].VirtualAddress = virtual_address
                if virtual_size > 0:
                    self.PE.sections[i].Misc_VirtualSize = \
                        self.get_aligned_va(virtual_size)

    def adjust_PE_layout(self):
        self.adjust_section()

    def adjust_section(self):
        data_directories = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY
        for index in xrange(len(self.PE.sections)-1):
            src_section = self.PE.sections[index]
            virtual_size = src_section.Misc_VirtualSize
            src_va = src_section.VirtualAddress
            src_va_end = src_va + virtual_size
            name = src_section.Name
            src_raw = src_section.PointerToRawData
            src_raw_end = src_raw + src_section.SizeOfRawData

            dst_section = self.PE.sections[index+1]
            if src_va <= dst_section.VirtualAddress < src_va_end:
                adjusted = True
                print "adjust virtual address"
                section_va = dst_section.VirtualAddress
                adjusted_section_va = section_va + (src_va_end - section_va)
                adjusted_section_va = self.get_aligned_va(adjusted_section_va)
                self.PE.sections[index+1].VirtualAddress = adjusted_section_va
                if section_va == self.PE.OPTIONAL_HEADER.BaseOfData:
                    self.PE.OPTIONAL_HEADER.BaseOfData = adjusted_section_va
                self.adjust_directories(data_directories, section_va, adjusted_section_va, dst_section.Misc_VirtualSize)

    def adjust_directories(self, data_directories, origin_section_va, adjusted_section_va, virtual_size):
        directory_adjust = {
            # 'IMAGE_DIRECTORY_ENTRY_IMPORT': self.adjust_import,
            # 'IMAGE_DIRECTORY_ENTRY_DEBUG': self.adjust_debug,
            # 'IMAGE_DIRECTORY_ENTRY_TLS': self.adjust_tls,
            'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG': self.adjust_load_config,
            'IMAGE_DIRECTORY_ENTRY_EXPORT': self.adjust_export,
            'IMAGE_DIRECTORY_ENTRY_RESOURCE': self.adjust_resource,
            'IMAGE_DIRECTORY_ENTRY_BASERELOC': self.adjust_relocation,
            'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT': self.adjust_delay_import,
            'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT': self.adjust_bound_imports
        }

        increase_vector = adjusted_section_va - origin_section_va
        for directory in data_directories:
            if origin_section_va <= directory.VirtualAddress < origin_section_va + virtual_size:
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[self.PE.OPTIONAL_HEADER.DATA_DIRECTORY.index(directory)].VirtualAddress \
                    = directory.VirtualAddress + increase_vector
                try:
                    if directory.name in directory_adjust:
                        entry = directory_adjust[directory.name]
                        entry(directory, directory.VirtualAddress, directory.Size, increase_vector)
                except IndexError:
                    print "===== [INDEX ERROR] ====="
                    return False
                data_directories.remove(directory)

    def uncerfication(self):
        for index in range(len(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY)):
            directory = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            if directory.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress = 0
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size = 0

    def pack_relocation(self, relocation_map):
        sorted_adjusted_relocation_map = sorted(relocation_map.items(),
                                                key=operator.itemgetter(0))
        packed = []
        offset = 0
        for block_address, block_entry in sorted_adjusted_relocation_map:
            packed.append(struct.pack("I", block_address))
            offset += 4
            for reloc_rva, reloc_raw in block_entry:
                packed.append(struct.pack("H", reloc_rva - block_address))
                offset += 2
        return packed

    def write_relocation(self, adjusted_relocation_map):
        self.adjusted_relocation_map = adjusted_relocation_map

    def adjust_relocation(self, directory, rva, size, increase_size):
        log = open('c:\\work\\peutil_adjust_relocation.log', 'w')
        relocation_map = self.get_relocation_map_from_structure()

        # TODO : fix assume that first section is text.
        sections = self.PE_ORIGIN.sections
        execute_section_start = sections[0].VirtualAddress
        execute_section_end = execute_section_start + sections[0].Misc_VirtualSize
        other_section_start = sections[1].VirtualAddress
        other_section_end = sections[-1:][0].VirtualAddress + sections[-1:][0].Misc_VirtualSize
        sorted_relocation_map = sorted(relocation_map.items(),
                                       key=operator.itemgetter(0))
        for block_va, entries in sorted_relocation_map:
            for entry in entries:
                if entry.Data == 0x0:
                    continue
                # get instrument size from 0x0(imagebase 0x400000, textsection 0x1000, till value)
                address = (entry.Data & 0xfff) + block_va
                value = self.PE.get_dword_at_rva(address)
                if execute_section_start + 0x400000 <= value < execute_section_end + 0x400000:
                    # get instrument size from 0x0(imagebase 0x400000, textsection 0x1000, till value)
                    instrumented_size = self.get_instrumentor().get_instrument_size_with_vector(value - 0x400000 - 0x1000)
                    self.set_dword_at_rva(address, value + instrumented_size)
                    log.write("[0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n".format(address, value, self.PE.get_dword_at_rva(address), instrumented_size))
                elif other_section_start + 0x400000 <= value < other_section_end + 0x400000:
                    self.set_dword_at_rva(address, value + 0x1000)
                    log.write("[0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n".format(address, value, self.PE.get_dword_at_rva(address), 0x1000))
        return 0

    def adjust_load_config(self, directory, rva, size, increase_size):
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
        Security_Cookie_VA = self.PE.get_dword_at_rva(rva + 0x3C)
        self.set_dword_at_rva(rva + 0x3C, Security_Cookie_VA + 0x1000)
        SE_Handler_Table_VA = self.PE.get_dword_at_rva(rva + 0x40)
        self.set_dword_at_rva(rva + 0x40, SE_Handler_Table_VA + 0x1000)
        SE_Handler_Count = self.PE.get_dword_at_rva(rva + 0x44)

        return 0

    def adjust_debug(self, directory, rva, size, increase_size):
        return 0

    def adjust_tls(self, directory, rva, size, increase_size):
        return 0

    def adjust_bound_imports(self, directory, rva, size, increase_size):
        return 0

    def adjust_delay_import(self, directory, rva, size, increase_size):
        pINT = self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pINT
        self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pINT = pINT + increase_size
        pIAT = self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pIAT
        self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pIAT = pIAT + increase_size
        self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.pBoundIAT += increase_size
        self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.phmod += increase_size
        self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].struct.szName += increase_size

        for importdata in self.PE.DIRECTORY_ENTRY_DELAY_IMPORT[0].imports:
            iat = importdata.struct_iat
            ilt = importdata.struct_table
            address = iat.AddressOfData
            instrumented_size = self.get_instrumentor().get_instrument_size_with_vector(address - 0x400000 - 0x1000)
            iat.AddressOfData += instrumented_size
            iat.ForwarderString += instrumented_size
            iat.Function += instrumented_size
            iat.Ordinal += instrumented_size
            ilt.AddressOfData += increase_size
            ilt.ForwarderString += increase_size
            ilt.Function += increase_size
            ilt.Ordinal += increase_size

    # def adjust_import(self, directory, rva, size, increase_size):
    def adjust_import(self, instrument_size):
        log = open('c:\\work\\import_log.txt', 'w')
        for importindex in xrange(len(self.PE.DIRECTORY_ENTRY_IMPORT)):
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.Characteristics += 0x1000
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.FirstThunk += 0x1000
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.Name += 0x1000
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.OriginalFirstThunk += 0x1000
            log.write("===============================================================\n")
            log.write("{}\n".format(self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct))
            for entryindex in xrange(len(self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports)):
                importdata = self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex]
                iat = importdata.struct_iat
                self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_table.AddressOfData += 0x1000
                self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_table.ForwarderString += 0x1000
                self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_table.Function += 0x1000
                self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_table.Ordinal += 0x1000
                if iat:
                    self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat.AddressOfData += 0x1000
                    self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat.ForwarderString += 0x1000
                    self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat.Function += 0x1000
                    self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat.Ordinal += 0x1000
                    log.write("{}\n".format(self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat))
                else:
                    origin_iat_rva = importdata.address - self.PE.OPTIONAL_HEADER.ImageBase
                    # name_rva = peutil.PE.get_dword_at_rva(origin_iat_rva)
                    name = self.PE.get_data(
                        origin_iat_rva,
                        Structure(self.PE.__IMAGE_THUNK_DATA_format__).sizeof())
                    # peutil.PE.set_dword_at_rva(origin_iat_rva, name_rva + 0x1000)
                    thunk_data = self.PE.__unpack_data__(
                        self.PE.__IMAGE_THUNK_DATA_format__, name,
                        file_offset=self.PE.get_offset_from_rva(origin_iat_rva))
                    thunk_data.AddressOfData += 0x1000
                    thunk_data.ForwarderString += 0x1000
                    thunk_data.Function += 0x1000
                    thunk_data.Ordinal += 0x1000
                    self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat = thunk_data
                    log.write("{}\n".format(self.PE.DIRECTORY_ENTRY_IMPORT[importindex].imports[entryindex].struct_iat))
            log.write("===============================================================\n")
        print "DEBUG"

    def adjust_export(self, directory, rva, size, increase_size):
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions += increase_size
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals += increase_size
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames += increase_size
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.Name += increase_size

        log = open('c:\\work\\adjust_export.log', 'w')
        for index in xrange(len(self.PE.DIRECTORY_ENTRY_EXPORT.symbols)):
            entry_name_rva = self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames + (index * 4)
            name_rva = self.PE.get_dword_at_rva(entry_name_rva)
            name_rva += increase_size
            self.set_dword_at_rva(entry_name_rva, name_rva)

            entry_function_rva = self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions + (index * 4)
            function_rva = self.PE.get_dword_at_rva(entry_function_rva)
            log.write("[EXPORT ELEMENT]\n[0x{:x}]\t".format(function_rva))

            instrument_size = self.get_instrumentor().get_instrument_size_with_vector(function_rva - 0x1000)
            log.write("[adjust][0x{:x}]\t".format(function_rva + instrument_size))
            self.set_dword_at_rva(entry_function_rva, function_rva + instrument_size)

    def adjust_resource(self, directory, rva, size, increase_size):
        for rsrc_entries in self.PE.DIRECTORY_ENTRY_RESOURCE.entries:
            for rsrc_directory_entry in rsrc_entries.directory.entries:
                for rsrc_entry_directory_entry in rsrc_directory_entry.directory.entries:
                    print "0x{:x}".format(rsrc_entry_directory_entry.data.struct.OffsetToData)
                    rsrc_entry_directory_entry.data.struct.OffsetToData += increase_size

    def set_dword_at_rva(self, rva, dword):
        return self.PE.set_dword_at_rva(rva, dword)
