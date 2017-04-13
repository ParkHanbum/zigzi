#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEUtil, parse PE format and modify it.
"""

import pefile
import copy
import struct
import operator

_DWORD_SIZE = 4
_WORD_SIZE = 2


class PEUtil(object):

    fast_load = False

    def __init__(self, name):
        self.PE_name = name
        pe_file = open(name, 'rb')
        pe_file_bytes = bytearray(pe_file.read())
        self.PE = pefile.PE(None, pe_file_bytes, self.fast_load)

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

    def create_new_section_header(self, point_to_raw, size_of_raw):
        # TODO : We assume that the new section to be created is a copy of the 0th section, text section.
        new_section = self.clone_section_header(self.PE.sections[0])
        new_section.SizeOfRawData = size_of_raw
        new_section.PointerToRawData = point_to_raw
        new_section.Misc_VirtualSize = self.get_aligned_va(size_of_raw)
        self.PE.OPTIONAL_HEADER.SizeOfCode = new_section.Misc_VirtualSize
        #self.PE.OPTIONAL_HEADER.SizeOfImage = point_to_raw + size_of_raw
        self.append_section_to_PE(new_section)

        return new_section

    """
    def create_new_section_header(self, section=None, point_to_raw=0, size_of_raw=0):
        if not section:
            new_section = self.clone_section_header(self.PE.sections[0])
        else:
            new_section = self.clone_section_header(section)
        if point_to_raw > 0:
            new_section.SizeOfRawData = size_of_raw
            new_section.Misc_VirtualSize = size_of_raw
        if size_of_raw > 0:
            new_section.PointerToRawData = point_to_raw
        if point_to_raw > 0 and size_of_raw > 0:
            self.PE.OPTIONAL_HEADER.SizeOfImage = \
                point_to_raw + size_of_raw
        self.append_section_to_PE(new_section)
        return new_section
    """
    def create_new_section_and_append_data(self, data):
        (point_to_raw, size_of_raw) = self.append_data_to_PE(data)
        return self.create_new_section_header(point_to_raw, size_of_raw)

    def append_data_to_executable(self, data):
        copied_execute_section = self.create_new_section_and_append_data(data)
        return copied_execute_section

    def append_data_to_PE(self, data):
        orig_data_len = len(self.PE.__data__)
        aligned_orig_data_len = self.get_aligned_offset(orig_data_len)
        data_len = len(data)
        aligned_data_len = self.get_aligned_offset(data_len)
        # make space
        space = bytearray((aligned_orig_data_len+aligned_data_len) - orig_data_len)
        self.PE.__data__[orig_data_len:aligned_orig_data_len+aligned_data_len] = space
        # Fill space with data
        self.PE.__data__[aligned_orig_data_len:aligned_orig_data_len+aligned_data_len] = data
        return aligned_orig_data_len, aligned_data_len

    """
    def create_new_section(self, data):
        orig_data_len = len(self.PE.__data__)
        aligned_orig_data_len = self.get_aligned_offset(orig_data_len)
        # make data to aligned
        data_len = len(data)
        aligned_data_len = self.get_aligned_offset(data_len)
        # padding to data for fit
        # data = data.ljust(aligned_data_len, '\0')
        # make space
        space = bytearray((aligned_orig_data_len+aligned_data_len) - orig_data_len)
        self.PE.__data__[orig_data_len:aligned_orig_data_len+aligned_data_len] = space
        # Fill space with data
        self.PE.__data__[aligned_orig_data_len:aligned_orig_data_len+aligned_data_len] = data

        # assume that first section is executable
        new_section = self.clone_section_header(self.PE.sections[0])
        return self.create_new_section_header(new_section,
                                              aligned_orig_data_len,
                                              aligned_data_len)
    """

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
        data_len = len(self.PE.__data__)
        sizeofimage = self.get_aligned_offset(data_len)
        if sizeofimage - data_len > 0:
            self.PE.__data__.extend([0] * (sizeofimage - data_len))

        self.PE.merge_modified_section_data()
        self.adjust_PE_layout()
        self.uncerfication()
        self.PE.OPTIONAL_HEADER.CheckSum = self.PE.generate_checksum()
        self.PE.write(path)


    def get_relocation_map(self):
        relocation_map = {}
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            for entry in self.PE.DIRECTORY_ENTRY_BASERELOC:
                for el in entry.entries:
                    address = el.rva
                    relocation_map[address] = [el.rva, address, el.type]
        return relocation_map

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
        for index in xrange(len(self.PE.sections)):
            self.adjust_sections(index)

    def adjust_sections(self, index):
        src_section = self.PE.sections[index]
        virtual_address = src_section.VirtualAddress
        virtual_size = src_section.Misc_VirtualSize
        name = src_section.Name
        pointer_raw = src_section.PointerToRawData
        size_raw = src_section.SizeOfRawData

        src_va = virtual_address
        src_va_end = virtual_address + virtual_size
        src_raw = pointer_raw
        src_raw_end = pointer_raw + size_raw

        for dst_index in range(len(self.PE.sections)):
            if index == dst_index:
                continue
            adjusted = False
            section_va = 0
            adjusted_section_va = 0
            dst_section = self.PE.sections[dst_index]
            if src_va < dst_section.VirtualAddress < src_va_end:
                adjusted = True
                print "adjust virtual address"
                section_va = dst_section.VirtualAddress
                adjusted_section_va = section_va + (src_va_end - section_va)
                adjusted_section_va = self.get_aligned_va(adjusted_section_va)
                self.PE.sections[dst_index].VirtualAddress = adjusted_section_va
            if src_raw < dst_section.PointerToRawData < src_raw_end:
                print "adjust raw point"
                self.PE.sections[dst_index].PointerToRawData = \
                    self.get_aligned_va(dst_section.PointerToRawData + src_raw_end - dst_section.PointerToRawData)
            if adjusted:
                self.adjust_directories(section_va, adjusted_section_va)
                self.adjust_sections(dst_index)

    def adjust_directories(self, origin_section_va, adjusted_section_va):
        data_directories = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY
        for index in range(len(data_directories)):
            directory = data_directories[index]
            if origin_section_va == directory.VirtualAddress:
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress = adjusted_section_va

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

    def write_relocation(self, relocation_map):
        packed_relocation = self.pack_relocation(relocation_map)




