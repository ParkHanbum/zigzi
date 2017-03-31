#!/usr/bin/python
# -*- coding: utf-8 -*-
"""PEUtil, parse PE format and modify it.
"""

import pefile
import copy

class PEUtil(object):
    fast_load = True

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
        self.PE.__structures__.append(section)

    def get_file_data(self):
        return self.PE.__data__

    def get_aligned_offset(self, offset):
        file_align = self.PE.OPTIONAL_HEADER.FileAlignment
        v = offset % file_align
        if v > 0:
            return (offset - v) + file_align
        return offset

    def create_new_section_header(self, point_to_raw, size_of_raw):
        new_section = self.clone_section_header(self.PE.sections[0])
        new_section.SizeOfRawData = size_of_raw
        new_section.PointerToRawData = point_to_raw
        #self.PE.OPTIONAL_HEADER.SizeOfImage = point_to_raw + size_of_raw
        self.append_section_to_PE(new_section)

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


    def create_new_section(self, data):
        orig_data_len = len(self.PE.__data__)
        aligned_orig_data_len = self.get_aligned_offset(orig_data_len)
        data_len = len(data)
        aligned_data_len = self.get_aligned_offset(data_len)
        # make space
        space = bytearray((aligned_orig_data_len+aligned_data_len) - orig_data_len)
        self.PE.__data__[orig_data_len:aligned_orig_data_len+aligned_data_len] = space
        # Fill space with data
        self.PE.__data__[aligned_orig_data_len:aligned_orig_data_len+aligned_data_len] = data
        self.create_new_section_header(aligned_orig_data_len, aligned_data_len)
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

    def get_entry_point_va(self):
        return self.PE.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_entry_point_rva(self, entry_va):
        for curr_section in self.get_section_headers():
            if curr_section.contains_rva(entry_va):
                return entry_va - curr_section.VirtualAddress

    def get_executable_section(self):
        for curr_section in self.get_section_headers():
            if curr_section.Characteristics & 0x20000000:
                return curr_section

    def setentrypoint(self, entry_va):
        self.PE.OPTIONAL_HEADER.AddressOfEntryPoint = entry_va

    def write(self, path):
        self.PE.OPTIONAL_HEADER.CheckSum = self.PE.generate_checksum()
        self.PE.write(path)
