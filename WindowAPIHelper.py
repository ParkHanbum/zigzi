
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
        self.PE = pe_manager.PE
        self.structures = self.PE.__structures__
        self.pe_manager = pe_manager
        self.import_entries = pe_manager.PE.DIRECTORY_ENTRY_IMPORT
        self.import_structures = pe_manager.get_import_structures()

        self._origin_import_section = None
        self._new_import_section = None

        self.count_of_additional_fn = 0
        self.count_of_additional_dll = 0

    def _get_gap_size(self):
        result = 0
        if (self._origin_import_section is not None
            and self._new_import_section is not None):
            result = self._new_import_section.VirtualAddress \
                     - self._origin_import_section.VirtualAddress
        return result

    def move_imports_offset_to_new_section(self):
        """
        Move the import descriptor and related structures
        to the new aligned address located at new section.
        """
        self.print_imports_offset()
        (entry_rva, size) = self.pe_manager.get_import_descriptor_address_range()
        section = self.pe_manager.get_section_belong_rva(entry_rva)
        data = self.pe_manager.get_section_raw_data(section)
        # append free space that to use be import descriptor.
        import_free_space = 0x3000
        data = data + bytearray(import_free_space)
        new_section = self.pe_manager.create_new_data_section(data, ".newdata")
        self._origin_import_section = section
        self._new_import_section = new_section

        rva_gap_size = new_section.VirtualAddress - section.VirtualAddress
        offset_gap_size = new_section.PointerToRawData \
                          - section.PointerToRawData

        origin_iat_rva = 0
        origin_iat_size = 0
        for entry in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == 'IMAGE_DIRECTORY_ENTRY_IMPORT':
                entry.VirtualAddress += (rva_gap_size
                                         + self._IMPORT_DESCRIPTOR_TABLE_RVA_)
            elif entry.name == 'IMAGE_DIRECTORY_ENTRY_IAT':
                origin_iat_rva = entry.VirtualAddress
                origin_iat_size = entry.Size
                entry.VirtualAddress += rva_gap_size

        for entry in self.import_structures:
            entry_rva = self.PE.get_rva_from_offset(entry.get_file_offset())
            if entry.name == 'IMAGE_IMPORT_DESCRIPTOR':
                entry.set_file_offset(
                    self.PE.get_offset_from_rva(entry_rva + rva_gap_size
                                                + self._IMPORT_DESCRIPTOR_TABLE_RVA_)
                )
                if entry.OriginalFirstThunk > 0:
                    entry.OriginalFirstThunk += (rva_gap_size
                                                 + self._IMPORT_LOOKUP_TABLE_RVA_)
                if entry.Characteristics > 0:
                    entry.Characteristics += (rva_gap_size
                                              + self._IMPORT_LOOKUP_TABLE_RVA_)
                if entry.FirstThunk > 0:
                    # FirstThunk point to _IMPORT_ADDRESS_TABLE_
                    entry.FirstThunk += (rva_gap_size + self._IMPORT_ADDRESS_TABLE_RVA_)
                if entry.Name > 0:
                    entry.Name += rva_gap_size
            elif entry.name == 'IMAGE_THUNK_DATA':
                entry_rva = self.PE.get_rva_from_offset(entry.get_file_offset())
                if (origin_iat_rva
                        <= entry_rva
                        <= origin_iat_rva + origin_iat_size):
                    # this entry is located at import address table
                    entry.set_file_offset(
                        self.PE.get_offset_from_rva(
                            entry_rva + rva_gap_size
                            + self._IMPORT_ADDRESS_TABLE_RVA_)
                    )
                else:
                    # this entry is located at import lookup table
                    entry.set_file_offset(
                        self.PE.get_offset_from_rva(
                            entry_rva + rva_gap_size
                            + self._IMPORT_LOOKUP_TABLE_RVA_)
                    )

                if entry.Ordinal & 0x80000000:
                    # This is Ordinal import
                    pass
                else:
                    # IMPORT_THUNK_DATA is not moving.
                    if entry.Ordinal > 0:
                        entry.Ordinal += rva_gap_size + self._IMPORT_ADDRESS_TABLE_RVA_
                    if entry.AddressOfData > 0:
                        entry.AddressOfData += rva_gap_size + self._IMPORT_ADDRESS_TABLE_RVA_
                    if entry.ForwarderString > 0:
                        entry.ForwarderString += rva_gap_size + self._IMPORT_ADDRESS_TABLE_RVA_
                    if entry.Function > 0:
                        entry.Function += rva_gap_size + self._IMPORT_ADDRESS_TABLE_RVA_

        for entry in self.import_structures:
            if entry.name == 'IMAGE_IMPORT_DESCRIPTOR':
                if entry.OriginalFirstThunk > 0:
                    pass
                if entry.FirstThunk > 0:
                    pass
            elif entry.name == 'IMAGE_THUNK_DATA':
                if entry.Ordinal & 0x80000000:
                    # This is Ordinal import
                    pass

        self.adjust_references_of_iat(origin_iat_rva,
                                      origin_iat_rva + origin_iat_size,
                                      rva_gap_size)

    def adjust_references_of_iat(self, start, end, gap_size):
        """
        adjust a relocation element that references the import address table.

        Args:
            start(int) : start of range.
            end(int) : end of range.
            gap_size(int) : size to adjust.
        """
        self.pe_manager.adjust_data_in_range(start, end, gap_size)

    def get_iat_rva_with_size(self):
        """
        get import address relative address and its size.

        Returns:
            (tuple) :
                rva(int) : relative address of import address table.
                size(int) : size of import address table.
        """
        rva = 0
        size = 0
        for entry in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == 'IMAGE_DIRECTORY_ENTRY_IAT':
                rva = entry.VirtualAddress
                size = entry.Size
        return rva, size

    def gen_new_thunk(self, attr_data):
        """
        Creates a new thunk filled with the attribute value given as an argument.

        Args:
            attr_data(int) : attribute value that to be filled.

        Returns:
            (Structure) : import thunk structure.
        """
        new_thunk = self.pe_manager.gen_new_empty_import_thunk()
        setattr(new_thunk, "AddressOfData", attr_data)
        setattr(new_thunk, "ForwarderString", attr_data)
        setattr(new_thunk, "Function", attr_data)
        setattr(new_thunk, "Ordinal", attr_data)
        return new_thunk

    def gen_separator_thunk(self):
        """
        Creates a new thunk filled with zero that mean separator.

        Returns:
            (Structure) : import thunk structure that has filled zero.
        """
        separator_thunk = self.gen_new_thunk(0)
        return separator_thunk

    def gen_new_import_thunk(self, ordinal):
        """
        create the new import thunk with given ordinal as argument.
        and append it to structure.

        Args:
            ordinal(int) : Ordinal to be assigned to a new import thunk.

        Returns:
            (tuple) :
                import_thunk(Structure) : created import thunk.
                rva(int) : rva of ordinal located in import address table.
        """
        separator_thunk = self.gen_separator_thunk()
        empty_thunk = self.gen_new_thunk(ordinal)

        last_import_lookup_thunk = self.get_last_import_lookup_thunk()
        last_import_lookup_thunk_offset = \
            last_import_lookup_thunk.get_file_offset()
        separator_thunk.set_file_offset(last_import_lookup_thunk_offset +4)
        empty_thunk.set_file_offset(last_import_lookup_thunk_offset + 8)

        rva_at_iat = self.append_to_iat(ordinal)
        self.count_of_additional_fn += 1
        return empty_thunk, rva_at_iat

    def append_to_iat(self, ordinal):
        # TODO : Change the way of editing iat to use import thunk.
        for entry in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == 'IMAGE_DIRECTORY_ENTRY_IAT':
                iat_rva = entry.VirtualAddress
                iat_size = entry.Size
                break
        entry.Size += 4
        rva_at_iat = iat_rva + iat_size
        self.PE.set_dword_at_rva(iat_rva + iat_size, ordinal)
        return rva_at_iat

    def add_message_box(self):
        """
        add MessageBoxA window API to PE File.

        Returns:
            rva(int) : relative address of message box Api located in iat.
        """
        dll_import_descriptor = 0
        if not self.is_already_import_function('MessageBoxA'):
            if not self.is_already_import_dll('USER32.DLL'):
                self.move_imports_offset_to_new_section()

        ordinal = self.get_ordinal_from_common_library('USER32.DLL',
                                                       'MessageBoxA')
        import_thunk, rva_at_iat = self.gen_new_import_thunk(ordinal)
        ilt_rva, dll_name_rva = self.gen_new_import_lookup_table('MessageBoxA',
                                                                 'USER32.DLL')

        import_thunk_rva = \
            self.PE.get_rva_from_offset(import_thunk.get_file_offset())
        dll_import_descriptor = \
            self.add_dll_to_import_descriptor(import_thunk_rva, dll_name_rva,
                                              rva_at_iat)
        if not isinstance(dll_import_descriptor, Structure):
            print("THIS IS WRONG")
            exit()

            # self.add_function_to_import(dll_import_descriptor,
            #                            'USER32.DLL', 'MessageBoxA')
        self.append_import_thunk_to_next_of_descriptor(import_thunk,
                                                       dll_import_descriptor)

        self.print_imports_offset()
        self.save_modified_imports()
        self.adjust_data_directory_size()
        return rva_at_iat

    def print_imports_offset(self):
        """
        for debugging.
        """
        descriptor = {}
        thunks = {}
        for entry in self.import_structures:
            if entry.name == 'IMAGE_IMPORT_DESCRIPTOR':
                offset = entry.get_file_offset()
                rva = self.PE.get_rva_from_offset(offset)
                descriptor[rva] = entry
            elif entry.name == 'IMAGE_THUNK_DATA':
                offset = entry.get_file_offset()
                rva = self.PE.get_rva_from_offset(offset)
                thunks[rva] = entry

        sorted_descriptor = sorted(descriptor.items(),
                                   key=operator.itemgetter(0))
        sorted_thunks = sorted(thunks.items(),
                               key=operator.itemgetter(0))

        print("============[IMAGE_IMPORT_DESCRIPTOR]=============")
        for rva, entry in sorted_descriptor:
            print("{:x} - {:x}\t".format(rva, rva + 20))
        print("============[IMAGE_IMPORT_THUNK]=============")
        for rva, entry in sorted_thunks:
            print("{:x} - {:x}\t".format(rva, rva + 4))

    def append_import_thunk_to_next_of_descriptor(self, import_thunk,
                                                  descriptor):
        """
        append import thunk to the next index of given descriptor as an argument.

        Args:
            import_thunk(Structure) : import thunk
            descriptor(Structure): import descriptor
        """
        descriptor_index = self.import_structures.index(descriptor)
        self.import_structures.insert(descriptor_index + 1, import_thunk)

    def adjust_data_directory_size(self):
        """
        Increase the size of the import directory and import address table
        by the number of import descriptors and import thunks added.
        """
        for entry in self.PE.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name == 'IMAGE_DIRECTORY_ENTRY_IMPORT':
                # TODO : modify this.
                entry.Size += (self.count_of_additional_dll * 20)
            elif entry.name == 'IMAGE_DIRECTORY_ENTRY_IAT':
                entry.Size += (self.count_of_additional_fn * 4)

    def save_modified_imports(self):
        """
        reflect modified import structure to origin.
        """
        # apply changed imports.
        imports_range = self.pe_manager.get_imports_range_in_structures()
        self.PE.__structures__[imports_range[0]:imports_range[1]] = \
            self.import_structures

    def add_dll_to_import_descriptor(self, first_thunk_rva, dll_name_rva,
                                     iat_rva):
        """
        create import descriptor with given argument and append it to structure.

        Args:
            first_thunk_rva(int) : relative address of first thunk.
            dll_name_rva(int) : relative address of dll name string.
            iat_rva(int) : the relative address of import thunk located at
            import address table.

        Returns:
            (Structure) : a new import descriptor.
        """
        empty_import_descriptor = \
            self.pe_manager.gen_new_empty_import_descriptor()
        setattr(empty_import_descriptor, "Characteristics", 0)
        setattr(empty_import_descriptor, "FirstThunk", iat_rva)
        setattr(empty_import_descriptor, "ForwarderChain", 0)
        setattr(empty_import_descriptor, "Name", dll_name_rva)
        setattr(empty_import_descriptor, "OriginalFirstThunk", first_thunk_rva)
        setattr(empty_import_descriptor, "TimeDateStamp", 0)

        # TODO : inject dll_name and get its rva for set name

        last_descriptor = self.import_structures[-1]
        if last_descriptor.name != 'IMAGE_IMPORT_DESCRIPTOR':
            print("something wrong")
            exit

        last_descriptor_offset = self.get_last_import_descriptor_offset()
        last_descriptor = self.get_last_import_descriptor()
        last_descriptor_index = self.import_structures.index(last_descriptor)

        empty_import_descriptor.set_file_offset(last_descriptor_offset)
        last_descriptor.set_file_offset(last_descriptor_offset
                                        + empty_import_descriptor.sizeof())
        self.import_structures.insert(last_descriptor_index,
                                      empty_import_descriptor)
        # print("OFFSET : {:x}".format(last_descriptor_offset))
        self.count_of_additional_dll += 1
        return empty_import_descriptor

    def get_ordinal_from_common_library(self, dll_name, fn_name):
        """
        get the ordinal from common libraries with given dll
        and function name as argument.

        Args:
            dll_name(str) : dll name.
            fn_name(str) : function name.

        Returns:
            ordinal(int) : ordinal of matched.
        """
        ordinal = 0
        if dll_name in self._COMMON_FUNCTIONS_:
            functions = self._COMMON_FUNCTIONS_[dll_name]
            if fn_name in functions:
                ordinal = functions[fn_name]
        return ordinal + self._ORDINAL_MASK_

    def append_import_thunk_to_descriptor(self, descriptor, thunk):
        """
        add import thunk at the following index of the descriptor in structures.

        Args:
            descriptor(Structure) : descriptor
            thunk(Structure) : import thunk to append.
        """
        # TODO : now, this method only support 1 import thunk. must need enhance.
        descriptor_index = self.import_structures.index(descriptor)
        self.import_structures.insert(descriptor_index + 1, thunk)
        rva = self.PE.get_rva_from_offset(thunk.get_file_offset())
        print("RVA : {:x}".format(rva))
        descriptor.Characteristics = rva
        descriptor.FirstThunk = rva
        descriptor.ForwarderChain = rva
        descriptor.Name = 0
        descriptor.OriginalFirstThunk = rva
        descriptor.TimeDateStamp = 0

        self.count_of_additional_fn += 1

    def add_function_to_import(self, dll_import_descriptor, dll_name, fn_name):
        """
        create import thunk by given argument dll and function name.
        and append it to structures.

        Args:
            dll_import_descriptor(Structure) : The generated import thunk is
            appended to the following index of this descriptor in structures.
            dll_name(str) : dll name.
            fn_name(str) : function name.
        """

        # TODO : Currently, only the functions in the list are supported.
        ordinal = self.get_ordinal_from_common_library(dll_name, fn_name)
        if ordinal == 0:
            print("not supported yet.")
            exit()

        ordinal += self._ORDINAL_MASK_
        thunk = self.pe_manager.gen_new_thunk(ordinal)
        last_import_thunk_offset = self.get_last_import_thunk_offset()
        print("IMPORT THUNK OFFSET : {:x}".format(last_import_thunk_offset))
        print("IMPORT THUNK RVA : {:x}".format(
            self.PE.get_rva_from_offset(last_import_thunk_offset)
        ))
        thunk.set_file_offset(last_import_thunk_offset + 4)
        self.append_import_thunk_to_descriptor(dll_import_descriptor, thunk)

    def is_already_import_dll(self, dll_name):
        """
        Checks whether an import descriptor with the given dll name exists.

        Args:
            dll_name(str) : dll name.

        Returns:
            (bool) : True, if dll name exist in import descriptor.
                    False, if dll name doesn't exist in import descriptor.
        """
        for descriptor in self.import_entries:
            if descriptor.dll == dll_name:
                return True
        return False

    def is_already_import_function(self, fn):
        """
        check whether an import thunk with the given function name.

        Args:
            fn(str) : function name.

        Returns:
            (bool) : True, if function name exist in import thunk.
                    False, if function name doesn't exist in import thunk.
        """
        if isinstance(fn, basestring):
            for descriptor in self.import_entries:
                for import_element in descriptor.imports:
                    if import_element.name == fn:
                        return True

        elif isinstance(fn, int):
            # TODO : add ordinary import
            pass
        return False

    def get_last_import_thunk_offset(self):
        """
        get the import thunk offset that located last offset.

        Returns:
            (int) : the offset of the import thunk at the last offset.
        """
        offset = 0
        for entry in self.import_structures:
            if entry.name == 'IMAGE_THUNK_DATA':
                entry_offset = entry.get_file_offset()
                if entry_offset > offset:
                    if entry.AddressOfData > 0:
                        offset = entry_offset
        return offset

    def get_last_import_lookup_thunk(self):
        """
        get the import lookup thunk that located last offset.

        Returns:
            (Structure) : import lookup thunk
        """
        (import_address_table_rva, size) = \
            self.pe_manager.get_import_address_table_address_range()
        offset = 0
        import_lookup_thunk = None
        for entry in self.import_structures:
            if entry.name == 'IMAGE_THUNK_DATA':
                entry_offset = entry.get_file_offset()
                entry_rva = self.PE.get_rva_from_offset(entry_offset)
                if entry_offset > offset \
                        and not (import_address_table_rva
                                 <= entry_rva
                                 <= import_address_table_rva + size):
                    if entry.AddressOfData > 0:
                        offset = entry_offset
                        import_lookup_thunk = entry
        return import_lookup_thunk

    def get_last_import_address_thunk(self):
        """
        get the import address thunk that located last offset.

        Returns:
            (Structure) : import thunk
        """
        (import_address_table_rva, size) = \
            self.pe_manager.get_import_address_table_address_range()
        offset = 0
        import_address_thunk = None
        for entry in self.import_structures:
            if entry.name == 'IMAGE_THUNK_DATA':
                entry_offset = entry.get_file_offset()
                entry_rva = self.PE.get_rva_from_offset(entry_offset)
                if entry_offset > offset \
                        and (import_address_table_rva
                                 <= entry_rva
                                 <= import_address_table_rva + size):
                    if entry.AddressOfData > 0:
                        offset = entry_offset
                        import_address_thunk = entry
        return import_address_thunk

    def get_last_import_descriptor_offset(self):
        """
        get offset of the import descriptor that located last offset.

        Returns:
            (int) : offset of the last import descriptor.
        """
        offset = 0
        for entry in self.import_structures:
            if entry.name == 'IMAGE_IMPORT_DESCRIPTOR':
                entry_offset = entry.get_file_offset()
                if entry_offset > offset:
                    offset = entry_offset
        return offset

    def get_last_import_descriptor(self):
        """
        get the import descriptor that located last offset.

        Returns:
            (Structure) : the last import descriptor.
        """
        descriptor = None
        offset = 0
        for entry in self.import_structures:
            if entry.name == 'IMAGE_IMPORT_DESCRIPTOR':
                entry_offset = entry.get_file_offset()
                if entry_offset > offset:
                    offset = entry_offset
                    descriptor = entry
        return descriptor

    def gen_new_import_lookup_table(self, fn_name, dll_name):
        """
        create import lookup table.

        Args:
            fn_name(str) : name of function.
            dll_name(str) : name of dll.

        Returns:
            (tuple):
                next_ilt_rva (int) : relative address of generated ilt table.
                dll_name_rva (int) : relative address of name.
        """
        # TODO : currently, this method modify import lookup table directly,
        # it must be abstract.
        name = self.import_entries[-1].dll
        name_rva = self.import_entries[-1].struct.Name
        next_ilt_rva = name_rva + len(name) + 1
        fn_name = '\x00' + fn_name
        self.PE.set_bytes_at_rva(next_ilt_rva, fn_name)
        dll_name = '\x00' + dll_name + '\x00'
        dll_rva = next_ilt_rva + len(dll_name)
        self.PE.set_bytes_at_rva(dll_rva, dll_name)
        return next_ilt_rva, dll_rva + 1
