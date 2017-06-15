"""DataObject
Helper class for data instrument to file.
"""

import struct
import sys


class DataObject(object):

    def __init__(self, base_address):
        self._base_address = base_address
        self._base_point = base_address
        self._frame_point = base_address
        self._size = 0
        self.is_appending = False
        self.data = []
        self.variable = {}
        # default little endian
        self.prefix_byte_order = "<"
        self.init_byte_order()

    def init_byte_order(self):
        if 'little' == sys.byteorder:
            self.prefix_byte_order = "<"
        else:
            self.prefix_byte_order = ">"

    def is_append_not_finish(self):
        return self.is_appending

    def append_finish(self):
        self.is_appending = False

    @property
    def base_address(self):
        return self._base_address

    @property
    def size(self):
        return self._size

    def get_current_base_pos(self):
        return self._base_point

    def append_chunk(self, data_list, variable_name):
        base_point = self.get_current_base_pos()
        if self.is_append_not_finish():
            print("previous append is not finish correctly.")
            exit()
        data_len = len(data_list)
        # local variable log
        self.save_local_variable(self._base_point, variable_name)
        self.data[self._base_point:self._base_point + data_len - 1] = data_list
        self._size += data_len
        self._base_point += data_len
        self._frame_point += data_len
        return base_point

    def save_local_variable(self, base_point, variable_name):
        if variable_name is None:
            self.variable[base_point] = base_point
        else:
            self.variable[variable_name] = base_point

    def append_dword(self, dword, variable_name=None):
        """
        append_dword size value to data list.

        Args:
            dword: value.
            variable_name: name of this space.

        Returns:
            int : base position point before appending.
        """
        base_point = self.get_current_base_pos()
        encoding_list = struct.pack(self.prefix_byte_order + "I", dword)
        self.append_chunk(encoding_list, variable_name)
        return base_point

    def append_word(self, word, variable_name=None):
        base_point = self.get_current_base_pos()
        encoding_list = struct.pack(self.prefix_byte_order + "H", word)
        self.append_chunk(encoding_list, variable_name)
        return base_point

    def append_byte(self, byte, variable_name=None):
        base_point = self.get_current_base_pos()
        encoding_list = struct.pack(self.prefix_byte_order + "B", byte)
        self.append_chunk(encoding_list, variable_name)
        return base_point

    def declare_dword(self, init_value=None, variable_name=None):
        """declare and set up dword type variable.

        Args:
            init_value: value of this variable
            variable_name:  name of this variable

        Returns:
            int : current base position.
        """
        if init_value == 0:
            return self.append_dword(0, variable_name)
        else:
            return self.append_dword(init_value, variable_name)

    def declare_word(self, init_value=None, variable_name=None):
        if init_value == 0:
            return self.append_word(0, variable_name)
        else:
            return self.append_word(init_value, variable_name)

    def declare_byte(self, init_value=None, variable_name=None):
        if init_value == 0:
            return self.append_byte(0, variable_name)
        else:
            return self.append_byte(init_value, variable_name)

    def set_variable_value(self, variable_name, value):
        if variable_name in self.variable:
            self.variable[variable_name] = value
        else:
            print("CANNOT FIND VARIABLE NAME")
            exit()

    def get_variable_reference(self, variable_name):
        if variable_name in self.variable:
            return self.variable[variable_name]
        else:
            print("CANNOT FIND VARIABLE NAME")
            exit()

    def get_variable_value(self, variable_name):
        if variable_name in self.variable:
            address = self.variable[variable_name]
            return self.data[address:address + 4]
        else:
            print("CANNOT FIND VARIABLE NAME")
            exit()
