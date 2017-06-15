"""Heap,
helper class for heap space.
"""

import binascii
from DataObject import *


class Heap(DataObject):

    def __init__(self, base_address):
        DataObject.__init__(self, base_address)
        self._frame_point = base_address

    def append_element(self, element):
        self.is_appending = True
        self.data[self._frame_point:self._frame_point + 1] = element
        self._frame_point += 1

    def append_element_finish(self, last_element, variable_name):
        self.append_element(last_element)
        increase_size = self._frame_point - self._base_point
        # local variable log
        self.save_local_variable(self._frame_point - increase_size,
                                 variable_name)
        self._size += increase_size
        self._base_point = self._frame_point
        self.is_appending = False
        return increase_size

    def append_string(self, _str, variable_name=None):
        """
        Convert a string hex byte values into a byte string.
        The Hex Byte values may or may not be space separated.
        """
        base_point = self.get_current_base_pos()
        hex_str = binascii.hexlify(_str)
        hex_str = ''.join(hex_str.split(" "))
        for i in range(0, len(hex_str), 2):
            self.append_element(chr(int(hex_str[i:i + 2], 16)))
        self.append_element_finish(chr(int("0", 16)), variable_name)
        return base_point
