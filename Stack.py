"""Stack,
helper class for stack.
"""

from DataObject import *


class Stack(DataObject):

    _Stack_frame_point = "Stack_Frame_Pointer"
    _Stack_base_point = "Stack_Base_Pointer"

    def __init__(self, base_address, stack_size=0x1000):
        DataObject.__init__(self, base_address)
        self.declare_dword(0, self._Stack_frame_point)
        self.declare_dword(0, self._Stack_base_point)
        stack_space = [chr(int("0", 16))] * stack_size
        # allocation stack space
        stack_point = self.append_chunk(stack_space, "stack")
        # This is only specification of stack
        # set _frame_point to base_point
        self.set_variable_value(self._Stack_frame_point, stack_point)
        self.set_variable_value(self._Stack_base_point, stack_point)

    @property
    def frame_point(self):
        return self.get_variable_reference(self._Stack_frame_point)

    @frame_point.setter
    def frame_point(self, value):
        return self.set_variable_value(self._Stack_frame_point, value)

    @property
    def base_point(self):
        return self.get_variable_reference(self._Stack_base_point)

    @base_point.setter
    def base_point(self, value):
        return self.set_variable_value(self._Stack_base_point, value)

    def push(self, value, variable_name=None):
        self.frame_point = self.append_dword(value, variable_name)
        return self.frame_point

    def pop(self):
        value = self.get_variable_value(self.frame_point)
        self.frame_point -= 4
        return value

