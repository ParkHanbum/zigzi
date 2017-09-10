import collections
from PEManager import *


class Chunk(object):

    def __init__(self, pe_manager, size=0x1000):
        """
        creator of memory chunk that be allocated.

        Args:
            pe_manager(PEManager) : target PEManager to append chunk.
            size(int) : size of chunk.
        """
        if not isinstance(pe_manager, PEManager):
            raise TypeError('data should be of type: PEManager')
        data = bytearray(size)
        section = pe_manager.create_new_data_section(data, ".zigzi")
        self.pe_manager = pe_manager
        self.offset = section.PointerToRawData
        self.offset_end = section.SizeOfRawData
        self.section_rva = section.VirtualAddress
        self.section_va = pe_manager.get_abs_va_from_rva(self.section_rva)
        self.size = size

    def __len__(self):
        return self.size

    def __getitem__(self, i):
        if type(i) is slice:
            start = i.start + self.offset
            stop = i.stop + self.offset
            step = i.step
            if step is not None:
                print("NOT SUPPORTED STEP")
        else:
            start = self.offset + i
            stop = self.offset + i + 1

        if start >= self.size + self.offset\
                or start < self.offset:
            raise IndexError(
                "Indexing is out of range Min:0 ~ Max:{} but argument:{}"
                    .format(self.size, start - self.offset)
            )
        if stop >= self.size + self.offset \
                or start < self.offset:
            raise IndexError(
                "Indexing is out of range Min:0 ~ Max:{} but argument:{}"
                    .format(self.size, start - self.offset)
            )

        return self.pe_manager.get_bytes_at_offset(start, stop)

    def __delitem__(self, i):
        pass

    def __setitem__(self, i, v):
        if type(i) is slice:
            start = i.start + self.offset
            stop = i.stop
            step = i.step
            if step is not None:
                print("NOT SUPPORTED STEP")
                exit()
        else:
            start = i + self.offset

        if start >= self.size + self.offset \
                or start < self.offset:
            raise IndexError(
                "Indexing is out of range Max:{} but argument:{}"
                    .format(self.size, start - self.offset)
            )
        self.pe_manager.PE.set_bytes_at_offset(start, v)
                                               # struct.pack('<L', v))

    def get_va(self):
        return self.section_va
