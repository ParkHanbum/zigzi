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
        self.PEName = name
        PEFile = open(name, 'r+b')
        PEFileBytes = bytearray(PEFile.read())
        FastLoad = False
        PEData = mmap.mmap(PEFile.fileno(), 0, access=mmap.ACCESS_COPY)
        self.PEOrigin = PE(None, data=PEData, fast_load=False)
        self.PE = PE(None, data=PEData, fast_load=False)

        self._IMAGE_BASE_ = self.PE.OPTIONAL_HEADER.ImageBase

        # self.PE.full_load()
        # self.PE = pefile.PE(name)
        self.instrumentor = None

    def setInstrumentor(self, instrumentor):
        self.instrumentor = instrumentor

    def getInstrumentor(self):
        return self.instrumentor

    def getFileName(self):
        return self.PEName

    def getSectionHeaders(self):
        return self.PE.sections

    def getClonedSectionHeader(self, section):
        cloneSection = copy.copy(section)
        return cloneSection

    def appendSectionToFile(self, section):
        self.PE.sections.append(section)
        self.PE.__structures__.append(section)

    def getFileData(self):
        return self.PE.__data__

    def getAlignedOffset(self, offset):
        fileAlign = self.PE.OPTIONAL_HEADER.FileAlignment
        v = offset % fileAlign
        if v > 0:
            return (offset - v) + fileAlign
        return offset

    def getAlignedVA(self, va):
        alignedVA = self.getSectionAlign()
        v = va % alignedVA
        if v > 0:
            return (va - v) + alignedVA
        return va

    def appendDataToFile(self, data):
        origDataLen = len(self.PE.__data__)
        alignedOrigDataLen = self.getAlignedOffset(origDataLen)
        dataLen = len(data)
        alignedDataLen = self.getAlignedOffset(dataLen)
        # make null space for data.
        space = bytearray((alignedOrigDataLen+alignedDataLen) - origDataLen + 1)
        self.PE.set_bytes_at_offset(origDataLen - 1, bytes(space))
        #self.PE.__data__[origDataLen:alignedOrigDataLen+alignedDataLen] = space
        # Fill space with data
        self.PE.set_bytes_at_offset(alignedOrigDataLen, bytes(data))
        #self.PE.__data__[alignedOrigDataLen:alignedOrigDataLen+alignedDataLen] = data
        return alignedOrigDataLen, alignedDataLen

    def createNewSectionHeader(self, pointToRaw, sizeOfRaw):
        # TODO : We assume that the new section to be created is a copy of the 0th section, text section.
        newSection = self.getClonedSectionHeader(self.PE.sections[0])
        newSection.SizeOfRawData = sizeOfRaw
        newSection.PointerToRawData = pointToRaw
        newSection.Misc_VirtualSize = self.getAlignedVA(sizeOfRaw)
        newSection.Misc_PhysicalAddress = self.getAlignedVA(sizeOfRaw)
        newSection.Misc = self.getAlignedVA(sizeOfRaw)
        self.PE.OPTIONAL_HEADER.SizeOfCode = newSection.Misc_VirtualSize
        #self.PE.OPTIONAL_HEADER.SizeOfImage = point_to_raw + size_of_raw
        self.appendSectionToFile(newSection)
        return newSection

    def createNewSectionWithData(self, data):
        (pointToRaw, sizeOfRaw) = self.appendDataToFile(data)
        return self.createNewSectionHeader(pointToRaw, sizeOfRaw)

    def createNewExecutionSection(self, pointToRaw, sizeOfRaw, sizeOfData):
        # TODO : We assume that the new section to be created is a copy of the 0th section, text section.
        self.PE.sections[0].SizeOfRawData = sizeOfRaw
        self.PE.sections[0].PointerToRawData = pointToRaw
        self.PE.sections[0].Misc_VirtualSize = sizeOfData
        self.PE.sections[0].Misc_PhysicalAddress = sizeOfData
        self.PE.sections[0].Misc = sizeOfData
        self.PE.OPTIONAL_HEADER.SizeOfCode = sizeOfData
        # self.PE.OPTIONAL_HEADER.SizeOfImage = point_to_raw + size_of_raw

    def appendDataToExecution(self, data):
        sizeOfData = len(data)
        (pointToRaw, sizeOfRaw) = self.appendDataToFile(data)
        self.createNewExecutionSection(pointToRaw, sizeOfRaw, sizeOfData)

    def getSectionRawData(self, sectionHeader):
        startOffset = sectionHeader.PointerToRawData
        size = sectionHeader.SizeOfRawData
        data = bytearray(self.PE.__data__[startOffset:startOffset+size])
        return data

    def getEntryPointVA(self):
        return self.PE.OPTIONAL_HEADER.AddressOfEntryPoint

    def getExecutableVirtualAddressRange(self):
        executableSection = self.getExecutableSection()
        va_size = executableSection.Misc_VirtualSize
        va = executableSection.VirtualAddress
        return va, va + va_size

    def getExecutableSection(self):
        for currentSection in self.getSectionHeaders():
            if currentSection.Characteristics & 0x20000000:
                return currentSection

    def getSectionAlign(self):
        return self.PE.OPTIONAL_HEADER.SectionAlignment

    def setEntryPoint(self, entry_va):
        self.PE.OPTIONAL_HEADER.AddressOfEntryPoint = entry_va

    def write(self, path):
        self.uncerfication()
        self.adjustFileLayout()
        self.PE.merge_modified_section_data()
        self.PE.OPTIONAL_HEADER.SizeOfImage = self.getImageSize()
        self.PE.OPTIONAL_HEADER.CheckSum = 0
        self.PE.OPTIONAL_HEADER.CheckSum = self.PE.generate_checksum()
        self.PE.write(path)

    def getImageSize(self):
        section = self.PE.sections[-1]
        va = section.VirtualAddress
        size = section.Misc_VirtualSize
        return self.getAlignedVA(va + size)

    def getRelocationMap(self):
        relocation_map = {}
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            for entry in self.PE.DIRECTORY_ENTRY_BASERELOC:
                for el in entry.entries:
                    if el.struct.Data == 0:
                        continue
                    address = el.rva
                    relocation_map[address] = [el.rva, address, el.type]
        return relocation_map

    def getRelocationMapFromFile(self):
        structuresRelocationBlock = {}
        structuresRelocationEntries = {}
        block_va = -1
        for entry in self.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if block_va > 0:
                    structuresRelocationEntries[block_va].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                block_va = entry.VirtualAddress
                structuresRelocationBlock[block_va] = entry
                structuresRelocationEntries[block_va] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"
        return structuresRelocationEntries

    def isRelocable(self):
        if hasattr(self.PE, 'DIRECTORY_ENTRY_BASERELOC'):
            return True
        return False

    def adjustFileLayout(self):

        self.adjustEntryPoint()
        self.adjustExecutableSection()
        self.adjustImport()
        self.adjustRelocationDirectories()

        self.adjustSection()
        self.adjustOptionalHeader()
        self.adjustDataDirectories()

    def adjustSection(self):
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
                print "adjust virtual address"
                section_va = dst_section.VirtualAddress
                adjusted_section_va = section_va + (src_va_end - section_va)
                adjusted_section_va = self.getAlignedVA(adjusted_section_va)
                self.PE.sections[index+1].VirtualAddress = adjusted_section_va
                self.PE.sections[index].next_section_virtual_address = adjusted_section_va

    def adjustOptionalHeader(self):
        # adjust base of data
        if hasattr(self.PEOrigin.OPTIONAL_HEADER, 'BaseOfData'):
            baseOfData = self.PEOrigin.OPTIONAL_HEADER.BaseOfData
            for index in xrange(len(self.PEOrigin.sections)):
                section = self.PEOrigin.sections[index]
                if section.VirtualAddress <= baseOfData < section.VirtualAddress + section.Misc_VirtualSize:
                    baseOfDataSectionRVA = baseOfData - section.VirtualAddress
                    adjustedSection = self.PE.sections[index]
                    self.PE.OPTIONAL_HEADER.BaseOfData = adjustedSection.VirtualAddress + baseOfDataSectionRVA

    def adjustDataDirectories(self):
        Sections = self.PE.sections
        OriginSections = self.PEOrigin.sections
        dataDirectories = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY

        for index in xrange(len(Sections)):
            section = Sections[index]
            originSection = OriginSections[index]
            dataDirectories = self.adjustFileHeaderDirectories(dataDirectories,
                                                               originSection.VirtualAddress,
                                                               section.VirtualAddress,
                                                               originSection.VirtualAddress,
                                                               section.Misc_VirtualSize)

    def adjustFileHeaderDirectories(self, dataDirectories, sectionOriginVA, sectionAdjustedVA,
                                    originSectionSize, adjustedSectionSize):
        directoryAdjust = {
            # 'IMAGE_DIRECTORY_ENTRY_IMPORT': self.adjustImport,
            # 'IMAGE_DIRECTORY_ENTRY_DEBUG': self.adjustDebug,
            'IMAGE_DIRECTORY_ENTRY_TLS': self.adjustTLS,
            'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG': self.adjustLoadConfig,
            'IMAGE_DIRECTORY_ENTRY_EXPORT': self.adjustExport,
            'IMAGE_DIRECTORY_ENTRY_RESOURCE': self.adjustResource,
            'IMAGE_DIRECTORY_ENTRY_BASERELOC': self.adjustRelocation,
            'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT': self.adjustDelayImport,
            'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT': self.adjustBoundImports
        }

        removeList = []
        increasedSize = sectionAdjustedVA - sectionOriginVA
        for directory in dataDirectories:
            if sectionOriginVA <= directory.VirtualAddress < sectionOriginVA + originSectionSize:
                index = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY.index(directory)
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress = directory.VirtualAddress + increasedSize
                try:
                    if directory.name in directoryAdjust:
                        entry = directoryAdjust[directory.name]
                        entry(directory, directory.VirtualAddress, directory.Size, increasedSize)
                except IndexError:
                    print "===== [INDEX ERROR] ====="
                    return False
                removeList.append(directory)
        for el in removeList:
            dataDirectories.remove(el)
        return dataDirectories

    def uncerfication(self):
        for index in range(len(self.PE.OPTIONAL_HEADER.DATA_DIRECTORY)):
            directory = self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            if directory.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress = 0
                self.PE.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size = 0

    def adjustRelocation(self, directory, rva, size, increase_size):
        log = open(os.path.join(os.getcwd(), 'peutil_adjust_relocation.log'), 'w')
        relocation_map = self.getRelocationMapFromFile()
        # TODO : fix assume that first section is text.
        sections = self.PEOrigin.sections
        executeSectionStart = sections[0].VirtualAddress
        executeSectionEnd = executeSectionStart + sections[0].Misc_VirtualSize
        otherSectionStart = sections[1].VirtualAddress
        otherSectionEnd = sections[-1:][0].VirtualAddress + sections[-1:][0].Misc_VirtualSize
        sortedRelocationMap = sorted(relocation_map.items(), key=operator.itemgetter(0))
        for blockVA, entries in sortedRelocationMap:
            for entry in entries:
                if entry.Data == 0x0:
                    continue
                # get instrument size from 0x0(imagebase 0x400000, textsection 0x1000, till value)
                address = (entry.Data & 0xfff) + blockVA
                value = self.PE.get_dword_at_rva(address)
                if executeSectionStart + self._IMAGE_BASE_ <= value < executeSectionEnd + self._IMAGE_BASE_:
                    # get instrument size from 0x0(imagebase self._IMAGE_BASE_, textsection 0x1000, till value)
                    instrumented_size = self.getInstrumentor().getInstrumentSizeWithVector(value - self._IMAGE_BASE_ - increase_size)
                    self.setDwordAtRVA(address, value + instrumented_size)
                    log.write("[IF] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n".format(address, value, self.PE.get_dword_at_rva(address), instrumented_size))
                elif otherSectionStart + self._IMAGE_BASE_ <= value < otherSectionEnd + self._IMAGE_BASE_:
                    self.setDwordAtRVA(address, value + increase_size)
                    log.write("[ELIF] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n".format(address, value, self.PE.get_dword_at_rva(address), increase_size))
                else:
                    log.write(
                        "[ELSE] [0x{:x}]\t0x{:x}\t0x{:x}\t0x{:x}\n".format(address, value, self.PE.get_dword_at_rva(address), increase_size))
                    # if executeSectionEnd + self._IMAGE_BASE_ < value < otherSectionStart + self._IMAGE_BASE_:
        return 0

    def adjustLoadConfig(self, directory, rva, size, increase_size):
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
        if self.PE.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie > 0x0:
            self.PE.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie += increase_size
        if self.PE.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable > 0x0:
            self.PE.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable += increase_size
        if self.PE.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFCheckFunctionPointer > 0x0:
            self.PE.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFCheckFunctionPointer += increase_size
        # Security_Cookie_VA = self.PE.get_dword_at_rva(rva + 0x3C)
        # self.setDwordAtRVA(rva + 0x3C, Security_Cookie_VA + increase_size)
        # SE_Handler_Table_VA = self.PE.get_dword_at_rva(rva + 0x40)
        # self.setDwordAtRVA(rva + 0x40, SE_Handler_Table_VA + increase_size)
        SE_Handler_Count = self.PE.get_dword_at_rva(rva + 0x44)
        return 0

    def adjustDebug(self, directory, rva, size, increase_size):
        return 0

    def adjustTLS(self, directory, rva, size, increase_size):
        if self.PE.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks > 0:
            self.PE.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks += increase_size
        if self.PE.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex > 0:
            self.PE.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex += increase_size
        if self.PE.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData > 0:
            self.PE.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData += increase_size
        if self.PE.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData > 0:
            self.PE.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData += increase_size
        return 0

    def adjustBoundImports(self, directory, rva, size, increase_size):
        return 0

    def adjustDelayImport(self, directory, rva, size, increase_size):
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
            instrumented_size = self.getInstrumentor(). \
                getInstrumentSizeWithVector(address - self._IMAGE_BASE_ - increase_size)
            iat.AddressOfData += instrumented_size
            iat.ForwarderString += instrumented_size
            iat.Function += instrumented_size
            iat.Ordinal += instrumented_size
            ilt.AddressOfData += increase_size
            ilt.ForwarderString += increase_size
            ilt.Function += increase_size
            ilt.Ordinal += increase_size

    # def adjustImport(self, directory, rva, size, increase_size):
    def adjustImport(self):
        for importindex in xrange(len(self.PE.DIRECTORY_ENTRY_IMPORT)):
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.Characteristics += 0x1000
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.FirstThunk += 0x1000
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.Name += 0x1000
            self.PE.DIRECTORY_ENTRY_IMPORT[importindex].struct.OriginalFirstThunk += 0x1000
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

    def adjustExport(self, directory, rva, size, increase_size):
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions += increase_size
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals += increase_size
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames += increase_size
        self.PE.DIRECTORY_ENTRY_EXPORT.struct.Name += increase_size

        for index in xrange(len(self.PE.DIRECTORY_ENTRY_EXPORT.symbols)):
            entry_name_rva = self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames + (index * 4)
            name_rva = self.PE.get_dword_at_rva(entry_name_rva)
            name_rva += increase_size
            self.setDwordAtRVA(entry_name_rva, name_rva)
            entry_function_rva = self.PE.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions + (index * 4)
            function_rva = self.PE.get_dword_at_rva(entry_function_rva)

            # when export RVA belong other section.
            if self.PEOrigin.sections[1].VirtualAddress <= function_rva:
                instrument_size = self.PE.sections[1].VirtualAddress - self.PEOrigin.sections[1].VirtualAddress

            # when export RVA belong code section.
            if self.PEOrigin.sections[0].VirtualAddress <= function_rva < self.PEOrigin.sections[1].VirtualAddress:
                instrument_size = self.getInstrumentor().getInstrumentSizeWithVector(function_rva - increase_size)
            self.setDwordAtRVA(entry_function_rva, function_rva + instrument_size)

    def adjustResource(self, directory, rva, size, increase_size):
        for rsrc_entries in self.PE.DIRECTORY_ENTRY_RESOURCE.entries:
            for rsrc_directory_entry in rsrc_entries.directory.entries:
                for rsrc_entry_directory_entry in rsrc_directory_entry.directory.entries:
                    # print "0x{:x}".format(rsrc_entry_directory_entry.data.struct.OffsetToData)
                    rsrc_entry_directory_entry.data.struct.OffsetToData += increase_size

    def setDwordAtRVA(self, rva, dword):
        return self.PE.set_dword_at_rva(rva, dword)

    def getSectionBelongRVA(self, sections, rva):
        for section in sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section

        return None

    def isExecutableSection(self, section):
        if section.Characteristics & 0x20000000:
            return True

        return False

    def adjustEntryPoint(self):
        entry_va = self.getEntryPointVA()
        instrumentSize = \
            self.getInstrumentor().getInstrumentSizeWithVector(entry_va - 0x1000)
        # instrumentSize = self.get_instrument_size_until(entry_va)
        self.setEntryPoint(entry_va + instrumentSize)


    def adjustExecutableSection(self):
        execute_data = self.getInstrumentor().getCode()
        self.appendDataToExecution(execute_data)


    def adjustRelocationDirectories(self):
        structuresRelocationBlock = {}
        structuresRelocationEntries = {}
        blockVA = -1
        for entry in self.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if blockVA > 0:
                    structuresRelocationEntries[blockVA].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                blockVA = entry.VirtualAddress
                structuresRelocationBlock[blockVA] = entry
                structuresRelocationEntries[blockVA] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"

        """
        TODO:
        #1
        If the virtual address of the relocation block exceeds the range of the text section,
        the virtual address of the relocation block is increased by the amount of movement of the section.
        If there is an entry that has moved to the next block due to the size instrumented
        in the previous relocation block, it must be processed.

        #2
        it can cause exception what address of next block is not exist.
        next block address is not sequential increase
        """
        sortedRelocationBlock = sorted(structuresRelocationBlock.items(), key=operator.itemgetter(0))
        sections = self.getSectionHeaders()
        section_start = sections[1].VirtualAddress
        structuresRelocationBlock.clear()
        for index, (blockVA, block) in enumerate(sortedRelocationBlock):
            # first, adjust other block besides text section
            # The cause, relocation factor can be added to the next block.
            if blockVA >= section_start:
                # 0x1000 mean increased size of section va.
                self.PE.__structures__[self.PE.__structures__.index(block)].VirtualAddress += 0x1000

        blockVA = -1
        for entry in self.PE.__structures__:
            if entry.name.find('IMAGE_BASE_RELOCATION_ENTRY') != -1:
                if blockVA > 0:
                    structuresRelocationEntries[blockVA].append(entry)
            elif entry.name.find('IMAGE_BASE_RELOCATION') != -1:
                blockVA = entry.VirtualAddress
                structuresRelocationBlock[blockVA] = entry
                structuresRelocationEntries[blockVA] = []
            elif entry.name.find('DIRECTORY_ENTRY_BASERELOC') != -1:
                "DIRECTORY"

        sortedRelocationBlock = sorted(structuresRelocationBlock.items(), key=operator.itemgetter(0))
        for index, (blockVA, block) in enumerate(sortedRelocationBlock):
            if blockVA < section_start:
                for entry in structuresRelocationEntries[blockVA]:
                    if entry.Data == 0:
                        continue
                    entry_rva = entry.Data & 0x0fff
                    entry_type = entry.Data & 0xf000
                    # 0x1000 mean virtual address of first section that text section.
                    entry_va = blockVA + entry_rva
                    instrumented_size = self.getInstrumentor().getInstrumentSizeWithVector(entry_va - 0x1000)
                    entry_rva += instrumented_size

                    # move entry to appropriate block
                    if entry_rva >= 0x1000:
                        self.PE.__structures__.remove(entry)
                        self.PE.__structures__[self.PE.__structures__.index(block)].SizeOfBlock -= 2
                        appropriateBlockVA = (entry_rva & 0xf000) + blockVA
                        entry.Data = (entry_rva & 0xfff) + entry_type

                        # if appropriate block address is exist.
                        if appropriateBlockVA in structuresRelocationBlock:
                            appropriateBlockIndex = \
                                self.PE.__structures__.index(structuresRelocationBlock[appropriateBlockVA])
                        else:
                            # create new relocation block with appropriateBlockVA
                            nextBlockVA, nextBlock = sortedRelocationBlock[index+1]
                            nextBlockIndex = self.PE.__structures__.index(nextBlock)
                            newBlock = copy.deepcopy(nextBlock)
                            newBlock.SizeOfBlock = 8
                            newBlock.VirtualAddress = appropriateBlockVA
                            appropriateBlockIndex = nextBlockIndex-1
                            structuresRelocationBlock[appropriateBlockVA] = newBlock
                            self.PE.__structures__.insert(appropriateBlockIndex, newBlock)
                        self.PE.__structures__[appropriateBlockIndex].SizeOfBlock += 2
                        self.PE.__structures__.insert(appropriateBlockIndex+1, entry)
                    else:
                        entry.Data = entry_rva + entry_type

        """
        structures has owned offset.
        so, if modify position or order of structures element then must fix offset of structures element.
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
