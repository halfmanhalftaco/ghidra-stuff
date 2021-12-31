#!/usr/bin/env python2
from __future__ import print_function

import struct
import os
import sys
from collections import namedtuple
import binascii
import glob
from datetime import datetime

in_ghidra = "ghidra" in globals()

OMAGIC = 0o407
NMAGIC = 0o410
ZMAGIC = 0o413

ECOFFHeader = namedtuple('ECOFFHeader', 'f_magic f_nscns f_timdat f_symptr f_nsyms f_opthdr f_flags')
AOutHeader = namedtuple('AOutHeader', 'magic vstamp tsize dsize bsize entry text_start data_start bss_start gprmask cprmask0 cprmask1 cprmask2 cprmask3 gp_value')
COFFSectionHeader = namedtuple('COFFSectionHeader', 's_name s_paddr s_vaddr s_size s_scnptr s_relptr s_lnnoptr s_nreloc s_nlnno s_flags')
LibSectionHeader = namedtuple('LibSectionHeader', 'size offset tsize dsize bsize text_start data_start bss_start')

def bytestring(b):
    return b.rstrip(b'\x00').decode('ascii')

def main():
    if not in_ghidra:
        if len(sys.argv) > 1:
            file = sys.argv[1]
        else:
            file = "irix53_lib/libc_s"
    else:
        file = askFile("Select ECOFF binary to import", "Import")
        file = file.toString()

    f = loadECOFF(file)
    addToGhidra(f)

def loadAll():
    for obj in glob.glob('*.o'):
        loadECOFF(obj)

def loadECOFF(filename):
    global symbols, externs

    bin = open(filename, "rb")
    shlibs = []
    sections = []

    # MIPS32
    header_fmt = ">2H3L2H"
    aout_fmt = ">2H13L"
    scnhdr_fmt = ">8s6L2HL"
    reloc_fmt = ">2L"
    libscn_fmt = ">8L"
    symhdr_fmt = ">2H23L"

    header_size = struct.calcsize(header_fmt)
    aout_size = struct.calcsize(aout_fmt)
    scnhdr_size = struct.calcsize(scnhdr_fmt)
    reloc_size = struct.calcsize(reloc_fmt)
    libscn_size = struct.calcsize(libscn_fmt)
    symhdr_size = struct.calcsize(symhdr_fmt)

    header_bytes = bin.read(header_size)
    bin_header = struct.unpack(header_fmt, header_bytes)
    ecoff = ECOFFHeader(*bin_header)

    if ecoff.f_magic != 0x0160:
        print("This file is likely not a MIPSEB ECOFF file.")

    print("Magic: " + hex(ecoff.f_magic))
    print("Sections: " + str(ecoff.f_nscns))
    print("Timestamp: " + str(datetime.fromtimestamp(ecoff.f_timdat)))
    print("Ptr to Symhdr: " + hex(ecoff.f_symptr))
    print("Symbols: " + str(ecoff.f_nsyms))
    print("Size of a.out header: " + str(ecoff.f_opthdr))
    print("Flags: " + hex(ecoff.f_flags))

    aout_bytes = bin.read(aout_size)
    aout_header = struct.unpack(aout_fmt, aout_bytes)
    aout = AOutHeader(*aout_header)

    print("a.out magic: " + oct(aout.magic))
    print("entry point: " + hex(aout.entry))
    print(aout)
    
    for i in range(bin_header[1]):
        section_hdr_bytes = bin.read(scnhdr_size)
        section_hdr = struct.unpack(scnhdr_fmt, section_hdr_bytes)
        s = COFFSectionHeader(*(bytestring(section_hdr[0]),) + section_hdr[1:])
        print("Section: {}, {} bytes, {} relocations".format(s.s_name, s.s_size, s.s_nreloc))

        if s.s_size > 0:
            pos = bin.tell()
            bin.seek(s.s_scnptr)
            s_data = bin.read(s.s_size)
            bin.seek(pos)
        else:
            s_data = None
        if s.s_name == ".text":
            print(".text section load address: {}, a.out header text loc: {}".format(hex(s.s_vaddr), hex(aout.text_start)))
        if s.s_name == ".data":
            print(".data section load address: {}, a.out header data loc: {}".format(hex(s.s_vaddr), hex(aout.data_start)))
        if s.s_name == ".bss":
            print(".bss section load address: {}, a.out header bss loc: {}".format(hex(s.s_vaddr), hex(aout.bss_start)))
        if s.s_name == ".lib":
            buf_pos = 0
            while buf_pos < s.s_size:
                lib_hdr = struct.unpack(libscn_fmt, s_data[buf_pos:buf_pos+libscn_size])
                l = LibSectionHeader(*lib_hdr)
                path = s_data[buf_pos+(l.offset*4):buf_pos+(l.size)*4]
                path = bytestring(path)
                shlibs.append({'header': l, 'path': path})
                buf_pos = buf_pos+(l.size*4)
                print(" shared library: {} load addr: {}".format(path, hex(l.text_start)), path)


        sections.append({'header': s, 'data': s_data})

    if ecoff.f_symptr > 0:
        bin.seek(ecoff.f_symptr)
        symhdr_bytes = bin.read(symhdr_size)
        symhdr = struct.unpack(symhdr_fmt, symhdr_bytes)
        assert symhdr[0] == 0x7009 # magic
        print(symhdr)

    bin.close()
    return {'filename': os.path.basename(filename), 'filehdr': ecoff, 'aouthdr': aout, 'sections': sections, 'shlibs': shlibs }


def addToGhidra(f):
    if not in_ghidra:
        return

    cpu = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("MIPS"))
    compiler = cpu.getDefaultCompilerSpec()
    prog = createProgram(f['filename'], cpu, compiler)

    tran = prog.startTransaction("Load binary")

    for section in f['sections']:
        h = section['header']
        section_name = h.s_name
        print("Loading section \"" + section_name + "\"")

        if h.s_size == 0:
            continue
        if h.s_scnptr == 0:
            m = createMemoryBlock(section_name, parseAddress("0x%x" % h.s_vaddr), None, h.s_size, False)
        else:
            m = createMemoryBlock(section_name, parseAddress("0x%x" % h.s_vaddr), section['data'], False)

        if section_name == ".text":
            m.setExecute(True)
            m.setWrite(False)
        elif section_name == ".bss" or section_name == ".sbss":
            m.setExecute(False)
            m.setWrite(True)

    for l in f['shlibs']:
        # find lib, figure out how to load symbols
        pass

    addEntryPoint(parseAddress("0x%x" % f['aouthdr'].entry))

    analyzeChanges(prog)
    prog.endTransaction(tran, True)
    
    saveProgram(prog)

main()
