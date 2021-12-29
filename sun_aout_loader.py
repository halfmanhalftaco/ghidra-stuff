# Load a SunOS 3.x/4.x 68k a.out binary into Ghidra

# a.out format reference:
# https://www.freebsd.org/cgi/man.cgi?query=a.out&apropos=0&sektion=5&manpath=SunOS+4.1.3&arch=default&format=html


import struct
import os
import sys
from collections import namedtuple
import binascii
import glob

print("Python version", sys.version, sys.version_info)
in_ghidra = "ghidra" in globals()

PAGESIZE = 0x02000
SEGSIZE = 0x20000

OMAGIC = 0o407
NMAGIC = 0o410
ZMAGIC = 0o413

M_OLDSUN2 = 0
M_68010 = 1
M_68020 = 2
M_SPARC = 3

AOutHeader = namedtuple('AOutHeader', 'a_dynamic a_toolversion a_machtype a_magic a_text a_data a_bss a_syms a_entry a_trsize a_drsize')
MemoryMap = namedtuple('MemoryMap', 'text_addr data_addr bss_addr extern_addr')
Symbol = namedtuple('Symbol', 'name n_type n_other n_desc n_value n_value_orig')

symbols = []

def iter_unpack(fmt, buffer):
    fmtsize = struct.calcsize(fmt)
    for i in range(0, len(buffer), fmtsize):
        yield struct.unpack_from(fmt, buffer, i)

def reloc(segment, mmap, offset, r_symbolnum, flags):
    global symbols
    r_extern = False

    desc = ""

    reloc_len = (flags & 0x60) >> 5
    if reloc_len == 0:
        desc += "byte "
    if reloc_len == 1:
        desc += "word "
    if reloc_len == 2:
        desc += "long "

    if reloc_len != 2:
        print("Only long reloc supported currently")
        sys.exit(1)

    if flags & 0x80:
        desc += "pcrel "
    if flags & 0x10:
        desc += "extern "
        r_extern = True
    if flags & 0x08:
        desc += "baserel "
    if flags & 0x04:
        desc += "jmptable "
    if flags & 0x02:
        desc += "relative "

    if not r_extern:
        n_type = r_symbolnum & 0x1e
        if n_type == 0x2:
            desc += "abs "
        elif n_type == 0x4:
            desc += "text "
        elif n_type == 0x6:
            desc += "data "
        elif n_type == 0x8:
            desc += "bss "
        elif n_type == 0x12:
            desc += "comm "
        elif n_type == 0x1f:
            desc += "fname "
    else:
        desc += "sym: " + symbols[r_symbolnum].name + ' '

    orig_val = struct.unpack('>l', bytes(segment[offset:offset+4]))[0]
    desc += "({:#010x}".format(orig_val)

    if not r_extern:
        new_val = None
        if n_type == 0x4:
            new_val = mmap.text_addr + orig_val
        elif n_type == 0x6:
            new_val = mmap.data_addr + orig_val
        elif n_type == 0x8:
            new_val = mmap.data_addr + orig_val

        if new_val:
            reloc_data = struct.pack('>L', new_val)
            segment[offset:offset+4] = reloc_data
            desc += " -> {:#010x}".format(new_val)
    else:
        sym = symbols[r_symbolnum]
        if flags & 0x80:
            new_val = sym.n_value - (mmap.text_addr + offset)
        else:
            new_val = sym.n_value
        reloc_data = struct.pack('>L', new_val)
        segment[offset:offset+4] = reloc_data
        desc += " -> {:#010x}".format(new_val)

    desc += ")"

    print("    {:#010x} {:#08x} {:08b} {}".format(offset, r_symbolnum, flags, desc))


def main():
    if not in_ghidra:
        #file = "sun3_sunos411u1/lib/libc.so.0.15.2"
        file = "../ghidra/hello"
        #file = "rpc.frameusersd"
    else:
        file = askFile("Select Sun a.out binary to import", "Import")
        file = file.toString()

    loadBinary(file)

def loadAll():
    for obj in glob.glob('/data/frame/sun3_sunos35_libc/[A-Z]*.o'):
        loadBinary(obj)

def loadBinary(filename):
    global symbols, externs

    bin = open(filename, "rb")

    header_fmt = ">2BH7L"
    reloc_fmt = ">LL"
    sym_fmt = ">lBbhL"
    header_size = struct.calcsize(header_fmt)
    reloc_size = struct.calcsize(reloc_fmt)
    sym_size = struct.calcsize(sym_fmt)

    header_bytes = bin.read(header_size)
    bin_header = struct.unpack(header_fmt, header_bytes)
    a_dynamic = (bin_header[0] & 0x80 ) == 0x80
    a_toolversion = bin_header[0] & 0x7F

    header = AOutHeader._make((a_dynamic, a_toolversion) + bin_header[1:])

    # determine load addresses

    if header.a_magic == ZMAGIC and header.a_entry < PAGESIZE:
        text_addr = 0
    else:
        text_addr = PAGESIZE

    data_addr = (SEGSIZE + text_addr + header.a_text - 1) & ~(SEGSIZE-1)
    bss_addr = data_addr + header.a_data

    mmap = MemoryMap(text_addr, data_addr, bss_addr, 0x800000)

    if header.a_magic == ZMAGIC:
        bin.seek(0)

    # read segments and reloc, symbol and string tables

    text = bytearray(bin.read(header.a_text))
    data = bytearray(bin.read(header.a_data))

    if header.a_trsize > 0:
        text_reloc = bin.read(header.a_trsize)
    if header.a_drsize > 0:
        data_reloc = bin.read(header.a_drsize)
    if header.a_syms > 0:
        syms = bin.read(header.a_syms)

    string_table = ''
    try:
        string_table_size, = struct.unpack(">L", bin.read(4))
    except:
        print("couldn't read string table size (probably no strings)")
        string_table_size = 0

    if string_table_size > 0:
        string_table = bin.read(string_table_size - 4)

    bin.close()

    if header.a_machtype == M_OLDSUN2:
        a_machtype = "M_OLDSUN2"
    elif header.a_machtype == M_68010:
        a_machtype = "M_68010"
    elif header.a_machtype == M_68020:
        a_machtype = "M_68020"
    elif header.a_machtype == M_SPARC:
        a_machtype == "M_SPARC"

    if header.a_magic == OMAGIC:
        a_magic = "OMAGIC"
    elif header.a_magic == NMAGIC:
        a_magic = "NMAGIC"
    elif header.a_magic == ZMAGIC: 
        a_magic = "ZMAGIC"

    print(os.path.basename(filename), '({} {})'.format(a_machtype, a_magic))
    print(header)

    print("  .text: 0x%x at 0x%x" % (len(text), mmap.text_addr))
    print("  .data: 0x%x at 0x%x" % (len(data), mmap.data_addr))
    print("  .bss: 0x%x at 0x%x" % (header.a_bss, mmap.bss_addr))
    print("  entry at 0x%x" % header.a_entry)
    
    symbols = []
    extern_size = 0

    if header.a_syms > 0:
        print("  symbols: ", int(header.a_syms / sym_size))
        for (n_strx, n_type, n_other, n_desc, n_value) in iter_unpack(sym_fmt, syms):
            end = string_table.find(b"\0", n_strx - 3)
            if end != -1:
                sym_str = string_table[n_strx-4:end].decode('ascii')
            else:
                sym_str = string_table[n_strx-4:].decode('ascii')

            desc = ''
            if n_type & 0x1:
                desc = 'extern '
            reloc_type = n_type & 0x1e
            if reloc_type == 0:
                desc += "undf "
            if reloc_type == 0x2:
                desc += "abs "
            if reloc_type == 0x4:
                desc += "text "
            if reloc_type == 0x6:
                desc += "data "
            if reloc_type == 0x8:
                desc += "bss "

            n_value_orig = n_value
            if n_type == 0x1 and n_value == 0:  # external symbol, create placeholder
                n_value = mmap.extern_addr + extern_size
                extern_size += 4

            symbols.append(Symbol(sym_str, n_type, n_other, n_desc, n_value, n_value_orig))
            print("{:>16} {:#04x} {:#06x} {:#010x} {}".format(sym_str, n_type, n_desc, n_value, desc))

    if header.a_trsize > 0:
        print("  text relocations:", int(header.a_trsize / reloc_size))
        for (r_addr, flags) in iter_unpack(reloc_fmt, text_reloc):
            r_symbolnum = (flags & 0xFFF0) >> 8
            flags = flags & 0xFF
            reloc(text, mmap, r_addr, r_symbolnum, flags)

    if header.a_drsize > 0:
        print("  data relocations:", int(header.a_drsize / reloc_size))
        for (r_addr, flags) in iter_unpack(reloc_fmt, data_reloc):
            r_symbolnum = (flags & 0xFFF0) >> 8
            flags = flags & 0xFF
            reloc(data, mmap, r_addr, r_symbolnum, flags)
            
    if len(string_table) > 0:
        strings = string_table.split(b"\0")
        print("  strings: ", len(strings))


    if not in_ghidra:
        return

    cpu = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("68000"))
    compiler = cpu.getDefaultCompilerSpec()
    prog = createProgram(os.path.basename(filename), cpu, compiler)

    tran = prog.startTransaction("Load binary")
    if header.a_text > 0:
        createMemoryBlock('.text', parseAddress("0x%x" % mmap.text_addr), bytes(text), False)
    if header.a_data > 0:
        createMemoryBlock('.data', parseAddress("0x%x" % mmap.data_addr), bytes(data), False)
    if header.a_bss > 0:
        createMemoryBlock('.bss', parseAddress("0x%x" % mmap.bss_addr), None, header.a_bss, False)
    if extern_size > 0:
        createMemoryBlock('.extern', parseAddress("0x%x" % mmap.extern_addr), None, extern_size, False)

    for sym in symbols:
        if sym.name.endswith('.o'):
            continue

        sym_base = None
        if sym.n_type & 0x1e == 0x4:
            sym_base = mmap.text_addr
        elif sym.n_type & 0x1e == 0x6:
            sym_base = mmap.data_addr
        elif sym.n_type & 0x1e == 0x8:
            sym_base = mmap.bss_addr

        if sym_base is not None:
            createLabel(parseAddress("0x%x" % (sym_base + sym.n_value)), sym.name, False)
            print("Created label for symbol {} at {:#010x}".format(sym.name, sym_base + sym.n_value))
        elif sym.n_type == 0x1 and sym.n_value >= mmap.extern_addr:
            createLabel(parseAddress("0x%x" % (sym.n_value)), sym.name, False)
            print("Created label for extern symbol {} at {:#010x}".format(sym.name, sym.n_value))

    if header.a_entry == 0:
        addEntryPoint(parseAddress("0x%x" % mmap.text_addr))
    else:
        addEntryPoint(parseAddress("0x%x" % header.a_entry))

    analyzeChanges(prog)
    prog.endTransaction(tran, True)
    
    saveProgram(prog)

main()
