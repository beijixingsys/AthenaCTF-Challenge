import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

P = r'D:\2026\ctf\bjxctfbc\Agentctf\timu\round2_1330\pwn01\attachments\attachment'
f = open(P,'rb'); elf = ELFFile(f)
print('=== ELF header ===')
print('class', elf.elfclass, 'machine', elf['e_machine'], 'type', elf['e_type'], 'entry', hex(elf['e_entry']))
print('=== program headers ===')
for seg in elf.iter_segments():
    if seg['p_type'] in ('PT_LOAD','PT_GNU_STACK','PT_GNU_RELRO','PT_DYNAMIC','PT_INTERP'):
        print(' %-16s off=%#x vaddr=%#x filesz=%#x memsz=%#x flags=%s align=%#x' % (
            seg['p_type'], seg['p_offset'], seg['p_vaddr'], seg['p_filesz'], seg['p_memsz'], seg['p_flags'], seg['p_align']))
print('=== sections ===')
for sec in elf.iter_sections():
    if sec['sh_size']:
        print(' %-18s addr=%#010x off=%#08x size=%#08x flags=%s' % (sec.name, sec['sh_addr'], sec['sh_offset'], sec['sh_size'], sec['sh_flags']))
print()
print('=== symbols (FUNC/OBJECT, non-zero) ===')
sym = elf.get_section_by_name('.symtab')
for s in sym.iter_symbols():
    if s['st_value'] and s['st_info']['type'] in ('STT_FUNC','STT_OBJECT'):
        print(' %-24s %#010x size=%d type=%s' % (s.name, s['st_value'], s['st_size'], s['st_info']['type']))
print()
print('=== dynamic symbols (imports) ===')
dyn = elf.get_section_by_name('.dynsym')
gotmap = {}
for s in dyn.iter_symbols():
    if s.name:
        print(' %-22s %#x' % (s.name, s['st_value']))
print()
print('=== relocations ===')
for sec in elf.iter_sections():
    if 'rel' in sec.name and sec['sh_size']:
        print('--', sec.name)
        for r in sec.iter_relocations():
            print('   off=%#x sym=%s type=%s' % (r['r_offset'], dyn.get_symbol(r['r_info_sym']).name if r['r_info_sym'] else '', r['r_info_type']))
print()
print('=== version needs ===')
vn = elf.get_section_by_name('.gnu.version_r')
if vn:
    for v in vn.iter_versions():
        print(' ', v.name, [str(x.name) for x in v.aux])
