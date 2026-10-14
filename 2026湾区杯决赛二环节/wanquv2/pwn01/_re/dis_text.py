from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
P = r'D:\2026\ctf\bjxctfbc\Agentctf\timu\round2_1330\pwn01\attachments\attachment'
f=open(P,'rb'); elf=ELFFile(f)
md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
sec=elf.get_section_by_name('.text')
data=sec.data(); base=sec['sh_addr']
for ins in md.disasm(data, base):
    print('%08x: %-22s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print()
print('=== .plt / .plt.sec ===')
for n in ('.plt','.plt.sec'):
    s=elf.get_section_by_name(n)
    for ins in md.disasm(s.data(), s['sh_addr']):
        print('%08x: %-22s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print()
print('=== .init / .fini ===')
for n in ('.init','.fini'):
    s=elf.get_section_by_name(n)
    for ins in md.disasm(s.data(), s['sh_addr']):
        print('%08x: %-22s %s %s' % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print()
print('=== .rodata dump ===')
s=elf.get_section_by_name('.rodata'); d=s.data()
import re
for m in re.finditer(rb'[\x20-\x7e]{4,}', d):
    print(' %#x  %r' % (s['sh_addr']+m.start(), m.group()))
