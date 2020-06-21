from pwn import *

p = remote('ggcs-nm01.allyourbases.co', 6167)

def solve():
	eq = p.recvuntil("=")[:-1]
	print(eq)
	result = eval(eq)
	print(p.recvline())
	print(result)
	p.sendline(str(result))


solve()
solve()

p.interactive()