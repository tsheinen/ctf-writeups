from pwn import *

key = "MDULCTKBSJARIZQHYPGXOFWNEV"

comp = "SASRRWSXBIEBCMPX"
password = ""

for i in range(16):
    password += chr(0x41 + key.find(comp[i]))
r = remote('challenges.auctf.com',30005)
r.sendline(password)
print(r.recvall())