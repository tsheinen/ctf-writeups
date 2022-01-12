# vault

```text
After following a series of tips, you have arrived at your destination; a giant vault door. Water drips and steam hisses from the locking mechanism, as you examine the small display - "PLEASE SUPPLY PASSWORD". Below, a typewriter for you to input. You must study the mechanism hard - you might only have one shot...
```
[vault](/ctf/htb-uni-quals-2021/vault)

## reversing

The first place to go is the main funtion! The binary is stripped but binary ninja is kinda enough to detect and rename it automatically, so all that is left is analyzing the function. 

![main function; reads a string from "flag.txt" and checks each char against another char derived from some gross vtable](/ctf/htb-uni-quals-2021/vault_main.png)

It's fairly straightforward for a stripped c++ binary. At the top it opens up an ifstream for flag.txt and then it reads it byte by byte. Each byte is compared against the output of some gross function pointer return and if any of those comparisons are wrong it will print "Incorrect credentials". 

All of the functions are just there in the binary if you wanted to reverse it manually but I do not. The thing is that every byte of the flag is in memory at some point so all you need to is feed it some placeholder flag and then extract each comparison byte. 

## solve

I solved it using Qiling. I provided it a fake file and hooked the comparison instruction to log the register the byte of the flag was stored in -- ecx. 

```python
from qiling import *
from qiling.os.mapper import QlFsMappedObject
class fake_flag(QlFsMappedObject):
    def read(self, size):
        return b"A" * 20
    def fstat(self): # syscall fstat will ignore it if return -1
        return -1
    def close(self):
        return 0
compared = ""
def log_ecx(ql):
    global compared
    compared += chr(ql.reg.ecx)
ql = Qiling(["./vault"], rootfs="/home/sky/tools/qiling/examples/rootfs/x8664_linux", console=False)
ql.add_fs_mapper('flag.txt', fake_flag())
ql.hook_address(log_ecx, 0x555555554000 + 0xc3a1) # rebase!
ql.run()
print(f"found flag = \"{compared}\"")
```

```text
❯ python3 ./solve.py
Incorrect Credentials - Anti Intruder Sequence Activated...
found flag = "HTB{vt4bl3s_4r3_c00l_huh}"
```