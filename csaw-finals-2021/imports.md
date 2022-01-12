# imports

```text
Find the only Win API function called by the shellcode.
```

```text
e839000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000019622f7defaaed2b15a8be281ec0001000081e400ffffff648b0d3000000085c90f84c4010000807902000f85210000008b490c85c90f84af0100008b591485db0f84a401000083c1143bcb0f8499010000ff7328e8a500000083c40452e85100000083c4043b42310f840f0000008b1b3bcb0f8472010000e9d4ffffff8b5b100fb64a308bfa83c73103f903f903f903f98b375653e88e00000083c40889074983f9000f85dbffffffe82b010000e937010000558bec608b4d0833d233c00fbe3185f60f841b00000003f28bfec1e705c1e70503fe8bd7c1ea05d1ea33d741e9daffffff8d04d28bc8c1e90b33c88bc1c1e00f03c18944241c618be55dc3558bec608b750833c9668b066685c00f840d0000000c20880283c60242e9e7ffffffc60200618be55dc3558bec6083ec188b7d0885ff0f84910000008b550c8b4f3c8b44397885c00f847f000000837c397c000f84740000008d0c38890c248b4c381c03cf894c24048b4c382003cf894c24088b4c382403cf894c240c8b0424837818000f844300000033db8b4424088b0c98803c39000f842a0000008d043950e80fffffff83c4043bc20f85160000008b44240c0fb70c588b4424048b048803c7e90800000043e9bfffffff33c083c4188944241c618be55dc3558bec6052ff52358944241c618be55dc39090909090909090
```

God, fuck, windows :(

I wasn't gonna do this but then I found a lovely paragraph on the [Qiling](https://docs.qiling.io/en/latest/) documentation. 

```text
Not only working cross-architecture, Qiling is also cross-platform, so for example you can run Linux ELF file on top of Windows. In contrast, Qemu usermode only run binary of the same OS, such as Linux ELF on Linux, due to the way it forwards syscall from emulated code to native OS
```

Fuck yeah I'm never gonna use windows again. 


```python
import sys
from qiling import *
from unicorn import *
from unicorn.x86_const import *
from qiling.os.posix.stat import Fstat
import capstone.x86_const
from binascii import hexlify
def code_hook(ql, address, size):
    global dump
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        if i.mnemonic == "call" and i.op_str != "0x400e9" :
        	print("[*] 0x{:08x}: {} {}".format(i.address, i.mnemonic, i.op_str))
        if address ==0x0004004d:
        	ql.reg.esp = 0xfffe0000
code = bytes.fromhex("e839000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000019622f7defaaed2b15a8be281ec0001000081e400ffffff648b0d3000000085c90f84c4010000807902000f85210000008b490c85c90f84af0100008b591485db0f84a401000083c1143bcb0f8499010000ff7328e8a500000083c40452e85100000083c4043b42310f840f0000008b1b3bcb0f8472010000e9d4ffffff8b5b100fb64a308bfa83c73103f903f903f903f98b375653e88e00000083c40889074983f9000f85dbffffffe82b010000e937010000558bec608b4d0833d233c00fbe3185f60f841b00000003f28bfec1e705c1e70503fe8bd7c1ea05d1ea33d741e9daffffff8d04d28bc8c1e90b33c88bc1c1e00f03c18944241c618be55dc3558bec608b750833c9668b066685c00f840d0000000c20880283c60242e9e7ffffffc60200618be55dc3558bec6083ec188b7d0885ff0f84910000008b550c8b4f3c8b44397885c00f847f000000837c397c000f84740000008d0c38890c248b4c381c03cf894c24048b4c382003cf894c24088b4c382403cf894c240c8b0424837818000f844300000033db8b4424088b0c98803c39000f842a0000008d043950e80fffffff83c4043bc20f85160000008b44240c0fb70c588b4424048b048803c7e90800000043e9bfffffff33c083c4188944241c618be55dc3558bec6052ff52358944241c618be55dc39090909090909090")
ql = Qiling(shellcoder=code, ostype="windows", rootfs="/home/sky/tools/qiling/examples/rootfs/x86_windows", archtype="x86")
ql.hook_code(code_hook)
md = ql.create_disassembler()
md.detail = True
ql.run()
```

```text
❯ python solve.py
[=]	Initiate stack address at 0xfffdd000 
[=]	TEB addr is 0x6000
[=]	PEB addr is 0x6044
[=]	Loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/ntdll.dll ...
[!]	Warnings while loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/ntdll.dll:
[!]	- SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run under Windows 8.
[!]	- AddressOfEntryPoint lies outside the sections' boundaries. AddressOfEntryPoint: 0x0
[=]	Done with loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/ntdll.dll
[=]	Loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/kernel32.dll ...
[=]	Done with loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/kernel32.dll
[=]	Loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/user32.dll ...
[=]	Done with loading /home/sky/tools/qiling/examples/rootfs/x86_windows/Windows/System32/user32.dll
56
[*] 0x00040000: call 0x4003e
[*] 0x0004008a: call 0x40134
[*] 0x0004008a: call 0x40134
[*] 0x0004008a: call 0x40134
[*] 0x000400cb: call 0x4015e
[*] 0x000400df: call 0x4020f
[*] 0x00040214: call dword ptr [edx + 0x35]
[!]	api GetKeyboardLayoutNameA is not implemented
[*] 0x69e88825: call dword ptr [0x69ea37b4]
```

Haha sweet I didn't need to do anything because Qiling kindly told me that they didn't implement the function which got called. I was confused for a little bit but then we got an announcement clarifying the flag format; take the function and wrap it in flag{}

flag: flag{GetKeyboardLayoutNameA}