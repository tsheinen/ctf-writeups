+++
title = "Root Power"
weight = 1
+++

# Root Power

[source](https://github.com/tamucybersec/gctf-2020/tree/master/reversing/root-power)

[Attachment](https://storage.googleapis.com/gctf-2020-attachments-project/4905c5f476c7e7eac34bd15fbd2e61a6d6c724c8431056f57a61fb0a0a35bf4bbdcae058d9c3fc528ce306e97a42924878c36c4bc2c145548553744e630c6073)

Root is an incredibly powerful account to access. Especially in this National Grid VM.

## Initial review
[Addison], [theinen], [komputerwiz], [Arjun]

The attachment provided in the CTF provides us with a "vm.tar.xz". Extracting reveals a disk image (disk.img) and a
script which launches a QEMU VM using the disk image (run.sh).

Let's take a look around that disk image.

### Mounting the image
[theinen]

With a disk image provided to us and a task to log in as root, the obvious thing is to just mount the disk and look for
interesting stuff.  If we can't log in as root we can still look for interesting files.  

```text
❯ fdisk -l disk.img
Disk disk.img: 1.5 GiB, 1610612736 bytes, 3145728 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x415c2e94

Device     Boot Start     End Sectors  Size Id Type
disk.img1  *     2048 3145727 3143680  1.5G 83 Linux
```

The bootable partition starts at 2048 with block sizes of 512 so to mount it we need to start at 1048576.  

`❯ sudo mount -o loop,offset=1048576 disk.img disk` will mount the partition at the "disk" folder in the same directory.  

### chroot, systemd-nspawn-ing,  QEMU + autologin
[Addison]

Google provides us with a script to launch it with QEMU, but it needs a password we don't have! We recognised that we
would need a root shell on the device, so to do so, we employed multiple tools.

[chroot], the obvious first choice, allows us to simply log into the target's mounted folder with just `chroot vm`.
Unfortunately, this doesn't give us [systemd] or other boot-based services, so it just won't do.

The next step was using [systemd-nspawn] to start the program at the systemd level. The following commands were used (in
different shells):

```bash
$ sudo systemd-nspawn --private-network -x --image disk.img -M root-power /lib/systemd/systemd
$ sudo machinectl shell root@root-power
```

This gave us a root shell with root privileges, but ultimately we still didn't find that anything significant changed.

Finally, to get root on the device in QEMU, we modified the systemd units using the [standard override for getty][getty
override]. This was the access level we used for the rest of the challenge and ended up with how we did all of our
live investigation from here.

### Hiding in the /etc/shadow?

[komputerwiz]

The first place anyone should think to go to get root access is the "shadow file" in `/etc/shadow`. This file contains
the hashed password of all users in a linux system. In this case, we can get the hashed root password:

```console
[root@gctf-root-power ~]# head -1 /etc/shadow
root:$1$OesMIrMe$m3dh/8JZc6k/fz9SW2PrI.:18445::::::
```

Here is a dissection of that hash:

* `$1` - MD5 algorithm (this should be easy to crack!)
* `$OesMIrMe` - Salt
* `$m3dh/8JZc6k/fz9SW2PRI.` - Hash

If we put the hash line into `hash.txt`, [hashcat] makes quick work of this password against the [rockyou] password
list:

```console
sky@$ hashcat -a0 -m 500 hash.txt ~/Downloads/rockyou.txt -O 

sky@$ hashcat -a0 -m 500 hash.txt ~/Downloads/rockyou.txt -O --show
$1$OesMIrMe$m3dh/8JZc6k/fz9SW2PrI.:no
```

Turns out the hashed password is simply `no`. A feeling this seemed a bit too easy is quickly justified:

```
NATIONAL POWER GRID CONTROL SERVER. ALL ACCOUNTS EXCEPT ROOT DISABLED. ADMINISTRATORS ONLY.
gctf-root-power login: root
Password: ("no")
NATIONAL POWER GRID CONTROL SERVER. ALL ACCOUNTS EXCEPT ROOT DISABLED. ADMINISTRATORS ONLY.
gctf-root-power login:
```

So there is something more than just a password at play here...

### Pacman tells all
[komputerwiz]

Once we have a login on the system, we can use the following script to query Arch's `pacman` package manager database
for any files that are not owned by any packages:

```bash
#!/bin/sh

tmp=${TMPDIR-/tmp}/pacman-disowned-$UID-$$
db=$tmp/db
fs=$tmp/fs

mkdir "$tmp"
trap  'rm -rf "$tmp"' EXIT

pacman -Qlq | sort -u > "$db"

find /bin /etc /lib /sbin /usr \
    ! -name lost+found \
    \( -type d -printf '%p/\n' -o -print \) | sort > "$fs"

comm -23 "$fs" "$db"|less
```

(Credit to [graysky](https://bbs.archlinux.org/viewtopic.php?pid=1102910#p1102910) on the Arch Forums)

This effectively "diffs" the filesystem against what would otherwise be a vanilla Arch installation. This yielded many
auto-generated / user-specified configuration files, SSL certificates, and some particularly interesting files in
`/usr/` toward the end:

```console
[root@gctf-root-power ~]# ./find-extra-files.sh
/etc/.pwd.lock
/etc/.updated
/etc/adjtime
/etc/ca-certificates/extracted/ca-bundle.trust.crt
/etc/ca-certificates/extracted/cadir/
/etc/ca-certificates/extracted/cadir/00673b5b.0
...
/etc/systemd/user/sockets.target.wants/dirmngr.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
/etc/systemd/user/sockets.target.wants/p11-kit-server.socket
/usr/lib/modules/5.6.14-arch1-1/kernel/drivers/char/chck.ko
/usr/lib/modules/5.6.14-arch1-1/kernel/drivers/hello.ko
/usr/lib/security/pam_chck.so
/usr/lib/udev/hwdb.bin
[root@gctf-root-power ~]#
```

The `pam_check.so` module was indeed being used in `/etc/pam.d/system-auth`, which is probably why our attempt to log in
with the root password earlier would not work. Let's see what is inside the PAM module and those kernel modules.

## Ghidra review of kernel and PAM modules
[Addison], [theinen], [Arjun]

### [hello.ko](https://github.com/tamucybersec/gctf-2020/blob/master/reversing/root-power/files/hello.ko)
[theinen]

![init function, prints out Hello World to kernel log](images/hello_ko_hello_init.png)
![init function, prints out Goodbye World to kernel log](images/hello_ko_hello_exit.png)
![strings in memory, shows Hello World! and Goodbye World!](images/hello_ko_strings.png)

This was a fairly trivial kernel module. It printed "Hello World" and "Goodbye World" to the kernel log. To the best of
my knowledge it had nothing to do with the actual challenge but it was an extra file on the disk so we analyzed it.  

### [chck.ko](https://github.com/tamucybersec/gctf-2020/blob/master/reversing/root-power/files/chck.ko)
[Addison], [theinen], [Arjun]

We run strings on the kernel module, and find that the author is someone working at Google. There is also a mention of
acpi in the alias:

```bash
arjun@broly:~/Playground/google_ctf/reversing/root_power/vm$ strings chck.ko
Linux
eH3<%(
]A\A]
CHCK0001
chck
author=Connor Wood <venos@google.com>
license=GPL
srcversion=B36F4E186ADBA29CCB7A579
alias=acpi*:CHCK0001:*
depends=
retpoline=Y
name=chck
...
```

We look at the kernel modules in ghidra, and we see that the read function calls a function `acpi_evaluate_integer`.
This function is external and invokes relies on uninitialised data which is likely to be defined in initramfs:

![chck_read](images/chck_read.png)

### [pam_chck.so](https://github.com/tamucybersec/gctf-2020/blob/master/reversing/root-power/files/pam_chck.so)
[theinen]

![pam_chck.so functions](images/pam_chck_so_functions.png)

pam_chck.so has four functions, three of which are implementations of a pam interface.
[pam_setcred](https://linux.die.net/man/3/pam_setcred),
[pam_authenticate](https://linux.die.net/man/3/pam_authenticate), and
[pam_acct_mgmt](https://linux.die.net/man/3/pam_acct_mgmt).  We know that the login prompt is seemingly ignoring the
root password so pam_authenticate (which controls the login flow) seems like it'll be relevant.

![pam_chck.so authenticate](images/pam_chck_so_authenticate.png)

This explains the strange behavior we had noticed earlier with the login prompt. Any account which was not root would
fail immediately by querying username again and root would fail with the correct password. It's worth noting that it
doesn't read input for the password at all. The check_device function determines if we log in successfully or so, so the
next place to look is that function.

![pam_chck.so check_device](images/pam_chck_so_check_device.png)

check_device reads two bytes from `/dev/chck`, converts them into an integer using atoi, and returns it. Looking back at
pam_sm_authenticate, if `/dev/chck` returns a 1 then the login will succeed, otherwise it will fail.  

## initramfs exploration
[Addison], [komputerwiz]

By this point, we had worked out that it was necessary to view the initramfs in order to access the data present in the
kernel module (specifically, `chck_handle` and the call to `acpi_evaluate_integer`). So, we extracted the initramfs.

### Unpacking and peeking
[Addison]

```bash
$ cp vm/boot/initramfs-linux.img .
$ cpio -iv < initramfs-linux.img 
kernel
kernel/firmware
kernel/firmware/acpi
kernel/firmware/acpi/ssdt.aml
3 blocks
$ cd kernel/firmware/acpi/
$ file ssdt.aml
ssdt.aml: data
```

Hmm, that's unhelpful. A little google-fu shows us that this is an ACPI [Secondary System Description Table][SSDT],
which is used for further providing functionality to devices with [ACPI Machine Language][AML]. On the AML page, it
specifically mentions:

>The Intel ASL assembler (iasl) is freely available on many Linux distributions and can convert in **either direction**
>between these formats.

I run a variant of Ubuntu, so installing that was as easy as `sudo apt install acpica-tools`.

```bash
$ iasl -d ssdt.aml

Intel ACPI Component Architecture
ASL+ Optimizing Compiler/Disassembler version 20190509
Copyright (c) 2000 - 2019 Intel Corporation

File appears to be binary: found 167 non-ASCII characters, disassembling
Binary file appears to be a valid ACPI table, disassembling
Input file ssdt.aml, Length 0x1FD (509) bytes
ACPI: SSDT 0x0000000000000000 0001FD (v02                 00000000 INTL 20190509)
Pass 1 parse of [SSDT]
Pass 2 parse of [SSDT]
Parsing Deferred Opcodes (Methods/Buffers/Packages/Regions)

Parsing completed
Disassembly completed
ASL Output:    ssdt.dsl - 4182 bytes
```

Huzzah! Now we can mess around with the .dsl file, the full content of which is available
[here](files/kernel/firmware/acpi).

### ACPI fun
[Addison]

Upon inspecting the DSL file, we find the method used in [chck.ko](#chckko) via `acpi_evaluate_integer`. It's quite
long, so I've redacted everything except the most important bit.

```
Method (CHCK, 0, NotSerialized)
{
    ...
    KBDB [Local1] = Local0
    Local1 += One
    While ((Local0 != 0x9C))
    {
        WDTA ()
        Local0 = DTAR /* \CHCK.DTAR */
        If ((Local0 == 0x36))
        {
            Local0 = 0x2A
        }

        If ((Local0 == 0xB6))
        {
            Local0 = 0xAA
        }

        If ((Local1 < 0x3E))
        {
            KBDB [Local1] = Local0
            Local1 += One
        }
    }
    EINT ()
    If ((KBDA == KBDB))
    {
        Return (One)
    }
    ...
}
```

KBDA and KBDB are buffers defined above:

```
Name (KBDA, Buffer (0x3E)
{
    /* 0000 */  0x2A, 0x2E, 0xAE, 0x14, 0x94, 0x21, 0xA1, 0x1A,  // *....!..
    /* 0008 */  0x9A, 0xAA, 0x1E, 0x9E, 0x2E, 0xAE, 0x19, 0x99,  // ........
    /* 0010 */  0x17, 0x97, 0x2A, 0x0C, 0x8C, 0xAA, 0x32, 0xB2,  // ..*...2.
    /* 0018 */  0x1E, 0x9E, 0x2E, 0xAE, 0x23, 0xA3, 0x17, 0x97,  // ....#...
    /* 0020 */  0x31, 0xB1, 0x12, 0x92, 0x2A, 0x0C, 0x8C, 0xAA,  // 1...*...
    /* 0028 */  0x26, 0xA6, 0x1E, 0x9E, 0x31, 0xB1, 0x22, 0xA2,  // &...1.".
    /* 0030 */  0x16, 0x96, 0x1E, 0x9E, 0x22, 0xA2, 0x12, 0x92,  // ...."...
    /* 0038 */  0x2A, 0x1B, 0x9B, 0xAA, 0x1C, 0x9C               // *.....
})
Name (KBDB, Buffer (0x3E){})
```

It was at this point that two things happen:
- [theinen] worked out that, when reading the device, it would only return values after hitting enter.
- [komputerwiz] worked out that these are virtual keyboard events values.

So now, we just need to decode the keyboard events into ASCII.

## Keyboard decoding
[Addison], [theinen], [komputerwiz], [Arjun]

When pressing -- or _releasing_ -- a key on a keyboard (or pressing a button on the mouse), the kernel receives these
events in the form of "key codes." The [keybd\_event repo] by [@micmonay] contains a
[mapping](https://github.com/micmonay/keybd_event/blob/master/keybd_linux.go) that gives more meaningful names to the
key codes. Decoding the key codes above gives the following sequence of keys:

```
VK_SHIFT
VK_C
VK_EXIT
VK_T
VK_PROG1
VK_F
VK_EJECTCD
VK_LEFTBRACE
VK_CYCLEWINDOWS
VK_ISO
VK_A
VK_BACK
VK_C
VK_EXIT
VK_P
NOT_FOUND
VK_I
VK_MSDOS
VK_SHIFT
VK_MINUS
VK_CALC
VK_ISO
VK_M
VK_SCROLLDOWN
VK_A
VK_BACK
VK_C
VK_EXIT
VK_H
VK_NEXTSONG
VK_I
VK_MSDOS
VK_N
VK_SCROLLUP
VK_E
VK_DELETEFILE
VK_SHIFT
VK_MINUS
VK_CALC
VK_ISO
VK_L
VK_STOPCD
VK_A
VK_BACK
VK_N
VK_SCROLLUP
VK_G
VK_EJECTCLOSECD
VK_U
VK_WWW
VK_A
VK_BACK
VK_G
VK_EJECTCLOSECD
VK_E
VK_DELETEFILE
VK_SHIFT
VK_RIGHTBRACE
VK_MAIL
VK_ISO
VK_ENTER
VK_BOOKMARKS
```

Wow, there is a lot of extra "junk" buttons being pressed. We can ignore the `MSDOS`, `CALC`, `NEXTSONG`, `EJECTCD`,
etc. events. One pattern of note is the `SHIFT` event when the shift key is pressed down, and the corresponding `ISO`
event when it is released. This means that the initial `C`, `T`, and `F` are capitalized, `LEFTBRACE` and `RIGHTBRACE`
are actually curly braces ("{}"), and `MINUS` is actually an underscore ("\_"). Putting all of this together yields the
flag:

`CTF{acpi_machine_language}`

[Addison]: https://github.com/VTCAKAVSMoACE
[theinen]: https://github.com/tcheinen
[komputerwiz]: https://github.com/komputerwiz
[Arjun]: https://github.com/alalith
[chroot]: https://wiki.archlinux.org/index.php/Chroot
[getty override]: https://wiki.archlinux.org/index.php/Getty#Automatic_login_to_virtual_console
[systemd]: https://wiki.archlinux.org/index.php/Systemd
[systemd-nspawn]: https://wiki.archlinux.org/index.php/Systemd-nspawn
[hashcat]: https://hashcat.net/hashcat/
[rockyou]: https://wiki.skullsecurity.org/Passwords
[SSDT]: https://wiki.osdev.org/SSDT
[AML]: https://wiki.osdev.org/AML
[keybd\_event repo]: https://github.com/micmonay/keybd_event/blob/master/keybd_linux.go
[@micmonay]: https://github.com/micmonay
