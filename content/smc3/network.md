+++
title = "Network"
weight = 5
+++

## ne01

i used nmap to scan all the open ports.  I had to use the `-p` flag to enable scanning ports above 1000 because the service with the flag was on port 6166. 

`nmap ggcs-ne01.allyourbases.co -Pn -p- -T5`


flag: `hunTingPoRTS_7727`

## nm01

```python
from pwn import *

p = remote('ggcs-nm01.allyourbases.co', 6167)

def solve():
	eq = p.recvuntil("=")[:-1]
	print(eq)
	result = eval(eq)
	print(p.recvline())
	print(result)
	p.sendline(str(result))


solve()
solve()

p.interactive()
```
