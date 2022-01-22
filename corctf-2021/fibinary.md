```text
Warmup your crypto skills with the superior number system!
```

We're provided two files -- an encryption script in python and an encrypted flag. 

# enc.py
```python
fib = [1, 1]
for i in range(2, 11):
    fib.append(fib[i - 1] + fib[i - 2])
def c2f(c):
    n = ord(c)
    b = ''
    for i in range(10, -1, -1):
        if n >= fib[i]:
            n -= fib[i]
            b += '1'
        else:
            b += '0'
    return b
flag = open('flag.txt', 'r').read()
enc = ''
for c in flag:
    enc += c2f(c) + ' '
with open('flag.enc', 'w') as f:
    f.write(enc.strip())
```
# flag.enc
```text
10000100100 10010000010 10010001010 10000100100 10010010010 10001000000 10100000000 10000100010 00101010000 10010010000 00101001010 10000101000 10000010010 00101010000 10010000000 10000101000 10000010010 10001000000 00101000100 10000100010 10010000100 00010101010 00101000100 00101000100 00101001010 10000101000 10100000100 00000100100
```

Each character is "encrypted" individually which means it's looking awfully tractable. We can engage in a little wholesome brute force to crack each character individually. 

```python
from z3 import *
from string import printable
fib = [1, 1]
for i in range(2, 11):
    fib.append(fib[i - 1] + fib[i - 2])
def brute(target):
    def c2f(c):
        n = ord(c)
        b = ''
        for i in range(10, -1, -1):
            if n >= fib[i]:
                n -= fib[i]
                b += '1'
            else:
                b += '0'
        return b
    for x in printable:
        if c2f(x) == target:
            return x
flag = open('flag.enc', 'r').read().split(" ")
for i in flag:
    char = brute(i)
    print(char,end="")
```
The flag is corctf{b4s3d_4nd_f1bp!113d}