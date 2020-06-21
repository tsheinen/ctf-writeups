import itertools
import string
from multiprocessing import Pool
from pwn import *
import tqdm

def check(i):
    p = remote('ggcs-bx01.allyourbases.co', 9171)
    p.recvuntil("> ")
    p.sendline(''.join(i))
    res = p.recvline()
    if b'Invalid' not in res:
        print("with: ", i)
        print("result: ", res)


tasks = list(itertools.combinations(string.printable,2))

pool = Pool(processes=8)
for _ in tqdm.tqdm(pool.imap_unordered(check, tasks), total=len(tasks)):
    pass
