+++
title = "Reversing"
weight = 1
+++

## Cracker Barrel
```
I found a USB drive under the checkers board at cracker barrel. My friends told me not to plug it in but surely nothing bad is on it?

I found this file, but I can't seem to unlock it's secrets. Can you help me out?

Also.. once you think you've got it I think you should try to connect to challenges.auctf.com at port 30000 not sure what that means, but it written on the flash drive..
```


```
...
│           0x0000137b      e8a0fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x00001380      488d85f0dfff.  lea rax, [var_2010h]
│           0x00001387      4889c7         mov rdi, rax
│           0x0000138a      e8dafeffff     call sym.remove_newline
│           0x0000138f      488b85e8dfff.  mov rax, qword [var_2018h]
│           0x00001396      4889c7         mov rdi, rax
│           0x00001399      e8c8000000     call sym.check_1
│           0x0000139e      85c0           test eax, eax
│       ┌─< 0x000013a0      0f84a5000000   je 0x144b
│       │   0x000013a6      488d3d7b0c00.  lea rdi, str.You_have_passed_the_first_test__Now_I_need_another_key ; 0x2028 ; "You have passed the first test! Now I need another key!" ; const char *s
│       │   0x000013ad      e82efdffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x000013b2      488b15672c00.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│       │                                                              ; [0x4020:8]=0 ; FILE *stream
│       │   0x000013b9      488b85e8dfff.  mov rax, qword [var_2018h]
│       │   0x000013c0      be00200000     mov esi, obj._IO_stdin_used ; 0x2000 ; int size
│       │   0x000013c5      4889c7         mov rdi, rax                ; char *s
│       │   0x000013c8      e853fdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│       │   0x000013cd      488b85e8dfff.  mov rax, qword [var_2018h]
│       │   0x000013d4      4889c7         mov rdi, rax
│       │   0x000013d7      e88dfeffff     call sym.remove_newline
│       │   0x000013dc      488b85e8dfff.  mov rax, qword [var_2018h]
│       │   0x000013e3      4889c7         mov rdi, rax
│       │   0x000013e6      e8e4000000     call sym.check_2
│       │   0x000013eb      85c0           test eax, eax
│      ┌──< 0x000013ed      745c           je 0x144b
│      ││   0x000013ef      488d3d6a0c00.  lea rdi, str.Nice_work__You_ve_passes_the_second_test__we_aren_t_done_yet ; 0x2060 ; "Nice work! You've passes the second test, we aren't done yet!" ; const char *s
│      ││   0x000013f6      e8e5fcffff     call sym.imp.puts           ; int puts(const char *s)
│      ││   0x000013fb      488b151e2c00.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│      ││                                                              ; [0x4020:8]=0 ; FILE *stream
│      ││   0x00001402      488b85e8dfff.  mov rax, qword [var_2018h]
│      ││   0x00001409      be00200000     mov esi, obj._IO_stdin_used ; 0x2000 ; int size
│      ││   0x0000140e      4889c7         mov rdi, rax                ; char *s
│      ││   0x00001411      e80afdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│      ││   0x00001416      488b85e8dfff.  mov rax, qword [var_2018h]
│      ││   0x0000141d      4889c7         mov rdi, rax
│      ││   0x00001420      e844feffff     call sym.remove_newline
│      ││   0x00001425      488b85e8dfff.  mov rax, qword [var_2018h]
│      ││   0x0000142c      4889c7         mov rdi, rax                ; char *arg1
│      ││   0x0000142f      e83c010000     call sym.check_3
│      ││   0x00001434      85c0           test eax, eax
│     ┌───< 0x00001436      7413           je 0x144b
│     │││   0x00001438      488d3d610c00.  lea rdi, str.Congrats_you_finished__Here_is_your_flag ; 0x20a0 ; "Congrats you finished! Here is your flag!" ; const char *s
│     │││   0x0000143f      e89cfcffff     call sym.imp.puts           ; int puts(const char *s)
...
```
As can be seen from this excerpt of the check function, the binary will ask for three strings and give us the flag if they are all correct.  

```
[0x00001180]> pdf@sym.check_1
            ; CALL XREF from sym.check @ 0x1399
┌ 105: sym.check_1 (char *arg1);
│           ; var char *s1 @ rbp-0x18
│           ; var char *s2 @ rbp-0x10
│           ; var char *var_8h @ rbp-0x8
│           ; arg char *arg1 @ rdi
│           0x00001466      f30f1efa       endbr64
│           0x0000146a      55             push rbp
│           0x0000146b      4889e5         mov rbp, rsp
│           0x0000146e      4883ec20       sub rsp, 0x20
│           0x00001472      48897de8       mov qword [s1], rdi         ; arg1
│           0x00001476      488d054d0c00.  lea rax, str.starwars       ; 0x20ca ; "starwars"
│           0x0000147d      488945f0       mov qword [s2], rax
│           0x00001481      488d054b0c00.  lea rax, str.startrek       ; 0x20d3 ; "startrek"
│           0x00001488      488945f8       mov qword [var_8h], rax
│           0x0000148c      488b55f0       mov rdx, qword [s2]
│           0x00001490      488b45e8       mov rax, qword [s1]
│           0x00001494      4889d6         mov rsi, rdx                ; const char *s2
│           0x00001497      4889c7         mov rdi, rax                ; const char *s1
│           0x0000149a      e891fcffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x0000149f      85c0           test eax, eax
│       ┌─< 0x000014a1      7525           jne 0x14c8
│       │   0x000014a3      488b55f8       mov rdx, qword [var_8h]
│       │   0x000014a7      488b45e8       mov rax, qword [s1]
│       │   0x000014ab      4889d6         mov rsi, rdx                ; const char *s2
│       │   0x000014ae      4889c7         mov rdi, rax                ; const char *s1
│       │   0x000014b1      e87afcffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│       │   0x000014b6      85c0           test eax, eax
│      ┌──< 0x000014b8      7507           jne 0x14c1
│      ││   0x000014ba      b800000000     mov eax, 0
│     ┌───< 0x000014bf      eb0c           jmp 0x14cd
│     │││   ; CODE XREF from sym.check_1 @ 0x14b8
│     │└──> 0x000014c1      b801000000     mov eax, 1
│     │┌──< 0x000014c6      eb05           jmp 0x14cd
│     │││   ; CODE XREF from sym.check_1 @ 0x14a1
│     ││└─> 0x000014c8      b800000000     mov eax, 0
│     ││    ; CODE XREFS from sym.check_1 @ 0x14bf, 0x14c6
│     └└──> 0x000014cd      c9             leave
└           0x000014ce      c3             ret
```

The function check_1 will jump to 0x14c8 (aka return false) if your input is not equal to the string "starwars" and then return true if your input is not equal to the string "startrek".  The input "starwars" passes both of these constraints and will pass the first checking function.  I didn't actually reverse check_2 and check_3 because I bumped my keyboard and noticed that an empty string would pass both of them.  

flag: auctf{w3lc0m3_to_R3_1021}

## mobile0

`Hey, look its an android file. Can you find the flag?`

We are provided with an android apk file `mobile0.apk` and told to find the flag.  The flag can be found with `strings mobile0.apk | grep auctf`.  

flag: auctf{m0b1le_r3v3rs1ng!!}

## mobile1

`My friend sent this file to me and said that there was a flag in it. Can you help me?`

We are provided with an ipa file - which is an iOS app store package.  These are compressed, rather like java jars, so you need to unzip it first.  I was pretty invested in not actually reversing the code for this so I ran strings on a few files inside and found the flag in the root info.plist file.  

flag: auctf{i0s_r3v3rs1ng_1s_1nt3r3st1ng}

## sora

```
This obnoxious kid with spiky hair keeps telling me his key can open all doors.

Can you generate a key to open this program before he does?

Connect to challenges.auctf.com 30004
```

I opened up the binary with radare2 to determine the key length and target location and then solved it with angr.  We can see from this excerpt of the main function that it reads in 0x1e bytes from stdin and the program calls print_flag at 0x12aa

```
...
│           0x0000126d      488945c8       mov qword [var_38h], rax
│           0x00001271      488d3da10d00.  lea rdi, str.Give_me_a_key  ; 0x2019 ; "Give me a key!" ; const char *s
│           0x00001278      e843feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000127d      488b15ac2d00.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x4030:8]=0 ; FILE *stream
│           0x00001284      488d45d0       lea rax, [s]
│           0x00001288      be1e000000     mov esi, 0x1e               ; int size
│           0x0000128d      4889c7         mov rdi, rax                ; char *s
│           0x00001290      e86bfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x00001295      488b45c8       mov rax, qword [var_38h]
│           0x00001299      4889c7         mov rdi, rax
│           0x0000129c      e83c000000     call sym.encrypt
│           0x000012a1      85c0           test eax, eax
│       ┌─< 0x000012a3      7411           je 0x12b6
│       │   0x000012a5      b800000000     mov eax, 0
│       │   0x000012aa      e8d9000000     call sym.print_flag
│       │   0x000012af      b800000000     mov eax, 0
│      ┌──< 0x000012b4      eb11           jmp 0x12c7
│      ││   ; CODE XREF from main @ 0x12a3
│      │└─> 0x000012b6      488d3d6b0d00.  lea rdi, str.That_s_not_it  ; 0x2028 ; "That's not it!" ; const char *s
│      │    0x000012bd      e8fefdffff     call sym.imp.puts           ; int puts(const char *s)
...
```

```python
import angr
import sys
from claripy import *
from pwn import *

def main(argv):

    path_to_binary = "sora"
    project = angr.Project(path_to_binary, load_options={'main_opts': {'base_addr': 0x0}})

    x = BVS('x', 0x1e * 8)


    initial_state = project.factory.entry_state(stdin=x)

    # constrain to printable characters
    def char(state, byte):
        return initial_state.solver.And(byte <= '~', byte >= ' ')

    for c in x.chop(8):
        initial_state.solver.add(char(initial_state, c))

    simulation = project.factory.simgr(initial_state)


    simulation.explore(find=0x000012aa)
    if simulation.found:
        solution_state = simulation.found[0]
        r = remote('challenges.auctf.com',30004)
        r.sendline(solution_state.solver.eval(x, cast_to=bytes))
        print(r.recvall())
    else:
        print(simulation.stashes)
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
```

flag: auctf{that_w@s_2_ezy_29302}

## dont_break_me

```python
from pwn import *

key = "MDULCTKBSJARIZQHYPGXOFWNEV"

comp = "SASRRWSXBIEBCMPX"
password = ""

for i in range(16):
    password += chr(0x41 + key.find(comp[i]))
r = remote('challenges.auctf.com',30005)
r.sendline(password)
print(r.recvall())
```

this challenge encrypts your input and then compares it against a constant, failing if it detects any CC bytes. The encryption function is a simple polyalphabetic cipher that can be leaked with ltrace.  


flag: auctf{static_or_dyn@mIc?_12923}
