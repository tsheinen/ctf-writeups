```text
In some alternate reality, computers are not electronics-based but instead use air pressure. No electrons are zipping by and instead, a large pneumatic circuit takes care of all the math. In that world, we reverse engineers are not staring countless hours into debuggers and disassemblers but are inspecting the circuits on a valve level, trying to figure out how the particles will behave in weird components and how they are connected. Thinking about it, that doesn't sound too different, does it? 
```
[pneumaticvalidator](/htb-uni-quals-2021/pneumaticvalidator)

# reversing

```c
undefined8 main(int argc,char **argv)
{
  undefined8 uVar1;
  size_t sVar2;
  float fVar3;
  int local_10;
  
  puts("Starting the Pneumatic Flag Validation Machine...");
  if (argc == 2) {
    sVar2 = strlen(argv[1]);
    if (sVar2 == 0x14) {
      FUN_00105498(argv[1],0x14);
      puts("Initializing Simulation...");
      init_heap();
      FUN_001012bf();
      FUN_0010149a();
      puts("Simulating...");
      for (local_10 = 0; local_10 < 0x400; local_10 = local_10 + 1) {
        simulate();
      }
      fVar3 = find_max();
      if (15.0 <= fVar3) {
        puts("Wrong \\o\\");
      }
      else {
        puts("Correct /o/");
      }
      FUN_0010125a();
      uVar1 = 0;
    }
    else {
      puts("Wrong length");
      uVar1 = 1;
    }
  }
  else {
    puts("Please provide the flag to verify");
    uVar1 = 1;
  }
  return uVar1;
}
```

It takes a flag provided in argv[1] and asserts the length is 20. It'll run a few setup functions to populate global variables and then run a simulator function 0x400 times. This is honestly pretty big and gross and I didn't want to reverse it so I decided to poke around with GDB. 

![=](/htb-uni-quals-2021/pneumatic_validator_dynamic.png)


Ah, yes, I can actually just do that lmao. ✨ dynamic analysis ✨. 

# solve

```python
from subprocess import run, PIPE
from string import ascii_letters, digits, punctuation
from pwn import *
def check_pw(pw):
    proc = run(f'gdb ./pneumaticvalidator --nx --ex "b *0x0000555555554000+0x5640" --ex "r {pw}" --ex \'x/f $rbp-4\' --batch', stdout=PIPE,shell=True)
    lines = proc.stdout.decode().split("\n")
    return float(lines[-2].split(":\t")[1])
# known = ""
known = "HTB{PN7Um4t1C_l0g1C}"
# initial pass; not fully accurate but it's enough to get the gist and we can try individual characters again later
while len(known) < 20:
    log.info(f"trying with known \"{known}\"")
    pressures = {}
    for i in ascii_letters + digits + "_{}":
        pw = (known + i).ljust(20,"A")
        pressures[i] = check_pw(pw)
    next = min(pressures.items(), key=lambda x: x[1])
    log.info(f"guessing next letter to be \"{next[0]}\" with pressure of {next[1]}")
    known += next[0]
def vary_index(idx, pw):
    pressures = {}
    log.info(f"varying idx = {idx}, char = {known[idx]}")
    for i in ascii_letters + digits:
        pw[idx] = i
        pressure = check_pw("".join(pw))
        pressures[i] = pressure
    print(sorted(pressures.items(), key=lambda x: x[1]))
    return min(pressures.items(), key=lambda x: x[1])
pw = list(known)
for i in range(4,20): # we know HTB{ is correct
    old_pw = [x for x in pw]
    pw[i] = vary_index(i, pw)[0]
    if pw != old_pw:
        log.info(f"found better flag \"{''.join(pw)}\" -> \"{''.join(old_pw)}\"")
```


lmao i don't deserve this HTB{pN3Um4t1C_l0g1C}