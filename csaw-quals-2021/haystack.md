```text
Help! I've lost my favorite needle!
nc pwn.chal.csaw.io 5002
```
[haySTACK](/csaw-quals-2021/bins/haySTACK)

![](/csaw-quals-2021/haystack_function.png)

🧐

The only vulnerability I caught was an underflow in the haystack check -- it checked the upper bound but not the lower bound so we could guess any location on the stack. It also displays 4 bytes at the guessed location. I guessed with a negative number to leak the randomly generated location for the needle and then guessed that location. 

![](/csaw-quals-2021/haystack_flag.png)