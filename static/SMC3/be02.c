#include <stdio.h>

// I wonder what this does...

int main() {
    unsigned char s[] = 
{

    0xf1, 0xe1, 0x97, 0xa7, 0x1, 0x5b, 0xa8, 0x5c, 
    0x16, 0x57, 0x9a, 0x9e, 0x90, 0x38, 0x79, 0x20, 
    0xa8, 0x8d, 0x3, 0x3e, 0xdc, 0x92, 0xa6, 0x4e
};

for (unsigned int m = 0; m < sizeof(s); ++m)
{
    unsigned char c = s[m];
    c = ~c;
    c ^= 0xd;
    c = -c;
    c -= 0x67;
    c = (c >> 0x3) | (c << 0x5);
    c ^= m;
    c -= m;
    c ^= m;
    c = ~c;
    c += m;
    c ^= m;
    c -= m;
    c = (c >> 0x1) | (c << 0x7);
    c += m;
    c = (c >> 0x7) | (c << 0x1);
    c ^= 0x6f;
    c -= 0xed;
    c = ~c;
    c -= 0x4a;
    c = -c;
    c -= 0xa8;
    c ^= 0xf7;
    c -= 0x67;
    c = ~c;
    c -= 0xc9;
    c = (c >> 0x1) | (c << 0x7);
    c ^= m;
    c = -c;
    c -= m;
    c ^= m;
    c = ~c;
    c = -c;
    c ^= m;
    c -= 0x88;
    c = ~c;
    c ^= 0x9b;
    c = ~c;
    c = -c;
    c ^= 0x90;
    c -= m;
    c = (c >> 0x1) | (c << 0x7);
    c ^= m;
    c -= 0xf9;
    c ^= m;
    c += 0xfd;
    c ^= m;
    c -= m;
    c = ~c;
    c += m;
    c = ~c;
    c += m;
    c ^= m;
    c += m;
    c ^= 0xaa;
    c += 0x18;
    c = -c;
    c ^= m;
    c = ~c;
    c += 0xd;
    c = -c;
    c -= m;
    c = -c;
    c -= m;
    c ^= m;
    c += 0x8f;
    c ^= 0x46;
    s[m] = c;
}

printf("%s\n", s);
}