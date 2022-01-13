```text
glootie has made an app which is super-safe! no one in the J19-Zeta-7 universe can crack the password!
```

[app-debug.apk](/csaw-finals-2021/app-debug.apk)


Hmm Android reversing; gonna use the lovely [jadx-gui](https://github.com/skylot/jadx)

![checkPassword is native fuck](/csaw-finals-2021/glootie_native_func.png)

Well ok I'll grab the native libs and reverse that. 

![shaders in assets](/csaw-finals-2021/glootie_assets_shaders.png)

Oops, fear. Well, let's look at the checkPassword function anyway. 

![](/csaw-finals-2021/glootie_checkPasswd_decomp.png)

So looks like we load the shader, send it the password, and then assert that the return value is [0, 1, 2, 3, 4,...]. Looks like we aren't getting out of reversing the shader. 

I found a tool called [spirv-cross](https://github.com/KhronosGroup/SPIRV-Cross) and used it to decompile the shaders. 

```text
❯ ~/tools/spirv-cross/bin/spirv-cross --version 310 --es assets/shaders/test.comp.spv
#version 310 es
layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;
const uint _39[34] = uint[](102u, 109u, 99u, 100u, 127u, 100u, 106u, 80u, 57u, 112u, 112u, 84u, 121u, 62u, 107u, 80u, 116u, 32u, 124u, 84u, 120u, 112u, 84u, 39u, 104u, 70u, 46u, 68u, 122u, 113u, 45u, 44u, 98u, 92u);
layout(binding = 0, std430) buffer MyBuffer
{
    uint array[];
} myBuffer;
struct Scalar
{
    uint x;
};
uniform Scalar scalar;
void main()
{
    uint i = gl_GlobalInvocationID.x;
    myBuffer.array[i] = _39[i] ^ myBuffer.array[i];
}
```

It'll XOR each byte of the input with a byte in an array. Since we know the expected output we can just solve for the flag!

flag: flag{alW1yz_u3e_d1nGleB0p_4_fl33B}