---
title: "TCP1P Playground 2024"
date: "2025-02-19"
description: "Reverse Engineering, Web Exploitation, Forensic, Blockchain Walktrough"
categories: [
    "Write-up"
]
tags : [
    "National",
    "Individual"
]
---
## TCP1P
TCP1P is an Indonesian CTF team actively engaging in competitive cybersecurity events on ctftime.

![](ra.png)

This event CTF has very long time (1 Year(its not even finish yet)), so i kinda confused to write the right year on the title (lol), so this CTF has so many categories, and my overall solved is on Forensic, Web Exploitation, Binary Exploitation, Reverse Engineering, and Blockchain.

So maybe i'll post 1 category/day or smth, depends on my mood
## Reverse Engineering
### Micro Rev
###### Author: Dimas Maulana
###### Desc: First C reverse engineering challenge :P
As same as the title, is Micro means its easy (i think).
So we got a file of exe, and enc.txt
this Main function contains:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *ptr; // [rsp+20h] [rbp-10h]
  FILE *stream; // [rsp+28h] [rbp-8h]

  if ( argc > 1 )
  {
    ptr = (char *)xorMessage(argv[1], &unk_203D);
    stream = fopen("enc.txt", "w");
    if ( stream )
    {
      fprintf(stream, "%s\n", ptr);
      fclose(stream);
      free(ptr);
      puts("Encrypted message saved to enc.txt");
      return 0;
    }
    else
    {
      perror("Failed to open file for writing");
      free(ptr);
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "Usage: %s <secret message>\n", *argv);
    return 1;
  }
}
```
if u can read those main function correctly, u will know that the enc.txt is got XOR'ed by key (ofc), and the key is in ``&unk_203D``
```c
.rodata:000000000000203D 22 unk_203D db  22h ; "                    ; DATA XREF: main+54↑o
.rodata:000000000000203E 11  db  11h
.rodata:000000000000203F 75  db  75h ; u
.rodata:0000000000002040 E1  db 0E1h
.rodata:0000000000002041 66  db  66h ; f
.rodata:0000000000002042 12  db  12h
.rodata:0000000000002043 0A  db  0Ah
.rodata:0000000000002044 75  db  75h ; u
.rodata:0000000000002045 E1  db 0E1h
.rodata:0000000000002046 66  db  66h ; f
.rodata:0000000000002047 00  db    0
```
well, we got the key, and this is the solver
#### Solver
```py
key = [0x22, 0x11, 0x75, 0xE1, 0x66, 0x12, 0x0A, 0x75, 0xE1, 0x66]

def decrypt_xor(ciphertext):
    plaintext = []
    key_len = len(key)
    for i in range(len(ciphertext)):
        plaintext.append(chr(ciphertext[i] ^ key[i % key_len]))
    return ''.join(plaintext)

with open('enc.txt', 'rb') as f:
    encrypted = f.read().strip()

cipher_bytes = list(encrypted)
decrypted_message = decrypt_xor(cipher_bytes)
print(f"Flag: {decrypted_message}")
```
Flag: ``TCP1P{micro_challenge_for_c_reverser_XP}``
### Mini Rev
##### Author: Dimas Maulana
##### Desc First C++ reverse engineering challenge :P
i think its same as the previous one, but just diff language, and we got also same file type, exe and enc.txt, this is the main function
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rsi
  __int64 v4; // rdx
  int v5; // ebx
  __int64 v6; // rax
  char v8; // [rsp+1Fh] [rbp-281h] BYREF
  char v9[32]; // [rsp+20h] [rbp-280h] BYREF
  char v10[32]; // [rsp+40h] [rbp-260h] BYREF
  char v11[32]; // [rsp+60h] [rbp-240h] BYREF
  char v12[520]; // [rsp+80h] [rbp-220h] BYREF
  unsigned __int64 v13; // [rsp+288h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  std::allocator<char>::allocator(&v8, argv, envp);
  v3 = argv[1];
  std::string::basic_string<std::allocator<char>>(v9, v3, &v8);
  std::allocator<char>::~allocator(&v8);
  std::allocator<char>::allocator(&v8, v3, v4);
  std::string::basic_string<std::allocator<char>>(v10, &unk_3008, &v8);
  std::allocator<char>::~allocator(&v8);
  xorMessage(v11, v9, v10);
  std::ofstream::basic_ofstream(v12, "enc.txt", 16LL);
  if ( (unsigned __int8)std::ofstream::is_open(v12) != 1 )
  {
    v5 = 1;
  }
  else
  {
    v6 = std::operator<<<char>(v12, v11);
    std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
    std::ofstream::close(v12);
    v5 = 0;
  }
  std::ofstream::~ofstream(v12);
  std::string::~string(v11);
  std::string::~string(v10);
  std::string::~string(v9);
  return v5;
}
```
as we know on the main function, the **enc.txt** is XOR'ed and yea the key is in ``&unk_3008``, this same as the previous one, and this is the key

```c
.rodata:0000000000003008 76  unk_3008 db  76h ; v                    ; DATA XREF: main+8E↑o
.rodata:0000000000003009 22  db  22h ; "
.rodata:000000000000300A 99  db  99h
.rodata:000000000000300B F2  db 0F2h
.rodata:000000000000300C 11  db  11h
.rodata:000000000000300D 67  db  67h ; g
.rodata:000000000000300E FE  db 0FEh
.rodata:000000000000300F 66  db  66h ; f
.rodata:0000000000003010 00  db    0
```
we got the key, and this is the solver
#### Solver
```py
key = [0x76, 0x22, 0x99, 0xF2, 0x11, 0x67, 0xFE, 0x66]

def decrypt_xor(ciphertext):
    plaintext = []
    key_len = len(key)
    for i in range(len(ciphertext)):
        plaintext.append(ciphertext[i] ^ key[i % key_len])
    return bytes(plaintext)

with open('enc.txt', 'rb') as f:
    ciphertext = f.read().strip()

decrypted_message = decrypt_xor(ciphertext)
print(f"Flag: {decrypted_message.decode(errors='ignore')}")
```
Flag: ``TCP1P{mini_rev_for_mini_challenge_XD}``
### Key Checker
##### Author: aimardcr
##### Desc: Flag Checkers are too common, what about Key Checker?
we got exe file, and this is main function after decompile (with IDA)
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // r12
  unsigned __int64 v5; // rbx
  size_t v6; // rax
  size_t v7; // rbx
  char s[8]; // [rsp+8h] [rbp-48h] BYREF
  char s1[8]; // [rsp+10h] [rbp-40h] BYREF
  _QWORD v10[4]; // [rsp+18h] [rbp-38h]
  int i; // [rsp+3Ch] [rbp-14h]

  *(_QWORD *)s1 = 0x5A15715955270E75LL;
  v10[0] = 0x39727E370854130ALL;
  *(_QWORD *)((char *)v10 + 5) = 0x4F721D155539727ELL;
  *(_QWORD *)((char *)&v10[1] + 5) = 0x5C552D5857311246LL;
  printf("Enter the key: ");
  __isoc99_scanf("%07s", s);
  if ( strlen(s) == 7 )
  {
    for ( i = 0; ; ++i )
    {
      v7 = i;
      if ( v7 >= strlen(s1) )
        break;
      v4 = s1[i];
      v5 = i;
      v6 = strlen(s);
      s1[i] = s[v5 % v6] ^ v4;
    }
    if ( !strncmp(s1, "TCF2024", 7uLL) )
    {
      puts("Correct key!");
      return 0;
    }
    else
    {
      puts("Invalid key");
      return 1;
    }
  }
  else
  {
    puts("Invalid key length");
    return 1;
  }
}
```
as you can see, **s** input get XOR'ed with s1 and the result is "TCF2024", to solve this, we need to brute force it key, basically key in key (lol)

#### Key Solver
```py
target = b"TCF2024"
s1_init = bytes([0x75, 0x0E, 0x27, 0x55, 0x59, 0x71, 0x15, 0x5A])

key = []
for i in range(7):
    key.append(target[i] ^ s1_init[i])

key = bytes(key).decode()
print(f"Key: {key}")
```
and we got result:
``!MagiC!``
we alr got the key, whats the next? yea, find the encrypted ciphertext, but IDA is somehow is dumb or smth, he cannot give me encrypted of the ciphertext, then i use ghidra to decompile main function
```c
undefined8 main(void)

{
  byte bVar1;
  int iVar2;
  size_t sVar3;
  undefined8 uVar4;
  ulong uVar5;
  byte local_50 [8];
  undefined8 local_48;
  undefined5 local_40;
  undefined3 uStack_3b;
  undefined5 uStack_38;
  undefined8 local_33;
  int local_1c;
  
  local_48 = 0x5a15715955270e75;
  local_40 = 0x370854130a;
  uStack_3b = 0x39727e;
  uStack_38 = 0x4f721d1555;
  local_33 = 0x5c552d5857311246;
  printf("Enter the key: ");
  __isoc99_scanf(&DAT_00102014,local_50);
  sVar3 = strlen((char *)local_50);
  if (sVar3 == 7) {
    local_1c = 0;
    while( true ) {
      uVar5 = (ulong)local_1c;
      sVar3 = strlen((char *)&local_48);
      if (sVar3 <= uVar5) break;
      bVar1 = *(byte *)((long)&local_48 + (long)local_1c);
      uVar5 = (ulong)local_1c;
      sVar3 = strlen((char *)local_50);
      *(byte *)((long)&local_48 + (long)local_1c) = bVar1 ^ local_50[uVar5 % sVar3];
      local_1c = local_1c + 1;
    }
    iVar2 = strncmp((char *)&local_48,"TCF2024",7);
    if (iVar2 == 0) {
      puts("Correct key!");
      uVar4 = 0;
    }
    else {
      puts("Invalid key");
      uVar4 = 1;
    }
  }
  else {
    puts("Invalid key length");
    uVar4 = 1;
  }
  return uVar4;
}

```
as you can see, the result of decompile between them was different, the Ghidra has more than IDA (i blame ida cus i solve it a hour), anyways, we alr got the enc
```c
local_48 = 0x5a15715955270e75;
local_40 = 0x370854130a;
uStack_3b = 0x39727e;
uStack_38 = 0x4f721d1555;
local_33 = 0x5c552d5857311246;
```
and this is the Final Solver
#### Final Solver
```py
key = b"!MagiC!"

cipher = bytes([
    0x75, 0x0e, 0x27, 0x55, 0x59, 0x71, 0x15, 0x5a,
    0x0a, 0x13, 0x54, 0x08, 0x37,
    0x7e, 0x72, 0x39,
    0x55, 0x15, 0x1d, 0x72, 0x4f,
    0x46, 0x12, 0x31, 0x57, 0x58, 0x2d, 0x55, 0x5c
])

decrypted = bytes([cipher[i] ^ key[i % len(key)] for i in range(len(cipher))])
print(f"Flag: {decrypted.decode(errors='ignore')}")
```
Flag: ``TCF2024{Gr3at_St4rt1ng_P01nt}``

### Random XOR
##### Author: 404Gh0st
##### Desc: Hanya program simpel untuk enkripsi sebuah file.

we got 2 file, exe and flag_enc.txt, so this is the main function with IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int seed; // [rsp+1Ch] [rbp-34h] BYREF
  int i; // [rsp+20h] [rbp-30h]
  int v6; // [rsp+24h] [rbp-2Ch]
  int v7; // [rsp+28h] [rbp-28h]
  int v8; // [rsp+2Ch] [rbp-24h]
  FILE *stream; // [rsp+30h] [rbp-20h]
  void *ptr; // [rsp+38h] [rbp-18h]
  FILE *s; // [rsp+40h] [rbp-10h]
  unsigned __int64 v12; // [rsp+48h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  seed = time(0LL);
  srand(seed);
  stream = fopen(argv[1], "rb");
  if ( stream )
  {
    fseek(stream, 0LL, 2);
    v6 = ftell(stream);
    fseek(stream, 0LL, 0);
    ptr = malloc(0x40uLL);
    fread(ptr, 1uLL, v6, stream);
    for ( i = 0; i < v6; ++i )
    {
      v7 = (unsigned __int8)rand();
      v8 = rand();
      *((_BYTE *)ptr + i) ^= v7;
    }
    s = fopen(argv[2], "wb");
    fwrite(&seed, 1uLL, 4uLL, s);
    fwrite(ptr, 1uLL, v6, s);
    printf("Encrypted flag: %s\n", (const char *)ptr);
    fclose(stream);
    fclose(s);
    free(ptr);
    return 0;
  }
  else
  {
    puts("Error opening file.");
    return 1;
  }
}
```
and this is with Ghidra
```c

undefined8 main(undefined8 param_1,long param_2)

{
  time_t tVar1;
  undefined8 uVar2;
  long lVar3;
  long in_FS_OFFSET;
  uint local_3c;
  int local_38;
  int local_34;
  uint local_30;
  int local_2c;
  FILE *local_28;
  void *local_20;
  FILE *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  local_3c = (uint)tVar1;
  srand(local_3c);
  local_28 = fopen(*(char **)(param_2 + 8),"rb");
  if (local_28 == (FILE *)0x0) {
    puts("Error opening file.");
    uVar2 = 1;
  }
  else {
    fseek(local_28,0,2);
    lVar3 = ftell(local_28);
    local_34 = (int)lVar3;
    fseek(local_28,0,0);
    local_20 = malloc(0x40);
    fread(local_20,1,(long)local_34,local_28);
    for (local_38 = 0; local_38 < local_34; local_38 = local_38 + 1) {
      local_30 = rand();
      local_30 = local_30 & 0xff;
      local_2c = rand();
      *(byte *)((long)local_20 + (long)local_38) =
           *(byte *)((long)local_20 + (long)local_38) ^ (byte)local_30;
    }
    local_18 = fopen(*(char **)(param_2 + 0x10),"wb");
    fwrite(&local_3c,1,4,local_18);
    fwrite(local_20,1,(long)local_34,local_18);
    printf("Encrypted flag: %s\n",local_20);
    fclose(local_28);
    fclose(local_18);
    free(local_20);
    uVar2 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

as you can see, this program is using current time as seed, and set the seet to rand
```c
seed = time(0LL);
srand(seed);
```
and for each byte get XOR with result rand() & 0xFF, then delete the first rand()
```c
for (int i = 0; i < size; i++) {
    rand();                   
    ((char*)data)[i] ^= rand() & 0xFF; 
}
```
i mean like this 
```c
rand() -> delete
rand() -> XOR byte 1
rand() -> del
rand() -> XOR byte 2
rand() -> del
rand() -> XOR byte 3
...
```
and yea finally this is the solver
#### Solver
```py
from ctypes import CDLL
import ctypes.util

libc_path = ctypes.util.find_library("c")
libc = CDLL(/usr/lib/x86_64-linux-gnu/libc.so.6)

flag_enc_file = open("flag_enc.txt", "rb").read()

seed = int.from_bytes(flag_enc_file[:4], "little")
flag_enc = flag_enc_file[4:]

libc.srand(seed)

flag = ""

for c in flag_enc:
    key = libc.rand() & 0xFF
    libc.rand()
    flag += chr(c ^ key)

print(f"Random seed: {seed}")
print(f"Flag: {flag}")

```
Output:
```bash
❯ python3 r.py
Random seed: 1712064365
Flag: TCP1P{p53uDO_RANDOM_IS_NOt_R4ndOM_at_A11}
```
Flag: ``TCP1P{p53uDO_RANDOM_IS_NOt_R4ndOM_at_A11}``

## LANJUT BESOK WAK NGANTUK