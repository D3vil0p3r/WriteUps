# Reversing ELF

![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Tags
--
* Reverse Engineering
* Debugger

Tools used
--
* GDB
* Ghidra
* IDA
* Radare2

Note: in Arch Linux, for running 32-bit ELF, you need to install `lib32-glibc` package.

## Crackme1

Just `./index.crackme1` and you will get the flag.

## Crackme2

Run `strings index.crackme2` and on the output you will see `super_secret_password`.

## Crackme3

Run `strings index.crackme3` and on the output you will see `ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==`. So, run `echo -n "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d` and you will get the flag.

## Crackme4

When we run `./index.crackme4`, we get the message `This time the string is hidden and we used strcmp`. This is an hint saying that `strcmp` function is used and we need to debug the binary.

This one is more elaborated and we can do this by using different tools. Let's see everything.

### IDA

Open IDA and import the executable file. On the "Functions" window on the left, double click on `compare_pwd` and you will see the process flow. Looking at the code around `call _strcmp`, we can understand that the password strings to compare (one typed by the user and the other one that is the valid one) should be stored in `rdx` and `rax` registers.

Right-click on `mov rdi, rax` and click on `Add breakpoint`. Then, for debugging, we need to set the input that the user should give but we can do this directly on IDA giving a dummy password value. For doing this, on the top menu, click on "Debugger" -> "Process options" and, in "Parameters", type a dummy value as `1234` and click OK.

Now, we can run the debugger by clicking on green play icon above. The execution will stop at our set breakpoint. Now, for looking the content of the registers, just go to the line `mov rdi, rax` and pass the mouse pointer over `rdi` or `rax` and double click on it. You will see the content of those registers at that time of execution and you will see the flag.

### GDB

Run `gdb index.crackme4`, then let's identify the functions:
```
(gdb) info functions

All defined functions:

Non-debugging symbols:
0x00000000004004b0  _init
0x00000000004004e0  puts@plt
0x00000000004004f0  __stack_chk_fail@plt
0x0000000000400500  printf@plt
0x0000000000400510  __libc_start_main@plt
0x0000000000400520  strcmp@plt
0x0000000000400530  __gmon_start__@plt
0x0000000000400540  _start
0x0000000000400570  deregister_tm_clones
0x00000000004005a0  register_tm_clones
0x00000000004005e0  __do_global_dtors_aux
0x0000000000400600  frame_dummy
0x000000000040062d  get_pwd
0x000000000040067a  compare_pwd
0x0000000000400716  main
0x0000000000400760  __libc_csu_init
0x00000000004007d0  __libc_csu_fini
0x00000000004007d4  _fini
```
We can set a breakpoint on `strcmp@plt`:
```
(gdb) b *0x0000000000400520
Breakpoint 1 at 0x400520
```
Then, run the debugger:
```
(gdb) run passwordtest
Starting program: /home/athena/Downloads/index.crackme4 passwordtest
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, 0x0000000000400520 in strcmp@plt ()
```
At this point, one of the registers should maintain the real password value. Run:
```
(gdb) info registers
rax            0x7fffffffde90      140737488346768
rbx            0x7fffffffdfe8      140737488347112
rcx            0x11                17
rdx            0x7fffffffe41a      140737488348186
rsi            0x7fffffffe41a      140737488348186
rdi            0x7fffffffde90      140737488346768
rbp            0x7fffffffdeb0      0x7fffffffdeb0
rsp            0x7fffffffde78      0x7fffffffde78
r8             0x4007d0            4196304
r9             0x7ffff7fced70      140737353936240
r10            0x7ffff7dd0f90      140737351847824
r11            0x7ffff7de57c0      140737351931840
r12            0x0                 0
r13            0x7fffffffe000      140737488347136
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x400520            0x400520 <strcmp@plt>
eflags         0x246               [ PF ZF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```
I can see that the general purpose registers `rax` and `rdx` have memory address values. Let's use gdb to print the strings at these addresses:
```
(gdb) x/s 0x7fffffffde90
0x7fffffffde90:	"my_m0r3_secur3_pwd"
```

### Radare2

Run:
```
r2 -d index.crackme4 passwordtest
```
Note: it is important to set the parameter if requested by the executable.

Now, for getting information about functions inside the code, we need to run a command for analyzing the code. It can be done by several commands: `aa` or `aaa` or `aaaa`. The last one will provide us too many functions when we show them, so it is better using `aaa` for our purpose:
```
[0x7fafd8c94ed0]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Skipping type matching analysis in debugger mode (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
```
Now, let's show the functions it found:
```
[0x7fafd8c94ed0]> afl
0x00400540    1     41 entry0
0x00400510    1      6 sym.imp.__libc_start_main
0x00400570    4     41 sym.deregister_tm_clones
0x004005a0    4     57 sym.register_tm_clones
0x004005e0    3     28 sym.__do_global_dtors_aux
0x00400600    4     42 sym.frame_dummy
0x004007d0    1      2 sym.__libc_csu_fini
0x0040062d    4     77 sym.get_pwd
0x004007d4    1      9 sym._fini
0x0040067a    6    156 sym.compare_pwd
0x00400760    4    101 sym.__libc_csu_init
0x00400716    4     74 main
0x004004b0    3     26 sym._init
0x00400530    1      6 loc.imp.__gmon_start__
0x004004e0    1      6 sym.imp.puts
0x004004f0    1      6 sym.imp.__stack_chk_fail
0x00400500    1      6 sym.imp.printf
0x00400520    1      6 sym.imp.strcmp
```
We should infer the function where the password is stored in the right register. In our case, according to the hint of the exercise, it should be `sym.imp.strcmp`. So, let's set a breakpoint there:
```
[0x7fafd8c94ed0]> db sym.imp.strcmp
```
Then, run the debugger:
```
[0x7fafd8c94ed0]> dc
hit breakpoint at: 0x400520
```
Now run the list of registers and related details:
```
[0x00400520]> drr
role reg     value            refstr
――――――――――――――――――――――――――――――――――――
     riz     0                0
R0   rax     7ffe66a90890     [stack] rax,rdi stack R W 0x5f3372306d5f796d my_m0r3_secur3_pwd
     rbx     7ffe66a909e8     [stack] rbx stack R W 0x7ffe66a9143b
A3   rcx     11               17 .comment rcx
A2   rdx     7ffe66a9144c     [stack] rdx,rsi stack R W 0x4944450073736170 pass
A4   r8      4007d0           4196304 /home/athena/Downloads/index.crackme4 .text __libc_csu_fini,r8 sym.__libc_csu_fini program R X 'ret' 'index.crackme4'
A5   r9      7fce626b0d70     /usr/lib/ld-linux-x86-64.so.2 r9 library R X 'endbr64' 'ld-linux-x86-64.so.2'
     r10     7fce624b8f90     r10
     r11     7fce624cd7c0     r11
     r12     0                0
     r13     7ffe66a90a00     [stack] r13 stack R W 0x7ffe66a91451
     r14     0                0
     r15     7fce626df000     /usr/lib/ld-linux-x86-64.so.2 r15 library R W 0x7fce626e02c0
A1   rsi     7ffe66a9144c     [stack] rdx,rsi stack R W 0x4944450073736170 pass
A0   rdi     7ffe66a90890     [stack] rax,rdi stack R W 0x5f3372306d5f796d my_m0r3_secur3_pwd
SP   rsp     7ffe66a90878     [stack] rsp stack R W 0x4006da
BP   rbp     7ffe66a908b0     [stack] rbp stack R W 0x7ffe66a908d0
PC   rip     400520           4195616 /home/athena/Downloads/index.crackme4 .plt strcmp,rip sym.imp.strcmp program R X 'jmp qword [rip + 0x200b12]' 'index.crackme4'
     cs      33               51 .shstrtab ascii ('3')
     rflags  246              582 .symtab rflags
SN   orax    ffffffffffffffff 
     ss      2b               43 .shstrtab ascii ('+')
     fs      7fce62692640     
     gs      0                0
     ds      0                0
     es      0                0
     fs_base 0                0
     gs_base 0                0
```
Look on the output above, on `rax` we already see the flag. In case we would have a detail of `rax` register, run:
```
x/32x @0x7ffe66a90890
```
where `0x7ffe66a90890` refers to the address shown in `rax` row without `0x`.

### ltrace
Run:
```
ltrace ./index.crackme4 passwordtest
__libc_start_main(0x400716, 2, 0x7ffefc0c41d8, 0x400760 <unfinished ...>
strcmp("my_m0r3_secur3_pwd", "passwordtest")                                                                                   = -7
printf("password "%s" not OK\n", "test"password "test" not OK
)                                                                               = 23
+++ exited (status 0) +++
```

## Crackme5

By running `./index.crackme5`, we get:
```
Enter your input:
proofinput
Always dig deeper
```
We can use the same technique of the previous exercise by checking for `rcx`.

We can also use `ltrace ./index.crackme5`.

You can also disassemble the file by IDA or Ghidra, then search for `main` function and on the pseudo-code, you can see some constants before entering the input. Just convert them to char, and you will get flag.

## Crackme6

By running `./index.crackme6 passwordtest`, we get `password "passwordtest" not OK`.

Let's disassemble it and check `my_secure_test` function. Inside the "if-else" statements you can see the flag.

## Crackme7

Disassemble the file. Go to the `main` function and focus on the following piece of code:
```
else if (local_14 == 0x7a69) {
    puts("Wow such h4x0r!");
    giveFlag();
}
```
Let's convert `0x7a69` to integer: `31337`.

Since `local_14` is used for selecting the menu entry (on the program we have only 1), 2) and 3)), let's run the program and type `31337`:
```
./index.crackme7
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 31337
Wow such h4x0r!
flag{much_reversing_very_ida_wow}
```

## Crackme8

Disassemble the file. Go to the `main` function and focus on the following piece of code:
```
if (param_1 == 2) {
  iVar2 = atoi((char *)param_2[1]);
  if (iVar2 == -0x35010ff3) {
    puts("Access granted.");
    giveFlag();
    uVar1 = 0;
  }
  else {
    puts("Access denied.");
    uVar1 = 1;
  }
}
```
Let's convert `-0x35010ff3` to integer: `-889262067`. Let's run:
```
./index.crackme8 -889262067
Access granted.
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
```