# Linux 二进制分析学习手册（三）

> 原文：[`zh.annas-archive.org/md5/557450C26A7CBA64AA60AA031A39EC59`](https://zh.annas-archive.org/md5/557450C26A7CBA64AA60AA031A39EC59)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：ECFS – 扩展核心文件快照技术

**扩展核心文件快照**（**ECFS**）技术是一款插入 Linux 核心处理程序并创建专门设计用于进程内存取证的特殊进程内存快照的软件。大多数人不知道如何解析进程镜像，更不用说如何检查其中的异常。即使对于专家来说，查看进程镜像并检测感染或恶意软件可能是一项艰巨的任务。

在 ECFS 之前，除了使用大多数 Linux 发行版附带的**gcore**脚本创建的核心文件之外，没有真正的进程镜像快照标准。如前一章简要讨论的那样，常规核心文件对于进程取证分析并不特别有用。这就是 ECFS 核心文件出现的原因——提供一种可以描述进程镜像的每一个细微差别的文件格式，以便可以进行高效分析、轻松导航，并且可以轻松集成到恶意软件分析和进程取证工具中。

在本章中，我们将讨论 ECFS 的基础知识以及如何使用 ECFS 核心文件和**libecfs** API 来快速设计恶意软件分析和取证工具。

# 历史

2011 年，我为 DARPA 合同创建了一个名为 Linux VMA Monitor 的软件原型([`www.bitlackeys.org/#vmavudu`](http://www.bitlackeys.org/#vmavudu))。这个软件旨在查看实时进程内存或进程内存的原始快照。它能够检测各种运行时感染，包括共享库注入、PLT/GOT 劫持和其他指示运行时恶意软件的异常。

最近，我考虑将这个软件重写为更完善的状态，我觉得为进程内存创建一个本地快照格式将是一个非常好的功能。这是开发 ECFS 的最初灵感，尽管我已经取消了重新启动 Linux VMA Monitor 软件的计划，但我仍在继续扩展和开发 ECFS 软件，因为它对其他许多人的项目非常有价值。它甚至被整合到了 Lotan 产品中，这是一款用于通过分析崩溃转储来检测利用尝试的软件([`www.leviathansecurity.com/lotan`](http://www.leviathansecurity.com/lotan))。

# ECFS 的理念

ECFS 的目标是使程序的运行时分析比以往任何时候都更容易。整个过程都封装在一个单一文件中，并且以一种有序和高效的方式组织，以便通过解析部分头来访问有用的数据，如符号表、动态链接数据和取证相关结构，从而实现定位和访问对于检测异常和感染至关重要的数据和代码。 

# 开始使用 ECFS

撰写本章时，完整的 ECFS 项目和源代码可在[`github.com/elfmaster/ecfs`](http://github.com/elfmaster/ecfs)上找到。一旦你用 git 克隆了存储库，你应该按照 README 文件中的说明编译和安装软件。

目前，ECFS 有两种使用模式：

+   将 ECFS 插入核心处理程序

+   ECFS 快照而不终止进程

### 注意

在本章中，术语 ECFS 文件、ECFS 快照和 ECFS 核心文件是可以互换使用的。

## 将 ECFS 插入核心处理程序

首先要做的是将 ECFS 核心处理程序插入 Linux 内核中。`make` install 会为您完成这项工作，但必须在每次重启后进行操作，或者存储在一个`init`脚本中。手动设置 ECFS 核心处理程序的方法是修改`/proc/sys/kernel/core_pattern`文件。

这是激活 ECFS 核心处理程序的命令：

```
echo '|/opt/ecfs/bin/ecfs_handler -t -e %e -p %p -o \ /opt/ecfs/cores/%e.%p' > /proc/sys/kernel/core_pattern
```

### 注意

请注意设置了`-t`选项。这对取证非常重要，而且很少关闭。此选项告诉 ECFS 捕获任何可执行文件或共享库映射的整个文本段。在传统核心文件中，文本图像被截断为 4k。在本章的后面，我们还将研究`-h`选项（启发式），它可以设置为启用扩展启发式以检测共享库注入。

`ecfs_handler`二进制文件将调用`ecfs32`或`ecfs64`，具体取决于进程是 64 位还是 32 位。我们写入 procfs `core_pattern`条目的行前面的管道符（`|`）告诉内核将其产生的核心文件导入到我们的 ECFS 核心处理程序进程的标准输入中。然后 ECFS 核心处理程序将传统核心文件转换为高度定制和出色的 ECFS 核心文件。每当进程崩溃或收到导致核心转储的信号，例如**SIGSEGV**或**SIGABRT**，那么 ECFS 核心处理程序将介入并使用自己的一套特殊程序来创建 ECFS 风格的核心转储。

以下是捕获`sshd`的 ECFS 快照的示例：

```
$ kill -ABRT `pidof sshd`
$ ls -lh /opt/ecfs/cores
-rwxrwx--- 1 root root 8244638 Jul 24 13:36 sshd.1211
$
```

将 ECFS 作为默认的核心文件处理程序非常好，非常适合日常使用。这是因为 ECFS 核心向后兼容传统核心文件，并且可以与诸如 GDB 之类的调试器一起使用。但是，有时用户可能希望捕获 ECFS 快照而无需终止进程。这就是 ECFS 快照工具的用处所在。

## 在不终止进程的情况下进行 ECFS 快照

让我们考虑一个场景，有一个可疑的进程正在运行。它可疑是因为它消耗了大量的 CPU，并且它打开了网络套接字，尽管已知它不是任何类型的网络程序。在这种情况下，可能希望让进程继续运行，以便潜在的攻击者尚未被警告，但仍然具有生成 ECFS 核心文件的能力。在这些情况下应该使用`ecfs_snapshot`实用程序。

`ecfs_snapshot`实用程序最终使用 ptrace 系统调用，这意味着两件事：

+   捕获进程的快照可能需要更长的时间。

+   它可能对使用反调试技术防止 ptrace 附加的进程无效

在这些问题中的任何一个成为问题的情况下，您可能需要考虑使用 ECFS 核心处理程序来处理工作，这种情况下您将不得不终止进程。然而，在大多数情况下，`ecfs_snapshot`实用程序将起作用。

以下是使用快照实用程序捕获 ECFS 快照的示例：

```
$ ecfs_snapshot -p `pidof host` -o host_snapshot
```

这为程序 host 捕获了快照，并创建了一个名为`host_snapshot`的 ECFS 快照。在接下来的章节中，我们将演示 ECFS 的一些实际用例，并使用各种实用程序查看 ECFS 文件。

# libecfs - 用于解析 ECFS 文件的库

ECFS 文件格式非常容易使用传统的 ELF 工具进行解析，比如`readelf`，但是为了构建自定义的解析工具，我强烈建议您使用 libecfs 库。这个库是专门设计用于轻松解析 ECFS 核心文件的。稍后在本章中，我们将演示更多细节，当我们设计高级恶意软件分析工具来检测被感染的进程时。

libecfs 也用于正在开发的`readecfs`实用程序，这是一个用于解析 ECFS 文件的工具，非常类似于众所周知的`readelf`实用程序。请注意，libecfs 包含在 GitHub 存储库上的 ECFS 软件包中。

# readecfs

在本章的其余部分中，将使用`readecfs`实用程序来演示不同的 ECFS 功能。以下是从`readecfs -h`中的工具的概要：

```
Usage: readecfs [-RAPSslphega] <ecfscore>
-a  print all (equiv to -Sslphega)
-s  print symbol table info
-l  print shared library names
-p  print ELF program headers
-S  print ELF section headers
-h  print ELF header
-g  print PLTGOT info
-A  print Auxiliary vector
-P  print personality info
-e  print ecfs specific (auiliary vector, process state, sockets, pipes, fd's, etc.)

-[View raw data from a section]
-R <ecfscore> <section>

-[Copy an ELF section into a file (Similar to objcopy)]
-O <ecfscore> .section <outfile>

-[Extract and decompress /proc/$pid from .procfs.tgz section into directory]
-X <ecfscore> <output_dir>

Examples:
readecfs -e <ecfscore>
readecfs -Ag <ecfscore>
readecfs -R <ecfscore> .stack
readecfs -R <ecfscore> .bss
readecfs -eR <ecfscore> .heap
readecfs -O <ecfscore> .vdso vdso_elf.so
readecfs -X <ecfscore> procfs_dir
```

# 使用 ECFS 检查被感染的进程

在展示 ECFS 在真实案例中的有效性之前，了解一下我们将从黑客的角度使用的感染方法的背景将会很有帮助。对于黑客来说，能够将反取证技术纳入其在受损系统上的工作流程中是非常有用的，这样他们的程序，尤其是那些充当后门等的程序，可以对未经训练的人保持隐藏。

其中一种技术是执行**伪装**进程。这是在现有进程内运行程序的行为，理想情况下是在已知是良性但持久的进程内运行，例如 ftpd 或 sshd。Saruman 反取证执行([`www.bitlackeys.org/#saruman`](http://www.bitlackeys.org/#saruman))允许攻击者将一个完整的、动态链接的 PIE 可执行文件注入到现有进程的地址空间并运行它。

它使用线程注入技术，以便注入的程序可以与主机程序同时运行。这种特定的黑客技术是我在 2013 年想出并设计的，但我毫不怀疑其他类似的工具在地下场景中存在的时间比这长得多。通常，这种类型的反取证技术会不被注意到，并且很难被检测到。

让我们看看通过使用 ECFS 技术分析这样的进程可以实现什么样的效率和准确性。

## 感染主机进程

主机进程是一个良性进程，通常会是像 sshd 或 ftpd 这样的东西，就像之前提到的那样。为了举例，我们将使用一个简单而持久的名为 host 的程序；它只是在屏幕上打印一条消息并在无限循环中运行。然后，我们将使用 Saruman 反取证执行启动程序将远程服务器后门注入到该进程中。

在终端 1 中，运行主机程序：

```
$ ./host
I am the host
I am the host
I am the host
```

在终端 2 中，将后门注入到进程中：

```
$ ./launcher `pidof host` ./server
[+] Thread injection succeeded, tid: 16187
[+] Saruman successfully injected program: ./server
[+] PT_DETACHED -> 16186
$
```

## 捕获和分析 ECFS 快照

现在，如果我们通过使用`ecfs_snapshot`实用程序捕获进程的快照，或者通过向进程发出核心转储信号，我们就可以开始我们的检查了。

### 符号表分析

让我们来看一下`host.16186`快照的符号表分析：

```
 readelf -s host.16186

Symbol table '.dynsym' contains 6 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 00007fba3811e000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00007fba3818de30     0 FUNC    GLOBAL DEFAULT  UND puts
     2: 00007fba38209860     0 FUNC    GLOBAL DEFAULT  UND write
     3: 00007fba3813fdd0     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 00007fba3818c4e0     0 FUNC    GLOBAL DEFAULT  UND fopen

Symbol table '.symtab' contains 6 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000400470    96 FUNC    GLOBAL DEFAULT   10 sub_400470
     1: 00000000004004d0    42 FUNC    GLOBAL DEFAULT   10 sub_4004d0
     2: 00000000004005bd    50 FUNC    GLOBAL DEFAULT   10 sub_4005bd
     3: 00000000004005ef    69 FUNC    GLOBAL DEFAULT   10 sub_4005ef
     4: 0000000000400640   101 FUNC    GLOBAL DEFAULT   10 sub_400640
     5: 00000000004006b0     2 FUNC    GLOBAL DEFAULT   10 sub_4006b0
```

`readelf`命令允许我们查看符号表。请注意，`.dynsym`中存在动态符号的符号表，以及存储在`.symtab`符号表中的本地函数的符号表。ECFS 能够通过访问动态段并找到`DT_SYMTAB`来重建动态符号表。

### 注意

`.symtab`符号表有点棘手，但非常有价值。ECFS 使用一种特殊的方法来解析包含以 dwarf 格式的帧描述条目的`PT_GNU_EH_FRAME`段；这些用于异常处理。这些信息对于收集二进制文件中定义的每个函数的位置和大小非常有用。

在函数被混淆的情况下，诸如 IDA 之类的工具将无法识别二进制或核心文件中定义的每个函数，但 ECFS 技术将成功。这是 ECFS 对逆向工程世界产生的主要影响之一——一种几乎无懈可击的定位和确定每个函数大小并生成符号表的方法。在`host.16186`文件中，符号表被完全重建。这很有用，因为它可以帮助我们检测是否有任何 PLT/GOT 钩子被用来重定向共享库函数，如果是的话，我们可以识别被劫持的函数的实际名称。

### 段头分析

现在，让我们来看一下`host.16186`快照的段头分析。

我的`readelf`版本已经稍作修改，以便它识别以下自定义类型：`SHT_INJECTED`和`SHT_PRELOADED`。如果不对 readelf 进行这种修改，它将只显示与这些定义相关的数值。如果你愿意，可以查看`include/ecfs.h`中的定义，并将它们添加到`readelf`源代码中：

```
$ readelf -S host.16186
There are 46 section headers, starting at offset 0x255464:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00002238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note             NOTE             0000000000000000  000005f0
       000000000000133c  0000000000000000   A       0     0     4
  [ 3] .hash             GNU_HASH         0000000000400298  00002298
       000000000000001c  0000000000000000   A       0     0     4
  [ 4] .dynsym           DYNSYM           00000000004002b8  000022b8
       0000000000000090  0000000000000018   A       5     0     8
  [ 5] .dynstr           STRTAB           0000000000400348  00002348
       0000000000000049  0000000000000018   A       0     0     1
  [ 6] .rela.dyn         RELA             00000000004003c0  000023c0
       0000000000000018  0000000000000018   A       4     0     8
  [ 7] .rela.plt         RELA             00000000004003d8  000023d8
       0000000000000078  0000000000000018   A       4     0     8
  [ 8] .init             PROGBITS         0000000000400450  00002450
       000000000000001a  0000000000000000  AX       0     0     8
  [ 9] .plt              PROGBITS         0000000000400470  00002470
       0000000000000060  0000000000000010  AX       0     0     16
  [10] ._TEXT            PROGBITS         0000000000400000  00002000
       0000000000001000  0000000000000000  AX       0     0     16
  [11] .text             PROGBITS         00000000004004d0  000024d0
       00000000000001e2  0000000000000000           0     0     16
  [12] .fini             PROGBITS         00000000004006b4  000026b4
       0000000000000009  0000000000000000  AX       0     0     16
  [13] .eh_frame_hdr     PROGBITS         00000000004006e8  000026e8
       000000000000003c  0000000000000000  AX       0     0     4
  [14] .eh_frame         PROGBITS         0000000000400724  00002728
       0000000000000114  0000000000000000  AX       0     0     8
  [15] .ctors            PROGBITS         0000000000600e10  00003e10
       0000000000000008  0000000000000008   A       0     0     8
  [16] .dtors            PROGBITS         0000000000600e18  00003e18
       0000000000000008  0000000000000008   A       0     0     8
  [17] .dynamic          DYNAMIC          0000000000600e28  00003e28
       00000000000001d0  0000000000000010  WA       0     0     8
  [18] .got.plt          PROGBITS         0000000000601000  00004000
       0000000000000048  0000000000000008  WA       0     0     8
  [19] ._DATA            PROGBITS         0000000000600000  00003000
       0000000000001000  0000000000000000  WA       0     0     8
  [20] .data             PROGBITS         0000000000601040  00004040
       0000000000000010  0000000000000000  WA       0     0     8
  [21] .bss              PROGBITS         0000000000601050  00004050
       0000000000000008  0000000000000000  WA       0     0     8
  [22] .heap             PROGBITS         0000000000e9c000  00006000
       0000000000021000  0000000000000000  WA       0     0     8
  [23] .elf.dyn.0        INJECTED         00007fba37f1b000  00038000
       0000000000001000  0000000000000000  AX       0     0     8
  [24] libc-2.19.so.text SHLIB            00007fba3811e000  0003b000
       00000000001bb000  0000000000000000   A       0     0     8
  [25] libc-2.19.so.unde SHLIB            00007fba382d9000  001f6000
       00000000001ff000  0000000000000000   A       0     0     8
  [26] libc-2.19.so.relr SHLIB            00007fba384d8000  001f6000
       0000000000004000  0000000000000000   A       0     0     8
  [27] libc-2.19.so.data SHLIB            00007fba384dc000  001fa000
       0000000000002000  0000000000000000   A       0     0     8
  [28] ld-2.19.so.text   SHLIB            00007fba384e3000  00201000
       0000000000023000  0000000000000000   A       0     0     8
  [29] ld-2.19.so.relro  SHLIB            00007fba38705000  0022a000
       0000000000001000  0000000000000000   A       0     0     8
  [30] ld-2.19.so.data   SHLIB            00007fba38706000  0022b000
       0000000000001000  0000000000000000   A       0     0     8
  [31] .procfs.tgz       LOUSER+0         0000000000000000  00254388
       00000000000010dc  0000000000000001           0     0     8
  [32] .prstatus         PROGBITS         0000000000000000  00253000
       00000000000002a0  0000000000000150           0     0     8
  [33] .fdinfo           PROGBITS         0000000000000000  002532a0
       0000000000000ac8  0000000000000228           0     0     4
  [34] .siginfo          PROGBITS         0000000000000000  00253d68
       0000000000000080  0000000000000080           0     0     4
  [35] .auxvector        PROGBITS         0000000000000000  00253de8
       0000000000000130  0000000000000008           0     0     8
  [36] .exepath          PROGBITS         0000000000000000  00253f18
       000000000000001c  0000000000000008           0     0     1
  [37] .personality      PROGBITS         0000000000000000  00253f34
       0000000000000004  0000000000000004           0     0     1
  [38] .arglist          PROGBITS         0000000000000000  00253f38
       0000000000000050  0000000000000001           0     0     1
  [39] .fpregset         PROGBITS         0000000000000000  00253f88
       0000000000000400  0000000000000200           0     0     8
  [40] .stack            PROGBITS         00007fff4447c000  0022d000
       0000000000021000  0000000000000000  WA       0     0     8
  [41] .vdso             PROGBITS         00007fff444a9000  0024f000
       0000000000002000  0000000000000000  WA       0     0     8
  [42] .vsyscall         PROGBITS         ffffffffff600000  00251000
       0000000000001000  0000000000000000  WA       0     0     8
  [43] .symtab           SYMTAB           0000000000000000  0025619d
       0000000000000090  0000000000000018          44     0     4
  [44] .strtab           STRTAB           0000000000000000  0025622d
       0000000000000042  0000000000000000           0     0     1
  [45] .shstrtab         STRTAB           0000000000000000  00255fe4
       00000000000001b9  0000000000000000           0     0     1
```

第二十三部分对我们来说特别重要；它被标记为一个带有注入标记的可疑 ELF 对象：

```
  [23] .elf.dyn.0        INJECTED         00007fba37f1b000  00038000
       0000000000001000  0000000000000000  AX       0     0     8 
```

当 ECFS 启发式检测到一个 ELF 对象可疑，并且在其映射的共享库列表中找不到该特定对象时，它会以以下格式命名该段：

```
.elf.<type>.<count>
```

类型可以是四种之一：

+   `ET_NONE`

+   `ET_EXEC`

+   `ET_DYN`

+   `ET_REL`

在我们的例子中，它显然是`ET_DYN`，表示为`dyn`。计数只是找到的注入对象的索引。在这种情况下，索引是`0`，因为它是在这个特定进程中找到的第一个并且唯一的注入 ELF 对象。

`INJECTED`类型显然表示该部分包含一个被确定为可疑或通过非自然手段注入的 ELF 对象。在这种特殊情况下，进程被 Saruman（前面描述过）感染，它注入了一个**位置无关可执行文件**（**PIE**）。PIE 可执行文件的类型是`ET_DYN`，类似于共享库，这就是为什么 ECFS 将其标记为这种类型。

## 使用 readecfs 提取寄生代码

我们在 ECFS 核心文件中发现了一个与寄生代码相关的部分，这是一个注入的 PIE 可执行文件。下一步是调查代码本身。可以通过以下方式之一来完成：使用`objdump`实用程序或更高级的反汇编器，如 IDA pro，来导航到名为`.elf.dyn.0`的部分，或者首先使用`readecfs`实用程序从 ECFS 核心文件中提取寄生代码：

```
$ readecfs -O host.16186 .elf.dyn.0 parasite_code.exe

- readecfs output for file host.16186
- Executable path (.exepath): /home/ryan/git/saruman/host
- Command line: ./host                                                                          

[+] Copying section data from '.elf.dyn.0' into output file 'parasite_code.exe'
```

现在，我们有了从进程映像中提取的寄生代码的唯一副本，这要归功于 ECFS。要识别这种特定的恶意软件，然后提取它，如果没有 ECFS，这将是一项极其繁琐的任务。现在我们可以将`parasite_code.exe`作为一个单独的文件进行检查，在 IDA 中打开它等等：

```
root@elfmaster:~/ecfs/cores# readelf -l parasite_code.exe
readelf: Error: Unable to read in 0x40 bytes of section headers
readelf: Error: Unable to read in 0x780 bytes of section headers

Elf file type is DYN (Shared object file)
Entry point 0xdb0
There are 9 program headers, starting at offset 64

Program Headers:
 Type        Offset             VirtAddr           PhysAddr
              FileSiz            MemSiz              Flags  Align
 PHDR         0x0000000000000040 0x0000000000000040 0x0000000000000040
              0x00000000000001f8 0x00000000000001f8  R E    8
 INTERP       0x0000000000000238 0x0000000000000238 0x0000000000000238
              0x000000000000001c 0x000000000000001c  R      1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
 LOAD         0x0000000000000000 0x0000000000000000 0x0000000000000000
              0x0000000000001934 0x0000000000001934  R E    200000
 LOAD         0x0000000000001df0 0x0000000000201df0 0x0000000000201df0
              0x0000000000000328 0x0000000000000330  RW     200000
 DYNAMIC      0x0000000000001e08 0x0000000000201e08 0x0000000000201e08
              0x00000000000001d0 0x00000000000001d0  RW     8
 NOTE         0x0000000000000254 0x0000000000000254 0x0000000000000254
              0x0000000000000044 0x0000000000000044  R      4
 GNU_EH_FRAME 0x00000000000017e0 0x00000000000017e0 0x00000000000017e0
              0x000000000000003c 0x000000000000003c  R      4
  GNU_STACK   0x0000000000000000 0x0000000000000000 0x0000000000000000
              0x0000000000000000 0x0000000000000000  RW     10
  GNU_RELRO   0x0000000000001df0 0x0000000000201df0 0x0000000000201df0
              0x0000000000000210 0x0000000000000210  R      1
readelf: Error: Unable to read in 0x1d0 bytes of dynamic section
```

请注意，`readelf`在前面的输出中抱怨。这是因为我们提取的寄生体没有自己的段头表。将来，`readecfs`实用程序将能够为从整体 ECFS 核心文件中提取的映射 ELF 对象重建一个最小的段头表。

## 分析 Azazel 用户态 rootkit

如第七章中所述，*进程内存取证*，Azazel 用户态 rootkit 是一种通过`LD_PRELOAD`感染进程的用户态 rootkit，其中 Azazel 共享库链接到进程，并劫持各种`libc`函数。在第七章中，*进程内存取证*，我们使用 GDB 和`readelf`来检查这种特定的 rootkit 感染进程。现在让我们尝试使用 ECFS 方法来进行这种类型的进程内省。以下是从已感染 Azazel rootkit 的可执行文件 host2 中的一个进程的 ECFS 快照。

### 重建 host2 进程的符号表

现在，这是 host2 的符号表在进程重建时：

```
$ readelf -s host2.7254

Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00007f0a0d0ed070     0 FUNC    GLOBAL DEFAULT  UND unlink
     2: 00007f0a0d06fe30     0 FUNC    GLOBAL DEFAULT  UND puts
     3: 00007f0a0d0bcef0     0 FUNC    GLOBAL DEFAULT  UND opendir
     4: 00007f0a0d021dd0     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fopen

 Symbol table '.symtab' contains 5 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 00000000004004b0   112 FUNC    GLOBAL DEFAULT   10 sub_4004b0
     1: 0000000000400520    42 FUNC    GLOBAL DEFAULT   10 sub_400520
     2: 000000000040060d    68 FUNC    GLOBAL DEFAULT   10 sub_40060d
     3: 0000000000400660   101 FUNC    GLOBAL DEFAULT   10 sub_400660
     4: 00000000004006d0     2 FUNC    GLOBAL DEFAULT   10 sub_4006d0
```

从前面的符号表中我们可以看出，host2 是一个简单的程序，只有少量的共享库调用（这在`.dynsym`符号表中显示）：`unlink`，`puts`，`opendir`和`fopen`。

### 重建 host2 进程的段头表

让我们看看 host2 的段头表在进程重建时是什么样子的：

```
$ readelf -S host2.7254

There are 65 section headers, starting at offset 0x27e1ee:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00002238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note             NOTE             0000000000000000  00000900
       000000000000105c  0000000000000000   A       0     0     4
  [ 3] .hash             GNU_HASH         0000000000400298  00002298
       000000000000001c  0000000000000000   A       0     0     4
  [ 4] .dynsym           DYNSYM           00000000004002b8  000022b8
       00000000000000a8  0000000000000018   A       5     0     8
  [ 5] .dynstr           STRTAB           0000000000400360  00002360
       0000000000000052  0000000000000018   A       0     0     1
  [ 6] .rela.dyn         RELA             00000000004003e0  000023e0
       0000000000000018  0000000000000018   A       4     0     8
  [ 7] .rela.plt         RELA             00000000004003f8  000023f8
       0000000000000090  0000000000000018   A       4     0     8
  [ 8] .init             PROGBITS         0000000000400488  00002488
       000000000000001a  0000000000000000  AX       0     0     8
  [ 9] .plt              PROGBITS         00000000004004b0  000024b0
       0000000000000070  0000000000000010  AX       0     0     16
  [10] ._TEXT            PROGBITS         0000000000400000  00002000
       0000000000001000  0000000000000000  AX       0     0     16
  [11] .text             PROGBITS         0000000000400520  00002520
       00000000000001b2  0000000000000000           0     0     16
  [12] .fini             PROGBITS         00000000004006d4  000026d4
       0000000000000009  0000000000000000  AX       0     0     16
  [13] .eh_frame_hdr     PROGBITS         0000000000400708  00002708
       0000000000000034  0000000000000000  AX       0     0     4
  [14] .eh_frame         PROGBITS         000000000040073c  00002740
       00000000000000f4  0000000000000000  AX       0     0     8
  [15] .ctors            PROGBITS         0000000000600e10  00003e10
       0000000000000008  0000000000000008   A       0     0     8
  [16] .dtors            PROGBITS         0000000000600e18  00003e18
       0000000000000008  0000000000000008   A       0     0     8
  [17] .dynamic          DYNAMIC          0000000000600e28  00003e28
       00000000000001d0  0000000000000010  WA       0     0     8
  [18] .got.plt          PROGBITS         0000000000601000  00004000
       0000000000000050  0000000000000008  WA       0     0     8
  [19] ._DATA            PROGBITS         0000000000600000  00003000
       0000000000001000  0000000000000000  WA       0     0     8
  [20] .data             PROGBITS         0000000000601048  00004048
       0000000000000010  0000000000000000  WA       0     0     8
  [21] .bss              PROGBITS         0000000000601058  00004058
       0000000000000008  0000000000000000  WA       0     0     8
  [22] .heap             PROGBITS         0000000000602000  00005000
       0000000000021000  0000000000000000  WA       0     0     8
  [23] libaudit.so.1.0.0 SHLIB            0000003001000000  00026000
       0000000000019000  0000000000000000   A       0     0     8
  [24] libaudit.so.1.0.0 SHLIB            0000003001019000  0003f000
       00000000001ff000  0000000000000000   A       0     0     8
  [25] libaudit.so.1.0.0 SHLIB            0000003001218000  0003f000
       0000000000001000  0000000000000000   A       0     0     8
  [26] libaudit.so.1.0.0 SHLIB            0000003001219000  00040000
       0000000000001000  0000000000000000   A       0     0     8
  [27] libpam.so.0.83.1\. SHLIB            0000003003400000  00041000
       000000000000d000  0000000000000000   A       0     0     8
  [28] libpam.so.0.83.1\. SHLIB            000000300340d000  0004e000
       00000000001ff000  0000000000000000   A       0     0     8
  [29] libpam.so.0.83.1\. SHLIB            000000300360c000  0004e000
       0000000000001000  0000000000000000   A       0     0     8
  [30] libpam.so.0.83.1\. SHLIB            000000300360d000  0004f000
       0000000000001000  0000000000000000   A       0     0     8
  [31] libutil-2.19.so.t SHLIB            00007f0a0cbf9000  00050000
       0000000000002000  0000000000000000   A       0     0     8
  [32] libutil-2.19.so.u SHLIB            00007f0a0cbfb000  00052000
       00000000001ff000  0000000000000000   A       0     0     8
  [33] libutil-2.19.so.r SHLIB            00007f0a0cdfa000  00052000
       0000000000001000  0000000000000000   A       0     0     8
  [34] libutil-2.19.so.d SHLIB            00007f0a0cdfb000  00053000
       0000000000001000  0000000000000000   A       0     0     8
  [35] libdl-2.19.so.tex SHLIB            00007f0a0cdfc000  00054000
       0000000000003000  0000000000000000   A       0     0     8
  [36] libdl-2.19.so.und SHLIB            00007f0a0cdff000  00057000
       00000000001ff000  0000000000000000   A       0     0     8
  [37] libdl-2.19.so.rel SHLIB            00007f0a0cffe000  00057000
       0000000000001000  0000000000000000   A       0     0     8
  [38] libdl-2.19.so.dat SHLIB            00007f0a0cfff000  00058000
       0000000000001000  0000000000000000   A       0     0     8
  [39] libc-2.19.so.text SHLIB            00007f0a0d000000  00059000
       00000000001bb000  0000000000000000   A       0     0     8
  [40] libc-2.19.so.unde SHLIB            00007f0a0d1bb000  00214000
       00000000001ff000  0000000000000000   A       0     0     8
  [41] libc-2.19.so.relr SHLIB            00007f0a0d3ba000  00214000
       0000000000004000  0000000000000000   A       0     0     8
  [42] libc-2.19.so.data SHLIB            00007f0a0d3be000  00218000
       0000000000002000  0000000000000000   A       0     0     8
  [43] azazel.so.text    PRELOADED        00007f0a0d3c5000  0021f000
       0000000000008000  0000000000000000   A       0     0     8
  [44] azazel.so.undef   PRELOADED        00007f0a0d3cd000  00227000
       00000000001ff000  0000000000000000   A       0     0     8
  [45] azazel.so.relro   PRELOADED        00007f0a0d5cc000  00227000
       0000000000001000  0000000000000000   A       0     0     8
  [46] azazel.so.data    PRELOADED        00007f0a0d5cd000  00228000
       0000000000001000  0000000000000000   A       0     0     8
  [47] ld-2.19.so.text   SHLIB            00007f0a0d5ce000  00229000
       0000000000023000  0000000000000000   A       0     0     8
  [48] ld-2.19.so.relro  SHLIB            00007f0a0d7f0000  00254000
       0000000000001000  0000000000000000   A       0     0     8
  [49] ld-2.19.so.data   SHLIB            00007f0a0d7f1000  00255000
       0000000000001000  0000000000000000   A       0     0     8
  [50] .procfs.tgz       LOUSER+0         0000000000000000  0027d038
       00000000000011b6  0000000000000001           0     0     8
  [51] .prstatus         PROGBITS         0000000000000000  0027c000
       0000000000000150  0000000000000150           0     0     8
  [52] .fdinfo           PROGBITS         0000000000000000  0027c150
       0000000000000ac8  0000000000000228           0     0     4
  [53] .siginfo          PROGBITS         0000000000000000  0027cc18
       0000000000000080  0000000000000080           0     0     4
  [54] .auxvector        PROGBITS         0000000000000000  0027cc98
       0000000000000130  0000000000000008           0     0     8
  [55] .exepath          PROGBITS         0000000000000000  0027cdc8
       000000000000001c  0000000000000008           0     0     1
  [56] .personality      PROGBITS         0000000000000000  0027cde4
       0000000000000004  0000000000000004           0     0     1
  [57] .arglist          PROGBITS         0000000000000000  0027cde8
       0000000000000050  0000000000000001           0     0     1
  [58] .fpregset         PROGBITS         0000000000000000  0027ce38
       0000000000000200  0000000000000200           0     0     8
  [59] .stack            PROGBITS         00007ffdb9161000  00257000
       0000000000021000  0000000000000000  WA       0     0     8
  [60] .vdso             PROGBITS         00007ffdb918f000  00279000
       0000000000002000  0000000000000000  WA       0     0     8
  [61] .vsyscall         PROGBITS         ffffffffff600000  0027b000
       0000000000001000  0000000000000000  WA       0     0     8
  [62] .symtab           SYMTAB           0000000000000000  0027f576
       0000000000000078  0000000000000018          63     0     4
  [63] .strtab           STRTAB           0000000000000000  0027f5ee
       0000000000000037  0000000000000000           0     0     1
  [64] .shstrtab         STRTAB           0000000000000000  0027f22e
       0000000000000348  0000000000000000           0     0     1
```

ELF 的 43 到 46 节都立即引起怀疑，因为它们标记为`PRELOADED`节类型，这表明它们是从使用`LD_PRELOAD`环境变量预加载的共享库的映射：

```
  [43] azazel.so.text    PRELOADED        00007f0a0d3c5000  0021f000
       0000000000008000  0000000000000000   A       0     0     8
  [44] azazel.so.undef   PRELOADED        00007f0a0d3cd000  00227000
       00000000001ff000  0000000000000000   A       0     0     8
  [45] azazel.so.relro   PRELOADED        00007f0a0d5cc000  00227000
       0000000000001000  0000000000000000   A       0     0     8
  [46] azazel.so.data    PRELOADED        00007f0a0d5cd000  00228000
       0000000000001000  0000000000000000   A       0     0     8
```

各种用户态 rootkit，如 Azazel，使用`LD_PRELOAD`作为它们的注入手段。下一步是查看 PLT/GOT（全局偏移表），并检查它是否包含指向各自边界之外的函数的指针。

你可能还记得前面的章节中提到 GOT 包含一个指针值表，应该指向这两者之一：

+   对应的 PLT 条目中的 PLT 存根（记住第二章中的延迟链接概念，*ELF 二进制格式*）

+   如果链接器已经以某种方式（延迟或严格链接）解析了特定的 GOT 条目，那么它将指向可执行文件的`.rela.plt`节中相应重定位条目所表示的共享库函数

### 使用 ECFS 验证 PLT/GOT

手动理解和系统验证 PLT/GOT 的完整性是很繁琐的。幸运的是，使用 ECFS 可以很容易地完成这项工作。如果你喜欢编写自己的工具，那么你应该使用专门为此目的设计的`libecfs`函数：

```
ssize_t get_pltgot_info(ecfs_elf_t *desc, pltgot_info_t **pginfo)
```

该函数分配了一个结构数组，每个元素都与单个 PLT/GOT 条目相关。

名为`pltgot_info_t`的 C 结构具有以下格式：

```
typedef struct pltgotinfo {
   unsigned long got_site; // addr of the GOT entry itself
   unsigned long got_entry_va; // pointer value stored in the GOT entry
   unsigned long plt_entry_va; // the expected PLT address
   unsigned long shl_entry_va; // the expected shared lib function addr
} pltgot_info_t;
```

可以在`ecfs/libecfs/main/detect_plt_hooks.c`中找到使用此函数的示例。这是一个简单的演示工具，用于检测共享库注入和 PLT/GOT 钩子，稍后在本章中进行了展示和注释，以便清晰地理解。`readecfs`实用程序还演示了在传递`-g`标志时使用`get_pltgot_info()`函数。 

### 用于 PLT/GOT 验证的 readecfs 输出

```
- readecfs output for file host2.7254
- Executable path (.exepath): /home/user/git/azazel/host2
- Command line: ./host2
- Printing out GOT/PLT characteristics (pltgot_info_t):
gotsite    gotvalue       gotshlib          pltval         symbol
0x601018   0x7f0a0d3c8c81  0x7f0a0d0ed070   0x4004c6      unlink
0x601020   0x7f0a0d06fe30  0x7f0a0d06fe30   0x4004d6      puts
0x601028   0x7f0a0d3c8d77  0x7f0a0d0bcef0   0x4004e6      opendir
0x601030   0x7f0a0d021dd0  0x7f0a0d021dd0   0x4004f6      __libc_start_main
```

前面的输出很容易解析。`gotvalue`应该有一个地址，与`gotshlib`或`pltval`匹配。然而，我们可以看到，第一个条目，即符号`unlink`，其地址为`0x7f0a0d3c8c81`。这与预期的共享库函数或 PLT 值不匹配。

进一步调查将显示该地址指向`azazel.so`中的一个函数。从前面的输出中，我们可以看到，唯一没有被篡改的两个函数是`puts`和`__libc_start_main`。为了更深入地了解检测过程，让我们看一下一个工具的源代码，该工具作为其检测功能的一部分自动进行 PLT/GOT 验证。这个工具叫做`detect_plt_hooks`，是用 C 编写的。它利用 libecfs API 来加载和解析 ECFS 快照。

请注意，以下代码大约有 50 行源代码，这相当了不起。如果我们不使用 ECFS 或 libecfs，要准确分析共享库注入和 PLT/GOT 钩子的进程映像，大约需要 3000 行 C 代码。我知道这一点，因为我已经做过了，而使用 libecfs 是迄今为止最轻松的方法。

这里有一个使用`detect_plt_hooks.c`的代码示例：

```
#include "../include/libecfs.h"

int main(int argc, char **argv)
{
    ecfs_elf_t *desc;
    ecfs_sym_t *dsyms;
    char *progname;
    int i;
    char *libname;
    long evil_addr = 0;

    if (argc < 2) {
        printf("Usage: %s <ecfs_file>\n", argv[0]);
        exit(0);
    }

    /*
     * Load the ECFS file and creates descriptor
     */
    desc = load_ecfs_file(argv[1]);
    /*
     * Get the original program name
    */
    progname = get_exe_path(desc);

    printf("Performing analysis on '%s' which corresponds to executable: %s\n", argv[1], progname);

    /*
     * Look for any sections that are marked as INJECTED
     * or PRELOADED, indicating shared library injection
     * or ELF object injection.
     */
    for (i = 0; i < desc->ehdr->e_shnum; i++) {
        if (desc->shdr[i].sh_type == SHT_INJECTED) {
            libname = strdup(&desc->shstrtab[desc->shdr[i].sh_name]);
            printf("[!] Found malicously injected ET_DYN (Dynamic ELF): %s - base: %lx\n", libname, desc->shdr[i].sh_addr);
        } else
        if (desc->shdr[i].sh_type == SHT_PRELOADED) {
            libname = strdup(&desc->shstrtab[desc->shdr[i].sh_name]);
            printf("[!] Found a preloaded shared library (LD_PRELOAD): %s - base: %lx\n", libname, desc->shdr[i].sh_addr);
        }
    }
    /*
     * Load and validate the PLT/GOT to make sure that each
     * GOT entry points to its proper respective location
     * in either the PLT, or the correct shared lib function.
     */
    pltgot_info_t *pltgot;
    int gotcount = get_pltgot_info(desc, &pltgot);
    for (i = 0; i < gotcount; i++) {
        if (pltgot[i].got_entry_va != pltgot[i].shl_entry_va &&
            pltgot[i].got_entry_va != pltgot[i].plt_entry_va &&
            pltgot[i].shl_entry_va != 0) {
            printf("[!] Found PLT/GOT hook: A function is pointing at %lx instead of %lx\n",
                pltgot[i].got_entry_va, evil_addr = pltgot[i].shl_entry_va);
     /*
      * Load the dynamic symbol table to print the
      * hijacked function by name.
      */
            int symcount = get_dynamic_symbols(desc, &dsyms);
            for (i = 0; i < symcount; i++) {
                if (dsyms[i].symval == evil_addr) {
                    printf("[!] %lx corresponds to hijacked function: %s\n", dsyms[i].symval, &dsyms[i].strtab[dsyms[i].nameoffset]);
                break;
                }
            }
        }
    }
    return 0;
}
```

# ECFS 参考指南

ECFS 文件格式既简单又复杂！总的来说，ELF 文件格式本身就很复杂，ECFS 从结构上继承了这些复杂性。另一方面，如果你知道它具有哪些特定特性以及要寻找什么，ECFS 可以帮助你轻松地浏览进程映像。

在前面的章节中，我们给出了一些利用 ECFS 的实际例子，展示了它的许多主要特性。然而，重要的是要有一个简单直接的参考，了解这些特性是什么，比如存在哪些自定义节以及它们的确切含义。在本节中，我们将为 ECFS 快照文件提供一个参考。

## ECFS 符号表重建

ECFS 处理程序使用对 ELF 二进制格式甚至是 dwarf 调试格式的高级理解，特别是动态段和`GNU_EH_FRAME`段，来完全重建程序的符号表。即使原始二进制文件已经被剥离并且没有部分头，ECFS 处理程序也足够智能，可以重建符号表。

我个人从未遇到过符号表重建完全失败的情况。它通常会重建所有或大多数符号表条目。可以使用诸如`readelf`或`readecfs`之类的实用程序访问符号表。libecfs API 还具有几个功能：

```
int get_dynamic_symbols(ecfs_elf_t *desc, ecfs_sym_t **syms)
int get_local_symbols(ecfs_elf_t *desc, ecfs_sym_t **syms)
```

一个函数获取动态符号表，另一个获取本地符号表——分别是`.dynsym`和`.symtab`。

以下是使用`readelf`读取符号表：

```
$ readelf -s host.6758

Symbol table '.dynsym' contains 8 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 00007f3dfd48b000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00007f3dfd4f9730     0 FUNC    GLOBAL DEFAULT  UND fputs
     2: 00007f3dfd4acdd0     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main
     3: 00007f3dfd4f9220     0 FUNC    GLOBAL DEFAULT  UND fgets
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 00007f3dfd4f94e0     0 FUNC    GLOBAL DEFAULT  UND fopen
     6: 00007f3dfd54bd00     0 FUNC    GLOBAL DEFAULT  UND sleep
     7: 00007f3dfd84a870     8 OBJECT  GLOBAL DEFAULT   25 stdout

Symbol table '.symtab' contains 5 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 00000000004004f0   112 FUNC    GLOBAL DEFAULT   10 sub_4004f0
     1: 0000000000400560    42 FUNC    GLOBAL DEFAULT   10 sub_400560
     2: 000000000040064d   138 FUNC    GLOBAL DEFAULT   10 sub_40064d
     3: 00000000004006e0   101 FUNC    GLOBAL DEFAULT   10 sub_4006e0
     4: 0000000000400750     2 FUNC    GLOBAL DEFAULT   10 sub_400750
```

## ECFS 部分头

ECFS 处理程序重建了程序可能具有的大部分原始部分头。它还添加了一些非常有用的新部分和部分类型，对于取证分析非常有用。部分头由名称和类型标识，并包含数据或代码。

解析部分头非常容易，因此它们对于创建进程内存映像的地图非常有用。通过部分头导航整个进程布局比仅具有程序头（例如常规核心文件）要容易得多，后者甚至没有字符串名称。程序头描述内存段，而部分头为给定段的每个部分提供上下文。部分头有助于为逆向工程师提供更高的分辨率。

| 部分头 | 描述 |
| --- | --- |
| `._TEXT` | 这指向文本段（而不是`.text`部分）。这使得在不必解析程序头的情况下定位文本段成为可能。 |
| `._DATA` | 这指向数据段（而不是`.data`部分）。这使得在不必解析程序头的情况下定位数据段成为可能。 |
| `.stack` | 这指向了几个可能的堆栈段之一，取决于线程的数量。如果没有名为`.stack`的部分，要知道进程的实际堆栈在哪里将会更加困难。您将不得不查看`%rsp`寄存器的值，然后查看哪些程序头段包含与堆栈指针值匹配的地址范围。 |
| `.heap` | 类似于`.stack`部分，这指向堆段，也使得识别堆变得更加容易，特别是在 ASLR 将堆移动到随机位置的系统上。在旧系统上，它总是从数据段扩展的。 |
| `.bss` | 此部分并非 ECFS 的新内容。之所以在这里提到它，是因为对于可执行文件或共享库，`.bss`部分不包含任何内容，因为未初始化的数据在磁盘上不占用空间。然而，ECFS 表示内存，因此`.bss`部分实际上直到运行时才会被创建。ECFS 文件具有一个实际反映进程使用的未初始化数据变量的`.bss`部分。 |
| `.vdso` | 这指向映射到每个 Linux 进程中的[vdso]段，其中包含对于某些`glibc`系统调用包装器调用真实系统调用所必需的代码。 |
| `.vsyscall` | 类似于`.vdso`代码，`.vsyscall`页面包含用于调用少量虚拟系统调用的代码。它已经保留了向后兼容性。在逆向工程中了解此位置可能会很有用。 |
| `.procfs.tgz` | 此部分包含由 ECFS 处理程序捕获的进程`/proc/$pid`的整个目录结构和文件。如果您是一位狂热的取证分析师或程序员，那么您可能已经知道`proc`文件系统中包含的信息有多么有用。对于单个进程，在`/proc/$pid`中有超过 300 个文件。 |

| `.prstatus` | 此部分包含一系列`elf_prstatus`结构的数组。这些结构中存储了有关进程状态和寄存器状态的非常重要的信息：

```
struct elf_prstatus
  {
    struct elf_siginfo pr_info;         /* Info associated with signal.  */
    short int pr_cursig;                /* Current signal.  */
    unsigned long int pr_sigpend;       /* Set of pending signals.  */
    unsigned long int pr_sighold;       /* Set of held signals.  */
    __pid_t pr_pid;
    __pid_t pr_ppid;
    __pid_t pr_pgrp;
    __pid_t pr_sid;
    struct timeval pr_utime;            /* User time.  */
    struct timeval pr_stime;            /* System time.  */
    struct timeval pr_cutime;           /* Cumulative user time.  */
    struct timeval pr_cstime;           /* Cumulative system time.  */
    elf_gregset_t pr_reg;               /* GP registers.  */
    int pr_fpvalid;                     /* True if math copro being used.  */
  };
```

|

| `.fdinfo` | 此部分包含描述进程打开文件、网络连接和进程间通信所使用的文件描述符、套接字和管道的 ECFS 自定义数据。头文件`ecfs.h`定义了`fdinfo_t`类型：

```
typedef struct fdinfo {
        int fd;
        char path[MAX_PATH];
        loff_t pos;
        unsigned int perms;
        struct {
                struct in_addr src_addr;
                struct in_addr dst_addr;
                uint16_t src_port;
                uint16_t dst_port;
        } socket;
        char net;
} fd_info_t;
```

`readecfs`实用程序可以解析并漂亮地显示文件描述符信息，如查看 sshd 的 ECFS 快照时所示：

```
        [fd: 0:0] perms: 8002 path: /dev/null
        [fd: 1:0] perms: 8002 path: /dev/null
        [fd: 2:0] perms: 8002 path: /dev/null
        [fd: 3:0] perms: 802 path: socket:[10161]
        PROTOCOL: TCP
        SRC: 0.0.0.0:22
        DST: 0.0.0.0:0

        [fd: 4:0] perms: 802 path: socket:[10163]
        PROTOCOL: TCP
        SRC: 0.0.0.0:22
        DST: 0.0.0.0:0
```

|

| `.siginfo` | 此部分包含特定信号的信息，例如杀死进程的信号，或者在快照被拍摄之前的最后一个信号代码。`siginfo_t struct`存储在此部分。此结构的格式可以在`/usr/include/bits/siginfo.h`中看到。 |
| --- | --- |
| `.auxvector` | 这包含来自堆栈底部（最高内存地址）的实际辅助向量。辅助向量由内核在运行时设置，它包含传递给动态链接器的运行时信息。这些信息对于高级取证分析人员可能在多种情况下都很有价值。 |
| `.exepath` | 这保存了为该进程调用的原始可执行路径的字符串，即`/usr/sbin/sshd`。 |

| `.personality` | 这包含个性信息，即 ECFS 个性信息。可以使用 8 字节的无符号整数设置任意数量的个性标志：

```
#define ELF_STATIC (1 << 1) // if it's statically linked (instead of dynamically)
#define ELF_PIE (1 << 2)    // if it's a PIE executable
#define ELF_LOCSYM (1 << 3) // was a .symtab symbol table created by ecfs?
#define ELF_HEURISTICS (1 << 4) // were detection heuristics used by ecfs?
#define ELF_STRIPPED_SHDRS (1 << 8) // did the binary have section headers?
```

|

| `.arglist` | 包含存储为数组的原始`'char **argv'`。 |
| --- | --- |

## 将 ECFS 文件用作常规核心文件

ECFS 核心文件格式基本上与常规 Linux 核心文件向后兼容，因此可以像传统方式一样与 GDB 一起用作调试核心文件。

ECFS 文件的 ELF 文件头将其`e_type`（ELF 类型）设置为`ET_NONE`，而不是`ET_CORE`。这是因为核心文件不应该有节头，但 ECFS 文件确实有节头，为了确保它们被诸如`objdump`、`objcopy`等特定实用程序所承认，我们必须将它们标记为非 CORE 文件。在 ECFS 文件中切换 ELF 类型的最快方法是使用随 ECFS 软件套件一起提供的`et_flip`实用程序。

以下是使用 GDB 与 ECFS 核心文件的示例：

```
$ gdb -q /usr/sbin/sshd sshd.1195
Reading symbols from /usr/sbin/sshd...(no debugging symbols found)...done.
"/opt/ecfs/cores/sshd.1195" is not a core dump: File format not recognized
(gdb) quit
```

接下来，以下是将 ELF 文件类型更改为`ET_CORE`并重试的示例：

```
$ et_flip sshd.1195
$ gdb -q /usr/sbin/sshd sshd.1195
Reading symbols from /usr/sbin/sshd...(no debugging symbols found)...done.
[New LWP 1195]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Core was generated by `/usr/sbin/sshd -D'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x00007ff4066b8d83 in __select_nocancel () at ../sysdeps/unix/syscall-template.S:81
81  ../sysdeps/unix/syscall-template.S: No such file or directory.
(gdb)
```

## libecfs API 及其使用方法

libecfs API 是将 ECFS 支持集成到 Linux 恶意软件分析和逆向工程工具中的关键组件。这个库的文档内容太多，无法放入本书的一个章节中。我建议您使用与项目本身一起不断增长的手册：

[`github.com/elfmaster/ecfs/blob/master/Documentation/libecfs_manual.txt`](https://github.com/elfmaster/ecfs/blob/master/Documentation/libecfs_manual.txt)

# 使用 ECFS 进行进程复活

您是否曾经想过能够在 Linux 中暂停和恢复进程？设计 ECFS 后，很快就显而易见，它们包含了足够的关于进程及其状态的信息，可以将它们重新加载到内存中，以便它们可以从上次停止的地方开始执行。这个功能有许多可能的用途，并需要更多的研究和开发。

目前，ECFS 快照执行的实现是基本的，只能处理简单的进程。在撰写本章时，它可以恢复文件流，但不能处理套接字或管道，并且只能处理单线程进程。执行 ECFS 快照的软件可以在 GitHub 上找到：[`github.com/elfmaster/ecfs_exec`](https://github.com/elfmaster/ecfs_exec)。

以下是快照执行的示例：

```
$ ./print_passfile
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin

– interrupted by snapshot -
```

我们现在有了 ECFS 快照文件 print_passfile.6627（其中 6627 是进程 ID）。我们将使用 ecfs_exec 来执行这个快照，它应该会从离开的地方开始执行：

```
$ ecfs_exec ./print_passfile.6627
[+] Using entry point: 7f79a0473f20
[+] Using stack vaddr: 7fff8c752738
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
usbmux:x:103:46:usbmux daemon,,,:/home/usbmux:/bin/false
dnsmasq:x:104:65534:dnsmasq,,,:/var/lib/misc:/bin/false
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
kernoops:x:106:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
saned:x:108:115::/home/saned:/bin/false
whoopsie:x:109:116::/nonexistent:/bin/false
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
avahi:x:111:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
lightdm:x:112:118:Light Display Manager:/var/lib/lightdm:/bin/false
colord:x:113:121:colord colour management daemon,,,:/var/lib/colord:/bin/false
hplip:x:114:7:HPLIP system user,,,:/var/run/hplip:/bin/false
pulse:x:115:122:PulseAudio daemon,,,:/var/run/pulse:/bin/false
statd:x:116:65534::/var/lib/nfs:/bin/false
guest-ieu5xg:x:117:126:Guest,,,:/tmp/guest-ieu5xg:/bin/bash
sshd:x:118:65534::/var/run/sshd:/usr/sbin/nologin
gdm:x:119:128:Gnome Display Manager:/var/lib/gdm:/bin/false
```

这是一个关于`ecfs_exec`如何工作的非常简单的演示。它使用了来自`.fdinfo`部分的文件描述符信息来获取文件描述符号、文件路径和文件偏移量。它还使用了`.prstatus`和`.fpregset`部分来获取寄存器状态，以便可以从离开的地方恢复执行。

# 了解更多关于 ECFS 的信息

扩展核心文件快照技术 ECFS 仍然相对较新。我在 defcon 23 上做了演讲（[`www.defcon.org/html/defcon-23/dc-23-speakers.html#O%27Neill`](https://www.defcon.org/html/defcon-23/dc-23-speakers.html#O%27Neill)），目前这个技术还在不断传播。希望会有一个社区的发展，更多人会开始采用 ECFS 进行日常取证工作和工具。尽管如此，目前已经存在一些关于 ECFS 的资源：

官方 GitHub 页面：[`github.com/elfmaster/ecfs`](https://github.com/elfmaster/ecfs)

+   原始白皮书（已过时）：[`www.leviathansecurity.com/white-papers/extending-the-elf-core-format-for-forensics-snapshots`](http://www.leviathansecurity.com/white-papers/extending-the-elf-core-format-for-forensics-snapshots)

+   POC || GTFO 0x7 的一篇文章：*核心文件的创新*，[`speakerdeck.com/ange/poc-gtfo-issue-0x07-1`](https://speakerdeck.com/ange/poc-gtfo-issue-0x07-1)

# 总结

在本章中，我们介绍了 ECFS 快照技术和快照格式的基础知识。我们使用了几个真实的取证案例来实验 ECFS，甚至编写了一个使用 libecfs C 库来检测共享库注入和 PLT/GOT 钩子的工具。在下一章中，我们将跳出用户空间，探索 Linux 内核、vmlinux 的布局以及内核 rootkit 和取证技术的组合。


# 第九章：Linux /proc/kcore 分析

到目前为止，我们已经涵盖了与用户空间相关的 Linux 二进制文件和内存。然而，如果我们不花一章的时间来讨论 Linux 内核，这本书就不会完整。这是因为它实际上也是一个 ELF 二进制文件。类似于程序加载到内存中，Linux 内核映像，也被称为**vmlinux**，在启动时加载到内存中。它有一个文本段和一个数据段，上面覆盖着许多与内核非常特定的部分头，这些部分头在用户空间可执行文件中是看不到的。在本章中，我们还将简要介绍 LKM，因为它们也是 ELF 文件。

# Linux 内核取证和 rootkit

学习 Linux 内核映像的布局对于想要成为 Linux 内核取证真正专家的人来说非常重要。攻击者可以修改内核内存以创建非常复杂的内核 rootkit。有很多技术可以在运行时感染内核。列举一些，我们有以下内容：

+   - `sys_call_table`感染

+   - 中断处理程序修补

+   - 函数跳板

+   - 调试寄存器 rootkit

+   - 异常表感染

+   - Kprobe 仪器化

这里列出的技术是最常被内核 rootkit 使用的主要方法，通常以**LKM**（**可加载内核模块**的缩写）的形式感染内核。了解每种技术并知道每种感染在 Linux 内核中的位置以及在内存中的查找位置对于能够检测这种阴险的 Linux 恶意软件类别至关重要。然而，首先让我们退一步，看看我们有什么可以使用的。目前市场上和开源世界中有许多工具可以检测内核 rootkit 并帮助搜索内存感染。我们不会讨论这些。然而，我们将讨论从内核 Voodoo 中提取的方法。内核 Voodoo 是我的一个项目，目前大部分仍然是私有的，只有一些组件被发布给公众，比如**taskverse**。这将在本章后面讨论，并提供下载链接。它使用一些非常实用的技术来检测几乎任何类型的内核感染。该软件基于我原始作品的想法，名为 Kernel Detective，该作品设计于 2009 年，对于好奇的人，仍然可以在我的网站上找到[`www.bitlackeys.org/#kerneldetective`](http://www.bitlackeys.org/#kerneldetective)。

这个软件只适用于旧的 32 位 Linux 内核（2.6.0 到 2.6.32）；64 位支持只完成了部分。然而，这个项目的一些想法是永恒的，我最近提取了它们，并结合了一些新的想法。结果就是 Kernel Voodoo，一个依赖于/proc/kcore 进行高级内存获取和分析的主机入侵检测系统和内核取证软件。在本章中，我们将讨论它使用的一些基本技术，并在某些情况下，我们将使用 GDB 和/proc/kcore 手动进行操作。

# - 标准 vmlinux 没有符号

除非您自己编译了内核，否则您将无法直接访问 vmlinux，它是一个 ELF 可执行文件。相反，您将在`/boot`中有一个压缩的内核，通常命名为`vmlinuz-<kernel_version>`。这个压缩的内核镜像可以被解压缩，但结果是一个没有符号表的内核可执行文件。这对于取证分析师或使用 GDB 进行内核调试来说是一个问题。在这种情况下，大多数人的解决方案是希望他们的 Linux 发行版有一个带有调试符号的内核版本的特殊软件包。如果是这样，他们可以从发行库中下载一个带有符号的内核副本。然而，在许多情况下，这是不可能的，或者由于某种原因不方便。尽管如此，这个问题可以通过我在 2014 年设计和发布的一个自定义实用程序来解决。这个工具叫做**kdress**，因为它装饰了内核符号表。

实际上，它是以 Michael Zalewskis 的一个旧工具 dress 命名的。那个工具会给一个静态可执行文件添加一个符号表。这个名字源于人们运行一个叫做**strip**的程序来从可执行文件中删除符号，因此"装饰"是一个重建符号表的工具的合适名字。我们的工具 kdress 只是从`System.map`文件或`/proc/kallsyms`中获取符号的信息，然后通过为符号表创建一个段头将该信息重建到内核可执行文件中。这个工具可以在我的 GitHub 个人资料中找到[`github.com/elfmaster/kdress`](https://github.com/elfmaster/kdress)。

## 使用 kdress 构建适当的 vmlinux

以下是一个示例，展示了如何使用 kdress 实用程序构建一个可以在 GDB 中加载的 vmlinux 镜像：

```
Usage: ./kdress vmlinuz_input vmlinux_output <system.map>

$ ./kdress /boot/vmlinuz-`uname -r` vmlinux /boot/System.map-`uname -r`
[+] vmlinux has been successfully extracted
[+] vmlinux has been successfully instrumented with a complete ELF symbol table.
```

该实用程序已创建一个名为 vmlinux 的输出文件，其中包含完全重建的符号表。例如，如果我们想要在内核中定位`sys_call_table`，那么我们可以很容易地找到它：

```
$ readelf -s vmlinux | grep sys_call_table
 34214: ffffffff81801460  4368 OBJECT  GLOBAL DEFAULT    4 sys_call_table
 34379: ffffffff8180c5a0  2928 OBJECT  GLOBAL DEFAULT    4 ia32_sys_call_table
```

具有符号的内核镜像对于调试和取证分析都非常重要。几乎所有对 Linux 内核的取证都可以通过 GDB 和`/proc/kcore`完成。

# /proc/kcore 和 GDB 探索

`/proc/kcore`技术是访问内核内存的接口，以 ELF 核心文件的形式方便地使用 GDB 进行导航。

使用 GDB 和`/proc/kcore`是一种无价的技术，可以扩展到熟练分析师的深入取证。以下是一个简短的示例，展示了如何导航`sys_call_table`。

## 导航 sys_call_table 的示例

```
$ sudo gdb -q vmlinux /proc/kcore
Reading symbols from vmlinux...
[New process 1]
Core was generated by `BOOT_IMAGE=/vmlinuz-3.16.0-49-generic root=/dev/mapper/ubuntu--vg-root ro quiet'.
#0  0x0000000000000000 in ?? ()
(gdb) print &sys_call_table
$1 = (<data variable, no debug info> *) 0xffffffff81801460 <sys_call_table>
(gdb) x/gx &sys_call_table
0xffffffff81801460 <sys_call_table>:  0xffffffff811d5260
(gdb) x/5i 0xffffffff811d5260
   0xffffffff811d5260 <sys_read>:  data32 data32 data32 xchg %ax,%ax
   0xffffffff811d5265 <sys_read+5>:  push   %rbp
   0xffffffff811d5266 <sys_read+6>:  mov    %rsp,%rbp
   0xffffffff811d5269 <sys_read+9>:  push   %r14
   0xffffffff811d526b <sys_read+11>:mov    %rdx,%r14
```

在这个例子中，我们可以查看`sys_call_table[0]`中保存的第一个指针，并确定它包含了系统调用函数`sys_read`的地址。然后我们可以查看该系统调用的前五条指令。这是一个例子，说明使用 GDB 和`/proc/kcore`轻松导航内核内存。如果已经安装了钩住`sys_read`的内核 rootkit，并使用了函数 trampolines，那么显示前几条指令将显示跳转或返回到另一个恶意函数。如果您知道要查找什么，使用调试器来检测内核 rootkit 非常有用。Linux 内核的结构细微差别以及可能被感染的方式是高级主题，对许多人来说似乎是神秘的。一章不足以完全揭开所有这些，但我们将涵盖可能用于感染内核和检测感染的方法。在接下来的章节中，我将从一般的角度讨论一些用于感染内核的方法，并给出一些例子。

### 注意

只使用 GDB 和`/proc/kcore`，就可以检测到本章中提到的每一种感染。像内核 Voodoo 这样的工具非常好用方便，但并不是绝对必要的，可以检测到与正常运行的内核有所不同。

# 直接 sys_call_table 修改

传统的内核 rootkit，如**adore**和**phalanx**，通过覆盖`sys_call_table`中的指针，使它们指向替代函数，然后根据需要调用原始系统调用来工作。这是通过 LKM 或通过`/dev/kmem`或`/dev/mem`修改内核的程序来实现的。在今天的 Linux 系统中，出于安全原因，这些可写的内存窗口已被禁用，或者根据内核的配置，除了读操作外，不再能够进行任何操作。还有其他方法试图防止这种感染，例如将`sys_call_table`标记为`const`，以便它存储在文本段的`.rodata`部分。这可以通过将相应的**PTE**（Page Table Entry 的缩写）标记为可写，或者通过禁用`cr0`寄存器中的写保护位来绕过。因此，这种类型的感染是一种非常可靠的制作 rootkit 的方法，但也非常容易被检测到。

## 检测`sys_call_table`的修改

要检测`sys_call_table`的修改，可以查看`System.map`文件或`/proc/kallsyms`，以查看每个系统调用的内存地址。例如，如果我们想要检测`sys_write`系统调用是否被感染，我们需要了解`sys_write`的合法地址及其在`sys_call_table`中的索引，然后使用 GDB 和`/proc/kcore`验证正确的地址是否实际存储在内存中。

### 验证系统调用完整性的示例

```
$ sudo grep sys_write /proc/kallsyms
ffffffff811d5310 T sys_write
$ grep _write /usr/include/x86_64-linux-gnu/asm/unistd_64.h
#define __NR_write 1
$ sudo gdb -q vmlinux /proc/kcore
(gdb) x/gx &sys_call_table+1
0xffffffff81801464 <sys_call_table+4>:  0x811d5310ffffffff
```

请记住，在 x86 架构上，数字是以小端存储的。`sys_call_table[1]`处的值等同于在`/proc/kallsyms`中查找的正确的`sys_write`地址。因此，我们已成功验证了`sys_write`的`sys_call_table`条目没有被篡改。

## 内核函数跳板

这种技术最初是由 Silvio Cesare 于 1998 年引入的。其想法是能够修改系统调用而无需触及`sys_call_table`，但事实上，这种技术允许钩住内核中的任何函数。因此，它非常强大。自 1998 年以来，很多事情已经发生了；内核的文本段现在不能再被修改，除非禁用`cr0`中的写保护位或修改 PTE。然而，主要问题在于，大多数现代内核使用 SMP，而内核函数跳板是不安全的，因为它们在每次调用补丁函数时使用非原子操作，比如`memcpy()`。事实证明，还有方法可以规避这个问题，使用一种我在这里不讨论的技术。真正的问题在于，内核函数跳板实际上仍在使用，因此理解它们仍然非常重要。

### 注意

修改调用原始函数的单个调用指令，使其调用替代函数，被认为是一种更安全的技术。这种方法可以用作替代函数跳板，但可能很难找到每个单独的调用，而且这通常会因内核而异。因此，这种方法不太具有可移植性。

## 函数跳板的示例

想象一下，你想劫持系统调用`SYS_write`，并且不想担心直接修改`sys_call_table`，因为这很容易被检测到。这可以通过覆盖`sys_write`代码的前 7 个字节，使用包含跳转到另一个函数的代码的存根来实现。

### 在 32 位内核上劫持 sys_write 的示例代码

```
#define SYSCALL_NR __NR_write

static char syscall_code[7];
static char new_syscall_code[7] =
"\x68\x00\x00\x00\x00\xc3"; // push $addr; ret

// our new version of sys_write
int new_syscall(long fd, void *buf, size_t len)
{
        printk(KERN_INFO "I am the evil sys_write!\n");

        // Replace the original code back into the first 6
        // bytes of sys_write (remove trampoline)

        memcpy(
       sys_call_table[SYSCALL_NR], syscall_code,
                sizeof(syscall_code)
        );

        // now we invoke the original system call with no trampoline
        ((int (*)(fd, buf, len))sys_call_table[SYSCALL_NR])(fd, buf, len);

        // Copy the trampoline back in place!
        memcpy(
                sys_call_table[SYSCALL_NR], new_syscall_code,
                sizeof(syscall_code)
        );
}

int init_module(void)
{
        // patch trampoline code with address of new sys_write
        *(long *)&new_syscall_code[1] = (long)new_syscall;

        // insert trampoline code into sys_write
        memcpy(
                syscall_code, sys_call_table[SYSCALL_NR],
                sizeof(syscall_code)
        );
        memcpy(
                sys_call_table[SYSCALL_NR], new_syscall_code,
                sizeof(syscall_code)
        );
        return 0;
}

void cleanup_module(void)
{
        // remove infection (trampoline)
        memcpy(
                sys_call_table[SYSCALL_NR], syscall_code,
                sizeof(syscall_code)
        );
}
```

这个代码示例用`push; ret`存根替换了`sys_write`的前 6 个字节，它将新的`sys_write`函数的地址推送到堆栈上并返回到它。然后新的`sys_write`函数可以做任何诡秘的事情，尽管在这个示例中我们只是向内核日志缓冲区打印一条消息。在完成了诡秘的事情之后，它必须删除跳板代码，以便调用未篡改的 sys_write，并最后将跳板代码放回原处。

## 检测函数跳板

通常，函数跳板将覆盖它们钩住的函数的过程前言的一部分（前 5 到 7 个字节）。因此，要检测内核函数或系统调用中的函数跳板，应检查前 5 到 7 个字节，并寻找跳转或返回到另一个地址的代码。这样的代码可以有各种形式。以下是一些示例。

### 使用 ret 指令的示例

将目标地址推送到堆栈上并返回到它。当使用 32 位目标地址时，这需要 6 个字节的机器代码：

```
push $address
ret
```

### 使用间接 jmp 的示例

将目标地址移入寄存器以进行间接跳转。当使用 32 位目标地址时，这需要 7 个字节的代码：

```
movl $addr, %eax
jmp *%eax
```

### 使用相对 jmp 的示例

计算偏移量并执行相对跳转。当使用 32 位偏移量时，这需要 5 个字节的代码：

```
jmp offset
```

例如，如果我们想要验证`sys_write`系统调用是否已经被函数跳板钩住，我们可以简单地检查它的代码，看看过程前言是否还在原位：

```
$ sudo grep sys_write /proc/kallsyms
0xffffffff811d5310
$ sudo gdb -q vmlinux /proc/kcore
Reading symbols from vmlinux...
[New process 1]
Core was generated by `BOOT_IMAGE=/vmlinuz-3.16.0-49-generic root=/dev/mapper/ubuntu--vg-root ro quiet'.
#0  0x0000000000000000 in ?? ()
(gdb) x/3i 0xffffffff811d5310
   0xffffffff811d5310 <sys_write>:  data32 data32 data32 xchg %ax,%ax
   0xffffffff811d5315 <sys_write+5>:  push   %rbp
   0xffffffff811d5316 <sys_write+6>:  mov    %rsp,%rbp
```

前 5 个字节实际上用作 NOP 指令以进行对齐（或可能是 ftrace 探针的空间）。内核使用某些字节序列（0x66、0x66、0x66、0x66 和 0x90）。过程前言代码跟随最初的 5 个 NOP 字节，并且完全完整。因此，这验证了`sys_write`系统调用没有被任何函数跳板钩住。

### 中断处理程序修补- int 0x80, syscall

感染内核的一个经典方法是将一个虚假的系统调用表插入内核内存，并修改负责调用系统调用的顶半部中断处理程序。在 x86 架构中，中断 0x80 已经被弃用，并已被用特殊的`syscall/sysenter`指令替换，用于调用系统调用。syscall/sysenter 和`int 0x80`最终都会调用同一个函数，名为`system_call()`，它又调用`sys_call_table`中选择的系统调用。

```
(gdb) x/i system_call_fastpath+19
0xffffffff8176ea86 <system_call_fastpath+19>:  
callq  *-0x7e7feba0(,%rax,8)

```

在 x86_64 上，在`system_call()`中的 swapgs 之后发生前面的 call 指令。以下是`entry.S`中代码的样子：

```
call *sys_call_table(,%rax,8)

```

`(r/e)ax`寄存器包含被`sizeof(long)`乘以以获取正确系统调用指针的索引的系统调用号。很容易想象，攻击者可以`kmalloc()`一个虚假的系统调用表到内存中（其中包含一些指向恶意函数的修改），然后修补调用指令，以便使用虚假的系统调用表。这种技术实际上非常隐秘，因为它对原始的`sys_call_table`没有任何修改。然而，对于训练有素的人来说，这种技术仍然很容易检测到。

## 检测中断处理程序的修补

要检测`system_call()`例程是否已经被修补为调用虚假的`sys_call_table`，只需使用 GDB 和`/proc/kcore`反汇编代码，然后找出调用偏移是否指向`sys_call_table`的地址。正确的`sys_call_table`地址可以在`System.map`或`/proc/kallsyms`中找到。

# Kprobe rootkits

这种特定类型的内核 rootkit 最初是在 2010 年我写的一篇 Phrack 论文中详细构想和描述的。该论文可以在[`phrack.org/issues/67/6.html`](http://phrack.org/issues/67/6.html)找到。

这种类型的内核 rootkit 是比较奇特的品牌之一，它使用 Linux 内核的 Kprobe 调试钩子在 rootkit 试图修改的目标内核函数上设置断点。这种特定的技术有其局限性，但它可以非常强大和隐蔽。然而，就像其他任何技术一样，如果分析人员知道要寻找什么，那么使用 kprobes 的内核 rootkit 就可以很容易地被检测到。

## 检测 kprobe rootkit

通过分析内存来检测 kprobes 的存在非常容易。当设置常规 kprobe 时，会在函数的入口点（参见 jprobes）或任意指令上设置断点。通过扫描整个代码段寻找断点来检测是非常容易的，因为除了为了 kprobes 而设置断点外，没有其他原因应该在内核代码中设置断点。对于检测优化过的 kprobes，会使用 jmp 指令而不是断点（`int3`）指令。当 jmp 放置在函数的第一个字节上时，这是最容易检测的，因为那显然是不合适的。最后，在`/sys/kernel/debug/kprobes/list`中有一个活跃的 kprobes 简单列表，其中实际包含正在使用的 kprobes 的列表。然而，任何 rootkit，包括我在 phrack 中演示的 rootkit，都会隐藏其 kprobes，所以不要依赖它。一个好的 rootkit 还会阻止在`/sys/kernel/debug/kprobes/enabled`中禁用 kprobes。

# 调试寄存器 rootkit – DRR

这种类型的内核 rootkit 使用 Intel Debug 寄存器来劫持控制流。 *halfdead*在这种技术上写了一篇很棒的 Phrack 论文。它可以在这里找到：

[`phrack.org/issues/65/8.html`](http://phrack.org/issues/65/8.html)。

这种技术通常被誉为超级隐蔽，因为它不需要修改`sys_call_table`。然而，同样地，也有方法来检测这种类型的感染。

## 检测 DRR

在许多 rootkit 实现中，`sys_call_table`和其他常见的感染点确实没有被修改，但`int1`处理程序没有。对`do_debug`函数的调用指令被修改为调用另一个`do_debug`函数，如前面链接的 phrack 论文所示。因此，检测这种类型的 rootkit 通常就像反汇编 int1 处理程序并查看`call do_debug`指令的偏移一样简单，如下所示：

```
target_address = address_of_call + offset + 5
```

如果`target_address`的值与`System.map`或`/proc/kallsyms`中找到的`do_debug`地址相同，则意味着 int1 处理程序未被修改，被视为干净的。

# VFS 层 rootkit

感染内核的另一个经典而强大的方法是通过感染内核的 VFS 层。这种技术非常出色和隐蔽，因为它在技术上修改了内存中的数据段而不是文本段，而后者更容易检测到不一致。VFS 层是非常面向对象的，包含各种带有函数指针的结构。这些函数指针是文件系统操作，如打开、读取、写入、读取目录等。如果攻击者可以修改这些函数指针，那么他们可以以任何他们认为合适的方式控制这些操作。

## 检测 VFS 层 rootkit

可能有几种技术可以用来检测这种类型的感染。然而，一般的想法是验证函数指针地址，并确认它们指向预期的函数。在大多数情况下，这些应该指向内核中的函数，而不是存在于 LKMs 中的函数。检测的一个快速方法是验证指针是否在内核的文本段范围内。

### 验证 VFS 函数指针的一个例子

```
if ((long)vfs_ops->readdir >= KERNEL_MIN_ADDR &&
    (long)vfs_ops->readdir < KERNEL_MAX_ADDR)
        pointer_is_valid = 1;
else
        pointer_is_valid = 0;
```

# 其他内核感染技术

黑客可以使用其他技术来感染 Linux 内核（我们在本章中没有讨论这些技术），比如劫持 Linux 页面错误处理程序（[`phrack.org/issues/61/7.html`](http://phrack.org/issues/61/7.html)）。许多这些技术可以通过查找对文本段的修改来检测，这是我们将在接下来的章节中进一步研究的检测方法。

# vmlinux 和.altinstructions 补丁

在我看来，检测 rootkit 最有效的方法可以通过验证内核内存中的代码完整性来概括，换句话说，就是将内核内存中的代码与预期的代码进行比较。但是我们可以将内核内存代码与什么进行比较呢？嗯，为什么不是 vmlinux 呢？这是我最初在 2008 年探索的一种方法。知道 ELF 可执行文件的文本段从磁盘到内存不会改变，除非它是一些奇怪的自修改二进制文件，而内核不是……或者它是吗？我很快遇到了麻烦，并发现内核内存文本段和 vmlinux 文本段之间存在各种代码差异。这一开始让我感到困惑，因为在这些测试期间我没有安装任何内核 rootkit。然而，在检查了 vmlinux 中的一些 ELF 部分后，我很快发现了一些引起我的注意的地方：

```
$ readelf -S vmlinux | grep alt
  [23] .altinstructions  PROGBITS         ffffffff81e64528  01264528
  [24] .altinstr_replace PROGBITS         ffffffff81e6a480  0126a480
```

Linux 内核二进制文件中有几个部分包含了替代指令。事实证明，Linux 内核开发人员有一个聪明的想法：如果 Linux 内核可以智能地在运行时修补自己的代码段，根据检测到的特定 CPU 改变某些指令以进行“内存屏障”，这将是一个好主意，因为更少的标准内核需要为所有不同类型的 CPU 创建。不幸的是，对于想要检测内核代码段中的任何恶意更改的安全研究人员来说，这些替代指令首先需要被理解和应用。

## .altinstructions 和 .altinstr_replace

有两个部分包含了大部分需要知道的信息，即内核中哪些指令在运行时被修补。现在有一篇很好的文章解释了这些部分，这在我早期研究这一内核领域时是不可用的。

[`lwn.net/Articles/531148/`](https://lwn.net/Articles/531148/)

然而，总体思路是，`.altinstructions` 部分包含一个 `struct alt_instr` 结构的数组。每个结构代表一个替代指令记录，给出了应该用于修补原始指令的新指令的位置。`.altinstr_replace` 部分包含了实际的替代指令，这些指令由 `alt_instr->repl_offset` 成员引用。

## 来自 arch/x86/include/asm/alternative.h

```
struct alt_instr {
   s32 instr_offset;      /* original instruction */
   s32 repl_offset;       /* offset to replacement instruction */
   u16 cpuid;             /* cpuid bit set for replacement */
   u8  instrlen;          /* length of original instruction */
   u8  replacementlen;    /* length of new instruction, <= instrlen */
};
```

在旧内核上，前两个成员给出了旧指令和新指令的绝对地址，但在新内核上，使用了相对偏移量。

## 使用 textify 来验证内核代码完整性

多年来，我设计了几个工具，用于检测 Linux 内核代码段的完整性。这种检测技术显然只对修改文本段的内核 rootkit 有效，而大多数内核 rootkit 在某种程度上都会这样做。但是，也有一些例外，例如仅依赖于修改 VFS 层的 rootkit，它位于数据段中，不会通过验证文本段的完整性来检测到。最近，我编写的工具（内核 Voodoo 软件套件的一部分）名为 textify，它基本上比较了从`/proc/kcore`中获取的内核内存的文本段与 vmlinux 中的文本段。它解析`.altinstructions`和其他各种部分，例如`.parainstructions`，以了解合法修补的代码指令的位置。通过这种方式，不会出现错误的阳性。尽管 textify 目前不向公众开放，但一般思路已经解释过。因此，任何希望尝试使其工作的人都可以重新实现它，尽管这需要一些繁琐的编码过程。

## 使用 textify 检查 sys_call_table 的示例

```
# ./textify vmlinux /proc/kcore -s sys_call_table
kernel Detective 2014 - Bitlackeys.org
[+] Analyzing kernel code/data for symbol sys_call_table in range [0xffffffff81801460 - 0xffffffff81802570]
[+] No code modifications found for object named 'sys_call_table'

# ./textify vmlinux /proc/kcore -a
kernel Detective 2014 - Bitlackeys.org
[+] Analyzing kernel code of entire text segment. [0xffffffff81000000 - 0xffffffff81773da4]
[+] No code modifications have been detected within kernel memory
```

在上面的示例中，我们首先检查`sys_call_table`是否已被修改。在现代 Linux 系统上，`sys_call_table`被标记为只读，因此存储在文本段中，这就是为什么我们可以使用 textify 来验证其完整性。在下一个命令中，我们使用`-a`开关运行 textify，该开关扫描整个文本段中的每个字节，以查找非法修改。我们本可以直接运行`-a`，因为`sys_call_table`包含在`-a`中，但有时，按符号名称扫描东西也很好。

# 使用 taskverse 查看隐藏进程

在 Linux 内核中，有几种修改内核的方法，以便进程隐藏可以工作。由于本章不是要对所有内核 rootkit 进行详细解释，我只会介绍最常用的方法，然后提出一种检测方法，这种方法已经在我 2014 年发布的 taskverse 程序中实现。

在 Linux 中，进程 ID 存储为`/proc`文件系统中的目录；每个目录包含有关进程的大量信息。`/bin/ps`程序在`/proc`中进行目录列表，以查看系统上当前正在运行的 pid。Linux 中的目录列表（例如使用`ps`或`ls`）使用`sys_getdents64`系统调用和`filldir64`内核函数。许多内核 rootkit 劫持其中一个这些函数（取决于内核版本），然后插入一些代码，跳过包含隐藏进程的`d_name`的目录条目。因此，`/bin/ps`程序无法找到内核 rootkit 认为在目录列表中跳过的进程。

## Taskverse 技术

taskverse 程序是内核 Voodoo 软件包的一部分，但我发布了一个更基本的免费版本，只使用一种技术来检测隐藏进程；但是，这种技术仍然非常有用。正如我们刚才讨论的，rootkit 通常会隐藏`/proc`中的 pid 目录，以便`sys_getdents64`和`filldir64`无法看到它们。用于查看这些进程的最直接和明显的方法是完全绕过/proc 目录，并在内核内存中的任务列表中查看由`struct task_struct`条目的链接列表表示的每个进程描述符。可以通过查找`init_task`符号找到列表指针的头部。有一定技能的程序员可以利用这些知识打开`/proc/kcore`并遍历任务列表。此代码的详细信息可以在项目本身中查看，该项目可以在我的 GitHub 个人资料上找到[`github.com/elfmaster/taskverse`](https://github.com/elfmaster/taskverse)。

# 感染的 LKMs-内核驱动程序

到目前为止，我们已经涵盖了内存中各种类型的内核 rootkit 感染，但我认为这一章节需要专门解释攻击者如何感染内核驱动程序，以及如何检测这些感染。

## 方法 1 感染 LKM 文件的方法-符号劫持

LKMs 是 ELF 对象。更具体地说，它们是`ET_REL`文件（目标文件）。由于它们实际上只是可重定位代码，因此感染它们的方式（如劫持函数）更有限。幸运的是，在加载 ELF 内核对象的过程中，会发生一些特定于内核的机制，即在 LKM 内重定位函数的过程，这使得感染它们变得非常容易。整个方法及其原因在这篇精彩的 phrack 论文中有详细描述：[`phrack.org/issues/68/11.html`](http://phrack.org/issues/68/11.html)，但总体思路很简单：

1.  将寄生虫代码注入或链接到内核模块中。

1.  更改`init_module()`的符号值，使其具有与恶意替换函数相同的偏移/值。

这是攻击者在现代 Linux 系统（2.6 到 3.x 内核）上最常用的方法。还有另一种方法，其他地方没有具体描述，我会简要分享一下。

## 方法 2 感染 LKM 文件（函数劫持）

LKM 文件是可重定位代码，如前所述，因此非常容易添加代码，因为寄生虫可以用 C 编写，然后在链接之前编译为可重定位代码。在链接新的寄生虫代码之后，攻击者可以使用函数跳板简单地劫持 LKM 中的任何函数，就像本章节早期描述的那样。因此，攻击者用新函数替换目标函数的前几个字节。新函数然后将原始字节复制到旧函数中，然后调用它，并将跳板复制回原来的位置，以便下次调用钩子时使用。

### 注意

在较新的系统上，在对文本段进行补丁之前，必须禁用写保护位，例如使用`memcpy()`调用来实现函数跳板。

## 检测感染的 LKM

基于刚刚描述的两种简单检测方法，解决这个问题的方法似乎是显而易见的。对于符号劫持方法，您可以简单地查找具有相同值的两个符号。在 Phrack 文章中显示的示例中，`init_module()`函数被劫持，但该技术应该适用于攻击者想要劫持的任何函数。这是因为内核为每个函数处理重定位（尽管我尚未测试过这个理论）：

```
$ objdump -t infected.lkm
00000040 g     F .text  0000001b evil
...
00000040 g     F .text  0000001b init_module
```

请注意，在前面的符号输出中，`init_module`和`evil`具有相同的相对地址。这就是 Phrack 68 #11 中演示的感染 LKM。检测使用跳板劫持的函数也非常简单，并且已经在第 9.6.3 节中描述过，在那里我们讨论了在内核中检测跳板的方法。只需将相同的分析应用于 LKM 文件中的函数，可以使用诸如 objdump 之类的工具对其进行反汇编。

# 关于/dev/kmem 和/dev/mem 的注意事项

在过去，黑客可以使用/dev/kmem 设备文件修改内核。这个文件为程序员提供了一个对内核内存的原始入口，最终受到各种安全补丁的影响，并从许多发行版中删除。但是，一些发行版仍然可以从中读取，这可以成为检测内核恶意软件的强大工具，但只要/proc/kcore 可用即可。有关修补 Linux 内核的最佳工作之一是由 Silvio Cesare 构思的，可以在他 1998 年的早期著作中看到，并且可以在 vxheaven 或此链接中找到：

+   *运行时内核 kmem 补丁*：[`althing.cs.dartmouth.edu/local/vsc07.html`](http://althing.cs.dartmouth.edu/local/vsc07.html)

# /dev/mem

有一些内核 rootkit 使用了/dev/mem，即由 Rebel 编写的 phalanx 和 phalanx2。这个设备也经历了一些安全补丁。目前，它在所有系统上都存在以实现向后兼容性，但只有前 1MB 的内存是可访问的，主要用于 X Windows 使用的传统工具。

## FreeBSD /dev/kmem

在一些操作系统（如 FreeBSD）中，/dev/kmem 设备仍然可用，并且默认情况下是可写的。甚至还有一个专门设计用于访问它的 API，还有一本名为*Writing BSD rootkits*的书展示了它的能力。

# K-ecfs – 内核 ECFS

在上一章中，我们讨论了**ECFS**（**扩展核心文件快照**）技术。值得一提的是，在本章末尾，我已经为 kernel-ecfs 编写了一些代码，将 vmlinux 和`/proc/kcore`合并到一个 kernel-ecfs 文件中。结果实质上是一个类似于/proc/kcore 的文件，但它还具有段头和符号。通过这种方式，分析人员可以轻松访问内核、LKMs 和内核内存（如“vmalloc'd”内存）的任何部分。这些代码最终将公开可用。

## 内核-ecfs 文件的一瞥

在这里，我们展示了如何将`/proc/kcore`快照到一个名为`kcore.img`的文件中，并给出了一组 ELF 段头：

```
# ./kcore_ecfs kcore.img

# readelf -S kcore.img
here are 6 section headers, starting at offset 0x60404afc:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note             NULL             0000000000000000  000000e8
       0000000000001a14  000000000000000c           0    48     0
  [ 2] .kernel           PROGBITS         ffffffff81000000  01001afc
       0000000001403000  0000000000000000 WAX       0     0     0
  [ 3] .bss              PROGBITS         ffffffff81e77000  00000000
       0000000000169000  0000000000000000  WA       0     0     0
  [ 4] .modules          PROGBITS         ffffffffa0000000  01404afc
       000000005f000000  0000000000000000 WAX       0     0     0
  [ 5] .shstrtab         STRTAB           0000000000000000  60404c7c
       0000000000000026  0000000000000000           0     0     0

# readelf -s kcore.img | grep sys_call_table
 34214: ffffffff81801460  4368 OBJECT 4 sys_call_table
 34379: ffffffff8180c5a0  2928 OBJECT 4 ia32_sys_call_table
```

# 内核黑客好东西

Linux 内核是关于取证分析和逆向工程的广泛主题。有许多令人兴奋的方法可以用于对内核进行仪器化，以进行黑客攻击、逆向和调试，Linux 为用户提供了许多进入这些领域的入口。我在本章中讨论了一些在研究中有用的文件和 API，但我也将列出一些可能对您的研究有帮助的小而简洁的清单。

## 一般逆向工程和调试

+   `/proc/kcore`

+   `/proc/kallsyms`

+   `/boot/System.map`

+   `/dev/mem`（已弃用）

+   `/dev/kmem`（已弃用）

+   GNU 调试器（与 kcore 一起使用）

## 高级内核黑客/调试接口

+   Kprobes

+   Ftrace

## 本章提到的论文

+   Kprobe 仪器：[`phrack.org/issues/67/6.html`](http://phrack.org/issues/67/6.html)

+   *运行时内核* *kmem 修补*：[`althing.cs.dartmouth.edu/local/vsc07.html`](http://althing.cs.dartmouth.edu/local/vsc07.html)

+   LKM 感染：[`phrack.org/issues/68/11.html`](http://phrack.org/issues/68/11.html)

+   *Linux 二进制文件中的特殊部分*：[`lwn.net/Articles/531148/`](https://lwn.net/Articles/531148/)

+   内核巫术：[`www.bitlackeys.org/#ikore`](http://www.bitlackeys.org/#ikore)

# 总结

在本书的最后一章中，我们走出了用户空间二进制文件，对内核中使用的 ELF 二进制文件类型进行了一般性的介绍，以及如何利用它们与 GDB 和`/proc/kcore`进行内存分析和取证目的。我们还解释了一些常见的 Linux 内核 rootkit 技术以及可以应用于检测它们的方法。这个小章节只是作为理解基础知识的主要资源，但我们列出了一些优秀的资源，以便您可以继续扩展您在这个领域的知识。
