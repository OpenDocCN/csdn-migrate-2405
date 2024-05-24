# C++ 专家编程（五）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：调试多线程代码

理想情况下，一个人的代码第一次就能正常工作，并且不包含等待崩溃应用程序、损坏数据或引起其他问题的隐藏错误。现实情况当然是不可能的。因此，开发了一些工具，使得检查和调试多线程应用程序变得容易。

在本章中，我们将研究其中一些内容，包括常规调试器以及 Valgrind 套件的一些工具，特别是 Helgrind 和 DRD。我们还将研究如何对多线程应用程序进行分析，以查找设计中的热点和潜在问题。

本章涵盖的主题包括以下内容：

+   介绍 Valgrind 工具套件

+   使用 Helgrind 和 DRD 工具

+   解释 Helgrind 和 DRD 分析结果

+   对应用程序进行分析和分析结果

# 何时开始调试

理想情况下，每次达到特定里程碑时，无论是针对单个模块、多个模块还是整个应用程序，都应该测试和验证自己的代码。重要的是要确定自己的假设是否与最终功能相匹配。

特别是在多线程代码中，一个特定的错误状态在每次运行应用程序时都不能保证达到。实现不当的多线程应用程序可能会导致诸如看似随机崩溃等症状。

当应用程序崩溃并留下核心转储时，人们可能会得到的第一个提示是，某些地方出了问题。这是一个包含应用程序在崩溃时的内存内容的文件，包括堆栈。

这个核心转储可以以几乎与运行进程调试器相同的方式使用。检查我们崩溃的代码位置以及线程位置特别有用。我们也可以通过这种方式检查内存内容。

处理多线程问题的最佳指标之一是应用程序在不同位置从不崩溃（不同的堆栈跟踪），或者总是在执行互斥操作的地方崩溃，例如操作全局数据结构。

首先，我们将更深入地研究使用调试器进行诊断和调试，然后再深入研究 Valgrind 工具套件。

# 谦逊的调试器

开发人员可能会有许多问题，其中“为什么我的应用程序刚刚崩溃？”可能是最重要的问题之一。这也是调试器最容易回答的问题之一。无论是实时调试进程还是分析崩溃进程的核心转储，调试器都可以（希望）生成回溯，也称为堆栈跟踪。此跟踪包含自应用程序启动以来调用的所有函数的时间顺序列表，就像它们在堆栈上一样（有关堆栈工作原理的详细信息，请参见第九章，*处理器和操作系统上的多线程实现*）。

因此，回溯的最后几个条目将向我们显示代码的哪个部分出了问题。如果调试信息已编译到二进制文件中，或者提供给调试器，我们还可以看到该行的代码以及变量的名称。

更好的是，由于我们正在查看堆栈帧，我们还可以检查该堆栈帧中的变量。这意味着传递给函数的参数以及任何局部变量和它们的值。

为了使调试信息（符号）可用，必须使用适当的编译器标志编译源代码。对于 GCC，可以选择一系列调试信息级别和类型。通常，会使用`-g`标志并附加一个指定调试级别的整数，如下所示：

+   `-g0`：不生成调试信息（否定`-g`）

+   `-g1`：有关函数描述和外部变量的最少信息

+   `-g3`：包括宏定义在内的所有信息

这个标志指示 GCC 以 OS 的本机格式生成调试信息。也可以使用不同的标志以特定格式生成调试信息；然而，这对于与 GCC 的调试器（GDB）以及 Valgrind 工具一起使用并不是必需的。

GDB 和 Valgrind 都将使用这些调试信息。虽然在没有调试信息的情况下使用它们是技术上可能的，但最好留给真正绝望的时候来练习。

# GDB

用于基于 C 和基于 C++的代码的最常用的调试器之一是 GNU 调试器，简称 GDB。在下面的例子中，我们将使用这个调试器，因为它被广泛使用并且免费提供。最初于 1986 年编写，现在与各种编程语言一起使用，并且已成为个人和专业使用中最常用的调试器。

GDB 最基本的接口是一个命令行 shell，但它也可以与图形前端一起使用，其中还包括一些 IDE，如 Qt Creator、Dev-C++和 Code::Blocks。这些前端和 IDE 可以使管理断点、设置监视变量和执行其他常见操作变得更容易和更直观。然而，并不需要使用它们。

在 Linux 和 BSD 发行版上，gdb 可以很容易地从软件包中安装，就像在 Windows 上使用 MSYS2 和类似的类 UNIX 环境一样。对于 OS X/MacOS，可能需要使用 Homebrew 等第三方软件包管理器安装 gdb。

由于 gdb 在 MacOS 上通常没有代码签名，因此无法获得正常操作所需的系统级访问权限。在这里，可以以 root 身份运行 gdb（不建议），或者按照与您的 MacOS 版本相关的教程。 

# 调试多线程代码

如前所述，有两种方法可以使用调试器，一种是从调试器内启动应用程序（或附加到正在运行的进程），另一种是加载核心转储文件。在调试会话中，可以中断运行的进程（使用*Ctrl*+*C*，发送`SIGINT`信号），或者加载加载的核心转储的调试符号。之后，我们可以检查这个框架中的活动线程：

```cpp
Thread 1 received signal SIGINT, Interrupt.
0x00007fff8a3fff72 in mach_msg_trap () from /usr/lib/system/libsystem_kernel.dylib
(gdb) info threads
Id   Target Id         Frame 
* 1    Thread 0x1703 of process 72492 0x00007fff8a3fff72 in mach_msg_trap () from /usr/lib/system/libsystem_kernel.dylib
3    Thread 0x1a03 of process 72492 0x00007fff8a406efa in kevent_qos () from /usr/lib/system/libsystem_kernel.dylib
10   Thread 0x2063 of process 72492 0x00007fff8a3fff72 in mach_msg_trap () from /usr/lib/system/libsystem_kernel.dylibs
14   Thread 0x1e0f of process 72492 0x00007fff8a405d3e in __pselect () from /usr/lib/system/libsystem_kernel.dylib
(gdb) c
Continuing.

```

在上述代码中，我们可以看到在向应用程序发送`SIGINT`信号之后（一个在 OS X 上运行的基于 Qt 的应用程序），我们请求此时存在的所有线程的列表，以及它们的线程号、ID 和它们当前正在执行的函数。这也清楚地显示了根据后者信息，哪些线程可能正在等待，这在像这样的图形用户界面应用程序中经常发生。在这里，我们还可以看到当前活动的线程，由其编号前的星号标记（线程 1）。

我们还可以使用`thread <ID>`命令随意在线程之间切换，并在线程的堆栈帧之间移动`up`和`down`。这使我们能够检查每个线程的每个方面。

当完整的调试信息可用时，通常还会看到线程正在执行的确切代码行。这意味着在应用程序的开发阶段，有尽可能多的调试信息可用是有意义的，以使调试变得更容易。

# 断点

对于我们在第四章中查看的调度器代码，*线程同步和通信*，我们可以设置一个断点，以便我们可以检查活动线程：

```cpp
$ gdb dispatcher_demo.exe 
GNU gdb (GDB) 7.9 
Copyright (C) 2015 Free Software Foundation, Inc. 
Reading symbols from dispatcher_demo.exe...done. 
(gdb) break main.cpp:67 
Breakpoint 1 at 0x4017af: file main.cpp, line 67\. 
(gdb) run 
Starting program: dispatcher_demo.exe 
[New Thread 10264.0x2a90] 
[New Thread 10264.0x2bac] 
[New Thread 10264.0x2914] 
[New Thread 10264.0x1b80] 
[New Thread 10264.0x213c] 
[New Thread 10264.0x2228] 
[New Thread 10264.0x2338] 
[New Thread 10264.0x270c] 
[New Thread 10264.0x14ac] 
[New Thread 10264.0x24f8] 
[New Thread 10264.0x1a90] 
```

正如我们在上面的命令行输出中所看到的，我们以应用程序的名称作为参数启动 GDB，这里是在 Windows 下的 Bash shell 中。之后，我们可以在这里设置一个断点，使用源文件的文件名和我们希望在(gdb)后面中断的行号作为 gdb 命令行输入。我们选择在发送请求给调度程序的循环之后的第一行，然后运行应用程序。这之后是由 GDB 报告的调度程序创建的新线程的列表。

接下来，我们等待直到断点被触发：

```cpp
Breakpoint 1, main () at main.cpp:67 
67              this_thread::sleep_for(chrono::seconds(5)); 
(gdb) info threads 
Id   Target Id         Frame 
11   Thread 10264.0x1a90 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
10   Thread 10264.0x24f8 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
9    Thread 10264.0x14ac 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
8    Thread 10264.0x270c 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
7    Thread 10264.0x2338 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
6    Thread 10264.0x2228 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
5    Thread 10264.0x213c 0x00000000775ec2ea in ntdll!ZwWaitForMultipleObjects () from /c/Windows/SYSTEM32/ntdll.dll 
4    Thread 10264.0x1b80 0x0000000064942eaf in ?? () from /mingw64/bin/libwinpthread-1.dll 
3    Thread 10264.0x2914 0x00000000775c2385 in ntdll!LdrUnloadDll () from /c/Windows/SYSTEM32/ntdll.dll 
2    Thread 10264.0x2bac 0x00000000775c2385 in ntdll!LdrUnloadDll () from /c/Windows/SYSTEM32/ntdll.dll 
* 1    Thread 10264.0x2a90 main () at main.cpp:67 
(gdb) bt 
#0  main () at main.cpp:67 
(gdb) c 
Continuing. 
```

到达断点后，*info threads*命令列出了活动线程。在这里，我们可以清楚地看到条件变量的使用，其中一个线程在`ntdll!ZwWaitForMultipleObjects()`中等待。正如第三章中所介绍的，*C++多线程 API*，这是在 Windows 上使用其本机多线程 API 实现的条件变量。

当我们创建一个回溯(`bt`命令)时，我们可以看到线程 1(当前线程)的当前堆栈只有一个帧，只有主方法，因为我们从这个起始点没有调用其他函数。

# 回溯

在正常的应用程序执行期间，例如我们之前看过的 GUI 应用程序，向应用程序发送`SIGINT`也可以跟随着创建回溯的命令，就像这样：

```cpp
Thread 1 received signal SIGINT, Interrupt.
0x00007fff8a3fff72 in mach_msg_trap () from /usr/lib/system/libsystem_kernel.dylib
(gdb) bt
#0  0x00007fff8a3fff72 in mach_msg_trap () from /usr/lib/system/libsystem_kernel.dylib
#1  0x00007fff8a3ff3b3 in mach_msg () from /usr/lib/system/libsystem_kernel.dylib
#2  0x00007fff99f37124 in __CFRunLoopServiceMachPort () from /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
#3  0x00007fff99f365ec in __CFRunLoopRun () from /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
#4  0x00007fff99f35e38 in CFRunLoopRunSpecific () from /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
#5  0x00007fff97b73935 in RunCurrentEventLoopInMode ()
from /System/Library/Frameworks/Carbon.framework/Versions/A/Frameworks/HIToolbox.framework/Versions/A/HIToolbox
#6  0x00007fff97b7376f in ReceiveNextEventCommon ()
from /System/Library/Frameworks/Carbon.framework/Versions/A/Frameworks/HIToolbox.framework/Versions/A/HIToolbox
#7  0x00007fff97b735af in _BlockUntilNextEventMatchingListInModeWithFilter ()
from /System/Library/Frameworks/Carbon.framework/Versions/A/Frameworks/HIToolbox.framework/Versions/A/HIToolbox
#8  0x00007fff9ed3cdf6 in _DPSNextEvent () from /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
#9  0x00007fff9ed3c226 in -[NSApplication _nextEventMatchingEventMask:untilDate:inMode:dequeue:] ()
from /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
#10 0x00007fff9ed30d80 in -[NSApplication run] () from /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit
#11 0x0000000102a25143 in qt_plugin_instance () from /usr/local/Cellar/qt/5.8.0_1/plugins/platforms/libqcocoa.dylib
#12 0x0000000100cd3811 in QEventLoop::exec(QFlags<QEventLoop::ProcessEventsFlag>) () from /usr/local/opt/qt5/lib/QtCore.framework/Versions/5/QtCore
#13 0x0000000100cd80a7 in QCoreApplication::exec() () from /usr/local/opt/qt5/lib/QtCore.framework/Versions/5/QtCore
#14 0x0000000100003956 in main (argc=<optimized out>, argv=<optimized out>) at main.cpp:10
(gdb) c
Continuing.

```

在上述代码中，我们可以看到线程 ID 1 的执行从创建开始，通过入口点(main)。每个后续的函数调用都被添加到堆栈中。当一个函数结束时，它就从堆栈中移除了。这既是一个好处，也是一个缺点。虽然它确实保持了回溯的整洁，但也意味着在最后一个函数调用之前发生的历史不再存在。

如果我们使用核心转储文件创建一个回溯，没有这些历史信息可能会非常恼人，并且可能会让人在试图缩小崩溃原因的范围时陷入困境。这意味着需要一定水平的经验才能成功调试。

在应用程序崩溃的情况下，调试器会将我们带到遭受崩溃的线程上。通常，这是有问题的代码所在的线程，但也可能是真正的错误在于另一个线程执行的代码，甚至是变量的不安全使用。如果一个线程改变了另一个线程当前正在读取的信息，后者可能会得到垃圾数据。这可能导致崩溃，甚至更糟糕的是--在应用程序的后续过程中出现损坏。

最坏的情况是堆栈被覆盖，例如，被一个野指针。在这种情况下，堆栈上的缓冲区或类似的东西被写入超出其限制，从而用新数据填充它来擦除堆栈的部分。这就是缓冲区溢出，可能导致应用程序崩溃，或者(恶意)利用应用程序。

# 动态分析工具

尽管调试器的价值难以忽视，但有时需要不同类型的工具来回答关于内存使用、泄漏以及诊断或预防线程问题等问题。这就是 Valgrind 套件中的工具可以提供很大帮助的地方。作为构建动态分析工具的框架，Valgrind 发行版目前包含以下对我们感兴趣的工具：

+   内存检查

+   Helgrind

+   DRD

Memcheck 是一个内存错误检测器，它允许我们发现内存泄漏、非法读写，以及分配、释放和类似的与内存相关的问题。

Helgrind 和 DRD 都是线程错误检测器。这基本上意味着它们将尝试检测任何多线程问题，如数据竞争和互斥锁的不正确使用。它们的区别在于 Helgrind 可以检测锁定顺序的违规，而 DRD 支持分离线程，同时使用的内存比 Helgrind 少。

# 限制

动态分析工具的一个主要限制是它们需要与主机操作系统紧密集成。这是 Valgrind 专注于 POSIX 线程的主要原因，目前无法在 Windows 上运行的主要原因。

Valgrind 网站（[`valgrind.org/info/platforms.html`](http://valgrind.org/info/platforms.html)）对该问题的描述如下：

“Windows 不在考虑范围内，因为将其移植到 Windows 需要进行如此多的更改，几乎可以成为一个独立的项目。（但是，Valgrind + Wine 可以通过一些努力使其工作。）此外，非开源操作系统很难处理；能够看到操作系统和相关（libc）源代码使事情变得更容易。但是，Valgrind 与 Wine 结合使用非常方便，这意味着可以通过一些努力在 Valgrind 下运行 Windows 程序。”

基本上，这意味着可以在 Linux 下使用 Valgrind 调试 Windows 应用程序，但在短期内不太可能使用 Windows 作为操作系统。

Valgrind 可以在 OS X/macOS 上运行，从 OS X 10.8（Mountain Lion）开始。由于苹果公司的更改，对最新版本的 macOS 的支持可能会有些不完整。与 Valgrind 的 Linux 版本一样，通常最好始终使用最新版本的 Valgrind。与 gdb 一样，使用发行版的软件包管理器，或者在 MacOS 上使用 Homebrew 等第三方软件包管理器。

# 替代方案

在 Windows 和其他平台上，Valgrind 工具的替代方案包括以下表中列出的工具：

| **名称** | **类型** | **平台** | **许可证** |
| --- | --- | --- | --- |
| Dr. Memory | 内存检查器 | 所有主要平台 | 开源 |
| gperftools（Google） | 堆，CPU 和调用分析器 | Linux（x86） | 开源 |
| Visual Leak Detector | 内存检查器 | Windows（Visual Studio） | 开源 |
| Intel Inspector | 内存和线程调试器 | Windows，Linux | 专有 |
| PurifyPlus | 内存，性能 | Windows，Linux | 专有 |
| Parasoft Insure++ | 内存和线程调试器 | Windows，Solaris，Linux，AIX | 专有 |

# Memcheck

当可执行文件的参数中未指定其他工具时，Memcheck 是默认的 Valgrind 工具。Memcheck 本身是一个内存错误检测器，能够检测以下类型的问题：

+   访问超出分配边界的内存，堆栈溢出以及访问先前释放的内存块

+   使用未定义值，即未初始化的变量

+   不正确释放堆内存，包括重复释放块

+   C 和 C++风格内存分配的不匹配使用，以及数组分配器和释放器（`new[]`和`delete[]`）

+   在`memcpy`等函数中重叠源和目标指针

+   将无效值（例如负值）作为`malloc`或类似函数的大小参数传递

+   内存泄漏；即，没有任何有效引用的堆块

使用调试器或简单的任务管理器，几乎不可能检测到前面列表中给出的问题。Memcheck 的价值在于能够在开发的早期检测和修复问题，否则可能会导致数据损坏和神秘崩溃。

# 基本用法

使用 Memcheck 非常容易。如果我们使用第四章中创建的演示应用程序，*线程同步和通信*，我们知道通常我们会这样启动它：

```cpp
$ ./dispatcher_demo
```

使用默认的 Memcheck 工具运行 Valgrind，并将结果输出到日志文件中，我们可以按照以下方式启动它：

```cpp
$ valgrind --log-file=dispatcher.log --read-var-info=yes --leak-check=full ./dispatcher_demo
```

通过上述命令，我们将 Memcheck 的输出记录到一个名为 `dispatcher.log` 的文件中，并且还启用了对内存泄漏的全面检查，包括详细报告这些泄漏发生的位置，使用二进制文件中可用的调试信息。通过读取变量信息（`--read-var-info=yes`），我们可以获得更详细的关于内存泄漏发生位置的信息。

不能将日志记录到文件中，但除非是一个非常简单的应用程序，否则 Valgrind 生成的输出可能会非常多，可能无法适应终端缓冲区。将输出作为文件允许将来使用它作为参考，并使用比终端通常提供的更高级的工具进行搜索。

运行完这个之后，我们可以按以下方式检查生成的日志文件的内容：

```cpp
==5764== Memcheck, a memory error detector
==5764== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==5764== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==5764== Command: ./dispatcher_demo
==5764== Parent PID: 2838
==5764==
==5764==
==5764== HEAP SUMMARY:
==5764==     in use at exit: 75,184 bytes in 71 blocks
==5764==   total heap usage: 260 allocs, 189 frees, 88,678 bytes allocated
==5764==
==5764== 80 bytes in 10 blocks are definitely lost in loss record 1 of 5
==5764==    at 0x4C2E0EF: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==5764==    by 0x402EFD: Dispatcher::init(int) (dispatcher.cpp:40)
==5764==    by 0x409300: main (main.cpp:51)
==5764==
==5764== 960 bytes in 40 blocks are definitely lost in loss record 3 of 5
==5764==    at 0x4C2E0EF: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==5764==    by 0x409338: main (main.cpp:60)
==5764==
==5764== 1,440 (1,200 direct, 240 indirect) bytes in 10 blocks are definitely lost in loss record 4 of 5
==5764==    at 0x4C2E0EF: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==5764==    by 0x402EBB: Dispatcher::init(int) (dispatcher.cpp:38)
==5764==    by 0x409300: main (main.cpp:51)
==5764==
==5764== LEAK SUMMARY:
==5764==    definitely lost: 2,240 bytes in 60 blocks
==5764==    indirectly lost: 240 bytes in 10 blocks
==5764==      possibly lost: 0 bytes in 0 blocks
==5764==    still reachable: 72,704 bytes in 1 blocks
==5764==         suppressed: 0 bytes in 0 blocks
==5764== Reachable blocks (those to which a pointer was found) are not shown.
==5764== To see them, rerun with: --leak-check=full --show-leak-kinds=all
==5764==
==5764== For counts of detected and suppressed errors, rerun with: -v
==5764== ERROR SUMMARY: 3 errors from 3 contexts (suppressed: 0 from 0) 
```

在这里，我们可以看到总共有三个内存泄漏。其中两个是在第 38 和 40 行的 `dispatcher` 类中分配的：

```cpp
w = new Worker; 
```

另一个是：

```cpp
t = new thread(&Worker::run, w); 
```

我们还看到在 `main.cpp` 的第 60 行分配了一个泄漏：

```cpp
rq = new Request(); 
```

虽然这些分配本身没有问题，但是如果我们在应用程序生命周期中跟踪它们，我们会注意到我们从未在这些对象上调用 `delete`。如果我们要修复这些内存泄漏，我们需要在完成后删除这些 `Request` 实例，并在 `dispatcher` 类的析构函数中清理 `Worker` 和 `thread` 实例。

在这个演示应用程序中，整个应用程序在运行结束时由操作系统终止和清理，因此这并不是一个真正的问题。对于一个使用相同的调度程序以一种不断生成和添加新请求的方式使用的应用程序，同时可能还动态扩展工作线程的数量，这将是一个真正的问题。在这种情况下，必须小心解决这些内存泄漏。

# 错误类型

Memcheck 可以检测到各种与内存相关的问题。以下部分总结了这些错误及其含义。

# 非法读取/非法写入错误

这些错误通常以以下格式报告：

```cpp
Invalid read of size <bytes>
at 0x<memory address>: (location)
by 0x<memory address>: (location)
by 0x<memory address>: (location)
Address 0x<memory address> <error description>

```

前面错误消息中的第一行告诉我们是否是无效的读取或写入访问。接下来的几行将是一个回溯，详细说明了发生无效读取或写入的位置（可能还包括源文件中的行），以及从哪里调用了该代码。

最后，最后一行将详细说明发生的非法访问类型，例如读取已释放的内存块。

这种类型的错误表明写入或读取不应访问的内存部分。这可能是因为访问了野指针（即引用随机内存地址），或者由于代码中的早期问题导致计算了错误的内存地址，或者没有尊重内存边界，读取了数组或类似结构的边界之外。

通常，当报告这种类型的错误时，应该非常重视，因为它表明了一个基本问题，不仅可能导致数据损坏和崩溃，还可能导致其他人可以利用的错误。

# 使用未初始化的值

简而言之，这是一个问题，即在未为变量分配值的情况下使用变量的值。此时，很可能这些内容只是刚刚分配的 RAM 部分中的任何字节。因此，每当使用或访问这些内容时，可能会导致不可预测的行为。

遇到时，Memcheck 将抛出类似于这些的错误：

```cpp
$ valgrind --read-var-info=yes --leak-check=full ./unval
==6822== Memcheck, a memory error detector
==6822== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==6822== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==6822== Command: ./unval
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E87B83: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Use of uninitialised value of size 8
==6822==    at 0x4E8476B: _itoa_word (_itoa.c:179)
==6822==    by 0x4E8812C: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E84775: _itoa_word (_itoa.c:179)
==6822==    by 0x4E8812C: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E881AF: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E87C59: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E8841A: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E87CAB: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== Conditional jump or move depends on uninitialised value(s)
==6822==    at 0x4E87CE2: vfprintf (vfprintf.c:1631)
==6822==    by 0x4E8F898: printf (printf.c:33)
==6822==    by 0x400541: main (unval.cpp:6)
==6822== 
==6822== 
==6822== HEAP SUMMARY:
==6822==     in use at exit: 0 bytes in 0 blocks
==6822==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==6822== 
==6822== All heap blocks were freed -- no leaks are possible
==6822== 
==6822== For counts of detected and suppressed errors, rerun with: -v
==6822== Use --track-origins=yes to see where uninitialised values come from
==6822== ERROR SUMMARY: 8 errors from 8 contexts (suppressed: 0 from 0)

```

这一系列特定的错误是由以下一小段代码引起的：

```cpp
#include <cstring>
 #include <cstdio>

 int main() {
    int x;  
    printf ("x = %dn", x); 
    return 0;
 } 
```

正如我们在前面的代码中看到的，我们从未初始化我们的变量，这将设置为任何随机值。如果幸运的话，它将被设置为零，或者一个同样（希望）无害的值。这段代码展示了我们的任何未初始化变量如何进入库代码。

未初始化变量的使用是否有害很难说，这在很大程度上取决于变量的类型和受影响的代码。然而，简单地分配一个安全的默认值要比追踪和调试可能由未初始化变量（随机）引起的神秘问题要容易得多。

要了解未初始化变量的来源，可以向 Memcheck 传递`-track-origins=yes`标志。这将告诉它为每个变量保留更多信息，从而使追踪此类问题变得更容易。

# 未初始化或不可寻址的系统调用值

每当调用一个函数时，可能会传递未初始化的值作为参数，甚至是指向不可寻址的缓冲区的指针。在任何一种情况下，Memcheck 都会记录这一点：

```cpp
$ valgrind --read-var-info=yes --leak-check=full ./unsyscall
==6848== Memcheck, a memory error detector
==6848== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==6848== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==6848== Command: ./unsyscall
==6848== 
==6848== Syscall param write(buf) points to uninitialised byte(s)
==6848==    at 0x4F306E0: __write_nocancel (syscall-template.S:84)
==6848==    by 0x4005EF: main (unsyscall.cpp:7)
==6848==  Address 0x5203040 is 0 bytes inside a block of size 10 alloc'd
==6848==    at 0x4C2DB8F: malloc (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==6848==    by 0x4005C7: main (unsyscall.cpp:5)
==6848== 
==6848== Syscall param exit_group(status) contains uninitialised byte(s)
==6848==    at 0x4F05B98: _Exit (_exit.c:31)
==6848==    by 0x4E73FAA: __run_exit_handlers (exit.c:97)
==6848==    by 0x4E74044: exit (exit.c:104)
==6848==    by 0x4005FC: main (unsyscall.cpp:8)
==6848== 
==6848== 
==6848== HEAP SUMMARY:
==6848==     in use at exit: 14 bytes in 2 blocks
==6848==   total heap usage: 2 allocs, 0 frees, 14 bytes allocated
==6848== 
==6848== LEAK SUMMARY:
==6848==    definitely lost: 0 bytes in 0 blocks
==6848==    indirectly lost: 0 bytes in 0 blocks
==6848==      possibly lost: 0 bytes in 0 blocks
==6848==    still reachable: 14 bytes in 2 blocks
==6848==         suppressed: 0 bytes in 0 blocks
==6848== Reachable blocks (those to which a pointer was found) are not shown.
==6848== To see them, rerun with: --leak-check=full --show-leak-kinds=all
==6848== 
==6848== For counts of detected and suppressed errors, rerun with: -v
==6848== Use --track-origins=yes to see where uninitialised values come from
==6848== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 0 from 0)

```

前面的日志是由以下代码生成的：

```cpp
#include <cstdlib>
 #include <unistd.h> 

 int main() {  
    char* arr  = (char*) malloc(10);  
    int*  arr2 = (int*) malloc(sizeof(int));  
    write(1, arr, 10 ); 
    exit(arr2[0]);
 } 
```

与前一节详细介绍的未初始化值的一般使用情况类似，传递未初始化或其他可疑的参数至少是有风险的，而在最坏的情况下，可能会导致崩溃、数据损坏或更糟。

# 非法释放

非法的释放或删除通常是试图在已经释放的内存块上重复调用`free()`或`delete()`。虽然不一定有害，但这表明了糟糕的设计，并且绝对必须修复。

当试图使用不指向该内存块开头的指针释放内存块时，也会发生这种情况。这是为什么永远不应该对从`malloc()`或`new()`调用中获得的原始指针进行指针算术运算，而应该使用副本的主要原因之一。

# 不匹配的释放

内存块的分配和释放应始终使用匹配函数执行。这意味着当我们使用 C 风格的函数进行分配时，我们使用相同 API 的匹配函数进行释放。对于 C++风格的分配和释放也是如此。

简而言之，这意味着以下内容：

+   如果我们使用`malloc`、`calloc`、`valloc`、`realloc`或`memalign`进行分配，我们使用`free`进行释放

+   如果我们使用 new 进行分配，我们使用`delete`进行释放

+   如果我们使用`new[]`进行分配，我们使用`delete[]`进行释放

混合使用这些不一定会引起问题，但这样做是未定义的行为。后一种分配和释放是特定于数组的。不使用`delete[]`释放使用`new[]`分配的数组可能会导致内存泄漏，甚至更糟。

# 重叠的源和目的地

这种类型的错误表明传递给源和目的地内存块的指针重叠（基于预期大小）。这种错误的结果通常是一种形式的损坏或系统崩溃。

# 可疑的参数值

对于内存分配函数，Memcheck 验证传递给它们的参数是否真的有意义。其中一个例子是传递负大小，或者它将远远超出合理的分配大小：例如，请求分配一百万兆字节的内存。很可能，这些值是代码中早期计算错误的结果。

Memcheck 会像在 Memcheck 手册中的这个例子中报告这个错误：

```cpp
==32233== Argument 'size' of function malloc has a fishy (possibly negative) value: -3
==32233==    at 0x4C2CFA7: malloc (vg_replace_malloc.c:298)
==32233==    by 0x400555: foo (fishy.c:15)
==32233==    by 0x400583: main (fishy.c:23)

```

在这里尝试将值-3 传递给`malloc`，这显然没有多大意义。由于这显然是一个荒谬的操作，这表明代码中存在严重的错误。

# 内存泄漏检测

对于 Memcheck 报告的内存泄漏，最重要的是，许多报告的*泄漏*实际上可能并不是泄漏。这反映在 Memcheck 报告它发现的任何潜在问题的方式上，如下所示：

+   明确丢失

+   间接丢失

+   可能丢失

在三种可能的报告类型中，**明确丢失**类型是唯一一种绝对确定相关内存块不再可达的类型，没有指针或引用剩余，这使得应用程序永远无法释放内存。

在**间接丢失**类型的情况下，我们没有丢失这些内存块本身的指针，而是丢失了指向这些块的结构的指针。例如，当我们直接丢失对数据结构的根节点（如红黑树或二叉树）的访问权限时，就会发生这种情况。结果，我们也失去了访问任何子节点的能力。

最后，**可能丢失**是一个包罗万象的类型，Memcheck 并不完全确定内存块是否仍然有引用。这可能发生在存在内部指针的情况下，例如特定类型的数组分配。它也可能通过多重继承发生，其中 C++对象使用自引用。

如前面在 Memcheck 的基本使用部分提到的，建议始终使用`--leak-check=full`来运行 Memcheck，以获取关于内存泄漏位置的详细信息。

# Helgrind

Helgrind 的目的是检测多线程应用程序中同步实现的问题。它可以检测到对 POSIX 线程的错误使用，由于错误的锁定顺序而导致的潜在死锁问题，以及数据竞争--在没有线程同步的情况下读取或写入数据。

# 基本使用

我们以以下方式启动 Helgrind：

```cpp
$ valgrind --tool=helgrind --read-var-info=yes --log-file=dispatcher_helgrind.log ./dispatcher_demo

```

与运行 Memcheck 类似，这将运行应用程序并将所有生成的输出记录到日志文件中，同时明确使用二进制文件中的所有可用调试信息。

运行应用程序后，我们检查生成的日志文件：

```cpp
==6417== Helgrind, a thread error detector
==6417== Copyright (C) 2007-2015, and GNU GPL'd, by OpenWorks LLP et al.
==6417== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==6417== Command: ./dispatcher_demo
==6417== Parent PID: 2838
==6417== 
==6417== ---Thread-Announcement------------------------------------------
==6417== 
==6417== Thread #1 is the program's root thread 
```

在关于应用程序和 Valgrind 版本的初始基本信息之后，我们被告知已创建了根线程：

```cpp
==6417== 
==6417== ---Thread-Announcement------------------------------------------
==6417== 
==6417== Thread #2 was created
==6417==    at 0x56FB7EE: clone (clone.S:74)
==6417==    by 0x53DE149: create_thread (createthread.c:102)
==6417==    by 0x53DFE83: pthread_create@@GLIBC_2.2.5 (pthread_create.c:679)
==6417==    by 0x4C34BB7: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x4EF8DC2: std::thread::_M_start_thread(std::shared_ptr<std::thread::_Impl_base>, void (*)()) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x403AD7: std::thread::thread<void (Worker::*)(), Worker*&>(void (Worker::*&&)(), Worker*&) (thread:137)
==6417==    by 0x4030E6: Dispatcher::init(int) (dispatcher.cpp:40)
==6417==    by 0x4090A0: main (main.cpp:51)
==6417== 
==6417== ----------------------------------------------------------------
```

第一个线程是由调度程序创建并记录的。接下来我们收到第一个警告：

```cpp
==6417== 
==6417==  Lock at 0x60F4A0 was first observed
==6417==    at 0x4C321BC: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x401CD1: __gthread_mutex_lock(pthread_mutex_t*) (gthr-default.h:748)
==6417==    by 0x402103: std::mutex::lock() (mutex:135)
==6417==    by 0x40337E: Dispatcher::addWorker(Worker*) (dispatcher.cpp:108)
==6417==    by 0x401DF9: Worker::run() (worker.cpp:49)
==6417==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6417==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6417==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6417==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6417==    by 0x4EF8C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x4C34DB6: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x53DF6B9: start_thread (pthread_create.c:333)
==6417==  Address 0x60f4a0 is 0 bytes inside data symbol "_ZN10Dispatcher12workersMutexE"
==6417== 
==6417== Possible data race during write of size 1 at 0x5CD9261 by thread #1
==6417== Locks held: 1, at address 0x60F4A0
==6417==    at 0x403650: Worker::setRequest(AbstractRequest*) (worker.h:38)
==6417==    by 0x403253: Dispatcher::addRequest(AbstractRequest*) (dispatcher.cpp:70)
==6417==    by 0x409132: main (main.cpp:63)
==6417== 
==6417== This conflicts with a previous read of size 1 by thread #2
==6417== Locks held: none
==6417==    at 0x401E02: Worker::run() (worker.cpp:51)
==6417==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6417==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6417==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6417==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6417==    by 0x4EF8C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x4C34DB6: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x53DF6B9: start_thread (pthread_create.c:333)
==6417==  Address 0x5cd9261 is 97 bytes inside a block of size 104 alloc'd
==6417==    at 0x4C2F50F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x40308F: Dispatcher::init(int) (dispatcher.cpp:38)
==6417==    by 0x4090A0: main (main.cpp:51)
==6417==  Block was alloc'd by thread #1
==6417== 
==6417== ----------------------------------------------------------------
```

在前面的警告中，Helgrind 告诉我们线程 ID 1 和 2 之间存在大小为 1 的冲突读取。由于 C++11 线程 API 使用了大量模板，跟踪可能有些难以阅读。关键在于这些行：

```cpp
==6417==    at 0x403650: Worker::setRequest(AbstractRequest*) (worker.h:38) ==6417==    at 0x401E02: Worker::run() (worker.cpp:51) 
```

这对应以下代码行：

```cpp
void setRequest(AbstractRequest* request) { this->request = request; ready = true; }
while (!ready && running) { 
```

这些代码行中唯一大小为 1 的变量是布尔变量`ready`。由于这是一个布尔变量，我们知道它是一个原子操作（详见第十五章，*原子操作-与硬件交互*）。因此，我们可以忽略这个警告。

接下来，我们为这个线程收到另一个警告：

```cpp
==6417== Possible data race during write of size 1 at 0x5CD9260 by thread #1
==6417== Locks held: none
==6417==    at 0x40362C: Worker::stop() (worker.h:37)
==6417==    by 0x403184: Dispatcher::stop() (dispatcher.cpp:50)
==6417==    by 0x409163: main (main.cpp:70)
==6417== 
==6417== This conflicts with a previous read of size 1 by thread #2 ==6417== Locks held: none
==6417==    at 0x401E0E: Worker::run() (worker.cpp:51)
==6417==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6417==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6417==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6417==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6417==    by 0x4EF8C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x4C34DB6: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x53DF6B9: start_thread (pthread_create.c:333)
==6417==  Address 0x5cd9260 is 96 bytes inside a block of size 104 alloc'd
==6417==    at 0x4C2F50F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x40308F: Dispatcher::init(int) (dispatcher.cpp:38)
==6417==    by 0x4090A0: main (main.cpp:51)
==6417==  Block was alloc'd by thread #1 
```

与第一个警告类似，这也涉及一个布尔变量--这里是`Worker`实例中的`running`变量。由于这也是一个原子操作，我们可以再次忽略这个警告。

在收到这个警告后，我们看到其他线程也出现了类似的警告。我们还看到这个警告多次重复出现：

```cpp
==6417==  Lock at 0x60F540 was first observed
==6417==    at 0x4C321BC: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==    by 0x401CD1: __gthread_mutex_lock(pthread_mutex_t*) (gthr-default.h:748)
==6417==    by 0x402103: std::mutex::lock() (mutex:135)
==6417==    by 0x409044: logFnc(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >) (main.cpp:40)
==6417==    by 0x40283E: Request::process() (request.cpp:19)
==6417==    by 0x401DCE: Worker::run() (worker.cpp:44)
==6417==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6417==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6417==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6417==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6417==    by 0x4EF8C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x4C34DB6: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
==6417==  Address 0x60f540 is 0 bytes inside data symbol "logMutex"
==6417== 
==6417== Possible data race during read of size 8 at 0x60F238 by thread #1
==6417== Locks held: none
==6417==    at 0x4F4ED6F: std::basic_ostream<char, std::char_traits<char> >& std::__ostream_insert<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*, long) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x4F4F236: std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x403199: Dispatcher::stop() (dispatcher.cpp:53)
==6417==    by 0x409163: main (main.cpp:70)
==6417== 
==6417== This conflicts with a previous write of size 8 by thread #7
==6417== Locks held: 1, at address 0x60F540
==6417==    at 0x4F4EE25: std::basic_ostream<char, std::char_traits<char> >& std::__ostream_insert<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*, long) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6417==    by 0x409055: logFnc(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >) (main.cpp:41)
==6417==    by 0x402916: Request::finish() (request.cpp:27)
==6417==    by 0x401DED: Worker::run() (worker.cpp:45)
==6417==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6417==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6417==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6417==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6417==  Address 0x60f238 is 24 bytes inside data symbol "_ZSt4cout@@GLIBCXX_3.4"  
```

这个警告是由于在线程之间没有同步使用标准输出而触发的。尽管这个演示应用程序的日志函数使用互斥锁来同步工作线程记录的文本，但在一些地方我们也以不安全的方式写入标准输出。

这相对容易通过使用一个中央、线程安全的日志函数来修复。尽管这不太可能引起任何稳定性问题，但很可能会导致任何日志输出最终成为一团乱码，无法使用。

# 对 pthread API 的误用

Helgrind 检测到大量涉及 pthread API 的错误，如其手册所总结的，并列在下面：

+   解锁无效的互斥锁

+   解锁未锁定的互斥锁

+   解锁由不同线程持有的互斥锁

+   销毁无效或锁定的互斥锁

+   递归锁定非递归互斥锁

+   释放包含锁定互斥锁的内存

+   将互斥锁参数传递给期望读写锁参数的函数，反之亦然

+   POSIX pthread 函数的失败会返回一个必须处理的错误代码

+   线程在仍持有锁定的情况下退出

+   使用`pthread_cond_wait`调用未锁定的互斥锁、无效的互斥锁或被其他线程锁定的互斥锁。

+   条件变量与其关联的互斥锁之间的不一致绑定

+   无效或重复初始化 pthread 屏障

+   在等待线程上初始化 pthread 屏障

+   销毁从未初始化的 pthread 屏障对象，或者仍在等待线程的 pthread 屏障对象

+   等待未初始化的 pthread 屏障

此外，如果 Helgrind 本身没有检测到错误，但是 pthread 库本身对 Helgrind 拦截的每个函数返回错误，那么 Helgrind 也会报告错误。

# 锁定顺序问题

锁定顺序检测使用的假设是一旦一系列锁以特定顺序被访问，它们将永远以这种顺序使用。例如，想象一下，一个资源由两个锁保护。正如我们在第十一章的调度程序演示中看到的，*线程同步和通信*，我们在其调度程序类中使用两个互斥锁，一个用于管理对工作线程的访问，另一个用于请求实例。

在该代码的正确实现中，我们始终确保在尝试获取另一个互斥锁之前解锁一个互斥锁，因为另一个线程可能已经获得了对第二个互斥锁的访问权，并尝试获取对第一个互斥锁的访问权，从而创建死锁情况。

虽然有用，但重要的是要意识到，在某些领域，这种检测算法目前还不完善。这在使用条件变量时最为明显，条件变量自然使用的锁定顺序往往会被 Helgrind 报告为*错误*。

这里的要点是要检查这些日志消息并判断它们的价值，但与多线程 API 的直接误用不同，报告的问题是否是误报还不那么明确。

# 数据竞争

实质上，数据竞争是指两个或更多线程在没有任何同步机制的情况下尝试读取或写入相同的资源。在这里，只有并发读取和写入，或两个同时写入，才会真正有害；因此，只有这两种访问类型会被报告。

在早期关于基本 Helgrind 使用的部分，我们在日志中看到了这种类型错误的一些示例。那里涉及同时写入和读取变量。正如我们在该部分中也提到的，Helgrind 并不关心写入或读取是否是原子的，而只是报告潜在问题。

就像锁定顺序问题一样，这意味着人们必须根据每个数据竞争报告的价值来判断，因为许多报告可能是误报。

# DRD

DRD 与 Helgrind 非常相似，因为它也可以检测应用程序中的线程和同步问题。DRD 与 Helgrind 的主要区别在于以下几点：

+   DRD 使用的内存较少

+   DRD 不会检测锁定顺序违规

+   DRD 支持分离线程

通常，我们希望同时运行 DRD 和 Helgrind，以便比较两者的输出。由于许多潜在问题是高度不确定的，使用这两种工具通常有助于确定最严重的问题。

# 基本用法

启动 DRD 与启动其他工具非常相似--我们只需指定我们想要的工具，如下所示：

```cpp
$ valgrind --tool=drd --log-file=dispatcher_drd.log --read-var-info=yes ./dispatcher_demo
```

应用程序完成后，我们检查生成的日志文件内容。

```cpp
==6576== drd, a thread error detector
==6576== Copyright (C) 2006-2015, and GNU GPL'd, by Bart Van Assche.
==6576== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==6576== Command: ./dispatcher_demo
==6576== Parent PID: 2838
==6576== 
==6576== Conflicting store by thread 1 at 0x05ce51b1 size 1
==6576==    at 0x403650: Worker::setRequest(AbstractRequest*) (worker.h:38)
==6576==    by 0x403253: Dispatcher::addRequest(AbstractRequest*) (dispatcher.cpp:70)
==6576==    by 0x409132: main (main.cpp:63)
==6576== Address 0x5ce51b1 is at offset 97 from 0x5ce5150\. Allocation context:
==6576==    at 0x4C3150F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_drd-amd64-linux.so)
==6576==    by 0x40308F: Dispatcher::init(int) (dispatcher.cpp:38)
==6576==    by 0x4090A0: main (main.cpp:51)
==6576== Other segment start (thread 2)
==6576==    at 0x4C3818C: pthread_mutex_unlock (in /usr/lib/valgrind/vgpreload_drd-amd64-linux.so)
==6576==    by 0x401D00: __gthread_mutex_unlock(pthread_mutex_t*) (gthr-default.h:778)
==6576==    by 0x402131: std::mutex::unlock() (mutex:153)
==6576==    by 0x403399: Dispatcher::addWorker(Worker*) (dispatcher.cpp:110)
==6576==    by 0x401DF9: Worker::run() (worker.cpp:49)
==6576==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6576==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6576==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6576==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6576==    by 0x4F04C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6576==    by 0x4C3458B: ??? (in /usr/lib/valgrind/vgpreload_drd-amd64-linux.so)
==6576==    by 0x53EB6B9: start_thread (pthread_create.c:333)
==6576== Other segment end (thread 2)
==6576==    at 0x4C3725B: pthread_mutex_lock (in /usr/lib/valgrind/vgpreload_drd-amd64-linux.so)
==6576==    by 0x401CD1: __gthread_mutex_lock(pthread_mutex_t*) (gthr-default.h:748)
==6576==    by 0x402103: std::mutex::lock() (mutex:135)
==6576==    by 0x4023F8: std::unique_lock<std::mutex>::lock() (mutex:485)
==6576==    by 0x40219D: std::unique_lock<std::mutex>::unique_lock(std::mutex&) (mutex:415)
==6576==    by 0x401E33: Worker::run() (worker.cpp:52)
==6576==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
==6576==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
==6576==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
==6576==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
==6576==    by 0x4F04C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==6576==    by 0x4C3458B: ??? (in /usr/lib/valgrind/vgpreload_drd-amd64-linux.so) 
```

前面的总结基本上重复了我们在 Helgrind 日志中看到的内容。我们看到了相同的数据竞争报告（冲突的存储），由于原子性，我们可以安全地忽略它。至少对于这个特定的代码来说，使用 DRD 并没有为我们使用 Helgrind 所知道的内容增添任何新东西。

无论如何，最好同时使用两种工具，以防一种工具发现了另一种工具没有发现的问题。

# 特性

DRD 将检测以下错误：

+   数据竞争

+   锁定争用（死锁和延迟）

+   错误使用 pthreads API

对于第三点，根据 DRD 的手册，DRD 检测到的错误列表与 Helgrind 的非常相似：

+   将一个类型的同步对象（例如互斥锁）的地址传递给期望指向另一种类型同步对象（例如条件变量）的 POSIX API 调用

+   尝试解锁一个未被锁定的互斥锁

+   尝试解锁另一个线程锁定的互斥锁

+   尝试递归锁定类型为`PTHREAD_MUTEX_NORMAL`的互斥锁或自旋锁

+   销毁或释放被锁定的互斥锁

+   在与条件变量关联的互斥锁上未持有锁的情况下发送信号给条件变量

+   在未锁定的互斥锁上调用`pthread_cond_wait`，即由另一个线程锁定或已递归锁定

+   通过`pthread_cond_wait`将两个不同的互斥锁与条件变量关联

+   销毁或释放正在等待的条件变量

+   销毁或释放被锁定的读写同步对象

+   尝试解锁未被调用线程锁定的读写同步对象

+   尝试递归锁定独占读写同步对象

+   尝试将用户定义的读写同步对象的地址传递给 POSIX 线程函数

+   尝试将 POSIX 读写同步对象的地址传递给用户定义的读写同步对象的注释之一

+   重新初始化互斥锁、条件变量、读写锁、信号量或屏障

+   销毁或释放正在等待的信号量或屏障

+   屏障等待和屏障销毁之间的缺少同步

+   在不先解锁线程锁定的自旋锁、互斥锁或读写同步对象的情况下退出线程

+   将无效的线程 ID 传递给`pthread_join`或`pthread_cancel`

如前所述，DRD 还支持分离线程，这里有帮助的是锁定顺序检查是否重要取决于一个人的应用程序。

# C++11 线程支持

DRD 手册中包含了关于 C++11 线程支持的这一部分。

如果要使用`c++11`类`std::thread`，则需要对该类的实现中使用的`std::shared_ptr<>`对象进行注释：

+   在公共头文件的开头或在每个源文件的开头添加以下代码，然后再包含任何 C++头文件：

```cpp
    #include <valgrind/drd.h>
    #define _GLIBCXX_SYNCHRONIZATION_HAPPENS_BEFORE(addr)
    ANNOTATE_HAPPENS_BEFORE(addr)
    #define _GLIBCXX_SYNCHRONIZATION_HAPPENS_AFTER(addr)
    ANNOTATE_HAPPENS_AFTER(addr)
```

+   下载 GCC 源代码，并从源文件`libstdc++-v3/src/c++11/thread.cc`中复制`execute_native_thread_routine()`和`std::thread::_M_start_thread()`函数的实现到一个与您的应用程序链接的源文件中。确保在这个源文件中，`_GLIBCXX_SYNCHRONIZATION_HAPPENS_*()`宏也被正确定义。

在使用 DRD 与使用 C++11 线程 API 的应用程序时，可能会看到很多误报，这将通过前面的*修复*来解决。

然而，当使用 GCC 5.4 和 Valgrind 3.11（可能也适用于旧版本）时，这个问题似乎不再存在。然而，当使用 C++11 线程 API 时，突然看到很多 DRD 输出中的误报时，这是需要记住的事情。

# 总结

在本章中，我们看了如何调试多线程应用程序。我们探讨了在多线程环境中使用调试器的基础知识。接下来，我们看到了如何使用 Valgrind 框架中的三种工具，这些工具可以帮助我们追踪多线程和其他关键问题。

在这一点上，我们可以拿之前章节中的信息编写的应用程序进行分析，找出需要修复的问题，包括内存泄漏和不正确使用同步机制。

在下一章中，我们将综合我们所学的知识，探讨多线程编程和一般开发中的一些最佳实践。


# 第十六章：最佳实践

和大多数事情一样，最好是避免犯错，而不是事后纠正。本章将介绍多线程应用程序中的一些常见错误和设计问题，并展示避免常见和不太常见问题的方法。

本章的主题包括：

+   常见的多线程问题，如死锁和数据竞争。

+   互斥锁、锁的正确使用和陷阱。

+   静态初始化时可能出现的潜在问题。

# 正确的多线程

在前面的章节中，我们已经看到了编写多线程代码时可能出现的各种潜在问题。这些问题从明显的问题，比如两个线程无法同时写入同一位置，到更微妙的问题，比如互斥锁的不正确使用。

还有许多与多线程代码直接相关的问题，但它们仍然可能导致看似随机的崩溃和其他令人沮丧的问题。其中一个例子是变量的静态初始化。在接下来的章节中，我们将看到所有这些问题以及更多问题，并介绍避免不得不处理这些问题的方法。

和生活中的许多事情一样，它们是有趣的经历，但通常你不想重复它们。

# 错误的期望 - 死锁

死锁的描述已经相当简洁了。当两个或更多进程试图访问另一个进程持有的资源，而另一个线程同时正在等待访问它持有的资源时，就会发生死锁。

例如：

1.  线程 1 获得对资源 A 的访问

1.  线程 1 和 2 都想获得对资源 B 的访问

1.  线程 2 获胜，现在拥有 B，而线程 1 仍在等待 B

1.  线程 2 现在想要使用 A，并等待访问。

1.  线程 1 和 2 都永远等待资源

在这种情况下，我们假设线程最终能够访问每个资源，而事实上却相反，因为每个线程都持有另一个线程需要的资源。

可视化，这个死锁过程会像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/6bda8592-427c-467e-bfc6-e9a87991853a.png)

这清楚地表明了在防止死锁时的两个基本规则：

+   尽量不要同时持有多个锁。

+   尽快释放任何持有的锁。

我们在第十一章中看到了一个现实生活中的例子，*线程同步和通信*，当我们查看调度程序演示代码时。这段代码涉及两个互斥锁，以保护对两个数据结构的访问：

```cpp
void Dispatcher::addRequest(AbstractRequest* request) {
    workersMutex.lock();
    if (!workers.empty()) {
          Worker* worker = workers.front();
          worker->setRequest(request);
          condition_variable* cv;
          mutex* mtx;
          worker->getCondition(cv);
          worker->getMutex(mtx);
          unique_lock<mutex> lock(*mtx);
          cv->notify_one();
          workers.pop();
          workersMutex.unlock();
    }
    else {
          workersMutex.unlock();
          requestsMutex.lock();
          requests.push(request);
          requestsMutex.unlock();
    }
 } 
```

这里的互斥锁是`workersMutex`和`requestsMutex`变量。我们可以清楚地看到，在任何时候我们都没有在尝试获取另一个互斥锁之前持有一个互斥锁。我们明确地在方法的开始处锁定`workersMutex`，这样我们就可以安全地检查工作数据结构是否为空。

如果不为空，我们将新请求交给一个工作线程。然后，当我们完成了对工作数据结构的操作后，我们释放互斥锁。此时，我们不再持有任何互斥锁。这里没有太复杂的东西，因为我们只使用了一个互斥锁。

有趣的是在 else 语句中，当没有等待的工作线程并且我们需要获取第二个互斥锁时。当我们进入这个范围时，我们保留一个互斥锁。我们可以尝试获取`requestsMutex`并假设它会起作用，但这可能会导致死锁，原因很简单：

```cpp
bool Dispatcher::addWorker(Worker* worker) {
    bool wait = true;
    requestsMutex.lock();
    if (!requests.empty()) {
          AbstractRequest* request = requests.front();
          worker->setRequest(request);
          requests.pop();
          wait = false;
          requestsMutex.unlock();
    }
    else {
          requestsMutex.unlock();
          workersMutex.lock();
          workers.push(worker);
          workersMutex.unlock();
    }
          return wait;
 } 
```

与前面的函数相配套的函数也使用了这两个互斥锁。更糟糕的是，这个函数在一个单独的线程中运行。结果，当第一个函数持有`workersMutex`并尝试获取`requestsMutex`时，第二个函数同时持有后者，并尝试获取前者时，我们就陷入了死锁。

然而，在这里我们看到的函数中，这两条规则都已成功实施；我们从不同时持有多个锁，并且尽快释放我们持有的任何锁。这可以在两个 else 情况中看到，当我们进入它们时，我们首先释放不再需要的任何锁。

在任一情况下，我们都不需要再分别检查工作线程或请求数据结构；在做其他事情之前，我们可以释放相关的锁。这导致以下可视化效果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/75aa2220-ea54-4fa5-bf1f-bc61cf4d3a68.png)

当然，我们可能需要使用两个或更多数据结构或变量中包含的数据；这些数据同时被其他线程使用。很难确保在生成的代码中没有死锁的可能性。

在这里，人们可能希望考虑使用临时变量或类似方法。通过锁定互斥量，复制相关数据，并立即释放锁，就不会出现死锁的可能性。即使必须将结果写回数据结构，也可以在单独的操作中完成。

这增加了防止死锁的两条规则：

+   尽量不要同时持有多个锁。

+   尽快释放任何持有的锁。

+   永远不要持有锁的时间超过绝对必要的时间。

+   持有多个锁时，要注意它们的顺序。

# 粗心大意 - 数据竞争

数据竞争，也称为竞争条件，发生在两个或更多线程同时尝试写入同一共享内存时。因此，每个线程执行的指令序列期间和结束时的共享内存状态在定义上是不确定的。

正如我们在第十三章中看到的，“调试多线程代码”，调试多线程应用程序的工具经常报告数据竞争。例如：

```cpp
    ==6984== Possible data race during write of size 1 at 0x5CD9260 by thread #1
 ==6984== Locks held: none
 ==6984==    at 0x40362C: Worker::stop() (worker.h:37)
 ==6984==    by 0x403184: Dispatcher::stop() (dispatcher.cpp:50)
 ==6984==    by 0x409163: main (main.cpp:70)
 ==6984== 
 ==6984== This conflicts with a previous read of size 1 by thread #2
 ==6984== Locks held: none
 ==6984==    at 0x401E0E: Worker::run() (worker.cpp:51)
 ==6984==    by 0x408FA4: void std::_Mem_fn_base<void (Worker::*)(), true>::operator()<, void>(Worker*) const (in /media/sf_Projects/Cerflet/dispatcher/dispatcher_demo)
 ==6984==    by 0x408F38: void std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::_M_invoke<0ul>(std::_Index_tuple<0ul>) (functional:1531)
 ==6984==    by 0x408E3F: std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)>::operator()() (functional:1520)
 ==6984==    by 0x408D47: std::thread::_Impl<std::_Bind_simple<std::_Mem_fn<void (Worker::*)()> (Worker*)> >::_M_run() (thread:115)
 ==6984==    by 0x4EF8C7F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
 ==6984==    by 0x4C34DB6: ??? (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
 ==6984==    by 0x53DF6B9: start_thread (pthread_create.c:333)
 ==6984==  Address 0x5cd9260 is 96 bytes inside a block of size 104 alloc'd
 ==6984==    at 0x4C2F50F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_helgrind-amd64-linux.so)
 ==6984==    by 0x40308F: Dispatcher::init(int) (dispatcher.cpp:38)
 ==6984==    by 0x4090A0: main (main.cpp:51)
 ==6984==  Block was alloc'd by thread #1

```

生成上述警告的代码如下：

```cpp
bool Dispatcher::stop() {
    for (int i = 0; i < allWorkers.size(); ++i) {
          allWorkers[i]->stop();
    }
          cout << "Stopped workers.n";
          for (int j = 0; j < threads.size(); ++j) {
          threads[j]->join();
                      cout << "Joined threads.n";
    }
 } 
```

考虑在`Worker`实例中的这段代码：

```cpp
   void stop() { running = false; } 
```

我们还有：

```cpp
void Worker::run() {
    while (running) {
          if (ready) {
                ready = false;
                request->process();
                request->finish();
          }
                      if (Dispatcher::addWorker(this)) {
                while (!ready && running) {
                      unique_lock<mutex> ulock(mtx);
                      if (cv.wait_for(ulock, chrono::seconds(1)) == cv_status::timeout) {
                      }
                }
          }
    }
 } 
```

在这里，`running`是一个布尔变量，被设置为`false`（从一个线程写入），表示工作线程应该终止其等待循环，而读取布尔变量是从不同的进程进行的，主线程与工作线程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c5cacd65-8eda-4ec0-b186-915b29ab3acc.png)

这个特定示例的警告是由于一个布尔变量同时被写入和读取。当然，这种特定情况之所以安全，与原子操作有关，详细解释在第八章“原子操作 - 与硬件交互”中。

即使像这样的操作潜在风险很大的原因是，读取操作可能发生在变量仍在更新过程中。例如，对于 32 位整数，根据硬件架构，更新此变量可能是一次完成，或者多次完成。在后一种情况下，读取操作可能读取一个中间值，导致结果不确定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1ce79d19-50bf-4450-b4b5-0299d486910a.png)

更有趣的情况是，当多个线程写入一个标准输出时，例如，不使用`cout`。由于这个流不是线程安全的，结果输出流将包含输入流的片段，每当任一线程有机会写入时：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4bc9344c-37a8-4666-998a-ed75bac419fb.png)

因此，防止数据竞争的基本规则是：

+   永远不要向未锁定的、非原子的共享资源中写入

+   永远不要从未锁定的、非原子的共享资源中读取

这基本上意味着任何写入或读取都必须是线程安全的。如果一个线程写入共享内存，那么其他线程就不应该能够同时写入它。同样，当我们从共享资源中读取时，我们需要确保最多只有其他线程也在读取共享资源。

这种级别的互斥自然是由互斥锁实现的，正如我们在前面的章节中所看到的，读写锁提供了一种改进，允许同时进行读取，同时将写入作为完全互斥的事件。

当然，互斥锁也有一些陷阱，我们将在下一节中看到。

# 互斥锁并不是魔术

互斥锁构成了几乎所有形式的互斥 API 的基础。在它们的核心，它们似乎非常简单，只有一个线程可以拥有一个互斥锁，其他线程则整齐地等待在队列中，直到它们可以获得互斥锁上的锁。

甚至可以将这个过程想象成如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/697b3b4a-2072-498c-a97c-64ab09b5f9a5.png)

现实当然没有那么美好，主要是由于硬件对我们施加的实际限制。一个明显的限制是同步原语并不是免费的。即使它们是在硬件中实现的，也需要多次调用才能使它们工作。

在硬件中实现互斥锁的两种最常见的方法是使用**测试和设置**（TAS）或**比较和交换**（CAS）CPU 特性。

测试和设置通常被实现为两个汇编级指令，这些指令是自主执行的，意味着它们不能被中断。第一条指令测试某个内存区域是否设置为 1 或零。第二条指令只有在值为零（`false`）时才执行。这意味着互斥锁尚未被锁定。因此，第二条指令将内存区域设置为 1，锁定互斥锁。

在伪代码中，这将如下所示：

```cpp
bool TAS(bool lock) { 
   if (lock) { 
         return true; 
   } 
   else { 
         lock = true; 
         return false; 
   } 
} 
```

比较和交换是一个较少使用的变体，它对内存位置和给定值执行比较操作，只有在前两者匹配时才替换该内存位置的内容：

```cpp
bool CAS(int* p, int old, int new) { 
   if (*p != old) { 
               return false; 
         } 

   *p = new; 
         return true; 
} 
```

在任何一种情况下，都需要积极重复任一函数，直到返回一个正值：

```cpp
volatile bool lock = false; 

 void critical() { 
     while (TAS(&lock) == false); 
     // Critical section 
     lock = 0; 
 } 
```

在这里，使用一个简单的 while 循环来不断轮询内存区域（标记为 volatile 以防止可能有问题的编译器优化）。通常，使用一个算法来慢慢减少轮询的频率。这是为了减少对处理器和内存系统的压力。

这清楚地表明使用互斥锁并不是免费的，而每个等待互斥锁的线程都会积极地使用资源。因此，这里的一般规则是：

+   确保线程尽可能短暂地等待互斥锁和类似的锁。

+   对于较长的等待期间，使用条件变量或定时器。

# 锁是一种高级的互斥锁

正如我们在互斥锁部分中所看到的，使用互斥锁时需要牢记一些问题。当然，当使用基于互斥锁的锁和其他机制时，这些问题也同样适用，即使其中一些问题被这些 API 平滑地解决了。

当首次使用多线程 API 时，人们可能会对不同的同步类型之间的实际区别感到困惑。正如我们在本章前面所介绍的，互斥锁是几乎所有同步机制的基础，只是在它们使用互斥锁来实现所提供的功能的方式上有所不同。

这里的重要一点是它们不是不同的同步机制，而只是基本互斥类型的特殊化。无论是使用常规互斥锁、读/写锁、信号量，甚至像可重入（递归）互斥锁或锁这样奇特的东西，完全取决于试图解决的特定问题。

对于调度器，我们首先在第十一章中遇到，*线程同步和通信*，我们使用常规互斥锁来保护包含排队工作线程和请求的数据结构。由于任何对任一数据结构的访问可能不仅涉及读取操作，还可能涉及结构的操作，因此在那里使用读/写锁是没有意义的。同样，递归锁也不会对谦虚的互斥锁有任何作用。

对于每个同步问题，因此必须问以下问题：

+   我有哪些要求？

+   哪种同步机制最适合这些要求？

因此，选择复杂类型是有吸引力的，但通常最好坚持满足所有要求的更简单的类型。当涉及调试自己的实现时，与使用更直接和低级的 API 相比，可以节省宝贵的时间。

# 线程与未来

最近，有人开始建议不要使用线程，而是倡导使用其他异步处理机制，比如`promise`。背后的原因是使用线程和涉及的同步是复杂且容易出错的。通常，人们只想并行运行一个任务，而不用担心结果是如何获得的。

对于只运行短暂的简单任务，这当然是有意义的。基于线程的实现的主要优势始终是可以完全定制其行为。使用`promise`，可以发送一个要运行的任务，并在最后，从`future`实例中获取结果。这对于简单的任务很方便，但显然并不涵盖很多情况。

在这里最好的方法是首先充分了解线程和同步机制，以及它们的限制。只有在那之后才真正有意义地考虑是否希望使用`promise`、`packaged_task`或完整的线程。

另一个重要考虑因素是，这些更复杂的、基于未来的 API 通常是基于模板的，这可能会使调试和解决可能发生的任何问题变得更加困难，而不像使用更直接和低级的 API 那样容易。

# 静态初始化顺序

静态变量是只声明一次的变量，基本上存在于全局范围内，尽管可能只在特定类的实例之间共享。也可能有完全静态的类：

```cpp
class Foo { 
   static std::map<int, std::string> strings; 
   static std::string oneString; 

public: 
   static void init(int a, std::string b, std::string c) { 
         strings.insert(std::pair<int, std::string>(a, b)); 
         oneString = c; 
   } 
}; 

std::map<int, std::string> Foo::strings; 
std::string Foo::oneString; 
```

正如我们在这里所看到的，静态变量和静态函数似乎是一个非常简单但强大的概念。虽然从本质上讲这是正确的，但在静态变量和类的初始化方面存在一个主要问题，这将会让不注意的人掉入陷阱。这个问题就是初始化顺序。

想象一下，如果我们希望在另一个类的静态初始化中使用前面的类，就像这样：

```cpp
class Bar { 
   static std::string name; 
   static std::string initName(); 

public: 
   void init(); 
}; 

// Static initializations. 
std::string Bar::name = Bar::initName(); 

std::string Bar::initName() { 
   Foo::init(1, "A", "B"); 
   return "Bar"; 
} 
```

虽然这似乎会很好地工作，将第一个字符串添加到类的映射结构中，整数作为键，但这段代码很有可能会崩溃。原因很简单，没有保证在调用`Foo::init()`时`Foo::string`已经初始化。因此，尝试使用未初始化的映射结构将导致异常。

简而言之，静态变量的初始化顺序基本上是随机的，如果不考虑这一点，就会导致非确定性行为。

这个问题的解决方案非常简单。基本上，目标是使更复杂的静态变量的初始化显式，而不是像前面的例子中那样隐式。为此，我们修改了 Foo 类：

```cpp
class Foo { 
   static std::map<int, std::string>& strings(); 
   static std::string oneString; 

public: 
   static void init(int a, std::string b, std::string c) { 
         static std::map<int, std::string> stringsStatic = Foo::strings(); 
         stringsStatic.insert(std::pair<int, std::string>(a, b)); 
         oneString = c; 
   } 
}; 

std::string Foo::oneString; 

std::map<int, std::string>& Foo::strings() { 
   static std::map<int, std::string>* stringsStatic = new std::map<int, std::string>(); 
   return *stringsStatic; 
} 
```

从顶部开始，我们看到我们不再直接定义静态映射。相反，我们有一个同名的私有函数。这个函数的实现在这个示例代码的底部找到。在其中，我们有一个指向具有熟悉映射定义的静态指针。

当调用此函数时，如果尚未存在实例，则会创建一个新的映射，因为它是一个静态变量。在修改后的`init()`函数中，我们看到我们调用`strings()`函数来获取对此实例的引用。这是显式初始化的部分，因为调用该函数将始终确保在使用之前初始化映射结构，解决了我们先前遇到的问题。

我们还可以看到一个小优化：我们创建的`stringsStatic`变量也是静态的，这意味着我们只会调用`strings()`函数一次。这样就不需要重复调用函数，恢复了我们在先前简单但不稳定的实现中所具有的速度。

静态变量初始化的基本规则是，对于非平凡的静态变量，始终使用显式初始化。

# 摘要

在本章中，我们看了一些编写多线程代码时需要牢记的良好实践和规则，以及一些建议。到这一点，人们应该能够避免一些编写此类代码时的较大陷阱和主要混淆源。

在下一章中，我们将看看如何利用底层硬件来实现原子操作，以及在 C++11 中引入的`<atomics>`头文件。


# 第十七章：原子操作-与硬件交互

很多优化和线程安全取决于对底层硬件的理解：从某些架构上的对齐内存访问，到知道哪些数据大小和因此 C++类型可以安全地访问而不会有性能惩罚或需要互斥锁等。

本章探讨了如何利用多种处理器架构的特性，例如，防止使用互斥锁，而原子操作可以防止任何访问冲突。还考察了诸如 GCC 中的特定于编译器的扩展。

本章主题包括：

+   原子操作的类型以及如何使用它们

+   如何针对特定处理器架构进行优化

+   基于编译器的原子操作

# 原子操作

简而言之，原子操作是处理器可以用单条指令执行的操作。这使得它在某种意义上是原子的，即除了中断外，没有任何干扰，也不会改变任何变量或数据。

应用包括保证指令执行顺序，无锁实现以及指令执行顺序和内存访问保证重要的相关用途。

在 2011 年 C++标准之前，处理器提供的原子操作的访问仅由编译器使用扩展提供。

# Visual C++

对于微软的 MSVC 编译器，有原子函数，从 MSDN 文档总结而来，首先是添加功能：

| **原子函数** | **描述** |
| --- | --- |
| `InterlockedAdd` | 对指定的`LONG`值执行原子加法操作。 |
| `InterlockedAddAcquire` | 对指定的`LONG`值执行原子加法操作。该操作使用获取内存排序语义执行。 |
| `InterlockedAddRelease` | 对指定的`LONG`值执行原子加法操作。该操作使用释放内存排序语义执行。 |
| `InterlockedAddNoFence` | 对指定的`LONG`值执行原子加法操作。该操作是原子执行的，但不使用内存屏障（在本章中介绍）。 |

这些是该功能的 32 位版本。API 中还有其他方法的 64 位版本。原子函数往往专注于特定的变量类型，但本摘要中省略了此 API 的变体，以保持简洁。

我们还可以看到获取和释放的变体。这些保证了相应的读取或写入访问将受到内存重排序（在硬件级别）的保护，并且任何后续的读取或写入操作都会受到保护。最后，无屏障变体（也称为内存屏障）在不使用任何内存屏障的情况下执行操作。

通常 CPU 执行指令（包括内存读写）是为了优化性能而无序执行的。由于这种行为并不总是理想的，因此添加了内存屏障以防止指令重排序。

接下来是原子`AND`功能：

| **原子函数** | **描述** |
| --- | --- |
| `InterlockedAnd` | 对指定的`LONG`值执行原子`AND`操作。 |
| `InterlockedAndAcquire` | 对指定的`LONG`值执行原子`AND`操作。该操作使用获取内存排序语义执行。 |
| `InterlockedAndRelease` | 对指定的`LONG`值执行原子`AND`操作。该操作使用释放内存排序语义执行。 |
| `InterlockedAndNoFence` | 对指定的`LONG`值执行原子`AND`操作。该操作是原子执行的，但不使用内存屏障。 |

位测试功能如下：

| **原子函数** | **描述** |
| --- | --- |
| `InterlockedBitTestAndComplement` | 测试指定的`LONG`值的指定位并对其进行补码。 |
| `InterlockedBitTestAndResetAcquire` | 测试指定`LONG`值的指定位，并将其设置为`0`。该操作是`原子`的，并且使用获取内存排序语义执行。 |
| `InterlockedBitTestAndResetRelease` | 测试指定`LONG`值的指定位，并将其设置为`0`。该操作是`原子`的，并且使用内存释放语义执行。 |
| `InterlockedBitTestAndSetAcquire` | 测试指定`LONG`值的指定位，并将其设置为`1`。该操作是`原子`的，并且使用获取内存排序语义执行。 |
| `InterlockedBitTestAndSetRelease` | 测试指定`LONG`值的指定位，并将其设置为`1`。该操作是`原子`的，并且使用释放内存排序语义执行。 |
| `InterlockedBitTestAndReset` | 测试指定`LONG`值的指定位，并将其设置为`0`。 |
| `InterlockedBitTestAndSet` | 测试指定`LONG`值的指定位，并将其设置为`1`。 |

比较特性可以列举如下：

| **Interlocked function** | **描述** |
| --- | --- |
| `InterlockedCompareExchange` | 对指定数值执行原子比较和交换操作。该函数比较两个指定的 32 位数值，并根据比较结果与另一个 32 位数值进行交换。 |
| `InterlockedCompareExchangeAcquire` | 对指定数值执行原子比较和交换操作。该函数比较两个指定的 32 位数值，并根据比较结果与另一个 32 位数值进行交换。该操作使用获取内存排序语义执行。 |
| `InterlockedCompareExchangeRelease` | 对指定数值执行原子比较和交换操作。该函数比较两个指定的 32 位数值，并根据比较结果与另一个 32 位数值进行交换。交换是使用释放内存排序语义执行的。 |
| `InterlockedCompareExchangeNoFence` | 对指定数值执行原子比较和交换操作。该函数比较两个指定的 32 位数值，并根据比较结果与另一个 32 位数值进行交换。该操作是原子性的，但不使用内存屏障。 |
| `InterlockedCompareExchangePointer` | 对指定指针数值执行原子比较和交换操作。该函数比较两个指定的指针数值，并根据比较结果与另一个指针数值进行交换。 |
| `InterlockedCompareExchangePointerAcquire` | 对指定指针数值执行原子比较和交换操作。该函数比较两个指定的指针数值，并根据比较结果与另一个指针数值进行交换。该操作使用获取内存排序语义执行。 |
| `InterlockedCompareExchangePointerRelease` | 对指定指针数值执行原子比较和交换操作。该函数比较两个指定的指针数值，并根据比较结果与另一个指针数值进行交换。该操作使用释放内存排序语义执行。 |
| `InterlockedCompareExchangePointerNoFence` | 对指定数值执行原子比较和交换操作。该函数比较两个指定的指针数值，并根据比较结果与另一个指针数值进行交换。该操作是原子性的，但不使用内存屏障。 |

| 减量特性如下：

| **Interlocked function** | **描述** |
| --- | --- |
| `InterlockedDecrement` | 以`原子`操作的方式将指定 32 位变量的值减少 1。 |
| `InterlockedDecrementAcquire` | 以`原子`操作的方式将指定 32 位变量的值减少 1。该操作使用获取内存排序语义执行。 |
| `InterlockedDecrementRelease` | 对指定的 32 位变量的值进行递减（减少一），作为原子操作。该操作使用释放内存排序语义。 |
| `InterlockedDecrementNoFence` | 对指定的 32 位变量的值进行递减（减少一），作为原子操作。该操作是原子的，但不使用内存屏障。 |

交换（交换）功能包括：

| **Interlocked function** | **Description** |
| --- | --- |
| `InterlockedExchange` | 将 32 位变量设置为指定值，作为原子操作。 |
| `InterlockedExchangeAcquire` | 将 32 位变量设置为指定值，作为原子操作。该操作使用获取内存排序语义。 |
| `InterlockedExchangeNoFence` | 将 32 位变量设置为指定值，作为原子操作。该操作是原子的，但不使用内存屏障。 |
| `InterlockedExchangePointer` | 原子交换一对指针值。 |
| `InterlockedExchangePointerAcquire` | 原子交换一对指针值。该操作使用获取内存排序语义。 |
| `InterlockedExchangePointerNoFence` | 原子交换一对地址。该操作是原子的，但不使用内存屏障。 |
| `InterlockedExchangeSubtract` | 执行两个值的原子减法。 |
| `InterlockedExchangeAdd` | 执行两个 32 位值的原子加法。 |
| `InterlockedExchangeAddAcquire` | 执行两个 32 位值的原子加法。该操作使用获取内存排序语义。 |
| `InterlockedExchangeAddRelease` | 执行两个 32 位值的原子加法。该操作使用释放内存排序语义。 |
| `InterlockedExchangeAddNoFence` | 执行两个 32 位值的原子加法。该操作是原子的，但不使用内存屏障。 |

增量功能包括：

| **Interlocked function** | **Description** |
| --- | --- |
| `InterlockedIncrement` | 对指定的 32 位变量的值进行递增（增加一），作为原子操作。 |
| `InterlockedIncrementAcquire` | 使用获取内存排序语义，作为原子操作增加指定 32 位变量的值（增加一）。 |
| `InterlockedIncrementRelease` | 对指定的 32 位变量的值进行递增（增加一），作为原子操作。该操作使用释放内存排序语义。 |
| `InterlockedIncrementNoFence` | 对指定的 32 位变量的值进行递增（增加一），作为原子操作。该操作是原子的，但不使用内存屏障。 |

`OR`功能：

| **Interlocked function** | **Description** |
| --- | --- |
| `InterlockedOr` | 对指定的`LONG`值执行原子`OR`操作。 |
| `InterlockedOrAcquire` | 对指定的`LONG`值执行原子`OR`操作。该操作使用获取内存排序语义。 |
| `InterlockedOrRelease` | 对指定的`LONG`值执行原子`OR`操作。该操作使用释放内存排序语义。 |
| `InterlockedOrNoFence` | 对指定的`LONG`值执行原子`OR`操作。该操作是原子的，但不使用内存屏障。 |

最后，独占`OR`（`XOR`）功能包括：

| **Interlocked function** | **Description** |
| --- | --- |
| `InterlockedXor` | 对指定的`LONG`值执行原子`XOR`操作。 |
| `InterlockedXorAcquire` | 对指定的`LONG`值执行原子`XOR`操作。该操作使用获取内存排序语义。 |
| `InterlockedXorRelease` | 对指定的`LONG`值执行原子`XOR`操作。该操作使用释放内存排序语义执行。 |
| `InterlockedXorNoFence` | 对指定的`LONG`值执行原子`XOR`操作。该操作是原子执行的，但不使用内存屏障。 |

# GCC

与 Visual C++一样，GCC 也配备了一组内置的原子函数。这些函数根据所使用的 GCC 版本和标准库的底层架构而异。由于 GCC 在比 VC++更多的平台和操作系统上使用，这在考虑可移植性时绝对是一个重要因素。

例如，在 x86 平台上提供的并非每个内置的原子函数都在 ARM 上可用，部分原因是由于架构差异，包括特定 ARM 架构的变化。例如，ARMv6、ARMv7 或当前的 ARMv8，以及 Thumb 指令集等。

在 C++11 标准之前，GCC 使用了`__sync-prefixed`扩展来进行原子操作：

```cpp
type __sync_fetch_and_add (type *ptr, type value, ...) 
type __sync_fetch_and_sub (type *ptr, type value, ...) 
type __sync_fetch_and_or (type *ptr, type value, ...) 
type __sync_fetch_and_and (type *ptr, type value, ...) 
type __sync_fetch_and_xor (type *ptr, type value, ...) 
type __sync_fetch_and_nand (type *ptr, type value, ...) 
```

这些操作从内存中获取一个值，并对其执行指定的操作，返回内存中的值。这些都使用内存屏障。

```cpp
type __sync_add_and_fetch (type *ptr, type value, ...) 
type __sync_sub_and_fetch (type *ptr, type value, ...) 
type __sync_or_and_fetch (type *ptr, type value, ...) 
type __sync_and_and_fetch (type *ptr, type value, ...) 
type __sync_xor_and_fetch (type *ptr, type value, ...) 
type __sync_nand_and_fetch (type *ptr, type value, ...) 
```

这些操作与第一组类似，只是它们在指定操作后返回新值。

```cpp
bool __sync_bool_compare_and_swap (type *ptr, type oldval, type newval, ...) 
type __sync_val_compare_and_swap (type *ptr, type oldval, type newval, ...) 
```

这些比较操作将在旧值匹配提供的值时写入新值。布尔变体在写入新值时返回 true。

```cpp
__sync_synchronize (...) 
```

该函数创建一个完整的内存屏障。

```cpp
type __sync_lock_test_and_set (type *ptr, type value, ...) 
```

该方法实际上是一个交换操作，与名称所示不同。它更新指针值并返回先前的值。这不使用完整的内存屏障，而是使用获取屏障，这意味着它不会释放屏障。

```cpp
void __sync_lock_release (type *ptr, ...) 
```

该函数释放前一方法获得的屏障。

为了适应 C++11 内存模型，GCC 添加了`__atomic`内置方法，这也大大改变了 API：

```cpp
type __atomic_load_n (type *ptr, int memorder) 
void __atomic_load (type *ptr, type *ret, int memorder) 
void __atomic_store_n (type *ptr, type val, int memorder) 
void __atomic_store (type *ptr, type *val, int memorder) 
type __atomic_exchange_n (type *ptr, type val, int memorder) 
void __atomic_exchange (type *ptr, type *val, type *ret, int memorder) 
bool __atomic_compare_exchange_n (type *ptr, type *expected, type desired, bool weak, int success_memorder, int failure_memorder) 
bool __atomic_compare_exchange (type *ptr, type *expected, type *desired, bool weak, int success_memorder, int failure_memorder) 
```

首先是通用的加载、存储和交换函数。它们相当容易理解。加载函数读取内存中的值，存储函数将值存储在内存中，交换函数交换现有值和新值。比较和交换函数使交换有条件。

```cpp
type __atomic_add_fetch (type *ptr, type val, int memorder) 
type __atomic_sub_fetch (type *ptr, type val, int memorder) 
type __atomic_and_fetch (type *ptr, type val, int memorder) 
type __atomic_xor_fetch (type *ptr, type val, int memorder) 
type __atomic_or_fetch (type *ptr, type val, int memorder) 
type __atomic_nand_fetch (type *ptr, type val, int memorder) 
```

这些函数本质上与旧 API 中的函数相同，返回特定操作的结果。

```cpp
type __atomic_fetch_add (type *ptr, type val, int memorder) 
type __atomic_fetch_sub (type *ptr, type val, int memorder) 
type __atomic_fetch_and (type *ptr, type val, int memorder) 
type __atomic_fetch_xor (type *ptr, type val, int memorder) 
type __atomic_fetch_or (type *ptr, type val, int memorder) 
type __atomic_fetch_nand (type *ptr, type val, int memorder) 
```

同样的函数，针对新 API 进行了更新。这些函数返回操作前的原始值。

```cpp
bool __atomic_test_and_set (void *ptr, int memorder) 
```

与旧 API 中同名函数不同，该函数执行真正的测试和设置操作，而不是旧 API 函数的交换操作，后者仍然需要在之后释放内存屏障。测试是针对某个定义的值。

```cpp
void __atomic_clear (bool *ptr, int memorder) 
```

该函数清除指针地址，将其设置为`0`。

```cpp
void __atomic_thread_fence (int memorder) 
```

使用该函数可以在线程之间创建同步内存屏障（fence）。

```cpp
void __atomic_signal_fence (int memorder) 
```

该函数在线程和同一线程内的信号处理程序之间创建内存屏障。

```cpp
bool __atomic_always_lock_free (size_t size, void *ptr) 
```

该函数检查指定大小的对象是否总是为当前处理器架构创建无锁原子指令。

```cpp
bool __atomic_is_lock_free (size_t size, void *ptr) 
```

这本质上与之前的函数相同。

# 内存顺序

在 C++11 内存模型中，并非总是使用内存屏障（fences）进行原子操作。在 GCC 内置原子 API 中，这在其函数的`memorder`参数中反映出来。该参数的可能值直接映射到 C++11 原子 API 中的值：

+   `__ATOMIC_RELAXED`：意味着没有线程间排序约束。

+   `__ATOMIC_CONSUME`：由于 C++11 对`memory_order_consume`的语义存在缺陷，目前使用更强的`__ATOMIC_ACQUIRE`内存顺序来实现。

+   `__ATOMIC_ACQUIRE`：从释放（或更强）语义存储到此获取加载创建一个线程间 happens-before 约束

+   `__ATOMIC_RELEASE`: 创建一个跨线程 happens-before 约束，以获取（或更强）语义加载以从此释放存储中读取。

+   `__ATOMIC_ACQ_REL`: 结合了`__ATOMIC_ACQUIRE`和`__ATOMIC_RELEASE`的效果。

+   `__ATOMIC_SEQ_CST`: 强制与所有其他`__ATOMIC_SEQ_CST`操作进行完全排序。

上述列表是从 GCC 手册的 GCC 7.1 原子章节中复制的。连同该章节中的注释，这清楚地表明在实现 C++11 原子支持以及编译器实现中都做出了权衡。

由于原子依赖于底层硬件支持，永远不会有一个使用原子的代码能够在各种不同的架构上运行。

# 其他编译器

当然，C/C++有许多不同于 VC++和 GCC 的编译器工具链，包括英特尔编译器集合（ICC）和其他通常是专有工具。所有这些都有自己的内置原子函数集。幸运的是，由于 C++11 标准，我们现在在编译器之间有了一个完全可移植的原子标准。一般来说，这意味着除了非常特定的用例（或者维护现有代码），人们会使用 C++标准而不是特定于编译器的扩展。

# C++11 原子

为了使用本地 C++11 原子特性，我们只需要包含`<atomic>`头文件。这将使`atomic`类可用，该类使用模板来使自己适应所需的类型，并具有大量预定义的 typedef：

| **Typedef name** | **Full specialization** |
| --- | --- |
| `std::atomic_bool` | `std::atomic<bool>` |
| `std::atomic_char` | `std::atomic<char>` |
| `std::atomic_schar` | `std::atomic<signed char>` |
| `std::atomic_uchar` | `std::atomic<unsigned char>` |
| `std::atomic_short` | `std::atomic<short>` |
| `std::atomic_ushort` | `std::atomic<unsigned short>` |
| `std::atomic_int` | `std::atomic<int>` |
| `std::atomic_uint` | `std::atomic<unsigned int>` |
| `std::atomic_long` | `std::atomic<long>` |
| `std::atomic_ulong` | `std::atomic<unsigned long>` |
| `std::atomic_llong` | `std::atomic<long long>` |
| `std::atomic_ullong` | `std::atomic<unsigned long long>` |
| `std::atomic_char16_t` | `std::atomic<char16_t>` |
| `std::atomic_char32_t` | `std::atomic<char32_t>` |
| `std::atomic_wchar_t` | `std::atomic<wchar_t>` |
| `std::atomic_int8_t` | `std::atomic<std::int8_t>` |
| `std::atomic_uint8_t` | `std::atomic<std::uint8_t>` |
| `std::atomic_int16_t` | `std::atomic<std::int16_t>` |
| `std::atomic_uint16_t` | `std::atomic<std::uint16_t>` |
| `std::atomic_int32_t` | `std::atomic<std::int32_t>` |
| `std::atomic_uint32_t` | `std::atomic<std::uint32_t>` |
| `std::atomic_int64_t` | `std::atomic<std::int64_t>` |
| `std::atomic_uint64_t` | `std::atomic<std::uint64_t>` |
| `std::atomic_int_least8_t` | `std::atomic<std::int_least8_t>` |
| `std::atomic_uint_least8_t` | `std::atomic<std::uint_least8_t>` |
| `std::atomic_int_least16_t` | `std::atomic<std::int_least16_t>` |
| `std::atomic_uint_least16_t` | `std::atomic<std::uint_least16_t>` |
| `std::atomic_int_least32_t` | `std::atomic<std::int_least32_t>` |
| `std::atomic_uint_least32_t` | `std::atomic<std::uint_least32_t>` |
| `std::atomic_int_least64_t` | `std::atomic<std::int_least64_t>` |
| `std::atomic_uint_least64_t` | `std::atomic<std::uint_least64_t>` |
| `std::atomic_int_fast8_t` | `std::atomic<std::int_fast8_t>` |
| `std::atomic_uint_fast8_t` | `std::atomic<std::uint_fast8_t>` |
| `std::atomic_int_fast16_t` | `std::atomic<std::int_fast16_t>` |
| `std::atomic_uint_fast16_t` | `std::atomic<std::uint_fast16_t>` |
| `std::atomic_int_fast32_t` | `std::atomic<std::int_fast32_t>` |
| `std::atomic_uint_fast32_t` | `std::atomic<std::uint_fast32_t>` |
| `std::atomic_int_fast64_t` | `std::atomic<std::int_fast64_t>` |
| `std::atomic_uint_fast64_t` | `std::atomic<std::uint_fast64_t>` |
| `std::atomic_intptr_t` | `std::atomic<std::intptr_t>` |
| `std::atomic_uintptr_t` | `std::atomic<std::uintptr_t>` |
| `std::atomic_size_t` | `std::atomic<std::size_t>` |
| `std::atomic_ptrdiff_t` | `std::atomic<std::ptrdiff_t>` |
| `std::atomic_intmax_t` | `std::atomic<std::intmax_t>` |
| `std::atomic_uintmax_t` | `std::atomic<std::uintmax_t>` |

这个`atomic`类定义了以下通用函数：

| **函数** | **描述** |
| --- | --- |
| `operator=` | 为原子对象赋值。 |
| `is_lock_free` | 如果原子对象是无锁的，则返回 true。 |
| `store` | 用非原子参数原子地替换原子对象的值。 |
| `load` | 原子地获取原子对象的值。 |
| `operator T` | 从原子对象中加载一个值。 |
| `exchange` | 原子地用新值替换对象的值并返回旧值。 |
| `compare_exchange_weak``compare_exchange_strong` | 原子地比较对象的值，如果相等则交换值，否则返回当前值。 |

随着 C++17 的更新，添加了`is_always_lock_free`常量。这允许我们查询类型是否总是无锁。

最后，我们有专门的`atomic`函数：

| **函数** | **描述** |
| --- | --- |
| `fetch_add` | 原子地将参数添加到`atomic`对象中存储的值并返回旧值。 |
| `fetch_sub` | 原子地从`atomic`对象中减去参数并返回旧值。 |
| `fetch_and` | 在参数和`atomic`对象的值之间原子地执行位`AND`并返回旧值。 |
| `fetch_or` | 在参数和`atomic`对象的值之间原子地执行位`OR`并返回旧值。 |
| `fetch_xor` | 在参数和`atomic`对象的值之间原子地执行位`XOR`并返回旧值。 |
| `operator++``operator++(int)``operator--``operator--(int)` | 将原子值增加或减少一。 |
| `operator+=``operator-=``operator&=``operator&#124;=``operator^=` | 添加、减去或执行位`AND`、`OR`、`XOR`操作。 |

# 示例

使用`fetch_add`的基本示例如下：

```cpp
#include <iostream> 
#include <thread> 
#include <atomic> 

std::atomic<long long> count; 
void worker() { 
         count.fetch_add(1, std::memory_order_relaxed); 
} 

int main() { 
         std::thread t1(worker); 
         std::thread t2(worker); 
         std::thread t3(worker); 
         std::thread t4(worker); 
         std::thread t5(worker); 

         t1.join(); 
         t2.join(); 
         t3.join(); 
         t4.join(); 
         t5.join(); 

         std::cout << "Count value:" << count << 'n'; 
} 
```

这个示例代码的结果将是`5`。正如我们在这里看到的，我们可以用原子操作来实现一个基本的计数器，而不必使用任何互斥锁或类似的东西来提供线程同步。

# 非类函数

除了`atomic`类之外，`<atomic>`头文件中还定义了一些基于模板的函数，我们可以以更类似于编译器内置的原子函数的方式使用：

| **函数** | **描述** |
| --- | --- |
| `atomic_is_lock_free` | 检查原子类型的操作是否是无锁的。 |
| `atomic_storeatomic_store_explicit` | 原子地用非原子参数替换`atomic`对象的值。 |
| `atomic_load``atomic_load_explicit` | 原子地获取存储在`atomic`对象中的值。 |
| `atomic_exchange``atomic_exchange_explicit` | 原子地用非原子参数替换`atomic`对象的值并返回`atomic`的旧值。 |
| `atomic_compare_exchange_weak``atomic_compare_exchange_weak_explicit``atomic_compare_exchange_strong``atomic_compare_exchange_strong_explicit` | 原子地比较`atomic`对象的值和非原子参数，并在相等时执行原子交换，否则执行原子加载。 |
| `atomic_fetch_add``atomic_fetch_add_explicit` | 将非原子值添加到`atomic`对象中并获取`atomic`的先前值。 |
| `atomic_fetch_sub``atomic_fetch_sub_explicit` | 从`atomic`对象中减去非原子值并获取`atomic`的先前值。 |
| `atomic_fetch_and``atomic_fetch_and_explicit` | 用非原子参数的逻辑`AND`结果替换`atomic`对象并获取原子的先前值。 |
| `atomic_fetch_or``atomic_fetch_or_explicit` | 用非原子参数的逻辑`OR`结果替换`atomic`对象，并获取`atomic`的先前值。 |
| `atomic_fetch_xor``atomic_fetch_xor_explicit` | 用非原子参数的逻辑`XOR`结果替换`atomic`对象，并获取`atomic`的先前值。 |
| `atomic_flag_test_and_set``atomic_flag_test_and_set_explicit` | 原子地将标志设置为`true`并返回其先前的值。 |
| `atomic_flag_clear``atomic_flag_clear_explicit` | 原子地将标志的值设置为`false`。 |
| `atomic_init` | 默认构造的`atomic`对象的非原子初始化。 |
| `kill_dependency` | 从`std::memory_order_consume`依赖树中移除指定的对象。 |
| `atomic_thread_fence` | 通用的内存顺序相关的栅栏同步原语。 |
| `atomic_signal_fence` | 在同一线程中的线程和信号处理程序之间设置栅栏。 |

常规和显式函数之间的区别在于后者允许实际设置要使用的内存顺序。前者总是使用`memory_order_seq_cst`作为内存顺序。

# 示例

在这个使用`atomic_fetch_sub`的示例中，一个带索引的容器被多个线程同时处理，而不使用锁：

```cpp
#include <string> 
#include <thread> 
#include <vector> 
#include <iostream> 
#include <atomic> 
#include <numeric> 

const int N = 10000; 
std::atomic<int> cnt; 
std::vector<int> data(N); 

void reader(int id) { 
         for (;;) { 
               int idx = atomic_fetch_sub_explicit(&cnt, 1, std::memory_order_relaxed); 
               if (idx >= 0) { 
                           std::cout << "reader " << std::to_string(id) << " processed item " 
                                       << std::to_string(data[idx]) << 'n'; 
               }  
         else { 
                           std::cout << "reader " << std::to_string(id) << " done.n"; 
                           break; 
               } 
         } 
} 

int main() { 
         std::iota(data.begin(), data.end(), 1); 
         cnt = data.size() - 1; 

         std::vector<std::thread> v; 
         for (int n = 0; n < 10; ++n) { 
               v.emplace_back(reader, n); 
         } 

         for (std::thread& t : v) { 
               t.join(); 
         } 
} 
```

这个示例代码使用了一个大小为*N*的整数向量作为数据源，用 1 填充它。原子计数器对象设置为数据向量的大小。之后，创建了 10 个线程（使用向量的`emplace_back` C++11 特性就地初始化），运行`reader`函数。

在该函数中，我们使用`atomic_fetch_sub_explicit`函数从内存中读取索引计数器的当前值，这使我们能够使用`memory_order_relaxed`内存顺序。该函数还从这个旧值中减去我们传递的值，将索引减少 1。

只要我们以这种方式获得的索引号大于或等于零，函数就会继续，否则它将退出。一旦所有线程都完成了，应用程序就会退出。

# 原子标志

`std::atomic_flag`是一个原子布尔类型。与`atomic`类的其他特化不同，它保证是无锁的。然而，它不提供任何加载或存储操作。

相反，它提供了赋值运算符，以及清除或`test_and_set`标志的函数。前者将标志设置为`false`，后者将测试并将其设置为`true`。

# 内存顺序

这个属性在`<atomic>`头文件中被定义为一个枚举：

```cpp
enum memory_order { 
    memory_order_relaxed, 
    memory_order_consume, 
    memory_order_acquire, 
    memory_order_release, 
    memory_order_acq_rel, 
    memory_order_seq_cst 
}; 
```

在 GCC 部分，我们已经简要涉及了内存顺序的话题。如前所述，这是底层硬件架构特征的一部分。

基本上，内存顺序决定了非原子内存访问在原子操作周围的顺序（内存访问顺序）。这会影响不同线程在执行指令时如何看到内存中的数据：

| **枚举** | **描述** |
| --- | --- |
| `memory_order_relaxed` | 松散操作：对其他读取或写入没有同步或排序约束，只有这个操作的原子性是有保证的。 |
| `memory_order_consume` | 具有这种内存顺序的加载操作在受影响的内存位置上执行*consume 操作*：当前加载之前的当前线程中对当前加载的值的依赖变量的读取或写入不能被重新排序。在其他释放相同原子变量的数据依赖变量的写入对当前线程可见。在大多数平台上，这只影响编译器优化。 |
| `memory_order_acquire` | 具有此内存顺序的加载操作在受影响的内存位置上执行*获取操作*：在此加载之前，当前线程中的任何读取或写入都不能被重新排序。释放相同原子变量的其他线程中的所有写入对于当前线程都是可见的。 |
| `memory_order_release` | 具有此内存顺序的存储操作执行*释放操作*：在此存储之后，当前线程中的任何读取或写入都不能被重新排序。当前线程中的所有写入对于获取相同原子变量的其他线程都是可见的，并且对原子变量进行依赖的写入也对于消费相同原子的其他线程是可见的。 |
| `memory_order_acq_rel` | 具有此内存顺序的读-修改-写操作既是*获取操作*又是*释放操作*。当前线程中的任何内存读取或写入都不能在此存储之前或之后被重新排序。释放相同原子变量的其他线程中的所有写入在修改之前是可见的，并且对于获取相同原子变量的其他线程来说，修改是可见的。 |
| `memory_order_seq_cst` | 具有此内存顺序的任何操作既是*获取操作*又是*释放操作*，并且存在一个单一的总顺序，所有线程都以相同的顺序观察到所有修改。 |

# 松散排序

在松散内存排序中，并没有对并发内存访问之间的顺序进行强制。这种类型的排序只保证了原子性和修改顺序。

这种类型的排序的典型用途是用于计数器，无论是增加还是减少，就像我们在上一节的示例代码中看到的那样。

# 释放-获取排序

如果线程 A 中的原子存储标记为`memory_order_release`，并且线程 B 中从相同变量进行的原子加载标记为`memory_order_acquire`，则所有内存写入（非原子和松散原子）在线程 A 的视角中发生在原子存储之前，都会成为线程 B 中的*可见副作用*。也就是说，一旦原子加载完成，线程 B 就能够看到线程 A 写入内存的所有内容。

这种类型的操作在所谓的强顺序架构上是自动的，包括 x86、SPARC 和 POWER。弱顺序架构，如 ARM、PowerPC 和 Itanium，将需要在这里使用内存屏障。

这种类型的内存排序的典型应用包括互斥机制，比如互斥锁或原子自旋锁。

# 释放-消费排序

如果线程 A 中的原子存储标记为`memory_order_release`，并且线程 B 中从相同变量进行的原子加载标记为`memory_order_consume`，则所有内存写入（非原子和松散原子）在线程 A 的视角中在原子存储之前是*依赖排序*的，这些操作在线程 B 中成为*可见副作用*，并且加载操作*携带依赖性*。也就是说，一旦原子加载完成，线程 B 中使用从加载中获得的值的那些运算符和函数都能够看到线程 A 写入内存的内容。

这种类型的排序在几乎所有架构上都是自动的。唯一的主要例外是（已过时的）Alpha 架构。这种类型排序的典型用例是对很少被更改的数据进行读取访问。

截至 C++17，这种类型的内存排序正在进行修订，暂时不建议使用`memory_order_consume`。

# 顺序一致排序

标记为`memory_order_seq_cst`的原子操作不仅对内存进行排序（在一个线程中存储之前发生的所有事情都成为了加载线程中的*可见副作用*），而且还建立了所有被标记的原子操作的*单一总修改顺序*。

这种排序可能在所有消费者必须以完全相同的顺序观察其他线程所做的更改的情况下是必要的。这在多核或多 CPU 系统上需要完整的内存屏障。

由于这种复杂的设置，这种排序比其他类型要慢得多。它还要求每个原子操作都必须带有这种类型的内存排序标记，否则顺序排序将丢失。

# volatile 关键字

`volatile`关键字对于编写复杂的多线程代码的人来说可能非常熟悉。它的基本用途是告诉编译器相关变量应始终从内存中加载，永远不要对其值进行假设。它还确保编译器不会对变量进行任何激进的优化。

对于多线程应用程序，它通常是无效的，但不鼓励使用。volatile 规范的主要问题是它没有定义多线程内存模型，这意味着这个关键字的结果可能在不同平台、CPU 甚至工具链上都不是确定的。

在原子操作领域，不需要使用这个关键字，实际上使用它可能不会有帮助。为了确保获得在多个 CPU 核心和它们的缓存之间共享的变量的当前版本，人们必须使用像`atomic_compare_exchange_strong`、`atomic_fetch_add`或`atomic_exchange`这样的操作来让硬件获取正确和当前的值。

对于多线程代码，建议不要使用 volatile 关键字，而是使用原子操作，以确保正确的行为。

# 总结

在本章中，我们看了原子操作以及它们如何集成到编译器中，以使代码尽可能与底层硬件紧密配合。读者现在将熟悉原子操作的类型，内存屏障（围栏）的使用，以及内存排序的各种类型及其影响。

读者现在可以在自己的代码中使用原子操作来实现无锁设计，并正确使用 C++11 内存模型。

在下一章中，我们将总结到目前为止学到的一切，摆脱 CPU，转而看看 GPGPU，即在视频卡（GPU）上对数据进行通用处理。


# 第十八章：分布式计算中的多线程

分布式计算是多线程编程的最初应用之一。在每台个人电脑只包含单个处理器和单个核心的时代，政府和研究机构，以及一些公司会拥有多处理器系统，通常以集群的形式存在。这些系统可以进行多线程处理；通过将任务分配到处理器上，它们可以加速各种任务，包括模拟、CGI 电影的渲染等。

如今，几乎每台桌面级或更高级别的系统都有多个处理器核心，并且使用廉价的以太网布线非常容易将多台系统组装成集群。结合 OpenMP 和 Open MPI 等框架，很容易将基于 C++（多线程）的应用程序扩展到分布式系统上。

本章的主题包括：

+   在多线程 C++应用程序中集成 OpenMP 和 MPI

+   实现分布式多线程应用程序

+   分布式多线程编程的常见应用和问题

# 分布式计算简介

当涉及并行处理大型数据集时，如果能够将数据分割成许多小部分，并将其推送到许多线程中，从而显著缩短处理所述数据的总时间，那将是理想的。

分布式计算的理念正是这样：在分布式系统的每个节点上运行我们的应用程序的一个或多个实例，这个应用程序可以是单线程或多线程。由于进程间通信的开销，使用多线程应用程序通常更有效，还有其他可能的优化--由于资源共享。

如果已经有一个准备好使用的多线程应用程序，那么可以直接使用 MPI 使其在分布式系统上运行。否则，OpenMP 是一个编译器扩展（用于 C/C++和 Fortran），可以相对轻松地使应用程序多线程化而无需重构。

为了做到这一点，OpenMP 允许用户标记一个常见的代码段，以便在所有从属线程上执行。主线程创建了许多从属线程，这些线程将同时处理相同的代码段。一个基本的*Hello World* OpenMP 应用程序看起来像这样：

```cpp
/******************************************************************************
 * FILE: omp_hello.c
 * DESCRIPTION:
 *   OpenMP Example - Hello World - C/C++ Version
 *   In this simple example, the master thread forks a parallel region.
 *   All threads in the team obtain their unique thread number and print it.
 *   The master thread only prints the total number of threads.  Two OpenMP
 *   library routines are used to obtain the number of threads and each
 *   thread's number.
 * AUTHOR: Blaise Barney  5/99
 * LAST REVISED: 04/06/05
 ******************************************************************************/
 #include <omp.h>
 #include <stdio.h>
 #include <stdlib.h>

 int main (int argc, char *argv[])  {
    int nthreads, tid;

    /* Fork a team of threads giving them their own copies of variables */
 #pragma omp parallel private(nthreads, tid) {
          /* Obtain thread number */
          tid = omp_get_thread_num();
          printf("Hello World from thread = %dn", tid);

          /* Only master thread does this */
          if (tid == 0) {
                nthreads = omp_get_num_threads();
                printf("Number of threads = %dn", nthreads);
                }

    }  /* All threads join master thread and disband */ 
} 
```

从这个基本示例中很容易看出，OpenMP 通过`<omp.h>`头文件提供了一个基于 C 的 API。我们还可以看到每个线程将执行的部分，由`#pragma omp`预处理器宏标记。

OpenMP 相对于我们在前面章节中看到的多线程代码的优势在于，可以轻松地将代码段标记为多线程，而无需进行任何实际的代码更改。这带来的明显限制是，每个线程实例将执行完全相同的代码，并且进一步的优化选项有限。

# MPI

为了安排在特定节点上执行代码，**MPI**（**消息传递接口**）通常被使用。Open MPI 是这方面的一个免费库实现，被许多高级超级计算机使用。MPICH 是另一个流行的实现。

MPI 本身被定义为并行计算编程的通信协议。它目前处于第三个修订版（MPI-3）。

总之，MPI 提供了以下基本概念：

+   **通信器**：通信器对象连接了 MPI 会话中的一组进程。它为进程分配唯一标识符，并在有序拓扑中安排进程。

+   **点对点操作**：这种操作允许特定进程之间的直接通信。

+   **集体函数**：这些函数涉及在进程组内进行广播通信。它们也可以以相反的方式使用，从进程组中获取所有进程的结果，例如在单个节点上对它们进行求和。更具选择性的版本可以确保特定的数据项被发送到特定的节点。

+   **派生数据类型**：由于 MPI 集群中的每个节点都不能保证具有相同的定义、字节顺序和数据类型的解释，MPI 要求指定每个数据段的类型，以便 MPI 进行数据转换。

+   **单边通信**：这些操作允许在远程内存中写入或读取数据，或者在多个任务之间执行归约操作，而无需在任务之间进行同步。这对于某些类型的算法非常有用，比如涉及分布式矩阵乘法的算法。

+   **动态进程管理**：这是一个允许 MPI 进程创建新的 MPI 进程，或者与新创建的 MPI 进程建立通信的功能。

+   **并行 I/O**：也称为 MPI-IO，这是分布式系统上 I/O 管理的抽象，包括文件访问，方便与 MPI 一起使用。

其中，MPI-IO、动态进程管理和单边通信是 MPI-2 的特性。由于从基于 MPI-1 的代码迁移和动态进程管理与某些设置不兼容，以及许多应用程序不需要 MPI-2 的特性，MPI-2 的采用速度相对较慢。

# 实现

MPI 的最初实现是由阿贡国家实验室（ANL）和密西西比州立大学开发的 MPICH。它目前是最受欢迎的实现之一，被用作 MPI 实现的基础，包括 IBM（蓝色基因）、英特尔、QLogic、Cray、Myricom、微软、俄亥俄州立大学（MVAPICH）等公司的实现。

另一个非常常见的实现是 Open MPI，它是由三个 MPI 实现合并而成的：

+   FT-MPI（田纳西大学）

+   洛斯阿拉莫斯国家实验室（LA-MPI）

+   LAM/MPI（印第安纳大学）

这些术语，以及斯图加特大学的 PACX-MPI 团队，是 Open MPI 团队的创始成员。Open MPI 的主要目标之一是创建一个高质量的开源 MPI-3 实现。

MPI 实现必须支持 C 和 Fortran。C/C++和 Fortran 以及汇编支持非常普遍，还有其他语言的绑定。

# 使用 MPI

无论选择哪种实现，结果的 API 都将始终符合官方 MPI 标准，只有所选择的库支持的 MPI 版本不同。任何 MPI 实现都应该支持所有 MPI-1（修订版 1.3）的特性。

这意味着无论选择哪个库，MPI 的典型 Hello World（例如，在 MPI 教程网站上找到的）应该都能工作：

```cpp
#include <mpi.h> 
#include <stdio.h> 

int main(int argc, char** argv) { 
         // Initialize the MPI environment 
         MPI_Init(NULL, NULL); 

         // Get the number of processes 
         int world_size; 
         MPI_Comm_size(MPI_COMM_WORLD, &world_size); 

         // Get the rank of the process 
         int world_rank; 
         MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); 

         // Get the name of the processor 
         char processor_name[MPI_MAX_PROCESSOR_NAME]; 
         int name_len; 
         MPI_Get_processor_name(processor_name, &name_len); 

         // Print off a hello world message 
         printf("Hello world from processor %s, rank %d" 
                     " out of %d processorsn", 
                     processor_name, world_rank, world_size); 

         // Finalize the MPI environment. 
         MPI_Finalize(); 
} 
```

阅读这个基于 MPI 的应用程序的基本示例时，熟悉 MPI 使用的术语是很重要的，特别是：

+   **世界**：这个作业的注册 MPI 进程

+   **通信器**：连接会话中所有 MPI 进程的对象

+   **秩**：通信器内的进程的标识符

+   **处理器**：物理 CPU，多核 CPU 的单个核心，或系统的主机名

在这个 Hello World 的例子中，我们可以看到我们包含了`<mpi.h>`头文件。无论我们使用哪种实现，这个 MPI 头文件都是一样的。

初始化 MPI 环境只需要调用一次`MPI_Init()`，此时可以传入两个参数，这两个参数都是可选的。

获取世界的大小（即可用进程数）是下一步。这是使用`MPI_Comm_size()`完成的，它接受`MPI_COMM_WORLD`全局变量（由 MPI 为我们定义）并使用第二个参数更新该世界中的进程数。

然后我们获得的排名基本上是 MPI 为该进程分配的唯一 ID。使用`MPI_Comm_rank()`执行此 UID。同样，这需要`MPI_COMM_WORLD`变量作为第一个参数，并将我们的数字排名作为第二个参数返回。此排名对于自我识别和进程之间的通信很有用。

获取正在运行的特定硬件的名称也可能很有用，特别是用于诊断目的。为此，我们可以调用`MPI_Get_processor_name()`。返回的字符串将具有全局定义的最大长度，并且将以某种方式标识硬件。此字符串的确切格式由实现定义。

最后，我们打印出我们收集的信息，并在终止应用程序之前清理 MPI 环境。

# 编译 MPI 应用程序

为了编译 MPI 应用程序，使用`mpicc`编译器包装器。这个可执行文件应该是已安装的任何 MPI 实现的一部分。

然而，使用它与使用例如 GCC 是相同的：

```cpp
    $ mpicc -o mpi_hello_world mpi_hello_world.c
```

这可以与：

```cpp
    $ gcc mpi_hello_world.c -lmsmpi -o mpi_hello_world
```

这将编译和链接我们的 Hello World 示例为一个二进制文件，准备执行。然而，执行此二进制文件不是直接启动它，而是使用启动器，如下所示：

```cpp
    $ mpiexec.exe -n 4 mpi_hello_world.exe
    Hello world from processor Generic_PC, rank 0 out of 4 processors
    Hello world from processor Generic_PC, rank 2 out of 4 processors
    Hello world from processor Generic_PC, rank 1 out of 4 processors
    Hello world from processor Generic_PC, rank 3 out of 4 processors

```

前面的输出来自在 Windows 系统上运行的 Bash shell 中的 Open MPI。正如我们所看到的，我们总共启动了四个进程（4 个排名）。处理器名称报告为每个进程的主机名（“PC”）。

用于启动 MPI 应用程序的二进制文件称为 mpiexec 或 mpirun，或 orterun。这些是相同二进制文件的同义词，尽管并非所有实现都具有所有同义词。对于 Open MPI，所有三者都存在，可以使用其中任何一个。

# 集群硬件

MPI 基于或类似应用程序将运行的系统由多个独立系统（节点）组成，每个系统都使用某种网络接口连接到其他系统。对于高端应用程序，这些往往是具有高速、低延迟互连的定制节点。在光谱的另一端是所谓的 Beowulf 和类似类型的集群，由标准（台式）计算机组成，通常使用常规以太网连接。

在撰写本文时，根据 TOP500 榜单，最快的超级计算机是中国无锡国家超级计算中心的 Sunway TaihuLight 超级计算机。它使用了总共 40,960 个中国设计的 SW26010 多核 RISC 架构 CPU，每个 CPU 有 256 个核心（分为 4 个 64 核心组），以及四个管理核心。术语“多核”是指一种专门的 CPU 设计，它更注重显式并行性，而不是大多数 CPU 核心的单线程和通用重点。这种类型的 CPU 类似于 GPU 架构和矢量处理器。

每个节点都包含一个 SW26010 和 32GB 的 DDR3 内存。它们通过基于 PCIe 3.0 的网络连接，本身由三级层次结构组成：中央交换网络（用于超级节点），超级节点网络（连接超级节点中的所有 256 个节点）和资源网络，提供对 I/O 和其他资源服务的访问。节点之间的网络带宽为 12GB/秒，延迟约为 1 微秒。

以下图表（来自“Sunway TaihuLight 超级计算机：系统和应用”，DOI：10.1007/s11432-016-5588-7）提供了对该系统的视觉概述：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/916608cf-a01d-43b6-86c2-af46982d0d28.png)

在预算不允许这样复杂和高度定制的系统，或者特定任务不需要这样的方法的情况下，总是可以采用“Beowulf”方法。Beowulf 集群是指由普通计算机系统构建的分布式计算系统。这些可以是基于 Intel 或 AMD 的 x86 系统，现在也流行起了基于 ARM 处理器的系统。

通常希望集群中的每个节点大致相同。虽然可以有不对称的集群，但是当可以对每个节点做出广泛的假设时，管理和作业调度变得更加容易。

至少，希望匹配处理器架构，具有基本的 CPU 扩展，如 SSE2/3，也许还有 AVX 等，所有节点上都通用。这样做可以让您在节点上使用相同的编译二进制文件，以及相同的算法，大大简化作业的部署和代码库的维护。

对于节点之间的网络，以太网是一个非常受欢迎的选项，传输时间以十到百微秒计，成本只是更快选项的一小部分。通常，每个节点都会连接到一个以太网网络，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/28e8fc11-68fd-4692-9f6e-93250348f221.png)

还有一个选项，可以为每个或特定节点添加第二甚至第三个以太网链接，使它们可以访问文件、I/O 和其他资源，而无需在主要网络层上竞争带宽。对于非常大的集群，可以考虑一种类似于 Sunway TaihuLight 和许多其他超级计算机使用的方法：将节点分割成超级节点，每个节点都有自己的节点间网络。这将允许通过限制只与相关节点通信来优化网络流量。

这样优化的 Beowulf 集群的示例将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/8a4a767b-6ab9-4f17-bc91-63a04a9452cf.png)

显然，基于 MPI 的集群有各种可能的配置，利用定制的、现成的或两种硬件类型的组合。集群的预期用途通常决定了特定集群的最佳布局，例如运行模拟或处理大型数据集。每种类型的作业都有自己的一套限制和要求，这也反映在软件实现中。

# 安装 Open MPI

在本章的其余部分，我们将专注于 Open MPI。为了获得 Open MPI 的工作开发环境，需要安装其头文件和库文件，以及支持工具和二进制文件。

# Linux 和 BSD

在具有软件包管理系统的 Linux 和 BSD 发行版上，这很容易：只需安装 Open MPI 软件包，一切都应该设置和配置好，准备好使用。查阅特定发行版的手册，了解如何搜索和安装特定软件包。

在基于 Debian 的发行版上，可以使用：

```cpp
    $ sudo apt-get install openmpi-bin openmpi-doc libopenmpi-dev
```

上述命令将安装 Open MPI 二进制文件、文档和开发头文件。计算节点上可以省略最后两个软件包。

# Windows

在 Windows 上，情况变得稍微复杂，主要是因为 Visual C++和相应的编译器工具链的主导地位。如果希望在 Linux 或 BSD 上使用与之相同的开发环境，使用 MinGW，就需要采取一些额外的步骤。

本章假设使用 GCC 或 MinGW。如果希望使用 Visual Studio 环境开发 MPI 应用程序，请查阅相关文档。

最易于使用且最新的 MinGW 环境是 MSYS2，它提供了一个 Bash shell，以及大多数在 Linux 和 BSD 下熟悉的工具。它还具有 Pacman 软件包管理器，正如 Linux Arch 发行版所知。使用这个软件包管理器，可以轻松安装 Open MPI 开发所需的软件包。

从[`msys2.github.io/`](https://msys2.github.io/)安装 MSYS2 环境后，安装 MinGW 工具链：

```cpp
    $ pacman -S base-devel mingw-w64-x86_64-toolchain
```

这假设安装了 64 位版本的 MSYS2。对于 32 位版本，请选择 i686 而不是 x86_64。安装了这些软件包后，我们将同时安装 MinGW 和基本开发工具。为了使用它们，使用 MinGW 64 位后缀的名称启动一个新的 shell，可以通过开始菜单中的快捷方式，或者通过 MSYS2 `install`文件夹中的可执行文件来实现。

准备好 MinGW 后，现在是安装 MS-MPI 版本 7.x 的时候了。这是微软在 Windows 上使用 MPI 的最简单的方法。它是 MPI-2 规范的实现，与 MPICH2 参考实现大部分兼容。由于 MS-MPI 库在不同版本之间不兼容，我们使用这个特定的版本。

尽管 MS-MPI 的第 7 版已经存档，但仍然可以通过 Microsoft 下载中心下载，网址为[`www.microsoft.com/en-us/download/details.aspx?id=49926`](https://www.microsoft.com/en-us/download/details.aspx?id=49926)。

MS-MPI 版本 7 带有两个安装程序，`msmpisdk.msi`和`MSMpiSetup.exe`。都需要安装。之后，我们应该能够打开一个新的 MSYS2 shell，并找到以下环境变量设置：

```cpp
    $ printenv | grep "WIN|MSMPI"
    MSMPI_INC=D:DevMicrosoftSDKsMPIInclude
    MSMPI_LIB32=D:DevMicrosoftSDKsMPILibx86
    MSMPI_LIB64=D:DevMicrosoftSDKsMPILibx64
    WINDIR=C:Windows
```

printenv 命令的输出显示 MS-MPI SDK 和运行时已经正确安装。接下来，我们需要将 Visual C++ LIB 格式的静态库转换为 MinGW A 格式：

```cpp
    $ mkdir ~/msmpi
    $ cd ~/msmpi
    $ cp "$MSMPI_LIB64/msmpi.lib" .
    $ cp "$WINDIR/system32/msmpi.dll" .
    $ gendef msmpi.dll
    $ dlltool -d msmpi.def -D msmpi.dll -l libmsmpi.a
    $ cp libmsmpi.a /mingw64/lib/.
```

我们首先将原始 LIB 文件复制到我们的主文件夹中的一个新临时文件夹中，以及运行时 DLL。接下来，我们使用 gendef 工具处理 DLL，以创建我们需要的定义，以便将其转换为新格式。

最后一步是使用 dlltool，它需要使用定义文件和 DLL，输出一个与 MinGW 兼容的静态库文件。然后我们将该文件复制到 MinGW 在链接时可以找到的位置。

接下来，我们需要复制 MPI 头文件：

```cpp
    $ cp "$MSMPI_INC/mpi.h" .
```

复制这个头文件后，我们必须打开它并找到以下部分：

```cpp
typedef __int64 MPI_Aint 
```

在该行的正上方，我们需要添加以下行：

```cpp
    #include <stdint.h>
```

这个包含添加了`__int64`的定义，这是我们编译代码所需要的。

最后，将头文件复制到 MinGW 的`include`文件夹中：

```cpp
    $ cp mpi.h /mingw64/include
```

有了这些，我们就可以在 MinGW 下进行 MPI 开发所需的库和头文件，从而可以编译和运行之前的 Hello World 示例，并继续进行本章的其余部分。

# 跨节点分发作业

为了在集群中的节点之间分发 MPI 作业，必须将这些节点作为`mpirun`/`mpiexec`命令的参数指定，或者使用主机文件。这个主机文件包含网络上将用于运行的节点的名称，以及主机上可用插槽的数量。

在远程节点上运行 MPI 应用程序的先决条件是在该节点上安装了 MPI 运行时，并且已为该节点配置了无密码访问。这意味着只要主节点安装了 SSH 密钥，它就可以登录到每个节点，以便在其上启动 MPI 应用程序。

# 设置 MPI 节点

在节点上安装 MPI 后，下一步是为主节点设置无密码 SSH 访问。这需要在节点上安装 SSH 服务器（在基于 Debian 的发行版中属于*ssh*软件包的一部分）。之后，我们需要生成并安装 SSH 密钥。

一个简单的方法是在主节点和其他节点上有一个公共用户，并使用 NFS 网络共享或类似的方式在计算节点上挂载主节点上的用户文件夹。这样所有节点都将拥有相同的 SSH 密钥和已知主机文件。这种方法的一个缺点是缺乏安全性。对于连接到互联网的集群来说，这不是一个很好的方法。

然而，以相同用户在每个节点上运行作业绝对是一个好主意，以防止任何可能的权限问题，特别是在使用文件和其他资源时。通过在每个节点上创建一个公共用户帐户，并生成 SSH 密钥，我们可以使用以下命令将公钥传输到节点：

```cpp
    $ ssh-copy-id mpiuser@node1
```

或者，在设置节点系统时，我们可以将公钥复制到节点系统的`authorized_keys`文件中。如果要创建和配置大量节点，最好使用镜像复制到每个节点的系统驱动器上，使用设置脚本，或者可能通过 PXE 引导从镜像启动。

完成了这一步，主节点现在可以登录到每个计算节点以运行作业。

# 创建 MPI 主机文件

如前所述，为了在其他节点上运行作业，我们需要指定这些节点。最简单的方法是创建一个文件，其中包含我们希望使用的计算节点的名称，以及可选参数。

为了让我们能够使用节点的名称而不是 IP 地址，我们首先需要修改操作系统的主机文件：例如，在 Linux 上是`/etc/hosts`。

```cpp
    192.168.0.1 master
    192.168.0.2 node0
    192.168.0.3 node1
```

接下来，我们创建一个新文件，这将是用于 MPI 的主机文件：

```cpp
    master
    node0
    node1
```

有了这个配置，作业将在两个计算节点以及主节点上执行。我们可以从这个文件中删除主节点，以防止这种情况发生。

如果没有提供任何可选参数，MPI 运行时将使用节点上的所有可用处理器。如果需要，我们可以限制这个数字：

```cpp
    node0 slots=2
    node1 slots=4
```

假设两个节点都是四核 CPU，这意味着只有 node0 上的一半核心会被使用，而 node1 上的所有核心都会被使用。

# 运行作业

在多个 MPI 节点上运行 MPI 作业基本上与仅在本地执行相同，就像本章前面的示例一样：

```cpp
    $ mpirun --hostfile my_hostfile hello_mpi_world
```

这个命令会告诉 MPI 启动器使用一个名为`my_hostfile`的主机文件，并在该主机文件中找到的每个节点的每个处理器上运行指定的 MPI 应用程序的副本。

# 使用集群调度程序

除了使用手动命令和主机文件在特定节点上创建和启动作业之外，还有集群调度程序应用程序。这些通常涉及在每个节点以及主节点上运行一个守护进程。使用提供的工具，我们可以管理资源和作业，安排分配并跟踪作业状态。

最受欢迎的集群管理调度程序之一是 SLURM，它是 Simple Linux Utility for Resource management 的缩写（尽管现在更名为 Slurm Workload Manager，网站为[`slurm.schedmd.com/`](https://slurm.schedmd.com/)）。它通常被超级计算机以及许多计算机集群所使用。其主要功能包括：

+   使用时间段为特定用户分配对资源（节点）的独占或非独占访问权限

+   在一组节点上启动和监视诸如基于 MPI 的应用程序之类的作业

+   管理待处理作业队列，以调解共享资源的争用

设置集群调度程序对于基本的集群操作并不是必需的，但在运行多个作业同时或者有多个集群用户希望运行自己的作业时，它可能非常有用。

# MPI 通信

此时，我们有一个功能齐全的 MPI 集群，可以用于以并行方式执行基于 MPI 的应用程序（以及其他应用程序）。虽然对于某些任务，只需将几十个或几百个进程发送出去并等待它们完成可能是可以的，但很多时候，这些并行进程能够相互通信是至关重要的。

这就是 MPI（“消息传递接口”）的真正含义所在。在 MPI 作业创建的层次结构中，进程可以以各种方式进行通信和共享数据。最基本的是，它们可以共享和接收消息。

MPI 消息具有以下属性：

+   发送方

+   接收方

+   消息标签（ID）

+   消息中元素的计数

+   一个 MPI 数据类型

发送方和接收方应该是相当明显的。消息标签是发送方可以设置的数字 ID，接收方可以使用它来过滤消息，例如，允许对特定消息进行优先排序。数据类型确定消息中包含的信息类型。

发送和接收函数如下所示：

```cpp
int MPI_Send( 
         void* data, 
         int count, 
         MPI_Datatype datatype, 
         int destination, 
         int tag, 
         MPI_Comm communicator) 

int MPI_Recv( 
         void* data, 
         int count, 
         MPI_Datatype datatype, 
         int source, 
         int tag, 
         MPI_Comm communicator, 
         MPI_Status* status) 
```

这里需要注意的一个有趣的事情是，发送函数中的计数参数表示函数将发送的元素数，而接收函数中的相同参数表示此线程将接受的最大元素数。

通信器指的是正在使用的 MPI 通信器实例，接收函数包含一个最终参数，可用于检查 MPI 消息的状态。

# MPI 数据类型

MPI 定义了许多基本类型，可以直接使用：

| **MPI 数据类型** | **C 等效** |
| --- | --- |
| `MPI_SHORT` | short int |
| `MPI_INT` | int |
| `MPI_LONG` | long int |
| `MPI_LONG_LONG` | long long int |
| `MPI_UNSIGNED_CHAR` | unsigned char |
| `MPI_UNSIGNED_SHORT` | unsigned short int |
| `MPI_UNSIGNED` | unsigned int |
| `MPI_UNSIGNED_LONG` | unsigned long int |
| `MPI_UNSIGNED_LONG_LONG` | unsigned long long int |
| `MPI_FLOAT` | float |
| `MPI_DOUBLE` | double |
| `MPI_LONG_DOUBLE` | long double |
| `MPI_BYTE` | char |

MPI 保证使用这些类型时，接收方将始终以其期望的格式获取消息数据，而不受字节顺序和其他与平台相关的问题的影响。

# 自定义类型

除了这些基本格式之外，还可以创建新的 MPI 数据类型。这些使用了许多 MPI 函数，包括`MPI_Type_create_struct`：

```cpp
int MPI_Type_create_struct( 
   int count,  
   int array_of_blocklengths[], 
         const MPI_Aint array_of_displacements[],  
   const MPI_Datatype array_of_types[], 
         MPI_Datatype *newtype) 
```

使用此函数，可以创建一个包含结构的 MPI 类型，就像使用基本的 MPI 数据类型一样：

```cpp
#include <cstdio> 
#include <cstdlib> 
#include <mpi.h> 
#include <cstddef> 

struct car { 
        int shifts; 
        int topSpeed; 
}; 

int main(int argc, char **argv) { 
         const int tag = 13; 
         int size, rank; 

         MPI_Init(&argc, &argv); 
         MPI_Comm_size(MPI_COMM_WORLD, &size); 

         if (size < 2) { 
               fprintf(stderr,"Requires at least two processes.n"); 
               MPI_Abort(MPI_COMM_WORLD, 1); 
         } 

         const int nitems = 2; 
         int blocklengths[2] = {1,1}; 
   MPI_Datatype types[2] = {MPI_INT, MPI_INT}; 
         MPI_Datatype mpi_car_type; 
         MPI_Aint offsets[2]; 

         offsets[0] = offsetof(car, shifts); 
         offsets[1] = offsetof(car, topSpeed); 

         MPI_Type_create_struct(nitems, blocklengths, offsets, types, &mpi_car_type); 
         MPI_Type_commit(&mpi_car_type); 

         MPI_Comm_rank(MPI_COMM_WORLD, &rank); 
         if (rank == 0) { 
               car send; 
               send.shifts = 4; 
               send.topSpeed = 100; 

               const int dest = 1; 

         MPI_Send(&send, 1, mpi_car_type, dest, tag, MPI_COMM_WORLD); 

               printf("Rank %d: sent structure carn", rank); 
         } 

   if (rank == 1) { 
               MPI_Status status; 
               const int src = 0; 

         car recv; 

         MPI_Recv(&recv, 1, mpi_car_type, src, tag, MPI_COMM_WORLD, &status); 
         printf("Rank %d: Received: shifts = %d topSpeed = %dn", rank, recv.shifts, recv.topSpeed); 
    } 

    MPI_Type_free(&mpi_car_type); 
    MPI_Finalize(); 

         return 0; 
} 
```

在这里，我们看到了一个名为`mpi_car_type`的新 MPI 数据类型是如何定义和用于在两个进程之间传递消息的。要创建这样的结构类型，我们需要定义结构中的项目数，每个块中的元素数，它们的字节位移以及它们的基本 MPI 类型。

# 基本通信

MPI 通信的一个简单示例是从一个进程向另一个进程发送单个值。为了做到这一点，需要使用以下列出的代码，并运行编译后的二进制文件以启动至少两个进程。这些进程是在本地运行还是在两个计算节点上运行并不重要。

以下代码感激地借鉴自[`mpitutorial.com/tutorials/mpi-hello-world/`](http://mpitutorial.com/tutorials/mpi-hello-world/)：

```cpp
#include <mpi.h> 
#include <stdio.h> 
#include <stdlib.h> 

int main(int argc, char** argv) { 
   // Initialize the MPI environment. 
   MPI_Init(NULL, NULL); 

   // Find out rank, size. 
   int world_rank; 
   MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); 
   int world_size; 
   MPI_Comm_size(MPI_COMM_WORLD, &world_size); 

   // We are assuming at least 2 processes for this task. 
   if (world_size < 2) { 
               fprintf(stderr, "World size must be greater than 1 for %s.n", argv[0]); 
               MPI_Abort(MPI_COMM_WORLD, 1); 
   } 

   int number; 
   if (world_rank == 0) { 
         // If we are rank 0, set the number to -1 and send it to process 1\. 
               number = -1; 
               MPI_Send(&number, 1, MPI_INT, 1, 0, MPI_COMM_WORLD); 
   }  
   else if (world_rank == 1) { 
               MPI_Recv(&number, 1, MPI_INT, 0, 0,  
                           MPI_COMM_WORLD,  
                           MPI_STATUS_IGNORE); 
               printf("Process 1 received number %d from process 0.n", number); 
   } 

   MPI_Finalize(); 
} 
```

这段代码并不复杂。我们通过通常的 MPI 初始化，然后检查我们的世界大小是否至少有两个进程。

具有等级 0 的进程将发送一个数据类型为`MPI_INT`且值为`-1`的 MPI 消息。等级为`1`的进程将等待接收此消息。接收进程指定`MPI_Status MPI_STATUS_IGNORE`以指示该进程不会检查消息的状态。这是一种有用的优化技术。

最后，预期的输出如下：

```cpp
    $ mpirun -n 2 ./send_recv_demo
    Process 1 received number -1 from process 0
```

在这里，我们启动了一个总共有两个进程的编译后的演示代码。输出显示第二个进程从第一个进程接收了 MPI 消息，并且值是正确的。

# 高级通信

对于高级 MPI 通信，可以使用`MPI_Status`字段来获取有关消息的更多信息。可以使用`MPI_Probe`在接受消息之前发现消息的大小，然后使用`MPI_Recv`接受消息。这在不事先知道消息大小的情况下非常有用。

# 广播

广播消息意味着世界上的所有进程都会收到它。这简化了广播函数相对于发送函数：

```cpp
int MPI_Bcast( 
   void *buffer,  
   int count,  
   MPI_Datatype datatype, 
         int root,    
   MPI_Comm comm) 
```

接收进程将简单地使用普通的`MPI_Recv`函数。广播函数所做的就是优化使用一种算法同时使用多个网络链接发送多条消息，而不是只使用一个。

# 散射和聚集

散射非常类似于广播消息，但有一个非常重要的区别：它不是在每条消息中发送相同的数据，而是将数组的不同部分发送给每个接收者。其功能定义如下：

```cpp
int MPI_Scatter( 
         void* send_data, 
         int send_count, 
         MPI_Datatype send_datatype, 
         void* recv_data, 
         int recv_count, 
         MPI_Datatype recv_datatype, 
         int root, 
         MPI_Comm communicator) 
```

每个接收进程将获得相同的数据类型，但我们可以指定将发送到每个进程的项目数（`send_count`）。这个函数在发送和接收方都使用，后者只需要定义与接收数据相关的最后一组参数，提供根进程的世界等级和相关的通信器。

聚集是散射的逆过程。在这里，多个进程将发送的数据最终到达单个进程，这些数据按发送它的进程的等级进行排序。其功能定义如下：

```cpp
int MPI_Gather( 
         void* send_data, 
         int send_count, 
         MPI_Datatype send_datatype, 
         void* recv_data, 
         int recv_count, 
         MPI_Datatype recv_datatype, 
         int root, 
         MPI_Comm communicator) 
```

人们可能会注意到这个函数看起来与散射函数非常相似。这是因为它基本上是以相同的方式工作，只是这一次发送节点必须填写与发送数据相关的参数，而接收进程必须填写与接收数据相关的参数。

这里需要注意的是`recv_count`参数与从每个发送进程接收的数据量有关，而不是总大小。

这两个基本功能还有进一步的专业化，但这里不会涉及。

# MPI 与线程

有人可能认为最容易的方法是使用 MPI 将 MPI 应用程序的一个实例分配给每个集群节点上的单个 CPU 核心，这是正确的。然而，这并不是最快的解决方案。

尽管在网络上的进程间通信方面，MPI 可能是最佳选择，但在单个系统（单 CPU 或多 CPU 系统）中，使用多线程是非常有意义的。

这主要是因为线程之间的通信比进程间通信要快得多，特别是在使用诸如 MPI 这样的通用通信层时。

可以编写一个使用 MPI 在集群网络上进行通信的应用程序，其中为每个 MPI 节点分配一个应用程序实例。应用程序本身将检测该系统上的 CPU 核心数量，并为每个核心创建一个线程。因此，混合 MPI，通常被称为，因为它提供了以下优势，因此通常被使用：

+   **更快的通信** - 使用快速的线程间通信。

+   **更少的 MPI 消息** - 更少的消息意味着带宽和延迟的减少。

+   **避免数据重复** - 数据可以在线程之间共享，而不是向一系列进程发送相同的消息。

可以通过使用在前几章中看到的 C++11 和后续版本中找到的多线程功能来实现这一点。另一种选择是使用 OpenMP，就像我们在本章的开头看到的那样。

使用 OpenMP 的明显优势是开发者几乎不需要付出什么努力。如果需要的只是运行相同例程的更多实例，只需要对代码进行少量修改，标记代码用于工作线程即可。

例如：

```cpp
#include <stdio.h>
#include <mpi.h>
#include <omp.h>

int main(int argc, char *argv[]) {
  int numprocs, rank, len;
  char procname[MPI_MAX_PROCESSOR_NAME];
  int tnum = 0, tc = 1;

  MPI_Init(&argc, &argv);
  MPI_Comm_size(MPI_COMM_WORLD, &numprocs);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Get_processor_name(procname, &len);

  #pragma omp parallel default(shared) private(tnum, tc) {
      np = omp_get_num_threads();
      tnum = omp_get_thread_num();
      printf("Thread %d out of %d from process %d out of %d on %sn", 
      tnum, tc, rank, numprocs, procname);
  }

  MPI_Finalize();
}
```

上述代码将 OpenMP 应用程序与 MPI 结合起来。例如，要编译它，我们将运行：

```cpp
$ mpicc -openmp hellohybrid.c -o hellohybrid
```

接下来，要运行应用程序，我们将使用 mpirun 或等效命令：

```cpp
$ export OMP_NUM_THREADS=8
$ mpirun -np 2 --hostfile my_hostfile -x OMP_NUM_THREADS ./hellohybrid
```

mpirun 命令将使用 hellohybrid 二进制文件运行两个 MPI 进程，并将我们使用-x 标志导出的环境变量传递给每个新进程。然后，该变量中包含的值将由 OpenMP 运行时用于创建相应数量的线程。

假设我们的 MPI 主机文件中至少有两个 MPI 节点，我们将在两个节点上运行两个 MPI 进程，每个进程运行八个线程，这将适合具有超线程的四核 CPU 或八核 CPU。

# 潜在问题

在编写基于 MPI 的应用程序并在多核 CPU 或集群上执行时，可能会遇到的问题与我们在前面章节中已经遇到的多线程代码问题非常相似。

然而，使用 MPI 的一个额外担忧是依赖网络资源的可用性。由于用于`MPI_Send`调用的发送缓冲区在网络堆栈处理缓冲区之前无法回收，并且此调用是阻塞类型，发送大量小消息可能导致一个进程等待另一个进程，而另一个进程又在等待调用完成。

在设计 MPI 应用程序的消息传递结构时，应该牢记这种死锁。例如，可以确保一侧没有发送调用积累，这将导致这种情况。提供有关队列深度等的反馈消息可以用于减轻压力。

MPI 还包含使用所谓的屏障的同步机制。这是用于允许 MPI 进程在例如一个任务上进行同步的。使用 MPI 屏障（`MPI_Barrier`）调用与互斥锁类似，如果 MPI 进程无法实现同步，一切都将在此时挂起。

# 总结

在本章中，我们详细研究了 MPI 标准，以及其中一些实现，特别是 Open MPI，并了解了如何设置集群。我们还看到如何使用 OpenMP 轻松地为现有代码添加多线程。

到这一点，读者应该能够建立一个基本的贝奥武夫或类似的集群，为 MPI 进行配置，并在其上运行基本的 MPI 应用程序。应该知道如何在 MPI 进程之间进行通信以及如何定义自定义数据类型。此外，读者将意识到在为 MPI 编程时可能遇到的潜在问题。

在下一章中，我们将汇总前面章节的所有知识，并看看如何在最后一章中将它们结合起来，以便研究通用计算机上的视频卡（GPGPU）。
