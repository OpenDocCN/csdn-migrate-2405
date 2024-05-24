# 将 Linux 迁移到微软 Azure（二）

> 原文：[`zh.annas-archive.org/md5/DFC4E6F489A560394D390945DB597424`](https://zh.annas-archive.org/md5/DFC4E6F489A560394D390945DB597424)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：故障排除性能问题

在第三章中，我们通过使用第一章中介绍的故障排除方法论，以及第二章中找到的几个基本故障排除命令和资源，来解决了 Web 应用程序的问题。

# 性能问题

在本章中，我们将继续在第三章中涵盖的情景，我们是一家新公司的新系统管理员。当我们到达开始我们的一天时，一位同事要求我们调查一个服务器变慢的问题。

在要求详细信息时，我们的同事只能提供主机名和被认为“慢”的服务器的 IP。我们的同行提到一个用户报告了这个问题，而用户并没有提供太多细节。

在这种情况下，与第三章中讨论的情况不同，我们没有太多信息可以开始。似乎我们也无法向用户提出故障排除问题。作为系统管理员，需要用很少的信息来排除问题并不罕见。事实上，这种类型的情况非常普遍。

## 它很慢

“它很慢”很难排除故障。关于服务器或服务变慢的投诉最大的问题是，“慢”是相对于遇到问题的用户而言的。

在处理任何关于性能的投诉时，重要的区别是环境设计的基准。在某些环境中，系统以 30%的 CPU 利用率运行可能是一种常规活动，而其他环境可能会保持系统以 10%的 CPU 利用率运行，30%的利用率会表示问题。

在排除故障和调查性能问题时，重要的是回顾系统的历史性能指标，以确保您对收集到的测量值有上下文。这将有助于确定当前系统利用率是否符合预期或异常。

# 性能

一般来说，性能问题可以分为五个领域：

+   应用程序

+   CPU

+   内存

+   磁盘

+   网络

任何一个领域的瓶颈通常也会影响其他领域；因此，了解每个领域是一个好主意。通过了解如何访问和交互每个资源，您将能够找到消耗多个资源的问题的根本原因。

由于报告的问题没有包括任何性能问题的细节，我们将探索和了解每个领域。完成后，我们将查看收集的数据并查看历史统计数据，以确定性能是否符合预期，或者系统性能是否真的下降了。

## 应用程序

在创建性能类别列表时，我按照我经常看到的领域进行了排序。每个环境都是不同的，但根据我的经验，应用程序通常是性能问题的主要来源。

虽然本章旨在涵盖性能问题，第九章，“使用系统工具排除应用程序”专门讨论了使用系统工具排除应用程序问题，包括性能问题。在本章中，我们将假设我们的问题与应用程序无关，并专注于系统性能。

## CPU

CPU 是一个非常常见的性能瓶颈。有时，问题严格基于 CPU，而其他时候，增加的 CPU 使用率是另一个问题的症状。

调查 CPU 利用率最常见的命令是 top 命令。这个命令的主要作用是识别进程的 CPU 利用率。在第二章，“故障排除命令和有用信息的来源”中，我们讨论了使用`ps`命令进行这种活动。在本节中，我们将使用 top 和 ps 来调查 CPU 利用率，以解决我们的速度慢的问题。

### Top – 查看所有内容的单个命令

`top`命令是系统管理员和用户运行的第一批命令之一，用于查看整体系统性能。原因在于 top 不仅显示了负载平均值、CPU 和内存的详细情况，还显示了利用这些资源的进程的排序列表。

`top`最好的部分是，当不带任何标志运行时，这些详细信息每 3 秒更新一次。

以下是不带任何标志运行时`top`输出的示例。

```
top - 17:40:43 up  4:07,  2 users,  load average: 0.32, 0.43, 0.44
Tasks: 100 total,   2 running,  98 sleeping,   0 stopped,   0 zombie
%Cpu(s): 37.3 us,  0.7 sy,  0.0 ni, 62.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem:    469408 total,   228112 used,   241296 free,      764 buffers
KiB Swap:  1081340 total,        0 used,  1081340 free.    95332 cached Mem

 PID USER      PR  NI    VIRT    RES    SHR S %CPU %MEM     TIME+ COMMAND
 3023 vagrant   20   0    7396    720    504 S 37.6  0.2  91:08.04 lookbusy
 11 root      20   0       0      0      0 R  0.3  0.0   0:13.28 rcuos/0
 682 root      20   0  322752   1072    772 S  0.3  0.2   0:05.60 VBoxService
 1 root      20   0   50784   7256   2500 S  0.0  1.5   0:01.39 systemd
 2 root      20   0       0      0      0 S  0.0  0.0   0:00.00 kthreadd
 3 root      20   0       0      0      0 S  0.0  0.0   0:00.24 ksoftirqd/0
 5 root       0 -20       0      0      0 S  0.0  0.0   0:00.00 kworker/0:0H
 6 root      20   0       0      0      0 S  0.0  0.0   0:00.04 kworker/u2:0
 7 root      rt   0       0      0      0 S  0.0  0.0   0:00.00 migration/0
 8 root      20   0       0      0      0 S  0.0  0.0   0:00.00 rcu_bh
 9 root      20   0       0      0      0 S  0.0  0.0   0:00.00 rcuob/0
 10 root      20   0       0      0      0 S  0.0  0.0   0:05.44 rcu_sched

```

`top`的默认输出中显示了相当多的信息。在本节中，我们将专注于 CPU 利用率信息。

```
%Cpu(s): 37.3 us,  0.7 sy,  0.0 ni, 62.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st

```

`top`命令输出的第一部分显示了当前 CPU 利用率的详细情况。列表中的每一项代表了 CPU 的不同使用方式。为了更好地理解输出结果，让我们来看看每个数值的含义：

+   **us – User**：这个数字表示用户模式中进程所消耗的 CPU 百分比。在这种模式下，应用程序无法访问底层硬件，必须使用系统 API（也称为系统调用）来执行特权操作。在执行这些系统调用时，执行将成为系统 CPU 利用率的一部分。

+   **sy – System**：这个数字表示内核模式执行所消耗的 CPU 百分比。在这种模式下，系统可以直接访问底层硬件；这种模式通常保留给受信任的操作系统进程。

+   **ni – Nice user processes**：这个数字表示由设置了 nice 值的用户进程所消耗的 CPU 时间百分比。`us%`值特指那些未修改过 niceness 值的进程。

+   **id – Idle**：这个数字表示 CPU 空闲的时间百分比。基本上，它是 CPU 未被利用的时间。

+   **wa – Wait**：这个数字表示 CPU 等待的时间百分比。当有很多进程在等待 I/O 设备时，这个值通常很高。I/O 等待状态不仅指硬盘，而是指所有 I/O 设备，包括硬盘。

+   **hi – Hardware interrupts**：这个数字表示由硬件中断所消耗的 CPU 时间百分比。硬件中断是来自系统硬件（如硬盘或网络设备）的信号，发送给 CPU。这些中断表示有事件需要 CPU 时间。

+   **si - 软件中断**：这个数字是被软件中断消耗的 CPU 时间的百分比。软件中断类似于硬件中断；但是，它们是由运行进程发送给内核的信号触发的。

+   **st - 被窃取**：这个数字特别适用于作为虚拟机运行的 Linux 系统。这个数字是被主机从这台机器上窃取的 CPU 时间的百分比。当主机机器本身遇到 CPU 争用时，通常会出现这种情况。在一些云环境中，这也可能发生，作为强制执行资源限制的一种方法。

我之前提到`top`的输出默认每 3 秒刷新一次。CPU 百分比行也每 3 秒刷新一次；`top`将显示自上次刷新间隔以来每个状态的 CPU 时间百分比。

#### 这个输出告诉我们关于我们的问题的什么？

如果我们回顾之前`top`命令的输出，我们可以对这个系统了解很多。

```
%Cpu(s): 37.3 us,  0.7 sy,  0.0 ni, 62.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st

```

从前面的输出中，我们可以看到 CPU 时间的`37.3%`被用户模式下的进程消耗。另外`0.7%`的 CPU 时间被内核执行模式下的进程使用；这是基于`us`和`sy`的值。`id`值告诉我们剩下的 CPU 没有被利用，这意味着总体上，这台服务器上有充足的 CPU 可用。

`top`命令显示的另一个事实是 CPU 时间没有花在等待 I/O 上。我们可以从`wa`值为`0.0`看出。这很重要，因为它告诉我们报告的性能问题不太可能是由于高 I/O。在本章后面，当我们开始探索磁盘性能时，我们将深入探讨 I/O 等待。

#### 来自 top 的单个进程

`top`命令输出中的 CPU 行是整个服务器的摘要，但 top 还包括单个进程的 CPU 利用率。为了更清晰地聚焦，我们可以再次执行 top，但这次，让我们专注于正在运行的`top`进程。

```
$ top -n 1
top - 15:46:52 up  3:21,  2 users,  load average: 1.03, 1.11, 1.06
Tasks: 108 total,   3 running, 105 sleeping,   0 stopped,   0 zombie
%Cpu(s): 34.1 us,  0.7 sy,  0.0 ni, 65.1 id,  0.0 wa,  0.0 hi,  0.1 si,  0.0 st
KiB Mem:    502060 total,   220284 used,   281776 free,      764 buffers
KiB Swap:  1081340 total,        0 used,  1081340 free.    92940 cached Mem

 PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 3001 vagrant   20   0    7396    720    504 R  98.4  0.1 121:08.67 lookbusy
 3002 vagrant   20   0    7396    720    504 S   6.6  0.1  19:05.12 lookbusy
 1 root      20   0   50780   7264   2508 S   0.0  1.4   0:01.69 systemd
 2 root      20   0       0      0      0 S   0.0  0.0   0:00.01 kthreadd
 3 root      20   0       0      0      0 S   0.0  0.0   0:00.97 ksoftirqd/0
 5 root       0 -20       0      0      0 S   0.0  0.0   0:00.00 kworker/0:0H
 6 root      20   0       0      0      0 S   0.0  0.0   0:00.00 kworker/u4:0
 7 root      rt   0       0      0      0 S   0.0  0.0   0:00.67 migration/0

```

这次执行`top`命令时，使用了`-n`（数字）标志。这个标志告诉`top`只刷新指定次数，这里是 1 次。在尝试捕获`top`的输出时，这个技巧可能会有所帮助。

如果我们回顾上面`top`命令的输出，我们会看到一些非常有趣的东西。

```
 PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 3001 vagrant   20   0    7396    720    504 R  98.4  0.1 121:08.67 lookbusy

```

默认情况下，`top`命令按照进程利用的 CPU 百分比对进程进行排序。这意味着列表中的第一个进程是在该时间间隔内消耗 CPU 最多的进程。

如果我们看一下进程 ID 为`3001`的顶部进程，我们会发现它正在使用 CPU 时间的`98.4%`。然而，根据 top 命令的系统范围 CPU 统计数据，CPU 时间的`65.1%`处于空闲状态。这种情况实际上是许多系统管理员困惑的常见原因。

```
%Cpu(s): 34.1 us,  0.7 sy,  0.0 ni, 65.1 id,  0.0 wa,  0.0 hi,  0.1 si,  0.0 st

```

一个单个进程如何使用几乎 100%的 CPU 时间，而系统本身显示 CPU 时间的 65%是空闲的？答案其实很简单；当`top`在其标题中显示 CPU 利用率时，比例是基于整个系统的。然而，对于单个进程，CPU 利用率的比例是针对一个 CPU 的。这意味着我们的进程 3001 实际上几乎使用了一个完整的 CPU，而我们的系统很可能有多个 CPU。

通常会看到能够利用多个 CPU 的进程显示的百分比高于 100%。例如，完全利用三个 CPU 的进程将显示 300%。这也可能会让不熟悉`top`命令服务器总体和每个进程输出差异的用户感到困惑。

### 确定可用 CPU 数量

先前，我们确定了这个系统必须有多个可用的 CPU。我们没有确定的是有多少个。确定可用 CPU 数量的最简单方法是简单地读取`/proc/cpuinfo`文件。

```
# cat /proc/cpuinfo
processor  : 0
vendor_id  : GenuineIntel
cpu family  : 6
model    : 58
model name  : Intel(R) Core(TM) i7-3615QM CPU @ 2.30GHz
stepping  : 9
microcode  : 0x19
cpu MHz    : 2348.850
cache size  : 6144 KB
physical id  : 0
siblings  : 2
core id    : 0
cpu cores  : 2
apicid    : 0
initial apicid  : 0
fpu    : yes
fpu_exception  : yes
cpuid level  : 5
wp    : yes
flags    : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl pni ssse3 lahf_lm
bogomips  : 4697.70
clflush size  : 64
cache_alignment  : 64
address sizes  : 36 bits physical, 48 bits virtual
power management:

processor  : 1
vendor_id  : GenuineIntel
cpu family  : 6
model    : 58
model name  : Intel(R) Core(TM) i7-3615QM CPU @ 2.30GHz
stepping  : 9
microcode  : 0x19
cpu MHz    : 2348.850
cache size  : 6144 KB
physical id  : 0
siblings  : 2
core id    : 1
cpu cores  : 2
apicid    : 1
initial apicid  : 1
fpu    : yes
fpu_exception  : yes
cpuid level  : 5
wp    : yes
flags    : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl pni ssse3 lahf_lm
bogomips  : 4697.70
clflush size  : 64
cache_alignment  : 64
address sizes  : 36 bits physical, 48 bits virtual
power management:

```

`/proc/cpuinfo`文件包含了关于系统可用 CPU 的大量有用信息。它显示了 CPU 的类型到型号，可用的标志，CPU 的速度，最重要的是可用的 CPU 数量。

系统中每个可用的 CPU 都将在`cpuinfo`文件中列出。这意味着您可以简单地在`cpuinfo`文件中计算处理器的数量，以确定服务器可用的 CPU 数量。

从上面的例子中，我们可以确定这台服务器有 2 个可用的 CPU。

#### 线程和核心

使用`cpuinfo`来确定可用 CPU 数量的一个有趣的注意事项是，当使用具有多个核心并且是超线程的 CPU 时，细节有点误导。`cpuinfo`文件将 CPU 上的核心和线程都报告为它可以利用的处理器。这意味着即使您的系统上安装了一个物理芯片，如果该芯片是一个四核超线程 CPU，`cpuinfo`文件将显示八个处理器。

#### lscpu – 查看 CPU 信息的另一种方法

虽然`/proc/cpuinfo`是许多管理员和用户用来确定 CPU 信息的方法；在基于 RHEL 的发行版上，还有另一条命令也会显示这些信息。

```
$ lscpu
Architecture:          x86_64
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
CPU(s):                2
On-line CPU(s) list:   0,1
Thread(s) per core:    1
Core(s) per socket:    2
Socket(s):             1
NUMA node(s):          1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 58
Model name:            Intel(R) Core(TM) i7-3615QM CPU @ 2.30GHz
Stepping:              9
CPU MHz:               2348.850
BogoMIPS:              4697.70
L1d cache:             32K
L1d cache:             32K
L2d cache:             6144K
NUMA node0 CPU(s):     0,1

```

`/proc/cpuinfo`和`lscpu`命令之间的一个区别是，`lscpu`使得很容易识别核心、插槽和线程的数量。从`/proc/cpuinfo`文件中识别这些信息通常会有点困难。

### ps – 通过 ps 更深入地查看单个进程

虽然`top`命令可以用来查看单个进程，但我个人认为`ps`命令更适合用于调查运行中的进程。在第二章中，我们介绍了`ps`命令以及它如何用于查看运行进程的许多不同方面。

在本章中，我们将使用`ps`命令更深入地查看我们用`top`命令确定为利用最多 CPU 时间的进程`3001`。

```
$ ps -lf 3001
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY TIME CMD
1 S vagrant   3001  3000 73  80   0 -  1849 hrtime 01:34 pts/1 892:23 lookbusy --cpu-mode curve --cpu-curve-peak 14h -c 20-80

```

在第二章中，我们讨论了使用`ps`命令来显示运行中的进程。在前面的例子中，我们指定了两个标志，这些标志在第二章中显示，`-l`（长列表）和`–f`（完整格式）。在本章中，我们讨论了这些标志如何为显示的进程提供额外的细节。

为了更好地理解上述进程，让我们分解一下这两个标志提供的额外细节。

+   当前状态：`S`（可中断睡眠）

+   用户：`vagrant`

+   进程 ID：`3001`

+   父进程 ID：`3000`

+   优先级值：`80`

+   优先级级别：`0`

+   正在执行的命令：`lookbusy –cpu-mode-curve –cpu-curve-peak 14h –c 20-80`

早些时候，使用`top`命令时，这个进程几乎使用了一个完整的 CPU，这意味着这个进程是导致报告的缓慢的嫌疑对象。通过查看上述细节，我们可以确定这个进程的一些情况。

首先，它是进程`3000`的子进程；这是我们通过父进程 ID 确定的。其次，当我们运行`ps`命令时，它正在等待一个任务完成；我们可以通过进程当前处于可中断睡眠状态来确定这一点。

除了这两项之外，我们还可以看出该进程没有高调度优先级。我们可以通过查看优先级值来确定这一点，在这种情况下是 80。调度优先级系统的工作方式如下：数字越高，进程在系统调度程序中的优先级越低。

我们还可以看到 niceness 级别设置为`0`，即默认值。这意味着用户没有调整 niceness 级别以获得更高（或更低）的优先级。

这些都是收集有关进程的重要数据点，但单独来看，它们并不能回答这个进程是否是报告的缓慢的原因。

#### 使用 ps 来确定进程的 CPU 利用率

由于我们知道进程`3001`是进程`3000`的子进程，我们不仅应该查看进程`3000`的相同信息，还应该使用`ps`来确定进程`3000`利用了多少 CPU。我们可以通过使用`-o`（选项）标志和`ps`来一次完成所有这些。这个标志允许您指定自己的输出格式；它还允许您查看通过常见的`ps`标志通常不可见的字段。

在下面的命令中，使用`-o`标志来格式化`ps`命令的输出，使用前一次运行的关键字段并包括`%cpu`字段。这个额外的字段将显示进程的 CPU 利用率。该命令还将使用`-p`标志来指定进程`3000`和进程`3001`。

```
$ ps -o state,user,pid,ppid,nice,%cpu,cmd -p 3000,3001
S USER       PID  PPID  NI %CPU CMD
S vagrant   3000  2980   0  0.0 lookbusy --cpu-mode curve --cpu- curve-peak 14h -c 20-80
R vagrant   3001  3000   0 71.5 lookbusy --cpu-mode curve --cpu- curve-peak 14h -c 20-80

```

虽然上面的命令非常长，但它展示了`-o`标志有多么有用。在给定正确的选项的情况下，只用`ps`命令就可以找到大量关于进程的信息。

从上面命令的输出中，我们可以看到进程`3000`是`lookbusy`命令的另一个实例。我们还可以看到进程`3000`是进程`2980`的子进程。在进一步进行之前，我们应该尝试识别与进程`3001`相关的所有进程。

我们可以使用`ps`命令和`--forest`标志来做到这一点，该标志告诉`ps`以树状格式打印父进程和子进程。当提供`-e`（所有）标志时，`ps`命令将以这种树状格式打印所有进程。

### 提示

默认情况下，`ps`命令只会打印与执行命令的用户相关的进程。`-e`标志改变了这种行为，以打印所有可能的进程。

下面的输出被截断，以特别识别`lookbusy`进程。

```
$ ps --forest -eo user,pid,ppid,%cpu,cmd
root      1007     1  0.0 /usr/sbin/sshd -D
root      2976  1007  0.0  \_ sshd: vagrant [priv]
vagrant   2979  2976  0.0      \_ sshd: vagrant@pts/1
vagrant   2980  2979  0.0          \_ -bash
vagrant   3000  2980  0.0              \_ lookbusy --cpu-mode curve - -cpu-curve-peak 14h -c 20-80
vagrant   3001  3000 70.4                  \_ lookbusy --cpu-mode curve --cpu-curve-peak 14h -c 20-80
vagrant   3002  3000 14.6                  \_ lookbusy --cpu-mode curve --cpu-curve-peak 14h -c 20-80

```

从上面的`ps`输出中，我们可以看到 ID 为`3000`的`lookbusy`进程产生了两个进程，分别是`3001`和`3002`。我们还可以看到当前通过 SSH 登录的 vagrant 用户启动了`lookbusy`进程。

由于我们还使用了`-o`标志和`ps`来显示 CPU 利用率，我们可以看到进程`3002`正在利用单个 CPU 的`14.6%`。

### 提示

重要的是要注意，`ps`命令还显示了单个处理器的 CPU 时间百分比，这意味着利用多个处理器的进程可能具有高于 100%的值。

## 把它们都放在一起

现在我们已经通过命令来识别系统的 CPU 利用率，让我们把它们放在一起总结一下找到的东西。

### 用 top 快速查看

我们识别与 CPU 性能相关的问题的第一步是执行`top`命令。

```
$ top

top - 01:50:36 up 23:41,  2 users,  load average: 0.68, 0.56, 0.48
Tasks: 107 total,   4 running, 103 sleeping,   0 stopped,   0 zombie
%Cpu(s): 34.5 us,  0.7 sy,  0.0 ni, 64.9 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem:    502060 total,   231168 used,   270892 free,      764 buffers
KiB Swap:  1081340 total,        0 used,  1081340 free.    94628 cached Mem

 PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 3001 vagrant   20   0    7396    724    508 R  68.8  0.1 993:06.80 lookbusy
 3002 vagrant   20   0    7396    724    508 S   1.0  0.1 198:58.16 lookbusy
 12 root      20   0       0      0      0 S   0.3  0.0   3:47.55 rcuos/0
 13 root      20   0       0      0      0 R   0.3  0.0   3:38.85 rcuos/1
 2718 vagrant   20   0  131524   2536   1344 R   0.3  0.5   0:02.28 sshd

```

从`top`的输出中，我们可以识别以下内容：

+   总体而言，系统大约 60%–70%的时间处于空闲状态

+   有两个正在运行`lookbusy`命令/程序的进程，其中一个似乎正在使用单个 CPU 的 70%

+   鉴于这个单独进程的 CPU 利用率和系统 CPU 利用率，所涉及的服务器很可能有多个 CPU

+   我们可以用`lscpu`命令确认存在多个 CPU

+   进程 3001 和 3002 是该系统上利用 CPU 最多的两个进程

+   CPU 等待状态百分比为 0，这意味着问题不太可能与磁盘 I/O 有关

#### 通过 ps 深入挖掘

由于我们从`top`命令的输出中确定了进程`3001`和`3002`是可疑的，我们可以使用`ps`命令进一步调查这些进程。为了快速进行调查，我们将使用`ps`命令和`-o`和`--forest`标志来用一个命令识别最大可能的信息。

```
$ ps --forest -eo user,pid,ppid,%cpu,cmd
root      1007     1  0.0 /usr/sbin/sshd -D
root      2976  1007  0.0  \_ sshd: vagrant [priv]
vagrant   2979  2976  0.0      \_ sshd: vagrant@pts/1
vagrant   2980  2979  0.0          \_ -bash
vagrant   3000  2980  0.0              \_ lookbusy --cpu-mode curve --cpu-curve-peak 14h -c 20-80
vagrant   3001  3000 69.8                  \_ lookbusy --cpu-mode curve --cpu-curve-peak 14h -c 20-80
vagrant   3002  3000 13.9                  \_ lookbusy --cpu-mode curve --cpu-curve-peak 14h -c 20-80

```

从这个输出中，我们可以确定以下内容：

+   进程 3001 和 3002 是进程 3000 的子进程

+   进程 3000 是由`vagrant`用户启动的

+   `lookbusy`命令似乎是一个利用大量 CPU 的命令

+   启动`lookbusy`的方法并不表明这是一个系统进程，而是一个用户运行的临时命令。

根据上述信息，`vagrant`用户启动的`lookbusy`进程有可能是性能问题的根源。如果这个系统通常的 CPU 利用率较低，这是一个合理的根本原因的假设。然而，考虑到我们对这个系统不太熟悉，`lookbusy`进程几乎使用了整个 CPU 也是可能的。

考虑到我们对系统的正常运行条件不太熟悉，我们应该在得出结论之前继续调查性能问题的其他可能来源。

## 内存

在应用程序和 CPU 利用率之后，内存利用率是性能下降的一个非常常见的来源。在 CPU 部分，我们广泛使用了`top`，虽然`top`也可以用来识别系统和进程的内存利用率，但在这一部分，我们将使用其他命令。

### free – 查看空闲和已用内存

如第二章中所讨论的，*故障排除命令和有用信息来源* `free`命令只是简单地打印系统当前的内存可用性和使用情况。

当没有标志时，`free`命令将以千字节为单位输出其值。为了使输出以兆字节为单位，我们可以简单地使用`-m`（兆字节）标志执行`free`命令。

```
$ free -m
 total       used       free     shared    buffers     cached
Mem:     490         92        397          1          0         17
-/+ buffers/cache:         74        415
Swap:         1055         57        998

```

`free`命令显示了关于这个系统以及内存使用情况的大量信息。为了更好地理解这个命令，让我们对输出进行一些分解。

由于输出中有多行，我们将从输出标题之后的第一行开始：

```
Mem:         490        92       397         1         0         17

```

这一行中的第一个值是系统可用的**物理内存**总量。在我们的情况下，这是 490 MB。第二个值是系统使用的**内存**量。第三个值是系统上**未使用**的内存量；请注意，我使用了“未使用”而不是“可用”这个术语。第四个值是用于**共享内存**的内存量；除非您的系统经常使用共享内存，否则这通常是一个较低的数字。

第五个值是用于**缓冲区**的内存量。Linux 通常会尝试通过将频繁使用的磁盘信息放入物理内存来加快磁盘访问速度。缓冲区内存通常是文件系统元数据。**缓存内存**，也就是第六个值，是经常访问文件的内容。

#### Linux 内存缓冲区和缓存

Linux 通常会尝试使用“未使用”的内存来进行缓冲和缓存。这意味着为了提高效率，Linux 内核将频繁访问的文件数据和文件系统元数据存储在未使用的内存中。这使得系统能够利用本来不会被使用的内存来增强磁盘访问，而磁盘访问通常比系统内存慢。

这就是为什么第三个值“未使用”内存通常比预期的数字要低的原因。

然而，当系统的未使用内存不足时，Linux 内核将根据需要释放缓冲区和缓存内存。这意味着即使从技术上讲，用于缓冲区和缓存的内存被使用了，但在需要时它从技术上讲是可用的。

这将我们带到了 free 输出的第二行。

```
-/+ buffers/cache:         74        415

```

第二行有两个值，第一个是**Used**列的一部分，第二个是**Free**或“未使用”列的一部分。这些值是在考虑缓冲区和缓存内存的可用或未使用内存值之后得出的。

简单来说，第二行的已使用值是从第一行的已使用内存值减去缓冲区和缓存值得到的结果。对于我们的示例，这是 92 MB（已使用）减去 17 MB（cached）。

第二行的 free 值是第一行的 Free 值加上缓冲区和缓存内存的结果。使用我们的示例数值，这将是 397 MB（free）加上 17 MB（cached）。

#### 交换内存

`free`命令的输出的第三行是用于交换内存的。

```
Swap:         1055         57        998

```

在这一行中，有三列：可用、已使用和空闲。交换内存的值相当容易理解。可用交换值是系统可用的交换内存量，已使用值是当前分配的交换量，而空闲值基本上是可用交换减去已分配的交换量。

有许多环境不赞成分配大量的交换空间，因为这通常是系统内存不足并使用交换空间来补偿的指标。

#### free 告诉我们关于我们系统的信息

如果我们再次查看 free 的输出，我们可以确定关于这台服务器的很多事情。

```
$ free -m
 total       used       free     shared    buffers     cached
Mem:       490        105        385          1          0         25
-/+ buffers/cache:         79        410
Swap:         1055         56        999

```

我们可以确定实际上只使用了很少的内存（79 MB）。这意味着总体上，系统应该有足够的内存可用于进程。

然而，还有一个有趣的事实，在第三行显示，**56** MB 的内存已被写入交换空间。尽管系统当前有大量可用内存，但已经有 56 MB 被写入交换空间。这意味着在过去的某个时刻，这个系统可能内存不足，足够低到系统不得不将内存页面从物理内存交换到交换内存。

### 检查 oomkill

当 Linux 系统的物理内存耗尽时，它首先尝试重用分配给缓冲区和缓存的内存。如果没有额外的内存可以从这些来源中回收，那么内核将从物理内存中获取旧的内存页面并将它们写入交换内存。一旦物理内存和交换内存都被分配，内核将启动**内存不足杀手**（**oomkill**）进程。`oomkill`进程旨在找到使用大量内存的进程并将其杀死（停止）。

一般来说，在大多数环境中，`oomkill`进程是不受欢迎的。一旦调用，`oomkill`进程可以杀死许多不同类型的进程。无论进程是系统的一部分还是用户级别的，`oomkill`都有能力杀死它们。

对于可能影响内存利用的性能问题，检查`oomkill`进程最近是否被调用是一个很好的主意。确定`oomkill`最近是否运行的最简单方法是简单地查看系统的控制台，因为这个进程的启动会直接记录在系统控制台上。然而，在云和虚拟环境中，控制台可能不可用。

另一个确定最近是否调用了`oomkill`的好方法是搜索`/var/log/messages`日志文件。我们可以通过执行`grep`命令并搜索字符串`Out of memory`来做到这一点。

```
# grep "Out of memory" /var/log/messages

```

对于我们的示例系统，最近没有发生`oomkill`调用。如果我们的系统调用了`oomkill`进程，我们可能会收到类似以下消息：

```
# grep "Out of memory" /var/log/messages
Feb  7 19:38:45 localhost kernel: Out of memory: Kill process 3236 (python) score 838 or sacrifice child

```

在第十一章中，*从常见故障中恢复*，我们将再次调查内存问题，并深入了解`oomkill`及其工作原理。对于本章，我们可以得出结论，系统尚未完全耗尽其可用内存。

### ps - 检查单个进程的内存利用率

到目前为止，系统上的内存使用似乎很小，但是我们从 CPU 验证步骤中知道，运行`lookbusy`的进程是可疑的，可能导致性能问题。由于我们怀疑`lookbusy`进程存在问题，我们还应该查看这些进程使用了多少内存。为了做到这一点，我们可以再次使用带有`-o`标志的`ps`命令。

```
$ ps -eo user,pid,ppid,%mem,rss,vsize,comm | grep lookbusy
vagrant   3000  2980  0.0     4   7396 lookbusy
vagrant   3001  3000  0.0   296   7396 lookbusy
vagrant   3002  3000  0.0   220   7396 lookbusy
vagrant   5380  2980  0.0     8   7396 lookbusy
vagrant   5381  5380  0.0   268   7396 lookbusy
vagrant   5382  5380  0.0   268   7396 lookbusy
vagrant   5383  5380 40.7 204812 212200 lookbusy
vagrant   5531  2980  0.0    40   7396 lookbusy
vagrant   5532  5531  0.0   288   7396 lookbusy
vagrant   5533  5531  0.0   288   7396 lookbusy
vagrant   5534  5531 34.0 170880 222440 lookbusy

```

然而，这一次我们以稍有不同的方式运行了我们的`ps`命令，因此得到了不同的结果。这一次执行`ps`命令时，我们使用了`-e`（everything）标志来显示所有进程。然后将结果传输到`grep`，以便将它们缩小到只匹配`lookbusy`模式的进程。

这是使用`ps`命令的一种非常常见的方式；事实上，这比在命令行上指定进程 ID 更常见。除了使用`grep`之外，这个`ps`命令示例还介绍了一些新的格式选项。

+   **%mem**：这是进程正在使用的系统内存的百分比。

+   **rss**：这是进程的常驻集大小，基本上是指进程使用的不可交换内存量。

+   **vsize**：这是虚拟内存大小，它包含进程完全使用的内存量，无论这些内存是物理内存的一部分还是交换内存的一部分。

+   **comm**：此选项类似于 cmd，但不显示命令行参数。

`ps`示例显示了有趣的信息，特别是以下几行：

```
vagrant   5383  5380 40.7 204812 212200 lookbusy
vagrant   5534  5531 34.0 170880 222440 lookbusy

```

似乎已经启动了几个额外的`lookbusy`进程，并且这些进程正在利用系统内存的 40%和 34%（通过使用`%mem`列）。从 rss 列中，我们可以看到这两个进程正在使用总共 490MB 物理内存中的约 374MB。

看起来这些进程在我们开始调查后开始利用大量内存。最初，我们的 free 输出表明只使用了 70MB 内存；然而，这些进程似乎利用了更多。我们可以通过再次运行 free 来确认这一点。

```
$ free -m
 total       used       free     shared    buffers     cached
Mem:       490        453         37          0          0          3
-/+ buffers/cache:        449         41
Swap:         1055        310        745

```

事实上，我们的系统现在几乎利用了所有的内存；事实上，我们还使用了 310MB 的交换空间。

### vmstat - 监控内存分配和交换

由于这个系统的内存利用率似乎有所波动，有一个非常有用的命令可以定期显示内存分配和释放以及换入和换出的页面数。这个命令叫做`vmstat`。

```
$ vmstat -n 10 5
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
5  0 204608  31800      0   7676    8    6    12     6  101  131 44 1 55  0  0
1  0 192704  35816      0   2096 1887  130  4162   130 2080 2538 53 6 39  2  0
1  0 191340  32324      0   3632 1590   57  3340    57 2097 2533 54 5 41  0  0
4  0 191272  32260      0   5400  536    2  2150     2 1943 2366 53 4 43  0  0
3  0 191288  34140      0   4152  392    0   679     0 1896 2366 53 3 44  0  0

```

在上面的示例中，`vmstat`命令是使用`-n`（一个标题）标志执行的，后面跟着延迟时间（10 秒）和要生成的报告数（5）。这些选项告诉`vmstat`仅为此次执行输出一个标题行，而不是为每个报告输出一个新的标题行，每 10 秒运行一次报告，并将报告数量限制为 5。如果省略了报告数量的限制，`vmstat`将简单地持续运行，直到使用*CTRL*+*C*停止。

`vmstat`的输出一开始可能有点压倒性，但如果我们分解输出，就会更容易理解。`vmstat`的输出有六个输出类别，即进程、内存、交换、IO、系统和 CPU。在本节中，我们将专注于这两个类别：内存和交换。

+   **内存**

+   `swpd`：写入交换的内存量

+   `free`：未使用的内存量

+   `buff`：用作缓冲区的内存量

+   `cache`：用作缓存的内存量

+   `inact`：非活动内存量

+   `active`：活动内存量

+   **交换**

+   `si`：从磁盘交换的内存量

+   `so`：交换到磁盘的内存量

现在我们已经了解了这些值的定义，让我们看看`vmstat`的输出告诉我们关于这个系统内存使用情况的信息。

```
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 5  0 204608  31800      0   7676    8    6    12     6  101  131 44  1 55  0  0
 1  0 192704  35816      0   2096 1887  130  4162   130 2080 2538 53  6 39  2  0

```

如果我们比较`vmstat`输出的第一行和第二行，我们会看到一个相当大的差异。特别是，我们可以看到在第一个间隔中，缓存内存是`7676`，而在第二个间隔中，这个值是 2096。我们还可以看到第一行中的`si`或交换入值是 8，而第二行中是 1887。

这种差异的原因是，`vmstat`的第一个报告总是自上次重启以来的统计摘要，而第二个报告是自上一个报告以来的统计摘要。每个后续的报告将总结前一个报告，这意味着第三个报告将总结自第二个报告以来的统计数据。`vmstat`的这种行为经常会让新的系统管理员和用户感到困惑；因此，它通常被认为是一种高级故障排除工具。

由于`vmstat`生成第一个报告的方法，通常的做法是丢弃它并从第二个报告开始。我们将遵循这一原则，特别关注第二个和第三个报告。

```
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 5  0 204608  31800      0   7676    8    6    12     6  101  131 44  1 55  0  0
 1  0 192704  35816      0   2096 1887  130  4162   130 2080 2538 53  6 39  2  0
 1  0 191340  32324      0   3632 1590   57  3340    57 2097 2533 54  5 41  0  0

```

在第二个和第三个报告中，我们可以看到一些有趣的数据。

最引人注目的是，从第一个报告的生成时间到第二个报告的生成时间，交换了 1,887 页，交换出了 130 页。第二个报告还显示，只有 35 MB 的内存是空闲的，缓冲区中没有内存，缓存中有 2 MB 的内存。根据 Linux 内存的利用方式，这意味着系统上实际上只有 37 MB 的可用内存。

这种低可用内存量解释了为什么我们的系统已经交换了大量页面。我们可以从第三行看到这种趋势正在持续，我们继续交换了相当多的页面，我们的可用内存已经减少到大约 35 MB。

从这个`vmstat`的例子中，我们可以看到我们的系统现在已经用尽了物理内存。因此，我们的系统正在从物理 RAM 中取出内存页面并将其写入我们的交换设备。

### 把所有东西放在一起

现在我们已经探索了用于故障排除内存利用的工具，让我们把它们都放在一起来解决系统性能缓慢的问题。

#### 用 free 查看系统的内存利用

给我们提供系统内存利用快照的第一个命令是`free`命令。这个命令将为我们提供在哪里进一步查找任何内存利用问题的想法。

```
$ free -m
 total       used       free     shared    buffers     cached
Mem:       490        293        196          0          0         18
-/+ buffers/cache:        275        215
Swap:         1055        183        872

```

从`free`的输出中，我们可以看到目前有 215 MB 的内存可用。我们可以通过第二行的`free`列看到这一点。我们还可以看到，总体上，这个系统有 183 MB 的内存已经被交换到我们的交换设备。

#### 观察 vmstat 的情况

由于系统在某个时候已经进行了交换（或者说分页），我们可以使用`vmstat`命令来查看系统当前是否正在进行交换。

这次执行`vmstat`时，我们将不指定报告值的数量，这将导致`vmstat`持续报告内存统计，类似于 top 命令的输出。

```
$ vmstat -n 10
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 4  0 188008 200320      0  19896   35    8    61     9  156    4 44 1 55  0  0
 4  0 188008 200312      0  19896    0    0     0     0 1361 1314 36 2 62  0  0
 2  0 188008 200312      0  19896    0    0     0     0 1430 1442 37 2 61  0  0
 0  0 188008 200312      0  19896    0    0     0     0 1431 1418 37 2 61  0  0
 0  0 188008 200280      0  19896    0    0     0     0 1414 1416 37 2 61  0  0
 2  0 188008 200280      0  19896    0    0     0     0 1456 1480 37 2 61  0  0

```

这个`vmstat`输出与我们之前的执行不同。从这个输出中，我们可以看到虽然有相当多的内存被交换，但系统目前并没有进行交换。我们可以通过`si`（交换入）和 so（交换出）列中的 0 值来确定这一点。

实际上，在这次`vmstat`运行期间，内存利用率似乎很稳定。每个`vmstat`报告中，`free`内存值都相当一致，缓存和缓冲内存统计也是如此。

#### 使用 ps 找到内存利用最多的进程

我们的系统有 490MB 的物理内存，`free`和`vmstat`都显示大约 215MB 的可用内存。这意味着我们系统内存的一半以上目前被使用；在这种使用水平下，找出哪些进程正在使用我们系统的内存是一个好主意。即使没有别的，这些数据也将有助于显示系统当前的状态。

要识别使用最多内存的进程，我们可以使用`ps`命令以及 sort 和 tail。

```
# ps -eo rss,vsize,user,pid,cmd | sort -nk 1 | tail -n 5
 1004 115452 root      5073 -bash
 1328 123356 root      5953 ps -eo rss,vsize,user,pid,cmd
 2504 525652 root       555 /usr/sbin/NetworkManager --no-daemon
 4124  50780 root         1 /usr/lib/systemd/systemd --switched-root --system --deserialize 23
204672 212200 vagrant  5383 lookbusy -m 200MB -c 10

```

上面的例子使用管道将`ps`的输出重定向到 sort 命令。sort 命令执行数字（`-n`）对第一列（`-k 1`）的排序。这将对输出进行排序，将具有最高`rss`大小的进程放在底部。在`sort`命令之后，输出也被管道传递到`tail`命令，当指定了`-n`（数字）标志后跟着一个数字，将限制输出只包括指定数量的结果。

### 提示

如果将命令与管道一起链接的概念是新的，我强烈建议练习这一点，因为它对日常的`sysadmin`任务以及故障排除非常有用。我们将在本书中多次讨论这个概念，并提供示例。

```
204672 212200 vagrant  5383 lookbusy -m 200MB -c 10

```

从`ps`的输出中，我们可以看到进程 5383 正在使用大约 200MB 的内存。我们还可以看到该进程是另一个`lookbusy`进程，再次由 vagrant 用户生成。

从`free`，`vmstat`和`ps`的输出中，我们可以确定以下内容：

+   系统当前大约有 200MB 的可用内存

+   虽然系统目前没有交换，但过去曾经有过，根据我们之前从`vmstat`看到的情况，我们知道它最近进行了交换

+   我们发现进程`5383`正在使用大约 200MB 的内存

+   我们还可以看到进程`5383`是由`vagrant`用户启动的，并且正在运行`lookbusy`进程

+   使用`free`命令，我们可以看到这个系统有 490MB 的物理内存

根据以上信息，似乎由`vagrant`用户执行的`lookbusy`进程不仅是 CPU 的可疑使用者，还是内存的可疑使用者。

## 磁盘

磁盘利用率是另一个常见的性能瓶颈。一般来说，性能问题很少是由于磁盘空间的问题。虽然我曾经看到由于大量文件或大文件的性能问题，但一般来说，磁盘性能受到写入和读取磁盘的限制。因此，在故障排除性能问题时，了解文件系统是否已满很重要，但仅仅根据文件系统的使用情况并不总是能指示是否存在问题。

### iostat - CPU 和设备输入/输出统计

`iostat`命令是用于故障排除磁盘性能问题的基本命令，类似于 vmstat，它提供的使用和信息都是相似的。像`vmstat`一样，执行`iostat`命令后面跟着两个数字，第一个是报告生成的延迟，第二个是要生成的报告数。

```
$ iostat -x 10 3
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/08/2015 _x86_64_  (2 CPU)

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 43.58    0.00    1.07    0.16    0.00   55.19

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda              12.63     3.88    8.47    3.47   418.80   347.40 128.27     0.39   32.82    0.80  110.93   0.47   0.56
dm-0              0.00     0.00   16.37    3.96    65.47    15.82 8.00     0.48   23.68    0.48  119.66   0.09   0.19
dm-1              0.00     0.00    4.73    3.21   353.28   331.71 172.51     0.39   48.99    1.07  119.61   0.54   0.43

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 20.22    0.00   20.33   22.14    0.00   37.32

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.10    13.67  764.97  808.68 71929.34 78534.73 191.23    62.32   39.75    0.74   76.65   0.42  65.91
dm-0              0.00     0.00    0.00    0.10     0.00     0.40 8.00     0.01   70.00    0.00   70.00  70.00   0.70
dm-1              0.00     0.00  765.27  769.76 71954.89 78713.17 196.31    64.65   42.25    0.74   83.51   0.43  66.46

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 18.23    0.00   15.56   29.26    0.00   36.95

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.10     7.10  697.50  440.10 74747.60 42641.75 206.38    74.13   66.98    0.64  172.13   0.58  66.50
dm-0              0.00     0.00    0.00    0.00     0.00     0.00 0.00     0.00    0.00    0.00    0.00   0.00   0.00
dm-1              0.00     0.00  697.40  405.00 74722.00 40888.65 209.74    75.80   70.63    0.66  191.11   0.61  67.24

```

在上面的例子中，提供了`-x`（扩展统计）标志以打印扩展统计信息。扩展统计非常有用，并提供了额外的信息，对于识别性能瓶颈至关重要。

#### CPU 详情

`iostat`命令将显示 CPU 统计信息以及 I/O 统计信息。这是另一个可以用来排除 CPU 利用率的命令。当 CPU 利用率指示高 I/O 等待时间时，这是特别有用的。

```
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 20.22    0.00   20.33   22.14    0.00   37.32

```

以上是从`top`命令显示的相同信息；在 Linux 中找到多个输出类似信息的命令并不罕见。由于这些细节已在 CPU 故障排除部分中涵盖，我们将专注于`iostat`命令的 I/O 统计部分。

#### 审查 I/O 统计

要开始审查 I/O 统计，让我们从前两份报告开始。我在下面包括了 CPU 利用率，以帮助指示每份报告的开始位置，因为它是每份统计报告中的第一项。

```
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 43.58    0.00    1.07    0.16    0.00   55.19

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda              12.63     3.88    8.47    3.47   418.80   347.40 128.27     0.39   32.82    0.80  110.93   0.47   0.56
dm-0              0.00     0.00   16.37    3.96    65.47    15.82 8.00     0.48   23.68    0.48  119.66   0.09   0.19
dm-1              0.00     0.00    4.73    3.21   353.28   331.71 172.51     0.39   48.99    1.07  119.61   0.54   0.43

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 20.22    0.00   20.33   22.14    0.00   37.32

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.10    13.67  764.97  808.68 71929.34 78534.73 191.23    62.32   39.75    0.74   76.65   0.42  65.91
dm-0              0.00     0.00    0.00    0.10     0.00     0.40 8.00     0.01   70.00    0.00   70.00  70.00   0.70
dm-1              0.00     0.00  765.27  769.76 71954.89 78713.17 196.31    64.65   42.25    0.74   83.51   0.43  66.46

```

通过比较前两份报告，我们发现它们之间存在很大的差异。在第一个报告中，`sda`设备的`％util`值为`0.56`，而在第二个报告中为`65.91`。

这种差异的原因是，与`vmstat`一样，第一次执行`iostat`的统计是基于服务器最后一次重启的时间。第二份报告是基于第一份报告之后的时间。这意味着第二份报告的输出是基于第一份报告生成之间的 10 秒。这与`vmstat`中看到的行为相同，并且是其他收集性能统计信息的工具的常见行为。

与`vmstat`一样，我们将丢弃第一个报告，只看第二个报告。

```
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 20.22    0.00   20.33   22.14    0.00   37.32

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.10    13.67  764.97  808.68 71929.34 78534.73 191.23    62.32   39.75    0.74   76.65   0.42  65.91
dm-0              0.00     0.00    0.00    0.10     0.00     0.40 8.00     0.01   70.00    0.00   70.00  70.00   0.70
dm-1              0.00     0.00  765.27  769.76 71954.89 78713.17 196.31    64.65   42.25    0.74   83.51   0.43  66.46

```

从上面，我们可以确定这个系统的几个情况。最重要的是 CPU 行中的`％iowait`值。

```
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 20.22    0.00   20.33   22.14    0.00   37.32

```

早些时候在执行 top 命令时，等待 I/O 的时间百分比相当小；然而，在运行`iostat`时，我们可以看到 CPU 实际上花了很多时间等待 I/O。虽然 I/O 等待并不一定意味着等待磁盘，但这个输出的其余部分似乎表明磁盘活动相当频繁。

```
Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.10    13.67  764.97  808.68 71929.34 78534.73 191.23    62.32   39.75    0.74   76.65   0.42  65.91
dm-0              0.00     0.00    0.00    0.10     0.00     0.40 8.00     0.01   70.00    0.00   70.00  70.00   0.70
dm-1              0.00     0.00  765.27  769.76 71954.89 78713.17 196.31    64.65   42.25    0.74   83.51   0.43  66.46

```

扩展统计输出有许多列，为了使这个输出更容易理解，让我们分解一下这些列告诉我们的内容。

+   **rrqm/s**：每秒合并和排队的读取请求数

+   **wrqm/s**：每秒合并和排队的写入请求数

+   **r/s**：每秒完成的读取请求数

+   **w/s**：每秒完成的写入请求数

+   **rkB/s**：每秒读取的千字节数

+   **wkB/s**：每秒写入的千字节数

+   **avgr-sz**：发送到设备的请求的平均大小（以扇区为单位）

+   **avgqu-sz**：发送到设备的请求的平均队列长度

+   **await**：请求等待服务的平均时间（毫秒）

+   **r_await**：读取请求等待服务的平均时间（毫秒）

+   **w_await**：写入请求等待服务的平均时间（毫秒）

+   **svctm**：此字段无效，将被删除；不应被信任或使用

+   **％util**：在此设备服务 I/O 请求时所花费的 CPU 时间百分比。设备最多只能利用 100％

对于我们的示例，我们将专注于`r/s`，`w/s`，`await`和`％util`值，因为这些值将告诉我们关于这个系统的磁盘利用率的很多信息，同时保持我们的示例简单。

经过审查`iostat`输出后，我们可以看到`sda`和`dm-1`设备都具有最高的`％util`值，这意味着它们最接近达到容量。

```
Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.10    13.67  764.97  808.68 71929.34 78534.73 191.23    62.32   39.75    0.74   76.65   0.42  65.91
dm-1              0.00     0.00  765.27  769.76 71954.89 78713.17 196.31    64.65   42.25    0.74   83.51   0.43  66.46

```

从这份报告中，我们可以看到`sda`设备平均完成了 764 次读取（`r/s`）和 808 次写入（`w/s`）每秒。我们还可以确定这些请求平均需要 39 毫秒（等待时间）来完成。虽然这些数字很有趣，但并不一定意味着系统处于异常状态。由于我们对这个系统不熟悉，我们并不一定知道读取和写入的水平是否出乎意料。然而，收集这些信息是很重要的，因为这些统计数据是故障排除过程中数据收集阶段的重要数据。

从`iostat`中我们可以看到另一个有趣的统计数据是，`sda`和`dm-1`设备的`%util`值都约为 66%。这意味着在第一次报告生成和第二次报告之间的 10 秒内，66%的 CPU 时间都是在等待`sd`或`dm-1`设备。

#### 识别设备

对于磁盘设备来说，66%的利用率通常被认为是很高的，虽然这是非常有用的信息，但它并没有告诉我们是谁或什么在利用这个磁盘。为了回答这些问题，我们需要弄清楚`sda`和`dm-1`到底被用来做什么。

由于`iostat`命令输出的设备通常是磁盘设备，识别这些设备的第一步是运行`mount`命令。

```
$ mount
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
devtmpfs on /dev type devtmpfs (rw,nosuid,seclabel,size=244828k,nr_inodes=61207,mode=755)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,seclabel)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,seclabel,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,nodev,seclabel,mode=755)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,seclabel,mode=755)
configfs on /sys/kernel/config type configfs (rw,relatime)
/dev/mapper/root on / type xfs (rw,relatime,seclabel,attr2,inode64,noquota)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,seclabel)
mqueue on /dev/mqueue type mqueue (rw,relatime,seclabel)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
/dev/sda1 on /boot type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

`mount`命令在没有任何选项的情况下运行时，将显示所有当前挂载的文件系统。`mount`输出中的第一列是已经挂载的设备。在上面的输出中，我们可以看到`sda`设备实际上是一个磁盘设备，并且它有一个名为`sda1`的分区，挂载为`/boot`。

然而，我们没有看到`dm-1`设备。由于这个设备没有出现在`mount`命令的输出中，我们可以通过另一种方式，在`/dev`文件夹中查找`dm-1`设备。

系统上的所有设备都被呈现为`/dev`文件夹结构中的一个文件。`dm-1`设备也不例外。

```
$ ls -la /dev/dm-1
brw-rw----. 1 root disk 253, 1 Feb  1 18:47 /dev/dm-1

```

虽然我们已经找到了`dm-1`设备的位置，但我们还没有确定它的用途。然而，关于这个设备，有一件事引人注目，那就是它的名字`dm-1`。当设备以`dm`开头时，这表明该设备是由设备映射器创建的逻辑设备。

设备映射器是一个 Linux 内核框架，允许系统创建虚拟磁盘设备，这些设备“映射”回物理设备。这个功能用于许多特性，包括软件 RAID、磁盘加密和逻辑卷。

设备映射器框架中的一个常见做法是为这些特性创建符号链接，这些符号链接指向单个逻辑设备。由于我们可以用`ls`命令看到`dm-1`是一个块设备，通过输出的第一列的“b”值（`brw-rw----.`），我们知道`dm-1`不是一个符号链接。我们可以利用这些信息以及 find 命令来识别任何指向`dm-1`块设备的符号链接。

```
# find -L /dev -samefile /dev/dm-1
/dev/dm-1
/dev/rhel/root
/dev/disk/by-uuid/beb5220d-5cab-4c43-85d7-8045f870ba7d
/dev/disk/by-id/dm-uuid-LVM-qj3iMeektIlL3Z0g4WMPMJRbzacnpS9IVOCzB60GSHCEgbRKYW9ZKXR5prUPEE1e
/dev/disk/by-id/dm-name-root
/dev/block/253:1
/dev/mapper/root

```

在前面的章节中，我们使用 find 命令来识别配置和日志文件。在上面的例子中，我们使用了`-L`（跟随链接）标志，后面跟着`/dev`路径和`--samefile`标志，告诉 find 搜索`/dev`文件夹结构，搜索任何符号链接的文件，以识别任何与`/dev/dm-1`相同的文件。

`--samefile`标志标识具有相同`inode`号的文件。当命令中包含`-L`标志时，输出包括符号链接，而这个例子似乎返回了几个结果。最引人注目的符号链接文件是`/dev/mapper/root`；这个文件之所以引人注目，是因为它也出现在挂载命令的输出中。

```
/dev/mapper/root on / type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

看起来`/dev/mapper/root`似乎是一个逻辑卷。在 Linux 中，逻辑卷本质上是存储虚拟化。这个功能允许您创建伪设备（作为设备映射器的一部分），它映射到一个或多个物理设备。

例如，可以将四个不同的硬盘组合成一个逻辑卷。逻辑卷然后可以用作单个文件系统的磁盘。甚至可以在以后通过使用逻辑卷添加另一个硬盘。

确认`/dev/mapper/root`设备实际上是一个逻辑卷，我们可以执行`lvdisplay`命令，该命令用于显示系统上的逻辑卷。

```
# lvdisplay
 --- Logical volume ---
 LV Path                /dev/rhel/swap
 LV Name                swap
 VG Name                rhel
 LV UUID                y1ICUQ-l3uA-Mxfc-JupS-c6PN-7jvw-W8wMV6
 LV Write Access        read/write
 LV Creation host, time localhost, 2014-07-21 23:35:55 +0000
 LV Status              available
 # open                 2
 LV Size                1.03 GiB
 Current LE             264
 Segments               1
 Allocation             inherit
 Read ahead sectors     auto
 - currently set to     256
 Block device           253:0

 --- Logical volume ---
 LV Path                /dev/rhel/root
 LV Name                root
 VG Name                rhel
 LV UUID                VOCzB6-0GSH-CEgb-RKYW-9ZKX-R5pr-UPEE1e
 LV Write Access        read/write
 LV Creation host, time localhost, 2014-07-21 23:35:55 +0000
 LV Status              available
 # open                 1
 LV Size                38.48 GiB
 Current LE             9850
 Segments               1
 Allocation             inherit
 Read ahead sectors     auto
 - currently set to     256
 Block device           253:1

```

从`lvdisplay`的输出中，我们可以看到一个名为`/dev/rhel/root`的有趣路径，这个路径也存在于我们的`find`命令的输出中。让我们用`ls`命令来查看这个设备。

```
# ls -la /dev/rhel/root
lrwxrwxrwx. 1 root root 7 Aug  3 16:27 /dev/rhel/root -> ../dm-1

```

在这里，我们可以看到`/dev/rhel/root`是一个指向`/dev/dm-1`的符号链接；这证实了`/dev/rhel/root`与`/dev/dm-1`是相同的，这些实际上是逻辑卷设备，这意味着这些并不是真正的物理设备。

要显示这些逻辑卷背后的物理设备，我们可以使用`pvdisplay`命令。

```
# pvdisplay
 --- Physical volume ---
 PV Name               /dev/sda2
 VG Name               rhel
 PV Size               39.51 GiB / not usable 3.00 MiB
 Allocatable           yes (but full)
 PE Size               4.00 MiB
 Total PE              10114
 Free PE               0
 Allocated PE          10114
 PV UUID               n5xoxm-kvyI-Z7rR-MMcH-1iJI-D68w-NODMaJ

```

我们可以从`pvdisplay`的输出中看到，`dm-1`设备实际上映射到`sda2`，这解释了为什么`dm-1`和`sda`的磁盘利用率非常接近，因为对`dm-1`的任何活动实际上都是在`sda`上执行的。

### 谁在向这些设备写入？

现在我们已经找到了 I/O 的利用情况，我们需要找出谁在利用这个 I/O。找出哪些进程最多地写入磁盘的最简单方法是使用`iotop`命令。这个工具是一个相对较新的命令，现在默认包含在 Red Hat Enterprise Linux 7 中。然而，在以前的 RHEL 版本中，这个命令并不总是可用的。

在采用`iotop`之前，查找使用 I/O 最多的进程的方法涉及使用`ps`命令并浏览`/proc`文件系统。

#### ps - 使用 ps 命令识别利用 I/O 的进程

在收集与 CPU 相关的数据时，我们涵盖了`ps`命令的输出中的状态字段。我们没有涵盖的是进程可能处于的各种状态。以下列表包含了`ps`命令将显示的七种可能的状态：

+   不间断睡眠（`D`）：进程通常在等待 I/O 时处于睡眠状态

+   **运行或可运行**（`R`）：运行队列上的进程

+   **可中断睡眠**（`S`）：等待事件完成但不阻塞 CPU 或 I/O 的进程

+   **已停止**（`T`）：被作业控制系统停止的进程，如 jobs 命令

+   **分页**（`P`）：当前正在分页的进程；但是，在较新的内核上，这不太相关

+   **死亡**（`X`）：已经死亡的进程，不应该出现在运行`ps`时

+   **僵尸**（`Z`）：已终止但保留在不死状态的僵尸进程

在调查 I/O 利用率时，重要的是要识别状态列为`D`的**不间断睡眠**。由于这些进程通常在等待 I/O，它们是最有可能过度利用磁盘 I/O 的进程。

为了做到这一点，我们将使用`ps`命令和`-e`（所有）、`-l`（长格式）和`-f`（完整格式）标志。我们还将再次使用管道将输出重定向到`grep`命令，并将输出过滤为只显示具有`D`状态的进程。

```
# ps -elf | grep " D "
1 D root     13185     2  2  80   0 -     0 get_re 00:21 ? 00:01:32 [kworker/u4:1]
4 D root     15639 15638 30  80   0 -  4233 balanc 01:26 pts/2 00:00:02 bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp

```

从上面的输出中，我们看到有两个进程目前处于不间断睡眠状态。一个进程是`kworker`，这是一个内核系统进程，另一个是`bonnie++`，是由 root 用户启动的进程。由于`kworker`进程是一个通用的内核进程，我们将首先关注`bonnie++`进程。

为了更好地理解这个过程，我们将再次运行`ps`命令，但这次使用`--forest`选项。

```
# ps -elf –forest
4 S root      1007     1  0  80   0 - 20739 poll_s Feb07 ? 00:00:00 /usr/sbin/sshd -D
4 S root     11239  1007  0  80   0 - 32881 poll_s Feb08 ? 00:00:00  \_ sshd: vagrant [priv]
5 S vagrant  11242 11239  0  80   0 - 32881 poll_s Feb08 ? 00:00:02      \_ sshd: vagrant@pts/2
0 S vagrant  11243 11242  0  80   0 - 28838 wait   Feb08 pts/2 00:00:01          \_ -bash
4 S root     16052 11243  0  80   0 - 47343 poll_s 01:39 pts/2 00:00:00              \_ sudo bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp
4 S root     16053 16052 32  80   0 - 96398 hrtime 01:39 pts/2 00:00:03                  \_ bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp

```

通过审查上述输出，我们可以看到`bonnie++`进程实际上是进程`16052`的子进程，后者是`11243`的另一个子进程，后者是`vagrant`用户的 bash shell。

前面的`ps`命令告诉我们，进程 ID 为`16053`的`bonnie++`进程正在等待 I/O 任务。但是，这并没有告诉我们这个进程正在使用多少 I/O；为了确定这一点，我们可以读取`/proc`文件系统中的一个特殊文件，名为`io`。

```
# cat /proc/16053/io
rchar: 1002448848
wchar: 1002438751
syscr: 122383
syscw: 122375
read_bytes: 1002704896
write_bytes: 1002438656
cancelled_write_bytes: 0

```

每个运行的进程在`/proc`中都有一个与进程`id`同名的子文件夹；对于我们的示例，这是`/proc/16053`。这个文件夹由内核维护，用于每个运行的进程，在这些文件夹中存在许多包含有关运行进程信息的文件。

这些文件非常有用，它们实际上是`ps`命令信息的来源之一。其中一个有用的文件名为`io`；`io`文件包含有关进程执行的读取和写入次数的统计信息。

从 cat 命令的输出中，我们可以看到这个进程已经读取和写入了大约 1GB 的数据。虽然这看起来很多，但可能是在很长一段时间内完成的。为了了解这个进程向磁盘写入了多少数据，我们可以再次读取这个文件以捕捉差异。

```
# cat /proc/16053/io
cat: /proc/16053/io: No such file or directory

```

然而，当我们第二次执行 cat 命令时，我们收到了一个错误，即`io`文件不再存在。如果我们再次运行`ps`命令并使用`grep`在输出中搜索`bonnie++`进程，我们会发现`bonnie++`进程正在运行；但是，它是一个新的进程，具有新的进程`ID`。

```
# ps -elf | grep bonnie
4 S root     17891 11243  0  80   0 - 47343 poll_s 02:34 pts/2 00:00:00 sudo bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp
4 D root     17892 17891 33  80   0 -  4233 sleep_ 02:34 pts/2 00:00:02 bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp

```

由于`bonnie++`子进程是短暂的进程，通过读取`io`文件来跟踪 I/O 统计可能会非常困难。

### iotop - 一个用于磁盘 I/O 的类似 top 的命令

由于这些进程频繁启动和停止，我们可以使用`iotop`命令来确定哪些进程最多地利用了 I/O。

```
# iotop
Total DISK READ :     102.60 M/s | Total DISK WRITE :      26.96 M/s
Actual DISK READ:     102.60 M/s | Actual DISK WRITE:      42.04 M/s
 TID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN     IO> COMMAND
16395 be/4 root        0.00 B/s    0.00 B/s  0.00 % 45.59 % [kworker/u4:0]
18250 be/4 root      101.95 M/s   26.96 M/s  0.00 % 42.59 % bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp

```

在`iotop`的输出中，我们可以看到一些有趣的 I/O 统计信息。通过`iotop`，我们不仅可以看到系统范围的统计信息，比如每秒的**总磁盘读取**和**总磁盘写入**，还可以看到单个进程的许多统计信息。

从每个进程的角度来看，我们可以看到`bonnie++`进程正在以 101.96 MBps 的速度从磁盘读取数据，并以 26.96 MBps 的速度向磁盘写入数据。

```
16395 be/4 root        0.00 B/s    0.00 B/s  0.00 % 45.59 % [kworker/u4:0]
18250 be/4 root      101.95 M/s   26.96 M/s  0.00 % 42.59 % bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp

```

`iotop`命令与 top 命令非常相似，它会每隔几秒刷新报告的结果。这样做的效果是实时显示 I/O 统计信息。

### 提示

诸如`top`和`iotop`之类的命令在书本格式中很难展示。我强烈建议在具有这些命令的系统上执行这些命令，以了解它们的工作方式。

### 整合起来

现在我们已经介绍了一些用于故障排除磁盘性能和利用率的工具，让我们在解决报告的缓慢时将它们整合起来。

#### 使用 iostat 来确定是否存在 I/O 带宽问题

我们将首先运行的命令是`iostat`，因为这将首先为我们验证是否确实存在问题。

```
# iostat -x 10 3
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/09/2015 _x86_64_  (2 CPU)

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 38.58    0.00    3.22    5.46    0.00   52.75

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda              10.86     4.25  122.46  118.15 11968.97 12065.60 199.78    13.27   55.18    0.67  111.67   0.51  12.21
dm-0              0.00     0.00   14.03    3.44    56.14    13.74 8.00     0.42   24.24    0.51  121.15   0.46   0.80
dm-1              0.00     0.00  119.32  112.35 11912.79 12051.98 206.89    13.52   58.33    0.68  119.55   0.52  12.16

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 7.96    0.00   14.60   29.31    0.00   48.12

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.70     0.80  804.49  776.85 79041.12 76999.20 197.35    64.26   41.41    0.54   83.73   0.42  66.38
dm-0              0.00     0.00    0.90    0.80     3.59     3.19 8.00     0.08   50.00    0.00  106.25  19.00   3.22
dm-1              0.00     0.00  804.29  726.35 79037.52 76893.81 203.75    64.68   43.03    0.53   90.08   0.44  66.75

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
 5.22    0.00   11.21   36.21    0.00   47.36

Device:         rrqm/s   wrqm/s     r/s     w/s    rkB/s    wkB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               1.10     0.30  749.40  429.70 84589.20 43619.80 217.47    76.31   66.49    0.43  181.69   0.58  68.32
dm-0              0.00     0.00    1.30    0.10     5.20     0.40 8.00     0.00    2.21    1.00   18.00   1.43   0.20
dm-1              0.00     0.00  749.00  391.20 84558.40 41891.80 221.80    76.85   69.23    0.43  200.95   0.60  68.97

```

从`iostat`的输出中，我们可以确定以下信息：

+   该系统的 CPU 目前花费了相当多的时间在等待 I/O，占 30%–40%。

+   看起来`dm-1`和`sda`设备是利用率最高的设备

+   从`iostat`来看，这些设备的利用率为 68%，这个数字似乎相当高

基于这些数据点，我们可以确定存在潜在的 I/O 利用率问题，除非 68%的利用率是预期的。

#### 使用 iotop 来确定哪些进程正在消耗磁盘带宽

现在我们已经确定了大量的 CPU 时间被用于等待 I/O，我们现在应该关注哪些进程最多地利用了磁盘。为了做到这一点，我们将使用`iotop`命令。

```
# iotop
Total DISK READ :     100.64 M/s | Total DISK WRITE :      23.91 M/s
Actual DISK READ:     100.67 M/s | Actual DISK WRITE:      38.04 M/s
 TID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN     IO> COMMAND
19358 be/4 root        0.00 B/s    0.00 B/s  0.00 % 40.38 % [kworker/u4:1]
20262 be/4 root      100.35 M/s   23.91 M/s  0.00 % 33.65 % bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp
 363 be/4 root        0.00 B/s    0.00 B/s  0.00 %  2.51 % [xfsaild/dm-1]
 32 be/4 root        0.00 B/s    0.00 B/s  0.00 %  1.74 % [kswapd0]

```

从`iotop`命令中，我们可以看到进程`20262`，它正在运行`bonnie++`命令，具有高利用率以及大量的磁盘读写值。

从`iotop`中，我们可以确定以下信息：

+   系统的每秒总磁盘读取量为 100.64 MBps

+   系统的每秒总磁盘写入量为 23.91 MBps

+   运行`bonnie++`命令的进程`20262`正在读取 100.35 MBps，写入 23.91 MBps

+   比较总数，我们发现进程`20262`是磁盘读写的主要贡献者

鉴于上述情况，似乎我们需要更多地了解进程`20262`的信息。

#### 使用 ps 来更多地了解进程

现在我们已经确定了一个使用大量 I/O 的进程，我们可以使用`ps`命令来调查这个进程的详细信息。我们将再次使用带有`--forest`标志的`ps`命令来显示父进程和子进程的关系。

```
# ps -elf --forest
1007  0  80   0 - 32881 poll_s Feb08 ?        00:00:00  \_ sshd: vagrant [priv]
5 S vagrant  11242 11239  0  80   0 - 32881 poll_s Feb08 ? 00:00:05      \_ sshd: vagrant@pts/2
0 S vagrant  11243 11242  0  80   0 - 28838 wait   Feb08 pts/2 00:00:02          \_ -bash
4 S root     20753 11243  0  80   0 - 47343 poll_s 03:52 pts/2 00:00:00              \_ sudo bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp
4 D root     20754 20753 52  80   0 -  4233 sleep_ 03:52 pts/2 00:00:01                  \_ bonnie++ -n 0 -u 0 -r 239 -s 478 -f -b -d /tmp

```

使用`ps`命令，我们可以确定以下内容：

+   用`iotop`识别的`bonnie++`进程`20262`不见了；然而，其他`bonnie++`进程存在

+   `vagrant`用户已经通过使用`sudo`命令启动了父`bonnie++`进程

+   `vagrant`用户与早期观察中讨论的 CPU 和内存部分的用户相同

鉴于上述细节，似乎`vagrant`用户是我们性能问题的嫌疑人。

## 网络

性能问题的最后一个常见资源是网络。有许多工具可以用来排除网络问题；然而，这些命令中很少有专门针对网络性能的。大多数这些工具都是为深入的网络故障排除而设计的。

由于第五章，*网络故障排除*专门用于解决网络问题，本节将专门关注性能。

### ifstat - 查看接口统计

在网络方面，有大约四个指标可以用来衡量吞吐量。

+   **接收数据包**：接口接收的数据包数量

+   **发送数据包**：接口发送的数据包数量

+   **接收数据**：接口接收的数据量

+   **发送数据**：接口发送的数据量

有许多命令可以提供这些指标，从`ifconfig`或`ip`到`netstat`都有。一个非常有用的专门输出这些指标的实用程序是`ifstat`命令。

```
# ifstat
#21506.1804289383 sampling_interval=5 time_const=60
Interface   RX Pkts/Rate   TX Pkts/Rate   RX Data/Rate   TX Data/Rate
 RX Errs/Drop   TX Errs/Drop   RX Over/Rate   TX Coll/Rate
lo              47 0            47 0         4560 0          4560 0
 0 0             0 0            0 0             0 0
enp0s3       70579 1         50636 0      17797K 65        5520K 96
 0 0             0 0            0 0             0 0
enp0s8       23034 0            43 0       2951K 18          7035 0
 0 0             0 0            0 0             0 0

```

与`vmstat`或`iostat`类似，`ifstat`生成的第一个报告是基于服务器上次重启以来的统计数据。这意味着上面的报告表明`enp0s3`接口自上次重启以来已接收了 70,579 个数据包。

当第二次执行`ifstat`时，结果将与第一个报告有很大的差异。原因是第二个报告是基于自第一个报告以来的时间。

```
# ifstat
#21506.1804289383 sampling_interval=5 time_const=60
Interface   RX Pkts/Rate    TX Pkts/Rate   RX Data/Rate  TX Data/Rate
 RX Errs/Drop    TX Errs/Drop   RX Over/Rate  TX Coll/Rate
lo                0 0             0 0             0 0             0 0
 0 0             0 0             0 0             0 0
enp0s3           23 0            18 0         1530 59         1780 80
 0 0             0 0             0 0             0 0
enp0s8            1 0             0 0           86 10             0 0
 0 0             0 0             0 0             0 0

```

在上面的例子中，我们可以看到我们的系统通过`enp0s3`接口接收了 23 个数据包（RX Pkts）并发送了 18 个数据包（`TX Pkts`）。

通过`ifstat`命令，我们可以确定以下关于我们的系统的内容：

+   目前的网络利用率相当小，不太可能对整个系统造成影响

+   早期显示的`vagrant`用户的进程不太可能利用大量网络资源

根据`ifstat`所见的统计数据，在这个系统上几乎没有网络流量，不太可能导致感知到的缓慢。

## 对我们已经确定的内容进行快速回顾

在继续之前，让我们回顾一下到目前为止我们从性能统计数据中学到的东西：

### 注意

`vagrant`用户一直在启动运行`bonnie++`和`lookbusy`应用程序的进程。

`lookbusy`应用程序似乎要么一直占用整个系统 CPU 的 20%–30%。

这个服务器有两个 CPU，`lookbusy`似乎一直占用一个 CPU 的大约 60%。

`lookbusy`应用程序似乎也一直使用大约 200 MB 的内存；然而，在故障排除期间，我们确实看到这些进程几乎使用了系统的所有内存，导致系统交换。

在启动`bonnie++`进程时，`vagrant`用户的系统经历了高 I/O 等待时间。

在运行时，`bonnie++`进程利用了大约 60%–70%的磁盘吞吐量。

`vagrant`用户正在执行的活动似乎对网络利用率几乎没有影响。

# 比较历史指标

从迄今为止我们了解到的所有事实来看，我们下一个最佳行动方案似乎是建议联系`vagrant`用户，以确定`lookbusy`和`bonnie++`应用程序是否应该以如此高的资源利用率运行。

尽管先前的观察显示了高资源利用率，但这种利用率水平可能是预期的。在开始联系用户之前，我们应该首先审查服务器的历史性能指标。在大多数环境中，都会有一些服务器性能监控软件，如 Munin、Cacti 或许多云 SaaS 提供商之一，用于收集和存储系统统计信息。

如果您的环境使用了这些服务，您可以使用收集的性能数据来将以前的性能统计与我们刚刚收集到的信息进行比较。例如，在过去 30 天中，CPU 性能从未超过 10%，那么`lookbusy`进程可能在那个时候没有运行。

即使您的环境没有使用这些工具之一，您仍然可以执行历史比较。为此，我们将使用一个默认安装在大多数 Red Hat Enterprise Linux 系统上的工具；这个工具叫做`sar`。

## sar – 系统活动报告

在第二章，*故障排除命令和有用信息来源*中，我们简要讨论了使用`sar`命令来查看历史性能统计信息。

当安装了部署`sar`实用程序的`sysstat`软件包时，它将部署`/etc/cron.d/sysstat`文件。在这个文件中有两个`cron`作业，运行`sysstat`命令，其唯一目的是收集系统性能统计信息并生成收集信息的报告。

```
$ cat /etc/cron.d/sysstat
# Run system activity accounting tool every 10 minutes
*/2 * * * * root /usr/lib64/sa/sa1 1 1
# 0 * * * * root /usr/lib64/sa/sa1 600 6 &
# Generate a daily summary of process accounting at 23:53
53 23 * * * root /usr/lib64/sa/sa2 -A

```

当执行这些命令时，收集的信息将存储在`/var/log/sa/`文件夹中。

```
# ls -la /var/log/sa/
total 1280
drwxr-xr-x. 2 root root   4096 Feb  9 00:00 .
drwxr-xr-x. 9 root root   4096 Feb  9 03:17 ..
-rw-r--r--. 1 root root  68508 Feb  1 23:20 sa01
-rw-r--r--. 1 root root  40180 Feb  2 16:00 sa02
-rw-r--r--. 1 root root  28868 Feb  3 05:30 sa03
-rw-r--r--. 1 root root  91084 Feb  4 20:00 sa04
-rw-r--r--. 1 root root  57148 Feb  5 23:50 sa05
-rw-r--r--. 1 root root  34524 Feb  6 23:50 sa06
-rw-r--r--. 1 root root 105224 Feb  7 23:50 sa07
-rw-r--r--. 1 root root 235312 Feb  8 23:50 sa08
-rw-r--r--. 1 root root 105224 Feb  9 06:00 sa09
-rw-r--r--. 1 root root  56616 Jan 23 23:00 sa23
-rw-r--r--. 1 root root  56616 Jan 24 20:10 sa24
-rw-r--r--. 1 root root  24648 Jan 30 23:30 sa30
-rw-r--r--. 1 root root  11948 Jan 31 23:20 sa31
-rw-r--r--. 1 root root  44476 Feb  5 23:53 sar05
-rw-r--r--. 1 root root  27244 Feb  6 23:53 sar06
-rw-r--r--. 1 root root  81094 Feb  7 23:53 sar07
-rw-r--r--. 1 root root 180299 Feb  8 23:53 sar08

```

`sysstat`软件包生成的数据文件使用遵循“`sa<两位数的日期>`”格式的文件名。例如，在上面的输出中，我们可以看到“`sa24`”文件是在 1 月 24 日生成的。我们还可以看到这个系统有从 1 月 23 日到 2 月 9 日的文件。

`sar`命令是一个允许我们读取这些捕获的性能指标的命令。本节将向您展示如何使用`sar`命令来查看与`iostat`、`top`和`vmstat`等命令之前查看的相同统计信息。然而，这次`sar`命令将提供最近和历史信息。

### CPU

要使用`sar`命令查看 CPU 统计信息，我们可以简单地使用`–u`（CPU 利用率）标志。

```
# sar -u
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/09/2015   _x86_64_  (2 CPU)

12:00:01 AM     CPU     %user     %nice   %system   %iowait    %steal %idle
12:10:02 AM     all      7.42      0.00     13.46     37.51      0.00 41.61
12:20:01 AM     all      7.59      0.00     13.61     38.55      0.00 40.25
12:30:01 AM     all      7.44      0.00     13.46     38.50      0.00 40.60
12:40:02 AM     all      8.62      0.00     15.71     31.42      0.00 44.24
12:50:02 AM     all      8.77      0.00     16.13     29.66      0.00 45.44
01:00:01 AM     all      8.88      0.00     16.20     29.43      0.00 45.49
01:10:01 AM     all      7.46      0.00     13.64     37.29      0.00 41.61
01:20:02 AM     all      7.35      0.00     13.52     37.79      0.00 41.34
01:30:01 AM     all      7.40      0.00     13.36     38.60      0.00 40.64
01:40:01 AM     all      7.42      0.00     13.53     37.86      0.00 41.19
01:50:01 AM     all      7.44      0.00     13.58     38.38      0.00 40.60
04:20:02 AM     all      7.51      0.00     13.72     37.56      0.00 41.22
04:30:01 AM     all      7.34      0.00     13.36     38.56      0.00 40.74
04:40:02 AM     all      7.40      0.00     13.41     37.94      0.00 41.25
04:50:01 AM     all      7.45      0.00     13.81     37.73      0.00 41.01
05:00:02 AM     all      7.49      0.00     13.75     37.72      0.00 41.04
05:10:01 AM     all      7.43      0.00     13.30     39.28      0.00 39.99
05:20:02 AM     all      7.24      0.00     13.17     38.52      0.00 41.07
05:30:02 AM     all     13.47      0.00     11.10     31.12      0.00 44.30
05:40:01 AM     all     67.05      0.00      1.92      0.00      0.00 31.03
05:50:01 AM     all     68.32      0.00      1.85      0.00      0.00 29.82
06:00:01 AM     all     69.36      0.00      1.76      0.01      0.00 28.88
06:10:01 AM     all     70.53      0.00      1.71      0.01      0.00 27.76
Average:        all     14.43      0.00     12.36     33.14      0.00 40.07

```

如果我们从上面的头信息中查看，我们可以看到带有`-u`标志的`sar`命令与`iostat`和 top CPU 详细信息相匹配。

```
12:00:01 AM     CPU     %user     %nice   %system   %iowait    %steal %idle

```

从`sar -u`的输出中，我们可以发现一个有趣的趋势：从 00:00 到 05:30，CPU I/O 等待时间保持在 30%–40%。然而，从 05:40 开始，I/O 等待时间减少，但用户级 CPU 利用率增加到 65%–70%。

尽管这两个测量并没有明确指向任何一个过程，但它们表明 I/O 等待时间最近已经减少，而用户 CPU 时间已经增加。

为了更好地了解历史统计信息，我们需要查看前一天的 CPU 利用率。幸运的是，我们可以使用`–f`（文件名）标志来做到这一点。`–f`标志将允许我们为`sar`命令指定一个历史文件。这将允许我们有选择地查看前一天的统计信息。

```
# sar -f /var/log/sa/sa07 -u
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/07/2015 _x86_64_  (2 CPU)

12:00:01 AM     CPU     %user     %nice   %system   %iowait    %steal %idle
12:10:01 AM     all     24.63      0.00      0.71      0.00      0.00 74.66
12:20:01 AM     all     25.31      0.00      0.70      0.00      0.00 73.99
01:00:01 AM     all     27.59      0.00      0.68      0.00      0.00 71.73
01:10:01 AM     all     29.64      0.00      0.71      0.00      0.00 69.65
05:10:01 AM     all     44.09      0.00      0.63      0.00      0.00 55.28
05:20:01 AM     all     60.94      0.00      0.58      0.00      0.00 38.48
05:30:01 AM     all     62.32      0.00      0.56      0.00      0.00 37.12
05:40:01 AM     all     63.74      0.00      0.56      0.00      0.00 35.70
05:50:01 AM     all     65.08      0.00      0.56      0.00      0.00 34.35
0.00     76.07
Average:        all     37.98      0.00      0.65      0.00      0.00 61.38

```

在 2 月 7 日的报告中，我们可以看到 CPU 利用率与我们之前的故障排除所发现的情况有很大的不同。一个突出的问题是，在 7 日的报告中，没有 CPU 时间花费在 I/O 等待状态。

然而，我们看到用户 CPU 时间根据一天中的时间波动从 20%到 65%不等。这可能表明预期会有更高的用户 CPU 时间利用率。

### 内存

要显示内存统计信息，我们可以使用带有`-r`（内存）标志的`sar`命令。

```
# sar -r
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/09/2015 _x86_64_  (2 CPU)

12:00:01 AM kbmemfree kbmemused  %memused kbbuffers  kbcached kbcommit   %commit  kbactive   kbinact   kbdirty
12:10:02 AM     38228    463832     92.39         0    387152 446108     28.17    196156    201128         0
12:20:01 AM     38724    463336     92.29         0    378440 405128     25.59    194336    193216     73360
12:30:01 AM     38212    463848     92.39         0    377848 405128     25.59      9108    379348     58996
12:40:02 AM     37748    464312     92.48         0    387500 446108     28.17    196252    201684         0
12:50:02 AM     33028    469032     93.42         0    392240 446108     28.17    196872    205884         0
01:00:01 AM     34716    467344     93.09         0    380616 405128     25.59    195900    195676     69332
01:10:01 AM     31452    470608     93.74         0    384092 396660     25.05    199100    196928     74372
05:20:02 AM     38756    463304     92.28         0    387120 399996     25.26    197184    198456         4
05:30:02 AM    187652    314408     62.62         0     19988 617000     38.97    222900     22524         0
05:40:01 AM    186896    315164     62.77         0     20116 617064     38.97    223512     22300         0
05:50:01 AM    186824    315236     62.79         0     20148 617064     38.97    223788     22220         0
06:00:01 AM    182956    319104     63.56         0     24652 615888     38.90    226744     23288         0
06:10:01 AM    176992    325068     64.75         0     29232 615880     38.90    229356     26500         0
06:20:01 AM    176756    325304     64.79         0     29480 615884     38.90    229448     26588         0
06:30:01 AM    176636    325424     64.82         0     29616 615888     38.90    229516     26820         0
Average:        77860    424200     84.49         0    303730 450102     28.43    170545    182617     29888

```

再次，如果我们查看`sar`的内存报告标题，我们可以看到一些熟悉的值。

```
12:00:01 AM kbmemfree kbmemused  %memused kbbuffers  kbcached kbcommit   %commit  kbactive   kbinact   kbdirty

```

从这份报告中，我们可以看到在 05:40 时，系统突然释放了 150MB 的物理内存。从`kbcached`列可以看出，这 150MB 的内存被分配给了磁盘缓存。这是基于 05:40 时，缓存内存从 196MB 下降到 22MB 的事实。

有趣的是，这与 CPU 利用率的变化在 05:40 也是一致的。如果我们希望回顾历史内存利用情况，我们也可以使用带有`-f`（文件名）标志和`-r`（内存）标志。然而，由于我们可以看到 05:40 有一个相当明显的趋势，我们现在将重点放在这个时间上。

### 磁盘

要显示今天的磁盘统计信息，我们可以使用`-d`（块设备）标志。

```
# sar -d
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/09/2015 _x86_64_  (2 CPU)

12:00:01 AM       DEV       tps  rd_sec/s  wr_sec/s  avgrq-sz  avgqu-sz     await     svctm     %util
12:10:02 AM    dev8-0   1442.64 150584.15 146120.49    205.67 82.17     56.98      0.51     74.17
12:10:02 AM  dev253-0      1.63     11.11      1.96      8.00 0.06     34.87     19.72      3.22
12:10:02 AM  dev253-1   1402.67 150572.19 146051.96    211.47 82.73     58.98      0.53     74.68
04:20:02 AM    dev8-0   1479.72 152799.09 150240.77    204.80 81.27     54.89      0.50     73.86
04:20:02 AM  dev253-0      1.74     10.98      2.96      8.00 0.06     31.81     14.60      2.54
04:20:02 AM  dev253-1   1438.57 152788.11 150298.01    210.69 81.84     56.83      0.52     74.38
05:30:02 AM  dev253-0      1.00      7.83      0.17      8.00 0.00      3.81      2.76      0.28
05:30:02 AM  dev253-1   1170.61 123647.27 122655.72    210.41 69.12     59.04      0.53     62.20
05:40:01 AM    dev8-0      0.08      1.00      0.34     16.10 0.00      1.88      1.00      0.01
05:40:01 AM  dev253-0      0.11      0.89      0.00      8.00 0.00      1.57      0.25      0.00
05:40:01 AM  dev253-1      0.05      0.11      0.34      8.97 0.00      2.77      1.17      0.01
05:50:01 AM    dev8-0      0.07      0.49      0.28     11.10 0.00      1.71      1.02      0.01
05:50:01 AM  dev253-0      0.06      0.49      0.00      8.00 0.00      2.54      0.46      0.00
05:50:01 AM  dev253-1      0.05      0.00      0.28      6.07 0.00      1.96      0.96      0.00

Average:          DEV       tps  rd_sec/s  wr_sec/s  avgrq-sz avgqu-sz     await     svctm     %util
Average:       dev8-0   1215.88 125807.06 123583.62    205.11 66.86     55.01      0.50     60.82
Average:     dev253-0      2.13     12.48      4.53      8.00 0.10     44.92     17.18      3.65
Average:     dev253-1   1181.94 125794.56 123577.42    210.99 67.31     56.94      0.52     61.17

```

默认情况下，`sar`命令将打印设备名称为“`dev<major>-<minor>`”，这可能有点令人困惑。如果添加了`-p`（持久名称）标志，设备名称将使用持久名称，与挂载命令中的设备匹配。

```
# sar -d -p
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   08/16/2015 _x86_64_  (4 CPU)

01:46:42 AM       DEV       tps  rd_sec/s  wr_sec/s  avgrq-sz  avgqu-sz     await     svctm     %util
01:48:01 AM       sda      0.37      0.00      3.50      9.55 0.00      1.86      0.48      0.02
01:48:01 AM rhel-swap      0.00      0.00      0.00      0.00 0.00      0.00      0.00      0.00
01:48:01 AM rhel-root      0.37      0.00      3.50      9.55 0.00      2.07      0.48      0.02

```

即使名称以不可识别的格式显示，我们也可以看到`dev253-1`似乎在 05:40 之前有相当多的活动，磁盘`tps`（每秒事务）从 1170 下降到 0.11。磁盘 I/O 利用率的大幅下降似乎表明今天在 05:40 发生了相当大的变化。

### 网络

要显示网络统计信息，我们需要使用带有`-n DEV`标志的`sar`命令。

```
# sar -n DEV
Linux 3.10.0-123.el7.x86_64 (blog.example.com)   02/09/2015 _x86_64_  (2 CPU)

12:00:01 AM     IFACE   rxpck/s   txpck/s    rxkB/s    txkB/s rxcmp/s   txcmp/s  rxmcst/s
12:10:02 AM    enp0s3      1.51      1.18      0.10      0.12 0.00      0.00      0.00
12:10:02 AM    enp0s8      0.14      0.00      0.02      0.00 0.00      0.00      0.07
12:10:02 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
12:20:01 AM    enp0s3      0.85      0.85      0.05      0.08 0.00      0.00      0.00
12:20:01 AM    enp0s8      0.18      0.00      0.02      0.00 0.00      0.00      0.08
12:20:01 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
12:30:01 AM    enp0s3      1.45      1.16      0.10      0.11 0.00      0.00      0.00
12:30:01 AM    enp0s8      0.18      0.00      0.03      0.00 0.00      0.00      0.08
12:30:01 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
05:20:02 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
05:30:02 AM    enp0s3      1.23      1.02      0.08      0.11 0.00      0.00      0.00
05:30:02 AM    enp0s8      0.15      0.00      0.02      0.00 0.00      0.00      0.04
05:30:02 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
05:40:01 AM    enp0s3      0.79      0.78      0.05      0.14 0.00      0.00      0.00
05:40:01 AM    enp0s8      0.18      0.00      0.02      0.00 0.00      0.00      0.08
05:40:01 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
05:50:01 AM    enp0s3      0.76      0.75      0.05      0.13 0.00      0.00      0.00
05:50:01 AM    enp0s8      0.16      0.00      0.02      0.00 0.00      0.00      0.07
05:50:01 AM        lo      0.00      0.00      0.00      0.00 0.00      0.00      0.00
06:00:01 AM    enp0s3      0.67      0.60      0.04      0.10 0.00      0.00      0.00

```

在网络统计报告中，我们看到整天都没有变化。这表明，总体上，这台服务器从未出现与网络性能瓶颈相关的问题。

## 通过比较历史统计数据来回顾我们所学到的内容

通过使用`sar`查看历史统计数据和使用`ps`、`iostat`、`vmstat`和`top`等命令查看最近的统计数据后，我们可以得出关于我们的“性能慢”的以下结论。

由于我们被同事要求调查这个问题，我们的结论将以电子邮件回复的形式发送给这位同事。

*嗨鲍勃！*

*我调查了一个用户说服务器“慢”的服务器。看起来用户 vagrant 一直在运行两个主要程序的多个实例。第一个是 lookbusy 应用程序，似乎始终使用大约 20%–40%的 CPU。然而，至少有一个实例中，lookbusy 应用程序还使用了大量内存，耗尽了物理内存并迫使系统大量交换。然而，这个过程并没有持续很长时间。*

*第二个程序是 bonnie++应用程序，似乎利用了大量的磁盘 I/O 资源。当 vagrant 用户运行 bonnie++应用程序时，它占用了大约 60%的 dm-1 和 sda 磁盘带宽，导致了大约 30%的高 I/O 等待。通常，这个系统的 I/O 等待为 0%（通过 sar 确认）。*

*看起来 vagrant 用户可能正在运行超出预期水平的应用程序，导致其他用户的性能下降。*

# 总结

在本章中，我们开始使用一些高级的 Linux 命令，这些命令在第二章中进行了探索，例如`iostat`和`vmstat`。我们还对 Linux 中的一个基本实用程序`ps`命令非常熟悉，同时解决了一个模糊的性能问题。

在第三章中，*故障排除 Web 应用程序*，我们能够从数据收集到试错的完整故障排除过程，而在本章中，我们的行动主要集中在数据收集和建立假设阶段。发现自己只是在解决问题而不是执行纠正措施是非常常见的。有许多问题应该由系统的用户而不是系统管理员来解决，但管理员的角色仍然是识别问题的来源。

在第五章中，*网络故障排除*，我们将解决一些非常有趣的网络问题。网络对于任何系统都至关重要；问题有时可能很简单，而有时则非常复杂。在下一章中，我们将探讨网络和如何使用诸如`netstat`和`tcpdump`之类的工具来排除网络问题。


# 第五章：网络故障排除

在第三章中，*故障排除 Web 应用程序*，我们深入研究了故障排除 Web 应用程序；虽然我们解决了一个复杂的应用程序错误，但我们完全跳过了 Web 应用程序的网络方面。在本章中，我们将调查一个报告的问题，这将引导我们了解 DNS、路由，当然还有 RHEL 系统的网络配置等概念。

对于任何 Linux 系统管理员来说，网络是一项必不可少的技能。引用一位过去的讲师的话：

> 没有网络的服务器对每个人都是无用的。

作为系统管理员，您管理的每台服务器或台式机都将有某种网络连接。无论这种网络连接是在隔离的公司网络内还是直接连接到互联网，都涉及到网络。

由于网络是一个如此关键的主题，本章将涵盖网络和网络连接的许多方面；然而，它不会涵盖防火墙。防火墙故障排除和配置实际上将在第六章中进行，*诊断和纠正防火墙问题*。

# 数据库连接问题

在第三章中，*故障排除 Web 应用程序*，我们正在解决公司博客的问题。在本章中，我们将再次解决这个博客；然而，今天的问题有点不同。

到达当天后，我们接到一位开发人员的电话，他说：“WordPress 博客返回了一个无法连接到数据库的错误”。

# 数据收集

根据我们一直遵循的故障排除过程，下一步是尽可能收集关于问题的数据。信息的最佳来源之一是报告问题的人；对于这种情况，我们将问两个基本问题：

+   我如何复制问题并查看错误？

+   最近 WordPress 应用有什么变化吗？

当被问及时，开发人员表示我们只需在网页浏览器中访问博客就可以看到错误。在第二个问题上，开发人员告诉我们，数据库服务最近从 Web 服务器移动到了一个新的专用数据库服务器。他还提到这个移动是在几天前发生的，并且应用程序一直到今天都在工作。

由于数据库服务是几天前移动的，而且应用程序直到今天早上都在工作，所以这个改变不太可能引起问题。然而，我们不应该排除这种可能性。

## 复制问题

正如前几章讨论的，关键的数据收集任务是复制问题。我们这样做不仅是为了验证报告的问题是否确实存在，还为了找出可能没有被报告的任何其他错误。

由于开发人员表示我们可以直接访问博客来复制这个问题，我们将在网页浏览器中进行操作。

![复制问题](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel-tbst-gd/img/00004.jpeg)

似乎我们可以很容易地复制这个问题。根据这个错误，似乎应用程序只是在说它在建立数据库连接时出现了问题。虽然这本身并不意味着问题与网络有关，但也可能是。问题也可能只是数据库服务本身的问题。

为了确定问题是网络问题还是数据库服务问题，我们首先需要找出应用程序配置为连接到哪个服务器。

## 查找数据库服务器

与上一章类似，我们将通过查看应用程序配置文件来确定应用程序使用的服务器。根据我们在第三章中的先前故障排除，*故障排除 Web 应用程序*，我们知道 WordPress 应用程序托管在`blog.example.com`上。首先，我们将登录到博客的 Web 服务器并查看 WordPress 配置文件。

```
$ ssh blog.example.com -l vagrant
vagrant@blog.example.com's password:
Last login: Sat Feb 28 18:49:40 2015 from 10.0.2.2
[blog]$

```

### 提示

由于我们将针对多个系统执行命令，因此本章的示例将在命令行提示中包含主机名，如`blog`或`db`。

我们在第三章中学到，WordPress 数据库配置存储在`/var/www/html/wp-config.php`文件中。为了快速搜索该文件以获取数据库信息，我们可以使用`grep`命令搜索字符串`DB`，因为在我们先前的事件中，该字符串出现在数据库配置中。

```
[blog]$ grep DB wp-config.php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wordpress');
define('DB_PASSWORD', 'password');
define('DB_HOST', 'db.example.com');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');

```

通过上述内容，我们可以看到该应用程序当前配置为连接到`db.example.com`。简单的第一步故障排除是尝试手动连接到数据库。手动测试数据库连接的简单方法是使用`telnet`命令。

## 测试连接

`telnet`命令是一个非常有用的网络和网络服务故障排除工具，因为它旨在简单地建立到指定主机和端口的基于 TCP 的网络连接。在我们的例子中，我们将尝试连接到主机`db.example.com`的端口`3306`。

端口`3306`是 MySQL 和 MariaDB 的默认端口；在上一章中，我们已经确定了这个 Web 应用程序需要这两个数据库服务中的一个。由于在`wp-config.php`文件的配置中没有看到特定的端口，我们将假设数据库服务正在运行在这个默认端口上。

### 从 blog.example.com 进行 Telnet

首先，我们将从博客服务器本身执行`telnet`命令。从应用程序运行的同一服务器进行测试非常重要，因为这样可以在应用程序接收到错误的相同网络条件下进行测试。

为了使用 telnet 连接到我们的数据库服务器，我们将执行`telnet`命令，后面跟着我们希望连接到的主机名（`db.example.com`）和端口（`3306`）。

```
[blog]$ telnet db.example.com 3306
Trying 192.168.33.12...
telnet: connect to address 192.168.33.12: No route to host

```

Telnet 连接似乎失败了。有趣的是提供的错误；**无法连接到主机**错误似乎清楚地指示了潜在的网络问题。

### 从我们的笔记本电脑进行 Telnet

由于从博客服务器的连接尝试失败，并指示存在与网络相关的问题，我们可以尝试从我们的笔记本电脑进行相同的连接，以确定问题是在博客服务器端还是`db`服务器端。

为了从我们的笔记本电脑测试这种连接，我们可以再次使用`telnet`命令。尽管我们的笔记本电脑不一定运行 Linux 操作系统，但我们仍然可以使用这个命令。原因是`telnet`命令是一个跨平台实用程序；在本章中，我们将利用几个跨平台命令。虽然这样的命令可能不多，但一般来说，有几个命令适用于大多数操作系统，包括那些传统上没有广泛命令行功能的系统。

虽然一些操作系统已经从默认安装中删除了`telnet`客户端，但该软件仍然可以安装。在我们的例子中，笔记本电脑正在运行 OS X，该系统目前部署了`telnet`客户端。

```
[laptop]$ telnet db.example.com 3306
Trying 10.0.0.50...
Connected to 10.0.0.50.
Escape character is '^]'.
Connection closed by foreign host.

```

看起来我们的笔记本也无法连接到数据库服务；然而，这次错误不同。这次似乎表明连接尝试被远程服务关闭。我们也没有看到来自远程服务的消息，这表明连接从未完全建立。

使用`telnet`命令建立端口可用性的一个注意事项是，`telnet`命令将显示连接为**已连接**；然而，此时连接可能并没有真正建立。在使用 telnet 时的一般规则是，在收到来自远程服务的消息之前，不要假设连接成功。在我们的例子中，我们没有收到来自远程服务的消息。

## Ping

由于博客服务器和我们的笔记本都无法从“db”服务器进行 telnet 连接，我们应该检查问题是否仅限于数据库服务或整个服务器的连接。测试服务器之间的连接的一个工具是`ping`命令，就像`telnet`命令一样是一个跨平台实用程序。

要使用`ping`命令测试与主机的连接性，我们只需执行命令，然后跟随我们希望`ping`的主机。

```
[blog]$ ping db.example.com
PING db.example.com (192.168.33.12) 56(84) bytes of data.
From blog.example.com (192.168.33.11) icmp_seq=1 Destination Host Unreachable
From blog.example.com (192.168.33.11) icmp_seq=2 Destination Host Unreachable
From blog.example.com (192.168.33.11) icmp_seq=3 Destination Host Unreachable
From blog.example.com (192.168.33.11) icmp_seq=4 Destination Host Unreachable
^C
--- db.example.com ping statistics ---
6 packets transmitted, 0 received, +4 errors, 100% packet loss, time 5008ms

```

`ping`命令的错误似乎与`telnet`命令的错误非常相似。为了更好地理解这个错误，让我们首先更好地了解`ping`命令的工作原理。

首先，在执行任何其他操作之前，`ping`命令将尝试解析提供的主机名。这意味着在执行任何其他操作之前，我们的 ping 执行尝试识别`db.example.com`的 IP 地址。

```
PING db.example.com (192.168.33.12) 56(84) bytes of data.

```

从结果中，我们可以看到`ping`命令将此主机解析为`192.168.33.12`。一旦 ping 有了 IP 地址，它将向该 IP 发送一个`ICMP`回显请求网络数据包。在这种情况下，这意味着它正在向`192.168.33.12`发送一个`ICMP`回显请求。

ICMP 是一种用作控制系统的网络协议。当远程主机，比如`192.168.33.12`接收到`ICMP`回显请求网络数据包时，它应该发送一个`ICMP`回显回复网络数据包回到请求的主机。这种活动允许两个主机通过进行简单的网络版本的“乒乓球”来验证网络连接。

```
From blog.example.com (192.168.33.11) icmp_seq=1 Destination Host Unreachable

```

如果我们的`ICMP`回显请求数据包从`192.168.33.12`服务器没有传输过来，我们的`ping`命令就不会有任何输出。然而，我们收到了一个错误；这意味着另一端的系统是开启的，但两个主机之间的连接存在问题，阻止了完全的双向交流。

围绕这个问题出现的一个问题是，这个错误是否适用于博客服务器的所有网络连接，还是仅限于`blog`和`db`服务器之间的通信。我们可以通过向另一个通用地址执行`ping`请求来测试这一点。由于我们的系统连接到互联网，我们可以简单地使用一个常见的互联网域名。

```
# ping google.com
PING google.com (216.58.216.46) 56(84) bytes of data.
64 bytes from lax02s22-in-f14.1e100.net (216.58.216.46): icmp_seq=1 ttl=63 time=23.5 ms
64 bytes from lax02s22-in-f14.1e100.net (216.58.216.46): icmp_seq=2 ttl=63 time=102 ms
64 bytes from lax02s22-in-f14.1e100.net (216.58.216.46): icmp_seq=3 ttl=63 time=26.9 ms
64 bytes from lax02s22-in-f14.1e100.net (216.58.216.46): icmp_seq=4 ttl=63 time=25.6 ms
64 bytes from lax02s22-in-f14.1e100.net (216.58.216.46): icmp_seq=5 ttl=63 time=25.6 ms
^C
--- google.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4106ms
rtt min/avg/max/mdev = 23.598/40.799/102.156/30.697 ms

```

前面的例子是一个工作的`ping`请求和回复的例子。在这里，我们不仅可以看到[Google.com](http://Google.com)解析为的 IP，还可以看到返回的`ping`请求。这意味着，当我们的博客服务器发送一个“ICMP 回显请求”时，远程服务器`216.58.216.46`会发送一个“ICMP 回显回复”。

## 故障排除 DNS

除了网络连接之外，`ping`和`telnet`命令告诉我们的另一件有趣的事情是`db.example.com`主机名的 IP 地址。然而，当我们从我们的笔记本执行这些操作时，结果似乎与从博客服务器执行这些操作时不同。

从博客服务器，我们的`telnet`尝试连接到`192.168.33.12`，与我们的`ping`命令相同的地址。

```
[blog]$ telnet db.example.com 3306
Trying 192.168.33.12...
However, from the laptop, our telnet tried to connect to 10.0.0.50, a completely different IP address.
[laptop]$ telnet db.example.com 3306
Trying 10.0.0.50...

```

原因很简单；看起来我们的笔记本得到了与我们的博客服务器不同的 DNS 结果。然而，如果是这种情况，这可能意味着我们的问题可能只是与 DNS 问题有关。

### 使用 dig 检查 DNS

DNS 是现代网络的重要组成部分。我们当前的问题就是它重要性的一个完美例子。在 WordPress 配置文件中，我们的数据库服务器设置为`db.example.com`。这意味着在应用服务器建立数据库连接之前，必须首先查找 IP 地址。

在许多情况下，可以相当安全地假设`ping`识别的 IP 地址很可能是 DNS 呈现的 IP 地址。然而，并非总是如此，正如我们可能很快发现的那样。

`dig`命令是一个非常有用的 DNS 故障排除命令；它非常灵活，可以用来执行许多不同类型的 DNS 请求。要验证`db.example.com`的 DNS，我们只需执行`dig`命令，然后跟上我们要查询的主机名：`db.example.com`。

```
[blog]$ dig db.example.com

; <<>> DiG 9.9.4-RedHat-9.9.4-14.el7_0.1 <<>> db.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15857
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;db.example.com.      IN  A

;; ANSWER SECTION:
db.example.com.    15  IN  A  10.0.0.50

;; Query time: 39 msec
;; SERVER: 10.0.2.3#53(10.0.2.3)
;; WHEN: Sun Mar 01 20:51:22 UTC 2015
;; MSG SIZE  rcvd: 59

```

如果我们查看`dig`返回的数据，我们可以看到 DNS 名称`db.example.com`解析为`192.168.33.12`，而不是`10.0.0.50`。我们可以在`dig`命令的输出的`ANSWER SECTION`中看到这一点。

```
;; ANSWER SECTION:
db.example.com.    15  IN  A  10.0.0.50

```

`dig`的一个非常有用的选项是指定要查询的服务器。在之前执行的`dig`中，我们可以看到服务器`10.0.2.3`是提供`10.0.0.50`地址的服务器。

```
;; Query time: 39 msec
;; SERVER: 10.0.2.3#53(10.0.2.3)

```

由于我们对这个 DNS 服务器不熟悉，我们可以通过查询谷歌的公共 DNS 服务器来进一步验证返回的结果。我们可以通过在 DNS 服务器 IP 或主机名后面添加`@`来实现这一点。在下面的例子中，我们请求`8.8.8.8`，这是谷歌公共 DNS 基础设施的一部分。

```
[blog]$ dig @8.8.8.8 db.example.com

; <<>> DiG 9.9.4-RedHat-9.9.4-14.el7_0.1 <<>> @8.8.8.8 example.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42743
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;db.example.com.      IN  A

;; ANSWER SECTION:
db.example.com.    18639  IN  A  10.0.0.50

;; Query time: 39 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Sun Mar 01 22:14:53 UTC 2015
;; MSG SIZE  rcvd: 56
It seems that Google's public DNS has the same results as 10.0.2.3.

```

### 使用 nslookup 查找 DNS

另一个用于故障排除 DNS 的好工具是`nslookup`。`nslookup`命令已经存在了相当长的时间。实际上，它是另一个跨平台命令，几乎存在于所有主要操作系统上。

要使用`nslookup`进行简单的 DNS 查找，我们只需运行命令，然后跟上要查询的 DNS 名称，类似于`dig`。

```
[blog]$ nslookup db.example.com
Server:    10.0.2.3
Address:  10.0.2.3#53

Non-authoritative answer:
Name:  db.example.com
Address: 10.0.0.50

```

`dig`命令可以用于查询特定的 DNS 服务器。这可以通过两种方法来实现。第一种方法是在命令的末尾添加服务器地址。

```
[blog]$ nslookup db.example.com 8.8.8.8
Server:    8.8.8.8
Address:  8.8.8.8#53

Non-authoritative answer:
Name:  db.example.com
Address: 10.0.0.50

```

第二种方法是在交互模式下使用`nslookup`。要进入交互模式，只需执行`nslookup`而不使用其他选项。

```
# nslookup
>

```

进入交互模式后，通过输入`server <dns 服务器>`来指定要使用的服务器。

```
# nslookup
> server 8.8.8.8
Default server: 8.8.8.8
Address: 8.8.8.8#53
>

```

最后，要查找 DNS 名称，我们只需输入要查询的域。

```
# nslookup
> server 8.8.8.8
Default server: 8.8.8.8
Address: 8.8.8.8#53
> db.example.com
Server:    8.8.8.8
Address:  8.8.8.8#53

Non-authoritative answer:
Name:  db.example.com
Address: 10.0.0.50
>
To leave the interactive mode, simply type exit.
> exit

```

那么为什么使用`nslookup`而不是`dig`呢？虽然`dig`命令非常有用，但它不是一个跨平台命令，通常只存在于 Unix 和 Linux 系统上。另一方面，`nslookup`命令是跨平台的，可以在大多数环境中找到，而`dig`命令可能不可用。作为系统管理员，熟悉许多命令是很重要的，能够使用任何可用的命令来执行任务是非常有用的。

### `dig`和`nslookup`告诉了我们什么？

现在我们已经使用`dig`和`nslookup`来查询 DNS 名称`db.example.com`，让我们回顾一下我们找到了什么。

+   域`db.example.com`实际上解析为`10.0.0.50`

+   `ping`命令返回了域`db.example.com`的`192.168.33.12`地址。

`ping`命令返回一个地址，而 DNS 返回另一个地址，这是怎么回事？一个可能的原因是`/etc/hosts`文件中的配置。这是我们可以用简单的`grep`命令快速验证的事情。

```
[blog]$ grep example.com /etc/hosts
192.168.33.11 blog.example.com
192.168.33.12 db.example.com

```

#### 关于`/etc/hosts`的一点说明

在创建诸如**Bind**这样的 DNS 服务器之前，本地的`hosts`文件被用来管理域名到 IP 的映射。这个文件包含了系统需要连接的每个域地址的列表。然而，随着网络从几个主机发展到成千上万甚至数百万个主机，这种方法随着时间的推移变得复杂起来。

在 Linux 和大多数 Unix 发行版中，`hosts`文件位于`/etc/hosts`。默认情况下，`/etc/hosts`文件中的任何条目都将覆盖 DNS 请求。这意味着，默认情况下，如果`/etc/hosts`文件中存在域到 IP 的映射，系统将使用该映射，而不会从另一个 DNS 系统中获取相同的域。

这是 Linux 的默认行为；但是，我们可以通过阅读`/etc/nsswitch.conf`文件来检查该服务器是否使用此默认配置。

```
[blog]$ grep hosts /etc/nsswitch.conf
hosts:      files dns

```

`nsswitch.conf`文件是一个允许管理员配置要使用哪些后端系统来查找用户、组、网络组、主机名和服务等项目的配置。例如，如果我们想要配置系统使用`ldap`来查找用户组，我们可以通过更改`/etc/nsswitch.conf`文件中的值来实现。

```
[blog]$ grep group /etc/nsswitch.conf
group:      files sss

```

根据前面`grep`命令的输出，博客系统配置为首先使用本地组文件，然后使用 SSSD 服务来查找用户组。要将`ldap`添加到此配置中，只需按所需顺序（即“ldap 文件 sss”）将其添加到列表中。

对于由`hosts`配置指定的 DNS，似乎我们的服务器配置为首先基于文件查找主机，然后再查找 DNS。这意味着我们的系统会在通过 DNS 查找域之前优先使用`/etc/hosts`文件。

### DNS 总结

现在我们已经确认了 DNS 和`/etc/hosts`文件，我们知道有人配置了此应用服务器，使其认为`db.example.com`解析为`192.168.33.12`。这是一个错误还是一种在不使用 DNS 的情况下连接到数据库服务器的方式？

此时，现在还为时过早，但我们知道主机`192.168.33.12`没有向我们的博客服务器发送“ICMP 回显应答”来响应我们的“ICMP 回显请求”。

## 从另一个位置进行 ping

在处理网络问题时，最好尝试从多个位置或服务器进行连接。这对于数据收集类型的故障排除者可能似乎是显而易见的，但是受过教育的猜测型故障排除者可能会忽视这一极其有用的步骤。

在我们的示例中，我们将从笔记本电脑运行一个测试`ping`到`192.168.33.12`。

```
[laptop]$ ping 192.168.33.12
PING 192.168.33.12 (192.168.33.12): 56 data bytes
64 bytes from 192.168.33.12: icmp_seq=0 ttl=64 time=0.573 ms
64 bytes from 192.168.33.12: icmp_seq=1 ttl=64 time=0.425 ms
64 bytes from 192.168.33.12: icmp_seq=2 ttl=64 time=0.461 ms
^C
--- 192.168.33.12 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.425/0.486/0.573/0.063 ms

```

从`ping`请求的结果来看，我们的笔记本电脑似乎能够无问题地连接到`192.168.33.12`。

这告诉我们什么？实际上告诉我们很多！它告诉我们所讨论的服务器正在运行；它还确认了存在连接问题，特别是在`blog.example.com`和`db.example.com`之间。如果问题是由于`db.example.com`服务器宕机或配置错误引起的，我们的笔记本电脑也会受到影响。

然而事实并非如此。实际上恰恰相反；似乎我们的笔记本电脑与服务器之间的连接正常工作。

## 使用 cURL 测试端口连接

早些时候，当使用`telnet`从我们的笔记本电脑测试 MariaDB 端口时，`telnet`命令正在测试服务器`10.0.0.50`。然而，根据`/etc/hosts`配置，似乎期望的数据库服务器是`192.168.33.12`。

为了验证数据库服务实际上是否正常运行，我们应该使用`192.168.33.12`地址执行相同的`telnet`测试。但是，这一次我们将使用`curl`而不是`telnet`来执行此测试。

我见过许多环境（尤其是最近）禁止安装`telnet`客户端或默认情况下不执行安装。对于这样的环境，有一些可以测试端口连接的工具是很重要的。如果 telnet 不可用，可以使用`curl`命令作为替代。

在第三章中，“故障排除 Web 应用程序”，我们使用`curl`命令请求网页。实际上，`curl`命令可以与许多不同的协议一起使用；我们在这种情况下感兴趣的协议是 Telnet 协议。

以下是使用`curl`从我们的笔记本连接到`db.example.com`服务器的端口`3306`的示例。

```
[laptop]$  curl -v telnet://192.168.33.12:3306
* Rebuilt URL to: telnet://192.168.33.12:3306/
* Hostname was NOT found in DNS cache
*   Trying 192.168.33.12...
* Connected to 192.168.33.12 (192.168.33.12) port 3306 (#0)
* RCVD IAC 106
^C

```

从示例中，似乎不仅笔记本能够连接到端口`3306`的服务器，而且`curl`命令还收到了来自`RCVD IAC 106`服务的消息。

在进行 Telnet 测试时，使用`curl`时，需要使用`-v`（详细）标志将 curl 置于详细模式。没有详细标志，`curl`将简单地隐藏连接细节，而连接细节正是我们要寻找的。

在前面的例子中，我们可以看到从我们的笔记本成功连接；为了进行比较，我们可以使用相同的命令从博客服务器测试连接。

```
[blog]$ curl -v telnet://192.168.33.12:3306
* About to connect() to 192.168.33.12 port 3306 (#0)
*   Trying 192.168.33.12...
* No route to host
* Failed connect to 192.168.33.12:3306; No route to host
* Closing connection 0
curl: (7) Failed connect to 192.168.33.12:3306; No route to host

```

连接尝试失败，正如预期的那样。

从上面使用`curl`的测试中，我们可以确定数据库服务器正在监听并接受端口`3306`上的连接；但是，博客服务器无法连接到数据库服务器。我们不知道的是问题是在博客服务器端还是在数据库服务器端。要确定连接的哪一端存在问题，我们需要查看网络连接的详细信息。为此，我们将使用两个命令，第一个是`netstat`，第二个是`tcpdump`。

## 使用 netstat 显示当前网络连接

`netstat`命令是一个非常全面的工具，可以用于排除网络问题的许多方面。在这种情况下，我们将使用两个基本标志来打印现有的网络连接。

```
[blog]# netstat -na
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address State 
tcp        0      0 127.0.0.1:25            0.0.0.0:* LISTEN 
tcp        0      0 0.0.0.0:52903           0.0.0.0:* LISTEN 
tcp        0      0 0.0.0.0:3306            0.0.0.0:* LISTEN 
tcp        0      0 0.0.0.0:111             0.0.0.0:* LISTEN 
tcp        0      0 0.0.0.0:22              0.0.0.0:* LISTEN 
tcp        0      0 10.0.2.16:22            10.0.2.2:50322 ESTABLISHED
tcp        0      0 192.168.33.11:22        192.168.33.1:53359 ESTABLISHED
tcp6       0      0 ::1:25                  :::* LISTEN 
tcp6       0      0 :::57504                :::* LISTEN 
tcp6       0      0 :::111                  :::* LISTEN 
tcp6       0      0 :::80                   :::* LISTEN 
tcp6       0      0 :::22                   :::* LISTEN 
udp        0      0 0.0.0.0:5353            0.0.0.0:*
udp        0      0 0.0.0.0:68              0.0.0.0:*
udp        0      0 0.0.0.0:111             0.0.0.0:*
udp        0      0 0.0.0.0:52594           0.0.0.0:*
udp        0      0 127.0.0.1:904           0.0.0.0:*
udp        0      0 0.0.0.0:49853           0.0.0.0:*
udp        0      0 0.0.0.0:53449           0.0.0.0:*
udp        0      0 0.0.0.0:719             0.0.0.0:*
udp6       0      0 :::54762                :::*
udp6       0      0 :::58674                :::*
udp6       0      0 :::111                  :::*
udp6       0      0 :::719                  :::*
raw6       0      0 :::58                   :::*

```

在前面的例子中，我们使用了`-n`（无 dns）标志执行了`netstat`命令，告诉`netstat`不要查找 IP 的 DNS 主机名或将端口号转换为服务名称，以及`-a`（全部）标志，告诉`netstat`打印监听和非监听套接字。

这些标志的效果类似于`netstat`，显示所有应用程序绑定的所有网络连接和端口。

示例`netstat`命令显示了相当多的信息。为了更好地理解这些信息，让我们更仔细地检查一下输出。

```
Proto Recv-Q Send-Q Local Address         Foreign Address      State
tcp       0     0 127.0.0.1:25            0.0.0.0:*            LISTEN

```

```
The second column Recv-Q is a count of bytes received but not copied by the application by using this socket. This is basically the number of bytes waiting between the kernel receiving the data from the network and the application accepting it.
shows the local host address as 127.0.0.1 and the port as 25.
```

第五列是**Foreign Address**或远程地址。此列列出了远程服务器的 IP 和端口。由于我们之前使用的示例类型，这被列为 IP`0.0.0.0`和端口`*`，这是一个通配符，表示任何内容。

第六列，我们的最后一列，是**状态**套接字。对于 TCP 连接，状态将告诉我们 TCP 连接的当前状态。对于我们之前的例子，状态列为`LISTEN`；这告诉我们列出的套接字用于接受 TCP 连接。

如果我们将所有列放在一起，这一行告诉我们，我们的服务器正在通过 IP`127.0.0.1`监听端口`25`上的新连接，并且这是基于 TCP 的连接。

### 使用 netstat 来监视新连接

现在我们对`netstat`的输出有了更多的了解，我们可以使用它来查找应用程序服务器到数据库服务器的新连接。要使用`netstat`监视新连接，我们将使用`netstat`经常被忽视的一个功能。

与`vmstat`命令类似，可以将`netstat`置于连续模式中，每隔几秒打印相同的输出。要做到这一点，只需在命令的末尾放置间隔。

在下一个例子中，我们将使用相同的`netstat`标志，间隔为`5`秒；但是，我们还将将输出导向到`grep`并使用`grep`来过滤端口`3306`。

```
[blog]# netstat -na 5 | grep 3306
tcp        0      1 192.168.33.11:59492     192.168.33.12:3306 SYN_SENT 
tcp        0      1 192.168.33.11:59493     192.168.33.12:3306 SYN_SENT 
tcp        0      1 192.168.33.11:59494     192.168.33.12:3306 SYN_SENT

```

除了运行`netstat`命令，我们还可以在浏览器中导航到`blog.example.com`地址。我们可以这样做，以强制 Web 应用程序尝试连接到数据库。

一般来说，Web 应用程序对数据库有两种类型的连接，一种是持久连接，它们始终保持与数据库的连接，另一种是非持久连接，只有在需要时才建立。由于我们不知道这个 WordPress 安装使用哪种类型，因此在这种类型的故障排除中，假设它们是非持久的更安全。这意味着，为了触发数据库连接，必须有流量到 WordPress 应用程序。

从`netstat`的输出中，我们可以看到对数据库的连接尝试，而且不仅仅是任何数据库，而是`192.168.33.12`上的数据库服务。这些信息证实，当 Web 应用程序尝试建立连接时，它使用的是`hosts`文件中的 IP，而不是来自 DNS。直到这一点，我们怀疑这是基于`telnet`和`ping`，但没有证据表明应用程序的连接。

然而，有趣的事实是`netstat`输出显示 TCP 连接处于`SYN_SENT`状态。这个`SYN_SENT`状态是在首次建立网络连接时使用的状态。`netstat`命令可以打印许多不同的连接状态；每个状态告诉我们连接所处的过程中的位置。这些信息对于识别网络连接问题的根本原因至关重要。

### `netstat`状态的详细说明

在深入研究之前，我们应该快速查看一下不同的`netstat`状态及其含义。以下是`netstat`使用的所有状态的完整列表：

+   `ESTABLISHED`：连接已建立，可用于数据传输

+   `SYN_SENT`：TCP 套接字正在尝试与远程主机建立连接

+   `SYN_RECV`：已从远程主机接收到 TCP 连接请求

+   `FIN_WAIT1`：TCP 连接正在关闭

+   `FIN_WAIT2`：TCP 连接正在等待远程主机关闭连接

+   `TIME_WAIT`：套接字在关闭后等待任何未完成的网络数据包

+   `CLOSE`：套接字不再被使用

+   `CLOSE_WAIT`：远程端已关闭其连接，本地套接字正在关闭

+   `LAST_ACK`：远程端已启动关闭连接，本地系统正在等待最终确认

+   `LISTEN`：套接字正在用于监听传入连接

+   `CLOSING`：本地和远程套接字都已关闭，但并非所有数据都已发送

+   `UNKNOWN`：用于处于未知状态的套接字

从上面的列表中，我们可以确定应用程序到数据库的连接从未变为`ESTABLISHED`。这意味着应用程序服务器在`SYN_SENT`状态下开始连接，但从未转换到下一个状态。

## 使用 tcpdump 捕获网络流量

为了更好地理解网络流量，我们将使用第二个命令来查看网络流量的详细信息——`tcpdump`。在这里，`netstat`命令用于打印套接字的状态；`tcpdump`命令用于创建网络流量的“转储”或“跟踪”。这些转储允许用户查看捕获的网络流量的所有方面。

通过`tcpdump`，可以查看完整的 TCP 数据包细节，从数据包头部到实际传输的数据。`tcpdump`不仅可以捕获这些数据，还可以将捕获的数据写入文件。数据写入文件后，可以保存或移动，并且稍后可以使用`tcpdump`命令或其他网络数据包分析工具（例如`wireshark`）进行读取。

以下是运行`tcpdump`捕获网络流量的简单示例。

```
[blog]# tcpdump -nvvv
tcpdump: listening on enp0s3, link-type EN10MB (Ethernet), capture size 65535 bytes
16:18:04.125881 IP (tos 0x10, ttl 64, id 20361, offset 0, flags [DF], proto TCP (6), length 156)
 10.0.2.16.ssh > 10.0.2.2.52618: Flags [P.], cksum 0x189f (incorrect -> 0x62a4), seq 3643405490:3643405606, ack 245510335, win 26280, length 116
16:18:04.126203 IP (tos 0x0, ttl 64, id 9942, offset 0, flags [none], proto TCP (6), length 40)
 10.0.2.2.52618 > 10.0.2.16.ssh: Flags [.], cksum 0xbc71 (correct), seq 1, ack 116, win 65535, length 0
16:18:05.128497 IP (tos 0x10, ttl 64, id 20362, offset 0, flags [DF], proto TCP (6), length 332)
 10.0.2.16.ssh > 10.0.2.2.52618: Flags [P.], cksum 0x194f (incorrect -> 0xecc9), seq 116:408, ack 1, win 26280, length 292
16:18:05.128784 IP (tos 0x0, ttl 64, id 9943, offset 0, flags [none], proto TCP (6), length 40)
 10.0.2.2.52618 > 10.0.2.16.ssh: Flags [.], cksum 0xbb4d (correct), seq 1, ack 408, win 65535, length 0
16:18:06.129934 IP (tos 0x10, ttl 64, id 20363, offset 0, flags [DF], proto TCP (6), length 156)
 10.0.2.16.ssh > 10.0.2.2.52618: Flags [P.], cksum 0x189f (incorrect -> 0x41d5), seq 408:524, ack 1, win 26280, length 116
16:18:06.130441 IP (tos 0x0, ttl 64, id 9944, offset 0, flags [none], proto TCP (6), length 40)
 10.0.2.2.52618 > 10.0.2.16.ssh: Flags [.], cksum 0xbad9 (correct), seq 1, ack 524, win 65535, length 0
16:18:07.131131 IP (tos 0x10, ttl 64, id 20364, offset 0, flags [DF], proto TCP (6), length 140)

```

在前面的示例中，我为`tcpdump`命令提供了几个标志。第一个标志`–n`（无 dns）告诉`tcpdump`不要查找它找到的任何 IP 的主机名。其余的标志`–vvv`（详细）告诉`tcpdump`非常“非常”详细。`tcpdump`命令有三个详细级别；每个添加到命令行的`–v`都会增加使用的详细级别。在前面的示例中，`tcpdump`处于最详细的模式。

前面的示例是运行`tcpdump`的最简单方式之一；然而，它并没有捕获我们需要的流量。

### 查看服务器的网络接口

当在具有多个网络接口的系统上执行`tcpdump`时，除非定义了接口，否则该命令将选择最低编号的接口进行连接。在前面的示例中，选择的接口是`enp0s3`；然而，这可能不是用于数据库连接的接口。

在使用`tcpdump`来调查我们的网络连接问题之前，我们首先需要确定用于此连接的网络接口；为了做到这一点，我们将使用`ip`命令。

```
[blog]# ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT qlen 1000
 link/ether 08:00:27:7f:fd:54 brd ff:ff:ff:ff:ff:ff

```

在高层次上，`ip`命令允许用户打印、修改和添加网络配置。在上面的示例中，我们告诉`ip`命令通过使用`show links`参数来“显示”所有可用的“链接”。显示的链接实际上是为该服务器定义的网络接口。

#### 什么是网络接口？

在谈论物理服务器时，网络接口通常是物理以太网端口的表示。如果我们假设前面示例中使用的机器是一台物理机器，我们可以假设`enp0s3`和`enp0s8`链接是物理设备。然而，实际上，上述机器是一台虚拟机。这意味着这些设备逻辑上连接到这台虚拟机；但是，这台机器的内核并不知道，甚至不需要知道这种区别。

例如，在这本书中，大多数接口（除了“`lo`”或回环接口）都直接与物理（或虚拟物理）网络设备相关。然而，也有可能创建虚拟接口，这允许您创建多个接口，这些接口链接回单个物理接口。一般来说，这些接口以“`:`”或“`.`”作为原始设备名称的分隔符。如果我们要为`enp0s8`创建一个虚拟接口，它看起来会像`enp0s8:1`。

#### 查看设备配置

从`ip`命令的输出中，我们可以看到有三个定义的网络接口。在了解哪个接口用于我们的数据库连接之前，我们首先需要更好地了解这些接口。

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT

```

`lo`或回环接口是列表中的第一个。在 Linux 或 Unix 上工作了足够长时间的人都会对回环接口非常熟悉。回环接口旨在为系统的用户提供一个本地网络地址，只能用于连接回本地系统。

这个特殊的接口允许位于同一台服务器上的应用程序通过 TCP/IP 进行交互，而无需将其连接外部网络。它还允许这些应用程序在没有网络数据包离开本地服务器的情况下进行交互，从而使其成为非常快速的网络连接。

传统上，回环接口 IP 的已知地址是`127.0.0.1`。然而，就像本书中的其他内容一样，我们将在假设其为真之前先验证这些信息。我们可以使用`ip`命令来显示回环接口的定义地址来做到这一点。

```
[blog]# ip addr show lo
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever

```

在显示可用接口的前面示例中，使用了“`link show`”选项；为了显示 IP 地址，可以使用“`addr show`”选项。`ip`命令打印项目的语法在整个过程中都遵循这个相同的方案。

前面的例子还指定了我们感兴趣的设备的名称；这限制了输出到指定的设备。如果我们在前面的命令中省略设备名称，它将简单地打印出所有设备的 IP 地址。

那么，上面的内容告诉我们关于 lo 接口的什么呢？其中一件事是，`lo`接口正在监听 IPv4 地址`127.0.0.1`；我们可以在下一行看到这一点。

```
 inet 127.0.0.1/8 scope host lo

```

这意味着，如果我们想通过环回接口连接到这个主机，我们可以通过定位`127.0.0.1`来实现。然而，`ip`命令还显示了在这个接口上定义的第二个 IP。

```
 inet6 ::1/128 scope host

```

这告诉我们`::1`的 IPv6 地址也绑定到了 lo 接口。这个地址用于相同的目的作为`127.0.0.1`，但它是为`IPv6`通信设计的。

通过`ip`命令提供的上述信息，我们可以看到`lo`或环回接口被按预期定义。

在这台服务器上定义的第二个接口是`enp0s3`；这个设备，不像 lo，要么是一个物理设备，要么是一个虚拟化的物理接口。之前执行的`ip` link show 命令已经告诉我们关于这个接口的很多信息。

```
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff

```

```
The device is in an **up** state: `state UP`The MTU size is **1500**: `mtu 1500`The MAC address is **08:00:27:20:5d:4b**: `link/ether 08:00:27:20:5d:4b`
```

从这些信息中，我们知道接口已经启动并且可以被利用。我们还知道 MTU 大小设置为默认的 1500，并且可以轻松地识别 MAC 地址。虽然 MTU 大小和 MAC 地址可能与这个问题无关，但在其他情况下它们可能非常有用。

然而，对于我们当前的任务，即确定用于数据库连接的接口，我们需要确定绑定到这个接口的 IP 是哪些。

```
[blog]# ip addr show enp0s3
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff
 inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
 valid_lft 49655sec preferred_lft 49655sec
 inet6 fe80::a00:27ff:fe20:5d4b/64 scope link
 valid_lft forever preferred_lft forever

```

从前面的输出中，我们可以看到`enp0s3`接口正在监听 IPv4 IP `10.0.2.15`（`inet 10.0.2.15/24`）以及 IPv6 IP `f380::a00:27ff:fe20:5d4b`（`inet6 fe80::a00:27ff:fe20:5d4b/64`）。这是否告诉我们连接到`192.168.33.12`是通过这个接口？不，但也不意味着不是。

这告诉我们`enp0s3`接口被用于连接到`10.0.2.15/24`网络。这个网络可能能够路由到`192.168.33.12`的地址；在做出这个决定之前，我们应该首先审查下一个接口的配置。

这个系统上的第三个接口是`enp0s8`；它也是一个物理或虚拟网络设备，从`ip` link show 命令提供的信息中，我们可以看到它与`enp0s3`有类似的配置。

```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT qlen 1000
 link/ether 08:00:27:7f:fd:54 brd ff:ff:ff:ff:ff:ff

```

从这个输出中，我们可以看到`enp0s8`接口也处于`UP`状态，并且具有默认的 MTU 大小为 1500。我们还可以确定这个接口的 MAC 地址，这在这个时候并不是特别需要；然而，以后可能会变得有用。

然而，如果我们看一下在这台服务器上定义的 IP，与`enp0s3`设备相比，有一个显著的不同。

```
[blog]# ip addr show enp0s8
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:7f:fd:54 brd ff:ff:ff:ff:ff:ff
 inet 192.168.33.11/24 brd 192.168.33.255 scope global enp0s8
 valid_lft forever preferred_lft forever
 inet6 fe80::a00:27ff:fe7f:fd54/64 scope link
 valid_lft forever preferred_lft forever

```

我们可以看到`enp0s8`接口正在监听 IPv4 地址`192.168.33.11`（`inet 192.168.33.11/24`）和 IPv6 地址`fe80::a00:27ff:fe7f:fd54`（`inet6 fe80::a00:27ff:fe7f:fd54/64`）。

这是否意味着`enp0s8`接口被用于连接到`192.168.33.12`？实际上，可能是的。

`enp0s8`定义的子网是`192.168.33.11/24`，这意味着这个接口连接到一个跨越`192.168.33.0`到`192.168.33.255`的 IP 范围的设备网络。由于数据库服务器的`IP 192.168.33.12`在这个范围内，很可能是通过`enp0s8`接口进行与这个地址的通信。

在这一点上，我们可以“怀疑”`enp0s8`接口被用于与数据库服务器进行通信。虽然这个接口可能被配置为与包含`192.168.33.12`的子网进行通信，但完全有可能通过使用定义的路由强制通过另一个接口进行通信。

为了检查是否定义了路由并强制通过另一个接口进行通信，我们将再次使用`ip`命令。然而，对于这个任务，我们将使用`ip`命令的“`route get`”选项。

```
[blog]# ip route get 192.168.33.12
192.168.33.12 dev enp0s8  src 192.168.33.11
 cache

```

当使用“`route get`”参数执行时，`ip`命令将特别输出用于路由到指定 IP 的接口。

从前面的输出中，我们可以看到`blog.example.com`服务器实际上是使用`enp0s8`接口路由到 192.168.33.12 地址，即`db.example.com`的 IP。

到目前为止，我们不仅使用`ip`命令确定了这台服务器上存在哪些网络接口，还使用它确定了网络数据包到达目标主机所需的接口。

`ip`命令是一个非常有用的工具，最近被计划用来替代诸如`ifconfig`和`route`之类的旧命令。如果你通常熟悉使用`ifconfig`等命令，但对`ip`命令不太熟悉，那么建议你回顾一下上面介绍的用法，因为最终`ifconfig`命令将被弃用。

### 指定 tcpdump 的接口

现在我们已经确定了与`db.example.com`通信所使用的接口，我们可以通过使用`tcpdump`开始我们的网络跟踪。如前所述，我们将使用`-nvvv`标志将`tcpdump`置于非常“非常”详细的模式，而不进行主机名解析。然而，这一次，我们将指定`tcpdump`从`enp0s8`接口捕获网络流量；我们可以使用`-i`（接口）标志来实现这一点。我们还将使用`-w`（写入）标志将捕获的数据写入文件。

```
[blog]# tcpdump -nvvv -i enp0s8 -w /var/tmp/chapter5.pcap
tcpdump: listening on enp0s8, link-type EN10MB (Ethernet), capture size 65535 bytes
48 packets captured

```

当我们首次执行`tcpdump`命令时，屏幕上输出了相当多的内容。当要求将其输出保存到文件时，`tcpdump`不会将捕获的数据输出到屏幕上，而是会持续显示捕获的数据包的计数器。

一旦我们让`tcpdump`将捕获的数据保存到文件中，我们需要复制问题以尝试生成数据库流量。我们将通过与`netstat`命令相同的方法来实现这一点：简单地在 Web 浏览器中导航到`blog.example.com`。

当我们导航到 WordPress 网站时，我们应该看到`捕获的数据包`计数器在增加；这表明`tcpdump`已经看到了流量并进行了捕获。一旦计数器达到一个合理的数字，我们就可以停止`tcpdump`的捕获。要做到这一点，只需在命令行上按下*Ctrl* + *C*；一旦停止，我们应该看到类似以下的消息：

```
^C48 packets captured
48 packets received by filter
0 packets dropped by kernel

```

### 读取捕获的数据

现在我们已经将捕获的`网络跟踪`保存到文件中，我们可以使用这个文件来调查数据库流量。将这些数据保存在文件中的好处是我们可以多次读取这些数据，并通过过滤器来减少输出。此外，当对实时网络流进行`tcpdump`时，我们可能只能捕获一次流量，再也捕获不到了。

为了读取保存的数据，我们可以使用`-r`（读取）标志后跟要读取的文件名来运行`tcpdump`。

我们可以通过使用以下命令打印我们捕获的所有`48`个数据包的数据包头信息来开始。

```
[blog]# tcpdump -nvvv -r /var/tmp/chapter5.pcap

```

然而，这个命令的输出可能会让人感到不知所措；为了找到问题的核心，我们需要缩小`tcpdump`的输出范围。为此，我们将使用 tcpdump 的过滤器功能来对捕获的数据进行过滤。特别是，我们将使用`host`过滤器将输出过滤到特定的 IP 地址。

```
[blog]# tcpdump -nvvv -r /var/tmp/chapter5.pcap host 192.168.33.12
reading from file /var/tmp/chapter5.pcap, link-type EN10MB (Ethernet)
03:33:05.569739 IP (tos 0x0, ttl 64, id 26591, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x3543), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53696341 ecr 0,nop,wscale 6], length 0
03:33:06.573145 IP (tos 0x0, ttl 64, id 26592, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x3157), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53697345 ecr 0,nop,wscale 6], length 0
03:33:08.580122 IP (tos 0x0, ttl 64, id 26593, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x2980), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53699352 ecr 0,nop,wscale 6], length 0

```

通过在`tcpdump`命令的末尾添加`host 192.168.33.12`，输出被过滤为只与主机 192.168.33.12 相关的流量。这是通过`host`过滤器实现的。`tcpdump`命令有许多可用的过滤器；然而，在本章中，我们主要将利用主机过滤器。我强烈建议经常解决网络问题的人熟悉`tcpdump`过滤器。

在运行`tcpdump`（与上面类似）时，重要的是要知道每一行都是通过指定接口发送或接收的一个数据包。下面的例子是一个完整的`tcpdump`行，本质上是通过`enp0s8`接口传递的一个数据包。

```
03:33:05.569739 IP (tos 0x0, ttl 64, id 26591, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x3543), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53696341 ecr 0,nop,wscale 6], length 0

```

如果我们看一下前面的行，我们可以看到这个数据包是从`192.168.33.11`发送到`192.168.33.12`的。我们可以从以下部分看到这一点：

```
192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S]

```

```
192.168.33.11 to 192.168.33.12. We can identify this by the first and the second IPs in this snippet. Since 192.168.33.11 is the first IP, it is the source of the packet, and the second IP (192.168.33.12) is then the destination.
```

```
192.168.33.11.37785 > 192.168.33.12.mysql

```

```
192.168.33.11 was from the local port 37785 to a remote port of 3306. We can infer this as the fifth dot in the source address is 37785 and "mysql" is in the target address. The reason that tcpdump has printed "mysql" is that by default it will map common service ports to their common name. In this case, it mapped port 3306 to mysql and simply printed mysql. This can be turned off on the command line by using two –n flags (i.e. -nn) to the tcpdump command.
tcpdump output will have a section for flags. When the flags set on a packet are only S, this means that the packet is the initial SYN packet.
```

这个数据包是一个`SYN`数据包实际上告诉了我们关于这个数据包的很多信息。

### 关于 TCP 的快速入门

**传输控制协议**（**TCP**）是互联网通信中最常用的协议之一。它是我们每天依赖的许多服务的选择协议。从用于加载网页的 HTTP 协议到所有 Linux 系统管理员最喜欢的`SSH`，这些协议都是在 TCP 协议之上实现的。

虽然 TCP 被广泛使用，但它也是一个相当高级的话题，每个系统管理员都应该至少有基本的了解。在本节中，我们将快速介绍一些 TCP 基础知识；这绝不是一个详尽的指南，但足以理解我们问题的根源。

要理解我们的问题，我们必须首先了解 TCP 连接是如何建立的。在 TCP 通信中，通常有两个重要的参与方，即客户端和服务器。客户端是连接的发起者，并将发送一个`SYN`数据包作为建立 TCP 连接的第一步。

当服务器接收到一个`SYN`数据包并愿意接受连接时，它会向客户端发送一个**同步确认**（**SYN-ACK**）数据包。这是为了让服务器确认它已经收到了原始的`SYN`数据包。

当客户端接收到这个`SYN-ACK`数据包时，它会回复服务器一个`ACK`，有时也称为`SYN-ACK-ACK`。这个数据包的想法是让客户端确认它已经收到了服务器的确认。

这个过程被称为*三次握手*，是 TCP 的基础。这种方法的好处是，每个系统都确认它接收到的数据包，因此不会有关于客户端和服务器是否能够来回通信的问题。一旦进行了三次握手，连接就会转移到已建立的状态。在这种状态下可以使用其他类型的数据包，比如**推送**（**PSH**）数据包，用于在客户端和服务器之间传输信息。

#### TCP 数据包的类型

说到其他类型的数据包，重要的是要知道确定一个数据包是`SYN`数据包还是`ACK`数据包的组件只是在数据包头中设置一个标志。

在我们捕获的数据的第一个数据包上，只有`SYN`标志被设置；这就是为什么我们会看到输出如`Flags [S]`的原因。这是第一个数据包被发送并且该数据包只有`SYN`标志被设置的一个例子。

一个`SYN-ACK`数据包是一个`SYN`和`ACK`标志被设置的数据包。这通常在`tcpdump`中看到的是`[S.]`。

以下是在使用`tcpdump`进行故障排除活动中常见的数据包标志的表格。这绝不是一个完整的列表，但它确实给出了常见数据包类型的一个大致概念。

+   `SYN- [S]`：这是一个同步数据包，从客户端发送到服务器的第一个数据包。

+   `SYN-ACK- [S.]`：这是一个同步确认数据包；这些数据包标志用于指示服务器接收到客户端的`SYN`请求。

+   `ACK- [.]`：确认数据包被服务器和客户端用来确认接收到的数据包。在初始的`SYN`数据包发送后，所有后续的数据包都应该设置确认标志。

+   `PSH- [P]`: 这是一个推送数据包。它旨在将缓冲的网络数据推送到接收方。这是实际传输数据的数据包类型。

+   `PSH-ACK- [P.]`: 推送确认数据包用于确认先前的数据包并向接收方发送数据。

+   `FIN- [F]`: `FIN`或完成数据包用于告诉服务器没有更多数据，可以关闭已建立的连接。

+   `FIN-ACK- [F.]`: 完成确认数据包用于确认先前的完成数据包已被接收。

+   `RST- [R]`: 重置数据包用于源系统希望重置连接时使用。一般来说，这是由于错误或目标端口实际上不处于监听状态。

+   `RST-ACK -[R.]`: 重置确认数据包用于确认先前的重置数据包已被接收。

现在我们已经探讨了不同类型的数据包，让我们把它们联系起来，快速回顾一下之前捕获的数据。

```
[blog]# tcpdump -nvvv -r /var/tmp/chapter5.pcap host 192.168.33.12
reading from file /var/tmp/chapter5.pcap, link-type EN10MB (Ethernet)
03:33:05.569739 IP (tos 0x0, ttl 64, id 26591, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x3543), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53696341 ecr 0,nop,wscale 6], length 0
03:33:06.573145 IP (tos 0x0, ttl 64, id 26592, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x3157), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53697345 ecr 0,nop,wscale 6], length 0
03:33:08.580122 IP (tos 0x0, ttl 64, id 26593, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S], cksum 0xc396 (incorrect -> 0x2980), seq 3937874058, win 14600, options [mss 1460,sackOK,TS val 53699352 ecr 0,nop,wscale 6], length 0
If we look at just the IP addresses and the flags from the captured data, from each line, it becomes very clear what the issue is.
192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S],
192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S],
192.168.33.11.37785 > 192.168.33.12.mysql: Flags [S],

```

如果我们分解这三个数据包，我们可以看到它们都来自源端口`37785`，目标端口为 3306。我们还可以看到这些数据包是`SYN`数据包。这意味着我们的系统发送了 3 个`SYN`数据包，但从目标端口，即`192.168.33.12`，没有收到`SYN-ACK`。

这告诉我们关于与主机`192.168.33.12`的网络连接的什么？它告诉我们要么远程服务器`192.168.33.12`从未收到我们的数据包，要么它收到了并且我们从未能收到`SYN-ACK`回复。如果问题是由于数据库服务器不接受我们的数据包，我们将期望看到一个`RST`或`重置`数据包。

## 审查收集的数据

此时，现在是时候盘点我们收集的信息和我们目前所知的信息了。

我们已经确定的第一条关键信息是博客服务器（`blog.example.com`）无法连接到数据库服务器（`db.example.com`）。我们已经确定的第二条关键信息是 DNS 名称`db.example.com`解析为`10.0.0.50`。但是，在`blog.example.com`服务器上还有一个`/etc/hosts`文件条目覆盖了 DNS。由于 hosts 文件，当 Web 应用程序尝试连接到`db.example.com`时，它实际上连接到了`192.168.33.12`。

我们还确定了主机`192.168.33.11`（`blog.example.com`）在访问 WordPress 应用程序时向`192.168.33.12`发送初始的`SYN`数据包。然而，服务器`192.168.33.12`要么没有接收到这些数据包，要么没有回复这些数据包。

在我们的调查过程中，我们审查了博客服务器的网络配置，并确定它似乎已正确设置。我们可以通过简单使用 ping 命令向每个网络接口的子网内的 IP 发送 ICMP 回显来对此进行额外验证。

```
[blog]# ip addr show enp0s3
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff
 inet 10.0.2.16/24 brd 10.0.2.255 scope global dynamic enp0s3
 valid_lft 62208sec preferred_lft 62208sec
 inet6 fe80::a00:27ff:fe20:5d4b/64 scope link
 valid_lft forever preferred_lft forever

```

对于`enp0s3`接口，我们可以看到绑定的 IP 地址是`10.0.2.16`，子网掩码为`/24`或`255.255.255.0`。通过这种设置，我们应该能够与该子网内的其他 IP 进行通信。以下是使用 ping 命令测试与`10.0.2.2`的连通性的输出。

```
[blog]# ping 10.0.2.2
PING 10.0.2.2 (10.0.2.2) 56(84) bytes of data.
64 bytes from 10.0.2.2: icmp_seq=1 ttl=63 time=0.250 ms
64 bytes from 10.0.2.2: icmp_seq=2 ttl=63 time=0.196 ms
64 bytes from 10.0.2.2: icmp_seq=3 ttl=63 time=0.197 ms
^C
--- 10.0.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 0.196/0.214/0.250/0.027 ms

```

这表明`enp0s3`接口至少可以连接到其子网内的其他 IP。对于`enp0s8`，我们可以使用另一个 IP 执行相同的测试。

```
[blog]# ip addr show enp0s8
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:7f:fd:54 brd ff:ff:ff:ff:ff:ff
 inet 192.168.33.11/24 brd 192.168.33.255 scope global enp0s8
 valid_lft forever preferred_lft forever
 inet6 fe80::a00:27ff:fe7f:fd54/64 scope link
 valid_lft forever preferred_lft forever

```

从上述命令中，我们可以看到`enp0s8`的 IP 为`192.168.33.11`，子网掩码为`/24`或`255.255.255.0`。如果我们可以使用 ping 命令与`192.168.33.11/24`子网内的任何其他 IP 进行通信，那么我们可以验证该接口也已正确配置。

```
# ping 192.168.33.1
PING 192.168.33.1 (192.168.33.1) 56(84) bytes of data.
64 bytes from 192.168.33.1: icmp_seq=1 ttl=64 time=0.287 ms
64 bytes from 192.168.33.1: icmp_seq=2 ttl=64 time=0.249 ms
64 bytes from 192.168.33.1: icmp_seq=3 ttl=64 time=0.260 ms
64 bytes from 192.168.33.1: icmp_seq=4 ttl=64 time=0.192 ms
^C
--- 192.168.33.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3028ms
rtt min/avg/max/mdev = 0.192/0.247/0.287/0.034 ms

```

从结果中，我们可以看到对 IP`192.168.33.1`的连接正常工作。因此，这意味着，至少在基本方面，`enp0s8`接口已正确配置。

有了所有这些信息，我们可以假设`blog.example.com`服务器已正确配置，并且可以连接到其配置的网络。从这一点开始，如果我们想要更多关于我们问题的信息，我们需要从`db.example.com`（`192.168.33.12`）服务器获取。

## 看看对方的情况

虽然可能并非总是可能的，但在处理网络问题时，最好从对话的两端进行故障排除。在我们之前的例子中，我们有两个构成我们网络对话的系统，即客户端和服务器。到目前为止，我们已经从客户端的角度看了一切；在本节中，我们将从服务器的角度来看这次对话的另一面。

### 识别网络配置

在前一节中，我们在查看博客服务器的网络配置之前经历了几个步骤。在数据库服务器的情况下，我们已经知道问题与网络有关，特别是 IP 为`192.168.33.12`。既然我们已经知道问题与哪个 IP 相关，我们应该做的第一件事是确定这个 IP 绑定到哪个接口。

我们将再次使用`ip`命令和`addr show`选项来执行此操作。

```
[db]# ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff
 inet 10.0.2.16/24 brd 10.0.2.255 scope global dynamic enp0s3
 valid_lft 86304sec preferred_lft 86304sec
 inet6 fe80::a00:27ff:fe20:5d4b/64 scope link
 valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:c9:d3:65 brd ff:ff:ff:ff:ff:ff
 inet 192.168.33.12/24 brd 192.168.33.255 scope global enp0s8
 valid_lft forever preferred_lft forever
 inet6 fe80::a00:27ff:fec9:d365/64 scope link
 valid_lft forever preferred_lft forever

```

在之前的例子中，我们使用`addr show`选项来显示与单个接口关联的 IP。然而，这次通过省略接口名称，`ip`命令显示了所有 IP 以及这些 IP 绑定到的接口。这是一种快速简单的方法，可以显示与这台服务器关联的 IP 地址和接口。

从前面的命令中，我们可以看到数据库服务器与应用服务器的配置类似，都有三个接口。在深入之前，让我们更好地了解服务器的接口，并看看我们可以从中识别出什么信息。

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever

```

这台服务器上的第一个接口是环回接口`lo`。如前所述，这个接口对于每台服务器来说都是通用的，只用于本地网络流量。这个接口不太可能与我们的问题有关。

```
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff
 inet 10.0.2.16/24 brd 10.0.2.255 scope global dynamic enp0s3
 valid_lft 86304sec preferred_lft 86304sec
 inet6 fe80::a00:27ff:fe20:5d4b/64 scope link
 valid_lft forever preferred_lft forever

```

对于第二个接口`enp0s3`，数据库服务器的配置与博客服务器非常相似。在 Web 应用服务器上，我们也有一个名为`enp0s3`的接口，这个接口也在`10.0.2.0/24`网络上。

由于博客和数据库服务器之间的连接似乎是针对 IP`192.168.33.12`，因此`enp0s3`不是一个需要关注的接口，因为`enp0s3`接口的 IP 是`10.0.2.16`。

```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:c9:d3:65 brd ff:ff:ff:ff:ff:ff
 inet 192.168.33.12/24 brd 192.168.33.255 scope global enp0s8
 valid_lft forever preferred_lft forever
 inet6 fe80::a00:27ff:fec9:d365/64 scope link
 valid_lft forever preferred_lft forever

```

另一方面，第三个网络设备`enp0s8`确实绑定了 IP`192.168.33.12`。`enp0s8`设备的设置也与博客服务器上的`enp0s8`设备类似，因为这两个设备似乎都在`192.168.33.0/24`网络上。

通过之前的故障排除，我们知道我们的 Web 应用程序所针对的 IP 是 IP 192.168.33.12。通过`ip`命令，我们已经确认 192.168.33.12 通过`enp0s8`接口绑定到了这台服务器上。

### 从 db.example.com 测试连接

现在我们知道数据库服务器有预期的网络配置，我们需要确定这台服务器是否正确连接到`192.168.33.0/24`网络。最简单的方法是执行一个我们之前在博客服务器上执行过的任务；使用`ping`连接到该子网上的另一个 IP。

```
[db]# ping 192.168.33.1
PING 192.168.33.1 (192.168.33.1) 56(84) bytes of data.
64 bytes from 192.168.33.1: icmp_seq=1 ttl=64 time=0.438 ms
64 bytes from 192.168.33.1: icmp_seq=2 ttl=64 time=0.208 ms
64 bytes from 192.168.33.1: icmp_seq=3 ttl=64 time=0.209 ms
^C
--- 192.168.33.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 0.208/0.285/0.438/0.108 ms

```

通过上面的输出，我们可以看到数据库服务器能够联系到`192.168.33.0/24`子网上的另一个 IP。在故障排除时，我们曾试图从博客服务器连接到数据库服务器，但测试失败了。一个有趣的测试是验证当数据库服务器发起连接到博客服务器时，连接是否也失败。

```
[db]# ping 192.168.33.11
PING 192.168.33.11 (192.168.33.11) 56(84) bytes of data.
From 10.0.2.16 icmp_seq=1 Destination Host Unreachable
From 10.0.2.16 icmp_seq=2 Destination Host Unreachable
From 10.0.2.16 icmp_seq=3 Destination Host Unreachable
From 10.0.2.16 icmp_seq=4 Destination Host Unreachable
^C
--- 192.168.33.11 ping statistics ---
6 packets transmitted, 0 received, +4 errors, 100% packet loss, time 5005ms

```

从数据库服务器运行`ping`命令到博客服务器的 IP（192.168.33.11），我们可以看到 ping 已经回复**目标主机不可达**。这与我们从博客服务器尝试连接时看到的错误相同。

如前所述，除了网络连接问题之外，ping 失败的原因还有很多；为了确保存在连接问题，我们还应该使用`telnet`测试连接。我们知道博客服务器正在接受到 Web 服务器的连接，因此简单地 telnet 到 Web 服务器的端口应该明确告诉我们从数据库服务器到 Web 服务器是否存在任何连接。

运行`telnet`时，我们需要指定要连接的端口。我们知道 Web 服务器正在运行，当我们导航到`http://blog.example.com`时，我们会得到一个网页。基于这些信息，我们可以确定使用默认的 HTTP 端口并且正在监听。有了这些信息，我们还知道我们可以简单地使用 telnet 连接到端口`80`，这是`HTTP`通信的默认端口。

```
[db]# telnet 192.168.33.11 80
-bash: telnet: command not found

```

但是，在这台服务器上，未安装`telnet`。这没关系，因为我们可以像在之前的示例中那样使用`curl`命令。

```
[db]# curl telnet://192.168.33.11:80 -v
* About to connect() to 192.168.33.11 port 80 (#0)
*   Trying 192.168.33.11...
* No route to host
* Failed connect to 192.168.33.11:80; No route to host
* Closing connection 0
curl: (7) Failed connect to 192.168.33.11:80; No route to host

```

从`curl`命令的输出中，我们可以看到无论是博客服务器还是数据库服务器发起连接，通信问题都存在。

### 使用 netstat 查找连接

在之前的部分中，当从博客服务器进行故障排除时，我们使用`netstat`查看了到数据库服务器的开放 TCP 连接。现在我们已经登录到数据库服务器，我们可以使用相同的命令从数据库服务器的角度查看连接的状态。为此，我们将使用指定的间隔运行`netstat`；这会导致`netstat`每 5 秒打印一次网络连接统计，类似于`vmstat`或`top`命令。

在`netstat`命令运行时，我们只需刷新浏览器，使 WordPress 应用程序再次尝试数据库连接。

```
[db]# netstat -na 5 | grep 192.168.33.11

```

在我喜欢称为“连续模式”的情况下运行`netstat`命令，并使用`grep`过滤博客服务器的 IP（192.168.33.11），我们无法看到任何 TCP 连接或连接尝试。

在许多情况下，这似乎表明数据库服务器从未收到来自博客服务器的 TCP 数据包。我们可以通过使用`tcpdump`命令在`enp0s8`接口上捕获所有网络流量来确认是否是这种情况。

### 使用 tcpdump 跟踪网络连接

早些时候学习`tcpdump`时，我们了解到它默认使用编号最低的接口。这意味着，为了捕获连接尝试，我们必须使用`-i`（接口）标志来跟踪正确的接口`enp0s8`。除了告诉`tcpdump`监视`enp0s8`接口外，我们还将让`tcpdump`将其输出写入文件。我们这样做是为了尽可能多地捕获数据，并稍后使用`tcpdump`命令多次分析数据。

```
[db]# tcpdump -i enp0s8 -w /var/tmp/db-capture.pcap
tcpdump: listening on enp0s8, link-type EN10MB (Ethernet), capture size 65535 bytes

```

现在`tcpdump`正在运行，我们只需要再次刷新浏览器。

```
^C110 packets captured
110 packets received by filter
0 packets dropped by kernel

```

在刷新浏览器并看到`捕获的数据包`计数器增加后，我们可以通过在键盘上按*Ctrl* + *C*来停止`tcpdump`。

一旦`tcpdump`停止，我们可以使用`-r`（读取）标志读取捕获的数据；但是，这将打印`tcpdump`捕获的所有数据包。在某些环境中，这可能是相当多的数据。因此，为了将输出修剪为仅有用的数据，我们将使用`port`过滤器告诉`tcpdump`仅输出从端口 3306 发起或针对端口 3306 的捕获流量，默认的 MySQL 端口。

我们可以通过在`tcpdump`命令的末尾添加`port 3306`来实现这一点。

```
[db]# tcpdump -nnvvv -r /var/tmp/db-capture.pcap port 3306
reading from file /var/tmp/db-capture.pcap, link-type EN10MB (Ethernet)
03:11:03.697543 IP (tos 0x10, ttl 64, id 43196, offset 0, flags [DF], proto TCP (6), length 64)
 192.168.33.1.59510 > 192.168.33.12.3306: Flags [S], cksum 0xc125 (correct), seq 2335155468, win 65535, options [mss 1460,nop,wscale 5,nop,nop,TS val 1314733695 ecr 0,sackOK,eol], length 0
03:11:03.697576 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.12.3306 > 192.168.33.1.59510: Flags [S.], cksum 0xc38c (incorrect -> 0x5d87), seq 2658328059, ack 2335155469, win 14480, options [mss 1460,sackOK,TS val 1884022 ecr 1314733695,nop,wscale 6], length 0
03:11:03.697712 IP (tos 0x10, ttl 64, id 61120, offset 0, flags [DF], proto TCP (6), length 52)
 192.168.33.1.59510 > 192.168.33.12.3306: Flags [.], cksum 0xb4cd (correct), seq 1, ack 1, win 4117, options [nop,nop,TS val 1314733695 ecr 1884022], length 0
03:11:03.712018 IP (tos 0x8, ttl 64, id 25226, offset 0, flags [DF], proto TCP (6), length 127)

```

然而，在使用上述过滤器的同时，似乎这个数据库服务器不仅仅被 WordPress 应用程序使用。从`tcpdump`输出中，我们可以看到端口`3306`上的流量不仅仅是博客服务器。

为了进一步清理此输出，我们可以向`tcpdump`命令添加主机过滤器，以仅过滤出我们感兴趣的流量：来自主机`192.168.33.11`的流量。

```
[db]# tcpdump -nnvvv -r /var/tmp/db-capture.pcap port 3306 and host 192.168.33.11
reading from file /var/tmp/db-capture.pcap, link-type EN10MB (Ethernet)
04:04:09.167121 IP (tos 0x0, ttl 64, id 60173, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S], cksum 0x4111 (correct), seq 558685560, win 14600, options [mss 1460,sackOK,TS val 9320053 ecr 0,nop,wscale 6], length 0
04:04:10.171104 IP (tos 0x0, ttl 64, id 60174, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S], cksum 0x3d26 (correct), seq 558685560, win 14600, options [mss 1460,sackOK,TS val 9321056 ecr 0,nop,wscale 6], length 0
04:04:12.175107 IP (tos 0x0, ttl 64, id 60175, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S], cksum 0x3552 (correct), seq 558685560, win 14600, options [mss 1460,sackOK,TS val 9323060 ecr 0,nop,wscale 6], length 0
04:04:16.187731 IP (tos 0x0, ttl 64, id 60176, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S], cksum 0x25a5 (correct), seq 558685560, win 14600, options [mss 1460,sackOK,TS val 9327073 ecr 0,nop,wscale 6], length 0

```

在这里，我们使用`and`运算符告诉`tcpdump`只打印到/从端口`3306`和到/从主机`192.168.33.11`的流量。

`tcpdump`命令有许多可能的过滤器和运算符；然而，在所有这些中，我建议熟悉基于端口和主机的过滤，因为这些将足够满足大多数情况。

如果我们分解前面捕获的网络跟踪，我们可以看到一些有趣的信息；为了更容易发现，让我们将输出修剪到只显示正在使用的 IP 和标志。

```
04:04:09.167121 IP
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S],
04:04:10.171104 IP
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S],
04:04:12.175107 IP
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S],
04:04:16.187731 IP
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S],

```

从这些信息中，我们可以看到从`blog.example.com`（`192.168.33.11`）发送的`SYN`数据包，并到达`db.example.com`（`192.168.33.12`）。然而，我们看不到返回的`SYN-ACKS`。

这告诉我们，我们至少已经找到了网络问题的源头；服务器`db.example.com`没有正确地回复从博客服务器收到的数据包。

现在的问题是：什么会导致这种问题？导致此类问题的原因有很多；但是，一般来说，这样的问题是由网络配置设置中的错误配置引起的。根据我们收集的信息，我们可以假设数据库服务器只是配置错误。

然而，有几种方法可以通过错误配置导致这种类型的问题。为了确定可能的错误配置，我们可以使用`tcpdump`命令在此服务器上捕获所有网络流量。

在以前的`tcpdump`示例中，我们总是指定单个要监视的接口。在大多数情况下，这对于问题是适当的，因为它减少了`tcpdump`捕获的数据量。在非常活跃的服务器上，`tcpdump`数据的几分钟可能非常庞大，因此最好将数据减少到只有必需的部分。

然而，在某些情况下，例如这种问题，告诉`tcpdump`捕获所有接口的网络流量是有用的。为此，我们只需指定`any`作为要监视的接口。

```
[db]# tcpdump -i any -w /var/tmp/alltraffic.pcap
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 65535 bytes

```

现在我们有`tcpdump`捕获并保存所有接口上的所有流量，我们需要再次刷新浏览器，以强制 WordPress 应用程序尝试数据库连接。

```
^C440 packets captured
443 packets received by filter
0 packets dropped by kernel

```

经过几次尝试，我们可以再次按*Ctrl* + *C*停止`tcpdump`。将捕获的网络数据保存到文件后，我们可以开始调查这些连接尝试的情况。

由于`tcpdump`捕获了大量数据包，我们将再次使用“主机”过滤器将结果限制为与`192.168.33.11`之间的网络流量。

```
[db]# tcpdump -nnvvv -r /var/tmp/alltraffic.pcap host 192.168.33.11
reading from file /var/tmp/alltraffic.pcap, link-type LINUX_SLL (Linux cooked)
15:37:51.616621 IP (tos 0x0, ttl 64, id 8389, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [S], cksum 0x34dd (correct), seq 4225047048, win 14600, options [mss 1460,sackOK,TS val 3357389 ecr 0,nop,wscale 6], length 0
15:37:51.616665 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.12.3306 > 192.168.33.11.47339: Flags [S.], cksum 0xc396 (incorrect -> 0x3609), seq 1637731271, ack 4225047049, win 14480, options [mss 1460,sackOK,TS val 3330467 ecr 3357389,nop,wscale 6], length 0
15:37:51.616891 IP (tos 0x0, ttl 255, id 2947, offset 0, flags [none], proto TCP (6), length 40)
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [R], cksum 0x10c4 (correct), seq 4225047049, win 0, length 0
15:37:52.619386 IP (tos 0x0, ttl 64, id 8390, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [S], cksum 0x30f2 (correct), seq 4225047048, win 14600, options [mss 1460,sackOK,TS val 3358392 ecr 0,nop,wscale 6], length 0
15:37:52.619428 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.12.3306 > 192.168.33.11.47339: Flags [S.], cksum 0xc396 (incorrect -> 0x1987), seq 1653399428, ack 4225047049, win 14480, options [mss 1460,sackOK,TS val 3331470 ecr 3358392,nop,wscale 6], length 0
15:37:52.619600 IP (tos 0x0, ttl 255, id 2948, offset 0, flags [none], proto TCP (6), length 40)
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [R], cksum 0x10c4 (correct), seq 4225047049, win 0, length 0

```

通过捕获的数据，似乎我们已经找到了预期的`SYN-ACK`。为了更清晰地展示这一点，让我们将输出修剪到仅包括正在使用的 IP 和标志。

```
15:37:51.616621 IP
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [S],
15:37:51.616665 IP
 192.168.33.12.3306 > 192.168.33.11.47339: Flags [S.],
15:37:51.616891 IP
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [R],
15:37:52.619386 IP
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [S],
15:37:52.619428 IP
 192.168.33.12.3306 > 192.168.33.11.47339: Flags [S.],
15:37:52.619600 IP
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [R],

```

通过更清晰的图片，我们可以看到一系列有趣的网络数据包正在传输。

```
15:37:51.616621 IP
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [S],

```

第一个数据包是从`192.168.33.11`到`192.168.33.12`的端口`3306`的`SYN`数据包。这与我们之前使用`tcpdump`执行捕获的数据包类型相同。

```
15:37:51.616665 IP
 192.168.33.12.3306 > 192.168.33.11.47339: Flags [S.],

```

然而，我们以前没有看到第二个数据包。在第二个数据包中，我们看到它是一个`SYN-ACK`（由`Flags [S.]`标识）。`SYN-ACK`是从端口`3306`的`192.168.33.12`发送到端口`47339`的`192.168.33.11`（发送原始`SYN`数据包的端口）。

乍一看，这似乎是一个正常的`SYN`和`SYN-ACK`握手。

```
15:37:51.616891 IP
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [R],

```

然而，第三个数据包很有趣，因为它清楚地表明了一个问题。第三个数据包是一个`RESET`数据包（由`Flags [R]`标识），从博客服务器`192.168.33.11`发送。关于这个有趣的事情是，当在博客服务器上执行`tcpdump`时，我们从未捕获到`RESET`数据包。如果我们在博客服务器上再次执行`tcpdump`，我们可以再次看到这个。

```
[blog]# tcpdump -i any port 3306
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on any, link-type LINUX_SLL (Linux cooked), capture size 65535 bytes
15:24:25.646731 IP blog.example.com.47336 > db.example.com.mysql: Flags [S], seq 3286710391, win 14600, options [mss 1460,sackOK,TS val 2551514 ecr 0,nop,wscale 6], length 0
15:24:26.648706 IP blog.example.com.47336 > db.example.com.mysql: Flags [S], seq 3286710391, win 14600, options [mss 1460,sackOK,TS val 2552516 ecr 0,nop,wscale 6], length 0
15:24:28.652763 IP blog.example.com.47336 > db.example.com.mysql: Flags [S], seq 3286710391, win 14600, options [mss 1460,sackOK,TS val 2554520 ecr 0,nop,wscale 6], length 0
15:24:32.660123 IP blog.example.com.47336 > db.example.com.mysql: Flags [S], seq 3286710391, win 14600, options [mss 1460,sackOK,TS val 2558528 ecr 0,nop,wscale 6], length 0
15:24:40.676112 IP blog.example.com.47336 > db.example.com.mysql: Flags [S], seq 3286710391, win 14600, options [mss 1460,sackOK,TS val 2566544 ecr 0,nop,wscale 6], length 0
15:24:56.724102 IP blog.example.com.47336 > db.example.com.mysql: Flags [S], seq 3286710391, win 14600, options [mss 1460,sackOK,TS val 2582592 ecr 0,nop,wscale 6], length 0

```

从前面的`tcpdump`输出中，我们从未看到博客服务器上的`SYN-ACK`或`RESET`数据包。这意味着`RESET`要么是由另一个系统发送的，要么是在`tcpdump`捕获之前被博客服务器的内核拒绝了`SYN-ACK`数据包。

当`tcpdump`命令捕获网络流量时，它是在内核处理这些网络流量之后进行的。这意味着如果由于任何原因内核拒绝了数据包，它将不会通过`tcpdump`命令看到。因此，博客服务器的内核在`tcpdump`能够捕获它们之前可能会拒绝来自数据库服务器的返回数据包。

通过在数据库上执行`tcpdump`，我们还发现了另一个有趣的点，即如果我们查看在`enp0s8`上执行的`tcpdump`，我们看不到`SYN-ACK`数据包。然而，如果我们告诉`tcpdump`查看我们使用的所有接口，`tcpdump`也会显示`SYN-ACK`数据包来自`192.168.33.12`。这表明`SYN-ACK`是从另一个接口发送的。

为了确认这一点，我们可以再次运行`tcpdump`，限制捕获经过`enp0s8`接口的数据包。

```
[db]# tcpdump -nnvvv -i enp0s8 port 3306 and host 192.168.33.11
04:04:09.167121 IP (tos 0x0, ttl 64, id 60173, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S], cksum 0x4111 (correct), seq 558685560, win 14600, options [mss 1460,sackOK,TS val 9320053 ecr 0,nop,wscale 6], length 0
04:04:10.171104 IP (tos 0x0, ttl 64, id 60174, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.51149 > 192.168.33.12.3306: Flags [S], cksum 0x3d26 (correct), seq 558685560, win 14600, options [mss 1460,sackOK,TS val 9321056 ecr 0,nop,wscale 6], length 0

```

通过这次对`tcpdump`的执行，我们只能再次看到来自博客服务器的`SYN`数据包。然而，如果我们对所有接口运行相同的`tcpdump`，我们不仅应该看到`SYN`数据包，还应该看到`SYN-ACK`数据包。

```
[db]# tcpdump -nnvvv -i any port 3306 and host 192.168.33.11
15:37:51.616621 IP (tos 0x0, ttl 64, id 8389, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.47339 > 192.168.33.12.3306: Flags [S], cksum 0x34dd (correct), seq 4225047048, win 14600, options [mss 1460,sackOK,TS val 3357389 ecr 0,nop,wscale 6], length 0
15:37:51.616665 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.12.3306 > 192.168.33.11.47339: Flags [S.], cksum 0xc396 (incorrect -> 0x3609), seq 1637731271, ack 4225047049, win 14480, options [mss 1460,sackOK,TS val 3330467 ecr 3357389,nop,wscale 6], length 0

```

返回到`192.168.33.11`的`SYN-ACK`数据包源自`192.168.33.12`。早些时候，我们确定了这个 IP 绑定到网络设备`enp0s8`。然而，当我们使用`tcpdump`查看所有发送的数据包时，`SYN-ACK`并没有被捕获从`enp0s8`出去。这意味着`SYN-ACK`数据包是从另一个接口发送的。

## 路由

`SYN`数据包如何到达一个接口，而`SYN-ACK`却从另一个接口返回呢？一个可能的答案是这是由于数据库服务器路由定义的错误配置。

支持网络的每个操作系统都维护着一个称为**路由表**的东西。这个路由表是一组定义的网络路由，数据包应该经过的路由。为了给这个概念提供一些背景，让我们以`enp0s3`和`enp0s8`两个接口为例。

```
# ip addr show enp0s8
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:c9:d3:65 brd ff:ff:ff:ff:ff:ff
 inet 192.168.33.12/24 brd 192.168.33.255 scope global enp0s8
 valid_lft forever preferred_lft forever
 inet6 fe80::a00:27ff:fec9:d365/64 scope link
 valid_lft forever preferred_lft forever
# ip addr show enp0s3
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
 link/ether 08:00:27:20:5d:4b brd ff:ff:ff:ff:ff:ff
 inet 10.0.2.16/24 brd 10.0.2.255 scope global dynamic enp0s3
 valid_lft 65115sec preferred_lft 65115sec
 inet6 fe80::a00:27ff:fe20:5d4b/64 scope link
 valid_lft forever preferred_lft forever

```

如果我们查看这两个接口，我们知道`enp0s8`接口连接到`192.168.33.0/24`（`inet 192.168.33.12/24`）网络，而`enp0s3`接口连接到`10.0.2.0/24`（`inet 10.0.2.16/24`）网络。

如果我们要连接到 IP 10.0.2.19，数据包不应该从`enp0s8`接口出去，因为这些数据包的最佳路由应该是通过`enp0s3`接口路由。这是最佳路由的原因是`enp0s3`接口已经是`10.0.2.0/24`网络的一部分，其中包含 IP`10.0.2.19`。

`enp0s8`接口是不同网络（`192.168.33.0/24`）的一部分，因此是不太理想的路由。事实上，`enp0s8`接口甚至可能无法路由到`10.0.2.0/24`网络。

即使`enp0s8`可能是一个不太理想的路由，内核在没有路由表中对应条目的情况下是不知道这一点的。为了更深入地了解我们的问题，我们需要查看数据库服务器上的路由表。

### 查看路由表

在 Linux 中，有几种方法可以查看当前的路由表；在本节中，我将介绍两种方法。第一种方法将利用`netstat`命令。

要使用`netstat`命令查看路由表，只需使用`-r`（route）或`--route`标志运行它。在下面的例子中，我们还将使用`-n`标志防止`netstat`执行 DNS 查找。

```
[db]# netstat -rn
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window irtt Iface
0.0.0.0         10.0.2.2        0.0.0.0         UG        0 0 0 enp0s3
10.0.2.0        0.0.0.0         255.255.255.0   U         0 0 0 enp0s3
169.254.0.0     0.0.0.0         255.255.0.0     U         0 0 0 enp0s8
192.168.33.0    0.0.0.0         255.255.255.0   U         0 0 0 enp0s8
192.168.33.11   10.0.2.1        255.255.255.255 UGH       0 0 0 enp0s3

```

虽然`netstat`可能不是打印路由表的最佳 Linux 命令，但在这个例子中使用它有一个非常特殊的原因。正如我在本章和本书中早些时候提到的，`netstat`命令是一个几乎存在于每台现代服务器、路由器或台式机上的通用工具。通过了解如何使用`netstat`查看路由表，您可以在安装了`netstat`的任何操作系统上执行基本的网络故障排除。

一般来说，可以肯定地说`netstat`命令是可用的，并且可以为您提供系统网络状态和配置的基本细节。

与其他实用程序（如`ip`命令）相比，`netstat`的格式可能有点晦涩。然而，前面的路由表向我们展示了相当多的信息。为了更好地理解，让我们逐条分解输出的路由。

```
Destination     Gateway         Genmask         Flags   MSS Window irtt Iface
0.0.0.0         10.0.2.2        0.0.0.0         UG        0 0 0 enp0s3

```

正如你所看到的，`netstat`命令的输出有多列，确切地说有八列。第一列是`Destination`列。这用于定义路由范围内的目标地址。在前面的例子中，目的地是`0.0.0.0`，这实际上是一个通配值，意味着任何东西都应该通过这个表项进行路由。

第二列是`Gateway`。网关地址是利用这条路由的网络数据包应该发送到的下一跳。在这个例子中，下一跳或网关地址设置为`10.0.2.2`；这意味着通过这个表项进行路由的任何数据包将被发送到`10.0.2.2`，然后应该将数据包路由到下一个系统，直到它们到达目的地。

第三列是`Genmask`，本质上是一种陈述路由的“`一般性`”的方式。另一种思考这一列的方式是作为`netmask`；在前面的例子中，“`genmask`”设置为`0.0.0.0`，这是一个开放范围。这意味着任何地方的数据包都应该通过这个路由表项进行路由。

第四列是`Flag`列，用于提供有关这条路由的具体信息。例子中的`U`值表示此路由使用的接口处于上行状态。`G`值用于显示路由使用了网关地址。在前面的例子中，我们可以看到我们的路由使用了网关地址；然而，并非这个系统的所有路由都是这样。

第五、第六和第七列在 Linux 服务器上并不经常使用。`MSS`列用于显示为这条路由指定的**最大分段大小**。值为 0 意味着此值设置为默认值且未更改。

`Window`列是 TCP 窗口大小，表示单个突发接受的最大数据量。同样，当值设置为 0 时，将使用默认大小。

第七列是`irtt`，用于指定这条路由的**初始往返时间**。内核将通过设置初始往返时间重新发送从未得到响应的数据包；您可以增加或减少内核认为数据包丢失之后的时间。与前两列一样，值为 0 意味着使用这条路由的数据包将使用默认值。

第八和最后一列是`IFace`列，是利用这条路由的数据包应该使用的网络接口。在前面的例子中，这是`enp0s3`接口。

#### 默认路由

我们例子中的第一条路由实际上是我们系统的一个非常特殊的路由。

```
Destination     Gateway         Genmask         Flags   MSS Window irtt Iface
0.0.0.0         10.0.2.2        0.0.0.0         UG        0 0 0 enp0s3

```

如果我们查看这条路由的详细信息和每列的定义，我们可以确定这条路由是服务器的默认路由。默认路由是一种特殊路由，在没有其他路由取代它时“默认”使用。简而言之，如果我们有要发送到诸如`172.0.0.10`的地址的数据包，这些数据包将通过默认路由发送。

这是因为我们的数据库服务器路由表中没有其他指定 IP`172.0.0.10`的路由。因此，系统只需通过默认路由发送数据包到这个 IP，这是一个万能路由。

我们可以通过目的地址为`0.0.0.0`来确定第一条路由是服务器的默认路由，这基本上意味着任何东西。第二个指示是`Genmask`为`0.0.0.0`，这与目的地一起意味着任何 IPv4 地址。

默认路由通常使用网关地址，因此网关为`destination`和`genmask`设置通配符是明确表明上述路由是默认路由的迹象。

非默认路由通常看起来像这样：

```
10.0.2.0        0.0.0.0         255.255.255.0   U         0 0 0 enp0s3

```

上述路由的目的地是 10.0.2.0，`genmask`为 255.255.255.0；这基本上意味着 10.0.2.0/24 网络中的任何内容都会匹配这条路由。

由于这条路由的范围是`10.0.2.0/24`，很可能是由`enp0s3`接口配置添加的。我们可以根据`enp0s3`接口配置来确定这一点，因为它连接到`10.0.2.0/24`网络，这是这条路由的目标。默认情况下，Linux 会根据网络接口的配置自动添加路由。

```
10.0.2.0        0.0.0.0         255.255.255.0   U         0 0 0 enp0s3

```

这条路由是内核确保`10.0.2.0/24`网络的通信通过`enp0s3`接口进行的一种方式，因为这条路由将取代默认路由。在网络路由中，将始终使用最具体的路由。由于默认路由是通配符，而这条路由是特定于`10.0.2.0/24`网络的，因此这条路由将用于网络中的任何内容。

### 利用 IP 显示路由表

审查路由表的另一个工具是`ip`命令。从本章中使用的情况可以看出，`ip`命令是一个非常全面的实用工具，几乎可以用于现代 Linux 系统上的任何网络相关事务。

`ip`命令的一个用途是添加、删除或显示网络路由配置。要显示当前的路由表，只需执行带有`route show`选项的`ip`命令。

```
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16
169.254.0.0/16 dev enp0s8  scope link  metric 1003
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12
192.168.33.11 via 10.0.2.1 dev enp0s3  proto static  metric 1

```

虽然学习使用`netstat`命令对于非 Linux 操作系统很重要，但`ip`命令是任何 Linux 网络故障排除或配置的基本工具。

使用`ip`命令来排除故障路由时，我们甚至可能会发现它比`netstat`命令更容易。一个例子是查找默认路由。当`ip`命令显示默认路由时，它使用单词"default"作为目的地，而不是 0.0.0.0，这种方法对于新系统管理员来说更容易理解。

阅读其他路由也更容易。例如，之前在`netstat`中查看路由时，我们的示例路由如下：

```
10.0.2.0        0.0.0.0         255.255.255.0   U         0 0 0 enp0s3

```

使用`ip`命令，相同的路由以以下格式显示：

```
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16

```

在我看来，`ip` route show 的格式比`netstat -rn`命令的格式简单得多。

### 寻找路由错误配置

现在我们知道如何查看服务器上的路由表，我们可以使用`ip`命令查找可能导致数据库连接问题的任何路由。

```
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16
169.254.0.0/16 dev enp0s8  scope link  metric 1003
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12
192.168.33.11 via 10.0.2.1 dev enp0s3  proto static  metric 1

```

在这里，我们可以看到系统上定义了五条路由。让我们分解这些路由，以更好地理解它们。

```
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16

```

我们已经介绍了前两条路由，不会再次复习。

```
169.254.0.0/16 dev enp0s8  scope link  metric 1003

```

第三条路由定义了所有来自`169.254.0.0/16`（`169.254.0.0`到`169.254.255.255`）的流量通过`enp0s8`设备发送。这是一个非常广泛的路由，但很可能不会影响我们到 IP`192.168.33.11`的路由。

```
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12
192.168.33.11 via 10.0.2.1 dev enp0s3  proto static  metric 1

```

然而，第四和第五条路由将改变网络数据包到 192.168.33.11 的路由方式。

```
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12

```

第四条路由定义了所有流量到`192.168.33.0/24`（`192.168.33.0`到`192.168.33.255`）网络都从`enp0s8`接口路由，并且源自`192.168.33.12`。这条路由似乎也是由`enp0s8`接口的配置自动添加的；这与`enp0s3`添加的早期路由类似。

由于`enp0s8`设备被定义为`192.168.33.0/24`网络的一部分，将该网络的流量路由到这个接口是合理的。

```
192.168.33.11 via 10.0.2.1 dev enp0s3  proto static  metric 1

```

然而，第五条路由定义了所有流量到特定 IP`192.168.33.11`（博客服务器的 IP）都通过`enp0s3`设备发送到`10.0.2.1`的网关。这很有趣，因为第五条路由和第四条路由有非常冲突的配置，因为它们都定义了对`192.168.33.0/24`网络中的 IP 该怎么做。

#### 更具体的路由获胜

正如前面提到的，路由网络数据包的“黄金法则”是更具体的路由总是获胜。如果我们查看路由配置，我们有一个路由，它表示`192.168.33.0/24`子网中的所有流量应该从`enp0s8`设备出去。还有第二条路由，它明确表示`192.168.33.11`应该通过`enp0s3`设备出去。IP`192.168.33.11`适用于这两条规则，但系统应该通过哪条路由发送数据包呢？

答案总是更具体的路由。

由于第二条路由明确定义了所有流量到`192.168.33.11`都从`enp0s3`接口出去，内核将通过`enp0s3`接口路由所有返回的数据包。这种情况不受`192.168.33.0/24`或甚至默认路由的影响。

我们可以通过使用带有`route get`选项的`ip`命令来看到所有这些情况。

```
[db]# ip route get 192.168.33.11
192.168.33.11 via 10.0.2.1 dev enp0s3  src 10.0.2.16
 cache

```

带有`route get`选项的`ip`命令将获取提供的 IP 并输出数据包将经过的路由。

当我们使用这个命令与`192.168.33.11`一起使用时，我们可以看到`ip`明确显示数据包将通过`enp0s3`设备。如果我们使用相同的命令与其他 IP 一起使用，我们可以看到默认路由和`192.168.33.0/24`路由是如何使用的。

```
[db]# ip route get 192.168.33.15
192.168.33.15 dev enp0s8  src 192.168.33.12
 cache
[db]# ip route get 4.4.4.4
4.4.4.4 via 10.0.2.2 dev enp0s3  src 10.0.2.16
 cache
[db]# ip route get 192.168.33.200
192.168.33.200 dev enp0s8  src 192.168.33.12
 cache
[db]# ip route get 169.254.3.5
169.254.3.5 dev enp0s8  src 192.168.33.12
 cache

```

我们可以看到，当提供一个特定路由定义的子网内的 IP 地址时，将采用这个特定路由。然而，当 IP 没有被特定路由定义时，将采用默认路由。

# 假设

现在我们了解了到`192.168.33.11`的数据包是如何路由的，我们应该调整我们之前的假设，以反映`192.168.33.11`到`enp0s3`的路由是不正确的，并且导致了我们的问题。

基本上，正在发生的事情（我们通过`tcpdump`看到了这一点）是，当数据库服务器（`192.168.33.12`）从博客服务器（`192.168.33.11`）接收到网络数据包时，它是通过`enp0s8`设备到达的。然而，当数据库服务器发送回复数据包（`SYN-ACK`）到 Web 应用服务器时，数据包是通过`enp0s3`接口发送出去的。

由于`enp0s3`设备连接到`10.0.2.0/24`网络，似乎数据包被`10.0.2.0/24`网络上的另一个系统或设备拒绝（`RESET`）。很可能，这是由于这是异步路由的一个典型例子。

异步路由是指数据包到达一个接口，但在另一个接口上回复。在大多数网络配置中，默认情况下是被拒绝的，但在某些情况下可以被启用；然而，这些情况并不是非常常见。

在我们的情况下，由于`enp0s8`接口是`192.168.33.0/24`子网的一部分，启用异步路由是没有意义的。我们的数据包到`192.168.33.11`应该简单地通过`enp0s8`接口路由。

# 反复试验

现在我们已经确定了数据收集的问题，并建立了我们的假设可能的原因，我们可以开始下一个故障排除步骤：使用试错法来纠正问题。

## 删除无效路由

为了纠正我们的问题，我们需要删除针对`192.168.33.11`的无效路由。为此，我们将再次使用`ip`命令，这次使用`route del`选项。

```
[db]# ip route del 192.168.33.11
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16
169.254.0.0/16 dev enp0s8  scope link  metric 1003
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12

```

在前面的例子中，我们使用了`ip`命令和`route del`选项来删除针对单个 IP 的路由。我们可以使用相同的命令和选项来删除针对子网定义的路由。以下示例将删除`169.254.0.0/16`网络的路由：

```
[db]# ip route del 169.254.0.0/16
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12

```

从`ip route show`的执行中，我们可以看到`192.168.33.11`不再存在冲突的路由。问题是：这个修复了我们的问题吗？唯一确定的方法是测试它，为此我们可以简单地刷新加载了博客错误页面的浏览器。

![删除无效路由](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel-tbst-gd/img/00005.jpeg)

看来我们成功地纠正了问题。如果我们现在执行`tcpdump`，我们可以验证博客和数据库服务器能够通信。

```
[db]# tcpdump -nnvvv -i enp0s8 port 3306
tcpdump: listening on enp0s8, link-type EN10MB (Ethernet), capture size 65535 bytes
16:14:05.958507 IP (tos 0x0, ttl 64, id 7605, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.47350 > 192.168.33.12.3306: Flags [S], cksum 0xa9a7 (correct), seq 4211276877, win 14600, options [mss 1460,sackOK,TS val 46129656 ecr 0,nop,wscale 6], length 0
16:14:05.958603 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.12.3306 > 192.168.33.11.47350: Flags [S.], cksum 0xc396 (incorrect -> 0x786b), seq 2378639726, ack 4211276878, win 14480, options [mss 1460,sackOK,TS val 46102446 ecr 46129656,nop,wscale 6], length 0
16:14:05.959103 IP (tos 0x0, ttl 64, id 7606, offset 0, flags [DF], proto TCP (6), length 52)
 192.168.33.11.47350 > 192.168.33.12.3306: Flags [.], cksum 0xdee0 (correct), seq 1, ack 1, win 229, options [nop,nop,TS val 46129657 ecr 46102446], length 0
16:14:05.959336 IP (tos 0x8, ttl 64, id 24256, offset 0, flags [DF], proto TCP (6), length 138)
 192.168.33.12.3306 > 192.168.33.11.47350: Flags [P.], cksum 0xc3e4 (incorrect -> 0x99c9), seq 1:87, ack 1, win 227, options [nop,nop,TS val 46102447 ecr 46129657], length 86
16:14:05.959663 IP (tos 0x0, ttl 64, id 7607, offset 0, flags [DF], proto TCP (6), length 52)

```

前面的输出是我们从一个健康的连接中期望看到的。

在这里，我们看到四个数据包，第一个是来自`blog.example.com`（`192.168.33.11`）的`SYN`（`Flags [S]`），接着是来自`db.example.com`（`192.168.33.12`）的`SYN-ACK`（`Flags [S.]`），以及来自`blog.example.com`（`192.168.33.12`）的`ACK`（或`SYN-ACK-ACK`）（`Flags [.]`）。这三个数据包是完成的 TCP 三次握手。第四个数据包是一个`PUSH`（`Flags [P.]`）数据包，这是实际的数据传输。所有这些都是良好工作的网络连接的迹象。

## 配置文件

现在我们已经从路由表中删除了无效的路由，我们可以看到博客正在工作；这意味着我们已经完成了，对吗？不，至少还没有。

当我们使用`ip`命令删除路由时，我们从活动路由表中删除了路由，但没有从整个系统中删除路由。如果我们重新启动网络，或者简单地重新启动服务器，这个无效的路由将重新出现。

```
[db]# service network restart
Restarting network (via systemctl):                        [  OK  ]
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16
169.254.0.0/16 dev enp0s8  scope link  metric 1003
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12
192.168.33.11 via 10.0.2.1 dev enp0s3  proto static  metric 1

```

这是因为当系统启动时，它会根据一组文件中的配置来配置网络。`ip`命令用于操作实时网络配置，而不是这些网络配置文件。因此，使用`ip`命令进行的任何更改都不是永久性的，而只是暂时的，直到系统下一次读取和应用网络配置为止。

为了完全从网络配置中删除这个路由，我们需要修改网络配置文件。

```
[db]# cd /etc/sysconfig/network-scripts/

```

在基于 Red Hat 企业 Linux 的系统上，网络配置文件大多存储在`/etc/sysconfig/network-scripts`文件夹中。首先，我们可以切换到这个文件夹并执行`ls -la`来识别当前的网络配置文件。

```
[db]# ls -la
total 228
drwxr-xr-x. 2 root root  4096 Mar 14 14:37 .
drwxr-xr-x. 6 root root  4096 Mar 14 23:42 ..
-rw-r--r--. 1 root root   195 Jul 22  2014 ifcfg-enp0s3
-rw-r--r--. 1 root root   217 Mar 14 14:37 ifcfg-enp0s8
-rw-r--r--. 1 root root   254 Apr  2  2014 ifcfg-lo
lrwxrwxrwx. 1 root root    24 Jul 22  2014 ifdown -> ../../../usr/sbin/ifdown
-rwxr-xr-x. 1 root root   627 Apr  2  2014 ifdown-bnep
-rwxr-xr-x. 1 root root  5553 Apr  2  2014 ifdown-eth
-rwxr-xr-x. 1 root root   781 Apr  2  2014 ifdown-ippp
-rwxr-xr-x. 1 root root  4141 Apr  2  2014 ifdown-ipv6
lrwxrwxrwx. 1 root root    11 Jul 22  2014 ifdown-isdn -> ifdown-ippp
-rwxr-xr-x. 1 root root  1642 Apr  2  2014 ifdown-post
-rwxr-xr-x. 1 root root  1068 Apr  2  2014 ifdown-ppp
-rwxr-xr-x. 1 root root   837 Apr  2  2014 ifdown-routes
-rwxr-xr-x. 1 root root  1444 Apr  2  2014 ifdown-sit
-rwxr-xr-x. 1 root root  1468 Jun  9  2014 ifdown-Team
-rwxr-xr-x. 1 root root  1532 Jun  9  2014 ifdown-TeamPort
-rwxr-xr-x. 1 root root  1462 Apr  2  2014 ifdown-tunnel
lrwxrwxrwx. 1 root root    22 Jul 22  2014 ifup -> ../../../usr/sbin/ifup
-rwxr-xr-x. 1 root root 12449 Apr  2  2014 ifup-aliases
-rwxr-xr-x. 1 root root   859 Apr  2  2014 ifup-bnep
-rwxr-xr-x. 1 root root 10223 Apr  2  2014 ifup-eth
-rwxr-xr-x. 1 root root 12039 Apr  2  2014 ifup-ippp
-rwxr-xr-x. 1 root root 10430 Apr  2  2014 ifup-ipv6
lrwxrwxrwx. 1 root root     9 Jul 22  2014 ifup-isdn -> ifup-ippp
-rwxr-xr-x. 1 root root   642 Apr  2  2014 ifup-plip
-rwxr-xr-x. 1 root root  1043 Apr  2  2014 ifup-plusb
-rwxr-xr-x. 1 root root  2609 Apr  2  2014 ifup-post
-rwxr-xr-x. 1 root root  4154 Apr  2  2014 ifup-ppp
-rwxr-xr-x. 1 root root  1925 Apr  2  2014 ifup-routes
-rwxr-xr-x. 1 root root  3263 Apr  2  2014 ifup-sit
-rwxr-xr-x. 1 root root  1628 Oct 31  2013 ifup-Team
-rwxr-xr-x. 1 root root  1856 Jun  9  2014 ifup-TeamPort
-rwxr-xr-x. 1 root root  2607 Apr  2  2014 ifup-tunnel
-rwxr-xr-x. 1 root root  1621 Apr  2  2014 ifup-wireless
-rwxr-xr-x. 1 root root  4623 Apr  2  2014 init.ipv6-global
-rw-r--r--. 1 root root 14238 Apr  2  2014 network-functions
-rw-r--r--. 1 root root 26134 Apr  2  2014 network-functions-ipv6
-rw-r--r--. 1 root root    30 Mar 13 02:20 route-enp0s3

```

从目录列表中，我们可以看到几个配置文件。然而，一般来说，我们主要只对以`ifcfg-`开头的文件和以`route-`开头的文件感兴趣。

以`ifcfg-`开头的文件用于定义网络接口；这些文件的命名约定是“ifcfg-<设备名称>”；例如，要查看`enp0s8`的配置，我们可以读取`ifcfg-enp0s8`文件。

```
[db]# cat ifcfg-enp0s8
NM_CONTROLLED=no
BOOTPROTO=none
ONBOOT=yes
IPADDR=192.168.33.12
NETMASK=255.255.255.0
DEVICE=enp0s8
PEERDNS=no

```

我们可以看到，这个配置文件定义了用于这个接口的 IP 地址和`Netmask`。

"`route-`"文件用于定义系统的路由配置。这个文件的约定与接口文件的约定相似，即"`route-<设备名称>`"。在文件夹列表中，只有一个路由文件`route-enp0s3`。这是定义不正确路由的最可能位置。

```
[db]# cat route-enp0s3
192.168.33.11/32 via 10.0.2.1

```

一般来说，除非定义了静态路由（静态定义的路由），否则"`route-*`"文件是不存在的。我们可以看到这里只定义了一个路由在这个文件中，这意味着路由表中定义的所有其他路由都是根据接口配置动态配置的。

在上面的例子中，`route-enp0s3`文件中定义的路由没有指定接口。因此，接口将根据文件名来定义；如果相同的条目出现在`route-enp0s8`文件中，网络服务将尝试在`enp0s8`接口上定义路由。

为了确保这个路由不再出现在路由表中，我们需要从这个文件中删除它；或者，在这种情况下，因为它是唯一的路由，我们应该完全删除这个文件。

```
[db]# rm route-enp0s3
rm: remove regular file 'route-enp0s3'? y

```

决定删除文件和路由取决于所支持的环境；如果您不确定这是否是正确的操作，应该询问能告诉您事先是否正确的人。在这个例子中，我们将假设可以删除这个网络配置文件。

重新启动网络服务后，我们应该看到路由消失。

```
[db]# service network restart
Restarting network (via systemctl):                        [  OK  ]
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.16
169.254.0.0/16 dev enp0s8  scope link  metric 1003
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12

```

现在路由已经消失，网络配置已经重新加载，我们可以安全地说我们已经解决了问题。我们可以通过再次加载网页来验证这一点，以确保博客正常工作。

![配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel-tbst-gd/img/00006.jpeg)

# 总结

如果我们回顾一下本章，我们对在 Linux 上解决网络连接问题学到了很多。我们学会了如何使用`netstat`和`tcpdump`工具来查看传入和传出的连接。我们了解了 TCP 的三次握手以及`/etc/hosts`文件如何取代 DNS 设置。

在本章中，我们涵盖了许多命令，虽然我们对每个命令及其功能都有一个相当好的概述，但有一些命令我们只是浅尝辄止。

诸如`tcpdump`之类的命令就是一个很好的例子。在本章中，我们使用了`tcpdump`相当多，但这个工具的功能远不止我们在本章中使用的那些。在本书中涵盖的所有命令中，我个人认为`tcpdump`是一个值得花时间学习的工具，因为它是一个非常有用和强大的工具。我用它解决了许多问题，有时这些问题不是特定于网络，而是特定于应用程序的。

在下一章中，我们将继续保持这种网络动力，解决防火墙问题。我们可能会看到一些在本章中使用的相同命令在下一章中再次出现，但这没关系；这只是显示了理解网络和故障排除工具的重要性。
