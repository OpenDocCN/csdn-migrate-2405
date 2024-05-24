# 精通 Linux 嵌入式编程（五）

> 原文：[`zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814`](https://zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：性能分析和跟踪

使用源级调试器进行交互式调试，如前一章所述，可以让您深入了解程序的工作方式，但它将您的视野限制在一小部分代码上。在本章中，我将着眼于更大的图片，以查看系统是否按预期运行。

程序员和系统设计师在猜测瓶颈位置时通常表现得很糟糕。因此，如果您的系统存在性能问题，最好从整个系统开始查看，然后逐步使用更复杂的工具。在本章中，我首先介绍了众所周知的`top`命令，作为获取概述的手段。问题通常可以局限在单个程序上，您可以使用 Linux 分析器`perf`进行分析。如果问题不是如此局限，而您想获得更广泛的图片，`perf`也可以做到。为了诊断与内核相关的问题，我将描述跟踪工具`Ftrace`和`LTTng`，作为收集详细信息的手段。

我还将介绍 Valgrind，由于其沙箱执行环境，可以监视程序并在其运行时报告代码。我将以描述一个简单的跟踪工具`strace`来完成本章，它通过跟踪程序所做的系统调用来揭示程序的执行。

# 观察者效应

在深入了解工具之前，让我们谈谈工具将向您展示什么。就像在许多领域一样，测量某个属性会影响观察本身。测量线路中的电流需要测量一个小电阻上的电压降。然而，电阻本身会影响电流。性能分析也是如此：每个系统观察都会消耗 CPU 周期，这些资源将不再用于应用程序。测量工具还会影响缓存行为，占用内存空间，并写入磁盘，这些都会使情况变得更糟。没有不带开销的测量。

我经常听到工程师说，性能分析的结果完全是误导性的。这通常是因为他们在接近真实情况下进行测量。始终尝试在目标上进行测量，使用软件的发布版本构建，使用有效的数据集，尽可能少地使用额外服务。

## 符号表和编译标志

我们将立即遇到一个问题。虽然观察系统处于其自然状态很重要，但工具通常需要额外的信息来理解事件。

一些工具需要特殊的内核选项，特别是在介绍中列出的那些，如`perf`，`Ftrace`和`LTTng`。因此，您可能需要为这些测试构建和部署新的内核。

调试符号对将原始程序地址转换为函数名称和代码行非常有帮助。部署带有调试符号的可执行文件不会改变代码的执行，但这确实需要您拥有使用`debug`编译的二进制文件和内核的副本，至少对于您想要进行性能分析的组件。例如，一些工具在目标系统上安装这些组件效果最佳，比如`perf`。这些技术与一般调试相同，正如我在第十二章中所讨论的那样，*使用 GDB 进行调试*。

如果您想要一个工具生成调用图，您可能需要启用堆栈帧进行编译。如果您希望工具准确地将地址与代码行对应起来，您可能需要以较低级别的优化进行编译。

最后，一些工具需要将插装仪器插入程序中以捕获样本，因此您将不得不重新编译这些组件。这适用于应用程序的`gprof`，以及内核的`Ftrace`和`LTTng`。

请注意，您观察的系统发生的变化越大，您所做的测量与生产系统之间的关系就越难以建立。

### 提示

最好采取等待和观察的方法，只有在需要明确时才进行更改，并且要注意，每次这样做时，都会改变您正在测量的内容。

# 开始进行分析

在查看整个系统时，一个很好的起点是使用`top`这样的简单工具，它可以让您快速地获得概览。它会显示正在使用多少内存，哪些进程正在占用 CPU 周期，以及这些情况如何分布在不同的核心和时间上。

如果`top`显示单个应用程序在用户空间中使用了所有的 CPU 周期，那么您可以使用`perf`对该应用程序进行分析。

如果两个或更多进程的 CPU 使用率很高，那么它们之间可能存在某种耦合，也许是数据通信。如果大量的周期花费在系统调用或处理中断上，那么可能存在内核配置或设备驱动程序的问题。在任何一种情况下，您需要从整个系统开始进行分析，再次使用`perf`。

如果您想了解更多关于内核和事件顺序的信息，可以使用`Ftrace`或`LTTng`。

`top`可能无法帮助您解决其他问题。如果您有多线程代码，并且存在死锁问题，或者存在随机数据损坏问题，那么 Valgrind 加上 Helgrind 插件可能会有所帮助。内存泄漏也属于这一类问题：我在第十一章中介绍了与内存相关的诊断，*管理内存*。

# 使用 top 进行分析

`top`是一个简单的工具，不需要任何特殊的内核选项或符号表。BusyBox 中有一个基本版本，`procps`包中有一个更功能齐全的版本，该包在 Yocto Project 和 Buildroot 中可用。您还可以考虑使用`htop`，它在功能上类似于`top`，但具有更好的用户界面（有些人这样认为）。

首先，关注`top`的摘要行，如果您使用的是 BusyBox，则是第二行，如果使用`procps` `top`则是第三行。以下是一个使用 BusyBox `top`的示例：

```
Mem: 57044K used, 446172K free, 40K shrd, 3352K buff, 34452K cached
CPU:  58% usr   4% sys   0% nic   0% idle  37% io   0% irq   0% sirq
Load average: 0.24 0.06 0.02 2/51 105
 PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND
 105   104 root     R    27912   6%  61% ffmpeg -i track2.wav
 [...]

```

摘要行显示了在各种状态下运行的时间百分比，如下表所示：

| procps | Busybox |   |
| --- | --- | --- |
| `us` | `usr` | 默认优先级值的用户空间程序 |
| `sy` | `sys` | 内核代码 |
| `ni` | `nic` | 非默认优先级值的用户空间程序 |
| `id` | `idle` | 空闲 |
| `wa` | `io` | I/O 等待 |
| `hi` | `irq` | 硬件中断 |
| `si` | `sirq` | 软件中断 |
| `st` | `--` | 窃取时间：仅在虚拟化环境中相关 |

在前面的例子中，几乎所有的时间（58%）都花在用户模式下，只有一小部分时间（4%）花在系统模式下，因此这是一个在用户空间中 CPU 绑定的系统。摘要后的第一行显示只有一个应用程序负责：`ffmpeg`。任何减少 CPU 使用率的努力都应该集中在那里。

这里是另一个例子：

```
Mem: 13128K used, 490088K free, 40K shrd, 0K buff, 2788K cached
CPU:   0% usr  99% sys   0% nic   0% idle   0% io   0% irq   0% sirq
Load average: 0.41 0.11 0.04 2/46 97
 PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND
 92    82 root     R     2152   0% 100% cat /dev/urandom
 [...]

```

这个系统几乎所有的时间都花在内核空间，因为`cat`正在从`/dev/urandom`读取。在这种人为的情况下，仅对`cat`进行分析是没有帮助的，但对`cat`调用的内核函数进行分析可能会有所帮助。

`top`的默认视图只显示进程，因此 CPU 使用率是进程中所有线程的总和。按*H*键查看每个线程的信息。同样，它会汇总所有 CPU 上的时间。如果您使用的是`procps top`，可以通过按*1*键查看每个 CPU 的摘要。

想象一下，有一个单独的用户空间进程占用了大部分时间，看看如何对其进行分析。

## 穷人的分析器

您可以通过使用 GDB 在任意间隔停止应用程序并查看其正在执行的操作来对应用程序进行分析。这就是*穷人的分析器*。它很容易设置，也是收集分析数据的一种方法。

该过程很简单，这里进行了解释：

1.  使用`gdbserver`（用于远程调试）或 gbd（用于本地调试）附加到进程。进程停止。

1.  观察它停在哪个功能上。您可以使用`backtrace GDB`命令查看调用堆栈。

1.  输入`continue`以使程序恢复。

1.  过一会儿，输入*Ctrl* + *C*再次停止它，然后回到步骤 2。

如果您多次重复步骤 2 到 4，您将很快了解它是在循环还是在进行，如果您重复这些步骤足够多次，您将了解代码中的热点在哪里。

有一个专门的网页致力于这个想法，网址为[`poormansprofiler.org`](http://poormansprofiler.org)，还有一些脚本可以使它变得更容易。多年来，我已经在各种操作系统和调试器中多次使用了这种技术。

这是统计分析的一个例子，您可以在间隔时间内对程序状态进行采样。经过一些样本后，您开始了解执行函数的统计可能性。您真正需要的样本数量是令人惊讶的少。其他统计分析器包括`perf record`、`OProfile`和`gprof`。

使用调试器进行采样是具有侵入性的，因为在收集样本时程序会停止一段时间。其他工具可以以更低的开销做到这一点。

我现在将考虑如何使用`perf`进行统计分析。

# 介绍 perf

`perf`是**Linux 性能事件计数子系统**`perf_events`的缩写，也是与`perf_events`进行交互的命令行工具的名称。自 Linux 2.6.31 以来，它们一直是内核的一部分。在`tools/perf/Documentation`目录中的 Linux 源树中有大量有用的信息，还可以在[`perf.wiki.kernel.org`](https://perf.wiki.kernel.org)找到。

开发`perf`的最初动力是提供一种统一的方式来访问大多数现代处理器核心中的**性能测量单元**（**PMU**）的寄存器。一旦 API 被定义并集成到 Linux 中，将其扩展到涵盖其他类型的性能计数器就变得合乎逻辑。

在本质上，`perf`是一组事件计数器，具有关于何时主动收集数据的规则。通过设置规则，您可以从整个系统中捕获数据，或者只是内核，或者只是一个进程及其子进程，并且可以跨所有 CPU 或只是一个 CPU 进行。它非常灵活。使用这个工具，您可以从查看整个系统开始，然后关注似乎导致问题的设备驱动程序，或者运行缓慢的应用程序，或者似乎执行时间比您想象的长的库函数。

`perf`命令行工具的代码是内核的一部分，位于`tools/perf`目录中。该工具和内核子系统是手牵手开发的，这意味着它们必须来自相同版本的内核。`perf`可以做很多事情。在本章中，我将仅将其作为分析器进行检查。有关其其他功能的描述，请阅读`perf`手册页并参考前一段提到的文档。

## 为 perf 配置内核

您需要一个配置为`perf_events`的内核，并且需要交叉编译的`perf`命令才能在目标上运行。相关的内核配置是`CONFIG_PERF_EVENTS`，位于菜单**General setup** | **Kernel Performance Events And Counters**中。

如果您想使用 tracepoints 进行分析（稍后会详细介绍），还要启用有关`Ftrace`部分中描述的选项。当您在那里时，也值得启用`CONFIG_DEBUG_INFO`。

`perf`命令有许多依赖项，这使得交叉编译变得非常混乱。然而，Yocto Project 和 Buildroot 都有针对它的目标软件包。

您还需要在目标上为您感兴趣的二进制文件安装调试符号，否则`perf`将无法将地址解析为有意义的符号。理想情况下，您希望为整个系统包括内核安装调试符号。对于后者，请记住内核的调试符号位于`vmlinux`文件中。

## 使用 Yocto Project 构建 perf

如果您正在使用标准的 linux-yocto 内核，`perf_events` 已经启用，因此无需进行其他操作。

要构建`perf`工具，您可以将其明确添加到目标镜像的依赖项中，或者您可以添加 tools-profile 功能，该功能还会引入`gprof`。如前所述，您可能希望在目标镜像上有调试符号，以及内核`vmlinux`镜像。总之，这是您在`conf/local.conf`中需要的内容：

```
EXTRA_IMAGE_FEATURES = "debug-tweaks dbg-pkgs tools-profile"
IMAGE_INSTALL_append = " kernel-vmlinux"
```

## 使用 Buildroot 构建 perf

许多 Buildroot 内核配置不包括`perf_events`，因此您应该首先检查您的内核是否包括前面部分提到的选项。

要交叉编译 perf，请运行 Buildroot 的`menuconfig`并选择以下内容：

+   `BR2_LINUX_KERNEL_TOOL_PERF` 在**Kernel** | **Linux Kernel Tools**中。要构建带有调试符号的软件包并在目标上安装未剥离的软件包，请选择这两个设置。

+   `BR2_ENABLE_DEBUG` 在**Build options** | **build packages with debugging symbols**菜单中。

+   `BR2_STRIP = none` 在**Build options** | **strip command for binaries on target**菜单中。

然后，运行`make clean`，然后运行`make`。

构建完所有内容后，您将需要手动将`vmlinux`复制到目标镜像中。

## 使用 perf 进行性能分析

您可以使用`perf`来使用事件计数器之一对程序的状态进行采样，并在一段时间内累积样本以创建一个性能分析。这是统计分析的另一个例子。默认事件计数器称为循环，这是一个通用的硬件计数器，映射到表示核心时钟频率的 PMU 寄存器的循环计数。

使用`perf`创建性能分析是一个两阶段过程：`perf record`命令捕获样本并将其写入一个名为`perf.data`的文件（默认情况下），然后`perf report`分析结果。这两个命令都在目标上运行。正在收集的样本已经被过滤，以用于您指定的进程及其子进程，以及您指定的命令。以下是一个示例，对搜索字符串`linux`的 shell 脚本进行性能分析：

```
# perf record sh -c "find /usr/share | xargs grep linux > /dev/null"
[ perf record: Woken up 2 times to write data ]
[ perf record: Captured and wrote 0.368 MB perf.data (~16057 samples) ]
# ls -l perf.data
-rw-------    1 root     root      387360 Aug 25  2015 perf.data

```

现在，您可以使用命令`perf report`显示来自`perf.data`的结果。您可以在命令行上选择三种用户界面：

+   `--stdio`：这是一个纯文本界面，没有用户交互。您将需要启动`perf report`并为跟踪的每个视图进行注释。

+   `--tui`：这是一个简单的基于文本的菜单界面，可以在屏幕之间进行遍历。

+   `--gtk`：这是一个图形界面，其行为与`--tui`相同。

默认为 TUI，如此示例所示：

![使用 perf 进行性能分析](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_13_01.jpg)

`perf`能够记录代表进程执行的内核函数，因为它在内核空间中收集样本。

列表按最活跃的函数首先排序。在此示例中，除了一个函数在运行`grep`时捕获之外，其他所有函数都被捕获。有些在库`libc-2.20`中，有些在程序`busybox.nosuid`中，有些在内核中。我们对程序和库函数有符号名称，因为所有二进制文件都已安装在目标上，并带有调试信息，并且内核符号是从`/boot/vmlinux`中读取的。如果您的`vmlinux`位于不同的位置，请在`perf report`命令中添加`-k <path>`。您可以使用`perf record -o <file name>`将样本保存到不同的文件中，而不是将样本存储在`perf.data`中，并使用`perf report -i <file name>`进行分析。

默认情况下，`perf record` 使用循环计数器以 1000Hz 的频率进行采样。

### 提示

1000Hz 的采样频率可能比您实际需要的要高，并且可能是观察效应的原因。尝试较低的频率：根据我的经验，100Hz 对大多数情况已经足够了。您可以使用`-F`选项设置采样频率。

## 调用图

这仍然并不是真的让生活变得容易；列表顶部的函数大多是低级内存操作，你可以相当肯定它们已经被优化过了。很高兴能够退后一步，看看这些函数是从哪里被调用的。您可以通过在每个样本中捕获回溯来做到这一点，可以使用`perf record`的`-g`选项来实现。

现在，`perf report`在函数是调用链的一部分时显示加号（**+**）。您可以展开跟踪以查看链中较低的函数：

![调用图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_13_02.jpg)

### 注意

生成调用图依赖于从堆栈中提取调用帧的能力，就像在 GDB 中需要回溯一样。解开堆栈所需的信息被编码在可执行文件的调试信息中，但并非所有架构和工具链的组合都能够做到这一点。

## perf annotate

现在您知道要查看哪些函数，很高兴能够深入了解并查看代码，并对每条指令进行计数。这就是`perf annotate`的作用，它调用了安装在目标上的`objdump`的副本。您只需要使用`perf annotate`来代替`perf report`。

`perf annotate`需要可执行文件和 vmlinux 的符号表。这是一个带注释的函数的示例：

![perf annotate](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_13_03.jpg)

如果您想看到与汇编程序交错的源代码，可以将相关部分复制到目标设备。如果您正在使用 Yocto Project 并使用额外的镜像功能`dbg-pkgs`构建，或者已安装了单独的`-dbg`软件包，则源代码将已经安装在`/usr/src/debug`中。否则，您可以检查调试信息以查看源代码的位置：

```
$ arm-buildroot-linux-gnueabi-objdump --dwarf lib/libc-2.19.so  | grep DW_AT_comp_dir
 <3f>   DW_AT_comp_dir : /home/chris/buildroot/output/build/host-gcc-initial-4.8.3/build/arm-buildroot-linux-gnueabi/libgcc

```

目标上的路径应该与`DW_AT_comp_dir`中看到的路径完全相同。

这是带有源代码和汇编代码的注释示例：

![perf annotate](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_13_04.jpg)

# 其他分析器：OProfile 和 gprof

这两个统计分析器早于`perf`。它们都是`perf`功能的子集，但仍然非常受欢迎。我只会简要提到它们。

OProfile 是一个内核分析器，始于 2002 年。最初，它有自己的内核采样代码，但最近的版本使用`perf_events`基础设施来实现这一目的。有关更多信息，请访问[`oprofile.sourceforge.net`](http://oprofile.sourceforge.net)。OProfile 由内核空间组件和用户空间守护程序和分析命令组成。

OProfile 需要启用这两个内核选项：

+   **常规设置** | **分析支持**中的`CONFIG_PROFILING`

+   **常规设置** | **OProfile 系统分析**中的`CONFIG_OPROFILE`

如果您正在使用 Yocto Project，则用户空间组件将作为`tools-profile`镜像功能的一部分安装。如果您正在使用 Buildroot，则该软件包将通过`BR2_PACKAGE_OPROFILE`启用。

您可以使用以下命令收集样本：

```
# operf <program>

```

等待应用程序完成，或按下*Ctrl* + *C*停止分析。分析数据存储在`<cur-dir>/oprofile_data/samples/current`中。

使用`opreport`生成概要文件。OProfile 手册中记录了各种选项。

`gprof`是 GNU 工具链的一部分，是最早的开源代码分析工具之一。它结合了编译时的插装和采样技术，使用 100 Hz 的采样率。它的优点是不需要内核支持。

要准备使用`gprof`进行分析的程序，您需要在编译和链接标志中添加`-pg`，这会注入收集有关调用树信息的代码到函数前言中。运行程序时，会收集样本并将其存储在一个缓冲区中，当程序终止时，会将其写入名为`gmon.out`的文件中。

您可以使用`gprof`命令从`gmon.out`中读取样本和程序的副本中的调试信息。

例如，如果您想要对 BusyBox 的`grep` applet 进行分析。您需要使用`-pg`选项重新构建 BusyBox，运行命令，并查看结果：

```
# busybox grep "linux" *
# ls -l gmon.out
-rw-r--r-- 1 root root   473 Nov 24 14:07 gmon.out

```

然后，您可以在目标机或主机上分析捕获的样本，使用以下内容：

```
# gprof busybox
Flat profile:

Each sample counts as 0.01 seconds.
 no time accumulated

 %   cumulative   self              self     total
 time   seconds   seconds    calls  Ts/call  Ts/call  name
 0.00     0.00     0.00      688     0.00     0.00  xrealloc
 0.00     0.00     0.00      345     0.00     0.00  bb_get_chunk_from_file
 0.00     0.00     0.00      345     0.00     0.00  xmalloc_fgetline
 0.00     0.00     0.00       6      0.00     0.00  fclose_if_not_stdin
 0.00     0.00     0.00       6      0.00     0.00  fopen_for_read
 0.00     0.00     0.00       6      0.00     0.00  grep_file
[...]
 Call graph

granularity: each sample hit covers 2 byte(s) no time propagated

index  % time    self  children    called     name
 0.00    0.00      688/688  bb_get_chunk_from_file [2]
[1]      0.0     0.00    0.00      688         xrealloc [1]
----------------------------------------------------------
 0.00    0.00      345/345  xmalloc_fgetline [3]
[2]      0.0     0.00    0.00      345      bb_get_chunk_from_file [2]
 0.00    0.00      688/688  xrealloc [1]
---------------------------------------------------------
 0.00    0.00      345/345  grep_file [6]
[3]      0.0     0.00    0.00     345       xmalloc_fgetline [3]
 0.00    0.00     345/345   bb_get_chunk_from_file [2]
--------------------------------------------------------
 0.00    0.00       6/6     grep_main [12]
[4]      0.0     0.00    0.00       6       fclose_if_not_stdin [4]
[...]

```

请注意，执行时间都显示为零，因为大部分时间都花在系统调用上，而`gprof`不会对系统调用进行跟踪。

### 提示

`gprof`不会捕获多线程进程的主线程以外的线程的样本，并且不会对内核空间进行采样，这些限制了它的实用性。

# 跟踪事件

到目前为止，我们所见过的所有工具都使用统计采样。通常您希望了解事件的顺序，以便能够看到它们并将它们与彼此关联起来。函数跟踪涉及使用跟踪点对代码进行仪器化，以捕获有关事件的信息，并可能包括以下一些或全部内容：

+   时间戳

+   上下文，例如当前 PID

+   函数参数和返回值

+   调用堆栈

它比统计分析更具侵入性，并且可能会生成大量数据。通过在捕获样本时应用过滤器，以及在查看跟踪时稍后应用过滤器，可以减轻后者。

我将在这里介绍两个跟踪工具：内核函数跟踪器`Ftrace`和`LTTng`。

# 介绍 Ftrace

内核函数跟踪器`Ftrace`是由 Steven Rostedt 等人进行的工作发展而来，他们一直在追踪高延迟的原因。`Ftrace`出现在 Linux 2.6.27 中，并自那时以来一直在积极开发。在内核源代码的`Documentation/trace`中有许多描述内核跟踪的文档。

`Ftrace`由许多跟踪器组成，可以记录内核中各种类型的活动。在这里，我将讨论`function`和`function_graph`跟踪器，以及事件 tracepoints。在第十四章中，*实时编程*，我将重新讨论 Ftrace，并使用它来显示实时延迟。

`function`跟踪器对每个内核函数进行仪器化，以便可以记录和时间戳调用。值得一提的是，它使用`-pg`开关编译内核以注入仪器化，但与 gprof 的相似之处就到此为止了。`function_graph`跟踪器进一步记录函数的进入和退出，以便可以创建调用图。事件 tracepoints 功能还记录与调用相关的参数。

`Ftrace`具有非常适合嵌入式的用户界面，完全通过`debugfs`文件系统中的虚拟文件实现，这意味着您无需在目标机上安装任何工具即可使其工作。尽管如此，如果您愿意，还有其他用户界面可供选择：`trace-cmd`是一个命令行工具，可记录和查看跟踪，并且在 Buildroot（`BR2_PACKAGE_TRACE_CMD`）和 Yocto Project（`trace-cmd`）中可用。还有一个名为 KernelShark 的图形跟踪查看器，可作为 Yocto Project 的一个软件包使用。

## 准备使用 Ftrace

`Ftrace`及其各种选项在内核配置菜单中进行配置。您至少需要以下内容：

+   在菜单**内核调试** | **跟踪器** | **内核函数跟踪器**中的`CONFIG_FUNCTION_TRACER`

出于以后会变得清晰的原因，您最好也打开这些选项：

+   在菜单**内核调试** | **跟踪器** | **内核函数图跟踪器**中的`CONFIG_FUNCTION_GRAPH_TRACER`

+   在菜单**内核调试** | **跟踪器** | **启用/禁用动态函数跟踪**中的`CONFIG_DYNAMIC_FTRACE`

由于整个系统托管在内核中，因此不需要进行用户空间配置。

在使用`Ftrace`之前，您必须挂载`debugfs`文件系统，按照惯例，它位于`/sys/kernel/debug`目录中：

```
# mount –t debugfs none /sys/kernel/debug

```

所有`Ftrace`的控件都在`/sys/kernel/debug/tracing`目录中；甚至在`README`文件中有一个迷你的`HOWTO`。

这是内核中可用的跟踪器列表：

```
# cat /sys/kernel/debug/tracing/available_tracers
blk function_graph function nop

```

`current_tracer`显示的是活动跟踪器，最初将是空跟踪器`nop`。

要捕获跟踪，请通过将`available_tracers`中的一个名称写入`current_tracer`来选择跟踪器，然后启用跟踪一小段时间，如下所示：

```
# echo function > /sys/kernel/debug/tracing/current_tracer
# echo 1 > /sys/kernel/debug/tracing/tracing_on
# sleep 1
# echo 0 > /sys/kernel/debug/tracing/tracing_on

```

在一秒钟内，跟踪缓冲区将被填满内核调用的每个函数的详细信息。跟踪缓冲区的格式是纯文本，如`Documentation/trace/ftrace.txt`中所述。您可以从`trace`文件中读取跟踪缓冲区：

```
# cat /sys/kernel/debug/tracing/trace
# tracer: function
#
# entries-in-buffer/entries-written: 40051/40051   #P:1
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
 sh-361   [000] ...1   992.990646: mutex_unlock <-rb_simple_write
 sh-361   [000] ...1   992.990658: __fsnotify_parent <-vfs_write
 sh-361   [000] ...1   992.990661: fsnotify <-vfs_write
 sh-361   [000] ...1   992.990663: __srcu_read_lock <-fsnotify
 sh-361   [000] ...1   992.990666: preempt_count_add <-__srcu_read_lock
 sh-361   [000] ...2   992.990668: preempt_count_sub <-__srcu_read_lock
 sh-361   [000] ...1   992.990670: __srcu_read_unlock <-fsnotify
 sh-361   [000] ...1   992.990672: __sb_end_write <-vfs_write
 sh-361   [000] ...1   992.990674: preempt_count_add <-__sb_end_write
[...]

```

您可以在短短一秒钟内捕获大量数据点。

与分析器一样，很难理解这样的平面函数列表。如果选择`function_graph`跟踪器，Ftrace 会捕获如下的调用图：

```
# tracer: function_graph
#
# CPU  DURATION            FUNCTION CALLS
#|     |   |               |   |   |   |
 0) + 63.167 us   |              } /* cpdma_ctlr_int_ctrl */
 0) + 73.417 us   |            } /* cpsw_intr_disable */
 0)               |            disable_irq_nosync() {
 0)               |              __disable_irq_nosync() {
 0)               |                __irq_get_desc_lock() {
 0)   0.541 us    |                  irq_to_desc();
 0)   0.500 us    |                  preempt_count_add();
 0) + 16.000 us   |                }
 0)               |                __disable_irq() {
 0)   0.500 us    |                  irq_disable();
 0)   8.208 us    |                }
 0)               |                __irq_put_desc_unlock() {
 0)   0.459 us    |                  preempt_count_sub();
 0)   8.000 us    |                }
 0) + 55.625 us   |              }
 0) + 63.375 us   |            }

```

现在您可以看到函数调用的嵌套，由括号`{`和`}`分隔。在终止括号处，有一个函数中所花费的时间的测量，如果花费的时间超过`10 µs`，则用加号`+`进行注释，如果花费的时间超过`100 µs`，则用感叹号`!`进行注释。

通常您只对由单个进程或线程引起的内核活动感兴趣，这种情况下，您可以通过将线程 ID 写入`set_ftrace_pid`来限制跟踪到一个线程。

## 动态 Ftrace 和跟踪过滤器

启用`CONFIG_DYNAMIC_FTRACE`允许 Ftrace 在运行时修改函数`trace`站点，这有一些好处。首先，它触发了跟踪函数探针的额外构建时间处理，使 Ftrace 子系统能够在引导时定位它们并用 NOP 指令覆盖它们，从而将函数跟踪代码的开销几乎降为零。然后，您可以在生产或接近生产的内核中启用 Ftrace 而不会影响性能。

第二个优点是您可以有选择地启用函数`trace sites`而不是跟踪所有内容。函数列表放入`available_filter_functions`中；有数万个函数。您可以通过将名称从`available_filter_functions`复制到`set_ftrace_filter`来根据需要有选择地启用函数跟踪，然后通过将名称写入`set_ftrace_notrace`来停止跟踪该函数。您还可以使用通配符并将名称附加到列表中。例如，假设您对`tcp`处理感兴趣：

```
# cd /sys/kernel/debug/tracing
# echo "tcp*" > set_ftrace_filter
# echo function > current_tracer
# echo 1 > tracing_on

```

运行一些测试，然后查看跟踪：

```
# cat trace
# tracer: function
#
# entries-in-buffer/entries-written: 590/590   #P:1
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
 dropbear-375   [000] ...1 48545.022235: tcp_poll <-sock_poll
 dropbear-375   [000] ...1 48545.022372: tcp_poll <-sock_poll
 dropbear-375   [000] ...1 48545.022393: tcp_sendmsg <-inet_sendmsg
 dropbear-375   [000] ...1 48545.022398: tcp_send_mss <-tcp_sendmsg
 dropbear-375   [000] ...1 48545.022400: tcp_current_mss <-tcp_send_mss
[...]

```

`set_ftrace_filter`也可以包含命令，例如在执行某些函数时启动和停止跟踪。这里没有空间来详细介绍这些内容，但如果您想了解更多，请阅读`Documentation/trace/ftrace.txt`中的**Filter commands**部分。

## 跟踪事件

在前面的部分中描述的函数和`function_graph`跟踪器仅记录执行函数的时间。跟踪事件功能还记录与调用相关的参数，使跟踪更易读和信息丰富。例如，跟踪事件将记录请求的字节数和返回的指针，而不仅仅是记录调用了函数`kmalloc`。跟踪事件在 perf 和 LTTng 以及 Ftrace 中使用，但跟踪事件子系统的开发是由 LTTng 项目促成的。

创建跟踪事件需要内核开发人员的努力，因为每个事件都是不同的。它们在源代码中使用`TRACE_EVENT`宏进行定义：现在有一千多个。您可以在`/sys/kernel/debug/tracing/available_events`中看到运行时可用的事件列表。它们的名称是`subsystem:function`，例如，`kmem:kmalloc`。每个事件还由`tracing/events/[subsystem]/[function]`中的子目录表示，如下所示：

```
# ls events/kmem/kmalloc
enable   filter   format   id   trigger

```

文件如下：

+   `enable`：您可以将`1`写入此文件以启用事件。

+   `filter`：这是一个必须对事件进行跟踪的表达式。

+   `格式`：这是事件和参数的格式。

+   `id`：这是一个数字标识符。

+   `触发器`：这是在事件发生时执行的命令，使用`Documentation/trace/ftrace.txt`中`过滤命令`部分定义的语法。我将为您展示一个涉及`kmalloc`和`kfree`的简单示例。

事件跟踪不依赖于功能跟踪器，因此首先选择`nop`跟踪器：

```
# echo nop > current_tracer

```

接下来，通过逐个启用每个事件来选择要跟踪的事件：

```
# echo 1 > events/kmem/kmalloc/enable
# echo 1 > events/kmem/kfree/enable

```

您还可以将事件名称写入`set_event`，如下所示：

```
# echo "kmem:kmalloc kmem:kfree" > set_event

```

现在，当您阅读跟踪时，您可以看到函数及其参数：

```
# tracer: nop
#
# entries-in-buffer/entries-written: 359/359   #P:1
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
 cat-382   [000] ...1  2935.586706: kmalloc: call_site=c0554644 ptr=de515a00 bytes_req=384 bytes_alloc=512 gfp_flags=GFP_ATOMIC|GFP_NOWARN|GFP_NOMEMALLOC
 cat-382   [000] ...1  2935.586718: kfree: call_site=c059c2d8 ptr=  (null)

```

在 perf 中，完全相同的跟踪事件可见为*tracepoint 事件*。

# 使用 LTTng

Linux Trace Toolkit 项目是由 Karim Yaghmour 发起的，作为跟踪内核活动的手段，并且是最早为 Linux 内核提供的跟踪工具之一。后来，Mathieu Desnoyers 接受了这个想法，并将其重新实现为下一代跟踪工具 LTTng。然后，它被扩展以覆盖用户空间跟踪以及内核。项目网站位于[`lttng.org/`](http://lttng.org/)，包含了全面的用户手册。

LTTng 由三个组件组成：

+   核心会话管理器

+   作为一组内核模块实现的内核跟踪器

+   作为库实现的用户空间跟踪器

除此之外，您还需要一个跟踪查看器，比如 Babeltrace（[`www.efficios.com/babeltrace`](http://www.efficios.com/babeltrace)）或 Eclipse Trace Compaas 插件，以在主机或目标上显示和过滤原始跟踪数据。

LTTng 需要一个配置了`CONFIG_TRACEPOINTS`的内核，当您选择**内核调试** | **跟踪器** | **内核函数跟踪器**时会启用。

以下描述是针对 LTTng 版本 2.5 的；其他版本可能有所不同。

## LTTng 和 Yocto 项目

您需要将这些软件包添加到目标依赖项中，例如在`conf/local.conf`中：

```
IMAGE_INSTALL_append = " lttng-tools lttng-modules lttng-ust"
```

如果您想在目标上运行 Babeltrace，还需要附加软件包`babeltrace`。

## LTTng 和 Buildroot

您需要启用以下内容：

+   在菜单**目标软件包** | **调试、性能分析和基准测试** | **lttng-modules**中的`BR2_PACKAGE_LTTNG_MODULES`。

+   在菜单**目标软件包** | **调试、性能分析和基准测试** | **lttng-tools**中的`BR2_PACKAGE_LTTNG_TOOLS`。

对于用户空间跟踪，启用此选项：

+   在菜单**目标软件包** | **库** | **其他**中的`BR2_PACKAGE_LTTNG_LIBUST`，启用**lttng-libust**。

有一个名为`lttng-babletrace`的软件包供目标使用。Buildroot 会自动构建主机的`babeltrace`并将其放置在`output/host/usr/bin/babeltrace`中。

## 使用 LTTng 进行内核跟踪

LTTng 可以使用上述`ftrace`事件集作为潜在的跟踪点。最初，它们是禁用的。

LTTng 的控制接口是`lttng`命令。您可以使用以下命令列出内核探针：

```
# lttng list --kernel
Kernel events:
-------------
 writeback_nothread (loglevel: TRACE_EMERG (0)) (type: tracepoint)
 writeback_queue (loglevel: TRACE_EMERG (0)) (type: tracepoint)
 writeback_exec (loglevel: TRACE_EMERG (0)) (type: tracepoint)
[...]

```

在这个示例中，跟踪是在会话的上下文中捕获的，会话名为`test`：

```
# lttng create test
Session test created.
Traces will be written in /home/root/lttng-traces/test-20150824-140942
# lttng list
Available tracing sessions:
 1) test (/home/root/lttng-traces/test-20150824-140942) [inactive]

```

现在在当前会话中启用一些事件。您可以使用`--all`选项启用所有内核跟踪点，但请记住关于生成过多跟踪数据的警告。让我们从一些与调度器相关的跟踪事件开始：

```
# lttng enable-event --kernel sched_switch,sched_process_fork

```

检查一切是否设置好：

```
# lttng list test
Tracing session test: [inactive]
 Trace path: /home/root/lttng-traces/test-20150824-140942
 Live timer interval (usec): 0

=== Domain: Kernel ===

Channels:
-------------
- channel0: [enabled]

 Attributes:
 overwrite mode: 0
 subbufers size: 26214
 number of subbufers: 4
 switch timer interval: 0
 read timer interval: 200000
 trace file count: 0
 trace file size (bytes): 0
 output: splice()

 Events:
 sched_process_fork (loglevel: TRACE_EMERG (0)) (type: tracepoint) [enabled]
 sched_switch (loglevel: TRACE_EMERG (0)) (type: tracepoint) [enabled]

```

现在开始跟踪：

```
# lttng start

```

运行测试负载，然后停止跟踪：

```
# lttng stop

```

会话的跟踪写入会话目录`lttng-traces/<session>/kernel`。

您可以使用 Babeltrace 查看器以文本格式转储原始跟踪数据，在这种情况下，我在主机计算机上运行它：

```
$ babeltrace  lttng-traces/test-20150824-140942/kernel

```

输出内容过于冗长，无法适应本页，因此我将其留给您，读者，以此方式捕获和显示跟踪。eBabeltrace 的文本输出具有一个优点，那就是可以使用 grep 和类似的命令轻松搜索字符串。

一个用于图形跟踪查看器的不错选择是 Eclipse 的 Trace Compass 插件，它现在是 Eclipse IDE for C/C++ Developers 捆绑包的一部分。将跟踪数据导入 Eclipse 通常有点麻烦。简而言之，您需要按照以下步骤进行操作：

1.  打开跟踪透视图。

1.  通过选择**文件** | **新建** | **跟踪项目**来创建一个新项目。

1.  输入项目名称，然后点击**完成**。

1.  在**项目资源管理器**菜单中右键单击**新建项目**选项，然后选择**导入**。

1.  展开**跟踪**，然后选择**跟踪导入**。

1.  浏览到包含跟踪的目录（例如`test-20150824-140942`），选中要指示的子目录的复选框（可能是内核），然后点击**完成**。

1.  现在，展开项目，在其中展开**Traces[1]**，然后在其中双击**kernel**。

1.  您应该在以下截图中看到跟踪数据：![使用 LTTng 进行内核跟踪](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_13_05.jpg)

在前面的截图中，我已经放大了控制流视图，以显示`dropbear`和 shell 之间的状态转换，以及`lttng`守护程序的一些活动。

# 使用 Valgrind 进行应用程序分析。

我在第十一章中介绍了 Valgrind，*内存管理*，作为使用 memcheck 工具识别内存问题的工具。Valgrind 还有其他有用的应用程序分析工具。我要在这里看的两个是**Callgrind**和**Helgrind**。由于 Valgrind 通过在沙盒中运行代码来工作，它能够在代码运行时检查并报告某些行为，而本地跟踪器和分析器无法做到这一点。

# Callgrind

Callgrind 是一个生成调用图的分析器，还收集有关处理器缓存命中率和分支预测的信息。如果您的瓶颈是 CPU 密集型，Callgrind 才有用。如果涉及大量 I/O 或多个进程，则没有用。

Valgrind 不需要内核配置，但需要调试符号。它在 Yocto Project 和 Buildroot（`BR2_PACKAGE_VALGRIND`）中都作为目标软件包提供。

您可以在目标上使用 Valgrind 中的 Callgrind 运行，如下所示：

```
# valgrind --tool=callgrind <program>

```

这将生成一个名为`callgrind.out.<PID>`的文件，您可以将其复制到主机并使用`callgrind_annotate`进行分析。

默认情况下，会将所有线程的数据捕获到单个文件中。如果在捕获时添加`--separate-threads=yes`选项，则将每个线程的配置文件分别保存在名为`callgrind.out.<PID>-<thread id>`的文件中，例如`callgrind.out.122-01`，`callgrind.out.122-02`等。

Callgrind 可以模拟处理器 L1/L2 缓存并报告缓存未命中。使用`--simulate-cache=yes`选项捕获跟踪。L2 未命中比 L1 未命中要昂贵得多，因此要注意具有高 D2mr 或 D2mw 计数的代码。

# Helgrind

这是一个用于检测 C、C++和 Fortran 程序中包含 POSIX 线程的同步错误的线程错误检测器。

Helgrind 可以检测三类错误。首先，它可以检测 API 的不正确使用。例如，它可以解锁已经解锁的互斥锁，解锁由不同线程锁定的互斥锁，不检查某些 Pthread 函数的返回值。其次，它监视线程获取锁的顺序，从而检测可能由于锁的循环形成而产生的潜在死锁。最后，它检测数据竞争，当两个线程访问共享内存位置而不使用适当的锁或其他同步来确保单线程访问时可能发生。

使用 Helgrind 很简单，您只需要这个命令：

```
# valgrind --tool=helgrind <program>

```

它在发现问题和潜在问题时打印出来。您可以通过添加`--log-file=<filename>`将这些消息定向到文件。

# 使用 strace 显示系统调用

我从简单且无处不在的工具`top`开始了本章，我将以另一个工具`strace`结束。它是一个非常简单的跟踪器，可以捕获程序及其子进程所进行的系统调用。您可以使用它来执行以下操作：

+   了解程序进行了哪些系统调用。

+   找出那些一起失败的系统调用以及错误代码。如果程序无法启动但没有打印错误消息，或者消息太一般化，我发现这很有用。`strace`显示了失败的系统调用。

+   查找程序打开了哪些文件。

+   找出正在运行的程序进行了哪些系统调用，例如查看它是否陷入了循环中。

在线上还有更多的例子，只需搜索`strace`的技巧和窍门。每个人都有自己喜欢的故事，例如，[`chadfowler.com/blog/2014/01/26/the-magic-of-strace`](http://chadfowler.com/blog/2014/01/26/the-magic-of-strace)

`strace`使用`ptrace(2)`函数来挂钩用户空间到内核的调用。如果您想了解更多关于`ptrace`如何工作的信息，man 手册详细且易懂。

获取跟踪的最简单方法是像这样运行带有`strace`的命令（列表已经编辑过以使其更清晰）：

```
# strace ./helloworld
execve("./helloworld", ["./helloworld"], [/* 14 vars */]) = 0
brk(0)                                  = 0x11000
uname({sys="Linux", node="beaglebone", ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb6f40000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=8100, ...}) = 0
mmap2(NULL, 8100, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb6f3e000
close(3)                                = 0
open("/lib/tls/v7l/neon/vfp/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[...]
open("/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0(\0\1\0\0\0$`\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1291884, ...}) = 0
mmap2(NULL, 1328520, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb6df9000
mprotect(0xb6f30000, 32768, PROT_NONE)  = 0
mmap2(0xb6f38000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x137000) = 0xb6f38000
mmap2(0xb6f3b000, 9608, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb6f3b000
close(3)
[...]
write(1, "Hello, world!\n", 14Hello, world!
)         = 14
exit_group(0)                           = ?
+++ exited with 0 +++

```

大部分的跟踪显示了运行时环境是如何创建的。特别是您可以看到库加载器是如何寻找`libc.so.6`的，最终在`/lib`中找到它。最后，它开始运行程序的`main()`函数，打印其消息并退出。

如果您希望`strace`跟踪原始进程创建的任何子进程或线程，请添加`-f`选项。

### 提示

如果您正在使用`strace`来跟踪创建线程的程序，几乎肯定需要`-f`选项。最好使用`-ff`和`-o <file name>`，这样每个子进程或线程的输出都将被写入一个名为`<filename>.<PID | TID>`的单独文件中。

`strace`的常见用途是发现程序在启动时尝试打开哪些文件。您可以通过`-e`选项限制要跟踪的系统调用，并且可以使用`-o`选项将跟踪写入文件而不是`stdout`：

```
# strace -e open -o ssh-strace.txt ssh localhost

```

这显示了`ssh`在建立连接时打开的库和配置文件。

您甚至可以将`strace`用作基本的性能分析工具：如果使用`-c`选项，它会累积系统调用所花费的时间，并打印出类似这样的摘要：

```
# strace -c grep linux /usr/lib/* > /dev/null
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------
 78.68    0.012825         1       11098      18    read
 11.03    0.001798         1        3551            write
 10.02    0.001634         8         216      15    open
 0.26    0.000043         0         202            fstat64
 0.00    0.000000         0         201            close
 0.00    0.000000         0          1             execve
 0.00    0.000000         0          1       1     access
 0.00    0.000000         0          3             brk
 0.00    0.000000         0         199            munmap
 0.00    0.000000         0          1             uname
 0.00    0.000000         0          5             mprotect
 0.00    0.000000         0         207            mmap2
 0.00    0.000000         0         15       15    stat64
 0.00    0.000000         0          1             getuid32
 0.00    0.000000         0          1             set_tls
------ ----------- ----------- --------- --------- -----------
100.00    0.016300                 15702      49 total

```

# 摘要

没有人能抱怨 Linux 缺乏性能分析和跟踪的选项。本章为您概述了一些最常见的选项。

当面对性能不如预期的系统时，从`top`开始并尝试识别问题。如果问题被证明是单个应用程序引起的，那么您可以使用`perf record/report`来对其进行性能分析，但需要注意您必须配置内核以启用`perf`，并且需要二进制文件和内核的调试符号。OProfile 是`perf record`的替代方案，可以提供类似的信息。`gprof`已经过时，但它的优势是不需要内核支持。如果问题没有那么局部化，使用`perf`（或 OProfile）来获取系统范围的视图。

当您对内核的行为有特定问题时，`Ftrace`就派上用场了。`function`和`function_graph`跟踪器提供了函数调用关系和顺序的详细视图。事件跟踪器允许您提取有关函数的更多信息，包括参数和返回值。LTTng 执行类似的角色，利用事件跟踪机制，并添加了高速环形缓冲区以从内核中提取大量数据。Valgrind 具有特殊优势，它在沙盒中运行代码，并且可以报告其他方式难以跟踪到的错误。

使用 Callgrind 工具，它可以生成调用图并报告处理器缓存的使用情况，而使用 Helgrind 时，它可以报告与线程相关的问题。最后，不要忘记`strace`。它是发现程序正在进行哪些系统调用的良好工具，从跟踪文件打开调用以查找文件路径名到检查系统唤醒和传入信号。

与此同时，要注意并尽量避免观察者效应：确保您正在进行的测量对生产系统是有效的。在下一章中，我将继续探讨这一主题，深入探讨帮助我们量化目标系统实时性能的延迟跟踪工具。


# 第十四章：实时编程

计算机系统与现实世界之间的许多交互都是实时进行的，因此这对于嵌入式系统的开发人员来说是一个重要的主题。到目前为止，我已经在几个地方提到了实时编程：在第十章中，*了解进程和线程*，我研究了调度策略和优先级反转，在第十一章中，*管理内存*，我描述了页面错误的问题和内存锁定的需求。现在，是时候把这些主题联系在一起，深入研究实时编程了。

在本章中，我将首先讨论实时系统的特性，然后考虑应用程序和内核级别的系统设计的影响。我将描述实时内核补丁`PREEMPT_RT`，并展示如何获取它并将其应用于主线内核。最后几节将描述如何使用两个工具`cyclictest`和`Ftrace`来表征系统延迟。

嵌入式 Linux 设备实现实时行为的其他方法，例如，使用专用微控制器或在 Linux 内核旁边使用单独的实时内核，就像 Xenomai 和 RTAI 所做的那样。我不打算在这里讨论这些，因为本书的重点是将 Linux 用作嵌入式系统的核心。

# 什么是实时？

实时编程的性质是软件工程师喜欢长时间讨论的主题之一，通常给出一系列矛盾的定义。我将从阐明我认为实时重要的内容开始。

如果一个任务必须在某个时间点之前完成，这个时间点被称为截止日期，那么这个任务就是实时任务。通过考虑在编译 Linux 内核时在计算机上播放音频流时会发生什么，可以看出实时任务和非实时任务之间的区别。

第一个是实时任务，因为音频驱动程序不断接收数据流，并且必须以播放速率将音频样本块写入音频接口。同时，编译不是实时的，因为没有截止日期。您只是希望它尽快完成；无论它花费 10 秒还是 10 分钟，都不会影响内核的质量。

另一个重要的事情要考虑的是错过截止日期的后果，这可能从轻微的烦恼到系统故障和死亡。以下是一些例子：

+   **播放音频流**：截止日期在几十毫秒的范围内。如果音频缓冲区不足，你会听到点击声，这很烦人，但你会克服它。

+   **移动和点击鼠标**：截止日期也在几十毫秒的范围内。如果错过了，鼠标会移动不稳定，按钮点击将丢失。如果问题持续存在，系统将变得无法使用。

+   **打印一张纸**：纸张进纸的截止日期在毫秒级范围内，如果错过了，可能会导致打印机卡住，有人必须去修理。偶尔卡纸是可以接受的，但没有人会购买一台不断卡纸的打印机。

+   **在生产线上的瓶子上打印保质期**：如果一个瓶子没有被打印，整个生产线必须停止，瓶子被移除，然后重新启动生产线，这是昂贵的。

+   **烘烤蛋糕**：有大约 30 分钟的截止日期。如果你迟到了几分钟，蛋糕可能会被毁掉。如果你迟到了很长时间，房子就会烧毁。

+   **电力浪涌检测系统**：如果系统检测到浪涌，必须在 2 毫秒内触发断路器。未能这样做会损坏设备，并可能伤害或杀死人员。

换句话说，错过截止日期会有许多后果。我们经常谈论这些不同的类别：

+   软实时：截止日期是可取的，但有时会错过而系统不被视为失败。前两个例子就是这样。

+   硬实时：在这里，错过截止日期会产生严重影响。我们可以进一步将硬实时细分为在错过截止日期会产生成本的关键任务系统，比如第四个例子，以及在错过截止日期会对生命和肢体造成危险的安全关键系统，比如最后两个例子。我提出银行的例子是为了表明，并非所有硬实时系统的截止日期都是以微秒计量的。

为安全关键系统编写的软件必须符合各种标准，以确保其能够可靠地执行。对于像 Linux 这样复杂的操作系统来说，要满足这些要求非常困难。

在关键任务系统中，Linux 通常可以用于各种控制系统，这是可能的，也是常见的。软件的要求取决于截止日期和置信水平的组合，这通常可以通过广泛的测试来确定。

因此，要说一个系统是实时的，你必须在最大预期负载下测量其响应时间，并证明它在约定时间内满足截止日期的比例。作为一个经验法则，使用主线内核的良好配置的 Linux 系统适用于截止日期为几十毫秒的软实时任务，而使用`PREEMPT_RT`补丁的内核适用于截止日期为几百微秒的软实时和硬实时的关键任务系统。

创建实时系统的关键是减少响应时间的变化，以便更有信心地确保它们不会被错过；换句话说，你需要使系统更确定性。通常情况下，这是以性能为代价的。例如，缓存通过缩短访问数据项的平均时间来使系统运行得更快，但在缓存未命中的情况下，最大时间更长。缓存使系统更快但不太确定，这与我们想要的相反。

### 提示

实时计算的神话是它很快。事实并非如此，系统越确定性越高，最大吞吐量就越低。

本章的其余部分关注识别延迟的原因以及您可以采取的措施来减少延迟。

# 识别非确定性的来源

从根本上说，实时编程是确保实时控制输出的线程在需要时被调度，从而能够在截止日期之前完成工作。任何阻碍这一点的都是问题。以下是一些问题领域：

+   调度：实时线程必须在其他线程之前被调度，因此它们必须具有实时策略，`SCHED_FIFO`或`SCHED_RR`。此外，它们应该按照我在第十章中描述的速率单调分析理论，按照截止日期最短的顺序分配优先级。

+   调度延迟：内核必须能够在事件（如中断或定时器）发生时立即重新调度，并且不会受到无限延迟的影响。减少调度延迟是本章后面的一个关键主题。

+   优先级反转：这是基于优先级的调度的结果，当高优先级线程在低优先级线程持有的互斥锁上被阻塞时，会导致无限延迟，正如我在第十章中所描述的，*了解进程和线程*。用户空间具有优先级继承和优先级屏障互斥锁；在内核空间中，我们有实时互斥锁，它实现了优先级继承，我将在实时内核部分讨论它。

+   准确的定时器：如果你想要管理毫秒或微秒级别的截止期限，你需要匹配的定时器。高分辨率定时器至关重要，并且几乎所有内核都有配置选项。

+   **页面错误**：在执行关键代码部分时发生页面错误会破坏所有时间估计。您可以通过锁定内存来避免它们，我稍后会详细描述。

+   **中断**：它们在不可预测的时间发生，并且如果突然出现大量中断，可能会导致意外的处理开销。有两种方法可以避免这种情况。一种是将中断作为内核线程运行，另一种是在多核设备上，将一个或多个 CPU 屏蔽免受中断处理的影响。我稍后会讨论这两种可能性。

+   处理器缓存：提供了 CPU 和主内存之间的缓冲区，并且像所有缓存一样，是非确定性的来源，特别是在多核设备上。不幸的是，这超出了本书的范围，但是可以参考本章末尾的参考资料。

+   **内存总线争用**：当外围设备通过 DMA 通道直接访问内存时，它们会占用一部分内存总线带宽，从而减慢 CPU 核心（或核心）的访问速度，因此有助于程序的非确定性执行。然而，这是一个硬件问题，也超出了本书的范围。

我将在接下来的章节中扩展重要问题并看看可以采取什么措施。

列表中缺少的一项是电源管理。实时和电源管理的需求方向相反。在睡眠状态之间切换时，电源管理通常会导致高延迟，因为设置电源调节器和唤醒处理器都需要时间，改变核心时钟频率也需要时间，因为时钟需要时间稳定。但是，你肯定不会期望设备立即从挂起状态响应中断吧？我知道在至少喝一杯咖啡之后我才能开始一天。

# 理解调度延迟

实时线程需要在有任务要做时立即调度。然而，即使没有其他相同或更高优先级的线程，从唤醒事件发生的时间点（中断或系统定时器）到线程开始运行的时间总会有延迟。这称为调度延迟。它可以分解为几个组件，如下图所示：

![理解调度延迟](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_14_01.jpg)

首先，硬件中断延迟是指从中断被断言直到**ISR**（中断服务例程）开始运行的时间。其中一小部分是中断硬件本身的延迟，但最大的问题是软件中禁用的中断。最小化这种*IRQ 关闭时间*很重要。

接下来是中断延迟，即 ISR 服务中断并唤醒任何等待此事件的线程所需的时间。这主要取决于 ISR 的编写方式。通常应该只需要很短的时间，以微秒为单位。

最后一个延迟是抢占延迟，即内核被通知线程准备运行的时间点到调度器实际运行线程的时间点。这取决于内核是否可以被抢占。如果它正在运行关键部分的代码，那么重新调度将不得不等待。延迟的长度取决于内核抢占的配置。

# 内核抢占

抢占延迟是因为并不总是安全或者希望抢占当前的执行线程并调用调度器。主线 Linux 有三种抢占设置，通过**内核特性** | **抢占模型**菜单选择：

+   `CONFIG_PREEMPT_NONE`：无抢占

+   `CONFIG_PREEMPT_VOLUNTARY`：启用额外的检查以请求抢占

+   `CONFIG_PREEMPT`：允许内核被抢占

设置为`none`时，内核代码将继续执行，直到通过`syscall`返回到用户空间，其中始终允许抢占，或者遇到停止当前线程的睡眠等待。由于它减少了内核和用户空间之间的转换次数，并可能减少了上下文切换的总数，这个选项以牺牲大的抢占延迟为代价，实现了最高的吞吐量。这是服务器和一些桌面内核的默认设置，其中吞吐量比响应性更重要。

第二个选项启用了更明确的抢占点，如果设置了`need_resched`标志，则调用调度程序，这会以略微降低吞吐量的代价减少最坏情况的抢占延迟。一些发行版在桌面上设置了这个选项。

第三个选项使内核可抢占，这意味着中断可以导致立即重新调度，只要内核不在原子上下文中执行，我将在下一节中描述。这减少了最坏情况的抢占延迟，因此，总体调度延迟在典型嵌入式硬件上大约为几毫秒。这通常被描述为软实时选项，大多数嵌入式内核都是以这种方式配置的。当然，总体吞吐量会有所减少，但这通常不如对嵌入式设备具有更确定的调度重要。

# 实时 Linux 内核（PREEMPT_RT）

长期以来一直在努力进一步减少延迟，这个努力被称为内核配置选项的名称为这些功能，`PREEMPT_RT`。该项目由 Ingo Molnar、Thomas Gleixner 和 Steven Rostedt 发起，并多年来得到了许多其他开发人员的贡献。内核补丁位于[`www.kernel.org/pub/linux/kernel/projects/rt`](https://www.kernel.org/pub/linux/kernel/projects/rt)，并且有一个维基，包括一个 FAQ（略有过时），位于[`rt.wiki.kernel.org`](https://rt.wiki.kernel.org)。

多年来，项目的许多部分已经并入了主线 Linux，包括高分辨率定时器、内核互斥锁和线程中断处理程序。然而，核心补丁仍然留在主线之外，因为它们相当具有侵入性，而且（有人声称）只有很小一部分 Linux 用户受益。也许，有一天，整个补丁集将被合并到上游。

中央计划是减少内核在原子上下文中运行的时间，这是不安全调用调度程序并切换到不同线程的地方。典型的原子上下文是内核：

+   正在运行中断或陷阱处理程序

+   持有自旋锁或处于 RCU 临界区。自旋锁和 RCU 是内核锁原语，这里的细节并不相关

+   在调用`preempt_disable()`和`preempt_enable()`之间

+   硬件中断被禁用

`PREEMPT_RT`的更改分为两个主要领域：一个是通过将中断处理程序转换为内核线程来减少中断处理程序的影响，另一个是使锁可抢占，以便线程在持有锁的同时可以休眠。很明显，这些更改会带来很大的开销，这使得平均情况下中断处理变慢，但更加确定，这正是我们所追求的。

# 线程中断处理程序

并非所有中断都是实时任务的触发器，但所有中断都会从实时任务中窃取周期。线程中断处理程序允许将优先级与中断关联，并在适当的时间进行调度，如下图所示：

![线程中断处理程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_14_02.jpg)

如果中断处理程序代码作为内核线程运行，那么它就没有理由不被优先级更高的用户空间线程抢占，因此中断处理程序不会增加用户空间线程的调度延迟。自 2.6.30 版起，分线程中断处理程序已成为主线 Linux 的特性。您可以通过使用`request_threaded_irq()`注册单个中断处理程序来请求将其作为线程化，而不是使用普通的`request_irq()`。您可以通过配置内核使所有处理程序成为线程，将分线程中断设置为默认值`CONFIG_IRQ_FORCED_THREADING=y`，除非它们通过设置`IRQF_NO_THREAD`标志明确阻止了这一点。当您应用`PREEMPT_RT`补丁时，默认情况下会将中断配置为线程。以下是您可能看到的示例：

```
# ps -Leo pid,tid,class,rtprio,stat,comm,wchan | grep FF
PID     TID     CLS     RTPRIO  STAT    COMMAND          WCHAN
3       3       FF      1       S      ksoftirqd/0      smpboot_th
7       7       FF      99      S      posixcputmr/0    posix_cpu_
19      19      FF      50      S      irq/28-edma      irq_thread
20      20      FF      50      S      irq/30-edma_err  irq_thread
42      42      FF      50      S      irq/91-rtc0      irq_thread
43      43      FF      50      S      irq/92-rtc0      irq_thread
44      44      FF      50      S      irq/80-mmc0      irq_thread
45      45      FF      50      S      irq/150-mmc0     irq_thread
47      47      FF      50      S      irq/44-mmc1      irq_thread
52      52      FF      50      S      irq/86-44e0b000  irq_thread
59      59      FF      50      S      irq/52-tilcdc    irq_thread
65      65      FF      50      S      irq/56-4a100000  irq_thread
66      66      FF      50      S      irq/57-4a100000  irq_thread
67      67      FF      50      S      irq/58-4a100000  irq_thread
68      68      FF      50      S      irq/59-4a100000  irq_thread
76      76      FF      50      S      irq/88-OMAP UAR  irq_thread

```

在这种情况下，运行`linux-yocto-rt`的 BeagleBone 只有`gp_timer`中断没有被线程化。定时器中断处理程序以内联方式运行是正常的。

### 注意

请注意，中断线程都已被赋予默认策略`SCHED_FIFO`和优先级`50`。然而，将它们保留为默认值是没有意义的；现在是您根据中断的重要性与实时用户空间线程相比分配优先级的机会。

以下是建议的降序线程优先级顺序：

+   POSIX 计时器线程`posixcputmr`应始终具有最高优先级。

+   与最高优先级实时线程相关的硬件中断。

+   最高优先级的实时线程。

+   逐渐降低优先级的实时线程的硬件中断，然后是线程本身。

+   非实时接口的硬件中断。

+   软中断守护程序`ksoftirqd`，在 RT 内核上负责运行延迟中断例程，并且在 Linux 3.6 之前负责运行网络堆栈、块 I/O 层和其他内容。您可能需要尝试不同的优先级级别以获得平衡。

您可以使用`chrt`命令作为引导脚本的一部分来更改优先级，使用类似以下的命令：

```
# chrt -f -p 90 `pgrep irq/28-edma`

```

`pgrep`命令是`procps`软件包的一部分。

# 可抢占内核锁

使大多数内核锁可抢占是`PREEMPT_RT`所做的最具侵入性的更改，这段代码仍然在主线内核之外。

问题出现在自旋锁上，它们用于大部分内核锁定。自旋锁是一种忙等待互斥锁，在争用情况下不需要上下文切换，因此只要锁定时间很短，它就非常高效。理想情况下，它们应该被锁定的时间少于两次重新调度所需的时间。以下图表显示了在两个不同 CPU 上运行的线程争用相同自旋锁的情况。**CPU0**首先获得它，迫使**CPU1**自旋，等待直到它被解锁：

![可抢占内核锁](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_14_03.jpg)

持有自旋锁的线程不能被抢占，因为这样做可能会使新线程进入相同的代码并在尝试锁定相同自旋锁时发生死锁。因此，在主线 Linux 中，锁定自旋锁会禁用内核抢占，创建原子上下文。这意味着持有自旋锁的低优先级线程可以阻止高优先级线程被调度。

### 注意

`PREEMPT_RT`采用的解决方案是用 rt-mutexes 几乎替换所有自旋锁。互斥锁比自旋锁慢，但是完全可抢占。不仅如此，rt-mutexes 实现了优先级继承，因此不容易发生优先级反转。

# 获取 PREEMPT_RT 补丁

RT 开发人员不会为每个内核版本创建补丁集，因为这需要大量的工作。平均而言，他们为每个其他内核创建补丁。在撰写本文时支持的最新内核版本如下：

+   4.1-rt

+   4.0-rt

+   3.18-rt

+   3.14-rt

+   3.12-rt

+   3.10-rt

这些补丁可以在[`www.kernel.org/pub/linux/kernel/projects/rt`](https://www.kernel.org/pub/linux/kernel/projects/rt)上找到。

如果您正在使用 Yocto 项目，那么内核已经有了`rt`版本。否则，您获取内核的地方可能已经应用了`PREEMPT_RT`补丁。否则，您将不得不自己应用补丁。首先确保`PREEMPT_RT`补丁版本与您的内核版本完全匹配，否则您将无法干净地应用补丁。然后按照正常方式应用，如下所示：

```
$ cd linux-4.1.10
$ zcat patch-4.1.10-rt11.patch.gz | patch -p1

```

然后，您将能够使用`CONFIG_PREEMPT_RT_FULL`配置内核。

最后一段有一个问题。RT 补丁只有在使用兼容的主线内核时才会应用。您可能不会使用兼容的内核，因为这是嵌入式 Linux 内核的特性，因此您将不得不花一些时间查看失败的补丁并修复它们，然后分析您的目标的板支持并添加任何缺失的实时支持。这些细节再次超出了本书的范围。如果您不确定该怎么做，您应该向您正在使用的内核的开发人员和内核开发人员论坛咨询。

## Yocto 项目和 PREEMPT_RT

Yocto 项目提供了两个标准的内核配方：`linux-yocto`和`linux-yoco-rt`，后者已经应用了实时补丁。假设您的目标受到这些内核的支持，那么您只需要选择`linux-yocto-rt`作为首选内核，并声明您的设备兼容，例如，通过向您的`conf/local.conf`添加类似以下的行：

```
PREFERRED_PROVIDER_virtual/kernel = "linux-yocto-rt"
COMPATIBLE_MACHINE_beaglebone = "beaglebone"
```

# 高分辨率定时器

如果您有精确的定时要求，这在实时应用程序中很典型，那么定时器分辨率就很重要。Linux 中的默认定时器是以可配置速率运行的时钟，嵌入式系统通常为 100 赫兹，服务器和台式机通常为 250 赫兹。两个定时器滴答之间的间隔称为**jiffy**，在上面的示例中，嵌入式 SoC 上为 10 毫秒，服务器上为 4 毫秒。

Linux 在 2.6.18 版本中从实时内核项目中获得了更精确的定时器，现在它们在所有平台上都可用，只要有高分辨率定时器源和设备驱动程序——这几乎总是如此。您需要使用`CONFIG_HIGH_RES_TIMERS=y`配置内核。

启用此功能后，所有内核和用户空间时钟都将准确到基础硬件的粒度。找到实际的时钟粒度很困难。显而易见的答案是`clock_getres(2)`提供的值，但它总是声称分辨率为一纳秒。我将在后面描述的`cyclictest`工具有一个选项，用于分析时钟报告的时间以猜测分辨率：

```
# cyclictest -R
# /dev/cpu_dma_latency set to 0us
WARN: reported clock resolution: 1 nsec
WARN: measured clock resolution approximately: 708 nsec
You can also look at the kernel log messages for strings like this:
# dmesg | grep clock
OMAP clockevent source: timer2 at 24000000 Hz
sched_clock: 32 bits at 24MHz, resolution 41ns, wraps every 178956969942ns
OMAP clocksource: timer1 at 24000000 Hz
Switched to clocksource timer1

```

这两种方法给出了不同的数字，我无法给出一个好的解释，但由于两者都低于一微秒，我很满意。

# 在实时应用程序中避免页面错误

当应用程序读取或写入未提交到物理内存的内存时，会发生页面错误。不可能（或者非常困难）预测何时会发生页面错误，因此它们是计算机中另一个非确定性的来源。

幸运的是，有一个函数可以让您为进程提交所有内存并将其锁定，以便它不会引起页面错误。这就是`mlockall(2)`。这是它的两个标志：

+   `MCL_CURRENT`：锁定当前映射的所有页面

+   `MCL_FUTURE`：锁定稍后映射的页面

通常在应用程序启动时调用`mlockall(2)`，同时设置两个标志以锁定所有当前和未来的内存映射。

### 提示

请注意，`MCL_FUTURE`并不是魔法，使用`malloc()/free()`或`mmap()`分配或释放堆内存时仍会存在非确定性延迟。这些操作最好在启动时完成，而不是在主控循环中完成。

在堆栈上分配的内存更加棘手，因为它是自动完成的，如果您调用一个使堆栈比以前更深的函数，您将遇到更多的内存管理延迟。一个简单的解决方法是在启动时将堆栈增大到比您预期需要的更大的尺寸。代码看起来像这样：

```
#define MAX_STACK (512*1024)
static void stack_grow (void)
{
  char dummy[MAX_STACK];
  memset(dummy, 0, MAX_STACK);
  return;
}

int main(int argc, char* argv[])
{
  [...]
  stack_grow ();
  mlockall(MCL_CURRENT | MCL_FUTURE);
  [...]
```

`stack_grow()`函数在堆栈上分配一个大变量，然后将其清零，以强制将这些内存页分配给该进程。

# 中断屏蔽

使用线程化中断处理程序有助于通过以比不影响实时任务的中断处理程序更高的优先级运行一些线程来减轻中断开销。如果您使用多核处理器，您可以采取不同的方法，完全屏蔽一个或多个核心的处理中断，从而使它们专用于实时任务。这适用于普通的 Linux 内核或`PREEMPT_RT`内核。

实现这一点的关键是将实时线程固定到一个 CPU，将中断处理程序固定到另一个 CPU。您可以使用命令行工具`taskset`设置线程或进程的 CPU 亲和性，也可以使用`sched_setaffinity(2)`和`pthread_setaffinity_np(3)`函数。

要设置中断的亲和性，首先注意`/proc/irq/<IRQ number>`中有每个中断号的子目录。其中包括中断的控制文件，包括`smp_affinity`中的 CPU 掩码。向该文件写入一个位掩码，其中每个允许处理该 IRQ 的 CPU 都设置了一个位。

# 测量调度延迟

您可能进行的所有配置和调整都将是无意义的，如果您不能证明您的设备满足截止日期。最终测试需要您自己的基准测试，但我将在这里描述两个重要的测量工具：`cyclictest`和`Ftrace`。

## cyclictest

`cyclictest` 最初由 Thomas Gleixner 编写，现在在大多数平台上都可以在名为`rt-tests`的软件包中使用。如果您使用 Yocto Project，可以通过构建实时镜像配方来创建包含`rt-tests`的目标镜像，方法如下：

```
$ bitbake core-image-rt

```

如果您使用 Buildroot，您需要在菜单**目标软件包** | **调试、性能分析和基准测试** | **rt-tests**中添加软件包`BR2_PACKAGE_RT_TESTS`。

`cyclictest` 通过比较实际休眠所需的时间和请求的时间来测量调度延迟。如果没有延迟，它们将是相同的，报告的延迟将为零。`cyclictest` 假设定时器分辨率小于一微秒。

它有大量的命令行选项。首先，您可以尝试在目标上以 root 身份运行此命令：

```
# cyclictest -l 100000 -m -n -p 99
# /dev/cpu_dma_latency set to 0us
policy: fifo: loadavg: 1.14 1.06 1.00 1/49 320

T: 0 (  320) P:99 I:1000 C: 100000 Min:  9 Act:  13 Avg:  15 Max:  134

```

所选的选项如下：

+   `-l N`: 循环 N 次：默认为无限

+   `-m`: 使用 mlockall 锁定内存

+   `-n`: 使用`clock_nanosleep(2)`而不是`nanosleep(2)`

+   `-p N`: 使用实时优先级`N`

结果行从左到右显示以下内容：

+   `T: 0`: 这是线程 0，这次运行中唯一的线程。您可以使用参数`-t`设置线程数。

+   `(320)`: 这是 PID 320。

+   `P:99`: 优先级为 99。

+   `I:1000`: 循环之间的间隔为 1,000 微秒。您可以使用参数`-i N`设置间隔。

+   `C:100000`: 该线程的最终循环计数为 100,000。

+   `Min: 9`: 最小延迟为 9 微秒。

+   `Act:13`: 实际延迟为 13 微秒。实际延迟是最近的延迟测量，只有在观察`cyclictest`运行时才有意义。

+   `Avg:15`: 平均延迟为 15 微秒。

+   `Max:134`: 最大延迟为 134 微秒。

这是在运行未修改的`linux-yocto`内核的空闲系统上获得的，作为该工具的快速演示。要真正有用，您需要在运行负载代表您期望的最大负载的同时，进行 24 小时或更长时间的测试。

`cyclictest`生成的数字中，最大延迟是最有趣的，但了解值的分布也很重要。您可以通过添加`-h <N>`来获得最多迟到`N`微秒的样本的直方图。使用这种技术，我在相同的目标板上运行了没有抢占、标准抢占和 RT 抢占的内核，同时通过洪水 ping 加载以太网流量，获得了三个跟踪。命令行如下所示：

```
# cyclictest -p 99 -m -n -l 100000 -q -h 500 > cyclictest.data

```

以下是没有抢占生成的输出：

![cyclictest](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_14_04.jpg)

没有抢占时，大多数样本在截止日期之前 100 微秒内，但有一些离群值高达 500 微秒，这基本上是您所期望的。

这是使用标准抢占生成的输出：

![cyclictest](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_14_05.jpg)

有抢占时，样本在较低端分布，但没有超过 120 微秒的情况。

这是使用 RT 抢占生成的输出：

![cyclictest](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_14_06.jpg)

RT 内核是明显的赢家，因为一切都紧密地集中在 20 微秒左右，没有超过 35 微秒的情况。

因此，`cyclictest`是调度延迟的标准度量。但它无法帮助您识别和解决内核延迟的特定问题。为此，您需要`Ftrace`。

## 使用 Ftrace

内核函数跟踪器有跟踪器可帮助跟踪内核延迟，这也是它最初编写的目的。这些跟踪器捕获了在运行过程中检测到的最坏情况延迟的跟踪，显示导致延迟的函数。感兴趣的跟踪器以及内核配置参数如下：

+   `irqsoff`：`CONFIG_IRQSOFF_TRACER`跟踪禁用中断的代码，记录最坏情况

+   `preemptoff`：`CONFIG_PREEMPT_TRACER`类似于`irqsoff`，但跟踪内核抢占被禁用的最长时间（仅适用于可抢占内核）

+   `preemptirqsoff`：它结合了前两个跟踪，记录了禁用`irqs`和/或抢占的最长时间

+   `wakeup`：跟踪并记录唤醒后最高优先级任务被调度所需的最大延迟

+   `wakeup_rt`：与唤醒相同，但仅适用于具有`SCHED_FIFO`、`SCHED_RR`或`SCHED_DEADLINE`策略的实时线程

+   `wakeup_dl`：与唤醒相同，但仅适用于具有`SCHED_DEADLINE`策略的截止线程

请注意，运行`Ftrace`会增加大量延迟，每次捕获新的最大值时，`Ftrace`本身可以忽略。但是，它会扭曲用户空间跟踪器（如`cyclictest`）的结果。换句话说，如果您在捕获跟踪时运行`cyclictest`，请忽略其结果。

选择跟踪器与我们在第十三章中看到的函数跟踪器相同，*性能分析和跟踪*。以下是捕获禁用抢占的最长时间的跟踪 60 秒的示例：

```
# echo preemptoff > /sys/kernel/debug/tracing/current_tracer
# echo 0 > /sys/kernel/debug/tracing/tracing_max_latency
# echo 1  > /sys/kernel/debug/tracing/tracing_on
# sleep 60
# echo 0  > /sys/kernel/debug/tracing/tracing_on

```

生成的跟踪，经过大量编辑，看起来像这样：

```
# cat /sys/kernel/debug/tracing/trace
# tracer: preemptoff
#
# preemptoff latency trace v1.1.5 on 3.14.19-yocto-standard
# --------------------------------------------------------------------
# latency: 1160 us, #384/384, CPU#0 | (M:preempt VP:0, KP:0, SP:0 HP:0)
#    -----------------
#    | task: init-1 (uid:0 nice:0 policy:0 rt_prio:0)
#    -----------------
#  => started at: ip_finish_output
#  => ended at:   __local_bh_enable_ip
#
#
#                  _------=> CPU#
#                 / _-----=> irqs-off
#                | / _----=> need-resched
#                || / _---=> hardirq/softirq
#                ||| / _--=> preempt-depth
#                |||| /     delay
#  cmd     pid   ||||| time  |   caller
#     \   /      |||||  \    |   /
 init-1       0..s.    1us+: ip_finish_output
 init-1       0d.s2   27us+: preempt_count_add <-cpdma_chan_submit
 init-1       0d.s3   30us+: preempt_count_add <-cpdma_chan_submit
 init-1       0d.s4   37us+: preempt_count_sub <-cpdma_chan_submit

[...]

 init-1       0d.s2 1152us+: preempt_count_sub <-__local_bh_enable
 init-1       0d..2 1155us+: preempt_count_sub <-__local_bh_enable_ip
 init-1       0d..1 1158us+: __local_bh_enable_ip
 init-1       0d..1 1162us!: trace_preempt_on <-__local_bh_enable_ip
 init-1       0d..1 1340us : <stack trace>

```

在这里，您可以看到在运行跟踪时禁用内核抢占的最长时间为 1,160 微秒。通过阅读`/sys/kernel/debug/tracing/tracing_max_latency`，可以获得这个简单的事实，但上面的跟踪进一步提供了导致该测量的内核函数调用序列。标记为`delay`的列显示了每个函数被调用的时间，最后一次调用是在`1162us`时的`trace_preempt_on()`，在这一点上内核抢占再次被启用。有了这些信息，您可以回顾调用链，并（希望）弄清楚这是否是一个问题。

提到的其他跟踪器工作方式相同。

## 结合 cyclictest 和 Ftrace

如果`cyclictest`报告出现意外长的延迟，您可以使用`breaktrace`选项中止程序并触发`Ftrace`以获取更多信息。

您可以使用`-b<N>`或`--breaktrace=<N>`来调用 breaktrace，其中`N`是将触发跟踪的延迟的微秒数。您可以使用`-T[tracer name]`或以下之一选择`Ftrace`跟踪器：

+   `-C`：上下文切换

+   `-E`：事件

+   -`f`：函数

+   `-w`：唤醒

+   `-W`：唤醒-rt

例如，当测量到大于 100 微秒的延迟时，这将触发`Ftrace`函数跟踪器：

```
# cyclictest -a -t -n -p99 -f -b100

```

# 进一步阅读

以下资源提供了有关本章介绍的主题的更多信息：

+   *硬实时计算系统：可预测的调度算法和应用*，作者*Buttazzo*，*Giorgio*，*Springer*，2011

+   *多核应用程序编程*，作者*Darryl Gove*，*Addison Wesley*，2011

# 总结

实时这个术语是没有意义的，除非您用截止日期和可接受的错过率来限定它。当您知道这一点时，您可以确定 Linux 是否适合作为操作系统的候选，并且开始调整系统以满足要求。调整 Linux 和您的应用程序以处理实时事件意味着使其更具确定性，以便它可以在截止日期内可靠地处理数据。确定性通常是以总吞吐量为代价的，因此实时系统无法处理与非实时系统一样多的数据。

不可能提供数学证明，证明像 Linux 这样的复杂操作系统总是能满足给定的截止日期，因此唯一的方法是通过使用`cyclictest`和`Ftrace`等工具进行广泛测试，更重要的是使用您自己的应用程序的基准测试。

为了提高确定性，您需要考虑应用程序和内核。在编写实时应用程序时，您应该遵循本章关于调度、锁定和内存的指导方针。

内核对系统的确定性有很大影响。幸运的是，多年来已经进行了大量工作。启用内核抢占是一个很好的第一步。如果您发现它错过截止日期的频率比您想要的要高，那么您可能需要考虑`PREEMPT_RT`内核补丁。它们确实可以产生低延迟，但它们尚未纳入主线内核，这意味着您可能在将它们与特定板子的供应商内核集成时遇到问题。您可能需要使用`Ftrace`和类似工具来找出延迟的原因。

这就是我对嵌入式 Linux 的剖析的结束。作为嵌入式系统工程师需要具备广泛的技能，从对硬件的低级了解，系统引导程序的工作原理以及内核与其交互的方式，到成为一个能够配置用户应用程序并调整其以高效方式运行的优秀系统工程师。所有这些都必须在几乎总是只能胜任任务的硬件上完成。有一句话概括了这一切，“一个工程师可以用一美元做到别人用两美元才能做到的事情”。我希望您能够通过我在本书中提供的信息实现这一点。
