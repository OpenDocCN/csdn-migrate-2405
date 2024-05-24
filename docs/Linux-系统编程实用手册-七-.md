# Linux 系统编程实用手册（七）

> 原文：[`zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320`](https://zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：使用 Pthreads 进行多线程编程第一部分 - 基础知识

你是否使用过下载加速器类型的应用程序下载过大文件？你玩过在线游戏吗？飞行模拟器程序？使用过文字处理、网页浏览器、Java 应用程序等等？（在这里放一个笑脸表情的诱惑很高！）

很可能你至少使用过其中一些；那又怎样呢？所有这些不同的应用程序有一个共同点：它们很可能都是为多线程设计的，这意味着它们的实现使用多个线程并行运行。多线程确实已经成为现代程序员几乎是一种生活方式。

解释一个像多线程这样庞大的话题本身就是一项艰巨的任务；因此我们将其分成三个单独的章节进行覆盖。这是其中的第一章。

本章本身在逻辑上分为两个广泛的部分：在第一部分中，我们仔细考虑并理解线程模型背后的概念——多线程的“什么”和“为什么”。线程到底是什么，我们为什么需要线程，以及多线程在 Linux 平台上是如何发展的一个快速了解。

在第二部分中，我们将重点关注 Linux 上多线程的线程管理 API，即多线程的“如何”（在某种程度上）。我们将讨论创建和管理线程所需的 API 集合，并且当然会有很多实际的代码可以看到和尝试。

在这个话题的开始，我们还必须明确指出这样一个事实，即在本书中，我们只关注软件编程的多线程；特别是在 Linux 平台上的 POSIX 线程（pthreads）实现，具体来说是 Linux 平台上的 pthreads。我们不打算处理其他各种出现的多线程框架和实现（如 MPI、OpenMP、OpenCL 等）或硬件线程（超线程、具有 CUDA 的 GPU 等）。

在本章中，你将学习如何在 Linux 平台上使用多个线程进行编程，具体来说，是如何开始使用 pthread 编程模型或框架。本章大致分为两部分：

+   在第一部分，涵盖了关键的多线程概念——多线程的“什么”和“为什么”，为第二部分（以及后面两章关于多线程的内容）奠定了基础。

+   第二部分涵盖了在 Linux 上构建功能性多线程应用程序所需的基本 pthread API（它故意没有涵盖所有方面；接下来的两章将在此基础上展开）。

# 多线程概念

在本节中，我们将学习在 Linux 平台上多线程的“什么”和“为什么”。我们将从回答“线程到底是什么？”这个常见问题开始。

# 线程到底是什么？

在古老的 Unix 程序员的好（或坏？）旧日子里，有一个简单的软件模型（其他操作系统和供应商几乎完全继承了这个模型）：有一个存在于虚拟地址空间（VAS）中的进程；VAS 本质上由称为段的同质区域（基本上是虚拟页面的集合）组成：文本、数据、其他映射（库）和栈。文本实际上是可执行的——事实上是机器——代码，它被馈送到处理器。我们在本书的早期部分已经涵盖了所有这些内容（你可以在第二章《虚拟内存》中复习这些基础知识）。

线程是进程内部的独立执行（或流）路径。在线程的生命周期和范围中，在我们通常使用的熟悉的过程式编程范式中，它只是一个函数。

因此，在我们之前提到的传统模型中，我们有一个执行线程；在 C 编程范式中，该线程是`main()`函数！想想看：`main()`线程是执行开始（至少从应用程序开发者的角度来看）和结束的地方。这个模型现在被称为单线程软件模型。与之相对的是什么？当然是多线程模型。所以，我们可以有多个线程与同一进程中的其他独立线程同时执行（并行）。

但是，等等，进程难道也不能产生并行性，并且在应用程序的不同方面上有多个副本在工作吗？当然可以：我们已经在第十章中以所有的荣耀（和影响）介绍了`fork(2)`系统调用。这被称为多进程模型。因此，如果我们有多进程——在这里，有几个进程并行运行，并且完成了工作——百万美元的问题就变成了：“为什么还要使用多线程？”（请存入一百万美元，我们将提供答案。）有几个很好的理由；请查看接下来的章节（特别是*动机-为什么要使用线程？*；我们建议第一次读者按照本书中所规定的顺序进行阅读）以获取更多细节。

# 资源共享

在第十章中，*进程创建*，我们反复指出，虽然 fork(2)系统调用非常强大和有用，但它被认为是一种重量级操作；执行 fork 需要大量的 CPU 周期（因此需要时间），而且在内存（RAM）方面也很昂贵。计算机科学家们正在寻找一种减轻这种情况的方法；结果，正如你所猜到的那样，就是线程。

不过，为了方便读者，我们在这里重现了一个图表——*Linux 进程-在 fork()中的继承和非继承*——来自第十章，*进程创建*：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/8beb0e4e-7a50-43a7-a15e-f07976f2cf65.png)

图 1：Linux 进程-在 fork()中的继承和非继承

这个图表很重要，因为它向我们展示了为什么 fork 是一种重量级操作：每次调用 fork(2)系统调用时，父进程的完整虚拟地址空间和图表右侧的所有数据结构都必须被复制到新生的子进程中。这确实是很多工作和内存使用！（好吧，我们有点夸张：正如在第十章中所提到的，*进程创建*，*现代操作系统，特别是 Linux，确实费了很多功夫来优化 fork。尽管如此，它还是很重的。请查看我们的示例 1 演示程序，进程的创建和销毁比线程的创建和销毁要慢得多（并且需要更多的 RAM）。

事实是这样的：当一个进程创建一个线程时，该线程与同一进程的所有其他线程（几乎）共享所有内容——包括之前的虚拟地址空间、段和所有数据结构——除了栈。

每个线程都有自己的私有堆栈段。它位于哪里？显然，它位于创建进程的虚拟地址空间内；它确切地位于哪里对我们来说并不重要（回想一下，无论如何都是虚拟内存，而不是物理内存）。对应用程序开发人员来说，更相关和重要的问题是线程堆栈的大小。简短的答案是：与通常一样（在 Linux 平台上通常为 8MB），但我们将在本章后面详细介绍细节。只需这样想：`main()`的堆栈总是位于（用户模式）虚拟地址空间的顶部；进程中其余线程的堆栈通常位于该空间中的任何位置。实际上，它们通常位于堆和（main 的）堆栈之间的虚拟内存空间中。

以下图表帮助我们了解 Linux 上多线程进程的内存布局；图表的上部是`pthread_create(3)`之前的进程；下部显示了成功创建线程后的进程：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/8f2b1600-8814-4675-988c-45739f349fd6.png)

图 2：线程-除了堆栈之外，一切都在 pthread_create()中共享

进程文本段中的蓝色波浪线代表`main()`线程；它的堆栈也清晰可见。我们使用虚线表示所有这些内存对象（用户空间和内核空间）都在`pthread_create(3)`中被共享。显然可以看到，在`pthread_create(3)`之后，唯一的新对象是新线程本身（**thrd2**；在进程文本段中显示为红色波浪线）和刚刚创建的线程**thrd2**的新堆栈（红色）。将此图与*图 1*进行对比；当我们进行`fork(2)`时，几乎所有东西都必须复制到新生的子进程中。

到目前为止，我们描述的唯一区别是进程和线程之间的资源共享——进程不共享，它们复制；线程共享一切，除了堆栈。再深入一点，你会意识到软件和硬件状态都必须以每个线程为基础进行维护。Linux 操作系统正是这样做的：它在操作系统内部维护了一个每个线程的任务结构；任务结构包含所有进程/线程属性，包括软件和硬件上下文（CPU 寄存器值等）信息。

再深入挖掘一下，我们意识到操作系统确实会为每个线程维护以下属性的独立副本：堆栈段（因此堆栈指针）、可能的备用信号堆栈（在第十一章中介绍，*信号-第一部分*）、常规信号和实时信号掩码、线程 ID、调度策略和优先级、能力位、CPU 亲和性掩码以及 errno 值（不用担心，这些中的几个将在后面解释）。

# 多进程与多线程

为了清楚地理解为什么和如何线程可以提供性能优势，让我们进行一些实验！（实证的重要性-实验，尝试-是一个关键特征；我们的第十九章，*故障排除和最佳实践*，更多涵盖了这些内容）。首先，我们进行两个简单示例程序的比较：一个是比较创建和销毁进程与线程的程序，另一个是以两种方式进行矩阵乘法运算的程序——一种是传统的单线程进程模型，另一种是多线程模型。

因此，我们在这里真正比较的是使用多进程模型和多线程模型的执行时间性能。我们要请读者注意，我们现在不会费力详细解释线程代码的原因有两个：一是这不是重点，二是在我们详细介绍线程 API 之前，这样做没有意义。（因此，亲爱的读者，我们要求你暂时忽略线程代码；只需跟着我们，构建和重现我们在这里做的事情；随着你的学习，代码和 API 将变得清晰。）

# 示例 1 - 创建/销毁 - 进程/线程

进程模型：我们的做法是：在一个循环中（总共执行了 60,000 次！），通过调用`fork(2)`创建和销毁进程，然后退出。（我们处理了一些细节，比如在父进程中等待子进程死亡，以清除任何可能的僵尸进程，然后继续循环。）相关的代码如下（`ch14/speed_multiprcs_vs_multithrd_simple/create_destroy/fork_test.c`）：

为了便于阅读，以下代码中只显示了相关部分；要查看和运行完整的源代码，可以在这里找到：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
...
#define NFORKS 60000
void do_nothing()
{
  unsigned long f = 0xb00da;
}
int main(void)
{
  int pid, j, status;

  for (j = 0; j < NFORKS; j++) {
        switch (pid = fork()) {
        case -1:
              FATAL("fork failed! [%d]\n", pid);
        case 0: // Child process
              do_nothing();
              exit(EXIT_SUCCESS);
        default: // Parent process
              waitpid(pid, &status, 0);
        }
  }
  exit(EXIT_SUCCESS);
}
```

我们在`time(1)`实用程序的前缀下运行它，这给了我们一个程序在处理器上花费的时间的大致概念；花费的时间显示为三个组成部分：`real`（总的挂钟时间），`user`（用户空间中花费的时间）和`sys`（内核空间中花费的时间）：

```
$ time ./fork_test 

real    0m10.993s
user    0m7.436s
sys     0m2.969s
$ 
```

显然，你在 Linux 系统上得到的确切数值可能会有所不同。而且，`user` + `sys`的总和也不会完全等于 real。

# 多线程模型

再次强调，我们的做法是：关键是要理解这里使用的代码（`ch14/speed_multiprcs_vs_multithrd_simple/create_destroy/pthread_test.c`）在所有方面都与前面的代码相同，只是这里我们使用线程而不是进程：在一个循环中（总共执行了 60,000 次！），通过调用`pthread_create(3)`创建和销毁线程，然后通过调用`pthread_exit(3)`退出。（我们处理了一些细节，比如在调用线程中等待兄弟线程终止，通过调用`pthread_join(3)`。）如前所述，让我们暂时跳过代码/API 的细节，只看执行情况：

```
$ time ./pthread_test 

real    0m3.584s
user    0m0.379s
sys     0m2.704s
$ 
```

哇，线程化的代码运行速度大约比进程模型的代码快 3 倍！结论很明显：创建和销毁线程比创建和销毁进程要快得多。

技术方面的一点说明：对于更好奇的极客：为什么`fork(2)`比`pthread_create(3)`慢得多？熟悉操作系统开发的人会明白，Linux 在`fork(2)`的内部实现中大量使用了性能增强的**写时复制**（COW）内存技术。因此，问题是，如果 COW 被大量使用，那么是什么使 fork 变慢？简短的答案是：页表的创建和设置不能进行 COW；这需要一段时间。当创建同一进程的线程时，这项工作（页表设置）完全被跳过。

即便如此，Linux 的 fork 在今天任何可比较的操作系统中都被认为是最快的。

另外，衡量花费的时间和性能特征的一种更准确的方法是使用众所周知的`perf(1)`实用程序（请注意，在本书中，我们不打算详细介绍`perf`；如果感兴趣，请查看 GitHub 存储库的*进一步阅读*部分，其中有一些与`perf`相关的链接）：

```
$ perf stat ./fork_test

 Performance counter stats for './fork_test':

       9054.969497 task-clock (msec)      # 0.773 CPUs utilized 
            61,245 context-switches       # 0.007 M/sec 
               202 cpu-migrations         # 0.022 K/sec 
         15,00,063 page-faults            # 0.166 M/sec 
   <not supported> cycles 
   <not supported> instructions 
   <not supported> branches 
   <not supported> branch-misses 

      11.714134973 seconds time elapsed
$ 
```

正如前面的代码所示，在虚拟机上，当前版本的`perf`不能显示所有的计数器；这在这里并不妨碍我们，因为我们真正关心的是执行所花费的最终时间——这显示在`perf`输出的最后一行中。

以下代码显示了多线程应用程序的`perf(1)`：

```
$ perf stat ./pthread_test

 Performance counter stats for './pthread_test':

       2377.866371 task-clock (msec)        # 0.587 CPUs utilized 
            60,887 context-switches         # 0.026 M/sec 
               117 cpu-migrations           # 0.049 K/sec 
                69 page-faults              # 0.029 K/sec 
   <not supported> cycles 
   <not supported> instructions 
   <not supported> branches 
   <not supported> branch-misses 

       4.052964938 seconds time elapsed
$ 
```

对于感兴趣的读者，我们还提供了一个包装脚本（`ch14/speed_multiprcs_vs_multithrd_simple/create_destroy/perf_runs.sh`），允许用户使用`perf(1)`进行记录和报告会话。

# 示例 2-矩阵乘法-进程/线程

一个众所周知的练习是编写一个计算两个给定矩阵的（点）积的程序。基本上，我们想执行以下操作：

`矩阵 C = 矩阵 A * 矩阵 B`

再次强调的是，我们在这里实际上并不关心算法（和代码）的细节；我们关心的是在设计层面上如何执行矩阵乘法。我们提出（并编写相应的代码）两种方法：

+   按顺序，通过单线程模型

+   同时，通过多线程模型

注意：这些算法或代码都不打算是原创或突破性的；这些都是众所周知的程序。

在第一个模型中，一个线程-当然是`main()`-将运行并执行计算；程序可以在这里找到：`ch14/speed_multiprcs_vs_multithrd_simple/matrixmul/prcs_matrixmul.c`。

其次，我们将在目标系统上创建至少与 CPU 核心数相同的线程，以充分利用硬件（这个方面在本章的后面一节中处理，名为*你可以创建多少线程？*）；每个线程将与其他线程并行执行一部分计算。程序可以在这里找到：`ch14/speed_multiprcs_vs_multithrd_simple/matrixmul/thrd_matrixmul.c`。

在多线程版本中，目前，我们只是在代码中硬编码 CPU 核心数为四，因为它与我们的本机 Linux 测试系统之一匹配。

为了真正了解我们的应用程序的进程和/或线程如何实际消耗 CPU 带宽，让我们使用有趣的`gnome-system-monitor` GUI 应用程序以图形方式查看资源消耗！（要运行它，假设已安装，只需在 shell 上键入`$ gnome-system-monitor＆`）。

我们提醒您，所有软件和硬件要求都已在本书的 GitHub 存储库上提供的软件硬件清单材料中详细列出。

我们将按以下方式进行实验：

1.  在具有四个 CPU 核心的本机 Linux 系统上运行应用程序：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/e3a13cd1-66d2-48a1-b3ef-527f115b79ef.png)

仔细看前面的（带注释的）屏幕截图（如果您正在阅读电子版本，请放大）；我们会注意到几个有趣的项目：

+   在前台是我们运行`prcs_matrixmul`和`thrd_matrixmul`应用程序的终端窗口应用程序：

+   我们使用`perf(1)`来准确测量所花费的时间，并故意过滤除了执行期间经过的最终秒数之外的所有输出。

+   在背景中，您可以看到正在运行的`gnome-system-monitor` GUI 应用程序。

+   （本机 Linux）系统-我们已经在其上进行了测试-有四个 CPU 核心：

+   找到系统上 CPU 核心数量的一种方法是使用以下代码：`getconf -a | grep _NPROCESSORS_ONLN | awk '{print $2}'`

（您可以在源代码`thrd_matrixmul.c`中更新`NCORES`宏以反映此值）

+   `prcs_matrixmul`应用程序首先运行；当它运行时，它会在四个可用的 CPU 核心中的一个上消耗 100%的 CPU 带宽（它恰好是 CPU 核心＃2）

+   请注意，在 CPU 历史记录仪的中间到左侧，代表 CPU2 的红线飙升到 100%（用紫色椭圆标出并标记为进程）！

+   在实际拍摄屏幕截图时（OS 在 X 轴时间线上；它从右向左移动），CPU 恢复到正常水平。

+   接下来（在这次运行的间隔为 10 秒后），`thrd_matrixmul`应用程序运行；这里的关键点在于：当它运行时，它会在所有四个 CPU 核心上消耗 100%的 CPU 带宽！

+   请注意，在 X 轴时间线上大约在 15 秒标记之后（从右到左阅读），所有四个 CPU 核心都突然达到了 100%——这是在执行`thrd_matrixmul`（用红色省略号突出显示并标记为 Threads）时发生的。

这告诉我们什么？非常重要的一点：底层的 Linux 操作系统 CPU 调度器将尝试利用硬件，并且如果可能的话，将我们的四个应用程序线程安排在四个可用的 CPU 上并行运行！因此，我们获得了更高的吞吐量、更高的性能和更高的性价比。

可以理解的是，此时您可能会对 Linux 如何执行 CPU（线程）调度产生很多疑问；不用担心，但请耐心等待——我们将在第十七章中详细探讨 Linux 的 CPU 调度。

1.  限制为仅一个 CPU：

`taskset(1)`实用程序允许在指定的处理器核心上运行进程。 （将进程与给定的 CPU 关联起来的能力称为 CPU 亲和性。我们将在调度章节中回到这一点。）使用`taskset`的基本形式很容易：`taskset -c <cpu-mask> <app-to-run-on-given-cpus>`

正如您可以从以下截图中看到的，我们对系统上所有四个 CPU 核心（通常方式）执行`thrd_matrixmul`应用程序的运行进行了对比，以及通过`taskset(1)`指定 CPU 掩码在仅一个 CPU 上运行它；截图再次清楚地显示了，在前一次运行中，所有四个 CPU 都被操作系统利用（总共需要 8.084 秒），而在后一次运行中，只有一个 CPU（以绿色显示为 CPU3）被用于执行其代码（总共需要 11.189 秒）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/61357669-4d7c-4bf5-8ddd-2dcfbd514e28.png)

根据本节刚学到的内容，您可能会得出结论：“嘿，我们找到答案了：让我们总是使用多线程。”但是，当然，经验告诉我们并没有银弹。事实是，尽管线程确实提供了一些真正的优势，但就像生活中的一切一样，它也有缺点。我们将在第十六章中推迟更多关于利弊的讨论，即*使用 Pthreads 进行多线程编程第三部分*；但请记住这一点。

现在，让我们进行另一个实验，以清楚地说明不仅多线程，而且多进程——使用 fork 生成多个进程——也非常有助于获得更高的吞吐量。

# 示例 3——内核构建

因此，最后一个实验（本节）：我们将为 ARM Versatile Express 平台构建（交叉编译）Linux 内核版本 4.17（使用默认配置）。内核构建的细节等都不在本书的范围之内，但没关系：关键点在于内核构建绝对是一个 CPU 和 RAM 密集型的操作。不仅如此，现代的`make(1)`实用程序也支持多进程！可以通过其`-jn`选项开关告诉`make`要内部生成（fork）的作业数量，其中`n`是作业（线程）的数量。我们使用一个启发式（经验法则）来确定这个数量：

`n = CPU 核心数量 * 2`

（在具有大量核心的高端系统上乘以 1.5。）

了解了这一点，接下来看看接下来的实验。

# 在具有 1GB RAM、两个 CPU 核心和并行化 make -j4 的 VM 上

我们配置了虚拟机客户机具有两个处理器，并进行了并行化构建（通过指定`make -j4`）：

```
$ cd <linux-4.17-kernel-src-dir>
$ perf stat make V=0 -j4 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- allscripts/kconfig/conf --syncconfig Kconfig
  CHK include/config/kernel.release
  SYSHDR arch/arm/include/generated/uapi/asm/unistd-oabi.h
  SYSHDR arch/arm/include/generated/uapi/asm/unistd-common.h
  WRAP arch/arm/include/generated/uapi/asm/bitsperlong.h
  WRAP arch/arm/include/generated/uapi/asm/bpf_perf_event.h
  WRAP arch/arm/include/generated/uapi/asm/errno.h
[...]                  *<< lots of output >>* 
  CC arch/arm/boot/compressed/string.o
  AS arch/arm/boot/compressed/hyp-stub.o
  AS arch/arm/boot/compressed/lib1funcs.o
  AS arch/arm/boot/compressed/ashldi3.o
  AS arch/arm/boot/compressed/bswapsdi2.o
  AS arch/arm/boot/compressed/piggy.o
  LD arch/arm/boot/compressed/vmlinux
  OBJCOPY arch/arm/boot/zImage
  Kernel: arch/arm/boot/zImage is ready

 Performance counter stats for 'make V=0 -j4 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- all':

    1174027.949123 task-clock (msec) # 1.717 CPUs utilized 
          3,80,189 context-switches  # 0.324 K/sec 
             7,921 cpu-migrations    # 0.007 K/sec 
       2,13,51,434 page-faults       # 0.018 M/sec 
   <not supported> cycles 
   <not supported> instructions 
   <not supported> branches 
   <not supported> branch-misses 

 683.798578130 seconds time elapsed
$ ls -lh <...>/linux-4.17/arch/arm/boot/zImage 
-rwxr-xr-x 1 seawolf seawolf 4.0M Aug 13 13:10  <...>/zImage*
$ ls -lh <...>/linux-4.17/vmlinux
-rwxr-xr-x 1 seawolf seawolf 103M Aug 13 13:10  <...>/vmlinux*
$ 
```

构建总共花费了大约 684 秒（11.5 分钟）。只是让您知道，用于 ARM 的压缩内核映像是名为`zImage`的文件；未压缩的内核映像（仅用于调试目的）是`vmlinux`文件。

在构建过程中，通过快速执行`ps -LA`确实显示了其多进程——而不是多线程——的性质：

```
$ ps -LA
[...]
11204 11204 pts/0 00:00:00 make
11227 11227 pts/0 00:00:00 sh
11228 11228 pts/0 00:00:00 arm-linux-gnuea
11229 11229 pts/0 00:00:01 cc1
11242 11242 pts/0 00:00:00 sh
11243 11243 pts/0 00:00:00 arm-linux-gnuea
11244 11244 pts/0 00:00:00 cc1
11249 11249 pts/0 00:00:00 sh
11250 11250 pts/0 00:00:00 arm-linux-gnuea
11251 11251 pts/0 00:00:00 cc1
11255 11255 pts/0 00:00:00 sh
11256 11256 pts/0 00:00:00 arm-linux-gnuea
11257 11257 pts/0 00:00:00 cc1
[...]
$ 
```

# 在具有 1GB RAM、一个 CPU 核心和顺序 make -j1 的 VM 上

我们配置客户 VM 只有一个处理器，清理构建目录，然后再次进行，但这次是顺序构建（通过指定`make -j1`）：

```
$ cd <linux-4.17-kernel-src-dir>
$ perf stat make V=0 -j1 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- all
scripts/kconfig/conf --syncconfig Kconfig
  SYSHDR arch/arm/include/generated/uapi/asm/unistd-common.h
  SYSHDR arch/arm/include/generated/uapi/asm/unistd-oabi.h
  SYSHDR arch/arm/include/generated/uapi/asm/unistd-eabi.h
  CHK include/config/kernel.release
  UPD include/config/kernel.release
  WRAP arch/arm/include/generated/uapi/asm/bitsperlong.h

[...]                  *<< lots of output >>*

  CC crypto/hmac.mod.o
  LD [M] crypto/hmac.ko
  CC crypto/jitterentropy_rng.mod.o
  LD [M] crypto/jitterentropy_rng.ko
  CC crypto/sha256_generic.mod.o
  LD [M] crypto/sha256_generic.ko
  CC drivers/video/backlight/lcd.mod.o
  LD [M] drivers/video/backlight/lcd.ko

 Performance counter stats for 'make V=0 -j1 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- all':

    1031535.713905 task-clock (msec) # 0.837 CPUs utilized 
          1,78,172 context-switches # 0.173 K/sec 
                 0 cpu-migrations # 0.000 K/sec 
       2,13,29,573 page-faults # 0.021 M/sec 
   <not supported> cycles 
   <not supported> instructions 
   <not supported> branches 
   <not supported> branch-misses 

    1232.146348757 seconds time elapsed
$ 
```

构建总共花费了大约 1232 秒（20.5 分钟），几乎是上一次构建的两倍长！

你可能会问这个问题：那么，如果使用一个进程构建大约花费了 20 分钟，而使用多个进程进行相同的构建大约花费了一半的时间，为什么还要使用多线程？多处理似乎也很好！

不，想一想：我们关于进程与线程创建/销毁的第一个例子告诉我们，生成（和终止）进程比使用线程慢得多。这仍然是许多应用程序利用的关键优势。毕竟，线程在创建和销毁方面比进程更有效。

在一个动态、不可预测的环境中，我们事先不知道需要多少工作，使用多线程能够快速创建工作线程（并快速终止它们）非常重要。想想著名的 Apache 网络服务器：它默认是多线程的（通过其 mpm_worker 模块，以便快速响应客户端请求）。同样，现代的 NGINX 网络服务器使用线程池（对于感兴趣的人，更多信息可以在 GitHub 存储库的“进一步阅读”部分找到）。

# 动机 - 为什么要使用线程？

线程确实提供了许多有用的优势；在这里，我们试图列举一些更重要的优势。我们认为这是对应用架构师使用多线程的动机，因为可能获得的优势。我们将这个讨论分为两个方面：设计和性能。

# 设计动机

在设计方面，我们考虑以下内容：

# 利用潜在的并行性

许多现实世界的应用程序将受益于以这样的方式设计它们，使得工作可以分成不同的单元，并且这些单元或工作包可以并行 - 与彼此同时运行。在实现层面，我们可以使用线程来实现工作包。

例如，下载加速器程序通过让几个线程执行网络 I/O 来利用网络。每个线程被分配下载文件的一部分的工作；它们都并行运行，有效地获得比单个线程更多的网络带宽，完成后，目标文件被拼接在一起。

有许多这样的例子；认识到并行性的潜力是架构师工作的重要部分。

# 逻辑分离

线程模型直观地适合让设计者逻辑上分离工作。例如，GUI 前端应用程序可能有几个线程管理 GUI 状态，等待并响应用户输入等。其他线程可以用于处理应用程序的业务逻辑。不将用户界面（UI）与业务逻辑混合在一起是良好设计的关键要素。

# CPU 与 I/O 重叠

这一点与前面的类似——任务的逻辑分离。在我们讨论的背景下，CPU 指的是软件是 CPU 密集型或 CPU 绑定的（经典的例子是 C 代码的`while（1）`）；I/O 指的是软件处于阻塞状态 - 我们说它在等待 I/O，意味着它在等待某些其他操作完成（也许是文件或网络读取，或者任何阻塞 API），然后它才能继续前进；这被称为 I/O 绑定。

所以，这样想：假设我们有一系列要执行的任务（它们之间没有依赖关系）：任务 A，任务 B，任务 C 和任务 D。

我们还可以说，任务 A 和任务 C 高度依赖 CPU，而任务 B 和任务 D 更依赖 I/O。如果我们使用传统的单线程方法，那么每个任务都必须按顺序执行；因此，进程最终会等待——也许要等很长时间——等待任务 B 和 D，从而延迟任务 C。另一方面，如果我们使用多线程方法，我们可以将任务分开为单独的线程。因此，即使任务 B 和 D 的线程在 I/O 上被阻塞，任务 A 和 C 的线程仍然可以取得进展。

这被称为 CPU 与 I/O 的重叠。在没有依赖关系的情况下，通过使用线程来解耦（和分离）任务，这是一种通常值得追求的设计方法。这会导致更好的应用程序响应能力。

# 经理-工人模型

线程非常容易适用于熟悉的经理-工人模型；一个经理线程（通常是`main()`）根据需要创建工作线程（或者将它们汇集在一起）；当工作出现时，工作线程处理它。想想繁忙的网络服务器。

# IPC 变得更简单

在进程之间执行 IPC 需要学习曲线、经验和大量工作。对于属于一个进程的线程，它们之间的 IPC——通信——就像写入和读取全局内存一样简单（说实话，这并不那么简单，当我们在下一章中讨论并发和同步的主题时，我们将了解到，概念上和实际上，这仍然比处理 IPC 要少得多）。

# 性能动机

正如前一节的两个示例清楚地向我们展示的那样，使用多线程可以显著提高应用程序的性能；这其中的一些原因在这里提到。

# 创建和销毁

前面的示例 1 清楚地表明，创建和销毁线程所需的时间远远少于进程。许多应用程序几乎要求您几乎不断地这样做。（我们将看到，与进程相比，创建和销毁线程在编程上要简单得多。）

# 自动利用现代硬件的优势

前面的示例 2 清楚地说明了这一点：在现代多核硬件上运行多线程应用程序时（高端企业级服务器可以拥有超过 700 个 CPU 核心！），底层操作系统将负责将线程优化地调度到可用的 CPU 核心上；应用程序开发人员不需要关心这一点。实际上，Linux 内核将尽可能确保完美的 SMP 可伸缩性，这将导致更高的吞吐量，最终实现速度增益。（亲爱的读者，我们在这里是乐观的：现实是，随着并行性和 CPU 核心的增加，也伴随着并发问题的严重缺陷；我们将在接下来的章节中更详细地讨论所有这些。）

# 资源共享

我们已经在本章的开始部分的*资源共享*部分中涵盖了这一点（如果需要，可以重新阅读）。最重要的是：与进程创建相比，线程创建成本较低（销毁也是如此）。此外，与进程相比，线程的内存占用要低得多。因此，可以获得资源共享和相关的性能优势。

# 上下文切换

上下文切换是操作系统上不幸的现实-每次操作系统从运行一个进程切换到运行另一个进程时都必须进行的元工作（我们有自愿和非自愿的上下文切换）。上下文切换所需的实际时间高度依赖于硬件系统和操作系统的软件质量；通常情况下，对于基于 x86 的硬件系统，大约在几十微秒的范围内。这听起来很小：要想知道为什么这被认为很重要（而且确实很浪费），看看在平均 Linux 台式电脑上运行`vmstat 3`的输出（`vmstat(1)`是一个著名的实用程序；以这种方式使用，它给我们提供了系统活动的一个很好的总体视图；嘿，还可以尝试它的现代继任者`dstat(1)`）：

```
$ vmstat 3
procs --------memory----------- --swap-- --io-- -system-- ------cpu-----
 r b  swpd   free   buff  cache  si so  bi  bo   in   cs  us sy id wa st
 0 0 287332 664156 719032 6168428 1 2  231  141   73   22 23 16 60  1  0
 0 0 287332 659440 719056 6170132 0 0    0  124 2878 2353  5  5 89  1  0
 1 0 287332 660388 719064 6168484 0 0    0  104 2862 2224  4  5 90  0  0
 0 0 287332 662116 719072 6170276 0 0    0  427 2922 2257  4  6 90  1  0
 0 0 287332 662056 719080 6170220 0 0    0   12 2358 1984  4  5 91  0  0
 0 0 287332 660876 719096 6170544 0 0    0   88 2971 2293  5  6 89  1  0
 0 0 287332 660908 719104 6170520 0 0    0   24 2982 2530  5  6 89  0  0
[...]
```

（请查阅`vmstat(1)`的 man 页面，详细解释所有字段）。在`system`标题下，我们有两列：`in`和`cs`（硬件）中断和上下文切换，分别表示在过去一秒内发生的。只需看看数字（尽管忽略第一行输出）！这是相当高的。这就是为什么这对系统设计者来说真的很重要。

在同一进程的线程之间进行上下文切换所需的工作量（因此时间）要比在不同进程（或属于不同进程的线程）之间要少得多。这是有道理的：当整个进程保持不变时，大部分内核代码可以有效地被短路。因此，这成为使用线程的另一个优势。

# 线程的简要历史

线程-一个顺序控制流-现在已经存在很长时间了；只是以进程的名义存在（据报道，这是在 1965 年的伯克利分时系统时）。然后，在 20 世纪 70 年代初，Unix 出现了，将进程巩固为 VAS 和顺序控制流的组合。正如前面提到的，这现在被称为单线程模型，因为当然只有一个控制流-主函数-存在。

然后，1993 年 5 月，Sun Solaris 2.2 推出了 UI 线程，并推出了一个名为*libthread*的线程库，它公开了 UI API 集；实际上，这是现代线程。竞争的 Unix 供应商迅速推出了自己的专有多线程解决方案（带有暴露 API 的运行时库）-Digital 的 DECthreads（后来被 Compaq Tru64 Unix 吸收，随后是 HP-UX）、IBM 的 AIX、Silicon Graphics 的 IRIX 等等-每个都有自己的专有解决方案。

# POSIX 线程

专有解决方案对拥有来自几家供应商的异构硬件和软件的大客户构成了重大问题；由于是专有的，很难让不同的库和 API 集相互通信。这是一个常见的问题-缺乏互操作性。好消息是：1995 年，IEEE 成立了一个单独的 POSIX 委员会-IEEE 1003.1c-**POSIX 线程**（**pthreads**）委员会，以制定多线程 API 的标准化解决方案。

POSIX：显然，IEEE 机构的原始名称是**计算环境的便携式操作系统接口**（**POSICE**）。Richard M. Stallman（RMS）建议将名称缩短为**Unix 的便携式操作系统接口**（**POSIX**），这个名称一直沿用至今。

因此，pthreads 是一个 API 标准；正式来说，是 IEEE 1003.1c-1995。所有 Unix 和类 Unix 操作系统供应商逐渐构建了支持 pthreads 的实现；因此，今天（至少在理论上），你可以编写一个 pthreads 多线程应用程序，并且它将在任何支持 pthreads 的平台上运行（在实践中，可能需要一些移植工作）。

# Pthreads 和 Linux

当然，Linux 希望符合 POSIX 线程标准；但是谁会真正构建一个实现（记住，标准只是一个草案规范文件；它不是代码）？1996 年，Xavier Leroy 站出来构建了 Linux 的第一个 pthread 实现——一个名为 Linux 线程的线程库。总的来说，这是一个很好的努力，但并不完全兼容（当时全新的）pthread 标准。

早期解决问题的努力被称为**下一代 Posix 线程**（**NGPT**）。大约在同一时间，Red Hat 也派出一个团队来处理这个领域；他们称之为**本机 Posix 线程库**（**NPTL**）项目。在开源文化的最佳传统中，NGPT 开发人员与 NPTL 的同行合作，开始将 NGPT 的最佳特性合并到 NPTL 中。NGPT 的开发在 2003 年的某个时候被放弃；到那时，在 Linux 上实际的 pthread 实现——直到今天仍然存在的——是 NPTL。

更具体地说：尽管特性被集成到 2.6 版 Linux 内核（2003 年 12 月以后），NPTL 作为优越的线程 API 接口得到了巩固，这有助于大大提高线程性能。

NPTL 实现了 1:1 线程模型；这个模型提供了真正的多线程（用户和内核状态），也被称为本地线程模型。在这里，我们不打算深入探讨这些内部细节；在 GitHub 存储库的*进一步阅读*部分中提供了一个链接，供感兴趣的读者参考。

可以使用以下代码（在 Fedora 28 系统上）查找线程实现（自 glibc 2.3.2 以来）：

```
$ getconf GNU_LIBPTHREAD_VERSION
NPTL 2.27
$ 
```

显然，这是 NPTL。

# 线程管理——基本的 pthread API

在这个第一章关于多线程的第二个重要部分中，我们现在将专注于机制：使用 pthread API，程序员究竟如何以有效的方式创建和管理线程？我们将探索基本的 pthread API 接口，以实现这一关键目的；这种知识是编写功能性和性能友好的 pthread 应用程序的基础。

我们将通过 API 集来介绍线程的生命周期——创建、终止、等待（等待）、以及一般地管理进程的线程。我们还将涵盖线程堆栈管理。

这当然意味着我们在 Linux 系统上安装了一个 pthread 运行时库。在现代 Linux 发行版上，这肯定是这样；只有在使用相当古怪的嵌入式 Linux 时，您才需要验证这一点。Linux 平台上 pthread 库的名称是 libpthread。

关于 pthread API 的一些关键点如下：

+   所有 pthread API 都需要在源文件中包含`<pthread.h>`头文件。

+   该 API 经常使用面向对象的数据隐藏和数据抽象概念；许多数据类型是内部 typedefs；这种设计是故意的：我们希望代码是可移植的。因此，程序员不应该假设类型，并且必须使用提供的辅助方法来访问和/或查询数据类型。 （当然，代码本身是通常的过程式 C；然而，许多概念都是围绕对象导向建模的。有趣的是，Linux 内核也遵循这种方法。）

# 线程创建

用于创建线程的 pthread API 是`pthread_create(3)`；其签名如下：

```
#include <pthread.h>
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                void *(*start_routine) (void *), void *arg);
```

在编译 pthread 应用程序时，非常重要的是指定`-pthread` `gcc`选项开关（它启用了使用 libpthread 库所需的宏（后续将详细介绍）。

`pthread_create`是调用以在调用进程中创建新线程的 API。成功时，新线程将与该进程中可能存在的其他线程并发（并行）运行；但它将运行什么代码呢？它将从运行`start_routine`函数的代码开始（这是 API 的第三个参数：指向函数的指针）。当然，这个线程函数随后可以进行任意数量的函数调用。

新线程的线程 ID 将被存储在不透明数据项`thread`中——第一个参数（这是一个值-结果样式的参数）。它的数据类型`pthread_t`是故意不透明的；我们不能假设它是整数（或任何其他东西）。我们很快将遇到何时以及如何使用线程 ID。

请注意，第三个参数，函数指针——新线程运行的例程本身接收一个 void*参数——一个通用指针。这是一种常见且有用的编程技术，使我们能够向新创建的线程传递绝对任何值。 （这种参数通常在文献中被称为客户数据或标签。）我们如何传递它？通过`pthread_create(3)`的第四个参数`arg`。

`pthread_create(3)`的第二个参数是线程属性结构；在这里，程序员应该传递正在创建的线程的属性（我们很快将讨论其中的一些）。有一个快捷方式：在这里传递`NULL`意味着库应该在创建线程时使用默认属性。然而，在某个 Unix 上的默认值可能与另一个 Unix 或 Linux 上的默认值有很大不同；编写可移植的代码意味着不要假设任何默认值，而是显式地初始化适合应用程序的属性。因此，我们的建议肯定是不要传递`NULL`，而是显式地初始化一个`pthread_attr_t`结构并将其传递（接下来的代码示例将说明这一点）。

最后，`pthread_create(3)`的返回值在成功时为`0`，失败时为非零；`errno`将根据需要设置为几个值（我们建议您参考`pthread_create(3)`的手册页了解这些细节）。

当创建新线程时，它会从创建线程那里继承某些属性；其中包括以下内容：

+   创建线程的能力集（回想一下我们在第八章中的讨论，*进程能力*）；这是特定于 Linux 的

+   创建线程的 CPU 亲和性掩码；这是特定于 Linux 的

+   信号掩码

新线程中的任何未决信号和未决定时器（警报）都将被清除。新线程的 CPU 执行时间也将被重置。

只要你知道，在 Linux libpthreads 实现中，`pthread_create(3)`调用了`clone(2)`系统调用，在内核中实际上创建了线程。

有趣的是，现代 glibc 的`fork`实现也调用了`clone(2)`系统调用。传递给`clone(2)`的标志确定了如何进行资源共享。

是时候写一些代码了！我们将为 pthread 编写一个非常简单（实际上相当有 bug 的）`hello, world.`应用程序（`ch14/pthreads1.c`）：

```
[...]
#include <pthread.h>
#include "../common.h"
#define NTHREADS 3

void * worker(void *data)
{
      long datum = (long)data;
      printf("Worker thread #%ld says: hello, world.\n", datum);
      printf(" #%ld: work done, exiting now\n", datum);
}

int main(void)
{
      long i;
      int ret;
      pthread_t tid;

      for (i = 0; i < NTHREADS; i++) {
            ret = pthread_create(&tid, NULL, worker, (void *)i);
            if (ret)
                  FATAL("pthread_create() failed! [%d]\n", ret);
      }
      exit(EXIT_SUCCESS);
}
```

正如你所看到的，我们循环三次，在每次循环迭代时创建一个线程。注意`pthread_create(3)`的第三个参数——一个函数指针（只提供函数名称就足够了；编译器会自动处理剩下的部分）；这是线程的工作例程。这里是函数`worker`。我们还传递第四个参数给`pthread_create`——记住这是客户数据，任何你想传递给新创建线程的数据；这里我们传递循环索引`i`（当然，我们适当地对其进行类型转换，以免编译器抱怨）。

在`worker`函数中，我们通过再次将`void *`强制转换回其原始类型`long`来访问客户数据（作为形式参数`data`接收）：

`long datum = (long)data;`

然后我们只是发出了一些 printf 来显示，是的，我们确实在这里。请注意，所有工作线程都运行相同的代码——`worker`函数。这是完全可以接受的；请记住，代码（文本）是按页权限进行读取执行的；并行运行文本不仅是可以的，而且通常是可取的（提供高吞吐量）。

构建它，我们提供了 Makefile；请注意，所有 pthread API 默认情况下并未链接，就像 glibc 一样。不，它们当然在 libpthread 中，我们需要显式编译（到我们的源文件）并通过`-pthread`指令链接到我们的二进制可执行文件中。Makefile 中的以下片段显示了这一点：

```
CC := gcc
CFLAGS=-O2 -Wall -UDEBUG -pthread
LINKIN := -pthread

#--- Target :: pthreads1
pthreads1.o: pthreads1.c
    ${CC} ${CFLAGS} -c pthreads1.c -o pthreads1.o
pthreads1: common.o pthreads1.o
    ${CC} -o pthreads1 pthreads1.o common.o ${LINKIN}
```

现在构建已经可以工作了，但是请注意，这个程序实际上并不工作得很好！在下面的代码中，我们通过循环运行`./pthreads1`来执行一些测试运行：

```
$ for i in $(seq 1 5); do echo "trial run #$i:" ; ./pthreads1; done trial run #1:
Worker thread #0 says: hello, world.
Worker thread #0 says: hello, world.
trial run #2:
Worker thread #0 says: hello, world.
Worker thread #0 says: hello, world.
 #0: work done, exiting now
trial run #3:
Worker thread #1 says: hello, world.
Worker thread #1 says: hello, world.
 #1: work done, exiting now
trial run #4:
trial run #5: $ 
```

正如您所看到的，`hello, world.`消息只是间歇性地出现，并且在第 4 和第 5 次试运行中根本没有出现（当然，由于时间问题，您尝试这个程序时看到的输出肯定会有所不同）。

为什么会这样？很简单：我们无意中设置了一个有 bug 的情况——竞争！到底在哪里？仔细再看一遍代码：一旦循环结束，`main()`函数会做什么？它调用`exit(3)`；因此整个进程终止，不仅仅是主线程！而且谁能说工作线程在这发生之前完成了他们的工作呢？啊——这位女士们先生们，这就是您经典的竞争。

那么，我们该如何修复它呢？目前，我们将只进行一些快速修复；避免竞争代码的正确方法是通过同步；这是一个重要的话题，值得单独一章来讨论（您将会看到）。好的，首先，让我们解决主线程过早退出的问题。

# 终止

`exit(3)`库 API 会导致调用进程以及其所有线程终止。如果您希望单个线程终止，请让它调用`pthread_exit(3)`API：

```
#include <pthread.h>
 void pthread_exit(void *retval);
```

这个参数指定了调用线程的退出状态；目前，我们忽略它，只传递`NULL`（我们将很快研究如何使用这个参数）。

那么，回到我们的竞争应用程序（`ch14/pthreads1.c`）；让我们制作一个第二个更好的版本（`ch14/pthreads2.c`）。实际上，我们第一个版本的问题是竞争——主线程调用`exit(3)`，导致整个进程可能在工作线程有机会完成工作之前就死掉了。所以，让我们通过让`main()`调用`pthread_exit(3)`来解决这个问题！另外，为什么不让我们的线程工作函数通过显式调用`pthread_exit(3)`来正确终止呢？

以下是`worker()`和`main()`函数的修改后的代码片段（`ch14/pthreads2.c`）：

```
void * worker(void *data)
{
      long datum = (long)data;
      printf("Worker thread #%ld running ...\n", datum);
      printf("#%ld: work done, exiting now\n", datum);
      pthread_exit(NULL);
}
[...]
  for (i = 0; i < NTHREADS; i++) {
        ret = pthread_create(&tid, NULL, worker, (void *)i);
        if (ret)
              FATAL("pthread_create() failed! [%d]\n", ret);
  }
#if 1
 pthread_exit(NULL);
#else
      exit(EXIT_SUCCESS);
#endif
[...]
```

让我们尝试一下前面的程序：

```
$ ./pthreads2 
Worker thread #0 running ...
#0: work done, exiting now
Worker thread #1 running ...
#1: work done, exiting now
Worker thread #2 running ...
#2: work done, exiting now
$ 
```

好多了！

# 鬼魂的回归

还有一个隐藏的问题。让我们进行更多的实验：让我们编写这个程序的第三个版本（让我们称之为`ch14/pthreads3.c`）。在这个版本中，我们假设工作线程需要更长的时间来完成他们的工作（比它们目前所需的时间长）。我们可以很容易地通过一个简单的`sleep(3)`函数来模拟这一点，这将被引入到工作例程中：

```
[...]
void * worker(void *data)
{
      long datum = (long)data;
      printf("Worker thread #%ld running ...\n", datum);
      sleep(3);
      printf("#%ld: work done, exiting now\n", datum);
      pthread_exit(NULL);
}
[...]
```

让我们试一试：

```
$ ./pthreads3 
Worker thread #0 running ...
Worker thread #1 running ...
Worker thread #2 running ...
 *[... All three threads sleep for 3s ...]*

#1: work done, exiting now
#0: work done, exiting now
#2: work done, exiting now
$ 
```

好了？看起来很好。真的吗？还有一个快速而次要的修改必须完成；将睡眠时间从 3 秒增加到 30 秒，然后重新构建和重试（我们这样做的唯一原因是给最终用户一个机会输入`ps(1)`命令，如下面的屏幕截图所示，然后应用程序就会死掉）。现在，在后台运行，并仔细观察！

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/142c88d2-a84e-4026-855c-0fe06c95b0a1.png)

查看前面的屏幕截图：我们在后台运行`pthreads3`应用程序；该应用程序（实际上是应用程序的主线程）创建了另外三个线程。这些线程只是通过每个休眠三十秒来阻塞。当我们在后台运行进程时，我们可以在 shell 进程上获得控制；现在我们使用`ps(1)`和`-LA`选项开关运行。从`ps(1)`的 man 页面上：

+   `-A`：选择所有进程；与`-e`相同

+   `-L`：显示线程，可能带有 LWP 和 NLWP 列

好吧！（GNU）`ps(1)`甚至可以通过使用`-L`选项开关来显示每个活动的线程（也尝试一下`ps H`）。使用`-L`开关，`ps`输出的第一列是进程的 PID（对我们来说非常熟悉）；第二列是**轻量级进程**（**LWP**）；实际上，这是内核所见的单个线程的 PID。有趣。不仅如此，仔细看看这些数字：PID 和 LWP 匹配的地方是进程的`main()`线程；PID 和 LWP 不同的地方告诉我们这是一个子线程，或者更准确地说是属于进程的对等线程；LWP 是操作系统所见的线程 PID。因此，在我们的示例运行中，我们有进程 PID 为 3906，以及四个线程：第一个是`main()`线程（因为其 PID == 其 LWP 值），而其余三个具有相同的 PID——证明它们属于同一个进程，但它们各自的线程 PID（它们的 LWP）是唯一的——3907、3908 和 3909！

我们一直在提到的问题是，在`ps`输出的第一行（代表`main`线程）中，进程名称后面跟着短语

`<defunct>`（极端右侧）。敏锐的读者会记得`defunct`是`zombie`的另一个术语！是的，臭名昭著的僵尸又回来了。

主线程通过调用`pthread_exit(3)`（回想一下`ch14/pthreads3.c`中的主代码）在进程中的其他线程之前退出；因此 Linux 内核将其标记为僵尸。正如我们在第十章中学到的那样，僵尸是不受欢迎的实体；我们真的不希望有僵尸挂在那里（浪费资源）。因此，问题当然是如何防止主线程成为僵尸？答案很简单：不要允许主线程在应用程序中的其他线程之前终止；换句话说，建议始终保持`main()`活动，等待所有其他线程死亡，然后再终止自身（从而终止进程）。如何做到？继续阅读。

再次强调（但我们还是要说！）：只要其中至少一个线程保持活动状态，进程就会保持活动状态。

作为一个快速的旁白，工作线程何时运行相对于彼此和主线程？换句话说，第一个创建的线程是否保证首先运行，然后是第二个线程，然后是第三个，依此类推？

简短的答案是：没有这样的保证。特别是在现代的**对称多处理器**（**SMP**）硬件和像 Linux 这样的现代多进程和多线程能力的操作系统上，运行时的实际顺序是不确定的（这是一种说法，即无法知道）。实际上，这取决于操作系统调度程序来做出这些决定（也就是说，在没有实时调度策略和线程优先级的情况下；我们将在本书的后面讨论这些主题）。

我们的`./pthreads2`示例程序的另一个试运行显示了这种情况：

```
$ ./pthreads2 
Worker thread #0 running ...
#0: work done, exiting now
Worker thread #2 running ...
#2: work done, exiting now
Worker thread #1 running ...
#1: work done, exiting now
$ 
```

你能看到发生了什么吗？在前面的代码中显示的顺序是：`thread #0`，然后是`thread #2`，然后是`thread #1`！这是不可预测的。在设计多线程应用程序时，不要假设任何特定的执行顺序（我们将在以后的章节中介绍同步，教我们如何实现所需的顺序）。

# 死亡的方式有很多

线程如何终止？事实证明有几种方式：

+   通过调用`pthread_exit(3)`。

+   通过从线程函数返回，返回值会被隐式传递（就像通过`pthread_exit`参数一样）。

+   隐式地，通过从线程函数中跳出；也就是说，到达右括号`}`；但请注意，这并不推荐（稍后的讨论将告诉你为什么）

+   任何调用`exit(3)`API 的线程，当然会导致整个进程以及其中的所有线程死掉。

+   线程被取消（我们稍后会讨论）。

# 有太多线程了吗？

到目前为止，我们知道如何创建一个应用程序进程，并在其中执行一些线程。我们将重复我们的第一个演示程序`ch14/pthreads1.c`中的代码片段，如下：

```
#include <pthread.h>
#define NTHREADS 3
[...]

int main(void)
{
  [...]
 for (i = 0; i < NTHREADS; i++) {
        ret = pthread_create(&tid, NULL, worker, (void *)i);
        if (ret)
              FATAL("pthread_create() failed! [%d]\n", ret);
  }
[...]
```

显然，进程-实际上我们指的是进程的主线程（或应用程序）-进入循环，每次循环迭代都会创建一个线程。因此，当完成时，我们将有三个线程，加上主线程，总共有四个线程，在进程中活动。

这是显而易见的。这里的重点是：创建线程比使用`fork(2)`创建（子）进程要简单得多；使用 fork 时，我们必须仔细编写代码，让子进程运行其代码，而父进程继续其代码路径（回想一下 switch-case 结构；如果愿意，可以快速查看我们的`ch10/fork4.c`代码示例）。使用`pthread_create(3)`，对于应用程序员来说变得很容易-只需在循环中调用 API-就可以了！在前面的代码片段中，想象一下调整它，将`NTHREADS`的值从 3 更改为 300；就这样，进程将产生 300 个线程。如果我们将`NTHREADS`设为 3,000 呢？或者 30,000！？

思考这一点会引发一些相关的问题：一，你实际上能创建多少线程？二，你应该创建多少线程？请继续阅读。

# 你能创建多少线程？

如果你仔细想想，底层操作系统对应用程序可以创建的线程数量肯定有一些人为的限制；否则，系统资源会很快被耗尽。事实上，这并不是什么新鲜事；我们在第三章中的整个讨论实际上就是关于类似的事情。

关于线程（和进程），有两个（直接）限制影响着任何给定时间点可以存在的线程数量：

+   每个进程的资源限制：你会回忆起我们在第三章中讨论过，有两个实用程序可以查看当前定义的资源限制：`ulimit(1)`和`prlimit(1)`，后者是现代接口。让我们快速看一下最大用户进程的资源限制；还要意识到，尽管使用了单词进程，但实际上应该将其视为线程：

```
$ ulimit -u
63223
$ 
```

同样，`prlimit()`向我们展示了以下内容：

```
$ prlimit --nproc
RESOURCE DESCRIPTION          SOFT  HARD  UNITS
NPROC max number of processes 63223 63223 processes
$ 
```

在这里，我们已经向你展示了如何通过 CLI 查询限制；要查看如何进行交互和使用 API 接口来更改它，请参考第三章，*资源限制*。

+   系统范围限制：Linux 操作系统维护着一个系统范围的（而不是每个进程的）限制，限制了在任何给定时间点可以活动的线程总数。这个值通过 proc 文件系统暴露给用户空间：

```
$ cat /proc/sys/kernel/threads-max 
126446
$ 
```

因此，要理解的是，如果违反了前两个限制中的任何一个，`pthread_create(3)`（以及类似地，`fork(2)`）将失败（通常将`errno`设置为值`EAGAIN`再试一次；操作系统实际上是在说：“我现在无法为你做到这一点，请稍后再试一次”）。

你能改变这些值吗？当然可以，但通常情况下，你需要 root（超级用户）访问权限才能这样做。（同样，我们已经在第三章中详细讨论了这些要点，*资源限制*）关于系统范围的限制，你确实可以作为 root 来改变它。但是，请等一下，盲目地改变系统参数而不了解其影响是失去对系统控制的一种确定方式！所以，让我们首先问自己这个问题：操作系统在启动时设置`threads-max`限制的值是基于什么的？

简短的回答是：它与系统上的 RAM 数量成正比。这是有道理的：最终，内存是关于创建线程和进程的关键限制资源。

对于我们亲爱的操作系统级别的极客读者来说，更详细地说：内核代码在启动时设置了`/proc/sys/kernel/threads-max`的值，以便操作系统中的线程（任务）结构最多可以占用可用 RAM 的八分之一。（`threads-max`的最小值是 20；最大值是常量`FUTEX_TID_MASK 0x3fffffff`。）

此外，默认情况下，最大线程数的每进程资源限制是系统限制的一半。

从前面的代码中可以看出，我们得到的值是 126,446；这是在一台带有 16GB RAM 的本机 Linux 笔记本电脑上完成的。在一台带有 1GB RAM 的虚拟机上运行相同的命令会得到以下结果：

```
$ cat /proc/sys/kernel/threads-max 
7420
$ prlimit --nproc
RESOURCE DESCRIPTION          SOFT  HARD  UNITS
NPROC max number of processes 3710  3710  processes
$ 
```

将`threads-max`内核可调整值设置为过高的值——超过`FUTEX_TID_MASK`——将导致它被降低到该值（但是，当然，在任何情况下，这几乎肯定都太大了）。但即使在限制范围内，你也可能走得太远，导致系统变得脆弱（可能会受到**拒绝服务**（DoS）攻击的影响！）。在嵌入式 Linux 系统上，降低限制实际上可能有助于约束系统。

# 代码示例——创建任意数量的线程

所以，让我们来测试一下：我们将编写我们先前程序的一个简单扩展，这次允许用户指定要在进程中尝试创建的线程数量作为参数（`ch14/cr8_so_many_threads.c`）。主函数如下：

```
int main(int argc, char **argv)
{
  long i;
  int ret;
  pthread_t tid;
  long numthrds=0;

  if (argc != 2) {
      fprintf(stderr, "Usage: %s number-of-threads-to-create\n", argv[0]);
      exit(EXIT_FAILURE);
  }
  numthrds = atol(argv[1]);
  if (numthrds <= 0) {
      fprintf(stderr, "Usage: %s number-of-threads-to-create\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  for (i = 0; i < numthrds; i++) {
        ret = pthread_create(&tid, NULL, worker, (void *)i);
        if (ret)
              FATAL("pthread_create() failed! [%d]\n", ret);
  }
  pthread_exit(NULL);
}
```

这很简单：我们将用户传递的字符串值作为第一个参数转换为数字值，然后我们循环`numthrds`次，每次调用`pthread_create(3)`，从而在每次循环迭代时创建一个全新的线程！一旦创建，新线程会做什么？很明显——它们执行`worker`函数的代码。让我们来看一下：

```
void * worker(void *data)
{
      long datum = (long)data;
      printf("Worker thread #%5ld: pausing now...\n", datum);
      (void)pause();
```

```

      printf(" #%5ld: work done, exiting now\n", datum);
      pthread_exit(NULL);
}
```

同样，这非常简单：工作线程只是发出一个`printf(3)`——这很有用，因为它们打印出它们的线程号——当然只是循环索引。然后，它们通过`pause(2)`系统调用进入睡眠状态。（这个系统调用很有用：它是一个完美的阻塞调用；它会将调用线程置于睡眠状态，直到收到信号。）

好了，让我们试一试：

```
$ ./cr8_so_many_threads 
Usage: ./cr8_so_many_threads number-of-threads-to-create
$ ./cr8_so_many_threads 300
Worker thread #   0: pausing now...
Worker thread #   1: pausing now...
Worker thread #   2: pausing now...
Worker thread #   3: pausing now...
Worker thread #   5: pausing now...
Worker thread #   6: pausing now...
Worker thread #   4: pausing now...
Worker thread #   7: pausing now...
Worker thread #  10: pausing now...
Worker thread #  11: pausing now...
Worker thread #   9: pausing now...
Worker thread #   8: pausing now...

[...]

Worker thread #  271: pausing now...
Worker thread #  299: pausing now...
Worker thread #  285: pausing now...
Worker thread #  284: pausing now...
Worker thread #  273: pausing now...
Worker thread #  287: pausing now...
[...]
^C
$ 
```

它起作用了（请注意，我们已经截断了输出，因为在本书中显示太多内容）。请注意，线程启动和执行的顺序（发出它们的`printf`）是随机的。我们可以看到，我们创建的最后一个线程是加粗显示的——线程`# 299`（0 到 299 是 300 个线程）。

现在，让我们再次运行它，但这次让它创建一个不可能的大数量的线程（我们目前正在一台带有 1GB RAM 的虚拟机上尝试这个）：

```
$ prlimit --nproc ; ulimit -u RESOURCE DESCRIPTION          SOFT HARD UNITS
NPROC max number of processes 3710 3710 processes
3710 $ ./cr8_so_many_threads 40000
Worker thread # 0: pausing now...
Worker thread # 1: pausing now...
Worker thread # 2: pausing now...
Worker thread # 4: pausing now...

[...]

Worker thread # 2139: pausing now...
Worker thread # 2113: pausing now...
Worker thread # 2112: pausing now...
FATAL:cr8_so_many_threads.c:main:52: pthread_create() #2204 failed ! [11]
 kernel says: Resource temporarily unavailable
$ 
```

显然，你将看到的结果取决于你的系统；我们鼓励读者在不同的系统上尝试一下。此外，实际的失败消息可能出现在你的终端窗口的更高位置；向上滚动以找到它！

线程的名称，如`ps(1)`所示，等等，可以通过`pthread_setname_np(3)`API 来设置；请注意，`np`后缀意味着该 API 是不可移植的（仅限 Linux）。

# 应该创建多少个线程？

你创建的线程数量确实取决于应用程序的性质。在我们的讨论中，我们将考虑应用程序倾向于是 CPU 还是 I/O 限制。

在本章的前面（特别是在*设计动机*和*重叠 CPU 与 I/O*的部分），我们提到了一个事实，即一个线程在执行行为上，处于一个连续体的某个位置，介于两个极端之间：一个极端是完全 CPU 限制的任务，另一个极端是完全 I/O 限制的任务。这个连续体可以被想象成这样：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/4d003f8d-0633-4386-a8b0-d06b42ae6701.png)

图 3：CPU 限制/I/O 限制连续体

一个 100%的 CPU 绑定线程将不断地在 CPU 上运行；一个 100%的 I/O 绑定线程是一个总是处于阻塞（或等待）状态的线程，从不在 CPU 上执行。这两个极端在真实应用中都是不现实的；然而，很容易想象出它们倾向于出现的领域。例如，涉及大量数学处理（科学模型，矢量图形，如 Web 浏览器中的 Flash 动画，矩阵乘法等），（解）压缩实用程序，多媒体编解码器等领域肯定倾向于更多地受 CPU 限制。另一方面，我们人类每天与之交互的许多（但不是所有）应用程序（想想你的电子邮件客户端，Web 浏览器，文字处理等）倾向于等待人类做一些事情；实际上，它们倾向于受 I/O 限制。

因此，尽管有点简化，但这仍然作为一个有用的设计经验法则：如果正在设计的应用程序在性质上受到 I/O 限制，那么创建甚至是大量等待工作的线程是可以的；这是因为它们大部分时间都会处于休眠状态，因此不会对 CPU 造成任何压力（当然，创建太多线程会对内存造成压力）。

另一方面，如果应用程序被确定为高度 CPU 限制，那么创建大量线程将会给系统带来压力（最终导致抖动-一种现象，其中元工作的时间比实际工作的时间更长！）。因此，对于 CPU 限制的工作负载，经验法则是：

```
max number of threads = number of CPU cores * factor;
 where factor = 1.5 or 2.
```

但需要注意的是，确实存在一些 CPU 核心不提供任何**超线程**（**HT**）功能；在这样的核心上，因子应该保持为 1。

实际上，我们的讨论相当简单：许多现实世界的应用程序（想想像 Apache 和 NGINX 这样的强大的 Web 服务器）将根据确切的情况、配置预设和当前工作负载动态地创建和调整所需的线程数量。然而，前面的讨论作为一个起点，让你开始思考多线程应用程序的设计。

# 线程属性

在本章早期的*线程创建*讨论中，我们看到了`pthread_create(3)`API；第二个参数是指向线程属性结构的指针：`const pthread_attr_t *attr`。我们提到过，在这里传递 NULL，实际上是让库使用默认属性创建线程。虽然这确实是这样，但问题在于，对于真正可移植的应用程序，这是不够的。为什么？因为默认线程属性在不同的实现中实际上有很大的差异。正确的方法是在线程创建时显式指定线程属性。

首先，当然，我们需要了解 pthread 具有哪些属性。以下表格列举了这些属性：

| **属性** | **含义** | **APIs: **`pthread_attr_...` | **可能的值** | ***Linux 默认*** |
| --- | --- | --- | --- | --- |
| 分离状态 | 创建可连接或分离的线程 | `pthread_attr_` `[get&#124;set]detachstate` | PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_DETACHED | PTHREAD_CREATE_JOINABLE |
| 调度/争用范围 | 我们与之竞争资源（CPU）的线程集 | `pthread_attr_``[get&#124;set]scope` | PTHREAD_SCOPE_SYSTEM PTHREAD_SCOPE_PROCESS | PTHREAD_SCOPE_SYSTEM |
| 调度/继承 | 确定调度属性是从调用线程隐式继承还是从 attr 结构显式继承 | `pthread_attr_``[get&#124;set]inheritsched` | PTHREAD_INHERIT_SCHED PTHREAD_EXPLICIT_SCHED | PTHREAD_INHERIT_SCHED |

| 调度/策略 | 确定正在创建的线程的调度策略 | `pthread_attr_``[get&#124;set]schedpolicy` | SCHED_FIFO SCHED_RR

SCHED_OTHER | SCHED_OTHER |

| 调度/优先级 | 确定正在创建的线程的调度优先级 | `pthread_attr_``[get&#124;set]schedparam` | 结构 sched_param 保存    int sched_priority | 0（非实时） |
| --- | --- | --- | --- | --- |
| 栈/保护区域 | 线程栈的保护区域 | `pthread_attr_``[get&#124;set]guardsize` | 字节中的栈保护区域大小 | 1 页 |

| 栈/位置，大小 | 查询或设置线程的栈位置和大小 | `pthread_attr_` `[get&#124;set]stack``pthread_attr_`

`[get&#124;set]stackaddr``pthread_attr_`

`[get&#124;set]stacksize` | 字节中的栈地址和/或栈大小 | 线程栈位置：左到 OSThread 栈大小：8 MB |

正如您所看到的，要清楚地理解这些属性的确切含义需要进一步的信息。请耐心等待我们在本章（实际上是本书）中继续进行，因为其中的一些属性及其含义将变得非常清楚（调度的详细信息将在第十七章中显示，*Linux 上的 CPU 调度*）。 

# 代码示例 - 查询默认线程属性

现在，一个有用的实验是查询新创建线程的默认属性，其属性结构指定为 NULL（默认）。如何？`pthread_default_getattr_np(3)`将起作用（请注意，再次，`_np`后缀意味着它是一个仅限 Linux 的非可移植 API）：

```
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <pthread.h>
int pthread_getattr_default_np(pthread_attr_t *attr);
```

有趣的是，由于此函数依赖于定义`_GNU_SOURCE`宏，因此我们必须首先定义该宏（在源代码中的早期）；否则，编译会触发警告并可能失败。（在我们的代码中，我们首先使用`#include "../common.h"`，因为我们的*common.h*头文件定义了`_GNU_SOURCE`宏。）

我们的代码示例可以在这里找到，位于本书的 GitHub 存储库中：`ch14/disp_defattr_pthread.c` *。*

在下面的代码中，我们在运行 4.17.12 Linux 内核的 Fedora x86_64 箱上进行了试验：

```
$ ./disp_defattr_pthread 
Linux Default Thread Attributes:
Detach State : PTHREAD_CREATE_JOINABLE
Scheduling 
 Scope       : PTHREAD_SCOPE_SYSTEM
 Inheritance : PTHREAD_INHERIT_SCHED
 Policy      : SCHED_OTHER
 Priority    : 0
Thread Stack 
  Guard Size :    4096 bytes
  Stack Size : 8388608 bytes
$ 
```

为了便于阅读，只显示了源代码的关键部分；要查看完整的源代码，构建并运行它，整个树都可以从 GitHub 克隆到这里：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

这里的关键函数显示在以下代码中（`ch14/disp_defattr_pthread.c`）；我们首先查询和显示线程属性结构的“分离状态”（这些术语将很快详细解释）：

```
static void display_thrd_attr(pthread_attr_t *attr)
{
  int detachst=0;
  int sched_scope=0, sched_inh=0, sched_policy=0;
  struct sched_param sch_param;
  size_t guardsz=0, stacksz=0;
  void *stackaddr;

  // Query and display the 'Detached State'
  if (pthread_attr_getdetachstate(attr, &detachst))
        WARN("pthread_attr_getdetachstate() failed.\n");
  printf("Detach State : %s\n",
    (detachst == PTHREAD_CREATE_JOINABLE) ? "PTHREAD_CREATE_JOINABLE" :
    (detachst == PTHREAD_CREATE_DETACHED) ? "PTHREAD_CREATE_DETACHED" :
     "<unknown>");
```

接下来，将查询和显示各种调度属性（一些细节稍后在第十七章中讨论，*Linux 上的 CPU 调度*）：

```
//--- Scheduling Attributes
  printf("Scheduling \n");
  // Query and display the 'Scheduling Scope'
  if (pthread_attr_getscope(attr, &sched_scope))
        WARN("pthread_attr_getscope() failed.\n");
  printf(" Scope : %s\n",
    (sched_scope == PTHREAD_SCOPE_SYSTEM) ? "PTHREAD_SCOPE_SYSTEM" :
    (sched_scope == PTHREAD_SCOPE_PROCESS) ? "PTHREAD_SCOPE_PROCESS" :
     "<unknown>");

  // Query and display the 'Scheduling Inheritance'
  if (pthread_attr_getinheritsched(attr, &sched_inh))
        WARN("pthread_attr_getinheritsched() failed.\n");
  printf(" Inheritance : %s\n",
    (sched_inh == PTHREAD_INHERIT_SCHED) ? "PTHREAD_INHERIT_SCHED" :
    (sched_inh == PTHREAD_EXPLICIT_SCHED) ? "PTHREAD_EXPLICIT_SCHED" :
     "<unknown>");

  // Query and display the 'Scheduling Policy'
  if (pthread_attr_getschedpolicy(attr, &sched_policy))
        WARN("pthread_attr_getschedpolicy() failed.\n");
  printf(" Policy : %s\n",
        (sched_policy == SCHED_FIFO)  ? "SCHED_FIFO" :
        (sched_policy == SCHED_RR)    ? "SCHED_RR" :
        (sched_policy == SCHED_OTHER) ? "SCHED_OTHER" :
         "<unknown>");

  // Query and display the 'Scheduling Priority'
  if (pthread_attr_getschedparam(attr, &sch_param))
        WARN("pthread_attr_getschedparam() failed.\n");
  printf(" Priority : %d\n", sch_param.sched_priority);
```

最后，线程栈属性被查询和显示：

```
//--- Thread Stack Attributes
  printf("Thread Stack \n");
  // Query and display the 'Guard Size'
  if (pthread_attr_getguardsize(attr, &guardsz))
        WARN("pthread_attr_getguardsize() failed.\n");
  printf(" Guard Size : %9zu bytes\n", guardsz);

  /* Query and display the 'Stack Size':
   * 'stack location' will be meaningless now as there is no
   * actual thread created yet!
   */
  if (pthread_attr_getstack(attr, &stackaddr, &stacksz))
        WARN("pthread_attr_getstack() failed.\n");
  printf(" Stack Size : %9zu bytes\n", stacksz);
}
```

在前面的代码中，我们使用`pthread_getattr_default_np(3)` API 来查询默认线程属性。它的对应物，`pthread_setattr_default_np(3)` API，允许您在创建线程时指定默认线程属性应该是什么，并且将第二个参数传递给`pthread_create(3)`。请参阅其手册以获取详细信息。

有一种编写类似程序的替代方法：为什么不创建一个带有 NULL 属性结构的线程，从而使其成为默认属性，然后使用`pthread_getattr_np(3)` API 来查询和显示实际的线程属性？我们把这留给读者作为一个练习（事实上，`pthread_attr_init(3)`的 man 页面提供了这样一个程序）。

# 连接

想象一个应用程序，其中一个线程（通常是`main`）产生了几个其他工作线程。每个工作线程都有特定的工作要做；一旦完成，它就会终止（通过`pthread_exit(3)`）。创建线程如何知道工作线程何时完成（终止）？啊，这正是连接的作用。通过连接，创建线程可以等待另一个线程在进程内终止。

这不是听起来非常像父进程发出的`wait(2)`系统调用等待子进程死亡吗？是的，但正如我们马上会看到的那样，它肯定不是完全相同的。

同样重要的是，终止的线程的返回值被传递给发出对其的连接的线程。这样，它就知道工作线程是否成功完成了它的任务（如果没有，失败的值可以被检查以找出失败的原因）：

```
#include <pthread.h>
int pthread_join(pthread_t thread, void **retval);
```

`pthread_join(3)`的第一个参数`thread`是要等待的线程的 ID。它终止时，调用线程将在第二个参数中接收到终止的线程的返回值（是的，这是一个值-结果风格的参数），这当然是通过其`pthread_exit(3)`调用传递的值。

因此，连接非常有帮助；使用这个结构，你可以确保一个线程可以阻塞在任何给定线程的终止上。特别是在`main`线程的情况下，我们经常使用这种机制来确保`main`等待所有其他应用程序线程在它自己终止之前终止（从而防止我们之前看到的僵尸）。这被认为是正确的方法。

回想一下，在前面的部分，“幽灵的回归”中，我们清楚地看到了`main`线程在其对应线程之前死亡，成为了一个无意识的僵尸（`ch14/pthreads3.c`程序）。建立在这个先前代码的快速示例将有助于澄清事情。所以，让我们增强那个程序 - 现在我们将它称为`ch14/pthreads_joiner1.c` - 以便我们的`main`线程通过调用`pthread_join(3)` API 等待所有其他线程死亡，然后自己终止：

```
int main(void)
{
  long i;
  int ret, stat=0;
  pthread_t tid[NTHREADS];
 pthread_attr_t attr;

  /* Init the thread attribute structure to defaults */
  pthread_attr_init(&attr);
  /* Create all threads as joinable */
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  // Thread creation loop
  for (i = 0; i < NTHREADS; i++) {
      printf("main: creating thread #%ld ...\n", i);
      ret = pthread_create(&tid[i], &attr, worker, (void *)i);
      if (ret)
          FATAL("pthread_create() failed! [%d]\n", ret);
  }
  pthread_attr_destroy(&attr);
```

这里有几件事情需要注意：

+   随后执行连接，我们需要每个线程的 ID；因此，我们声明了一个`pthread_t`的数组（`tid`变量）。每个元素将存储相应线程的 ID 值。

+   线程属性：

+   到目前为止，我们在创建线程时没有明确地初始化和使用线程属性结构。在这里，我们纠正了这个缺点。`pthread_attr_init(3)`用于初始化（为默认值）属性结构。

+   此外，我们通过在结构中设置这个属性（通过`pthread_attr_setdetachstate(3)` API）来明确地使线程可连接。

+   一旦线程被创建，我们必须销毁线程属性结构（通过`pthread_attr_destroy(3)` API）。

关键是要理解，只有将其分离状态设置为可连接的线程才能被连接。有趣的是，可连接的线程以后可以被设置为分离状态（通过调用`pthread_detach(3)` API）；没有相反的例程。

代码继续；现在我们向你展示线程`worker`函数：

```
void * worker(void *data)
{
      long datum = (long)data;
      int slptm=8;

      printf(" worker #%ld: will sleep for %ds now ...\n", datum, slptm);
      sleep(slptm);
      printf(" worker #%ld: work (eyeroll) done, exiting now\n", datum);

      /* Terminate with success: status value 0.
 * The join will pick this up. */
 pthread_exit((void *)0);
}
```

简单：我们让所谓的工作线程睡 8 秒然后死掉；这次，`pthread_exit(3)`传递`0`作为返回状态。在下面的代码片段中，我们继续`main`的代码：

```
  // Thread join loop
  for (i = 0; i < NTHREADS; i++) {
      printf("main: joining (waiting) upon thread #%ld ...\n", i);
      ret = pthread_join(tid[i], (void **)&stat);
      if (ret)
          WARN("pthread_join() failed! [%d]\n", ret);
      else
          printf("Thread #%ld successfully joined; it terminated with"
                 "status=%d\n", i, stat);
  }
  printf("\nmain: now dying... <Dramatic!> Farewell!\n");
  pthread_exit(NULL);
}
```

这是关键部分：在循环中，主线程通过`pthread_join(3)`API 阻塞（等待）每个工作线程的死亡；第二个（值-结果风格）参数实际上返回刚终止的线程的状态。遵循通常的成功返回零的约定，因此允许主线程判断工作线程是否成功完成工作。

让我们构建并运行它：

```
$ make pthreads_joiner1 
gcc -O2 -Wall -UDEBUG -c ../common.c -o common.o
gcc -O2 -Wall -UDEBUG -c pthreads_joiner1.c -o pthreads_joiner1.o
gcc -o pthreads_joiner1 pthreads_joiner1.o common.o -lpthread
$ ./pthreads_joiner1 
main: creating thread #0 ...
main: creating thread #1 ...
 worker #0: will sleep for 8s now ...
main: creating thread #2 ...
 worker #1: will sleep for 8s now ...
main: joining (waiting) upon thread #0 ...
 worker #2: will sleep for 8s now ...

*<< ... worker threads sleep for 8s ... >>*

 worker #0: work (eyeroll) done, exiting now
 worker #1: work (eyeroll) done, exiting now
 worker #2: work (eyeroll) done, exiting now
Thread #0 successfully joined; it terminated with status=0
main: joining (waiting) upon thread #1 ...
Thread #1 successfully joined; it terminated with status=0
main: joining (waiting) upon thread #2 ...
Thread #2 successfully joined; it terminated with status=0

main: now dying... <Dramatic!> Farewell!
$ 
```

当工作线程死亡时，它们被`main`线程通过`pthread_join`接收或加入；不仅如此，它们的终止状态-返回值-可以被检查。

好的，我们将复制前面的程序并将其命名为`ch14/pthreads_joiner2.c`。我们唯一的改变是，不是让每个工作线程睡眠相同的 8 秒，而是让睡眠时间动态变化。我们将更改代码；例如，这一行将被更改为：`sleep(slptm);`

新的一行将如下所示：`sleep(slptm-datum);`

在这里，`datum`是传递给线程的值-循环索引。这样，我们发现工作线程的睡眠如下：

+   工作线程＃0 睡眠（8-0）= 8 秒

+   工作线程＃1 睡眠（8-1）= 7 秒

+   工作线程＃2 睡眠（8-2）= 6 秒

显然，工作线程＃2 将首先终止；那又怎样？嗯，想想看：与此同时，`main`线程正在循环`pthread_join`，但是按照线程＃0，线程＃1，线程＃2 的顺序。现在，线程＃0 将最后死亡，线程＃2 将首先死亡。这会有问题吗？

让我们试一试：

```
$ ./pthreads_joiner2 
main: creating thread #0 ...
main: creating thread #1 ...
main: creating thread #2 ...
main: joining (waiting) upon thread #0 ...
 worker #0: will sleep for 8s now ...
 worker #1: will sleep for 7s now ...
 worker #2: will sleep for 6s now ... *<< ... worker threads sleep for 8s, 7s and 6s resp ... >>*
 worker #2: work (eyeroll) done, exiting now
 worker #1: work (eyeroll) done, exiting now
 worker #0: work (eyeroll) done, exiting now
Thread #0 successfully joined; it terminated with status=0
main: joining (waiting) upon thread #1 ...
Thread #1 successfully joined; it terminated with status=0
main: joining (waiting) upon thread #2 ...
Thread #2 successfully joined; it terminated with status=0

main: now dying... <Dramatic!> Farewell!
$ 
```

我们注意到什么？尽管工作线程＃2 首先死亡，但工作线程＃0 首先加入，因为在代码中，这是我们首先等待的线程！

# 线程模型加入和进程模型等待

到目前为止，您应该已经开始意识到，尽管`pthread_join(3)`和`wait(2)`（以及家族）API 似乎非常相似，但它们肯定不是等价的；它们之间存在几个差异，并在以下表中列举出来：

| **情况** | **线程：`pthread_join(3)`** | **进程：`waitpid`** |
| --- | --- | --- |
| 条件 | 等待的线程必须将其分离状态属性设置为可连接的，而不是分离的。 | 无；任何子进程都可以（实际上必须）等待（回想一下我们的*fork 规则＃7*） |
| 层次结构 | 无：任何线程都可以加入任何其他线程；没有父子关系的要求。实际上，我们不认为线程像进程那样严格存在父子关系；所有线程都是对等的。 | 存在严格的父子关系层次结构；只有父进程可以等待子进程。 |
| 顺序 | 使用线程时，必须强制加入（等待）指定为`pthread_join(3)`参数的特定线程。换句话说，如果有，比如说，三个线程在运行，主线程在一个升序循环中发出加入，那么它必须等待线程＃1 的死亡，然后是线程＃2，然后是线程＃3。如果线程＃2 提前终止，那就没办法了。 | 使用`wait`，进程可以等待（或停止）任何子进程的死亡，或者使用`waitpid`指定等待的特定子进程。 |
| 信号 | 在线程死亡时不发送信号。 | 在进程死亡时，内核向父进程发送`SIGCHLD`信号。 |

关于`pthread_join(3)`的另外一些要点如下：

+   您需要线程的线程 ID 才能加入它；这是故意这样做的，以便我们实际上只加入我们应用程序进程的线程。尝试加入其他线程（比如第三方库线程）将是糟糕的设计。

+   如果我们正在等待的线程（已经死亡）已经死亡了怎么办？然后`pthread_join(3)`立即返回。

+   如果一个线程试图加入自己会怎样？这会导致失败（`errno`设置为`EDEADLK`）。

+   试图让几个线程加入一个线程会导致未定义的行为；要避免这种情况。

+   如果一个试图连接到另一个线程的线程被取消（稍后会讨论），目标线程保持原样（可连接）。

# 检查生命，超时

有时，我们可能会遇到这样的情况，我们想要检查特定线程是否仍然存活；通过`pthread_tryjoin_np(3)` API 就可以做到这一点：

```
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <pthread.h>

int pthread_tryjoin_np(pthread_t thread, void **retval);
int pthread_timedjoin_np(pthread_t thread, void **retval,
                         const struct timespec *abstime);
```

`pthread_tryjoin_np(3)`的第一个参数是我们要连接的线程；（第二个参数和往常一样，是目标线程的终止状态）。注意 API 中的 try 短语 - 这通常指定调用是非阻塞的；换句话说，我们对目标线程执行非阻塞连接。如果目标线程仍然存活，那么 API 将立即返回错误：`errno`将被设置为`EBUSY`（手册页告诉我们，这意味着在调用时线程尚未终止）。

如果我们想要等待（阻塞）直到目标线程死亡，但不是永远？换句话说，我们想要等待一段给定的最长时间。这可以通过`pthread_timedjoin_np(3)` API 实现；前两个参数与`pthread_join`相同，而第三个参数指定了绝对时间的超时（通常称为 Unix 时间 - 自 1970 年 1 月 1 日午夜以来经过的秒数（和纳秒数） - 纪元！）。

如第十三章所述，*定时器*，`timespec`数据结构的格式如下：

```
 struct timespec {
     time_t tv_sec; /* seconds */
     long tv_nsec;  /* nanoseconds */
 };
```

这很简单；但是我们如何将时间指定为 UNIX 时间（或自纪元以来的时间）？我们建议读者参考`pthread_timedjoin_np(3)`的手册页，其中提供了一个简单的示例（同时，我们建议您尝试这个 API 作为练习）。

当使用`pthread_timedjoin_np(3)` API 时，我注意到另一件事：连接可能超时，然后继续释放一些资源，比如在工作线程仍然存活并使用它时执行`free(3)`在堆缓冲区上。这显然是一个错误；这也表明你必须仔细考虑和测试设计；通常，对所有工作线程执行阻塞连接，从而确保它们在释放资源之前已经全部终止，是正确的方法。

再次提醒您，API 的后缀`_np`表示它们是不可移植的（仅限 Linux）。

# 连接还是不连接？

一个明确设置为分离状态的线程不能被连接；那么当它死亡时会发生什么？它的资源将被库处理。

一个明确设置为可连接状态的线程（或者可连接是默认状态）必须被连接；否则会导致一种资源泄漏。所以要小心：如果你已经创建了可连接的线程，那么你必须确保连接已经完成。

通常认为，通过主线程对其他应用程序线程执行连接是最佳实践，因为这可以防止我们之前看到的僵尸线程行为。此外，对于创建线程来说，了解它的工作线程是否成功执行了任务，如果没有，原因是什么通常是很重要的。连接使所有这些成为可能。

然而，可能你的应用程序不想等待一些工作线程；在这种情况下，请确保将它们创建为分离状态。

# 参数传递

回想一下`pthread_create(3)` API 的签名：

`int pthread_create(pthread_t *thread, const pthread_attr_t *attr,`

`                    void *(*start_routine) **(void *), void *arg**);`

第三个参数是线程函数 - 实际上是新生线程的生命和范围。它接收一个类型为`void *`的参数；这个参数传递给新生线程的是通过第四个参数`pthread_create`传递的：`void *arg`。

正如前面提到的，它的数据类型是一个通用指针，这样我们就可以实际上将任何数据类型作为参数传递，然后在线程例程中适当地进行类型转换和使用。到目前为止，我们已经遇到了相同的简单用例 - 通常是将整数值作为参数传递。在我们的第一个简单的多线程应用程序`ch14/pthreads1.c`中，在我们的`main`函数中，我们做了以下操作：

```
long i;
int ret;
pthread_t tid;

for (i = 0; i < NTHREADS; i++) {
     ret = pthread_create(&tid, NULL, worker, (void *)i);
    ...
}
```

而在线程例程`worker`中，我们进行了简单的类型转换和使用：

```
void * worker(void *data)
{
 long datum = (long)data;
...
```

这很简单，但确实引发了一个非常明显的问题：在`pthread_create(3)` API 中，似乎只有一个占位符用于`arg`（参数），如何传递多个数据项 - 实际上是几个参数 - 给线程例程？

# 将结构作为参数传递

前面的标题揭示了答案：我们传递一个数据结构。但是，具体来说呢？为数据结构的指针分配内存，初始化它，并将指针强制转换为`void *`进行传递。（事实上，这是 C 程序员常用的方法。）在线程例程中，像往常一样，进行类型转换并使用它。

为了澄清，我们将尝试这个（`ch14/param_passing/struct_as_param.c`）：

为了可读性，只显示了源代码的关键部分；要查看完整的源代码，构建并运行它，整个树可以在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)*.*

```
/* Our data structure that we intend to pass as a parameter to the threads. City Airport information. */
typedef struct {
    char IATA_code[IATA_MAXSZ];
              /* http://www.nationsonline.org/oneworld/IATA_Codes/ */
    char city[CITY_MAXSZ];     /* city name */
    float latitude, longitude; /* coordinates of the city airport */
    unsigned int altitude;     /* metres */
  /* todo: add # runways, runway direction, radio beacons freq, etc etc */
    unsigned long reserved;    /* for future use */
} Airport; /* yes! the {lat,long,alt} tuple is accurate :-) */
static const Airport city_airports[3] = {
  { "BLR", "Bangalore International", 13.1986, 77.7066, 904, 0 },
  { "BNE", "Brisbane International", 27.3942, 153.1218, 4, 0 },
  { "BRU", "Brussels National", 50.9010, 4.4856, 58, 0 },
};
```

举个例子，我们构建了自己的机场信息数据结构 airport，然后设置了一个数组（`city_airports`），初始化了其中的一些成员。

在`main`函数中，我们声明了一个指向机场结构的指针数组；我们知道单独的指针没有内存，所以在线程创建循环中，我们为每个指针分配内存，然后将其初始化为一个机场（通过简单的`memcpy(3)`）：

```
  Airport * plocdata[NTHREADS];
...
  // Thread creation loop
  for (i = 0; i < NTHREADS; i++) {
      printf("main: creating thread #%ld ...\n", i);

      /* Allocate and initialize data structure to be passed to the
       * thread as a parameter */
       plocdata[i] = calloc(1, sizeof(Airport));
       if (!plocdata[i])
          FATAL("calloc [%d] failed\n", i);
       memcpy(plocdata[i], &city_airports[i], sizeof(Airport));

       ret = pthread_create(&tid[i], &attr, worker, (void *)plocdata[i]);
       if (ret)
          FATAL("pthread_create() index %d failed! [%d]\n", i, ret);
  }
```

好吧，我们已经知道前面的代码并不是真正的最佳选择；我们本可以只将`city_airports[i]`结构指针作为线程的参数传递。为了举例说明，我们使用刚刚分配的`plocdata[i]`结构，将一个结构`memcpy`到另一个结构中。

然后，在`pthread_create(3)`调用中，我们将指向我们数据结构的指针作为第四个参数传递。这将成为线程的参数；在线程例程中，我们声明一个相同数据类型的`arg`指针，并将其等同于我们接收到的类型转换数据指针：

```
void * worker(void *data)
{
 Airport * arg = (Airport *)data;
  int slptm=8;

  printf( "\n----------- Airports Details ---------------\n"
    " IATA code : %.*s %32s\n"
    " Latitude, Longitude, Altitude : %9.4f %9.4f %9um\n"
    , IATA_MAXSZ, arg->IATA_code,
    arg->city,
    arg->latitude, arg->longitude, arg->altitude);
...
```

然后我们可以将`arg`用作指向 Airport 的指针；在前面的演示代码中，我们只是打印了结构中的值。我们鼓励读者构建并运行此代码。

在前面的代码中，你注意到了`%.*s` C printf 格式说明符的技巧吗？当我们想要打印一个不一定以 NULL 结尾的字符串时，`%.*s`格式说明符允许我们指定大小，然后是字符串指针。字符串将只打印大小字节。

# 线程参数 - 不要这样做

将参数传递给线程例程时要牢记的关键事情是，必须保证传递的参数是线程安全的；基本上，在线程（或线程）使用它时不会以任何方式进行修改。

（线程安全是处理线程的一个关键方面；在接下来的章节中，我们将经常回顾这一点）。

为了更清楚地理解可能的问题，让我们举几个典型的例子。在第一个例子中，我们将尝试将循环索引作为参数传递给新创建的线程，比如在主函数中（代码：`ch14/pthreads1_wrong.c`）：

```
 printf("main: &i=%p\n", &i);
 for (i = 0; i < NTHREADS; i++) {
     printf("Creating thread #%ld now ...\n", i);
     ret = pthread_create(&tid, NULL, worker, (void *)&i);
     ...
}
```

你注意到了吗？我们将参数传递为`&i`。那么？在线程例程中正确解引用它应该仍然有效，对吧：

```
void * worker(void *data)
{
    long data_addr = (long)data;
    long index = *(long *)data_addr;
    printf("Worker thread: data_addr=%p value=%ld\n", 
            (void *)data_addr, index);
    pthread_exit((void *)0);
}
```

看起来不错 - 让我们试试看！

```
$ ./pthreads1_wrong
main: &i=0x7ffebe160f00
Creating thread #0 now ...
Creating thread #1 now ...
Worker thread: data_addr=0x7ffebe160f00 value=1
Creating thread #2 now ...
Worker thread: data_addr=0x7ffebe160f00 value=2
Worker thread: data_addr=0x7ffebe160f00 value=3 $ 
```

嗯，它有效。但等等，再试几次 - 时间巧合可能会让你误以为一切都很好，但实际上并非如此：

```
$ ./pthreads1_wrong
main: &i=0x7fff4475e0d0
Creating thread #0 now ...
Creating thread #1 now ...
Creating thread #2 now ...
Worker thread: data_addr=0x7fff4475e0d0 value=2
Worker thread: data_addr=0x7fff4475e0d0 value=2
Worker thread: data_addr=0x7fff4475e0d0 value=3
$ 
```

有一个错误！`index`的值已经两次评估为值`2`；为什么？仔细思考：我们已经通过引用将循环索引传递了 - 作为循环变量的指针。线程 1 启动，并查找其值 - 线程 2 也是如此，线程 3 也是如此。但等等：这里难道不可能存在竞争吗？难道不可能在线程 1 运行并查找循环变量的值时，它已经在其下发生了变化（因为，不要忘记，循环是在主线程中运行的）？当然，这正是在前面的代码中发生的。

换句话说，通过地址传递变量是不安全的，因为在它被读取（由工作线程）的同时被写入（由主线程）时，其值可能会发生变化；因此，它不是线程安全的，因此会出现错误（竞争）。

解决方案实际上非常简单：不要通过地址传递循环索引；只需将其作为文字值传递：

```
for (i = 0; i < NTHREADS; i++) {
     printf("Creating thread #%ld now ...\n", i);
     ret = pthread_create(&tid, NULL, worker, (void *)i);
    ...
}
```

现在，每个工作线程都收到了循环索引的副本，从而消除了任何竞争，使其安全。

现在，不要草率地得出结论，嘿，好吧，所以我们永远不应该将指针（地址）作为参数传递。当然可以！只要确保它是线程安全的 - 在主线程和其他应用线程操作它时，它的值不会在其下发生变化。

参考我们在上一节演示的`ch14/struct_as_param.c`代码；我们非常明确地将线程参数作为结构体的指针传递。仔细看：在主线程创建循环中，每个指针都是单独分配的（通过`calloc(3)`）。因此，每个工作线程都收到了结构体的副本；因此，一切都是安全的，而且运行良好。

一个有趣的练习（我们留给读者）是故意在`struct_as_param`应用程序中插入一个缺陷，方法是只分配一个结构（而不是三个），并将其传递给每个工作线程。这次，它将是竞争的，并且（最终）会失败。

# 线程堆栈

我们知道，每当创建一个线程时，它都会为其堆栈获取一个新的、新分配的内存块。这导致了这样的理解：（显然，但我们还是要说明）在线程函数中声明的所有局部变量都将保持私有，因为它们将驻留在该线程的堆栈中。（参考本章中的*图 2* - 新创建线程的新堆栈显示为红色）。此外，每当发生上下文切换时，**堆栈指针**（**SP**）寄存器会更新为指向当前线程的堆栈。

# 获取和设置线程堆栈大小

了解并能够更改线程堆栈的大小很重要（请参阅 GitHub 存储库中*进一步阅读*部分提供的链接，其中提到了如何设置某个平台的堆栈太小导致了随机且难以调试的故障的真实经验）。

那么，默认的线程堆栈大小是多少？答案已经提供了；回想一下我们在本章前面运行的`disp_defattr_pthread`程序（在*代码示例 - 查询默认线程属性*部分）：它告诉我们，在（现代 NPTL）Linux 平台上，默认的线程堆栈大小为 8 MB。

pthread API 集提供了一些例程来设置和查询线程堆栈大小。一种方法如下：

```
#include <pthread.h>
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
int pthread_attr_getstacksize(const pthread_attr_t *attr, 
                              size_t *stacksize);
```

由于我们之前已经在早期的`disp_defattr_pthread`程序中使用了`pthread_attr_getstacksize(3)`，我们将避免在这里再次展示它的用法。使用互补的`pthread_attr_setstacksize(3)` API 可以轻松设置线程大小-第二个参数是所需的大小（以字节为单位）。不过，这两个 API 都包含`_attr_`短语，这意味着栈大小实际上是从线程属性结构中设置或查询的，而不是从活动线程本身。这使我们了解到我们只能在创建线程时通过设置属性结构（当然，随后作为第二个参数传递给`pthread_create(3)`）来设置或查询栈大小。一旦线程被创建，其栈大小就无法更改。这条规则的例外是主线程的栈。

# 栈位置

线程栈实际上位于内存中的哪个位置（从技术上讲，给定进程的 VAS 中的哪个位置）？以下几点有助于我们理解：

+   主线程的栈总是位于进程 VAS 的顶部。

+   进程中所有其他线程的栈位于进程堆段和主栈之间的某个位置；这个具体位置对应用程序开发人员来说事先是未知的；无论如何，我们不应该需要知道。

+   这与直接相关，但很重要：回想一下第二章，“虚拟内存”中提到，对于大多数处理器，栈符合栈向下增长的语义；也就是说，栈段的增长方向是朝着较低的虚拟地址。

虽然我们不应该需要，但是有没有一种方法可以指定线程栈的位置？如果你坚持的话，是的：`pthread_attr_[get|set]stack(3)` API 可以用于此目的，以及设置和/或查询线程栈的大小：

```
#include <pthread.h>
int pthread_attr_setstack(pthread_attr_t *attr,
                           void *stackaddr, size_t stacksize);
int pthread_attr_getstack(const pthread_attr_t *attr,
                           void **stackaddr, size_t *stacksize);
```

虽然您可以使用`pthread_attr_setstack`来设置栈位置，但建议将此工作留给操作系统。此外，如果您确实使用它，还建议栈位置`stackaddr`和栈大小`stacksize`都是系统页面大小的倍数（并且位置对齐到页面边界）。通过`posix_memalign(3)` API 可以轻松实现将线程栈对齐到页面边界（我们已经在第四章，“动态内存分配”中涵盖了此 API 的示例用法）。

要小心：如果您在线程属性结构中指定栈位置，并且在循环中创建线程（这是正常的方式），您必须确保每个线程都接收到唯一的栈位置（通常通过通过前述的`posix_memalign(3)`分配栈内存，然后将其返回值作为栈位置传递）。当然，将用于线程栈的内存页面必须具有读写权限（回想一下第四章，“动态内存分配”中的`mprotect(2)`）。

说了这么多，设置和查询线程栈的机制是直截了当的；真正关键的一点是：（强调）测试您的应用程序，以确保提供的线程栈内存是足够的。正如我们在第十一章，“信号-第一部分”中看到的，栈溢出是一个严重的缺陷，并将导致未定义的行为。

# 栈保护

这很好地引出了下一个问题：有没有一种方法可以让应用程序知道堆栈内存处于危险之中，或者说，已经溢出了？确实有：堆栈保护。保护内存是一个或多个虚拟内存页面的区域，它被故意放置，并且具有适当的权限，以确保任何尝试访问该内存都会导致失败（或某种警告；例如，`SIGSEGV`的信号处理程序可以提供这样的语义-但要注意一旦收到 SIGSEGV，我们就处于未定义状态，必须终止；但至少我们会知道并且可以修复堆栈大小！）：

```
#include <pthread.h>
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize);
int pthread_attr_getguardsize(const pthread_attr_t *attr, 
                               size_t *guardsize);
```

保护区是在线程堆栈末尾分配的额外内存区域，其大小为指定的字节数。默认（保护）大小是系统页面大小。再次注意，保护大小是线程的一个属性，因此只能在线程创建时（而不是以后）指定。我们将运行（代码：`ch14/stack_test.c`）这样的应用程序：

```
$ ./stack_test 
Usage: ./stack_test size-of-thread-stack-in-KB
$ ./stack_test 2560
Default thread stack size       : 8388608 bytes
Thread stack size now set to    : 2621440 bytes
Default thread stack guard size :    4096 bytes

main: creating thread #0 ...
main: creating thread #1 ...
main: creating thread #2 ...
 worker #0:
main: joining (waiting) upon thread #0 ...
 worker #1:

 *** In danger(): here, sizeof long is 8
 worker #2:
Thread #0 successfully joined; it terminated with status=1
main: joining (waiting) upon thread #1 ...
dummy(): parameter val = 115709118
Thread #1 successfully joined; it terminated with status=0
main: joining (waiting) upon thread #2 ...
Thread #2 successfully joined; it terminated with status=1
main: now dying... <Dramatic!> Farewell!
$ 
```

在前面的代码中，我们将 2,560 KB（2.5 MB）指定为线程堆栈大小。尽管这远低于默认值（8 MB），但事实证明足够了（至少对于 x86_64 来说，一个快速的粗略计算显示，对于给定的程序参数，我们将需要为每个线程堆栈分配至少 1,960 KB）。

在下面的代码中，我们再次运行它，但这次将线程堆栈大小指定为仅 256 KB：

```
$ ./stack_test 256
Default thread stack size       : 8388608 bytes
Thread stack size now set to    :  262144 bytes
Default thread stack guard size :    4096 bytes

main: creating thread #0 ...
main: creating thread #1 ...
 worker #0:
main: creating thread #2 ...
 worker #1:
main: joining (waiting) upon thread #0 ...
Segmentation fault (core dumped)
$ 
```

正如预期的那样，它导致段错误。

使用 GDB 检查核心转储将揭示关于为什么发生段错误的许多线索-包括非常重要的线程堆栈的状态（实际上是堆栈`回溯`）在崩溃时。然而，这超出了本书的范围。

我们绝对鼓励您学习使用诸如 GDB 这样强大的调试器（请参见 GitHub 存储库上的*进一步阅读*部分）。

此外（至少在我们的测试系统上），内核会向内核日志中发出有关此崩溃的消息；查找内核日志消息的一种方法是通过方便的实用程序`dmesg(1)`。以下输出来自 Ubuntu 18.04 框：

```
$ dmesg [...]
kern :info : [*<timestamp>*] stack_test_dbg[27414]: segfault at 7f5ad1733000 ip 0000000000400e68 sp 00007f5ad164aa20 error 6 in stack_test_dbg[400000+2000]
$ 
```

前面应用程序的代码可以在这里找到：`ch14/stack_test.c`：

为了便于阅读，只显示了源代码的关键部分；要查看完整的源代码，构建并运行它，整个树都可以从 GitHub 克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
int main(int argc, char **argv)
{
[...]
  stack_set = atoi(argv[1]) * 1024;
[...]
  /* Init the thread attribute structure to defaults */
  pthread_attr_init(&attr);
[...]
  /* Set thread stack size */
  ret = pthread_attr_setstacksize(&attr, stack_set);
  if (ret)
      FATAL("pthread_attr_setstack(%u) failed! [%d]\n", TSTACK, ret);
  printf("Thread stack size now set to : %10u bytes\n", stack_set);
[...]
```

在`main`中，我们展示了线程堆栈大小属性被初始化为用户传递的参数（以 KB 为单位）。然后代码继续创建三个工作线程，然后等待它们。

在线程工作例程中，我们只有线程＃2 执行一些实际工作-你猜对了，是堆栈密集型工作。这段代码如下：

```
void * worker(void *data)
{
  long datum = (long)data;

  printf(" worker #%ld:\n", datum);
  if (datum != 1)
      pthread_exit((void *)1);

 danger(); ...
```

`danger`函数，当然，是进行这项危险的、潜在的堆栈溢出工作的函数：

```
static void danger(void)
{
#define NEL    500
  long heavylocal[NEL][NEL], alpha=0;
  int i, j;
  long int k=0;

  srandom(time(0));

  printf("\n *** In %s(): here, sizeof long is %ld\n",
          __func__, sizeof(long));
  /* Turns out to be 8 on an x86_64; so the 2d-array takes up
   * 500 * 500 * 8 = 2,000,000 ~= 2 MB.
   * So thread stack space of less than 2 MB should result in a segfault.
   * (On a test box, any value < 1960 KB = 2,007,040 bytes,
   * resulted in segfault).
   */

  /* The compiler is quite intelligent; it will optimize away the
   * heavylocal 2d array unless we actually use it! So lets do some
   * thing with it...
   */
  for (i=0; i<NEL; i++) {
      k = random() % 1000;
      for (j=0; j<NEL-1; j++)
 heavylocal[i][j] = k;
      /*printf("hl[%d][%d]=%ld\n", i, j, (long)heavylocal[i][j]);*/
  }

  for (i=0; i<NEL; i++)
      for (j=0; j<NEL; j++)
          alpha += heavylocal[i][j];
  dummy(alpha);
}
```

前面的函数使用大量（线程）堆栈空间，因为我们声明了一个名为`heavylocal`的本地变量-一个`NEL*NEL`元素（`NEL=500`）的二维数组。在一个占用 8 字节的 x86_64 上，这大约相当于 2 MB 的空间！因此，将线程堆栈大小指定为小于 2 MB 的任何值应该导致堆栈溢出（堆栈保护内存区域实际上将检测到这一点），因此导致分段违规（或段错误）；这正是发生的事情（正如您在我们的试运行中所看到的）。

有趣的是，如果我们仅声明本地变量但实际上没有使用它，现代编译器将会优化代码；因此，在代码中，我们努力对`heavylocal`变量进行一些（愚蠢的）使用。

关于堆栈保护内存区域的一些额外要点，以结束本讨论，如下：

+   如果应用程序使用了`pthread_attr_setstack(3)`，这意味着它正在自行管理线程堆栈内存，并且任何保护大小属性都将被忽略。

+   保护区域必须对齐到页面边界。

+   如果保护内存区域的大小小于一页，实际（内部）大小将会被舍入到一页；`pthread_attr_getguardsize(3)`返回理论大小。

+   `pthread_attr_[get|set]guardsize(3)`的 man 页面提供了额外信息，包括实现中可能存在的 glibc 错误。

# 摘要

本章是关于在 Linux 平台上编写多线程应用程序的三章中的第一章。在这里，我们涵盖了两个关键领域：第一个是关于关于线程的重要概念，我们将其与进程模型进行了对比（我们在第九章*进程执行*和第十章*进程创建*中学习过）。我们详细介绍了为什么你会更喜欢多线程设计，并包括了三个例子。通过这种方式，我们展现了使用多线程设计方法的动机。

本章的第二部分着重介绍了实际的 pthread API（及其相关概念），我们如何创建线程，可以创建多少个线程以及应该创建多少个线程也有所讨论。还涉及了线程终止的基础知识，线程属性，向新创建的线程传递参数，什么是加入以及如何执行加入，最后还介绍了如何操纵线程堆栈（和堆栈保护）的细节。展示了许多示例程序来帮助巩固所学的概念。

在下一章中，我们将专注于另一个编写强大且安全的多线程软件的关键方面——并发性、竞争、临界区、死锁（及其避免）和原子性；我们如何使用互斥锁（及其变体）以及条件变量来处理这些问题。


# 第十五章：使用 Pthreads 进行多线程编程第二部分-同步

多线程强大并且在性能上产生巨大影响的一个关键原因是它适用于并行或并发的概念；根据我们在之前的[第十四章]中学到的，*使用 Pthreads 进行多线程编程第一部分-基础*，我们了解到一个进程的多个线程可以（而且确实）并行执行。在大型多核系统上（多核现在几乎是标准，即使在嵌入式系统中），效果会被放大。

然而，正如经验告诉我们的那样，总是存在权衡。并行性带来了丑陋的竞争和随后的缺陷的潜在可能。不仅如此，这种情况通常变得极其难以调试，因此也难以修复。

在本章中，我们将尝试：

+   让读者了解并发（竞争）缺陷的位置和具体内容

+   如何通过良好的设计和编码实践在多线程应用程序中避免这些问题

同样，本章分为两个广泛的领域：

+   在第一部分中，我们清楚地解释了问题，比如原子性的重要性和死锁问题。

+   在本章的后半部分，我们将介绍 pthread API 集提供给应用程序开发人员的锁定（和其他）机制，以帮助解决和完全避免这些问题。

# 竞争问题

首先，让我们尝试理解我们试图解决的问题是什么以及问题的确切位置。在上一章中，我们了解到一个进程的所有线程除了堆栈之外都共享一切；每个线程都有自己的私有堆栈内存空间。

仔细再看一下[第十四章]，*使用 Pthreads 进行多线程编程第一部分-基础：图 2*（省略内核内容）；虚拟地址空间-文本和数据段，但不包括堆栈段-在一个进程的所有线程之间共享。数据段当然是全局和静态变量所在的地方。

冒着过分强调这些事实的风险，这意味着给定进程的所有线程真正（如果不可能，则使 COW 也成为正常字体而不是**写时复制**（COW））共享以下内容：

+   文本段

+   数据段-初始化数据，未初始化数据（之前称为 BSS）和堆段

+   几乎所有由操作系统维护的进程的内核级对象和数据（再次参考[第十四章]，*使用 Pthreads 进行多线程编程第一部分-基础*：图 2*）

一个非常重要的理解点是共享文本段根本不是问题。为什么？文本是代码；机器代码-构成我们所谓的机器语言的操作码和操作数-驻留在这些内存页中。回想一下[第二章]，*虚拟内存*，所有文本（代码）的页面都具有相同的权限：**读-执行**（r-x）。这很重要，因为多个线程并行执行文本（代码）不仅是可以的-而且是鼓励的！毕竟，这就是并行性的全部意义。想想看；如果我们只读取和执行代码，我们不以任何方式修改它；因此，即使在并行执行时，它也是完全安全的。

另一方面，数据页的权限为**读-写**（rw）。这意味着一个线程 A 与另一个线程 B 并行工作在一个数据页上时是固有的危险。为什么？这是相当直观的：它们可能会破坏页面内的内存值。（可以想象两个线程同时写入全局链表，例如。）关键点是，共享的可写内存必须受到保护，以防止并发访问，以便始终保持数据完整性。

要真正理解为什么我们如此关心这些问题，请继续阅读。

# 并发和原子性

并发执行意味着多个线程可以在多个 CPU 核心上真正并行运行。当这在文本（代码）上发生时，这是好事；我们获得了更高的吞吐量。然而，一旦我们在处理共享可写数据时并发运行，我们将遇到数据完整性的问题。这是因为文本是只读的（和可执行的），而数据是可读写的。

当然，我们真正想要的是贪婪地同时拥有两全其美的情况：通过多个线程并发执行代码，但是在必须处理共享数据的时候停止并发（并行），并且只有一个线程按顺序运行数据部分，直到完成，然后恢复并行执行。

# 教学银行账户示例

一个经典（教学）例子是有缺陷的银行账户软件应用。想象一下，卡卢尔（不用说，这里使用了虚构的名字和数字），一个自由职业的雕塑家，有一个银行账户；他目前的余额是 12000.00 美元。同时发生了两笔交易，分别是 3000 美元和 8000 美元的存款，这是他成功完成工作的付款。毫无疑问，很快，他的账户余额应该反映出 23000.00 美元的金额（假设没有其他交易）。

为了这个例子，让我们想象银行软件应用是一个多线程进程；为了保持简单，我们考虑一个线程被分派来处理一个交易。软件运行的服务器系统是一台强大的多核机器——它有 12 个 CPU 核心。当然，这意味着线程可以同时在不同的核心上并行运行。

因此，让我们想象一下，对于卡卢尔的每一笔交易，我们都有一个线程在运行来执行它——线程 A 和线程 B。线程 A（在 CPU＃0 上运行）处理 3000 美元的第一笔存款，而线程 B（在 CPU＃1 上运行）处理（几乎立即的）8000 美元的第二笔存款。

我们在这里考虑两种情况：

+   偶然情况下，交易成功进行。下图清楚地显示了这种情况：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/d972a362-4cc9-438d-b07a-427fa3231681.png)

图 1：银行账户；由于偶然而正确

+   再次偶然情况下，交易不成功进行。下图显示了这种情况：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/286e0061-b9fd-4086-b167-6d94cd2df5c1.png)

图 2：银行账户；由于偶然而不正确

在前面的表格中，问题区域已经被突出显示：很明显，线程 B 已经对余额进行了无效读取——它读取了 12000 美元的陈旧值（**t4 时刻**的值），而不是获取实际的当前值 15000 美元，导致卡卢尔损失了 3000 美元。

这是怎么发生的？简而言之，竞争条件导致了问题。要理解这场竞赛，请仔细看前面的表格并想象活动：

+   代表账户当前余额的变量；余额是全局的：

+   它位于数据段中

+   它被进程的所有线程共享

+   **在 t3 时刻**，**CPU＃0 上的线程 A**：存款 3000 美元；`余额`仍然是 12000 美元（尚未更新）

+   **在 t4 时刻**，**CPU＃1 上的线程 B**：存款 8000 美元；余额仍然是 12000 美元（尚未更新）

+   **在 t5 时刻**：

+   CPU＃0 上的线程 A：更新余额

+   同时，但在另一个核心上：

+   CPU＃1 上的线程 B：更新余额

+   偶然情况下，如果线程 B 在 CPU＃1 上比线程 A 在 CPU＃0 上更新`余额`变量早了几微秒！？

+   然后，线程 B 读取余额为 12000 美元（少了 3000 美元！）这被称为脏读，是问题的核心。这种情况被称为竞争；竞争是一种结果不确定和不可预测的情况。在大多数情况下，这将是一个问题（就像这里一样）；在一些罕见的情况下，这并不重要，被称为良性竞争。

需要强调的事实是，存款和更新余额（或相反，取款和更新余额）的操作必须保证是原子的。它们不能竞争，因为那将是一个缺陷（错误）。

短语原子操作（或原子性）在软件编程上下文中意味着一旦开始，操作将在没有中断的情况下完成。

# 临界区

我们如何修复前面的竞争？这实际上非常简单：我们必须确保，如前所述，银行操作 - 存款、取款等 - 被保证执行两件事：

+   成为在那个时间点上运行代码的唯一线程

+   原子性 - 完成，不中断

一旦实现了这一点，共享数据将不受损坏。必须以前述方式运行的代码部分称为临界区。

在我们虚构的银行应用程序中，运行执行银行操作（存款或取款）的线程必须在临界区中执行，如下所示：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/4f210b98-b336-46d2-b12e-96597699f140.png)

图 3：临界区

现在，假设银行应用程序已经根据这些事实进行了更正；线程 A 和线程 B 的垂直时间线执行路径现在如下：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/6e4698e1-51d8-4dec-914b-66b6eaf8efd4.png)

图 4：正确的银行应用程序 - 临界区

在这里，一旦线程 A 和线程 B 开始它们的（存款）操作，它们就会独自完成（不中断）；因此，按顺序和原子方式。

总结一下：

+   临界区是必须的代码：

+   在处理一些共享资源（如全局数据）时，不受其他线程的干扰运行

+   原子地运行（完成，不中断）

+   如果临界区的代码可以与其他线程并行运行，这是一个缺陷（错误），称为竞争。

+   为了防止竞争，我们必须保证临界区的代码独立和原子地运行

+   为此，我们必须同步临界区

现在，问题是：我们如何同步临界区？继续阅读。

# 锁定概念

软件中有几种形式的同步；其中一种常见的形式，也是我们将要大量使用的一种，称为**锁定**。在编程术语中，锁，如应用程序开发人员所见，最终是作为变量实例化的数据结构。

当需要临界区时，只需将临界区的代码封装在锁和相应的解锁操作之间。（现在，不要担心代码级 API 细节；我们稍后会涵盖。在这里，我们只关注正确理解概念。）

让我们表示临界区，以及同步机制 - 锁 - 使用图表（前述*图 3*的超集）：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/6889d1bb-3e14-4d0c-9c7a-12ca130fe2ea.png)

图 5：带锁的临界区

锁的基本前提如下：

+   在任何给定时间点，只有一个线程可以持有或拥有锁；该线程是锁的所有者。

+   在解锁时，当多个线程尝试获取或获取锁时，内核将保证只有一个线程会获取锁。

+   获得锁的线程称为赢家（或锁的所有者）；尝试但未获得锁的线程称为失败者。

因此，想象一下：假设我们有三个线程 A、B 和 C，在不同的 CPU 核心上并行运行，都试图获取锁。锁的保证是确切地有一个线程得到它 - 假设线程 C 获胜，获取锁（因此线程 C 是锁的赢家或所有者）；线程 A 和 B 是失败者。之后会发生什么？

+   赢家线程将锁操作视为非阻塞调用；它继续进入临界区（可能在处理一些共享可写资源，如全局数据）。

+   失败的线程将锁操作视为阻塞调用；他们现在阻塞（等待），但究竟在等待什么？（回想一下，阻塞调用是指我们等待事件发生并在事件发生后解除阻塞。）嗯，当然是解锁操作！

+   获胜的线程在（原子地）完成临界区后执行解锁操作。

+   现在线程 A 或 B 将获得锁，整个序列重复。

更一般地说，我们现在可以理解为：如果有 N 个线程竞争一个锁，那么锁操作（由操作系统）的保证是只有一个线程——获胜者——会获得锁。因此，我们将有一个获胜者和 N-1 个失败者。获胜的线程进入临界区的代码；与此同时，所有 N-1 个失败者线程等待（阻塞）解锁操作。在将来的某个时刻（希望很快），获胜者执行解锁操作；这将重新触发整个序列：N-1 个失败者再次竞争锁；我们将有一个获胜者和 N-2 个失败者；获胜的线程进入临界区的代码。与此同时，所有 N-2 个失败者线程等待（阻塞）解锁操作，依此类推，直到所有失败者线程都成为获胜者并因此运行了临界区的代码。

# 它是原子的吗？

关于对临界区进行原子执行的必要性的前述讨论可能会让您，程序员，感到担忧：也许您正在想，如何才能识别临界区？嗯，这很容易：如果您有并行性的潜力（多个线程可以并行运行通过代码路径）并且代码路径正在处理某些共享资源（通常是全局或静态数据），那么您就有一个临界区，这意味着您将通过锁定来保护它。

一个快速的经验法则：在大多数情况下，多个线程将通过代码路径运行。因此，从一般意义上讲，任何一种可写的共享资源的存在——全局变量、静态变量、IPC 共享内存区域，甚至是表示设备驱动程序中硬件寄存器的数据项——都会使代码路径成为临界区。规则是：保护它。

我们在上一节中看到的虚构的银行账户示例清楚地表明，我们有一个需要保护的临界区（通过锁定）。然而，有些情况下，我们可能并不清楚是否确实需要锁定。举个例子：在一个多线程的 C 应用程序中，我们有一个全局整数`g`；在某个时刻，我们增加它的值，比如：`g++`。

看起来很简单，但等等！这是一个可写的共享资源——全局数据；多个线程可能会并行运行这段代码，因此它成为一个需要保护的临界区（通过锁）。是的？还是不是？

乍一看，简单的增量（或减量）操作可能看起来是原子的（回想一下，原子操作是指在没有中断的情况下完成），因此不需要通过锁或任何其他形式的同步进行特殊保护。但事实真的是这样吗？

在我们继续之前，还有一个关键事实需要注意，那就是，现代微处理器上唯一保证原子性的是单个机器语言指令。每当一个机器指令完成后，CPU 上的控制单元会检查是否需要处理其他事情，通常是硬件中断或（软件）异常条件；如果需要，它会将程序计数器（IP 或 PC）设置为该地址并进行分支；如果不需要，执行将继续顺序进行，PC 寄存器将适当递增。

因此，请仔细考虑这一点：增量操作`g++`是否原子取决于两个因素：

+   正在使用的微处理器的指令集架构（ISA）（更简单地说，这取决于 CPU 本身）

+   该处理器的 C 编译器如何生成代码

如果编译器为`g++` C 代码生成了单个机器语言指令，那么执行确实是原子的。但是真的吗？让我们找出来！（实证的重要性——实验，尝试事物——是一个关键特征；我们的第十九章，*故障排除和最佳实践*，涵盖了更多这样的要点）。

一个非常有趣的网站，[`godbolt.org`](https://godbolt.org)（屏幕截图将随后出现），允许我们看到各种编译器如何编译给定的高级语言代码（在撰写本书时，它支持 14 种语言，包括 C 和 C++，以及各种编译器，当然包括 gcc(1)和 clang(1)。有趣的是，将语言下拉菜单设置为 C++后，还可以通过 gcc 为 ARM 进行编译！）。

让我们从访问这个网站开始，然后进行以下操作：

1.  通过下拉菜单选择 C 作为语言

1.  在右窗格中，选择编译器为 x86_64 gcc 8.2

1.  在左窗格中，输入以下程序：

```
int g=41;
int main(void)
{
    g ++;
}
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/f940d6e7-d28a-428c-9dcf-8d4dc50c6c5c.png)

图 6：通过 x86_64 上的 gcc 8.2 进行 g++增量，无优化

看看右窗格——可以看到编译器生成的汇编语言（当然，随后将成为与处理器 ISA 相对应的机器代码）。那么呢？请注意，`g++` C 高级语言语句在其左窗格中以淡黄色突出显示；右窗格中使用相同的颜色突出显示相应的汇编。有什么明显的发现吗？单行 C 代码`g++`已经变成了四条汇编语言指令。因此，根据我们之前的学习，这段代码本身不能被认为是原子的（但我们当然可以使用锁来强制它成为原子）。

下一个实验：保持一切不变，只是注意到在右窗格中有一个文本小部件，你可以在其中输入传递给编译器的选项开关；我们输入`-O2`，表示我们希望编译器使用优化级别 2（一个相当高的优化级别）。现在，输出为：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/78e01152-0b99-40e6-a4d1-0271a63ff19b.png)

图 7：通过 x86_64 上的 gcc 8.2 进行 g++增量，优化级别 2

`g++` C 代码现在只剩下一个汇编指令，因此确实变成了原子的。

使用 ARM 编译器，没有优化，`g++`转换为几行汇编——显然不是原子的：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/9e172c33-992a-4810-9189-6d1ea542a5ca.png)

图 8：通过 ARM 上的 gcc 7.2.1 进行 g++增量，无优化

我们的结论？对于应用程序来说，我们编写的代码通常很重要，要跨（CPU）架构保持可移植性。在前面的例子中，我们清楚地发现，编译器为简单的`g++`操作生成的代码有时是原子的，有时不是。（这将取决于几个因素：CPU 的 ISA，编译器，以及它编译的优化级别`-On`等等。）因此，我们唯一可以得出的安全结论是：要安全，并且无论何时存在关键部分，都要保护它（使用锁或其他手段）。

# 脏读

许多对这些主题新手的程序员会做出一个致命的假设，认为类似这样：好吧，我明白了，当修改共享资源——比如全局数据结构——时，我将需要将代码视为关键部分，并用锁来保护它，但是，我的代码只是在全局链表上进行迭代；它只是读取它而不是写入它，因此，这不是一个关键部分，不需要保护（我甚至会因高性能而得到好处）。

请打破这个泡泡！这是一个关键部分。为什么？想象一下：当您的代码在全局链表上进行迭代（仅读取它）时，正因为您没有采取锁定或以其他方式进行同步，另一个写入线程很可能正在写入数据结构，而您正在读取它。想一想：这是一场灾难的预兆；您的代码很可能最终会读取过时或不一致的数据。这就是所谓的*脏读*，当您不保护关键部分时，它可能发生。实际上，这正是我们虚构的银行应用示例中的缺陷。

再次强调这些事实：

+   如果代码正在访问任何类型的可写共享资源，并且存在并行性的潜力，那么它就是一个关键部分。保护它。

+   这些的一些副作用包括：

+   如果您的代码确实具有并行性，但仅适用于局部变量，则没有问题，这不是关键部分。（记住：每个线程都有自己的私有堆栈，因此在没有显式保护的情况下使用局部变量是可以的。）

+   如果全局变量标记为`const`，那当然没问题——它是只读的，在任何情况下。

（尽管在 C 语言中，const 关键字实际上并不保证值确实是常量（通常理解的常量）！它只意味着变量是只读的，但它所引用的数据仍然可以在另一个指针从下面访问时被更改，使用宏而不是 const 关键字可能有所帮助）。

正确使用锁定有一个学习曲线，可能比其他编程结构陡峭一些；这是因为，首先必须学会识别关键部分，因此需要锁定（在前一节中介绍），然后学习和使用良好的设计锁定指南，第三，理解并避免令人讨厌的死锁！

# 锁定指南

在本节中，我们将提出一组小而重要的启发式或指导原则，供开发人员在设计和实现使用锁的多线程代码时牢记。这些可能适用于特定情况，也可能不适用；通过经验，人们学会在适当的时候应用正确的指导原则。

话不多说，它们在这里：

+   **保持锁定粒度足够细**：锁定数据，而不是代码。

+   **简单是关键**：涉及多个锁和线程的复杂锁定方案不仅会导致性能问题（极端情况是死锁），还会导致其他缺陷。保持设计尽可能简单始终是一个好的实践。

+   **预防饥饿**：持有锁定的时间任意长会导致失败者线程饿死；必须设计——并确实测试——以确保，作为一个经验法则，每个关键部分（在 lock 和 unlock 操作之间的代码）尽快完成。良好的设计确保代码关键部分不会花费太长时间；在锁定中使用超时是缓解这个问题的一种方法（稍后详细介绍）。

+   还要了解锁定会产生瓶颈。锁定的良好物理类比如下：

+   漏斗：将漏斗的茎视为关键部分——它只宽到足够容纳一个线程通过（赢家）；失败者线程则保持阻塞在漏斗口

+   多车道繁忙公路上的一个收费站

因此，避免长时间的关键部分是关键：

+   将同步构建到设计中，并避免诱惑，比如，好吧，我先写代码，然后再回来看锁定。通常情况下效果不佳；锁定本身就很复杂；试图推迟其正确的设计和实现只会加剧问题。

让我们更详细地检查这些观点中的第一个。

# 锁定粒度

在应用程序中工作时，假设有几个地方需要通过锁定来保护数据，换句话说，有几个关键部分：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/58bff04b-3089-46aa-99d8-fc7cbb9fa098.png)

图 9：具有几个关键部分的时间线

我们已经在时间线上用实心红色矩形显示了关键部分（正如我们所学到的，需要同步锁定）。开发人员可能会意识到，为什么不简化一下呢？只需在 t1 时刻获取一个锁，然后在 t6 时刻解锁它：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/ca5dea18-639b-404e-91db-dda609ef947a.png)

图 10：粗粒度锁定

这将保护所有的关键部分。但这是以性能为代价的。想想看；每次一个线程运行前面的代码路径时，它必须获取锁，执行工作，然后解锁。这没问题，但并行性呢？它实际上被打败了；从 t1 到 t6 的代码现在被序列化了。这种过度放大的锁定所有关键部分的行为被称为粗粒度锁定。

回想我们之前的讨论：代码（文本）从来不是问题——根本不需要在这里锁定；只需锁定可写共享数据的地方。这些就是关键部分！这就产生了细粒度锁定——我们只在关键部分开始的时候获取锁，并在结束的时候解锁；以下图表反映了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/0bc4c06e-a618-4dad-8f18-263f0b664697.png)

图 11：细粒度锁定

正如我们之前所述，一个好的经验法则是锁定数据，而不是代码。

超细粒度锁定总是最好的吗？也许不是；锁定是一个复杂的业务。实际工作表明，有时即使在代码上工作（纯文本——关键部分之间的代码），持有锁也是可以的。这是一个平衡的行为；开发人员理想情况下应该利用经验和试错来判断锁定的粒度和效率，不断测试和重新评估代码路径的健壮性和性能。

在任何方向上走得太远都可能是一个错误；锁定粒度太粗会导致性能不佳，但粒度太细也是如此。

# 死锁及其避免

死锁是一种不希望发生的情况，其中相关线程无法再取得进展。死锁的典型症状是应用程序（或设备驱动程序或任何其他软件）似乎“挂起”。

# 常见的死锁类型

思考一些典型的死锁场景将有助于读者更好地理解。回想一下，锁的基本前提是只能有一个赢家（获得锁的线程）和 N-1 个输家。另一个关键点是只有赢家线程才能执行解锁操作，没有其他线程可以这样做。

# 自死锁（重新锁定）

了解了上述信息，想象一下这种情况：有一个锁（我们称之为 L1）和三个竞争它的线程（我们称它们为 A、B 和 C）；假设线程 B 是赢家。这没问题，但是如果线程 B 在其关键部分内再次尝试获取相同的锁 L1 会发生什么呢？嗯，想想看：锁 L1 当前处于锁定状态，因此迫使线程 B 在其解锁时阻塞（等待）。然而，除了线程 B 本身，没有其他线程可能执行解锁操作，因此线程 B 最终将永远等待下去！这就是死锁。这种类型的死锁被称为自死锁，或重新锁定错误。

有人可能会争辩，实际上确实存在这种情况，锁能够递归地被获取吗？是的，正如我们将在后面看到的，这可以在 pthread API 中完成。然而，良好的设计通常会反对使用递归锁；事实上，Linux 内核不允许这样做。

# ABBA 死锁

在涉及嵌套锁定的情况下，可能会出现更复杂的死锁形式：两个或更多竞争线程和两个或更多锁。在这里，让我们以最简单的情况为例：两个线程（A 和 B）与两个锁（L1 和 L2）一起工作。 

假设这是在垂直时间线上展开的情况，如下表所示：

| **时间** | **线程 A** | **线程 B** |
| --- | --- | --- |
| t1 | 尝试获取锁 L1 | 尝试获取锁 L2 |
| t2 | 获取锁 L1 | 获取锁 L2 |
| t3 | <--- 在 L1 的临界区中 ---> |  <--- 在 L2 的临界区中 ---> |
| t4 | 尝试获取锁 L2 | 尝试获取锁 L1 |
| t5 | 阻塞，等待 L2 解锁 | 阻塞，等待 L1 解锁 |
|  | <永远等待：死锁> |  <永远等待：死锁> |

很明显，每个线程都在等待另一个解锁它想要的锁；因此，每个线程都永远等待，保证了死锁。这种死锁通常被称为致命拥抱或 ABBA 死锁。

# 避免死锁

显然，避免死锁是我们希望确保的事情。除了*锁定指南*部分涵盖的要点之外，还有一个关键点，那就是获取多个锁的顺序很重要；始终保持锁定顺序一致将提供对抗死锁的保护。

为了理解原因，让我们重新看一下刚才讨论过的 ABBA 死锁场景（参考上表）。再次看表格：注意线程 A 获取锁 L1，然后尝试获取锁 L2，而线程 B 则相反。现在我们将表示这种情况，但有一个关键的警告：锁定顺序！这一次，我们将有一个锁定顺序规则；它可能很简单，比如：首先获取锁 L1，然后获取锁 L2：

锁 L1 --> 锁 L2

考虑到这种锁定顺序，我们发现情况可能会如下展开：

| **时间** | **线程 A** | **线程 B** |
| --- | --- | --- |
| t1 | 尝试获取锁 L1 | 尝试获取锁 L1 |
| t2 |  | 获取锁 L1 |
| t3 | <等待 L1 解锁> | <--- 在 L1 的临界区中 ---> |
| t4 |  | 解锁 L1 |
| t5 | 获取锁 L1 |  |
| t6 | <--- 在 L1 的临界区中 ---> | 尝试获取锁 L2 |
| t7 | 解锁 L1 | 获取锁 L2 |
| t8 | 尝试获取锁 L2 | <--- 在 L2 的临界区中  |
| t9 | <等待 L2 解锁> |                                                             ---> |
| t10 |  | 解锁 L2 |
| t11 | 获取锁 L2 | <继续其他工作> |
| t12 | <--- 在 L2 的临界区中 ---> | ... |
| t13 | 解锁 L2 | ... |

关键点在于两个线程尝试按照给定顺序获取锁；首先是 L1，然后是 L2。在上表中，我们可以想象一种情况，即线程 B 首先获取锁，迫使线程 A 等待。这是完全正常和预期的；不发生死锁是整个重点。

确切的顺序本身并不重要；重要的是设计者和开发者记录并遵守要遵循的锁定顺序。

锁定顺序语义，实际上开发者关于这一关键点的评论，通常可以在 Linux 内核源代码树（截至本文撰写时的版本 4.19）中找到。以下是一个例子：`virt/kvm/kvm_main.c``...`

`/*`

` * 锁的顺序：`

` *`

` * kvm->lock --> kvm->slots_lock --> kvm->irq_lock`

` */`

`...`

因此，回顾我们的第一个表格，我们现在可以清楚地看到，死锁发生是因为违反了锁定顺序规则：线程 B 在获取锁 L1 之前获取了锁 L2！

# 使用 pthread API 进行同步

既然我们已经涵盖了所需的理论背景信息，让我们继续进行实际操作：在本章的其余部分，我们将专注于如何使用 pthread API 进行同步，从而避免竞争。

我们已经了解到，为了保护任何类型的可写共享数据，我们需要在临界区域进行锁定。pthread API 为这种情况提供了互斥锁；我们打算只在临界区域内短暂持有锁。

然而，有些情况下，我们需要一种不同类型的同步 - 我们需要根据某个数据元素的值进行同步；pthread API 为这种情况提供了条件变量（CV）。

让我们依次来看看这些。

# 互斥锁

**互斥锁**一词实际上是**互斥排斥**的缩写；对于所有其他（失败的）线程的互斥排斥，一个线程 - 赢家 - 持有（或拥有）互斥锁。只有在它被解锁时，另一个线程才能获取锁。

一个常见问题：信号量和互斥锁之间的真正区别是什么？首先，信号量可以以两种方式使用 - 一种是作为计数器（使用计数信号量对象），另一种（我们这里关注的）基本上是作为互斥锁 - 二进制信号量。

二进制信号量和互斥锁之间存在两个主要区别：一是信号量用于在进程之间进行同步，而不是单个进程内部的线程（它确实是一个众所周知的 IPC 设施）；互斥锁用于同步给定（单个）进程的线程。 （话虽如此，可以创建一个进程共享的互斥锁，但这并不是默认值）。

其次，信号量的 SysV IPC 实现提供了这样的可能性，即内核可以在所有者进程被突然终止时（总是可能通过信号#9）解锁信号量（通过`semop(2)` `SEM_UNDO`标志）；对于互斥锁，甚至不存在这样的可能性 - 获胜者必须解锁它（我们稍后将介绍开发人员如何确保这一点）。

让我们从一个简单的示例开始，初始化、使用和销毁互斥锁。在这个程序中，我们将创建三个线程，仅在线程的工作例程中每次增加三个全局整数。

为了可读性，只显示了源代码的关键部分；要查看完整的源代码，请构建并运行它。整个树可在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

代码：`ch15/mutex1.c`：

```
static long g1=10, g2=12, g3=14;    /* our globals */
pthread_mutex_t mylock;   /* lock to protect our globals */ 
```

为了使用互斥锁，必须首先将其初始化为未锁定状态；可以这样做：

```
 if ((ret = pthread_mutex_init(&mylock, NULL)))
     FATAL("pthread_mutex_init() failed! [%d]\n", ret);
```

或者，我们可以将初始化作为声明来执行，例如：

```
pthread_mutex_t mylock = PTHREAD_MUTEX_INITIALIZER;
```

实际上，有一些可以为互斥锁指定的互斥属性（通过`pthread_mutexattr_init(3)` API）；我们将在本章后面介绍这一点。现在，属性将是系统默认值。

另外，一旦完成，我们必须销毁互斥锁：

```
 if ((ret = pthread_mutex_destroy(&mylock)))
     FATAL("pthread_mutex_destroy() failed! [%d]\n", ret);
```

通常情况下，我们在循环中创建（三个）工作线程（我们不在这里显示这段代码，因为它是重复的）。这是线程的工作例程：

```
void * worker(void *data)
{
     long datum = (long)data + 1;
     if (locking)
         pthread_mutex_lock(&mylock);

     /*--- Critical Section begins */
 g1 ++; g2 ++; g3 ++;
     printf("[Thread #%ld] %2ld %2ld %2ld\n", datum, g1, g2, g3);
     /*--- Critical Section ends */

     if (locking)
         pthread_mutex_unlock(&mylock);

     /* Terminate with success: status value 0.
      * The join will pick this up. */
     pthread_exit((void *)0);
}
```

因为我们正在使用每个线程的可写共享（它在数据段中！）资源进行操作，我们意识到这是一个临界区域！

因此，我们必须保护它 - 在这里，我们使用互斥锁。因此，在进入临界区域之前，我们首先获取互斥锁，然后处理全局数据，然后解锁我们的锁，使操作安全地抵御竞争。（请注意，在前面的代码中，我们只在变量称为`locking`为真时才执行锁定和解锁；这是一种测试代码的故意方式。在生产中，当然，请取消`if`条件并执行锁定！）细心的读者还会注意到，我们将临界区域保持得相当短 - 它只包含全局更新和随后的`printf(3)`，没有更多的内容。（这对于良好的性能很重要；回想一下我们在前一节关于*锁定粒度*中学到的内容）。

如前所述，我们故意为用户提供了一个选项，可以完全避免使用锁定，这当然会导致错误行为。让我们试一试：

```
$ ./mutex1 
Usage: ./mutex1 lock-or-not
 0 : do Not lock (buggy!)
 1 : do lock (correct)
$ ./mutex1 1
At start:   g1 g2 g3
            10 12 14
[Thread #1] 11 13 15
[Thread #2] 12 14 16
[Thread #3] 13 15 17
$ 
```

它确实按预期工作。即使我们将参数传递为零，从而关闭锁定，程序（通常）似乎也能正常工作：

```
$ ./mutex1 0
At start:   g1 g2 g3
            10 12 14
[Thread #1] 11 13 15
[Thread #2] 12 14 16
[Thread #3] 13 15 17
$ 
```

为什么？啊，这很重要要理解：回想一下我们在前一节“它是原子的吗？”中学到的内容。对于一个简单的整数增量和编译器优化设置为高级别（实际上是`-O2`），整数增量很可能是原子的，因此不真正需要锁定。然而，这并不总是情况，特别是当我们对整数变量进行比简单的增量或减量更复杂的操作时（考虑读取/写入一个大的全局链表等）！最重要的是：我们必须始终识别关键部分并确保我们保护它们。

# 看到竞争

为了确切地演示这个问题（实际上看到数据竞争），我们将编写另一个演示程序。在这个程序中，我们将计算给定数字的阶乘（一个快速提醒：3！= 3 x 2 x 1 = 6；从学校时代记得的符号 N！表示 N 的阶乘）。以下是相关代码：

为了便于阅读，只显示了源代码的关键部分；要查看完整的源代码，构建并运行它。整个树可以从 GitHub 克隆到这里：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)*.*

代码：`ch15/facto.c`：

在`main()`中，我们初始化我们的互斥锁（并创建两个工作线程；我们没有显示创建线程、销毁线程以及互斥锁的代码）：

```
printf( "Locking mode : %s\n" 
        "Verbose mode : %s\n",
          (gLocking == 1?"ON":"OFF"),
          (gVerbose == 1?"ON":"OFF"));

if (gLocking) {
     if ((ret = pthread_mutex_init(&mylock, NULL)))
         FATAL("pthread_mutex_init() failed! [%d]\n", ret);
 }
...
```

线程的`worker`例程如下：

```
void * worker(void *data)
{
    long datum = (long)data + 1;
    int N=0;
...
    if (gLocking)
        pthread_mutex_lock(&mylock);

    /*--- Critical Section begins! */
 factorize(N);
    printf("[Thread #%ld] (factorial) %d ! = %20lld\n",
      datum, N, gFactorial);
    /*--- Critical Section ends */

    if (gLocking)
        pthread_mutex_unlock(&mylock);
...
```

识别临界区，我们获取（然后解锁）我们的互斥锁。`factorize`函数的代码如下：

```
/*
 * This is the function that calculates the factorial of the given   parameter. 
Stress it, making it susceptible to the data race, by turning verbose mode On; then, it will take more time to execute, and likely end up "racing" on the value of the global gFactorial. */
static void factorize(int num)
{
     int i;
     gFactorial = 1;
     if (num <= 0)
         return;
    for (i=1; i<=num; i++) {
         gFactorial *= i;
         VPRINT(" i=%2d fact=%20lld\n", i, gFactorial);
    }
}
```

仔细阅读前面的评论；这对这个演示很关键。让我们试一试：

```
$ ./facto 
Usage: ./facto lock-or-not [verbose=[0]|1]
Locking mode:
 0 : do Not lock (buggy!)
 1 : do lock (correct)
(TIP: turn locking OFF and verbose mode ON to see the issue!)
$ ./facto 1
Locking mode : ON
Verbose mode : OFF
[Thread #2] (factorial) 12 ! =     479001600
[Thread #1] (factorial) 10 ! =       3628800
$ 
```

结果是正确的（自行验证）。现在我们关闭锁定并打开详细模式重新运行它：

```
$ ./facto 0 1
Locking mode : OFF
Verbose mode : ON
facto.c:factorize:50: i= 1 fact=                 1
facto.c:factorize:50: i= 2 fact=                 2
facto.c:factorize:50: i= 3 fact=                 6
facto.c:factorize:50: i= 4 fact=                24
facto.c:factorize:50: i= 5 fact=               120
facto.c:factorize:50: i= 6 fact=               720
facto.c:factorize:50: i= 7 fact=              5040
facto.c:factorize:50: i= 8 fact=             40320
facto.c:factorize:50: i= 9 fact=            362880
facto.c:factorize:50: i=10 fact=            3628800
[Thread #1] (factorial) 10 ! =           3628800
facto.c:factorize:50: i= 1 fact=                        1
facto.c:factorize:50: i= 2 fact=         7257600  *<-- Dirty Read!*
facto.c:factorize:50: i= 3 fact=                 21772800
facto.c:factorize:50: i= 4 fact=                 87091200
facto.c:factorize:50: i= 5 fact=                435456000
facto.c:factorize:50: i= 6 fact=               2612736000
facto.c:factorize:50: i= 7 fact=              18289152000
facto.c:factorize:50: i= 8 fact=             146313216000
facto.c:factorize:50: i= 9 fact=            1316818944000
facto.c:factorize:50: i=10 fact=           13168189440000
facto.c:factorize:50: i=11 fact=          144850083840000
facto.c:factorize:50: i=12 fact=         1738201006080000
[Thread #2] (factorial) 12 ! =        1738201006080000
$ 
```

啊哈！在这种情况下，`10！`是正确的，但`12！`是错误的！我们可以从前面的输出中清楚地看到发生了脏读（在计算 12！时的 i==2 迭代中），导致了缺陷。当然：我们在这里没有保护关键部分（锁定被关闭）；难怪出错了。

我们再次要强调的是，这些竞争是微妙的时间巧合；在一个有错误的实现中，你的测试用例可能仍然会成功，但这并不能保证任何事情（它很可能在实际应用中失败，正如墨菲定律告诉我们的那样！）。（一个不幸的事实是测试可以揭示错误的存在，但不能保证它们的不存在。重要的是，第十九章，*故障排除和最佳实践*，涵盖了这些要点）。

读者会意识到，由于这些数据竞争是微妙的时间巧合，它们可能会或可能不会在您的测试系统上完全如此发生。多次重试应用程序可能有助于重现这些情况。

我们留给读者尝试在锁定模式和详细模式下使用用例；当然它应该工作。

# 互斥锁属性

互斥锁可以有几个与之关联的属性。此外，我们列举了其中的几个。

# 互斥锁类型

互斥锁可以是四种类型之一，默认情况下通常是正常互斥锁，但并不总是（这取决于实现）。使用的互斥锁类型会影响锁定和解锁的行为。这些类型是：PTHREAD_MUTEX_NORMAL，PTHREAD_MUTEX_ERRORCHECK，PTHREAD_MUTEX_RECURSIVE 和 PTHREAD_MUTEX_DEFAULT。

系统手册中关于`pthread_mutex_lock(3)`的行为取决于互斥锁类型的表格；为了读者方便，我们在这里重复了相同的内容。

如果线程尝试重新锁定已经锁定的互斥锁，则`pthread_mutex_lock(3)`将按照以下表格中的重新锁定列中描述的行为进行。如果线程尝试解锁未锁定或已解锁的互斥锁，则`pthread_mutex_unlock(3)`将按照以下表格中的**非所有者解锁**列中描述的行为进行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/2dfc4139-4ba1-47be-a5fe-8d878fbb3a0c.png)

如果互斥锁类型为 PTHREAD_MUTEX_DEFAULT，则`pthread_mutex_lock(3)`的行为可能对应于前表中描述的三种其他标准互斥锁类型之一。如果它不对应于这三种中的任何一种，对于标记为†的情况，行为是未定义的。

重新锁定列直接对应于我们在本章前面描述的自死锁场景，比如，尝试重新锁定已经锁定的锁（或许是诗意的措辞？）会产生什么影响。显然，除了递归和错误检查互斥锁的情况，最终结果要么是未定义的（这意味着任何事情都可能发生！），要么确实是死锁。

同样，除了拥有者之外的任何线程尝试解锁互斥锁都会导致未定义行为或错误。

人们可能会想：为什么锁定 API 的行为会根据互斥锁的类型而有所不同——在错误返回或失败方面？为什么不为所有类型都设定一个标准行为，从而简化情况？嗯，这是简单性和性能之间的通常权衡：实现的方式允许，例如，一个编写良好、在程序上经过验证正确的实时嵌入式应用程序放弃额外的错误检查，从而获得速度（这在关键代码路径上尤为重要）。另一方面，在开发或调试环境中，开发人员可能选择允许额外的检查，以便在发货前捕捉缺陷。（`pthread_mutex_destroy(3)`的 man 页面有一个名为*错误检查和性能支持之间的权衡*的部分，其中对这个方面进行了比较详细的描述。）

`get`和`set`互斥锁类型属性的一对 API（在上表的第一列）非常直接：

```
include <pthread.h>
int pthread_mutexattr_gettype(const pthread_mutexattr_t *restrict attr,     int *restrict type);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
```

# 鲁棒互斥锁属性

看一下上表，人们会注意到鲁棒性列；这是什么意思？回想一下，只有互斥锁的拥有者线程可能解锁互斥锁；现在，我们问，如果拥有者线程碰巧死亡会怎么样？（首先，良好的设计将确保这种情况永远不会发生；其次，即使发生了，也有方法来保护线程取消，这是我们将在下一章中讨论的一个主题。）从表面上看，没有帮助；任何其他等待锁的线程现在都将陷入死锁（实际上，它们将被挂起）。这实际上是默认行为；这也是由称为 PTHREAD_MUTEX_STALLED 的鲁棒属性设置的行为。在这种情况下，可能的救援存在于另一个鲁棒互斥锁属性的值：PTHREAD_MUTEX_ROBUST。可以通过以下一对 API 查询和设置这些属性：

```
#include <pthread.h>
int pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr,
    int *robustness);
int pthread_mutexattr_setrobust(const pthread_mutexattr_t *attr,
    int robustness);
```

如果在互斥锁上设置了此属性（值为 PTHREAD_MUTEX_ROBUST），那么如果拥有者线程在持有互斥锁时死亡，随后对锁的`pthread_mutex_lock(3)`将成功返回值`EOWNERDEAD`。不过，即使调用返回了（所谓的）成功返回，重要的是要理解，相关的锁现在被认为处于不一致状态，并且必须通过`pthread_mutex_consistent(3)`API 将其重置为一致状态：

`int pthread_mutex_consistent(pthread_mutex_t *mutex);`

这里返回值为零表示成功；互斥锁现在恢复到一致（稳定）状态，并且可以正常使用（使用它，当然在某个时候，你必须解锁它）。

总之，要使用鲁棒属性互斥锁，请使用以下方法：

+   初始化互斥锁：

`pthread_mutexattr_t attr`;

`pthread_mutexattr_init(&attr)`；

+   在它上面设置 robust 属性：`pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST)`；

+   拥有者线程

+   锁定它：`pthread_mutex_lock(&mylock)`。

+   现在，假设线程所有者突然死亡（同时持有互斥锁）

+   另一个线程（可能是主线程）可以假定所有权：

+   首先，检测情况：

+   `ret = pthread_mutex_lock(&mylock)`；

`if (ret == EOWNERDEAD) {`

+   然后，使其一致：

`pthread_mutex_consistent(&mylock)`；

+   使用它（或解锁它）

+   解锁它：`pthread_mutex_unlock(&mylock)`；

我们不打算重复造轮子，我们将读者指向一个简单易读的示例，该示例使用了之前描述的 robust 互斥锁属性功能。在`pthread_mutexattr_setrobust(3)`的 man 页面中可以找到它。

在底层，Linux pthreads 互斥锁是通过`futex(2)`系统调用（因此由操作系统）实现的。`futex（快速用户互斥锁）`提供了快速、健壮、仅原子指令的锁定实现。更多详细信息的链接可以在 GitHub 存储库的*进一步阅读*部分中找到。

# IPC、线程和进程共享的互斥锁

想象一个由几个独立的多线程进程组成的大型应用程序。现在，如果这些进程想要相互通信（他们通常会想要这样做），这该如何实现？答案当然是**进程间通信**（IPC）——为此目的存在的机制。广义上说，在典型的 Unix/Linux 平台上有几种 IPC 机制可用；这些包括共享内存（以及`mmap(2)`）、消息队列、信号量（通常用于同步）、命名（FIFO）和无名管道、套接字（Unix 和互联网域），在一定程度上还有信号。

不幸的是，由于空间限制，我们在本书中没有涵盖进程 IPC 机制；我们敦促感兴趣的读者查看 IPC 部分在 GitHub 存储库的*进一步阅读*部分中提供的链接（和书籍）。

这里需要强调的是，所有这些 IPC 机制都是用于在 VM 隔离的进程之间进行通信。因此，我们在这里讨论的重点是多线程，那么给定进程内的线程如何相互通信呢？实际上很简单：就像可以设置并使用共享内存区域来有效和高效地在进程之间进行通信（写入和读取该区域，通过信号量同步访问），线程可以简单有效地使用全局内存缓冲区（或任何适当的数据结构）作为彼此通信的媒介，并且当然，通过互斥锁同步访问全局内存区域。

有趣的是，可以使用互斥锁作为不同进程的线程之间的同步原语。这是通过设置名为 pshared 或进程共享的互斥锁属性来实现的。获取和设置 pshared 互斥锁属性的一对 API 如下：

```
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr,
    int *pshared);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,
    int pshared);
```

第二个参数 pshared 可以设置为以下之一：

+   **PTHREAD_PROCESS_PRIVATE**：默认值；在这里，互斥锁只对创建互斥锁的进程内的线程可见。

+   **PTHREAD_PROCESS_SHARED**：在这里，互斥锁对在创建互斥锁的内存区域中具有访问权限的任何线程可见，包括不同进程的线程。

但是，如何确保互斥锁存在的内存区域在进程之间是共享的（如果没有，将无法让相关进程使用互斥锁）？嗯，这实际上是基本的：我们必须使用我们提到的 IPC 机制之一——共享内存原来是正确的。因此，我们让应用程序设置一个共享内存区域（通过传统的 SysV IPC `shmget(2)`或较新的 POSIX IPC `shm_open(2)`系统调用），并且在这个共享内存中实例化我们的进程共享的互斥锁。

因此，让我们用一个简单的应用程序将所有这些联系在一起：我们将编写一个应用程序，创建两个共享内存区域：

+   一、一个小的共享内存区域，用作进程共享互斥锁和一次性初始化控制的共享空间（稍后详细介绍）

+   二、一个共享内存区域，用作存储 IPC 消息的简单缓冲区

我们将使用进程共享属性初始化互斥锁，以便在不同进程的线程之间同步访问；在这里，我们 fork 并让原始父进程和新生的子进程的线程竞争互斥锁。一旦它们（顺序地）获得它，它们将向第二个共享内存段写入消息。在应用程序结束时，我们销毁资源并显示共享内存缓冲区（作为一个简单的概念验证）。

让我们尝试一下我们的应用程序（`ch15/pshared_mutex_demo.c`）：

为了便于阅读，我们在下面的代码中添加了一些空行。

```
$ ./pshared_mutex_demo 
./pshared_mutex_demo:15317: shmem segment successfully created / accessed. ID=38928405
./pshared_mutex_demo:15317: Attached successfully to shmem segment at 0x7f45e9d50000
./pshared_mutex_demo:15317: shmem segment successfully created / accessed. ID=38961174
./pshared_mutex_demo:15317: Attached successfully to shmem segment at 0x7f45e9d4f000

[pthread_once(): calls init_mutex(): from PID 15317]

Worker thread #0 [15317] running ...
 [thrd 0]: attempting to take the shared mutex lock...
 [thrd 0]: got the (shared) lock!
#0: work done, exiting now

 Child[15319]: attempting to taking the shared mutex lock...
 Child[15319]: got the (shared) lock!

main: joining (waiting) upon thread #0 ...
Thread #0 successfully joined; it terminated with status=0

Shared Memory 'comm' buffer:
00000000 63 63 63 63 63 00 63 68 69 6c 64 20 31 35 33 31 ccccc.child 1531
00000016 39 20 68 65 72 65 21 0a 00 74 74 74 74 74 00 74 9 here!..ttttt.t
00000032 68 72 65 61 64 20 31 35 33 31 37 20 68 65 72 65 hread 15317 here
00000048 21 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 !...............
00000064 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000080 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000096 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000112 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
```

在现实世界中，事情并不像这样简单；还存在一个额外的同步问题需要考虑：如何确保互斥锁正确且原子地初始化（只由一个进程或线程），并且只初始化一次，其他线程应该如何使用它？在我们的演示程序中，我们使用了`pthread_once(3)` API 来实现互斥对象的一次性初始化（但忽略了线程等待并且只在初始化后使用的问题）。 （Stack Overflow 上的一个有趣的问答突出了这个问题；请看：[`stackoverflow.com/questions/42628949/using-pthread-mutex-shared-between-processes-correctly#`](https://stackoverflow.com/questions/42628949/using-pthread-mutex-shared-between-processes-correctly#)*。）然而，事实是`pthread_once(3)` API 是用于在一个进程的线程之间使用的。此外，POSIX 要求`once_control`的初始化是静态完成的；在这里，我们在运行时执行了它，所以并不完美。

在`main`函数中，我们设置并初始化（IPC）共享内存段；我们敦促读者仔细阅读源代码（阅读所有注释），并自行尝试：

为了便于阅读，只显示了源代码的关键部分；要查看完整的源代码，请构建并运行它。整个树可以在 GitHub 上克隆：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)*.*

```
...

  /* Setup a shared memory region for the process-shared mutex lock.
   * A bit of complexity due to the fact that we use the space within for:
   * a) memory for 1 process-shared mutex
   * b) 32 bytes of padding (not strictly required)
   * c) memory for 1 pthread_once_t variable.
   * We need the last one for performing guaranteed once-only
   * initialization of the mutex object.
   */
  shmaddr = shmem_setup(&gshm_id, argv[0], 0, 
              (NUM_PSMUTEX*sizeof(pthread_mutex_t) + 32 +  
                sizeof(pthread_once_t)));
  if (!shmaddr)
      FATAL("shmem setup 1 failed\n");

  /* Associate the shared memory segment with the mutex and 
   * the pthread_once_t variable. */
  shmtx = (pthread_mutex_t *)shmaddr;
  mutex_init_once = (pthread_once_t *)shmaddr +     
                      (NUM_PSMUTEX*sizeof(pthread_mutex_t)) + 32;
  *mutex_init_once = PTHREAD_ONCE_INIT; /* see below comment on pthread_once */

  /* Setup a second shared memory region to be used as a comm buffer */
  gshmbuf = shmem_setup(&gshmbuf_id, argv[0], 0, GBUFSIZE);
  if (!gshmbuf)
      FATAL("shmem setup 2 failed\n");
  memset(gshmbuf, 0, GBUFSIZE);

  /* Initialize the mutex; here, we come across a relevant issue: this
   * mutex object is already instantiated in a shared memory region that
   * other processes might well have access to. So who will initialize
   * the mutex? (it must be done only once).
   * Enter the pthread_once(3) API: it guarantees that, given a
   * 'once_control' variable (1st param), the 2nd param - a function
   * pointer, that function will be called exactly once.
   * However: the reality is that the pthread_once is meant to be used
   * between the threads of a process. Also, POSIX requires that the
   * initialization of the 'once_control' is done statically; here, we
   * have performed it at runtime...
   */
  pthread_once(mutex_init_once, init_mutex);
...
```

`init_mutex`函数用于使用进程共享属性初始化互斥锁，如下所示：

```
static void init_mutex(void)
{
  int ret=0;

  printf("[pthread_once(): calls %s(): from PID %d]\n",
      __func__, getpid());
  ret = pthread_mutexattr_init(&mtx_attr);
  if (ret)
      FATAL("pthread_mutexattr_init failed [%d]\n", ret);

  ret = pthread_mutexattr_setpshared(&mtx_attr, PTHREAD_PROCESS_SHARED);
  if (ret)
      FATAL("pthread_mutexattr_setpshared failed [%d]\n", ret);

  ret = pthread_mutex_init(shmtx, &mtx_attr);
  if (ret)
      FATAL("pthread_mutex_init failed [%d]\n", ret);
}
```

工作线程的代码——`worker`例程——如下所示。在这里，我们需要操作第二个共享内存段，这意味着这是一个关键部分。因此，我们获取进程共享锁，执行工作，然后解锁互斥锁：

```
void * worker(void *data)
{
  long datum = (long)data;
  printf("Worker thread #%ld [%d] running ...\n", datum, getpid());
  sleep(1);
  printf(" [thrd %ld]: attempting to take the shared mutex lock...\n", datum);

  LOCK_MTX(shmtx);
  /*--- critical section begins */
  printf(" [thrd %ld]: got the (shared) lock!\n", datum);
  /* Lets write into the shmem buffer; first, a 5-byte 'signature',
     followed by a message. */
  memset(&gshmbuf[0]+25, 't', 5);
  snprintf(&gshmbuf[0]+31, 32, "thread %d here!\n", getpid());
  /*--- critical section ends */
  UNLOCK_MTX(shmtx);

  printf("#%ld: work done, exiting now\n", datum);
  pthread_exit(NULL);
}
```

请注意，锁定和解锁操作是通过宏执行的；这里它们是：

```
#define LOCK_MTX(mtx) do {                           \
  int ret=0;                                         \
  if ((ret = pthread_mutex_lock(mtx)))               \
    FATAL("pthread_mutex_lock failed! [%d]\n", ret); \
} while(0)

#define UNLOCK_MTX(mtx) do {                           \
  int ret=0;                                           \
  if ((ret = pthread_mutex_unlock(mtx)))               \
    FATAL("pthread_mutex_unlock failed! [%d]\n", ret); \
} while(0)
```

我们留给读者查看代码，在那里我们 fork 并让新生的子进程基本上做与前面的工作线程相同的事情——操作（相同的）第二个共享内存段；作为关键部分，它也尝试获取进程共享锁，一旦获取，执行工作，然后解锁互斥锁。

除非有令人信服的理由不这样做，在设置进程之间的 IPC 时，我们建议您使用专门为此目的设计的众多 IPC 机制之一（或其中一些）。使用进程共享互斥锁作为两个或多个进程的线程之间的同步机制是可能的，但请问自己是否真的需要。

话虽如此，使用互斥锁而不是传统的（二进制）信号量对象也有一些优点；其中包括互斥锁始终与一个所有者线程相关联，只有所有者才能对其进行操作（防止一些非法或有缺陷的情况），互斥锁可以设置为使用嵌套（递归）锁定，并有效地处理**优先级反转**问题（通过继承协议和/或优先级天花板属性）。

# 优先级反转，看门狗和火星

**实时操作系统**（RTOS）通常在其上运行时间关键的多线程应用程序。非常简单地说，但仍然是真的，RTOS 调度程序决定下一个要运行的线程的主要规则是最高优先级的可运行线程必须是正在运行的线程。（顺便说一下，我们将在第十七章中涵盖有关 Linux 操作系统的 CPU 调度，*Linux 上的 CPU 调度*；现在不用担心细节。）

# 优先级反转

让我们想象一个包含三个线程的应用程序；其中一个是高优先级线程（让我们称其为优先级为 90 的线程 A），另一个是低优先级线程（让我们称其为优先级为 10 的线程 B），最后是一个中等优先级线程 C。（SCHED_FIFO 调度策略的优先级范围是 1 到 99，99 是最高可能的优先级；稍后的章节中会详细介绍。）因此，我们可以想象我们在一个进程中有这三个不同优先级的线程：

+   线程 A：高优先级，90

+   线程 B：低优先级，10

+   线程 C：中等优先级，45

此外，让我们考虑一下我们有一些共享资源 X，线程 A 和 B 都渴望拥有它；这当然构成了一个关键部分，因此，我们需要同步访问它以确保正确性。我们将使用**互斥锁**来做到这一点。

正常情况可能是这样的（现在先忽略线程 C）：线程 B 正在 CPU 上运行一些代码；线程 A 正在另一个 CPU 核心上处理其他事情。两个线程都不在关键部分；因此，互斥锁处于未锁定状态。

现在（在时间**t1**），线程 B 进入关键部分的代码并获取互斥锁，从而成为**所有者**。它现在运行关键部分的代码（处理 X）。与此同时，如果—在时间**t2**—线程 A 也碰巧进入关键部分，因此尝试获取互斥锁呢？嗯，我们知道它已经被锁定，因此线程 A 将不得不等待（阻塞），直到线程 B 执行（希望很快）解锁。一旦线程 B 解锁互斥锁（在时间**t3**），线程 A 获取它（在时间**t4**；我们认为延迟**t4**-**t3**非常小），生活（非常愉快地）继续。这看起来很好：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/ebe8bb6c-fdc5-4d88-ae4a-6769f82daea6.png)

图 12：互斥锁定：正常情况

然而，也存在潜在的不良情况！继续阅读。

# 简要介绍看门狗定时器

看门狗是一种用于定期检测系统是否处于健康状态的机制，如果被认为不是，就会重新启动系统。这是通过设置（内核）定时器（比如，60 秒超时）来实现的。如果一切正常，看门狗守护进程（守护进程只是系统后台进程）将始终取消定时器（在其到期之前，当然），然后重新启用它；这被称为**抚摸狗**。如果守护进程没有这样做（由于某些事情出了大问题），看门狗就会生气并重新启动系统！纯软件看门狗实现将无法防止内核错误和故障；硬件看门狗（它连接到板复位电路）将始终能够在需要时重新启动系统。

通常，嵌入式应用的高优先级线程被设计为在其中必须完成一些工作的非常真实的截止日期；否则，系统被认为已经失败。人们不禁想，如果操作系统本身在运行时由于不幸的错误而崩溃或挂起（恐慌）会怎么样？然后应用线程就无法继续；我们需要一种方法来检测并摆脱这种困境。嵌入式设计人员经常利用**看门狗定时器**（**WDT**）硬件电路（以及相关的设备驱动程序）来精确实现这一点。如果系统或关键线程未能在截止日期前完成其工作（未能喂狗），系统将重新启动。

所以，回到我们的场景。假设我们对线程 A 的截止日期为 100 毫秒；在你的脑海中重复前面的锁定场景，但有一个区别（参考*图 13*：）：

+   **线程 B**（低优先级线程）在时间**t1**获得互斥锁。

+   **线程 A**也在时间**t2**请求互斥锁（但必须等待线程 B 的解锁）。

+   在线程 B 完成关键部分之前，另一个中等优先级的线程 C（在同一 CPU 核心上运行，并且优先级为 45）醒来了！它会立即抢占线程 B，因为它的优先级更高（请记住，可运行的最高优先级线程必须是正在运行的线程）。

+   现在，在线程 C 离开 CPU 之前，线程 B 无法完成关键部分，因此无法执行解锁。

+   这反过来会显著延迟线程 A，它正在等待线程 B 尚未发生的解锁：

+   然而，线程 B 已被线程 C 抢占，因此无法执行解锁。

+   如果解锁的时间超过了线程 A 的截止日期（在时间**t4**）会怎么样？

+   然后看门狗定时器将会过期，强制系统重新启动：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/5d1e63a3-f58b-49e8-abf4-80d9eed4a655.png)

图 13：优先级反转

有趣而不幸的是；你是否注意到最高优先级的线程（A）实际上被迫等待系统中优先级最低的线程（B）？这种现象实际上是一种已记录的软件风险，正式称为优先级反转。

不仅如此，想象一下，如果在线程 B 处于其关键部分（因此持有锁）时，有几个中等优先级的线程醒来会发生什么？线程 A 的潜在等待时间现在可能会变得非常长；这种情况被称为无界优先级反转。

# 火星探路者任务简介

非常有趣的是，这种精确的优先级反转场景在一个真正超凡脱俗的环境中发生了：在火星表面！美国宇航局成功地在 1997 年 7 月 4 日将一艘机器人飞船（探路者着陆器）降落在火星表面；然后它继续卸载并部署了一个更小的机器人——Sojourner Rover——到表面上。然而，控制器发现着陆器遇到了问题——每隔一段时间就会重新启动。对实时遥测数据的详细分析最终揭示了潜在问题——是软件，它遇到了优先级反转问题！值得赞扬的是，美国宇航局的**喷气推进实验室**（**JPL**）团队，以及 Wind River 公司的工程师，他们为美国宇航局提供了定制的 VxWorks RTOS，他们从地球上诊断和调试了这种情况，确定了根本原因是优先级反转问题，修复了它，上传了新的固件到探路者，一切都正常运行了：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/e0ce7e31-9f76-42ff-8936-e9358bb67eca.png)

图 14：火星探路者着陆器的照片

当微软工程师迈克·琼斯在 IEEE 实时研讨会上写了一封有趣的电子邮件，讲述了 NASA 的 Pathfinder 任务发生了什么事情时，这一消息以病毒式传播。这封电子邮件最终得到了 NASA 的 JPL 团队负责人格伦·里夫斯的详细回复，题为《火星上到底发生了什么？》。这和后续文章中捕捉到了许多有趣的见解。在我看来，所有软件工程师都应该读一读这些文章！（在 GitHub 存储库的*进一步阅读*部分查找提供的链接，标题为火星 Pathfinder 和优先级倒置。）

Glenn Reeves 强调了一些重要的教训和他们能够重现和解决问题的原因，其中之一是：我们坚信测试你所飞行的东西，飞行你所测试的哲学。实际上，由于设计决策将相关的详细诊断和调试信息保留在跟踪/日志环形缓冲区中，这些信息可以随意转储（并发送到地球），他们能够调试手头的根本问题。

# 优先级继承-避免优先级倒置

好的；但是如何解决优先级倒置这样的问题呢？有趣的是，这是一个已知的风险，互斥锁的设计包括了一个内置的解决方案。关于帮助解决优先级倒置问题的互斥锁属性存在两个——优先级继承（PI）和优先级上限。

PI 是一个有趣的解决方案。想想看，关键问题是操作系统调度线程的方式。在操作系统（尤其是在实时操作系统上），实时线程的调度——决定谁运行——基本上与竞争线程的优先级成正比：你的优先级越高，你运行的机会就越大。所以，让我们快速重新看一下我们之前的场景示例。回想一下，我们有这三个不同优先级的线程：

+   线程 A：高优先级，90

+   线程 B：低优先级，10

+   线程 C：中等优先级，45

优先级倒置发生在线程 B 长时间持有互斥锁时，从而迫使线程 A 在解锁时可能要等待太久（超过截止日期）。所以，想想这个：如果线程 B 一抓住互斥锁，我们就把它的优先级提高到系统上等待相同互斥锁的最高优先级线程的优先级。然后，当然，线程 B 将获得优先级 90，因此不能被抢占（无论是被线程 C 还是其他任何线程）！这确保了它快速完成临界区并解锁互斥锁；一旦解锁，它就会恢复到原来的优先级。这解决了问题；这种方法被称为 PI。

pthreads API 集提供了一对 API 来查询和设置协议互斥锁属性，你可以利用 PI：

```
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t
     *restrict attr, int *restrict protocol);
int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr,
     int protocol);
```

协议参数可以取以下值之一：PTHREAD_PRIO_INHERIT，

PTHREAD_PRIO_NONE，或 PTHREAD_PRIO_PROTECT（默认为 PTHREAD_PRIO_NONE）。当互斥锁具有 INHERIT 或 PROTECT 协议之一时，其所有者线程在调度优先级方面会受到影响。

对于使用 PTHREAD_PRIO_INHERIT 协议初始化的任何互斥锁，持有锁（拥有它）的线程将继承任何线程的最高优先级（因此以该优先级执行），这些线程在任何使用此协议的互斥锁（鲁棒或非鲁棒）上阻塞（等待）。

对于使用 PTHREAD_PRIO_PROTECT 协议初始化的任何互斥锁，持有锁（拥有它）的线程将继承任何使用此协议的线程的最高优先级上限（因此以该优先级执行），无论它们当前是否在任何这些互斥锁（鲁棒或非鲁棒）上阻塞（等待）。

如果一个线程使用了使用不同协议初始化的互斥锁，它将以它们中定义的最高优先级执行。

在“开拓者”任务中，RTOS 使用的是著名的 VxWorks，由风河公司提供。互斥锁（或信号量）肯定具有 PI 属性；只是 JPL 软件团队忘记打开互斥锁的 PI 属性，导致了优先级反转问题！（实际上，软件团队对此非常清楚，并在几个地方使用了它，但没有在发生问题的地方使用 —— 这就是墨菲定律在起作用！）

此外，开发人员可以利用优先级上限——这是所有者线程执行临界区代码的最低优先级。因此，通过能够指定这一点，可以确保它具有足够高的值，以确保所有者线程在临界区时不会被抢占。Pthreads `pthread_mutexattr_getprioceiling(3)` 和 `pthread_mutexattr_setprioceiling(3)` API 可以用于查询和设置互斥锁的优先级上限属性。（它必须在有效的 SCHED_FIFO 优先级范围内，通常在 Linux 平台上为 1 到 99）。

再次强调，在实践中，使用优先级继承和上限属性存在一些挑战，主要是性能开销：

+   更重的任务/上下文切换可能会导致

+   优先级传播会增加开销

+   有许多线程和许多锁时，会有性能开销，同时也会有死锁的潜在风险

# 互斥属性使用摘要

实际上，如果您想彻底测试和调试您的应用程序，并且现在并不真的关心性能，那么请设置您的互斥锁如下：

+   在其上设置 robust 属性（允许捕获所有者死亡而不解锁的情况）：`pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST)`

+   将类型设置为错误检查（允许捕获自死锁/重新锁定的情况）：

`pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)`

另一方面，一个设计良好且经过验证的应用程序，需要您挤出性能，将使用正常（默认）的互斥锁类型和属性。前面的情况不会被捕捉到（而是导致未定义的行为），但是它们本来就不应该发生！

如果需要递归锁定，（显然）将互斥锁类型设置为 PTHREAD_MUTEX_RECURSIVE。对于递归互斥锁，重要的是要意识到，如果互斥锁被锁定 `n` 次，则为了被认为真正处于解锁状态（因此可以再次锁定），它也必须被解锁 `n` 次。

在多进程和多线程应用程序中，如果需要在不同进程的线程之间使用互斥锁，可以通过互斥对象的进程共享属性来实现。请注意，在这种情况下，包含互斥锁的内存本身必须在进程之间共享（通常使用共享内存段）。

PI 和优先级上限属性使开发人员能够保护应用程序免受众所周知的软件风险：优先级反转。

# 互斥锁定 - 附加变体

本节帮助理解互斥锁的附加变体，稍微不同的语义。我们将涵盖超时互斥锁变体、"忙等待"用例和读者-写者锁。

# 争取互斥锁超时

在前面的“锁定指南”部分中，在防止饥饿的标签下，我们了解到长时间持有互斥锁会导致性能问题；显然，失败的线程会饿死。避免这个问题的一种方法（尽管，当然，修复任何饥饿的根本原因才是重要的！）是让失败的线程等待一定时间后再等待互斥锁；如果等待时间超过一定时间，就放弃。这正是 `pthread_mutex_timedlock(3)` API 提供的功能：

```
#include <pthread.h>
#include <time.h>
int pthread_mutex_timedlock(pthread_mutex_t *restrict mutex,
        const struct timespec *restrict abstime);
```

很明显：所有锁定语义与通常的`pthread_mutex_lock(3)`一样，只是如果在锁上花费的阻塞时间（等待）超过第二个参数——作为绝对值指定的时间，API 返回失败——返回的值将是`ETIMEDOUT`。（我们已经在第十三章中详细编程了超时，*定时器*。）

请注意，其他错误返回值也是可能的（例如，对于先前所有者终止的鲁棒互斥锁，可能返回`EOWNERDEAD`，对于检查错误的互斥锁检测到死锁，等等）。有关详细信息，请参阅`pthread_mutex_timedlock(3)`的手册页。

# 忙等待（非阻塞变体）锁

我们知道互斥锁的正常工作方式：如果锁已经被锁定，那么尝试获取锁将导致该线程阻塞（等待）解锁事件发生。如果有人想要一个设计，大致如下：如果锁已被锁定，不要让我等待；我会做一些其他工作然后重试？这种语义通常被称为忙等待或非阻塞，并由 trylock 变体提供。顾名思义，我们尝试获取锁，如果成功，很好；如果没有，没关系——我们不会强迫线程等待。锁可以被进程内的任何线程（甚至是外部线程，如果它是进程共享的互斥锁）获取，包括相同的线程——如果它被标记为递归。但是等等；如果互斥锁确实是递归锁，那么获取它将立即成功，并且调用将立即返回。

其 API 如下：

`int pthread_mutex_trylock(pthread_mutex_t *mutex);`。

虽然这种忙等待语义偶尔会很有用——具体来说，它用于检测和防止某些类型的死锁——但在使用时要小心。想一想：对于一个轻度争用的锁（很少被使用的锁，在这种情况下，尝试获取锁的线程很可能会立即获得锁），使用这种忙等待语义可能是有用的。但对于一个严重争用的锁（在热代码路径上的锁，经常被获取和释放），这实际上可能会损害获得锁的机会！为什么？因为你不愿意等待它。（有时软件模仿生活，是吧？）

# 读者-写者互斥锁

想象一个多线程应用程序，有十个工作线程；假设大部分时间（比如 90%的时间），八个工作线程都在忙于扫描全局链表（或类似的数据结构）。现在，当然，由于它是全局的，我们知道它是一个临界区；如果没有用互斥锁保护它，很容易导致脏读错误。但是，这会带来很大的性能成本：因为每个工作线程都想要搜索列表，它被迫等待来自所有者的解锁事件。

计算机科学家已经提出了一种创新的替代方案，用于这种情况（也称为读者-写者问题），其中数据访问的大部分时间（共享）数据只被读取而不被写入。我们使用了一种特殊的互斥锁变体，称为读者-写者锁：

```
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
```

请注意，这是一种全新的锁类型：`pthread_wrlock_t`。

如果一个线程为自己获取了读锁，关键点在于：实现现在信任这个线程只会读取而不会写入；因此，不会进行实际的锁定，API 将直接返回成功！这样，读者实际上是并行运行的，从而保持了性能；没有安全问题或竞争，因为他们保证只会读取。

然而，一旦一个线程希望写入数据，它必须获得写锁：当这发生时，正常的锁定语义适用。写入线程现在必须等待所有读者执行解锁，然后写入者获得写锁并继续。在临界区内，没有线程——读者也不是写者——能够干预；它们将像通常一样阻塞（等待）写入者的解锁。因此，现在两种情况都得到了优化。

通常的嫌疑犯——用于设置读写互斥锁属性的 API 存在（按字母顺序排列）：

+   `pthread_rwlockattr_destroy(3P)`

+   `pthread_rwlockattr_getpshared(3P)`

+   `pthread_rwlockattr_setkind_np(3P)`

+   `pthread_rwlockattr_getkind_np(3P)`

+   `pthread_rwlockattr_init(3P)`

+   `pthread_rwlockattr_setpshared(3P)`

请注意，以`_np`结尾的 API 意味着它们是非便携的，仅适用于 Linux。

同样，读写锁定的 API 遵循通常的模式——超时和尝试变体也存在。

+   `pthread_rwlock_destroy(3P)`

+   `pthread_rwlock_init(3P)`

+   `pthread_rwlock_timedrdlock(3P)`

+   `pthread_rwlock_tryrdlock(3P)`

+   `pthread_rwlock_unlock(3P)`

+   `pthread_rwlock_rdlock(3P)`

+   `pthread_rwlock_timedwrlock(3P)`

+   `pthread_rwlock_trywrlock(3P)`

+   `pthread_rwlock_wrlock(3P)`

我们期望程序员按照正常的方式设置——初始化读写锁属性对象，初始化读写锁本身（使用`pthread_rwlock_init(3P)`），在完成后销毁属性结构，然后根据需要执行实际的锁定。

请注意，当使用读写锁时，应该仔细测试性能；已经注意到它比通常的互斥锁实现要慢。此外，还有一个额外的担忧，在负载下，读写锁的语义可能导致写入者饥饿。想象一下：如果读者不断出现，写入线程可能要等很长时间才能获得锁。

显然，使用读写锁也可能出现相反的动态：读者可能被饥饿。有趣的是，Linux 提供了一个非便携的 API，允许程序员指定要防止哪种类型的饥饿——读者还是写者，其中默认是写者被饥饿。调用此 API 进行设置的方法是`pthread_rwlockattr_setkind_np(3)`。这允许根据特定的工作负载进行一定程度的调整。（然而，实现显然仍然存在一个 bug，实际上，写者饥饿仍然是现实。我们不打算进一步讨论这一点；如有需要，读者可以参考手册页以获得进一步的帮助。）

然而，读写锁变体通常是有用的；想想那些经常需要扫描某些键值映射数据结构并执行某种表查找的应用程序。（例如，操作系统经常有网络代码路径经常查找路由表但很少更新它。）不变的是，所讨论的全局共享数据通常被读取，但很少被写入。

# 自旋锁变体

这里有一点重复：我们已经了解了互斥锁的正常工作方式；如果锁已经被锁定，那么尝试获取锁将导致该线程阻塞（等待解锁）。让我们深入一点；失败的线程究竟如何阻塞——等待——互斥锁的解锁？答案是，对于互斥锁，它们通过睡眠（被操作系统调度下 CPU）来实现。事实上，这是互斥锁的一个定义属性。

另一方面，还存在一种完全不同的锁——spinlock（在 Linux 内核中非常常用），其行为恰恰相反：它通过让失败的线程等待解锁操作来工作（旋转/轮询）——实际上，实际的 spinlock 实现要比这里描述的更加精细和高效；不过，这个讨论已经超出了本书的范围。乍一看，轮询似乎是让失败的线程等待解锁的一种不好的方式；它能够与 spinlock 很好地配合工作的原因在于临界区内所需的时间保证非常短（从技术上讲，小于执行两次上下文切换所需的时间），因此在临界区很小的情况下，使用 spinlock 比互斥锁更加高效。

尽管 pthread 实现确实提供了自旋锁，但应明确以下几点：

+   自旋锁只应该由使用实时操作系统调度策略（SCHED_FIFO，可能还有 SCHED_RR；我们在第十七章中讨论这些，*Linux 上的 CPU 调度*）的极端性能实时线程使用。

+   Linux 平台上的默认调度策略从不是实时的；它是非实时的 SCHED_OTHER 策略，非常适合非确定性应用程序；使用互斥锁是正确的方法。

+   在用户空间使用自旋锁不被认为是正确的设计方法；此外，代码将更容易受到死锁和（无限）优先级反转的影响。

出于上述原因，我们不深入研究以下 pthread spinlock API：

+   `pthread_spin_init(3)`

+   `pthread_spin_lock(3)`

+   `pthread_spin_trylock(3)`

+   `pthread_spin_unlock(3)`

+   `pthread_spin_destroy(3)`

如果需要，确保在各自的手册页中查找它们（但在使用时要格外小心！）。

# 一些互斥锁使用指南

除了之前提供的提示和指南（参考*锁定指南*部分）之外，也要考虑这一点：

+   应该使用多少个锁？

+   有了许多锁实例，如何知道何时使用哪个锁变量？

+   测试互斥锁是否被锁定。

我们逐一来看这些要点。

在小型应用程序中（如此处所示的类型），也许只使用一个锁来保护临界区就足够了；这样做的好处是保持简单（这很重要）。然而，在大型项目中，只使用一个锁来对可能遇到的每个临界区进行锁定可能会成为一个主要的性能瓶颈！思考一下为什么会这样：一旦代码中的任何地方遇到一个互斥锁，所有的并行性都会停止，代码将以串行方式运行；如果这种情况经常发生，性能将迅速下降。

有趣的是，Linux 内核多年来一直因为在代码库的大部分区域中使用了一把锁而导致了严重的性能问题——以至于它被昵称为**大内核锁**（**BKL**）（一个巨大的锁）。它最终在 Linux 内核的 2.6.39 版本中才被彻底摆脱（在 GitHub 存储库的*进一步阅读*部分中有关于 BKL 的更多链接）。

因此，虽然没有规则可以准确决定应该使用多少个锁，但启发式方法是考虑简单性与性能之间的权衡。在大型生产质量项目（如 Linux 内核）中，我们经常使用单个锁来保护单个数据——数据对象；通常，这是一种数据结构。这将确保在访问时保护全局数据，但只有实际访问它的代码路径，从而确保数据安全和并行性（性能）。

好的。现在，如果我们遵循这个指南，如果最终有几百个锁怎么办？（是的，在有几百个全局数据结构的大型项目中，这是完全可能的。）现在，我们有另一个实际问题：开发人员必须确保他们使用正确的锁来保护给定的数据结构（使用为数据结构 X 设计的锁 X 来访问数据结构 Y 有什么用呢？那将是一个严重的缺陷）。因此，一个实际的问题是我怎么确定哪个数据结构由哪个锁保护，或者另一种陈述方式是：我怎么确定哪个锁变量确实保护哪个数据结构？天真的解决方案是适当地命名每个锁，也许像`lock_<DataStructureName>`这样。嗯，这并不像看起来那么简单！

非正式的调查显示，程序员经常做的最困难的事情之一是变量命名！（请参阅 GitHub 存储库上的*进一步阅读*部分，以获取相关链接。）

因此，这里有一个提示：将保护给定数据结构的锁嵌入到数据结构本身中；换句话说，将其作为保护它的数据结构的成员！（再次，Linux 内核经常使用这种方法。）

# 互斥锁被锁定了吗？

在某些情况下，开发人员可能会想问：给定一个互斥锁，我能否找出它是锁定还是未锁定状态？也许推理是：如果锁定了，让我们解锁它。

有一种方法可以测试这个问题：使用`pthread_mutex_trylock(3)`API。如果它返回`EBUSY`，这意味着互斥锁当前被锁定（否则，它应该返回`0`，表示它是未锁定的）。但等等！这里存在一个固有的竞争条件；想一想：

```
if (pthread_mutex_trylock(&mylock) != EBUSY)) {    <-- time t1
    // it's unlocked                               <-- time t2
}
// it's locked
```

当我们到达时间 t2 时，没有保证另一个线程现在没有锁定该互斥锁！因此，这种方法是不正确的。（这种同步的唯一现实方法是放弃使用互斥锁，而是使用条件变量；这是我们在下一节中讨论的内容。）

这结束了我们对互斥锁的（相当长的）覆盖。在我们结束之前，我们想指出另一个有趣的地方：我们之前说过，原子意味着能够完整地运行临界代码段而不被中断。但现实是，我们的现代系统确实经常中断我们——硬件中断和异常是常态！因此，人们应该意识到：

+   在用户空间中，由于无法屏蔽硬件中断，进程和线程随时可能因此而中断。因此，使用用户空间代码实际上不可能真正地原子化。（但如果我们被硬件中断/故障/异常中断，那又怎样呢？它们会执行它们的工作并迅速将控制权交还给我们。我们几乎不可能与这些代码实体共享全局可写数据而发生竞争。）

+   在内核空间中，我们以操作系统特权运行，实际上可以屏蔽甚至硬件中断，从而使我们能够以真正的原子方式运行（你认为著名的 Linux 内核自旋锁是如何工作的？）。

现在我们已经介绍了用于锁定的典型 API，我们鼓励读者一方面以实际操作的方式尝试示例；另一方面，重新访问之前涵盖的部分，*锁定指南*和*死锁*。

# 条件变量

CV 是一种线程间的事件通知机制。在我们使用互斥锁来同步（串行化）对临界区的访问，从而保护它时，我们使用条件变量来促进有效的通信——根据数据项的值来同步进程的线程之间的通信。以下讨论将使这一点更清晰。

在多线程应用程序的设计和实现中，经常会面临这种情况：一个线程 B 正在执行一些工作，另一个线程 A 正在等待该工作的完成。只有当线程 B 完成工作时，线程 A 才能继续；我们如何在代码中高效地实现这一点？

# 没有 CV - 幼稚的方法

我们可能会记得线程的退出状态（通过`pthread_exit(3)`）会传递回调用`pthread_join(3)`的线程；我们能利用这个特性吗？好吧，不行：首先，并不一定线程 B 一旦指定的工作完成就会终止（它可能只是一个里程碑，而不是它要执行的所有工作），其次，即使它终止了，也许除了调用`pthread_join(3)`的线程之外，可能还有其他线程需要知道。

好吧，为什么不让线程 A 通过简单的技术来轮询完成工作，即当工作完成时，线程 B 将一个全局整数（称为`gWorkDone`）设置为 1（当然线程 A 会轮询它），也许就像伪代码中的以下内容：

| **时间** | **线程 B** | **线程 A** |
| --- | --- | --- |
| t0 | 初始化：`gWorkDone = 0` |  <通用> |
| t1 | 执行工作... | `while (!gWorkDone) ;` |
| t2 | ... | ... |
| t3 | 工作完成；`gWorkDone = 1` | ... |
| t4 |  | 检测到；跳出循环并继续 |

它可能有效，但实际上并不是。为什么呢？：

+   首先，对变量进行无限期的轮询在 CPU 方面非常昂贵（而且设计不好）。

+   其次，注意我们在没有保护的情况下操作共享可写全局变量；这正是引入数据竞争和 bug 的方法。

因此，前表中显示的方法被认为是幼稚、低效甚至可能有 bug（竞争条件）。

# 使用条件变量

正确的方法是使用 CV。条件变量是线程以高效的方式同步数据值的一种方式。它实现了与幼稚的轮询方法相同的最终结果，但以一种更高效、更重要的正确方式。

查看以下表格：

| **时间** | **线程 B** | **线程 A** |
| --- | --- | --- |
| t0 | 初始化：gWorkDone = 0；初始化{CV，互斥锁}对 |  <通用> |
| t1 |  | 等待来自线程 B 的信号：锁定相关的互斥锁；`pthread_cond_wait()` |
| t2 | 执行工作... |  <...阻塞...> |
| t3 | 工作完成；锁定相关的互斥锁；向线程 A 发出信号：`pthread_cond_signal()`；解锁相关的互斥锁 | ... |
| t4 |  | 解除阻塞；检查工作是否真的完成，如果是，解锁相关的互斥锁，然后继续... |

尽管前表显示了步骤的顺序，但需要一些解释。在幼稚的方法中，我们看到一个（严重的）缺点是全局共享数据变量在没有保护的情况下被操纵！条件变量通过要求条件变量始终与互斥锁相关联来解决了这个问题；我们可以将其视为**{CV，互斥锁}对**。

这个想法很简单：每当我们打算使用全局谓词来告诉我们工作是否已经完成（在我们的例子中是`gWorkDone`），我们会锁定互斥锁，读/写全局变量，解锁互斥锁，从而重要的是保护它。

CV 的美妙之处在于我们根本不需要轮询：等待工作完成的线程使用`pthread_cond_wait(3)`来阻塞（等待）事件发生，完成工作的线程通过`pthread_cond_signal(3)`API 向其对应的线程发出“信号”：

```
int pthread_cond_wait(pthread_cond_t *restrict cond,
                      pthread_mutex_t *restrict mutex);
int pthread_cond_signal(pthread_cond_t *cond);
```

尽管我们在这里使用了“信号”这个词，但这与我们在之前的第十一章和第十二章中讨论的 Unix/Linux 信号和信号毫无关系。

（注意{CV，mutex}对是如何一起使用的）。当然，就像线程一样，我们必须首先初始化 CV 及其关联的互斥锁；CV 可以通过静态方式进行初始化：

`pthread_cond_t cond = PTHREAD_COND_INITIALIZER; `

或者在运行时动态地通过以下 API 进行初始化：

```
int pthread_cond_init(pthread_cond_t *restrict cond,
                          const pthread_condattr_t *restrict attr);
```

如果需要设置 CV 的特定非默认属性，可以通过`pthread_condattr_set*(3P)`API 来设置，或者通过首先调用`pthread_condattr_init(3P)`API 并将初始化的 CV 属性对象作为第二个参数传递给`pthread_cond_init(3P)`来将 CV 设置为默认值：

`int pthread_condattr_init(pthread_condattr_t *attr);`

相反，当完成时，使用以下 API 来销毁 CV 属性对象和 CV 本身：

```
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
```

# 一个简单的 CV 使用演示应用程序

太多的初始化/销毁？查看下面的简单代码（`ch15/cv_simple.c`）将澄清它们的用法；我们编写一个小程序来演示条件变量及其关联互斥锁的用法。在这里，我们创建两个线程 A 和 B。然后，线程 B 执行一些工作，线程 A 在完成该工作后使用{CV，mutex}对进行同步：

为了便于阅读，只显示了源代码的关键部分；要查看完整的源代码，请构建并运行它。整个树可以从 GitHub 克隆到这里：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
...
#define LOCK_MTX(mtx) do { \
  int ret=0; \
  if ((ret = pthread_mutex_lock(mtx))) \
    FATAL("pthread_mutex_lock failed! [%d]\n", ret); \
} while(0)

#define UNLOCK_MTX(mtx) do { \
  int ret=0; \
  if ((ret = pthread_mutex_unlock(mtx))) \
    FATAL("pthread_mutex_unlock failed! [%d]\n", ret); \
} while(0)

static int gWorkDone=0;
/* The {cv,mutex} pair */
static pthread_cond_t mycv;
static pthread_mutex_t mycv_mutex = PTHREAD_MUTEX_INITIALIZER;
```

在前面的代码中，我们再次显示了实现互斥锁和解锁的宏，全局谓词（布尔）变量`gWorkDone`，当然还有{CV，mutex}对变量。

在下面的代码中，在 main 函数中，我们初始化了 CV 属性对象和 CV 本身：

```
// Init a condition variable attribute object
  if ((ret = pthread_condattr_init(&cvattr)))
      FATAL("pthread_condattr_init failed [%d].\n", ret);
  // Init a {cv,mutex} pair: condition variable & it's associated mutex
  if ((ret = pthread_cond_init(&mycv, &cvattr)))
      FATAL("pthread_cond_init failed [%d].\n", ret);
  // the mutex lock has been statically initialized above.
```

工作线程 A 和 B 被创建并开始他们的工作（我们这里不重复显示线程创建的代码）。在这里，你会找到线程 A 的工作例程 - 它必须等待直到线程 B 完成工作。我们使用{CV，mutex}对来轻松高效地实现这一点。

然而，该库要求应用程序在调用`pthread_cond_wait(3P)`API 之前保证关联的互斥锁被获取（锁定）；否则，这将导致未定义的行为（或者当互斥锁类型为`PTHREAD_MUTEX_ERRORCHECK`或者鲁棒互斥锁时会导致实际失败）。一旦线程在 CV 上阻塞，互斥锁会自动释放。

此外，如果在线程在等待条件上阻塞时传递了信号，它将被处理并且等待将会恢复；这也可能导致虚假唤醒的返回值为零（稍后会详细介绍）：

```
static void * workerA(void *msg)
{
  int ret=0;

  LOCK_MTX(&mycv_mutex);
  while (1) {
      printf(" [thread A] : now waiting on the CV for thread B to finish...\n");
      ret = pthread_cond_wait(&mycv, &mycv_mutex);
      // Blocking: associated mutex auto-released ...
      if (ret)
          FATAL("pthread_cond_wait() in thread A failed! [%d]\n", ret);
      // Unblocked: associated mutex auto-acquired upon release from the condition wait...

      printf(" [thread A] : recheck the predicate (is the work really "
 "done or is it a spurious wakeup?)\n");
 if (gWorkDone)
 break;
      printf(" [thread A] : SPURIOUS WAKEUP detected !!! "
             "(going back to CV waiting)\n");
  }
 UNLOCK_MTX(&mycv_mutex);
  printf(" [thread A] : (cv wait done) thread B has completed it's work...\n");
  pthread_exit((void *)0);
}
```

非常重要的是要理解：仅仅从`pthread_cond_wait(3P)`返回并不一定意味着我们等待（阻塞）的条件 - 在这种情况下，线程 B 完成工作 - 实际发生了！在软件中，可能会发生虚假唤醒（由于其他事件 - 也许是信号而导致的虚假唤醒）；健壮的软件将会在循环中重新检查条件，以确定我们被唤醒的原因是正确的 - 在我们这里，工作确实已经完成。这就是为什么我们在一个无限循环中运行，并且一旦从`pthread_cond_wait(3P)`中解除阻塞，就会检查全局整数`gWorkDone`是否确实具有我们期望的值（在这种情况下为 1，表示工作已经完成）。

好吧，但也要考虑这一点：即使是读取共享全局变量也会成为一个临界区（否则会导致脏读）；因此，在这之前我们需要获取互斥锁。啊，这就是{CV，mutex}对的一个内置自动机制，真的帮助了我们——一旦调用`pthread_cond_wait(3P)`，关联的互斥锁会自动原子释放（解锁），然后我们会阻塞在条件变量信号上。当另一个线程（这里是 B）向我们发出信号（显然是在同一个 CV 上），我们就会从`pthread_cond_wait(3P)`中解除阻塞，并且关联的互斥锁会自动原子锁定，允许我们重新检查全局变量（或其他内容）。所以，我们完成工作然后解锁它。

这是线程 B 的工作例程的代码，它执行一些示例工作然后向线程 A 发出信号：

```
static void * workerB(void *msg)
{
  int ret=0;

  printf(" [thread B] : perform the 'work' now (first sleep(1) :-)) ...\n");
  sleep(1);
  DELAY_LOOP('b', 72);
  gWorkDone = 1;

  printf("\n [thread B] : work done, signal thread A to continue ...\n");
  /* It's not strictly required to lock/unlock the associated mutex
   * while signalling; we do it here to be pedantically correct (and
   * to shut helgrind up).
   */
  LOCK_MTX(&mycv_mutex);
  ret = pthread_cond_signal(&mycv);
  if (ret)
      FATAL("pthread_cond_signal() in thread B failed! [%d]\n", ret);
  UNLOCK_MTX(&mycv_mutex);
  pthread_exit((void *)0);
}
```

注意注释详细说明了为什么我们在信号之前再次获取互斥锁。好的，让我们试一下（我们建议您构建和运行调试版本，因为这样延迟循环才能正确显示）：

```
$ ./cv_simple_dbg 
 [thread A] : now waiting on the CV for thread B to finish...
 [thread B] : perform the 'work' now (first sleep(1) :-)) ...
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
 [thread B] : work done, signal thread A to continue ...
 [thread A] : recheck the predicate (is the work really done or is it a spurious wakeup?)
 [thread A] : (cv wait done) thread B has completed it's work...
$ 
```

API 还提供了阻塞调用的超时变体：

```
int pthread_cond_timedwait(pthread_cond_t *restrict cond,
    pthread_mutex_t *restrict mutex, const struct timespec *restrict abstime);
```

语义与`pthread_cond_wait`相同，只是如果第三个参数 abstime 中指定的时间已经过去，API 会返回（失败值为`ETIMEDOUT`）。用于测量经过的时间的时钟是 CV 的属性，并且可以通过`pthread_condattr_setclock(3P)`API 进行设置。

（`pthread_cond_wait`和`pthread_cond_timedwait`都是取消点；这个主题将在下一章中讨论。）

# CV 广播唤醒

正如我们之前看到的，`pthread_cond_signal(3P)` API 用于解除阻塞在特定 CV 上的线程。这个 API 的变体如下：

`int pthread_cond_broadcast(pthread_cond_t *cond);`

这个 API 允许你解除阻塞在同一个 CV 上的多个线程。例如，如果有三个线程在同一个 CV 上阻塞；当应用程序调用`pthread_cond_broadcast(3P)`时，哪个线程会首先运行？嗯，这就像问，当线程被创建时，哪一个会首先运行（回想一下前一章中的讨论）。答案当然是，在没有特定调度策略的情况下，这是不确定的。当应用到 CV 解除阻塞并在 CPU 上运行时，也是同样的答案。

继续，一旦等待的线程解除阻塞，要记住关联的互斥锁会被获取，但当然只有一个解除阻塞的线程会首先获取它。同样，这取决于调度策略和优先级。在所有默认情况下，无法确定哪个线程会首先获取它。无论如何，在没有实时特性的情况下，这对应用程序不应该有影响（如果应用程序是实时的，那么首先在每个应用程序线程上阅读我们的第十七章，*Linux 上的 CPU 调度*，并设置实时调度策略和优先级）。

此外，这些 API 的手册页面清楚地指出，尽管调用前面的 API（`pthread_cond_signal`和`pthread_cond_broadcast`）的线程在这样做时不需要持有关联的互斥锁（请记住，我们总是有{CV，mutex}对），但严谨的正确语义要求他们持有互斥锁，执行信号或广播，然后解锁互斥锁（我们的示例应用程序`ch15/cv_simple.c`遵循了这一准则）。

为了结束对 CV 的讨论，这里有一些建议：

+   不要在信号处理程序中使用条件变量方法；该代码不被认为是异步信号安全的（回想我们之前的第十一章，*信号-第一部分*和第十二章，*信号-第二部分*）。

+   使用众所周知的 Valgrind 套件（回想一下，我们在第六章中介绍了 Valgrind 的 Memcheck 工具，*内存问题的调试工具*），特别是名为 helgrind 的工具，有时可以检测到 pthread 多线程应用程序中的同步错误（数据竞争）。使用方法很简单：

`$ valgrind --tool=helgrind [-v] <app_name> [app-params ...]`：

+   然而，像这种类型的许多工具一样，helgrind 经常会引发许多错误警报。例如，我们发现在我们之前编写的`cv_simple`应用程序中消除`printf(3)`会消除 helgrind 中的许多（错误的）错误和警告！

+   在调用`pthread_cond_signal`和/或`pthread_cond_broadcast` API 之前，如果未首先获取相关的互斥锁（不是必需的），helgrind 会抱怨。

请尝试使用 helgrind（再次提醒，GitHub 存储库的*进一步阅读*部分有链接到其（非常好的）文档）。

# 摘要

我们开始本章时，重点关注并发性、原子性的关键概念，以及识别和保护关键部分的必要性。锁定是实现这一点的典型方式；pthread API 集提供了强大的互斥锁来实现。然而，在大型项目中使用锁定，尤其是隐藏的问题和危险，我们讨论了有用的*锁定指南*、*死锁*及其避免。

本章随后指导读者使用 pthread 互斥锁。这里涵盖了很多内容，包括各种互斥锁属性，识别和避免优先级反转问题的重要性，以及互斥锁的变化。最后，我们介绍了条件变量（CV）的需求和用法，以及如何有效地促进线程间事件通知。

下一章是这个关于多线程的三部曲的最后一章；在其中，我们将专注于线程安全的重要问题（和线程安全的 API），线程取消和清理，将信号与 MT 混合，一些常见问题和提示，并看看多进程与多线程模型的利弊。
