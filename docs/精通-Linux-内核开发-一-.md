# 精通 Linux 内核开发（一）

> 原文：[`zh.annas-archive.org/md5/B50238228DC7DE75D9C3CCE2886AAED2`](https://zh.annas-archive.org/md5/B50238228DC7DE75D9C3CCE2886AAED2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

*精通 Linux 内核开发*着眼于 Linux 内核，其内部

安排和设计，以及各种核心子系统，帮助您获得

对这个开源奇迹的重要理解。您将了解 Linux 内核，由于其众多贡献者的集体智慧，它仍然如此优雅，这要归功于其出色的设计。

本书还涵盖了所有关键的内核代码、核心数据结构、函数和宏，为您提供了内核核心服务和机制实现细节的全面基础。您还将了解 Linux 内核作为设计良好的软件，这使我们对软件设计有了深入的见解，这种设计容易扩展，但基本上是强大而安全的。

# 本书内容

第一章，理解进程、地址空间和线程，仔细研究了 Linux 的一个主要抽象称为进程以及整个生态系统，这些都促进了这种抽象。我们还将花时间了解地址空间、进程创建和线程。

第二章，*解析进程调度器*，解释了进程调度，这是任何操作系统的重要方面。在这里，我们将建立对 Linux 采用的不同调度策略的理解，以实现有效的进程执行。

第三章，*信号管理*，帮助理解信号使用的所有核心方面，它们的表示、数据结构以及用于信号生成和传递的内核例程。

第四章，*内存管理和分配器*，带领我们穿越 Linux 内核最关键的方面之一，理解内存表示和分配的各种微妙之处。我们还将评估内核在最大化资源利用方面的效率。

第五章，*文件系统和文件 I/O*，传授了对典型文件系统、其结构、设计以及使其成为操作系统基本组成部分的理解。我们还将通过 VFS 全面了解抽象，使用常见的分层架构设计。

第六章，*进程间通信*，涉及内核提供的各种 IPC 机制。我们将探索每种 IPC 机制的布局和关系，以及 SysV 和 POSIX IPC 机制。

第七章，*虚拟内存管理*，解释了内存管理，详细介绍了虚拟内存管理和页表。我们将研究虚拟内存子系统的各个方面，如进程虚拟地址空间及其段、内存描述符结构、内存映射和 VMA 对象、页缓存和页表的地址转换。

第八章，*内核同步和锁定*，使我们能够理解内核提供的各种保护和同步机制，并理解这些机制的优点和缺点。我们将尝试欣赏内核解决这些不同同步复杂性的坚韧性。

第九章，*中断和延迟工作*，讨论了中断，这是任何操作系统完成必要和优先任务的关键方面。我们将了解 Linux 中中断是如何生成、处理和管理的。我们还将研究各种底半部机制。

第十章**，** *时钟和时间管理*，揭示了内核如何测量和管理时间。我们将查看所有关键的与时间相关的结构、例程和宏，以帮助我们有效地管理时间。

第十一章，*模块管理*，快速查看模块，内核在管理模块方面的基础设施以及涉及的所有核心数据结构。这有助于我们理解内核如何融入动态可扩展性。

# 您需要为本书做好准备

除了深刻理解 Linux 内核及其设计的渴望外，您需要对 Linux 操作系统有一定的了解，并且对开源软件的概念有一定的了解，才能开始阅读本书。但这并不是必需的，任何对获取有关 Linux 系统及其工作的详细信息感兴趣的人都可以阅读本书。

# 这本书是为谁准备的

+   这本书是为系统编程爱好者和专业人士准备的，他们希望加深对 Linux 内核及其各种组成部分的理解。

+   这是一本对从事各种与内核相关项目的开发人员非常有用的书籍。

+   软件工程的学生可以将其用作理解 Linux 内核及其设计原则的参考指南。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“在 `loop()` 函数中，我们读取传感器的距离值，然后在串行端口上显示它。”

代码块设置如下：

```
/* linux-4.9.10/arch/x86/include/asm/thread_info.h */
struct thread_info {
 unsigned long flags; /* low level flags */
};
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“转到 Sketch | Include Library | Manage Libraries，然后会出现一个对话框。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法-您喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它有助于我们开发出您真正能够充分利用的标题。要向我们发送一般反馈，只需发送电子邮件至 `feedback@packtpub.com`，并在主题中提及书名。如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南，网址为 [www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经是 Packt 图书的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

# 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误-可能是文本或代码中的错误-我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书，点击“勘误提交表”链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的勘误列表中。要查看以前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需的信息将出现在“勘误”部分下。

# 盗版

互联网上盗版受版权保护的材料是跨所有媒体持续存在的问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何形式的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。我们感谢您帮助保护我们的作者和我们为您提供有价值内容的能力。

# 问题

如果您对本书的任何方面有问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。


# 第一章：理解进程、地址空间和线程

当内核服务在当前进程上下文中被调用时，它的布局为更详细地探索内核打开了正确的路径。本章中的努力集中在理解进程和内核为它们提供的基础生态系统上。我们将在本章中探讨以下概念：

+   程序到进程

+   进程布局

+   虚拟地址空间

+   内核和用户空间

+   进程 API

+   进程描述符

+   内核堆栈管理

+   线程

+   Linux 线程 API

+   数据结构

+   命名空间和 cgroups

# 进程

从本质上讲，计算系统被设计、开发并经常进行调整，以便有效地运行用户应用程序。计算平台中的每个元素都旨在实现有效和高效地运行应用程序的方式。换句话说，计算系统存在是为了运行各种应用程序。应用程序可以作为专用设备中的固件运行，也可以作为系统软件（操作系统）驱动的系统中的“进程”运行。

在本质上，进程是内存中程序的运行实例。当程序（在磁盘上）被获取到内存中执行时，程序到进程的转换发生。

程序的二进制映像包含**代码**（带有所有二进制指令）和**数据**（带有所有全局数据），这些数据被映射到具有适当访问权限（读、写和执行）的内存区域。除了代码和数据，进程还被分配了额外的内存区域，称为**堆栈**（用于分配带有自动变量和函数参数的函数调用帧）和*堆*（用于运行时的动态分配）。

同一程序的多个实例可以存在，它们具有各自的内存分配。例如，对于具有多个打开标签页的网络浏览器（同时运行浏览会话），内核将每个标签页视为一个进程实例，并分配唯一的内存。

以下图表示了内存中进程的布局：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00005.jpeg)

# 被称为地址空间的幻觉

现代计算平台预期能够有效地处理大量进程。因此，操作系统必须处理为所有竞争进程在物理内存中分配唯一内存，并确保它们可靠地执行。随着多个进程同时竞争和执行（*多任务处理*），操作系统必须确保每个进程的内存分配受到另一个进程的意外访问的保护。

为了解决这个问题，内核在进程和物理内存之间提供了一层抽象，称为*虚拟* *地址空间*。虚拟地址空间是进程对内存的视图；这是运行程序查看内存的方式。

虚拟地址空间创建了一个幻觉，即每个进程在执行时独占整个内存。这种内存的抽象视图称为*虚拟内存*，是由内核的内存管理器与 CPU 的 MMU 协调实现的。每个进程都被赋予一个连续的 32 位或 64 位地址空间，由体系结构限制并且对该进程唯一。通过 MMU 将每个进程限制在其虚拟地址空间中，任何进程试图访问其边界之外的地址区域的尝试都将触发硬件故障，使得内存管理器能够检测和终止违规进程，从而确保保护。

以下图描述了为每个竞争进程创建的地址空间的幻觉：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00006.jpeg)

# 内核和用户空间

现代操作系统不仅防止一个进程访问另一个进程，还防止进程意外访问或操纵内核数据和服务（因为内核被所有进程共享）。

操作系统通过将整个内存分成两个逻辑部分，用户空间和内核空间，来实现这种保护。这种分割确保了所有被分配地址空间的进程都映射到内存的用户空间部分，而内核数据和服务则在内核空间中运行。内核通过与硬件协调实现了这种保护。当应用进程从其代码段执行指令时，CPU 处于用户模式。当一个进程打算调用内核服务时，它需要将 CPU 切换到特权模式（内核模式），这是通过称为 API（应用程序编程接口）的特殊函数实现的。这些 API 使用户进程可以使用特殊的 CPU 指令切换到内核空间，然后通过*系统调用*执行所需的服务。在完成所请求的服务后，内核执行另一个模式切换，这次是从内核模式切换回用户模式，使用另一组 CPU 指令。

系统调用是内核向应用进程公开其服务的接口；它们也被称为*内核入口点*。由于系统调用是在内核空间中实现的，相应的处理程序通过用户空间中的 API 提供。API 抽象还使调用相关系统调用更容易和方便。

下图描述了虚拟化内存视图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00007.jpeg)

# 进程上下文

当一个进程通过系统调用请求内核服务时，内核将代表调用进程执行。此时内核被称为处于*进程上下文*中执行。同样，内核也会响应其他硬件实体引发的*中断*；在这里，内核在*中断上下文*中执行。在中断上下文中，内核不是代表任何进程运行。

# 进程描述符

从一个进程诞生到退出，都是内核的进程管理子系统执行各种操作，包括进程创建、分配 CPU 时间、事件通知以及进程终止时的销毁。

除了地址空间外，内存中的一个进程还被分配了一个称为*进程描述符*的数据结构，内核用它来识别、管理和调度进程。下图描述了内核中进程地址空间及其相应的进程描述符：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00008.jpeg)

在 Linux 中，进程描述符是在`<linux/sched.h>`中定义的`struct task_struct`类型的实例，它是一个中心数据结构，包含了进程持有的所有属性、标识细节和资源分配条目。查看`struct task_struct`就像窥视内核看到或处理进程的窗口。

由于任务结构包含了与各种内核子系统功能相关的广泛数据元素，本章讨论所有元素的目的和范围将超出上下文。我们将考虑一些与进程管理相关的重要元素。

# 进程属性-关键元素

进程属性定义了进程的所有关键和基本特征。这些元素包含了进程的状态和标识以及其他重要的关键值。

# 状态

一个进程从产生到退出可能存在于各种状态，称为*进程状态*，它们定义了进程的当前状态：

+   **TASK_RUNNING** (0)：任务正在执行或在调度器运行队列中争夺 CPU。

+   **TASK_INTERRUPTIBLE**（1）：任务处于可中断的等待状态；它会一直等待，直到等待条件变为真，比如互斥锁的可用性、设备准备好进行 I/O、休眠时间已过或者独占唤醒调用。在这种等待状态下，为进程生成的任何信号都会被传递，导致它在等待条件满足之前被唤醒。

+   **TASK_KILLABLE**：这类似于**TASK_INTERRUPTIBLE**，唯一的区别是中断只能发生在致命信号上，这使得它成为**TASK_INTERRUPTIBLE**的更好替代品。

+   **TASK_UNINTERRUTPIBLE**（2）：任务处于不可中断的等待状态，类似于**TASK_INTERRUPTIBLE**，只是对于正在睡眠的进程生成的信号不会导致唤醒。当等待的事件发生时，进程转换为**TASK_RUNNING**。这种进程状态很少被使用。

+   **TASK_STOPPED**（4）：任务已收到 STOP 信号。在收到继续信号（SIGCONT）后将恢复运行。

+   **TASK_TRACED**（8）：当进程正在被梳理时，它被称为处于被跟踪状态，可能是由调试器进行的。

+   **EXIT_ZOMBIE**（32）：进程已终止，但其资源尚未被回收。

+   **EXIT_DEAD**（16）：子进程已终止，并且在父进程使用*wait*收集子进程的退出状态后，所有其持有的资源都被释放。

以下图示了进程状态：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00009.jpeg)

# pid

该字段包含一个称为**PID**的唯一进程标识符。在 Linux 中，PID 的类型为`pid_t`（整数）。尽管 PID 是一个整数，但默认的最大 PID 数量是 32,768，通过`/proc/sys/kernel/pid_max`接口指定。该文件中的值可以设置为最多 2²²（`PID_MAX_LIMIT`，约 400 万）的任何值。

为了管理 PID，内核使用位图。该位图允许内核跟踪正在使用的 PID 并为新进程分配唯一的 PID。每个 PID 在 PID 位图中由一个位标识；PID 的值是根据其对应位的位置确定的。位图中值为 1 的位表示对应的 PID 正在*使用*，值为 0 的位表示空闲的 PID。每当内核需要分配一个唯一的 PID 时，它会寻找第一个未设置的位并将其设置为 1，反之，要释放一个 PID，它会将对应的位从 1 切换为 0。

# tgid

该字段包含线程组 ID。为了便于理解，可以这样说，当创建一个新进程时，其 PID 和 TGID 是相同的，因为该进程恰好是唯一的线程。当进程生成一个新线程时，新的子线程会获得一个唯一的 PID，但会继承父线程的 TGID，因为它属于同一线程组。TGID 主要用于支持多线程进程。我们将在本章的线程部分详细介绍。

# 线程信息

该字段包含特定于处理器的状态信息，是任务结构的关键要素。本章的后续部分将详细介绍`thread_info`的重要性。

# 标志

标志字段记录与进程对应的各种属性。字段中的每个位对应进程生命周期中的各个阶段。每个进程的标志在`<linux/sched.h>`中定义：

```
#define PF_EXITING           /* getting shut down */
#define PF_EXITPIDONE        /* pi exit done on shut down */
#define PF_VCPU              /* I'm a virtual CPU */
#define PF_WQ_WORKER         /* I'm a workqueue worker */
#define PF_FORKNOEXEC        /* forked but didn't exec */
#define PF_MCE_PROCESS       /* process policy on mce errors */
#define PF_SUPERPRIV         /* used super-user privileges */
#define PF_DUMPCORE          /* dumped core */
#define PF_SIGNALED          /* killed by a signal */
#define PF_MEMALLOC          /* Allocating memory */
#define PF_NPROC_EXCEEDED    /* set_user noticed that RLIMIT_NPROC was exceeded */
#define PF_USED_MATH         /* if unset the fpu must be initialized before use */
#define PF_USED_ASYNC        /* used async_schedule*(), used by module init */
#define PF_NOFREEZE          /* this thread should not be frozen */
#define PF_FROZEN            /* frozen for system suspend */
#define PF_FSTRANS           /* inside a filesystem transaction */
#define PF_KSWAPD            /* I am kswapd */
#define PF_MEMALLOC_NOIO0    /* Allocating memory without IO involved */
#define PF_LESS_THROTTLE     /* Throttle me less: I clean memory */
#define PF_KTHREAD           /* I am a kernel thread */
#define PF_RANDOMIZE         /* randomize virtual address space */
#define PF_SWAPWRITE         /* Allowed to write to swap */
#define PF_NO_SETAFFINITY    /* Userland is not allowed to meddle with cpus_allowed */
#define PF_MCE_EARLY         /* Early kill for mce process policy */
#define PF_MUTEX_TESTER      /* Thread belongs to the rt mutex tester */
#define PF_FREEZER_SKIP      /* Freezer should not count it as freezable */
#define PF_SUSPEND_TASK      /* this thread called freeze_processes and should not be frozen */
```

# exit_code 和 exit_signal

这些字段包含任务的退出值和导致终止的信号的详细信息。这些字段在子进程终止时通过`wait()`由父进程访问。

# comm

该字段保存了用于启动进程的可执行二进制文件的名称。

# ptrace

该字段在使用`ptrace()`系统调用将进程置于跟踪模式时启用并设置。

# 进程关系-关键要素

每个进程都可以与父进程建立父子关系。同样，由同一进程生成的多个进程被称为*兄弟进程*。这些字段建立了当前进程与另一个进程的关系。

# real_parent 和 parent

这些是指向父任务结构的指针。对于正常进程，这两个指针都指向相同的`task_struct`*；*它们只在使用`posix`线程实现的多线程进程中有所不同。对于这种情况，`real_parent`指的是父线程任务结构，而`parent`指的是将 SIGCHLD 传递给的进程任务结构。

# 子进程

这是子任务结构列表的指针。

# 兄弟

这是兄弟任务结构列表的指针。

# group_leader

这是指向进程组领导者的任务结构的指针。

# 调度属性 - 关键元素

所有竞争进程必须获得公平的 CPU 时间，因此需要基于时间片和进程优先级进行调度。这些属性包含调度程序在决定哪个进程获得优先级时使用的必要信息。

# prio 和 static_prio

`prio`有助于确定进程的调度优先级。如果进程被分配了实时调度策略，则此字段在`1`到`99`的范围内保存进程的静态优先级（由`sched_setscheduler()`指定）。对于正常进程，此字段保存从 nice 值派生的动态优先级。

# se、rt 和 dl

每个任务都属于调度实体（任务组），因为调度是在每个实体级别上进行的。`se`用于所有正常进程，`rt`用于实时进程，`dl`用于截止进程。我们将在下一章中更多地讨论这些属性。

# 策略

此字段包含有关进程调度策略的信息，有助于确定其优先级。

# cpus_allowed

此字段指定进程的 CPU 掩码，即进程在多处理器系统中有资格被调度到哪个 CPU。

# rt_priority

此字段指定实时调度策略应用的优先级。对于非实时进程，此字段未使用。

# 进程限制 - 关键元素

内核强加资源限制，以确保系统资源在竞争进程之间公平分配。这些限制保证随机进程不会垄断资源的所有权。有 16 种不同类型的资源限制，`task structure`指向`struct rlimit`*类型的数组，其中每个偏移量保存特定资源的当前值和最大值。

```
/*include/uapi/linux/resource.h*/
struct rlimit {
  __kernel_ulong_t        rlim_cur;
  __kernel_ulong_t        rlim_max;
};
These limits are specified in *include/uapi/asm-generic/resource.h* 
 #define RLIMIT_CPU        0       /* CPU time in sec */
 #define RLIMIT_FSIZE      1       /* Maximum filesize */
 #define RLIMIT_DATA       2       /* max data size */
 #define RLIMIT_STACK      3       /* max stack size */
 #define RLIMIT_CORE       4       /* max core file size */
 #ifndef RLIMIT_RSS
 # define RLIMIT_RSS       5       /* max resident set size */
 #endif
 #ifndef RLIMIT_NPROC
 # define RLIMIT_NPROC     6       /* max number of processes */
 #endif
 #ifndef RLIMIT_NOFILE
 # define RLIMIT_NOFILE    7       /* max number of open files */
 #endif
 #ifndef RLIMIT_MEMLOCK
 # define RLIMIT_MEMLOCK   8       /* max locked-in-memory   
 address space */
 #endif
 #ifndef RLIMIT_AS
 # define RLIMIT_AS        9       /* address space limit */
 #endif
 #define RLIMIT_LOCKS      10      /* maximum file locks held */
 #define RLIMIT_SIGPENDING 11      /* max number of pending signals */
 #define RLIMIT_MSGQUEUE   12      /* maximum bytes in POSIX mqueues */
 #define RLIMIT_NICE       13      /* max nice prio allowed to 
 raise to 0-39 for nice level 19 .. -20 */
 #define RLIMIT_RTPRIO     14      /* maximum realtime priority */
 #define RLIMIT_RTTIME     15      /* timeout for RT tasks in us */
 #define RLIM_NLIMITS      16
```

# 文件描述符表 - 关键元素

在进程的生命周期中，它可能访问各种资源文件以完成其任务。这导致进程打开、关闭、读取和写入这些文件。系统必须跟踪这些活动；文件描述符元素帮助系统知道进程持有哪些文件。

# fs

文件系统信息存储在此字段中。

# 文件

文件描述符表包含指向进程打开以执行各种操作的所有文件的指针。文件字段包含一个指针，指向此文件描述符表。

# 信号描述符 - 关键元素

为了处理信号，*任务结构*具有各种元素，确定信号的处理方式。

# 信号

这是`struct signal_struct`*的类型，其中包含与进程关联的所有信号的信息。

# sighand

这是`struct sighand_struct`*的类型，其中包含与进程关联的所有信号处理程序。

# sigset_t blocked, real_blocked

这些元素标识当前由进程屏蔽或阻塞的信号。

# 待处理

这是`struct sigpending`*的类型，用于标识生成但尚未传递的信号。

# sas_ss_sp

此字段包含指向备用堆栈的指针，用于信号处理。

# sas_ss_size

此字段显示备用堆栈的大小，用于信号处理。

# 内核堆栈

随着当前一代计算平台由能够运行同时应用程序的多核硬件驱动，当请求相同进程时，多个进程同时启动内核模式切换的可能性已经内置。为了能够处理这种情况，内核服务被设计为可重入，允许多个进程参与并使用所需的服务。这要求请求进程维护自己的私有内核栈，以跟踪内核函数调用序列，存储内核函数的本地数据等。

内核栈直接映射到物理内存，要求布局在一个连续的区域内。默认情况下，x86-32 和大多数其他 32 位系统的内核栈为 8kb（在内核构建期间可以配置为 4k 内核栈），在 x86-64 系统上为 16kb。

当内核服务在当前进程上下文中被调用时，它们需要在承诺任何相关操作之前验证进程的特权。为了执行这样的验证，内核服务必须访问当前进程的任务结构并查看相关字段。同样，内核例程可能需要访问当前的“任务结构”来修改各种资源结构，例如信号处理程序表，寻找未决信号，文件描述符表和内存描述符等。为了在运行时访问“任务结构”，当前“任务结构”的地址被加载到处理器寄存器中（所选择的寄存器是特定于架构的），并通过内核全局宏`current`（在特定于架构的内核头文件`asm/current.h`中定义）提供：

```
  /* arch/ia64/include/asm/current.h */
  #ifndef _ASM_IA64_CURRENT_H
  #define _ASM_IA64_CURRENT_H
  /*
  * Modified 1998-2000
  *      David Mosberger-Tang <davidm@hpl.hp.com>, Hewlett-Packard Co
  */
  #include <asm/intrinsics.h>
  /*
  * In kernel mode, thread pointer (r13) is used to point to the 
    current task
  * structure.
  */
 #define current ((struct task_struct *) ia64_getreg(_IA64_REG_TP))
 #endif /* _ASM_IA64_CURRENT_H */
 /* arch/powerpc/include/asm/current.h */
 #ifndef _ASM_POWERPC_CURRENT_H
 #define _ASM_POWERPC_CURRENT_H
 #ifdef __KERNEL__
 /*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
 struct task_struct;
 #ifdef __powerpc64__
 #include <linux/stddef.h>
 #include <asm/paca.h>
 static inline struct task_struct *get_current(void)
 {
       struct task_struct *task;

       __asm__ __volatile__("ld %0,%1(13)"
       : "=r" (task)
       : "i" (offsetof(struct paca_struct, __current)));
       return task;
 }
 #define current get_current()
 #else
 /*
 * We keep `current' in r2 for speed.
 */
 register struct task_struct *current asm ("r2");
 #endif
 #endif /* __KERNEL__ */
 #endif /* _ASM_POWERPC_CURRENT_H */
```

然而，在寄存器受限的架构中，如果寄存器很少，那么保留一个寄存器来保存当前任务结构的地址是不可行的。在这样的平台上，当前进程的“任务结构”直接放置在它拥有的内核栈的顶部。这种方法在定位“任务结构”方面具有显著优势，只需屏蔽栈指针的最低有效位即可。

随着内核的演变，`任务结构`变得越来越大，无法包含在内核栈中，而内核栈在物理内存中已经受限（8Kb）。因此，`任务结构`被移出内核栈，除了定义进程的 CPU 状态和其他低级处理器特定信息的一些关键字段之外。然后，这些字段被包装在一个新创建的结构体`struct thread_info`中。这个结构体位于内核栈的顶部，并提供一个指针，指向可以被内核服务使用的当前`任务结构`。

```
struct thread_info for x86 architecture (kernel 3.10):
```

```
/* linux-3.10/arch/x86/include/asm/thread_info.h */ struct thread_info {
 struct task_struct *task; /* main task structure */
 struct exec_domain *exec_domain; /* execution domain */
 __u32 flags; /* low level flags */
 __u32 status; /* thread synchronous flags */
 __u32 cpu; /* current CPU */
 int preempt_count; /* 0 => preemptable, <0 => BUG */
 mm_segment_t addr_limit;
 struct restart_block restart_block;
 void __user *sysenter_return;
 #ifdef CONFIG_X86_32
 unsigned long previous_esp; /* ESP of the previous stack in case of   
 nested (IRQ) stacks */
 __u8 supervisor_stack[0];
 #endif
 unsigned int sig_on_uaccess_error:1;
 unsigned int uaccess_err:1; /* uaccess failed */
};
```

使用`thread_info`包含与进程相关的信息，除了`任务结构`之外，内核对当前进程结构有多个视图：`struct task_struct`，一个与架构无关的信息块，以及`thread_info`，一个特定于架构的信息块。以下图示了`thread_info`和`task_struct`：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00010.jpeg)

对于使用`thread_info`的架构，当前宏的实现被修改为查看内核栈顶部以获取对当前`thread_info`和通过它对`当前任务结构`的引用。以下代码片段显示了 x86-64 平台的当前实现：

```
  #ifndef __ASM_GENERIC_CURRENT_H
  #define __ASM_GENERIC_CURRENT_H
  #include <linux/thread_info.h>

    __attribute_const__;

  static inline struct thread_info *current_thread_info(void)
  {
        **return (struct thread_info *)**  **                (current_stack_pointer & ~(THREAD_SIZE - 1));**
  }
PER_CPU variable:
```

```
#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#include <linux/compiler.h>
#include <asm/percpu.h>

#ifndef __ASSEMBLY__
struct task_struct;

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
        return this_cpu_read_stable(current_task);
}

#define current get_current()

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CURRENT_H */
thread_info structure with just one element:
```

```
/* linux-4.9.10/arch/x86/include/asm/thread_info.h */
struct thread_info {
 unsigned long flags; /* low level flags */
};
```

# 栈溢出问题

与用户模式不同，内核模式堆栈存在于直接映射的内存中。当一个进程调用内核服务时，可能会出现内部嵌套深的情况，有可能会超出立即内存范围。最糟糕的是内核对这种情况毫不知情。内核程序员通常会使用各种调试选项来跟踪堆栈使用情况并检测溢出，但这些方法并不方便在生产系统上防止堆栈溢出。通过使用*守护页面*进行传统保护在这里也被排除了（因为这会浪费一个实际的内存页面）。

内核程序员倾向于遵循编码标准--最小化使用本地数据，避免递归，避免深度嵌套等--以降低堆栈溢出的概率。然而，实现功能丰富且深度分层的内核子系统可能会带来各种设计挑战和复杂性，特别是在存储子系统中，文件系统、存储驱动程序和网络代码可以堆叠在几个层中，导致深度嵌套的函数调用。

Linux 内核社区一直在思考如何防止这种溢出，为此，决定将内核堆栈扩展到 16kb（x86-64，自内核 3.15 以来）。扩展内核堆栈可能会防止一些溢出，但会占用大量直接映射的内核内存用于每个进程的内核堆栈。然而，为了系统的可靠运行，期望内核能够优雅地处理在生产系统上出现的堆栈溢出。

在 4.9 版本中，内核引入了一种新的系统来设置虚拟映射内核堆栈。由于虚拟地址目前用于映射甚至是直接映射的页面，因此内核堆栈实际上并不需要物理上连续的页面。内核为虚拟映射内存保留了一个单独的地址范围，当调用`vmalloc()`时，这个范围内的地址被分配。这段内存范围被称为**vmalloc 范围**。主要用于当程序需要大块虚拟连续但物理分散的内存时。使用这种方法，内核堆栈现在可以分配为单独的页面，映射到 vmalloc 范围。虚拟映射还可以防止溢出，因为可以分配一个无访问守护页面，并且可以通过页表项（而不浪费实际页面）来分配。守护页面将促使内核在内存溢出时弹出一个 oops 消息，并对溢出的进程发起 kill。

目前，带有守护页面的虚拟映射内核堆栈仅适用于 x86-64 架构（对其他架构的支持似乎将会跟进）。这可以通过选择`HAVE_ARCH_VMAP_STACK`或`CONFIG_VMAP_STACK`构建时选项来启用。

# 进程创建

在内核引导期间，会生成一个名为`init`的内核线程，该线程被配置为初始化第一个用户模式进程（具有相同的名称）。然后，`init`（pid 1）进程被配置为执行通过配置文件指定的各种初始化操作，创建多个进程。进一步创建的每个子进程（可能会创建自己的子进程）都是*init*进程的后代。因此，这些进程最终形成了一个类似树状结构或单一层次模型的结构。`shell`，就是这样一个进程，当调用程序执行时，它成为用户创建用户进程的接口。

Fork、vfork、exec、clone、wait 和 exit 是用于创建和控制新进程的核心内核接口。这些操作是通过相应的用户模式 API 调用的。

# fork()

`Fork()`是自* nix 系统的核心“Unix 线程 API”之一，自古老的 Unix 版本问世以来一直可用。恰如其名，它从运行中的进程中分叉出一个新进程。当`fork()`成功时，通过复制调用者的`地址空间`和`任务结构`创建新进程（称为`子进程`）。从`fork()`返回时，调用者（父进程）和新进程（子进程）都从同一代码段中执行指令，该代码段在写时复制下被复制。`Fork()`也许是唯一一个以调用者进程的上下文进入内核模式的 API，并在成功时返回到调用者和子进程（新进程）的用户模式上下文。

父进程的`任务结构`的大多数资源条目，如内存描述符、文件描述符表、信号描述符和调度属性，都被子进程继承，除了一些属性，如内存锁、未决信号、活动定时器和文件记录锁（有关例外的完整列表，请参阅 fork(2)手册页）。子进程被分配一个唯一的`pid`，并通过其`任务结构`的`ppid`字段引用其父进程的`pid`；子进程的资源利用和处理器使用条目被重置为零。

父进程使用`wait()`系统调用更新自己关于子进程状态的信息，并通常等待子进程的终止。如果没有调用`wait()`，子进程可能会终止并进入僵尸状态。

# 写时复制（COW）

父进程的复制以创建子进程需要克隆用户模式地址空间（`堆栈`、`数据`、`代码`和`堆`段）和父进程的任务结构，这将导致执行开销，从而导致不确定的进程创建时间。更糟糕的是，如果父进程和子进程都没有对克隆资源进行任何状态更改操作，这种克隆过程将变得毫无意义。

根据 COW，当创建子进程时，它被分配一个唯一的`任务结构`，其中所有资源条目（包括页表）都指向父进程的`任务结构`，父子进程都具有只读访问权限。当任一进程启动状态更改操作时，资源才会真正复制，因此称为*写时复制*（COW 中的`写`意味着状态更改）。COW 确实带来了效率和优化，通过推迟复制进程数据的需求，以及在只读发生时，完全避免复制。这种按需复制还减少了所需的交换页面数量，减少了交换所需的时间，并可能有助于减少需求分页。

# exec

有时创建子进程可能没有用，除非它运行一个全新的程序：`exec`系列调用正好满足这一目的。`exec`用新的可执行二进制文件替换进程中的现有程序。

```
#include <unistd.h>
int execve(const char *filename, char *const argv[],
char *const envp[]);
```

`execve`是执行作为其第一个参数传递的程序二进制文件的系统调用。第二和第三个参数是以空字符结尾的参数和环境字符串数组，将作为命令行参数传递给新程序。这个系统调用也可以通过各种`glibc`（库）包装器调用，这些包装器被发现更加方便和灵活。

```
#include <unistd.h>
extern char **environ;
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg,
..., char * const envp[]);
int execv(const char *path, char *constargv[]);
int execvp(const char *file, char *constargv[]);
int execvpe(const char *file, char *const argv[],
char *const envp[]);
```

命令行用户界面程序如`shell`使用`exec`接口启动用户请求的程序二进制文件。

# vfork()

与`fork()`不同，`vfork()`创建一个子进程并阻塞父进程，这意味着子进程作为单个线程运行，不允许并发；换句话说，父进程暂时挂起，直到子进程退出或调用`exec()`。子进程共享父进程的数据。

# Linux 对线程的支持

进程中的执行流被称为**线程**，这意味着每个进程至少会有一个执行线程。多线程意味着进程中存在多个执行上下文的流。在现代的多核架构中，进程中的多个执行流可以真正并发，实现公平的多任务处理。

线程通常被枚举为进程中纯粹的用户级实体，它们被调度执行；它们共享父进程的虚拟地址空间和系统资源。每个线程都维护其代码、堆栈和线程本地存储。线程由线程库调度和管理，它使用一个称为线程对象的结构来保存唯一的线程标识符，用于调度属性和保存线程上下文。用户级线程应用通常在内存上更轻，是事件驱动应用程序的首选并发模型。另一方面，这种用户级线程模型不适合并行计算，因为它们被绑定到其父进程绑定的同一处理器核心上。

Linux 不直接支持用户级线程；相反，它提出了一个替代的 API 来枚举一个特殊的进程，称为轻量级进程（LWP），它可以与父进程共享一组配置好的资源，如动态内存分配、全局数据、打开的文件、信号处理程序和其他广泛的资源。每个 LWP 都由唯一的 PID 和任务结构标识，并且被内核视为独立的执行上下文。在 Linux 中，术语线程不可避免地指的是 LWP，因为由线程库（Pthreads）初始化的每个线程都被内核枚举为 LWP。

# clone()

`clone()`是一个 Linux 特定的系统调用，用于创建一个新的进程；它被认为是`fork()`系统调用的通用版本，通过`flags`参数提供更精细的控制来自定义其功能：

```
int clone(int (*child_func)(void *), void *child_stack, int flags, void *arg);
```

它提供了超过二十个不同的`CLONE_*`标志，用于控制`clone`操作的各个方面，包括父进程和子进程是否共享虚拟内存、打开文件描述符和信号处理程序。子进程使用适当的内存地址（作为第二个参数传递）作为`堆栈`（用于存储子进程的本地数据）进行创建。子进程使用其启动函数（作为克隆调用的第一个参数）开始执行。

当一个进程尝试通过`pthread`库创建一个线程时，将使用以下标志调用`clone()`：

```
/*clone flags for creating threads*/
flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID;
```

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00011.jpeg)

`clone()`也可以用于创建一个通常使用`fork()`和`vfork()`生成的常规子进程：

```
/* clone flags for forking child */
flags = SIGCHLD;
/* clone flags for vfork child */ 
flags = CLONE_VFORK | CLONE_VM | SIGCHLD;
```

# 内核线程

为了增加运行后台操作的需求，内核生成线程（类似于进程）。这些内核线程类似于常规进程，它们由任务结构表示，并分配一个 PID。与用户进程不同，它们没有任何映射的地址空间，并且完全在内核模式下运行，这使它们不可交互。各种内核子系统使用`kthreads`来运行周期性和异步操作。

所有内核线程都是`kthreadd（pid 2）`的后代，它是在引导期间由`kernel（pid 0）`生成的。`kthreadd`枚举其他内核线程；它通过接口例程提供内核服务动态生成其他内核线程的能力。可以使用`ps -ef`命令从命令行查看内核线程--它们显示在[方括号]中：

```
UID PID PPID C STIME TTY TIME CMD
root 1 0 0 22:43 ? 00:00:01 /sbin/init splash
root 2 0 0 22:43 ? 00:00:00 [kthreadd]
root 3 2 0 22:43 ? 00:00:00 [ksoftirqd/0]
root 4 2 0 22:43 ? 00:00:00 [kworker/0:0]
root 5 2 0 22:43 ? 00:00:00 [kworker/0:0H]
root 7 2 0 22:43 ? 00:00:01 [rcu_sched]
root 8 2 0 22:43 ? 00:00:00 [rcu_bh]
root 9 2 0 22:43 ? 00:00:00 [migration/0]
root 10 2 0 22:43 ? 00:00:00 [watchdog/0]
root 11 2 0 22:43 ? 00:00:00 [watchdog/1]
root 12 2 0 22:43 ? 00:00:00 [migration/1]
root 13 2 0 22:43 ? 00:00:00 [ksoftirqd/1]
root 15 2 0 22:43 ? 00:00:00 [kworker/1:0H]
root 16 2 0 22:43 ? 00:00:00 [watchdog/2]
root 17 2 0 22:43 ? 00:00:00 [migration/2]
root 18 2 0 22:43 ? 00:00:00 [ksoftirqd/2]
root 20 2 0 22:43 ? 00:00:00 [kworker/2:0H]
root 21 2 0 22:43 ? 00:00:00 [watchdog/3]
root 22 2 0 22:43 ? 00:00:00 [migration/3]
root 23 2 0 22:43 ? 00:00:00 [ksoftirqd/3]
root 25 2 0 22:43 ? 00:00:00 [kworker/3:0H]
root 26 2 0 22:43 ? 00:00:00 [kdevtmpfs]
/*kthreadd creation code (init/main.c) */
static noinline void __ref rest_init(void)
{
 int pid;

 rcu_scheduler_starting();
 /*
 * We need to spawn init first so that it obtains pid 1, however
 * the init task will end up wanting to create kthreads, which, if
 * we schedule it before we create kthreadd, will OOPS.
 */
 kernel_thread(kernel_init, NULL, CLONE_FS);
 numa_default_policy();
 pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
 rcu_read_lock();
 kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
 rcu_read_unlock();
 complete(&kthreadd_done);

 /*
 * The boot idle thread must execute schedule()
 * at least once to get things moving:
 */
 init_idle_bootup_task(current);
 schedule_preempt_disabled();
 /* Call into cpu_idle with preempt disabled */
 cpu_startup_entry(CPUHP_ONLINE);
}
```

前面的代码显示了内核引导例程`rest_init()`调用`kernel_thread()`例程，并使用适当的参数来生成`kernel_init`线程（然后继续启动用户模式的`init`进程）和`kthreadd`。

`kthread`是一个永久运行的线程，它查看一个名为`kthread_create_list`的列表，以获取要创建的新`kthreads`的数据：

```
/*kthreadd routine(kthread.c) */
int kthreadd(void *unused)
{
 struct task_struct *tsk = current;

 /* Setup a clean context for our children to inherit. */
 set_task_comm(tsk, "kthreadd");
 ignore_signals(tsk);
 set_cpus_allowed_ptr(tsk, cpu_all_mask);
 set_mems_allowed(node_states[N_MEMORY]);

 current->flags |= PF_NOFREEZE;

 for (;;) {
 set_current_state(TASK_INTERRUPTIBLE);
 if (list_empty(&kthread_create_list))
 schedule();
 __set_current_state(TASK_RUNNING);

 spin_lock(&kthread_create_lock);
 while (!list_empty(&kthread_create_list)) {
 struct kthread_create_info *create;

 create = list_entry(kthread_create_list.next,
 struct kthread_create_info, list);
 list_del_init(&create->list);
 spin_unlock(&kthread_create_lock);

 create_kthread(create); /* creates kernel threads with attributes enqueued */

 spin_lock(&kthread_create_lock);
 }
 spin_unlock(&kthread_create_lock);
 }

 return 0;
}
kthread_create invoking kthread_create_on_node(), which by default creates threads on the current Numa node:
```

```
struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
 void *data,
 int node,
 const char namefmt[], ...);

/**
 * kthread_create - create a kthread on the current node
 * @threadfn: the function to run in the thread
 * @data: data pointer for @threadfn()
 * @namefmt: printf-style format string for the thread name
 * @...: arguments for @namefmt.
 *
 * This macro will create a kthread on the current node, leaving it in
 * the stopped state. This is just a helper for       
 * kthread_create_on_node();
 * see the documentation there for more details.
 */
#define kthread_create(threadfn, data, namefmt, arg...) 
 kthread_create_on_node(threadfn, data, NUMA_NO_NODE, namefmt, ##arg)

struct task_struct *kthread_create_on_cpu(int (*threadfn)(void *data),
 void *data,
 unsigned int cpu,
 const char *namefmt);

/**
 * kthread_run - create and wake a thread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @namefmt: printf-style name for the thread.
 *
 * Description: Convenient wrapper for kthread_create() followed by
 * wake_up_process(). Returns the kthread or ERR_PTR(-ENOMEM).
 */
#define kthread_run(threadfn, data, namefmt, ...) 
({ 
 struct task_struct *__k 
 = kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); 
 if (!IS_ERR(__k)) 
 wake_up_process(__k); 
 __k; 
})
```

`kthread_create_on_node()` 将要创建的 `kthread` 的详细信息（作为参数接收）实例化为 `kthread_create_info` 类型的结构，并将其排队到 `kthread_create_list` 的末尾。然后唤醒 `kthreadd` 并等待线程创建完成：

```
/* kernel/kthread.c */
static struct task_struct *__kthread_create_on_node(int (*threadfn)(void *data),
 void *data, int node,
 const char namefmt[],
 va_list args)
{
 DECLARE_COMPLETION_ONSTACK(done);
 struct task_struct *task;
 struct kthread_create_info *create = kmalloc(sizeof(*create),
 GFP_KERNEL);

 if (!create)
 return ERR_PTR(-ENOMEM);
 create->threadfn = threadfn;
 create->data = data;
 create->node = node;
 create->done = &done;

 spin_lock(&kthread_create_lock);
 list_add_tail(&create->list, &kthread_create_list);
 spin_unlock(&kthread_create_lock);

 wake_up_process(kthreadd_task);
 /*
 * Wait for completion in killable state, for I might be chosen by
 * the OOM killer while kthreadd is trying to allocate memory for
 * new kernel thread.
 */
 if (unlikely(wait_for_completion_killable(&done))) {
 /*
 * If I was SIGKILLed before kthreadd (or new kernel thread)
 * calls complete(), leave the cleanup of this structure to
 * that thread.
 */
 if (xchg(&create->done, NULL))
 return ERR_PTR(-EINTR);
 /*
 * kthreadd (or new kernel thread) will call complete()
 * shortly.
 */
 wait_for_completion(&done); // wakeup on completion of thread creation.
 }
...
...
...
}

struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
 void *data, int node,
 const char namefmt[],
 ...)
{
 struct task_struct *task;
 va_list args;

 va_start(args, namefmt);
 task = __kthread_create_on_node(threadfn, data, node, namefmt, args);
 va_end(args);

 return task;
}
```

回想一下，`kthreadd` 调用 `create_thread()` 例程来根据排队到列表中的数据启动内核线程。这个例程创建线程并发出完成信号：

```
/* kernel/kthread.c */
static void create_kthread(struct kthread_create_info *create)
{
 int pid;

 #ifdef CONFIG_NUMA
 current->pref_node_fork = create->node;
 #endif

 /* We want our own signal handler (we take no signals by default). */
 pid = kernel_thread(kthread, create, CLONE_FS | CLONE_FILES |  
 SIGCHLD);
 if (pid < 0) {
 /* If user was SIGKILLed, I release the structure. */
 struct completion *done = xchg(&create->done, NULL);

 if (!done) {
 kfree(create);
 return;
 }
 create->result = ERR_PTR(pid);
 complete(done); /* signal completion of thread creation */
 }
}
```

# do_fork() 和 copy_process()

到目前为止讨论的所有进程/线程创建调用都会调用不同的系统调用（除了 `create_thread`）进入内核模式。所有这些系统调用最终汇聚到通用内核 `function _do_fork()` 中，该函数以不同的 `CLONE_*` 标志调用。`do_fork()` 在内部回退到 `copy_process()` 完成任务。以下图表总结了进程创建的调用顺序：

```
/* kernel/fork.c */
/*
 * Create a kernel thread.
 */
```

```
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
 return _do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn,
 (unsigned long)arg, NULL, NULL, 0);
}

/* sys_fork: create a child process by duplicating caller */
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
 return _do_fork(SIGCHLD, 0, 0, NULL, NULL, 0);
#else
 /* cannot support in nommu mode */
 return -EINVAL;
#endif
}

/* sys_vfork: create vfork child process */
SYSCALL_DEFINE0(vfork)
{
 return _do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0,
 0, NULL, NULL, 0);
}

/* sys_clone: create child process as per clone flags */

#ifdef __ARCH_WANT_SYS_CLONE
#ifdef CONFIG_CLONE_BACKWARDS
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
 int __user *, parent_tidptr,
 unsigned long, tls,
 int __user *, child_tidptr)
#elif defined(CONFIG_CLONE_BACKWARDS2)
SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,
 int __user *, parent_tidptr,
 int __user *, child_tidptr,
 unsigned long, tls)
#elif defined(CONFIG_CLONE_BACKWARDS3)
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,
 int, stack_size,
 int __user *, parent_tidptr,
 int __user *, child_tidptr,
 unsigned long, tls)
#else
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
 int __user *, parent_tidptr,
 int __user *, child_tidptr,
 unsigned long, tls)
#endif
{
 return _do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr, tls);
}
#endif

```

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00012.jpeg)

# 进程状态和终止

在进程的生命周期中，它在最终终止之前会遍历许多状态。用户必须具有适当的机制来了解进程在其生命周期中发生的一切。Linux 为此提供了一组函数。

# 等待

对于由父进程创建的进程和线程，父进程知道子进程/线程的执行状态可能是有用的。可以使用 `wait` 系列系统调用来实现这一点：

```
#include <sys/types.h>
#include <sys/wait.h>
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, intoptions);
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
```

这些系统调用会更新调用进程的状态，以便通知子进程的状态变化事件。

+   子进程的终止

+   被信号停止

+   被信号恢复

除了报告状态，这些 API 还允许父进程收集终止的子进程。进程在终止时被放入僵尸状态，直到其直接父进程调用 `wait` 来收集它。

# 退出

每个进程都必须结束。进程的终止是通过进程调用 `exit()` 或主函数返回来完成的。进程也可能在接收到强制其终止的信号或异常时被突然终止，例如发送终止进程的 `KILL` 命令，或引发异常。在终止时，进程被放入退出状态，直到其直接父进程收集它。

`exit` 调用 `sys_exit` 系统调用，该系统调用内部调用 `do_exit` 例程。 `do_exit` 主要执行以下任务（`do_exit` 设置许多值，并多次调用相关内核例程以完成其任务）：

+   获取子进程返回给父进程的退出码。

+   设置 `PF_EXITING` 标志，表示进程正在退出。

+   清理和回收进程持有的资源。这包括释放 `mm_struct`，如果进程正在等待 IPC 信号量，则从队列中移除，释放文件系统数据和文件（如果有的话），并在进程不再可执行时调用 `schedule()`。

在 `do_exit` 之后，进程保持僵尸状态，进程描述符仍然完整，父进程可以收集状态，之后系统会回收资源。

# 命名空间和 cgroups

登录到 Linux 系统的用户可以透明地查看各种系统实体，如全局资源、进程、内核和用户。例如，有效用户可以访问系统上所有运行进程的 PID（无论它们属于哪个用户）。用户可以观察系统上其他用户的存在，并运行命令查看全局系统资源的状态，如内存、文件系统挂载和设备。这些操作不被视为侵入或被视为安全漏洞，因为始终保证一个用户/进程永远不会侵入其他用户/进程。

然而，在一些服务器平台上，这种透明性是不受欢迎的。例如，考虑云服务提供商提供**PaaS**（**平台即服务**）。他们提供一个环境来托管和部署自定义客户端应用程序。他们管理运行时、存储、操作系统、中间件和网络服务，让客户端管理他们的应用程序和数据。各种电子商务、金融、在线游戏和其他相关企业使用 PaaS 服务。

为了客户端的高效隔离和资源管理，PaaS 服务提供商使用各种工具。他们为每个客户端虚拟化系统环境，以实现安全性、可靠性和健壮性。Linux 内核提供了低级机制，以 cgroups 和命名空间的形式构建各种轻量级工具，可以虚拟化系统环境。Docker 就是一个建立在 cgroups 和命名空间之上的框架。

命名空间基本上是一种机制，用于抽象、隔离和限制一组进程对诸如进程树、网络接口、用户 ID 和文件系统挂载等各种系统实体的可见性。命名空间分为几个组，我们现在将看到。

# 挂载命名空间

传统上，挂载和卸载操作会改变系统中所有进程所看到的文件系统视图；换句话说，所有进程都能看到一个全局挂载命名空间。挂载命名空间限制了进程命名空间内可见的文件系统挂载点集合，使得一个挂载命名空间中的一个进程组可以对文件系统列表有独占的视图，与另一个进程相比。

# UTS 命名空间

这些使得在 uts 命名空间中隔离系统的主机和域名成为可能。这使得初始化和配置脚本能够根据各自的命名空间进行引导。

# IPC 命名空间

这些将进程从使用 System V 和 POSIX 消息队列中分隔出来。这样可以防止一个 ipc 命名空间内的进程访问另一个 ipc 命名空间的资源。

# PID 命名空间

传统上，*nix 内核（包括 Linux）在系统启动期间使用 PID 1 生成`init`进程，然后启动其他用户模式进程，并被认为是进程树的根（所有其他进程在树中的这个进程下方启动）。PID 命名空间允许进程在其下方产生一个新的进程树，具有自己的根进程（PID 1 进程）。PID 命名空间隔离进程 ID 号，并允许在不同的 PID 命名空间中复制 PID 号，这意味着不同 PID 命名空间中的进程可以具有相同的进程 ID。PID 命名空间内的进程 ID 是唯一的，并且从 PID 1 开始按顺序分配。

PID 命名空间在容器（轻量级虚拟化解决方案）中用于迁移具有进程树的容器到不同的主机系统，而无需更改 PID。

# 网络命名空间

这种类型的命名空间提供了网络协议服务和接口的抽象和虚拟化。每个网络命名空间都有自己的网络设备实例，可以配置具有独立网络地址。其他网络服务的隔离也得以实现：路由表、端口号等。

# 用户命名空间

用户命名空间允许进程在命名空间内外使用唯一的用户和组 ID。这意味着进程可以在用户命名空间内使用特权用户和组 ID（零），并在命名空间外继续使用非零用户和组 ID。

# Cgroup 命名空间

Cgroup 命名空间虚拟化了`/proc/self/cgroup`文件的内容。在 cgroup 命名空间内的进程只能查看相对于其命名空间根的路径。

# 控制组（cgroups）

Cgroups 是内核机制，用于限制和测量每个进程组的资源分配。使用 cgroups，可以分配 CPU 时间、网络和内存等资源。

与 Linux 中的进程模型类似，每个进程都是父进程的子进程，并相对于`init`进程而言形成单树结构，cgroups 是分层的，子 cgroups 继承父级的属性，但不同之处在于在单个系统中可以存在多个 cgroup 层次结构，每个层次结构都具有不同的资源特权。

将 cgroups 应用于命名空间会将进程隔离到系统中的“容器”中，资源得到独立管理。每个“容器”都是一个轻量级虚拟机，所有这些虚拟机都作为独立实体运行，并且对系统中的其他实体毫不知情。

以下是 Linux man 页面中描述的命名空间 API：

```
clone(2)
The clone(2) system call creates a new process. If the flags argument of the call specifies one or more of the CLONE_NEW* flags listed below, then new namespaces are created for each flag, and the child process is made a member of those namespaces.(This system call also implements a number of features unrelated to namespaces.)

setns(2)
The setns(2) system call allows the calling process to join an existing namespace. The namespace to join is specified via a file descriptor that refers to one of the /proc/[pid]/ns files described below.

unshare(2)
The unshare(2) system call moves the calling process to a new namespace. If the flags argument of the call specifies one or more of the CLONE_NEW* flags listed below, then new namespaces are created for each flag, and the calling process is made a member of those namespaces. (This system call also implements a number of features unrelated to namespaces.)
Namespace   Constant          Isolates
Cgroup      CLONE_NEWCGROUP   Cgroup root directory
IPC         CLONE_NEWIPC      System V IPC, POSIX message queues
Network     CLONE_NEWNET      Network devices, stacks, ports, etc.
Mount       CLONE_NEWNS       Mount points
PID         CLONE_NEWPID      Process IDs
User        CLONE_NEWUSER     User and group IDs
UTS         CLONE_NEWUTS      Hostname and NIS domain name
```

# 总结

我们了解了 Linux 的一个主要抽象称为进程，并且整个生态系统都在促进这种抽象。现在的挑战在于通过提供公平的 CPU 时间来运行大量的进程。随着多核系统施加了多种策略和优先级的进程，确定性调度的需求变得至关重要。

在我们的下一章中，我们将深入研究进程调度，这是进程管理的另一个关键方面，并了解 Linux 调度程序是如何设计来处理这种多样性的。


# 第二章：解密进程调度程序

进程调度是任何操作系统的最关键的执行工作之一，Linux 也不例外。调度进程的启发式和效率是使任何操作系统运行并赋予其身份的关键因素，例如通用操作系统、服务器或实时系统。在本章中，我们将深入了解 Linux 调度程序，解密诸如：

+   Linux 调度程序设计

+   调度类

+   调度策略和优先级

+   完全公平调度器

+   实时调度程序

+   截止时间调度器

+   组调度

+   抢占

# 进程调度程序

任何操作系统的有效性与其公平调度所有竞争进程的能力成正比。进程调度程序是内核的核心组件，它计算并决定进程何时以及多长时间获得 CPU 时间。理想情况下，进程需要 CPU 的*时间片*来运行，因此调度程序基本上需要公平地分配处理器时间片给进程。

调度程序通常需要：

+   避免进程饥饿

+   管理优先级调度

+   最大化所有进程的吞吐量

+   确保低周转时间

+   确保资源使用均匀

+   避免 CPU 占用

+   考虑进程的行为模式进行优先级排序

+   在重负载下优雅地补贴

+   有效地处理多核上的调度

# Linux 进程调度程序设计

Linux 最初是为桌面系统开发的，但不知不觉地演变成了一个多维操作系统，其使用范围涵盖嵌入式设备、大型机和超级计算机，以及房间大小的服务器。它还无缝地适应了不断发展的多样化计算平台，如 SMP、虚拟化和实时系统。这些平台的多样性是由在这些系统上运行的进程类型带来的。例如，一个高度交互式的桌面系统可能运行 I/O 绑定的进程，而实时系统则依赖确定性进程。因此，每种类型的进程在需要公平调度时都需要不同类型的启发式方法，因为 CPU 密集型进程可能需要比普通进程更多的 CPU 时间，而实时进程则需要确定性执行。因此，Linux 面临着处理这些多样化进程管理时带来的不同调度挑战。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00013.jpeg)

Linux 进程调度程序的内在设计通过采用简单的两层模型，优雅而巧妙地处理了这一挑战。其第一层，**通用调度程序**，定义了作为调度程序入口函数的抽象操作，而第二层，调度类，实现了实际的调度操作，其中每个类专门处理特定类型进程的调度启发式。这种模型使得通用调度程序能够从每个调度类的实现细节中抽象出来。例如，普通进程（I/O 绑定）可以由一个类处理，而需要确定性执行的进程，如实时进程，可以由另一个类处理。这种架构还能够无缝地添加新的调度类。前面的图示了进程调度程序的分层设计。

通用调度程序通过一个称为`sched_class`的结构定义了抽象接口：

```
struct sched_class {
    const struct sched_class *next;

     void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
   void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
   void (*yield_task) (struct rq *rq);
       bool (*yield_to_task) (struct rq *rq, struct task_struct *p, bool preempt);

 void (*check_preempt_curr) (struct rq *rq, struct task_struct *p, int flags);

       /*
         * It is the responsibility of the pick_next_task() method that will
       * return the next task to call put_prev_task() on the @prev task or
  * something equivalent.
   *
         * May return RETRY_TASK when it finds a higher prio class has runnable
    * tasks.
  */
       struct task_struct * (*pick_next_task) (struct rq *rq,
                                            struct task_struct *prev,
                                         struct rq_flags *rf);
     void (*put_prev_task) (struct rq *rq, struct task_struct *p);

#ifdef CONFIG_SMP
        int  (*select_task_rq)(struct task_struct *p, int task_cpu, int sd_flag, int flags);
      void (*migrate_task_rq)(struct task_struct *p);

     void (*task_woken) (struct rq *this_rq, struct task_struct *task);

  void (*set_cpus_allowed)(struct task_struct *p,
                            const struct cpumask *newmask);

    void (*rq_online)(struct rq *rq);
 void (*rq_offline)(struct rq *rq);
#endif

      void (*set_curr_task) (struct rq *rq);
    void (*task_tick) (struct rq *rq, struct task_struct *p, int queued);
     void (*task_fork) (struct task_struct *p);
        void (*task_dead) (struct task_struct *p);

  /*
         * The switched_from() call is allowed to drop rq->lock, therefore we
   * cannot assume the switched_from/switched_to pair is serialized by
        * rq->lock. They are however serialized by p->pi_lock.
      */
       void (*switched_from) (struct rq *this_rq, struct task_struct *task);
     void (*switched_to) (struct rq *this_rq, struct task_struct *task);
       void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
                            int oldprio);

  unsigned int (*get_rr_interval) (struct rq *rq,
                                    struct task_struct *task);

 void (*update_curr) (struct rq *rq);

#define TASK_SET_GROUP  0
#define TASK_MOVE_GROUP  1

#ifdef CONFIG_FAIR_GROUP_SCHED
       void (*task_change_group) (struct task_struct *p, int type);
#endif
};
```

每个调度类都实现了`sched_class`结构中定义的操作。截至 4.12.x 内核，有三个调度类：**完全公平调度**（**CFS**）类，实时调度类和截止时间调度类，每个类处理具有特定调度要求的进程。以下代码片段显示了每个类如何根据`sched_class`结构填充其操作。

**CFS 类**：

```
const struct sched_class fair_sched_class = {
         .next                   = &idle_sched_class,
         .enqueue_task           = enqueue_task_fair,
         .dequeue_task           = dequeue_task_fair,
         .yield_task             = yield_task_fair,
         .yield_to_task          = yield_to_task_fair,

         .check_preempt_curr     = check_preempt_wakeup,

         .pick_next_task         = pick_next_task_fair,
         .put_prev_task          = put_prev_task_fair,
....
}
```

**实时调度类**：

```
const struct sched_class rt_sched_class = {
         .next                   = &fair_sched_class,
         .enqueue_task           = enqueue_task_rt,
         .dequeue_task           = dequeue_task_rt,
         .yield_task             = yield_task_rt,

         .check_preempt_curr     = check_preempt_curr_rt,

         .pick_next_task         = pick_next_task_rt,
         .put_prev_task          = put_prev_task_rt,
....
}
```

**截止时间调度类**：

```
const struct sched_class dl_sched_class = {
         .next                   = &rt_sched_class,
         .enqueue_task           = enqueue_task_dl,
         .dequeue_task           = dequeue_task_dl,
         .yield_task             = yield_task_dl,

         .check_preempt_curr     = check_preempt_curr_dl,

         .pick_next_task         = pick_next_task_dl,
         .put_prev_task          = put_prev_task_dl,
....
}
```

# 运行队列

传统上，运行队列包含了在给定 CPU 核心上争夺 CPU 时间的所有进程（每个 CPU 都有一个运行队列）。通用调度程序被设计为在调度下一个最佳的可运行任务时查看运行队列。由于每个调度类处理特定的调度策略和优先级，维护所有可运行进程的公共运行队列是不可能的。

内核通过将其设计原则引入前台来解决这个问题。每个调度类都定义了其运行队列数据结构的布局，以最适合其策略。通用调度程序层实现了一个抽象的运行队列结构，其中包含作为运行队列接口的公共元素。该结构通过指针扩展，这些指针指向特定类的运行队列。换句话说，所有调度类都将其运行队列嵌入到主运行队列结构中。这是一个经典的设计技巧，它让每个调度程序类选择适合其运行队列数据结构的适当布局。

```
struct rq (runqueue) will help us comprehend the concept (elements related to SMP have been omitted from the structure to keep our focus on what's relevant):
```

```
 struct rq {
        /* runqueue lock: */
        raw_spinlock_t lock;
   /*
    * nr_running and cpu_load should be in the same cacheline because
    * remote CPUs use both these fields when doing load calculation.
    */
         unsigned int nr_running;
    #ifdef CONFIG_NUMA_BALANCING
         unsigned int nr_numa_running;
         unsigned int nr_preferred_running;
    #endif
         #define CPU_LOAD_IDX_MAX 5
         unsigned long cpu_load[CPU_LOAD_IDX_MAX];
 #ifdef CONFIG_NO_HZ_COMMON
 #ifdef CONFIG_SMP
         unsigned long last_load_update_tick;
 #endif /* CONFIG_SMP */
         unsigned long nohz_flags;
 #endif /* CONFIG_NO_HZ_COMMON */
 #ifdef CONFIG_NO_HZ_FULL
         unsigned long last_sched_tick;
 #endif
         /* capture load from *all* tasks on this cpu: */
         struct load_weight load;
         unsigned long nr_load_updates;
         u64 nr_switches;

         struct cfs_rq cfs;
         struct rt_rq rt;
         struct dl_rq dl;

 #ifdef CONFIG_FAIR_GROUP_SCHED
         /* list of leaf cfs_rq on this cpu: */
         struct list_head leaf_cfs_rq_list;
         struct list_head *tmp_alone_branch;
 #endif /* CONFIG_FAIR_GROUP_SCHED */

          unsigned long nr_uninterruptible;

         struct task_struct *curr, *idle, *stop;
         unsigned long next_balance;
         struct mm_struct *prev_mm;

         unsigned int clock_skip_update;
         u64 clock;
         u64 clock_task;

         atomic_t nr_iowait;

 #ifdef CONFIG_IRQ_TIME_ACCOUNTING
         u64 prev_irq_time;
 #endif
 #ifdef CONFIG_PARAVIRT
         u64 prev_steal_time;
 #endif
 #ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
         u64 prev_steal_time_rq;
 #endif

         /* calc_load related fields */
         unsigned long calc_load_update;
         long calc_load_active;

 #ifdef CONFIG_SCHED_HRTICK
 #ifdef CONFIG_SMP
         int hrtick_csd_pending;
         struct call_single_data hrtick_csd;
 #endif
         struct hrtimer hrtick_timer;
 #endif
 ...
 #ifdef CONFIG_CPU_IDLE
         /* Must be inspected within a rcu lock section */
         struct cpuidle_state *idle_state;
 #endif
};
```

您可以看到调度类（`cfs`、`rt` 和 `dl`）是如何嵌入到运行队列中的。运行队列中其他感兴趣的元素包括：

+   `nr_running`: 这表示运行队列中的进程数量

+   `load`: 这表示队列上的当前负载（所有可运行进程）

+   `curr` 和 `idle`: 这些分别指向当前运行任务的 *task_struct* 和空闲任务。当没有其他任务要运行时，空闲任务会被调度。

# 调度程序的入口

调度过程始于对通用调度程序的调用，即 `<kernel/sched/core.c>` 中定义的 `schedule()` 函数。这可能是内核中最常调用的例程之一。`schedule()` 的功能是选择下一个最佳的可运行任务。`schedule()` 函数的 `pick_next_task()` 遍历调度类中包含的所有相应函数，并最终选择下一个最佳的任务来运行。每个调度类都使用单链表连接，这使得 `pick_next_task()` 能够遍历这些类。

考虑到 Linux 主要设计用于高度交互式系统，该函数首先在 CFS 类中查找下一个最佳的可运行任务，如果在其他类中没有更高优先级的可运行任务（通过检查运行队列中可运行任务的总数（`nr_running`）是否等于 CFS 类子运行队列中可运行任务的总数来实现）；否则，它会遍历所有其他类，并选择下一个最佳的可运行任务。最后，如果找不到任务，则调用空闲后台任务（始终返回非空值）。

以下代码块显示了 `pick_next_task()` 的实现：

```
/*
 * Pick up the highest-prio task:
 */
static inline struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
   const struct sched_class *class;
  struct task_struct *p;

      /*
         * Optimization: we know that if all tasks are in the fair class we can
    * call that function directly, but only if the @prev task wasn't of a
        * higher scheduling class, because otherwise those loose the
      * opportunity to pull in more work from other CPUs.
       */
       if (likely((prev->sched_class == &idle_sched_class ||
                  prev->sched_class == &fair_sched_class) &&
                rq->nr_running == rq->cfs.h_nr_running)) {

         p = fair_sched_class.pick_next_task(rq, prev, rf);
                if (unlikely(p == RETRY_TASK))
                    goto again;

         /* Assumes fair_sched_class->next == idle_sched_class */
               if (unlikely(!p))
                 p = idle_sched_class.pick_next_task(rq, prev, rf);

          return p;
 }

again:
       for_each_class(class) {
           p = class->pick_next_task(rq, prev, rf);
               if (p) {
                  if (unlikely(p == RETRY_TASK))
                            goto again;
                       return p;
         }
 }

   /* The idle class should always have a runnable task: */
  BUG();
}
```

# 进程优先级

决定运行哪个进程取决于进程的优先级。每个进程都标有一个优先级值，这使得它在获得 CPU 时间方面有一个即时的位置。在 *nix 系统上，优先级基本上分为 *动态* 和 *静态* 优先级。**动态优先级** 基本上是内核动态地应用于正常进程，考虑到诸如进程的良好值、其历史行为（I/O 绑定或处理器绑定）、已过去的执行和等待时间等各种因素。**静态优先级** 是由用户应用于实时进程的，内核不会动态地改变它们的优先级。因此，具有静态优先级的进程在调度时会被赋予更高的优先级。

**I/O 绑定进程：**当进程的执行严重受到 I/O 操作的影响（等待资源或事件），例如文本编辑器几乎在运行和等待按键之间交替时，这样的进程被称为 I/O 绑定。由于这种特性，调度器通常会为 I/O 绑定的进程分配较短的处理器时间片，并将它们与其他进程复用，增加了上下文切换的开销以及计算下一个最佳进程的后续启发式。

**处理器绑定进程：**这些进程喜欢占用 CPU 时间片，因为它们需要最大限度地利用处理器的计算能力。需要进行复杂科学计算和视频渲染编解码的进程是处理器绑定的。虽然需要更长的 CPU 时间片看起来很理想，但通常不需要在固定时间段内运行它们。交互式操作系统上的调度器倾向于更喜欢 I/O 绑定的进程而不是处理器绑定的进程。Linux 旨在提供良好的交互性能，更倾向于 I/O 绑定的进程，即使处理器绑定的进程运行频率较低，它们通常会被分配更长的时间片来运行。

进程也可以是**多面手**，I/O 绑定进程需要执行严肃的科学计算，占用 CPU。

任何正常进程的*nice*值范围在 19（最低优先级）和-20（最高优先级）之间，0 是默认值。较高的 nice 值表示较低的优先级（进程对其他进程更友好）。实时进程的优先级在 0 到 99 之间（静态优先级）。所有这些优先级范围都是从用户的角度来看的。

**内核对优先级的看法**

然而，Linux 从自己的角度看待进程优先级。它为计算进程的优先级增加了更多的计算。基本上，它将所有优先级在 0 到 139 之间进行缩放，其中 0 到 99 分配给实时进程，100 到 139 代表了 nice 值范围（-20 到 19）。

# 调度器类

现在让我们深入了解每个调度类，并了解它在管理调度操作时所涉及的操作、政策和启发式。如前所述，每个调度类必须提供`struct sched_class`的一个实例；让我们看一下该结构中的一些关键元素：

+   `enqueue_task`：基本上是将新进程添加到运行队列

+   `dequeue_task`：当进程从运行队列中移除时

+   `yield_task`：当进程希望自愿放弃 CPU 时

+   `pick_next_task`：由*s*chedule()调用的*pick_next_task*的相应函数。它从其类中挑选出下一个最佳的可运行任务。

# 完全公平调度类（CFS）

所有具有动态优先级的进程都由 CFS 类处理，而大多数通用*nix 系统中的进程都是正常的（非实时），因此 CFS 仍然是内核中最繁忙的调度器类。

CFS 依赖于根据任务分配处理器时间的政策和动态分配的优先级来保持*平衡*。CFS 下的进程调度是在假设下实现的，即它具有"理想的、精确的多任务 CPU"，在其峰值容量下平等地为所有进程提供动力。例如，如果有两个进程，完美的多任务 CPU 确保两个进程同时运行，每个进程利用其 50%的能力。由于这在实际上是不可能的（实现并行性），CFS 通过在所有竞争进程之间保持适当的平衡来为进程分配处理器时间。如果一个进程未能获得公平的时间，它被认为是不平衡的，因此作为最佳可运行进程进入下一个进程。

CFS 不依赖于传统的时间片来分配处理器时间，而是使用虚拟运行时间（*vruntime*）的概念：它表示进程获得 CPU 时间的数量，这意味着低`vruntime`值表示进程处理器匮乏，而高`vruntime`值表示进程获得了相当多的处理器时间。具有低`vruntime`值的进程在调度时获得最高优先级。CFS 还为理想情况下等待 I/O 请求的进程使用*睡眠公平性*。睡眠公平性要求等待的进程在最终唤醒后获得相当多的 CPU 时间。根据`vruntime`值，CFS 决定进程运行的时间。它还使用 nice 值来衡量进程与所有竞争进程的关系：较高值的低优先级进程获得较少的权重，而较低值的高优先级任务获得更多的权重。即使在 Linux 中处理具有不同优先级的进程也是优雅的，因为与较高优先级任务相比，较低优先级任务会有相当大的延迟因素；这使得分配给低优先级任务的时间迅速消失。

# 在 CFS 下计算优先级和时间片

优先级是基于进程等待时间、进程运行时间、进程的历史行为和其 nice 值来分配的。通常，调度程序使用复杂的算法来找到下一个最佳的要运行的进程。

在计算每个进程获得的时间片时，CFS 不仅依赖于进程的 nice 值，还考虑进程的负载权重。对于进程 nice 值的每次增加 1，CPU 时间片将减少 10%，对于 nice 值的每次减少 1，CPU 时间片将增加 10%，这表明 nice 值对于每次变化都是以 10%的乘法变化。为了计算相应 nice 值的负载权重，内核维护了一个名为`prio_to_weight`的数组，其中每个 nice 值对应一个权重：

```
static const int prio_to_weight[40] = {
  /* -20 */     88761,     71755,     56483,     46273,     36291,
  /* -15 */     29154,     23254,     18705,     14949,     11916,
  /* -10 */      9548,      7620,      6100,      4904,      3906,
  /*  -5 */      3121,      2501,      1991,      1586,      1277,
  /*   0 */      1024,       820,       655,       526,       423,
  /*   5 */       335,       272,       215,       172,       137,
  /*  10 */       110,        87,        70,        56,        45,
  /*  15 */        36,        29,        23,        18,        15,
};
```

进程的负载值存储在`struct load_weight`的`weight`字段中。

像进程的权重一样，CFS 的运行队列也被分配了一个权重，这是运行队列中所有任务的总权重。现在，时间片是通过考虑实体的负载权重、运行队列的负载权重和`sched_period`（调度周期）来计算的。

# CFS 的运行队列

CFS 摆脱了普通运行队列的需要，而是使用自平衡的红黑树，以便在最短时间内找到下一个最佳的要运行的进程。*RB 树*保存了所有竞争进程，并便于对进程进行快速插入、删除和搜索。最高优先级的进程被放置在最左边的节点上。`pick_next_task()`函数现在只是从`rb tree`中选择最左边的节点进行调度。

# 分组调度

为了确保调度时的公平性，CFS 被设计为保证每个可运行的进程在一个定义的时间段内至少运行一次，称为**调度周期**。在调度周期内，CFS 基本上确保公平性，或者换句话说，确保不公平性被最小化，因为每个进程至少运行一次。CFS 将调度周期分成时间片，以避免进程饥饿；然而，想象一下这样的情况，进程 A 生成了 10 个执行线程，进程 B 生成了 5 个执行线程：在这里，CFS 将时间片均匀分配给所有线程，导致进程 A 及其生成的线程获得最大的时间，而进程 B 则受到不公平对待。如果进程 A 继续生成更多的线程，情况可能对进程 B 及其生成的线程变得严重，因为进程 B 将不得不应对最小的调度粒度或时间片（即 1 毫秒）。在这种情况下，公平性要求进程 A 和 B 获得相等的时间片，并且生成的线程在内部共享这些时间片。例如，如果进程 A 和 B 各获得 50%的时间，那么进程 A 将把其 50%的时间分配给其生成的 10 个线程，每个线程在内部获得 5%的时间。

为了解决这个问题并保持公平性，CFS 引入了**组调度**，其中时间片分配给线程组而不是单个线程。继续上面的例子，在组调度下，进程 A 及其生成的线程属于一组，进程 B 及其生成的线程属于另一组。由于调度粒度是在组级别而不是线程级别上强加的，它给予进程 A 和 B 相等的处理器时间份额，进程 A 和 B 在其组成员内部分配时间片。在这里，生成在进程 A 下的线程会受到影响，因为它因生成更多的执行线程而受到惩罚。为了确保组调度，在配置内核时需要设置`CONFIG_FAIR_GROUP_SCHED`。CFS 任务组由结构`sched_entity`*表示，每个组被称为**调度实体**。以下代码片段显示了调度实体结构的关键元素：

```
struct sched_entity {
        struct load_weight      load;   /* for load-balancing */
        struct rb_node          run_node;
        struct list_head        group_node;
        unsigned int            on_rq;

        u64                     exec_start;
        u64                     sum_exec_runtime;
        u64                     vruntime;
        u64                     prev_sum_exec_runtime;

        u64                     nr_migrations;

 #ifdef CONFIG_SCHEDSTATS
        struct sched_statistics statistics;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
        int depth;
        struct sched_entity *parent;
         /* rq on which this entity is (to be) queued: */
        struct cfs_rq           *cfs_rq;
        /* rq "owned" by this entity/group: */
        struct cfs_rq           *my_q;
#endif

....
};
```

+   `load`：表示每个实体对队列总负载的负载量

+   `vruntime`：表示进程运行的时间

# 许多核心系统下的调度实体

任务组可以在许多核心系统上的任何 CPU 核心上运行，但为了实现这一点，创建一个调度实体是不够的。因此，组必须为系统上的每个 CPU 核心创建一个调度实体。跨 CPU 的调度实体由`struct task_group`表示：

```
/* task group related information */
struct task_group {
       struct cgroup_subsys_state css;

#ifdef CONFIG_FAIR_GROUP_SCHED
 /* schedulable entities of this group on each cpu */
      struct sched_entity **se;
 /* runqueue "owned" by this group on each cpu */
  struct cfs_rq **cfs_rq;
   unsigned long shares;

#ifdef CONFIG_SMP
        /*
         * load_avg can be heavily contended at clock tick time, so put
    * it in its own cacheline separated from the fields above which
   * will also be accessed at each tick.
     */
       atomic_long_t load_avg ____cacheline_aligned;
#endif
#endif

#ifdef CONFIG_RT_GROUP_SCHED
     struct sched_rt_entity **rt_se;
   struct rt_rq **rt_rq;

       struct rt_bandwidth rt_bandwidth;
#endif

       struct rcu_head rcu;
      struct list_head list;

      struct task_group *parent;
        struct list_head siblings;
        struct list_head children;

#ifdef CONFIG_SCHED_AUTOGROUP
       struct autogroup *autogroup;
#endif

    struct cfs_bandwidth cfs_bandwidth;
};
```

现在，每个任务组都有一个调度实体，每个 CPU 核心都有一个与之关联的 CFS 运行队列。当一个任务从一个任务组迁移到另一个 CPU 核心时，该任务将从 CPU x 的 CFS 运行队列中出列，并入列到 CPU y 的 CFS 运行队列中。

# 调度策略

调度策略适用于进程，并有助于确定调度决策。如果您回忆一下，在第一章中，*理解进程、地址空间和线程*，我们描述了`task_struct`结构的调度属性下的`int policy`字段。`policy`字段包含一个值，指示调度时要应用哪种策略。CFS 类使用以下两种策略处理所有普通进程：

+   `SCHED_NORMAL (0)`：用于所有普通进程。所有非实时进程都可以总结为普通进程。由于 Linux 旨在成为一个高度响应和交互式的系统，大部分调度活动和启发式方法都集中在公平调度普通进程上。普通进程根据 POSIX 标准被称为`SCHED_OTHER`。

+   `SCHED_BATCH (3)`: 通常在服务器上，非交互式的 CPU 密集型批处理被使用。这些 CPU 密集型的进程比`SCHED_NORMAL`进程被赋予更低的优先级，并且它们不会抢占正常进程的调度。

+   CFS 类还处理空闲进程的调度，其指定如下策略：

+   `SCHED_IDLE (5)`: 当没有进程需要运行时，*空闲*进程（低优先级后台进程）被调度。*空闲*进程被分配了所有进程中最低的优先级。

# 实时调度类

Linux 支持软实时任务，并由实时调度类进行调度。`rt`进程被分配静态优先级，并且不会被内核动态改变。由于实时任务旨在确定性运行并希望控制何时以及多长时间被调度，它们总是优先于正常任务（`SCHED_NORMAL`）。与 CFS 使用`rb 树`作为其子运行队列不同，较不复杂的`rt`调度器使用每个优先级值（1 到 99）的简单`链表`。Linux 应用了两种实时策略，`rr`和`fifo`*,*在调度静态优先级进程时；这些由`struct task_struct`*:*的`policy`元素指示。

+   `SCHED_FIFO` (1): 这使用先进先出的方法来调度软实时进程

+   `SCHED_RR` (2): 这是用于调度软实时进程的轮转策略

# FIFO

**FIFO**是应用于优先级高于 0 的进程的调度机制（0 分配给正常进程）。FIFO 进程在没有任何时间片分配的情况下运行；换句话说，它们一直运行直到阻塞某个事件或明确让出给另一个进程。当调度器遇到更高优先级的可运行 FIFO、RR 或截止任务时，FIFO 进程也会被抢占。当调度器遇到多个具有相同优先级的 fifo 任务时，它会以轮转的方式运行这些进程，从列表头部的第一个进程开始。在抢占时，进程被添加回列表的尾部。如果更高优先级的进程抢占了 FIFO 进程，它会等待在列表的头部，当所有其他高优先级任务被抢占时，它再次被选中运行。当新的 fifo 进程变为可运行时，它被添加到列表的尾部。

# RR

轮转策略类似于 FIFO，唯一的区别是它被分配了一个时间片来运行。这是对 FIFO 的一种增强（因为 FIFO 进程可能一直运行直到让出或等待）。与 FIFO 类似，列表头部的 RR 进程被选中执行（如果没有其他更高优先级的任务可用），并在时间片完成时被抢占，并被添加回列表的尾部。具有相同优先级的 RR 进程会轮流运行，直到被高优先级任务抢占。当高优先级任务抢占 RR 任务时，它会等待在列表的头部，并在恢复时只运行其剩余的时间片。

# 实时组调度

与 CFS 下的组调度类似，实时进程也可以通过设置`CONFIG_RT_GROUP_SCHED`来进行分组调度。为了使组调度成功，每个组必须被分配一部分 CPU 时间，并保证时间片足够运行每个实体下的任务，否则会失败。因此，每个组都被分配了一部分“运行时间”（CPU 在一段时间内可以运行的时间）。分配给一个组的运行时间不会被另一个组使用。未分配给实时组的 CPU 时间将被正常优先级任务使用，实时实体未使用的时间也将被正常任务使用。FIFO 和 RR 组由`struct sched_rt_entity`*:*表示

```
struct sched_rt_entity {
 struct list_head                run_list;
 unsigned long                   timeout;
  unsigned long                   watchdog_stamp;
   unsigned int                    time_slice;
       unsigned short                  on_rq;
    unsigned short                  on_list;

    struct sched_rt_entity          *back;
#ifdef CONFIG_RT_GROUP_SCHED
  struct sched_rt_entity          *parent;
  /* rq on which this entity is (to be) queued: */
  struct rt_rq                    *rt_rq;
   /* rq "owned" by this entity/group: */
    struct rt_rq                    *my_q;
#endif
};
```

# 截止调度类（间歇任务模型截止调度）

**Deadline**代表 Linux 上新一代的 RT 进程（自 3.14 内核以来添加）。与 FIFO 和 RR 不同，这些进程可能占用 CPU 或受到时间片的限制，截止进程基于 GEDF（全局最早截止时间优先）和 CBS（恒定带宽服务器）算法，预先确定其运行时需求。间歇性进程内部运行多个任务，每个任务都有一个相对截止时间，必须在其中完成执行，并且有一个计算时间，定义 CPU 需要完成进程执行的时间。为了确保内核成功执行截止进程，内核基于截止时间参数运行准入测试，如果失败则返回错误`EBUSY`。截止策略的进程优先于所有其他进程。截止进程使用`SCHED_DEADLINE`（6）作为其策略元素。

# 与调度程序相关的系统调用

Linux 提供了一整套系统调用，用于管理各种调度程序参数、策略和优先级，并为调用线程检索大量与调度相关的信息。它还允许线程显式地放弃 CPU：

```
nice(int inc)
```

`nice()`接受一个*int*参数，并将其添加到调用线程的`nice`值中。成功时返回线程的新`nice`值。`Nice`值在范围 19（最低优先级）到-20（最高优先级）内。*Nice*值只能在此范围内递增：

```
getpriority(int which, id_t who)
```

这返回线程、组、用户或一组由其参数指示的特定用户的`nice`值。它返回任何进程持有的最高优先级：

```
setpriority(int which, id_t who, int prio)
```

`setpriority`*.*设置由其参数指示的特定用户的线程、组、用户或一组线程的调度优先级。成功时返回零：

```
sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
```

这设置了指定线程的调度策略和参数，由其`pid`指示。如果`pid`为零，则设置调用线程的策略。指定调度参数的`param`参数指向一个`sched_param`结构，其中包含`int sched_priority`。对于正常进程，`sched_priority`必须为零，对于 FIFO 和 RR 策略（在策略参数中提到）的优先级值必须在 1 到 99 的范围内。成功时返回零：

```
sched_getscheduler(pid_t pid)
```

它返回线程（`pid`）的调度策略。如果`pid`为零，则将检索调用线程的策略：

```
sched_setparam(pid_t pid, const struct sched_param *param)
```

它设置与给定线程（`pid`）的调度策略相关联的调度参数。如果`pid`为零，则设置调用进程的参数。成功时返回零：

```
sched_getparam(pid_t pid, struct sched_param *param)
```

这将为指定的线程（`pid`）设置调度参数。如果`pid`为零，则将检索调用线程的调度参数。成功时返回零：

```
sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags)
```

它为指定的线程（`pid`）设置调度策略和相关属性。如果`pid`为零，则设置调用进程的策略和属性。这是一个特定于 Linux 的调用，是`sched_setscheduler()`和`sched_setparam()`调用提供的功能的超集。成功时返回零。

```
sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags)
```

它获取指定线程（`pid`）的调度策略和相关属性。如果`pid`为零，则将检索调用线程的调度策略和相关属性。这是一个特定于 Linux 的调用，是`sched_getscheduler()`和`sched_getparam()`调用提供的功能的超集。成功时返回零。

```
sched_get_priority_max(int policy) 
sched_get_priority_min(int policy)
```

这分别返回指定`policy`的最大和最小优先级。`fifo`、`rr`、`deadline`、`normal`、`batch`和`idle`是策略的支持值。

```
sched_rr_get_interval(pid_t pid, struct timespec *tp)
```

它获取指定线程（`pid`）的时间量，并将其写入由`tp`指定的`timespec`结构。如果`pid`为零，则将调用进程的时间量获取到`tp`中。这仅适用于具有`*rr*`策略的进程。成功时返回零。

```
sched_yield(void)
```

这被称为显式地放弃 CPU。线程现在被添加回队列。成功时返回零。

# 处理器亲和力调用

提供了特定于 Linux 的处理器亲和性调用，帮助线程定义它们想要在哪个 CPU 上运行。默认情况下，每个线程继承其父线程的处理器亲和性，但它可以定义其亲和性掩码以确定其处理器亲和性。在许多核心系统上，CPU 亲和性调用有助于提高性能，通过帮助进程保持在一个核心上（但 Linux 会尝试保持一个线程在一个 CPU 上）。亲和性位掩信息包含在`struct task_struct`的`cpu_allowed`字段中。亲和性调用如下：

```
sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)
```

它将线程（`pid`）的 CPU 亲和性掩码设置为`mask`指定的值。如果线程（`pid`）不在指定 CPU 的队列中运行，则迁移到指定的`cpu`。成功时返回零。

```
sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
```

这将线程（`pid`）的亲和性掩码提取到由*mask*指向的`cpusetsize`结构中。如果`pid`为零，则返回调用线程的掩码。成功时返回零。

# 进程抢占

理解抢占和上下文切换对于完全理解调度以及它对内核在维持低延迟和一致性方面的影响至关重要。每个进程都必须被隐式或显式地抢占，以为另一个进程腾出位置。抢占可能导致上下文切换，这需要一个低级别的特定体系结构操作，由函数`context_switch()`执行。为了使处理器切换上下文，需要完成两个主要任务：将旧进程的虚拟内存映射切换为新进程的映射，并将处理器状态从旧进程切换为新进程的状态。这两个任务由`switch_mm()`和`switch_to()`执行。

抢占可能发生的原因有：

当高优先级进程变为可运行状态时。为此，调度程序将不时地检查是否有高优先级的可运行线程。从中断和系统调用返回时，设置`TIF_NEED_RESCHEDULE`（内核提供的指示需要重新调度的标志），调用调度程序。由于有一个周期性的定时器中断保证定期发生，调用调度程序也是有保证的。当进程进入阻塞调用或发生中断事件时，也会发生抢占。

Linux 内核在历史上一直是非抢占的，这意味着内核模式下的任务在没有中断事件发生或选择显式放弃 CPU 的情况下是不可抢占的。自 2.6 内核以来，已经添加了抢占（需要在内核构建期间启用）。启用内核抢占后，内核模式下的任务因为列出的所有原因都是可抢占的，但内核模式下的任务在执行关键操作时可以禁用内核抢占。这是通过向每个进程的`thread_info`结构添加了一个抢占计数器（`preempt_count`）来实现的。任务可以通过内核宏`preempt_disable()`和`preempt_enable()`来禁用/启用抢占，这会增加和减少`preempt_counter`。这确保了只有当`preempt_counter`为零时（表示没有获取锁）内核才是可抢占的。

内核代码中的关键部分是通过禁用抢占来执行的，这是通过在内核锁操作（自旋锁、互斥锁）中调用`preempt_disable`和`preempt_enable`来实现的。

使用“抢占 rt”构建的 Linux 内核，支持*完全可抢占内核*选项，启用后使所有内核代码包括关键部分都是完全可抢占的。

# 总结

进程调度是内核的一个不断发展的方面，随着 Linux 的发展和进一步多样化到许多计算领域，对进程调度器的微调和更改将是必要的。然而，通过本章建立的理解，深入了解或理解任何新的变化将会很容易。我们现在已经具备了进一步探索作业控制和信号管理的另一个重要方面的能力。我们将简要介绍信号的基础知识，然后进入内核的信号管理数据结构和例程。


# 第三章：信号管理

信号提供了一个基本的基础设施，任何进程都可以异步地被通知系统事件。它们也可以作为进程之间的通信机制。了解内核如何提供和管理整个信号处理机制的平稳吞吐量，让我们对内核有更深入的了解。在本章中，我们将从进程如何引导信号到内核如何巧妙地管理例程以确保信号事件的发生，深入研究以下主题：

+   信号概述及其类型

+   进程级别的信号管理调用

+   进程描述符中的信号数据结构

+   内核的信号生成和传递机制

# 信号

**信号**是传递给进程或进程组的短消息。内核使用信号通知进程系统事件的发生；信号也用于进程之间的通信。Linux 将信号分为两组，即通用 POSIX（经典 Unix 信号）和实时信号。每个组包含 32 个不同的信号，由唯一的 ID 标识：

```
#define _NSIG 64
#define _NSIG_BPW __BITS_PER_LONG
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPOLL SIGIO
/*
#define SIGLOST 29
*/
#define SIGPWR 30
#define SIGSYS 31
#define SIGUNUSED 31

/* These should not be considered constants from userland. */
#define SIGRTMIN 32
#ifndef SIGRTMAX
#define SIGRTMAX _NSIG
#endif
```

通用 POSIX 类别中的信号与特定系统事件绑定，并通过宏适当命名。实时类别中的信号不与特定事件绑定，可以自由用于进程通信；内核用通用名称引用它们：`SIGRTMIN` 和 `SIGRTMAX`。

在生成信号时，内核将信号事件传递给目标进程，目标进程可以根据配置的操作（称为**信号处理方式**）对信号做出响应。

以下是进程可以设置为其信号处理方式的操作列表。进程可以在某个时间点设置任何一个操作为其信号处理方式，但可以在没有任何限制的情况下在这些操作之间任意切换任意次数。

+   **内核处理程序**: 内核为每个信号实现了默认处理程序。这些处理程序通过任务结构的信号处理程序表对进程可用。收到信号后，进程可以请求执行适当的信号处理程序。这是默认的处理方式。

+   **进程定义的处理程序:** 进程允许实现自己的信号处理程序，并设置它们以响应信号事件的执行。这是通过适当的系统调用接口实现的，允许进程将其处理程序例程与信号绑定。在发生信号时，进程处理程序将被异步调用。

+   **忽略:** 进程也可以忽略信号的发生，但需要通过调用适当的系统调用宣布其忽略意图。

内核定义的默认处理程序例程可以执行以下任何操作：

+   **Ignore**: 什么都不会发生。

+   **终止**: 终止进程，即组中的所有线程（类似于 `exit_group`）。组长（仅）向其父进程报告 `WIFSIGNALED` 状态。

+   **Coredump**: 写入描述使用相同 `mm` 的所有线程的核心转储文件，然后终止所有这些线程

+   **停止**: 停止组中的所有线程，即 `TASK_STOPPED` 状态。

以下是总结表，列出了默认处理程序执行的操作：

```
 +--------------------+------------------+
 * | POSIX signal     | default action |
 * +------------------+------------------+
 * | SIGHUP           | terminate 
 * | SIGINT           | terminate 
 * | SIGQUIT          | coredump 
 * | SIGILL           | coredump 
 * | SIGTRAP          | coredump 
 * | SIGABRT/SIGIOT   | coredump 
 * | SIGBUS           | coredump 
 * | SIGFPE           | coredump 
 * | SIGKILL          | terminate
 * | SIGUSR1          | terminate 
 * | SIGSEGV          | coredump 
 * | SIGUSR2          | terminate
 * | SIGPIPE          | terminate 
 * | SIGALRM          | terminate 
 * | SIGTERM          | terminate 
 * | SIGCHLD          | ignore 
 * | SIGCONT          | ignore 
 * | SIGSTOP          | stop
 * | SIGTSTP          | stop
 * | SIGTTIN          | stop
 * | SIGTTOU          | stop
 * | SIGURG           | ignore 
 * | SIGXCPU          | coredump 
 * | SIGXFSZ          | coredump 
 * | SIGVTALRM        | terminate 
 * | SIGPROF          | terminate 
 * | SIGPOLL/SIGIO    | terminate 
 * | SIGSYS/SIGUNUSED | coredump 
 * | SIGSTKFLT        | terminate 
 * | SIGWINCH         | ignore 
 * | SIGPWR           | terminate 
 * | SIGRTMIN-SIGRTMAX| terminate 
 * +------------------+------------------+
 * | non-POSIX signal | default action |
 * +------------------+------------------+
 * | SIGEMT           | coredump |
 * +--------------------+------------------+
```

# 信号管理 API

应用程序提供了各种 API 用于管理信号；我们将看一下其中一些重要的 API：

1.  `Sigaction()`: 用户模式进程使用 POSIX API `sigaction()` 来检查或更改信号的处理方式。该 API 提供了各种属性标志，可以进一步定义信号的行为：

```
 #include <signal.h>
 int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);

 The sigaction structure is defined as something like:

 struct sigaction {
 void (*sa_handler)(int);
 void (*sa_sigaction)(int, siginfo_t *, void *);
 sigset_t sa_mask;
 int sa_flags;
 void (*sa_restorer)(void);
 };
```

+   `int signum` 是已识别的 `signal` 的标识号。`sigaction()` 检查并设置与该信号关联的操作。

+   `const struct sigaction *act`可以被赋予一个`struct sigaction`实例的地址。在此结构中指定的操作成为与信号绑定的新操作。当*act*指针未初始化（NULL）时，当前的处理方式不会改变。

+   `struct sigaction *oldact`是一个 outparam，需要用未初始化的`sigaction`实例的地址进行初始化；`sigaction()`通过此参数返回当前与信号关联的操作。

+   以下是各种`flag`选项：

+   `SA_NOCLDSTOP`：此标志仅在绑定`SIGCHLD`的处理程序时相关。它用于禁用对子进程停止（`SIGSTP`）和恢复（`SIGCONT`）事件的`SIGCHLD`通知。

+   `SA_NOCLDWAIT`：此标志仅在绑定`SIGCHLD`的处理程序或将其设置为`SIG_DFL`时相关。设置此标志会导致子进程在终止时立即被销毁，而不是处于*僵尸*状态。

+   `SA_NODEFER`：设置此标志会导致生成的信号即使相应的处理程序正在执行也会被传递。

+   `SA_ONSTACK`：此标志仅在绑定信号处理程序时相关。设置此标志会导致信号处理程序使用备用堆栈；备用堆栈必须由调用进程通过`sigaltstack()`API 设置。如果没有备用堆栈，处理程序将在当前堆栈上被调用。

+   `SA_RESETHAND`：当与`sigaction()`一起应用此标志时，它使信号处理程序成为一次性的，也就是说，指定信号的操作对于该信号的后续发生被重置为`SIG_DFL`。

+   `SA_RESTART`：此标志使系统调用操作被当前信号处理程序中断后重新进入。

+   `SA_SIGINFO`：此标志用于向系统指示信号处理程序已分配--`sigaction`结构的`sa_sigaction`指针而不是`sa_handler`。分配给`sa_sigaction`的处理程序接收两个额外的参数：

```
      void handler_fn(int signo, siginfo_t *info, void *context);
```

第一个参数是`signum`，处理程序绑定的信号。第二个参数是一个 outparam，是指向`siginfo_t`类型对象的指针，提供有关信号来源的附加信息。以下是`siginfo_t`的完整定义：

```
 siginfo_t {
 int si_signo; /* Signal number */
 int si_errno; /* An errno value */
 int si_code; /* Signal code */
 int si_trapno; /* Trap number that caused hardware-generated signal (unused on most           architectures) */
 pid_t si_pid; /* Sending process ID */
 uid_t si_uid; /* Real user ID of sending process */
 int si_status; /* Exit value or signal */
 clock_t si_utime; /* User time consumed */
 clock_t si_stime; /* System time consumed */
 sigval_t si_value; /* Signal value */
 int si_int; /* POSIX.1b signal */
 void *si_ptr; /* POSIX.1b signal */
 int si_overrun; /* Timer overrun count; POSIX.1b timers */
 int si_timerid; /* Timer ID; POSIX.1b timers */
 void *si_addr; /* Memory location which caused fault */
 long si_band; /* Band event (was int in glibc 2.3.2 and earlier) */
 int si_fd; /* File descriptor */
 short si_addr_lsb; /* Least significant bit of address (since Linux 2.6.32) */
 void *si_call_addr; /* Address of system call instruction (since Linux 3.5) */
 int si_syscall; /* Number of attempted system call (since Linux 3.5) */
 unsigned int si_arch; /* Architecture of attempted system call (since Linux 3.5) */
 }
```

1.  `Sigprocmask()`：除了改变信号处理程序外，该处理程序还允许阻止或解除阻止信号传递。应用程序可能需要在执行关键代码块时进行这些操作，以防止被异步信号处理程序抢占。例如，网络通信应用程序可能不希望在进入启动与其对等体连接的代码块时处理信号：

+   `sigprocmask()`是一个 POSIX API，用于检查、阻塞和解除阻塞信号。

```
    int sigprocmask(int how, const sigset_t *set, sigset_t *oldset); 
```

任何被阻止的信号发生都会排队在每个进程的挂起信号列表中。挂起队列设计用于保存一个被阻止的通用信号的发生，同时排队每个实时信号的发生。用户模式进程可以使用`sigpending()`和`rt_sigpending()`API 来查询挂起信号。这些例程将挂起信号的列表返回到由`sigset_t`指针指向的实例中。

```
    int sigpending(sigset_t *set);
```

这些操作适用于除了`SIGKILL`和`SIGSTOP`之外的所有信号；换句话说，进程不允许改变默认的处理方式或阻止`SIGSTOP`和`SIGKILL`信号。

# 从程序中引发信号

`kill()`和`sigqueue()`是 POSIX API，通过它们，一个进程可以为另一个进程或进程组引发信号。这些 API 促进了信号作为**进程通信**机制的利用：

```
 int kill(pid_t pid, int sig);
 int sigqueue(pid_t pid, int sig, const union sigval value);

 union sigval {
 int sival_int;
 void *sival_ptr;
 };
```

虽然这两个 API 都提供了参数来指定接收者的`PID`和要提升的`signum`，`sigqueue()`通过一个额外的参数（联合信号）提供了*数据*可以与信号一起发送到接收进程。目标进程可以通过`struct siginfo_t`（`si_value`）实例访问数据。Linux 通过本机 API 扩展了这些函数，可以将信号排队到线程组，甚至到线程组中的轻量级进程（LWP）：

```
/* queue signal to specific thread in a thread group */
int tgkill(int tgid, int tid, int sig);

/* queue signal and data to a thread group */
int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo);

/* queue signal and data to specific thread in a thread group */
int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo);

```

# 等待排队信号

在应用信号进行进程通信时，对于进程来说，暂停自身直到发生特定信号，然后在来自另一个进程的信号到达时恢复执行可能更合适。POSIX 调用`sigsuspend()`、`sigwaitinfo()`和`sigtimedwait()`提供了这种功能：

```
int sigsuspend(const sigset_t *mask);
int sigwaitinfo(const sigset_t *set, siginfo_t *info);
int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout);
```

虽然所有这些 API 允许进程等待指定的信号发生，`sigwaitinfo()`通过`info`指针返回的`siginfo_t`实例提供有关信号的附加数据。`sigtimedwait()`通过提供一个额外的参数扩展了功能，允许操作超时，使其成为一个有界等待调用。Linux 内核提供了一个替代 API，允许进程通过名为`signalfd()`的特殊文件描述符被通知信号的发生：

```
 #include <sys/signalfd.h>
 int signalfd(int fd, const sigset_t *mask, int flags);
```

成功时，`signalfd()`返回一个文件描述符，进程需要调用`read()`来阻塞，直到掩码中指定的任何信号发生。

# 信号数据结构

内核维护每个进程的信号数据结构，以跟踪*信号处理*、*阻塞信号*和*待处理信号队列*。进程任务结构包含对这些数据结构的适当引用：

```
struct task_struct {

....
....
....
/* signal handlers */
 struct signal_struct *signal;
 struct sighand_struct *sighand;

 sigset_t blocked, real_blocked;
 sigset_t saved_sigmask; /* restored if set_restore_sigmask() was used */
 struct sigpending pending;

 unsigned long sas_ss_sp;
 size_t sas_ss_size;
 unsigned sas_ss_flags;
  ....
  ....
  ....
  ....

};
```

# 信号描述符

回顾一下我们在第一章的早期讨论中提到的，Linux 通过轻量级进程支持多线程应用程序。线程应用程序的所有 LWP 都是*进程组*的一部分，并共享信号处理程序；每个 LWP（线程）维护自己的待处理和阻塞信号队列。

任务结构的**signal**指针指向`signal_struct`类型的实例，这是信号描述符。这个结构被线程组的所有 LWP 共享，并维护诸如共享待处理信号队列（对于排队到线程组的信号）之类的元素，这对进程组中的所有线程都是共同的。

以下图表示维护共享待处理信号所涉及的数据结构：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00014.jpeg)

以下是`signal_struct`的一些重要字段：

```
struct signal_struct {
 atomic_t sigcnt;
 atomic_t live;
 int nr_threads;
 struct list_head thread_head;

 wait_queue_head_t wait_chldexit; /* for wait4() */

 /* current thread group signal load-balancing target: */
 struct task_struct *curr_target;

 /* shared signal handling: */
 struct sigpending shared_pending; 
 /* thread group exit support */
 int group_exit_code;
 /* overloaded:
 * - notify group_exit_task when ->count is equal to notify_count
 * - everyone except group_exit_task is stopped during signal delivery
 * of fatal signals, group_exit_task processes the signal.
 */
 int notify_count;
 struct task_struct *group_exit_task;

 /* thread group stop support, overloads group_exit_code too */
 int group_stop_count;
 unsigned int flags; /* see SIGNAL_* flags below */

```

# 阻塞和待处理队列

任务结构中的`blocked`和`real_blocked`实例是被阻塞信号的位掩码；这些队列是每个进程的。线程组中的每个 LWP 都有自己的阻塞信号掩码。任务结构的`pending`实例用于排队私有待处理信号；所有排队到普通进程和线程组中特定 LWP 的信号都排队到这个列表中：

```
struct sigpending {
 struct list_head list; // head to double linked list of struct sigqueue
 sigset_t signal; // bit mask of pending signals
};
```

以下图表示维护私有待处理信号所涉及的数据结构：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00015.jpeg)

# 信号处理程序描述符

任务结构的`sighand`指针指向`struct sighand_struct`的一个实例，这是线程组中所有进程共享的信号处理程序描述符。这个结构也被所有使用`clone()`和`CLONE_SIGHAND`标志创建的进程共享。这个结构包含一个`k_sigaction`实例的数组，每个实例包装一个`sigaction`的实例，描述了每个信号的当前处理方式：

```
struct k_sigaction {
 struct sigaction sa;
#ifdef __ARCH_HAS_KA_RESTORER 
 __sigrestore_t ka_restorer;
#endif
};

struct sighand_struct {
 atomic_t count;
 struct k_sigaction action[_NSIG];
 spinlock_t siglock;
 wait_queue_head_t signalfd_wqh;
};

```

以下图表示信号处理程序描述符：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00016.jpeg)

# 信号生成和传递

当发生信号时，将其加入到接收进程或进程的任务结构中的挂起信号列表中。信号是在用户模式进程、内核或任何内核服务的请求下生成的（对于进程或组）。当接收进程或进程意识到其发生并被强制执行适当的响应处理程序时，信号被认为是**已传递**；换句话说，信号传递等同于相应处理程序的初始化。理想情况下，每个生成的信号都被假定立即传递；然而，存在信号生成和最终传递之间的延迟可能性。为了便于可能的延迟传递，内核为信号生成和传递提供了单独的函数。

# 信号生成调用

内核为信号生成提供了两组不同的函数：一组用于在单个进程上生成信号，另一组用于进程线程组。

+   以下是生成进程信号的重要函数列表：

`send_sig()`: 在进程上生成指定信号；这个函数被内核服务广泛使用

+   `end_sig_info()`: 用额外的`siginfo_t`实例扩展`send_sig()`

+   `force_sig()`: 用于生成无法被忽略或阻止的优先级非可屏蔽信号

+   `force_sig_info()`: 用额外的`siginfo_t`实例扩展`force_sig()`

所有这些例程最终调用核心内核函数`send_signal()`，该函数被设计用于生成指定的信号。

以下是生成进程组信号的重要函数列表：

+   `kill_pgrp()`: 在进程组中的所有线程组上生成指定信号

+   `kill_pid()`: 向由 PID 标识的线程组生成指定信号

+   `kill_pid_info()`: 用额外的`siginfo_t`实例扩展`kill_pid()`

所有这些例程调用一个名为`group_send_sig_info()`的函数，最终使用适当的参数调用`send_signal()`。

`send_signal()`函数是核心信号生成函数；它使用适当的参数调用`__send_signal()`例程：

```
 static int send_signal(int sig, struct siginfo *info, struct task_struct *t,
 int group)
{
 int from_ancestor_ns = 0;

#ifdef CONFIG_PID_NS
 from_ancestor_ns = si_fromuser(info) &&
 !task_pid_nr_ns(current, task_active_pid_ns(t));
#endif

 return __send_signal(sig, info, t, group, from_ancestor_ns);
}
```

以下是`__send_signal()`执行的重要步骤：

1.  从`info`参数中检查信号的来源。如果信号生成是由内核发起的，对于不可屏蔽的`SIGKILL`或`SIGSTOP`，它立即设置适当的 sigpending 位，设置`TIF_SIGPENDING`标志，并通过唤醒目标线程启动传递过程：

```
 /*
 * fast-pathed signals for kernel-internal things like SIGSTOP
 * or SIGKILL.
 */
 if (info == SEND_SIG_FORCED)
 goto out_set;
....
....
....
out_set:
 signalfd_notify(t, sig);
 sigaddset(&pending->signal, sig);
 complete_signal(sig, t, group);

```

1.  调用`__sigqeueue_alloc()`函数，检查接收进程的挂起信号数量是否小于资源限制。如果是，则增加挂起信号计数器并返回`struct sigqueue`实例的地址：

```
 q = __sigqueue_alloc(sig, t, GFP_ATOMIC | __GFP_NOTRACK_FALSE_POSITIVE,
 override_rlimit);
```

1.  将`sigqueue`实例加入到挂起列表中，并将信号信息填入`siginfo_t`：

```
if (q) {
 list_add_tail(&q->list, &pending->list);
 switch ((unsigned long) info) {
 case (unsigned long) SEND_SIG_NOINFO:
       q->info.si_signo = sig;
       q->info.si_errno = 0;
       q->info.si_code = SI_USER;
       q->info.si_pid = task_tgid_nr_ns(current,
       task_active_pid_ns(t));
       q->info.si_uid = from_kuid_munged(current_user_ns(), current_uid());
       break;
 case (unsigned long) SEND_SIG_PRIV:
       q->info.si_signo = sig;
       q->info.si_errno = 0;
       q->info.si_code = SI_KERNEL;
       q->info.si_pid = 0;
       q->info.si_uid = 0;
       break;
 default:
      copy_siginfo(&q->info, info);
      if (from_ancestor_ns)
      q->info.si_pid = 0;
      break;
 }

```

1.  在挂起信号的位掩码中设置适当的信号位，并通过调用`complete_signal()`尝试信号传递，进而设置`TIF_SIGPENDING`标志：

```
 sigaddset(&pending->signal, sig);
 complete_signal(sig, t, group);
```

# 信号传递

信号通过更新接收器任务结构中的适当条目生成后，内核进入传递模式。如果接收进程在 CPU 上并且未阻止指定的信号，则立即传递信号。即使接收方不在 CPU 上，也会传递优先级信号`SIGSTOP`和`SIGKILL`，通过唤醒进程；然而，对于其余的信号，传递将推迟直到进程准备好接收信号。为了便于推迟传递，内核在从中断和系统调用返回时检查进程的非阻塞挂起信号，然后允许进程恢复用户模式执行。当进程调度程序（在从中断和异常返回时调用）发现`TIF_SIGPENDING`标志设置时，它调用内核函数`do_signal()`来启动挂起信号的传递，然后恢复进程的用户模式上下文。

进入内核模式时，进程的用户模式寄存器状态存储在称为`pt_regs`的进程内核堆栈中（特定于体系结构）：

```
 struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
 unsigned long r15;
 unsigned long r14;
 unsigned long r13;
 unsigned long r12;
 unsigned long rbp;
 unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
 unsigned long r11;
 unsigned long r10;
 unsigned long r9;
 unsigned long r8;
 unsigned long rax;
 unsigned long rcx;
 unsigned long rdx;
 unsigned long rsi;
 unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
 unsigned long orig_rax;
/* Return frame for iretq */
 unsigned long rip;
 unsigned long cs;
 unsigned long eflags;
 unsigned long rsp;
 unsigned long ss;
/* top of stack page */
};
```

`do_signal()`例程在内核堆栈中使用`pt_regs`的地址调用。虽然`do_signal()`旨在传递非阻塞的挂起信号，但其实现是特定于体系结构的。

以下是`do_signal()`的 x86 版本：

```
void do_signal(struct pt_regs *regs)
{
 struct ksignal ksig;
 if (get_signal(&ksig)) {
 /* Whee! Actually deliver the signal. */
 handle_signal(&ksig, regs);
 return;
 }
 /* Did we come from a system call? */
 if (syscall_get_nr(current, regs) >= 0) {
 /* Restart the system call - no handlers present */
 switch (syscall_get_error(current, regs)) {
 case -ERESTARTNOHAND:
 case -ERESTARTSYS:
 case -ERESTARTNOINTR:
 regs->ax = regs->orig_ax;
 regs->ip -= 2;
 break;
 case -ERESTART_RESTARTBLOCK:
 regs->ax = get_nr_restart_syscall(regs);
 regs->ip -= 2;
 break;
 }
 }
 /*
 * If there's no signal to deliver, we just put the saved sigmask
 * back.
 */
 restore_saved_sigmask();
}
```

`do_signal()`使用`struct ksignal`类型实例的地址调用`get_signal()`函数（我们将简要考虑此例程的重要步骤，跳过其他细节）。此函数包含一个循环，它调用`dequeue_signal()`直到从私有和共享挂起列表中取出所有非阻塞的挂起信号。它从最低编号的信号开始查找私有挂起信号队列，然后进入共享队列中的挂起信号，然后更新数据结构以指示该信号不再挂起并返回其编号：

```
 signr = dequeue_signal(current, &current->blocked, &ksig->info);
```

对于`dequeue_signal()`返回的每个挂起信号，`get_signal()`通过`struct ksigaction *ka`类型的指针检索当前的信号处理方式：

```
ka = &sighand->action[signr-1]; 
```

如果信号处理方式设置为`SIG_IGN`，则静默忽略当前信号并继续迭代以检索另一个挂起信号：

```
if (ka->sa.sa_handler == SIG_IGN) /* Do nothing. */
 continue;
```

如果处理方式不等于`SIG_DFL`，则检索**sigaction**的地址并将其初始化为参数`ksig->ka`，以便进一步执行用户模式处理程序。它进一步检查用户的**sigaction**中的`SA_ONESHOT (SA_RESETHAND)`标志，如果设置，则将信号处理方式重置为`SIG_DFL`，跳出循环并返回给调用者。`do_signal()`现在调用`handle_signal()`例程来执行用户模式处理程序（我们将在下一节详细讨论这个）。

```
  if (ka->sa.sa_handler != SIG_DFL) {
 /* Run the handler. */
 ksig->ka = *ka;

 if (ka->sa.sa_flags & SA_ONESHOT)
 ka->sa.sa_handler = SIG_DFL;

 break; /* will return non-zero "signr" value */
 }
```

如果处理方式设置为`SIG_DFL`，则调用一组宏来检查内核处理程序的默认操作。可能的默认操作是：

+   **Term**：默认操作是终止进程

+   **Ign**：默认操作是忽略信号

+   **Core**：默认操作是终止进程并转储核心

+   **Stop**：默认操作是停止进程

+   **Cont**：默认操作是如果当前停止则继续进程

```
get_signal() that initiates the default action as per the set disposition:
```

```
/*
 * Now we are doing the default action for this signal.
 */
 if (sig_kernel_ignore(signr)) /* Default is nothing. */
 continue;

 /*
 * Global init gets no signals it doesn't want.
 * Container-init gets no signals it doesn't want from same
 * container.
 *
 * Note that if global/container-init sees a sig_kernel_only()
 * signal here, the signal must have been generated internally
 * or must have come from an ancestor namespace. In either
 * case, the signal cannot be dropped.
 */
 if (unlikely(signal->flags & SIGNAL_UNKILLABLE) &&
 !sig_kernel_only(signr))
 continue;

 if (sig_kernel_stop(signr)) {
 /*
 * The default action is to stop all threads in
 * the thread group. The job control signals
 * do nothing in an orphaned pgrp, but SIGSTOP
 * always works. Note that siglock needs to be
 * dropped during the call to is_orphaned_pgrp()
 * because of lock ordering with tasklist_lock.
 * This allows an intervening SIGCONT to be posted.
 * We need to check for that and bail out if necessary.
 */
 if (signr != SIGSTOP) {
 spin_unlock_irq(&sighand->siglock);

 /* signals can be posted during this window */

 if (is_current_pgrp_orphaned())
 goto relock;

 spin_lock_irq(&sighand->siglock);
 }

 if (likely(do_signal_stop(ksig->info.si_signo))) {
 /* It released the siglock. */
 goto relock;
 }

 /*
 * We didn't actually stop, due to a race
 * with SIGCONT or something like that.
 */
 continue;
 }

 spin_unlock_irq(&sighand->siglock);

 /*
 * Anything else is fatal, maybe with a core dump.
 */
 current->flags |= PF_SIGNALED;

 if (sig_kernel_coredump(signr)) {
 if (print_fatal_signals)
 print_fatal_signal(ksig->info.si_signo);
 proc_coredump_connector(current);
 /*
 * If it was able to dump core, this kills all
 * other threads in the group and synchronizes with
 * their demise. If we lost the race with another
 * thread getting here, it set group_exit_code
 * first and our do_group_exit call below will use
 * that value and ignore the one we pass it.
 */
 do_coredump(&ksig->info);
 }

 /*
 * Death signals, no core dump.
 */
 do_group_exit(ksig->info.si_signo);
 /* NOTREACHED */
 }
```

首先，宏`sig_kernel_ignore`检查默认操作是否为忽略。如果为真，则继续循环迭代以查找下一个挂起信号。第二个宏`sig_kernel_stop`检查默认操作是否为停止；如果为真，则调用`do_signal_stop()`例程，将进程组中的每个线程置于`TASK_STOPPED`状态。第三个宏`sig_kernel_coredump`检查默认操作是否为转储；如果为真，则调用`do_coredump()`例程，生成转储二进制文件并终止线程组中的所有进程。接下来，对于默认操作为终止的信号，通过调用`do_group_exit()`例程杀死组中的所有线程。

# 执行用户模式处理程序

回顾我们在上一节中的讨论，`do_signal()` 调用 `handle_signal()` 例程以传递处于用户处理程序状态的挂起信号。用户模式信号处理程序驻留在进程代码段中，并需要访问进程的用户模式堆栈；因此，内核需要切换到用户模式堆栈以执行信号处理程序。成功从信号处理程序返回需要切换回内核堆栈以恢复用户上下文以进行正常的用户模式执行，但这样的操作将失败，因为内核堆栈不再包含用户上下文（`struct pt_regs`），因为在每次进程从用户模式进入内核模式时都会清空它。

为了确保进程在用户模式下正常执行时的平稳过渡（从信号处理程序返回），`handle_signal()` 将内核堆栈中的用户模式硬件上下文（`struct pt_regs`）移动到用户模式堆栈（`struct ucontext`）中，并设置处理程序帧以在返回时调用 `_kernel_rt_sigreturn()` 例程；此函数将硬件上下文复制回内核堆栈，并恢复当前进程的用户模式上下文以恢复正常执行。

以下图示了用户模式信号处理程序的执行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00017.jpeg)

# 设置用户模式处理程序帧

为了为用户模式处理程序设置堆栈帧，`handle_signal()` 使用 `ksignal` 实例的地址调用 `setup_rt_frame()`，其中包含与信号相关的 `k_sigaction` 和当前进程内核堆栈中 `struct pt_regs` 的指针。

以下是 `setup_rt_frame()` 的 x86 实现：

```
setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
{
 int usig = ksig->sig;
 sigset_t *set = sigmask_to_save();
 compat_sigset_t *cset = (compat_sigset_t *) set;

 /* Set up the stack frame */
 if (is_ia32_frame(ksig)) {
 if (ksig->ka.sa.sa_flags & SA_SIGINFO)
 return ia32_setup_rt_frame(usig, ksig, cset, regs); // for 32bit systems with SA_SIGINFO
 else
 return ia32_setup_frame(usig, ksig, cset, regs); // for 32bit systems without SA_SIGINFO
 } else if (is_x32_frame(ksig)) {
 return x32_setup_rt_frame(ksig, cset, regs);// for systems with x32 ABI
 } else {
 return __setup_rt_frame(ksig->sig, ksig, set, regs);// Other variants of x86
 }
}
```

它检查 x86 的特定变体，并调用适当的帧设置例程。在进一步讨论中，我们将专注于适用于 x86-64 的 `__setup_rt_frame()`。此函数使用一个名为 `struct rt_sigframe` 的结构的实例填充了处理信号所需的信息，设置了一个返回路径（通过 `_kernel_rt_sigreturn()` 函数），并将其推送到用户模式堆栈中。

```
/*arch/x86/include/asm/sigframe.h */
#ifdef CONFIG_X86_64

struct rt_sigframe {
 char __user *pretcode;
 struct ucontext uc;
 struct siginfo info;
 /* fp state follows here */
};

-----------------------  

/*arch/x86/kernel/signal.c */
static int __setup_rt_frame(int sig, struct ksignal *ksig,
 sigset_t *set, struct pt_regs *regs)
{
 struct rt_sigframe __user *frame;
 void __user *restorer;
 int err = 0;
 void __user *fpstate = NULL;

 /* setup frame with Floating Point state */
 frame = get_sigframe(&ksig->ka, regs, sizeof(*frame), &fpstate);

 if (!access_ok(VERIFY_WRITE, frame, sizeof(*frame)))
 return -EFAULT;

 put_user_try {
 put_user_ex(sig, &frame->sig);
 put_user_ex(&frame->info, &frame->pinfo);
 put_user_ex(&frame->uc, &frame->puc);

 /* Create the ucontext. */
 if (boot_cpu_has(X86_FEATURE_XSAVE))
 put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
 else 
 put_user_ex(0, &frame->uc.uc_flags);
 put_user_ex(0, &frame->uc.uc_link);
 save_altstack_ex(&frame->uc.uc_stack, regs->sp);

 /* Set up to return from userspace. */
 restorer = current->mm->context.vdso +
 vdso_image_32.sym___kernel_rt_sigreturn;
 if (ksig->ka.sa.sa_flags & SA_RESTORER)
 restorer = ksig->ka.sa.sa_restorer;
 put_user_ex(restorer, &frame->pretcode);

 /*
 * This is movl $__NR_rt_sigreturn, %ax ; int $0x80
 *
 * WE DO NOT USE IT ANY MORE! It's only left here for historical
 * reasons and because gdb uses it as a signature to notice
 * signal handler stack frames.
 */
 put_user_ex(*((u64 *)&rt_retcode), (u64 *)frame->retcode);
 } put_user_catch(err);

 err |= copy_siginfo_to_user(&frame->info, &ksig->info);
 err |= setup_sigcontext(&frame->uc.uc_mcontext, fpstate,
 regs, set->sig[0]);
 err |= __copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));

 if (err)
 return -EFAULT;

 /* Set up registers for signal handler */
 regs->sp = (unsigned long)frame;
 regs->ip = (unsigned long)ksig->ka.sa.sa_handler;
 regs->ax = (unsigned long)sig;
 regs->dx = (unsigned long)&frame->info;
 regs->cx = (unsigned long)&frame->uc;

 regs->ds = __USER_DS;
 regs->es = __USER_DS;
 regs->ss = __USER_DS;
 regs->cs = __USER_CS;

 return 0;
}
```

`rt_sigframe` 结构的 `*pretcode` 字段被分配为信号处理程序函数的返回地址，该函数是 `_kernel_rt_sigreturn()` 例程。 `struct ucontext uc` 用 `sigcontext` 初始化，其中包含从内核堆栈的 `pt_regs` 复制的用户模式上下文，常规阻塞信号的位数组和浮点状态。在设置并将 `frame` 实例推送到用户模式堆栈后，`__setup_rt_frame()` 改变了进程的内核堆栈中的 `pt_regs`，以便在当前进程恢复执行时将控制权交给信号处理程序。**指令指针（ip）**设置为信号处理程序的基地址，**堆栈指针（sp）**设置为先前推送的帧的顶部地址；这些更改导致信号处理程序执行。

# 重新启动中断的系统调用

我们在第一章中了解到，用户模式进程调用 *系统调用* 以切换到内核模式执行内核服务。当进程进入内核服务例程时，有可能例程被阻塞以等待资源的可用性（例如，等待排他锁）或事件的发生（例如中断）。这些阻塞操作要求调用进程处于 `TASK_INTERRUPTIBLE`、`TASK_UNINTERRUPTIBLE` 或 `TASK_KILLABLE` 状态。所采取的具体状态取决于在系统调用中调用的阻塞调用的选择。

如果调用者任务被置于`TASK_UNINTERRUPTIBLE`状态，那么在该任务上发生的信号会导致它们进入挂起列表，并且仅在服务例程完成后（返回到用户模式时）才会传递给进程。然而，如果任务被置于`TASK_INTERRUPTIBLE`状态，那么在该任务上发生的信号会导致其状态被改变为`TASK_RUNNING`，从而导致任务在阻塞的系统调用上被唤醒，甚至在系统调用完成之前就被唤醒（导致系统调用操作失败）。这种中断通过返回适当的失败代码来指示。在`TASK_KILLABLE`状态下，信号对任务的影响与`TASK_INTERRUPTIBLE`类似，只是在发生致命的`SIGKILL`信号时才会唤醒。

`EINTR`、`ERESTARTNOHAND`、`ERESTART_RESTARTBLOCK`、`ERESTARTSYS`或`ERESTARTNOINTR`是各种内核定义的失败代码；系统调用被编程为在失败时返回适当的错误标志。错误代码的选择决定了在处理中断信号后是否重新启动失败的系统调用操作：

```
(include/uapi/asm-generic/errno-base.h)
 #define EPERM 1 /* Operation not permitted */
 #define ENOENT 2 /* No such file or directory */
 #define ESRCH 3 /* No such process */
 #define EINTR 4 /* Interrupted system call */
 #define EIO 5 /* I/O error */
 #define ENXIO 6 /* No such device or address */
 #define E2BIG 7 /* Argument list too long */
 #define ENOEXEC 8 /* Exec format error */
 #define EBADF 9 /* Bad file number */
 #define ECHILD 10 /* No child processes */
 #define EAGAIN 11 /* Try again */
 #define ENOMEM 12 /* Out of memory */
 #define EACCES 13 /* Permission denied */
 #define EFAULT 14 /* Bad address */
 #define ENOTBLK 15 /* Block device required */
 #define EBUSY 16 /* Device or resource busy */
 #define EEXIST 17 /* File exists */
 #define EXDEV 18 /* Cross-device link */
 #define ENODEV 19 /* No such device */
 #define ENOTDIR 20 /* Not a directory */
 #define EISDIR 21 /* Is a directory */
 #define EINVAL 22 /* Invalid argument */
 #define ENFILE 23 /* File table overflow */
 #define EMFILE 24 /* Too many open files */
 #define ENOTTY 25 /* Not a typewriter */
 #define ETXTBSY 26 /* Text file busy */
 #define EFBIG 27 /* File too large */
 #define ENOSPC 28 /* No space left on device */
 #define ESPIPE 29 /* Illegal seek */
 #define EROFS 30 /* Read-only file system */
 #define EMLINK 31 /* Too many links */
 #define EPIPE 32 /* Broken pipe */
 #define EDOM 33 /* Math argument out of domain of func */
 #define ERANGE 34 /* Math result not representable */
 linux/errno.h)
 #define ERESTARTSYS 512
 #define ERESTARTNOINTR 513
 #define ERESTARTNOHAND 514 /* restart if no handler.. */
 #define ENOIOCTLCMD 515 /* No ioctl command */
 #define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */
 #define EPROBE_DEFER 517 /* Driver requests probe retry */
 #define EOPENSTALE 518 /* open found a stale dentry */
```

从中断的系统调用返回时，用户模式 API 始终返回`EINTR`错误代码，而不管底层内核服务例程返回的具体错误代码是什么。其余的错误代码由内核的信号传递例程使用，以确定从信号处理程序返回时是否可以重新启动中断的系统调用。以下表格显示了系统调用执行被中断时的错误代码以及对各种信号处理的影响：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00018.jpeg)

这是它们的含义：

+   **不重新启动**：系统调用不会被重新启动。进程将从跟随系统调用的指令（int $0x80 或 sysenter）中的用户模式恢复执行。

+   **自动重启**：内核强制用户进程通过将相应的系统调用标识符加载到*eax*中并执行系统调用指令（int $0x80 或 sysenter）来重新启动系统调用操作。

+   **显式重启**：只有在进程设置中断信号的处理程序（通过 sigaction）时启用了`SA_RESTART`标志，系统调用才会被重新启动。

# 摘要

信号，虽然是进程和内核服务之间进行的一种基本形式的通信，但它们提供了一种简单有效的方式，以便在发生各种事件时从运行中的进程获得异步响应。通过理解信号使用的所有核心方面，它们的表示、数据结构和内核例程用于信号生成和传递，我们现在对内核更加了解，也更有准备在本书的后面部分更深入地研究进程之间更复杂的通信方式。在前三章中讨论了进程及其相关方面之后，我们现在将深入研究内核的其他子系统，以提高我们的可见性。在下一章中，我们将建立对内核的核心方面之一——内存子系统的理解。

在接下来的一章中，我们将逐步理解许多关键的内存管理方面，如内存初始化、分页和保护，以及内核内存分配算法等。
