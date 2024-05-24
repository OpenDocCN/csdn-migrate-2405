# Linux 内核编程第二部分（三）

> 原文：[`zh.annas-archive.org/md5/066F8708F0154057BE24B556F153766F`](https://zh.annas-archive.org/md5/066F8708F0154057BE24B556F153766F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用内核定时器、线程和工作队列

如果你的设备驱动的低级规范要求在执行`func_a()`和`func_b()`之间应该有 50 毫秒的延迟呢？此外，根据你的情况，当你在进程或中断上下文中运行时，延迟应该起作用。在驱动的另一部分，如果你需要异步定期执行某种监控功能（比如，每秒一次）怎么办？或者你需要在内核中静默执行工作的线程（或多个线程）？

这些都是各种软件中非常常见的要求，包括我们所在的领域- Linux 内核模块（和驱动）开发！在本章中，你将学习如何在内核空间中设置、理解和使用延迟，以及如何使用内核定时器、内核线程和工作队列。

在本章中，你将学习如何最优地执行这些任务。简而言之，我们将涵盖以下主题：

+   在内核中延迟一段时间

+   设置和使用内核定时器

+   创建和使用内核线程

+   使用内核工作队列

让我们开始吧！

# 技术要求

我假设你已经阅读了前言部分，以便充分利用本书，并已经准备好运行 Ubuntu 18.04 LTS（或更高版本的稳定发布版）的虚拟机，并安装了所有必需的软件包。如果没有，我强烈建议你首先这样做。为了充分利用本书，我强烈建议你首先设置好工作环境，包括克隆本书的 GitHub 代码库，并以实际操作的方式进行工作。代码库可以在这里找到：[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/ch5)。

# 在内核中延迟一段时间

通常情况下，你的内核或驱动代码需要在继续执行下一条指令之前等待一段时间。在 Linux 内核空间中，可以通过一组延迟 API 来实现这一点。从一开始，需要理解的一个关键点是，你可以通过两种广泛的方式强制延迟：

+   通过永远不会导致进程休眠的非阻塞或原子 API 进行延迟（换句话说，它永远不会调度出）

+   通过导致当前进程上下文休眠的阻塞 API 进行延迟（换句话说，通过调度出）

（正如我们在《Linux 内核编程》的配套指南中详细介绍的那样，我们在 CPU 调度的章节中涵盖了这一点，《第十章- CPU 调度器-第一部分》和《第十一章- CPU 调度器-第二部分》），将进程上下文内部休眠意味着内核的核心`schedule()`函数在某个时刻被调用，最终导致上下文切换发生。这引出了一个非常重要的观点（我们之前提到过！）：在任何原子或中断上下文中运行时，绝对不能调用`schedule()`。

通常情况下，就像我们在插入延迟的情况下一样，你必须弄清楚你打算插入延迟的代码所在的上下文是什么。我们在配套指南《Linux 内核编程-第六章-内核内部要点-进程和线程》的“确定上下文”部分中涵盖了这一点；如果你不清楚，请参考一下。（我们在《第四章-处理硬件中断》中对此进行了更详细的讨论。）

接下来，请仔细考虑一下：如果你确实处于原子（或中断）上下文中，是否真的需要延迟？原子或中断上下文的整个目的是，其中的执行时间应尽可能短暂；强烈建议你以这种方式设计。这意味着除非你无法避免，否则不要在原子代码中插入延迟。

+   **使用第一种类型**：这些是永远不会导致休眠发生的非阻塞或原子 API。当您的代码处于原子（或中断）上下文中，并且您确实需要一个短暂的非阻塞延迟时，您应该使用这些 API；但是多短呢？作为一个经验法则，对于 1 毫秒或更短的非阻塞原子延迟使用这些 API。即使您需要在原子上下文中延迟超过一毫秒 - 比如，在中断处理程序的代码中（*但为什么要在中断中延迟！？*） - 使用这些`*delay()`API（`*`字符表示通配符；在这里，您将看到它表示`ndelay()`、`delay()`和`mdelay()`例程）。

+   **使用第二种类型**：这些是导致当前进程上下文休眠的阻塞 API。当您的代码处于进程（或任务）上下文中，需要阻塞性较长时间的延迟时，您应该使用这些；实际上，对于超过一毫秒的延迟。这些内核 API 遵循`*sleep()`的形式。（再次，不详细讨论，想想这个：如果您在进程上下文中，但在自旋锁的临界区内，那就是一个原子上下文 - 如果您必须加入延迟，那么您必须使用`*delay()`API！我们将在本书的最后两章中涵盖自旋锁等更多内容。）

现在，让我们来看看这些内核 API，看看它们是如何使用的。我们将首先看一下`*delay()`原子 API。

## 理解如何使用*delay()原子 API

话不多说，让我们来看一张表，快速总结一下可用的（对于我们模块作者来说）非阻塞或原子`*delay()`内核 API；*它们旨在用于任何类型的原子或中断上下文，其中您不能阻塞或休眠*（或调用`schedule()`）：

| **API** | **注释** |
| --- | --- |
| `ndelay(ns);` | 延迟`ns`纳秒。 |
| `udelay(us);` | 延迟`us`微秒。 |
| `mdelay(ms);` | 延迟`ms`毫秒。 |

表 5.1 - *delay()非阻塞 API

关于这些 API、它们的内部实现和使用，有一些要注意的地方：

+   在使用这些宏/API 时，始终包括`<linux/delay.h>`头文件。

+   你应该根据你需要延迟的时间调用适当的例程；例如，如果你需要执行一个原子非阻塞延迟，比如 30 毫秒，你应该调用`mdelay(30)`而不是`udelay(30*1000)`。内核代码提到了这一点：`linux/delay.h` - *"对于大于几毫秒的间隔使用 udelay()可能会在高 loops_per_jiffy（高 bogomips）的机器上出现溢出风险...".*

+   这些 API 的内部实现，就像 Linux 上的许多 API 一样，是微妙的：在`<linux/delay.h>`头文件中，这些函数（或宏）有一个更高级的抽象实现；在特定于体系结构的头文件中（`<asm-<arch>/delay.h>`或`<asm-generic/delay.h>`；其中`arch`当然是 CPU），通常会有一个特定于体系结构的低级实现，它会在调用时自动覆盖高级版本（链接器会确保这一点）。

+   在当前的实现中，这些 API 最终都会转换为对`udelay()`的包装；这个函数本身会转换为一个紧凑的汇编循环，执行所谓的“忙循环”！（对于 x86，代码可以在`arch/x86/lib/delay.c:__const_udelay()`中找到）。不详细讨论，早期在引导过程中，内核会校准一些值：所谓的**bogomips -**虚假 MIPS - 和**每个 jiffy 的循环**（**lpj**）值。基本上，内核会在那个特定系统上找出，为了使一个定时器滴答或一个 jiffy 经过多少次循环。这个值被称为系统的 bogomips 值，并且可以在内核日志中看到。例如，在我的 Core-i7 笔记本上，它是这样的：

```
Calibrating delay loop (skipped), value calculated using timer frequency.. 5199.98 BogoMIPS (lpj=10399968)
```

+   对于超过`MAX_UDELAY_MS`（设置为 5 毫秒）的延迟，内核将在循环中内部调用`udelay()`函数。

请记住，`*delay()` APIs 必须在任何类型的原子上下文中使用，例如中断处理程序（顶部或底部），因为它们保证不会发生睡眠 - 因此也不会调用`schedule()`。提醒一下（我们在*第四章*中提到过这一点，*处理硬件中断*）：`might_sleep()`用作调试辅助工具；内核（和驱动程序）在代码库中的某些地方内部使用`might_sleep()`宏，即代码在进程上下文中运行时；也就是说，它可以睡眠。现在，如果`might_sleep()`在原子上下文中被调用，那就是完全错误的 - 然后会发出一个嘈杂的`printk`堆栈跟踪，从而帮助您及早发现并修复这些问题。您也可以在进程上下文中使用这些`*delay()` APIs。

在这些讨论中，您经常会遇到`jiffies`内核变量；基本上，将`jiffies`视为一个全局的无符号 64 位值，它在每次定时器中断（或定时器滴答）时递增（它在内部受到溢出的保护）。因此，这个不断递增的变量被用作测量正常运行时间的一种方式，以及实现简单超时和延迟的手段。

现在，让我们看看可用的第二种类型的延迟 APIs - 阻塞类型。

## 了解如何使用*sleep*() 阻塞 APIs

让我们再看一个表，它快速总结了可用的（对我们模块作者来说）阻塞`*sleep*()`内核 APIs；这些只能在进程上下文中使用，当安全睡眠时；也就是说，在进程上下文实际上进入睡眠状态的延迟期间，然后在完成时唤醒：

| **API** | **内部“支持”** | **评论** |
| --- | --- | --- |
| `usleep_range(umin, umax);` | `hrtimers`（高分辨率定时器） | 睡眠介于`umin`和`umax`微秒之间。在唤醒时间灵活的情况下使用。这是**推荐的 API**。 |
| `msleep(ms);` | `jiffies`/`legacy_timers` | 睡眠`ms`毫秒。通常用于持续时间为 10 毫秒或更长的睡眠。 |
| `msleep_interruptible(ms);` | `jiffies`/`legacy_timers` | `msleep(ms);`的可中断变体。 |
| `ssleep(s);` | `jiffies`/`legacy_timers` | 睡眠`s`秒。这是用于睡眠时间大于 1 秒的情况（对`msleep()`的封装）。 |

表 5.2 - *sleep*() 阻塞 APIs

关于这些 API、它们的内部实现和使用，有一些要注意的地方：

+   在使用这些宏/ API 时，请确保包含`<linux/delay.h>`头文件。

+   所有这些`*sleep()` API 都是以这样一种方式内部实现的，即它们会使当前进程上下文进入睡眠状态（也就是通过内部调用`schedule()`）；因此，当进程上下文“安全睡眠”时，它们必须只能被调用。再次强调，仅仅因为您的代码在进程上下文中，并不一定意味着它是安全的睡眠；例如，自旋锁的临界区是原子的；因此，在那里您不能调用上述的`*sleep()` API！

+   我们提到`usleep_range()`是**首选/推荐的 API**，当您需要短暂的睡眠时使用它 - 但是为什么？这将在*让我们试试 - 延迟和睡眠实际需要多长时间？*部分中变得更清晰。

正如您所知，Linux 上的睡眠可以分为两种类型：可中断和不可中断。后者意味着没有信号任务可以“打扰”睡眠。因此，当您调用`msleep(ms);`时，它会通过内部调用以下内容将当前进程上下文置于睡眠状态，持续`ms`：

```
__set_current_state(TASK_UNINTERRUPTIBLE);
return schedule_timeout(timeout);
```

`schedule_timeout()`例程通过设置一个内核定时器（我们下一个话题！）来工作，该定时器将在所需的时间内到期，然后立即通过调用`schedule()`将进程置于睡眠状态！（对于好奇的人，可以在这里查看它的代码：`kernel/time/timer.c:schedule_timeout()`。）`msleep_interruptible()`的实现非常类似，只是调用了`__set_current_state(TASK_INTERRUPTIBLE);`。作为设计启发，遵循*提供机制，而不是策略*的 UNIX 范式；这样，调用`msleep_interruptible()`可能是一个好主意，因为在用户空间应用程序中终止工作（例如用户按下`^C`）时，内核或驱动程序会顺从地释放任务：它的进程上下文被唤醒，运行适当的信号处理程序，生活继续。在内核空间不受用户生成的信号干扰很重要的情况下，使用`msleep()`变体。

同样，作为一个经验法则，根据延迟的持续时间使用以下 API：

+   **超过 10 毫秒的延迟**：`msleep()`或`msleep_interruptible()`

+   **超过 1 秒的延迟**：`ssleep()`

正如你所期望的，`ssleep()`是`msleep()`的简单包装；并且变成了`msleep(seconds * 1000);`。

实现（近似）等效于用户空间`sleep(3)`API 的一种简单方法可以在我们的`convenient.h`头文件中看到；本质上，它使用了`schedule_timeout()`API：

```
#ifdef __KERNEL__
void delay_sec(long);
/*------------ delay_sec --------------------------------------------------
 * Delays execution for @val seconds.
 * If @val is -1, we sleep forever!
 * MUST be called from process context.
 * (We deliberately do not inline this function; this way, we can see it's
 * entry within a kernel stack call trace).
 */
void delay_sec(long val)
{
    asm (""); // force the compiler to not inline it!
    if (in_task()) {
        set_current_state(TASK_INTERRUPTIBLE);
        if (-1 == val)
            schedule_timeout(MAX_SCHEDULE_TIMEOUT);
        else
            schedule_timeout(val * HZ);
    } 
}
#endif /* #ifdef __KERNEL__ */
```

现在你已经学会了如何延迟（是的，请微笑），让我们继续学习一个有用的技能：给内核代码加上时间戳。这样可以快速计算特定代码执行所需的时间。

## 在内核代码中获取时间戳

能够获取准确的时间戳对内核开放使用这一设施非常重要。例如，`dmesg(1)`实用程序以`seconds.microseconds`格式显示系统启动以来的时间；Ftrace 跟踪通常显示函数执行所需的时间。在用户模式下，我们经常使用`gettimeofday(2)`系统调用来获取时间戳。在内核中，存在多个接口；通常使用`ktime_get_*()`系列例程来获取准确的时间戳。对于我们的目的，以下例程很有用：

```
u64 ktime_get_real_ns(void);
```

这个例程通过`ktime_get_real()`API 内部查询墙（时钟）时间，然后将结果转换为纳秒数量。我们不会在这里烦恼内部细节。此外，这个 API 还有几个变体；例如，`ktime_get_real_fast_ns()`，`ktime_get_real_ts64()`等。前者既快速又 NMI 安全。

现在你知道如何获取时间戳，你可以计算一段代码执行所需的时间，而且精度相当高，甚至可以达到纳秒级别的分辨率！你可以使用以下伪代码来实现这一点：

```
#include <linux/ktime.h>
t1 = ktime_get_real_ns();
foo();
bar();
t2 = ktime_get_real_ns();
time_taken_ns = (t2 -> t1);
```

在这里，计算了（虚构的）`foo()`和`bar()`函数执行所需的时间，并且结果（以纳秒为单位）存储在`time_taken_ns`变量中。`<linux/ktime.h>`内核头文件本身包括了`<linux/timekeeping.h>`头文件，其中定义了`ktime_get_*()`系列例程。

在我们的`convenient.h`头文件中提供了一个宏来帮助你计算两个时间戳之间的时间：`SHOW_DELTA(later, earlier);`。确保将后一个时间戳作为第一个参数，第一个时间戳作为第二个参数。

下一节的代码示例将帮助我们采用这种方法。

## 让我们来试试看-延迟和睡眠实际上需要多长时间？

到目前为止，你已经知道如何使用`*delay()`和`*sleep()`API 来构建延迟和睡眠（非阻塞和阻塞）。不过，我们还没有真正在内核模块中尝试过。而且，延迟和睡眠是否像我们所相信的那样准确呢？让我们像往常一样*经验主义*（这很重要！）而不是做任何假设。让我们亲自尝试一下！

我们将在本小节中查看的演示内核模块执行两种延迟，顺序如下：

+   首先，它使用`*delay()`例程（您在*理解如何使用*delay()原子**API*部分中了解到）来实现 10 纳秒、10 微秒和 10 毫秒的原子非阻塞延迟。

+   接下来，它使用`*sleep()`例程（您在*理解如何使用*sleep()阻塞**API*部分中了解到）来实现 10 微秒、10 毫秒和 1 秒的阻塞延迟。

我们这样调用这段代码：

```
DILLY_DALLY("udelay() for     10,000 ns", udelay(10));
```

这里，`DILLY_DALLY()`是一个自定义宏。其实现如下：

```
// ch5/delays_sleeps/delays_sleeps.c
/*
 * DILLY_DALLY() macro:
 * Runs the code @run_this while measuring the time it takes; prints the string
 * @code_str to the kernel log along with the actual time taken (in ns, us
 * and ms).
 * Macro inspired from the book 'Linux Device Drivers Cookbook', PacktPub.
 */
#define DILLY_DALLY(code_str, run_this) do {    \
    u64 t1, t2;                                 \
    t1 = ktime_get_real_ns();                   \
 run_this;                                   \
 t2 = ktime_get_real_ns();                   \
    pr_info(code_str "-> actual: %11llu ns = %7llu us = %4llu ms\n", \
        (t2-t1), (t2-t1)/1000, (t2-t1)/1000000);\
} while(0)
```

在这里，我们以简单的方式实现了时间差计算；一个良好的实现将涉及检查`t2`的值是否大于`t1`，是否发生溢出等。

我们在内核模块的`init`函数中调用它，用于各种延迟和睡眠，如下所示：

```
    [ ... ]
    /* Atomic busy-loops, no sleep! */
    pr_info("\n1\. *delay() functions (atomic, in a delay loop):\n");
    DILLY_DALLY("ndelay() for         10 ns", ndelay(10));
    /* udelay() is the preferred interface */
    DILLY_DALLY("udelay() for     10,000 ns", udelay(10));
    DILLY_DALLY("mdelay() for 10,000,000 ns", mdelay(10));

    /* Non-atomic blocking APIs; causes schedule() to be invoked */
    pr_info("\n2\. *sleep() functions (process ctx, sleeps/schedule()'s out):\n");
    /* usleep_range(): HRT-based, 'flexible'; for approx range [10us - 20ms] */
    DILLY_DALLY("usleep_range(10,10) for 10,000 ns", usleep_range(10, 10));
    /* msleep(): jiffies/legacy-based; for longer sleeps (> 10ms) */
    DILLY_DALLY("msleep(10) for      10,000,000 ns", msleep(10));
    DILLY_DALLY("msleep_interruptible(10)         ", msleep_interruptible(10));
    /* ssleep() is a wrapper over msleep(): = msleep(ms*1000); */
    DILLY_DALLY("ssleep(1)                        ", ssleep(1));
```

当我们的可靠的 x86_64 Ubuntu VM 上运行内核模块时，这是一些示例输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/f9d48d06-517c-4f1c-8883-91e2d9d6f34e.png)

图 5.1 - 部分截图显示我们的 delays_sleeps.ko 内核模块的输出

仔细研究前面的输出；奇怪的是，`udelay(10)`和`mdelay(10)`例程似乎在所需的延迟期间*之前*完成了执行（在我们的示例输出中，分别为`9 微秒`和`9 毫秒`）！为什么？事实是**`*delay()`例程往往会提前完成**。这个事实在内核源代码中有记录。让我们来看看这里的相关代码部分（这是不言自明的）：

```
// include/linux/delay.h
/*
 [ ... ]
 * Delay routines, using a pre-computed "loops_per_jiffy" value.
 *
 * Please note that ndelay(), udelay() and mdelay() may return early for
 * several reasons:
 * 1\. computed loops_per_jiffy too low (due to the time taken to
 * execute the timer interrupt.)
 * 2\. cache behavior affecting the time it takes to execute the
 * loop function.
 * 3\. CPU clock rate changes.
 *
 * Please see this thread:
 * http://lists.openwall.net/linux-kernel/2011/01/09/56
```

`*sleep()`例程具有相反的特性；它们几乎总是**比要求的时间*睡眠更长**。同样，这些是标准 Linux 等非实时操作系统中预期的问题。

您可以通过几种方式**减轻这些问题**：

+   在标准 Linux 中，用户模式下，执行以下操作：

+   首先，最好使用**高分辨率定时器（HRT）**接口以获得高精度。这又是从 RTL 项目合并到主流 Linux（早在 2006 年）的代码。它支持需要小于单个*jiffy*（您知道，这与定时器“tick”、内核`CONFIG_HZ`值紧密耦合）的分辨率的定时器；例如，当`HZ`值为 100 时，一个 jiffy 为 1000/100 = 10 毫秒；当`HZ`为 250 时，一个 jiffy 为 4 毫秒，依此类推。

+   完成后，为什么不使用 Linux 的软实时调度功能呢？在这里，您可以指定`SCHED_FIFO`或`SCHED_RR`的调度策略，并为用户模式线程设置高优先级（范围为 1 到 99；我们在配套指南*Linux 内核编程*的*第十章* *CPU 调度器-第一部分*中介绍了这些细节）。

大多数现代 Linux 系统都支持 HRT。但是，如何利用它呢？这很简单：建议您在*用户空间*编写您的定时器代码，并使用标准的 POSIX 定时器 API（例如`timer_create(2)`和`timer_settime(2)`系统调用）。由于本书关注内核开发，我们不会在这里深入探讨这些用户空间 API。实际上，这个主题在我的早期著作*Linux 系统编程实践*的*第十三章* *定时器*的*较新的 POSIX（间隔）定时器*部分有详细介绍。

+   内核开发人员已经费心清楚地记录了一些关于在内核中使用这些延迟和睡眠 API 时的出色建议。非常重要的是，您浏览一下官方内核文档中的这份文件：[`www.kernel.org/doc/Documentation/timers/timers-howto.rst`](https://www.kernel.org/doc/Documentation/timers/timers-howto.rst)。

+   将 Linux OS 配置为 RTOS 并构建；这将显著减少调度“抖动”（我们在配套指南*Linux 内核编程*的*第十一章* *CPU 调度器-第二部分*的*将主线 Linux 转换为 RTOS*部分中详细介绍了这个主题）。

有趣的是，使用我们“更好”的 Makefile 的 checkpatch 目标可能会带来真正的好处。让我们看看它（内核的 checkpatch Perl 脚本）已经捕捉到了什么（首先确保你在正确的源目录中）：

```
$ cd <...>/ch5/delays_sleeps $ make checkpatch 
make clean
[ ... ]
--- cleaning ---
[ ... ]
--- kernel code style check with checkpatch.pl ---

/lib/modules/5.4.0-58-generic/build/scripts/checkpatch.pl --no-tree -f --max-line-length=95 *.[ch]
[ ... ]
WARNING: usleep_range should not use min == max args; see Documentation/timers/timers-howto.rst
#63: FILE: delays_sleeps.c:63:
+ DILLY_DALLY("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", usleep_range(10, 10));

total: 0 errors, 2 warnings, 79 lines checked
[ ... ]
```

这真的很好！确保你使用我们“更好”的`Makefile`中的目标（我们在伴随指南*Linux 内核编程*的*第五章，编写你的第一个内核模块 LKM - 第二部分*中详细介绍了这一点，在*为你的内核模块提供一个“更好”的 Makefile 模板*部分）。

有了这个，我们已经完成了对内核延迟和内核内睡眠的研究。有了这个基础，你现在将学习如何在本章的其余部分设置和使用内核定时器、内核线程和工作队列。

## “sed”驱动程序——演示内核定时器、内核线程和工作队列

为了使本章更有趣和实用，我们将开始演变一个名为**简单加密解密**的杂项字符“驱动程序”（简称**sed**驱动程序）（不要与著名的`sed(1)`实用程序混淆）。不，你猜对了也不会得到大奖，它提供了一些非常简单的文本加密/解密支持。

这里的重点是，我们应该想象在这个驱动程序的规范中，有一个条款要求工作（实际上是加密/解密功能）在给定的时间间隔内完成——实际上是*在给定的截止日期内*。为了检查这一点，我们将设计我们的驱动程序，使其具有一个内核定时器，在给定的时间间隔内到期；驱动程序将检查功能确实在这个时间限制内完成！

我们将演变一系列`sed`驱动程序及其用户空间对应程序（应用程序）：

+   第一个驱动程序——`sed1`驱动程序和用户模式应用程序（`ch5/sed1`）——将执行我们刚才描述的操作：演示用户模式应用程序将使用`ioctl`系统调用与驱动程序进行接口，并启动加密/解密消息功能。驱动程序将专注于一个内核定时器，我们将设置它在给定的截止日期前到期。如果它到期了，我们认为操作失败；如果没有，定时器被取消，操作就成功了。

+   第二个版本，`sed2`（`ch5/sed2`），将执行与`sed1`相同的操作，只是这里实际的加密/解密消息功能将在一个单独创建的内核线程的上下文中执行！这改变了项目的设计。

+   第三个版本，`sed3`（`ch5/sed3`），将再次执行与`sed1`和`sed2`相同的操作，只是这次实际的加密/解密消息功能将由内核工作队列执行！

现在你已经学会了如何执行延迟（原子和阻塞）和捕获时间戳，让我们学习如何设置和使用内核定时器。

# 设置和使用内核定时器

**定时器**提供了软件在指定时间过去时异步通知的手段。各种软件，无论是在用户空间还是内核空间，都需要定时器；这通常包括网络协议实现、块层代码、设备驱动程序和各种内核子系统。这个定时器提供了异步通知的手段，从而允许驱动程序与运行的定时器并行执行工作。一个重要的问题是，*我怎么知道定时器何时到期？*在用户空间应用程序中，通常情况下，内核会向相关进程发送一个信号（信号通常是`SIGALRM`）。

在内核空间中，这有点微妙。正如您从我们对硬件中断的上半部分和下半部分的讨论中所了解的（请参阅*第四章，处理硬件中断*，*理解和使用上半部分和下半部分*部分），在定时器中断的上半部分（或 ISR）完成后，内核将确保运行定时器中断的下半部分或定时器 softirq（正如我们在第四章中所示，*处理硬件中断*部分*可用的 softirq 及其用途*）。这是一个非常高优先级的 softirq，称为`TIMER_SOFTIRQ`。这个 softirq 就是消耗已到期的定时器！实际上-这一点非常重要-您的定时器的“回调”函数-定时器到期时将运行的函数-由定时器 softirq 运行*因此在原子（中断）上下文中运行*。因此，它在能够和不能做的方面受到限制（同样，这在*第四章*，*处理硬件中断*中有详细解释）。

在下一节中，您将学习如何设置和使用内核定时器。

## 使用内核定时器

要使用内核定时器，您必须遵循一些步骤。简而言之，要做的是（我们稍后会详细讨论）：

1.  使用`timer_setup()`宏初始化定时器元数据结构（`struct timer_list`）。这里初始化的关键项目如下：

+   到期时间（`jiffies`应达到的值，定时器才会到期）

+   定时器到期时要调用的函数-实际上是定时器的“回调”函数

1.  编写定时器回调例程的代码。

1.  在适当的时候，“启动”定时器-也就是，通过调用`add_timer()`（或`mod_timer()`）函数来启动。

1.  当定时器超时（到期）时，操作系统将自动调用您的定时器回调函数（在*步骤 2*中设置的函数）；请记住，它将在定时器 softirq 或原子或中断上下文中运行。

1.  （可选）*定时器默认不是循环的，它们默认是一次性的*。要使定时器再次运行，您将需要调用`mod_timer()` API；这是如何设置间隔定时器-在给定的固定时间间隔后超时。如果不执行此步骤，您的定时器将是一次性定时器-它将倒计时并到期一次。

1.  完成后，使用`del_timer[_sync]()`删除定时器；这也可以用于取消超时。它返回一个值，表示是否已停用挂起的定时器；也就是说，对于活动定时器返回`1`，对于被取消的非活动定时器返回`0`。

`timer_list`数据结构是我们这里相关的；其中，相关成员（模块/驱动程序作者）如下所示：

```
// include/linux/timer.h
struct timer_list {[ ... ]
    unsigned long expires;
    void (*function)(struct timer_list *);
    u32 flags; 
[ ...] };
```

使用`timer_setup()`宏进行初始化：

```
timer_setup(timer, callback, flags);
```

`timer_setup()`的参数如下：

+   `@timer`：指向`timer_list`数据结构的指针（这应该首先分配内存；另外，用`@`作为形式参数名的前缀是一种常见的约定）。

+   `@callback`：回调函数的指针。这是操作系统在定时器到期时调用的函数（在 softirq 上下文中）。它的签名是`void (*function)(struct timer_list *);`。回调函数中接收的参数是指向`timer_list`数据结构的指针。那么，我们如何在定时器回调中传递和访问一些任意数据呢？我们很快就会回答这个问题。

+   `@flags`：这些是定时器标志。我们通常将其传递为`0`（意味着没有特殊行为）。您可以指定的标志是`TIMER_DEFERRABLE`、`TIMER_PINNED`和`TIMER_IRQSAFE`。让我们在内核源代码中看一下：

```
// include/linux/timer.h
/**
 * @TIMER_DEFERRABLE: A deferrable timer will work normally when the
 * system is busy, but will not cause a CPU to come out of idle just
 * to service it; instead, the timer will be serviced when the CPU
 * eventually wakes up with a subsequent non-deferrable timer.
  [ ... ]
 * @TIMER_PINNED: A pinned timer will not be affected by any timer
 * placement heuristics (like, NOHZ) and will always expire on the CPU
 * on which the timer was enqueued.
```

在必要时，使用`TIMER_DEFERRABLE`标志是有用的，当需要监视功耗时（例如在备电设备上）。第三个标志`TIMER_IRQSAFE`只是特定目的；避免使用它。

接下来，使用`add_timer()` API 来启动定时器。一旦调用，定时器就是“活动的”并开始倒计时：

```
void add_timer(struct timer_list *timer);
```

它的参数是你刚刚初始化的`timer_list`结构的指针（通过`timer_setup()`宏）。

### 我们的简单内核定时器模块-代码视图 1

不多说了，让我们来看一下使用**可加载内核模块**（**LKM**）框架编写的简单内核定时器代码的第一部分（可以在`ch5/timer_simple`找到）。和大多数驱动程序一样，我们保留一个包含在运行时所需的信息的上下文或私有数据结构；在这里，我们称之为`st_ctx`。我们将其实例化为`ctx`变量。我们还在一个名为`exp_ms`的全局变量中指定了过期时间（为 420 毫秒）。

```
// ch5/timer_simple/timer_simple.c
#include <linux/timer.h>
[ ... ]
static struct st_ctx {
    struct timer_list tmr;
    int data;
} ctx;
static unsigned long exp_ms = 420;
```

现在，让我们来看一下我们*init*代码的第一部分：

```
static int __init timer_simple_init(void)
{
    ctx.data = INITIAL_VALUE;

    /* Initialize our kernel timer */
    ctx.tmr.expires = jiffies + msecs_to_jiffies(exp_ms);
    ctx.tmr.flags = 0;
    timer_setup(&ctx.tmr, ding, 0);
```

这非常简单。首先，我们初始化`ctx`数据结构，将`data`成员设置为值`3`。这里的一个关键点是`timer_list`结构在我们的`ctx`结构内部，所以我们必须初始化它。现在，设置定时器回调函数（`function`参数）和`flags`参数的值很简单；那么设置过期时间呢？你必须将`timer_list.expires`成员设置为内核中`jiffies`变量（实际上是宏）必须达到的值；在那一点，定时器将会过期！所以，我们设置它在未来 420 毫秒后过期，方法是将当前的 jiffies 值加到 420 毫秒经过的 jiffies 值上，就像这样：

```
ctx.tmr.expires = jiffies + msecs_to_jiffies(exp_ms);
```

`msecs_to_jiffies()`方便的例程在这里帮了我们一个忙，因为它将传递给`jiffies`的毫秒值转换了一下。将这个结果加到当前的`jiffies`值上将会给我们一个`jiffies`在未来的值，在 420 毫秒后，也就是我们希望内核定时器过期的时间。

这段代码是在`include/linux/jiffies.h:msecs_to_jiffies()`中的一个内联函数；注释帮助我们理解它是如何工作的。同样地，内核包含了`usecs_to_jiffies()`、`nsecs_to_jiffies()`、`timeval_to_jiffies()`和`jiffies_to_timeval()`（内联）函数辅助例程。

*init*代码的下一部分如下：

```
    pr_info("timer set to expire in %ld ms\n", exp_ms);
    add_timer(&ctx.tmr); /* Arm it; let's get going! */
    return 0;     /* success */
}
```

正如我们所看到的，通过调用`add_timer()` API，我们已经启动了我们的内核定时器。它现在是活动的并且在倒计时……大约 420 毫秒后，它将会过期。（为什么是大约？正如你在*让我们试试吧-延迟和睡眠到底需要多长时间？*部分看到的，延迟和睡眠的 API 并不是那么精确。事实上，一个建议给你后续工作的练习是测试超时的准确性；你可以在*Questions/kernel_timer_check*部分找到这个。此外，在这个练习的一个示例解决方案中，我们将展示使用`time_after()`宏是一个好主意；它执行一个有效性检查，以确保第二个时间戳实际上比第一个晚。类似的宏可以在`include/linux/jiffies.h`中找到；请参阅这一行之前的注释：`include/linux/jiffies.h:#define time_after(a,b)`）。

### 我们的简单内核定时器模块-代码视图 2

`add_timer()`启动了我们的内核定时器。正如你刚才看到的，它很快就会过期。内部地，正如我们之前提到的，内核的定时器软中断将运行我们的定时器回调函数。在前面的部分，我们初始化了回调函数为`ding()`函数（哈，*拟声词* - 一个描述它所描述的声音的词 - 在行动中！）通过`timer_setup()` API。因此，当定时器过期时，这段代码将会运行：

```
static void ding(struct timer_list *timer)
{
    struct st_ctx *priv = from_timer(priv, timer, tmr);
    /* from_timer() is in fact a wrapper around the well known
     * container_of() macro! This allows us to retrieve access to our
     * 'parent' driver context structure */
    pr_debug("timed out... data=%d\n", priv->data--);
    PRINT_CTX();

    /* until countdown done, fire it again! */
    if (priv->data)
        mod_timer(&priv->tmr, jiffies + msecs_to_jiffies(exp_ms));
}
```

关于这个函数有一些事情需要记住：

+   定时器回调处理程序代码（这里是`ding()`）在原子（中断，软中断）上下文中运行；因此，你不被允许调用任何阻塞 API，内存分配除了使用`GFP_ATOMIC`标志之外，或者在内核和用户空间之间进行任何数据传输（我们在前一章的*中断上下文指南-要做什么和不要做什么*部分详细介绍了这一点）。

+   回调函数接收`timer_list`结构的指针作为参数。由于我们非常有意地将`struct timer_list`保留在我们的上下文或私有数据结构中，我们可以有用地使用`from_timer()`宏来检索指向我们私有结构的指针；也就是`struct st_ctx`）。前面显示的代码的第一行就是这样做的。这是如何工作的？让我们看看它的实现：

```
 // include/linux/timer.h
 #define from_timer(var, callback_timer, timer_fieldname) \
           container_of(callback_timer, typeof(*var), timer_fieldname)

```

它实际上是`container_of()`宏的包装器！

+   然后，我们打印并减少我们的`data`值。

+   然后我们发出我们的`PRINT_CTX()`宏（回想一下，它是在我们的`convenient.h`头文件中定义的）。它将显示我们正在 softirq 上下文中运行。

+   接下来，只要我们的数据成员是正数，我们就通过调用`mod_timer()`API 来强制另一个超时（相同的时间段）：

```
int mod_timer(struct timer_list *timer, unsigned long expires);
```

如您所见，使用`mod_timer()`，定时器再次触发完全取决于您；这被认为是更新定时器到期日期的有效方法。通过使用`mod_timer()`，甚至可以启动非活动定时器（`add_timer()`的工作）；在这种情况下，返回值为`0`，否则为`1`（意味着我们修改了现有的活动定时器）。

### 我们的简单内核定时器模块 - 运行它

现在，让我们测试我们的内核定时器模块。在我们的 x86_64 Ubuntu VM 上，我们将使用我们的`lkm`便利脚本来加载内核模块。以下截图显示了这个过程的部分视图和内核日志：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/8d3fa66c-52cc-44fa-98b5-e7f92ccd785d.png)

图 5.2 - 运行我们的 timer_simple.ko 内核模块的部分截图

研究这里显示的`dmesg`（内核日志）输出。由于我们将私有结构的`data`成员的初始值设置为`3`，内核定时器会过期三次（正如我们的逻辑要求的那样）。查看最左边的时间戳；您可以看到第二个定时器到期发生在`4234.289334`（秒.微秒），第三个在`4234.737346`；快速减法表明时间差为 448,012 微秒；即约 448 毫秒。这是合理的，因为我们要求的超时为 420 毫秒（略高于此；printks 的开销也很重要）。

`PRINT_CTX()`宏的输出也很有启发性；让我们看看前面截图中显示的第二个：

```
[ 4234.290177] timer_simple:ding(): 001) [swapper/1]:0   |  ..s1   /* ding() */
```

这表明（如*第四章*中详细解释的那样，*处理硬件中断*），代码在 CPU 1（`001`）上以 softirq 上下文（`s`在`..s1`中）运行。此外，被定时器中断和 softirq 中断的进程上下文是`swapper/1`内核线程；这是 CPU 1 上空闲时运行的 CPU 空闲线程。这是合理的，在空闲或轻负载系统上很典型。当定时器中断被启动并随后的 softirq 到来并运行我们的定时器回调时，系统（或至少 CPU 1）是空闲的。

## sed1 - 使用我们的演示 sed1 驱动程序实现超时

在这一部分，我们将编写一个更有趣的驱动程序（代码可以在`ch5/sed1/sed1_driver`中找到）。我们将设计它以便加密和/或解密给定的消息（当然非常简单）。基本思想是用户模式应用程序（可以在`ch5/userapp_sed`中找到）作为其用户界面。运行时，它打开我们的`misc`字符驱动程序的设备文件（`/dev/sed1_drv`）并对其进行`ioctl(2)`系统调用。

我们提供了在线材料，以帮助您了解如何通过几种常见方法将内核模块或设备驱动程序与用户空间进程进行接口：通过 procfs、sysfs、debugfs、netlink 套接字和`ioctl()`系统调用（[`github.com/PacktPublishing/Learn-Linux-Kernel-Development/blob/master/User_kernel_communication_pathways.pdf`](https://github.com/PacktPublishing/Learn-Linux-Kernel-Development/blob/master/User_kernel_communication_pathways.pdf)）！

`ioctl()`调用传递了一个封装传递的数据、其长度、要对其执行的操作（或转换）以及`timed_out`字段的数据结构（以确定是否由于未能在截止日期前完成而失败）。有效的操作如下：

+   加密：`XF_ENCRYPT`

+   解密：`XF_DECRYPT`

由于空间不足，我们不打算在这里详细显示代码 - 毕竟，阅读了这么多书，现在你已经有能力自己浏览和理解代码了！尽管如此，与本节相关的某些关键细节将被显示。

让我们来看一下它的整体设计：

+   我们的`sed1`驱动程序（`ch5/sed1/sed1_driver/sed1_drv.c`）实际上是一个伪驱动程序，它不是在任何外围硬件控制器或芯片上运行，而是在内存上运行；尽管如此，它是一个完整的`misc`类字符设备驱动程序。

+   它注册自己作为一个`misc`设备；在这个过程中，内核会自动创建一个设备节点（这里我们称之为`/dev/sed1_drv`）。

+   我们安排它有一个驱动程序“上下文”结构（`struct stMyCtx`），其中包含它在整个过程中使用的关键成员；其中一个是用于内核定时器的`struct timer_list`结构，在`init`代码路径中进行初始化（使用`timer_setup()`API）。

+   一个用户空间应用程序（`ch5/sed1/userapp_sed/userapp_sed1.c`）打开我们的`sed1`驱动程序的设备文件（它作为参数传递给它，以及要加密的消息）。它调用了一个`ioctl(2)`系统调用 - 命令是加密 - 以及`arg`参数，它是一个指向包含所有必需信息的结构的指针（包括要加密的消息负载）。让我们简要看一下：

```
​ kd->data_xform = XF_ENCRYPT;
 ioctl(fd, IOCTL_LLKD_SED_IOC_ENCRYPT_MSG, kd);
```

+   我们的`sed1`驱动程序的`ioctl`方法接管。在执行有效性检查后，它复制元数据结构（通过通常的`copy_from_user()`）并启动我们的`process_it()`函数，然后调用我们的`encrypt_decrypt_payload()`例程。

+   `encrypt_decrypt_payload()`是关键例程。它做以下事情：

+   启动我们的内核定时器（使用`mod_timer()`API），设置它在`TIMER_EXPIRE_MS`毫秒后过期（这里，我们将`TIMER_EXPIRE_MS`设置为`1`）。

+   获取时间戳，`t1 = ktime_get_real_ns();`。

+   启动实际工作 - 它是加密还是解密操作（我们保持它非常简单：对负载的每个字节进行简单的`XOR`操作，然后递增；解密时相反）。

+   工作完成后，立即做两件事：获取第二个时间戳，`t2 = ktime_get_real_ns();`，并取消内核定时器（使用`del_timer()`API）。

+   显示完成所需的时间（通过我们的`SHOW_DELTA()`宏）。

+   然后用户空间应用程序休眠 1 秒钟（以收集自己），并运行`ioctl`解密，导致我们的驱动程序解密消息。

+   最后，终止。

以下是`sed1`驱动程序的相关代码：

```
// ch5/sed1/sed1_driver/sed1_drv.c
[ ... ]
static void encrypt_decrypt_payload(int work, struct sed_ds *kd, struct sed_ds *kdret)
{
        int i;
        ktime_t t1, t2;   // a s64 qty
        struct stMyCtx *priv = gpriv;
        [ ... ]
        /* Start - the timer; set it to expire in TIMER_EXPIRE_MS ms */
        mod_timer(&priv->timr, jiffies + msecs_to_jiffies(TIMER_EXPIRE_MS));
        t1 = ktime_get_real_ns();

        // perform the actual processing on the payload
        memcpy(kdret, kd, sizeof(struct sed_ds));
        if (work == WORK_IS_ENCRYPT) {
                for (i = 0; i < kd->len; i++) {
                        kdret->data[i] ^= CRYPT_OFFSET;
                        kdret->data[i] += CRYPT_OFFSET;
                }
        } else if (work == WORK_IS_DECRYPT) {
                for (i = 0; i < kd->len; i++) {
                        kdret->data[i] -= CRYPT_OFFSET;
                        kdret->data[i] ^= CRYPT_OFFSET;
                }
        }
        kdret->len = kd->len;
        // work done!
        [ ... // code to miss the deadline here! (explained below) ... ]
        t2 = ktime_get_real_ns();

        // work done, cancel the timeout
        if (del_timer(&priv->timr) == 0)
                pr_debug("cancelled the timer while it's inactive! (deadline missed?)\n");
        else
                pr_debug("processing complete, timeout cancelled\n");
        SHOW_DELTA(t2, t1);
}
```

就是这样！为了了解它是如何工作的，让我们看看它的运行情况。首先，我们必须插入我们的内核驱动程序（LKM）：

```
$ sudo insmod ./sed1_drv.ko
$ dmesg 
[29519.684832] misc sed1_drv: LLKD sed1_drv misc driver (major # 10) registered, minor# = 55,
 dev node is /dev/sed1_drv
[29519.689403] sed1_drv:sed1_drv_init(): init done (make_it_fail is off)
[29519.690358] misc sed1_drv: loaded.
$ 
```

以下截图显示了它加密和解密的示例运行（这里我们故意运行了这个应用的**Address Sanitizer**（**ASan**）调试版本；这可能会暴露 bug，所以为什么不呢！）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/b69c5a7c-64ac-4b18-83fb-5b944288b6eb.png)

图 5.3 - 我们的`sed1`迷你项目在规定的截止日期内加密和解密消息

一切进行得很顺利。

让我们来看看我们内核定时器回调函数的代码。在我们简单的`sed1`驱动程序中，我们只需要让它做以下事情：

+   原子地将我们私有结构中的整数`timed_out`设置为`1`，表示失败。当我们将数据结构通过`ioctl()`复制回用户模式应用程序时，这允许它轻松检测失败并报告/记录它（有关使用原子操作符等更多细节将在本书的最后两章中介绍）。

+   向内核日志发出`printk`（在`KERN_NOTICE`级别），指示我们超时了。

+   调用我们的`PRINT_CTX()`宏来显示上下文细节。

我们的内核定时器回调函数的代码如下：

```
static void timesup(struct timer_list *timer)
{
    struct stMyCtx *priv = from_timer(priv, timer, timr);

    atomic_set(&priv->timed_out, 1);
    pr_notice("*** Timer expired! ***\n");
    PRINT_CTX();
}
```

我们能看到这段代码 - `timesup()`定时器到期函数 - 运行吗？我们安排下一步就是这样做。

### 故意错过公交车

我之前遗漏的部分是一个有趣的细节：就在第二个时间戳被取之前，我们插入了一小段代码，故意错过了神圣的截止日期！怎么做？实际上非常简单：

```
static void encrypt_decrypt_payload(int work, struct sed_ds *kd, struct sed_ds *kdret)
{
    [ ... ]
    // work done!
    if (make_it_fail == 1)
 msleep(TIMER_EXPIRE_MS + 1);
    t2 = ktime_get_real_ns();
```

`make_it_fail`是一个模块参数，默认设置为`0`；因此，只有当你想要冒险（是的，有点夸张！）时，你才应该将其传递为`1`。让我们试一试，看看我们的内核定时器何时到期。用户模式应用程序也会检测到这一点，并报告失败：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/29cfeb09-64fd-40e7-92e9-8752bcd8fde6.png)

图 5.4 - 我们的 sed1 迷你项目运行时，make_it_fail 模块参数设置为 1，导致截止日期被错过

这次，截止日期在定时器被取消之前就已经过期，因此导致它到期并触发。它的`timesup()`回调函数随后运行（在前面的截图中突出显示）。我强烈建议您花时间详细阅读驱动程序和用户模式应用程序的代码，并自行尝试。

我们之前简要使用的`schedule_timeout()`函数是使用内核定时器的一个很好的例子！它的内部实现可以在这里看到：`kernel/time/timer.c:schedule_timeout()`.

关于定时器的其他信息可以在`proc`文件系统中找到；其中相关的（伪）文件包括`/proc/[pid]/timers`（每个进程的 POSIX 定时器）和`/proc/timer_list`伪文件（其中包含有关所有待处理的高分辨率定时器以及所有时钟事件源的信息。请注意，内核版本 4.10 之后，`/proc/timer_stats`伪文件消失了）。您可以在关于`proc(5)`的 man 页面上找到更多关于它们的信息，网址为[`man7.org/linux/man-pages/man5/proc.5.html`](https://man7.org/linux/man-pages/man5/proc.5.html)。

在下一节中，您将学习如何创建和使用内核线程以使其对您有利。继续阅读！

# 创建和使用内核线程

线程是一个执行路径；它纯粹关注执行给定的函数。那个函数就是它的生命和范围；一旦它从那个函数返回，它就死了。在用户空间，线程是进程内的执行路径；进程可以是单线程或多线程的。在许多方面，内核线程与用户模式线程非常相似。在内核空间，线程也是一个执行路径，只是它在内核 VAS 中运行，具有内核特权。这意味着内核也是多线程的。快速查看`ps(1)`的输出（使用**伯克利软件发行版**（**BSD**）风格的`aux`选项开关运行）可以显示出内核线程 - 它们的名称被括在方括号中：

```
$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY        STAT START   TIME COMMAND
root           1  0.0  0.5 167464 11548 ?          Ss   06:20   0:00 /sbin/init splash 3
root           2  0.0  0.0      0     0 ?          S    06:20   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?          I<   06:20   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?          I<   06:20   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?          I<   06:20   0:00 [kworker/0:0H-kblockd]
root           9  0.0  0.0      0     0 ?          I<   06:20   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?          S    06:20   0:00 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?          I    06:20   0:05 [rcu_sched]
root          12  0.0  0.0      0     0 ?          S    06:20   0:00 [migration/0]
[ ... ]
root          18  0.0  0.0      0     0 ?          S    06:20   0:00 [ksoftirqd/1]
[ ... ]
```

大多数内核线程都是为了特定目的而创建的；通常它们在系统启动时创建并永远运行（在一个无限循环中）。它们会进入睡眠状态，当需要做一些工作时，就会唤醒，执行它，并立即回到睡眠状态。一个很好的例子是`ksoftirqd/n`内核线程（通常每个 CPU 核心有一个；`n`表示核心编号）；当软中断负载过重时，它们会被内核唤醒，以帮助消耗待处理的软中断（我们在第四章中讨论过这一点，*处理硬件中断*，在*使用 ksoftirqd 内核线程*部分；在前面的`ps`输出中，您可以在双核 VM 上看到它们；它们的 PID 分别为 10 和 18）。同样，内核还使用“kworker”工作线程，它们是动态的 - 随着工作的需要而来去（快速运行`ps aux | grep kworker`应该会显示出其中几个）。

让我们来看看内核线程的一些特点：

+   它们总是在内核 VAS 中执行，在内核模式下具有内核特权。

+   它们总是在进程上下文中运行（参考伴随指南*Linux 内核编程 - 第六章，内核内部要点 - 进程和线程*，*理解进程和中断上下文*部分），它们有一个任务结构（因此有一个 PID 和所有其他典型的线程属性，尽管它们的*凭据*总是设置为`0`，意味着具有根访问权限）。

+   它们与其他线程（包括用户模式线程）竞争 CPU 资源，通过 CPU 调度程序；内核线程（通常缩写为**kthreads**）确实会获得优先级的轻微提升。

+   由于它们纯粹在内核 VAS 中运行，它们对用户 VAS 是盲目的；因此，它们的`current->mm`值始终为`NULL`（实际上，这是识别内核线程的一种快速方法）。

+   所有内核线程都是从名为`kthreadd`的内核线程派生出来的，它的 PID 是`2`。这是在早期引导期间由内核（技术上是第一个 PID 为`0`的`swapper/0`内核线程）创建的；你可以通过执行`pstree -t -p 2`来验证这一点（查阅`pstree(1)`的手册页以获取使用详情）。

+   它们有命名约定。内核线程的命名方式不同，尽管有一些约定是遵循的。通常，名称以`/n`结尾；这表示它是一个每 CPU 内核线程。数字指定了它所关联的 CPU 核心（我们在伴随指南*Linux 内核编程 - 第十一章，CPU 调度程序 - 第二部分*中介绍了 CPU 亲和力，在*理解、查询和设置 CPU 亲和力掩码*部分）。此外，内核线程用于特定目的，它们的名称反映了这一点；例如，`irq/%d-%s`（其中`%d`是 PID，`%s`是名称）是一个线程中断处理程序（在*第四章，处理硬件中断*中介绍）。你可以通过阅读内核文档*减少由每 CPU 内核线程引起的 OS 抖动*，了解如何找到内核线程的名称以及内核线程的许多实际用途（以及如何调整它们以减少抖动），网址为[`www.kernel.org/doc/Documentation/kernel-per-CPU-kthreads.txt`](https://www.kernel.org/doc/Documentation/kernel-per-CPU-kthreads.txt)。

我们感兴趣的是，内核模块和设备驱动程序通常需要在后台运行某些代码路径，与它和内核通常执行的其他工作并行进行。假设你需要在发生异步事件时阻塞，或者需要在某些事件发生时在内核中执行一个用户模式进程，这是耗时的。内核线程在这里就派上用场了；因此，我们将重点关注作为模块作者如何创建和管理内核线程。

是的，你可以在内核中执行用户模式进程或应用程序！内核提供了一些**用户模式辅助**（**umh**）API 来实现这一点，其中一个常见的是`call_usermode_helper()`。你可以在这里查看它的实现：`kernel/umh.c:int call_usermodehelper(const char *path, char **argv, char **envp, int wait)`。不过要小心，你不应该滥用这个 API 从内核中调用任何应用程序 - 这只是糟糕的设计！在内核中使用这个 API 的实际用例非常少；使用`cscope(1)`来查看它。

好的；有了这些，让我们学习如何创建和使用内核线程。

## 一个简单的演示 - 创建一个内核线程

创建内核线程的主要 API（对于我们模块/驱动程序的作者来说）是`kthread_create()`；它是一个调用`kthread_create_on_node()`API 的宏。事实是，仅仅调用`kthread_create()`是不足以使您的内核线程执行任何有用的操作的；这是因为，虽然这个宏确实创建了内核线程，但您需要通过将其状态设置为运行并唤醒它来使其成为调度程序的候选者。这可以通过`wake_up_process()`API 来实现（一旦成功，它将被排入 CPU 运行队列，从而使其可以在不久的将来运行）。好消息是，`kthread_run()`辅助宏可以用来一次性调用`kthread_create()`和`wake_up_process()`。让我们来看看它在内核中的实现：

```
// include/linux/kthread.h
/**
 * kthread_run - create and wake a thread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @namefmt: printf-style name for the thread.
 *
 * Description: Convenient wrapper for kthread_create() followed by
 * wake_up_process(). Returns the kthread or ERR_PTR(-ENOMEM).
 */
#define kthread_run(threadfn, data, namefmt, ...) \
({ \
    struct task_struct *__k \
        = kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
    if (!IS_ERR(__k)) \
        wake_up_process(__k); \
    __k; \
})
```

前面代码片段中的注释清楚地说明了`kthread_run()`的参数和返回值。

为了演示如何创建和使用内核线程，我们将编写一个名为`kthread_simple`的内核模块。以下是其`init`方法的相关代码：

```
// ch5/kthread_simple/kthread_simple.c
static int kthread_simple_init(void)
{   [ ... ]
    gkthrd_ts = kthread_run(simple_kthread, NULL, "llkd/%s", KTHREAD_NAME);
    if (IS_ERR(gkthrd_ts)) {
        ret = PTR_ERR(gkthrd_ts); // it's usually -ENOMEM
        pr_err("kthread creation failed (%d)\n", ret);
        return ret;
    } 
    get_task_struct(gkthrd_ts); // inc refcnt, marking the task struct as in use
    [ ... ]
```

`kthread_run()`的第一个参数是新的内核线程的核心功能！在这里，我们不打算向我们的新生内核线程传递任何数据，这就是为什么第二个参数是`NULL`。其余参数是 printf 风格的格式字符串，指定了它的名称。一旦成功，它将返回指向新内核线程任务结构的指针（我们在伴随指南*Linux 内核编程*-*第六章*-*内核内部要点-进程和线程*-*了解和访问内核任务结构*部分中详细介绍了任务结构）。现在，`get_task_struct()`内联函数很重要-它增加了传递给它的任务结构的引用计数。这标记着任务正在使用中（稍后，在清理代码中，我们将发出`kthread_stop()`辅助例程；它将执行相反的操作，从而减少（最终释放）任务结构的引用计数）。

现在，让我们看看我们的内核线程本身（我们只会显示相关的代码片段）：

```
static int simple_kthread(void *arg)
{
    PRINT_CTX();
    if (!current->mm)
        pr_info("mm field NULL, we are a kernel thread!\n");
```

一旦`kthread_run()`成功创建内核线程，它将开始与系统的其余部分并行运行其代码：现在它是可调度的线程！我们的`PRINT_CTX()`宏显示它在进程上下文中运行，确实是一个内核线程。（我们模仿了将其名称括在方括号中的传统，以显示这一点。验证当前`mm`指针是否为`NULL`的检查证实了这一点。）您可以在*图 5.5*中看到输出。您内核线程例程中的所有代码都将在*进程上下文*中运行；因此，您可以执行阻塞操作（与中断上下文不同）。

接下来，默认情况下，内核线程以 root 所有权运行，并且所有信号都被屏蔽。但是，作为一个简单的测试案例，我们可以通过`allow_signal()`辅助例程打开一些信号。之后，我们简单地循环（我们很快会到`kthread_should_stop()`例程）；在循环体中，我们通过将任务状态设置为`TASK_INTERRUPTIBLE`（意味着睡眠可以被信号中断）并调用`schedule()`来让自己进入睡眠状态：

```
    allow_signal(SIGINT);
    allow_signal(SIGQUIT);

    while (!kthread_should_stop()) {
        pr_info("FYI, I, kernel thread PID %d, am going to sleep now...\n",
            current->pid);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule(); // yield the processor, go to sleep...
        /* Aaaaaand we're back! Here, it's typically due to either the
         * SIGINT or SIGQUIT signal hitting us! */
        if (signal_pending(current))
            break;
    }
```

因此，只有当我们被唤醒时-当您向内核线程发送`SIGINT`或`SIGQUIT`信号时会发生这种情况-我们才会恢复执行。当这发生时，我们跳出循环（请注意我们首先使用`signal_pending()`辅助例程验证了这一点！）。现在，我们的内核线程在循环外恢复执行，只是（故意而戏剧性地）死亡：

```
    set_current_state(TASK_RUNNING);
    pr_info("FYI, I, kernel thread PID %d, have been rudely awoken; I shall"
            " now exit... Good day Sir!\n", current->pid);
    return 0;
}
```

内核模块的清理代码如下：

```
static void kthread_simple_exit(void)
{
    kthread_stop(gkthrd_ts);   /* waits for our kthread to terminate; 
                                * it also internally invokes 
                                * the put_task_struct() to decrement task's  
                                * reference count
                                */
    pr_info("kthread stopped, and LKM removed.\n");
}
```

在清理代码路径中，你应该调用`kthread_stop()`，它执行必要的清理。在内部，它实际上等待内核线程死亡（通过`wait_for_completion()`例程）。因此，如果你在没有通过发送`SIGINT`或`SIGQUIT`信号杀死内核线程的情况下调用`rmmod`，`rmmod`进程将似乎挂起；它（也就是`rmmod`进程）正在等待（嗯，`kthread_stop()`实际上是在等待）内核线程死亡！这就是为什么，如果内核线程还没有被发送信号，这可能会导致问题。

处理内核线程停止的更好方法应该不是从用户空间发送信号给它。确实有一个更好的方法：正确的方法是使用`kthread_should_stop()`例程作为它运行的`while`循环的（反向）条件，这正是我们要做的！在前面的代码中，我们有以下内容：

```
while (!kthread_should_stop()) {
```

`kthread_should_stop()`例程返回一个布尔值，如果内核线程现在应该停止（终止）则为真！在清理代码路径中调用`kthread_stop()`将导致`kthread_should_stop()`返回 true，从而导致我们的内核线程跳出`while`循环并通过简单的`return 0;`终止。这个值（`0`）被传回`kthread_stop()`。由于这个原因，即使没有向我们的内核线程发送信号，内核模块也能成功卸载。我们将把测试这种情况留给你作为一个简单的练习！

注意`kthread_stop()`的返回值可能会有用：它是一个整数，是运行的线程函数的结果 - 实际上，它说明了你的内核线程是否成功（返回`0`）完成了它的工作。如果你的内核线程从未被唤醒，它将是值`-EINTR`。

## 运行 kthread_simple 内核线程演示

现在，让我们试一下（`ch5/kthread_simple`）！我们可以通过`insmod(8)`进行模块插入；模块按计划插入到内核中。如下截图所示的内核日志，以及快速的`ps`，证明我们全新的内核线程确实已经被创建。另外，正如你从代码（`ch5/kthread_simple/kthread_simple.c`）中看到的，我们的内核线程将自己置于睡眠状态（通过将其状态设置为`TASK_INTERRUPTIBLE`，然后调用`schedule()`）：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/9c126689-076e-44b5-9a88-b20b3004f4d4.png)

图 5.5 - 部分截图显示我们的内核线程诞生、活着 - 还有，嗯，睡着了

通过名称快速运行`ps(1) grep`来查找我们的内核线程，可以看到我们的内核线程是活着的（而且睡着的）。

```
$ ps -e |grep kt_simple
 11372   ?        00:00:00 llkd/kt_simple
$
```

让我们来点新意，给我们的内核线程发送`SIGQUIT`信号。这将唤醒它（因为我们已经设置了它的信号掩码以允许`SIGINT`和`SIGQUIT`信号），将其状态设置为`TASK_RUNNING`，然后，简单地退出。然后我们使用`rmmod(8)`来移除内核模块，如下截图所示：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/c3f089f4-57d3-4048-a739-8fe84c1e7292.png)

图 5.6 - 部分截图显示我们的内核线程唤醒和模块成功卸载

现在你已经了解了如何创建和使用内核线程，让我们继续设计和实现我们的`sed`驱动程序的第二个版本。

## sed2 驱动程序 - 设计与实现

在这一部分（如在*“sed”驱动程序 - 演示内核定时器、内核线程和工作队列*部分中提到的），我们将编写`sed1`驱动程序的下一个演变，称为`sed2`。

### sed2 - 设计

我们的`sed` v2（`sed2`*;*代码：`ch5/sed2/`）小项目与我们的`sed1`项目非常相似。关键区别在于，这一次，我们将通过驱动程序专门为此目的创建的内核线程来进行“工作”。这个版本与上一个版本的主要区别如下：

+   有一个全局共享的内存缓冲区用于保存元数据和有效载荷；也就是说，要加密/解密的消息。这是我们驱动程序上下文结构`struct stMyCtx`中的`struct sed_ds->shmem`成员。

+   加密/解密的工作现在在内核线程（由此驱动程序生成）中执行；我们让内核线程保持休眠。只有在出现工作时，驱动程序才会唤醒 kthread 并让其消耗（执行）工作。

+   现在我们在 kthread 的上下文中运行内核定时器，并显示它是否过早到期（表明未满足截止日期）。

+   快速测试表明，在内核线程的关键部分消除了几个`pr_debug()` printks 可以大大减少完成工作所需的时间！（如果您希望消除此开销，可以随时更改 Makefile 的`EXTRA_CFLAGS`变量以取消定义`DEBUG`符号（通过使用`EXTRA_CFLAGS += -UDEBUG`）！）。因此，在这里，截止日期更长（10 毫秒）。

因此，简而言之，这里的整个想法主要是演示使用自定义内核线程以及内核定时器来超时操作。一个重要的理解点改变了整体设计（特别是用户空间应用程序与我们的`sed2`驱动程序交互的方式），即由于我们在内核线程的上下文中运行工作，这与发出`ioctl()`的进程的上下文不同。因此，非常重要的是要意识到以下几点：

+   您不能简单地将数据从内核线程的进程上下文传输到用户空间进程 - 它们完全不同（它们在不同的虚拟地址空间中运行：用户模式进程有自己完整的 VAS 和 PID 等；内核线程实际上生活在内核 VAS 中，有自己的 PID 和内核模式堆栈）。因此，使用`copy_{from|to}_user()`（以及类似的）例程来从 kthread 通信到用户模式应用程序是不可能的。

+   危险的*竞争*可能性很大；内核线程与用户进程上下文异步运行；因此，如果我们不小心，就可能产生与并发相关的错误。这就是本书最后两章的整个原因，我们将在其中涵盖内核同步、锁定（以及相关）概念和技术。目前，请耐心等待 - 我们通过使用一些简单的轮询技巧来代替适当的同步，尽量保持简单。

我们的`sed2`项目内有四个操作：

+   **加密**消息（这也将消息从用户空间传输到驱动程序；因此，这必须首先完成）。

+   **解密**消息。

+   **检索**消息（从驱动程序发送到用户空间应用程序）。

+   **销毁**消息（实际上，它被重置 - 驱动程序内的内存和元数据被清除）。

重要的是要意识到，由于存在竞争的可能性，我们*不能简单地*直接从 kthread 传输数据到用户空间应用程序。因此，我们必须执行以下操作：

+   我们必须通过发出`ioctl()`系统调用在用户空间进程的进程上下文中执行检索和销毁操作。

+   我们必须在我们的内核线程的进程上下文中异步执行加密和解密操作（我们在内核线程中运行它，不是因为我们*必须*，而是因为我们想要；毕竟，这是这个主题的重点！）。

这个设计可以用一个简单的 ASCII 艺术图来总结：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/f2d0e4db-7478-467d-b76a-16fcd637e48b.png)

图 5.7 - 我们的 sed2 迷你项目的高级设计

好了，现在让我们来查看`sed2`的相关代码实现。

### sed2 驱动程序 - 代码实现

在代码方面，`sed2`驱动程序中用于加密操作的`ioctl()`方法的代码如下（为了清晰起见，我们不会在这里显示所有的错误检查代码；我们只会显示最相关的部分）。您可以在`ch5/sed2/`找到完整的代码：

```
// ch5/sed2/sed2_driver/sed2_drv.c
[ ... ]
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static long ioctl_miscdrv(struct file *filp, unsigned int cmd, unsigned long arg)
#else
static int ioctl_miscdrv(struct inode *ino, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
    struct stMyCtx *priv = gpriv;

[ ... ]
switch (cmd) {
    case IOCTL_LLKD_SED_IOC_ENCRYPT_MSG: /* kthread: encrypts the msg passed in */
        [ ... ]
        if (atomic_read(&priv->msg_state) == XF_ENCRYPT) { // already encrypted?
            pr_notice("encrypt op: message is currently encrypted; aborting op...\n");
            return -EBADRQC; /* 'Invalid request code' */
        }
        if (copy_from_user(priv->kdata, (struct sed_ds *)arg, sizeof(struct sed_ds))) {
         [ ... ]

        POLL_ON_WORK_DONE(1);
        /* Wake up our kernel thread and have it encrypt the message ! */
        if (!wake_up_process(priv->kthrd_work))
            pr_warn("worker kthread already running when awoken?\n");
        [ ... ]
```

驱动程序在其`ioctl()`方法中执行了几个有效性检查后，开始工作：对于加密操作，我们检查当前有效载荷是否已经加密（显然，我们在上下文结构中有一个状态成员，用于更新并保存这些信息；即`priv->msg_state`）。如果一切正常，它会从用户空间应用程序中复制消息（以及`struct sed_ds`中所需的元数据）。然后，它*唤醒我们的内核线程*（通过`wake_up_process()` API；参数是从`kthread_create()` API 返回的任务结构指针）。这会导致内核线程恢复执行！

在`init`代码中，我们使用`kthread_create()` API（而不是`kthread_run()`宏）创建了 kthread，因为我们*不*希望 kthread 立即运行！相反，我们更喜欢让它保持睡眠状态，只有在需要工作时才唤醒它。这是我们在使用工作线程时应该遵循的典型方法（所谓的管理者-工作者模型）。

在我们的`init`方法中创建内核线程的代码如下：

```
static int __init sed2_drv_init(void)
{
    [ ... ]
    gpriv->kthrd_work = kthread_create(worker_kthread, NULL, "%s/%s", DRVNAME, KTHREAD_NAME);
    if (IS_ERR(gpriv->kthrd_work)) {
        ret = PTR_ERR(gpriv->kthrd_work); // it's usually -ENOMEM
        dev_err(dev, "kthread creation failed (%d)\n", ret);
        return ret;
    }
    get_task_struct(gpriv->kthrd_work); // inc refcnt, marking the task struct as in use
    pr_info("worker kthread created... (PID %d)\n", task_pid_nr(gpriv->kthrd_work));
    [ ... ]
```

之后，通过`timer_setup()` API 初始化了定时器。我们的工作线程的（截断的）代码如下所示：

```
static int worker_kthread(void *arg)
{
    struct stMyCtx *priv = gpriv;

    while (!kthread_should_stop()) {
        /* Start - the timer; set it to expire in TIMER_EXPIRE_MS ms */
        if (mod_timer(&priv->timr, jiffies + msecs_to_jiffies(TIMER_EXPIRE_MS)))
            pr_alert("timer already active?\n");
        priv->t1 = ktime_get_real_ns();

        /*--------------- Critical section begins --------------------------*/
        atomic_set(&priv->work_done, 0);
        switch (priv->kdata->data_xform) {
        [ ... ]
        case XF_ENCRYPT:
            pr_debug("data transform type: XF_ENCRYPT\n");
            encrypt_decrypt_payload(WORK_IS_ENCRYPT, priv->kdata);
 atomic_set(&priv->msg_state, XF_ENCRYPT);
            break;
        case XF_DECRYPT:
            pr_debug("data transform type: XF_DECRYPT\n");
            encrypt_decrypt_payload(WORK_IS_DECRYPT, priv->kdata);
            atomic_set(&priv->msg_state, XF_DECRYPT);
            break;
        [ ... ]
        priv->t2 = ktime_get_real_ns();
        // work done, cancel the timeout
        if (del_timer(&priv->timr) == 0)
        [ ... ]
```

在这里，您可以看到定时器被启动（`mod_timer()`），根据需要调用实际的加密/解密功能，捕获时间戳，然后取消内核定时器。这就是`sed1`中发生的事情，只是这次（`sed2`）工作发生在我们的内核线程的上下文中！内核线程函数然后使自己进入睡眠状态，通过（正如在配套指南*Linux 内核编程 - 第十章，CPU 调度器 - 第一部分和第十一章，CPU 调度器 - 第二部分中所介绍的）将任务状态设置为睡眠状态（`TASK_INTERRUPTIBLE`）并调用`schedule()`来让出处理器。

等一下 - 在`ioctl()`方法中，您是否注意到在唤醒内核线程之前调用了`POLL_ON_WORK_DONE(1);`宏？看一下以下代码：

```
        [ ... ]       
         POLL_ON_WORK_DONE(1);
        /* Wake up our kernel thread 
         * and have it encrypt the message ! 
         */
        if (!wake_up_process(priv->kthrd_work))
            pr_warn("worker kthread already running when awoken?\n");
        /*
         * Now, our kernel thread is doing the 'work'; 
         * it will either be done, or it will miss it's 
         * deadline and fail. Attempting to lookup the payload 
         * or do anything more here would be a
         * mistake, a race! Why? We're currently running in 
         * the ioctl() process context; the kernel thread runs 
         * in it's own process context! (If we must look it up, 
         * then we really require a (mutex) lock; we shall
         * discuss locking in detail in the book's last two chapters.
         */
        break;
```

使用轮询来规避可能的竞争：如果一个（用户模式）线程调用`ioctl()`来加密给定的消息，同时在另一个 CPU 核心上，另一个用户模式线程调用`ioctl()`来解密给定的消息会发生什么？这将导致并发问题！再次强调，本书的最后两章致力于理解和处理这些问题；但在这里和现在，我们能做什么？让我们实现一个简陋的同步解决方案：*轮询*。

这并不理想，但只能这样做。我们将利用驱动程序在驱动程序上下文结构中设置的一个名为`work_done`的原子变量，当工作完成时，其值为`1`；否则为`0`。我们在这个宏中进行轮询：

```
/*
 * Is our kthread performing any ongoing work right now? poll...
 * Not ideal (but we'll live with it); ideally, use a lock (we cover locking in
 * this book's last two chapters)
 */
#define POLL_ON_WORK_DONE(sleep_ms) do { \
        while (atomic_read(&priv->work_done) == 0) \
            msleep_interruptible(sleep_ms); \
} while (0)
```

为了使这段代码看起来更加可接受，我们不会独占处理器；如果工作还没有完成，我们会通过`msleep_interruptible()` API 睡眠一毫秒，并再次尝试。

到目前为止，我们已经涵盖了`sed2`的`encrypt`和`decrypt`功能的相关代码（这两个功能都在我们的工作线程的上下文中运行）。现在，让我们看看剩下的两个功能 - 检索和销毁消息。这些功能是在原始用户空间进程上下文中执行的 - 发出`ioctl()`系统调用的进程（或线程）。以下是它们的相关代码：

```
// ch5/sed2/sed2_driver/sed2_drv.c : ioctl() method
[ ... ]
case IOCTL_LLKD_SED_IOC_RETRIEVE_MSG: /* ioctl: retrieves the encrypted msg */
        if (atomic_read(&priv->timed_out) == 1) {
            pr_debug("the encrypt op had timed out! returning -ETIMEDOUT\n");
            return -ETIMEDOUT;
        }
        if (copy_to_user((struct sed_ds *)arg, (struct sed_ds *)priv->kdata, sizeof(struct sed_ds))) {
           //  [ ... error handling ... ]
        break;
    case IOCTL_LLKD_SED_IOC_DESTROY_MSG: /* ioctl: destroys the msg */
        pr_debug("In ioctl 'destroy' cmd option\n");
        memset(priv->kdata, 0, sizeof(struct sed_ds));
        atomic_set(&priv->msg_state, 0);
        atomic_set(&priv->work_done, 1);
        atomic_set(&priv->timed_out, 0);
        priv->t1 = priv->t2 = 0;
        break;
[ ... ]
```

现在您已经看到了（相关的）`sed2`代码，让我们来尝试一下吧！

### sed2 - 尝试它

让我们来看看我们的`sed2`迷你项目的一个示例运行，确保您仔细查看它们：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/a00d3a39-6d42-400c-aa33-930747f6a037.png)

图 5.8 - 我们的 sed2 迷你项目展示了一个交互式菜单系统。在这里，一条消息已成功加密

因此，我们已经加密了一条消息，但我们如何查看它呢？简单：我们使用菜单！选择选项`2`来检索（加密的）消息（它将显示供您悠闲阅读），选项`3`来解密它，再次选择选项`2`来查看它，选项`5`来查看内核日志-非常有用！以下截图显示了其中一些选项：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/35866e17-68c1-4168-abb3-8c5e3c2d856c.png)

图 5.9-我们的 sed2 迷你项目展示了一个交互式菜单系统。在这里，一条消息已经成功加密

正如内核日志中所示，我们的用户模式应用程序（`userapp_sed2_dbg_asan`）已经打开了设备并发出了检索操作，然后几秒钟后进行了加密操作（前面截图左下角的时间戳可以帮助你弄清楚这一点）。然后，驱动程序唤醒了内核线程；你可以看到它的 printk 输出，以及`PRINT_CTX()`的输出，如下所示：

```
[41178.885577] sed2_drv:worker_kthread(): 001) [sed2_drv/worker]:24117   |  ...0   /* worker_kthread() */
```

然后，加密操作完成（成功并在截止日期内；定时器被取消）：

```
[41178.888875] sed2_drv:worker_kthread(): processing complete, timeout cancelled
```

类似地，其他操作也在进行中。我们将在这里避免显示用户空间应用程序的代码，因为它是一个简单的用户模式“C”程序。这次（不寻常的是），它是一个带有简单菜单的交互式应用程序（如屏幕截图所示）；请查看一下。我将让你自己详细阅读和理解`sed2`代码，并尝试自己使用它。

## 查询和设置内核线程的调度策略/优先级

最后，你如何查询和/或更改内核线程的调度策略和（实时）优先级呢？内核为此提供了 API（`sched_setscheduler_nocheck()`API 经常在内核中使用）。作为一个实际的例子，内核将需要内核线程来处理中断-我们在第四章中介绍的*线程化中断*模型，在*内部实现线程化中断*部分中已经涵盖了。

它通过`kthread_create()`创建这些线程，并通过`sched_setscheduler_nocheck()`API 更改它们的调度策略和实时优先级。我们不会在这里明确介绍它们的用法，因为我们在配套指南*Linux 内核编程*的*第十一章*“CPU 调度器-第二部分”中已经介绍过了。有趣的是：`sched_setscheduler_nocheck()`API 只是对底层`_sched_setscheduler()`例程的简单包装。为什么呢？`_sched_setscheduler()`API 根本没有被导出，因此模块作者无法使用它；`sched_setscheduler_nocheck()`包装器是通过`EXPORT_SYMBOL_GPL()`宏导出的（这意味着只有 GPL 许可的代码才能使用它！）。

那么，如何查询和/或更改**用户空间线程**的调度策略和（实时）优先级呢？Pthreads 库提供了包装 API 来做到这一点；`pthread_[get|set]schedparam(3)`对可以在这里使用，因为它们是对`sched_[get|set]scheduler(2)`和`sched_[get|set]attr(2)`等系统调用的包装。它们需要 root 访问权限，并且出于安全目的，在二进制可执行文件中设置了`CAP_SYS_NICE`能力位。

尽管本书只涵盖内核编程，但我在这里提到它，因为这是一个非常强大的东西：实际上，用户空间应用程序的设计者/开发者有能力创建和部署完全适合其目的的应用程序线程：具有不同调度策略的实时线程，实时优先级在 1 到 99 之间，非实时线程（基本 nice 值为`0`），等等。不加区别地创建内核线程是不被赞成的，原因很明显-每个额外的内核线程都会增加开销，无论是内存还是 CPU 周期。当你处于设计阶段时，请暂停一下并思考：你真的需要一个或多个内核线程吗？还是有更好的方法来做这些事情？工作队列通常就是这样-更好的方法！

现在，让我们来看看工作队列！

# 使用内核工作队列

**工作队列**是在创建和管理内核工作线程方面的一个抽象层。它们有助于解决一个关键问题：直接与内核线程一起工作，特别是当涉及到多个线程时，不仅困难，而且很容易导致危险的错误，如竞争（从而可能导致死锁），以及线程管理不善，导致效率损失。工作队列是在 Linux 内核中使用的*底半部*机制（连同 tasklets 和 softirqs）。

Linux 内核中的现代工作队列实现 - 称为**并发管理工作队列**（**cmwq**）- 实际上是一个非常复杂的框架，具有根据特定要求动态和高效地提供内核线程的各种策略。

在这本书中，我们更喜欢专注于内核全局工作队列的使用，而不是其内部设计和实现。如果您想了解更多关于内部工作的信息，我建议您阅读这里的“官方”内核文档：[`www.kernel.org/doc/Documentation/core-api/workqueue.rst`](https://www.kernel.org/doc/Documentation/core-api/workqueue.rst)。*进一步阅读*部分还包含一些有用的资源。

工作队列的关键特征如下：

+   工作队列任务（回调）始终在可抢占的进程上下文中执行。一旦你意识到它们是由内核（工作）线程执行的，这一点就很明显，这些线程在可抢占的进程上下文中运行。

+   默认情况下，所有中断都是启用的，不会采取任何锁。

+   上述观点意味着你可以在你的工作队列函数中进行漫长的、阻塞的、I/O 密集型的工作（这与原子上下文（如硬中断、tasklet 或 softirq）完全相反！）。

+   就像你了解内核线程一样，通过典型的`copy_[to|from]_user()`和类似的例程传输数据到用户空间（*不*可能）；这是因为你的工作队列处理程序（函数）在其自己的进程上下文中执行 - 即内核线程的上下文。正如我们所知，内核线程没有用户映射。

+   内核工作队列框架维护工作池。这些工作池实际上是以不同方式组织的几个内核工作线程。内核处理所有管理它们以及并发性问题的复杂性。以下截图显示了几个工作队列内核工作线程（这是在我的 x86_64 Ubuntu 20.04 虚拟机上拍摄的）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/3c46ac29-5b59-49ec-bb67-8209b7f52082.png)

图 5.10 - 为内核工作队列的底半部机制提供服务的几个内核线程

正如我们在*创建和使用内核线程*部分中提到的，了解 kthread 的名称并了解 kthreads 的许多实际用途（以及如何调整它们以减少抖动）的一种方法是阅读相关的内核文档；也就是说，*减少由于每个 CPU kthreads 而导致的 OS 抖动*（[`www.kernel.org/doc/Documentation/kernel-per-CPU-kthreads.txt`](https://www.kernel.org/doc/Documentation/kernel-per-CPU-kthreads.txt)）。

关于如何使用工作队列（以及其他底半部机制），请参阅*第四章*，*处理硬件中断*，*硬中断、tasklet 和线程处理程序 - 何时使用*部分，特别是那里的表格。

重要的是要理解内核始终有一个可用的默认工作队列；它被称为***内核全局工作队列***或***系统工作队列***。为了避免过度使用系统，强烈建议您使用它。我们将使用内核全局工作队列，将我们的工作任务排队，并让它消耗我们的工作。

你甚至可以使用和创建其他类型的工作队列！内核提供了复杂的*cmwq*框架，以及一组 API，帮助您创建特定类型的工作队列。我们将在下一节中更详细地讨论这个问题。

## 最低限度的工作队列内部

我们在这里不会深入讨论工作队列的内部；实际上，我们只会浅尝辄止（正如我们之前提到的，我们在这里的目的只是专注于使用内核全局工作队列）。

始终建议您使用默认的内核全局（系统）工作队列来处理异步后台工作。如果认为这不够用，不用担心 - 有一些接口可以让您创建自己的工作队列。（请记住，这样做会增加系统的压力！）要分配一个新的工作队列实例，您可以使用`alloc_workqueue()` API；这是用于创建（分配）工作队列的主要 API（通过现代*cmwq*框架）：

```
include/linux/workqueue.h
struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...);
```

请注意，它是通过`EXPORT_SYMBOL_GPL()`导出的，这意味着它只对使用 GPL 许可证的模块和驱动程序可用。`fmt`（以及`max_active`后面的参数）指定了如何命名池中的工作队列线程。`flags`参数指定了特殊行为值或其他特性的位掩码，例如以下内容：

+   当工作队列在内存压力下需要前进保证时，请使用`WQ_MEM_RECLAIM`标志。

+   当工作项需要由一个优先级较高的 kthreads 工作池来服务时，请使用`WQ_HIGHPRI`标志。

+   使用`WQ_SYSFS`标志，使一些工作队列的细节通过 sysfs 对用户空间可见（实际上，在`/sys/devices/virtual/workqueue/`下查看）。

+   同样，还有其他几个标志。查看官方内核文档以获取更多详细信息（[`www.kernel.org/doc/Documentation/core-api/workqueue.rst`](https://www.kernel.org/doc/Documentation/core-api/workqueue.rst)；它提供了一些有趣的内容，关于减少内核中工作队列执行的“抖动”）。

`max_active`参数用于指定每个 CPU 可以分配给工作项的最大内核线程数。

大体上，有两种类型的工作队列：

+   **单线程**（**ST**）**工作队列或有序工作队列**：在这里，系统中任何给定时间只能有一个线程处于活动状态。它们可以使用`alloc_ordered_workqueue()`来创建（实际上只是一个在`alloc_workqueue()`上指定有序标志和`max_active`设置为`1`的包装器）。

+   **多线程**（**MT**）**工作队列**：这是默认选项。确切的`flags`指定了行为；`max_active`指定了每个 CPU 可能拥有的工作项的最大工作线程数。

所有的工作队列都可以通过`alloc_workqueue()` API 来创建。创建它们的代码如下：

```
// kernel/workqueue.c
​int __init workqueue_init_early(void)
{
    [ ... ]
    system_wq = alloc_workqueue("events", 0, 0);
    system_highpri_wq = alloc_workqueue("events_highpri", WQ_HIGHPRI, 0);
    system_long_wq = alloc_workqueue("events_long", 0, 0);
    system_unbound_wq = alloc_workqueue("events_unbound", WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
    system_freezable_wq = alloc_workqueue("events_freezable", WQ_FREEZABLE, 0);
    system_power_efficient_wq = alloc_workqueue("events_power_efficient", WQ_POWER_EFFICIENT, 0);
    system_freezable_power_efficient_wq = alloc_workqueue("events_freezable_power_efficient",
                          WQ_FREEZABLE | WQ_POWER_EFFICIENT, 0);
[ ... ]
```

这发生在引导过程的早期（确切地说是在早期的 init 内核代码路径中）。第一个被加粗了；这是正在创建的内核全局工作队列或系统工作队列。它的工作池被命名为`events`。（属于这个池的内核线程的名称遵循这个命名约定，并且在它们的名称中有`events`这个词；再次参见*图 5.10*。其他工作池的 kthreads 也是如此。）

底层框架已经发展了很多；早期的*传统*工作队列框架（2010 年之前）曾经使用`create_workqueue()`和相关 API；然而，现在这些被认为是不推荐的。现代**并发管理工作队列**（**cmwq**）框架（2010 年以后）有趣的是，它向后兼容旧的框架。以下表总结了旧的工作队列 API 与现代 cmwq 的映射：

| **传统（旧的和不推荐的）工作队列 API** | **现代（cmwq）工作队列 API** |
| --- | --- |
| `create_workqueue(name)` | `alloc_workqueue(name,WQ_MEM_RECLAIM, 1)` |
| `create_singlethread_workqueue(name)` | `alloc_ordered_workqueue(name, WQ_MEM_RECLAIM)` |
| `create_freezable_workqueue(name)` | `alloc_workqueue(name, WQ_FREEZABLE &#124; WQ_UNBOUND &#124; WQ_MEM_RECLAIM, 1)` |

表 5.3 - 旧的工作队列 API 与现代 cmwq 的映射

以下图表以简单的概念方式总结了内核工作队列子系统：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/6a2e40f7-3546-45d4-843f-520afe0c298b.png)

图 5.11 - 内核工作队列子系统的简单概念视图

内核的工作队列框架动态维护这些工作线程池；一些，如`events`工作队列（对应于全局内核工作队列）是通用的，而其他一些是为特定目的创建和维护的（就其内核线程的名称而言，如块 I/O，`kworker*blockd`，内存控制，`kworker*mm_percpu_wq`，特定设备的，如 tpm，`tpm_dev_wq`，CPU 频率管理驱动程序，`devfreq_wq`等）。

请注意，内核工作队列子系统自动、优雅、高效地维护所有这些工作队列（及其相关的内核线程的工作线程池）。

那么，您如何实际使用工作队列？下一节将向您展示如何使用全局内核工作队列。接下来将是一个演示内核模块，清楚地展示了其用法。

## 使用全局内核工作队列

在本节中，我们将学习如何使用全局内核（也称为系统或事件工作队列，这是默认的）工作队列。这通常涉及使用您的工作任务初始化工作队列，让它消耗您的工作，并最终进行清理。

### 为您的任务初始化全局内核工作队列 - INIT_WORK()

将工作排队到这个工作队列上实际上非常容易：使用`INIT_WORK()`宏！这个宏接受两个参数：

```
#include <linux/workqueue.h>
INIT_WORK(struct work_struct *_work, work_func_t _func);
```

`work_struct`结构是工作队列的工作结构（至少从模块/驱动程序作者的角度来看）；您需要为其分配内存并将指针作为第一个参数传递。`INIT_WORK()`的第二个参数是指向工作队列回调函数的指针 - 这个函数将被工作队列的工作线程消耗！`work_func_t`是一个`typedef`，指定了这个函数的签名，即`void (*work_func_t)(struct work_struct *work)`。

### 让您的工作任务执行 - schedule_work()

调用`INIT_WORK()`会将指定的工作结构和函数注册到内部默认的全局内核工作队列中。但它不会执行它 - 还没有！您需要在适当的时刻调用`schedule_work()`API 来告诉它何时执行您的“工作”：

```
bool schedule_work(struct work_struct *work);
```

显然，`schedule_work()`的参数是指向`work_struct`结构的指针（您之前通过`INIT_WORK()`宏初始化）。它返回一个布尔值（直接引用源代码）：如果@work 已经在全局内核工作队列上，则返回`%false`，否则返回`%true`。实际上，`schedule_work()`检查通过工作结构指定的函数是否已经在全局内核工作队列上；如果没有，它会将其排队在那里；如果它已经在那里，它会保持在同一位置（不会添加更多的实例）。然后标记工作项以执行。这通常会在相应的内核线程被调度时立即发生，从而给您一个运行您的工作的机会。

要使您的模块或驱动程序中的两个工作项（函数）通过（默认）全局内核工作队列执行，只需两次调用`INIT_WORK()`宏，每次传递不同的工作结构和函数。类似地，对于更多的工作项，为每个工作项调用`INIT_WORK()`...（例如，考虑这个内核块驱动程序（`drivers/block/mtip32xx/mtip32xx.c`）：显然，对于 Micron PCIe SSD，它在其探测方法中连续调用`INIT_WORK()`八次（！），使用数组来保存所有的项目）。

请注意，您可以在原子上下文中调用`schedule_work()`！这个调用是非阻塞的；它只是安排工作项在稍后的延迟（和安全）时间点被消耗时运行在进程上下文中。

#### 调度工作任务的变化

我们刚刚描述的`schedule_work()` API 有一些变体，所有这些变体都可以通过`schedule[_delayed]_work[_on]()`API 获得。让我们简要列举一下。首先，让我们看一下`schedule_delayed_work()`内联函数，其签名如下：

```
bool schedule_delayed_work(struct delayed_work *dwork, unsigned long delay);
```

当您希望延迟执行工作队列处理程序函数一定时间时，请使用此例程；第二个参数`delay`是您希望等待的`jiffies`数。现在，我们知道`jiffies`变量每秒增加`HZ`个`jiffies`；因此，要延迟`n`秒执行您的工作任务，请指定`n * jiffies`。同样，您也可以将`msecs_to_jiffies(n)`值作为第二个参数传递，以便`n`毫秒后执行。

接下来，请注意`schedule_delayed_work()`的第一个参数不同；它是一个`delayed_work`结构，其中包含了现在熟悉的`work_struct`结构作为成员，以及其他一些管理成员（内核定时器、指向工作队列结构的指针和 CPU 编号）。要初始化它，只需为其分配内存，然后利用`INIT_DELAYED_WORK()`宏（语法与`INIT_WORK()`保持相同）；它将负责所有初始化工作。

主题的另一个轻微变体是`schedule[_delayed]_work_on()`例程；名称中的`on`允许您指定执行工作任务时将在哪个 CPU 核心上安排。以下是`schedule_delayed_work_on()`内联函数的签名：

```
bool schedule_delayed_work_on(int cpu, struct delayed_work *dwork, unsigned long delay);
```

第一个参数指定要在其上执行工作任务的 CPU 核心，而其余两个参数与`schedule_delayed_work()`例程的参数相同。（您可以使用`schedule_delayed_work()`例程在给定的 CPU 核心上立即安排您的任务）。

### 清理 - 取消或刷新您的工作任务

在某个时候，您会希望确保您的工作任务已经完成执行。您可能希望在销毁工作队列之前（假设这是一个自定义创建的工作队列，而不是内核全局的工作队列），或者更可能是在使用内核全局工作队列时，在 LKM 或驱动程序的清理方法中执行此操作。在这里使用的典型 API 是`cancel_[delayed_]work[_sync]()`。它的变体和签名如下：

```
bool cancel_work_sync(struct work_struct *work);
bool cancel_delayed_work(struct delayed_work *dwork);
bool cancel_delayed_work_sync(struct delayed_work *dwork);
```

这很简单：一旦使用了`INIT_WORK()`和`schedule_work()`例程，请使用`cancel_work_sync()`；当您延迟了工作任务时，请使用后两者。请注意，其中两个例程的后缀是`_sync`；这意味着取消是*同步的* - 内核将等待您的工作任务完成执行，然后这些函数才会返回！这通常是我们想要的。这些例程返回一个布尔值：如果有待处理的工作，则返回`True`，否则返回`False`。

在内核模块中，不取消（或刷新）您的工作任务在清理（`rmmod`）代码路径中是导致严重问题的一种确定方法；请确保您这样做！

内核工作队列子系统还提供了一些`flush_*()`例程（包括`flush_scheduled_work()`、`flush_workqueue()`和`flush_[delayed_]work()`）。内核文档（[`www.kernel.org/doc/html/latest/core-api/workqueue.html`](https://www.kernel.org/doc/html/latest/core-api/workqueue.html)）明确警告我们，这些例程不容易使用，因为您很容易因为它们而导致死锁问题。建议您改用前面提到的`cancel_[delayed_]work[_sync]()`API。

### 工作流程的快速总结

在使用内核全局工作队列时，出现了一个简单的模式（工作流程）：

1.  *初始化*工作任务。

1.  在适当的时间点，*安排*它执行（也许延迟和/或在特定的 CPU 核心上）。

1.  清理。通常，在内核模块（或驱动程序）的清理代码路径中，*取消*它。（最好是同步进行，以便首先完成任何待处理的工作任务。在这里，我们将坚持使用推荐的`cancel*work*()`例程，避免使用`flush_*()`例程）。

让我们用表格总结一下：

| **使用内核全局工作队列** | **常规工作任务** | **延迟工作任务** | **在给定 CPU 上执行工作任务** |
| --- | --- | --- | --- |
| 1. 初始化 | `INIT_WORK()` | `INIT_DELAYED_WORK()` | *<立即或延迟都可以>* |
| 2. 安排工作任务执行 | `schedule_work()` | `schedule_delayed_work()` | `schedule_delayed_work_on()` |
| 3. 取消（或刷新）它；*foo_sync()*以确保它完成 | `cancel_work_sync()` | `cancel_delayed_work_sync()` | *<立即或延迟都可以>* |

表 5.4 - 使用内核全局工作队列 - 工作流程摘要

在接下来的几节中，我们将编写一个简单的内核模块，使用内核默认工作队列来执行工作任务。

## 我们的简单工作队列内核模块 - 代码视图

让我们动手使用工作队列！在接下来的几节中，我们将编写一个简单的演示内核模块（`ch5/workq_simple`），演示使用内核默认工作队列来执行工作任务。实际上，它是建立在我们之前用来演示内核定时器的 LKM（`ch5/timer_simple`）之上的。让我们来看看代码（像往常一样，我们不会在这里展示完整的代码，只展示最相关的部分）。我们将从它的私有上下文数据结构和*init*方法开始：

```
static struct st_ctx {
    struct work_struct work;
    struct timer_list tmr;
    int data;
} ctx;
[ ... ]
static int __init workq_simple_init(void)
{
    ctx.data = INITIAL_VALUE;
    /* Initialize our work queue */
 INIT_WORK(&ctx.work, work_func);
    /* Initialize our kernel timer */
    ctx.tmr.expires = jiffies + msecs_to_jiffies(exp_ms);
    ctx.tmr.flags = 0;
    timer_setup(&ctx.tmr, ding, 0);
    add_timer(&ctx.tmr); /* Arm it; let's get going! */
    return 0;
}
```

一个需要考虑的关键问题是：我们将如何将一些有用的数据项传递给我们的工作函数？`work_struct`结构只有一个用于内部目的的原子长整型。一个好的（非常典型的！）技巧是将你的`work_struct`结构嵌入到驱动程序的上下文结构中；然后，在工作任务回调函数中，使用`container_of()`宏来访问父上下文数据结构！这是一种经常使用的策略。（`container_of()`是一个强大的宏，但并不容易解释！我们在*进一步阅读*部分提供了一些有用的链接。）因此，在前面的代码中，我们的驱动程序上下文结构嵌入了一个`struct work_struct`。你可以在`INIT_WORK()`宏中看到我们的工作任务的初始化。

一旦定时器被装备好（`add_timer()`在这里起作用），它将在大约 420 毫秒后到期，并且定时器回调函数将在定时器 softirq 上下文中运行（这实际上是一个原子上下文）：

```
static void ding(struct timer_list *timer)
{ 
    struct st_ctx *priv = from_timer(priv, timer, tmr);
    pr_debug("timed out... data=%d\n", priv->data--);
    PRINT_CTX();

    /* until countdown done, fire it again! */
    if (priv->data)
        mod_timer(&priv->tmr, jiffies + msecs_to_jiffies(exp_ms));
    /* Now 'schedule' our work queue function to run */
    if (!schedule_work(&priv->work))
        pr_notice("our work's already on the kernel-global workqueue!\n");
}
```

在减少`data`变量之后，它设置定时器再次触发（通过`mod_timer()`，在 420 毫秒后），然后通过`schedule_work()` API，安排我们的工作队列回调运行！内核将意识到现在必须执行（消耗）工作队列函数，只要是可行的。但是等一下 - 工作队列回调必须且将仅在进程上下文中通过全局内核工作线程运行 - 所谓的事件线程。因此，只有在我们退出这个 softirq 上下文并且（其中之一）"事件"内核工作线程在 CPU 运行队列上，并且实际运行时，我们的工作队列回调函数才会被调用。

放松 - 它很快就会发生...使用工作队列的整个目的不仅是线程管理完全由内核负责，而且函数在进程上下文中运行，因此可以执行漫长的阻塞或 I/O 操作。

再次，多快是“很快”？让我们尝试测量一下：我们在`schedule_work()`之后立即（通过通常的`ktime_get_real_ns()`内联函数）获取一个时间戳作为工作队列函数中的第一行代码。我们信任的`SHOW_DELTA()`宏显示了时间差。正如预期的那样，它很小，通常在几百分之几微秒的范围内（当然，这取决于几个因素，包括硬件平台、内核版本等）。高负载系统会导致切换到事件内核线程花费更长的时间，这可能会导致工作队列的功能执行出现延迟。您将在以下部分的截图捕获（*图 5.12*）中看到一个样本运行。

以下代码是我们的工作任务函数。这是我们使用`container_of()`宏访问我们模块上下文结构的地方：

```
/* work_func() - our workqueue callback function! */
static void work_func(struct work_struct *work)
{
    struct st_ctx *priv = container_of(work, struct st_ctx, work);

    t2 = ktime_get_real_ns();
    pr_info("In our workq function: data=%d\n", priv->data);
    PRINT_CTX();
    SHOW_DELTA(t2, t1);
}
```

此外，我们的`PRINT_CTX()`宏的输出明确显示了这个函数是在进程上下文中运行的。

在*延迟*工作任务回调函数中使用`container_of()`时要小心 - 您必须将第三个参数指定为`struct delayed_work`的`work`成员（我们的一个练习问题让您尝试这个东西！也提供了解决方案...）。我建议您先掌握基础知识，然后再尝试自己做这个。

在下一节中，我们将运行我们的内核模块。

## 我们的简单工作队列内核模块 - 运行它

让我们试一试！看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/a9d89aad-617f-47e8-88d5-37443a49ce5b.png)

图 5.12 - 我们的 workq_simple.ko LKM，突出显示了工作队列函数的执行

让我们更详细地看一下这段代码：

+   通过我们的`lkm`辅助脚本，我们构建然后`insmod(8)`内核模块；也就是`workq_simple.ko`。

+   内核日志通过`dmesg(1)`显示：

+   在 init 方法中初始化和启用了工作队列和内核定时器。

+   定时器到期（大约 420 毫秒）；您可以看到它的 printks（显示`timed out...`和我们的`data`变量的值）。

+   它调用`schedule_work()`API，导致我们的工作队列函数运行。

+   如前面的截图所示，我们的工作队列函数`work_func()`确实运行了；它显示了数据变量的当前值，证明它正确地访问了我们的“上下文”或私有数据结构。

请注意，我们在这个 LKM 中使用了我们的`PRINT_CTX()`宏（它在我们的`convenient.h`头文件中）来揭示一些有趣的东西：

+   +   当它在定时器回调函数的上下文中运行时，它的状态位包含`s`字符（在四字符字段中的第三个字符 - `.Ns1`或类似的），表明它在*softirq*（中断、原子）上下文中运行。

+   当它在工作队列回调函数的上下文中运行时，它的状态位的第三个字符将*永远*不包含`s`字符；它将始终是一个`.`，*证明工作队列总是在进程上下文中执行！*

接下来，`SHOW_DELTA()`宏计算并输出了工作队列被调度和实际执行之间的时间差。正如您所看到的（至少在我们轻载的 x86_64 虚拟机上），它在几百微秒的范围内。

为什么不查找实际使用来消耗我们的工作队列的内核工作线程呢？在这里只需要对 PID 进行简单的`ps(1)`。在这种特殊情况下，它恰好是内核的每个 CPU 核心的通用工作队列消费者线程之一 - 一个内核工作线程（`kworker/...`线程）：

```
$ ps -el | grep -w 55200
 1 I     0   55200       2  0  80  0 -    0 -    ?       00:00:02 kworker/1:0-mm_percpu_wq
 $
```

当然，内核代码库中到处都是工作队列的使用（特别是许多设备驱动程序）。请使用`cscope(1)`来查找和浏览这类代码的实例。

## sed3 迷你项目 - 简要介绍

让我们通过简要地看一下我们的`sed2`项目演变为`sed3`来结束本章。这个小项目与`sed2`相同，只是更简单！（加/解密）工作现在是通过我们的工作任务（函数）通过内核的工作队列功能或底半机制来执行的。我们使用一个工作队列 - 默认的内核全局工作队列 - 来完成工作，而不是手动创建和管理 k 线程（就像我们在`sed2`中所做的那样）！

以下截图显示我们访问样本运行的内核日志；在运行中，我们让用户模式应用程序进行加密，然后解密，最后检索消息进行查看。我们在这里突出显示了有趣的部分 - 通过内核全局工作队列的工作线程执行我们的工作任务 - 在两个红色矩形中：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/670779a5-067a-4d15-be9b-d4dcd7b862b5.png)

图 5.13 - 运行我们的 sed3 驱动程序时的内核日志；通过默认的内核全局工作队列运行的工作任务被突出显示

顺便说一句，用户模式应用程序与我们在`sed2`中使用的应用程序相同。前面的截图显示了（通过我们可靠的`PRINT_CTX()`宏）内核工作线程，内核全局工作队列用于运行我们的加密和解密工作；在这种情况下，加密工作是`[kworker/1:0]` PID 9812，解密工作是`[kworker/0:2]` PID 9791。请注意它们都在进程上下文中运行。我们将让您浏览`sed3`（`ch5/sed3`）的代码。

这就结束了本节。在这里，您了解了内核工作队列基础设施确实是模块/驱动程序作者的福音，因为它帮助您在关于内核线程的底层细节、它们的创建以及复杂的管理和操作方面添加了一个强大的抽象层。这使得您可以非常轻松地在内核中执行工作 - 尤其是通过使用预先存在的内核全局（默认）工作队列 - 而不必担心这些令人讨厌的细节。

# 总结

干得好！在本章中，我们涵盖了很多内容。首先，您学会了如何在内核空间中创建延迟，包括原子和阻塞类型（通过`*delay()`和`*sleep()`例程）。接下来，您学会了如何在 LKM（或驱动程序）中设置和使用内核定时器 - 这是一个非常常见和必需的任务。直接创建和使用内核线程可能是一种令人兴奋（甚至困难）的体验，这就是为什么您学会了如何做到这一点的基础知识。之后，您看了内核工作队列子系统，它解决了复杂性（和并发性）问题。您了解了它是什么，以及如何实际利用内核全局（默认）工作队列在需要时执行您的工作任务。

我们设计和实现的三个`sed`（简单加密解密）演示驱动程序向您展示了这些有趣技术的一个更复杂的用例：`sed1`实现了超时，`sed2`增加了内核线程来执行工作，`sed3`使用内核全局工作队列在需要时消耗工作。

请花一些时间来解决本章的以下*问题*/练习，并浏览*进一步阅读*资源。完成后，我建议您休息一下，然后重新开始。我们快要完成了：最后两章涵盖了一个非常关键的主题 - 内核同步！

# 问题

1.  找出以下伪代码中的错误。

```
static my_chip_tasklet(void)
{
    // ... process data
    if (!copy_to_user(to, from, count)) {
        pr_warn("..."); [...]
    }
}
static irqreturn_t chip_hardisr(int irq, void *data)
{
    // ack irq
    // << ... fetch data into kfifo ... >>
    // << ... call func_a(), delay, then call func_b() >>
    func_a();
    usleep(100); // 100 us delay required here! see datasheet pg ...
    func_b();
    tasklet_schedule(...);
    return IRQ_HANDLED;
}
my_chip_probe(...)
{
    // ...
    request_irq(CHIP_IRQ, chip_hardisr, ...);
    // ...
    tasklet_init(...);
}
```

1.  `timer_simple_check`: 增强`timer_simple`内核模块，以便检查设置超时和实际服务之间经过的时间量。

1.  `kclock`: 编写一个内核模块，设置一个内核定时器，以便每秒超时一次。然后，使用这个来将时间戳打印到内核日志中，实际上得到一个简单的“时钟应用程序”在内核中。

1.  `mutlitime`*：开发一个内核模块，以秒数作为参数发出定时器回调。默认为零（表示没有定时器，因此是一个有效性错误）。它应该这样工作：如果传递的数字是 3，它应该创建三个内核定时器；第一个将在 3 秒后到期，第二个在 2 秒后到期，最后一个在 1 秒后到期。换句话说，如果传递的数字是“n”，它应该创建“n”个内核定时器；第一个将在“n”秒后到期，第二个在“n-1”秒后到期，第三个在“n-2”秒后到期，依此类推，直到计数达到零。

1.  在本章中提供的`sed[123]`迷你项目中构建并运行，并通过查看内核日志验证它们是否按预期工作。

1.  `workq_simple2`：我们提供的`ch5/workq_simple` LKM 设置并通过内核全局工作队列“消耗”一个工作项（函数）；增强它，以便设置并执行两个“工作”任务。验证它是否正常工作。

1.  `workq_delayed`：在之前的任务（`workq_simple2`）的基础上构建，以执行两个工作任务，再加上一个任务（来自 init 代码路径）。第三个任务应该延迟执行；延迟的时间量应该作为名为`work_delay_ms`的模块参数传递（以毫秒为单位；默认值应为 500 毫秒）。

[*提示：*在延迟工作任务回调函数中使用`container_of()`时要小心；您必须将第三个参数指定为`struct delayed_work`的`work`成员；查看我们提供的解决方案]。

您将在书的 GitHub 存储库中找到一些问题的答案：[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/solutions_to_assgn)。

# 进一步阅读

+   内核文档：*延迟，睡眠机制*：[`www.kernel.org/doc/Documentation/timers/timers-howto.tx`](https://www.kernel.org/doc/Documentation/timers/timers-howto.txt)

+   内核定时器系统：[`elinux.org/Kernel_Timer_Systems#Timer_information`](https://elinux.org/Kernel_Timer_Systems#Timer_information)

+   工作队列：

+   这是一个非常好的演示：*使用工作队列进行异步执行*，Bhaktipriya Shridhar：[`events.static.linuxfound.org/sites/events/files/slides/Async%20execution%20with%20wqs.pdf`](https://events.static.linuxfound.org/sites/events/files/slides/Async%20execution%20with%20wqs.pdf)

+   内核文档：*并发管理工作队列（cmwq）*：[`www.kernel.org/doc/html/latest/core-api/workqueue.html#concurrency-managed-workqueue-cmwq`](https://www.kernel.org/doc/html/latest/core-api/workqueue.html#concurrency-managed-workqueue-cmwq)

+   解释了`container_of()`宏：

+   *神奇的 container_of()宏*，2012 年 11 月：[`radek.io/2012/11/10/magical-container_of-macro/`](https://radek.io/2012/11/10/magical-container_of-macro/)

+   *在 Linux 内核中理解 container_of 宏*：[`embetronicx.com/tutorials/linux/c-programming/understanding-of-container_of-macro-in-linux-kernel/`](https://embetronicx.com/tutorials/linux/c-programming/understanding-of-container_of-macro-in-linux-kernel/)


# 第二部分：深入探讨

在这里，您将了解一个高级和关键的主题：内核同步技术和 API 背后的概念、需求和用法。

本节包括以下章节：

+   第六章，*内核同步-第一部分*

+   第七章，*内核同步-第二部分*


# 第六章：内核同步 - 第一部分

任何熟悉在多线程环境中编程的开发人员（甚至在多个进程共享内存或中断可能发生的单线程环境中）都知道，当两个或更多个线程（一般的代码路径）可能会竞争时，需要**同步**；也就是说，它们的结果是无法预测的。纯代码本身从来不是问题，因为它的权限是读/执行（`r-x`）；在多个 CPU 核心上同时读取和执行代码不仅完全正常和安全，而且是受鼓励的（它会提高吞吐量，这就是为什么多线程是一个好主意）。然而，当你开始处理共享可写数据时，你就需要开始非常小心了！

围绕并发性及其控制 - 同步 - 的讨论是多种多样的，特别是在像 Linux 内核这样的复杂软件环境中（其子系统和相关区域，如设备驱动程序），这也是我们在本书中要处理的。因此，为了方便起见，我们将把这个大主题分成两章，本章和下一章。

在本章中，我们将涵盖以下主题：

+   关键部分、独占执行和原子性

+   Linux 内核中的并发性问题

+   互斥锁还是自旋锁？在什么情况下使用

+   使用互斥锁

+   使用自旋锁

+   锁定和中断

让我们开始吧！

# 关键部分、独占执行和原子性

想象一下，你正在为一个多核系统编写软件（嗯，现在，通常情况下，你会在多核系统上工作，即使是在大多数嵌入式项目中）。正如我们在介绍中提到的，同时运行多个代码路径不仅是安全的，而且是可取的（否则，为什么要花那些钱呢，对吧？）。另一方面，在其中**共享可写数据**（也称为**共享状态**）**被访问**的并发（并行和同时）代码路径是需要你保证，在任何给定的时间点，只有一个线程可以同时处理该数据！这真的很关键；为什么？想想看：如果你允许多个并发代码路径在共享可写数据上并行工作，你实际上是在自找麻烦：**数据损坏**（"竞争"）可能会发生。

## 什么是关键部分？

可以并行执行并且可以处理（读取和/或写入）共享可写数据（共享状态）的代码路径被称为关键部分。它们需要保护免受并行性的影响。识别和保护关键部分免受同时执行是你 - 设计师/架构师/开发人员 - 必须处理的隐含要求，以确保正确的软件。

关键部分是必须要么独占地运行；也就是说，单独运行（串行化），要么是原子地；也就是说，不可分割地，一直运行到完成，没有中断。

通过“独占”，我们暗示在任何给定的时间点，一个线程正在运行关键部分的代码；这显然是出于数据安全的原因而需要的。

这个概念也提出了*原子性*的重要概念：单个原子操作是不可分割的。在任何现代处理器上，两个操作被认为总是**原子的**；也就是说，它们不能被中断，并且会一直运行到完成：

+   单个机器语言指令的执行。

+   对齐的原始数据类型的读取或写入，它在处理器的字长（通常为 32 位或 64 位）内；例如，在 64 位系统上读取或写入 64 位整数是有保证的。读取该变量的线程永远不会看到中间、撕裂或脏的结果；它们要么看到旧值，要么看到新值。

因此，如果您有一些代码行处理共享（全局或静态）可写数据，那么在没有任何显式同步机制的情况下，不能保证其独占运行。请注意，有时需要以原子方式运行临界区的代码，以及独占运行，但并非始终如此。

当临界区的代码在安全睡眠的进程上下文中运行时（例如通过用户应用程序对驱动程序进行典型文件操作（打开，读取，写入，ioctl，mmap 等），或者内核线程或工作队列的执行路径），也许可以接受临界区不是真正原子的。但是，当其代码在非阻塞原子上下文中运行时（例如硬中断，tasklet 或 softirq），*它必须以原子方式运行以及独占运行*（我们将在*互斥锁还是自旋锁？何时使用*部分中更详细地讨论这些问题）。

一个概念性的例子将有助于澄清事情。假设三个线程（来自用户空间应用程序）在多核系统上几乎同时尝试打开并从您的驱动程序读取。在没有任何干预的情况下，它们可能会并行运行临界区的代码，从而并行地处理共享可写数据，从而很可能损坏它！现在，让我们看一个概念图示，看看临界区代码路径内的非独占执行是错误的（我们甚至不会在这里谈论原子性）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/4daabc10-0ddf-4879-96c2-49eeb6aa96e3.png)

图 6.1 - 一个概念图示，显示了临界区代码路径如何被同时运行的多个线程违反

如前图所示，在您的设备驱动程序中，在其（比如）读取方法中，您正在运行一些代码以执行其工作（从硬件中读取一些数据）。让我们更深入地看一下这个图示*在不同时间点进行的数据访问*：

+   从时间`t0`到`t1`：没有或只有本地变量数据被访问。这是并发安全的，不需要保护，并且可以并行运行（因为每个线程都有自己的私有堆栈）。

+   从时间`t1`到`t2`：访问全局/静态共享可写数据。这是*不*并发安全的；它是**临界区**，因此必须受到**保护**，以免并发访问。它应该只包含以独占方式运行的代码（独自，每次只有一个线程，串行），也许还是原子的。

+   从时间`t2`到`t3`：没有或只有本地变量数据被访问。这是并发安全的，不需要保护，并且可以并行运行（因为每个线程都有自己的私有堆栈）。

在本书中，我们假设您已经意识到需要同步临界区；我们将不再讨论这个特定的主题。有兴趣的人可以参考我早期的书，*Linux 系统编程实战（Packt，2018 年 10 月）*，其中详细介绍了这些问题（特别是*第十五章*，*使用 Pthreads 进行多线程编程第二部分-同步*）。

因此，了解这一点，我们现在可以重新阐述临界区的概念，同时提到情况何时出现（在项目符号和斜体中显示在项目符号中）。临界区是必须按以下方式运行的代码：

+   （始终）*独占地*：独自（串行）

+   （在原子上下文中）*原子地*：不可分割地，完整地，没有中断

在下一节中，我们将看一个经典的场景 - 全局整数的增量。

## 一个经典的例子 - 全局 i ++

想象一下这个经典的例子：在并发代码路径中递增一个全局整数`i`，其中多个执行线程可以同时执行。对计算机硬件和软件的天真理解会让您相信这个操作显然是原子的。然而，现实是，现代硬件和软件（编译器和操作系统）要比您想象的复杂得多，因此会引起各种看不见的（对应用程序开发人员来说）性能驱动的优化。

我们不会在这里深入讨论太多细节，但现实是，现代处理器非常复杂：它们采用许多技术来提高性能，其中一些是超标量和超流水线执行，以便并行执行多个独立指令和各种指令的几个部分（分别），进行即时指令和/或内存重排序，在复杂的 CPU 缓存中缓存内存，虚假共享等等！我们将在第七章中的*内核同步-第二部分*中的*缓存效应-虚假共享*和*内存屏障*部分中深入探讨其中的一些细节。

Matt Kline 于 2020 年 4 月撰写的论文*《每个系统程序员都应该了解的并发知识》*（[`assets.bitbashing.io/papers/concurrency-primer.pdf`](https://assets.bitbashing.io/papers/concurrency-primer.pdf)）非常出色，是这个主题上的必读之作；一定要阅读！

所有这些使得情况比起初看起来更加复杂。让我们继续讨论经典的`i ++`：

```
static int i = 5;
[ ... ]
foo()
{
    [ ... ]
    i ++;     // is this safe? yes, if truly atomic... but is it truly atomic??
}
```

这个递增本身安全吗？简短的答案是否定的，您必须保护它。为什么？这是一个关键部分——我们正在访问共享的可写数据进行读取和/或写入操作。更长的答案是，这实际上取决于递增操作是否真正是原子的（不可分割的）；如果是，那么`i ++`在并行性的情况下不会造成危险——如果不是，就会有危险！那么，我们如何知道`i ++`是否真正是原子的呢？有两件事决定了这一点：

+   处理器的**指令集架构**（ISA），它决定了（与处理器低级相关的几件事情之一）在运行时执行的机器指令。

+   编译器。

如果 ISA 具有使用单个机器指令执行整数递增的功能，并且编译器具有使用它的智能，那么它就是真正原子的——它是安全的，不需要锁定。否则，它是不安全的，需要锁定！

尝试一下：将浏览器导航到这个精彩的编译器探索网站：[`godbolt.org/`](https://godbolt.org/)。选择 C 作为编程语言，然后在左侧窗格中声明全局整数`i`并在函数内递增。在右侧窗格中使用适当的编译器和编译器选项进行编译。您将看到为 C 高级`i ++;`语句生成的实际机器代码。如果确实是单个机器指令，那么它将是安全的；如果不是，您将需要锁定。总的来说，您会发现您实际上无法判断：实际上，您*不能*假设事情——您将不得不默认假设它是不安全的并加以保护！这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/a6f1659c-346b-40c8-b5e0-f0e4033381ef.png)

图 6.2——即使是最新的稳定 gcc 版本，但没有优化，x86_64 gcc 为 i ++生成了多个指令

前面的截图清楚地显示了这一点：左右两个窗格中的黄色背景区域分别是 C 源代码和编译器生成的相应汇编代码（基于 x86_64 ISA 和编译器的优化级别）。默认情况下，没有优化，`i ++`变成了三条机器指令。这正是我们所期望的：它对应于*获取*（内存到寄存器）、*增量*和*存储*（寄存器到内存）！现在，这*不是*原子的；完全有可能，在其中一条机器指令执行后，控制单元干扰并将指令流切换到不同的位置。这甚至可能导致另一个进程或线程被上下文切换！

好消息是，通过在`编译器选项...`窗口中快速加上`-O2`，`i ++`就变成了一条机器指令 - 真正的原子操作！然而，我们无法预测这些事情；有一天，你的代码可能会在一个相当低端的 ARM（RISC）系统上执行，增加了`i ++`需要多条机器指令的可能性。（不用担心 - 我们将在*使用原子整数操作符*部分专门介绍针对整数的优化锁技术）。

现代语言提供了本地原子操作符；对于 C/C++来说，这是相当近期的（从 2011 年起）；ISO C++11 和 ISO C11 标准提供了现成的和内置的原子变量。稍微搜索一下就可以快速找到它们。现代的 glibc 也在使用它们。举个例子，如果你在用户空间使用信号，你会知道要使用`volatile sig_atomic_t`数据类型来安全地访问和/或更新信号处理程序中的原子整数。那么内核呢？在下一章中，你将了解 Linux 内核对这个关键问题的解决方案。我们将在*使用原子整数操作符*和*使用原子位操作符*部分进行介绍。

Linux 内核当然是一个并发环境：多个执行线程在多个 CPU 核心上并行运行。不仅如此，即使在单处理器（UP/单 CPU）系统上，硬件中断、陷阱、故障、异常和软件信号的存在也可能导致数据完整性问题。毋庸置疑，保护代码路径中必要的并发性是易说难做的；识别和保护关键部分使用诸如锁等技术的同步原语和技术是绝对必要的，这也是为什么这是本章和下一章的核心主题。

## 概念 - 锁

我们需要同步是因为，没有任何干预，线程可以同时执行关键部分，其中共享可写数据（共享状态）正在被处理。为了打败并发性，我们需要摆脱并行性，我们需要*串行化*关键部分内的代码 - 共享数据正在被处理的地方（用于读取和/或写入）。

为了强制一个代码路径变成串行化，一个常见的技术是使用**锁**。基本上，锁通过保证在任何给定时间点上只有一个执行线程可以“获取”或拥有锁来工作。因此，在代码中使用锁来保护关键部分将给我们想要的东西 - 专门运行关键部分的代码（也许是原子的；更多内容即将到来）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/5ccf6307-e970-4b7f-bcaa-566fb4acfb80.png)

图 6.3 - 一个概念图示，展示了如何使用锁来保证关键部分代码路径的独占性

前面的图示展示了解决前面提到的情况的一种方法：使用锁来保护关键部分！锁（和解锁）在概念上是如何工作的呢？

锁的基本前提是，每当有争用时（即多个竞争线程（比如`n`个线程）尝试获取锁（`LOCK`操作）时），只有一个线程会成功。这被称为锁的“赢家”或“所有者”。它将*lock* API 视为非阻塞调用，因此在执行关键部分的代码时会继续运行 - 并且是独占的（关键部分实际上是*lock*和*unlock*操作之间的代码！）。那么剩下的`n-1`个“失败者”线程会发生什么呢？它们（也许）会将锁 API 视为阻塞调用；它们实际上会等待。等待什么？当然是锁的*unlock*操作，这是由锁的所有者（“赢家”线程）执行的！一旦解锁，剩下的`n-1`个线程现在会竞争下一个“赢家”位置；当然，它们中的一个会“赢”并继续前进；在此期间，`n-2`个失败者现在会等待（新的）赢家的*unlock*；这种情况会重复，直到所有`n`个线程（最终和顺序地）获取锁。

当然，锁定是有效的，但 - 这应该是相当直观的 - 它会导致（相当大的！）**开销，因为它破坏了并行性并串行化了**执行流！为了帮助您可视化这种情况，想象一个漏斗，狭窄的部分是只有一个线程可以一次进入的关键部分。所有其他线程都会被堵住；锁定会创建瓶颈：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/4f476235-4b35-4d76-8d49-694b0095c1be.png)

图 6.4 - 锁创建了一个瓶颈，类似于一个物理漏斗

另一个经常提到的物理类比是一条高速公路，有几条车道汇入一条非常繁忙 - 交通拥挤 - 的车道（也许是一个设计不佳的收费站）。同样，并行性 - 车辆（线程）在不同车道上与其他车辆并行行驶（CPU） - 丢失，并且需要串行行为 - 车辆被迫排队排队。

因此，作为软件架构师，我们必须努力设计我们的产品/项目，以尽量减少对锁的需求。虽然在大多数实际项目中完全消除全局变量是不可行的，但优化和最小化它们的使用是必需的。我们将在以后更详细地介绍这一点，包括一些非常有趣的无锁编程技术。

另一个非常关键的点是，新手程序员可能天真地认为在共享可写数据对象上执行读取是完全安全的，因此不需要显式保护（除了在处理器总线大小范围内的对齐原始数据类型的情况下）；这是不正确的。这种情况可能导致所谓的**脏读或破碎读**，即在另一个写入线程同时写入时可能读取到过时的数据，而你在没有锁定的情况下错误地读取了相同的数据项。

既然我们谈到了原子性，正如我们刚刚了解的那样，在典型的现代微处理器上，唯一保证原子性的是单个机器语言指令或者在处理器总线宽度内对齐的原始数据类型的读/写。那么，我们如何标记几行“C”代码，使其真正原子化呢？在用户空间中，这甚至是不可能的（我们可以接近，但无法保证原子性）。

在用户空间应用程序中如何“接近”原子性？您可以始终构建一个用户线程来使用`SCHED_FIFO`策略和实时优先级为`99`。这样，当它想要运行时，除了硬件中断/异常之外，几乎没有其他东西可以抢占它。（旧的音频子系统实现在很大程度上依赖于此。）

在内核空间中，我们可以编写真正原子的代码。怎么做呢？简短的答案是，我们可以使用自旋锁！我们很快将更详细地了解自旋锁。

### 关键点总结

让我们总结一些关于临界区的关键点。仔细审查这些内容非常重要，保持这些内容方便，并确保在实践中使用它们：

+   **临界区**是一个可以并行执行并且可以操作（读和/或写）共享可写数据（也称为“共享状态”）的代码路径。

+   由于它处理共享可写数据，临界区需要保护免受以下影响：

+   并行性（也就是说，它必须单独运行/串行运行/以互斥的方式运行）

+   在原子（中断）非阻塞上下文中运行 - 原子地：不可分割地，完全地，没有中断。一旦受保护，你可以安全地访问你的共享状态，直到“解锁”。

+   代码库中的每个临界区都必须被识别和保护：

+   识别临界区至关重要！仔细审查你的代码，确保你没有漏掉它们。

+   可以通过各种技术来保护它们；一个非常常见的技术是*锁定*（还有无锁编程，我们将在下一章中看到）。

+   一个常见的错误是只保护对全局可写数据的*写*的临界区；你还必须保护对全局可写数据的*读*的临界区；否则，你会面临**破碎或脏读！**为了帮助澄清这一关键点，想象一下在 32 位系统上读取和写入无符号 64 位数据项；在这种情况下，操作不能是原子的（需要两次加载/存储操作）。因此，如果在一个线程中读取数据项的值的同时，另一个线程正在同时写入它，会怎么样！？写入线程以某种方式“锁定”，但因为你认为读取是安全的，读取线程没有获取锁；由于不幸的时间巧合，你最终可能会执行部分/破碎/脏读！我们将在接下来的章节和下一章中学习如何通过使用各种技术来克服这些问题。

+   另一个致命的错误是不使用相同的锁来保护给定的数据项。

+   未保护临界区会导致**数据竞争**，即实际值的结果 - 被读/写的数据的实际值 - 是“竞争的”，这意味着它会根据运行时环境和时间而变化。这被称为一个 bug。（一旦在“现场”中，这是极其难以看到、重现、确定其根本原因和修复的 bug。我们将在下一章中涵盖一些非常强大的内容，以帮助你解决这个问题，在*内核中的锁调试*部分；一定要阅读！）

+   **例外**：在以下情况下，你是安全的（隐式地，没有显式保护）：

+   当你在处理局部变量时。它们分配在线程的私有堆栈上（或者，在中断上下文中，分配在本地 IRQ 堆栈上），因此，根据定义，是安全的。

+   当你在代码中处理共享可写数据时，这段代码不可能在另一个上下文中运行；也就是说，它是串行化的。在我们的情况下，LKM 的*init*和*cleanup*方法符合条件（它们仅在`insmod`和`rmmod`上一次串行运行）。

+   当你在处理真正常量和只读的共享数据时（不要让 C 的`const`关键字误导你）。

+   锁定本质上是复杂的；你必须仔细思考、设计和实现，以避免*死锁*。我们将在*锁定指南和死锁*部分中更详细地介绍这一点。

# Linux 内核中的并发性问题

在内核代码中识别临界区至关重要；如果你甚至看不到它，你怎么保护它呢？以下是一些建议，可以帮助你作为一个新手内核/驱动程序开发人员，识别并发性问题的地方 - 因此可能出现临界区的地方：

+   **对称多处理器**（**SMP**）系统的存在（`CONFIG_SMP`）

+   可抢占内核的存在

+   阻塞 I/O

+   硬件中断（在 SMP 或 UP 系统上）

这些都是需要理解的关键点，我们将在本节中讨论每一个。

## 多核 SMP 系统和数据竞争

第一个点是非常明显的；看一下以下截图中显示的伪代码：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/79357d73-c814-478c-b463-1951621f15e2.png)

图 6.5 - 伪代码 - 在（虚构的）驱动程序读取方法中的一个关键部分；由于没有锁定，这是错误的

这与我们在*图 6.1*和*6.3*中展示的情况类似；只是这里，我们用伪代码来展示并发。显然，从时间`t2`到时间`t3`，驱动程序正在处理一些全局共享的可写数据，因此这是一个关键部分。

现在，想象一个具有四个 CPU 核心（SMP 系统）的系统；两个用户空间进程，P1（运行在 CPU 0 上）和 P2（运行在 CPU 2 上），可以同时打开设备文件并同时发出`read(2)`系统调用。现在，两个进程将同时执行驱动程序的读取“方法”，因此同时处理共享的可写数据！这（在`t2`和`t3`之间的代码）是一个关键部分，由于我们违反了基本的排他性规则 - 关键部分必须由单个线程在任何时间点执行 - 我们很可能会破坏数据、应用程序，甚至更糟。

换句话说，这现在是一个**数据竞争**；取决于微妙的时间巧合，我们可能会或可能不会产生错误（bug）。这种不确定性 - 微妙的时间巧合 - 正是使得像这样找到和修复错误变得极其困难的原因（它可能逃脱了您的测试努力）。

这句格言太不幸地是真的：*测试可以检测到错误的存在，但不能检测到它们的缺失。*更糟糕的是，如果您的测试未能捕捉到竞争（和错误），那么它们将在现场自由发挥。

您可能会觉得，由于您的产品是运行在单个 CPU 核心（UP）上的小型嵌入式系统，因此关于控制并发性（通常通过锁定）的讨论对您不适用。我们不这么认为：几乎所有现代产品，如果尚未，都将转向多核（也许是在它们的下一代阶段）。更重要的是，即使是 UP 系统也存在并发性问题，我们将在接下来的部分中探讨。

## 可抢占内核，阻塞 I/O 和数据竞争

想象一下，您正在运行配置为可抢占的 Linux 内核的内核模块或驱动程序（即`CONFIG_PREEMPT`已打开；我们在配套指南*Linux 内核编程*的*第十章* *CPU 调度器-第一部分*中涵盖了这个主题）。考虑一个进程 P1，在进程上下文中运行驱动程序的读取方法代码，正在处理全局数组。现在，在关键部分内（在时间`t2`和`t3`之间），如果内核*抢占*了进程 P1 并上下文切换到另一个进程 P2，后者正好在等待执行这个代码路径？这是危险的，同样是数据竞争。这甚至可能发生在 UP 系统上！

另一个有些类似的情景（同样，可能发生在单核（UP）或多核系统上）：进程 P1 正在通过驱动程序方法的关键部分运行（在时间`t2`和`t3`之间；再次参见*图 6.5*）。这一次，如果在关键部分中遇到了阻塞调用呢？

**阻塞调用**是一个导致调用进程上下文进入休眠状态，等待事件发生的函数；当事件发生时，内核将“唤醒”任务，并从上次中断的地方恢复执行。这也被称为 I/O 阻塞，非常常见；许多 API（包括几个用户空间库和系统调用，以及几个内核 API）天生就是阻塞的。在这种情况下，进程 P1 实际上是从 CPU 上上下文切换并进入休眠状态，这意味着`schedule()`的代码运行并将其排队到等待队列。

在 P1 被切换回来之前，如果另一个进程 P2 被调度运行怎么办？如果该进程也在运行这个特定的代码路径怎么办？想一想-当 P1 回来时，共享数据可能已经在“它下面”发生了变化，导致各种错误；再次，数据竞争，一个错误！

## 硬件中断和数据竞争

最后，设想这种情况：进程 P1 再次无辜地运行驱动程序的读取方法代码；它进入了临界区（在时间`t2`和`t3`之间；再次参见*图 6.5*）。它取得了一些进展，但然后，哎呀，硬件中断触发了（在同一个 CPU 上）！在 Linux 操作系统上，硬件（外围）中断具有最高优先级；它们默认情况下会抢占任何代码（包括内核代码）。因此，进程（或线程）P1 将至少暂时被搁置，从而失去处理器；中断处理代码将抢占它并运行。

你可能会想，那又怎样呢？确实，这是一个非常普遍的情况！在现代系统上，硬件中断非常频繁地触发，有效地（字面上）中断了各种任务上下文（在你的 shell 上快速执行`vmstat 3`；`system`标签下的列显示了你的系统在过去 1 秒内触发的硬件中断的数量！）。要问的关键问题是：中断处理代码（无论是硬中断的顶半部分还是所谓的任务 let 或软中断的底半部分，无论哪个发生了），*是否共享并处理了它刚刚中断的进程上下文的相同共享可写数据？*

如果这是真的，那么，*休斯顿，我们有一个问题*-数据竞争！如果不是，那么你中断的代码对于中断代码路径来说不是一个临界区，那就没问题。事实上，大多数设备驱动程序确实处理中断；因此，驱动程序作者（你！）有责任确保没有全局或静态数据-实际上，没有临界区-在进程上下文和中断代码路径之间共享。如果有（这确实会发生），你必须以某种方式保护这些数据，以防数据竞争和可能的损坏。

这些情景可能会让你觉得，在面对这些并发问题时保护数据安全是一个非常艰巨的任务；你究竟如何在存在临界区的情况下确保数据安全，以及各种可能的并发问题？有趣的是，实际的 API 并不难学习使用；我们再次强调**识别临界区**是关键。

关于锁（概念上）的工作原理，锁定指南（非常重要；我们很快会对它们进行总结），以及死锁的类型和如何预防死锁，都在我早期的书籍《Linux 系统编程实践（Packt，2018 年 10 月）》中有所涉及。这本书在第十五章“使用 Pthreads 进行多线程编程第二部分-同步”中详细介绍了这些要点。

话不多说，让我们深入探讨主要的同步技术，以保护我们的临界区-锁定。

## 锁定指南和死锁

锁定本质上是一个复杂的问题；它往往会引发复杂的交叉锁定场景。不充分理解它可能会导致性能问题和错误-死锁、循环依赖、中断不安全的锁定等。以下锁定指南对确保使用锁定时编写正确的代码至关重要：

+   **锁定粒度**：锁定和解锁之间的“距离”（实际上是临界区的长度）不应该是粗粒度的（临界区太长），它应该是“足够细”; 这是什么意思？下面的要点解释了这一点：

+   在这里你需要小心。在处理大型项目时，保持过少的锁是一个问题，保持过多的锁也是一个问题！过少的锁可能会导致性能问题（因为相同的锁被重复使用，因此很容易受到高度争用）。

+   拥有大量锁实际上对性能有好处，但对复杂性控制不利。这也导致另一个关键点的理解：在代码库中有许多锁时，您应该非常清楚哪个锁保护哪个共享数据对象。如果您在代码路径中使用，例如`lockA`来保护`mystructX`，但在远处的代码路径（也许是中断处理程序）中忘记了这一点，并尝试在相同的结构上使用其他锁，`lockB`来保护！现在这些事情可能听起来很明显，但（有经验的开发人员知道），在足够的压力下，即使明显的事情也不总是明显的！

+   尝试平衡事物。在大型项目中，使用一个锁来保护一个全局（共享）数据结构是典型的。(*命名*好锁变量本身可能成为一个大问题！这就是为什么我们将保护数据结构的锁放在其中作为成员。)

+   **锁定顺序**至关重要；**锁必须以相同的顺序获取**，并且其顺序应该由所有参与项目开发的开发人员记录和遵循（注释锁也很有用；在下一章节关于*lockdep*的部分中会更多介绍）。不正确的锁定顺序经常导致死锁。

+   尽量避免递归锁定。

+   注意防止饥饿；验证一旦获取锁，确实会“足够快”释放。

+   **简单是关键**：尽量避免复杂性或过度设计，特别是涉及锁的复杂情况。

在锁定的话题上，（危险的）死锁问题出现了。**死锁**是无法取得任何进展；换句话说，应用程序和/或内核组件似乎无限期地挂起。虽然我们不打算在这里深入研究死锁的可怕细节，但我会快速提到一些可能发生的常见死锁情况类型：

+   简单情况，单个锁，进程上下文：

+   我们尝试两次获取相同的锁；这会导致**自死锁**。

+   简单情况，多个（两个或更多）锁，进程上下文 - 一个例子：

+   在 CPU `0`上，线程 A 获取锁 A，然后想要获取锁 B。

+   同时，在 CPU `1`上，线程 B 获取锁 B，然后想要获取锁 A。

+   结果是死锁，通常称为**AB-BA** **死锁**。

+   它可以被扩展；例如，AB-BC-CA **循环依赖**（A-B-C 锁链）会导致死锁。

+   复杂情况，单个锁，进程和中断上下文：

+   锁 A 在中断上下文中获取。

+   如果发生中断（在另一个核心上），并且处理程序试图获取锁 A，会发生死锁！因此，在中断上下文中获取的锁必须始终与中断禁用一起使用。（如何？当我们涵盖自旋锁时，我们将更详细地讨论这个问题。）

+   更复杂的情况，多个锁，进程和中断（硬中断和软中断）上下文

在更简单的情况下，始终遵循*锁定顺序指南*就足够了：始终以有记录的顺序获取和释放锁（我们将在内核代码中的*使用互斥锁*部分提供一个示例）。然而，这可能变得非常复杂；复杂的死锁情况甚至会让经验丰富的开发人员感到困惑。幸运的是，***lockdep*** - Linux 内核的运行时锁依赖验证器 - 可以捕捉每一个死锁情况！（不用担心 - 我们会到那里的：我们将在下一章节详细介绍 lockdep）。当我们涵盖自旋锁（*使用自旋锁*部分）时，我们将遇到类似于先前提到的进程和/或中断上下文情况；在那里明确了要使用的自旋锁类型。

关于死锁，Steve Rostedt 在 2011 年的 Linux Plumber's Conference 上对 lockdep 进行了非常详细的介绍；相关幻灯片内容丰富，探讨了简单和复杂的死锁场景，以及 lockdep 如何检测它们（[`blog.linuxplumbersconf.org/2011/ocw/sessions/153`](https://blog.linuxplumbersconf.org/2011/ocw/sessions/153)）。

另外，现实情况是，不仅是死锁，甚至**活锁**情况也可能同样致命！活锁本质上是一种类似于死锁的情况；只是参与任务的状态是运行而不是等待。例如，中断“风暴”可能导致活锁；现代网络驱动程序通过关闭中断（在中断负载下）并采用一种称为**新 API；切换中断**（**NAPI**）的轮询技术来减轻这种效应（在适当时重新打开中断；好吧，实际情况比这更复杂，但我们就到此为止）。

对于那些生活在石头下的人，你会知道 Linux 内核有两种主要类型的锁：互斥锁和自旋锁。实际上，还有几种类型，包括其他同步（和“无锁”编程）技术，所有这些都将在本章和下一章中涵盖。

# 互斥锁还是自旋锁？在何时使用

学习使用互斥锁和自旋锁的确切语义非常简单（在内核 API 集中有适当的抽象，使得对于典型的驱动程序开发人员或模块作者来说更容易）。在这种情况下的关键问题是一个概念性的问题：两种锁之间的真正区别是什么？更重要的是，在什么情况下应该使用哪种锁？你将在本节中找到这些问题的答案。

以前的驱动程序读取方法的伪代码（*图 6.5*）作为基本示例，假设三个线程 - **tA**，**tB**和**tC** - 在并行运行（在 SMP 系统上）通过这段代码。我们将通过在关键部分开始之前获取锁或获取锁来解决这个并发问题，同时避免任何数据竞争，并在关键部分代码路径结束后释放锁（解锁）（时间**t3**）。让我们再次看一下伪代码，这次使用锁定以确保它是正确的：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/a0db53d6-0c64-4377-90a2-bdb95a2fab16.png)

图 6.6 - 伪代码 - 驱动程序读取方法中的关键部分；正确，带锁

当三个线程尝试同时获取锁时，系统保证只有一个线程会获得它。假设**tB**（线程 B）获得了锁：现在它是“获胜者”或“所有者”线程。这意味着线程**tA**和**tC**是“失败者”；他们会等待解锁！一旦“获胜者”（**tB**）完成关键部分并解锁锁，之前的失败者之间的战斗就会重新开始；其中一个将成为下一个获胜者，进程重复。

两种锁类型之间的关键区别 - 互斥锁和自旋锁 - 基于失败者等待解锁的方式。使用互斥锁，失败者线程会进入睡眠；也就是说，它们通过睡眠等待。一旦获胜者执行解锁，内核就会唤醒失败者（所有失败者）并重新运行，再次竞争锁。（事实上，互斥锁和信号量有时被称为睡眠锁。）

然而，使用**自旋锁**，没有睡眠的问题；失败者会在锁上自旋等待，直到它被解锁。从概念上看，情况如下：

```
while (locked) ;
```

请注意，这仅仅是*概念性的*。想一想——这实际上是轮询。然而，作为一个优秀的程序员，你会明白，轮询通常被认为是一个不好的主意。那么，自旋锁为什么会这样工作呢？嗯，它并不是这样的；它只是以这种方式呈现出来是为了概念上的目的。正如你很快会明白的，自旋锁只在多核（SMP）系统上才有意义。在这样的系统上，当获胜的线程离开并运行关键部分的代码时，失败者会在其他 CPU 核上旋转等待！实际上，在实现层面，用于实现现代自旋锁的代码是高度优化的（并且特定于体系结构），并不是通过简单地“自旋”来工作（例如，许多 ARM 的自旋锁实现使用**等待事件**（**WFE**）机器语言指令，这使得 CPU 在低功耗状态下等待；请参阅*进一步阅读*部分，了解有关自旋锁内部实现的几个资源）。

## 在理论上确定使用哪种锁

自旋锁的实现方式实际上并不是我们关心的重点；自旋锁的开销比互斥锁更低对我们来说是有兴趣的。为什么呢？实际上很简单：为了使互斥锁工作，失败者线程必须休眠。为了做到这一点，内部调用了`schedule()`函数，这意味着失败者将互斥锁 API 视为一个阻塞调用！对调度程序的调用最终将导致处理器被上下文切换。相反，当所有者线程解锁锁时，失败者线程必须被唤醒；同样，它将被上下文切换回处理器。因此，互斥锁/解锁操作的最小“成本”是在给定机器上执行两次上下文切换所需的时间。（请参阅下一节中的*信息框*。）通过再次查看前面的屏幕截图，我们可以确定一些事情，包括在关键部分中花费的时间（“锁定”代码路径）；即，`t_locked = t3 - t2`。

假设`t_ctxsw`代表上下文切换的时间。正如我们所了解的，互斥锁/解锁操作的最小成本是`2 * t_ctxsw`。现在，假设以下表达式为真：

```
t_locked < 2 * t_ctxsw
```

换句话说，如果在关键部分内花费的时间少于两次上下文切换所需的时间，那么使用互斥锁就是错误的，因为这会带来太多的开销；执行元工作的时间比实际工作的时间更多——这种现象被称为**抖动**。这种精确的用例——非常短的关键部分的存在——在现代操作系统（如 Linux）中经常出现。因此，总的来说，对于短的非阻塞关键部分，使用自旋锁（远远）优于使用互斥锁。

## 在实践中确定使用哪种锁

因此，在“`t_locked < 2 * t_ctxsw`”的“规则”下运行在理论上可能很好，但是等等：你真的期望精确地测量每种情况下关键部分的上下文切换时间和花费的时间吗？当然不是——那是相当不现实和迂腐的。

从实际角度来看，可以这样理解：互斥锁通过在解锁时使失败者线程休眠来工作；自旋锁不会（失败者“自旋”）。让我们回顾一下 Linux 内核的一个黄金规则：内核不能在任何类型的原子上下文中休眠（调用`schedule()`）。因此，我们永远不能在中断上下文中使用互斥锁，或者在任何不安全休眠的上下文中使用；然而，使用自旋锁是可以的。让我们总结一下：

+   **关键部分是在原子（中断）上下文中运行，还是在进程上下文中运行，无法休眠？** 使用自旋锁。

+   **关键部分是在进程上下文中运行，且在关键部分中需要休眠？** 使用互斥锁。

当然，使用自旋锁的开销比使用互斥锁的开销要低；因此，您甚至可以在进程上下文中使用自旋锁（例如我们虚构的驱动程序的读取方法），只要关键部分不会阻塞（休眠）。

**[1]** 上下文切换所需的时间是不同的；这在很大程度上取决于硬件和操作系统的质量。最近（2018 年 9 月）的测量结果显示，在固定的 CPU 上，上下文切换时间在 1.2 到 1.5**us**（**微秒**）左右，在没有固定的情况下大约为 2.2 微秒（[`eli.thegreenplace.net/2018/measuring-context-switching-and-memory-overheads-for-linux-threads/`](https://eli.thegreenplace.net/2018/measuring-context-switching-and-memory-overheads-for-linux-threads/)）。

硬件和 Linux 操作系统都有了巨大的改进，因此平均上下文切换时间也有所改善。一篇旧的（1998 年 12 月）Linux Journal 文章确定，在 x86 类系统上，平均上下文切换时间为 19 微秒（微秒），最坏情况下为 30 微秒。

这带来了一个问题，我们如何知道代码当前是在进程上下文还是中断上下文中运行？很简单：我们的`PRINT_CTX()`宏（在我们的`convenient.h`头文件中）可以显示这一点：

```
if (in_task())
    /* we're in process context (usually safe to sleep / block) */
else
    /* we're in an atomic or interrupt context (cannot sleep / block) */
```

现在您了解了何时使用互斥锁或自旋锁，让我们进入实际用法。我们将从如何使用互斥锁开始！

# 使用互斥锁

如果关键部分可以休眠（阻塞），则互斥锁也称为可休眠或阻塞互斥排他锁。它们必须不在任何类型的原子或中断上下文（顶半部，底半部，如 tasklets 或 softirqs 等），内核定时器，甚至不允许阻塞的进程上下文中使用。

## 初始化互斥锁

互斥锁“对象”在内核中表示为`struct mutex`数据结构。考虑以下代码：

```
#include <linux/mutex.h>
struct mutex mymtx;
```

要使用互斥锁，*必须*将其显式初始化为未锁定状态。可以使用`DEFINE_MUTEX()`宏静态地（声明并初始化对象）进行初始化，也可以通过`mutex_init()`函数动态进行初始化（这实际上是对`__mutex_init()`函数的宏包装）。

例如，要声明并初始化名为`mymtx`的互斥锁对象，我们可以使用`DEFINE_MUTEX(mymtx);`。

我们也可以动态地执行此操作。为什么要动态执行？通常，互斥锁是它所保护的（全局）数据结构的成员（聪明！）。例如，假设我们在驱动程序代码中有以下全局上下文结构（请注意，此代码是虚构的）：

```
struct mydrv_priv {
    <member 1>
    <member 2>
    [...]
    struct mutex mymtx; /* protects access to mydrv_priv */
    [...]
};
```

然后，在您的驱动程序（或 LKM）的`init`方法中，执行以下操作：

```
static int init_mydrv(struct mydrv_priv *drvctx)
{
    [...]
    mutex_init(drvctx-mymtx);
    [...]
}
```

将锁变量作为（父）数据结构的成员保护是 Linux 中常用的（聪明）模式；这种方法还有一个额外的好处，即避免命名空间污染，并且清楚地说明哪个互斥锁保护哪个共享数据项（这可能是一个比起初看起来更大的问题，尤其是在像 Linux 内核这样的庞大项目中！）。

将保护全局或共享数据结构的锁作为该数据结构的成员。

## 正确使用互斥锁

通常，您可以在内核源树中找到非常有见地的注释。这里有一个很好的总结了您必须遵循的规则以正确使用互斥锁的注释；请仔细阅读：

```
// include/linux/mutex.h
/*
 * Simple, straightforward mutexes with strict semantics:
 *
 * - only one task can hold the mutex at a time
 * - only the owner can unlock the mutex
 * - multiple unlocks are not permitted
 * - recursive locking is not permitted
 * - a mutex object must be initialized via the API
 * - a mutex object must not be initialized via memset or copying
 * - task may not exit with mutex held
 * - memory areas where held locks reside must not be freed
 * - held mutexes must not be reinitialized
 * - mutexes may not be used in hardware or software interrupt
 * contexts such as tasklets and timers
 *
 * These semantics are fully enforced when DEBUG_MUTEXES is
 * enabled. Furthermore, besides enforcing the above rules, the mutex
 * [ ... ]
```

作为内核开发人员，您必须了解以下内容：

+   关键部分导致代码路径*被串行化，破坏了并行性*。因此，至关重要的是尽量保持关键部分的时间尽可能短。与此相关的是**锁定数据，而不是代码**。

+   尝试重新获取已经获取（锁定）的互斥锁 - 这实际上是递归锁定 - 是*不*支持的，并且会导致自死锁。

+   **锁定顺序**：这是防止危险死锁情况的一个非常重要的经验法则。在存在多个线程和多个锁的情况下，关键的是*记录锁被获取的顺序，并且所有参与项目开发的开发人员都严格遵循*。实际的锁定顺序本身并不是不可侵犯的，但一旦决定了，就必须遵循。在浏览内核源代码时，您会发现许多地方，内核开发人员确保这样做，并且（通常）为其他开发人员编写注释以便查看和遵循。这是来自 slab 分配器代码（`mm/slub.c`）的一个示例注释：

```
/*
 * Lock order:
 * 1\. slab_mutex (Global Mutex)
 * 2\. node-list_lock
 * 3\. slab_lock(page) (Only on some arches and for debugging)
```

现在我们从概念上理解了互斥锁的工作原理（并且了解了它们的初始化），让我们学习如何使用锁定/解锁 API。

## 互斥锁定和解锁 API 及其用法

互斥锁的实际锁定和解锁 API 如下。以下代码分别显示了如何锁定和解锁互斥锁：

```
void __sched mutex_lock(struct mutex *lock);
void __sched mutex_unlock(struct mutex *lock);
```

（这里忽略`__sched`；这只是一个编译器属性，使得这个函数在`WCHAN`输出中消失，在 procfs 中显示，并且在`ps(1)`的某些选项开关（如`-l`）中显示）。

同样，在`kernel/locking/mutex.c`中的源代码中的注释非常详细和描述性；我鼓励您更详细地查看这个文件。我们在这里只显示了其中的一些代码，这些代码直接来自 5.4 Linux 内核源代码树：

```
// kernel/locking/mutex.c
[ ... ]
/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * (The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 * checks that will enforce the restrictions and will also do
 * deadlock debugging)
 *
 * This function is similar to (but not equivalent to) down().
 */
void __sched mutex_lock(struct mutex *lock)
{
    might_sleep();

    if (!__mutex_trylock_fast(lock))
        __mutex_lock_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock);
```

`might_sleep()`是一个具有有趣调试属性的宏；它捕捉到了本应在原子上下文中执行但实际上没有执行的代码！所以，请思考一下：`might_sleep()`是`mutex_lock()`中的第一行代码，这意味着这段代码路径不应该被任何处于原子上下文中的东西执行，因为它可能会睡眠。这意味着只有在安全睡眠时才应该在进程上下文中使用互斥锁！

**一个快速而重要的提醒**：Linux 内核可以配置大量的调试选项；在这种情况下，`CONFIG_DEBUG_MUTEXES`配置选项将帮助您捕捉可能的与互斥锁相关的错误，包括死锁。同样，在 Kernel Hacking 菜单下，您将找到大量与调试相关的内核配置选项。我们在配套指南*Linux Kernel Programming - Chapter 5*，*Writing Your First Kernel Module – LKMs Part 2*中讨论了这一点。关于锁调试，有几个非常有用的内核配置，我们将在下一章中介绍，在*内核中的锁调试*部分。

### 互斥锁 - 通过[不]可中断的睡眠？

和往常一样，互斥锁比我们迄今所见到的更复杂。您已经知道 Linux 进程（或线程）在状态机的各种状态之间循环。在 Linux 上，睡眠有两种离散状态 - 可中断睡眠和不可中断睡眠。处于可中断睡眠状态的进程（或线程）是敏感的，这意味着它将响应用户空间信号，而处于不可中断睡眠状态的任务对用户信号不敏感。

在具有底层驱动程序的人机交互应用程序中，通常的经验法则是，您应该将一个进程放入可中断的睡眠状态（当它在锁上阻塞时），这样就由最终用户决定是否通过按下*Ctrl* + *C*（或某种涉及信号的机制）来中止应用程序。在类 Unix 系统上通常遵循的设计规则是：**提供机制，而不是策略**。话虽如此，在非交互式代码路径上，通常情况下，您必须等待锁来无限期地等待，语义上，已传递给任务的信号不应中止阻塞等待。在 Linux 上，不可中断的情况是最常见的情况。

因此，这里的问题是：`mutex_lock()` API 总是将调用任务置于不可中断的睡眠状态。如果这不是你想要的，使用`mutex_lock_interruptible()` API 将调用任务置于可中断的睡眠状态。在语法上有一个不同之处；后者在成功时返回整数值`0`，在失败时返回`-EINTR`（记住`0`/`-E`返回约定）（由于信号中断）。

一般来说，使用`mutex_lock()`比使用`mutex_lock_interruptible()`更快；当临界区很短时使用它（因此几乎可以保证锁定时间很短，这是一个非常理想的特性）。

5.4.0 内核包含超过 18,500 个`mutex_lock()`和 800 多个`mutex_lock_interruptible()` API 的调用实例；你可以通过内核源树上强大的`cscope(1)`实用程序来检查这一点。

理论上，内核提供了`mutex_destroy()` API。这是`mutex_init()`的相反操作；它的工作是将互斥锁标记为不可用。只有在互斥锁处于未锁定状态时才能调用它，一旦调用，互斥锁就不能再使用。这有点理论性，因为在常规系统上，它只是一个空函数；只有在启用了`CONFIG_DEBUG_MUTEXES`的内核上，它才变成实际的（简单的）代码。因此，当使用互斥锁时，我们应该使用这种模式，如下面的伪代码所示：

```
DEFINE_MUTEX(...);        // init: initialize the mutex object
/* or */ mutex_init();
[ ... ]
    /* critical section: perform the (mutex) locking, unlocking */
    mutex_lock[_interruptible]();
    << ... critical section ... >>
    mutex_unlock();
    mutex_destroy();      // cleanup: destroy the mutex object
```

现在你已经学会了如何使用互斥锁 API，让我们把这些知识付诸实践。在下一节中，我们将在之前的一个（编写不好 - 没有保护！）“misc”驱动程序的基础上，通过使用互斥对象来锁定必要的临界区来构建。

## 互斥锁定 - 一个示例驱动程序

我们在*第一章* - *编写一个简单的 misc 字符设备驱动程序*中创建了一个简单的设备驱动程序示例，即`ch1/miscdrv_rdwr`。在那里，我们编写了一个简单的`misc`类字符设备驱动程序，并使用了一个用户空间实用程序（`ch12/miscdrv_rdwr/rdwr_drv_secret.c`）来从设备驱动程序的内存中读取和写入一个（所谓的）秘密。

然而，在那段代码中，我们明显（egregiously 是正确的词！）未能保护共享（全局）可写数据！这在现实世界中会让我们付出昂贵的代价。我敦促你花些时间考虑一下：两个（或三个或更多）用户模式进程打开该驱动程序的设备文件，然后同时发出各种 I/O 读写是不可行的。在这里，全局共享可写数据（在这种特殊情况下，两个全局整数和驱动程序上下文数据结构）很容易被破坏。

因此，让我们从错误中吸取教训，并通过复制这个驱动程序（我们现在将其称为`ch12/1_miscdrv_rdwr_mutexlock/1_miscdrv_rdwr_mutexlock.c`）并重写其中的一些部分来纠正错误。关键点是我们必须使用互斥锁来保护所有关键部分。而不是在这里显示代码（毕竟，它在这本书的 GitHub 存储库中[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)，请使用`git clone`！），让我们做一些有趣的事情：让我们看一下旧的未受保护版本和新的受保护代码版本之间的“diff”（`diff(1)`生成的差异 - ）的输出在这里已经被截断：

```
$ pwd
<.../ch12/1_miscdrv_rdwr_mutexlock
$ diff -u ../../ch12/miscdrv_rdwr/miscdrv_rdwr.c miscdrv_rdwr_mutexlock.c>> miscdrv_rdwr.patch
$ cat miscdrv_rdwr.patch
[ ... ]
+#include <linux/mutex.h> // mutex lock, unlock, etc
 #include "../../convenient.h"
[ ... ] 
-#define OURMODNAME "miscdrv_rdwr"
+#define OURMODNAME "miscdrv_rdwr_mutexlock"

+DEFINE_MUTEX(lock1); // this mutex lock is meant to protect the integers ga and gb
[ ... ]
+     struct mutex lock; // this mutex protects this data structure
 };
[ ... ]
```

在这里，我们可以看到在驱动程序的更新的安全版本中，我们声明并初始化了一个名为`lock1`的互斥变量；我们将用它来保护（仅用于演示目的）驱动程序中的两个全局整数`ga`和`gb`。接下来，重要的是，在“驱动程序上下文”数据结构`drv_ctx`中声明了一个名为`lock`的互斥锁；这将用于保护对该数据结构成员的任何访问。它在`init`代码中初始化：

```
+     mutex_init(&ctx->lock);
+
+     /* Initialize the "secret" value :-) */
      strscpy(ctx->oursecret, "initmsg", 8);
-     dev_dbg(ctx->dev, "A sample print via the dev_dbg(): driver initialized\n");
+     /* Why don't we protect the above strscpy() with the mutex lock?
+      * It's working on shared writable data, yes?
+      * Yes, BUT this is the init code; it's guaranteed to run in exactly
+      * one context (typically the insmod(8) process), thus there is
+      * no concurrency possible here. The same goes for the cleanup
+      * code path.
+      */
```

这个详细的注释清楚地解释了为什么我们不需要在`strscpy()`周围进行锁定/解锁。再次强调，这应该是显而易见的，但是局部变量隐式地对每个进程上下文都是私有的（因为它们驻留在该进程或线程的内核模式堆栈中），因此不需要保护（每个线程/进程都有一个变量的单独*实例*，所以没有人会干涉别人的工作！）。在我们忘记之前，*清理*代码路径（通过`rmmod(8)`进程上下文调用）必须销毁互斥锁：

```
-static void __exit miscdrv_rdwr_exit(void)
+static void __exit miscdrv_exit_mutexlock(void)
 {
+     mutex_destroy(&lock1);
+     mutex_destroy(&ctx->lock);
      misc_deregister(&llkd_miscdev);
 }
```

现在，让我们看一下驱动程序的打开方法的差异：

```
+
+     mutex_lock(&lock1);
+     ga++; gb--;
+     mutex_unlock(&lock1);
+
+     dev_info(dev, " filename: \"%s\"\n"
      [ ... ]
```

这是我们操纵全局整数的地方，*使其成为关键部分*；与程序的先前版本不同，在这里，我们使用`lock1`互斥锁*保护这个关键部分*。所以，关键部分就是这里的代码`ga++; gb--;`：在（互斥）锁定和解锁操作之间的代码。

但是（总是有一个但是，不是吗？），一切并不顺利！看一下`mutex_unlock()`代码行后面的`printk`函数（`dev_info()`）：

```
+ dev_info(dev, " filename: \"%s\"\n"
+         " wrt open file: f_flags = 0x%x\n"
+         " ga = %d, gb = %d\n",
+         filp->f_path.dentry->d_iname, filp->f_flags, ga, gb);
```

这对你来说看起来还好吗？不，仔细看：我们正在*读取*全局整数`ga`和`gb`的值。回想一下基本原理：在并发存在的情况下（在这个驱动程序的*打开*方法中肯定是可能的），*即使没有锁定，读取共享可写数据也可能是不安全的*。如果这对你来说没有意义，请想一想：如果一个线程正在读取整数，同时另一个线程正在更新（写入）它们；那么呢？这种情况被称为**脏读**（或**断裂读**）；我们可能会读取过时的数据，必须加以保护。（事实上，这并不是一个真正的脏读的很好的例子，因为在大多数处理器上，读取和写入单个整数项目确实 tend to be an atomic operation。然而，我们不应该假设这样的事情 - 我们只需要做好我们的工作并保护它。）

实际上，还有另一个类似的潜在错误：我们从打开文件结构（`filp`指针）中读取数据而没有进行保护（的确，打开文件结构有一个锁；我们应该使用它！我们以后会这样做）。

诸如*脏读*之类的事情发生的具体语义通常非常依赖于体系结构（机器），然而，我们作为模块或驱动程序的作者的工作是清楚的：我们必须确保保护所有关键部分。这包括对共享可写数据的读取。

目前，我们将把这些标记为潜在的错误（bug）。我们将在*使用原子整数操作符*部分以更加性能友好的方式处理这个问题。查看驱动程序的读取方法的差异会发现一些有趣的东西（忽略这里显示的行号；它们可能会改变）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/ad26b085-7d4a-4090-96b8-44aef98664ce.png)

图 6.7 - 驱动程序的 read()方法的差异；查看新版本中互斥锁的使用

我们现在使用驱动程序上下文结构的互斥锁来保护关键部分。对于设备驱动程序的*写*和*关闭*（释放）方法也是一样的（生成补丁并查看）。

请注意用户模式应用程序保持不变，这意味着为了测试新的更安全的版本，我们必须继续使用用户模式应用程序`ch12/miscdrv_rdwr/rdwr_drv_secret.c`。在调试内核上运行和测试此驱动程序代码，其中包含各种锁定错误和死锁检测功能，这是至关重要的（我们将在下一章中返回到这些“调试”功能，在*内核中的锁调试*部分）。

在前面的代码中，我们在`copy_to_user()`例程之前获取了互斥锁；这很好。然而，我们只在`dev_info()`之后释放它。为什么不在这个`printk`之前释放它，从而缩短关键部分的时间？

仔细观察`dev_info()`，可以看出为什么它*在*关键部分。我们在这里打印了三个变量的值：`secret_len`读取的字节数，以及`ctx->tx`和`ctx->rx`分别“传输”和“接收”的字节数。`secret_len`是一个局部变量，不需要保护，但另外两个变量在全局驱动程序上下文结构中，因此需要保护，即使是（可能是脏的）读取也需要。

## 互斥锁 - 一些剩余的要点

在本节中，我们将涵盖有关互斥锁的一些其他要点。

### 互斥锁 API 变体

首先，让我们看一下互斥锁 API 的几个变体；除了可中断变体（在*互斥锁 - 通过[不]可中断睡眠？*部分中描述），我们还有*trylock，可杀死*和*io*变体。

#### 互斥 trylock 变体

如果你想实现一个**忙等待**语义；也就是说，测试（互斥）锁的可用性，如果可用（意味着当前未锁定），则获取/锁定它并继续关键部分代码路径？如果不可用（当前处于锁定状态），则不等待锁；而是执行其他工作并重试。实际上，这是一个非阻塞的互斥锁变体，称为 trylock；以下流程图显示了它的工作原理：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/421daaad-97a1-4acc-8cfc-e4d33751eb84.png)

图 6.8 - “忙等待”语义，一个非阻塞的 trylock 操作

这个互斥锁的 trylock 变体的 API 如下：

```
int mutex_trylock(struct mutex *lock);
```

这个 API 的返回值表示了运行时发生了什么：

+   返回值`1`表示成功获取了锁。

+   返回值`0`表示当前争用（已锁定）。

尽管尝试使用`mutex_trylock()` API 来确定互斥锁是处于锁定还是未锁定状态可能听起来很诱人，但*不要*尝试这样做，因为这本质上是“竞争的”。另外，要注意，在高度竞争的锁路径中使用这个 trylock 变体可能会降低你获取锁的机会。trylock 变体传统上用于死锁预防代码，可能需要退出某个锁定顺序序列并通过另一个序列（顺序）重试。

另外，关于 trylock 变体，尽管文献中使用了术语*尝试原子地获取互斥锁*，但它不适用于原子或中断上下文——它*只*适用于进程上下文（与任何类型的互斥锁一样）。通常情况下，锁必须由拥有者上下文调用的`mutex_unlock()`来释放。

我建议你尝试作为练习使用 trylock 互斥锁变体。请参阅本章末尾的*问题*部分进行作业！

#### 互斥可中断和可杀死变体

正如你已经学到的，当驱动程序（或模块）愿意接受任何（用户空间）信号中断时，会使用`mutex_lock_interruptible()` API（并返回`-ERESTARTSYS`告诉内核 VFS 层执行信号处理；用户空间系统调用将以`errno`设置为`EINTR`失败）。一个例子可以在内核中的模块处理代码中找到，在`delete_module(2)`系统调用中（由`rmmod(8)`调用）：

```
// kernel/module.c
[ ... ]
SYSCALL_DEFINE2(delete_module, const char __user *, name_user,
        unsigned int, flags)
{
    struct module *mod;
    [ ... ]
    if (!capable(CAP_SYS_MODULE) || modules_disabled)
        return -EPERM;
    [ ... ]
    if (mutex_lock_interruptible(&module_mutex) != 0)
 return -EINTR;
    mod = find_module(name);
    [ ... ]
out:
    mutex_unlock(&module_mutex);
    return ret;
}
```

注意 API 在失败时返回`-EINTR`。（`SYSCALL_DEFINEn()`宏成为系统调用签名；`n`表示这个特定系统调用接受的参数数量。还要注意权限检查——除非你以 root 身份运行或具有`CAP_SYS_MODULE`权限（或者模块加载完全被禁用），否则系统调用将返回失败（`-EPERM`）。）

然而，如果你的驱动程序只愿意被致命信号（那些*将杀死*用户空间上下文的信号）中断，那么使用`mutex_lock_killable()` API（签名与可中断变体相同）。

#### 互斥 io 变体

`mutex_lock_io()` API 在语法上与`mutex_lock()` API 相同；唯一的区别是内核认为失败线程的等待时间与等待 I/O 相同（`kernel/locking/mutex.c:mutex_lock_io()`中的代码注释清楚地记录了这一点；看一下）。这在会计方面很重要。

您可以在内核中找到相当奇特的 API，比如`mutex_lock[_interruptible]_nested()`，这里重点是`nested`后缀。但是，请注意，Linux 内核不希望开发人员使用嵌套（或递归）锁定（正如我们在*正确使用互斥锁*一节中提到的）。此外，这些 API 只在存在`CONFIG_DEBUG_LOCK_ALLOC`配置选项时才会被编译；实际上，嵌套 API 是为了支持内核锁验证器机制而添加的。它们只应在特殊情况下使用（在同一类型的锁实例之间必须包含嵌套级别的情况下）。

在下一节中，我们将回答一个典型的常见问题：互斥锁和信号量对象有什么区别？Linux 是否有信号量对象？继续阅读以了解更多！

### 信号量和互斥锁

Linux 内核确实提供了一个信号量对象，以及您可以对（二进制）信号量执行的常规操作：

+   通过`down[_interruptible]()`（和变体）API 获取信号量锁

+   通过`up()` API 解锁信号量。

一般来说，信号量是一种较旧的实现，因此建议您使用互斥锁来代替它。

值得一看的常见问题是：*互斥锁和信号量之间有什么区别？*它们在概念上看起来相似，但实际上是非常不同的。

+   信号量是互斥锁的一种更一般化的形式；互斥锁可以被获取（然后释放或解锁）一次，而信号量可以被获取（然后释放）多次。

+   互斥锁用于保护临界区免受同时访问，而信号量应该被用作一种机制，用于向另一个等待任务发出信号，表明已经达到了某个里程碑（通常，生产者任务通过信号量对象发布信号，等待接收的消费者任务可以继续进行进一步的工作）。

+   互斥锁具有锁的所有权概念，只有所有者上下文才能执行解锁；二进制信号量没有所有权。

### 优先级反转和 RT-互斥锁

在使用任何类型的锁定时需要注意的一点是，您应该仔细设计和编码，以防止可能出现的可怕的*死锁*情况（在*锁验证器 lockdep - 及早捕捉锁定问题*一节中将更多地讨论这一点）。

除了死锁之外，使用互斥锁时还会出现另一种风险情况：优先级反转（在本书中我们不会深入讨论细节）。可以说，无界**优先级反转**情况可能是致命的；最终结果是产品的高（最高）优先级线程被长时间挡在 CPU 之外。

正如我在早期的书籍*使用 Linux 进行系统编程*中详细介绍的那样，正是这种优先级反转问题在 1997 年 7 月击中了 NASA 的火星探路者机器人，而且还是在火星表面！请参阅本章的*进一步阅读*部分，了解有关这一问题的有趣资源，这是每个软件开发人员都应该知道的内容！

用户空间 Pthreads 互斥锁实现当然具有**优先级继承**（**PI**）语义。但在 Linux 内核中呢？对此，Ingo Molnar 提供了基于 PI-futex 的 RT 互斥锁（实时互斥锁；实际上是扩展为具有 PI 功能的互斥锁。`futex(2)`是一个提供快速用户空间互斥锁的复杂系统调用）。当启用`CONFIG_RT_MUTEXES`配置选项时，这些就可用了。与“常规”互斥锁语义非常相似，RT 互斥锁 API 用于初始化、（解）锁定和销毁 RT 互斥锁对象。（此代码已从 Ingo Molnar 的`-rt`树合并到主线内核）。就实际使用而言，RT 互斥锁用于在内部实现 PI futex（`futex(2)`系统调用本身在内部实现了用户空间 Pthreads 互斥锁）。除此之外，内核锁定自测代码和 I2C 子系统直接使用 RT 互斥锁。

因此，对于典型的模块（或驱动程序）作者来说，这些 API 并不经常使用。内核确实提供了一些关于 RT 互斥锁内部设计的文档（涵盖了优先级反转、优先级继承等）。

### 内部设计

关于互斥锁在内核结构深处的内部实现的现实：Linux 在可能的情况下尝试实现*快速路径*方法。

**快速路径**是最优化的高性能代码路径；例如，没有锁和阻塞。目的是让代码尽可能地遵循这条快速路径。只有在真的不可能的情况下，内核才会退回到“中间路径”，然后是“慢路径”；它仍然可以工作，但速度较慢。

在没有锁争用的情况下（即，锁最初处于未锁定状态），会采用这条快速路径。因此，锁会立即被锁定，没有麻烦。然而，如果互斥锁已经被锁定，那么内核通常会使用中间路径的乐观自旋实现，使其更像是混合（互斥锁/自旋锁）锁类型。如果甚至这也不可能，就会遵循“慢路径” – 尝试获取锁的进程上下文可能会进入睡眠状态。如果您对其内部实现感兴趣，可以在官方内核文档中找到更多详细信息。

*LDV（Linux 驱动程序验证）项目：*在伴随指南*Linux 内核编程 - 第一章*，*内核工作空间设置*的*LDV – Linux 驱动程序验证 – 项目*部分中，我们提到该项目对 Linux 模块（主要是驱动程序）以及核心内核的各种编程方面有有用的“规则”。

关于我们当前的主题，这里有一个规则：*两次锁定互斥锁或在先前未锁定的情况下解锁*。它提到了您不能使用互斥锁做的事情（我们已经在*正确使用互斥锁*部分中涵盖了这一点）。有趣的是：您可以看到一个实际的 bug 示例 – 一个互斥锁双重获取尝试，导致（自身）死锁 – 在内核驱动程序中（以及随后的修复）。

现在您已经了解了如何使用互斥锁，让我们继续看看内核中另一个非常常见的锁 – 自旋锁。

# 使用自旋锁

在*互斥锁还是自旋锁？何时使用*部分，您学会了何时使用自旋锁而不是互斥锁，反之亦然。为了方便起见，我们在此重复了我们之前提供的关键声明。

+   **关键部分是在原子（中断）上下文中运行还是在不能睡眠的进程上下文中运行？**使用自旋锁。

+   **关键部分是在进程上下文中运行并且在关键部分中睡眠是必要的吗？**使用互斥锁。

在这一部分，我们假设您现在决定使用自旋锁。

## 自旋锁 - 简单用法

对于所有自旋锁 API，您必须包括相关的头文件；即`include <linux/spinlock.h>`。

与互斥锁类似，您*必须*在使用之前声明和初始化自旋锁为未锁定状态。自旋锁是通过`typedef`数据类型`spinlock_t`（在内部，它是在`include/linux/spinlock_types.h`中定义的结构）声明的“对象”。它可以通过`spin_lock_init()`宏动态初始化：

```
spinlock_t lock;
spin_lock_init(&lock);
```

或者，这可以通过`DEFINE_SPINLOCK(lock);`静态执行（声明和初始化）。

与互斥锁一样，在（全局/静态）数据结构中声明自旋锁是为了防止并发访问，并且通常是一个非常好的主意。正如我们之前提到的，这个想法在内核中经常被使用；例如，表示 Linux 内核上打开文件的数据结构被称为`struct file`：

```
// include/linux/fs.h
struct file {
    [...]
    struct path f_path;
    struct inode *f_inode; /* cached value */
    const struct file_operations *f_op;
    /*
     * Protects f_ep_links, f_flags.
     * Must not be taken from IRQ context.
     */
    spinlock_t f_lock;
    [...]
    struct mutex f_pos_lock;
    loff_t f_pos;
    [...]
```

看一下：对于`file`结构，名为`f_lock`的自旋锁变量是保护`file`数据结构的`f_ep_links`和`f_flags`成员的自旋锁（它还有一个互斥锁来保护另一个成员；即文件的当前寻位位置 - `f_pos`）。

你如何实际上锁定和解锁自旋锁？内核向我们模块/驱动程序作者公开了许多 API 的变体；自旋锁 API 的最简单形式如下：

```
void spin_lock(spinlock_t *lock);
<< ... critical section ... >>
void spin_unlock(spinlock_t *lock);
```

请注意，`mutex_destroy()`API 没有自旋锁的等效 API。

现在，让我们看看自旋锁 API 的实际应用！

## 自旋锁 - 一个示例驱动程序

与我们的互斥锁示例驱动程序（*互斥锁 - 一个示例驱动程序*部分）所做的类似，为了说明自旋锁的简单用法，我们将复制我们之前的`ch12/1_miscdrv_rdwr_mutexlock`驱动程序作为起始模板，然后将其放置在一个新的内核驱动程序中；也就是`ch12/2_miscdrv_rdwr_spinlock`。同样，在这里，我们只会显示差异的小部分（`diff(1)`生成的差异，我们不会显示每一行差异，只显示相关部分）。

```
// location: ch12/2_miscdrv_rdwr_spinlock/
+#include <linux/spinlock.h>
[ ... ]
-#define OURMODNAME "miscdrv_rdwr_mutexlock"
+#define OURMODNAME "miscdrv_rdwr_spinlock"
[ ... ]
static int ga, gb = 1;
-DEFINE_MUTEX(lock1); // this mutex lock is meant to protect the integers ga and gb
+DEFINE_SPINLOCK(lock1); // this spinlock protects the global integers ga and gb
[ ... ]
+/* The driver 'context' data structure;
+ * all relevant 'state info' reg the driver is here.
  */
 struct drv_ctx {
    struct device *dev;
@@ -63,10 +66,22 @@
    u64 config3;
 #define MAXBYTES 128
    char oursecret[MAXBYTES];
- struct mutex lock; // this mutex protects this data structure
+ struct mutex mutex; // this mutex protects this data structure
+ spinlock_t spinlock; // ...so does this spinlock
 };
 static struct drv_ctx *ctx;
```

这一次，为了保护我们的`drv_ctx`全局数据结构的成员，我们既有原始的互斥锁，又有一个新的自旋锁。这是相当常见的；互斥锁用于保护关键部分中可能发生阻塞的成员使用，而自旋锁用于保护关键部分中不会发生阻塞（睡眠 - 请记住它可能会睡眠）的成员。

当然，我们必须确保初始化所有锁，使它们处于未锁定状态。我们可以在驱动程序的`init`代码中执行这个操作（继续使用补丁输出）：

```
-   mutex_init(&ctx->lock);
+   mutex_init(&ctx->mutex);
+   spin_lock_init(&ctx->spinlock);
```

在驱动程序的`open`方法中，我们用自旋锁替换互斥锁来保护全局整数的增量和减量：

```
 * open_miscdrv_rdwr()
@@ -82,14 +97,15 @@

    PRINT_CTX(); // displays process (or intr) context info

-   mutex_lock(&lock1);
+   spin_lock(&lock1);
    ga++; gb--;
-   mutex_unlock(&lock1);
+   spin_unlock(&lock1);
```

现在，在驱动程序的`read`方法中，我们使用自旋锁而不是互斥锁来保护一些关键部分：

```
 static ssize_t read_miscdrv_rdwr(struct file *filp, char __user *ubuf, size_t count, loff_t  *off)
 {
-   int ret = count, secret_len;
+   int ret = count, secret_len, err_path = 0;
    struct device *dev = ctx->dev;

-   mutex_lock(&ctx->lock);
+   spin_lock(&ctx->spinlock);
    secret_len = strlen(ctx->oursecret);
-   mutex_unlock(&ctx->lock);
+   spin_unlock(&ctx->spinlock);
```

然而，这还不是全部！继续使用驱动程序的`read`方法，仔细看一下以下代码和注释：

```
[ ... ]
@@ -139,20 +157,28 @@
     * member to userspace.
     */
    ret = -EFAULT;
-   mutex_lock(&ctx->lock);
+   mutex_lock(&ctx->mutex);
+   /* Why don't we just use the spinlock??
+    * Because - VERY IMP! - remember that the spinlock can only be used when
+    * the critical section will not sleep or block in any manner; here,
+    * the critical section invokes the copy_to_user(); it very much can
+    * cause a 'sleep' (a schedule()) to occur.
+    */
    if (copy_to_user(ubuf, ctx->oursecret, secret_len)) {
[ ... ]
```

在保护关键部分可能有阻塞 API 的数据时 - 例如在`copy_to_user()`中 - 我们*必须*只使用互斥锁！（由于空间不足，我们没有在这里显示更多的代码差异；我们希望您阅读自旋锁示例驱动程序代码并自行尝试。）

## 测试 - 在原子上下文中睡眠

你已经学会了我们*不应该在任何类型的原子或中断上下文中睡眠（阻塞）*。让我们来测试一下。一如既往，经验主义方法 - 在测试自己的东西而不是依赖他人的经验时 - 是关键！

我们究竟如何测试这个？很简单：我们将使用一个简单的整数模块参数`buggy`，当设置为`1`（默认值为`0`）时，会执行违反此规则的自旋锁临界区内的代码路径。我们将调用`schedule_timeout()` API（正如您在第五章中学到的，*使用内核定时器、线程和工作队列*，在*理解如何使用*sleep()阻塞 API*部分中）内部调用`schedule()`；这是我们在内核空间中进入睡眠的方式）。以下是相关代码：

```
// ch12/2_miscdrv_rdwr_spinlock/2_miscdrv_rdwr_spinlock.c
[ ... ]
static int buggy;
module_param(buggy, int, 0600);
MODULE_PARM_DESC(buggy,
"If 1, cause an error by issuing a blocking call within a spinlock critical section");
[ ... ]
static ssize_t write_miscdrv_rdwr(struct file *filp, const char __user *ubuf,
                size_t count, loff_t *off)
{
    int ret, err_path = 0;
    [ ... ]
    spin_lock(&ctx->spinlock);
    strscpy(ctx->oursecret, kbuf, (count > MAXBYTES ? MAXBYTES : count));
    [ ... ]
    if (1 == buggy) {
        /* We're still holding the spinlock! */
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1*HZ); /* ... and this is a blocking call!
 * Congratulations! you've just engineered a bug */
    }
    spin_unlock(&ctx->spinlock);
    [ ... ]
}
```

现在，有趣的部分：让我们在两个内核中测试这个（错误的）代码路径：首先是在我们的自定义 5.4“调试”内核中（我们在这个内核中启用了几个内核调试配置选项（主要是从`make menuconfig`中的`Kernel Hacking`菜单中），如伴随指南*Linux 内核编程*-*第五章*，*编写您的第一个内核模块-LKMs 第二部分*中所解释的），其次是在一个没有启用任何相关内核调试选项的通用发行版（我们通常在 Ubuntu 上运行）5.4 内核上。

### 在 5.4 调试内核上进行测试

首先确保您已经构建了自定义的 5.4 内核，并且所有必需的内核调试配置选项都已启用（再次回到伴随指南*Linux 内核编程*-*第五章*，*编写您的第一个内核模块-LKMs 第二部分*，*配置调试内核*部分，如果需要的话）。然后，从调试内核启动（这里命名为`5.4.0-llkd-dbg`）。现在，在这个调试内核中构建驱动程序（在`ch12/2_miscdrv_rdwr_spinlock/`中）（在驱动程序目录中通常使用`make`命令即可完成；您可能会发现，在调试内核上，构建速度明显较慢！）：

```
$ lsb_release -a 2>/dev/null | grep "^Description" ; uname -r
Description: Ubuntu 20.04.1 LTS
5.4.0-llkd-dbg $ make
[ ... ]
$ modinfo ./miscdrv_rdwr_spinlock.ko 
filename: /home/llkd/llkd_src/ch12/2_miscdrv_rdwr_spinlock/./miscdrv_rdwr_spinlock.ko
[ ... ]
description: LLKD book:ch12/2_miscdrv_rdwr_spinlock: simple misc char driver rewritten with spinlocks
[ ... ]
parm: buggy:If 1, cause an error by issuing a blocking call within a spinlock critical section (int)
$ sudo virt-what
virtualbox
kvm
$ 
```

如您所见，我们在我们的 x86_64 Ubuntu 20.04 客户 VM 上运行我们的自定义 5.4.0“调试”内核。

您如何知道自己是在**虚拟机**（VM）上运行还是在“裸机”（本机）系统上运行？`virt-what(1)`是一个有用的小脚本，可以显示这一点（您可以在 Ubuntu 上使用`sudo apt install virt-what`进行安装）。

要运行我们的测试用例，将驱动程序插入内核并将`buggy`模块参数设置为`1`。调用驱动程序的`read`方法（通过我们的用户空间应用程序；也就是`ch12/miscdrv_rdwr/rdwr_test_secret`）不是问题，如下所示：

```
$ sudo dmesg -C
$ sudo insmod ./miscdrv_rdwr_spinlock.ko buggy=1
$ ../../ch12/miscdrv_rdwr/rdwr_test_secret 
Usage: ../../ch12/miscdrv_rdwr/rdwr_test_secret opt=read/write device_file ["secret-msg"]
 opt = 'r' => we shall issue the read(2), retrieving the 'secret' form the driver
 opt = 'w' => we shall issue the write(2), writing the secret message <secret-msg>
  (max 128 bytes)
$ 
$ ../../ch12/miscdrv_rdwr/rdwr_test_secret r /dev/llkd_miscdrv_rdwr_spinlock 
Device file /dev/llkd_miscdrv_rdwr_spinlock opened (in read-only mode): fd=3
../../ch12/miscdrv_rdwr/rdwr_test_secret: read 7 bytes from /dev/llkd_miscdrv_rdwr_spinlock
The 'secret' is:
 "initmsg"
$ 
```

接下来，我们通过用户模式应用程序向驱动程序发出`write(2)`；这次，我们的错误代码路径被执行。正如您所看到的，我们在自旋锁的临界区内发出了`schedule_timeout()`（也就是在锁定和解锁之间）。调试内核将此检测为错误，并在内核日志中生成（令人印象深刻的大量）调试诊断（请注意，这样的错误很可能会使您的系统挂起，因此请先在虚拟机上进行测试）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/3c6f7129-6f1c-4a04-9f5c-df29e28b0420.png)

图 6.9-由我们故意触发的“在原子上下文中调度”错误触发的内核诊断

前面的屏幕截图显示了发生的部分情况（在查看`ch12/2_miscdrv_rdwr_spinlock/2_miscdrv_rdwr_spinlock.c`中的驱动程序代码时，请跟随一起）：

1.  首先，我们有我们的用户模式应用程序的进程上下文（`rdwr_test_secre`；请注意名称被截断为前 16 个字符，包括`NULL`字节），它进入驱动程序的写入方法；也就是`write_miscdrv_rdwr()`。这可以在我们有用的`PRINT_CTX()`宏的输出中看到（我们在这里重现了这一行）：

```
miscdrv_rdwr_spinlock:write_miscdrv_rdwr(): 004) rdwr_test_secre :23578 | ...0 /*  write_miscdrv_rdwr() */
```

1.  它从用户空间写入进程中复制新的“秘密”并将其写入，共 24 个字节。

1.  然后，“获取”自旋锁，进入临界区，并将这些数据复制到我们驱动程序上下文结构的`oursecret`成员中。

1.  之后，`if (1 == buggy) {`评估为 true。

1.  然后，它调用`schedule_timeout()`，这是一个阻塞 API（因为它内部调用`schedule()`），触发了错误，这在红色中得到了很好的突出显示：

```
BUG: scheduling while atomic: rdwr_test_secre/23578/0x00000002
```

1.  内核现在会输出大量的诊断输出。首先要输出的是**调用堆栈**。

进程的内核模式堆栈或堆栈回溯（或“调用跟踪”）- 在这里，它是我们的用户空间应用程序`rdwr_drv_secret`，它正在运行我们（有缺陷的）驱动程序的代码在进程上下文中- 可以在*图 6.9*中清楚地看到。`Call Trace:`标题之后的每一行本质上都是内核堆栈上的一个调用帧。

作为提示，忽略以`?`符号开头的堆栈帧；它们很可能是同一内存区域中以前堆栈使用的“剩余物”。在这里值得进行一次与内存相关的小的偏离：这就是堆栈分配的真正工作原理；堆栈内存不是按照每个调用帧的基础分配和释放的，因为那将是非常昂贵的。只有在堆栈内存页耗尽时，才会自动*故障*新的内存页！（回想一下我们在伴随指南*Linux 内核编程-第九章*，*模块作者的内核内存分配-第二部分*中的讨论，在*内存分配和需求分页的简短说明*部分。）因此，现实情况是，当代码调用和从函数返回时，相同的堆栈内存页往往会不断被重用。

不仅如此，出于性能原因，内存并不是每次都被擦除，这导致以前的帧留下的情况经常出现。（它们可以真正“破坏”图像。然而，幸运的是，现代堆栈调用帧跟踪算法通常能够出色地找出正确的堆栈跟踪。）

从下到上（*总是从下到上阅读*）跟踪堆栈，我们可以看到，如预期的那样，我们的用户空间`write(2)`系统调用（它经常显示为（类似于）`SyS_write`或在 x86 上显示为`__x64_sys_write`，尽管在*图 6.9*中看不到）调用了内核的 VFS 层代码（您可以在这里看到`vfs_write()`，它调用了`__vfs_write()`），进一步调用了我们驱动程序的写方法；也就是`write_miscdrv_rdwr()`！正如我们所知，这段代码调用了有缺陷的代码路径，我们在其中调用了`schedule_timeout()`，这又调用了`schedule()`（和`__schedule()`），导致整个**`BUG：scheduling while atomic`**错误触发。

`scheduling while atomic`代码路径的格式是从以下代码行中检索的，该代码行可以在`kernel/sched/core.c`中找到：

```
printk(KERN_ERR "BUG: scheduling while atomic: %s/%d/0x%08x\n", prev->comm, prev->pid, preempt_count());
```

有趣！在这里，您可以看到它打印了以下字符串：

```
      BUG: scheduling while atomic: rdwr_test_secre/23578/0x00000002
```

在`atomic:`之后，它打印进程名称-PID-，然后调用`preempt_count()`内联函数，该函数打印*抢占深度*；抢占深度是一个计数器，每次获取锁时递增，每次解锁时递减。因此，如果它是正数，这意味着代码在关键或原子部分内；在这里，它显示为值`2`。

请注意，这个错误在这次测试运行中得到了很好的解决，因为`CONFIG_DEBUG_ATOMIC_SLEEP`调试内核配置选项已经打开。这是因为我们正在运行一个自定义的“调试内核”（内核版本 5.4.0）！配置选项的详细信息（您可以在`make menuconfig`中交互地找到并设置此选项，在`Kernel Hacking`菜单下）如下：

```
// lib/Kconfig.debug
[ ... ]
config DEBUG_ATOMIC_SLEEP
    bool "Sleep inside atomic section checking"
    select PREEMPT_COUNT
    depends on DEBUG_KERNEL
    depends on !ARCH_NO_PREEMPT
    help 
      If you say Y here, various routines which may sleep will become very 
 noisy if they are called inside atomic sections: when a spinlock is
 held, inside an rcu read side critical section, inside preempt disabled
 sections, inside an interrupt, etc...
```

### 在 5.4 非调试 distro 内核上进行测试

作为对比测试，我们现在将在我们的 Ubuntu 20.04 LTS VM 上执行完全相同的操作，我们将通过其默认的通用“distro” 5.4 Linux 内核引导，通常*未配置为“调试”内核*（这里，`CONFIG_DEBUG_ATOMIC_SLEEP`内核配置选项尚未设置）。

首先，我们插入我们的（有缺陷的）驱动程序。然后，当我们运行我们的`rdwr_drv_secret`进程以向驱动程序写入新的秘密时，有缺陷的代码路径被执行。然而，这一次，内核*既不崩溃，也不报告任何问题*（查看`dmesg(1)`输出验证了这一点）：

```
$ uname -r
5.4.0-56-generic
$ sudo insmod ./miscdrv_rdwr_spinlock.ko buggy=1
$ ../../ch12/miscdrv_rdwr/rdwr_test_secret w /dev/llkd_miscdrv_rdwr_spinlock "passwdcosts500bucksdude"
Device file /dev/llkd_miscdrv_rdwr_spinlock opened (in write-only mode): fd=3
../../ch12/miscdrv_rdwr/rdwr_test_secret: wrote 24 bytes to /dev/llkd_miscdrv_rdwr_spinlock
$ dmesg 
[ ... ]
[ 65.420017] miscdrv_rdwr_spinlock:miscdrv_init_spinlock(): LLKD misc driver (major # 10) registered, minor# = 56, dev node is /dev/llkd_miscdrv_rdwr
[ 81.665077] miscdrv_rdwr_spinlock:miscdrv_exit_spinlock(): miscdrv_rdwr_spinlock: LLKD misc driver deregistered, bye
[ 86.798720] miscdrv_rdwr_spinlock:miscdrv_init_spinlock(): VERMAGIC_STRING = 5.4.0-56-generic SMP mod_unload 
[ 86.799890] miscdrv_rdwr_spinlock:miscdrv_init_spinlock(): LLKD misc driver (major # 10) registered, minor# = 56, dev node is /dev/llkd_miscdrv_rdwr
[ 130.214238] misc llkd_miscdrv_rdwr_spinlock: filename: "llkd_miscdrv_rdwr_spinlock"
                wrt open file: f_flags = 0x8001
                ga = 1, gb = 0
[ 130.219233] misc llkd_miscdrv_rdwr_spinlock: stats: tx=0, rx=0
[ 130.219680] misc llkd_miscdrv_rdwr_spinlock: rdwr_test_secre wants to write 24 bytes
[ 130.220329] misc llkd_miscdrv_rdwr_spinlock: 24 bytes written, returning... (stats: tx=0, rx=24)
[ 131.249639] misc llkd_miscdrv_rdwr_spinlock: filename: "llkd_miscdrv_rdwr_spinlock"
                ga = 0, gb = 1
[ 131.253511] misc llkd_miscdrv_rdwr_spinlock: stats: tx=0, rx=24
$ 
```

我们知道我们的写入方法有一个致命的错误，但它似乎并没有以任何方式失败！这真的很糟糕；这种事情可能会误导你错误地认为你的代码很好，而实际上一个难以察觉的致命错误悄悄地等待着某一天突然袭击！

为了帮助我们调查底层到底发生了什么，让我们再次运行我们的测试应用程序（`rdwr_drv_secret`进程），但这次通过强大的`trace-cmd（1）`工具（一个非常有用的包装器，覆盖了 Ftrace 内核基础设施；以下是它的截断输出：

Linux 内核的**Ftrace**基础设施是内核的主要跟踪基础设施；它提供了内核空间中几乎每个执行的函数的详细跟踪。在这里，我们通过一个方便的前端利用 Ftrace：`trace-cmd（1）`实用程序。这些确实是非常强大和有用的调试工具；我们在伴随指南* Linux 内核编程 - 第一章* *内核工作空间设置*中提到了其他几个，但不幸的是，这些细节超出了本书的范围。查看手册以了解更多。

```
$ sudo trace-cmd record -p function_graph -F ../../ch12/miscdrv_rdwr/rdwr_test_secret w /dev/llkd_miscdrv_rdwr_spinlock "passwdcosts500bucks"
$ sudo trace-cmd report -I -S -l > report.txt
$ sudo less report.txt
[ ... ]
```

输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/63b163f7-5ce7-45f1-907e-b10a06909ef3.png)

图 6.10 - trace-cmd（1）报告输出的部分截图

正如你所看到的，我们用户模式应用程序的`write（2）`系统调用变成了预期的`vfs_write()`，它本身（经过安全检查后）调用了`__vfs_write()`，然后调用了我们的驱动程序的写入方法 - `write_miscdrv_rdwr()`函数！

在（大量的）Ftrace 输出流中，我们可以看到`schedule_timeout()`函数确实被调用了：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/1cd0401a-b6a2-43e1-998d-10994995cdd6.png)

图 6.11 - trace-cmd（1）报告输出的部分截图，显示了在原子上下文中调用 schedule_timeout()和 schedule()的（错误的！）调用

在`schedule_timeout()`之后的几行输出中，我们可以清楚地看到`schedule()`被调用！所以，我们的驱动程序（当然是故意的）执行了一些错误的操作 - 在原子上下文中调用`schedule()`。但这里的关键点是，在这个 Ubuntu 系统上，我们*没有*运行“调试”内核，这就是为什么我们有以下情况：

```
$ grep DEBUG_ATOMIC_SLEEP /boot/config-5.4.0-56-generic
# CONFIG_DEBUG_ATOMIC_SLEEP is not set
$
```

这就是为什么错误没有被报告的原因！这证明了运行测试用例的有用性 - 事实上，在“调试”内核上进行内核开发 - 一个启用了许多调试功能的内核。（作为练习，如果您还没有这样做，请准备一个“调试”内核并在其上运行此测试用例。）

Linux 驱动程序验证（LDV）项目：在伴随指南* Linux 内核编程 - 第一章* *内核工作空间设置*中，我们提到了这个项目对 Linux 模块（主要是驱动程序）以及核心内核的各种编程方面有用的“规则”。

关于我们当前的主题，这是其中一条规则：*使用自旋锁和解锁函数*（[`linuxtesting.org/ldv/online?action=show_rule&rule_id=0039`](http://linuxtesting.org/ldv/online?action=show_rule&rule_id=0039)）。它提到了关于正确使用自旋锁的关键点；有趣的是，它在这里展示了一个驱动程序中实际的错误实例，其中尝试两次释放自旋锁 - 这是对锁定规则的明显违反，导致系统不稳定。

# 锁定和中断

到目前为止，我们已经学会了如何使用互斥锁，对于自旋锁，基本的`spin_[un]lock()` API。自旋锁还有一些其他 API 变体，我们将在这里检查更常见的一些。

为了确切理解为什么你可能需要其他的自旋锁 API，让我们来看一个情景：作为驱动程序的作者，你发现你正在处理的设备断言了一个硬件中断；因此，你为其编写了中断处理程序。现在，在为你的驱动程序实现`read`方法时，你发现其中有一个非阻塞的临界区。这很容易处理：正如你所学的，你应该使用自旋锁来保护它。太好了！但是，如果在`read`方法的临界区内，设备的硬件中断触发了怎么办？正如你所知，*硬件中断会抢占任何事情*；因此，控制权将转移到中断处理程序代码，抢占了驱动程序的`read`方法。

关键问题在于：这是一个问题吗？答案取决于你的中断处理程序和`read`方法在做什么以及它们是如何实现的。让我们想象一些情景：

+   中断处理程序（理想情况下）仅使用局部变量，因此即使`read`方法处于临界区，它实际上并不重要；中断处理将非常快速地完成，并且控制权将被交还给被中断的内容（同样，这还不止这些；正如你所知，任何现有的底半部，比如任务 let 或软中断，也可能需要执行）。换句话说，在这种情况下实际上没有竞争。

+   中断处理程序正在处理（全局）共享可写数据，但*不是*你的读取方法正在使用的数据项。因此，再次，没有冲突，也没有与读取代码的竞争。当然，你应该意识到，中断代码*确实有一个临界区，它必须受到保护*（也许需要另一个自旋锁）。

+   中断处理程序正在处理与你的`read`方法使用的相同的全局共享可写数据。在这种情况下，我们可以看到存在竞争的潜力，因此我们需要锁！

让我们专注于第三种情况。显然，我们应该使用自旋锁来保护中断处理代码中的临界区（请记住，在任何类型的中断上下文中使用互斥锁是不允许的）。此外，*除非我们在`read`方法和中断处理程序的代码路径中都使用完全相同的自旋锁*，否则它们将根本得不到保护！（在处理锁时要小心；花时间仔细思考你的设计和代码细节。）

让我们尝试更加实际一些（暂时使用伪代码）：假设我们有一个名为`gCtx`的全局（共享）数据结构；我们在驱动程序的`read`方法和中断处理程序（硬中断处理程序）中都在操作它。由于它是共享的，它是一个临界区，因此需要保护；由于我们在一个原子（中断）上下文中运行，我们*不能使用互斥锁*，因此必须使用自旋锁（这里，自旋锁变量称为`slock`）。以下伪代码显示了这种情况的一些时间戳（`t1，t2，...`）：

```
// Driver read method ; WRONG ! driver_read(...)                  << time t0 >>
{
    [ ... ]
    spin_lock(&slock);
    <<--- time t1 : start of critical section >>
... << operating on global data object gCtx >> ...
    spin_unlock(&slock);
    <<--- time t2 : end of critical section >>
    [ ... ]
}                                << time t3 >>
```

以下伪代码是设备驱动程序的中断处理程序：

```
handle_interrupt(...)           << time t4; hardware interrupt fires!     >>
{
    [ ... ]
    spin_lock(&slock);
    <<--- time t5: start of critical section >>
    ... << operating on global data object gCtx >> ...
    spin_unlock(&slock);
    <<--- time t6 : end of critical section >>
    [ ... ]
}                               << time t7 >> 
```

这可以用以下图表总结：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/3d9d5f60-bb83-44a5-a694-2a05f28df4f8.png)

图 6.12 - 时间轴 - 当处理全局数据时，驱动程序的读取方法和硬中断处理程序按顺序运行；这里没有问题

幸运的是，一切都进行得很顺利 - “幸运”是因为硬件中断是在`read`函数的临界区完成之后触发的。当然，我们不能指望幸运成为我们产品的唯一安全标志！硬件中断是异步的；如果它在一个不太合适的时间（对我们来说）触发了 - 比如，在`read`方法的临界区在时间 t1 和 t2 之间运行时怎么办？好吧，自旋锁会执行它的工作并保护我们的数据吗？

此时，中断处理程序的代码将尝试获取相同的自旋锁（`&slock`）。等一下——它无法“获取”它，因为它当前被锁定了！在这种情况下，它“自旋”，实际上是在等待解锁。但它怎么能解锁呢？它不能，这就是我们所面临的一个**(自身)死锁**。

有趣的是，自旋锁在 SMP（多核）系统上更直观，更有意义。让我们假设`read`方法在 CPU 核心 1 上运行；中断可以在另一个 CPU 核心上，比如核心 2 上被传递。中断代码路径将在 CPU 核心 2 上的锁上“自旋”，而`read`方法在核心 1 上完成临界区，然后解锁自旋锁，从而解除中断处理程序的阻塞。但是在**UP**（单处理器，只有一个 CPU 核心）上呢？那么它会怎么工作呢？啊，所以这是解决这个难题的方法：当与中断“竞争”时，*无论是单处理器还是 SMP，都简单地使用*自旋锁 API*的*`_irq` *变体*：

```
#include <linux/spinlock.h>
void spin_lock_irq(spinlock_t *lock);
```

`spin_lock_irq()` API 在处理器核心上禁用中断；也就是说，在本地核心上。因此，通过在我们的`read`方法中使用这个 API，中断将在本地核心上被禁用，从而通过中断使任何可能的“竞争”变得不可能。（如果中断在另一个 CPU 核心上触发，自旋锁技术将像之前讨论的那样正常工作！）

`spin_lock_irq()`的实现是相当嵌套的（就像大多数自旋锁功能一样），但是很快；在下一行，它最终调用了`local_irq_disable()`和`preempt_disable()`宏，在运行它的本地处理器核心上禁用了中断和内核抢占。（禁用硬件中断也会有禁用内核抢占的（理想的）副作用。）

`spin_lock_irq()`与相应的`spin_unlock_irq()` API 配对。因此，对于这种情况（与我们之前看到的情况相反），自旋锁的正确用法如下：

```
// Driver read method ; CORRECT ! driver_read(...)                  << time t0 >>
{
    [ ... ]
    spin_lock_irq(&slock);
    <<--- time t1 : start of critical section >>
*[now all interrupts + preemption on local CPU core are masked (disabled)]*
... << operating on global data object gCtx >> ...
    spin_unlock_irq(&slock);
    <<--- time t2 : end of critical section >>
    [ ... ]
}                                << time t3 >>
```

在我们自满地拍拍自己的背并休息一天之前，让我们考虑另一种情况。这一次，在一个更复杂的产品（或项目）上，有可能在代码库上工作的几个开发人员中，有人故意将中断屏蔽设置为某个值，从而阻止一些中断，同时允许其他中断。为了我们的例子，让我们假设这在某个时间点`t0`之前发生过。现在，正如我们之前描述的，另一个开发人员（你！）过来了，为了保护驱动程序`read`方法中的临界区，使用了`spin_lock_irq()` API。听起来正确，是吗？是的，但是这个 API 有权利*关闭（屏蔽）所有硬件中断*（和内核抢占，我们现在将忽略）。它通过在低级别上操作（非常特定于架构的）硬件中断屏蔽寄存器来做到这一点。假设将与中断对应的位设置为`1`会启用该中断，而清除该位（为`0`）会禁用或屏蔽它。由于这个原因，我们可能会得到以下情况：

+   时间`t0`：中断屏蔽被设置为某个值，比如`0x8e (10001110b)`，启用了一些中断并禁用了一些中断。这对项目很重要（在这里，为了简单起见，我们假设有一个 8 位掩码寄存器）

*[...时间流逝...].*

+   时间`t1`：就在进入驱动程序`read`方法的临界区之前，调用

`spin_lock_irq(&slock);`。这个 API 的内部效果是将中断屏蔽寄存器中的所有位清零，从而禁用所有中断（正如我们*认为*我们所期望的）。

+   时间`t2`：现在，硬件中断无法在这个 CPU 核心上触发，所以我们继续完成临界区。完成后，我们调用`spin_unlock_irq(&slock);`。这个 API 的内部效果是将中断屏蔽寄存器中的所有位设置为`1`，重新启用所有中断。

然而，中断掩码寄存器现在被错误地“恢复”为`0xff (11111111b)`的值，*而不是*原始开发人员想要、需要和假设的`0x8e`的值！这可能会（并且可能会）在项目中出现问题。

解决方案非常简单：不要假设任何东西，**只需保存和恢复中断掩码**。可以通过以下 API 对实现这一点：

```
#include <linux/spinlock.h>>
 unsigned long spin_lock_irqsave(spinlock_t *lock, unsigned long flags);
 void spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags);
```

锁定和解锁函数的第一个参数都是要使用的自旋锁变量。第二个参数`flags` *必须是*`unsigned long`类型的本地变量。这将用于保存和恢复中断掩码：

```
spinlock_t slock;
spin_lock_init(&slock);
[ ... ]
driver_read(...) 
{
    [ ... ]
    spin_lock_irqsave(&slock, flags);
    << ... critical section ... >>
    spin_unlock_irqrestore(&slock, flags);
    [ ... ]
}
```

要严格，`spin_lock_irqsave()`不是一个 API，而是一个宏；我们将其显示为 API 是为了可读性。此宏的返回值虽然不是 void，但这是一个内部细节（这里更新了`flags`参数变量）。

如果一个任务或软中断（底半部中断机制）有一个关键部分与您的进程上下文代码路径“竞争”，在这种情况下，使用`spin_lock_bh()`例程可能是所需的，因为它可以在本地处理器上禁用底半部，然后获取自旋锁，从而保护关键部分（类似于`spin_lock_irq[save]()`在进程上下文中保护关键部分，通过在本地核心上禁用硬件中断）：

```
void spin_lock_bh(spinlock_t *lock);
```

当然，*开销*在高性能敏感的代码路径中很重要（网络堆栈是一个很好的例子）。因此，使用最简单形式的自旋锁将有助于处理更复杂的变体。尽管如此，肯定会有需要使用更强形式的自旋锁 API 的情况。例如，在 Linux 内核 5.4.0 上，这是我们看到的不同形式自旋锁 API 的使用实例数量的近似值：`spin_lock()`:超过 9,400 个使用实例；`spin_lock_irq()`:超过 3,600 个使用实例；`spin_lock_irqsave()`:超过 15,000 个使用实例；和`spin_lock_bh()`:超过 3,700 个使用实例。（我们不从中得出任何重大推论；只是我们希望指出，在 Linux 内核中广泛使用更强形式的自旋锁 API）。

最后，让我们简要介绍一下自旋锁的内部实现：在底层内部实现方面，实现往往是非常特定于体系结构的代码，通常由在微处理器上执行非常快的原子机器语言指令组成。例如，在流行的 x86[_64]体系结构上，自旋锁最终归结为自旋锁结构的成员上的*原子测试和设置*机器指令（通常通过`cmpxchg`机器语言指令实现）。在 ARM 机器上，正如我们之前提到的，实现的核心通常是`wfe`（等待事件，以及**SetEvent**（**SEV**））机器指令。（您将在*进一步阅读*部分找到关于其内部实现的资源）。无论如何，作为内核或驱动程序的作者，您在使用自旋锁时应该只使用公开的 API（和宏）。

## 使用自旋锁-快速总结

让我们快速总结一下自旋锁：

+   **最简单，开销最低**：在保护进程上下文中的关键部分时，请使用非 irq 自旋锁原语`spin_lock()`/`spin_unlock()`（要么没有中断需要处理，要么有中断，但我们根本不与它们竞争；实际上，当中断不发挥作用或不重要时使用这个）。

+   **中等开销**：当中断发挥作用并且很重要时，请使用禁用 irq（以及内核抢占禁用）版本的`spin_lock_irq() / spin_unlock_irq()`（进程和中断上下文可能会“竞争”；也就是说，它们共享全局数据）。

+   **最强（相对）高开销**：这是使用自旋锁的最安全方式。它与中等开销的方式相同，只是通过`spin_lock_irqsave()` / `spin_unlock_irqrestore()`对中断掩码执行保存和恢复，以确保以前的中断掩码设置不会被意外覆盖，这可能会发生在前一种情况下。

正如我们之前所看到的，自旋锁 - 在等待锁时在其运行的处理器上“自旋” - 在 UP 系统上是不可能的（在另一个线程同时在同一 CPU 上运行时，您如何在仅有的一个 CPU 上自旋？）。实际上，在 UP 系统上，自旋锁 API 的唯一真正效果是它可以禁用处理器上的硬件中断和内核抢占！然而，在 SMP（多核）系统上，自旋逻辑实际上会发挥作用，因此锁定语义会按预期工作。但是请注意 - 这不应该让您感到压力，新手内核/驱动程序开发人员；事实上，整个重点是您应该简单地按照描述使用自旋锁 API，您将永远不必担心 UP 与 SMP 之间的区别；做什么和不做什么的细节都被内部实现隐藏起来。

尽管本书基于 5.4 LTS 内核，但从**实时 Linux**（**RTL**，以前称为 PREEMPT_RT）项目中添加了一个新功能到 5.8 内核，值得在这里快速提一下：“**本地锁**”。虽然本地锁的主要用例是用于（硬）实时内核，但它们也对非实时内核有所帮助，主要用于通过静态分析进行锁调试，以及通过 lockdep 进行运行时调试（我们将在下一章中介绍 lockdep）。这是有关该主题的 LWN 文章：[`lwn.net/Articles/828477/`](https://lwn.net/Articles/828477/)。

通过这一部分，我们完成了自旋锁的部分，这是 Linux 内核中几乎所有子系统（包括驱动程序）都使用的一种极为常见和关键的锁。

# 总结

祝贺您完成了本章！

理解并发性及其相关问题对于任何软件专业人员来说都是非常关键的。在本章中，您学习了关于临界区的关键概念，其中需要在其中进行独占执行，以及原子性的含义。然后，您了解了在为 Linux 操作系统编写代码时为什么需要关注并发性。之后，我们详细探讨了实际的锁技术 - 互斥锁和自旋锁。您还学会了在何时使用哪种锁。最后，学习了在硬件中断（以及可能的底半部分）参与时如何处理并发性问题。

但我们还没有完成！我们还需要学习更多概念和技术，这正是我们将在本书的下一章，也是最后一章中要做的。我建议您先浏览本章的内容，以及*进一步阅读*部分和提供的练习，然后再深入研究最后一章！

# 问题

随着我们的结束，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会在书的 GitHub 存储库中找到一些问题的答案：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入了解这个主题并提供有用的材料，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）。*进一步阅读*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。
