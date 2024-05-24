# 使用 Yocto 项目学习 Linux 嵌入式编程（三）

> 原文：[`zh.annas-archive.org/md5/6A5B9E508EC2401ECE20C211D2D71910`](https://zh.annas-archive.org/md5/6A5B9E508EC2401ECE20C211D2D71910)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：实时

在本章中，您将了解 Yocto 项目的实时组件的信息。此外，在相同的背景下，将解释操作系统和实时操作系统的通用目的的简要讨论。然后我们将转向 PREEMPT_RT 补丁，试图将正常的 Linux 变成一个功能强大的实时操作系统；我们将尝试从更多角度来看待它，并最终总结并得出结论。这还不是全部，任何实时操作都需要其应用程序，因此还将简要介绍适用于实时操作系统背景下的应用程序编写的注意事项。记住所有这些，我相信现在是时候继续本章内容了；希望您喜欢。

您将在本章找到对实时组件的更详细解释。还将向您展示 Linux 与实时的关系。众所周知，Linux 操作系统被设计为一个类似于已有的 UNIX 的通用操作系统。很容易看出，多用户系统（如 Linux）和实时系统在某种程度上存在冲突。这主要是因为对于通用目的，多用户操作系统（如 Linux）被配置为获得最大的平均吞吐量。这牺牲了对实时操作系统来说恰恰相反的延迟要求。

实时的定义相当容易理解。在计算中，其主要思想是计算机或任何嵌入式设备能够及时向其环境提供反馈。这与快速不同；事实上，在系统的上下文中足够快。对于汽车行业或核电厂来说，足够快是不同的。此外，这种系统将提供可靠的响应以做出不影响任何外部系统的决策。例如，在核电厂中，它应该检测并防止任何异常情况，以确保避免灾难发生。

# 理解 GPOS 和 RTOS

当提到 Linux 时，通常会将**通用目的操作系统**（**GPOS**）与之联系起来，但随着时间的推移，对 Linux 具有与**实时操作系统**（**RTOS**）相同的好处的需求变得更为迫切。任何实时系统的挑战在于满足给定的时间约束，尽管存在各种随机的异步事件。这并不是一项简单的任务，对实时系统的理论进行了大量的论文和研究。实时系统的另一个挑战是对延迟设置上限，称为调度截止日期。根据系统如何应对这一挑战，它们可以分为硬实时、稳固实时和软实时：

+   硬实时系统：这代表了一个如果错过截止日期将导致完全系统故障的系统。

+   **稳固实时系统**：这代表了一个截止日期错过是可以接受的，但系统质量可能会降低的系统。此外，在错过截止日期后，所提供的结果将不再有用。

+   **软实时系统**：这代表了一个错过截止日期会降低所收到结果的有用性，从而降低系统的质量的系统。在这种系统中，满足截止日期被视为一个目标而不是严格要求。

有多个原因导致 Linux 不适合作为 RTOS：

+   **分页**：通过虚拟内存的页面交换过程是没有限制的。目前没有方法可以知道从磁盘获取页面需要多长时间，这意味着页面故障可能导致的延迟没有上限。

+   **粗粒度同步**：在这里，Linux 内核的定义是不可抢占的。这意味着一旦一个进程处于内核上下文中，它就不能被抢占，直到退出上下文。在事件发生时，新事件需要等待调度，直到已有的事件退出内核上下文。

+   **批处理**：可以对操作进行批处理，以更有效地利用资源。这种方法的最简单示例是页面释放过程。Linux 能够传递多个页面并尽可能多地进行清理，而不是释放每个单独的页面。

+   **请求重排序**：可以对进程的 I/O 请求进行重新排序，使硬件的使用过程更加高效。

+   **调度公平性**：这是 UNIX 的遗产，指的是调度程序试图对所有运行的进程公平。这个特性提供了等待时间较长的较低优先级进程在较高优先级进程之前被调度的可能性。

所有前述特征构成了任务或进程的延迟不能应用上限的原因，也是 Linux 不能成为硬实时操作系统的原因。让我们看一下下面的图表，它说明了 Linux 操作系统提供实时特性的方法：

![理解 GPOS 和 RTOS](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00361.jpeg)

任何人可以做的第一件事来改善标准 Linux 操作系统的延迟就是尝试更改调度策略。默认的 Linux 时间共享调度策略称为**SCHED_OTHER**，它使用公平算法，给予所有进程零优先级，即可用的最低优先级。其他类似的调度策略有**SCHED_BATCH**用于进程的批处理调度和**SCHED_IDLE**，适用于极低优先级作业的调度。这些调度策略的替代方案是**SCHED_FIFO**和**SCHED_RR**。它们都是用作实时策略的，适用于需要精确控制进程和它们的延迟的时间关键应用程序。

为了给 Linux 操作系统提供更多的实时特性，还有另外两种方法可以提出。第一种是对 Linux 内核更具抢占性的实现。这种方法可以利用已有的用于 SMP 支持的自旋锁机制，确保多个进程不会同时执行，尽管在单处理器的情况下，自旋锁是无操作的。中断处理也需要修改以进行重新调度，以便在出现另一个更高优先级的进程时进行可能的重新调度；在这种情况下，可能还需要一个新的调度程序。这种方法的优点是不改变用户空间的交互，并且可以使用诸如 POSIX 或其他 API。缺点是内核的更改非常严重，每次内核版本更改时，这些更改都需要相应地进行调整。如果这项工作还不够，最终结果并不是完全的实时操作系统，而是减少了操作系统的延迟。

另一种可用的实现是中断抽象。这种方法基于这样一个事实，即并非所有系统都需要硬实时确定性，大多数系统只需要执行其任务的一部分在实时环境中执行。这种方法的理念是在实时内核下以空闲任务的优先级运行 Linux，并继续执行非实时任务，就像它们通常做的那样。这种实现伪装了实时内核的中断禁用，但实际上是传递给了实时内核。对于这种类型的实现，有三种可用的解决方案：

+   **RTLinux**：它代表中断抽象方法的原始实现，是在新墨西哥矿业技术研究所开发的。尽管它仍有开源实现，但大部分开发现在是由 FSMLabs 工程师完成的，后来被 Wind River System 收购用于其商业版本。对 RTLinux 的商业支持于 2011 年 8 月结束。

+   **RTAI**：这是对在米兰理工大学航空航天工程系开发的 RTLinux 解决方案的增强。该项目非常活跃，有大量开发人员，并且有当前版本可用。

+   **Xenomai**：它代表第三种实现。它的历史有些扭曲：它于 2001 年 8 月出现，只是在 2013 年与 RTAI 合并，以生成适合生产的实时操作系统。然而，这种融合在 2005 年解散，又重新成为一个独立项目。

以下图表展示了基本的 RTLinux 架构。

![理解 GPOS 和 RTOS](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00362.jpeg)

与前面图表中显示的类似架构适用于另外两种解决方案，因为它们都是从 RTLinux 实现中诞生的。它们之间的区别在于实现级别，每种都提供各种好处。

# PREEMPT_RT

当需要实时解决方案时，PREEMPT_RT 补丁是每个开发人员的首选。对于一些开发人员，PREEMPT_RT 补丁将 Linux 转变为适合其需求的实时解决方案。这个解决方案不能取代实时操作系统，但实际上适用于大量系统。

PREEMPT_RT 相对于 Linux 的其他实时解决方案的最大优势在于，它实际上将 Linux 转变为实时操作系统。所有其他替代方案通常创建一个微内核，作为超级监视器执行，而 Linux 只作为其任务执行，因此实时任务与非实时任务之间的通信是通过这个微内核完成的。对于 PREEMPT_RT 补丁，这个问题不复存在。

标准版的 Linux 内核只能提供基本的软实时要求，如基本的 POSIX 用户空间操作，其中没有保证的截止期。通过添加补丁，如 Ingo Molnar 的 PREEMPT_RT 补丁，以及 Thomas Gheixner 关于提供高分辨率支持的通用时钟事件层的补丁，可以说你有一个提供高实时能力的 Linux 内核。

随着实时抢占补丁在行业中的出现，出现了许多有趣的机会，使其成为工业控制或专业音频等领域的坚实和硬实时应用的选择。这主要是因为 PREEMPT_RT 补丁的设计及其旨在集成到主线内核中。我们将在本章中进一步了解其用法。以下图表显示了可抢占 Linux 内核的工作原理：

![PREEMPT_RT](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00363.jpeg)

PREEMPT_RT 补丁通过以下技巧将 Linux 从通用操作系统转变为可抢占的操作系统：

+   使用可抢占的`rwlock_t preemptible`和`spinlock_t`来保护关键部分。仍然可以使用旧的解决方案，使用`raw_spinlock_t`，它与`spinlock_t`具有相同的 API。

+   使用`rtmutexes`抢占内核锁定机制。

+   为`mutexes`、`spinlocks`和`rw_semaphores`实现了优先级倒置和优先级继承机制。

+   将现有的 Linux 定时器 API 转换为具有高分辨率定时器的 API，从而提供超时的可能性。

+   实现使用内核线程作为中断处理程序。实时抢占补丁将软中断处理程序处理为内核线程上下文，使用`task_struct`结构来处理每个用户空间进程。还可以将 IRQ 注册到内核上下文中。

### 注意

有关优先级反转的更多信息，请参阅[`www.embedded.com/electronics-blogs/beginner-s-corner/4023947/Introduction-to-Priority-Inversion`](http://www.embedded.com/electronics-blogs/beginner-s-corner/4023947/Introduction-to-Priority-Inversion)。

## 应用 PREEMPT_RT 补丁

在移动到实际配置部分之前，您应该下载适合内核的版本。最好的灵感来源是[`www.kernel.org/`](https://www.kernel.org/)，这应该是起点，因为它不包含任何额外的补丁。收到源代码后，可以从[`www.kernel.org/pub/linux/kernel/projects/rt/`](https://www.kernel.org/pub/linux/kernel/projects/rt/)下载相应的`rt`补丁版本。本演示选择的内核版本是 3.12 内核版本，但如果需要其他内核版本，则可以采取类似的步骤，获得类似的结果。实时抢占补丁的开发非常活跃，因此任何缺失的版本支持都会很快得到解决。此外，对于其他子级版本，可以在特定内核版本的`incr`或旧的子目录中找到补丁。以下是子级版本的示例：

```
wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.12.38.tar.xz
wget https://www.kernel.org/pub/linux/kernel/projects/rt/3.12/patch-3.12.38-rt52.patch.gz
```

收到源代码后，需要解压源代码并应用补丁：

```
tar xf linux-3.12.38.tar.xz
cd linux-3.12.38/
gzip -cd ../patch-3.12.38-rt52.patch.gz | patch -p1

```

下一步涉及内核源代码的配置。配置因架构而异，但总体思路保持不变。在 Poky 内支持 QEMU ARM 机器需要以下配置。要为机器启用 PREEMPT_RT 支持，有多种选项可用。您可以实现低延迟支持版本，这对于使用类似于这样的内核配置片段的台式计算机最合适：

```
CONFIG_GENERIC_LOCKBREAK=y
CONFIG_TREE_PREEMPT_RCU=y
CONFIG_PREEMPT_RCU=y
CONFIG_UNINLINE_SPIN_UNLOCK=y
CONFIG_PREEMPT=y
CONFIG_PREEMPT__LL=y
CONFIG_PREEMPT_COUNT=y
CONFIG_DEBUG_PREEMPT=y
CONFIG_RCU_CPU_STALL_VERBOSE=y
```

这个选项是最常用的选项之一，也构成了 PREEMPT_RT 补丁的主要使用来源。另一种选择是使用类似于这样的配置启用 PREEMPT_RT 补丁的全抢占支持：

```
CONFIG_PREEMPT_RT_FULL=y
CONFIG_HZ_1000=y
CONFIG_HZ=1000
```

如果您有兴趣手动配置内核，可以使用`menuconfig`选项。以下`CONFIG_PREEMPT*`配置可更轻松地访问所需的选项。第一个图像主要包含`CONFIG_PREEMPT`和`CONFIG_PREEMPT_COUNT`变量，这应该是启用的第一个变量。还有一个名为`CONFIG_PREEMPT_NONE`的配置选项，用于不强制进行抢占操作。

![应用 PREEMPT_RT 补丁](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00364.jpeg)

在下一个图像中，`CONFIG_PREEMPT_RCU`和`CONFIG_PREEMPT_RT_FULL`配置可用。有关`RCU`的更多信息，请参阅[`lwn.net/Articles/262464/`](https://lwn.net/Articles/262464/)。

![应用 PREEMPT_RT 补丁](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00365.jpeg)

第三个图像包含`CONFIG_PREEMPT__LL`配置。另一个有趣的配置是`CONFIG_PREEMPT_VOLUNTARY`，它与`CONFIG_PREEMPT__LL`配置一起减少延迟，适用于台式计算机。

有关*低延迟台式机*选项的有趣论点可在[`sevencapitalsins.wordpress.com/2007/08/10/low-latency-kernel-wtf/`](https://sevencapitalsins.wordpress.com/2007/08/10/low-latency-kernel-wtf/)找到。

![应用 PREEMPT_RT 补丁](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00366.jpeg)

最后一个包含`CONFIG_TREE_PREEMPT_RCU`配置，用于更改`RCU`实现。可以使用相同的过程搜索和启用其他不包含搜索词的配置。

![应用 PREEMPT_RT 补丁](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00367.jpeg)

有关 PREEMPT_RT 补丁的更多信息，请参阅[`varun-anand.com/preempt.html`](http://varun-anand.com/preempt.html)和[`www.versalogic.com/mediacenter/whitepapers/wp_linux_rt.asp`](http://www.versalogic.com/mediacenter/whitepapers/wp_linux_rt.asp)。

获得了新应用和配置的实时可抢占内核补丁的内核映像后，需要引导它以确保活动被适当地完成，以便最终结果可以被使用。使用`uname –a`命令，`patch rt*`修订号是可见的，并且应该应用于内核版本。当然，还有其他方法可以用来识别这些信息。`uname –a`命令的替代方法是`dmesg`命令，其输出字符串应该可见实时抢占支持，但只需要一种方法就足够了。以下图像提供了`uname –a`命令输出应该是什么样子的表示：

![应用 PREEMPT_RT 补丁](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00368.jpeg)

查看进程列表时，可以看到，如前所述，IRQ 处理程序是使用内核线程处理的。由于它被放置在方括号之间，这些信息在下一个`ps`命令输出中是可见的。单个 IRQ 处理程序由类似于用户空间的`task_struct`结构表示，使它们可以很容易地从用户空间进行控制：

```
ps ax 
PID TTY      STAT   TIME COMMAND 
1 ?        S      0:00 init [2] 
2 ?        S      0:00 [softirq-high/0] 
3 ?        S      0:00 [softirq-timer/0] 
4 ?        S      0:00 [softirq-net-tx/] 
5 ?        S      0:00 [softirq-net-rx/] 
6 ?        S      0:00 [softirq-block/0] 
7 ?        S      0:00 [softirq-tasklet] 
8 ?        S      0:00 [softirq-hrtreal] 
9 ?        S      0:00 [softirq-hrtmono] 
10 ?        S<     0:00 [desched/0] 
11 ?        S<     0:00 [events/0] 
12 ?        S<     0:00 [khelper] 
13 ?        S<     0:00 [kthread] 
15 ?        S<     0:00 [kblockd/0] 
58 ?        S      0:00 [pdflush] 
59 ?        S      0:00 [pdflush] 
61 ?        S<     0:00 [aio/0] 
60 ?        S      0:00 [kswapd0] 
647 ?        S<     0:00 [IRQ 7] 
648 ?        S<     0:00 [kseriod] 
651 ?        S<     0:00 [IRQ 12] 
654 ?        S<     0:00 [IRQ 6] 
675 ?        S<     0:09 [IRQ 14] 
687 ?        S<     0:00 [kpsmoused] 
689 ?        S      0:00 [kjournald] 
691 ?        S<     0:00 [IRQ 1] 
769 ?        S<s    0:00 udevd --daemon 
871 ?        S<     0:00 [khubd] 
882 ?        S<     0:00 [IRQ 10] 
2433 ?        S<     0:00 [IRQ 11] 
[...] 

```

需要收集的下一个信息涉及中断过程条目的格式，这些条目与普通内核使用的条目有些不同。可以通过检查`/proc/interrupts`文件来查看此输出：

```
cat /proc/interrupts 
CPU0 
0:     497464  XT-PIC         [........N/  0]  pit 
2:          0  XT-PIC         [........N/  0]  cascade 
7:          0  XT-PIC         [........N/  0]  lpptest 
10:          0  XT-PIC         [........./  0]  uhci_hcd:usb1 
11:      12069  XT-PIC         [........./  0]  eth0 
14:       4754  XT-PIC         [........./  0]  ide0 
NMI:          0 
LOC:       1701 
ERR:          0 
MIS:          0 

```

然后，第四列中提供的信息提供了 IRQ 线通知，例如：`[........N/ 0]`。在这里，每个点代表一个属性，每个属性都是一个值，如下所述。它们的出现顺序如下：

+   `I (IRQ_INPROGRESS)`: 这指的是活动的 IRQ 处理程序

+   `D (IRQ_DISABLED)`: 这表示 IRQ 被禁用了

+   `P (IRQ_PENDING)`: 这里的 IRQ 被表示为处于挂起状态

+   `R (IRQ_REPLAY)`: 在此状态下，IRQ 已被回复，但尚未收到 ACK

+   `A (IRQ_AUTODETECT)`: 这表示 IRQ 处于自动检测状态

+   `W (IRQ_WAITING)`: 这指的是 IRQ 处于自动检测状态，但尚未被看到

+   `L (IRQ_LEVEL)`: IRQ 处于电平触发状态

+   `M (IRQ_MASKED)`: 这表示 IRQ 不再被视为被屏蔽的状态

+   `N (IRQ_NODELAY)`: 这是 IRQ 必须立即执行的状态

在上面的示例中，可以看到多个 IRQ 被标记为可见和在内核上下文中运行的硬 IRQ。当 IRQ 状态标记为`IRQ_NODELAY`时，它向用户显示 IRQ 的处理程序是一个内核线程，并且将作为一个内核线程执行。IRQ 的描述可以手动更改，但这不是本文将描述的活动。

### 注意

有关如何更改进程的实时属性的更多信息，一个很好的起点是`chrt`工具，可在[`linux.die.net/man/1/chrt`](http://linux.die.net/man/1/chrt)上找到。

## Yocto 项目-rt 内核

在 Yocto 中，应用了带有 PREEMPT_RT 补丁的内核配方。目前，只有两个配方包含了 PREEMPT_RT 补丁；两者都在 meta 层中可用。涉及内核版本 3.10 和 3.14 的配方及其命名为`linux-yocto-rt_3.10.bb`和`linux-yocto-rt_3.14.bb`。命名中的`–rt`表示这些配方获取了 Yocto 社区维护的 Linux 内核版本的 PREEMPT_RT 分支。

这里呈现了 3.14 内核配方的格式：

```
cat ./meta/recipes-kernel/linux/linux-yocto-rt_3.14.bb
KBRANCH ?= "standard/preempt-rt/base"
KBRANCH_qemuppc ?= "standard/preempt-rt/qemuppc"

require recipes-kernel/linux/linux-yocto.inc

SRCREV_machine ?= "0a875ce52aa7a42ddabdb87038074381bb268e77"
SRCREV_machine_qemuppc ?= "b993661d41f08846daa28b14f89c8ae3e94225bd"
SRCREV_meta ?= "fb6271a942b57bdc40c6e49f0203be153699f81c"

SRC_URI = "git://git.yoctoproject.org/linux-yocto-3.14.git;bareclone=1;branch=${KBRANCH},meta;name=machine,meta"

LINUX_VERSION ?= "3.14.19"

PV = "${LINUX_VERSION}+git${SRCPV}"

KMETA = "meta"

LINUX_KERNEL_TYPE = "preempt-rt"

COMPATIBLE_MACHINE = "(qemux86|qemux86-64|qemuarm|qemuppc|qemumips)"

# Functionality flags
KERNEL_EXTRA_FEATURES ?= "features/netfilter/netfilter.scc features/taskstats/taskstats.scc"
KERNEL_FEATURES_append = " ${KERNEL_EXTRA_FEATURES}"
KERNEL_FEATURES_append_qemux86=" cfg/sound.scc cfg/paravirt_kvm.scc"
KERNEL_FEATURES_append_qemux86=" cfg/sound.scc cfg/paravirt_kvm.scc"
KERNEL_FEATURES_append_qemux86-64=" cfg/sound.scc"
```

如图所示，似乎有一个重复的行，需要打补丁来删除它：

```
commit e799588ba389ad3f319afd1a61e14c43fb78a845
Author: Alexandru.Vaduva <Alexandru.Vaduva@enea.com>
Date:   Wed Mar 11 10:47:00 2015 +0100

    linux-yocto-rt: removed duplicated line

    Seemed that the recipe contained redundant information.

    Signed-off-by: Alexandru.Vaduva <Alexandru.Vaduva@enea.com>

diff --git a/meta/recipes-kernel/linux/linux-yocto-rt_3.14.bb b/meta/recipes-kernel/linux/linux-yocto-rt_3.14.bb
index 7dbf82c..bcfd754 100644
--- a/meta/recipes-kernel/linux/linux-yocto-rt_3.14.bb
+++ b/meta/recipes-kernel/linux/linux-yocto-rt_3.14.bb
@@ -23,5 +23,4 @@ COMPATIBLE_MACHINE = "(qemux86|qemux86-64|qemuarm|qemuppc|qemumips)"
 KERNEL_EXTRA_FEATURES ?= "features/netfilter/netfilter.scc features/taskstats/taskstats.scc"
 KERNEL_FEATURES_append = " ${KERNEL_EXTRA_FEATURES}"
 KERNEL_FEATURES_append_qemux86=" cfg/sound.scc cfg/paravirt_kvm.scc"
-KERNEL_FEATURES_append_qemux86=" cfg/sound.scc cfg/paravirt_kvm.scc"
 KERNEL_FEATURES_append_qemux86-64=" cfg/sound.scc"
```

前面的配方与基本配方非常相似。这里，我指的是`linux-yocto_3.14.bb`；它们是应用了 PREEMPT_RT 补丁的配方。它们之间的区别在于每个配方都来自其特定的分支，到目前为止，没有一个带有 PREEMPT_RT 补丁的 Linux 内核版本为`qemumips64`兼容的机器提供支持。

## PREEMPT_RT 补丁的缺点

Linux 是一个针对吞吐量进行优化的通用操作系统，这与实时操作系统的要求完全相反。当然，它通过使用大型、多层缓存提供了高吞吐量，这对于硬实时操作过程来说是一场噩梦。

要实现实时 Linux，有两种可用的选项：

+   第一种方法涉及使用 PREEMPT_RT 补丁，通过最小化延迟并在线程上下文中执行所有活动来提供抢占。

+   第二种解决方案涉及使用实时扩展，这些扩展充当 Linux 和用于管理实时任务的硬件之间的层。这第二种解决方案包括前面提到的 RTLinux、RTAI 和 XENOMAI 解决方案，以及其他商业解决方案和涉及移动层并将其分离为多个组件的变体。

第二个选项的变体意味着各种解决方案，从为实时活动隔离核心到为此类任务分配核心。还有许多解决方案涉及使用虚拟化程序或在 Linux 内核下方提供一定数量的中断服务给 RTOS。这些替代方案的存在不仅为读者提供了其他选项，也是因为 PREEMPT_RT 补丁有其缺点。

一个显著的缺点是通过强制内核在出现更高优先级任务时抢占任务来减少延迟。当然，这会降低系统的吞吐量，因为它不仅在进程中增加了一些上下文切换，而且使较低优先级的任务等待时间比正常的 Linux 内核更长。

`preempt-rt`补丁的另一个缺点是需要将其从一个内核版本移植到另一个内核版本，并从一个架构或软件供应商调整到另一个。这仅意味着特定供应商应该内部具备 Linux 内核的知识，并且应该为其每个可用的内核调整解决方案。这一事实使得它对 BSP 或 Linux 操作系统提供商来说不太受欢迎。

### 注

有关 Linux 抢占的一个有趣演示可在以下链接中找到。可咨询此链接以获取有关 Linux 实时解决方案的更多信息，网址为[`www.slideshare.net/jserv/realtime-linux`](http://www.slideshare.net/jserv/realtime-linux)。

# Linux 实时应用程序

拥有实时操作系统并不总是对每个人都足够。有些人还需要在操作系统上运行经过实时优化的应用程序。为了确保可以设计和与实时应用程序交互，操作系统和硬件上都需要确定性。就硬件配置而言，要求涉及低延迟中断处理。导致 ISR 延迟的机制应该在几十微秒左右。

关于实时应用程序所需的内核配置，需要以下配置：

+   **按需 CPU 缩放**：使用此配置有助于在 CPU 处于低功耗模式时创建长延迟事件。

+   **NOHZ**：此配置禁用 CPU 接收的定时器中断。启用此选项后，CPU 唤醒所花费的延迟将减少。

要编写应用程序，需要注意一些事项，例如确保禁用交换以减少页面错误引起的延迟。全局变量或数组的使用应尽量减少。99 优先级号未配置为运行应用程序，而是使用优先级继承 futexes 而不是其他自旋锁。还要避免输入/输出操作和应用程序之间的数据共享。

对于设备驱动程序，建议有所不同。之前我们提到实时内核的中断处理是在线程上下文中进行的，但硬件中断上下文仍然可以在这里发挥作用。为了从中断处理程序中识别硬件中断上下文，可以使用`IRQF_NODELAY`标志。如果使用`IRQF_NODELAY`上下文，请确保避免使用`wake_up()`、`up()`或`complete()`等函数。

# 基准测试

Linux 操作系统长期以来被视为 GPOS，但在过去几年中，一些项目试图通过修改 Linux 内核成为 RTOS 来改变这一点。其中一个项目是之前提到的 PREEMPT_RT 补丁。

在本章的这一部分，我将讨论一系列测试，这些测试可以针对 Linux OS 的两个版本执行，无论是否应用了 PREEMPT_RT 补丁。我应该提到，对于那些对一些实际结果感兴趣的人，有许多可用的论文试图调查 PREEMPT_RT 的延迟效应或其优缺点。其中一个例子可在[`www.versalogic.com/downloads/whitepapers/real-time_linux_benchmark.pdf`](http://www.versalogic.com/downloads/whitepapers/real-time_linux_benchmark.pdf)找到。

在继续之前，我认为有必要定义一些技术术语，以便正确理解一些信息：

+   **中断延迟**：指中断生成后到中断处理程序中的执行开始之间经过的时间。

+   **调度延迟**：表示事件唤醒信号和调度程序有机会为其安排线程之间的时间。也称为**分派延迟**。

+   **最坏情况延迟**：指发出需求后到接收到该需求的响应之间经过的时间。

+   **上下文切换**：表示 CPU 从一个进程或线程切换到另一个进程或线程。它只发生在内核模式中。

**LPPTest**包含在 PREEMPT_RT 补丁中，它包含一个 Linux 驱动程序，只需更改并行端口上的位值以识别响应时间。另一个驱动程序响应位值的变化，用户空间应用程序测量结果。要执行此测试，需要两台机器：一台用于发送信号，另一台用于接收和发送响应。这一要求很严格，因为使用回环电缆可能会影响测量结果。

**RealFeel**是一个用于中断处理的测试。该程序使用`/dev/rtc`来触发周期性中断，测量一个中断到另一个中断之间的持续时间，并将其与预期值进行比较。最后，它无限期地打印与预期值的偏差，以便将这些变化导出到日志文件中以供以后处理。

Linux 实时基准测试框架（LRTB）代表了一组脚本和驱动程序，用于评估 Linux 内核的各种性能计数器，并添加了实时功能。它测量了实时补丁所施加的负载，以及它们获取更确定性中断响应的能力。

在基准测试阶段，可以使用`hackbench`、`lmbench`或甚至`Ingo Molnar dohell`脚本等程序。当然，还有许多其他工具可用于测试（`cyclictest`、`hourglass`等）或基准测试（`unixbench`、`cache-calibrator`或任何将实时性能推至极限的其他压力测试），但我会让用户测试并应用最适合他们需求的工具。

PREEMPT_RT 补丁提高了 Linux 内核的抢占性，但这并不意味着它是最好的解决方案。如果应用领域的各个方面发生变化，PREEMPT_RT 补丁的有用性可能会有所不同。关于 PREEMPT_RT 补丁，它已经准备好在硬实时系统中使用。不能得出一个结论，但我必须承认，如果它用于维持生命或任务关键系统，它可以被认为是硬实时材料。这是每个人都要做出的决定，因此需要进行测试。支持这一观点的一个意见来自 Steven Rostedt，他是 Linux 内核开发人员，也是红帽公司实时 Linux 内核补丁稳定版本的维护者。该信息可以在[`www.linux.com/news/featured-blogs/200-libby-clark/710319-intro-to-real-time-linux-for-embedded-developers`](http://www.linux.com/news/featured-blogs/200-libby-clark/710319-intro-to-real-time-linux-for-embedded-developers)上找到。

### 注意

关于这个问题的一些有趣信息可以在[`elinux.org/Realtime_Testing_Best_Practices`](http://elinux.org/Realtime_Testing_Best_Practices)上找到。

# 元实时

`meta-realtime`层是由 WindRiver 的 Bruce Ashfield 维护的一个倡议，旨在创建一个与 Linux 内核或系统开发相关的实时活动的场所。它被创建为 PREEMPT_RT、SCHED_DEADLINE、POSIX 实时和通用操作系统和实时操作系统的替代配对的占位符，无论这涉及用户空间 RTOS、虚拟机监视程序还是 AMP 解决方案。此外，这也是系统分区、CPU 隔离和其他相关应用程序的所在地。当然，如果没有为整个 Linux 操作系统提供一些性能分析和基准测试应用程序，这一切都不会被认为是完整的。

虽然这个层描述起初听起来很激动人心，但其内容实际上非常贫乏。它只能整合一些测试工具，更准确地说，其中两个是`schedtool-dl`和`rt-app`，以及额外的脚本，试图在目标机器上远程运行`rt-app`并收集结果数据。

第一个`schedtool-dl`应用是一个用于截止时间调度的调度器测试工具。它出现的原因是需要在 Linux 下更改或查询 CPU 调度策略，甚至是进程级别。它还可以用于在 SMP/NUMA 系统上锁定各种 CPU 上的进程，以避免音频/视频应用程序中的跳过，并且通常可以在高负载下保持高水平的交互和响应能力。

### 注意

有关`schedtool-dl`应用程序的更多信息可以在[`github.com/jlelli/schedtool-dl`](https://github.com/jlelli/schedtool-dl)上找到。

下一个也是最后一个可用的应用是`rt-app`，它用作系统上实时负载的模拟测试应用程序。它通过在给定时间段启动多个线程来实现这一点。它支持 SCHED_FIFO、SCHED_OTHER、SCHED_RR、SCHED_DEADLINE，以及**自适应服务质量架构**（**AQuoSA**）框架，这是一个旨在为 Linux 内核提供自适应**服务质量**（**QoS**）的开源项目。

### 注意

有关`rt-app`应用程序和 AQuoSa 框架的更多信息可以在[`github.com/scheduler-tools/rt-app`](https://github.com/scheduler-tools/rt-app)和[`aquosa.sourceforge.net/`](http://aquosa.sourceforge.net)上找到。

除了包含的软件包外，该层还包含一个集成了它们的镜像，但这远远不足以使该层包含实质性内容。虽然它内部并不包含大量信息，但本章将介绍该层，因为它包含了起点，并提供了迄今为止所呈现的所有信息的发展视角。当然，应该驻留在该层中的一些应用程序已经分布在多个其他层中，比如`meta-linaro`中可用的`idlestat`软件包。然而，这并不构成本解释的核心。我只想指出可以包含任何实时相关活动的最合适的地方，而在我看来，`meta-realtime`就是这个地方。

# 总结

在本章中，您对 PREEMPT_RT 和 Linux 内核实时问题的其他替代解决方案进行了简要介绍。我们还探讨了一些可用于相关实时活动的工具和应用程序。然而，如果不提及 Yocto 项目，不仅涉及到 PREEMPT_RT Linux 内核的配方，还涉及`meta-realtime`层的应用程序，这个介绍就不完整。开发适用于新环境的应用程序也是一个关注点，因此在*Linux 实时应用程序*部分解决了这个问题。最后，我希望通过本章中提供的链接来呈现这个主题的完整画面，以激发读者的好奇心。

在下一章中，将对`meta-security`和`meta-selinux`层进行简要解释，并提供 Linux 生态系统和 Yocto 项目的安全需求的更广泛视角。还将介绍一些旨在保护我们的 Linux 系统的工具和应用程序的信息，但这还不是全部。看看下一章吧；我相信你会喜欢它。


# 第十一章：安全

在本章中，您将了解各种安全增强工具。我们首先来到 Linux 内核，在这里，有两个工具，SELinux 和 grsecurity，这两个工具都非常有趣，也非常必要。接下来，将解释 Yocto 项目的安全特定层。这包括包含大量工具的 meta-security 和 meta-selinux，可用于保护或审计 Linux 系统的各个组件。由于这个主题很广泛，我还会让您检查各种其他解决方案，既在 Linux 内核中实施，也在外部实施。希望您喜欢本章，并且觉得这些信息有趣且有用。

在任何操作系统中，安全性对用户和开发人员都是一个非常重要的关注点。开发人员已经开始以各种方法解决这些安全问题。这导致了许多可用操作系统的安全方法和改进。在本章中，将介绍一些安全增强工具，以及一些旨在确保各种组件（如 Linux 内核或 Yocto 项目）足够安全以供使用的策略和验证例程。我们还将看看在本章进行过程中如何处理各种威胁或问题。

SELinux 和 grsecurity 是对 Linux 内核进行的两项显著的安全改进，试图强制执行 Linux。SELinux 是一种强制访问控制（MAC）机制，提供基于身份和角色的访问控制，以及域类型强制。第二个选择 grsecurity 更类似于 ACL，并且实际上更适合支持远程连接的 Web 服务器和其他系统。关于 Linux 的安全实现以及 Yocto 项目如何处理这个领域，这些方面将在下一节中介绍。我必须承认的一件事是，在撰写本章时，Yocto 项目内部的安全处理仍然是一个年轻的项目，但我怀着热情期待看到迭代次数随着时间的推移而增加。

# Linux 中的安全

在每个 Linux 系统的核心是 Linux 内核。任何能够损害或控制系统的恶意代码也会对影响 Linux 内核产生影响。因此，用户清楚地知道，拥有一个安全的内核也是方程式的重要部分。幸运的是，Linux 内核是安全的，并且具有许多安全功能和程序。所有这些背后的人是 James Morris，Linux 内核安全子系统的维护者。甚至还有一个专门的 Linux 存储库，可以在[`git.kernel.org/?p=linux/kernel/git/jmorris/linux-security.git;a=summary`](http://git.kernel.org/?p=linux/kernel/git/jmorris/linux-security.git;a=summary)上访问。此外，通过检查[`kernsec.org/wiki/index.php/Main_Page`](http://kernsec.org/wiki/index.php/Main_Page)，即 Linux 内核安全子系统的主页，您可以看到在该子系统内部管理的确切项目，并且如果感兴趣，也许可以帮助他们。

还有一个工作组，为 Linux 内核提供安全增强和验证，以确保其安全性，并在 Linux 生态系统的安全性方面保持一定水平的信任。他们的活动包括但不限于对各种漏洞进行验证和测试，或开发辅助安全 Linux 内核的工具。该工作组还包括对安全子系统的指导和维护，或者对各种项目或构建工具添加的安全改进。

所有其他 Linux 软件组件都有自己的安全团队。当然，有些软件组件没有明确定义这些团队，或者有一些与此主题相关的内部规则，但它们仍然意识到围绕其组件发生的安全威胁，并尝试修复这些漏洞。Yocto 项目试图帮助解决这些问题，并在某些方面统一这些软件组件。我希望在这个领域的一些改进会在未来几年内实现。

# SELinux

SELinux 是 Linux 内核的安全增强功能，由国家安全局信息保障办公室开发。它具有基于策略的架构，是建立在**Linux 安全模块**（**LSM**）接口上的 Linux 安全模块之一，旨在实现军事级别的安全性。

目前，它已经随着大量的发行版一起发布，包括最知名和经常使用的发行版，如 Debian、SuSe、Fedora、Red Hat 和 Gentoo。它基于 MAC，管理员可以控制系统用户空间组件的所有交互。它使用最小权限的概念：在这里，默认情况下，用户和应用程序没有权限访问系统资源，因为所有这些权限都是由管理员实体授予的。这构成了系统安全策略的一部分，其重点显示在以下图中：

![SELinux](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00369.jpeg)

SELinux 内部的基本功能通过 MAC 的实现进行了隔离。在沙盒中，每个应用程序只允许执行其设计为在安全策略中定义的任务。当需要访问时，当然，标准的 Linux 权限仍然适用于系统，并且在策略之前将进行咨询。如果没有权限可用，SELinux 将无法以任何方式影响系统。但是，如果权限允许访问，则应咨询 SELinux 策略以提供最终的许可或拒绝访问的裁决。

在 SELinux 的上下文中，访问决策是基于主体的安全上下文进行的。这可能是与特定用户上下文相关联的进程，该进程与实际尝试的操作（例如文件读取操作）进行比较，以及可用对象的安全上下文，该对象可以是文件。

在继续之前，我们将看看如何在 Ubuntu 机器上启用 SELinux 支持。我将首先介绍一些与 SELinux 相关的基本概念：

+   **用户**：在 SELinux 上下文中，用户与 UNIX 上下文中的用户不同。它们之间的主要区别在于，在 SELinux 上下文中，用户在用户会话期间不会改变，并且有可能有更多的 UNIX 用户在相同的 SELinux 用户上下文中操作。然而，也有可能进行 1:1 用户映射的操作，例如 Linux 根用户和 SELinux 根用户。通常，SELinux 用户的命名中会添加`_u`后缀。

+   **角色**：SELinux 用户可以拥有一个或多个角色。角色的含义在策略中定义。对象通常具有`object_r`角色，角色通常以`_r`字符串结尾。

+   **类型**：这是应用授权决策的主要方法。它也可以被称为域，通常以`_t`结尾。

+   **上下文**：每个进程和对象都有自己的上下文。实际上，它是一个属性，确定是否应该允许对象和进程之间的访问。SELinux 上下文表示为三个必需字段和一个可选字段，例如`user:role:type:range`。前三个字段代表 SELinux 用户、角色和类型。最后一个代表 MLS 的范围，稍后将介绍。有关 MLS 的更多信息，请参阅[`web.mit.edu/rhel-doc/5/RHEL-5-manual/Deployment_Guide-en-US/sec-mls-ov.html`](http://web.mit.edu/rhel-doc/5/RHEL-5-manual/Deployment_Guide-en-US/sec-mls-ov.html)。

+   **对象类**：一个 SELinux 对象类表示可用对象的类别。类别，如`dir`表示目录，`file`表示文件，还有一组与它们相关的权限。

+   **规则**：这些是 SELinux 的安全机制。它们被用作一种强制执行，并且是使用对象和进程的类型来指定的。规则通常说明了一个类型是否被允许执行各种操作。

如前所述，SELinux 非常出名和受人赞赏，以至于它被包含在大多数可用的 Linux 发行版中。它的成功也通过大量关于这个主题的书籍得到了证明。有关更多信息，请参阅[`www.amazon.com/s/ref=nb_ss_gw/102-2417346-0244921?url=search-alias%3Daps&field-keywords=SELinux&Go.x=12&Go.y=8&Go=Go`](http://www.amazon.com/s/ref=nb_ss_gw/102-2417346-0244921?url=search-alias%3Daps&field-keywords=SELinux&Go.x=12&Go.y=8&Go=Go)。说到这一点，让我们来看看在 Ubuntu 主机上安装 SELinux 所需的步骤。第一步是安装 SELinux 软件包：

```
sudo apt-get install selinux

```

安装软件包后，需要将 SELinux 模式从禁用（不执行或记录 SELinux 策略的模式）更改为其他两个可用选项之一：

+   `强制执行`：这在生产系统中最有用：

```
sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config 

```

+   `宽容`：在此模式下，策略不会被执行。但是，任何拒绝都会被记录下来，主要用于调试活动和开发新策略时：

```
sudo sed -i 's/SELINUX=.*/SELINUX=permissive/' /etc/selinux/config

```

配置实施后，系统需要重新启动，以确保系统文件被正确标记。

有关 SELinux 的更多信息也可以在 Yocto 项目中找到。有一个专门的层专门支持 SELinux。此外，有关此工具的更多信息，建议阅读专门讨论此问题的书籍之一。如果您不喜欢这种方法，那么还有其他手册提供与 SELinux 相关的信息，可在各种发行版中找到，如 Fedora ([`docs.fedoraproject.org/en-US/Fedora/19/html/Security_Guide/ch09.html`](https://docs.fedoraproject.org/en-US/Fedora/19/html/Security_Guide/ch09.html))，Red Hat ([`access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/4/html/SELinux_Guide/index.html`](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/4/html/SELinux_Guide/index.html))等。

# Grsecurity

Grsecurity 是一个补丁套件，根据 GNU 通用公共许可证发布，适用于 Linux 内核，并将有助于增强 Linux 的安全性。这个补丁套件提供了四个主要的好处：

+   无需配置的操作

+   保护免受各种地址空间更改错误的影响

+   它包括一个访问控制列表系统和一些相当全面的审计系统，以满足各种需求

+   它能够与多个操作系统和处理器架构进行交互

grsecurity 软件是免费的，其开发始于 2001 年，首先从 Openwall 项目移植了一些增强安全性的补丁。它首次发布于 2.4.1 Linux 内核版本，自那时以来，开发一直在进行。随着时间的推移，它包括了一个 PaX 捆绑补丁，提供了保护内存页面的可能性。这是通过使用最小特权方法来完成的，这意味着在执行程序时，应该采取的操作不应超过必要的行动，借助额外或更少的步骤。

### 注意

如果您对了解更多有关 PaX 的信息感兴趣，可以访问[`en.wikipedia.org/wiki/PaX`](http://en.wikipedia.org/wiki/PaX)和[`pax.grsecurity.net/`](https://pax.grsecurity.net/)。

Grsecurity 具有许多功能，主要适用于 Web 服务器或接受来自不受信任用户的 shell 访问的服务器。其中一个主要功能是**基于角色的访问控制**（**RBAC**），它是已有的 UNIX **自主访问控制**（**DAC**）的替代方案，甚至是由 Smack 或 SELinux 提供的强制访问控制（MAC）。RBAC 的目标是提供最少特权系统，其中进程和用户只具有完成任务所需的最低特权。grsecurity 的另一个功能与加固`chroot()`系统调用有关，以确保消除特权升级。除此之外，还有一些其他功能，如审计和`/proc`限制。

我已经将 grsecurity 的功能分组保留在章节中，因为我认为了解其功能将有助于用户和开发人员在需要安全解决方案时做出正确的决定。以下是所有 grsecurity 功能的列表：

+   内存损坏防御：

+   自动响应暴力利用

+   针对喷洒攻击的加固 BPF JIT

+   加固的用户空间内存权限

+   线程堆栈之间的随机填充

+   防止内核直接访问用户空间

+   行业领先的 ASLR

+   内核边界检查复制到/从用户空间

+   文件系统加固：

+   Chroot 加固

+   消除针对管理员终端的侧信道攻击

+   防止用户欺骗 Apache 访问其他用户文件

+   隐藏非特权用户的进程

+   提供可信路径执行

+   其他保护：

+   防止基于 ptrace 的进程窥探

+   防止无法读取的二进制文件转储

+   防止攻击者自动加载易受攻击的内核模块

+   拒绝访问过于宽松的 IPC 对象

+   强制一致的多线程特权

+   RBAC：

+   直观的设计

+   自动完整系统策略学习

+   自动策略分析

+   人类可读的策略和日志

+   与 LSM 堆叠

+   非常规功能

+   GCC 插件：

+   防止大小参数中的整数溢出

+   防止从先前的系统调用中泄漏堆栈数据

+   在早期引导和运行时增加熵

+   随机化内核结构布局

+   使只读敏感内核结构

+   确保所有内核函数指针指向内核

牢记 grsecurity 的功能，我们现在可以进入 grsecurity 的安装阶段和其名为`gradm`的管理员。

需要做的第一件事是获取相应的软件包和补丁。如下所示，启用 grsecurity 的内核版本为`3.14.19`：

```
wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.14.19.tar.gz
wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.14.19.tar.sign
wget http://grsecurity.net/stable/gradm-3.1-201502222102.tar.gz
wget http://grsecurity.net/stable/gradm-3.1-201502222102.tar.gz.sig
wget http://grsecurity.net/stable/grsecurity-3.1-3.14.36-201503182218.patch
wget http://grsecurity.net/stable/grsecurity-3.1-3.14.36-201503182218.patch.sig

```

软件包可用后，需要检查其签名。Linux 内核的签名检查过程很大，与其他系统不同，如下所示：

```
wget http://grsecurity.net/spender-gpg-key.asc
sudo gpg --import spender-gpg-key.asc
sudo gpg --verify gradm-3.1-201502222102.tar.gz.sig
sudo gpg --verify grsecurity-3.1-3.14.35-201503092203.patch.sig
gzip -d linux-3.14.19.tar.gz
sudo gpg --verify linux-3.14.19.tar.sign

```

第一次调用此命令时，不会验证签名，但 ID 字段将可供以后使用。它用于从 PGP 密钥服务器识别公钥：

```
gpg: Signature made Mi 17 sep 2014 20:20:53 +0300 EEST using RSA key ID 6092693E
sudo gpg --keyserver hkp://keys.gnupg.net --recv-keys 6092693E
sudo gpg --verify linux-3.14.19.tar.sign

```

在所有软件包都可用且经过适当验证后，我们现在可以进入内核配置阶段。第一步是修补过程，使用 grsecurity 补丁完成，但这首先需要访问 Linux 内核源代码：

```
tar xf linux-3.14.19.tar 
cd linux-3.14.19/
patch -p1 < ../grsecurity-3.1-3.14.35-201503092203.patch

```

在修补过程中，源代码中缺少`include/linux/compiler-gcc5.h`，因此需要跳过此部分。然而，在此之后，修补过程顺利完成。完成此步骤后，配置阶段可以继续。有一些通用配置应该可以在不进行任何额外修改的情况下工作，但对于每个发行版，总会有一些特定的配置可用。可以使用以下命令来查看它们，并确保每个配置与您的硬件匹配：

```
make menuconfig

```

如果您是第一次调用它，前面的命令会有一个警告消息，提示您如下：

```
HOSTCC  scripts/basic/fixdep
HOSTCC  scripts/kconfig/conf.o
 *** Unable to find the ncurses libraries or the
 *** required header files.
 *** 'make menuconfig' requires the ncurses libraries.
 *** 
 *** Install ncurses (ncurses-devel) and try again.
 *** 
make[1]: *** [scripts/kconfig/dochecklxdialog] Error 1
make: *** [menuconfig] Error 2

```

可以通过安装`libncurses5-dev`软件包来解决这个问题，使用以下命令：

```
sudo apt-get install libncurses5-dev

```

有了这些问题解决后，配置过程可以继续。`grsecurity`选项位于安全选项子菜单中，如下截图所示：

![Grsecurity](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00370.jpeg)

在`grsecurity`选项中，还有两个子菜单选项。有关此的更多详细信息可以在以下截图中看到：

![Grsecurity](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00371.jpeg)

第一个选项是配置方法，可以是**自定义**或**自动**：

![Grsecurity](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00372.jpeg)

第二个选项是实际可用的配置选项：

![Grsecurity](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00373.jpeg)

### 注意

有关 Grsecurity 和 PaX 配置选项的更多信息可以在[`en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options`](http://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options)找到。

我想提供的一个建议是，首先启用**自动**配置方法，然后再进行自定义配置，以微调 Grsecurity 和 PaX 设置（如果需要）。另一个提示是启用**Grsecurity** | **自定义配置** | **Sysctl 支持**选项，因为它提供了在不重新编译内核的情况下更改 grsecurity 选项的可能性。当然，如果选择了**自动**配置方法，则此选项默认启用。审计选项会产生大量日志，为了防止日志泛滥，请确保**Grsecurity** | **自定义配置** | **日志选项**也已启用。

grsecurity 家族的下一个工具是`gradm`管理员，它是 ACL 的强大解析器，也对其进行优化。为了确保可以安装此实用程序，安装过程要求`gradm`的主机操作机器提供 grsecurity 支持，否则编译过程将失败。在安装`gradm`之前还需要一些其他软件包：`lex`、`flex`、`byacc`、`bison`，甚至`pam`（如果需要）。

一旦满足了所有依赖关系，安装过程就可以开始了。我想给你的最后一点信息是，如果您使用的发行版带有对 grsecurity 补丁的内核支持，那么您可能首先要检查它，因为补丁也可能预先安装了`gradm`实用程序。

### 注意

有关 Grsecurity 管理的更多信息可以在以下链接找到：

[`en.wikibooks.org/wiki/Grsecurity/The_Administration_Utility`](http://en.wikibooks.org/wiki/Grsecurity/The_Administration_Utility)

[`en.wikibooks.org/wiki/Grsecurity/Additional_Utilities`](http://en.wikibooks.org/wiki/Grsecurity/Additional_Utilities)

[`en.wikibooks.org/wiki/Grsecurity/Runtime_Configuration`](http://en.wikibooks.org/wiki/Grsecurity/Runtime_Configuration)

在 Yocto 层中，支持`meta-oe`层内的`gradm`配方。它位于主分支的`recipes-support/gradm/gradm_3.0.bb`。此外，`meta-accel`层的主分支上提供了 grsecurity 内核配置；配置片段的确切位置是`recipes-kernel/linux/linux-yocto-iio/grsec.cfg`。对于任何对 Yocto 中提供的具体 grsecurity 支持感兴趣的人，我相信你可以开始着手做这件事。不过，我建议你首先向 Yocto 项目社区询问是否已经有人开始做这件事。

# Yocto 项目的安全性

在 Yocto 项目中，安全问题仍然很年轻。由于该项目宣布不到五年，讨论安全问题是很正常的，最近一年左右才开始。当然，安全团队有专门的邮件列表，其中包括来自各个公司的大量成员，但他们的工作程序还没有完全完成，因为目前仍处于进行中的状态。

安全团队成员主要开展的活动包括了解最新和最危险的安全威胁，并确保找到修复方法，即使包括自己修复并应用更改到 Yocto 的可用层内。

目前，安全活动中最耗时的是围绕 Poky 参考系统展开的，但也有各个公司采取的倡议，试图向各种 BSP 维护层或其他第三方层推送一系列补丁。对于感兴趣的人，与安全相关的讨论邮件列表是`<yocto-security@yoctoproject.org>`。此外，在团队形成之前，他们可以在`#yocto` IRC 上找到，网址是[`webchat.freenode.net/?channels=#yocto`](http://webchat.freenode.net/?channels=#yocto)，甚至可以参加每两周举行一次的 Yocto 技术团队会议。

### 注意

有关安全团队的更多信息可以在其 Wiki 页面上找到。我鼓励所有对这个主题感兴趣的人至少访问一次[`wiki.yoctoproject.org/wiki/Security`](https://wiki.yoctoproject.org/wiki/Security)。

# Meta-security 和 meta-selinux

在这一部分，介绍了与 Linux 安全工具相关的层倡议。在这一章中，为 Linux 内核及其库提供安全和硬化工具的两个层可供使用。它们的目的是简化嵌入式设备的模式，确保它们是安全的，并可能提供类似桌面的安全级别。

由于嵌入式设备变得越来越强大，与安全相关的问题只能是自然而然的。 Yocto 项目的倡议层，我指的是 meta-security 和 meta-selinux，在简化确保安全、硬化和保护 Linux 系统的过程中迈出了另一步。与检测和修复漏洞系统一起，它们被实施在安全团队内部，并有助于在嵌入式设备上实现与桌面相同级别的安全性，并进一步推动这一理念。话虽如此，让我们继续讲解层的实际内容。

## Meta-security

在 meta-security 层中，有一些工具用于保护、加固和保护嵌入式设备，这些设备可能向各种实体提供外部访问。如果设备连接到互联网或容易受到任何形式的攻击或劫持，那么 meta-security 层可能是您的第一站。通过这一层和 meta-selinux 层，Yocto 项目试图为大多数社区或嵌入式用户设备提供适当的安全级别。当然，增强对各种工具的支持或添加新工具并不是被禁止的，所以如果您感到需要或有冲动，不要犹豫，为增强工具做出您的贡献。欢迎任何新的提交或提交者-我们的社区真的很友好。

正如您已经习惯的那样，提供的工具是适用于嵌入式设备的开源软件包。在 meta-security 层中，有许多可用的软件包，每个软件包都试图提供不仅系统加固，还有安全检查、安全、端口扫描和其他针对各种安全级别的有用功能。包括以下软件包：

+   Bastille

+   Redhat-security

+   Pax-utils

+   Buck-security

+   Libseccomp

+   Ckecksecurity

+   Nikto

+   Nmap

+   Clamav

+   Isic

+   Samhain

+   Suricata

+   Tripwire

除了这些软件包，还有许多库和**TOMOYO**，一个用于 MAC 实现的内核安全模块，也非常有用作为系统分析工具。它于 2003 年 3 月首次发布，并由日本 NTT 数据公司赞助，直到 2012 年 3 月。

TOMOYO 的主要关注点是系统行为。为此，参与系统创建的每个进程都声明了其行为和实现目的所需的必要资源。它由两个组件组成：一个内核组件，linux-ccs，和一个用户空间组件，ccs-tools；两者都需要才能正常运行。TOMOYO 试图提供一个既实用又易于使用的 MAC 实现。最后，它希望让系统对大多数用户可用，非常适合普通用户和系统管理员。它与 SELinux 不同，因为它具有**LEARNING 模式**提供的自动策略配置机制；此外，它的策略语言非常容易理解。

启用保护后，TOMOYO Linux 充当一个看门狗，限制进程使用超出其最初声明的资源。其主要特点包括以下内容：

+   系统分析

+   提供策略生成过程中的辅助工具

+   简单易用的语法

+   易于使用

+   通过 MAC 实现增强系统安全性

+   包含少量依赖项（嵌入式 GNU C 库、libncurses 和 GNU readline 库）

+   不修改根文件系统中已有的二进制文件

+   自 2.6.30 版本以来，Linux 内核与 TOMOYO 内核模块合并，只需要在配置阶段启用模块即可。它起初是一个提供 MAC 支持的补丁，将其移植到主线内核需要使用**LSM**（Linux 安全模块）的钩子，其中还包括 SELinux、AppArmor 和 SMACK。然而，由于需要更多的钩子来集成剩余的 MAC 功能，因此该项目有另外两条并行的开发线：

+   **TOMOYO Linux 1.x**：这是原始代码版本：

+   它使用非标准的特定钩子

+   它提供了所有的 MAC 功能

+   它作为内核的补丁发布，因为它不依赖于 LSM

+   其最新版本为 1.7.1

+   TOMOYO Linux 2.x：这是主线源代码版本：

+   它使用标准的 LSM 钩子

+   它包含了更少的功能子集

+   它是 2.6.30 Linux 内核版本的一个组成部分

+   最新版本是 2.5.0，支持 Linux 内核版本 3.2

+   **AKARI 和 TOMOYO 1.x 分支版本**：

+   它还使用标准的 LSM 钩子

+   它的特点是与 TOMOYO 1.x 相比具有较少的功能，但与 TOMOYO 2.x 不同。

+   它作为 LSM 发布；不需要重新编译内核

### 注意

对于那些对三个版本进行比较感兴趣的人，请参阅[`akari.sourceforge.jp/comparison.html.en`](http://akari.sourceforge.jp/comparison.html.en)。

下一个软件包是`samhain`，这是一个系统完整性监控和报告工具，由系统管理员使用，用于怀疑系统上的更改或活动。它的操作基于客户端/服务器环境，并能够监视多个主机，同时提供集中的维护和日志记录系统。除了已经宣传的功能外，它还能提供端口监控、检测恶意 SUID、rootkit 检测，以及隐藏进程，这使得它支持多个平台；这是一个非常有趣的工具。

这里的下一个元素属于与`samhain`相同的类别，称为`tripwire`。这是另一个完整性工具，但它试图检测文件系统对象的更改，并作为主机入侵检测系统工作。在每次文件扫描后，信息都存储在数据库中，并与已有结果进行比较。任何进行的更改都会向用户报告。

**Bastille**是一个用于保护 Unix 主机环境和系统的加固程序。它使用规则来实现其目标，首先通过调用`bastille -c`命令，让您通过一长串问题。回答完后，将创建并执行一个配置文件，这意味着您的操作系统现在根据您的需求已经加固。如果系统上已经有一个配置文件，可以通过调用`bastille -b`来设置系统加固。

下一个工具是`redhat-security`，它是一组用于与安全扫描相关的各种问题的脚本集合。以下是运行`redhat-security`脚本所需的工具集合，只需在终端中调用一个脚本：

+   `find-chroot.sh`：此工具扫描整个系统以查找调用`chroot`并包括对`chdir`的调用的 ELF 文件。未通过此测试的程序不包含`chroot`内的`cwd`，它们不受保护，不安全。

+   `find-chroot-py.sh`：此工具类似于前面的工具，但仅测试 Python 脚本。

+   `rpm-chksec.sh`：此工具接受一个 rpm 文件，并检查其编译标志。出于安全原因进行此操作。如果结果是绿色，则一切正常，黄色表示可以接受，红色需要用户注意。

+   `find-nodrop-groups.sh`：此工具扫描整个系统，查找在不调用`setgroups`和`initgroups`调用的情况下更改 UID 或 GID 的程序。

+   `rpm-drop-groups.sh`：此工具类似于前一个工具，但这个工具使用可用的 RPM 文件。

+   `find-execstack.sh`：此工具扫描整个系统以查找将堆栈标记为可执行的 ELF 文件。它用于识别易受堆栈缓冲区溢出攻击的程序。

+   `find-sh4errors.sh`：此工具扫描整个系统以查找 shell 脚本，并使用`sh -n`命令检查其正确性。

+   `find-hidden-exec.sh`：此工具扫描系统以查找隐藏的可执行文件，并将结果报告给用户进行调查。

+   `selinux-ls-unconfined.sh`：此工具用于扫描所有运行中的进程，并查找其中的`initrc_t`标签或`inetd`（这意味着它们是运行不受限制的守护进程）。问题应报告为 SELinux 策略问题。

+   `selinux-check-devides.sh`：此工具检查所有可用设备，以查看它们是否正确标记。它也被标记为应该解决的 SELinux 策略问题。

+   `find-elf4tmp.sh`：此工具扫描整个系统，并检查所使用的`tmp`文件是否为众所周知，是否使用`mktemp`创建，或者是否具有某种模糊的格式。

+   `find-sh3tm.sh`：此工具还扫描文件系统，尽管仅在`/tmp`内部查找 ELF 文件。当找到它们时，它会检查是否通过调查符号表对它们中的任何随机名称生成器函数进行了调用。如果结果是肯定的，它将输出字符串值。

+   `lib-bin-check.sh`：此工具检查库的软件包及其包含的软件包。它基于这样一个想法，即系统上可用的二进制文件越少，系统就越安全。

另一个包含的工具是`pax-utils`。它还包括一些用于扫描 ELF 二进制文件的脚本，主要用于一致性检查，但这并非全部。看一下其中一些：

+   `scanelf`：此工具用于查找有关二进制文件的 ELF 结构的预先信息

+   `dumpelf`：此工具是一个用户空间实用程序，用于以等效的 C 结构转储内部 ELF 结构，用于调试或参考目的

+   `pspax`：此工具用于扫描`/proc`并列出各种可用的 ELF 类型及其对应的 PaX 标志、属性和文件名

现在，接下来要介绍的工具是一种与已经介绍的 bastille 不同的安全扫描器。与`redhat-security`命令类似，这个命令也执行一些脚本，并可以根据用户的需求进行配置。它适用于 Debian 和 Ubuntu 用户，在调用 buck-security 可执行文件之前，需要进行一些配置。使用`export GPG_TTY=`tty``来确保启用 buck-security 的所有功能，并在执行该工具之前，检查`conf/buck-security.conf`配置文件，以确保满足您的需求。

**Suricata**是一个用于网络的高性能 IDS/IPS 和安全监控引擎。它由**OISF**（**Open Information Security Foundation**）及其支持者拥有和维护。它使用**HTP**库，这是一个非常强大的 HTTP 解析器和标准化器，并提供一些不错的功能，如协议识别、MD5 校验和文件识别等。

另一方面，**ISIC**正如其名字所示，是一个 IP 堆栈完整性检查器。实际上，它是一套用于 IP 堆栈和其他堆栈（如 TCP、ICMP、UDP 等）的实用程序，用于测试防火墙或协议本身。

对于任何 Web 服务器，**nikto**是在您的设备上执行的工具。它是一个用于运行一系列测试的扫描程序，用于识别危险的 CGI1 或其他文件。它还为超过 1250 个服务器的过时版本和每个版本的各种漏洞提供了列表。

接下来是**libseccomp**库，它提供了一个易于使用的抽象接口到 Linux 内核的`syscall`过滤机制，称为`seccomp`。它通过将 BPF `syscall`过滤语言抽象化，并以更用户友好的格式呈现给应用程序开发人员来实现这一点。

**Checksecurity**是下一行的包，它使用一系列 shell 脚本和其他插件来测试对`setuid`程序的各种更改。使用`/etc/checksecurity.conf`中定义的过滤器，它扫描已挂载的文件系统，并将已有的`setuid`程序列表与新扫描的程序进行比较，并将更改打印给用户查看。它还提供有关这些已挂载不安全文件系统的信息。

**ClamAV**是 Unix 的一种命令行操作的防病毒软件。它是一个非常好的引擎，用于跟踪木马、恶意软件、病毒和其他恶意威胁的检测。它可以做很多事情，从电子邮件扫描到网络扫描和端点安全。它还具有非常多功能和可扩展的守护程序、命令行扫描程序和数据库交互工具。

列表中的最后一个是**网络映射器**（**nmap**）。这是最著名的安全审计工具，也是网络和系统管理员用于网络发现的工具。它用于管理服务升级计划、网络清单、监控各种服务，甚至主机的正常运行时间。

这些是 meta-security 层内支持和提供的工具。我在简洁的方式中介绍了大部分工具，目的是让它们以简单的方式对您可用。我认为对于安全问题，不应该过于复杂，只保留最适合您需求的解决方案。通过提供大量工具和软件组件，我试图做两件事：为公众提供更多的工具，并帮助您在寻求提供甚至维护安全系统的过程中做出决策。当然，鼓励好奇心，所以请确保您查看任何其他可能帮助您了解更多安全信息的工具，以及为什么它们不应该集成到 meta-security 层内。

## Meta-selinux

另一个可用的安全层由 meta-selinux 层表示。这与 meta-security 不同，因为它只支持一个工具，但正如前面的工具所述，它是如此庞大和广泛，以至于它将其翅膀展开到整个系统。

该层的目的是支持 SELinux 并通过 Poky 向 Yocto Project 社区中的任何人提供使用。正如之前提到的，由于它影响整个 Linux 系统，因此该层的大部分工作都是在 bbappend 文件中完成的。我希望您喜欢使用该层内可用的功能，并且如果您认为合适，甚至可以为其做出贡献。

这一层不仅包含许多令人印象深刻的 bbappend 文件，还提供了一系列不仅可以用作 SELinux 扩展的软件包。这些软件包也可以用于其他独立的目的。meta-selinx 层中可用的软件包如下：

+   audit

+   libcap-ng

+   setools

+   swig

+   ustr

我将从**audit**用户空间工具开始介绍这一层，正如其名称所示，这是一个用于审计的工具，更具体地说是用于内核审计。它使用多种实用程序和库来搜索和存储记录的数据。数据是通过 Linux 内核中可用的审计子系统生成的。它被设计为一个独立的组件，但如果没有第二个安全组件可用，它就无法提供**公共标准**（**CC**）或**FIPS 140-2**功能。

列表中的下一个元素是**libcap-ng**，这是一个替代库，具有简化的 POSIX 功能，可以与传统的 libcap 解决方案进行比较。它提供了分析运行应用程序并打印其功能的实用程序，或者如果它们具有开放的边界集。对于缺乏`securebit`的开放边界集，只有使用`execve()`调用才能允许保留`0` UID 的应用程序保留完整的功能。通过使用 libcap-ng 库，这些具有最高权限的应用程序非常容易识别和处理。与其他工具进行交互和检测，如**netcap**、**pscap**或**filecap**。

**SETools**是一个策略分析工具。实际上，它是 SELinux 的扩展，包含一系列库、图形工具和命令行，试图简单地分析 SELinux 策略。这个开源项目的主要工具如下：

+   `apol`：这是一个用于分析 SELinux 策略的工具

+   `sediff`：这是一个用于比较 SELinux 策略的语义差异器

+   `seaudit`：这是一个用于分析 SELinux 审计消息的工具

+   `seaudit-report`：这用于基于可用的审计日志生成高度可定制的审计报告

+   `sechecker`：这是一个用于对 SELinux 策略进行模块化检查的命令行工具

+   `secmds`：这是另一个用于访问和分析 SELinux 策略的命令行工具

接下来是**SWIG**（**简化包装器和接口生成器**），这是一个软件开发工具，用于与各种目标语言一起创建高级编程环境、用户界面和其他必要的内容。它通常用于快速测试或原型设计，因为它生成了目标语言可以在 C 或 C++代码中调用的粘合剂。

最后要介绍的组件是用于 C 语言的微字符串 API，称为**ustr**，它与可用的 API 相比具有更低的开销。它在 C 代码中非常容易使用，因为它只包括一个头文件并且可以立即使用。与`strdup()`相比，对于字符串的开销从 1-9 字节的 85.45 变化到 1-198 字节的 23.85。举个简单的例子，如果一个 8 字节的存储 ustr 使用 2 字节，`strdup()`函数使用 3 字节。

这是其他工具和库与 SELinux 功能一起提供的地方，尽管其中一些可以作为单独的组件或与此处介绍的其他可用软件组件一起使用。这将为 SELinux 产品增加更多价值，因此在同一位置找到它们似乎是公平的。

对于那些有兴趣获得 SELinux 增强发行版的人，您可以选择在 meta-selinux 层中使用两个可用的映像之一：`core-image-selinux-minimal.bb`或`core-image-selinux.bb`。另一种选择是根据开发人员的需求将其中一个可用的 SELinux 特定定义的软件包组，`packagegroup-selinux-minimal`或`packagegroup-core-selinux`，合并到新定义的映像中。在做出这个选择并相应地进行配置之后，唯一剩下的就是为所选择的映像调用`bitbake`，在构建过程结束时，将会显示一个启用了 SELinux 支持的自定义 Linux 发行版，并且如果需要，可以进一步进行调整。

# 总结

在本章中，您将了解有关内核特定安全项目和外部项目的信息。其中大多数以不好的方式呈现。您还将获得有关各种安全子系统和子组如何跟上各种安全威胁和安全项目实施的信息。

在下一章中，我们将继续探讨另一个有趣的主题。在这里，我指的是虚拟化领域。您将在稍后了解更多关于元虚拟化方面的内容，以及各种虚拟化实现，例如 KVM，在过去几年中已经积累了大量经验，并已经确立了自己的标准。我将让下一章中将介绍的其他元素成为一个秘密。现在让我们进一步探索本书的内容。


# 第十二章：虚拟化

在本章中，您将了解到 Linux 虚拟化部分出现的各种概念。正如一些人可能知道的那样，这个主题非常广泛，仅选择一些组件进行解释也是一个挑战。我希望我的决定能够让大多数对这个领域感兴趣的人满意。本章提供的信息可能并不适合每个人的需求。因此，我附上了多个链接，以获取更详细的描述和文档。我鼓励您在必要时开始阅读并了解更多。我知道我无法用几句话包含所有必要的信息。

在任何 Linux 环境中，Linux 虚拟化并不是一件新事物。它已经存在了十多年，并且以一种非常迅速和有趣的方式发展。现在的问题不再围绕虚拟化作为解决方案，而更多地是关于部署虚拟化解决方案和虚拟化什么。

当然，也有一些情况下虚拟化并不是解决方案。在嵌入式 Linux 中，有一大类领域不适用虚拟化，主要是因为一些工作负载更适合在硬件上运行。然而，对于那些没有这种要求的领域，使用虚拟化有相当多的优势。本章将讨论有关各种虚拟化策略、云计算和其他相关主题的更多信息，让我们来看看。

# Linux 虚拟化

当人们看到虚拟化时，首先看到的好处是服务器利用率的提高和能源成本的降低。使用虚拟化，服务器上的工作负载得到了最大化，这与硬件只使用计算能力的一小部分的情况截然不同。它可以减少与各种环境的交互复杂性，同时还提供了一个更易于使用的管理系统。如今，由于大多数工具提供的可扩展性，与大量虚拟机一起工作并不像与其中几个交互那样复杂。此外，部署时间真的已经减少了。在几分钟内，您可以取消配置和部署操作系统模板，或者创建一个虚拟环境用于虚拟设备部署。

虚拟化带来的另一个好处是灵活性。当工作负载对分配的资源来说太大时，它可以很容易地复制或移动到另一个更适合其需求的环境中，无论是在相同的硬件上还是在更强大的服务器上。对于基于云的解决方案，这里的可能性是无限的。限制可能是由云类型所施加的，基于是否有可用于主机操作系统的工具。

随着时间的推移，Linux 能够为每一个需求和组织提供许多出色的选择。无论您的任务涉及企业数据中心中的服务器整合，还是改善小型非营利组织的基础设施，Linux 都应该有一个适合您需求的虚拟化平台。您只需要弄清楚在哪里以及应该选择哪个项目。

虚拟化是广泛的，主要是因为它包含了广泛的技术范围，而且大部分术语都没有明确定义。在本章中，您将只了解与 Yocto 项目相关的组件，以及我个人感兴趣的一个新倡议。这个倡议试图使**网络功能虚拟化**（**NFV**）和**软件定义网络**（**SDN**）成为现实，被称为**NFV 开放平台**（**OPNFV**）。这里将对其进行简要介绍。

## SDN 和 NFV

我决定从这个话题开始，因为我相信这个领域的所有研究都开始得到各种领域和行业的开源倡议的支持，这是非常重要的。这两个概念并不新。它们自 20 年前首次被描述以来就存在，但过去几年使它们有可能重新出现为真实而非常可能的实现。本节的重点将放在*NFV*部分，因为它受到了最多的关注，并包含了各种实施提议。

## NFV

NFV 是一种网络架构概念，用于将整个网络节点功能虚拟化为可以相互连接以创建通信服务的块。它不同于已知的虚拟化技术。它使用**虚拟网络功能**（**VNF**），可以包含在一个或多个虚拟机中，执行不同的进程和软件组件，可用于服务器、交换机甚至云基础设施。一些例子包括虚拟化负载均衡器、入侵检测设备、防火墙等。

由于各种标准和协议需要很长时间才能达到一致性和质量，电信行业的产品开发周期非常严格和漫长。这使得快速发展的组织有可能成为竞争对手，并迫使它们改变自己的方法。

2013 年，一个行业规范组发布了一份关于软件定义网络和 OpenFlow 的白皮书。该组是**欧洲电信标准化协会**（**ETSI**）的一部分，被称为网络功能虚拟化。在这份白皮书发布后，还发布了更深入的研究论文，从术语定义到各种使用案例，都有参考供应商可以考虑使用 NFV 实现。

## ETSI NFV

ETSI NFV 工作组对电信行业非常有用，可以创建更灵活的开发周期，并且能够及时响应来自动态和快速变化环境的需求。SDN 和 NFV 是两个互补的概念，在这方面是关键的启用技术，并包含了电信和 IT 行业共同开发的主要技术要素。

NFV 框架包括六个组件：

+   **NFV 基础设施（NFVI）**：它需要支持各种用例和应用。它包括为部署 VNF 创建环境的软件和硬件组件的总体。它是一个多租户基础设施，负责同时利用多种标准虚拟化技术用例。它在以下**NFV 行业规范组**（**NFV ISG**）文件中有描述：

+   NFV 基础设施概述

+   NFV 计算

+   NFV 虚拟化程序域

+   NFV 基础设施网络域

以下图片展示了 NFV 基础设施的各种用例和应用领域的可视化图表。

![ETSI NFV](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00374.jpeg)

+   **NFV 管理和编排（MANO）**：它是负责将计算、网络和存储组件与软件实现分离的组件，借助虚拟化层。它需要管理新元素和编排它们之间的新依赖关系，这需要一定的互操作性标准和一定的映射。

+   **NFV 软件架构**：它涉及已实施的网络功能的虚拟化，如专有硬件设备。它意味着从硬件实施到软件实施的理解和过渡。过渡基于可以在过程中使用的各种定义的模式。

+   **NFV 可靠性和可用性**：这些是真正的挑战，这些组件的工作始于各种问题、用例、需求和原则的定义，并且它提出要提供与传统系统相同水平的可用性。它涉及可靠性组件，文档只是为未来的工作奠定基础。它只确定了各种问题，并指出了在设计具有弹性的 NFV 系统中使用的最佳实践。

+   **NFV 性能和可移植性**：总体而言，NFV 的目的是改变未来网络的工作方式。为此，它需要证明自己是行业标准的解决方案。本节解释了如何在一般 VNF 部署中应用与性能和可移植性相关的最佳实践。

+   **NFV 安全性**：由于它是行业的一个重要组成部分，因此它关注并且也依赖于网络和云计算的安全性，这使得确保 NFV 安全性至关重要。安全专家组专注于这些问题。

这些组件的架构如下所示：

![ETSI NFV](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00375.jpeg)

在所有文档就位之后，需要执行一些概念验证，以测试这些组件的限制，并相应地调整理论组件。它们还出现鼓励 NFV 生态系统的发展。

### 注意

有关 NFV 可用概念和规范的更多信息，请参考以下链接：[`www.etsi.org/technologies-clusters/technologies/nfv/nfv-poc?tab=2`](http://www.etsi.org/technologies-clusters/technologies/nfv/nfv-poc?tab=2) 和 [`www.etsi.org/technologies-clusters/technologies/nfv`](http://www.etsi.org/technologies-clusters/technologies/nfv)。

## SDN

**软件定义网络**（**SDN**）是一种网络方法，通过将可用功能的抽象提供给管理员，实现了管理各种服务的可能性。这是通过将系统分离为控制平面和数据平面，并根据发送的网络流量做出决策来实现的；这代表了控制平面领域，而数据平面代表了流量的转发位置。当然，控制平面和数据平面之间需要一种通信方法，因此 OpenFlow 机制首先进入了方程式；然而其他组件也可以取代它。

SDN 的目的是提供一种可管理、成本效益高、适应性强、动态的架构，以及适用于当今动态和高带宽场景的解决方案。OpenFlow 组件是 SDN 解决方案的基础。SDN 架构允许以下内容：

+   **直接编程**：控制平面是直接可编程的，因为它完全与数据平面分离。

+   **可编程配置**：SDN 允许通过程序对资源进行管理、配置和优化。这些程序可以由任何人编写，因为它们不依赖于任何专有组件。

+   **灵活性**：两个组件之间的抽象允许根据开发人员的需求调整网络流量。

+   **中央管理**：逻辑组件可以集中在控制平面上，为其他应用程序、引擎等提供了一个网络视图。

+   **开放标准和供应商中立性**：它使用开放标准实施，这简化了 SDN 的设计和操作，因为控制器提供的指令数量较少。这与其他情况相比要小得多，在其他情况下，需要处理多个供应商特定的协议和设备。

此外，考虑到传统解决方案无法满足市场需求，尤其是新兴的移动设备通信、物联网（IoT）、机器对机器（M2M）、工业 4.0 等市场都需要网络支持。考虑到各个 IT 部门进一步发展的可用预算，他们都面临着做出决定的困境。似乎移动设备通信市场都决定朝着开源的方向发展，希望这种投资能够证明其真正的能力，并带来更加光明的未来。

## OPNFV

网络功能虚拟化项目的开放平台试图提供一个开源参考平台，该平台具有运营商级别的紧密集成，以便促进行业同行帮助改进和推动 NFV 概念。其目的是在已经存在的众多模块和项目之间提供一致性、互操作性和性能。该平台还将尝试与各种开源项目密切合作，并不断帮助集成，同时填补它们中任何一个留下的开发空白。

该项目预计将带来性能、可靠性、可维护性、可用性和功耗效率的提高，同时也将提供一个广泛的仪器平台。它将从开发 NFV 基础设施和虚拟化基础设施管理系统开始，其中将结合多个已有项目。其参考系统架构由 x86 架构表示。

该项目的初始重点和拟议实施可以在以下图片中查看。从这张图片中可以很容易地看出，尽管该项目自 2014 年 11 月开始，但已经有了加速的起步，并已经提出了一些实施建议。已经有许多大公司和组织开始着手他们的特定演示。OPNFV 并没有等待他们完成，已经在讨论一些拟议项目和倡议。这些旨在满足其成员的需求，并确保各种组件的可靠性，如持续集成、故障管理、测试基础设施等。以下图描述了 OPNFV 的结构。

![OPNFV](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00376.jpeg)

该项目一直在利用尽可能多的开源项目。对这些项目所做的所有调整可以在两个地方进行。首先，如果不需要导致与其目的和路线图背道而驰的重大功能更改，可以在项目内部进行。第二个选项是对第一个选项的补充，对于不属于第一类的更改，应该在 OPNFV 项目的代码库中的某个地方包含它们。在 OPNFV 的开发周期内，没有经过适当测试的更改不应该被上游。

还需要提到的另一个重要因素是，OPNFV 不使用任何特定或额外的硬件。只要支持 VI-Ha 参考点，它就可以使用现有的硬件资源。在前面的图片中，可以看到这已经通过提供商实现，例如英特尔提供计算硬件，NetApp 提供存储硬件，Mellanox 提供网络硬件组件。

OPNFV 董事会和技术指导委员会拥有大量的开源项目。它们涵盖从基础设施即服务（IaaS）和虚拟化管理程序到 SDN 控制器等各种项目。这为大量贡献者提供了尝试一些可能没有时间或机会学习的技能的可能性。此外，更多样化的社区提供了对同一主题的更广泛的视角。

OPNFV 项目有各种各样的设备。移动部署的虚拟网络功能多种多样，其中移动网关（如 Serving Gateway（SGW）、Packet Data Network Gateway（PGW）等）和相关功能（Mobility Management Entity（MME）和网关）、防火墙或应用级网关和过滤器（Web 和电子邮件流量过滤器）用于测试诊断设备（服务级别协议（SLA）监控）。这些 VNF 部署需要易于操作、扩展，并且可以独立于部署的 VNF 类型进行演进。OPNFV 旨在创建一个平台，支持以下一系列特性和用例：

+   需要一种常见的机制来管理 VNF 的生命周期，包括部署、实例化、配置、启动和停止、升级/降级以及最终的取消

+   使用一种一致的机制来指定和互连 VNF、VNFC 和 PNF；这些与物理网络基础设施、网络覆盖等无关，即虚拟链路

+   使用一种常见的机制来动态实例化新的 VNF 实例或取消足够的实例以满足当前的性能、规模和网络带宽需求

+   使用一种机制来检测 NFVI、VIM 和基础设施的其他组件中的故障和失败，并从这些故障中恢复

+   使用一种机制从/向虚拟网络功能源/接收流量到/从物理网络功能

+   NFVI 作为服务用于在同一基础设施上托管来自不同供应商的不同 VNF 实例

这里应该提到一些显著且易于理解的用例示例。它们分为四类。让我们从第一类开始：住宅/接入类。它可以用于虚拟化家庭环境，但也提供对 NFV 的固定访问。接下来是数据中心：它具有 CDN 的虚拟化，并提供处理它的用例。移动类别包括移动核心网络和 IMS 的虚拟化，以及移动基站的虚拟化。最后，有云类别，包括 NFVIaaS、VNFaaS、VNF 转发图（服务链）以及 VNPaaS 的用例。

### 注意

有关该项目和各种实施组件的更多信息，请访问[`www.opnfv.org/`](https://www.opnfv.org/)。有关缺失术语的定义，请参阅[`www.etsi.org/deliver/etsi_gs/NFV/001_099/003/01.02.01_60/gs_NFV003v010201p.pdf`](http://www.etsi.org/deliver/etsi_gs/NFV/001_099/003/01.02.01_60/gs_NFV003v010201p.pdf)。

# Yocto Project 的虚拟化支持

`meta-virtualization`层试图创建一个长期和中期的、专门用于嵌入式虚拟化的生产就绪层。它的作用是：

+   简化协作基准测试和研究的方式，使用 KVM/LxC 虚拟化等工具，结合先进的核心隔离和其他技术

+   集成和贡献项目，如 OpenFlow、OpenvSwitch、LxC、dmtcp、CRIU 等，这些项目可以与其他组件一起使用，如 OpenStack 或 Carrier Graded Linux。

简而言之，这一层试图在构建基于 OpenEmbedded 和 Yocto Project 的虚拟化解决方案时提供支持。

我将简要讨论的这一层中可用的软件包如下：

+   `CRIU`

+   `Docker`

+   `LXC`

+   `Irqbalance`

+   `Libvirt`

+   `Xen`

+   `Open vSwitch`

这一层可以与提供各种云解决方案的云代理和 API 支持的`meta-cloud-services`层一起使用。在这一部分，我提到这两个层，因为我认为一起呈现这两个组件是合适的。在`meta-cloud-services`层中，还有一些将被讨论和简要介绍的软件包，如下所示：

+   `openLDAP`

+   `SPICE`

+   `Qpid`

+   `RabbitMQ`

+   风暴

+   `Cyrus-SASL`

+   `Puppet`

+   `oVirt`

+   `OpenStack`

提到了这些组件，我现在将继续解释每个工具。让我们从元虚拟化层的内容开始，更确切地说是`CRIU`软件包，这是一个为 Linux 实现**用户空间中的检查点/恢复**的项目。它可以用于冻结已经运行的应用程序，并将其检查点到硬盘上作为一组文件。这些检查点可以用于从该点恢复和执行应用程序。它可以作为许多用例的一部分使用，如下所示：

+   **容器的实时迁移**：这是该项目的主要用例。容器被检查点，生成的镜像被移动到另一个盒子中并在那里恢复，使整个体验对用户几乎是不可察觉的。

+   **无缝升级内核**：内核替换活动可以在不停止活动的情况下进行。它可以被检查点，通过调用 kexec 替换，并且所有服务可以在之后恢复。

+   **加快启动速度慢的服务**：对于启动过程缓慢的服务，可以在第一次启动完成后进行检查点，并在后续启动时从该点恢复。

+   **网络负载均衡**：它是`TCP_REPAIR`套接字选项的一部分，并将套接字切换到特殊状态。实际上，套接字被放置在操作结束时所期望的状态中。例如，如果调用`connect()`，则套接字将被放置在所请求的`ESTABLISHED`状态中，而不会检查来自另一端的通信确认，因此卸载可以在应用程序级别进行。

+   **桌面环境的挂起/恢复**：它基于这样一个事实，即屏幕会话或`X`应用程序的挂起/恢复操作比关闭/打开操作要快得多。

+   **高性能和计算问题**：它可以用于在集群上平衡任务的负载和保存集群节点状态以防发生崩溃。对应用程序进行多个快照不会对任何人造成伤害。

+   **进程的复制**：类似于远程`fork()`操作。

+   **应用程序的快照**：一系列应用程序状态可以被保存并在必要时恢复。它可以被用作应用程序所需状态的重做，也可以用于调试目的。

+   **在没有此选项的应用程序中保存能力**：这样的应用程序的一个例子可能是游戏，在达到一定级别后，建立检查点是你需要的。

+   **将遗忘的应用程序迁移到屏幕上**：如果您忘记将一个应用程序包含在屏幕上，而您已经在那里，CRIU 可以帮助进行迁移过程。

+   **调试挂起的应用程序**：对于因`git`而被卡住并需要快速重启的服务，可以使用服务的副本进行恢复。也可以使用转储过程，并通过调试找到问题的原因。

+   **在不同机器上分析应用程序行为**：对于那些在不同机器上可能表现不同的应用程序，可以使用该应用程序的快照，并将其转移到另一台机器上。在这里，调试过程也可以是一个选项。

+   **干运行更新**：在系统或内核更新之前，可以将其服务和关键应用程序复制到虚拟机上，系统更新并且所有测试用例通过后，才能进行真正的更新。

+   **容错系统**：它可以成功用于在其他机器上复制进程。

下一个元素是`irqbalance`，这是一个分布式硬件中断系统，可跨多个处理器和多处理器系统使用。实际上，它是一个用于在多个 CPU 之间平衡中断的守护程序，其目的是在 SMP 系统上提供更好的性能以及更好的 IO 操作平衡。它有替代方案，如`smp_affinity`，理论上可以实现最大性能，但缺乏`irqbalance`提供的同样灵活性。

`libvirt`工具包可用于连接到最近的 Linux 内核版本中提供的虚拟化功能，这些功能已根据 GNU Lesser General Public License 许可。它支持大量软件包，如下所示：

+   KVM/QEMU Linux 监督员

+   Xen 监督员

+   LXC Linux 容器系统

+   OpenVZ Linux 容器系统

+   Open Mode Linux 是一个半虚拟化内核

+   包括 VirtualBox、VMware ESX、GSX、Workstation 和 player、IBM PowerVM、Microsoft Hyper-V、Parallels 和 Bhyve 在内的虚拟机监视器

除了这些软件包，它还支持多种文件系统的存储，如 IDE、SCSI 或 USB 磁盘、FiberChannel、LVM 以及 iSCSI 或 NFS，以及虚拟网络的支持。它是其他专注于节点虚拟化的更高级别应用程序和工具的构建块，并以安全的方式实现这一点。它还提供了远程连接的可能性。

### 注意

有关`libvirt`的更多信息，请查看其项目目标和术语[`libvirt.org/goals.html`](http://libvirt.org/goals.html)。

接下来是`Open vSwitch`，一个多层虚拟交换机的生产质量实现。这个软件组件根据 Apache 2.0 许可证授权，并旨在通过各种编程扩展实现大规模网络自动化。`Open vSwitch`软件包，也缩写为**OVS**，提供了硬件虚拟化的两个堆栈层，并支持计算机网络中的大量标准和协议，如 sFlow、NetFlow、SPAN、CLI、RSPAN、802.1ag、LACP 等。

Xen 是一个具有微内核设计的虚拟化程序，提供服务，可以在同一架构上执行多个计算机操作系统。它最初是在 2003 年在剑桥大学开发的，并在 GNU 通用公共许可证第 2 版下开发。这个软件运行在更高特权状态下，并可用于 ARM、IA-32 和 x86-64 指令集。

虚拟机监视器是一种软件，涉及 CPU 调度和各种域的内存管理。它是从**域 0**（**dom0**）执行的，控制所有其他非特权域，称为**domU**；Xen 从引导加载程序引导，并通常加载到 dom0 主机域，一个半虚拟化操作系统。Xen 项目架构的简要介绍在这里：

![Yocto 项目的虚拟化支持](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00377.jpeg)

**Linux 容器**（**LXC**）是 meta-virtualization 层中提供的下一个元素。它是一组著名的工具和库，通过在 Linux 控制主机机器上提供隔离容器，以操作系统级别进行虚拟化。它结合了内核**控制组**（**cgroups**）的功能与对隔离命名空间的支持，以提供一个隔离的环境。它受到了相当多的关注，主要是由于稍后将简要提到的 Docker。此外，它被认为是完整机器虚拟化的轻量级替代方案。

这两个选项，容器和机器虚拟化，都有相当多的优点和缺点。如果选择容器，它们通过共享某些组件来提供低开销，但可能会发现它的隔离效果不好。机器虚拟化恰恰相反，提供了很好的隔离解决方案，但开销更大。这两种解决方案也可以看作是互补的，但这只是我个人对这两种解决方案的看法。实际上，它们每个都有自己特定的一套优点和缺点，有时也可能是互补的。

### 注

有关 Linux 容器的更多信息，请访问[`linuxcontainers.org/`](https://linuxcontainers.org/)。

将讨论的`meta-virtualization`层的最后一个组件是 Docker，这是一款开源软件，试图自动化在 Linux 容器中部署应用程序的方法。它通过在 LXC 上提供一个抽象层来实现这一点。它的架构在这张图片中更好地描述了：

![Yocto 项目的虚拟化支持](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00378.jpeg)

正如您在上图中所看到的，这个软件包能够使用操作系统的资源。我指的是 Linux 内核的功能，并且已经将其他应用程序从操作系统中隔离出来。它可以通过 LXC 或其他替代方案（如`libvirt`和`systemd-nspawn`）来实现，也可以直接通过`libcontainer`库来实现，这个库从 Docker 的 0.9 版本开始就存在了。

Docker 是一个很好的组件，如果您想要为分布式系统（如大规模 Web 部署、面向服务的架构、持续部署系统、数据库集群、私有 PaaS 等）获得自动化。有关其用例的更多信息，请访问[`www.docker.com/resources/usecases/`](https://www.docker.com/resources/usecases/)。确保您查看这个网站；这里经常有有趣的信息。

### 注

有关 Docker 项目的更多信息，请访问他们的网站。在[`www.docker.com/whatisdocker/`](https://www.docker.com/whatisdocker/)上查看**什么是 Docker？**部分。

完成`meta-virtualization`层后，我将转向包含各种元素的`meta-cloud-services`层。我将从**独立计算环境的简单协议**（**Spice**）开始。这可以被翻译成用于虚拟化桌面设备的远程显示系统。

它最初是作为闭源软件开始的，在两年后决定将其开源。然后它成为了与设备交互的开放标准，无论它们是虚拟化的还是非虚拟化的。它建立在客户端-服务器架构上，使其能够处理物理和虚拟化设备。后端和前端之间的交互是通过 VD-Interfaces（VDI）实现的，如下图所示，它目前的重点是远程访问 QEMU/KVM 虚拟机：

![Yocto 项目的虚拟化支持](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00379.jpeg)

接下来是**oVirt**，一个提供 Web 界面的虚拟化平台。它易于使用，并有助于管理虚拟机、虚拟化网络和存储。它的架构由 oVirt Engine 和多个节点组成。引擎是一个配备了用户友好界面的组件，用于管理逻辑和物理资源。它还运行虚拟机，这些虚拟机可以是 oVirt 节点、Fedora 或 CentOS 主机。使用 oVirt 的唯一缺点是它只支持有限数量的主机，如下所示：

+   Fedora 20

+   CentOS 6.6, 7.0

+   Red Hat Enterprise Linux 6.6, 7.0

+   Scientific Linux 6.6, 7.0

作为一个工具，它真的很强大。它与`libvirt`集成，用于**虚拟桌面和服务器管理器**（**VDSM**）与虚拟机的通信，还支持能够实现远程桌面共享的 SPICE 通信协议。这是一个由 Red Hat 发起并主要由其维护的解决方案。它是他们**Red Hat 企业虚拟化**（**RHEV**）的基本元素，但有一件有趣的事情需要注意的是，Red Hat 现在不仅是 oVirt 和 Aeolus 等项目的支持者，自 2012 年以来还是 OpenStack 基金会的白金会员。

### 注意

有关 oVirt、Aeolus 和 RHEV 等项目的更多信息，以下链接对您可能有用：[`www.redhat.com/promo/rhev3/?sc_cid=70160000000Ty5wAAC&offer_id=70160000000Ty5NAAS http://www.aeolusproject.org/`](http://www.redhat.com/promo/rhev3/?sc_cid=70160000000Ty5wAAC&offer_id=70160000000Ty5NAAS%20http://www.aeolusproject.org/)，以及[`www.ovirt.org/Home`](http://www.ovirt.org/Home)。

我现在将转向另一个组件。在这里，我指的是轻量级目录访问协议的开源实现，简称为**OpenLDAP**。尽管它有一个有争议的许可证，称为**OpenLDAP Public License**，在本质上类似于 BSD 许可证，但它没有在 opensource.org 上记录，因此未经**开源倡议**（**OSI**）认证。

这个软件组件是一套元素，如下所示：

+   一个独立的 LDAP 守护程序，扮演服务器的角色，称为**slapd**

+   一些实现 LDAP 协议的库

+   最后但同样重要的是，一系列工具和实用程序，它们之间也有一些客户端示例

还有一些应该提到的附加内容，例如用 C++编写的 ldapc++和库，用 Java 编写的 JLDAP 和库；LMDB，一个内存映射数据库库；Fortress，基于角色的身份管理；也是用 Java 编写的 SDK；以及用 Java 编写的 JDBC-LDAP 桥驱动程序，称为**JDBC-LDAP**。

**Cyrus SASL**是一个用于**简单认证和安全层**（**SASL**）认证的通用客户端-服务器库实现。这是一种用于为基于连接的协议添加认证支持的方法。基于连接的协议添加一个命令，用于标识和认证用户到请求的服务器，如果需要协商，还会在协议和连接之间添加一个额外的安全层，用于安全目的。有关 SASL 的更多信息，请参阅 RFC 2222，网址为[`www.ietf.org/rfc/rfc2222.txt`](http://www.ietf.org/rfc/rfc2222.txt)。

### 注意

有关 Cyrus SASL 的更详细描述，请参阅[`www.sendmail.org/~ca/email/cyrus/sysadmin.html`](http://www.sendmail.org/~ca/email/cyrus/sysadmin.html)。

**Qpid**是 Apache 开发的消息工具，它理解**高级消息队列协议**（**AMQP**），并支持各种语言和平台。AMQP 是一个设计用于在网络上以可靠的方式进行高性能消息传递的开源协议。有关 AMQP 的更多信息，请访问[`www.amqp.org/specification/1.0/amqp-org-download`](http://www.amqp.org/specification/1.0/amqp-org-download)。在这里，您可以找到有关协议规范以及项目的更多信息。

Qpid 项目推动了 AMQP 生态系统的发展，通过提供消息代理和 API，可以在任何开发人员打算在其产品中使用 AMQP 消息传递的应用程序中使用。为此，可以执行以下操作：

+   让源代码开源。

+   使 AMQP 在各种计算环境和编程语言中可用。

+   提供必要的工具来简化应用程序开发过程。

+   创建一个消息基础设施，以确保其他服务可以与 AMQP 网络很好地集成。

+   创建一个消息产品，使得与 AMQP 对于任何编程语言或计算环境来说都是微不足道的集成。确保您查看 Qpid Proton [`qpid.apache.org/proton/overview.html`](http://qpid.apache.org/proton/overview.html)。

### 注意

有关前述功能的更多信息，请访问[`qpid.apache.org/components/index.html#messaging-apis`](http://qpid.apache.org/components/index.html#messaging-apis)。

**RabbitMQ**是另一个实现 AMQP 的消息代理软件组件，也可作为开源软件使用。它有一些组件，如下：

+   RabbitMQ 交换服务器

+   HTTP、**流文本定向消息协议**（**STOMP**）和**消息队列遥测传输**（**MQTT**）的网关

+   各种编程语言的 AMQP 客户端库，尤其是 Java、Erlang 和.Net Framework

+   一种用于许多自定义组件的插件平台，还提供了一系列预定义的组件：

+   **铲子**：这是一个在经纪人之间执行消息复制/移动操作的插件

+   **管理**：它使经纪人和经纪人集群的控制和监视成为可能

+   **联邦**：它使经纪人之间在交换级别共享消息

### 注意

您可以通过参考 RabbitMQ 文档部分[`www.rabbitmq.com/documentation.html`](http://www.rabbitmq.com/documentation.html)了解有关 RabbitMQ 的更多信息。

比较 Qpid 和 RabbitMQ，可以得出 RabbitMQ 更好的结论，而且它有一个很棒的文档。这使得它成为 OpenStack 基金会的首选，也是对于对这些框架感兴趣的读者来说，提供了超过这些框架的基准信息。它也可以在[`blog.x-aeon.com/2013/04/10/a-quick-message-queue-benchmark-activemq-rabbitmq-hornetq-qpid-apollo/`](http://blog.x-aeon.com/2013/04/10/a-quick-message-queue-benchmark-activemq-rabbitmq-hornetq-qpid-apollo/)找到。为了比较目的，这样的结果也可以在这个图像中找到：

![Yocto 项目的虚拟化支持](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00380.jpeg)

下一个元素是**木偶**，这是一个开源的配置管理系统，允许 IT 基础设施定义某些状态，并强制执行这些状态。通过这样做，它为系统管理员提供了一个很好的自动化系统。这个项目由 Puppet Labs 开发，并在 GNU 通用公共许可证下发布，直到 2.7.0 版。之后，它移至 Apache 许可证 2.0，现在有两种风味：

+   **开源木偶版本**：它与前述工具大致相似，能够提供允许定义和自动化状态的配置管理解决方案。它适用于 Linux 和 UNIX 以及 Max OS X 和 Windows。

+   企业版木偶：这是一个商业版本，超出了开源木偶的能力，并允许自动化配置和管理过程。

这是一个工具，为系统配置定义了一个声明性语言，以供以后使用。它可以直接应用于系统，甚至可以编译为目录，并使用客户端-服务器范式部署到目标上，通常是 REST API。另一个组件是一个代理，强制执行清单中可用的资源。资源抽象当然是通过一个抽象层来完成的，该抽象层通过更高级别的术语定义配置，这些术语与操作系统特定的命令非常不同。

### 注意

如果您访问[`docs.puppetlabs.com/`](http://docs.puppetlabs.com/)，您将找到与 Puppet 和其他 Puppet Lab 工具相关的更多文档。

有了这一切，我相信是时候介绍元云服务层的主要组件**OpenStack**了。它是一个基于控制大量组件的云操作系统，共同提供计算、存储和网络资源池。所有这些资源都通过一个仪表板进行管理，当然，这个仪表板是由另一个组件提供的，并提供管理员控制。它为用户提供了通过同一网络界面提供资源的可能性。下面是一个描述开源云操作系统 OpenStack 的图像：

![Yocto 项目的虚拟化支持](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00381.jpeg)

它主要用作 IaaS 解决方案，其组件由 OpenStack 基金会维护，并在 Apache 许可证第 2 版下提供。在基金会中，今天有 200 多家公司为软件的源代码和一般开发和维护做出贡献。在其核心，所有组件都保持着，每个组件都有一个用于简单交互和自动化可能性的 Python 模块：

+   **计算（Nova）**：它用于托管和管理云计算系统。它管理环境中计算实例的生命周期。它负责根据需要生成、退役和调度各种虚拟机。在虚拟化程序方面，KVM 是首选选项，但其他选项如 Xen 和 VMware 也是可行的。

+   **对象存储（Swift）**：它用于通过 RESTful 和 HTTP API 进行存储和数据结构检索。它是一个可伸缩和容错系统，允许对象和文件在多个磁盘驱动器上进行数据复制。它主要由一个名为**SwiftStack**的对象存储软件公司开发。

+   **块存储（Cinder）**：它为 OpenStack 实例提供持久的块存储。它管理块设备的创建以及附加和分离操作。在云中，用户管理自己的设备，因此应支持绝大多数存储平台和场景。为此，它提供了一个可插拔的架构，简化了这个过程。

+   **网络（Neutron）**：它是负责网络相关服务的组件，也被称为**作为服务的网络连接**。它提供了一个用于网络管理的 API，并确保防止某些限制。它还具有基于可插拔模块的架构，以确保尽可能支持尽可能多的网络供应商和技术。

+   **仪表板（Horizon）**：它为管理员和用户提供基于 Web 的图形界面，用于与所有其他组件提供的其他资源进行交互。它还考虑了可扩展性，因为它能够与负责监控和计费的其他组件以及其他管理工具进行交互。它还提供了根据商业供应商的需求重新品牌的可能性。

+   **身份服务（Keystone）**：它是一个身份验证和授权服务。它支持多种形式的身份验证，还支持现有的后端目录服务，如 LDAP。它为用户和他们可以访问的资源提供了目录。

+   **镜像服务（Glance）**：它用于发现、存储、注册和检索虚拟机的镜像。一些已存储的镜像可以用作模板。OpenStack 还提供了一个用于测试目的的操作系统镜像。Glance 是唯一能够在各个服务器和虚拟机之间添加、删除、复制和共享 OpenStack 镜像的模块。所有其他模块都使用 Glance 的可用 API 与镜像进行交互。

+   **遥测（Ceilometer）**：它是一个模块，通过大量计数器的帮助，提供了跨所有当前和未来的 OpenStack 组件的计费、基准测试和统计结果，从而实现了可扩展性。这使得它成为一个非常可扩展的模块。

+   **编排器（Heat）**：它是一个管理多个复合云应用程序的服务，借助各种模板格式，如 Heat 编排模板（HOT）或 AWS CloudFormation。通信既可以在 CloudFormation 兼容的查询 API 上进行，也可以在 Open Stack REST API 上进行。

+   **数据库（Trove）**：它提供可靠且可扩展的云数据库服务功能。它使用关系型和非关系型数据库引擎。

+   **裸金属配置（Ironic）**：它是一个提供虚拟机支持而不是裸金属机支持的组件。它起初是作为 Nova 裸金属驱动程序的一个分支开始的，并发展成为裸金属超级监视器的最佳解决方案。它还提供了一组插件，用于与各种裸金属超级监视器进行交互。它默认与 PXE 和 IPMI 一起使用，但当然，借助可用插件的帮助，它可以为各种特定于供应商的功能提供扩展支持。

+   多租户云消息传递（Zaqar）：正如其名称所示，这是一个面向对**软件即服务**（**SaaS**）感兴趣的 Web 开发人员的多租户云消息传递服务。他们可以使用它通过多种通信模式在各种组件之间发送消息。然而，它也可以与其他组件一起用于向最终用户呈现事件以及在云层进行通信。它以前的名称是**Marconi**，并且还提供可扩展和安全的消息传递的可能性。

+   **弹性 Map Reduce（Sahara）**：它是一个试图自动化提供 Hadoop 集群功能的模块。它只需要定义各种字段，如 Hadoop 版本、各种拓扑节点、硬件细节等。之后，几分钟内，一个 Hadoop 集群就部署好并准备好进行交互。它还提供了部署后的各种配置的可能性。

说了这么多，也许您不介意在下面的图像中呈现一个概念架构，以向您展示上述先前组件的交互方式。为了在生产环境中自动部署这样的环境，可以使用自动化工具，例如前面提到的 Puppet 工具。看一下这个图表：

![Yocto 项目的虚拟化支持](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00382.jpeg)

现在，让我们继续看看如何使用 Yocto 项目的功能部署这样的系统。为了开始这项活动，应将所有所需的元数据层放在一起。除了已经可用的 Poky 存储库外，还需要其他存储库，并且它们在 OpenEmbedded 网站的层索引中定义，因为这次，`README`文件是不完整的：

```
git clone –b dizzy git://git.openembedded.org/meta-openembedded
git clone –b dizzy git://git.yoctoproject.org/meta-virtualization
git clone –b icehouse git://git.yoctoproject.org/meta-cloud-services
source oe-init-build-env ../build-controller
```

创建适当的控制器构建后，需要进行配置。在`conf/layer.conf`文件中，添加相应的机器配置，例如 qemux86-64，在`conf/bblayers.conf`文件中，应相应地定义`BBLAYERS`变量。除了已经可用的层外，还有额外的元数据层。应该在此变量中定义的层是：

+   `meta-cloud-services`

+   `meta-cloud-services/meta-openstack-controller-deploy`

+   `meta-cloud-services/meta-openstack`

+   `meta-cloud-services/meta-openstack-qemu`

+   `meta-openembedded/meta-oe`

+   `meta-openembedded/meta-networking`

+   `meta-openembedded/meta-python`

+   `meta-openembedded/meta-filesystem`

+   `meta-openembedded/meta-webserver`

+   `meta-openembedded/meta-ruby`

使用`bitbake openstack-image-controller`命令完成配置后，将构建控制器镜像。可以使用`runqemu qemux86-64 openstack-image-controller kvm nographic qemuparams="-m 4096"`命令启动控制器。完成这项活动后，可以以这种方式开始计算的部署：

```
source oe-init-build-env ../build-compute

```

有了新的构建目录，由于大部分构建过程的工作已经在控制器上完成，因此可以在它们之间共享构建目录，如`downloads`和`sstate-cache`。这些信息应该通过`DL_DIR`和`SSTATE_DIR`来指示。`conf/bblayers.conf`文件的两个之间的区别在于`build-compute`构建目录的第二个文件用`meta-cloud-services/meta-openstack-controller-deploy`替换了`meta-cloud-services/meta-openstack-compute-deploy`。

这次构建是用`bitbake openstack-image-compute`完成的，应该会更快。完成构建后，可以使用`runqemu qemux86-64 openstack-image-compute kvm nographic qemuparams="-m 4096 –smp 4"`命令启动计算节点。这一步意味着为 OpenStack Cirros 加载镜像，如下所示：

```
wget download.cirros-cloud.net/0.3.2/cirros-0.3.2-x86_64-disk.img 
scp cirros-0.3.2-x86_64-disk.img  root@<compute_ip_address>:~
ssh root@<compute_ip_address>
./etc/nova/openrc
glance image-create –name "TestImage" –is=public true –container-format bare –disk-format qcow2 –file /home/root/cirros-0.3.2-x86_64-disk.img

```

完成所有这些后，用户可以使用`http://<compute_ip_address>:8080/`访问 Horizon 网页浏览器。登录信息是 admin，密码是 password。在这里，您可以玩耍，创建新实例，与它们交互，总之，做任何你想做的事情。如果您对实例做错了什么，不要担心；您可以删除它并重新开始。

`meta-cloud-services`层的最后一个元素是用于 OpenStack 的**Tempest 集成测试套件**。它通过一组测试来执行 OpenStack 主干上的测试，以确保一切都按预期工作。对于任何 OpenStack 部署来说都非常有用。

### 注意

有关 Tempest 的更多信息，请访问[`github.com/openstack/tempest`](https://github.com/openstack/tempest)。

# 总结

在本章中，不仅介绍了一些虚拟化概念，如 NFV、SDN、VNF 等，还介绍了一些贡献于日常虚拟化解决方案的开源组件。我为您提供了示例，甚至进行了一些小练习，以确保信息在您阅读本书后仍然留在您心中。我希望我引起了一些人对某些事情的好奇心。我也希望有些人记录了这里没有介绍的项目，比如**OpenDaylight**（**ODL**）倡议，它只在图像中被提及作为一个实施建议。如果是这样，我可以说我实现了我的目标。如果不是，也许这个总结会让您再次翻阅前面的页面。

在下一章中，我们将访问一个新的真实的载波级产品。这将是本书的最后一章，我将以一个对我个人非常重要的主题作为总结。我将讨论 Yocto 羞涩倡议称为**meta-cgl**及其目的。我将介绍**Carrier Graded Linux**（**CGL**）的各种规范和变化，以及**Linux Standard Base**（**LSB**）的要求。我希望您阅读它时和我写作时一样享受。


# 第十三章：CGL 和 LSB

在本章中，您将了解本书最后一个主题的信息，即**Carrier Grade Linux**（**CGL**）和**Linux Standard Base**（**LSB**）倡议，当然还有与 Yocto 项目集成和支持相关的内容。这里也会提到这些标准及其规范的一些信息，以及 Yocto 为它们提供的支持水平。我还将介绍一些与 CGL 相关的倡议，如**Automotive Grade Linux**和**Carrier Grade Virtualization**。它们也构成了一系列可行的解决方案，适用于各种应用。

在今天的任何 Linux 环境中，都需要一个可用的 Linux 发行版的通用语言。如果没有定义实际的规范，这种通用语言是无法实现的。这些规范的一部分也由载波级别的替代方案代表。它与本书或其他类似书籍中已经介绍的其他规范共存。查看可用的规范和标准化只会向我们展示 Linux 生态系统随着时间的推移已经发展了多少。

Linux 基金会发布的最新报告显示了 Linux 内核的开发实际情况，工作情况，赞助情况，对其进行的更改以及发展速度。该报告可在[`www.linuxfoundation.org/publications/linux-foundation/who-writes-linux-2015`](https://www.linuxfoundation.org/publications/linux-foundation/who-writes-linux-2015)上找到。

报告中描述，不到 20％的内核开发是由个人开发者完成的。大部分开发是由公司完成的，比如英特尔、红帽、Linaro、三星等。这意味着超过 80％的 Linux 内核开发人员是为他们的工作而获得报酬的。Linaro 和三星是提交次数最多的公司之一，这只是一种对 ARM 处理器和特别是 Android 的有利看法。

另一个有趣的信息是，超过一半的 Linux 内核开发人员是第一次提交。这意味着只有很少一部分开发者在做大部分的工作。Linux 基金会正在尝试通过为学生提供各种项目来减少 Linux 内核开发过程中的这种功能障碍。这是否成功，只有时间才能告诉我们，但我认为他们正在做正确的事情，朝着正确的方向发展。

所有这些信息都是针对 Linux 内核解释的，但其中的一部分也适用于其他开源组件。我想在这里强调的是，Linux 中的 ARM 支持比 PowerPC 或 MIPS 等架构要成熟得多。这不仅已经变得显而易见，而且也表明了英特尔 x86 阶段所采取的方法。到目前为止，这种方法还没有受到任何干扰。

# Linux 标准基础

LSB 似乎降低了 Linux 平台提供的支持成本，通过减少各种可用 Linux 发行版之间的差异。它还有助于应用程序的移植成本。每当开发人员编写应用程序时，他们需要确保在一个 Linux 发行版上产生的源代码也能在其他发行版上执行。他们还希望确保这在多年内仍然可能。

LSB 工作组是 Linux 基金会的一个项目，旨在解决这些确切的问题。为此，LSB 工作组开始制定一个描述 Linux 发行版应支持的一组 API 的标准。随着标准的定义，工作组还进一步开发了一套工具和测试来衡量支持水平。通过这样做，他们能够定义一定的符合性集，并检测各种发行版之间的差异。

LSB 是 Linux 基金会在这个方向上的首次努力，成为了所有试图为 Linux 平台的各个领域提供标准化的工作组的总称。所有这些工作组都有相同的路线图，并提供相应的规范、软件组件（如符合性测试、开发工具）以及其他可用的样本和实现。

由工作组开发的每个软件组件，如果在 Linux 标准基础中可用，都被定义为`lsb`模块。所有这些模块都有一个共同的格式，以便更容易地进行集成。有必需的和可选的模块。必需的模块是符合 LSB 接受标准的模块。可选的模块仍在进行中，在规范定义的时候，还没有写入接受标准，但将包括在未来版本的 LSB 标准中。

当然，也有一些工作组并不生产`lsb`模块。他们也没有制定标准，而是在项目中集成了各种补丁，比如 Linux 内核或其他软件包，甚至是文档。这一节只考虑与 LSB 相关的工作组。

不时地，每当发布新的规范文档时，测试工具包也会提供给供应商，以测试该工具包对特定版本的合规性。供应商可以测试他们的产品的合规性，可以是一个应用程序或一个 Linux 发行版。测试工具包的结果是一个证书，表明他们的产品是 LSB 认证的。对于应用程序，我们当然有一个**LSB 应用程序测试工具包**。也有一个类似的工具包适用于 Linux 发行版，以及适用于各种发行版的其他工具包。

对于对可选模块感兴趣的供应商，这些模块不仅可用于帮助供应商准备未来的 LSB 合规认证，还可以让他们接触到可选模块，以便从他们那里获得更多的评价和贡献。此外，供应商的投票与这些模块在未来 LSB 规范文档中的存在有关，这一发布也很重要。供应商可以确定一个可选模块是否符合未来的纳入条件。

LSB 工作组由指导委员会管理，并由选举产生的主席领导。这两个实体代表了工作组的利益。工作组采用粗略共识模式运作。这表明了工作组对特定问题的解决方案，即由选举产生的主席确定的解决方案。如果贡献者不认同他们的决定，并且不符合达成粗略共识所需的标准，那么就会向指导委员会提出申诉。

LSB 工作组的所有业务都在一个开放的论坛内进行。它可以包括邮件列表、会议、维基页面，甚至是面对面的会议；这些活动对工作组成员都是开放的。此外，成员资格并不受限制，决定也都有明确的记录，因为随时可能会就某个特定主题进行进一步讨论。

工作组中有明确定义的角色：

+   **贡献者**：这指的是积极参与的个人。他们始终有名单可供主席查阅，但任何个人都可以要求被列入贡献者名单。

+   **主席**：这指的是代表项目领导者。一个人被贡献者选举到这个职位，并得到指导委员会和 Linux 基金会董事会的批准。一旦当选，他们可以连任两年。没有限制一个人可以当选的次数。如果指导委员会或 Linux 基金会董事会对其缺乏信任，就会被免职。职位空缺后，将进行新的选举。在空缺期间，指导委员会将指定一名代理主席。

+   **选举委员会**：这指的是由指导委员会为主席选举成立的贡献者委员会。它负责在主席任期到期前至少 30 天或主席职位空缺后 10 天内选择主席候选人。它负责进行选举，通过电子投票进行。每个人只能投一票；投票是秘密的，只有符合条件的成员才能进行投票。投票期为一周，然后结果提交给指导委员会，由其批准并宣布获胜者。

+   **指导委员会**：它由代表工作组利益相关者组成。他们可能是发行商、OEM 厂商、ISV、上游开发人员，以及 LSB 宪章下的 LSB 子工作组的主席。该委员会由主席任命，并根据他们在工作组活动中的参与程度，可以无限期地保持职位。一个成员可以被指导委员会的三个实体之一罢免：主席、其他指导委员会成员，或 Linux 基金会董事会。

这是一张展示 LSB 工作组更详细结构的图片：

![Linux 标准基础](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00383.jpeg)

LSB 是一个相当复杂的结构，正如前面的图片所示，因此如果需要，工作组可以定义更多的角色。工作组的主要焦点仍然是其使命；为了实现这一目标，需要推广和培育新的工作组。它们需要一定程度的独立性，但也需要对 LSB 主席所做的活动负责。这主要涉及确保满足某些截止日期，并确保项目按照其路线图进行。

与 LSB 可交付成果互动的第一步应该是确定目标系统需要满足的确切 LSB 要求。规范分为两个组成部分：与体系结构相关和与体系结构无关，或者也称为通用组件。与体系结构相关的组件包含三个模块：

+   核心

+   C++

+   桌面

与体系结构无关的组件包含五个模块：

+   核心

+   C++

+   桌面

+   打印

+   语言

当然，还有另一种结构用于对它们进行排序。在这里，我指的是其中一些是强制性的，而另一些处于试验和测试阶段。第一类是为了拥有符合 LSB 标准的发行版，而第二类并不是拥有符合标准的发行版的严格要求，但可能代表未来几个版本 LSB 的候选人。

以下图片代表 LSB 的关键可交付组件。我希望它能指导您了解该项目的组件，并收集您未来与 LSB 工作组各个组件互动所需的信息。

![Linux 标准基础](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00384.jpeg)

根据用户的兴趣，他们可以选择与发行版开发或应用程序组件开发进行交互。正如前面的图像清楚地显示的那样，这两条道路都有适合工作的工具。在开始工作之前，请确保查看 LSB Navigator 的网站并收集所需的信息。对于对 LSB 导航器感兴趣的用户，可以在以下链接中找到一个演示，其中还涉及与 Yocto 的交互。确保您查看并与之交互，以了解其工作原理。

### 注意

可以在[`www.linuxbase.org/navigator/commons/welcome.php`](http://www.linuxbase.org/navigator/commons/welcome.php)访问 LSB Navigator。

假设交互已经完成，现在您有兴趣参与这个项目。当然，有多种方法可以做到这一点。无论您是开发人员还是软件供应商，您的反馈对任何项目都是有帮助的。此外，对于希望通过代码做出贡献的开发人员，有多个组件和工具可以从您的帮助中受益。这还不是全部。有许多测试框架和测试基础设施始终需要改进，因此某人不仅可以通过代码做出贡献，还可以进行错误修复和工具的开发或测试。还要记住，您的反馈总是受到赞赏的。

在进入下一节之前，我想再介绍一件事。如前图所示，任何由开发人员执行的与 LSB 工作组组件相关的活动，都应在检查 LSB 规范并选择适当版本之后进行。例如，在 CGL 规范中，至少需要 LSB 3.0，并且在相同的要求描述中指出了所需的模块。对于希望了解所需规范及其组件的开发人员，请参阅[`refspecs.linuxfoundation.org/lsb.shtml`](http://refspecs.linuxfoundation.org/lsb.shtml)。确保您还检查了新推出的 LSB 5 规范的进展，该规范已经通过了测试阶段，目前处于 RC1 状态。有关此的更多信息，请访问[`www.linuxfoundation.org/collaborate/workgroups/lsb/lsb-50-rc1`](https://www.linuxfoundation.org/collaborate/workgroups/lsb/lsb-50-rc1)。

### 注意

有关 LSB 的更多信息，请访问[`www.linuxfoundation.org/collaborate/workgroups/lsb`](http://www.linuxfoundation.org/collaborate/workgroups/lsb)。

# 运营商级别选项

本节将讨论多种选项，并且我们将从定义术语*运营商级别*开始。这似乎是一个完美的开始。那么，在电信环境中，这个术语是什么意思呢？它指的是一个真正可靠的系统、软件，甚至硬件组件。在这里，我不仅指的是 CGL 提供的五个九或六个九，因为并非所有行业和场景都需要这种可靠性。我们只会提到在项目范围内可以定义为可靠的东西。要将系统、软件或硬件组件定义为运营商级别，它还应该经过全面测试，并具有各种功能，如高可用性、容错性等。

这些五个九和六个九指的是产品可用时间占 99.999 或 99.9999％。这意味着每年的停机时间约为五个九的 5 分钟和六个九的 30 秒。解释完这一点后，我将继续介绍运营商级别的可用选项。

## 运营商级别 Linux

这是第一个也是最古老的选项。它出现是因为电信行业需要定义一组规范，从而为基于 Linux 的操作系统定义一组标准。实施后，这将使系统具备运营商级别的能力。

CGL 背后的动机是提出一个开放架构作为电信系统中已有的专有和闭源解决方案的可能解决方案或替代方案。开放架构的替代方案不仅因为它避免了单一形式，不难维护、扩展和开发，而且它还提供了速度的优势。拥有一个解耦并使其组件对更多软件或硬件工程师可访问的系统更快、更便宜。所有这些组件最终都能够达到相同的目的。

该工作组最初由**开放源开发实验室**（**OSDL**）发起，后来与自由标准组合并形成了 Linux 基金会。现在所有工作都转移到那里，包括工作组。CGL 的最新可用版本是 5.0，其中包括 Wind River、MontaVista 和 Red Flag 等注册的 Linux 发行版。

OSDL CGL 工作组有三类 CGL 可能适用的应用程序：

+   **信令服务器应用程序**：包括为呼叫和服务提供控制服务的产品，如路由、会话控制和状态。这些产品通常处理大量连接，大约有 1 万到 10 万个同时连接，而且由于它们有需要在毫秒内从进程中获取结果的实时要求。

+   **网关应用程序**：提供技术和管理域的桥接。除了已经提到的特征，这些应用程序在实时环境中处理大量连接，但接口数量并不是很多。它们还要求在通信过程中不丢失帧或数据包。

+   **管理应用程序**：通常提供计费操作、网络管理和其他传统服务。它们对实时操作没有同样强烈的要求，而是集中于快速数据库操作和其他面向通信的请求。

为了确保它能满足前述类别，CGL 工作组专注于两项主要活动。第一项涉及与前述类别的沟通，确定它们的需求，并编写应该由分发供应商实施的规范。第二项涉及收集和帮助满足规范中定义的要求的项目。总之，CGL 试图代表的不仅是电信行业代表和 Linux 发行版，还有最终用户和服务提供商；它还为每个类别提供了运营商级别的选项。

每个希望获得 CGL 认证的发行供应商都会提供其实施作为模板。它填充了软件包的版本、名称和其他额外信息。然而，它在不披露太多有关实施过程的信息的情况下进行，这些软件包可能是专有软件。此外，披露的信息由供应商拥有和维护。CGL 工作组只显示供应商提供的链接。

规范文档现在已经到了 5.0 版本，包含了对于载波级认证的 Linux 发行版中实际上是强制性的或可选的应用程序的要求。强制性的要求由 P1 优先级描述，可选的要求标记为 P2。其他元素与缺口方面有关，表示一个功能，由于没有针对它的开源实现，因此未实现。规范文档中提出了这些要求，以激励发行版开发人员为其做出贡献。

如下图所示，并且在规范文档中强调的信息中所述，CGL 系统应提供大量功能：

![Carrier Grade Linux](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00385.jpeg)

由于功能数量的要求很大，工作组决定将它们分成以下各类：

+   **可用性**：对于单节点的可用性和恢复是相关的。

+   **集群**：它描述了在从个体系统构建集群中有用的组件。其背后的关键目标是系统的高可用性和负载平衡，这也可能带来一些性能改进。

+   **可维护性**：它涵盖了系统的维护和维修功能。

+   **性能**：它描述了一些功能，如实时要求等，可以帮助系统实现更好的性能。

+   **标准**：这些作为各种 API、标准和规范的参考。

+   **硬件**：它提供了必要的载波级操作系统的各种硬件特定支持。其中大部分来自参与此过程的硬件供应商，而这一部分的要求在最新的 CGL 规范发布中已大大减少。

+   **安全**：它代表了构建安全系统所需的相关功能。

### 注意

有关 CGL 要求的更多信息，请参考[`www.linuxfoundation.org/sites/main/files/CGL_5.0_Specification.pdf`](https://www.linuxfoundation.org/sites/main/files/CGL_5.0_Specification.pdf)。您还可以参考 CGL 工作组[`www.linuxfoundation.org/collaborate/workgroups/cgl`](https://www.linuxfoundation.org/collaborate/workgroups/cgl)。

## 汽车级 Linux

汽车级 Linux 也是 Linux 基金会的一个工作组。它是新成立的，试图提供一个具有汽车应用的开源解决方案。它的主要重点是车载信息娱乐领域，但它还包括远程信息系统和仪表盘。它的努力基于已经可用的开源组件。这些组件适用于它的目的，并且还试图实现快速开发，这在这个行业中是非常需要的。

工作组的目标是：

+   一个透明、协作和开放的环境，涉及到的元素。

+   一个专注于汽车的 Linux 操作系统堆栈，利用开源社区的支持，如开发人员、学术组件和公司。

+   开源社区的集体声音这次以相反的形式发布，从 AGL 到社区。

+   用于快速原型设计的嵌入式 Linux 发行版。

通过使用项目，如 Tizen，作为参考发行版，并拥有像 Jaguar、Nissan、路虎或丰田这样的项目，这个项目足够有趣，值得密切关注。它刚刚被开发出来，但有改进的潜力。对于那些对此感兴趣的人，请参考[`www.linuxfoundation.org/collaborate/workgroups/automotive-grade-linux`](https://www.linuxfoundation.org/collaborate/workgroups/automotive-grade-linux)。该项目的维基页面是一个有趣的资源，可以在[`wiki.automotivelinux.org/`](https://wiki.automotivelinux.org/)上查阅。

## 运营商级虚拟化

CGL 的最新发展使得虚拟化成为运营商级领域的一个有趣选择，因为它涉及到降低成本以及透明地利用运行单核设计应用程序的多核设备。虚拟化选项也需要满足其他运营商级系统的期望。

运营商级虚拟化一直试图成为集成在已有的运营商级平台中的一个重要组成部分。这是为了保留系统的属性和性能。它还试图扩展设备目标，并允许**原始设备制造商**（OEM）从与 CGL 相同的支持中获益。这些好处以成熟的目标形式存在。

虚拟化的应用更加广泛，可以看到从 x86 架构到基于 ARM 和 DSP 的处理器以及各种领域。从运营商级的角度来看虚拟化的研究是这个解决方案的重点，因为这样可以更清晰地看到需要改进的领域。通过这种方式，可以识别这些领域，并根据需要进行改进。不幸的是，这个倡议并没有像其他一些倡议那样被广泛宣传，但它仍然是一个非常好的文档来源，并且可以从 virtualLogix 的[`www.linuxpundit.com/documents/CGV_WP_Final_FN.pdf`](http://www.linuxpundit.com/documents/CGV_WP_Final_FN.pdf)获取。希望你喜欢它的内容。

# Yocto 项目的特定支持

在 Poky 参考系统中，支持 LSB 和兼容 LSB 应用程序的开发。在 Poky 中，有一个特殊的`poky-lsb.conf`分发策略配置，如果一个发行版有兴趣开发符合 LSB 标准的应用程序，就需要定义这个配置。这在生成一个符合 LSB 标准的 Linux 发行版或者至少准备获得 LSB 认证时是成立的。这里将介绍准备 LSB 认证所需的 Linux 发行版构建步骤。如果你有兴趣开发符合 LSB 标准的应用程序，这个过程会更简单，也会在这里简要介绍；然而，这与前者相反。

第一步很简单：只需要克隆 poky 存储库和`meta-qt3`依赖层，因为 LSB 模块的要求。

```
git clone git://git.yoctoproject.org/poky.git
git clone git://git.yoctoproject.org/meta-qt3

```

接下来，需要创建构建目录：

```
source oe-init-build-env -b ../build_lsb

```

在`conf/bblayers.conf`文件中，只需要添加`meta-qt3`层。在`conf/local.conf`文件中，应选择相应的机器。我建议选择一个性能强大的平台，但如果为这样的演示提供了足够的 CPU 和内存，使用模拟架构，比如`qemuppc`，也应该足够了。还要确保将`DISTRO`变量更改为`poky-lsb`。所有这些准备就绪后，构建过程可以开始。这需要以下命令：

```
bitbake core-image-lsb

```

生成的二进制文件在所选的机器上生成并引导后，用户可以使用`LSB_Test.sh`脚本运行所有测试，该脚本还设置了 LSB 测试框架环境，或者运行特定的测试套件：

```
/usr/bin/LSB_Test.sh

```

你也可以使用以下命令：

```
cd /opt/lsb/test/manager/utils
./dist-checker.pl –update
./dist-checker.pl –D –s 'LSB 4.1' <test_suite>

```

如果各种测试未通过，系统需要重新配置以确保所需的兼容性水平。在`meta/recipes-extended/images`中，除了`core-image-lsb.bb`配方外，还有两个类似的配方：

+   `core-image-lsb-sdk.bb`：它包括一个`meta-toolchain`和生成应用程序开发所需的必要库和开发头文件

+   `core-image-lsb-dev.bb`：适用于目标开发工作，因为它包括`dev-pkgs`，这些包暴露了特定于图像的软件包所需的头文件和库

在 Yocto 项目中，有一个名为`meta-cgl`的层，旨在成为 CGL 倡议的基石。它汇集了 CGL 工作组定义的所有可用和必需的软件包。该层的格式试图为将来支持各种机器上的 CGL 设置舞台。在`meta-cgl`层内，有两个子目录：

+   `meta-cgl-common`：这是活动的焦点位置，也是在 poky 内提供支持的子目录，例如`qemuarm`，`qemuppc`等。

+   `meta-cgl-fsl-ppc`：这是一个定义 BSP 特定支持的子目录。如果需要其他机器的支持，应该提供这样的层。

正如我已经提到的，`meta-cgl`层负责 CGL 支持。正如之前提到的，CGL 的要求之一是具有 LSB 支持，而这种支持在 Poky 内是可用的。它作为一个特定要求集成在这个层内。`meta-cgl`层的另一个建议是将所有可用的软件包分组到定义各种类别的软件包组中。可用的软件包组非常通用，但所有可用的软件包都集成在一个称为`packagegroup-cgl.bb`的核心软件包组中。

该层还公开了一个符合 CGL 的操作系统镜像。该镜像试图首先包含各种 CGL 特定的要求，并打算通过包含 CGL 规范文档中定义的所有要求来增长。除了符合 CGL 要求并准备进行 CGL 认证的结果 Linux 操作系统外，该层还试图定义一个特定于 CGL 的测试框架。这项任务可能看起来类似于 LSB 检查兼容性所需的任务，但我向您保证它并不相同。它不仅需要根据定义的规范制定一个特定于 CGL 的语言定义，还需要一系列与语言定义保持同步的测试定义。此外，有一些要求可以通过一个软件包或软件包的功能来满足，这些要求应该被收集并组合在一起。还有各种其他情景可以被解释和正确回答；这是使 CGL 测试成为一项艰巨任务的条件。

在`meta-cgl`层内，有以下软件包的配方：

+   `cluster-glue`

+   `cluster-resource-agents`

+   `corosync`

+   `heartbeat`

+   `lksctp-tools`

+   `monit`

+   `ocfs2-tools`

+   `openais`

+   `pacemaker`

+   `openipmi`

除了这些配方，还有其他一些对于各种 CGL 要求是必要的。`meta-cgl`倡议所提供的支持正如前面所述的那样。它还将包含这些软件包：

+   `evlog`

+   `mipv6-daemon-umip`

+   `makedumpfile`

所有这些都是必要的，以提供具有 LSB 支持和 CGL 兼容性的基于 Linux 的操作系统。这将在适当的时候完成，也许当这本书到达您手中时，该层将以其最终格式存在，并成为 CGL 兼容性的标准。

我现在将开始解释一些您可能在 CGL 环境中遇到的软件包。我将首先从 Heartbeat 守护程序开始，它为集群服务提供通信和成员资格。将其放置在那里将使客户端能够确定其他机器上可用进程的当前状态，并与它们建立通信。

为了确保 Heartbeat 守护程序是有用的，它需要与**集群资源管理器**（**CRM**）一起使用，后者负责启动和停止各种服务，以获得高可用性的 Linux 系统。这个 CRM 被称为**Pacemaker**，它无法检测资源级别的故障，只能与两个节点进行交互。随着时间的推移，它得到了改进，现在有更好的支持和额外的用户界面可用。其中一些服务如下：

+   **crm shell**：这是由 Dejan Muhamedagic 实现的命令行界面，用于隐藏 XML 配置并帮助进行交互。

+   **高可用性 Web 控制台**：这是一个 AJAX 前端

+   **Heartbeat GUI**：这是一个提供大量相关信息的高级 XML 编辑器

+   **Linux 集群管理控制台（LCMC）**：它最初是**DRBD-管理控制台**（**DRBD-MC**），是一个用于 Pacemaker 管理目的的 Java 平台。

Pacemaker 接受三种类型的资源代理（资源代理代表集群资源之间的标准接口）。资源代理是 Linux-HA 管理的项目，由 ClusterLabs 的人员提供和维护。根据所选择的类型，它能够执行操作，如对给定资源的启动/停止，监视，验证等。支持的资源代理包括：

+   LSB 资源代理

+   OCF 资源代理

+   传统的 Heartbeat 资源代理

**Cluster Glue**是与 Pacemaker/Heartbeat 一起使用的一组库、实用程序和工具。它基本上是将集群资源管理器（我指的是 Pacemaker）和消息传递层（可能是 Heartbeat）之间的一切联系在一起的粘合剂。尽管它最初是 Heartbeat 的一个组件，但现在它作为 Linux-HA 子项目的一个独立组件进行管理。它有一些有趣的组件：

+   **Local Resource Manager (LRM)**：它充当 Pacemaker 和资源代理之间的接口，不具备集群感知能力。其任务包括处理从 CRM 接收的命令，将其传递给资源代理，并报告这些活动。

+   **Shoot The Other Node In The Head (STONITH)**：这是一种机制，用于通过使集群认为已经死亡的节点来进行节点围栏，以便将其从中移除并防止任何交互风险。

+   **hb_report**：这是一个经常用于故障修复和隔离问题的错误报告实用程序。

+   **集群管道库**：这是一个低级别的集群间通信库。

### 注意

有关 Linux-HA 的更多信息，以下链接可能会有所帮助：[`www.linux-ha.org/doc/users-guide/users-guide.html`](http://www.linux-ha.org/doc/users-guide/users-guide.html)

接下来的元素是 Corosync 集群引擎。它是从 OpenAIS 衍生出来的项目，即将介绍。它是一个具有一系列功能和实现的组通信系统，试图提供高可用性支持，并在 BSD 许可下授权。其功能包括以下内容：

+   一个用于在故障发生时重新启动应用程序的可用性管理器。

+   一个关于仲裁状态及其是否已经实现的仲裁系统通知。

+   一个支持同步以复制状态机的封闭进程组通信模型。

+   一个驻留在内存中的配置和统计数据库。它提供了接收、检索、设置和更改各种通知的能力。

接下来，我们将看看 OpenAIS。这是由**Service Availability Forum**（**SA**或**SA Forum**）提供的**Application Interface Specification**（**AIS**）的开放实现。它代表了提供高可用性支持的接口。OpenAIS 中的源代码随着时间的推移在 OpenAIS 中进行了重构，只剩下了 SA Forum 特定的 API 和 Corosync 中的核心基础设施组件。OpenAIS 与 Heartbeat 非常相似；事实上，它是 Heartbeat 的替代品，是行业标准特定的。它也得到了 Pacemaker 的支持。

### 注意

有关 AIS 的更多信息可以在其维基百科页面和 SA 论坛网站上找到[`www.saforum.org/page/16627~217404/Service-Availability-Forum-Application-Interface-Specification`](http://www.saforum.org/page/16627~217404/Service-Availability-Forum-Application-Interface-Specification)。

接下来是`ocfs2-tools`软件包。这是一组实用程序，可以以创建、调试、修复或管理 OCFS2 文件系统的形式进行工作。它包括与 Linux 用户习惯的非常相似的工具，如`mkfs.ocfs2`、`mount.ocfs2 fsck.ocfs2`、`tunefs.ocfs2`和`debugfs.ocfs2`。

**Oracle Cluster File System** (**OCFS**)是由 Oracle 开发的第一个共享磁盘文件系统，并在 GNU 通用公共许可证下发布。它不是一个符合 POSIX 标准的文件系统，但当 OCFS2 出现并集成到 Linux 内核中时，情况发生了变化。随着时间的推移，它成为了一个分布式锁管理器，能够提供高可用性和高性能。现在它被用于各种场合，如虚拟化、数据库集群、中间件和设备。以下是它的一些显著特点：

+   优化的分配

+   REFLINKs

+   元数据校验和

+   索引目录

+   每个 inode 的扩展属性

+   用户和组配额

+   高级安全性，如 SELinux 和 POSIX ACL 支持

+   集群感知工具，如前面提到的工具，包括 mkfs、tunefs、fsck、mount 和 debugfs

+   内置的具有分布式锁管理器的 Clusterstack

+   日志记录

+   可变块和簇大小

+   缓冲，内存映射，拼接，直接，异步 I/O

+   架构和端中立

`lksctp-tools`软件包是一个 Linux 用户空间实用程序，包括一个库和适当的 C 语言头文件，用于与 SCTP 接口进行交互。自 2.6 版本以来，Linux 内核就支持 SCTP，因此用户空间兼容性工具的存在对任何人来说都不足为奇。Lksctp 提供对 SCTP 基于套接字的 API 的访问。该实现是根据 IETF 互联网草案制定的，可在[`tools.ietf.org/html/draft-ietf-tsvwg-sctpsocket-15`](http://tools.ietf.org/html/draft-ietf-tsvwg-sctpsocket-15)上找到。它提供了一种灵活和一致的开发基于套接字的应用程序的方法，利用了**Stream Control Transmission Protocol**（**SCTP**）。

SCTP 是一种面向消息的传输协议。作为传输层协议，它在 IPv4 或 IPv6 实现上运行，并且除了 TCP 的功能外，还提供对这些功能的支持：

+   多流

+   消息帧

+   多宿

+   有序和无序消息传递

+   安全和认证

这些特殊功能对于行业载波级系统是必要的，并且在电话信令等领域中使用。

### 注意

有关 SCTP 的更多信息，请访问[`www.ietf.org/rfc/rfc2960.txt`](http://www.ietf.org/rfc/rfc2960.txt)和[`www.ietf.org/rfc/rfc3286.txt`](http://www.ietf.org/rfc/rfc3286.txt)

现在，我将稍微改变一下节奏，解释一下**monit**，这是一个非常小但功能强大的实用程序，用于监视和管理系统。它在自动维护和修复 Unix 系统方面非常有用，例如 BSD 发行版、各种 Linux 发行版以及可能包括 OS X 在内的其他平台。它可用于各种任务，包括文件监视、文件系统更改以及与事件进程的交互，如果通过各种阈值。

很容易配置和控制 monit，因为所有配置都基于易于理解的基于令牌的语法。此外，它提供了各种日志和关于其活动的通知。它还提供了一个网页浏览器界面，以便更容易访问。因此，拥有一个通用的系统资源管理器，也很容易与之交互，使 monit 成为运营商级 Linux 系统的选择。如果您有兴趣了解更多信息，请访问项目的网站[`mmonit.com/monit/`](http://mmonit.com/monit/)。

**OpenIPMI**是**智能平台管理接口**（**IPMI**）的实现，旨在提供对 IPMI 所有功能的访问，并为更容易使用提供抽象。它由两个组件组成：

+   可插入 Linux 内核的内核驱动程序

+   提供 IPMI 的抽象功能并提供对操作系统使用的各种服务的访问的库

IPMI 代表一组计算机接口规范，旨在通过提供智能和自主的系统来监视和管理主机系统的功能，从而降低总体拥有成本。这里我们不仅指的是操作系统，还包括固件和 CPU 本身。这个智能接口的开发由英特尔领导，现在得到了令人印象深刻的公司的支持。

### 注意

有关 IPMI、OpenIMPI 和其他支持的 IPMI 驱动程序和功能的更多信息，请访问[`openipmi.sourceforge.net/`](http://openipmi.sourceforge.net/)和[`www.intel.com/content/www/us/en/servers/ipmi/ipmi-home.html`](http://www.intel.com/content/www/us/en/servers/ipmi/ipmi-home.html)。

`meta-cgl`层中还应该有一些软件包，但在撰写本章时，它们仍然不可用。我将从`mipv6-daemon-umip`开始，它试图为**移动互联网协议版本 6**（**MIPv6**）守护程序提供数据分发。**UMIP**是一个基于 MIPL2 的开源移动 IPv6 堆栈，维护着最新的内核版本。该软件包是**UniverSAl playGround** **for Ipv6**（**USAGI**）项目对 MIPL2 的一组补丁，该项目试图为 Linux 系统提供 IPsec（IPv6 和 IPv4 选项）和 IPv6 协议栈实现的行业就绪质量。

### 注意

有关 UMIP 的更多信息，请访问[`umip.linux-ipv6.org/index.php?n=Main.Documentation`](http://umip.linux-ipv6.org/index.php?n=Main.Documentation)。

**Makedumfile**是一个工具，可以压缩转储文件的大小，并且还可以排除不需要进行分析的内存页面。对于一些 Linux 发行版，它与一个名为`kexec-tools`的软件包一起提供，可以使用运营商级规范支持的软件包管理器 RPM 在您的发行版中安装。它与`gzip`或`split`等命令非常相似。它只接收来自 ELF 格式文件的输入，这使得它成为`kdumps`的首选。

另一个有趣的项目是`evlog`，这是一个**用于企业级系统的 Linux 事件记录系统**。它也符合 POSIX 标准，并提供了从`printk`到`syslog`以及其他内核和用户空间函数的各种形式的日志记录。输出事件以符合 POSIX 标准的格式提供。它还在选择与特定定义的过滤器匹配的日志或注册特殊事件格式时提供支持。只有在满足注册的事件过滤器时才能通知这些事件。它的功能确实使这个软件包变得有趣，并且可以在[`evlog.sourceforge.net/`](http://evlog.sourceforge.net/)上找到。

还有许多其他软件包可以包含到`meta-cgl`层中。查看注册的 CGL 发行版可以帮助你了解这样一个项目的复杂性。为了更容易地访问这个列表，请参考[`www.linuxfoundation.org/collaborate/workgroups/cgl/registered-distributions`](http://www.linuxfoundation.org/collaborate/workgroups/cgl/registered-distributions)以简化搜索过程。

与`meta-cgl`层互动的第一步是确保所有相互依赖的层都可用。关于如何构建兼容运营级的 Linux 镜像的最新信息始终可以在附加的`README`文件中找到。我在这里也给出了一个示例以进行演示：

```
git clone git://git.yoctoproject.org/poky.git
cd ./poky
git clone git://git.yoctoproject.org /meta-openembedded.git
git clone git://git.enea.com/linux/meta-cgl.git
git clone git://git.yoctoproject.org/meta-qt3
git clone git://git.yoctoproject.org/meta-virtualization
git clone git://git.yoctoproject.org/meta-selinux
git clone git://git.yoctoproject.org/meta-cloud-services
git clone git://git.yoctoproject.org/meta-security
git clone https://github.com/joaohf/meta-openclovis.git

```

接下来，需要创建和配置构建目录：

```
source oe-init-build-env -b ../build_cgl

```

在`conf/bblayers.conf`文件中，需要添加以下层：

```
meta-cgl/meta-cgl-common
meta-qt3
meta-openembedded/meta-networking
meta-openembedded/meta-filesystems
meta-openembedded/meta-oe
meta-openembedded/meta-perl
meta-virtualization
meta-openclovis
meta-selinux
meta-security
meta-cloud-services/meta-openstack
```

在`conf/local.conf`文件中，应选择相应的机器。我建议选择`qemuppc`，以及可以更改为`poky-cgl`的`DISTRO`变量。由于食谱的重复，应该提供`BBMASK`：

```
BBMASK = "meta-openembedded/meta-oe/recipes-support/multipath-tools"
```

有了这些准备，构建过程就可以开始了。这个过程的必要命令是：

```
bitbake core-image-cgl

```

确保你有时间花在这上面，因为构建可能需要一段时间，这取决于你的主机系统的配置。

# 总结

在本章中，你们了解了运营级 Linux 和 Linux 标准基础所需的规范信息。其他选项，如汽车级和运营级虚拟化，也得到了解释，最后，为了完成这个学习过程，我向你们展示了对 Yocto 项目的支持和一些演示。

这是本书的最后一章，我希望你们喜欢这段旅程。同时，我希望我能够把我所学到的一些信息传递给你们。既然我们已经到了这本书的结尾，我必须承认在写书的过程中我也学到了新的信息。我希望你们也能对 Yocto 项目产生兴趣，并且能够为 Yocto 项目和开源社区做出贡献。我相信从现在开始，嵌入式世界对你来说将不再有太多秘密。确保你也向其他人阐明这个话题！
