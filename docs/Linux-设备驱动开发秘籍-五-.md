# Linux 设备驱动开发秘籍（五）

> 原文：[`zh.annas-archive.org/md5/6B7A321F07B3F3827350A558F12EF0DA`](https://zh.annas-archive.org/md5/6B7A321F07B3F3827350A558F12EF0DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：附加信息：管理中断和并发

回顾我们在[第三章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=28&action=edit#post_26)中所做的工作，即*使用 Char 驱动程序*，当我们讨论`read()`系统调用以及如何为我们的 char 驱动程序实现它时（请参阅 GitHub 上的`chapter_4/chrdev/chrdev.c`文件），我们注意到我们的实现很棘手，因为数据总是可用的：

```
static ssize_t chrdev_read(struct file *filp,
               char __user *buf, size_t count, loff_t *ppos)
{
    struct chrdev_device *chrdev = filp->private_data;
    int ret;

    dev_info(chrdev->dev, "should read %ld bytes (*ppos=%lld)\n",
                count, *ppos);

    /* Check for end-of-buffer */
    if (*ppos + count >= BUF_LEN)
        count = BUF_LEN - *ppos;

    /* Return data to the user space */
    ret = copy_to_user(buf, chrdev->buf + *ppos, count);
    if (ret < 0)
        return ret;

    *ppos += count;
    dev_info(chrdev->dev, "return %ld bytes (*ppos=%lld)\n", count, *ppos);

    return count;
}
```

在前面的示例中，`chrdev->buf`中的数据总是存在的，但在真实的外围设备中，这往往并不是真的；我们通常必须等待新数据，然后当前进程应该被挂起（即*休眠*）。这就是为什么我们的`chrdev_read()`应该是这样的：

```
static ssize_t chrdev_read(struct file *filp,
               char __user *buf, size_t count, loff_t *ppos)
{
    struct chrdev_device *chrdev = filp->private_data;
    int ret;

    /* Wait for available data */
    wait_for_event(chrdev->available > 0);

    /* Check for end-of-buffer */
    if (count > chrdev->available)
        count = chrdev->available;

    /* Return data to the user space */
    ret = copy_to_user(buf, ..., count);
    if (ret < 0)
        return ret;

    *ppos += count;

    return count;
}
```

请注意，由于一个真实（完整的）`read()`系统调用实现将在第七章中呈现，所以本示例故意不完整。在本章中，我们只是介绍机制，而不是如何在设备驱动程序中使用它们。

通过使用`wait_for_event()`函数，我们要求内核测试是否有一些可用数据，如果有的话，允许进程执行，否则，当前进程将被挂起，一旦条件`chrdev->available > 0`为真，就会再次唤醒。

外围设备通常使用中断来通知 CPU 有新数据可用（或者必须对它们进行一些重要的活动），因此很明显，我们作为设备驱动程序开发人员，必须在中断处理程序中通知内核，等待数据的睡眠进程应该被唤醒。在接下来的章节中，我们将通过使用非常简单的示例来看看内核中有哪些机制可用，并且它们如何被用来挂起一个进程，我们还将看到什么时候可以安全地这样做！事实上，如果我们要求调度程序在中断处理程序中将 CPU 撤销给当前进程以便将其分配给另一个进程，那么我们只是在进行一个无意义的操作。当我们处于中断上下文时，我们并不执行进程代码，那么我们可以撤销 CPU 给哪个进程呢？简而言之，当 CPU 处于进程上下文时，执行进程可以*进入睡眠*，而当我们处于中断上下文时，我们不能这样做，因为当前没有进程正式持有 CPU！

这个概念非常重要，设备驱动程序开发人员必须充分理解；事实上，如果我们尝试在 CPU 处于中断上下文时进入睡眠状态，那么将会生成一个严重的异常，并且很可能整个系统都会挂起。

另一个需要真正清楚的重要概念是**原子操作**。设备驱动程序不是一个有常规开始和结束的正常程序；相反，设备驱动程序是一组可以同时运行的方法和异步中断处理程序。这就是为什么我们很可能必须保护我们的数据，以防可能损坏它们的竞争条件。

例如，如果我们使用缓冲区仅保存来自外围设备的接收数据，我们必须确保数据被正确排队，以便读取进程可以读取有效数据，而且不会丢失任何信息。因此，在这些情况下，我们应该使用一些 Linux 提供给我们的互斥机制来完成我们的工作。然而，我们必须注意我们所做的事情，因为其中一些机制可以在进程或中断上下文中安全使用，而另一些则不行；其中一些只能在进程上下文中使用，如果我们在中断上下文中使用它们，可能会损坏我们的系统。

此外，我们应该考虑到现代 CPU 有多个核心，因此使用禁用 CPU 中断的技巧来获得原子代码根本行不通，必须使用特定的互斥机制。在 Linux 中，这种机制称为**自旋锁**，它可以在中断或进程上下文中使用，但是只能用于非常短的时间，因为它们是使用忙等待方法实现的。这意味着为了执行原子操作，当一个核心在属于这种原子操作的关键代码部分中操作时，CPU 中的所有其他核心都被排除在同一关键部分之外，通过在紧密循环中积极旋转来等待，这反过来意味着你实际上在浪费 CPU 的周期，这些周期没有做任何有用的事情。

在接下来的章节中，我们将详细讨论所有这些方面，并尝试用非常简单的例子解释它们的用法；在[第七章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=28&action=edit#post_30)，*高级字符驱动程序操作*中，我们将看到如何在设备驱动程序中使用这些机制。

# 推迟工作

很久以前，有**底半部**，也就是说，硬件事件被分成两半：顶半部（硬件中断处理程序）和底半部（软件中断处理程序）。这是因为中断处理程序必须尽快执行，以准备为下一个传入的中断提供服务，因此，例如，CPU 不能在中断处理程序的主体中等待慢速外围设备发送或接收数据的时间太长。这就是为什么我们使用底半部；中断被分成两部分：顶部是真正的硬件中断处理程序，它快速执行并禁用中断，只是确认外围设备，然后启动一个底半部，启用中断，可以安全地完成发送/接收工作。

然而，底半部非常有限，因此内核开发人员在 Linux 2.4 系列中引入了**tasklets**。Tasklets 允许以非常简单的方式动态创建可延迟的函数；它们在软件中断上下文中执行，适合快速执行，因为它们不能休眠。但是，如果我们需要休眠，我们必须使用另一种机制。在 Linux 2.6 系列中，**workqueues**被引入作为 Linux 2.4 系列中已经存在的类似构造称为 taskqueue 的替代品；它们允许内核函数像 tasklets 一样被激活（或延迟）以供以后执行，但是与 tasklets（在软件中断中执行）相比，它们在称为**worker threads**的特殊内核线程中执行。这意味着两者都可以用于推迟工作，但是 workqueue 处理程序可以休眠。当然，这个处理程序的延迟更高，但是相比之下，workqueues 包括更丰富的工作推迟 API。

在结束本食谱之前，还有两个重要的概念要谈论：共享工作队列和`container_of()`宏。

# 共享工作队列

在食谱中的前面的例子可以通过使用**共享工作队列**来简化。这是内核本身定义的一个特殊工作队列，如果设备驱动程序（和其他内核实体）*承诺*不会长时间垄断队列（也就是说不会长时间休眠和不会长时间运行的任务），如果它们接受它们的处理程序可能需要更长时间来获得公平的 CPU 份额。如果两个条件都满足，我们可以避免使用`create_singlethread_workqueue()`创建自定义工作队列，并且可以通过简单地使用`schedule_work()`和`schedule_delayed_work()`来安排工作。以下是处理程序：

```
--- a/drivers/misc/irqtest.c
+++ b/drivers/misc/irqtest.c
...
+static void irqtest_work_handler(struct work_struct *ptr)
+{
+     struct irqtest_data *info = container_of(ptr, struct irqtest_data,
+                                                      work);
+     struct device *dev = info->dev;
+
+     dev_info(dev, "work executed after IRQ %d", info->irq);
+
+     /* Schedule the delayed work after 2 seconds */
+     schedule_delayed_work(&info->dwork, 2*HZ);
+}
+
 static irqreturn_t irqtest_interrupt(int irq, void *dev_id)
 {
      struct irqtest_data *info = dev_id;
@@ -36,6 +60,8 @@ static irqreturn_t irqtest_interrupt(int irq, void *dev_id)

      dev_info(dev, "interrupt occurred on IRQ %d\n", irq);

+     schedule_work(&info->work);
+
      return IRQ_HANDLED;
 }
```

然后，初始化和移除的修改：

```
@@ -80,6 +106,10 @@ static int irqtest_probe(struct platform_device *pdev)
      dev_info(dev, "GPIO %u correspond to IRQ %d\n",
                                irqinfo.pin, irqinfo.irq);

+     /* Init works */
+     INIT_WORK(&irqinfo.work, irqtest_work_handler);
+     INIT_DELAYED_WORK(&irqinfo.dwork, irqtest_dwork_handler);
+
      /* Request IRQ line and setup corresponding handler */
      irqinfo.dev = dev;
      ret = request_irq(irqinfo.irq, irqtest_interrupt, 0,
@@ -98,6 +128,8 @@ static int irqtest_remove(struct platform_device *pdev)
 {
        struct device *dev = &pdev->dev;

+     cancel_work_sync(&irqinfo.work);
+     cancel_delayed_work_sync(&irqinfo.dwork);
      free_irq(irqinfo.irq, &irqinfo);
      dev_info(dev, "IRQ %d is now unmanaged!\n", irqinfo.irq);
```

前面的补丁可以在 GitHub 存储库的`add_workqueue_2_to_irqtest_module.patch`文件中找到，并且可以使用以下命令像往常一样应用：

**`$ patch -p1 < add_workqueue_2_to_irqtest_module.patch`**

# `container_of()`宏

最后，我们应该利用一些词来解释一下`container_of()`宏。该宏在`linux/include/linux/kernel.h`中定义如下：

```
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({ \
    void *__mptr = (void *)(ptr); \
    BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) && \
                     !__same_type(*(ptr), void), \
                     "pointer type mismatch in container_of()"); \
    ((type *)(__mptr - offsetof(type, member))); })
```

`container_of()`函数接受三个参数：一个指针`ptr`，容器的`type`，以及指针在容器内引用的`member`的名称。通过使用这些信息，宏可以扩展为指向包含结构的新地址，该结构容纳了相应的成员。

因此，在我们的示例中，在`irqtest_work_handler()`中，我们可以获得一个指向`struct irqtest_data`的指针，以告诉`container_of()`其成员`work`的地址。

有关`container_of()`函数的更多信息，可以在互联网上找到；但是，一个很好的起点是内核源代码中的`linux/Documentation/driver-model/design-patterns.txt`文件，该文件描述了在使用此宏的设备驱动程序中发现的一些常见设计模式。

可能有兴趣看一下**通知器链**，简称**通知器**，它是内核提供的一种通用机制，旨在为内核元素提供一种表达对一般**异步**事件发生感兴趣的方式。

# 通知器

通知器机制的基本构建块是在`linux/include/linux/notifier.h`头文件中定义的`struct notifier_block`，如下所示：

```
typedef int (*notifier_fn_t)(struct notifier_block *nb,
                        unsigned long action, void *data);

struct notifier_block {
    notifier_fn_t notifier_call;
    struct notifier_block __rcu *next;
    int priority;
};
```

该结构包含指向发生事件时要调用的函数的指针`notifier_call`。当调用通知器函数时传递的参数包括指向通知器块本身的`nb`指针，一个依赖于特定使用链的事件`action`代码，以及指向未指定私有数据类型的`data`指针，该类型可以以与 tasklets 或 waitqueues 类似的方式使用。

`next`字段由通知器内部管理，而`priority`字段定义了在通知器链中由`notifier_call`指向的函数的优先级。首先执行具有更高优先级的函数。实际上，几乎所有注册都将优先级留给通知器块定义之外，这意味着它以 0 作为默认值，并且执行顺序最终取决于注册顺序（这是一种半随机顺序）。

设备驱动程序开发人员不应该需要创建自己的通知器，而且很多时候他们需要使用现有的通知器。Linux 定义了几个通知器，如下所示：

+   网络设备通知器（参见`linux/include/linux/netdevice.h`）-报告网络设备的事件

+   背光通知器（参见`linux/include/linux/backlight.h`）-报告 LCD 背光事件

+   挂起通知器（参见`linux/include/linux/suspend.h`）-报告挂起和恢复相关事件的电源

+   重启通知器（参见`linux/include/linux/reboot.h`）-报告重启请求

+   电源供应通知器（参见`linux/include/linux/power_supply.h`）-报告电源供应活动

每个通知器都有一个注册函数，可以用来要求系统在特定事件发生时通知。例如，以下代码被报告为请求网络设备和重启事件的有用示例：

```
static int __init notifier_init(void)
{
    int ret;

    ninfo.netdevice_nb.notifier_call = netdevice_notifier;
    ninfo.netdevice_nb.priority = 10; 

    ret = register_netdevice_notifier(&ninfo.netdevice_nb);
    if (ret) {
        pr_err("unable to register netdevice notifier\n");
        return ret;
    }

    ninfo.reboot_nb.notifier_call = reboot_notifier;
    ninfo.reboot_nb.priority = 10; 

    ret = register_reboot_notifier(&ninfo.reboot_nb);
    if (ret) {
        pr_err("unable to register reboot notifier\n");
        goto unregister_netdevice;
    }

    pr_info("notifier module loaded\n");

    return 0;

unregister_netdevice:
    unregister_netdevice_notifier(&ninfo.netdevice_nb);
    return ret;
}

static void __exit notifier_exit(void)
{
    unregister_netdevice_notifier(&ninfo.netdevice_nb);
    unregister_reboot_notifier(&ninfo.reboot_nb);

    pr_info("notifier module unloaded\n");
}
```

这里呈现的所有代码都在 GitHub 存储库中的`notifier.c`文件中。

`register_netdevice_notifier()`和`register_reboot_notifier()`函数都使用以下定义的两个 struct notifier_block：

```
static struct notifier_data {
    struct notifier_block netdevice_nb;
    struct notifier_block reboot_nb;
    unsigned int data;
} ninfo;
```

通知器函数的定义如下：

```
static int netdevice_notifier(struct notifier_block *nb,
                              unsigned long code, void *unused)
{
    struct notifier_data *ninfo = container_of(nb, struct notifier_data,
                                               netdevice_nb);

    pr_info("netdevice: event #%d with code 0x%lx caught!\n",
                    ninfo->data++, code);

    return NOTIFY_DONE;
}

static int reboot_notifier(struct notifier_block *nb,
                           unsigned long code, void *unused)
{ 
    struct notifier_data *ninfo = container_of(nb, struct notifier_data,
                                               reboot_nb);

    pr_info("reboot: event #%d with code 0x%lx caught!\n",
                    ninfo->data++, code);

    return NOTIFY_DONE;
}
```

通过使用`container_of()`，像往常一样，我们可以获得指向我们的数据结构`struct notifier_data`的指针；然后，一旦我们的工作完成，我们必须返回在`linux/include/linux/notifier.h`头文件中定义的一个固定值：

```
#define NOTIFY_DONE       0x0000                     /* Don't care */
#define NOTIFY_OK         0x0001                     /* Suits me */
#define NOTIFY_STOP_MASK  0x8000                     /* Don't call further */
#define NOTIFY_BAD        (NOTIFY_STOP_MASK|0x0002)  /* Bad/Veto action */
```

它们的含义如下：

+   `NOTIFY_DONE`：对此通知不感兴趣。

+   `NOTIFY_OK`：通知已正确处理。

+   `NOTIFY_BAD`：此通知出现问题，因此停止调用此事件的回调函数！

`NOTIFY_STOP_MASK`可以用于封装（负）`errno`值，如下所示：

```
/* Encapsulate (negative) errno value (in particular, NOTIFY_BAD <=> EPERM). */
static inline int notifier_from_errno(int err)
{
    if (err)
        return NOTIFY_STOP_MASK | (NOTIFY_OK - err);

    return NOTIFY_OK;
}
```

然后可以使用`notifier_to_errno()`检索`errno`值，如下所示：

```
/* Restore (negative) errno value from notify return value. */
static inline int notifier_to_errno(int ret)
{
    ret &= ~NOTIFY_STOP_MASK;
    return ret > NOTIFY_OK ? NOTIFY_OK - ret : 0;
}
```

要测试我们的简单示例，我们必须编译`notifier.c`内核模块，然后将`notifier.ko`模块移动到 ESPRESSObin，然后可以将其插入内核，如下所示：

```
# insmod notifier.ko 
notifier:netdevice_notifier: netdevice: event #0 with code 0x5 caught!
notifier:netdevice_notifier: netdevice: event #1 with code 0x1 caught!
notifier:netdevice_notifier: netdevice: event #2 with code 0x5 caught!
notifier:netdevice_notifier: netdevice: event #3 with code 0x5 caught!
notifier:netdevice_notifier: netdevice: event #4 with code 0x5 caught!
notifier:netdevice_notifier: netdevice: event #5 with code 0x5 caught!
notifier:notifier_init: notifier module loaded
```

插入后，已经通知了一些事件；但是，为了生成新事件，我们可以尝试使用以下`ip`命令禁用或启用网络设备：

```
# ip link set lan0 up
notifier:netdevice_notifier: netdevice: event #6 with code 0xd caught!
RTNETLINK answers: Network is down
```

代码`0xd`对应于`linux/include/linux/netdevice.h`中定义的`NETDEV_PRE_UP`事件：

```
/* netdevice notifier chain. Please remember to update netdev_cmd_to_name()
 * and the rtnetlink notification exclusion list in rtnetlink_event() when
 * adding new types.
 */
enum netdev_cmd {
    NETDEV_UP = 1, /* For now you can't veto a device up/down */
    NETDEV_DOWN,
    NETDEV_REBOOT, /* Tell a protocol stack a network interface
                      detected a hardware crash and restarted
                      - we can use this eg to kick tcp sessions
                      once done */
    NETDEV_CHANGE, /* Notify device state change */
    NETDEV_REGISTER,
    NETDEV_UNREGISTER,
    NETDEV_CHANGEMTU, /* notify after mtu change happened */
    NETDEV_CHANGEADDR,
    NETDEV_GOING_DOWN,
    NETDEV_CHANGENAME,
    NETDEV_FEAT_CHANGE,
    NETDEV_BONDING_FAILOVER,
    NETDEV_PRE_UP,
...
```

如果我们重新启动系统，我们应该在内核消息中看到以下消息：

```
# reboot
...
[ 2804.502671] notifier:reboot_notifier: reboot: event #7 with code 1 caught!
```

# 内核定时器

**内核定时器**是请求内核在经过明确定义的时间后执行特定函数的简单方法。 Linux 实现了两种不同类型的内核定时器：在`linux/include/linux/timer.h`头文件中定义的旧但仍然有效的内核定时器和在`linux/include/linux/hrtimer.h`头文件中定义的新的**高分辨率**内核定时器。即使它们实现方式不同，但两种机制的工作方式非常相似：我们必须声明一个保存定时器数据的结构，可以通过适当的函数进行初始化，然后可以使用适当的函数启动定时器。一旦到期，定时器调用处理程序执行所需的操作，最终，我们有可能停止或重新启动定时器。

传统内核定时器仅支持 1 个 jiffy 的分辨率。 jiffy 的长度取决于 Linux 内核中定义的`HZ`的值（请参阅`linux/include/asm-generic/param.h`文件）；通常在 PC 和其他一些平台上为 1 毫秒，在大多数嵌入式平台上设置为 10 毫秒。过去，1 毫秒的分辨率解决了大多数设备驱动程序开发人员的问题，但是现在，大多数外围设备需要更高的分辨率才能得到正确管理。这就是为什么需要更高分辨率的定时器，允许系统在更准确的时间间隔内快速唤醒和处理数据。目前，内核定时器已被高分辨率定时器所取代（即使它们仍然在内核源代码周围使用），其目标是在 Linux 中实现 POSIX 1003.1b 第十四部分（时钟和定时器）API，即精度优于 1 个 jiffy 的定时器。

请注意，我们刚刚看到，为了延迟作业，我们还可以使用延迟工作队列。


# 第十一章：附加信息：杂项内核内部

以下是有关动态内存分配和 I/O 内存访问方法的一些一般信息。

在谈论动态内存分配时，我们应该记住我们是在内核中使用 C 语言进行编程，因此非常重要的一点是要记住每个分配的内存块在不再使用时必须被释放。这非常重要，因为在用户空间，当一个进程结束执行时，内核（实际上知道进程拥有的所有内存块）可以轻松地收回所有进程分配的内存；但对于内核来说，情况并非如此。实际上，要求内存块的驱动程序（或其他内核实体）必须确保释放它，否则没有人会要求它回来，内存块将丢失，直到机器重新启动。

关于对 I/O 内存的访问，这是由底层外围寄存器下的内存单元组成的区域，我们必须考虑到我们不能使用它们的物理内存地址来访问它们；相反，我们将不得不使用相应的虚拟地址。事实上，Linux 是一个使用**内存管理单元**（MMU）来虚拟化和保护内存访问的操作系统，因此我们必须将每个外围设备的物理内存区域重新映射到其相应的虚拟内存区域，以便能够从中读取和写入。

这个操作可以很容易地通过使用代码段中介绍的内核函数来完成，但是非常重要的一点是必须在尝试进行任何 I/O 内存访问之前完成，否则将触发段错误。这可能会终止用户空间中的进程，或者可能因为设备驱动程序中的错误而终止内核本身。

# 动态内存分配

分配内存的最直接方式是使用`kmalloc()`函数，并且为了安全起见，最好使用清除分配的内存为零的例程，例如`kzalloc()`函数。另一方面，如果我们需要为数组分配内存，有专门的函数`kmalloc_array()`和`kcalloc()`。

以下是包含内存分配内核函数（以及相关的内核内存释放函数）的一些片段，如内核源文件`linux/include/linux/slab.h`中所述。

```
/**
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
...
*/
static __always_inline void *kmalloc(size_t size, gfp_t flags);

/**
 * kzalloc - allocate memory. The memory is set to zero.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kzalloc(size_t size, gfp_t flags)
{
    return kmalloc(size, flags | __GFP_ZERO);
}

/**
 * kmalloc_array - allocate memory for an array.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags);

/**
 * kcalloc - allocate memory for an array. The memory is set to zero.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
    return kmalloc_array(n, size, flags | __GFP_ZERO);
}

void kfree(const void *);
```

所有前述函数都暴露了用户空间对应的`malloc()`和其他内存分配函数之间的两个主要区别：

1.  使用`kmalloc()`和其他类似函数分配的块的最大大小是有限的。实际限制取决于硬件和内核配置，但是最好的做法是对小于页面大小的对象使用`kmalloc()`和其他内核辅助函数。

定义`PAGE_SIZE`信息内核源文件`linux/include/asm-generic/page.h`中指定了构成页面大小的字节数；通常情况下，32 位系统为 4096 字节，64 位系统为 8192 字节。用户可以通过通常的内核配置机制来明确选择它。

1.  用于动态内存分配的内核函数，如`kmalloc()`和类似函数，需要额外的参数；分配标志用于指定`kmalloc()`的行为方式，如下面从内核源文件`linux/include/linux/slab.h`中报告的片段所述。

```
/**
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * kmalloc is the normal method of allocating memory
 * for objects smaller than page size in the kernel.
 *
 * The @flags argument may be one of:
 *
 * %GFP_USER - Allocate memory on behalf of user. May sleep.
 *
 * %GFP_KERNEL - Allocate normal kernel ram. May sleep.
 *
 * %GFP_ATOMIC - Allocation will not sleep. May use emergency pools.
 * For example, use this inside interrupt handlers.
 *
 * %GFP_HIGHUSER - Allocate pages from high memory.
 *
 * %GFP_NOIO - Do not do any I/O at all while trying to get memory.
 *
 * %GFP_NOFS - Do not make any fs calls while trying to get memory.
 *
 * %GFP_NOWAIT - Allocation will not sleep.
...
```

正如我们所看到的，存在许多标志；然而，设备驱动程序开发人员主要感兴趣的是`GFP_KERNEL`和`GFP_ATOMIC`。

很明显，这两个标志之间的主要区别在于前者可以分配正常的内核 RAM 并且可能会休眠，而后者在不允许调用者休眠的情况下执行相同的操作。这两个函数之间的这个巨大区别告诉我们，当我们处于中断上下文或进程上下文时，我们必须使用哪个标志。

如[第五章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=6&action=edit#post_28)所示，*管理中断和并发*，当我们处于中断上下文时，我们不能休眠（如上面的代码所述），在这种情况下，我们必须通过指定`GFP_ATOMIC`标志来调用`kmalloc()`和相关函数，而`GFP_KERNEL`标志可以在其他地方使用，需要注意的是它可能导致调用者休眠，然后 CPU 可能会让我们执行其他操作；因此，我们应该避免以下操作：

```
spin_lock(...);
ptr = kmalloc(..., GFP_KERNEL);
spin_unlock(...);
```

实际上，即使我们在进程上下文中执行，持有自旋锁的休眠`kmalloc()`被认为是邪恶的！因此，在这种情况下，我们无论如何都必须使用`GFP_ATOMIC`标志。此外，需要注意的是，对于相同原因，成功的`GFP_ATOMIC`分配请求的最大大小往往比`GFP_KERNEL`请求要小，这与物理连续内存分配有关，内核保留了有限的内存池可供原子分配使用。

关于上面的第一点，对于可分配内存块的有限大小，对于大型分配，我们可以考虑使用另一类函数：`vmalloc()`和`vzalloc()`，即使我们必须强调`vmalloc()`和相关函数分配的内存不是物理上连续的，不能用于**直接内存访问**（**DMA**）活动（而`kmalloc()`和相关函数，如前面所述，分配了虚拟和物理寻址空间中的连续内存区域）。

目前，本书未涉及为 DMA 活动分配内存；但是，您可以在内核源代码中的`linux/Documentation/DMA-API.txt`和`linux/Documentation/DMA-API-HOWTO.txt`文件中获取有关此问题的更多信息。

以下是`vmalloc()`函数的原型和在`linux/include/linux/vmalloc.h`头文件中报告的函数定义：

```
extern void *vmalloc(unsigned long size);
extern void *vzalloc(unsigned long size);
```

如果我们不确定分配的大小是否对于`kmalloc()`来说太大，我们可以使用`kvmalloc()`及其衍生函数。这个函数将尝试使用`kmalloc()`来分配内存，如果分配失败，它将退而使用`vmalloc()`。

请注意，`kvmalloc()`可能返回的内存不是物理上连续的。

还有关于`kvmalloc()`可以与哪些`GFP_*`标志一起使用的限制，可以在[`www.kernel.org/doc/html/latest/core-api/mm-api.html#c.kvmalloc_node`](https://www.kernel.org/doc/html/latest/core-api/mm-api.html#c.kvmalloc_node)中的`kvmalloc_node()`文档中找到。

以下是`linux/include/linux/mm.h`头文件中报告的`kvmalloc()`、`kvzalloc()`、`kvmalloc_array()`、`kvcalloc()`和`kvfree()`的代码片段：

```
static inline void *kvmalloc(size_t size, gfp_t flags)
{
    return kvmalloc_node(size, flags, NUMA_NO_NODE);
}

static inline void *kvzalloc(size_t size, gfp_t flags)
{
    return kvmalloc(size, flags | __GFP_ZERO);
}

static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
    size_t bytes;

    if (unlikely(check_mul_overflow(n, size, &bytes)))
        return NULL;

    return kvmalloc(bytes, flags);
}

static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
    return kvmalloc_array(n, size, flags | __GFP_ZERO);
}

extern void kvfree(const void *addr);
```

# 内核双向链表

在使用 Linux 的**双向链表**接口时，我们应该始终记住这些列表函数不执行锁定，因此我们的设备驱动程序（或其他内核实体）可能尝试对同一列表执行并发操作。这就是为什么我们必须确保实现一个良好的锁定方案来保护我们的数据免受竞争条件的影响。

要使用列表机制，我们的驱动程序必须包括头文件`linux/include/linux/list.h`；这个文件包括头文件`linux/include/linux/types.h`，在这里定义了`struct list_head`类型的简单结构如下：

```
struct list_head {
    struct list_head *next, *prev;
};
```

正如我们所看到的，这个结构包含两个指针（`prev`和`next`）指向`list_head`结构；这两个指针实现了双向链表的功能。然而，有趣的是`struct list_head`没有专用的数据字段，就像在经典的列表实现中那样。事实上，在 Linux 内核列表实现中，数据字段并没有嵌入在列表元素本身中；相反，列表结构是被认为被封装在相关数据结构中。这可能会让人困惑，但实际上并不是；事实上，要在我们的代码中使用 Linux 列表功能，我们只需要在使用列表的结构中嵌入一个`struct list_head`。

我们可以在设备驱动程序中声明对象结构的简单示例如下：

```
struct l_struct {
    int data;
    ... 
    /* other driver specific fields */
    ...
    struct list_head list;
};
```

通过这样做，我们创建了一个带有自定义数据的双向链表。然后，要有效地创建我们的列表，我们只需要声明并初始化列表头，使用以下代码：

```
struct list_head data_list;
INIT_LIST_HEAD(&data_list);
```

与其他内核结构一样，我们有编译时对应的宏`LIST_HEAD()`，它可以用于在非动态列表分配的情况下执行相同的操作。在我们的示例中，我们可以这样做：`LIST_HEAD(data_list)`；

一旦列表头部被声明并正确初始化，我们可以使用`linux/include/linux/list.h`文件中的几个函数来添加、删除或执行其他列表条目操作。

如果我们查看头文件，我们可以看到以下函数用于向列表中添加或删除元素：

```
/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new, struct list_head *head);

 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry);
```

用于用新条目替换旧条目的以下函数也是可见的：

```
/**
 * list_replace - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
static inline void list_replace(struct list_head *old,
                                struct list_head *new);
...
```

这只是所有可用函数的一个子集。鼓励您查看`linux/include/linux/list.h`文件以发现更多。

除了前面的函数之外，用于向列表中添加或删除条目的宏更有趣。例如，如果我们希望以有序的方式添加新条目，我们可以这样做：

```
void add_ordered_entry(struct l_struct *new)
{
    struct list_head *ptr;
    struct my_struct *entry;

    list_for_each(ptr, &data_list) {
        entry = list_entry(ptr, struct l_struct, list);
        if (entry->data < new->data) {
            list_add_tail(&new->list, ptr);
            return;
        }
    }
    list_add_tail(&new->list, &data_list)
}
```

通过使用`list_for_each()`宏，我们可以迭代列表，并通过使用`list_entry()`，我们可以获得指向我们封闭数据的指针。请注意，我们必须将指向当前元素`ptr`、我们的结构类型以及我们结构中的列表条目的名称（在前面的示例中为`list`）传递给`list_entry()`。

最后，我们可以使用`list_add_tail()`函数将我们的新元素添加到正确的位置。

请注意，`list_entry()`只是使用`container_of()`宏来执行其工作。该宏在第五章*管理中断和并发性*的*container_of()宏*部分中有解释。

如果我们再次查看`linux/include/linux/list.h`文件，我们可以看到更多的函数，我们可以使用这些函数来从列表中获取条目或以不同的方式迭代所有列表元素：

```
/**
 * list_entry - get the struct for this entry
 * @ptr: the &struct list_head pointer.
 * @type: the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr: the list head to take the element from.
 * @type: the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr: the list head to take the element from.
 * @type: the type of the struct this is embedded in.
 * @member: the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
        list_entry((ptr)->prev, type, member)
...
```

一些宏也可用于迭代每个列表的元素：

```
/**
 * list_for_each - iterate over a list
 * @pos: the &struct list_head to use as a loop cursor.
 * @head: the head for your list.
 */
#define list_for_each(pos, head) \
        for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev - iterate over a list backwards
 * @pos: the &struct list_head to use as a loop cursor.
 * @head: the head for your list.
 */
#define list_for_each_prev(pos, head) \
        for (pos = (head)->prev; pos != (head); pos = pos->prev)
...
```

再次注意，这只是所有可用函数的一个子集，因此鼓励您查看`linux/include/linux/list.h`文件以发现更多。

# 内核哈希表

如前所述，对于链表，当使用 Linux 的**哈希表**接口时，我们应该始终记住这些哈希函数不执行锁定，因此我们的设备驱动程序（或其他内核实体）可能尝试对同一哈希表执行并发操作。这就是为什么我们必须确保还实现了一个良好的锁定方案来保护我们的数据免受竞争条件的影响。

与内核列表一样，我们可以声明然后初始化一个具有 2 的幂位大小的哈希表，使用以下代码：

```
DECLARE_HASHTABLE(data_hash, bits)
hash_init(data_hash);
```

与列表一样，我们有编译时对应的宏`DEFINE_HASHTABLE()`，它可以用于在非动态哈希表分配的情况下执行相同的操作。在我们的示例中，我们可以使用`DEFINE_HASHTABLE(data_hash, bits)`；

这将创建并初始化一个名为`data_hash`的表，其大小基于 2 的幂。正如刚才所说，该表是使用包含内核`struct hlist_head`类型的桶来实现的；这是因为内核哈希表是使用哈希链实现的，而哈希冲突只是添加到列表的头部。为了更好地看到这一点，我们可以参考`DECLARE_HASHTABLE()`宏的定义：

```
#define DECLARE_HASHTABLE(name, bits) \
    struct hlist_head name[1 << (bits)]
```

完成后，可以构建一个包含`struct hlist_node`指针的结构来保存要插入的数据，就像我们之前为列表所做的那样：

```
struct h_struct {
    int key;
    int data;
    ... 
    /* other driver specific fields */
    ...
    struct hlist_node node;
};
```

`struct hlist_node`及其头`struct hlist_head`在`linux/include/linux/types.h`头文件中定义如下：

```
struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};
```

然后可以使用`hash_add()`函数将新节点添加到哈希表中，如下所示，其中`&entry.node`是数据结构中`struct hlist_node`的指针，`key`是哈希键：

```
hash_add(data_hash, &entry.node, key);
```

密钥可以是任何东西；但通常是通过使用特殊的哈希函数应用于要存储的数据来计算的。例如，有一个 256 个桶的哈希表，密钥可以用以下`hash_func()`计算：

```
u8 hash_func(u8 *buf, size_t len)
{
    u8 key = 0;

    for (i = 0; i < len; i++)
        key += data[i];

    return key;
}
```

相反的操作，即删除，可以通过使用`hash_del()`函数来完成，如下所示：

```
hash_del(&entry.node);
```

但是，与列表一样，最有趣的宏是用于迭代表的宏。存在两种机制；一种是遍历整个哈希表，返回每个桶中的条目：

```
hash_for_each(name, bkt, node, obj, member)
```

另一个仅返回与密钥的哈希桶对应的条目：

```
hash_for_each_possible(name, obj, member, key)
```

通过使用最后一个宏，从哈希表中删除节点的过程如下：

```
void del_node(int data)
{
    int key = hash_func(data);
    struct h_struct *entry;

    hash_for_each_possible(data_hash, entry, node, key) {
        if (entry->data == data) {
            hash_del(&entry->node);
            return;
        }
    }
}
```

请注意，此实现只删除第一个匹配的条目。

通过使用`hash_for_each_possible()`，我们可以迭代与密钥相关的桶中的列表。

以下是`linux/include/linux/hashtable.h`文件中报告的`hash_add()`、`hash_del()`和`hash_for_each_possible()`的定义：

```
/**
 * hash_add - add an object to a hashtable
 * @hashtable: hashtable to add to
 * @node: the &struct hlist_node of the object to be added
 * @key: the key of the object to be added
 */
#define hash_add(hashtable, node, key) \
        hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])

/**
 * hash_del - remove an object from a hashtable
 * @node: &struct hlist_node of the object to remove
 */
static inline void hash_del(struct hlist_node *node);

/**
 * hash_for_each_possible - iterate over all possible objects hashing to the
 * same bucket
 * @name: hashtable to iterate
 * @obj: the type * to use as a loop cursor for each entry
 * @member: the name of the hlist_node within the struct
 * @key: the key of the objects to iterate over
 */
#define hash_for_each_possible(name, obj, member, key) \
        hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)
```

这些只是管理哈希表的所有可用函数的子集。鼓励您查看`linux/include/linux/hashtable.h`文件以了解更多。

# 访问 I/O 内存

为了能够有效地与外围设备通信，我们需要一种方法来读写其寄存器，为此我们有两种方法：通过**I/O 端口**或通过**I/O 内存**。前一种机制在本书中没有涵盖，因为它在现代平台中（除了 x86 和 x86_64 之外）并不经常使用，而后者只是使用正常的内存区域来映射每个外围寄存器，这是现代 CPU 中常用的一种方法。事实上，I/O 内存映射在**片上系统**（**SoC**）系统中非常常见，其中 CPU 可以通过读写到众所周知的物理地址来与其内部外围设备通信；在这种情况下，每个外围设备都有其自己的保留地址，并且每个外围设备都连接到一个寄存器。

要看我所说的一个简单示例，您可以从[`ww1.microchip.com/downloads/en/DeviceDoc/Atmel-11121-32-bit-Cortex-A5-Microcontroller-SAMA5D3_Datasheet_B.pdf`](http://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-11121-32-bit-Cortex-A5-Microcontroller-SAMA5D3_Datasheet_B.pdf)获取 SAMA5D3 CPU 的数据表，查看第 30 页，其中报告了整个 CPU 的完整内存映射。

然后，这个 I/O 内存映射被报告在与平台相关的设备树文件中。举个例子，如果我们看一下内核源文件中`linux/arch/arm64/boot/dts/marvell/armada-37xx.dtsi`文件中我们 ESPRESSObin 的 CPU 的 UART 控制器的定义，我们可以看到以下设置：

```
soc {
    compatible = "simple-bus";
    #address-cells = <2>;
    #size-cells = <2>;
    ranges;

    internal-regs@d0000000 {
        #address-cells = <1>;
        #size-cells = <1>;
        compatible = "simple-bus";
        /* 32M internal register @ 0xd000_0000 */
        ranges = <0x0 0x0 0xd0000000 0x2000000>;

...

        uart0: serial@12000 {
            compatible = "marvell,armada-3700-uart";
            reg = <0x12000 0x200>;
            clocks = <&xtalclk>;
            interrupts =
            <GIC_SPI 11 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 12 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 13 IRQ_TYPE_LEVEL_HIGH>;
            interrupt-names = "uart-sum", "uart-tx", "uart-rx";
            status = "disabled";
        };
```

如第四章中所解释的，*使用设备树*，我们可以推断 UART0 控制器被映射到物理地址`0xd0012000`。这也被我们在启动时可以看到的以下内核消息所证实：

```
d0012000.serial: ttyMV0 at MMIO 0xd0012000 (irq = 0, base_baud = 
1562500) is a mvebu-uart
```

好的，现在我们必须记住`0xd0012000`是 UART 控制器的**物理地址**，但我们的 CPU 知道**虚拟地址**，因为它使用其 MMU 来访问 RAM！那么，我们如何在物理地址`0xd0012000`和其虚拟对应地址之间进行转换呢？答案是：通过内存重新映射。在每次读取或写入 UART 控制器的寄存器之前，必须在内核中执行此操作，否则将引发段错误。

只是为了了解物理地址和虚拟地址之间的差异以及重新映射操作的行为，我们可以看一下名为`devmem2`的实用程序，该实用程序可以通过 ESPRESSObin 上的`wget`程序从[`free-electrons.com/pub/mirror/devmem2.c`](http://free-electrons.com/pub/mirror/devmem2.c)下载：

```
# wget http://free-electrons.com/pub/mirror/devmem2.c
```

如果我们看一下代码，我们会看到以下操作：

```
    if((fd = open("/dev/mem", O_RDWR | O_SYNC)) == -1) FATAL;
    printf("/dev/mem opened.\n"); 
    fflush(stdout);

    /* Map one page */
    map_base = mmap(0, MAP_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, target & ~MAP_MASK);
    if(map_base == (void *) -1) FATAL;
    printf("Memory mapped at address %p.\n", map_base); 
    fflush(stdout);
```

因此，`devmem2`程序只是打开`/dev/mem`设备，然后调用`mmap()`系统调用。这将导致在内核源文件`linux/ drivers/char/mem.c`中执行`mmap_mem（）`方法，其中实现了`/dev/mem`字符设备：

```
static int mmap_mem(struct file *file, struct vm_area_struct *vma)
{
    size_t size = vma->vm_end - vma->vm_start;
    phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;

...

    /* Remap-pfn-range will mark the range VM_IO */
    if (remap_pfn_range(vma,
                        vma->vm_start, vma->vm_pgoff,
                        size,
                        vma->vm_page_prot)) {
        return -EAGAIN;
    }
    return 0;
}
```

有关这些内存重新映射操作以及`remap_pfn_range（）`函数和类似函数的使用的更多信息将在第七章“高级字符驱动程序操作”中更清楚。

好吧，`mmap_mem（）`方法对物理地址`0xd0012000`进行内存重新映射操作，将其映射为适合 CPU 访问 UART 控制器寄存器的虚拟地址。

如果我们尝试在 ESPRESSObin 上使用以下命令编译代码，我们将得到一个可执行文件，从用户空间访问 UART 控制器的寄存器：

```
# make CFLAGS="-Wall -O" devmem2 cc -Wall -O devmem2.c -o devmem2
```

您可以安全地忽略下面显示的可能的警告消息：

`devmem2.c:104:33: 警告：格式“％X”需要类型为“unsigned int”的参数，`

`但参数 2 的类型为'off_t {aka long int}' [-Wformat=]`

`printf("地址 0x%X（%p）处的值：0x%X\n"，target，virt_addr，read_result`

`);`

`devmem2.c:104:44: 警告：格式“％X”需要类型为“unsigned int”的参数，`

`但参数 4 的类型为'long unsigned int' [-Wformat=]`

`printf("地址 0x%X（%p）处的值：0x%X\n"，target，virt_addr，read_result`

`);`

`devmem2.c:123:22: 警告：格式“％X”需要类型为“unsigned int”的参数，`

`但参数 2 的类型为'long unsigned int' [-Wformat=]`

`printf("写入 0x%X；读回 0x%X\n"，writeval，read_result);`

`devmem2.c:123:37: 警告：格式“％X”需要类型为“unsigned int”的参数，`

`但参数 3 的类型为'long unsigned int' [-Wformat=]`

`printf("写入 0x%X；读回 0x%X\n"，writeval，read_result);`

然后，如果我们执行程序，我们应该得到以下输出：

```
# ./devmem2 0xd0012000 
/dev/mem opened.
Memory mapped at address 0xffffbd41d000.
Value at address 0xD0012000 (0xffffbd41d000): 0xD
```

正如我们所看到的，`devmem2`程序按预期打印了重新映射结果，并且实际读取是使用虚拟地址完成的，而 MMU 又将其转换为所需的物理地址`0xd0012000`。

好了，现在清楚了，访问外围寄存器需要进行内存重新映射，我们可以假设一旦我们有了一个虚拟地址物理映射到一个寄存器，我们可以简单地引用它来实际读取或写入数据。这是错误的！实际上，尽管硬件寄存器在内存中映射和通常的 RAM 内存之间有很强的相似性，但当我们访问 I/O 寄存器时，我们必须小心避免被 CPU 或编译器优化所欺骗，这些优化可能会修改预期的 I/O 行为。

I/O 寄存器和 RAM 之间的主要区别在于 I/O 操作具有副作用，而内存操作则没有；实际上，当我们向 RAM 中写入一个值时，我们希望它不会被其他人改变，但对于 I/O 内存来说，这并不是真的，因为我们的外设可能会改变寄存器中的一些数据，即使我们向其中写入了特定的值。这是一个非常重要的事实，因为为了获得良好的性能，RAM 内容可以被缓存，并且 CPU 指令流水线可以重新排序读/写指令；此外，编译器可以自主决定将数据值放入 CPU 寄存器而不将其写入内存，即使最终将其存储到内存中，写入和读取操作都可以在缓存内存上进行，而不必到达物理 RAM。即使最终将其存储到内存中，这两种优化在 I/O 内存上是不可接受的。实际上，这些优化在应用于常规内存时是透明且良性的，但在 I/O 操作中可能是致命的，因为外设有明确定义的编程方式，对其寄存器的读写操作不能重新排序或缓存，否则会导致故障。

这些是我们不能简单地引用虚拟内存地址来从内存映射的外设中读取和写入数据的主要原因。因此，驱动程序必须确保在访问寄存器时不执行缓存操作，也不进行读取或写入重排序；解决方案是使用实际执行读写操作的特殊函数。在`linux/include/asm-generic/io.h`头文件中，我们可以找到这些函数，如以下示例所示：

```
static inline void writeb(u8 value, volatile void __iomem *addr)
{
    __io_bw();
    __raw_writeb(value, addr);
    __io_aw();
}

static inline void writew(u16 value, volatile void __iomem *addr)
{
    __io_bw();
    __raw_writew(cpu_to_le16(value), addr);
    __io_aw();
}

static inline void writel(u32 value, volatile void __iomem *addr)
{
    __io_bw();
    __raw_writel(__cpu_to_le32(value), addr);
    __io_aw();
}

#ifdef CONFIG_64BIT
static inline void writeq(u64 value, volatile void __iomem *addr)
{
    __io_bw();
    __raw_writeq(__cpu_to_le64(value), addr);
    __io_aw();
}
#endif /* CONFIG_64BIT */
```

前述函数仅用于写入数据；您可以查看头文件以查看读取函数的定义，例如`readb()`、`readw()`、`readl()`和`readq()`。

每个函数都定义为与要操作的寄存器的大小相对应的明确定义的数据类型一起使用；此外，它们每个都使用内存屏障来指示 CPU 按照明确定义的顺序执行读写操作。

我不打算在本书中解释内存屏障是什么；如果您感兴趣，您可以在`linux/Documentation/memory-barriers.txt`文件中的内核文档目录中阅读更多相关内容。

作为前述功能的一个简单示例，我们可以看一下 Linux 源文件中`linux/drivers/watchdog/sunxi_wdt.c`文件中的`sunxi_wdt_start()`函数：

```
static int sunxi_wdt_start(struct watchdog_device *wdt_dev)
{
...
    void __iomem *wdt_base = sunxi_wdt->wdt_base;
    const struct sunxi_wdt_reg *regs = sunxi_wdt->wdt_regs;

...

    /* Set system reset function */
    reg = readl(wdt_base + regs->wdt_cfg);
    reg &= ~(regs->wdt_reset_mask);
    reg |= regs->wdt_reset_val;
    writel(reg, wdt_base + regs->wdt_cfg);

    /* Enable watchdog */
    reg = readl(wdt_base + regs->wdt_mode);
    reg |= WDT_MODE_EN;
    writel(reg, wdt_base + regs->wdt_mode);

    return 0;
}
```

一旦寄存器的基地址`wdt_base`和寄存器的映射`regs`已经获得，我们可以简单地通过使用`readl()`和`writel()`来执行我们的读写操作，如前面的部分所示，并且我们可以放心地确保它们将被正确执行。

# 在内核中花费时间

在第五章中，*管理中断和并发*，我们看到了如何延迟在以后的时间执行操作；然而，可能会发生这样的情况，我们仍然需要在外设上的两个操作之间等待一段时间，如下所示：

```
writeb(0x12, ctrl_reg);
wait_us(100);
writeb(0x00, ctrl_reg);
```

也就是说，如果我们需要向寄存器中写入一个值，然后等待 100 微秒，然后再写入另一个值，这些操作可以通过简单地使用`linux/include/linux/delay.h`头文件（和其他文件）中定义的函数来完成，而不是使用之前介绍的技术（内核定时器和工作队列等）：

```
void ndelay(unsigned long nsecs);
void udelay(unsigned long usecs);
void mdelay(unsigned long msecs);

void usleep_range(unsigned long min, unsigned long max);
void msleep(unsigned int msecs);
unsigned long msleep_interruptible(unsigned int msecs);
void ssleep(unsigned int seconds);
```

所有这些函数都是用于延迟一定量的时间，以纳秒、微秒或毫秒（或仅以秒为单位，如`ssleep()`）表示。

第一组函数（即`*delay()`函数）可以在中断或进程上下文中的任何地方使用，而第二组函数必须仅在进程上下文中使用，因为它们可能会隐式进入睡眠状态。

此外，我们看到，例如，`usleep_range()`函数采用最小和最大睡眠时间，以通过允许高分辨率定时器利用已经安排的中断来减少功耗，而不是仅为此睡眠安排新的中断。以下是`linux/kernel/time/timer.c`文件中的函数描述：

```
/**
 * usleep_range - Sleep for an approximate time
 * @min: Minimum time in usecs to sleep
 * @max: Maximum time in usecs to sleep
 *
 * In non-atomic context where the exact wakeup time is flexible, use
 * usleep_range() instead of udelay(). The sleep improves responsiveness
 * by avoiding the CPU-hogging busy-wait of udelay(), and the range reduces
 * power usage by allowing hrtimers to take advantage of an already-
 * scheduled interrupt instead of scheduling a new one just for this sleep.
 */
void __sched usleep_range(unsigned long min, unsigned long max);
```

此外，在同一文件中，我们看到`msleep_interruptible()`是`msleep()`的变体，可以被信号中断（在*等待事件*配方中，在第五章中，*管理中断和并发性*，我们谈到了这种可能性），返回值只是由于中断而未睡眠的时间（以毫秒为单位）：

```
/**
 * msleep_interruptible - sleep waiting for signals
 * @msecs: Time in milliseconds to sleep for
 */
unsigned long msleep_interruptible(unsigned int msecs);
```

最后，我们还应该注意以下内容：

+   `*delay()`函数使用时钟速度的 jiffy 估计（`loops_per_jiffy`值），并将忙等待足够的循环周期以实现所需的延迟。

+   `*delay()`函数可能会在计算出的`loops_per_jiffy`太低（由于执行定时器中断所需的时间）或者缓存行为影响执行循环函数所需的时间，或者由于 CPU 时钟速率的变化而提前返回。

+   `udelay()`是通常首选的 API，`ndelay()`的级别精度实际上可能不存在于许多非 PC 设备上。

+   `mdelay()`是对`udelay()`的宏包装，以考虑将大参数传递给`udelay()`时可能发生的溢出。这就是为什么不建议使用`mdelay()`，代码应该重构以允许使用`msleep()`。


# 第十二章：附加信息：高级字符驱动程序操作

# 技术要求

当我们必须管理外围设备时，通常需要修改其内部配置设置，或者将其从用户空间映射为内存缓冲区可能很有用，就好像我们可以通过引用指针来修改内部数据一样。

例如，帧缓冲区或帧抓取器是作为用户空间的大块内存映射的良好候选者。

在这种情况下，具有`lseek()`、`ioctl()`和`mmap()`系统调用的支持是至关重要的。如果从用户空间使用这些系统调用并不复杂，在内核中，它们需要驱动程序开发人员的一些注意，特别是`mmap()`系统调用，它涉及内核**内存管理单元**（**MMU**）。

不仅驱动程序开发人员必须注意的主要任务之一是与用户空间的数据交换机制；事实上，实现这种机制的良好实现可能会简化许多外围设备的管理。例如，使用读取和写入内存缓冲区可能会提高系统性能，当一个或多个进程访问外围设备时，为用户空间开发人员提供了一系列良好的设置和管理机制，使他们能够充分利用我们的硬件。

# 使用 lseek()在文件中上下移动

在这里，我们应该记住`read()`和`write()`系统调用的原型如下：

```
ssize_t (*read) (struct file *filp,
                 char __user *buf, size_t len, loff_t *ppos);
ssize_t (*write) (struct file *filp,
                 const char __user *buff, size_t len, loff_t *ppos);
```

当我们使用`chapter_03/chrdev_test.c`文件中的程序测试我们的字符驱动程序时，我们注意到除非我们对文件进行了如下修补，否则我们无法重新读取写入的数据：

```
--- a/chapter_03/chrdev_test.c
+++ b/chapter_03/chrdev_test.c
@@ -55,6 +55,16 @@ int main(int argc, char *argv[])
       dump("data written are: ", buf, n);
   }

+  close(fd);
+
+  ret = open(argv[1], O_RDWR);
+  if (ret < 0) {
+      perror("open");
+      exit(EXIT_FAILURE);
+  }
+  printf("file %s reopened\n", argv[1]);
+  fd = ret;
+
   for (c = 0; c < sizeof(buf); c += n) {
       ret = read(fd, buf, sizeof(buf));
       if (ret == 0) {
```

这是在不关闭然后重新打开与我们的驱动程序连接的文件的情况下（这样，内核会自动将`ppos`指向的值重置为`0`）。

然而，这并不是修改`ppos`指向的值的唯一方法；事实上，我们也可以使用`lseek()`系统调用来做到这一点。系统调用的原型，如其手册页（`man 2 lseek`）所述，如下所示：

```
off_t lseek(int fd, off_t offset, int whence);
```

在这里，`whence`参数可以假定以下值（由以下代码中的定义表示）：

```
  SEEK_SET
      The file offset is set to offset bytes.

  SEEK_CUR
      The file offset is set to its current location plus offset
      bytes.

  SEEK_END
      The file offset is set to the size of the file plus offset
      bytes.
```

因此，例如，如果我们希望像在第三章中所做的那样将`ppos`指向我们设备的数据缓冲区的开头，但是不关闭和重新打开设备文件，我们可以这样做：

```
--- a/chapter_03/chrdev_test.c
+++ b/chapter_03/chrdev_test.c
@@ -55,6 +55,13 @@ int main(int argc, char *argv[])
        dump("data written are: ", buf + c, n);
    }

+  ret = lseek(fd, SEEK_SET, 0);
+  if (ret < 0) {
+       perror("lseek");
+       exit(EXIT_FAILURE);
+  }
+  printf("*ppos moved to 0\n");
+
   for (c = 0; c < sizeof(buf); c += n) {
       ret = read(fd, buf, sizeof(buf));
       if (ret == 0) {
```

请注意，所有这些修改都存储在 GitHub 存储库中的`modify_lseek_to_chrdev_test.patch`文件中，可以通过在`chapter_03`目录中使用以下命令应用，该目录中包含`chrdev_test.c`文件：

**`$ patch -p2 < ../../chapter_07/modify_lseek_to_chrdev_test.patch`**

如果我们看一下`linux/include/uapi/linux/fs.h`头文件，我们可以看到这些定义是如何声明的：

```

#define SEEK_SET    0 /* seek relative to beginning of file */
#define SEEK_CUR    1 /* seek relative to current file position */
#define SEEK_END    2 /* seek relative to end of file */
```

`lseek()`的实现是如此简单，以至于在`linux/fs/read_write.c`文件中我们可以找到一个名为`default_llseek()`的此方法的默认实现。其原型如下所示：

```
loff_t default_llseek(struct file *file,
                      loff_t offset, int whence);
```

这是因为如果我们不指定自己的实现，那么内核将自动使用前面代码块中的实现。然而，如果我们快速查看`default_llseek()`函数，我们会注意到它对我们的设备不太适用，因为它太*面向文件*（也就是说，当`lseek()`操作的文件是真实文件而不是外围设备时，它可以很好地工作），因此我们可以使用`noop_llseek()`函数来代替`lseek()`的两种替代实现之一来执行无操作：

```
/**
 * noop_llseek - No Operation Performed llseek implementation
 * @file: file structure to seek on
 * @offset: file offset to seek to
 * @whence: type of seek
 *
 * This is an implementation of ->llseek useable for the rare special case when
 * userspace expects the seek to succeed but the (device) file is actually not
 * able to perform the seek. In this case you use noop_llseek() instead of
 * falling back to the default implementation of ->llseek.
 */
loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
    return file->f_pos;
}
```

或者我们可以返回一个错误，然后使用`no_llseek()`函数向用户空间发出信号，表明我们的设备不适合使用寻址：

```
loff_t no_llseek(struct file *file, loff_t offset, int whence)
{
    return -ESPIPE;
}
```

这两个前面的函数位于内核源码的`linux/fs/read_write.c`文件中。

这两个功能的不同用法在上面关于`noop_llseek()`的评论中有很好的描述；虽然`default_llseek()`通常不适用于字符设备，但我们可以简单地使用`no_llseek()`，或者在那些罕见的特殊情况下，用户空间期望寻址成功，但（设备）文件实际上无法执行寻址时，我们可以使用`no_llseek()`如下：

```
static const struct file_operations chrdev_fops = {
    .owner   = THIS_MODULE,
    .llseek  = no_llseek,
    .read    = chrdev_read,
    .write   = chrdev_write,
    .open    = chrdev_open,
    .release = chrdev_release
};
```

这段代码是在 GitHub 的`chapter_04/chrdev/chrdev.c`文件中讨论的 chrdev 字符驱动程序中提到的，如第四章中所述，*使用设备树*。

# 使用 ioctl()进行自定义命令

在[第三章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=30&action=edit#post_26)中，*使用字符驱动程序*，我们讨论了文件抽象，并提到字符驱动程序在用户空间的角度上与通常的文件非常相似。但是，它根本不是一个文件；它被用作文件，但它属于一个外围设备，通常需要配置外围设备才能正常工作，因为它们可能支持不同的操作方法。

例如，让我们考虑一个串行端口；它看起来像一个文件，我们可以使用`read()`和`write()`系统调用进行读取或写入，但在大多数情况下，我们还必须设置一些通信参数，如波特率、奇偶校验位等。当然，这些参数不能通过`read()`或`write()`来设置，也不能通过使用`open()`系统调用来设置（即使它可以设置一些访问模式，如只读或只写），因此内核为我们提供了一个专用的系统调用，我们可以用来设置这些串行通信参数。这个系统调用就是`ioctl()`。

从用户空间的角度来看，它看起来像是它的 man 页面（通过使用`man 2 ioctl`命令可用）：

```
SYNOPSIS
   #include <sys/ioctl.h>

   int ioctl(int fd, unsigned long request, ...);

DESCRIPTION
   The ioctl() system call manipulates the underlying device parameters of special files. In particular, many operating characteristics of character special files (e.g., terminals) may be controlled with ioctl() requests.
```

如前面的段落所述，`ioctl()`系统调用通过获取文件描述符（通过打开我们的设备获得）作为第一个参数，以及设备相关的请求代码作为第二个参数，来操作特殊文件的底层设备参数（就像我们的字符设备一样，但实际上不仅仅是这样，它也可以用于网络或块设备），最后，作为第三个可选参数，是一个无类型指针，用户空间程序员可以用来与驱动程序交换数据。

因此，借助这个通用定义，驱动程序开发人员可以实现他们的自定义命令来管理底层设备。即使不是严格要求，`ioctl()`命令中编码了参数是输入参数还是输出参数，以及第三个参数的字节数。用于指定`ioctl()`请求的宏和定义位于`linux/include/uapi/asm-generic/ioctl.h`文件中，如下所述：

```
/*
 * Used to create numbers.
 *
 * NOTE: _IOW means userland is writing and kernel is reading. _IOR
 * means userland is reading and kernel is writing.
 */
#define _IO(type,nr)            _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)      _IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)      _IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)     _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
```

正如我们在前面的评论中也可以看到的，`read()`和`write()`操作是从用户空间的角度来看的，因此当我们将一个命令标记为*写入*时，我们的意思是用户空间在写入，内核在读取，而当我们将一个命令标记为*读取*时，我们的意思是完全相反。

关于如何使用这些宏的一个非常简单的例子，我们可以看一下关于看门狗的实现，位于文件`linux/include/uapi/linux/watchdog.h`中：

```
#include <linux/ioctl.h>
#include <linux/types.h>

#define WATCHDOG_IOCTL_BASE 'W'

struct watchdog_info {
    __u32 options;          /* Options the card/driver supports */
    __u32 firmware_version; /* Firmware version of the card */
    __u8 identity[32];      /* Identity of the board */
};

#define WDIOC_GETSUPPORT    _IOR(WATCHDOG_IOCTL_BASE, 0, struct watchdog_info)
#define WDIOC_GETSTATUS     _IOR(WATCHDOG_IOCTL_BASE, 1, int)
#define WDIOC_GETBOOTSTATUS _IOR(WATCHDOG_IOCTL_BASE, 2, int)
#define WDIOC_GETTEMP       _IOR(WATCHDOG_IOCTL_BASE, 3, int)
#define WDIOC_SETOPTIONS    _IOR(WATCHDOG_IOCTL_BASE, 4, int)
#define WDIOC_KEEPALIVE     _IOR(WATCHDOG_IOCTL_BASE, 5, int)
#define WDIOC_SETTIMEOUT    _IOWR(WATCHDOG_IOCTL_BASE, 6, int)
#define WDIOC_GETTIMEOUT    _IOR(WATCHDOG_IOCTL_BASE, 7, int)
#define WDIOC_SETPRETIMEOUT _IOWR(WATCHDOG_IOCTL_BASE, 8, int)
#define WDIOC_GETPRETIMEOUT _IOR(WATCHDOG_IOCTL_BASE, 9, int)
#define WDIOC_GETTIMELEFT   _IOR(WATCHDOG_IOCTL_BASE, 10, int)
```

看门狗（或看门狗定时器）通常用于自动化系统。它是一个电子定时器，用于检测和从计算机故障中恢复。事实上，在正常操作期间，系统中的一个进程应定期重置看门狗定时器，以防止它超时，因此，如果由于硬件故障或程序错误，系统未能重置看门狗，定时器将过期，并且系统将自动重新启动。

这里我们定义了一些命令来管理看门狗外围设备，每个命令都使用`_IOR()`宏（用于指定读取命令）或`_IOWR`宏（用于指定读/写命令）进行定义。每个命令都有一个渐进的数字，后面跟着第三个参数指向的数据类型，它可以是一个简单类型（如前面的`int`类型）或一个更复杂的类型（如前面的`struct watchdog_info`）。最后，`WATCHDOG_IOCTL_BASE`通用参数只是用来添加一个随机值，以避免命令重复。

在后面我们将解释我们的示例时，这些宏中`type`参数（在前面的示例中为`WATCHDOG_IOCTL_BASE`）的使用将更加清晰。

当然，这只是一个纯粹的约定，我们可以简单地使用渐进的整数来定义我们的`ioctl()`命令，它仍然可以完美地工作；然而，通过这种方式行事，我们将嵌入到命令代码中很多有用的信息。

一旦所有命令都被定义，我们需要添加我们自定义的`ioctl()`实现，并且通过查看`linux/include/linux/fs.h`文件中的`struct file_operations`，我们可以看到其中存在两个：

```
struct file_operations {
...
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
```

在 2.6.36 之前的内核中，只有一个`ioctl()`方法可以获取**Big Kernel Lock**（**BKL**），因此其他任何东西都无法同时执行。这导致多处理器机器上的性能非常糟糕，因此大力去除它，这就是为什么引入了`unlocked_ioctl()`。通过使用它，每个驱动程序开发人员都可以选择使用哪个锁。

另一方面，`compat_ioctl()`，尽管是同时添加的，但实际上与`unlocked_ioctl()`无关。它的目的是允许 32 位用户空间程序在 64 位内核上进行`ioctl()`调用。

最后，我们应该首先注意到命令和结构定义必须在用户空间和内核空间中使用，因此当我们定义交换的数据类型时，必须使用这两个空间都可用的数据类型（这就是为什么使用`__u32`类型而不是`u32`，后者实际上只存在于内核中）。

此外，当我们希望使用自定义的`ioctl()`命令时，我们必须将它们定义到一个单独的头文件中，并且必须与用户空间共享；通过这种方式，我们可以将内核代码与用户空间分开。然而，如果难以将所有用户空间代码与内核空间分开，我们可以使用`__KERNEL__`定义，如下面的片段所示，指示预处理器根据我们编译的空间来排除一些代码：

```
#ifdef __KERNEL__
  /* This is code for kernel space */
  ...
#else
  /* This is code for user space */
  ...
#endif
```

这就是为什么通常，包含`ioctl()`命令的头文件通常位于`linux/include/uapi`目录下，该目录包含用户空间程序编译所需的所有头文件。

# 使用 mmap()访问 I/O 内存

在[第六章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=30&action=edit#post_29)的*杂项内核内部*中的*获取 I/O 内存访问*中，我们看到了 MMU 的工作原理以及如何访问内存映射的外围设备。在内核空间中，我们必须指示 MMU 以便正确地将虚拟地址转换为一个正确的地址，这个地址必须指向我们外围设备所属的一个明确定义的物理地址，否则我们无法控制它！

另一方面，在该部分，我们还使用了一个名为`devmem2`的用户空间工具，它可以使用`mmap()`系统调用从用户空间访问物理地址。这个系统调用非常有趣，因为它允许我们做很多有用的事情，所以让我们先来看一下它的 man 页面（`man 2 mmap`）：

```
NAME
   mmap, munmap - map or unmap files or devices into memory

SYNOPSIS
   #include <sys/mman.h>

   void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
   int munmap(void *addr, size_t length);

DESCRIPTION
   mmap() creates a new mapping in the virtual address space of the call‐
   ing process. The starting address for the new mapping is specified in
   addr. The length argument specifies the length of the mapping (which
   must be greater than 0).
```

正如我们从前面的片段中看到的，通过使用`mmap()`，我们可以在调用进程的虚拟地址空间中创建一个新的映射，这个映射可以与作为参数传递的文件描述符`fd`相关联。

通常，此系统调用用于以这样的方式将普通文件映射到系统内存中，以便可以使用普通指针而不是通常的`read()`和`write()`系统调用来寻址。

举个简单的例子，让我们考虑一个通常的文件如下：

```
$ cat textfile.txt 
This is a test file

This is line 3.

End of the file
```

这是一个包含三行文本的普通文本文件。我们可以在终端上使用`cat`命令读取和写入它，就像之前所述的那样；当然，我们现在知道`cat`命令在文件上运行`open()`，然后是一个或多个`read()`操作，然后是一个或多个`write()`操作，最后是标准输出（反过来是连接到我们终端的文件抽象）。但是，这个文件也可以被读取为一个 char 的内存缓冲区，使用`mmap()`系统调用，可以通过以下步骤完成：

```
    ret = open(argv[1], O_RDWR);
    if (ret < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    printf("file %s opened\n", argv[1]);
    fd = ret;

    /* Try to remap file into memory */
    addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_FILE | MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    ptr = (char *) addr;
    for (i = 0; i < len; i++)
        printf("%c", ptr[i]);
```

前面示例的完整代码实现将在以下片段中呈现。这是`chrdev_mmap.c`文件的片段。

因此，正如我们所看到的，我们首先像往常一样打开文件，但是，我们没有使用`read()`系统调用，而是使用了`mmap()`，最后，我们使用返回的内存地址作为 char 指针来打印内存缓冲区。请注意，在`mmap()`之后，我们将在内存中得到文件的图像。

如果我们尝试在`textfile.txt`文件上执行前面的代码，我们会得到我们期望的结果：

```
# ls -l textfile.txt 
-rw-r--r-- 1 root root 54 May 11 16:41 textfile.txt
# ./chrdev_mmap textfile.txt 54 
file textfile.txt opened
got address=0xffff8357b000 and len=54
---
This is a test file

This is line 3.

End of the file
```

请注意，我使用`ls`命令获取了`chrdev_mmap`程序所需的文件长度。

现在我们应该问自己是否有办法像上面的文本文件一样映射字符设备（从用户空间的角度看起来非常类似文件）；显然，答案是肯定的！我们必须使用`struct file_operations`中定义的`mmap()`方法：

```
struct file_operations {
...
        int (*mmap) (struct file *, struct vm_area_struct *);
```

除了我们已经完全了解的通常的`struct file`指针之外，此函数还需要`vma`参数（指向`struct vm_area_struct`的指针），用于指示应该由驱动程序映射内存的虚拟地址空间。

`struct vm_area_struct`包含有关连续虚拟内存区域的信息，其特征是起始地址、停止地址、长度和权限。

每个进程拥有更多的虚拟内存区域，可以通过查看名为`/proc/<PID>/maps`的相对 procfs 文件来检查（其中`<PID>`是进程的 PID 号）。

虚拟内存区域是 Linux 内存管理器的一个非常复杂的部分，本书未涉及。好奇的读者可以查看[`www.kernel.org/doc/html/latest/admin-guide/mm/index.html`](https://www.kernel.org/doc/html/latest/admin-guide/mm/index.html)以获取更多信息。

将物理地址映射到用户地址空间，如`vma`参数所示，可以使用辅助函数轻松完成，例如在头文件`linux/include/linux/mm.h`中定义的`remap_pfn_range()`：

```
int remap_pfn_range(structure vm_area_struct *vma,
                    unsigned long addr,
                    unsigned long pfn, unsigned long size,
                    pgprot_t prot);
```

它将由`pfn`寻址的连续物理地址空间映射到由`vma`指针表示的虚拟空间。具体来说，参数是：

+   `vma` - 进行映射的虚拟内存空间

+   `addr` - 重新映射开始的虚拟地址空间

+   `pfn` - 虚拟地址应映射到的物理地址（以页面帧号表示）

+   `size` - 要映射的内存大小（以字节为单位）

+   `prot` - 此映射的保护标志

因此，一个真正简单的`mmap()`实现，考虑到外围设备在物理地址`base_addr`处具有内存区域，大小为`area_len`，可以如下所示：

```
static int my_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct my_device *my_ptr = filp->private_data;
    size_t size = vma->vm_end - vma->vm_start;
    phys_addr_t offset = (phys_addr_t) vma->vm_pgoff << PAGE_SHIFT;
    unsigned long pfn;

    /* Does it even fit in phys_addr_t? */
    if (offset >> PAGE_SHIFT != vma->vm_pgoff)
        return -EINVAL;

    /* We cannot mmap too big areas */
    if ((offset > my_ptr->area_len) ||
        (size > my_ptr->area_len - offset))
        return -EINVAL;

    /* Remap-pfn-range will mark the range VM_IO */
    if (remap_pfn_range(vma, vma->vm_start,
                        my_ptr->base_addr, size,
                        vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}
```

最后需要注意的是，`remap_pfn_range()`使用物理地址，而使用`kmalloc()`或`vmalloc()`函数和相关函数（参见[第六章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=30&action=edit#post_29)，*杂项内核内部*）分配的内存必须使用不同的方法进行管理。对于`kmalloc()`，我们可以使用以下方法来获取`pfn`参数：

```
unsigned long pfn = virt_to_phys(kvirt) >> PAGE_SHIFT;
```

其中 kvirt 是由`kmalloc()`返回的内核虚拟地址要重新映射，对于`vmalloc()`，我们可以这样做：

```
unsigned long pfn = vmalloc_to_pfn(vvirt);
```

在这里，`vvirt`是由`vmalloc()`返回的内核虚拟地址要重新映射。

请注意，使用`vmalloc()`分配的内存不是物理上连续的，因此，如果我们想要映射使用它分配的范围，我们必须逐个映射每个页面，并计算每个页面的物理地址。这是一个更复杂的操作，本书没有解释，因为它与设备驱动程序无关（真正的外围设备只使用物理地址）。

# 使用进程上下文进行锁定

了解如何避免竞争条件是很重要的，因为可能会有多个进程尝试访问我们的驱动程序，或者如何使读取进程进入睡眠状态（我们在这里讨论读取，但对于写入也是一样的）如果我们的驱动程序没有数据供应。前一种情况将在这里介绍，而后一种情况将在下一节介绍。

如果我们看一下我们的 chrdev 驱动程序中如何实现`read()`和`write()`系统调用，我们很容易注意到，如果多个进程尝试进行`read()`调用，甚至如果一个进程尝试进行`read()`调用，另一个尝试进行`write()`调用，就会发生竞争条件。这是因为 ESPRESSObin 的 CPU 是由两个核心组成的多处理器，因此它可以有效地同时执行两个进程。

然而，即使我们的系统只有一个核心，由于例如函数`copy_to_user()`和`copy_from_user()`可能使调用进程进入睡眠状态，因此调度程序可能会撤销 CPU 以便将其分配给另一个进程，这样，即使我们的系统只有一个核心，仍然可能发生`read()`或`write()`方法内部的代码以交错（即非原子）方式执行。

为了避免这些情况可能发生的竞争条件，一个真正可靠的解决方案是使用互斥锁，正如第五章中所介绍的那样，*管理中断和并发*。

我们只需要为每个 chrdev 设备使用一个互斥锁来保护对驱动程序方法的多次访问。

# 使用 poll()和 select()等待 I/O 操作

在现代计算机这样的复杂系统中，通常会有几个有用的外围设备来获取有关外部环境和/或系统状态的信息。有时，我们可能使用不同的进程来管理它们，但可能需要同时管理多个外围设备，但只有一个进程。

在这种情况下，我们可以想象对每个外围设备进行多次`read()`系统调用来获取其数据，但是如果一个外围设备非常慢，需要很长时间才能返回其数据会发生什么？如果我们这样做，可能会减慢所有数据采集的速度（甚至如果一个外围设备没有接收到新数据，可能会锁定数据采集）：

```
fd1 = open("/dev/device1", ...);
fd2 = open("/dev/device2", ...);
fd3 = open("/dev/device3", ...);

while (1) {
    read(fd1, buf1, size1);
    read(fd2, buf2, size2);
    read(fd3, buf3, size3);

    /* Now use data from peripherals */
    ...
}
```

实际上，如果一个外围设备很慢，或者需要很长时间才能返回其数据，我们的循环将停止等待它，我们的程序可能无法正常工作。

一个可能的解决方案是在有问题的外围设备上使用`O_NONBLOCK`标志，甚至在所有外围设备上使用，但这样做可能会使 CPU 过载，产生不必要的系统调用。向内核询问哪个文件描述符属于持有准备好被读取的数据的外围设备（或者可以用于写入）可能更加优雅（和有效）。

为此，我们可以使用`poll()`或`select()`系统调用。`poll()`手册页中指出：

```
NAME
   poll, ppoll - wait for some event on a file descriptor

SYNOPSIS
   #include <poll.h>

   int poll(struct pollfd *fds, nfds_t nfds, int timeout);

   #define _GNU_SOURCE /* See feature_test_macros(7) */
   #include <signal.h>
   #include <poll.h>

   int ppoll(struct pollfd *fds, nfds_t nfds,
           const struct timespec *tmo_p, const sigset_t *sigmask);
```

另一方面，`select()`手册页如下所示：

```
NAME
  select, pselect, FD_CLR, FD_ISSET, FD_SET, FD_ZERO - synchronous I/O
   multiplexing

SYNOPSIS
   /* According to POSIX.1-2001, POSIX.1-2008 */
   #include <sys/select.h>

   /* According to earlier standards */
   #include <sys/time.h>
   #include <sys/types.h>
   #include <unistd.h>

   int select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout);

   void FD_CLR(int fd, fd_set *set);
   int FD_ISSET(int fd, fd_set *set);
   void FD_SET(int fd, fd_set *set);
   void FD_ZERO(fd_set *set);
```

即使它们看起来非常不同，它们几乎做相同的事情；实际上，在内核内部，它们是通过使用相同的`poll()`方法来实现的，该方法在著名的`struct file_operations`中定义如下（请参阅`linux/include/linux/fs.h`文件）：

```
struct file_operations {
...
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
```

从内核的角度来看，`poll()`方法的实现非常简单；我们只需要上面使用的等待队列，然后我们必须验证我们的设备是否有一些数据要返回。简而言之，通用的`poll()`方法如下所示：

```
static __poll_t simple_poll(struct file *filp, poll_table *wait)
{
    struct simple_device *chrdev = filp->private_data;
    __poll_t mask = 0;

    poll_wait(filp, &simple_device->queue, wait);

    if (has_data_to_read(simple_device))
        mask |= EPOLLIN | EPOLLRDNORM;

    if (has_space_to_write(simple_device))
        mask |= EPOLLOUT | EPOLLWRNORM;

    return mask;
}
```

我们只需使用`poll_wait()`函数告诉内核驱动程序使用哪个等待队列来使读取或写入进程进入睡眠状态，然后我们将变量`mask`返回为 0；如果没有准备好要读取的数据，或者我们无法接受新的要写入的数据，我们将返回`EPOLLIN | EPOLLRDNORM`值，如果有一些数据可以按位读取，并且我们也愿意接受这些数据。

所有可用的`poll()`事件都在头文件`linux/include/uapi/linux/eventpoll.h`中定义。

一旦`poll()`方法被实现，我们可以使用它，例如，如下所示使用`select()`：

```
fd_set read_fds;

fd1 = open("/dev/device1", ...);
fd2 = open("/dev/device2", ...);
fd3 = open("/dev/device3", ...);

while (1) {
    FD_ZERO(&read_fds);
    FD_SET(fd1, &read_fds);
    FD_SET(fd2, &read_fds);
    FD_SET(fd2, &read_fds);

    select(FD_SETSIZE, &read_fds, NULL, NULL, NULL);

    if (FD_ISSET(fd1, &read_fds))
        read(fd1, buf1, size1);
    if (FD_ISSET(fd2, &read_fds))
        read(fd2, buf2, size2);
    if (FD_ISSET(fd3, &read_fds))
        read(fd3, buf3, size3);

    /* Now use data from peripherals */
    ...
}
```

打开所有需要的文件描述符后，我们必须使用`FD_ZERO()`宏清除`read_fds`变量，然后使用`FD_SET()`宏将每个文件描述符添加到由`read_fds`表示的读取进程集合中。完成后，我们可以将`read_fds`传递给`select()`，以指示内核要观察哪些文件描述符。

请注意，通常情况下，我们应该将观察集合中文件描述符的最高编号加 1 作为`select()`系统调用的第一个参数；然而，我们也可以传递`FD_SETSIZE`值，这是系统允许的最大允许值。这可能是一个非常大的值，因此以这种方式编程会导致扫描整个文件描述符位图的低效性；好的程序员应该使用最大值加 1。

另外，请注意，我们的示例适用于读取，但完全相同的方法也适用于写入！

# 使用`fasync()`管理异步通知

在前一节中，我们考虑了一个特殊情况，即我们可能需要管理多个外围设备的情况。在这种情况下，我们可以询问内核，即准备好的文件描述符，从哪里获取数据或使用`poll()`或`select()`系统调用将数据写入。然而，这不是唯一的解决方案。另一种可能性是使用`fasync()`方法。

通过使用这种方法，我们可以要求内核在文件描述符上发生新事件时发送信号（通常是`SIGIO`）；当然，事件是准备好读取或准备好写入的事件，文件描述符是与我们的外围设备连接的文件描述符。

由于本书中已经介绍的方法，`fasync()`方法没有用户空间对应项；根本没有`fasync()`系统调用。我们可以通过利用`fcntl()`系统调用间接使用它。如果我们查看它的手册页，我们会看到以下内容：

```
NAME
   fcntl - manipulate file descriptor

SYNOPSIS
   #include <unistd.h>
   #include <fcntl.h>

   int fcntl(int fd, int cmd, ... /* arg */ );

...

   F_SETOWN (int)
          Set the process ID or process group ID that will receive SIGIO
          and SIGURG signals for events on the file descriptor fd. The
          target process or process group ID is specified in arg. A
          process ID is specified as a positive value; a process group ID
          is specified as a negative value. Most commonly, the calling
          process specifies itself as the owner (that is, arg is specified
          as getpid(2)).
```

现在，让我们一步一步来。从内核的角度来看，我们必须实现`fasync()`方法，如下所示（请参阅`linux/include/linux/fs.h`文件中的`struct file_operations`）：

```
struct file_operations {
...
    int (*fsync) (struct file *, loff_t, loff_t, int datasync);
```

它的实现非常简单，因为通过使用`fasync_helper()`辅助函数，我们只需要在以下通用驱动程序中报告的步骤：

```
static int simple_fasync(int fd, struct file *filp, int on)
{
    struct simple_device *simple = filp->private_data;

    return fasync_helper(fd, filp, on, &simple->fasync_queue);
}
```

其中，`fasync_queue`是一个指向`struct fasync_struct`的指针，内核使用它来排队所有对接收`SIGIO`信号感兴趣的进程，每当驱动程序准备好进行读取或写入操作时。这些事件使用`kill_fasync()`函数通知，通常在中断处理程序中或者每当我们知道新数据已经到达或者我们准备写入时。

```
kill_fasync(&simple->fasync_queue, SIGIO, POLL_IN);
```

请注意，当数据可供读取时，我们必须使用`POLL_IN`，而当我们的外围设备准备好接受新数据时，我们应该使用`POLL_OUT`。

请参阅`linux/include/uapi/asm-generic/siginfo.h`文件，查看所有可用的`POLL_*`定义。

从用户空间的角度来看，我们需要采取一些步骤来实现`SIGIO`信号：

1.  首先，我们必须安装一个合适的信号处理程序。

1.  然后，我们必须使用`F_SETOWN`命令调用`fcntl()`来设置将接收与我们的设备相关的`SIGIO`的进程 ID（通常称为 PID）（由文件描述符`fd`表示）。

1.  然后，我们必须通过设置`FASYNC`位来更改描述文件访问模式的`flags`。

一个可能的实现如下：

```
long flags;

fd = open("/dev/device", ...);

signal(SIGIO, sigio_handler);

fcntl(fd, F_SETOWN, getpid());

flags = fcntl(fd, F_GETFL);

fcntl(fd, F_SETFL, flags | FASYNC);
```
