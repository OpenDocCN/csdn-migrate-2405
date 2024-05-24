# 精通 Linux 内核开发（四）

> 原文：[`zh.annas-archive.org/md5/B50238228DC7DE75D9C3CCE2886AAED2`](https://zh.annas-archive.org/md5/B50238228DC7DE75D9C3CCE2886AAED2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：中断和延迟工作

**中断**是传递给处理器的电信号，指示发生需要立即处理的重大事件。这些信号可以来自系统连接的外部硬件或处理器内部的电路。在本章中，我们将研究内核的中断管理子系统，并探讨以下内容：

+   可编程中断控制器

+   中断向量表

+   IRQs

+   IRQ 芯片和 IRQ 描述符

+   注册和注销中断处理程序

+   IRQ 线路控制操作

+   IRQ 堆栈

+   延迟例程的需求

+   软中断

+   任务

+   工作队列

# 中断信号和向量

当中断来自外部设备时，称为**硬件中断**。这些信号是由外部硬件产生的，以寻求处理器对重大外部事件的关注，例如键盘上的按键、鼠标按钮的点击或移动鼠标触发硬件中断，通过这些中断处理器被通知有数据可供读取。硬件中断与处理器时钟异步发生（意味着它们可以在随机时间发生），因此也被称为**异步中断**。

由于当前执行的程序指令生成的事件而触发的 CPU 内部的中断被称为**软件中断**。软件中断是由当前执行的程序指令触发的**异常**引起的，或者在执行特权指令时引发中断。例如，当程序指令尝试将一个数字除以零时，处理器的算术逻辑单元会引发一个称为除零异常的中断。类似地，当正在执行的程序意图调用内核服务调用时，它执行一个特殊指令（sysenter），引发一个中断以将处理器转换到特权模式，为执行所需的服务调用铺平道路。这些事件与处理器时钟同步发生，因此也被称为**同步中断**。

在发生中断事件时，CPU 被设计为抢占当前的指令序列或执行线程，并执行一个称为**中断服务例程**（**ISR**）的特殊函数。为了找到与中断事件对应的适当的***ISR***，使用**中断向量表**。**中断向量**是内存中包含对应于中断执行的软件定义**中断服务**的引用的地址。处理器架构定义支持的**中断向量**的总数，并描述内存中每个中断向量的布局。一般来说，对于大多数处理器架构，所有支持的向量都被设置在内存中作为一个称为**中断向量表**的列表，其地址由平台软件编程到处理器寄存器中。

让我们以*x86*架构为例，以便更好地理解。x86 系列处理器支持总共 256 个中断向量，其中前 32 个保留用于处理器异常，其余用于软件和硬件中断。x86 通过实现一个向量表来引用**中断描述符表（IDT）**，这是一个 8 字节（32 位机器）或 16 字节（64 位*x86*机器）大小的描述符数组。在早期引导期间，内核代码的特定于架构的分支在内存中设置**IDT**并将处理器的**IDTR**寄存器（特殊的 x86 寄存器）编程为**IDT**的物理起始地址和长度。当发生中断时，处理器通过将报告的向量编号乘以向量描述符的大小（*x86_32 机器上的向量编号 x8*，*x86_64 机器上的向量编号 x16*）并将结果加到**IDT**的基地址来定位相关的向量描述符。一旦到达有效的*向量描述符*，处理器将继续执行描述符中指定的操作。

在 x86 平台上，每个*向量描述符*实现了一个*门（中断、任务或陷阱）*，用于在段之间传递执行控制。代表硬件中断的向量描述符实现了一个*中断门*，它指向包含中断处理程序代码的段的基地址和偏移量。*中断门*在将控制传递给指定的中断处理程序之前禁用所有可屏蔽中断。代表*异常*和软件中断的向量描述符实现了一个*陷阱门*，它也指向被指定为事件处理程序的代码的位置。与*中断门*不同，*陷阱门*不会禁用可屏蔽中断，这使其适用于执行软中断处理程序。

# 可编程中断控制器

现在让我们专注于外部中断，并探讨处理器如何识别外部硬件中断的发生，以及它们如何发现与中断相关联的向量编号。CPU 设计有一个专用输入引脚（中断引脚），用于信号外部中断。每个能够发出中断请求的外部硬件设备通常由一个或多个输出引脚组成，称为**中断请求线（IRQ）**，用于在 CPU 上信号中断请求。所有计算平台都使用一种称为**可编程中断控制器（PIC）**的硬件电路，将 CPU 的中断引脚多路复用到各种中断请求线上。所有来自板载设备控制器的现有 IRQ 线路都被路由到中断控制器的输入引脚，该控制器监视每个 IRQ 线路以获取中断信号，并在中断到达时将请求转换为 CPU 可理解的向量编号，并将中断信号传递到 CPU 的中断引脚。简而言之，可编程中断控制器将多个设备中断请求线路多路复用到处理器的单个中断线上：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00049.jpeg)

中断控制器的设计和实现是特定于平台的。英特尔 x86 多处理器平台使用高级可编程中断控制器（APIC）。APIC 设计将中断控制器功能分为两个不同的芯片组件：第一个组件是位于系统总线上的 I/O APIC。所有共享的外围硬件 IRQ 线路都被路由到 I/O APIC；该芯片将中断请求转换为向量代码。第二个是称为本地 APIC 的每 CPU 控制器（通常集成到处理器核心中），它将硬件中断传递给特定的 CPU 核心。I/O APIC 将中断事件路由到所选 CPU 核心的本地 APIC。它被编程为一个重定向表，用于进行中断路由决策。CPU 本地 APIC 管理特定 CPU 核心的所有外部中断；此外，它们传递来自 CPU 本地硬件的事件，如定时器，并且还可以接收和生成 SMP 平台上可能发生的处理器间中断（IPI）。

以下图表描述了 APIC 的分裂架构。现在事件的流程始于各个设备在 I/O APIC 上引发 IRQ，后者将请求路由到特定的本地 APIC，后者又将中断传递给特定的 CPU 核心：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00050.jpeg)

类似于 APIC 架构，多核 ARM 平台将通用中断控制器（GIC）的实现分为两部分。第一个组件称为分发器，它是全局的，有几个外围硬件中断源物理路由到它。第二个组件是每 CPU 复制的，称为 CPU 接口。分发器组件被编程为将共享外围中断（SPI）的分发逻辑路由到已知的 CPU 接口。

# 中断控制器操作

内核代码的体系结构特定分支实现了中断控制器特定操作，用于管理 IRQ 线路，例如屏蔽/取消屏蔽单个中断，设置优先级和 SMP 亲和性。这些操作需要从内核的体系结构无关代码路径中调用，以便操纵单个 IRQ 线路，并为了促进这样的调用，内核通过一个称为`struct irq_chip`的结构定义了一个体系结构无关的抽象层。该结构可以在内核头文件`<include/linux/irq.h>`中找到：

```
struct irq_chip {
     struct device *parent_device;
     const char    *name;
     unsigned int (*irq_startup)(struct irq_data *data);
     void (*irq_shutdown)(struct irq_data *data);
     void (*irq_enable)(struct irq_data *data);
     void (*irq_disable)(struct irq_data *data);

     void (*irq_ack)(struct irq_data *data);
     void (*irq_mask)(struct irq_data *data);
     void (*irq_mask_ack)(struct irq_data *data);
     void (*irq_unmask)(struct irq_data *data);
     void (*irq_eoi)(struct irq_data *data);

     int (*irq_set_affinity)(struct irq_data *data, const struct cpumask
                             *dest, bool force);

     int (*irq_retrigger)(struct irq_data *data);    
     int (*irq_set_type)(struct irq_data *data, unsigned int flow_type);
     int (*irq_set_wake)(struct irq_data *data, unsigned int on);    
     void (*irq_bus_lock)(struct irq_data *data);   
     void (*irq_bus_sync_unlock)(struct irq_data *data);    
     void (*irq_cpu_online)(struct irq_data *data);   
     void (*irq_cpu_offline)(struct irq_data *data);   
     void (*irq_suspend)(struct irq_data *data); 
     void (*irq_resume)(struct irq_data *data); 
     void (*irq_pm_shutdown)(struct irq_data *data); 
     void (*irq_calc_mask)(struct irq_data *data); 
     void (*irq_print_chip)(struct irq_data *data, struct seq_file *p);    
     int (*irq_request_resources)(struct irq_data *data); 
     void (*irq_release_resources)(struct irq_data *data); 
     void (*irq_compose_msi_msg)(struct irq_data *data, struct msi_msg *msg);
     void (*irq_write_msi_msg)(struct irq_data *data, struct msi_msg *msg);  

     int (*irq_get_irqchip_state)(struct irq_data *data, enum  irqchip_irq_state which, bool *state);
     int (*irq_set_irqchip_state)(struct irq_data *data, enum irqchip_irq_state which, bool state);

     int (*irq_set_vcpu_affinity)(struct irq_data *data, void *vcpu_info);   
     void (*ipi_send_single)(struct irq_data *data, unsigned int cpu);   
     void (*ipi_send_mask)(struct irq_data *data, const struct cpumask *dest);      unsigned long flags; 
};
```

该结构声明了一组函数指针，以考虑各种硬件平台上发现的 IRQ 芯片的所有特殊性。因此，由特定于板级的代码定义的结构的特定实例通常只支持可能操作的子集。以下是定义 I/O APIC 和 LAPIC 操作的 x86 多核平台版本的`irq_chip`实例。

```
static struct irq_chip ioapic_chip __read_mostly = {
              .name             = "IO-APIC",
              .irq_startup      = startup_ioapic_irq,
              .irq_mask         = mask_ioapic_irq,
              .irq_unmask       = unmask_ioapic_irq,
              .irq_ack          = irq_chip_ack_parent,
              .irq_eoi          = ioapic_ack_level,
              .irq_set_affinity = ioapic_set_affinity,
              .irq_retrigger    = irq_chip_retrigger_hierarchy,
              .flags            = IRQCHIP_SKIP_SET_WAKE,
};

static struct irq_chip lapic_chip __read_mostly = {
              .name            = "local-APIC",
              .irq_mask        = mask_lapic_irq,
              .irq_unmask      = unmask_lapic_irq,
              .irq_ack         = ack_lapic_irq,
};
```

# 中断描述符表

另一个重要的抽象是与与硬件中断相关的 IRQ 号。中断控制器使用唯一的硬件 IRQ 号标识每个 IRQ 源。内核的通用中断管理层将每个硬件 IRQ 映射到称为 Linux IRQ 的唯一标识符；这些数字抽象了硬件 IRQ，从而确保内核代码的可移植性。所有外围设备驱动程序都被编程为使用 Linux IRQ 号来绑定或注册它们的中断处理程序。

Linux IRQ 由 IRQ 描述符结构表示，由`struct irq_desc`定义；在早期内核引导期间，对于每个 IRQ 源，将枚举此结构的一个实例。IRQ 描述符的列表以 IRQ 号为索引，称为 IRQ 描述符表：

```
 struct irq_desc {
      struct irq_common_data    irq_common_data;
      struct irq_data           irq_data;
      unsigned int __percpu    *kstat_irqs;
      irq_flow_handler_t        handle_irq;
#ifdef CONFIG_IRQ_PREFLOW_FASTEOI
      irq_preflow_handler_t     preflow_handler;
#endif
      struct irqaction         *action;    /* IRQ action list */
      unsigned int             status_use_accessors;
      unsigned int             core_internal_state__do_not_mess_with_it;
      unsigned int             depth;    /* nested irq disables */
      unsigned int             wake_depth;/* nested wake enables */
      unsigned int             irq_count;/* For detecting broken IRQs */
      unsigned long            last_unhandled;   
      unsigned int             irqs_unhandled;
      atomic_t                 threads_handled;
      int                      threads_handled_last;
      raw_spinlock_t           lock;
      struct cpumask           *percpu_enabled;
      const struct cpumask     *percpu_affinity;
#ifdef CONFIG_SMP
     const struct cpumask         *affinity_hint;
     struct irq_affinity_notify   *affinity_notify;

     ...
     ...
     ...
};
```

`irq_data`是`struct irq_data`的一个实例，其中包含与中断管理相关的低级信息，例如 Linux 中断号、硬件中断号，以及指向中断控制器操作（`irq_chip`）的指针等其他重要字段：

```
/**
 * struct irq_data - per irq chip data passed down to chip functions
 * @mask:          precomputed bitmask for accessing the chip registers
 * @irq:           interrupt number
 * @hwirq:         hardware interrupt number, local to the interrupt domain
 * @common:        point to data shared by all irqchips
 * @chip:          low level interrupt hardware access
 * @domain:        Interrupt translation domain; responsible for mapping
 *                 between hwirq number and linux irq number.
 * @parent_data:   pointer to parent struct irq_data to support hierarchy
 *                 irq_domain
 * @chip_data:     platform-specific per-chip private data for the chip
 *                 methods, to allow shared chip implementations
 */

struct irq_data { 
       u32 mask;    
       unsigned int irq;    
       unsigned long hwirq;    
       struct irq_common_data *common;    
       struct irq_chip *chip;    
       struct irq_domain *domain; 
#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY    
       struct irq_data *parent_data; 
#endif    
       void *chip_data; 
};
```

`irq_desc`结构的`handle_irq`元素是一个`irq_flow_handler_t`类型的函数指针，它指的是处理线路上流管理的高级函数。通用中断层提供了一组预定义的中断流函数；根据其类型，每个中断线路都分配了适当的例程。

+   `handle_level_irq()`：电平触发中断的通用实现

+   `handle_edge_irq()`：边沿触发中断的通用实现

+   `handle_fasteoi_irq()`：只需要在处理程序结束时进行 EOI 的中断的通用实现

+   `handle_simple_irq()`：简单中断的通用实现

+   `handle_percpu_irq()`：每 CPU 中断的通用实现

+   `handle_bad_irq()`：用于虚假中断

`irq_desc`结构的`*action`元素是指向一个或一组动作描述符的指针，其中包含特定于驱动程序的中断处理程序等其他重要元素。每个动作描述符都是在内核头文件`<linux/interrupt.h>`中定义的`struct irqaction`的实例：

```
/**
 * struct irqaction - per interrupt action descriptor
 * @handler: interrupt handler function
 * @name: name of the device
 * @dev_id: cookie to identify the device
 * @percpu_dev_id: cookie to identify the device
 * @next: pointer to the next irqaction for shared interrupts
 * @irq: interrupt number
 * @flags: flags 
 * @thread_fn: interrupt handler function for threaded interrupts
 * @thread: thread pointer for threaded interrupts
 * @secondary: pointer to secondary irqaction (force threading)
 * @thread_flags: flags related to @thread
 * @thread_mask: bitmask for keeping track of @thread activity
 * @dir: pointer to the proc/irq/NN/name entry
 */
struct irqaction {
       irq_handler_t handler;
       void * dev_id;
       void __percpu * percpu_dev_id;
       struct irqaction * next;
       irq_handler_t thread_fn;
       struct task_struct * thread;
       struct irqaction * secondary;
       unsigned int irq;
       unsigned int flags;
       unsigned long thread_flags;
       unsigned long thread_mask;
       const char * name;
       struct proc_dir_entry * dir;
};  
```

# 高级中断管理接口

通用 IRQ 层提供了一组函数接口，供设备驱动程序获取 IRQ 描述符和绑定中断处理程序，释放 IRQ，启用或禁用中断线等。我们将在本节中探讨所有通用接口。

# 注册中断处理程序

```
typedef irqreturn_t (*irq_handler_t)(int, void *);

/**
 * request_irq - allocate an interrupt line
 * @irq: Interrupt line to allocate
 * @handler: Function to be called when the IRQ occurs.
 * @irqflags: Interrupt type flags
 * @devname: An ascii name for the claiming device
 * @dev_id: A cookie passed back to the handler function
 */
 int request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
                 const char *name, void *dev);
```

`request_irq()`使用传递的值实例化一个`irqaction`对象，并将其绑定到作为第一个（`irq`）参数指定的`irq_desc`。此调用分配中断资源并启用中断线和 IRQ 处理。`handler`是一个`irq_handler_t`类型的函数指针，它接受特定于驱动程序的中断处理程序例程的地址。`flags`是与中断管理相关的选项的位掩码。标志位在内核头文件`<linux/interrupt.h>`中定义：

+   `IRQF_SHARED`：在将中断处理程序绑定到共享的 IRQ 线时使用。

+   `IRQF_PROBE_SHARED`：当调用者期望共享不匹配时设置。

+   `IRQF_TIMER`：标记此中断为定时器中断。

+   `IRQF_PERCPU`：中断是每 CPU 的。

+   `IRQF_NOBALANCING`：标志，用于排除此中断不参与 IRQ 平衡。

+   `IRQF_IRQPOLL`：中断用于轮询（仅考虑在共享中断中首先注册的中断以提高性能）。

+   `IRQF_NO_SUSPEND`：在挂起期间不禁用此 IRQ。不能保证此中断将唤醒系统从挂起状态。

+   `IRQF_FORCE_RESUME`：即使设置了`IRQF_NO_SUSPEND`，也在恢复时强制启用它。

+   `IRQF_EARLY_RESUME`：在 syscore 期间提前恢复 IRQ，而不是在设备恢复时。

+   `IRQF_COND_SUSPEND`：如果 IRQ 与`NO_SUSPEND`用户共享，则在挂起中断后执行此中断处理程序。对于系统唤醒设备，用户需要在其中断处理程序中实现唤醒检测。

由于每个标志值都是一个位，可以传递这些标志的子集的逻辑 OR（即|），如果没有适用的标志，则`flags`参数的值为 0 是有效的。分配给`dev`的地址被视为唯一的 cookie，并用作共享 IRQ 情况下操作实例的标识符。在注册中断处理程序时，此参数的值可以为 NULL，而不使用`IRQF_SHARED`标志。

成功时，`request_irq()`返回零；非零返回值表示注册指定中断处理程序失败。返回错误代码`-EBUSY`表示注册或绑定处理程序到已经使用的指定 IRQ 失败。

中断处理程序例程具有以下原型：

```
irqreturn_t handler(int irq, void *dev_id);
```

`irq`指定了 IRQ 号码，而`dev_id`是在注册处理程序时使用的唯一 cookie。`irqreturn_t`是一个枚举整数常量的 typedef：

```
enum irqreturn {
        IRQ_NONE         = (0 << 0),
        IRQ_HANDLED              = (1 << 0),
        IRQ_WAKE_THREAD          = (1 << 1),
};

typedef enum irqreturn irqreturn_t;
```

中断处理程序应返回`IRQ_NONE`以指示未处理中断。它还用于指示中断的来源不是来自其设备的情况下的共享 IRQ。当中断处理正常完成时，必须返回`IRQ_HANDLED`以指示成功。`IRQ_WAKE_THREAD`是一个特殊标志，用于唤醒线程处理程序；我们将在下一节详细介绍它。

# 注销中断处理程序

驱动程序的中断处理程序可以通过调用`free_irq()`例程来注销：

```
/**
 * free_irq - free an interrupt allocated with request_irq
 * @irq: Interrupt line to free
 * @dev_id: Device identity to free
 *
 * Remove an interrupt handler. The handler is removed and if the
 * interrupt line is no longer in use by any driver it is disabled.
 * On a shared IRQ the caller must ensure the interrupt is disabled
 * on the card it drives before calling this function. The function
 * does not return until any executing interrupts for this IRQ
 * have completed.
 * Returns the devname argument passed to request_irq.
 */
const void *free_irq(unsigned int irq, void *dev_id);
```

`dev_id`是用于在共享 IRQ 情况下标识要注销的处理程序的唯一 cookie（在注册处理程序时分配）；对于其他情况，此参数可以为 NULL。此函数是一个潜在的阻塞调用，并且不得从中断上下文中调用：它会阻塞调用上下文，直到指定的 IRQ 线路上的任何中断处理程序的执行完成。

# 线程中断处理程序

通过`request_irq()`注册的处理程序由内核的中断处理路径执行。这条代码路径是异步的，通过暂停本地处理器上的调度程序抢占和硬件中断来运行，因此被称为硬中断上下文。因此，必须将驱动程序的中断处理程序编程为简短（尽量少做工作）和原子（非阻塞），以确保系统的响应性。然而，并非所有硬件中断处理程序都可以简短和原子：有许多复杂设备生成中断事件，其响应涉及复杂的可变时间操作。

传统上，驱动程序被编程为处理中断处理程序的这种复杂性，采用了分离处理程序设计，称为**顶半部**和**底半部**。顶半部例程在硬中断上下文中被调用，这些函数被编程为执行*中断关键*操作，例如对硬件寄存器的物理 I/O，并安排底半部进行延迟执行。底半部例程通常用于处理*中断非关键*和*可推迟工作*，例如处理顶半部生成的数据，与进程上下文交互以及访问用户地址空间。内核提供了多种机制来调度和执行底半部例程，每种机制都有不同的接口 API 和执行策略。我们将在下一节详细介绍正式底半部机制的设计和用法细节。

作为使用正式底半部机制的替代方案，内核支持设置可以在线程上下文中执行的中断处理程序，称为**线程中断处理程序**。驱动程序可以通过另一个名为`request_threaded_irq()`的接口例程设置线程中断处理程序：

```
/**
 * request_threaded_irq - allocate an interrupt line
 * @irq: Interrupt line to allocate
 * @handler: Function to be called when the IRQ occurs.
 * Primary handler for threaded interrupts
 * If NULL and thread_fn != NULL the default
 * primary handler is installed
 * @thread_fn: Function called from the irq handler thread
 * If NULL, no irq thread is created
 * @irqflags: Interrupt type flags
 * @devname: An ascii name for the claiming device
 * @dev_id: A cookie passed back to the handler function
 */
   int request_threaded_irq(unsigned int irq, irq_handler_t handler,
                            irq_handler_t thread_fn, unsigned long irqflags,
                            const char *devname, void *dev_id);
```

分配给`handler`的函数作为在硬中断上下文中执行的主要中断处理程序。分配给`thread_fn`的例程在线程上下文中执行，并在主处理程序返回`IRQ_WAKE_THREAD`时被调度运行。通过这种分离处理程序设置，有两种可能的用例：主处理程序可以被编程为执行中断关键工作，并将非关键工作推迟到线程处理程序以供以后执行，类似于底半部分。另一种设计是将整个中断处理代码推迟到线程处理程序，并将主处理程序限制为验证中断源并唤醒线程例程。这种用例可能需要相应的中断线路在线程处理程序完成之前被屏蔽，以避免中断的嵌套。这可以通过编程主处理程序在唤醒线程处理程序之前关闭中断源或通过在注册线程中断处理程序时分配的标志位`IRQF_ONESHOT`来实现。

以下是与线程中断处理程序相关的`irqflags`：

+   `IRQF_ONESHOT`：硬 IRQ 处理程序完成后不会重新启用中断。这由需要保持 IRQ 线禁用直到线程处理程序运行完毕的线程化中断使用。

+   `IRQF_NO_THREAD`：中断不能被线程化。这在共享 IRQ 中用于限制使用线程化中断处理程序。

调用此例程并将 NULL 分配给`handler`将导致内核使用默认的主处理程序，该处理程序简单地返回`IRQ_WAKE_THREAD`。而将 NULL 分配给`thread_fn`调用此函数等同于`request_irq()`：

```
static inline int __must_check
request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
            const char *name, void *dev)
{
        return request_threaded_irq(irq, handler, NULL, flags, name, dev);
}
```

设置中断处理程序的另一种替代接口是`request_any_context_irq()`。此例程具有与`request_irq()`类似的签名，但在功能上略有不同：

```
/**
 * request_any_context_irq - allocate an interrupt line
 * @irq: Interrupt line to allocate
 * @handler: Function to be called when the IRQ occurs.
 * Threaded handler for threaded interrupts.
 * @flags: Interrupt type flags
 * @name: An ascii name for the claiming device
 * @dev_id: A cookie passed back to the handler function
 *
 * This call allocates interrupt resources and enables the
 * interrupt line and IRQ handling. It selects either a
 * hardirq or threaded handling method depending on the
 * context.
 * On failure, it returns a negative value. On success,
 * it returns either IRQC_IS_HARDIRQ or IRQC_IS_NESTED..
 */
int request_any_context_irq(unsigned int irq,irq_handler_t handler, 
                            unsigned long flags,const char *name,void *dev_id)

```

此函数与`request_irq()`的不同之处在于，它查看由特定于体系结构的代码设置的 IRQ 描述符的中断线属性，并决定是否将分配的函数建立为传统的硬 IRQ 处理程序或作为线程中断处理程序。成功时，如果已建立处理程序以在硬 IRQ 上下文中运行，则返回`IRQC_IS_HARDIRQ`，否则返回`IRQC_IS_NESTED`。

# 控制接口

通用的 IRQ 层提供了对 IRQ 线进行控制操作的例程。以下是用于屏蔽和取消屏蔽特定 IRQ 线的函数列表：

```
void disable_irq(unsigned int irq);
```

通过操作 IRQ 描述符结构中的计数器来禁用指定的 IRQ 线。此例程可能是一个阻塞调用，因为它会等待此中断的任何运行处理程序完成。另外，也可以使用函数`disable_irq_nosync()`来*禁用*给定的 IRQ 线；此调用不会检查并等待给定中断线的任何运行处理程序完成：

```
void disable_irq_nosync(unsigned int irq);
```

可以通过调用以下函数来启用已禁用的 IRQ 线：

```
void enable_irq(unsigned int irq);
```

请注意，IRQ 启用和禁用操作是嵌套的，即，多次*禁用*IRQ 线的调用需要相同数量的*启用*调用才能重新启用该 IRQ 线。这意味着`enable_irq()`只有在调用它与最后的*禁用*操作匹配时才会启用给定的 IRQ。

可以选择为本地 CPU 禁用/启用中断；以下宏对应用于相同目的：

+   `local_irq_disable()`：在本地处理器上禁用中断。

+   `local_irq_enable()`：为本地处理器启用中断。

+   `local_irq_save(unsigned long flags)`：通过将当前中断状态保存在*flags*中，在本地 CPU 上禁用中断。

+   `local_irq_restore(unsigned long flags)`：通过将中断恢复到先前的状态，在本地 CPU 上启用中断。

# IRQ 堆栈

从历史上看，对于大多数体系结构，中断处理程序共享了被中断的运行进程的内核堆栈。正如第一章所讨论的，32 位体系结构的进程内核堆栈通常为 8 KB，而 64 位体系结构为 16 KB。固定的内核堆栈可能并不总是足够用于内核工作和 IRQ 处理例程，导致内核代码和中断处理程序都需要谨慎地分配数据。为了解决这个问题，内核构建（对于一些体系结构）默认配置为为中断处理程序设置每个 CPU 硬 IRQ 堆栈，并为软中断代码设置每个 CPU 软 IRQ 堆栈。以下是内核头文件`<arch/x86/include/asm/processor.h>`中特定于 x86-64 位体系结构的堆栈声明：

```
/*
 * per-CPU IRQ handling stacks
 */
struct irq_stack {
        u32                     stack[THREAD_SIZE/sizeof(u32)];
} __aligned(THREAD_SIZE);

DECLARE_PER_CPU(struct irq_stack *, hardirq_stack);
DECLARE_PER_CPU(struct irq_stack *, softirq_stack);
```

除此之外，x86-64 位构建还包括特殊的堆栈；更多细节可以在内核源代码文档`<x86/kernel-stacks>`中找到：

+   双重故障堆栈

+   调试堆栈

+   NMI 堆栈

+   Mce 堆栈

# 延迟工作

如前一节介绍的，**底半部**是内核机制，用于执行延迟工作，并且可以由任何内核代码参与，以推迟对非关键工作的执行，直到将来的某个时间。为了支持实现和管理延迟例程，内核实现了特殊的框架，称为**softirqs**、**tasklets**和**work queues**。每个这些框架都包括一组数据结构和函数接口，用于注册、调度和排队底半部例程。每种机制都设计有一个独特的*策略*来管理和执行底半部。需要延迟执行的驱动程序和其他内核服务将需要通过适当的框架绑定和调度它们的 BH 例程。

# Softirqs

术语**softirq**大致翻译为**软中断**，正如其名称所示，由该框架管理的延迟例程以高优先级执行，但启用了硬中断线*。因此，softirq 底半部（或 softirqs）可以抢占除硬中断处理程序之外的所有其他任务。然而，softirq 的使用仅限于静态内核代码，这种机制对于动态内核模块不可用。

每个 softirq 通过在内核头文件`<linux/interrupt.h>`中声明的`struct softirq_action`类型的实例表示。该结构包含一个函数指针，可以保存底半部例程的地址：

```
struct softirq_action
{
        void (*action)(struct softirq_action *);
};
```

当前版本的内核有 10 个 softirq，每个通过内核头文件`<linux/interrupt.h>`中的枚举索引。这些索引作为标识，并被视为 softirq 的相对优先级，具有较低索引的条目被视为优先级较高，索引 0 为最高优先级的 softirq：

```
enum
{
        HI_SOFTIRQ=0,
        TIMER_SOFTIRQ,
        NET_TX_SOFTIRQ,
        NET_RX_SOFTIRQ,
        BLOCK_SOFTIRQ,
        IRQ_POLL_SOFTIRQ,
        TASKLET_SOFTIRQ,
        SCHED_SOFTIRQ,
        HRTIMER_SOFTIRQ, /* Unused, but kept as tools rely on the
                            numbering. Sigh! */
        RCU_SOFTIRQ, /* Preferable RCU should always be the last softirq */

        NR_SOFTIRQS
};
```

内核源文件`<kernel/softirq.c>`声明了一个名为`softirq_vec`的数组，大小为`NR_SOFTIRQS`，每个偏移量包含一个对应 softirq 枚举中的`softirq_action`实例：

```
static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

/* string constants for naming each softirq */
const char * const softirq_to_name[NR_SOFTIRQS] = {
        "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
        "TASKLET", "SCHED", "HRTIMER", "RCU"
};
```

框架提供了一个函数`open_softriq()`，用于使用相应的底半部例程初始化 softirq 实例：

```
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
        softirq_vec[nr].action = action;
}

```

`nr`是要初始化的 softirq 的索引，`*action`是要用底半部例程的地址初始化的函数指针。以下代码摘录来自定时器服务，并显示了调用`open_softirq`来注册 softirq：

```
/*kernel/time/timer.c*/
open_softirq(TIMER_SOFTIRQ, run_timer_softirq);
```

内核服务可以使用函数`raise_softirq()`来发出 softirq 处理程序的执行。此函数以 softirq 的索引作为参数：

```
void raise_softirq(unsigned int nr)
{
        unsigned long flags;

        local_irq_save(flags);
        raise_softirq_irqoff(nr);
        local_irq_restore(flags);
} 
```

以下代码摘录来自`<kernel/time/timer.c>`：

```
void run_local_timers(void)
{
        struct timer_base *base = this_cpu_ptr(&amp;timer_bases[BASE_STD]);

        hrtimer_run_queues();
        /* Raise the softirq only if required. */
        if (time_before(jiffies, base->clk)) {
                if (!IS_ENABLED(CONFIG_NO_HZ_COMMON) || !base->nohz_active)
                        return;
                /* CPU is awake, so check the deferrable base. */
                base++;
                if (time_before(jiffies, base->clk))
                        return;
        }
        raise_softirq(TIMER_SOFTIRQ);
}
```

内核维护了一个每 CPU 位掩码，用于跟踪为执行而引发的 softirq，并且函数`raise_softirq()`设置本地 CPU 的 softirq 位掩码中的相应位（作为参数提到的索引）以标记指定的 softirq 为待处理。

待处理的 softirq 处理程序在内核代码的各个点检查并执行。主要是在中断上下文中执行，在硬中断处理程序完成后立即执行，同时启用 IRQ 线。这保证了从硬中断处理程序引发的 softirq 的快速处理，从而实现了最佳的缓存使用。然而，内核允许任意任务通过`local_bh_disable()`或`spin_lock_bh()`调用来暂停本地处理器上的 softirq 处理。待处理的 softirq 处理程序在重新启用 softirq 处理的任意任务的上下文中执行，通过调用`local_bh_enable()`或`spin_unlock_bh()`来重新启用 softirq 处理。最后，softirq 处理程序也可以由每个 CPU 内核线程`ksoftirqd`执行，当任何进程上下文内核例程引发 softirq 时，它会被唤醒。当由于负载过高而积累了太多的 softirq 时，该线程也会从中断上下文中被唤醒。

Softirqs 最适合用于完成从硬中断处理程序推迟的优先级工作，因为它们在硬中断处理程序完成后立即运行。但是，softirq 处理程序是可重入的，并且必须编程以在访问数据结构时使用适当的保护机制。softirq 的可重入性可能导致无界延迟，影响整个系统的效率，这就是为什么它们的使用受到限制，几乎不会添加新的 softirq，除非绝对需要执行高频率的线程推迟工作。对于所有其他类型的推迟工作，建议使用任务队列。

# 任务队列

**任务队列**机制是对 softirq 框架的一种包装；事实上，任务队列处理程序是由 softirq 执行的。与 softirq 不同，任务队列不是可重入的，这保证了相同的任务队列处理程序永远不会并发运行。这有助于最小化总体延迟，前提是程序员检查并施加相关检查，以确保任务队列中的工作是非阻塞和原子的。另一个区别是在使用方面：与受限的 softirq 不同，任何内核代码都可以使用任务队列，包括动态链接的服务。

每个任务队列通过在内核头文件`<linux/interrupt.h>`中声明的`struct tasklet_struct`类型的实例表示：

```
struct tasklet_struct
{
        struct tasklet_struct *next;
        unsigned long state;
        atomic_t count;
        void (*func)(unsigned long);
        unsigned long data;
};
```

在初始化时，`*func`保存处理程序例程的地址，`data`用于在调用期间将数据块作为参数传递给处理程序例程。每个任务队列都携带一个`state`，可以是`TASKLET_STATE_SCHED`，表示已安排执行，也可以是`TASKLET_STATE_RUN`，表示正在执行。使用原子计数器来*启用*或*禁用*任务队列；当`count`等于*非零*值*时，表示任务队列*已禁用*，*零*表示任务队列*已启用*。禁用的任务队列即使已排队，也不能执行，直到将来某个时间启用。

内核服务可以通过以下任何宏之一静态实例化新的任务队列：

```
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
```

新的任务队列可以通过以下方式在运行时动态实例化：

```
void tasklet_init(struct tasklet_struct *t,
                  void (*func)(unsigned long), unsigned long data)
{
        t->next = NULL;
        t->state = 0;
        atomic_set(&t->count, 0);
        t->func = func;
        t->data = data;
}
```

内核为排队的任务队列维护了两个每 CPU 任务队列列表，这些列表的定义可以在源文件`<kernel/softirq.c>`中找到：

```
/*
 * Tasklets
 */
struct tasklet_head {
        struct tasklet_struct *head;
        struct tasklet_struct **tail;
};

static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);

```

`tasklet_vec`被认为是正常列表，此列表中的所有排队的任务队列都由`TASKLET_SOFTIRQ`（10 个 softirq 之一）运行。`tasklet_hi_vec`是一个高优先级的任务队列列表，此列表中的所有排队的任务队列都由`HI_SOFTIRQ`执行，这恰好是最高优先级的 softirq。可以通过调用`tasklet_schedule()`或`tasklet_hi_scheudule()`将任务队列排队到适当的列表中执行。

以下代码显示了`tasklet_schedule()`的实现；此函数通过要排队的任务队列实例的地址作为参数调用：

```
extern void __tasklet_schedule(struct tasklet_struct *t);

static inline void tasklet_schedule(struct tasklet_struct *t)
{
        if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
                __tasklet_schedule(t);
}
```

条件构造检查指定的任务队列是否已经排队；如果没有，它会原子地将状态设置为`TASKLET_STATE_SCHED`，并调用`__tasklet_shedule()`将任务队列实例排队到待处理列表中。如果发现指定的任务队列已经处于`TASKLET_STATE_SCHED`状态，则不会重新调度：

```
void __tasklet_schedule(struct tasklet_struct *t)
{
        unsigned long flags;

        local_irq_save(flags);
        t->next = NULL;
 *__this_cpu_read(tasklet_vec.tail) = t;
 __this_cpu_write(tasklet_vec.tail, &(t->next));
        raise_softirq_irqoff(TASKLET_SOFTIRQ);
        local_irq_restore(flags);
}
```

此函数将指定的任务队列静默排队到`tasklet_vec`的尾部，并在本地处理器上引发`TASKLET_SOFTIRQ`。

下面是`tasklet_hi_scheudle()`例程的代码：

```
extern void __tasklet_hi_schedule(struct tasklet_struct *t);

static inline void tasklet_hi_schedule(struct tasklet_struct *t)
{
        if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
                __tasklet_hi_schedule(t);
}
```

此例程中执行的操作与`tasklet_schedule()`类似，唯一的例外是它调用`__tasklet_hi_scheudle()`将指定的任务队列排队到`tasklet_hi_vec`的尾部：

```
void __tasklet_hi_schedule(struct tasklet_struct *t)
{
        unsigned long flags;

        local_irq_save(flags);
        t->next = NULL;
 *__this_cpu_read(tasklet_hi_vec.tail) = t;
 __this_cpu_write(tasklet_hi_vec.tail, &(t->next));
 raise_softirq_irqoff(HI_SOFTIRQ);
        local_irq_restore(flags);
}
```

此调用在本地处理器上引发`HI_SOFTIRQ`，这将把`tasklet_hi_vec`中排队的所有任务队列转换为最高优先级的底部半部（优先级高于其他 softirq）。

另一个变体是`tasklet_hi_schedule_first()`，它将指定的 tasklet 插入到`tasklet_hi_vec`的开头，并提高`HI_SOFTIRQ`：

```
extern void __tasklet_hi_schedule_first(struct tasklet_struct *t);

 */
static inline void tasklet_hi_schedule_first(struct tasklet_struct *t)
{
        if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
                __tasklet_hi_schedule_first(t);
}

/*kernel/softirq.c */
void __tasklet_hi_schedule_first(struct tasklet_struct *t)
{
        BUG_ON(!irqs_disabled());
        t->next = __this_cpu_read(tasklet_hi_vec.head);
 __this_cpu_write(tasklet_hi_vec.head, t);
        __raise_softirq_irqoff(HI_SOFTIRQ);
}

```

还存在其他接口例程，用于启用、禁用和终止已调度的 tasklet。

```
void tasklet_disable(struct tasklet_struct *t);
```

此函数通过增加其*禁用计数*来禁用指定的 tasklet。tasklet 仍然可以被调度，但直到再次启用它之前不会被执行。如果在调用此函数时 tasklet 当前正在运行，则此函数会忙等待直到 tasklet 完成。

```
void tasklet_enable(struct tasklet_struct *t);
```

此函数尝试通过递减其*禁用计数*来启用先前已禁用的 tasklet。如果 tasklet 已经被调度，它将很快运行：

```
void tasklet_kill(struct tasklet_struct *t);
```

此函数用于终止给定的 tasklet，以确保它不能再次被调度运行。如果在调用此函数时指定的 tasklet 已经被调度，则此函数会等待其执行完成：

```
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu);
```

此函数用于终止已经调度的 tasklet。即使 tasklet 处于`TASKLET_STATE_SCHED`状态，它也会立即从列表中删除指定的 tasklet。

# 工作队列

**工作队列**（**wqs**）是用于执行异步进程上下文例程的机制。正如名称所暗示的那样，工作队列（wq）是一个*work*项目的列表，每个项目包含一个函数指针，该指针指向要异步执行的例程的地址。每当一些内核代码（属于子系统或服务）打算将一些工作推迟到异步进程上下文执行时，它必须使用处理程序函数的地址初始化*work*项目，并将其排队到工作队列中。内核使用专用的内核线程池，称为*kworker*线程，按顺序执行队列中每个*work*项目绑定的函数。

# 接口 API

工作队列 API 提供了两种类型的函数接口：首先，一组接口例程用于实例化和排队*work*项目到全局工作队列，该队列由所有内核子系统和服务共享；其次，一组接口例程用于设置新的工作队列，并将工作项目排队到其中。我们将开始探索与全局共享工作队列相关的宏和函数的工作队列接口。

队列中的每个*work*项目由类型为`struct work_struct`的实例表示，该类型在内核头文件`<linux/workqueue.h>`中声明：

```
struct work_struct {
        atomic_long_t data;
        struct list_head entry;
        work_func_t func;
#ifdef CONFIG_LOCKDEP
        struct lockdep_map lockdep_map;
#endif
};
```

`func`是一个指针，指向延迟例程的地址；可以通过宏`DECLARE_WORK`创建并初始化一个新的 struct work 对象：

```
#define DECLARE_WORK(n, f) \
 struct work_struct n = __WORK_INITIALIZER(n, f)
```

`n`是要创建的实例的名称，`f`是要分配的函数的地址。可以通过`schedule_work()`将工作实例排队到工作队列中：

```
bool schedule_work(struct work_struct *work);
```

此函数将给定的*work*项目排队到本地 CPU 工作队列，但不能保证其在其中执行。如果成功排队给定的*work*，则返回*true*，如果给定的*work*已经在工作队列中，则返回*false*。一旦排队，与*work*项目相关联的函数将由相关的`kworker`线程在任何可用的 CPU 上执行。或者，可以将*work*项目标记为在特定 CPU 上执行，同时将其调度到队列中（这可能会产生更好的缓存利用）；可以通过调用`schedule_work_on()`来实现：

```
bool schedule_work_on(int cpu, struct work_struct *work);
```

`cpu`是要绑定到的*work*任务的标识符。例如，要将*work*任务调度到本地 CPU，调用者可以调用：

```
schedule_work_on(smp_processor_id(), &t_work);
```

`smp_processor_id()`是一个内核宏（在`<linux/smp.h>`中定义），它返回本地 CPU 标识符。

接口 API 还提供了调度调用的变体，允许调用者排队*work*任务，其执行保证至少延迟到指定的超时。这是通过将*work*任务与定时器绑定来实现的，可以使用到期超时初始化定时器，直到*work*任务被调度到队列中为止：

```
struct delayed_work {
        struct work_struct work;
        struct timer_list timer;

        /* target workqueue and CPU ->timer uses to queue ->work */
        struct workqueue_struct *wq;
        int cpu;
};
```

`timer`是动态定时器描述符的一个实例，它在安排*工作*任务时初始化了到期间隔并启动。我们将在下一章更详细地讨论内核定时器和其他与时间相关的概念。

调用者可以通过宏实例化`delayed_work`并静态初始化它：

```
#define DECLARE_DELAYED_WORK(n, f) \
        struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, 0)
```

与普通*工作*任务类似，延迟*工作*任务可以安排在任何可用的 CPU 上运行，或者安排在指定的核心上执行。要安排可以在任何可用处理器上运行的延迟*工作*，调用者可以调用`schedule_delayed_work()`，要安排延迟*工作*到特定 CPU 上，使用函数`schedule_delayed_work_on()`：

```
bool schedule_delayed_work(struct delayed_work *dwork,unsigned long delay);
bool schedule_delayed_work_on(int cpu, struct delayed_work *dwork,
                                                       unsigned long delay);
```

请注意，如果延迟为零，则指定的*工作*项将安排立即执行。

# 创建专用工作队列

全局工作队列上安排的*工作*项的执行时间是不可预测的：一个长时间运行的*工作*项总是会导致其他*工作*项的无限延迟。或者，工作队列框架允许分配专用工作队列，这些队列可以由内核子系统或服务拥有。用于创建和安排工作到这些队列中的接口 API 提供了控制标志，通过这些标志，所有者可以设置特殊属性，如 CPU 局部性、并发限制和优先级，这些属性会影响排队的工作项的执行。

可以通过调用`alloc_workqueue()`来设置新的工作队列；以下摘录取自`<fs/nfs/inode.c>`，显示了示例用法：

```
   struct workqueue_struct *wq;
   ...
   wq = alloc_workqueue("nfsiod", WQ_MEM_RECLAIM, 0);
```

这个调用需要三个参数：第一个是一个字符串常量，用于“命名”工作队列。第二个参数是`flags`的位字段，第三个是称为`max_active`的整数。最后两个参数用于指定队列的控制属性。成功时，此函数返回工作队列描述符的地址。

以下是标志选项列表：

+   `WQ_UNBOUND`：使用此标志创建的工作队列由未绑定到任何特定 CPU 的 kworker 池管理。这会导致安排到此队列的所有*工作*项在任何可用处理器上运行。此队列中的*工作*项将尽快由 kworker 池执行。

+   `WQ_FREEZABLE`：此类型的工作队列是可冻结的，这意味着它会受到系统挂起操作的影响。在挂起期间，所有当前的*工作*项都会被清空，并且直到系统解冻或恢复之前，不会有新的*工作*项可以运行。

+   `WQ_MEM_RECLAIM`：此标志用于标记包含在内存回收路径中的*工作*项的工作队列。这会导致框架确保始终有一个*工作*线程可用于在此队列上运行*工作*项。

+   `WQ_HIGHPRI`：此标志用于将工作队列标记为高优先级。高优先级工作队列中的工作项优先级高于普通工作项，这些工作项由高优先级的*kworker*线程池执行。内核为每个 CPU 维护了一个专用的高优先级 kworker 线程池，这些线程池与普通的 kworker 池不同。

+   `WQ_CPU_INTENSIVE`：此标志标记此工作队列上的工作项为 CPU 密集型。这有助于系统调度程序调节预计会长时间占用 CPU 的*工作*项的执行。这意味着可运行的 CPU 密集型*工作*项不会阻止同一 kworker 池中的其他工作项的启动。可运行的非 CPU 密集型*工作*项始终可以延迟执行标记为 CPU 密集型的*工作*项。对于未绑定的 wq，此标志毫无意义。

+   `WQ_POWER_EFFICIENT`：标记了此标志的工作队列默认情况下是每 CPU 的，但如果系统是使用`workqueue.power_efficient`内核参数启动的，则变为未绑定。已确定对功耗有显着贡献的每 CPU 工作队列将被识别并标记为此标志，并且启用 power_efficient 模式会导致明显的功耗节约，但会略微降低性能。

最终参数`max_active`是一个整数，必须指定在任何给定 CPU 上可以同时执行的*工作*项的数量。

一旦建立了专用工作队列，*工作*项可以通过以下任一调用进行调度：

```
bool queue_work(struct workqueue_struct *wq, struct work_struct *work);
```

`wq`是一个指向队列的指针；它会将指定的*工作*项排入本地 CPU，但不能保证在本地处理器上执行。如果成功排队，则此调用返回*true*，如果已安排给定的工作项，则返回*false*。

或者，调用者可以通过调用以下方式将工作项排入与特定 CPU 绑定的工作项队列：

```
bool queue_work_on(int cpu,struct workqueue_struct *wq,struct work_struct
                                                                 *work);                                         
```

一旦将工作项排入指定`cpu`的工作队列中，如果成功排队，则返回*true*，如果已在队列中找到给定的工作项，则返回*false*。

与共享工作队列 API 类似，专用工作队列也提供了延迟调度选项。以下调用用于延迟调度*工作*项：

```
bool queue_delayed_work_on(int cpu, struct workqueue_struct *wq, struct                                                                                                                                                        delayed_work *dwork,unsigned long delay);

bool queue_delayed_work(struct workqueue_struct *wq, struct delayed_work                             *dwork, unsigned long delay
```

这两个调用都会延迟给定工作项的调度，直到`delay`指定的超时时间已经过去，但`queue_delayed_work_on()`除外，它会将给定的*工作*项排入指定的 CPU，并保证在该 CPU 上执行。请注意，如果指定的延迟为零且工作队列为空闲，则给定的*工作*项将被安排立即执行。

# 总结

通过本章，我们已经接触到了中断，构建整个基础设施的各种组件，以及内核如何有效地管理它。我们了解了内核如何利用抽象来平稳处理来自各种控制器的各种中断信号。内核通过高级中断管理接口再次突出了简化复杂编程方法的努力。我们还深入了解了中断子系统的所有关键例程和重要数据结构。我们还探讨了内核处理延迟工作的机制。

在下一章中，我们将探索内核的时间管理子系统，以了解诸如时间测量、间隔定时器和超时和延迟例程等关键概念。


# 第十章：时钟和时间管理

Linux 时间管理子系统管理各种与时间相关的活动，并跟踪时间数据，如当前时间和日期、自系统启动以来经过的时间（系统正常运行时间）和超时，例如，等待特定事件启动或终止的时间、在超时后锁定系统，或引发信号以终止无响应的进程。

Linux 时间管理子系统处理两种类型的定时活动：

+   跟踪当前时间和日期

+   维护定时器

# 时间表示

根据使用情况，Linux 以三种不同的方式表示时间：

1.  **墙上时间（或实时时间）：**这是真实世界中的实际时间和日期，例如 2017 年 8 月 10 日上午 07:00，用于文件和通过网络发送的数据包的时间戳。

1.  **进程时间：**这是进程在其生命周期中消耗的时间。它包括进程在用户模式下消耗的时间以及内核代码在代表进程执行时消耗的时间。这对于统计目的、审计和分析很有用。

1.  **单调时间：**这是自系统启动以来经过的时间。它是不断增加且单调的（系统正常运行时间）。

这三种时间可以用以下任一方式来衡量：

1.  **相对时间：**这是相对于某个特定事件的时间，例如自系统启动以来的 7 分钟，或自用户上次输入以来的 2 分钟。

1.  **绝对时间：**这是没有任何参考先前事件的唯一时间点，例如 2017 年 8 月 12 日上午 10:00。在 Linux 中，绝对时间表示为自 1970 年 1 月 1 日午夜 00:00:00（UTC）以来经过的秒数。

墙上的时间是不断增加的（除非用户修改了它），即使在重新启动和关机之间，但进程时间和系统正常运行时间始于某个预定义的时间点（*通常为零*），每次创建新进程或系统启动时。

# 计时硬件

Linux 依赖于适当的硬件设备来维护时间。这些硬件设备可以大致分为两类：系统时钟和定时器。

# 实时时钟（RTC）

跟踪当前时间和日期非常重要，不仅是为了让用户了解时间，还可以将其用作系统中各种资源的时间戳，特别是存储在辅助存储器中的文件。每个文件都有元数据信息，如创建日期和最后修改日期，每当创建或修改文件时，这两个字段都会使用系统中的当前时间进行更新。这些字段被多个应用程序用于管理文件，例如排序、分组，甚至删除（如果文件长时间未被访问）。*make*工具使用此时间戳来确定自上次访问以来源文件是否已被编辑；只有在这种情况下才会对其进行编译，否则保持不变。

系统时钟 RTC 跟踪当前时间和日期；由额外的电池支持，即使系统关闭，它也会继续运行。

RTC 可以定期在 IRQ8 上引发中断。通过编程 RTC 在达到特定时间时在 IRQ8 上引发中断，可以将此功能用作警报设施。在兼容 IBM 的个人电脑中，RTC 被映射到 0x70 和 0x71 I/O 端口。可以通过`/dev/rtc`设备文件访问它。

# 时间戳计数器（TSC）

这是通过 64 位寄存器 TSC 实现的计数器，每个 x86 微处理器都有，该寄存器称为 TSC 寄存器。它计算处理器的 CLK 引脚上到达的时钟信号数量。可以通过访问 TSC 寄存器来读取当前计数器值。每秒计数的时钟信号数可以计算为 1/(时钟频率)；对于 1 GHz 时钟，这相当于每纳秒一次。

知道两个连续 tick 之间的持续时间非常关键。一个处理器时钟的频率可能与其他处理器不同，这使得它在处理器之间变化。CPU 时钟频率是在系统引导期间通过`calibrate_tsc()`回调例程计算的，该例程定义在`arch/x86/include/asm/x86_init.h`头文件中的`x86_platform_ops`结构中：

```
struct x86_platform_ops {
        unsigned long (*calibrate_cpu)(void);
        unsigned long (*calibrate_tsc)(void);
        void (*get_wallclock)(struct timespec *ts);
        int (*set_wallclock)(const struct timespec *ts);
        void (*iommu_shutdown)(void);
        bool (*is_untracked_pat_range)(u64 start, u64 end);
        void (*nmi_init)(void);
        unsigned char (*get_nmi_reason)(void);
        void (*save_sched_clock_state)(void);
        void (*restore_sched_clock_state)(void);
        void (*apic_post_init)(void);
        struct x86_legacy_features legacy;
        void (*set_legacy_features)(void);
};
```

这个数据结构还管理其他计时操作，比如通过`get_wallclock()`从 RTC 获取时间或通过`set_wallclock()`回调在 RTC 上设置时间。

# 可编程中断定时器（PIT）

内核需要定期执行某些任务，比如：

+   更新当前时间和日期（在午夜）

+   更新系统运行时间（正常运行时间）

+   跟踪每个进程消耗的时间，以便它们不超过分配给 CPU 运行的时间

+   跟踪各种计时器活动

为了执行这些任务，必须定期引发中断。每次引发这种周期性中断时，内核都知道是时候更新前面提到的时间数据了。PIT 是负责发出这种周期性中断的硬件部件，称为定时器中断。PIT 会以大约 1000 赫兹的频率在 IRQ0 上定期发出定时器中断，即每毫秒一次。这种周期性中断称为**tick**，发出的频率称为**tick rate**。tick rate 频率由内核宏**HZ**定义，以赫兹为单位。

系统响应性取决于 tick rate：tick 越短，系统的响应性就越高，反之亦然。使用较短的 tick，`poll()`和`select()`系统调用将具有更快的响应时间。然而，较短的 tick rate 的相当大缺点是 CPU 将在内核模式下工作（执行定时器中断的中断处理程序）大部分时间，留下较少的时间供用户模式代码（程序）在其上执行。在高性能 CPU 中，这不会产生太多开销，但在较慢的 CPU 中，整体系统性能会受到相当大的影响。

为了在响应时间和系统性能之间取得平衡，在大多数机器上使用了 100 赫兹的 tick rate。除了*Alpha*和*m68knommu*使用 1000 赫兹的 tick rate 外，其余常见架构，包括*x86*（arm、powerpc、sparc、mips 等），使用了 100 赫兹的 tick rate。在*x86*机器中找到的常见 PIT 硬件是 Intel 8253。它是 I/O 映射的，并通过地址 0x40-0x43 进行访问。PIT 由`setup_pit_timer()`初始化，定义在`arch/x86/kernel/i8253.c`文件中。

```
void __init setup_pit_timer(void)
{
        clockevent_i8253_init(true);
        global_clock_event = &i8253_clockevent;
}
```

这在内部调用`clockevent_i8253_init()`，定义在`<drivers/clocksource/i8253.c>`中：

```
void __init clockevent_i8253_init(bool oneshot)
{
        if (oneshot)
                i8253_clockevent.features |= CLOCK_EVT_FEAT_ONESHOT;
        /*
        * Start pit with the boot cpu mask. x86 might make it global
        * when it is used as broadcast device later.
        */
        i8253_clockevent.cpumask = cpumask_of(smp_processor_id());

        clockevents_config_and_register(&i8253_clockevent, PIT_TICK_RATE,
                                        0xF, 0x7FFF);
}
#endif
```

# CPU 本地定时器

PIT 是一个全局定时器，由它引发的中断可以由 SMP 系统中的任何 CPU 处理。在某些情况下，拥有这样一个共同的定时器是有益的，而在其他情况下，每 CPU 定时器更可取。在 SMP 系统中，保持进程时间并监视每个 CPU 中进程的分配时间片将更加容易和高效。

最近的 x86 微处理器中的本地 APIC 嵌入了这样一个 CPU 本地定时器。CPU 本地定时器可以发出一次或定期中断。它使用 32 位计时器，可以以非常低的频率发出中断（这个更宽的计数器允许更多的 tick 发生在引发中断之前）。APIC 定时器与总线时钟信号一起工作。APIC 定时器与 PIT 非常相似，只是它是本地 CPU 的，有一个 32 位计数器（PIT 有一个 16 位计数器），并且与总线时钟信号一起工作（PIT 使用自己的时钟信号）。

# 高精度事件定时器（HPET）

HPET 使用超过 10 Mhz 的时钟信号，每 100 纳秒发出一次中断，因此被称为高精度。HPET 实现了一个 64 位的主计数器，以如此高的频率进行计数。它是由英特尔和微软共同开发的，用于需要新的高分辨率计时器。HPET 嵌入了一组定时器。每个定时器都能够独立发出中断，并可以由内核分配给特定应用程序使用。这些定时器被管理为定时器组，每个组最多可以有 32 个定时器。一个 HPET 最多可以实现 8 个这样的组。每个定时器都有一组*比较器*和*匹配寄存器*。当定时器的匹配寄存器中的值与主计数器的值匹配时，定时器会发出中断。定时器可以被编程为定期或周期性地生成中断。

寄存器是内存映射的，并具有可重定位的地址空间。在系统引导期间，BIOS 设置寄存器的地址空间并将其传递给内核。一旦 BIOS 映射了地址，内核就很少重新映射它。

# ACPI 电源管理计时器（ACPI PMT）

ACPI PMT 是一个简单的计数器，具有固定频率时钟，为 3.58 Mhz。它在每个时钟脉冲上递增。PMT 是端口映射的；BIOS 在引导期间的硬件初始化阶段负责地址映射。PMT 比 TSC 更可靠，因为它使用恒定的时钟频率。TSC 依赖于 CPU 时钟，根据当前负载可以被降频或超频，导致时间膨胀和不准确的测量。在所有情况下，HPET 是首选，因为它允许系统中存在非常短的时间间隔。

# 硬件抽象

每个系统至少有一个时钟计数器。与机器中的任何硬件设备一样，这个计数器也由一个结构表示和管理。硬件抽象由`include/linux/clocksource.h`头文件中定义的`struct clocksource`提供。该结构提供了回调函数来通过`read`、`enable`、`disable`、`suspend`和`resume`例程访问和处理计数器的电源管理：

```
struct clocksource {
        u64 (*read)(struct clocksource *cs);
        u64 mask;
        u32 mult;
        u32 shift;
        u64 max_idle_ns;
        u32 maxadj;
#ifdef CONFIG_ARCH_CLOCKSOURCE_DATA
        struct arch_clocksource_data archdata;
#endif
        u64 max_cycles;
        const char *name;
        struct list_head list;
        int rating;
        int (*enable)(struct clocksource *cs);
        void (*disable)(struct clocksource *cs);
        unsigned long flags;
        void (*suspend)(struct clocksource *cs);
        void (*resume)(struct clocksource *cs);
        void (*mark_unstable)(struct clocksource *cs);
        void (*tick_stable)(struct clocksource *cs);

        /* private: */
#ifdef CONFIG_CLOCKSOURCE_WATCHDOG
        /* Watchdog related data, used by the framework */
        struct list_head wd_list;
        u64 cs_last;
        u64 wd_last;
#endif
        struct module *owner;
};
```

成员`mult`和`shift`对于获取相关单位的经过时间非常有用。

# 计算经过的时间

到目前为止，我们知道在每个系统中都有一个自由运行的、不断递增的计数器，并且所有时间都是从中派生的，无论是墙上的时间还是任何持续时间。在这里计算时间（自计数器启动以来经过的秒数）的最自然的想法是将这个计数器提供的周期数除以时钟频率，如下式所示：

时间（秒）=（计数器值）/（时钟频率）

然而，这种方法有一个问题：它涉及除法（它使用迭代算法，使其成为四种基本算术运算中最慢的）和浮点计算，在某些体系结构上可能会更慢。在处理嵌入式平台时，浮点计算显然比在个人电脑或服务器平台上慢。

那么我们如何解决这个问题呢？与其使用除法，不如使用乘法和位移操作来计算时间。内核提供了一个辅助例程，以这种方式推导时间。`include/linux/clocksource.h`中定义的`clocksource_cyc2ns()`将时钟源周期转换为纳秒：

```
static inline s64 clocksource_cyc2ns(u64 cycles, u32 mult, u32 shift)
{
        return ((u64) cycles * mult) >> shift;
}
```

在这里，参数 cycles 是来自时钟源的经过的周期数，`mult`是周期到纳秒的乘数，而`shift`是周期到纳秒的除数（2 的幂）。这两个参数都是时钟源相关的。这些值是由之前讨论的时钟源内核抽象提供的。

时钟源硬件并非始终准确；它们的频率可能会变化。这种时钟变化会导致时间漂移（使时钟运行得更快或更慢）。在这种情况下，可以调整变量*mult*来弥补这种时间漂移。

在`kernel/time/clocksource.c`中定义的辅助例程`clocks_calc_mult_shift()`有助于评估`mult`和`shift`因子：

```
void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
        u64 tmp;
        u32 sft, sftacc= 32;

        /*
        * Calculate the shift factor which is limiting the conversion
        * range:
        */
        tmp = ((u64)maxsec * from) >> 32;
        while (tmp) {
                tmp >>=1;
                sftacc--;
        }

        /*
        * Find the conversion shift/mult pair which has the best
        * accuracy and fits the maxsec conversion range:
        */
        for (sft = 32; sft > 0; sft--) {
                tmp = (u64) to << sft;
                tmp += from / 2;
                do_div(tmp, from);
                if ((tmp >> sftacc) == 0)
                        break;
        }
        *mult = tmp;
        *shift = sft;
}
```

两个事件之间的时间持续时间可以通过以下代码片段计算：

```
struct clocksource *cs = &curr_clocksource;
cycle_t start = cs->read(cs);
/* things to do */
cycle_t end = cs->read(cs);
cycle_t diff = end – start;
duration =  clocksource_cyc2ns(diff, cs->mult, cs->shift);
```

# Linux 时间保持数据结构、宏和辅助例程

现在我们将通过查看一些关键的时间保持结构、宏和辅助例程来扩大我们的认识，这些可以帮助程序员提取特定的与时间相关的数据。

# Jiffies

`jiffies`变量保存自系统启动以来经过的滴答数。每次发生滴答时，`jiffies`增加一。它是一个 32 位变量，这意味着对于 100 Hz 的滴答率，大约在 497 天后（对于 1000 Hz 的滴答率，在 49 天 17 小时后）会发生溢出。

为了解决这个问题，使用了 64 位变量`jiffies_64`，它允许在溢出发生之前经过数千万年。`jiffies`变量等于`jiffies_64`的 32 位最低有效位。之所以同时拥有`jiffies`和`jiffies_64`变量，是因为在 32 位机器中，无法原子地访问 64 位变量；在处理这两个 32 位半部分时需要一些同步，以避免在处理这两个 32 位半部分时发生任何计数器更新。在`/kernel/time/jiffies.c`源文件中定义的函数`get_jiffies_64()`返回`jiffies`的当前值：

```
u64 get_jiffies_64(void)
{
        unsigned long seq;
        u64 ret;

        do {
                seq = read_seqbegin(&jiffies_lock);
                ret = jiffies_64;
        } while (read_seqretry(&jiffies_lock, seq));
        return ret;
}
```

在处理`jiffies`时，必须考虑可能发生的回绕，因为在比较两个时间事件时会导致不可预测的结果。有四个宏在`include/linux/jiffies.h`中定义，用于此目的：

```
#define time_after(a,b)           \
       (typecheck(unsigned long, a) && \
        typecheck(unsigned long, b) && \
        ((long)((b) - (a)) < 0))
#define time_before(a,b)       time_after(b,a)

#define time_after_eq(a,b)     \
       (typecheck(unsigned long, a) && \
        typecheck(unsigned long, b) && \
        ((long)((a) - (b)) >= 0))
#define time_before_eq(a,b)    time_after_eq(b,a)
```

所有这些宏都返回布尔值；参数**a**和**b**是要比较的时间事件。如果 a 恰好是 b 之后的时间，`time_after()`返回 true，否则返回 false。相反，如果 a 恰好在 b 之前，`time_before()`返回 true，否则返回 false。`time_after_eq()`和`time_before_eq()`如果 a 和 b 都相等，则返回 true。可以使用`kernel/time/time.c`中定义的例程`jiffies_to_msecs()`、`jiffies_to_usecs()`将 jiffies 转换为其他时间单位，如毫秒、微秒和纳秒，以及`include/linux/jiffies.h`中的`jiffies_to_nsecs()`：

```
unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
# if BITS_PER_LONG == 32
        return (HZ_TO_MSEC_MUL32 * j) >> HZ_TO_MSEC_SHR32;
# else
        return (j * HZ_TO_MSEC_NUM) / HZ_TO_MSEC_DEN;
# endif
#endif
}

unsigned int jiffies_to_usecs(const unsigned long j)
{
        /*
        * Hz doesn't go much further MSEC_PER_SEC.
        * jiffies_to_usecs() and usecs_to_jiffies() depend on that.
        */
        BUILD_BUG_ON(HZ > USEC_PER_SEC);

#if !(USEC_PER_SEC % HZ)
        return (USEC_PER_SEC / HZ) * j;
#else
# if BITS_PER_LONG == 32
        return (HZ_TO_USEC_MUL32 * j) >> HZ_TO_USEC_SHR32;
# else
        return (j * HZ_TO_USEC_NUM) / HZ_TO_USEC_DEN;
# endif
#endif
}

static inline u64 jiffies_to_nsecs(const unsigned long j)
{
        return (u64)jiffies_to_usecs(j) * NSEC_PER_USEC;
}
```

其他转换例程可以在`include/linux/jiffies.h`文件中探索。

# Timeval 和 timespec

在 Linux 中，当前时间是通过保持自 1970 年 1 月 1 日午夜以来经过的秒数（称为纪元）来维护的；这些中的每个第二个元素分别表示自上次秒数以来经过的时间，以微秒和纳秒为单位：

```
struct timespec {
        __kernel_time_t  tv_sec;                   /* seconds */
        long            tv_nsec;          /* nanoseconds */
};
#endif

struct timeval {
        __kernel_time_t          tv_sec;           /* seconds */
        __kernel_suseconds_t     tv_usec;  /* microseconds */
};
```

从时钟源读取的时间（计数器值）需要在某个地方累积和跟踪；`include/linux/timekeeper_internal.h`中定义的`struct tk_read_base`结构用于此目的：

```
struct tk_read_base {
        struct clocksource        *clock;
        cycle_t                  (*read)(struct clocksource *cs);
        cycle_t                  mask;
        cycle_t                  cycle_last;
        u32                      mult;
        u32                      shift;
        u64                      xtime_nsec;
        ktime_t                  base_mono;
};
```

`include/linux/timekeeper_internal.h`中定义的`struct timekeeper`结构保持各种时间保持值。它是用于维护和操作不同时间线的时间保持数据的主要数据结构，如单调和原始：

```
struct timekeeper {
        struct tk_read_base       tkr;
        u64                      xtime_sec;
        unsigned long           ktime_sec;
        struct timespec64 wall_to_monotonic;
        ktime_t                  offs_real;
        ktime_t                  offs_boot;
        ktime_t                  offs_tai;
        s32                      tai_offset;
        ktime_t                  base_raw;
        struct timespec64 raw_time;

        /* The following members are for timekeeping internal use */
        cycle_t                  cycle_interval;
        u64                      xtime_interval;
        s64                      xtime_remainder;
        u32                      raw_interval;
        u64                      ntp_tick;
        /* Difference between accumulated time and NTP time in ntp
        * shifted nano seconds. */
        s64                      ntp_error;
        u32                      ntp_error_shift;
        u32                      ntp_err_mult;
};
```

# 跟踪和维护时间

时间保持辅助例程`timekeeping_get_ns()`和`timekeeping_get_ns()`有助于获取通用时间和地球时间之间的校正因子（Δt），单位为纳秒：

```
static inline u64 timekeeping_delta_to_ns(struct tk_read_base *tkr, u64 delta)
{
        u64 nsec;

        nsec = delta * tkr->mult + tkr->xtime_nsec;
        nsec >>= tkr->shift;

        /* If arch requires, add in get_arch_timeoffset() */
        return nsec + arch_gettimeoffset();
}

static inline u64 timekeeping_get_ns(struct tk_read_base *tkr)
{
        u64 delta;

        delta = timekeeping_get_delta(tkr);
        return timekeeping_delta_to_ns(tkr, delta);
}
```

例程`logarithmic_accumulation()`更新 mono、raw 和 xtime 时间线；它将周期的移位间隔累积到纳秒的移位间隔中。例程`accumulate_nsecs_to_secs()`将`struct tk_read_base`的`xtime_nsec`字段中的纳秒累积到`struct timekeeper`的`xtime_sec`中。这些例程有助于跟踪系统中的当前时间，并在`kernel/time/timekeeping.c`中定义：

```
static u64 logarithmic_accumulation(struct timekeeper *tk, u64 offset,
                                    u32 shift, unsigned int *clock_set)
{
        u64 interval = tk->cycle_interval << shift;
        u64 snsec_per_sec;

        /* If the offset is smaller than a shifted interval, do nothing */
        if (offset < interval)
                return offset;

        /* Accumulate one shifted interval */
        offset -= interval;
        tk->tkr_mono.cycle_last += interval;
        tk->tkr_raw.cycle_last  += interval;

        tk->tkr_mono.xtime_nsec += tk->xtime_interval << shift;
        *clock_set |= accumulate_nsecs_to_secs(tk);

        /* Accumulate raw time */
        tk->tkr_raw.xtime_nsec += (u64)tk->raw_time.tv_nsec << tk->tkr_raw.shift;
        tk->tkr_raw.xtime_nsec += tk->raw_interval << shift;
        snsec_per_sec = (u64)NSEC_PER_SEC << tk->tkr_raw.shift;
        while (tk->tkr_raw.xtime_nsec >= snsec_per_sec) {
                tk->tkr_raw.xtime_nsec -= snsec_per_sec;
                tk->raw_time.tv_sec++;
        }
        tk->raw_time.tv_nsec = tk->tkr_raw.xtime_nsec >> tk->tkr_raw.shift;
        tk->tkr_raw.xtime_nsec -= (u64)tk->raw_time.tv_nsec << tk->tkr_raw.shift;

        /* Accumulate error between NTP and clock interval */
        tk->ntp_error += tk->ntp_tick << shift;
        tk->ntp_error -= (tk->xtime_interval + tk->xtime_remainder) <<
                                                (tk->ntp_error_shift + shift);

        return offset;
}
```

另一个例程`update_wall_time()`，在`kernel/time/timekeeping.c`中定义，负责维护壁钟时间。它使用当前时钟源作为参考递增壁钟时间。

# 时钟中断处理

为了提供编程接口，生成滴答的时钟设备通过`include/linux/clockchips.h`中定义的`struct clock_event_device`结构进行抽象：

```
struct clock_event_device {
        void                    (*event_handler)(struct clock_event_device *);
        int                     (*set_next_event)(unsigned long evt, struct clock_event_device *);
        int                     (*set_next_ktime)(ktime_t expires, struct clock_event_device *);
        ktime_t                  next_event;
        u64                      max_delta_ns;
        u64                      min_delta_ns;
        u32                      mult;
        u32                      shift;
        enum clock_event_state    state_use_accessors;
        unsigned int            features;
        unsigned long           retries;

        int                     (*set_state_periodic)(struct  clock_event_device *);
        int                     (*set_state_oneshot)(struct clock_event_device *);
        int                     (*set_state_oneshot_stopped)(struct clock_event_device *);
        int                     (*set_state_shutdown)(struct clock_event_device *);
        int                     (*tick_resume)(struct clock_event_device *);

        void                    (*broadcast)(const struct cpumask *mask);
        void                    (*suspend)(struct clock_event_device *);
        void                    (*resume)(struct clock_event_device *);
        unsigned long           min_delta_ticks;
        unsigned long           max_delta_ticks;

        const char               *name;
        int                     rating;
        int                     irq;
        int                     bound_on;
        const struct cpumask       *cpumask;
        struct list_head  list;
        struct module             *owner;
} ____cacheline_aligned;
```

在这里，`event_handler`是由框架分配的适当例程，由低级处理程序调用以运行滴答。根据配置，这个`clock_event_device`可以是`periodic`、`one-shot`或`ktime`基础的。在这三种情况中，滴答设备的适当操作模式是通过`unsigned int features`字段设置的，使用这些宏之一：

```
#define CLOCK_EVT_FEAT_PERIODIC 0x000001
#define CLOCK_EVT_FEAT_ONESHOT 0x000002
#define CLOCK_EVT_FEAT_KTIME  0x000004
```

周期模式配置硬件每*1/HZ*秒生成一次滴答，而单次模式使硬件在当前时间后经过特定数量的周期生成滴答。

根据用例和操作模式，event_handler 可以是这三个例程中的任何一个：

+   `tick_handle_periodic()`是周期性滴答的默认处理程序，定义在`kernel/time/tick-common.c`中。

+   `tick_nohz_handler()`是低分辨率中断处理程序，在低分辨率模式下使用。它在`kernel/time/tick-sched.c`中定义。

+   `hrtimer_interrupt()`在高分辨率模式下使用，并在调用时禁用中断。

通过`clockevents_config_and_register()`例程配置和注册时钟事件设备，定义在`kernel/time/clockevents.c`中。

# 滴答设备

`clock_event_device`抽象是为了核心定时框架；我们需要一个单独的抽象来处理每个 CPU 的滴答设备；这是通过`struct tick_device`结构和`DEFINE_PER_CPU()`宏来实现的，分别在`kernel/time/tick-sched.h`和`include/linux/percpu-defs.h`中定义：

```
enum tick_device_mode {
 TICKDEV_MODE_PERIODIC,
 TICKDEV_MODE_ONESHOT,
};

struct tick_device {
        struct clock_event_device *evtdev;
        enum tick_device_mode mode;
}
```

`tick_device`可以是周期性的或单次的。它通过`enum tick_device_mode`设置。

# 软件定时器和延迟函数

软件定时器允许在时间到期时调用函数。有两种类型的定时器：内核使用的动态定时器和用户空间进程使用的间隔定时器。除了软件定时器，还有另一种常用的定时函数称为延迟函数。延迟函数实现一个精确的循环，根据延迟函数的参数执行（通常是多次）。

# 动态定时器

动态定时器可以随时创建和销毁，因此称为动态定时器。动态定时器由`struct timer_list`对象表示，定义在`include/linux/timer.h`中：

```
struct timer_list {
        /*
        * Every field that changes during normal runtime grouped to the
        * same cacheline
        */
        struct hlist_node entry;
        unsigned long           expires;
        void                    (*function)(unsigned long);
        unsigned long           data;
        u32                      flags;

#ifdef CONFIG_LOCKDEP
        struct lockdep_map        lockdep_map;
#endif
};
```

系统中的所有定时器都由一个双向链表管理，并按照它们的到期时间排序，由 expires 字段表示。expires 字段指定定时器到期后的时间。一旦当前的`jiffies`值匹配或超过此字段的值，定时器就会过期。通过 entry 字段，定时器被添加到此定时器链表中。函数字段指向在定时器到期时要调用的例程，数据字段保存要传递给函数的参数（如果需要）。expires 字段不断与`jiffies_64`值进行比较，以确定定时器是否已经过期。

动态定时器可以按以下方式创建和激活：

+   创建一个新的`timer_list`对象，比如说`t_obj`。

+   使用宏`init_timer(&t_obj)`初始化此定时器对象，定义在`include/linux/timer.h`中。

+   使用函数字段初始化函数的地址，以在定时器到期时调用该函数。如果函数需要参数，则也初始化数据字段。

+   如果定时器对象已经添加到定时器列表中，则通过调用函数`mod_timer(&t_obj, <timeout-value-in-jiffies>)`更新 expires 字段，定义在`kernel/time/timer.c`中。

+   如果没有，初始化 expires 字段，并使用`add_timer(&t_obj)`将定时器对象添加到定时器列表中，定义在`/kernel/time/timer.c`中。

内核会自动从定时器列表中删除已过期的定时器，但也有其他方法可以从列表中删除定时器。`kernel/time/timer.c`中定义的`del_timer()`和`del_timer_sync()`例程以及宏`del_singleshot_timer_sync()`可以帮助实现这一点：

```
int del_timer(struct timer_list *timer)
{
        struct tvec_base *base;
        unsigned long flags;
        int ret = 0;

        debug_assert_init(timer);

        timer_stats_timer_clear_start_info(timer);
        if (timer_pending(timer)) {
                base = lock_timer_base(timer, &flags);
                if (timer_pending(timer)) {
                        detach_timer(timer, 1);
                        if (timer->expires == base->next_timer &&
                            !tbase_get_deferrable(timer->base))
                                base->next_timer = base->timer_jiffies;
                        ret = 1;
                }
                spin_unlock_irqrestore(&base->lock, flags);
        }

        return ret;
}

int del_timer_sync(struct timer_list *timer)
{
#ifdef CONFIG_LOCKDEP
        unsigned long flags;

        /*
        * If lockdep gives a backtrace here, please reference
        * the synchronization rules above.
        */
        local_irq_save(flags);
        lock_map_acquire(&timer->lockdep_map);
        lock_map_release(&timer->lockdep_map);
        local_irq_restore(flags);
#endif
        /*
        * don't use it in hardirq context, because it
        * could lead to deadlock.
        */
        WARN_ON(in_irq());
        for (;;) {
                int ret = try_to_del_timer_sync(timer);
                if (ret >= 0)
                        return ret;
                cpu_relax();
        }
}

#define del_singleshot_timer_sync(t) del_timer_sync(t)
```

`del_timer()` 删除活动和非活动的定时器。在 SMP 系统中特别有用，`del_timer_sync()` 会停止定时器，并等待处理程序在其他 CPU 上执行完成。

# 动态定时器的竞争条件

```
RESOURCE_DEALLOCATE() here could be any relevant resource deallocation routine:
```

```
...
del_timer(&t_obj);
RESOURCE_DEALLOCATE();
....
```

然而，这种方法仅适用于单处理器系统。在 SMP 系统中，当定时器停止时，其功能可能已经在另一个 CPU 上运行。在这种情况下，资源将在`del_timer()`返回时立即释放，而定时器功能仍在其他 CPU 上操作它们；这绝非理想的情况。`del_timer_sync()`解决了这个问题：在停止定时器后，它会等待定时器功能在其他 CPU 上执行完成。`del_timer_sync()`在定时器功能可以重新激活自身的情况下非常有用。如果定时器功能不重新激活定时器，则应该使用一个更简单和更快的宏`del_singleshot_timer_sync()`。

# 动态定时器处理

软件定时器复杂且耗时，因此不应由定时器 ISR 处理。而应该由一个可延迟的底半软中断例程`TIMER_SOFTIRQ`来执行，其例程在`kernel/time/timer.c`中定义：

```
static __latent_entropy void run_timer_softirq(struct softirq_action *h)
{
        struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);

        base->must_forward_clk = false;

        __run_timers(base);
        if (IS_ENABLED(CONFIG_NO_HZ_COMMON) && base->nohz_active)
                __run_timers(this_cpu_ptr(&timer_bases[BASE_DEF]));
}
```

# 延迟函数

定时器在超时期相对较长时非常有用；在所有其他需要较短持续时间的用例中，使用延迟函数。在处理诸如存储设备（即*闪存*和*EEPROM*）等硬件时，设备驱动程序非常关键，需要等待设备完成写入和擦除等硬件操作，这在大多数情况下是在几微秒到毫秒的范围内。在不等待硬件完成这些操作的情况下继续执行其他指令将导致不可预测的读/写操作和数据损坏。在这种情况下，延迟函数非常有用。内核通过`ndelay()`、`udelay()`和`mdelay()`例程和宏提供这样的短延迟，分别接收纳秒、微秒和毫秒为参数。

以下函数可以在`include/linux/delay.h`中找到：

```
static inline void ndelay(unsigned long x)
{
        udelay(DIV_ROUND_UP(x, 1000));
}
```

这些函数可以在`arch/ia64/kernel/time.c`中找到：

```
static void
ia64_itc_udelay (unsigned long usecs)
{
        unsigned long start = ia64_get_itc();
        unsigned long end = start + usecs*local_cpu_data->cyc_per_usec;

        while (time_before(ia64_get_itc(), end))
                cpu_relax();
}

void (*ia64_udelay)(unsigned long usecs) = &ia64_itc_udelay;

void
udelay (unsigned long usecs)
{
        (*ia64_udelay)(usecs);
}
```

# POSIX 时钟

POSIX 为多线程和实时用户空间应用程序提供了软件定时器，称为 POSIX 定时器。POSIX 提供以下时钟：

+   `CLOCK_REALTIME`：该时钟表示系统中的实时时间。也称为墙上时间，类似于挂钟上的时间，用于时间戳和向用户提供实际时间。该时钟是可修改的。

+   `CLOCK_MONOTONIC`：该时钟保持系统启动以来经过的时间。它是不断增加的，并且不可被任何进程或用户修改。由于其单调性质，它是确定两个时间事件之间时间差的首选时钟。

+   `CLOCK_BOOTTIME`：该时钟与`CLOCK_MONOTONIC`相同；但它包括在挂起中花费的时间。

这些时钟可以通过以下 POSIX 时钟例程进行访问和修改（如果所选时钟允许）：

+   `int clock_getres(clockid_t clk_id, struct timespec *res);`

+   `int clock_gettime(clockid_t clk_id, struct timespec *tp);`

+   `int clock_settime(clockid_t clk_id, const struct timespec *tp);`

函数 `clock_getres()` 获取由 *clk_id* 指定的时钟的分辨率（精度）。如果分辨率非空，则将其存储在由分辨率指向的 `struct timespec` 中。函数 `clock_gettime()` 和 `clock_settime()` 读取和设置由 *clk_id* 指定的时钟的时间。*clk_id* 可以是任何 POSIX 时钟：`CLOCK_REALTIME`，`CLOCK_MONOTONIC` 等等。

`CLOCK_REALTIME_COARSE`

`CLOCK_MONOTONIC_COARSE`

每个这些 POSIX 例程都有相应的系统调用，即 `sys_clock_getres()，sys_clock_gettime()` 和 `sys_clock_settime`*.* 因此，每次调用这些例程时，都会发生从用户模式到内核模式的上下文切换。如果对这些例程的调用频繁，上下文切换可能会导致系统性能下降。为了避免上下文切换，POSIX 时钟的两个粗糙变体被实现为 vDSO（虚拟动态共享对象）库：

vDSO 是一个小型共享库，其中包含内核空间的选定例程，内核将其映射到用户空间应用程序的地址空间中，以便这些内核空间例程可以直接由它们在用户空间中的进程调用。C 库调用 vDSO，因此用户空间应用程序可以通过标准函数以通常的方式进行编程，并且 C 库将利用通过 vDSO 可用的功能，而不涉及任何系统调用接口，从而避免任何用户模式-内核模式上下文切换和系统调用开销。作为 vDSO 实现，这些粗糙的变体速度更快，分辨率为 1 毫秒。

# 总结

在本章中，我们详细了解了内核提供的大多数用于驱动基于时间的事件的例程，以及理解了 Linux 时间、其基础设施和其测量的基本方面。我们还简要介绍了 POSIX 时钟及其一些关键的时间访问和修改例程。然而，有效的时间驱动程序取决于对这些例程的谨慎和计算使用。

在下一章中，我们将简要介绍动态内核模块的管理。


# 第十一章：模块管理

内核模块（也称为 LKM）由于易用性而强调了内核服务的发展。本章的重点将是了解内核如何无缝地促进整个过程，使模块的加载和卸载变得动态和简单，我们将深入了解模块管理中涉及的所有核心概念、函数和重要数据结构。我们假设读者熟悉模块的基本用法。

在本章中，我们将涵盖以下主题：

+   内核模块的关键元素

+   模块布局

+   模块加载和卸载接口

+   关键数据结构

# 内核模块

内核模块是一种简单而有效的机制，可以在不重建整个内核的情况下扩展运行系统的功能，它们对于引入动态性和可扩展性到 Linux 操作系统至关重要。内核模块不仅满足了内核的可扩展性，还引入了以下功能：

+   允许内核仅保留必要的功能，从而提高容量利用率

+   允许专有/非 GPL 兼容服务加载和卸载

+   内核可扩展性的底线特性

# LKM 的元素

每个模块对象都包括*init（构造函数）*和*exit（析构函数）*例程。当模块部署到内核地址空间时，将调用*init*例程，而在模块被移除时将调用*exit*例程。正如名称本身所暗示的那样，*init*例程通常被编程为执行设置模块主体所必需的操作和动作，例如注册到特定的内核子系统或分配对加载的功能至关重要的资源。但是，*init*和*exit*例程中编程的特定操作取决于模块的设计目的以及它为内核带来的功能。以下代码摘录显示了*init*和*exit*例程的模板：

```
int init_module(void)
{
  /* perform required setup and registration ops */
    ...
    ...
    return 0;
}

void cleanup_module(void)
{
   /* perform required cleanup operations */
   ...
   ...
}
```

注意，*init*例程返回一个整数——如果模块已提交到内核地址空间，则返回零，如果失败则返回负数。这还为程序员提供了灵活性，只有在成功注册到所需子系统时才能提交模块。

*init*和*exit*例程的默认名称分别为`init_module()`和`cleanup_module()`。模块可以选择更改*init*和*exit*例程的名称以提高代码可读性。但是，它们必须使用`module_init`和`module_exit`宏进行声明：

```
int myinit(void)
{
        ...
        ...
        return 0;
}

void myexit(void)
{
        ...
        ...
}

module_init(myinit);
module_exit(myexit);
```

注释宏是模块代码的另一个关键元素。这些宏用于提供模块的用法、许可和作者信息。这很重要，因为模块来自各种供应商：

+   `MODULE_DESCRIPTION()`: 该宏用于指定模块的一般描述

+   `MODULE_AUTHOR()`: 用于提供作者信息

+   `MODULE_LICENSE()`: 用于指定模块中代码的合法许可证

通过这些宏指定的所有信息都保留在模块二进制文件中，并且可以通过名为*modinfo*的实用程序由用户访问。`MODULE_LICENSE()`是模块必须提到的唯一强制性宏。这非常方便，因为它通知用户模块中的专有代码容易受到调试和支持问题的影响（内核社区很可能会忽略专有模块引起的问题）。

模块可用的另一个有用功能是使用模块参数动态初始化模块数据变量。这允许在模块中声明的数据变量在模块部署期间或模块在内存中*live*时（通过 sysfs 接口）进行初始化。这可以通过通过适当的`module_param()`宏族（在内核头文件`<linux/moduleparam.h>`中找到）将选定的变量设置为模块参数来实现。在模块部署期间传递给模块参数的值在调用*init*函数之前进行初始化。

模块中的代码可以根据需要访问全局内核函数和数据。这使得模块的代码可以利用现有的内核功能。通过这样的函数调用，模块可以执行所需的操作，例如将消息打印到内核日志缓冲区，分配和释放内存，获取和释放排他锁，以及向适当的子系统注册和注销模块代码。

类似地，一个模块也可以将其符号导出到内核的全局符号表中，然后可以从其他模块中的代码中访问这些符号。这通过将内核服务组织在一组模块中，而不是将整个服务实现为单个 LKM，从而促进了内核服务的细粒度设计和实现。相关服务的堆叠会导致模块依赖，例如：如果模块 A 正在使用模块 B 的符号，则 A 依赖于 B，在这种情况下，必须在加载模块 A 之前加载模块 B，并且在卸载模块 A 之前不能卸载模块 B。

# LKM 的二进制布局

模块是使用 kbuild makefile 构建的；一旦构建过程完成，将生成一个带有*.ko*（内核对象）扩展名的 ELF 二进制文件。模块 ELF 二进制文件经过适当的调整，以添加新的部分，使其与其他 ELF 二进制文件区分开，并存储与模块相关的元数据。以下是内核模块中的部分：

| `.gnu.linkonce.this_module` | 模块结构 |
| --- | --- |
| `.modinfo` | 有关模块的信息（许可证等） |
| `__versions` | 编译时模块依赖的符号的预期版本 |
| `__ksymtab*` | 由此模块导出的符号表 |
| `__kcrctab*` | 由此模块导出的符号版本表 |
| `.init` | 初始化时使用的部分 |
| `.text, .data 等` | 代码和数据部分 |

# 加载和卸载操作

模块可以通过一个名为*modutils*的应用程序包中的特殊工具部署，其中*insmod*和*rmmod*被广泛使用。*insmod*用于将模块部署到内核地址空间，*rmmod*用于卸载活动模块。这些工具通过调用适当的系统调用来启动加载/卸载操作：

```
int finit_module(int fd, const char *param_values, int flags);
int delete_module(const char *name, int flags);
```

在这里，`finit_module()`（由`insmod`）被调用，带有指定模块二进制文件（.ko）的文件描述符和其他相关参数。此函数通过调用底层系统调用进入内核模式：

```
SYSCALL_DEFINE3(finit_module, int, fd, const char __user *, uargs, int, flags)
{
        struct load_info info = { };
        loff_t size;
        void *hdr;
        int err;

        err = may_init_module();
        if (err)
                return err;

        pr_debug("finit_module: fd=%d, uargs=%p, flags=%i\n", fd, uargs, flags);

        if (flags & ~(MODULE_INIT_IGNORE_MODVERSIONS
                      |MODULE_INIT_IGNORE_VERMAGIC))
                return -EINVAL;

        err = kernel_read_file_from_fd(fd, &hdr, &size, INT_MAX,
                                       READING_MODULE);
        if (err)
                return err;
        info.hdr = hdr;
        info.len = size;

        return load_module(&info, uargs, flags);
}
```

在这里，`may_init_module()`被调用来验证调用上下文的`CAP_SYS_MODULE`特权；此函数在失败时返回负数，在成功时返回零。如果调用者具有所需的特权，则通过使用`kernel_read_file_from_fd()`例程访问指定的模块映像，该例程返回模块映像的地址，然后将其填充到`struct load_info`的实例中。最后，通过将`load_info`的实例地址和从`finit_module()`调用传递下来的其他用户参数，调用`load_module()`核心内核例程：

```
static int load_module(struct load_info *info, const char __user *uargs,int flags)
{
        struct module *mod;
        long err;
        char *after_dashes;

        err = module_sig_check(info, flags);
        if (err)
                goto free_copy;

        err = elf_header_check(info);
        if (err)
                goto free_copy;

        /* Figure out module layout, and allocate all the memory. */
        mod = layout_and_allocate(info, flags);
        if (IS_ERR(mod)) {
                err = PTR_ERR(mod);
                goto free_copy;
        }

        ....
        ....
        ....

}
```

在这里，`load_module（）`是一个核心内核例程，它尝试将模块映像链接到内核地址空间。此函数启动一系列健全性检查，并最终通过将模块参数初始化为调用者提供的值并调用模块的*init*函数来提交模块。以下步骤详细说明了这些操作，以及调用的相关辅助函数的名称：

+   检查签名（`module_sig_check（）`）

+   检查 ELF 头（`elf_header_check（）`）

+   检查模块布局并分配必要的内存（`layout_and_allocate（）`）

+   将模块附加到模块列表（`add_unformed_module（）`）

+   为模块分配每个 CPU 区域（`percpu_modalloc（）`）

+   由于模块位于最终位置，需要找到可选部分（`find_module_sections（）`）

+   检查模块许可证和版本（`check_module_license_and_versions（）`）

+   解析符号（`simplify_symbols（）`）

+   根据 args 列表中传递的值设置模块参数

+   检查符号的重复（`complete_formation（）`）

+   设置 sysfs（`mod_sysfs_setup（）`）

+   释放*load_info*结构中的副本（`free_copy（）`）

+   调用模块的*init*函数（`do_init_module（）`）

卸载过程与加载过程非常相似；唯一不同的是，有一些健全性检查，以确保安全地从内核中移除模块，而不影响系统稳定性。模块的卸载是通过调用*rmmod*实用程序来初始化的，该实用程序调用`delete_module（）`例程，该例程进入底层系统调用：

```
SYSCALL_DEFINE2(delete_module, const char __user *, name_user,
                unsigned int, flags)
{
        struct module *mod;
        char name[MODULE_NAME_LEN];
        int ret, forced = 0;

        if (!capable(CAP_SYS_MODULE) || modules_disabled)
                return -EPERM;

        if (strncpy_from_user(name, name_user, MODULE_NAME_LEN-1) < 0)
                return -EFAULT;
        name[MODULE_NAME_LEN-1] = '\0';

        audit_log_kern_module(name);

        if (mutex_lock_interruptible(&module_mutex) != 0)
                return -EINTR;

        mod = find_module(name);
        if (!mod) {
                ret = -ENOENT;
                goto out;
        }

        if (!list_empty(&mod->source_list)) {
                /* Other modules depend on us: get rid of them first. */
                ret = -EWOULDBLOCK;
                goto out;
        }

        /* Doing init or already dying? */
        if (mod->state != MODULE_STATE_LIVE) {
                /* FIXME: if (force), slam module count damn the torpedoes */
                pr_debug("%s already dying\n", mod->name);
                ret = -EBUSY;
                goto out;
        }

        /* If it has an init func, it must have an exit func to unload */
        if (mod->init && !mod->exit) {
                forced = try_force_unload(flags);
                if (!forced) {
                        /* This module can't be removed */
                        ret = -EBUSY;
                        goto out;
                }
        }

        /* Stop the machine so refcounts can't move and disable module. */
        ret = try_stop_module(mod, flags, &forced);
        if (ret != 0)
                goto out;

        mutex_unlock(&module_mutex);
        /* Final destruction now no one is using it. */
        if (mod->exit != NULL)
                mod->exit();
        blocking_notifier_call_chain(&module_notify_list,
                                     MODULE_STATE_GOING, mod);
        klp_module_going(mod);
        ftrace_release_mod(mod);

        async_synchronize_full();

        /* Store the name of the last unloaded module for diagnostic purposes */
        strlcpy(last_unloaded_module, mod->name, sizeof(last_unloaded_module));

        free_module(mod);
        return 0;
out:
        mutex_unlock(&module_mutex);
        return ret;
}
```

在调用时，系统调用会检查调用者是否具有必要的权限，然后检查是否存在任何模块依赖项。如果没有，模块就可以被移除（否则，将返回错误）。之后，验证模块状态（*live*）。最后，调用模块的退出例程，最后调用`free_module（）`例程：

```
/* Free a module, remove from lists, etc. */
static void free_module(struct module *mod)
{
        trace_module_free(mod);

        mod_sysfs_teardown(mod);

        /* We leave it in list to prevent duplicate loads, but make sure
        * that no one uses it while it's being deconstructed. */
        mutex_lock(&module_mutex);
        mod->state = MODULE_STATE_UNFORMED;
        mutex_unlock(&module_mutex);

        /* Remove dynamic debug info */
        ddebug_remove_module(mod->name);

        /* Arch-specific cleanup. */
        module_arch_cleanup(mod);

        /* Module unload stuff */
        module_unload_free(mod);

        /* Free any allocated parameters. */
        destroy_params(mod->kp, mod->num_kp);

        if (is_livepatch_module(mod))
                free_module_elf(mod);

        /* Now we can delete it from the lists */
        mutex_lock(&module_mutex);
        /* Unlink carefully: kallsyms could be walking list. */
        list_del_rcu(&mod->list);
        mod_tree_remove(mod);
        /* Remove this module from bug list, this uses list_del_rcu */
        module_bug_cleanup(mod);
        /* Wait for RCU-sched synchronizing before releasing mod->list and buglist. */
        synchronize_sched();
        mutex_unlock(&module_mutex);

        /* This may be empty, but that's OK */
        disable_ro_nx(&mod->init_layout);
        module_arch_freeing_init(mod);
        module_memfree(mod->init_layout.base);
        kfree(mod->args);
        percpu_modfree(mod);

        /* Free lock-classes; relies on the preceding sync_rcu(). */
        lockdep_free_key_range(mod->core_layout.base, mod->core_layout.size);

        /* Finally, free the core (containing the module structure) */
        disable_ro_nx(&mod->core_layout);
        module_memfree(mod->core_layout.base);

#ifdef CONFIG_MPU
        update_protections(current->mm);
#endif
}
```

此调用将模块从加载期间放置的各种列表中删除（sysfs、模块列表等），以启动清理。调用特定于体系结构的清理例程（可以在`</linux/arch/<arch>/kernel/module.c>`*）*中找到。对所有依赖模块进行迭代，并从它们的列表中删除模块。一旦清理结束，将释放为模块分配的所有资源和内存。

# 模块数据结构

内核中部署的每个模块通常通过称为`struct module`的描述符表示。内核维护着模块实例的列表，每个实例代表内存中的特定模块：

```
struct module {
        enum module_state state;

        /* Member of list of modules */
        struct list_head list;

        /* Unique handle for this module */
        char name[MODULE_NAME_LEN];

        /* Sysfs stuff. */
        struct module_kobject mkobj;
        struct module_attribute *modinfo_attrs;
        const char *version;
        const char *srcversion;
        struct kobject *holders_dir;

        /* Exported symbols */
        const struct kernel_symbol *syms;
        const s32 *crcs;
        unsigned int num_syms;

        /* Kernel parameters. */
#ifdef CONFIG_SYSFS
        struct mutex param_lock;
#endif
        struct kernel_param *kp;
        unsigned int num_kp;

        /* GPL-only exported symbols. */
        unsigned int num_gpl_syms;
        const struct kernel_symbol *gpl_syms;
        const s32 *gpl_crcs;

#ifdef CONFIG_UNUSED_SYMBOLS
        /* unused exported symbols. */
        const struct kernel_symbol *unused_syms;
        const s32 *unused_crcs;
        unsigned int num_unused_syms;

        /* GPL-only, unused exported symbols. */
        unsigned int num_unused_gpl_syms;
        const struct kernel_symbol *unused_gpl_syms;
        const s32 *unused_gpl_crcs;
#endif

#ifdef CONFIG_MODULE_SIG
        /* Signature was verified. */
        bool sig_ok;
#endif

        bool async_probe_requested;

        /* symbols that will be GPL-only in the near future. */
        const struct kernel_symbol *gpl_future_syms;
        const s32 *gpl_future_crcs;
        unsigned int num_gpl_future_syms;

        /* Exception table */
        unsigned int num_exentries;
        struct exception_table_entry *extable;

        /* Startup function. */
        int (*init)(void);

        /* Core layout: rbtree is accessed frequently, so keep together. */
        struct module_layout core_layout __module_layout_align;
        struct module_layout init_layout;

        /* Arch-specific module values */
        struct mod_arch_specific arch;

        unsigned long taints;     /* same bits as kernel:taint_flags */

#ifdef CONFIG_GENERIC_BUG
        /* Support for BUG */
        unsigned num_bugs;
        struct list_head bug_list;
        struct bug_entry *bug_table;
#endif

#ifdef CONFIG_KALLSYMS
        /* Protected by RCU and/or module_mutex: use rcu_dereference() */
        struct mod_kallsyms *kallsyms;
        struct mod_kallsyms core_kallsyms;

        /* Section attributes */
        struct module_sect_attrs *sect_attrs;

        /* Notes attributes */
        struct module_notes_attrs *notes_attrs;
#endif

        /* The command line arguments (may be mangled).  People like
          keeping pointers to this stuff */
        char *args;

#ifdef CONFIG_SMP
        /* Per-cpu data. */
        void __percpu *percpu;
        unsigned int percpu_size;
#endif

#ifdef CONFIG_TRACEPOINTS
        unsigned int num_tracepoints;
        struct tracepoint * const *tracepoints_ptrs;
#endif
#ifdef HAVE_JUMP_LABEL
        struct jump_entry *jump_entries;
        unsigned int num_jump_entries;
#endif
#ifdef CONFIG_TRACING
        unsigned int num_trace_bprintk_fmt;
        const char **trace_bprintk_fmt_start;
#endif
#ifdef CONFIG_EVENT_TRACING
        struct trace_event_call **trace_events;
        unsigned int num_trace_events;
        struct trace_enum_map **trace_enums;
        unsigned int num_trace_enums;
#endif
#ifdef CONFIG_FTRACE_MCOUNT_RECORD
        unsigned int num_ftrace_callsites;
        unsigned long *ftrace_callsites;
#endif

#ifdef CONFIG_LIVEPATCH
        bool klp; /* Is this a livepatch module? */
        bool klp_alive;

        /* Elf information */
        struct klp_modinfo *klp_info;
#endif

#ifdef CONFIG_MODULE_UNLOAD
        /* What modules depend on me? */
        struct list_head source_list;
        /* What modules do I depend on? */
        struct list_head target_list;

        /* Destruction function. */
        void (*exit)(void);

        atomic_t refcnt;
#endif

#ifdef CONFIG_CONSTRUCTORS
        /* Constructor functions. */
        ctor_fn_t *ctors;
        unsigned int num_ctors;
#endif
} ____cacheline_aligned;
```

现在让我们看一下此结构的一些关键字段：

+   `list`：这是一个双向链表，其中包含内核中加载的所有模块。

+   `name`：指定模块的名称。这必须是一个唯一的名称，因为模块是通过此名称引用的。

+   `state`：表示模块的当前状态。模块可以处于`<linux/module.h>`下指定的任一状态中：

```
enum module_state {
        MODULE_STATE_LIVE,        /* Normal state. */
        MODULE_STATE_COMING,      /* Full formed, running module_init. */
        MODULE_STATE_GOING,       /* Going away. */
        MODULE_STATE_UNFORMED,    /* Still setting it up. */
};
```

在加载或卸载模块时，了解其当前状态很重要；例如，如果其状态指定模块已经存在，则无需插入现有模块。

`syms, crc 和 num_syms`：用于管理模块代码导出的符号。

`init`：这是指向在模块初始化时调用的函数的指针。

`arch`：表示特定于体系结构的结构，应填充体系结构特定数据，以便模块运行。但是，由于大多数体系结构不需要任何额外的信息，因此此结构大多数情况下保持为空。

`taints`：如果模块使内核受到污染，则使用此选项。这可能意味着内核怀疑模块会执行一些有害的操作或者是非 GPL 兼容的代码。

`percpu`：指向属于模块的每个 CPU 数据。它在模块加载时初始化。

`source_list 和 target_list`：这包含了模块依赖的详细信息。

`exit`：这只是 init 的相反。它指向调用模块清理过程的函数。它释放模块持有的内存并执行其他清理特定任务。

# 内存布局

模块的内存布局通过*<linux/module.h>*中定义的`struct module_layout`对象显示。

```
struct module_layout {
        /* The actual code + data. */
        void *base;
        /* Total size. */
        unsigned int size;
        /* The size of the executable code.  */
        unsigned int text_size;
        /* Size of RO section of the module (text+rodata) */
        unsigned int ro_size;

#ifdef CONFIG_MODULES_TREE_LOOKUP
        struct mod_tree_node mtn;
#endif
};
```

# 总结

在这一章中，我们简要介绍了模块的所有核心元素，其含义和管理细节。我们的目标是为您提供一个快速和全面的视角，了解内核如何通过模块实现其可扩展性。您还了解了促进模块管理的核心数据结构。内核在这个动态环境中保持安全和稳定的努力也是一个显著的特点。

我真诚地希望这本书能成为您去实验 Linux 内核的手段！
