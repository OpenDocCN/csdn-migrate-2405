# Linux 设备驱动开发（六）

> 原文：[`zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E`](https://zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：GPIO 控制器驱动程序 - gpio_chip

在上一章中，我们处理了 GPIO 线路。这些线路通过一个名为 GPIO 控制器的特殊设备向系统公开。本章将逐步解释如何为这类设备编写驱动程序，从而涵盖以下主题：

+   GPIO 控制器驱动程序架构和数据结构

+   GPIO 控制器的 Sysfs 接口

+   DT 中 GPIO 控制器的表示

# 驱动程序架构和数据结构

这类设备的驱动程序应该提供：

+   建立 GPIO 方向（输入和输出）的方法。

+   用于访问 GPIO 值的方法（获取和设置）。

+   将给定的 GPIO 映射到 IRQ 并返回相关的编号的方法。

+   标志，表示其方法是否可以休眠，这非常重要。

+   可选的 `debugfs dump` 方法（显示额外状态，如上拉配置）。

+   可选的基数号码，从哪里开始对 GPIO 进行编号。如果省略，将自动分配。

在内核中，GPIO 控制器表示为 `struct gpio_chip` 的实例，定义在 `linux/gpio/driver.h` 中：

```
struct gpio_chip { 
  const char *label; 
  struct device *dev; 
  struct module *owner; 

  int (*request)(struct gpio_chip *chip, unsigned offset); 
  void (*free)(struct gpio_chip *chip, unsigned offset); 
  int (*get_direction)(struct gpio_chip *chip, unsigned offset); 
  int (*direction_input)(struct gpio_chip *chip, unsigned offset); 
  int (*direction_output)(struct gpio_chip *chip, unsigned offset, 

            int value); 
  int (*get)(struct gpio_chip *chip,unsigned offset); 
  void (*set)(struct gpio_chip *chip, unsigned offset, int value); 
  void (*set_multiple)(struct gpio_chip *chip, unsigned long *mask, 
            unsigned long *bits); 
  int (*set_debounce)(struct gpio_chip *chip, unsigned offset, 
            unsigned debounce); 

  int (*to_irq)(struct gpio_chip *chip, unsigned offset); 

  int base; 
  u16 ngpio; 
  const char *const *names; 
  bool can_sleep; 
  bool irq_not_threaded; 
  bool exported; 

#ifdef CONFIG_GPIOLIB_IRQCHIP 
  /* 
   * With CONFIG_GPIOLIB_IRQCHIP we get an irqchip 
    * inside the gpiolib to handle IRQs for most practical cases. 
   */ 
  struct irq_chip *irqchip; 
  struct irq_domain *irqdomain; 
  unsigned int irq_base; 
  irq_flow_handler_t  irq_handler; 
  unsigned int irq_default_type; 
#endif 

#if defined(CONFIG_OF_GPIO) 
  /* 
   * If CONFIG_OF is enabled, then all GPIO controllers described in the 
   * device tree automatically may have an OF translation 
   */ 
  struct device_node *of_node; 
  int of_gpio_n_cells; 
  int (*of_xlate)(struct gpio_chip *gc, 
      const struct of_phandle_args *gpiospec, u32 *flags); 
} 
```

以下是结构中每个元素的含义：

+   `request` 是一个可选的钩子，用于特定于芯片的激活。如果提供，它将在分配 GPIO 之前执行，每当调用 `gpio_request()` 或 `gpiod_get()` 时。

+   `free` 是一个可选的钩子，用于特定于芯片的停用。如果提供，它将在每次调用 `gpiod_put()` 或 `gpio_free()` 时，在释放 GPIO 之前执行。

+   `get_direction` 每当需要知道 GPIO `offset` 的方向时执行。返回值应为 0 表示输出，1 表示输入（与 `GPIOF_DIR_XXX` 相同），或者负错误。

+   `direction_input` 配置信号 `offset` 为输入，或返回错误。

+   `get` 返回 GPIO `offset` 的值；对于输出信号，这将返回实际感应到的值，或者零。

+   `set` 将输出值分配给 GPIO `offset`。

+   `set_multiple` 当需要为 `mask` 定义的多个信号分配输出值时调用。如果未提供，内核将安装一个通用的钩子，将遍历 `mask` 位并在每个设置的位上执行 `chip->set(i)` 。

请参阅以下内容，显示了如何实现此功能：

```
 static void gpio_chip_set_multiple(struct gpio_chip *chip, 
      unsigned long *mask, unsigned long *bits) 
{ 
  if (chip->set_multiple) { 
    chip->set_multiple(chip, mask, bits); 
  } else { 
    unsigned int i; 

    /* set outputs if the corresponding mask bit is set */ 
    for_each_set_bit(i, mask, chip->ngpio) 
      chip->set(chip, i, test_bit(i, bits)); 
  } 
} 
```

+   `set_debounce` 如果控制器支持，这个钩子是一个可选的回调，用于设置指定 GPIO 的去抖时间。

+   `to_irq` 是一个可选的钩子，用于提供 GPIO 到 IRQ 的映射。每当需要执行 `gpio_to_irq()` 或 `gpiod_to_irq()` 函数时，就会调用这个函数。这个实现可能不会休眠。

+   `base` 标识了该芯片处理的第一个 GPIO 编号；或者，在注册期间为负时，内核将自动（动态）分配一个。

+   `ngpio` 是该控制器提供的 GPIO 数量，从 `base` 开始，到 `(base + ngpio - 1)` 结束。

+   `names`，如果设置，必须是一个字符串数组，用作该芯片中 GPIO 的替代名称。数组的大小必须为 `ngpio`，任何不需要别名的 GPIO 可以在数组中的条目中设置为 `NULL`。

+   `can_sleep` 是一个布尔标志，如果 `get()`/`set()` 方法可能会休眠，则设置。对于 GPIO 控制器（也称为扩展器）位于总线上，如 I2C 或 SPI，其访问可能会导致休眠。这意味着如果芯片支持 IRQ，这些 IRQ 需要被线程化，因为芯片访问可能会休眠，例如，读取 IRQ 状态寄存器时。对于映射到内存（SoC 的一部分）的 GPIO 控制器，可以将其设置为 false。

+   `irq_not_threaded` 是一个布尔标志，如果设置了 `can_sleep`，则必须设置该标志，但 IRQs 不需要被线程化。

每个芯片公开了一些信号，通过方法调用中的偏移值（在范围 0（`ngpio - 1`）内）进行标识。当这些信号通过 `gpio_get_value(gpio)` 等调用引用时，偏移量是通过从 GPIO 编号中减去基数来计算的。

在定义了每个回调和其他字段之后，应在配置的 `struct gpio_chip` 结构上调用 `gpiochip_add()`，以便向内核注册控制器。在注销时，使用 `gpiochip_remove()`。就是这样。您可以看到编写自己的 GPIO 控制器驱动程序有多么容易。在本书源代码库中，您将找到一个可用的 MCP23016 I2C I/O 扩展器的 GPIO 控制器驱动程序，其数据表可在 [`ww1.microchip.com/downloads/en/DeviceDoc/20090C.pdf`](http://ww1.microchip.com/downloads/en/DeviceDoc/20090C.pdf) 上找到。

要编写这样的驱动程序，您应该包括：

```
#include <linux/gpio.h>  
```

以下是我们为控制器编写的驱动程序的摘录，只是为了向您展示编写 GPIO 控制器驱动程序有多么容易：

```
#define GPIO_NUM 16 
struct mcp23016 { 
  struct i2c_client *client; 
  struct gpio_chip chip; 
}; 

static int mcp23016_probe(struct i2c_client *client, 
          const struct i2c_device_id *id) 
{ 
  struct mcp23016 *mcp; 

  if (!i2c_check_functionality(client->adapter, 
      I2C_FUNC_SMBUS_BYTE_DATA)) 
    return -EIO; 

  mcp = devm_kzalloc(&client->dev, sizeof(*mcp), GFP_KERNEL); 
  if (!mcp) 
    return -ENOMEM; 

  mcp->chip.label = client->name; 
  mcp->chip.base = -1; 
  mcp->chip.dev = &client->dev; 
  mcp->chip.owner = THIS_MODULE; 
  mcp->chip.ngpio = GPIO_NUM; /* 16 */ 
  mcp->chip.can_sleep = 1; /* may not be accessed from actomic context */ 
  mcp->chip.get = mcp23016_get_value; 
  mcp->chip.set = mcp23016_set_value; 
  mcp->chip.direction_output = mcp23016_direction_output; 
  mcp->chip.direction_input = mcp23016_direction_input; 
  mcp->client = client; 
  i2c_set_clientdata(client, mcp); 

  return gpiochip_add(&mcp->chip); 
} 
```

要从控制器驱动程序内部请求自有 GPIO，不应使用 `gpio_request()`。GPIO 驱动程序可以使用以下函数来请求和释放描述符，而不会永远固定在内核中：

```
struct gpio_desc *gpiochip_request_own_desc(struct gpio_desc *desc, const char *label) 
void gpiochip_free_own_desc(struct gpio_desc *desc) 
```

使用 `gpiochip_request_own_desc()` 请求的描述符必须使用 `gpiochip_free_own_desc()` 释放。

# 引脚控制器指南

根据您为其编写驱动程序的控制器，您可能需要实现一些引脚控制操作，以处理引脚复用、配置等：

+   对于只能执行简单 GPIO 的引脚控制器，简单的 `struct gpio_chip` 就足以处理它。无需设置 `struct pinctrl_desc` 结构，只需编写 GPIO 控制器驱动程序即可。

+   如果控制器可以在 GPIO 功能之上生成中断，则必须设置并向 IRQ 子系统注册 `struct irq_chip`。

+   对于具有引脚复用、高级引脚驱动强度、复杂偏置的控制器，您应该设置以下三个接口：

+   `struct gpio_chip`，在本章前面讨论过

+   `struct irq_chip`，在下一章（[第十六章](http://advanced)，*高级中断管理*）中讨论。

+   `struct pinctrl_desc`，本书未讨论，但在内核文档 *Documentation/pinctrl.txt* 中有很好的解释

# GPIO 控制器的 Sysfs 接口

成功调用 `gpiochip_add()` 后，将创建一个目录条目，路径类似于 `/sys/class/gpio/gpiochipX/`，其中 `X` 是 GPIO 控制器基地址（提供从 `#X` 开始的 GPIO 的控制器），具有以下属性：

+   `base`，其值与 `X` 相同，对应于 `gpio_chip.base`（如果静态分配），并且是由此芯片管理的第一个 GPIO。

+   `label`，用于诊断（不一定是唯一的）。

+   `ngpio`，告诉这个控制器提供多少个 GPIO（`N` 到 `N + ngpio - 1`）。这与 `gpio_chip.ngpios` 中定义的相同。

所有前述属性都是只读的。

# GPIO 控制器和 DT

在 DT 中声明的每个 GPIO 控制器都必须设置布尔属性 `gpio-controller`。一些控制器提供与 GPIO 映射的中断。在这种情况下，还应该设置属性 `interrupt-cells`，通常使用 `2`，但这取决于需要。第一个单元格是引脚编号，第二个表示中断标志。

`gpio-cells` 应设置为标识用于描述 GPIO 指定器的单元格数量。通常使用 `<2>`，第一个单元格用于标识 GPIO 编号，第二个用于标志。实际上，大多数非内存映射 GPIO 控制器不使用标志：

```
expander_1: mcp23016@27 { 
    compatible = "microchip,mcp23016"; 
    interrupt-controller; 
    gpio-controller; 
    #gpio-cells = <2>; 
    interrupt-parent = <&gpio6>; 
    interrupts = <31 IRQ_TYPE_LEVEL_LOW>; 
    reg = <0x27>; 
    #interrupt-cells=<2>; 
}; 
```

前述示例是我们的 GPIO 控制器设备节点，完整的设备驱动程序随本书的源代码一起提供。

# 摘要

本章远不止是为您可能遇到的 GPIO 控制器编写驱动程序的基础。它解释了描述这些设备的主要结构。下一章将涉及高级中断管理，我们将看到如何管理中断控制器，并在微芯片的 MCP23016 扩展器驱动程序中添加此功能。


# 第十六章：高级 IRQ 管理

Linux 是一个系统，设备通过 IRQ 通知内核特定事件。CPU 暴露 IRQ 线，由连接的设备使用，因此当设备需要 CPU 时，它会向 CPU 发送请求。当 CPU 收到此请求时，它会停止其实际工作并保存其上下文，以便为设备发出的请求提供服务。在为设备提供服务之后，其状态将恢复到中断发生时停止的确切位置。有这么多的 IRQ 线，另一个设备负责它们给 CPU。该设备是中断控制器：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00034.gif)

中断控制器和 IRQ 线

设备不仅可以引发中断，某些处理器操作也可以引发中断。有两种不同类型的中断：

1.  同步中断称为**异常**，由 CPU 在处理指令时产生。这些是**不可屏蔽中断**（**NMI**），是由于硬件故障等严重故障而产生的。它们始终由 CPU 处理。

1.  异步中断称为**中断**，由其他硬件设备发出。这些是正常的可屏蔽中断。这是我们将在本章的后续部分讨论的内容。因此，让我们深入了解异常：

异常是由内核处理的编程错误的后果，内核向程序发送信号并尝试从错误中恢复。这些被分类为以下两类：

+   **处理器检测到的异常**：CPU 对异常情况生成的异常，分为三组：

+   故障，通常可以纠正（虚假指令）。

+   陷阱，发生在用户进程中（无效的内存访问，除以零），也是响应系统调用切换到内核模式的机制。如果内核代码确实引起陷阱，它会立即发生恐慌。

+   中止，严重错误。

+   **程序化异常**：这些是由程序员请求的，像陷阱一样处理。

以下数组列出了不可屏蔽中断（有关更多详细信息，请参阅[`wiki.osdev.org/Exceptions`](http://wiki.osdev.org/Exceptions)）：

| **中断号** | **描述** |
| --- | --- |
| 0 | 除零错误 |
| 1 | 调试异常 |
| 2 | NMI 中断 |
| 3 | 断点 |
| 4 | 检测到溢出 |
| 5 | BOUND 范围超出 |
| 6 | 无效的操作码 |
| 7 | 协处理器（设备）不可用 |
| 8 | 双重故障 |
| 9 | 协处理器段溢出 |
| 10 | 无效的任务状态段 |
| 11 | 段不存在 |
| 12 | 栈故障 |
| 13 | 通用保护错误 |
| 14 | 页错误 |
| 15 | 保留 |
| 16 | 协处理器错误 |
| 17 - 31 | 保留 |
| 32 - 255 | 可屏蔽中断 |

NMI 足以覆盖整个异常列表。回到可屏蔽中断，它们的数量取决于连接的设备数量，以及它们实际如何共享这些 IRQ 线。有时它们是不够的，其中一些需要多路复用。常用的方法是通过 GPIO 控制器，它也充当中断控制器。在本章中，我们将讨论内核提供的管理 IRQ 的 API 以及多路复用的方式，并深入研究中断控制器驱动程序编写。

也就是说，在本章中将涵盖以下主题：

+   中断控制器和中断多路复用

+   高级外围 IRQ 管理

+   中断请求和传播（串联或嵌套）

+   GPIOLIB irqchip API

+   从 DT 处理中断控制器

# 多路复用中断和中断控制器

通常，仅有来自 CPU 的单个中断是不够的。大多数系统有数十甚至数百个中断。现在是中断控制器的时候，它允许它们进行多路复用。非常常见的架构或平台特定提供特定的设施，例如：

+   屏蔽/取消屏蔽单个中断

+   设置优先级

+   SMP 亲和力

+   像唤醒中断这样的奇特事物

IRQ 管理和中断控制器驱动程序都依赖于 IRQ 域，其依次建立在以下结构之上：

+   `struct irq_chip`：这个结构实现了一组描述如何驱动中断控制器的方法，并且这些方法直接被核心 IRQ 代码调用。

+   `struct irqdomain` 结构，提供：

+   给定中断控制器的固件节点的指针（fwnode）

+   将固件描述的 IRQ 转换为本地于此中断控制器的 ID 的方法（hwirq）

+   从 hwirq 中检索 IRQ 的 Linux 视图的方法

+   `struct irq_desc`：这个结构是 Linux 对中断的视图，包含所有核心内容，并且与 Linux 中断号一一对应

+   `struct irq_action`：这个结构 Linux 用于描述 IRQ 处理程序

+   `struct irq_data`：这个结构嵌入在 `struct irq_desc` 结构中，包含：

+   与管理此中断的 `irq_chip` 相关的数据

+   Linux IRQ 号和 hwirq

+   指向 `irq_chip` 的指针

几乎每个 `irq_chip` 调用都会给定一个 `irq_data` 作为参数，从中可以获取相应的 `irq_desc`。

所有前述结构都是 IRQ 域 API 的一部分。中断控制器在内核中由 `struct irq_chip` 结构的实例表示，该结构描述了实际的硬件设备，以及 IRQ 核心使用的一些方法：

```
struct irq_chip { 
   struct device *parent_device; 
   const char  *name; 
   void (*irq_enable)(struct irq_data *data); 
   void (*irq_disable)(struct irq_data *data); 

   void (*irq_ack)(struct irq_data *data); 
   void (*irq_mask)(struct irq_data *data); 
   void (*irq_unmask)(struct irq_data *data); 
   void (*irq_eoi)(struct irq_data *data); 

   int (*irq_set_affinity)(struct irq_data *data, const struct cpumask *dest, bool force); 
   int (*irq_retrigger)(struct irq_data *data); 
   int (*irq_set_type)(struct irq_data *data, unsigned int flow_type); 
   int (*irq_set_wake)(struct irq_data *data, unsigned int on); 

   void (*irq_bus_lock)(struct irq_data *data); 
   void (*irq_bus_sync_unlock)(struct irq_data *data); 

   int (*irq_get_irqchip_state)(struct irq_data *data, enum irqchip_irq_state which, bool *state); 
   int(*irq_set_irqchip_state)(struct irq_data *data, enum irqchip_irq_state which, bool state); 

   unsigned long flags; 
}; 
```

以下是结构中元素的含义：

+   `parent_device`：这是指向此 irqchip 的父级的指针。

+   `name`：这是 `/proc/interrupts` 文件的名称。

+   `irq_enable`：这个钩子函数用于启用中断，默认值是 `chip->unmask` 如果为 `NULL`。

+   `irq_disable`：这个函数用于禁用中断。

+   ***** `irq_ack`：这是一个新中断的开始。一些控制器不需要这个。Linux 在中断被触发后立即调用此函数，远在中断被服务之前。一些实现将此函数映射到 `chip->disable()`，以便在当前中断请求被服务之后，该线路上的另一个中断请求不会再次引发中断。

+   `irq_mask`：这个钩子函数用于在硬件中屏蔽中断源，使其无法再次触发。

+   `irq_unmask`：这个钩子函数用于取消屏蔽中断源。

+   `irq_eoi`：eoi 代表**中断结束**。Linux 在 IRQ 服务完成后立即调用此钩子。使用此函数根据需要重新配置控制器，以便在该线路上接收另一个中断请求。一些实现将此函数映射到 `chip->enable()`，以撤消 `chip->ack()` 中的操作。

+   `irq_set_affinity`：这个函数仅在 SMP 机器上设置 CPU 亲和性。在 SMP 环境中，此函数设置将服务中断的 CPU。在单处理器机器中不使用此函数。

+   `irq_retrigger`：这个函数重新触发硬件中断，将中断重新发送到 CPU。

+   `irq_set_type`：这个函数设置中断的流类型（IRQ_TYPE_LEVEL/等）。

+   `irq_set_wake`：这个函数用于启用/禁用中断的电源管理唤醒功能。

+   `irq_bus_lock`：这个函数用于锁定对慢总线（I2C）芯片的访问。在这里锁定互斥锁就足够了。

+   `irq_bus_sync_unlock`：这个函数用于同步和解锁慢总线（I2C）芯片。解锁之前锁定的互斥锁。

+   `irq_get_irqchip_state` 和 `irq_set_irqchip_state`：分别返回或设置中断的内部状态。

每个中断控制器都有一个域，对于控制器来说，这就像进程的地址空间一样（参见[第十一章](http://kernel)，*内核内存管理*）。中断控制器域在内核中被描述为 `struct irq_domain` 结构的实例。它管理硬件 IRQ 和 Linux IRQ（即虚拟 IRQ）之间的映射。它是硬件中断编号转换对象：

```
struct irq_domain { 
   const char *name; 
   const struct irq_domain_ops *ops; 
   void *host_data; 
   unsigned int flags; 

   /* Optional data */ 
   struct fwnode_handle *fwnode; 
   [...] 
}; 
```

+   `name` 是中断域的名称。

+   `ops` 是指向 irq_domain 方法的指针。

+   `host_data` 是所有者使用的私有数据指针。不会被 irqdomain 核心代码触及。

+   `flags`是每个`irq_domain`标志的主机。

+   `fwnode`是可选的。它是与`irq_domain`关联的 DT 节点的指针。在解码 DT 中断规范时使用。

中断控制器驱动程序通过调用`irq_domain_add_<mapping_method>()`函数之一创建并注册`irq_domain`，其中`<mapping_method>`是 hwirq 应该映射到 Linux IRQ 的方法。这些是：

1.  `irq_domain_add_linear()`：这使用一个由 hwirq 号索引的固定大小表。当映射 hwirq 时，为 hwirq 分配一个`irq_desc`，并将 IRQ 号存储在表中。这种线性映射适用于固定和小数量的 hwirq（~ <256）。这种映射的不便之处在于表的大小，它与最大可能的 hwirq 号一样大。因此，IRQ 号查找时间是固定的，`irq_desc`仅为正在使用的 IRQ 分配。大多数驱动程序应该使用线性映射。此函数具有以下原型：

```
struct irq_domain *irq_domain_add_linear(struct device_node *of_node, 
                            unsigned int size, 
                            const struct irq_domain_ops *ops, 
                            void *host_data) 
```

1.  `irq_domain_add_tree()`：这是`irq_domain`在 radix 树中维护 Linux IRQ 和 hwirq 号之间的映射。当映射 hwirq 时，将分配一个`irq_desc`，并且 hwirq 将用作 radix 树的查找键。如果 hwirq 号可能非常大，则树映射是一个不错的选择，因为它不需要分配一个与最大 hwirq 号一样大的表。缺点是 hwirq 到 IRQ 号的查找取决于表中有多少条目。很少有驱动程序应该需要这种映射。它具有以下原型：

```
struct irq_domain *irq_domain_add_tree(struct device_node *of_node, 
                                  const struct irq_domain_ops *ops, 
                                  void *host_data) 
```

1.  `irq_domain_add_nomap()`：您可能永远不会使用此方法。尽管如此，它的整个描述在*Documentation/IRQ-domain.txt*中可以找到，位于内核源树中。它的原型是：

```
struct irq_domain *irq_domain_add_nomap(struct device_node *of_node, 
                              unsigned int max_irq, 
                              const struct irq_domain_ops *ops, 
                              void *host_data)  
```

`of_node` 是指向中断控制器的 DT 节点的指针。`size` 表示域中中断的数量。`ops` 表示映射/取消映射域回调，`host_data` 是控制器的私有数据指针。

由于 IRQ 域在创建时为空（没有映射），因此应该使用`irq_create_mapping()`函数来创建映射并将其分配给域。在下一节中，我们将决定在代码中创建映射的正确位置：

```
unsigned int irq_create_mapping(struct irq_domain *domain, 
                                irq_hw_number_t hwirq) 
```

+   `domain`：这是此硬件中断所属的域，或者对于默认域为`NULL`。

+   `Hwirq`：这是该域空间中的硬件 IRQ 号

当编写同时作为中断控制器的 GPIO 控制器的驱动程序时，`irq_create_mapping()`是从`gpio_chip.to_irq()`回调函数内部调用的，如下所示：

```
return irq_create_mapping(gpiochip->irq_domain, offset); 
```

其他人更喜欢在`probe`函数内提前为每个 hwirq 创建映射，如下所示：

```
for (j = 0; j < gpiochip->chip.ngpio; j++) { 
      irq = irq_create_mapping( 
                 gpiochip ->irq_domain, j); 
} 
```

hwirq 是从 gpiochip 的 GPIO 偏移量。

如果 hwirq 的映射尚不存在，该函数将分配一个新的 Linux `irq_desc`结构，将其与 hwirq 关联，并调用`irq_domain_ops.map()`（通过`irq_domain_associate()`函数）回调，以便驱动程序可以执行任何必需的硬件设置：

```
struct irq_domain_ops { 
   int (*map)(struct irq_domain *d, unsigned int virq, irq_hw_number_t hw); 
   void (*unmap)(struct irq_domain *d, unsigned int virq); 
   int (*xlate)(struct irq_domain *d, struct device_node *node, 
              const u32 *intspec, unsigned int intsize, 
              unsigned long *out_hwirq, unsigned int *out_type); 
}; 
```

+   `.map()`：这在**虚拟 irq**（**virq**）号和 hwirq 号之间创建或更新映射。对于给定的映射，只调用一次。它通常使用`irq_set_chip_and_handler*`将 virq 与给定处理程序进行映射，以便调用`generic_handle_irq()`或`handle_nested_irq`将触发正确的处理程序。这里的魔法被称为`irq_set_chip_and_handler()`函数：

```
void irq_set_chip_and_handler(unsigned int irq, 
          struct irq_chip *chip, irq_flow_handler_t handle) 
```

其中：

+   `irq`：这是作为`map()`函数参数给出的 Linux IRQ。

+   `chip`：这是您的`irq_chip`。一些控制器非常愚蠢，几乎不需要在其`irq_chip`结构中做任何事情。在这种情况下，您应该传递`dummy_irq_chip`，它在`kernel/irq/dummychip.c`中定义，这是为这种控制器定义的内核`irq_chip`结构。

+   `handle`：这确定将调用使用 `request_irq()` 注册的真正处理程序的包装函数。其值取决于 IRQ 是边沿触发还是电平触发。在任何一种情况下，`handle` 应设置为 `handle_edge_irq` 或 `handle_level_irq`。这两个都是内核辅助函数，在调用真正的 IRQ 处理程序之前和之后执行一些技巧。示例如下：

```
    static int pcf857x_irq_domain_map(struct irq_domain  *domain, 
                            unsigned int irq, irq_hw_number_t hw) 
    { 
       struct pcf857x *gpio = domain->host_data; 

       irq_set_chip_and_handler(irq, &dummy_irq_chip,handle_level_irq); 
    #ifdef CONFIG_ARM 
       set_irq_flags(irq, IRQF_VALID); 
    #else 
       irq_set_noprobe(irq); 
    #endif 
       gpio->irq_mapped |= (1 << hw); 

       return 0; 
    } 
```

+   `xlate`：给定 DT 节点和中断说明符，此钩子解码硬件 IRQ 号码和 Linux IRQ 类型值。根据您的 DT 控制器节点中指定的 `#interrupt-cells`，内核提供了一个通用的翻译函数：

+   `irq_domain_xlate_twocell()`：用于直接双元绑定的通用翻译函数。适用于两个单元绑定的 DT IRQ 说明符，其中单元值直接映射到 hwirq 号码和 Linux irq 标志。

+   `irq_domain_xlate_onecell()`：直接单元绑定的通用 xlate。

+   `irq_domain_xlate_onetwocell():` 用于一个或两个单元绑定的通用 xlate。

给出了域操作的示例如下：

```
static struct irq_domain_ops mcp23016_irq_domain_ops = { 
   .map  = mcp23016_irq_domain_map, 
   .xlate  = irq_domain_xlate_twocell, 
}; 
```

当收到中断时，应使用 `irq_find_mapping()` 函数从 hwirq 号码中找到 Linux IRQ 号码。当然，在返回之前必须存在映射。Linux IRQ 号码始终与 `struct irq_desc` 结构相关联，这是 Linux 用来描述 IRQ 的结构：

```
struct irq_desc { 
   struct irq_common_data irq_common_data; 
   struct irq_data irq_data; 
   unsigned int __percpu *kstat_irqs; 
   irq_flow_handler_t handle_irq; 
   struct irqaction *action; 
   unsigned int irqs_unhandled; 
   raw_spinlock_t lock; 
   struct cpumask *percpu_enabled; 
   atomic_t threads_active; 
   wait_queue_head_t wait_for_threads; 
#ifdef CONFIG_PM_SLEEP 
   unsigned int nr_actions; 
   unsigned int no_suspend_depth; 
   unsigned int  force_resume_depth; 
#endif 
#ifdef CONFIG_PROC_FS 
   struct proc_dir_entry *dir; 
#endif 
   int parent_irq; 
   struct module *owner; 
   const char *name; 
}; 
```

这里未描述的一些字段是内部字段，由 IRQ 核心使用：

+   `irq_common_data` 是传递给芯片函数的每个 IRQ 和芯片数据

+   `kstat_irqs` 是自启动以来每个 CPU 的 IRQ 统计信息

+   `handle_irq` 是高级别 IRQ 事件处理程序

+   `action` 表示此描述符的 IRQ 动作列表

+   `irqs_unhandled` 是虚假未处理中断的统计字段

+   `lock` 表示 SMP 的锁定

+   `threads_active` 是当前正在运行此描述符的 IRQ 动作线程的数量

+   `wait_for_threads` 表示 `sync_irq` 等待线程处理程序的等待队列

+   `nr_actions` 是此描述符上安装的动作数量

+   `no_suspend_depth` 和 `force_resume_depth` 表示具有 `IRQF_NO_SUSPEND` 或 `IRQF_FORCE_RESUME` 标志设置的 IRQ 描述符上的 `irqactions` 数量

+   `dir` 表示 `/proc/irq/ procfs` 条目

+   `name` 命名了流处理程序，在 `/proc/interrupts` 输出中可见

`irq_desc.action` 字段是 `irqaction` 结构的列表，每个结构记录了与关联中断源的中断处理程序的地址。每次调用内核的 `request_irq()` 函数（或线程版本 `o`）都会在列表的末尾创建一个 `struct irqaction` 结构。例如，对于共享中断，该字段将包含与注册的处理程序数量相同的 IRQ 动作；

```
struct irqaction { 
   irq_handler_t handler; 
   void *dev_id; 
   void __percpu *percpu_dev_id; 
   struct irqaction *next; 
   irq_handler_t thread_fn; 
   struct task_struct *thread; 
   unsigned int irq; 
   unsigned int flags; 
   unsigned long thread_flags; 
   unsigned long thread_mask; 
   const char *name; 
   struct proc_dir_entry *dir; 
}; 
```

+   `handler` 是非线程（硬件）中断处理程序函数

+   `name` 是设备的名称

+   `dev_id` 是用于标识设备的 cookie

+   `percpu_dev_id` 是用于标识设备的 cookie

+   `next` 是共享中断的下一个 IRQ 动作的指针

+   `irq` 是 Linux 中断号

+   `flags` 表示 IRQ 的标志（参见 `IRQF_*`）

+   `thread_fn` 是线程中断处理程序函数，用于线程中断

+   `thread` 是线程中断的线程结构的指针

+   `thread_flags` 表示与线程相关的标志

+   `thread_mask` 是用于跟踪线程活动的位掩码

+   `dir` 指向 `/proc/irq/NN/<name>/` 条目

`irqaction.handler` 字段引用的中断处理程序只是与处理来自特定外部设备的中断相关的函数，它们对于将这些中断请求传递给主机微处理器的方式几乎没有（如果有的话）了解。它们不是微处理器级别的中断服务例程，因此不会通过 RTE 或类似的与中断相关的操作码退出。这使得基于中断驱动的设备驱动程序在不同的微处理器架构之间具有很大的可移植性

以下是`struct irq_data`结构的重要字段的定义，该结构是传递给芯片函数的每个 IRQ 芯片数据：

```
struct irq_data { 
   [...] 
   unsigned int irq; 
   unsigned long hwirq; 
   struct irq_common_data *common; 
   struct irq_chip *chip; 
   struct irq_domain *domain; 
   void *chip_data; 
}; 
```

+   `irq`是中断号（Linux IRQ）

+   `hwirq`是硬件中断号，局限于`irq_data.domain`中断域

+   `common`指向所有 irqchips 共享的数据

+   `chip`表示底层中断控制器硬件访问

+   `domain`表示中断转换域，负责在 hwirq 号和 Linux irq 号之间进行映射

+   `chip_data`是每个芯片方法的特定于平台的芯片私有数据，以允许共享芯片实现

# 高级外围 IRQ 管理

在第三章 *内核设施和辅助函数*中，我们介绍了外围 IRQ，使用`request_irq()`和`request_threaded_irq()`。使用`request_irq()`，可以注册一个在原子上下文中执行的处理程序（顶半部），从中可以使用在同一章节中讨论的不同机制之一调度底半部。另一方面，使用`request_thread_irq()`，可以为函数提供顶部和底部，以便前者将作为 hardirq 处理程序运行，可以决定引发第二个线程处理程序，后者将在内核线程中运行。

这些方法的问题在于，有时，请求 IRQ 的驱动程序不知道提供此 IRQ 线的中断的性质，特别是当中断控制器是一个离散芯片（通常是通过 SPI 或 I2C 总线连接的 GPIO 扩展器）时。现在有了`request_any_context_irq()`，请求 IRQ 的驱动程序知道处理程序是否在线程上下文中运行，并相应地调用`request_threaded_irq()`或`request_irq()`。这意味着无论我们的设备关联的 IRQ 来自可能不休眠的中断控制器（内存映射）还是来自可以休眠的中断控制器（在 I2C/SPI 总线后面），都不需要更改代码。它的原型如下：

```
int request_any_context_irq ( unsigned int irq, irq_handler_t handler, 
             unsigned long flags,  const char * name,  void * dev_id); 
```

以下是函数中每个参数的含义：

+   `irq`表示要分配的中断线。

+   `handler`是在发生 IRQ 时要调用的函数。根据上下文，此函数可能作为 hardirq 运行，也可能作为线程运行。

+   `flags`表示中断类型标志。与`request_irq()`中的标志相同。

+   `name`将用于调试目的，在`/proc/interrupts`中命名中断。

+   `dev_id`是传递回处理程序函数的 cookie。

`request_any_context_irq()`表示可以获得 hardirq 或 treaded。它的工作方式类似于通常的`request_irq()`，只是它检查 IRQ 级别是否配置为嵌套，并调用正确的后端。换句话说，它根据上下文选择硬件中断或线程处理方法。此函数在失败时返回负值。成功时，它返回`IRQC_IS_HARDIRQ`或`IRQC_IS_NESTED`。以下是一个用例：

```
static irqreturn_t packt_btn_interrupt(int irq, void *dev_id) 
{ 
    struct btn_data *priv = dev_id; 

   input_report_key(priv->i_dev, BTN_0, 
                    gpiod_get_value(priv->btn_gpiod) & 1); 
    input_sync(priv->i_dev); 
   return IRQ_HANDLED; 
} 

static int btn_probe(struct platform_device *pdev) 
{ 
    struct gpio_desc *gpiod; 
    int ret, irq; 

    [...] 
    gpiod = gpiod_get(&pdev->dev, "button", GPIOD_IN); 
    if (IS_ERR(gpiod)) 
        return -ENODEV; 

    priv->irq = gpiod_to_irq(priv->btn_gpiod); 
    priv->btn_gpiod = gpiod; 

    [...] 

    ret = request_any_context_irq(priv->irq, 
                  packt_btn_interrupt, 
                  (IRQF_TRIGGER_FALLING | IRQF_TRIGGER_RISING), 
                  "packt-input-button", priv); 
    if (ret < 0) { 
        dev_err(&pdev->dev, 
            "Unable to acquire interrupt for GPIO line\n"); 
        goto err_btn; 
    } 

    return ret; 
} 
```

上述代码是输入设备驱动程序的驱动程序示例的摘录。实际上，它是下一章中使用的代码。使用`request_any_context_irq()`的优势在于，不需要关心在 IRQ 处理程序中可以做什么，因为处理程序将运行的上下文取决于提供 IRQ 线的中断控制器。在我们的示例中，如果 GPIO 属于坐落在 I2C 或 SPI 总线上的控制器，处理程序将是线程化的。否则，处理程序将在 hardirq 中运行。

# 中断请求和传播

让我们考虑以下图，它表示链接的 IRQ 流

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00035.gif)

中断请求始终在 Linux IRQ 上执行（而不是 hwirq）。在 Linux 上请求 IRQ 的一般函数是`request_threaded_irq()`或`request_irq()`，它在内部调用前者：

```
int request_threaded_irq(unsigned int irq, irq_handler_t handler, 
                  irq_handler_t thread_fn, unsigned long irqflags, 
                  const char *devname, void *dev_id) 
```

当调用该函数时，该函数使用`irq_to_desc()`宏提取与 IRQ 关联的`struct irq_desc`，然后分配一个新的`struct irqaction`结构并设置它，填充处理程序、标志等参数。

```
action->handler = handler; 
action->thread_fn = thread_fn; 
action->flags = irqflags; 
action->name = devname; 
action->dev_id = dev_id; 
```

该函数最终通过调用`__setup_irq()`（通过`setup_irq()`）函数将描述符插入/注册到适当的 IRQ 列表中，该函数在`kernel/irq/manage.c`中定义。

现在，当发生中断时，内核会执行一些汇编代码以保存当前状态，并跳转到特定于体系结构的处理程序`handle_arch_irq`，该处理程序在`arch/arm/kernel/setup.c`的`setup_arch()`函数中的我们平台的`struct machine_desc`的`handle_irq`字段中设置：

```
handle_arch_irq = mdesc->handle_irq 
```

对于使用 ARM GIC 的 SoC，`handle_irq`回调使用`gic_handle_irq`设置，可以在`drivers/irqchip/irq-gic.c`或`drivers/irqchip/irq-gic-v3.c`中找到：

```
set_handle_irq(gic_handle_irq); 
```

`gic_handle_irq()`调用`handle_domain_irq()`，执行`generic_handle_irq()`，然后调用`generic_handle_irq_desc()`，最终调用`desc->handle_irq()`。查看`include/linux/irqdesc.h`以获取最后一次调用，查看`arch/arm/kernel/irq.c`以获取其他函数调用。`handle_irq`是实际的流处理程序调用，我们将其注册为`mcp23016_irq_handler`。

`gic_hande_irq()`是一个 GIC 中断处理程序。`generic_handle_irq()`将执行 SoC 的 GPIO4 IRQ 的处理程序，该处理程序将寻找负责中断的 GPIO 引脚，并调用`generic_handle_irq_desc()`，依此类推。现在您已经熟悉了中断传播，让我们通过编写自己的中断控制器来切换到一个实际的例子。

# 链接 IRQ

本节描述了父级中断处理程序如何调用子级中断处理程序，进而调用它们的子级中断处理程序，依此类推。内核提供了两种方法来在父级（中断控制器）设备的 IRQ 处理程序中调用子设备的中断处理程序，这些方法是链接和嵌套方法：

# 链接中断

这种方法用于 SoC 的内部 GPIO 控制器，它们是内存映射的，其访问不会休眠。链接意味着这些中断只是函数调用链（例如，SoC 的 GPIO 模块中断处理程序是从 GIC 中断处理程序调用的，就像函数调用一样）。`generic_handle_irq()`用于链接子 IRQ 处理程序，并在父 hwirq 处理程序内调用。即使在子中断处理程序内部，我们仍然处于原子上下文（硬件中断）。不能调用可能休眠的函数。

# 嵌套中断

这种方法用于坐在慢总线上的控制器，比如 I2C（例如，GPIO 扩展器），其访问可能会休眠（I2C 函数可能会休眠）。嵌套意味着这些中断处理程序不在硬件上下文中运行（它们实际上不是 hwirq，它们不在原子上下文中），而是线程化的，可以被抢占（或被另一个中断中断）。`handle_nested_irq()`用于创建嵌套中断子 IRQ。处理程序在`handle_nested_irq()`函数创建的新线程内部被调用；我们需要它们在进程上下文中运行，以便我们可以调用可能会休眠的总线函数（比如可能会休眠的 I2C 函数）。

# 案例研究- GPIO 和 IRQ 芯片

让我们考虑下面的图，它将一个中断控制器设备与另一个设备连接起来，我们将用它来描述中断复用：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00036.jpg)

mcp23016 IRQ 流程

假设您已将`io_1`和`io_2`配置为中断。即使中断发生在`io_1`或`io_2`上，相同的中断线也会触发中断控制器。现在 GPIO 驱动程序必须找出读取 GPIO 的中断状态寄存器，以找出哪个中断（`io_1`或`io_2`）实际上已触发。因此，在这种情况下，单个中断线是 16 个 GPIO 中断的复用。

现在让我们修改原始的 mcp23016 驱动程序，该驱动程序在第十五章中编写，*GPIO 控制器驱动程序 - gpio_chip*，以支持首先作为中断控制器的 IRQ 域 API。第二部分将介绍新的和推荐的 gpiolib irqchip API。这将被用作逐步指南来编写中断控制器驱动程序，至少对于 GPIO 控制器。

# 传统 GPIO 和 IRQ 芯片

1.  第一步，为我们的 gpiochip 分配一个`struct irq_domain`，它将存储 hwirq 和 virq 之间的映射。线性映射对我们来说是合适的。我们在`probe`函数中这样做。该域将保存我们的驱动程序希望提供的 IRQ 数量。例如，对于 I/O 扩展器，IRQ 的数量可以是扩展器提供的 GPIO 数量：

```
my_gpiochip->irq_domain = irq_domain_add_linear( client->dev.of_node, 
             my_gpiochip->chip.ngpio, &mcp23016_irq_domain_ops, NULL); 
```

`host_data`参数是`NULL`。因此，您可以传递任何您需要的数据结构。在分配域之前，我们的域 ops 结构应该被定义：

```
static struct irq_domain_ops mcp23016_irq_domain_ops = { 
   .map  = mcp23016_irq_domain_map, 
   .xlate  = irq_domain_xlate_twocell, 
}; 
```

在填充我们的 IRQ 域 ops 结构之前，我们必须至少定义`.map()`回调：

```
static int mcp23016_irq_domain_map( 
              struct irq_domain *domain, 
              unsigned int virq, irq_hw_number_t hw) 
{ 
   irq_set_chip_and_handler(virq, 
               &dummy_irq_chip, /* Dumb irqchip */ 
               handle_level_irq); /* Level trigerred irq */ 
   return 0; 
} 
```

我们的控制器不够智能。因此，没有必要设置`irq_chip`。我们将使用内核为这种芯片提供的一个：`dummy_irq_chip`。有些控制器足够智能，需要设置`irq_chip`。在`drivers/gpio/gpio-mcp23s08.c`中查看。

下一个 ops 回调是`.xlate`。在这里，我们再次使用内核提供的帮助程序。`irq_domain_xlate_twocell`是一个能够解析具有两个单元的中断指定符的帮助程序。我们可以在我们的控制器 DT 节点中添加`interrupt-cells = <2>;`。

1.  下一步是使用`irq_create_mapping()`函数填充域与 IRQ 映射。在我们的驱动程序中，我们将在`gpiochip.to_irq`回调中执行此操作，这样每当有人在 GPIO 上调用`gpio{d}_to_irq()`时，如果映射存在，它将被返回，如果不存在，它将被创建：

```
static int mcp23016_to_irq(struct gpio_chip *chip, 
                           unsigned offset) 
{ 
   return irq_create_mapping(chip->irq_domain, offset); 
} 
```

我们可以在`probe`函数中为每个 GPIO 都这样做，并在`.to_irq`函数中只调用`irq_find_mapping()`。

1.  现在仍然在`probe`函数中，我们需要注册我们控制器的 IRQ 处理程序，这个处理程序负责调用引发其引脚中断的正确处理程序：

```
devm_request_threaded_irq(client->irq, NULL, 
                          mcp23016_irq, irqflags, 
                          dev_name(chip->parent), mcp); 
```

在注册 IRQ 之前，函数`mcp23016`应该已经被定义：

```
static irqreturn_t mcp23016_irq(int irq, void *data) 
{ 
    struct mcp23016 *mcp = data; 
    unsigned int child_irq, i; 
    /* Do some stuff */ 
    [...] 
    for (i = 0; i < mcp->chip.ngpio; i++) { 
        if (gpio_value_changed_and_raised_irq(i)) { 
            child_irq = 
                  irq_find_mapping(mcp->chip.irqdomain, i); 
            handle_nested_irq(child_irq); 
        } 
    } 

    return IRQ_HANDLED; 
} 
```

`handle_nested_irq()`已经在前面的部分中描述，将为每个注册的处理程序创建一个专用线程。

# 新的 gpiolib irqchip API

几乎每个 GPIO 控制器驱动程序都在使用 IRQ 域来实现相同的目的。内核开发人员决定将这些代码移动到 gpiolib 框架中，通过`GPIOLIB_IRQCHIP` Kconfig 符号，以便协调开发并避免冗余代码。

该代码部分有助于处理 GPIO irqchips 和相关的`irq_domain`和资源分配回调，以及它们的设置，使用减少的帮助函数集。这些是`gpiochip_irqchip_add()`和`gpiochip_set_chained_irqchip()`。

`gpiochip_irqchip_add():` 这将一个 irqchip 添加到一个 gpiochip 中。这个函数的作用是：

+   将`gpiochip.to_irq`字段设置为`gpiochip_to_irq`，这是一个 IRQ 回调，只返回`irq_find_mapping(chip->irqdomain, offset);`

+   使用`irq_domain_add_simple()`函数为 gpiochip 分配一个 irq_domain，传递一个内核 IRQ 核心`irq_domain_ops`，称为`gpiochip_domain_ops`，并在`drivers/gpio/gpiolib.c`中定义。

+   使用`irq_create_mapping()`函数从 0 到`gpiochip.ngpio`创建映射

它的原型如下：

```
int gpiochip_irqchip_add(struct gpio_chip *gpiochip, 
                struct irq_chip *irqchip, 
                unsigned int first_irq, 
                irq_flow_handler_t handler, 
                unsigned int type) 
```

`gpiochip` 是我们的 GPIO 芯片，要添加 irqchip 到其中，`irqchip` 是要添加到 gpiochip 的 irqchip。如果没有动态分配，`first_irq` 是要从中分配 gpiochip IRQ 的基础（第一个）IRQ。`handler` 是要使用的 IRQ 处理程序（通常是预定义的 IRQ 核心函数），`type` 是该 irqchip 上 IRQ 的默认类型，传递 `IRQ_TYPE_NONE` 以使核心避免在硬件中设置任何默认类型。

此函数将处理两个单元格的简单 IRQ（因为它将 `irq_domain_ops.xlate` 设置为 `irq_domain_xlate_twocell`），并假定 gpiochip 上的所有引脚都可以生成唯一的 IRQ。

```
static const struct irq_domain_ops gpiochip_domain_ops = { 
   .map  = gpiochip_irq_map, 
   .unmap = gpiochip_irq_unmap, 
   /* Virtually all GPIO irqchips are twocell:ed */ 
   .xlate = irq_domain_xlate_twocell, 
}; 
```

`gpiochip_set_chained_irqchip()`：此函数将链式 irqchip 设置为从父 IRQ 到 `gpio_chip`，并将 `struct gpio_chip` 的指针传递为处理程序数据：

```
void gpiochip_set_chained_irqchip(struct gpio_chip *gpiochip, 
                       struct irq_chip *irqchip, int parent_irq, 
                       irq_flow_handler_t parent_handler) 
```

`parent_irq` 是此芯片连接到的 IRQ 号。在我们的 mcp23016 中，如 *Case study-GPIO and IRQ chip* 部分中的图所示，它对应于 `gpio4_29` 线的 IRQ。换句话说，它是此链式 irqchip 的父 IRQ 号。`parent_handler` 是累积的从 gpiochip 出来的 IRQ 的父中断处理程序。如果中断是嵌套而不是级联的，可以在此处理程序参数中传递 `NULL`。

有了这个新的 API，我们的 `probe` 函数中需要添加的唯一代码是：

```
/* Do we have an interrupt line? Enable the irqchip */ 
if (client->irq) { 
    status = gpiochip_irqchip_add(&gpio->chip, &dummy_irq_chip, 
                            0, handle_level_irq, IRQ_TYPE_NONE); 
    if (status) { 
        dev_err(&client->dev, "cannot add irqchip\n"); 
        goto fail_irq; 
    } 

    status = devm_request_threaded_irq(&client->dev, client->irq, 
                           NULL, mcp23016_irq, IRQF_ONESHOT | 
                           IRQF_TRIGGER_FALLING | IRQF_SHARED, 
                           dev_name(&client->dev), gpio); 
    if (status) 
       goto fail_irq; 

    gpiochip_set_chained_irqchip(&gpio->chip, 
                            &dummy_irq_chip, client->irq, NULL); 
} 
```

IRQ 核心为我们做了一切。甚至不需要定义 `gpiochip.to_irq` 函数，因为 API 已经设置了它。我们的示例使用了 IRQ 核心 `dummy_irq_chip`，但也可以自己定义。自内核 v4.10 版本以来，还添加了另外两个函数：`gpiochip_irqchip_add_nested()` 和 `gpiochip_set_nested_irqchip()`。请查看 *Documentation/gpio/driver.txt* 了解更多细节。在同一内核版本中使用此 API 的驱动程序是 `drivers/gpio/gpio-mcp23s08.c`。

# 中断控制器和 DT

现在我们将在 DT 中声明我们的控制器。如果你还记得第六章：*设备树的概念*，每个中断控制器必须具有设置为布尔属性 interrupt-controller 的属性。第二个强制性的布尔属性是 `gpio-controller`，因为它也是 GPIO 控制器。我们需要定义我们的设备的中断描述符需要多少个单元格。由于我们已将 `irq_domain_ops.xlate` 字段设置为 `irq_domain_xlate_twocell`，`#interrupt-cells` 应该是 2：

```
expander: mcp23016@20 { 
    compatible = "microchip,mcp23016"; 
    reg = <0x20>; 
    interrupt-controller; 
    #interrupt-cells = <2>; 
    gpio-controller; 
    #gpio-cells = <2>; 
    interrupt-parent = <&gpio4>; 
    interrupts = <29 IRQ_TYPE_EDGE_FALLING>; 
}; 
```

`interrupt-parent` 和 `interrupts` 属性描述了中断线连接。

最后，让我们说一下，我们有一个 mcp23016 的驱动程序，以及两个其他设备的驱动程序：`foo_device` 和 `bar_device`，当然都在 CPU 上运行。在 `foo_device` 驱动程序中，我们希望在 `mcp23016` 的 `io_2` 引脚发生变化时请求中断。`bar_device` 驱动程序需要分别用于复位和电源 GPIO 的 `io_8` 和 `io_12`。让我们在 DT 中声明这一点：

```
foo_device: foo_device@1c { 
    reg = <0x1c>; 
    interrupt-parent = <&expander>; 
    interrupts = <2 IRQ_TYPE_EDGE_RISING>; 
}; 

bar_device { 
    reset-gpios = <&expander 8 GPIO_ACTIVE_HIGH>; 
    power-gpios = <&expander 12 GPIO_ACTIVE_HIGH>; 
    /* Other properties do here */ 
}; 
```

# 总结

现在 IRQ 多路复用对你来说已经没有秘密了。我们讨论了 Linux 系统下 IRQ 管理的最重要的元素，即 IRQ 域 API。你已经掌握了开发中断控制器驱动程序的基础，以及从 DT 中管理它们的绑定。我们讨论了 IRQ 传播，以便了解从请求到处理的过程。这一章将帮助你理解下一章中的中断驱动部分，该部分涉及输入设备驱动程序。


# 第十七章：输入设备驱动程序

输入设备是可以与系统交互的设备。这些设备是按钮、键盘、触摸屏、鼠标等。它们通过发送事件来工作，由输入核心捕获并广播到系统中。本章将解释输入核心用于处理输入设备的每个结构。也就是说，我们将看到如何从用户空间管理事件。

在本章中，我们将涵盖以下主题：

+   输入核心数据结构

+   分配和注册输入设备，以及轮询设备系列

+   生成并向输入核心报告事件

+   用户空间的输入设备

+   编写驱动程序示例

# 输入设备结构

首先，要与输入子系统进行接口的主文件是 `linux/input.h`：

```
#include <linux/input.h> 
```

无论输入设备的类型是什么，它发送的事件的类型是什么，输入设备在内核中都表示为 `struct input_dev` 的实例：

```
struct input_dev { 
  const char *name; 
  const char *phys; 

  unsigned long evbit[BITS_TO_LONGS(EV_CNT)]; 
  unsigned long keybit[BITS_TO_LONGS(KEY_CNT)]; 
  unsigned long relbit[BITS_TO_LONGS(REL_CNT)]; 
  unsigned long absbit[BITS_TO_LONGS(ABS_CNT)]; 
  unsigned long mscbit[BITS_TO_LONGS(MSC_CNT)]; 

  unsigned int repeat_key; 

  int rep[REP_CNT]; 
  struct input_absinfo *absinfo; 
  unsigned long key[BITS_TO_LONGS(KEY_CNT)]; 

  int (*open)(struct input_dev *dev); 
  void (*close)(struct input_dev *dev); 

  unsigned int users; 
  struct device dev; 

  unsigned int num_vals; 
  unsigned int max_vals; 
  struct input_value *vals; 

  bool devres_managed; 
}; 
```

字段的含义如下：

+   `name` 表示设备的名称。

+   `phys` 是设备在系统层次结构中的物理路径。

+   `evbit` 是设备支持的事件类型的位图。一些类型的区域如下：

+   `EV_KEY` 用于支持发送键事件（键盘、按钮等）的设备。

+   `EV_REL` 用于支持发送相对位置的设备（鼠标、数字化器等）

+   `EV_ABS` 用于支持发送绝对位置（游戏手柄）的设备

事件列表在内核源代码中的 `include/linux/input-event-codes.h` 文件中可用。我们使用 `set_bit()` 宏来根据我们的输入设备功能设置适当的位。当然，设备可以支持多种类型的事件。例如，鼠标将同时设置 `EV_KEY` 和 `EV_REL`。

```
set_bit(EV_KEY, my_input_dev->evbit); 
set_bit(EV_REL, my_input_dev->evbit); 
```

+   `keybit` 用于启用 `EV_KEY` 类型的设备，是该设备公开的键/按钮的位图。例如，`BTN_0`，`KEY_A`，`KEY_B`等。键/按钮的完整列表在 `include/linux/input-event-codes.h` 文件中。

+   `relbit` 用于启用 `EV_REL` 类型的设备，是设备的相对轴的位图。例如，`REL_X`，`REL_Y`，`REL_Z`，`REL_RX`等。请查看 `include/linux/input-event-codes.h` 获取完整列表。

+   `absbit` 用于启用 `EV_ABS` 类型的设备，是设备的绝对轴的位图。例如，`ABS_Y`，`ABS_X`等。请查看相同的先前文件以获取完整列表。

+   `mscbit` 用于启用 `EV_MSC` 类型的设备，是设备支持的各种杂项事件的位图。

+   `repeat_key` 存储最后按下的键的键码；用于实现软件自动重复。

+   `rep`，自动重复参数（延迟、速率）的当前值。

+   `absinfo` 是一个 `&struct input_absinfo` 元素的数组，其中包含有关绝对轴的信息（当前值、最小值、最大值、平坦值、模糊值、分辨率）。您应该使用 `input_set_abs_params()` 函数来设置这些值。

```
void input_set_abs_params(struct input_dev *dev, unsigned int axis, 

                             int min, int max, int fuzz, int flat) 
```

+   `min` 和 `max` 指定了较低和较高的边界值。`fuzz` 表示指定输入设备的指定通道上的预期噪音。以下是一个示例，我们仅设置每个通道的边界：

```
#define ABSMAX_ACC_VAL 0x01FF 
#define ABSMIN_ACC_VAL -(ABSMAX_ACC_VAL) 
[...] 
set_bit(EV_ABS, idev->evbit); 
input_set_abs_params(idev, ABS_X, ABSMIN_ACC_VAL, 
                     ABSMAX_ACC_VAL, 0, 0); 
input_set_abs_params(idev, ABS_Y, ABSMIN_ACC_VAL, 
                     ABSMAX_ACC_VAL, 0, 0); 
input_set_abs_params(idev, ABS_Z, ABSMIN_ACC_VAL, 
                     ABSMAX_ACC_VAL, 0, 0); 
```

+   `key` 反映了设备键/按钮的当前状态。

+   `open` 是在第一个用户调用 `input_open_device()` 时调用的方法。使用此方法来准备设备，例如中断请求、轮询线程启动等。

+   `close` 在最后一个用户调用 `input_close_device()` 时被调用。在这里，您可以停止轮询（这会消耗大量资源）。

+   `users` 存储了打开此设备的用户（输入处理程序）的数量。它被 `input_open_device()` 和 `input_close_device()` 使用，以确保只有在第一个用户打开设备时才调用 `dev->open()`，并且在最后一个用户关闭设备时调用 `dev->close()`。

+   `dev` 是与此设备关联的设备结构（用于设备模型）。

+   `num_vals` 是当前帧中排队的值的数量。

+   `max_vals` 是在一个帧中排队的值的最大数量。

+   `Vals` 是当前帧中排队的值的数组。

+   `devres_managed` 表示设备由 `devres` 框架管理，不需要显式取消注册或释放。

# 分配和注册输入设备

在注册并向输入设备发送事件之前，应使用 `input_allocate_device()` 函数为其分配内存。为了释放先前为未注册的输入设备分配的内存，应使用 `input_free_device()` 函数。如果设备已经注册，应改用 `input_unregister_device()`。像每个需要内存分配的函数一样，我们可以使用函数的资源管理版本：

```
struct input_dev *input_allocate_device(void) 
struct input_dev *devm_input_allocate_device(struct device *dev) 

void input_free_device(struct input_dev *dev) 
static void devm_input_device_unregister(struct device *dev, 
                                         void *res) 
int input_register_device(struct input_dev *dev) 
void input_unregister_device(struct input_dev *dev) 
```

设备分配可能会休眠，因此不能在原子上下文中调用，也不能在持有自旋锁时调用。

以下是一个位于 I2C 总线上的输入设备的 `probe` 函数的摘录：

```
struct input_dev *idev; 
int error; 

idev = input_allocate_device(); 
if (!idev) 
    return -ENOMEM; 

idev->name = BMA150_DRIVER; 
idev->phys = BMA150_DRIVER "/input0"; 
idev->id.bustype = BUS_I2C; 
idev->dev.parent = &client->dev; 

set_bit(EV_ABS, idev->evbit); 
input_set_abs_params(idev, ABS_X, ABSMIN_ACC_VAL, 
                     ABSMAX_ACC_VAL, 0, 0); 
input_set_abs_params(idev, ABS_Y, ABSMIN_ACC_VAL, 
                     ABSMAX_ACC_VAL, 0, 0); 
input_set_abs_params(idev, ABS_Z, ABSMIN_ACC_VAL, 
                     ABSMAX_ACC_VAL, 0, 0); 

error = input_register_device(idev); 
if (error) { 
    input_free_device(idev); 
    return error; 
} 

error = request_threaded_irq(client->irq, 
            NULL, my_irq_thread, 
            IRQF_TRIGGER_RISING | IRQF_ONESHOT, 
            BMA150_DRIVER, NULL); 
if (error) { 
    dev_err(&client->dev, "irq request failed %d, error %d\n", 
            client->irq, error); 
    input_unregister_device(bma150->input); 
    goto err_free_mem; 
} 
```

# 轮询输入设备子类

轮询输入设备是一种特殊类型的输入设备，它依赖轮询来感知设备状态的变化，而通用输入设备类型依赖于 IRQ 来感知变化并将事件发送到输入核心。

内核中描述了一个轮询输入设备，它是 `struct input_polled_dev` 结构的一个实例，它是通用 `struct input_dev` 结构的一个包装器：

```
struct input_polled_dev { 
    void *private; 

    void (*open)(struct input_polled_dev *dev); 
    void (*close)(struct input_polled_dev *dev); 
    void (*poll)(struct input_polled_dev *dev); 
    unsigned int poll_interval; /* msec */ 
    unsigned int poll_interval_max; /* msec */ 
    unsigned int poll_interval_min; /* msec */ 

    struct input_dev *input; 

    bool devres_managed; 
}; 
```

这个结构中元素的含义如下：

+   `private` 是驱动程序的私有数据。

+   `open` 是一个可选的方法，用于准备设备进行轮询（启用设备，可能刷新设备状态）。

+   `close` 是一个可选的方法，当设备不再被轮询时调用。它用于将设备置于低功耗模式。

+   `poll` 是一个强制性的方法，每当需要轮询设备时都会调用。它以 `poll_interval` 的频率调用。

+   `poll_interval` 是应调用 `poll()` 方法的频率。默认为 500 毫秒，除非在注册设备时被覆盖。

+   `poll_interval_max` 指定了轮询间隔的上限。默认为 `poll_interval` 的初始值。

+   `poll_interval_min` 指定了轮询间隔的下限。默认为 0。

+   `input` 是轮询设备构建的输入设备。它必须由驱动程序正确初始化（ID、名称、位）。轮询输入设备只提供了一个接口，用于使用轮询而不是 IRQ 来感知设备状态变化。

使用 `input_allocate_polled_device()` 和 `input_free_polled_device()` 来分配/释放 `struct input_polled_dev` 结构。您应该注意初始化其中嵌入的 `struct input_dev` 的强制性字段。轮询间隔也应该设置，否则默认为 500 毫秒。也可以使用资源管理版本。两个原型如下：

```
struct input_polled_dev *devm_input_allocate_polled_device(struct             device *dev) 
struct input_polled_dev *input_allocate_polled_device(void) 
void input_free_polled_device(struct input_polled_dev *dev) 
```

对于资源管理的设备，输入核心将设置字段 `input_dev->devres_managed` 为 true。

在分配和正确初始化字段之后，可以使用 `input_register_polled_device()` 注册轮询输入设备，成功时返回 0。反向操作（取消注册）使用 `input_unregister_polled_device()` 函数完成：

```
int input_register_polled_device(struct input_polled_dev *dev) 
void  input_unregister_polled_device(struct input_polled_dev *dev) 
```

这样的设备的 `probe()` 函数的典型示例如下：

```
static int button_probe(struct platform_device *pdev) 
{ 
    struct my_struct *ms; 
    struct input_dev *input_dev; 
    int retval; 

    ms = devm_kzalloc(&pdev->dev, sizeof(*ms), GFP_KERNEL); 
    if (!ms) 
        return -ENOMEM; 

    ms->poll_dev = input_allocate_polled_device(); 
    if (!ms->poll_dev){ 
        kfree(ms); 
        return -ENOMEM; 
    } 

    /* This gpio is not mapped to IRQ */ 
    ms->reset_btn_desc = gpiod_get(dev, "reset", GPIOD_IN); 

    ms->poll_dev->private = ms ; 
    ms->poll_dev->poll = my_btn_poll; 
    ms->poll_dev->poll_interval = 200; /* Poll every 200ms */ 
    ms->poll_dev->open = my_btn_open; /* consist */ 

    input_dev = ms->poll_dev->input; 
    input_dev->name = "System Reset Btn"; 

    /* The gpio belong to an expander sitting on I2C */ 
    input_dev->id.bustype = BUS_I2C;  
    input_dev->dev.parent = &pdev->dev; 

    /* Declare the events generated by this driver */ 
    set_bit(EV_KEY, input_dev->evbit); 
    set_bit(BTN_0, input_dev->keybit); /* buttons */ 

    retval = input_register_polled_device(mcp->poll_dev); 
    if (retval) { 
        dev_err(&pdev->dev, "Failed to register input device\n"); 
        input_free_polled_device(ms->poll_dev); 
        kfree(ms);   
    } 
    return retval; 
} 
```

以下是我们的 `struct my_struct` 结构的样子：

```
struct my_struct { 
    struct gpio_desc *reset_btn_desc; 
    struct input_polled_dev *poll_dev; 
} 
```

以下是 `open` 函数的样子：

```
static void my_btn_open(struct input_polled_dev *poll_dev) 
{ 
    struct my_strut *ms = poll_dev->private; 
    dev_dbg(&ms->poll_dev->input->dev, "reset open()\n"); 
} 
```

`open` 方法用于准备设备所需的资源。对于这个例子，我们实际上不需要这个方法。

# 生成和报告输入事件

设备分配和注册是必不可少的，但它们不是输入设备驱动程序的主要目标，输入设备驱动程序旨在向输入核心报告。根据设备支持的事件类型，内核提供了适当的 API 来将它们报告给核心。

给定一个支持 `EV_XXX` 的设备，相应的报告函数将是 `input_report_xxx()` 。以下表格显示了最重要的事件类型及其报告函数之间的映射关系：

| **事件类型** | **报告函数** | **代码示例** |
| --- | --- | --- |
| `EV_KEY` | `input_report_key()` | `input_report_key(poll_dev->input, BTN_0, gpiod_get_value(ms-> reset_btn_desc) & 1)` ; |
| `EV_REL` | `input_report_rel()` | `input_report_rel(nunchuk->input, REL_X, (nunchuk->report.joy_x - 128)/10)` ; |
| `EV_ABS` | `input_report_abs()` | `input_report_abs(bma150->input, ABS_X, x_value)` ;`input_report_abs(bma150->input, ABS_Y, y_value)` ;`input_report_abs(bma150->input, ABS_Z, z_value)` ; |

它们的原型如下：

```
void input_report_abs(struct input_dev *dev, 
                      unsigned int code, int value) 
void input_report_key(struct input_dev *dev, 
                      unsigned int code, int value) 
void input_report_rel(struct input_dev *dev, 
                      unsigned int code, int value) 
```

可用报告函数的列表可以在内核源文件 `include/linux/input.h` 中找到。它们都具有相同的框架：

+   `dev` 是负责事件的输入设备。

+   `code` 表示事件代码，例如 `REL_X` 或 `KEY_BACKSPACE` 。完整的列表在 `include/linux/input-event-codes.h` 中。

+   `value` 是事件携带的值。对于 `EV_REL` 事件类型，它携带相对变化。对于 `EV_ABS`（如摇杆等）事件类型，它包含绝对的新值。对于 `EV_KEY` 事件类型，应设置为 `0` 表示按键释放，`1` 表示按键按下，`2` 表示自动重复。

在报告了所有更改之后，驱动程序应调用 `input_sync()` 来指示输入设备此事件已完成。输入子系统将这些事件收集到一个数据包中，并通过 `/dev/input/event<X>` 发送，这是表示系统上的 `struct input_dev` 的字符设备，其中 `<X>` 是输入核心分配给驱动程序的接口号：

```
void input_sync(struct input_dev *dev) 
```

让我们看一个示例，这是 `drivers/input/misc/bma150.c` 中 `bma150` 数字加速传感器驱动程序的摘录：

```
static void threaded_report_xyz(struct bma150_data *bma150) 
{ 
  u8 data[BMA150_XYZ_DATA_SIZE]; 
  s16 x, y, z; 
  s32 ret; 

  ret = i2c_smbus_read_i2c_block_data(bma150->client, 
      BMA150_ACC_X_LSB_REG, BMA150_XYZ_DATA_SIZE, data); 
  if (ret != BMA150_XYZ_DATA_SIZE) 
    return; 

  x = ((0xc0 & data[0]) >> 6) | (data[1] << 2); 
  y = ((0xc0 & data[2]) >> 6) | (data[3] << 2); 
  z = ((0xc0 & data[4]) >> 6) | (data[5] << 2); 

  /* sign extension */ 
  x = (s16) (x << 6) >> 6; 
  y = (s16) (y << 6) >> 6; 
  z = (s16) (z << 6) >> 6; 

  input_report_abs(bma150->input, ABS_X, x); 
  input_report_abs(bma150->input, ABS_Y, y); 
  input_report_abs(bma150->input, ABS_Z, z); 
  /* Indicate this event is complete */ 
  input_sync(bma150->input); 
} 
```

在前面的示例中，`input_sync()` 告诉核心将这三个报告视为同一事件。这是有道理的，因为位置有三个轴（X、Y、Z），我们不希望 X、Y 或 Z 分别报告。

报告事件的最佳位置是在轮询设备的 `poll` 函数中，或者在启用了 IRQ 的设备的 IRQ 例程（线程部分或非线程部分）中。如果执行了可能休眠的操作，应在 IRQ 处理的线程部分内处理报告：

```
static void my_btn_poll(struct input_polled_dev *poll_dev) 
{ 
    struct my_struct *ms = poll_dev->private; 
    struct i2c_client *client = mcp->client; 

    input_report_key(poll_dev->input, BTN_0, 
                     gpiod_get_value(ms->reset_btn_desc) & 1); 
    input_sync(poll_dev->input); 
} 
```

# 用户空间接口

每个注册的输入设备都由 `/dev/input/event<X>` 字符设备表示，我们可以从用户空间读取该设备的事件。读取此文件的应用程序将以 `struct input_event` 格式接收事件数据包：

```
struct input_event { 
  struct timeval time; 
  __u16 type; 
  __u16 code; 
  __s32 value; 
} 
```

让我们看看结构中每个元素的含义：

+   `time` 是时间戳，它返回事件发生的时间。

+   `type` 是事件类型。例如，`EV_KEY` 表示按键按下或释放，`EV_REL` 表示相对移动，`EV_ABS` 表示绝对移动。更多类型在 `include/linux/input-event-codes.h` 中定义。

+   `code` 是事件代码，例如：`REL_X` 或 `KEY_BACKSPACE` ，完整的列表在 `include/linux/input-event-codes.h` 中。

+   `value` 是事件携带的值。对于 `EV_REL` 事件类型，它携带相对变化。对于 `EV_ABS`（如摇杆等）事件类型，它包含绝对的新值。对于 `EV_KEY` 事件类型，应设置为 `0` 表示按键释放，`1` 表示按键按下，`2` 表示自动重复。

用户空间应用程序可以使用阻塞和非阻塞读取，还可以使用 `poll()` 或 `select()` 系统调用来在打开此设备后接收事件通知。以下是一个使用 `select()` 系统调用的示例，完整的源代码在书籍源代码库中提供：

```
#include <unistd.h> 
#include <fcntl.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <linux/input.h> 
#include <sys/select.h> 

#define INPUT_DEVICE "/dev/input/event1" 

int main(int argc, char **argv) 
{    
    int fd; 
    struct input_event event; 
    ssize_t bytesRead; 

    int ret; 
    fd_set readfds; 

    fd = open(INPUT_DEVICE, O_RDONLY); 
    /* Let's open our input device */ 
    if(fd < 0){ 
        fprintf(stderr, "Error opening %s for reading", INPUT_DEVICE); 
        exit(EXIT_FAILURE); 
    } 

    while(1){  
        /* Wait on fd for input */ 
        FD_ZERO(&readfds); 
        FD_SET(fd, &readfds); 

        ret = select(fd + 1, &readfds, NULL, NULL, NULL); 
        if (ret == -1) { 
            fprintf(stderr, "select call on %s: an error ocurred", 
                    INPUT_DEVICE); 
            break; 
        } 
        else if (!ret) { /* If we have decided to use timeout */ 
            fprintf(stderr, "select on %s: TIMEOUT", INPUT_DEVICE); 
            break; 
        } 

        /* File descriptor is now ready */ 
        if (FD_ISSET(fd, &readfds)) { 
            bytesRead = read(fd, &event, 
                             sizeof(struct input_event)); 
            if(bytesRead == -1) 
                /* Process read input error*/ 
            if(bytesRead != sizeof(struct input_event)) 
                /* Read value is not an input even */ 

            /*  
             * We could have done a switch/case if we had 
             * many codes to look for 
             */ 
            if(event.code == BTN_0) { 
                /* it concerns our button */ 
                if(event.value == 0){ 
                    /* Process Release */ 
                    [...] 
                } 
                else if(event.value == 1){ 
                    /* Process KeyPress */ 
                    [...] 
                } 
            } 
        } 
    } 
    close(fd); 
    return EXIT_SUCCESS; 
} 
```

# 将所有内容整合在一起

到目前为止，我们已经描述了在编写输入设备驱动程序时使用的结构，以及它们如何可以从用户空间进行管理。

1.  根据其类型，轮询或非轮询，使用`input_allocate_polled_device()`或`input_allocate_device()`分配新的输入设备。

1.  填写强制字段或不填写（如果有必要）：

+   +   通过在`input_dev.evbit`字段上使用`set_bit()`辅助宏指定设备支持的事件类型

+   根据事件类型，`EV_REL`、`EV_ABS`、`EV_KEY`或其他，指定此设备可以报告的代码，使用`input_dev.relbit`、`input_dev.absbit`、`input_dev.keybit`或其他。

+   指定`input_dev.dev`以设置正确的设备树

+   如有必要，填写`abs_`信息

+   对于轮询设备，请指定应调用`poll()`函数的间隔：

1.  如果有必要，请编写您的`open()`函数，在其中应准备和设置设备使用的资源。此函数仅调用一次。在此函数中，设置 GPIO，如有需要请求中断，初始化设备。

1.  编写您的`close()`函数，在其中释放和释放`open()`函数中完成的内容。例如，释放 GPIO，IRQ，将设备置于省电模式。

1.  将您的`open()`或`close()`函数（或两者）传递给`input_dev.open`和`input_dev.close`字段。

1.  如果是轮询的，请使用`input_register_polled_device()`注册您的设备，如果不是，请使用`input_register_device()`。

1.  在您的 IRQ 函数（线程化或非线程化）或`poll()`函数中，根据事件类型收集和报告事件，使用`input_report_key()`、`input_report_rel()`、`input_report_abs()`或其他，并在输入设备上调用`input_sync()`以指示帧结束（报告完成）。

通常的方法是，如果没有提供 IRQ，则使用经典输入设备，否则回退到轮询设备：

```
if(client->irq > 0){ 
    /* Use generic input device */ 
} else { 
    /* Use polled device */ 
} 
```

查看如何从用户空间管理这些设备，请参考书籍源代码中提供的示例。

# 驱动程序示例

可以总结以下两个驱动程序。第一个是基于未映射到 IRQ 的 GPIO 的轮询输入设备。轮询输入核心将轮询 GPIO 以检测任何变化。此驱动程序配置为发送 0 键代码。每个 GPIO 状态对应于按键按下或释放：

```
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/slab.h> 
#include <linux/of.h>                   /* For DT*/ 
#include <linux/platform_device.h>      /* For platform devices */ 
#include <linux/gpio/consumer.h>        /* For GPIO Descriptor interface */ 
#include <linux/input.h> 
#include <linux/input-polldev.h> 

struct poll_btn_data { 
   struct gpio_desc *btn_gpiod; 
   struct input_polled_dev *poll_dev; 
}; 

static void polled_btn_open(struct input_polled_dev *poll_dev) 
{ 
    /* struct poll_btn_data *priv = poll_dev->private; */ 
    pr_info("polled device opened()\n"); 
} 

static void polled_btn_close(struct input_polled_dev *poll_dev) 
{ 
    /* struct poll_btn_data *priv = poll_dev->private; */ 
    pr_info("polled device closed()\n"); 
} 

static void polled_btn_poll(struct input_polled_dev *poll_dev) 
{ 
    struct poll_btn_data *priv = poll_dev->private; 

    input_report_key(poll_dev->input, BTN_0, gpiod_get_value(priv->btn_gpiod) & 1); 
    input_sync(poll_dev->input); 
} 

static const struct of_device_id btn_dt_ids[] = { 
    { .compatible = "packt,input-polled-button", }, 
    { /* sentinel */ } 
}; 

static int polled_btn_probe(struct platform_device *pdev) 
{ 
    struct poll_btn_data *priv; 
    struct input_polled_dev *poll_dev; 
    struct input_dev *input_dev; 
    int ret; 

    priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL); 
    if (!priv) 
        return -ENOMEM; 

    poll_dev = input_allocate_polled_device(); 
    if (!poll_dev){ 
        devm_kfree(&pdev->dev, priv); 
        return -ENOMEM; 
    } 

    /* We assume this GPIO is active high */ 
    priv->btn_gpiod = gpiod_get(&pdev->dev, "button", GPIOD_IN); 

    poll_dev->private = priv; 
    poll_dev->poll_interval = 200; /* Poll every 200ms */ 
    poll_dev->poll = polled_btn_poll; 
    poll_dev->open = polled_btn_open; 
    poll_dev->close = polled_btn_close; 
    priv->poll_dev = poll_dev; 

    input_dev = poll_dev->input; 
    input_dev->name = "Packt input polled Btn"; 
    input_dev->dev.parent = &pdev->dev; 

    /* Declare the events generated by this driver */ 
    set_bit(EV_KEY, input_dev->evbit); 
    set_bit(BTN_0, input_dev->keybit); /* buttons */ 

    ret = input_register_polled_device(priv->poll_dev); 
    if (ret) { 
        pr_err("Failed to register input polled device\n"); 
        input_free_polled_device(poll_dev); 
        devm_kfree(&pdev->dev, priv); 
        return ret; 
    } 

    platform_set_drvdata(pdev, priv); 
    return 0; 
} 

static int polled_btn_remove(struct platform_device *pdev) 
{ 
   struct poll_btn_data *priv = platform_get_drvdata(pdev); 
   input_unregister_polled_device(priv->poll_dev); 
    input_free_polled_device(priv->poll_dev); 
    gpiod_put(priv->btn_gpiod); 
   return 0; 
} 

static struct platform_driver mypdrv = { 
    .probe      = polled_btn_probe, 
    .remove     = polled_btn_remove, 
    .driver     = { 
        .name     = "input-polled-button", 
        .of_match_table = of_match_ptr(btn_dt_ids),   
        .owner    = THIS_MODULE, 
    }, 
}; 
module_platform_driver(mypdrv); 

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_DESCRIPTION("Polled input device"); 
```

这第二个驱动程序根据按钮的 GPIO 映射到的 IRQ 向输入核心发送事件。当使用 IRQ 来检测按键按下或释放时，最好在边缘变化时触发中断：

```
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/slab.h> 
#include <linux/of.h>                   /* For DT*/ 
#include <linux/platform_device.h>      /* For platform devices */ 
#include <linux/gpio/consumer.h>        /* For GPIO Descriptor interface */ 
#include <linux/input.h> 
#include <linux/interrupt.h> 

struct btn_data { 
   struct gpio_desc *btn_gpiod; 
   struct input_dev *i_dev; 
   struct platform_device *pdev; 
   int irq; 
}; 

static int btn_open(struct input_dev *i_dev) 
{ 
    pr_info("input device opened()\n"); 
    return 0; 
} 

static void btn_close(struct input_dev *i_dev) 
{ 
    pr_info("input device closed()\n"); 
} 

static irqreturn_t packt_btn_interrupt(int irq, void *dev_id) 
{ 
    struct btn_data *priv = dev_id; 

   input_report_key(priv->i_dev, BTN_0, gpiod_get_value(priv->btn_gpiod) & 1); 
    input_sync(priv->i_dev); 
   return IRQ_HANDLED; 
} 

static const struct of_device_id btn_dt_ids[] = { 
    { .compatible = "packt,input-button", }, 
    { /* sentinel */ } 
}; 

static int btn_probe(struct platform_device *pdev) 
{ 
    struct btn_data *priv; 
    struct gpio_desc *gpiod; 
    struct input_dev *i_dev; 
    int ret; 

    priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL); 
    if (!priv) 
        return -ENOMEM; 

    i_dev = input_allocate_device(); 
    if (!i_dev) 
        return -ENOMEM; 

    i_dev->open = btn_open; 
    i_dev->close = btn_close; 
    i_dev->name = "Packt Btn"; 
    i_dev->dev.parent = &pdev->dev; 
    priv->i_dev = i_dev; 
    priv->pdev = pdev; 

    /* Declare the events generated by this driver */ 
    set_bit(EV_KEY, i_dev->evbit); 
    set_bit(BTN_0, i_dev->keybit); /* buttons */ 

    /* We assume this GPIO is active high */ 
    gpiod = gpiod_get(&pdev->dev, "button", GPIOD_IN); 
    if (IS_ERR(gpiod)) 
        return -ENODEV; 

    priv->irq = gpiod_to_irq(priv->btn_gpiod); 
    priv->btn_gpiod = gpiod; 

    ret = input_register_device(priv->i_dev); 
    if (ret) { 
        pr_err("Failed to register input device\n"); 
        goto err_input; 
    } 

    ret = request_any_context_irq(priv->irq, 
                           packt_btn_interrupt, 
                           (IRQF_TRIGGER_FALLING | IRQF_TRIGGER_RISING), 
                           "packt-input-button", priv); 
    if (ret < 0) { 
        dev_err(&pdev->dev, 
            "Unable to acquire interrupt for GPIO line\n"); 
        goto err_btn; 
    } 

    platform_set_drvdata(pdev, priv); 
    return 0; 

err_btn: 
    gpiod_put(priv->btn_gpiod); 
err_input: 
    printk("will call input_free_device\n"); 
    input_free_device(i_dev); 
    printk("will call devm_kfree\n"); 
    return ret; 
} 

static int btn_remove(struct platform_device *pdev) 
{ 
    struct btn_data *priv; 
    priv = platform_get_drvdata(pdev); 
    input_unregister_device(priv->i_dev); 
    input_free_device(priv->i_dev); 
    free_irq(priv->irq, priv); 
    gpiod_put(priv->btn_gpiod); 
    return 0; 
} 

static struct platform_driver mypdrv = { 
    .probe      = btn_probe, 
    .remove     = btn_remove, 
    .driver     = { 
    .name     = "input-button", 
    .of_match_table = of_match_ptr(btn_dt_ids),   
    .owner    = THIS_MODULE, 
    }, 
}; 
module_platform_driver(mypdrv); 

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_DESCRIPTION("Input device (IRQ based)"); 
```

对于这两个示例，当设备与模块匹配时，将在`/dev/input`目录中创建一个节点。该节点对应于我们示例中的`event0`。可以使用`udevadm`工具来显示有关设备的信息：

```
# udevadm info /dev/input/event0

P: /devices/platform/input-button.0/input/input0/event0

N: input/event0

S: input/by-path/platform-input-button.0-event

E: DEVLINKS=/dev/input/by-path/platform-input-button.0-event

E: DEVNAME=/dev/input/event0

E: DEVPATH=/devices/platform/input-button.0/input/input0/event0

E: ID_INPUT=1

E: ID_PATH=platform-input-button.0

E: ID_PATH_TAG=platform-input-button_0

E: MAJOR=13

E: MINOR=64

E: SUBSYSTEM=input

E: USEC_INITIALIZED=74842430

```

实际允许我们将事件键打印到屏幕的工具是`evtest`，给定输入设备的路径：

```
# evtest /dev/input/event0

input device opened()

Input driver version is 1.0.1

Input device ID: bus 0x0 vendor 0x0 product 0x0 version 0x0

Input device name: "Packt Btn"

Supported events:

Event type 0 (EV_SYN)

Event type 1 (EV_KEY)

Event code 256 (BTN_0)

```

由于第二个模块是基于 IRQ 的，可以轻松检查 IRQ 请求是否成功，并且它已被触发了多少次：

```
$ cat /proc/interrupts | grep packt

160: 0 0 0 0 gpio-mxc 0 packt-input-button

```

最后，可以连续按下/释放按钮，并检查 GPIO 的状态是否发生了变化：

```
$ cat /sys/kernel/debug/gpio | grep button

gpio-193 (button-gpio ) in hi

$ cat /sys/kernel/debug/gpio | grep button

gpio-193 (button-gpio ) in lo

```

# 总结

本章描述了整个输入框架，并突出了轮询和中断驱动输入设备之间的区别。在本章结束时，您将具备为任何输入驱动程序编写驱动程序的必要知识，无论其类型和支持的输入事件如何。还讨论了用户空间接口，并提供了示例。下一章将讨论另一个重要的框架，即 RTC，它是 PC 和嵌入式设备中时间管理的关键元素。


# 第十八章：RTC 驱动程序

**实时时钟**（**RTC**）是用于在非易失性存储器中跟踪绝对时间的设备，可以是内部到处理器，也可以是通过 I2C 或 SPI 总线外部连接的。

可以使用 RTC 执行以下操作：

+   读取和设置绝对时钟，并在时钟更新期间生成中断

+   生成周期性中断

+   设置闹钟

RTC 和系统时钟有不同的目的。前者是硬件时钟，以非易失性方式维护绝对时间和日期，而后者是由内核维护的软件时钟，用于实现`gettimeofday(2)`和`time(2)`系统调用，以及在文件上设置时间戳等。系统时钟报告从起始点开始的秒和微秒，定义为 POSIX 纪元：`1970-01-01 00:00:00 +0000 (UTC)`。

在本章中，我们将涵盖以下主题：

+   介绍 RTC 框架 API

+   描述此类驱动程序的架构，以及一个虚拟驱动程序示例

+   处理闹钟

+   从用户空间管理 RTC 设备，可以通过 sysfs 接口或使用 hwclock 工具

# RTC 框架数据结构

在 Linux 系统上，RTC 框架使用三种主要数据结构。它们是`strcut rtc_time`，`struct rtc_device`和`struct rtc_class_ops`结构。前者是表示给定日期和时间的不透明结构；第二个结构表示物理 RTC 设备；最后一个表示驱动程序公开的一组操作，并由 RTC 核心用于读取/更新设备的日期/时间/闹钟。

从驱动程序中提取 RTC 函数所需的唯一标头是：

```
#include <linux/rtc.h> 
```

同一个文件包含了前一节中列举的三个结构：

```
struct rtc_time { 
   int tm_sec;  /* seconds after the minute */ 
   int tm_min;  /* minutes after the hour - [0, 59] */ 
   int tm_hour; /* hours since midnight - [0, 23] */ 
   int tm_mday; /* day of the month - [1, 31] */ 
   int tm_mon;  /* months since January - [0, 11] */ 
   int tm_year; /* years since 1900 */ 
   int tm_wday; /* days since Sunday - [0, 6] */ 
   int tm_yday; /* days since January 1 - [0, 365] */ 
   int tm_isdst; /* Daylight saving time flag */ 
}; 
```

此结构类似于`<time.h>`中的`struct tm`，用于传递时间。下一个结构是`struct rtc_device`，它代表内核中的芯片：

```
struct rtc_device { 
   struct device dev; 
   struct module *owner; 

   int id; 
   char name[RTC_DEVICE_NAME_SIZE]; 

   const struct rtc_class_ops *ops; 
   struct mutex ops_lock; 

   struct cdev char_dev; 
   unsigned long flags; 

   unsigned long irq_data; 
   spinlock_t irq_lock; 
   wait_queue_head_t irq_queue; 

   struct rtc_task *irq_task; 
   spinlock_t irq_task_lock; 
   int irq_freq; 
   int max_user_freq; 

   struct work_struct irqwork; 
}; 
```

以下是结构的元素的含义：

+   `dev`：这是设备结构。

+   `owner`：这是拥有此 RTC 设备的模块。使用`THIS_MODULE`就足够了。

+   `id`：这是内核为 RTC 设备分配的全局索引`/dev/rtc<id>`。

+   `name`：这是给 RTC 设备的名称。

+   `ops`：这是由 RTC 设备公开的一组操作（如读取/设置时间/闹钟），由核心或用户空间管理。

+   `ops_lock`：这是内核内部使用的互斥锁，用于保护 ops 函数调用。

+   `cdev`：这是与此 RTC 相关联的字符设备，`/dev/rtc<id>`。

下一个重要的结构是`struct rtc_class_ops`，它是一组用作回调的函数，用于在 RTC 设备上执行标准和有限的操作。它是顶层和底层 RTC 驱动程序之间的通信接口：

```
struct rtc_class_ops { 
   int (*open)(struct device *); 
   void (*release)(struct device *); 
   int (*ioctl)(struct device *, unsigned int, unsigned long); 
   int (*read_time)(struct device *, struct rtc_time *); 
   int (*set_time)(struct device *, struct rtc_time *); 
   int (*read_alarm)(struct device *, struct rtc_wkalrm *); 
   int (*set_alarm)(struct device *, struct rtc_wkalrm *); 
   int (*read_callback)(struct device *, int data); 
   int (*alarm_irq_enable)(struct device *, unsigned int enabled); 
}; 
```

在前面的代码中，所有的钩子都以`struct device`结构作为参数，这与嵌入在`struct rtc_device`结构中的结构相同。这意味着从这些钩子中，可以随时访问 RTC 设备，使用`to_rtc_device()`宏，该宏建立在`container_of()`宏之上。

```
#define to_rtc_device(d) container_of(d, struct rtc_device, dev) 
```

当用户空间对设备调用`open()`，`release()`和`read_callback()`函数时，内核会内部调用这些钩子。

`read_time()`是一个从设备读取时间并填充`struct rtc_time`输出参数的驱动程序函数。此函数应在成功时返回`0`，否则返回负错误代码。

`set_time()`是一个驱动程序函数，根据输入参数给定的`struct rtc_time`结构更新设备的时间。返回参数的备注与`read_time`函数相同。

如果您的设备支持闹钟功能，驱动程序应提供`read_alarm()`和`set_alarm()`来读取/设置设备上的闹钟。`struct rtc_wkalrm`将在后面的章节中描述。还应提供`alarm_irq_enable()`来启用闹钟。

# RTC API

RTC 设备在内核中表示为`struct rtc_device`结构的实例。与其他内核框架设备注册不同（其中设备作为参数提供给注册函数），RTC 设备由核心构建并首先注册，然后`rtc_device`结构返回给驱动程序。使用`rtc_device_register()`函数将设备与内核构建和注册：

```
struct rtc_device *rtc_device_register(const char *name, 

                             struct device *dev, 
                             const struct rtc_class_ops *ops, 
                             struct module *owner) 
```

可以看到每个函数的每个参数的含义如下：

+   `name`：这是您的 RTC 设备名称。它可以是芯片的名称，例如：ds1343。

+   `dev`：这是父设备，用于设备模型的目的。例如，对于位于 I2C 或 SPI 总线上的芯片，`dev`可以使用`spi_device.dev`或`i2c_client.dev`进行设置。

+   `ops`：这是您的 RTC 操作，根据 RTC 具有的功能或驱动程序可以支持的功能进行填充。

+   `owner`：这是此 RTC 设备所属的模块。在大多数情况下，`THIS_MODULE`就足够了。

注册应该在`probe`函数中执行，显然，可以使用此函数的资源管理版本：

```
struct rtc_device *devm_rtc_device_register(struct device *dev, 
                              const char *name, 
                              const struct rtc_class_ops *ops, 
                              struct module *owner) 
```

这两个函数在成功时返回由内核构建的`struct rtc_device`结构的指针，或者返回一个指针错误，您应该使用`IS_ERR`和`PTR_ERR`宏。

相关的反向操作是`rtc_device_unregister()`和`devm_ rtc_device_unregister()`：

```
void rtc_device_unregister(struct rtc_device *rtc) 
void devm_rtc_device_unregister(struct device *dev,

                           struct rtc_device *rtc) 
```

# 读取和设置时间

驱动程序负责提供用于读取和设置设备时间的函数。这是 RTC 驱动程序可以提供的最少功能。在读取方面，读取回调函数被给予一个已分配/清零的`struct rtc_time`结构的指针，驱动程序必须填充该结构。因此，RTC 几乎总是以**二进制编码十进制**（**BCD**）存储/恢复时间，其中每个四位数（4 位的一系列）代表 0 到 9 之间的数字（而不是 0 到 15 之间的数字）。内核提供了两个宏，`bcd2bin()`和`bin2bcd()`，分别用于将 BCD 编码转换为十进制，或将十进制转换为 BCD。接下来您应该注意的是一些`rtc_time`字段，它们具有一些边界要求，并且需要进行一些转换。数据以 BCD 形式从设备中读取，应使用`bcd2bin()`进行转换。

由于`struct rtc_time`结构比较复杂，内核提供了`rtc_valid_tm()`辅助函数，以验证给定的`rtc_time`结构，并在成功时返回`0`，表示该结构表示一个有效的日期/时间：

```
int rtc_valid_tm(struct rtc_time *tm);
```

以下示例描述了 RTC 读取操作的回调：

```
static int foo_rtc_read_time(struct device *dev, struct rtc_time *tm) 
{ 
   struct foo_regs regs; 
   int error; 

   error = foo_device_read(dev, &regs, 0, sizeof(regs)); 
   if (error) 
         return error; 

   tm->tm_sec = bcd2bin(regs.seconds); 
   tm->tm_min = bcd2bin(regs.minutes); 
   tm->tm_hour = bcd2bin(regs.cent_hours); 
   tm->tm_mday = bcd2bin(regs.date); 

   /* 
    * This device returns weekdays from 1 to 7 
    * But rtc_time.wday expect days from 0 to 6\. 
    * So we need to substract 1 to the value returned by the chip 
    */ 
   tm->tm_wday = bcd2bin(regs.day) - 1; 

    /* 
    * This device returns months from 1 to 12 
    * But rtc_time.tm_month expect a months 0 to 11\. 
    * So we need to substract 1 to the value returned by the chip 
    */ 
   tm->tm_mon = bcd2bin(regs.month) - 1; 

    /* 
    * This device's Epoch is 2000\. 
    * But rtc_time.tm_year expect years from Epoch 1900\. 
    * So we need to add 100 to the value returned by the chip 
    */ 
   tm->tm_year = bcd2bin(regs.years) + 100; 

   return rtc_valid_tm(tm); 
} 
```

在使用 BCD 转换函数之前，需要以下标头：

```
#include <linux/bcd.h> 
```

在`set_time`函数中，输入参数是指向`struct rtc_time`的指针。该参数已经填充了要存储在 RTC 芯片中的值。不幸的是，这些值是十进制编码的，应在发送到芯片之前转换为 BCD。`bin2bcd`进行转换。对`struct rtc_time`结构的一些字段也应该引起注意。以下是描述通用`set_time`函数的伪代码：

```
static int foo_rtc_set_time(struct device *dev, struct rtc_time *tm) 
{ 

   regs.seconds = bin2bcd(tm->tm_sec); 
   regs.minutes = bin2bcd(tm->tm_min); 
   regs.cent_hours = bin2bcd(tm->tm_hour); 

   /* 
    * This device expects week days from 1 to 7 
    * But rtc_time.wday contains week days from 0 to 6\. 
    * So we need to add 1 to the value given by rtc_time.wday 
    */ 
   regs.day = bin2bcd(tm->tm_wday + 1); 
   regs.date = bin2bcd(tm->tm_mday); 

   /* 
    * This device expects months from 1 to 12 
    * But rtc_time.tm_mon contains months from 0 to 11\. 
    * So we need to add 1 to the value given by rtc_time.tm_mon 
    */ 
   regs.month = bin2bcd(tm->tm_mon + 1); 

   /* 
    * This device expects year since Epoch 2000 
    * But rtc_time.tm_year contains year since Epoch 1900\. 
    * We can just extract the year of the century with the 
    * rest of the division by 100\. 
    */ 
   regs.cent_hours |= BQ32K_CENT; 
   regs.years = bin2bcd(tm->tm_year % 100); 

   return write_into_device(dev, &regs, 0, sizeof(regs)); 
} 
```

RTC 的纪元与 POSIX 纪元不同，后者仅用于系统时钟。如果根据 RTC 的纪元和年寄存器的年份小于 1970 年，则假定它比实际时间晚 100 年，即在 2000 年至 2069 年之间。

# 驱动程序示例

可以用一个简单的虚拟驱动程序总结前面的概念，该驱动程序只是在系统上注册一个 RTC 设备：

```
#include <linux/platform_device.h> 
#include <linux/module.h> 
#include <linux/types.h> 
#include <linux/time.h> 
#include <linux/err.h> 
#include <linux/rtc.h> 
#include <linux/of.h> 

static int fake_rtc_read_time(struct device *dev, struct rtc_time *tm) 
{ 
   /* 
    * One can update "tm" with fake values and then call 
    */ 
   return rtc_valid_tm(tm); 
} 

static int fake_rtc_set_time(struct device *dev, struct rtc_time *tm) 
{ 
   return 0; 
} 

static const struct rtc_class_ops fake_rtc_ops = { 
   .read_time = fake_rtc_read_time, 
   .set_time = fake_rtc_set_time 
}; 

static const struct of_device_id rtc_dt_ids[] = { 
    { .compatible = "packt,rtc-fake", }, 
    { /* sentinel */ } 
}; 

static int fake_rtc_probe(struct platform_device *pdev) 
{ 
   struct rtc_device *rtc; 
   rtc = rtc_device_register(pdev->name, &pdev->dev, 
                           &fake_rtc_ops, THIS_MODULE); 

   if (IS_ERR(rtc)) 
         return PTR_ERR(rtc); 

   platform_set_drvdata(pdev, rtc); 
   pr_info("Fake RTC module loaded\n"); 

   return 0; 
} 

static int fake_rtc_remove(struct platform_device *pdev) 
{ 
   rtc_device_unregister(platform_get_drvdata(pdev)); 
   return 0; 
} 

static struct platform_driver fake_rtc_drv = { 
   .probe = fake_rtc_probe, 
   .remove = fake_rtc_remove, 
   .driver = { 
         .name = KBUILD_MODNAME, 
         .owner = THIS_MODULE, 
         .of_match_table = of_match_ptr(rtc_dt_ids), 
   }, 
}; 
module_platform_driver(fake_rtc_drv); 

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_DESCRIPTION("Fake RTC driver description"); 
```

# 操作闹钟

RTC 闹钟是设备在特定时间触发的可编程事件。RTC 闹钟表示为`struct rtc_wkalarm`结构的实例：

```
struct rtc_wkalrm { 
unsigned char enabled;  /* 0 = alarm disabled, 1 = enabled */ 
unsigned char pending;  /* 0 = alarm not pending, 1 = pending */ 
struct rtc_time time;   /* time the alarm is set to */ 
}; 
```

驱动程序应提供`set_alarm()`和`read_alarm()`操作，以设置和读取警报应发生的时间，以及`alarm_irq_enable()`，这是一个用于启用/禁用警报的函数。当调用`set_alarm()`函数时，它将作为输入参数给出一个指向`struct rtc_wkalrm`的指针，其中的`.time`字段包含必须设置警报的时间。由驱动程序以正确的方式提取每个值（如有必要，使用`bin2dcb()`），并将其写入适当的寄存器中。`rtc_wkalrm.enabled`告诉警报设置后是否应启用警报。如果为 true，则驱动程序必须在芯片中启用警报。对于`read_alarm()`也是如此，它给出了一个指向`struct rtc_wkalrm`的指针，但这次作为输出参数。驱动程序必须使用从设备中读取的数据填充结构。

`{read | set}_alarm()`和`{read | set}_time()`函数的行为方式相同，只是每对函数从/存储数据到设备的不同寄存器集。

在向系统报告警报事件之前，必须将 RTC 芯片连接到 SoC 的 IRQ 线上。它依赖于 RTC 的 INT 线在警报发生时被拉低。根据制造商，该线保持低电平，直到读取状态寄存器或清除特殊位为止：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00037.jpg)

此时，我们可以使用通用的 IRQ API，例如`request_threaded_irq()`，以注册警报 IRQ 的处理程序。在 IRQ 处理程序内部，重要的是使用`rtc_update_irq()`函数通知内核有关 RTC IRQ 事件：

```
void rtc_update_irq(struct rtc_device *rtc, 
                 unsigned long num, unsigned long events) 
```

+   `rtc`：这是引发 IRQ 的 RTC 设备

+   `num`：显示正在报告的 IRQ 数量（通常为一个）

+   `events`：这是带有一个或多个`RTC_PF`，`RTC_AF`，`RTC_UF`的`RTC_IRQF`掩码

```
/* RTC interrupt flags */ 
#define RTC_IRQF 0x80 /* Any of the following is active */ 
#define RTC_PF 0x40  /* Periodic interrupt */ 
#define RTC_AF 0x20  /* Alarm interrupt */ 
#define RTC_UF 0x10  /* Update interrupt for 1Hz RTC */ 
```

该函数可以从任何上下文中调用，无论是原子的还是非原子的。IRQ 处理程序可能如下所示：

```
static irqreturn_t foo_rtc_alarm_irq(int irq, void *data) 
{ 
   struct foo_rtc_struct * foo_device = data; 
   dev_info(foo_device ->dev, "%s:irq(%d)\n", __func__, irq); 
   rtc_update_irq(foo_device ->rtc_dev, 1, RTC_IRQF | RTC_AF); 

   return IRQ_HANDLED; 
} 
```

请记住，具有警报功能的 RTC 设备可以用作唤醒源。也就是说，每当警报触发时，系统都可以从挂起模式唤醒。此功能依赖于 RTC 设备引发的中断。使用`device_init_wakeup()`函数声明设备为唤醒源。实际唤醒系统的 IRQ 也必须使用电源管理核心注册，使用`dev_pm_set_wake_irq()`函数：

```
int device_init_wakeup(struct device *dev, bool enable) 
int dev_pm_set_wake_irq(struct device *dev, int irq) 
```

我们不会在本书中详细讨论电源管理。想法只是为了让您了解 RTC 设备如何改进您的系统。驱动程序`drivers/rtc/rtc-ds1343.c`可能有助于实现这些功能。让我们通过为 SPI foo RTC 设备编写一个虚假的`probe`函数来将所有内容放在一起：

```
static const struct rtc_class_ops foo_rtc_ops = { 
   .read_time  = foo_rtc_read_time, 
   .set_time   = foo_rtc_set_time, 
   .read_alarm = foo_rtc_read_alarm, 
   .set_alarm  = foo_rtc_set_alarm, 
   .alarm_irq_enable = foo_rtc_alarm_irq_enable, 
   .ioctl      = foo_rtc_ioctl, 
}; 

static int foo_spi_probe(struct spi_device *spi) 
{ 
   int ret; 
    /* initialise and configure the RTC chip */ 
   [...] 

foo_rtc->rtc_dev = 
devm_rtc_device_register(&spi->dev, "foo-rtc", 
&foo_rtc_ops, THIS_MODULE); 
   if (IS_ERR(foo_rtc->rtc_dev)) { 
         dev_err(&spi->dev, "unable to register foo rtc\n"); 
         return PTR_ERR(priv->rtc); 
   } 

   foo_rtc->irq = spi->irq; 

   if (foo_rtc->irq >= 0) { 
         ret = devm_request_threaded_irq(&spi->dev, spi->irq, 
                                 NULL, foo_rtc_alarm_irq, 
                                 IRQF_ONESHOT, "foo-rtc", priv); 
         if (ret) { 
               foo_rtc->irq = -1; 
               dev_err(&spi->dev, 
                     "unable to request irq for rtc foo-rtc\n"); 
         } else { 
               device_init_wakeup(&spi->dev, true); 
               dev_pm_set_wake_irq(&spi->dev, spi->irq); 
         } 
   } 

   return 0; 
} 
```

# RTC 和用户空间

在 Linux 系统中，为了正确地从用户空间管理 RTC，有两个内核选项需要关注。这些选项是`CONFIG_RTC_HCTOSYS`和`CONFIG_RTC_HCTOSYS_DEVICE`。

`CONFIG_RTC_HCTOSYS`在内核构建过程中包括代码文件`drivers/rtc/hctosys.c`，该文件在启动和恢复时从 RTC 设置系统时间。启用此选项后，系统时间将使用从指定 RTC 设备读取的值进行设置。RTC 设备应在`CONFIG_RTC_HCTOSYS_DEVICE`中指定：

```
CONFIG_RTC_HCTOSYS=y 
CONFIG_RTC_HCTOSYS_DEVICE="rtc0" 
```

在前面的示例中，我们告诉内核从 RTC 设置系统时间，并指定要使用的 RTC 为`rtc0`。

# sysfs 接口

负责在 sysfs 中实例化 RTC 属性的内核代码在内核源树中的`drivers/rtc/rtc-sysfs.c`中定义。一旦注册，RTC 设备将在`/sys/class/rtc`目录下创建一个`rtc<id>`目录。该目录包含一组只读属性，其中最重要的是：

+   `date`：此文件打印 RTC 接口的当前日期：

```
$ cat /sys/class/rtc/rtc0/date

2017-08-28

```

+   `time`：打印此 RTC 的当前时间：

```
    $ cat /sys/class/rtc/rtc0/time

    14:54:20

```

+   `hctosys`：此属性指示 RTC 设备是否是`CONFIG_RTC_HCTOSYS_DEVICE`中指定的设备，这意味着此 RTC 用于在启动和恢复时设置系统时间。将`1`读为 true，将`0`读为 false：

```
 $ cat /sys/class/rtc/rtc0/hctosys
    1

```

+   `dev`：此属性显示设备的主要和次要。读作 major:minor：

```
 $ cat /sys/class/rtc/rtc0/dev
    251:0

```

+   `since_epoch`：此属性将打印自 UNIX 纪元（1970 年 1 月 1 日）以来经过的秒数：

```
    $ cat /sys/class/rtc/rtc0/since_epoch

    1503931738

```

# hwclock 实用程序

**硬件时钟**（**hwclock**）是用于访问 RTC 设备的工具。`man hwclock`命令可能比本节讨论的所有内容更有意义。也就是说，让我们写一些命令，从系统时钟设置 hwclock RTC：

```
 $ sudo ntpd -q    # make sure system clock is set from network time

 $ sudo hwclock --systohc   # set rtc from the system clock

 $ sudo hwclock --show      # check rtc was set

 Sat May 17 17:36:50 2017  -0.671045 seconds

```

上面的例子假设主机有一个可以访问 NTP 服务器的网络连接。也可以手动设置系统时间：

```
 $ sudo date -s '2017-08-28 17:14:00' '+%s' #set system clock manually

 $ sudo hwclock --systohc #synchronize rtc chip on system time

```

如果没有作为参数给出，`hwclock`假定 RTC 设备文件是`/dev/rtc`，实际上这是一个指向真实 RTC 设备的符号链接：

```
 $ ls -l /dev/rtc
 lrwxrwxrwx 1 root root 4 août  27 17:50 /dev/rtc -> rtc0

```

# 摘要

本章向您介绍了 RTC 框架及其 API。其减少的功能和数据结构使其成为最轻量级的框架，并且易于掌握。使用本章描述的技能，您将能够为大多数现有的 RTC 芯片开发驱动程序，甚至可以进一步处理这些设备，轻松设置日期和时间以及闹钟。下一章，PWM 驱动程序，与本章没有任何共同之处，但对于嵌入式工程师来说是必须了解的。
