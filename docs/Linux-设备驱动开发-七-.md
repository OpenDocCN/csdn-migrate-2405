# Linux 设备驱动开发（七）

> 原文：[`zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E`](https://zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：PWM 驱动程序

**脉冲宽度调制**（**PWM**）类似于不断循环开关。它是一种用于控制舵机、电压调节等的硬件特性。PWM 最著名的应用包括：

+   电机速度控制

+   调光

+   电压调节

现在，让我们通过以下简单的图介绍 PWM：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00038.jpg)

前面的图描述了完整的 PWM 周期，介绍了我们需要在深入研究内核 PWM 框架之前澄清的一些术语：

+   `Ton`：这是信号高电平的持续时间。

+   `Toff`：这是信号低电平的持续时间。

+   `周期`：这是完整 PWM 周期的持续时间。它代表 PWM 信号的`Ton`和`Toff`的总和。

+   `占空比`：它表示信号在 PWM 信号周期内保持开启的时间的百分比。

不同的公式详细说明如下：

+   PWM 周期：![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00039.gif)

+   占空比：![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00040.gif)

您可以在[`en.wikipedia.org/wiki/Pulse-width_modulation`](https://en.wikipedia.org/wiki/Pulse-width_modulation)找到有关 PWM 的详细信息。

Linux PWM 框架有两个接口：

1.  **控制器接口**：公开 PWM 线的接口。它是 PWM 芯片，即生产者。

1.  **消费者接口**：由控制器公开的使用 PWM 线的设备。此类设备的驱动程序使用控制器导出的辅助函数，通过通用 PWM 框架。

消费者或生产者接口取决于以下头文件：

```
#include <linux/pwm.h> 
```

在本章中，我们将处理：

+   PWM 驱动程序架构和数据结构，用于控制器和消费者，以及一个虚拟驱动程序

+   在设备树中实例化 PWM 设备和控制器

+   请求和使用 PWM 设备

+   通过 sysfs 接口从用户空间使用 PWM

# PWM 控制器驱动程序

在编写 GPIO 控制器驱动程序时需要`struct gpio_chip`，在编写 IRQ 控制器驱动程序时需要`struct irq_chip`，PWM 控制器在内核中表示为`struct pwm_chip`结构的实例。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00041.jpg)

PWM 控制器和设备

```
struct pwm_chip { 
   struct device *dev; 
   const struct pwm_ops *ops; 
   int base; 
   unsigned int npwm; 

   struct pwm_device *pwms; 
   struct pwm_device * (*of_xlate)(struct pwm_chip *pc, 
                    const struct of_phandle_args *args); 
   unsigned int of_pwm_n_cells; 
   bool can_sleep; 
}; 
```

以下是结构中每个元素的含义：

+   `dev`：这代表与此芯片关联的设备。

+   `Ops`：这是一个数据结构，提供此芯片向消费者驱动程序公开的回调函数。

+   `Base`：这是由此芯片控制的第一个 PWM 的编号。如果`chip->base < 0`，则内核将动态分配一个基数。

+   `can_sleep`：如果 ops 字段的`.config()`、`.enable()`或`.disable()`操作可能休眠，则由芯片驱动程序设置为`true`。

+   `npwm`：这是此芯片提供的 PWM 通道（设备）的数量。

+   `pwms`：这是由框架分配给此芯片的 PWM 设备数组，供消费者驱动程序使用。

+   `of_xlate`：这是一个可选的回调，用于根据 DT PWM 指定器请求 PWM 设备。如果未定义，PWM 核心将将其设置为`of_pwm_simple_xlate`，同时将`of_pwm_n_cells`强制设置为`2`。

+   `of_pwm_n_cells`：这是 DT 中 PWM 指定器预期的单元数。

PWM 控制器/芯片的添加和移除依赖于两个基本函数，`pwmchip_add()`和`pwmchip_remove()`。每个函数都应该以填充的`struct pwm_chip`结构作为参数。它们各自的原型如下：

```
int pwmchip_add(struct pwm_chip *chip) 
int pwmchip_remove(struct pwm_chip *chip) 
```

与其他框架移除函数不返回值不同，`pwmchip_remove()`具有返回值。它在成功时返回`0`，如果芯片仍在使用（仍在请求），则返回`-EBUSY`。

每个 PWM 驱动程序必须通过`struct pwm_ops`字段实现一些钩子，该字段由 PWM 核心或消费者接口使用，以配置和充分利用其 PWM 通道。其中一些是可选的。

```
struct pwm_ops { 
   int (*request)(struct pwm_chip *chip, struct pwm_device *pwm); 
   void (*free)(struct pwm_chip *chip, struct pwm_device *pwm); 
   int (*config)(struct pwm_chip *chip, struct pwm_device *pwm, 
                           int duty_ns, int period_ns); 
   int (*set_polarity)(struct pwm_chip *chip, struct pwm_device *pwm, 
                           enum pwm_polarity polarity); 
   int (*enable)(struct pwm_chip *chip,struct pwm_device *pwm); 
   void (*disable)(struct pwm_chip *chip, struct pwm_device *pwm); 
   void (*get_state)(struct pwm_chip *chip, struct pwm_device *pwm, 
                struct pwm_state *state); /* since kernel v4.7 */ 
   struct module *owner; 
}; 
```

让我们看看结构中的每个元素的含义：

+   `request`：这是一个可选的钩子，如果提供，将在请求 PWM 通道时执行。

+   `free`：这与请求相同，在 PWM 释放时运行。

+   `config`：这是 PMW 配置钩子。它配置了这个 PWM 的占空比和周期长度。

+   `set_polarity`：这个钩子配置了 PWM 的极性。

+   `Enable`：这启用 PWM 线，开始输出切换。

+   `Disable`：这禁用 PWM 线，停止输出切换。

+   `Apply`：这个原子地应用一个新的 PWM 配置。状态参数应该根据实际的硬件配置进行调整。

+   `get_state`：这返回当前 PWM 状态。当 PWM 芯片注册时，每个 PWM 设备只调用一次这个函数。

+   `Owner`：这是拥有这个芯片的模块，通常是`THIS_MODULE`。

在 PWM 控制器驱动的`probe`函数中，最好的做法是检索 DT 资源，初始化硬件，填充`struct pwm_chip`和它的`struct pwm_ops`，然后使用`pwmchip_add`函数添加 PWM 芯片。

# 驱动示例

现在让我们通过编写一个虚拟 PWM 控制器的虚拟驱动来总结一下事情，它有三个通道：

```
#include <linux/module.h> 
#include <linux/of.h> 
#include <linux/platform_device.h> 
#include <linux/pwm.h> 

struct fake_chip { 
   struct pwm_chip chip; 
   int foo; 
   int bar; 
   /* put the client structure here (SPI/I2C) */ 
}; 

static inline struct fake_chip *to_fake_chip(struct pwm_chip *chip) 
{ 
   return container_of(chip, struct fake_chip, chip); 
} 

static int fake_pwm_request(struct pwm_chip *chip, 
                               struct pwm_device *pwm) 
{ 
   /* 
    * One may need to do some initialization when a PWM channel 
    * of the controller is requested. This should be done here. 
    * 
    * One may do something like  
    *     prepare_pwm_device(struct pwm_chip *chip, pwm->hwpwm); 
    */ 

   return 0; 
} 

static int fake_pwm_config(struct pwm_chip *chip, 
                       struct pwm_device *pwm, 
                      int duty_ns, int period_ns) 
{ 

    /* 
     * In this function, one ne can do something like: 
     *      struct fake_chip *priv = to_fake_chip(chip); 
     * 
     *      return send_command_to_set_config(priv, 
     *                      duty_ns, period_ns); 
     */ 

   return 0; 
} 

static int fake_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm) 
{ 
    /* 
     * In this function, one ne can do something like: 
     *  struct fake_chip *priv = to_fake_chip(chip); 
     * 
     * return foo_chip_set_pwm_enable(priv, pwm->hwpwm, true); 
     */ 

    pr_info("Somebody enabled PWM device number %d of this chip", 
             pwm->hwpwm); 
   return 0; 
} 

static void fake_pwm_disable(struct pwm_chip *chip, 
                              struct pwm_device *pwm) 
{ 
    /* 
     * In this function, one ne can do something like: 
     *  struct fake_chip *priv = to_fake_chip(chip); 
     * 
     * return foo_chip_set_pwm_enable(priv, pwm->hwpwm, false); 
     */ 

    pr_info("Somebody disabled PWM device number %d of this chip", 
              pwm->hwpwm); 
} 

static const struct pwm_ops fake_pwm_ops = { 
   .request = fake_pwm_request, 
   .config = fake_pwm_config, 
   .enable = fake_pwm_enable, 
   .disable = fake_pwm_disable, 
   .owner = THIS_MODULE, 
}; 

static int fake_pwm_probe(struct platform_device *pdev) 
{ 
   struct fake_chip *priv; 

   priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL); 
   if (!priv) 
         return -ENOMEM; 

   priv->chip.ops = &fake_pwm_ops; 
   priv->chip.dev = &pdev->dev; 
   priv->chip.base = -1;   /* Dynamic base */ 
   priv->chip.npwm = 3;    /* 3 channel controller */  

   platform_set_drvdata(pdev, priv); 
   return pwmchip_add(&priv->chip); 
} 

static int fake_pwm_remove(struct platform_device *pdev) 
{ 
   struct fake_chip *priv = platform_get_drvdata(pdev); 
   return pwmchip_remove(&priv->chip); 
} 

static const struct of_device_id fake_pwm_dt_ids[] = { 
   { .compatible = "packt,fake-pwm", }, 
   { } 
}; 
MODULE_DEVICE_TABLE(of, fake_pwm_dt_ids); 

static struct platform_driver fake_pwm_driver = { 
   .driver = { 
         .name = KBUILD_MODNAME, 
.owner = THIS_MODULE, 
         .of_match_table = of_match_ptr(fake_pwm_dt_ids), 
   }, 
   .probe = fake_pwm_probe, 
   .remove = fake_pwm_remove, 
}; 
module_platform_driver(fake_pwm_driver); 

MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_DESCRIPTION("Fake pwm driver"); 
MODULE_LICENSE("GPL"); 
```

# PWM 控制器绑定

在 DT 中绑定 PWM 控制器时，最重要的属性是`#pwm-cells`。它表示用于表示该控制器的 PWM 设备的单元格数。如果记得，在`struct pwm_chip`结构中，`of_xlate`钩子用于翻译给定的 PWM 说明符。如果没有设置这个钩子，这里的`pwm-cells`必须设置为 2，否则，它应该与`of_pwm_n_cells`的值相同。以下是 i.MX6 SoC 设备树中 PWM 控制器节点的示例。

```
pwm3: pwm@02088000 { 
    #pwm-cells = <2>; 
    compatible = "fsl,imx6q-pwm", "fsl,imx27-pwm"; 
    reg = <0x02088000 0x4000>; 
    interrupts = <0 85 IRQ_TYPE_LEVEL_HIGH>; 
    clocks = <&clks IMX6QDL_CLK_IPG>, 
         <&clks IMX6QDL_CLK_PWM3>; 
    clock-names = "ipg", "per"; 
    status = "disabled"; 
}; 
```

另一方面，对应我们的虚拟 PWM 驱动的节点如下：

```
fake_pwm: pwm@0 { 
    #pwm-cells = <2>; 
    compatible = "packt,fake-pwm"; 
    /*  
     * Our driver does not use resource  
     * neither mem, IRQ, nor Clock) 
     */ 
}; 
```

# PWM 消费者接口

消费者是实际使用 PWM 通道的设备。在内核中，PWM 通道表示为`struct pwm_device`结构的实例：

```
struct pwm_device { 
   const char *label; 
   unsigned long flags; 
   unsigned int hwpwm; 
   unsigned int pwm; 
   struct pwm_chip *chip; 
   void *chip_data; 

  unsigned int period;     /* in nanoseconds */ 
  unsigned int duty_cycle; /* in nanoseconds */ 
  enum pwm_polarity polarity; 
}; 
```

+   `Label`：这是这个 PWM 设备的名称

+   `Flags`：这代表与 PWM 设备相关的标志

+   `hwpw`：这是 PWM 设备的相对索引，局部于芯片

+   `pwm`：这是 PWM 设备的系统全局索引

+   `chip`：这是一个 PWM 芯片，提供这个 PWM 设备的控制器

+   `chip_data`：这是与这个 PWM 设备关联的芯片私有数据

自内核 v4.7 以来，结构已更改为：

```
struct pwm_device { 
   const char *label; 
   unsigned long flags; 
   unsigned int hwpwm; 
   unsigned int pwm; 
   struct pwm_chip *chip; 
   void *chip_data; 

   struct pwm_args args; 
   struct pwm_state state; 
}; 
```

+   `args`：这代表与这个 PWM 设备相关的依赖于板的 PWM 参数，通常从 PWM 查找表或设备树中检索。PWM 参数代表用户想要在这个 PWM 设备上使用的初始配置，而不是当前的 PWM 硬件状态。

+   `状态`：这代表了当前 PWM 通道的状态。

```
struct pwm_args { 
   unsigned int period; /* Device's nitial period */ 
   enum pwm_polarity polarity; 
}; 

struct pwm_state { 
   unsigned int period; /* PWM period (in nanoseconds) */ 
   unsigned int duty_cycle; /* PWM duty cycle (in nanoseconds) */ 
   enum pwm_polarity polarity; /* PWM polarity */ 
   bool enabled; /* PWM enabled status */ 
} 
```

随着 Linux 的发展，PWM 框架面临了几次变化。这些变化涉及到从消费者端请求 PWM 设备的方式。我们可以将消费者接口分为两部分，或者更准确地说是两个版本。

**传统版本**，在这个版本中使用`pwm_request()`和`pwm_free()`来请求一个 PWM 设备，并在使用后释放它。

**新的和推荐的 API**，使用`pwm_get()`和`pwm_put()`函数。前者给定了消费者设备和通道名称作为参数来请求 PWM 设备，后者给定了要释放的 PWM 设备作为参数。这些函数的托管变体`devm_pwm_get()`和`devm_pwm_put()`也存在。

```
struct pwm_device *pwm_get(struct device *dev, const char *con_id) 
void pwm_put(struct pwm_device *pwm) 
```

`pwm_request()`/`pwm_get()`和`pwm_free()`/`pwm_put()`不能在原子上下文中调用，因为 PWM 核心使用互斥锁，可能会休眠。

在请求后，必须使用以下方式配置 PWM：

```
int pwm_config(struct pwm_device *pwm, int duty_ns, int period_ns); 
```

要开始/停止切换 PWM 输出，使用`pwm_enable()`/`pwm_disable()`。这两个函数都以`struct pwm_device`的指针作为参数，并且都是通过`pwm_chip.pwm_ops`字段公开的钩子的包装器。

```
int pwm_enable(struct pwm_device *pwm) 
void pwm_disable(struct pwm_device *pwm) 
```

`pwm_enable（）`在成功时返回`0`，在失败时返回负错误代码。一个很好的 PWM 消费者驱动程序的例子是内核源树中的`drivers/leds/leds-pwm.c`。以下是一个 PWM led 的消费者代码示例：

```
static void pwm_led_drive(struct pwm_device *pwm, 
                      struct private_data *priv) 
{ 
    /* Configure the PWM, applying a period and duty cycle */ 
    pwm_config(pwm, priv->duty, priv->pwm_period); 

    /* Start toggling */ 
    pwm_enable(pchip->pwmd); 

    [...] /* Do some work */ 

    /* And then stop toggling*/ 
    pwm_disable(pchip->pwmd); 
} 
```

# PWM 客户端绑定

PWM 设备可以从以下分配给消费者：

+   设备树

+   ACPI

+   静态查找表，在板`init`文件中。

本书将仅处理 DT 绑定，因为这是推荐的方法。当将 PWM 消费者（客户端）绑定到其驱动程序时，您需要提供其链接的控制器的 phandle。

建议您将 PWM 属性命名为`pwms`；由于 PWM 设备是命名资源，您可以提供一个可选的属性`pwm-names`，其中包含一个字符串列表，用于为`pwms`属性中列出的每个 PWM 设备命名。如果没有给出`pwm-names`属性，则将使用用户节点的名称作为回退。

使用多个 PWM 设备的设备的驱动程序可以使用`pwm-names`属性将`pwm_get（）`调用请求的 PWM 设备的名称映射到`pwms`属性给出的列表中的索引。

以下示例描述了基于 PWM 的背光设备，这是 PWM 设备绑定的内核文档的摘录（请参阅*Documentation/devicetree/bindings/pwm/pwm.txt*）：

```
pwm: pwm { 
    #pwm-cells = <2>; 
}; 

[...] 

bl: backlight { 
pwms = <&pwm 0 5000000>; 
   pwm-names = "backlight"; 
}; 
```

PWM 规范通常编码芯片相对 PWM 编号和以纳秒为单位的 PWM 周期。使用以下行：

```
pwms = <&pwm 0 5000000>; 
```

`0`对应于相对于控制器的 PWM 索引，`5000000`表示以纳秒为单位的周期。请注意，在前面的示例中，指定`pwm-names`是多余的，因为名称`backlight`无论如何都将用作回退。因此，驱动程序必须调用：

```
static int my_consummer_probe(struct platform_device *pdev) 
{ 
    struct pwm_device *pwm; 

    pwm = pwm_get(&pdev->dev, "backlight"); 
    if (IS_ERR(pwm)) { 
       pr_info("unable to request PWM, trying legacy API\n"); 
       /* 
        * Some drivers use the legacy API as fallback, in order 
        * to request a PWM ID, global to the system 
        * pwm = pwm_request(global_pwm_id, "pwm beeper"); 
        */ 
    } 

    [...] 
    return 0; 
} 
```

PWM 规范通常编码芯片相对 PWM 编号和以纳秒为单位的 PWM 周期。

# 使用 sysfs 接口的 PWM

PWM 核心`sysfs`根路径为`/sys/class/pwm/`。这是管理 PWM 设备的用户空间方式。系统中添加的每个 PWM 控制器/芯片都会在`sysfs`根路径下创建一个`pwmchipN`目录条目，其中`N`是 PWM 芯片的基础。该目录包含以下文件：

+   `npwm`：这是一个只读文件，打印此芯片支持的 PWM 通道数

+   `导出`：这是一个只写文件，允许将 PWM 通道导出供`sysfs`使用（此功能等效于 GPIO sysfs 接口）

+   `取消导出`：从`sysfs`中取消导出 PWM 通道（只写）

PWM 通道使用从 0 到`pwm<n-1>`的索引编号。这些数字是相对于芯片的。每个 PWM 通道导出都会在`pwmchipN`中创建一个`pwmX`目录，该目录与使用的`export`文件相同。**X**是导出的通道号。每个通道目录包含以下文件：

+   `周期`：这是一个可读/可写文件，用于获取/设置 PWM 信号的总周期。值以纳秒为单位。

+   `duty_cycle`：这是一个可读/可写文件，用于获取/设置 PWM 信号的占空比。它表示 PWM 信号的活动时间。值以纳秒为单位，必须始终小于周期。

+   `极性`：这是一个可读/可写文件，仅在此 PWM 设备的芯片支持极性反转时使用。最好只在此 PWM 未启用时更改极性。接受的值为字符串*normal*或*inversed*。

+   `启用`：这是一个可读/可写文件，用于启用（开始切换）/禁用（停止切换）PWM 信号。接受的值为：

+   0：已禁用

+   1：已启用

以下是通过`sysfs`接口从用户空间使用 PWM 的示例：

1.  启用 PWM：

```
 # echo 1 > /sys/class/pwm/pwmchip<pwmchipnr>/pwm<pwmnr>/enable

```

1.  设置 PWM 周期：

```
# echo **<value in nanoseconds> >** 

/sys/class/pwm/pwmchip**<pwmchipnr>**

/pwm**<pwmnr>**

/period

```

1.  设置 PWM 占空比：占空比的值必须小于 PWM 周期的值：

```
# echo **<value in nanoseconds>**

 > /sys/class/pwm/pwmchip**<pwmchipnr>**

/pwm**<pwmnr>**

/duty_cycle

```

1.  禁用 PWM：

```
 # echo 0 > /sys/class/pwm/pwmchip<pwmchipnr>/pwm<pwmnr>/enable 

```

完整的 PWM 框架 API 和 sysfs 描述可在内核源树中的*Documentation/pwm.txt*文件中找到。

# 摘要

到本章结束时，您将具备处理任何 PWM 控制器的能力，无论它是内存映射的还是外部连接在总线上的。本章描述的 API 将足以编写和增强控制器驱动程序作为消费者设备驱动程序。如果您对 PWM 内核端还不熟悉，可以完全使用用户空间 sysfs 接口。话虽如此，在下一章中，我们将讨论有时由 PWM 驱动的调节器。所以，请稍等，我们快要完成了。


# 第二十章：调节器框架

调节器是一种为其他设备提供电源的电子设备。由调节器供电的设备称为消费者。有人说他们消耗调节器提供的电源。大多数调节器可以启用和禁用其输出，有些还可以控制其输出电压或电流。驱动程序应通过特定的函数和数据结构向消费者公开这些功能，我们将在本章讨论。

物理提供调节器的芯片称为**电源管理集成电路**（**PMIC**）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00042.jpg)

Linux 调节器框架已经被设计用于接口和控制电压和电流调节器。它分为四个独立的接口，如下所示：

+   调节器驱动程序接口用于调节器 PMIC 驱动程序。此接口的结构可以在`include/linux/regulator/driver.h`中找到。

+   设备驱动程序的消费者接口。

+   用于板配置的机器接口。

+   用户空间的 sysfs 接口。

在本章中，我们将涵盖以下主题：

+   介绍 PMIC/生产者驱动程序接口、驱动程序方法和数据结构

+   ISL6271A MIC 驱动程序的案例研究，以及用于测试目的的虚拟调节器

+   调节器消费者接口及其 API

+   DT 中的调节器（生产者/消费者）绑定

# PMIC/生产者驱动程序接口

生产者是产生调节电压或电流的设备。这种设备的名称是 PMIC，它可以用于电源排序、电池管理、DC-DC 转换或简单的电源开关（开/关）。它通过软件控制调节输入电源的输出功率。

它涉及调节器驱动程序，特别是生产者 PMIC 方面，需要一些头文件：

```
#include <linux/platform_device.h> 
#include <linux/regulator/driver.h> 
#include <linux/regulator/of_regulator.h> 
```

# 驱动程序数据结构

我们将从调节器框架使用的数据结构的简短介绍开始。本节仅描述了生产者接口。

# 描述结构

内核通过`struct regulator_desc`结构描述了 PMIC 提供的每个调节器，该结构表征了调节器。通过调节器，我指的是任何独立的调节输出。例如，来自 Intersil 的 ISL6271A 是一个具有三个独立调节输出的 PMIC。然后，其驱动程序中应该有三个`regulator_desc`的实例。这个结构包含调节器的固定属性，看起来像下面这样：

```
struct regulator_desc { 
   const char *name; 
   const char *of_match; 

   int id; 
   unsigned n_voltages; 
   const struct regulator_ops *ops; 
   int irq; 
   enum regulator_type type; 
   struct module *owner; 

   unsigned int min_uV; 
   unsigned int uV_step; 
}; 
```

出于简单起见，我们将省略一些字段。完整的结构定义可以在`include/linux/regulator/driver.h`中找到：

+   `name`保存调节器的名称。

+   `of_match`保存了在 DT 中用于识别调节器的名称。

+   `id`是调节器的数字标识符。

+   `owner`表示提供调节器的模块。将此字段设置为`THIS_MODULE`。

+   `type`指示调节器是电压调节器还是电流调节器。它可以是`REGULATOR_VOLTAGE`或`REGULATOR_CURRENT`。任何其他值都将导致调节器注册失败。

+   `n_voltages`表示此调节器可用的选择器数量。它代表调节器可以输出的数值。对于固定输出电压，`n_voltages`应设置为 1。

+   `min_uV`表示此调节器可以提供的最小电压值。这是由最低选择器给出的电压。

+   `uV_step`表示每个选择器的电压增加。

+   `ops`表示调节器操作表。它是一个指向调节器可以支持的一组操作回调的结构。此字段稍后会讨论。

+   `irq`是调节器的中断号。

# 约束结构

当 PMIC 向消费者公开调节器时，它必须借助`struct regulation_constraints`结构为此调节器强加一些名义上的限制。这是一个收集调节器的安全限制并定义消费者不能越过的边界的结构。这是调节器驱动程序和消费者驱动程序之间的一种合同：

```
struct regulation_constraints { 
   const char *name; 

   /* voltage output range (inclusive) - for voltage control */ 
   int min_uV; 
   int max_uV; 

   int uV_offset; 

   /* current output range (inclusive) - for current control */ 
   int min_uA; 
   int max_uA; 

   /* valid regulator operating modes for this machine */ 
   unsigned int valid_modes_mask; 

   /* valid operations for regulator on this machine */ 
   unsigned int valid_ops_mask; 

   struct regulator_state state_disk; 
   struct regulator_state state_mem; 
   struct regulator_state state_standby; 
   suspend_state_t initial_state; /* suspend state to set at init */ 

   /* mode to set on startup */ 
   unsigned int initial_mode; 

   /* constraint flags */ 
   unsigned always_on:1;   /* regulator never off when system is on */ 
   unsigned boot_on:1;     /* bootloader/firmware enabled regulator */ 
   unsigned apply_uV:1;    /* apply uV constraint if min == max */ 
}; 
```

让我们描述结构中的每个元素：

+   `min_uV`，`min_uA`，`max_uA`和`max_uV`是消费者可以设置的最小电压/电流值。

+   `uV_offset` 是应用于消费者电压的补偿电压偏移量。

+   `valid_modes_mask`和`valid_ops_mask`分别是可以由消费者配置/执行的模式/操作的掩码。

+   如果寄存器永远不应该被禁用，则应设置`always_on`。

+   如果寄存器在系统初始启动时已启用，则应设置`boot_on`。如果寄存器不是由硬件或引导加载程序启用的，则在应用约束时将启用它。

+   `name`是用于显示目的的约束的描述性名称。

+   `apply_uV`在初始化时应用电压约束。

+   `input_uV`表示由另一个寄存器供电时该寄存器的输入电压。

+   `state_disk`，`state_mem` 和 `state_standby` 定义了系统在磁盘模式、内存模式或待机模式下挂起时的寄存器状态。

+   `initial_state` 表示默认设置为挂起状态。

+   `initial_mode`是启动时设置的模式。

# 初始化数据结构

有两种方法可以将`regulator_init_data`传递给驱动程序；这可以通过板初始化文件中的平台数据完成，也可以通过设备树中的节点使用`of_get_regulator_init_data`函数完成：

```
struct regulator_init_data { 
   struct regulation_constraints constraints; 

   /* optional regulator machine specific init */ 
   int (*regulator_init)(void *driver_data); 
   void *driver_data;      /* core does not touch this */ 
}; 
```

以下是结构中各元素的含义：

+   `constraints`表示寄存器约束

+   `regulator_init`是在核心注册寄存器时调用的可选回调

+   `driver_data`表示传递给`regulator_init`的数据

正如大家所看到的，`struct constraints`结构是`init data`的一部分。这是因为在初始化寄存器时，其约束直接应用于它，远在任何消费者使用之前。

# 将初始化数据输入到板文件中

该方法包括填充约束数组，可以从驱动程序内部或板文件中进行，并将其用作平台数据的一部分。以下是基于案例研究中的设备 ISL6271A from Intersil 的示例：

```
static struct regulator_init_data isl_init_data[] = { 
    [0] = { 
                .constraints = { 
                    .name           = "Core Buck", 
                    .min_uV         = 850000, 
                    .max_uV         = 1600000, 
                    .valid_modes_mask   = REGULATOR_MODE_NORMAL 
                                | REGULATOR_MODE_STANDBY, 
                    .valid_ops_mask     = REGULATOR_CHANGE_MODE 
                                | REGULATOR_CHANGE_STATUS, 
                }, 
        }, 
    [1] = { 
                .constraints = { 
                    .name           = "LDO1", 
                    .min_uV         = 1100000, 
                    .max_uV         = 1100000, 
                    .always_on      = true, 
                    .valid_modes_mask   = REGULATOR_MODE_NORMAL 
                                | REGULATOR_MODE_STANDBY, 
                    .valid_ops_mask     = REGULATOR_CHANGE_MODE 
                                | REGULATOR_CHANGE_STATUS, 
                }, 
        }, 
    [2] = { 
                .constraints = { 
                    .name           = "LDO2", 
                    .min_uV         = 1300000, 
                    .max_uV         = 1300000, 
                    .always_on      = true, 
                    .valid_modes_mask   = REGULATOR_MODE_NORMAL 
                                | REGULATOR_MODE_STANDBY, 
                    .valid_ops_mask     = REGULATOR_CHANGE_MODE 
                                | REGULATOR_CHANGE_STATUS, 
                }, 
        }, 
}; 
```

尽管此方法现在已被弃用，但这里仍介绍了它供您参考。新的推荐方法是 DT，将在下一节中介绍。

# 将初始化数据输入 DT

为了从 DT 中提取传递的初始化数据，我们需要引入一个新的数据类型`struct of_regulator_match`，它看起来像这样：

```
struct of_regulator_match { 
   const char *name; 
   void *driver_data; 
   struct regulator_init_data *init_data; 
   struct device_node *of_node; 
   const struct regulator_desc *desc; 
}; 
```

在使用此数据结构之前，我们需要弄清楚如何实现 DT 文件的寄存器绑定。

DT 中的每个 PMIC 节点都应该有一个名为`regulators`的子节点，在其中我们必须声明此 PMIC 提供的每个寄存器作为专用子节点。换句话说，每个 PMIC 的寄存器都被定义为`regulators`节点的子节点，而`regulators`节点又是 DT 中 PMIC 节点的子节点。

在寄存器节点中，您可以定义标准化的属性：

+   `regulator-name`：这是用作寄存器输出的描述性名称的字符串

+   `regulator-min-microvolt`：这是消费者可以设置的最小电压

+   `regulator-max-microvolt`：这是消费者可以设置的最大电压

+   `regulator-microvolt-offset`：这是应用于电压以补偿电压下降的偏移量

+   `regulator-min-microamp`：这是消费者可以设置的最小电流

+   `regulator-max-microamp`：这是消费者可以设置的最大电流

+   `regulator-always-on`：这是一个布尔值，指示寄存器是否永远不应该被禁用

+   `regulator-boot-on`：这是一个由引导加载程序/固件启用的寄存器

+   `<name>-supply`：这是父供电/寄存器节点的 phandle

+   `regulator-ramp-delay`：这是寄存器的斜坡延迟（以 uV/uS 为单位）

这些属性看起来真的像是`struct regulator_init_data`中的字段。回到`ISL6271A`驱动程序，其 DT 条目可能如下所示：

```
isl6271a@3c { 
   compatible = "isl6271a"; 
   reg = <0x3c>; 
   interrupts = <0 86 0x4>; 

    /* supposing our regulator is powered by another regulator */ 
   in-v1-supply = <&some_reg>; 
   [...] 

   regulators { 
         reg1: core_buck { 
               regulator-name = "Core Buck"; 
               regulator-min-microvolt = <850000>; 
               regulator-max-microvolt = <1600000>; 
         }; 

         reg2: ldo1 { 
               regulator-name = "LDO1"; 
               regulator-min-microvolt = <1100000>; 
               regulator-max-microvolt = <1100000>; 
               regulator-always-on; 
         }; 

         reg3: ldo2 { 
               regulator-name = "LDO2"; 
               regulator-min-microvolt = <1300000>; 
               regulator-max-microvolt = <1300000>; 
               regulator-always-on; 
         }; 
   }; 
}; 
```

使用内核辅助函数`of_regulator_match()`，给定`regulators`子节点作为参数，该函数将遍历每个调节器设备节点，并为每个构建一个`struct init_data`结构。在驱动程序方法部分讨论的`probe()`函数中有一个示例。

# 配置结构

调节器设备通过`struct regulator_config`结构进行配置，该结构保存调节器描述的可变元素。在向核心注册调节器时，将传递此结构：

```
struct regulator_config { 
   struct device *dev; 
   const struct regulator_init_data *init_data; 
   void *driver_data; 
   struct device_node *of_node; 
}; 
```

+   `dev`代表调节器所属的设备结构。

+   `init_data`是结构的最重要字段，因为它包含一个包含调节器约束（机器特定结构）的元素。

+   `driver_data`保存调节器的私有数据。

+   `of_node` 用于支持 DT 的驱动程序。这是要解析 DT 绑定的节点。开发人员负责设置此字段。它也可以是`NULL`。

# 设备操作结构

`struct regulator_ops`结构是一个回调列表，表示调节器可以执行的所有操作。这些回调是辅助函数，并由通用内核函数包装：

```
struct regulator_ops { 
   /* enumerate supported voltages */ 
   int (*list_voltage) (struct regulator_dev *, 
                        unsigned selector); 

   /* get/set regulator voltage */ 
   int (*set_voltage) (struct regulator_dev *, 
                        int min_uV, int max_uV, 
                        unsigned *selector); 
   int (*map_voltage)(struct regulator_dev *, 
                       int min_uV, int max_uV); 
   int (*set_voltage_sel) (struct regulator_dev *, 
                           unsigned selector); 
   int (*get_voltage) (struct regulator_dev *); 
   int (*get_voltage_sel) (struct regulator_dev *); 

   /* get/set regulator current  */ 
   int (*set_current_limit) (struct regulator_dev *, 
                          int min_uA, int max_uA); 
   int (*get_current_limit) (struct regulator_dev *); 

   int (*set_input_current_limit) (struct regulator_dev *, 
                                   int lim_uA); 
   int (*set_over_current_protection) (struct regulator_dev *); 
   int (*set_active_discharge) (struct regulator_dev *, 
                                bool enable); 

   /* enable/disable regulator */ 
   int (*enable) (struct regulator_dev *); 
   int (*disable) (struct regulator_dev *); 
   int (*is_enabled) (struct regulator_dev *); 

   /* get/set regulator operating mode (defined in consumer.h) */ 
   int (*set_mode) (struct regulator_dev *, unsigned int mode); 
   unsigned int (*get_mode) (struct regulator_dev *); 
}; 
```

回调名称很好地解释了它们的作用。这里没有列出的其他回调，您必须在消费者使用它们之前在调节器的约束中启用适当的掩码`valid_ops_mask`或`valid_modes_mask`。可用的操作掩码标志在`include/linux/regulator/machine.h`中定义。

因此，给定一个`struct regulator_dev`结构，可以通过调用`rdev_get_id()`函数获取相应调节器的 ID：

```
int rdev_get_id(struct regulator_dev *rdev) 
```

# 驱动程序方法

驱动程序方法包括`probe()`和`remove()`函数。如果此部分对您不清楚，请参考前面的数据结构。

# 探测功能

PMIC 驱动程序的`probe`功能可以分为几个步骤，列举如下：

1.  为此 PMIC 提供的所有调节器定义一个`struct regulator_desc`对象数组。在此步骤中，您应该已经定义了一个有效的`struct regulator_ops`，以链接到适当的`regulator_desc`。假设它们都支持相同的操作，可以对所有调节器使用相同的`regulator_ops`。

1.  现在在`probe`函数中，对于每个调节器：

+   +   从平台数据中获取适当的`struct regulator_init_data`，该数据必须已包含有效的`struct regulation_constraints`，或者从 DT 构建一个`struct regulation_constraints`，以构建一个新的`struct regulator_init_data`对象。

+   使用先前的`struct regulator_init_data`来设置`struct regulator_config`结构。如果驱动程序支持 DT，可以使`regulator_config.of_node`指向用于提取调节器属性的节点。

+   调用`regulator_register()`（或托管版本的`devm_regulator_register()`）来使用先前的`regulator_desc`和`regulator_config`作为参数向核心注册调节器。

使用`regulator_register()`函数或`devm_regulator_register()`，将调节器注册到内核中：

```
struct regulator_dev * regulator_register(const struct regulator_desc           *regulator_desc, const struct regulator_config *cfg) 
```

此函数返回一个我们到目前为止尚未讨论的数据类型：`struct regulator_dev`对象，定义在`include/linux/regulator/driver.h`中。该结构表示来自生产方的调节器设备的实例（在消费方方面不同）。`struct regulator_dev`结构的实例不应直接被任何东西使用，除了调节器核心和通知注入（应该获取互斥锁，而不是其他直接访问）。也就是说，为了跟踪驱动程序内部注册的调节器，应该为注册函数返回的每个`regulator_dev`对象保留引用。

# 删除功能

`remove()`函数是在`probe`期间执行的每个操作的地方。因此，你应该牢记的关键函数是`regulator_unregister()`，当需要从系统中移除调节器时：

```
void regulator_unregister(struct regulator_dev *rdev) 
```

这个函数接受一个`struct regulator_dev`结构的指针作为参数。这也是为每个注册的调节器保留引用的另一个原因。以下是 ISL6271A 驱动程序的`remove`函数：

```
static int __devexit isl6271a_remove(struct i2c_client *i2c) 
{ 
   struct isl_pmic *pmic = i2c_get_clientdata(i2c); 
   int i; 

   for (i = 0; i < 3; i++) 
         regulator_unregister(pmic->rdev[i]); 

   kfree(pmic); 
   return 0; 
} 
```

# 案例研究：Intersil ISL6271A 电压调节器

回顾一下，这个 PMIC 提供了三个调节器设备，其中只有一个可以改变其输出值。另外两个提供固定电压：

```
struct isl_pmic { 
   struct i2c_client *client; 
   struct regulator_dev    *rdev[3]; 
   struct mutex            mtx; 
}; 
```

首先我们定义 ops 回调函数，来设置`struct regulator_desc`：

1.  处理`get_voltage_sel`操作的回调函数：

```
static int isl6271a_get_voltage_sel(struct regulator_dev *rdev) 
{ 
   struct isl_pmic *pmic = rdev_get_drvdata(dev); 
   int idx = rdev_get_id(rdev); 
   idx = i2c_smbus_read_byte(pmic->client); 
   if (idx < 0) 
         [...] /* handle this error */ 

   return idx; 
} 
```

以下是处理`set_voltage_sel`操作的回调函数：

```
static int isl6271a_set_voltage_sel( 
struct regulator_dev *dev, unsigned selector) 
{ 
   struct isl_pmic *pmic = rdev_get_drvdata(dev); 
   int err; 

   err = i2c_smbus_write_byte(pmic->client, selector); 
   if (err < 0) 
         [...] /* handle this error */ 

   return err; 
} 
```

1.  既然我们已经完成了回调函数的定义，我们可以构建一个`struct regulator_ops`：

```
static struct regulator_ops isl_core_ops = { 
   .get_voltage_sel = isl6271a_get_voltage_sel, 
   .set_voltage_sel = isl6271a_set_voltage_sel, 
   .list_voltage     = regulator_list_voltage_linear, 
   .map_voltage      = regulator_map_voltage_linear, 
}; 

static struct regulator_ops isl_fixed_ops = { 
   .list_voltage     = regulator_list_voltage_linear, 
}; 
```

你可能会问`regulator_list_voltage_linear`和`regulator_list_voltage_linear`函数是从哪里来的。和许多其他调节器辅助函数一样，它们也在`drivers/regulator/helpers.c`中定义。内核为线性输出调节器提供了辅助函数，就像 ISL6271A 一样。

现在是时候为所有调节器构建一个`struct regulator_desc`数组了：

```
static const struct regulator_desc isl_rd[] = { 
   { 
         .name       = "Core Buck", 
         .id         = 0, 
         .n_voltages = 16, 
         .ops        = &isl_core_ops, 
         .type       = REGULATOR_VOLTAGE, 
         .owner            = THIS_MODULE, 
         .min_uV     = ISL6271A_VOLTAGE_MIN, 
         .uV_step    = ISL6271A_VOLTAGE_STEP, 
   }, { 
         .name       = "LDO1", 
         .id         = 1, 
         .n_voltages = 1, 
         .ops        = &isl_fixed_ops, 
         .type       = REGULATOR_VOLTAGE, 
         .owner            = THIS_MODULE, 
         .min_uV     = 1100000, 
   }, { 
         .name       = "LDO2", 
         .id         = 2, 
         .n_voltages = 1, 
         .ops        = &isl_fixed_ops, 
         .type       = REGULATOR_VOLTAGE, 
         .owner            = THIS_MODULE, 
         .min_uV     = 1300000, 
   }, 
}; 
```

`LDO1`和`LDO2`具有固定的输出电压。这就是为什么它们的`n_voltages`属性被设置为 1，它们的 ops 只提供`regulator_list_voltage_linear`映射。

1.  现在我们在`probe`函数中，这是我们需要构建`struct init_data`结构的地方。如果你记得，我们将使用之前介绍的`struct of_regulator_match`。我们应该声明一个该类型的数组，在其中我们应该设置每个需要获取`init_data`的调节器的`.name`属性：

```
static struct of_regulator_match isl6271a_matches[] = { 
   { .name = "core_buck",  }, 
   { .name = "ldo1",       }, 
   { .name = "ldo2",       }, 
}; 
```

仔细看，你会注意到`.name`属性的设置与设备树中调节器的标签完全相同。这是你应该关心和尊重的规则。

现在让我们看一下`probe`函数。ISL6271A 提供三个调节器输出，这意味着应该调用`regulator_register()`函数三次：

```
static int isl6271a_probe(struct i2c_client *i2c, 
                          const struct i2c_device_id *id) 
{ 
struct regulator_config config = { }; 
struct regulator_init_data *init_data     = 
dev_get_platdata(&i2c->dev); 
struct isl_pmic *pmic; 
int i, ret; 

    struct device *dev = &i2c->dev; 
    struct device_node *np, *parent; 

   if (!i2c_check_functionality(i2c->adapter, 
                     I2C_FUNC_SMBUS_BYTE_DATA)) 
         return -EIO; 

   pmic = devm_kzalloc(&i2c->dev, 
sizeof(struct isl_pmic), GFP_KERNEL); 
   if (!pmic) 
         return -ENOMEM; 

    /* Get the device (PMIC) node */ 
    np = of_node_get(dev->of_node); 
   if (!np) 
         return -EINVAL; 

    /* Get 'regulators' subnode */ 
    parent = of_get_child_by_name(np, "regulators"); 
   if (!parent) { 
         dev_err(dev, "regulators node not found\n"); 
         return -EINVAL; 
   } 

    /* fill isl6271a_matches array */ 
    ret = of_regulator_match(dev, parent, isl6271a_matches, 
                            ARRAY_SIZE(isl6271a_matches)); 

    of_node_put(parent); 
   if (ret < 0) { 
         dev_err(dev, "Error parsing regulator init data: %d\n", 
               ret); 
         return ret; 
   } 

   pmic->client = i2c; 
   mutex_init(&pmic->mtx); 

   for (i = 0; i < 3; i++) { 
        struct regulator_init_data *init_data; 
         struct regulator_desc *desc; 
         int val; 

         if (pdata) 
               /* Given as platform data */ 
               config.init_data = pdata->init_data[i]; 
         else 
               /* Fetched from device tree */ 
               config.init_data = isl6271a_matches[i].init_data; 

         config.dev = &i2c->dev; 
config.of_node = isl6271a_matches[i].of_node; 
config.ena_gpio = -EINVAL; 

         /* 
          * config is passed by reference because the kernel 
          * internally duplicate it to create its own copy 
          * so that it can override some fields 
          */ 
         pmic->rdev[i] = devm_regulator_register(&i2c->dev, 
                                 &isl_rd[i], &config); 
         if (IS_ERR(pmic->rdev[i])) { 
               dev_err(&i2c->dev, "failed to register %s\n", 
id->name); 
               return PTR_ERR(pmic->rdev[i]); 
         } 
   } 
   i2c_set_clientdata(i2c, pmic); 
   return 0; 
} 
```

对于固定调节器，`init_data`可以是`NULL`。这意味着对于 ISL6271A，只有可能改变电压输出的调节器可以被分配一个`init_data`。

```
/* Only the first regulator actually need it */ 
if (i == 0) 
    if(pdata) 
            config.init_data = init_data; /* pdata */ 
      else 
            isl6271a_matches[i].init_data; /* DT */ 
else 
    config.init_data = NULL; 
```

前面的驱动程序并没有填充`struct regulator_desc`的每个字段。这在很大程度上取决于我们为其编写驱动程序的设备类型。一些驱动程序将整个工作交给了调节器核心，只提供了调节器核心需要处理的芯片寄存器地址。这样的驱动程序使用**regmap** API，这是一个通用的 I2C 和 SPI 寄存器映射库。`drivers/regulator/max8649.c`就是一个例子。

# 驱动程序示例

让我们总结一下之前讨论的内容，对于一个带有两个调节器的虚拟 PMIC 的真实驱动程序，其中第一个调节器的电压范围为 850000 µV 到 1600000 µV，步进为 50000 µV，而第二个调节器的电压固定为 1300000 µV：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/platform_device.h>      /* For platform devices */ 
#include <linux/interrupt.h>            /* For IRQ */ 
#include <linux/of.h>                   /* For DT*/ 
#include <linux/err.h> 
#include <linux/regulator/driver.h> 
#include <linux/regulator/machine.h> 

#define DUMMY_VOLTAGE_MIN    850000 
#define DUMMY_VOLTAGE_MAX    1600000 
#define DUMMY_VOLTAGE_STEP   50000 

struct my_private_data { 
    int foo; 
    int bar; 
    struct mutex lock; 
}; 

static const struct of_device_id regulator_dummy_ids[] = { 
    { .compatible = "packt,regulator-dummy", }, 
    { /* sentinel */ } 
}; 

static struct regulator_init_data dummy_initdata[] = { 
    [0] = { 
        .constraints = { 
            .always_on = 0, 
            .min_uV = DUMMY_VOLTAGE_MIN, 
            .max_uV = DUMMY_VOLTAGE_MAX, 
        }, 
    }, 
    [1] = { 
        .constraints = { 
            .always_on = 1, 
        }, 
    }, 
}; 

static int isl6271a_get_voltage_sel(struct regulator_dev *dev) 
{ 
    return 0; 
} 

static int isl6271a_set_voltage_sel(struct regulator_dev *dev, 
                    unsigned selector) 
{ 
    return 0; 
} 

static struct regulator_ops dummy_fixed_ops = { 
    .list_voltage   = regulator_list_voltage_linear, 
}; 

static struct regulator_ops dummy_core_ops = { 
    .get_voltage_sel = isl6271a_get_voltage_sel, 
    .set_voltage_sel = isl6271a_set_voltage_sel, 
    .list_voltage   = regulator_list_voltage_linear, 
    .map_voltage    = regulator_map_voltage_linear, 
}; 

static const struct regulator_desc dummy_desc[] = { 
    { 
        .name       = "Dummy Core", 
        .id     = 0, 
        .n_voltages = 16, 
        .ops        = &dummy_core_ops, 
        .type       = REGULATOR_VOLTAGE, 
        .owner      = THIS_MODULE, 
        .min_uV     = DUMMY_VOLTAGE_MIN, 
        .uV_step    = DUMMY_VOLTAGE_STEP, 
    }, { 
        .name       = "Dummy Fixed", 
        .id     = 1, 
        .n_voltages = 1, 
        .ops        = &dummy_fixed_ops, 
        .type       = REGULATOR_VOLTAGE, 
        .owner      = THIS_MODULE, 
        .min_uV     = 1300000, 
    }, 
}; 

static int my_pdrv_probe (struct platform_device *pdev) 
{ 
   struct regulator_config config = { }; 
   config.dev = &pdev->dev; 

   struct regulator_dev *dummy_regulator_rdev[2]; 

    int ret, i; 
    for (i = 0; i < 2; i++){ 
        config.init_data = &dummy_initdata[i]; 
        dummy_regulator_rdev[i] = \ 
              regulator_register(&dummy_desc[i], &config); 
        if (IS_ERR(dummy_regulator_rdev)) { 
            ret = PTR_ERR(dummy_regulator_rdev); 
            pr_err("Failed to register regulator: %d\n", ret); 
            return ret; 
        } 
    } 

    platform_set_drvdata(pdev, dummy_regulator_rdev); 
    return 0; 
} 

static void my_pdrv_remove(struct platform_device *pdev) 
{ 
    int i; 
    struct regulator_dev *dummy_regulator_rdev = \ 
                            platform_get_drvdata(pdev); 
    for (i = 0; i < 2; i++) 
        regulator_unregister(&dummy_regulator_rdev[i]); 
} 

static struct platform_driver mypdrv = { 
    .probe      = my_pdrv_probe, 
    .remove     = my_pdrv_remove, 
    .driver     = { 
        .name     = "regulator-dummy", 
        .of_match_table = of_match_ptr(regulator_dummy_ids),   
        .owner    = THIS_MODULE, 
    }, 
}; 
module_platform_driver(mypdrv); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

一旦模块加载并且设备匹配，内核将打印类似于这样的内容：

```
Dummy Core: at 850 mV

Dummy Fixed: 1300 mV

```

然后可以检查底层发生了什么：

```
 # ls /sys/class/regulator/

regulator.0 regulator.11 regulator.14 regulator.4 regulator.7

regulator.1 regulator.12 regulator.2 regulator.5 regulator.8

regulator.10 regulator.13 regulator.3 regulator.6 regulator.9 

```

`regulator.13`和`regulator.14`已经被我们的驱动程序添加。现在让我们检查它们的属性：

```
# cd /sys/class/regulator

# cat regulator.13/name

Dummy Core

# cat regulator.14/name

Dummy Fixed

# cat regulator.14/type

voltage

# cat regulator.14/microvolts

1300000

# cat regulator.13/microvolts

850000

```

# 调节器消费者接口

消费者接口只需要驱动程序包含一个头文件：

```
#include <linux/regulator/consumer.h> 
```

消费者可以是静态的或动态的。静态消费者只需要一个固定的供应，而动态消费者需要在运行时主动管理调节器。从消费者的角度来看，调节器设备在内核中表示为`drivers/regulator/internal.h`中定义的`struct regulator`结构的实例，如下所示：

```
/* 
 * struct regulator 
 * 
 * One for each consumer device. 
 */ 
struct regulator { 
   struct device *dev; 
   struct list_head list; 
   unsigned int always_on:1; 
   unsigned int bypass:1; 
   int uA_load; 
   int min_uV; 
   int max_uV; 
   char *supply_name; 
   struct device_attribute dev_attr; 
   struct regulator_dev *rdev; 
   struct dentry *debugfs; 
}; 
```

这个结构已经足够有意义，不需要我们添加任何注释。为了看到消费者如何轻松地使用调节器，这里有一个消费者获取调节器的小例子：

```
[...] 
int ret; 
struct regulator *reg; 
const char *supply = "vdd1"; 
int min_uV, max_uV; 
reg = regulator_get(dev, supply); 
[...] 
```

# 调节器设备请求

在获得对调节器的访问之前，消费者必须通过`regulator_get()`函数向内核请求。也可以使用托管版本，即`devm_regulator_get()`函数：

```
struct regulator *regulator_get(struct device *dev, 
const char *id) 
```

使用此函数的一个例子是：

```
    reg = regulator_get(dev, "Vcc"); 
```

消费者传递它的`struct device`指针和电源供应 ID。内核将尝试通过查阅 DT 或特定于机器的查找表来找到正确的调节器。如果我们只关注设备树，`*id`应该与设备树中调节器供应的`<name>`模式匹配。如果查找成功，那么此调用将返回一个指向为此消费者提供电源的`struct regulator`的指针。

要释放调节器，消费者驱动程序应调用：

```
void regulator_put(struct regulator *regulator) 
```

在调用此函数之前，驱动程序应确保对此调节器源进行的所有`regulator_enable()`调用都由`regulator_disable()`调用平衡。

一个消费者可以由多个调节器供应，例如，带有模拟和数字供应的编解码器消费者：

```
    digital = regulator_get(dev, "Vcc");  /* digital core */ 
    analog = regulator_get(dev, "Avdd");  /* analog */ 
```

消费者的`probe()`和`remove()`函数是抓取和释放调节器的适当位置。

# 控制调节器设备

调节器控制包括启用、禁用和设置调节器的输出值。

# 调节器输出启用和禁用

消费者可以通过调用以下方式启用其电源：

```
int regulator_enable(regulator); 
```

此函数成功返回 0。相反的操作是通过调用此函数来禁用电源：

```
int regulator_disable(regulator); 
```

要检查调节器是否已启用，消费者应调用此函数：

```
int regulator_is_enabled(regulator); 
```

如果调节器已启用，则此函数返回大于 0 的值。由于调节器可能会被引导加载程序提前启用或与其他消费者共享，因此可以使用`regulator_is_enabled()`函数来检查调节器状态。

这里有一个例子，

```
 printk (KERN_INFO "Regulator Enabled = %d\n", 
                           regulator_is_enabled(reg));     
```

对于共享的调节器，`regulator_disable()`只有在启用的引用计数为零时才会真正禁用调节器。也就是说，在紧急情况下，例如通过调用`regulator_force_disable()`可以强制禁用：

```
int regulator_force_disable(regulator); 
```

我们将在接下来的章节中讨论的每个函数实际上都是围绕着`regulator_ops`操作的一个包装器。例如，`regulator_set_voltage()`在检查相应的掩码允许此操作设置后，内部调用`regulator_ops.set_voltage`，依此类推。

# 电压控制和状态

对于需要根据其操作模式调整其电源的消费者，内核提供了这个：

```
int regulator_set_voltage(regulator, min_uV, max_uV); 
```

`min_uV`和`max_uV`是微伏的最小和最大可接受电压。

如果在调节器禁用时调用此函数，它将更改电压配置，以便在下次启用调节器时物理设置电压。也就是说，消费者可以通过调用`regulator_get_voltage()`来获取调节器配置的电压输出，无论调节器是否启用：

```
int regulator_get_voltage(regulator); 
```

这里有一个例子，

```
printk (KERN_INFO "Regulator Voltage = %d\n",  
regulator_get_voltage(reg)); 
```

# 电流限制控制和状态

我们在电压部分讨论的内容在这里也适用。例如，USB 驱动程序可能希望在供电时将限制设置为 500 毫安。

消费者可以通过调用以下方式控制其供应电流限制：

```
int regulator_set_current_limit(regulator, min_uA, max_uA); 
```

`min_uA`和`max_uA`是微安的最小和最大可接受电流限制。

同样，消费者可以通过调用`regulator_get_current_limit()`来获取调节器配置的电流限制，无论调节器是否启用：

```
int regulator_get_current_limit(regulator); 
```

# 工作模式控制和状态

为了有效的电源管理，一些消费者可能会在他们的操作状态改变时改变他们供应的工作模式。消费者驱动程序可以通过调用以下方式请求改变他们的供应调节器工作模式：

```
int regulator_set_optimum_mode(struct regulator *regulator, 
int load_uA); 
int regulator_set_mode(struct regulator *regulator, 
unsigned int mode); 
unsigned int regulator_get_mode(struct regulator *regulator); 
```

消费者应仅在了解调节器并且不与其他消费者共享调节器时，才能在调节器上使用`regulator_set_mode（）`。这被称为**直接模式**。`regulator_set_uptimum_mode（）`会导致核心进行一些后台工作，以确定请求电流的最佳操作模式。这被称为**间接模式**。

# 调节器绑定

本节仅涉及消费者接口绑定。因为 PMIC 绑定包括为该 PMIC 提供的调节器提供`init data`，所以您应该参考*将 init data 输入 DT*部分以了解生产者绑定。

消费者节点可以使用以下绑定引用其一个或多个供应/调节器：

```
<name>-supply: phandle to the regulator node 
```

这与 PWM 消费者绑定的原理相同。 `<name>` 应该有足够的意义，以便驱动程序在请求调节器时可以轻松地引用它。也就是说，`<name>` 必须与`regulator_get（）`函数的`*id`参数匹配：

```
twl_reg1: regulator@0 { 
   [...] 
}; 

twl_reg2: regulator@1 { 
   [...] 
}; 

mmc: mmc@0x0 { 
   [...] 
   vmmc-supply = <&twl_reg1>; 
   vmmcaux-supply = <&twl_reg2>; 
}; 
```

消费者代码（即 MMC 驱动程序）实际请求其供应可能如下所示：

```
struct regulator *main_regulator; 
struct regulator *aux_regulator;  
int ret; 
main_regulator = devm_regulator_get(dev, "vmmc"); 

/* 
 * It is a good practive to apply the config before 
 * enabling the regulator 
 */ 
if (!IS_ERR(io_regulator)) { 
   regulator_set_voltage(main_regulator, 
                    MMC_VOLTAGE_DIGITAL, 
                     MMC_VOLTAGE_DIGITAL); 
   ret = regulator_enable(io_regulator); 
} 
[...] 
aux_regulator = devm_regulator_get(dev, "vmmcaux"); 
[...] 
```

# 摘要

由于需要智能和平稳供电的各种设备，可以依靠本章来处理它们的电源管理。 PMIC 设备通常位于 SPI 或 I2C 总线上。在之前的章节中已经处理过这些总线，因此您应该能够编写任何 PMIC 驱动程序。现在让我们跳到下一章，该章涉及帧缓冲驱动程序，这是一个完全不同但同样有趣的主题。


# 第二十一章：帧缓冲驱动程序

视频卡始终具有一定数量的 RAM。这个 RAM 是图像数据的位图在显示时缓冲的地方。从软件的角度来看，帧缓冲是一个字符设备，提供对这个 RAM 的访问。

也就是说，帧缓冲驱动程序提供了一个接口：

+   显示模式设置

+   访问视频缓冲区的内存

+   基本的 2D 加速操作（例如滚动）

为了提供这个接口，帧缓冲驱动程序通常直接与硬件通信。有一些众所周知的帧缓冲驱动程序，比如：

+   **intelfb**，这是各种英特尔 8xx/9xx 兼容图形设备的帧缓冲

+   **vesafb**，这是一个使用 VESA 标准接口与视频硬件通信的帧缓冲驱动程序

+   **mxcfb**，i.MX6 芯片系列的帧缓冲驱动程序

帧缓冲驱动程序是 Linux 下最简单的图形驱动程序形式，不要将它们与实现高级功能（如 3D 加速等）的 X.org 驱动程序混淆，也不要将它们与内核模式设置（KMS）驱动程序混淆，后者公开了帧缓冲和 GPU 功能（与 X.org 驱动程序一样）。

i.MX6 X.org 驱动程序是一个闭源的，称为**vivante**。

回到我们的帧缓冲驱动程序，它们是非常简单的 API 驱动程序，通过字符设备公开了视频卡功能，可以通过`/dev/fbX`条目从用户空间访问。有关 Linux 图形堆栈的更多信息，可以参考 Martin Fiedler 的全面讲座*Linux Graphics Demystified*：[`keyj.emphy.de/files/linuxgraphics_en.pdf`](http://keyj.emphy.de/files/linuxgraphics_en.pdf)。

在本章中，我们涵盖以下主题：

+   帧缓冲驱动程序数据结构和方法，从而涵盖了整个驱动程序架构

+   帧缓冲设备操作，加速和非加速

+   从用户空间访问帧缓冲

# 驱动程序数据结构

帧缓冲驱动程序严重依赖于四个数据结构，所有这些都在`include/linux/fb.h`中定义，这也是您应该在代码中包含的头文件，以便处理帧缓冲驱动程序：

```
#include <linux/fb.h> 
```

这些结构是`fb_var_screeninfo`，`fb_fix_screeninfo`，`fb_cmap`和`fb_info`。前三个可以在用户空间代码中使用。现在让我们描述每个结构的目的，它们的含义以及它们的用途。

1.  内核使用`struct struct fb_var_screeninfo`的实例来保存视频卡的可变属性。这些值是用户定义的，比如分辨率深度：

```
struct fb_var_screeninfo { 
   __u32 xres; /* visible resolution */ 
   __u32 yres; 

   __u32 xres_virtual; /* virtual resolution */ 
   __u32 yres_virtual; 

   __u32 xoffset; /* offset from virtual to visible resolution */ 
   __u32 yoffset; 

   __u32 bits_per_pixel; /* # of bits needed to hold a pixel */ 
   [...] 

   /* Timing: All values in pixclocks, except pixclock (of course) */ 
   __u32 pixclock;   /* pixel clock in ps (pico seconds) */ 
   __u32 left_margin;      /* time from sync to picture */ 
   __u32 right_margin; /* time from picture to sync */ 
   __u32 upper_margin; /* time from sync to picture */ 
   __u32 lower_margin; 
   __u32 hsync_len;  /* length of horizontal sync */ 
   __u32 vsync_len;  /* length of vertical sync */ 
   __u32 rotate; /* angle we rotate counter clockwise */ 
}; 
```

这可以总结为以下所示的图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00043.jpg)

1.  视频卡的属性是固定的，要么由制造商固定，要么在设置模式时应用，并且否则不能更改。这通常是硬件信息。一个很好的例子是帧缓冲内存的开始，即使用户程序也不能更改。内核将这样的信息保存在`struct fb_fix_screeninfo`结构的实例中：

```
struct fb_fix_screeninfo { 
   char id[16];      /* identification string eg "TT Builtin" */ 
   unsigned long smem_start;     /* Start of frame buffer mem */ 
                           /* (physical address) */ 
   __u32 smem_len;/* Length of frame buffer mem */ 
   __u32 type;    /* see FB_TYPE_*           */ 
   __u32 type_aux; /* Interleave for interleaved Planes */ 
   __u32 visual;   /* see FB_VISUAL_*  */  
   __u16 xpanstep; /* zero if no hardware panning  */ 
   __u16 ypanstep;   /* zero if no hardware panning  */ 
   __u16 ywrapstep;  /* zero if no hardware ywrap    */ 
   __u32 line_length;  /* length of a line in bytes    */ 
   unsigned long mmio_start; /* Start of Memory Mapped I/O  
 *(physical address) 
 */ 
   __u32 mmio_len;   /* Length of Memory Mapped I/O  */ 
   __u32 accel;      /* Indicate to driver which   */ 
                     /* specific chip/card we have */ 
   __u16 capabilities; /* see FB_CAP_* */ 
}; 
```

1.  `struct fb_cmap`结构指定了颜色映射，用于以内核可以理解的方式存储用户对颜色的定义，以便将其发送到底层视频硬件。可以使用这个结构来定义您对不同颜色所需的 RGB 比例：

```
struct fb_cmap { 
    __u32 start;   /* First entry */ 
    __u32 len;     /* Number of entries */ 
    __u16 *red;    /* Red values */ 
    __u16 *green;  /* Green values */ 
    __u16 *blue;   /* Blue values */ 
    __u16 *transp; /* Transparency. Discussed later on */ 
}; 
```

1.  代表帧缓冲本身的`struct fb_info`结构是帧缓冲驱动程序的主要数据结构。与前面讨论的其他结构不同，`fb_info`仅存在于内核中，不是用户空间帧缓冲 API 的一部分：

```
struct fb_info { 
    [...] 
    struct fb_var_screeninfo var; /* Variable screen information. 
                                   Discussed earlier. */ 
    struct fb_fix_screeninfo fix; /* Fixed screen information. */ 
    struct fb_cmap cmap;          /* Color map. */ 
    struct fb_ops *fbops;         /* Driver operations.*/ 
    char __iomem *screen_base;    /* Frame buffer's 
                                   virtual address */ 
    unsigned long screen_size;    /* Frame buffer's size */ 
    [...] 
   struct device *device;        /* This is the parent */ 
struct device *dev;           /* This is this fb device */ 
#ifdef CONFIG_FB_BACKLIGHT 
      /* assigned backlight device */ 
      /* set before framebuffer registration,  
         remove after unregister */ 
      struct backlight_device *bl_dev; 

      /* Backlight level curve */ 
      struct mutex bl_curve_mutex;   
      u8 bl_curve[FB_BACKLIGHT_LEVELS]; 
#endif 
[...] 
void *par; /* Pointer to private memory */ 
}; 
```

`struct fb_info`结构应始终动态分配，使用`framebuffer_alloc()`，这是一个内核（帧缓冲核心）辅助函数，用于为帧缓冲设备的实例分配内存，以及它们的私有数据内存：

```
struct fb_info *framebuffer_alloc(size_t size, struct device *dev) 
```

在这个原型中，`size`表示私有区域的大小作为参数，并将其附加到分配的`fb_info`的末尾。可以使用`fb_info`结构中的`.par`指针引用此私有区域。`framebuffer_release()`执行相反的操作：

```
void framebuffer_release(struct fb_info *info) 
```

设置完成后，应使用`register_framebuffer()`向内核注册帧缓冲，如果出现错误，则返回负的`errno`，或者成功返回`零`：

```
int register_framebuffer(struct fb_info *fb_info) 
```

注册后，可以使用`unregister_framebuffer()`函数取消注册帧缓冲，如果出现错误，则返回负的`errno`，或者成功返回`零`：

```
int unregister_framebuffer(struct fb_info *fb_info) 
```

分配和注册应在设备探测期间完成，而取消注册和释放应在驱动程序的`remove()`函数内完成。

# 设备方法

在`struct fb_info`结构中，有一个`.fbops`字段，它是`struct fb_ops`结构的一个实例。该结构包含一组需要在帧缓冲设备上执行一些操作的函数。这些是`fbdev`和`fbcon`工具的入口点。该结构中的一些方法是强制性的，是使帧缓冲正常工作所需的最低要求，而其他方法是可选的，取决于驱动程序需要公开的功能，假设设备本身支持这些功能。

以下是`struct fb_ops`结构的定义：

```
    struct fb_ops { 
   /* open/release and usage marking */ 
   struct module *owner; 
   int (*fb_open)(struct fb_info *info, int user); 
   int (*fb_release)(struct fb_info *info, int user); 

   /* For framebuffers with strange nonlinear layouts or that do not 
    * work with normal memory mapped access 
    */ 
   ssize_t (*fb_read)(struct fb_info *info, char __user *buf, 
                  size_t count, loff_t *ppos); 
   ssize_t (*fb_write)(struct fb_info *info, const char __user *buf, 
                   size_t count, loff_t *ppos); 

   /* checks var and eventually tweaks it to something supported, 
    * DO NOT MODIFY PAR */ 
   int (*fb_check_var)(struct fb_var_screeninfo *var, struct fb_info *info); 

   /* set the video mode according to info->var */ 
   int (*fb_set_par)(struct fb_info *info); 

   /* set color register */ 
   int (*fb_setcolreg)(unsigned regno, unsigned red, unsigned green, 
                   unsigned blue, unsigned transp, struct fb_info *info); 

   /* set color registers in batch */ 
   int (*fb_setcmap)(struct fb_cmap *cmap, struct fb_info *info); 

   /* blank display */ 
   int (*fb_blank)(int blank_mode, struct fb_info *info); 

   /* pan display */ 
   int (*fb_pan_display)(struct fb_var_screeninfo *var, struct fb_info *info); 

   /* Draws a rectangle */ 
   void (*fb_fillrect) (struct fb_info *info, const struct fb_fillrect *rect); 
   /* Copy data from area to another */ 
   void (*fb_copyarea) (struct fb_info *info, const struct fb_copyarea *region); 
   /* Draws a image to the display */ 
   void (*fb_imageblit) (struct fb_info *info, const struct fb_image *image); 

   /* Draws cursor */ 
   int (*fb_cursor) (struct fb_info *info, struct fb_cursor *cursor); 

   /* wait for blit idle, optional */ 
   int (*fb_sync)(struct fb_info *info); 

   /* perform fb specific ioctl (optional) */ 
   int (*fb_ioctl)(struct fb_info *info, unsigned int cmd, 
               unsigned long arg); 

   /* Handle 32bit compat ioctl (optional) */ 
   int (*fb_compat_ioctl)(struct fb_info *info, unsigned cmd, 
               unsigned long arg); 

   /* perform fb specific mmap */ 
   int (*fb_mmap)(struct fb_info *info, struct vm_area_struct *vma); 

   /* get capability given var */ 
   void (*fb_get_caps)(struct fb_info *info, struct fb_blit_caps *caps, 
                   struct fb_var_screeninfo *var); 

   /* teardown any resources to do with this framebuffer */ 
   void (*fb_destroy)(struct fb_info *info); 
   [...] 
}; 
```

可以根据希望实现的功能设置不同的回调。

在[第四章](http://character)，*字符设备驱动程序*中，我们了解到字符设备可以通过`struct file_operations`结构导出一组文件操作，这些操作是与文件相关的系统调用的入口点，例如`open()`，`close()`，`read()`，`write()`，`mmap()`，`ioctl()`等。

也就是说，不要混淆`fb_ops`和`file_operations`结构。`fb_ops`提供了低级操作的抽象，而`file_operations`用于上层系统调用接口。内核在`drivers/video/fbdev/core/fbmem.c`中实现了帧缓冲文件操作，其中内部调用了我们在`fb_ops`中定义的方法。通过这种方式，可以根据系统调用接口的需要实现低级硬件操作，即`file_operations`结构。例如，当用户`open()`设备时，核心的打开文件操作方法将执行一些核心操作，并在设置时执行`fb_ops.fb_open()`方法，`release`，`mmap`等。

帧缓冲设备支持在`include/uapi/linux/fb.h`中定义的一些 ioctl 命令，用户程序可以使用这些命令来操作硬件。所有这些命令都由核心的`fops.ioctl`方法处理。对于其中的一些命令，核心的 ioctl 方法可能在内部执行`fb_ops`结构中定义的方法。

有人可能会想知道`fb_ops.ffb_ioctl`用于什么。当给定的 ioctl 命令内核不认识时，帧缓冲核心执行`fb_ops.fb_ioctl`。换句话说，`fb_ops.fb_ioctl`在帧缓冲核心的`fops.ioctl`方法的默认语句中执行。

# 驱动程序方法

驱动程序方法包括`probe()`和`remove()`函数。在进一步描述这些方法之前，让我们设置我们的`fb_ops`结构：

```
static struct fb_ops myfb_ops = { 
   .owner        = THIS_MODULE, 
   .fb_check_var = myfb_check_var, 
   .fb_set_par   = myfb_set_par, 
   .fb_setcolreg = myfb_setcolreg, 
   .fb_fillrect  = cfb_fillrect, /* Those three hooks are */  
   .fb_copyarea  = cfb_copyarea, /* non accelerated and */ 
   .fb_imageblit = cfb_imageblit, /* are provided by kernel */ 
   .fb_blank     = myfb_blank, 
}; 
```

+   `Probe`：驱动程序`probe`函数负责初始化硬件，使用`framebuffer_alloc()`函数创建`struct fb_info`结构，并在其上调用`register_framebuffer()`。以下示例假定设备是内存映射的。因此，可能存在非内存映射的情况，例如位于 SPI 总线上的屏幕。在这种情况下，应使用特定于总线的例程：

```
static int myfb_probe(struct platform_device *pdev) 
{ 
   struct fb_info *info; 
   struct resource *res; 
    [...] 

   dev_info(&pdev->dev, "My framebuffer driver\n"); 

/* 
 * Query resource, like DMA channels, I/O memory, 
 * regulators, and so on. 
 */ 
   res = platform_get_resource(pdev, IORESOURCE_MEM, 0); 
   if (!res) 
         return -ENODEV; 
   /* use request_mem_region(), ioremap() and so on */ 
    [...] 
    pwr = regulator_get(&pdev->dev, "lcd"); 

   info = framebuffer_alloc(sizeof( 
struct my_private_struct), &pdev->dev); 
   if (!info) 
         return -ENOMEM; 

   /* Device init and default info value*/ 
   [...] 
   info->fbops = &myfb_ops; 

    /* Clock setup, using devm_clk_get() and so on */ 
    [...] 

    /* DMA setup using dma_alloc_coherent() and so on*/   
    [...] 

    /* Register with the kernel */ 
   ret = register_framebuffer(info); 

   hardware_enable_controller(my_private_struct); 
   return 0; 
} 
```

+   `Remove`：`remove()`函数应释放在`probe()`中获取的任何内容，并调用：

```
static int myfb_remove(struct platform_device *pdev) 
{ 

   /* iounmap() memory and release_mem_region() */ 
   [...] 
   /* Reverse DMA, dma_free_*();*/ 
   [...] 

   hardware_disable_controller(fbi); 

    /* first unregister, */ 
   unregister_framebuffer(info); 
    /* and then free the memory */ 
   framebuffer_release(info); 

   return 0; 
} 
```

+   假设您使用了资源分配的管理器版本，您只需要使用`unregister_framebuffer()`和`framebuffer_release()`。其他所有操作都将由内核完成。

# 详细的 fb_ops

让我们描述一些在`fb_ops`结构中声明的钩子。也就是说，要了解编写帧缓冲区驱动程序的想法，可以查看内核中的`drivers/video/fbdev/vfb.c`，这是一个简单的虚拟帧缓冲区驱动程序。还可以查看其他特定的帧缓冲区驱动程序，比如 i.MX6，位于`drivers/video/fbdev/imxfb.c`，或者查看内核关于帧缓冲区驱动程序 API 的文档，位于`Documentation/fb/api.txt`。

# 检查信息

钩子`fb_ops->fb_check_var`负责检查帧缓冲区参数。其原型如下：

```
int (*fb_check_var)(struct fb_var_screeninfo *var, 
struct fb_info *info); 
```

此函数应检查帧缓冲区变量参数并调整为有效值。`var`表示应检查和调整的帧缓冲区变量参数：

```
static int myfb_check_var(struct fb_var_screeninfo *var, 
struct fb_info *info) 
{ 
   if (var->xres_virtual < var->xres) 
         var->xres_virtual = var->xres; 

   if (var->yres_virtual < var->yres) 
         var->yres_virtual = var->yres; 

   if ((var->bits_per_pixel != 32) && 
(var->bits_per_pixel != 24) && 
(var->bits_per_pixel != 16) && 
(var->bits_per_pixel != 12) && 
       (var->bits_per_pixel != 8)) 
         var->bits_per_pixel = 16; 

   switch (var->bits_per_pixel) { 
   case 8: 
         /* Adjust red*/ 
         var->red.length = 3; 
         var->red.offset = 5; 
         var->red.msb_right = 0; 

         /*adjust green*/ 
         var->green.length = 3; 
         var->green.offset = 2; 
         var->green.msb_right = 0; 

         /* adjust blue */ 
         var->blue.length = 2; 
         var->blue.offset = 0; 
         var->blue.msb_right = 0; 

         /* Adjust transparency */ 
         var->transp.length = 0; 
         var->transp.offset = 0; 
         var->transp.msb_right = 0; 
         break; 
   case 16: 
         [...] 
         break; 
   case 24: 
         [...] 
         break; 
   case 32: 
         var->red.length = 8; 
         var->red.offset = 16; 
         var->red.msb_right = 0; 

         var->green.length = 8; 
         var->green.offset = 8; 
         var->green.msb_right = 0; 

         var->blue.length = 8; 
         var->blue.offset = 0; 
         var->blue.msb_right = 0; 

         var->transp.length = 8; 
         var->transp.offset = 24; 
         var->transp.msb_right = 0; 
         break; 
   } 

   /* 
 * Any other field in *var* can be adjusted 
 * like var->xres,      var->yres, var->bits_per_pixel, 
 * var->pixclock and so on. 
 */ 
   return 0; 
} 
```

前面的代码根据用户选择的配置调整可变帧缓冲区属性。

# 设置控制器的参数

钩子`fp_ops->fb_set_par`是另一个硬件特定的钩子，负责向硬件发送参数。它根据用户设置`(info->var)`来对硬件进行编程：

```
static int myfb_set_par(struct fb_info *info) 
{ 
   struct fb_var_screeninfo *var = &info->var; 

   /* Make some compute or other sanity check */ 
   [...] 

    /* 
     * This function writes value to the hardware, 
     * in the appropriate registers 
     */ 
   set_controller_vars(var, info); 

   return 0; 
} 
```

# 屏幕空白

钩子`fb_ops->fb_blank`是一个硬件特定的钩子，负责屏幕空白。其原型如下：

```
int (*fb_blank)(int blank_mode, struct fb_info *info) 
```

`blank_mode`参数始终是以下值之一：

```
enum { 
   /* screen: unblanked, hsync: on,  vsync: on */ 
   FB_BLANK_UNBLANK       = VESA_NO_BLANKING, 

   /* screen: blanked,   hsync: on,  vsync: on */ 
   FB_BLANK_NORMAL        = VESA_NO_BLANKING + 1, 

   /* screen: blanked,   hsync: on,  vsync: off */ 
   FB_BLANK_VSYNC_SUSPEND = VESA_VSYNC_SUSPEND + 1, 

   /* screen: blanked,   hsync: off, vsync: on */ 
   FB_BLANK_HSYNC_SUSPEND = VESA_HSYNC_SUSPEND + 1, 

   /* screen: blanked,   hsync: off, vsync: off */ 
   FB_BLANK_POWERDOWN     = VESA_POWERDOWN + 1 
}; 
```

空白显示的通常方法是对`blank_mode`参数进行`switch case`操作，如下所示：

```
static int myfb_blank(int blank_mode, struct fb_info *info) 
{ 
   pr_debug("fb_blank: blank=%d\n", blank); 

   switch (blank) { 
   case FB_BLANK_POWERDOWN: 
   case FB_BLANK_VSYNC_SUSPEND: 
   case FB_BLANK_HSYNC_SUSPEND: 
   case FB_BLANK_NORMAL: 
         myfb_disable_controller(fbi); 
         break; 

   case FB_BLANK_UNBLANK: 
         myfb_enable_controller(fbi); 
         break; 
   } 
   return 0; 
} 
```

空白操作应该禁用控制器，停止其时钟并将其断电。取消空白应执行相反的操作。

# 加速方法

用户视频操作，如混合、拉伸、移动位图或动态渐变生成都是繁重的任务。它们需要图形加速才能获得可接受的性能。可以使用`struct fp_ops`结构的以下字段来实现帧缓冲区加速方法：

+   `.fb_imageblit()`: 此方法在显示器上绘制图像，非常有用

+   `.fb_copyarea()`: 此方法将矩形区域从一个屏幕区域复制到另一个屏幕区域

+   `.fb_fillrect():` 此方法以优化的方式填充一个带有像素行的矩形

因此，内核开发人员考虑到没有硬件加速的控制器，并提供了一种经过软件优化的方法。这使得加速实现是可选的，因为存在软件回退。也就是说，如果帧缓冲区控制器没有提供任何加速机制，必须使用内核通用例程填充这些方法。

这些分别是：

+   `cfb_imageblit()`: 这是用于 imageblit 的内核提供的回退。内核在启动过程中用它将标志输出到屏幕。

+   `cfb_copyarea()`: 用于区域复制操作。

+   `cfb_fillrect`(): 这是帧缓冲核心非加速方法，用于实现相同名称的操作。

# 把所有东西放在一起

在本节中，让我们总结前一节讨论的内容。为了编写帧缓冲区驱动程序，必须：

+   填充`struct fb_var_screeninfo`结构，以提供有关帧缓冲区可变属性的信息。这些属性可以由用户空间更改。

+   填充`struct fb_fix_screeninfo`结构，以提供固定参数。

+   设置`struct fb_ops`结构，提供必要的回调函数，帧缓冲区子系统将使用这些函数响应用户操作。

+   在`struct fb_ops`结构中，如果设备支持，必须提供加速函数回调。

+   设置`struct fb_info`结构，用之前步骤中填充的结构填充它，并在其上调用`register_framebuffer()`，以便在内核中注册它。

要了解编写简单帧缓冲区驱动程序的想法，可以查看内核中的`drivers/video/fbdev/vfb.c`，这是一个虚拟帧缓冲区驱动程序。可以通过`CONGIF_FB_VIRTUAL`选项在内核中启用它。

# 用户空间的帧缓冲区

通常通过`mmap()`命令访问帧缓冲内存，以便将帧缓冲内存映射到系统 RAM 的某个部分，从而在屏幕上绘制像素变得简单，影响内存值。屏幕参数（可变和固定）是通过 ioctl 命令提取的，特别是`FBIOGET_VSCREENINFO`和`FBIOGET_FSCREENINFO`。完整列表可在内核源代码的`include/uapi/linux/fb.h`中找到。

以下是在帧缓冲上绘制 300*300 正方形的示例代码：

```
#include <stdlib.h> 
#include <unistd.h> 
#include <stdio.h> 
#include <fcntl.h> 
#include <linux/fb.h> 
#include <sys/mman.h> 
#include <sys/ioctl.h> 

#define FBCTL(_fd, _cmd, _arg)         \ 
    if(ioctl(_fd, _cmd, _arg) == -1) { \ 
        ERROR("ioctl failed");         \ 
        exit(1); } 

int main() 
{ 
    int fd; 
    int x, y, pos; 
    int r, g, b; 
    unsigned short color; 
    void *fbmem; 

    struct fb_var_screeninfo var_info; 
    struct fb_fix_screeninfo fix_info; 

    fd = open(FBVIDEO, O_RDWR); 
    if (tfd == -1 || vfd == -1) { 
        exit(-1); 
    } 

    /* Gather variable screen info (virtual and visible) */ 
    FBCTL(fd, FBIOGET_VSCREENINFO, &var_info); 

    /* Gather fixed screen info */ 
    FBCTL(fd, FBIOGET_FSCREENINFO, &fix_info); 

    printf("****** Frame Buffer Info ******\n"); 
    printf("Visible: %d,%d  \nvirtual: %d,%d \n  line_len %d\n", 
           var_info.xres, this->var_info.yres, 
           var_info.xres_virtual, var_info.yres_virtual, 
           fix_info.line_length); 
    printf("dim %d,%d\n\n", var_info.width, var_info.height); 

    /* Let's mmap frame buffer memory */ 
    fbmem = mmap(0, v_var.yres_virtual * v_fix.line_length, \ 
                     PROT_WRITE | PROT_READ, \ 
                     MAP_SHARED, fd, 0); 

    if (fbmem == MAP_FAILED) { 
        perror("Video or Text frame bufer mmap failed"); 
        exit(1); 
    } 

    /* upper left corner (100,100). The square is 300px width */ 
    for (y = 100; y < 400; y++) { 
        for (x = 100; x < 400; x++) { 
            pos = (x + vinfo.xoffset) * (vinfo.bits_per_pixel / 8) 
                   +   (y + vinfo.yoffset) * finfo.line_length; 

            /* if 32 bits per pixel */ 
            if (vinfo.bits_per_pixel == 32) { 
                /* We prepare some blue color */ 
                *(fbmem + pos) = 100; 

                /* adding a little green */ 
                *(fbmem + pos + 1) = 15+(x-100)/2; 

                /* With lot of read */ 
                *(fbmem + pos + 2) = 200-(y-100)/5; 

                /* And no transparency */ 
                *(fbmem + pos + 3) = 0; 
            } else  { /* This assume 16bpp */ 
                r = 31-(y-100)/16; 
                g = (x-100)/6; 
                b = 10; 

                /* Compute color */  
                color = r << 11 | g << 5 | b; 
                *((unsigned short int*)(fbmem + pos)) = color; 
            } 
        } 
    } 

    munmap(fbp, screensize); 
    close(fbfd); 
    return 0; 
} 
```

还可以使用`cat`或`dd`命令将帧缓冲内存转储为原始图像：

```
 # cat /dev/fb0 > my_image 

```

使用以下命令将其写回：

```
 # cat my_image > /dev/fb0 

```

可以通过特殊的`/sys/class/graphics/fb<N>/blank sysfs`文件来使屏幕变暗/恢复亮度，其中`<N>`是帧缓冲索引。写入 1 将使屏幕变暗，而 0 将使其恢复亮度：

```
 # echo 0 > /sys/class/graphics/fb0/blank

    # echo 1 > /sys/class/graphics/fb0/blank

```

# 总结

帧缓冲驱动程序是 Linux 图形驱动程序的最简单形式，需要很少的实现工作。它们对硬件进行了很大的抽象。在这个阶段，您应该能够增强现有的驱动程序（例如具有图形加速功能），或者从头开始编写一个全新的驱动程序。但是，建议依赖于一个现有的驱动程序，其硬件与您需要编写驱动程序的硬件共享尽可能多的特征。让我们跳到下一个也是最后一个章节，处理网络设备。
