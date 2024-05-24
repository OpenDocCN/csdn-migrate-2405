# Linux 设备驱动开发（三）

> 原文：[`zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E`](https://zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：I2C 客户端驱动程序

由飞利浦（现在是 NXP）发明的 I2C 总线是一种双线：**串行数据**（**SDA**），**串行时钟**（**SCL**）异步串行总线。它是一个多主总线，尽管多主模式并不广泛使用。SDA 和 SCL 都是开漏/开集电器，这意味着它们中的每一个都可以将其输出拉低，但没有一个可以在没有上拉电阻的情况下将其输出拉高。SCL 由主机生成，以同步通过总线传输的数据（由 SDA 携带）。从机和主机都可以发送数据（当然不是同时），从而使 SDA 成为双向线。也就是说，SCL 信号也是双向的，因为从机可以通过保持 SCL 线低来拉伸时钟。总线由主机控制，而在我们的情况下，主机是 SoC 的一部分。这种总线经常用于嵌入式系统，用于连接串行 EEPROM、RTC 芯片、GPIO 扩展器、温度传感器等等：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00012.gif)

I2C 总线和设备

时钟速度从 10 KHz 到 100 KHz，400 KHz 到 2 MHz 不等。我们不会在本书中涵盖总线规格或总线驱动程序。然而，总线驱动程序负责管理总线并处理规格。例如，i.MX6 芯片的总线驱动程序的示例可以在内核源代码的`drivers/i2C/busses/i2c-imx.c`中找到，I2C 规格可以在[`www.nxp.com/documents/user_manual/UM10204.pdf`](http://www.nxp.com/documents/user_manual/UM10204.pdf)中找到。

在本章中，我们对客户端驱动程序感兴趣，以处理坐在总线上的从设备。本章将涵盖以下主题：

+   I2C 客户端驱动程序架构

+   访问设备，因此从/向设备读取/写入数据

+   从 DT 中声明客户端

# 驱动程序架构

当您为其编写驱动程序的设备坐在称为*总线控制器*的物理总线上时，它必须依赖于称为*控制器驱动程序*的总线的驱动程序，负责在设备之间共享总线访问。控制器驱动程序在您的设备和总线之间提供了一个抽象层。每当您在 I2C 或 USB 总线上执行事务（读或写）时，例如，I2C/USB 总线控制器会在后台自动处理。每个总线控制器驱动程序都导出一组函数，以便为坐在该总线上的设备开发驱动程序。这适用于每个物理总线（I2C、SPI、USB、PCI、SDIO 等）。

I2C 驱动程序在内核中表示为 `struct i2c_driver` 的实例。I2C 客户端（代表设备本身）由 `struct i2c_client` 结构表示。

# i2c_driver 结构

在内核中，I2C 驱动程序被声明为`struct i2c_driver`的实例，其外观如下：

```
struct i2c_driver { 
    /* Standard driver model interfaces */ 
int (*probe)(struct i2c_client *, const struct i2c_device_id *); 
int (*remove)(struct i2c_client *); 

    /* driver model interfaces that don't relate to enumeration */ 
    void (*shutdown)(struct i2c_client *); 

struct device_driver driver; 
const struct i2c_device_id *id_table; 
}; 
```

`struct i2c_driver` 结构包含和表征了通用访问例程，需要处理声称驱动程序的设备，而 `struct i2c_client` 包含设备特定信息，比如它的地址。`struct i2c_client` 结构代表和表征了一个 I2C 设备。在本章的后面，我们将看到如何填充这些结构。

# probe()函数

`probe()`函数是`struct i2c_driver`结构的一部分，一旦实例化了一个 I2C 设备，它就会被执行。它负责以下任务：

+   检查设备是否是您期望的设备

+   使用`i2c_check_functionality`函数检查 SoC 的 I2C 总线控制器是否支持设备所需的功能

+   初始化设备

+   设置设备特定数据

+   注册适当的内核框架

`probe` 函数的原型如下：

```
static int foo_probe(struct i2c_client *client, const struct 
                                              i2c_device_id *id) 
```

正如您所看到的，它的参数是：

+   `struct i2c_client` 指针：这代表 I2C 设备本身。这个结构继承自设备结构，并由内核提供给您的`probe`函数。客户端结构在`include/linux/i2c.h`中定义。它的定义如下：

```
struct i2c_client { 
  unsigned short flags;  /* div., see below  */ 
  unsigned short addr;   /* chip address - NOTE: 7bit    */ 
                         /* addresses are stored in the  */ 
                         /* _LOWER_ 7 bits               */ 
  char name[I2C_NAME_SIZE]; 
  struct i2c_adapter *adapter; /* the adapter we sit on  */ 
  struct device dev;     /* the device structure         */ 
  intirq;               /* irq issued by device         */ 
  struct list_head detected; 
 #if IS_ENABLED(CONFIG_I2C_SLAVE) 
  i2c_slave_cb_t slave_cb; /* callback for slave mode  */ 
 #endif 
}; 
```

+   所有字段都由内核填充，基于您提供的参数来注册客户端。我们稍后将看到如何向内核注册设备。

+   `struct i2c_device_id`指针：这指向与正在被探测的设备匹配的 I2C 设备 ID 条目。

# 每个设备的数据

I2C 核心为您提供了将指针存储到您选择的任何数据结构中的可能性，作为特定于设备的数据。要存储或检索数据，请使用 I2C 核心提供的以下函数：

```
/* set the data */ 
void i2c_set_clientdata(struct i2c_client *client, void *data); 

/* get the data */ 
void *i2c_get_clientdata(const struct i2c_client *client); 
```

这些函数内部调用`dev_set_drvdata`和`dev_get_drvdata`来更新或获取`struct i2c_client`结构中`struct device`子结构的`void *driver_data`字段的值。

这是一个如何使用额外客户数据的例子；摘自`drivers/gpio/gpio-mc9s08dz60.c:`

```
/* This is the device specific data structure */ 
struct mc9s08dz60 { 
   struct i2c_client *client; 
   struct gpio_chip chip; 
}; 

static int mc9s08dz60_probe(struct i2c_client *client, 
const struct i2c_device_id *id) 
{ 
    struct mc9s08dz60 *mc9s; 
    if (!i2c_check_functionality(client->adapter, 
               I2C_FUNC_SMBUS_BYTE_DATA)) 
    return -EIO; 
    mc9s = devm_kzalloc(&client->dev, sizeof(*mc9s), GFP_KERNEL); 
    if (!mc9s) 
        return -ENOMEM; 

    [...] 
    mc9s->client = client; 
    i2c_set_clientdata(client, mc9s); 

    return gpiochip_add(&mc9s->chip); 
} 
```

实际上，这些函数并不真正特定于 I2C。它们只是获取/设置`struct device`的`void *driver_data`指针，它本身是`struct i2c_client`的成员。实际上，我们可以直接使用`dev_get_drvdata`和`dev_set_drvdata`。可以在`linux/include/linux/i2c.h`中看到它们的定义。

# `remove()`函数

`remove`函数的原型如下：

```
static int foo_remove(struct i2c_client *client) 
```

`remove()`函数还提供与`probe()`函数相同的`struct i2c_client*`，因此您可以检索您的私有数据。例如，您可能需要根据您在`probe`函数中设置的私有数据进行一些清理或其他操作：

```
static int mc9s08dz60_remove(struct i2c_client *client) 
{ 
    struct mc9s08dz60 *mc9s; 

    /* We retrieve our private data */ 
    mc9s = i2c_get_clientdata(client); 

    /* Wich hold gpiochip we want to work on */ 
   return gpiochip_remove(&mc9s->chip); 
} 
```

`remove`函数负责从我们在`probe()`函数中注册的子系统中注销我们。在上面的例子中，我们只是从内核中移除`gpiochip`。

# 驱动程序初始化和注册

当模块加载时，可能需要进行一些初始化。大多数情况下，只需向 I2C 核心注册驱动程序即可。同时，当模块被卸载时，通常只需要从 I2C 核心中移除自己。在第五章，*平台设备驱动程序*中，我们看到使用 init/exit 函数并不值得，而是使用`module_*_driver`函数。在这种情况下，要使用的函数是：

```
module_i2c_driver(foo_driver); 
```

# 驱动程序和设备供应

正如我们在匹配机制中看到的，我们需要提供一个`device_id`数组，以便公开我们的驱动程序可以管理的设备。由于我们谈论的是 I2C 设备，结构将是`i2c_device_id`。该数组将向内核通知我们对驱动程序中感兴趣的设备。

现在回到我们的 I2C 设备驱动程序；在`include/linux/mod_devicetable.h`中查看，您将看到`struct i2c_device_id`的定义：

```
struct i2c_device_id { 
    char name[I2C_NAME_SIZE]; 
    kernel_ulong_tdriver_data;     /* Data private to the driver */ 
}; 
```

也就是说，`struct i2c_device_id`必须嵌入在`struct i2c_driver`中。为了让 I2C 核心（用于模块自动加载）知道我们需要处理的设备，我们必须使用`MODULE_DEVICE_TABLE`宏。内核必须知道每当发生匹配时调用哪个`probe`或`remove`函数，这就是为什么我们的`probe`和`remove`函数也必须嵌入在同一个`i2c_driver`结构中：

```
static struct i2c_device_id foo_idtable[] = { 
   { "foo", my_id_for_foo }, 
   { "bar", my_id_for_bar }, 
   { } 
}; 

MODULE_DEVICE_TABLE(i2c, foo_idtable); 

static struct i2c_driver foo_driver = { 
   .driver = { 
   .name = "foo", 
   }, 

   .id_table = foo_idtable, 
   .probe    = foo_probe, 
   .remove   = foo_remove, 
} 
```

# 访问客户端

串行总线事务只是访问寄存器以设置/获取其内容。I2C 遵守这一原则。I2C 核心提供了两种 API，一种用于普通的 I2C 通信，另一种用于与 SMBUS 兼容设备通信，它也适用于 I2C 设备，但反之则不然。

# 普通 I2C 通信

以下是通常在与 I2C 设备通信时处理的基本函数：

```
int i2c_master_send(struct i2c_client *client, const char *buf, int count); 
int i2c_master_recv(struct i2c_client *client, char *buf, int count); 
```

几乎所有 I2C 通信函数的第一个参数都是`struct i2c_client`。第二个参数包含要读取或写入的字节，第三个表示要读取或写入的字节数。与任何读/写函数一样，返回的值是读取/写入的字节数。还可以使用以下函数处理消息传输：

```
int i2c_transfer(struct i2c_adapter *adap, struct i2c_msg *msg, 

                 int num); 
```

`i2c_transfer`发送一组消息，每个消息可以是读取或写入操作，并且可以以任何方式混合。请记住，每个事务之间没有停止位。查看`include/uapi/linux/i2c.h`，消息结构如下：

```
struct i2c_msg { 
        __u16 addr;    /* slave address */ 
        __u16 flags;   /* Message flags */ 
        __u16 len;     /* msg length */ 
        __u8 *buf;     /* pointer to msg data */ 
}; 
```

`i2c_msg`结构描述和表征了一个 I2C 消息。对于每个消息，它必须包含客户端地址、消息的字节数和消息有效载荷。

`msg.len`是`u16`。这意味着您的读/写缓冲区的长度必须始终小于 2¹⁶（64k）。

让我们看一下微芯片 I2C 24LC512eeprom 字符驱动程序的`read`函数；我们应该了解事物是如何真正工作的。本书的源代码中提供了完整的代码。

```
ssize_t 
eep_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) 
{ 
    [...] 
    int _reg_addr = dev->current_pointer; 
    u8 reg_addr[2]; 
    reg_addr[0] = (u8)(_reg_addr>> 8); 
    reg_addr[1] = (u8)(_reg_addr& 0xFF); 

    struct i2c_msg msg[2]; 
    msg[0].addr = dev->client->addr; 
    msg[0].flags = 0;                /* Write */ 
    msg[0].len = 2;                  /* Address is 2bytes coded */ 
    msg[0].buf = reg_addr; 

    msg[1].addr = dev->client->addr; 
    msg[1].flags = I2C_M_RD;         /* We need to read */ 
    msg[1].len = count;  
    msg[1].buf = dev->data; 

    if (i2c_transfer(dev->client->adapter, msg, 2) < 0) 
        pr_err("ee24lc512: i2c_transfer failed\n");  

    if (copy_to_user(buf, dev->data, count) != 0) { 
        retval = -EIO; 
    goto end_read; 
    } 
    [...] 
} 
```

`msg.flags`应为`I2C_M_RD`表示读取，`0`表示写入事务。有时，您可能不想创建`struct i2c_msg`，而只是进行简单的读取和写入。

# 系统管理总线（SMBus）兼容函数

SMBus 是由英特尔开发的双线总线，与 I2C 非常相似。I2C 设备是 SMBus 兼容的，但反之则不然。因此，如果对于正在为其编写驱动程序的芯片有疑问，最好使用 SMBus 函数。

以下显示了一些 SMBus API：

```
   s32 i2c_smbus_read_byte_data(struct i2c_client *client, u8 command); 
   s32 i2c_smbus_write_byte_data(struct i2c_client *client, 
                           u8 command, u8 value); 
   s32 i2c_smbus_read_word_data(struct i2c_client *client, u8 command); 
   s32 i2c_smbus_write_word_data(struct i2c_client *client, 
                           u8 command, u16 value); 
   s32 i2c_smbus_read_block_data(struct i2c_client *client, 
                           u8 command, u8 *values); 
   s32 i2c_smbus_write_block_data(struct i2c_client *client, 
                            u8 command, u8 length, const u8 *values); 
```

有关更多解释，请查看内核源代码中的`include/linux/i2c.h`和`drivers/i2c/i2c-core.c`。

以下示例显示了在 I2C gpio 扩展器中进行简单的读/写操作：

```
struct mcp23016 { 
   struct i2c_client   *client; 
   structgpio_chip    chip; 
   structmutex        lock; 
}; 
[...] 
/* This function is called when one needs to change a gpio state */ 
static int mcp23016_set(struct mcp23016 *mcp, 
             unsigned offset, intval) 
{ 
    s32 value; 
    unsigned bank = offset / 8 ; 
    u8 reg_gpio = (bank == 0) ? GP0 : GP1; 
    unsigned bit = offset % 8 ; 

    value = i2c_smbus_read_byte_data(mcp->client, reg_gpio); 
    if (value >= 0) { 
        if (val) 
            value |= 1 << bit; 
        else 
            value &= ~(1 << bit); 
        return i2c_smbus_write_byte_data(mcp->client, 
                                         reg_gpio, value); 
    } else 
        return value; 
} 
[...] 
```

# 在板配置文件中实例化 I2C 设备（旧的和不推荐的方法）

我们必须告知内核系统上物理存在哪些设备。有两种方法可以实现。在 DT 中，正如我们将在本章后面看到的，或者通过板配置文件（这是旧的和不推荐的方法）。让我们看看如何在板配置文件中实现这一点：

`struct i2c_board_info`是用于表示我们板上的 I2C 设备的结构。该结构定义如下：

```
struct i2c_board_info { 
    char type[I2C_NAME_SIZE]; 
    unsigned short addr; 
    void *platform_data; 
    int irq; 
}; 
```

再次，我们已经从结构中删除了对我们不相关的元素。

在上述结构中，`type`应包含与设备驱动程序中的`i2c_driver.driver.name`字段中定义的相同值。然后，您需要填充一个`i2c_board_info`数组，并将其作为参数传递给板初始化例程中的`i2c_register_board_info`函数：

```
int i2c_register_board_info(int busnum, struct i2c_board_info const *info, unsigned len) 
```

在这里，`busnum`是设备所在的总线编号。这是一种旧的和不推荐的方法，因此我不会在本书中进一步介绍。请随时查看内核源代码中的*Documentation/i2c/instantiating-devices*，以了解如何完成这些操作。

# I2C 和设备树

正如我们在前面的章节中所看到的，为了配置 I2C 设备，基本上有两个步骤：

+   定义和注册 I2C 驱动程序

+   定义和注册 I2C 设备

I2C 设备属于 DT 中的非内存映射设备系列，而 I2C 总线是可寻址总线（通过可寻址，我是指您可以在总线上寻址特定设备）。在这种情况下，设备节点中的`reg`属性表示总线上的设备地址。

I2C 设备节点都是它们所在总线节点的子节点。每个设备只分配一个地址。没有长度或范围的涉及。I2C 设备需要声明的标准属性是`reg`，表示设备在总线上的地址，以及`compatible`字符串，用于将设备与驱动程序匹配。有关寻址的更多信息，可以参考第六章，*设备树的概念*。

```
&i2c2 { /* Phandle of the bus node */ 
    pcf8523: rtc@68 { 
        compatible = "nxp,pcf8523"; 
        reg = <0x68>; 
    }; 
    eeprom: ee24lc512@55 { /* eeprom device */ 
        compatible = "packt,ee24lc512"; 
        reg = <0x55>; 
       }; 
}; 
```

上述示例声明了 SoC 的 I2C 总线编号 2 上地址为 0x50 的 HDMI EDID 芯片，以及在同一总线上地址为 0x68 的**实时时钟**（**RTC**）。

# 定义和注册 I2C 驱动程序

到目前为止，我们所看到的并没有改变。我们需要额外的是定义一个`struct of_device_id`。`Struct of_device_id`定义为匹配`.dts`文件中相应节点的结构：

```
/* no extra data for this device */ 
static const struct of_device_id foobar_of_match[] = { 
        { .compatible = "packtpub,foobar-device" }, 
        {} 
}; 
MODULE_DEVICE_TABLE(of, foobar_of_match); 
```

现在我们定义`i2c_driver`如下：

```
static struct i2c_driver foo_driver = { 
    .driver = { 
    .name   = "foo", 
    .of_match_table = of_match_ptr(foobar_of_match), /* Only this line is added */ 
    }, 
    .probe  = foo_probe, 
    .id_table = foo_id, 
}; 
```

然后可以通过以下方式改进`probe`函数：

```
static int my_probe(struct i2c_client *client, const struct i2c_device_id *id) 
{ 
    const struct of_device_id *match; 
    match = of_match_device(mcp23s08_i2c_of_match, &client->dev); 
    if (match) { 
        /* Device tree code goes here */ 
    } else { 
        /*  
         * Platform data code comes here. 
         * One can use 
         *   pdata = dev_get_platdata(&client->dev); 
         * 
         * or *id*, which is a pointer on the *i2c_device_id* entry that originated 
         * the match, in order to use *id->driver_data* to extract the device 
         * specific data, as described in platform driver chapter. 
         */ 
    } 
    [...] 
} 
```

# 备注

对于早于 4.10 的内核版本，如果查看`drivers/i2c/i2c-core.c`，在`i2c_device_probe()`函数中（供参考，这是内核每次向 I2C 核心注册 I2C 设备时调用的函数），将看到类似于以下内容：

```
    if (!driver->probe || !driver->id_table) 
            return -ENODEV; 
```

这意味着即使一个人不需要使用`.id_table`，在驱动程序中也是强制性的。实际上，可以只使用 OF 匹配样式，但不能摆脱`.id_table`。内核开发人员试图消除对`.id_table`的需求，并专门使用`.of_match_table`进行设备匹配。补丁可以在此 URL 找到：[`git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c80f52847c50109ca248c22efbf71ff10553dca4`](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c80f52847c50109ca248c22efbf71ff10553dca4)。

然而，已经发现了回归问题，并且提交已被撤销。有关详细信息，请查看此处：[`git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=661f6c1cd926c6c973e03c6b5151d161f3a666ed`](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=661f6c1cd926c6c973e03c6b5151d161f3a666ed)。自内核版本>= 4.10 以来，已经修复了此问题。修复如下：

```
/* 
 * An I2C ID table is not mandatory, if and only if, a suitable Device 
 * Tree match table entry is supplied for the probing device. 
 */ 
if (!driver->id_table && 
    !i2c_of_match_device(dev->driver->of_match_table, client)) 
        return -ENODEV; 
```

换句话说，对于 I2C 驱动程序，必须同时定义`.id_table`和`.of_match_table`，否则您的设备将无法在内核版本 4.10 或更早版本中进行探测。

# 在设备树中实例化 I2C 设备-新方法

`struct i2c_client`是用于描述 I2C 设备的结构。但是，使用 OF 样式，这个结构不再能在板文件中定义。我们需要做的唯一的事情就是在 DT 中提供设备的信息，内核将根据此信息构建一个设备。

以下代码显示了如何在`dts`文件中声明我们的 I2C `foobar`设备节点：

```
&i2c3 { 
    status = "okay"; 
    foo-bar: foo@55 { 
    compatible = "packtpub,foobar-device"; 
reg = &lt;55>; 
    }; 
}; 
```

# 将所有内容放在一起

总结编写 I2C 客户端驱动程序所需的步骤：

1.  声明驱动程序支持的设备 ID。您可以使用`i2c_device_id`来实现。如果支持 DT，也可以使用`of_device_id`。

1.  调用`MODULE_DEVICE_TABLE(i2c, my_id_table)`将设备列表注册到 I2C 核心。如果支持设备树，必须调用`MODULE_DEVICE_TABLE(of, your_of_match_table)`将设备列表注册到 OF 核心。

1.  根据各自的原型编写`probe`和`remove`函数。如果需要，还要编写电源管理函数。`probe`函数必须识别您的设备，配置它，定义每个设备（私有）数据，并向适当的内核框架注册。驱动程序的行为取决于您在`probe`函数中所做的事情。`remove`函数必须撤消您在`probe`函数中所做的一切（释放内存并从任何框架中注销）。

1.  声明并填充`struct i2c_driver`结构，并使用您创建的 id 数组设置`id_table`字段。使用上面编写的相应函数的名称设置`.probe`和`.remove`字段。在`.driver`子结构中，将`.owner`字段设置为`THIS_MODULE`，设置驱动程序名称，最后，如果支持 DT，则使用`of_device_id`数组设置`.of_match_table`字段。

1.  使用刚刚填写的`i2c_driver`结构调用`module_i2c_driver`函数：`module_i2c_driver(serial_eeprom_i2c_driver)`，以便将驱动程序注册到内核中。

# 总结

我们刚刚处理了 I2C 设备驱动程序。现在是时候选择市场上的任何 I2C 设备并编写相应的驱动程序，支持 DT。本章讨论了内核 I2C 核心和相关 API，包括设备树支持，以便为您提供与 I2C 设备通信所需的技能。您应该能够编写高效的`probe`函数并向内核 I2C 核心注册。在下一章中，我们将使用在这里学到的技能来开发 SPI 设备驱动程序。


# 第八章：SPI 设备驱动程序

**串行外围接口**（**SPI**）是一个（至少）四线总线--**主输入从输出**（**MISO**），**主输出从输入**（**MOSI**），**串行时钟**（**SCK**）和**片选**（**CS**），用于连接串行闪存，AD/DA 转换器。主机始终生成时钟。其速度可以达到 80 MHz，即使没有真正的速度限制（比 I2C 快得多）。CS 线也是由主机管理的。

每个信号名称都有一个同义词：

+   每当您看到 SIMO，SDI，DI 或 SDA 时，它们指的是 MOSI。

+   SOMI，SDO，DO，SDA 将指的是 MISO。

+   SCK，CLK，SCL 将指的是 SCK。

+   S̅ S̅是从选择线，也称为 CS。可以使用 CSx（其中 x 是索引，CS0，CS1），也可以使用 EN 和 ENB，表示启用。CS 通常是一个低电平有效的信号：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00013.jpg)

SPI 拓扑结构（来自维基百科的图片）

本章将介绍 SPI 驱动程序的概念，例如：

+   SPI 总线描述

+   驱动程序架构和数据结构描述

+   半双工和全双工中的数据发送和接收

+   从 DT 声明 SPI 设备

+   从用户空间访问 SPI 设备，既可以进行半双工也可以进行全双工

# 驱动程序架构

在 Linux 内核中 SPI 的必需头文件是`<linux/spi/spi.h>`。在讨论驱动程序结构之前，让我们看看内核中如何定义 SPI 设备。在内核中，SPI 设备表示为`spi_device`的实例。管理它们的驱动程序实例是`struct spi_driver`结构。

# 设备结构

`struct spi_device`结构表示一个 SPI 设备，并在`include/linux/spi/spi.h`中定义：

```
struct spi_device { 
    struct devicedev; 
    struct spi_master*master; 
    u32 max_speed_hz; 
    u8 chip_select; 
    u8 bits_per_word; 
    u16 mode; 
    int irq; 
    [...] 
    int cs_gpio;        /* chip select gpio */ 
}; 
```

对我们来说没有意义的一些字段已被删除。也就是说，以下是结构中元素的含义：

+   `master`：这代表 SPI 控制器（总线），设备连接在其上。

+   `max_speed_hz`：这是与芯片一起使用的最大时钟速率（在当前板上）；此参数可以从驱动程序内部更改。您可以使用每次传输的`spi_transfer.speed_hz`覆盖该参数。我们将在后面讨论 SPI 传输。

+   `chip_select`：这允许您启用需要通信的芯片，区分由主控制的芯片。`chip_select`默认为低电平有效。此行为可以通过在模式中添加`SPI_CS_HIGH`标志来更改。

+   `mode`：这定义了数据应该如何进行时钟同步。设备驱动程序可以更改这个。默认情况下，每次传输中的每个字的数据同步是**最高有效位**（**MSB**）优先。可以通过指定`SPI_LSB_FIRST`来覆盖此行为。

+   `irq`：这代表中断号（在您的板`init`文件或通过 DT 中注册为设备资源），您应该传递给`request_irq()`以从此设备接收中断。

关于 SPI 模式的一点说明；它们是使用两个特征构建的：

+   `CPOL`：这是初始时钟极性：

+   `0`：初始时钟状态为低，并且第一个边沿为上升

+   `1`：初始时钟状态为高，并且第一个状态为下降

+   `CPHA`：这是时钟相位，选择在哪个边沿对数据进行采样：

+   `0`：数据在下降沿（高到低转换）锁存，而输出在上升沿改变

+   `1`：在上升沿（低到高转换）锁存的数据，并在下降沿输出

这允许根据`include/linux/spi/spi.h`中的以下宏在内核中定义四种 SPI 模式：

```
#define  SPI_CPHA  0x01 
#define  SPI_CPOL  0x02 
```

然后可以生成以下数组来总结事情：

| **模式** | **CPOL** | **CPHA** | **内核宏** |
| --- | --- | --- | --- |
| 0 | 0 | 0 | `#define SPI_MODE_0 (0&#124;0)` |
| 1 | 0 | 1 | `#define SPI_MODE_1 (0&#124;SPI_CPHA)` |
| 2 | 1 | 0 | `#define SPI_MODE_2 (SPI_CPOL&#124;0)` |
| 3 | 1 | 1 | `#define SPI_MODE_3 (SPI_CPOL&#124;SPI_CPHA)` |

以下是每种 SPI 模式的表示，如前述数组中定义的。也就是说，只有 MOSI 线被表示，但对于 MISO 原理是相同的。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00014.jpg)

常用模式是`SPI_MODE_0`和`SPI_MODE_3`。

# spi_driver 结构

`struct spi_driver`代表您开发的用于管理 SPI 设备的驱动程序。其结构如下：

```
struct spi_driver { 
   const struct spi_device_id *id_table; 
   int (*probe)(struct spi_device *spi); 
   int (*remove)(struct spi_device *spi); 
   void (*shutdown)(struct spi_device *spi); 
   struct device_driver    driver; 
}; 
```

# probe()功能

它的原型如下：

```
static int probe(struct spi_device *spi) 
```

您可以参考[第七章]（text00189.html），*I2C 客户端驱动程序*，以了解在“探测”功能中要做什么。相同的步骤也适用于这里。因此，与无法在运行时更改控制器总线参数（CS 状态，每字位，时钟）的 I2C 驱动程序不同，SPI 驱动程序可以。您可以根据设备属性设置总线。

典型的 SPI“探测”功能如下所示：

```
static int my_probe(struct spi_device *spi) 
{ 
    [...] /* declare your variable/structures */ 

    /* bits_per_word cannot be configured in platform data */ 
    spi->mode = SPI_MODE_0; /* SPI mode */ 
    spi->max_speed_hz = 20000000;   /* Max clock for the device */ 
    spi->bits_per_word = 16;    /* device bit per word */ 
    ret = spi_setup(spi); 
    ret = spi_setup(spi); 
    if (ret < 0) 
        return ret; 

    [...] /* Make some init */ 
    [...] /* Register with apropriate framework */ 

    return ret; 
} 
```

`struct spi_device*`是一个输入参数，由内核传递给“探测”功能。它代表您正在探测的设备。在您的“探测”功能中，您可以使用`spi_get_device_id`（在`id_table match`的情况下）获取触发匹配的`spi_device_id`并提取驱动程序数据：

```
const struct spi_device_id *id = spi_get_device_id(spi); 
my_private_data = array_chip_info[id->driver_data]; 
```

# 每个设备数据

在“探测”功能中，跟踪私有（每个设备）数据以在模块生命周期中使用是一项常见任务。这已在[第七章]（text00189.html），*I2C 客户端驱动程序*中讨论过。

以下是用于设置/获取每个设备数据的函数的原型：

```
/* set the data */ 
void spi_set_drvdata(struct *spi_device, void *data); 

/* Get the data back */ 
 void *spi_get_drvdata(const struct *spi_device); 
```

例如：

```
struct mc33880 { 
    struct mutex    lock; 
    u8      bar; 
    struct foo chip; 
    struct spi_device *spi; 
}; 

static int mc33880_probe(struct spi_device *spi) 
{ 
    struct mc33880 *mc; 
    [...] /* Device set up */ 

    mc = devm_kzalloc(&spi->dev, sizeof(struct mc33880), 
                      GFP_KERNEL); 
    if (!mc) 
        return -ENOMEM; 

    mutex_init(&mc->lock); 
    spi_set_drvdata(spi, mc); 

    mc->spi = spi; 
    mc->chip.label = DRIVER_NAME, 
    mc->chip.set = mc33880_set; 

    /* Register with appropriate framework */ 
    [...] 
} 
```

# remove()功能

`remove`功能必须释放在“探测”功能中抓取的每个资源。其结构如下：

```
static int  my_remove(struct spi_device *spi); 
```

典型的`remove`功能可能如下所示：

```
static int mc33880_remove(struct spi_device *spi) 
{ 
    struct mc33880 *mc; 
    mc = spi_get_drvdata(spi); /* Get our data back */ 
    if (!mc) 
        return -ENODEV; 

    /* 
     * unregister from frameworks with which we registered in the 
     * probe function 
     */ 
    [...] 
    mutex_destroy(&mc->lock); 
    return 0; 
} 
```

# 驱动程序初始化和注册

对于设备坐在总线上，无论是物理总线还是伪平台总线，大部分时间都是在“探测”功能中完成的。 `init`和`exit`功能只是用来在总线核心中注册/注销驱动程序：

```
static int __init foo_init(void) 
{ 
    [...] /*My init code */ 
   return spi_register_driver(&foo_driver); 
} 
module_init(foo_init); 

static void __exit foo_cleanup(void) 
{ 
    [...] /* My clean up code */ 
   spi_unregister_driver(&foo_driver); 
} 
module_exit(foo_cleanup); 
```

也就是说，如果您除了注册/注销驱动程序之外什么都不做，内核会提供一个宏：

```
module_spi_driver(foo_driver); 
```

这将在内部调用`spi_register_driver`和`spi_unregister_driver`。这与我们在上一章中看到的完全相同。

# 驱动程序和设备配置

由于我们需要对 I2C 设备使用`i2c_device_id`，所以我们必须对 SPI 设备使用`spi_device_id`，以便为我们的设备提供`device_id`数组进行匹配。它在`include/linux/mod_devicetable.h`中定义：

```
struct spi_device_id { 
   char name[SPI_NAME_SIZE]; 
   kernel_ulong_t driver_data; /* Data private to the driver */ 
}; 
```

我们需要将我们的数组嵌入到`struct spi_device_id`中，以便通知 SPI 核心我们需要在驱动程序中管理的设备 ID，并在驱动程序结构上调用`MODULE_DEVICE_TABLE`宏。当然，宏的第一个参数是设备所在的总线的名称。在我们的情况下，它是 SPI：

```
#define ID_FOR_FOO_DEVICE  0 
#define ID_FOR_BAR_DEVICE  1  

static struct spi_device_id foo_idtable[] = { 
   { "foo", ID_FOR_FOO_DEVICE }, 
   { "bar", ID_FOR_BAR_DEVICE }, 
   { } 
}; 
MODULE_DEVICE_TABLE(spi, foo_idtable); 

static struct spi_driver foo_driver = { 
   .driver = { 
   .name = "KBUILD_MODULE", 
   }, 

   .id_table    = foo_idtable, 
   .probe       = foo_probe, 
   .remove      = foo_remove, 
}; 

module_spi_driver(foo_driver); 
```

# 在板配置文件中实例化 SPI 设备-旧的和不推荐的方法

只有在系统不支持设备树时，设备才应该在板文件中实例化。由于设备树已经出现，这种实例化方法已被弃用。因此，让我们只记住板文件位于`arch/`目录中。用于表示 SPI 设备的结构是`struct spi_board_info`，而不是我们在驱动程序中使用的`struct spi_device`。只有在您填写并使用`spi_register_board_info`函数注册了`struct spi_board_info`后，内核才会构建一个`struct spi_device`（它将传递给您的驱动程序并在 SPI 核心中注册）。

请随意查看`include/linux/spi/spi.h`中的`struct spi_board_info`字段。`spi_register_board_info`的定义可以在`drivers/spi/spi.c`中找到。现在让我们来看看板文件中的一些 SPI 设备注册：

```
/** 
 * Our platform data 
 */ 
struct my_platform_data { 
   int foo; 
   bool bar; 
}; 
static struct my_platform_data mpfd = { 
   .foo = 15, 
   .bar = true, 
}; 

static struct spi_board_info 
   my_board_spi_board_info[] __initdata = { 
    { 
       /* the modalias must be same as spi device driver name */ 
        .modalias = "ad7887", /* Name of spi_driver for this device */ 
        .max_speed_hz = 1000000,  /* max spi clock (SCK) speed in HZ */ 
        .bus_num = 0, /* Framework bus number */ 
        .irq = GPIO_IRQ(40), 
        .chip_select = 3, /* Framework chip select */ 
        .platform_data = &mpfd, 
        .mode = SPI_MODE_3, 
   },{ 
        .modalias = "spidev", 
        .chip_select = 0, 
        .max_speed_hz = 1 * 1000 * 1000, 
        .bus_num = 1, 
        .mode = SPI_MODE_3, 
    }, 
}; 

static int __init board_init(void) 
{ 
   [...] 
   spi_register_board_info(my_board_spi_board_info, ARRAY_SIZE(my_board_spi_board_info)); 
   [...] 

   return 0; 
} 
[...] 
```

# SPI 和设备树

与 I2C 设备一样，SPI 设备属于设备树中的非内存映射设备系列，但也是可寻址的。这里，地址表示控制器（主控）给定的 CS（从 0 开始）列表中的 CS 索引。例如，我们可能在 SPI 总线上有三个不同的 SPI 设备，每个设备都有自己的 CS 线。主控将获得一组 GPIO，每个 GPIO 代表一个 CS 以激活设备。如果设备 X 使用第二个 GPIO 线作为 CS，我们必须将其地址设置为 1（因为我们总是从 0 开始）在`reg`属性中。

以下是 SPI 设备的真实 DT 列表：

```
ecspi1 { 
    fsl,spi-num-chipselects = <3>; 
    cs-gpios = <&gpio5 17 0>, <&gpio5 17 0>, <&gpio5 17 0>; 
    pinctrl-0 = <&pinctrl_ecspi1 &pinctrl_ecspi1_cs>; 
    #address-cells = <1>; 
    #size-cells = <0>; 
    compatible = "fsl,imx6q-ecspi", "fsl,imx51-ecspi"; 
    reg = <0x02008000 0x4000>; 
    status = "okay"; 

    ad7606r8_0: ad7606r8@0 { 
        compatible = "ad7606-8"; 
        reg = <0>; 
        spi-max-frequency = <1000000>; 
        interrupt-parent = <&gpio4>; 
        interrupts = <30 0x0>; 
   }; 
   label: fake_spi_device@1 { 
        compatible = "packtpub,foobar-device"; 
        reg = <1>; 
        a-string-param = "stringvalue"; 
        spi-cs-high; 
   }; 
   mcp2515can: can@2 { 
        compatible = "microchip,mcp2515"; 
        reg = <2>; 
        spi-max-frequency = <1000000>; 
        clocks = <&clk8m>; 
        interrupt-parent = <&gpio4>; 
        interrupts = <29 IRQ_TYPE_LEVEL_LOW>; 
    }; 
}; 
```

SPI 设备节点中引入了一个新属性：`spi-max-frequency`。它表示设备的最大 SPI 时钟速度（以赫兹为单位）。每当访问设备时，总线控制器驱动程序将确保时钟不会超过此限制。其他常用的属性包括：

+   `spi-cpol`：这是一个布尔值（空属性），表示设备需要反向时钟极性模式。它对应于 CPOL。

+   `spi-cpha`：这是一个空属性，表示设备需要移位时钟相位模式。它对应于 CPHA。

+   `spi-cs-high`：默认情况下，SPI 设备需要 CS 低才能激活。这是一个布尔属性，表示设备需要 CS 高活动。

也就是说，要获取完整的 SPI 绑定元素列表，您可以参考内核源代码中的*Documentation/devicetree/bindings/spi/spi-bus.txt*。

# 在设备树中实例化 SPI 设备-新的方法

通过正确填写设备节点，内核将为我们构建一个`struct spi_device`，并将其作为参数传递给我们的 SPI 核心函数。以下只是先前定义的 SPI DT 列表的摘录：

```
&ecspi1 { 
    status = "okay"; 
    label: fake_spi_device@1 { 
    compatible = "packtpub,foobar-device"; 
    reg = <1>; 
    a-string-param = "stringvalue"; 
    spi-cs-high; 
   }; 
 }; 
```

# 定义和注册 SPI 驱动程序

同样的原则适用于 I2C 驱动程序。我们需要定义一个`struct of_device_id`来匹配设备，然后调用`MODULE_DEVICE_TABLE`宏来注册到 OF 核心：

```
static const struct of_device_id foobar_of_match[] = { 
           { .compatible = "packtpub,foobar-device" }, 
           { .compatible = "packtpub,barfoo-device" }, 
        {} 
}; 
MODULE_DEVICE_TABLE(of, foobar_of_match); 
```

然后定义我们的`spi_driver`如下：

```
static struct spi_driver foo_driver = { 
    .driver = { 
    .name   = "foo", 
        /* The following line adds Device tree */ 
    .of_match_table = of_match_ptr(foobar_of_match), 
    }, 
    .probe   = my_spi_probe, 
    .id_table = foo_id, 
}; 
```

然后可以通过以下方式改进`probe`函数：

```
static int my_spi_probe(struct spi_device *spi) 
{ 
    const struct of_device_id *match; 
    match = of_match_device(of_match_ptr(foobar_of_match), &spi->dev); 
    if (match) { 
        /* Device tree code goes here */ 
    } else { 
        /*  
         * Platform data code comes here. 
         * One can use 
         *   pdata = dev_get_platdata(&spi->dev); 
         * 
         * or *id*, which is a pointer on the *spi_device_id* entry that originated 
         * the match, in order to use *id->driver_data* to extract the device 
         * specific data, as described in Chapter 5, Platform Device Drivers. 
         */ 
    } 
    [...] 
} 
```

# 访问和与客户端交流

SPI I/O 模型由一组排队的消息组成。我们提交一个或多个`struct spi_message`结构，这些结构被同步或异步地处理和完成。单个消息由一个或多个`struct spi_transfer`对象组成，每个对象代表一个全双工 SPI 传输。这两个主要结构用于在驱动程序和设备之间交换数据。它们都在`include/linux/spi/spi.h`中定义：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00015.jpg)

SPI 消息结构

`struct spi_transfer`代表一个全双工 SPI 传输：

```
struct spi_transfer { 
    const void  *tx_buf; 
    void *rx_buf; 
    unsigned len; 

    dma_addr_t tx_dma; 
    dma_addr_t rx_dma; 

    unsigned cs_change:1; 
    unsigned tx_nbits:3; 
    unsigned rx_nbits:3; 
#define  SPI_NBITS_SINGLE   0x01 /* 1bit transfer */ 
#define  SPI_NBITS_DUAL            0x02 /* 2bits transfer */ 
#define  SPI_NBITS_QUAD            0x04 /* 4bits transfer */ 
    u8 bits_per_word; 
    u16 delay_usecs; 
    u32 speed_hz; 
}; 
```

以下是结构元素的含义：

+   `tx_buf`：这个缓冲区包含要写入的数据。在只读事务的情况下，它应为 NULL 或保持不变。在需要通过**直接内存访问**（**DMA**）执行 SPI 事务的情况下，它应该是`dma`-安全的。

+   `rx_buf`：这是用于读取数据的缓冲区（具有与`tx_buf`相同的属性），或在只写事务中为 NULL。

+   `tx_dma`：这是`tx_buf`的 DMA 地址，如果`spi_message.is_dma_mapped`设置为`1`。DMA 在[第十二章](http://post)中讨论，*DMA-直接内存访问*。

+   `rx_dma`：这与`tx_dma`相同，但用于`rx_buf`。

+   `len`：这表示`rx`和`tx`缓冲区的字节大小，这意味着如果两者都被使用，它们必须具有相同的大小。

+   `speed_hz`：这会覆盖默认速度，指定为`spi_device.max_speed_hz`，但仅适用于当前传输。如果为`0`，则使用默认值（在`struct spi_device`结构中提供）。

+   `bits_per_word`：数据传输涉及一个或多个字。一个字是数据的单位，其大小以位为单位根据需要变化。在这里，`bits_per_word`表示此 SPI 传输的字位大小。这将覆盖`spi_device.bits_per_word`中提供的默认值。如果为`0`，则使用默认值（来自`spi_device`）。

+   `cs_change`：这确定此传输完成后`chip_select`线的状态。

+   `delay_usecs`：这表示在此传输之后的延迟（以微秒为单位），然后（可选）更改`chip_select`状态，然后开始下一个传输或完成此`spi_message`。

在另一侧，`struct spi_message`被用来原子地包装一个或多个 SPI 传输。驱动程序将独占使用 SPI 总线，直到完成构成消息的每个传输。SPI 消息结构也在`include/linux/spi/spi.h`中定义：

```
    struct spi_message { 
       struct list_head transfers; 
       struct spi_device *spi; 
       unsigned is_dma_mapped:1; 
       /* completion is reported through a callback */ 
       void (*complete)(void *context); 
       void *context; 
       unsigned frame_length; 
       unsigned actual_length; 
       int status; 
    }; 
```

+   `transfers`：这是构成消息的传输列表。稍后我们将看到如何将传输添加到此列表中。

+   `is_dma_mapped`：这告诉控制器是否使用 DMA（或不使用）执行事务。然后，您的代码负责为每个传输缓冲区提供 DMA 和 CPU 虚拟地址。

+   `complete`：这是在事务完成时调用的回调，`context`是要传递给回调的参数。

+   `frame_length`：这将自动设置为消息中的总字节数。

+   `actual_length`：这是所有成功段中传输的字节数。

+   `status`：这报告传输状态。成功为零，否则为`-errno`。

消息中的`spi_transfer`元素按 FIFO 顺序处理。在消息完成之前，您必须确保不使用传输缓冲区，以避免数据损坏。您进行完成调用以确保可以。

在消息可以提交到总线之前，必须使用`void spi_message_init(struct spi_message *message)`对其进行初始化，这将将结构中的每个元素都设置为零，并初始化`transfers`列表。对于要添加到消息中的每个传输，应该在该传输上调用`void spi_message_add_tail(struct spi_transfer *t, struct spi_message *m)`，这将导致将传输排队到`transfers`列表中。完成后，您有两种选择来启动事务：

+   同步地，使用`int spi_sync(struct spi_device *spi, struct spi_message *message)`函数，这可能会休眠，不应在中断上下文中使用。这里不需要回调的完成。这个函数是第二个函数（`spi_async()`）的包装器。

+   异步地，使用`spi_async()`函数，也可以在原子上下文中使用，其原型为`int spi_async(struct spi_device *spi, struct spi_message *message)`。在这里提供回调是一个好习惯，因为它将在消息完成时执行。

以下是单个传输 SPI 消息事务可能看起来像的内容：

```
char tx_buf[] = { 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0x40, 0x00, 0x00, 0x00, 
        0x00, 0x95, 0xEF, 0xBA, 0xAD, 
        0xF0, 0x0D, 
}; 

char rx_buf[10] = {0,}; 
int ret; 
struct spi_message single_msg; 
struct spi_transfer single_xfer; 

single_xfer.tx_buf = tx_buf; 
single_xfer.rx_buf = rx_buf; 
single_xfer.len    = sizeof(tx_buff); 
single_xfer.bits_per_word = 8; 

spi_message_init(&msg); 
spi_message_add_tail(&xfer, &msg); 
ret = spi_sync(spi, &msg); 
```

现在让我们写一个多传输消息事务：

```
struct { 
    char buffer[10]; 
    char cmd[2] 
    int foo; 
} data; 

struct data my_data[3]; 
initialize_date(my_data, ARRAY_SIZE(my_data)); 

struct spi_transfer   multi_xfer[3]; 
struct spi_message    single_msg; 
int ret; 

multi_xfer[0].rx_buf = data[0].buffer; 
multi_xfer[0].len = 5; 
multi_xfer[0].cs_change = 1; 
/* command A */ 
multi_xfer[1].tx_buf = data[1].cmd; 
multi_xfer[1].len = 2; 
multi_xfer[1].cs_change = 1; 
/* command B */ 
multi_xfer[2].rx_buf = data[2].buffer; 
multi_xfer[2].len = 10; 

spi_message_init(single_msg); 
spi_message_add_tail(&multi_xfer[0], &single_msg); 
spi_message_add_tail(&multi_xfer[1], &single_msg); 
spi_message_add_tail(&multi_xfer[2], &single_msg); 
ret = spi_sync(spi, &single_msg); 
```

还有其他辅助函数，都围绕着`spi_sync()`构建。其中一些是：

```
int spi_read(struct spi_device *spi, void *buf, size_t len) 
int spi_write(struct spi_device *spi, const void *buf, size_t len) 
int spi_write_then_read(struct spi_device *spi, 
        const void *txbuf, unsigned n_tx, 
void *rxbuf, unsigned n_rx) 
```

请查看`include/linux/spi/spi.h`以查看完整列表。这些包装器应该与少量数据一起使用。

# 把所有东西放在一起

编写 SPI 客户端驱动程序所需的步骤如下：

1.  声明驱动程序支持的设备 ID。您可以使用`spi_device_id`来做到这一点。如果支持 DT，也使用`of_device_id`。您可以完全使用 DT。

1.  调用`MODULE_DEVICE_TABLE(spi, my_id_table);`将设备列表注册到 SPI 核心。如果支持 DT，必须调用`MODULE_DEVICE_TABLE(of, your_of_match_table);`将设备列表注册到`of`核心。

1.  根据各自的原型编写`probe`和`remove`函数。`probe`函数必须识别您的设备，配置它，定义每个设备（私有）数据，如果需要配置总线（SPI 模式等），则使用`spi_setup`函数，并向适当的内核框架注册。在`remove`函数中，只需撤消`probe`函数中完成的所有操作。

1.  声明并填充`struct spi_driver`结构，使用您创建的 ID 数组设置`id_table`字段。使用您编写的相应函数的名称设置`.probe`和`.remove`字段。在`.driver`子结构中，将`.owner`字段设置为`THIS_MODULE`，设置驱动程序名称，最后使用`of_device_id`数组设置`.of_match_table`字段，如果支持 DT。

1.  在`module_spi_driver(serial_eeprom_spi_driver);`之前，使用您刚刚填充的`spi_driver`结构调用`module_spi_driver`函数，以便向内核注册您的驱动程序。

# SPI 用户模式驱动程序

有两种使用用户模式 SPI 设备驱动程序的方法。为了能够这样做，您需要使用`spidev`驱动程序启用您的设备。一个示例如下：

```
spidev@0x00 { 
    compatible = "spidev"; 
    spi-max-frequency = <800000>; /* It depends on your device */ 
    reg = <0>; /* correspond tochipselect 0 */ 
}; 
```

您可以调用读/写函数或`ioctl()`。通过调用读/写，您一次只能读取或写入。如果需要全双工读写，您必须使用**输入输出控制**（**ioctl**）命令。提供了两种的示例。这是读/写的示例。您可以使用平台的交叉编译器或板上的本地编译器进行编译：

```
#include <stdio.h> 
#include <fcntl.h> 
#include <stdlib.h> 

int main(int argc, char **argv)  
{ 
   int i,fd; 
   char wr_buf[]={0xff,0x00,0x1f,0x0f}; 
   char rd_buf[10];  

   if (argc<2) { 
         printf("Usage:\n%s [device]\n", argv[0]); 
         exit(1); 
   } 

   fd = open(argv[1], O_RDWR); 
   if (fd<=0) {  
         printf("Failed to open SPI device %s\n",argv[1]); 
         exit(1); 
   } 

   if (write(fd, wr_buf, sizeof(wr_buf)) != sizeof(wr_buf)) 
         perror("Write Error"); 
   if (read(fd, rd_buf, sizeof(rd_buf)) != sizeof(rd_buf)) 
         perror("Read Error"); 
   else 
         for (i = 0; i < sizeof(rd_buf); i++) 
             printf("0x%02X ", rd_buf[i]); 

   close(fd); 
   return 0; 
} 
```

# 使用 IOCTL

使用 IOCTL 的优势在于您可以进行全双工工作。您可以在内核源树中的`documentation/spi/spidev_test.c`中找到最好的示例。

也就是说，前面使用读/写的示例并没有改变任何 SPI 配置。然而，内核向用户空间公开了一组 IOCTL 命令，您可以使用这些命令来根据需要设置总线，就像在 DT 中所做的那样。以下示例显示了如何更改总线设置：

```
 #include <stdint.h> 
 #include <unistd.h> 
 #include <stdio.h> 
 #include <stdlib.h> 
 #include <string.h> 
 #include <fcntl.h> 
 #include <sys/ioctl.h> 
 #include <linux/types.h> 
 #include <linux/spi/spidev.h> 
static int pabort(const char *s) 
{ 
    perror(s); 
    return -1; 
} 

static int spi_device_setup(int fd) 
{ 
    int mode, speed, a, b, i; 
    int bits = 8; 

    /* 
     * spi mode: mode 0 
     */ 
    mode = SPI_MODE_0; 
    a = ioctl(fd, SPI_IOC_WR_MODE, &mode); /* write mode */ 
    b = ioctl(fd, SPI_IOC_RD_MODE, &mode); /* read mode */ 
    if ((a < 0) || (b < 0)) { 
        return pabort("can't set spi mode"); 
    } 

    /* 
     * Clock max speed in Hz 
     */ 
    speed = 8000000; /* 8 MHz */ 
    a = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed); /* Write speed */ 
    b = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed); /* Read speed */ 
    if ((a < 0) || (b < 0)) { 
        return pabort("fail to set max speed hz"); 
    } 

    /* 
     * setting SPI to MSB first.  
     * Here, 0 means "not to use LSB first". 
     * In order to use LSB first, argument should be > 0 
     */ 
    i = 0; 
    a = ioctl(dev, SPI_IOC_WR_LSB_FIRST, &i); 
    b = ioctl(dev, SPI_IOC_RD_LSB_FIRST, &i); 
    if ((a < 0) || (b < 0)) { 
        pabort("Fail to set MSB first\n"); 
    } 

    /* 
     * setting SPI to 8 bits per word 
     */ 
    bits = 8; 
    a = ioctl(dev, SPI_IOC_WR_BITS_PER_WORD, &bits); 
    b = ioctl(dev, SPI_IOC_RD_BITS_PER_WORD, &bits); 
    if ((a < 0) || (b < 0)) { 
        pabort("Fail to set bits per word\n"); 
    } 

    return 0; 
} 
```

您可以查看*Documentation/spi/spidev*以获取有关 spidev ioctl 命令的更多信息。在发送数据到总线时，您可以使用`SPI_IOC_MESSAGE(N)`请求，它提供了全双工访问和复合操作，而无需取消芯片选择，从而提供了多传输支持。这相当于内核的`spi_sync()`。这里，一个传输被表示为`struct spi_ioc_transfer`的实例，它相当于内核的`struct spi_transfer`，其定义可以在`include/uapi/linux/spi/spidev.h`中找到。以下是一个使用示例：

```
static void do_transfer(int fd) 
{ 
    int ret; 
    char txbuf[] = {0x0B, 0x02, 0xB5}; 
    char rxbuf[3] = {0, }; 
    char cmd_buff = 0x9f; 

    struct spi_ioc_transfer tr[2] = { 
        0 = { 
            .tx_buf = (unsigned long)&cmd_buff, 
            .len = 1, 
            .cs_change = 1; /* We need CS to change */ 
            .delay_usecs = 50, /* wait after this transfer */ 
            .bits_per_word = 8, 
        }, 
        [1] = { 
            .tx_buf = (unsigned long)tx, 
            .rx_buf = (unsigned long)rx, 
            .len = txbuf(tx), 
            .bits_per_word = 8, 
        }, 
    }; 

    ret = ioctl(fd, SPI_IOC_MESSAGE(2), &tr); 
    if (ret == 1){ 
        perror("can't send spi message"); 
        exit(1); 
    } 

    for (ret = 0; ret < sizeof(tx); ret++) 
        printf("%.2X ", rx[ret]); 
    printf("\n"); 
} 

int main(int argc, char **argv) 
{ 
    char *device = "/dev/spidev0.0"; 
    int fd; 
    int error; 

    fd = open(device, O_RDWR); 
    if (fd < 0) 
        return pabort("Can't open device "); 

    error = spi_device_setup(fd); 
    if (error) 
        exit (1); 

    do_transfer(fd); 

    close(fd); 
    return 0; 
} 
```

# 总结

我们刚刚处理了 SPI 驱动程序，现在可以利用这个更快的串行（和全双工）总线。我们讨论了 SPI 上的数据传输，这是最重要的部分。也就是说，您可能需要更多的抽象，以便不必理会 SPI 或 I2C 的 API。这就是下一章的内容，介绍了 Regmap API，它提供了更高和统一的抽象级别，使得 SPI（或 I2C）命令对您来说变得透明。


# 第九章：Regmap API - 寄存器映射抽象

在开发 regmap API 之前，处理 SPI 核心、I2C 核心或两者的设备驱动程序存在冗余代码。原则是相同的；访问寄存器进行读/写操作。以下图显示了在 Regmap 引入内核之前，SPI 或 I2C API 是如何独立存在的：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00016.gif)

regmap 之前的 SPI 和 I2C 子系统

regmap API 是在内核的 3.1 版本中引入的，以因式分解和统一内核开发人员访问 SPI/I2C 设备的方式。然后只是如何初始化、配置 regmap，并流畅地处理任何读/写/修改操作，无论是 SPI 还是 I2C：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00017.jpg)

regmap 之后的 SPI 和 I2C 子系统

本章将通过以下方式介绍 regmap 框架：

+   介绍了 regmap 框架中使用的主要数据结构

+   通过 regmap 配置进行漫游

+   使用 regmap API 访问设备

+   介绍 regmap 缓存系统

+   提供一个总结先前学习的概念的完整驱动程序

# 使用 regmap API 进行编程

regmap API 非常简单。只有少数结构需要了解。此 API 的两个最重要的结构是`struct regmap_config`，它表示 regmap 的配置，以及`struct regmap`，它是 regmap 实例本身。所有 regmap 数据结构都在`include/linux/regmap.h`中定义。

# regmap_config 结构

`struct regmap_config`在驱动程序的生命周期内存储 regmap 的配置。您在这里设置的内容会影响读/写操作。这是 regmap API 中最重要的结构。源代码如下：

```
struct regmap_config { 
    const char *name; 

    int reg_bits; 
    int reg_stride; 
    int pad_bits; 
    int val_bits; 

    bool (*writeable_reg)(struct device *dev, unsigned int reg); 
    bool (*readable_reg)(struct device *dev, unsigned int reg); 
    bool (*volatile_reg)(struct device *dev, unsigned int reg); 
    bool (*precious_reg)(struct device *dev, unsigned int reg); 
    regmap_lock lock; 
    regmap_unlock unlock; 
    void *lock_arg; 

    int (*reg_read)(void *context, unsigned int reg, 
                    unsigned int *val); 
    int (*reg_write)(void *context, unsigned int reg, 
                    unsigned int val); 

    bool fast_io; 

    unsigned int max_register; 
    const struct regmap_access_table *wr_table; 
    const struct regmap_access_table *rd_table; 
    const struct regmap_access_table *volatile_table; 
    const struct regmap_access_table *precious_table; 
    const struct reg_default *reg_defaults; 
    unsigned int num_reg_defaults; 
    enum regcache_type cache_type; 
    const void *reg_defaults_raw; 
    unsigned int num_reg_defaults_raw; 

    u8 read_flag_mask; 
    u8 write_flag_mask; 

    bool use_single_rw; 
    bool can_multi_write; 

    enum regmap_endian reg_format_endian; 
    enum regmap_endian val_format_endian; 
    const struct regmap_range_cfg *ranges; 
    unsigned int num_ranges; 
} 
```

+   `reg_bits`：这是寄存器地址中的位数，是强制性字段。

+   `val_bits`：表示用于存储寄存器值的位数。这是一个强制性字段。

+   `writeable_reg`：这是一个可选的回调函数。如果提供，当需要写入寄存器时，regmap 子系统将使用它。在写入寄存器之前，将自动调用此函数以检查寄存器是否可以写入：

```
static bool foo_writeable_register(struct device *dev, 
                                    unsigned int reg) 
{ 
    switch (reg) { 
    case 0x30 ... 0x38: 
    case 0x40 ... 0x45: 
    case 0x50 ... 0x57: 
    case 0x60 ... 0x6e: 
    case 0x70 ... 0x75: 
    case 0x80 ... 0x85: 
    case 0x90 ... 0x95: 
    case 0xa0 ... 0xa5: 
    case 0xb0 ... 0xb2: 
        return true; 
    default: 
        return false; 
    } 
} 
```

+   `readable_reg`：与`writeable_reg`相同，但用于每个寄存器读取操作。

+   `volatile_reg`：这是一个回调函数，每当需要通过 regmap 缓存读取或写入寄存器时都会调用。如果寄存器是易失性的，则函数应返回 true。然后对寄存器执行直接读/写。如果返回 false，则表示寄存器是可缓存的。在这种情况下，将使用缓存进行读取操作，并在写入操作的情况下写入缓存：

```
static bool foo_volatile_register(struct device *dev, 
                                    unsigned int reg) 
{ 
    switch (reg) { 
    case 0x24 ... 0x29: 
    case 0xb6 ... 0xb8: 
        return true; 
    default: 
        return false; 
    } 
} 
```

+   `wr_table`：可以提供`writeable_reg`回调，也可以提供`regmap_access_table`，它是一个包含`yes_range`和`no_range`字段的结构，都指向`struct regmap_range`。属于`yes_range`条目的任何寄存器都被视为可写，并且如果属于`no_range`，则被视为不可写。

+   `rd_table`：与`wr_table`相同，但用于任何读取操作。

+   `volatile_table`：可以提供`volatile_reg`，也可以提供`volatile_table`。原则与`wr_table`或`rd_table`相同，但用于缓存机制。

+   `max_register`：这是可选的，它指定了最大有效寄存器地址，超过该地址将不允许任何操作。

+   `reg_read`：您的设备可能不支持简单的 I2C/SPI 读取操作。那么您别无选择，只能编写自己定制的读取函数。`reg_read`应指向该函数。也就是说，大多数设备不需要。

+   `reg_write`：与`reg_read`相同，但用于写操作。

我强烈建议您查看`include/linux/regmap.h`以获取有关每个元素的更多详细信息。

以下是`regmap_config`的一种初始化方式：

```
static const struct regmap_config regmap_config = { 
    .reg_bits     = 8, 
    .val_bits     = 8, 
    .max_register = LM3533_REG_MAX, 
    .readable_reg = lm3533_readable_register, 
    .volatile_reg = lm3533_volatile_register, 
    .precious_reg = lm3533_precious_register, 
}; 
```

# regmap 初始化

正如我们之前所说，regmap API 支持 SPI 和 I2C 协议。根据驱动程序中需要支持的协议，您将需要在`probe`函数中调用`regmap_init_i2c()`或`regmap_init_sp()`。要编写通用驱动程序，regmap 是最佳选择。

regmap API 是通用和同质的。只有初始化在总线类型之间变化。其他函数都是一样的。

在`probe`函数中始终初始化 regmap 是一个良好的实践，必须在初始化 regmap 之前始终填充`regmap_config`元素。

无论是分配了 I2C 还是 SPI 寄存器映射，都可以使用`regmap_exit`函数释放它：

```
void regmap_exit(struct regmap *map) 
```

此函数只是释放先前分配的寄存器映射。

# SPI 初始化

Regmap SPI 初始化包括设置 regmap，以便任何设备访问都会在内部转换为 SPI 命令。执行此操作的函数是`regmap_init_spi()`。

```
struct regmap * regmap_init_spi(struct spi_device *spi, 
const struct regmap_config); 
```

它以一个有效的`struct spi_device`结构的指针作为参数，这是将要交互的 SPI 设备，以及代表 regmap 配置的`struct regmap_config`。此函数在成功时返回分配的 struct regmap 的指针，或者在错误时返回`ERR_PTR()`的值。

一个完整的例子如下：

```
static int foo_spi_probe(struct spi_device *client) 
{ 
    int err; 
    struct regmap *my_regmap; 
    struct regmap_config bmp085_regmap_config; 

        /* fill bmp085_regmap_config somewhere */ 
        [...] 
    client->bits_per_word = 8; 

    my_regmap = 
           regmap_init_spi(client,&bmp085_regmap_config); 

    if (IS_ERR(my_regmap)) { 
        err = PTR_ERR(my_regmap); 
        dev_err(&client->dev, "Failed to init regmap: %d\n", err); 
        return err; 
    } 
    [...] 
} 
```

# I2C 初始化

另一方面，I2C regmap 初始化包括在 regmap 配置上调用`regmap_init_i2c()`，这将配置 regmap，以便任何设备访问都在内部转换为 I2C 命令：

```
struct regmap * regmap_init_i2c(struct i2c_client *i2c, 
const struct regmap_config); 
```

该函数以`struct i2c_client`结构作为参数，这是将用于交互的 I2C 设备，以及代表 regmap 配置的指针`struct regmap_config`。此函数在成功时返回分配的`struct regmap`的指针，或者在错误时返回`ERR_PTR()`的值。

一个完整的例子是：

```
static int bar_i2c_probe(struct i2c_client *i2c, 
const struct i2c_device_id *id) 
{ 
    struct my_struct * bar_struct; 
    struct regmap_config regmap_cfg; 

        /* fill regmap_cfgsome  where */ 
        [...] 
    bar_struct = kzalloc(&i2c->dev, 
sizeof(*my_struct), GFP_KERNEL); 
    if (!bar_struct) 
        return -ENOMEM; 

    i2c_set_clientdata(i2c, bar_struct); 

    bar_struct->regmap = regmap_init_i2c(i2c, 
&regmap_config); 
    if (IS_ERR(bar_struct->regmap)) 
        return PTR_ERR(bar_struct->regmap); 

    bar_struct->dev = &i2c->dev; 
    bar_struct->irq = i2c->irq; 
    [...] 
} 
```

# 设备访问函数

该 API 处理数据解析、格式化和传输。在大多数情况下，使用`regmap_read`、`regmap_write`和`regmap_update_bits`执行设备访问。这些是在存储/从设备中获取数据时应该始终记住的三个最重要的函数。它们的原型分别是：

```
int regmap_read(struct regmap *map, unsigned int reg, 
                 unsigned int *val); 
int regmap_write(struct regmap *map, unsigned int reg, 
                 unsigned int val); 
int regmap_update_bits(struct regmap *map, unsigned int reg, 
                 unsigned int mask, unsigned int val); 
```

+   `regmap_write`：向设备写入数据。如果在`regmap_config`中设置了`max_register`，则将用它来检查您需要从中读取的寄存器地址是大于还是小于。如果传递的寄存器地址小于或等于`max_register`，则将执行写入操作；否则，regmap 核心将返回无效的 I/O 错误（`-EIO`）。紧接着，将调用`writeable_reg`回调。回调必须在进行下一步之前返回`true`。如果返回`false`，则返回`-EIO`并停止写操作。如果设置了`wr_table`而不是`writeable_reg`，则：

+   如果寄存器地址位于`no_range`中，则返回`-EIO`。

+   如果寄存器地址位于`yes_range`中，则执行下一步。

+   如果寄存器地址既不在`yes_range`也不在`no_range`中，则返回`-EIO`并终止操作。

+   如果`cache_type != REGCACHE_NONE`，则启用缓存。在这种情况下，首先更新缓存条目，然后执行硬件写入；否则，执行无缓存操作。

+   如果提供了`reg_write`回调，则将使用它执行写操作；否则，将执行通用的 regmap 写函数。

+   `regmap_read`：从设备中读取数据。它与`regmap_write`的工作方式完全相同，具有适当的数据结构（`readable_reg`和`rd_table`）。因此，如果提供了`reg_read`，则将使用它执行读取操作；否则，将执行通用的 remap 读取函数。

# regmap_update_bits 函数

`regmap_update_bits`是一个三合一的函数。其原型如下：

```
int regmap_update_bits(struct regmap *map, unsigned int reg, 
         unsigned int mask, unsigned int val) 
```

它在寄存器映射上执行读取/修改/写入循环。它是`_regmap_update_bits`的包装器，其形式如下：

```
static int _regmap_update_bits(struct regmap *map, 
                    unsigned int reg, unsigned int mask,  
                    unsigned int val, bool *change) 
{ 
    int ret; 
    unsigned int tmp, orig; 

    ret = _regmap_read(map, reg, &orig); 
    if (ret != 0) 
        return ret; 

    tmp = orig& ~mask; 
    tmp |= val & mask; 

    if (tmp != orig) { 
        ret = _regmap_write(map, reg, tmp); 
        *change = true; 
    } else { 
        *change = false; 
    } 

    return ret; 
} 
```

这样，您需要更新的位必须在`mask`中设置为`1`，并且相应的位应在`val`中设置为您需要给予它们的值。

例如，要将第一位和第三位设置为`1`，掩码应为`0b00000101`，值应为`0bxxxxx1x1`。要清除第七位，掩码必须为`0b01000000`，值应为`0bx0xxxxxx`，依此类推。

# 特殊的 regmap_multi_reg_write 函数

`remap_multi_reg_write()`函数的目的是向设备写入多个寄存器。其原型如下所示：

```
int regmap_multi_reg_write(struct regmap *map, 
                    const struct reg_sequence *regs, int num_regs) 
```

要了解如何使用该函数，您需要知道`struct reg_sequence`是什么：

```
/** 
 * Register/value pairs for sequences of writes with an optional delay in 
 * microseconds to be applied after each write. 
 * 
 * @reg: Register address. 
 * @def: Register value. 
 * @delay_us: Delay to be applied after the register write in microseconds 
 */ 
struct reg_sequence { 
    unsigned int reg; 
    unsigned int def; 
    unsigned int delay_us; 
}; 
```

这就是它的使用方式：

```
static const struct reg_sequence foo_default_regs[] = { 
    { FOO_REG1,          0xB8 }, 
    { BAR_REG1,          0x00 }, 
    { FOO_BAR_REG1,      0x10 }, 
    { REG_INIT,          0x00 }, 
    { REG_POWER,         0x00 }, 
    { REG_BLABLA,        0x00 }, 
}; 

staticint probe ( ...) 
{ 
    [...] 
    ret = regmap_multi_reg_write(my_regmap, foo_default_regs, 
                                   ARRAY_SIZE(foo_default_regs)); 
    [...] 
} 
```

# 其他设备访问函数

`regmap_bulk_read()`和`regmap_bulk_write()`用于从/向设备读取/写入多个寄存器。将它们与大块数据一起使用。

```
int regmap_bulk_read(struct regmap *map, unsigned int reg, void 
                     *val, size_tval_count); 
int regmap_bulk_write(struct regmap *map, unsigned int reg, 
                     const void *val, size_t val_count); 
```

随时查看内核源中的 regmap 头文件，了解您有哪些选择。

# regmap 和缓存

显然，regmap 支持缓存。是否使用缓存系统取决于`regmap_config`中的`cache_type`字段的值。查看`include/linux/regmap.h`，接受的值为：

```
/* Anenum of all the supported cache types */ 
enum regcache_type { 
   REGCACHE_NONE, 
   REGCACHE_RBTREE, 
   REGCACHE_COMPRESSED, 
   REGCACHE_FLAT, 
}; 
```

默认情况下，它设置为`REGCACHE_NONE`，表示缓存已禁用。其他值只是定义缓存应如何存储。

您的设备可能在某些寄存器中具有预定义的上电复位值。这些值可以存储在一个数组中，以便任何读操作都返回数组中包含的值。但是，任何写操作都会影响设备中的真实寄存器，并更新数组中的内容。这是一种我们可以使用的缓存，以加快对设备的访问速度。该数组是`reg_defaults`。它在源代码中的结构如下：

```
/** 
 * Default value for a register.  We use an array of structs rather 
 * than a simple array as many modern devices have very sparse 
 * register maps. 
 * 
 * @reg: Register address. 
 * @def: Register default value. 
 */ 
struct reg_default { 
    unsigned int reg; 
    unsigned int def; 
}; 
```

如果将`cache_type`设置为 none，则将忽略`reg_defaults`。如果未设置`default_reg`但仍然启用缓存，则将为您创建相应的缓存结构。

使用起来非常简单。只需声明它并将其作为参数传递给`regmap_config`结构。让我们看看`drivers/regulator/ltc3589.c`中的`LTC3589`调节器驱动程序：

```
static const struct reg_default ltc3589_reg_defaults[] = { 
{ LTC3589_SCR1,   0x00 }, 
{ LTC3589_OVEN,   0x00 }, 
{ LTC3589_SCR2,   0x00 }, 
{ LTC3589_VCCR,   0x00 }, 
{ LTC3589_B1DTV1, 0x19 }, 
{ LTC3589_B1DTV2, 0x19 }, 
{ LTC3589_VRRCR,  0xff }, 
{ LTC3589_B2DTV1, 0x19 }, 
{ LTC3589_B2DTV2, 0x19 }, 
{ LTC3589_B3DTV1, 0x19 }, 
{ LTC3589_B3DTV2, 0x19 }, 
{ LTC3589_L2DTV1, 0x19 }, 
{ LTC3589_L2DTV2, 0x19 }, 
}; 
static const struct regmap_config ltc3589_regmap_config = { 
        .reg_bits = 8, 
        .val_bits = 8, 
        .writeable_reg = ltc3589_writeable_reg, 
        .readable_reg = ltc3589_readable_reg, 
        .volatile_reg = ltc3589_volatile_reg, 
        .max_register = LTC3589_L2DTV2, 
        .reg_defaults = ltc3589_reg_defaults, 
        .num_reg_defaults = ARRAY_SIZE(ltc3589_reg_defaults), 
        .use_single_rw = true, 
        .cache_type = REGCACHE_RBTREE, 
}; 
```

对数组中存在的任何寄存器进行任何读操作都会立即返回数组中的值。但是，写操作将在设备本身上执行，并更新数组中受影响的寄存器。这样，读取`LTC3589_VRRCR`寄存器将返回`0xff`；在该寄存器中写入任何值，它将更新数组中的条目，以便任何新的读操作将直接从缓存中返回最后写入的值。

# 将所有内容放在一起

执行以下步骤设置 regmap 子系统：

1.  根据设备的特性设置一个`regmap_config`结构。如果需要，设置寄存器范围，默认值，如果需要，`cache_type`等等。如果需要自定义读/写函数，请将它们传递给`reg_read/reg_write`字段。

1.  在`probe`函数中，使用`regmap_init_i2c`或`regmap_init_spi`分配一个 regmap，具体取决于总线：I2C 或 SPI。

1.  每当您需要从寄存器中读取/写入时，请调用`remap_[read|write]`函数。

1.  当您完成对 regmap 的操作后，调用`regmap_exit`来释放在`probe`中分配的寄存器映射。

# 一个 regmap 示例

为了实现我们的目标，让我们首先描述一个假的 SPI 设备，我们可以为其编写驱动程序：

+   8 位寄存器地址

+   8 位寄存器值

+   最大寄存器：0x80

+   写入掩码为 0x80

+   有效地址范围：

+   0x20 到 0x4F

+   0x60 到 0x7F

+   不需要自定义读/写函数。

以下是一个虚拟的骨架：

```
/* mandatory for regmap */ 
#include <linux/regmap.h> 
/* Depending on your need you should include other files */ 

static struct private_struct 
{ 
    /* Feel free to add whatever you want here */ 
    struct regmap *map; 
    int foo; 
}; 

static const struct regmap_range wr_rd_range[] = 
{ 
    { 
            .range_min = 0x20, 
            .range_max = 0x4F, 
    },{ 
            .range_min = 0x60, 
            .range_max = 0x7F 
    }, 
};  

struct regmap_access_table drv_wr_table = 
{ 
        .yes_ranges =   wr_rd_range, 
        .n_yes_ranges = ARRAY_SIZE(wr_rd_range), 
}; 

struct regmap_access_table drv_rd_table = 
{ 
        .yes_ranges =   wr_rd_range, 
        .n_yes_ranges = ARRAY_SIZE(wr_rd_range), 
}; 

static bool writeable_reg(struct device *dev, unsigned int reg) 
{ 
    if (reg>= 0x20 &&reg<= 0x4F) 
        return true; 
    if (reg>= 0x60 &&reg<= 0x7F) 
        return true; 
    return false; 
} 

static bool readable_reg(struct device *dev, unsigned int reg) 
{ 
    if (reg>= 0x20 &&reg<= 0x4F) 
        return true; 
    if (reg>= 0x60 &&reg<= 0x7F) 
        return true; 
    return false; 
} 

static int my_spi_drv_probe(struct spi_device *dev) 
{ 
    struct regmap_config config; 
    struct custom_drv_private_struct *priv; 
    unsigned char data; 

    /* setup the regmap configuration */ 
    memset(&config, 0, sizeof(config)); 
    config.reg_bits = 8; 
    config.val_bits = 8; 
    config.write_flag_mask = 0x80; 
    config.max_register = 0x80; 
    config.fast_io = true; 
    config.writeable_reg = drv_writeable_reg; 
    config.readable_reg = drv_readable_reg; 

    /*  
     * If writeable_reg and readable_reg are set, 
     * there is no need to provide wr_table nor rd_table. 
     * Uncomment below code only if you do not want to use 
     * writeable_reg nor readable_reg. 
     */ 
    //config.wr_table = drv_wr_table; 
    //config.rd_table = drv_rd_table; 

    /* allocate the private data structures */ 
    /* priv = kzalloc */ 

    /* Init the regmap spi configuration */ 
    priv->map = regmap_init_spi(dev, &config); 
    /* Use regmap_init_i2c in case of i2c bus */ 

    /*  
     * Let us write into some register 
     * Keep in mind that, below operation will remain same 
     * whether you use SPI or I2C. It is and advantage when 
     * you use regmap. 
     */  
    regmap_read(priv->map, 0x30, &data); 
    [...] /* Process data */ 

    data = 0x24; 
    regmap_write(priv->map, 0x23, data); /* write new value */ 

    /* set bit 2 (starting from 0) and 6 of register 0x44 */ 
    regmap_update_bits(priv->map, 0x44, 0b00100010, 0xFF); 
    [...] /* Lot of stuff */      
    return 0; 
} 
```

# 总结

本章主要讲述了 regmap API。它有多么简单，让你了解了它有多么有用和广泛使用。本章告诉了你关于 regmap API 的一切你需要知道的东西。现在你应该能够将任何标准的 SPI/I2C 驱动程序转换成 regmap。下一章将涵盖 IIO 设备，这是一个用于模数转换器的框架。这些类型的设备总是位于 SPI/I2C 总线的顶部。在下一章结束时，使用 regmap API 编写 IIO 驱动程序将是一个挑战。


# 第十章：IIO 框架

**工业 I/O**（**IIO**）是一个专门用于**模拟到数字转换器**（**ADC**）和**数字到模拟转换器**（**DAC**）的内核子系统。随着不断增加的传感器（具有模拟到数字或数字到模拟能力的测量设备）以不同的代码实现分散在内核源代码中，对它们进行收集变得必要。这就是 IIO 框架以一种通用和统一的方式所做的。自 2009 年以来，Jonathan Cameron 和 Linux-IIO 社区一直在开发它。

加速度计、陀螺仪、电流/电压测量芯片、光传感器、压力传感器等都属于 IIO 设备系列。

IIO 模型基于设备和通道架构：

+   设备代表芯片本身。它是层次结构的最高级别。

+   通道表示设备的单个采集线。一个设备可能有一个或多个通道。例如，加速度计是一个具有三个通道的设备，分别用于每个轴（X、Y 和 Z）。

IIO 芯片是物理和硬件传感器/���换器。它以字符设备（当支持触发缓冲时）和一个**sysfs**目录条目暴露给用户空间，该目录将包含一组文件，其中一些表示通道。单个通道用单个**sysfs**文件条目表示。

这是从用户空间与 IIO 驱动程序交互的两种方式：

+   `/sys/bus/iio/iio:deviceX/`：这代表传感器以及其通道

+   `/dev/iio:deviceX`：这是一个字符设备，用于导出设备的事件和数据缓冲区

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00018.jpg)

IIO 框架的架构和布局

前面的图显示了 IIO 框架在内核和用户空间之间的组织方式。驱动程序管理硬件并将处理报告给 IIO 核心，使用 IIO 核心提供的一组设施和 API。然后，IIO 子系统通过 sysfs 接口和字符设备将整个底层机制抽象到用户空间，用户可以在其上执行系统调用。

IIO API 分布在几个头文件中，列举如下：

```
#include <linux/iio/iio.h>    /* mandatory */ 
#include <linux/iio/sysfs.h>  /* mandatory since sysfs is used */ 
#include <linux/iio/events.h> /* For advanced users, to manage iio events */ 
#include <linux/iio/buffer.h> /* mandatory to use triggered buffers */ 
#include <linux/iio/trigger.h>/* Only if you implement trigger in your driver (rarely used)*/ 
```

在本章中，我们将描述和处理 IIO 框架的每个概念，比如

+   遍历其数据结构（设备、通道等）

+   触发缓冲区支持和连续捕获，以及其 sysfs 接口

+   探索现有的 IIO 触发器

+   以单次模式或连续模式捕获数据

+   列出可用的工具，可以帮助开发人员测试他们的设备

# IIO 数据结构

IIO 设备在内核中表示为`struct iio_dev`的实例，并由`struct iio_info`结构描述。所有重要的 IIO 结构都在`include/linux/iio/iio.h`中定义。

# iio_dev 结构

这个结构表示 IIO 设备，描述设备和驱动程序。它告诉我们关于：

+   设备上有多少个通道可用？

+   设备可以以哪些模式操作：单次、触发缓冲？

+   这个驱动程序有哪些可用的钩子？

```
struct iio_dev { 
   [...] 
   int modes; 
   int currentmode; 
   struct device dev; 

   struct iio_buffer *buffer; 
   int scan_bytes; 

   const unsigned long *available_scan_masks; 
   const unsigned long *active_scan_mask; 
   bool scan_timestamp; 
   struct iio_trigger *trig; 
   struct iio_poll_func *pollfunc; 

   struct iio_chan_spec const *channels; 
   int num_channels; 
   const char *name; 
   const struct iio_info *info; 
   const struct iio_buffer_setup_ops *setup_ops; 
   struct cdev chrdev; 
}; 
```

完整的结构在 IIO 头文件中定义。这里删除了我们不感兴趣的字段。

+   `modes`：这代表设备支持的不同模式。支持的模式有：

+   `INDIO_DIRECT_MODE` 表示设备提供 sysfs 类型的接口。

+   `INDIO_BUFFER_TRIGGERED` 表示设备支持硬件触发。当您使用`iio_triggered_buffer_setup()`函数设置触发缓冲区时，此模式会自动添加到您的设备中。

+   `INDIO_BUFFER_HARDWARE`显示设备具有硬件缓冲区。

+   `INDIO_ALL_BUFFER_MODES`是上述两者的并集。

+   `currentmode`：这代表设备实际使用的模式。

+   `dev`：这代表了 IIO 设备绑定的 struct device（根据 Linux 设备模型）。

+   `buffer`：这是您的数据缓冲区，在使用触发缓冲区模式时推送到用户空间。当使用`iio_triggered_buffer_setup`函数启用触发缓冲区支持时，它会自动分配并与您的设备关联。

+   `scan_bytes`：这是捕获并馈送到`buffer`的字节数。当从用户空间使用触发缓冲区时，缓冲区应至少为`indio->scan_bytes`字节大。

+   `available_scan_masks`：这是允许的位掩码的可选数组。在使用触发缓冲区时，可以启用通道以被捕获并馈送到 IIO 缓冲区中。如果不希望允许某些通道被启用，应该只填充此数组。以下是为加速度计提供扫描掩码的示例（具有 X、Y 和 Z 通道）：

```
/* 
 * Bitmasks 0x7 (0b111) and 0 (0b000) are allowed. 
 * It means one can enable none or all of them. 
 * one can't for example enable only channel X and Y 
 */ 
static const unsigned long my_scan_masks[] = {0x7, 0}; 
indio_dev->available_scan_masks = my_scan_masks; 
```

+   `active_scan_mask`：这是启用通道的位掩码。只有这些通道的数据应该被推送到`buffer`中。例如，对于 8 通道 ADC 转换器，如果只启用第一个（0）、第三个（2）和最后一个（7）通道，位掩码将是 0b10000101（0x85）。`active_scan_mask`将设置为 0x85。然后驱动程序可以使用`for_each_set_bit`宏来遍历每个设置的位，根据通道获取数据，并填充缓冲区。

+   `scan_timestamp`：这告诉我们是否将捕获时间戳推送到缓冲区。如果为 true，则时间戳将作为缓冲区的最后一个元素推送。时间戳为 8 字节（64 位）。

+   `trig`：这是当前设备的触发器（当支持缓冲模式时）。

+   `pollfunc`：这是在接收到触发器时运行的函数。

+   `channels`：这代表通道规范结构表，描述设备具有的每个通道。

+   `num_channels`：这代表在`channels`中指定的通道数。

+   `name`：这代表设备名称。

+   `info`：来自驱动程序的回调和常量信息。

+   `setup_ops`：在启用/禁用缓冲区之前和之后调用的回调函数集。此结构在`include/linux/iio/iio.h`中定义如下：

```
struct iio_buffer_setup_ops { 
    int (* preenable) (struct iio_dev *); 
    int (* postenable) (struct iio_dev *); 
    int (* predisable) (struct iio_dev *); 
    int (* postdisable) (struct iio_dev *); 
    bool (* validate_scan_mask) (struct iio_dev *indio_dev, 
                                 const unsigned long *scan_mask); 
}; 
```

+   `setup_ops`：如果未指定，IIO 核心将使用在`drivers/iio/buffer/industrialio-triggered-buffer.c`中定义的默认`iio_triggered_buffer_setup_ops`。

+   `chrdev`：这是由 IIO 核心创建的关联字符设备。

用于为 IIO 设备分配内存的函数是`iio_device_alloc()`：

```
struct iio_dev *devm_iio_device_alloc(struct device *dev,  

                                      int sizeof_priv) 
```

`dev`是为其分配`iio_dev`的设备，`sizeof_priv`是用于分配任何私有结构的内存空间。通过这种方式，传递每个设备（私有）数据结构非常简单。如果分配失败，该函数将返回`NULL`：

```
struct iio_dev *indio_dev; 
struct my_private_data *data; 
indio_dev = iio_device_alloc(sizeof(*data)); 
if (!indio_dev) 
    return -ENOMEM; 
/*data is given the address of reserved momory for private data */ 
data = iio_priv(indio_dev); 
```

分配了 IIO 设备内存后，下一步是填充不同的字段。完成后，必须使用`iio_device_register`函数向 IIO 子系统注册设备：

```
int iio_device_register(struct iio_dev *indio_dev) 
```

此函数执行后，设备将准备好接受来自用户空间的请求。反向操作（通常在释放函数中完成）是`iio_device_unregister()`：

```
void iio_device_unregister(struct iio_dev *indio_dev) 
```

一旦注销，由`iio_device_alloc`分配的内存可以使用`iio_device_free`释放：

```
void iio_device_free(struct iio_dev *iio_dev) 
```

给定一个 IIO 设备作为参数，可以以以下方式检索私有数据：

```
struct my_private_data *the_data = iio_priv(indio_dev); 
```

# iio_info 结构

`struct iio_info`结构用于声明 IIO 核心用于读取/写入通道/属性值的钩子：

```
struct iio_info { 
   struct module *driver_module; 
   const struct attribute_group *attrs; 

   int (*read_raw)(struct iio_dev *indio_dev, 
               struct iio_chan_spec const *chan, 
               int *val, int *val2, long mask); 

   int (*write_raw)(struct iio_dev *indio_dev, 
                struct iio_chan_spec const *chan, 
                int val, int val2, long mask); 
    [...] 
}; 
```

我们不感兴趣的字段已被移除。

+   `driver_module`：这是用于确保`chrdevs`正确拥有权的模块结构，通常设置为`THIS_MODULE`。

+   `attrs`：这代表设备的属性。

+   `read_raw`：这是当用户读取设备`sysfs`文件属性时运行的回调。`mask`参数是一个位掩码，允许我们知道请求的是哪种类型的值。`channel`参数让我们知道所关注的通道。它可以用于采样频率、用于将原始值转换为可用值的比例，或者原始值本身。

+   `write_raw`：这是用于向设备写入值的回调。例如，可以使用它来设置采样频率。

以下代码显示了如何设置`struct iio_info`结构：

```
static const struct iio_info iio_dummy_info = { 
    .driver_module = THIS_MODULE, 
    .read_raw = &iio_dummy_read_raw, 
    .write_raw = &iio_dummy_write_raw, 
[...] 

/* 
 * Provide device type specific interface functions and 
 * constant data. 
 */ 
indio_dev->info = &iio_dummy_info; 
```

# IIO 通道

通道表示单个采集线。例如，加速度计将有 3 个通道（X、Y、Z），因为每个轴代表单个采集线。`struct iio_chan_spec`是在内核中表示和描述单个通道的结构：

```
    struct iio_chan_spec { 
        enum iio_chan_type type; 
        int channel; 
        int channel2; 
        unsigned long address; 
        int scan_index; 
        struct { 
            charsign; 
            u8 realbits; 
            u8 storagebits; 
            u8 shift; 
            u8 repeat; 
            enum iio_endian endianness; 
        } scan_type; 
        long info_mask_separate; 
        long info_mask_shared_by_type; 
        long info_mask_shared_by_dir; 
        long info_mask_shared_by_all; 
        const struct iio_event_spec *event_spec; 
        unsigned int num_event_specs; 
        const struct iio_chan_spec_ext_info *ext_info; 
        const char *extend_name; 
        const char *datasheet_name; 
        unsigned modified:1; 
        unsigned indexed:1; 
        unsigned output:1; 
        unsigned differential:1; 
    }; 
```

以下是结构中每个元素的含义：

+   `类型`：这指定了通道进行何种类型的测量。在电压测量的情况下，应该是`IIO_VOLTAGE`。对于光传感器，是`IIO_LIGHT`。对于加速度计，使用`IIO_ACCEL`。所有可用类型都在`include/uapi/linux/iio/types.h`中定义为`enum iio_chan_type`。要为给定的转换器编写驱动程序，请查看该文件，以查看每个通道所属的类型。

+   `通道`：当`.indexed`设置为 1 时，这指定了通道索引。

+   `channel2`：当`.modified`设置为 1 时，这指定了通道修饰符��

+   `修改`：这指定了是否要对该通道属性名称应用修饰符。在这种情况下，修饰符设置为`.channel2`。（例如，`IIO_MOD_X`，`IIO_MOD_Y`，`IIO_MOD_Z`是关于 xyz 轴的轴向传感器的修饰符）。可用的修饰符列表在内核 IIO 头文件中定义为`enum iio_modifier`。修饰符只会对`sysfs`中的通道属性名称进行操作，而不会对值进行操作。

+   `indexed`：这指定了通道属性名称是否具有索引。如果是，则索引在`.channel`字段中指定。

+   `scan_index`和`scan_type`：这些字段用于在使用缓冲区触发器时识别缓冲区中的元素。`scan_index`设置了缓冲区中捕获的通道的位置。具有较低`scan_index`的通道将放置在具有较高索引的通道之前。将`.scan_index`设置为`-1`将阻止通道进行缓冲捕获（在`scan_elements`目录中没有条目）。

向用户空间公开的通道 sysfs 属性以位掩码的形式指定。根据它们的共享信息，属性可以设置为以下掩码之一：

+   `info_mask_separate`将属性标记为特定于此通道。

+   `info_mask_shared_by_type`将属性标记为所有相同类型的通道共享的属性。导出的信息由所有相同类型的通道共享。

+   `info_mask_shared_by_dir`将属性标记为所有相同方向的通道共享的属性。导出的信息由相同方向的所有通道共享。

+   `info_mask_shared_by_all`将属性标记为所有通道共享的属性，无论它们的类型或方向如何。导出的信息由所有通道共享。这些属性的枚举位掩码都在`include/linux/iio/iio.h`中定义。

```
enum iio_chan_info_enum { 
    IIO_CHAN_INFO_RAW = 0, 
    IIO_CHAN_INFO_PROCESSED, 
    IIO_CHAN_INFO_SCALE, 
    IIO_CHAN_INFO_OFFSET, 
    IIO_CHAN_INFO_CALIBSCALE, 
    [...] 
    IIO_CHAN_INFO_SAMP_FREQ, 
    IIO_CHAN_INFO_FREQUENCY, 
    IIO_CHAN_INFO_PHASE, 
    IIO_CHAN_INFO_HARDWAREGAIN, 
    IIO_CHAN_INFO_HYSTERESIS, 
    [...] 
}; 
```

字节顺序字段应为以下之一：

```
enum iio_endian { 
    IIO_CPU, 
    IIO_BE, 
    IIO_LE, 
}; 
```

# 通道属性命名约定

属性的名称由 IIO 核心自动生成，遵循以下模式：`{direction}_{type}_{index}_{modifier}_{info_mask}`：

+   `方向`对应于属性方向，根据`drivers/iio/industrialio-core.c`中的`struct iio_direction`结构：

```
static const char * const iio_direction[] = { 
   [0] = "in", 
   [1] = "out", 
}; 
```

+   `类型`对应于通道类型，根据字符数组`const iio_chan_type_name_spec`：

```
static const char * const iio_chan_type_name_spec[] = { 
   [IIO_VOLTAGE] = "voltage", 
   [IIO_CURRENT] = "current", 
   [IIO_POWER] = "power", 
   [IIO_ACCEL] = "accel", 
   [...] 
   [IIO_UVINDEX] = "uvindex", 
   [IIO_ELECTRICALCONDUCTIVITY] = "electricalconductivity", 
   [IIO_COUNT] = "count", 
   [IIO_INDEX] = "index", 
   [IIO_GRAVITY]  = "gravity", 
}; 
```

+   `index`模式取决于通道`.indexed`字段是否设置。如果设置，索引将从`.channel`字段中取出，以替换`{index}`模式。

+   `modifier` 模式取决于通道`.modified`字段是否设置。如果设置，修饰符将从`.channel2`字段中取出，并且`{modifier}`模式将根据`struct iio_modifier_names`结构中的字符数组进行替换：

```
static const char * const iio_modifier_names[] = { 
   [IIO_MOD_X] = "x", 
   [IIO_MOD_Y] = "y", 
   [IIO_MOD_Z] = "z", 
   [IIO_MOD_X_AND_Y] = "x&y", 
   [IIO_MOD_X_AND_Z] = "x&z", 
   [IIO_MOD_Y_AND_Z] = "y&z", 
   [...] 
   [IIO_MOD_CO2] = "co2", 
   [IIO_MOD_VOC] = "voc", 
}; 
```

+   `info_mask` 取决于通道信息掩码，私有或共享，字符数组`iio_chan_info_postfix`中的索引值：

```
/* relies on pairs of these shared then separate */ 
static const char * const iio_chan_info_postfix[] = { 
   [IIO_CHAN_INFO_RAW] = "raw", 
   [IIO_CHAN_INFO_PROCESSED] = "input", 
   [IIO_CHAN_INFO_SCALE] = "scale", 
   [IIO_CHAN_INFO_CALIBBIAS] = "calibbias", 
   [...] 
   [IIO_CHAN_INFO_SAMP_FREQ] = "sampling_frequency", 
   [IIO_CHAN_INFO_FREQUENCY] = "frequency", 
   [...] 
}; 
```

# 区分通道

当每个通道类型有多个数据通道时，您可能会陷入麻烦。两种解决方案是：索引和修饰符。

**使用索引**：给定一个具有一个通道线的 ADC 设备，不需要索引。它的通道定义将是：

```
static const struct iio_chan_spec adc_channels[] = { 
        { 
                .type = IIO_VOLTAGE, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
        }, 
} 
```

由前述通道描述产生的属性名称将是`in_voltage_raw`。

`/sys/bus/iio/iio:deviceX/in_voltage_raw`

现在假设转换器有 4 个甚至 8 个通道。我们如何识别它们？解决方案是使用索引。将`.indexed`字段设置为 1 将使用`.channel`值替换`{index}`模式来搅乱通道属性名称：

```
static const struct iio_chan_spec adc_channels[] = { 
        { 
                .type = IIO_VOLTAGE, 
                .indexed = 1, 
                .channel = 0, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
        }, 
        { 
                .type = IIO_VOLTAGE, 
                .indexed = 1, 
                .channel = 1, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
        }, 
        { 
                .type = IIO_VOLTAGE, 
                .indexed = 1, 
                .channel = 2, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
        }, 
        { 
                .type = IIO_VOLTAGE, 
                .indexed = 1, 
                .channel = 3, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
        }, 
} 
```

结果通道属性是：

`/sys/bus/iio/iio:deviceX/in_voltage0_raw`

`/sys/bus/iio/iio:deviceX/in_voltage1_raw`

`/sys/bus/iio/iio:deviceX/in_voltage2_raw`

`/sys/bus/iio/iio:deviceX/in_voltage3_raw`

**使用修饰符**：给定一个具有两个通道的光传感器——一个用于红外光，一个用于红外和可见光，没有索引或修饰符，属性名称将是`in_intensity_raw`。在这里使用索引可能会出错，因为`in_intensity0_ir_raw`和`in_intensity1_ir_raw`是没有意义的。使用修饰符将有助于提供有意义的属性名称。通道的定义可能如下所示：

```
static const struct iio_chan_spec mylight_channels[] = { 
        { 
                .type = IIO_INTENSITY, 
                .modified = 1, 
                .channel2 = IIO_MOD_LIGHT_IR, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
                .info_mask_shared = BIT(IIO_CHAN_INFO_SAMP_FREQ), 
        }, 
        { 
                .type = IIO_INTENSITY, 
                .modified = 1, 
                .channel2 = IIO_MOD_LIGHT_BOTH, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_RAW), 
                .info_mask_shared = BIT(IIO_CHAN_INFO_SAMP_FREQ), 
        }, 
        { 
                .type = IIO_LIGHT, 
                .info_mask_separate = BIT(IIO_CHAN_INFO_PROCESSED), 
                .info_mask_shared = BIT(IIO_CHAN_INFO_SAMP_FREQ), 
        }, 
} 
```

结果属性将是：

+   `/sys/bus/iio/iio:deviceX/in_intensity_ir_raw` 用于测量红外强度的通道

+   `/sys/bus/iio/iio:deviceX/in_intensity_both_raw` 用于测量红外和可见光的通道

+   `/sys/bus/iio/iio:deviceX/in_illuminance_input` 用于处理后的数据

+   `/sys/bus/iio/iio:deviceX/sampling_frequency` 用于所有共享的采样频率

这对于加速度计也有效，正如我们将在案例研究中看到的那样。现在，让我们总结一下到目前为止在虚拟 IIO 驱动程序中讨论的内容。

# 把所有东西放在一起

让我们总结一下到目前为止在一个简单的虚拟驱动程序中看到的内容，它将公开四个电压通道。我们将忽略`read()`或`write()`函数：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/platform_device.h> 
#include <linux/interrupt.h> 
#include <linux/of.h> 
#include <linux/iio/iio.h> 
#include <linux/iio/sysfs.h> 
#include <linux/iio/events.h> 
#include <linux/iio/buffer.h> 

#define FAKE_VOLTAGE_CHANNEL(num)                  \ 
   {                                               \ 
         .type = IIO_VOLTAGE,                      \ 
         .indexed = 1,                             \ 
         .channel = (num),                         \ 
         .address = (num),                         \ 
         .info_mask_separate = BIT(IIO_CHAN_INFO_RAW),   \ 
         .info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE) \ 
   } 

struct my_private_data { 
    int foo; 
    int bar; 
    struct mutex lock; 
}; 

static int fake_read_raw(struct iio_dev *indio_dev, 
                   struct iio_chan_spec const *channel, int *val, 
                   int *val2, long mask) 
{ 
    return 0; 
} 

static int fake_write_raw(struct iio_dev *indio_dev, 
                   struct iio_chan_spec const *chan, 
                   int val, int val2, long mask) 
{ 
    return 0; 
} 

static const struct iio_chan_spec fake_channels[] = { 
   FAKE_VOLTAGE_CHANNEL(0), 
   FAKE_VOLTAGE_CHANNEL(1), 
   FAKE_VOLTAGE_CHANNEL(2), 
   FAKE_VOLTAGE_CHANNEL(3), 
}; 

static const struct of_device_id iio_dummy_ids[] = { 
    { .compatible = "packt,iio-dummy-random", }, 
    { /* sentinel */ } 
}; 

static const struct iio_info fake_iio_info = { 
   .read_raw = fake_read_raw, 
   .write_raw        = fake_write_raw, 
   .driver_module = THIS_MODULE, 
}; 

static int my_pdrv_probe (struct platform_device *pdev) 
{ 
    struct iio_dev *indio_dev; 
    struct my_private_data *data; 

   indio_dev = devm_iio_device_alloc(&pdev->dev, sizeof(*data)); 
   if (!indio_dev) { 
         dev_err(&pdev->dev, "iio allocation failed!\n"); 
         return -ENOMEM; 
   } 

   data = iio_priv(indio_dev); 
   mutex_init(&data->lock); 
   indio_dev->dev.parent = &pdev->dev; 
   indio_dev->info = &fake_iio_info; 
   indio_dev->name = KBUILD_MODNAME; 
   indio_dev->modes = INDIO_DIRECT_MODE; 
   indio_dev->channels = fake_channels; 
   indio_dev->num_channels = ARRAY_SIZE(fake_channels); 
   indio_dev->available_scan_masks = 0xF; 

    iio_device_register(indio_dev); 
    platform_set_drvdata(pdev, indio_dev); 
    return 0; 
} 

static void my_pdrv_remove(struct platform_device *pdev) 
{ 
    struct iio_dev *indio_dev = platform_get_drvdata(pdev); 
    iio_device_unregister(indio_dev); 
} 

static struct platform_driver mypdrv = { 
    .probe      = my_pdrv_probe, 
    .remove     = my_pdrv_remove, 
    .driver     = { 
        .name     = "iio-dummy-random", 
        .of_match_table = of_match_ptr(iio_dummy_ids),   
        .owner    = THIS_MODULE, 
    }, 
}; 
module_platform_driver(mypdrv); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

加载上述模块后，我们将得到以下输出，显示我们的设备确实对应于我们注册的平台设备：

```
~# ls -l /sys/bus/iio/devices/

lrwxrwxrwx 1 root root 0 Jul 31 20:26 iio:device0 -> ../../../devices/platform/iio-dummy-random.0/iio:device0

lrwxrwxrwx 1 root root 0 Jul 31 20:23 iio_sysfs_trigger -> ../../../devices/iio_sysfs_trigger

```

以下清单显示了此设备具有的通道及其名称，这些名称与驱动程序中描述的完全相对应：

```
~# ls /sys/bus/iio/devices/iio\:device0/

dev in_voltage2_raw name uevent

in_voltage0_raw in_voltage3_raw power

in_voltage1_raw in_voltage_scale subsystem

~# cat /sys/bus/iio/devices/iio:device0/name

iio_dummy_random

```

# 触发缓冲区支持

在许多数据分析应用程序中，根据某些外部信号（触发器）捕获数据是有用的。这些触发器可能是：

+   数据准备信号

+   连接到某些外部系统的 IRQ 线（GPIO 或其他）

+   处理器周期性中断

+   用户空间读/写 sysfs 中的特定文件

IIO 设备驱动程序与触发器完全无关。触发器可以初始化一个或多个设备上的数据捕获。这些触发器用于填充缓冲区，向用户空间公开为字符设备。

可以开发自己的触发器驱动程序，但这超出了本书的范围。我们将尝试仅专注于现有的触发器。这些是：

+   `iio-trig-interrupt`：这提供了使用任何 IRQ 作为 IIO 触发器的支持。在旧的内核版本中，它曾经是`iio-trig-gpio`。启用此触发模式的内核选项是`CONFIG_IIO_INTERRUPT_TRIGGER`。如果构建为模块，该模块将被称为`iio-trig-interrupt`。

+   `iio-trig-hrtimer`：这提供了使用 HRT 作为中断源的基于频率的 IIO 触发器（自内核 v4.5 以来）。在较旧的内核版本中，它曾经是`iio-trig-rtc`。负责此触发模式的内核选项是`IIO_HRTIMER_TRIGGER`。如果作为模块构建，该模块将被称为`iio-trig-hrtimer`。

+   `iio-trig-sysfs`：这允许我们使用 sysfs 条目触发数据捕获。 `CONFIG_IIO_SYSFS_TRIGGER`是内核选项，用于添加对此触发模式的支持。

+   `iio-trig-bfin-timer`：这允许我们将黑脸定时器用作 IIO 触发器（仍在暂存中）。

IIO 公开 API，以便我们可以：

+   声明任意数量的触发器

+   选择哪些通道的数据将被推送到缓冲区

当您的 IIO 设备提供触发缓冲区的支持时，必须设置`iio_dev.pollfunc`，当触发器触发时执行。此处理程序负责通过`indio_dev->active_scan_mask`找到已启用的通道，检索其数据，并使用`iio_push_to_buffers_with_timestamp`函数将其馈送到`indio_dev->buffer`中。因此，在 IIO 子系统中，缓冲区和触发器是非常相关的。

IIO 核心提供了一组辅助函数，用于设置触发缓冲区，可以在`drivers/iio/industrialio-triggered-buffer.c`中找到。

以下是支持从驱动程序内部支持触发缓冲区的步骤：

1.  如果需要，填写`iio_buffer_setup_ops`结构：

```
const struct iio_buffer_setup_ops sensor_buffer_setup_ops = { 
  .preenable    = my_sensor_buffer_preenable, 
  .postenable   = my_sensor_buffer_postenable, 
  .postdisable  = my_sensor_buffer_postdisable, 
  .predisable   = my_sensor_buffer_predisable, 
}; 
```

1.  编写与触发器相关联的上半部分。在 99%的情况下，只需提供与捕获相关的时间戳：

```
irqreturn_t sensor_iio_pollfunc(int irq, void *p) 
{ 
    pf->timestamp = iio_get_time_ns((struct indio_dev *)p); 
    return IRQ_WAKE_THREAD; 
} 
```

1.  编写触发器的下半部分，它将从每个启用的通道中获取数据，并将其馈送到缓冲区中：

```
irqreturn_t sensor_trigger_handler(int irq, void *p) 
{ 
    u16 buf[8]; 
    int bit, i = 0; 
    struct iio_poll_func *pf = p; 
    struct iio_dev *indio_dev = pf->indio_dev; 

    /* one can use lock here to protect the buffer */ 
    /* mutex_lock(&my_mutex); */ 

    /* read data for each active channel */ 
    for_each_set_bit(bit, indio_dev->active_scan_mask, 
                     indio_dev->masklength) 
        buf[i++] = sensor_get_data(bit) 

    /* 
     * If iio_dev.scan_timestamp = true, the capture timestamp 
     * will be pushed and stored too, as the last element in the 
     * sample data buffer before pushing it to the device buffers. 
     */ 
    iio_push_to_buffers_with_timestamp(indio_dev, buf, timestamp); 

    /* Please unlock any lock */ 
    /* mutex_unlock(&my_mutex); */ 

    /* Notify trigger */ 
    iio_trigger_notify_done(indio_dev->trig); 
    return IRQ_HANDLED; 
} 
```

1.  最后，在`probe`函数中，必须在使用`iio_device_register()`注册设备之前设置缓冲区本身：

```
iio_triggered_buffer_setup(indio_dev, sensor_iio_polfunc, 
                           sensor_trigger_handler, 
                           sensor_buffer_setup_ops); 
```

这里的魔术函数是`iio_triggered_buffer_setup`。这也将为您的设备提供`INDIO_DIRECT_MODE`功能。当从用户空间给您的设备触发器时，您无法知道何时会触发捕获。

在连续缓冲捕获处于活动状态时，应该防止（通过返回错误）驱动程序执行 sysfs 每通道数据捕获（由`read_raw()`挂钩执行），以避免未确定的行为，因为触发处理程序和`read_raw()`挂钩将尝试同时访问设备。用于检查是否实际使用了缓冲模式的函数是`iio_buffer_enabled()`。挂钩将如下所示：

```
static int my_read_raw(struct iio_dev *indio_dev, 
                     const struct iio_chan_spec *chan, 
                     int *val, int *val2, long mask) 
{ 
      [...] 
      switch (mask) { 
      case IIO_CHAN_INFO_RAW: 
            if (iio_buffer_enabled(indio_dev)) 
                  return -EBUSY; 
      [...]        
}  
```

`iio_buffer_enabled()`函数只是测试给定 IIO 设备是否启用了缓冲区。

让我们描述一些在前面部分中使用的重要内容：

+   `iio_buffer_setup_ops`提供了在缓冲区配置序列的固定步骤（启用/禁用之前/之后）调用的缓冲区设置函数。如果未指定，默认的`iio_triggered_buffer_setup_ops`将由 IIO 核心提供给您的设备。

+   `sensor_iio_pollfunc`是触发器的顶半部分。与每个顶半部分一样，它在中断上下文中运行，并且必须尽可能少地进行处理。在 99%的情况下，您只需提供与捕获���关的时间戳。再次，可以使用默认的 IIO `iio_pollfunc_store_time`函数。

+   `sensor_trigger_handler`是底半部分，它在内核线程中运行，允许我们进行任何处理，甚至包括获取互斥锁或休眠。重要的处理应该在这里进行。它通常从设备中读取数据，并将其与顶半部分记录的时间戳一起存储在内部缓冲区中，并将其推送到您的 IIO 设备缓冲区中。

触发器对于触发缓冲是强制性的。它告诉驱动程序何时从设备中读取样本并将其放入缓冲区中。触发缓冲对于编写 IIO 设备驱动程序并非强制性。人们也可以通过 sysfs 进行单次捕获，方法是读取通道的原始属性，这将仅执行单次转换（对于正在读取的通道属性）。缓冲模式允许连续转换，因此可以在一次触发中捕获多个通道。

# IIO 触发器和 sysfs（用户空间）

sysfs 中与触发器相关的两个位置：

+   `/sys/bus/iio/devices/triggerY/`一旦 IIO 触发器与 IIO 核心注册并对应于索引`Y`的触发器，将创建至少一个目录属性：

+   `name`是触发器名称，稍后可以用于与设备关联

+   如果您的设备支持触发缓冲区，则将自动创建`/sys/bus/iio/devices/iio:deviceX/trigger/*`目录。可以通过将触发器的名称写入`current_trigger`文件来将触发器与我们的设备关联。

# Sysfs 触发器接口

通过`CONFIG_IIO_SYSFS_TRIGGER=y`配置选项在内核中启用 sysfs 触发器，将自动创建`/sys/bus/iio/devices/iio_sysfs_trigger/`文件夹，并可用于 sysfs 触发器管理。目录中将有两个文件，`add_trigger`和`remove_trigger`。其驱动程序位于`drivers/iio/trigger/iio-trig-sysfs.c`中。

# add_trigger 文件

用于创建新的 sysfs 触发器。可以通过将正值（将用作触发器 ID）写入该文件来创建新的触发器。它将创建新的 sysfs 触发器，可在`/sys/bus/iio/devices/triggerX`访问，其中`X`是触发器编号。

例如：

```
 # echo 2 > add_trigger

```

这将创建一个新的 sysfs 触发器，可在`/sys/bus/iio/devices/trigger2`访问。如果系统中已经存在指定 ID 的触发器，则会返回无效参数消息。sysfs 触发器名称模式为`sysfstrig{ID}`。命令`echo 2 > add_trigger`将创建触发器`/sys/bus/iio/devices/trigger2`，其名称为`sysfstrig2`：

```
 $ cat /sys/bus/iio/devices/trigger2/name

 sysfstrig2

```

每个 sysfs 触发器至少包含一个文件：`trigger_now`。将`1`写入该文件将指示所有具有其`current_trigger`中相应触发器名称的设备开始捕获，并将数据推送到各自的缓冲区中。每个设备缓冲区必须设置其大小，并且必须启用（`echo 1 > /sys/bus/iio/devices/iio:deviceX/buffer/enable`）。

# remove_trigger 文件

要删除触发器，使用以下命令：

```
 # echo 2 > remove_trigger

```

# 将设备与触发器绑定

将设备与给定触发器关联包括将触发器的名称写入设备触发器目录下的`current_trigger`文件。例如，假设我们需要将设备与索引为 2 的触发器绑定：

```
# set trigger2 as current trigger for device0
# echo sysfstrig2 >    /sys/bus/iio/devices/iio:device0/trigger/current_trigger 

```

要将触发器与设备分离，应将空字符串写入设备触发器目录的`current_trigger`文件，如下所示：

```
# echo "" > iio:device0/trigger/current_trigger 

```

在本章中，我们将进一步看到有关数据捕获的 sysfs 触发器的实际示例。

# 中断触发器接口

考虑以下示例：

```
static struct resource iio_irq_trigger_resources[] = { 
    [0] = { 
        .start = IRQ_NR_FOR_YOUR_IRQ, 
        .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_LOWEDGE, 
    }, 
}; 

static struct platform_device iio_irq_trigger = { 
    .name = "iio_interrupt_trigger", 
    .num_resources = ARRAY_SIZE(iio_irq_trigger_resources), 
    .resource = iio_irq_trigger_resources, 
}; 
platform_device_register(&iio_irq_trigger); 
```

声明我们的 IRQ 触发器，将导致加载 IRQ 触发器独立模块。如果其`probe`函数成功，将会有一个与触发器对应的目录。IRQ 触发器名称的形式为`irqtrigX`，其中`X`对应于您刚刚传递的虚拟 IRQ，在`/proc/interrupt`中可以看到。

```
 $ cd /sys/bus/iio/devices/trigger0/
 $ cat name

```

`irqtrig85`：与其他触发器一样，您只需将该触发器分配给您的设备，方法是将其名称写入设备的`current_trigger`文件中。

```
# echo "irqtrig85" > /sys/bus/iio/devices/iio:device0/trigger/current_trigger

```

现在，每次触发中断时，设备数据将被捕获。

IRQ 触发器驱动程序尚不支持 DT，这就是为什么我们使用了我们的板`init`文件的原因。但这并不重要；由于驱动程序需要资源，因此我们可以在不进行任何代码更改的情况下使用 DT。

以下是声明 IRQ 触发接口的设备树节点示例：

```
mylabel: my_trigger@0{ 
    compatible = "iio_interrupt_trigger"; 
    interrupt-parent = <&gpio4>; 
    interrupts = <30 0x0>; 
}; 
```

该示例假设 IRQ 线是属于 GPIO 控制器节点`gpio4`的 GPIO＃30。这包括使用 GPIO 作为中断源，因此每当 GPIO 变为给定状态时，中断就会被触发，从而触发捕获。

# hrtimer 触发接口

`hrtimer`触发器依赖于 configfs 文件系统（请参阅内核源中的*Documentation/iio/iio_configfs.txt*），可以通过`CONFIG_IIO_CONFIGFS`配置选项启用，并挂载到我们的系统上（通常在`/config`目录下）：

```
 # mkdir /config

  # mount -t configfs none /config

```

现在，加载模块`iio-trig-hrtimer`将创建可在`/config/iio`下访问的 IIO 组，允许用户在`/config/iio/triggers/hrtimer`下创建 hrtimer 触发器。

例如：

```
 # create a hrtimer trigger
  $ mkdir /config/iio/triggers/hrtimer/my_trigger_name
  # remove the trigger
  $ rmdir /config/iio/triggers/hrtimer/my_trigger_name 

```

每个 hrtimer 触发器在触发目录中包含一个单独的`sampling_frequency`属性。在本章的*使用 hrtimer 触发进行数据捕获*部分中提供了一个完整且可用的示例。

# IIO 缓冲区

IIO 缓冲区提供连续数据捕获，可以同时读取多个数据通道。缓冲区可通过`/dev/iio:device`字符设备节点从用户空间访问。在触发处理程序中，用于填充缓冲区的函数是`iio_push_to_buffers_with_timestamp`。为设备分配触发缓冲区的函数是`iio_triggered_buffer_setup()`。

# IIO 缓冲区 sysfs 接口

IIO 缓冲区在`/sys/bus/iio/iio:deviceX/buffer/*`下有一个关联的属性目录。以下是一些现有属性：

+   `length`：缓冲区可以存储的数据样本（容量）的总数。这是缓冲区包含的扫描数。

+   `enable`：这将激活缓冲区捕获，启动缓冲区捕获。

+   `watermark`：此属性自内核版本 v4.2 起可用。它是一个正数，指定阻塞读取应等待多少个扫描元素。例如，如果使用`poll`，它将阻塞直到达到水印。只有在水印大于请求的读取量时才有意义。它不影响非阻塞读取。可以在带有超时的 poll 上阻塞，并在超时到期后读取可用样本，从而保证最大延迟。

# IIO 缓冲区设置

要读取并推送到缓冲区的数据通道称为扫描元素。它们的配置可通过`/sys/bus/iio/iio:deviceX/scan_elements/*`目录从用户空间访��，包含以下属性：

+   `en`（实际上是属性名称的后缀）用于启用通道。仅当其属性非零时，触发捕获才会包含此通道的数据样本。例如，`in_voltage0_en`，`in_voltage1_en`等。

+   `type`描述了缓冲区内的扫描元素数据存储方式，因此也描述了从用户空间读取的形式。例如，`in_voltage0_type`。格式为`[be|le]:[s|u]bits/storagebitsXrepeat[>>shift]`。

+   `be`或`le`指定字节顺序（大端或小端）。

+   `s`或`u`指定符号，即有符号（2 的补码）或无符号。

+   `bits`是有效数据位数。

+   `storagebits`是该通道在缓冲区中占用的位数。也就是说，一个值可能实际上是用 12 位编码（**bits**），但在缓冲区中占用 16 位（**storagebits**）。因此，必须将数据向右移动四次才能获得实际值。此参数取决于设备，应参考其数据表。

+   `shift`表示在屏蔽未使用的位之前应移动数据值的次数。此参数并非总是需要的。如果有效位数（**bits**）等于存储位数，则移位将为 0。也可以在设备数据表中找到此参数。

+   `repeat`指定位/存储位重复的次数。当重复元素为 0 或 1 时，重复值被省略。

解释这一部分的最佳方法是通过内核文档的摘录，可以在这里找到：[`www.kernel.org/doc/html/latest/driver-api/iio/buffers.html`](https://www.kernel.org/doc/html/latest/driver-api/iio/buffers.html)。例如，一个具有 12 位分辨率的 3 轴加速度计的驱动程序，其中数据存储在两个 8 位寄存器中，如下所示：

```
      7   6   5   4   3   2   1   0 
    +---+---+---+---+---+---+---+---+ 
    |D3 |D2 |D1 |D0 | X | X | X | X | (LOW byte, address 0x06) 
    +---+---+---+---+---+---+---+---+ 
      7   6   5   4   3   2   1   0 
    +---+---+---+---+---+---+---+---+ 
    |D11|D10|D9 |D8 |D7 |D6 |D5 |D4 | (HIGH byte, address 0x07) 
    +---+---+---+---+---+---+---+---+ 
```

每个轴将具有以下扫描元素类型：

```
 $ cat /sys/bus/iio/devices/iio:device0/scan_elements/in_accel_y_type
 le:s12/16>>4

```

应该将其解释为小端符号数据，16 位大小，需要在屏蔽掉 12 个有效数据位之前向右移 4 位。

`struct iio_chan_spec`中负责确定通道值如何存储到缓冲区的元素是`scant_type`。

```
struct iio_chan_spec { 
        [...] 
        struct { 
            char sign; /* Should be 'u' or 's' as explained above */ 
            u8 realbits; 
            u8 storagebits; 
            u8 shift; 
            u8 repeat; 
            enum iio_endian endianness; 
        } scan_type; 
        [...] 
}; 
```

这个结构绝对匹配`[be|le]:[s|u]bits/storagebitsXrepeat[>>shift]`，这是前一节中描述的模式。让我们来看看结构的每个成员：

+   `sign`表示数据的符号，并匹配模式中的`[s|u]`。

+   `realbits`对应于模式中的`bits`

+   `storagebits`与模式中的相同名称匹配

+   `shift`对应于模式中的 shift，`repeat`也是一样的

+   `iio_indian`表示字节序，与模式中的`[be|le]`匹配

此时，可以编写与先前解释的类型相对应的 IIO 通道结构：

```
struct struct iio_chan_spec accel_channels[] = { 
        { 
                .type = IIO_ACCEL, 
                .modified = 1, 
                .channel2 = IIO_MOD_X, 
                /* other stuff here */ 
                .scan_index = 0, 
                .scan_type = { 
                        .sign = 's', 
                        .realbits = 12, 
                        .storagebits = 16, 
                        .shift = 4, 
                        .endianness = IIO_LE, 
                }, 
        } 
      /* similar for Y (with channel2 = IIO_MOD_Y, scan_index = 1) 
       * and Z (with channel2 = IIO_MOD_Z, scan_index = 2) axis 
       */ 
} 
```

# 把所有东西放在一起

让我们更仔细地看一下 BOSH 的数字三轴加速度传感器 BMA220。这是一个 SPI/I2C 兼容设备，具有 8 位大小的寄存器，以及一个片上运动触发中断控制器，实际上可以感应倾斜、运动和冲击振动��其数据表可在以下网址找到：[`www.mouser.fr/pdfdocs/BSTBMA220DS00308.PDF`](http://www.mouser.fr/pdfdocs/BSTBMA220DS00308.PDF)，其驱动程序自内核 v4.8 以来已经被引入（`CONFIG_BMA200`）。让我们来看一下：

首先，我们使用`struct iio_chan_spec`声明我们的 IIO 通道。一旦触发缓冲区被使用，我们需要填充`.scan_index`和`.scan_type`字段：

```
#define BMA220_DATA_SHIFT 2 
#define BMA220_DEVICE_NAME "bma220" 
#define BMA220_SCALE_AVAILABLE "0.623 1.248 2.491 4.983" 

#define BMA220_ACCEL_CHANNEL(index, reg, axis) {           \ 
   .type = IIO_ACCEL,                                      \ 
   .address = reg,                                         \ 
   .modified = 1,                                          \ 
   .channel2 = IIO_MOD_##axis,                             \ 
   .info_mask_separate = BIT(IIO_CHAN_INFO_RAW),           \ 
   .info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE),   \ 
   .scan_index = index,                                    \ 
   .scan_type = {                                          \ 
         .sign = 's',                                      \ 
         .realbits = 6,                                    \ 
         .storagebits = 8,                                 \ 
         .shift = BMA220_DATA_SHIFT,                       \ 
         .endianness = IIO_CPU,                            \ 
   },                                                      \ 
} 

static const struct iio_chan_spec bma220_channels[] = { 
   BMA220_ACCEL_CHANNEL(0, BMA220_REG_ACCEL_X, X), 
   BMA220_ACCEL_CHANNEL(1, BMA220_REG_ACCEL_Y, Y), 
   BMA220_ACCEL_CHANNEL(2, BMA220_REG_ACCEL_Z, Z), 
}; 
```

`.info_mask_separate = BIT(IIO_CHAN_INFO_RAW)`表示每个通道将有一个`*_raw` sysfs 条目（属性），`.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE)`表示所有相同类型的通道只有一个`*_scale` sysfs 条目：

```
    jma@jma:~$ ls -l /sys/bus/iio/devices/iio:device0/

(...)

# without modifier, a channel name would have in_accel_raw (bad)

-rw-r--r-- 1 root root 4096 jul 20 14:13 in_accel_scale

-rw-r--r-- 1 root root 4096 jul 20 14:13 in_accel_x_raw

-rw-r--r-- 1 root root 4096 jul 20 14:13 in_accel_y_raw

-rw-r--r-- 1 root root 4096 jul 20 14:13 in_accel_z_raw

(...)

```

读取`in_accel_scale`调用`read_raw()`钩子，将 mask 设置为`IIO_CHAN_INFO_SCALE`。读取`in_accel_x_raw`调用`read_raw()`钩子，将 mask 设置为`IIO_CHAN_INFO_RAW`。因此，真实值是`raw_value * scale`。

`.scan_type`表示每个通道返回的值是 8 位大小（将占用缓冲区中的 8 位），但有用的有效载荷只占用 6 位，并且数据必须在屏蔽未使用的位之前右移 2 次。任何扫描元素类型都将如下所示：

```
$ cat /sys/bus/iio/devices/iio:device0/scan_elements/in_accel_x_type

le:s6/8>>2 

```

以下是我们的`pollfunc`（实际上是底部），它从设备中读取样本并将读取的值推送到缓冲区（`iio_push_to_buffers_with_timestamp()`）。完成后，我们通知核心（`iio_trigger_notify_done()`）：

```
static irqreturn_t bma220_trigger_handler(int irq, void *p) 
{ 
   int ret; 
   struct iio_poll_func *pf = p; 
   struct iio_dev *indio_dev = pf->indio_dev; 
   struct bma220_data *data = iio_priv(indio_dev); 
   struct spi_device *spi = data->spi_device; 

   mutex_lock(&data->lock); 
   data->tx_buf[0] = BMA220_REG_ACCEL_X | BMA220_READ_MASK; 
   ret = spi_write_then_read(spi, data->tx_buf, 1, data->buffer, 
                       ARRAY_SIZE(bma220_channels) - 1); 
   if (ret < 0) 
         goto err; 

   iio_push_to_buffers_with_timestamp(indio_dev, data->buffer, 
                              pf->timestamp); 
err: 
   mutex_unlock(&data->lock); 
   iio_trigger_notify_done(indio_dev->trig); 

   return IRQ_HANDLED; 
} 
```

以下是`read`函数。这是一个钩子，每次读取设备的 sysfs 条目时都会调用它：

```
static int bma220_read_raw(struct iio_dev *indio_dev, 
                  struct iio_chan_spec const *chan, 
                  int *val, int *val2, long mask) 
{ 
   int ret; 
   u8 range_idx; 
   struct bma220_data *data = iio_priv(indio_dev); 

   switch (mask) { 
   case IIO_CHAN_INFO_RAW: 
           /* If buffer mode enabled, do not process single-channel read */ 
           if (iio_buffer_enabled(indio_dev)) 
                   return -EBUSY; 
           /* Else we read the channel */ 
           ret = bma220_read_reg(data->spi_device, chan->address); 
           if (ret < 0) 
                   return -EINVAL; 
           *val = sign_extend32(ret >> BMA220_DATA_SHIFT, 5); 
           return IIO_VAL_INT; 
   case IIO_CHAN_INFO_SCALE: 
           ret = bma220_read_reg(data->spi_device, BMA220_REG_RANGE); 
           if (ret < 0) 
                   return ret; 
           range_idx = ret & BMA220_RANGE_MASK; 
           *val = bma220_scale_table[range_idx][0]; 
           *val2 = bma220_scale_table[range_idx][1]; 
           return IIO_VAL_INT_PLUS_MICRO; 
   } 

   return -EINVAL; 
} 
```

当读取`*raw` sysfs 文件时，将调用该钩子，`mask`参数中给出`IIO_CHAN_INFO_RAW`，并且`*val`和`val2`实际上是输出参数。它们必须设置为原始值（从设备中读取）。对`*scale` sysfs 文件的任何读取都将调用带有`IIO_CHAN_INFO_SCALE`的`mask`参数的钩子，以及每个属性掩码。

这也适用于`write`函数，用于将值写入设备。你的驱动程序有 80%的可能不需要`write`函数。这个`write`钩子允许用户更改设备的比例：

```
static int bma220_write_raw(struct iio_dev *indio_dev, 
                   struct iio_chan_spec const *chan, 
                   int val, int val2, long mask) 
{ 
   int i; 
   int ret; 
   int index = -1; 
   struct bma220_data *data = iio_priv(indio_dev); 

   switch (mask) { 
   case IIO_CHAN_INFO_SCALE: 
         for (i = 0; i < ARRAY_SIZE(bma220_scale_table); i++) 
               if (val == bma220_scale_table[i][0] && 
                   val2 == bma220_scale_table[i][1]) { 
                     index = i; 
                     break; 
               } 
         if (index < 0) 
               return -EINVAL; 

         mutex_lock(&data->lock); 
         data->tx_buf[0] = BMA220_REG_RANGE; 
         data->tx_buf[1] = index; 
         ret = spi_write(data->spi_device, data->tx_buf, 
                     sizeof(data->tx_buf)); 
         if (ret < 0) 
               dev_err(&data->spi_device->dev, 
                     "failed to set measurement range\n"); 
         mutex_unlock(&data->lock); 

         return 0; 
   } 

   return -EINVAL; 
} 
```

每当写入设备时，都会调用此函数。经常更改的参数是比例。例如：`echo <desired-scale> > /sys/bus/iio/devices/iio;devices0/in_accel_scale`。

现在，要填写一个`struct iio_info`结构，以提供给我们的`iio_device`：

```
static const struct iio_info bma220_info = { 
   .driver_module    = THIS_MODULE, 
   .read_raw         = bma220_read_raw, 
   .write_raw        = bma220_write_raw, /* Only if your driver need it */ 
}; 
```

在`probe`函数中，我们分配并设置了一个`struct iio_dev` IIO 设备。私有数据的内存也被保留：

```
/* 
 * We provide only two mask possibility, allowing to select none or every 
 * channels. 
 */ 
static const unsigned long bma220_accel_scan_masks[] = { 
   BIT(AXIS_X) | BIT(AXIS_Y) | BIT(AXIS_Z), 
   0 
}; 

static int bma220_probe(struct spi_device *spi) 
{ 
   int ret; 
   struct iio_dev *indio_dev; 
   struct bma220_data *data; 

   indio_dev = devm_iio_device_alloc(&spi->dev, sizeof(*data)); 
   if (!indio_dev) { 
         dev_err(&spi->dev, "iio allocation failed!\n"); 
         return -ENOMEM; 
   } 

   data = iio_priv(indio_dev); 
   data->spi_device = spi; 
   spi_set_drvdata(spi, indio_dev); 
   mutex_init(&data->lock); 

   indio_dev->dev.parent = &spi->dev; 
   indio_dev->info = &bma220_info; 
   indio_dev->name = BMA220_DEVICE_NAME; 
   indio_dev->modes = INDIO_DIRECT_MODE; 
   indio_dev->channels = bma220_channels; 
   indio_dev->num_channels = ARRAY_SIZE(bma220_channels); 
   indio_dev->available_scan_masks = bma220_accel_scan_masks; 

   ret = bma220_init(data->spi_device); 
   if (ret < 0) 
         return ret; 

   /* this call will enable trigger buffer support for the device */ 
   ret = iio_triggered_buffer_setup(indio_dev, iio_pollfunc_store_time, 
                            bma220_trigger_handler, NULL); 
   if (ret < 0) { 
         dev_err(&spi->dev, "iio triggered buffer setup failed\n"); 
         goto err_suspend; 
   } 

   ret = iio_device_register(indio_dev); 
   if (ret < 0) { 
         dev_err(&spi->dev, "iio_device_register failed\n"); 
         iio_triggered_buffer_cleanup(indio_dev); 
         goto err_suspend; 
   } 

   return 0; 

err_suspend: 
   return bma220_deinit(spi); 
} 
```

可以通过`CONFIG_BMA220`内核选项启用此驱动程序。也就是说，这仅在内核 v4.8 及以后版本中可用。在旧版本的内核中，可以使用`CONFIG_BMA180`选项启用最接近的设备。

# IIO 数据访问

您可能已经猜到，使用 IIO 框架访问数据只有两种方式；通过 sysfs 通道进行一次性捕获，或通过 IIO 字符设备进行连续模式（触发缓冲区）。

# 一次性捕获

一次性数据捕获是通过 sysfs 接口完成的。通过读取与通道对应的 sysfs 条目，您将仅捕获与该通道特定的数据。假设有一个具有两个通道的温度传感器：一个用于环境温度，另一个用于热电偶温度：

```
 # cd /sys/bus/iio/devices/iio:device0
  # cat in_voltage3_raw
  6646

 # cat in_voltage_scale
  0.305175781

```

通过将比例乘以原始值来获得处理后的值。

`电压值`：`6646 * 0.305175781 = 2028.19824053`

设备数据表说明处理值以 MV 为单位。在我们的情况下，它对应于 2.02819V。

# 缓冲区数据访问

要使触发采集工作，触发支持必须已经在您的驱动程序中实现。然后，要从用户空间获取数据，必须：创建触发器，分配它，启用 ADC 通道，设置缓冲区的维度，并启用它）。以下是此代码：

# 使用 sysfs 触发器进行捕获

使用 sysfs 触发器捕获数据包括发送一组命令到 sysfs 文件。让我们列举一下我们应该做什么来实现这一点：

1.  **创建触发器**：在触发器可以分配给任何设备之前，它应该被创建：

```
 #

 echo 0 > /sys/devices/iio_sysfs_trigger/add_trigger

```

在这里，`0`对应于我们需要分配给触发器的索引。在此命令之后，触发器目录将在`*/sys/bus/iio/devices/*`下作为`trigger0`可用。

1.  **将触发器分配给设备**：触发器通过其名称唯一标识，我们可以使用它来将设备与触发器绑定。由于我们使用 0 作为索引，触发器将被命名为`sysfstrig0`：

```
# echo sysfstrig0 > /sys/bus/iio/devices/iio:device0/trigger/current_trigger

```

我们也可以使用这个命令：`cat /sys/bus/iio/devices/trigger0/name > /sys/bus/iio/devices/iio:device0/trigger/current_trigger`。也就是说，如果我们写入的值与现有的触发器名称不对应，什么也不会发生。为了确保我们真的定义了一个触发器，我们可以使用`cat /sys/bus/iio/devices/iio:device0/trigger/current_trigger`。

1.  **启用一些扫描元素**：这一步包括选择哪些通道的数据值应该被推送到缓冲区中。在驱动程序中应该注意`available_scan_masks`：

```
 # echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage4_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage5_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage6_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage7_en

```

1.  **设置缓冲区大小**：在这里，应该设置缓冲区可以容纳的样本集的数量：

```
 #

 echo 100 > /sys/bus/iio/devices/iio:device0/buffer/length

```

1.  **启用缓冲区**：这一步包括将缓冲区标记为准备好接收推送数据：

```
 #

 echo 1 > /sys/bus/iio/devices/iio:device0/buffer/enable

```

要停止捕获，我们必须在同一文件中写入 0。

1.  **触发**：启动采集：

```
 #

 echo 1 > /sys/bus/iio/devices/trigger0/trigger_now

```

现在采集完成了，我们可以：

1.  禁用缓冲区：

```
 #

 echo 0 > /sys/bus/iio/devices/iio:device0/buffer/enable

```

1.  分离触发器：

```
 #

 echo "" > /sys/bus/iio/devices/iio:device0/trigger/current_trigger

```

1.  转储我们的 IIO 字符设备的内容：

```
 #

 cat /dev/iio\:device0 | xxd -

```

# 使用 hrtimer 触发进行捕获

以下是一组命令，允许使用 hrtimer 触发来捕获数据：

```
 # echo /sys/kernel/config/iio/triggers/hrtimer/trigger0

 #

 echo 50 > /sys/bus/iio/devices/trigger0/sampling_frequency

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage4_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage5_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage6_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage7_en

 #

 echo 1 > /sys/bus/iio/devices/iio:device0/buffer/enable

 #

 cat /dev/iio:device0 | xxd -

 0000000: 0188 1a30 0000 0000 8312 68a8 c24f 5a14 ...0......h..OZ.

  0000010: 0188 1a30 0000 0000 192d 98a9 c24f 5a14 ...0.....-...OZ.

  [...] 

```

并且，我们查看类型以确定如何处理数据：

```
$ cat /sys/bus/iio/devices/iio:device0/scan_elements/in_voltage_type

be:s14/16>>2

```

电压处理：`0x188 >> 2 = 98 * 250 = 24500 = 24.5 v`

# IIO 工具

有一些有用的工具可以帮助您简化和加快使用 IIO 设备开发应用程序的过程。它们在内核树中的`tools/iio`中可用：

+   `lsiio.c` **：** 枚举 IIO 触发器、设备和通道

+   `iio_event_monitor.c`：监视 IIO 设备的 ioctl 接口以获取 IIO 事件

+   `generic_buffer.c`：从 IIO 设备的缓冲区中检索、处理和打印数据

+   `libiio`：由模拟设备开发的强大库，用于与 IIO 设备进行接口交互，可在[`github.com/analogdevicesinc/libiio`](https://github.com/analogdevicesinc/libiio)上获得。

# 摘要

到本章结束时，您应该已经熟悉了 IIO 框架和词汇。您知道通道、设备和触发器是什么。您甚至可以通过用户空间、sysfs 或字符设备与您的 IIO 设备进行交互。现在是编写自己的 IIO 驱动程序的时候了。有很多现有的驱动程序不支持触发缓冲区。您可以尝试在其中一个驱动程序中添加这样的功能。在下一章中，我们将使用系统上最有用/最常用的资源：内存。要坚强，游戏刚刚开始。
