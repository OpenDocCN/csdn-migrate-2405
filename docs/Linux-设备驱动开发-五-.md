# Linux 设备驱动开发（五）

> 原文：[`zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E`](https://zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：Linux 设备模型

直到 2.5 版本，内核没有描述和管理对象的方法，代码的可重用性也不像现在这样增强。换句话说，没有设备拓扑结构，也没有组织。没有关于子系统关系或系统如何组合的信息。然后**Linux 设备模型**（**LDM**）出现了，引入了：

+   类的概念，用于将相同类型的设备或公开相同功能的设备（例如，鼠标和键盘都是输入设备）分组。

+   通过名为`sysfs`的虚拟文件系统与用户空间通信，以便让用户空间管理和枚举设备及其公开的属性。

+   使用引用计数（在受管理资源中大量使用）管理对象生命周期。

+   电源管理，以处理设备应该关闭的顺序。

+   代码的可重用性。类和框架公开接口，行为类似于任何注册的驱动程序必须遵守的合同。

+   LDM 在内核中引入了类似于**面向对象**（**OO**）的编程风格。

在本章中，我们将利用 LDM 并通过`sysfs`文件系统向用户空间导出一些属性。

在本章中，我们将涵盖以下主题：

+   引入 LDM 数据结构（驱动程序，设备，总线）

+   按类型收集内核对象

+   处理内核`sysfs`接口

# LDM 数据结构

目标是构建一个完整的设备树，将系统上存在的每个物理设备映射到其中，并介绍它们的层次结构。已经创建了一个通用结构，用于表示可能是设备模型一部分的任何对象。LDM 的上一级依赖于内核中表示为`struct bus_type`实例的总线；设备驱动程序，表示为`struct device_driver`结构，以及设备，作为`struct device`结构的实例表示的最后一个元素。在本节中，我们将设计一个总线驱动程序包 bus，以深入了解 LDM 数据结构和机制。

# 总线

公共汽车是设备和处理器之间的通道链接。管理总线并向设备导出其协议的硬件实体称为总线控制器。例如，USB 控制器提供 USB 支持。I2C 控制器提供 I2C 总线支持。因此，总线控制器作为一个设备，必须像任何设备一样注册。它将是需要放在总线上的设备的父级。换句话说，每个放在总线上的设备必须将其父字段指向总线设备。总线在内核中由`struct bus_type`结构表示：

```
struct bus_type { 
   const char *name; 
   const char *dev_name; 
   struct device *dev_root; 
   struct device_attribute  *dev_attrs; /* use dev_groups instead */ 
   const struct attribute_group **bus_groups; 
   const struct attribute_group **dev_groups; 
   const struct attribute_group **drv_groups; 

   int (*match)(struct device *dev, struct device_driver *drv); 
   int (*probe)(struct device *dev); 
   int (*remove)(struct device *dev); 
   void (*shutdown)(struct device *dev); 

   int (*suspend)(struct device *dev, pm_message_t state); 
   int (*resume)(struct device *dev); 

   const struct dev_pm_ops *pm; 

   struct subsys_private *p; 
   struct lock_class_key lock_key; 
}; 
```

以下是结构中元素的含义：

+   `match`：这是一个回调，每当新设备或驱动程序添加到总线时都会调用。回调必须足够智能，并且在设备和驱动程序之间存在匹配时应返回非零值，这两者作为参数给出。`match`回调的主要目的是允许总线确定特定设备是否可以由给定驱动程序处理，或者其他逻辑，如果给定驱动程序支持给定设备。大多数情况下，验证是通过简单的字符串比较完成的（设备和驱动程序名称，或表和 DT 兼容属性）。对于枚举设备（PCI，USB），验证是通过比较驱动程序支持的设备 ID 与给定设备的设备 ID 进行的，而不会牺牲总线特定功能。

+   `probe`：这是在匹配发生后，当新设备或驱动程序添加到总线时调用的回调。此函数负责分配特定的总线设备结构，并调用给定驱动程序的`probe`函数，该函数应该管理之前分配的设备。

+   `remove`：当设备从总线中移除时调用此函数。

+   `suspend`：这是一种在总线上的设备需要进入睡眠模式时调用的方法。

+   `resume`：当总线上的设备需要被唤醒时调用此函数。

+   `pm`：这是总线的电源管理操作集，将调用特定设备驱动程序的`pm-ops`。

+   `drv_groups`：这是指向`struct attribute_group`元素列表（数组）的指针，每个元素都指向`struct attribute`元素列表（数组）。它代表总线上设备驱动程序的默认属性。传递给此字段的属性将赋予总线上注册的每个驱动程序。这些属性可以在`/sys/bus/<bus-name>/drivers/<driver-name>`中的驱动程序目录中找到。

+   `dev_groups`：这代表总线上设备的默认属性。通过传递给此字段的`struct attribute_group`元素的列表/数组，将赋予总线上注册的每个设备这些属性。这些属性可以在`/sys/bus/<bus-name>/devices/<device-name>`中的设备目录中找到。

+   `bus_group`：这保存总线注册到核心时自动添加的默认属性集（组）。

除了定义`bus_type`之外，总线控制器驱动程序还必须定义一个特定于总线的驱动程序结构，该结构扩展了通用的`struct device_driver`，以及一个特定于总线的设备结构，该结构扩展了通用的`struct device`结构，都是设备模型核心的一部分。总线驱动程序还必须为探测到的每个物理设备分配一个特定于总线的设备结构，并负责初始化设备的`bus`和`parent`字段，并将设备注册到 LDM 核心。这些字段必须指向总线设备和总线驱动程序中定义的`bus_type`结构。LDM 核心使用这些来构建设备层次结构并初始化其他字段。

在我们的示例中，以下是两个辅助宏，用于获取 packt 设备和 packt 驱动程序，给定通用的`struct device`和`struct driver`：

```
#define to_packt_driver(d) container_of(d, struct packt_driver, driver) 
#define to_packt_device(d) container_of(d, struct packt_device, dev) 
```

然后是用于识别 packt 设备的结构：

```
struct packt_device_id { 
    char name[PACKT_NAME_SIZE]; 
    kernel_ulong_t driver_data;   /* Data private to the driver */ 
}; 
```

以下是 packt 特定的设备和驱动程序结构：

```
/* 
 * Bus specific device structure 
 * This is what a packt device structure looks like 
 */ 
struct packt_device { 
   struct module *owner; 
   unsigned char name[30]; 
   unsigned long price; 
   struct device dev; 
}; 

/* 
 * Bus specific driver structure 
 * This is what a packt driver structure looks like 
 * You should provide your device's probe and remove function. 
 * may be release too 
 */ 
struct packt_driver { 
   int (*probe)(struct packt_device *packt); 
   int (*remove)(struct packt_device *packt); 
   void (*shutdown)(struct packt_device *packt); 
}; 
```

每个总线内部管理两个重要列表；添加到总线上的设备列表和注册到总线上的驱动程序列表。每当添加/注册或移除/注销设备/驱动程序到/从总线时，相应的列表都会更新为新条目。总线驱动程序必须提供辅助函数来注册/注销可以处理该总线上设备的设备驱动程序，以及注册/注销坐在总线上的设备的辅助函数。这些辅助函数始终包装 LDM 核心提供的通用函数，即`driver_register()`，`device_register()`，`driver_unregister`和`device_unregister()`。

```
/* 
 * Now let us write and export symbols that people writing 
 * drivers for packt devices must use. 
 */ 

int packt_register_driver(struct packt_driver *driver) 
{   
   driver->driver.bus = &packt_bus_type; 
   return driver_register(&driver->driver); 
} 
EXPORT_SYMBOL(packt_register_driver); 

void packt_unregister_driver(struct packt_driver *driver) 
{ 
   driver_unregister(&driver->driver); 
} 
EXPORT_SYMBOL(packt_unregister_driver); 

int packt_device_register(struct packt_device *packt) 
{ 
   return device_register(&packt->dev); 
} 
EXPORT_SYMBOL(packt_device_register); 

void packt_unregister_device(struct packt_device *packt) 
{ 
   device_unregister(&packt->dev); 
} 
EXPORT_SYMBOL(packt_device_unregister); 
```

用于分配 packt 设备的函数如下。必须使用此函数来创建总线上任何物理设备的实例：

```
/* 
 * This function allocate a bus specific device structure 
 * One must call packt_device_register to register 
 * the device with the bus 
 */ 
struct packt_device * packt_device_alloc(const char *name, int id) 
{ 
   struct packt_device *packt_dev; 
   int status; 

   packt_dev = kzalloc(sizeof *packt_dev, GFP_KERNEL); 
   if (!packt_dev) 
         return NULL; 

    /* new devices on the bus are son of the bus device */ 
    strcpy(packt_dev->name, name); 
    packt_dev->dev.id = id; 
    dev_dbg(&packt_dev->dev, 
      "device [%s] registered with packt bus\n", packt_dev->name); 

    return packt_dev; 

out_err: 
    dev_err(&adap->dev, "Failed to register packt client %s\n", packt_dev->name); 
    kfree(packt_dev); 
    return NULL; 
} 
EXPORT_SYMBOL_GPL(packt_device_alloc); 

int packt_device_register(struct packt_device *packt) 
{ 
    packt->dev.parent = &packt_bus; 
   packt->dev.bus = &packt_bus_type; 
   return device_register(&packt->dev); 
} 
EXPORT_SYMBOL(packt_device_register); 
```

# 总线注册

总线控制器本身也是一个设备，在 99%的情况下总线是平台设备（即使提供枚举的总线也是如此）。例如，PCI 控制器是一个平台设备，它的相应驱动程序也是如此。必须使用`bus_register(struct *bus_type)`函数来注册总线到内核。packt 总线结构如下：

```
/* 
 * This is our bus structure 
 */ 
struct bus_type packt_bus_type = { 
   .name      = "packt", 
   .match     = packt_device_match, 
   .probe     = packt_device_probe, 
   .remove    = packt_device_remove, 
   .shutdown  = packt_device_shutdown, 
}; 
```

总线控制器本身也是一个设备，它必须在内核中注册，并且将用作总线上设备的父设备。这是在总线控制器的`probe`或`init`函数中完成的。在 packt 总线的情况下，代码如下：

```
/* 
 * Bus device, the master. 
 *  
 */ 
struct device packt_bus = { 
    .release  = packt_bus_release, 
    .parent = NULL, /* Root device, no parent needed */ 
}; 

static int __init packt_init(void) 
{ 
    int status; 
    status = bus_register(&packt_bus_type); 
    if (status < 0) 
        goto err0; 

    status = class_register(&packt_master_class); 
    if (status < 0) 
        goto err1; 

    /* 
     * After this call, the new bus device will appear 
     * under /sys/devices in sysfs. Any devices added to this 
     * bus will shows up under /sys/devices/packt-0/. 
     */ 
    device_register(&packt_bus); 

   return 0; 

err1: 
   bus_unregister(&packt_bus_type); 
err0: 
   return status; 
} 
```

当总线控制器驱动程序注册设备时，设备的父成员必须指向总线控制器设备，其总线属性必须指向总线类型以构建物理 DT。要注册 packt 设备，必须调用`packt_device_register`，并将其分配为`packt_device_alloc`的参数：

```
int packt_device_register(struct packt_device *packt) 
{ 
    packt->dev.parent = &packt_bus; 
   packt->dev.bus = &packt_bus_type; 
   return device_register(&packt->dev); 
} 
EXPORT_SYMBOL(packt_device_register); 
```

# 设备驱动程序

全局设备层次结构允许以通用方式表示系统中的每个设备。这使得核心可以轻松地遍历 DT 以创建诸如适当排序的电源管理转换之类的东西：

```
struct device_driver { 
    const char *name; 
    struct bus_type *bus; 
    struct module *owner; 

    const struct of_device_id   *of_match_table; 
    const struct acpi_device_id  *acpi_match_table; 

    int (*probe) (struct device *dev); 
    int (*remove) (struct device *dev); 
    void (*shutdown) (struct device *dev); 
    int (*suspend) (struct device *dev, pm_message_t state); 
    int (*resume) (struct device *dev); 
    const struct attribute_group **groups; 

    const struct dev_pm_ops *pm; 
}; 
```

`struct device_driver` 定义了一组简单的操作，供核心对每个设备执行这些操作：

+   `* name` 表示驱动程序的名称。它可以通过与设备名称进行比较来进行匹配。

+   `* bus` 表示驱动程序所在的总线。总线驱动程序必须填写此字段。

+   `module` 表示拥有驱动程序的模块。在 99% 的情况下，应将此字段设置为 `THIS_MODULE`。

+   `of_match_table` 是指向 `struct of_device_id` 数组的指针。`struct of_device_id` 结构用于通过称为 DT 的特殊文件执行 OF 匹配，该文件在引导过程中传递给内核：

```
struct of_device_id { 
    char compatible[128]; 
    const void *data; 
}; 
```

+   `suspend` 和 `resume` 回调提供电源管理功能。当设备从系统中物理移除或其引用计数达到 `0` 时，将调用 `remove` 回调。在系统重新启动期间也会调用 `remove` 回调。

+   `probe` 是在尝试将驱动程序绑定到设备时运行的探测回调函数。总线驱动程序负责调用设备驱动程序的 `probe` 函数。

+   `group` 是指向 `struct attribute_group` 列表（数组）的指针，用作驱动程序的默认属性。使用此方法而不是单独创建属性。

# 设备驱动程序注册

`driver_register()` 是用于在总线上注册设备驱动程序的低级函数。它将驱动程序添加到总线的驱动程序列表中。当设备驱动程序与总线注册时，核心会遍历总线的设备列表，并对每个没有与之关联驱动程序的设备调用总线的匹配回调，以找出驱动程序可以处理的设备。

当发生匹配时，设备和设备驱动程序被绑定在一起。将设备与设备驱动程序关联的过程称为绑定。

现在回到使用我们的 packt 总线注册驱动程序，必须使用 `packt_register_driver(struct packt_driver *driver)`，这是对 `driver_register()` 的包装。在注册 packt 驱动程序之前，必须填写 `*driver` 参数。LDM 核心提供了用于遍历已注册到总线的驱动程序列表的辅助函数：

```
int bus_for_each_drv(struct bus_type * bus, 
                struct device_driver * start,  
                void * data, int (*fn)(struct device_driver *, 
                void *)); 
```

此助手遍历总线的驱动程序列表，并对列表中的每个驱动程序调用 `fn` 回调。

# 设备

结构体设备是用于描述和表征系统上每个设备的通用数据结构，无论其是否是物理设备。它包含有关设备的物理属性的详细信息，并提供适当的链接信息以构建合适的设备树和引用计数：

```
struct device { 
    struct device *parent; 
    struct kobject kobj; 
    const struct device_type *type; 
    struct bus_type      *bus; 
    struct device_driver *driver; 
    void    *platform_data; 
    void *driver_data; 
    struct device_node      *of_node; 
    struct class *class; 
    const struct attribute_group **groups; 
    void (*release)(struct device *dev); 
}; 
```

+   `* parent` 表示设备的父级，用于构建设备树层次结构。当与总线注册时，总线驱动程序负责使用总线设备设置此字段。

+   `* bus` 表示设备所在的总线。总线驱动程序必须填写此字段。

+   `* type` 标识设备的类型。

+   `kobj` 是处理引用计数和设备模型支持的 kobject。

+   `* of_node` 是指向与设备关联的 OF（DT）节点的指针。由总线驱动程序设置此字段。

+   `platform_data` 是指向特定于设备的平台数据的指针。通常在设备供应期间在特定于板的文件中声明。

+   `driver_data` 是驱动程序的私有数据的指针。

+   `class` 是指向设备所属类的指针。

+   `* group` 是指向 `struct attribute_group` 列表（数组）的指针，用作设备的默认属性。使用此方法而不是单独创建属性。

+   `release` 是在设备引用计数达到零时调用的回调。总线有责任设置此字段。packt 总线驱动程序向您展示了如何做到这一点。

# 设备注册

`device_register`是 LDM 核心提供的用于在总线上注册设备的函数。调用此函数后，将遍历驱动程序的总线列表以找到支持此设备的驱动程序，然后将此设备添加到总线的设备列表中。`device_register()`在内部调用`device_add()`：

```
int device_add(struct device *dev) 
{ 
    [...] 
    bus_probe_device(dev); 
       if (parent) 
             klist_add_tail(&dev->p->knode_parent, 
                          &parent->p->klist_children); 
    [...] 
} 
```

内核提供的用于遍历总线设备列表的辅助函数是`bus_for_each_dev`：

```
int bus_for_each_dev(struct bus_type * bus, 
                    struct device * start, void * data, 
                    int (*fn)(struct device *, void *)); 
```

每当添加设备时，核心都会调用总线驱动程序的匹配方法（`bus_type->match`）。如果匹配函数表示有驱动程序支持此设备，核心将调用总线驱动程序的`probe`函数（`bus_type->probe`），给定设备和驱动程序作为参数。然后由总线驱动程序调用设备的驱动程序的`probe`方法（`driver->probe`）。对于我们的 packt 总线驱动程序，用于注册设备的函数是`packt_device_register(struct packt_device *packt)`，它在内部调用`device_register`，参数是使用`packt_device_alloc`分配的 packt 设备。

# 深入 LDM

LDM 在内部依赖于三个重要的结构，即 kobject、kobj_type 和 kset。让我们看看这些结构中的每一个如何参与设备模型。

# kobject 结构

kobject 是设备模型的核心，运行在后台。它为内核带来了类似 OO 的编程风格，主要用于引用计数和公开设备层次结构和它们之间的关系。kobject 引入了封装常见对象属性的概念，如使用引用计数：

```
struct kobject { 
    const char *name; 
    struct list_head entry; 
    struct kobject *parent; 
    struct kset *kset; 
    struct kobj_type *ktype; 
    struct sysfs_dirent *sd; 
    struct kref kref; 
    /* Fields out of our interest have been removed */ 
}; 
```

+   `name`指向此 kobject 的名称。可以使用`kobject_set_name(struct kobject *kobj, const char *name)`函数来更改这个名称。

+   `parent`是指向此 kobject 父级的指针。它用于构建描述对象之间关系的层次结构。

+   `sd`指向一个`struct sysfs_dirent`结构，表示 sysfs 中此 kobject 的 inode 内部的结构。

+   `kref`提供了对 kobject 的引用计数。

+   `ktype`描述了对象，`kset`告诉我们这个对象属于哪个集合（组）。

每个嵌入 kobject 的结构都会嵌入并接收 kobject 提供的标准化函数。嵌入的 kobject 将使结构成为对象层次结构的一部分。

`container_of`宏用于获取 kobject 所属对象的指针。每个内核设备直接或间接地嵌入一个 kobject 属性。在添加到系统之前，必须使用`kobject_create()`函数分配 kobject，该函数将返回一个空的 kobject，必须使用`kobj_init()`进行初始化，给定分配和未初始化的 kobject 指针以及其`kobj_type`指针：

```
struct kobject *kobject_create(void) 
void kobject_init(struct kobject *kobj, struct kobj_type *ktype) 
```

`kobject_add()`函数用于将 kobject 添加和链接到系统，同时根据其层次结构创建其目录，以及其默认属性。反向函数是`kobject_del()`：

```
int kobject_add(struct kobject *kobj, struct kobject *parent, 
                const char *fmt, ...); 
```

`kobject_create`和`kobject_add`的反向函数是`kobject_put`。在书中提供的源代码中，将 kobject 绑定到系统的摘录是：

```
/* Somewhere */ 
static struct kobject *mykobj; 

mykobj = kobject_create(); 
    if (mykobj) { 
        kobject_init(mykobj, &mytype); 
        if (kobject_add(mykobj, NULL, "%s", "hello")) { 
             err = -1; 
             printk("ldm: kobject_add() failed\n"); 
             kobject_put(mykobj); 
             mykobj = NULL; 
        } 
        err = 0; 
    } 
```

可以使用`kobject_create_and_add`，它在内部调用`kobject_create`和`kobject_add`。`drivers/base/core.c`中的以下摘录显示了如何使用它：

```
static struct kobject * class_kobj   = NULL; 
static struct kobject * devices_kobj = NULL; 

/* Create /sys/class */ 
class_kobj = kobject_create_and_add("class", NULL); 

if (!class_kobj) { 
    return -ENOMEM; 
} 

/* Create /sys/devices */ 
devices_kobj = kobject_create_and_add("devices", NULL); 

if (!devices_kobj) { 
    return -ENOMEM; 
} 
```

如果 kobject 有一个`NULL`父级，那么`kobject_add`会将父级设置为 kset。如果两者都是`NULL`，对象将成为顶级 sys 目录的子成员

# kobj_type

`struct kobj_type`结构描述了 kobjects 的行为。`kobj_type`结构通过`ktype`字段描述了嵌入 kobject 的对象的类型。每个嵌入 kobject 的结构都需要一个相应的`kobj_type`，它将控制在创建和销毁 kobject 以及读取或写入属性时发生的情况。每个 kobject 都有一个`struct kobj_type`类型的字段，代表**内核对象类型**：

```
struct kobj_type { 
   void (*release)(struct kobject *); 
   const struct sysfs_ops sysfs_ops; 
   struct attribute **default_attrs; 
}; 
```

`struct kobj_type`结构允许内核对象共享公共操作（`sysfs_ops`），无论这些对象是否在功能上相关。该结构的字段是有意义的。`release`是由`kobject_put()`函数调用的回调，每当需要释放对象时。您必须在这里释放对象持有的内存。可以使用`container_of`宏来获取对象的指针。`sysfs_ops`字段指向 sysfs 操作，而`default_attrs`定义了与此 kobject 关联的默认属性。`sysfs_ops`是一组在访问 sysfs 属性时调用的回调（sysfs 操作）。`default_attrs`是指向`struct attribute`元素列表的指针，将用作此类型的每个对象的默认属性：

```
struct sysfs_ops { 
    ssize_t (*show)(struct kobject *kobj, 
                    struct attribute *attr, char *buf); 
    ssize_t (*store)(struct kobject *kobj, 
                     struct attribute *attr,const char *buf, 
                     size_t size); 
}; 
```

`show`是当读取具有此`kobj_type`的任何 kobject 的属性时调用的回调。缓冲区大小始终为`PAGE_SIZE`，即使要显示的值是一个简单的`char`。应该设置`buf`的值（使用`scnprintf`），并在成功时返回实际写入缓冲区的数据的大小（以字节为单位），或者在失败时返回负错误。`store`用于写入目的。它的`buf`参数最多为`PAGE_SIZE`，但可以更小。它在成功时返回实际从缓冲区读取的数据的大小（以字节为单位），或者在失败时返回负错误（或者如果它收到一个不需要的值）。可以使用`get_ktype`来获取给定 kobject 的`kobj_type`：

```
struct kobj_type *get_ktype(struct  kobject *kobj); 
```

在书中的示例中，我们的`k_type`变量表示我们 kobject 的类型：

```
static struct sysfs_ops s_ops = { 
    .show = show, 
    .store = store, 
}; 

static struct kobj_type k_type = { 
    .sysfs_ops = &s_ops, 
    .default_attrs = d_attrs, 
}; 
```

这里，`show`和`store`回调定义如下：

```
static ssize_t show(struct kobject *kobj, struct attribute *attr, char *buf) 
{ 
    struct d_attr *da = container_of(attr, struct d_attr, attr); 
    printk( "LDM show: called for (%s) attr\n", da->attr.name ); 
    return scnprintf(buf, PAGE_SIZE, 
                     "%s: %d\n", da->attr.name, da->value); 
} 

static ssize_t store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t len) 
{ 
    struct d_attr *da = container_of(attr, struct d_attr, attr); 
    sscanf(buf, "%d", &da->value); 
    printk("LDM store: %s = %d\n", da->attr.name, da->value); 

    return sizeof(int); 
} 
```

# ksets

**内核对象集**（**ksets**）主要将相关的内核对象分组在一起。ksets 是 kobjects 的集合。换句话说，kset 将相关的 kobjects 聚集到一个地方，例如，所有块设备：

```
struct kset { 
   struct list_head list;  
   spinlock_t list_lock; 
   struct kobject kobj; 
 }; 
```

+   `list`是 kset 中所有 kobject 的链表

+   `list_lock`是用于保护链表访问的自旋锁

+   `kobj`表示集合的基类

每个注册（添加到系统中）的 kset 对应一个 sysfs 目录。可以使用`kset_create_and_add()`函数创建和添加 kset，并使用`kset_unregister()`函数删除：

```
struct kset * kset_create_and_add(const char *name, 
                                const struct kset_uevent_ops *u, 
                                struct kobject *parent_kobj); 
void kset_unregister (struct kset * k); 
```

将 kobject 添加到集合中就像将其 kset 字段指定为正确的 kset 一样简单：

```
static struct kobject foo_kobj, bar_kobj; 

example_kset = kset_create_and_add("kset_example", NULL, kernel_kobj); 
/* 
 * since we have a kset for this kobject, 
 * we need to set it before calling the kobject core. 
 */ 
foo_kobj.kset = example_kset; 
bar_kobj.kset = example_kset; 

retval = kobject_init_and_add(&foo_kobj, &foo_ktype, 
                              NULL, "foo_name"); 
retval = kobject_init_and_add(&bar_kobj, &bar_ktype, 
                              NULL, "bar_name"); 
```

现在在模块的`exit`函数中，kobject 及其属性已被删除：

```
kset_unregister(example_kset); 
```

# 属性

属性是由 kobjects 向用户空间导出的 sysfs 文件。属性表示可以从用户空间可读、可写或两者的对象属性。也就是说，每个嵌入`struct kobject`的数据结构可以公开由 kobject 本身提供的默认属性（如果有的话），也可以公开自定义属性。换句话说，属性将内核数据映射到 sysfs 中的文件。

属性定义如下：

```
struct attribute { 
        char * name; 
        struct module *owner; 
        umode_t mode; 
}; 
```

用于从文件系统中添加/删除属性的内核函数是：

```
int sysfs_create_file(struct kobject * kobj, 
                      const struct attribute * attr); 
void sysfs_remove_file(struct kobject * kobj, 
                        const struct attribute * attr); 
```

让我们尝试定义两个我们将导出的属性，每个属性由一个属性表示：

```
struct d_attr { 
    struct attribute attr; 
    int value; 
}; 

static struct d_attr foo = { 
    .attr.name="foo", 
    .attr.mode = 0644, 
    .value = 0, 
}; 

static struct d_attr bar = { 
    .attr.name="bar", 
    .attr.mode = 0644, 
    .value = 0, 
}; 
```

要单独创建每个枚举属性，我们必须调用以下内容：

```
sysfs_create_file(mykobj, &foo.attr); 
sysfs_create_file(mykobj, &bar.attr); 
```

属性的一个很好的起点是内核源码中的`samples/kobject/kobject-example.c`。

# 属性组

到目前为止，我们已经看到了如何单独添加属性，并在每个属性上调用（直接或间接通过包装函数，如`device_create_file()`，`class_create_file()`等）`sysfs_create_file()`。如果我们可以一次完成，为什么要自己处理多个调用呢？这就是属性组的作用。它依赖于`struct attribute_group`结构：

```
struct attribute_group { 
   struct attribute  **attrs; 
}; 
```

当然，我们已经删除了不感兴趣的字段。`attr`字段是指向属性列表/数组的指针。每个属性组必须给定一个指向`struct attribute`元素的列表/数组的指针。该组只是一个帮助包装器，使得更容易管理多个属性。

用于向文件系统添加/删除组属性的内核函数是：

```
int sysfs_create_group(struct kobject *kobj, 
                       const struct attribute_group *grp) 
void sysfs_remove_group(struct kobject * kobj, 
                        const struct attribute_group * grp) 
```

前面定义的两个属性可以嵌入到`struct attribute_group`中，只需一次调用即可将它们都添加到系统中：

```
static struct d_attr foo = { 
    .attr.name="foo", 
    .attr.mode = 0644, 
    .value = 0, 
}; 

static struct d_attr bar = { 
    .attr.name="bar", 
    .attr.mode = 0644, 
    .value = 0, 
}; 

/* attrs is a pointer to a list (array) of attributes */ 
static struct attribute * attrs [] = 
{ 
    &foo.attr, 
    &bar.attr, 
    NULL, 
}; 

static struct attribute_group my_attr_group = { 
    .attrs = attrs, 
}; 
```

在这里唯一需要调用的函数是：

```
sysfs_create_group(mykobj, &my_attr_group); 
```

这比为每个属性都调用一次要好得多。

# 设备模型和 sysfs

`Sysfs`是一个非持久的虚拟文件系统，它提供了系统的全局视图，并通过它们的 kobjects 公开了内核对象的层次结构（拓扑）。每个 kobjects 显示为一个目录，目录中的文件表示由相关 kobject 导出的内核变量。这些文件称为属性，可以被读取或写入。

如果任何注册的 kobject 在 sysfs 中创建一个目录，那么目录的创建取决于 kobject 的父对象（也是一个 kobject）。自然而然地，目录被创建为 kobject 的父目录的子目录。这将内部对象层次结构突显到用户空间。sysfs 中的顶级目录表示对象层次结构的共同祖先，也就是对象所属的子系统。

顶级 sysfs 目录可以在`/sys/`目录下找到：

```
    /sys$ tree -L 1

    ├── block

    ├── bus

    ├── class

    ├── dev

    ├── devices

    ├── firmware

    ├── fs

    ├── hypervisor

    ├── kernel

    ├── module

    └── power

```

`block`包含系统上每个块设备的目录，每个目录包含设备上分区的子目录。`bus`包含系统上注册的总线。`dev`以原始方式包含注册的设备节点（无层次结构），每个都是指向`/sys/devices`目录中真实设备的符号链接。`devices`显示系统中设备的拓扑视图。`firmware`显示系统特定的低级子系统树，例如：ACPI、EFI、OF（DT）。`fs`列出系统上实际使用的文件系统。`kernel`保存内核配置选项和状态信息。`Modules`是已加载模块的列表。

这些目录中的每一个都对应一个 kobject，其中一些作为内核符号导出。这些是：

+   `kernel_kobj`对应于`/sys/kernel`

+   `power_kobj`对应于`/sys/power`

+   `firmware_kobj`对应于`/sys/firmware`，在`drivers/base/firmware.c`源文件中导出

+   `hypervisor_kobj`对应于`/sys/hypervisor`，在`drivers/base/hypervisor.c`中导出

+   `fs_kobj`对应于`/sys/fs`，在`fs/namespace.c`文件中导出

然而，`class/`、`dev/`、`devices/`是在内核源代码中的`drivers/base/core.c`中由`devices_init`函数在启动时创建的，`block/`是在`block/genhd.c`中创建的，`bus/`是在`drivers/base/bus.c`中作为 kset 创建的。

当将 kobject 目录添加到 sysfs（使用`kobject_add`）时，它被添加的位置取决于 kobject 的父位置。如果其父指针已设置，则将其添加为父目录中的子目录。如果父指针为空，则将其添加为`kset->kobj`中的子目录。如果父字段和 kset 字段都未设置，则映射到 sysfs 中的根级目录（`/sys`）。

可以使用`sysfs_{create|remove}_link`函数在现有对象（目录）上创建/删除符号链接：

```
int sysfs_create_link(struct kobject * kobj, 
                      struct kobject * target, char * name);  
void sysfs_remove_link(struct kobject * kobj, char * name); 
```

这将允许一个对象存在于多个位置。创建函数将创建一个名为`name`的符号链接，指向`target` kobject sysfs 条目。一个众所周知的例子是设备同时出现在`/sys/bus`和`/sys/devices`中。创建的符号链接将在`target`被移除后仍然存在。您必须知道`target`何时被移除，然后删除相应的符号链接。

# Sysfs 文件和属性

现在我们知道，默认的文件集是通过 kobjects 和 ksets 中的 ktype 字段提供的，通过`kobj_type`的`default_attrs`字段。默认属性在大多数情况下都足够了。但有时，ktype 的一个实例可能需要自己的属性来提供不被更一般的 ktype 共享的数据或功能。

只是一个提醒，用于在默认集合之上添加/删除新属性（或属性组）的低级函数是：

```
int sysfs_create_file(struct kobject *kobj,  
                      const struct attribute *attr); 
void sysfs_remove_file(struct kobject *kobj, 
                       const struct attribute *attr); 
int sysfs_create_group(struct kobject *kobj, 
                       const struct attribute_group *grp); 
void sysfs_remove_group(struct kobject * kobj, 
                        const struct attribute_group * grp); 
```

# 当前接口

目前在 sysfs 中存在接口层。除了创建自己的 ktype 或 kobject 以添加属性外，还可以使用当前存在的属性：设备、驱动程序、总线和类属性。它们的描述如下：

# 设备属性

除了设备结构中嵌入的默认属性之外，您还可以创建自定义属性。用于此目的的结构是`struct device_attribute`，它只是标准`struct attribute`的包装，并且一组回调函数来显示/存储属性的值：

```
struct device_attribute { 
    struct attribute attr; 
    ssize_t (*show)(struct device *dev, 
                    struct device_attribute *attr, 
                   char *buf); 
    ssize_t (*store)(struct device *dev, 
                     struct device_attribute *attr, 
                     const char *buf, size_t count); 
}; 
```

它们的声明是通过`DEVICE_ATTR`宏完成的：

```
DEVICE_ATTR(_name, _mode, _show, _store); 
```

每当使用`DEVICE_ATTR`声明设备属性时，属性名称前缀`dev_attr_`将添加到属性名称中。例如，如果使用`_name`参数设置为 foo 来声明属性，则可以通过`dev_attr_foo`变量名称访问该属性。

要理解为什么，让我们看看`DEVICE_ATTR`宏在`include/linux/device.h`中是如何定义的：

```
#define DEVICE_ATTR(_name, _mode, _show, _store) \ 
   struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store) 
```

最后，您可以使用`device_create_file`和`device_remove_file`函数添加/删除这些：

```
int device_create_file(struct device *dev,  
                      const struct device_attribute * attr); 
void device_remove_file(struct device *dev, 
                       const struct device_attribute * attr); 
```

以下示例演示了如何将所有内容放在一起：

```
static ssize_t foo_show(struct device *child, 
    struct device_attribute *attr, char *buf) 
{ 
    return sprintf(buf, "%d\n", foo_value); 
} 

static ssize_t bar_show(struct device *child, 
         struct device_attribute *attr, char *buf) 
{ 
    return sprintf(buf, "%d\n", bar_value); 
}  
```

以下是属性的静态声明：

```
static DEVICE_ATTR(foo, 0644, foo_show, NULL); 
static DEVICE_ATTR(bar, 0644, bar_show, NULL); 
```

以下代码显示了如何在系统上实际创建文件：

```
if ( device_create_file(dev, &dev_attr_foo) != 0 ) 
    /* handle error */ 

if ( device_create_file(dev, &dev_attr_bar) != 0 ) 
    /* handle error*/ 
```

对于清理，属性的移除是在移除函数中完成的：

```
device_remove_file(wm->dev, &dev_attr_foo); 
device_remove_file(wm->dev, &dev_attr_bar); 
```

您可能会想知道我们是如何以前定义相同的存储/显示回调来处理相同 kobject/ktype 的所有属性，现在我们为每个属性使用自定义的回调。第一个原因是，设备子系统定义了自己的属性结构，它包装了标准属性结构，其次，它不是显示/存储属性的值，而是使用`container_of`宏来提取`struct device_attribute`，从而给出一个通用的`struct attribute`，然后根据用户操作执行 show/store 回调。以下是来自`drivers/base/core.c`的摘录，显示了设备 kobject 的`sysfs_ops`：

```
static ssize_t dev_attr_show(struct kobject *kobj, 
                            struct attribute *attr, 
                            char *buf) 
{ 
   struct device_attribute *dev_attr = to_dev_attr(attr); 
   struct device *dev = kobj_to_dev(kobj); 
   ssize_t ret = -EIO; 

   if (dev_attr->show) 
         ret = dev_attr->show(dev, dev_attr, buf); 
   if (ret >= (ssize_t)PAGE_SIZE) { 
         print_symbol("dev_attr_show: %s returned bad count\n", 
                     (unsigned long)dev_attr->show); 
   } 
   return ret; 
} 

static ssize_t dev_attr_store(struct kobject *kobj, struct attribute *attr, 
                     const char *buf, size_t count) 
{ 
   struct device_attribute *dev_attr = to_dev_attr(attr); 
   struct device *dev = kobj_to_dev(kobj); 
   ssize_t ret = -EIO; 

   if (dev_attr->store) 
         ret = dev_attr->store(dev, dev_attr, buf, count); 
   return ret; 
} 

static const struct sysfs_ops dev_sysfs_ops = { 
   .show = dev_attr_show, 
   .store      = dev_attr_store, 
}; 
```

原则对于总线（在`drivers/base/bus.c`中）、驱动程序（在`drivers/base/bus.c`中）和类（在`drivers/base/class.c`中）属性是相同的。它们使用`container_of`宏来提取其特定属性结构，然后调用其中嵌入的 show/store 回调。

# 总线属性

它依赖于`struct bus_attribute`结构：

```
struct bus_attribute { 
   struct attribute attr; 
   ssize_t (*show)(struct bus_type *, char * buf); 
   ssize_t (*store)(struct bus_type *, const char * buf, size_t count); 
}; 
```

使用`BUS_ATTR`宏声明总线属性：

```
BUS_ATTR(_name, _mode, _show, _store) 
```

使用`BUS_ATTR`声明的任何总线属性都将在属性变量名称中添加前缀`bus_attr_`：

```
#define BUS_ATTR(_name, _mode, _show, _store)      \ 
struct bus_attribute bus_attr_##_name = __ATTR(_name, _mode, _show, _store) 
```

它们是使用`bus_{create|remove}_file`函数创建/删除的：

```
int bus_create_file(struct bus_type *, struct bus_attribute *); 
void bus_remove_file(struct bus_type *, struct bus_attribute *); 
```

# 设备驱动程序属性

所使用的结构是`struct driver_attribute`：

```
struct driver_attribute { 
        struct attribute attr; 
        ssize_t (*show)(struct device_driver *, char * buf); 
        ssize_t (*store)(struct device_driver *, const char * buf, 
                         size_t count); 
}; 
```

声明依赖于`DRIVER_ATTR`宏，该宏将在属性变量名称中添加前缀`driver_attr_`：

```
DRIVER_ATTR(_name, _mode, _show, _store) 
```

宏定义如下：

```
#define DRIVER_ATTR(_name, _mode, _show, _store) \ 
struct driver_attribute driver_attr_##_name = __ATTR(_name, _mode, _show, _store) 
```

创建/删除依赖于`driver_{create|remove}_file`函数：

```
int driver_create_file(struct device_driver *, 
                       const struct driver_attribute *); 
void driver_remove_file(struct device_driver *, 
                       const struct driver_attribute *); 
```

# 类属性

`struct class_attribute`是基本结构：

```
struct class_attribute { 
        struct attribute        attr; 
        ssize_t (*show)(struct device_driver *, char * buf); 
        ssize_t (*store)(struct device_driver *, const char * buf, 
                         size_t count); 
}; 
```

类属性的声明依赖于`CLASS_ATTR`：

```
CLASS_ATTR(_name, _mode, _show, _store) 
```

正如宏的定义所示，使用`CLASS_ATTR`声明的任何类属性都将在属性变量名称中添加前缀`class_attr_`：

```
#define CLASS_ATTR(_name, _mode, _show, _store) \ 
struct class_attribute class_attr_##_name = __ATTR(_name, _mode, _show, _store) 
```

最后，文件的创建和删除是使用`class_{create|remove}_file`函数完成的：

```
int class_create_file(struct class *class, 
        const struct class_attribute *attr); 

void class_remove_file(struct class *class, 
        const struct class_attribute *attr); 
```

请注意，`device_create_file()`，`bus_create_file()`，`driver_create_file()`和`class_create_file()`都会内部调用`sysfs_create_file()`。由于它们都是内核对象，它们的结构中嵌入了`kobject`。然后将该`kobject`作为参数传递给`sysfs_create_file`，如下所示：

```
int device_create_file(struct device *dev, 
                    const struct device_attribute *attr) 
{ 
    [...] 
    error = sysfs_create_file(&dev->kobj, &attr->attr); 
    [...] 
} 

int class_create_file(struct class *cls, 
                    const struct class_attribute *attr) 
{ 
    [...] 
    error = 
        sysfs_create_file(&cls->p->class_subsys.kobj, 
                          &attr->attr); 
    return error; 
} 

int bus_create_file(struct bus_type *bus, 
                   struct bus_attribute *attr) 
{ 
    [...] 
    error = 
        sysfs_create_file(&bus->p->subsys.kobj, 
                           &attr->attr); 
    [...] 
} 
```

# 允许 sysfs 属性文件进行轮询

在这里，我们将看到如何避免进行 CPU 浪费的轮询以检测 sysfs 属性数据的可用性。想法是使用`poll`或`select`系统调用等待属性内容的更改。使 sysfs 属性可轮询的补丁是由**Neil Brown**和**Greg Kroah-Hartman**创建的。kobject 管理器（具有对 kobject 的访问权限的驱动程序）必须支持通知，以允许`poll`或`select`在内容更改时返回（被释放）。执行这一技巧的神奇函数来自内核侧，即`sysfs_notify()`：

```
void sysfs_notify(struct kobject *kobj, const char *dir, 
                  const char *attr) 
```

如果`dir`参数非空，则用于查找包含属性的子目录（可能是由`sysfs_create_group`创建的）。每个属性的成本为一个`int`，每个 kobject 的`wait_queuehead`，每个打开文件一个 int。

`poll`将返回`POLLERR|POLLPRI`，而`select`将返回 fd，无论它是等待读取、写入还是异常。阻塞的 poll 来自用户端。只有在调整内核属性值后才应调用`sysfs_notify()`。

将`poll()`（或`select()`）代码视为对感兴趣属性的更改通知的**订阅者**，并将`sysfs_notify()`视为**发布者**，通知订阅者任何更改。

以下是书中提供的代码摘录，这是属性的存储函数：

```
static ssize_t store(struct kobject *kobj, struct attribute *attr, 
                     const char *buf, size_t len) 
{ 
    struct d_attr *da = container_of(attr, struct d_attr, attr); 

    sscanf(buf, "%d", &da->value); 
    printk("sysfs_foo store %s = %d\n", a->attr.name, a->value); 

    if (strcmp(a->attr.name, "foo") == 0){ 
        foo.value = a->value; 
        sysfs_notify(mykobj, NULL, "foo"); 
    } 
    else if(strcmp(a->attr.name, "bar") == 0){ 
        bar.value = a->value; 
        sysfs_notify(mykobj, NULL, "bar"); 
    } 
    return sizeof(int); 
} 
```

用户空间的代码必须像这样才能感知数据的更改：

1.  打开文件属性。

1.  对所有内容进行虚拟读取。

1.  调用`poll`请求`POLLERR|POLLPRI`（select/exceptfds 也可以）。

1.  当`poll`（或`select`）返回（表示值已更改）时，读取数据已更改的文件内容。

1.  关闭文件并返回循环的顶部。

如果对 sysfs 属性是否可轮询存在疑问，请设置合适的超时值。书中提供了用户空间示例。

# 摘要

现在您已经熟悉了 LDM 概念及其数据结构（总线、类、设备驱动程序和设备），包括低级数据结构，即`kobject`、`kset`、`kobj_types`和属性（或这些属性的组合），内核中如何表示对象（因此 sysfs 和设备拓扑结构）不再是秘密。您将能够创建一个通过 sysfs 公开您的设备或驱动程序功能的属性（或组）。如果前面的话题对您来说很清楚，我们将转到下一个第十四章，*引脚控制和 GPIO 子系统*，该章节大量使用了`sysfs`的功能。


# 第十四章：引脚控制和 GPIO 子系统

大多数嵌入式 Linux 驱动程序和内核工程师都使用 GPIO 或玩转引脚复用。在这里，引脚指的是组件的输出线。SoC 会复用引脚，这意味着一个引脚可能有多个功能，例如，在`arch/arm/boot/dts/imx6dl-pinfunc.h`中的`MX6QDL_PAD_SD3_DAT1`可以是 SD3 数据线 1、UART1 的 cts/rts、Flexcan2 的 Rx 或普通的 GPIO。

选择引脚应该工作的模式的机制称为引脚复用。负责此功能的系统称为引脚控制器。在本章的第二部分中，我们将讨论通用输入输出（GPIO），这是引脚可以操作的特殊功能（模式）。

在本章中，我们将：

+   了解引脚控制子系统，并看看如何在 DT 中声明它们的节点

+   探索传统的基于整数的 GPIO 接口，以及新的基于描述符的接口 API

+   处理映射到 IRQ 的 GPIO

+   处理专用于 GPIO 的 sysfs 接口

# 引脚控制子系统

引脚控制（pinctrl）子系统允许管理引脚复用。在 DT 中，需要以某种方式复用引脚的设备必须声明它们需要的引脚控制配置。

引脚控制子系统提供：

+   引脚复用，允许重用同一引脚用于不同的目的，比如一个引脚可以是 UART TX 引脚、GPIO 线或 HSI 数据线。复用可以影响引脚组或单个引脚。

+   引脚配置，应用引脚的电子属性，如上拉、下拉、驱动器强度、去抖时间等。

本书的目的仅限于使用引脚控制器驱动程序导出的函数，并不涉及如何编写引脚控制器驱动程序。

# 引脚控制和设备树

引脚控制只是一种收集引脚（不仅仅是 GPIO）并将它们传递给驱动程序的方法。引脚控制器驱动程序负责解析 DT 中的引脚描述并在芯片中应用它们的配置。驱动程序通常需要一组两个嵌套节点来描述引脚配置的组。第一个节点描述组的功能（组将用于什么目的），第二个节点保存引脚配置。

引脚组在设备树中的分配严重依赖于平台，因此也依赖于引脚控制器驱动程序。每个引脚控制状态都被赋予一个从 0 开始的连续整数 ID。可以使用一个名称属性，它将映射到 ID 上，以便相同的名称始终指向相同的 ID。

每个客户设备自己的绑定确定了必须在其 DT 节点中定义的状态集，以及是否定义必须提供的状态 ID 集，或者是否定义必须提供的状态名称集。在任何情况下，可以通过两个属性将引脚配置节点分配给设备：

+   `pinctrl-<ID>`：这允许为设备的某个状态提供所需的 pinctrl 配置列表。这是一个 phandle 列表，每个 phandle 指向一个引脚配置节点。这些引用的引脚配置节点必须是它们配置的引脚控制器的子节点。此列表中可能存在多个条目，以便可以配置多个引脚控制器，或者可以从单个引脚控制器的多个节点构建状态，每个节点都为整体配置的一部分做出贡献。

+   `pinctrl-name`：这允许为列表中的每个状态提供一个名称。列表条目 0 定义整数状态 ID 0 的名称，列表条目 1 定义状态 ID 1 的名称，依此类推。状态 ID 0 通常被赋予名称*default*。标准化状态列表可以在`include/linux/pinctrl/pinctrl-state.h`中找到。

+   以下是 DT 的摘录，显示了一些设备节点以及它们的引脚控制节点：

```
usdhc@0219c000 { /* uSDHC4 */ 
   non-removable; 
   vmmc-supply = <&reg_3p3v>; 
   status = "okay"; 
   pinctrl-names = "default"; 
   pinctrl-0 = <&pinctrl_usdhc4_1>; 
}; 

gpio-keys { 
    compatible = "gpio-keys"; 
    pinctrl-names = "default"; 
    pinctrl-0 = <&pinctrl_io_foo &pinctrl_io_bar>; 
}; 

iomuxc@020e0000 { 
    compatible = "fsl,imx6q-iomuxc"; 
    reg = <0x020e0000 0x4000>; 

    /* shared pinctrl settings */ 
    usdhc4 { /* first node describing the function */ 
        pinctrl_usdhc4_1: usdhc4grp-1 { /* second node */ 
            fsl,pins = < 
                MX6QDL_PAD_SD4_CMD__SD4_CMD    0x17059 
                MX6QDL_PAD_SD4_CLK__SD4_CLK    0x10059 
                MX6QDL_PAD_SD4_DAT0__SD4_DATA0 0x17059 
                MX6QDL_PAD_SD4_DAT1__SD4_DATA1 0x17059 
                MX6QDL_PAD_SD4_DAT2__SD4_DATA2 0x17059 
                MX6QDL_PAD_SD4_DAT3__SD4_DATA3 0x17059 
                MX6QDL_PAD_SD4_DAT4__SD4_DATA4 0x17059 
                MX6QDL_PAD_SD4_DAT5__SD4_DATA5 0x17059 
                MX6QDL_PAD_SD4_DAT6__SD4_DATA6 0x17059 
                MX6QDL_PAD_SD4_DAT7__SD4_DATA7 0x17059 
            >; 
        }; 
    }; 
    [...] 
    uart3 { 
        pinctrl_uart3_1: uart3grp-1 { 
            fsl,pins = < 
                MX6QDL_PAD_EIM_D24__UART3_TX_DATA 0x1b0b1 
                MX6QDL_PAD_EIM_D25__UART3_RX_DATA 0x1b0b1 
            >; 
        }; 
    }; 
    // GPIOs (Inputs) 
   gpios { 
        pinctrl_io_foo: pinctrl_io_foo { 
            fsl,pins = < 
                MX6QDL_PAD_DISP0_DAT15__GPIO5_IO09  0x1f059 
                MX6QDL_PAD_DISP0_DAT13__GPIO5_IO07  0x1f059 
            >; 
        }; 
        pinctrl_io_bar: pinctrl_io_bar { 
            fsl,pins = < 
                MX6QDL_PAD_DISP0_DAT11__GPIO5_IO05  0x1f059 
                MX6QDL_PAD_DISP0_DAT9__GPIO4_IO30   0x1f059 
                MX6QDL_PAD_DISP0_DAT7__GPIO4_IO28   0x1f059 
                MX6QDL_PAD_DISP0_DAT5__GPIO4_IO26   0x1f059 
            >; 
        }; 
    }; 
}; 
```

在上面的示例中，引脚配置以`<PIN_FUNCTION> <PIN_SETTING>`的形式给出。例如：

```
MX6QDL_PAD_DISP0_DAT15__GPIO5_IO09  0x80000000 
```

`MX6QDL_PAD_DISP0_DAT15__GPIO5_IO09`表示引脚功能，在这种情况下是 GPIO，`0x80000000`表示引脚设置。

对于这一行，

```
MX6QDL_PAD_EIM_D25__UART3_RX_DATA 0x1b0b1 
```

`MX6QDL_PAD_EIM_D25__UART3_RX_DATA`表示引脚功能，即 UART3 的 RX 线，`0x1b0b1`表示设置。

引脚功能是一个宏，其值仅对引脚控制器驱动程序有意义。这些通常在位于`arch/<arch>/boot/dts/`中的头文件中定义。例如，如果使用的是 UDOO quad，它具有 i.MX6 四核（ARM），则引脚功能头文件将是`arch/arm/boot/dts/imx6q-pinfunc.h`。以下是与 GPIO5 控制器的第五行对应的宏：

```
#define MX6QDL_PAD_DISP0_DAT11__GPIO5_IO05  0x19c 0x4b0 0x000 0x5 0x0 
```

`<PIN_SETTING>`可用于设置上拉电阻、下拉电阻、保持器、驱动强度等。如何指定它取决于引脚控制器绑定，其值的含义取决于 SoC 数据表，通常在 IOMUX 部分。在 i.MX6 IOMUXC 上，仅使用低于 17 位来实现此目的。

这些前置节点是从相应的驱动程序特定节点调用的。此外，这些引脚在相应的驱动程序初始化期间进行配置。在选择引脚组状态之前，必须首先使用`pinctrl_get()`函数获取引脚控制，调用`pinctrl_lookup_state()`来检查请求的状态是否存在，最后使用`pinctrl_select_state()`来应用状态。

以下是一个示例，显示如何获取 pincontrol 并应用其默认配置：

```
struct pinctrl *p; 
struct pinctrl_state *s; 
int ret; 

p = pinctrl_get(dev); 
if (IS_ERR(p)) 
    return p; 

s = pinctrl_lookup_state(p, name); 
if (IS_ERR(s)) { 
    devm_pinctrl_put(p); 
    return ERR_PTR(PTR_ERR(s)); 
} 

ret = pinctrl_select_state(p, s); 
if (ret < 0) { 
    devm_pinctrl_put(p); 
    return ERR_PTR(ret); 
} 
```

通常在驱动程序初始化期间执行这些步骤。此代码的适当位置可以在`probe()`函数内。

`pinctrl_select_state()`在内部调用`pinmux_enable_setting()`，后者又在引脚控制节点中的每个引脚上调用`pin_request()`。

可以使用`pinctrl_put()`函数释放引脚控制。可以使用 API 的资源管理版本。也就是说，可以使用`pinctrl_get_select()`，给定要选择的状态的名称，以配置引脚控制。该函数在`include/linux/pinctrl/consumer.h`中定义如下：

```
static struct pinctrl *pinctrl_get_select(struct device *dev, 
                             const char *name) 
```

其中`*name`是`pinctrl-name`属性中写的状态名称。如果状态的名称是`default`，可以直接调用`pinctr_get_select_default()`函数，这是`pinctl_get_select()`的包装器：

```
static struct pinctrl * pinctrl_get_select_default( 
                                struct device *dev) 
{ 
   return pinctrl_get_select(dev, PINCTRL_STATE_DEFAULT); 
} 
```

让我们看一个真实的例子，位于特定于板的 dts 文件（`am335x-evm.dts`）中：

```
dcan1: d_can@481d0000 { 
    status = "okay"; 
    pinctrl-names = "default"; 
    pinctrl-0 = <&d_can1_pins>; 
}; 
```

以及相应的驱动程序：

```
pinctrl = devm_pinctrl_get_select_default(&pdev->dev); 
if (IS_ERR(pinctrl)) 
    dev_warn(&pdev->dev,"pins are not configured from the driver\n"); 
```

当设备被探测时，引脚控制核心将自动为我们声明`default` pinctrl 状态。如果定义了`init`状态，引脚控制核心将在`probe()`函数之前自动将 pinctrl 设置为此状态，然后在`probe()`之后切换到`default`状态（除非驱动程序已经显式更改了状态）。

# GPIO 子系统

从硬件角度来看，GPIO 是一种功能，是引脚可以操作的模式。从软件角度来看，GPIO 只是一个数字线，可以作为输入或输出，并且只能有两个值：（`1`表示高，`0`表示低）。内核 GPIO 子系统提供了您可以想象的每个功能，以便从驱动程序内部设置和处理 GPIO 线：

+   在驱动程序中使用 GPIO 之前，应该向内核声明它。这是一种获取 GPIO 所有权的方法，可以防止其他驱动程序访问相同的 GPIO。获取 GPIO 所有权后，可以进行以下操作：

+   设置方向

+   切换其输出状态（将驱动线设置为高电平或低电平）如果用作输出

+   如果用作输入，则设置去抖动间隔并读取状态。对于映射到中断请求的 GPIO 线，可以定义触发中断的边缘/电平，并注册一个处理程序，每当中断发生时就会运行。

实际上，内核中处理 GPIO 有两种不同的方式，如下所示：

+   使用整数表示 GPIO 的传统和已弃用的接口

+   新的和推荐的基于描述符的接口，其中 GPIO 由不透明结构表示和描述，具有专用 API

# 基于整数的 GPIO 接口：传统

基于整数的接口是最为人熟知的。GPIO 由一个整数标识，该标识用于对 GPIO 执行的每个操作。以下是包含传统 GPIO 访问函数的标头：

```
#include <linux/gpio.h> 
```

内核中有众所周知的函数来处理 GPIO。

# 声明和配置 GPIO

可以使用`gpio_request（）`函数分配和拥有 GPIO：

```
static int  gpio_request(unsigned gpio, const char *label) 
```

`gpio`表示我们感兴趣的 GPIO 编号，`label`是内核在 sysfs 中用于 GPIO 的标签，如我们在`/sys/kernel/debug/gpio`中所见。必须检查返回的值，其中`0`表示成功，错误时为负错误代码。完成 GPIO 后，应使用`gpio_free（）`函数释放它：

```
void gpio_free(unsigned int gpio) 
```

如果有疑问，可以使用`gpio_is_valid（）`函数在分配之前检查系统上的 GPIO 编号是否有效：

```
static bool gpio_is_valid(int number) 
```

一旦我们拥有了 GPIO，就可以根据需要改变它的方向，无论是输入还是输出，都可以使用`gpio_direction_input（）`或`gpio_direction_output（）`函数：

```
static int  gpio_direction_input(unsigned gpio) 
static int  gpio_direction_output(unsigned gpio, int value) 
```

`gpio`是我们需要设置方向的 GPIO 编号。在配置 GPIO 为输出时有第二个参数：`value`，这是一旦输出方向生效后 GPIO 应处于的状态。同样，返回值为零或负错误号。这些函数在内部映射到我们使用的 GPIO 控制器驱动程序公开的较低级别回调函数之上。在下一章[第十五章](http://gpio)，*GPIO 控制器驱动程序-gpio_chip*中，处理 GPIO 控制器驱动程序，我们将看到 GPIO 控制器必须通过其`struct gpio_chip`结构公开一组通用的回调函数来使用其 GPIO。

一些 GPIO 控制器提供更改 GPIO 去抖动间隔的可能性（仅当 GPIO 线配置为输入时才有用）。这个功能是平台相关的。可以使用`int gpio_set_debounce（）`来实现这一点：

```
static  int  gpio_set_debounce(unsigned gpio, unsigned debounce) 
```

其中`debounce`是以毫秒为单位的去抖时间。

所有前述函数应在可能休眠的上下文中调用。从驱动程序的`probe`函数中声明和配置 GPIO 是一个良好的实践。

# 访问 GPIO-获取/设置值

在访问 GPIO 时应注意。在原子上下文中，特别是在中断处理程序中，必须确保 GPIO 控制器回调函数不会休眠。设计良好的控制器驱动程序应该能够通知其他驱动程序（实际上是客户端）其方法是否可能休眠。可以使用`gpio_cansleep（）`函数进行检查。

用于访问 GPIO 的函数都不返回错误代码。这就是为什么在 GPIO 分配和配置期间应注意并检查返回值的原因。

# 在原子上下文中

有一些 GPIO 控制器可以通过简单的内存读/写操作进行访问和管理。这些通常嵌入在 SoC 中，不需要休眠。对于这些控制器，`gpio_cansleep（）`将始终返回`false`。对于这样的 GPIO，可以在 IRQ 处理程序中使用众所周知的`gpio_get_value（）`或`gpio_set_value（）`获取/设置它们的值，具体取决于 GPIO 线被配置为输入还是输出：

```
static int  gpio_get_value(unsigned gpio) 
void gpio_set_value(unsigned int gpio, int value); 
```

当 GPIO 配置为输入（使用`gpio_direction_input（）`）时，应使用`gpio_get_value（）`，并返回 GPIO 的实际值（状态）。另一方面，`gpio_set_value（）`将影响 GPIO 的值，应该已经使用`gpio_direction_output（）`配置为输出。对于这两个函数，`value`可以被视为`布尔值`，其中零表示低，非零值表示高。

# 在可能休眠的非原子上下文中

另一方面，还有 GPIO 控制器连接在 SPI 和 I2C 等总线上。由于访问这些总线的函数可能导致休眠，因此`gpio_cansleep()`函数应始终返回`true`（由 GPIO 控制器负责返回 true）。在这种情况下，您不应该在 IRQ 处理中访问这些 GPIO，至少不是在顶半部分（硬 IRQ）。此外，您必须使用作为通用访问的访问器应该以`_cansleep`结尾。

```
static int gpio_get_value_cansleep(unsigned gpio); 
void gpio_set_value_cansleep(unsigned gpio, int value); 
```

它们的行为与没有`_cansleep()`名称后缀的访问器完全相同，唯一的区别是它们在访问 GPIO 时阻止内核打印警告。

# 映射到 IRQ 的 GPIO

输入 GPIO 通常可以用作 IRQ 信号。这些 IRQ 可以是边沿触发或电平触发的。配置取决于您的需求。GPIO 控制器负责提供 GPIO 和其 IRQ 之间的映射。可以使用`goio_to_irq()`将给定的 GPIO 号码映射到其 IRQ 号码：

```
int gpio_to_irq(unsigned gpio);
```

返回值是 IRQ 号码，可以调用`request_irq()`（或线程化版本`request_threaded_irq()`）来为此 IRQ 注册处理程序：

```
static irqreturn_t my_interrupt_handler(int irq, void *dev_id) 
{ 
    [...] 
    return IRQ_HANDLED; 
} 

[...] 
int gpio_int = of_get_gpio(np, 0); 
int irq_num = gpio_to_irq(gpio_int); 
int error = devm_request_threaded_irq(&client->dev, irq_num, 
                               NULL, my_interrupt_handler, 
                               IRQF_TRIGGER_RISING | IRQF_ONESHOT, 
                               input_dev->name, my_data_struct); 
if (error) { 
    dev_err(&client->dev, "irq %d requested failed, %d\n", 
        client->irq, error); 
    return error; 
} 
```

# 将所有内容放在一起

以下代码是将所有讨论的关于基于整数的接口的概念付诸实践的摘要。该驱动程序管理四个 GPIO：两个按钮（btn1 和 btn2）和两个 LED（绿色和红色）。Btn1 映射到 IRQ，每当其状态变为 LOW 时，btn2 的状态将应用于 LED。例如，如果 btn1 的状态变为 LOW，而 btn2 的状态为高，则`GREEN`和`RED` led 将被驱动到 HIGH：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/gpio.h>        /* For Legacy integer based GPIO */ 
#include <linux/interrupt.h>   /* For IRQ */ 

static unsigned int GPIO_LED_RED = 49; 
static unsigned int GPIO_BTN1 = 115; 
static unsigned int GPIO_BTN2 = 116; 
static unsigned int GPIO_LED_GREEN = 120; 
static unsigned int irq; 

static irq_handler_t btn1_pushed_irq_handler(unsigned int irq, 
                             void *dev_id, struct pt_regs *regs) 
{ 
    int state; 

    /* read BTN2 value and change the led state */ 
    state = gpio_get_value(GPIO_BTN2); 
    gpio_set_value(GPIO_LED_RED, state); 
    gpio_set_value(GPIO_LED_GREEN, state); 

    pr_info("GPIO_BTN1 interrupt: Interrupt! GPIO_BTN2 state is %d)\n", state); 
    return IRQ_HANDLED; 
} 

static int __init helloworld_init(void) 
{ 
    int retval; 

    /* 
     * One could have checked whether the GPIO is valid on the controller or not, 
     * using gpio_is_valid() function. 
     * Ex: 
     *  if (!gpio_is_valid(GPIO_LED_RED)) { 
     *       pr_infor("Invalid Red LED\n"); 
     *       return -ENODEV; 
     *   } 
     */ 
    gpio_request(GPIO_LED_GREEN, "green-led"); 
    gpio_request(GPIO_LED_RED, "red-led"); 
    gpio_request(GPIO_BTN1, "button-1"); 
    gpio_request(GPIO_BTN2, "button-2"); 

    /* 
     * Configure Button GPIOs as input 
     * 
     * After this, one can call gpio_set_debounce() 
     * only if the controller has the feature 
     * 
     * For example, to debounce a button with a delay of 200ms 
     *  gpio_set_debounce(GPIO_BTN1, 200); 
     */ 
    gpio_direction_input(GPIO_BTN1); 
    gpio_direction_input(GPIO_BTN2); 

    /* 
     * Set LED GPIOs as output, with their initial values set to 0 
     */ 
    gpio_direction_output(GPIO_LED_RED, 0); 
    gpio_direction_output(GPIO_LED_GREEN, 0); 

    irq = gpio_to_irq(GPIO_BTN1); 
    retval = request_threaded_irq(irq, NULL,\ 
                            btn1_pushed_irq_handler, \ 
                            IRQF_TRIGGER_LOW | IRQF_ONESHOT, \ 
                            "device-name", NULL); 

    pr_info("Hello world!\n"); 
    return 0; 
} 

static void __exit hellowolrd_exit(void) 
{ 
    free_irq(irq, NULL); 
    gpio_free(GPIO_LED_RED); 
    gpio_free(GPIO_LED_GREEN); 
    gpio_free(GPIO_BTN1); 
    gpio_free(GPIO_BTN2); 

    pr_info("End of the world\n"); 
} 

module_init(hellowolrd_init); 
module_exit(hellowolrd_exit); 

MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

# 基于描述符的 GPIO 接口：新的推荐方式

使用新的基于描述符的 GPIO 接口，GPIO 由一个连贯的`struct gpio_desc`结构来描述：

```
struct gpio_desc { 
   struct gpio_chip  *chip; 
   unsigned long flags; 
   const char *label; 
}; 
```

应该使用以下标头才能使用新接口：

```
#include <linux/gpio/consumer.h> 
```

使用基于描述符的接口，在分配和拥有 GPIO 之前，这些 GPIO 必须已经映射到某个地方。通过映射，我的意思是它们应该分配给您的设备，而使用传统的基于整数的接口，您只需在任何地方获取一个数字并将其请求为 GPIO。实际上，内核中有三种映射：

+   **平台数据映射**：映射在板文件中完成。

+   **设备树**：映射以 DT 样式完成，与前面的部分讨论的相同。这是我们将在本书中讨论的映射。

+   **高级配置和电源接口映射**（**ACPI**）：映射以 ACPI 样式完成。通常用于基于 x86 的系统。

# GPIO 描述符映射-设备树

GPIO 描述符映射在使用者设备的节点中定义。包含 GPIO 描述符映射的属性必须命名为`<name>-gpios`或`<name>-gpio`，其中`<name>`足够有意义，以描述这些 GPIO 将用于的功能。

应该始终在属性名称后缀加上`-gpio`或`-gpios`，因为每个基于描述符的接口函数都依赖于`gpio_suffixes[]`变量，在`drivers/gpio/gpiolib.h`中定义如下：

```
/* gpio suffixes used for ACPI and device tree lookup */ 
static const char * const gpio_suffixes[] = { "gpios", "gpio" }; 
```

让我们看看在 DT 中查找设备中 GPIO 描述符映射的函数：

```
static struct gpio_desc *of_find_gpio(struct device *dev, 
                                    const char *con_id, 
                                   unsigned int idx, 
                                   enum gpio_lookup_flags *flags) 
{ 
   char prop_name[32]; /* 32 is max size of property name */ 
   enum of_gpio_flags of_flags; 
   struct gpio_desc *desc; 
   unsigned int i; 

   for (i = 0; i < ARRAY_SIZE(gpio_suffixes); i++) { 
         if (con_id) 
               snprintf(prop_name, sizeof(prop_name), "%s-%s", 
                       con_id, 
                      gpio_suffixes[i]); 
         else 
               snprintf(prop_name, sizeof(prop_name), "%s", 
                      gpio_suffixes[i]); 

         desc = of_get_named_gpiod_flags(dev->of_node, 
                                          prop_name, idx, 
                                 &of_flags); 
         if (!IS_ERR(desc) || (PTR_ERR(desc) == -EPROBE_DEFER)) 
               break; 
   } 

   if (IS_ERR(desc)) 
         return desc; 

   if (of_flags & OF_GPIO_ACTIVE_LOW) 
         *flags |= GPIO_ACTIVE_LOW; 

   return desc; 
} 
```

现在，让我们考虑以下节点，这是`Documentation/gpio/board.txt`的摘录：

```
foo_device { 
   compatible = "acme,foo"; 
   [...] 
   led-gpios = <&gpio 15 GPIO_ACTIVE_HIGH>, /* red */ 
               <&gpio 16 GPIO_ACTIVE_HIGH>, /* green */ 
               <&gpio 17 GPIO_ACTIVE_HIGH>; /* blue */ 

   power-gpios = <&gpio 1 GPIO_ACTIVE_LOW>; 
   reset-gpios = <&gpio 1 GPIO_ACTIVE_LOW>; 
}; 
```

这就是映射应该看起来像的，具有有意义的名称。

# 分配和使用 GPIO

可以使用`gpiog_get()`或`gpiod_get_index()`来分配 GPIO 描述符：

```
struct gpio_desc *gpiod_get_index(struct device *dev, 
                                 const char *con_id, 
                                 unsigned int idx, 
                                 enum gpiod_flags flags) 
struct gpio_desc *gpiod_get(struct device *dev, 
                            const char *con_id, 
                            enum gpiod_flags flags) 
```

在错误的情况下，如果没有分配具有给定功能的 GPIO，则这些函数将返回`-ENOENT`，或者可以使用`IS_ERR()`宏的其他错误。第一个函数返回与给定索引处的 GPIO 对应的 GPIO 描述符结构，而第二个函数返回索引为 0 的 GPIO（对于单个 GPIO 映射很有用）。`dev`是 GPIO 描述符将属于的设备。这是你的设备。`con_id`是 GPIO 使用者内的功能。它对应于 DT 中属性名称的`<name>`前缀。`idx`是需要描述符的 GPIO 的索引（从 0 开始）。`flags`是一个可选参数，用于确定 GPIO 初始化标志，以配置方向和/或输出值。它是`include/linux/gpio/consumer.h`中定义的`enum gpiod_flags`的一个实例：

```
enum gpiod_flags { 
    GPIOD_ASIS = 0, 
    GPIOD_IN = GPIOD_FLAGS_BIT_DIR_SET, 
    GPIOD_OUT_LOW = GPIOD_FLAGS_BIT_DIR_SET | 
                    GPIOD_FLAGS_BIT_DIR_OUT, 
    GPIOD_OUT_HIGH = GPIOD_FLAGS_BIT_DIR_SET | 
                     GPIOD_FLAGS_BIT_DIR_OUT | 
                     GPIOD_FLAGS_BIT_DIR_VAL, 
}; 
```

现在让我们为在前面的 DT 中定义的映射分配 GPIO 描述符：

```
struct gpio_desc *red, *green, *blue, *power; 

red = gpiod_get_index(dev, "led", 0, GPIOD_OUT_HIGH); 
green = gpiod_get_index(dev, "led", 1, GPIOD_OUT_HIGH); 
blue = gpiod_get_index(dev, "led", 2, GPIOD_OUT_HIGH); 

power = gpiod_get(dev, "power", GPIOD_OUT_HIGH); 
```

LED GPIO 将是主动高电平，而电源 GPIO 将是主动低电平（即`gpiod_is_active_low(power)`将为 true）。分配的反向操作使用`gpiod_put()`函数完成：

```
gpiod_put(struct gpio_desc *desc); 
```

让我们看看如何释放`red`和`blue` GPIO LED：

```
gpiod_put(blue); 
gpiod_put(red); 
```

在我们继续之前，请记住，除了`gpiod_get()`/`gpiod_get_index()`和`gpio_put()`函数与`gpio_request()`和`gpio_free()`完全不同之外，可以通过将`gpio_`前缀更改为`gpiod_`来执行从基于整数的接口到基于描述符的接口的 API 转换。

也就是说，要更改方向，应该使用`gpiod_direction_input()`和`gpiod_direction_output()`函数：

```
int gpiod_direction_input(struct gpio_desc *desc); 
int gpiod_direction_output(struct gpio_desc *desc, int value); 
```

`value`是在将方向设置为输出后应用于 GPIO 的状态。如果 GPIO 控制器具有此功能，则可以使用其描述符设置给定 GPIO 的去抖动超时：

```
int gpiod_set_debounce(struct gpio_desc *desc, unsigned debounce); 
```

为了访问给定描述符的 GPIO，必须像基于整数的接口一样注意。换句话说，应该注意自己是处于原子（无法休眠）还是非原子上下文中，然后使用适当的函数：

```
int gpiod_cansleep(const struct gpio_desc *desc); 

/* Value get/set from sleeping context */ 
int gpiod_get_value_cansleep(const struct gpio_desc *desc); 
void gpiod_set_value_cansleep(struct gpio_desc *desc, int value); 

/* Value get/set from non-sleeping context */ 
int gpiod_get_value(const struct gpio_desc *desc); 
void gpiod_set_value(struct gpio_desc *desc, int value); 
```

对于映射到 IRQ 的 GPIO 描述符，可以使用`gpiod_to_irq()`来获取与给定 GPIO 描述符对应的 IRQ 编号，然后可以与`request_irq()`函数一起使用：

```
int gpiod_to_irq(const struct gpio_desc *desc); 
```

在代码中的任何时候，可以使用`desc_to_gpio()`或`gpio_to_desc()`函数从基于描述符的接口切换到传统的基于整数的接口，反之亦然：

```
/* Convert between the old gpio_ and new gpiod_ interfaces */ 
struct gpio_desc *gpio_to_desc(unsigned gpio); 
int desc_to_gpio(const struct gpio_desc *desc); 
```

# 把所有东西放在一起

以下是驱动程序总结了描述符接口中介绍的概念。原则是相同的，GPIO 也是一样的：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/platform_device.h>      /* For platform devices */ 
#include <linux/gpio/consumer.h>        /* For GPIO Descriptor */ 
#include <linux/interrupt.h>            /* For IRQ */ 
#include <linux/of.h>                   /* For DT*/ 

/* 
 * Let us consider the below mapping in device tree: 
 * 
 *    foo_device { 
 *       compatible = "packt,gpio-descriptor-sample"; 
 *       led-gpios = <&gpio2 15 GPIO_ACTIVE_HIGH>, // red  
 *                   <&gpio2 16 GPIO_ACTIVE_HIGH>, // green  
 * 
 *       btn1-gpios = <&gpio2 1 GPIO_ACTIVE_LOW>; 
 *       btn2-gpios = <&gpio2 31 GPIO_ACTIVE_LOW>; 
 *   }; 
 */ 

static struct gpio_desc *red, *green, *btn1, *btn2; 
static unsigned int irq; 

static irq_handler_t btn1_pushed_irq_handler(unsigned int irq, 
                              void *dev_id, struct pt_regs *regs) 
{ 
    int state; 

    /* read the button value and change the led state */ 
    state = gpiod_get_value(btn2); 
    gpiod_set_value(red, state); 
    gpiod_set_value(green, state); 

    pr_info("btn1 interrupt: Interrupt! btn2 state is %d)\n", 
              state); 
    return IRQ_HANDLED; 
} 

static const struct of_device_id gpiod_dt_ids[] = { 
    { .compatible = "packt,gpio-descriptor-sample", }, 
    { /* sentinel */ } 
}; 

static int my_pdrv_probe (struct platform_device *pdev) 
{ 
    int retval; 
    struct device *dev = &pdev->dev; 

    /* 
     * We use gpiod_get/gpiod_get_index() along with the flags 
     * in order to configure the GPIO direction and an initial 
     * value in a single function call. 
     * 
     * One could have used: 
     *  red = gpiod_get_index(dev, "led", 0); 
     *  gpiod_direction_output(red, 0); 
     */ 
    red = gpiod_get_index(dev, "led", 0, GPIOD_OUT_LOW); 
    green = gpiod_get_index(dev, "led", 1, GPIOD_OUT_LOW); 

    /* 
     * Configure GPIO Buttons as input 
     * 
     * After this, one can call gpiod_set_debounce() 
     * only if the controller has the feature 
     * For example, to debounce  a button with a delay of 200ms 
     *  gpiod_set_debounce(btn1, 200); 
     */ 
    btn1 = gpiod_get(dev, "led", 0, GPIOD_IN); 
    btn2 = gpiod_get(dev, "led", 1, GPIOD_IN); 

    irq = gpiod_to_irq(btn1); 
    retval = request_threaded_irq(irq, NULL,\ 
                            btn1_pushed_irq_handler, \ 
                            IRQF_TRIGGER_LOW | IRQF_ONESHOT, \ 
                            "gpio-descriptor-sample", NULL); 
    pr_info("Hello! device probed!\n"); 
    return 0; 
} 

static void my_pdrv_remove(struct platform_device *pdev) 
{ 
    free_irq(irq, NULL); 
    gpiod_put(red); 
    gpiod_put(green); 
    gpiod_put(btn1); 
    gpiod_put(btn2); 
    pr_info("good bye reader!\n"); 
} 

static struct platform_driver mypdrv = { 
    .probe      = my_pdrv_probe, 
    .remove     = my_pdrv_remove, 
    .driver     = { 
        .name     = "gpio_descriptor_sample", 
        .of_match_table = of_match_ptr(gpiod_dt_ids),   
        .owner    = THIS_MODULE, 
    }, 
}; 
module_platform_driver(mypdrv); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

# GPIO 接口和设备树

无论需要为什么接口使用 GPIO，如何指定 GPIO 取决于提供它们的控制器，特别是关于其`#gpio-cells`属性，该属性确定用于 GPIO 指定器的单元格数量。 GPIO 指定器至少包含控制器 phandle 和一个或多个参数，其中参数的数量取决于提供 GPIO 的控制器的`#gpio-cells`属性。第一个单元通常是控制器上的 GPIO 偏移量编号，第二个表示 GPIO 标志。

GPIO 属性应命名为`[<name>-]gpios]`，其中`<name>`是设备的 GPIO 用途。请记住，对于基于描述符的接口，这个规则是必须的，并且变成了`<name>-gpios`（注意没有方括号，这意味着`<name>`前缀是必需的）：

```
gpio1: gpio1 { 
    gpio-controller; 
    #gpio-cells = <2>; 
}; 
gpio2: gpio2 { 
    gpio-controller; 
    #gpio-cells = <1>; 
}; 
[...] 

cs-gpios = <&gpio1 17 0>, 
           <&gpio2 2>; 
           <0>, /* holes are permitted, means no GPIO 2 */ 
           <&gpio1 17 0>; 

reset-gpios = <&gpio1 30 0>; 
cd-gpios = <&gpio2 10>; 
```

在前面的示例中，CS GPIO 包含控制器 1 和控制器 2 的 GPIO。如果不需要在列表中指定给定索引处的 GPIO，则可以使用`<0>`。复位 GPIO 有两个单元格（控制器 phandle 之后的两个参数），而 CD GPIO 只有一个单元格。您可以看到我给我的 GPIO 指定器起的名字是多么有意义。

# 传统的基于整数的接口和设备树

该接口依赖于以下标头：

```
#include <linux/of_gpio.h> 
```

当您需要使用传统的基于整数的接口支持 DT 时，您应该记住两个函数：`of_get_named_gpio()`和`of_get_named_gpio_count()`：

```
int of_get_named_gpio(struct device_node *np, 
                      const char *propname, int index) 
int of_get_named_gpio_count(struct device_node *np, 
                      const char* propname) 
```

给定设备节点，前者返回`*propname`属性在`index`位置的 GPIO 编号。第二个只返回属性中指定的 GPIO 数量：

```
int n_gpios = of_get_named_gpio_count(dev.of_node, 
                                    "cs-gpios"); /* return 4 */ 
int second_gpio = of_get_named_gpio(dev.of_node, "cs-gpio", 1); 
int rst_gpio = of_get_named_gpio("reset-gpio", 0); 
gpio_request(second_gpio, "my-gpio); 
```

仍然支持旧的说明符的驱动程序，其中 GPIO 属性命名为`[<name>-gpio`]或`gpios`。在这种情况下，应使用未命名的 API 版本，通过`of_get_gpio()`和`of_gpio_count()`：

```
int of_gpio_count(struct device_node *np) 
int of_get_gpio(struct device_node *np, int index) 
```

DT 节点如下所示：

```
my_node@addr { 
    compatible = "[...]"; 

    gpios = <&gpio1 2 0>, /* INT */ 
            <&gpio1 5 0>; /* RST */ 
    [...] 
}; 
```

驱动程序中的代码如下所示：

```
struct device_node *np = dev->of_node; 

if (!np) 
    return ERR_PTR(-ENOENT); 

int n_gpios = of_gpio_count(); /* Will return 2 */ 
int gpio_int = of_get_gpio(np, 0); 
if (!gpio_is_valid(gpio_int)) { 
    dev_err(dev, "failed to get interrupt gpio\n"); 
    return ERR_PTR(-EINVAL); 
} 

gpio_rst = of_get_gpio(np, 1); 
if (!gpio_is_valid(pdata->gpio_rst)) { 
    dev_err(dev, "failed to get reset gpio\n"); 
    return ERR_PTR(-EINVAL); 
} 
```

可以通过重写第一个驱动程序（基于整数接口的驱动程序）来总结这一点，以符合平台驱动程序结构，并使用 DT API：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/platform_device.h>      /* For platform devices */ 
#include <linux/interrupt.h>            /* For IRQ */ 
#include <linux/gpio.h>        /* For Legacy integer based GPIO */ 
#include <linux/of_gpio.h>     /* For of_gpio* functions */ 
#include <linux/of.h>          /* For DT*/ 

/* 
 * Let us consider the following node 
 * 
 *    foo_device { 
 *       compatible = "packt,gpio-legacy-sample"; 
 *       led-gpios = <&gpio2 15 GPIO_ACTIVE_HIGH>, // red  
 *                   <&gpio2 16 GPIO_ACTIVE_HIGH>, // green  
 * 
 *       btn1-gpios = <&gpio2 1 GPIO_ACTIVE_LOW>; 
 *       btn2-gpios = <&gpio2 1 GPIO_ACTIVE_LOW>; 
 *   }; 
 */ 

static unsigned int gpio_red, gpio_green, gpio_btn1, gpio_btn2; 
static unsigned int irq; 

static irq_handler_t btn1_pushed_irq_handler(unsigned int irq, void *dev_id, 
                            struct pt_regs *regs) 
{ 
    /* The content of this function remains unchanged */ 
    [...] 
} 

static const struct of_device_id gpio_dt_ids[] = { 
    { .compatible = "packt,gpio-legacy-sample", }, 
    { /* sentinel */ } 
}; 

static int my_pdrv_probe (struct platform_device *pdev) 
{ 
    int retval; 
    struct device_node *np = &pdev->dev.of_node; 

    if (!np) 
        return ERR_PTR(-ENOENT); 

    gpio_red = of_get_named_gpio(np, "led", 0); 
    gpio_green = of_get_named_gpio(np, "led", 1); 
    gpio_btn1 = of_get_named_gpio(np, "btn1", 0); 
    gpio_btn2 = of_get_named_gpio(np, "btn2", 0); 

    gpio_request(gpio_green, "green-led"); 
    gpio_request(gpio_red, "red-led"); 
    gpio_request(gpio_btn1, "button-1"); 
    gpio_request(gpio_btn2, "button-2"); 

    /* Code to configure GPIO and request IRQ remains unchanged */ 
    [...] 
    return 0; 
} 

static void my_pdrv_remove(struct platform_device *pdev) 
{ 
    /* The content of this function remains unchanged */ 
    [...] 
} 

static struct platform_driver mypdrv = { 
    .probe  = my_pdrv_probe, 
    .remove = my_pdrv_remove, 
    .driver = { 
    .name   = "gpio_legacy_sample", 
            .of_match_table = of_match_ptr(gpio_dt_ids),   
            .owner    = THIS_MODULE, 
    }, 
}; 
module_platform_driver(mypdrv); 

MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

# 设备树中的 GPIO 映射到 IRQ

可以轻松地在设备树中将 GPIO 映射到 IRQ。使用两个属性来指定中断：

+   `interrupt-parent`：这是 GPIO 的 GPIO 控制器

+   `interrupts`：这是中断说明符列表

这适用于传统和基于描述符的接口。 IRQ 说明符取决于提供此 GPIO 的 GPIO 控制器的`#interrupt-cell`属性。 `#interrupt-cell`确定在指定中断时使用的单元数。通常，第一个单元表示要映射到 IRQ 的 GPIO 编号，第二个单元表示应触发中断的电平/边缘。无论如何，中断说明符始终取决于其父级（具有设置中断控制器的父级），因此请参考内核源中的绑定文档：

```
gpio4: gpio4 { 
    gpio-controller; 
    #gpio-cells = <2>; 
    interrupt-controller; 
    #interrupt-cells = <2>; 
}; 

my_label: node@0 { 
    reg = <0>; 
    spi-max-frequency = <1000000>; 
    interrupt-parent = <&gpio4>; 
    interrupts = <29 IRQ_TYPE_LEVEL_LOW>; 
}; 
```

获取相应的 IRQ 有两种解决方案：

1.  **您的设备位于已知总线（I2C 或 SPI）上**：IRQ 映射将由您完成，并通过`struct i2c_client`或`struct spi_device`结构通过`probe()`函数（通过`i2c_client.irq`或`spi_device.irq`）提供。

1.  **您的设备位于伪平台总线上**：`probe()`函数将获得一个`struct platform_device`，您可以在其中调用`platform_get_irq()`：

```
int platform_get_irq(struct platform_device *dev, unsigned int num); 
```

随意查看第六章，*设备树的概念*。

# GPIO 和 sysfs

sysfs GPIO 接口允许人们通过集或文件管理和控制 GPIO。它位于`/sys/class/gpio`下。设备模型在这里被广泛使用，有三种类型的条目可用：

+   `/sys/class/gpio/：`这是一切的开始。此目录包含两个特殊文件，`export`和`unexport`：

+   `export`：这允许我们要求内核将给定 GPIO 的控制权导出到用户空间，方法是将其编号写入此文件。例如：`echo 21 > export`将为 GPIO＃21 创建一个 GPIO21 节点，如果内核代码没有请求。

+   `unexport`：这将撤消向用户空间的导出效果。例如：`echo 21 > unexport`将删除使用导出文件导出的任何 GPIO21 节点。

+   `/sys/class/gpio/gpioN/`：此目录对应于 GPIO 编号 N（其中 N 是系统全局的，而不是相对于芯片），可以使用`export`文件导出，也可以在内核内部导出。例如：`/sys/class/gpio/gpio42/`（对于 GPIO＃42）具有以下读/写属性：

+   `direction`文件用于获取/设置 GPIO 方向。允许的值是`in`或`out`字符串。通常可以写入此值。写入`out`会将值初始化为低。为了确保无故障操作，可以写入低值和高值以将 GPIO 配置为具有该初始值的输出。如果内核代码已导出此 GPIO，则不会存在此属性，从而禁用方向（请参阅`gpiod_export()`或`gpio_export()`函数）。

+   `value`属性允许我们根据方向（输入或输出）获取/设置 GPIO 线的状态。如果 GPIO 配置为输出，写入任何非零值将被视为高电平状态。如果配置为输出，写入`0`将使输出低电平，而`1`将使输出高电平。如果引脚可以配置为产生中断的线，并且已配置为生成中断，则可以在该文件上调用`poll(2)`系统调用，`poll(2)`将在中断触发时返回。使用`poll(2)`将需要设置事件`POLLPRI`和`POLLERR`。如果使用`select(2)`，则应在`exceptfds`中设置文件描述符。`poll(2)`返回后，要么`lseek(2)`到 sysfs 文件的开头并读取新值，要么关闭文件并重新打开以读取值。这与我们讨论的可轮询 sysfs 属性的原理相同。

+   `edge`确定了将让`poll()`或`select()`函数返回的信号边缘。允许的值为`none`，`rising`，`falling`或`both`。此文件可读/可写，仅在引脚可以配置为产生中断的输入引脚时存在。

+   `active_low`读取为 0（假）或 1（真）。写入任何非零值将反转*value*属性的读取和写入。现有和随后的`poll(2)`支持通过边缘属性进行配置，用于上升和下降边缘，将遵循此设置。内核中设置此值的相关函数是`gpio_sysf_set_active_low()`。

# 从内核代码中导出 GPIO

除了使用`/sys/class/gpio/export`文件将 GPIO 导出到用户空间外，还可以使用内核代码中的`gpio_export`（用于传统接口）或`gpioD_export`（新接口）等函数来显式管理已经使用`gpio_request()`或`gpiod_get()`请求的 GPIO 的导出：

```
int gpio_export(unsigned gpio, bool direction_may_change); 

int gpiod_export(struct gpio_desc *desc, bool direction_may_change); 
```

`direction_may_change`参数决定是否可以从输入更改信号方向为输出，反之亦然。内核的反向操作是`gpio_unexport()`或`gpiod_unexport()`：

```
void gpio_unexport(unsigned gpio); /* Integer-based interface */ 
void gpiod_unexport(struct gpio_desc *desc) /* Descriptor-based */ 
```

一旦导出，可以使用`gpio_export_link()`（或`gpiod_export_link()`用于基于描述符的接口）来创建符号链接，从 sysfs 的其他位置指向 GPIO sysfs 节点。驱动程序可以使用此功能在 sysfs 中的自己设备下提供接口，并提供描述性名称：

```
int gpio_export_link(struct device *dev, const char *name, 
                      unsigned gpio) 
int gpiod_export_link(struct device *dev, const char *name, 
                      struct gpio_desc *desc) 
```

可以在基于描述符的接口的`probe()`函数中使用如下：

```
static struct gpio_desc *red, *green, *btn1, *btn2; 

static int my_pdrv_probe (struct platform_device *pdev) 
{ 
    [...] 
    red = gpiod_get_index(dev, "led", 0, GPIOD_OUT_LOW); 
    green = gpiod_get_index(dev, "led", 1, GPIOD_OUT_LOW); 

    gpiod_export(&pdev->dev, "Green_LED", green); 
    gpiod_export(&pdev->dev, "Red_LED", red); 

       [...] 
    return 0; 
} 
```

对于基于整数的接口，代码如下：

```
static int my_pdrv_probe (struct platform_device *pdev) 
{ 
    [...] 

    gpio_red = of_get_named_gpio(np, "led", 0); 
    gpio_green = of_get_named_gpio(np, "led", 1); 
    [...] 

    int gpio_export_link(&pdev->dev, "Green_LED", gpio_green) 
    int gpio_export_link(&pdev->dev, "Red_LED", gpio_red) 
    return 0; 
} 
```

# 摘要

在本章中，我们展示了在内核中处理 GPIO 是一项简单的任务。讨论了传统接口和新接口，为您提供了选择适合您需求的接口的可能性，以编写增强的 GPIO 驱动程序。您将能够处理映射到 GPIO 的中断请求。下一章将处理提供和公开 GPIO 线的芯片，称为 GPIO 控制器。
