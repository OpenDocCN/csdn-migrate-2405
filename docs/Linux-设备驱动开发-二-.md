# Linux 设备驱动开发（二）

> 原文：[`zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E`](https://zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：字符设备驱动程序

字符设备通过字符的方式（一个接一个）向用户应用程序传输数据，就像串行端口一样。字符设备驱动程序通过`/dev`目录中的特殊文件公开设备的属性和功能，可以用来在设备和用户应用程序之间交换数据，并且还允许你控制真实的物理设备。这是 Linux 的基本概念，即*一切都是文件*。字符设备驱动程序代表内核源代码中最基本的设备驱动程序。字符设备在内核中表示为`include/linux/cdev.h`中定义的`struct cdev`的实例：

```
struct cdev { 
    struct kobject kobj; 
    struct module *owner; 
    const struct file_operations *ops; 
    struct list_head list; 
    dev_t dev; 
    unsigned int count; 
}; 
```

本章将介绍字符设备驱动程序的具体特性，解释它们如何创建、识别和向系统注册设备，还将更好地概述设备文件方法，这些方法是内核向用户空间公开设备功能的方法，可通过使用与文件相关的系统调用（`read`，`write`，`select`，`open`，`close`等）访问，描述在`struct file_operations`结构中，这些你肯定以前听说过。

# 主要和次要背后的概念

字符设备位于`/dev`目录中。请注意，它们不是该目录中唯一的文件。字符设备文件可以通过其类型识别，我们可以通过`ls -l`命令显示。主要和次要标识并将设备与驱动程序绑定。让我们看看它是如何工作的，通过列出`*/dev*`目录的内容（`ls -l /dev`）：

```
[...]

drwxr-xr-x 2 root root 160 Mar 21 08:57 input

crw-r----- 1 root kmem 1, 2 Mar 21 08:57 kmem

lrwxrwxrwx 1 root root 28 Mar 21 08:57 log -> /run/systemd/journal/dev-log

crw-rw---- 1 root disk 10, 237 Mar 21 08:57 loop-control

brw-rw---- 1 root disk 7, 0 Mar 21 08:57 loop0

brw-rw---- 1 root disk 7, 1 Mar 21 08:57 loop1

brw-rw---- 1 root disk 7, 2 Mar 21 08:57 loop2

brw-rw---- 1 root disk 7, 3 Mar 21 08:57 loop3

```

给定上述摘录，第一列的第一个字符标识文件类型。可能的值有：

+   `c`：这是用于字符设备文件

+   `b`：这是用于块设备文件

+   `l`：这是用于符号链接

+   `d`：这是用于目录

+   `s`：这是用于套接字

+   `p`：这是用于命名管道

对于`b`和`c`文件类型，在日期之前的第五和第六列遵循<`X，Y`>模式。`X`代表主要号，`Y`是次要号。例如，第三行是<`1，2`>，最后一行是<`7，3`>。这是一种从用户空间识别字符设备文件及其主要和次要的经典方法之一。

内核在`dev_t`类型变量中保存标识设备的数字，它们只是`u32`（32 位无符号长整型）。主要号仅用 12 位表示，而次要号编码在剩余的 20 位上。

正如可以在`include/linux/kdev_t.h`中看到的，给定一个`dev_t`类型的变量，可能需要提取次要或主要。内核为这些目的提供了一个宏：

```
MAJOR(dev_t dev); 
MINOR(dev_t dev); 
```

另一方面，你可能有一个次要和一个主要，需要构建一个`dev_t`。你应该使用的宏是`MKDEV(int major, int minor);`：

```
#define MINORBITS    20 
#define MINORMASK    ((1U << MINORBITS) - 1) 
#define MAJOR(dev)   ((unsigned int) ((dev) >> MINORBITS)) 
#define MINOR(dev)   ((unsigned int) ((dev) & MINORMASK)) 
#define MKDEV(ma,mi) (((ma) << MINORBITS) | (mi)) 
```

设备注册时使用一个标识设备的主要号和一个次要号，可以将次要号用作本地设备列表的数组索引，因为同一驱动程序的一个实例可能处理多个设备，而不同的驱动程序可能处理相同类型的不同设备。

# 设备号分配和释放

设备号标识系统中的设备文件。这意味着，有两种分配这些设备号（实际上是主要和次要）的方法：

+   **静态**：使用`register_chrdev_region()`函数猜测尚未被其他驱动程序使用的主要号。应尽量避免使用这个。它的原型如下：

```
   int register_chrdev_region(dev_t first, unsigned int count, \ 
                             char *name); 
```

该方法在成功时返回`0`，在失败时返回负错误代码。`first`由我们需要的主要号和所需范围的第一个次要号组成。应该使用`MKDEV(ma,mi)`。`count`是所需的连续设备号的数量，`name`应该是相关设备或驱动程序的名称。

+   **动态地**：让内核为我们做这件事，使用`alloc_chrdev_region()`函数。这是获取有效设备号的推荐方法。它的原型如下：

```
int alloc_chrdev_region(dev_t *dev, unsigned int firstminor, \ 
                        unsigned int count, char *name); 
```

该方法在成功时返回`0`，在失败时返回负错误代码。`dev`是唯一的输出参数。它代表内核分配的第一个号码。`firstminor`是请求的次要号码范围的第一个，`count`是所需的次要号码数量，`name`应该是相关设备或驱动程序的名称。

两者之间的区别在于，对于前者，我们应该预先知道我们需要什么号码。这是注册：告诉内核我们想要什么设备号。这可能用于教学目的，并且只要驱动程序的唯一用户是您，它就可以工作。但是当要在另一台机器上加载驱动程序时，无法保证所选的号码在该机器上是空闲的，这将导致冲突和麻烦。第二种方法更干净、更安全，因为内核负责为我们猜测正确的号码。我们甚至不必关心在将模块加载到另一台机器上时的行为会是什么，因为内核会相应地进行调整。

无论如何，通常不直接从驱动程序中调用前面的函数，而是通过驱动程序依赖的框架（IIO 框架、输入框架、RTC 等）通过专用 API 进行屏蔽。这些框架在本书的后续章节中都有讨论。

# 设备文件操作简介

可以在文件上执行的操作取决于管理这些文件的驱动程序。这些操作在内核中被定义为`struct file_operations`的实例。`struct file_operations`公开了一组回调函数，这些函数将处理文件上的任何用户空间系统调用。例如，如果希望用户能够对表示我们设备的文件执行`write`操作，就必须实现与`write`函数对应的回调，并将其添加到与您的设备绑定的`struct file_operations`中。让我们填写一个文件操作结构：

```
struct file_operations { 
    struct module *owner; 
    loff_t (*llseek) (struct file *, loff_t, int); 
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *); 
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *); 
    unsigned int (*poll) (struct file *, struct poll_table_struct *); 
    int (*mmap) (struct file *, struct vm_area_struct *); 
    int (*open) (struct inode *, struct file *); 
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long); 
    int (*release) (struct inode *, struct file *); 
    int (*fsync) (struct file *, loff_t, loff_t, int datasync); 
    int (*fasync) (int, struct file *, int); 
    int (*lock) (struct file *, int, struct file_lock *); 
    int (*flock) (struct file *, int, struct file_lock *); 
   [...] 
}; 
```

前面的摘录只列出了结构的重要方法，特别是对本书需求相关的方法。可以在内核源码的`include/linux/fs.h`中找到完整的描述。这些回调函数中的每一个都与系统调用相关联，没有一个是强制性的。当用户代码对给定文件调用与文件相关的系统调用时，内核会寻找负责该文件的驱动程序（特别是创建文件的驱动程序），找到其`struct file_operations`结构，并检查与系统调用匹配的方法是否已定义。如果是，就简单地运行它。如果没有，就返回一个错误代码，这取决于系统调用。例如，未定义的`(*mmap)`方法将返回`-ENODEV`给用户，而未定义的`(*write)`方法将返回`-EINVAL`。

# 内核中的文件表示

内核将文件描述为`struct inode`的实例（而不是`struct file`），该结构在`include/linux/fs.h`中定义：

```
struct inode { 
    [...] 
   struct pipe_inode_info *i_pipe;     /* Set and used if this is a 
 *linux kernel pipe */ 
   struct block_device *i_bdev;  /* Set and used if this is a 
 * a block device */ 
   struct cdev       *i_cdev;    /* Set and used if this is a 
 * character device */ 
    [...] 
} 
```

`struct inode`是一个文件系统数据结构，保存着关于文件（无论其类型是字符、块、管道等）或目录（是的！从内核的角度来看，目录是一个文件，它指向其他文件）的与操作系统相关的信息。

`struct file`结构（也在`include/linux/fs.h`中定义）实际上是内核中表示打开文件的更高级别的文件描述，它依赖于较低级别的`struct inode`数据结构：

```
struct file { 
   [...] 
   struct path f_path;                /* Path to the file */ 
   struct inode *f_inode;             /* inode associated to this file */ 
   const struct file_operations *f_op;/* operations that can be 
          * performed on this file 
          */ 
   loff_t f_pos;                       /* Position of the cursor in 
 * this file */ 
   /* needed for tty driver, and maybe others */ 
   void *private_data;     /* private data that driver can set 
                            * in order to share some data between file 
                            * operations. This can point to any data 
                            * structure. 
 */ 
[...] 
} 
```

`struct inode`和`struct file`之间的区别在于 inode 不跟踪文件内的当前位置或当前模式。它只包含帮助操作系统找到底层文件结构（管道、目录、常规磁盘文件、块/字符设备文件等）内容的东西。另一方面，`struct file`被用作通用结构（实际上它持有一个指向`struct inode`结构的指针），代表并打开文件并提供一组与在底层文件结构上执行的方法相关的函数。这些方法包括：`open`，`write`，`seek`，`read`，`select`等。所有这些都强调了 UNIX 系统的哲学，即*一切皆为文件*。

换句话说，`struct inode`代表内核中的一个文件，`struct file`描述了它在实际打开时的情况。可能有不同的文件描述符代表同一个文件被多次打开，但这些将指向相同的 inode。

# 分配和注册字符设备

在内核中，字符设备被表示为`struct cdev`的实例。当编写字符设备驱动程序时，您的目标是最终创建并注册与`struct file_operations`相关联的该结构的实例，暴露一组用户空间可以对设备执行的操作（函数）。为了实现这个目标，我们必须经历一些步骤，如下所示：

1.  使用`alloc_chrdev_region()`保留一个主设备号和一系列次设备号。

1.  使用`class_create()`为您的设备创建一个类，在`/sys/class/`中可见。

1.  设置一个`struct file_operation`（要提供给`cdev_init`），并为每个需要创建的设备调用`cdev_init()`和`cdev_add()`来注册设备。

1.  然后为每个设备创建一个`device_create()`，并赋予一个适当的名称。这将导致您的设备在`/dev`目录中被创建：

```
#define EEP_NBANK 8 
#define EEP_DEVICE_NAME "eep-mem" 
#define EEP_CLASS "eep-class" 

struct class *eep_class; 
struct cdev eep_cdev[EEP_NBANK]; 
dev_t dev_num; 

static int __init my_init(void) 
{ 
    int i; 
    dev_t curr_dev; 

    /* Request the kernel for EEP_NBANK devices */ 
    alloc_chrdev_region(&dev_num, 0, EEP_NBANK, EEP_DEVICE_NAME); 

    /* Let's create our device's class, visible in /sys/class */ 
    eep_class = class_create(THIS_MODULE, EEP_CLASS); 

    /* Each eeprom bank represented as a char device (cdev)   */ 
    for (i = 0; i < EEP_NBANK; i++) { 

        /* Tie file_operations to the cdev */ 
        cdev_init(&my_cdev[i], &eep_fops); 
        eep_cdev[i].owner = THIS_MODULE; 

        /* Device number to use to add cdev to the core */ 
        curr_dev = MKDEV(MAJOR(dev_num), MINOR(dev_num) + i); 

        /* Now make the device live for the users to access */ 
        cdev_add(&eep_cdev[i], curr_dev, 1); 

        /* create a device node each device /dev/eep-mem0, /dev/eep-mem1, 
         * With our class used here, devices can also be viewed under 
         * /sys/class/eep-class. 
         */ 
        device_create(eep_class, 
                      NULL,     /* no parent device */ 
                      curr_dev, 
                      NULL,     /* no additional data */ 
                      EEP_DEVICE_NAME "%d", i); /* eep-mem[0-7] */ 
    } 
    return 0; 
} 
```

# 编写文件操作

在引入上述文件操作之后，是时候实现它们以增强驱动程序的功能并将设备的方法暴露给用户空间（通过系统调用）。这些方法各有其特点，我们将在本节中进行重点介绍。

# 在内核空间和用户空间之间交换数据

本节不描述任何驱动程序文件操作，而是介绍一些内核设施，可以用来编写这些驱动程序方法。驱动程序的`write()`方法包括从用户空间读取数据到内核空间，然后从内核处理该数据。这样的处理可能是像*推送*数据到设备一样。另一方面，驱动程序的`read()`方法包括将数据从内核复制到用户空间。这两种方法都引入了我们需要在跳转到各自步骤之前讨论的新元素。第一个是`__user`。`__user`是由稀疏（内核用于查找可能的编码错误的语义检查器）使用的一个标记，用于让开发人员知道他实际上将要不正确地使用一个不受信任的指针（或者在当前虚拟地址映射中可能无效的指针），并且他不应该解引用，而应该使用专用的内核函数来访问该指针指向的内存。

这使我们能够引入不同的内核函数，以便访问这样的内存，无论是读取还是写入。这些分别是`copy_from_user()`和`copy_from_user()`，用于将缓冲区从用户空间复制到内核空间，反之亦然，将缓冲区从内核复制到用户空间：

```
unsigned long copy_from_user(void *to, const void __user *from, 
                             unsigned long n) 
unsigned long copy_to_user(void __user *to, const void *from, 
                              unsigned long n) 
```

在这两种情况下，以`__user`为前缀的指针指向用户空间（不受信任）内存。`n`代表要复制的字节数。`from`代表源地址，`to`是目标地址。这些返回未能复制的字节数。成功时，返回值应为`0`。

请注意，使用`copy_to_user（）`，如果无法复制某些数据，函数将使用零字节填充已复制的数据以达到请求的大小。

# 单个值复制

在复制`char`和`int`等单个和简单变量时，但不是在复制结构或数组等较大的数据类型时，内核提供了专用宏以快速执行所需的操作。这些宏是`put_user(x, ptr)`和`get_used(x, ptr)`，解释如下：

+   `put_user(x, ptr);`：此宏将变量从内核空间复制到用户空间。`x`表示要复制到用户空间的值，`ptr`是用户空间中的目标地址。该宏在成功时返回`0`，在错误时返回`-EFAULT`。`x`必须可分配给解引用`ptr`的结果。换句话说，它们必须具有（或指向）相同的类型。

+   `get_user(x, ptr);`：此宏将变量从用户空间复制到内核空间，并在成功时返回`0`，在错误时返回`-EFAULT`。请注意，错误时`x`设置为`0`。`x`表示要存储结果的内核变量，`ptr`是用户空间中的源地址。解引用`ptr`的结果必须可分配给`x`而不需要转换。猜猜它是什么意思。

# 打开方法

`open`是每次有人打开设备文件时调用的方法。如果未定义此方法，则设备打开将始终成功。通常使用此方法来执行设备和数据结构初始化，并在出现问题时返回负错误代码，或`0`。`open`方法的原型定义如下：

```
int (*open)(struct inode *inode, struct file *filp); 
```

# 每个设备的数据

对于在您的字符设备上执行的每个`open`，回调函数将以`struct inode`作为参数，该参数是文件的内核底层表示。该`struct inode`结构具有一个名为`i_cdev`的字段，指向我们在`init`函数中分配的`cdev`。通过在以下示例中的`struct pcf2127`中将`struct cdev`嵌入到我们的设备特定数据中，我们将能够使用`container_of`宏获取指向该特定数据的指针。以下是一个`open`方法示例。

以下是我们的数据结构：

```
struct pcf2127 { 
    struct cdev cdev; 
    unsigned char *sram_data; 
    struct i2c_client *client; 
    int sram_size; 
    [...] 
}; 
```

根据这个数据结构，`open`方法将如下所示：

```
static unsigned int sram_major = 0; 
static struct class *sram_class = NULL; 

static int sram_open(struct inode *inode, struct file *filp) 
{ 
   unsigned int maj = imajor(inode); 
   unsigned int min = iminor(inode); 

   struct pcf2127 *pcf = NULL; 
   pcf = container_of(inode->i_cdev, struct pcf2127, cdev); 
   pcf->sram_size = SRAM_SIZE; 

   if (maj != sram_major || min < 0 ){ 
         pr_err ("device not found\n"); 
         return -ENODEV; /* No such device */ 
   } 

   /* prepare the buffer if the device is opened for the first time */ 
   if (pcf->sram_data == NULL) { 
         pcf->sram_data = kzalloc(pcf->sram_size, GFP_KERNEL); 
         if (pcf->sram_data == NULL) { 
               pr_err("Open: memory allocation failed\n"); 
               return -ENOMEM; 
         } 
   } 
   filp->private_data = pcf; 
   return 0; 
} 
```

# 释放方法

当设备关闭时，将调用`release`方法，这是`open`方法的反向操作。然后，您必须撤消在打开任务中所做的一切。您大致要做的是：

1.  释放在“open（）”步骤中分配的任何私有内存。

1.  关闭设备（如果支持），并在最后关闭时丢弃每个缓冲区（如果设备支持多次打开，或者驱动程序可以同时处理多个设备）。

以下是`release`函数的摘录：

```
static int sram_release(struct inode *inode, struct file *filp) 
{ 
   struct pcf2127 *pcf = NULL; 
   pcf = container_of(inode->i_cdev, struct pcf2127, cdev); 

   mutex_lock(&device_list_lock); 
   filp->private_data = NULL; 

   /* last close? */ 
   pcf2127->users--; 
   if (!pcf2127->users) { 
         kfree(tx_buffer); 
         kfree(rx_buffer); 
         tx_buffer = NULL; 
         rx_buffer = NULL; 

         [...] 

         if (any_global_struct) 
               kfree(any_global_struct); 
   } 
   mutex_unlock(&device_list_lock); 

   return 0; 
} 
```

# 写入方法

“write（）”方法用于向设备发送数据；每当用户应用程序在设备文件上调用`write`函数时，将调用内核实现。其原型如下：

```
ssize_t(*write)(struct file *filp, const char __user *buf, size_t count, loff_t *pos); 
```

+   返回值是写入的字节数（大小）

+   `*buf`表示来自用户空间的数据缓冲区

+   `count`是请求传输的大小

+   `*pos`表示应在文件中写入数据的起始位置

# 写入步骤

以下步骤不描述任何标准或通用的方法来实现驱动程序的“write（）”方法。它们只是概述了在此方法中可以执行的操作类型。

1.  检查来自用户空间的错误或无效请求。如果设备公开其内存（eeprom、I/O 内存等），可能存在大小限制，则此步骤才相关：

```
/* if trying to Write beyond the end of the file, return error. 
 * "filesize" here corresponds to the size of the device memory (if any) 
 */ 
if ( *pos >= filesize ) return -EINVAL; 
```

1.  调整`count`以便不超出文件大小的剩余字节。这一步骤不是强制性的，与步骤 1 的条件相同：

```
/* filesize coerresponds to the size of device memory */ 
if (*pos + count > filesize)  
    count = filesize - *pos; 
```

1.  找到要开始写入的位置。如果设备具有内存，供“write（）”方法写入给定数据，则此步骤才相关。与步骤 2 和 3 一样，此步骤不是强制性的：

```
/* convert pos into valid address */ 
void *from = pos_to_address( *pos );  
```

1.  从用户空间复制数据并将其写入适当的内核空间：

```
if (copy_from_user(dev->buffer, buf, count) != 0){ 
    retval = -EFAULT; 
    goto out; 
} 
/* now move data from dev->buffer to physical device */ 
```

1.  写入物理设备并在失败时返回错误：

```
write_error = device_write(dev->buffer, count); 
if ( write_error ) 
    return -EFAULT; 
```

1.  根据写入的字节数增加文件中光标的当前位置。最后，返回复制的字节数：

```
*pos += count; 
Return count; 
```

以下是`write`方法的一个示例。再次强调，这旨在给出一个概述：

```
ssize_t  
eeprom_write(struct file *filp, const char __user *buf, size_t count, 
   loff_t *f_pos) 
{ 
   struct eeprom_dev *eep = filp->private_data; 
   ssize_t retval = 0; 

    /* step (1) */ 
    if (*f_pos >= eep->part_size)  
        /* Writing beyond the end of a partition is not allowed. */ 
        return -EINVAL; 

    /* step (2) */ 
    if (*pos + count > eep->part_size) 
        count = eep->part_size - *pos; 

   /* step (3) */ 
   int part_origin = PART_SIZE * eep->part_index; 
   int register_address = part_origin + *pos; 

    /* step(4) */ 
    /* Copy data from user space to kernel space */ 
    if (copy_from_user(eep->data, buf, count) != 0) 
        return -EFAULT; 

       /* step (5) */ 
    /* perform the write to the device */ 
    if (write_to_device(register_address, buff, count) < 0){ 
        pr_err("ee24lc512: i2c_transfer failed\n");   
        return -EFAULT; 
     } 

    /* step (6) */ 
    *f_pos += count; 
    return count; 
} 
```

# 读取方法

`read()`方法的原型如下：

```
ssize_t (*read) (struct file *filp, char __user *buf, size_t count, loff_t *pos);
```

返回值是读取的大小。方法的其余元素在这里描述：

+   `*buf`是我们从用户空间接收的缓冲区

+   `count` 是请求传输的大小（用户缓冲区的大小）

+   `*pos`指示应从文件中读取数据的起始位置

# 读取步骤

1.  防止读取超出文件大小，并返回文件末尾：

```
if (*pos >= filesize) 
  return 0; /* 0 means EOF */ 
```

1.  读取的字节数不能超过文件大小。相应地调整`count`：

```
if (*pos + count > filesize) 
    count = filesize - (*pos); 
```

1.  找到将开始读取的位置：

```
void *from = pos_to_address (*pos); /* convert pos into valid address */ 
```

1.  将数据复制到用户空间缓冲区，并在失败时返回错误：

```
sent = copy_to_user(buf, from, count); 
if (sent) 
    return -EFAULT; 
```

1.  根据读取的字节数提前文件的当前位置，并返回复制的字节数：

```
*pos += count; 
Return count; 
```

以下是一个驱动程序`read()`文件操作的示例，旨在概述可以在那里完成的工作：

```
ssize_t  eep_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) 
{ 
    struct eeprom_dev *eep = filp->private_data; 

    if (*f_pos >= EEP_SIZE) /* EOF */ 
        return 0; 

    if (*f_pos + count > EEP_SIZE) 
        count = EEP_SIZE - *f_pos; 

    /* Find location of next data bytes */ 
    int part_origin  =  PART_SIZE * eep->part_index; 
    int eep_reg_addr_start  =  part_origin + *pos; 

    /* perform the read from the device */ 
    if (read_from_device(eep_reg_addr_start, buff, count) < 0){ 
        pr_err("ee24lc512: i2c_transfer failed\n");   
        return -EFAULT; 
    }  

    /* copy from kernel to user space */ 
    if(copy_to_user(buf, dev->data, count) != 0) 
        return -EIO; 

    *f_pos += count; 
    return count; 
} 
```

# llseek 方法

当在文件内移动光标位置时，将调用`llseek`函数。该方法在用户空间的入口点是`lseek()`。可以参考 man 页面以打印用户空间中任一方法的完整描述：`man llseek`和`man lseek`。其原型如下：

```
loff_t(*llseek) (structfile *filp, loff_t offset, int whence); 
```

+   返回值是文件中的新位置

+   `loff_t`是相对于当前文件位置的偏移量，定义了它将被改变多少

+   `whence`定义了从哪里寻找。可能的值有：

+   `SEEK_SET`：这将光标放置在相对于文件开头的位置

+   `SEEK_CUR`：这将光标放置在相对于当前文件位置的位置

+   `SEEK_END`：这将光标调整到相对于文件末尾的位置

# llseek 步骤

1.  使用`switch`语句检查每种可能的`whence`情况，因为它们是有限的，并相应地调整`newpos`：

```
switch( whence ){ 
    case SEEK_SET:/* relative from the beginning of file */ 
        newpos = offset; /* offset become the new position */ 
        break; 
    case SEEK_CUR: /* relative to current file position */ 
        newpos = file->f_pos + offset; /* just add offset to the current position */ 
        break; 
    case SEEK_END: /* relative to end of file */ 
        newpos = filesize + offset; 
        break; 
    default: 
        return -EINVAL; 
} 
```

1.  检查`newpos`是否有效：

```
if ( newpos < 0 ) 
    return -EINVAL; 
```

1.  使用新位置更新`f_pos`：

```
filp->f_pos = newpos; 
```

1.  返回新的文件指针位置：

```
return newpos; 
```

以下是一个连续读取和搜索文件的用户程序示例。底层驱动程序将执行`llseek()`文件操作入口：

```
#include <unistd.h> 
#include <fcntl.h> 
#include <sys/types.h> 
#include <stdio.h> 

#define CHAR_DEVICE "toto.txt" 

int main(int argc, char **argv) 
{ 
    int fd= 0; 
    char buf[20]; 

    if ((fd = open(CHAR_DEVICE, O_RDONLY)) < -1) 
        return 1; 

    /* Read 20 bytes */ 
    if (read(fd, buf, 20) != 20) 
        return 1; 
    printf("%s\n", buf); 

    /* Move the cursor to 10 time, relative to its actual position */ 
    if (lseek(fd, 10, SEEK_CUR) < 0) 
        return 1; 
    if (read(fd, buf, 20) != 20)  
        return 1; 
    printf("%s\n",buf); 

    /* Move the cursor ten time, relative from the beginig of the file */ 
    if (lseek(fd, 7, SEEK_SET) < 0) 
        return 1; 
    if (read(fd, buf, 20) != 20) 
        return 1; 
    printf("%s\n",buf); 

    close(fd); 
    return 0; 
} 
```

代码产生以下输出：

```
jma@jma:~/work/tutos/sources$ cat toto.txt

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

jma@jma:~/work/tutos/sources$ ./seek

Lorem ipsum dolor si

nsectetur adipiscing

psum dolor sit amet,

jma@jma:~/work/tutos/sources$

```

# 轮询方法

如果需要实现被动等待（在感知字符设备时不浪费 CPU 周期），必须实现`poll()`函数，每当用户空间程序对与设备关联的文件执行`select()`或`poll()`系统调用时都会调用该函数：

```
unsigned int (*poll) (struct file *, struct poll_table_struct *); 
```

这个方法的核心是`poll_wait()`内核函数，定义在`<linux/poll.h>`中，这是驱动程序代码中应该包含的头文件：

```
void poll_wait(struct file * filp, wait_queue_head_t * wait_address, 
poll_table *p) 
```

`poll_wait()`将与`struct file`结构（作为第一个参数给出）相关联的设备添加到可以唤醒进程的列表中（这些进程已经在`struct wait_queue_head_t`结构中休眠，该结构作为第二个参数给出），根据在`struct poll_table`结构中注册的事件（作为第三个参数给出）。用户进程可以运行`poll()`，`select()`或`epoll()`系统调用，将一组文件添加到等待的列表中，以便了解相关（如果有）设备的准备情况。然后内核将调用与每个设备文件相关联的驱动程序的`poll`入口。然后，每个驱动程序的`poll`方法应调用`poll_wait()`以注册进程需要被内核通知的事件，将该进程置于休眠状态，直到其中一个事件发生，并将驱动程序注册为可以唤醒该进程的驱动程序之一。通常的方法是根据`select()`（或`poll()`）系统调用支持的事件类型使用一个等待队列（一个用于可读性，另一个用于可写性，如果需要的话，最终还有一个用于异常）。

`(*poll)`文件操作的返回值必须设置为`POLLIN | POLLRDNORM`，如果有数据可读（在调用 select 或 poll 时），如果设备可写，则设置为`POLLOUT | POLLWRNORM`（在这里也是调用 select 或 poll），如果没有新数据且设备尚未可写，则设置为`0`。在下面的示例中，我们假设设备同时支持阻塞读和写。当然，可以只实现其中一个。如果驱动程序没有定义此方法，则设备将被视为始终可读和可写，因此`poll()`或`select()`系统调用会立即返回。

# 轮询步骤

当实现`poll`函数时，`read`或`write`方法中的任何一个都可能会发生变化：

1.  为需要实现被动等待的每种事件类型（读取、写入、异常）声明一个等待队列，当没有数据可读或设备尚不可写时，将任务放入其中：

```
static DECLARE_WAIT_QUEUE_HEAD(my_wq); 
static DECLARE_WAIT_QUEUE_HEAD(my_rq); 
```

1.  实现`poll`函数如下：

```
#include <linux/poll.h> 
static unsigned int eep_poll(struct file *file, poll_table *wait) 
{ 
    unsigned int reval_mask = 0; 
    poll_wait(file, &my_wq, wait); 
    poll_wait(file, &my_rq, wait); 

    if (new-data-is-ready) 
        reval_mask |= (POLLIN | POLLRDNORM); 
    if (ready_to_be_written) 
       reval_mask |= (POLLOUT | POLLWRNORM); 
    return reval_mask; 
} 
```

1.  当有新数据或设备可写时，通知等待队列：

```
wake_up_interruptible(&my_rq); /* Ready to read */ 
wake_up_interruptible(&my_wq); /* Ready to be written to */ 
```

可以从驱动程序的`write()`方法内部或者从 IRQ 处理程序内部通知可读事件，这意味着写入的数据可以被读取，或者从 IRQ 处理程序内部通知可写事件，这意味着设备已完成数据发送操作，并准备好再次接受数据。

在使用阻塞 I/O 时，`read`或`write`方法中的任何一个都可能会发生变化。在`poll`中使用的等待队列也必须在读取时使用。当用户需要读取时，如果有数据，该数据将立即发送到进程，并且必须更新等待队列条件（设置为`false`）；如果没有数据，进程将在等待队列中休眠。

如果`write`方法应该提供数据，那么在`write`回调中，您必须填充数据缓冲区并更新等待队列条件（设置为`true`），并唤醒读取者（参见*等待队列*部分）。如果是 IRQ，这些操作必须在其处理程序中执行。

以下是对在给定字符设备上进行`select()`以检测数据可用性的代码的摘录：

```
#include <unistd.h> 
#include <fcntl.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <sys/select.h> 

#define NUMBER_OF_BYTE 100 
#define CHAR_DEVICE "/dev/packt_char" 

char data[NUMBER_OF_BYTE]; 

int main(int argc, char **argv) 
{ 
    int fd, retval; 
    ssize_t read_count; 
    fd_set readfds; 

    fd = open(CHAR_DEVICE, O_RDONLY); 
    if(fd < 0) 
        /* Print a message and exit*/ 
        [...] 

    while(1){  
        FD_ZERO(&readfds); 
        FD_SET(fd, &readfds); 

        /* 
         * One needs to be notified of "read" events only, without timeout. 
         * This call will put the process to sleep until it is notified the 
         * event for which it registered itself 
         */ 
        ret = select(fd + 1, &readfds, NULL, NULL, NULL); 

        /* From this line, the process has been notified already */ 
        if (ret == -1) { 
            fprintf(stderr, "select call on %s: an error ocurred", CHAR_DEVICE); 
            break; 
        } 

        /* 
         * file descriptor is now ready. 
         * This step assume we are interested in one file only. 
         */ 
        if (FD_ISSET(fd, &readfds)) { 
            read_count = read(fd, data, NUMBER_OF_BYTE); 
            if (read_count < 0 ) 
                /* An error occured. Handle this */ 
                [...] 

            if (read_count != NUMBER_OF_BYTE) 
                /* We have read less than need bytes */ 
                [...] /* handle this */ 
            else 
            /* Now we can process data we have read */ 
            [...] 
        } 
    }     
    close(fd); 
    return EXIT_SUCCESS; 
} 
```

# ioctl 方法

典型的 Linux 系统包含大约 350 个系统调用（syscalls），但只有少数与文件操作相关。有时设备可能需要实现特定的命令，这些命令不是由系统调用提供的，特别是与文件相关的命令，因此是设备文件。在这种情况下，解决方案是使用**输入/输出控制**（**ioctl**），这是一种方法，通过它可以扩展与设备相关的系统调用（实际上是命令）的列表。可以使用它向设备发送特殊命令（`reset`，`shutdown`，`configure`等）。如果驱动程序没有定义此方法，内核将对任何`ioctl()`系统调用返回`-ENOTTY`错误。

为了有效和安全，一个`ioctl`命令需要由一个数字标识，这个数字应该对系统是唯一的。在整个系统中 ioctl 号的唯一性将防止它向错误的设备发送正确的命令，或者向正确的命令传递错误的参数（给定重复的 ioctl 号）。Linux 提供了四个辅助宏来创建`ioctl`标识符，具体取决于是否有数据传输，以及传输的方向。它们的原型分别是：

```
_IO(MAGIC, SEQ_NO) 
_IOW(MAGIC, SEQ_NO, TYPE) 
_IOR(MAGIC, SEQ_NO, TYPE) 
_IORW(MAGIC, SEQ_NO, TYPE) 
```

它们的描述如下：

+   `_IO`：`ioctl`不需要数据传输

+   `_IOW`：`ioctl`需要写参数（`copy_from_user`或`get_user`）

+   `_IOR`：`ioctl`需要读参数（`copy_to_user`或`put_user`）

+   `_IOWR`：`ioctl`需要写和读参数

它们的参数意义（按照它们传递的顺序）在这里描述：

1.  一个编码为 8 位（0 到 255）的数字，称为魔术数字。

1.  一个序列号或命令 ID，也是 8 位。

1.  一个数据类型（如果有的话），将通知内核要复制的大小。

在内核源中的*Documentation/ioctl/ioctl-decoding.txt*中有很好的文档，现有的`ioctl`在*Documentation/ioctl/ioctl-number.txt*中列出，这是需要创建`ioctl`命令时的好起点。

# 生成 ioctl 号（命令）

应该在专用的头文件中生成自己的 ioctl 号。这不是强制性的，但建议这样做，因为这个头文件也应该在用户空间中可用。换句话说，应该复制 ioctl 头文件，以便内核和用户空间各有一个，用户可以在用户应用程序中包含其中。现在让我们在一个真实的例子中生成 ioctl 号：

`eep_ioctl.h`：

```
#ifndef PACKT_IOCTL_H 
#define PACKT_IOCTL_H 
/* 
 * We need to choose a magic number for our driver, and sequential numbers 
 * for each command: 
 */ 
#define EEP_MAGIC 'E' 
#define ERASE_SEQ_NO 0x01 
#define RENAME_SEQ_NO 0x02 
#define ClEAR_BYTE_SEQ_NO 0x03 
#define GET_SIZE 0x04 

/* 
 * Partition name must be 32 byte max 
 */ 
#define MAX_PART_NAME 32 

/* 
 * Now let's define our ioctl numbers: 
 */ 
#define EEP_ERASE _IO(EEP_MAGIC, ERASE_SEQ_NO) 
#define EEP_RENAME_PART _IOW(EEP_MAGIC, RENAME_SEQ_NO, unsigned long) 
#define EEP_GET_SIZE _IOR(EEP_MAGIC, GET_SIZE, int *) 
#endif 
```

# `ioctl`的步骤

首先，让我们看一下它的原型。它看起来如下：

```
long ioctl(struct file *f, unsigned int cmd, unsigned long arg); 
```

只有一步：使用`switch ... case`语句，并在调用未定义的`ioctl`命令时返回`-ENOTTY`错误。可以在[`man7.org/linux/man-pages/man2/ioctl.2.html`](http://man7.org/linux/man-pages/man2/ioctl.2.html)找到更多信息：

```
/* 
 * User space code also need to include the header file in which ioctls 
 * defined are defined. This is eep_ioctl.h in our case. 
 */ 
#include "eep_ioctl.h" 
static long eep_ioctl(struct file *f, unsigned int cmd, unsigned long arg) 
{ 
    int part; 
    char *buf = NULL; 
    int size = 1300; 

    switch(cmd){ 
        case EEP_ERASE: 
            erase_eepreom(); 
            break; 
        case EEP_RENAME_PART: 
            buf = kmalloc(MAX_PART_NAME, GFP_KERNEL); 
            copy_from_user(buf, (char *)arg, MAX_PART_NAME); 
            rename_part(buf); 
            break; 
        case EEP_GET_SIZE: 
            copy_to_user((int*)arg, &size, sizeof(int)); 
            break; 
        default: 
            return -ENOTTY; 
    } 
    return 0; 
} 
```

如果您认为您的`ioctl`命令需要多个参数，您应该将这些参数收集在一个结构中，并只是将结构中的指针传递给`ioctl`。

现在，从用户空间，您必须使用与驱动程序代码中相同的`ioctl`头文件：

`my_main.c`

```
#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h> 
#include <unistd.h> 
#include "eep_ioctl.h"  /* our ioctl header file */ 

int main() 
{ 
    int size = 0; 
    int fd; 
    char *new_name = "lorem_ipsum"; /* must not be longer than MAX_PART_NAME */ 

    fd = open("/dev/eep-mem1", O_RDWR); 
    if (fd == -1){ 
        printf("Error while opening the eeprom\n"); 
        return -1; 
    } 

    ioctl(fd, EEP_ERASE);  /* ioctl call to erase partition */ 
    ioctl(fd, EEP_GET_SIZE, &size); /* ioctl call to get partition size */ 
    ioctl(fd, EEP_RENAME_PART, new_name);  /* ioctl call to rename partition */ 

    close(fd); 
    return 0; 
} 
```

# 填充 file_operations 结构

在编写内核模块时，最好在静态初始化结构及其参数时使用指定的初始化器。它包括命名需要分配值的成员。形式是`.member-name`来指定应初始化的成员。这允许以未定义的顺序初始化成员，或者保持不想修改的字段不变，等等。

一旦我们定义了我们的函数，我们只需填充结构如下：

```
static const struct file_operations eep_fops = { 
   .owner =    THIS_MODULE, 
   .read =     eep_read, 
   .write =    eep_write, 
   .open =     eep_open, 
   .release =  eep_release, 
   .llseek =   eep_llseek, 
   .poll =     eep_poll, 
   .unlocked_ioctl = eep_ioctl, 
}; 
```

让我们记住，结构作为参数传递给`cdev_init`的`init`方法。

# 总结

在本章中，我们已经揭开了字符设备的神秘面纱，看到了如何通过设备文件让用户与我们的驱动程序进行交互。我们学会了如何将文件操作暴露给用户空间，并从内核内部控制它们的行为。我们甚至可以实现多设备支持。下一章有点偏向硬件，因为它涉及到将硬件设备的功能暴露给用户空间的平台驱动程序。字符驱动程序与平台驱动程序的结合力量简直令人惊叹。下一章见。


# 第五章：平台设备驱动程序

我们都知道即插即用设备。它们在插入时立即由内核处理。这些可能是 USB 或 PCI Express，或任何其他自动发现的设备。因此，还存在其他类型的设备，这些设备不是热插拔的，内核需要在管理之前知道它们。有 I2C、UART、SPI 和其他未连接到可枚举总线的设备。

您可能已经知道的真实物理总线：USB、I2S、I2C、UART、SPI、PCI、SATA 等。这些总线是名为控制器的硬件设备。由于它们是 SoC 的一部分，因此无法移除，不可发现，也称为平台设备。

人们经常说平台设备是芯片上的设备（嵌入在 SoC 中）。实际上，这在一定程度上是正确的，因为它们被硬连到芯片中，无法移除。但连接到 I2C 或 SPI 的设备不是芯片上的设备，它们也是平台设备，因为它们不可发现。同样，可能存在芯片上的 PCI 或 USB 设备，但它们不是平台设备，因为它们是可发现的。

从 SoC 的角度来看，这些设备（总线）通过专用总线内部连接，并且大多数时间是专有的，特定于制造商。从内核的角度来看，这些是根设备，与任何东西都没有连接。这就是*伪平台总线*的作用。伪平台总线，也称为平台总线，是内核虚拟总线，用于内核不知道的物理总线上的设备。在本章中，平台设备指的是依赖于伪平台总线的设备。

处理平台设备基本上需要两个步骤：

+   注册一个管理您的设备的平台驱动程序（使用唯一名称）

+   使用与驱动程序相同的名称注册您的平台设备，以及它们的资源，以便让内核知道您的设备在那里

话虽如此，在本章中，我们将讨论以下内容：

+   平台设备及其驱动程序

+   内核中的设备和驱动程序匹配机制

+   注册平台驱动程序与设备，以及平台数据

# 平台驱动程序

在继续之前，请注意以下警告。并非所有平台设备都由平台驱动程序处理（或者我应该说伪平台驱动程序）。平台驱动程序专用于不基于常规总线的设备。I2C 设备或 SPI 设备是平台设备，但分别依赖于 I2C 或 SPI 总线，而不是平台总线。一切都需要使用平台驱动程序手动完成。平台驱动程序必须实现一个`probe`函数，当模块被插入或设备声明它时，内核会调用该函数。在开发平台驱动程序时，必须填写的主要结构是`struct platform_driver`，并使用以下显示的专用函数将驱动程序注册到平台总线核心：

```
static struct platform_driver mypdrv = { 
    .probe    = my_pdrv_probe, 
    .remove   = my_pdrv_remove, 
    .driver   = { 
    .name     = "my_platform_driver", 
    .owner    = THIS_MODULE, 
    }, 
}; 
```

让我们看看组成结构的每个元素的含义，以及它们的用途：

+   `probe()`：这是在设备在匹配后声明您的驱动程序时调用的函数。稍后，我们将看到核心如何调用`probe`。其声明如下：

```
static int my_pdrv_probe(struct platform_device *pdev) 
```

+   `remove()`：当设备不再需要时，调用此函数来摆脱驱动程序，其声明如下：

```
static int my_pdrv_remove(struct platform_device *pdev) 
```

+   `struct device_driver`：这描述了驱动程序本身，提供名称、所有者和一些字段，我们稍后会看到。

使用`platform_driver_register()`或`platform_driver_probe()`在`init`函数中（加载模块时）注册平台驱动程序与内核一样简单。这些函数之间的区别在于：

+   `platform_driver_register()`将驱动程序注册并放入内核维护的驱动程序列表中，以便在发生新的匹配时可以按需调用其`probe()`函数。为了防止您的驱动程序被插入和注册到该列表中，只需使用`next`函数。

+   使用`platform_driver_probe()`，内核立即运行匹配循环，检查是否有与匹配名称相匹配的平台设备，然后调用驱动程序的`probe()`，如果发生匹配，表示设备存在。如果没有，驱动程序将被忽略。这种方法可以防止延迟探测，因为它不会在系统上注册驱动程序。在这里，`probe`函数放置在`__init`部分中，在内核引导完成后释放，从而防止延迟探测并减少驱动程序的内存占用。如果您 100%确定设备存在于系统中，请使用此方法：

```
ret = platform_driver_probe(&mypdrv, my_pdrv_probe); 
```

以下是一个简单的平台驱动程序，它在内核中注册自己：

```
#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/init.h> 
#include <linux/platform_device.h> 

static int my_pdrv_probe (struct platform_device *pdev){ 
    pr_info("Hello! device probed!\n"); 
    return 0; 
} 

static void my_pdrv_remove(struct platform_device *pdev){ 
    pr_info("good bye reader!\n"); 
} 

static struct platform_driver mypdrv = { 
    .probe          = my_pdrv_probe, 
    .remove         = my_pdrv_remove, 
    .driver = { 
            .name  = KBUILD_MODNAME, 
            .owner = THIS_MODULE, 
    }, 
}; 

static int __init my_drv_init(void) 
{ 
    pr_info("Hello Guy\n"); 

    /* Registering with Kernel */ 
    platform_driver_register(&mypdrv); 
    return 0; 
} 

static void __exit my_pdrv_remove (void) 
{ 
    Pr_info("Good bye Guy\n"); 

    /* Unregistering from Kernel */ 
    platform_driver_unregister(&my_driver); 
} 

module_init(my_drv_init); 
module_exit(my_pdrv_remove); 

MODULE_LICENSE(

"GPL

");

MODULE_AUTHOR(

"John Madieu

");

MODULE_DESCRIPTION(

"My platform Hello World module

");

```

我们的模块在`init`/`exit`函数中除了在平台总线核心中注册/注销之外什么也不做。大多数驱动程序都是这样。在这种情况下，我们可以摆脱`module_init`和`module_exit`，并使用`module_platform_driver`宏。

`module_platform_driver`宏如下所示：

```
/* 
 * module_platform_driver() - Helper macro for drivers that don't 
 * do anything special in module init/exit. This eliminates a lot 
 * of boilerplate.  Each module may only use this macro once, and 
 * calling it replaces module_init() and module_exit() 
 */ 
#define module_platform_driver(__platform_driver) \ 
module_driver(__platform_driver, platform_driver_register, \ 
platform_driver_unregister) 
```

这个宏将负责在平台驱动核心中注册我们的模块。不再需要`module_init`和`module_exit`宏，也不再需要`init`和`exit`函数。这并不意味着这些函数不再被调用，只是我们可以忘记自己编写它们。

`probe`函数不能替代`init`函数。每当给定设备与驱动程序匹配时，都会调用`probe`函数，而`init`函数只在模块加载时运行一次。

```

[...] 
static int my_driver_probe (struct platform_device *pdev){ 
    [...] 
} 

static void my_driver_remove(struct platform_device *pdev){ 
    [...] 
} 

static struct platform_drivermy_driver = { 
    [...] 
}; 
module_platform_driver(my_driver); 
```

每个总线都有特定的宏，用于注册驱动程序。以下列表不是详尽无遗的：

+   `module_platform_driver(struct platform_driver)` 用于平台驱动程序，专用于不位于传统物理总线上的设备（我们刚刚在上面使用了它）

+   `module_spi_driver(struct spi_driver)` 用于 SPI 驱动程序

+   `module_i2c_driver(struct i2c_driver)` 用于 I2C 驱动程序

+   `module_pci_driver(struct pci_driver)` 用于 PCI 驱动程序

+   `module_usb_driver(struct usb_driver)` 用于 USB 驱动程序

+   `module_mdio_driver(struct mdio_driver)` 用于 mdio

+   [...]

如果您不知道驱动程序需要位于哪个总线上，那么它是一个平台驱动程序，您应该使用`platform_driver_register`或`platform_driver_probe`来注册驱动程序。

# 平台设备

实际上，我们应该说伪平台设备，因为这一部分涉及的是位于伪平台总线上的设备。当您完成驱动程序后，您将不得不向内核提供需要该驱动程序的设备。平台设备在内核中表示为`struct platform_device`的实例，并且如下所示：

```
struct platform_device { 
   const char *name; 
   u32 id; 
   struct device dev; 
   u32 num_resources; 
   struct resource *resource; 
}; 
```

在涉及平台驱动程序之前，驱动程序和设备匹配之前，`struct platform_device`和`static struct platform_driver.driver.name`的`name`字段必须相同。`num_resources`和`struct resource *resource`字段将在下一节中介绍。只需记住，由于`resource`是一个数组，因此`num_resources`必须包含该数组的大小。

# 资源和平台数据

与可热插拔设备相反，内核不知道系统上存在哪些设备，它们的功能是什么，或者为了正常工作需要什么。没有自动协商过程，因此内核提供的任何信息都是受欢迎的。有两种方法可以通知内核设备需要的资源（中断请求，直接内存访问，内存区域，I/O 端口，总线）和数据（任何自定义和私有数据结构，您可能希望传递给驱动程序），如下所述：

# 设备供应 - 旧的和不推荐的方式

这种方法适用于不支持设备树的内核版本。使用此方法，驱动程序保持通用，设备在与板相关的源文件中注册。

# 资源

资源代表了从硬件角度来看设备的所有特征元素，以及设备需要的元素，以便进行设置和正常工作。内核中只有六种资源类型，全部列在`include/linux/ioport.h`中，并用作标志来描述资源的类型：

```
#define IORESOURCE_IO  0x00000100  /* PCI/ISA I/O ports */ 
#define IORESOURCE_MEM 0x00000200  /* Memory regions */ 
#define IORESOURCE_REG 0x00000300  /* Register offsets */ 
#define IORESOURCE_IRQ 0x00000400  /* IRQ line */ 
#define IORESOURCE_DMA 0x00000800  /* DMA channels */ 
#define IORESOURCE_BUS 0x00001000  /* Bus */ 
```

资源在内核中表示为`struct resource`的实例：

```
struct resource { 
        resource_size_t start; 
        resource_size_t end; 
        const char *name; 
        unsigned long flags; 
    }; 
```

让我们解释结构中每个元素的含义：

+   `start/end`：这表示资源的开始/结束位置。对于 I/O 或内存区域，它表示它们的开始/结束位置。对于 IRQ 线、总线或 DMA 通道，开始/结束必须具有相同的值。

+   `flags`：这是一个掩码，用于描述资源的类型，例如`IORESOURCE_BUS`。

+   `name`：这标识或描述资源。

一旦提供了资源，就需要在驱动程序中提取它们以便使用。`probe`函数是提取它们的好地方。在继续之前，让我们记住平台设备驱动程序的`probe`函数的声明：

```
int probe(struct platform_device *pdev); 
```

`pdev`由内核自动填充，其中包含我们之前注册的数据和资源。让我们看看如何选择它们。

嵌入在`struct platform_device`中的`struct resource`可以使用`platform_get_resource()`函数检索。以下是`platform_get_resource`的原型：

```
struct resource *platform_get_resource(structplatform_device *dev, 
                    unsigned int type, unsigned int num); 
```

第一个参数是平台设备本身的实例。第二个参数告诉我们需要什么类型的资源。对于内存，它应该是`IORESOURCE_MEM`。再次，请查看`include/linux/ioport.h`以获取更多详细信息。`num`参数是一个索引，表示所需的资源类型。零表示第一个，依此类推。

如果资源是 IRQ，我们必须使用`int platform_get_irq(struct platform_device * pdev, unsigned intnum)`，其中`pdev`是平台设备，`num`是资源中的 IRQ 索引（如果有多个）。我们可以使用以下整个`probe`函数来提取我们为设备注册的平台数据：

```
static int my_driver_probe(struct platform_device *pdev) 
{ 
struct my_gpios *my_gpio_pdata = 
                   (struct my_gpios*)dev_get_platdata(&pdev->dev); 

    int rgpio = my_gpio_pdata->reset_gpio; 
    int lgpio = my_gpio_pdata->led_gpio; 

    struct resource *res1, *res2; 
    void *reg1, *reg2; 
    int irqnum; 

    res1 = platform_get_resource(pdev, IORESSOURCE_MEM, 0); 
    if((!res1)){ 
        pr_err(" First Resource not available"); 
        return -1; 
    } 
    res2 = platform_get_resource(pdev, IORESSOURCE_MEM, 1); 
    if((!res2)){ 
        pr_err(" Second Resource not available"); 
        return -1; 
    } 

    /* extract the irq */ 
    irqnum = platform_get_irq(pdev, 0); 
    Pr_info("\n IRQ number of Device: %d\n", irqnum); 

    /* 
     * At this step, we can use gpio_request, on gpio, 
     * request_irq on irqnum and ioremap() on reg1 and reg2\. 
     * ioremap() is discussed in chapter 11, Kernel Memory Management  
     */ 
    [...] 
    return 0; 
} 
```

# 平台数据

任何其他数据，其类型不属于前一节中列举的资源类型（例如 GPIO），都属于这里。无论它们的类型是什么，`struct platform_device`包含一个`struct device`字段，该字段又包含一个`struct platform_data`字段。通常，应该将这些数据嵌入到一个结构中，并将其传递给`platform_device.device.platform_data`字段。例如，假设您声明了一个平台设备，该设备需要两个 GPIO 号作为平台数据，一个中断号和两个内存区域作为资源。以下示例显示了如何注册平台数据以及设备。在这里，我们使用`platform_device_register(struct platform_device *pdev)`函数，该函数用于向平台核心注册平台设备：

```
/* 
 * Other data than irq or memory must be embedded in a structure 
 * and passed to "platform_device.device.platform_data" 
 */ 
struct my_gpios { 
    int reset_gpio; 
    int led_gpio; 
}; 

/*our platform data*/ 
static struct my_gpiosneeded_gpios = { 
    .reset_gpio = 47, 
    .led_gpio   = 41, 
}; 

/* Our resource array */ 
static struct resource needed_resources[] = { 
   [0] = { /* The first memory region */ 
         .start = JZ4740_UDC_BASE_ADDR, 
         .end   = JZ4740_UDC_BASE_ADDR + 0x10000 - 1, 
         .flags = IORESOURCE_MEM, 
         .name  = "mem1", 
   }, 
   [1] = { 
         .start = JZ4740_UDC_BASE_ADDR2, 
         .end   = JZ4740_UDC_BASE_ADDR2 + 0x10000 -1, 
         .flags = IORESOURCE_MEM, 
         .name  = "mem2", 
   }, 
   [2] = { 
         .start = JZ4740_IRQ_UDC, 
         .end   = JZ4740_IRQ_UDC, 
         .flags = IORESOURCE_IRQ, 
         .name  = "mc", 
   }, 
}; 

static struct platform_devicemy_device = { 
    .name = "my-platform-device", 
    .id   = 0, 
    .dev  = { 
        .platform_data      = &needed_gpios, 
    }, 
    .resource              = needed_resources, 
    .num_resources = ARRY_SIZE(needed_resources), 
}; 
platform_device_register(&my_device); 
```

在前面的示例中，我们使用了`IORESOURCE_IRQ`和`IORESOURCE_MEM`来告知内核我们提供了什么类型的资源。要查看所有其他标志类型，请查看内核树中的`include/linux/ioport.h`。

为了检索我们之前注册的平台数据，我们可以直接使用`pdev->dev.platform_data`（记住`struct platform_device`结构），但建议使用内核提供的函数（尽管它做的是同样的事情）：

```
void *dev_get_platdata(const struct device *dev) 
struct my_gpios *picked_gpios = dev_get_platdata(&pdev->dev); 
```

# 在哪里声明平台设备？

设备与其资源和数据一起注册。在这种旧的和不推荐的方法中，它们被声明为一个单独的模块，或者在`arch/<arch>/mach-xxx/yyyy.c`中的板`init`文件中声明，这在我们的情况下是`arch/arm/mach-imx/mach-imx6q.c`，因为我们使用的是基于 NXP i.MX6Q 的 UDOO quad。函数`platform_device_register()`让您可以这样做：

```
static struct platform_device my_device = { 
        .name                   = "my_drv_name", 
        .id                     = 0, 
        .dev.platform_data      = &my_device_pdata, 
        .resource              = jz4740_udc_resources, 
        .num_resources         = ARRY_SIZE(jz4740_udc_resources), 
}; 
platform_device_register(&my_device); 

```

设备的名称非常重要，内核使用它来将驱动程序与相同名称的设备进行匹配。

# 设备配置-新的推荐方式

在第一种方法中，任何修改都将需要重新构建整个内核。如果内核必须包含任何应用程序/板特定的配置，其大小将会大幅增加。为了保持简单，并将设备声明（因为它们实际上并不是内核的一部分）与内核源代码分开，引入了一个新概念：*设备树*。DTS 的主要目标是从内核中删除非常特定且从未经过测试的代码。使用设备树，平台数据和资源是同质的。设备树是硬件描述文件，其格式类似于树结构，其中每个设备都表示为一个节点，并且任何数据、资源或配置数据都表示为节点的属性。这样，您只需要在进行一些修改时重新编译设备树。设备树将成为下一章的主题，我们将看到如何将其引入到平台设备中。

# 设备、驱动程序和总线匹配

在任何匹配发生之前，Linux 都会调用`platform_match(struct device *dev, struct device_driver *drv)`。平台设备通过字符串与其驱动程序匹配。根据 Linux 设备模型，总线元素是最重要的部分。每个总线都维护着与其注册的驱动程序和设备的列表。总线驱动程序负责设备和驱动程序的匹配。每当连接新设备或向总线添加新驱动程序时，该总线都会启动匹配循环。

现在，假设您使用 I2C 核心提供的函数（在下一章中讨论）注册了一个新的 I2C 设备。内核将通过调用与 I2C 总线驱动程序注册的 I2C 核心匹配函数来触发 I2C 总线匹配循环，以检查是否已经有与您的设备匹配的注册驱动程序。如果没有匹配项，将不会发生任何事情。如果发生匹配，内核将通过一种称为 netlink 套接字的通信机制通知设备管理器（udev/mdev），后者将加载（如果尚未加载）与您的设备匹配的驱动程序。一旦驱动程序加载，其`probe()`函数将立即执行。不仅 I2C 工作方式如此，而且每个总线都有自己的匹配机制，大致相同。在每个设备或驱动程序注册时都会触发总线匹配循环。

我们可以总结前面部分所说的内容如下图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00010.jpg)

每个注册的驱动程序和设备都位于总线上。这构成了一棵树。USB 总线可能是 PCI 总线的子级，而 MDIO 总线通常是其他设备的子级，依此类推。因此，我们前面的图将如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00011.jpg)

当您使用`platform_driver_probe()`函数注册驱动程序时，内核会遍历已注册的平台设备表，并寻找匹配项。如果有匹配项，它将使用平台数据调用匹配驱动程序的`probe`函数。

# 平台设备和平台驱动程序如何匹配？

到目前为止，我们只讨论了如何填充设备和驱动程序的不同结构。但现在我们将看到它们如何在内核中注册，以及 Linux 如何知道哪些设备由哪个驱动程序处理。答案是`MODULE_DEVICE_TABLE`。这个宏让驱动程序暴露其 ID 表，描述了它可以支持哪些设备。同时，如果驱动程序可以编译为模块，`driver.name`字段应该与模块名称匹配。如果不匹配，模块将不会自动加载，除非我们使用`MODULE_ALIAS`宏为模块添加另一个名称。在编译时，该信息从所有驱动程序中提取出来，以构建设备表。当内核需要为设备找到驱动程序（需要执行匹配时），内核会遍历设备表。如果找到与添加的设备的`compatible`（对于设备树）、`device/vendor id`或`name`（对于设备 ID 表或名称）匹配的条目，那么提供该匹配的模块将被加载（运行模块的`init`函数），并调用`probe`函数。`MODULE_DEVICE_TABLE`宏在`linux/module.h`中定义：

```
#define MODULE_DEVICE_TABLE(type, name) 
```

以下是给这个宏的每个参数的描述：

+   `type`：这可以是`i2c`、`spi`、`acpi`、`of`、`platform`、`usb`、`pci`或您可能在`include/linux/mod_devicetable.h`中找到的任何其他总线。它取决于我们的设备所在的总线，或者我们想要使用的匹配机制。

+   `name`：这是一个指向`XXX_device_id`数组的指针，用于设备匹配。如果我们谈论的是 I2C 设备，结构将是`i2c_device_id`。对于 SPI 设备，应该是`spi_device_id`，依此类推。对于设备树**Open Firmware**（**OF**）匹配机制，我们必须使用`of_device_id`。

对于新的非可发现平台设备驱动程序，建议不再使用平台数据，而是改用设备树功能，使用 OF 匹配机制。请注意，这两种方法并不是互斥的，因此可以混合使用。

让我们深入了解匹配机制的细节，除了我们将在第六章中讨论的 OF 风格匹配之外，*设备树的概念*。

# 内核设备和驱动程序匹配函数

内核中负责平台设备和驱动程序匹配功能的函数在`/drivers/base/platform.c`中定义如下：

```
static int platform_match(struct device *dev, struct device_driver *drv) 
{ 
   struct platform_device *pdev = to_platform_device(dev); 
   struct platform_driver *pdrv = to_platform_driver(drv); 

   /* When driver_override is set, only bind to the matching driver */ 
   if (pdev->driver_override) 
         return !strcmp(pdev->driver_override, drv->name); 

   /* Attempt an OF style match first */ 
   if (of_driver_match_device(dev, drv)) 
         return 1; 

   /* Then try ACPI style match */ 
   if (acpi_driver_match_device(dev, drv)) 
         return 1; 

   /* Then try to match against the id table */ 
   if (pdrv->id_table) 
         return platform_match_id(pdrv->id_table, pdev) != NULL; 

   /* fall-back to driver name match */ 
   return (strcmp(pdev->name, drv->name) == 0); 
} 
```

我们可以列举四种匹配机制。它们都基于字符串比较。如果我们看一下`platform_match_id`，我们就会了解底层的工作原理：

```
static const struct platform_device_id *platform_match_id( 
                        const struct platform_device_id *id, 
                        struct platform_device *pdev) 
{ 
        while (id->name[0]) { 
                if (strcmp(pdev->name, id->name) == 0) { 
                        pdev->id_entry = id; 
                        return id; 
                } 
                id++; 
        } 
        return NULL; 
} 
```

现在让我们来看一下我们在第四章中讨论的`struct device_driver`结构：

```
struct device_driver { 
        const char *name; 
        [...] 
        const struct of_device_id       *of_match_table; 
        const struct acpi_device_id     *acpi_match_table; 
}; 
```

我故意删除了我们不感兴趣的字段。`struct device_driver`构成了每个设备驱动程序的基础。无论是 I2C、SPI、TTY 还是其他设备驱动程序，它们都嵌入了一个`struct device_driver`元素。

# OF 风格和 ACPI 匹配

OF 风格在第六章中有解释，*设备树的概念*。第二种机制是基于 ACPI 表的匹配。我们在本书中不会讨论它，但供您参考，它使用`acpi_device_id`结构。

# ID 表匹配

这种匹配风格已经存在很长时间，它基于`struct device_id`结构。所有设备 id 结构都在`include/linux/mod_devicetable.h`中定义。要找到正确的结构名称，您需要使用总线名称作为前缀，即您的设备驱动程序所在的总线名称。例如：`struct i2c_device_id`用于 I2C，`struct platform_device_id`用于平台设备（不在真实物理总线上），`spi_device_id`用于 SPI 设备，`usb_device_id`用于 USB 等。平台设备的`device_id 表`的典型结构如下：

```
struct platform_device_id { 
   char name[PLATFORM_NAME_SIZE]; 
   kernel_ulong_t driver_data; 
}; 
```

无论如何，如果注册了 ID 表，每当内核运行匹配函数以查找未知或新的平台设备的驱动程序时，都会遍历它。如果匹配成功，将调用匹配驱动程序的 `probe` 函数，并将匹配的 ID 表条目的指针作为参数传递给 `struct platform_device` ，该指针将指向发起匹配的匹配 ID 表条目。`.driver_data` 元素是一个 `unsigned long` ，有时会被强制转换为指针地址，以便指向任何东西，就像在 serial-imx 驱动程序中一样。以下是 `drivers/tty/serial/imx.c` 中使用 `platform_device_id` 的示例：

```
static const struct platform_device_id imx_uart_devtype[] = { 
        { 
              .name = "imx1-uart", 
              .driver_data = (kernel_ulong_t) &imx_uart_devdata[IMX1_UART], 
        }, { 
              .name = "imx21-uart", 
              .driver_data = (kernel_ulong_t) &imx_uart_devdata[IMX21_UART], 
        }, { 
              .name = "imx6q-uart", 
              .driver_data = (kernel_ulong_t) &imx_uart_devdata[IMX6Q_UART], 
        }, { 
                /* sentinel */ 
        } 
}; 
```

`.name` 字段必须与在特定于板的文件中注册设备时给出的设备名称相同。负责此匹配样式的函数是 `platform_match_id` 。如果查看 `drivers/base/platform.c` 中的定义，你会看到：

```
static const struct platform_device_id *platform_match_id( 
        const struct platform_device_id *id, 
        struct platform_device *pdev) 
{ 
    while (id->name[0]) { 
        if (strcmp(pdev->name, id->name) == 0) { 
            pdev->id_entry = id; 
            return id; 
        } 
        id++; 
    } 
    return NULL; 
} 
```

在下面的示例中，这是内核源代码中 `drivers/tty/serial/imx.c` 的摘录，可以看到平台数据是如何通过强制转换转换回原始数据结构的。这就是人们有时将任何数据结构作为平台数据传递的方式：

```
static void serial_imx_probe_pdata(struct imx_port *sport, 
         struct platform_device *pdev) 
{ 
   struct imxuart_platform_data *pdata = dev_get_platdata(&pdev->dev); 

   sport->port.line = pdev->id; 
   sport->devdata = (structimx_uart_data *) pdev->id_entry->driver_data; 

   if (!pdata) 
         return; 
   [...] 
} 
```

`pdev->id_entry` 是一个 `struct platform_device_id` ，它是一个指向内核提供的匹配 ID 表条目的指针，其 `driver_data` 元素被强制转换回数据结构的指针。

**ID 表匹配的每个特定设备数据**

在前一节中，我们已经将 `platform_device_id.platform_data` 用作指针。你的驱动程序可能需要支持多种设备类型。在这种情况下，你将需要为你支持的每种设备类型使用特定的设备数据。然后，你应该将设备 ID 用作包含每种可能的设备数据的数组的索引，而不再是指针地址。以下是示例中的详细步骤：

1.  我们根据驱动程序需要支持的设备类型定义一个枚举：

```
enum abx80x_chip { 
    AB0801, 
    AB0803, 
    AB0804, 
    AB0805, 
    AB1801, 
    AB1803, 
    AB1804, 
    AB1805, 
    ABX80X 
}; 
```

1.  我们定义特定的数据类型结构：

```
struct abx80x_cap { 
    u16 pn; 
boolhas_tc; 
}; 
```

1.  我们使用默认值填充数组，并根据 `device_id` 中的索引，我们可以选择正确的数据：

```
static struct abx80x_cap abx80x_caps[] = { 
    [AB0801] = {.pn = 0x0801}, 
    [AB0803] = {.pn = 0x0803}, 
    [AB0804] = {.pn = 0x0804, .has_tc = true}, 
    [AB0805] = {.pn = 0x0805, .has_tc = true}, 
    [AB1801] = {.pn = 0x1801}, 
    [AB1803] = {.pn = 0x1803}, 
    [AB1804] = {.pn = 0x1804, .has_tc = true}, 
    [AB1805] = {.pn = 0x1805, .has_tc = true}, 
    [ABX80X] = {.pn = 0} 
}; 
```

1.  我们使用特定索引定义我们的 `platform_device_id`：

```
static const struct i2c_device_id abx80x_id[] = { 
    { "abx80x", ABX80X }, 
    { "ab0801", AB0801 }, 
    { "ab0803", AB0803 }, 
    { "ab0804", AB0804 }, 
    { "ab0805", AB0805 }, 
    { "ab1801", AB1801 }, 
    { "ab1803", AB1803 }, 
    { "ab1804", AB1804 }, 
    { "ab1805", AB1805 }, 
    { "rv1805", AB1805 }, 
    { } 
}; 
```

1.  在 `probe` 函数中我们只需要做一些事情：

```
static int rs5c372_probe(struct i2c_client *client, 
const struct i2c_device_id *id) 
{ 
    [...] 

    /* We pick the index corresponding to our device */ 
int index = id->driver_data; 

    /* 
     * And then, we can access the per device data 
     * since it is stored in abx80x_caps[index] 
     */ 
} 
```

# 名称匹配 - 平台设备名称匹配

现在，大多数平台驱动程序根本不提供任何表；它们只是在驱动程序的名称字段中填写驱动程序本身的名称。但匹配仍然有效，因为如果查看 `platform_match` 函数，你会发现最终匹配会回退到名称匹配，比较驱动程序的名称和设备的名称。一些旧的驱动程序仍然使用该匹配机制。以下是 `sound/soc/fsl/imx-ssi.c` 中的名称匹配：

```
static struct platform_driver imx_ssi_driver = { 
   .probe = imx_ssi_probe, 
   .remove = imx_ssi_remove, 

    /* As you can see here, only the 'name' field is filled */ 
   .driver = { 
         .name = "imx-ssi", 
   }, 
}; 

module_platform_driver(imx_ssi_driver); 
```

要添加与此驱动程序匹配的设备，必须在特定于板的文件中（通常在 `arch/<your_arch>/mach-*/board-*.c` 中）调用 `platform_device_register` 或 `platform_add_devices` ，并使用相同的名称 `imx-ssi` 。对于我们的四核 i.MX6-based UDOO，它是 `arch/arm/mach-imx/mach-imx6q.c` 。

# 总结

内核伪平台总线对你来说已经没有秘密了。通过总线匹配机制，你能够理解你的驱动程序何时、如何以及为什么被加载，以及它是为哪个设备加载的。我们可以根据我们想要的匹配机制实现任何 `probe` 函数。由于驱动程序的主要目的是处理设备，我们现在能够在系统中填充设备（旧的和不推荐的方式）。最后，下一章将专门讨论设备树，这是用于在系统上填充设备及其配置的新机制。


# 第六章：设备树的概念

**设备树**（**DT**）是一个易于阅读的硬件描述文件，具有类似 JSON 的格式样式，是一个简单的树结构，其中设备由具有其属性的节点表示。属性可以是空的（只是键，用于描述布尔值），也可以是键值对，其中值可以包含任意字节流。本章是对 DT 的简单介绍。每个内核子系统或框架都有自己的 DT 绑定。当我们处理相关主题时，我们将讨论这些特定的绑定。DT 起源于 OF，这是一个由计算机公司认可的标准，其主要目的是为计算机固件系统定义接口。也就是说，可以在[`www.devicetree.org/`](http://www.devicetree.org/)找到更多关于 DT 规范的信息。因此，本章将涵盖 DT 的基础知识，例如：

+   命名约定，以及别名和标签

+   描述数据类型及其 API

+   管理寻址方案和访问设备资源

+   实现 OF 匹配样式并提供特定于应用程序的数据

# 设备树机制

通过将选项`CONFIG_OF`设置为`Y`，可以在内核中启用 DT。为了从驱动程序中调用 DT API，必须添加以下标头：

```
#include <linux/of.h> 
#include <linux/of_device.h> 
```

DT 支持几种数据类型。让我们通过一个示例节点描述来看看它们：

```
/* This is a comment */ 
// This is another comment 
node_label: nodename@reg{ 
   string-property = "a string"; 
   string-list = "red fish", "blue fish"; 
   one-int-property = <197>; /* One cell in this property */ 
   int-list-property = <0xbeef 123 0xabcd4>; /*each number (cell) is a                         

                                               *32 bit integer(uint32).

                                               *There are 3 cells in  

                                               */this property 

    mixed-list-property = "a string", <0xadbcd45>, <35>, [0x01 0x23 0x45] 
    byte-array-property = [0x01 0x23 0x45 0x67]; 
    boolean-property; 
}; 
```

以下是设备树中使用的一些数据类型的定义：

+   文本字符串用双引号表示。可以使用逗号创建字符串列表。

+   单元是由尖括号分隔的 32 位无符号整数。

+   布尔数据只是一个空属性。真或假的值取决于属性是否存在。

# 命名约定

每个节点必须具有形式为`<name>[@<address>]`的名称，其中`<name>`是一个长度最多为 31 个字符的字符串，`[@<address>]`是可选的，取决于节点是否表示可寻址设备。`<address>`应该是用于访问设备的主要地址。设备命名的示例如下：

```
expander@20 { 
    compatible = "microchip,mcp23017"; 
    reg = <20>; 
    [...]        
}; 
```

或

```
i2c@021a0000 { 
    compatible = "fsl,imx6q-i2c", "fsl,imx21-i2c"; 
    reg = <0x021a0000 0x4000>; 
    [...] 
}; 
```

另一方面，“标签”是可选的。只有当节点打算从另一个节点的属性引用时，标记节点才有用。可以将标签视为指向节点的指针，如下一节所述。

# 别名，标签和 phandle

了解这三个元素如何工作非常重要。它们在 DT 中经常被使用。让我们看看以下的 DT 来解释它们是如何工作的：

```
aliases { 
    ethernet0 = &fec; 
    gpio0 = &gpio1; 
    gpio1 = &gpio2; 
    mmc0 = &usdhc1; 
    [...] 
}; 
gpio1: gpio@0209c000 { 
    compatible = "fsl,imx6q-gpio", "fsl,imx35-gpio"; 
    [...] 
}; 
node_label: nodename@reg { 
    [...]; 
    gpios = <&gpio1 7 GPIO_ACTIVE_HIGH>; 
}; 
```

标签只是一种标记节点的方式，以便让节点通过唯一名称进行标识。在现实世界中，DT 编译器将该名称转换为唯一的 32 位值。在前面的示例中，`gpio1`和`node_label`都是标签。然后可以使用标签来引用节点，因为标签对节点是唯一的。

**指针句柄**（**phandle**）是与节点关联的 32 位值，用于唯一标识该节点，以便可以从另一个节点的属性中引用该节点。标签用于指向节点。通过使用`<&mylabel>`，您指向其标签为`mylabel`的节点。

使用`&`与 C 编程语言中的用法相同；用于获取元素的地址。

在前面的示例中，`&gpio1`被转换为 phandle，以便它引用`gpio1`节点。对于以下示例也是如此：

```
thename@address { 
    property = <&mylabel>; 
}; 

mylabel: thename@adresss { 
    [...] 
} 
```

为了不必遍历整个树来查找节点，引入了别名的概念。在 DT 中，`aliases`节点可以看作是一个快速查找表，另一个节点的索引。可以使用函数`find_node_by_alias()`来查找给定别名的节点。别名不直接在 DT 源中使用，而是由 Linux 内核进行解引用。

# DT 编译器

DT 有两种形式：文本形式，表示源也称为`DTS`，以及二进制 blob 形式，表示已编译的 DT，也称为`DTB`。源文件的扩展名为`.dts`。实际上，还有`.dtsi`文本文件，表示 SoC 级别定义，而`.dts`文件表示板级别定义。可以将`.dtsi`视为头文件，应包含在`.dts`中，这些是源文件，而不是反向的，有点像在源文件（`.c`）中包含头文件（`.h`）。另一方面，二进制文件使用`.dtb`扩展名。

实际上还有第三种形式，即在`/proc/device-tree`中的 DT 的运行时表示。

正如其名称所示，用于编译设备树的工具称为**设备树编译器**（**dtc**）。从根内核源中，可以编译特定体系结构的独立特定 DT 或所有 DT。

让我们为 arm SoC 编译所有 DT（`.dts`）文件：

```
ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make dtbs 

```

对于独立的 DT：

```
ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make imx6dl-sabrelite.dtb 

```

在前面的示例中，源文件的名称是`imx6dl-sabrelite.dts`。

给定一个已编译的设备树（.dtb）文件，您可以执行反向操作并提取源（.dts）文件：

```
dtc -I dtb -O dtsarch/arm/boot/dts imx6dl-sabrelite.dtb >path/to/my_devicetree.dts 
```

出于调试目的，将 DT 暴露给用户空间可能很有用。`CONFIG_PROC_DEVICETREE`配置变量将为您执行此操作。然后，您可以在`/proc/device-tree`中探索和浏览 DT。

# 表示和寻址设备

每个设备在 DT 中至少有一个节点。某些属性对许多设备类型都是共同的，特别是对于内核已知的总线上的设备（SPI、I2C、平台、MDIO 等）。这些属性是`reg`、`#address-cells`和`#size-cells`。这些属性的目的是在它们所在的总线上寻址设备。也就是说，主要的寻址属性是`reg`，这是一个通用属性，其含义取决于设备所在的总线。前缀`size-cell`和`address-cell`的`#`（sharp）可以翻译为`length`。

每个可寻址设备都有一个`reg`属性，其形式为`reg = <address0size0 [address1size1] [address2size2] ...>`的元组列表，其中每个元组表示设备使用的地址范围。`#size-cells`指示用于表示大小的 32 位单元的数量，如果大小不相关，则可能为 0。另一方面，`#address-cells`指示用于表示地址的 32 位单元的数量。换句话说，每个元组的地址元素根据`#address-cell`进行解释；大小元素也是如此，根据`#size-cell`进行解释。

实际上，可寻址设备继承自其父节点的`#size-cell`和`#address-cell`，即代表总线控制器的节点。给定设备中`#size-cell`和`#address-cell`的存在不会影响设备本身，而是其子级。换句话说，在解释给定节点的`reg`属性之前，必须了解父节点的`#address-cells`和`#size-cells`值。父节点可以自由定义适合设备子节点（子级）的任何寻址方案。

# SPI 和 I2C 寻址

SPI 和 I2C 设备都属于非内存映射设备，因为它们的地址对 CPU 不可访问。相反，父设备的驱动程序（即总线控制器驱动程序）将代表 CPU 执行间接访问。每个 I2C/SPI 设备始终表示为所在的 I2C/SPI 总线节点的子节点。对于非内存映射设备，“＃size-cells”属性为 0，寻址元组中的大小元素为空。这意味着这种类型的设备的`reg`属性始终在单元上：

```
&i2c3 { 
    [...] 
    status = "okay"; 

    temperature-sensor@49 { 
        compatible = "national,lm73"; 
        reg = <0x49>; 
    }; 

    pcf8523: rtc@68 { 
        compatible = "nxp,pcf8523"; 
        reg = <0x68>; 
    }; 
}; 

&ecspi1 { 
fsl,spi-num-chipselects = <3>; 
cs-gpios = <&gpio5 17 0>, <&gpio5 17 0>, <&gpio5 17 0>; 
status = "okay"; 
[...] 

ad7606r8_0: ad7606r8@1 { 
    compatible = "ad7606-8"; 
    reg = <1>; 
    spi-max-frequency = <1000000>; 
    interrupt-parent = <&gpio4>; 
    interrupts = <30 0x0>; 
    convst-gpio = <&gpio6 18 0>; 
}; 
}; 
```

如果有人查看`arch/arm/boot/dts/imx6qdl.dtsi`中的 SoC 级文件，就会注意到`#size-cells`和`#address-cells`分别设置为前者为`0`，后者为`1`，在`i2c`和`spi`节点中，它们分别是 I2C 和 SPI 设备在前面部分列举的父节点。这有助于我们理解它们的`reg`属性，地址值只有一个单元，大小值没有。

I2C 设备的`reg`属性用于指定总线上设备的地址。对于 SPI 设备，`reg`表示分配给设备的芯片选择线的索引，该索引位于控制器节点具有的芯片选择列表中。例如，对于 ad7606r8 ADC，芯片选择索引是`1`，对应于`cs-gpios`中的`<&gpio5 17 0>`，这是控制器节点的芯片选择列表。

你可能会问为什么我使用了 I2C/SPI 节点的 phandle：答案是因为 I2C/SPI 设备应该在板级文件（`.dts`）中声明，而 I2C/SPI 总线控制器应该在 SoC 级文件（`.dtsi`）中声明。

# 平台设备寻址

本节涉及的是内存对 CPU 可访问的简单内存映射设备。在这里，`reg`属性仍然定义了设备的地址，这是可以访问设备的内存区域列表。每个区域用单元组表示，其中第一个单元是内存区域的基地址，第二个单元是区域的大小。它的形式是`reg = <base0 length0 [base1 length1] [address2 length2] ...>`。每个元组表示设备使用的地址范围。

在现实世界中，不应该在不知道另外两个属性`#size-cells`和`#address-cells`的值的情况下解释`reg`属性。`#size-cells`告诉我们每个子`reg`元组中长度字段有多大。`#address-cell`也是一样，它告诉我们必须使用多少个单元来指定一个地址。

这种设备应该在一个具有特殊值`compatible = "simple-bus"`的节点中声明，表示一个没有特定处理或驱动程序的简单内存映射总线：

```
soc { 
    #address-cells = <1>; 
    #size-cells = <1>; 
    compatible = "simple-bus"; 
    aips-bus@02000000 { /* AIPS1 */ 
        compatible = "fsl,aips-bus", "simple-bus"; 
        #address-cells = <1>; 
        #size-cells = <1>; 
        reg = <0x02000000 0x100000>; 
        [...]; 

        spba-bus@02000000 { 
            compatible = "fsl,spba-bus", "simple-bus"; 
            #address-cells = <1>; 
            #size-cells = <1>; 
            reg = <0x02000000 0x40000>; 
            [...] 

            ecspi1: ecspi@02008000 { 
                #address-cells = <1>; 
                #size-cells = <0>; 
                compatible = "fsl,imx6q-ecspi", "fsl,imx51-ecspi"; 
                reg = <0x02008000 0x4000>; 
                [...] 
            }; 

            i2c1: i2c@021a0000 { 
                #address-cells = <1>; 
                #size-cells = <0>; 
                compatible = "fsl,imx6q-i2c", "fsl,imx21-i2c"; 
                reg = <0x021a0000 0x4000>; 
                [...] 
            }; 
        }; 
    }; 
```

在前面的例子中，具有`compatible`属性中`simple-bus`的子节点将被注册为平台设备。人们还可以看到 I2C 和 SPI 总线控制器如何通过设置`#size-cells = <0>;`来改变其子节点的寻址方案，因为这对它们来说并不重要。查找任何绑定信息的一个著名地方是内核设备树的文档：*Documentation/devicetree/bindings/*。

# 处理资源

驱动程序的主要目的是处理和管理设备，并且大部分时间将其功能暴露给用户空间。这里的目标是收集设备的配置参数，特别是资源（内存区域、中断线、DMA 通道、时钟等）。

以下是我们在本节中将使用的设备节点。它是在`arch/arm/boot/dts/imx6qdl.dtsi`中定义的 i.MX6 UART 设备节点：

```
uart1: serial@02020000 { 
        compatible = "fsl,imx6q-uart", "fsl,imx21-uart"; 
reg = <0x02020000 0x4000>; 
        interrupts = <0 26 IRQ_TYPE_LEVEL_HIGH>; 
        clocks = <&clks IMX6QDL_CLK_UART_IPG>, 
<&clks IMX6QDL_CLK_UART_SERIAL>; 
        clock-names = "ipg", "per"; 
dmas = <&sdma 25 4 0>, <&sdma 26 4 0>; 
dma-names = "rx", "tx"; 
        status = "disabled"; 
    }; 
```

# 命名资源的概念

当驱动程序期望某种类型的资源列表时，没有保证列表按照驱动程序期望的方式排序，因为编写板级设备树的人通常不是编写驱动程序的人。例如，驱动程序可能期望其设备节点具有 2 个 IRQ 线，一个用于索引 0 的 Tx 事件，另一个用于索引 1 的 Rx。如果顺序没有得到尊重会发生什么？驱动程序将产生不需要的行为。为了避免这种不匹配，引入了命名资源（`clock`，`irq`，`dma`，`reg`）的概念。它包括定义我们的资源列表，并对其进行命名，以便无论它们的索引如何，给定的名称始终与资源匹配。

用于命名资源的相应属性如下：

+   `reg-names`：这是在`reg`属性中的内存区域列表

+   `clock-names`：这是在`clocks`属性中命名时钟

+   `interrupt-names`：这为`interrupts`属性中的每个中断提供了一个名称

+   `dma-names`：这是`dma`属性

现在让我们创建一个虚假的设备节点条目来解释一下：

```
fake_device { 
    compatible = "packt,fake-device"; 
    reg = <0x4a064000 0x800>, <0x4a064800 0x200>, <0x4a064c00 0x200>; 
    reg-names = "config", "ohci", "ehci"; 
    interrupts = <0 66 IRQ_TYPE_LEVEL_HIGH>, <0 67 IRQ_TYPE_LEVEL_HIGH>; 
    interrupt-names = "ohci", "ehci"; 
    clocks = <&clks IMX6QDL_CLK_UART_IPG>, <&clks IMX6QDL_CLK_UART_SERIAL>; 
    clock-names = "ipg", "per"; 
    dmas = <&sdma 25 4 0>, <&sdma 26 4 0>; 
    dma-names = "rx", "tx"; 
}; 
```

驱动程序中提取每个命名资源的代码如下：

```
struct resource *res1, *res2; 
res1 = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ohci"); 
res2 = platform_get_resource_byname(pdev, IORESOURCE_MEM, "config"); 

struct dma_chan  *dma_chan_rx, *dma_chan_tx; 
dma_chan_rx = dma_request_slave_channel(&pdev->dev, "rx"); 
dma_chan_tx = dma_request_slave_channel(&pdev->dev, "tx"); 

inttxirq, rxirq; 
txirq = platform_get_irq_byname(pdev, "ohci"); 
rxirq = platform_get_irq_byname(pdev, "ehci"); 

structclk *clck_per, *clk_ipg; 
clk_ipg = devm_clk_get(&pdev->dev, "ipg"); 
clk_ipg = devm_clk_get(&pdev->dev, "pre"); 
```

这样，您可以确保将正确的名称映射到正确的资源，而无需再使用索引。

# 访问寄存器

在这里，驱动程序将接管内存区域并将其映射到虚拟地址空间中。我们将在[第十一章](http://post)中更多地讨论这个问题，*内核内存管理*。

```
struct resource *res; 
void __iomem *base; 

res = platform_get_resource(pdev, IORESOURCE_MEM, 0); 
/* 
 * Here one can request and map the memory region 
 * using request_mem_region(res->start, resource_size(res), pdev->name) 
 * and ioremap(iores->start, resource_size(iores) 
 * 
 * These function are discussed in chapter 11, Kernel Memory Management. 
 */ 
base = devm_ioremap_resource(&pdev->dev, res); 
if (IS_ERR(base)) 
    return PTR_ERR(base); 
```

`platform_get_resource()`将根据 DT 节点中第一个（索引 0）`reg`分配中存在的内存区域设置`struct res`的开始和结束字段。请记住，`platform_get_resource()`的最后一个参数表示资源索引。在前面的示例中，`0`索引了该资源类型的第一个值，以防设备在 DT 节点中分配了多个内存区域。在我们的示例中，它是`reg = <0x02020000 0x4000>`，意味着分配的区域从物理地址`0x02020000`开始，大小为`0x4000`字节。然后，`platform_get_resource()`将设置`res.start = 0x02020000`和`res.end = 0x02023fff`。

# 处理中断

中断接口实际上分为两部分；消费者端和控制器端。在 DT 中用四个属性来描述中断连接：

控制器是向消费者公开 IRQ 线的设备。在控制器端，有以下属性：

+   `interrupt-controller`：一个空（布尔）属性，应该定义为标记设备为中断控制器

+   `#interrupt-cells`：这是中断控制器的属性。它说明用于为该中断控制器指定中断的单元格数

消费者是生成 IRQ 的设备。消费者绑定期望以下属性：

+   `interrupt-parent`：对于生成中断的设备节点，它是一个包含指向设备附加的中断控制器节点的指针`phandle`的属性。如果省略，设备将从其父节点继承该属性。

+   `interrupts`：这是中断指定器。

中断绑定和中断指定器与中断控制器设备绑定。用于定义中断输入的单元格数取决于中断控制器，这是唯一决定的，通过其`#interrupt-cells`属性。在 i.MX6 的情况下，中断控制器是**全局中断控制器**（**GIC**）。其绑定在*Documentation/devicetree/bindings/arm/gic.txt*中有很好的解释。

# 中断处理程序

这包括从 DT 中获取 IRQ 号，并将其映射到 Linux IRQ，从而为其注册一个函数回调。执行此操作的驱动程序代码非常简单：

```
int irq = platform_get_irq(pdev, 0); 
ret = request_irq(irq, imx_rxint, 0, dev_name(&pdev->dev), sport); 
```

`platform_get_irq()`调用将返回`irq`号；这个数字可以被`devm_request_irq()`使用（`irq`然后在`/proc/interrupts`中可见）。第二个参数`0`表示我们需要设备节点中指定的第一个中断。如果有多个中断，我们可以根据需要更改此索引，或者只使用命名资源。

在我们之前的例子中，设备节点包含一个中断指定器，看起来像这样：

```
interrupts = <0 66 IRQ_TYPE_LEVEL_HIGH>; 
```

+   根据 ARM GIC，第一个单元格告诉我们中断类型：

+   `0` **：共享外围中断**（**SPI**），用于在核心之间共享的中断信号，可以由 GIC 路由到任何核心

+   `1`：**私有外围中断**（**PPI**），用于单个核心的私有中断信号

文档可以在以下网址找到：[`infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0407e/CCHDBEBE.html`](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0407e/CCHDBEBE.html)。

+   第二个单元格保存中断号。这个数字取决于中断线是 PPI 还是 SPI。

+   第三个单元格，在我们的情况下是`IRQ_TYPE_LEVEL_HIGH`，表示感应电平。所有可用的感应电平都在`include/linux/irq.h`中定义。

# 中断控制器代码

`interrupt-controller`属性用于声明设备为中断控制器。`#interrupt-cells`属性定义了必须使用多少个单元格来定义单个中断线。我们将在[第十六章](http://advanced)中详细讨论这个问题，*高级中断管理*。

# 提取应用程序特定数据

应用程序特定数据是超出常见属性（既不是资源也不是 GPIO、调节器等）的数据。这些是可以分配给设备的任意属性和子节点。这些属性名称通常以制造商代码为前缀。这些可以是任何字符串、布尔值或整数值，以及它们在 Linux 源代码中`drivers/of/base.c`中定义的 API。我们讨论的以下示例并不详尽。现在让我们重用本章前面定义的节点：

```
node_label: nodename@reg{ 
  string-property = ""a string""; 
  string-list = ""red fish"", ""blue fish""; 
  one-int-property = <197>; /* One cell in this property */ 
  int-list-property = <0xbeef 123 0xabcd4>;/* each number (cell) is 32      a                                        * bit integer(uint32). There 
                                         * are 3 cells in this property 
                                         */ 
    mixed-list-property = "a string", <0xadbcd45>, <35>, [0x01 0x23 0x45] 
    byte-array-property = [0x01 0x23 0x45 0x67]; 
    one-cell-property = <197>; 
    boolean-property; 
}; 
```

# 文本字符串

以下是一个`string`属性：

```
string-property = "a string"; 
```

回到驱动程序中，应该使用`of_property_read_string()`来读取字符串值。其原型定义如下：

```
int of_property_read_string(const struct device_node *np, const 
                        char *propname, const char **out_string) 
```

以下代码显示了如何使用它：

```
const char *my_string = NULL; 
of_property_read_string(pdev->dev.of_node, "string-property", &my_string); 
```

# 单元格和无符号 32 位整数

以下是我们的`int`属性：

```
one-int-property = <197>; 
int-list-property = <1350000 0x54dae47 1250000 1200000>; 
```

应该使用`of_property_read_u32()`来读取单元格值。其原型定义如下：

```
int of_property_read_u32_index(const struct device_node *np, 
                     const char *propname, u32 index, u32 *out_value) 
```

回到驱动程序中，

```
unsigned int number; 
of_property_read_u32(pdev->dev.of_node, "one-cell-property", &number); 
```

可以使用`of_property_read_u32_array`来读取单元格列表。其原型如下：

```
int of_property_read_u32_array(const struct device_node *np, 
                      const char *propname, u32 *out_values, size_tsz); 
```

在这里，`sz`是要读取的数组元素的数量。查看`drivers/of/base.c`以查看如何解释其返回值：

```
unsigned int cells_array[4]; 
if (of_property_read_u32_array(pdev->dev.of_node, "int-list-property", 
cells_array, 4)) { 
    dev_err(&pdev->dev, "list of cells not specified\n"); 
    return -EINVAL; 
} 
```

# 布尔值

应该使用`of_property_read_bool()`来读取函数的第二个参数中给定的布尔属性的名称：

```
bool my_bool = of_property_read_bool(pdev->dev.of_node, "boolean-property"); 
If(my_bool){ 
    /* boolean is true */ 
} else 
    /* Bolean is false */ 
} 
```

# 提取和解析子节点

您可以在设备节点中添加任何子节点。给定表示闪存设备的节点，分区可以表示为子节点。对于处理一组输入和输出 GPIO 的设备，每个集合可以表示为一个子节点。示例节点如下：

```
eeprom: ee24lc512@55 { 
        compatible = "microchip,24xx512"; 
reg = <0x55>; 

        partition1 { 
            read-only; 
            part-name = "private"; 
            offset = <0>; 
            size = <1024>; 
        }; 

        partition2 { 
            part-name = "data"; 
            offset = <1024>; 
            size = <64512>; 
        }; 
    }; 
```

可以使用`for_each_child_of_node()`来遍历给定节点的子节点：

```
struct device_node *np = pdev->dev.of_node; 
struct device_node *sub_np; 
for_each_child_of_node(np, sub_np) { 
        /* sub_np will point successively to each sub-node */ 
        [...] 
int size; 
        of_property_read_u32(client->dev.of_node, 
"size", &size); 
        ... 
 } 
```

# 平台驱动程序和 DT

平台驱动程序也可以使用 DT。也就是说，这是处理平台设备的推荐方式，而且不再需要触及板文件，甚至在设备属性更改时重新编译内核。如果您还记得，在上一章中我们讨论了 OF 匹配样式，这是一种基于 DT 的匹配机制。让我们在下一节中看看它是如何工作的：

# OF 匹配样式

OF 匹配样式是平台核心执行的第一个匹配机制，用于将设备与其驱动程序匹配。它使用设备树的`compatible`属性来匹配`of_match_table`中的设备条目，这是`struct driver`子结构的一个字段。每个设备节点都有一个`compatible`属性，它是一个字符串或字符串列表。任何声明在`compatible`属性中列出的字符串之一的平台驱动程序都将触发匹配，并将看到其`probe`函数执行。

DT 匹配条目在内核中被描述为`struct of_device_id`结构的一个实例，该结构在`linux/mod_devicetable.h`中定义，如下所示：

```
// we are only interested in the two last elements of the structure 
struct of_device_id { 
    [...] 
    char  compatible[128]; 
    const void *data; 
}; 
```

以下是结构的每个元素的含义：

+   `char compatible[128]`：这是用于匹配设备节点的 DT 兼容属性的字符串。在匹配发生之前，它们必须相同。

+   `const void *data`：这可以指向任何结构，可以根据设备类型配置数据使用。

由于`of_match_table`是一个指针，您可以传递`struct of_device_id`的数组，使您的驱动程序与多个设备兼容：

```
static const struct of_device_id imx_uart_dt_ids[] = { 
    { .compatible = "fsl,imx6q-uart", }, 
    { .compatible = "fsl,imx1-uart", }, 
    { .compatible = "fsl,imx21-uart", }, 
    { /* sentinel */ } 
}; 
```

一旦填充了 id 数组，它必须传递给平台驱动程序的`of_match_table`字段，在驱动程序子结构中：

```
static struct platform_driver serial_imx_driver = { 
    [...] 
    .driver     = { 
        .name   = "imx-uart", 
        .of_match_table = imx_uart_dt_ids, 
        [...] 
    }, 
}; 
```

在这一步，只有您的驱动程序知道您的`of_device_id`数组。为了让内核也知道（以便它可以将您的 ID 存储在平台核心维护的设备列表中），您的数组必须在`MODULE_DEVICE_TABLE`中注册，如第五章中所述，*平台设备驱动程序*：

```
MODULE_DEVICE_TABLE(of, imx_uart_dt_ids); 
```

就是这样！我们的驱动程序是 DT 兼容的。回到我们的 DT，在那里声明一个与我们的驱动程序兼容的设备：

```
uart1: serial@02020000 { 
    compatible = "fsl,imx6q-uart", "fsl,imx21-uart"; 
    reg = <0x02020000 0x4000>; 
    interrupts = <0 26 IRQ_TYPE_LEVEL_HIGH>; 
    [...] 
}; 
```

这里提供了两个兼容的字符串。如果第一个与任何驱动程序都不匹配，核心将使用第二个进行匹配。

当发生匹配时，将调用您的驱动程序的`probe`函数，参数是一个`struct platform_device`结构，其中包含一个`struct device dev`字段，在其中有一个`struct device_node *of_node`字段，对应于我们的设备关联的节点，因此可以使用它来提取设备设置：

```
static int serial_imx_probe(struct platform_device *pdev) 
{ 
    [...] 
struct device_node *np; 
np = pdev->dev.of_node; 

    if (of_get_property(np, "fsl,dte-mode", NULL)) 
        sport->dte_mode = 1; 
        [...] 
 }   
```

一个可以检查 DT 节点是否设置来知道驱动程序是否已经在`of_match`的响应中加载，或者是在板子的`init`文件中实例化。然后应该使用`of_match_device`函数，以选择发起匹配的`struct *of_device_id`条目，其中可能包含您传递的特定数据：

```
static int my_probe(struct platform_device *pdev) 
{ 
struct device_node *np = pdev->dev.of_node; 
const struct of_device_id *match; 

    match = of_match_device(imx_uart_dt_ids, &pdev->dev); 
    if (match) { 
        /* Devicetree, extract the data */ 
        my_data = match->data 
    } else { 
        /* Board init file */ 
        my_data = dev_get_platdata(&pdev->dev); 
    } 
    [...] 
} 
```

# 处理非设备树平台

在内核中启用了`CONFIG_OF`选项的情况下启用了 DT 支持。当内核中未启用 DT 支持时，人们可能希望避免使用 DT API。可以通过检查`CONFIG_OF`是否设置来实现。人们过去通常会做如下操作：

```
#ifdef CONFIG_OF 
    static const struct of_device_id imx_uart_dt_ids[] = { 
        { .compatible = "fsl,imx6q-uart", }, 
        { .compatible = "fsl,imx1-uart", }, 
        { .compatible = "fsl,imx21-uart", }, 
        { /* sentinel */ } 
    }; 

    /* other devicetree dependent code */ 
    [...] 
#endif 
```

即使在缺少设备树支持时，`of_device_id`数据类型总是定义的，但在构建过程中，被包装在`#ifdef CONFIG_OF ... #endif`中的代码将被省略。这用于条件编译。这不是您唯一的选择；还有`of_match_ptr`宏，当`OF`被禁用时，它简单地返回`NULL`。在您需要将`of_match_table`作为参数传递的任何地方，它都应该被包装在`of_match_ptr`宏中，以便在`OF`被禁用时返回`NULL`。该宏在`include/linux/of.h`中定义：

```
#define of_match_ptr(_ptr) (_ptr) /* When CONFIG_OF is enabled */ 
#define of_match_ptr(_ptr) NULL   /* When it is not */ 
```

我们可以这样使用它：

```
static int my_probe(struct platform_device *pdev) 
{ 
    const struct of_device_id *match; 
    match = of_match_device(of_match_ptr(imx_uart_dt_ids), 
                     &pdev->dev); 
    [...] 
} 
static struct platform_driver serial_imx_driver = { 
    [...] 
    .driver         = { 
    .name   = "imx-uart", 
    .of_match_table = of_match_ptr(imx_uart_dt_ids), 
    }, 
}; 
```

这消除了使用`#ifdef`，在`OF`被禁用时返回`NULL`。

# 支持具有每个特定设备数据的多个硬件

有时，驱动程序可以支持不同的硬件，每个硬件都有其特定的配置数据。这些数据可能是专用的函数表、特定的寄存器值，或者是每个硬件独有的任何内容。下面的示例描述了一种通用的方法：

让我们首先回顾一下`include/linux/mod_devicetable.h`中`struct of_device_id`的外观。

```
/* 
 * Struct used for matching a device 
 */ 
struct of_device_id { 
        [...] 
        char    compatible[128]; 
const void *data; 
}; 
```

我们感兴趣的字段是`const void *data`，所以我们可以使用它来为每个特定设备传递任何数据。

假设我们拥有三种不同的设备，每个设备都有特定的私有数据。`of_device_id.data`将包含指向特定参数的指针。这个示例受到了`drivers/tty/serial/imx.c`的启发。

首先，我们声明私有结构：

```
/* i.MX21 type uart runs on all i.mx except i.MX1 and i.MX6q */ 
enum imx_uart_type { 
    IMX1_UART, 
    IMX21_UART, 
    IMX6Q_UART, 
}; 

/* device type dependent stuff */ 
struct imx_uart_data { 
    unsigned uts_reg; 
    enum imx_uart_type devtype; 
}; 
```

然后我们用每个特定设备的数据填充一个数组：

```
static struct imx_uart_data imx_uart_devdata[] = { 
        [IMX1_UART] = { 
                 .uts_reg = IMX1_UTS, 
                 .devtype = IMX1_UART, 
        }, 
        [IMX21_UART] = { 
                .uts_reg = IMX21_UTS, 
                .devtype = IMX21_UART, 
        }, 
        [IMX6Q_UART] = { 
                .uts_reg = IMX21_UTS, 
                .devtype = IMX6Q_UART, 
        }, 
}; 
```

每个兼容条目都与特定的数组索引相关联：

```
static const struct of_device_idimx_uart_dt_ids[] = { 
        { .compatible = "fsl,imx6q-uart", .data = &imx_uart_devdata[IMX6Q_UART], }, 
        { .compatible = "fsl,imx1-uart", .data = &imx_uart_devdata[IMX1_UART], }, 
        { .compatible = "fsl,imx21-uart", .data = &imx_uart_devdata[IMX21_UART], }, 
        { /* sentinel */ } 
}; 
MODULE_DEVICE_TABLE(of, imx_uart_dt_ids); 

static struct platform_driver serial_imx_driver = { 
    [...] 
    .driver         = { 
        .name   = "imx-uart", 
        .of_match_table = of_match_ptr(imx_uart_dt_ids), 
    }, 
}; 
```

现在在`probe`函数中，无论匹配条目是什么，它都将保存指向特定设备结构的指针：

```
static int imx_probe_dt(struct platform_device *pdev) 
{ 
    struct device_node *np = pdev->dev.of_node; 
    const struct of_device_id *of_id = 
    of_match_device(of_match_ptr(imx_uart_dt_ids), &pdev->dev); 

        if (!of_id) 
                /* no device tree device */ 
                return 1; 
        [...] 
        sport->devdata = of_id->data; /* Get private data back  */ 
} 
```

在前面的代码中，`devdata`是原始源代码中结构的一个元素，并且声明为`const struct imx_uart_data *devdata`；我们可以在数组中存储任何特定的参数。

# 匹配样式混合

OF 匹配样式可以与任何其他匹配机制结合使用。在下面的示例中，我们混合了 DT 和设备 ID 匹配样式：

我们为设备 ID 匹配样式填充一个数组，每个设备都有自己的数据：

```
static const struct platform_device_id sdma_devtypes[] = { 
    { 
        .name = "imx51-sdma", 
        .driver_data = (unsigned long)&sdma_imx51, 
    }, { 
        .name = "imx53-sdma", 
        .driver_data = (unsigned long)&sdma_imx53, 
    }, { 
        .name = "imx6q-sdma", 
        .driver_data = (unsigned long)&sdma_imx6q, 
    }, { 
        .name = "imx7d-sdma", 
        .driver_data = (unsigned long)&sdma_imx7d, 
    }, { 
        /* sentinel */ 
    } 
}; 
MODULE_DEVICE_TABLE(platform, sdma_devtypes); 
```

我们对 OF 匹配样式也是一样的：

```
static const struct of_device_idsdma_dt_ids[] = { 
    { .compatible = "fsl,imx6q-sdma", .data = &sdma_imx6q, }, 
    { .compatible = "fsl,imx53-sdma", .data = &sdma_imx53, }, 
       { .compatible = "fsl,imx51-sdma", .data = &sdma_imx51, }, 
    { .compatible = "fsl,imx7d-sdma", .data = &sdma_imx7d, }, 
    { /* sentinel */ } 
}; 
MODULE_DEVICE_TABLE(of, sdma_dt_ids); 
```

`probe`函数将如下所示：

```
static int sdma_probe(structplatform_device *pdev) 
{ 
conststructof_device_id *of_id = 
of_match_device(of_match_ptr(sdma_dt_ids), &pdev->dev); 
structdevice_node *np = pdev->dev.of_node; 

    /* If devicetree, */ 
    if (of_id) 
drvdata = of_id->data; 
    /* else, hard-coded */ 
    else if (pdev->id_entry) 
drvdata = (void *)pdev->id_entry->driver_data; 

    if (!drvdata) { 
dev_err(&pdev->dev, "unable to find driver data\n"); 
        return -EINVAL; 
    } 
    [...] 
} 
```

然后我们声明我们的平台驱动程序；将所有在前面的部分中定义的数组都传递进去：

```
static struct platform_driversdma_driver = { 
    .driver = { 
    .name   = "imx-sdma", 
    .of_match_table = of_match_ptr(sdma_dt_ids), 
    }, 
    .id_table  = sdma_devtypes, 
    .remove  = sdma_remove, 
    .probe   = sdma_probe, 
}; 
module_platform_driver(sdma_driver); 
```

# 平台资源和 DT

平台设备可以在启用设备树的系统中工作，无需任何额外修改。这就是我们在“处理资源”部分中所展示的。通过使用`platform_xxx`系列函数，核心还会遍历 DT（使用`of_xxx`系列函数）以找到所需的资源。反之则不成立，因为`of_xxx`系列函数仅保留给 DT 使用。所有资源数据将以通常的方式提供给驱动程序。现在驱动程序知道这个设备是否是在板文件中以硬编码参数初始化的。让我们以一个 uart 设备节点为例：

```
uart1: serial@02020000 { 
    compatible = "fsl,imx6q-uart", "fsl,imx21-uart"; 
reg = <0x02020000 0x4000>; 
    interrupts = <0 26 IRQ_TYPE_LEVEL_HIGH>; 
dmas = <&sdma 25 4 0>, <&sdma 26 4 0>; 
dma-names = "rx", "tx"; 
}; 
```

以下摘录描述了其驱动程序的`probe`函数。在`probe`中，函数“platform_get_resource（）”可用于提取任何资源（内存区域、DMA、中断），或特定功能，如“platform_get_irq（）”，它提取 DT 中`interrupts`属性提供的`irq`：

```
static int my_probe(struct platform_device *pdev) 
{ 
struct iio_dev *indio_dev; 
struct resource *mem, *dma_res; 
struct xadc *xadc; 
int irq, ret, dmareq; 

    /* irq */ 
irq = platform_get_irq(pdev, 0); 
    if (irq<= 0) 
        return -ENXIO; 
    [...] 

    /* memory region */ 
mem = platform_get_resource(pdev, IORESOURCE_MEM, 0); 
xadc->base = devm_ioremap_resource(&pdev->dev, mem); 
    /* 
     * We could have used 
     *      devm_ioremap(&pdev->dev, mem->start, resource_size(mem)); 
     * too. 
     */ 
    if (IS_ERR(xadc->base)) 
        return PTR_ERR(xadc->base); 
    [...] 

    /* second dma channel */ 
dma_res = platform_get_resource(pdev, IORESOURCE_DMA, 1); 
dmareq = dma_res->start; 

    [...] 
} 
```

总之，对于诸如`dma`、`irq`和`mem`之类的属性，您在平台驱动程序中无需做任何匹配`dtb`的工作。如果有人记得，这些数据与作为平台资源传递的数据类型相同。要理解原因，我们只需查看这些函数的内部处理方式；我们将看到它们如何内部处理 DT 函数。以下是`platform_get_irq`函数的示例：

```
int platform_get_irq(struct platform_device *dev, unsigned int num) 
{ 
    [...] 
    struct resource *r; 
    if (IS_ENABLED(CONFIG_OF_IRQ) &&dev->dev.of_node) { 
        int ret; 

        ret = of_irq_get(dev->dev.of_node, num); 
        if (ret > 0 || ret == -EPROBE_DEFER) 
            return ret; 
    } 

    r = platform_get_resource(dev, IORESOURCE_IRQ, num); 
    if (r && r->flags & IORESOURCE_BITS) { 
        struct irq_data *irqd; 
        irqd = irq_get_irq_data(r->start); 
        if (!irqd) 
            return -ENXIO; 
        irqd_set_trigger_type(irqd, r->flags & IORESOURCE_BITS); 
    } 
    return r ? r->start : -ENXIO; 
} 
```

也许有人会想知道`platform_xxx`函数如何从 DT 中提取资源。这应该是`of_xxx`函数族。你是对的，但在系统启动期间，内核会在每个设备节点上调用“of_platform_device_create_pdata（）”，这将导致创建一个带有相关资源的平台设备，您可以在其上调用`platform_xxx`系列函数。其原型如下：

```
static struct platform_device *of_platform_device_create_pdata( 
                 struct device_node *np, const char *bus_id, 
                 void *platform_data, struct device *parent) 
```

# 平台数据与 DT

如果您的驱动程序期望平台数据，您应该检查`dev.platform_data`指针。非空值意味着您的驱动程序已在板配置文件中以旧方式实例化，并且 DT 不涉及其中。对于从 DT 实例化的驱动程序，`dev.platform_data`将为`NULL`，并且您的平台设备将获得指向与`dev.of_node`指针中对应于您设备的 DT 条目（节点）的指针，从中可以提取资源并使用 OF API 来解析和提取应用程序数据。

还有一种混合方法可以用来将在 C 文件中声明的平台数据与 DT 节点关联起来，但这只适用于特殊情况：DMA、IRQ 和内存。这种方法仅在驱动程序仅期望资源而不是特定应用程序数据时使用。

可以将 I2C 控制器的传统声明转换为 DT 兼容节点，如下所示：

```
#define SIRFSOC_I2C0MOD_PA_BASE 0xcc0e0000 
#define SIRFSOC_I2C0MOD_SIZE 0x10000 
#define IRQ_I2C0 
static struct resource sirfsoc_i2c0_resource[] = { 
    { 
        .start = SIRFSOC_I2C0MOD_PA_BASE, 
        .end = SIRFSOC_I2C0MOD_PA_BASE + SIRFSOC_I2C0MOD_SIZE - 1, 
        .flags = IORESOURCE_MEM, 
    },{ 
        .start = IRQ_I2C0, 
        .end = IRQ_I2C0, 
        .flags = IORESOURCE_IRQ, 
    }, 
}; 
```

和 DT 节点：

```
i2c0: i2c@cc0e0000 { 
    compatible = "sirf,marco-i2c"; 
    reg = <0xcc0e0000 0x10000>; 
    interrupt-parent = <&phandle_to_interrupt_controller_node> 
    interrupts = <0 24 0>; 
    #address-cells = <1>; 
    #size-cells = <0>; 
    status = "disabled"; 
}; 
```

# 总结

现在是从硬编码设备配置切换到 DT 的时候了。本章为您提供了处理 DT 所需的一切。现在您已经具备了自定义或添加任何节点和属性到 DT 中，并从驱动程序中提取它们的必要技能。在下一章中，我们将讨论 I2C 驱动程序，并使用 DT API 来枚举和配置我们的 I2C 设备。
