# Linux 设备驱动开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/6B7A321F07B3F3827350A558F12EF0DA`](https://zh.annas-archive.org/md5/6B7A321F07B3F3827350A558F12EF0DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：高级字符驱动程序操作

在之前的章节中，我们学到了一些在设备驱动程序开发中很有用的东西；然而，还需要一步。我们必须看看如何为我们的字符设备添加高级功能，并充分理解如何将用户空间进程与外围 I/O 活动同步。

在本章中，我们将看到如何为`lseek()`、`ioctl()`和`mmap()`函数实现系统调用，并且我们还将了解几种技术来使进程进入睡眠状态，以防我们的外围设备尚未有数据返回；因此，在本章中，我们将涵盖以下配方：

+   在文件中上下移动 lseek()

+   使用 ioctl()进行自定义命令

+   使用 mmap()访问 I/O 内存

+   与进程上下文锁定

+   锁定（和同步）中断上下文

+   使用 poll()和 select()等待 I/O 操作

+   使用 fasync()管理异步通知

# 技术要求

有关更多信息，请查看本章的附录部分。

本章中使用的代码和其他文件可以从 GitHub 上下载，网址为[`github.com/giometti/linux_device_driver_development_cookbook/tree/master/chapter_07`](https://github.com/giometti/linux_device_driver_development_cookbook/tree/master/chapter_07)。

# 在文件中上下移动 lseek()

在这个配方中，我们将更仔细地看一下如何操纵`ppos`指针（在第三章中的*与字符驱动程序交换数据*配方中描述），这与`read()`和`write()`系统调用的实现有关。

# 准备就绪

为了提供`lseek()`实现的一个简单示例，我们可以在第四章中的`chapter_04/chrdev`目录中重用我们的`chrdev`驱动程序（我们需要 GitHub 存储库的`chrdev.c`和`chrdev-req.c`文件），在那里我们可以根据我们的设备内存布局简单地添加我们的自定义`llseek()`方法。

为简单起见，我只是将这些文件复制到`chapter_07/chrdev/`目录中，并对其进行了重新处理。

我们还需要修改 ESPRESSObin 的 DTS 文件，就像我们在第四章中使用`chapter_04/chrdev/add_chrdev_devices.dts.patch`文件一样，以启用 chrdev 设备，然后最后，我们可以重用第三章中创建的`chrdev_test.c`程序，作为我们的`lseek()`实现测试的基本程序。

关于 ESPRESSObin 的 DTS 文件，我们可以通过进入内核源并执行`patch`命令来修补它，如下所示：

```
$ patch -p1 < ../github/chapter_04/chrdev/add_chrdev_devices.dts.patch 
patching file arch/arm64/boot/dts/marvell/armada-3720-espressobin.dts
```

然后，我们必须重新编译内核，并像我们在第一章中所做的那样，使用前述的 DTS 重新安装内核，最后，重新启动系统。

# 如何做...

让我们看看如何通过以下步骤来做到这一点：

1.  首先，我们可以通过添加我们的`chrdev_llseek`方法来简单地重新定义`struct file_operations`：

```
static const struct file_operations chrdev_fops = {
    .owner   = THIS_MODULE,
    .llseek  = chrdev_llseek,
    .read    = chrdev_read,
    .write   = chrdev_write,
    .open    = chrdev_open,
    .release = chrdev_release
};
```

1.  然后，我们通过使用一个大开关来定义方法的主体，根据驱动程序的内存布局来处理`SEEK_SET`、`SEEK_CUR`和`SEEK_END`可能的值：

```
static loff_t chrdev_llseek(struct file *filp, loff_t offset, int whence)
{
    struct chrdev_device *chrdev = filp->private_data;
    loff_t newppos;

    dev_info(chrdev->dev, "should move *ppos=%lld by whence %d off=%lld\n",
                filp->f_pos, whence, offset);

    switch (whence) {
    case SEEK_SET:
        newppos = offset; 
        break;

    case SEEK_CUR:
        newppos = filp->f_pos + offset; 
        break;

    case SEEK_END:
        newppos = BUF_LEN + offset; 
        break;

    default:
        return -EINVAL;
    }
```

1.  最后，我们必须验证`newppos`是否仍在 0 和`BUF_LEN`之间，并且在肯定的情况下，我们必须更新`filp->f_pos`为`newppos`值，如下所示：

```
    if ((newppos < 0) || (newppos >= BUF_LEN))
        return -EINVAL;

    filp->f_pos = newppos;
    dev_info(chrdev->dev, "return *ppos=%lld\n", filp->f_pos);

    return newppos;
}
```

请注意，可以从 GitHub 源中的`chapter_07/`目录中检索到`chrdev.c`驱动程序的新版本，该目录与本章相关。

# 它是如何工作的...

在*步骤 2*中，我们应该记住每个设备有一个`BUF_LEN`字节的内存缓冲区，因此我们可以通过执行一些简单的操作来计算设备内的新`newppos`位置。

因此，对于`SEEK_SET`，将`ppos`设置为`offset`，我们可以简单地执行赋值操作；对于`SEEK_CUR`，将`ppos`从其当前位置（即`filp->f_pos`）加上`offset`字节，我们执行求和操作；最后，对于`SEEK_END`，将`ppos`设置为文件末尾加上`offset`字节，我们仍然执行与`BUF_LEN`缓冲区大小的求和操作，因为我们期望从用户空间得到负值或零。

# 还有更多...

如果您现在希望测试`lseek()`系统调用，我们可以修改之前报告的`chrdev_test.c`程序，然后尝试在我们的新驱动程序版本上执行它。

因此，让我们使用`modify_lseek_to_chrdev_test.patch`文件修改`chrdev_test.c`，如下所示：

```
$ cd github/chapter_03/
$ patch -p2 < ../chapter_07/chrdev/modify_lseek_to_chrdev_test.patch 
```

然后，我们必须重新编译它，如下所示：

```
$ make CFLAGS="-Wall -O2" \
 CC=aarch64-linux-gnu-gcc \
 chrdev_test
aarch64-linux-gnu-gcc -Wall -O2 chrdev_test.c -o chrdev_test
```

请注意，可以通过简单地删除`CC=aarch64-linux-gnu-gcc`设置在 ESPRESSObin 上执行此命令。

然后，我们必须将新的`chrdev_test`可执行文件和具有`lseek()`支持的`chrdev.ko`（以及`chrdev-req.ko`内核模块）移动到 ESPRESSObin，然后将它们插入内核：

```
# insmod chrdev.ko 
chrdev:chrdev_init: got major 239
# insmod chrdev-req.ko
chrdev cdev-eeprom@2: chrdev cdev-eeprom with id 2 added
chrdev cdev-rom@4: chrdev cdev-rom with id 4 added

```

这个输出来自串行控制台，因此我们也会得到内核消息。如果您通过 SSH 连接执行这些命令，您将得不到输出，您将不得不使用`dmesg`命令来获取前面示例中的输出。

最后，我们可以在一个 chrdev 设备上执行`chrdev_test`程序，如下所示：

```
# ./chrdev_test /dev/cdev-eeprom\@2 
file /dev/cdev-eeprom@2 opened
wrote 11 bytes into file /dev/cdev-eeprom@2
data written are: 44 55 4d 4d 59 20 44 41 54 41 00 
*ppos moved to 0
read 11 bytes from file /dev/cdev-eeprom@2
data read are: 44 55 4d 4d 59 20 44 41 54 41 00 
```

正如预期的那样，`lseek()`系统调用调用了驱动程序的`chrdev_llseek()`方法，这正是我们所期望的。与前述命令相关的内核消息如下所示：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: should write 11 bytes (*ppos=0)
chrdev cdev-eeprom@2: got 11 bytes (*ppos=11)
chrdev cdev-eeprom@2: should move *ppos=11 by whence 0 off=0
chrdev cdev-eeprom@2: return *ppos=0
chrdev cdev-eeprom@2: should read 11 bytes (*ppos=0)
chrdev cdev-eeprom@2: return 11 bytes (*ppos=11)
chrdev cdev-eeprom@2: chrdev (id=2) released
```

因此，当第一个`write()`系统调用执行时，`ppos`从字节 0 移动到字节 11，然后由于`lseek()`的作用又移回到 0，最后由于`read()`系统调用的执行又移动到 11。

请注意，我们还可以使用`dd`命令调用`lseek()`方法，如下所示：

```
# dd if=/dev/cdev-eeprom\@2 skip=11 bs=1 count=3 | od -tx1
3+0 records in
3+0 records out
3 bytes copied, 0.0530299 s, 0.1 kB/s
0000000 00 00 00
0000003

```

在这里，我们打开设备，然后将`ppos`从开头向前移动 11 个字节，然后对每个进行三次 1 字节长度的读取。

在以下内核消息中，我们可以验证`dd`程序的行为与预期完全一致：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: should move *ppos=0 by whence 1 off=0
chrdev cdev-eeprom@2: return *ppos=0
chrdev cdev-eeprom@2: should move *ppos=0 by whence 1 off=11
chrdev cdev-eeprom@2: return *ppos=11
chrdev cdev-eeprom@2: should read 1 bytes (*ppos=11)
chrdev cdev-eeprom@2: return 1 bytes (*ppos=12)
chrdev cdev-eeprom@2: should read 1 bytes (*ppos=12)
chrdev cdev-eeprom@2: return 1 bytes (*ppos=13)
chrdev cdev-eeprom@2: should read 1 bytes (*ppos=13)
chrdev cdev-eeprom@2: return 1 bytes (*ppos=14)
chrdev cdev-eeprom@2: chrdev (id=2) released
```

# 另请参阅

+   有关`lseek()`系统调用的更多信息，一个很好的起点是它的 man 页面，可以使用`man 2 lseek`命令获取。

# 使用 ioctl()进行自定义命令

在本教程中，我们将看到如何以非常定制的方式添加自定义命令来配置或管理我们的外围设备。

# 准备工作完成

现在，为了展示如何在我们的驱动程序中实现`ioctl()`系统调用的简单示例，我们仍然可以使用之前介绍的 chrdev 驱动程序，在其中添加`unlocked_ioctl()`方法，如后面所述。

# 如何做...

让我们按照以下步骤来做：

1.  首先，我们必须在`chrdev_fops`结构中添加`unlocked_ioctl()`方法：

```
static const struct file_operations chrdev_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = chrdev_ioctl,
    .llseek         = chrdev_llseek,
    .read           = chrdev_read,
    .write          = chrdev_write,
    .open           = chrdev_open,
    .release        = chrdev_release
};
```

1.  然后，我们添加方法的主体，在开始时，我们进行了一些赋值和检查，如下所示：

```
static long chrdev_ioctl(struct file *filp,
                unsigned int cmd, unsigned long arg)
{
    struct chrdev_device *chrdev = filp->private_data;
    struct chrdev_info info;
    void __user *uarg = (void __user *) arg;
    int __user *iuarg = (int __user *) arg;
    int ret;

    /* Get some command information */
    if (_IOC_TYPE(cmd) != CHRDEV_IOCTL_BASE) {
        dev_err(chrdev->dev, "command %x is not for us!\n", cmd);
        return -EINVAL;
    }
    dev_info(chrdev->dev, "cmd nr=%d size=%d dir=%x\n",
                _IOC_NR(cmd), _IOC_SIZE(cmd), _IOC_DIR(cmd));
```

1.  然后，我们可以实现一个大开关来执行请求的命令，如下所示：

```
    switch (cmd) {
    case CHRDEV_IOC_GETINFO:
        dev_info(chrdev->dev, "CHRDEV_IOC_GETINFO\n");

        strncpy(info.label, chrdev->label, NAME_LEN);
        info.read_only = chrdev->read_only;

        ret = copy_to_user(uarg, &info, sizeof(struct chrdev_info));
        if (ret)
            return -EFAULT;

        break;

    case WDIOC_SET_RDONLY:
        dev_info(chrdev->dev, "WDIOC_SET_RDONLY\n");

        ret = get_user(chrdev->read_only, iuarg); 
        if (ret)
            return -EFAULT;

        break;

    default:
        return -ENOIOCTLCMD;
    }

    return 0;
}
```

1.  在最后一步中，我们必须定义`chrdev_ioctl.h`包含文件，以便与用户空间共享，其中包含在前面的代码块中定义的`ioctl()`命令：

```
/*
 * Chrdev ioctl() include file
 */

#include <linux/ioctl.h>
#include <linux/types.h>

#define CHRDEV_IOCTL_BASE    'C'
#define CHRDEV_NAME_LEN      32

struct chrdev_info {
    char label[CHRDEV_NAME_LEN];
    int read_only;
};

/*
 * The ioctl() commands
 */

#define CHRDEV_IOC_GETINFO _IOR(CHRDEV_IOCTL_BASE, 0, struct chrdev_info)
#define WDIOC_SET_RDONLY _IOW(CHRDEV_IOCTL_BASE, 1, int)
```

# 工作原理...

在*步骤 2*中，将使用`info`、`uarg`和`iuarg`变量，而使用`_IOC_TYPE()`宏是为了通过检查命令的类型与`CHRDEV_IOCTL_BASE`定义相比较来验证`cmd`命令对我们的驱动程序是否有效。

细心的读者应该注意，由于命令类型只是一个随机数，因此此检查并不是绝对可靠的；但是，对于我们在这里的目的来说可能已经足够了。

此外，通过使用`_IOC_NR()`、`_IOC_SIZE()`和`_IOC_DIR()`，我们可以从命令中提取其他信息，这对进一步的检查可能有用。

在*步骤 3*中，我们可以看到对于每个命令，根据它是读取还是写入（或两者），我们必须通过使用适当的访问函数从用户空间获取或放置用户数据，如第三章中所解释的那样，*使用字符驱动程序*，以避免内存损坏！

现在应该清楚`info`、`uarg`和`iuarg`变量是如何使用的。第一个用于本地存储`struct chrdev_info`数据，而其他变量用于具有适当类型的数据，以便与`copy_to_user()`或`get_user()`函数一起使用。

# 还有更多...

为了测试代码并查看其行为，我们需要制作一个适当的工具来执行我们的新`ioctl()`命令。

`chrdev_ioctl.c`文件中提供了一个示例，并在下面的片段中使用了`ioctl()`调用：

```
    /* Try reading device info */
    ret = ioctl(fd, CHRDEV_IOC_GETINFO, &info);
        if (ret < 0) {
            perror("ioctl(CHRDEV_IOC_GETINFO)");
            exit(EXIT_FAILURE);
        }
    printf("got label=%s and read_only=%d\n", info.label, info.read_only);

    /* Try toggling the device reading mode */
    read_only = !info.read_only;
    ret = ioctl(fd, WDIOC_SET_RDONLY, &read_only);
        if (ret < 0) {
            perror("ioctl(WDIOC_SET_RDONLY)");
            exit(EXIT_FAILURE);
        }
    printf("device has now read_only=%d\n", read_only);
```

现在，让我们在主机 PC 上使用下一个命令行编译`chrdev_ioctl.c`程序：

```
$ make CFLAGS="-Wall -O2 -Ichrdev/" \
 CC=aarch64-linux-gnu-gcc \
 chrdev_ioctl aarch64-linux-gnu-gcc -Wall -O2 chrdev_ioctl.c -o chrdev_ioctl 
```

请注意，这个命令也可以在 ESPRESSObin 上执行，只需删除`CC=aarch64-linux-gnu-gcc`设置。

现在，如果我们尝试在 chrdev 设备上执行该命令，我们应该得到以下输出：

```
# ./chrdev_ioctl /dev/cdev-eeprom\@2
file /dev/cdev-eeprom@2 opened
got label=cdev-eeprom and read_only=0
device has now read_only=1
```

当然，为了使其工作，我们将已经加载了包含`ioctl()`方法的新 chrdev 驱动程序版本。

在内核消息中，我们应该得到以下内容：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: cmd nr=0 size=36 dir=2
chrdev cdev-eeprom@2: CHRDEV_IOC_GETINFO
chrdev cdev-eeprom@2: cmd nr=1 size=4 dir=1
chrdev cdev-eeprom@2: WDIOC_SET_RDONLY
chrdev cdev-eeprom@2: chrdev (id=2) released
```

如我们所见，在设备打开后，两个`ioctl()`命令按预期执行。

# 另请参阅

+   有关`ioctl()`系统调用的更多信息，一个很好的起点是它的 man 页面，可以使用`man 2 ioctl`命令获得。

# 使用 mmap()访问 I/O 内存

在这个示例中，我们将看到如何映射一个 I/O 内存区域到进程内存空间，以便通过内存中的指针访问我们的外围设备内部。

# 准备就绪

现在，让我们看看如何为我们的 chrdev 驱动程序实现自定义的`mmap()`系统调用。

由于我们有一个完全映射到内存中的虚拟设备，我们可以假设`struct chrdev_device`中的`buf`缓冲区代表要映射的内存区域。此外，我们需要动态分配它以便重新映射；这是因为内核虚拟内存地址不能使用`remap_pfn_range()`函数重新映射。

这是`remap_pfn_range()`的唯一限制，它无法重新映射未动态分配的内核虚拟内存地址。这些地址也可以重新映射，但是使用本书未涵盖的另一种技术。

为了准备我们的驱动程序，我们必须对`struct chrdev_device`进行以下修改：

```
diff --git a/chapter_07/chrdev/chrdev.h b/chapter_07/chrdev/chrdev.h
index 6b925fe..40a244f 100644
--- a/chapter_07/chrdev/chrdev.h
+++ b/chapter_07/chrdev/chrdev.h
@@ -7,7 +7,7 @@

 #define MAX_DEVICES 8
 #define NAME_LEN    CHRDEV_NAME_LEN
-#define BUF_LEN     300
+#define BUF_LEN     PAGE_SIZE

 /*
  * Chrdev basic structs
@@ -17,7 +17,7 @@
 struct chrdev_device {
     char label[NAME_LEN];
     unsigned int busy : 1;
-    char buf[BUF_LEN];
+    char *buf;
     int read_only;

     unsigned int id;
```

请注意，我们还修改了缓冲区大小，至少为`PAGE_SIZE`长，因为我们不能重新映射小于`PAGE_SIZE`字节的内存区域。

然后，为了动态分配内存缓冲区，我们必须进行以下列出的修改：

```
diff --git a/chapter_07/chrdev/chrdev.c b/chapter_07/chrdev/chrdev.c
index 3717ad2..a8bffc3 100644
--- a/chapter_07/chrdev/chrdev.c
+++ b/chapter_07/chrdev/chrdev.c
@@ -7,6 +7,7 @@
 #include <linux/module.h>
 #include <linux/fs.h>
 #include <linux/uaccess.h>
+#include <linux/slab.h>
 #include <linux/mman.h>

@@ -246,6 +247,13 @@ int chrdev_device_register(const char *label, unsigned int 
id,
          return -EBUSY;
      }

+     /* First try to allocate memory for internal buffer */
+     chrdev->buf = kzalloc(BUF_LEN, GFP_KERNEL);
+     if (!chrdev->buf) {
+         dev_err(chrdev->dev, "cannot allocate memory buffer!\n");
+         return -ENOMEM;
+     }
+
      /* Create the device and initialize its data */
      cdev_init(&chrdev->cdev, &chrdev_fops);
      chrdev->cdev.owner = owner;
@@ -255,7 +263,7 @@ int chrdev_device_register(const char *label, unsigned int id,
      if (ret) {
          pr_err("failed to add char device %s at %d:%d\n",
                            label, MAJOR(chrdev_devt), id);
-         return ret;
+         goto kfree_buf;
      }
 chrdev->dev = device_create(chrdev_class, parent, devt, chrdev,
```

这是前面`diff`文件的延续：

```
@@ -272,7 +280,6 @@ int chrdev_device_register(const char *label, unsigned int id,
      chrdev->read_only = read_only;
      chrdev->busy = 1;
      strncpy(chrdev->label, label, NAME_LEN);
-     memset(chrdev->buf, 0, BUF_LEN);

      dev_info(chrdev->dev, "chrdev %s with id %d added\n", label, id);

@@ -280,6 +287,8 @@ int chrdev_device_register(const char *label, unsigned int id,

  del_cdev:
      cdev_del(&chrdev->cdev);
+ kfree_buf:
+     kfree(chrdev->buf);

      return ret;
 }
@@ -309,6 +318,9 @@ int chrdev_device_unregister(const char *label, unsigned int id)

      dev_info(chrdev->dev, "chrdev %s with id %d removed\n", label, id);

+     /* Free allocated memory */
+     kfree(chrdev->buf);
+
        /* Dealocate the device */
        device_destroy(chrdev_class, chrdev->dev->devt);
        cdev_del(&chrdev->cdev);
```

然而，除了这个小注释，我们可以像之前一样继续，即修改我们的 chrdev 驱动程序并添加新的方法。

# 如何做...

让我们按照以下步骤来做：

1.  与前几节一样，第一步是将我们的新`mmap()`方法添加到驱动程序的`struct file_operations`中：

```
static const struct file_operations chrdev_fops = {
    .owner          = THIS_MODULE,
    .mmap           = chrdev_mmap,
    .unlocked_ioctl = chrdev_ioctl,
    .llseek         = chrdev_llseek,
    .read           = chrdev_read,
    .write          = chrdev_write,
    .open           = chrdev_open,
    .release        = chrdev_release
};
```

1.  然后，我们添加`chrdev_mmap()`实现，如前一节中所解释的并在下面报告：

```
static int chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct chrdev_device *chrdev = filp->private_data;
    size_t size = vma->vm_end - vma->vm_start;
    phys_addr_t offset = (phys_addr_t) vma->vm_pgoff << PAGE_SHIFT;
    unsigned long pfn;

    /* Does it even fit in phys_addr_t? */
    if (offset >> PAGE_SHIFT != vma->vm_pgoff)
        return -EINVAL;

    /* We cannot mmap too big areas */
    if ((offset > BUF_LEN) || (size > BUF_LEN - offset))
        return -EINVAL;
```

1.  然后，我们必须获取`buf`缓冲区的物理地址：

```
    /* Get the physical address belong the virtual kernel address */
    pfn = virt_to_phys(chrdev->buf) >> PAGE_SHIFT;
```

请注意，如果我们只想重新映射外围设备映射的物理地址，则不需要这一步。

1.  最后，我们可以进行重新映射：

```
    /* Remap-pfn-range will mark the range VM_IO */
    if (remap_pfn_range(vma, vma->vm_start,
                pfn, size,
                vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}
```

# 它是如何工作的...

在*步骤 2*中，函数从一些健全性检查开始，我们必须验证所请求的内存区域是否与系统和外围设备的要求兼容。在我们的示例中，我们必须验证内存区域的大小和偏移量，以及映射开始的位置是否在`buf`的大小（`BUF_LEN`字节）内。

# 还有更多...

为了测试我们的新的`mmap()`实现，我们可以使用之前介绍的`chrdev_mmap.c`程序。在这里我们谈到了`textfile.txt`。要编译它，我们可以在主机 PC 上使用以下命令：

```
$ make CFLAGS="-Wall -O2" \
 CC=aarch64-linux-gnu-gcc \
 chrdev_mmap
aarch64-linux-gnu-gcc -Wall -O2 chrdev_mmap.c -o chrdev_mmap
```

请注意，可以通过简单删除`CC=aarch64-linux-gnu-gcc`设置在 ESPRESSObin 中执行此命令。

现在，让我们开始在驱动程序中写点东西：

```
# cp textfile.txt /dev/cdev-eeprom\@2
```

内核消息如下：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: chrdev (id=2) released
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: should write 54 bytes (*ppos=0)
chrdev cdev-eeprom@2: got 54 bytes (*ppos=54)
chrdev cdev-eeprom@2: chrdev (id=2) released
```

现在，如预期的那样，在我们的内存缓冲区中有`textfile.txt`的内容；实际上：

```
# cat /dev/cdev-eeprom\@2 
This is a test file

This is line 3.

End of the file
```

现在我们可以尝试在我们的设备上执行`chrdev_mmap`程序，以验证一切是否正常工作：

```
# ./chrdev_mmap /dev/cdev-eeprom\@2 54
file /dev/cdev-eeprom@2 opened
got address=0xffff9896c000 and len=54
---
This is a test file

This is line 3.

End of the file
```

请注意，我们必须确保不指定大于设备缓冲区大小的值，例如在我们的示例中为 4,096。实际上，如果我们这样做，会出现错误：

**`./chrdev_mmap /dev/cdev-eeprom\@2 4097`**

`file /dev/cdev-eeprom@2 opened`

`mmap: Invalid argument`

这意味着我们成功了！请注意，`chrdev_mmap`程序（如`cp`和`cat`）在通常文件和我们的字符设备上的工作完全相同。

与`mmap()`执行相关的内核消息如下：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: mmap vma=ffff9896c000 pfn=79ead size=1000
chrdev cdev-eeprom@2: chrdev (id=2) released
```

请注意，在重新映射之后，程序不执行任何系统调用来访问数据。这导致在获取对设备数据的访问权限时，可能会比我们需要使用`read()`或`write()`系统调用的情况下性能更好。

我们还可以通过向`chrdev_mmap`程序添加可选参数`0`来修改缓冲区内容，如下所示：

```
./chrdev_mmap /dev/cdev-eeprom\@2 54 0
file /dev/cdev-eeprom@2 opened
got address=0xffff908ef000 and len=54
---
This is a test file

This is line 3.

End of the file
---
First character changed to '0'
```

然后，当我们使用`read()`系统调用和`cat`命令再次读取缓冲区时，我们可以看到文件中的第一个字符已经按预期更改为 0：

```
# cat /dev/cdev-eeprom\@2 
0his is a test file

This is line 3.

End of the file
```

# 另请参阅

+   有关`mmap()`的更多信息，一个很好的起点是它的 man 页面（`man 2 mmap`）；然后，查看[`linux-kernel-labs.github.io/master/labs/memory_mapping.html`](https://linux-kernel-labs.github.io/master/labs/memory_mapping.html)会更好。

# 使用进程上下文进行锁定

在这个示例中，我们将看到如何保护数据，以防止两个或更多进程并发访问，以避免竞争条件。

# 如何做...

为了简单地演示如何向 chrdev 驱动程序添加互斥体，我们可以对其进行一些修改，如下所示。

1.  首先，我们必须在`chrdev.h`头文件中的驱动程序主结构中添加`mux`互斥体，如下所示：

```
/* Main struct */
struct chrdev_device {
    char label[NAME_LEN];
    unsigned int busy : 1;
    char *buf;
    int read_only;

    unsigned int id;
    struct module *owner;
    struct cdev cdev;
    struct device *dev;

    struct mutex mux;
};
```

这里介绍的所有修改都可以应用于 chrdev 代码，使用`add_mutex_to_chrdev.patch`文件中的`patch`命令，如下所示：

**`$ patch -p3 < add_mutex_to_chrdev.patch`**

1.  然后，在`chrdev_device_register()`函数中，我们必须使用`mutex_init()`函数初始化互斥体：

```
    /* Init the chrdev data */
    chrdev->id = id;
    chrdev->read_only = read_only;
    chrdev->busy = 1;
    strncpy(chrdev->label, label, NAME_LEN);
    mutex_init(&chrdev->mux);

    dev_info(chrdev->dev, "chrdev %s with id %d added\n", label, id);

    return 0;
```

1.  接下来，我们可以修改`read()`和`write()`方法以保护它们。然后，`read()`方法应该如下所示：

```
static ssize_t chrdev_read(struct file *filp,
               char __user *buf, size_t count, loff_t *ppos)
{
    struct chrdev_device *chrdev = filp->private_data;
    int ret;

    dev_info(chrdev->dev, "should read %ld bytes (*ppos=%lld)\n",
                count, *ppos);
    mutex_lock(&chrdev->mux); // Grab the mutex

    /* Check for end-of-buffer */
    if (*ppos + count >= BUF_LEN)
        count = BUF_LEN - *ppos;

    /* Return data to the user space */
    ret = copy_to_user(buf, chrdev->buf + *ppos, count);
    if (ret < 0) {
        count = -EFAULT;
        goto unlock;
    }

    *ppos += count;
    dev_info(chrdev->dev, "return %ld bytes (*ppos=%lld)\n", count, *ppos);

unlock:
    mutex_unlock(&chrdev->mux); // Release the mutex

    return count;
}
```

`write()`方法报告如下：

```
static ssize_t chrdev_write(struct file *filp,
                const char __user *buf, size_t count, loff_t *ppos)
{
    struct chrdev_device *chrdev = filp->private_data;
    int ret;

    dev_info(chrdev->dev, "should write %ld bytes (*ppos=%lld)\n",
                count, *ppos);

    if (chrdev->read_only)
        return -EINVAL;

    mutex_lock(&chrdev->mux); // Grab the mutex

    /* Check for end-of-buffer */
    if (*ppos + count >= BUF_LEN)
        count = BUF_LEN - *ppos;

    /* Get data from the user space */
    ret = copy_from_user(chrdev->buf + *ppos, buf, count);
    if (ret < 0) {
        count = -EFAULT;
        goto unlock;
    }

    *ppos += count;
    dev_info(chrdev->dev, "got %ld bytes (*ppos=%lld)\n", count, *ppos);

unlock:
    mutex_unlock(&chrdev->mux); // Release the mutex

    return count;
}
```

1.  最后，我们还必须保护`ioctl()`方法，因为驱动程序的`read_only`属性可能会改变：

```
static long chrdev_ioctl(struct file *filp,
            unsigned int cmd, unsigned long arg)
{
    struct chrdev_device *chrdev = filp->private_data;
    struct chrdev_info info;
    void __user *uarg = (void __user *) arg;
    int __user *iuarg = (int __user *) arg;
    int ret;

...

    /* Grab the mutex */
    mutex_lock(&chrdev->mux);

    switch (cmd) {
    case CHRDEV_IOC_GETINFO:
        dev_info(chrdev->dev, "CHRDEV_IOC_GETINFO\n");

...

    default:
        ret = -ENOIOCTLCMD;
        goto unlock;
    }
    ret = 0;

unlock:
    /* Release the mutex */
    mutex_unlock(&chrdev->mux);

    return ret;
}
```

这确实是一个愚蠢的例子，但你应该考虑即使`ioctl()`方法也可能改变驱动程序的数据缓冲区或其他共享数据的情况。

这一次，我们删除了所有的`return`语句，改用`goto`。

# 工作原理...

展示代码的工作原理是非常困难的，因为在复制竞争条件时存在固有的困难，所以最好讨论一下我们可以从中期望什么。

但是，您仍然被鼓励测试代码，也许尝试编写一个更复杂的驱动程序，如果不正确地使用互斥体来管理并发，可能会成为一个真正的问题。

在*步骤 1*中，我们为系统中可能有的每个 chrdev 设备添加了一个互斥体。然后，在*步骤 2*中初始化后，我们可以有效地使用它，如*步骤 3*和*步骤 4*中所述。

通过使用`mutex_lock()`函数，实际上告诉内核没有其他进程可以在这一点之后并发地进行，以确保只有一个进程可以管理驱动程序的共享数据。如果其他进程确实尝试在第一个进程已经持有互斥锁的情况下获取互斥锁，新进程将在它尝试获取已锁定的互斥锁的确切时刻被放入等待队列中进入睡眠状态。

完成后，通过使用`mutex_unlock()`，我们通知内核`mux`互斥锁已被释放，因此，任何等待（即睡眠）的进程将被唤醒；然后，一旦最终重新调度运行，它可以继续并尝试，反过来，抓住锁。

请注意，在*步骤 3*中，在两个函数中，我们在真正有用的时候才抓住互斥锁，而不是在它们的开始；实际上，我们应该尽量保持锁定尽可能小，以保护共享数据（在我们的例子中，`ppos`指针和`buf`数据缓冲区）。通过这样做，我们将我们选择的互斥排除机制的使用限制在代码的最小可能部分（临界区），这个临界区访问我们想要保护免受在先前指定的条件下发生的竞争条件引入的可能破坏。

还要注意的是，我们必须小心，不要在释放锁之前返回，否则新的访问进程将挂起！这就是为什么我们删除了所有的`return`语句，除了最后一个，并且使用`goto`语句跳转到`unlock`标签。

# 另请参阅

+   有关互斥锁和锁定的更多信息，请参阅内核文档目录中的`linux/Documentation/locking/mutex-design.txt`。

# 使用中断上下文进行锁定（和同步）

现在，让我们看看如何避免进程上下文和中断上下文之间的竞争条件。然而，这一次我们必须比以前更加注意，因为这一次我们必须实现一个锁定机制来保护进程上下文和中断上下文之间的共享数据。但是，我们还必须为读取进程和驱动程序之间提供同步机制，以允许读取进程在驱动程序的队列中存在要读取的数据时继续执行其操作。

为了解释这个问题，最好做一个实际的例子。假设我们有一个生成数据供读取进程使用的外围设备。为了通知新数据已到达，外围设备向 CPU 发送中断，因此我们可以想象使用循环缓冲区来实现我们的驱动程序，其中中断处理程序将数据从外围设备保存到缓冲区中，并且任何读取进程可以从中获取数据。

循环缓冲区（也称为环形缓冲区）是固定大小的缓冲区，其工作方式就好像内存是连续的，所有内存位置都以循环方式处理。随着信息从缓冲区生成和消耗，不需要重新整理；我们只需调整头指针和尾指针。添加数据时，头指针前进，而消耗数据时，尾指针前进。如果到达缓冲区的末尾，那么每个指针都会简单地回到环的起始位置。

在这种情况下，我们必须保护循环缓冲区免受进程和中断上下文的竞争条件，因为两者都可以访问它，但我们还必须提供同步机制，以便在没有可供读取的数据时使任何读取进程进入睡眠状态！

在[第五章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=30&action=edit#post_28)中，*管理中断和并发*，我们介绍了自旋锁，它可以用于在进程和中断上下文之间放置锁定机制；我们还介绍了等待队列，它可以用于将读取进程与中断处理程序同步。

# 准备工作

这一次，我们必须使用我们 chrdev 驱动程序的修改版本。在 GitHub 存储库的`chapter_07/chrdev/`目录中，我们可以找到实现我们修改后的驱动程序的`chrdev_irq.c`和`chrdev_irq.h`文件。

我们仍然可以使用`chrdev-req.ko`在系统中生成 chrdev 设备，但现在内核模块将使用`chrdev_irq.ko`而不是`chrdev.ko`。

此外，由于我们有一个真正的外围设备，我们可以使用内核定时器来模拟 IRQ（请参阅[第五章](https://cdp.packtpub.com/linux_device_driver_development_cookbook/wp-admin/post.php?post=30&action=edit#post_28)，*管理中断和并发性*），该定时器还使用以下`get_new_char()`函数触发数据生成：

```
/*
 * Dummy function to generate data
 */

static char get_new_char(void)
{
    static char d = 'A' - 1;

    if (++d == ('Z' + 1))
        d = 'A';

    return d;
}
```

该功能每次调用时都会简单地从 A 到 Z 生成一个新字符，在生成 Z 后重新从字符 A 开始。

为了集中精力关注驱动程序的锁定和同步机制，我们在这里介绍了一些有用的函数来管理循环缓冲区，这是不言自明的。以下是两个检查缓冲区是否为空或已满的函数：

```
/*
 * Circular buffer management functions
 */

static inline bool cbuf_is_empty(size_t head, size_t tail,
                                 size_t len)
{
    return head == tail;
}

static inline bool cbuf_is_full(size_t head, size_t tail,
                                 size_t len)
{
    head = (head + 1) % len;
    return head == tail;
}
```

然后，有两个函数来检查缓冲区的内存区域直到末尾有多少数据或多少空间可用。当我们必须使用`memmove()`等函数时，它们非常有用：

```
static inline size_t cbuf_count_to_end(size_t head, size_t tail,
                                  size_t len)
{
    if (head >= tail)
        return head - tail;
    else
        return len - tail + head;
}

static inline size_t cbuf_space_to_end(size_t head, size_t tail,
                                  size_t len)
{
    if (head >= tail)
        return len - head + tail - 1;
    else
        return tail - head - 1;
}
```

最后，我们可以使用函数正确地向前移动头部或尾部指针，以便在缓冲区末尾时重新开始：

```
static inline void cbuf_pointer_move(size_t *ptr, size_t n,
                                 size_t len)
{
    *ptr = (*ptr + n) % len;
}
```

# 如何做...

让我们按照以下步骤来做：

1.  第一步是通过添加`mux`互斥锁（与以前一样）、`lock`自旋锁、内核`timer`和等待队列`queue`来重写我们驱动程序的主要结构，如下所示：

```
 /* Main struct */
struct chrdev_device {
    char label[NAME_LEN];
    unsigned int busy : 1;
    char *buf;
    size_t head, tail;
    int read_only;

    unsigned int id;
    struct module *owner;
    struct cdev cdev;
    struct device *dev;

    struct mutex mux;
    struct spinlock lock;
    struct wait_queue_head queue;
    struct hrtimer timer;
};
```

1.  然后，在`chrdev_device_register()`函数中进行设备分配期间必须对其进行初始化，如下所示：

```
    /* Init the chrdev data */
    chrdev->id = id;
    chrdev->read_only = read_only;
    chrdev->busy = 1;
    strncpy(chrdev->label, label, NAME_LEN);
    mutex_init(&chrdev->mux);
    spin_lock_init(&chrdev->lock);
    init_waitqueue_head(&chrdev->queue);
    chrdev->head = chrdev->tail = 0;

    /* Setup and start the hires timer */
    hrtimer_init(&chrdev->timer, CLOCK_MONOTONIC,
                        HRTIMER_MODE_REL | HRTIMER_MODE_SOFT);
    chrdev->timer.function = chrdev_timer_handler;
    hrtimer_start(&chrdev->timer, ns_to_ktime(delay_ns),
                        HRTIMER_MODE_REL | HRTIMER_MODE_SOFT);
```

1.  现在，`read()`方法的可能实现如下代码片段所示。我们首先获取互斥锁，以对其他进程进行第一次锁定：

```
static ssize_t chrdev_read(struct file *filp,
                           char __user *buf, size_t count, loff_t *ppos)
{
    struct chrdev_device *chrdev = filp->private_data;
    unsigned long flags;
    char tmp[256];
    size_t n;
    int ret;

    dev_info(chrdev->dev, "should read %ld bytes\n", count);

    /* Grab the mutex */
    mutex_lock(&chrdev->mux);
```

现在，我们可以确信没有其他进程可以超越这一点，但是在中断上下文中运行的一些核心仍然可以这样做！

1.  这就是为什么我们需要以下步骤来确保它们与中断上下文同步：

```
    /* Check for some data into read buffer */
    if (filp->f_flags & O_NONBLOCK) {
        if (cbuf_is_empty(chrdev->head, chrdev->tail, BUF_LEN)) {
            ret = -EAGAIN;
            goto unlock;
        }
    } else if (wait_event_interruptible(chrdev->queue,
        !cbuf_is_empty(chrdev->head, chrdev->tail, BUF_LEN))) {
        count = -ERESTARTSYS;
        goto unlock; 
    }

    /* Grab the lock */
    spin_lock_irqsave(&chrdev->lock, flags);
```

1.  当我们获取了锁时，我们可以确信我们是唯一的读取进程，并且我们也受到中断上下文的保护；因此，我们可以安全地从循环缓冲区读取数据，然后释放锁，如下所示：

```
    /* Get data from the circular buffer */
    n = cbuf_count_to_end(chrdev->head, chrdev->tail, BUF_LEN);
    count = min(count, n); 
    memcpy(tmp, &chrdev->buf[chrdev->tail], count);

    /* Release the lock */
    spin_unlock_irqrestore(&chrdev->lock, flags);
```

请注意，我们必须将数据从循环缓冲区复制到本地缓冲区，而不是直接复制到用户空间缓冲区`buf`，使用`copy_to_user()`函数；这是因为此函数可能会进入睡眠状态，而在我们睡眠时持有自旋锁是不好的！

1.  自旋锁释放后，我们可以安全地调用`copy_to_user()`将数据发送到用户空间：

```
    /* Return data to the user space */
    ret = copy_to_user(buf, tmp, count);
    if (ret < 0) {
        ret = -EFAULT;
        goto unlock; 
    }
```

1.  最后，在释放互斥锁之前，我们必须更新循环缓冲区的`tail`指针，如下所示：

```
    /* Now we can safely move the tail pointer */
    cbuf_pointer_move(&chrdev->tail, count, BUF_LEN);
    dev_info(chrdev->dev, "return %ld bytes\n", count);

unlock:
    /* Release the mutex */
    mutex_unlock(&chrdev->mux);

    return count;
}
```

请注意，由于在进程上下文中只有读取器，它们是唯一移动`tail`指针的进程（或者中断处理程序这样做——请参见下面的代码片段），我们可以确信一切都会正常工作。

1.  最后，中断处理程序（在我们的情况下，它是由内核定时器处理程序模拟的）如下所示：

```
static enum hrtimer_restart chrdev_timer_handler(struct hrtimer *ptr)
{
    struct chrdev_device *chrdev = container_of(ptr,
                    struct chrdev_device, timer);

    spin_lock(&chrdev->lock);    /* grab the lock */ 

    /* Now we should check if we have some space to
     * save incoming data, otherwise they must be dropped...
     */
    if (!cbuf_is_full(chrdev->head, chrdev->tail, BUF_LEN)) {
        chrdev->buf[chrdev->head] = get_new_char();

        cbuf_pointer_move(&chrdev->head, 1, BUF_LEN);
    }
    spin_unlock(&chrdev->lock);  /* release the lock */

    /* Wake up any possible sleeping process */
    wake_up_interruptible(&chrdev->queue);

    /* Now forward the expiration time and ask to be rescheduled */
    hrtimer_forward_now(&chrdev->timer, ns_to_ktime(delay_ns));
    return HRTIMER_RESTART;
}
```

处理程序的主体很简单：它获取锁，然后将单个字符添加到循环缓冲区。

请注意，在这里，由于我们有一个真正的外围设备，我们只是丢弃数据；在实际情况下，驱动程序开发人员可能需要采取任何必要的措施来防止数据丢失，例如停止外围设备，然后以某种方式向用户空间发出此错误条件的信号！

此外，在退出之前，它使用`wake_up_interruptible()`函数唤醒等待队列上可能正在睡眠的进程。

# 工作原理...

这些步骤相当不言自明。但是，在*步骤 4*中，我们执行了两个重要步骤：第一个是如果循环缓冲区为空，则挂起进程，如果不是，则使用中断上下文抓取锁，因为我们将要访问循环缓冲区。

对`O_NONBLOCK`标志的检查只是为了遵守`read()`的行为，即如果使用了`O_NONBLOCK`标志，那么它应该继续进行，然后如果没有数据可用，则返回`EAGAIN`错误。

请注意，在检查缓冲区是否为空之前，可以安全地获取锁，因为如果我们决定缓冲区为空，但同时到达了一些新数据并且`O_NONBLOCK`处于活动状态，我们只需返回`EAGAIN`（向读取进程发出重新执行操作的信号）。如果不是，我们会在等待队列上睡眠，然后会被中断处理程序唤醒（请参阅以下信息）。在这两种情况下，我们的操作都是正确的。

# 还有更多...

如果您希望测试代码，请编译代码并将其插入 ESPRESSObin 中：

```
# insmod chrdev_irq.ko 
chrdev_irq:chrdev_init: got major 239
# insmod chrdev-req.ko 
chrdev cdev-eeprom@2: chrdev cdev-eeprom with id 2 added
chrdev cdev-rom@4: chrdev cdev-rom with id 4 added
```

现在我们的外围设备已启用（内核定时器已在`chrdev_device_register()`函数中的*步骤 2*中启用），并且应该已经有一些数据可供读取；实际上，如果我们通过使用`cat`命令在驱动程序上进行`read()`，我们会得到以下结果：

```
# cat /dev/cdev-eeprom\@2 
ACEGIKMOQSUWYACEGIKMOQSUWYACEGIKMOQSUWYACEGIKMOQSUWYACEGIKMOQSUWYACEGIKMOQSUWYACEGIKMOQSUW
```

在这里，我们应该注意，由于我们在系统中定义了两个设备（请参阅本章开头使用的`chapter_04/chrdev/add_chrdev_devices.dts.patch` DTS 文件），因此`get_new_char()`函数每秒执行两次，这就是为什么我们得到序列`ACE...`而不是`ABC...`。

在这里，一个很好的练习是修改驱动程序，当第一次打开驱动程序时启动内核定时器，然后在最后一次释放时停止它。此外，您可以尝试为每个系统中的设备提供一个每设备的`get_new_char()`函数来生成正确的序列（ABC...）。

相应的内核消息如下所示：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: should read 131072 bytes
chrdev cdev-eeprom@2: return 92 bytes
```

在这里，由于*步骤 3*到*步骤 7*，`read()`系统调用使调用进程进入睡眠状态，然后一旦数据到达就立即返回新数据。

实际上，如果我们等一会儿，我们会看到以下内核消息每秒获得一个新字符：

```
...
[ 227.675229] chrdev cdev-eeprom@2: should read 131072 bytes
[ 228.292171] chrdev cdev-eeprom@2: return 1 bytes
[ 228.294129] chrdev cdev-eeprom@2: should read 131072 bytes
[ 229.292156] chrdev cdev-eeprom@2: return 1 bytes
...
```

我留下了时间，以便了解生成每条消息的时间。

这种行为是由*步骤 8*引起的，内核定时器生成新数据。

# 另请参阅

+   有关自旋锁和锁定的更多信息，请参阅内核文档目录中的`linux/Documentation/locking/spinlocks.txt`。

# 使用 poll()和 select()等待 I/O 操作

在本教程中，我们将了解如何要求内核在我们的驱动程序有新数据可供读取（或愿意接受新数据进行写入）时为我们检查，然后唤醒读取（或写入）进程，而不会在 I/O 操作上被阻塞。

# 做好准备

要测试我们的实现，我们仍然可以像以前一样使用`chrdev_irq.c`驱动程序；这是因为我们可以使用内核定时器模拟的*新数据*事件。

# 如何做...

让我们看看如何通过以下步骤来做到这一点：

1.  首先，我们必须在驱动程序的`struct file_operations`中添加我们的新`chrdev_poll()`方法：

```
static const struct file_operations chrdev_fops = {
    .owner   = THIS_MODULE,
    .poll    = chrdev_poll,
    .llseek  = no_llseek,
    .read    = chrdev_read,
    .open    = chrdev_open,
    .release = chrdev_release
};
```

1.  然后，实现如下。我们首先通过将当前设备`chrdev->queue`的等待队列传递给`poll_wait()`函数：

```
static __poll_t chrdev_poll(struct file *filp, poll_table *wait)
{
    struct chrdev_device *chrdev = filp->private_data;
    __poll_t mask = 0;

    poll_wait(filp, &chrdev->queue, wait);
```

1.  最后，在检查循环缓冲区不为空并且我们可以继续从中读取数据之前，我们抓住互斥锁：

```
    /* Grab the mutex */
    mutex_lock(&chrdev->mux);

    if (!cbuf_is_empty(chrdev->head, chrdev->tail, BUF_LEN))
        mask |= EPOLLIN | EPOLLRDNORM;

    /* Release the mutex */
    mutex_unlock(&chrdev->mux);

    return mask;
}
```

请注意，抓取自旋锁也是不必要的。这是因为如果缓冲区为空，当新数据通过中断（在我们的模拟中是内核定时器）处理程序到达时，我们将得到通知。这将反过来调用`wake_up_interruptible(&chrdev->queue)`，它作用于我们之前提供给`poll_wait()`函数的等待队列。另一方面，如果缓冲区不为空，它不可能在中断上下文中变为空，因此我们根本不可能有任何竞争条件。

# 还有更多...

与以前一样，如果我们希望测试代码，我们需要实现一个适当的工具来执行我们的新`poll()`方法。当我们将其添加到驱动程序中时，我们将获得`poll()`和`select()`系统调用支持；`select()`的使用示例在`chrdev_select.c`文件中报告，在下面，有一个片段中使用了`select()`调用：

```
    while (1) {
        /* Set up reading file descriptors */
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(fd, &read_fds);

        /* Wait for any data from our device or stdin */
        ret = select(FD_SETSIZE, &read_fds, NULL, NULL, NULL);
        if (ret < 0) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            ret = read(STDIN_FILENO, &c, 1);
            if (ret < 0) { 
                perror("read(STDIN, ...)");
                exit(EXIT_FAILURE);
            }
            printf("got '%c' from stdin!\n", c);
        }
 ...

    }
```

正如我们所看到的，这个程序将使用`select()`系统调用来监视我们进程的标准输入通道（名为`stdin`）和字符设备，`select()`系统调用又调用我们在*步骤 2*和*步骤 3*中实现的新`poll()`方法。

现在，让我们在我们的主机 PC 上使用下一个命令行编译`chrdev_select.c`程序：

```
$ make CFLAGS="-Wall -O2 -Ichrdev/" \
 CC=aarch64-linux-gnu-gcc \
 chrdev_select aarch64-linux-gnu-gcc -Wall -O2 chrdev_ioctl.c -o chrdev_select
```

请注意，这个命令可以通过简单地删除`CC=aarch64-linux-gnu-gcc`设置在 ESPRESSObin 上执行。

现在，如果我们尝试在 chrdev 设备上执行该命令，我们应该会得到这个输出：

```
# ./chrdev_select /dev/cdev-eeprom\@2
file /dev/cdev-eeprom@2 opened
got 'K' from device!
got 'M' from device!
got 'O' from device!
got 'Q' from device!
...
```

当然，我们已经加载了包含`poll()`方法的`chrdev_irq`驱动程序。

如果我们尝试从标准输入插入一些字符，如下所示，我们可以看到当设备有新数据时，进程可以安全地对其进行读取而不会阻塞，而当标准输入有新数据时，进程也可以做同样的事情，同样也不会阻塞：

```
...
got 'Y' from device!
got 'A' from device!
TEST
got 'T' from stdin!
got 'E' from stdin!
got 'S' from stdin!
got 'T' from stdin!
got '
' from stdin!
got 'C' from device!
got 'E' from device!
...
```

# 另请参阅

+   有关`poll()`或`select()`的更多信息，一个很好的起点是它们的 man 页面（`man 2 poll`和`man 2 select`）。

# 使用`fasync()`管理异步通知

在这个示例中，我们将看到如何在我们的驱动程序有新数据要读取时（或者愿意接受来自用户空间的新数据）生成异步的`SIGIO`信号。

# 准备工作

与以前一样，我们仍然可以使用`chrdev_irq.c`驱动程序来展示我们的实现。

# 如何做...

让我们看看如何通过以下步骤来做到：

1.  首先，我们必须在驱动程序的`struct file_operations`中添加我们的新`chrdev_fasync()`方法：

```
static const struct file_operations chrdev_fops = {
    .owner   = THIS_MODULE,
    .fasync  = chrdev_fasync,
    .poll    = chrdev_poll,
    .llseek  = no_llseek,
    .read    = chrdev_read,
    .open    = chrdev_open,
    .release = chrdev_release
};
```

1.  实现如下：

```
static int chrdev_fasync(int fd, struct file *filp, int on)
{
    struct chrdev_device *chrdev = filp->private_data;

    return fasync_helper(fd, filp, on, &chrdev->fasync_queue);
}
```

1.  最后，我们必须在我们的（模拟的）中断处理程序中添加`kill_fasync()`调用，以表示由于有新数据准备好被读取，可以发送`SIGIO`信号：

```
static enum hrtimer_restart chrdev_timer_handler(struct hrtimer *ptr)
{
    struct chrdev_device *chrdev = container_of(ptr,
                                    struct chrdev_device, timer);

...
    /* Wake up any possible sleeping process */
    wake_up_interruptible(&chrdev->queue);
    kill_fasync(&chrdev->fasync_queue, SIGIO, POLL_IN);

    /* Now forward the expiration time and ask to be rescheduled */
    hrtimer_forward_now(&chrdev->timer, ns_to_ktime(delay_ns));
    return HRTIMER_RESTART;
}
```

# 还有更多...

如果您希望测试代码，您需要实现一个适当的工具来执行所有步骤，以要求内核接收`SIGIO`信号。下面报告了`chrdev_fasync.c`程序的片段，其中执行了所需的操作：

```
    /* Try to install the signal handler and the fasync stuff */
    sigh = signal(SIGIO, sigio_handler);
    if (sigh == SIG_ERR) {
            perror("signal");
            exit(EXIT_FAILURE);
    }
    ret = fcntl(fd, F_SETOWN, getpid());
    if (ret < 0) {
            perror("fcntl(..., F_SETOWN, ...)");
            exit(EXIT_FAILURE);
    }
    flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
            perror("fcntl(..., F_GETFL)");
            exit(EXIT_FAILURE);
    }
    ret = fcntl(fd, F_SETFL, flags | FASYNC);
    if (flags < 0) {
            perror("fcntl(..., F_SETFL, ...)");
            exit(EXIT_FAILURE);
    }
```

这段代码是要求内核调用我们在*步骤 2*中实现的`fasync()`方法。然后，每当有新数据到达时，由于*步骤 3*，`SIGIO`信号将发送到我们的进程，并且信号处理程序`sigio_handler()`将被执行，即使进程被挂起，例如，在读取另一个文件描述符时。

```
void sigio_handler(int unused) {
    char c;
    int ret;

    ret = read(fd, &c, 1);
    if (ret < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    ret = write(STDOUT_FILENO, &c, 1);
    if (ret < 0) {
        perror("write");
        exit(EXIT_FAILURE);
    }
}
```

现在，让我们在我们的主机 PC 上使用下一个命令行编译`chrdev_fasync.c`程序：

```
$ make CFLAGS="-Wall -O2 -Ichrdev/" \
 CC=aarch64-linux-gnu-gcc \
 chrdev_fasync aarch64-linux-gnu-gcc -Wall -O2 chrdev_ioctl.c -o chrdev_fasync
```

请注意，这个命令可以通过简单地删除`CC=aarch64-linux-gnu-gcc`设置在 ESPRESSObin 上执行。

现在，如果我们尝试在 chrdev 设备上执行该命令，我们应该会得到以下输出：

```
# ./chrdev_fasync /dev/cdev-eeprom\@2 
file /dev/cdev-eeprom@2 opened
QSUWYACEGI
```

当然，我们已经加载了包含`fasync()`方法的`chrdev_irq`驱动程序。

在这里，进程在标准输入上的`read()`上被挂起，每当信号到达时，信号处理程序被执行并且新数据被读取。然而，当我们尝试向标准输入发送一些字符时，进程会如预期地读取它们：

```
# ./chrdev_fasync /dev/cdev-eeprom\@2 
file /dev/cdev-eeprom@2 opened
QSUWYACEGIKMOQS....
got '.' from stdin!
got '.' from stdin!
got '.' from stdin!
got '.' from stdin!
got '
' from stdin!
UWYACE
```

# 另请参阅

+   有关`fasync()`方法或`fcntl()`系统调用的更多信息，一个很好的起点是`man 2 fcntl`手册页。


# 第八章：附加信息：使用字符驱动程序

# 与字符驱动程序交换数据

与外围设备交换数据意味着向其发送或接收数据，为此，我们已经看到我们必须使用在内核中定义的`write()`和`read()`系统调用的原型。

```
ssize_t write(struct file *filp,
              const char __user *buf, size_t count,
              loff_t *ppos);
ssize_t read(struct file *filp,
              char __user *buf, size_t count,
              loff_t *ppos);
```

另一方面，它们在用户空间中的对应形式如下：

```
ssize_t write(int fd, const void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count);
```

前面的原型（无论是在内核空间还是用户空间）看起来很相似，但是它们的含义当然是不同的，作为驱动程序开发人员，我们必须完全了解这些含义，以便准确地完成我们的工作。

让我们从`write()`开始；当我们从用户空间程序调用`write()`系统调用时，我们必须提供一个文件描述符`fd`；一个填充有要写入的数据的缓冲区`buf`；以及缓冲区大小`count`。然后，系统调用返回一个值，可以是负值（如果有错误），正值（表示实际写入的字节数），或零（表示没有写入任何内容）。

请注意，`count`并不代表我们希望写入多少字节，而只是缓冲区的大小！实际上，`write()`可以返回一个小于`count`的正值。这就是为什么我在`chrdev_test.c`程序的`write()`系统调用中使用了`for()`循环！实际上，如果我必须写入一个长度为 10 字节的缓冲区，而`write()`返回了 4 字节，我必须重复调用它，直到剩下的 6 字节都被写入。

从内核空间的角度来看，我们将文件描述符`fd`视为`struct file *filp`（存储有关文件描述符的内核信息），而数据缓冲区由`buf`指针和`count`变量指定（暂时不考虑`ppos`指针；稍后将对其进行解释）。

从`write()`内核原型中可以看出，`buf`参数带有`__user`属性，这表明这个缓冲区来自用户空间，因此我们不能直接从中读取。实际上，这个内存区域是虚拟的，因此在执行我们的驱动程序的`write()`方法时，它实际上不能映射到真正的物理内存中！为了解决这种情况，内核提供了`copy_from_user()`函数，如下所示：

```
unsigned long copy_from_user(void *to,
                   const void __user *from, unsigned long n);
```

正如我们所看到的，这个函数从用户空间缓冲区`from`中获取数据，然后在验证指向`from`的内存区域可以进行读取后，将它们复制到指向`to`的缓冲区中。一旦数据被传输到内核空间（在`to`指向的缓冲区内），我们的驱动程序就可以自由访问它。

对于`read()`系统调用，执行相同的步骤（即使是相反的方向）。我们仍然有一个文件描述符`fd`；一个缓冲区`buf`，用于存放读取的数据，以及它的`count`大小。然后，系统调用返回一个值，可以是负值（如果有错误），正值（表示实际读取的字节数），或零（表示我们已经到达文件末尾）。

再次，我们应该注意`count`不是我们希望读取的字节数，而只是缓冲区的大小。实际上，`read()`可以返回小于`count`的正值，这就是为什么我在`chrdev_test.c`程序中将其放在`for()`循环中的原因。

与前面的`write()`情况相比，`read()`系统调用还可以返回`0`，表示**文件末尾**；也就是说，从这个文件描述符中没有更多的数据可用，我们应该停止读取。

与前面的`write()`情况一样，`buf`指向的缓冲区仍然带有`__user`属性，这意味着要从中读取数据，我们必须使用`copy_to_user()`函数，其定义如下：

```
unsigned long copy_to_user(void __user *to,
                   const void *from, unsigned long n);
```

`copy_from_user()`和`copy_to_user()`都在`linux/include/linux/uaccess.h`文件中定义。

现在，在本节结束之前，我们必须花一些时间来讨论内核原型中存在的`ppos`指针。

当我们希望读取文件中存储的一些数据时，我们必须多次使用 `read()` 系统调用（特别是如果文件很大而我们的内存缓冲区很小）。为了做到这一点，我们希望简单地多次调用 `read()` 而不必担心在每个前一次迭代中到达的位置；例如，如果我们有一个大小为 16 KB 的文件，并且希望使用 4 KB 内存缓冲区来读取它，我们只需调用 `read()` 系统调用四次，但是每次调用应该如何知道前一个调用完成了它的工作？嗯，这个任务被分配给了 `ppos` 指针：当文件被打开时，它开始指向文件的第一个字节（索引为 0），然后每次调用 `read()` 时，系统调用本身将它移动到下一个位置，以便接下来的 `read()` 调用知道它应该从哪里开始读取下一块数据。

请注意，`ppos` 对于读操作和写操作都是唯一的，因此如果我们先执行 `read()`，然后再执行 `write()`，数据将被写入的位置不是文件的开头，而是在前一个 `read()` 调用完成其操作的地方！


# 第九章：附加信息：使用设备树

# 设备树内部

设备树是一种树形数据结构，其中的节点告诉您系统中当前存在哪些设备以及它们的配置设置。每个节点都有描述所代表设备属性/值对。每个节点只有一个父节点，但根节点没有父节点。

下面的代码显示了一个简单设备树的示例表示，该示例几乎足够完整以引导一个简单的操作系统，其中包括平台类型、CPU、内存和一个**通用同步和异步收发器**（UART），并描述了其时钟和中断线。设备节点显示为每个节点内的属性和值。

设备树语法几乎是自解释的；但是，我们将通过查看与第四章相关的 GitHub 存储库中的`simple_platform.dts`文件来详细解释它。因此，让我们从文件末尾开始查看：

```
        serial0: serial@11100 {
            compatible = "fsl,mpc5125-psc-uart", "fsl,mpc5125-psc";
            reg = <0x11100 0x100>;
            interrupt-parent = <&ipic>;
            interrupts = <40 0x8>; 
            fsl,rx-fifo-size = <16>;
            fsl,tx-fifo-size = <16>;
            clocks = <&clks 47>, <&clks 34>; 
            clock-names = "ipg", "mclk";
        };
    };
};
```

首先，我们应该注意，属性定义是以下形式的名称/值对：

```
[label:] property-name = value;
```

这是真实的，除了具有空（零长度）值的属性，其形式如下：

`[label:] property-name;`

例如，在前面的例子中，我们有`serial@11100`节点（标记为`serial0`）的`compatible`属性设置为由两个字符串`"fsl,mpc5125-psc-uart"`和`"fsl,mpc5125-psc"`组成的列表，而`fsl,rx-fifo-size`属性设置为数字`16`。

属性值可以定义为 8、16、32 或 64 位整数元素的数组，作为以 NULL 结尾的字符串，作为字节字符串，或者这些的组合。元素的存储大小可以使用`/bits/`前缀进行更改，如下所示，它将属性`interrupts`定义为字节数组，`clock-frequency`定义为 64 位数字：

```
interrupts = /bits/ 8 <17 0xc>;
clock-frequency = /bits/ 64 <0x0000000100000000>;
```

`/bits/`前缀允许创建 8、16、32 和 64 位元素。

设备树中的每个节点都根据以下`node-name@unit-address`约定命名，其中`node-name`组件指定节点的名称（通常描述设备的一般类别），而名称的`unit-address`组件是特定于节点所在总线类型的。例如，在前面的例子中，我们有`serial@11100`，这意味着我们在地址`0x11100`处有一个串行端口，偏移量为`soc`节点的基地址`0x80000000`。

看前面的例子，很明显每个节点都是由节点名称和单元地址定义的，用大括号标记节点定义的开始和结束（它们可能由标签前导），如下所示：

```
[label:] node-name[@unit-address] {
    [properties definitions]
    [child nodes]
};
```

设备树中的每个节点都有描述节点特征的属性；存在具有明确定义和标准化功能的标准属性，但我们也可以使用自己的属性来指定自定义值。属性由名称和值组成，对于我们串行端口的示例，我们将`interrupts`属性设置为`<40 0x8>`数组，而`compatible`属性设置为字符串列表，`fsl,rx-fifo-size`设置为数字。

设备树中的节点可以通过清楚地说明从根节点到所需节点的所有后代节点的完整路径来唯一标识。指定设备路径的约定类似于我们通常用于文件系统中的文件的路径名称；例如，在前面的定义中，我们串行端口的设备路径是`/soc@80000000/serial@11100`，而根节点的路径显然是`/`。这种情况是标签发挥作用的地方；实际上，它们可以用来代替节点的完整路径，即串行端口使用`clks`标签可以轻松寻址，如下所示：

```
    clks: clock@f00 {
        ...
    };

    serial0: serial@11100 {
        compatible = "fsl,mpc5125-psc-uart", "fsl,mpc5125-psc";
        ....     
        clocks = <&clks 47>, <&clks 34>;
        clock-names = "ipg", "mclk";
    };

```

我们还可以注意到`serial0`被定义为`tty0`的别名。这种语法为开发人员提供了另一种使用标签而不是使用完整路径名引用节点的方式：

```
    aliases {
        tty0 = &serial0;
    };
```

前面的定义等同于以下内容：

```
    aliases {
        tty0 = "/soc@80000000/serial@11100";
    }
```

现在很明显，标签可以在设备树源文件中作为属性句柄（标签通常被命名为 phandle）值或路径使用，具体取决于上下文。实际上，如果`&`字符在数组内部，则它只引用 phandle；否则（如果在数组外部），它引用路径！

别名不直接在设备树源中使用，而是由 Linux 内核进行解引用。实际上，当我们要求内核通过路径找到一个节点时（我们将很快在本章中看到这样的函数的用法，比如`of_find_node_by_path()`），如果路径不以`/`字符开头，那么路径的第一个元素必须是`/aliases`节点中的属性名称。该元素将被别名的完整路径替换。

在节点、标签和别名中，另一个设备树的重要实体是 phandles。官方定义告诉我们，phandle 属性指定了设备树中唯一的节点的数值标识符。实际上，其他需要引用与该属性关联的节点的节点使用了该属性值，因此这实际上只是一个绕过设备树没有指针数据类型的方法。

在上面的例子中，`serial@11100`节点是指定哪个节点是中断控制器，哪个节点是 phandles 使用的时钟定义的一种方式。然而，在该示例中，它们没有被显式定义，因为`dtc`编译器会从标签中创建 phandles。因此，在上面的例子中，我们有以下语法（已删除不需要的信息以便更好地阅读）：

```
        ipic: interrupt-controller@c00 {
            compatible = "fsl,mpc5121-ipic", "fsl,ipic";
            ...
        };

        clks: clock@f00 {
            compatible = "fsl,mpc5121-clock";
            ...
        };

        serial0: serial@11100 {
            compatible = "fsl,mpc5125-psc-uart", "fsl,mpc5125-psc";
            ...
            interrupt-parent = <&ipic>;
            ...
            clocks = <&clks 47>, <&clks 34>; 
            ...
        };
```

`dtc`编译器是设备树编译器，在第四章中将介绍*使用设备树*，使用设备树编译器和实用程序。

这相当于下一个语法，其中 phandles 被显式地制作出来：

```
        interrupt-controller@c00 {
            compatible = "fsl,mpc5121-ipic", "fsl,ipic";
            ...
            phandle = <0x2>;
        };

        clock@f00 {
            compatible = "fsl,mpc5121-clock";
            ...
            phandle = <0x3>;
        };

        serial@11100 {
            compatible = "fsl,mpc5125-psc-uart", "fsl,mpc5125-psc";
            ...
            interrupt-parent = <0x2>;
            ...
            clocks = <0x3 0x2f 0x3 0x22>;
            ...
        };
```

简而言之，`&`字符告诉`dtc`后面的字符串是引用与该字符串匹配的标签的 phandle；然后它将为每个用于 phandle 引用的标签创建一个唯一的`u32`值。

当然，您可以在一个节点中定义自己的 phandle 属性，并在不同节点的名称上指定一个标签。然后，`dtc`将意识到任何明确声明的 phandle 值，并在为带标签的节点创建 phandle 值时不使用这些值。

关于设备树语法有很多要说的。然而，我们已经涵盖了足够理解如何在设备驱动程序开发过程中使用设备树的内容。

有关此主题的完整文档，请阅读[`www.devicetree.org/specifications/`](https://www.devicetree.org/specifications/)上的设备树规范。

# 使用设备树编译器和实用程序

以下是关于`dtc`及其实用程序的一些有趣用法的注释，这些用法在设备驱动程序开发和内核配置过程中可能非常有用。

# 获取运行设备树的源代码形式

`dtc`也可以用来将运行中的设备树转换为人类可读的形式！假设我们想知道我们的 ESPRESSObin 是如何配置的；首先要做的事情是查看内核源代码中 ESPRESSObin 的 DTS 文件。但是，假设我们没有它。在这种情况下，我们可以要求`dtc`回退到相应的 DTB 文件，就像前面的部分所示，但是假设我们仍然没有它。我们能做什么？嗯，`dtc`可以通过回退存储在`/proc/device-tree`目录中的数据再次帮助我们，该目录保存了运行设备树的文件系统表示。

实际上，我们可以使用`tree`命令检查`/proc/device-tree`目录，就像下面所示的那样（这个输出只是整个目录内容的一部分）：

```
# tree /proc/device-tree/proc/device-tree/
|-- #address-cells
|-- #size-cells
|-- aliases
|   |-- name
|   |-- serial0
|   `-- serial1
|-- chosen
|   |-- bootargs
|   |-- name
|   `-- stdout-path
|-- compatible
|-- cpus
|   |-- #address-cells
|   |-- #size-cells
|   |-- cpu@0
|   |   |-- clocks
|   |   |-- compatible
|   |   |-- device_type
|   |   |-- enable-method
|   |   |-- name
|   |   `-- reg
...
```

如果不存在，可以像通常一样使用`apt install tree`命令安装`tree`命令。

然后我们可以按以下方式读取每个文件中的字符串数据：

```
# cat /proc/device-tree/compatible ; echo
globalscale,espressobinmarvell,armada3720marvell,armada3710
# cat /proc/device-tree/cpus/cpu\@0/compatible ; echo 
arm,cortex-a53arm,armv8
```

最后的`echo`命令只是用于在`cat`输出后添加一个新行字符，以获得更可读的输出。

数字必须按以下方式读取：

```
# cat /proc/device-tree/#size-cells | od -tx4
0000000 02000000
0000004
# cat /proc/device-tree/cpus/cpu\@1/reg | od -tx4
0000000 01000000
0000004
```

但是，通过使用`dtc`，我们可以获得更好的结果。实际上，如果我们使用下一个命令行，我们要求`dtc`将所有 DTB 数据转换为人类可读的形式：

```
# dtc -I fs -o espressobin-reverted.dts /proc/device-tree/
```

当然，我们还必须使用`apt install device-tree-compiler`命令将`dtc`程序安装到我们的 ESPRESSObin 中。

现在，从`espressobin-reverted.dts`文件中，我们可以轻松读取设备树数据：

```
# head -20 espressobin-reverted.dts
/dts-v1/;

/ {
    #address-cells = <0x2>;
    model = "Globalscale Marvell ESPRESSOBin Board";
    #size-cells = <0x2>;
    interrupt-parent = <0x1>;
    compatible = "globalscale,espressobin", "marvell,armada3720", "marvell,armada3710";

    memory@0 {
        device_type = "memory";
        reg = <0x0 0x0 0x0 0x80000000 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0>;
    };

    regulator {
        regulator-max-microvolt = <0x325aa0>;
        gpios-states = <0x0>;
        regulator-boot-on;
        enable-active-high;
        regulator-min-microvolt = <0x1b7740>;
..
```

# 设备树实用程序的注意事项

如果我们查看之前安装的`device-tree-compiler`软件包中的程序，我们会发现除了`dtc`之外还有更多的程序：

```
$ dpkg -L device-tree-compiler | grep '/usr/bin'
/usr/bin
/usr/bin/convert-dtsv0
/usr/bin/dtc
/usr/bin/dtdiff
/usr/bin/fdtdump
/usr/bin/fdtget
/usr/bin/fdtoverlay
/usr/bin/fdtput
```

这些其他程序通常称为**设备树实用程序**，可用于检查或操作设备树的二进制形式（DTB）。

例如，我们可以使用`fdtdump`实用程序轻松转储 DTB 文件：

```
$ fdtdump simple_platform.dtb | head -23

**** fdtdump is a low-level debugging tool, not meant for general use.
**** If you want to decompile a dtb, you probably want
**** dtc -I dtb -O dts <filename>

/dts-v1/;
// magic: 0xd00dfeed
// totalsize: 0x642 (1602)
...

/ {
    model = "fsl,mpc8572ds";
    compatible = "fsl,mpc8572ds";
    #address-cells = <0x00000001>;
    #size-cells = <0x00000001>;
    interrupt-parent = <0x00000001>;
    chosen {
        bootargs = "root=/dev/sda2";
    };
    aliases {
        tty0 = "/soc@80000000/serial@11100";
    };
```

细心的读者会注意到`fdtdump`实用程序本身告诉我们它只是一个低级调试工具，然后使用`dtc`而不是反编译（或恢复为 DTS）DTB 文件！

另外两个有用的命令是`fdtget`和`fdtput`，可以用来读取和写入数据到我们的 DTB 文件中。以下是我们可以用来读取前述 DTB 文件的`bootargs`条目的命令：

```
$ fdtget simple_platform.dtb /chosen bootargs
root=/dev/sda2
```

然后，我们可以使用下一个命令进行更改：

```
$ fdtput -ts simple_platform.dtb /chosen bootargs 'root=/dev/sda1 rw'
$ fdtget simple_platform.dtb /chosen bootargs
root=/dev/sda1 rw
```

请注意，我们必须使用`-ts`选项参数告诉`fdtput`我们的数据类型，否则可能会写入错误的值！

不仅如此，我们还可以要求`fdtget`列出每个提供节点的所有子节点：

```
$ fdtget -l simple_platform.dtb /cpus /soc@80000000
cpu@0
cpu@1
interrupt-controller@c00
clock@f00
serial@11100
```

此外，我们还可以要求它列出每个节点的所有属性：

```
$ fdtget -p simple_platform.dtb /cpus /soc@80000000
#address-cells
#size-cells
compatible
#address-cells
#size-cells
device_type
ranges
reg
bus-frequency
```

# 从设备树获取特定应用程序数据

通过使用`linux/drivers/of`目录中的函数，我们将能够从设备树中提取我们的驱动程序所需的所有信息。例如，通过使用`of_find_node_by_path()`函数，我们可以通过其路径名获取节点指针：

```
struct device_node *of_find_node_by_path(const char *path);
```

然后，一旦我们有了指向设备树节点的指针，我们可以使用它来通过使用`of_property_read_*()`函数提取所需的信息，如下所示：

```
int of_property_read_u8(const struct device_node *np,
                        const char *propname,
                        u8 *out_value);
int of_property_read_u16(const struct device_node *np,
                         const char *propname,
                         u16 *out_value);
int of_property_read_u32(const struct device_node *np,
                         const char *propname,
                         u32 *out_value);
...
```

请注意，我们可以使用许多其他函数从设备树中提取信息，因此您可以查看`linux/include/linux/of.h`文件以获取完整列表。

如果我们希望解析节点的每个属性，我们可以使用`for_each_property_of_node()`宏来迭代它们，其定义如下：

```
#define for_each_property_of_node(dn, pp) \
        for (pp = dn->properties; pp != NULL; pp = pp->next)
```

然后，如果我们的节点有多个子节点，我们可以使用`for_each_child_of_node()`宏来迭代它们，其定义如下：

```
#define for_each_child_of_node(parent, child) \
        for (child = of_get_next_child(parent, NULL); child != NULL; \
             child = of_get_next_child(parent, child))
```

# 使用设备树描述字符驱动程序

我们已经看到，通过使用设备树，我们可以指定不同的驱动程序设置，然后修改驱动程序的功能。但是，我们的可能性并不止于此！实际上，我们可以将相同的代码用于不同的驱动程序发布版本或相同设备的不同类型。

# 如何管理不同的设备类型

假设我们的`chrdev`有另外两个实现（加上当前的实现），在这两个实现中，硬件的大部分参数都是固定的（并且是众所周知的），开发人员无法选择；在这种情况下，我们仍然可以使用节点属性来指定它们，但这样做容易出错，并且迫使用户了解这些约束。例如，如果在这两个实现中，硬件只能以只读或读/写模式工作（即用户无法自由指定`read-only`属性），我们可以将这些特殊情况称为`"chrdev-fixed"`用于读/写版本，`"chrdev-fixed_read-only"`用于只读版本。

此时，我们可以指定驱动程序现在与其他两个设备兼容，方法是修改`of_chrdev_req_match`数组，如下所示：

```
static const struct of_device_id of_chrdev_req_match[] = {
    {
        .compatible = "ldddc,chrdev",
    },
    {
        .compatible = "ldddc,chrdev-fixed",
        .data = &chrdev_fd,
    },
    {
        .compatible = "ldddc,chrdev-fixed_read-only",
        .data = &chrdev_fd_ro,
    },
    { /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_chrdev_req_match);
```

我们只需添加两个具有适当`compatible`字符串和两个特殊数据条目，如下所定义：

```
static const struct chrdev_fixed_data chrdev_fd = {
    .label = "cdev-fixed",
};

static const struct chrdev_fixed_data chrdev_fd_ro = {
    .label = "cdev-fixedro",
    .read_only = 1, 
};
```

通过这种方式，我们告诉驱动程序这些设备只能有一个实例，并且它们可以以读/写或只读模式工作。通过这样做，用户可以通过简单地指定设备树来使用我们的设备，如下所示：

```
--- a/arch/arm64/boot/dts/marvell/armada-3720-espressobin.dts
+++ b/arch/arm64/boot/dts/marvell/armada-3720-espressobin.dts
@@ -41,6 +41,10 @@
             3300000 0x0>;
         enable-active-high;
     };
+
+    chrdev {
+        compatible = "ldddc,chrdev-fixed_read-only";
+    };
 };

 /* J9 */
```

同样，您必须修改 ESPRESSObin 的 DTS 文件，然后重新编译和重新安装内核。

通过使用这种解决方案，用户不需要了解硬件内部情况，因为驱动程序开发人员（在这种情况下是我们）已将其封装到驱动程序中。

可以使用`of_device_is_compatible()`函数为驱动程序评估此兼容属性，如下例所示，我们已修改`chrdev_req_probe()`函数以支持我们的`chrdev`特殊版本：

```
static int chrdev_req_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct device_node *np = dev->of_node;
    const struct chrdev_fixed_data *data = of_device_get_match_data(dev);
    struct fwnode_handle *child;
    struct module *owner = THIS_MODULE;
    int count, ret;

    /* Check the chrdev device type */
    if (of_device_is_compatible(np, "ldddc,chrdev-fixed") ||
        of_device_is_compatible(np, "ldddc,chrdev-fixed_read-only")) {
        ret = chrdev_device_register(data->label, 0,
                         data->read_only, owner, dev);
        if (ret)
            dev_err(dev, "unable to register fixed");

        return ret;
    }

    /* If we are not registering a fixed chrdev device then get
     * the number of chrdev devices from DTS
     */
    count = device_get_child_node_count(dev);
    if (count == 0)
        return -ENODEV;
    if (count > MAX_DEVICES)
        return -ENOMEM;

    device_for_each_child_node(dev, child) {
        const char *label; 
        unsigned int id, ro; 
...
```

正如我们所看到的，在扫描节点的子项之前，我们只需验证当前已安装的系统的`chrdev`设备版本；在这种情况下，我们有两个新设备中的一个，因此我们相应地注册一个新的`chrdev`设备。

所有这些修改都可以使用`add_fixed_chrdev_devices.patch`文件和以下命令行进行：

**`$ patch -p3 < add_fixed_chrdev_devices.patch`**

现在我们可以通过重新编译我们的`chrdev`驱动程序并将其重新插入（实际上是两个模块）到 ESPRESSObin 中来尝试代码，如下所示：

```
# insmod chrdev.ko 
chrdev:chrdev_init: got major 239
# insmod chrdev-req.ko 
chrdev cdev-fixedro@0: chrdev cdev-fixedro with id 0 added
# ls -l /dev/cdev-fixedro\@0 
crw------- 1 root root 239, 0 Feb 28 15:23 /dev/cdev-fixedro@0
```

正如我们所看到的，驱动程序正确地识别出设备树中已定义了`chrdev`设备的特殊版本（只读版本）。

# 如何向设备添加 sysfs 属性

在前面的部分中，我们简要讨论了`/sys/class/chrdev`目录。我们说它与设备类（可以在系统中定义）和内核设备有关。实际上，当我们调用`device_create()`函数时，我们必须指定第一个参数，即为`chrdev_init()`函数分配的设备类指针，此操作将为每个`chrdev`设备创建`/sys/class/chrdev`目录，如下所示：

```
# ls /sys/class/chrdev/
cdev-eeprom@2 cdev-rom@4
```

因此，设备类将所有具有共同特征的设备分组在一起，但我们在谈论哪些特征？简单地说，这些特征或属性（我们将很快看到它们确切的名称）是关于我们设备的一组共同信息。

每次向系统添加新设备时，内核都会创建默认属性，可以在用户空间中看到这些属性，如下所示：

```
# ls -l /sys/class/chrdev/cdev-eeprom\@2/
total 0
-r--r--r-- 1 root root 4096 Feb 28 10:51 dev
lrwxrwxrwx 1 root root 0 Feb 28 10:51 device -> ../../../chrdev
drwxr-xr-x 2 root root 0 Feb 28 10:51 power
lrwxrwxrwx 1 root root 0 Feb 27 19:53 subsystem -> ../../../../../class/chrdev
-rw-r--r-- 1 root root 4096 Feb 27 19:53 uevent
```

在前面的列表中，有些是文件，有些是目录或符号链接；然而，在这里，重要的是，对于每个设备，我们都有一些描述它的属性。例如，如果我们查看`dev`属性，我们会得到以下内容：

```
# cat /sys/class/chrdev/cdev-eeprom\@2/dev
239:2
```

我们设备的主次编号是多少？现在的问题是，我们可以有更多（和自定义）属性吗？当然，答案是肯定的，所以让我们看看如何做到这一点。

首先，我们必须修改`chrdev.c`文件，向`chrdev_init()`添加一行，如下所示：

```
--- a/chapter_4/chrdev/chrdev.c
+++ b/chapter_4/chrdev/chrdev.c
@@ -216,6 +288,7 @@ static int __init chrdev_init(void)
        pr_err("chrdev: failed to allocate class\n");
        return -ENOMEM;
    }
+   chrdev_class->dev_groups = chrdev_groups;

    /* Allocate a region for character devices */
    ret = alloc_chrdev_region(&chrdev_devt, 0, MAX_DEVICES, "chrdev");
```

此修改只是将指向`chrdev_class`的结构的`dev_groups`字段设置为`chrdev_groups`结构，如下所示：

```
static struct attribute *chrdev_attrs[] = {
    &dev_attr_id.attr,
    &dev_attr_reset_to.attr,
    &dev_attr_read_only.attr,
    NULL,
};

static const struct attribute_group chrdev_group = {
    .attrs = chrdev_attrs,
};

static const struct attribute_group *chrdev_groups[] = {
    &chrdev_group,
    NULL,
};
```

本段中的所有修改都可以使用`add_sysfs_attrs_chrdev.patch`文件和以下命令行进行：

**`$ patch -p3 < add_sysfs_attrs_chrdev.patch`**

前面的代码是向我们的 chrdev 设备添加一组属性的复杂方式。更具体地说，该代码只是向名为`id`、`reset_to`和`read_only`的一组属性添加了单个组。所有这些属性名称仍然在修改后的`chrdev.c`文件中定义，如下摘录所示。这是只读属性：

```
static ssize_t id_show(struct device *dev,
                struct device_attribute *attr, char *buf)
{
    struct chrdev_device *chrdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", chrdev->id);
}
static DEVICE_ATTR_RO(id);
```

然后，只写属性如下：

```
static ssize_t reset_to_store(struct device *dev,
                struct device_attribute *attr,
                const char *buf, size_t count)
{
    struct chrdev_device *chrdev = dev_get_drvdata(dev);

    if (count > BUF_LEN)
        count = BUF_LEN;
    memcpy(chrdev->buf, buf, count);

    return count;
}
static DEVICE_ATTR_WO(reset_to);
```

最后，读/写属性如下：

```
static ssize_t read_only_show(struct device *dev,
                struct device_attribute *attr, char *buf)
{
    struct chrdev_device *chrdev = dev_get_drvdata(dev);

    return sprintf(buf, "%d\n", chrdev->read_only);
}

static ssize_t read_only_store(struct device *dev,
                struct device_attribute *attr,
                const char *buf, size_t count)
{
    struct chrdev_device *chrdev = dev_get_drvdata(dev);
    int data, ret;

    ret = sscanf(buf, "%d", &data);
    if (ret != 1)
        return -EINVAL;

    chrdev->read_only = !!data;

    return count;
}
static DEVICE_ATTR_RW(read_only);
```

通过使用`DEVICE_ATTR_RW()`，`DEVICE_ATTR_WO()`和`DEVICE_ATTR_RO()`，我们声明读/写、只写和只读属性，这些属性与名为`chrdev_attrs`的数组中的条目相关联，该数组被定义为`struct attribute`类型。

当我们使用 DEVICE_ATTR_RW(read_only)时，我们必须定义两个名为 read_only_show()和 read_only_store()的函数（变量名为 read_only，带有后缀 _show 和 _store），这样内核在用户空间进程在属性文件上执行 read()或 write()系统调用时会调用每个函数。当然，DEVICE_ATTR_RO()和 DEVICE_ATTR_WO()变体只需要 _show 和 _store 函数，分别。

为了更好地理解数据是如何交换的，让我们更仔细地看看这些函数。通过查看 read_only_show()函数，我们可以看到要写入的数据由 buf 指向，而通过使用 dev_get_drvdata()，我们可以获得指向我们的 struct chrdev_device 的指针，其中包含与我们自定义实现相关的所有必要信息。例如，read_only_show()函数将返回存储在 read_only 变量中的值，该值表示设备的只读属性。请注意，read_only_show()必须返回一个表示返回多少字节的正值，或者如果有任何错误则返回一个负值。

以类似的方式，`read_only_store()`函数为我们提供要写入`buf`缓冲区和`count`的数据，同时我们可以使用相同的技术来获得指向`struct chrdev_device`的指针。`read_only_store()`函数以人类可读形式（即 ASCII 表示）读取一个数字，然后如果我们读取值为 0，则将`read_only`属性设置为 0，否则设置为 1。

其他属性 id 和 reset_to 分别用于显示设备的 id 或强制内部缓冲区达到所需状态，而不管设备本身是否被定义为只读。

为了测试代码，我们必须像之前描述的那样修改 chrdev.c 文件，然后重新编译代码并将生成的内核模块移动到 ESPRESSObin。现在，如果我们插入模块，我们应该得到几乎与之前相同的内核消息，但是现在/sys/class/chrdev 子目录的内容应该已经改变。实际上，现在我们有以下内容：

```
# ls -l /sys/class/chrdev/cdev-eeprom\@2/
total 0
-r--r--r-- 1 root root 4096 Feb 28 13:45 dev
lrwxrwxrwx 1 root root 0 Feb 28 13:45 device -> ../../../chrdev
-r--r--r-- 1 root root 4096 Feb 28 13:45 id
drwxr-xr-x 2 root root 0 Feb 28 13:45 power
-rw-r--r-- 1 root root 4096 Feb 28 13:45 read_only
--w------- 1 root root 4096 Feb 28 13:45 reset_to
lrwxrwxrwx 1 root root 0 Feb 28 13:45 subsystem -> ../../../../../class/chrdev
-rw-r--r-- 1 root root 4096 Feb 28 13:45 uevent
```

正如预期的那样，我们在代码中定义了三个新属性。然后，我们可以尝试从中读取：

```
# cat /sys/class/chrdev/cdev-eeprom\@2/id 
2
# cat /sys/class/chrdev/cdev-eeprom\@2/read_only 
0
# cat /sys/class/chrdev/cdev-eeprom\@2/reset_to 
cat: /sys/class/chrdev/cdev-eeprom@2/reset_to: Permission denied
```

所有答案都如预期；实际上，cdev-eeprom 设备的 id 等于 2，并且不是只读的，而 reset_to 属性是只写的，不可读。类似的输出也可以从 cdev-rom 中获得，如下所示：

```
# cat /sys/class/chrdev/cdev-rom\@4/id 
4
# cat /sys/class/chrdev/cdev-rom\@4/read_only 
1
```

这些属性对于检查当前设备状态很有用，但也可以用于修改其行为。实际上，我们可以使用 reset_to 属性来为只读 cdev-rom 设备设置初始值，如下所示：

```
# echo "THIS IS A READ ONLY DEVICE!" > /sys/class/chrdev/cdev-rom\@4/reset_to 
```

现在/dev/cdev-rom@4 设备仍然是只读的，但不再被全部零填充：

```
# cat /dev/cdev-rom\@4
THIS IS A READ ONLY DEVICE!
```

或者，我们可以从/dev/cdev-rom@4 设备中移除只读属性：

```
# echo 0 > /sys/class/chrdev/cdev-rom\@4/read_only
```

现在，如果我们尝试再次向其中写入数据，我们会成功（echo 命令下方的内核消息是从串行控制台报告的）：

```
root@espressobin:~# echo "TEST STRING" > /dev/cdev-rom\@4 
chrdev cdev-rom@4: chrdev (id=4) opened
chrdev cdev-rom@4: should write 12 bytes (*ppos=0)
chrdev cdev-rom@4: got 12 bytes (*ppos=12)
chrdev cdev-rom@4: chrdev (id=4) released
```

请注意，这样做是有效的，但会产生意外的副作用；我们可以写入设备，但新的 TEST STRING 会覆盖我们刚刚设置的新（更长的）reset_to 字符串（即 THIS IS A READ-ONLY DEVICE），因此随后的读取将会得到：

＃cat /dev/cdev-rom\@4

测试字符串

只读设备！

然而，这只是一个例子，我们可以安全地接受这种行为。

# 为特定外围设备配置 CPU 引脚

即使 ESPRESSObin 是本书的参考平台，在本段中，我们将解释内核开发人员如何修改不同平台的引脚设置，因为这个任务可能因不同的实现而有所不同。实际上，即使所有这些实现都是基于设备树的，它们之间存在一些必须概述的差异。

当前的 CPU 是非常复杂的系统——复杂到大多数 CPU 都被赋予了缩写**SoC**，意思是**片上系统**；事实上，在一个芯片上，我们可能不仅可以找到**中央处理单元**（**CPU**），还有很多外围设备，CPU 可以用来与外部环境进行通信。因此，我们可以在一个芯片内找到显示控制器、键盘控制器、USB 主机或设备控制器、磁盘和网络控制器。不仅如此，现代 SoC 还有几个副本！所有这些外围设备都有自己的信号，每个信号都通过专用的物理线路进行路由，每条线路都需要一个引脚与外部环境进行通信；然而，可能会出现 CPU 引脚不足以将所有这些线路路由到外部的情况，这就是为什么大多数引脚都是多路复用的原因。这意味着，例如，CPU 可能有六个串行端口和两个以太网端口，但它们不能同时使用。这就是**pinctrl 子系统**发挥作用的地方。

Linux 的 pinctrl 子系统处理枚举、命名和多路可控引脚，例如软件控制的偏置和驱动模式特定的引脚，例如上拉/下拉、开漏、负载电容等。所有这些设置都可以通过**引脚控制器**来完成，这是一种硬件（通常是一组寄存器），可以控制 CPU 引脚，可能能够对单个引脚或引脚组进行多路复用、偏置、设置负载电容或设置驱动强度。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/3d784abe-8a03-493a-b9e2-2f8e780c1db8.png)

无符号整数从 0 到最大引脚编号用于表示我们想要控制的封装输入或输出线路。

这个数字空间是每个引脚控制器本地的，因此在系统中可能有几个这样的数字空间；每次实例化引脚控制器时，它都会注册一个包含一组引脚描述符的描述符，描述这个特定引脚控制器处理的引脚。

在本书中，我们不打算解释如何在内核中定义引脚控制器，因为这超出了本书的范围（而且也是一个相当复杂的任务），但我们将尝试为读者提供配置每个 CPU 引脚的能力，以便它们可以与他们正在开发的驱动程序一起使用，例如，在嵌入式系统行业中使用的三种最常用的 CPU。

# Armada 3720

ESPRESSObin 的 CPU 是 Marvell 的 Armada 3720，我们可以通过查看`linux/arch/arm64/boot/dts/marvell/armada-37xx.dtsi`文件来了解其内部外围设备的情况。该文件定义了内部外围设备的内存映射（即每个外围设备在 CPU 内存中的映射方式和位置），以及按引脚控制器和引脚功能分组的所有 CPU 引脚。

例如，以下代码段定义了一个名为`pinctrl@13800`的引脚控制器：

```
   pinctrl_nb: pinctrl@13800 {
        compatible = "marvell,armada3710-nb-pinctrl",
                 "syscon", "simple-mfd";
        reg = <0x13800 0x100>, <0x13C00 0x20>;
        /* MPP1[19:0] */
        gpionb: gpio {
            #gpio-cells = <2>;
            gpio-ranges = <&pinctrl_nb 0 0 36>;
            gpio-controller;
            interrupt-controller;
            #interrupt-cells = <2>;
            interrupts =
            <GIC_SPI 51 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 52 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 53 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 54 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 55 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 56 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 57 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 58 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 152 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 153 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 154 IRQ_TYPE_LEVEL_HIGH>,
            <GIC_SPI 155 IRQ_TYPE_LEVEL_HIGH>;
        };

        xtalclk: xtal-clk {
            compatible = "marvell,armada-3700-xtal-clock";
            clock-output-names = "xtal"; 
            #clock-cells = <0>;
        };

        spi_quad_pins: spi-quad-pins {
            groups = "spi_quad";
            function = "spi";
        };
...
```

我们应该记住，这个表示法意味着它从名为`internal-regs@d0000000`的父节点的开头偏移`0x13800`处进行映射，并映射到`0xd0000000`处。

`compatible`属性表示这个引脚控制器的驱动程序（存储在`linux/drivers/pinctrl/mvebu/pinctrl-armada-37xx.c`文件中），而每个子节点描述了引脚的功能。我们可以看到一个带有时钟设备和一组引脚定义的 GPIO 控制器（从`spi_quad_pins`开始），这些引脚控制器在以下报告的代码中进行了定义。

```
static struct armada_37xx_pin_group armada_37xx_nb_groups[] = {
    PIN_GRP_GPIO("jtag", 20, 5, BIT(0), "jtag"),
    PIN_GRP_GPIO("sdio0", 8, 3, BIT(1), "sdio"),
    PIN_GRP_GPIO("emmc_nb", 27, 9, BIT(2), "emmc"),
    PIN_GRP_GPIO("pwm0", 11, 1, BIT(3), "pwm"),
    PIN_GRP_GPIO("pwm1", 12, 1, BIT(4), "pwm"),
    PIN_GRP_GPIO("pwm2", 13, 1, BIT(5), "pwm"),
    PIN_GRP_GPIO("pwm3", 14, 1, BIT(6), "pwm"),
    PIN_GRP_GPIO("pmic1", 17, 1, BIT(7), "pmic"),
    PIN_GRP_GPIO("pmic0", 16, 1, BIT(8), "pmic"),
    PIN_GRP_GPIO("i2c2", 2, 2, BIT(9), "i2c"),
    PIN_GRP_GPIO("i2c1", 0, 2, BIT(10), "i2c"),
    PIN_GRP_GPIO("spi_cs1", 17, 1, BIT(12), "spi"),
    PIN_GRP_GPIO_2("spi_cs2", 18, 1, BIT(13) | BIT(19), 0, BIT(13), "spi"),
    PIN_GRP_GPIO_2("spi_cs3", 19, 1, BIT(14) | BIT(19), 0, BIT(14), "spi"),
    PIN_GRP_GPIO("onewire", 4, 1, BIT(16), "onewire"),
    PIN_GRP_GPIO("uart1", 25, 2, BIT(17), "uart"),
    PIN_GRP_GPIO("spi_quad", 15, 2, BIT(18), "spi"),
    PIN_GRP_EXTRA("uart2", 9, 2, BIT(1) | BIT(13) | BIT(14) | BIT(19),
              BIT(1) | BIT(13) | BIT(14), BIT(1) | BIT(19),
              18, 2, "gpio", "uart"),
    PIN_GRP_GPIO("led0_od", 11, 1, BIT(20), "led"),
    PIN_GRP_GPIO("led1_od", 12, 1, BIT(21), "led"),
    PIN_GRP_GPIO("led2_od", 13, 1, BIT(22), "led"),
    PIN_GRP_GPIO("led3_od", 14, 1, BIT(23), "led"),

};
```

`PIN_GRP_GPIO()`和`PIN_GRP_GPIO_2()`宏用于指定引脚组可以被内部外围设备使用，或者只能作为普通的 GPIO 线路使用。因此，当我们在 ESPRESSObin 的 DTS 文件中使用以下代码（来自`linux/arch/arm64/boot/dts/marvell/armada-3720-espressobin.dts`文件）时，我们要求引脚控制器为`uart0`设备保留`uart1_pins`组。

```
/* Exported on the micro USB connector J5 through an FTDI */
&uart0 {
    pinctrl-names = "default";
    pinctrl-0 = <&uart1_pins>;
    status = "okay";
};
```

请注意，`status = "okay"` 这一行是必需的，因为每个设备通常都是禁用的，如果不指定，设备将无法工作。

请注意，这次我们使用了 `pinctrl-0` 属性来声明外围设备的引脚。

`pinctrl-0` 和 `pinctrl-names` 属性的使用与多引脚配置状态密切相关，由于空间有限，本书未对其进行报告。然而，有兴趣的读者可以查看 `https://www.kernel.org/doc/Documentation/devicetree/bindings/pinctrl/pinctrl-bindings.txt` 以获取更多信息。

# i.MX7Dual

另一个相当著名的 CPU 是来自 Freescale 的 **i.MX7Dual**，它在 `linux/arch/arm/boot/dts/imx7s.dtsi` 设备树文件中有描述。在该文件中，我们可以看到其两个引脚控制器的定义如下：

```
    iomuxc_lpsr: iomuxc-lpsr@302c0000 {
        compatible = "fsl,imx7d-iomuxc-lpsr";
        reg = <0x302c0000 0x10000>;
        fsl,input-sel = <&iomuxc>;
    };

    iomuxc: iomuxc@30330000 {
        compatible = "fsl,imx7d-iomuxc";
        reg = <0x30330000 0x10000>;
    };
```

通过使用 `compatible` 属性，我们可以发现引脚控制器的驱动程序存储在文件 `linux/drivers/pinctrl/freescale/pinctrl-imx7d.c` 中，我们可以在其中找到所有 CPU 引脚的列表，如下所示（由于空间原因，仅报告了第二个引脚控制器的引脚）：

```
enum imx7d_lpsr_pads {
    MX7D_PAD_GPIO1_IO00 = 0,
    MX7D_PAD_GPIO1_IO01 = 1,
    MX7D_PAD_GPIO1_IO02 = 2,
    MX7D_PAD_GPIO1_IO03 = 3,
    MX7D_PAD_GPIO1_IO04 = 4,
    MX7D_PAD_GPIO1_IO05 = 5,
    MX7D_PAD_GPIO1_IO06 = 6,
    MX7D_PAD_GPIO1_IO07 = 7,
};
```

然后，所有需要引脚的外围设备只需声明它们，就像从 Freescale 的 **i.MX 7Dual SABRE board** 的 DTS 文件中取出的以下示例一样：

```
...
    panel {
        compatible = "innolux,at043tn24";
        pinctrl-0 = <&pinctrl_backlight>;
        enable-gpios = <&gpio1 1 GPIO_ACTIVE_HIGH>;
        power-supply = <&reg_lcd_3v3>;

        port {
            panel_in: endpoint {
                remote-endpoint = <&display_out>; 
            };
        };
    };
};
...
&wdog1 {
    pinctrl-names = "default";
    pinctrl-0 = <&pinctrl_wdog>;
    fsl,ext-reset-output;
};
...
&iomuxc_lpsr {
    pinctrl_wdog: wdoggrp {
        fsl,pins = <
            MX7D_PAD_LPSR_GPIO1_IO00__WDOG1_WDOG_B 0x74
        >;
    };

    pinctrl_backlight: backlightgrp {
        fsl,pins = <
            MX7D_PAD_LPSR_GPIO1_IO01__GPIO1_IO1 0x110b0
        >;
    };
};
```

在前面的示例中，`panel` 节点要求 `pinctrl_backlight` 引脚组，而 `wdog1` 要求 `pinctrl_wdog` 引脚组；所有这些组都需要来自 `lpsr` 垫的引脚。

请注意，DTS 中定义的引脚可以在文件 `linux/arch/arm/boot/dts/imx7d-pinfunc.h` 中找到。此外，以下数字是特定的引脚设置，这些设置在 CPU 的用户手册中有解释，因此请参考手册以获取有关这些神奇数字的更多信息。

同样，`pinctrl-0` 属性已用于寻址默认引脚配置。

# SAMA5D3

最后一个示例是关于名为 **SAMA5D3 from Microchip** 的 CPU，在 `linux/arch/arm/boot/dts/sama5d3.dtsi` 文件中有描述。引脚定义模式与前面的相似，其中引脚控制器驱动程序存储在 `linux/drivers/pinctrl/pinctrl-at91.c` 文件中，并且所有引脚特性都根据设备树中的定义进行管理，如下例所示：

```
    pinctrl@fffff200 {
        #address-cells = <1>;
        #size-cells = <1>;
        compatible = "atmel,sama5d3-pinctrl", "atmel,at91sam9x5-pinctrl", "simple-bus";
        ranges = <0xfffff200 0xfffff200 0xa00>;
        atmel,mux-mask = <
            /* A B C */
            0xffffffff 0xc0fc0000 0xc0ff0000 /* pioA */
            0xffffffff 0x0ff8ffff 0x00000000 /* pioB */
            0xffffffff 0xbc00f1ff 0x7c00fc00 /* pioC */
            0xffffffff 0xc001c0e0 0x0001c1e0 /* pioD */
            0xffffffff 0xbf9f8000 0x18000000 /* pioE */
            >;

        /* shared pinctrl settings */
        adc0 {
            pinctrl_adc0_adtrg: adc0_adtrg {
                atmel,pins =
                    <AT91_PIOD 19 AT91_PERIPH_A AT91_PINCTRL_NONE>; /* PD19 periph A ADTRG */
            };
            pinctrl_adc0_ad0: adc0_ad0 {
                atmel,pins =
                    <AT91_PIOD 20 AT91_PERIPH_A AT91_PINCTRL_NONE>; /* PD20 periph A AD0 */
            };
...
            pinctrl_adc0_ad7: adc0_ad7 {
                atmel,pins =
                    <AT91_PIOD 27 AT91_PERIPH_A AT91_PINCTRL_NONE>; /* PD27 periph A AD7 */
...
```

同样，当外围设备需要一个以上的引脚组时，它只需声明它们，就像从 Microchip Technology 的 **SAMA5D3 Xplained board** 的 DTS 文件中取出的以下代码一样：

```
    adc0: adc@f8018000 {
        atmel,adc-vref = <3300>; 
        atmel,adc-channels-used = <0xfe>; 
        pinctrl-0 = <
            &pinctrl_adc0_adtrg
            &pinctrl_adc0_ad1
            &pinctrl_adc0_ad2
            &pinctrl_adc0_ad3
            &pinctrl_adc0_ad4
            &pinctrl_adc0_ad5
            &pinctrl_adc0_ad6
            &pinctrl_adc0_ad7
            >;
        status = "okay"; 
    };
```

在前面的示例中，`adc0` 节点要求多个引脚组，以便能够管理其内部 ADC 外围设备。

SAMA5D3 CPU 的 DTS 模式仍然使用 `pinctrl-0` 属性来寻址默认引脚配置。

# 使用设备树描述字符驱动程序

为了测试在本章中呈现的代码，并展示一切是如何工作的，我们必须在采取任何进一步步骤之前对其进行编译：

```
$ make KERNEL_DIR=../../../linux
make -C ../../../linux \
            ARCH=arm64 \
            CROSS_COMPILE=aarch64-linux-gnu- \
            SUBDIRS=/home/giometti/Projects/ldddc/github/chapter_4/chrdev modules
make[1]: Entering directory '/home/giometti/Projects/ldddc/linux'
  CC [M] /home/giometti/Projects/ldddc/github/chapter_4/chrdev/chrdev.o
  CC [M] /home/giometti/Projects/ldddc/github/chapter_4/chrdev/chrdev-req.o
...
  LD [M] /home/giometti/Projects/ldddc/github/chapter_4/chrdev/chrdev.ko
make[1]: Leaving directory '/home/giometti/Projects/ldddc/linux'
```

然后，我们必须将 `chrdev.ko` 和 `chrdev-req.ko` 文件移动到 ESPRESSObin。现在，如果我们插入第一个模块，我们将在串行控制台上（或内核消息中）看到与之前完全相同的输出：

```
# insmod chrdev.ko
chrdev: loading out-of-tree module taints kernel.
chrdev:chrdev_init: got major 239
```

当我们插入第二个模块时，差异将会出现：

```
# insmod chrdev-req.ko 
chrdev cdev-eeprom@2: chrdev cdev-eeprom with id 2 added
chrdev cdev-rom@4: chrdev cdev-rom with id 4 added
```

太棒了！现在已经创建了两个新设备。通过这样做，以下两个字符文件已自动创建到 `/dev` 目录中：

```
# ls -l /dev/cdev*
crw------- 1 root root 239, 2 Feb 27 18:35 /dev/cdev-eeprom@2
crw------- 1 root root 239, 4 Feb 27 18:35 /dev/cdev-rom@4
```

实际上，这里没有什么神奇之处，而是由 `udev` 程序为我们完成的，这将在下一节中更深入地解释。

新设备的名称根据设备树中指定的标签进行命名（如前所述），次要编号对应于每个 `reg` 属性使用的值。

请注意，当我们指定 printf 格式时，`cdev-eeprom@2` 和 `cdev-rom@4` 名称是由 `device_create()` 函数创建的：

`device_create(... , "%s@%d", label, id);`

现在我们可以尝试在我们新创建的设备中读取和写入数据。根据设备树中的定义，标记为`cdev-eeprom`的设备应该是读/写设备，而标记为`cdev-rom`的设备是只读设备。因此，让我们在`/dev/cdev-eeprom@2`字符设备上尝试一些简单的读/写命令：

```
# echo "TEST STRING" > /dev/cdev-eeprom\@2 
# cat /dev/cdev-eeprom\@2
TEST STRING
```

请注意在`@`之前的反斜杠（`\`）字符，否则，BASH 会生成错误。

为了验证一切是否与以前一样，相关的内核消息报告如下：

```
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: should write 12 bytes (*ppos=0)
chrdev cdev-eeprom@2: got 12 bytes (*ppos=12)
chrdev cdev-eeprom@2: chrdev (id=2) released
chrdev cdev-eeprom@2: chrdev (id=2) opened
chrdev cdev-eeprom@2: should read 131072 bytes (*ppos=0)
chrdev cdev-eeprom@2: return 300 bytes (*ppos=300)
chrdev cdev-eeprom@2: should read 131072 bytes (*ppos=300)
chrdev cdev-eeprom@2: return 0 bytes (*ppos=300)
chrdev cdev-eeprom@2: chrdev (id=2) released
```

我们可以看到，通过第一个命令，我们调用了`open()`系统调用，驱动程序识别出设备`id`等于 2，然后我们写入了 12 个字节（即`TEST STRING`加上终止字符）；之后，我们关闭了设备。相反，使用`cat`命令，我们仍然打开了设备，但之后，我们进行了 131,072 字节的第一次读取（驱动程序只正确返回了 300 字节），然后进行了相同数量的字节的另一次读取，得到了答案 0，表示文件结束；因此，`cat`命令关闭了设备并打印了接收到的数据（或者至少是所有可打印的字节），然后退出。

现在我们可以尝试在另一个`/dev/cdev-rom@4`设备上执行相同的命令。输出如下：

```
# echo "TEST STRING" > /dev/cdev-rom\@4 
-bash: echo: write error: Invalid argument
# cat /dev/cdev-rom\@4 
```

第一个命令如预期般失败，而第二个似乎没有返回任何内容；然而，这是因为所有读取的数据都是 0，为了验证这一点，我们可以使用`od`命令如下：

```
# od -tx1 -N 16 /dev/cdev-rom\@4 
0000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0000020
```

这表明没有数据被写入`/dev/cdev-rom@4`设备，该设备在设备树中被定义为只读。

与前面的代码一样，我们可以再次查看内核消息，以验证一切是否正常（以下是与`od`命令相关的报告的内核消息）：

```
chrdev cdev-rom@4: chrdev (id=4) opened
chrdev cdev-rom@4: should write 12 bytes (*ppos=0)
chrdev cdev-rom@4: chrdev (id=4) released
chrdev cdev-rom@4: chrdev (id=4) opened
chrdev cdev-rom@4: should read 131072 bytes (*ppos=0)
chrdev cdev-rom@4: return 300 bytes (*ppos=300)
chrdev cdev-rom@4: should read 131072 bytes (*ppos=300)
chrdev cdev-rom@4: return 0 bytes (*ppos=300)
chrdev cdev-rom@4: chrdev (id=4) released
chrdev cdev-rom@4: chrdev (id=4) opened
chrdev cdev-rom@4: should read 16 bytes (*ppos=0)
chrdev cdev-rom@4: return 16 bytes (*ppos=16)
chrdev cdev-rom@4: chrdev (id=4) released
```

在前面的输出中，我们可以看到我们首先打开了设备（这次是设备 id 等于四的设备），然后我们使用了`write()`系统调用，显然失败了，所以设备被简单地关闭了。接下来的两次读取与前面的读取完全相同。

现在我们应该尝试修改设备树以定义不同的 chrdev 设备，或者更好的是，应该尝试修改驱动程序以添加更多功能。
