# 使用 Yocto 项目学习 Linux 嵌入式编程（二）

> 原文：[`zh.annas-archive.org/md5/6A5B9E508EC2401ECE20C211D2D71910`](https://zh.annas-archive.org/md5/6A5B9E508EC2401ECE20C211D2D71910)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Linux 根文件系统

在本章中，您将了解根文件系统及其结构。您还将获得有关根文件系统内容、各种设备驱动程序以及与 Linux 内核的通信的信息。我们将逐渐过渡到 Yocto 项目以及用于定义 Linux 根文件系统内容的方法。将提供必要的信息，以确保用户能够根据自己的需求定制`rootfs`文件系统。

将介绍根文件系统的特殊要求。您将获得有关其内容、子目录、定义目的、各种文件系统选项、BusyBox 替代方案以及许多有趣功能的信息。

在与嵌入式环境交互时，许多开发人员会从分发提供商（如 Debian）那里获得一个最小的根文件系统，并使用交叉工具链来增强它，添加各种软件包、工具和实用程序。如果要添加的软件包数量很大，这可能会是非常麻烦的工作。从头开始将是一个更大的噩梦。在 Yocto 项目中，这项工作是自动化的，无需手动工作。开发是从头开始的，并且在根文件系统中提供了大量的软件包，使工作变得有趣和有趣。因此，让我们继续前进，看看本章的内容，以更全面地了解根文件系统。

# 与根文件系统交互

根文件系统由目录和文件层次结构组成。在这个文件层次结构中，可以挂载各种文件系统，显示特定存储设备的内容。挂载是使用`mount`命令完成的，在操作完成后，挂载点将被存储设备上可用的内容填充。反向操作称为`umount`，用于清空挂载点的内容。

前面的命令对应用程序与各种可用文件的交互非常有用，无论它们的位置和格式如何。例如，`mount`命令的标准形式是`mount -t type device directory`。这个命令要求内核连接设备上的文件系统，该设备在命令行中指定了`type`格式，同时还要连接命令中提到的目录。在移除设备之前，需要使用`umount`命令来确保内核缓存被写入存储点。

根文件系统位于根目录结构中，也称为`/`。它是第一个可用的文件系统，也是不使用`mount`命令的文件系统，因为它是通过内核直接通过`root=`参数挂载的。以下是加载根文件系统的多个选项：

+   从内存

+   使用 NFS 从网络中

+   从 NAND 芯片

+   从 SD 卡分区

+   从 USB 分区

+   从硬盘分区

这些选项由硬件和系统架构师选择。要使用这些选项，需要相应地配置内核和引导加载程序。

除了需要与板载内存或存储设备进行交互的选项外，加载根文件系统最常用的方法之一是 NFS 选项，这意味着根文件系统在本地机器上可用，并且在目标机器上通过网络进行导出。此选项提供以下优势：

+   由于开发机器上的存储空间比目标机器上的存储空间大得多，根文件系统的大小不会成为问题

+   更新过程更容易，无需重新启动

+   访问网络存储是对于内部或外部存储空间较小甚至不存在的设备的最佳解决方案

通过网络存储的缺点是需要服务器客户端架构。因此，对于 NFS，开发机器上需要提供 NFS 服务器功能。对于 Ubuntu 主机，所需的配置涉及安装`nfs-kernel-server`软件包，`sudo apt-get install nfs-kernel-server`。安装软件包后，需要指定和配置导出目录位置。这是通过`/etc/exports`文件完成的；在这里，类似于`/nfs/rootfs <client-IP-address> (rw,no_root_squash,no_subtree_check)`的配置行出现，其中每行定义了 NFS 客户端的网络共享位置。配置完成后，需要以以下方式重新启动 NFS 服务器：`sudo /etc/init.d/nfs-kernel-server restart`。

对于目标上可用的客户端端，需要相应配置 Linux 内核，以确保启用 NFS 支持，并且在启动时 IP 地址可用。这些配置是`CONFIG_NFS_FS=y`，`CONFIG_IP_PNP=y`和`CONFIG_ROOT_NFS=y`。内核还需要配置`root=/dev/nfs`参数，目标的 IP 地址和 NFS 服务器`nfsroot=192.168.1.110:/nfs/rootfs`信息。以下是两个组件之间通信的示例：

![与根文件系统交互](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00323.jpeg)

还有一种可能性，即将根文件系统集成到内核映像中，即最小根文件系统，其目的是启动完整功能的根文件系统。这个根文件系统称为`initramfs`。这种类型的文件系统对于对快速启动选项感兴趣的人非常有帮助，因为它只包含一些有用的功能，并且需要在更早的时候启动。它对于在启动时快速加载系统非常有用，但也可以作为启动实际根文件系统之前的中间步骤。根文件系统在内核引导过程之后首先启动，因此它应该与 Linux 内核一起可用，因为它驻留在 RAM 内存上的内核附近。以下图片解释了这一点：

![与根文件系统交互](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00324.jpeg)

要创建`initramfs`，需要提供配置。这是通过定义根文件系统目录的路径、`cpio`存档的路径，甚至是描述`initramfs`内容的文本文件来完成的，这些都在`CONFIG_INITRAMFS_SOURCE`中。当内核构建开始时，将读取`CONFIG_INITRAMFS_SOURCE`的内容，并将根文件系统集成到内核映像中。

### 注意

有关`initramfs`文件系统选项的更多信息可以在内核文档文件`Documentation/filesystems/ramfs-rootfs-initramfs.txt`和`Documentation/early-userspace/README`中找到。

初始 RAM 磁盘或`initrd`是另一种挂载早期根文件系统的机制。它还需要在 Linux 内核中启用支持，并作为内核的组件加载。它包含一小组可执行文件和目录，并代表了完整功能的根文件系统的临时阶段。它只代表了对于没有能够容纳更大根文件系统的存储设备的嵌入式设备的最终阶段。

在传统系统上，使用`mkinitrd`工具创建`initrd`，实际上是一个自动化创建`initrd`所需步骤的 shell 脚本。以下是其功能的示例：

```
#!/bin/bash

# Housekeeping...
rm -f /tmp/ramdisk.img
rm -f /tmp/ramdisk.img.gz

# Ramdisk Constants
RDSIZE=4000
BLKSIZE=1024

# Create an empty ramdisk image
dd if=/dev/zero of=/tmp/ramdisk.img bs=$BLKSIZE count=$RDSIZE

# Make it an ext2 mountable file system
/sbin/mke2fs -F -m 0 -b $BLKSIZE /tmp/ramdisk.img $RDSIZE

# Mount it so that we can populate
mount /tmp/ramdisk.img /mnt/initrd -t ext2 -o loop=/dev/loop0

# Populate the filesystem (subdirectories)
mkdir /mnt/initrd/bin
mkdir /mnt/initrd/sys
mkdir /mnt/initrd/dev
mkdir /mnt/initrd/proc

# Grab busybox and create the symbolic links
pushd /mnt/initrd/bin
cp /usr/local/src/busybox-1.1.1/busybox .
ln -s busybox ash
ln -s busybox mount
ln -s busybox echo
ln -s busybox ls
ln -s busybox cat
ln -s busybox ps
ln -s busybox dmesg
ln -s busybox sysctl
popd

# Grab the necessary dev files
cp -a /dev/console /mnt/initrd/dev
cp -a /dev/ramdisk /mnt/initrd/dev
cp -a /dev/ram0 /mnt/initrd/dev
cp -a /dev/null /mnt/initrd/dev
cp -a /dev/tty1 /mnt/initrd/dev
cp -a /dev/tty2 /mnt/initrd/dev

# Equate sbin with bin
pushd /mnt/initrd
ln -s bin sbin
popd

# Create the init file
cat >> /mnt/initrd/linuxrc << EOF
#!/bin/ash
echo
echo "Simple initrd is active"
echo
mount -t proc /proc /proc
mount -t sysfs none /sys
/bin/ash --login
EOF

chmod +x /mnt/initrd/linuxrc

# Finish up...
umount /mnt/initrd
gzip -9 /tmp/ramdisk.img
cp /tmp/ramdisk.img.gz /boot/ramdisk.img.gz

```

### 注意

有关`initrd`的更多信息可以在`Documentation/initrd.txt`中找到。

使用`initrd`不像`initramfs`那样简单。在这种情况下，需要以类似于用于内核映像的方式复制一个存档，并且引导加载程序需要将其位置和大小传递给内核，以确保它已经启动。因此，在这种情况下，引导加载程序还需要支持`initrd`。`initrd`的中心点由`linuxrc`文件构成，这是第一个启动的脚本，通常用于提供对系统引导的最后阶段的访问，即真正的根文件系统。在`linuxrc`完成执行后，内核会卸载它并继续执行真正的根文件系统。

## 深入文件系统

无论它们的来源是什么，大多数可用的根文件系统都具有相同的目录组织，由**文件系统层次结构**（**FHS**）定义，通常被称为。这种组织对开发人员和用户都非常有帮助，因为它不仅提到了目录层次结构，还提到了目录的目的和内容。最显著的是：

+   `/bin`：这是大多数程序的位置

+   `/sbin`：这是系统程序的位置

+   `/boot`：这是引导选项的位置，例如`内核映像`、`内核配置`、`initrd`、`系统映射`和其他信息

+   `/home`：这是用户主目录

+   `/root`：这是根用户的主目录位置

+   `/usr`：这是用户特定的程序和库的位置，并模仿了根文件系统的部分内容

+   `/lib`：这是库的位置

+   `/etc`：这是系统范围的配置

+   `/dev`：这是设备文件的位置

+   `/media`：这是可移动设备的挂载点的位置

+   `/mnt`：这是静态媒体的挂载位置点

+   `/proc`：这是`proc`虚拟文件系统的挂载点

+   `/sys`：这是`sysfs`虚拟文件系统的挂载点

+   `/tmp`：这是临时文件的位置

+   `/var`：这是数据文件的位置，例如日志数据、管理信息或瞬态数据的位置

FHS 随时间而变化，但变化不大。大多数先前提到的目录出于各种原因保持不变-最简单的原因是它们需要确保向后兼容性。

### 注意

FHS 的最新信息可在[`refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.pdf`](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.pdf)上找到。

根文件系统由内核启动，这是内核在结束引导阶段之前执行的最后一步。以下是执行此操作的确切代码：

```
/*
  * We try each of these until one succeeds.
  *
  * The Bourne shell can be used instead of init if we are
  * trying to recover a really broken machine.
  */
  if (execute_command) {
    ret = run_init_process(execute_command);
    if (!ret)
      return 0;
    pr_err("Failed to execute %s (error %d).  Attempting defaults...\n",execute_command, ret);
  }
  if (!try_to_run_init_process("/sbin/init") ||
    !try_to_run_init_process("/etc/init") ||
    !try_to_run_init_process("/bin/init") ||
    !try_to_run_init_process("/bin/sh"))
      return 0;

  panic("No working init found.  Try passing init= option to kernel." "See Linux Documentation/init.txt for guidance.");
```

在此代码中，可以轻松地识别出用于搜索需要在退出 Linux 内核引导执行之前启动的`init`进程的多个位置。`run_init_process()`函数是`execve()`函数的包装器，如果在调用过程中未遇到错误，则不会返回值。被调用的程序覆盖了执行进程的内存空间，替换了调用线程并继承了它的`PID`。

这个初始化阶段是如此古老，以至于 Linux 1.0 版本中也有类似的结构。这代表了用户空间处理的开始。如果内核无法在预定义的位置执行前述四个函数中的一个，则内核将停止，并且会在控制台上提示恐慌消息，以发出无法启动任何 init 进程的警报。因此，在内核空间处理完成之前，用户空间处理将不会开始。

对于大多数可用的 Linux 系统，`/sbin/init`是内核生成 init 进程的位置；对于 Yocto 项目生成的根文件系统，同样也是如此。它是用户空间中运行的第一个应用程序，但它并不是根文件系统的唯一必要特性。在运行根文件系统中的任何进程之前，需要解决一些依赖关系。有一些用于解决动态链接依赖引用的依赖关系，这些引用之前未解决，还有一些需要外部配置的依赖关系。对于第一类依赖关系，可以使用`ldd`工具来查找动态链接依赖关系，但对于第二类依赖关系，没有通用解决方案。例如，对于`init`进程，配置文件是`inittab`，它位于`/etc`目录中。

对于不希望运行另一个`init`进程的开发人员，可以使用内核命令行中的`init=`参数来访问此选项，其中应提供要执行的二进制文件的路径。这些信息也在前面的代码中提供。定制`init`进程并不是开发人员常用的方法，但这是因为`init`进程非常灵活，可以提供多个启动脚本。

在`init`之后启动的每个进程都使用父子关系，其中`init`充当用户空间中所有进程的父进程，并且还提供环境参数。最初，init 进程根据`/etc/inittab`配置文件中的信息生成进程，该文件定义了运行级别的概念。运行级别表示系统的状态，并定义了已启动的程序和服务。有八个可用的运行级别，编号从`0`到`6`，还有一个特殊的`S`。它们的目的在这里描述：

| 运行级别值 | 运行级别目的 |
| --- | --- |
| `0` | 它指的是整个系统的关闭和关机命令 |
| `1` | 它是带有标准登录访问的单用户管理模式 |
| `2` | 它是没有 TCP/IP 连接的多用户模式 |
| `3` | 它指的是通用多用户 |
| `4` | 它由系统所有者定义 |
| `5` | 它指的是图形界面和 TCP/IP 连接的多用户系统 |
| `6` | 它指的是系统重启 |
| `s` | 它是提供对最小根 shell 的单用户模式访问 |

每个运行级别启动和终止一些服务。启动的服务以`S`开头，终止的服务以`K`开头。每个服务实际上是一个 shell 脚本，定义了它所提供的行为。

`/etc/inittab`配置脚本定义了运行级别和应用于所有运行级别的指令。对于 Yocto 项目，`/etc/inittab`看起来类似于这样：

```
# /etc/inittab: init(8) configuration.
# $Id: inittab,v 1.91 2002/01/25 13:35:21 miquels Exp $

# The default runlevel.
id:5:initdefault:

# Boot-time system configuration/initialization script.
# This is run first except when booting in emergency (-b) mode.
si::sysinit:/etc/init.d/rcS

# What to do in single-user mode.
~~:S:wait:/sbin/sulogin

# /etc/init.d executes the S and K scripts upon change
# of runlevel.
#
# Runlevel 0 is halt.
# Runlevel 1 is single-user.
# Runlevels 2-5 are multi-user.
# Runlevel 6 is reboot.

l0:0:wait:/etc/init.d/rc 0
l1:1:wait:/etc/init.d/rc 1
l2:2:wait:/etc/init.d/rc 2
l3:3:wait:/etc/init.d/rc 3
l4:4:wait:/etc/init.d/rc 4
l5:5:wait:/etc/init.d/rc 5
l6:6:wait:/etc/init.d/rc 6
# Normally not reached, but fallthrough in case of emergency.
z6:6:respawn:/sbin/sulogin
S0:12345:respawn:/sbin/getty 115200 ttyS0
# /sbin/getty invocations for the runlevels.
#
# The "id" field MUST be the same as the last
# characters of the device (after "tty").
#
# Format:
#  <id>:<runlevels>:<action>:<process>
#

1:2345:respawn:/sbin/getty 38400 tty1
```

当`init`解析前面的`inittab`文件时，首先执行的是通过`sysinit`标签标识的`si::sysinit:/etc/init.d/rcS`行。然后，进入`runlevel 5`，并继续处理指令，直到最后一个级别，最终使用`/sbin/getty symlink`生成一个 shell。可以在控制台中运行`man init`或`man inittab`来获取有关`init`或`inittab`的更多信息。

任何 Linux 系统的最后阶段都由关机或关闭命令表示。这非常重要，因为如果不适当地执行，可能会通过损坏数据来影响系统。当然，有多种选项可以实现关闭方案，但最方便的形式仍然是使用诸如`shutdown`、`halt`或`reboot`之类的实用程序。还可以使用`init 0`来关闭系统，但实际上，它们都共同使用`SIGTERM`和`SIGKILL`信号。`SIGTERM`最初用于通知您关于关闭系统的决定，以便系统执行必要的操作。完成后，发送`SIGKILL`信号以终止所有进程。

## 设备驱动程序

Linux 系统面临的最重要挑战之一是允许应用程序访问各种硬件设备。诸如虚拟内存、内核空间和用户空间之类的概念并没有简化事情，而是为这些信息增加了另一层复杂性。

设备驱动程序的唯一目的是将硬件设备和内核数据结构与用户空间应用程序隔离开来。用户不需要知道，要向硬盘写入数据，他或她将需要使用不同大小的扇区。用户只需打开一个文件进行写入，完成后关闭即可。设备驱动程序是执行所有底层工作的程序，比如隔离复杂性。

在用户空间中，所有设备驱动程序都有关联的设备节点，实际上是表示设备的特殊文件。所有设备文件都位于`/dev`目录中，并通过`mknod`实用程序与它们进行交互。设备节点在两个抽象层上可用：

+   **块设备**：这些由固定大小的块组成，通常在与硬盘、SD 卡、USB 存储设备等交互时使用

+   **字符设备**：这些是不具有大小、起始或结束的字符流；它们大多不是块设备的形式，比如终端、串行端口、声卡等

每个设备都有一个提供有关其信息的结构：

+   `Type`标识设备节点是字符设备还是块设备

+   `Major`标识设备的类别

+   `Minor`保存设备节点的标识符

创建设备节点的`mknod`实用程序使用三元组信息，例如`mknod /dev/testdev c 234 0`。执行命令后，将出现一个`new /dev/testdev`文件。它应该绑定到已安装并已定义其属性的设备驱动程序。如果发出`open`命令，内核将寻找与设备节点相同主要编号注册的设备驱动程序。次要编号用于处理多个设备或使用相同设备驱动程序的设备系列。它被传递给设备驱动程序以便使用。没有标准的使用次要编号的方法，但通常它定义了来自共享相同主要编号的设备系列中的特定设备。

使用`mknod`实用程序需要手动交互和 root 权限，并允许开发人员完成识别设备节点及其设备驱动程序对应的属性所需的所有繁重工作。最新的 Linux 系统提供了自动化此过程的可能性，并且还可以在每次检测到设备或设备消失时完成这些操作。具体操作如下：

+   `devfs`：这是一个作为文件系统设计的设备管理器，也可在内核空间和用户空间中访问。

+   `devtmpfs`：这是一个虚拟文件系统，自 2.6.32 内核版本发布以来就可用，是对用于启动时间优化的`devfs`的改进。它只为本地系统上可用的硬件创建设备节点。

+   `udev`：这是指在服务器和桌面 Linux 系统上使用的守护程序。有关此的更多信息可以通过访问[`www.kernel.org/pub/linux/utils/kernel/hotplug/udev/udev.html`](https://www.kernel.org/pub/linux/utils/kernel/hotplug/udev/udev.html)来参考。Yocto 项目也将其用作默认设备管理器。

+   `mdev`：这提供了比`udev`更简单的解决方案；实际上，它是`udev`的一个派生物。

由于系统对象也被表示为文件，这简化了应用程序与它们交互的方法。如果没有使用设备节点，这是不可能的，设备节点实际上是文件，可以对其应用正常的文件交互功能，如`open()`，`read()`，`write()`和`close()`。

## 文件系统选项

根文件系统可以以非常广泛的文件系统类型部署，并且每种文件系统都比其他文件系统更适合执行特定任务。如果某些文件系统针对性能进行了优化，那么其他文件系统则更擅长节省空间甚至恢复数据。这里将介绍一些最常用和有趣的文件系统。

物理设备的逻辑分区，如硬盘或 SD 卡，称为**分区**。物理设备可以有一个或多个分区，覆盖其可用存储空间。它可以被视为具有文件系统供用户使用的逻辑磁盘。在 Linux 中，使用`fdisk`实用程序来管理分区。它可以用于`创建`，`列出`，`销毁`和其他一般交互，有 100 多种分区类型。更准确地说，在我的 Ubuntu 14.04 开发机器上有 128 种分区类型可用。

最常用和知名的文件系统分区格式之一是`ext2`。也称为**第二扩展文件系统**，它是由法国软件开发人员 Rémy Card 于 1993 年引入的。它曾被用作许多 Linux 发行版的默认文件系统，如 Debian 和 Red Hat Linux，直到被其年轻的兄弟`ext3`和`ext4`取代。它继续是许多嵌入式 Linux 发行版和闪存存储设备的选择。

`ext2`文件系统将数据分割为块，并将块排列成块组。每个块组维护超级块的副本和该块组的描述符表。超级块用于存储配置信息，并保存引导过程所需的信息，尽管有多个副本；通常，位于文件系统第一个块中的第一个副本是所使用的。通常将文件的所有数据保存在单个块中，以便可以更快地进行搜索。除了包含的数据外，每个块组还包含有关超级块、块组的描述符表、索引节点位图和表信息以及块位图的信息。超级块是保存引导过程所需信息的地方。它的第一个块用于引导过程。最后一个概念是`inode`，或索引节点，它通过其权限、大小、在磁盘上的位置和所有权来表示文件和目录。

有多个应用程序用于与`ext2`文件系统格式进行交互。其中之一是`mke2fs`，用于在`mke2fs /deb/sdb1 –L`分区（`ext2`标签分区）上创建`ext2`文件系统。还有`e2fsck`命令，用于验证文件系统的完整性。如果未发现错误，这些工具会为您提供有关分区文件系统配置的信息，`e2fsck /dev/sdb1`。此实用程序还能够修复设备不正确使用后出现的一些错误，但不能在所有情况下使用。

Ext3 是另一个强大而广为人知的文件系统。它取代了`ext2`，成为 Linux 发行版中最常用的文件系统之一。实际上，它与`ext2`类似；不同之处在于它具有日志记录信息的可能性。可以使用`tune2fs –j /dev/sdb1`命令将`ext2`文件格式更改为`ext3`文件格式。基本上被视为`ext2`文件系统格式的扩展，它添加了日志记录功能。这是因为它被设计为向前和向后兼容。

日志记录是一种方法，用于记录文件系统上所做的所有更改，从而实现恢复功能。除了已经提到的功能外，`ext3`还添加了其他功能；在这里，我指的是文件系统中不需要检查一致性的可能性，主要是因为日志记录可以被撤消。另一个重要功能是，它可以在不检查关机是否正确执行的情况下挂载。这是因为系统在关机时不需要进行一致性检查。

Ext4 是`ext3`的后继者，旨在改善`ext3`中的性能和存储限制。它还向后兼容`ext3`和`ext2`文件系统，并添加了许多功能：

+   持久性预分配：这定义了`fallocate()`系统调用，可用于预先分配空间，这在大多数情况下是连续的形式；对于数据库和媒体流非常有用

+   延迟分配：这也称为**在刷新时分配**；它用于延迟分配块，从磁盘刷新数据的时刻开始，以减少碎片化并提高性能

+   多块分配：这是延迟分配的副作用，因为它允许数据缓冲，同时分配多个块。

+   增加子目录限制：`ext3`的子目录限制为 32000 个，而`ext4`没有此限制，即子目录的数量是无限的

+   日志的校验和：这用于提高可靠性

**日志闪存文件系统版本 2**（**JFFS2**）是为 NAND 和 NOR 闪存设计的文件系统。它于 2001 年被包含在 Linux 主线内核中，与`ext3`文件系统在同一年发布，尽管在不同的月份。它在 Linux 2.4.15 版本中于 11 月发布，而 JFFS2 文件系统在 2.4.10 内核版本中于 9 月发布。由于它特别用于支持闪存设备，因此考虑了某些因素，例如需要处理小文件以及这些设备具有与之相关的磨损水平，这通过其设计解决和减少。尽管 JFFS2 是闪存的标准，但也有一些替代方案，例如 LogFS、另一个闪存文件系统（YAFFS）和未排序块映像文件系统（UBIFS）。

除了前面提到的文件系统外，还有一些伪文件系统可用，包括`proc`、`sysfs`和`tmpfs`。在下一节中，将描述前两者，留下最后一个让您自己发现。

`proc`文件系统是 Linux 的第一个版本中提供的虚拟文件系统。它被定义为允许内核向用户提供有关正在运行的进程的信息，但随着时间的推移，它已经发展，现在不仅可以提供有关正在运行的进程的统计信息，还可以提供有关内存管理、进程、中断等各种参数的调整。

随着时间的推移，`proc`虚拟文件系统对于 Linux 系统用户来说变得必不可少，因为它汇集了大量的用户空间功能。命令，如`top`、`ps`和`mount`，没有它将无法工作。例如，给出没有参数的`mount`示例将以`proc`挂载在`/proc`上的形式呈现为`proc` on `/proc type proc (rw,noexec,nosuid,nodev)`。这是因为需要将`proc`挂载在`root`文件系统上，与目录`/etc`、`/home`等一起使用作为`/proc`文件系统的目的地。要挂载`proc`文件系统，使用类似于其他可用文件系统的`mount –t proc nodev/proc`挂载命令。有关此更多信息可以在内核源文件的`Documentation/filesystems/proc.txt`中找到。

`proc`文件系统具有以下结构：

+   对于每个运行的进程，`/proc/<pid>`内有一个可用的目录。它包含有关打开的文件、使用的内存、CPU 使用情况和其他特定于进程的信息。

+   一般设备的信息位于`/proc/devices`、`/proc/interrupts`、`/proc/ioports`和`/proc/iomem`内。

+   内核命令行位于`/proc/cmdline`内。

+   用于更改内核参数的文件位于`/proc/sys`内。有关更多信息，也可以在`Documentation/sysctl`中找到。

`sysfs`文件系统用于表示物理设备。自 2.6 版 Linux 内核引入以来，它提供了将物理设备表示为内核对象并将设备驱动程序与相应设备关联的可能性。对于工具，如`udev`和其他设备管理器，它非常有用。

`sysfs`目录结构为每个主要系统设备类都有一个子目录，还有一个系统总线子目录。还有`systool`可以用来浏览`sysfs`目录结构。与 proc 文件系统类似，如果在控制台上提供了`sysfs on /sys type sysfs (rw,noexec,nosuid,nodev)` `mount`命令，`systool`也可以可见。可以使用`mount -t sysfs nodev /sys`命令进行挂载。

### 注意

有关可用文件系统的更多信息，请访问[`en.wikipedia.org/wiki/List_of_file_systems`](http://en.wikipedia.org/wiki/List_of_file_systems)。

# 理解 BusyBox

BusyBox 由 Bruce Perens 于 1999 年开发，旨在将可用的 Linux 工具集成到一个单一的可执行文件中。它已被广泛成功地用作许多 Linux 命令行实用程序的替代品。由于这个原因，以及它能够适应小型嵌入式 Linux 发行版，它在嵌入式环境中获得了很多的流行。它提供了文件交互的实用工具，如`cp`、`mkdir`、`touch`、`ls`和`cat`，以及一般实用工具，如`dmesg`、`kill`、`fdisk`、`mount`、`umount`等。

它不仅非常容易配置和编译，而且非常易于使用。它非常模块化，并提供高度的配置，使其成为理想的选择。它可能不包括主机 PC 上可用的完整 Linux 发行版中的所有命令，但它包含的命令已经足够了。此外，这些命令只是完整命令的简化版本，用于实现级别，并且都集成在一个单一可执行文件中，作为`/bin/busybox`中的符号链接。

开发人员与 BusyBox 源代码包的交互非常简单：只需配置、编译和安装，就可以了。以下是一些详细的步骤来解释以下内容：

+   运行配置工具并选择要提供的功能

+   执行`make dep`来构建依赖树

+   使用`make`命令构建软件包

### 提示

在目标上安装可执行文件和符号链接。对于希望在其工作站上与该工具进行交互的人来说，如果该工具已安装到主机系统，则安装应该在不覆盖主机可用的任何实用程序和启动脚本的位置进行。

BusyBox 包的配置还有一个`menuconfig`选项，类似于内核和 U-Boot 可用的`make menuconfig`。它用于显示一个文本菜单，可用于更快的配置和配置搜索。要使此菜单可用，首先需要在调用`make menuconfig`命令的系统上安装`ncurses`包。

在过程结束时，BusyBox 可执行文件可用。如果没有参数调用它，它将呈现一个与此类似的输出：

```
Usage: busybox [function] [arguments]...
 or: [function] [arguments]...

 BusyBox is a multi-call binary that combines many common Unix
 utilities into a single executable.  Most people will create a
 link to busybox for each function they wish to use and BusyBox
 will act like whatever it was invoked as!

Currently defined functions:
 [, [[, arping, ash, awk, basename, bunzip2, busybox, bzcat, cat,
 chgrp, chmod, chown, chroot, clear, cp, crond, crontab, cut, date,
 dd, df, dirname, dmesg, du, echo, egrep, env, expr, false, fgrep,
 find, free, grep, gunzip, gzip, halt, head, hexdump, hostid, hostname,
 id, ifconfig, init, insmod, ipcalc, ipkg, kill, killall, killall5,
 klogd, length, ln, lock, logger, logread, ls, lsmod, md5sum, mesg,
 mkdir, mkfifo, mktemp, more, mount, mv, nc, "netmsg", netstat,
 nslookup, passwd, pidof, ping, pivot_root, poweroff, printf, ps,
 pwd, rdate, reboot, reset, rm, rmdir, rmmod, route, sed, seq,
 sh, sleep, sort, strings, switch_root, sync, sysctl, syslogd,
 tail, tar, tee, telnet, test, time, top, touch, tr, traceroute,
 true, udhcpc, umount, uname, uniq, uptime, vi, wc, wget, which,
 xargs, yes, zcat

```

它呈现了在配置阶段启用的实用程序列表。调用上述实用程序之一有两种选项。第一种选项需要使用 BusyBox 二进制文件和调用的实用程序数量，表示为`./busybox ls`，而第二种选项涉及使用已经在目录中可用的符号链接，如`/bin、/sbin、/usr/bin`等。

除了已经可用的实用程序之外，BusyBox 还为`init`程序提供了实现替代方案。在这种情况下，`init`不知道运行级别，所有配置都在`/etc/inittab`文件中。另一个与标准`/etc/inittab`文件不同的因素是，它还具有自己的特殊语法。有关更多信息，可以查看 BusyBox 中的`examples/inittab`。BusyBox 包中还实现了其他工具和实用程序，例如`vi`的轻量级版本，但我会让你自己去发现它们。

# 最小`root`文件系统

现在，所有关于`root`文件系统的信息都已经呈现给你，描述最小`root`文件系统的必备组件将是一个很好的练习。这不仅有助于您更好地理解`rootfs`结构及其依赖关系，还有助于满足引导时间和`root`文件系统大小优化的要求。

描述组件的起点是`/sbin/init`；在这里，可以使用`ldd`命令找到运行时依赖关系。对于 Yocto 项目，`ldd /sbin/init`命令返回：

```
linux-gate.so.1 (0xb7785000)
libc.so.6 => /lib/libc.so.6 (0x4273b000)
/lib/ld-linux.so.2 (0x42716000)

```

根据这些信息，定义了`/lib`目录结构。它的最小形式是：

```
lib
|-- ld-2.3.2.so
|-- ld-linux.so.2 -> ld-2.3.2.so
|-- libc-2.3.2.so
'-- libc.so.6 -> libc-2.3.2.so

```

以下是确保库的向后兼容性和版本免疫性的符号链接。在上述代码中，`linux-gate.so.1`文件是一个**虚拟动态链接共享对象**（**vDSO**），由内核在一个已建立的位置公开。它的地址因机器架构而异。

之后，必须定义`init`及其运行级别。这个最小形式在 BusyBox 包中可用，因此也将在`/bin`目录中可用。除此之外，还需要一个用于 shell 交互的符号链接，因此`/bin`目录的最小形式如下：

```
bin
|-- busybox
'-- sh -> busybox

```

接下来，需要定义运行级别。在最小的`root`文件系统中只使用一个，不是因为这是严格要求，而是因为它可以抑制一些 BusyBox 警告。这是`/etc`目录的样子：

```
etc
'-- init.d
 '-- rcS

```

最后，控制台设备需要对用户进行输入和输出操作，因此`root`文件系统的最后一部分位于`/dev`目录中：

```
dev
'-- console

```

提到了所有这些，最小的`root`文件系统似乎只有五个目录和八个文件。其最小尺寸低于 2 MB，大约 80%的尺寸归功于 C 库软件包。还可以通过使用 Library Optimizer Tool 来最小化其大小。您可以在[`libraryopt.sourceforge.net/`](http://libraryopt.sourceforge.net/)找到更多信息。

# Yocto 项目

转到 Yocto 项目，我们可以查看 core-image-minimal 以确定其内容和最低要求，如 Yocto 项目中所定义的。`core-image-minimal.bb`镜像位于`meta/recipes-core/images`目录中，看起来是这样的：

```
SUMMARY = "A small image just capable of allowing a device to boot."

IMAGE_INSTALL = "packagegroup-core-boot ${ROOTFS_PKGMANAGE_BOOTSTRAP} ${CORE_IMAGE_EXTRA_INSTALL} ldd"

IMAGE_LINGUAS = " "

LICENSE = "MIT"

inherit core-image

IMAGE_ROOTFS_SIZE ?= "8192"

```

您可以在这里看到这与任何其他配方都是相似的。该镜像定义了`LICENSE`字段，并继承了一个`bbclass`文件，该文件定义了其任务。使用简短的摘要来描述它，它与普通软件包配方非常不同。它没有`LIC_FILES_CHKSUM`来检查许可证或`SRC_URI`字段，主要是因为它不需要它们。作为回报，该文件定义了应包含在`root`文件系统中的确切软件包，并且其中一些软件包被分组在`packagegroup`中以便更容易处理。此外，`core-image bbclass`文件定义了许多其他任务，例如`do_rootfs`，这仅适用于镜像配方。

构建`root`文件系统对任何人来说都不是一件容易的事情，但 Yocto 做得更成功一些。它从 base-files 配方开始，用于根据**文件系统层次结构标准**（**FHS**）布置目录结构，并且还有一些其他配方。这些信息可在`./meta/recipes-core/packagegroups/packagegroup-core-boot.bb`配方中找到。正如在先前的例子中所看到的，它还继承了不同类型的类，比如`packagegroup.bbclass`，这是所有可用的包组的要求。然而，最重要的因素是它清楚地定义了构成`packagegroup`的软件包。在我们的情况下，核心引导包组包含软件包，如`base-files`，`base-passwd`（其中包含基本系统主密码和组文件），`udev`，`busybox`和`sysvinit`（类似于 System V 的 init）。

正如在先前显示的文件中所看到的，BusyBox 软件包是 Yocto 项目生成的发行版的核心组件。虽然有关 BusyBox 可以提供 init 替代方案的信息是可用的，但默认的 Yocto 生成的发行版并不使用这个功能。相反，它们选择转向类似于 Debian 发行版可用的 System V-like init。然而，通过`meta/recipes-core/busybox`位置内可用的 BusyBox 配方提供了一些 shell 交互工具。对于有兴趣增强或删除`busybox`软件包提供的一些功能的用户，可以使用与 Linux 内核配置相同的概念。`busybox`软件包使用`defconfig`文件，然后应用一些配置片段。这些片段可以添加或删除功能，最终得到最终的配置文件。这标识了`root`文件系统中可用的最终功能。

在 Yocto 项目中，可以通过使用`poky-tiny.conf`发行政策来最小化`root`文件系统的大小，这些政策可以在`meta-yocto/conf/distro`目录中找到。当使用这些政策时，不仅可以减小启动大小，还可以减小启动时间。最简单的示例是使用`qemux86`机器。在这里，变化是可见的，但与“最小根文件系统”部分中已经提到的有些不同。在`qemux86`上进行的最小化工作是围绕`core-image-minimal`镜像进行的。其目标是将结果`rootfs`的大小减小到 4MB 以下，启动时间减小到 2 秒以下。

现在，转向选定的 Atmel SAMA5D3 Xplained 机器，另一个`rootfs`被生成，其内容相当庞大。它不仅包括了`packagegroup-core-boot.bb`软件包组，还包括其他软件包组和单独的软件包。其中一个例子是在`meta-atmel`层的`recipes-core/images`目录中可用的`atmel-xplained-demo-image.bb`镜像：

```
DESCRIPTION = "An image for network and communication."
LICENSE = "MIT"
PR = "r1"

require atmel-demo-image.inc

IMAGE_INSTALL += "\
    packagegroup-base-3g \
    packagegroup-base-usbhost \
    "
```

在这个镜像中，还有另一个更通用的镜像定义被继承。我指的是`atmel-demo-image.inc`文件，打开后可以看到它包含了所有`meta-atmel`层镜像的核心。当然，如果所有可用的软件包都不够，开发人员可以决定添加自己的软件包。开发人员面临两种可能性：创建一个新的镜像，或者向已有的镜像添加软件包。最终结果是使用`bitbake atmel-xplained-demo-image`命令构建的。输出以各种形式可用，并且高度依赖于所定义的机器的要求。在构建过程结束时，输出将用于在实际板上引导根文件系统。

# 摘要

在本章中，您已经了解了 Linux `rootfs`的一般情况，以及与 Linux 内核、Linux `rootfs`的组织、原则、内容和设备驱动程序的通信。由于通信随着时间的推移而变得更加庞大，关于最小文件系统应该如何看待的信息也被呈现给您。

除了这些信息，下一章将为您概述 Yocto 项目的可用组件，因为它们大多数都在 Poky 之外。您还将被介绍并简要介绍每个组件。在本章之后，将向您介绍并详细阐述其中的一些组件。


# 第六章：Yocto 项目的组件

在本章中，您将简要介绍 Yocto 项目生态系统中的一些组件。本章的目的是介绍它们，以便在后续章节中更详细地介绍它们。它还试图引导读者进行额外阅读。对于每个工具、功能或有趣的事实，都提供了链接，以帮助感兴趣的读者寻找本书中的问题以及本章未涵盖的问题的答案。

本章充满了有关嵌入式开发过程的指导和相关示例，涉及特定的 Yocto 项目工具。工具的选择是纯主观的。只选择了在开发过程中被认为有帮助的工具。我们还考虑到其中一些工具可能会为嵌入式世界和嵌入式系统的开发提供新的见解。

# Poky

Poky 代表了 Yocto 项目的元数据和工具的参考构建系统，这些工具是任何对与 Yocto 项目进行交互感兴趣的人的起点。它是独立于平台的，并提供了构建和定制最终结果的工具和机制，实际上是一个 Linux 软件堆栈。Poky 被用作与 Yocto 项目进行交互的中心组件。

作为开发人员使用 Yocto 项目时，了解邮件列表和**Internet Relay Chat** (**IRC**)频道的信息非常重要。此外，项目 Bugzilla 也可以作为可用 bug 和功能列表的灵感来源。所有这些元素都需要一个简短的介绍，因此最好的起点是 Yocto 项目 Bugzilla。它代表了 Yocto 项目用户的 bug 跟踪应用程序，并且是问题报告的地方。下一个组件是 IRC 的可用频道。在 freenode 上有两个可用的组件，一个用于 Poky，另一个用于与 Yocto 项目相关的讨论，如**#poky**和**#yocto**。第三个元素是 Yocto 项目邮件列表，用于订阅 Yocto 项目的邮件列表：

+   [`lists.yoctoproject.org/listinfo/yocto`](http://lists.yoctoproject.org/listinfo/yocto)：这是 Yocto 项目讨论的邮件列表。

+   [`lists.yoctoproject.org/listinfo/poky`](http://lists.yoctoproject.org/listinfo/poky)：这是关于 Yocto 项目 Poky 构建的讨论邮件列表。

+   [`lists.yoctoproject.org/listinfo/yocto-announce`](http://lists.yoctoproject.org/listinfo/yocto-announce)：这是官方公告 Yocto 项目的邮件列表，也是 Yocto 项目里程碑的发布地点。

通过[`lists.yoctoproject.org/listinfo`](http://lists.yoctoproject.org/listinfo)，可以获取有关一般和项目特定邮件列表的更多信息。它包含了[`www.yoctoproject.org/tools-resources/community/mailing-lists`](https://www.yoctoproject.org/tools-resources/community/mailing-lists)上所有可用邮件列表的列表。

要开始使用 Yocto 项目，特别是 Poky，不仅应使用先前提到的组件；还应提供有关这些工具的信息。有关 Yocto 项目的非常好的解释可以在他们的文档页面上找到[`www.yoctoproject.org/documentation`](https://www.yoctoproject.org/documentation)。对于那些对阅读更简短介绍感兴趣的人，可以查看*Packt Publishing*出版的*Embedded Linux Development with Yocto Project*，作者是*Otavio Salvador*和*Daiane Angolini*。

要使用 Yocto 项目，需要满足一些特定的要求：

+   主机系统：假设这是一个基于 Linux 的主机系统。但这不仅仅是任何主机系统；Yocto 有特定的要求。支持的操作系统在`poky.conf`文件中可用，该文件位于`meta-yocto/conf/distro`目录中。支持的操作系统在`SANITY_TESTED_DISTROS`变量中定义，其中一些系统如下：

+   Ubuntu-12.04

+   Ubuntu-13.10

+   Ubuntu-14.04

+   Fedora-19

+   Fedora-20

+   CentOS-6.4

+   CentOS-6.5

+   Debian-7.0

+   Debian-7.1

+   Debian-7.2

+   Debian-7.3

+   Debian-7.4

+   Debian-7.5

+   Debian-7.6

+   SUSE-LINUX-12.2

+   openSUSE-project-12.3

+   openSUSE-project-13.1

+   所需软件包：这包含主机系统上可用的软件包的最低要求列表，除了已有的软件包。当然，这与一个主机系统到另一个主机系统是不同的，系统根据其目的而有所不同。但是，对于 Ubuntu 主机，我们需要以下要求：

+   基本要求：这指的是`sudo apt-get install gawk wget git-core diffstat unzip texinfo gcc-multilib build-essential chrpath socat`

+   图形和 Eclipse 插件额外组件：这指的是`sudo apt-get install libsdl1.2-dev xterm`

+   文档：这指的是`sudo apt-get install make xsltproc docbook-utils fop dblatex xmlto`

+   ADT 安装程序额外组件：这指的是`sudo apt-get install autoconf automake libtool libglib2.0-dev`

+   Yocto 项目发布：在开始任何工作之前，应选择一个可用的 Poky 版本。本书基于 dizzy 分支，即 Poky 1.7 版本，但开发人员可以选择最适合自己的版本。当然，由于与项目的交互是使用`git`版本控制系统完成的，用户首先需要克隆 Poky 存储库，并且对项目的任何贡献都应提交为开源社区的补丁。还有可能获取一个 tar 存档，但由于源代码上的任何更改更难追踪，并且还限制了与项目相关社区的交互，因此这种方法存在一些限制。

如果需要特殊要求，还有其他额外的可选要求需要注意，如下所示：

+   自定义 Yocto 项目内核交互：如果开发人员决定 Yocto 项目维护的内核源不适合他们的需求，他们可以获取 Yocto 项目支持的内核版本的本地副本之一，该副本可在[Yocto Linux Kernel](http://git.yoctoproject.org/cgit.cgi)下找到，并根据自己的需求进行修改。当然，这些更改以及其余的内核源都需要驻留在一个单独的存储库中，最好是`git`，并且将通过内核配方引入 Yocto 世界。

+   meta-yocto-kernel-extras git 存储库：在构建和修改内核映像时，此处收集所需的元数据。它包含一堆`bbappend`文件，可以编辑以指示本地源代码已更改，这是在开发 Linux 内核功能时更有效的方法。它在[Yocto Metadata Layers](http://git.yoctoproject.org/cgit.cgi)的**Yocto Metadata Layers**部分提供。

+   **支持的板支持包（BSPs）**：有许多 BSP 层可供 Yocto Project 支持。每个 BSP 层的命名非常简单，`meta-<bsp-name>`，可以在[`git.yoctoproject.org/cgit.cgi`](http://git.yoctoproject.org/cgit.cgi)的**Yocto Metadata Layers**部分找到。实际上，每个 BSP 层都是一组定义 BSP 提供者行为和最低要求的配方集合。有关 BSP 开发的更多信息可以在[`www.yoctoproject.org/docs/1.7/dev-manual/dev-manual.html#developing-a-board-support-package-bsp`](http://www.yoctoproject.org/docs/1.7/dev-manual/dev-manual.html#developing-a-board-support-package-bsp)找到。

+   **Eclipse Yocto 插件**：对于有兴趣编写应用程序的开发人员，Yocto 专用插件的 Eclipse**集成开发环境**（**IDE**）可用。您可以在[`www.yoctoproject.org/docs/1.7/dev-manual/dev-manual.html#setting-up-the-eclipse-ide`](http://www.yoctoproject.org/docs/1.7/dev-manual/dev-manual.html#setting-up-the-eclipse-ide)找到更多信息。

Yocto Project 内的开发过程有许多含义。它可以指的是 Yocto Project Bugzilla 中可用的各种错误和功能。开发人员可以将其中之一分配给自己的帐户并解决它。各种配方可以升级，这也需要开发人员的参与；还可以添加新功能，并且需要开发人员编写各种配方。所有这些任务都需要有一个明确定义的流程，其中也涉及`git`的交互。

要将配方中添加的更改发送回社区，可以使用可用的 create-pull-request 和 send-pull request 脚本。这些脚本位于 poky 存储库的 scripts 目录中。此外，在本节中还有一些其他有趣的脚本可用，如`create-recipe`脚本等，我会让你自己去发现。将更改发送到上游的另一种首选方法是使用手动方法，其中涉及与`git`命令的交互，如`git add`、`git commit –s`、`git format-patch`、`git send-email`等。

在继续描述本章节中呈现的其他组件之前，将对现有的 Yocto Project 开发模型进行审查。这个过程涉及 Yocto Project 提供的这些工具：

+   **系统开发**：这涵盖了 BSP 的开发、内核开发及其配置。Yocto Project 文档中有关于各自开发过程的部分，如[`www.yoctoproject.org/docs/1.7/bsp-guide/bsp-guide.html#creating-a-new-bsp-layer-using-the-yocto-bsp-script`](http://www.yoctoproject.org/docs/1.7/bsp-guide/bsp-guide.html#creating-a-new-bsp-layer-using-the-yocto-bsp-script)和[`www.yoctoproject.org/docs/1.7/kernel-dev/kernel-dev.html`](http://www.yoctoproject.org/docs/1.7/kernel-dev/kernel-dev.html)。

+   **用户应用程序开发**：这涵盖了针对目标硬件设备开发应用程序。有关在主机系统上进行应用程序开发所需设置的信息可在[`www.yoctoproject.org/docs/1.7/adt-manual/adt-manual.html`](http://www.yoctoproject.org/docs/1.7/adt-manual/adt-manual.html)找到。本章节还将讨论*Eclipse ADT 插件*部分。

+   **临时修改源代码**：这涵盖了开发过程中出现的临时修改。这涉及解决项目源代码中可用的各种实现问题的解决方案。问题解决后，更改需要上游可用并相应应用。

+   **Hob 镜像的开发**：Hob 构建系统可用于操作和定制系统镜像。它是一个用 Python 开发的图形界面，作为与 Bitbake 构建系统更高效的接口。

+   **Devshell 开发**：这是一种使用 Bitbake 构建系统任务的确切环境进行开发的方法。这是用于调试或包编辑的最有效方法之一。在编写项目的各个组件时，这也是设置构建环境的最快方法之一。

对于提供的组件过时无法满足 Yocto 项目要求的操作系统，建议使用`buildtools`工具链来提供所需版本的软件。用于安装`buildtools` tarball 的方法有两种。第一种方法涉及使用已经可用的预构建 tarball，第二种方法涉及使用 Bitbake 构建系统进行构建。有关此选项的更多信息可以在 Yocto 文档超级手册的**Required Git, tar, and Python Versions**部分的子部分中找到，网址为[`www.yoctoproject.org/docs/1.7/mega-manual/mega-manual.html#required-git-tar-and-python-versions`](http://www.yoctoproject.org/docs/1.7/mega-manual/mega-manual.html#required-git-tar-and-python-versions)。

# Eclipse ADT 插件

**应用程序开发工具包**，也称为 ADT，提供了一个适用于自定义构建和用户定制应用程序的交叉开发平台。它由以下元素组成：

+   **交叉工具链**：它与`sysroot`相关联，两者都是使用 Bitbake 自动生成的，并且目标特定的元数据由目标硬件供应商提供。

+   **快速仿真器环境（Qemu）**：用于模拟目标硬件。

+   **用户空间工具**：它改善了应用程序开发的整体体验

+   **Eclipse IDE**：它包含 Yocto 项目特定的插件

在本节中，将讨论前述每个元素，我们将从交叉开发工具链开始。它由用于目标应用程序开发的交叉链接器、交叉调试器和交叉编译器组成。它还需要相关的目标`sysroot`，因为在构建将在目标设备上运行的应用程序时需要必要的头文件和库。生成的`sysroot`是从生成`root`文件系统的相同配置中获得的；这指的是*image*配方。

工具链可以使用多种方法生成。最常见的方法是从[`downloads.yoctoproject.org/releases/yocto/yocto-1.7/toolchain/`](http://downloads.yoctoproject.org/releases/yocto/yocto-1.7/toolchain/)下载工具链，并获取适合您的主机和目标的适当工具链安装程序。一个例子是`poky-glibc-x86_64-core-image-sato-armv7a-vfp-neon-toolchain-1.7.sh`脚本，当执行时将在默认位置`/opt/poky/1.7/`目录中安装工具链。如果在执行脚本之前提供适当的参数，则可以更改此位置。

当生成工具链时，我更喜欢使用 Bitbake 构建系统。在这里，我指的是`meta-ide-support`。运行`bitbake meta-ide-support`时，会生成交叉工具链并填充构建目录。完成此任务后，将获得与先前提到的解决方案相同的结果，但在这种情况下，将使用已经可用的构建目录。对于这两种解决方案，唯一剩下的任务是使用包含`environment-setup`字符串的脚本设置环境并开始使用它。

Qemu 仿真器提供了在目标设备不可用时模拟一个硬件设备的可能性。在开发过程中，有多种方法可以使其可用：

+   使用 adt-installer 生成的脚本安装 ADT。在这个脚本中的一个可用步骤提供了在开发过程中启用或禁用 Qemu 的可能性。

+   Yocto 项目发布版被下载并在开发过程中默认设置环境。然后，Qemu 被安装并可供使用。

+   创建 Poky 存储库的`git`克隆并设置环境。在这种情况下，Qemu 也被安装并可供使用。

+   `cross-toolchain` tarball 被下载、安装并设置环境。这也默认启用了 Qemu 并安装了它以供以后使用。

用户空间工具包含在发行版中，并在开发过程中使用。它们在 Linux 平台上非常常见，可以包括以下内容：

+   **Perf**：它是一个 Linux 性能计数器，用于测量特定的硬件和软件事件。有关它的更多信息可在[`perf.wiki.kernel.org/`](https://perf.wiki.kernel.org/)找到，也可以在 Yocto 的性能和跟踪手册中找到一个专门的章节。

+   **PowerTop**：这是一个用于确定软件消耗的功率量的功率测量工具。有关它的更多信息可在[`01.org/powertop/`](https://01.org/powertop/)找到。

+   **LatencyTop**：这是一个类似于 PowerTop 的工具，不同之处在于它专注于从桌面音频跳跃和卡顿到服务器超载的延迟测量；它对这些情景进行测量并提供了延迟问题的解决方案。尽管自 2009 年以来似乎没有在这个项目中进行过提交，但由于它非常有用，至今仍在使用。

+   **OProfile**：它代表 Linux 生态系统的系统范围分析器，开销很低。有关它的更多信息可在[`oprofile.sourceforge.net/about/`](http://oprofile.sourceforge.net/about/)找到。在 Yocto 的性能和跟踪手册中也有一个章节可供参考。

+   **SystemTap**：它提供了关于运行中的 Linux 系统基础设施以及系统性能和功能问题的信息。但它并不作为 Eclipse 扩展，而是作为 Linux 发行版中的一个工具。关于它的更多信息可以在[`sourceware.org/systemtap`](http://sourceware.org/systemtap)找到。在 Yocto 的性能和跟踪手册中也有一个章节定义了它。

+   **Lttng-ust**：它是`lttng`项目的用户空间跟踪器，提供与用户空间活动相关的信息。更多信息可在[`lttng.org/`](http://lttng.org/)找到。

ADT 平台的最后一个元素是 Eclipse IDE。实际上，它是最受欢迎的开发环境，并为 Yocto 项目的开发提供全面支持。通过将 Yocto 项目 Eclipse 插件安装到 Eclipse IDE 中，Yocto 项目的体验就完整了。这些插件提供了跨编译、开发、部署和在 Qemu 模拟环境中执行生成的二进制文件的可能性。还可以进行诸如交叉调试、跟踪、远程性能分析和功耗数据收集等活动。有关与使用 Yocto 项目的 Eclipse 插件相关的活动的更多信息，请参阅[`www.yoctoproject.org/docs/1.7/mega-manual/mega-manual.html#adt-eclipse`](http://www.yoctoproject.org/docs/1.7/mega-manual/mega-manual.html#adt-eclipse)。

为了更好地理解 ADT 工具包平台和 Eclipse 应用开发的工作流程，整个过程的概述在下图中可见：

![Eclipse ADT 插件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00325.jpeg)

应用程序开发过程也可以使用与已经介绍的不同的其他工具。然而，所有这些选项都涉及使用 Yocto 项目组件，尤其是 Poby 参考系统。因此，ADT 是开源社区建议、测试和推荐的选项。

# Hob 和 Toaster

项目—**Hob**—代表了 Bitbake 构建系统的图形用户界面。它的目的是简化与 Yocto 项目的交互，并为项目创建一个更简单的学习曲线，使用户能够以更简单的方式执行日常任务。它的主要重点是生成 Linux 操作系统镜像。随着时间的推移，它发展起来，现在可以被认为是一个适合有经验和无经验用户的工具。尽管我更喜欢使用命令行交互，但这个说法并不适用于所有 Yocto 项目的用户。

尽管在 Daisy 1.6 发布后 Hob 开发似乎停止了。开发活动在某种程度上转移到了新项目—**Toaster**—，这将很快解释；Hob 项目仍然在使用中，其功能应该被提及。因此，当前可用的 Hob 版本能够做到以下几点：

+   自定义可用的基础镜像配方

+   创建完全定制的镜像

+   构建任何给定的镜像

+   使用 Qemu 运行镜像

+   在 USB 磁盘上部署镜像，以便在目标上进行现场引导

Hob 项目可以以与执行 Bitbake 相同的方式启动。在环境源和构建目录创建后，可以调用`hob`命令，用户将看到图形界面。这个工具的缺点是它不能替代命令行交互。如果需要创建新的配方，那么这个工具将无法提供任何帮助。

下一个项目叫做 Toaster。它是一个应用程序编程接口，也是 Yocto 项目构建的一个 Web 界面。在当前状态下，它只能通过 Web 浏览器收集和呈现与构建过程相关的信息。以下是它的一些功能：

+   在构建过程中执行和重用任务的可见性

+   构建组件的可见性，如镜像的配方和软件包 - 这与 Hob 类似地完成

+   提供有关配方的信息，如依赖关系、许可证等

+   提供与性能相关的信息，如磁盘 I/O、CPU 使用率等

+   为了调试目的呈现错误、警告和跟踪报告

尽管看起来可能不多，这个项目承诺提供与 Hob 相同的构建和定制构建的可能性，以及许多其他好处。您可以在这个工具的[`wiki.yoctoproject.org/wiki/Toaster`](https://wiki.yoctoproject.org/wiki/Toaster)上找到有用的信息。

# 自动构建器

**自动构建器**是一个项目，它促进了构建测试自动化并进行质量保证。通过这个内部项目，Yocto 社区试图为嵌入式开发人员设定一条路径，使他们能够发布他们的 QA 测试和测试计划，开发新的自动测试工具、持续集成，并开发 QA 程序以展示和展示给所有相关方的利益。

这些点已经被一个使用 Autobuilder 平台发布其当前状态的项目所实现，该平台可在[`autobuilder.yoctoproject.org/`](http://autobuilder.yoctoproject.org/)上找到。这个链接对每个人都是可访问的，测试是针对与 Yocto 项目相关的所有更改进行的，以及所有支持的硬件平台的夜间构建。尽管起源于 Buildbot 项目，从中借用了持续集成的组件，这个项目承诺将继续前进，并提供执行运行时测试和其他必不可少的功能的可能性。

您可以在以下网址找到有关该项目的一些有用信息：[`wiki.yoctoproject.org/wiki/AutoBuilder`](https://wiki.yoctoproject.org/wiki/AutoBuilder) 和 [`wiki.yoctoproject.org/wiki/QA`](https://wiki.yoctoproject.org/wiki/QA)，该网址提供了每个发布版本的 QA 程序的访问权限，以及一些额外的信息。

# Lava

Lava 项目并不是 Yocto 项目的内部工作，而是由 Linaro 开发的项目，旨在测试设备上 Linux 系统的部署的自动化验证架构。尽管其主要关注点是 ARM 架构，但它是开源的，这并不是一个缺点。它的实际名称是**Linaro 自动化和验证架构**（**LAVA**）。

该项目提供了在硬件或虚拟平台上部署操作系统的可能性，定义测试，并在项目上执行测试。测试可以具有各种复杂性，它们可以组合成更大更具有决定性的测试，并且结果会随时间跟踪，之后导出结果数据进行分析。

这是一个不断发展的架构，允许测试执行以及自动化和质量控制。同时，它还为收集的数据提供验证。测试可以是从编译引导测试到对内核调度器的更改，可能会或可能不会降低功耗。

尽管它还很年轻，但这个项目已经吸引了相当多的关注，因此对该项目进行一些调查不会伤害任何人。

### 注意

LAVA 手册可在[`validation.linaro.org/static/docs/`](https://validation.linaro.org/static/docs/)找到。

# Wic

**Wic**更像是一个功能而不是一个项目本身。它是最不被记录的，如果搜索它，你可能找不到结果。我决定在这里提到它，因为在开发过程中可能会出现一些特殊要求，比如从可用软件包（如`.deb`、`.rpm`或`.ipk`）生成自定义的`root`文件系统。这项工作最适合 wic 工具。

这个工具试图解决设备或引导加载程序的一些特殊要求，比如特殊格式化或`root`文件系统的分区。它是一个高度定制的工具，可以扩展其功能。它是从另一个名为**oeic**的工具开发而来，该工具用于为硬件创建特定的专有格式化映像，并被导入到 Yocto 项目中，以为那些不想要触及配方或已经打包好的源代码的开发人员提供更广泛的目的，或者需要为其可交付的 Linux 映像进行特殊格式化。

不幸的是，这个工具没有提供文档，但我可以指导感兴趣的人到 Yocto 项目的位置。它位于 Poky 存储库中的 scripts 目录下的 wic 名称。Wic 可以像任何脚本一样使用，并提供一个帮助界面，您可以在那里寻找更多信息。此外，它的功能将在接下来的章节中进行更详细的介绍。

可以在[`www.yoctoproject.org/tools-resources/projects`](https://www.yoctoproject.org/tools-resources/projects)找到所有围绕 Yocto 项目开发的可用项目的列表。其中一些项目在本章的上下文中没有讨论，但我会让你自己去发现它们。还有其他未列入列表的外部项目。我鼓励你自己去了解和学习它们。

# 总结

在这一章中，你将看到下一章中将要讨论的元素。在接下来的章节中，之前提到的每个部分将在不同的章节中进行详细和更加应用的介绍。

在下一章中，前面提到的过程将从应用开发工具包平台开始。将解释设置平台所需的步骤，并向您介绍一些使用场景。这些涉及跨开发、使用 Qemu 进行调试以及特定工具之间的交互。


# 第七章：ADT Eclipse 插件

在本章中，您将看到 Yocto 项目中可用工具的新视角。本章标志着对 Yocto 项目生态系统中各种工具的介绍的开始，这些工具非常有用，并且与 Poky 参考系统不同。在本章中，将简要介绍**应用开发环境**（**ADE**）并强调 Eclipse 项目和 Yocto 项目的附加插件。展示了一些插件以及它们的配置和用例。

还将向您展示**应用开发工具包**（**ADT**）的更广泛视图。该项目的主要目标是提供一个能够开发、编译、运行、调试和分析软件应用程序的软件堆栈。它试图在不需要开发者额外学习的情况下实现这一点。它的学习曲线非常低，考虑到 Eclipse 是最常用的**集成开发环境**（**IDE**）之一，而且随着时间的推移，它变得非常用户友好、稳定和可靠。ADT 用户体验与任何使用 Eclipse 或非 Eclipse 用户在使用 Eclipse IDE 时的体验非常相似。可用的插件尝试使这种体验尽可能相似，以便开发类似于任何 Eclipse IDE。唯一的区别在于配置步骤，这定义了一个 Eclipse IDE 版本与另一个版本之间的区别。

ADT 提供了使用独立交叉编译器、调试工具分析器、仿真器甚至是以平台无关的方式与开发板交互的可能性。虽然与硬件交互是嵌入式开发人员的最佳选择，但在大多数情况下，由于各种原因，真实硬件是缺失的。对于这些情况，可以使用 QEMU 仿真器来模拟必要的硬件。

# 应用开发工具包

ADT 是 Yocto 项目的组成部分，提供了一个跨开发平台，非常适合用户特定的应用程序开发。为了使开发过程有序进行，需要一些组件：

+   Eclipse IDE Yocto 插件

+   用于特定硬件模拟的 QEMU 仿真器

+   与特定体系结构相关的交叉工具链以及其特定的`sysroot`，这两者都是使用 Yocto 项目提供的元数据和构建系统生成的

+   用户空间工具以增强开发人员在应用程序开发过程中的体验

当提供对 Eclipse IDE 的完全支持并最大化 Yocto 体验时，Eclipse 插件可用。最终结果是为 Yocto 开发人员的需求定制的环境，具有交叉工具链、在真实硬件上部署或 QEMU 仿真功能，以及一些用于收集数据、跟踪、分析和性能评估的工具。

QEMU 仿真器用于模拟各种硬件。可以通过以下方法获得它：

+   使用 ADT 安装程序脚本，提供安装的可能性

+   克隆一个 Poky 存储库并获取环境，可以访问 QEMU 环境

+   下载 Yocto 发布并获取环境，以获得相同的结果

+   安装交叉工具链并获取环境以使 QEMU 环境可用

工具链包含交叉调试器、交叉编译器和交叉链接器，在应用程序开发过程中被广泛使用。工具链还配备了用于目标设备的匹配 sysroot，因为它需要访问运行在目标架构上所需的各种头文件和库。sysroot 是从根文件系统生成的，并使用相同的元数据配置。

用户空间工具包括在前几章中已经提到的工具，如 SystemTap、PowerTop、LatencyTop、perf、OProfile 和 LTTng-UST。它们用于获取有关系统和开发应用程序的信息；例如功耗、桌面卡顿、事件计数、性能概述以及诊断软件、硬件或功能问题，甚至跟踪软件活动的信息。

## 设置环境

在进一步解释 ADT 项目、其 Eclipse IDE 插件、设置的其他功能之前，需要安装 Eclipse IDE。安装 Eclipse IDE 的第一步涉及设置主机系统。有多种方法可以做到这一点：

+   **使用 ADT 安装脚本**：这是安装 ADT 的推荐方法，主要是因为安装过程是完全自动化的。用户可以控制他们想要的功能。

+   **使用 ADT tarball**：这种方法涉及使用特定架构工具链的适当 tarball 部分，并使用脚本进行设置。该 tarball 可以通过下载和使用 Bitbake 手动构建。由于安装后并非所有功能都可用，此方法也存在限制，除了交叉工具链和 QEMU 模拟器之外。

+   **使用构建目录中的工具链**：这种方法利用了构建目录已经可用的事实，因此交叉工具链的设置非常容易。此外，在这种情况下，它面临与前一点提到的相同的限制。

ADT 安装脚本是安装 ADT 的首选方法。当然，在进行安装步骤之前，需要确保必要的依赖项可用，以确保 ADT 安装脚本顺利运行。

这些软件包已经在前几章中提到过，但在这里将再次解释，以便为您简化事情。我建议您回到这些章节，再次查阅信息作为记忆练习。要查看可能对您感兴趣的软件包，请查看 ADT Installer 软件包，例如`autoconf automake libtool libglib2.0-dev`，Eclipse 插件以及`libsdl1.2-dev xterm`软件包提供的图形支持。

主机系统准备好所有所需的依赖项后，可以从[`downloads.yoctoproject.org/releases/yocto/yocto-1.7/adt-installer/`](http://downloads.yoctoproject.org/releases/yocto/yocto-1.7/adt-installer/)下载 ADT tarball。在这个位置，`adt_installer.tar.bz2`存档可用。需要下载并提取其内容。

这个 tarball 也可以在构建目录中使用 Bitbake 构建系统生成，并且结果将在`tmp/deploy/sdk/adt_installer.tar.bz2`位置可用。要生成它，需要在构建目录中输入下一个命令，即`bitbake adt-installer`。构建目录还需要为目标设备正确配置。

存档使用`tar -xjf adt_installer.tar.bz2`命令解压缩。它可以在任何目录中提取，并在解压缩`adt-installer`目录后，创建并包含名为`adt_installer`的 ADT 安装程序脚本。它还有一个名为`adt_installer.conf`的配置文件，用于在运行脚本之前定义配置。配置文件定义了诸如文件系统、内核、QEMU 支持等信息。

这些是配置文件包含的变量：

+   `YOCTOADT_REPO`：这定义了安装所依赖的软件包和根文件系统。其参考值在[`adtrepo.yoctoproject.org//1.7`](http://adtrepo.yoctoproject.org//1.7)中定义。在这里，定义了目录结构，其结构在发布之间是相同的。

+   `YOCTOADT_TARGETS`：这定义了为其设置交叉开发环境的目标架构。有一些默认值可以与此变量关联，如`arm`，`ppc`，`mips`，`x86`和`x86_64`。也可以关联多个值，并使用空格分隔它们。

+   `YOCTOADT_QEMU`：此变量定义了 QEMU 模拟器的使用。如果设置为`Y`，则安装后将可用模拟器；否则，值设置为`N`，因此模拟器将不可用。

+   `YOCTOADT_NFS_UTIL`：这定义了将安装的 NFS 用户模式。可用的值如前所述为`Y`和`N`。为了使用 Eclipse IDE 插件，必须为`YOCTOADT_QEMU`和`YOCTOADT_NFS_UTIL`同时定义`Y`值。

+   `YOCTOADT_ROOTFS_<arch>`：这指定了要从第一个提到的`YOCTOADT_REPO`变量中定义的存储库中使用哪个架构的根文件系统。对于`arch`变量，默认值是`YOCTOADT_TARGETS`变量中已经提到的值。该变量的有效值由可用的镜像文件表示，如`minimal`，`sato`，`minimal-dev`，`sato-sdk`，`lsb`，`lsb-sdk`等。对于该变量的多个参数，可以使用空格分隔符。

+   `YOCTOADT_TARGET_SYSROOT_IMAGE_<arch>`：这代表了交叉开发工具链的`sysroot`将从中生成的根文件系统。`arch`变量的有效值与之前提到的相同。它的值取决于之前为`YOCTOADT_ROOTFS_<arch>`变量定义的值。因此，如果只有一个变量被定义为`YOCTOADT_ROOTFS_<arch>`变量的值，那么相同的值将可用于`YOCTOADT_TARGET_SYSROOT_IMAGE_<arch>`。此外，如果在`YOCTOADT_ROOTFS_<arch>`变量中定义了多个变量，则其中一个需要定义`YOCTOADT_TARGET_SYSROOT_IMAGE_<arch>`变量。

+   `YOCTOADT_TARGET_MACHINE_<arch>`：这定义了下载镜像的目标机器，因为相同架构的机器之间可能存在编译选项的差异。该变量的有效值可以是：`qemuarm`，`qemuppc`，`ppc1022ds`，`edgerouter`，`beaglebone`等。

+   `YOCTOADT_TARGET_SYSROOT_LOC_<arch>`：这定义了安装过程结束后目标`sysroot`将可用的位置。

配置文件中还定义了一些变量，如`YOCTOADT_BITBAKE`和`YOCTOADT_METADATA`，这些变量是为了未来的工作参考而定义的。开发人员根据需要定义所有变量后，安装过程就可以开始了。这是通过运行`adt_installer`脚本来完成的：

```
cd adt-installer
./adt_installer

```

以下是`adt_installer.conf`文件的示例：

```
# Yocto ADT Installer Configuration File
#
# Copyright 2010-2011 by Intel Corp.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal 
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
# copies of the Software, and to permit persons to whom the Software is 
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
# THE SOFTWARE.

# Your yocto distro repository, this should include IPKG based packages and root filesystem files where the installation is based on

YOCTOADT_REPO="http://adtrepo.yoctoproject.org//1.7"
YOCTOADT_TARGETS="arm x86"
YOCTOADT_QEMU="Y"
YOCTOADT_NFS_UTIL="Y"

#YOCTOADT_BITBAKE="Y"
#YOCTOADT_METADATA="Y"

YOCTOADT_ROOTFS_arm="minimal sato-sdk"
YOCTOADT_TARGET_SYSROOT_IMAGE_arm="sato-sdk"
YOCTOADT_TARGET_MACHINE_arm="qemuarm"
YOCTOADT_TARGET_SYSROOT_LOC_arm="$HOME/test-yocto/$YOCTOADT_TARGET_MACHINE_arm"

#Here's a template for setting up target arch of x86 
YOCTOADT_ROOTFS_x86="sato-sdk"
YOCTOADT_TARGET_SYSROOT_IMAGE_x86="sato-sdk"
YOCTOADT_TARGET_MACHINE_x86="qemux86"
YOCTOADT_TARGET_SYSROOT_LOC_x86="$HOME/test-yocto/$YOCTOADT_TARGET_MACHINE_x86"

#Here's some template of other arches, which you need to change the value in ""
YOCTOADT_ROOTFS_x86_64="sato-sdk"
YOCTOADT_TARGET_SYSROOT_IMAGE_x86_64="sato-sdk"
YOCTOADT_TARGET_MACHINE_x86_64="qemux86-64"
YOCTOADT_TARGET_SYSROOT_LOC_x86_64="$HOME/test-yocto/$YOCTOADT_TARGET_MACHINE_x86_64"

YOCTOADT_ROOTFS_ppc="sato-sdk"
YOCTOADT_TARGET_SYSROOT_IMAGE_ppc="sato-sdk"
YOCTOADT_TARGET_MACHINE_ppc="qemuppc"
YOCTOADT_TARGET_SYSROOT_LOC_ppc="$HOME/test-yocto/$YOCTOADT_TARGET_MACHINE_ppc"

YOCTOADT_ROOTFS_mips="sato-sdk"
YOCTOADT_TARGET_SYSROOT_IMAGE_mips="sato-sdk"
YOCTOADT_TARGET_MACHINE_mips="qemumips"
YOCTOADT_TARGET_SYSROOT_LOC_mips="$HOME/test-yocto/$YOCTOADT_TARGET_MACHINE_mips"

```

安装开始后，用户会被询问交叉工具链的位置。如果没有提供替代方案，则选择默认路径，并将交叉工具链安装在`/opt/poky/<release>`目录中。安装过程可以以静默或交互方式可视化。通过使用`I`选项，可以以交互模式进行安装，而使用`S`选项可以启用静默模式。

安装过程结束时，交叉工具链将在其定义的位置找到。环境设置脚本将可供以后使用，并且镜像 tarball 位于`adt-installer`目录中，`sysroot`目录位于`YOCTOADT_TARGET_SYSROOT_LOC_<arch>`变量的位置。

如前所示，准备 ADT 环境有不止一种方法。第二种方法只涉及安装工具链安装程序，尽管它提供了预构建的交叉工具链、支持文件和脚本的可能性，比如`runqemu`脚本，可以在仿真器中启动类似于内核或 Linux 镜像的东西，但这不提供与第一种选择相同的可能性。此外，这个选项在`sysroot`目录方面有其局限性。尽管已经生成了`sysroot`目录，但可能仍需要将其提取并安装到单独的位置。这可能是由于各种原因，比如需要通过 NFS 引导根文件系统或者使用根文件系统作为目标`sysroot`开发应用程序。

根文件系统可以从已经生成的交叉工具链中提取出来，使用`runqemu-extract-sdk`脚本，这个脚本应该在使用 source 命令设置好交叉开发环境脚本之后才能调用。

有两种方法可以获得为第二个选项安装的工具链。第一种方法涉及使用[`downloads.yoctoproject.org/releases/yocto/yocto-1.7/toolchain/`](http://downloads.yoctoproject.org/releases/yocto/yocto-1.7/toolchain/)上可用的工具链安装程序。打开与您的开发主机机器匹配的文件夹。在此文件夹中，有多个安装脚本可用。每个脚本都与目标架构匹配，因此应为您拥有的目标选择正确的脚本。一个这样的例子可以从[`downloads.yoctoproject.org/releases/yocto/yocto-1.7/toolchain/x86_64/poky-glibc-x86_64-core-image-sato-armv7a-vfp-neon-toolchain-1.7.sh`](http://downloads.yoctoproject.org/releases/yocto/yocto-1.7/toolchain/x86_64/poky-glibc-x86_64-core-image-sato-armv7a-vfp-neon-toolchain-1.7.sh)中看到，实际上是`armv7a`目标和`x86_64`主机机器的安装程序脚本。

如果您的目标机器不是 Yocto 社区提供的机器之一，或者您更喜欢这种方法的替代方法，那么构建工具链安装程序脚本就是适合您的方法。在这种情况下，您将需要一个构建目录，并且将呈现两种同样好的选择：

+   第一种方法涉及使用`bitbake meta-toolchain`命令，最终结果是一个安装程序脚本，需要在单独的位置安装和设置交叉工具链。

+   第二种选择涉及使用`bitbake –c populate_sdk <image-name>`任务，该任务提供了工具链安装程序脚本和与目标匹配的`sysroot`。这里的优势在于二进制文件只与一个`libc`链接，使得工具链是自包含的。当然，每个架构只能创建一个特定的构建，但是目标特定的选项通过`gcc`选项传递。使用变量，如`CC`或`LD`，使得这个过程更容易维护，并且还节省了构建目录中的一些空间。

安装程序下载完成后，确保安装脚本已经正确设置执行权限，并使用`./poky-glibc-x86_64-core-image-sato-armv7a-vfp-neon-toolchain-1.7.sh`命令开始安装。

您需要的一些信息包括安装的位置，默认位置是`/opt/poky/1.7`目录。为了避免这一点，可以使用`–d <install-location>`参数调用脚本，并将安装位置设置为`<install-location>`，如上所述。

### 注意

确保`local.conf`文件中`MACHINE`变量设置正确。此外，如果为不同的主机机器进行构建，则还应设置`SDKMACHINE`。在同一个构建目录中可以生成多个`MACHINE`交叉工具链，但是这些变量需要正确配置。

安装过程完成后，交叉工具链将在所选位置可用，并且在需要时还将可用于源的环境脚本。

第三个选项涉及使用构建目录和执行`bitbake meta-ide-support`命令。在构建目录中，需要使用两个可用的构建环境设置脚本之一来设置适当的环境，其中包括`oe-init-build-env`脚本或`oe-init-build-env-memres`脚本。还需要根据目标架构相应地设置`local.conf`文件中的本地配置。开发人员完成这些步骤后，可以使用`bitbake meta-ide-support`命令开始生成交叉工具链。在过程结束时，将在`<build-dir-path>/tmp`目录中提供一个环境设置脚本，但在这种情况下，工具链紧密地链接到构建目录中。

环境设置完成后，可以开始编写应用程序，但开发人员仍然需要在完成活动之前完成一些步骤，例如在真实的根文件系统上测试应用程序、调试等。对于内核模块和驱动程序的实现，将需要内核源代码，因此活动刚刚开始。

# Eclipse IDE

Yocto 项目为 Eclipse 提供的插件包括 ADT 项目和工具链的功能。它们允许开发人员使用交叉编译器、调试器和 Yocto 项目、Poky 和其他元层生成的所有可用工具。这些组件不仅可以在 Eclipse IDE 中使用，而且还为应用程序开发提供了熟悉的环境。

Eclipse IDE 是开发人员的另一种选择，他们不想与编辑器进行交互，比如`vim`，尽管在我看来，`vim`可以用于各种项目。即使它们的尺寸或复杂性不是问题，使用`vim`的开销可能并不适合所有口味。Eclipse IDE 是所有开发人员可用的最佳选择。它具有许多有用的功能和功能，可以让您的生活变得更轻松，而且很容易掌握。

Yocto 项目支持 Eclipse 的两个版本，Kepler 和 Juno。 Kepler 版本是最新 Poky 版本推荐的版本。我还建议使用 Eclipse 的 Kepler 4.3.2 版本，这是从 Eclipse 官方下载站点[`www.eclipse.org/downloads`](http://www.eclipse.org/downloads)下载的版本。

从这个网站上，应该下载包含**Java 开发工具**（**JDT**）、Eclipse 平台和主机机器的开发环境插件的 Eclipse 标准 4.3.2 版本。下载完成后，应使用 tar 命令提取接收到的存档内容：

```
tar xzf eclipse-standard-kepler-SR2-linux-gtk-x86_64.tar.gzls

```

接下来的步骤是配置。在提取内容后，需要在安装 Yocto 项目特定插件之前配置 Eclipse IDE。配置从初始化 Eclipse IDE 开始：

执行`./eclipse`可执行文件并设置`Workspace`位置后，将启动 Eclipse IDE。这是启动窗口的外观：

![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00326.jpeg)

Eclipse 窗口

要初始化 Eclipse IDE，请执行以下步骤：

1.  选择**工作台**，您将进入空的工作台，可以在其中编写项目源代码。

1.  现在，通过**帮助**菜单导航并选择**安装新软件**。![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00327.jpeg)

帮助菜单

1.  将打开一个新窗口，在**使用：**下拉菜单中，选择**Kepler - http://download.eclipse.org/releases/kepler**，如下图所示：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00328.jpeg)

安装窗口

1.  展开**Linux 工具**部分，并选择**LTTng – Linux 跟踪工具包**框，如下截图所示：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00329.jpeg)

安装—LTTng – Linux 跟踪工具包框

1.  展开**移动和设备开发**部分，并选择以下内容：

+   **C/C++远程启动（需要 RSE 远程系统资源管理器）**

+   远程系统资源管理器终端用户运行时

+   远程系统资源管理器用户操作

+   目标管理终端

+   **TCF 远程系统资源管理器插件**

+   TCF 目标资源管理器

![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00330.jpeg)

1.  展开**编程语言**部分，并选择以下内容：

+   C/C++ Autotools 支持

+   C/C++开发工具

如下截图所示：

![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00331.jpeg)

可用软件列表窗口

1.  在快速查看**安装详细信息**菜单并启用许可协议后完成安装：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00332.jpeg)

安装详细信息窗口

完成这些步骤后，可以将 Yocto 项目 Eclipse 插件安装到 IDE 中，但在重新启动 Eclipse IDE 之前，不能确保前述更改生效。配置阶段结束后的结果在此可见：

![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00333.jpeg)

Eclipse—配置阶段结果

要安装 Yocto 项目的 Eclipse 插件，需要执行以下步骤：

1.  按照前面提到的方法启动 Eclipse IDE。

1.  如前面的配置所示，从**帮助**菜单中选择**安装新软件**选项。

1.  单击**添加**按钮，并在 URL 部分插入`downloads.yoctoproject.org/releases/eclipse-plugin/1.7/kepler/`。根据此处的指示为新的**Work with:**站点命名：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00334.jpeg)

编辑站点窗口

1.  按下**OK**按钮并更新**Work with**站点后，会出现新的框。选择所有这些框，如此图所示，并单击**下一步**按钮：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00335.jpeg)

安装详细信息窗口

1.  最后一次查看已安装的组件，安装即将结束。![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00336.jpeg)

安装详细信息窗口

1.  如果出现此警告消息，请按**确定**并继续。它只是让您知道已安装的软件包具有未签名的内容。![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00337.jpeg)

安全警告窗口

只有在重新启动 Eclipse IDE 后更改才会生效，安装才算完成。

安装完成后，Yocto 插件可用并准备好进行配置。配置过程涉及设置特定于目标的选项和交叉编译器。对于每个特定的目标，需要相应地执行前述配置步骤。

通过从**窗口**菜单中选择**首选项**选项来完成配置过程。将打开一个新窗口，从中应选择**Yocto 项目 ADT**选项。更多细节可参见以下截图：

![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00338.jpeg)

Eclipse IDE—首选项

接下来要做的事情涉及配置交叉编译器的可用选项。第一个选项是工具链类型，有两个选项可用，**独立预构建工具链**和**构建系统派生工具链**，默认选择后者。前者是指特定于已有现有内核和根文件系统的架构的工具链，因此开发的应用程序将手动在镜像中提供。但是，由于所有组件都是分开的，这一步并不是必需的。后者是指在 Yocto 项目构建目录中构建的工具链。

需要配置的下一个元素是工具链位置、`sysroot`位置和目标架构。**工具链根位置**用于定义工具链安装位置。例如，使用`adt_installer`脚本安装时，工具链将位于`/opt/poky/<release>`目录中。第二个参数**Sysroot 位置**表示目标设备根文件系统的位置。它可以在`/opt/poky/<release>`目录中找到，如前面的示例所示，或者如果使用其他方法生成它，则甚至可以在构建目录中找到。这一部分的第三个和最后一个选项由**目标架构**表示，它表示所使用或模拟的硬件类型。正如在窗口中所看到的，它是一个下拉菜单，用户可以选择所需的选项，并找到所有支持的架构列表。在所需架构在下拉菜单中不可用的情况下，将需要构建相应的架构镜像。

最后剩下的部分是目标特定选项。这指的是使用 QEMU 模拟架构或在外部可用的硬件上运行镜像的可能性。对于外部硬件，请使用需要选择的**外部硬件**选项以完成工作，但对于 QEMU 模拟，除了选择**QEMU**选项外，还有其他事情要做。在这种情况下，用户还需要指定**内核**和**自定义选项**。对于内核选择，过程很简单。如果选择了**独立预构建工具链**选项，它将位于预构建镜像位置，或者如果选择了**构建系统派生工具链**选项，则将位于`tmp/deploy/images/<machine-name>`目录中。对于第二个选项**自定义选项**参数，添加它的过程不会像前面的选项那样简单。

**自定义选项**字段需要填写各种选项，例如`kvm`、nographic、`publicvnc`或`serial`，它们表示模拟架构或其参数的主要选项。这些选项被保存在尖括号内，并包括参数，例如使用的内存（`-m 256`）、网络支持（`-net`）和全屏支持（`-full-screen`）。有关可用选项和参数的更多信息可以使用`man qemu`命令找到。在定义项目后，可以使用**更改 Yocto 项目设置**选项从**项目**菜单中覆盖所有前述配置。

要定义一个项目，需要执行以下步骤：

1.  从**文件** | **新建**菜单选项中选择**项目…**选项，如下所示：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00339.jpeg)

Eclipse IDE—项目

1.  从**C/C++**选项中选择**C 项目**。这将打开一个**C 项目**窗口：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00340.jpeg)

Eclipse IDE—新项目窗口

1.  在**C 项目**窗口中，有多个选项可用。让我们选择**Yocto 项目 ADT Autotools 项目**，然后选择**Hello World ANSI C Autotools 项目**选项。为新项目添加名称，我们准备进行下一步：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00341.jpeg)

C 项目窗口

1.  在**C 项目**窗口中，您将被提示相应地添加**作者**、**版权声明**、**Hello world 问候**、**源**和**许可**字段的信息：![Eclipse IDE](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00342.jpeg)

C 项目—基本设置窗口

1.  添加所有信息后，可以单击**完成**按钮。用户将在新的特定于**C/C++**的透视图中得到提示，该透视图特定于打开的项目，并且新创建的项目将出现在菜单的左侧。 

1.  创建项目并编写源代码后，要构建项目，请从**项目…**菜单中选择**构建项目**选项。

## QEMU 模拟器

QEMU 在 Yocto 项目中作为各种目标架构的虚拟化机器和仿真器使用。它非常有用，可以运行和测试各种 Yocto 生成的应用程序和映像，除了完成其他目的。在 Yocto 世界之外，它的主要用途也是 Yocto 项目的卖点，使其成为默认工具来模拟硬件。

### 注意

有关 QEMU 用例的更多信息，请访问[`www.yoctoproject.org/docs/1.7/adt-manual/adt-manual.html#the-qemu-emulator`](http://www.yoctoproject.org/docs/1.7/adt-manual/adt-manual.html#the-qemu-emulator)。

与 QEMU 仿真的交互是在 Eclipse 中完成的，如前所示。为此发生，需要适当的配置，如在前一节中所述。在这里启动 QEMU 仿真是使用“运行”菜单中的“外部工具”选项完成的。将为仿真器打开一个新窗口，并在传递相应的登录信息到提示后，shell 将可供用户交互。应用程序也可以在仿真器上部署和调试。

### 注意

有关 QEMU 交互的更多信息，请访问[`www.yoctoproject.org/docs/1.7/dev-manual/dev-manual.html#dev-manual-qemu`](http://www.yoctoproject.org/docs/1.7/dev-manual/dev-manual.html#dev-manual-qemu)。

## 调试

如果存在，还可以使用 QEMU 仿真器或实际目标硬件来调试应用程序。当项目配置时，将生成一个**C/C+远程应用程序**实例的运行/调试 Eclipse 配置，并且可以根据其名称找到，该名称符合`<project-name>_gdb_-<suffix>`的语法。例如，`TestProject_gdb_armv5te-poky-linux-gnueabi`可能是一个例子。

要连接到 Eclipse GDB 界面并启动远程目标调试过程，用户需要执行一些步骤：

1.  从“运行”|“调试配置”菜单中选择“C/C++远程应用程序”，并从左侧面板中的“C/C++远程应用程序”中选择运行/调试配置。

1.  从下拉列表中选择适当的连接。

1.  选择要部署的二进制应用程序。如果项目中有多个可执行文件，在按下“搜索项目”按钮后，Eclipse 将解析项目并提供所有可用二进制文件的列表。

1.  通过相应地设置“C/C++应用程序的远程绝对文件路径：”字段，输入应用程序将部署的绝对路径。

1.  在“调试器”选项卡中可以选择调试器选项。要调试共享库，需要进行一些额外的步骤：

+   从“源”选项卡中选择“添加”|“路径映射”选项，以确保调试配置中有路径映射可用。

+   从“调试/共享库”选项卡中选择“自动加载共享库符号”，并相应地指示共享库的路径。这个路径高度依赖于处理器的架构，所以非常小心地指定库文件。通常，对于 32 位架构，选择`lib`目录，对于 64 位架构，选择`lib64`目录。

+   在“参数”选项卡上，有可能在执行时向应用程序二进制文件传递各种参数。

1.  完成所有调试配置后，单击“应用”和“调试”按钮。将启动一个新的 GDB 会话，并打开“调试透视”。当调试器正在初始化时，Eclipse 将打开三个控制台：

+   一个名为之前描述的 GDB 二进制文件的 GDB 控制台，用于命令行交互

+   用于运行应用程序显示结果的远程 shell

+   一个名为二进制路径的本地机器控制台，在大多数情况下，不会被使用。它仍然是一个工件。

1.  在调试配置设置完成后，可以使用工具栏中的**调试**图标重新构建和执行应用程序。实际上，如果您只想运行和部署应用程序，可以使用**运行**图标。

## 性能分析和跟踪

在**Yocto 工具**菜单中，您可以看到用于跟踪和分析开发应用程序的支持工具。这些工具用于增强应用程序的各种属性，总的来说，是为了提高开发过程和体验。将介绍的工具包括 LTTng、Perf、LatencyTop、PerfTop、SystemTap 和 KGDB。

我们首先要看的是 LTTng Eclipse 插件，它提供了跟踪目标会话和分析结果的可能性。要开始使用该工具，首先需要进行快速配置，如下所示：

1.  从**窗口**菜单中选择**打开透视图**来开始跟踪透视图。

1.  从**文件** | **新建**菜单中选择**项目**来创建一个新的跟踪项目。

1.  从**窗口** | **显示视图** | **其他...** | **Lttng**菜单中选择**控制视图**。这将使您能够访问所有这些所需的操作：

+   创建一个新的连接

+   创建一个会话

+   开始/停止跟踪

+   启用事件

接下来，我们将介绍一个名为**Perf**的用户空间性能分析工具。它为多个线程和内核提供应用程序代码的统计分析和简单的 CPU 分析。为了做到这一点，它使用了许多性能计数器、动态探针或跟踪点。要使用 Eclipse 插件，需要远程连接到目标。可以通过 Perf 向导或使用**文件** | **新建** | **其他**菜单中的**远程系统资源管理器** | **连接**选项来完成。远程连接设置完成后，与该工具的交互与该工具的命令行支持相同。

**LatencyTop**是一个用于识别内核中可用延迟及其根本原因的应用程序。由于 ARM 内核的限制，此工具不适用于启用了**对称多处理**（**SMP**）支持的 ARM 内核。此应用程序还需要远程连接。远程连接设置完成后，与该工具的命令行支持相同。此应用程序是使用`sudo`从 Eclipse 插件运行的。

**PowerTop**用于测量电力消耗。它分析在 Linux 系统上运行的应用程序、内核选项和设备驱动程序，并估计它们的功耗。它非常有用，可以识别使用最多功率的组件。此应用程序需要远程连接。远程连接设置完成后，与该工具的命令行支持相同。此应用程序是使用-Eclipse 插件运行的，使用-d 选项在 Eclipse 窗口中显示输出。

**SystemTap**是一种工具，它可以使用脚本从运行中的 Linux 系统中获取结果。SystemTap 提供了一个自由软件（GPL）基础设施，用于简化通过跟踪所有内核调用来收集有关运行中 Linux 系统的信息。它与 Solaris 的 dtrace 非常相似，但与 dtrace 不同的是，它仍然不适用于生产系统。它使用类似于`awk`的语言，其脚本具有`.stp`扩展名。监视的数据可以被提取，并且可以对其进行各种过滤和复杂处理。Eclipse 插件使用`crosstap`脚本将`.stp`脚本转换为 C 语言，创建一个`Makefile`，运行 C 编译器以创建一个插入到目标内核的目标架构的内核模块，然后从内核中收集跟踪数据。要在 Eclipse 中启动 SystemTap 插件，需要遵循一些步骤。

1.  从**Yocto 项目工具**菜单中选择**systemtap**选项。

1.  在打开的窗口中，需要传递 crosstap 参数：

+   将**Metadata Location**变量设置为相应的`poky`目录

+   通过输入 root（默认选项）来设置**Remote User ID**，因为它对目标具有`ssh`访问权限-任何其他具有相同权限的用户也是一个不错的选择

+   将**Remote Host**变量设置为目标的相应 IP 地址

+   使用**Systemtap Scripts**变量来获取`.stp`脚本的完整路径

+   使用**Systemtap Args**字段设置额外的交叉选项

`.stp`脚本的输出应该在 Eclipse 的控制台视图中可用。

我们将要看的最后一个工具是**KGDB**。这个工具专门用于调试 Linux 内核，只有在 Eclipse IDE 内进行 Linux 内核源代码开发时才有用。要使用这个工具，需要进行一些必要的配置设置：

+   禁用 C/C++索引：

+   从**Window** | **Preferences**菜单中选择**C/C++ Indexer**选项

+   取消选择**Enable indexer**复选框

+   创建一个可以导入内核源代码的项目：

+   从**File** | **New**菜单中选择**C/C++** | **C Project**选项

+   选择**Makefile project** | **Empty project**选项，并为项目命名

+   取消选择**Use default location**选项

+   单击**Browse**按钮并标识内核源代码本地 git 存储库的位置

+   按下**Finish**按钮，项目应该已创建

在满足先决条件后，实际配置可以开始：

+   从**Run**菜单中选择**Debug Configuration**选项。

+   双击**GDB Hardware Debugging**选项以创建名为**<project name> Default**的默认配置。

+   从**Main**选项卡，浏览到`vmlinux`构建图像的位置，选择**Disable auto build**单选按钮，以及**GDB (DFS) Hardware Debugging Launcher**选项。

+   对于**Debugger**选项卡中可用的**C/C++ Application**选项，浏览工具链内可用的 GDB 二进制文件的位置（如果 ADT 安装程序脚本可用，则其默认位置应为`/opt/poky/1.7/sysroots/x86_64-pokysdk-linux/usr/bin/arm-poky-linux-gnueabi/arm-poky-linux-gnueabi-gdb`）。从**JTAG Device**菜单中选择**Generic serial option**。**Use remote target**选项是必需的。

+   从**Startup**选项卡，选择**Load symbols**选项。确保**Use Project binary**选项指示正确的`vmlinux`图像，并且未选择**Load image**选项。

+   按下**Apply**按钮以确保先前的配置已启用。

+   为串行通信调试准备目标：

+   设置`echo ttyS0,115200` | `/sys/module/kgdboc/parameters/kgdboc`选项以确保适当的设备用于调试

+   在`echo g` | `/proc/sysrq-trigger`目标上启动 KGDB

+   关闭目标终端但保持串行连接

+   从**Run**菜单中选择**Debug Configuration**选项

+   选择先前创建的配置，然后单击**Debug**按钮

按下**Debug**按钮后，调试会话应该开始，并且目标将在`kgdb_breakpoint()`函数中停止。从那里，所有特定于 GDB 的命令都可用并准备好使用。

## Yocto Project bitbake 指挥官

bitbake 指挥官提供了编辑配方和创建元数据项目的可能性，类似于命令行中可用的方式。两者之间的区别在于使用 Eclipse IDE 进行元数据交互。

为了确保用户能够执行这些操作，需要进行一些步骤：

+   从**File** | **New**菜单中选择**Project**选项

+   从打开的窗口中选择**Yocto Project BitBake Commander**向导

+   选择**New Yocto Project**选项，将打开一个新窗口来定义新项目的属性

+   使用**项目位置**，识别`poky`目录的父目录

+   使用**项目名称**选项定义项目名称。其默认值为 poky

+   对于**远程服务提供商**变量，选择**本地**选项，并在**连接名称**下拉列表中使用相同的选项

+   确保对已安装的`poky`源目录未选择**克隆**复选框

通过使用 Eclipse IDE，其功能可供使用。其中最有用的功能之一是快速搜索选项，对一些开发人员可能非常有用。其他好处包括使用模板创建配方的可能性，使用语法高亮、自动完成、实时错误报告等进行编辑，以及许多其他功能。

### 注意

使用 bitbake commander 仅限于本地连接。远程连接会导致 IDE 由于上游可用的错误而冻结。

# 摘要

在本章中，您了解了 Yocto 项目提供的 ADE 功能的信息，以及可用于应用程序开发的众多 Eclipse 插件，这不仅是一种替代方案，也是对连接到他们的 IDE 的开发人员的解决方案。尽管本章以介绍命令行爱好者的应用程序开发选项开始，但很快就变成了关于 IDE 交互的内容。这是因为需要提供替代解决方案，以便开发人员可以选择最适合他们需求的内容。

在下一章中，将介绍一些 Yocto 项目的组件。这一次，它们与应用程序开发无关，而涉及元数据交互、质量保证和持续集成服务。我将尝试展示 Yocto 项目的另一面，我相信这将帮助读者更好地了解 Yocto 项目，并最终与适合他们和他们需求的组件进行交互和贡献。


# 第八章：Hob，Toaster 和 Autobuilder

在本章中，您将被介绍 Yocto 社区中使用的新工具和组件。正如标题所示，本章专门介绍另一类工具。我将从 Hob 作为图形界面开始，它正在逐渐消失，并将被一个名为 Toaster 的新网络界面所取代。本章还将介绍一个新的讨论点。在这里，我指的是 QA 和测试组件，在大多数情况下，它是缺失或不足的。Yocto 非常重视这个问题，并为其提供了解决方案。这个解决方案将在本章的最后一节中介绍。

您还将获得有关 Hob，Toaster 和 Autobuilder 等组件的更详细的介绍。将分别评估这些组件，并详细查看它们的优势和用例。对于前两个组件（即 Hob 和 Toaster），提供了有关构建过程的信息以及各种设置方案。Hob 类似于 BitBake，并与 Poky 和构建目录紧密集成。另一方面，Toaster 是一个更松散的替代方案，提供多种配置选择和设置，并且性能部分对于任何有兴趣改进构建系统整体性能的开发人员非常有用。本章以 Autobuilder 部分结束。该项目是 Yocto 项目的基石，致力于使嵌入式开发和开源更加用户友好，但也提供了更安全和无错误的项目。希望您喜欢本章；让我们继续到第一节。

# Hob

Hob 项目代表了 BitBake 构建系统的图形界面替代方案。它的目的是以更简单更快的方式执行最常见的任务，但并不会消除命令行交互。这是因为大多数配方和配置的部分仍然需要手动完成。在上一章中，引入了 BitBake Commander 扩展作为编辑配方的替代解决方案，但在这个项目中，它有其局限性。

Hob 的主要目的是使用户更容易地与构建系统进行交互。当然，有些用户不喜欢图形用户界面的替代方案，而更喜欢命令行选项，我有点同意他们，但这是另一个讨论。Hob 也可以是他们的选择；它不仅是为那些喜欢在面前有界面的人提供的选择，也是为那些喜欢他们的命令行交互的人提供的选择。

Hob 除了最常见的任务外，可能无法执行很多任务，例如构建图像，修改现有的配方，通过 QEMU 模拟器运行图像，甚至在目标设备上将其部署到 USB 设备以进行一些现场引导操作。拥有所有这些功能并不多，但非常有趣。您在 Yocto Project 中使用工具的经验在这里并不重要。前面提到的任务可以非常轻松和直观地完成，这是 Hob 最有趣的地方。它以非常简单的方式为用户提供所需的功能。与之交互的人可以从它所提供的教训中学到东西，无论他们是图形界面爱好者还是命令行专家。

在本章中，我将向您展示如何使用 Hob 项目构建 Linux 操作系统图像。为了演示这一点，我将使用 Atmel SAMA5D3 Xplained 机器，这也是我在前几章中进行其他演示时使用的机器。

首先，让我们看看当您第一次启动 Hob 时它是什么样子。结果显示在以下截图中：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00343.jpeg)

要检索图形界面，用户需要执行 BitBake 命令行交互所需的给定步骤。首先，需要创建一个构建目录，并从该构建目录开始，用户需要使用以下 Hob 命令启动 Hob 图形界面：

```
source poky/oe-init-build-env ../build-test
hob

```

下一步是确定构建所需的层。您可以通过在**层**窗口中选择它们来完成。对于`meta-atmel`层的第一步是将其添加到构建中。尽管您可能在已经存在的构建目录中开始工作，但 Hob 将无法检索现有的配置，并将在`bblayers.conf`和`local.conf`配置文件上创建一个新的配置。它将使用下一个`#added by hob`消息标记添加的行。

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00344.jpeg)

在构建目录中添加了相应的`meta-atmel`层之后，所有支持的机器都可以在**选择机器**下拉菜单中找到，包括`meta-atmel`层添加的机器。从可用选项中，需要选择**sama5d3-xplained**机器：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00345.jpeg)

当选择 Atmel **sama5d3-xplained**机器时，会出现如下截图所示的错误：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00346.jpeg)

在将`meta-qt5`层添加到层部分后，此错误消失，构建过程可以继续。要检索`meta-qt5`层，需要以下`git`命令：

```
git clone -b dizzy https://github.com/meta-qt5/meta-qt5.git

```

由于所有可用的配置文件和配方都被解析，解析过程需要一段时间，之后您会看到如下截图所示的错误：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00347.jpeg)

经过快速检查后，您会看到以下代码：

```
find ../ -name "qt4-embedded*"
./meta/recipes-qt/qt4/qt4-embedded_4.8.6.bb
./meta/recipes-qt/qt4/qt4-embedded.inc
./meta-atmel/recipes-qt/qt4/qt4-embedded-4.8.5
./meta-atmel/recipes-qt/qt4/qt4-embedded_4.8.5.bbappend

```

唯一的解释是`meta-atmel`层没有更新其配方，而是附加它们。这可以通过两种方式克服。最简单的方法是更新`.bbappend`文件的配方，并确保新的可用配方被转换为上游社区的补丁。稍后将向您解释在`meta-atmel`层内具有所需更改的补丁，但首先，我将介绍可用的选项和解决构建过程中存在的问题所需的必要更改。

另一个解决方案是包含`meta-atmel`在构建过程中所需的必要配方。最好的地方也将其放在`meta-atmel`中。然而，在这种情况下，`.bbappend`配置文件应与配方合并，因为在同一位置拥有配方及其附加文件并不太合理。

在解决了这个问题之后，用户将可以看到新的选项，如下截图所示：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00348.jpeg)

现在，用户有机会选择需要构建的镜像，以及需要添加的额外配置。这些配置包括：

+   选择分发类型

+   选择镜像类型

+   打包格式

+   根文件系统周围的其他小调整

其中一些如下图所示：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00349.jpeg)

我选择将分发类型从**poky-tiny**更改为**poky**，并且生成的根文件系统输出格式可在下图中看到：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00350.jpeg)

经过调整后，配方被重新解析，当此过程完成后，可以选择生成的镜像，从而开始构建过程。此演示中选择的镜像是**atmel-xplained-demo-image**镜像，与同名的配方相对应。这些信息也显示在下图中：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00351.jpeg)

点击**构建镜像**按钮开始构建过程。构建开始后一段时间，将出现一个错误，告诉我们**meta-atmel**BSP 层需要我们定义更多的依赖项：

![Hob](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00352.jpeg)

这些信息是从`iperf`配方中收集的，该配方不在包含的层中；它在`meta-openembedded/meta-oe`层内可用。在进行更详细的搜索和更新过程后，有一些发现。`meta-atmel` BSP 层需要的层依赖关系比所需的更多，如下所示：

+   `meta-openembedded/meta-oe`层

+   `meta-openembedded/meta-networking`层

+   `meta-openembedded/meta-ruby`层

+   `meta-openembedded/meta-python`层

+   `meta-qt5`层

最终结果可在`bblayers.conf`文件中找到的`BBLAYERS`变量中找到，如下所示：

```
#added by hob
BBFILES += "${TOPDIR}/recipes/images/custom/*.bb"
#added by hob
BBFILES += "${TOPDIR}/recipes/images/*.bb"

#added by hob
BBLAYERS = "/home/alex/workspace/book/poky/meta /home/alex/workspace/book/poky/meta-yocto /home/alex/workspace/book/poky/meta-yocto-bsp /home/alex/workspace/book/poky/meta-atmel /home/alex/workspace/book/poky/meta-qt5 /home/alex/workspace/book/poky/meta-openembedded/meta-oe /home/alex/workspace/book/poky/meta-openembedded/meta-networking /home/alex/workspace/book/poky/meta-openembedded/meta-ruby /home/alex/workspace/book/poky/meta-openembedded/meta-python"
```

在开始完整构建之前，`meta-atmel`层中需要进行一些必要的更改，如下所示：

+   用`packagegroup-core-full-cmdline`替换`packagegroup-core-basic`，因为最新的 Poky 已更新了`packagegroup`名称。

+   删除`python-setuptools`，因为它在`meta-openembedded/meta-oe`层中不再可用，也不在新的`meta-openembedded/meta-python`层中，后者是所有与 Python 相关的配方的新占位符。`python-setuptools`工具被删除，因为它具有下载、构建、安装、升级和卸载额外 Python 软件包的能力，并且不是 Yocto 的强制要求。这是它的一般目的。

+   关于更新到`qt4-embedded-4.8.6`的前述更改，出现了错误。

`meta-atmel`层的所有更改都包含在以下补丁中：

```
From 35ccf73396da33a641f307f85e6b92d5451dc255 Mon Sep 17 00:00:00 2001
From: "Alexandru.Vaduva" <vaduva.jan.alexandru@gmail.com>
Date: Sat, 31 Jan 2015 23:07:49 +0200
Subject: [meta-atmel][PATCH] Update suppport for atmel-xplained-demo-image
 image.

The latest poky contains updates regarding the qt4 version support
and also the packagegroup naming.
Removed packages which are no longer available.

Signed-off-by: Alexandru.Vaduva <vaduva.jan.alexandru@gmail.com>
---
 recipes-core/images/atmel-demo-image.inc           |  3 +--
 ...qt-embedded-linux-4.8.4-phonon-colors-fix.patch | 26 ----------------------
 ...qt-embedded-linux-4.8.4-phonon-colors-fix.patch | 26 ++++++++++++++++++++++
 recipes-qt/qt4/qt4-embedded_4.8.5.bbappend         |  2 --
 recipes-qt/qt4/qt4-embedded_4.8.6.bbappend         |  2 ++
 5 files changed, 29 insertions(+), 30 deletions(-)
 delete mode 100644 recipes-qt/qt4/qt4-embedded-4.8.5/qt-embedded-linux-4.8.4-phonon-colors-fix.patch
 create mode 100644 recipes-qt/qt4/qt4-embedded-4.8.6/qt-embedded-linux-4.8.4-phonon-colors-fix.patch
 delete mode 100644 recipes-qt/qt4/qt4-embedded_4.8.5.bbappend
 create mode 100644 recipes-qt/qt4/qt4-embedded_4.8.6.bbappend

diff --git a/recipes-core/images/atmel-demo-image.inc b/recipes-core/images/atmel-demo-image.inc
index fe13303..a019586 100644
--- a/recipes-core/images/atmel-demo-image.inc
+++ b/recipes-core/images/atmel-demo-image.inc
@@ -2,7 +2,7 @@ IMAGE_FEATURES += "ssh-server-openssh package-management"

 IMAGE_INSTALL = "\
     packagegroup-core-boot \
-    packagegroup-core-basic \
+    packagegroup-core-full-cmdline \
     packagegroup-base-wifi \
     packagegroup-base-bluetooth \
     packagegroup-base-usbgadget \
@@ -23,7 +23,6 @@ IMAGE_INSTALL = "\
     python-smbus \
     python-ctypes \
     python-pip \
-    python-setuptools \
     python-pycurl \
     gdbserver \
     usbutils \
diff --git a/recipes-qt/qt4/qt4-embedded-4.8.5/qt-embedded-linux-4.8.4-phonon-colors-fix.patch b/recipes-qt/qt4/qt4-embedded-4.8.5/qt-embedded-linux-4.8.4-phonon-colors-fix.patch
deleted file mode 100644
index 0624eef..0000000
--- a/recipes-qt/qt4/qt4-embedded-4.8.5/qt-embedded-linux-4.8.4-phonon-colors-fix.patch
+++ /dev/null
@@ -1,26 +0,0 @@
-diff --git a/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp b/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp
-index 89d5a9d..8508001 100644
---- a/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp
-+++ b/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp
-@@ -18,6 +18,7 @@
- #include <QApplication>
- #include "videowidget.h"
- #include "qwidgetvideosink.h"
-+#include <gst/video/video.h>
-
- QT_BEGIN_NAMESPACE
-
-@@ -106,11 +107,7 @@ static GstStaticPadTemplate template_factory_rgb =-     GST_STATIC_PAD_TEMPLATE("sink",- GST_PAD_SINK,
-                             GST_PAD_ALWAYS,
--                            GST_STATIC_CAPS("video/x-raw-rgb, "
--                                            "framerate = (fraction) [ 0, MAX ], "
--                                            "width = (int) [ 1, MAX ], "
--                                            "height = (int) [ 1, MAX ],"
--                                            "bpp = (int) 32"));
-+                            GST_STATIC_CAPS(GST_VIDEO_CAPS_xRGB_HOST_ENDIAN));
-
- template <VideoFormat FMT>
- struct template_factory;
-
diff --git a/recipes-qt/qt4/qt4-embedded-4.8.6/qt-embedded-linux-4.8.4-phonon-colors-fix.patch b/recipes-qt/qt4/qt4-embedded-4.8.6/qt-embedded-linux-4.8.4-phonon-colors-fix.patch
new file mode 100644
index 0000000..0624eef
--- /dev/null
+++ b/recipes-qt/qt4/qt4-embedded-4.8.6/qt-embedded-linux-4.8.4-phonon-colors-fix.patch
@@ -0,0 +1,26 @@
+diff --git a/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp b/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp
+index 89d5a9d..8508001 100644
+--- a/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp
++++ b/src/3rdparty/phonon/gstreamer/qwidgetvideosink.cpp
+@@ -18,6 +18,7 @@
+ #include <QApplication>
+ #include "videowidget.h"
+ #include "qwidgetvideosink.h"
++#include <gst/video/video.h>
+
+ QT_BEGIN_NAMESPACE
+
+@@ -106,11 +107,7 @@ static GstStaticPadTemplate template_factory_rgb =+     GST_STATIC_PAD_TEMPLATE("sink",+ GST_PAD_SINK,+ GST_PAD_ALWAYS,+- GST_STATIC_CAPS("video/x-raw-rgb, "+-                                            "framerate = (fraction) [ 0, MAX ], "
+-                                            "width = (int) [ 1, MAX ], "
+-                                            "height = (int) [ 1, MAX ],"
+-                                            "bpp = (int) 32"));
++                            GST_STATIC_CAPS(GST_VIDEO_CAPS_xRGB_HOST_ENDIAN));
+
+ template <VideoFormat FMT>
+ struct template_factory;
+
diff --git a/recipes-qt/qt4/qt4-embedded_4.8.5.bbappend b/recipes-qt/qt4/qt4-embedded_4.8.5.bbappend
deleted file mode 100644
index bbb4d26..0000000
--- a/recipes-qt/qt4/qt4-embedded_4.8.5.bbappend
+++ /dev/null
@@ -1,2 +0,0 @@
-FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}-${PV}:"
-SRC_URI += "file://qt-embedded-linux-4.8.4-phonon-colors-fix.patch"
diff --git a/recipes-qt/qt4/qt4-embedded_4.8.6.bbappend b/recipes-qt/qt4/qt4-embedded_4.8.6.bbappend
new file mode 100644
index 0000000..bbb4d26
--- /dev/null
+++ b/recipes-qt/qt4/qt4-embedded_4.8.6.bbappend
@@ -0,0 +1,2 @@
+FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}-${PV}:"
+SRC_URI += "file://qt-embedded-linux-4.8.4-phonon-colors-fix.patch"
-- 
1.9.1
```

这个补丁在本章中作为 Git 交互的一个示例，并且在创建需要上游到社区的补丁时是必需的。在撰写本章时，这个补丁尚未发布到上游社区，因此这可能是一个礼物，供有兴趣向 meta-atmel 社区特别是 Yocto 社区添加贡献的人使用。

在更改完成后获得此补丁所需的步骤被简要描述。它定义了生成补丁所需的步骤，如下命令所示，即`0001-Update-suppport-for-atmel-xplained-demo-image-image.patch`。可以通过`README`文件和`git send-email`命令将其上游到社区或直接发送给`meta-atmel`层的维护者：

```
git status 
git add --all .
git commit -s
git fetch -a
git rebase -i origin/master 
git format-patch -s --subject-prefix='meta-atmel]PATCH' origin/master
vim 0001-Update-suppport-for-atmel-xplained-demo-image-image.patch

```

# Toaster

Toaster 是 Hob 的替代品，在某个特定时间点将完全取代它。它还是 BitBake 命令行的基于 Web 的界面。这个工具比 Hob 更有效；它不仅能够以与 Hob 类似的方式执行最常见的任务，而且还包括一个构建分析组件，收集有关构建过程和结果的数据。这些结果以非常易于理解的方式呈现，提供了搜索、浏览和查询信息的机会。

从收集的信息中，我们可以提到以下内容：

+   图像目录的结构

+   可用的构建配置

+   构建的结果以及注册的错误和警告

+   图像配方中存在的软件包

+   构建的配方和软件包

+   执行的任务

+   有关执行任务的性能数据，如 CPU 使用率、时间和磁盘 I/O 使用情况

+   配方的依赖关系和反向依赖关系

Hob 解决方案也存在一些缺点。Toaster 目前还不能配置和启动构建。但是，已经采取了措施将 Hob 内的这些功能包含在 Toaster 中，这将在不久的将来实现。

Toaster 项目的当前状态允许在各种设置和运行模式下执行。每个都将被呈现并相应地定义如下：

+   **交互模式**：这是在 Yocto Project 1.6 版本中提供的模式。它基于`toasterui`构建记录组件和`toastergui`构建检查和统计用户界面。

+   **管理模式**：除了 Yocto Project 1.6 版本之外，这是处理从 Web 界面触发的构建配置、调度和执行的模式。

+   **远程管理模式**：这是托斯特主机模式，用于生产环境，因为它支持多个用户和定制安装。

+   **本地管理模式或** **_ 本地 _ 模式**：这是在 Poky 检出后可用的模式，允许使用本地机器代码和构建目录进行构建。这也是任何第一次与 Toaster 项目交互的人使用的模式。

+   对于**交互模式**，需要与 Yocto Project 构建运行的硬件分开设置，例如使用 AutoBuilder、BuildBot 或 Jenkins 等工具进行构建。在普通的 Toaster 实例后面，有三件事情发生：

+   启动 BitBake 服务器

+   启动 Toaster UI，并连接到 BitBake 服务器以及 SQL 数据库。

+   启动 Web 服务器是为了读取与数据库相关的信息，并在 Web 界面上显示它

有时会出现多个 Toaster 实例在多台远程机器上运行的情况，或者单个 Toaster 实例在多个用户和构建服务器之间共享的情况。所有这些情况都可以通过修改 Toaster 启动的模式以及相应地更改 SQL 数据库和 Web 服务器的位置来解决。通过拥有一个共同的 SQL 数据库、Web 服务器和多个 BitBake 服务器，以及每个单独的构建目录的 Toaster 用户界面，可以解决前面提到的问题。因此，Toaster 实例中的每个组件都可以在不同的机器上运行，只要适当进行通信并且各组件了解彼此。

要在 Ubuntu 机器上设置 SQL 服务器，需要安装一个软件包，使用以下命令：

```
apt-get install mysgl-server

```

拥有必要的软件包还不够，还需要设置它们。因此，需要适当的用户名和密码来访问 Web 服务器，以及 MySQL 帐户的适当管理权限。此外，还需要 Toaster 主分支的克隆用于 Web 服务器，源代码可用后，请确保在`bitbake/lib/toaster/toastermain/settings.py`文件中，`DATABASES`变量指示了先前设置的数据库。确保使用为其定义的用户名和密码。

设置完成后，可以按以下方式开始数据库同步：

```
python bitbake/lib/toaster/manage.py syncdb
python bitbake/lib/toaster/manage.py migrate orm
python bitbake/lib/toaster/manage.py migrate bldcontrol

```

现在，可以使用`python bitbake/lib/toaster/manage.py runserver`命令启动 Web 服务器。对于后台执行，可以使用`nohup python bitbake/lib/toaster/manage.py runserver 2>toaster_web.log >toaster_web.log &`命令。

这可能足够作为起步，但由于构建需要案例日志，因此需要一些额外的设置。在`bitbake/lib/toaster/toastermain/settings.py`文件中，`DATABASES`变量指示用于日志服务器的 SQL 数据库。在构建目录中，调用`source toaster start`命令，并确保`conf/toaster.conf`文件可用。在此文件中，请确保启用了 Toaster 和构建历史`bbclasses`，以记录有关软件包的信息：

```
INHERIT += "toaster"
INHERIT += "buildhistory"
BUILDHISTORY_COMMIT = "1"

```

设置完成后，使用以下命令启动 BitBake 服务器和日志界面：

```
bitbake --postread conf/toaster.conf --server-only -t xmlrpc -B localhost:0 && export BBSERVER=localhost:-1
nohup bitbake --observe-only -u toasterui >toaster_ui.log &

```

完成后，可以启动正常的构建过程，并且在构建在 Web 界面内运行时，日志和数据可供检查。不过，要注意一点：在完成在构建目录内的工作后，不要忘记使用`bitbake –m`命令关闭 BitBake 服务器。

本地与迄今为止介绍的 Yocto Project 构建非常相似。这是个人使用和学习与工具交互的最佳模式。在开始设置过程之前，需要安装一些软件包，使用以下命令行：

```
sudo apt-get install python-pip python-dev build-essential 
sudo pip install --upgrade pip 
sudo pip install --upgrade virtualenv

```

安装了这些软件包后，请确保安装烤面包机所需的组件；在这里，我指的是 Django 和 South 软件包：

```
sudo pip install django==1.6
sudo pip install South==0.8.4

```

与 Web 服务器交互时，需要`8000`和`8200`端口，因此请确保它们没有被其他交互预留。考虑到这一点，我们可以开始与烤面包机交互。使用前几章节中提供的下载中可用的 Poky 构建目录，调用`oe-init-build-env`脚本创建一个新的构建目录。这可以在已经存在的构建目录上完成，但有一个新的构建目录将有助于识别可用于与烤面包机交互的额外配置文件。

根据您的需求设置构建目录后，应调用`source toaster start`命令，如前所述，启动烤面包机。在`http://localhost:8000`上，如果没有执行构建，您将看到以下屏幕截图：

![烤面包机在控制台中运行构建，它将自动在 Web 界面中更新，如下面的屏幕截图所示：![烤面包机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00354.jpeg)

构建完成后，Web 界面将相应地更新。我关闭了标题图像和信息，以确保在 Web 页面中只有构建可见。

![烤面包机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00355.jpeg)

如前面的例子所示，在前面的屏幕截图中有两个已完成的构建。它们都是内核构建。第一个成功完成，而第二个有一些错误和警告。我这样做是为了向用户展示他们构建的替代输出。

由于主机机器上的内存和空间不足，导致构建失败，如下面的屏幕截图所示：

![烤面包机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00356.jpeg)

对于失败的构建，有一个详细的失败报告可用，如下面的屏幕截图所示：

![烤面包机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00357.jpeg)

成功完成的构建提供了大量信息的访问。以下屏幕截图显示了构建应该具有的有趣功能。对于内核构建，它显示了使用的所有 BitBake 变量、它们的值、它们的位置和简短描述。这些信息对所有开发人员都非常有用，不仅因为它在一个位置提供了所有这些信息，而且因为它提供了一个减少寻找麻烦变量所需的搜索时间的搜索选项：

![烤面包机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00358.jpeg)

在执行活动完成后，可以使用`source toaster stop`命令停止烤面包机。

在构建目录中，烤面包机创建了许多文件；它们的命名和目的在以下行中介绍：

+   `bitbake-cookerdaemon.log`：这个日志文件对于 BitBake 服务器是必要的

+   `.toastermain.pid`：这是包含 Web 服务器`pid`的文件

+   `.toasterui.pid`：它包含 DSI 数据桥，`pid`

+   `toaster.sqlite`：这是数据库文件

+   `toaster_web.log`：这是 Web 服务器日志文件

+   `toaster_ui.log`：这是用户界面组件使用的日志文件

提到了所有这些因素，让我们转到下一个组件，但在提供有关烤面包机的一些有趣视频链接之前。

### 注意

有关烤面包机手册 1.7 的信息可在[`www.yoctoproject.org/documentation/toaster-manual-17`](https://www.yoctoproject.org/documentation/toaster-manual-17)上访问。

# 自动构建器

Autobuilder 是负责 QA 的项目，在 Yocto Project 内部提供了一个测试构建。它基于 BuildBot 项目。虽然这本书没有涉及这个主题，但对于那些对 BuildBot 项目感兴趣的人，可以在以下信息框中找到更多信息。

### 注意

Buildbot 的起始页面可以在[`trac.buildbot.net/`](http://trac.buildbot.net/)上访问。您可以在[`docs.buildbot.net/0.8.5/tutorial/tour.html`](http://docs.buildbot.net/0.8.5/tutorial/tour.html)找到有关快速启动 BuildBot 的指南，其概念可以在[`docs.buildbot.net/latest/manual/concepts.html`](http://docs.buildbot.net/latest/manual/concepts.html)找到。

我们现在要讨论的是一个在一般开发人员中受到非常糟糕对待的软件领域。我指的是开发过程的测试和质量保证。事实上，这是一个需要我们更多关注的领域，包括我自己在内。Yocto Project 通过 AutoBuilder 倡议试图引起更多对这一领域的关注。此外，在过去几年中，开源项目的 QA 和持续集成（CI）出现了转变，这主要可以在 Linux Foundation 的伞下项目中看到。

Yocto Project 积极参与 AutoBuilder 项目的以下活动：

+   使用 Bugzilla 测试用例和计划发布测试和 QA 计划([`bugzilla.yoctoproject.org`](https://bugzilla.yoctoproject.org))。

+   展示这些计划并使它们对所有人可见。当然，为此，您将需要相应的帐户。

+   为所有人开发工具、测试和 QA 程序。

在上述活动作为基础的基础上，他们提供了对 Poky 主分支当前状态的公共 AutoBuilder 的访问。每晚为所有支持的目标和架构执行构建和测试集，并且所有人都可以在[`autobuilder.yoctoproject.org/`](http://autobuilder.yoctoproject.org/)上找到。

### 注意

如果您没有 Bugzilla 帐户来访问 Yocto Project 内部完成的 QA 活动，请参阅[`wiki.yoctoproject.org/wiki/QA`](https://wiki.yoctoproject.org/wiki/QA)。

与 AutoBuilder 项目互动，设置在`README-QUICKSTART`文件中定义为一个四步程序：

```
cat README-QUICKSTART 
Setting up yocto-autobuilder in four easy steps:
------------------------------------------------
git clone git://git.yoctoproject.org/yocto-autobuilder
cd yocto-autobuilder
. ./yocto-autobuilder-setup
yocto-start-autobuilder both
```

该项目的配置文件位于`config`目录中。`autobuilder.conf`文件用于定义项目的参数，例如`DL_DIR`，`SSTATE_DIR`，以及其他构建工件对于生产设置非常有用，但对于本地设置则不太有用。要检查的下一个配置文件是`yoctoABConfig.py`，它位于`yocto-controller`目录中，用于定义执行构建的属性。

此时，AutoBuilder 应该正在运行。如果它在 Web 界面内启动，结果应该类似于以下截图：

![自动构建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00359.jpeg)

从网页标题中可以看出，不仅可以执行构建，还可以以不同的视图和角度查看它们。以下是其中一种可视化视角：

![自动构建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00360.jpeg)

这个项目对其用户有更多的提供，但我会让其余的通过试验和阅读 README 文件来发现。请记住，这个项目是基于 Buildbot 构建的，因此工作流程与它非常相似。

# 总结

在本章中，您将了解到 Yocto Project 中提供的一组新组件。在这里，我指的是 Hob、Toaster 和 AutoBuilder 项目。本章首先介绍了 Hob 作为 BitBake 的替代方案。接着介绍了 Toaster 作为 Hob 的替代方案，它也具有许多有趣的功能，尽管现在还不是最好的，但随着时间的推移，它将成为开发人员的真正解决方案，他们不想学习新技术，而是只需与工具交互，以快速简便的方式获得他们想要的东西。本章最后介绍了 AutoBuilder 项目，为 Yocto Project 社区提供了一个质量保证和测试平台，并可以转变为一个持续集成工具。

在下一章中，将介绍一些其他工具，但这次重点将稍微转向社区以及其小工具的外部。我们还将涵盖项目和工具，例如 Swabber，这是一个不断发展的项目。我们还将看看 Wic，一个性格鲜明的小工具，以及来自 Linaro 的新感觉 LAVA。希望您喜欢学习它们。


# 第九章：Wic 和其他工具

在本章中，将简要介绍一些解决各种问题并以巧妙方式解决它们的工具。这一章可以被认为是为你准备的开胃菜。如果这里介绍的任何工具似乎引起了你的兴趣，我鼓励你满足你的好奇心，尝试找到更多关于那个特定工具的信息。当然，这条建议适用于本书中提供的任何信息。然而，这条建议特别适用于本章，因为我选择了对我介绍的工具进行更一般的描述。我这样做是因为我假设你们中的一些人可能对冗长的描述不感兴趣，而只想把兴趣集中在开发过程中，而不是其他领域。对于其他对了解更多其他关键领域感兴趣的人，请随意浏览本章中提供的信息扩展。

在本章中，将提供对 Swabber、Wic 和 LAVA 等组件的更详细解释。这些工具不是嵌入式开发人员在日常工作中会遇到的工具，但与这些工具的交互可能会让生活变得更轻松一些。我应该首先提到这些工具的一件事是它们彼此之间没有任何共同之处，它们之间非常不同，并且解决了不同的问题。如果 Swabber，这里介绍的第一个工具，用于在主机开发机器上进行访问检测，那么第二个工具代表了 BitBake 在复杂打包选项方面的限制的解决方案。在这里，我指的是 wic 工具。本章介绍的最后一个元素是名为 LAVA 的自动化测试框架。这是来自 Linaro 的一个倡议，我认为这个项目非常有趣。它还与 Jenkins 等持续集成工具结合在一起，这可能对每个人都是一个致命的组合。

# 拖把

Swabber 是一个项目，虽然它在 Yocto Project 的官方页面上展示，但据说它还在进行中；自 2011 年 9 月 18 日以来没有任何活动。它没有维护者文件，您无法在其中找到更多关于其创建者的信息。然而，对于任何对这个项目感兴趣的人来说，提交者列表应该足够了解更多。

本章选择介绍这个工具，因为它构成了 Yocto Project 生态系统的另一个视角。当然，对主机系统进行访问检测的机制并不是一个坏主意，对于检测可能对系统有问题的访问非常有用，但在开发软件时并不是首选的工具。当你有可能重新构建并手动检查主机生态系统时，你往往会忽视工具也可以用于这个任务，并且它们可以让你的生活更轻松。

与 Swabber 交互，需要首先克隆存储库。可以使用以下命令来实现这一目的：

```
git clone http://git.yoctoproject.org/git/swabber

```

源代码在主机上可用后，存储库的内容应如下所示：

```
tree swabber/
swabber/
├── BUGS
├── canonicalize.c
├── canonicalize.h
├── COPYING
├── detect_distro
├── distros
│   ├── Fedora
│   │   └── whitelist
│   ├── generic
│   │   ├── blacklist
│   │   ├── filters
│   │   └── whitelist
│   ├── Ubuntu
│   │   ├── blacklist
│   │   ├── filters
│   │   └── whitelist
│   └── Windriver
│       └── whitelist
├── dump_blob.c
├── lists.c
├── lists.h
├── load_distro.c
├── Makefile
├── packages.h
├── README
├── swabber.c
├── swabber.h
├── swabprof.c
├── swabprof.in
├── swab_testf.c
├── update_distro
├── wandering.c
└── wandering.h

5 directories, 28 files

```

正如你所看到的，这个项目并不是一个重大项目，而是由一些热情的人提供的一些工具。其中包括来自**Windriver**的两个人：Alex deVries 和 David Borman。他们独自开发了之前介绍的工具，并将其提供给开源社区使用。Swabber 是用 C 语言编写的，这与 Yocto Project 社区提供的通常的 Python/Bash 工具和其他项目有很大的不同。每个工具都有自己的目的，相似之处在于所有工具都是使用相同的 Makefile 构建的。当然，这不仅限于使用二进制文件；还有两个 bash 脚本可用于分发检测和更新。

### 注

有关该工具的更多信息可以从其创建者那里获得。他们的电子邮件地址，可在项目的提交中找到，分别是`<alex.devries@windriver.com>`和`<david.borman@windriver.com>`。但请注意，这些是工作场所的电子邮件地址，而曾经参与 Swabber 工作的人现在可能没有相同的电子邮件地址。

与 Swabber 工具的交互在`README`文件中有很好的描述。在这里，关于 Swabber 的设置和运行的信息是可用的，不过，为了你的方便，这也将在接下来的几行中呈现，以便你能更快地理解和更容易地掌握。

第一个必要的步骤是编译源代码。这是通过调用`make`命令来完成的。在源代码构建并可执行文件可用后，可以使用`update_distro`命令对主机分发进行配置，然后是分发目录的位置。我们选择的名称是`Ubuntu-distro-test`，它是特定于执行工具的主机分发。这个生成过程一开始可能需要一些时间，但之后，对主机系统的任何更改都将被检测到，并且过程所需的时间将更少。在配置过程结束时，`Ubuntu-distro-test`目录的内容如下：

```
Ubuntu-distro-test/
├── distro
├── distro.blob
├── md5
└── packages

```

主机分发配置文件后，可以基于创建的配置文件生成一个 Swabber 报告。此外，在创建报告之前，还可以创建一个配置文件日志，以备报告过程中使用。为了生成报告，我们将创建一个具有特定日志信息的日志文件位置。日志可用后，就可以生成报告了：

```
strace -o logs/Ubuntu-distro-test-logs.log -e trace=open,execve -f pwd
./swabber -v -v -c all -l logs/ -o required.txt -r extra.txt -d Ubuntu-distro-test/ ~ /tmp/

```

工具需要这些信息，如其帮助信息所示：

```
Usage: swabber [-v] [-v] [-a] [-e]
 -l <logpath> ] -o <outputfile> <filter dir 1> <filter dir 2> ...

 Options:
 -v: verbose, use -v -v for more detail
 -a: print progress (not implemented)
 -l <logfile>: strace logfile or directory of log files to read
 -d <distro_dir>: distro directory
 -n <distro_name>: force the name of the distribution
 -r <report filename>: where to dump extra data (leave empty for stdout)
 -t <global_tag>: use one tag for all packages
 -o <outputfile>: file to write output to
 -p <project_dir>: directory were the build is being done
 -f <filter_dir>: directory where to find filters for whitelist,
 blacklist, filters
 -c <task1>,<task2>...: perform various tasks, choose from:
 error_codes: show report of files whose access returned an error
 whitelist: remove packages that are in the whitelist
 blacklist: highlight packages that are in the blacklist as
 being dangerous
 file_detail: add file-level detail when listing packages
 not_in_distro: list host files that are not in the package
 database
 wandering: check for the case where the build searches for a
 file on the host, then finds it in the project.
 all: all the above

```

从前面代码中附加的帮助信息中，可以调查测试命令所选参数的作用。此外，由于 C 文件中不超过 1550 行，最大的文件是`swabber.c`文件，因此建议检查工具的源代码。

`required.txt`文件包含有关使用的软件包和特定文件的信息。有关配置的更多信息也可以在`extra.txt`文件中找到。这些信息包括可以访问的文件和软件包，各种警告以及主机数据库中不可用的文件，以及各种错误和被视为危险的文件。

对于跟踪的命令，输出信息并不多。这只是一个示例；我鼓励你尝试各种场景，并熟悉这个工具。这可能对你以后有所帮助。

# Wic

Wic 是一个命令行工具，也可以看作是 BitBake 构建系统的扩展。它是由于需要有一个分区机制和描述语言而开发的。很容易得出结论，BitBake 在这些方面存在不足，尽管已经采取了一些措施，以确保这样的功能在 BitBake 构建系统内可用，但这只能在一定程度上实现；对于更复杂的任务，Wic 可以是一个替代解决方案。

在接下来的几行中，我将尝试描述与 BitBake 功能不足相关的问题，以及 Wic 如何以简单的方式解决这个问题。我还将向你展示这个工具是如何诞生的，以及灵感来源是什么。

在使用 BitBake 构建图像时，工作是在继承`image.bbclass`的图像配方中完成的，以描述其功能。在这个类中，`do_rootfs()`任务是负责创建后续将包含在最终软件包中的根文件系统目录的 OS。该目录包含了在各种板上引导 Linux 图像所需的所有源。完成`do_rootfs()`任务后，会查询一系列命令，为每种图像定义类型生成输出。图像类型的定义是通过`IMAGE_FSTYPE`变量完成的，对于每种图像输出类型，都有一个`IMAGE_CMD_type`变量被定义为从外部层继承的额外类型，或者是在`image_types.bbclass`文件中描述的基本类型。

实际上，每种类型背后的命令都是针对特定的根文件系统格式的 shell 命令。其中最好的例子就是`ext3`格式。为此，定义了`IMAGE_CMD_ext3`变量，并调用了这些命令，如下所示：

```
genext2fs -b $ROOTFS_SIZE ... ${IMAGE_NAME}.rootfs.ext3
tune2fs -j ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.ext3

```

在调用命令后，输出以`image-*.ext3`文件的形式呈现。这是根据定义的`FSTYPES`变量值新创建的 EXT3 文件系统，并包含了根文件系统内容。这个例子展示了一个非常常见和基本的文件系统创建命令。当然，在工业环境中可能需要更复杂的选项，这些选项不仅包括根文件系统，还可能包括额外的内核或甚至是引导加载程序。对于这些复杂的选项，需要广泛的机制或工具。

Yocto 项目中可见的可用机制在`image_types.bbclass`文件中通过`IMAGE_CMD_type`变量可见，并具有以下形式：

```
image_types_foo.bbclass:
  IMAGE_CMD_bar = "some shell commands"
  IMAGE_CMD_baz = "some more shell commands"
```

要使用新定义的图像格式，需要相应地更新机器配置，使用以下命令：

```
foo-default-settings.inc
  IMAGE_CLASSES += "image_types_foo"
```

通过在`image.bbclass`文件中使用`inherit ${IMAGE_CLASSES}`命令，新定义的`image_types_foo.bbclass`文件的功能可见并准备好被使用，并添加到`IMAGE_FSTYPE`变量中。

前面的实现意味着对于每个实现的文件系统，都会调用一系列命令。这对于非常简单的文件系统格式是一个很好的简单方法。然而，对于更复杂的文件系统，需要一种语言来定义格式、状态以及图像格式的属性。Poky 中提供了各种其他复杂的图像格式选项，如**vmdk**、**live**和**directdisk**文件类型，它们都定义了一个多阶段的图像格式化过程。

要使用`vmdk`图像格式，需要在`IMAGE_FSTYPE`变量中定义一个`vmdk`值。然而，为了生成和识别这种图像格式，应该可用并继承`image-vmdk.bbclass`文件的功能。有了这些功能，可以发生三件事：

+   在`do_rootfs()`任务中创建了对 EXT3 图像格式的依赖，以确保首先生成`ext3`图像格式。`vmdk`图像格式依赖于此。

+   `ROOTFS`变量被设置为`boot-directdisk`功能。

+   继承了`boot-directdisk.bbclass`。

此功能提供了生成可以复制到硬盘上的映像的可能性。在其基础上，可以生成 `syslinux` 配置文件，并且启动过程还需要两个分区。最终结果包括 MBR 和分区表部分，后跟一个包含引导文件、SYSLINUX 和 Linux 内核的 FAT16 分区，以及用于根文件系统位置的 EXT3 分区。此图像格式还负责将 Linux 内核、`syslinux.cfg` 和 `ldlinux.sys` 配置移动到第一个分区，并使用 `dd` 命令将 EXT3 图像格式复制到第二个分区。在此过程结束时，使用 `tune2fs` 命令为根目录保留空间。

从历史上看，`directdisk` 在其最初版本中是硬编码的。对于每个图像配方，都有一个类似的实现，它镜像了基本实现，并在 `image.bbclass` 功能的配方中硬编码了遗产。对于 `vmdk` 图像格式，添加了 `inherit boot-directdisk` 行。

关于自定义定义的图像文件系统类型，一个示例可以在 `meta-fsl-arm` 层中找到；此示例可在 `imx23evk.conf` 机器定义中找到。此机器添加了下面两种图像文件系统类型：`uboot.mxsboot-sdcard` 和 `sdcard`。

```
meta-fsl-arm/imx23evk.conf
  include conf/machine/include/mxs-base.inc
  SDCARD_ROOTFS ?= "${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.ext3"
  IMAGE_FSTYPES ?= "tar.bz2 ext3 uboot.mxsboot-sdcard sdcard"
```

在前面的行中包含的 `mxs-base.inc` 文件又包含了 `conf/machine/include/fsl-default-settings.inc` 文件，后者又添加了 `IMAGE_CLASSES +="image_types_fsl"` 行，如一般情况所示。使用前面的行提供了首先为 `uboot.mxsboot-sdcard` 格式可用的命令执行 `IMAGE_CMD` 命令的可能性，然后是 `sdcard IMAGE_CMD` 命令特定的图像格式。

`image_types_fsl.bbclass` 文件定义了 `IMAGE_CMD` 命令，如下所示：

```
inherit image_types
  IMAGE_CMD_uboot.mxsboot-sdcard = "mxsboot sd ${DEPLOY_DIR_IMAGE}/u-boot-${MACHINE}.${UBOOT_SUFFIX} \
${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.uboot.mxsboot-sdcard"
```

在执行过程结束时，使用 `mxsboot` 命令调用 `uboot.mxsboot-sdcard` 命令。执行此命令后，将调用 `IMAGE_CMD_sdcard` 特定命令来计算 SD 卡的大小和对齐方式，初始化部署空间，并将适当的分区类型设置为 `0x53` 值，并将根文件系统复制到其中。在此过程结束时，将可用多个分区，并且它们具有相应的 twiddles，用于打包可引导的映像。

有多种方法可以创建各种文件系统，它们分布在大量现有的 Yocto 层中，并且一些文档可供一般公众使用。甚至有许多脚本用于为开发人员的需求创建合适的文件系统。其中一个示例是 `scripts/contrib/mkefidisk.sh` 脚本。它用于从另一种图像格式（即 `live.hddimg`）创建一个 EFI 可引导的直接磁盘映像。然而，一个主要的想法仍然存在：这种类型的活动应该在没有在中间阶段生成的中间图像文件系统的情况下进行，并且应该使用无法处理复杂场景的分区语言。

牢记这些信息，似乎在前面的示例中，我们应该使用另一个脚本。考虑到可以在构建系统内部和外部构建映像的可能性，开始寻找适合我们需求的一些工具。这个搜索结果是 Fedora Kickstart 项目。尽管它的语法也适用于涉及部署工作的领域，但它通常被认为对开发人员最有帮助。

### 注意

有关 Fedora Kickstart 项目的更多信息，请访问 [`fedoraproject.org/wiki/Anaconda/Kickstart`](http://fedoraproject.org/wiki/Anaconda/Kickstart)。

从这个项目中，最常用和有趣的组件是`clearpart`，`part`和`bootloader`，这些对我们的目的也很有用。当您查看 Yocto 项目的 Wic 工具时，它也可以在配置文件中找到。如果 Wic 的配置文件在 Fedora kickstart 项目中定义为`.wks`，则配置文件使用`.yks`扩展名。一个这样的配置文件定义如下：

```
def pre():
    free-form python or named 'plugin' commands

  clearpart commands
  part commands
  bootloader commands
  named 'plugin' commands

  def post():
    free-form python or named 'plugin' commands  
```

前面脚本背后的想法非常简单：`clearpart`组件用于清除磁盘上的任何分区，而`part`组件用于相反的操作，即用于创建和安装文件系统的组件。定义的第三个工具是`bootloader`组件，用于安装引导加载程序，并处理从`part`组件接收到的相应信息。它还确保引导过程按照配置文件中的描述进行。定义为`pre()`和`post()`的函数用于创建图像、阶段图像工件或其他复杂任务的预和后计算。

如前述描述所示，与 Fedora kickstarter 项目的交互非常富有成效和有趣，但源代码是在 Wic 项目内使用 Python 编写的。这是因为搜索了一个类似工具的 Python 实现，并在`pykickstarted`库的形式下找到了。这并不是 Meego 项目在其**Meego Image Creator**（**MIC**）工具中使用的前述库的全部用途。该工具用于 Meego 特定的图像创建过程。后来，该项目被 Tizen 项目继承。

### 注意

有关 MIC 的更多信息，请参阅[`github.com/01org/mic`](https://github.com/01org/mic)。

Wic，我承诺在本节中介绍的工具，源自 MIC 项目，它们两者都使用 kickstarter 项目，因此所有三者都基于定义了创建各种图像格式过程行为的插件。在 Wic 的第一个实现中，它主要是 MIC 项目的功能。在这里，我指的是它定义的 Python 类，几乎完全复制到了 Poky 中。然而，随着时间的推移，该项目开始拥有自己的实现，也有了自己的个性。从 Poky 存储库的 1.7 版本开始，不再直接引用 MIC Python 定义的类，使 Wic 成为一个独立的项目，具有自己定义的插件和实现。以下是您可以检查 Wic 中可访问的各种格式配置的方法：

```
tree scripts/lib/image/canned-wks/
scripts/lib/image/canned-wks/
├── directdisk.wks
├── mkefidisk.wks
├── mkgummidisk.wks
└── sdimage-bootpart.wks
```

Wic 中定义了配置。然而，考虑到这个工具近年来的兴趣增加，我们只能希望支持的配置数量会增加。

我之前提到 MIC 和 Fedora kickstarter 项目的依赖关系已经被移除，但在 Poky `scripts/lib/wic`目录中快速搜索会发现情况并非如此。这是因为 Wic 和 MIC 都有相同的基础，即`pykickstarted`库。尽管 Wic 现在在很大程度上基于 MIC，并且两者都有相同的父级，即 kickstarter 项目，但它们的实现、功能和各种配置使它们成为不同的实体，尽管相关，但它们已经走上了不同的发展道路。

# LAVA

**LAVA**（**Linaro 自动化和验证架构**）是一个连续集成系统，专注于物理目标或虚拟硬件部署，其中执行一系列测试。执行的测试种类繁多，从只需要启动目标的最简单测试到需要外部硬件交互的非常复杂的场景。

LAVA 代表一系列用于自动验证的组件。LAVA 堆栈的主要思想是创建一个适用于各种规模项目的质量受控测试和自动化环境。要更仔细地查看 LAVA 实例，读者可以检查已经创建的实例，由 Linaro 在剑桥托管的官方生产实例。您可以在[`validation.linaro.org/`](https://validation.linaro.org/)访问它。希望您喜欢使用它。

LAVA 框架支持以下功能：

+   它支持在各种硬件包上对多个软件包进行定期自动测试

+   确保设备崩溃后系统会自动重新启动

+   它进行回归测试

+   它进行持续集成测试

+   它进行平台启用测试

+   它支持本地和云解决方案

+   它提供了结果捆绑支持

+   它提供性能和功耗的测量

LAVA 主要使用 Python 编写，这与 Yocto 项目提供的内容没有什么不同。正如在 Toaster 项目中看到的那样，LAVA 还使用 Django 框架进行 Web 界面，项目使用 Git 版本控制系统进行托管。这并不奇怪，因为我们正在谈论 Linaro，这是一个致力于自由开源项目的非营利组织。因此，应用于项目的所有更改应返回到上游项目，使项目更容易维护。但是，它也更健壮，性能更好。

### 注意

对于那些对如何使用该项目的更多细节感兴趣的人，请参阅[`validation.linaro.org/static/docs/overview.html`](https://validation.linaro.org/static/docs/overview.html)。

使用 LAVA 框架进行测试，第一步是了解其架构。了解这一点不仅有助于测试定义，还有助于扩展测试，以及整个项目的开发。该项目的主要组件如下：

```
               +-------------+
               |web interface|
               +-------------+
                      |
                      v
                  +--------+
            +---->|database|
            |     +--------+
            |
+-----------+------[worker]-------------+
|           |                           |
|  +----------------+     +----------+  |
|  |scheduler daemon|---→ |dispatcher|  |
|  +----------------+     +----------+  |
|                              |        |
+------------------------------+--------+
                               |
                               V
                     +-------------------+
                     | device under test |
                     +-------------------+
```

第一个组件**Web 界面**负责用户交互。它用于存储数据和使用 RDBMS 提交作业，并负责显示结果、设备导航，或者通过 XMLRPC API 进行作业提交接收活动。另一个重要组件是**调度程序守护程序**，负责分配作业。它的活动非常简单。它负责从数据库中汇集数据，并为由调度程序提供给它们的作业保留设备，调度程序是另一个重要组件。**调度程序**是负责在设备上运行实际作业的组件。它还管理与设备的通信，下载图像并收集结果。

有时只能使用调度程序的情况；这些情况涉及使用本地测试或测试功能开发。还有一些情况，所有组件都在同一台机器上运行，比如单个部署服务器。当然，理想的情况是组件解耦，服务器在一台机器上，数据库在另一台机器上，调度程序守护程序和调度程序在另一台机器上。

对于使用 LAVA 进行开发过程，推荐的主机是 Debian 和 Ubuntu。与 LAVA 合作的 Linaro 开发团队更喜欢 Debian 发行版，但它也可以在 Ubuntu 机器上很好地运行。有一些需要提到的事情：对于 Ubuntu 机器，请确保宇宙存储库可供包管理器使用并可见。

必需的第一个软件包是`lava-dev`；它还有脚本指示必要的软件包依赖项，以确保 LAVA 工作环境。以下是执行此操作所需的必要命令：

```
sudo apt-get install lava-dev
git clone http://git.linaro.org/git/lava/lava-server.git
cd lava-server
/usr/share/lava-server/debian-dev-build.sh lava-server

git clone http://git.linaro.org/git/lava/lava-dispatcher.git
cd lava-dispatcher
/usr/share/lava-server/debian-dev-build.sh lava-dispatcher

```

考虑到更改的位置，需要采取各种行动。例如，对于“模板”目录中的 HTML 内容的更改，刷新浏览器就足够了，但在`*_app`目录的 Python 实现中进行的任何更改都需要重新启动`apache2ctl`HTTP 服务器。此外，`*_daemon`目录中的 Python 源代码的任何更改都需要完全重新启动`lava-server`。

### 注意

对于所有对获取有关 LAVA 开发的更多信息感兴趣的人，开发指南构成了一份良好的文档资源，可在[`validation.linaro.org/static/docs/#developer-guides`](https://validation.linaro.org/static/docs/#developer-guides)找到。

要在 64 位 Ubuntu 14.04 机器上安装 LAVA 或任何与 LAVA 相关的软件包，除了启用通用存储库`deb http://people.linaro.org/~neil.williams/lava jessie main`之外，还需要新的软件包依赖项，以及之前为 Debian 发行版描述的安装过程。我必须提到，当安装`lava-dev`软件包时，用户将被提示进入一个菜单，指示`nullmailer mailname`。我选择让默认值保持不变，实际上这是运行`nullmailer`服务的计算机的主机名。我还保持了默认为`smarthost`定义的相同配置，并且安装过程已经继续。以下是在 Ubuntu 14.04 机器上安装 LAVA 所需的命令：

```
sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"
sudo apt-get update
sudo add-apt-repository "deb http://people.linaro.org/~neil.williams/lava jessie main"
sudo apt-get update

sudo apt-get install postgresql
sudo apt-get install lava
sudo a2dissite 000-default
sudo a2ensite lava-server.conf
sudo service apache2 restart

```

### 注意

有关 LAVA 安装过程的信息可在[`validation.linaro.org/static/docs/installing_on_debian.html#`](https://validation.linaro.org/static/docs/installing_on_debian.html#)找到。在这里，您还可以找到 Debian 和 Ubuntu 发行版的安装过程。

# 总结

在本章中，您被介绍了一组新的工具。我必须诚实地承认，这些工具并不是在嵌入式环境中最常用的工具，但它们被引入是为了为嵌入式开发环境提供另一个视角。本章试图向开发人员解释，嵌入式世界不仅仅是开发和帮助这些任务的工具。在大多数情况下，相邻的组件可能是对开发过程影响最大的组件。

在下一章中，将简要介绍 Linux 实时要求和解决方案。我们将强调在这一领域与 Linux 一起工作的各种功能。将提供 meta-realtime 层的简要介绍，并讨论 Preempt-RT 和 NOHZ 等功能。话不多说，让我们继续下一章。希望您会喜欢它的内容。
