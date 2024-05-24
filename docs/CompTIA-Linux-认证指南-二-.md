# CompTIA Linux 认证指南（二）

> 原文：[`zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E`](https://zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：设计硬盘布局

在前一章中，我们专注于运行级别和引导目标。我们与运行`init`和`systemd`的 Linux 系统进行了交互。我们看到了如何启动服务，以及如何在运行级别和引导目标之间切换。我们查看了各种启动和停止脚本，还查看了脚本的结构。

本章重点介绍在 CLI 中创建分区和分割物理硬盘。我们将特别关注`fdisk`实用程序和`parted`实用程序的使用。然后，我们将逐步介绍使用各种`mkfs`命令创建、删除和定义分区类型以及格式化硬盘的步骤。最后，我们将探讨挂载和卸载分区的方法。

因此，我们将在本章中涵盖以下主题：

+   使用`fdisk`实用程序

+   使用`parted`实用程序

+   格式化硬盘的步骤

+   挂载和卸载分区

# 使用 fdisk 实用程序

在 Linux 中，每当我们使用硬盘时，我们很可能会在某个时候**分区硬盘**。*分区*简单地意味着分离硬盘。这使我们能够拥有不同大小的分区，并使我们能够满足各种软件安装要求。此外，当我们分区硬盘时，每个分区都被操作系统视为完全独立的硬盘。`fdisk`（固定磁盘或格式化磁盘）是一个基于命令行的实用程序，可用于操作硬盘。使用`fdisk`，您可以查看、创建、删除和更改等操作。

首先，让我们在 Ubuntu 分发中公开硬盘：

```
philip@ubuntu:~$ ls /dev/ | grep sd
sda
sda1
sda2
sda5
philip@ubuntu:~$
```

从前面的输出中，系统中的硬盘由`/dev/sda`表示。第一个分区是`/dev/sda1`，第二个分区是`/dev/sda2`，依此类推。为了查看分区信息，我们将运行以下命令：

```
philip@ubuntu:~$ fdisk -l /dev/sda
fdisk: cannot open /dev/sda: Permission denied
philip@ubuntu:~$
```

从前面的输出中，我们得到了`Permission denied`。这是因为我们需要 root 权限来查看和更改硬盘的分区。让我们以 root 用户重试：

```
philip@ubuntu:~$ sudo su
[sudo] password for philip:
root@ubuntu:/home/philip#
root@ubuntu:/home/philip# fdisk -l /dev/sda
Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xf54f42a0

Device   Boot Start     End       Sectors  Size Id  Type
/dev/sda1  *   2048     39845887  39843840 19G 83   Linux
/dev/sda2      39847934 41940991  2093058  1022M  5 Extended
/dev/sda5      39847936 41940991  2093056 1022M 82 Linux swap / Solaris
root@ubuntu:/home/philip#
```

从前面的输出中，阅读的方式如下：

磁盘`/dev/sda`：20 GiB，21,474,836,480 字节，41,943,040 扇区：这是实际的物理硬盘：

| **设备** | **引导 ** | **开始 ** | ** 结束** | ** 扇区** | **大小** | ** ID** | **类型** | **注释** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `/dev/sda1` | *  |  2048 |  39,845,887  |   39,843,840  | 19 G  | 83  |  Linux | 第一分区为 19 GB |
| `/dev/sda2` |  | 39,847,934  | 41,940,991 | 2,093,058 |  1,022 M  |   5 | 扩展 | 第二分区为 1,022 MB |
| `/dev/sda5  ` |  |   39,847,936  |   41,940,991  |   2,093,056  | 1,022 M |  82  | Linux swap / Solaris | 第五分区为 1,022 MB |

现在，为了能够进行任何更改，我们将再次使用`fdisk`命令。这次我们将省略`-l`选项：

```
root@ubuntu:/home/philip# fdisk /dev/sda

Welcome to fdisk (util-linux 2.27.1).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Command (m for help):
```

从前面的代码中，我们现在在`fdisk`实用程序中，并且收到了一条不错的消息。

在进行任何更改之前，请确保您了解删除分区周围的危险；如果删除存储系统文件的分区，系统可能会变得不稳定，例如`/boot/`和`/`。

要查看可用选项，我们可以按`m`键：

```
Command (m for help): m
Help:
 DOS (MBR)
 a   toggle a bootable flag
 b   edit nested BSD disklabel
 c   toggle the dos compatibility flag
Generic
 d   delete a partition
 F   list free unpartitioned space
 l   list known partition types
 n   add a new partition
 p   print the partition table
 t   change a partition type
 v   verify the partition table
 i   print information about a partition

Misc
 m   print this menu
 u   change display/entry units
 x   extra functionality (experts only)
Script
 I   load disk layout from sfdisk script file
 O   dump disk layout to sfdisk script file

Save & Exit
 w   write table to disk and exit
 q   quit without saving changes
Create a new label
 g   create a new empty GPT partition table
 G   create a new empty SGI (IRIX) partition table
 o   create a new empty DOS partition table
 s   create a new empty Sun partition table

Command (m for help):
```

从前面的输出中，我们可以看到各种选择。我们甚至可以使用`l`来查看已知的分区类型：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00057.jpeg)

从前面的截图中，我们可以看到各种可用于使用的不同分区类型。常见类型包括`5 Extended`，`7 NTFS NTSF`，`82 Linux swap`，83（Linux），`a5 FreeBSD`，`ee GPT`和`ef EFI`等。

现在，要查看已创建的分区，我们可以使用`p`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00058.jpeg)

我已经向该系统添加了第二个硬盘，因此让我们验证一下：

```
root@ubuntu:/home/philip# ls /dev/ | grep sd
sda
sda1
sda2
sda5
sdb
root@ubuntu:/home/philip#
```

太棒了！我们现在可以看到`/dev/sdb`。我们将使用`fdisk`处理这个新硬盘：

```
root@ubuntu:/home/philip# fdisk /dev/sdb

Welcome to fdisk (util-linux 2.27.1).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Device does not contain a recognized partition table.
Created a new DOS disklabel with disk identifier 0x0079e169.
Command (m for help):
```

现在，让我们按下`p`，这将打印`/dev/sdb`上的当前分区：

```
Command (m for help): p
Disk /dev/sdb: 15 GiB, 16106127360 bytes, 31457280 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x0079e169

Command (m for help):
```

如您所见，`/dev/sdb`上没有分区。为了创建一个分区，我们将使用`n`键：

```
Command (m for help): n
Partition type
 p   primary (0 primary, 0 extended, 4 free)
 e   extended (container for logical partitions)
Select (default p):
```

这将要求我们声明分区的类型。`fdisk`实用程序提供了主分区和扩展分区类型。还有一个逻辑分区类型。为了安装操作系统，我们将选择`p`，代表*主分区类型*。

您不会在逻辑分区类型上安装操作系统。

如您所见，我们使用`n`来创建新分区。需要注意的一个重要点是，到目前为止我们创建的分区都是 Linux 类型的分区。如果出于某种原因我们想要更改分区类型，我们可以使用`t`来更改它。让我们将`/dev/sdb2`更改为`HPFS/NTFS/exFAT`分区。我们将在`fdisk`实用程序中使用`type 7`：

```
Command (m for help): t
Partition number (1-3, default 3): 2
Partition type (type L to list all types): l
0  Empty  24  NEC DOS 81  Minix / old Lin bf  Solaris 
1  FAT12  27  Hidden NTFS Win 82  Linux swap / So c1  DRDOS/sec (FAT-
2  XENIX root  39  Plan 9  83  Linux  c4  DRDOS/sec (FAT-
3  XENIX usr   3c  PartitionMagic 84 OS/2 hidden or c6 DRDOS/sec (FAT-
4  FAT16 <32M  40  Venix 80286     85  Linux extended  c7  Syrinx 
5  Extended   41  PPC PReP Boot   86  NTFS volume set da  Non-FS data 
6  FAT16    42  SFS  87  NTFS volume set db  CP/M / CTOS / .
7  HPFS/NTFS/exFAT
```

太棒了！现在我们可以看到分区类型为`type 7`：

```
Partition type (type L to list all types): 7
Changed type of partition 'Empty' to 'HPFS/NTFS/exFAT'.
Command (m for help): p
Disk /dev/sdb: 15 GiB, 16106127360 bytes, 31457280 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x2584b986
Device       Boot     Start    End      Sectors Size  Id   Type
/dev/sdb1    2048     10487807  10485760  5G      83        Linux
/dev/sdb2    10487808 18876415  8388608   4G      7     HPFS/NTFS/exFAT
/dev/sdb3    18876416 31457279  12580864  6G      0           Empty
```

此外，我们将把`/dev/sdb3`分区更改为类型`ef`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00059.jpeg)

现在当我们重新运行`p`命令时，我们可以看到我们新创建的分区类型设置为`ef`：

```
Device     Boot      Start     End     Sectors Size Id Type
/dev/sdb1   2048     10487807  10485760  5G    83 Linux
/dev/sdb2   10487808 18876415  8388608   4G    7 HPFS/NTFS/exFAT
/dev/sdb3   18876416 31457279  12580864  6G    ef EFI (FAT-12/16/32)
```

现在，如果我们决定安装操作系统，那么我们将不得不使其中一个分区可引导。我们将使第三个分区`/dev/sdb3`可引导：

```
Command (m for help): a 
Partition number (1-3, default 3): 3
The bootable flag on partition 3 is enabled now.
Command (m for help): p
Disk /dev/sdb: 15 GiB, 16106127360 bytes, 31457280 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x2584b986
Device     Boot    Start      End  Sectors Size Id Type
/dev/sdb1           2048 10487807 10485760   5G 83 Linux
/dev/sdb2       10487808 18876415  8388608   4G  7 HPFS/NTFS/exFAT
/dev/sdb3  *    18876416 31457279 12580864   6G ef EFI (FAT-12/16/32)
```

从前面的输出中，`/dev/sdb3`现在标记为可引导。

最后，要更改或保存我们的更改，我们将按`w`，保存并退出：

```
Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00060.jpeg)

# 使用 parted 实用程序

`parted`实用程序是针对我们有一个大于 2TB 的硬盘或硬盘的情况。此外，我们可以调整分区；`fdisk`实用程序无法调整分区。几乎所有较新的 Linux 发行版都支持`parted`实用程序。`parted`来自 GNU；它是一个基于文本的分区实用程序，可以与各种磁盘类型一起使用，例如 MBR、GPT 和 BSD 等。

在对分区进行任何更改之前，请备份数据。

首先，我们将在`/dev/sdb`上使用`parted`命令：

```
root@ubuntu:/home/philip# parted /dev/sdb
GNU Parted 3.2
Using /dev/sdb
Welcome to GNU Parted! Type 'help' to view a list of commands.
(parted)                                                                 
```

从这里，我们进入了`parted`实用程序。与`fdisk`实用程序类似，`parted`实用程序是交互式的。现在让我们假设我们想查看`help`菜单，我们可以在 CLI 中列出`help`：

```
(parted) help 
 align-check TYPE N check partition N for TYPE(min|opt) alignment
 help [COMMAND] print general help, or help on COMMAND
 mklabel,mktable LABEL-TYPE create a new disklabel (partition table)
 mkpart PART-TYPE [FS-TYPE] START END make a partition
 name NUMBER NAME name partition NUMBER as NAME
 print [devices|free|list,all|NUMBER] display the partition table, available devices, free space, all found partitions, or a particular partition
 quit exit program 
 rescue START END rescue a lost partition near START and END
 resizepart NUMBER END resize partition NUMBER
 rm NUMBER delete partition NUMBER
 select DEVICE choose the device to edit
 disk_set FLAG STATE change the FLAG on selected device
 disk_toggle [FLAG] toggle the state of FLAG on selected device
 set NUMBER FLAG STATE change the FLAG on partition NUMBER
 toggle [NUMBER [FLAG]] toggle the state of FLAG on partition NUMBER
```

```
 unit UNIT set the default unit to UNIT
 version display the version number and copyright information of GNU Parted
(parted)
```

从前面的输出中，我们有一长串命令供我们使用。

在对分区进行任何更改之前，请备份数据。

现在，要查看`/dev/sdb`的当前分区表，我们将输入`print`：

```
(parted) print
Model: VMware, VMware Virtual S (scsi)
Disk /dev/sdb: 16.1GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:
Number  Start   End     Size    Type  File system  Flags
 1     1049kB  5370MB 5369MB  primary
 2     5370MB  9665MB 4295MB  primary
 3     9665MB  16.1GB 6441MB  primary boot, esp
(parted) 
```

这将打印出`/dev/sdb`的分区表。但是，我们可以使用`print`命令和`list`选项来查看系统中所有可用的硬盘。让我们试试看：

```
(parted) print list
Model: VMware, VMware Virtual S (scsi)
Disk /dev/sdb: 16.1GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:
Number  Start   End     Size    Type    File system  Flags
 1      1049kB  5370MB  5369MB  primary
 2      5370MB  9665MB  4295MB  primary
 3      9665MB  16.1GB  6441MB  primary            boot, esp
 Model: VMware, VMware Virtual S (scsi)
Disk /dev/sda: 21.5GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:
Number  Start   End     Size    Type      File system     Flags
 1      1049kB  20.4GB  20.4GB  primary   ext4            boot
 2      20.4GB  21.5GB  1072MB  extended
 5      20.4GB  21.5GB  1072MB  logical   linux-swap(v1)
(parted)
```

太好了！如您所见，`/dev/sda`现在也被列出。接下来，让我们看看如何调整分区大小。为了实现这一点，我们将利用另一个强大的命令，即`resizepart`命令，这个命令本身的命名也很合适。

我们将选择第二个分区进行练习；我们将说`resizepart 2`，并将其减少到 2GB：

```
 (parted) resizepart
 Partition number? 2
 End? [5370MB]? 7518
 (parted) print
 Disk /dev/sdb: 16.1GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:
Number Start End Size Type File system Flags
 1 1049kB 5370MB 5369MB primary
 2 5370MB 7518MB 2148MB primary
 3 9665MB 16.1GB 6441MB primary boot, esp
(parted)            
```

从前面的输出中，您可以看到`parted`实用程序非常强大。我们已经有效地从第二个分区中拿走了 2GB（大约）。现在，如果您考虑一下，我们有 2GB 的可用空间。

硬盘空间在大型数据中心中至关重要，因此在为服务器进行配置时请记住这一点。

现在，为了演示我们如何使用 2GB 的可用空间，让我们创建另一个分区。`parted`实用程序非常强大，它可以识别从其他磁盘实用程序（如`fdisk`）创建的分区。在`parted`中，我们将使用`mkpart`命令来创建一个分区：

```
(parted)
(parted) mkpart 
Partition type?  primary/extended? 
```

到目前为止，您可以看到`fdisk`和`parted`之间存在相似之处，它们都会询问分区是主分区还是扩展分区。这在我们处理操作系统安装时非常重要。为了我们的目的，我们将创建另一个主分区：

```
Partition type?  primary/extended? primary
File system type?  [ext2]?
Start?
```

现在，在这一点上，我们将不得不指定我们即将创建的分区的起始大小。我们将使用第二个分区结束的大小：

```
File system type? [ext2]? 
Start? 7518 
End? 9665 
(parted) 
```

太棒了！现在让我们重新运行`print`命令：

```
(parted) print 
Model: VMware, VMware Virtual S (scsi)
Disk /dev/sdb: 16.1GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:
Number Start   End     Size    Type     File system  Flags
 1      1049kB  5370MB  5369MB  primary
 2      5370MB  7518MB  2148MB  primary
 4      7518MB  9665MB  2146MB  primary  ext2         lba
 3      9665MB  16.1GB  6441MB  primary               boot, esp
(parted)
```

从前面的输出中，我们现在可以看到我们新创建的大约 2GB 的分区。

现在我们可以将`boot`标志从当前的第三个分区`/dev/sdb3`移动到第四个分区`/dev/sdb4`。我们将使用`set`命令：

```
(parted) set 
Partition number? 4 
Flag to Invert?
```

从这里开始，我们必须告诉`parted`实用程序，我们要移动`boot`标志：

```
Flag to Invert? boot 
New state?  [on]/off?
```

现在，我们需要确认我们的更改，`on`是默认值，所以我们按*Enter*：

```
New state?  [on]/off? 
(parted) print 
Model: VMware, VMware Virtual S (scsi)
Disk /dev/sdb: 16.1GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:
Number  Start   End     Size    Type     File system  Flags
 1      1049kB  5370MB  5369MB  primary
 2      5370MB  7518MB  2148MB  primary
 4      7518MB  9665MB  2146MB  primary  ext2         boot, lba
 3      9665MB  16.1GB  6441MB  primary               esp
(parted)                                             
```

太棒了！现在我们可以看到`boot`标志已经移动到第四个分区`/dev/sdb4`。

最后，要保存我们的更改，我们只需输入`quit`：

```
(parted) quit 
Information: You may need to update /etc/fstab.
root@ubuntu:/home/philip#     
```

您需要在`/etc/fstab`中添加条目，以便自动挂载分区到它们各自的挂载点。

# 格式化硬盘的步骤

创建分区后，下一步是通过文件系统使分区可访问。在 Linux 中，当我们格式化分区时，系统会擦除分区，这使系统能够在分区上存储数据。

在 Linux 系统中有许多文件系统类型可用。我们使用`mkfs`命令结合所需的文件系统类型。要查看可用的文件系统，我们可以这样做：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00061.jpeg)

从前面的屏幕截图中，在这个 Ubuntu 发行版中，主要是`ext4`类型是当前使用的文件系统。我们还可以使用带有`-f`选项的`lsblk`命令来验证这一点：

```
root@ubuntu:/home/philip# lsblk -f
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00062.jpeg)

从前面的屏幕截图中，我们可以看到两个硬盘，`/dev/sda`和`/dev/sdb`。此外，我们看到了一个`FSTYPE`列。这标识了当前正在使用的文件系统。我们可以看到整个`/dev/sdb(1-4)`的`FSTYPE`为空。

我们也可以使用`blkid`命令查看系统正在使用的文件系统：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00063.jpeg)

从给定的输出中，`TYPE=`部分显示正在使用的文件系统。请注意，对于`/dev/sdb(1-4)`，`TYPE=`都是缺失的。这意味着我们尚未格式化`/dev/sdb`上的任何分区。

现在让我们开始格式化我们的分区。我们将在`/dev/sdb1`上使用`ext4`文件系统：

```
root@ubuntu:/home/philip# mkfs.ext4 /dev/sdb1
mke2fs 1.42.13 (17-May-2015)
Creating filesystem with 1310720 4k blocks and 327680 inodes
Filesystem UUID: fc51dddf-c23d-4160-8e49-f8a275c9b2f0
Superblock backups stored on blocks:
 32768, 98304, 163840, 229376, 294912, 819200, 884736
Allocating group tables: done 
Writing inode tables: done 
Creating journal (32768 blocks): done
Writing superblocks and filesystem accounting information: done
root@ubuntu:/home/philip#
```

从前面的输出中，`mkfs`实用程序，特别是`mkfs.ext4`，在原始分区上创建文件系统；然后为`/dev/sdb1`分区分配一个 UUID 以唯一标识它。

在格式化分区之前，您需要具有 root 权限。

接下来，让我们在`/dev/sdb2`上使用`ext3`文件系统：

```
root@ubuntu:/home/philip# mkfs.ext3 /dev/sdb2
mke2fs 1.42.13 (17-May-2015)
Creating filesystem with 524288 4k blocks and 131328 inodes
Filesystem UUID: fd6aab0f-0f16-4922-86c1-11fcb54fc466
Superblock backups stored on blocks:
 32768, 98304, 163840, 229376, 294912
Allocating group tables: done 
Writing inode tables: done 
Creating journal (16384 blocks): done
Writing superblocks and filesystem accounting information: done
root@ubuntu:/home/philip#
```

现在我们将在`/dev/sdb3`上使用`ext2`，在`/dev/sdb4`上使用`ntfs`：

```
root@ubuntu:/home/philip# mkfs.ext2 /dev/sdb3
mke2fs 1.42.13 (17-May-2015)
Creating filesystem with 1572608 4k blocks and 393216 inodes
Filesystem UUID: b7e075df-541d-468d-ab16-e3ec2e5fb5f8
Superblock backups stored on blocks:
 32768, 98304, 163840, 229376, 294912, 819200, 884736
Allocating group tables: done 
Writing inode tables: done 
Writing superblocks and filesystem accounting information: done
root@ubuntu:/home/philip# mkfs.ntfs /dev/sdb4
Cluster size has been automatically set to 4096 bytes.
Initializing device with zeroes: 100% - Done.
Creating NTFS volume structures.
mkntfs completed successfully. Have a nice day.
root@ubuntu:/home/philip#
```

您还可以使用`mk2fs`来创建`ext2`文件系统。

太棒了！现在我们刚刚格式化了`/dev/sdb1`，`/dev/sdb2`，`dev/sdb3`和`/dev/sdb4`。如果我们现在使用`lsblk`命令和`-f`选项重新运行，我们将看到两个分区的文件系统类型(`FSTYPE`)已经填充：

```
root@ubuntu:/home/philip# lsblk -f
NAME   FSTYPE LABEL UUID                                 MOUNTPOINT
sda 
├─sda1 ext4         adb5d090-3400-4411-aee2-dd871c39db38 /
├─sda2 
└─sda5 swap         025b1992-80ba-46ed-8490-e7aa68271e7b [SWAP]
sdb 
├─sdb1 ext4         fc51dddf-c23d-4160-8e49-f8a275c9b2f0
├─sdb2 ext3         fd6aab0f-0f16-4922-86c1-11fcb54fc466
├─sdb3 ext2         b7e075df-541d-468d-ab16-e3ec2e5fb5f8
└─sdb4 ntfs         1D9E4A6D4088D79A 
sr0 
root@ubuntu:/home/philip#
```

从前面的输出中，我们可以看到`FSTYPE`反映了我们所做的更改。

我们还可以重新运行`blkid`命令，查看为`/dev/sdb1`和`/dev/sdb2`创建的 UUID：

```
root@ubuntu:/home/philip# blkid
/dev/sda1: UUID="adb5d090-3400-4411-aee2-dd871c39db38" TYPE="ext4" PARTUUID="f54f42a0-01"
/dev/sda5: UUID="025b1992-80ba-46ed-8490-e7aa68271e7b" TYPE="swap" PARTUUID="f54f42a0-05"
/dev/sdb1: UUID="fc51dddf-c23d-4160-8e49-f8a275c9b2f0" TYPE="ext4" PARTUUID="7e707ac0-01"
/dev/sdb2: UUID="fd6aab0f-0f16-4922-86c1-11fcb54fc466" SEC_TYPE="ext2" TYPE="ext3" PARTUUID="7e707ac0-02"
/dev/sdb3: UUID="2a8a5768-1a7f-4ab4-8aa1-f45d30df5631" TYPE="ext2" PARTUUID="7e707ac0-03"
/dev/sdb4: UUID="1D9E4A6D4088D79A" TYPE="ntfs" PARTUUID="7e707ac0-04"
root@ubuntu:/home/philip#
```

如您所见，系统现在可以存储有关各个分区的信息。

# 挂载和卸载分区

在格式化分区后的最后一步是挂载分区。我们使用`mount`命令来挂载分区，使用`unmount`命令来卸载分区。`mount`命令还用于查看系统中当前的挂载点。但是，在重新启动后，除非我们在`/etc/fstab`目录中创建了条目，否则所有分区都将被卸载。

在`/etc/fstab`中保存任何更改都需要 root 权限。在进行任何更改之前，也要备份任何配置文件。

# 挂载命令

我们可以发出`mount`命令而不带任何参数来查看当前的挂载点：

```
root@ubuntu:/home/philip# mount
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=478356k,nr_inodes=119589,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size=99764k,mode=755)
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup(rw,relatime,user_id=0,group_id=0,default_permissions,allow_other)
tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev,relatime,size=99764k,mode=700,uid=1000,gid=1000)
gvfsd-fuse on /run/user/1000/gvfs type fuse.gvfsd-fuse (rw,nosuid,nodev,relatime,user_id=1000,group_id=1000)
root@ubuntu:/home/philip#
```

出于简洁起见，部分输出被省略。

从前面的输出中，我们可以看到许多挂载点（挂载点只是将分区/驱动器与文件夹/目录关联起来）。我们可以过滤`mount`命令，只显示`/dev/`：

```
root@ubuntu:/home/philip# mount | grep /dev
udev on /dev type devtmpfs (rw,nosuid,relatime,size=478356k,nr_inodes=119589,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
mqueue on /dev/mqueue type mqueue (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime)
root@ubuntu:/home/philip#
```

根据过滤器，我们可以看到`/dev/sda1`目前挂载在`/`目录上。如您所知，`/`目录是根目录。所有其他目录都属于`/`目录。

我们还可以使用带有`-h`选项的`df`命令查看更简洁的输出：

```
root@ubuntu:/home/philip# df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            468M     0  468M   0% /dev
tmpfs            98M  6.2M   92M   7% /run
/dev/sda1        19G  5.1G   13G  29% /
tmpfs           488M  212K  487M   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           488M     0  488M   0% /sys/fs/cgroup
tmpfs            98M   44K   98M   1% /run/user/1000
root@ubuntu:/home/philip#
```

太好了！现在这是以结构化格式呈现的，更容易阅读。根据输出，只有`/dev/sda1`分区当前被挂载。

现在我们可以继续挂载`/dev/sdb1`到`/mnt`上。`/mnt`是一个空目录，我们在想要挂载分区时使用它。

一次只能挂载一个分区。

我们将运行以下`mount`命令：

```
root@ubuntu:/# mount /dev/sdb1 /mnt
root@ubuntu:/#
```

请注意，没有任何选项，`mount`命令可以正常工作。现在让我们重新运行`mount`命令，并过滤只显示`/dev`：

```
root@ubuntu:/# mount | grep /dev
udev on /dev type devtmpfs (rw,nosuid,relatime,size=478356k,nr_inodes=119589,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
mqueue on /dev/mqueue type mqueue (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime)
/dev/sdb1 on /mnt type ext4 (rw,relatime,data=ordered)
root@ubuntu:/#
```

根据前面的输出，我们可以看到`/dev/sdb1`目前挂载在`/mnt`上。

我们还可以利用带有`h`选项的`df`命令来查看类似的结果：

```
root@ubuntu:/# df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            468M     0  468M   0% /dev
tmpfs            98M  6.2M   92M   7% /run
/dev/sda1        19G  5.1G   13G  29% /
tmpfs           488M  212K  487M   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           488M     0  488M   0% /sys/fs/cgroup
tmpfs            98M   44K   98M   1% /run/user/1000
/dev/sdb1       4.8G   10M  4.6G   1% /mnt
root@ubuntu:/#
```

从前面的输出中，我们可以看到分区的大小以及与分区关联的挂载点。

现在让我们创建两个目录，用于`/dev/sdb2`和`/dev/sdb4`分区：

```
root@ubuntu:/# mkdir /folder1
root@ubuntu:/# mkdir /folder2
root@ubuntu:/# ls
bin  dev   folder2  initrd.img.old  lost+found  opt run srv usr      vmlinuz.old
boot etc  home lib   media    proc  sbin  sys  var
cdrom  folder1  initrd.img  lib64     mnt         root  snap  tmp  vmlinuz
root@ubuntu:/#
```

现在我们将把`/dev/sdb2`和`/dev/sdb4`挂载到`/folder1`和`/folder2`目录中：

```
root@ubuntu:/# mount /dev/sdb2 /folder1
root@ubuntu:/# mount /dev/sdb4 /folder2
root@ubuntu:/#
root@ubuntu:/# mount | grep /dev
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/sdb1 on /mnt type ext4 (rw,relatime,data=ordered)
/dev/sdb2 on /folder1 type ext3 (rw,relatime,data=ordered)
/dev/sdb4 on /folder2 type fuseblk (rw,relatime,user_id=0,group_id=0,allow_other,blksize=4096)
root@ubuntu:/#
```

太好了！现在我们可以看到我们的挂载点在`mount`命令中显示出来。同样，我们可以使用带有`-h`选项的`df`命令以可读的格式显示：

```
root@ubuntu:/# df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            468M     0  468M   0% /dev
tmpfs            98M  6.2M   92M   7% /run
/dev/sda1        19G  5.1G   13G  29% /
tmpfs           488M  212K  487M   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           488M     0  488M   0% /sys/fs/cgroup
tmpfs            98M   44K   98M   1% /run/user/1000
/dev/sdb1       4.8G   10M  4.6G   1% /mnt
/dev/sdb2       2.0G  3.1M  1.9G   1% /folder1
/dev/sdb4       2.0G   11M  2.0G   1% /folder2
root@ubuntu:/#
```

正如您所看到的，挂载分区的步骤非常简单。但是，在某些发行版上，您将不得不指定文件系统类型。在网络中，挂载共享是一种常见的操作。挂载共享的一个例子如下：

```
root@ubuntu:/#mount //172.16.175.144/share /netshare -t cifs  -o user=philip,password=pass123,uid=1000,gid=1000,rw
```

# 卸载命令

在挂载了分区并进行了更改之后，清理和卸载分区总是一个好主意。我们使用`unmount`命令来卸载分区。

在运行`unmount`命令之前，始终更改/移出目录。

让我们卸载`/dev/sdb1`。格式如下：

```
root@ubuntu:/# umount /dev/sdb1
root@ubuntu:/#
root@ubuntu:/# mount | grep /dev
udev on /dev type devtmpfs (rw,nosuid,relatime,size=478356k,nr_inodes=119589,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
mqueue on /dev/mqueue type mqueue (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime)
/dev/sdb2 on /folder1 type ext3 (rw,relatime,data=ordered)
/dev/sdb4 on /folder2 type fuseblk (rw,relatime,user_id=0,group_id=0,allow_other,blksize=4096)
root@ubuntu:/#
```

现在我们可以看到`/dev/sdb1`不再挂载；我们也可以使用`df`命令来确认：

```
root@ubuntu:/# df -h
Filesystem Size Used Avail Use% Mounted on
udev 468M 0 468M 0% /dev
tmpfs 98M 7.5M 91M 8% /run
/dev/sda1 19G 5.2G 13G 30% /
tmpfs 488M 212K 487M 1% /dev/shm
tmpfs 5.0M 4.0K 5.0M 1% /run/lock
tmpfs 488M 0 488M 0% /sys/fs/cgroup
tmpfs 98M 48K 98M 1% /run/user/1000
/dev/sdb2 2.0G 3.1M 1.9G 1% /folder1
/dev/sdb4 2.0G 11M 2.0G 1% /folder2
root@ubuntu:/#
```

我们还可以使用`lsblk`命令来确认相同的情况：

```
root@ubuntu:/# lsblk -f
NAME   FSTYPE LABEL UUID       MOUNTPOINT
sda 
├─sda1 ext4         adb5d090-3400-4411-aee2-dd871c39db38 /
├─sda2 
└─sda5 swap         025b1992-80ba-46ed-8490-e7aa68271e7b [SWAP]
sdb 
├─sdb1 ext4         fc51dddf-c23d-4160-8e49-f8a275c9b2f0
├─sdb2 ext3         fd6aab0f-0f16-4922-86c1-11fcb54fc466 /folder1
├─sdb3 ext2         2a8a5768-1a7f-4ab4-8aa1-f45d30df5631
└─sdb4 ntfs         1D9E4A6D4088D79A                     /folder2
sr0 
root@ubuntu:/#
```

现在让我们也卸载`/dev/sdb2`：

```
root@ubuntu:/# umount /folder1
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00064.jpeg)

从前面的截图中，您会注意到，我使用了目录`/folder1`而不是分区`/dev/sdb2`；这完全取决于您；它们都被接受。此外，我们可以从`lsblk`命令中看到，`/dev/sdb2`没有列出挂载点。

现在，假设您希望在系统重新启动期间保持挂载点。那么，请放心，我们可以通过在`/etc/fstab`中创建条目来实现这一点。

首先，让我们在`/etc/fstab`中为`/dev/sdb4`创建一个条目。我们将使用`/dev/sdb4`的 UUID 来帮助我们。让我们运行`blkid`并保存`/dev/sdb4`的 UUID：

```
root@ubuntu:/# blkid
/dev/sdb4: UUID="1D9E4A6D4088D79A" TYPE="ntfs" PARTUUID="7e707ac0-04"
root@ubuntu:/#
```

现在让我们编辑`/etc/fstab`文件：

```
# /etc/fstab: static file system information. #
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/sda1 during installation
UUID=adb5d090-3400-4411-aee2-dd871c39db38 / ext4 errors=remount-ro 0       1
# swap was on /dev/sda5 during installation
UUID=025b1992-80ba-46ed-8490-e7aa68271e7b none swap sw 0   0
/dev/fd0  /media/floppy0  auto   rw,user,noauto,exec,utf8 0  0
UUID=1D9E4A6D4088D79A   /folder2   ntfs    0       0
```

现在最后一个条目引用了`/dev/sdb4`。格式以分区开头，由`UUID`表示，然后是`挂载点`，`文件系统`，`转储`和`通过`。

当系统重新启动时，`/dev/sdb4`将被挂载到`/folder2`上。这样可以避免重复输入。

# 总结

在本章中，我们看了如何格式化硬盘以及各种可用的分区实用程序。我们使用`fdisk`实用程序创建了分区，并打开了`boot`标志。然后我们看了`parted`实用程序，以及如何创建分区；此外，我们还看到了如何调整分区的大小。这在数据中心环境中非常有用。然后我们格式化了我们的分区，这使我们能够开始存储数据。我们研究了使用各种`mkfs`命令。然后我们专注于如何挂载我们的分区。在我们的挂载点上保存数据后，我们卸载了我们的分区/挂载点。最后，我们看到了如何通过在`/etc/fstab`文件中创建条目来避免重复输入；这在启动时为我们挂载了我们的分区。

接下来，在下一章中，我们将介绍安装各种 Linux 发行版。我们将特别关注红帽发行版，即 CentOS。另一方面，我们将介绍 Debian 发行版，特别是 Ubuntu 以及安装 Linux 发行版的最佳技术，这些技术在不同的发行版之间略有不同。此外，我们将介绍双引导环境，让我们面对现实吧，迟早你会在 Linux 职业生涯中接触到 Windows 操作系统。不过，你不用担心，因为我们会逐步详细介绍安装过程的每一步。完成下一章后，你肯定会在跨所有平台上安装 Linux 发行版的方法上变得更加熟练。安装 Linux 发行版所获得的技能将对您作为 Linux 工程师大有裨益。

# 问题

1.  哪个字母用于列出硬盘的分区，而不进入`fdisk`实用程序？

A. `fdisk –a /dev/sda`

B. `fdisk –c /dev/sda`

C. `fdisk –l /dev/sda`

D. `fdisk –r /dev/sda`

1.  哪个字母用于在`fdisk`实用程序内创建分区？

A. *b*

B. *c*

C. *r*

D. *n*

1.  哪个字母用于在`fdisk`实用程序内切换引导标志？

A. *b*

B. *a*

C. *d*

D. *c*

1.  哪个字母用于在`fdisk`实用程序内打印已知的分区类型？

A. *l*

B. *r*

C. *n*

D. *b*

1.  哪个字母用于在`fdisk`实用程序内创建分区？

A. *p*

B. *n*

C. *c*

D. *d*

1.  哪个字母用于在`fdisk`实用程序内写入更改？

A. *q*

B. *c*

C. *d*

D. *w*

1.  哪个命令用于启动`parted`实用程序？

A. `part -ad`

B. `parted`

C. `part -ed`

D. `part`

1.  哪个选项用于在`parted`实用程序内显示分区表？

A. `display`

B. `parted`

C. `print`

D. `console`

1.  哪个选项用于从 CLI 中挂载分区？

A. `mount /dev/sdb1`

B. `mnt /dev/sdb1`

C. `mt /dev/sdb1`

D. `mont /dev/sdb1`

1.  哪个命令在 CLI 上显示已知分区的 UUID？

A. `blkid`

B. `df -h`

C. `du -h`

D. `mount`

# 进一步阅读

+   您可以通过查看以下内容获取有关 CentOS 发行版的更多信息，例如安装、配置最佳实践等：[`www.centos.org`](https://www.centos.org)。

+   以下网站为您提供了许多有用的技巧和 Linux 社区用户的最佳实践，特别是适用于 Debian 发行版（如 Ubuntu）的：[`askubuntu.com`](https://askubuntu.com)。

+   最后，这个链接为您提供了与在 CentOS 和 Ubuntu 上运行的各种命令相关的一般信息。您可以在那里发布您的问题，其他社区成员将会回答：[`www.linuxquestions.org`](https://www.linuxquestions.org)。


# 第五章：安装 Linux 发行版

在上一章中，我们看了准备好用的硬盘。我们使用了`fdisk`和`parted`实用程序。我们看到了创建和删除分区的步骤。我们还看到了如何调整分区的大小。然后，我们将注意力转向格式化分区以供使用。我们看了今天 Linux 发行版上可用的各种文件系统。之后，我们看了如何挂载分区以开始存储数据。然后我们看了如何卸载分区。最后，我们在`/etc/fstab`文件中创建条目，以便在系统启动时加载我们的挂载点。在本章中，我们现在的重点是实际安装 Linux 发行版，以及从头开始安装 Linux 时涉及的过程。然后，我们将专注于在 Windows 操作系统旁边安装 Linux。最后，我们将看看如何在另一个 Linux 发行版旁边安装 Linux。

在本章中，我们将学习以下主题：

+   了解 LiveCD 的用途

+   作为全新安装安装 Linux 发行版

+   在 Windows 操作系统旁边安装 Linux 发行版

+   与另一种 Linux 发行版并存安装 Linux 发行版

# 了解 LiveCD 的用途

当我们启动系统时，在安装 Linux 发行版时，我们有许多选项可供选择。我们可以使用 LiveCD 来安装 Linux，而不是擦除我们的硬盘。请记住，体验可能看起来好像我们正在安装 Linux 发行版，但实际上我们实际上是将文件临时加载到 RAM 中，而 LiveCD 则表现得好像它安装在实际硬盘上一样。这就是 LiveCD 的主要概念。

我们将在此演示中使用 Ubuntu 发行版。首先，我们将设置系统从 CD/DVD 启动。然后我们启动系统：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00065.gif)

在这里，我们有许多选项可供选择。第一个选项将把 Linux 发行版加载到内存中。其他选项，如“安装 Ubuntu”，将用于正常安装。我们还可以检查光盘是否有缺陷等。

现在，使用光标，突出显示“尝试 Ubuntu 而不安装”，然后按*Enter*。之后，系统将启动到 Linux 发行版：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00066.jpeg)

从这里，我们可以执行各种任务，就像在已安装的操作系统上一样。当您的硬件资源不足或您有非常老旧的硬件无法支持最新的操作系统时，这就有了好处。放心，有许多适用于这种环境的 Linux 发行版可供选择。

另外，请注意我们可以从驱动器中取出 CD/DVD，系统将继续工作而不会出现任何错误。大多数情况下，我们将使用 LiveCD 执行管理任务。

# 作为全新安装安装 Linux 发行版

当我们只想执行一些管理任务时，在 LiveCD 中工作是可以的。为此，我们可以将 Linux 发行版作为完整安装进行安装；在硬盘上安装 Linux。为了继续 LiveCD 演示，我们将使用桌面上的“安装 Ubuntu...”选项来执行全新安装。这将呈现以下设置：

1.  从这里开始，我们必须选择继续安装的语言。有很多语言可供选择。在我们的情况下，我们将接受默认的英语，并选择继续：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00067.jpeg)

1.  现在，我们有选项在安装过程中下载更新和/或安装用于图形等的第三方软件。对于这一部分，您需要一个活动的互联网连接；原因是系统将去下载最近发布的更新。此外，当我们添加不属于系统的其他硬件时，它们需要模块（类似驱动程序），这些模块不会默认安装。因此，有第二个选项来下载第三方软件。在我们的情况下，因为我们在实验室环境中，我们将取消这些选项并选择继续：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00068.jpeg)

您需要一个活动的互联网连接来下载更新。

1.  在这里，我们有选项在整个硬盘上安装 Linux 发行版。如果出于某种原因，我们想要向硬盘添加一个或多个分区，那么我们将选择“其他”。此外，如果我们试图在 Windows 上进行双引导或在另一个 Linux 发行版上进行并排安装，我们将选择此选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00069.jpeg)

1.  对于新安装，让我们选择“其他”并创建自己的分区，并指定我们要挂载的内容：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00070.jpeg)

1.  太棒了！我们的环境中只有一个硬盘。我们将选择新分区表。让我们首先创建一个 200MB 的分区并挂载`/boot`；这是存储引导文件的地方：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00071.jpeg)

为`/boot`创建一个分区总是一个好主意，以保护引导文件。

1.  接下来，让我们创建一个 13GB 的分区，并指定它应该挂载到`/`目录上。此外，我们还指定分区类型为主分区，并将分区格式化为`ext3`文件系统：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00072.jpeg)

1.  接下来，让我们创建一个 5GB 的分区，并指定它应该挂载到`/home`。这是用户文件的存储位置：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00073.jpeg)

1.  太棒了！最后，让我们利用剩余的空间，让 Linux 发行版分配给交换内存：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00074.jpeg)

从前面的截图中，您会注意到没有挂载点选项可用。这是因为我们指定剩余的空间应该用作交换区。系统将根据需要使用交换区（我们在前面的章节中看到过；即第一章，*配置硬件设置*，在*查看 CPU、RAM、交换信息*部分）。

1.  分区完成后，我们可以选择继续。这将显示一个警告消息：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00075.jpeg)

接下来，我们将看到区域设置，并搜索您的国家并填写。在我的情况下，我在圭亚那；这个国家位于南美洲，所以我选择圭亚那然后继续。

1.  之后，会出现键盘选择，您需要选择适当的设置。这将带我们来到设置的关键部分：用户创建屏幕。我们为计算机指定一个名称，并创建一个带有超级秘密密码的用户帐户：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00076.jpeg)

太棒了！现在我们正要安装一个新的 Linux 发行版。

1.  您可以通过选择位于“正在安装系统”旁边的下拉箭头来随时检查正在下载或安装的文件：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00077.jpeg)

现在安装将下载各种语言包（需要互联网连接）。之后，设置将继续将必要的文件安装到硬盘上。

最后，系统会要求我们重新启动以启动系统，使用新安装的 Linux 发行版。

安装完成后，拔掉 CD、DVD 或 USB 驱动器，然后再系统启动之前。

# 在 Windows 操作系统旁边安装 Linux 发行版

在大多数环境中，您可能会遇到已经安装了其他操作系统（如 Windows）的系统。理想情况下，您不会完全删除 Windows 安装，因为您可能需要一些仅在 Windows 安装上运行的软件，或者可能是公司政策要求在系统上安装 Windows。在这种情况下，您可以在 Windows 旁边安装 Linux 发行版，而不会擦除 Windows 分区。这是可能的，因为 Linux 有能力识别 Windows 分区类型，如 NTFS。Linux 不会以任何方式改变 Windows 分区。

让我们启动现有的 Windows 系统，并配置系统从 Ubuntu ISO 映像启动，看看我们如何实现双启动安装：

1.  从这里开始，Ubuntu 安装将识别 Windows 10 操作系统。我们将选择最后一个选项“其他”：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00078.jpeg)

1.  接下来，我们将创建`/boot`分区：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00079.jpeg)

1.  之后，我们将创建`/`分区：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00080.jpeg)

从上面的屏幕截图中，我们可以看到我们刚刚成功创建了`/`分区。您可能已经注意到我们创建分区的模式。将系统文件与用户文件分开始终是一个好主意。

1.  接下来，我们将创建`/home`分区：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00081.jpeg)

1.  最后，我们将创建交换空间并使用剩余的空间：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00082.jpeg)

1.  最后一步是选择立即安装：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00083.jpeg)

从上面的屏幕截图中，我们将不得不确认我们是否要将更改写入磁盘。我们将选择“继续”。

我们可以随时返回并通过选择返回进行更改分区表。

现在，我们必须填写位置设置，类似于进行全新安装。我会再次选择圭亚那。

接下来，我们必须像之前一样创建一个用户帐户。必要的 Linux 文件将被安装到我们的双启动系统上。

1.  之后，我们将被提示重新启动系统，并将在 GRUB2 的双启动菜单中受到欢迎，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00084.jpeg)

在某些情况下，如果我们将 Linux 作为第一个操作系统，然后安装 Windows，有时 Windows 会删除 Linux 的启动项。解决此问题的最佳工具是运行`grub-install`。

# 在另一种 Linux 旁边安装 Linux

在某些环境中，您可能需要适应不同的 Linux 发行版。您可以在不丢失当前的 Linux 发行版的情况下安装另一个发行版。

让我们使用现有的 Ubuntu 系统并安装 CentOS 7 以演示如何进行双启动：

1.  首先，我们设置系统从 CentOS 7 ISO 映像启动：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00085.gif)

1.  从这里，我们选择第一个选项并按*Enter*。这将启动 CentOS 7 的设置：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00086.jpeg)

然后选择我们的语言并选择继续。

1.  在“安装摘要”页面上，关键重要的部分是“软件选择”和“系统”：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00087.jpeg)

1.  默认情况下，CentOS 7 将进行最小安装。我们想要进行完整安装，因此选择“软件选择”：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00088.jpeg)

从上面的屏幕截图中，默认情况下选择了最小安装。我在“基本环境”下选择了 GNOME 桌面，并选择了选中的附加组件。完成选择后，我将点击“完成”。

您可以选择为特定基本环境添加一些或所有附加组件。

1.  在双启动环境中特别重要的下一部分在“系统”部分下：安装目的地。

1.  这里是我们将对硬盘进行分区的地方：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00089.jpeg)

1.  默认情况下，系统将选择自动对硬盘进行分区。如果我们保留这个选项，允许系统为我们创建分区，那么系统将根据每个分区的推荐大小创建分区。为了演示的目的，我们将选择“我将配置分区”。这将说明在 CentOS 7 环境中创建分区涉及的各个步骤。接下来，我们将选择“完成”。这将带来分区屏幕：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00090.jpeg)

从前面的屏幕截图中，我们可以看到 CentOS 7 安装已经检测到了 Ubuntu 安装。

对于这个 CentOS 7 安装，我们将`/boot`挂载到 CentOS 7 的`/boot`挂载点。

在删除分区时要小心，因为这可能会对系统的运行状态产生一些不利影响。换句话说，您可能会意外删除一些存储在分区上的关键配置文件，或者更糟糕的是，您的系统可能无法启动。

1.  接下来，我们为 CentOS 7 创建`/`分区：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00091.jpeg)

1.  然后我们创建`/home`分区：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00092.jpeg)

1.  最后，我们使用剩余的空间创建交换空间：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00093.jpeg)

1.  完成后，我们选择“完成”：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00094.jpeg)

1.  现在，我们必须通过选择“接受更改”来确认我们的更改：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00095.jpeg)

1.  当我们选择开始安装时，实际的安装将开始。我们将不得不创建一个用户帐户：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00096.jpeg)

1.  然后我们需要设置一个 root 密码：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00097.jpeg)

1.  我们应该设置一个没有人能猜到的复杂密码：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00098.jpeg)

1.  现在，我们要允许 CentOS 7 执行安装——给它一些时间。最后，我们被提示重新启动，所以我们会选择重新启动。

1.  最后，我们迎来了双引导菜单，显示了 CentOS 7 和 Ubuntu，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00099.jpeg)

如您所见，我们现在可以选择加载哪个 Linux 发行版。

# 总结

在本章中，我们深入探讨了 Linux 发行版的安装。我们讨论了 LiveCD 的概念。我们讨论了使用 LiveCD 的场景；也就是说，当我们想要测试、当我们有硬件资源或正在执行一些管理任务时。然后我们演示了使用 LiveCD。请记住，实际的 Linux 发行版是从硬盘以外的介质运行的。它通过将一些文件加载到 RAM 中来实现这一点。LiveCD 提供的一个明显优势是它不会干扰您的基础操作系统。然后我们将注意力转向进行 Linux 发行版的全新安装。执行全新安装的步骤在不同的发行版之间有所不同。之后，我们专注于在 Windows 和 Linux 之间进行双引导，特别是 Windows 10 和 Ubuntu。最后，我们结束了本章，通过在 Linux 发行版之间进行双引导，特别是 CentOS 和 Ubuntu，来结束本章。

接下来，我们将要涵盖红帽世界的另一面：Debian 环境。换句话说，我们将主要关注 Ubuntu 环境下的软件包管理，涵盖诸如`dpkg`、`apt`和`aptitude`等使用的各种技术。我希望您能加入我，一起迈向实现认证目标的激动人心的新篇章。

# 问题

1.  在使用 LiveCD 时，临时文件存储在哪里？

A. 硬盘

B. LiveCD

C. RAM

D. 以上都不是

1.  哪个选项可以启动 Ubuntu LiveCD？

A. 从第一个硬盘启动

B. 测试完整性

C. 立即安装

D. 试用 Ubuntu 而不安装

1.  在 Ubuntu LiveCD 的桌面上，您会选择哪个选项进行全新安装？

A. 安装 Ubuntu…

B. 试用 Ubuntu 并安装

C. 重新启动并从硬盘启动

D. 全新安装

1.  在进行全新安装时下载更新时，需要什么？

A. 复杂编码

B. 一个活动的互联网连接

C. 从安装媒体复制文件到硬盘

D. 不需要任何要求

1.  哪个选项允许我们在安装类型下创建自己的分区？

A. 其他

B. 擦除整个硬盘

C. 复制整个硬盘

D. 加密整个硬盘

1.  系统要能够启动，需要哪种类型的分区？

A. 逻辑

B. 扩展

C. 主要

D. 次要

1.  为什么我们应该将`/boot`分区与其他分区分开？

A. 能够在`/boot`中下载我们的视频 B. 防止系统因意外删除`/boot`中的文件而无法启动 C. 证明我们知道如何分区

D. 证明所有系统文件都安装在`/boot`中

1.  哪个命令被选择来在 CentOS 7 安装中创建自定义分区？

A. 自动配置分区

B. 我会配置分区

C. 加密我的数据

D. 创建逻辑卷

1.  如果 Windows 安装在尝试进行**双重**启动时删除了 GRUB，那么使用哪个命令来安装 GRUB？

A. `grub-install`

B. `grub`

C. `grub-update`

D. `grub-configure`

1.  对于 CentOS 7，默认的软件选择是什么？

A. GNOME 桌面

B. KDE 桌面

C. XFCE 桌面

D. 最小安装

# 进一步阅读

+   您可以在以下网址获取有关 CentOS 发行版的更多信息，例如安装、配置最佳实践等：[`www.centos.org`](https://www.centos.org)。

+   这个网站为您提供了许多有用的技巧和 Linux 社区用户的最佳实践，特别是针对 Debian 发行版，如 Ubuntu：[`askubuntu.com`](https://askubuntu.com)。

+   这个最后的链接为您提供了一般信息，涉及适用于 CentOS 和 Ubuntu 的各种命令。您可以在那里发布您的问题，其他社区成员会回答：[`www.linuxquestions.org`](https://www.linuxquestions.org)。


# 第六章：使用 Debian 软件包管理

在上一章中，我们重点介绍了安装 Linux 发行版的步骤。我们首先使用了 LiveCD 的概念，而不是常规安装。我们看到了系统如何在没有硬盘的情况下启动。然后我们讨论了为什么要使用 LiveCD。之后，我们将注意力转移到演示如何执行 Linux 发行版的全新安装。重点放在了分区上，特别是常见的挂载点。接下来，我们看到了如何在 Windows 操作系统旁边进行安装。在此之后，我们进行了 Linux 发行版之间的并排安装。

在本章中，我们将继续我们的课程，重点关注软件安装周围的要点。我们将首先看一下 Debian 风格的软件包管理。首先，我们将从`dpkg`命令开始，并查看使用`dpkg`命令的各种方法。此外，我们将查看可以与`dpkg`命令一起使用的各种选项。接下来，我们将把注意力转向`apt-get`实用程序。这是另一个在 Debian 环境中安装应用程序的流行命令。我们将密切关注可以与`apt-get`命令一起使用的选项。之后，重点将转向`aptitude`实用程序。最后，我们将通过查看`synaptic`实用程序来结束。与前面的命令类似，我们将重点关注在 Debian 环境中部署软件的语法。本章讨论的所有实用程序都是在 Debian 环境中管理软件常用的。

在本章中，我们将涵盖以下主题：

+   `dpkg`命令

+   `apt-get`命令

+   `aptitude`命令

+   `synaptic`实用程序

# `dpkg`命令

首先，`dpkg`实用程序是一个低级系统工具，用于提取、分析、解压缩、安装和删除扩展名为`.deb`的软件包。在每个`.deb`文件中由`dpkg`读取的脚本非常重要，因为它们向程序提供有关软件包安装、删除和配置的信息。`dpkg`实用程序位于基于 Debian 的发行版中的软件包管理系统的基础。Debian 软件包`dpkg`提供了`dpkg`实用程序，以及运行时包装系统所必需的其他几个程序；即：`dpkg-deb`、`dpkg-split`、`dpkg-query`、`dpkg-statoverride`、`dpkg-divert`和`dpkg-trigger`。我们可以瞥一眼`/var/log/dpkg.log`文件。其中有大量关于触发器和软件包经过各种解压缩和配置阶段的详细信息。

让我们看看`/var/log/dpkg.log`：

```
philip@ubuntu:~$ cat /var/log/dpkg.log
2018-07-02 06:43:57 startup archives unpack
2018-07-02 06:44:01 install linux-image-4.4.0-130-generic:amd64 <none> 4.4.0-130.156
2018-07-02 06:44:01 status half-installed linux-image-4.4.0-130-generic:amd64 4.4.0-130.156
2018-07-02 06:44:09 status unpacked linux-image-4.4.0-130-generic:amd64 4.4.0-130.156
2018-07-02 06:44:09 status unpacked linux-image-4.4.0-130-generic:amd64 4.4.0-130.156
2018-07-02 06:44:09 install linux-image-extra-4.4.0-130-generic:amd64 <none> 4.4.0-130.156
2018-07-02 06:44:09 status half-installed linux-image-extra-4.4.0-130-generic:amd64 4.4.0-130.156
2018-07-02 06:44:20 status unpacked linux-image-extra-4.4.0-130-generic:amd64 4.4.0-130.156
2018-07-02 06:44:20 status unpacked linux-image-extra-4.4.0-130-generic:amd64 4.4.0-130.156
2018-07-02 06:44:21 upgrade linux-generic:amd64 4.4.0.128.134 4.4.0.130.136
2018-07-02 06:44:21 status half-configured linux-generic:amd64 4.4.0.128.134
2018-07-02 06:44:21 status unpacked linux-generic:amd64 4.4.0.128.134
2018-07-02 06:44:21 status half-installed linux-generic:amd64 4.4.0.128.134
2018-07-02 06:44:21 status half-installed linux-generic:amd64 4.4.0.128.134
2018-07-02 06:44:21 status unpacked linux-generic:amd64 4.4.0.130.136
2018-07-02 06:44:21 status unpacked linux-generic:amd64 4.4.0.130.136
2018-07-02 06:44:21 upgrade linux-image-generic:amd64 4.4.0.128.134 4.4.0.130.136
2018-07-02 06:44:21 status half-configured linux-image-generic:amd64 4.4.0.128.134
2018-07-02 06:44:21 status unpacked linux-image-generic:amd64 4.4.0.128.134
2018-07-02 06:44:21 status half-installed linux-image-generic:amd64 4.4.0.128.134
```

从前面的输出中，我们了解了`dpkg`实用程序正在管理的各种软件包。如果我们想要查看系统上的软件包列表，我们可以使用`l`选项：

```
philip@ubuntu:~$ dpkg -l
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                          Version             Architecture        Description
+++-=============================-===================-===================-================================================================
ii  a11y-profile-manager-indicato 0.1.10-0ubuntu3      amd64               Accessibility Profile Manager - Unity desktop indicator
ii  account-plugin-facebook       0.12+16.04.20160126 all                 GNOME Control Center account plugin for single signon - facebook
ii  account-plugin-flickr         0.12+16.04.20160126 all                 GNOME Control Center account plugin for single signon - flickr
ii  account-plugin-google         0.12+16.04.20160126 all                 GNOME Control Center account plugin for single signon
ii  accountsservice               0.6.40-2ubuntu11.3  amd64               query and manipulate user account information
ii  activity-log-manager          0.9.7-0ubuntu23.16\. amd64               blacklist configuration user interface for Zeitgeist
ii  adduser                       3.113+nmu3ubuntu4   all                 add and remove users and groups
ii  adium-theme-ubuntu            0.3.4-0ubuntu1.1    all                 Adium message style for Ubuntu
ii  app-install-data              15.10               all                 Ubuntu applications (data files)
ii  app-install-data-partner      16.04               all                 Application Installer (data files for partner applications/repos
ii  apparmor                      2.10.95-0ubuntu2.9  amd64               user-space parser utility for AppArmor
ii  appmenu-qt:amd64              0.2.7+14.04.2014030 amd64               application menu for Qt
ii  appmenu-qt5                   0.3.0+16.04.2017021 amd64               application menu for Qt5
ii  apport                        2.20.1-0ubuntu2.18  all                 automatically generate crash reports for debugging
ii  apport-gtk                    2.20.1-0ubuntu2.18  all                 GTK+ frontend for the apport crash report system
```

在前面的输出中，我们从左到右阅读输出。现在我们应该把注意力集中在输出的最右边。这是描述部分；软件包以人类可读的摘要形式呈现，说明了当前安装在该系统上的每个软件包。

我们还可以通过过滤`dpkg`命令来缩小输出范围；让我们只查找`xterm`程序：

```
philip@ubuntu:~$ dpkg -l xterm
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                          Version             Architecture        Description
+++-=============================-===================-===================-================================================================
ii  xterm                         322-1ubuntu1        amd64               X terminal emulator
philip@ubuntu:~$        
```

我们可以使用`--get-selections`验证软件包是否已安装：

```
philip@ubuntu:~$ dpkg --get-selections
a11y-profile-manager-indicator    install
account-plugin-facebook           install
account-plugin-flickr             install
account-plugin-google             install
accountsservice                   install
acl                               install
acpi-support                      install
acpid                             install
activity-log-manager              install
adduser                           install
adium-theme-ubuntu                install
adwaita-icon-theme                install
aisleriot                         install
alsa-base                         install
alsa-utils                        install
amd64-microcode                   install
anacron                           install
apg                               install
app-install-data                  install
app-install-data-partner          install
apparmor                          install
appmenu-qt:amd64                  install
appmenu-qt5                       install
apport                            install
```

我们可以使用`L`选项查看软件包拥有的文件。让我们继续我们的示例：

```
philip@ubuntu:~$ dpkg -L xterm
/.
/etc
/etc/X11
/etc/X11/app-defaults
/etc/X11/app-defaults/UXTerm-color
/etc/X11/app-defaults/UXTerm
/etc/X11/app-defaults/KOI8RXTerm-color
/etc/X11/app-defaults/KOI8RXTerm
/etc/X11/app-defaults/XTerm-color
/usr/share/man/man1/koi8rxterm.1.gz
/usr/share/man/man1/resize.1.gz
/usr/share/man/man1/xterm.1.gz
/usr/share/man/man1/lxterm.1.gz
philip@ubuntu:~$
```

我们可以使用`s`选项在系统中搜索特定的软件包：

```
philip@ubuntu:~$ dpkg -s apache
dpkg-query: package 'apache' is not installed and no information is available
Use dpkg --info (= dpkg-deb --info) to examine archive files,
and dpkg --contents (= dpkg-deb --contents) to list their contents.
philip@ubuntu:~$ dpkg --info apache
dpkg-deb: error: failed to read archive 'apache': No such file or directory
philip@ubuntu:~$
```

在这种情况下，Apache 在这个系统上默认没有安装。

我已经为这个演示下载了一个`tftp`客户端。让我们验证一下`tftp`客户端是否已安装在这个系统上：

```
philip@ubuntu:~/Downloads$ dpkg -l tftp
dpkg-query: no packages found matching tftp
philip@ubuntu:~/Downloads$
```

现在我们将使用`dpkg`命令安装一个软件包。让我们尝试使用`i`选项安装`tftp`客户端软件包：

```
philip@ubuntu:~/Downloads$ dpkg -i tftp_0.17-18_i386.deb
dpkg: error: requested operation requires superuser privilege
philip@ubuntu:~/Downloads$
```

从前面的输出中，您可以看到我们需要 root 权限来安装或删除软件包。让我们以 root 身份重试：

```
root@ubuntu:/home/philip/Downloads# ls -l | grep tftp
-rw-rw-r-- 1 philip philip  17208 Jul 18 08:15 tftp_0.17-18_i386.deb
root@ubuntu:/home/philip/Downloads# 
root@ubuntu:/home/philip/Downloads# dpkg -i tftp_0.17-18_i386.deb
Selecting previously unselected package tftp:i386.
(Reading database ... 241431 files and directories currently installed.)
Preparing to unpack tftp_0.17-18_i386.deb ...
Unpacking tftp:i386 (0.17-18) ...
Setting up tftp:i386 (0.17-18) ...
Processing triggers for man-db (2.7.5-1) ...
root@ubuntu:/home/philip/Downloads#
```

太棒了！现在，让我们使用`dpkg`命令和`l`选项重试一下：

```
root@ubuntu:/home/philip/Downloads# dpkg -l tftp
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                          Version             Architecture        Description
+++-=============================-===================-===================-================================================================
ii  tftp:i386                     0.17-18             i386                Trivial file transfer protocol client
root@ubuntu:/home/philip/Downloads#
```

太棒了！我们现在可以看到我们的`tftp`客户端已列出。我们还可以运行带有`--get-selections`的`dpkg`来验证：

```
root@ubuntu:/home/philip/Downloads# dpkg --get-selections | grep tftp
tftp:i386                                                            install
root@ubuntu:/home/philip/Downloads#
```

当您使用`dpkg`安装软件包时，有时可能会遇到依赖性问题。为了解决这个问题，您需要在使用`dpkg`安装软件包之前下载并安装每个依赖项。

我们还可以使用`dpkg`命令删除软件包。让我们删除在上一个示例中安装的`tftp`软件包。我们将使用`-r`选项：

```
root@ubuntu:/home/philip/Downloads# dpkg -r tftp
(Reading database ... 241438 files and directories currently installed.)
Removing tftp:i386 (0.17-18) ...
Processing triggers for man-db (2.7.5-1) ...
root@ubuntu:/home/philip/Downloads#
```

现在，让我们验证一下`tftp`包确实已被卸载：

```
root@ubuntu:/home/philip/Downloads# dpkg -l tftp
dpkg-query: no packages found matching tftp
root@ubuntu:/home/philip/Downloads#
```

太棒了！但是，当我们使用`-r`选项时，它不会删除配置文件。为了删除软件包以及配置文件，我们应该使用`-P`（清除）选项。下面是它的工作原理：

```
root@ubuntu:/home/philip/Downloads# dpkg -P tftp
(Reading database ... 241438 files and directories currently installed.)
Removing tftp:i386 (0.17-18) ...
Processing triggers for man-db (2.7.5-1) ...
root@ubuntu:/home/philip/Downloads#
```

我们还可以提取软件包的内容而不安装它。我们应该使用`-x`选项：

```
root@ubuntu:/home/philip/Downloads# dpkg -x tftp_0.17-18_i386.deb ./tftp_0.17-18_i386
root@ubuntu:/home/philip/Downloads# ls
root@ubuntu:/home/philip/Downloads# ls tftp_0.17-18_i386
usr
root@ubuntu:/home/philip/Downloads# ls tftp_0.17-18_i386/usr/
bin  share
root@ubuntu:/home/philip/Downloads#
root@ubuntu:/home/philip/Downloads# ls tftp_0.17-18_i386/usr/bin/
tftp
root@ubuntu:/home/philip/Downloads# ls tftp_0.17-18_i386/usr/share/
doc/ man/
root@ubuntu:/home/philip/Downloads# ls tftp_0.17-18_i386/usr/share/
doc  man
root@ubuntu:/home/philip/Downloads#
```

在使用`dpkg`实用程序下载任何软件包并安装之前，我们需要知道系统的正确硬件架构。幸运的是，我们可以使用`dpkg-architecture`命令：

```
root@ubuntu:/home/philip/Downloads# dpkg-architecture
DEB_BUILD_ARCH=amd64
DEB_BUILD_ARCH_BITS=64
DEB_BUILD_ARCH_CPU=amd64
DEB_BUILD_ARCH_ENDIAN=little
DEB_BUILD_ARCH_OS=linux
DEB_BUILD_GNU_CPU=x86_64
DEB_BUILD_GNU_SYSTEM=linux-gnu
DEB_BUILD_GNU_TYPE=x86_64-linux-gnu
DEB_TARGET_ARCH_CPU=amd64
DEB_TARGET_ARCH_ENDIAN=little
DEB_TARGET_ARCH_OS=linux
DEB_TARGET_GNU_CPU=x86_64
DEB_TARGET_GNU_SYSTEM=linux-gnu
DEB_TARGET_GNU_TYPE=x86_64-linux-gnu
DEB_TARGET_MULTIARCH=x86_64-linux-gnu
root@ubuntu:/home/philip/Downloads#
```

根据前面的输出，我们可以看到这个系统支持 32 位或 64 位软件包。我们还可以获取有关软件包用途的有用信息。我们需要使用带有`-s`选项的`dpkg-query`命令：

```
root@ubuntu:/home/philip/Downloads# dpkg-query -s tftp
Package: tftp
Status: install ok unpacked
Priority: optional
Section: net
Installed-Size: 80
Maintainer: Alberto Gonzalez Iniesta <agi@inittab.org>
Architecture: i386
Source: netkit-tftp
Version: 0.17-18
Config-Version: 0.17-18
Replaces: netstd
Depends: netbase, libc6 (>= 2.3)
Description: Trivial file transfer protocol client
Tftp is the user interface to the Internet TFTP (Trivial File Transfer
Protocol), which allows users to transfer files to and from a remote machine.
The remote host may be specified on the command line, in which case tftp uses
host as the default host for future transfers.
root@ubuntu:/home/philip/Downloads#
```

从前面的输出中，我们在底部得到了有关`tftp`软件包用途的描述。

# apt-get 命令

**高级软件包工具**（**APT**）是一个命令行工具，用于与`dpkg`软件包系统进行简单交互。 APT 是管理基于 Debian 的 Linux 发行版（如 Ubuntu）中软件的理想方法。它有效地管理依赖关系，维护大型配置文件，并正确处理升级和降级以确保系统稳定性。`dpkg`本身无法正确处理依赖关系。`apt-get`执行安装、软件包搜索、更新和许多其他操作，以使系统可用的软件包保持最新。保持软件包最新非常重要，因为使用过时的软件包可能会导致系统安全问题。`apt-get`实用程序需要 root 权限，类似于`dpkg`实用程序。

首先，在进行任何软件安装之前，最好的做法是更新软件包数据库。我们应该运行`apt-get` update：

```
root@ubuntu:/home/philip/Downloads# apt-get update
Get:1 http://security.ubuntu.com/ubuntu xenial-security InRelease [107 kB]
Hit:2 http://us.archive.ubuntu.com/ubuntu xenial InRelease 
Get:3 http://security.debian.org/debian-security wheezy/updates InRelease [54.0 kB]
Get:4 http://us.archive.ubuntu.com/ubuntu xenial-updates InRelease [109 kB] 
Ign:3 http://security.debian.org/debian-security wheezy/updates InRelease 
Get:5 http://us.archive.ubuntu.com/ubuntu xenial-backports InRelease [107 kB]
Get:6 http://security.debian.org/debian-security wheezy/updates/main amd64 Packages [589 kB]
Get:21 http://us.archive.ubuntu.com/ubuntu xenial-updates/multiverse amd64 DEP-11 Metadata [5,964 B]
Get:22 http://us.archive.ubuntu.com/ubuntu xenial-backports/main amd64 DEP-11 Metadata [3,328 B]
Get:23 http://us.archive.ubuntu.com/ubuntu xenial-backports/universe amd64 DEP-11 Metadata [5,096 B]
Fetched 6,189 kB in 6s (1,031 kB/s) 
Reading package lists... Done 
root@ubuntu:/home/philip/Downloads#
```

根据前面的输出，第一部分将是`Hit`，`Get`，`Ign`。现在，`Hit`表示软件包版本没有变化，`Get`表示有新版本可用。然后`Ign`表示软件包被忽略。出现`Ign`的原因有很多，从软件包太新到检索文件时出现错误。通常，这些错误是无害的。

现在，在安装应用程序之前，我们可以使用`apt-cache`命令搜索它。假设我们想安装一个即时通讯应用程序。我们可以这样做：

```
root@ubuntu:/home/philip/Downloads# apt-cache search messenger
adium-theme-ubuntu - Adium message style for Ubuntu
totem-plugins - Plugins for the Totem media player
ayttm - Universal instant messaging client
banshee-extension-telepathy - Telepathy extension for Banshee
droopy - mini web server to let others upload files to your computer
dsniff - Various tools to sniff network traffic for cleartext insecurities
ekg2 - instant messenger and IRC client for UNIX systems
ekg2-api-docs - instant messenger and IRC client for UNIX systems - API documentation
ekg2-core - instant messenger and IRC client for UNIX systems - main program
yate-qt4 - YATE-based universal telephony client
yowsup-cli - command line tool that acts as WhatsApp client
empathy-skype - Skype plugin for libpurple messengers (Empathy-specific files)
pidgin-skype - Skype plugin for libpurple messengers (Pidgin-specific files)
pidgin-skype-common - Skype plugin for libpurple messengers (common files)
pidgin-skype-dbg - Skype plugin for libpurple messengers (debug symbols)
root@ubuntu:/home/philip/Downloads#                                                        
```

根据前面的输出，我们可以看到有各种即时通讯软件包可供安装。如果出于某种原因，我们想查看所有可用的软件包，我们可以使用`pkgnames`选项：

```
root@ubuntu:/home/philip/Downloads# apt-cache pkgnames | less
libdatrie-doc
libfstrcmp0-dbg
librime-data-sampheng
xxdiff-scripts
globus-xioperf
edenmath.app
libghc-ansi-wl-pprint-doc
libjson0
zathura-cb
root@ubuntu:/home/philip/Downloads# 
```

我们可以看到各种可以安装到这个系统上的包。通过指定正确的包名称，我们可以看到每个包的简要描述：

```
root@ubuntu:/home/philip/Downloads# apt-cache search zathura-cb
zathura-cb - comic book archive support for zathura
root@ubuntu:/home/philip/Downloads# apt-cache search virtaal
virtaal - graphical localisation editor
root@ubuntu:/home/philip/Downloads# apt-cache search python-logbook
python-logbook - logging system for Python that replaces the standard library's module
python-logbook-doc - logging system for Python that replaces the standard library's module (doc)
root@ubuntu:/home/philip/Downloads#
```

根据前面的输出，我们可以看到我们使用`search`选项传递的各种包的描述。我们还可以使用`show`选项检查包的详细信息：

```
root@ubuntu:/home/philip/Downloads# apt-cache show python-logbook
Package: python-logbook
Priority: optional
Section: universe/python
Source: logbook
Version: 0.12.3-1
Depends: python:any (<< 2.8), python:any (>= 2.7.5-5~)
Suggests: python-logbook-doc
Filename: pool/universe/l/logbook/python-logbook_0.12.3-1_all.deb
Size: 47896
MD5sum: 865ee97095b97f74e362ce3d93a26a9e
SHA1: 812b08f4e4e4dbcd40264a99fa4cd4dff4f62961
SHA256: 3091d5c491e54007da8b510a6f2e463b63f62364938c4f371406cb4511b6232c
Origin: Ubuntu
root@ubuntu:/home/philip/Downloads#
```

我们甚至可以将这些信息过滤，只查找依赖关系。我们应该使用`showpkg`选项：

```
root@ubuntu:/home/philip/Downloads# apt-cache showpkg python-logbook
Package: python-logbook
Versions:
0.12.3-1 (/var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_xenial_universe_binary-amd64_Packages) (/var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_xenial_universe_binary-i386_Packages)
Dependencies:
0.12.3-1 - python:any (3 2.8) python:any (2 2.7.5-5~) python-logbook-doc (0 (null))
Provides:
0.12.3-1 -
Reverse Provides:
root@ubuntu:/home/philip/Downloads#
```

我们还可以使用`stats`选项查看此系统上缓存的统计信息：

```
root@ubuntu:/home/philip/Downloads# apt-cache stats
Total package names: 73419 (1,468 k)
Total package structures: 113356 (4,988 k)
 Normal packages: 84328
 Total buckets in PkgHashTable: 50503
 Unused: 11792
 Used: 38711
 Utilization: 76.6509%
 Average entries: 2.92826
 Longest: 15
 Shortest: 1
Total buckets in GrpHashTable: 50503
 Unused: 11792
 Used: 38711
 Utilization: 76.6509%
 Average entries: 1.89659
 Longest: 8
 Shortest: 1
root@ubuntu:/home/philip/Downloads#
```

现在，我们可以下载一个包而不安装它。我们可以使用`apt-get`的`download`选项：

```
root@ubuntu:/tmp# apt-get download zathura-cb
Get:1 http://us.archive.ubuntu.com/ubuntu xenial/universe amd64 zathura-cb amd64 0.1.5-1 [8,812 B]
Fetched 8,812 B in 0s (40.0 kB/s)
root@ubuntu:/tmp# ls | grep zathura
zathura-cb_0.1.5-1_amd64.deb
root@ubuntu:/tmp#
```

我们还可以安装已下载的软件包。我们需要使用`apt-get`命令指定路径：

```
root@ubuntu:/tmp# apt-get install ./zathura-cb_0.1.5-1_amd64.deb
Reading package lists... Done
Building dependency tree 
Reading state information... Done
You might want to run 'apt-get -f install' to correct these.
The following packages have unmet dependencies:
openssh-server:i386 : Depends: openssh-client:i386 (= 1:6.0p1-4+deb7u7)
 Recommends: ncurses-term:i386
 Recommends: openssh-blacklist:i386 but it is not installable
 Recommends: openssh-blacklist-extra:i386 but it is not installable
openssh-sftp-server:i386 : Breaks: openssh-server (< 1:6.5p1-5)
Breaks: openssh-server:i386 (< 1:6.5p1-5)
E: Unmet dependencies. Try using -f.
root@ubuntu:/tmp#
```

有时候，您可能会遇到前面示例中所见的问题。修复这个问题的最简单方法是使用`-f`选项重新运行`apt-get`命令，不包括软件包名称：

```
root@ubuntu:/tmp# apt-get -f install
Reading package lists... Done
Building dependency tree 
Reading state information... Done
Correcting dependencies... Done
The following packages were automatically installed and are no longer required:
Do you want to continue? [Y/n] y
Preconfiguring packages ...
(Reading database ... 241439 files and directories currently installed.)
Preparing to unpack .../openssh-server_1%3a7.2p2-4ubuntu2.4_i386.deb ...
Unpacking openssh-server:i386 (1:7.2p2-4ubuntu2.4) over (1:6.0p1-4+deb7u7) ...
Processing triggers for ufw (0.35-0ubuntu2) ...
Processing triggers for systemd (229-4ubuntu21.2) ...
Processing triggers for ureadahead (0.100.0-19) ...
Processing triggers for man-db (2.7.5-1) ...
Setting up openssh-server:i386 (1:7.2p2-4ubuntu2.4) ...
Setting up tftp:i386 (0.17-18) ...
root@ubuntu:/tmp#
```

看吧！正如我们所看到的，安装成功了。这就是`apt-get`实用程序的伟大之处。它找到了需要的依赖项，并提供安装它们以解决报告的问题。我们还可以同时安装多个应用程序。我们只需将每个软件包名称放在同一行上，用空格分隔：

```
root@ubuntu:/tmp# apt-get install virtaal vsftpd
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following packages were automatically installed and are no longer required:
 libllvm3.8 libpango1.0-0 libpangox-1.0-0 libqmi-glib1 linux-headers-4.4.0-21 linux-headers-4.4.0-21-generic linux-image-4.4.0-21-generic
 linux-image-extra-4.4.0-21-generic
Use 'sudo apt autoremove' to remove them.
The following additional packages will be installed: 
 javascript-common libglade2-0 libjs-jquery libjs-sph
Do you want to continue? [Y/n] y
Get:1 http://us.archive.ubuntu.com/ubuntu xenial/main amd64 libglade2-0 amd64 1:2.6.4-2 [44.6 kB]
Get:2 http://us.archive.ubuntu.com/ubuntu xenial/main amd64 javascript-common all 11 [6,066 B]
Get:3 http://us.archive.ubuntu.com/ubuntu xenial/main amd64 libjs-jquery all 1.11.3+dfsg-4 [161 kB]
Get:4 http://us.archive.ubuntu.com/ubuntu xenial/main amd64 libjs-underscore all 1.7.0~dfsg-1ubuntu1 [46.7 kB]
Get:5 http://us.archive.ubuntu.com/ubuntu xenial-updates/main amd64 libjs-sphinxdoc all 1.3.6-2ubuntu1.1 [57.6 kB]
Get:6 http://us.archive.ubuntu.com/ubuntu xenial-updates/main amd64 libpq5 amd64 9.5.13-0ubuntu0.16.04 [78.7 kB]
Setting up virtaal (0.7.1-1) ...
Setting up python-iniparse (0.4-2.2) ...
Setting up vsftpd (3.0.3-3ubuntu2) ...
Processing triggers for libc-bin (2.23-0ubuntu10) ...
Processing triggers for systemd (229-4ubuntu21.2) ...
Processing triggers for ureadahead (0.100.0-19) ...
root@ubuntu:/tmp#
```

太棒了！现在您可以看到`apt-get`实用程序的强大之处。我们还可以通过使用`upgrade`选项升级当前安装的所有软件包：

```
root@ubuntu:/tmp# apt-get upgrade
Reading package lists... Done
Building dependency tree 
Reading state information... Done
Calculating upgrade... Done
The following packages were automatically installed and are no longer required:
The following packages were automatically installed and are no longer required:
 libllvm3.8 libpango1.0-0 libpangox-1.0-0 libqmi-glib1 linux-headers-4.4.0-21 linux-headers-4.4.0-21-generic linux-image-4.4.0-21-generic
 linux-image-extra-4.4.0-21-generic
Use 'sudo apt autoremove' to remove them.
The following packages have been kept back: 
 libegl1-mesa libgbm1 libgl1-mesa-dri libwayland-egl1-mesa libxatracker2
The following packages will be upgraded:
 apt apt-transport-https apt-utils base-files cups cups-bsd cups-client cups-common cups-core-drivers cups-daemon cups-ppdc
63 upgraded, 0 newly installed, 0 to remove and 5 not upgraded.
Need to get 67.1 MB/160 MB of archives.
After this operation, 1,333 kB disk space will be freed.
Do you want to continue? [Y/n] y
root@ubuntu:/tmp#
```

我们还可以删除先前使用过的一些软件包，以确保特定软件包已正确安装。在我们的情况下，如果我们重新运行`upgrade`选项，我们应该会看到这个：

```
root@ubuntu:/tmp# apt-get upgrade
Reading package lists... Done
Building dependency tree 
Reading state information... Done
Calculating upgrade... Done
The following packages were automatically installed and are no longer required:
libllvm3.8 libpango1.0-0 libpangox-1.0-0 libqmi-glib1 linux-headers-4.4.0-21 linux-headers-4.4.0-21-generic linux-image-4.4.0-21-generic
linux-image-extra-4.4.0-21-generic
Use 'sudo apt autoremove' to remove them.
The following packages have been kept back:
libegl1-mesa libgbm1 libgl1-mesa-dri libwayland-egl1-mesa libxatracker2
0 upgraded, 0 newly installed, 0 to remove and 5 not upgraded.
root@ubuntu:/tmp#
```

我们应该按建议使用`autoremove`选项释放一些磁盘空间：

```
root@ubuntu:/tmp# apt-get autoremove
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following packages will be REMOVED:
libllvm3.8 libpango1.0-0 libpangox-1.0-0 libqmi-glib1 linux-headers-4.4.0-21 linux-headers-4.4.0-21-generic linux-image-4.4.0-21-generic
linux-image-extra-4.4.0-21-generic
0 upgraded, 0 newly installed, 8 to remove and 5 not upgraded.
After this operation, 339 MB disk space will be freed.
Do you want to continue? [Y/n] y
(Reading database ... 244059 files and directories currently installed.)
Removing libllvm3.8:amd64 (1:3.8-2ubuntu4) ...
Removing libpango1.0-0:amd64 (1.38.1-1) ...
Removing libpangox-1.0-0:amd64 (0.0.2-5) ...
done
Processing triggers for libc-bin (2.23-0ubuntu10) ...
root@ubuntu:/tmp#
```

我们还可以使用`clean`选项释放磁盘空间：

```
root@ubuntu:/tmp# apt-get clean
root@ubuntu:/tmp#
```

我们可以看到，命令运行得非常快。

定期清理磁盘空间是最佳实践。

我们还可以使用`remove`选项删除一个应用程序。这将删除应用程序，但不会删除配置：

```
root@ubuntu:/tmp# apt-get remove virtaal
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following packages were automatically installed and are no longer required:
javascript-common libglade2-0 libjs-jquery libjs-sphinxdoc libjs-underscore libpq5 libtidy-0.99-0 python-babel python-babel-localedata
python-bs4 python-cairo python-chardet python-dateutil python-diff-match-patch python-egenix-mxdatetime python-egenix-mxtools
python-enchant python-gi python-glade2 python-gobject python-gobject-2 python-gtk2 python-html5lib python-iniparse python-levenshtein
python-lxml python-pkg-resources python-psycopg2 python-pycurl python-simplejson python-six python-tz python-utidylib python-vobject
python-xapian translate-toolkit
Use 'sudo apt autoremove' to remove them.
The following packages will be REMOVED:
virtaal
0 upgraded, 0 newly installed, 1 to remove and 5 not upgraded.
After this operation, 3,496 kB disk space will be freed.
Do you want to continue? [Y/n] y
root@ubuntu:/tmp#
```

然后我们会运行`autoremove`选项来清理不必要的软件包。

# 自动删除选项

通常，当我们卸载一个软件包时，会有一些不必要的软件包最初安装，以便特定软件包能够正常运行。这些不需要的软件包占用了硬盘空间；我们可以使用`autoremove`选项来回收空间：

```
root@ubuntu:/tmp# apt-get autoremove virtaal
Reading package lists... Done
Building dependency tree 
Reading state information... Done
Package 'virtaal' is not installed, so not removed
The following packages will be REMOVED:
javascript-common libglade2-0 libjs-jquery libjs-sphinxdoc libjs-underscore libpq5 libtidy-0.99-0 python-babel python-babel-localedata
python-bs4 python-cairo python-chardet python-dateutil python-diff-match-patch python-egenix-mxdatetime python-egenix-mxtools
python-enchant python-gi python-glade2 python-gobject python-gobject-2 python-gtk2 python-html5lib python-iniparse python-levenshtein
python-lxml python-pkg-resources python-psycopg2 python-pycurl python-simplejson python-six python-tz python-utidylib python-vobject
python-xapian translate-toolkit
0 upgraded, 0 newly installed, 36 to remove and 5 not upgraded.
After this operation, 34.6 MB disk space will be freed.
Do you want to continue? [Y/n] y
Processing triggers for libc-bin (2.23-0ubuntu10) ...
Processing triggers for man-db (2.7.5-1) ...
Processing triggers for doc-base (0.10.7) ...
Processing 4 removed doc-base files...
root@ubuntu:/tmp#
```

太棒了！我们可以使用`purge`选项删除软件包及其配置。

# 清除选项

当使用`purge`选项时，不仅会删除软件包，还会删除软件包配置文件。这是理想的，因为大多数情况下，当我们使用`uninstall`卸载软件包时，它会在系统中留下不需要的配置文件。以下是我们如何使用`purge`选项：

```
root@ubuntu:/tmp# apt-get purge virtaal
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following packages will be REMOVED:
 virtaal*
0 upgraded, 0 newly installed, 1 to remove and 5 not upgraded.
After this operation, 0 B of additional disk space will be used.
Do you want to continue? [Y/n] y
Removing virtaal (0.7.1-1) ...
Purging configuration files for virtaal (0.7.1-1) ...
root@ubuntu:/tmp#
```

太棒了！

定期使用`clean`选项运行`apt-get`命令总是一个好主意。

每当我们使用`apt`实用程序安装软件包时，它会使用存储库将软件包下载到缓存中。默认情况下，当我们安装 Debian 发行版时，安装会附带官方存储库。这些存储在`/etc/apt/sources.list`文件中。让我们来看看那个文件：

```
root@ubuntu:/tmp# cat /etc/apt/sources.list
#deb cdrom:[Ubuntu 16.04 LTS _Xenial Xerus_ - Release amd64 (20160420.1)]/ xenial main restricted
 # See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://us.archive.ubuntu.com/ubuntu/ xenial main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial main restricted
 ## Major bug fix updates produced after the final release of the
## distribution.
deb http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted
## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu
## team, and may not be under a free licence. Please satisfy yourself as to
## your rights to use the software. Also, please note that software in
## universe WILL NOT receive any review or updates from the Ubuntu security
## team.
deb http://us.archive.ubuntu.com/ubuntu/ xenial universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial universe
# deb-src http://security.ubuntu.com/ubuntu xenial-security universe
deb http://security.ubuntu.com/ubuntu xenial-security multiverse
# deb-src http://security.ubuntu.com/ubuntu xenial-security multiverse
root@ubuntu:/tmp#
```

以`deb`开头的条目指的是搜索软件包的位置。以`deb-src`开头的条目指的是源软件包。

# aptitude 命令

Aptitude 是 APT 的前端，它是 Debian 软件包管理器。它最适合在没有图形界面的 shell 环境中使用。`aptitude`命令允许用户查看软件包列表，并执行安装、删除或升级软件包等软件包管理任务。还有交互模式；此外，它可以用作类似于`apt-get`的命令行工具。

我们可以通过简单输入`aptitude`命令而不传递任何选项来看到这一点：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00100.jpeg)

在前面的截图中显示的屏幕上，我们可以使用键盘或鼠标进行交互导航。顶部有一个菜单。我们可以从菜单中选择操作并查看可用选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00101.jpeg)

我们还可以直接从菜单中转到软件包，并查看类似于从命令行进行软件包管理的选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00102.jpeg)

正如我们所看到的，当我们使用这种方法进行软件包管理时，`aptitude`非常直观。

我们还可以使用命令行来管理软件包。如果我们更喜欢在菜单类型的环境中输入命令，那么我们需要使用`aptitude`命令传递选项。`aptitude`命令支持大多数我们会使用`apt-get`命令传递的选项。让我们从`search`选项开始：

# 搜索选项

当我们执行`search`选项时，`aptitude`命令会根据`search`选项后指定的标准搜索可能的匹配项：

```
root@ubuntu:/home/philip# aptitude search vlc
p   browser-plugin-vlc                                 - multimedia plugin for web browsers based on VLC 
p   browser-plugin-vlc:i386                            - multimedia plugin for web browsers based on VLC 
p   libvlc-dev                                         - development files for libvlc 
p   libvlc-dev:i386                                    - development files for libvlc 
p   libvlc5                                            - multimedia player and streamer library 
p   vlc                                                - multimedia player and streamer 
p   vlc:i386                                           - multimedia player and streamer 
root@ubuntu:/home/philip#     
```

根据前面的输出，我们可以看到`aptitude`命令与 APT 的模式相似。我们还可以通过传递`update`选项来安装和更新软件包列表：

```
root@ubuntu:/home/philip# aptitude update
Hit http://us.archive.ubuntu.com/ubuntu xenial InRelease 
Get: 1 http://security.ubuntu.com/ubuntu xenial-security InRelease [107 kB]
Get: 2 http://us.archive.ubuntu.com/ubuntu xenial-updates InRelease [109 kB] 
Get: 3 http://us.archive.ubuntu.com/ubuntu xenial-backports InRelease [107 kB] 
Get: 4 http://us.archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages [809 kB]
Get: 5 http://security.ubuntu.com/ubuntu xenial-security/main amd64 Packages [524 kB]
Get: 6 http://us.archive.ubuntu.com/ubuntu xenial-updates/main i386 Packages [738 kB]
Get: 7 http://security.ubuntu.com/ubuntu xenial-security/main i386 Packages [461 kB]
root@ubuntu:/home/philip#
```

在更新软件包列表后，我们可以通过传递`safe-upgrade`选项来升级软件包：

```
root@ubuntu:/home/philip# aptitude safe-upgrade
Resolving dependencies... 
The following NEW packages will be installed:
 libllvm6.0{a}
The following packages will be REMOVED:
 libllvm5.0{u}
The following packages will be upgraded:
 libegl1-mesa libgbm1 libgl1-mesa-dri libwayland-egl1-mesa libxatracker2
5 packages upgraded, 1 newly installed, 1 to remove and 0 not upgraded.
Need to get 21.6 MB of archives. After unpacking 14.1 MB will be used.
Do you want to continue? [Y/n/?] y
Installing new version of config file /etc/drirc ...
Setting up libegl1-mesa:amd64 (18.0.5-0ubuntu0~16.04.1) ...
Setting up libwayland-egl1-mesa:amd64 (18.0.5-0ubuntu0~16.04.1) ...
Processing triggers for libc-bin (2.23-0ubuntu10) ... 
Current status: 0 (-5) upgradable.
root@ubuntu:/home/philip#
```

我们还可以通过传递`install`选项来安装软件包：

```
root@ubuntu:/home/philip# aptitude install vlc
The following NEW packages will be installed:
i965-va-driver{a} liba52-0.7.4{a} libaacs0{a} libass5{a} libavcodec-ffmpeg56{a} libavformat-ffmpeg56{a}
libavutil-ffmpeg54{a} libbasicusageenvironment1{a} libbdplus0{a} libbluray1{a} libcddb2{a} libchromaprint0{a}
libcrystalhd3{a} libdc1394-22{a} libdca0{a} libdirectfb-1.2-9{a} libdvbpsi10{a} libdvdnav4{a} libdvdread4{a}
vlc-plugin-notify{a} vlc-plugin-samba{a}
0 packages upgraded, 73 newly installed, 0 to remove and 0 not upgraded.
Need to get 23.7 MB of archives. After unpacking 119 MB will be used.
Do you want to continue? [Y/n/?] y
Setting up va-driver-all:amd64 (1.7.0-1ubuntu0.1) ...
Processing triggers for libc-bin (2.23-0ubuntu10) ...
Processing triggers for vlc-nox (2.2.2-5ubuntu0.16.04.4) ... 
root@ubuntu:/home/philip#
```

太棒了！我们还可以删除软件包。我们只需传递`remove`选项：

```
root@ubuntu:/home/philip# aptitude remove vlc
The following packages will be removed: 
 i965-va-driver{u} liba52-0.7.4{u} libaacs0{u} libass5{u} libavcodec-ffmpeg56{u} libavformat-ffmpeg56{u}
 libzvbi-common{u} libzvbi0{u} mesa-va-drivers{u} va-driver-all{u} vlc vlc-data{u} vlc-nox{u} vlc-plugin-notify{u} vlc-plugin-samba{u}
Do you want to continue? [Y/n/?] y
Processing triggers for desktop-file-utils (0.22-1ubuntu5.2) ...
Processing triggers for libc-bin (2.23-0ubuntu10) ...
Processing triggers for hicolor-icon-theme (0.15-0ubuntu1) ... 
root@ubuntu:/home/philip#
```

太棒了！正如你所看到的，`aptitude`命令对于任何 Linux 管理员都非常有用。

# synaptic 实用程序

这是一种基于 APT 的图形化软件包管理形式。这个强大的图形界面实用程序使我们能够在易于使用的环境中安装、更新或删除软件包。使用`synaptic`实用程序使我们能够管理软件包，而无需在命令提示符下工作。让我们来看看 Ubuntu 18 系统中的`synaptic`实用程序。`synaptic`实用程序在 Ubuntu 18 中默认未安装。我们可以使用`apt-cache`命令在安装之前查看有关`synaptic`实用程序的信息：

```
root@ubuntu:/home/philip# apt-cache showpkg synaptic
 Package: synaptic
 Versions:
 0.83 (/var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_xenial_universe_binary-amd64_Packages)
 Description Language:
 File: /var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_xenial_universe_binary-amd64_Packages
 MD5: d4fb8e90c9684f1113e56123c017d85f
 Reverse Depends:
 aptoncd,synaptic 0.57.7
 apt,synaptic
 mate-menu,synaptic
 lubuntu-desktop,synaptic
 cinnamon-desktop-environment,synaptic
 update-notifier,synaptic 0.75.12
 apt,synaptic
 update-manager,synaptic
 Dependencies:
 0.83 - libapt-inst2.0 (2 0.8.16~exp12) libapt-pkg5.0 (2 1.1~exp9) libc6 (2 2.14) libept1.5.0 (0 (null)) libgcc1 (2 1:3.0) libgdk-pixbuf2.0-0 (2 2.22.0) libglib2.0-0 (2 2.14.0) libgtk-3-0 (2 3.3.16) libpango-1.0-0 (2 1.14.0) libstdc++6 (2 5.2) libvte-2.91-
 root@ubuntu:/home/philip#
```

根据前面的屏幕截图，我们可以看到`synaptic`实用程序依赖于许多依赖项。让我们使用`apt-get`命令安装`synaptic`实用程序：

```
root@ubuntu:/home/philip# apt-get install synaptic
 Reading package lists... Done
 Building dependency tree
 Reading state information... Done
 The following NEW packages will be installed:
 docbook-xml libept1.5.0 librarian0 rarian-compat sgml-data synaptic
 0 upgraded, 6 newly installed, 0 to remove and 81 not upgraded.
 Need to get 1,785 kB of archives.
 After this operation, 11.6 MB of additional disk space will be used.
 Do you want to continue? [Y/n] y
Setting up docbook-xml (4.5-7.3) ...
 Processing triggers for sgml-base (1.26+nmu4ubuntu1) ...
 root@ubuntu:/home/philip#
```

我们刚刚安装了`synaptic`实用程序。我们可以从 Ubuntu 18 系统左上角的**搜索您的计算机**按钮启动`synaptic`实用程序，以探索其功能，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00103.jpeg)

一旦我们选择`synaptic`软件包管理器，它将提示我们进行身份验证，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00104.jpeg)

认证后，我们将看到`synaptic`实用程序。我们可以使用搜索按钮来查找特定的软件包。以下屏幕截图描述了搜索功能对话框：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00105.jpeg)

干得漂亮！如前面的屏幕截图所示，我们可以通过简单输入所需的软件包名称来进行搜索。与命令行对应物相比，使用图形界面要容易得多。要进行搜索，我们只需选择搜索按钮。此外，我们可以通过简单选择重新加载按钮来从`synaptic`实用程序内更新软件包数据库：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00106.jpeg)

太棒了！正如你所看到的，`synaptic`实用程序非常直观。它可以以类似于其他图形界面程序的方式进行导航。

# 摘要

在本章中，我们专注于软件包管理的各种方法。首先，我们深入研究了软件包管理的传统方式；也就是使用`dpkg`实用程序。我们探讨了查看系统上当前软件包的方法。我们还涉及查询特定软件包的方法。然后我们看了软件包安装文件的各种位置。除此之外，我们还进行了一个实际的软件包安装。然后我们验证了软件包确实已安装。接着是删除软件包。接下来，我们将注意力转向更常见的软件包管理方法；即 APT。我们使用最佳实践，即始终将`update`选项与`apt`一起传递。然后我们专注于搜索软件包的方法。除此之外，我们还查看了当前的软件包。此外，我们还专注于获取有关特定软件包的一些有用信息。

接着是安装软件包。然后我们发现可以在单个`apt-get`命令中安装多个软件包。接着是演示如何更新软件包。此外，我们还看到了如何使用`apt-get`命令删除软件包。最后，我们使用了`aptitude`。`aptitude`命令本身提供了一个用户交互式、菜单驱动的环境。我们还研究了如何在`aptitude`命令中传递选项。最初，我们更新了软件包列表。然后升级了软件包。除此之外，我们还了解了搜索软件包的技巧。然后使用命令行执行了软件包安装。在此之后，我们进行了一个命令行上删除软件包的演示。最后，我们以命令行的替代方式结束，即`synaptic`实用程序。基于 APT 的`synaptic`实用程序是用于软件包管理的 GUI。

在下一章中，我们将深入探讨 Red-Hat 软件包管理的世界；特别是 Fedora。我们将介绍各种技术，如`rpm`、`yum`、`dnf`和`yumex`，用于管理软件包。我希望您能加入，因为我相信在阅读下一章后，您将更好地掌握 Red Hat 世界中的软件包管理。这将最终让您更接近认证。

# 问题

1.  `dpkg`命令的哪个选项用于显示`dpkg`在系统上管理的软件包？

A. `dpkg -a`

B. `dpkg -l`

C. `dpkg -i`

D. `dpkg –d`

1.  `dpkg-query`的哪个选项用于显示软件包的可读描述？

A. `dpkg-query -a`

B. `dpkg-query-c`

C. `dpkg-query -s`

D. `dpkg-query-r`

1.  哪个日志文件用于显示`dpkg`软件包相关的消息？

A. `cat /var/log/dpkg.log`

B. `cat /var/dpkg/dpkg.log`

C. `cat /var/dpkg-query/dpkg.log`

D. `cat /var/log/dpkg.dpkg`

1.  哪个选项用于显示使用`dpkg`命令安装的软件包？

A. `dpkg --get-selections`

B. `dpkg –set-selections`

C. `dpkg –get-selection`

D. `dpkg-query –get-selection`

1.  哪个选项用于使用`dpkg`命令添加软件包？

A. `dpkg -e`

B. `dpkg –r`

C. `dpkg -Add`

D. `dpkg -i`

1.  哪个选项用于使用`dpkg`命令删除软件包及其配置文件？

A. `dpkg -p`

B. `dpkg-e`

C. `dpkg -P`

D. `dpkg-a`

1.  哪个选项用于更新`apt`缓存？

A. `apt-get -c`

B. `apt-get update`

C. `apt-get upgrade`

D. `apt-get -u`

1.  哪个命令用于在缓存中搜索软件包？

A. `apt-get search`

B. `apt-cache search`

C. `apt-get -update`

D. `apt-get clean`

1.  哪个选项用于使用`apt`命令删除软件包及其配置？

A. `apt-get remove`

B. `apt-get purge`

C. `apt-get --remove`

D. `apt-get --update`

1.  哪个选项用于使用`aptitude`命令更新软件包列表？

A. `aptitude purge`

B. `aptitude clean`

C. `aptitude update`

D. `aptitude --clean`

# 进一步阅读

+   这个网站为您提供了关于 Debian 发行版的有用信息：[`wiki.debian.org`](https://wiki.debian.org)。

+   这个网站为您提供了 Debian 发行版的技巧和最佳实践：[`www.debian.org`](https://www.debian.org)。

+   下一个网站为您提供了 Linux 社区用户的许多有用的技巧和最佳实践，特别是针对 Debian 发行版，如 Ubuntu：[`askubuntu.com`](https://askubuntu.com)。

+   这个网站为您提供了许多有用的资源，涉及其他 Linux 用户在各种任务中遇到的各种问题：[`unix.stackexchange.com`](https://unix.stackexchange.com)。
