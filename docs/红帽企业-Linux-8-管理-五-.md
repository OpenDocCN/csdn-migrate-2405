# 红帽企业 Linux 8 管理（五）

> 原文：[`zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A`](https://zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：使用 Stratis 和 VDO 进行高级存储管理

在本章中，我们将学习**Stratis**和**虚拟数据优化器**（**VDO**）。

Stratis 是一个存储管理工具，用于简化运行最典型的日常任务。它使用前几章中解释的基础技术，如 LVM、分区模式和文件系统。

VDO 是一个存储层，包括一个驱动程序，位于我们的应用程序和存储设备之间，提供数据的去重和压缩，以及管理此功能的工具。这将使我们能够最大化系统容纳虚拟机（VM）实例的能力，这些实例将仅基于使它们独特的内容占用磁盘空间，但只存储它们共同的数据一次。

我们还可以使用 VDO 来存储我们备份的不同副本，知道磁盘使用仍将被优化。

在本章结束时，我们将了解 VDO 的工作原理以及为系统设置它所需的内容。

我们将在以下部分中探讨如何准备、配置和使用我们的系统：

+   理解 Stratis

+   安装和启用 Stratis

+   使用 Stratis 管理存储池和文件系统

+   准备系统以使用 VDO

+   创建 VDO 卷

+   将 VDO 卷分配给 LVM

+   测试 VDO 卷并查看统计信息

让我们开始准备我们的系统以使用 VDO。

# 技术要求

可以继续使用本书开头创建的 VM 的做法*第一章*，*安装 RHEL8*。本章所需的任何其他软件包将被指示，并可以从[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration)下载。

在*理解 Stratis*部分，我们将需要与*第十三章*中添加的相同两个磁盘，*使用 LVM 进行灵活的存储管理*，在所有 LVM 组件都已从中清理出来后。

# 理解 Stratis

作为一项新功能，为了管理存储，**Stratis**作为技术预览包含在 RHEL 8 中（截至 RHEL 8.3 版本）。Stratis 是为了通过将系统服务**stratisd**与 LVM 中的知名工具（在*第十三章*中解释，*使用 LVM 进行灵活的存储管理*）和 XFS 文件系统（在*第十二章*中解释，*管理本地存储和文件系统*）相结合来管理本地存储，这使其非常稳固和可靠。

重要提示

使用 Stratis 创建的文件系统/池应始终使用它来管理，而不是使用 LVM/XFS 工具。同样，已创建的 LVM 卷不应使用 Stratis 来管理。

Stratis 将本地磁盘组合成**池**，然后将存储分配到**文件系统**中，如下图所示：

![图 14.1 - Stratis 简化架构图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_001.jpg)

图 14.1 - Stratis 简化架构图

可以看到，与 LVM 相比，Stratis 提供了一个更简单和易于理解的存储管理界面。在接下来的部分中，我们将安装和启用 Stratis，然后使用在*第十三章*中创建的相同磁盘，*使用 LVM 进行灵活的存储管理*，来创建一个池和一对文件系统。

# 安装和启用 Stratis

要能够使用 Stratis，我们将从安装它开始。与之一起使用的两个软件包是这些：

+   `stratis-cli`：执行存储管理任务的命令行工具

+   `stratisd`：一个系统服务（也称为守护程序），接收命令并执行低级任务

要安装它们，我们将使用`dnf`命令：

```
[root@rhel8 ~]# dnf install stratis-cli stratisd
Updating Subscription Management repositories.
Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)                17 MB/s |  32 MB     00:01    
Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)             12 MB/s |  30 MB     00:02    
Dependencies resolved.
====================================================================================================
Package                           Arch    Version           Repository                         Size
====================================================================================================
Installing:
stratis-cli                       noarch  2.3.0-3.el8       rhel-8-for-x86_64-appstream-rpms   79 k
stratisd                          x86_64  2.3.0-2.el8       rhel-8-for-x86_64-appstream-rpms  2.1 M
[omitted]
Complete!
```

现在我们可以使用`systemctl`启动`stratisd`服务：

```
[root@rhel8 ~]# systemctl start stratisd
[root@rhel8 ~]# systemctl status stratisd
● stratisd.service - Stratis daemon
   Loaded: loaded (/usr/lib/systemd/system/stratisd.service; enabled; vendor preset: enabled)
   Active: active (running) since Sat 2021-05-22 17:31:35 CEST; 53s ago
     Docs: man:stratisd(8)
Main PID: 17797 (stratisd)
    Tasks: 1 (limit: 8177)
   Memory: 1.2M
   CGroup: /system.slice/stratisd.service
           └─17797 /usr/libexec/stratisd --log-level debug 
[omitted]
```

现在我们将启用它以在启动时启动：

```
[root@rhel8 ~]# systemctl enable stratisd
[root@rhel8 ~]# systemctl status stratisd
● stratisd.service - Stratis daemon
   Loaded: loaded (/usr/lib/systemd/system/stratisd.service; enabled; vendor preset: enabled)
[omitted]
```

提示

我们可以用一个命令完成这两个任务，即`systemctl enable --now stratisd`。

让我们用`stratis-cli`检查守护进程（也称为系统服务）是否正在运行：

```
[root@rhel8 ~]# stratis daemon version
2.3.0
```

我们已经准备就绪，现在是时候开始处理磁盘了。让我们继续下一个子部分。

# 使用 Stratis 管理存储池和文件系统

为了为 Stratis 提供一些存储空间，我们将使用`/dev/vdb`和`/dev/vdc`磁盘。我们需要确保它们上面没有任何逻辑卷或分区。让我们检查一下它们：

```
[root@rhel8 ~]# lvs
  LV   VG   Attr       LSize  Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root rhel -wi-ao---- <8,00g                                                    
  swap rhel -wi-ao----  1,00g                                                    
[root@rhel8 ~]# vgs
  VG   #PV #LV #SN Attr   VSize  VFree
  rhel   1   2   0 wz--n- <9,00g    0 
[root@rhel8 ~]# pvs
  PV         VG   Fmt  Attr PSize  PFree
  /dev/vda2  rhel lvm2 a--  <9,00g    0
```

我们很好：所有由 LVM 创建的对象都在磁盘`/dev/vda`上。让我们检查另外两个磁盘，`/dev/vdb`和`/dev/vdc`：

```
[root@rhel8 ~]# parted /dev/vdb print
Model: Virtio Block Device (virtblk)
Disk /dev/vdb: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start  End  Size  File system  Name  Flags
[root@rhel8 ~]# parted /dev/vdc print
Error: /dev/vdc: unrecognised disk label
Model: Virtio Block Device (virtblk)
Disk /dev/vdc: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: unknown
Disk Flags: 
```

磁盘`/dev/vdc`没有分区表标签。这个没问题。然而，磁盘`/dev/vdb`有一个分区表。让我们移除它：

```
[root@rhel8 ~]# dd if=/dev/zero of=/dev/vdb count=2048 bs=1024
2048+0 records in
2048+0 records out
2097152 bytes (2,1 MB, 2,0 MiB) copied, 0,0853277 s, 24,6 MB/s 
```

提示

`dd`命令，代表磁盘转储，用于从设备转储数据和到设备。特殊设备`/dev/zero`只是生成零，我们用它来覆盖磁盘的初始扇区，标签所在的位置。请谨慎使用`dd`；它可能在没有警告的情况下覆盖任何内容。

现在我们准备使用`stratis`命令创建第一个池：

```
[root@rhel8 ~]# stratis pool create mypool /dev/vdb
[root@rhel8 ~]# stratis pool list
Name                     Total Physical   Properties
mypool   1 GiB / 37.63 MiB / 986.37 MiB      ~Ca,~Cr
```

我们目前已经创建了池，如下图所示：

![图 14.2 – 创建的 Stratis 池](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_002.jpg)

图 14.2 – 创建的 Stratis 池

我们已经创建了池；现在可以在其上创建文件系统：

```
[root@rhel8 ~]# stratis filesystem create mypool data
[root@rhel8 ~]# stratis filesystem list
Pool Name   Name   Used      Created             Device                      UUID                            
mypool      data   546 MiB   May 23 2021 19:16    /dev/stratis/mypool/data   b073b6f1d56843b888cb83f6a7d80a43
```

存储的状态如下：

![图 14.3 – 创建的 Stratis 文件系统](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_003.jpg)

图 14.3 – 创建的 Stratis 文件系统

让我们准备挂载文件系统。我们需要在`/etc/fstab`中添加以下行：

```
/dev/stratis/mypool/data /srv/stratis-data      xfs     defaults,x-systemd.requires=stratisd.service        0 0
```

重要提示

为了在启动过程中正确挂载 Stratis 文件系统，我们应该添加`x-systemd.requires=stratisd.service`选项，以便在`stratisd`服务启动后挂载它。

现在我们可以挂载它：

```
[root@rhel8 ~]# mkdir /srv/stratis-data 
[root@rhel8 ~]# mount /srv/stratis-data/
```

现在让我们扩展池：

```
[root@rhel8 ~]# stratis blockdev list mypool 
Pool Name   Device Node   Physical Size   Tier
mypool      /dev/vdb              1 GiB   Data
[root@rhel8 ~]# stratis pool add-data mypool /dev/vdc
[root@rhel8 ~]# stratis blockdev list mypool 
Pool Name   Device Node   Physical Size   Tier
mypool      /dev/vdb              1 GiB   Data
mypool      /dev/vdc              1 GiB   Data
```

由于底层层使用了薄池，我们不需要扩展文件系统。存储如下：

![图 14.4 – Stratis 池扩展](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_004.jpg)

图 14.4 – Stratis 池扩展

使用`stratis snapshot`命令创建快照的时间。让我们创建一些数据，然后对其进行快照：

```
[root@rhel8 ~]# stratis filesystem
Pool Name   Name   Used      Created             Device                      UUID                            
mypool      data   546 MiB   May 23 2021 19:54    /dev/stratis/mypool/data   08af5d5782c54087a1fd4e9531ce4943
[root@rhel8 ~]# dd if=/dev/urandom of=/srv/stratis-data/file bs=1M count=512
512+0 records in
512+0 records out
536870912 bytes (537 MB, 512 MiB) copied, 2,33188 s, 230 MB/s
[root@rhel8 ~]# stratis filesystem
Pool Name   Name   Used      Created             Device                      UUID                            
mypool      data   966 MiB   May 23 2021 19:54    /dev/stratis/mypool/data   08af5d5782c54087a1fd4e9531ce4943
[root@rhel8 ~]# stratis filesystem snapshot mypool data data-snapshot1
[root@rhel8 ~]# stratis filesystem
Pool Name   Name             Used       Created             Device                               UUID                    
mypool      data             1.03 GiB   May 23 2021 19:54    /dev/stratis/mypool/data             08af5d5782c54087a1fd4e9531ce4943
mypool      data-snapshot1   1.03 GiB   May 23 2021 19:56    /dev/stratis/mypool/data-snapshot1   a2ae4aab56c64f728b59d710b82fb682
```

提示

要查看 Stratis 的内部组件，可以运行`lsblk`命令。通过它，您将看到 Stratis 在树中使用的组件：物理设备、元数据和数据的分配、池和文件系统。所有这些都被 Stratis 抽象化了。

通过这些，我们已经了解了 Stratis 的概述，以便覆盖其管理的基础知识。请记住，Stratis 目前处于预览阶段，因此不应在生产系统中使用。

现在让我们继续研究存储管理中的其他高级主题，通过回顾使用 VDO 进行数据去重。

# 准备系统使用 VDO

如前所述，VDO 是一个驱动程序，具体来说是一个 Linux 设备映射器驱动程序，它使用两个内核模块：

+   `kvdo`：这做数据压缩。

+   `uds`：这负责去重。

常规存储设备，如本地磁盘、**廉价磁盘冗余阵列**（**RAID**）等，是数据存储的最终后端；顶部的 VDO 层通过以下方式减少磁盘使用：

+   去除零块，只在元数据中存储它们。

+   去重：重复的数据块在元数据中被引用，但只存储一次。

+   使用 4KB 数据块和无损压缩算法（LZ4：[`lz4.github.io/lz4/`](https://lz4.github.io/lz4/)）进行压缩。

这些技术过去在其他解决方案中被使用过，比如只保留虚拟机之间的差异的薄配置**VMs**，但 VDO 使这一切变得透明。

与薄配置类似，VDO 可以意味着更快的数据吞吐量，因为数据可以被系统控制器和多个服务或甚至虚拟机缓存，而无需额外的磁盘读取来访问它。

让我们安装所需的软件包，以便通过安装`vdo`和`kmod-kvdo`软件包来创建 VDO 卷：

```
dnf install vdo kmod-kvdo
```

现在，安装了软件包，我们准备在下一节创建我们的第一个卷。

# 创建 VDO 卷

为了创建 VDO 设备，我们将利用我们在*第十二章*中创建的回环设备，*管理本地存储和文件系统*，所以我们首先检查它是否已挂载，执行以下命令：

```
mount|grep loop
```

如果没有输出显示，我们可以准备在其上创建我们的`vdo`卷，使用以下命令：

```
vdo create -n myvdo --device /dev/loop0 –force
```

输出显示在以下截图中：

![图 14.5 - vdo 卷创建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_005.jpg)

图 14.5 - vdo 卷创建

卷创建后，我们可以执行`vdo status`来获取有关创建的卷的详细信息，如下截图所示：

图 14.6 - vdo 状态输出

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_006.jpg)

图 14.6 - vdo 状态输出

正如我们所看到的，这里有关于`kvdo`版本、正在使用的配置文件以及我们的卷（大小、压缩状态等）的信息。

新卷现在可以通过`/dev/mapper/myvdo`看到（我们使用`–n`分配的名称），并且可以使用了。

我们可以执行`vdo status|egrep -i "compression|dedupli"`并获得以下输出：

图 14.7 - 检查 VDO 压缩和重复数据删除的状态

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_007.jpg)

图 14.7 - 检查 VDO 压缩和重复数据删除的状态

这意味着我们的卷上同时启用了压缩和重复数据删除，所以我们准备在下一节将其添加到 LVM 卷中进行功能测试。

# 将 VDO 卷分配给 LVM 卷

在上一节中，我们创建了一个 VDO 卷，现在将成为我们创建 LVM 卷组和一些逻辑卷的**物理卷**（**PV**）。

让我们通过以下命令序列创建 PV：

1.  `pvcreate /dev/mapper/myvdo`

1.  `vgcreate myvdo /dev/mapper/myvdo`

1.  `lvcreate -L 15G –n myvol myvdo`

此时，我们的`/dev/myvdo/myvol`已准备好格式化。让我们使用 XFS 文件系统：

```
mkfs.xfs /dev/myvdo/myvol
```

文件系统创建后，让我们通过挂载放一些数据：

```
mount /dev/myvdo/myvol /mnt
```

现在让我们在下一节测试 VDO 卷。

# 测试 VDO 卷并查看统计信息

为了测试重复数据删除和压缩，我们将使用一个大文件进行测试，比如在[`access.redhat.com/downloads/content/479/ver=/rhel---8/8.3/x86_64/product-software`](https://access.redhat.com/downloads/content/479/ver=/rhel---8/8.3/x86_64/product-software)上可用的 RHEL 8 KVM 客户机镜像。

下载后，将其保存为`rhel-8.3-x86_64-kvm.qcow2`并将其复制四次到我们的 VDO 卷：

```
cp rhel-8.3-x86_64-kvm.qcow2 /mnt/vm1.qcow2
cp rhel-8.3-x86_64-kvm.qcow2 /mnt/vm2.qcow2
cp rhel-8.3-x86_64-kvm.qcow2 /mnt/vm3.qcow2
cp rhel-8.3-x86_64-kvm.qcow2 /mnt/vm4.qcow2
```

这将是一个典型情况，对于一个持有以相同基础磁盘镜像启动的 VM 的服务器，但我们是否看到了任何改进？

让我们执行`vdostats --human-readable`来验证数据。请注意，从`ls –si`报告的图像下载大小为 1.4 GB。从`vdostats --human-readable`获得的输出如下：

```
Device                    Size      Used Available Use% Space saving%
/dev/mapper/myvdo        20.0G      5.2G     14.8G  25%           75%
```

原始卷（回环文件）为 20 GB，所以我们可以看到这个大小，但是从输出来看，我们创建的 LVM 卷为 15 GB，而且我们看到只消耗了大约 1.2 GB，即使我们有四个大小为 1.4 GB 的文件。

百分比也非常清楚。我们节省了 75%的空间（四个文件中有三个是完全相同的）。如果我们再复制一份，我们会看到百分比变为 80%（5 份复制中有 1 份）。

让我们看看另一种方法，通过创建一个空文件（填充为零）：

```
[root@bender mnt]# dd if=/dev/zero of=emptyfile bs=16777216 count=1024
dd: error writing 'emptyfile': No space left on device
559+0 records in
558+0 records out
9361883136 bytes (9.4 GB, 8.7 GiB) copied, 97.0276 s, 96.5 MB/s
```

正如我们所看到的，磁盘完全填满之前，我们能够写入 9.4 GB，但让我们再次使用`vdostats --human-readable`检查`vdo`统计信息，如下截图所示：

![图 14.8 - 检查 vdostats 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_008.jpg)

图 14.8 - 检查 vdostats 输出

正如我们所看到的，我们仍然有 14.8GB 可用，并且我们已经将磁盘空间从 80%增加到 92%，因为这个大文件是空的。

等等 - 如果我们使用去重和压缩，为什么我们填满了 92%的卷呢？

由于我们没有指定 VDO 卷的逻辑大小，默认情况下它与底层设备的比例为 1:1。这是最安全的方法，但我们没有真正利用压缩和去重的性能。

为了充分利用优化，我们可以在现有卷的基础上创建一个更大的逻辑驱动器。例如，如果经过长时间后我们相当确定磁盘优化可能是相似的，我们可以使用以下命令扩展逻辑大小：

```
vdo growLogical --name=myvdo --vdoLogicalSize=30G
```

当然，这不会增加可用的大小，因为我们定义了一个 PV 与卷组和顶部的逻辑卷。因此，我们还需要通过执行以下命令来扩展它：

1.  `pvresize /dev/mapper/myvdo`

1.  `lvresize –L +14G /dev/myvdo/myvol`

1.  `xfs_growfs /mnt`

通过这样做，我们扩展了物理卷，增加了逻辑卷的大小，并扩展了文件系统，因此现在可以使用这些空间。

如果现在执行`df|grep vdo`，我们会看到类似这样的内容：

![图 14.9 - 调整卷大小后的磁盘空间可用性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_14_009.jpg)

图 14.9 - 调整卷大小后的磁盘空间可用性

从这一点开始，我们必须非常小心，因为我们对磁盘空间的实际使用可能不像以前那样在可能的压缩方面进行了优化，导致写入失败。因此，需要监视可用的磁盘空间以及 VDO 状态，以确保我们没有尝试使用比可用空间更多的空间，例如，如果存储的文件无法以相同的比例进行压缩或去重。

重要提示

诱人的是，我们可以从真实的物理磁盘空间中设置一个非常大的逻辑卷，但我们应该提前计划并考虑避免未来可能出现的问题，比如压缩比可能不像我们的乐观主义那样高的可能性。充分地对存储的实际数据和其典型的压缩比进行分析可以让我们更好地了解在继续积极监视逻辑卷和物理卷的磁盘使用情况演变时使用的安全方法。

很久以前，当磁盘空间非常昂贵（硬盘总共只有 80MB）时，使用工具来通过透明的压缩层增加磁盘空间变得非常流行，这些工具可以通过一些估算和报告更大的空间来实现*增加*磁盘空间；但实际上，我们知道像图片和电影这样的内容并不像文本文件这样的其他文档格式那样容易压缩。一些文档格式，比如 LibreOffice 使用的格式，已经是压缩文件，因此不会获得额外的压缩好处。

但是，当我们谈论虚拟机时，情况就不同了，每个虚拟机的基础更多或更少是相等的（基于公司政策和标准），并且是通过克隆磁盘映像部署的，然后进行一些小的定制，但本质上，大部分磁盘内容是共享的。

提示

总的来说，要记住优化实际上只是一种权衡。在调整配置文件的情况下，您是在调整吞吐量以换取延迟，而在我们的情况下，您是在交换 CPU 和内存资源以换取磁盘可用性。判断某种东西是否值得权衡的唯一方法是实施它并查看其性能，看看获得了什么好处，然后继续随着时间的推移监视性能。

# 总结

在本章中，我们学习了 VDO 和 Stratis。我们看了一些简单的管理存储的方法，如如何透明地节省磁盘空间以及如何在过程中获得一些吞吐量。

使用 Stratis，我们创建了一个具有两个磁盘的池，并将其分配给一个挂载点。这比使用 LVM 要简单一些，但另一方面，我们对我们所做的事情的控制更少。无论如何，我们学会了如何在 RHEL 8 中使用这个预览技术。

使用 VDO，我们使用创建的卷来定义一个 LVM PV，并在其上创建了一个卷组和一个逻辑卷，我们使用在之前章节中获得的知识来格式化它，以存储多个 VM 磁盘映像，模拟从同一基础启动多个 VM 的场景。

我们还学会了如何检查 VDO 的优化和节省的磁盘空间量。

现在，我们准备使用 Stratis 而不是 LVM 来组合和分配存储（尽管不用于生产）。我们还可以为我们的服务器实施 VDO 来开始优化磁盘使用。

在下一章中，我们将学习关于引导过程。


# 第十五章：理解引导过程

引导过程是指从您打开机器（物理或虚拟）的那一刻到操作系统完全加载的过程。

就像许多好的视频游戏一样，它有三个阶段：硬件执行的初始启动（再次是物理或虚拟），操作系统初始阶段的加载，然后是帮助在系统中运行所需服务的机制。 我们将在本章中审查这三个阶段，并且还将添加提示和技巧，以干预系统并执行救援操作。

本章中我们将涵盖的部分如下：

+   理解引导过程 - BIOS 和 UEFI 引导

+   使用 GRUB，引导加载程序和 initrd 系统映像

+   使用 systemd 管理引导顺序

+   干预引导过程以获取对系统的访问权限

在引导过程的前两个阶段，您很可能不需要进行太多更改，但在紧急情况，取证或重大故障的情况下，这些点可能极其有帮助。 这就是为什么仔细阅读它们很重要。

第三阶段，由 **systemd** 管理，将执行更多操作和更改，以管理系统中默认运行的服务。 我们已经在之前的章节中看到了大部分要执行的任务的示例； 但是，在这一章中，我们将提供全面的审查。

让我们开始第一阶段。

# 理解引导过程 - BIOS 和 UEFI 引导

计算机具有硬件嵌入式软件控制器，也称为 **固件**，可让您管理硬件的最底层。 这个固件是对系统中可用的硬件进行第一次识别以及启用的硬件功能（如 **预引导网络执行**，称为 **PXE**）。

在被称为 **PC**（**个人计算机**）的架构中，也称为 x86，由英特尔和 IBM 推广，嵌入式固件称为 **BIOS**，代表 **基本输入输出系统**。

BIOS 引导过程，使用 Linux，采取以下步骤：

1.  计算机开机并加载 BIOS 固件。

1.  固件初始化设备，如键盘，鼠标，存储和其他外围设备。

1.  固件读取配置，包括引导顺序，指定哪个存储设备是继续引导过程的设备。

1.  一旦选择了存储设备，BIOS 将加载其中的 **主引导记录** (**MBR**)，这将启用 **操作系统加载程序**。 在 RHEL 中，操作系统加载程序称为 **Grand Unified Bootloader** (**GRUB**)。

1.  GRUB 加载配置和 `vmlinuz`，以及名为 `initrd` 的初始引导映像文件。 所有 GRUB 配置 `vmlinuz` 和 `initrd` 文件都存储在 `/boot` 分区中。

1.  初始引导映像使得加载系统的第一个进程成为可能，也称为 `init`，在 RHEL8 中是 **systemd**。

1.  *systemd* 加载操作系统的其余部分。

为了使这个过程发生，磁盘必须有一个 MBR 分区表，并且分配给 `/boot` 的分区必须标记为可引导。

提示

MBR 分区表格式非常有限，只允许四个主分区，并使用扩展分区等扩展来克服这一限制。 不建议使用这种类型的分区，除非完全需要。

UEFI 引导过程与 BIOS 引导过程非常相似。 **UEFI** 代表 **统一可扩展固件接口**。 引导顺序的主要区别在于 UEFI 可以直接访问和读取磁盘分区。 其流程如下：

1.  计算机开机并加载 UEFI 固件。

1.  固件初始化设备，如键盘，鼠标，存储和其他外围设备。

1.  固件读取配置，其中指定了继续引导过程所需的存储设备和可引导分区（UEFI 不需要 MBR 引导）。

1.  选择存储设备后，从`/boot/efi`分区读取其中的分区，并继续加载 GRUB。

1.  然后，GRUB 加载`vmlinuz`和`initrd`。GRUB 配置`vmlinuz`和`initrd`文件存储在`/boot`分区中。

1.  初始引导映像使系统的第一个进程加载，也称为`init`，在 RHEL8 中是**systemd**。

1.  *systemd*加载操作系统的其余部分。

UEFI 相对于 BIOS 具有几个优点，可以启用更完整的预引导环境和其他功能，例如安全引导和对 GPT 分区的支持，可以超出 MBR 分区的 2TB 限制。

安装程序将负责创建引导以及如果需要的 UEFI 分区和二进制文件。

需要了解的预引导部分是如何从中加载操作系统加载程序，这是红帽认证系统管理员认证考试的一部分。通过 BIOS 或 UEFI，我们可以选择从哪个存储设备加载操作系统，并转移到下一个阶段。让我们在下一节中进入下一个阶段。

# 使用 GRUB、引导加载程序和 initrd 系统映像进行工作。

预引导执行完成后，系统将运行 GRUB 引导加载程序。

GRUB 的任务是加载操作系统的主文件**kernel**，向其传递参数和选项，并加载初始 RAM 磁盘，也称为**initrd**。

可以使用`grub2-install`命令安装 GRUB。我们需要知道将用于引导的磁盘设备，例如`/dev/vda`：

```
[root@rhel8 ~]# grub2-install /dev/vda
Installing for i386-pc platform.
Installation finished. No error reported.
```

重要提示

您应该将`grub-install`指向您将用于引导系统的磁盘，与您在 BIOS/UEFI 中配置的相同磁盘。

这是用于手动重建系统或修复损坏引导的。

GRUB 文件存储在`/boot/grub2`中。主配置文件是`/boot/grub2/grub.cfg`；但是，如果您仔细查看此文件，您将看到以下标题：

```
[root@rhel8 ~]# head -n 6 /boot/grub2/grub.cfg 
#
# DO NOT EDIT THIS FILE
#
# It is automatically generated by grub2-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
#
```

如您所见，此文件是自动生成的，因此不打算手动编辑。那么我们如何进行更改呢？有两种方法可以这样做：

+   第一种方法是按照`grub.cfg`文件中提到的说明进行操作。这意味着编辑`/etc/default/grub`文件和/或`/etc/grub.d/`目录中的内容，然后通过运行`grub2-mkconfig`重新生成 GRUB 配置。

+   第二种方法是使用`grubby`命令行工具。

重要提示

在 RHEL 中，当有新版本的内核时，不会更新现有内核，而是在先前的内核旁边安装新的内核，并在 GRUB 中添加新的条目。这样，如果需要，可以轻松回滚到以前的工作内核。在安装过程中，为新内核创建了新的更新的`initrd`。

让我们使用`grubby`查看当前的内核配置。`--default-kernel`选项将显示默认加载的内核文件：

```
 [root@rhel8 ~]# grubby --default-kernel
/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
```

`--default-title`选项将显示引导时使用的名称：

```
[root@rhel8 ~]# grubby --default-title
Red Hat Enterprise Linux (4.18.0-240.15.1.el8_3.x86_64) 8.3 (Ootpa)
```

通过使用`--info`选项，我们可以查看默认内核的更多信息：

```
[root@rhel8 ~]# grubby --info=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
index=0
kernel="/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64"
args="ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet $tuned_params"
root="/dev/mapper/rhel-root"
initrd="/boot/initramfs-4.18.0-240.15.1.el8_3.x86_64.img $tuned_initrd"
title="Red Hat Enterprise Linux (4.18.0-240.15.1.el8_3.x86_64) 8.3 (Ootpa)"
id="21e418ac989a4b0c8afb156418393409-4.18.0-240.15.1.el8_3.x86_64"
```

我们可以看到传递给 GRUB 的选项：

+   `index`：显示条目的索引号

+   `kernel`：包含将加载以运行操作系统核心的内核的文件

+   `root`：将分配给根`/`目录并挂载的分区或逻辑卷

+   `initrd`：包含 RAM 磁盘的文件，用于执行引导过程的初始部分

+   `title`：在引导过程中向用户显示的描述性标题

+   `id`：引导项的标识符

提示

您可能希望运行`grubby`命令以获取默认配置的内核信息。为此，可以通过运行以下命令来执行：`grubby --info=$(grubby --default-kernel)`。

通过删除传递给内核的`quiet`和`rhbg`参数，让引导过程更加详细：

```
[root@rhel8 ~]# grubby --remove-args="rhgb quiet" \
--update-kernel=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
[root@rhel8 ~]# grubby \ 
--info=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
index=0
kernel="/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64"
args="ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap $tuned_params"
root="/dev/mapper/rhel-root"
initrd="/boot/initramfs-4.18.0-240.15.1.el8_3.x86_64.img $tuned_initrd"
title="Red Hat Enterprise Linux (4.18.0-240.15.1.el8_3.x86_64) 8.3 (Ootpa)"
id="21e418ac989a4b0c8afb156418393409-4.18.0-240.15.1.el8_3.x86_64"
```

让我们使用`systemctl reboot`命令重新启动机器进行测试。这是一个示例输出：

![图 15.1 - 详细引导](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_001.jpg)

图 15.1 - 详细引导

在正常引导中，这可能并不是非常有用，因为它进行得太快了。然而，如果有问题，它可以帮助从控制台调试情况。要在引导后查看这些消息，可以使用`dmesg`命令：

![图 15.2 - dmesg 命令的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_002.jpg)

图 15.2 - dmesg 命令的输出

我们可以使用`--args`选项向内核添加参数。让我们再次添加`quiet`选项：

```
[root@rhel8 ~]# grubby --args="quiet" \
--update-kernel=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
[root@rhel8 ~]# grubby \
--info=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
index=0
kernel="/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64"
args="ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap $tuned_params quiet"
root="/dev/mapper/rhel-root"
initrd="/boot/initramfs-4.18.0-240.15.1.el8_3.x86_64.img $tuned_initrd"
title="Red Hat Enterprise Linux (4.18.0-240.15.1.el8_3.x86_64) 8.3 (Ootpa)"
id="21e418ac989a4b0c8afb156418393409-4.18.0-240.15.1.el8_3.x86_64"
```

重要提示

`--info`和`--update-kernel`选项接受`ALL`选项来查看或执行所有配置的内核的操作。

如果任何管理任务需要我们更改内核参数，现在我们知道如何做了。让我们转到引导过程的下一部分，`initrd`。

`/boot/initramfs-4.18.0-240.15.1.el8_3.x86_64.img`。可以使用`dracut`命令重新生成。让我们看一个重新构建当前`initrd`文件的例子：

```
[root@rhel8 ~]# dracut --force --verbose
dracut: Executing: /usr/bin/dracut --force --verbose
dracut: dracut module 'busybox' will not be installed, because command 'busybox' could not be found!
[omitted]
dracut: *** Including module: shutdown ***
dracut: *** Including modules done ***
dracut: *** Installing kernel module dependencies ***
dracut: *** Installing kernel module dependencies done ***
dracut: *** Resolving executable dependencies ***
dracut: *** Resolving executable dependencies done***
dracut: *** Hardlinking files ***
dracut: *** Hardlinking files done ***
dracut: *** Generating early-microcode cpio image ***
dracut: *** Constructing GenuineIntel.bin ****
dracut: *** Constructing GenuineIntel.bin ****
dracut: *** Store current command line parameters ***
dracut: *** Stripping files ***
dracut: *** Stripping files done ***
dracut: *** Creating image file '/boot/initramfs-4.18.0-240.15.1.el8_3.x86_64.img' ***
dracut: *** Creating initramfs image file '/boot/initramfs-4.18.0-240.15.1.el8_3.x86_64.img' done ***
```

我们可以在先前的输出中看到，`initrd`文件中包括的用于早期访问的内核模块和文件。当我们的`initrd`文件损坏时，这一步是有用的，也是在从备份中恢复系统时，如果在不同的硬件上进行，需要包括适当的存储驱动程序。

提示

查看`dracut`的手册页面，了解创建`initrd`文件的选项。有一篇红帽知识库文章可以解压`initrd`，这是一个学习更多知识的有趣练习：[`access.redhat.com/solutions/24029.`](https://access.redhat.com/solutions/24029

)

我们已经学习了引导过程的早期阶段的基础知识，以便能够开始排除引导问题，这是成为 RHCSA 所需的。这个高级主题可以在一本完整的书中进行详细介绍，但在作为系统管理员的日常任务中几乎不会用到。这就是为什么我们只包括了其中必要的方面。我们将在本章的最后一节中包括一个特定的用例，名为*干预引导过程以访问系统*，并修复磁盘问题。让我们继续下一个关于如何使用**systemd**管理 RHEL 中服务的主题。

# 使用 systemd 管理引导顺序

我们已经学习了系统固件将如何指向一个磁盘来运行操作系统加载程序，在 RHEL 中就是 GRUB。

GRUB 将加载内核和 initrd 以准备系统启动。然后是启动系统的第一个进程，也称为进程 1 或 PID 1（**PID**代表**进程标识符**）。这个进程必须有效地负责加载系统中所有所需的服务。在 RHEL8 中，PID 1 由**systemd**运行。

在*第四章*，*常规操作工具*中，我们描述了使用 systemd 管理服务和目标。让我们在本章中回顾它与引导顺序的交互。

与`systemctl`工具相关的引导顺序的前两件事：

```
[root@rhel8 ~]# systemctl reboot
```

我们将看到系统将重新启动。我们可以使用`uptime`命令检查系统运行了多长时间：

```
[root@rhel8 ~]# uptime
11:11:39 up 0 min,  1 user,  load average: 0,62, 0,13, 0,04
```

现在是时候检查`poweroff`了。在这样做之前，请记住运行此命令后，您将需要一种方法再次打开机器。一旦我们了解了要遵循的流程，让我们运行它：

```
[root@rhel8 ~]# systemctl poweroff
```

现在我将再次打开我的机器。

有一个命令可以停止系统，但不发送关闭机器的信号，那就是`systemctl halt`。可以使用这个命令的情况很少；然而，知道它的存在和作用是很好的。

重要提示

先前显示的命令可以缩写为`reboot`和`poweroff`。如果您检查`/usr/sbin/poweroff`中的文件，您会发现它是一个指向`systemctl`的符号链接。

在*第四章*中，*常规操作工具*，我们还回顾了如何设置默认的`systemctl`。然而，我们可以通过传递`systemd.unit`参数给内核来在启动时覆盖默认配置。我们可以使用`grubby`来做到这一点：

```
[root@rhel8 ~]# systemctl get-default 
multi-user.target
[root@rhel8 ~]# grubby --args="systemd.unit=emergency.target" --update-kernel=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
[root@rhel8 ~]# systemctl reboot
```

现在系统正在重新启动。`systemd.unit=emergency.target`参数已经被**GRUB**传递给**内核**，然后从**内核**传递给**systemd**，**systemd**将忽略默认配置并加载**紧急目标**所需的服务。

现在系统以紧急模式启动，并等待根密码以让您控制：

![图 15.3 - RHEL 系统以紧急模式启动](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_003.jpg)

图 15.3 - RHEL 系统以紧急模式启动

在紧急模式下，没有配置网络，也没有其他进程在运行。您可以对系统进行更改，而无需担心其他用户正在访问。此外，只有`/`文件系统以只读模式挂载。

如果系统中的文件系统损坏，这将是一个检查它的好方法，而没有任何服务访问它。让我们尝试使用检查文件系统的命令`fsck`：

```
[root@rhel8 ~]# fsck /boot
fsck from util-linux 2.32.1
If you wish to check the consistency of an XFS filesystem or
repair a damaged filesystem, see xfs_repair(8).
```

文件系统正常。如果有问题需要修复（`fsck`检测到使用的文件系统），我们可以在其上运行`xfs_repair`，因为它是一个`xfs`文件系统。

此时我们可能会想，如果根文件系统已经以只读方式挂载在`/`上，我们如何对其进行更改？这个过程从将`/`文件系统重新挂载为读写开始：

```
[root@rhel8 ~]# mount -o remount -o rw /
```

记住，您可以通过运行`man mount`来访问命令的手册页面。现在我们的根文件系统以读写方式挂载在`/`上。我们还需要挂载`/boot`，所以让我们这样做：

```
[root@rhel8 ~]# mount /boot
```

有了`/boot`挂载，让我们做一些管理员任务，比如删除我们在 GRUB 中使用的参数：

```
[root@rhel8 ~]# grubby --remove-args="systemd.unit=emergency.target" --update-kernel=/boot/vmlinuz-4.18.0-240.15.1.el8_3.x86_64
[root@rhel8 ~]# reboot
```

然后我们回到了系统中的常规启动。这可能不是在 Linux 中进入紧急模式的实际方法，但它展示了如何在启动时传递参数给 systemd。

提示

有`rescue.target`加载更多服务并使过程变得更加容易。它通过等待`sysinit.target`完成来实现，而紧急目标不会这样做。一个很好的练习是使用`rescue.target`重复之前的序列。

在接下来的部分中，我们将看到如何对一次性启动进行此更改，以及在 GRUB 启动序列期间更轻松地进行类似的更改，而且无需密码。

# 干预引导过程以访问系统

有时您需要干预一个交接的系统，而您没有`root`用户的密码。尽管这听起来像是一个紧急情况，但实际上比您想象的更频繁。

重要提示

引导顺序必须没有任何加密的磁盘才能正常工作，否则您将需要加密卷的密码。

执行此过程的方法是在 GRUB 菜单中停止引导过程。这意味着我们需要重新启动系统。一旦 BIOS/UEFI 检查完成，系统将加载 GRUB。在那里，我们可以通过按下向上或向下箭头键来停止计数，就像以下截图中所示：

![图 15.4 - GRUB 菜单选择内核](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_004.jpg)

图 15.4 - GRUB 菜单选择内核

我们回到第一个条目。然后我们阅读屏幕底部，那里有编辑引导行的说明：

![图 15.5 - GRUB 菜单选择内核](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_005.jpg)

图 15.5 - GRUB 菜单选择内核

如果我们按下*E*键，我们将能够编辑菜单中选择的引导行。我们将看到以下五行：

图 15.6 - GRUB 菜单以选择内核

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_006.jpg)

图 15.6 - GRUB 菜单以选择内核

前三行`load_video`，`set` `gfx_payload=keep`和`insmod gzio`设置了 GRUB 的选项。接下来的两个选项是重要的。让我们来回顾一下它们：

+   `linux`：定义要加载的内核并向其传递参数

+   `initrd`：定义了从哪里加载 initrd 以及是否有任何选项

提示

请注意，`linux`行非常长，已经换行，我们可以看到`\`符号，这意味着该行在下面继续。

现在我们应该转到`linux`行的末尾，并添加`rd.break`选项，如下面的屏幕截图所示：

![图 15.7 - 使用 rd.break 选项编辑的 linux 内核行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_007.jpg)

图 15.7 - 使用 rd.break 选项编辑的 linux 内核行

要引导编辑后的行，我们只需要按下*Ctrl* + *X*。`rd.break`选项在加载 initrd 之前停止引导过程。现在的情况如下：

+   加载了单个 shell。

+   当前根文件系统挂载在`/`上，是一个带有基本管理命令的最小文件系统。

+   目标根文件系统以只读方式挂载在`/sysroot`上（而不是在`/`上）。

+   没有其他文件系统被挂载。

+   SELinux 未加载。

现在我们可以使用`chroot`切换到真正的磁盘根文件系统：

```
switch_root:/# chroot /sysroot
sh-4.4# 
```

现在我们的根文件系统已经正确挂载，但是只读。让我们以与上一节相同的方式进行更改：

```
sh-4.4# mount –o remount –o rw /
```

现在我们需要使用`passwd`命令更改 root 用户密码：

```
sh-4.4# passwd
Changing password for user root
New password:
Retype new password:
passwd: all authentication tokens updated successfully
```

root 用户的密码现在已更改，并且`/etc/shadow`文件已更新。但是，它是在未启用 SELinux 的情况下修改的，因此可能会在下一次引导时引发问题。为了避免这种情况，有一种机制可以在下一次引导时修复 SELinux 标签。该机制包括创建`/.autorelabel`隐藏的空文件，然后重新启动系统：

```
sh-4.4# touch /.autorelabel
```

创建文件后，现在是时候重新启动以应用 SELinux 更改。在此状态下，可能需要强制关闭电源，然后重新上电。在下一次引导时，我们将看到 SELinux 自动标记的发生：

![图 15.8 - 引导期间的 SELinux 自动标记](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_15_008.jpg)

图 15.8 - 引导期间的 SELinux 自动标记

现在我们可以使用 root 用户及其新密码登录。

# 总结

我们在本章中已经审查了引导顺序。正如您所见，它并不长，但它很复杂，而且也非常重要，因为如果系统无法引导，它就无法运行。我们已经了解了 BIOS 启用系统和 UEFI 系统之间的主要区别，后者可以实现一些功能，但也有自己的要求。我们还了解了 GRUB 及其在引导顺序中的重要作用，以及如何使用`grubby`永久修改条目以及如何进行一次性修改。我们现在知道了引导的主要文件，如内核`vmlinuz`和初始 RAM 磁盘`initrd`。

本章还向我们展示了如何在紧急和救援模式下启动，以及如何干预系统以重置 root 密码。

通过这些工具和程序，我们现在更有准备处理系统中的任何困难情况。现在是时候深入了解内核调优和性能配置文件了。


# 第十六章：内核调优和使用`tuned`管理性能配置文件

如前几章中偶尔描述的，每个系统性能配置文件必须适应我们系统的预期用途。

内核调优在这种优化中起着关键作用，我们将在本章的以下部分进一步探讨这一点：

+   识别进程，检查内存使用情况和终止进程

+   调整内核调度参数以更好地管理进程

+   安装`tuned`和管理调优配置文件

+   创建自定义的`tuned`配置文件

在本章结束时，您将了解如何应用内核调优，如何通过`tuned`使用快速配置文件以适应不同系统角色的一般用例，以及如何进一步扩展这些自定义配置以适用于您的服务器。

此外，识别已成为资源消耗者的进程以及如何终止它们或对它们进行优先处理将是在最需要时更充分利用我们的硬件的有用方法。

让我们动手学习这些主题！

# 技术要求

您可以继续使用本书开头创建的**虚拟机**（**VM**）*第一章*中的，*安装 RHEL8*。本章所需的任何其他软件包都将在文本旁边指示。

# 识别进程，检查内存使用情况和终止进程

进程是在我们系统上运行的程序 - 它可能是通过**安全外壳**（**SSH**）登录的用户，具有运行的 bash 终端进程，甚至是 SSH 守护程序的部分，用于监听和回复远程连接，或者可能是诸如邮件客户端、文件管理器等正在执行的程序。

当然，进程占用了我们系统的资源：内存、**中央处理单元**（**CPU**）、磁盘等。对于系统管理员来说，识别或定位可能行为不端的进程是一项关键任务。

一些基础知识已经在*第四章*中涵盖了，*常规操作工具*，但在继续之前，最好先复习一下；然而，在这里，我们将展示并使用一些这些工具，例如 - 例如`top`命令，它允许我们查看进程并根据 CPU 使用情况、内存使用情况等对列表进行排序。（查看`man top`的输出，了解如何更改排序标准。）

在检查系统性能时要注意的一个参数是负载平均值，它是由准备运行或等待`1`、`5`和`15`分钟的进程组成的移动平均值 - 并且可以让我们了解负载是增加还是减少的想法。一个经验法则是，如果负载平均值低于 1，那么没有资源饱和。

负载平均值可以通过许多其他工具显示，例如前面提到的`top`，或者使用`uptime`或`w`等。

如果系统负载平均值正在增长，CPU 或内存使用率正在上升，并且如果列出了一些进程，那么定位将更容易。如果负载平均值也很高且正在增加，可能是 I/O 操作在增加。可以安装`iotop`软件包，它提供`iotop`命令来监视磁盘活动。执行时，它将显示系统中的进程和磁盘活动：读取、写入和交换，这可能会给我们一些更多关于查找位置的提示。

一旦确定了占用太多资源的进程，我们就可以发送一个**信号**来控制它。

可以使用`kill -l`命令获取信号列表，如下截图所示：

![图 16.1 - 发送给进程的可用信号](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_001.jpg)

图 16.1 - 发送给进程的可用信号

请注意，每个信号都包含一个数字和一个名称 - 都可以用于通过其**进程标识符**（**PID**）向进程发送信号。

让我们来回顾一下最常见的信号，如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Table_16.1.jpg)

从*图 16.1*中显示的列表中，重要的是要知道每个信号都有一个`man 7 信号`，如下面的截图所示：

![图 16.2 - 信号列表，数字等效物，处置（操作）和行为（man 7 信号）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_002.jpg)

图 16.2 - 信号列表，数字等效物，处置（操作）和行为（man 7 信号）

到达这一点时最典型的用法之一是终止行为不端的进程，因此定位进程、获取 PID 并向其发送信号是一项非常常见的任务...甚至是如此常见，以至于甚至有工具可以让您将这些阶段组合成一个命令。

例如，我们可以将`ps aux|grep -i chrome|grep –v grep|awk '{print $2}'|xargs kill –9`与`pkill –9 –f chrome`进行比较：两者都会执行相同的操作，搜索名为`chrome`的进程，并向它们发送信号`9`（杀死）。

当然，即使用户登录也是系统中的一个进程（运行 SSH 或 shell 等）；我们可以通过类似的构造（使用`ps`、`grep`和其他工具）或使用`pgrep`选项（如`pgrep -l -u user`）找到我们目标用户启动的进程。

请注意，正如信号所指示的那样，最好发送一个`TERM`信号，以便让进程在退出之前运行其内部清理步骤，直接杀死它们可能会在我们的系统中留下残留物。

在终端复用器（如`tmux`或`screen`）变得普遍之前，一个广泛使用的有趣命令是`nohup`，它被添加到持续时间较长的命令之前，例如下载大文件。这个命令捕获了终端挂起信号，允许执行的进程继续执行，并将输出存储在`nohup.out`文件中，以便以后检查。

例如，要从客户门户下载最新的**Red Hat Enterprise Linux**（**RHEL**）**Image Standard Optical**（**ISO**）文件，选择一个版本，例如 8.4，然后在[`access.redhat.com/downloads/content/479/ver=/rhel---8/8.4/x86_64/product-software`](https://access.redhat.com/downloads/content/479/ver=/rhel---8/8.4/x86_64/product-software)登录后，我们将选择二进制 ISO 并右键单击复制下载的**统一资源定位符**（**URL**）。

提示

从**客户门户**复制时获得的 URL 是有时间限制的，这意味着它们只在短时间内有效，之后，下载链接将不再有效，应在刷新 URL 后获取新的链接。

然后，在终端中，我们将执行以下带有复制的 URL 的命令：

```
nohup wget URL_OBTAINED_FROM_CUSTOMER_PORTAL &
```

使用前面的命令，`nohup`将不会在终端挂断（断开连接）时关闭进程，因此`wget`将继续下载 URL，并且结束的`&`符号将执行从活动终端分离，将其作为后台作业，我们可以使用`jobs`命令检查直到它完成。

如果我们忘记添加`&`，程序将阻塞我们的输入，但我们可以在键盘上按下*Ctrl* + *Z*，进程将被停止。然而，由于我们真的希望它继续在后台执行，我们将执行`bg`，这将继续执行它。

如果我们想要将程序带回以接收我们的输入并与其交互，我们可以使用`fg`命令将其移到前台。

如果我们按下*Ctrl* + *C*，而程序有我们的输入，它将收到中断和停止执行的请求。

您可以在以下截图中看到工作流程：

![图 16.3 - 挂起进程，恢复到后台，带到前台，中止](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_003.jpg)

图 16.3 - 挂起进程，恢复到后台，带到前台，中止

在这种情况下，我们正在下载 Fedora 34 安装 ISO（8 `nohup`和`wget`；因为我们忘记添加&，我们执行了*Ctrl* + *Z*（显示为`^Z`）。

作业被报告为作业`[1]`，状态为`Stopped`（在执行`jobs`时也会报告）。

然后，我们使用`bg`将作业切换到后台执行，现在，`jobs`将其报告为`Running`。

之后，我们使用`fg`将作业切换回前台，并执行*Ctrl* + *C*，在屏幕上表示为`^C`，以结束它。

这个功能使我们能够运行多个后台命令 - 例如，我们可以并行复制文件到多台主机，如下面的截图所示：

![图 16.4 - 使用 nohup 复制文件到多台服务器的示例 for 循环](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_004.jpg)

图 16.4 - 使用 nohup 复制文件到多台服务器的示例 for 循环

在这个例子中，通过`scp`执行的复制操作将会并行进行，而且，如果从我们的终端断开连接，作业将继续执行，并且输出将存储在我们执行它的文件夹中的`nohup.out`文件中。

重要提示

使用`nohup`启动的进程将不会获得任何额外的输入，因此如果程序要求输入，它将停止执行。如果程序要求输入，建议使用`tmux`，因为它仍然可以防止终端断开连接，但也允许与启动的程序进行交互。

我们并不总是愿意杀死进程或停止或恢复它们；我们可能只想降低或提高它们的优先级 - 例如，对于可能不是关键的长时间运行的任务。

让我们在下一节中了解这个功能。

# 调整内核调度参数以更好地管理进程

Linux 内核是一款高度可配置的软件，因此有一整个世界的可调参数可用于调整其行为：用于进程、网络卡、磁盘、内存等等。

最常见的可调参数是`nice`进程值和 I/O 优先级，分别调节 CPU 和 I/O 时间相对于其他进程的优先级。

对于即将启动的进程进行交互，我们可以使用`nice`或`ionice`命令，在要执行的命令前面加上一些参数（记得检查每个命令的`man`内容以获取完整的可用选项范围）。只需记住，对于`nice`，进程的优先级可以从-20 到+19，0 是标准值，-20 是最高优先级，19 是最低优先级（值越高，进程越好）。

每个进程都有一个获得内核关注的可能性；通过在执行之前通过`nice`或在运行时通过`renice`改变优先级，我们可以稍微改变它。

让我们考虑一个长时间运行的进程，比如执行备份 - 我们希望任务成功，所以我们不会停止或杀死进程，但与此同时，我们也不希望它改变我们服务器的生产或服务水平。如果我们将进程定义为 19 的`nice`值，这意味着系统中的任何进程都会获得更高的优先级 - 也就是说，我们的进程将继续运行，但不会使我们的系统更忙碌。

这让我们进入了一个有趣的话题 - 许多新来到 Linux 世界的用户，或者其他平台的管理员，当他们看到系统使用了大量内存（随机存取内存，或 RAM），却使用了交换空间，或者系统负载很高时，会感到震惊。很明显，轻微使用交换空间并且有大量空闲 RAM 只意味着内核通过将未使用的内存交换到磁盘上进行了优化。只要系统不感到迟缓，高负载只意味着系统有一个长队列的进程等待执行，但是 - 例如 - 如果进程被*niced*到 19，它们在队列中，但是如前所述，任何其他进程都会超过它。

当我们使用`top`或`ps`检查系统状态时，我们也可以检查进程运行的时间，这也是由内核计算的。一个新创建的进程开始占用 CPU 和 RAM，被内核杀死的可能性更高，以确保系统的可操作性（还记得*第四章*中提到的**内存不足**（**OOM**）杀手，*常规操作工具*吗？）。

例如，让我们使用以下代码将运行备份的进程（包含进程名称中的备份模式）的优先级降低到最低：

```
pgrep –f backup | xargs renice –n 19
143405 (process ID) old priority 0, new priority 19
144389 (process ID) old priority 0, new priority 19
2924457 (process ID) old priority 0, new priority 19
3228039 (process ID) old priority 0, new priority 19
```

正如我们所看到的，`pgrep`已经收集了一系列 PID，并且该列表已被作为`renice`的参数进行了管道传输，优先级调整为 19，使实际在系统中运行的进程更加友好。

让我们在系统中通过使用`bc`运行π（π）计算来重复前面的例子，就像`bc`的 man 页面中所示。首先，我们将计算系统所需的时间，然后通过`renice`执行它。所以，让我们动手操作—首先，让我们计时，如下所示：

```
time echo "scale=10000; 4*a(1)" | bc –l
```

在我的系统中，这是结果：

```
real 3m8,336s
user 3m6,875s
sys  0m0,032s
```

现在，让我们使用`renice`运行它，如下所示：

```
time echo "scale=10000; 4*a(1)" | bc -l &
pgrep –f bc |xargs renice –n 19 ; fg
```

在我的系统中，这是结果：

```
real 3m9,013s
user 3m7,273s
sys  0m0,043s
```

有 1 秒的轻微差异，但您可以尝试在您的环境中运行更多进程以生成系统活动，使其更加明显，并在规模上增加更多的零以增加执行时间。同样，`ionice`可以调整进程引起的 I/O 操作（读取、写入）的优先级—例如，对于我们的备份进程重复操作，我们可以运行以下命令：

```
pgrep –f  backup|xargs ionice –c 3 –p 
```

默认情况下，它不会输出信息，但我们可以通过执行以下命令来检查值：

```
pgrep -f backup|xargs ionice -p
idle
idle
idle
idle
```

在这种情况下，我们已将备份进程移动，以便在系统空闲时处理 I/O 请求。

我们使用`-c`参数指定的类可以是以下之一：

+   `0`：无

+   `1`：实时

+   `2`：尽力而为

+   `3`：空闲

使用`-p`，我们指定要操作的进程。

我们可以应用到系统的大多数设置都来自特定的设置，通过`/proc/`虚拟文件系统应用到每个 PID，例如—例如—调整`oom_adj`文件以减少`oom_score`文件上显示的值，最终确定进程是否应在 OOM 需要杀死一些进程以尝试拯救系统免受灾难时更高。

当然，还有一些系统级设置，例如`/proc/sys/vm/panic_on_oom`，可以调整系统如何在 OOM 必须被调用时做出反应（是否恐慌）。

磁盘还有一个设置，用于定义正在使用的调度程序—例如，对于名为`sda`的磁盘，可以通过`cat /sys/block/sda/queue/scheduler`进行检查。

磁盘使用的调度程序有不同的方法，取决于内核版本—例如，在 RHEL 7 中，它曾经是`noop`、`deadline`或`cfq`，但在 RHEL 8 中，这些已被移除，我们有`md-deadline`、`bfq`、`kyber`和`none`。

这是一个如此庞大而复杂的主题，甚至有一个专门的手册，网址为[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux_for_real_time/8/html-single/tuning_guide/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_for_real_time/8/html-single/tuning_guide/index)，所以如果您有兴趣深入了解，请查看它。

我希望在这里实现两件事，如下所示：

+   明确指出系统有很多调整选项，并且有自己的文档，甚至有一个 Red Hat 认证架构师考试，网址为[`www.redhat.com/en/services/training/rh442-red-hat-enterprise-performance-tuning`](https://www.redhat.com/en/services/training/rh442-red-hat-enterprise-performance-tuning)。

+   这并不是一项容易的任务—在本书中多次强调了一个观点：使用您系统的工作负载测试一切，因为结果可能因系统而异。

幸运的是，不需要对系统调优感到害怕——我们可以通过经验在各个层面（知识、硬件、工作负载等）变得更加熟练，但另一方面，系统也包括一些更简单的方法来进行快速调整，适用于许多场景，我们将在下一节中看到。

# 安装 tuned 和管理调优配置文件

希望在前面的部分中发生了一些危言耸听之后，您已经准备好迎接更简单的路径了。

以防万一，请确保已安装了`tuned`软件包，或者使用`dnf –y install tuned`进行安装。该软件包提供了一个必须启用并启动的*tuned*服务；作为复习，我们通过运行以下命令来实现这一点：

```
systemctl enable tuned
systemctl start tuned
```

现在我们已经准备好与该服务进行交互并获取更多信息，该服务在`dnf info tuned`中宣布自己是一个根据某些观察动态调整系统的守护进程，目前正在以太网网络和硬盘上运行。

通过`tuned-adm`命令与守护进程进行交互。为了说明，我们在下图中展示了可用的命令行选项和配置文件列表：

![图 16.5 - tuned-adm 命令行选项和配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_005.jpg)

图 16.5 - tuned-adm 命令行选项和配置文件

正如我们所看到的，有一些选项可以列出、禁用和获取有关配置文件的信息，获取有关要使用哪个配置文件的建议，验证设置是否已被更改，自动选择配置文件等。

要记住的一件事是，较新版本的`tuned`软件包可能会带来额外的配置文件或配置（存储在`/usr/lib/tuned/`文件夹层次结构中），因此您的系统可能会有所不同。

让我们在下表中回顾一些最常见的选项：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Table_16.1_a.jpg)![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Table_16.1_b.jpg)

正如前面提到的，每个配置都是一种权衡：提高性能需要更多的功耗，或者提高吞吐量可能会增加延迟。

让我们为我们的系统启用`latency-performance`配置文件。为此，我们将执行以下命令：

```
tuned-adm profile latency-performance
```

我们可以通过`tuned-adm active`来验证它是否已激活，可以看到它显示了`latency-performance`，如下图所示：

![图 16.6 - tuned-adm 配置文件激活和验证](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_006.jpg)

图 16.6 - tuned-adm 配置文件激活和验证

我们还通过`sysctl -w vm.swappiness=69`（故意）修改了系统，以演示`tuned-adm verify`操作，因为它报告说一些设置已经从配置文件中定义的设置发生了变化。

重要提示

截至目前，默认情况下动态调整是禁用的——要启用或检查当前状态，请检查`/etc/tuned/tuned-main.conf`文件中是否出现了`dynamic_tuning=1`。在性能配置文件中它是被禁用的，因为默认情况下它试图在功耗和系统性能之间取得平衡，这与性能配置文件的目标相反。

另外，请记住，本书介绍的**Cockpit**界面还提供了一种更改性能配置文件的方法——如下截图所示——一旦您在主 Cockpit 页面上点击了**Performance profile**链接，就会打开此对话框：

![图 16.7 - 在 Cockpit Web 界面中更改 tuned 配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_007.jpg)

图 16.7 - 在 Cockpit Web 界面中更改 tuned 配置文件

在下一节中，我们将探讨调优配置文件在幕后是如何工作的，以及如何创建自定义配置文件。

# 创建一个自定义的调优配置文件

一旦我们评论了不同的 tuned 配置文件... *它们是如何工作的？如何创建一个？*

例如，让我们通过检查`/usr/lib/tuned/latency-performance/tuned.conf`文件来检查`latency-performance`。

一般来说，文件的语法在`man tuned.conf`页面中有描述，但是文件，正如您将能够检查的那样，是一个*初始化（ini）文件*——也就是说，它是一个在括号之间表达的类别文件，并且由等号（`=`）分配的键和值对。

主要部分定义了配置文件的摘要，如果它通过`include`从另一个配置文件继承，并且其他部分取决于安装的插件。

要了解可用的插件，man 页面中包含的文档指示我们执行`rpm -ql tuned | grep 'plugins/plugin_.*.py$'`，这将提供类似于以下的输出：

![图 16.8 - 系统中可用的 tuned 插件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_16_008.jpg)

图 16.8 - 系统中可用的 tuned 插件

重要提示

如果两个或更多的插件尝试对相同的设备进行操作，`replace=1`设置将标记运行它们所有还是只运行最新的一个。

回到`latency-performance`配置文件，它有三个部分：`main`、`cpu`和`sysctl`。

对于 CPU，它设置了性能调度器，我们可以通过`cat /sys/devices/system/cpu/*/cpufreq/scaling_governor`检查每个系统中可用的 CPU 是否支持。请记住，在某些系统中，路径可能不同，甚至可能不存在，我们可以通过执行`cpupower frequency-info –governors`来检查可用的路径，`powersave`和`performance`是最常见的。

对于每个插件的部分名称可能是任意的，如果我们指定`type`关键字来指示要使用哪个插件，并且我们可以使用`devices`关键字来对一些设备进行操作，例如，根据正在配置的磁盘的不同设置，允许定义几个磁盘部分。例如，我们可能希望为系统磁盘（比如`sda`）和用于数据备份的磁盘（比如`sdb`）定义一些设置，如下所示：

```
[main_disk]
type=disk
devices=sda
readahead=>4096
[data_disk]
type=disk
devices=!sda
spindown=1
```

在前面的例子中，名为`sda`的磁盘使用`readahead`进行配置（它在当前利用之前读取扇区，以便在实际请求访问数据之前将数据缓存），我们告诉系统`spindown`数据磁盘，这些磁盘可能仅在备份时使用，因此在不使用时减少噪音和功耗。

另一个有趣的插件是`sysctl`，被几个配置文件使用，它以与`sysctl`命令相同的方式定义设置，因此可能性是巨大的：定义用于调整网络、虚拟内存管理、透明大页等的**传输控制协议**（**TCP**）窗口大小。

提示

从头开始进行任何性能调整都很困难，而且由于`tuned`允许我们从父级继承设置，因此找到可用配置文件中最接近我们想要实现的目标的配置文件，检查其中的配置，当然，与其他配置文件进行比较是有意义的（正如我们所看到的，其他插件也有示例），并将其应用到我们的自定义配置文件中。

为了了解定义的系统配置文件如何影响系统，我的 RHEL 8 系统对`cat /usr/lib/tuned/*/tuned.conf|grep -v ^#|grep '^\'|sort –u`命令显示以下输出：

![图 16.9 - 系统提供的配置文件中的部分



图 16.9 - 系统提供的配置文件中的部分

因此，正如我们所看到的，它们涉及到很多领域，我想强调`script`部分，它定义了一个用于`powersave`配置文件执行的 shell 脚本，以及`variables`部分，它用于`throughput-performance`配置文件，用于定义后续匹配和基于 CPU 应用设置的正则表达式。

一旦我们准备好，我们将在`/etc/tuned/newprofile`下创建一个新的文件夹。必须创建一个`tuned.conf`文件，其中包含摘要的主要部分和我们想要使用的插件的其他部分。

创建新配置文件时，如果我们将感兴趣的配置文件从`/usr/lib/tuned/$profilename/`复制到我们的`/etc/tuned/newprofile/`文件夹中，并从那里开始定制，可能会更容易。

一旦准备就绪，我们可以使用`tuned-adm profile newprofile`启用配置文件，就像我们在本章中介绍的那样。

您可以在官方文档中找到有关可用配置文件的更多信息[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/monitoring_and_managing_system_status_and_performance/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/monitoring_and_managing_system_status_and_performance/index)。

有了这个，我们为调整性能设置设置了自定义配置文件。

# 摘要

在本章中，我们学习了如何识别进程，检查它们的资源消耗，以及如何向它们发送信号。

关于信号，我们了解到其中一些具有一些额外的行为，比如优雅或突然终止进程，或者只是发送通知，一些程序将其理解为重新加载配置而不重新启动等等。

此外，关于进程，我们学习了如何调整它们相对于 CPU 和 I/O 的优先级，以便我们可以调整长时间运行的进程或磁盘密集型进程，以免影响其他正在运行的服务。

最后，我们介绍了`tuned`守护程序，其中包括几个通用的使用案例配置文件，我们可以直接在我们的系统中使用，允许`tuned`应用一些动态调整，或者我们可以通过创建自己的配置文件来微调配置文件，以提高系统性能或优化功耗。

在下一章中，我们将学习如何使用容器、注册表和其他组件，以便应用程序可以在供应商提供的情况下运行，同时与运行它们的服务器隔离。


# 第十七章：使用 Podman、Buildah 和 Skopeo 管理容器

在本章中，我们将学习如何使用 Podman 和 Red Hat Universal Base Image（UBI）。Podman 和 UBI 共同为用户提供了在**Red Hat Enterprise Linux**（RHEL）上运行、构建和共享企业级容器所需的软件。

近年来，理解和使用容器已成为 Red Hat 系统管理员的关键要求。在本章中，我们将回顾容器的基础知识，容器的工作原理以及管理容器的标准任务。

您将学习如何使用简单命令运行容器，构建企业级容器镜像，并在生产系统上部署它们。您还将学习何时使用更高级的工具，如 Buildah 和 Skopeo。

本章将涵盖以下主题：

+   容器简介

+   使用 Podman 和 UBI 在本地 RHEL 8 系统上运行容器

+   何时使用 Buildah 和 Skopeo

# 技术要求

在本章中，我们将回顾 Podman、Buildah 和 Skopeo 的基本用法，以及如何使用 Red Hat UBI 构建和运行容器。

我们将在本地 RHEL 8 系统上创建和运行容器，就像我们在*第一章*中部署的那样，*安装 RHEL8*。您需要安装`container-tools:rhel8` **应用流**。

# 容器简介

容器为用户提供了在 Linux 系统上运行软件的新方式。容器以一种一致的可再分发方式提供了与给定软件相关的所有依赖关系。虽然最初是由 Docker、Google、Red Hat 等推广的，但许多其他公司加入 Docker 创建了一组名为**Open Container Initiative**（OCI）的开放标准。OCI 标准的流行促进了一个大型的工具生态系统，用户不必担心流行的容器镜像、注册表和工具之间的兼容性。近年来，容器已经标准化，大多数主要工具遵循 OCI 规范，如下所述：

+   镜像规范：规定了容器镜像在磁盘上的保存方式

+   运行时规范：指定了如何通过与操作系统（特别是 Linux 内核）通信来启动容器

+   分发规范：规定了如何从注册表服务器推送和拉取镜像

您可以在 https://opencontainers.org/了解更多信息。

所有容器工具（Docker、Podman、Kubernetes 等）都需要一个操作系统来运行容器，每个操作系统可以选择不同的技术集来保护容器，只要它们符合 OCI 标准。RHEL 使用以下操作系统功能来安全存储和运行容器：

+   命名空间：这是 Linux 内核中的一种技术，有助于将进程相互隔离。命名空间防止容器化进程看到主机操作系统上的其他进程（包括其他容器）。命名空间是使容器感觉像**虚拟机**（VM）的技术。

+   控制组（Cgroups）：这些限制了给定进程/容器可用的中央处理单元（CPU）、内存、磁盘输入/输出（I/O）和/或网络 I/O 的数量。这可以防止“吵闹的邻居”问题。

+   安全增强型 Linux（SELinux）：如*第十章*中所述，使用 SELinux 可以提供额外的操作系统安全层，可以限制安全漏洞造成的损害。当与容器一起使用时，SELinux 几乎是透明的，并且可以在工具（如 Podman、Docker 或 Runc）存在漏洞时提供安全突破的缓解。

许多系统管理员使用虚拟机来隔离应用程序及其依赖项（库等）。容器提供了相同级别的隔离，但减少了虚拟化的开销。由于容器是简单的进程，它们不需要具有所有翻译开销的**虚拟 CPU**（**vCPU**）。容器也比虚拟机小，这简化了管理和自动化。这对于**持续集成/持续交付**（**CI/CD**）特别有用。

RHEL 为用户提供了与所有 OCI 标准兼容的容器工具和镜像。这意味着它们的工作方式对于使用过 Docker 的人来说非常熟悉。对于不熟悉这些工具和镜像的人，以下概念很重要：

+   **层**：容器镜像是作为一组层构建的。通过添加新层（甚至删除内容）来创建新容器，这些新层重用现有的较低层。使用现有的预打包容器的能力对于只想对其应用程序进行更改并以可重现的方式进行测试的开发人员非常方便。

+   **分发和部署**：由于容器提供了与应用程序耦合的所有依赖项，因此它们易于部署和重新分发。将它们与容器注册表结合使用，可以轻松共享容器镜像，并且协作、部署和回滚都更快更容易。

RHEL 提供的容器工具使得在小规模上部署容器变得容易，即使是用于生产工作负载。但是，要以可靠的方式大规模管理容器，容器编排（如 Kubernetes）是更好的选择。红帽公司根据构建 Linux 发行版的经验，创建了一个名为**OpenShift**的 Kubernetes 发行版。如果您需要大规模部署容器，我们建议您看看这个平台。RHEL 提供的容器工具和镜像，以及本章介绍的内容，将为以后准备好部署到 Kubernetes/OpenShift 提供坚实的基础。本章介绍的工具将为您的应用程序在准备好时部署到 Kubernetes 做好准备。

## 安装容器工具

RHEL 8 提供了两个**容器工具**的应用流。第一个是每 12 周更新一次的快速移动流。第二个是每年发布一次并支持 24 个月的稳定流。

在安装容器工具之前，让我们看一下有哪些可用的，如下所示：

```
[root@rhel8 ~]# yum module list | grep container-tools
container-tools      rhel8 [d][e]    common [d]                               Most recent (rolling) versions of podman, buildah, skopeo, runc, conmon, runc, conmon, CRIU, Udica, etc as well as dependencies such as container-selinux built and tested together, and updated as frequently as every 12 weeks.
container-tools      1.0             common [d]                               Stable versions of podman 1.0, buildah 1.5, skopeo 0.1, runc, conmon, CRIU, Udica, etc as well as dependencies such as container-selinux built and tested together, and supported for 24 months.
container-tools      2.0             common [d]                               Stable versions of podman 1.6, buildah 1.11, skopeo 0.1, runc, conmon, etc as well as dependencies such as container-selinux built and tested together, and supported as documented on the Application Stream lifecycle page.    
container-tools      3.0             common [d]                               Stable versions of podman 3.0, buildah 1.19, skopeo 1.2, runc, conmon, etc as well as dependencies such as container-selinux built and tested 
together, and supported as documented on the Application Stream lifecycle page.
```

让我们来看一下我们列出的主要工具，如下所示：

+   `podman`：这是运行容器的命令。您可以在任何情况下使用它，就像您在互联网上发现的示例中使用`docker`命令一样。这是我们在本章中用来运行我们自己的容器的命令。

+   `buildah`：这是一个用于创建容器镜像的特定工具。它使用与 Docker 相同的 Dockerfile 定义，但不需要守护进程。

+   `skopeo`：这是一个用于审查容器并检查不同层的工具，以便我们可以查看它们是否包含任何不符合规范的问题。

我们将安装快速移动流，以便访问 Podman、Skopeo 和 Buildah 的最新版本，如下所示：

```
[root@rhel8 ~]# yum module install container-tools:rhel8
... [output omitted] ...
```

现在您已经安装了所有在 RHEL 8 系统上构建、运行和管理容器所需的工具。

# 使用 Podman 和 UBI 运行容器

现在您已经安装了容器工具的应用流，让我们运行一个基于红帽 UBI 的简单容器，这是一组基于 RHEL 的官方容器镜像和额外软件。要运行 UBI 镜像，只需要一个命令，如下面的代码片段所示：

```
[root@rhel8 ~]# podman run –it registry.access.redhat.com/ubi8/ubi bash
[root@407ca121cbbb /]#
```

提示

这些教程以 root 身份运行命令，但 Podman 的一个好处是它可以以普通用户身份运行容器，无需特殊权限或在系统中运行守护程序。

现在您有一个完全隔离的环境，可以在其中执行任何您想要的操作。您可以在此容器中运行任何命令。它与主机和可能正在运行的其他容器隔离，并且甚至可以在其中安装软件。

注意

Red Hat UBI 基于 RHEL 的软件和软件包。这是用于 RHEL 的官方镜像，并为您的容器提供了一个坚实、企业级的基础。UBI 在本章中被广泛使用。

运行这样的一次性容器对于测试新的配置更改和新的软件部件而不干扰主机上的软件非常有用。

让我们来看看容器中正在运行的进程，如下所示：

```
[root@ef3e08e4eac2 /]# ps -efa
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 13:50 pts/0    00:00:00 bash
root          12       1  0 13:52 pts/0    00:00:00 ps -efa
```

正如您所看到的，唯一正在运行的进程是我们正在使用的 shell 和我们刚刚运行的命令。这是一个完全隔离的环境。

现在，通过运行以下命令退出容器：

```
[root@407ca121cbbb /]# exit
[root@rhel8 ~]#
```

现在我们已经在本地缓存了一组可工作的容器工具和 UBI 容器镜像，我们将继续进行一些更基本的命令。

## 基本容器管理-拉取、运行、停止和移除

在本节中，我们将运行一些基本命令，以熟悉使用容器。首先，让我们拉取一些更多的镜像，如下所示：

```
[root@rhel8 ~]# podman pull registry.access.redhat.com/ubi8/ubi-minimal
...
[root@rhel8 ~]# podman pull registry.access.redhat.com/ubi8/ubi-micro
...
[root@rhel8 ~]# podman pull registry.access.redhat.com/ubi8/ubi-init
...
```

我们现在本地缓存了几个不同的镜像。让我们在这里看看它们：

```
[root@rhel8 ~]#  podman images
REPOSITORY                                   TAG     IMAGE ID      CREATED     SIZE
registry.access.redhat.com/ubi8/ubi          latest  613e5da7a934  2 weeks ago  213 MB
registry.access.redhat.com/ubi8/ubi-minimal  latest  332744c1854d  2 weeks ago  105 MB
registry.access.redhat.com/ubi8/ubi-micro    latest  75d0ed7e8b6b  5 weeks ago  38.9 MB
registry.access.redhat.com/ubi8/ubi-init     latest  e13482c4e694  2 weeks ago  233 MB
```

请注意，我们本地缓存了四个镜像。Red Hat UBI 实际上有多种不同的版本，如下所述：

+   `ubi8/ubi`): 这是一个基于 RHEL 的容器基础镜像，镜像中包含了**YellowDog Updater Modified** (**YUM**)/**Dandified YUM** (**DNF**)。它可以像任何其他 Linux 基础镜像一样使用。这个镜像针对 80%的用户使用情况，并且可以轻松地在 Dockerfile 或 Containerfile 中使用。这个镜像的折衷之处在于它比其他一些镜像更大。

+   `ubi8/ubi-minimal`): 这个基础镜像通过使用一个名为`microdnf`的小型包管理器来最小化尺寸，该包管理器是用 C 编写的，而不是像标准的 YUM/DNF 那样使用 Python。这个 C 实现使它更小，并且在容器镜像中拉取更少的依赖项。这个基础镜像可以在任何 Dockerfile 或 Containerfile 中使用，只需使用`microdnf`命令而不是`yum`。这个镜像在内存中节省了大约 80 兆字节（MB）。

+   `ubi8/ubi-micro`): 这个基础镜像没有包管理器。它不能与标准的 Dockerfile 或 Containerfile 一起使用。用户可以使用容器主机上的 Buildah 工具向这个镜像添加软件。这个镜像是 RHEL 提供的最小的基础镜像。

+   `ubi8/ubi-init`): 基于 RHEL 标准镜像，这个镜像也支持在容器中使用`systemd`。这使得安装一些软件、使用`systemd`启动它们并将容器视为 VM 变得很容易。这个镜像最适合那些不介意略大一些镜像，只想要使用方便的用户。

现在您已经了解了四种基础镜像的基础知识，让我们在后台启动一个容器，以便在其运行时进行检查。使用以下命令在后台启动它：

```
[root@rhel8 ~]# podman run -itd --name background ubi8 bash
262fa3beb8348333d77381095983233bf11b6584ec1f 22090604083c0d94bc50
```

请注意，当我们启动容器时，shell 返回正常状态，我们无法在容器中输入命令。我们的终端不会进入容器中的 shell。`-d`选项指定容器应在后台运行。这就是大多数基于服务器的软件（如 Web 服务器）在 Linux 系统上运行的方式。

如果需要，我们仍然可以将我们的 shell 连接到后台运行的容器，但是我们必须确定要连接到哪个容器。为此，请使用以下命令列出所有正在运行的容器：

```
[root@rhel8 ~]# podman ps
CONTAINER ID  IMAGE                                   COMMAND   CREATED             STATUS                 PORTS   NAMES
262fa3beb834  registry.access.redhat.com/ubi8:latest  bash     About a minute ago  Up About a minute ago          background
```

我们可以使用容器 ID 值引用容器，但我们已经使用名称 background 启动了容器，以便更容易引用。我们可以使用 exec 子命令进入容器并查看其中发生的情况，如下所示：

```
[root@rhel8 ~]# podman exec –it background bash
[root@262fa3beb834 /]#
```

在输入一些命令后，通过运行以下命令退出容器：

```
[root@262fa3beb834 /]# exit
```

现在，让我们通过运行以下命令停止容器化进程：

```
[root@262fa3beb834 /]# podman stop background 262fa3beb8348333d77381095983233bf11b6584ec1f 22090604083c0d94bc50
```

通过运行以下命令确保它确实已停止：

```
[root@rhel8 ~]# podman ps -a
CONTAINER ID  IMAGE                                   COMMAND   CREATED             STATUS                 PORTS   NAMES
262fa3beb834  registry.access.redhat.com/ubi8:latest  bash     7 minutes ago  Exited (0) About a minute ago          background
```

注意状态是`Exited`。这意味着进程已停止并且不再在内存中，但存储仍然可用在磁盘上。容器可以重新启动，或者我们可以使用以下命令永久删除它：

```
[root@rhel8 ~]# podman rm background
262fa3beb8348333d77381095983233bf11b6584ec1f 22090604083c0d94bc50
```

这将删除存储，容器现在已经永远消失。通过运行以下命令来验证：

```
[root@rhel8 ~]# podman ps -a
CONTAINER ID  IMAGE                                   COMMAND  CREATED              STATUS                 PORTS   NAMES
```

本节向您介绍了一些基本命令，但现在让我们转向附加存储。

## 将持久存储附加到容器

请记住，容器中的存储是临时的。一旦执行了`podman rm`命令，存储就会被删除。如果您有需要在容器被删除后保存的数据，您需要使用卷。要使用卷运行容器，请执行以下命令：

```
[root@rhel8 ~]# podman run –it --rm -v /mnt:/mnt:Z --name data ubi8 bash
[root@12ad2c1fcdc2 /]#
```

前面的命令已将`/mnt`挂载到容器中，并且`Z`选项已告诉它适当地更改 SELinux 标签，以便可以向其写入数据。`--rm`选项确保一旦退出 shell，容器就会被删除。您现在可以在此卷上保存数据，并且在退出容器时不会被删除。通过运行以下命令添加一些数据：

```
[root@12ad2c1fcdc2 /]# touch /mnt/test.txt
[root@12ad2c1fcdc2 /]# exit
exit
[root@rhel8 ~]#
```

现在，通过运行以下命令检查您创建的测试文件：

```
[root@rhel8 ~]# ls /mnt/data
test.txt
```

请注意，尽管容器已被删除并且其内部存储已被删除，但文件仍然存在于系统上。

## 在生产系统上使用`systemd`部署容器

由于 Podman 不是守护程序，它依赖于`systemd`在系统启动时启动容器。Podman 通过创建一个`systemd`来轻松启动一个`systemd`容器，`systemd`看起来像这样：

1.  使用 Podman 以与生产环境完全相同的方式运行容器。

1.  导出一个`systemd`单元文件。

1.  配置`systemd`以使用此单元文件。

首先，让我们运行一个示例容器，如下所示：

```
[root@rhel8 ~]# podman run -itd --name systemd-test ubi8 bash
D8a96d6a51a143853aa17b7dd4a827efa2755820c9967bee52 fccfeab2148e98
```

现在，让我们导出我们将用于启动此容器的`systemd`单元文件，如下所示：

```
[root@rhel8 ~]# podman generate systemd --name --new systemd-test > /usr/lib/systemd/system/podman-test.service
```

通过运行以下命令启用并启动服务：

```
systemctl enable --now podman-test
Created symlink /etc/systemd/system/multi-user.target.wants/podman-test.service → /usr/lib/systemd/system/podman-test.service.
Created symlink /etc/systemd/system/default.target.wants/podman-test.service → /usr/lib/systemd/system/podman-test.service
```

通过执行以下命令测试容器是否正在运行：

```
[root@rhel8 ~]# systemctl status podman-test
● podman-test.service - Podman container-systemd-test.service
Loaded: loaded (/usr/lib/systemd/system/podman-test.service; enabled; vendor preset: disabled)
Active: active (running) since Thu 2021-04-29 20:29:30 EDT; 13min ago
[output omitted] 
...
```

现在，使用`podman`命令检查容器是否正在运行，如下所示：

```
[root@rhel8 ~]# podman ps
CONTAINER ID  IMAGE                                   COMMAND  CREATED              STATUS                 PORTS   NAMES
7cb55cc98e81  registry.access.redhat.com/ubi8:latest  bash     About a minute ago  Up About a minute ago          systemd-test
```

这个容器现在将在系统启动时启动；即使您使用 Podman 杀死容器，`systemd`也会始终确保此容器正在运行。Podman 和`systemd`使得在生产环境中运行容器变得容易。现在，让我们使用`systemctl`停止容器并禁用它，如下所示：

```
systemctl stop podman-test
systemctl disable podman-test
```

## 使用 Dockerfile 或 Containerfile 构建容器镜像

现在我们知道如何运行容器，让我们学习如何构建自己的容器镜像。容器镜像通常是使用作为每次构建它的蓝图的文件构建的。具有以下内容的`Containerfile`：

```
FROM registry.access.redhat.com/ubi8/ubi
RUN yum update -y
```

这个简单的`Containerfile`拉取了 UBI 标准基础镜像，并对其应用了所有最新的更新。现在，通过运行以下命令构建一个容器镜像：

```
[root@rhel8 ~]# podman build –t test-build ./Containerfile
STEP 1: FROM registry.access.redhat.com/ubi8/ubi
STEP 2: RUN yum update –y
... [output omitted] ...
```

现在您有一个名为`test-build`的新镜像，其中包含来自 Red Hat UBI 存储库的所有更新包的新层，如下面的代码片段所示：

```
[root@rhel8 ~]# podman images
REPOSITORY                                   TAG     IMAGE ID      CREATED        SIZE
localhost/test-build                         latest  6550a939d3ef  9 minutes ago  335 MB
... [output omitted] ...
```

从 Dockerfile 或 Containerfile 构建图像的工作流程几乎与 RHEL 7 中的 Docker 或任何其他操作系统中的工作流程相同。这使得系统管理员和开发人员可以轻松地转移到 Podman。

## 配置 Podman 以搜索注册表服务器

**容器注册表**就像容器镜像的文件服务器。它们允许用户构建和共享容器镜像，从而实现更好的协作。通常，从位于互联网上的公共注册表服务器中拉取容器镜像是很有用的，但在许多情况下，公司有私有注册表，这些注册表不是公开的。Podman 可以轻松地搜索多个注册表，包括公司网络上的私有注册表。

Podman 带有一个配置文件，允许用户和管理员选择默认搜索哪些注册表。这使得用户可以轻松找到管理员希望他们找到的容器镜像。

一组默认的注册表搜索在`/etc/containers/registries.conf`中定义。让我们通过过滤其中的所有注释来快速查看这个文件，如下所示：

```
[root@rhel8 ~]# cat /etc/containers/registries.conf | grep -v ^#
[registries.search]
registries = ['registry.access.redhat.com', 'registry.redhat.io', 'docker.io'] 
[registries.insecure]
registries = []

[registries.block]
registries = []

unqualified-search-registries = ["registry.fedoraproject.org", "registry.access.redhat.com", "registry.centos.org", "docker.io"]
```

如您所见，我们在`registries.search`部分中为安全注册表定义了两个主要的 Red Hat 注册表，`registry.access.redhat.com`和`registry.redhat.io`，以及`docker.io` Docker 注册表。所有这些注册表都在`registries.insecure`部分中进行了安全配置。

除了 TLS 之外，Red Hat 提供的所有镜像都经过签名，并提供一个签名存储库，可用于验证它们。这不是默认配置，并且超出了本章的范围。

要验证 Podman 是否正在使用和搜索正确的注册表，请运行以下命令：

```
[root@rhel8 ~]# podman info | grep registries -A 4
registries:
  search:
  - registry.access.redhat.com
  - registry.redhat.io
  - docker.io
```

提示

如果您想发布自己的镜像，可以在 Red Hat 提供的服务中这样做：[`quay.io`](https://quay.io)。您还可以配置`registries.conf`来搜索您在那里存储的镜像的`quay.io`。

## Podman 选项摘要

让我们来回顾一下本章中与 Podman 一起使用的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Table_1.1.jpg)

通过查看表格，您可以看到 Podman 包括管理完整容器生命周期的选项。大多数 Podman 命令与`docker`兼容。Podman 甚至提供了一个包（`podman-docker`），它提供了从`podman`到`docker`的别名，以便用户可以继续输入他们熟悉的命令。虽然 Podman 和 Docker 在使用上感觉相似，但 Podman 可以作为普通用户运行，不需要持续运行的守护进程。让我们继续下一节，探索一些高级用例。

# 何时使用 Buildah 和 Skopeo

Podman 是一个通用的容器工具，应该能够解决用户 95%的需求。Podman 利用 Buildah 和 Skopeo 作为库，并将这些工具集成到一个界面下。也就是说，有一些边缘情况，用户可能希望单独利用 Buildah 或 Skopeo。我们将探讨两种这样的用例。

## 使用 Buildah 构建容器镜像

从 Dockerfile 或 Containerfile 构建非常容易，但也伴随着一些权衡。例如，Buildah 在以下情况下很好用：

+   当您需要对提交的镜像层进行细粒度控制时。当您希望运行两到三个命令，然后提交一个单独的层时，这可能是必要的。

+   当您有难以安装的软件时——例如，一些第三方软件带有标准化的安装程序，这些安装程序不知道它们正在 Dockerfile 中运行。许多这些`install.sh`安装程序假定它们可以访问整个文件系统。

+   当一个容器镜像没有提供包管理器时。UBI Micro 构建非常小的镜像，因为它没有安装 Linux 包管理器，也没有任何包管理器的依赖项。

对于这个例子，让我们在 UBI Micro 的基础上构建，以演示为什么 Buildah 是一个如此好用的工具。首先，创建一个新的容器来使用，如下所示：

```
[root@rhel8 ~]# buildah from registry.access.redhat.com/ubi8/ubi-micro
ubi-micro-working-container
```

上面的命令创建了一个对名为`ubi-micro-working-container`的新容器的引用。一旦 Buildah 创建了这个引用，您就可以在其基础上构建。为了更方便，让我们重新开始并将引用保存在一个 shell 变量中，如下所示：

```
microcontainer=$(buildah from registry.access.redhat.com/ubi8/ubi-micro)
```

然后，您可以将新容器挂载为一个卷。这样可以通过更改目录中的文件来修改容器镜像。运行以下命令来执行此操作：

```
micromount=$(buildah mount $microcontainer)
```

一旦容器存储被挂载，您可以以任何您想要的方式修改它。这些更改最终将被保存为容器镜像中的一个新层。这就是您可以运行一个安装程序（`install.sh`）的地方，但在下面的示例中，我们将使用主机上的软件包管理器在 UBI Micro 中安装软件包：

```
yum install \
    --installroot $micromount \  --releasever 8 \  --setopt install_weak_deps=false \  --nodocs -y \    httpd
... [output omitted] ...
[root@rhel8 ~]# yum clean all \
    --installroot $micromount
... [output omitted] ...
```

当软件包安装完成后，我们将卸载存储并将新的镜像层提交为一个名为`ubi-micro-httpd`的新容器镜像，如下面的代码片段所示：

```
[root@rhel8 ~]# buildah umount $microcontainer
467403b1633fbcb42535e818929fd49a5e381b86733c99d 65cd8b141e9d64fff
[root@rhel8 ~]# buildah commit $microcontainer ubi-micro-httpd
Getting image source signatures
Copying blob 5f70bf18a086 skipped: already exists  
Copying blob 8e7500796dee skipped: already exists  
Copying blob 881a7504d0b5 skipped: already exists  
Copying blob 771043083e15 done  
Copying config 9579d04234 done  
Writing manifest to image destination
Storing signatures
9579d0423482e766d72e3909f34e8c10d4258128d5cae394 c1f0816ac637eda0
```

您现在有一个安装了`httpd`的新容器镜像，构建在 UBI Micro 上。只引入了一组最小的依赖关系。看看这个镜像有多小：

```
[root@rhel8 ~]# podman images
localhost/ubi-micro-httpd                                     latest                                                       9579d0423482  About a minute ago  152 MB
```

Buildah 是一个很棒的工具，可以让您对构建方式有很多控制。现在，我们将转向 Skopeo。

## 使用 Skopeo 检查远程容器

Skopeo 专门设计和构建用于远程容器存储库。使用以下命令，您可以轻松地远程检查图像的可用标签：

```
[root@rhel8 ~]# skopeo inspect docker://registry.access.redhat.com/ubi8/ubi
{
    "Name": "registry.access.redhat.com/ubi8/ubi",
    "Digest": "sha256:37e09c34bcf8dd28d2eb7ace19d3cf634f8a073058ed63ec6e 199e3e2ad33c33",
    "RepoTags": [
        "8.2-343-source",
        "8.1-328",
        "8.2-265-source",
... [output omitted] ...
```

远程检查对于确定是否要拉取图像以及使用哪个标签非常有用。Skopeo 还可以用于在两个远程注册服务器之间进行复制，而不在本地存储中缓存副本。有关更多信息，请参阅`skopeo`手册页。

# 总结

在本章中，我们已经回顾了在 RHEL 8 上运行、构建和共享容器的基础知识。您已经准备好创建自己的容器，运行它们，管理它们，甚至使用`systemd`来确保它们在生产环境中始终运行。

您现在已经准备好利用容器提供的功能和部署便利性。虽然深入研究将软件迁移到容器中的所有复杂性超出了本书的范围，但容器简化了应用程序的打包和交付，使其准备好以其所有依赖项一起执行。

容器现在是信息技术（IT）行业的一个重点关注领域。容器本身简化了应用程序的打包和交付，但基于 Kubernetes 的 OpenShift 等编排平台使得在规模上部署、升级和管理容器化应用程序变得更加容易。

恭喜您——您已经完成了本章的学习！现在是时候转到下一章，进行自我评估，确保您已经掌握了材料并练习了您的技能。还有两章要学习。


# 第四部分：实际练习

本节包括实际练习，以复习前几节所学内容。它包括中级练习和更高级的练习，让您评估自己的进步。

本节包括以下章节：

+   第十八章，练习题-1

+   第十九章，练习题-2


# 第十八章：练习 1

在这个练习中，我们将运行一系列步骤，检查您在整本书中所学到的知识。与之前的章节不同，不会指示所有步骤，因此您可以自行决定执行所需的步骤以完成您的目标。建议避免参考以前的章节进行指导。相反，尝试使用您的记忆或系统中可用的工具。如果正确执行此练习，将有效地为官方考试进行培训。

强烈建议在进行此练习时使用时钟来跟踪时间。

# **技术要求**

**本章中的所有练习都需要使用虚拟机**（**VM**），运行安装了基本安装的 Red Hat Enterprise Linux 8。此外，存储操作将需要新的虚拟驱动器。

对于练习，假设您拥有以下内容：

+   安装了基本操作系统**最小安装**软件选择的 Red Hat Enterprise Linux 8。

+   访问 Red Hat 客户门户，具有有效的订阅。

+   虚拟机必须是可扩展的。这是因为在练习期间对其执行的操作可能使其无法使用，并需要重新安装。

# 练习提示

这是任何测试的一般建议清单，大多数属于常识范畴，但在进行任何测试之前将它们牢记在心是非常重要的：

+   在开始官方考试或任何测试之前，请先阅读所有问题。

+   特定的词语具有特定的含义，可以提示关于要求或完成目标的方法。这就是为什么先阅读所有内容可能会给您多个完成测试的途径。

+   让自己感到舒适。安装您喜欢的编辑器，并运行`updatedb`以获得一个新的软件包和已安装文件的数据库，以备使用。定义您的键盘布局。安装`tmux`并学习如何使用它，这样您就可以打开新标签并命名它们，而无需额外的窗口。

+   查找请求之间的依赖关系，因为有些目标取决于其他目标的完成。找到这些依赖关系，看看如何在不必后来回来重新做一些步骤的情况下找到解决方案。

+   使用计时器。这对于了解哪些练习将花费更多时间来完成是很重要的，以便看到您需要改进的领域。

+   不要记住具体的命令行。学习如何使用系统中的文档，通过`man`、`/usr/share/docs`或像`--help`这样的参数来获取所需命令的帮助。

+   确保更改持久并在重新启动后仍然有效。有些更改可能在运行时是有效的，但必须持久。例如防火墙规则、启动时要启动的服务等。

+   记住使用`dnf whatprovides /COMMAND"`来查找提供您可能缺少的文件的软件包。

+   检查以下链接：[`www.redhat.com/en/services/training/ex200-red-hat-certified-system-administrator-rhcsa-exam?=Objectives`](https://www.redhat.com/en/services/training/ex200-red-hat-certified-system-administrator-rhcsa-exam?=Objectives)。这将为您提供官方 EX200 考试目标。

# 练习 1

重要提示

以下练习是有意设计的，因此不会突出显示命令、软件包等。记住迄今为止学到的知识，以便检测关键字，看看需要做什么。

不要过早地进行实际操作。试着记住已经涵盖的内容。

## 练习

1.  将时区配置为 GMT。

1.  允许 root 用户使用 SSH 进行无密码登录。

1.  创建一个可以无密码连接到机器的用户（名为*user*）。

1.  用户`user`应该每周更改密码，提前 2 天警告，过期后使用 1 天。

1.  root 用户必须能够以*user*的身份通过 SSH 进行连接，而无需密码，以便没有人可以使用密码远程连接为 root。

1.  用户*user*应能够在无需密码的情况下成为 root 用户，并且还能够在无需密码的情况下执行命令。

1.  当用户尝试通过 SSH 登录时，显示有关不允许未经授权访问该系统的法律消息。

1.  SSH 必须在端口*22222*上监听，而不是默认的端口（*22*）。

1.  创建一个名为`devel`的组。

1.  将`user`添加为`devel`的成员。

1.  将用户成员身份存储在名为`userids`的文件中，位于*user*的主文件夹中。

1.  用户*user*和*root*用户应能够通过 SSH 连接到本地主机，而无需指定端口，并默认使用压缩进行连接。

1.  查找系统中所有的 man 页名称，并将名称放入名为*manpages.txt*的文件中。

1.  打印未允许登录到系统的用户的用户名。对于每个用户名，打印该用户的用户 ID 和组。

1.  每 5 分钟监视可用系统资源。不使用 cron。存储为*/root/resources.log*。

1.  添加一个每分钟的作业，报告可用磁盘空间的百分比，并将其存储在*/root/freespace.log*中，以便显示文件系统和可用空间。

1.  配置系统仅保留 3 天的日志。

1.  配置*/root/freespace.log*和*/root/resources.log*的日志轮换。

1.  使用快速同步配置时间同步针对*pool.ntp.org*。

1.  为子网*172.22.0.1/24*提供 NTP 服务器服务。

1.  配置系统统计信息，每分钟收集一次。

1.  将系统中用户的密码长度配置为 12 个字符。

1.  创建一个名为*privacy*的机器人用户，其文件默认情况下只对自己可见。

1.  创建一个在*shared*中可以被所有用户访问的文件夹，并将新文件和目录默认为仍然可以被*devel*组的用户访问。

1.  配置一个名为*mynic*的具有 IPv4 和 IPv6 地址的网络连接，使用以下数据：

```
Ip6: 2001:db8:0:1::c000:207/64 g
gateway 2001:db8:0:1::1 
Ipv4 192.0.1.3/24 
gateway 192.0.1.1 
```

1.  允许主机使用*google*主机名访问[www.google.com](https://www.google.com)，并使用*redhat*主机名访问[www.redhat.com](https://www.redhat.com)。

1.  报告从供应商分发的文件中修改的文件，并将它们存储在*/root/altered.txt*中。

1.  使我们的系统安装媒体包通过 HTTP 在*/mirror*路径下可供其他系统用作镜像，配置我们系统中的存储库。从该镜像中删除内核包，以便其他系统（甚至我们自己的系统）无法找到新的内核。防止从该存储库安装 glibc 包而不将其删除。

1.  在*user*身份下，将*/root*文件夹复制到*/home/user/root/*文件夹，并使其每天保持同步，同步添加和删除。

1.  检查我们的系统是否符合 PCI-DSS 标准。

1.  向系统添加第二个 30GB 的硬盘。但是，只使用 15GB 将镜像移动到其中，并使用压缩和去重功能使其在启动时可用。将其放置在*/mirror/mirror*下。

1.  由于我们计划基于相同数据镜像自定义软件包集，因此配置文件系统报告至少可供我们的镜像使用的 1,500GB。

1.  在*/mirror/mytailormirror*下创建镜像的第二个副本，删除所有以字母*k*开头的包。

1.  在添加的硬盘剩余空间（15GB）中创建一个新卷，并将其用于扩展根文件系统。

1.  创建一个启动项，允许您进入紧急模式，以更改根密码。

1.  创建一个自定义调整配置文件，定义第一个驱动器的预读为*4096*，第二个驱动器的预读为*1024*。此配置文件还应在发生 OOM 事件时使系统崩溃。

1.  禁用并删除已安装的 HTTP 包。然后，使用*registry.redhat.io/rhel8/httpd-24*镜像设置 HTTP 服务器。

对于这一部分，我们将复制目标列表中的每个项目，然后在其下方提供解释，使用适当的语法突出显示和解释。

# 练习 1 解决方案

## 1. 将时区配置为 GMT

我们可以通过执行`date`命令来检查当前系统日期。在随后打印的行的最后部分，将显示时区。为了配置它，我们可以使用`timedatectl`命令，或者修改`/etc/localtime`符号链接。

因此，为了实现这个目标，我们可以使用以下之一：

+   `timedatectl set-timezone GMT`

+   `rm –fv /etc/localtime; ln –s /usr/share/zoneinfo/GMT /etc/localtime`

现在`date`应该报告正确的时区。

## 2. 允许无密码登录到 root 用户使用 SSH

这将需要以下操作：

+   SSH 必须已安装并可用（这意味着已安装并已启动）。

+   root 用户应该生成一个 SSH 密钥并将其添加到授权密钥列表中。

首先，让我们通过 SSH 来解决这个问题，如下所示：

```
dnf –y install openssh-server; systemctl enable sshd; systemctl start sshd
```

现在，让我们通过按*Enter*来生成一个 SSH 密钥以接受所有默认值：

```
ssh-keygen
```

现在，让我们将生成的密钥（`/root/.ssh/id_rsa`）添加到授权密钥中：

```
cd; cd .ssh; cat id_rsa.pub >> authorized_keys; chmod 600 authorized_keys
```

为了验证这一点，我们可以执行`ssh localhost date`，之后我们将能够在不提供密码的情况下获取当前系统的日期和时间。

## 3. 创建一个名为'user'的用户，可以在没有密码的情况下连接到该机器

这需要创建一个用户和一个类似于 root 用户的 SSH 密钥。接下来的选项也将与用户相关，但为了演示目的，我们将它们作为单独的任务来解决：

```
useradd user
su – user
```

现在，让我们通过按*Enter*来生成一个 SSH 密钥以接受所有默认值：

```
ssh-keygen
```

现在，让我们将生成的密钥（`/root/.ssh/id_rsa`）添加到授权密钥中：

```
cd; cd .ssh; cat id_rsa.pub >> authorized_keys; chmod 600 authorized_keys
```

为了验证这一点，我们可以执行`ssh localhost date`，我们将能够在不提供密码的情况下获取当前系统日期和时间。

然后，使用`logout`返回到我们的`root`用户。

## 4. 用户'user'应该每周更改密码，提前 2 天警告，过期后使用 1 天

这要求我们调整用户限制，如下所示：

```
chage –W 2 user
chage –I 1 user
chage -M 7 user
```

## 5. root 用户必须能够以'user'的身份通过 SSH 登录，而无需密码，以便没有人可以使用密码远程连接为 root 用户

这需要两个步骤。第一步是使用 root 的授权密钥启用'user'，然后调整`sshd`守护程序，如下所示：

```
cat /root/id_rsa.pub >> ~user/.ssh/authorized_keys
```

编辑`/etc/sshd/sshd_config`文件，并添加或替换`PermitRootLogin`行，使其看起来像下面这样：

```
PermitRootLogin prohibit-password
```

保存，然后重新启动`sshd`守护程序：

```
systemctl restart sshd
```

## 6. 用户'user'应能够成为 root 并执行命令而无需密码

这意味着通过添加以下行来配置`/etc/sudoers`文件：

```
user ALL=(ALL) NOPASSWD:ALL
```

## 7. 当用户尝试通过 SSH 登录时，显示有关不允许未经授权访问此系统的法律消息

创建一个文件，例如`/etc/ssh/banner`，其中包含要显示的消息。例如，`"Get out of here"`。

修改`/etc/ssh/sshd_config`并将`banner`行设置为`/etc/ssh/banner`，然后使用`systemctl restart sshd`重新启动`sshd`守护程序。

## 8. SSH 必须在端口 22222 上监听，而不是默认端口

这是一个棘手的问题。第一步是修改`/etc/ssh/sshd_config`并定义端口`22222`。完成后，使用以下命令重新启动`sshd`：

```
systemctl restart sshd
```

这当然会失败...为什么？

必须配置防火墙：

```
firewall-cmd –-add-port=22222/tcp --permanent
firewall-cmd –-add-port=22222/tcp 
```

然后必须配置 SELinux：

```
semanage port -a -t ssh_port_t -p tcp 22222
```

现在，`sshd`守护程序可以重新启动：

```
systemctl restart sshd
```

## 9. 创建名为'devel'的组

使用以下命令：

```
groupadd devel
```

## 10. 使'user'成为'devel'的成员

使用以下命令：

```
usermod –G devel user
```

## 11. 将用户成员身份存储在名为'userids'的文件中，在'用户'的主文件夹中

使用以下命令：

```
id user > ~user/userids
```

## 12. 用户'user'和 root 用户应能够通过 SSH 连接到本地主机，而无需指定端口，并默认为连接进行压缩

我们修改了默认的 SSH 端口为`22222`。

为'user'和 root 创建一个名为`.ssh/config`的文件，内容如下：

```
Host localhost
Port 22222
    Compression yes
```

## 13. 查找系统中所有 man 页面名称，并将名称放入名为'manpages.txt'的文件中

手册页存储在 `/usr/share/man`。因此，使用以下命令：

```
find  /usr/share/man/ -type f > manpages.txt
```

## 14\. 打印没有登录的用户的用户名，以便他们可以被允许访问系统，并打印每个用户的用户 ID 和组

以下命令首先构建了一个使用 `nologin` shell 的系统用户列表：

```
for user in $(cat /etc/passwd| grep nologin|cut -d ":" -f 1)
do
echo "$user -- $(grep $user /etc/group|cut -d ":" -f 1|xargs)"
done
```

从列表中检查 `/etc/group` 文件中的成员资格，仅保留组名，并使用 `xargs` 将它们连接成一个要打印的字符串。

上面的示例使用了 `for` 循环和命令的内联执行，通过 `$()`。

## 15\. 每 5 分钟监视可用的系统资源，而不使用 cron，并将它们存储为 /root/resources.log

监视某些东西的理想方式是使用 cron，但由于我们被告知不要使用它，这只留下了我们使用 systemd 定时器。 （您可以通过以下链接检查经过测试的文件：[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/tree/main/chapter-18-exercise1.`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/tree/main/chapter-18-exercise1

）

创建 `/etc/systemd/system/monitorresources.service`，内容如下：

```
[Unit]
Description=Monitor system resources

[Service]
Type=oneshot
ExecStart=/root/myresources.sh
```

创建 `/etc/systemd/system/monitorresources.timer`，内容如下：

```
[Unit]
Description=Monitor system resources

[Timer]
OnCalendar=*-*-* *:0,5,10,15,20,25,30,35,40,45,50,55:00
Persistent=true

[Install]
WantedBy=timers.target
```

创建 `/root/myresources.sh`，内容如下：

```
#!/bin/bash
df > /root/resources.log
```

启用新的定时器，如下所示：

```
systemctl daemon-reload
systemctl enable  monitorresources.timer
```

它有效吗？如果不行，`journalctl –f` 将提供一些细节。SELinux 阻止我们执行 root 文件，所以让我们将其转换为二进制类型并标记为可执行，如下所示：

```
chcon –t bin_t /root/myresources.sh
chmod +x /root/myresources.sh
```

## 16\. 添加每分钟的作业，报告可用的空闲磁盘空间百分比，并将其存储在 /root/freespace.log 中，以显示文件系统和可用空间

`df` 报告已使用的磁盘空间和可用空间，所以我们需要进行一些数学运算。

这将报告挂载位置、大小、已用空间和可用空间，使用 `;` 作为分隔符。参考以下内容：

```
df|awk '{print $6";"$2";"$3";"$4}'
```

Bash 允许我们进行一些数学运算，但这些运算缺少小数部分。幸运的是，我们可以做一个小技巧：我们将循环执行它，如下所示：

```
for each in $(df|awk '{print $6";"$2";"$3";"$4}'|grep -v "Mounted")
do 
    FREE=$(echo $each|cut -d ";" -f 4) 
    TOTAL=$(echo $each|cut -d ";" -f 2) 
    echo "$each has $((FREE*100/TOTAL)) free"
done
```

`for` 循环将检查所有可用的数据，抓取一些特定字段，用 `;` 分隔它们，然后对每一行在 `$each` 变量中运行循环。

我们截取输出，然后获取第四个字段。这是可用空间。

我们截取输出，然后获取第二个字段。这是总块数。

由于 `bash` 可以进行整数除法，我们可以乘以 100，然后除以获取百分比，并将一个字符串添加到输出中。

或者（但不够说明性），我们可以通过 `df` 已经给出的使用百分比减去 100，并节省一些计算步骤。

我们还需要将输出存储在一个文件中。为此，我们可以将整个循环包装在重定向中，或者将其添加到 `echo` 行中，以便将其附加到一个文件中。

我们还需要通过 cron 来完成，因此完整的解决方案如下：

创建一个 `/root/myfreespace.sh` 脚本，内容如下：

```
for each in $(df|awk '{print $6";"$2";"$3";"$4}'|grep -v "Mounted")
do 
    FREE=$(echo $each|cut -d ";" -f 4) 
    TOTAL=$(echo $each|cut -d ";" -f 2) 
    echo "$each has $((FREE*100/TOTAL)) free"
done
```

然后，使用 `chmod 755 /root/myfreespace.sh` 使其可执行。

运行 `crontab -e` 来编辑 root 的 crontab，并添加以下行：

```
*/1 * * * * /root/myfreespace.sh >> /root/freespace.log
```

## 17\. 配置系统只保留 3 天的日志

这可以通过编辑 `/etc/logrorate.conf` 来完成，设置如下：

```
daily
rotate 3
```

删除其他的每周、每月等出现，只留下我们想要的一个。

## 18\. 为 /root/freespace.log 和 /root/resources.log 配置日志轮转

创建一个 `/etc/logrotate.d/rotateroot` 文件，内容如下：

```
/root/freespace.log {
    missingok
    notifempty
    sharedscripts
    copytruncate
}
/root/resources.log {
    missingok
    notifempty
    sharedscripts
    copytruncate
}
```

## 19\. 针对 pool.ntp.org 进行快速同步的时间同步配置

编辑 `/etc/chrony.conf`，添加以下行：

```
pool pool.ntp.org iburst
```

然后运行以下命令：

```
systemctl restart chronyd
```

## 20\. 为子网 172.22.0.1/24 提供 NTP 服务器服务

编辑 `/etc/chrony.conf`，添加以下行：

```
Allow 172.22.0.1/24
```

然后运行以下命令：

```
systemctl restart chronyd
```

## 21\. 每分钟配置系统统计收集

运行以下命令：

```
dnf –y install sysstat
```

现在我们需要修改`/usr/lib/systemd/system/sysstat-collect.timer`。让我们通过创建一个覆盖来做到这一点，如下所示：

```
cp /usr/lib/systemd/system/sysstat-collect.timer /etc/systemd/system/
```

编辑`/etc/systemd/system/sysstat-collect.timer`，将`OnCalendar`值替换为以下内容：

```
OnCalendar=*:00/1
```

然后，使用以下命令重新加载单元：

```
systemctl daemon-reload
```

## 22\. 配置系统中用户密码长度为 12 个字符

使用以下行编辑`/etc/login.defs`：

```
PASS_MIN_LEN 12
```

## 23\. 创建一个名为'privacy'的机器人用户，它默认情况下只能自己看到它的文件

要做到这一点，请运行以下命令：

```
adduser privacy
su – privacy
echo "umask 0077" >> .bashrc
```

此解决方案使用`umask`从所有新创建的文件中删除其他人的权限。

## 24\. 创建一个名为/shared 的文件夹，所有用户都可以访问，并将新文件和目录默认设置为仍然可以被‘devel’组的用户访问

要做到这一点，请运行以下命令：

```
mkdir /shared
chown root:devel /shared
chmod 777 /shared
chmod +s /shared
```

## 25\. 使用提供的数据 Ip6，配置一个名为'mynic'的具有 IPv4 和 IPv6 地址的网络连接，如下所示：2001:db8:0:1::c000:207/64 g gateway 2001:db8:0:1::1 IPv4 192.0.1.3/24 gateway 192.0.1.1

查看以下内容以了解如何完成此操作：

```
nmcli con add con-name mynic type ethernet ifname eth0 ipv6.address 2001:db8:0:1::c000:207/64 ipv6.gateway 2001:db8:0:1::1 ipv4.address 192.0.1.3/24 ipv4.gateway 192.0.1.1
```

## 26\. 允许主机使用 google 主机名访问 www.google.com，使用 redhat 主机名访问 www.redhat.com

运行并记录获取的 IP，如下所示：

```
ping www.google.com
ping www.redhat.com 
```

记下上面获取的 IP。

通过添加以下内容编辑`/etc/hosts`：

```
IPFORGOOGLE google
IPFORREDHAT redhat
```

然后，保存并退出。

## 27\. 报告从供应商分发的文件中修改的文件，并将它们存储在`/root/altered.txt`中

查看以下内容以了解如何完成此操作：

```
rpm  -Va > /root/altered.txt
```

## 28\. 通过 HTTP 在路径`/mirror`下使我们的系统安装媒体包对其他系统可用，并在我们的系统中配置存储库。从该镜像中删除内核软件包，以便其他系统（甚至我们自己）无法找到新的内核。忽略此存储库中的 glibc 软件包，以便安装而不删除它们

这是一个复杂的问题，所以让我们一步一步地来看看。

安装`http`并使用以下命令启用它：

```
dnf –y install httpd
firewall-cmd  --add-service=http --permanent
firewall-cmd  --add-service=http 
systemctl start httpd
systemctl enable httpd
```

在`/mirror`下创建一个文件夹，然后复制源媒体包并通过`http`使其可用：

```
mkdir /mirror /var/www/html/mirror
mount /dev/cdrom /mnt
rsync –avr –progress /mnt/ /mirror/
mount –o bind /mirror /var/www/html/mirror
chcon  -R -t httpd_sys_content_t /var/www/html/mirror/
```

删除内核软件包：

```
find /mirror -name kernel* -exec rm '{}' \;
```

使用以下命令创建存储库文件元数据：

```
dnf –y install createrepo
cd /mirror
createrepo .
```

使用我们创建的存储库文件，并在系统上设置它，忽略其中的`glibc*`软件包。

通过添加以下内容编辑`/etc/yum.repos.d/mymirror.repo`：

```
[mymirror]
name=My RHEL8 Mirror
baseurl=http://localhost/mirror/
enabled=1
gpgcheck=0
exclude=glibc*
```

## 29\. 作为‘user’，将/root 文件夹复制到/home/user/root/文件夹中，并每天保持同步，同步添加和删除

查看以下内容以了解如何完成此操作：

```
su – user
crontab –e 
```

编辑 crontab 并添加以下行：

```
@daily rsync  -avr –-progress –-delete root@localhost:/root/ /home/user/root/
```

## 30\. 检查我们的系统是否符合 PCI-DSS 标准

```
dnf –y install openscap  scap-security-guide openscap-utils 
oscap xccdf eval --report pci-dss-report.html --profile pci-dss /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

## 31\. 向系统添加一个 30GB 的第二硬盘，但只使用 15GB 将镜像移动到其中，并使用压缩和去重功能在启动时使其可用，并在`/mirror/mirror`下可用

这句话中的压缩和去重意味着 VDO。我们需要将当前的镜像移动到 VDO，并使我们以前的镜像移到那里。

如果我们有安装媒体，我们可以选择复制它并重复内核删除或转移。为此，首先让我们在新的硬盘（`sdb`）的分区中创建 VDO 卷：

```
fdisk /dev/sdb
n <enter>
p <enter>
1 <enter>
<enter>
+15G <enter>
w <enter>
q <enter>
```

这将从开始创建一个 15GB 的分区。让我们使用以下命令在其上创建一个 VDO 卷：

```
dnf –y install vdo kmod-kvdo
vdo create –n myvdo –device /dev/sdb --force
pvcreate /dev/mapper/myvdo
vgcreate myvdo /dev/mapper/myvdo
lvcreate –L 15G –n myvol myvdo
mkfs.xfs /dev/myvdo/myvol
# Let's umount cdrom if it was still mounted
umount /mnt
# Mount vdo under /mnt and copy files over
mount /dev/myvdo/myvol /mnt
rsync –avr –progress /mirror/ /mnt/mirror/
# Delete the original mirror once copy has finished 
rm –Rfv /mirror
umount /mnt
mount /dev/myvdo/myvol /mirror
```

此时，旧的镜像已复制到 VDO 卷上的`mirror`文件夹中。这在`/mirror`下挂载，因此它在`/mirror/mirror`下有原始镜像，如要求的。我们可能需要执行以下操作：

+   将`/mirror`绑定到`/var/www/html/mirror/`以使文件可用。

+   恢复 SELinux 上下文以允许`httpd`守护程序访问`/var/www/html/mirror/`中的文件。

调整我们创建的 repofile 以指向新路径。

## 32\. 配置文件系统报告至少 1,500GB 的大小，供我们的镜像使用

查看以下命令：

```
vdo growLogical --name=myvdo --vdoLogicalSize=1500G 
```

## 33. 在/mirror/mytailormirror 下创建镜像的第二个副本，并删除所有以 k*开头的软件包

请参考以下内容如何完成此操作：

```
rsync –avr –progress /mirror/mirror/ /mirror/mytailormirror/
find /mirror/mytailormirror/ -name "k*" -type f –exec rm '{}' \;
cd /mirror/mytailormirror/
createrepo . 
```

## 34. 在硬盘的剩余空间（15 GB）中创建一个新的卷，并用它来扩展根文件系统

请参考以下内容如何完成此操作：

```
fdisk /dev/sdb
n <enter>
p <enter>
<enter>
<enter>
w <enter>
q <enter>
pvcreate /dev/sdb2
# run vgscan to find out the volume name to use (avoid myvdo as is the VDO from above)
vgextend $MYROOTVG /dev/sdb2
# run lvscan to find out the LV storing the root filesystem and pvscan to find the maximum available space
lvresize –L +15G /dev/rhel/root
```

## 35. 创建一个引导项，允许我们进入紧急模式以更改根密码

请参考以下内容如何完成此操作：

```
grubby --args="systemd.unit=emergency.target" --update-kernel=/boot/vmlinuz-$(uname –r)
```

## 36. 创建一个自定义调整配置文件，定义第一个驱动器的预读取为 4096，第二个驱动器的预读取为 1024 - 此配置文件还应在发生 OOM 事件时使系统崩溃

参考以下命令：

```
dnf –y install tuned
mkdir –p /etc/tuned/myprofile
```

编辑`/etc/tuned/myprofile/tuned.conf`文件，添加以下内容：

```
[main]
summary=My custom tuned profile
[sysctl]
vm.panic_on_oom=1
[main_disk]
type=disk
devices=sda
readahead=>4096
[data_disk]
type=disk
devices=!sda
readahead=>1024
```

## 37. 禁用并删除已安装的 httpd 软件包，并使用 registry.redhat.io/rhel8/httpd-24 镜像设置 httpd 服务器

请参考以下内容如何完成此操作：

```
rpm –e httpd
dnf –y install podman
podman login registry.redhat.io # provide RHN credentials
podman pull registry.redhat.io/rhel8/httpd-24 
podman run -d --name httpd –p 80:8080 -v /var/www:/var/www:Z registry.redhat.io/rhel8/httpd-24
```
