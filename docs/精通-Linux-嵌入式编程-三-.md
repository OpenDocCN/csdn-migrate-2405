# 精通 Linux 嵌入式编程（三）

> 原文：[`zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814`](https://zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：创建存储策略

嵌入式设备的大容量存储选项对系统的其余部分在稳健性、速度和现场更新方法方面产生了巨大影响。

大多数设备以某种形式使用闪存存储器。随着存储容量从几十兆字节增加到几十吉字节，闪存存储器在过去几年中变得更加廉价。

在本章中，我将详细介绍闪存存储器背后的技术，以及不同的存储器组织如何影响必须管理它的低级驱动程序软件，包括 Linux 内存技术设备层 MTD。

对于每种闪存技术，都有不同的文件系统选择。我将描述在嵌入式设备上最常见的文件系统，并在一节中总结每种闪存类型的选择。

最后几节考虑了利用闪存存储器的最佳技术，研究了如何在现场更新设备，并将所有内容整合成一种连贯的存储策略。

# 存储选项

嵌入式设备需要存储器，它需要耗电少、物理上紧凑、稳固，并且在长达数十年的寿命内可靠。在几乎所有情况下，这意味着固态存储器，它在许多年前就已经引入了只读存储器（ROM），但在过去 20 年中一直是各种闪存存储器。在这段时间里，闪存存储器经历了几代，从 NOR 到 NAND 再到 eMMC 等托管闪存。

NOR 闪存价格昂贵，但可靠，并且可以映射到 CPU 地址空间，这使得可以直接从闪存中执行代码。NOR 闪存芯片容量较低，从几兆字节到大约一吉字节不等。

NAND 闪存存储器比 NOR 便宜得多，容量更大，范围从几十兆字节到几十吉字节。然而，它需要大量的硬件和软件支持，才能将其转化为有用的存储介质。

托管闪存存储器由一个或多个 NAND 闪存芯片与控制器组成，控制器处理闪存存储器的复杂性，并提供类似硬盘的硬件接口。吸引人的地方在于它可以减少驱动程序软件的复杂性，并使系统设计人员免受闪存技术的频繁变化的影响。SD 卡、eMMC 芯片和 USB 闪存驱动器属于这一类。几乎所有当前的智能手机和平板电脑都使用 eMMC 存储，这一趋势可能会在其他类别的嵌入式设备中继续发展。

在嵌入式系统中很少使用硬盘驱动器。一个例外是机顶盒和智能电视中的数字视频录制，这需要大量的存储空间和快速的写入时间。

在所有情况下，稳健性是最重要的：您希望设备在断电和意外重置的情况下能够引导并达到功能状态。您应该选择在这种情况下表现良好的文件系统。

## NOR 闪存

NOR 闪存芯片中的存储单元被排列成擦除块，例如 128 KiB。擦除块会将所有位设置为 1。它可以一次编程一个字（8、16 或 32 位，取决于数据总线宽度）。每次擦除循环都会轻微损坏存储单元，经过多次循环后，擦除块变得不可靠，无法再使用。芯片的最大擦除循环次数应该在数据表中给出，但通常在 10 万到 100 万次之间。

数据可以逐字读取。芯片通常被映射到 CPU 地址空间中，这意味着可以直接从 NOR 闪存中执行代码。这使得它成为放置引导加载程序代码的便利位置，因为它不需要除了硬连地址映射之外的任何初始化。支持 NOR 闪存的 SoC 具有配置，可以给出默认的内存映射，使其包含 CPU 的复位向量。

内核，甚至根文件系统，也可以位于闪存中，避免将它们复制到 RAM 中，从而创建具有小内存占用的设备。这种技术称为**原地执行**，或**XIP**。这是非常专业的，我在这里不会进一步讨论。本章末尾有一些参考资料。

NOR 闪存芯片有一个称为**通用闪存接口**或**CFI**的标准寄存器级接口，所有现代芯片都支持。

## NAND 闪存

NAND 闪存比 NOR 闪存便宜得多，并且容量更大。第一代 NAND 芯片以每个存储单元存储一个位，即现在所称的**SLC**或**单级单元**组织。后来的几代转向每个存储单元存储两位，即**多级单元**（**MLC**）芯片，现在转向每个存储单元存储三位，即**三级单元**（**TLC**）芯片。随着每个存储单元的位数增加，存储的可靠性降低，需要更复杂的控制器硬件和软件来进行补偿。

与 NOR 闪存一样，NAND 闪存被组织成擦除块，大小从 16 KiB 到 512 KiB 不等，再次擦除块会将所有位设置为 1。然而，块变得不可靠之前的擦除循环次数较低，对于 TLC 芯片通常只有 1K 次，而对于 SLC 则高达 100K 次。NAND 闪存只能以页面的形式读取和写入，通常为 2 或 4 KiB。由于它们无法逐字节访问，因此无法映射到地址空间，因此代码和数据必须在访问之前复制到 RAM 中。

与芯片之间的数据传输容易发生位翻转，可以使用纠错码进行检测和纠正。SLC 芯片通常使用简单的海明码，可以在软件中高效实现，并可以纠正页面读取中的单个位错误。MLC 和 TLC 芯片需要更复杂的编码，例如**BCH**（**Bose-Chaudhuri-Hocquenghem**），可以纠正每页高达 8 位的错误。这些需要硬件支持。

纠错码必须存储在某个地方，因此每页都有一个额外的内存区域，称为**带外**（**OOB**）区域，也称为备用区域。MLC 设计通常每 32 个字节的主存储空间有 1 个字节的 OOB，因此对于 2 KiB 页面设备，每页的 OOB 为 64 字节，对于 4 KiB 页面，则为 128 字节。MLC 和 TLC 芯片具有比例更大的 OOB 区域，以容纳更复杂的纠错码。下图显示了具有 128 KiB 擦除块和 2 KiB 页面的芯片的组织结构：

![NAND 闪存](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_01.jpg)

在生产过程中，制造商测试所有块，并标记任何失败的块，通过在每个块中的每个页面的 OOB 区域设置标志来实现。发现全新芯片以这种方式标记为坏的块高达 2%并不罕见。此外，在擦除循环限制达到之前，类似比例的块出现擦除错误是在规范内的。NAND 闪存驱动程序应该检测到这一点，并将其标记为坏块。

在 OOB 区域为坏块标志和 ECC 字节留出空间后，仍然有一些字节剩下。一些闪存文件系统利用这些空闲字节来存储文件系统元数据。因此，许多人对 OOB 区域的布局感兴趣：SoC ROM 引导代码、引导加载程序、内核 MTD 驱动程序、文件系统代码以及创建文件系统映像的工具。标准化程度不高，因此很容易出现这样的情况：引导加载程序使用无法被内核 MTD 驱动程序读取的 OOB 格式写入数据。您需要确保它们都达成一致。

访问 NAND 闪存芯片需要一个 NAND 闪存控制器，通常是 SoC 的一部分。您需要引导加载程序和内核中相应的驱动程序。NAND 闪存控制器处理与芯片的硬件接口，传输数据到和从页面，并可能包括用于纠错的硬件。

NAND 闪存芯片有一个称为**开放 NAND 闪存接口**（**ONFi**）的标准寄存器级接口，大多数现代芯片都遵循这一标准。请参阅[`www.onfi.org`](http://www.onfi.org)。

## 管理闪存

在操作系统中支持闪存存储的负担，尤其是 NAND 存储器，如果有一个明确定义的硬件接口和一个隐藏存储器复杂性的标准闪存控制器，那么负担就会减轻。这就是管理闪存存储器，它变得越来越普遍。实质上，它意味着将一个或多个闪存芯片与一个微控制器结合起来，提供一个与传统文件系统兼容的小扇区大小的理想存储设备。嵌入式系统中最重要的管理闪存类型是**安全数字**（**SD**）卡和嵌入式变体称为**eMMC**。

### 多媒体卡和安全数字卡

**多媒体卡**（**MMC**）于 1997 年由 SanDisk 和西门子推出，作为一种使用闪存存储的封装形式。不久之后，1999 年，SanDisk、松下和东芝创建了基于 MMC 的 SD 卡，增加了加密和数字版权管理（即安全部分）。两者都是为数码相机、音乐播放器和类似设备而设计的消费类电子产品。目前，SD 卡是消费类和嵌入式电子产品中主要的管理闪存形式，尽管加密功能很少被使用。SD 规范的更新版本允许更小的封装（mini SD 和 micro SD，通常写作 uSD）和更大的容量：高容量 SDHC，最高达 32GB，扩展容量 SDXC，最高达 2TB。

MMC 和 SD 卡的硬件接口非常相似，可以在全尺寸 SD 卡槽中使用全尺寸 MMC（但反之则不行）。早期版本使用 1 位**串行外围接口**（**SPI**）；更近期的卡使用 4 位接口。有一个用于读写 512 字节扇区内存的命令集。在封装内部有一个微控制器和一个或多个 NAND 闪存芯片，如下图所示：

![多媒体卡和安全数字卡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_07.jpg)

微控制器实现命令集并管理闪存，执行闪存转换层的功能，如本章后面所述。它们预先格式化为 FAT 文件系统：SDSC 卡上为 FAT16，SDHC 上为 FAT32，SDXC 上为 exFAT。NAND 闪存芯片的质量和微控制器上的软件在卡片之间差异很大。有人质疑它们是否足够可靠，尤其是对于容易发生文件损坏的 FAT 文件系统。请记住，MMC 和 SD 卡的主要用途是相机、平板电脑和手机上的可移动存储。

### eMMC

**eMMC**或**嵌入式 MMC**只是 MMC 存储器的封装，可以焊接到主板上，使用 4 位或 8 位接口进行数据传输。但是，它们旨在用作操作系统的存储，因此组件能够执行该任务。芯片通常没有预先格式化任何文件系统。

### 其他类型的管理闪存

最早的管理闪存技术之一是**CompactFlash**（**CF**），使用**个人计算机存储卡国际协会**（**PCMCIA**）接口的子集。CF 通过并行 ATA 接口公开存储器，并在操作系统中显示为标准硬盘。它们在基于 x86 的单板计算机和专业视频和摄像设备中很常见。

我们每天使用的另一种格式是 USB 闪存驱动器。在这种情况下，通过 USB 接口访问内存，并且控制器实现 USB 大容量存储规范以及闪存转换层和与闪存芯片的接口。USB 大容量存储协议又基于 SCSI 磁盘命令集。与 MMC 和 SD 卡一样，它们通常预先格式化为 FAT 文件系统。它们在嵌入式系统中的主要用途是与个人电脑交换数据。

### 注意

对于受管理的闪存存储的选项列表的最新添加是**通用闪存存储**（**UFS**）。与 eMMC 一样，它被封装在安装在主板上的芯片中。它具有高速串行接口，可以实现比 eMMC 更高的数据速率。它支持 SCSI 磁盘命令集。

# 从引导加载程序访问闪存

在第三章中，*关于引导加载程序的一切*，我提到了引导加载程序需要从各种闪存设备加载内核二进制文件和其他映像，并且能够执行系统维护任务，如擦除和重新编程闪存。因此，引导加载程序必须具有支持您拥有的内存类型的读取、擦除和写入操作的驱动程序和基础设施，无论是 NOR、NAND 还是受管理的内存。我将在以下示例中使用 U-Boot；其他引导加载程序遵循类似的模式。

## U-Boot 和 NOR 闪存

U-Boot 在`drivers/mtd`中具有 NOR CFI 芯片的驱动程序，并具有`erase`命令来擦除内存和`cp.b`命令来逐字节复制数据，编程闪存。假设您有从 0x40000000 到 0x48000000 映射的 NOR 闪存，其中从 0x40040000 开始的 4MiB 是内核映像，那么您将使用这些 U-Boot 命令将新内核加载到闪存中：

```
U-Boot# tftpboot 100000 uImage
U-Boot# erase 40040000 403fffff
U-Boot# cp.b 100000 40040000 $(filesize)
```

前面示例中的变量`filesize`是由`tftpboot`命令设置为刚刚下载的文件的大小。

## U-Boot 和 NAND 闪存

对于 NAND 闪存，您需要一个针对 SoC 上的 NAND 闪存控制器的驱动程序，您可以在`drivers/mtd/nand`中找到。您可以使用`nand`命令来使用子命令`erase`、`write`和`read`来管理内存。此示例显示内核映像被加载到 RAM 的 0x82000000 处，然后从偏移 0x280000 开始放入闪存：

```
U-Boot# tftpboot 82000000 uImage
U-Boot# nand erase 280000 400000
U-Boot# nand write 82000000 280000 $(filesize)
```

U-Boot 还可以读取存储在 JFFS2、YAFFS2 和 UBIFS 文件系统中的文件。

## U-Boot 和 MMC、SD 和 eMMC

U-Boot 在`drivers/mmc`中具有几个 MMC 控制器的驱动程序。您可以在用户界面级别使用`mmc read`和`mmc write`来访问原始数据，这允许您处理原始内核和文件系统映像。

U-Boot 还可以从 MMC 存储器上的 FAT32 和 ext4 文件系统中读取文件。

# 从 Linux 访问闪存内存

原始 NOR 和 NAND 闪存由内存技术设备子系统（MTD）处理，该子系统提供了读取、擦除和写入闪存块的基本接口。对于 NAND 闪存，有处理 OOB 区域和识别坏块的功能。

对于受管理的闪存，您需要驱动程序来处理特定的硬件接口。MMC/SD 卡和 eMMC 使用 mmcblk 驱动程序；CompactFlash 和硬盘使用 SCSI 磁盘驱动程序 sd。USB 闪存驱动器使用 usb_storage 驱动程序以及 sd 驱动程序。

## 内存技术设备

**内存技术** **设备**（**MTD**）子系统由 David Woodhouse 于 1999 年创建，并在随后的几年中得到了广泛的发展。在本节中，我将集中讨论它处理的两种主要技术，NOR 和 NAND 闪存。

MTD 由三层组成：一组核心功能、一组各种类型芯片的驱动程序以及将闪存内存呈现为字符设备或块设备的用户级驱动程序，如下图所示：

![内存技术设备](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_02.jpg)

芯片驱动程序位于最低级别，并与闪存芯片进行接口。对于 NOR 闪存芯片，只需要少量驱动程序，足以覆盖 CFI 标准和变体，以及一些现在大多已经过时的不符合标准的芯片。对于 NAND 闪存，您将需要一个用于所使用的 NAND 闪存控制器的驱动程序；这通常作为板支持包的一部分提供。在当前主线内核中的`drivers/mtd/nand`目录中有大约 40 个这样的驱动程序。

### MTD 分区

在大多数情况下，您会希望将闪存内存分成多个区域，例如为引导加载程序、内核映像或根文件系统提供空间。在 MTD 中，有几种指定分区大小和位置的方法，主要包括：

+   通过内核命令行使用`CONFIG_MTD_CMDLINE_PARTS`

+   通过设备树使用`CONFIG_MTD_OF_PARTS`

+   使用平台映射驱动程序

在第一种选项的情况下，要使用的内核命令行选项是`mtdparts`，在 Linux 源代码中在`drivers/mtd/cmdlinepart.c`中定义如下：

```
mtdparts=<mtddef>[;<mtddef]
<mtddef>  := <mtd-id>:<partdef>[,<partdef>]
<mtd-id>  := unique name for the chip
<partdef> := <size>[@<offset>][<name>][ro][lk]
<size>    := size of partition OR "-" to denote all remaining
             space
<offset>  := offset to the start of the partition; leave blank
             to follow the previous partition without any gap
<name>    := '(' NAME ')'
```

也许一个例子会有所帮助。假设您有一个 128MB 的闪存芯片，要分成五个分区。一个典型的命令行将是：

```
mtdparts=:512k(SPL)ro,780k(U-Boot)ro,128k(U-BootEnv),
4m(Kernel),-(Filesystem)
```

冒号`:`之前的第一个元素是`mtd-id`，它通过编号或者由板支持包分配的名称来标识闪存芯片。如果只有一个芯片，可以留空。如果有多个芯片，每个芯片的信息用分号`；`分隔。然后，对于每个芯片，有一个逗号分隔的分区列表，每个分区都有以字节、千字节`k`或兆字节`m`为单位的大小和括号中的名称。`ro`后缀使得分区对 MTD 是只读的，通常用于防止意外覆盖引导加载程序。对于芯片的最后一个分区，大小可以用破折号`-`替换，表示它应该占用所有剩余的空间。

您可以通过读取`/proc/mtd`来查看运行时的配置摘要：

```
# cat /proc/mtd
dev:    size   erasesize   name
mtd0: 00080000 00020000  "SPL"
mtd1: 000C3000 00020000  "U-Boot"
mtd2: 00020000 00020000  "U-BootEnv"
mtd3: 00400000 00020000  "Kernel"
mtd4: 07A9D000 00020000  "Filesystem"
```

在`/sys/class/mtd`中有关每个分区的更详细信息，包括擦除块大小和页面大小，并且可以使用`mtdinfo`进行很好地总结：

```
# mtdinfo /dev/mtd0
mtd0
Name:                           SPL
Type:                           nand
Eraseblock size:                131072 bytes, 128.0 KiB
Amount of eraseblocks:          4 (524288 bytes, 512.0 KiB)
Minimum input/output unit size: 2048 bytes
Sub-page size:                  512 bytes
OOB size:                       64 bytes
Character device major/minor:   90:0
Bad blocks are allowed:         true
Device is writable:             false
```

等效的分区信息可以在设备树的一部分中编写，如下所示：

```
nand@0,0 {
  #address-cells = <1>;
  #size-cells = <1>;
  partition@0 {
    label = "SPL";
    reg = <0 0x80000>;
  };
  partition@80000 {
    label = "U-Boot";
    reg = <0x80000 0xc3000>;
  };
  partition@143000 {
    label = "U-BootEnv";
    reg = <0x143000 0x20000>;
  };
  partition@163000 {
    label = "Kernel";
    reg = <0x163000 0x400000>;
  };
  partition@563000 {
    label = "Filesystem";
    reg = <0x563000 0x7a9d000>;
  };
};
```

第三种选择是将分区信息编码为`mtd_partition`结构中的平台数据，如从`arch/arm/mach-omap2/board-omap3beagle.c`中取出的此示例所示（NAND_BLOCK_SIZE 在其他地方定义为 128K）：

```
static struct mtd_partition omap3beagle_nand_partitions[] = {
  {
    .name           = "X-Loader",
    .offset         = 0,
    .size           = 4 * NAND_BLOCK_SIZE,
    .mask_flags     = MTD_WRITEABLE,    /* force read-only */
  },
  {
    .name           = "U-Boot",
    .offset         = 0x80000;
    .size           = 15 * NAND_BLOCK_SIZE,
    .mask_flags     = MTD_WRITEABLE,    /* force read-only */
  },
  {
    .name           = "U-Boot Env",
    .offset         = 0x260000;
    .size           = 1 * NAND_BLOCK_SIZE,
  },
  {
    .name           = "Kernel",
    .offset         = 0x280000;
    .size           = 32 * NAND_BLOCK_SIZE,
  },
  {
    .name           = "File System",
    .offset         = 0x680000;
    .size           = MTDPART_SIZ_FULL,
  },
};
```

### MTD 设备驱动程序

MTD 子系统的上层是一对设备驱动程序：

+   一个字符设备，主编号为 90。每个 MTD 分区号有两个设备节点，`N: /dev/mtdN`（*次编号=N*2*）和`/dev/mtdNro`（*次编号=(N*2 + 1)*）。后者只是前者的只读版本。

+   一个块设备，主编号为 31，次编号为 N。设备节点的形式为`/dev/mtdblockN`。

### MTD 字符设备，mtd

字符设备是最重要的：它们允许您将底层闪存内存作为字节数组进行访问，以便您可以读取和写入（编程）闪存。它还实现了一些`ioctl`函数，允许您擦除块并管理 NAND 芯片上的 OOB 区域。以下列表在`include/uapi/mtd/mtd-abi.h`中：

| IOCTL | 描述 |
| --- | --- |
| `MEMGETINFO` | 获取基本的 MTD 特性信息 |
| `MEMERASE` | 擦除 MTD 分区中的块 |
| `MEMWRITEOOB` | 写出页面的带外数据 |
| `MEMREADOOB` | 读取页面的带外数据 |
| `MEMLOCK` | 锁定芯片（如果支持） |
| `MEMUNLOCK` | 解锁芯片（如果支持） |
| `MEMGETREGIONCOUNT` | 获取擦除区域的数量：如果分区中有不同大小的擦除块，则为非零，这在 NOR 闪存中很常见，在 NAND 中很少见 |
| `MEMGETREGIONINFO` | 如果 `MEMGETREGIONCOUNT` 非零，可以用来获取每个区域的偏移量、大小和块数 |
| `MEMGETOOBSEL` | 已弃用 |
| `MEMGETBADBLOCK` | 获取坏块标志 |
| `MEMSETBADBLOCK` | 设置坏块标志 |
| `OTPSELECT` | 如果芯片支持，设置 OTP（一次可编程）模式 |
| `OTPGETREGIONCOUNT` | 获取 OTP 区域的数量 |
| `OTPGETREGIONINFO` | 获取有关 OTP 区域的信息 |
| `ECCGETLAYOUT` | 已弃用 |

有一组称为 `mtd-utils` 的实用程序，用于操作闪存内存，利用了这些 `ioctl` 函数。源代码可从 [`git.infradead.org/mtd-utils.git`](http://git.infradead.org/mtd-utils.git) 获取，并作为 Yocto 项目和 Buildroot 中的软件包提供。以下是基本工具。该软件包还包含了稍后将介绍的 JFFS2 和 UBI/UBIFS 文件系统的实用程序。对于这些工具中的每一个，MTD 字符设备是其中的一个参数：

+   **flash_erase**：擦除一系列块。

+   **flash_lock**：锁定一系列块。

+   **flash_unlock**：解锁一系列块。

+   **nanddump**：从 NAND 闪存中转储内存，可选择包括 OOB 区域。跳过坏块。

+   **nandtest**：用于 NAND 闪存的测试和诊断。

+   **nandwrite**：从数据文件向 NAND 闪存写入（编程），跳过坏块。

### 提示

在写入新内容之前，您必须始终擦除闪存内存：`flash_erase` 就是执行此操作的命令。

要编程 NOR 闪存，只需使用 `cp` 命令或类似命令将字节复制到 MTD 设备节点。

不幸的是，这在 NAND 存储器上不起作用，因为在第一个坏块处复制将失败。相反，应该使用 `nandwrite`，它会跳过任何坏块。要读取 NAND 存储器，应该使用 `nanddump`，它也会跳过坏块。

### MTD 块设备，mtdblock

mtdblock 驱动程序很少使用。它的目的是将闪存内存呈现为块设备，您可以使用它来格式化并挂载为文件系统。但是，它有严重的限制，因为它不处理 NAND 闪存中的坏块，不进行磨损平衡，也不处理文件系统块和闪存擦除块之间的大小不匹配。换句话说，它没有闪存转换层，这对于可靠的文件存储至关重要。 mtdblock 设备有用的唯一情况是在可靠的闪存内存（如 NOR）上挂载只读文件系统，例如 Squashfs。

### 提示

如果要在 NAND 闪存上使用只读文件系统，应该使用 UBI 驱动程序，如本章后面所述。

### 将内核 oops 记录到 MTD

内核错误，或者 oopsies，通常通过 `klogd` 和 `syslogd` 守护进程记录到循环内存缓冲区或文件中。重启后，如果是环形缓冲区，日志将会丢失，即使是文件，系统崩溃前可能也没有正确写入。

### 提示

更可靠的方法是将 oops 和内核恐慌写入 MTD 分区作为循环日志缓冲区。您可以通过 `CONFIG_MTD_OOPS` 启用它，并在内核命令行中添加 `console=ttyMTDN`，其中 `N` 是要将消息写入的 MTD 设备编号。

### 模拟 NAND 存储器

NAND 模拟器使用系统 RAM 模拟 NAND 芯片。主要用途是测试必须了解 NAND 的代码，而无法访问物理 NAND 存储器。特别是，模拟坏块、位翻转和其他错误的能力允许您测试难以使用真实闪存内存进行练习的代码路径。有关更多信息，最好的地方是查看代码本身，其中详细描述了您可以配置驱动程序的方式。代码位于 `drivers/mtd/nand/nandsim.c`。使用内核配置 `CONFIG_MTD_NAND_NANDSIM` 启用它。

## MMC 块驱动程序

MMC/SD 卡和 eMMC 芯片使用 mmcblk 块驱动程序进行访问。您需要一个与您使用的 MMC 适配器匹配的主机控制器，这是板支持包的一部分。驱动程序位于 Linux 源代码中的`drivers/mmc/host`中。

MMC 存储使用分区表进行分区，方式与硬盘完全相同，使用 fdisk 或类似的实用程序。

# 闪存内存的文件系统

在有效利用闪存内存进行大容量存储时存在几个挑战：擦除块和磁盘扇区大小不匹配，每个擦除块的擦除周期有限，以及 NAND 芯片上需要坏块处理。这些差异通过**全局闪存转换层**或**FTL**来解决。

## 闪存转换层

闪存转换层具有以下特点：

+   **子分配**：文件系统最适合使用小的分配单元，传统上是 512 字节扇区。这比 128 KiB 或更大的闪存擦除块要小得多。因此，必须将擦除块细分为更小的单元，以避免浪费大量空间。

+   **垃圾收集**：子分配的一个结果是，文件系统在使用一段时间后，擦除块将包含好数据和陈旧数据的混合。由于我们只能释放整个擦除块，因此重新获取空闲空间的唯一方法是将好数据合并到一个位置并将现在空的擦除块返回到空闲列表中：这就是垃圾收集，通常作为后台线程实现。

+   **磨损平衡**：每个块的擦除周期都有限制。为了最大限度地延长芯片的寿命，重要的是移动数据，使每个块大致相同次数地擦除。

+   **坏块处理**：在 NAND 闪存芯片上，您必须避免使用任何标记为坏的块，并且如果无法擦除，则将好块标记为坏。

+   **稳健性**：嵌入式设备可能会突然断电或重置，因此任何文件系统都应该能够在没有损坏的情况下应对，通常是通过包含事务日志或日志来实现。

部署闪存转换层有几种方法：

+   **在文件系统中**：与 JFFS2、YAFFS2 和 UBIFS 一样

+   **在块设备驱动程序中**：UBI 驱动程序实现了闪存转换层的一些方面，UBIFS 依赖于它

+   **在设备控制器中**：与托管闪存设备一样

当闪存转换层位于文件系统或块驱动程序中时，代码是内核的一部分，因此是开源的，这意味着我们可以看到它的工作方式，并且我们可以期望它会随着时间的推移而得到改进。另一方面，FTL 位于托管闪存设备中；它被隐藏起来，我们无法验证它是否按照我们的期望工作。不仅如此，将 FTL 放入磁盘控制器意味着它错过了文件系统层保存的信息，比如哪些扇区属于已删除且不再包含有用数据的文件。后一个问题通过在文件系统和设备之间添加传递此信息的命令来解决，我将在后面的`TRIM`命令部分中描述，但代码可见性的问题仍然存在。如果您使用托管闪存，您只需选择一个您可以信任的制造商。

# NOR 和 NAND 闪存内的文件系统

要将原始闪存芯片用于大容量存储，您必须使用了解底层技术特性的文件系统。有三种这样的文件系统：

+   **日志闪存文件系统 2，JFFS2**：这是 Linux 的第一个闪存文件系统，至今仍在使用。它适用于 NOR 和 NAND 存储器，但在挂载时速度慢。

+   **另一种闪存文件系统 2，YAFFS2**：这类似于 JFFS2，但专门用于 NAND 闪存。它被 Google 采用为 Android 设备上首选的原始闪存文件系统。

+   **未排序块映像文件系统，UBIFS**: 这是最新的适用于 NOR 和 NAND 存储器的闪存感知文件系统，它与 UBI 块驱动程序一起使用。它通常比 JFFS2 或 YAFFS2 提供更好的性能，因此应该是新设计的首选解决方案。

所有这些都使用 MTD 作为闪存内存的通用接口。

## JFFS2

日志闪存文件系统始于 1999 年 Axis 2100 网络摄像机的软件。多年来，它是 Linux 上唯一的闪存文件系统，并已部署在成千上万种不同类型的设备上。今天，它并不是最佳选择，但我会首先介绍它，因为它展示了进化路径的开始。

JFFS2 是一种使用 MTD 访问闪存内存的日志结构文件系统。在日志结构文件系统中，更改被顺序写入闪存内存作为节点。一个节点可能包含对目录的更改，例如创建和删除的文件名，或者它可能包含对文件数据的更改。一段时间后，一个节点可能被后续节点中包含的信息取代，并成为过时的节点。

擦除块分为三种类型：

+   **空闲**: 它根本不包含任何节点

+   **干净**: 它只包含有效节点

+   **脏**: 它至少包含一个过时的节点

在任何时候，都有一个正在接收更新的块，称为打开块。如果断电或系统重置，唯一可能丢失的数据就是对打开块的最后一次写入。此外，节点在写入时会被压缩，增加了闪存芯片的有效存储容量，这对于使用昂贵的 NOR 闪存存储器非常重要。

当空闲块的数量低于阈值时，将启动一个垃圾收集器内核线程，扫描脏块并将有效节点复制到打开块，然后释放脏块。

同时，垃圾收集器提供了一种粗糙的磨损平衡，因为它将有效数据从一个块循环到另一个块。选择打开块的方式意味着只要它包含不时更改的数据，每个块被擦除的次数大致相同。有时会选择一个干净的块进行垃圾收集，以确保包含很少写入的静态数据的块也得到磨损平衡。

JFFS2 文件系统具有写穿缓存，这意味着写入的数据会同步写入闪存内存，就好像已经使用`-o sync`选项挂载一样。虽然提高了可靠性，但会增加写入数据的时间。小写入还存在另一个问题：如果写入的长度与节点头部的大小（40 字节）相当，开销就会很高。一个众所周知的特例是由 syslogd 产生的日志文件。

### 摘要节点

JFFS2 有一个主要的缺点：由于没有芯片上的索引，目录结构必须在挂载时通过从头到尾读取日志来推导。在扫描结束时，您可以得到有效节点的目录结构的完整图像，但所花费的时间与分区的大小成正比。挂载时间通常为每兆字节一秒左右，导致总挂载时间为几十秒或几百秒。

为了减少挂载时的扫描时间，摘要节点在 Linux 2.6.15 中成为一个选项。摘要节点是在关闭之前的打开擦除块的末尾写入的。摘要节点包含挂载时扫描所需的所有信息，从而减少了扫描期间需要处理的数据量。摘要节点可以将挂载时间缩短两到五倍，但会增加大约 5%的存储空间开销。它们可以通过内核配置`CONFIG_JFFS2_SUMMARY`启用。

### 干净标记

所有位设置为 1 的擦除块与已写入 1 的块无法区分，但后者尚未刷新其存储单元，直到擦除后才能再次编程。JFFS2 使用称为清洁标记的机制来区分这两种情况。成功擦除块后，将写入一个清洁标记，可以写入到块的开头或块的第一页的 OOB 区域。如果存在清洁标记，则必须是一个干净的块。

### 创建 JFFS2 文件系统

在运行时创建空的 JFFS2 文件系统就像擦除带有清洁标记的 MTD 分区然后挂载它一样简单。因为空白的 JFFS2 文件系统完全由空闲块组成，所以没有格式化步骤。例如，要格式化 MTD 分区 6，您可以在设备上输入以下命令：

```
# flash_erase -j /dev/mtd6 0 0
# mount -t jffs2 mtd6 /mnt
```

`-j`选项`flash_erase`添加清洁标记，并使用类型`jffs2`挂载分区作为空文件系统。请注意，要挂载的设备是给定为`mtd6`，而不是`/dev/mtd6`。或者，您可以提供块设备节点`/dev/mtdblock6`。这只是 JFFS2 的一个特殊之处。一旦挂载，您可以像任何文件系统一样处理它，并且在下次启动和挂载时，所有文件仍将存在。

您可以直接从开发系统的暂存区使用`mkfs.jffs2`以 JFFS2 格式写出文件系统图像，并使用`sumtool`添加摘要节点。这两者都是`mtd-utils`软件包的一部分。

例如，要为擦除块大小为 128 KB（0x20000）且具有摘要节点的 NAND 闪存设备创建`rootfs`中的文件的图像，您将使用以下两个命令：

```
$ mkfs.jffs2 -n -e 0x20000 -p -d ~/rootfs -o ~/rootfs.jffs2
$ sumtool -n -e 0x20000 -p -i ~/rootfs.jffs2 -o ~/rootfs-sum.jffs2

```

`-p`选项在图像文件末尾添加填充，使其成为整数倍的擦除块。`-n`选项抑制在图像中创建清洁标记，这对于 NAND 设备是正常的，因为清洁标记在 OOB 区域中。对于 NOR 设备，您可以省略`-n`选项。您可以使用`mkfs.jffs2`的设备表通过添加`-D`[设备表]来设置文件的权限和所有权。当然，Buildroot 和 Yocto Project 将为您完成所有这些工作。

您可以从引导加载程序将图像编程到闪存中。例如，如果您已将文件系统图像加载到 RAM 的地址 0x82000000，并且希望将其加载到从闪存芯片开始的 0x163000 字节处的闪存分区，并且长度为 0x7a9d000 字节，则 U-Boot 命令将是：

```
nand erase clean 163000 7a9d000
nand write 82000000 163000 7a9d000
```

您可以使用 mtd 驱动程序从 Linux 执行相同的操作：

```
# flash_erase -j /dev/mtd6 0 0
# nandwrite /dev/mtd6 rootfs-sum.jffs2
```

要使用 JFFS2 根文件系统进行引导，您需要在内核命令行上传递`mtdblock`设备用于分区和根`fstype`，因为 JFFS2 无法自动检测：

```
root=/dev/mtdblock6 rootfstype=jffs2
```

## YAFFS2

YAFFS 文件系统是由 Charles Manning 于 2001 年开始编写的，专门用于处理当时 JFFS2 无法处理的 NAND 闪存芯片。后来的更改以处理更大（2 KiB）的页面大小导致了 YAFFS2。YAFFS 的网站是[`www.yaffs.net`](http://www.yaffs.net)。

YAFFS 也是一个遵循与 JFFS2 相同设计原则的日志结构文件系统。不同的设计决策意味着它具有更快的挂载时间扫描，更简单和更快的垃圾收集，并且没有压缩，这加快了读写速度，但以存储的效率较低为代价。

YAFFS 不仅限于 Linux；它已被移植到各种操作系统。它具有双重许可证：GPLv2 与 Linux 兼容，以及其他操作系统的商业许可证。不幸的是，YAFFS 代码从未合并到主线 Linux 中，因此您将不得不像下面的代码所示一样对内核进行补丁。

要获取 YAFFS2 并对内核进行补丁，您可以：

```
$ git clone git://www.aleph1.co.uk/yaffs2
$ cd yaffs2
$ ./patch-ker.sh c m <path to your link source>

```

然后，使用`CONFIG_YAFFS_YAFFS2`配置内核。

### 创建 YAFFS2 文件系统

与 JFFS2 一样，要在运行时创建 YAFFS2 文件系统，您只需要擦除分区并挂载它，但请注意，在这种情况下，不要启用清除标记：

```
# flash_erase /dev/mtd/mtd6 0 0
# mount -t yaffs2 /dev/mtdblock6 /mnt
```

要创建文件系统映像，最简单的方法是使用[`code.google.com/p/yaffs2utils`](https://code.google.com/p/yaffs2utils)中的`mkyaffs2`工具，使用以下命令：

```
$ mkyaffs2 -c 2048 -s 64 rootfs rootfs.yaffs2

```

这里`-c`是页面大小，`-s`是 OOB 大小。有一个名为`mkyaffs2image`的工具，它是 YAFFS 代码的一部分，但它有一些缺点。首先，页面和 OOB 大小在源代码中是硬编码的：如果内存与默认值 2,048 和 64 不匹配，则必须编辑并重新编译。其次，OOB 布局与 MTD 不兼容，MTD 使用前两个字节作为坏块标记，而`mkyaffs2image`使用这些字节来存储部分 YAFFS 元数据。

在 Linux shell 提示符下将图像复制到 MTD 分区，请按照以下步骤操作：

```
# flash_erase /dev/mtd6 0 0
# nandwrite -a /dev/mtd6 rootfs.yaffs2
```

要使用 YAFFS2 根文件系统启动，请将以下内容添加到内核命令行：

```
root=/dev/mtdblock6 rootfstype=yaffs2

```

## UBI 和 UBIFS

**未排序的块图像**（**UBI**）驱动程序是闪存的卷管理器，负责处理坏块处理和磨损平衡。它是由 Artem Bityutskiy 实现的，并首次出现在 Linux 2.6.22 中。与此同时，诺基亚的工程师们正在开发一种可以利用 UBI 功能的文件系统，他们称之为 UBIFS；它出现在 Linux 2.6.27 中。以这种方式拆分闪存转换层使代码更加模块化，并且还允许其他文件系统利用 UBI 驱动程序，我们稍后将看到。

### UBI

UBI 通过将**物理擦除块**（**PEB**）映射到**逻辑擦除块**（**LEB**）来为闪存芯片提供理想化的可靠视图。坏块不会映射到 LEB，因此不会被使用。如果块无法擦除，则将其标记为坏块并从映射中删除。UBI 在 LEB 的标头中保留了每个 PEB 被擦除的次数，并更改映射以确保每个 PEB 被擦除相同次数。

UBI 通过 MTD 层访问闪存。作为额外功能，它可以将 MTD 分区划分为多个 UBI 卷，从而以以下方式改善磨损平衡。想象一下，您有两个文件系统，一个包含相当静态的数据，例如根文件系统，另一个包含不断变化的数据。如果它们存储在单独的 MTD 分区中，磨损平衡只对第二个产生影响，而如果您选择将它们存储在单个 MTD 分区中的两个 UBI 卷中，磨损平衡将在存储的两个区域上进行，并且闪存的寿命将增加。以下图表说明了这种情况：

![UBI](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_03.jpg)

通过这种方式，UBI 满足了闪存转换层的两个要求：磨损平衡和坏块处理。

要为 UBI 准备 MTD 分区，不要像 JFFS2 和 YAFFS2 一样使用`flash_erase`，而是使用`ubiformat`实用程序，它保留存储在 PED 标头中的擦除计数。 `ubiformat`需要知道 IO 的最小单位，对于大多数 NAND 闪存芯片来说，这是页面大小，但是一些芯片允许以半页或四分之一页的子页进行读写。有关详细信息，请参阅芯片数据表，如果有疑问，请使用页面大小。此示例使用 2,048 字节的页面大小准备`mtd6`：

```
# ubiformat /dev/mtd6 -s 2048
```

您可以使用`ubiattach`命令在已准备好的 MTD 分区上加载 UBI 驱动程序：

```
# ubiattach -p /dev/mtd6 -O 2048
```

这将创建设备节点`/dev/ubi0`，通过它可以访问 UBI 卷。您可以多次使用`ubiattach`来处理其他 MTD 分区，在这种情况下，它们可以通过`/dev/ubi1`，`/dev/ubi2`等进行访问。

PEB 到 LEB 的映射在附加阶段加载到内存中，这个过程需要的时间与 PEB 的数量成正比，通常需要几秒钟。在 Linux 3.7 中添加了一个名为 UBI fastmap 的新功能，它会定期将映射检查点到闪存中，从而减少了附加时间。内核配置选项是`CONFIG_MTD_UBI_FASTMAP`。

在`ubiformat`后第一次附加到 MTD 分区时，不会有卷。您可以使用`ubimkvol`创建卷。例如，假设您有一个 128MB 的 MTD 分区，并且您想要使用具有 128 KB 擦除块和 2 KB 页面的芯片将其分成 32 MB 和 96 MB 两个卷：

```
# ubimkvol /dev/ubi0 -N vol_1 -s 32MiB
# ubimkvol /dev/ubi0 -N vol_2 -s 96MiB
```

现在，您有设备节点`/dev/ubi0_0`和`/dev/ubi0_1`。您可以使用`ubinfo`确认情况：

```
# ubinfo -a /dev/ubi0
ubi0
Volumes count:                           2
Logical eraseblock size:                 15360 bytes, 15.0 KiB
Total amount of logical eraseblocks:     8192 (125829120 bytes, 120.0 MiB)
Amount of available logical eraseblocks: 0 (0 bytes)
Maximum count of volumes                 89
Count of bad physical eraseblocks:       0
Count of reserved physical eraseblocks:  160
Current maximum erase counter value:     1
Minimum input/output unit size:          512 bytes
Character device major/minor:            250:0
Present volumes:                         0, 1
Volume ID:   0 (on ubi0)
Type:        dynamic
Alignment:   1
Size:        2185 LEBs (33561600 bytes, 32.0 MiB)
State:       OK
Name:        vol_1
Character device major/minor: 250:1
-----------------------------------
Volume ID:   1 (on ubi0)
Type:        dynamic
Alignment:   1
Size:        5843 LEBs (89748480 bytes, 85.6 MiB)
State:       OK
Name:        vol_2
Character device major/minor: 250:2
```

请注意，由于每个 LEB 都有一个头部来包含 UBI 使用的元信息，因此 LEB 比 PEB 小一个页面。例如，一个 PEB 大小为 128 KB，页面大小为 2 KB 的芯片将具有 126 KB 的 LEB。这是您在创建 UBIFS 映像时需要的重要信息。

### UBIFS

UBIFS 使用 UBI 卷创建一个稳健的文件系统。它添加了子分配和垃圾收集以创建一个完整的闪存转换层。与 JFFS2 和 YAFFS2 不同，它将索引信息存储在芯片上，因此挂载速度很快，尽管不要忘记预先附加 UBI 卷可能需要相当长的时间。它还允许像普通磁盘文件系统一样进行写回缓存，这意味着写入速度更快，但通常的问题是在断电事件中，未从缓存刷新到闪存内存的数据可能会丢失。您可以通过谨慎使用`fsync(2)`和`fdatasync(2)`函数来解决这个问题，在关键点强制刷新文件数据。

UBIFS 具有用于断电快速恢复的日志。日志占用一些空间，通常为 4 MiB 或更多，因此 UBIFS 不适用于非常小的闪存设备。

创建 UBI 卷后，您可以使用卷的设备节点`/dev/ubi0_0`进行挂载，或者使用整个分区的设备节点加上卷名称进行挂载，如下所示：

```
# mount -t ubifs ubi0:vol_1 /mnt
```

为 UBIFS 创建文件系统映像是一个两阶段的过程：首先使用`mkfs.ubifs`创建一个 UBIFS 映像，然后使用`ubinize`将其嵌入到 UBI 卷中。

对于第一阶段，`mkfs.ubifs`需要使用`-m`指定页面大小，使用`-e`指定 UBI LEB 的大小，记住 LEB 通常比 PEB 短一个页面，使用`-c`指定卷中擦除块的最大数量。如果第一个卷是 32 MiB，擦除块是 128 KiB，那么擦除块的数量是 256。因此，要获取目录 rootfs 的内容并创建一个名为`rootfs.ubi`的 UBIFS 映像，您需要输入以下内容：

```
$ mkfs.ubifs -r rootfs -m 2048 -e 126KiB -c 256 -o rootfs.ubi

```

第二阶段需要您为`ubinize`创建一个配置文件，描述映像中每个卷的特性。帮助页面（`ubinize -h`）提供了格式的详细信息。此示例创建了两个卷，`vol_1`和`vol_2`：

```
[ubifsi_vol_1]
mode=ubi
image=rootfs.ubi
vol_id=0
vol_name=vol_1
vol_size=32MiB
vol_type=dynamic

[ubifsi_vol_2]
mode=ubi
image=data.ubi
vol_id=1
vol_name=vol_2
vol_type=dynamic
vol_flags=autoresize
```

第二卷有一个自动调整大小的标志，因此会扩展以填满 MTD 分区上的剩余空间。只有一个卷可以有这个标志。根据这些信息，`ubinize`将创建一个由`-o`参数命名的映像文件，其 PEB 大小为`-p`，页面大小为`-m`，子页面大小为`-s`：

```
$ ubinize -o ~/ubi.img -p 128KiB -m 2048 -s 512 ubinize.cfg

```

要在目标上安装此映像，您需要在目标上输入以下命令：

```
# ubiformat /dev/mtd6 -s 2048
# nandwrite /dev/mtd6 /ubi.img
# ubiattach -p /dev/mtd6 -O 2048
```

如果要使用 UBIFS 根文件系统进行引导，您需要提供以下内核命令行参数：

```
ubi.mtd=6 root=ubi0:vol_1 rootfstype=ubifs
```

# 受管理的闪存文件系统

随着受管理的闪存技术的发展，特别是 eMMC，我们需要考虑如何有效地使用它。虽然它们看起来具有与硬盘驱动器相同的特性，但一些 NAND 闪存芯片具有大擦除块的限制，擦除周期有限，并且坏块处理能力有限。当然，在断电事件中我们需要稳健性。

可以使用任何正常的磁盘文件系统，但我们应该尽量选择一个减少磁盘写入并在非计划关闭后快速重启的文件系统，通常由日志提供。

## Flashbench

为了最佳利用底层闪存，您需要了解擦除块大小和页大小。通常制造商不会公布这些数字，但可以通过观察芯片或卡的行为来推断出它们。

Flashbench 就是这样一个工具。最初是由 Arnd Bergman 编写的，可以在[LWN 文章](http://lwn.net/Articles/428584)中找到。您可以从[`github.com/bradfa/flashbench`](https://github.com/bradfa/flashbench)获取代码。

这是一个典型的 SanDisk GiB SDHC 卡上的运行：

```
$ sudo ./flashbench -a  /dev/mmcblk0 --blocksize=1024
align 536870912 pre 4.38ms  on 4.48ms   post 3.92ms  diff 332µs
align 268435456 pre 4.86ms  on 4.9ms    post 4.48ms  diff 227µs
align 134217728 pre 4.57ms  on 5.99ms   post 5.12ms  diff 1.15ms
align 67108864  pre 4.95ms  on 5.03ms   post 4.54ms  diff 292µs
align 33554432  pre 5.46ms  on 5.48ms   post 4.58ms  diff 462µs
align 16777216  pre 3.16ms  on 3.28ms   post 2.52ms  diff 446µs
align 8388608   pre 3.89ms  on 4.1ms    post 3.07ms  diff 622µs
align 4194304   pre 4.01ms  on 4.89ms   post 3.9ms   diff 940µs
align 2097152   pre 3.55ms  on 4.42ms   post 3.46ms  diff 917µs
align 1048576   pre 4.19ms  on 5.02ms   post 4.09ms  diff 876µs
align 524288    pre 3.83ms  on 4.55ms   post 3.65ms  diff 805µs
align 262144    pre 3.95ms  on 4.25ms   post 3.57ms  diff 485µs
align 131072    pre 4.2ms   on 4.25ms   post 3.58ms  diff 362µs
align 65536     pre 3.89ms  on 4.24ms   post 3.57ms  diff 511µs
align 32768     pre 3.94ms  on 4.28ms   post 3.6ms   diff 502µs
align 16384     pre 4.82ms  on 4.86ms   post 4.17ms  diff 372µs
align 8192      pre 4.81ms  on 4.83ms   post 4.16ms  diff 349µs
align 4096      pre 4.16ms  on 4.21ms   post 4.16ms  diff 52.4µs
align 2048      pre 4.16ms  on 4.16ms   post 4.17ms  diff 9ns

```

Flashbench 在各种 2 的幂边界之前和之后读取块，本例中为 1,024 字节。当您跨越页或擦除块边界时，边界后的读取时间会变长。最右边的列显示了差异，这是最有趣的部分。从底部开始阅读，4 KiB 处有一个很大的跳跃，这很可能是一个页的大小。在 8 KiB 处，从 52.4µs 跳到 349µs 有第二个跳跃。这是相当常见的，表明卡可以使用多平面访问同时读取两个 4 KiB 页。除此之外，差异不太明显，但在 512 KiB 处有一个明显的跳跃，从 485µs 跳到 805µs，这可能是擦除块的大小。考虑到被测试的卡相当古老，这些是您可以预期的数字。

## 丢弃和 TRIM

通常，当您删除文件时，只有修改后的目录节点被写入存储，而包含文件内容的扇区保持不变。当闪存转换层位于磁盘控制器中时，例如受管理的闪存，它不知道这组磁盘扇区不再包含有用数据，因此最终会复制过时的数据。

在过去几年中，传递有关已删除扇区的事务的添加已改善了情况。SCSI 和 SATA 规范有一个`TRIM`命令，MMC 有一个类似的命令称为`ERASE`。在 Linux 中，此功能称为`discard`。

要使用`discard`，您需要一个支持它的存储设备 - 大多数当前的 eMMC 芯片都支持 - 以及与之匹配的 Linux 设备驱动程序。您可以通过查看`/sys/block/<block device>/queue/`中的块系统队列参数来检查。感兴趣的是以下内容：

+   `discard_granularity`：设备内部分配单元的大小

+   `discard_max_bytes`：一次可以丢弃的最大字节数

+   `discard_zeroes_data`：如果为`1`，丢弃的数据将被设置为零

如果设备或设备驱动程序不支持`discard`，这些值都将设置为零。以下是您将从 BeagleBone Black 上的 eMMC 芯片看到的参数：

```
# grep -s "" /sys/block/mmcblk0/queue/discard_*
/sys/block/mmcblk0/queue/discard_granularity:2097152
/sys/block/mmcblk0/queue/discard_max_bytes:2199023255040
/sys/block/mmcblk0/queue/discard_zeroes_data:1
```

在内核文档文件`Documentation/block/queue-sysfs.txt`中有更多信息。

您可以通过在`mount`命令中添加选项`-o discard`来在挂载文件系统时启用`discard`。ext4 和 F2FS 都支持它。

### 提示

在使用`-o discard mount`选项之前，请确保存储设备支持`discard`，否则可能会发生数据丢失。

还可以独立于分区的挂载方式从命令行强制执行`discard`，使用的是`util-linux`软件包的`fstrim`命令。通常，您可以定期运行此命令，例如每周运行一次，以释放未使用的空间。`fstrim`在挂载的文件系统上操作，因此要修剪根文件系统`/`，您需要输入以下内容：

```
# fstrim -v /
/: 2061000704 bytes were trimmed
```

上面的例子使用了冗长选项`-v`，因此打印出了潜在释放的字节数。在这种情况下，2,061,000,704 是文件系统中的大约可用空间，因此这是可能被释放的最大存储量。

## Ext4

扩展文件系统 ext 自 1992 年以来一直是 Linux 桌面的主要文件系统。当前版本 ext4 非常稳定，经过了充分测试，并且具有使从意外关机中恢复变得快速且基本无痛的日志。它是受控闪存设备的不错选择，您会发现它是 Android 设备的首选文件系统，这些设备具有 eMMC 存储。如果设备支持`discard`，您应该使用选项`-o discard`进行挂载。

要在运行时格式化和创建 ext4 文件系统，您需要输入以下命令：

```
# mkfs.ext4 /dev/mmcblk0p2
# mount -t ext4 -o discard /dev/mmcblk0p1 /mnt
```

要创建文件系统镜像，可以使用`genext2fs`实用程序，可从[`genext2fs.sourceforge.net`](http://genext2fs.sourceforge.net)获取。在这个例子中，我已经用`-B`指定了块大小，并用`-b`指定了镜像中的块数：

```
$ genext2fs -B 1024 -b 10000 -d rootfs rootfs.ext4

```

`genext2fs`可以利用设备表来设置文件权限和所有权，如第五章中所述，*构建根文件系统*，使用`-D [文件表]`。

顾名思义，这实际上会生成一个`.ext2`格式的镜像。您可以使用`tune2fs`进行升级，具体命令选项的详细信息在`tune2fs`的主页面中。

```
$ tune2fs -j -J size=1 -O filetype,extents,uninit_bg,dir_index rootfs.ext4
$ e2fsck -pDf rootfs.ext4

```

Yocto 项目和 Buildroot 在创建`.ext4`格式的镜像时使用完全相同的步骤。

虽然日志对于可能在没有警告的情况下断电的设备是一种资产，但它确实会给每个写事务增加额外的写周期，从而耗尽闪存。如果设备是由电池供电的，特别是如果电池无法移除，那么意外断电的可能性很小，因此您可能希望不使用日志。

## F2FS

**Flash-Friendly File System**，**F2FS**，是为受控闪存设备设计的日志结构文件系统，特别适用于 eMMC 和 SD。它由三星编写，并在 3.8 版中合并到主线 Linux。它被标记为实验性，表明它尚未被广泛部署，但似乎一些 Android 设备正在使用它。

F2FS 考虑了页面和擦除块大小，并尝试在这些边界上对齐数据。日志格式在断电时具有弹性，并且具有良好的写入性能，在某些测试中显示出比 ext4 的两倍改进。在内核文档中有 F2FS 设计的良好描述，位于`Documentation/filesystems/f2fs.txt`，并且在本章末尾有参考资料。

`mfs2.fs2`实用程序使用标签`-l`创建一个空的 F2FS 文件系统：

```
# mkfs.f2fs -l rootfs /dev/mmcblock0p1
# mount -t f2fs /dev/mmcblock0p1 /mnt
```

目前还没有工具可以离线创建 F2FS 文件系统镜像。

## FAT16/32

老的 Microsoft 文件系统，FAT16 和 FAT32，作为大多数操作系统理解的常见格式，仍然很重要。当你购买 SD 卡或 USB 闪存驱动器时，它几乎肯定是以 FAT32 格式格式化的，并且在某些情况下，卡上的微控制器被优化为 FAT32 访问模式。此外，一些引导 ROM 需要 FAT 分区用于第二阶段引导加载程序，例如 TI OMAP 芯片。然而，FAT 格式绝对不适合存储关键文件，因为它们容易损坏并且对存储空间利用不佳。

Linux 通过`msdos`文件系统支持 FAT16，通过`vfat`文件系统支持 FAT32 和 FAT16。在大多数情况下，您需要包括`vfat`驱动程序。然后，要挂载设备，比如第二个`mmc`硬件适配器上的 SD 卡，您需要输入以下命令：

```
# mount -t vfat /dev/mmcblock1p1 /mnt
```

过去，`vfat`驱动程序曾存在许可问题，可能侵犯了 Microsoft 持有的专利。

FAT32 对设备大小有 32 GiB 的限制。容量更大的设备可以使用 Microsoft exFAT 格式进行格式化，并且这是 SDXC 卡的要求。没有 exFAT 的内核驱动程序，但可以通过用户空间 FUSE 驱动程序来支持。由于 exFAT 是 Microsoft 专有的，如果您在设备上支持这种格式，肯定会有许可证方面的影响。

# 只读压缩文件系统

如果存储空间不够，压缩数据是有用的。JFFS2 和 UBIFS 默认情况下都进行即时数据压缩。但是，如果文件永远不会被写入，通常情况下是根文件系统，您可以通过使用只读的压缩文件系统来实现更好的压缩比。Linux 支持几种这样的文件系统：`romfs`、`cramfs`和`squashfs`。前两者现在已经过时，因此我只描述`squashfs`。

## squashfs

`squashfs`是由 Phillip Lougher 于 2002 年编写的，作为`cramfs`的替代品。它作为一个内核补丁存在了很长时间，最终在 2009 年的 Linux 主线版本 2.6.29 中合并。它非常容易使用：您可以使用`mksquashfs`创建一个文件系统映像，并将其安装到闪存存储器中：

```
$ mksquashfs rootfs rootfs.squashfs

```

由于生成的文件系统是只读的，因此没有机制可以在运行时修改任何文件。更新`squashfs`文件系统的唯一方法是擦除整个分区并编程一个新的映像。

`squashfs`不具备坏块感知功能，因此必须与可靠的闪存存储器一起使用，例如 NOR 闪存。它可以在 NAND 闪存上使用，只要您使用 UBI 在其上创建一个模拟的、可靠的 MTD 卷。您必须启用内核配置`CONFIG_MTD_UBI_BLOCK`，这将为每个 UBI 卷创建一个只读的 MTD 块设备。下图显示了两个 MTD 分区，每个分区都有相应的`mtdblock`设备。第二个分区还用于创建一个 UBI 卷，该卷作为第三个可靠的`mtdblock`设备公开，您可以将其用于任何不具备坏块感知功能的只读文件系统：

![squashfs](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_04.jpg)

# 临时文件系统

总是有一些文件的生命周期很短，或者在重新启动后就不再重要。许多这样的文件被放在`/tmp`中，因此将这些文件保存在永久存储中是有意义的。

临时文件系统`tmpfs`非常适合这个目的。您可以通过简单地挂载`tmpfs`来创建一个临时的基于 RAM 的文件系统：

```
# mount -t tmpfs tmp_files /tmp
```

与`procfs`和`sysfs`一样，`tmpfs`没有与设备节点相关联，因此您必须在前面的示例中提供一个占位符字符串`tmp_files`。

使用的内存量会随着文件的创建和删除而增长和缩小。默认的最大大小是物理 RAM 的一半。在大多数情况下，如果`tmpfs`增长到那么大，那将是一场灾难，因此最好使用`-o size`参数对其进行限制。该参数可以以字节、KiB（`k`）、MiB（`m`）或 GiB（`g`）的形式给出，例如：

```
mount -t tmpfs -o size=1m tmp_files /tmp
```

除了`/tmp`之外，`/var`的一些子目录包含易失性数据，最好也使用`tmpfs`为它们创建一个单独的文件系统，或者更经济地使用符号链接。Buildroot 就是这样做的：

```
/var/cache -> /tmp
/var/lock ->  /tmp
/var/log ->   /tmp
/var/run ->   /tmp
/var/spool -> /tmp
/var/tmp ->   /tmp
```

在 Yocto 项目中，`/run`和`/var/volatile`是`tmpfs`挂载点，具有指向它们的符号链接，如下所示：

```
/tmp ->       /var/tmp
/var/lock ->  /run/lock
/var/log ->   /var/volatile/log
/var/run ->   /run
/var/tmp ->   /var/volatile/tmp
```

# 使根文件系统只读

您需要使目标设备能够在发生意外事件时存活，包括文件损坏，并且仍然能够引导并实现至少最低级别的功能。使根文件系统只读是实现这一目标的关键部分，因为它消除了意外覆盖。将其设置为只读很容易：在内核命令行中用`ro`替换`rw`，或者使用固有的只读文件系统，如`squashfs`。但是，您会发现有一些传统上是可写的文件和目录：

+   `/etc/resolv.conf`：此文件由网络配置脚本编写，用于记录 DNS 名称服务器的地址。这些信息是易失性的，因此您只需将其设置为指向临时目录的符号链接，例如`/etc/resolv.conf -> /var/run/resolv.conf`。

+   `/etc/passwd`：此文件与`/etc/group`、`/etc/shadow`和`/etc/gshadow`一起存储用户和组名称以及密码。它们需要像`resolv.conf`一样被符号链接到持久存储区域。

+   `/var/lib`：许多应用程序希望能够写入此目录并在此处保留永久数据。一种解决方案是在启动时将一组基本文件复制到`tmpfs`文件系统，然后通过将一系列命令绑定到新位置的`/var/lib`来将`/var/lib`绑定到新位置，将这些命令放入其中一个启动脚本中：

```
mkdir -p /var/volatile/lib
cp -a /var/lib/* /var/volatile/lib
mount --bind /var/volatile/lib /var/lib

```

+   `/var/log`：这是 syslog 和其他守护程序保存其日志的地方。通常，由于产生许多小的写入周期，将日志记录到闪存内存中是不可取的。一个简单的解决方案是使用`tmpfs`挂载`/var/log`，使所有日志消息都是易失性的。在`syslogd`的情况下，BusyBox 有一个版本，可以记录到循环环形缓冲区。

如果您正在使用 Yocto 项目，可以通过将`IMAGE_FEATURES = "read-only-rootfs"`添加到`conf/local.conf`或您的镜像配方来创建只读根文件系统。

# 文件系统选择

到目前为止，我们已经看过固态存储器背后的技术以及许多类型的文件系统。现在是总结选项的时候了。

在大多数情况下，您将能够将存储需求分为这三类：

+   **永久的、可读写的数据**：运行时配置、网络参数、密码、数据日志和用户数据

+   **永久的只读数据**：程序、库和配置文件是恒定的，例如根文件系统

+   **易失性数据**：临时存储，例如`/tmp`

读写存储的选择如下：

+   **NOR**：UBIFS 或 JFFS2

+   **NAND**：UBIFS、JFFS2 或 YAFFS2

+   **eMMC**：ext4 或 F2FS

### 注意

对于只读存储，您可以使用上述所有内容，并带有`ro`属性进行挂载。此外，如果要节省空间，可以在 NAND 闪存的情况下使用`squashfs`，使用 UBI `mtdblock`设备仿真来处理坏块。

最后，对于易失性存储，只有一种选择，即`tmpfs`。

# 现场更新

已经有几个广为人知的安全漏洞，包括 Heartbleed（OpenSSL 库中的一个错误）和 Shellshock（bash shell 中的一个错误），这两者都可能对当前部署的嵌入式 Linux 设备造成严重后果。光是出于这个原因，就非常希望有一种机制来更新现场设备，以便在出现安全问题时进行修复。还有其他很好的原因：部署其他错误修复和功能更新。

更新机制的指导原则是不应该造成任何伤害，要记住墨菲定律：如果有可能出错，迟早会出错。任何更新机制必须是：

+   **健壮**：它不能使设备无法操作。我将谈论原子更新；系统要么成功更新，要么根本不更新，并继续像以前一样运行。

+   **故障安全**：它必须能够优雅地处理中断的更新。

+   **安全**：它不能允许未经授权的更新，否则它将成为一种攻击机制。

通过复制要更新的内容的副本并在安全时切换到新副本来实现原子性。

故障安全性要求必须有一种机制来检测失败的更新，例如硬件看门狗，并且有一个已知的良好软件副本可以回退。

安全性可以通过本地和经过密码或 PIN 码认证的更新来实现。但是，如果更新是远程和自动的，就需要通过网络进行一定级别的认证。最终，您可能希望添加安全的引导加载程序和签名的更新二进制文件。

有些组件比其他组件更容易更新。引导加载程序非常难以更新，因为通常存在硬件约束，意味着只能有一个引导加载程序，因此如果更新失败就无法备份。另一方面，引导加载程序通常不是运行时错误的原因。最好的建议是避免在现场更新引导加载程序。

## 粒度：文件、软件包或镜像？

这是一个重要的问题，取决于您的整体系统设计和所需的健壮性水平。

文件更新可以是原子的：技术是将新内容写入同一文件系统中的临时文件，然后使用 POSIX `rename(2)`函数将其移动到旧文件上。它有效是因为重命名是保证原子性的。然而，这只是问题的一部分，因为文件之间会有依赖关系需要考虑。

在软件包（`RPM`，`dpkg`或`ipk`）级别进行更新是一个更好的选择，假设您有一个运行时软件包管理器。毕竟，这就是桌面发行版多年来一直在做的事情。软件包管理器有一个更新数据库，并可以跟踪已更新和未更新的内容。每个软件包都有一个更新脚本，旨在确保软件包更新是原子的。最大的优势是您可以轻松更新现有软件包，安装新软件包，并删除过时的软件包。如果您使用的是以只读方式挂载的根文件系统，则在更新时必须暂时重新挂载为读写，这会打开一个小的损坏窗口。

软件包管理器也有缺点。它们无法更新原始闪存中的内核或其他镜像。在设备部署并多次更新后，您可能会得到大量软件包和软件包版本的组合，这将使每个新的更新周期的质量保证变得更加复杂。在更新期间发生断电时，软件包管理器也无法保证安全。

第三个选项是更新整个系统镜像：内核、根文件系统、用户应用程序等。

## 原子镜像更新

为了使更新是原子的，我们需要两样东西：一个可以在更新期间使用的操作系统的第二个副本，以及引导加载程序中选择要加载的操作系统副本的机制。第二个副本可能与第一个完全相同，从而实现操作系统的完全冗余，或者它可能是一个专门用于更新主操作系统的小型操作系统。

在第一种方案中，有两份操作系统副本，每个副本由 Linux 内核、根文件系统和系统应用程序组成，如下图所示：

![原子镜像更新](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_05.jpg)

最初，引导标志未设置，因此引导加载副本 1。要安装更新，操作系统的更新程序将覆盖副本 2。完成后，它设置引导标志并重新启动。现在，引导加载新的操作系统。安装进一步更新时，副本 2 中的更新程序将覆盖副本 1，并清除引导标志，因此您在两个副本之间来回移动。

如果更新失败，引导标志不会更改，并且将使用上一个良好的操作系统。即使更新由多个组件组成，如内核镜像、DTB、根文件系统和系统应用程序文件系统，整个更新也是原子的，因为只有在所有更新完成时才会更新引导标志。

这种方案的主要缺点是需要存储两份操作系统的副本。

您可以通过保留一个纯粹用于更新主操作系统的最小操作系统来减少存储需求，如下图所示：

![原子镜像更新](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_07_06.jpg)

当您想要安装更新时，设置引导标志并重新启动。一旦恢复操作系统运行，它启动更新程序，覆盖主操作系统镜像。完成后，清除引导标志并再次重新启动，这次加载新的主操作系统。

恢复操作系统通常比主操作系统小得多，可能只有几兆字节，因此存储开销并不大。事实上，这是 Android 采用的方案。主操作系统有几百兆字节，但恢复模式操作系统只是一个简单的几兆字节的 ramdisk。

# 进一步阅读

以下资源提供了有关本章介绍的主题的更多信息：

+   *XIP：过去，现在...未来？*，*Vitaly Wool*，在 FOSDEM 2007 年的演示：[`archive.fosdem.org/2007/slides/devrooms/embedded/Vitaly_Wool_XIP.pdf`](https://archive.fosdem.org/2007/slides/devrooms/embedded/Vitaly_Wool_XIP.pdf)

+   *MTD 文档*：[`www.linux-mtd.infradead.org/doc/general.html`](http://www.linux-mtd.infradead.org/doc/general.html)

+   *使用廉价闪存驱动器优化 Linux*，*Arnd Bergmann*：[`lwn.net/Articles/428584/`](http://lwn.net/Articles/428584/)

+   *闪存存储卡设计*：[`wiki.linaro.org/WorkingGroups/KernelArchived/Projects/FlashCardSurvey`](https://wiki.linaro.org/WorkingGroups/KernelArchived/Projects/FlashCardSurvey)

+   *eMMC/SSD 文件系统调优方法*：[`elinux.org/images/b/b6/EMMC-SSD_File_System_Tuning_Methodology_v1.0.pdf`](http://elinux.org/images/b/b6/EMMC-SSD_File_System_Tuning_Methodology_v1.0.pdf)

+   *闪存友好的文件系统（F2FS）*：[`elinux.org/images/1/12/Elc2013_Hwang.pdf`](http://elinux.org/images/1/12/Elc2013_Hwang.pdf)

+   *f2fS 拆解*：[`lwn.net/Articles/518988/`](http://lwn.net/Articles/518988/)

+   *构建兼容 Murphy 的嵌入式 Linux 系统*，*Gilad Ben-Yossef*：[`www.kernel.org/doc/ols/2005/ols2005v1-pages-21-36.pdf`](https://www.kernel.org/doc/ols/2005/ols2005v1-pages-21-36.pdf)

# 总结

从一开始，闪存存储技术一直是嵌入式 Linux 的首选技术，多年来 Linux 已经获得了非常好的支持，从低级驱动程序到支持闪存的文件系统，最新的是 UBIFS。

然而，随着新的闪存技术推出的速度加快，要跟上高端变化变得更加困难。系统设计师越来越倾向于使用 eMMC 形式的托管闪存，以提供稳定的硬件和软件接口，独立于内部存储芯片。嵌入式 Linux 开发人员开始逐渐掌握这些新芯片。对于 ext4 和 F2FS 中的 TRIM 的支持已经很成熟，并且它正在慢慢地进入芯片本身。此外，出现了新的针对管理闪存优化的文件系统，比如 F2FS，这是一个值得欢迎的进步。

然而，事实仍然是，闪存存储技术与硬盘驱动器不同。你必须小心减少文件系统写入的次数 - 尤其是高密度 TLC 芯片可能只支持 1000 次擦除循环。

最后，在现场更新设备上存储的文件和图像时，有一个更新策略是至关重要的。其中一个关键部分是决定是否使用软件包管理器。软件包管理器可以给你灵活性，但不能提供完全可靠的更新解决方案。你的选择取决于方便性和稳健性之间的平衡。

下一章描述了如何通过设备驱动程序控制系统的硬件组件，包括内核中的驱动程序以及用户空间中控制硬件的程度。


# 第八章：介绍设备驱动程序

内核设备驱动程序是将底层硬件暴露给系统其余部分的机制。作为嵌入式系统的开发人员，您需要了解设备驱动程序如何适应整体架构以及如何从用户空间程序中访问它们。您的系统可能会有一些新颖的硬件部件，您将不得不找出一种访问它们的方法。在许多情况下，您会发现已经为您提供了设备驱动程序，您可以在不编写任何内核代码的情况下实现您想要的一切。例如，您可以使用`sysfs`中的文件来操作 GPIO 引脚和 LED，并且有库可以访问串行总线，包括 SPI 和 I2C。

有很多地方可以找到如何编写设备驱动程序的信息，但很少有地方告诉你为什么要这样做以及在这样做时的选择。这就是我想在这里介绍的内容。但是，请记住，这不是一本专门写内核设备驱动程序的书，这里提供的信息是为了帮助您在这个领域中导航，而不一定是为了在那里设置家。有很多好书和文章可以帮助您编写设备驱动程序，其中一些列在本章末尾。

# 设备驱动程序的作用

如第四章中所述，*移植和配置内核*，内核的功能之一是封装计算机系统的许多硬件接口，并以一致的方式呈现给用户空间程序。有设计的框架使得在内核中编写设备的接口逻辑变得容易，并且可以将其集成到内核中：这就是设备驱动程序，它是介于其上方的内核和其下方的硬件之间的代码片段。设备驱动程序是控制物理设备（如 UART 或 MMC 控制器）或虚拟设备（如空设备(`/dev/null`)或 ramdisk）的软件。一个驱动程序可以控制多个相同类型的设备。

内核设备驱动程序代码以高特权级别运行，就像内核的其余部分一样。它可以完全访问处理器地址空间和硬件寄存器。它可以处理中断和 DMA 传输。它可以利用复杂的内核基础设施进行同步和内存管理。这也有一个缺点，即如果有错误的驱动程序出现问题，它可能会导致系统崩溃。因此，有一个原则是设备驱动程序应尽可能简单，只提供信息给应用程序，真正的决策是在应用程序中做出的。你经常听到这被表达为*内核中没有策略*。

在 Linux 中，有三种主要类型的设备驱动程序：

+   **字符**：这是用于具有丰富功能范围和应用程序代码与驱动程序之间薄层的无缓冲 I/O。在实现自定义设备驱动程序时，这是首选。

+   **块**：这具有专门针对从大容量存储设备进行块 I/O 的接口。有一个厚的缓冲层，旨在使磁盘读取和写入尽可能快，这使其不适用于其他用途。

+   **网络**：这类似于块设备，但用于传输和接收网络数据包，而不是磁盘块。

还有第四种类型，它表现为伪文件系统中的一组文件。例如，您可以通过`/sys/class/gpio`中的一组文件访问 GPIO 驱动程序，我将在本章后面描述。让我们首先更详细地看一下三种基本设备类型。

# 字符设备

这些设备在用户空间通过文件名进行标识：如果你想从 UART 读取数据，你需要打开设备节点，例如，在 ARM Versatile Express 上的第一个串行端口将是`/dev/ttyAMA0`。驱动程序在内核中以不同的方式进行标识，使用的是主设备号，在给定的示例中是`204`。由于 UART 驱动程序可以处理多个 UART，还有第二个号码，称为次设备号，用于标识特定的接口，例如在这种情况下是 64。

```
# ls -l /dev/ttyAMA*

crw-rw----    1 root     root      204,  64 Jan  1  1970 /dev/ttyAMA0
crw-rw----    1 root     root      204,  65 Jan  1  1970 /dev/ttyAMA1
crw-rw----    1 root     root      204,  66 Jan  1  1970 /dev/ttyAMA2
crw-rw----    1 root     root      204,  67 Jan  1  1970 /dev/ttyAMA3
```

标准主设备号和次设备号的列表可以在内核文档中找到，位于`Documentation/devices.txt`中。该列表不经常更新，也不包括前面段落中描述的`ttyAMA`设备。然而，如果你查看`drivers/tty/serial/amba-pl011.c`中的源代码，你会看到主设备号和次设备号是如何声明的。

```
#define SERIAL_AMBA_MAJOR       204
#define SERIAL_AMBA_MINOR       64
```

当一个设备有多个实例时，设备节点的命名约定为`<基本名称><接口号>`，例如，`ttyAMA0`，`ttyAMA1`等。

正如我在第五章中提到的，*构建根文件系统*，设备节点可以通过多种方式创建：

+   `devtmpfs`：当设备驱动程序使用驱动程序提供的基本名称（`ttyAMA`）和实例号注册新的设备接口时创建的节点。

+   `udev`或`mdev`（没有`devtmpfs`）：与`devtmpfs`基本相同，只是需要一个用户空间守护程序从`sysfs`中提取设备名称并创建节点。我稍后会谈到`sysfs`。

+   `mknod`：如果你使用静态设备节点，可以使用`mknod`手动创建它们。

你可能会从上面我使用的数字中得到这样的印象，即主设备号和次设备号都是 8 位数字，范围在 0 到 255 之间。实际上，从 Linux 2.6 开始，主设备号有 12 位长，有效数字范围为 1 到 4095，次设备号有 20 位，范围为 0 到 1048575。

当你打开一个设备节点时，内核会检查主设备号和次设备号是否落在该类型设备驱动程序注册的范围内（字符或块）。如果是，它会将调用传递给驱动程序，否则打开调用失败。设备驱动程序可以提取次设备号以找出要使用的硬件接口。如果次设备号超出范围，它会返回错误。

要编写一个访问设备驱动程序的程序，你必须对其工作原理有一定了解。换句话说，设备驱动程序与文件不同：你对它所做的事情会改变设备的状态。一个简单的例子是伪随机数生成器`urandom`，每次读取它都会返回随机数据的字节。下面是一个执行此操作的程序：

```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
  int f;
  unsigned int rnd;
  int n;
  f = open("/dev/urandom", O_RDONLY);
  if (f < 0) {
    perror("Failed to open urandom");
    return 1;
  }
  n = read(f, &rnd, sizeof(rnd));
  if (n != sizeof(rnd)) {
    perror("Problem reading urandom");
    return 1;
  }
  printf("Random number = 0x%x\n", rnd);
  close(f);
  return 0;
}
```

Unix 驱动程序模型的好处在于，一旦我们知道有一个名为`urandom`的设备，并且每次从中读取数据时，它都会返回一组新的伪随机数据，我们就不需要再了解其他任何信息。我们可以直接使用诸如`open(2)`、`read(2)`和`close(2)`等普通函数。

我们可以使用流 I/O 函数`fopen(3)`、`fread(3)`和`fclose(3)`，但是这些函数隐含的缓冲区通常会导致意外的行为。例如，`fwrite(3)`通常只写入用户空间缓冲区，而不是设备。我们需要调用`fflush(3)`来强制刷新缓冲区。

### 提示

不要在调用设备驱动程序时使用流 I/O 函数，比如`fread(3)`和`fwrite(3)`。

# 块设备

块设备也与设备节点相关联，同样具有主设备号和次设备号。

### 提示

尽管字符设备和块设备使用主设备号和次设备号进行标识，但它们位于不同的命名空间。主设备号为 4 的字符驱动程序与主设备号为 4 的块驱动程序没有任何关联。

对于块设备，主编号用于标识设备驱动程序，次编号用于标识分区。让我们以 MMC 驱动程序为例：

```
# ls -l /dev/mmcblk*

brw-------    1 root root  179,   0 Jan  1  1970 /dev/mmcblk0
brw-------    1 root root  179,   1 Jan  1  1970 /dev/mmcblk0p1
brw-------    1 root root  179,   2 Jan  1  1970 /dev/mmcblk0p2
brw-------    1 root root  179,   8 Jan  1  1970 /dev/mmcblk1
brw-------    1 root root  179,   9 Jan  1  1970 /dev/mmcblk1p1
brw-------    1 root root  179,  10 Jan  1  1970 /dev/mmcblk1p2
```

主编号为 179（在`devices.txt`中查找！）。次编号用于标识不同的`mmc`设备和该设备上存储介质的分区。对于 mmcblk 驱动程序，每个设备有八个次编号范围：从 0 到 7 的次编号用于第一个设备，从 8 到 15 的次编号用于第二个设备，依此类推。在每个范围内，第一个次编号代表整个设备的原始扇区，其他次编号代表最多七个分区。

您可能已经了解到 SCSI 磁盘驱动程序，称为 sd，用于控制使用 SCSI 命令集的一系列磁盘，其中包括 SCSI、SATA、USB 大容量存储和 UFS（通用闪存存储）。它的主编号为 8，每个接口（或磁盘）有 16 个次编号。从 0 到 15 的次编号用于第一个接口，设备节点的名称为`sda`到`sda15`，从 16 到 31 的编号用于第二个磁盘，设备节点为`sdb`到`sdb15`，依此类推。这一直持续到第 16 个磁盘，从 240 到 255，节点名称为`sdp`。由于 SCSI 磁盘非常受欢迎，还有其他为它们保留的主编号，但我们不需要在这里担心这些。

分区是使用诸如`fdisk`、`sfidsk`或`parted`之类的实用程序创建的。一个例外是原始闪存：MTD 驱动程序的分区信息是内核命令行或设备树中的一部分，或者是第七章中描述的其他方法之一，*创建存储策略*。

用户空间程序可以通过设备节点直接打开和与块设备交互。这不是常见的操作，通常用于执行分区、格式化文件系统和挂载等管理操作。一旦文件系统被挂载，您将通过该文件系统中的文件间接与块设备交互。

# 网络设备

网络设备不是通过设备节点访问的，也没有主次编号。相反，内核会根据字符串和实例号为网络设备分配一个名称。以下是网络驱动程序注册接口的示例方式：

```
my_netdev = alloc_netdev(0, "net%d", NET_NAME_UNKNOWN, netdev_setup);
ret = register_netdev(my_netdev);
```

这将创建一个名为`net0`的网络设备，第一次调用时为`net1`，依此类推。更常见的名称是`lo`、`eth0`和`wlan0`。

请注意，这是它起始的名称；设备管理器（如`udev`）可能会在以后更改为其他名称。

通常，网络接口名称仅在使用诸如`ip`和`ifconfig`之类的实用程序配置网络以建立网络地址和路由时使用。此后，您通过打开套接字间接与网络驱动程序交互，并让网络层决定如何将它们路由到正确的接口。

但是，可以通过创建套接字并使用`include/linux/sockios.h`中列出的`ioctl`命令直接从用户空间访问网络设备。例如，此程序使用`SIOCGIFHWADDR`查询驱动程序的硬件（MAC）地址：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <net/if.h>
int main (int argc, char *argv[])
{
  int s;
  int ret;
  struct ifreq ifr;
  int i;
  if (argc != 2) {
    printf("Usage %s [network interface]\n", argv[0]);
    return 1;
  }
  s = socket(PF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    perror("socket");
    return 1;
  }
  strcpy(ifr.ifr_name, argv[1]);
  ret = ioctl(s, SIOCGIFHWADDR, &ifr);
  if (ret < 0) {
    perror("ioctl");
    return 1;
  }
  for (i = 0; i < 6; i++)
    printf("%02x:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
  printf("\n");
  close(s);
  return 0;
}
```

这是一个标准设备`ioctl`，由网络层代表驱动程序处理，但是可以定义自己的`ioctl`编号并在自定义网络驱动程序中处理它们。

# 在运行时了解驱动程序

一旦您运行了 Linux 系统，了解加载的设备驱动程序及其状态是很有用的。您可以通过阅读`/proc`和`/sys`中的文件来了解很多信息。

首先，您可以通过读取`/proc/devices`来列出当前加载和活动的字符和块设备驱动程序：

```
# cat /proc/devices

Character devices:

  1 mem
  2 pty
  3 ttyp
  4 /dev/vc/0
  4 tty
  4 ttyS
  5 /dev/tty
  5 /dev/console
  5 /dev/ptmx
  7 vcs
 10 misc
 13 input
 29 fb
 81 video4linux
 89 i2c
 90 mtd
116 alsa
128 ptm
136 pts
153 spi
180 usb
189 usb_device
204 ttySC
204 ttyAMA
207 ttymxc
226 drm
239 ttyLP
240 ttyTHS
241 ttySiRF
242 ttyPS
243 ttyWMT
244 ttyAS
245 ttyO
246 ttyMSM
247 ttyAML
248 bsg
249 iio
250 watchdog
251 ptp
252 pps
253 media
254 rtc

Block devices:

259 blkext
  7 loop
  8 sd
 11 sr
 31 mtdblock
 65 sd
 66 sd
 67 sd
 68 sd
 69 sd
 70 sd
 71 sd
128 sd
129 sd
130 sd
131 sd
132 sd
133 sd
134 sd
135 sd
179 mmc
```

对于每个驱动程序，您可以看到主要编号和基本名称。但是，这并不能告诉您每个驱动程序连接到了多少设备。它只显示了`ttyAMA`，但并没有提示它连接了四个真实的 UART。我稍后会回到这一点，当我查看`sysfs`时。如果您正在使用诸如`mdev`、`udev`或`devtmpfs`之类的设备管理器，您可以通过查看`/dev`中的字符和块设备接口来列出它们。

您还可以使用`ifconfig`或`ip`列出网络接口：

```
# ip link show

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00

2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT qlen 1000
    link/ether 54:4a:16:bb:b7:03 brd ff:ff:ff:ff:ff:ff

3: usb0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT qlen 1000
    link/ether aa:fb:7f:5e:a8:d5 brd ff:ff:ff:ff:ff:ff
```

您还可以使用众所周知的命令`lsusb`和`lspci`来查找连接到 USB 或 PCI 总线的设备。关于它们的信息在各自的手册和大量的在线指南中都有，所以我在这里不再详细描述它们。

真正有趣的信息在`sysfs`中，这是下一个主题。

## 从 sysfs 获取信息

您可以以一种迂腐的方式定义`sysfs`，即内核对象、属性和关系的表示。内核对象是一个目录，属性是一个文件，关系是从一个对象到另一个对象的符号链接。

从更实际的角度来看，自 Linux 设备驱动程序模型在 2.6 版本中引入以来，它将所有设备和驱动程序表示为内核对象。您可以通过查看`/sys`来看到系统的内核视图，如下所示：

```
# ls /sys

block  bus  class  dev  devices  firmware  fs  kernel  module  power
```

在发现有关设备和驱动程序的信息方面，我将查看三个目录：`devices`、`class`和`block`。

## 设备：/sys/devices

这是内核对自启动以来发现的设备及其相互连接的视图。它是按系统总线在顶层组织的，因此您看到的内容因系统而异。这是 Versatile Express 的 QEMU 仿真：

```
# ls
 /sys/devices
armv7_cortex_a9  platform      system
breakpoint       software      virtual
```

所有系统上都存在三个目录：

+   `系统`：这包含了系统核心的设备，包括 CPU 和时钟。

+   `虚拟`：这包含基于内存的设备。您将在`virtual/mem`中找到出现为`/dev/null`、`/dev/random`和`/dev/zero`的内存设备。您将在`virtual/net`中找到环回设备`lo`。

+   `平台`：这是一个通用术语，用于指代通过传统硬件总线连接的设备。这几乎可以是嵌入式设备上的任何东西。

其他设备出现在与实际系统总线对应的目录中。例如，PCI 根总线（如果有）显示为`pci0000:00`。

浏览这个层次结构相当困难，因为它需要对系统的拓扑结构有一定的了解，而且路径名变得相当长，很难记住。为了让生活变得更容易，`/sys/class`和`/sys/block`提供了设备的两种不同视图。

## 驱动程序：/sys/class

这是设备驱动程序的视图，按其类型呈现，换句话说，这是一种软件视图而不是硬件视图。每个子目录代表一个驱动程序类，并由驱动程序框架的一个组件实现。例如，UART 设备由`tty`层管理，您将在`/sys/class/tty`中找到它们。同样，您将在`/sys/class/net`中找到网络设备，在`/sys/class/input`中找到输入设备，如键盘、触摸屏和鼠标，依此类推。

每个子目录中都有一个符号链接，指向该类型设备的每个实例在`/sys/device`中的表示。 

举个具体的例子，让我们看一下`/sys/class/tty/ttyAMA0`：

```
# cd  /sys/class/tty/ttyAMA0/
# ls
close_delay      flags            line             uartclk
closing_wait     io_type          port             uevent
custom_divisor   iomem_base       power            xmit_fifo_size
dev              iomem_reg_shift  subsystem
device           irq              type
```

链接`设备`引用了设备的硬件节点，`子系统`指向`/sys/class/tty`。其他属性是设备的属性。有些属性是特定于 UART 的，比如`xmit_fifo_size`，而其他属性适用于许多类型的设备，比如中断号`irq`和设备号`dev`。一些属性文件是可写的，允许您在运行时调整驱动程序的参数。

`dev`属性特别有趣。如果您查看它的值，您会发现以下内容：

```
# cat /sys/class/tty/ttyAMA0/dev
204:64
```

这是设备的主要和次要编号。当驱动程序注册了这个接口时，就会创建这个属性，如果没有`devtmpfs`的帮助，`udev`和`mdev`就会从这个文件中读取这些信息。

## 块驱动程序：/sys/block

设备模型的另一个重要视图是块驱动程序视图，你可以在`/sys/block`中找到。每个块设备都有一个子目录。这个例子来自 BeagleBone Black：

```
# ls /sys/block/

loop0  loop4  mmcblk0       ram0   ram12  ram2  ram6
loop1  loop5  mmcblk1       ram1   ram13  ram3  ram7
loop2  loop6  mmcblk1boot0  ram10  ram14  ram4  ram8
loop3  loop7  mmcblk1boot1  ram11  ram15  ram5  ram9
```

如果你查看这块板上的 eMMC 芯片`mmcblk1`，你可以看到接口的属性和其中的分区：

```
# cd /sys/block/mmcblk1
# ls

alignment_offset   ext_range     mmcblk1p1  ro
bdi                force_ro      mmcblk1p2  size
capability         holders       power      slaves
dev                inflight      queue      stat
device             mmcblk1boot0  range      subsystem
discard_alignment  mmcblk1boot1  removable  uevent
```

因此，通过阅读`sysfs`，你可以了解系统上存在的设备（硬件）和驱动程序（软件）。

# 寻找合适的设备驱动程序

典型的嵌入式板是基于制造商的参考设计，经过更改以适合特定应用。它可能通过 I2C 连接温度传感器，通过 GPIO 引脚连接灯和按钮，通过外部以太网 MAC 连接，通过 MIPI 接口连接显示面板，或者其他许多东西。你的工作是创建一个自定义内核来控制所有这些，那么你从哪里开始呢？

有些东西非常简单，你可以编写用户空间代码来处理它们。通过 I2C 或 SPI 连接的 GPIO 和简单外围设备很容易从用户空间控制，我稍后会解释。

其他东西需要内核驱动程序，因此你需要知道如何找到一个并将其整合到你的构建中。没有简单的答案，但这里有一些地方可以找到。

最明显的地方是制造商网站上的驱动程序支持页面，或者你可以直接问他们。根据我的经验，这很少能得到你想要的结果；硬件制造商通常不太懂 Linux，他们经常给出误导性的信息。他们可能有二进制的专有驱动程序，也可能有源代码，但是适用于与你拥有的内核版本不同的版本。所以，尽管可以尝试这种途径。我总是会尽力寻找适合手头任务的开源驱动程序。

你的内核可能已经支持：主线 Linux 中有成千上万的驱动程序，供应商内核中也有许多特定于供应商的驱动程序。首先运行`make menuconfig`（或`xconfig`），搜索产品名称或编号。如果找不到完全匹配的，尝试更通用的搜索，考虑到大多数驱动程序处理同一系列产品。接下来，尝试在驱动程序目录中搜索代码（这里用`grep`）。始终确保你正在运行适合你的板的最新内核：较新的内核通常有更多的设备驱动程序。

如果你还没有驱动程序，可以尝试在线搜索并在相关论坛上询问，看看是否有适用于不同 Linux 版本的驱动程序。如果找到了，你就需要将其移植到你的内核中。如果内核版本相似，可能会很容易，但如果相隔 12 到 18 个月以上，接口很可能已经发生了变化，你将不得不重写驱动程序的一部分，以使其与你的内核集成。你可能需要外包这项工作。如果所有上述方法都失败了，你就得自己找解决方案。

# 用户空间的设备驱动程序

在你开始编写设备驱动程序之前，暂停一下，考虑一下是否真的有必要。对于许多常见类型的设备，有通用的设备驱动程序，允许你直接从用户空间与硬件交互，而不必编写一行内核代码。用户空间代码肯定更容易编写和调试。它也不受 GPL 的限制，尽管我不认为这本身是一个好理由。

它们可以分为两大类：通过`sysfs`中的文件进行控制的设备，包括 GPIO 和 LED，以及通过设备节点公开通用接口的串行总线，比如 I2C。

## GPIO

**通用输入/输出**（**GPIO**）是数字接口的最简单形式，因为它可以直接访问单个硬件引脚，每个引脚可以配置为输入或输出。 GPIO 甚至可以用于通过在软件中操作每个位来创建更高级的接口，例如 I2C 或 SPI，这种技术称为位操作。主要限制是软件循环的速度和准确性以及您想要为它们分配的 CPU 周期数。一般来说，使用`CONFIG_PREEMPT`编译的内核很难实现比毫秒更好的定时器精度，使用`RT_PREEMPT`编译的内核很难实现比 100 微秒更好的定时器精度，我们将在第十四章中看到，*实时编程*。 GPIO 的更常见用途是读取按钮和数字传感器以及控制 LED、电机和继电器。

大多数 SoC 有很多 GPIO 位，这些位被分组在 GPIO 寄存器中，通常每个寄存器有 32 位。芯片上的 GPIO 位通过多路复用器（称为引脚复用器）路由到芯片封装上的 GPIO 引脚，我稍后会描述。在电源管理芯片和专用 GPIO 扩展器中可能有额外的 GPIO 位，通过 I2C 或 SPI 总线连接。所有这些多样性都由一个名为`gpiolib`的内核子系统处理，它实际上不是一个库，而是 GPIO 驱动程序用来以一致的方式公开 IO 的基础设施。

有关`gpiolib`实现的详细信息在内核源中的`Documentation/gpio`中，驱动程序本身在`drivers/gpio`中。

应用程序可以通过`/sys/class/gpio`目录中的文件与`gpiolib`进行交互。以下是在典型嵌入式板（BeagleBone Black）上看到的内容的示例：

```
# ls  /sys/class/gpio
export  gpiochip0   gpiochip32  gpiochip64  gpiochip96  unexport
```

`gpiochip0`到`gpiochip96`目录代表了四个 GPIO 寄存器，每个寄存器有 32 个 GPIO 位。如果你查看其中一个`gpiochip`目录，你会看到以下内容：

```
# ls /sys/class/gpio/gpiochip96/
base  label   ngpio  power  subsystem  uevent
```

文件`base`包含寄存器中第一个 GPIO 引脚的编号，`ngpio`包含寄存器中位的数量。在这种情况下，`gpiochip96/base`是 96，`gpiochip96/ngpio`是 32，这告诉您它包含 GPIO 位 96 到 127。寄存器中最后一个 GPIO 和下一个寄存器中第一个 GPIO 之间可能存在间隙。

要从用户空间控制 GPIO 位，您首先必须从内核空间导出它，方法是将 GPIO 编号写入`/sys/class/gpio/export`。此示例显示了 GPIO 48 的过程：

```
# echo 48 > /sys/class/gpio/export
# ls /sys/class/gpio
export      gpio48    gpiochip0   gpiochip32  gpiochip64  gpiochip96  unexport
```

现在有一个新目录`gpio48`，其中包含了控制引脚所需的文件。请注意，如果 GPIO 位已被内核占用，您将无法以这种方式导出它。

目录`gpio48`包含这些文件：

```
# ls /sys/class/gpio/gpio48
active_low  direction  edge  power  subsystem   uevent  value
```

引脚最初是输入的。要将其更改为输出，请将`out`写入`direction`文件。文件`value`包含引脚的当前状态，低电平为 0，高电平为 1。如果它是输出，您可以通过向`value`写入 0 或 1 来更改状态。有时，在硬件中低电平和高电平的含义是相反的（硬件工程师喜欢做这种事情），因此将 1 写入`active_low`会反转含义，以便在`value`中将低电压报告为 1，高电压为 0。

您可以通过将 GPIO 编号写入`/sys/class/gpio/unexport`来从用户空间控制中删除 GPIO。

### 从 GPIO 处理中断

在许多情况下，可以将 GPIO 输入配置为在状态更改时生成中断，这允许您等待中断而不是在低效的软件循环中轮询。如果 GPIO 位可以生成中断，则文件`edge`存在。最初，它的值为`none`，表示它不会生成中断。要启用中断，您可以将其设置为以下值之一：

+   **rising**：上升沿中断

+   **falling**：下降沿中断

+   **both**：上升沿和下降沿中断

+   **none**：无中断（默认）

您可以使用`poll（）`函数等待中断，事件为`POLLPRI`。如果要等待 GPIO 48 上的上升沿，首先要启用中断：

```
# echo 48 > /sys/class/gpio/export
# echo rising > /sys/class/gpio/gpio48/edge
```

然后，您可以使用`poll（）`等待更改，如此代码示例所示：

```
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

int main (int argc, char *argv[])
{
  int f;
  struct pollfd poll_fds [1];
  int ret;
  char value[4];
  int n;
  f = open("/sys/class/gpio/gpio48", O_RDONLY);
  if (f == -1) {
    perror("Can't open gpio48");
    return 1;
  }
  poll_fds[0].fd = f;
  poll_fds[0].events = POLLPRI | POLLERR;
  while (1) {
    printf("Waiting\n");
    ret = poll(poll_fds, 1, -1);
    if (ret > 0) {
        n = read(f, &value, sizeof(value));
        printf("Button pressed: read %d bytes, value=%c\n",
        n, value[0]);
    }
  }
  return 0;
}
```

## LED

LED 通常是通过 GPIO 引脚控制的，但是还有另一个内核子系统，提供了更专门的控制，用于特定目的。 `leds`内核子系统增加了设置亮度的功能，如果 LED 具有该功能，并且可以处理连接方式不同于简单 GPIO 引脚的 LED。它可以配置为在事件上触发 LED，例如块设备访问或只是心跳以显示设备正在工作。在`Documentation/leds/`中有更多信息，驱动程序位于`drivers/leds/`中。

与 GPIO 一样，LED 通过`sysfs`中的接口进行控制，在`/sys/class/leds`中。LED 的名称采用`devicename:colour:function`的形式，如下所示：

```
# ls /sys/class/leds
beaglebone:green:heartbeat  beaglebone:green:usr2
beaglebone:green:mmc0       beaglebone:green:usr3
```

这显示了一个单独的 LED：

```
# ls /sys/class/leds/beaglebone:green:usr2
brightness    max_brightness  subsystem     uevent
device        power           trigger
```

`brightness`文件控制 LED 的亮度，可以是 0（关闭）到`max_brightness`（完全打开）之间的数字。如果 LED 不支持中间亮度，则任何非零值都会打开它，零会关闭它。文件`trigger`列出了触发 LED 打开的事件。触发器列表因实现而异。这是一个例子：

```
# cat /sys/class/leds/beaglebone:green:heartbeat/trigger
none mmc0 mmc1 timer oneshot [heartbeat] backlight gpio cpu0 default-on
```

当前选择的触发器显示在方括号中。您可以通过将其他触发器之一写入文件来更改它。如果您想完全通过“亮度”控制 LED，请选择`none`。如果将触发器设置为`timer`，则会出现两个额外的文件，允许您以毫秒为单位设置开启和关闭时间：

```
# echo timer > /sys/class/leds/beaglebone:green:heartbeat/trigger
# ls /sys/class/leds/beaglebone:green:heartbeat
brightness  delay_on    max_brightness  subsystem   uevent
delay_off   device      power           trigger
# cat /sys/class/leds/beaglebone:green:heartbeat/delay_on
500
# cat /sys/class/leds/beaglebone:green:heartbeat/delay_off
500
#
```

如果 LED 具有片上定时器硬件，则闪烁会在不中断 CPU 的情况下进行。

## I2C

I2C 是一种简单的低速 2 线总线，通常用于访问 SoC 板上没有的外围设备，例如显示控制器、摄像头传感器、GPIO 扩展器等。还有一个相关的标准称为 SMBus（系统管理总线），它在 PC 上发现，用于访问温度和电压传感器。SMBus 是 I2C 的子集。

I2C 是一种主从协议，主要是 SoC 上的一个或多个主控制器。从设备由制造商分配的 7 位地址 - 请阅读数据表 - 允许每个总线上最多 128 个节点，但保留了 16 个，因此实际上只允许 112 个节点。总线速度为标准模式下的 100 KHz，或者快速模式下的最高 400 KHz。该协议允许主设备和从设备之间的读写事务最多达 32 个字节。通常，第一个字节用于指定外围设备上的寄存器，其余字节是从该寄存器读取或写入的数据。

每个主控制器都有一个设备节点，例如，这个 SoC 有四个：

```
# ls -l /dev/i2c*
crw-rw---- 1 root i2c 89, 0 Jan  1 00:18 /dev/i2c-0
crw-rw---- 1 root i2c 89, 1 Jan  1 00:18 /dev/i2c-1
crw-rw---- 1 root i2c 89, 2 Jan  1 00:18 /dev/i2c-2
crw-rw---- 1 root i2c 89, 3 Jan  1 00:18 /dev/i2c-3
```

设备接口提供了一系列`ioctl`命令，用于查询主控制器并向 I2C 从设备发送`read`和`write`命令。有一个名为`i2c-tools`的软件包，它使用此接口提供基本的命令行工具来与 I2C 设备交互。工具如下：

+   `i2cdetect`：这会列出 I2C 适配器并探测总线

+   `i2cdump`：这会从 I2C 外设的所有寄存器中转储数据

+   `i2cget`：这会从 I2C 从设备读取数据

+   `i2cset`：这将数据写入 I2C 从设备

`i2c-tools`软件包在 Buildroot 和 Yocto Project 中可用，以及大多数主流发行版。只要您知道从设备的地址和协议，编写一个用户空间程序来与设备通信就很简单： 

```
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <i2c-dev.h>
#include <sys/ioctl.h>
#define I2C_ADDRESS 0x5d
#define CHIP_REVISION_REG 0x10

void main (void)
{
  int f_i2c;
  int val;

  /* Open the adapter and set the address of the I2C device */
  f_i2c = open ("/dev/i2c-1", O_RDWR);
  ioctl (f_i2c, I2C_SLAVE, I2C_ADDRESS);

  /* Read 16-bits of data from a register */
  val = i2c_smbus_read_word_data(f, CHIP_REVISION_REG);
  printf ("Sensor chip revision %d\n", val);
  close (f_i2c);
}
```

请注意，标头`i2c-dev.h`是来自`i2c-tools`软件包的标头，而不是来自 Linux 内核标头的标头。 `i2c_smbus_read_word_data（）`函数是在`i2c-dev.h`中内联编写的。

有关 I2C 在`Documentation/i2c/dev-interface`中的 Linux 实现的更多信息。主控制器驱动程序位于`drivers/i2c/busses`中。

## SPI

串行外围接口总线类似于 I2C，但速度更快，高达低 MHz。该接口使用四根线，具有独立的发送和接收线，这使得它可以全双工操作。总线上的每个芯片都使用专用的芯片选择线进行选择。它通常用于连接触摸屏传感器、显示控制器和串行 NOR 闪存设备。

与 I2C 一样，它是一种主从协议，大多数 SoC 实现了一个或多个主机控制器。有一个通用的 SPI 设备驱动程序，您可以通过内核配置`CONFIG_SPI_SPIDEV`启用它。它为每个 SPI 控制器创建一个设备节点，允许您从用户空间访问 SPI 芯片。设备节点的名称为`spidev[bus].[chip select]`。

```
# ls -l /dev/spi*
crw-rw---- 1 root root 153, 0 Jan  1 00:29 /dev/spidev1.0
```

有关使用`spidev`接口的示例，请参考`Documentation/spi`中的示例代码。

# 编写内核设备驱动程序

最终，当您耗尽了上述所有用户空间选项时，您会发现自己不得不编写一个设备驱动程序来访问连接到您的设备的硬件。虽然现在不是深入细节的时候，但值得考虑一下选择。字符驱动程序是最灵活的，应该可以满足 90%的需求；如果您正在使用网络接口，网络设备也适用；块设备用于大容量存储。编写内核驱动程序的任务是复杂的，超出了本书的范围。在本节末尾有一些参考资料，可以帮助您一路前行。在本节中，我想概述与驱动程序交互的可用选项——这通常不是涵盖的主题——并向您展示驱动程序的基本结构。

## 设计字符设备接口

主要的字符设备接口基于字节流，就像串口一样。然而，许多设备并不符合这个描述：例如，机器人手臂的控制器需要移动和旋转每个关节的功能。幸运的是，与设备驱动程序进行通信的其他方法不仅仅是`read(2)`和`write(2)`。

+   `ioctl`：`ioctl`函数允许您向驱动程序传递两个参数，这两个参数可以有任何您喜欢的含义。按照惯例，第一个参数是一个命令，用于选择驱动程序中的几个函数中的一个，第二个参数是一个指向结构体的指针，该结构体用作输入和输出参数的容器。这是一个空白画布，允许您设计任何您喜欢的程序接口，当驱动程序和应用程序紧密链接并由同一团队编写时，这是非常常见的。然而，在内核中，`ioctl`已经被弃用，您会发现很难让任何具有新`ioctl`用法的驱动程序被上游接受。内核维护人员不喜欢`ioctl`，因为它使内核代码和应用程序代码过于相互依赖，并且很难在内核版本和架构之间保持两者同步。

+   `sysfs`：这是现在的首选方式，一个很好的例子是之前描述的 GPIO 接口。其优点是它是自我记录的，只要您为文件选择描述性名称。它也是可脚本化的，因为文件内容是 ASCII 字符串。另一方面，每个文件要求包含一个单一值，这使得如果您需要同时更改多个值，就很难实现原子性。例如，如果您想设置两个值然后启动一个操作，您需要写入三个文件：两个用于输入，第三个用于触发操作。即使这样，也不能保证其他两个文件没有被其他人更改。相反，`ioctl`通过单个函数调用中的结构传递所有参数。

+   `mmap`：您可以通过将内核内存映射到用户空间来直接访问内核缓冲区和硬件寄存器，绕过内核。您可能仍然需要一些内核代码来处理中断和 DMA。有一个封装这个想法的子系统，称为`uio`，即用户 I/O。在`Documentation/DocBook/uio-howto`中有更多文档，`drivers/uio`中有示例驱动程序。

+   `sigio`：您可以使用内核函数`kill_fasync()`从驱动程序发送信号，以通知应用程序事件，例如输入准备就绪或接收到中断。按照惯例，使用信号 SIGIO，但它可以是任何人。您可以在 UIO 驱动程序`drivers/uio/uio.c`和 RTC 驱动程序`drivers/char/rtc.c`中看到一些示例。主要问题是编写可靠的信号处理程序很困难，因此它仍然是一个很少使用的设施。

+   `debugfs`：这是另一个伪文件系统，它将内核数据表示为文件和目录，类似于`proc`和`sysfs`。主要区别在于`debugfs`不得包含系统正常操作所需的信息；它仅用于调试和跟踪信息。它被挂载为`mount -t debugfs debug /sys/kernel/debug`。

内核文档中有关`debugfs`的良好描述，`Documentation/filesystems/debugfs.txt`。

+   `proc`：`proc`文件系统已被弃用，除非它与进程有关，这是文件系统的最初预期目的。但是，您可以使用`proc`发布您选择的任何信息。并且，与`sysfs`和`debugfs`不同，它可用于非 GPL 模块。

+   `netlink`：这是一个套接字协议族。`AF_NETLINK`创建一个将内核空间链接到用户空间的套接字。最初创建它是为了使网络工具能够与 Linux 网络代码通信，以访问路由表和其他详细信息。udev 也使用它将事件从内核传递给 udev 守护程序。一般设备驱动程序中很少使用它。

内核源代码中有许多先前文件系统的示例，您可以为驱动程序代码设计非常有趣的接口。唯一的普遍规则是*最少惊讶原则*。换句话说，使用您的驱动程序的应用程序编写人员应该发现一切都以逻辑方式工作，没有怪癖或奇怪之处。

## 设备驱动程序的解剖

现在是时候通过查看简单设备驱动程序的代码来汇总一些线索了。

提供了名为`dummy`的设备驱动程序的源代码，该驱动程序创建了四个通过`/dev/dummy0`到`/dev/dummy3`访问的设备。这是驱动程序的完整代码：

```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#define DEVICE_NAME "dummy"
#define MAJOR_NUM 42
#define NUM_DEVICES 4

static struct class *dummy_class;
static int dummy_open(struct inode *inode, struct file *file)
{
  pr_info("%s\n", __func__);
  return 0;
}

static int dummy_release(struct inode *inode, struct file *file)
{
  pr_info("%s\n", __func__);
  return 0;
}

static ssize_t dummy_read(struct file *file,
  char *buffer, size_t length, loff_t * offset)
{
  pr_info("%s %u\n", __func__, length);
  return 0;
}

static ssize_t dummy_write(struct file *file,
  const char *buffer, size_t length, loff_t * offset)
{
  pr_info("%s %u\n", __func__, length);
  return length;
}

struct file_operations dummy_fops = {
  .owner = THIS_MODULE,
  .open = dummy_open,
  .release = dummy_release,
  .read = dummy_read,
  .write = dummy_write,
};

int __init dummy_init(void)
{
  int ret;
  int i;
  printk("Dummy loaded\n");
  ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &dummy_fops);
  if (ret != 0)
    return ret;
  dummy_class = class_create(THIS_MODULE, DEVICE_NAME);
  for (i = 0; i < NUM_DEVICES; i++) {
    device_create(dummy_class, NULL,
    MKDEV(MAJOR_NUM, i), NULL, "dummy%d", i);
  }
  return 0;
}

void __exit dummy_exit(void)
{
  int i;
  for (i = 0; i < NUM_DEVICES; i++) {
    device_destroy(dummy_class, MKDEV(MAJOR_NUM, i));
  }
  class_destroy(dummy_class);
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
  printk("Dummy unloaded\n");
}

module_init(dummy_init);
module_exit(dummy_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Simmonds");
MODULE_DESCRIPTION("A dummy driver");
```

代码末尾的宏`module_init`和`module_exit`指定了在加载和卸载模块时要调用的函数。其他三个添加了有关模块的一些基本信息，可以使用`modinfo`命令从编译的内核模块中检索。

模块加载时，将调用`dummy_init()`函数。

调用`register_chrdev`可以看到它何时成为一个字符设备，传递一个指向包含驱动程序实现的四个函数指针的`struct file_operations`指针。虽然`register_chrdev`告诉内核有一个主编号为 42 的驱动程序，但它并没有说明驱动程序的类型，因此它不会在`/sys/class`中创建条目。没有在`/sys/class`中的条目，设备管理器无法创建设备节点。因此，代码的下几行创建了一个设备类`dummy`，以及该类的四个名为`dummy0`到`dummy3`的设备。结果是`/sys/class/dummy`目录，其中包含`dummy0`到`dummy3`子目录，每个子目录中都包含一个名为`dev`的文件，其中包含设备的主要和次要编号。这就是设备管理器创建设备节点`/dev/dummy0`到`/dev/dummy3`所需的全部内容。

`exit`函数必须释放`init`函数声明的资源，这里指的是释放设备类和主要编号。

该驱动程序的文件操作由`dummy_open()`，`dummy_read()`，`dummy_write()`和`dummy_release()`实现，并在用户空间程序调用`open(2)`，`read(2)`，`write(2)`和`close(2)`时调用。 它们只是打印内核消息，以便您可以看到它们被调用。 您可以使用`echo`命令从命令行演示这一点：

```
# echo hello > /dev/dummy0

[ 6479.741192] dummy_open
[ 6479.742505] dummy_write 6
[ 6479.743008] dummy_release
```

在这种情况下，消息出现是因为我已登录到控制台，默认情况下内核消息会打印到控制台。

该驱动程序的完整源代码不到 100 行，但足以说明设备节点和驱动程序代码之间的链接方式，说明设备类是如何创建的，允许设备管理器在加载驱动程序时自动创建设备节点，以及数据如何在用户空间和内核空间之间移动。 接下来，您需要构建它。

### 编译和加载

此时，您有一些驱动程序代码，希望在目标系统上进行编译和测试。 您可以将其复制到内核源树中并修改 makefile 以构建它，或者您可以将其编译为树外模块。 让我们首先从树外构建开始。

您需要一个简单的 makefile，该 makefile 使用内核构建系统来完成艰苦的工作：

```
LINUXDIR := $(HOME)/MELP/build/linux

obj-m := dummy.o
all:
        make ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- \
          -C $(LINUXDIR) M=$(shell pwd)
clean:
        make -C $(LINUXDIR) M=$(shell pwd) clean
```

将`LINUXDIR`设置为您将在目标设备上运行模块的内核目录。 代码`obj-m：= dummy.o`将调用内核构建规则，以获取源文件`dummy.c`并创建内核模块`dummy.ko`。 请注意，内核模块在内核发布和配置之间不具有二进制兼容性，该模块只能在其编译的内核上加载。

构建的最终结果是内核`dummy.ko`，您可以将其复制到目标并按照下一节中所示加载。

如果要在内核源树中构建驱动程序，该过程非常简单。 选择适合您的驱动程序类型的目录。 该驱动程序是基本字符设备，因此我将`dummy.c`放在`drivers/char`中。 然后，编辑该目录中的 makefile，并添加一行以无条件地构建驱动程序作为模块，如下所示：

```
obj-m  += dummy.o
```

或者将以下行添加到无条件构建为内置：

```
obj-y   += dummy.o
```

如果要使驱动程序可选，可以在`Kconfig`文件中添加菜单选项，并根据配置选项进行条件编译，就像我在第四章中描述的那样，*移植和配置内核*，描述内核配置时。

# 加载内核模块

您可以使用简单的`insmod`，`lsmod`和`rmmod`命令加载，卸载和列出模块。 这里显示了加载虚拟驱动程序：

```
# insmod /lib/modules/4.1.10/kernel/drivers/dummy.ko
# lsmod
dummy 1248 0 - Live 0xbf009000 (O)
# rmmod dummy
```

如果模块放置在`/lib/modules/<kernel release>`中的子目录中，例如示例中，可以使用`depmod`命令创建模块依赖数据库：

```
# depmod -a
# ls /lib/modules/4.1.10/
kernel               modules.builtin.bin  modules.order
modules.alias        modules.dep          modules.softdep
modules.alias.bin    modules.dep.bin      modules.symbols
modules.builtin      modules.devname      modules.symbols.bin
```

`module.*`文件中的信息由`modprobe`命令使用，以按名称而不是完整路径定位模块。 `modprobe`还具有许多其他功能，这些功能在手册中有描述。

模块依赖信息也被设备管理器使用，特别是`udev`。 例如，当检测到新硬件时，例如新的 USB 设备，`udevd`守护程序会被警报，并从硬件中读取供应商和产品 ID。 `udevd`扫描模块依赖文件，寻找已注册这些 ID 的模块。 如果找到一个，它将使用`modprobe`加载。

# 发现硬件配置

虚拟驱动程序演示了设备驱动程序的结构，但它缺乏与真实硬件的交互，因为它只操作内存结构。 设备驱动程序通常用于与硬件交互，其中的一部分是能够首先发现硬件，要记住的是在不同配置中它可能位于不同的地址。

在某些情况下，硬件本身提供信息。可发现总线上的设备（如 PCI 或 USB）具有查询模式，该模式返回资源需求和唯一标识符。内核将标识符和可能的其他特征与设备驱动程序进行匹配，并将它们配对。

然而，大多数 SoC 上的硬件块都没有这样的标识符。您必须以设备树或称为平台数据的 C 结构的形式提供信息。

在 Linux 的标准驱动程序模型中，设备驱动程序会向适当的子系统注册自己：PCI、USB、开放固件（设备树）、平台设备等。注册包括标识符和称为探测函数的回调函数，如果硬件的 ID 与驱动程序的 ID 匹配，则会调用该函数。对于 PCI 和 USB，ID 基于设备的供应商和产品 ID，对于设备树和平台设备，它是一个名称（ASCII 字符串）。

## 设备树

我在第三章中向您介绍了设备树，*关于引导程序的一切*。在这里，我想向您展示 Linux 设备驱动程序如何与这些信息连接。

作为示例，我将使用 ARM Versatile 板，`arch/arm/boot/dts/versatile-ab.dts`，其中以太网适配器在此处定义：

```
net@10010000 {
  compatible = "smsc,lan91c111";
  reg = <0x10010000 0x10000>;
  interrupts = <25>;
};
```

## 平台数据

在没有设备树支持的情况下，还有一种使用 C 结构描述硬件的备用方法，称为平台数据。

每个硬件都由`struct platform_device`描述，其中包含名称和资源数组的指针。资源的类型由标志确定，其中包括以下内容：

+   `IORESOURCE_MEM`：内存区域的物理地址

+   `IORESOURCE_IO`：IO 寄存器的物理地址或端口号

+   `IORESOURCE_IRQ`：中断号

以下是从`arch/arm/mach-versatile/core.c`中获取的以太网控制器的平台数据示例，已经编辑以提高清晰度：

```
#define VERSATILE_ETH_BASE     0x10010000
#define IRQ_ETH                25
static struct resource smc91x_resources[] = {
  [0] = {
    .start          = VERSATILE_ETH_BASE,
    .end            = VERSATILE_ETH_BASE + SZ_64K - 1,
    .flags          = IORESOURCE_MEM,
  },
  [1] = {
    .start          = IRQ_ETH,
    .end            = IRQ_ETH,
    .flags          = IORESOURCE_IRQ,
  },
};
static struct platform_device smc91x_device = {
  .name           = "smc91x",
  .id             = 0,
  .num_resources  = ARRAY_SIZE(smc91x_resources),
  .resource       = smc91x_resources,
};
```

它有一个 64 KiB 的内存区域和一个中断。平台数据必须在初始化板时向内核注册：

```
void __init versatile_init(void)
{
  platform_device_register(&versatile_flash_device);
  platform_device_register(&versatile_i2c_device);
  platform_device_register(&smc91x_device);
  [ ...]
```

## 将硬件与设备驱动程序连接起来

在前面的部分中，您已经看到了以设备树和平台数据描述以太网适配器的方式。相应的驱动程序代码位于`drivers/net/ethernet/smsc/smc91x.c`中，它可以与设备树和平台数据一起使用。以下是初始化代码，再次编辑以提高清晰度：

```
static const struct of_device_id smc91x_match[] = {
  { .compatible = "smsc,lan91c94", },
  { .compatible = "smsc,lan91c111", },
  {},
};
MODULE_DEVICE_TABLE(of, smc91x_match);
static struct platform_driver smc_driver = {
  .probe          = smc_drv_probe,
  .remove         = smc_drv_remove,
  .driver         = {
    .name   = "smc91x",
    .of_match_table = of_match_ptr(smc91x_match),
  },
};
static int __init smc_driver_init(void)
{
  return platform_driver_register(&smc_driver);
}
static void __exit smc_driver_exit(void) \
{
  platform_driver_unregister(&smc_driver);
}
module_init(smc_driver_init);
module_exit(smc_driver_exit);
```

当驱动程序初始化时，它调用`platform_driver_register()`，指向`struct platform_driver`，其中包含对探测函数的回调，驱动程序名称`smc91x`，以及对`struct of_device_id`的指针。

如果此驱动程序已由设备树配置，内核将在设备树节点中的`compatible`属性和兼容结构元素指向的字符串之间寻找匹配项。对于每个匹配项，它都会调用`probe`函数。

另一方面，如果通过平台数据配置，`probe`函数将针对`driver.name`指向的每个匹配项进行调用。

`probe`函数提取有关接口的信息：

```
static int smc_drv_probe(struct platform_device *pdev)
{
  struct smc91x_platdata *pd = dev_get_platdata(&pdev->dev);
  const struct of_device_id *match = NULL;
  struct resource *res, *ires;
  int irq;

  res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
  ires = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
  [...]
  addr = ioremap(res->start, SMC_IO_EXTENT);
  irq = ires->start;
  [...]
}
```

调用`platform_get_resource()`从设备树或平台数据中提取内存和`irq`信息。驱动程序负责映射内存并安装中断处理程序。第三个参数在前面两种情况下都是零，如果有多个特定类型的资源，则会起作用。

设备树允许您配置的不仅仅是基本内存范围和中断。在`probe`函数中有一段代码，用于从设备树中提取可选参数。在这个片段中，它获取了`register-io-width`属性：

```
match = of_match_device(of_match_ptr(smc91x_match), &pdev->dev);
if (match) {
  struct device_node *np = pdev->dev.of_node;
  u32 val;
  [...]
  of_property_read_u32(np, "reg-io-width", &val);
  [...]
}
```

对于大多数驱动程序，特定的绑定都记录在`Documentation/devicetree/bindings`中。对于这个特定的驱动程序，信息在`Documentation/devicetree/bindings/net/smsc911x.txt`中。

这里要记住的主要事情是，驱动程序应该注册一个`probe`函数和足够的信息，以便内核在找到与其了解的硬件匹配时调用`probe`。设备树描述的硬件与设备驱动程序之间的链接是通过`compatible`属性实现的。平台数据与驱动程序之间的链接是通过名称实现的。

# 额外阅读

以下资源提供了关于本章介绍的主题的更多信息：

+   *Linux Device Drivers, 4th edition*，作者*Jessica McKellar*，*Alessandro Rubini*，*Jonathan Corbet*和*Greg Kroah-Hartman*。在撰写本文时尚未出版，但如果它像前作一样好，那将是一个不错的选择。但是，第三版已经过时，不建议阅读。

+   *Linux Kernel Development, 3rd edition*，作者*Robert Love*，*Addison-Wesley* Professional; (July 2, 2010) ISBN-10: 0672329468

+   *Linux Weekly News*，[www.lwn.net](https://www.lwn.net)。

# 摘要

设备驱动程序的工作是处理设备，通常是物理硬件，但有时也是虚拟接口，并以一种一致和有用的方式呈现给更高级别。Linux 设备驱动程序分为三大类：字符、块和网络。在这三种中，字符驱动程序接口是最灵活的，因此也是最常见的。Linux 驱动程序适用于一个称为驱动模型的框架，通过`sysfs`公开。几乎所有设备和驱动程序的状态都可以在`/sys`中看到。

每个嵌入式系统都有自己独特的硬件接口和要求。Linux 为大多数标准接口提供了驱动程序，通过选择正确的内核配置，您可以使设备非常快速地运行起来。这样，您就可以处理非标准组件，需要添加自己的设备支持。

在某些情况下，您可以通过使用通用的 GPIO、I2C 等驱动程序并编写用户空间代码来避开问题。我建议这作为一个起点，因为这样可以让您有机会熟悉硬件，而不必编写内核代码。编写内核驱动程序并不特别困难，但是如果您这样做，需要小心编码，以免影响系统的稳定性。

我已经谈到了编写内核驱动程序代码：如果您选择这条路线，您将不可避免地想知道如何检查它是否正常工作并检测任何错误。我将在第十二章中涵盖这个主题，*使用 GDB 进行调试*。

下一章将全面介绍用户空间初始化以及`init`程序的不同选项，从简单的 BusyBox 到复杂的 systemd。


# 第九章：启动- init 程序

我在第四章中看到了内核如何引导到启动第一个程序`init`的点，在第五章中，*构建根文件系统*和第六章中，*选择构建系统*，我看了创建不同复杂性的根文件系统，其中都包含了`init`程序。现在是时候更详细地看看`init`程序，并发现它对系统的重要性。

`init`有许多可能的实现。我将在本章中描述三种主要的实现：BusyBox `init`，System V `init`和`systemd`。对于每种实现，我将概述其工作原理和最适合的系统类型。其中一部分是在复杂性和灵活性之间取得平衡。

# 内核引导后

我们在第四章中看到了*移植和配置内核*，内核引导代码如何寻找根文件系统，要么是`initramfs`，要么是内核命令行上指定的文件系统`root=`，然后执行一个程序，默认情况下是`initramfs`的`/init`，常规文件系统的`/sbin/init`。`init`程序具有根特权，并且由于它是第一个运行的进程，它具有进程 ID（`PID`）为 1。如果由于某种原因`init`无法启动，内核将会恐慌。

`init`程序是所有其他进程的祖先，如`pstree`命令所示，它是大多数发行版中`psmisc`软件包的一部分：

```
# pstree -gn

init(1)-+-syslogd(63)
        |-klogd(66)
        |-dropbear(99)
        `-sh(100)---pstree(109)
```

`init`程序的工作是控制系统并使其运行。它可能只是一个运行 shell 脚本的 shell 命令-在第五章的开头有一个示例，*构建根文件系统*—但在大多数情况下，您将使用专用的`init`守护程序。它必须执行的任务如下：

+   在启动时，它启动守护程序，配置系统参数和其他必要的东西，使系统进入工作状态。

+   可选地，它启动守护程序，比如在允许登录 shell 的终端上启动`getty`。

+   它接管因其直接父进程终止而变成孤儿的进程，并且没有其他进程在线程组中。

+   它通过捕获信号`SIGCHLD`并收集返回值来响应`init`的任何直接子进程的终止，以防止它们变成僵尸进程。我将在第十章中更多地讨论僵尸进程，*了解进程和线程*。

+   可选地，它重新启动那些已经终止的守护进程。

+   它处理系统关闭。

换句话说，`init`管理系统的生命周期，从启动到关闭。目前的想法是`init`很适合处理其他运行时事件，比如新硬件和模块的加载和卸载。这就是`systemd`的作用。

# 介绍 init 程序

在嵌入式设备中，您最有可能遇到的三种`init`程序是 BusyBox `init`，System V `init`和`systemd`。Buildroot 有选项可以构建所有三种，其中 BusyBox `init`是默认选项。Yocto Project 允许您在 System V `init`和`systemd`之间进行选择，System `V init`是默认选项。

以下表格提供了比较这三种程序的一些指标：

| | BusyBox init | System V init | systemd |
| --- | --- | --- | --- |
| --- | --- | --- | --- |
| 复杂性 | 低 | 中等 | 高 |
| 启动速度 | 快 | 慢 | 中等 |
| 所需的 shell | ash | ash 或 bash | 无 |
| 可执行文件数量 | 0 | 4 | 50(*) |
| libc | 任何 | 任何 | glibc |
| 大小（MiB） | 0 | 0.1 | 34(*) |

(*)基于`system`的 Buildroot 配置。

总的来说，从 BusyBox `init`到`systemd`，灵活性和复杂性都有所增加。

# BusyBox init

BusyBox 有一个最小的`init`程序，使用配置文件`/etc/inittab`来定义在启动时启动程序的规则，并在关闭时停止它们。通常，实际工作是由 shell 脚本完成的，按照惯例，这些脚本放在`/etc/init.d`目录中。

`init`首先通过读取配置文件`/etc/inittab`来开始。其中包含要运行的程序列表，每行一个，格式如下：

`<id>::<action>:<program>`

这些参数的作用如下：

+   `id`：命令的控制终端

+   `action`：运行此命令的条件，如下一段所示

+   `program`：要运行的程序

以下是操作步骤：

+   `sysinit`：当`init`启动时运行程序，先于其他类型的操作。

+   `respawn`：运行程序并在其终止时重新启动。用于将程序作为守护进程运行。

+   `askfirst`：与`respawn`相同，但在控制台上打印消息**请按 Enter 键激活此控制台**，并在按下*Enter*后运行程序。用于在终端上启动交互式 shell 而无需提示用户名或密码。

+   `once`：运行程序一次，但如果终止则不尝试重新启动。

+   `wait`：运行程序并等待其完成。

+   `restart`：当`init`接收到信号`SIGHUP`时运行程序，表示应重新加载`inittab`文件。

+   `ctrlaltdel`：当`init`接收到信号`SIGINT`时运行程序，通常是在控制台上按下*Ctrl* + *Alt* + *Del*的结果。

+   `shutdown`：当`init`关闭时运行程序。

以下是一个小例子，它挂载`proc`和`sysfs`，并在串行接口上运行 shell：

```
null::sysinit:/bin/mount -t proc proc /proc
null::sysinit:/bin/mount -t sysfs sysfs /sys
console::askfirst:-/bin/sh
```

对于简单的项目，您希望启动少量守护进程并可能在串行终端上启动登录 shell，手动编写脚本很容易，如果您正在创建一个**RYO**（**roll your own**）嵌入式 Linux，这是合适的。但是，随着需要配置的内容增加，您会发现手写的`init`脚本很快变得难以维护。它们往往不太模块化，因此每次添加新组件时都需要更新。

## Buildroot init 脚本

多年来，Buildroot 一直在有效地使用 BusyBox `init`。Buildroot 在`/etc/init.d`中有两个脚本，名为`rcS`和`rcK`。第一个在启动时启动，并遍历所有以大写`S`开头后跟两位数字的脚本，并按数字顺序运行它们。这些是启动脚本。`rcK`脚本在关闭时运行，并遍历所有以大写`K`开头后跟两位数字的脚本，并按数字顺序运行它们。这些是关闭脚本。

有了这个，Buildroot 软件包可以轻松提供自己的启动和关闭脚本，使用两位数字来规定它们应该运行的顺序，因此系统变得可扩展。如果您正在使用 Buildroot，这是透明的。如果没有，您可以将其用作编写自己的 BusyBox `init`脚本的模型。

# System V init

这个`init`程序受 UNIX System V 的启发，可以追溯到 20 世纪 80 年代中期。在 Linux 发行版中最常见的版本最初是由 Miquel van Smoorenburg 编写的。直到最近，它被认为是引导 Linux 的方式，显然包括嵌入式系统，而 BusyBox `init`是 System V `init`的精简版本。

与 BusyBox `init`相比，System V `init`有两个优点。首先，引导脚本以众所周知的模块化格式编写，使得在构建时或运行时轻松添加新包。其次，它具有运行级别的概念，允许通过从一个运行级别切换到另一个运行级别来一次性启动或停止一组程序。

有从 0 到 6 编号的 8 个运行级别，另外还有 S：

+   **S**：单用户模式

+   **0**：关闭系统

+   **1 至 5**：通用使用

+   **6**：重新启动系统

级别 1 到 5 可以随您的意愿使用。在桌面 Linux 发行版中，它们通常分配如下：

+   **1**：单用户

+   **2**：无需网络配置的多用户

+   **3**：带网络配置的多用户

+   **4**：未使用

+   **5**：带图形登录的多用户

`init`程序启动由`/etc/inittab`中的`initdefault`行给出的默认`runlevel`。您可以使用`telinit [runlevel]`命令在运行时更改运行级别，该命令向`init`发送消息。您可以使用`runlevel`命令找到当前运行级别和先前的运行级别。以下是一个示例：

```
# runlevel
N 5
# telinit 3
INIT: Switching to runlevel: 3
# runlevel
5 3
```

在第一行上，`runlevel`的输出是`N 5`，这意味着没有先前的运行级别，因为自启动以来`runlevel`没有改变，当前的`runlevel`是`5`。在改变`runlevel`后，输出是`5 3`，显示已从`5`转换到`3`。`halt`和`reboot`命令分别切换到`0`和`6`的运行级别。您可以通过在内核命令行上给出不同的单个数字`0`到`6`，或者`S`表示单用户模式，来覆盖默认的`runlevel`。例如，要强制`runlevel`为单用户，您可以在内核命令行上附加`S`，看起来像这样：

```
console=ttyAMA0 root=/dev/mmcblk1p2 S

```

每个运行级别都有一些停止事物的脚本，称为`kill`脚本，以及另一组启动事物的脚本，称为`start`脚本。进入新的`runlevel`时，`init`首先运行`kill`脚本，然后运行`start`脚本。在新的`runlevel`中运行守护进程，如果它们既没有`start`脚本也没有`kill`脚本，那么它们将收到`SIGTERM`信号。换句话说，切换`runlevel`的默认操作是终止守护进程，除非另有指示。

事实上，在嵌入式 Linux 中并不经常使用运行级别：大多数设备只是启动到默认的`runlevel`并保持在那里。我有一种感觉，部分原因是大多数人并不知道它们。

### 提示

运行级别是在不同模式之间切换的一种简单方便的方式，例如，从生产模式切换到维护模式。

System V `init`是 Buildroot 和 Yocto Project 的一个选项。在这两种情况下，init 脚本已经被剥离了任何 bash 特定的内容，因此它们可以与 BusyBox ash shell 一起工作。但是，Buildroot 通过用 SystemV `init`替换 BusyBox `init`程序并添加模仿 BusyBox 行为的`inittab`来作弊。Buildroot 不实现运行级别，除非切换到级别 0 或 6 会停止或重新启动系统。

接下来，让我们看一些细节。以下示例取自 Yocto Project 的 fido 版本。其他发行版可能以稍有不同的方式实现`init`脚本。

## inittab

`init`程序首先读取`/etc/inttab`，其中包含定义每个`runlevel`发生的事情的条目。格式是我在前一节中描述的 BusyBox `inittab`的扩展版本，这并不奇怪，因为 BusyBox 首先从 System V 借鉴了它！

`inittab`中每行的格式如下：

```
id:runlevels:action:process
```

字段如下所示：

+   `id`：最多四个字符的唯一标识符。

+   `runlevels`：应执行此条目的运行级别。（在 BusyBox `inittab`中留空）

+   `action`：以下给出的关键字之一。

+   `process`：要运行的命令。

这些操作与 BusyBox `init`的操作相同：`sysinit`，`respawn`，`once`，`wait`，`restart`，`ctrlaltdel`和`shutdown`。但是，System V `init`没有`askfirst`，这是 BusyBox 特有的。

例如，这是 Yocto Project 目标 core-image-minimal 提供的完整的`inttab`：

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
AMA0:12345:respawn:/sbin/getty 115200 ttyAMA0
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

第一个条目`id:5:initdefault`将默认的`runlevel`设置为`5`。接下来的条目`si::sysinit:/etc/init.d/rcS`在启动时运行脚本`rcS`。稍后会有更多关于这个的内容。稍后，有一组六个条目，以`l0:0:wait:/etc/init.d/rc 0`开头。它们在运行级别发生变化时运行脚本`/etc/init.d/rc`：这个脚本负责处理`start`和`kill`脚本。还有一个运行级别`S`的条目，运行单用户登录程序。

在`inittab`的末尾，有两个条目，当进入运行级别 1 到 5 时，它们运行一个`getty`守护进程在设备`/dev/ttyAMA0`和`/dev/tty1`上生成登录提示，从而允许你登录并获得交互式 shell：

```
AMA0:12345:respawn:/sbin/getty 115200 ttyAMA0
1:2345:respawn:/sbin/getty 38400 tty1
```

设备`ttyAMA0`是我们用 QEMU 模拟的 ARM Versatile 板上的串行控制台，对于其他开发板来说可能会有所不同。Tty1 是一个虚拟控制台，通常映射到图形屏幕，如果你的内核使用了`CONFIG_FRAMEBUFFER_CONSOLE`或`VGA_CONSOLE`。桌面 Linux 通常在虚拟终端 1 到 6 上生成六个`getty`进程，你可以用组合键*Ctrl* + *Alt* + *F1*到*Ctrl* + *Alt* + *F6*来选择，虚拟终端 7 保留给图形屏幕。嵌入式设备上很少使用虚拟终端。

由`sysinit`条目运行的脚本`/etc/init.d/rcS`几乎只是进入运行级别`S`：

```
#!/bin/sh

[...]
exec /etc/init.d/rc S
```

因此，第一个进入的运行级别是`S`，然后是默认的`runlevel` `5`。请注意，`runlevel` `S`不会被记录，也不会被`runlevel`命令显示为先前的运行级别。

## init.d 脚本

需要响应`runlevel`变化的每个组件都有一个在`/etc/init.d`中执行该变化的脚本。脚本应该期望两个参数：`start`和`stop`。稍后我会举一个例子。

`runlevel`处理脚本`/etc/init.d/rc`以`runlevel`作为参数进行切换。对于每个`runlevel`，都有一个名为`rc<runlevel>.d`的目录：

```
# ls -d /etc/rc*
/etc/rc0.d  /etc/rc2.d  /etc/rc4.d  /etc/rc6.d
/etc/rc1.d  /etc/rc3.d  /etc/rc5.d  /etc/rcS.d
```

在那里你会找到一组以大写`S`开头后跟两位数字的脚本，你也可能会找到以大写`K`开头的脚本。这些是`start`和`kill`脚本：Buildroot 使用了相同的想法，从这里借鉴过来：

```
# ls /etc/rc5.d
S01networking   S20hwclock.sh   S99rmnologin.sh S99stop-bootlogd
S15mountnfs.sh  S20syslog
```

实际上，这些是指向`init.d`中适当脚本的符号链接。`rc`脚本首先运行所有以`K`开头的脚本，添加`stop`参数，然后运行以`S`开头的脚本，添加`start`参数。再次强调，两位数字代码用于指定脚本应该运行的顺序。

## 添加新的守护进程

假设你有一个名为`simpleserver`的程序，它是作为传统的 Unix 守护进程编写的，换句话说，它会分叉并在后台运行。你将需要一个像这样的`init.d`脚本：

```
#! /bin/sh

case "$1" in
  start)
    echo "Starting simpelserver"
    start-stop-daemon -S -n simpleserver -a /usr/bin/simpleserver
    ;;
  stop)
    echo "Stopping simpleserver"
    start-stop-daemon -K -n simpleserver
    ;;
  *)
    echo "Usage: $0 {start|stop}"
  exit 1
esac

exit 0
```

`Start-stop-daemon`是一个帮助函数，使得更容易操作后台进程。它最初来自 Debian 安装程序包`dpkg`，但大多数嵌入式系统使用的是 BusyBox 中的版本。它使用`-S`参数启动守护进程，确保任何时候都不会有多个实例在运行，并使用`-K`按名称查找守护进程，并默认发送信号`SIGTERM`。将此脚本放在`/etc/init.d/simpleserver`中并使其可执行。

然后，从你想要从中运行这个程序的每个运行级别添加`symlinks`，在这种情况下，只有默认的`runlevel`，`5`：

```
# cd /etc/init.d/rc5.d
# ln -s ../init.d/simpleserver S99simpleserver
```

数字`99`表示这将是最后启动的程序之一。请记住，可能会有其他以`S99`开头的链接，如果是这样，`rc`脚本将按照词法顺序运行它们。

在嵌入式设备中很少需要过多担心关机操作，但如果有需要做的事情，可以在 0 和 6 级别添加`kill symlinks`：

```
# cd /etc/init.d/rc0.d
# ln -s ../init.d/simpleserver K01simpleserver
# cd /etc/init.d/rc6.d
# ln -s ../init.d/simpleserver K01simpleserver
```

## 启动和停止服务

您可以通过直接调用`/etc/init.d`中的脚本与之交互，例如，控制`syslogd`和`klogd`守护进程的`syslog`脚本：

```
# /etc/init.d/syslog --help
Usage: syslog { start | stop | restart }

# /etc/init.d/syslog stop
Stopping syslogd/klogd: stopped syslogd (pid 198)
stopped klogd (pid 201)
done

# /etc/init.d/syslog start
Starting syslogd/klogd: done
```

所有脚本都实现了`start`和`stop`，并且应该实现`help`。有些还实现了`status`，它会告诉您服务是否正在运行。仍在使用 System V `init`的主流发行版有一个名为 service 的命令，用于启动和停止服务，并隐藏直接调用脚本的细节。

# systemd

`systemd`将自己定义为系统和服务管理器。该项目由 Lennart Poettering 和 Kay Sievers 于 2010 年发起，旨在创建一套集成的工具，用于管理 Linux 系统，包括`init`守护程序。它还包括设备管理（`udev`）和日志记录等内容。有人会说它不仅仅是一个`init`程序，它是一种生活方式。它是最先进的，仍在快速发展。`systemd`在桌面和服务器 Linux 发行版上很常见，并且在嵌入式 Linux 系统上也变得越来越受欢迎，特别是在更复杂的设备上。那么，它比 System V `init`在嵌入式系统上更好在哪里呢？

+   配置更简单更合乎逻辑（一旦你理解了它），而不是 System V `init`有时候复杂的 shell 脚本，`systemd`有单元配置文件来设置参数

+   服务之间有明确的依赖关系，而不是仅仅设置脚本运行顺序的两位数代码

+   为每个服务设置权限和资源限制很容易，这对安全性很重要

+   `systemd`可以监视服务并在需要时重新启动它们

+   每个服务和`systemd`本身都有看门狗

+   服务并行启动，减少启动时间

在这里，不可能也不合适对`systemd`进行完整描述。与 System V `init`一样，我将专注于嵌入式用例，并以 Yocto Fido 生成的配置为例，该配置具有`systemd`版本 219。我将进行快速概述，然后向您展示一些具体示例。

## 使用 Yocto Project 和 Buildroot 构建 systemd

Yocto Fido 中的默认`init`是 System V。要选择`systemd`，请在配置中添加这些行，例如，在`conf/local.conf`中：

```
DISTRO_FEATURES_append = " systemd"
VIRTUAL-RUNTIME_init_manager = "systemd"
```

请注意，前导空格很重要！然后重新构建。

Buildroot 将`systemd`作为第三个`init`选项。它需要 glibc 作为 C 库，并且需要启用特定一组配置选项的内核版本为 3.7 或更高。在`systemd`源代码的顶层的`README`文件中有完整的依赖项列表。

### 介绍目标、服务和单元

在我描述`systemd init`如何工作之前，我需要介绍这三个关键概念。

首先，目标是一组服务，类似于但更一般化的 SystemV `runlevel`。有一个默认目标，它是在启动时启动的服务组。

其次，服务是可以启动和停止的守护进程，非常类似于 SystemV `service`。

最后，一个单元是一个描述`target`，`service`和其他几个东西的配置文件。单元是包含属性和值的文本文件。

您可以使用`systemctl`命令更改状态并了解发生了什么。

#### 单元

配置的基本项是单元文件。单元文件位于三个不同的位置：

+   `/etc/systemd/system`：本地配置

+   `/run/systemd/system`：运行时配置

+   `/lib/systemd/system`：分发范围内的配置

在寻找单元时，`systemd`按照这个顺序搜索目录，一旦找到匹配项就停止，这样可以通过在`/etc/systemd/system`中放置同名单元来覆盖分发范围内单元的行为。您可以通过创建一个空的本地文件或链接到`/dev/null`来完全禁用一个单元。

所有单元文件都以标有`[Unit]`的部分开头，其中包含基本信息和依赖项，例如：

```
[Unit]
Description=D-Bus System Message Bus
Documentation=man:dbus-daemon(1)
Requires=dbus.socket
```

单元依赖关系通过`Requires`、`Wants`和`Conflicts`来表达：

+   `Requires`: 此单元依赖的单元列表，当此单元启动时启动

+   `Wants`: `Requires`的一种较弱形式：列出的单元被启动，但如果它们中的任何一个失败，当前单元不会停止

+   `冲突`: 一个负依赖：列出的单元在此单元启动时停止，反之亦然

处理依赖关系会产生一个应该启动（或停止）的单元列表。关键字`Before`和`After`确定它们启动的顺序。停止的顺序只是启动顺序的相反：

+   `Before`: 在列出的单元之前应启动此单元

+   `After`: 在列出的单元之后应启动此单元

在以下示例中，`After`指令确保网络后启动 Web 服务器：

```
[Unit]
Description=Lighttpd Web Server
After=network.target
```

在没有`Before`或`After`指令的情况下，单元将并行启动或停止，没有特定的顺序。

#### 服务

服务是可以启动和停止的守护进程，相当于 System V 的`service`。服务是以`.service`结尾的一种单元文件，例如`lighttpd.service`。

服务单元有一个描述其运行方式的`[Service]`部分。以下是`lighttpd.service`的相关部分：

```
[Service]
ExecStart=/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf -D
ExecReload=/bin/kill -HUP $MAINPID
```

这些是启动服务和重新启动服务时要运行的命令。您可以在这里添加更多配置点，因此请参考`systemd.service`的手册页。

#### 目标

目标是另一种将服务（或其他类型的单元）分组的单元类型。它是一种只有依赖关系的单元类型。目标的名称以`.target`结尾，例如`multi-user.target`。目标是一种期望状态，起到与 System V 运行级别相同的作用。

## systemd 如何引导系统

现在我们可以看到`systemd`如何实现引导。`systemd`由内核作为`/sbin/init`的符号链接到`/lib/systemd/systemd`而运行。它运行默认目标`default.target`，它始终是一个指向期望目标的链接，例如文本登录的`multi-user.target`或图形环境的`graphical.target`。例如，如果默认目标是`multi-user.target`，您将找到此符号链接：

```
/etc/systemd/system/default.target -> /lib/systemd/system/multi-user.target
```

默认目标可以通过在内核命令行上传递`system.unit=<new target>`来覆盖。您可以使用`systemctl`来查找默认目标，如下所示：

```
# systemctl get-default
multi-user.target
```

启动诸如`multi-user.target`之类的目标会创建一个依赖树，将系统带入工作状态。在典型系统中，`multi-user.target`依赖于`basic.target`，后者依赖于`sysinit.target`，后者依赖于需要早期启动的服务。您可以使用`systemctl list-dependencies`打印图形。

您还可以使用`systemctl list-units --type service`列出所有服务及其当前状态，以及使用`systemctl list-units --type target`列出目标。

## 添加您自己的服务

使用与之前相同的`simpleserver`示例，这是一个服务单元：

```
[Unit]
Description=Simple server

[Service]
Type=forking
ExecStart=/usr/bin/simpleserver

[Install]
WantedBy=multi-user.target
```

`[Unit]`部分只包含一个描述，以便在使用`systemctl`和其他命令列出时正确显示。没有依赖关系；就像我说的，它非常简单。

`[Service]`部分指向可执行文件，并带有一个指示它分叉的标志。如果它更简单并在前台运行，`systemd`将为我们进行守护进程，`Type=forking`将不需要。

`[Install]`部分使其依赖于`multi-user.target`，这样我们的服务器在系统进入多用户模式时启动。

一旦单元保存在`/etc/systemd/system/simpleserver.service`中，您可以使用`systemctl start simpleserver`和`systemctl stop simpleserver`命令启动和停止它。您可以使用此命令查找其当前状态：

```
# systemctl status simpleserver
  simpleserver.service - Simple server
  Loaded: loaded (/etc/systemd/system/simpleserver.service; disabled)
  Active: active (running) since Thu 1970-01-01 02:20:50 UTC; 8s ago
  Main PID: 180 (simpleserver)
  CGroup: /system.slice/simpleserver.service
           └─180 /usr/bin/simpleserver -n

Jan 01 02:20:50 qemuarm systemd[1]: Started Simple server.
```

此时，它只会按命令启动和停止，如所示。要使其持久化，您需要向目标添加永久依赖项。这就是单元中`[Install]`部分的目的，它表示当启用此服务时，它将依赖于`multi-user.target`，因此将在启动时启动。您可以使用`systemctl enable`来启用它，如下所示：

```
# systemctl enable simpleserver
Created symlink from /etc/systemd/system/multi-user.target.wants/simpleserver.service to /etc/systemd/system/simpleserver.service.
```

现在您可以看到如何在运行时添加依赖项，而无需编辑任何单元文件。一个目标可以有一个名为`<target_name>.target.wants`的目录，其中可以包含指向服务的链接。这与在目标中的`[Wants]`列表中添加依赖单元完全相同。在这种情况下，您会发现已创建了此链接：

```
/etc/systemd/system/multi-user.target.wants/simpleserver.service
/etc/systemd/system/simpleserver.service
```

如果这是一个重要的服务，如果失败，您可能希望重新启动。您可以通过向`[Service]`部分添加此标志来实现：

`Restart=on-abort`

`Restart`的其他选项是`on-success`、`on-failure`、`on-abnormal`、`on-watchdog`、`on-abort`或`always`。

## 添加看门狗

看门狗是嵌入式设备中的常见要求：如果关键服务停止工作，通常需要采取措施重置系统。在大多数嵌入式 SoC 中，有一个硬件看门狗，可以通过`/dev/watchdog`设备节点访问。看门狗在启动时使用超时进行初始化，然后必须在该期限内进行复位，否则看门狗将被触发，系统将重新启动。与看门狗驱动程序的接口在内核源代码中的`Documentation/watchdog`中有描述，驱动程序的代码在`drivers/watchdog`中。

如果有两个或更多需要由看门狗保护的关键服务，就会出现问题。`systemd`有一个有用的功能，可以在多个服务之间分配看门狗。

`systemd`可以配置为期望从服务接收定期的保持活动状态的调用，并在未收到时采取行动，换句话说，每个服务的软件看门狗。为了使其工作，您必须向守护程序添加代码以发送保持活动状态的消息。它需要检查`WATCHDOG_USEC`环境变量中的非零值，然后在此期间内调用`sd_notify(false, "WATCHDOG=1")`（建议使用看门狗超时的一半时间）。`systemd`源代码中有示例。

要在服务单元中启用看门狗，向`[Service]`部分添加类似以下内容：

```
WatchdogSec=30s
Restart=on-watchdog
StartLimitInterval=5min
StartLimitBurst=4
StartLimitAction=reboot-force
```

在这个例子中，该服务期望每 30 秒进行一次保持活动状态的检查。如果未能交付，该服务将被重新启动，但如果在五分钟内重新启动超过四次，`systemd`将强制立即重新启动。再次，在`systemd`手册中有关于这些设置的完整描述。

像这样的看门狗负责个别服务，但如果`systemd`本身失败，或者内核崩溃，或者硬件锁定。在这些情况下，我们需要告诉`systemd`使用看门狗驱动程序：只需将`RuntimeWatchdogSec=NN`添加到`/etc/systemd/system.conf`。`systemd`将在该期限内重置看门狗，因此如果`systemd`因某种原因失败，系统将重置。

## 嵌入式 Linux 的影响

`systemd`在嵌入式 Linux 中有许多有用的功能，包括我在这个简要描述中没有提到的许多功能，例如使用切片进行资源控制（参见`systemd.slice(5)`和`systemd.resource-control(5)`的手册页）、设备管理（`udev(7)`）和系统日志记录设施（`journald(5)`）。

您必须权衡其大小：即使只构建了核心组件`systemd`、`udevd`和`journald`，其存储空间也接近 10 MiB，包括共享库。

您还必须记住，`systemd`的开发与内核紧密相关，因此它不会在比`systemd`发布时间早一年或两年的内核上工作。

# 进一步阅读

以下资源提供了有关本章介绍的主题的进一步信息：

+   systemd 系统和服务管理器：[`www.freedesktop.org/wiki/Software/systemd/`](http://www.freedesktop.org/wiki/Software/systemd/)（该页面底部有许多有用的链接）

# 总结

每个 Linux 设备都需要某种类型的`init`程序。如果您正在设计一个系统，该系统只需在启动时启动少量守护程序并在此后保持相对静态，那么 BusyBox`init`就足够满足您的需求。如果您使用 Buildroot 作为构建系统，通常这是一个不错的选择。

另一方面，如果您的系统在启动时或运行时服务之间存在复杂的依赖关系，并且您有存储空间，那么`systemd`将是最佳选择。即使没有复杂性，`systemd`在处理看门狗、远程日志记录等方面也具有一些有用的功能，因此您应该认真考虑它。

很难仅凭其自身的优点支持 System V`init`，因为它几乎没有比简单的 BusyBox`init`更多的优势。尽管如此，它仍将长期存在，仅仅因为它存在。例如，如果您正在使用 Yocto Project 进行构建，并决定不使用`systemd`，那么 System V`init`就是另一种选择。

在减少启动时间方面，`systemd`比 System V`init`更快，但是，如果您正在寻找非常快速的启动，没有什么能比得上简单的 BusyBox`init`和最小的启动脚本。

本章是关于一个非常重要的进程，`init`。在下一章中，我将描述进程的真正含义，它与线程的关系，它们如何合作以及它们如何被调度。如果您想创建一个健壮且易于维护的嵌入式系统，了解这些内容是很重要的。
