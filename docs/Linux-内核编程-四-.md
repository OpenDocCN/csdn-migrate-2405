# Linux 内核编程（四）

> 原文：[`zh.annas-archive.org/md5/86EBDE91266D2750084E0C4C5C494FF7`](https://zh.annas-archive.org/md5/86EBDE91266D2750084E0C4C5C494FF7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：模块作者的内核内存分配-第一部分

在前两章中，一章介绍了内核内部方面和架构，另一章介绍了内存管理内部的基本知识，我们涵盖了为本章和下一章提供所需的背景信息的关键方面。在本章和下一章中，我们将着手实际分配和释放内核内存的各种方式。我们将通过您可以测试和调整的内核模块来演示这一点，详细说明其中的原因和方法，并提供许多实用的技巧，以使像您这样的内核或驱动程序开发人员在处理内核模块内存时能够获得最大的效率。

在本章中，我们将介绍内核的两个主要内存分配器——**页面分配器**（**PA**）（又称**Buddy System Allocator**（**BSA**））和 slab 分配器。我们将深入研究在内核模块中使用它们的 API 的细节。实际上，我们将远远超出简单地了解如何使用 API，清楚地展示在所有情况下都不是最佳的原因，以及如何克服这些情况。第九章，*模块作者的内核内存分配-第二部分*，将继续介绍内核内存分配器，深入探讨一些更高级的领域。

在本章中，我们将涵盖以下主题：

+   介绍内核内存分配器

+   理解和使用内核页面分配器（或 BSA）

+   理解和使用内核 slab 分配器

+   kmalloc API 的大小限制

+   Slab 分配器-一些额外的细节

+   使用 slab 分配器时的注意事项

# 技术要求

我假设您已经阅读了第一章，*内核工作空间设置*，并已经适当准备了一个运行 Ubuntu 18.04 LTS（或更高稳定版本）的虚拟机，并安装了所有必需的软件包。如果没有，我强烈建议您首先这样做。

为了充分利用本书，我强烈建议您首先设置好工作空间

环境，包括克隆本书的 GitHub 存储库（[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)）以获取代码，并进行实际操作。

请参考*Hands-On System Programming with Linux*，Kaiwan N Billimoria, Packt ([`www.packtpub.com/networking-and-servers/hands-system-programming-linux`](https://www.packtpub.com/networking-and-servers/hands-system-programming-linux))作为本章的先决条件（确实是必读的）：

+   *第一章*，*Linux 系统架构*

+   *第二章*，*虚拟内存*

# 介绍内核内存分配器

像任何其他操作系统一样，Linux 内核需要一个稳固的算法和实现来执行一个非常关键的任务——分配和释放内存或页面帧（RAM）。Linux 操作系统中的主要（de）分配器引擎被称为 PA 或 BSA。在内部，它使用所谓的伙伴系统算法来高效地组织和分配系统 RAM 的空闲块。我们将在*理解和使用内核页面分配器（或 BSA）*部分找到更多关于该算法的信息。

在本章和本书中，当我们使用*(de)allocate*这种表示法时，请将其理解为*allocate*和*deallocate*两个词。

当然，作为不完美的，页面分配器并不是获取和释放系统内存的唯一或总是最佳方式。Linux 内核中存在其他技术来实现这一点。其中之一是内核的**slab 分配器**或**slab 缓存**系统（我们在这里使用*slab*这个词作为这种类型分配器的通用名称，因为它起源于这个名称；实际上，Linux 内核使用的现代 slab 分配器的内部实现称为 SLUB（无队列 slab 分配器）；稍后会详细介绍）。

可以这样理解：slab 分配器解决了一些问题，并通过页面分配器优化了性能。到底解决了哪些问题？我们很快就会看到。不过，现在，真的很重要的是要理解，实际（de）分配物理内存的唯一方式是通过页面分配器。页面分配器是 Linux 操作系统上内存（de）分配的主要引擎！

为了避免混淆和重复，我们从现在开始将这个主要分配引擎称为页面分配器。*您将了解到它也被称为 BSA（源自驱动它的算法的名称）。*

因此，slab 分配器是建立在页面分配器之上的。各种核心内核子系统以及内核中的非核心代码，如设备驱动程序，都可以直接通过页面分配器或间接通过 slab 分配器分配（和释放）内存；以下图表说明了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/5ac7cdd2-8784-4148-a456-149595e71aed.png)

图 8.1 - Linux 的页面分配器引擎，上面是 slab 分配器

首先，有几件事要澄清：

+   整个 Linux 内核及其所有核心组件和子系统（不包括内存管理子系统本身）最终都使用页面分配器（或 BSA）进行内存（de）分配。这包括非核心内容，如内核模块和设备驱动程序。

+   前面的系统完全驻留在内核（虚拟）地址空间中，不可直接从用户空间访问。

+   页面帧（RAM）从页面分配器获取内存的地方位于内核低内存区域，或内核段的直接映射 RAM 区域（我们在上一章节详细介绍了内核段）

+   slab 分配器最终是页面分配器的用户，因此它的内存也是从那里获取的（这再次意味着从内核低内存区域获取）

+   用户空间使用熟悉的`malloc`系列 API 进行动态内存分配并不直接映射到前面的层（也就是说，在用户空间调用`malloc(3)`并不直接导致对页面或 slab 分配器的调用）。它是间接的。具体是如何？您将会学到；请耐心等待！（这个关键内容实际上在下一章的两个部分中找到，涉及到需求分页；在您学习那一章时要注意！）

+   另外，要明确的是，Linux 内核内存是不可交换的。它永远不会被交换到磁盘上；这是在早期 Linux 时代决定的，以保持性能高。用户空间内存页面默认是可交换的；系统程序员可以通过`mlock()`/`mlockall()`系统调用来改变这一点。

现在，系好安全带！有了对页面分配器和 slab 分配器的基本理解，让我们开始学习 Linux 内核内存分配器的工作原理，更重要的是，如何与它们良好地配合工作。

# 理解和使用内核页面分配器（或 BSA）

在这一部分，您将了解 Linux 内核主要（de）分配器引擎的两个方面：

+   首先，我们将介绍这个软件背后算法的基础知识（称为伙伴系统）。

+   然后，我们将介绍它向内核或驱动程序开发人员公开的 API 的实际使用。

理解页面分配器背后的算法的基础知识是重要的。然后您将能够了解其优缺点，以及在哪种情况下使用哪些 API。让我们从它的内部工作原理开始。再次提醒，本书关于内部内存管理细节的范围是有限的。我们将涵盖到足够的深度，不再深入。

## 页面分配器的基本工作原理

我们将把这个讨论分成几个相关的部分。让我们从内核的页面分配器如何通过其 freelist 数据结构跟踪空闲物理页面帧开始。

### Freelist 组织

页面分配器（伙伴系统）算法的关键是其主要内部元数据结构。它被称为伙伴系统空闲列表，由指向（非常常见的！）双向循环列表的指针数组组成。这个指针数组的索引称为列表的顺序 - 它是要提高 2 的幂。数组长度从`0`到`MAX_ORDER-1`。`MAX_ORDER`的值取决于体系结构。在 x86 和 ARM 上，它是 11，而在大型系统（如 Itanium）上，它是 17。因此，在 x86 和 ARM 上，顺序范围从 2⁰到 2¹⁰；也就是从 1 到 1,024。这是什么意思？请继续阅读...

每个双向循环链表指向大小为*2^(order)*的自由物理连续页面帧。因此（假设页面大小为 4 KB），我们最终得到以下列表：

+   2⁰ = 1 页 = 4 KB 块

+   2¹ = 2 页 = 8 KB 块

+   2² = 4 页 = 16 KB 块

+   2³ = 8 页 = 32 KB 块

+   2¹⁰ = 1024 页 = 1024*4 KB = 4 MB 块

以下图表是对（单个实例的）页面分配器空闲列表的简化概念说明：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/72c111f2-5fee-43ad-91e8-e1ee9d18eabf.png)

图 8.2 - 具有 4 KB 页面大小和 MAX_ORDER 为 11 的系统上的伙伴系统/页面分配器空闲列表

在上图中，每个内存“块”由一个正方形框表示（为了简单起见，我们在图中使用相同的大小）。当然，在内部，这些并不是实际的内存页面；相反，这些框代表指向物理内存帧的元数据结构（struct page）。在图的右侧，我们显示了可以排入左侧列表的每个物理连续空闲内存块的大小。

内核通过`proc`文件系统（在我们的 Ubuntu 虚拟机上，内存为 1 GB）为我们提供了对页面分配器当前状态的方便（汇总）视图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/12346cfe-59e4-438a-bea4-dced0a622b0e.png)

图 8.3 - 样本/proc/buddyinfo 输出的带注释的屏幕截图

我们的虚拟机是一个伪 NUMA 框，有一个节点（`Node 0`）和两个区域（`DMA`和`DMA32`）。在`zone XXX`后面的数字是从顺序 0，顺序 1，顺序 2 一直到`MAX_ORDER-1`（这里是*11 - 1 = 10*）的空闲（物理连续！）页框的数量。因此，让我们从前面的输出中取几个例子：

+   在节点`0`，`zone DMA`的顺序`0`列表中有 35 个单页的空闲 RAM 块。

+   在节点`0`，`zone DMA32`，顺序`3`，这里显示的数字是 678；现在，取*2^(order) = 2³* = 8* *页框 = 32 KB*（假设页面大小为 4 KB）；这意味着在该列表上有 678 个 32 KB 的物理连续空闲 RAM 块。

重要的是要注意**每个块都保证是物理连续的 RAM**。还要注意，给定顺序上的内存块的大小始终是前一个顺序的两倍（并且是下一个顺序的一半）。当然，这是因为它们都是 2 的幂。

请注意，`MAX_ORDER`可以（并且确实）随体系结构变化。在常规 x86 和 ARM 系统上，它是`11`，在空闲列表的顺序 10 上产生 4 MB 的物理连续 RAM 的最大块大小。在运行 Itanium（IA-64）处理器的高端企业服务器级系统上，`MAX_ORDER`可以高达`17`（意味着在空闲列表的顺序（17-1）上的最大块大小，因此在 16 的顺序上是*2¹⁶ = 65,536 页 = 512 MB 块*的物理连续 RAM，对于 4 KB 页面大小）。IA-64 MMU 支持从仅有的 4 KB 到 256 MB 的八种页面大小。作为另一个例子，对于 16 MB 的页面大小，顺序 16 列表可能每个具有*65,536 * 16 MB = 1 TB*的物理连续 RAM 块！

另一个关键点：内核保留多个 BSA 空闲列表 - 每个存在于系统上的 node:zone 都有一个！这为在 NUMA 系统上分配内存提供了一种自然的方式。

下图显示了内核如何实例化多个*空闲列表-系统上每个节点：区域一个*（图表来源：*Professional Linux Kernel Architecture*，Mauerer，Wrox Press，2008 年 10 月）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/998a8480-eae3-4f0e-bb2b-4ecd15a07d4b.png)

图 8.4-页面分配器（BSA）“空闲列表”，系统上每个节点：区域一个；图表来源：*Professional Linux Kernel Architecture*，Mauerer，Wrox Press，2008 年 10 月

此外，如图 8.5 所示，当内核被调用以通过页面分配器分配 RAM 时，它会选择最佳的空闲列表来分配内存-与请求的线程所在的*节点*相关联的列表（回想一下前一章的 NUMA 架构）。如果该节点没有内存或由于某种原因无法分配内存，内核将使用备用列表来确定从哪个空闲列表尝试分配内存（实际上，实际情况更加复杂；我们在*页面分配器内部-更多细节*部分提供了一些更多的细节）。

现在让我们以概念方式了解所有这些实际上是如何工作的。

### 页面分配器的工作原理

实际的（解）分配策略可以通过一个简单的例子来解释。假设一个设备驱动程序请求 128 KB 的内存。为了满足这个请求，（简化和概念化的）页面分配器算法将执行以下操作：

1.  该算法以页面的形式表示要分配的数量（这里是 128 KB），因此，这里是（假设页面大小为 4 KB）*128/4=32 页*。

1.  接下来，它确定 2 必须被提高到多少次方才能得到 32。这就是*log*[2]*32*，结果是 5（因为 2⁵等于 32）。

1.  现在，它检查适当的*节点：区域*页面分配器空闲列表上的顺序 5 列表。如果有可用的内存块（大小为*2**⁵**页=128 KB*），则从列表中出列，更新列表，并分配给请求者。任务完成！返回给调用者。

为什么我们说*适当的节点：区域**页面分配器空闲列表*？这是否意味着有不止一个？是的，确实如此！我们再次重申：实际情况是系统上将有几个空闲列表数据结构，每个*节点：区域*一个（还可以在*页面分配器内部-更多细节*部分中查看更多细节）。

1.  如果顺序 5 列表上没有可用的内存块（即为空），那么它将检查下一个顺序的列表；也就是顺序 6 的链表（如果不为空，它将有*2⁶**页=256 KB*的内存块排队，每个块的大小是我们想要的两倍）。

1.  如果顺序 6 列表不为空，那么它将从中取出（出列）一个内存块（大小为 256 KB，是所需大小的两倍），并执行以下操作：

+   更新列表以反映现在已经移除了一个块。

+   将这个块切成两半，从而得到两个 128 KB 的半块或**伙伴**！（请参阅下面的信息框。）

+   将一半（大小为 128 KB）迁移（入列）到顺序 5 列表。

+   将另一半（大小为 128 KB）分配给请求者。

+   任务完成！返回给调用者。

1.  如果顺序 6 列表也是空的，那么它将使用顺序 7 列表重复前面的过程，直到成功为止。

1.  如果所有剩余的高阶列表都为空（null），则请求将失败。

我们可以将内存块切成两半，因为列表上的每个块都保证是物理上连续的内存。切割后，我们得到两个半块；每个都被称为**伙伴块**，因此这个算法的名称。从学术角度来说，它被称为二进制伙伴系统，因为我们使用 2 的幂大小的内存块。**伙伴块**被定义为与另一个相同大小且物理相邻的块。

你会明白前面的描述是概念性的。实际的代码实现当然更复杂和优化。顺便说一句，代码-作为**分区伙伴分配器的核心**，正如它的注释所提到的，就在这里：`mm/page_alloc.c:__alloc_pages_nodemask()`。超出了本书的范围，我们不会尝试深入研究分配器的代码级细节。

### 通过几种情景来工作

现在我们已经了解了算法的基础，让我们考虑一些情景：首先是一个简单直接的情况，然后是一些更复杂的情况。

#### **最简单的情况**

假设一个内核空间设备驱动程序（或一些核心代码）请求 128 KB，并从一个空闲列表数据结构的 order 5 列表中接收到一个内存块。在以后的某个时间点，它将必然通过使用页面分配器的一个 free API 来释放内存块。现在，这个 API 的算法通过它的 order 计算出刚刚释放的块属于 order 5 列表；因此，它将其排队在那里。

#### **更复杂的情况**

现在，假设与之前的简单情况不同，当设备驱动程序请求 128 KB 时，order 5 列表为空；因此，根据页面分配器算法，我们转到下一个 order 6 的列表并检查它。假设它不为空；算法现在出列一个 256 KB 的块并将其分割（或切割）成两半。现在，一半（大小为 128 KB）发送给请求者，剩下的一半（同样大小为 128 KB）排队到 order 5 列表。

伙伴系统的真正有趣的特性是当请求者（设备驱动程序）在以后的某个时间点释放内存块时会发生什么。正如预期的那样，算法通过它的 order 计算出刚刚释放的块属于 order 5 列表。但在盲目地将其排队到那里之前，**它会寻找它的伙伴块**，在这种情况下，它（可能）找到了！现在它将两个伙伴块合并成一个更大的块（大小为 256 KB）并将合并后的块排队到*order 6*列表。这太棒了-它实际上帮助了**碎片整理内存**！

#### **失败的情况**

现在让我们通过不使用方便的 2 的幂大小作为需求来增加趣味性。这一次，假设设备驱动程序请求大小为 132 KB 的内存块。伙伴系统分配器会怎么做？当然，它不能分配比请求的内存更少，它会分配更多-你猜到了（见*图 8.2*），下一个可用的内存块是大小为 256 KB 的 order 7。但消费者（驱动程序）只会看到并使用分配给它的 256 KB 块的前 132 KB。剩下的（124 KB）是**浪费**的（想想看，接近 50%的浪费！）。这被称为**内部碎片（或浪费）**，是二进制伙伴系统的关键失败！

你会发现，对于这种情况确实有一种缓解方法：有一个补丁用于处理类似的情况（通过`alloc_pages_exact() / free_pages_exact()` API）。我们将很快介绍使用页面分配器的 API。

### 页面分配器内部-更多细节

在本书中，我们不打算深入研究页面分配器内部的代码级细节。话虽如此，事实是：在数据结构方面，`zone`结构包含一个`free_area`结构的数组。这是有道理的；正如你所学到的，系统上可以有（通常有）多个页面分配器空闲列表，每个节点：区域一个：

```
// include/linux/mmzone.h
struct zone { 
    [ ... ] 
    /* free areas of different sizes */
    struct free_area free_area[MAX_ORDER];
    [ ... ]
};
```

`free_area`结构是双向循环链表的实现（在该节点：区域内的空闲内存页框中）以及当前空闲的页框数量：

```
struct free_area {
    struct list_head free_list[MIGRATE_TYPES];
    unsigned long nr_free;
};
```

为什么是一个链表数组而不是一个链表？不深入细节，我们将提到，实际上，到目前为止，伙伴系统空闲列表的内核布局比表面上的更复杂：从 2.6.24 内核开始，我们看到的每个空闲列表实际上进一步分解为多个空闲列表，以满足不同的*页面迁移类型*。这是为了处理在尝试保持内存碎片整理时出现的复杂情况。除此之外，如前所述，这些空闲列表存在于系统上的每个*节点：区域*。因此，例如，在一个实际的 NUMA 系统上，每个节点有 4 个区域，每个节点有 3 个区域，将有 12（4 x 3）个空闲列表。不仅如此，每个空闲列表实际上进一步分解为 6 个空闲列表，每个迁移类型一个。因此，在这样的系统上，整个系统将存在*6 x 12 = 72*个空闲列表数据结构！

如果您感兴趣，请深入了解细节，并查看`/proc/buddyinfo`的输出-这是伙伴系统空闲列表状态的一个很好的总结视图（如图 8.3 所示）。接下来，为了获得更详细和更现实的视图（如前面提到的类型，显示*所有*空闲列表），查看`/proc/pagetypeinfo`（需要 root 访问）-它显示所有空闲列表（也分解为页面迁移类型）。

页面分配器（伙伴系统）算法的设计是*最佳适配*类之一。它的主要优点是实际上有助于在系统运行时整理物理内存。简而言之，它的优缺点如下。

页面分配器（伙伴系统）算法的优点如下：

+   有助于碎片整理内存（防止外部碎片）

+   保证分配物理连续的内存块

+   保证 CPU 缓存行对齐的内存块

+   快速（足够快；算法时间复杂度为*O(log n)*）

另一方面，迄今为止最大的缺点是内部碎片或浪费可能过高。

好的，很棒！我们已经涵盖了页面或伙伴系统分配器内部工作的大量背景材料。现在是动手的时候：让我们现在深入了解并使用页面分配器 API 来分配和释放内存。

## 学习如何使用页面分配器 API

Linux 内核提供了一组 API 来通过页面分配器分配和释放内存（RAM），这些通常被称为低级（de）分配器例程。以下表格总结了页面分配 API；您会注意到所有具有两个参数的 API 或宏，第一个参数称为*GFP 标志或位掩码*；我们将很快详细解释它，请现在忽略它。第二个参数是`order`-空闲列表的顺序，即要分配的内存量为 2^(order)页帧。所有原型都可以在`include/linux/gfp.h`中找到：

| **API 或宏名称** | **评论** | **API 签名或宏** |
| --- | --- | --- |
| `__get_free_page()` | 分配一个页面帧。分配的内存将具有随机内容；它是`__get_free_pages()`API 的包装器。返回值是刚分配的内存的内核逻辑地址的指针。 | `#define __get_free_page(gfp_mask) \ __get_free_pages((gfp_mask), 0)`​ |
| `__get_free_pages()` | 分配*2^(order)*个物理连续的页面帧。分配的内存将具有随机内容；返回值是刚分配的内存的内核逻辑地址的指针。 | `unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);` |
| `get_zeroed_page()` | 分配一个页面帧；其内容设置为 ASCII 零（`NULL`；即，它被清零）；返回值是刚分配的内存的内核逻辑地址的指针。 | `unsigned long get_zeroed_page(gfp_t gfp_mask);` |
| `alloc_page()` | 分配一个页面帧。分配的内存将具有随机内容；是`alloc_pages()` API 的包装器；返回值是指向刚分配的内存的`page`元数据结构的指针；可以通过`page_address()`函数将其转换为内核逻辑地址。 | `#define alloc_page(gfp_mask) \ alloc_pages(gfp_mask, 0)` |
| `alloc_pages()` | 分配*2^(order)*个物理连续页面帧。分配的内存将具有随机内容；返回值是指向刚分配的内存的`page`元数据结构开头的指针；可以通过`page_address()`函数将其转换为内核逻辑地址。 | `struct page * alloc_pages(gfp_t gfp_mask, unsigned int order);` |

表 8.1 - 低级（BSA/page）分配器 - 流行的导出分配 API

所有先前的 API 都是通过`EXPORT_SYMBOL()`宏导出的，因此可供内核模块和设备驱动程序开发人员使用。不用担心，您很快就会看到一个演示如何使用它们的内核模块。

Linux 内核认为维护一个（小）元数据结构来跟踪每个 RAM 页面帧是值得的。它被称为`page`结构。关键在于，要小心：与通常的返回指向新分配的内存块开头的指针（虚拟地址）的语义不同，注意先前提到的`alloc_page()`和`alloc_pages()` API 都返回指向新分配的内存的`page`结构开头的指针，而不是内存块本身（其他 API 所做的）。您必须通过调用返回的页面结构地址上的`page_address()` API 来获取新分配的内存开头的实际指针。在*编写内核模块以演示使用页面分配器 API*部分的示例代码将说明所有先前 API 的用法。

在这里提到的页面分配器 API 之前，至关重要的是了解至少关于**获取空闲页面**（GFP）标志的基础知识，这是接下来的部分的主题。

### 处理 GFP 标志

您会注意到所有先前的分配器 API（或宏）的第一个参数是`gfp_t gfp_mask`。这是什么意思？基本上，这些是 GFP 标志。这些是内核内部内存管理代码层使用的标志（有几个）。对于典型的内核模块（或设备驱动程序）开发人员来说，只有两个 GFP 标志至关重要（如前所述，其余是用于内部使用）。它们如下：

+   `GFP_KERNEL`

+   `GFP_ATOMIC`

在通过页面分配器 API 执行内存分配时决定使用哪个是重要的；始终记住的一个关键规则是：

*如果在进程上下文中并且可以安全休眠，则使用 GFP_KERNEL 标志。如果不安全休眠（通常在任何类型的原子或中断上下文中），必须使用 GFP_ATOMIC 标志。*

遵循上述规则至关重要。搞错了会导致整个机器冻结、内核崩溃和/或发生随机的不良情况。那么*安全/不安全休眠*这些陈述到底意味着什么？为此以及更多内容，我们推迟到接下来的*深入挖掘 GFP 标志*部分。尽管如此，这真的很重要，所以我强烈建议您阅读它。

**Linux 驱动程序验证**（LDV）项目：回到第一章，*内核工作空间设置*，在*LDV - Linux 驱动程序验证*项目部分，我们提到该项目对于 Linux 模块（主要是驱动程序）以及核心内核的各种编程方面有有用的“规则”。

关于我们当前的主题，这里有一个规则，一个否定的规则，暗示着你*不能*这样做：“在持有自旋锁时使用阻塞内存分配”([`linuxtesting.org/ldv/online?action=show_rule&rule_id=0043`](http://linuxtesting.org/ldv/online?action=show_rule&rule_id=0043))。持有自旋锁时，你不允许做任何可能会阻塞的事情；这包括内核空间内存分配。因此，非常重要的是，在任何原子或非阻塞上下文中执行内存分配时，必须使用`GFP_ATOMIC`标志，比如在持有自旋锁时（你会发现这在互斥锁中并不适用；在持有互斥锁时，你可以执行阻塞活动）。违反这个规则会导致不稳定，甚至可能引发（隐式）死锁的可能性。LDV 页面提到了一个违反这个规则的设备驱动程序以及随后的修复([`git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5b0691508aa99d309101a49b4b084dc16b3d7019`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5b0691508aa99d309101a49b4b084dc16b3d7019))。看一下：补丁清楚地显示了（在我们即将介绍的`kzalloc()`API 的上下文中）`GFP_KERNEL`标志被替换为`GFP_ATOMIC`标志。

另一个常用的 GFP 标志是`__GFP_ZERO`。它的使用向内核表明你想要零化的内存页面。它经常与`GFP_KERNEL`或`GFP_ATOMIC`标志按位或操作，以返回初始化为零的内存。

内核开发人员确实费心详细记录了 GFP 标志。在`include/linux/gfp.h`中有一个长而详细的注释；标题是`DOC: 有用的 GFP 标志组合`。

目前，为了让我们快速入门，只需了解使用`GFP_KERNEL`标志与 Linux 内核的内存分配 API 确实是内核内部分配的常见情况。

### 使用页面分配器释放页面

当然，分配内存的另一面是释放内存。内核中的内存泄漏绝对不是你想要贡献的东西。在*表 8.1*中显示的页面分配器 API 中，这里是相应的释放 API：

| **API 或宏名称** | **评论** | **API 签名或宏** |
| --- | --- | --- |
| `free_page()` | 释放通过`__get_free_page()`、`get_zeroed_page()`或`alloc_page()`API 分配的（单个）页面；它只是`free_pages()`API 的简单包装 | `#define free_page(addr) __free_pages((addr), 0)` |
| `free_pages()` | 释放通过`__get_free_pages()`或`alloc_pages()`API 分配的多个页面（实际上是`__free_pages()`的包装） | `void free_pages(unsigned long addr, unsigned int order)` |
| `__free_pages()` | （与前一行相同，另外）这是执行实际工作的基础例程；还要注意第一个参数是指向`page`元数据结构的指针。 | `void __free_pages(struct page *page, unsigned int order)` |

表 8.2 - 与页面分配器一起使用的常见释放页面 API

您可以看到前面函数中实际的基础 API 是`free_pages()`，它本身只是`mm/page_alloc.c:__free_pages()`代码的包装。`free_pages()`API 的第一个参数是指向被释放内存块的起始指针；当然，这是分配例程的返回值。然而，基础 API`__free_pages()`的第一个参数是指向被释放内存块的*page*元数据结构的指针。

一般来说，除非您真的知道自己在做什么，您肯定应该调用`foo()`包装例程而不是其内部的`__foo()`例程。这样做的一个原因是简单的正确性（也许包装器在调用底层例程之前使用了一些必要的同步机制 - 比如锁）。另一个原因是有效性检查（这有助于代码保持健壮和安全）。通常，`__foo()`例程会绕过有效性检查以换取速度。

正如所有有经验的 C/C++应用程序开发人员所知，分配和随后释放内存是错误的丰富来源！这主要是因为 C 是一种无管理语言，就内存而言；因此，您可能会遇到各种各样的内存错误。这些包括众所周知的内存泄漏，读/写的缓冲区溢出/下溢，双重释放和**使用后释放**（UAF）错误。

不幸的是，在内核空间中也没有什么不同；只是后果会更严重！要特别小心！请务必确保以下内容：

+   偏爱初始化分配的内存为零的例程。

+   在执行分配时考虑并使用适当的 GFP 标志 - 更多内容请参阅*GFP 标志 - 深入挖掘*部分，但简而言之，请注意以下内容：

+   在可以安全休眠的进程上下文中，使用`GFP_KERNEL`。

+   在原子上下文中，比如处理中断时，使用`GFP_ATOMIC`。

+   在使用页面分配器时（就像我们现在正在做的那样），尽量保持分配大小为圆整的 2 的幂页（关于这一点的原因以及在不需要这么多内存时如何减轻这一点 - 典型情况下 - 将在本章后续部分详细介绍）。

+   您只会尝试释放您之前分配的内存；不用说，不要忘记释放它，也不要重复释放它。

+   确保原始内存块的指针不受重用、操纵（`ptr ++`或类似的操作）和破坏，以便在完成时正确释放它。

+   检查（并再次检查！）传递给 API 的参数。是否需要指向先前分配的块或其底层`page`结构的指针？

在生产中发现困难和/或担心问题？别忘了，您有帮助！学习如何使用内核内部的强大静态分析工具（Coccinelle、`sparse`和其他工具，如`cppcheck`或`smatch`）。对于动态分析，学习如何安装和使用**KASAN**（内核地址消毒剂）。

回想一下我在第五章中提供的 Makefile 模板，*编写您的第一个内核模块 - LKMs 第二部分*，在*A better Makefile template*部分。它包含使用了几种这些工具的目标；请使用它！

好了，既然我们已经涵盖了页面分配器的（常见的）分配和释放 API，现在是时候将这些知识付诸实践了。让我们写一些代码！

### 编写一个内核模块来演示使用页面分配器 API

现在让我们动手使用我们迄今为止学到的低级页面分配器和释放 API。在本节中，我们将展示相关的代码片段，然后在必要时进行解释，来自我们的演示内核模块（`ch8/lowlevel_mem/lowlevel_mem.c`）。

在我们小型 LKM 的主要工作例程`bsa_alloc()`中，我们用粗体字突出显示了显示我们试图实现的代码注释。需要注意的几点：

1.  首先，我们做了一些非常有趣的事情：我们使用我们的小内核“库”函数`klib_llkd.c:show_phy_pages()`，直接向您展示物理 RAM 页框如何在内核低端内存区域与内核虚拟页进行身份映射！（`show_phy_pages()`例程的确切工作将很快讨论）：

```
// ch8/lowlevel_mem/lowlevel_mem.c
[...]
static int bsa_alloc(void)
{
    int stat = -ENOMEM;
    u64 numpg2alloc = 0;
    const struct page *pg_ptr1;

    /* 0\. Show the identity mapping: physical RAM page frames to kernel virtual
     * addresses, from PAGE_OFFSET for 5 pages */
    pr_info("%s: 0\. Show identity mapping: RAM page frames : kernel virtual pages :: 1:1\n", OURMODNAME);
    show_phy_pages((void *)PAGE_OFFSET, 5 * PAGE_SIZE, 1);
```

1.  接下来，我们通过底层的`__get_free_page()`页面分配器 API 分配一页内存（我们之前在*表 8.1*中看到过）：

```
  /* 1\. Allocate one page with the __get_free_page() API */
  gptr1 = (void *) __get_free_page(GFP_KERNEL);
  if (!gptr1) {
        pr_warn("%s: __get_free_page() failed!\n", OURMODNAME);
        /* As per convention, we emit a printk above saying that the
         * allocation failed. In practice it isn't required; the kernel
         * will definitely emit many warning printk's if a memory alloc
         * request ever fails! Thus, we do this only once (here; could also
         * use the WARN_ONCE()); from now on we don't pedantically print any
         * error message on a memory allocation request failing. */
        goto out1;
  }
  pr_info("%s: 1\. __get_free_page() alloc'ed 1 page from the BSA @ %pK (%px)\n",
      OURMODNAME, gptr1, gptr1);
```

注意我们发出一个`printk`函数，显示内核的逻辑地址。回想一下上一章，这是页面分配器内存，位于内核段/VAS 的直接映射 RAM 或 lowmem 区域。

出于安全考虑，我们应该一致且只使用`%pK`格式说明符来打印内核地址，以便在内核日志中显示哈希值而不是真实的虚拟地址。然而，在这里，为了向您展示实际的内核虚拟地址，我们还使用了`%px`格式说明符（与`%pK`一样，也是可移植的；出于安全考虑，请不要在生产中使用`%px`格式说明符）。

接下来，请注意在发出第一个`__get_free_page()` API（在前面的代码片段中）之后的详细注释。它提到您实际上不必打印内存不足的错误或警告消息。（好奇吗？要找出原因，请访问[`lkml.org/lkml/2014/6/10/382`](https://lkml.org/lkml/2014/6/10/382)。）在这个示例模块中（以及之前的几个模块和将要跟进的模块），我们通过使用适当的 printk 格式说明符（如`%zd`、`%zu`、`%pK`、`%px`和`%pa`）来编码我们的 printk（或`pr_foo()`宏）实例，以实现可移植性。

1.  让我们继续使用页面分配器进行第二次内存分配；请参阅以下代码片段：

```
/*2\. Allocate 2^bsa_alloc_order pages with the __get_free_pages() API */
  numpg2alloc = powerof(2, bsa_alloc_order); // returns 2^bsa_alloc_order
  gptr2 = (void *) __get_free_pages(GFP_KERNEL|__GFP_ZERO, bsa_alloc_order);
  if (!gptr2) {
      /* no error/warning printk now; see above comment */
      goto out2;
  }
  pr_info("%s: 2\. __get_free_pages() alloc'ed 2^%d = %lld page(s) = %lld bytes\n"
      " from the BSA @ %pK (%px)\n",
      OURMODNAME, bsa_alloc_order, powerof(2, bsa_alloc_order),
      numpg2alloc * PAGE_SIZE, gptr2, gptr2);
  pr_info(" (PAGE_SIZE = %ld bytes)\n", PAGE_SIZE);
```

在前面的代码片段中（请参阅代码注释），我们通过页面分配器的`__get_free_pages()` API（因为我们模块参数`bsa_alloc_order`的默认值是`3`）分配了 2³ - 也就是 8 页的内存。

一旁注意到，我们使用`GFP_KERNEL|__GFP_ZERO` GFP 标志来确保分配的内存被清零，这是最佳实践。然而，清零大内存块可能会导致轻微的性能损失。

现在，我们问自己一个问题：有没有办法验证内存是否真的是物理上连续的（承诺的）？事实证明，是的，我们实际上可以检索并打印出每个分配的页框的起始物理地址，并检索其**页框号**（PFN）。

PFN 是一个简单的概念：它只是索引或页码 - 例如，物理地址 8192 的 PFN 是 2（*8192/4096*）。由于我们已经展示了如何（以及何时可以）将内核虚拟地址转换为它们的物理对应物（反之亦然；这个覆盖在第七章中，*内存管理内部 - 基本知识*，在*直接映射 RAM 和地址转换*部分），我们就不在这里重复了。

为了完成将虚拟地址转换为物理地址并检查连续性的工作，我们编写了一个小的“库”函数，它保存在本书 GitHub 源树的根目录中的一个单独的 C 文件`klib_llkd.c`中。我们的意图是修改我们的内核模块的 Makefile，以便将这个库文件的代码也链接进来！（正确地完成这个工作在第五章中已经涵盖了，*编写您的第一个内核模块 - LKMs 第二部分*，在*通过多个源文件执行库模拟*部分。）这是我们对库例程的调用（就像在步骤 0 中所做的那样）：

```
show_phy_pages(gptr2, numpg2alloc * PAGE_SIZE, 1);
```

以下是我们库例程的代码（在`<booksrc>/klib_llkd.c`源文件中；为了清晰起见，我们不会在这里展示整个代码）：

```
// klib_llkd.c
[...]
/* show_phy_pages - show the virtual, physical addresses and PFNs of the memory range provided on a per-page basis.
 * @kaddr: the starting kernel virtual address
 * @len: length of the memory piece (bytes)
 * @contiguity_check: if True, check for physical contiguity of pages
 * 'Walk' the virtually contiguous 'array' of pages one by one (that is, page by page),  
 * printing the virt and physical address (and PFN- page frame number). This way, we can see 
 * if the memory really is *physically* contiguous or not
 */
void show_phy_pages(const void *kaddr, size_t len, bool contiguity_check)
{
    [...]
    if (len % PAGE_SIZE)
        loops++;
    for (i = 0; i < len/PAGE_SIZE; i++) {
        pa = virt_to_phys(vaddr+(i*PAGE_SIZE));
 pfn = PHYS_PFN(pa);

        if (!!contiguity_check) {
        /* what's with the 'if !!(<cond>) ...' ??
         * a 'C' trick: ensures that the if condition always evaluates
         * to a boolean - either 0 or 1 */
            if (i && pfn != prev_pfn + 1)
                pr_notice(" *** physical NON-contiguity detected ***\n");
        }
        pr_info("%05d 0x%px %pa %ld\n", i, vaddr+(i*PAGE_SIZE), &pa, pfn);
        if (!!contiguity_check)
            prev_pfn = pfn;
    }
}
```

研究前面的函数。我们逐个遍历给定的内存范围（虚拟页），获取物理地址和 PFN，然后通过 printk 发出（请注意，我们使用`%pa`格式说明符来可移植地打印*物理地址* - 它需要通过引用传递）。不仅如此，如果第三个参数`contiguity_check`是`1`，我们将检查 PFN 是否只相差一个数字，从而检查页面是否确实是物理上连续的。 （顺便说一句，我们使用的简单`powerof()`函数也在我们的库代码中。）

不过，有一个关键点：让内核模块与物理地址一起工作是*极不鼓励*的。只有内核的内部内存管理代码直接使用物理地址。甚至硬件设备驱动程序直接使用物理内存的真实案例非常少见（DMA 是其中之一，使用`*ioremap*`API 是另一个）。

我们只在这里这样做是为了证明一点-由页面分配器分配的内存（通过单个 API 调用）是物理连续的。此外，请意识到我们使用的`virt_to_phys()`（和其他）API 保证仅在直接映射内存（内核低内存区域）上工作，而不是在`vmalloc`范围、IO 内存范围、总线内存、DMA 缓冲区等其他地方。

1.  现在，让我们继续进行内核模块代码：

```
    /* 3\. Allocate and init one page with the get_zeroed_page() API */
    gptr3 = (void *) get_zeroed_page(GFP_KERNEL);
    if (!gptr3)
        goto out3;
    pr_info("%s: 3\. get_zeroed_page() alloc'ed 1 page from the BSA @ %pK (%px)\n", 
        OURMODNAME, gptr3, gptr3);
```

如前面的代码片段所示，我们分配了一页内存，但通过使用 PA `get_zeroed_page()` API 确保它被清零。`pr_info()`显示了哈希和实际的 KVA（使用`%pK`或`%px`以便地址以便以可移植的方式打印，无论你是在 32 位还是 64 位系统上运行）。

1.  接下来，我们使用`alloc_page()` API 分配一页。小心！它不会返回分配页面的指针，而是返回代表分配页面的元数据结构`page`的指针；这是函数签名：`struct page * alloc_page(gfp_mask)`。因此，我们使用`page_address()`助手将其转换为内核逻辑（或虚拟）地址：

```
/* 4\. Allocate one page with the alloc_page() API.
 pg_ptr1 = alloc_page(GFP_KERNEL);
 if (!pg_ptr1)
     goto out4;

 gptr4 = page_address(pg_ptr1);
 pr_info("%s: 4\. alloc_page() alloc'ed 1 page from the BSA @ %pK (%px)\n"
         " (struct page addr=%pK (%px)\n)",
        OURMODNAME, (void *)gptr4, (void *)gptr4, pg_ptr1, pg_ptr1);
```

在前面的代码片段中，我们通过`alloc_page()` PA API 分配了一页内存。正如所解释的，我们需要将其返回的页面元数据结构转换为 KVA（或内核逻辑地址）通过`page_address()` API。

1.  接下来，使用`alloc_pages()` API 分配和`init` *2³ = 8 页*。与前面的代码片段一样，这里也适用相同的警告：

```
 /* 5\. Allocate and init 2³ = 8 pages with the alloc_pages() API.
 gptr5 = page_address(alloc_pages(GFP_KERNEL, 3));
 if (!gptr5)
     goto out5;
 pr_info("%s: 5\. alloc_pages() alloc'ed %lld pages from the BSA @ %pK (%px)\n", 
     OURMODNAME, powerof(2, 3), (void *)gptr5, (void *)gptr5);
```

在前面的代码片段中，我们将`alloc_pages()`包装在`page_address()` API 中，以分配*2³ = 8*页内存！

有趣的是，我们在代码中使用了几个本地的`goto`语句（请在存储库中查看代码）。仔细观察，你会注意到它实际上保持了*错误处理代码路径*的清晰和逻辑。这确实是 Linux 内核*编码风格*指南的一部分。

对（有时有争议的）`goto`的使用在这里清楚地记录在这里：[`www.kernel.org/doc/html/v5.4/process/coding-style.html#centralized-exiting-of-functions`](https://www.kernel.org/doc/html/v5.4/process/coding-style.html#centralized-exiting-of-functions)。我敦促你去查看！一旦你理解了使用模式，你会发现它有助于减少所有太典型的内存泄漏（等等）清理错误！

1.  最后，在清理方法中，在从内核内存中删除之前，我们释放了在内核模块的清理代码中刚刚分配的所有内存块。

1.  为了将我们的库`klib_llkd`代码与我们的`lowlevel_mem`内核模块链接起来，`Makefile`更改为以下内容（回想一下，我们在第五章中学习了如何将多个源文件编译成单个内核模块，*编写你的第一个内核模块-LKMs 第二部分*，在*通过多个源文件执行库模拟*部分）：

```
 PWD                   := $(shell pwd)
 obj-m                 += lowlevel_mem_lkm.o
 lowlevel_mem_lkm-objs := lowlevel_mem.o ../../klib_lkdc.o
 EXTRA_CFLAGS          += -DDEBUG
```

同样，在这个示例 LKM 中，我们经常使用`%px` printk 格式说明符，以便我们可以看到实际的虚拟地址而不是哈希值（内核安全功能）。在这里可以，但在生产中不要这样做。

哎呀！这是相当多的内容。确保你理解了代码，然后继续看它的运行。

### 部署我们的 lowlevel_mem_lkm 内核模块

好了，是时候看看我们的内核模块在运行中的情况了！让我们在树莓派 4（运行默认的树莓派 OS）和 x86_64 VM（运行 Fedora 31）上构建和部署它。

在 Raspberry Pi 4 Model B 上（运行 Raspberry Pi 内核版本 5.4.79-v7l+），我们构建然后`insmod(8)`我们的`lowlevel_mem_lkm`内核模块。以下截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/08a93d27-6112-4b32-8314-20969b47d182.png)

图 8.5 - 在 Raspberry Pi 4 Model B 上的 lowlevel_mem_lkm 内核模块的输出

看看！在图 8.6 的输出的第 0 步中，我们的`show_phy_pages()`库例程清楚地显示 KVA `0xc000 0000`具有 PA `0x0`，KVA `0xc000 1000`具有 PA `0x1000`，依此类推，共五页（右侧还有 PFN）；你可以清楚地看到物理 RAM 页框与内核虚拟页（在内核段的 lowmem 区域）的 1:1 身份映射！

接下来，使用`__get_free_page()`API 进行初始内存分配如预期进行。更有趣的是我们的第 2 种情况。在这里，我们可以清楚地看到每个分配的页面（从 0 到 7，共 8 页）的物理地址和 PFN 是连续的，显示出分配的内存页面确实是物理上连续的！

我们在运行我们自定义的 5.4 'debug'内核的 Ubuntu 20.04 上的 x86_64 VM 上构建和运行相同的模块。以下截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/90c13860-8203-43b7-a2d7-7926b1256fd8.png)

图 8.6 - 在运行 Ubuntu 20.04 的 x86_64 VM 上的 lowlevel_mem_lkm 内核模块的输出

这一次（参见图 8.7），由于`PAGE_OFFSET`值是 64 位数量（这里的值是`0xffff 8880 0000 0000`），你可以再次清楚地看到物理 RAM 页框与内核虚拟地址的身份映射（5 页）。让我们花点时间仔细看看页分配器 API 返回的内核逻辑地址。在图 8.7 中，你可以看到它们都在`0xffff 8880 .... ....`范围内。以下片段来自 x86_64 的内核源树中的`Documentation/x86/x86_64/mm.txt`，记录了 x86_64 上的虚拟内存布局（部分）：

如果这一切对你来说都很新奇，请参考第七章，*内存管理内部-基本知识*，特别是*检查内核段*和*直接映射的 RAM 和地址转换*部分。

```
0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm hole caused by [47:63] sign extension
ffff800000000000 - ffff87ffffffffff (=43 bits) guard hole, reserved for hypervisor
ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
```

很清楚，不是吗？页分配器内存（伙伴系统空闲列表）直接映射到内核 VAS 的直接映射或 lowmem 区域内的空闲物理 RAM。因此，它显然会从这个区域返回内存。你可以在前面的文档输出中看到这个区域（用粗体字突出显示）- 内核直接映射或 lowmem 区域。再次强调特定的地址范围非常与架构相关。在前面的代码中，这是 x86_64 上的（最大可能的）范围。

虽然很想宣称你现在已经完成了页分配器及其 API，但现实情况是（像往常一样）并非完全如此。请继续阅读，看看为什么-理解这些方面真的很重要。

### 页分配器和内部碎片

虽然表面上看起来一切都很好，但我敦促你深入一点。在表面之下，一个巨大的（不愉快的！）惊喜可能在等待着你：那些毫不知情的内核/驱动程序开发人员。我们之前介绍的有关页分配器的 API（参见*表 8.1*）有能力在内部产生碎片-简单来说，**浪费**-内核内存的非常重要部分！

要理解为什么会这样，你必须至少了解页分配器算法及其空闲列表数据结构的基础知识。*页分配器的基本工作*部分涵盖了这一点（以防你还没有阅读，请务必阅读）。

在*通过几种情景*部分，你会看到当我们请求方便的、完全舍入的二次幂大小的页面时，情况会非常顺利。然而，当情况不是这样时——比如说驱动程序请求 132 KB 的内存——那么我们就会遇到一个主要问题：内部碎片或浪费非常高。这是一个严重的缺点，必须加以解决。我们将看到实际上有两种方法。请继续阅读！

#### 确切的页面分配器 API

意识到默认页面分配器（或 BSA）内存在浪费的巨大潜力后，来自 Freescale Semiconductor 的开发人员（请参见信息框）为内核页面分配器贡献了一个扩展 API 的补丁，添加了一些新的 API。

在 2.6.27-rc1 系列中，2008 年 7 月 24 日，Timur Tabi 提交了一个补丁来减轻页面分配器浪费问题。这是相关的提交：[`github.com/torvalds/linux/commit/2be0ffe2b29bd31d3debd0877797892ff2d91f4c`](https://github.com/torvalds/linux/commit/2be0ffe2b29bd31d3debd0877797892ff2d91f4c)。

使用这些 API 可以更有效地分配大块（多个页面）内存，**浪费要少得多**。用于分配和释放内存的新（嗯，至少在 2008 年是*新的*）API 对如下：

```
#include <linux/gfp.h>
void *alloc_pages_exact(size_t size, gfp_t gfp_mask);
void free_pages_exact(void *virt, size_t size);
```

`alloc_pages_exact()`API 的第一个参数`size`是以字节为单位的，第二个参数是之前讨论过的“通常”的 GFP 标志值（在*处理 GFP 标志*部分；对于可能休眠的进程上下文情况，使用`GFP_KERNEL`，对于永不休眠的中断或原子上下文情况，使用`GFP_ATOMIC`）。

请注意，由此 API 分配的内存仍然保证是物理上连续的。此外，一次（通过一个函数调用）可以分配的数量受到`MAX_ORDER`的限制；事实上，这也适用于我们迄今为止看到的所有其他常规页面分配 API。我们将在即将到来的*kmalloc API 的大小限制*部分中讨论更多关于这方面的内容。在那里，你会意识到讨论实际上不仅限于 slab 缓存，还包括页面分配器！

`free_pages_exact()` API 只能用于释放由其对应的`alloc_pages_exact()`分配的内存。此外，要注意“free”例程的第一个参数当然是匹配的“alloc”例程返回的值（指向新分配的内存块的指针）。

`alloc_pages_exact()`的实现很简单而巧妙：它首先通过`__get_free_pages()`API“通常”分配整个请求的内存块。然后，它循环——从要使用的内存的末尾到实际分配的内存量（通常远大于此）——释放那些不必要的内存页面！因此，在我们的例子中，如果通过`alloc_pages_exact()`API 分配了 132 KB，它实际上会首先通过`__get_free_pages()`分配 256 KB，然后释放从 132 KB 到 256 KB 的内存！

开源之美的又一个例子！可以在这里找到使用这些 API 的演示：`ch8/page_exact_loop`；我们将留给你来尝试。

在我们开始这一部分之前，我们提到了解决页面分配器浪费问题的两种方法。一种是使用更有效的`alloc_pages_exact()`和`free_pages_exact()`API，就像我们刚刚学到的那样；另一种是使用不同的层来分配内存——*slab 分配器*。我们很快就会涉及到它；在那之前，请耐心等待。接下来，让我们更详细地了解（典型的）GFP 标志以及你作为内核模块或驱动程序作者应该如何使用它们，这一点非常重要。

## GFP 标志——深入挖掘

关于我们对低级页面分配器 API 的讨论，每个函数的第一个参数都是所谓的 GFP 掩码。在讨论 API 及其使用时，我们提到了一个*关键规则*。

如果在*进程上下文中并且可以安全地休眠*，请使用`GFP_KERNEL`标志。如果*不安全*休眠（通常是在任何类型的中断上下文或持有某些类型的锁时），*必须*使用`GFP_ATOMIC`标志。

我们将在接下来的章节中详细阐述这一点。

### 永远不要在中断或原子上下文中休眠

短语*安全休眠*实际上是什么意思？为了回答这个问题，想想阻塞调用（API）：*阻塞调用*是指调用进程（或线程）因为在等待某些事件而进入休眠状态，而它正在等待的事件尚未发生。因此，它等待 - 它“休眠”。当在将来的某个时间点，它正在等待的事件发生或到达时，它会被内核唤醒并继续前进。

用户空间阻塞 API 的一个例子是`sleep(3)`。在这里，它正在等待的事件是一定时间的流逝。另一个例子是`read(2)`及其变体，其中正在等待的事件是存储或网络数据的可用性。使用`wait4(2)`，正在等待的事件是子进程的死亡或停止/继续，等等。

因此，任何可能阻塞的函数最终可能会花费一些时间处于休眠状态（在休眠时，它肯定不在 CPU 运行队列中，并且在等待队列中）。在内核模式下调用这种*可能阻塞*的功能（当然，这是我们在处理内核模块时所处的模式）*只允许在进程上下文中*。**在不安全休眠的上下文中调用任何类型的阻塞调用都是错误的**。*把这看作是一个黄金法则。这也被称为在原子上下文中休眠 - 这是错误的，是有 bug 的，绝对*不*应该发生。

您可能会想，*我怎么能*预先*知道我的代码是否会进入原子或中断上下文*？在某种程度上，内核会帮助我们：在配置内核时（回想一下第二章，*从源代码构建 5.x Linux 内核 - 第一部分*中的`make menuconfig`），在`Kernel Hacking / Lock Debugging`菜单下，有一个名为`"Sleep inside atomic section checking"`的布尔可调节项。打开它！（配置选项名为`CONFIG_DEBUG_ATOMIC_SLEEP`；您可以随时在内核配置文件中使用 grep 查找它。同样，在第五章，*编写您的第一个内核模块 - LKMs 第二部分*，在“配置”内核部分，这是您绝对应该打开的东西。）

另一种思考这种情况的方式是如何确切地让一个进程或线程进入休眠状态？简短的答案是通过调用调度代码 - `schedule()`函数。因此，根据我们刚刚学到的内容（作为推论），`schedule()`只能在安全休眠的上下文中调用；进程上下文通常是安全的，中断上下文永远不安全。

这一点非常重要！（我们在第四章中简要介绍了进程和中断上下文，*编写您的第一个内核模块 - LKMs 第一部分*，在*进程和中断上下文*部分中，以及开发人员如何使用`in_task()`宏来确定代码当前是否在进程或中断上下文中运行。）同样，您可以使用`in_atomic()`宏；如果代码处于*原子上下文* - 在这种情况下，它通常会在没有中断的情况下运行完成 - 它返回`True`；否则，返回`False`。您可以同时处于进程上下文和原子上下文 - 例如，当持有某些类型的锁时（自旋锁；当然，我们稍后会在关于*同步*的章节中介绍这一点）；反之则不会发生。

除了我们关注的 GFP 标志——`GFP_KERNEL`和`GFP_ATOMIC`之外，内核还有几个其他`[__]GFP_*`标志，用于内部使用；其中有几个是专门用于回收内存的。这些包括（但不限于）`__GFP_IO`，`__GFP_FS`，`__GFP_DIRECT_RECLAIM`，`__GFP_KSWAPD_RECLAIM`，`__GFP_RECLAIM`，`__GFP_NORETRY`等等。在本书中，我们不打算深入研究这些细节。我建议您查看`include/linux/gfp.h`中对它们的详细注释（也请参阅*进一步阅读*部分）。

**Linux 驱动程序验证**（**LDV**）项目：回到第一章，*内核工作空间设置*，我们提到这个项目对 Linux 模块（主要是驱动程序）以及核心内核的各种编程方面有有用的“规则”。

关于我们当前的主题，这是其中一个规则，一个否定的规则，暗示着你*不能*这样做：*在持有 USB 设备锁时不禁用 IO 进行内存分配*（[`linuxtesting.org/ldv/online?action=show_rule&rule_id=0077`](http://linuxtesting.org/ldv/online?action=show_rule&rule_id=0077)）。一些快速背景：当你指定`GFP_KERNEL`标志时，它隐含地意味着（除其他事项外）内核可以启动 IO（输入/输出；读/写）操作来回收内存。问题是，有时这可能会有问题，不应该这样做；为了解决这个问题，你应该在分配内核内存时使用 GFP 位掩码的一部分`GFP_NOIO`标志。

这正是这个 LDV“规则”所指的情况：在`usb_lock_device()`和`usb_unlock_device()`API 之间，不应该使用`GFP_KERNEL`标志，而应该使用`GFP_NOIO`标志。（你可以在这段代码中看到使用这个标志的几个实例：`drivers/usb/core/message.c`）。LDV 页面提到了一些 USB 相关的驱动程序代码源文件已经修复以符合这个规则。

好了，现在你已经掌握了大量关于页面分配器的细节（毕竟，它是 RAM（de）分配的内部“引擎”！），它的 API 以及如何使用它们，让我们继续讨论一个非常重要的主题——slab 分配器背后的动机，它的 API 以及如何使用它们。

# 理解和使用内核 slab 分配器

正如本章的第一节*介绍内核内存分配器*中所看到的，*slab 分配器*或*slab 缓存*位于页面分配器（或 BSA）之上（请参阅*图 8.1*）。slab 分配器通过两个主要的想法或目的来证明它的存在：

+   **对象缓存**：在这里，它作为常见“对象”的缓存，用于在 Linux 内核中高性能地分配（和随后释放）频繁分配的数据结构。

+   通过提供小巧方便的大小的缓存，通常是**页面的片段**，来减少页面分配器的高浪费（内部碎片）。

现在让我们以更详细的方式来检查这些想法。

## 对象缓存的想法

好的，我们从这些设计理念中的第一个开始——常见对象的缓存概念。很久以前，SunOS 的开发人员 Jeff Bonwick 注意到操作系统内部频繁分配和释放某些内核对象（通常是数据结构）。因此，他有了在某种程度上*预分配*它们的想法。这演变成了我们所说的*slab 缓存*。

因此，在 Linux 操作系统上，内核（作为引导时初始化的一部分）将相当多的对象预先分配到几个 slab 缓存中。原因是：性能！当核心内核代码（或设备驱动程序）需要为这些对象之一分配内存时，它直接请求 slab 分配器。如果有缓存，分配几乎是立即的（反之亦然在释放时）。你可能会想，*这真的有必要吗*？确实有！

高性能被要求的一个很好的例子是网络和块 IO 子系统的关键代码路径。正因为这个原因，内核在 slab 缓存中*自动缓存*（*预分配*）了几个网络和块 IO 数据结构（网络堆栈的套接字缓冲区`sk_buff`，块层的`biovec`，当然还有核心的`task_struct`数据结构或对象，这是一些很好的例子）。同样，文件系统的元数据结构（如`inode`和`dentry`结构等），内存描述符（`struct mm_struct`）等也都是在 slab 缓存中*预分配*的。我们能看到这些缓存的对象吗？是的，稍后我们将通过`/proc/slabinfo`来做到这一点。

slab（或者更正确地说，SLUB）分配器具有更优越的性能的另一个原因是传统的基于堆的分配器往往会频繁分配和释放内存，从而产生“空洞”（碎片）。因为 slab 对象在缓存中只分配一次（在启动时），并在那里释放（因此实际上并没有真正“释放”），所以性能保持很高。当然，现代内核具有智能功能，当内存压力过高时，会以一种优雅的方式开始释放 slab 缓存。

slab 缓存的当前状态 - 对象缓存、缓存中的对象数量、正在使用的数量、每个对象的大小等 - 可以通过几种方式查看：通过`proc`和`sysfs`文件系统的原始视图，或者通过各种前端实用程序（如`slabtop(1)`、`vmstat(8)`和`slabinfo`）的更易读的视图。在下面的代码片段中，在运行 Ubuntu 18.04 LTS 的本机 x86_64（带有 16 GB RAM），我们查看了从`/proc/slabinfo`输出的前 10 行：

```
$ sudo head /proc/slabinfo 
slabinfo - version: 2.1
# name <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
lttng_event     0     0     280   29   2 : tunables 0 0 0 : slabdata 0 0 0
kvm_async_pf    0     0     136   30   1 : tunables 0 0 0 : slabdata 0 0 0
kvm_vcpu        0     0   24576    1   8 : tunables 0 0 0 : slabdata 0 0 0
kvm_mmu_page_header 0 0     168   24   1 : tunables 0 0 0 : slabdata 0 0 0
pte_list_desc   0     0      32  128   1 : tunables 0 0 0 : slabdata 0 0 0
i915_request  112   112     576   28   4 : tunables 0 0 0 : slabdata 4 4 0
ext4_groupinfo_4k 6482 6496 144   28   1 : tunables 0 0 0 : slabdata 232 232 0
scsi_sense_cache 325 416 128 32 1 : tunables 0 0 0 : slabdata 13 13 0
```

需要注意的几点：

+   即使是读取`/proc/slabinfo`也需要 root 访问权限（因此，我们使用`sudo(8)`）。

+   在前面的输出中，最左边的一列是 slab 缓存的名称。它通常，但并不总是，与内核中实际缓存的数据结构的名称匹配。

+   然后，对于每个缓存，以这种格式提供信息：`<statistics> : <tunables> : <slabdata>`。在`slabinfo(5)`的 man 页面中解释了标题行中显示的每个字段的含义（使用`man 5 slabinfo`查找）。

顺便说一句，`slabinfo`实用程序是内核源代码树中`tools/`目录下的用户空间 C 代码的一个例子（还有其他几个）。它显示了一堆 slab 层统计信息（尝试使用`-X`开关）。要构建它，请执行以下操作：

```
cd <ksrc-tree>/tools/vm
make slabinfo
```

在这一点上你可能会问，*slab 缓存当前总共使用了多少内存*？这很容易通过在`/proc/meminfo`中查找`Slab:`条目来回答，如下所示：

```
$ grep "^Slab:" /proc/meminfo
Slab:            1580772 kB
```

显然，slab 缓存可以使用大量内存！事实上，这是 Linux 上一个让新手感到困惑的常见特性：内核可以并且*会*使用 RAM 进行缓存，从而大大提高性能。当然，它被设计为在内存压力增加时智能地减少用于缓存的内存量。在常规的 Linux 系统上，大部分内存可能用于缓存（特别是*页面缓存*；它用于在进行 IO 时缓存文件的内容）。这是可以接受的，*只要*内存压力低。`free(1)`实用程序清楚地显示了这一点（同样，在我的带有 16 GB RAM 的 x86_64 Ubuntu 系统上，在这个例子中）：

```
$ free -h
              total     used     free     shared     buff/cache  available
Mem:           15Gi    5.5Gi    1.4Gi      704Mi          8.6Gi      9.0Gi
Swap:         7.6Gi       0B    7.6Gi
$ 
```

`buff/cache`列指示了 Linux 内核使用的两个缓存 - 缓冲区和页面缓存。实际上，在内核使用的各种缓存中，*页面缓存*是一个关键的缓存，通常占据了大部分内存使用量。

查看`/proc/meminfo`以获取有关系统内存使用的细粒度详细信息；显示的字段很多。`proc(5)`的 man 页面在`/proc/meminfo`部分描述了这些字段。

现在你已经了解了 slab 分配器背后的动机（这方面还有更多内容），让我们深入学习如何使用它为核心内核和模块作者提供的 API。

## 学习如何使用 slab 分配器 API

到目前为止，您可能已经注意到我们还没有解释 slab 分配器（缓存）背后的第二个“设计理念”，即通过提供小巧方便的缓存（通常是页面的片段）来**减少页分配器的高浪费（内部碎片）**。我们将看到这实际上意味着什么，以及内核 slab 分配器 API。

### 分配 slab 内存

尽管在 slab 层内存在多个执行内存分配和释放的 API，但只有几个真正关键的 API，其余属于“便利或辅助”功能类别（我们当然会在后面提到）。对于内核模块或设备驱动程序作者来说，关键的 slab 分配 API 如下：

```
#include <linux/slab.h>
void *kmalloc(size_t size, gfp_t flags);
void *kzalloc(size_t size, gfp_t flags);
```

在使用任何 slab 分配器 API 时，请务必包含`<linux/slab.h>`头文件。

`kmalloc()`和`kzalloc()`例程往往是内核内存分配中**最常用的 API**。在 5.4.0 Linux 内核源代码树上使用非常有用的`cscope(1)`代码浏览工具进行快速检查（我们并不追求完全精确）后，发现了（大约）使用频率：`kmalloc()`被调用了大约 4600 次，而`kzalloc()`被调用了超过 11000 次！

这两个函数都有两个参数：要传递的第一个参数是以字节为单位所需的内存分配的大小，而第二个参数是要分配的内存类型，通过现在熟悉的 GFP 标志指定（我们已经在前面的部分中涵盖了这个主题，即**处理 GFP 标志**和**GFP 标志-深入挖掘**。如果您对它们不熟悉，我建议您先阅读这些部分）。

为了减轻**整数溢出**（IoF）错误的风险，您应该避免动态计算要分配的内存大小（第一个参数）。内核文档警告我们要特别注意这一点（链接：

[`www.kernel.org/doc/html/latest/process/deprecated.html#open-coded-arithmetic-in-allocator-arguments`](https://www.kernel.org/doc/html/latest/process/deprecated.html#open-coded-arithmetic-in-allocator-arguments)。

总的来说，要始终避免使用此处记录的过时内容：*过时的接口、语言特性、属性和约定*（链接：[`www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions`](https://www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions)）。

成功分配后，返回值是一个指针，即刚刚分配的内存块（或 slab）的*内核逻辑地址*（请记住，它仍然是虚拟地址，*不是*物理地址）。确实，您应该注意到，除了第二个参数之外，`kmalloc()`和`kzalloc()`API 与它们的用户空间对应物 glibc `malloc(3)`（及其伙伴）API 非常相似。不过，不要误解：它们完全不同。`malloc()`返回一个用户空间虚拟地址，并且如前所述，用户模式的`malloc(3)`和内核模式的`k[m|z]alloc()`之间没有直接的对应关系（因此，对`malloc()`的调用*不会*立即导致对`kmalloc()`的调用；稍后会详细介绍！）。

其次，重要的是要理解这些 slab 分配器 API 返回的内存**保证是物理上连续的**。此外，另一个关键的好处是返回地址保证在 CPU 缓存行边界上；也就是说，它将是**缓存行对齐**的。这两点都是重要的性能增强的好处。

每个 CPU 在 CPU 缓存<->RAM 中以原子单位读取和写入数据。缓存行的大小因 CPU 而异。你可以使用`getconf(1)`实用程序查找这个信息 - 例如，尝试执行`getconf -a|grep LINESIZE`。在现代 CPU 上，指令和数据的缓存行通常是分开的（CPU 缓存本身也是如此）。典型的 CPU 缓存行大小为 64 字节。

`kmalloc()`分配的内存块在分配后立即是随机的（就像`malloc(3)`一样）。事实上，`kzalloc()`被推荐和建议的 API 之所以被使用，是因为它*将分配的内存设置为零*。一些开发人员认为内存块的初始化需要一些时间，从而降低了性能。我们的反驳是，除非内存分配代码在一个极端时间关键的代码路径中（这在设计上并不是一个好的设计，但有时是无法避免的），你应该作为最佳实践*在分配时初始化你的内存*。这样可以避免一系列内存错误和安全副作用。

Linux 内核核心代码的许多部分肯定会使用 slab 层来管理内存。在其中，*有*时间关键的代码路径 - 很好的例子可以在网络和块 IO 子系统中找到。为了最大化性能，slab（实际上是 SLUB）层代码已经被编写成*无锁*（通过一种称为 per-CPU 变量的无锁技术）。在*进一步阅读*部分中可以了解更多关于性能挑战和实现细节。

### 释放 slab 内存

当然，你必须在将来的某个时候释放你分配的 slab 内存（以防内存泄漏）；`kfree()`例程就是为此目的而存在的。类似于用户空间的`free(3)`API，`kfree()`接受一个参数 - 要释放的内存块的指针。它必须是有效的内核逻辑（或虚拟）地址，并且必须已经被 slab 层 API（`k[m|z]alloc()`或其帮助程序之一）初始化。它的 API 签名很简单：

```
void kfree(const void *);
```

就像`free(3)`一样，`kfree()`没有返回值。如前所述，务必确保传递给`kfree()`的参数是`k[m|z]alloc()`返回的精确值。传递错误的值将导致内存损坏，最终导致系统不稳定。

还有一些额外的要点需要注意。

假设我们使用`kzalloc()`分配了一些 slab 内存：

```
static char *kptr = kzalloc(1024, GFP_KERNEL);
```

之后，在使用后，我们想要释放它，所以我们做以下操作：

```
if (kptr)
    kfree(kptr);
```

这段代码 - 在释放之前检查`kptr`的值是否不是`NULL` - *是不必要的*；只需执行`kfree(kptr);`就可以了。

另一个*不正确*的代码示例（伪代码）如下所示：

```
static char *kptr = NULL;
 while (<some-condition-is-true>) {
       if (!kptr)
                kptr = kmalloc(num, GFP_KERNEL);
        [... work on the slab memory ...]
       kfree(kptr);
 }
```

有趣的是：在第二次循环迭代开始，程序员*假设*`kptr`指针变量在被释放时会被设置为`NULL`！这显然不是事实（尽管这本来是一个很好的语义；同样的论点也适用于“通常”的用户空间库 API）。因此，我们遇到了一个危险的 bug：在循环的第二次迭代中，`if`条件很可能会变为 false，从而跳过分配。然后，我们遇到了`kfree()`，这当然会破坏内存（由于双重释放的 bug）！（我们在 LKM 中提供了这种情况的演示：`ch8/slab2_buggy`）。

关于在分配内存后（或期间）*初始化*内存缓冲区，就像我们提到分配时一样，释放内存也是一样的。您应该意识到`kfree()`API 只是将刚释放的 slab 返回到其相应的缓存中，内部内存内容保持不变！因此，在释放内存块之前，一个（稍微迂琐的）最佳实践是*清除（覆盖）*内存内容。这对于安全原因尤为重要（例如在“信息泄漏”情况下，恶意攻击者可能会扫描已释放的内存以寻找“秘密”）。Linux 内核提供了`kzfree()`API，专门用于此目的（签名与`kfree()`相同）。

*小心！*为了覆盖“秘密”，简单的`memset()`目标缓冲区可能不起作用。为什么？编译器可能会优化掉代码（因为不再使用缓冲区）。大卫·惠勒在他的优秀作品*安全编程 HOWTO*（[`dwheeler.com/secure-programs/`](https://dwheeler.com/secure-programs/)）中提到了这一事实，并提供了解决方案：“似乎在所有平台上都有效的一种方法是编写具有第一个参数的内部“挥发性”的 memset 的自己的实现。”（此代码基于迈克尔·霍华德提出的解决方案）：

`void *guaranteed_memset(void *v,int c,size_t n)`

`{ volatile char *p=v; while (n--) *p++=c; return v; }`

然后将此定义放入外部文件中，以强制该函数为外部函数（在相应的`.h`文件中定义函数，并在调用者中`#include`该文件，这是通常的做法）。这种方法似乎在任何优化级别下都是安全的（即使函数被内联）。

内核的`kzfree()`API 应该可以正常工作。在用户空间进行类似操作时要小心。

### 数据结构-一些设计提示

在内核空间使用 slab API 进行内存分配是非常推荐的。首先，它保证了物理上连续和缓存行对齐的内存。这对性能非常有利；此外，让我们看看一些可以带来巨大回报的快速提示。

*CPU 缓存*可以提供巨大的性能提升。因此，特别是对于时间关键的代码，要注意设计数据结构以获得最佳性能：

+   将最重要的（频繁访问的，“热”）成员放在一起并置于结构的顶部。要了解原因，想象一下您的数据结构中有五个重要成员（总大小为 56 字节）；将它们全部放在结构的顶部。假设 CPU 缓存行大小为 64 字节。现在，当您的代码访问*任何一个*这五个重要成员（无论读取/写入），*所有五个成员都将被取到 CPU 缓存中，因为 CPU 的内存读/写以 CPU 缓存行大小的原子单位工作；*这优化了性能（因为在缓存上的操作通常比在 RAM 上的操作快几倍）。

+   尝试对齐结构成员，使单个成员不会“掉出”缓存行。通常，编译器在这方面会有所帮助，但您甚至可以使用编译器属性来明确指定这一点。

+   顺序访问内存会因 CPU 缓存的有效使用而导致高性能。但是，我们不能认真地要求将所有数据结构都变成数组！经验丰富的设计师和开发人员知道使用链表是非常常见的。但是，这实际上会损害性能吗？嗯，是的，在某种程度上。因此，建议：使用链表。将列表的“节点”作为一个大数据结构（顶部和一起的“热”成员）。这样，我们尽量最大化两种情况的优势，因为大结构本质上是一个数组。（想想看，我们在第六章中看到的任务结构列表，*内核内部要点-进程和线程*，*任务列表*是一个具有大数据结构作为节点的链表的完美实际例子）。

即将到来的部分涉及一个关键方面：我们确切地了解内核在通过流行的`k[m|z]alloc()` API 分配（slab）内存时使用的 slab 缓存。

### 用于 kmalloc 的实际 slab 缓存

在尝试使用基本的 slab API 创建内核模块之前，我们将进行一个快速的偏离-尽管非常重要。重要的是要了解`k[m|z]alloc()` API 分配的内存确切来自哪里。好吧，是来自 slab 缓存，但确切是哪些？在`sudo vmstat -m`的输出上快速使用`grep`为我们揭示了这一点（以下截图是我们的 x86_64 Ubuntu 客户端）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/ec7fdc35-1bda-4de1-b8fb-fed9b2cce797.png)

图 8.7-显示 kmalloc-n slab 缓存的 sudo vmstat -m 截图

这非常有趣！内核有一系列专用的 slab 缓存，用于各种大小的通用`kmalloc`内存，*从 8192 字节到仅有 8 字节！*这告诉我们一些东西-使用页面分配器，如果我们请求了，比如，12 字节的内存，它最终会给我们整个页面（4 KB）-浪费太多了。在这里，使用 slab 分配器，对 12 字节的分配请求实际上分配了 16 字节（从图 8.8 中看到的倒数第二个缓存）！太棒了。

另请注意以下内容：

+   在`kfree()`之后，内存被释放回适当的 slab 缓存中。

+   `kmalloc`的 slab 缓存的精确大小因架构而异。在我们的树莓派系统（当然是 ARM CPU）上，通用内存`kmalloc-N`缓存范围从 64 字节到 8192 字节。

+   前面的截图也透露了一个线索。通常，需求是小到微小的内存片段。例如，在前面的截图中，标有`Num`的列代表*当前活动对象的数量*，最大数量来自 8 字节和 16 字节的`kmalloc` slab 缓存（当然，这不一定总是这种情况。快速提示：使用`slabtop(1)`实用程序（您需要以 root 身份运行）：靠近顶部的行显示当前经常使用的 slab 缓存。）

当然，Linux 不断发展。截至 5.0 主线内核，引入了一种新的`kmalloc`缓存类型，称为可回收缓存（命名格式为`kmalloc-rcl-N`）。因此，在 5.x 内核上进行与之前相同的 grep 操作也会显示这些缓存。

```
$ sudo vmstat -m | grep --color=auto "^kmalloc"
kmalloc-rcl-8k                0      0    8192      4
kmalloc-rcl-4k                0      0    4096      8
kmalloc-rcl-2k                0      0    2048     16
[...]
kmalloc-8k                   52     52    8192      4
kmalloc-4k                   99    120    4096      8
kmalloc-2k                  521    560    2048     16
[...]
```

新的`kmalloc-rcl-N`缓存在内部帮助更有效地回收页面并作为防止碎片化的措施。但是，像您这样的模块作者不需要关心这些细节。（此工作的提交可以在此处查看：[`github.com/torvalds/linux/commit/1291523f2c1d631fea34102fd241fb54a4e8f7a0`](https://github.com/torvalds/linux/commit/1291523f2c1d631fea34102fd241fb54a4e8f7a0)。）

`vmstat -m`本质上是内核的`/sys/kernel/slab`内容的包装器（后面会有更多内容）。可以使用诸如`slabtop(1)`和强大的`crash(1)`实用程序（在“实时”系统上，相关的 crash 命令是`kmem -s`（或`kmem -S`））来查看 slab 缓存的深层内部细节。

好了！是时候再次动手演示使用板块分配器 API 的代码了！

### 编写一个使用基本板块 API 的内核模块

在接下来的代码片段中，看一下演示内核模块代码（位于`ch8/slab1/`）。在`init`代码中，我们仅执行了一些板块层分配（通过`kmalloc()`和`kzalloc()`API），打印了一些信息，并在清理代码路径中释放了缓冲区（当然，完整的源代码可以在本书的 GitHub 存储库中找到）。让我们一步一步地看代码的相关部分。

在这个内核模块的`init`代码开始时，我们通过`kmalloc()`板块分配 API 为一个全局指针（`gkptr`）分配了 1,024 字节的内存（记住：指针没有内存！）。请注意，由于我们肯定是在进程上下文中运行，因此“安全地休眠”，我们在第二个参数中使用了`GFP_KERNEL`标志（以防您想要参考，前面的章节*GFP 标志-深入挖掘*已经涵盖了）：

```
// ch8/slab1/slab1.c
[...]
#include <linux/slab.h>
[...]
static char *gkptr;
struct myctx {
    u32 iarr[100];
    u64 uarr[100];
    char uname[128], passwd[16], config[16];
};
static struct myctx *ctx;

static int __init slab1_init(void)
{
    /* 1\. Allocate slab memory for 1 KB using the kmalloc() */
    gkptr = kmalloc(1024, GFP_KERNEL);
    if (!gkptr) {
        WARN_ONCE(1, "%s: kmalloc() failed!\n", OURMODNAME);
        /* As mentioned earlier, there is really no need to print an
         * error msg when a memory alloc fails; the situation "shouldn't"  
         * typically occur, and if it does, the kernel will emit a chain 
         * of messages in any case. Here, we use the WARN_ONCE()
         * macro pedantically, and as this is a 'learning' program.. */
        goto out_fail1;
    }
    pr_info("kmalloc() succeeds, (actual KVA) ret value = %px\n", gkptr);
    /* We use the %px format specifier here to show the actual KVA; in production, Don't! */
    print_hex_dump_bytes("gkptr before memset: ", DUMP_PREFIX_OFFSET, gkptr, 32);
    memset(gkptr, 'm', 1024);
    print_hex_dump_bytes(" gkptr after memset: ", DUMP_PREFIX_OFFSET, gkptr, 32);
```

在前面的代码中，还要注意我们使用`print_hex_dump_bytes()`内核便捷例程作为以人类可读格式转储缓冲区内存的便捷方式。它的签名是：

```
void print_hex_dump_bytes(const char *prefix_str, int prefix_type,
     const void *buf, size_t len);
```

其中`prefix_str`是您想要添加到每行十六进制转储的任何字符串；`prefix_type`是`DUMP_PREFIX_OFFSET`、`DUMP_PREFIX_ADDRESS`或`DUMP_PREFIX_NONE`中的一个；`buf`是要进行十六进制转储的源缓冲区；`len`是要转储的字节数。

接下来是许多设备驱动程序遵循的典型策略（*最佳实践*）：它们将所有所需的或上下文信息保存在一个单一的数据结构中，通常称为*驱动程序上下文*结构。我们通过声明一个（愚蠢/示例）名为`myctx`的数据结构以及一个名为`ctx`的全局指针来模仿这一点（结构和指针定义在前面的代码块中）：

```
    /* 2\. Allocate memory for and initialize our 'context' structure */
    ctx = kzalloc(sizeof(struct myctx), GFP_KERNEL);
    if (!ctx)
        goto out_fail2;
    pr_info("%s: context struct alloc'ed and initialized (actual KVA ret = %px)\n",
        OURMODNAME, ctx);
    print_hex_dump_bytes("ctx: ", DUMP_PREFIX_OFFSET, ctx, 32);

    return 0;        /* success */
out_fail2:
    kfree(gkptr);
out_fail1:
    return -ENOMEM;
}
```

在数据结构之后，我们通过有用的`kzalloc()`包装 API 为`ctx`分配并初始化了`myctx`数据结构的大小。随后的*hexdump*将显示它确实被初始化为全零（为了可读性，我们只会“转储”前 32 个字节）。

请注意我们如何使用`goto`处理错误路径；这在本书的前面已经提到过几次，所以我们不会在这里重复了。最后，在内核模块的清理代码中，我们使用`kfree()`释放了两个缓冲区，防止内存泄漏：

```
static void __exit slab1_exit(void)
{
    kfree(ctx);
 kfree(gkptr);
    pr_info("%s: freed slab memory, removed\n", OURMODNAME);
}
```

接下来是我在我的树莓派 4 上运行的一个示例截图。我使用我们的`../../lkm`便捷脚本来构建、加载和执行`dmesg`：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/ca0f2ab4-3db3-48cf-8ae9-d5ff027ddcdf.png)

图 8.8-我们的 slab1.ko 内核模块在树莓派 4 上运行的部分截图

好了，现在您已经掌握了使用常见板块分配器 API`kmalloc()`、`kzalloc()`和`kfree()`的基础知识，让我们继续。在下一节中，我们将深入探讨一个非常关键的问题-在通过板块（和页面）分配器获取的内存上的大小限制的现实。继续阅读！

# kmalloc API 的大小限制

页面和板块分配器的一个关键优势是，它们在分配时提供的内存块不仅在逻辑上是连续的（显而易见），而且还保证是*物理上连续的内存*。这是一件大事，肯定会提高性能。

但是（总会有*但是*，不是吗！），正因为有了这个保证，所以在执行分配时不可能提供任意*大*的大小。换句话说，您可以通过一次对我们亲爱的`k[m|z]alloc()`API 的调用从板块分配器获取的内存量是有明确限制的。这个限制是多少？（这确实是一个经常被问到的问题。）

首先，您应该了解，从技术上讲，限制由两个因素决定：

+   系统页面大小（由`PAGE_SIZE`宏确定）

+   第二，"orders"的数量（由`MAX_ORDER`宏确定）；也就是说，在页面分配器（或 BSA）空闲列表数据结构中的列表数量（见图 8.2）

使用标准的 4 KB 页面大小和`MAX_ORDER`值为 11，可以使用单个`kmalloc()`或`kzalloc()`API 调用分配的最大内存量为 4 MB。这在 x86_64 和 ARM 架构上都是如此。

您可能会想知道，*这个 4 MB 的限制到底是如何得出的*？想一想：一旦 slab 分配请求超过内核提供的最大 slab 缓存大小（通常为 8 KB），内核就会简单地将请求传递给页面分配器。页面分配器的最大可分配大小由`MAX_ORDER`确定。将其设置为`11`，最大可分配的缓冲区大小为*2^((MAX_ORDER-1)) = 2¹⁰页 = 1024 页 = 1024 * 4K = 4 MB*！

## 测试极限 - 一次性内存分配

对于开发人员（以及其他所有人来说），一个非常关键的事情是**要有实证精神**！英语单词*empirical*的意思是基于所经历或所见，而不是基于理论。这是一个始终要遵循的关键规则 - 不要简单地假设事情或接受它们的表面价值。自己尝试一下，看看。

让我们做一些非常有趣的事情：编写一个内核模块，从（通用）slab 缓存中分配内存（当然是通过`kmalloc()`API）。我们将在循环中这样做，每次迭代分配 - 和释放 - 一个（计算出的）数量。这里的关键点是，我们将不断增加给定“步长”大小的分配量。当`kmalloc()`失败时，循环终止；这样，我们可以测试通过单个`kmalloc()`调用实际上可以分配多少内存（当然，您会意识到，`kzalloc()`作为`kmalloc()`的简单包装，面临着完全相同的限制）。

在下面的代码片段中，我们展示了相关代码。`test_maxallocsz()`函数从内核模块的`init`代码中调用：

```
// ch8/slab3_maxsize/slab3_maxsize.c
[...]
static int stepsz = 200000;
module_param(stepsz, int, 0644);
MODULE_PARM_DESC(stepsz,
"Amount to increase allocation by on each loop iteration (default=200000");

static int test_maxallocsz(void)
{
  size_t size2alloc = 0;
  void *p;

  while (1) {
      p = kmalloc(size2alloc, GFP_KERNEL);
      if (!p) {
          pr_alert("kmalloc fail, size2alloc=%zu\n", size2alloc);
          return -ENOMEM;
      }
      pr_info("kmalloc(%7zu) = 0x%pK\n", size2alloc, p);
      kfree(p);
 size2alloc += stepsz;
  }
  return 0;
}
```

顺便说一下，注意我们的`printk()`函数如何使用`%zu`格式说明符来表示`size_t`（本质上是一个无符号整数）变量？`%zu`是一个可移植性辅助工具；它使变量格式对 32 位和 64 位系统都是正确的！

让我们在我们的树莓派设备上构建（在主机上进行交叉编译）并插入这个内核模块，该设备运行我们自定义构建的 5.4.51-v7+内核；几乎立即，在`insmod(8)`时，您将看到一个错误消息，`insmod`进程打印出`Cannot allocate memory`；下面（截断的）截图显示了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/5fd4b019-8594-448d-9c41-7f0cb0040383.png)

图 8.9 - 在树莓派 3 上运行自定义 5.4.51 内核的 slab3_maxsize.ko 内核模块的第一个 insmod(8)

这是预期的！想一想，我们的内核模块代码的`init`函数确实在最后失败了，出现了`ENOMEM`。不要被这个扔出去；查看内核日志会揭示实际发生了什么。事实上，在这个内核模块的第一次测试运行中，您会发现在`kmalloc()`失败的地方，内核会转储一些诊断信息，包括相当长的内核堆栈跟踪。这是因为它调用了一个`WARN()`宏。

所以，我们的 slab 内存分配工作了，直到某个点。要清楚地看到失败点，只需在内核日志（`dmesg`）显示中向下滚动。以下截图显示了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/df1b5ab9-fc13-4aa8-889f-e1e0294c79ea.png)

图 8.10 - 部分截图显示了在树莓派 3 上运行我们的 slab3_maxsize.ko 内核模块的 dmesg 输出的下部分

啊哈，看一下输出的最后一行（图 8.11）：`kmalloc()`在分配超过 4 MB（在 4,200,000 字节处）时失败，正如预期的那样；在那之前，它成功了。

有趣的是，注意我们故意在循环中的第一次分配中使用了大小为`0`；它没有失败：

+   `kmalloc(0, GFP_xxx);`返回零指针；在 x86[_64]上，它的值是`16`或`0x10`（详细信息请参阅`include/linux/slab.h`）。实际上，它是一个无效的虚拟地址，位于页面`0`的`NULL`指针陷阱。当然，访问它将导致页面错误（源自 MMU）。

+   同样地，尝试`kfree(NULL);`或`kfree()`零指针的结果是`kfree()`变成了一个无操作。

等等，一个非常重要的要点要注意：在*用于 kmalloc 的实际 slab 缓存*部分，我们看到用于向调用者分配内存的 slab 缓存是`kmalloc-n`slab 缓存，其中`n`的范围是`64`到`8192`字节（在树莓派上，因此对于本讨论是 ARM）。另外，FYI，您可以执行`sudo vmstat -m | grep -v "\-rcl\-" | grep --color=auto "^kmalloc"`来验证这一点。

但显然，在前面的内核模块代码示例中，我们通过`kmalloc()`分配了更大数量的内存（从 0 字节到 4 MB）。它真正的工作方式是`kmalloc()`API 仅对小于或等于 8192 字节的内存分配使用`kmalloc-'n'`slab 缓存（如果可用）；任何对更大内存块的分配请求都会传递给底层的页面（或伙伴系统）分配器！现在，回想一下我们在上一章学到的：页面分配器使用伙伴系统空闲列表（基于每个*节点:区域*）*和*在空闲列表上排队的内存块的最大尺寸为*2^((MAX_ORDER-1)) = 2¹⁰* *页*，当然，这是 4 MB（给定页面大小为 4 KB 和`MAX_ORDER`为`11`）。这与我们的理论讨论完美地结合在一起。

因此，从理论上和实践上来看，你现在可以看到（再次给定 4 KB 的页面大小和`MAX_ORDER`为`11`），通过单次调用`kmalloc()`（或`kzalloc()`）分配的内存的最大尺寸是 4 MB。

### 通过/proc/buddyinfo 伪文件检查

非常重要的是要意识到，尽管我们已经确定一次最多可以获得 4 MB 的 RAM，但这绝对不意味着你总是会得到那么多。不，当然不是。这完全取决于内存请求时特定空闲列表中的空闲内存量。想想看：如果你在运行了几天（或几周）的 Linux 系统上运行。找到物理上连续的 4 MB 的空闲 RAM 块的可能性是相当低的（再次取决于系统上的 RAM 量和其工作负载）。

作为一个经验法则，如果前面的实验没有产生我们认为的最大尺寸的最大分配（即 4 MB），为什么不在一个新启动的客户系统上尝试呢？现在，有物理上连续的 4 MB 的空闲 RAM 的机会要好得多。对此不确定？让我们再次进行实证研究，并查看`/proc/buddyinfo`的内容-在使用中和新启动的系统上-以确定内存块是否可用。在我们使用中的 x86_64 Ubuntu 客户系统上，只有 1 GB 的 RAM，我们查看到：

```
$ cat /proc/buddyinfo 
Node 0, zone      DMA    225  154   46   30   14   9   1   1   0   0   0 
Node 0, zone    DMA32    314  861  326  291  138  50  27   2   5   0   0 
  order --->               0    1    2    3    4   5   6   7   8   9  10
```

正如我们之前学到的（在*空闲列表组织*部分），在前面的代码块中看到的数字是顺序`0`到`MAX_ORDER-1`（通常是*0*到*11-1=10*），它们代表该顺序中的*2^(order)*连续空闲页框的数量。

在前面的输出中，我们可以看到我们在`10`列表（即 4 MB 块）上没有空闲块（为零）。在一个新启动的 Linux 系统上，可能性很高。在接下来的输出中，在刚刚重新启动的相同系统上，我们看到在节点`0`，DMA32 区域有 7 个空闲的物理连续的 4 MB RAM 块可用：

```
$ cat /proc/buddyinfo 
Node 0, zone      DMA      10   2    2    3   3   3   3   2   2   0   0 
Node 0, zone    DMA32     276 143  349  189  99   3   6   3   6   4   7 
 order --->                0   1    2    3   4   5   6   7   8   9  10
```

重申这一点，在一个刚刚运行了大约半小时的树莓派上，我们有以下情况：

```
rpi ~/ $ cat /proc/buddyinfo 
Node 0, zone   Normal    82   32   11   6   5   3   3   3   4   4   160
```

在这里，有 160 个 4 MB 的物理连续 RAM 块可用（空闲）。

当然，还有更多可以探索的。在接下来的部分中，我们将介绍更多关于使用板块分配器的内容 - 资源管理的 API 替代方案，可用的额外板块辅助 API，以及现代 Linux 内核中的 cgroups 和内存的注意事项。

# 板块分配器 - 一些额外的细节

还有一些关键点需要探讨。首先，关于使用内核的资源管理版本的内存分配 API 的一些信息，然后是内核内部的一些额外可用的板块辅助例程，然后简要介绍 cgroups 和内存。我们强烈建议您也阅读这些部分。请继续阅读！

## 使用内核的资源管理内存分配 API

对于设备驱动程序来说，内核提供了一些受管理的内存分配 API。这些正式称为设备资源管理或 devres API（关于此的内核文档链接是[`www.kernel.org/doc/Documentation/driver-model/devres.txt`](https://www.kernel.org/doc/Documentation/driver-model/devres.txt)）。它们都以`devm_`为前缀；虽然有几个，但我们在这里只关注一个常见用例 - 即在使用这些 API 替代通常的`k[m|z]alloc()`时。它们如下：

+   `void * devm_kmalloc(struct device *dev, size_t size, gfp_t gfp);`

+   `void * devm_kzalloc(struct device *dev, size_t size, gfp_t gfp);`

这些资源管理的 API 之所以有用，是因为*开发人员无需显式释放它们分配的内存*。内核资源管理框架保证它将在驱动程序分离时或者如果是内核模块时，在模块被移除时（或设备被分离时，以先发生者为准）自动释放内存缓冲区。这个特性立即增强了代码的健壮性。为什么？简单，我们都是人，都会犯错误。泄漏内存（尤其是在错误代码路径上）确实是一个相当常见的错误！

关于使用这些 API 的一些相关要点：

+   一个关键点 - 请不要盲目尝试用相应的`devm_k[m|z]alloc()`替换`k[m|z]alloc()`！这些受资源管理的分配实际上只设计用于设备驱动程序的`init`和/或`probe()`方法（所有与内核统一设备模型一起工作的驱动程序通常会提供`probe()`和`remove()`（或`disconnect()`）方法。我们将不在这里深入讨论这些方面）。

+   `devm_kzalloc()`通常更受欢迎，因为它也初始化缓冲区。在内部（与`kzalloc()`一样），它只是`devm_kmalloc()` API 的一个薄包装器。

+   第二个和第三个参数与`k[m|z]alloc()` API 一样 - 要分配的字节数和要使用的 GFP 标志。不过，第一个参数是指向`struct device`的指针。显然，它代表您的驱动程序正在驱动的*设备*。

+   由这些 API 分配的内存是自动释放的（在驱动程序分离或模块移除时），您不必做任何事情。但是，它可以通过`devm_kfree()` API 释放。不过，您这样做通常表明受管理的 API 不是正确的选择...

+   许可：受管理的 API 仅对在 GPL 下许可的模块（以及其他可能的许可）可用。

## 额外的板块辅助 API

还有几个辅助的板块分配器 API，是`k[m|z]alloc()` API 家族的朋友。这些包括用于为数组分配内存的`kcalloc()`和`kmalloc_array()` API，以及`krealloc()`，其行为类似于熟悉的用户空间 API`realloc(3)`。

与为元素数组分配内存一起，`array_size()`和`struct_size()`内核辅助程序非常有帮助。特别是，`struct_size()`已被广泛用于防止（实际上修复）在分配结构数组时的许多整数溢出（以及相关）错误，这确实是一个常见的任务。作为一个快速的例子，这里是来自`net/bluetooth/mgmt.c`的一个小代码片段：

```
rp = kmalloc(struct_size(rp, addr, i), GFP_KERNEL);
 if (!rp) {
     err = -ENOMEM; [...]
```

值得浏览一下`include/linux/overflow.h`内核头文件。

`kzfree()`类似于`kfree()`，但会清零（可能更大的）被释放的内存区域。（为什么更大？这将在下一节中解释。）请注意，这被认为是一种安全措施，但可能会影响性能。

这些 API 的资源管理版本也是可用的：`devm_kcalloc()`和`devm_kmalloc_array()`。

## 控制组和内存

Linux 内核支持一个非常复杂的资源管理系统，称为**cgroups**（控制组），简而言之，它们用于分层组织进程并执行资源管理（有关 cgroups 的更多信息，以及 cgroups v2 CPU 控制器用法示例，可以在第十一章中找到，*CPU 调度器-第二部分*，关于 CPU 调度）。

在几个资源控制器中，有一个用于内存带宽的控制器。通过仔细配置它，系统管理员可以有效地调节系统上内存的分配。内存保护是可能的，既可以作为（所谓的）硬保护，也可以通过某些`memcg`（内存 cgroup）伪文件（特别是`memory.min`和`memory.low`文件）作为尽力保护。类似地，在 cgroup 内，`memory.high`和`memory.max`伪文件是控制 cgroup 内存使用的主要机制。当然，这里提到的远不止这些，我建议你查阅有关新 cgroups（v2）的内核文档：[`www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html`](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)。

好的，现在你已经学会了如何更好地使用 slab 分配器 API，让我们再深入一点。事实是，关于 slab 分配器 API 分配的内存块大小仍然有一些重要的注意事项。继续阅读以了解它们是什么！

# 使用 slab 分配器时的注意事项

我们将把这个讨论分成三部分。我们将首先重新审视一些必要的背景（我们之前已经涵盖了），然后实际上详细说明两个用例的问题-第一个非常简单，第二个是问题的更真实的案例。

## 背景细节和结论

到目前为止，你已经学到了一些关键点：

+   *页面*（或*buddy 系统*）*分配器*向调用者分配 2 的幂次方页。要提高 2 的幂次方，称为*阶*；它通常范围从`0`到`10`（在 x86[_64]和 ARM 上都是如此）。

+   这很好，除非不是。当请求的内存量非常小时，*浪费*（或内部碎片）可能会很大。

+   对于页面的片段请求（小于 4,096 字节）非常常见。因此，*slab 分配器，叠加在页面分配器上*（见图 8.1）被设计为具有对象缓存，以及小的通用内存缓存，以有效地满足对小内存量的请求。

+   页面分配器保证物理上连续的页面和高速缓存对齐的内存。

+   slab 分配器保证物理上连续和高速缓存对齐的内存。

因此，很棒-这让我们得出结论，当需要的内存量较大且接近 2 的幂时，请使用页面分配器。当内存量相当小（小于一页）时，请使用 slab 分配器。事实上，`kmalloc()`的内核源代码中有一条注释，简洁地总结了应该如何使用`kmalloc()` API（如下所示以粗体字重现）：

```
// include/linux/slab.h
[...]
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 * kmalloc is the normal method of allocating memory
 * for objects smaller than page size in the kernel.
```

听起来很棒，但还有一个问题！为了看到它，让我们学习如何使用另一个有用的 slab API，`ksize()`。它的签名如下：

```
size_t ksize(const void *);
```

`ksize()`的参数是指向现有 slab 缓存的指针（它必须是有效的）。换句话说，它是 slab 分配器 API 的返回地址（通常是`k[m|z]alloc()`）。返回值是分配的实际字节数。

好的，现在你知道`ksize()`的用途，让我们首先以一种更实际的方式使用它，然后再用一个更好的方式！

## 使用 ksize()测试 slab 分配 - 情况 1

为了理解我们的意思，考虑一个小例子（为了可读性，我们不会显示必要的有效性检查。此外，由于这是一个小的代码片段，我们没有将其提供为书中代码库中的内核模块）：

```
struct mysmallctx {
    int tx, rx;
    char passwd[8], config[4];
} *ctx;

pr_info("sizeof struct mysmallctx = %zd bytes\n", sizeof(struct mysmallctx));
ctx = kzalloc(sizeof(struct mysmallctx), GFP_KERNEL);
pr_info("(context structure allocated and initialized to zero)\n"
        "*actual* size allocated = %zu bytes\n", ksize(ctx));
```

在我的 x86_64 Ubuntu 虚拟机系统上的结果输出如下：

```
$ dmesg
[...]
sizeof struct mysmallctx = 20 bytes
(context structure allocated and initialized to zero)
*actual* size allocated = 32 bytes
```

因此，我们尝试使用`kzalloc()`分配 20 字节，但实际上获得了 32 字节（因此浪费了 12 字节，或 60％！）。这是预期的。回想一下`kmalloc-n` slab 缓存 - 在 x86 上，有一个用于 16 字节的缓存，另一个用于 32 字节（还有许多其他）。因此，当我们要求介于两者之间的数量时，显然会从两者中较大的一个获取内存。（顺便说一句，在我们基于 ARM 的树莓派系统上，`kmalloc`的最小 slab 缓存是 64 字节，因此当我们要求 20 字节时，我们当然会得到 64 字节。）

请注意，`ksize()` API 仅适用于已分配的 slab 内存；您不能将其用于任何页分配器 API 的返回值（我们在*理解和使用内核页分配器（或 BSA）*部分中看到）。

现在是第二个更有趣的用例。

## 使用 ksize()测试 slab 分配 - 情况 2

好的，现在，让我们扩展我们之前的内核模块（`ch8/slab3_maxsize`）到`ch8/slab4_actualsize`。在这里，我们将执行相同的循环，使用`kmalloc()`分配内存并像以前一样释放它，但这一次，我们还将通过调用`ksize()`API 记录由 slab 层在每个循环迭代中分配给我们的实际内存量：

```
// ch8/slab4_actualsize/slab4_actualsize.c
static int test_maxallocsz(void)
{
    size_t size2alloc = 100, actual_alloced;
    void *p;

    pr_info("kmalloc(      n) :  Actual : Wastage : Waste %%\n");
    while (1) {
        p = kmalloc(size2alloc, GFP_KERNEL);
        if (!p) {
            pr_alert("kmalloc fail, size2alloc=%zu\n", size2alloc);
            return -ENOMEM;
        }
        actual_alloced = ksize(p);
        /* Print the size2alloc, the amount actually allocated,
         * the delta between the two, and the percentage of waste
         * (integer arithmetic, of course :-)  */
        pr_info("kmalloc(%7zu) : %7zu : %7zu : %3zu%%\n",
              size2alloc, actual_alloced, (actual_alloced-size2alloc),
              (((actual_alloced-size2alloc)*100)/size2alloc));        kfree(p);
        size2alloc += stepsz;
    }
    return 0;
}
```

这个内核模块的输出确实很有趣！在下图中，我们展示了我在运行我们自定义构建的 5.4.0 内核的 x86_64 Ubuntu 18.04 LTS 虚拟机上获得的输出的部分截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/bdf32434-baf3-4fa3-a64f-7327729d0c8a.png)

图 8.11 - slab4_actualsize.ko 内核模块的部分截图

内核模块的`printk`输出可以在前面的截图中清楚地看到。屏幕的其余部分是内核的诊断信息 - 这是因为内核空间内存分配请求失败而发出的。所有这些内核诊断信息都是由内核调用`WARN_ONCE()`宏的第一次调用产生的，因为底层页分配器代码`mm/page_alloc.c:__alloc_pages_nodemask()` - 众所周知的伙伴系统分配器的“核心” - 失败了！这通常不应该发生，因此有诊断信息（内核诊断的详细信息超出了本书的范围，因此我们将不予讨论。话虽如此，我们在接下来的章节中确实会在一定程度上检查内核堆栈回溯）。

### 解释情况 2 的输出

仔细看前面的截图（图 8.12；在这里，我们将简单地忽略由`WARN()`宏发出的内核诊断，因为内核级内存分配失败而调用了它！）。图 8.12 的输出有五列，如下：

+   来自`dmesg(1)`的时间戳；我们忽略它。

+   `kmalloc(n)`：`kmalloc()`请求的字节数（其中`n`是所需的数量）。

+   由 slab 分配器分配的实际字节数（通过`ksize()`揭示）。

+   浪费（字节）：实际字节和所需字节之间的差异。

+   浪费的百分比。

例如，在第二次分配中，我们请求了 200,100 字节，但实际获得了 262,144 字节（256 KB）。这是有道理的，因为这是伙伴系统空闲列表中的一个页面分配器列表的确切大小（它是*6 阶*，因为*2⁶ = 64 页 = 64 x 4 = 256 KB*；参见*图 8.2*）。因此，差值，或者实际上是浪费，是*262,144 - 200,100 = 62,044 字节*，以百分比表示，为 31%。

就像这样：请求的（或所需的）大小越接近内核可用的（或实际的）大小，浪费就越少；反之亦然。让我们从前面的输出中再看一个例子（为了清晰起见，以下是剪辑输出）：

```
[...]
[92.273695] kmalloc(1600100) : 2097152 :  497052 : 31%
[92.274337] kmalloc(1800100) : 2097152 :  297052 : 16%
[92.275292] kmalloc(2000100) : 2097152 :   97052 :  4%
[92.276297] kmalloc(2200100) : 4194304 : 1994204 : 90%
[92.277015] kmalloc(2400100) : 4194304 : 1794204 : 74%
[92.277698] kmalloc(2600100) : 4194304 : 1594204 : 61%
[...]
```

从前面的输出中，您可以看到当`kmalloc()`请求 1,600,100 字节（大约 1.5 MB）时，实际上获得了 2,097,152 字节（确切的 2 MB），浪费为 31%。随着我们接近分配的“边界”或阈值（内核的 slab 缓存或页面分配器内存块的实际大小）*，浪费逐渐减少：到 16%，然后降至 4%。但是请注意：在下一个分配中，当我们跨越该阈值，要求*略高于*2 MB（2,200,100 字节）时，我们实际上获得了 4 MB，*浪费了 90%*！然后，随着我们接近 4 MB 的内存大小，浪费再次减少...

这很重要！您可能认为仅通过使用 slab 分配器 API 非常高效，但实际上，当请求的内存量超过 slab 层可以提供的最大大小时（通常为 8 KB，在我们之前的实验中经常出现），slab 层会调用页面分配器。因此，页面分配器由于通常的浪费问题，最终分配的内存远远超过您实际需要的，或者实际上永远不会使用的。多么浪费！

寓言：*检查并反复检查使用 slab API 分配内存的代码*。使用`ksize()`对其进行试验，以找出实际分配了多少内存，而不是您认为分配了多少内存。

没有捷径。嗯，有一个：如果您需要的内存少于一页（非常典型的用例），只需使用 slab API。如果需要更多，前面的讨论就会起作用。另一件事：使用`alloc_pages_exact() / free_pages_exact()` API（在*一个解决方案 - 精确页面分配器 API*部分中介绍）也应该有助于减少浪费。

### 绘图

有趣的是，我们使用著名的`gnuplot(1)`实用程序从先前收集的数据绘制图形。实际上，我们必须最小限度地修改内核模块，只输出我们想要绘制的内容：要分配的内存量（*x*轴），以及运行时实际发生的浪费百分比（*y*轴）。您可以在书的 GitHub 存储库中找到我们略微修改的内核模块的代码，链接在这里：`ch8/slab4_actualsize`（[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/ch8/slab4_actualsize`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/ch8/slab4_actualsize)）。

因此，我们构建并插入这个内核模块，“整理”内核日志，将数据保存在`gnuplot`所需的适当的列格式中（保存在名为`2plotdata.txt`的文件中）。虽然我们不打算在这里深入讨论如何使用`gnuplot(1)`（请参阅*进一步阅读*部分以获取教程链接），但在以下代码片段中，我们展示了生成图形的基本命令：

```
gnuplot> set title "Slab/Page Allocator: Requested vs Actually allocated size Wastage in Percent"
gnuplot> set xlabel "Required size"
gnuplot> set ylabel "%age Waste"
gnuplot> plot "2plotdata.txt" using 1:100 title "Required Size" with points, "2plotdata.txt" title "Wastage %age" with linespoints 
gnuplot> 
```

看哪，图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/f0680fcb-f728-4941-a8ea-c00a301d1e8b.png)

图 8.12 - 显示 kmalloc()请求的大小（x 轴）与产生的浪费（作为百分比；y 轴）的图形

这个“锯齿”形状的图表有助于可视化您刚刚学到的内容。一个`kmalloc()`（或`kzalloc()`，或者*任何*页面分配器 API）分配请求的大小越接近内核预定义的空闲列表大小，浪费就越少。但一旦超过这个阈值，浪费就会飙升（尖峰），接近 100%（如前图中的垂直线所示）。

因此，我们已经涵盖了大量的内容。然而，我们还没有完成：下一节非常简要地介绍了内核中实际的 slab 层实现（是的，有几种）。让我们来看看吧！

## 内核中的 Slab 层实现

最后，我们提到了一个事实，即至少有三种不同的互斥的内核级 slab 分配器实现；在运行时只能使用其中一种。在*配置*内核时选择在运行时使用的分配器（您在第二章中详细了解了此过程，*从源代码构建 5.x Linux 内核-第一部分*）。相关的内核配置选项如下：

+   `CONFIG_SLAB`

+   `CONFIG_SLUB`

+   `CONFIG_SLOB`

第一个（`SLAB`）是早期的、得到很好支持（但相当未优化）的分配器；第二个（`SLUB`，未排队的分配器）在内存效率、性能和诊断方面是对第一个的重大改进，并且是默认选择的分配器。`SLOB`分配器是一种极端简化，根据内核配置帮助，“在大型系统上表现不佳”。

# 摘要

在本章中，您详细了解了页面（或伙伴系统）和 slab 分配器的工作原理。请记住，内核内部分配（和释放）RAM 的实际“引擎”最终是*页面（或伙伴系统）分配器*，slab 分配器则在其上层提供了对典型小于页面大小的分配请求的优化，并有效地分配了几种众所周知的内核数据结构（“对象”）。

您学会了如何有效地使用页面和 slab 分配器提供的 API，以及几个演示内核模块，以便以实际操作的方式展示这一点。我们非常正确地关注了开发人员发出对某个*N*字节数的内存请求的实际问题，但您学会了这可能是非常次优的，因为内核实际上分配了更多的内存（浪费可能接近 100%）！现在您知道如何检查和减轻这些情况。干得好！

以下章节涵盖了更多关于最佳分配策略的内容，以及有关内核内存分配的一些更高级主题，包括创建自定义 slab 缓存，使用`vmalloc`接口，以及*OOM killer*的相关内容等。因此，首先确保您已经理解了本章的内容，并且已经完成了内核模块和作业（如下所示）。然后，让我们继续下一章吧！

# 问题

随着我们的结束，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会在书的 GitHub 存储库中找到一些问题的答案：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入了解这个主题并提供有用的材料，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）。*进一步阅读*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。


# 第九章：模块作者的内核内存分配-第二部分

上一章详细介绍了通过内核中的页面（BSA）和 slab 分配器进行内存分配的可用 API 的基础知识（以及更多！）。在本章中，我们将进一步深入探讨这个广泛而有趣的主题。我们将涵盖创建自定义 slab 缓存、`vmalloc`接口，以及非常重要的是，鉴于选择的丰富性，应在哪种情况下使用哪些 API。关于令人恐惧的**内存不足**（**OOM**）杀手和需求分页的内部内核细节有助于完善这些重要主题。

这些领域往往是在处理内核模块时理解的关键方面之一，特别是设备驱动程序。一个 Linux 系统项目突然崩溃，控制台上只有一个`Killed`消息，需要一些解释，对吧！？OOM 杀手就是背后的甜蜜家伙...

简而言之，在本章中，主要涵盖了以下主要领域：

+   创建自定义 slab 缓存

+   在 slab 层进行调试

+   理解和使用内核 vmalloc()API

+   内核中的内存分配-何时使用哪些 API

+   保持存活- OOM 杀手

# 技术要求

我假设您已经阅读了第一章，*内核工作空间设置*，并已经适当地准备了一个运行 Ubuntu 18.04 LTS（或更高稳定版本）的虚拟机，并安装了所有必需的软件包。如果没有，我强烈建议您首先这样做。

此外，本章的最后一节让您故意运行一个*非常*占用内存的应用程序；如此占用内存以至于内核将采取一些极端的行动！显然，我强烈建议您在一个安全的、隔离的系统上尝试这样的东西，最好是一个 Linux 测试虚拟机（上面没有重要数据）。

为了充分利用本书，我强烈建议您首先设置工作空间

环境，包括克隆本书的 GitHub 存储库以获取代码，并以实际操作的方式进行工作。GitHub 存储库可以在[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)找到。

# 创建自定义 slab 缓存

如前一章节中详细解释的，slab 缓存背后的关键设计概念是对象缓存的强大理念。通过缓存频繁使用的对象-实际上是数据结构-性能得到提升。因此，想象一下：如果我们正在编写一个驱动程序，在该驱动程序中，某个数据结构（对象）被非常频繁地分配和释放？通常，我们会使用通常的`kzalloc()`（或`kmalloc()`）然后是`kfree()`API 来分配和释放这个对象。不过好消息是：Linux 内核充分地向我们模块作者公开了 slab 层 API，允许我们创建*我们自己的自定义 slab 缓存*。在本节中，您将学习如何利用这一强大功能。

## 在内核模块中创建和使用自定义 slab 缓存

在本节中，我们将创建，使用和随后销毁自定义 slab 缓存。在广义上，我们将执行以下步骤：

1.  使用`kmem_cache_create()`API 创建给定大小的自定义 slab 缓存。这通常作为内核模块的初始化代码路径的一部分进行（或者在驱动程序中的探测方法中进行）。

1.  使用 slab 缓存。在这里我们将做以下事情：

1.  使用`kmem_cache_alloc()`API 来分配自定义对象的单个实例在您的 slab 缓存中。

1.  使用对象。

1.  使用`kmem_cache_free()`API 将其释放回缓存。

1.  使用`kmem_cache_destroy()`在完成后销毁自定义 slab 缓存。这通常作为内核模块的清理代码路径的一部分进行（或者在驱动程序中的删除/分离/断开方法中进行）。

让我们稍微详细地探讨这些 API 中的每一个。我们从创建自定义（slab）缓存开始。

### 创建自定义 slab 缓存

首先，当然，让我们学习如何创建自定义的 slab 缓存。`kmem_cache_create()`内核 API 的签名如下：

```
#include <linux/slab.h>
struct kmem_cache *kmem_cache_create(const char *name, unsigned int size,  
           unsigned int align, slab_flags_t flags, void (*ctor)(void *));
```

第一个参数是缓存的*名称* - 将由`proc`（因此也由`proc`上的其他包装工具，如`vmstat(8)`，`slabtop(1)`等）显示。它通常与被缓存的数据结构或对象的名称匹配（但不一定要匹配）。

第二个参数`size`实际上是关键的参数-它是新缓存中每个对象的字节大小。基于此对象大小（使用最佳适配算法），内核的 slab 层构造了一个对象缓存。由于三个原因，缓存内每个对象的实际大小将比请求的稍大：

+   一，我们总是可以提供更多，但绝不会比请求的内存少。

+   二，需要一些用于元数据（管理信息）的空间。

+   第三，内核在能够提供所需确切大小的缓存方面存在限制。它使用最接近的可能匹配大小的内存（回想一下第八章，*模块作者的内核内存分配-第一部分*，在*使用 slab 分配器时的注意事项*部分，我们清楚地看到实际上可能使用更多（有时是很多！）内存）。

回想一下第八章，*模块作者的内核内存分配-第一部分*，`ksize()`API 可用于查询分配对象的实际大小。还有另一个 API，我们可以查询新 slab 缓存中个别对象的大小：

`unsigned int kmem_cache_size(struct kmem_cache *s);`。您很快将看到这个被使用。

第三个参数`align`是缓存内对象所需的*对齐*。如果不重要，只需将其传递为`0`。然而，通常有非常特定的对齐要求，例如，确保对象对齐到机器上的字大小（32 位或 64 位）。为此，将值传递为`sizeof(long)`（此参数的单位是字节，而不是位）。

第四个参数`flags`可以是`0`（表示没有特殊行为），也可以是以下标志值的按位或运算符。为了清晰起见，我们直接从源文件`mm/slab_common.c`的注释中复制以下标志的信息：

```
// mm/slab_common.c
[...]
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialized memory.
 *
 * %SLAB_RED_ZONE - Insert `Red` zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline. This can be beneficial if you're counting cycles as closely
 * as davem.
[...]
```

让我们快速检查一下标志：

+   第一个标志`SLAB_POISON`提供了 slab 毒化，即将缓存内存初始化为先前已知的值（`0xa5a5a5a5`）。这样做可以在调试情况下有所帮助。

+   第二个标志`SLAB_RED_ZONE`很有趣，它在分配的缓冲区周围插入红色区域（类似于保护页面）。这是检查缓冲区溢出错误的常见方法。它几乎总是在调试环境中使用（通常在开发过程中）。

+   第三个可能的标志`SLAB_HWCACHE_ALIGN`非常常用，实际上也是性能推荐的。它保证所有缓存对象都对齐到硬件（CPU）缓存行大小。这正是通过流行的`k[m|z]alloc()`API 分配的内存如何对齐到硬件（CPU）缓存行的。

最后，`kmem_cache_create()`的第五个参数也非常有趣：一个函数指针，`void (*ctor)(void *);`。它被建模为一个*构造函数*（就像面向对象和 OOP 语言中的构造函数）。它方便地允许您在分配时从自定义 slab 缓存初始化 slab 对象！作为内核中此功能的一个示例，请参阅名为`integrity`的**Linux 安全模块**（**LSM**）的代码：

```
 security/integrity/iint.c:integrity_iintcache_init()
```

它调用以下内容：

```
iint_cache = kmem_cache_create("iint_cache", sizeof(struct integrity_iint_cache),
 0, SLAB_PANIC, init_once);
```

`init_once()`函数初始化了刚刚分配的缓存对象实例。请记住，构造函数在此缓存分配新页面时被调用。

尽管这似乎有些违直觉，但事实是现代 Linux 内核在设计方面相当面向对象。当然，代码大多是传统的过程式语言 C。然而，在内核中有大量的架构实现（驱动程序模型是其中之一）在设计上是面向对象的：通过虚拟函数指针表进行方法分派 - 策略设计模式等。在 LWN 上有一篇关于此的两部分文章，详细介绍了这一点：*内核中的面向对象设计模式，第一部分，2011 年 6 月*（[`lwn.net/Articles/444910/`](https://lwn.net/Articles/444910/)）。

`kmem_cache_create()` API 的返回值在成功时是指向新创建的自定义 slab 缓存的指针，失败时是`NULL`。通常会将此指针保持为全局，因为您将需要访问它以实际从中分配对象（我们的下一步）。

重要的是要理解`kmem_cache_create()` API 只能从进程上下文中调用。许多内核代码（包括许多驱动程序）创建并使用自己的自定义 slab 缓存。例如，在 5.4.0 Linux 内核中，有超过 350 个实例调用了此 API。

好了，现在您有了一个自定义（slab）缓存，那么您究竟如何使用它来分配内存对象呢？接下来的部分将详细介绍这一点。

### 使用新的 slab 缓存的内存

好吧，我们创建了一个自定义的 slab 缓存。要使用它，您必须发出`kmem_cache_alloc()` API。它的作用是：给定一个 slab 缓存的指针（您刚刚创建的），它在该 slab 缓存上分配一个对象的单个实例（实际上，这确实是`k[m|z]alloc()` API 在底层是如何工作的）。它的签名如下（当然，记得始终为所有基于 slab 的 API 包含`<linux/slab.h>`头文件）：

```
void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags);
```

让我们看看它的参数：

+   `kmem_cache_alloc()`的第一个参数是指向我们在上一步中创建的（自定义）缓存的指针（从`kmem_cache_create()` API 的返回值）。

+   第二个参数是要传递的通常的 GFP 标志（记住基本规则：对于正常的进程上下文分配，请使用`GFP_KERNEL`，否则如果处于任何类型的原子或中断上下文中，请使用`GFP_ATOMIC`）。

与现在熟悉的`k[m|z]alloc()` API 一样，返回值是指向新分配的内存块的指针 - 内核逻辑地址（当然是 KVA）。

使用新分配的内存对象，并在完成后，不要忘记使用以下方法释放它：

```
void kmem_cache_free(struct kmem_cache *, void *);
```

在这里，关于`kmem_cache_free()` API，请注意以下内容：

+   `kmem_cache_free()`的第一个参数再次是指向您在上一步中创建的（自定义）slab 缓存的指针（从`kmem_cache_create()`的返回值）。

+   第二个参数是指向您希望释放的内存对象的指针 - 刚刚使用`kmem_cache_alloc()`分配的对象实例 - 因此，它将返回到由第一个参数指定的缓存！

与`k[z]free()` API 类似，没有返回值。

### 销毁自定义缓存

当完全完成时（通常在内核模块的清理或退出代码路径中，或者您的驱动程序的`remove`方法中），您必须销毁先前创建的自定义 slab 缓存，使用以下行：

```
void kmem_cache_destroy(struct kmem_cache *);
```

参数当然是指向您在上一步中创建的（自定义）缓存的指针（从`kmem_cache_create()` API 的返回值）。

现在您已经了解了该过程及其相关的 API，让我们来使用一个创建自己的自定义 slab 缓存的内核模块，并在完成后销毁它。

## 自定义 slab - 演示内核模块

是时候动手写一些代码了！让我们看一个简单的演示，使用前面的 API 来创建我们自己的自定义 slab 缓存。像往常一样，我们这里只显示相关的代码。我建议您克隆本书的 GitHub 存储库并自己尝试一下！您可以在`ch9/slab_custom/slab_custom.c`中找到此文件的代码。

在我们的初始化代码路径中，我们首先调用以下函数来创建我们的自定义 slab 缓存：

```
// ch9/slab_custom/slab_custom.c
#define OURCACHENAME   "our_ctx"
/* Our 'demo' structure, that (we imagine) is often allocated and freed;
 * hence, we create a custom slab cache to hold pre-allocated 'instances'
 * of it... Its size: 328 bytes.
 */
struct myctx {
    u32 iarr[10];
    u64 uarr[10];
    char uname[128], passwd[16], config[64];
};
static struct kmem_cache *gctx_cachep; 
```

在上述代码中，我们声明了一个（全局）指针（`gctx_cachep`）指向即将创建的自定义 slab 缓存 - 它将保存对象；即我们虚构的经常分配的数据结构`myctx`。

接下来，看看创建自定义 slab 缓存的代码：

```
static int create_our_cache(void)
{
    int ret = 0;
    void *ctor_fn = NULL;

    if (use_ctor == 1)
        ctor_fn = our_ctor;
    pr_info("sizeof our ctx structure is %zu bytes\n"
            " using custom constructor routine? %s\n",
            sizeof(struct myctx), use_ctor==1?"yes":"no");

  /* Create a new slab cache:
   * kmem_cache_create(const char *name, unsigned int size, unsigned int 
      align, slab_flags_t flags, void (*ctor)(void *));  */
    gctx_cachep = kmem_cache_create(OURCACHENAME, // name of our cache
          sizeof(struct myctx), // (min) size of each object
          sizeof(long),         // alignment
          SLAB_POISON |         /* use slab poison values (explained soon) */
          SLAB_RED_ZONE |       /* good for catching buffer under|over-flow bugs */
          SLAB_HWCACHE_ALIGN,   /* good for performance */
          ctor_fn);             // ctor: here, on by default

  if (!gctx_cachep) {
        [...]
        if (IS_ERR(gctx_cachep))
            ret = PTR_ERR(gctx_cachep);
  }
  return ret;
}
```

嘿，这很有趣：注意我们的缓存创建 API 提供了一个构造函数来帮助初始化任何新分配的对象；在这里：

```
/* The parameter is the pointer to the just allocated memory 'object' from
 * our custom slab cache; here, this is our 'constructor' routine; so, we
 * initialize our just allocated memory object.
 */
static void our_ctor(void *new)
{
    struct myctx *ctx = new;
    struct task_struct *p = current;

    /* TIP: to see how exactly we got here, insert this call:
     *  dump_stack();
     * (read it bottom-up ignoring call frames that begin with '?') */
    pr_info("in ctor: just alloced mem object is @ 0x%llx\n", ctx);

    memset(ctx, 0, sizeof(struct myctx));
    /* As a demo, we init the 'config' field of our structure to some
     * (arbitrary) 'accounting' values from our task_struct
     */
    snprintf(ctx->config, 6*sizeof(u64)+5, "%d.%d,%ld.%ld,%ld,%ld",
            p->tgid, p->pid,
            p->nvcsw, p->nivcsw, p->min_flt, p->maj_flt);
}
```

上述代码中的注释是不言自明的；请仔细查看。构造函数例程，如果设置（取决于我们`use_ctor`模块参数的值；默认为`1`），将在内核每当为我们的缓存分配新内存对象时自动调用。

在初始化代码路径中，我们调用`use_our_cache()`函数。它通过`kmem_cache_alloc()`API 分配了我们的`myctx`对象的一个实例，如果我们的自定义构造函数例程已启用，它会运行，初始化对象。然后我们将其内存转储以显示它确实按照编码进行了初始化，并在完成时释放它（为简洁起见，我们将不显示错误代码路径）：

```
    obj = kmem_cache_alloc(gctx_cachep, GFP_KERNEL);
    pr_info("Our cache object size is %u bytes; ksize=%lu\n",
            kmem_cache_size(gctx_cachep), ksize(obj));
    print_hex_dump_bytes("obj: ", DUMP_PREFIX_OFFSET, obj, sizeof(struct myctx));
 kmem_cache_free(gctx_cachep, obj);
```

最后，在退出代码路径中，我们销毁我们的自定义 slab 缓存：

```
kmem_cache_destroy(gctx_cachep);
```

来自一个样本运行的以下输出帮助我们理解它是如何工作的。以下只是部分截图，显示了我们的 x86_64 Ubuntu 18.04 LTS 客户机上运行 Linux 5.4 内核的输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/2a679dea-0e4b-4978-9faf-e3dd880fa594.png)

图 9.1 - 在 x86_64 VM 上的 slab_custom 内核模块的输出

太棒了！等一下，这里有几个要注意的关键点：

+   由于我们的构造函数例程默认启用（我们的`use_ctor`模块参数的值为`1`），每当内核 slab 层为我们的新缓存分配新对象实例时，它都会运行。在这里，我们只执行了一个`kmem_cache_alloc()`，但我们的构造函数例程已经运行了 21 次，这意味着内核的 slab 代码（预）分配了 21 个对象给我们的全新缓存！当然，这个数字会有所变化。

+   第二，非常重要的一点要注意！如前面的截图所示，每个对象的*大小*似乎是 328 字节（由`sizeof()`、`kmem_cache_size()`和`ksize()`显示）。然而，再次强调，这并不是真的！内核分配的对象的实际大小更大；我们可以通过`vmstat(8)`看到这一点。

```
$ sudo vmstat -m | head -n1
Cache                       Num  Total  Size  Pages
$ sudo vmstat -m | grep our_ctx
our_ctx                       0     21   768     21
$ 
```

正如我们之前看到的那样，每个分配的对象的实际大小不是 328 字节，而是 768 字节（确切的数字会有所变化；在一个案例中，我看到它是 448 字节）。这对您来说是很重要的，确实需要检查。我们在接下来的*在 slab 层调试*部分中展示了另一种相当容易检查这一点的方法。

FYI，您可以随时查看`vmstat(8)`的 man 页面，以了解先前看到的每一列的确切含义。

我们将用 slab 收缩器接口结束关于创建和使用自定义 slab 缓存的讨论。

## 理解 slab 收缩器

缓存对性能有利。想象一下从磁盘读取大文件的内容与从 RAM 读取其内容的情况。毫无疑问，基于 RAM 的 I/O 要快得多！可以想象，Linux 内核利用这些想法，因此维护了几个缓存-页面缓存、目录项缓存、索引节点缓存、slab 缓存等等。这些缓存确实极大地提高了性能，但是，仔细想想，实际上并不是强制性要求。当内存压力达到较高水平时（意味着使用的内存过多，可用内存过少），Linux 内核有机制智能地释放缓存（也称为内存回收-这是一个持续进行的过程；内核线程（通常命名为`kswapd*`）作为其管理任务的一部分回收内存；在*回收内存-内核管理任务和*OOM*部分中会更多地介绍）。

在 slab 缓存的情况下，事实上是一些内核子系统和驱动程序会像我们在本章前面讨论的那样创建自己的自定义 slab 缓存。为了与内核良好集成并合作，最佳实践要求您的自定义 slab 缓存代码应该注册一个 shrinker 接口。当这样做时，当内存压力足够高时，内核可能会调用多个 slab 收缩器回调，预期通过释放（收缩）slab 对象来缓解内存压力。

与内核注册 shrinker 函数的 API 是`register_shrinker()`API。它的单个参数（截至 Linux 5.4）是指向`shrinker`结构的指针。该结构包含（除其他管理成员外）两个回调例程：

+   第一个例程`count_objects()`仅计算并返回将要释放的对象的数量（当实际调用时）。如果返回`0`，这意味着现在无法确定可释放的内存对象的数量，或者我们现在甚至不应该尝试释放任何对象。

+   第二个例程`scan_objects()`仅在第一个回调例程返回非零值时调用；当 slab 缓存层调用它时，它实际上释放或收缩了相关的 slab 缓存。它返回在此回收周期中实际释放的对象数量，或者如果回收尝试无法进行（可能会导致死锁）则返回`SHRINK_STOP`。

我们现在将通过快速总结使用此层进行内存（解）分配的利弊来结束对 slab 层的讨论-对于您作为内核/驱动程序作者来说，这是非常重要的，需要敏锐意识到！

## slab 分配器-利弊-总结

在本节中，我们非常简要地总结了您现在已经学到的内容。这旨在让您快速查阅和回顾这些关键要点！

使用 slab 分配器（或 slab 缓存）API 来分配和释放内核内存的优点如下：

+   （非常）快速（因为它使用预缓存的内存对象）。

+   保证物理上连续的内存块。

+   当创建缓存时使用`SLAB_HWCACHE_ALIGN`标志时，保证硬件（CPU）缓存行对齐的内存。这适用于`kmalloc()`、`kzalloc()`等。

+   您可以为特定（频繁分配/释放）对象创建自定义的 slab 缓存。

使用 slab 分配器（或 slab 缓存）API 的缺点如下：

+   一次只能分配有限数量的内存；通常，通过 slab 接口直接分配 8 KB，或者通过大多数当前平台上的页面分配器间接分配高达 4 MB 的内存（当然，精确的上限取决于架构）。

+   使用`k[m|z]alloc()`API 不正确：请求过多的内存，或者请求一个略高于阈值的内存大小（在第八章中详细讨论，*内核内存分配给模块作者-第一部分*，在*kmalloc API 的大小限制*部分），肯定会导致内部碎片（浪费）。它的设计只是真正优化常见情况-分配小于一页大小的内存。

现在，让我们继续讨论另一个对于内核/驱动程序开发人员来说非常关键的方面-当内存分配/释放出现问题时，特别是在 slab 层内部。

# 在 slab 层调试

内存损坏不幸地是错误的一个非常常见的根本原因。能够调试它们是一个关键的技能。我们现在将看一下一些处理这个问题的方法。在深入细节之前，请记住，以下讨论是关于*SLUB*（未排队的分配器）实现的 slab 层。这是大多数 Linux 安装的默认设置（我们在第八章中提到，内核内存分配给模块作者-第一部分，*内核内存分配给模块作者-第一部分*，在*内核中的 slab 层实现*部分，当前的 Linux 内核有三个互斥的 slab 层实现）。

此外，我们的意图并不是深入讨论关于内存调试的内核调试工具-这本身就是一个庞大的话题，不幸的是超出了本书的范围。尽管如此，我会说你最好熟悉已经提到的强大框架/工具，特别是以下内容：

+   **KASAN**（**内核地址消毒剂**；从 x86_64 和 AArch64，4.x 内核开始可用）

+   SLUB 调试技术（在这里介绍）

+   `kmemleak`（尽管 KASAN 更好）

+   `kmemcheck`（请注意，`kmemcheck`在 Linux 4.15 中被移除）

不要忘记在*进一步阅读*部分寻找这些链接。好的，让我们来看看一些有用的方法，帮助开发人员在 slab 层调试代码。

## 通过 slab 毒害调试

一个非常有用的功能是所谓的 slab 毒害。在这种情况下，“毒害”一词意味着用特定的签名字节或易于识别的模式刺激内存。然而，使用这个的前提是`CONFIG_SLUB_DEBUG`内核配置选项是开启的。你怎么检查？简单：

```
$ grep -w CONFIG_SLUB_DEBUG /boot/config-5.4.0-llkd01
CONFIG_SLUB_DEBUG=y
```

在前面的代码中看到的`=y`表示它确实是开启的。现在（假设它已经开启），如果你使用`SLAB_POISON`标志创建一个 slab 缓存（我们在*创建自定义 slab 缓存*部分中介绍了创建 slab 缓存），那么当内存被分配时，它总是被初始化为特殊值或内存模式`0x5a5a5a5a`-它被毒害了（这是非常有意义的：十六进制值`0x5a`是 ASCII 字符`Z`代表零）！所以，想一想，如果你在内核诊断消息或转储中看到这个值，也称为*Oops*，那么很有可能这是一个（不幸地相当典型的）未初始化内存错误或**UMR**（未初始化内存读取）。

为什么在前面的句子中使用*也许*这个词？嗯，简单地因为调试深藏的错误是一件非常困难的事情！可能出现的症状并不一定是问题的根本原因。因此，不幸的开发人员经常被各种红鲱引入歧途！现实是调试既是一门艺术又是一门科学；对生态系统（这里是 Linux 内核）的深入了解在帮助你有效调试困难情况方面起到了很大作用。

如果未设置`SLAB_POISON`标志，则未初始化的 slab 内存将设置为`0x6b6b6b6b`内存模式（十六进制`0x6b`是 ASCII 字符`k`（见图 9.2））。同样，当 slab 高速缓存内存被释放并且`CONFIG_SLUB_DEBUG`打开时，内核将相同的内存模式（`0x6b6b6b6b；'k'`）写入其中。这也非常有用，可以让我们发现（内核认为的）未初始化或空闲内存。

毒值在`include/linux/poison.h`中定义如下：

```
/* ...and for poisoning */
#define POISON_INUSE    0x5a    /* for use-uninitialized poisoning */
#define POISON_FREE     0x6b    /* for use-after-free poisoning */
#define POISON_END      0xa5    /* end-byte of poisoning */
```

关于内核 SLUB 实现的 slab 分配器，让我们来看一下**何时**（具体情况由以下`if`部分确定）以及*slab 中毒发生的类型*的摘要视图，以及以下伪代码中的类型：

```
if CONFIG_SLUB_DEBUG is enabled
   AND the SLAB_POISON flag is set
   AND there's no custom constructor function
   AND it's type-safe-by-RCU
```

然后毒化 slab 发生如下：

+   slab 内存在初始化时设置为`POISON_INUSE（0x5a = ASCII 'Z'）`；此代码在此处：`mm/slub.c:setup_page_debug()`。

+   slab 对象在`mm/slub.c:init_object()`中初始化为`POISON_FREE（0x6b = ASCII 'k'）`。

+   slab 对象的最后一个字节在`mm/slub.c:init_object()`中初始化为`POISON_END（0xa5）`。

（因此，由于 slab 层执行这些 slab 内存初始化的方式，我们最终得到值`0x6b`（ASCII `k`）作为刚分配的 slab 内存的初始值）。请注意，为了使其工作，您不应安装自定义构造函数。此外，您现在可以忽略`it's-type-safe-by-RCU`指令；通常情况下是这样（即，“is type-safe-by-RCU”为真；FYI，RCU（Read Copy Update）是一种高级同步技术，超出了本书的范围）。从在 SLUB 调试模式下运行时 slab 的初始化方式可以看出，内存内容实际上被初始化为值`POISON_FREE（0x6b = ASCII 'k'）`。因此，如果内存释放后此值发生变化，内核可以检测到并触发报告（通过 printk）。当然，这是一个众所周知的**使用后释放**（**UAF**）内存错误的案例！类似地，在红色区域之前或之后写入（这些实际上是保护区域，通常初始化为`0xbb`）将触发写入缓冲区下/溢出错误，内核将报告。有用！

### 试一下-触发 UAF 错误

为了帮助您更好地理解这一点，我们将在本节的屏幕截图中展示一个示例。执行以下步骤：

1.  首先确保启用了`CONFIG_SLUB_DEBUG`内核配置（应设置为`y`；这通常是发行版内核的情况）

1.  然后，在包括内核命令行`slub_debug=`指令的情况下启动系统（这将打开完整的 SLUB 调试；或者您可以传递更精细的变体，例如`slub_debug=FZPU`（请参阅此处的内核文档以了解每个字段的解释：[`www.kernel.org/doc/Documentation/vm/slub.txt`](https://www.kernel.org/doc/Documentation/vm/slub.txt)）；作为演示，在我的 Fedora 31 虚拟机上，我传递了以下内核命令行-这里重要的是，`slub_debug=FZPU`以粗体字体突出显示：

```
$ cat /proc/cmdline
BOOT_IMAGE=(hd0,msdos1)/vmlinuz-5.4.0-llkd01 root=/dev/mapper/fedora_localhost--live-root ro resume=/dev/mapper/fedora_localhost--live-swap rd.lvm.lv=fedora_localhost-live/root rd.lvm.lv=fedora_localhost-live/swap rhgb slub_debug=FZPU 3
```

（有关`slub_debug`参数的更多详细信息，请参阅下一节*​引导和运行时的 SLUB 调试选项*）。

1.  编写一个创建新的自定义 slab 高速缓存的内核模块（当然其中存在内存错误！）。确保未指定构造函数（示例代码在此处：`ch9/poison_test`；我将留给您浏览代码并测试的练习）。

1.  我们在这里尝试一下：通过`kmem_cache_alloc()`（或等效方法）分配一些 slab 内存。下面是一个屏幕截图（图 9.2），显示分配的内存，以及在执行快速的`memset()`将前 16 个字节设置为`z`（`0x7a`）后的相同区域：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/2a38ad65-0115-41bb-bc1c-8de17c81ead1.png)

图 9.2-分配和 memset()后的 slab 内存）。

1.  现在，来说说 bug！在清理方法中，我们释放了分配的 slab，然后尝试对其进行另一个`memset()`，*从而触发了 UAF bug*。同样，我们通过另一张屏幕截图（图 9.3）显示内核日志：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/3a1f3f3a-ecf0-46a2-a5c4-be69803a03b4.png)

图 9.3 - 内核报告 UAF bug！

请注意内核如何报告这一点（前面图中红色的第一段文字）作为`Poison overwritten` bug。事实上就是这样：我们用`0x21`（故意是 ASCII 字符`!`）覆盖了`0x6b`毒值。在释放了来自 slab 缓存的缓冲区后，如果内核在有效负载中检测到毒值之外的任何值（`POISON_FREE = 0x6b = ASCII 'k'`），就会触发 bug。（还要注意，红区 - 保护区 - 的值初始化为`0xbb`）。

下一节将提供有关可用的 SLUB 层调试选项的更多细节。

## 引导和运行时的 SLUB 调试选项

在使用 SLUB 实现（默认）时，调试内核级 slab 问题非常强大，因为内核具有完整的调试信息。只是默认情况下它是关闭的。有各种方式（视口）可以打开和查看 slab 调试级别的信息；有大量的细节可用！其中一些方法包括以下内容：

+   通过在内核命令行上传递`slub_debug=`字符串（当然是通过引导加载程序）。这会打开完整的 SLUB 内核级调试。

+   要查看的特定调试信息可以通过传递给`slub_debug=`字符串的选项进行微调（在`=`后面不传递任何内容意味着启用所有 SLUB 调试选项）；例如，传递`slub_debug=FZ`会启用以下选项：

+   `F`: 对齐检查（启用`SLAB_DEBUG_CONSISTENCY_CHECKS`）；请注意，打开此选项可能会减慢系统速度。

+   `Z`: 红色分区。

+   即使没有通过内核命令行打开 SLUB 调试功能，我们仍然可以通过在`/sys/kernel/slab/<slab-name>`下的适当伪文件中写入`1`（作为 root 用户）来启用/禁用它：

+   回想一下我们之前的演示内核模块（`ch9/slab_custom`）；一旦加载到内核中，可以像这样查看每个分配对象的理论和实际大小：

```
$ sudo cat /sys/kernel/slab/our_ctx/object_size  /sys/kernel/slab/our_ctx/slab_size 
328 768
```

+   +   还有其他几个伪文件；在`/sys/kernel/slab/<name-of-slab>/`上执行`ls(1)`将会显示它们。例如，通过在`/sys/kernel/slab/our_ctx/ctor`上执行`cat`来查找到我们的`ch9/slab_custom` slab 缓存的构造函数：

```
$ sudo cat /sys/kernel/slab/our_ctx/ctor
our_ctor+0x0/0xe1 [slab_custom]
```

在这里可以找到一些相关的详细信息（非常有用！）：*SLUB 的简短用户指南*（[`www.kernel.org/doc/Documentation/vm/slub.txt`](https://www.kernel.org/doc/Documentation/vm/slub.txt)）。

此外，快速查看内核源树的`tools/vm`文件夹将会发现一些有趣的程序（这里相关的是`slabinfo.c`）和一个用于生成图表的脚本（通过`gnuplot(1)`）。前面段落提到的文档提供了有关生成图表的使用细节。

作为一个重要的附带说明，内核有大量（而且有用！）的*内核参数*可以在引导时（通过引导加载程序）选择性地传递给它。在这里的文档中可以看到完整的列表：*内核的命令行参数*（[`www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html`](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)）。

好了，这（终于）结束了我们对 slab 分配器的覆盖（从上一章延续到这一章）。您已经了解到它是在页面分配器之上的一层，解决了两个关键问题：一是允许内核创建和维护对象缓存，以便非常高效地执行一些重要的内核数据结构的分配和释放；二是包括通用内存缓存，允许您以非常低的开销（与二进制伙伴系统分配器不同）分配小量的 RAM——页面的片段。事实就是这样：slab API 是驱动程序中真正常用的 API；不仅如此，现代驱动程序作者还利用了资源管理的`devm_k{m,z}alloc()` API；我们鼓励您这样做。不过要小心：我们详细讨论了实际分配的内存可能比您想象的要多（使用`ksize()`来找出实际分配了多少）。您还学会了如何创建自定义的 slab 缓存，以及如何进行 slab 层的调试。

现在让我们学习`vmalloc()` API 是什么，如何以及何时用于内核内存分配。

# 理解并使用内核 vmalloc() API

在前一章中，我们已经学到，内核内存分配的最终引擎只有一个——页面（或伙伴系统）分配器。在其上层是 slab 分配器（或 slab 缓存）机制。此外，内核地址空间中还有另一个完全虚拟的地址空间，可以随意分配虚拟页面，这就是所谓的内核`vmalloc`区域。

当虚拟页面实际被使用时（由内核中的某个东西或通过进程或线程的用户空间使用），它实际上是通过页面分配器分配的物理页面帧（这对所有用户空间内存帧也是最终真实的，尽管是间接的方式；这一点我们稍后在*需求分页和 OOM*部分会详细介绍）。

在内核段或 VAS（我们在第七章中详细介绍了这些内容，*内存管理内部-基础*，在*检查内核段*部分），是*vmalloc*地址空间，从`VMALLOC_START`到`VMALLOC_END-1`。它起初是一个完全虚拟的区域，也就是说，它的虚拟页面最初并未映射到任何物理页面帧上。

要快速复习一下，可以重新查看用户和内核段的图表——实际上是完整的 VAS——通过重新查看*图 7.12*。您可以在第七章中的*内存管理内部-基础*部分的*尝试-查看内核段详细信息*部分找到这个图表。

在本书中，我们的目的不是深入研究内核的`vmalloc`区域的内部细节。相反，我们提供足够的信息，让您作为模块或驱动程序的作者，在运行时使用这个区域来分配虚拟内存。

## 学习使用 vmalloc 系列 API

您可以使用`vmalloc()` API 从内核的`vmalloc`区域中分配虚拟内存（当然是在内核空间中）：

```
#include <linux/vmalloc.h>
void *vmalloc(unsigned long size);
```

关于 vmalloc 的一些关键点：

+   `vmalloc()`API 将连续的虚拟内存分配给调用者。并不保证分配的区域在物理上是连续的；可能是连续的，也可能不是（事实上，分配越大，物理上连续的可能性就越小）。

+   理论上分配的虚拟页面的内容是随机的；实际上，它似乎是与架构相关的（至少在 x86_64 上，似乎会将内存区域清零）；当然，（尽管可能会稍微影响性能）建议您通过使用`vzalloc()`包装 API 来确保内存清零。

+   `vmalloc()`（以及相关函数）API 只能在进程上下文中调用（因为它可能导致调用者休眠）。

+   `vmalloc()`的返回值是成功时的 KVA（在内核 vmalloc 区域内），失败时为`NULL`。

+   刚刚分配的 vmalloc 内存的起始位置保证在页面边界上（换句话说，它总是页面对齐的）。

+   实际分配的内存（来自页面分配器）可能比请求的大小要大（因为它在内部分配足够的页面来覆盖请求的大小）

你会发现，这个 API 看起来非常类似于熟悉的用户空间`malloc(3)`。事实上，乍一看确实如此，只是当然，它是内核空间的分配（还要记住，两者之间没有直接的对应关系）。

在这种情况下，`vmalloc()`对我们模块或驱动程序的作者有什么帮助呢？当你需要一个大的虚拟连续缓冲区，其大小大于 slab API（即`k{m|z}alloc()`和友元）可以提供的大小时——请记住，在 ARM 和 x86[_64]上，单个分配通常为 4MB——那么你应该使用`vmalloc`！

值得一提的是，内核出于各种原因使用`vmalloc()`，其中一些如下：

+   在加载内核模块时为内核模块的（静态）内存分配空间（在`kernel/module.c:load_module()`中）。

+   如果定义了`CONFIG_VMAP_STACK`，那么`vmalloc()`用于为每个线程的内核模式堆栈分配内存（在`kernel/fork.c:alloc_thread_stack_node()`中）。

+   在内部，为了处理一个叫做`ioremap()`的操作。

+   在 Linux 套接字过滤器（bpf）代码路径中等。

为了方便起见，内核提供了`vzalloc()`包装 API（类似于`kzalloc()`）来分配并清零内存区域——这是一个良好的编码实践，但可能会稍微影响时间关键的代码路径：

```
void *vzalloc(unsigned long size);
```

一旦你使用了分配的虚拟缓冲区，当然你必须释放它：

```
void vfree(const void *addr);
```

如预期的那样，传递给`vfree()`的参数是`v[m|z]alloc()`的返回地址（甚至是这些调用的底层`__vmalloc()` API）。传递`NULL`会导致它只是无害地返回。

在下面的片段中，我们展示了我们的`ch9/vmalloc_demo`内核模块的一些示例代码。和往常一样，我建议你克隆本书的 GitHub 存储库并自己尝试一下（为了简洁起见，我们没有在下面的片段中显示整个源代码；我们显示了模块初始化代码调用的主要`vmalloc_try()`函数）。

这是代码的第一部分。如果`vmalloc()` API 出现任何问题，我们通过内核的`pr_warn()`辅助程序生成警告。请注意，以下的`pr_warn()`辅助程序实际上并不是必需的；在这里我有点迂腐，我们保留它……其他情况也是如此，如下所示：

```
// ch9/vmalloc_demo/vmalloc_demo.c
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__
[...]
#define KVN_MIN_BYTES     16
#define DISP_BYTES        16
static void *vptr_rndm, *vptr_init, *kv, *kvarr, *vrx;

static int vmalloc_try(void)
{
    if (!(vptr_rndm = vmalloc(10000))) {
        pr_warn("vmalloc failed\n");
        goto err_out1;
    }
    pr_info("1\. vmalloc(): vptr_rndm = 0x%pK (actual=0x%px)\n", 
            vptr_rndm, vptr_rndm);
    print_hex_dump_bytes(" content: ", DUMP_PREFIX_NONE, vptr_rndm,     
                DISP_BYTES);
```

在上面的代码块中，`vmalloc()` API 分配了一个至少有 10,000 字节的连续内核虚拟内存区域；实际上，内存是页面对齐的！我们使用内核的`print_hex_dump_bytes()`辅助例程来转储这个区域的前 16 个字节。

接下来，看一下以下代码如何使用`vzalloc()` API 再次分配另一个至少有 10,000 字节的连续内核虚拟内存区域（尽管它是页面对齐的内存）；这次，内存内容被设置为零：

```
    /* 2\. vzalloc(); memory contents are set to zeroes */
    if (!(vptr_init = vzalloc(10000))) {
        pr_warn("%s: vzalloc failed\n", OURMODNAME);
        goto err_out2;
    }
    pr_info("2\. vzalloc(): vptr_init = 0x%pK (actual=0x%px)\n",
            vptr_init, (TYPECST)vptr_init);
    print_hex_dump_bytes(" content: ", DUMP_PREFIX_NONE, vptr_init, 
                DISP_BYTES);
```

关于以下代码的一些要点：首先，注意使用`goto`进行错误处理（在多个`goto`实例的目标标签处，我们使用`vfree()`根据需要释放先前分配的内存缓冲区），这是典型的内核代码。其次，暂时忽略`kvmalloc()`、`kcalloc()`和`__vmalloc()`等友元例程；我们将在*vmalloc 的友元*部分介绍它们：

```
  /* 3\. kvmalloc(): allocate 'kvn' bytes with the kvmalloc(); if kvn is
   * large (enough), this will become a vmalloc() under the hood, else
   * it falls back to a kmalloc() */
    if (!(kv = kvmalloc(kvn, GFP_KERNEL))) {
        pr_warn("kvmalloc failed\n");
        goto err_out3;
    }
    [...]

    /* 4\. kcalloc(): allocate an array of 1000 64-bit quantities and zero
     * out the memory */
    if (!(kvarr = kcalloc(1000, sizeof(u64), GFP_KERNEL))) {
        pr_warn("kvmalloc_array failed\n");
        goto err_out4;
    }
    [...]
    /* 5\. __vmalloc(): <seen later> */
    [...]
    return 0;
err_out5:
  vfree(kvarr);
err_out4:
    vfree(kv);
err_out3:
    vfree(vptr_init);
err_out2:
    vfree(vptr_rndm);
err_out1:
    return -ENOMEM;
}
```

在我们内核模块的清理代码路径中，我们当然释放了分配的内存区域：

```
static void __exit vmalloc_demo_exit(void)
{
    vfree(vrx);
    kvfree(kvarr);
    kvfree(kv);
    vfree(vptr_init);
    vfree(vptr_rndm);
    pr_info("removed\n");
}
```

我们将让你自己尝试并验证这个演示内核模块。

现在，让我们简要地探讨另一个非常关键的方面——用户空间的`malloc()`或内核空间的`vmalloc()`内存分配如何变成物理内存？继续阅读以了解更多！

## 关于内存分配和需求分页的简要说明

不深入研究`vmalloc()`（或用户空间`malloc()`）的内部工作细节，我们仍然会涵盖一些关键点，这些关键点是像你这样的有能力的内核/驱动程序开发人员必须理解的。

首先，vmalloc-ed 虚拟内存必须在某个时候（在使用时）变成物理内存。这种物理内存是通过内核中唯一的方式分配的 - 通过页面（或伙伴系统）分配器。这是一个有点间接的过程，简要解释如下。

使用`vmalloc()`时，一个关键点应该被理解：`vmalloc()`只会导致虚拟内存页面被分配（它们只是被操作系统标记为保留）。此时实际上并没有分配物理内存。实际的物理页面框架只有在这些虚拟页面被触摸时才会被分配 - 而且也是逐页进行 - 无论是读取、写入还是执行。直到程序或进程实际尝试使用它之前，实际上并没有分配物理内存的这一关键原则被称为各种名称 - *需求分页、延迟分配、按需分配*等等。事实上，文档中明确说明了这一点：

"vmalloc 空间被懒惰地同步到使用页面错误处理程序的进程的不同 PML4/PML5 页面中..."

清楚地了解`vmalloc()`和相关内容以及用户空间 glibc `malloc()`系列例程的内存分配实际工作原理是非常有启发性的 - 这一切都是通过需求分页！这意味着这些 API 的成功返回实际上并不意味着*物理*内存分配。当`vmalloc()`或者用户空间的`malloc()`返回成功时，到目前为止实际上只是保留了一个虚拟内存区域；实际上还没有分配物理内存！*实际的物理页面框架分配只会在虚拟页面被访问时（无论是读取、写入还是执行）逐页进行*。

但这是如何在内部发生的呢？简而言之，答案是：每当内核或进程访问虚拟地址时，虚拟地址都会被 CPU 核心上的硅片的一部分**内存管理单元**（MMU）解释。MMU 的**转换旁路缓冲器**（TLB）*（我们没有能力在这里深入研究所有这些，抱歉！）*现在将被检查是否*命中*。如果是，内存转换（虚拟到物理地址）已经可用；如果不是，我们有一个 TLB 缺失。如果是这样，MMU 现在将*遍历*进程的分页表，有效地转换虚拟地址，从而获得*物理地址。*它将这个地址放在地址总线上，CPU 就可以继续进行。

但是，想一想，如果 MMU 找不到匹配的物理地址会怎么样？这可能是由于许多原因之一，其中之一就是我们这里的情况 - 我们（还）*没有*物理页面框架，只有一个虚拟页面。在这一点上，MMU 基本上放弃了，因为它无法处理。相反，它*调用操作系统的页面错误处理程序代码* - 在进程的上下文中运行的异常或错误处理程序 - 在`current`的上下文中。这个页面错误处理程序实际上解决了这种情况；在我们的情况下，使用`vmalloc()`（或者甚至是用户空间的`malloc()`！），它请求页面分配器为单个物理页面框架（在 order `0`处）并将其映射到虚拟页面。

同样重要的是要意识到，通过页面（伙伴系统）和 slab 分配器进行的内核内存分配并不是懒惰分页（或延迟分配）的情况。在那里，当分配内存时，要理解实际的物理页面框架是立即分配的。（在 Linux 上，实际上一切都非常快，因为伙伴系统的空闲列表已经将所有系统物理 RAM 映射到内核的 lowmem 区域，因此可以随意使用。）

回想一下我们在之前的程序`ch8/lowlevel_mem`中所做的事情；在那里，我们使用我们的`show_phy_pages()`库例程来显示给定内存范围的虚拟地址、物理地址和**页面帧号**（PFN），从而验证低级页面分配器例程确实分配了物理连续的内存块。现在，您可能会想，为什么不在这个`vmalloc_demo`内核模块中调用相同的函数？如果分配的（虚拟）页面的 PFN 不是连续的，我们再次证明，确实只是虚拟连续的。尝试听起来很诱人，但是不起作用！为什么？因为，正如之前所述（在第八章中，*模块作者的内核内存分配-第一部分*）：除了直接映射（身份映射/低内存区域）的地址之外，不要尝试将任何其他地址从虚拟转换为物理-页面或 slab 分配器提供的地址。它在`vmalloc`中根本不起作用。

`vmalloc`和一些相关信息的一些附加点将在下文中介绍；请继续阅读。

## vmalloc()的朋友

在许多情况下，执行内存分配的精确 API（或内存层）对调用者并不真正重要。因此，在许多内核代码路径中出现了以下伪代码的使用模式：

```
kptr = kmalloc(n);
if (!kptr) {
    kptr = vmalloc(n);
    if (unlikely(!kptr))
        <... failed, cleanup ...>
}
<ok, continue with kptr>
```

这种代码的更清晰的替代方案是`kvmalloc()`API。在内部，它尝试以以下方式分配所请求的`n`字节的内存：首先，通过更有效的`kmalloc()`；如果成功，很好，我们很快就获得了物理连续的内存并完成了；如果没有成功，它会回退到通过更慢但更可靠的`vmalloc()`分配内存（从而获得虚拟连续的内存）。它的签名如下：

```
#include <linux/mm.h>
void *kvmalloc(size_t size, gfp_t flags);
```

（记得包含头文件。）请注意，对于（内部的）`vmalloc()`要通过（如果需要的话），只需提供`GFP_KERNEL`标志。与往常一样，返回值是指向分配内存的指针（内核虚拟地址），或者在失败时为`NULL`。释放使用`kvfree`获得的内存：

```
void kvfree(const void *addr);
```

在这里，参数当然是从`kvmalloc()`返回的地址。

类似地，与`{k|v}zalloc()`API 类似，我们还有`kvzalloc()`API，它当然*将*内存内容设置为零。我建议您优先使用它而不是`kvmalloc()`API（通常的警告：它更安全但速度稍慢）。

此外，您可以使用`kvmalloc_array()`API 为*数组*分配虚拟连续内存。它分配`n`个`size`字节的元素。其实现如下所示：

```
// include/linux/mm.h
static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
        size_t bytes;
        if (unlikely(check_mul_overflow(n, size, &bytes)))
                return NULL;
        return kvmalloc(bytes, flags);
}
```

这里的一个关键点：注意对危险的整数溢出（IoF）错误进行有效性检查；这很重要和有趣；在代码中进行类似的有效性检查，以编写健壮的代码。

接下来，`kvcalloc()`API 在功能上等同于用户空间 API`calloc(3)`，只是`kvmalloc_array()`API 的简单包装器：

```
void *kvcalloc(size_t n, size_t size, gfp_t flags);
```

我们还提到，对于需要 NUMA 意识的代码（我们在第七章“内存管理内部-基本知识”中涵盖了 NUMA 和相关主题，*物理 RAM 组织*部分），可以使用以下 API，我们可以指定要从特定 NUMA 节点分配内存的参数（这是指向 NUMA 系统的要点；请看后面不久会出现的信息框）：

```
void *kvmalloc_node(size_t size, gfp_t flags, int node);
```

同样，我们也有`kzalloc_node()`API，它将内存内容设置为零。

实际上，通常我们看到的大多数内核空间内存 API 最终都归结为一个*以 NUMA 节点作为参数*的 API。例如，对于主要的页面分配器 API 之一，`__get_free_page()`API 的调用链如下：

`__get_free_page() -> __get_free_pages() -> alloc_pages() -> alloc_pages_current()

-> __alloc_pages_nodemask() `. **`__alloc_pages_nodemask()`** API 被认为是分区伙伴分配器的*核心*；请注意它的第四个参数，（NUMA）nodemask：

`mm/page_alloc.c:struct page *`

`__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,

int preferred_nid, nodemask_t *nodemask);`

当然，您必须释放您获取的内存；对于前面的`kv*()`API（和`kcalloc()`API），请使用`kvfree()`释放获得的内存。

另一个值得了解的内部细节，以及`k[v|z]malloc[_array]()`API 有用的原因：对于常规的`kmalloc()`，如果请求的内存足够小（当前定义为`CONFIG_PAGE_ALLOC_COSTLY_ORDER`，即`3`，表示 8 页或更少），内核将无限重试分配内存；这实际上会影响性能！使用`kvmalloc()`API，不会进行无限重试（此行为通过 GFP 标志`__GFP_NORETRY|__GFP_NOWARN`指定），从而加快速度。LWN 的一篇文章详细介绍了 slab 分配器的相当奇怪的无限重试语义：*“太小而无法失败”的内存分配规则，Jon Corbet，2014 年 12 月*（[`lwn.net/Articles/627419/`](https://lwn.net/Articles/627419/)）。

关于我们在本节中看到的`vmalloc_demo`内核模块，再快速看一下代码（`ch9/vmalloc_demo/vmalloc_demo.c`）。我们使用`kvmalloc()`以及`kcalloc()`（*注释中的步骤 3 和 4*）。让我们在 x86_64 Fedora 31 客户系统上运行它并查看输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/71b63bcd-29aa-476e-bcb1-052ffead0f5c.png)

图 9.4-加载我们的 vmalloc_demo.ko 内核模块时的输出

我们可以从前面的输出中的 API 中看到实际的返回（内核虚拟）地址-请注意它们都属于内核的 vmalloc 区域。注意`kvmalloc()`（图 9.4 中的步骤 3）的返回地址；让我们在`proc`下搜索一下：

```
$ sudo grep "⁰x00000000fb2af97f" /proc/vmallocinfo
0x00000000fb2af97f-0x00000000ddc1eb2c 5246976 0xffffffffc04a113d pages=1280 vmalloc vpages N0=1280
```

就是这样！我们可以清楚地看到，使用`kvmalloc()`API 为大量内存（5 MB）分配导致内部调用了`vmalloc()`API（`kmalloc()`API 将失败并且不会发出警告，也不会重试），因此，正如您所看到的，命中了`/proc/vmallocinfo`。

要解释`/proc/vmallocinfo`的前面字段，请参阅这里的内核文档：[`www.kernel.org/doc/Documentation/filesystems/proc.txt`](https://www.kernel.org/doc/Documentation/filesystems/proc.txt)。

在我们的`ch9/vmalloc_demo`内核模块中，通过将`kvnum=<# bytes to alloc>`作为模块参数传递来更改通过`kvmalloc()`分配的内存量。

FYI，内核提供了一个内部辅助 API，`vmalloc_exec()`-它（再次）是`vmalloc()`API 的包装器，并用于分配具有执行权限的虚拟连续内存区域。一个有趣的用户是内核模块分配代码路径（`kernel/module.c:module_alloc()`）；内核模块的（可执行部分）内存空间是通过这个例程分配的。不过，这个例程并没有被导出。

我们提到的另一个辅助例程是`vmalloc_user()`；它（再次）是`vmalloc()`API 的包装器，并用于分配适合映射到用户 VAS 的零内存的虚拟连续内存区域。这个例程是公开的；例如，它被几个设备驱动程序以及内核的性能事件环缓冲区使用。

## 指定内存保护

如果您打算为您分配的内存页面指定特定的内存保护（读、写和执行保护的组合），该怎么办？在这种情况下，使用底层的`__vmalloc()`API（它是公开的）。请参考内核源代码中的以下注释（`mm/vmalloc.c`）：

```
* For tight control over page level allocator and protection flags
* use __vmalloc() instead.
```

`__vmalloc()`API 的签名显示了我们如何实现这一点：

```
void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot);
```

值得一提的是，从 5.8 内核开始，`__vmalloc()`函数的第三个参数——`pgprot_t prot`已被移除（因为除了通常的用户之外，没有其他用户需要页面权限；[`github.com/torvalds/linux/commit/88dca4ca5a93d2c09e5bbc6a62fbfc3af83c4fca`](https://github.com/torvalds/linux/commit/88dca4ca5a93d2c09e5bbc6a62fbfc3af83c4fca)）。这告诉我们关于内核社区的另一件事——如果一个功能没有被任何人使用，它就会被简单地移除。

前两个参数是通常的嫌疑犯——以字节为单位的内存大小和用于分配的 GFP 标志。第三个参数在这里是感兴趣的：`prot`代表我们可以为内存页面指定的内存保护位掩码。例如，要分配 42 个设置为只读（`r--`）的页面，我们可以这样做：

```
vrx = __vmalloc(42 * PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_RO);
```

然后，当然，调用`vfree()`来将内存释放回系统。

### 测试它——一个快速的**概念验证**

我们将在我们的`vmalloc_demo`内核模块中尝试一个快速的概念验证。我们通过`__vmalloc()`内核 API 分配了一个内存区域，指定页面保护为只读（或*RO*）。然后我们通过读取和写入只读内存区域来测试它。以下是其中的一部分代码片段。

请注意，我们默认情况下未定义以下代码中的（愚蠢的）`WR2ROMEM_BUG`宏，这样你，无辜的读者，就不会让我们邪恶的`vmalloc_demo`内核模块在你身上崩溃。因此，为了尝试这个 PoC，请取消注释定义语句（如下所示），从而允许错误的代码执行：

```
static int vmalloc_try(void)
{
    [...]
    /* 5\. __vmalloc(): allocate some 42 pages and set protections to RO */
/* #undef WR2ROMEM_BUG */
#define WR2ROMEM_BUG /* 'Normal' usage: keep this commented out, else we 
                      *  will crash! Read  the book, Ch 9, for details :-) */
    if (!(vrx = __vmalloc(42*PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_RO))) {
        pr_warn("%s: __vmalloc failed\n", OURMODNAME);
        goto err_out5;
    }
    pr_info("5\. __vmalloc(): vrx = 0x%pK (actual=0x%px)\n", vrx, vrx);
    /* Try reading the memory, should be fine */
    print_hex_dump_bytes(" vrx: ", DUMP_PREFIX_NONE, vrx, DISP_BYTES);
#ifdef WR2ROMEM_BUG
    /* Try writing to the RO memory! We find that the kernel crashes
     * (emits an Oops!) */
   *(u64 *)(vrx+4) = 0xba;
#endif
    return 0;
    [...]
```

运行时，在我们尝试写入只读内存的地方，它会崩溃！请参见以下部分截图（图 9.5；在我们的 x86_64 Fedora 客户机上运行）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/bfbfd566-9506-4aa4-b538-05d438fed559.png)

图 9.5——当我们尝试写入只读内存区域时发生的内核 Oops！

这证明了我们执行的`__vmalloc()` API 成功地将内存区域设置为只读。再次强调，对于前面（部分可见）的内核诊断或*Oops*消息的解释细节超出了本书的范围。然而，很容易看出在前面的图中突出显示的问题的根本原因：以下行文字确切地指出了这个错误的原因：

```
BUG: unable to handle page fault for address: ffffa858c1a39004
#PF: supervisor write access in kernel mode
#PF: error_code(0x0003) - permissions violation
```

在用户空间应用程序中，可以通过`mprotect(2)`系统调用对任意内存区域执行类似的内存保护设置；请查阅其手册以获取使用详情（它甚至友好地提供了示例代码！）。

### 为什么要将内存设置为只读？

在分配时指定内存保护，比如只读，可能看起来是一个相当无用的事情：那么你怎么初始化那块内存为一些有意义的内容呢？嗯，想一想——**guard pages**就是这种情况的完美用例（类似于 SLUB 层在调试模式下保留的 redzone 页面）；它确实是有用的。

如果我们想要为某些目的而使用只读页面呢？那么，我们可以使用一些替代方法，而不是使用`__vmalloc()`，也许是通过`mmap()`方法将一些内核内存映射到用户空间，然后使用用户空间应用程序的`mprotect(2)`系统调用来设置适当的保护（甚至通过著名且经过测试的 LSM 框架，如 SELinux、AppArmor、Integrity 等来设置保护）。

我们用一个快速比较来结束本节：典型的内核内存分配器 API：`kmalloc()`和`vmalloc()`。

## `kmalloc()`和`vmalloc()` API——一个快速比较

以下表格中简要比较了`kmalloc()`（或`kzalloc()`）和`vmalloc()`（或`vzalloc()`）API：

| **特征** | **`kmalloc()`或`kzalloc()`** | **`vmalloc()`或`vzalloc()`** |
| --- | --- | --- |
| **分配的内存是** | 物理连续的 | 虚拟（逻辑）连续的 |
| 内存对齐 | 对硬件（CPU）缓存行对齐 | 页面对齐 |
| 最小粒度 | 与架构相关；在 x86[_64]上最低为 8 字节 | 1 页 |
| 性能 | 对于小内存分配（典型情况下）更快（分配物理 RAM）；适用于小于 1 页的分配 | 较慢，按需分页（只分配虚拟内存；涉及页面错误处理程序的延迟分配 RAM）；可以为大（虚拟）分配提供服务 |
| 大小限制 | 有限（通常为 4 MB） | 非常大（64 位系统上内核 vmalloc 区域甚至可以达到数 TB，但 32 位系统上要少得多） |
| 适用性 | 适用于几乎所有性能要求较高的用例，所需内存较小，包括 DMA（仍然，请使用 DMA API）；可以在原子/中断上下文中工作 | 适用于大型软件（几乎）连续的缓冲区；较慢，不能在原子/中断上下文中分配 |

这并不意味着其中一个优于另一个。它们的使用取决于具体情况。这将引出我们下一个 - 确实非常重要的 - 话题：在何时决定使用哪种内存分配 API？做出正确的决定对于获得最佳系统性能和稳定性非常关键 - 请继续阅读以了解如何做出选择！

# 内核中的内存分配 - 何时使用哪些 API

迄今为止我们学到的东西的一个非常快速的总结：内核内存分配（和释放）的基础引擎称为页面（或伙伴系统）分配器。最终，每个内存分配（和随后的释放）都经过这一层。然而，它也有自己的问题，其中主要问题是内部碎片或浪费（由于其最小粒度是一个页面）。因此，我们有了位于其上面的 slab 分配器（或 slab 缓存），它提供了对象缓存的功能，并缓存页面的片段（有助于减轻页面分配器的浪费问题）。此外，不要忘记您可以创建自己的自定义 slab 缓存，并且正如我们刚刚看到的，内核有一个`vmalloc`区域和 API 来从中分配*虚拟*页面。

有了这些信息，让我们继续。要了解何时使用哪种 API，让我们首先看看内核内存分配 API 集。

## 可视化内核内存分配 API 集

以下概念图向我们展示了 Linux 内核的内存分配层以及其中的显著 API；请注意以下内容：

+   在这里，我们只展示了内核向模块/驱动程序作者公开的（通常使用的）API（除了最终执行分配的`__alloc_pages_nodemask()` API 在底部！）。

+   为简洁起见，我们没有展示相应的内存释放 API。

以下是一个图表，显示了几个（向模块/驱动程序作者公开的）内核内存分配 API：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/60fd6661-248f-4bc6-824a-4271596f2180.png)

图 9.6 - 概念图显示内核的内存分配 API 集（用于模块/驱动程序作者）

既然您已经看到了（公开的）可用内存分配 API 的丰富选择，接下来的部分将深入探讨如何帮助您在何种情况下做出正确的选择。

## 选择适当的内核内存分配 API

有了这么多选择的 API，我们该如何选择？虽然我们在本章以及上一章已经讨论过这个问题，但我们会再次总结，因为这非常重要。大体上来说，有两种看待它的方式 - 使用的 API 取决于以下因素：

+   所需内存的数量

+   所需的内存类型

我们将在本节中说明这两种情况。

首先，通过扫描以下流程图（从标签“从这里开始”右上方开始），决定使用哪种 API 来分配内存的类型、数量和连续性：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/0a9000d5-5341-4715-80e7-746aa1d675e7.png)

图 9.7 - 决定为模块/驱动程序使用哪种内核内存分配 API 的决策流程图

当然，这并不是微不足道的；不仅如此，我想提醒您回顾一下我们在本章早些时候讨论过的详细内容，包括要使用的 GFP 标志（以及*不要在原子上下文中休眠*的规则）；实际上，以下内容：

+   在任何原子上下文中，包括中断上下文，确保只使用`GFP_ATOMIC`标志。

+   否则（进程上下文），您可以决定是否使用`GFP_ATOMIC`或`GFP_KERNEL`标志；当可以安全休眠时，请使用`GFP_KERNEL`

+   然后，如在*使用 slab 分配器时的注意事项*部分所述：在使用`k[m|z]alloc()` API 和相关函数时，请确保使用`ksize()`检查实际分配的内存。

接下来，根据要分配的内存类型决定使用哪个 API，扫描以下表：

| **所需内存类型** | **分配方法** | **API** |
| --- | --- | --- |
| 内核模块，典型情况：小量（少于一页），物理上连续的常规用法 | Slab 分配器 | `k[m | z]alloc()`，`kcalloc()`和`krealloc()` |
| 设备驱动程序：小量（<1 页），物理上连续的常规用法；适用于驱动程序`probe()`或 init 方法；建议驱动程序使用 | 资源管理 API | `devm_kzalloc()`和`devm_kmalloc()` |

物理上连续，通用用途 | 页面分配器 | `__get_free_page[s]()`, `get_zeroed_page()`和

`alloc_page[s][_exact]()` |

| 对于**直接内存访问**（**DMA**），物理上连续的情况下，可以使用专门的 DMA API 层，带有 CMA（或 slab/page 分配器） | （这里不涵盖：`dma_alloc_coherent(), dma_map_[single | sg]()`, Linux DMA 引擎 API 等） |
| --- | --- | --- |
| 对于大型软件缓冲区，虚拟上连续的情况下，可以通过页面分配器间接使用 | `v[m | z]alloc()` |
| 在运行时大小不确定时，虚拟或物理上连续的情况下，可以使用 slab 或 vmalloc 区域 | `kvmalloc[_array]()` |
| 自定义数据结构（对象） | 创建并使用自定义 slab 缓存 | `kmem_cache_[create | destroy]()`和`kmem_cache_[alloc | free]()` |

（当然，这个表格与*图 9.7*中的流程图有一些重叠）。作为一个通用的经验法则，您的首选应该是 slab 分配器 API，即通过`kzalloc()`或`kmalloc()`；这些对于典型小于一页的分配来说是最有效的。此外，请记住，当运行时所需大小不确定时，您可以使用`kvmalloc()` API。同样，如果所需大小恰好是完全舍入的 2 的幂页数（2⁰、2¹、...、2^(MAX_ORDER-1) *页*），那么使用页面分配器 API 将是最佳的。

## 关于 DMA 和 CMA 的说明

关于 DMA 的话题，虽然其研究和使用超出了本书的范围，但我仍然想提一下，Linux 有一套专门为 DMA 设计的 API，称为*DMA 引擎*。执行 DMA 操作的驱动程序作者非常希望使用这些 API，而不是直接使用 slab 或页面分配器 API（微妙的硬件问题确实会出现）。

此外，几年前，三星工程师成功地将一个补丁合并到主线内核中，称为**连续内存分配器**（**CMA**）。基本上，它允许分配*大的物理上连续的内存*块（超过典型的 4 MB 限制！）。这对于一些内存需求量大的设备的 DMA 是必需的（你想在大屏平板电脑或电视上播放超高清质量的电影吗？）。很酷的是，CMA 代码被透明地构建到 DMA 引擎和 DMA API 中。因此，像往常一样，执行 DMA 操作的驱动程序作者应该坚持使用 Linux DMA 引擎层。

如果您有兴趣了解 DMA 和 CMA，请参阅本章的进一步阅读部分提供的链接。

同时，要意识到我们的讨论大多是关于典型的内核模块或设备驱动程序作者。在操作系统本身，对单页的需求往往非常高（由于操作系统通过页面错误处理程序服务需求分页 - 即所谓的*次要*错误）。因此，在底层，内存管理子系统往往频繁地发出`__get_free_page[s]()`API。此外，为了满足*页面缓存*（和其他内部缓存）的内存需求，页面分配器发挥着重要作用。

好的，干得好，通过这个你（几乎！）完成了我们对各种内核内存分配层和 API（用于模块/驱动程序作者）的两章覆盖。让我们用一个重要的剩余领域来结束这个大主题 - Linux 内核（相当有争议的）OOM killer；继续阅读吧！

# 保持活力 - OOM killer

让我们首先介绍一些关于内核内存管理的背景细节，特别是有关回收空闲内存的内容。这将使您能够理解内核*OOM killer*组件是什么，如何与它一起工作，甚至如何故意调用它。

## 回收内存 - 内核的例行公事和 OOM

正如您所知，内核会尽量将内存页面的工作集保持在内存金字塔（或层次结构）的最高位置，以实现最佳性能。

系统上所谓的内存金字塔（或内存层次结构）包括（按顺序，从最小但速度最快到最大但速度最慢）：CPU 寄存器、CPU 缓存（L1、L2、L3...）、RAM 和交换空间（原始磁盘/闪存/SSD 分区）。在我们的后续讨论中，我们忽略 CPU 寄存器，因为它们的大小微不足道。

因此，处理器使用其硬件缓存（L1、L2 等）来保存页面的工作集。但当然，CPU 缓存内存非常有限，因此很快就会用完，导致内存溢出到下一个分层级别 - RAM。在现代系统中，甚至是许多嵌入式系统，都有相当多的 RAM；但是，如果操作系统的 RAM 不足，它会将无法放入 RAM 的内存页面溢出到原始磁盘分区 - *交换空间*。因此，系统继续正常工作，尽管一旦使用交换空间，性能成本就会显著增加。

为了确保 RAM 中始终有一定数量的空闲内存页面可用，Linux 内核不断进行后台页面回收工作 - 实际上，您可以将其视为例行公事。谁实际执行这项工作？`kswapd`内核线程不断监视系统上的内存使用情况，并在它们感觉到内存不足时调用页面回收机制。

这项页面回收工作是基于每个*节点:区域*的基础进行的。内核使用所谓的*水印级别* - 最小、低和高 - 每个*节点:区域*来智能地确定何时回收内存页面。您可以随时查看`/proc/zoneinfo`以查看当前的水印级别。（请注意，水印级别的单位是页面。）此外，正如我们之前提到的，缓存通常是第一个受害者，并且在内存压力增加时会被缩小。

但让我们假设反面：如果所有这些内存回收工作都没有帮助，内存压力继续增加，直到完整的内存金字塔耗尽，即使是几页的内核分配也失败（或者无限重试，坦率地说，这也是无用的，也许更糟糕）？如果所有 CPU 缓存、RAM 和交换空间（几乎完全）都满了呢？嗯，大多数系统在这一点上就死了（实际上，它们并没有死，它们只是变得非常慢，看起来好像它们永远挂起）。然而，作为 Linux 的 Linux 内核在这些情况下往往是积极的；它调用一个名为 OOM killer 的组件。OOM killer 的工作 - 你猜对了！ - 是识别并立即杀死内存占用进程（通过发送致命的 SIGKILL 信号；它甚至可能会杀死一大堆进程）。

正如您可能想象的那样，它也经历了自己的争议。早期版本的 OOM killer 已经（完全正确地）受到了批评。最近的版本使用了更好的启发式方法，效果相当不错。

您可以在此 LWN 文章（2015 年 12 月）中找到有关改进的 OOM killer 工作（启动策略和 OOM reaper 线程）的更多信息：*Towards more predictable and reliable out-of-memory handling:* [`lwn.net/Articles/668126/`](https://lwn.net/Articles/668126/)。

## 故意调用 OOM killer

要测试内核 OOM killer，我们必须对系统施加巨大的内存压力。因此，内核将释放其武器 - OOM killer，一旦被调用，将识别并杀死一些进程。因此，显然，我强烈建议您在一个安全的隔离系统上尝试这样的东西，最好是一个测试 Linux VM（上面没有重要数据）。

### 通过 Magic SysRq 调用 OOM killer

内核提供了一个有趣的功能，称为 Magic SysRq：基本上，某些键盘组合（或加速器）会导致回调到一些内核代码。例如，假设它已启用，在 x86[_64]系统上按下`Alt-SysRq-b`组合键将导致冷启动！小心，不要随便输入任何内容，确保阅读相关文档：[`www.kernel.org/doc/Documentation/admin-guide/sysrq.rst`](https://www.kernel.org/doc/Documentation/admin-guide/sysrq.rst)。

让我们尝试一些有趣的事情；我们在我们的 Fedora Linux VM 上运行以下命令：

```
$ cat /proc/sys/kernel/sysrq
16
```

这表明 Magic SysRq 功能部分启用（本节开头提到的内核文档给出了详细信息）。要完全启用它，我们运行以下命令：

```
$ sudo sh -c "echo 1 > /proc/sys/kernel/sysrq"
```

好吧，为了到达这里的要点：您可以使用 Magic SysRq 来调用 OOM killer！

小心！通过 Magic SysRq 或其他方式调用 OOM killer *将*导致一些进程 - 通常是*重*进程 - 无条件死亡！

如何？以 root 身份，只需输入以下内容：

```
# echo f > /proc/sysrq-trigger
```

查看内核日志，看看是否发生了什么有趣的事情！

### 通过一个疯狂的分配器程序调用 OOM killer

在接下来的部分中，我们还将演示一种更加实用和有趣的方式，通过这种方式，您可以（很可能）邀请 OOM killer。编写一个简单的用户空间 C 程序，作为一个疯狂的分配器，执行（通常）成千上万的内存分配，向每个页面写入一些内容，当然，永远不释放内存，从而对内存资源施加巨大压力。

像往常一样，我们在以下片段中只显示源代码的最相关部分；请参考并克隆本书的 GitHub 存储库以获取完整的代码；请记住，这是一个用户模式应用程序，而不是内核模块：

```
// ch9/oom_killer_try/oom_killer_try.c
#define BLK     (getpagesize()*2)
static int force_page_fault = 0;
int main(int argc, char **argv)
{
  char *p;
  int i = 0, j = 1, stepval = 5000, verbose = 0;
  [...]

  do {
      p = (char *)malloc(BLK);
      if (!p) {
          fprintf(stderr, "%s: loop #%d: malloc failure.\n",
                  argv[0], i);
          break;
      }

      if (force_page_fault) {
          p[1103] &= 0x0b; // write something into a byte of the 1st page
          p[5227] |= 0xaa; // write something into a byte of the 2nd page
      }
      if (!(i % stepval)) { // every 'stepval' iterations..
          if (!verbose) {
              if (!(j%5)) printf(". ");
         [...]
      }
      i++;
 } while (p && (i < atoi(argv[1])));
```

在以下代码块中，我们展示了在 x86_64 Fedora 31 VM 上运行我们的自定义 5.4.0 Linux 内核的*crazy allocator*程序时获得的一些输出：

```
$ cat /proc/sys/vm/overcommit_memory  /proc/sys/vm/overcommit_ratio0
50                       
$                           << explained below >>

$ ./oom-killer-try
Usage: ./oom-killer-try alloc-loop-count force-page-fault[0|1] [verbose_flag[0|1]]
$ ./oom-killer-try 2000000 0
./oom-killer-try: PID 28896
..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ...Killed
$
```

`Killed`消息是一个线索！用户模式进程已被内核终止。一旦我们瞥一眼内核日志，原因就显而易见了——当然是 OOM 杀手（我们在*需求分页和 OOM*部分展示了内核日志）。

## 理解 OOM 杀手背后的原理

瞥一眼我们的`oom_killer_try`应用程序的前面输出：（在这次运行中）出现了 33 个周期（`.`）之后是可怕的`Killed`消息。在我们的代码中，我们每次分配（2 页或 8KB）时发出一个`.`（通过`printf`）。因此，在这里，我们有 33 次 5 个周期，意味着 33 * 5 = 165 次=> 165 * 5000 * 8K ~= 6,445MB。因此，我们可以得出结论，我们的进程（虚拟地）分配了大约 6,445MB（约 6.29GB）的内存后，OOM 杀手终止了我们的进程！现在您需要理解为什么会在这个特定的数字发生这种情况。

在这个特定的 Fedora Linux VM 上，RAM 为 2GB，交换空间为 2GB；因此，在*内存金字塔*中，总可用内存=（CPU 缓存+）RAM + 交换空间。

这是 4GB（为了简单起见，让我们忽略 CPU 缓存中的相当微不足道的内存量）。但是，这就引出了一个问题，为什么内核在 4GB 点（或更低）没有调用 OOM 杀手呢？为什么只在大约 6GB 时？这是一个有趣的观点：Linux 内核遵循**VM 过度承诺**策略，故意过度承诺内存（在一定程度上）。要理解这一点，请查看当前的`vm.overcommit`设置：

```
$ cat /proc/sys/vm/overcommit_memory
0
```

这确实是默认值（`0`）。可设置的值（仅由 root 设置）如下：

+   `0`：允许使用启发式算法进行内存过度承诺；*默认设置*。

+   `1`：总是过度承诺；换句话说，从不拒绝任何`malloc(3)`；对于某些使用稀疏内存的科学应用程序很有用。

+   `2`：以下注释直接引用自内核文档（[`www.kernel.org/doc/html/v4.18/vm/overcommit-accounting.html#overcommit-accounting`](https://www.kernel.org/doc/html/v4.18/vm/overcommit-accounting.html#overcommit-accounting)）：

*"不要过度承诺。系统的总地址空间承诺不得超过交换空间加上可配置数量（默认为物理 RAM 的 50%）。根据您使用的数量，在大多数情况下，这意味着进程在访问页面时不会被终止，但将在适当的内存分配错误时收到错误。适用于希望保证其内存分配将来可用而无需初始化每个页面的应用程序"*

过度承诺程度由过度承诺比率确定：

```
$ cat /proc/sys/vm/overcommit_ratio
50
```

我们将在以下部分中检查两种情况。

### 情况 1——vm.overcommit 设置为 2，关闭过度承诺

首先，请记住，这*不是*默认设置。当`tunable`设置为`2`时，用于计算总（可能过度承诺的）可用内存的公式如下：

*总可用内存=（RAM + 交换空间）*（过度承诺比率/100）;*

这个公式仅适用于`vm.overcommit == 2`时。

在我们的 Fedora 31 VM 上，`vm.overcommit == 2`，RAM 和交换空间各为 2GB，这将产生以下结果（以 GB 为单位）：

*总可用内存=（2 + 2）*（50/100）= 4 * 0.5 = 2GB*

这个值——（过度）承诺限制——也可以在`/proc/meminfo`中看到，作为`CommitLimit`字段。

### 情况 2——vm.overcommit 设置为 0，过度承诺开启，为默认设置

这*是*默认设置。`vm.overcommit`设置为`0`（而不是`2`）：使用此设置，内核有效地计算总（过度）承诺的内存大小如下：

*总可用内存=（RAM + 交换空间）*（过度承诺比率+100）%;*

这个公式仅适用于`vm.overcommit == 0`时。

在我们的 Fedora 31 VM 上，`vm.overcommit == 0`，RAM 和交换空间各为 2GB，这个公式将产生以下结果（以 GB 为单位）：

*总可用内存=（2 + 2）*（50+100）% = 4 * 150% = 6GB*

因此，系统有效地*假装*有总共 6GB 的内存可用。现在我们明白了：当我们的`oom_killer_try`进程分配了大量内存并且超出了这个限制（6GB）时，OOM killer 就会介入！

我们现在明白，内核在`/proc/sys/vm`下提供了几个 VM 过度承诺的可调参数，允许系统管理员（或 root）对其进行微调（包括通过将`vm.overcommit`设置为值`2`来关闭它）。乍一看，关闭它似乎很诱人。不过，请暂停一下，仔细考虑一下；在大多数工作负载上，保持内核默认的 VM 过度承诺是最好的。

例如，在我的 Fedora 31 客户端 VM 上将`vm.overcommit`值设置为`2`会导致有效可用内存变为只有 2GB。典型的内存使用，特别是在 GUI 运行时，远远超过了这个值，导致系统甚至无法在 GUI 模式下登录用户！以下链接有助于更好地了解这个主题：Linux 内核文档：[`www.kernel.org/doc/Documentation/vm/overcommit-accounting`](https://www.kernel.org/doc/Documentation/vm/overcommit-accounting)和*在 Linux 中禁用内存过度承诺的缺点是什么？*：[`www.quora.com/What-are-the-disadvantages-of-disabling-memory-overcommit-in-Linux`](https://www.quora.com/What-are-the-disadvantages-of-disabling-memory-overcommit-in-Linux)。（请查看*更多阅读*部分了解更多信息。）

## 需求分页和 OOM

回想一下我们在本章早些时候学到的真正重要的事实，在*内存分配和需求分页简要说明*部分：由于操作系统使用的需求分页（或延迟分配）策略，当通过`malloc(3)`（和其他函数）分配内存页面时，实际上只会在进程 VAS 的某个区域保留虚拟内存空间，此时并不会分配物理内存。只有当你对虚拟页面的任何字节执行某些操作 - 读取、写入或执行 - 时，MMU 才会引发页面错误（一个*次要*错误），并且操作系统的页面错误处理程序会相应地运行。如果它认为这个内存访问是合法的，它会通过页面分配器分配一个物理帧。

在我们简单的`oom_killer_try`应用程序中，我们通过它的第三个参数`force_page_fault`来操纵这个想法：当设置为`1`时，我们通过在每个循环迭代中写入任何东西来精确模拟这种情况（如果需要，请再次查看代码）。

所以，现在你知道了这一点，让我们将我们的应用程序重新运行，将第三个参数`force_page_fault`设置为`1`，确实强制发生页面错误！这是我在我的 Fedora 31 VM 上运行此操作（在我们自定义的 5.4.0 内核上）时产生的输出：

```
$ cat /proc/sys/vm/overcommit_memory /proc/sys/vm/overcommit_ratio0
50
$ free -h
              total    used    free     shared   buff/cache    available
Mem:          1.9Gi   1.0Gi    76Mi       12Mi        866Mi        773Mi
Swap:         2.1Gi   3.0Mi   2.1Gi
$ ./oom-killer-try
Usage: ./oom-killer-try alloc-loop-count force-page-fault[0|1] [verbose_flag[0|1]]
$ ./oom-killer-try 900000 1
./oom_killer_try: PID 2032 (verbose mode: off)
..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... ..... .Killed
$ 
$ free -h
              total    used    free    shared   buff/cache     available
Mem:          1.9Gi   238Mi   1.5Gi     2.0Mi        192Mi         1.6Gi
Swap:         2.1Gi   428Mi   1.6Gi
$
```

这一次，你可以真切地感觉到系统在为内存而奋斗。这一次，它很快就耗尽了内存，*实际物理内存已经分配*。（从前面的输出中，我们在这个特定情况下看到了 15 x 5 + 1 个点（`. `或句号）；也就是说，15 乘以 5 个点加 1 个点=> = 76 次=> 76 * 5000 个循环迭代* 8K 每次迭代~= 2969 MB 虚拟*和物理*分配！）

显然，在这一点上，发生了两件事中的一件：

+   系统的 RAM 和交换空间都用完了，因此无法分配页面，从而引发了 OOM killer。

+   计算出的（人为的）内核 VM 提交限制已超出。

我们可以轻松查找这个内核 VM 提交值（再次在我运行此操作的 Fedora 31 VM 上）：

```
$ grep CommitLimit /proc/meminfo
CommitLimit: 3182372 kB
```

这相当于约 3108 MB（远远超过我们计算的 2969 MB）。因此，在这种情况下，很可能是由于所有的 RAM 和交换空间都被用来运行 GUI 和现有的应用程序，第一种情况发生了。

还要注意，在运行我们的程序之前，较大系统缓存（页面和缓冲缓存）使用的内存量是相当可观的。`free(1)`实用程序的输出中的名为`buff/cache`的列显示了这一点。在运行我们疯狂的分配器应用程序之前，2GB 中的 866MB 用于页面缓存。然而，一旦我们的程序运行，它对操作系统施加了如此大的内存压力，以至于大量的交换 - 将 RAM 页面换出到名为“swap”的原始磁盘分区 - 被执行，并且所有缓存都被释放。不可避免地（因为我们拒绝释放任何内存），OOM killer 介入并杀死我们，导致大量内存被回收。OOM killer 清理后的空闲内存和缓存使用量分别为 1.5GB 和 192MB。（当前缓存使用量较低；随着系统运行，它将增加。）

查看内核日志后，确实发现 OOM killer 来过了！请注意，以下部分截图仅显示了在运行 5.4.0 内核的 x86_64 Fedora 31 虚拟机上的堆栈转储：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/f228f9f4-25a4-498f-af3d-fb4ae0d50eca.png)

图 9.8 - OOM killer 后的内核日志，显示内核调用堆栈

以自下而上的方式阅读*图 9.8*中的内核模式堆栈（忽略以`?`开头的帧）：显然，发生了页错误；您可以看到调用帧：`page_fault()` | `do_page_fault()` | `[ ... ]` | `__hande_mm_fault()` | `__do_fault()` | `[ ... ]` | `__alloc_pages_nodemask()`。

想一想，这是完全正常的：MMU 在尝试为没有物理对应物的虚拟页面提供服务时引发了错误。操作系统的错误处理代码运行（在进程上下文中，意味着`current`运行其代码！）；最终导致操作系统调用页面分配器例程的`__alloc_pages_nodemask()`函数，正如我们之前所了解的，这实际上是分区伙伴系统（或页面）分配器的核心 - 内存分配的引擎！

不正常的是，这一次它（`__alloc_pages_nodemask()`函数）失败了！这被认为是一个关键问题，导致操作系统调用 OOM killer（您可以在前面的图中看到`out_of_memory`调用帧）。

在诊断转储的后期，内核努力为杀死给定进程提供理由。它显示了所有线程的表格，它们的内存使用情况（以及各种其他统计数据）。实际上，由于`sysctl：/proc/sys/vm/oom_dump_tasks`默认为`1`，这些统计数据被显示出来。以下是一个示例（在以下输出中，我们已经删除了`dmesg`的最左边的时间戳列，以使数据更易读）：

```
[...]
Tasks state (memory values in pages):
[ pid ]  uid  tgid total_vm    rss pgtables_bytes swapents oom_score_adj name
[  607]    0   607    11774      8   106496       361   -250 systemd-journal
[  622]    0   622    11097      0    90112      1021  -1000 systemd-udevd
[  732]    0   732     7804      0    69632       153  -1000 auditd

              [...]

[ 1950] 1000  1950    56717      1   77824        571  0    bash
[ 2032] 1000  2032   755460 434468 6086656     317451  0    oom_killer_try
oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/user.slice/user-1000.slice/session-3.scope,task=oom_killer_try,pid=2032,uid=1000
Out of memory: Killed process 2032 (oom_killer_try) total-vm:3021840kB, anon-rss:1737872kB, file-rss:0kB, shmem-rss:0kB, UID:1000 pgtables:6086656kB oom_score_adj:0
oom_reaper: reaped process 2032 (oom_killer_try), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB
$ 
```

在上述输出中，我们已经用粗体突出显示了`rss`（*Resident Set Size*）列，因为这是对所讨论进程的物理内存使用的良好指示（单位为 KB）。显然，我们的`oom_killer_try`进程使用了大量的物理内存。还要注意它的交换条目（`swapents`）数量非常高。现代内核（4.6 及更高版本）使用专门的`oom_reaper`内核线程来执行收割（杀死）受害进程的工作（上述输出的最后一行显示了这个内核线程收割了我们美妙的`oom_killer_try`进程！）。有趣的是，Linux 内核的 OOM 可以被认为是（最后的）防御措施，用来防止分叉炸弹和类似的（分布式）拒绝服务（D）DoS 攻击。

## 理解 OOM 分数

为了加快在关键时刻（当 OOM killer 被调用时）发现内存占用过多的进程，内核会为每个进程分配和维护一个*OOM 分数*（您可以随时在`/proc/<pid>/oom_score`伪文件中查找该值）。

OOM 分数范围是`0`到`1000`：

+   OOM 分数为`0`意味着该进程没有使用任何可用内存

+   OOM 分数为`1000`意味着该进程使用了其可用内存的 100％

显然，具有最高 OOM 分数的进程获胜。它的奖励-它会被 OOM killer 立即杀死（说到干燥的幽默）。不过，内核有启发式方法来保护重要任务。例如，内置的启发式方法意味着 OOM killer 不会选择任何属于 root 的进程、内核线程或具有硬件设备打开的任务作为其受害者。

如果我们想确保某个进程永远不会被 OOM killer 杀死怎么办？虽然需要 root 访问权限，但这是完全可能的。内核提供了一个可调节的`/proc/<pid>/oom_score_adj`，即 OOM 调整值（默认为`0`）。*net* OOM 分数是`oom_score`值和调整值的总和：

```
  net_oom_score = oom_score + oom_score_adj;
```

因此，将进程的`oom_score_adj`值设置为`1000`几乎可以保证它会被杀死，而将其设置为`-1000`则产生完全相反的效果-它永远不会被选为受害者。

快速查询（甚至设置）进程的 OOM 分数（以及 OOM 调整值）的方法是使用`choom(1)`实用程序。例如，要查询 systemd 进程的 OOM 分数和 OOM 调整值，只需执行`choom -p 1`。我们做了显而易见的事情-编写了一个简单的脚本（内部使用`choom(1)`）来查询系统上当前所有进程的 OOM 分数（在这里：`ch9/query_process_oom.sh`；请在您的系统上尝试一下）。快速提示：系统上 OOM 分数最高的（十个）进程可以通过以下方式快速查看（第三列是 net OOM 分数）：

```
./query_process_oom.sh | sort -k3n | tail
```

随此，我们结束了本节，也结束了本章。

# 总结

在本章中，我们延续了上一章的内容。我们详细介绍了如何创建和使用自定义的 slab 缓存（在您的驱动程序或模块非常频繁地分配和释放某个数据结构时非常有用），以及如何使用一些内核基础设施来帮助您调试 slab（SLUB）内存问题。然后，我们了解并使用了内核的`vmalloc` API（和相关内容），包括如何在内存页面上设置给定的内存保护。有了丰富的内存 API 和可用的策略，您如何选择在特定情况下使用哪一个呢？我们通过一个有用的*决策图*和表格来解决了这个重要问题。最后，我们深入了解了内核的*OOM killer*组件以及如何与其一起工作。

正如我之前提到的，对 Linux 内存管理内部和导出 API 集的深入了解将对您作为内核模块和/或设备驱动程序作者有很大帮助。事实是，我们都知道，开发人员花费了大量时间在故障排除和调试代码上；在这里获得的复杂知识和技能将帮助您更好地应对这些困难。

这完成了本书对 Linux 内核内存管理的明确覆盖。尽管我们涵盖了许多领域，但也留下或只是粗略地涉及了一些领域。

事实上，Linux 内存管理是一个庞大而复杂的主题，值得为了学习、编写更高效的代码和调试复杂情况而加以理解。

学习强大的`crash(1)`实用程序的（基本）用法（用于深入查看内核，通过实时会话或内核转储文件），然后利用这些知识重新查看本章和上一章的内容，确实是一种强大的学习方式！

在完成了 Linux 内存管理的学习之后，接下来的两章将让您了解另一个核心操作系统主题-在 Linux 操作系统上如何执行*CPU 调度*。休息一下，完成以下作业和问题，浏览引起您兴趣的*进一步阅读*材料。然后，精力充沛地跟我一起进入下一个令人兴奋的领域！

# 问题

最后，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会在本书的 GitHub 存储库中找到一些问题的答案：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入研究这一主题并获取有用的材料，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）的“进一步阅读”文档。*进一步阅读*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。
