# CompTIA Linux 认证指南（六）

> 原文：[`zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E`](https://zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：互联网协议基础知识

在上一章中，重点是维护系统的时间和日志记录。特别是，我们触及了可以操纵系统的方法。接下来，我们处理了日志记录并探讨了常见的日志文件。最后，我们使用远程。然后我们在我们的 Fedora 系统上生成了测试日志，并验证我们在 Ubuntu 的`rsyslog`服务器上收到了日志。

本章的重点是**Internet Protocol**（**IP**）。我们从 IPv4 开始，查看地址结构和今天环境中常用的各种 IPv4 地址。然后我们转向对 IPv4 地址进行子网划分，确定 IPv4 地址的网络和主机部分。然后是 IPv6。我们看一下 IPv6 地址的结构和一些知名的 IPv6 地址。然后我们关注如何缩短冗长的 IPv6 地址。最后，我们的重点是协议。我们将介绍一些知名的协议及其相应的端口号。

我们将涵盖以下主题：

+   IPv4 寻址

+   IPv6 寻址

+   知名协议

# IPv4 寻址

IP 版本 4 是 IP 的第四个版本。它在我们所知的互联网中扮演着至关重要的角色。到目前为止，IPv4 是在网络和互联网中为各种设备寻址最常用的协议。关于 IP 的另一个有趣的事实是，它不像 TCP 那样是面向连接的；相反，IP 是无连接的。

IPv4 地址由 32 位或 4 字节组成。我们使用 2 进制计算地址；这给我们 2³²，相当于 4,294,967,296 个地址。看起来 IPv4 地址很多；然而，现实并非如此。事实上，目前存在 IPv4 短缺。IPv4 地址以点分十进制格式表示。IPv4 地址的一个示例如下：

```
192.168.1.1
```

在这里，我们可以看到 IPv4 地址确实是以点分十进制格式表示的。点`.`充当地址之间的分隔符。数字可以在 0 到 255 之间的任何位置，包括 0 和 255。IPv4 地址的每部分称为一个八位组；因此，这四个数字组成了四个八位组。在今天的环境中有各种类型的 IPv4 地址；特别是在**局域网**（**LAN**）中，您可能会看到以下之一：

+   `10.0.0.0/8`

+   `172.16.0.0/12`

+   `192.16.0.0/16`

这些地址可能看起来很熟悉。这三个地址可以通过 RFC 1918 进一步解释；这个规范了一些应在私人网络中使用的地址，比如 LAN。

我们有五类地址空间；前四类地址在各种环境中常用。这些是地址类：

| Class A |  0-127 |
| --- | --- |
| Class B |  128-191 |
| Class C  | 192-223 |
| Class D | 224-239 |
| Class E |  240-255 |

在这里，数字范围代表第一个八位组中的占位符。我们可以分解 IPv4 地址以便更好地理解。我们将使用第一个八位组作为参考。首先，我们将建立一个表。IPv4 地址的每个八位组代表 1 个字节；1 个字节 = 8 位。然后我们可以使用这些信息来形成我们的表：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 18 | 4 | 2 | 1 |  = 255 |

太棒了！基于这一点，我们从 7 数到 0 的原因是因为在计算 IPv4 地址中的一个八位组的值时，我们总是从 0 开始，并且在添加时从右向左移动。现在，我们得到值的方式是通过乘以 2^x，其中 x = 最右边的字符。因此，它将如下所示：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 1 表示该位被打开 |
| 2^ | 2^ | 2^ | 2^ | 2^ | 2^ | 2^ | 2^ |  = 2 进制 |
| 128 |  6 | 32 |  16 |   8  | 4    |  2  |  1  |  = 每个位位置的 2 进制结果 |

使用 8 位中的所有值，我们得到*128+64+32+16+8+4+2+1 = 255*。

基于这一点，我们现在看到表是如何使用二进制进行计算的。因此，在任何给定时间，只有 0-255 之间的值，包括 0 和 255，才是合法值。

# A 类

A 类地址空间 0-127，只看第一个八位字节中的领先位（因为我们从 0 到 7 进行计数）；这被称为最重要的位位置。127 地址空间被保留；这被称为环回地址空间。因此，我们只使用值 0-126。此外，0 实际上是保留用于网络使用（稍后在我们讨论子网划分时会详细介绍）。现在，我们计算 A 类地址的第一个值的方式如下：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  =255 |
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |  = 0-127 |

基于这一点，我们在第一个八位字节中关闭了所有八位。因此，这给了我们类 A 地址空间，即第一个八位字节在 0-126 之间，0 被保留，127 被保留为环回空间。因此，第一个八位字节中真正可用的 IPv4 地址是 1-126。然后，接下来的三个八位字节都是零。因此，类 A 地址空间将如下所示：

+   A 类`0-126.0.0.0/8`，其中第 8 位位置为 0

+   A 类保留地址空间`127.0.0.0/8`

+   A 类**自动私有 IP 地址**（APIPA）`169.0.0.0/8`保留

基于这一点，我们可以定义最多 126 个网络。A 类地址的剩余三个八位字节`0.0.0`组成了主机部分；每个八位字节由八位组成。主机是可以分配 IPv4 地址的任何设备。A 类地址允许的最大主机数量是每个网络的 1677216-2 = 16,777,214 个主机。主机部分是 2³ 个八位字节的结果（每个八位字节 8 位 x 3 = 24 位）- 2 = 1677216-2 =每个 A 类网络的 16,777,214 个主机。

# B 类

B 类地址空间 128-191，查看领先位位置 7 和 6（记住我们从 0 开始计数，从左到右移动）。最重要的位，位置 7，在二进制中被打开。这被设置为 1，第二最重要的位，位置 6，被设置为 0。这可以通过我们之前创建的表来看到：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  =255 |
| 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |  = 128 |

基于这一点，最重要的位被打开，第二最重要的位被关闭。这给了我们地址空间为 128-191，其中 128 被保留用于网络使用，191 被保留为广播地址。我们将在本章后面讨论广播地址时讨论。在 B 类地址空间中，前 16 位被保留用于网络使用；然而，有两位被保留。这将给我们每个 B 类地址的 16384 个网络。这可以如下所示：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 255 |
| 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |  = 128 |

我们必须跳过前两位，位置 7 和 6；这样我们就得到了 2¹⁴ = 163864 个网络

基于这一点，我们看到了可用网络的最大数量，但我们没有看到最大主机数量。我们计算 B 类地址的主机的方式是使用最后两个八位字节作为主机；我们将进行 2² 个八位字节（每个八位字节 8 位 x 2 = 16 位）-两位用于网络和广播= 65,536-2 =每个 B 类网络的 65,534 个主机。

# C 类

类 C 地址空间，192-223，考虑了前三位最重要的位；即，位置 7、6 和 5。前两位最重要的位被打开；它们在二进制中设置为 1。第三位，二进制中的位置 5，被关闭；这被设置为 0。前 24 位被保留用于类 C 地址空间中的网络使用。然后我们可以使用这些信息构建我们的表。表格如下：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  =255 |
| 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |  = 128+64=>192 |

基于此，我们可以看到类 C 地址空间从 192 开始，到 223 结束。192 保留为网络，223 保留为广播。然后我们可以通过使用 2²¹ = 2,097,152 个网络来计算网络的数量。这可以用以下表格表示：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  =255 |
| 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |  = 前 3 位总共 192 |

24 位被保留用于类 C，24 位—三个最重要的位= 21，然后 2²¹ 位= 2,097,152 个网络。

最后一个八位`.0`保留用于主机地址。这意味着每个 C 类地址有 2¹ 个八位（8 位）- 2 位用于网络和广播= 256 - 2 = 254 个主机。

# 类 D

类 D，224-239，地址空间保留用于多播。前三位最重要的位被打开；它们被设置为 1。第四位最重要的位设置为 0。类 D 地址空间不用于 IP 寻址，就像前几个地址空间一样。相反，类 D 地址空间用于为多播组分配 IP 地址。然后主机是多播组的一部分，反过来共享一个组地址。以下表格说明了用于类 D 地址空间的位：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 255 |
| 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |  = 总共 224 |

基于此，类 D 地址空间从`224.0.0.0`开始，到`239.255.255.255`结束。

# 类 E

类 E，240-255，地址空间保留用于将来使用。因此，它不像以前的地址空间那样被实现。前四位最重要的位被打开；它们被设置为 1。在类 E 中唯一使用的地址是`255.255.255.255`；这就是所谓的所有广播地址。以下表格说明了用于类 E 地址空间的位：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 8 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 255 |
| 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |  = 总共 240 |

基于此，类 E 地址空间从`240.0.0.0`开始，到`255.255.255.255`结束，其中`255.255.255.255`保留为所有广播地址。

# 子网掩码

我们刚刚介绍了 IPv4 地址空间的各种类别，但在某些情况下，使用这些地址空间的类别可能不合适。事实上，如果我们使用这些 IP 地址类别的默认子网掩码，那么 A 类、B 类和 C 类都是有类别的地址空间。例如，A 类使用子网掩码`255.0.0.0`。但是，等等，什么是子网掩码？首先，子网掩码标识给定 IP 地址的网络部分和主机部分。这包括 IPv4 和 IPv6。子网掩码使我们能够轻松地找出给定 IP 地址的网络地址。子网掩码通常以点分十进制格式编写。但是，也可以用斜杠表示法来表示子网掩码；即 CIDR 表示法。CIDR（无类别域间路由）简称，通过在 IP 地址后附加网络位数的斜杠格式来表示子网掩码。对于 A 类地址，子网掩码如下：

```
255.0.0.0
```

基于此，值`255.0.0.0`表示前八位组中的所有位都被打开；它们被设置为 1。我们可以用之前创建的表来表示这一点：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^ 位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 打开的位数 |

128+64+32+16+8+4+2+1 = 255 位

基于此，255 的值来源于所有八位都被打开的总和。除此之外，子网掩码也可以用二进制格式表示。使用 A 类地址，子网掩码可以写成如下形式：

+   **十进制格式的 A 类子网掩码**：`255.0.0.0`

+   **二进制格式的 A 类子网掩码**：`11111111.00000000.00000000.00000000`

太棒了！现在我们可以看到子网掩码可以用 0-255 之间的值以十进制格式表示，也可以用 0 或 1 的值以二进制格式表示。此外，还可以用 CIDR 表示子网掩码。我们可以用以下格式表示 CIDR 格式的 A 类地址：

+   **十进制格式的 A 类子网掩码**：`255.0.0.0`

+   **二进制格式的 A 类子网掩码**：`11111111.00000000.00000000.00000000`

+   **CIDR 格式的 A 类子网掩码**：`/8`

基于此，`/8`表示地址的网络部分有八位被打开。

使用 B 类地址，我们可以用点分十进制格式表示 B 类地址如下：

```
255.255.0.0
```

基于此，值`255.255.0.0`表示前两个八位组中的所有位都被打开；它们被设置为 1。我们可以用之前创建的表来表示这一点：

第一个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^ 位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 打开的位数 |

128+64+32+16+8+4+2+1 = 255 位

第二个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^ 位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 打开的位数 |

128+64+32+16+8+4+2+1 = 255 位

基于此，值`255.255.0.0`来源于所有 16 位都被打开的总和。除此之外，子网掩码也可以用二进制格式表示。使用 B 类地址，子网掩码可以写成如下形式：

+   **十进制格式的 B 类子网掩码**：`255.255.0.0`

+   **二进制格式的 B 类子网掩码**：`11111111.11111111.00000000.00000000`

太棒了！现在我们可以看到子网掩码可以用 0-255 之间的值以十进制格式表示，也可以用 0 或 1 的值以二进制格式表示。此外，还可以用 CIDR 表示子网掩码。我们可以用以下格式表示 CIDR 格式的 B 类地址：

+   **十进制格式的 B 类子网掩码**：`255.255.0.0`

+   **二进制格式的 B 类子网掩码**：`11111111.11111111.00000000.00000000`

+   **CIDR 格式的 B 类子网掩码**：`/16`

基于此，`/16`表示地址的网络部分有十六位被打开。

使用 C 类地址，我们可以用点分十进制格式表示 C 类地址如下：

```
255.255.255.0
```

基于此，值`255.255.255.0`表示前两个八位组中的所有位都被打开；它们被设置为 1。我们可以用之前创建的表来表示这一点：

第一个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^ 位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 打开的位数 |

128+64+32+16+8+4+2+1 = 255 位

第二个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^ 位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 打开的位数 |

128+64+32+16+8+4+2+1 = 255 位

第三个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^ 位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 打开的位数 |

128+64+32+16+8+4+2+1 = 255 位

基于此，`255.255.255.0`的值是由所有 24 位打开的总和得出的。此外，子网掩码也可以用二进制格式表示。使用 C 类地址，子网掩码可以写成以下形式：

+   **十进制中的 C 类子网掩码**：`255.255.255.0`

+   **二进制中的 C 类子网掩码**：`11111111.11111111.11111111.00000000`

太棒了！现在，我们可以看到子网掩码可以用 0-255 之间的值以十进制格式表示，也可以用 0 或 1 的值以二进制格式表示。此外，可以用 CIDR 表示子网掩码。我们可以用以下方式用 CIDR 格式表示 C 类地址：

+   **十进制中的 C 类子网掩码**：`255.255.255.0`

+   **二进制中的 C 类子网掩码**：`11111111.11111111.11111111.00000000`

+   **CIDR 中的 C 类子网掩码**：`/24`

基于这一点，`/24`表示地址的网络部分有 24 位打开。

# 子网划分

正如我们刚刚看到的 A、B 和 C 类，它们的子网掩码分别使用 CIDR 表示为`/8`、`16`和`24`。在今天的大多数环境中，这些默认子网掩码被称为类别，这意味着如果我们使用这些子网掩码，我们将无法执行任何形式的流量工程。当我们想要控制广播域时，这就成了一个问题。我们应该尽量减少广播到特定的房间、办公室或部门。这确保在任何类型的网络广播事件发生时，整个网络不会开始出现延迟。我们可以利用子网划分来克服类别网络的限制。例如，让我们选择一个 C 类 IP 地址：

```
192.168.0.0/24
```

基于此，每个网络地址最多可以有 254 个主机。我们可能会遇到这样的情况，我们只有八个系统需要 IP 连接。这意味着我们正在失去那些剩余的 IP 地址，因为我们使用了默认的 C 类子网。在这种情况下的要求是有八个 IP 地址，而不是浪费剩下的 IP 地址。我们可以通过子网划分来实现这个要求。子网划分是通过从主机部分借用位来实现的。让我们写出给定 IP 地址的子网掩码：

```
192.168.0.0/24 Network
```

+   **十进制中的子网掩码**：`255.255.255.0 `

+   **二进制中的子网掩码**：`11111111.11111111.11111111.00000000 `

基于此，前 24 位被打开。我们可以对这个地址进行子网划分，以便更好地控制我们的 IP 地址空间。我们想要八个 IP 地址。我们借用位的方式是从主机位中取位。我们可以使用我们的表格来帮助：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  =2^ 位位置 |
| 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |  =借用了 4 位  |

+   2⁴ 位 = 可以创建 16 个网络

+   2⁴ -2 =每个网络 14 个主机

基于此，我们从网络的主机部分借用了四位；这使我们能够创建四个更小的子网/网络。然后，每个创建的网络将有 14 个主机。这使我们能够节省 IP 地址的数量，而不是使用标准的 C 类`/24`网络。因此，我们从网络部分借用了四位。我们如何用十进制和 CIDR 表示这一点呢？嗯，我们表示新创建的子网的方式是通过添加网络位。这可以在以下表格中说明： 

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  =2^ 位位置 |
| 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |  =4 位  |

128+64+32+16 = 240

+   旧的十进制子网 = `255.255.255.0`

+   老子网在 CIDR = `/24`

+   新的十进制子网 = `255.255.255.240`

+   新的 CIDR 子网 = `/28`

+   网络地址 = `192.168.0.0/28`

基于此，我们可以看到新的子网掩码的十进制和 CIDR 表示。下一步是使用这个新的子网掩码来识别可用的子网/网络。我们可以使用以下表格来计算可用的子网：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^位位置 |
| 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |  = 4 位 |

网络按位位置的 2 进制值递增：

+   **第一个网络**：`192.168.0.0/28`

+   **第二个网络**：`192.168.0.16/28`

+   **第三个网络**：`192.168.0.32/28`

+   **第四个网络**：`192.168.0.48/28`

+   **直到第十六个网络**：`192.168.0.240/28`

基于这一点，我们可以看到第四个八位组是增量发生的地方。特别是对于`/28`，子网增量为 16；这是因为计算得到的 2⁴ 位位置=16。最后一步是确定可以分配给网络内主机的可用 IP。我们将使用以下作为分解：

+   **第一个子网/网络**：`192.168.0.0/28`

+   **第一个可用 IP 地址**：`192.168.0.1/28`

+   **最后一个可用 IP 地址**：`192.168.0.14/28`

+   **广播 IP 地址**：`192.168.0.15/28`

+   **第二个子网/网络**：`192.168.0.16/28`

基于这一点，我们可以看到有两个 IP 是不可用的。这些是我们在计算主机 IP 时考虑的因素。同样，我们可以通过以下分解来获得第二个子网`192.168.0.16/28`的可用 IP：

+   **第二个子网/网络**：`192.168.0.16/28`

+   **第一个可用 IP 地址**：`192.168.0.17/28`

+   **最后一个可用 IP 地址**：`192.168.0.30/28`

+   **广播 IP 地址**：`192.168.0.31/28`

+   **第三个子网/网络**：`192.168.0.32/28`

太棒了！基于这一点，我们可以看到一个模式；我们总是最终得到 14 个可用的 IP 地址。此外，我们可以对 B 类地址进行子网划分，并利用主机位来更好地管理我们的网络。让我们使用以下 B 类地址：

```
172.16.0.0/16
Subnet mask:255.255.0.0
```

基于这一点，每个网络有超过 65,000 个主机 IP；这在大多数环境中都不理想。例如，我们想要对这个 IP 进行子网划分，以获得 500 个主机 IP。这可以通过从地址的主机部分借用一些主机位来实现。我们可以使用以下分解来帮助我们：

```
255.255.0.0
11111111.11111111.00000000.00000000 =/16 bits being used
```

我们计算主机的方法是从右到左移动。

第四个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  = 8 位总共 255 |

2⁸ = 255-2 = 每个网络 254 个主机。

第三个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^位位置 |
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |  = 9 位打开 |

2⁹ = 512 -2 = 每个网络 510 个主机。

太棒了！基于这一点，为了满足要求，需要九位。这意味着我们将不得不从第三个八位组借用八位来满足要求。我们可以通过以下方式进行分解：

```
255.255.0.0
11111111.11111111.11111110.00000000 =/23 bits being used.
```

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |  = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |  = 2^位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |  = 7 位打开 |

```
Eight bits in first octet + eight bits in second octet + seven bits in third octet =23 bits
The sum of the bits turned on in the third octet 128+64+32+16+8+4+2 =254
The new subnet mask in decimal = 255.255.254.0
```

基于这些计算，新网络将被写成如下：

```
172.16.0.0/23
The total number of subnets = 2 ^ 7 = 128 subnets created
The total number of hosts per subnet/network =2⁹ - 2 = 512 -2 = 510 hosts per subnet/network
Subnets = 172.16.0.0/23 , 172.16.2.0/23, 172.16.4.0/23, 172.16.6.0/23 - 172.16.254.0/23
```

基于这一点，我们有每个子网的总子网和主机。现在，我们需要计算每个子网的可用 IP 地址。这可以通过以下分解来完成：

+   **第一个子网/网络**：`172.16.0.0/23`

+   **第一个可用 IP**：`172.16.0.1/23`

+   **最后一个可用 IP**：`172.16.2.254/23`

+   **广播 IP**：`172.16.2.255`

+   **第二个子网/网络**：`172.16.2.0/23`

基于这一点，我们可以看到可用的 IP 地址；`172.16.2.255`是使用`/23`子网的有效 IP。同样，`172.16.1.0/23`也是有效的 IP 地址。在一些操作系统中，比如 Windows，如果你尝试分配这两个 IP 中的任何一个，可能会遇到错误。然而，在 Linux 中，一切都是公平的。我们通过增量子网 2 来增量，因为这是最后一个网络位的位置。

我们甚至可以对 A 类地址进行子网划分。例如，假设我们想要从单个 A 类地址创建 100 个子网。我们将使用以下：

```
10.0.0.0/8
255.0.0.0
```

我们可以使用之前创建的表来做到这一点。

第二个八位组：

| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | = 位位置 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 | = 2^位位置 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | = 7 位打开 |

太棒了！基于此，我们可以快速推导出我们需要从第二个八位组借用七位来创建 100 个子网。实际上，我们将有 128 个子网。这是因为我们正在计算第二个八位组中的 2⁷ 位。然后我们可以按以下格式写出我们的子网：

```
11111111.11111110.00000000.00000000
Subnet 255.254.0.0 /15
Subnets 10.0.0.0/15, 10.2.0.0/15, 10.4.0.0/15, 10.6.0.0/15 - 10.254.0.0/15
```

太棒了！这么容易就对 A 类进行子网划分。现在我们需要计算每个子网的主机总数。我们可以使用以下方法：

```
Subnet in binary
11111111.11111110.00000000.00000000
Network bits are represented by n
Host bits are represented by h
nnnnnnnn.nnnnnnnh.hhhhhhhh.hhhhhhhh
2¹⁷ -2 = 131072 - 2 = 131070 hosts per subnet/network
```

基于此，我们可以看到使用`/15`每个子网获得了相当多的主机。我们可以使用以下方法来推导每个子网的可用 IP：

+   第一个子网/网络：`10.0.0.0/15`

+   第一个可用 IP：`10.0.0.1/15`

+   最后一个可用 IP：`10.2.255.254/15`

+   广播 IP：`10.2.255.255`

+   第二个子网/网络：`10.2.0.0/15`

太棒了！计算任何一个子网的最简单方法是始终将网络位乘以 2。要计算总主机数，始终将主机位乘以 2，然后减去 2 得到网络和广播地址。

# IPv6 寻址

互联网协议第 6 版（IPv6），由互联网工程任务组（IETF）开发。IPv6 地址旨在解决 IPv4 地址短缺问题。IPv4 已经完全耗尽，公司现在愿意以巨额资金交换他们的 IPv4 地址块。IPv6 地址长度为 128 位或 16 字节。这给了我们 2¹²⁸ 个 IPv6 地址。IPv6 地址以十六进制格式表示。有三种类型的 IPv6 地址。

# 单播

单播地址指定设备上单个接口的标识符，类似于 IPv4 地址。使用 IPv6，很可能所有 IPv6 流量大多是基于单播的。

# 多播

IPv6 多播地址的概念类似于 IPv4 地址。数据包被发送到 IPv6 多播地址，属于多播组的接收者将接收多播数据包。

# 单播

这种地址类型是在 IPv6 中引入的。任播的概念是通过将多个设备分配相同的任播 IPv6 地址来工作。当发送者向任播 IPv6 地址发送数据包时，任播数据包通过路由协议路由到距离发送者最近的主机。

以下是 IPv6 地址的示例：

```
2001:0db8:0000:0000:0000:ff00:0042:8329
```

基于此，我们可以看到 IPv6 地址由八组 16 位或 2 字节值组成，用冒号分隔。这就是我们得到 128 位或 16 字节长度的方法。写 IPv6 地址可能看起来很长，但我们可以使用一些方法使 IPv6 地址变得更小。

# 删除前导零

我们可以删除 IPv6 地址中的前导零，从而使其更易读：

```
2001:0db8:0000:0000:0000:ff00:0042:8329
2001:db8:0:0:0:ff00:42:8329
```

太棒了！基于此，我们使 IPv6 地址更加易于呈现。但是，请等一下，我们还可以通过使用下面描述的技术使其更小。

# 删除连续的零

我们可以删除 IPv6 地址中连续的零，并用双冒号替换这些零。这只能做一次：

```
2001:db8::ff0:42:8329
```

太棒了！正如我们所看到的，IPv6 地址现在更易读。此外，在浏览器中输入 IPv6 地址时，我们会执行以下操作：

```
http://[ 2001:db8::ff0:42:8329]/
```

基于此，我们会用方括号括起 IPv6 地址。有一些特殊类型的单播 IPv6 地址值得一提：

+   全局单播地址：这些地址以`2000::/3`开头，如 RFC 4291 中所述。它们是类似于公共 IPv4 地址的可公开路由地址。

+   链路本地地址：这些地址以`fe80::/10`开头；它们仅在本地物理链路上有效。

+   站点本地地址：这些地址以`fec::/10`开头；它们仅在单个站点内有效。它们已被 RFC 机构弃用。

+   **唯一本地地址**：这些地址以`fc00::/7`开头；它们旨在在一组合作站点内进行路由。它们旨在取代站点本地地址。唯一本地地址的一个有趣特点是它们减少了地址冲突的风险。

有一些类似于 IPv4 的特殊 IPv6 地址。以下是一些保留的 IPv6 地址：

| `2000::/3` | 全局单播 |
| --- | --- |
| `::/128` | 未指定地址 |
| `::/0` | 默认路由 |
| `::1/128` | 回环地址 |
| `FF00::/8` | 多播地址 |

太棒了！在识别子网方面，我们需要解析 IPv6 地址。我们可以使用以下方法进行分解：

```
2001:db8:0000:0000:0000:ff0:42:8329
```

| 全局路由前缀 | 子网 | 主机 ID |
| --- | --- | --- |
| `2001:db8:0000:` | `0000:` | `0000:ff0:42:8329` |
| 48 位或 3 字节 | 16 位或 2 字节 | 64 位或 8 字节 |

基于此，全局路由前缀由 48 位组成。子网由接下来的 16 位组成。主机标识符由最后的 64 位组成。

# 知名协议

我们在环境中使用许多我们需要了解的知名协议。首先，当我们浏览互联网时，实际上是使用 HTTP 协议来查看网页。此外，当我们从服务器复制文件并提供身份验证时；在后台，我们使用某种 FTP 协议。同样，当我们输入 URL 时，实际上是使用 DNS 进行名称解析。正如我们所看到的，我们在我们的环境中使用了许多协议。接下来描述了一些知名协议及其相应的端口号。

# TCP

**传输控制协议**（**TCP**）是一种面向连接的协议，提供了许多服务，包括错误检查和排序等。它在 OSI 模型的第 4 层，即传输层上运行。

# HTTP

**超文本传输协议**（**HTTP**）按需提供网页；这是互联网上通过 URL 进行数据通信的协议。它使用端口`80`进行通信。此外，它建立在 TCP 之上。

# HTTPS

**超文本传输安全协议**（**HTTPS**）为互联网上的 URL 提供安全通信。它使用端口`443`进行通信。此外，它的通信使用**传输层安全**（**TLS**）。它建立在 TCP 之上。

# FTP

**文件传输协议**（**FTP**）用于在客户端和服务器之间传输文件。这可以在局域网内或通过互联网进行。FTP 支持身份验证，但所有传输都是明文发送的；没有内置安全性。FTP 使用 TCP 端口`20`进行数据传输和端口`21`进行命令传输。

# UDP

**用户数据报协议**（**UDP**）是一种无连接协议，提供速度但不进行任何错误检查。它在 OSI 模型的第 4 层，即传输层上运行。

# DNS

**域名系统**（**DNS**）提供了将 IP 地址转换为用户友好的名称的手段，用户可以与之相关联。它通常使用 UDP 端口`53`，但每当请求或响应大于一个数据包时，也使用 TCP 端口`53`。

# TFTP

**简单文件传输协议**（**TFTP**）用于以快速速率传输数据。不支持任何身份验证方法；也没有错误检查。TFTP 使用 UDP 端口`69`。

# ICMP

**互联网控制消息协议**（**ICMP**）是网络环境中使用的另一种协议。通常用于通过局域网或互联网在各种网络设备之间发送消息进行故障排除。还有 ICMPv6，用于 IPv6。ICMP 使用 IP 协议`1`，而 ICMPv6 使用 IP 协议`58`。

# 总结

在本章中，我们深入研究了 IPv4 和 IPv6 的世界。除此之外，我们还涵盖了子网掩码和识别子网掩码的方法。接下来，我们介绍了子网划分。我们通过了一些示例，并说明了推导所需主机数量和所需子网数量的技术。最后，我们使用了一些知名的协议。我们涵盖了一些最广泛使用的协议及其端口号。

在下一章中，我们将继续进行网络配置和故障排除。我们将在 Linux 系统上工作，分配 IPv4 地址和 IPv6 地址，并查看各种网络连接故障排除的方法。

# 问题

1.  哪个地址是 A 类地址？

A. `192.0.0.1`

B. `172.0.0.1`

C. `10.0.0.1`

D. 以上都不是

1.  哪个地址是 C 类地址？

A. `128.0.0.1`

B. `100.0.0.2`

C. `192.168.0.1`

D. 以上都不是

1.  哪个地址被称为 IPv4 环回地址？

A. `127.0.0.1`

B. `169.0.0.1`

C. `172.16.0.1`

D. `192.1.1.1`

1.  哪个地址是 APIPA 地址？

A. `169.0.0.1`

B. `172.16.0.1`

C. `10.1.1.1`

D. `192.168.1.1`

1.  哪个地址是 B 类地址？

A. `128.0.0.1`

B. `10.11.1.1`

C. `127.0.0.1`

D. 223.0.0.1

1.  IPv6 组播地址以什么开头？

A. `fc0e::/8`

B. `fce::/7`

C. `ff00::/8`

D. `fd0:/9`

1.  哪个地址是 IPv6 默认路由？

A. `::1/0`

B. `::/0`

C. `01A:00000000:00000000:00000000:00000000::9`

D. ::1/128

1.  哪个地址是 IPv6 环回地址？

A. `::0/1`

B. `::0/0`

C. `::1/128`

D. `::128/128`

1.  链路本地地址以什么开头？

A.`ff00::/8` B.`fc00::/10` C.`fcd00::128` D.`fe80::/10`

1.  HTTP 使用哪个端口？

A.TCP `10` B.UDP `80` C.TCP `80` D.UDP `69`

# 进一步阅读

+   这个网站提供了有关 IP 的有用信息：[`tools.ietf.org`](https://tools.ietf.org)

+   这个网站提供了有关子网划分的有用信息：[`www.quora.com`](https://www.quora.com)

+   这个网站提供了有关 IPv6 的有用信息：[`www.ipv6.com`](https://www.ipv6.com)


# 第十六章：网络配置和故障排除

在上一章中，我们深入研究了 IPv4 或 IPv4 和 IPv6 或（IPv6）的世界。除此之外，我们还涵盖了子网掩码。之后，我们涵盖了子网划分。最后，我们使用了一些知名协议。我们涵盖了一些最常用的协议及其端口号。

在本章中，我们的重点转向了 IPv4 和 IPv6 的配置。首先，我们将研究配置 IPv4 地址及其子网掩码的方法。接下来，我们将查看 Linux 系统中的路由表；特别是配置静态路由，最后是默认路由配置。然后是在 Linux 系统中配置 IPv6 地址；然后是 IPv6 的路由表。然后是配置 IPv6 路由；最后是配置 IPv6 的默认路由。之后，我们的重点转向 DNS 的配置；特别是在 Linux 环境中配置指向 DNS 服务器的 DNS IP 地址。最后，本章结束于网络故障排除；我们将研究各种命令行工具，以帮助我们解决潜在的连接问题。

在本章中，我们将涵盖以下主题：

+   IPv4 配置

+   IPv6 配置

+   客户端 DNS

+   网络故障排除

# IPv4 配置

在 Linux 系统中，有各种配置 IPv4 地址的方法。首先，我们可以使用 GUI 实用程序执行 IPv4 配置。让我们看看我们的 Ubuntu 18 系统。

我们可以选择网络图标，然后选择下拉箭头，选择有线设置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00156.jpeg)

太棒了！根据我们在上一个例子中所看到的，当我们选择有线设置时，它会打开设置对话框；之后，我们应该选择齿轮图标。然后会打开网络设置。为了配置 IPv4 设置，我们会选择 IPv4 选项卡，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00157.jpeg)

根据前面的例子，我们可以看到 IPv4 寻址的默认方法是自动（DHCP）；这意味着系统将通过网络上配置为动态分配 IPv4 寻址信息的服务器获取其 IPv4 寻址信息。为了演示目的，我们希望使用手动方法分配 IPv4 地址。在我们选择手动后，将出现一个地址字段，允许我们输入 IPv4 寻址信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00158.jpeg)

很棒！根据之前的截图，我们可以看到我们有机会输入 IPv4 信息。我们已经输入了一个 IPv4 地址；此外，我们会看到一个名为 Netmask 的文本框，这是子网掩码的另一个名称。一旦我们完成了输入 IPv4 地址信息，我们就会选择应用按钮。需要记住的一件重要事情是，我们可以在接口上配置多个 IPv4 地址。是的！我们可以简单地点击第二行的文本框并输入我们选择的 IPv4 地址，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00159.jpeg)

根据我们在上一个例子中所看到的，当我们输入第二个 IPv4 地址时，第三行会出现另一个文本框；如果我们在第三行输入 IPv4 地址，这种情况会再次发生。一旦我们对配置满意，我们应该选择应用按钮以保存更改。管理 IPv4 寻址的另一种方法是通过 shell；我们可以使用命令提示符处的各种命令添加和删除 IPv4 地址。

# ifconfig 命令

`ifconfig`命令可以用于在命令行管理 IPv4 地址信息。我们可以运行`ifconfig`命令而不带任何选项，它将只显示活动接口，如下面的命令所示：

```
root@philip-virtual-machine:/home/philip# ifconfig
Command 'ifconfig' not found, but can be installed with:
apt install net-tools
root@philip-virtual-machine:/home/philip#
```

根据我们在前面的命令中找到的信息，我们看到`ifconfig`实用程序在 Ubuntu 18 中默认没有安装；这可以通过运行`apt`或`apt-get`命令轻松解决，如下面的示例所示：

```
root@philip-virtual-machine:/home/philip# apt install net-tools
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following NEW packages will be installed:
 net-tools
Setting up net-tools (1.60+git20161116.90da8a0-1ubuntu1) ...
root@philip-virtual-machine:/home/philip#
```

为了简洁起见，一些输出已被省略。现在我们可以再次运行`ifconfig`命令，如下所示：

```
root@philip-virtual-machine:/home/philip# ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.175.132  netmask 255.255.255.0  broadcast 172.16.175.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 75738  bytes 57194615 (57.1 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35446  bytes 3084763 (3.0 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
 inet 127.0.0.1  netmask 255.0.0.0
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
 loop  txqueuelen 1000  (Local Loopback)
 RX packets 17102  bytes 1274792 (1.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 17102  bytes 1274792 (1.2 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip#
```

太棒了！根据我们在前面的代码中找到的信息，我们可以看到我们获得了大量信息；特别是 IPv4 地址位于`inet`部分。我们可以通过筛选来显示只有 IPv4 地址信息，如下所示的代码：

```
root@philip-virtual-machine:/home/philip# ifconfig | grep inet
 inet 172.16.175.132  netmask 255.255.255.0  broadcast 172.16.175.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 inet 127.0.0.1  netmask 255.0.0.0
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
root@philip-virtual-machine:/home/philip#
```

根据前面的代码，我们可以看到 IPv4 地址信息以及一些 IPv6。我们之前配置了另外两个 IPv4 地址；然而，它们没有显示出来，因为默认情况下只会显示主要的 IPv4 地址。我们将在下一个命令中看到如何轻松查看这些额外的 IPv4 地址。除了查看活动接口，我们还可以查看非活动接口；我们将传递`-a`选项，如下面的代码所示：

```
root@philip-virtual-machine:/home/philip# ifconfig -a
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.175.132  netmask 255.255.255.0  broadcast 172.16.175.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 75817  bytes 57204880 (57.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35485  bytes 3087793 (3.0 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
 inet 127.0.0.1  netmask 255.0.0.0
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
 loop  txqueuelen 1000  (Local Loopback)
 RX packets 17110  bytes 1275456 (1.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 17110  bytes 1275456 (1.2 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip#
```

根据我们在前面的示例中所看到的，这个系统上只有一个物理接口，所以输出与运行不带任何选项的`ifconfig`命令的输出相同。此外，我们可以选择要显示的接口，使用`ifconfig`命令；我们将指定接口，如下面的代码所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.175.132  netmask 255.255.255.0  broadcast 172.16.175.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 75825  bytes 57205574 (57.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35493  bytes 3088408 (3.0 MB)
 TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
root@philip-virtual-machine:/home/philip#
```

太棒了！这在系统可能有很多接口并且你只对特定接口感兴趣的情况下非常有用。我们可以使用`ifconfig`命令分配 IPv4 地址；我们只需传递接口和 IPv4 地址，如下面的代码所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33 172.10.1.1
root@philip-virtual-machine:/home/philip# ifconfig ens33
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.10.1.1  netmask 255.255.0.0  broadcast 172.10.255.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 76407  bytes 57564515 (57.5 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35550  bytes 3099266 (3.0 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip#
```

根据我们在前面的代码中找到的信息，我们可以看到主要的 IPv4 地址已经更改为我们指定的 IPv4 地址。那么如果我们不想删除先前的 IPv4 地址呢？我们可以通过创建一个别名接口来满足这个要求；它只是一个逻辑接口。然后我们将第二个 IPv4 地址分配到别名接口上。这是我们将如何完成这个任务的方式：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33 172.16.175.132/24
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 172.10.1.1
root@philip-virtual-machine:/home/philip# ifconfig ens33
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.175.132  netmask 255.255.255.0  broadcast 172.16.175.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 76902  bytes 57781395 (57.7 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35579  bytes 3104505 (3.1 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip# ifconfig ens33:0
ens33:0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.10.1.1  netmask 255.255.0.0  broadcast 172.10.255.255
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip#
```

太棒了！基于此，我们现在可以看到我们在物理接口上有原始的 IPv4 地址，另外还创建了一个具有次要 IPv4 地址的别名接口。需要注意的是，当我们为别名接口指定 IPv4 地址时，我们没有指定任何子网掩码。系统根据第一个八位自动检测了子网掩码；子网掩码设置为`255.255.0.0`或`/16`的 B 类子网掩码。我们可以通过删除 IPv4 地址然后以 CIDR 表示法添加带有子网掩码的 IPv4 地址来解决这个问题，如下面的代码所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 down
root@philip-virtual-machine:/home/philip# ifconfig ens33:0
ens33:0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 172.10.1.1/23
root@philip-virtual-machine:/home/philip# ifconfig ens33:0
ens33:0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.10.1.1  netmask 255.255.254.0  broadcast 172.10.1.255
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip#
```

干得好！根据我们在前面的代码中找到的信息，为了删除 IPv4 地址，我们可以通过输入`down`来禁用接口。然后我们应该以 CIDR 表示法添加带有子网掩码的 IPv4 地址。除此之外，广播地址已经为我们设置好了，系统根据子网掩码计算了广播地址。然而，我们可以使用`ifconfig`命令设置广播，因此我们将传递`broadcast`选项，如下面的示例所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 broadcast 172.10.20.255
root@philip-virtual-machine:/home/philip# ifconfig ens33:0
ens33:0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.10.0.1  netmask 255.255.254.0  broadcast 172.10.20.255
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip#
```

根据我们在前面的代码中找到的信息，我们可以看到广播地址已经被我们提供的地址改变了。让我们通过将其改回正确的广播地址来修复这个问题，如下面的示例所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 broadcast 172.10.1.255
root@philip-virtual-machine:/home/philip# ifconfig ens33:0
ens33:0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.10.0.1  netmask 255.255.254.0  broadcast 172.10.1.255
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip#
```

删除 IPv4 地址的另一种方法是使用`ifconfig`命令传递`del`选项，如下面的示例所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 del 172.10.0.1
root@philip-virtual-machine:/home/philip# ifconfig ens33:0
ens33:0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip#
```

太棒了！在前面的例子中，我们看到 IPv4 地址已成功删除。当我们完成与别名的工作时，可以通过传递`down`选项来删除其配置，如下面的代码所示：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33:0 down
root@philip-virtual-machine:/home/philip# ifconfig -a
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.175.132  netmask 255.255.255.0  broadcast 172.16.175.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 77475  bytes 57962754 (57.9 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35781  bytes 3140240 (3.1 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
 inet 127.0.0.1  netmask 255.0.0.0
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
 loop  txqueuelen 1000  (Local Loopback)
 RX packets 17311  bytes 1289908 (1.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 17311  bytes 1289908 (1.2 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip#
```

太棒了！从前面的例子中可以看出，接口在`ifconfig`命令中不再被识别。

# ifup 命令

`ifup`命令用于启动或启用接口。然后，接口就能够发送和接收数据包。

然而，只有列在`/etc/network/interfaces`中的接口才会被`ifup`命令识别。让我们关闭`ens33`接口，并使用`ifup`命令重新启动`ens33`接口。这是我们将如何做到这一点：

```
root@philip-virtual-machine:/home/philip# ifconfig ens33 down
root@philip-virtual-machine:/home/philip# ifup ens33
Unknown interface ens33
root@philip-virtual-machine:/home/philip# cat /etc/network/interfaces
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback
root@philip-virtual-machine:/home/philip#
```

根据我们在前面的例子中看到的，`ifup`不会识别`ens33`接口。这是因为`ens33`接口没有列在`/etc/network/interfaces`中。我们可以添加这个条目，然后它将与`ifup`命令一起工作。这可以在下面的例子中看到：

```
root@philip-virtual-machine:/home/philip# cat /etc/network/interfaces
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback
auto ens33
iface ens33 inet manual
root@philip-virtual-machine:/home/philip# ifup ens33
root@philip-virtual-machine:/home/philip# ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.170.1  netmask 255.255.255.0  broadcast 172.16.170.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 77776  bytes 58152478 (58.1 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 35893  bytes 3155908 (3.1 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
 inet 127.0.0.1  netmask 255.0.0.0
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
 loop  txqueuelen 1000  (Local Loopback)
 RX packets 17323  bytes 1290784 (1.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 17323  bytes 1290784 (1.2 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip# 
```

太棒了！根据我们在前面的例子中看到的，`ifup`命令成功地启动了`ens33`接口。此外，分配的 IPv4 地址是我们通过 GUI 网络设置配置的 IPv4 地址。在 Ubuntu 18 中，默认情况下所有的网络设置都由 network-manager 服务处理；每当我们通过命令提示符进行更改，如果系统重新启动或者 network-manager 服务重新启动，那么通过命令提示符进行的所有更改都会丢失，只有`network-manager.service`中的更改才会被使用。为了解决这个问题，我们需要停止`network-manger.service`，然后禁用 network-manager 服务。请注意，如果您没有在 Ubuntu 18 系统的`/etc/network/interfaces`中保存网络设置的更改（包括 IP、子网掩码默认网关、DNS 和 IP），这样做可能会导致系统失去连接。

除非您确定已经将网络配置保存在`/etc/network/interfaces`文件中，否则不要停止`network-manager.service`。

# ifdown 命令

`ifdown`命令可用于关闭或禁用接口；同样，只有列在`/etc/network/interfaces`中的接口才会被识别。让我们使用`ifdown`命令关闭`ens33`接口，如下面的代码中所示：

```
root@philip-virtual-machine:/home/philip# ifdown ens33
root@philip-virtual-machine:/home/philip# ifconfig
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
 inet 127.0.0.1  netmask 255.0.0.0
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
 loop  txqueuelen 1000  (Local Loopback)
 RX packets 17323  bytes 1290784 (1.2 MB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 17323  bytes 1290784 (1.2 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip#  
```

太棒了！在前面的例子中，`ifdown`命令成功地关闭了`ens33`接口，因为我们将`ens33`接口添加到了`/etc/network/interfaces`文件中。

# ip 命令

`ip`命令比`ifconfig`命令更具可扩展性。例如，我们可以使用 ip 命令查看在每个接口上配置的所有次要 IPv4 地址。没有任何选项，`ip`命令将显示可以使用的选项；这可以在下面的例子中看到：

```
root@philip-virtual-machine:/home/philip# ip
Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }
 ip [ -force ] -batch filename
where  OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |
tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm |
netns | l2tp | fou | macsec | tcp_metrics | token | netconf | ila |
vrf | sr }
OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[esolve] |
-h[uman-readable] | -iec |
-f[amily] { inet | inet6 | ipx | dnet | mpls | bridge | link } |
-4 | -6 | -I | -D | -B | -0 |
-l[oops] { maximum-addr-flush-attempts } | -br[ief] |
-o[neline] | -t[imestamp] | -ts[hort] | -b[atch] [filename] |
-rc[vbuf] [size] | -n[etns] name | -a[ll] | -c[olor]}
root@philip-virtual-machine:/home/philip#
```

根据前面的例子，我们可以看到可以传递一些选项；其中一个选项是`a`选项。这会显示所有的寻址信息，就像下面的代码中所示：

```
root@philip-virtual-machine:/home/philip# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

太棒了！从前面的例子中可以立即看到`ens33`接口有多个 IPv4 地址。我们可以使用`ip`命令添加 IPv4 地址；我们将传递`add`选项，如下面的代码中所示：

```
root@philip-virtual-machine:/home/philip# ip a add 172.16.20.2/24 dev ens33
root@philip-virtual-machine:/home/philip# ip a | grep ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
 inet 172.16.20.2/24 scope global ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！现在我们可以看到 IPv4 地址已经添加了。同样，我们也可以删除 IPv4 地址；我们会传递`del`选项，就像下面的代码中所示：

```
root@philip-virtual-machine:/home/philip# ip a del 172.16.20.2/24 dev ens33
root@philip-virtual-machine:/home/philip# ip a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

基于此，我们可以看到我们使用`del`选项指定的 IPv4 地址已被删除。此外，我们使用了`show`选项，这使我们能够指定我们感兴趣的接口。类似于`ifconfig`命令，也可以指定广播地址。为此，我们将传递`brd`或`broadcast`选项，如下例所示：

```
root@philip-virtual-machine:/home/philip# ip a add 172.16.20.2/22 brd 255.255.252.0 dev ens33
root@philip-virtual-machine:/home/philip# ip a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
```

```
 valid_lft forever preferred_lft forever
 inet 172.16.20.2/22 brd 255.255.252.0 scope global ens33
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

太棒了！根据先前的例子，我们可以看到为 IPv4 地址分配了广播地址。此外，可以使用`ip`命令关闭或启用接口。为此，我们将使用`ip`命令的`link`选项，如下代码所示：

```
root@philip-virtual-machine:/home/philip# ip link set dev ens33 down
root@philip-virtual-machine:/home/philip# ip a show ens33 | grep DOWN
2: ens33: <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
root@philip-virtual-machine:/home/philip#
```

通过查看先前的例子，我们可以看到链接已经断开。同样，我们可以通过传递`up`选项来启动接口，如下代码所示：

```
root@philip-virtual-machine:/home/philip# ip link set dev ens33 up
root@philip-virtual-machine:/home/philip# ip a show ens33 | grep UP
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
root@philip-virtual-machine:/home/philip#
```

太棒了！根据先前的例子，我们可以看到接口已经重新启动。我们也可以使用 IP 命令来处理别名；我们将通过`ip`命令传递`a`或`add`选项。这可以在下面的代码中看到：

```
root@philip-virtual-machine:/home/philip# ip a a 172.50.5.1/24 brd + dev ens33 label ens33:1
root@philip-virtual-machine:/home/philip# ip a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet 172.50.5.1/24 brd 172.50.5.255 scope global ens33:1
 valid_lft forever preferred_lft forever
 inet6 fe80::d5a6:db57:33f4:7285/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.170.1  netmask 255.255.255.0  broadcast 172.16.170.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 RX packets 79421  bytes 58846078 (58.8 MB)
 RX errors 0  dropped 1  overruns 0  frame 0
 TX packets 36124  bytes 3191485 (3.1 MB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
ens33:1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.50.5.1  netmask 255.255.255.0  broadcast 172.50.5.255
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
root@philip-virtual-machine:/home/philip#
```

太棒了！根据先前的例子，我们可以看到别名在`ens33`下使用`ip`命令列出。然而，当我们使用`ifconfig`命令时，我们会看到`ens33:1`被列为一个单独的逻辑接口。一旦我们完成使用别名，可以通过在`ip`命令中传递`del`选项来删除别名，如下例所示：

```
root@philip-virtual-machine:/home/philip# ip a del 172.50.5.1/24 brd + dev ens33 label ens33:1
root@philip-virtual-machine:/home/philip# ip a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
 valid_lft forever preferred_lft forever
 inet6 fe80::d5a6:db57:33f4:7285/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip# ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet 172.16.170.1  netmask 255.255.255.0  broadcast 172.16.170.255
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 ether 00:0c:29:32:fc:d5  txqueuelen 1000  (Ethernet)
root@philip-virtual-machine:/home/philip#
```

出于简洁起见，一些输出已被省略。根据先前的例子，我们可以看到别名接口已被删除。在网络使用 VLAN 或虚拟局域网的环境中，可以创建映射到 VLAN 的子接口，从而使 Linux 系统能够处理标记的 VLAN 流量。您需要配置网络交换机以标记流量，然后将流量发送到 Linux 系统中的 VLAN。Linux 系统和交换机之间的链接被视为`trunk`端口，因为它可以通过其物理链接发送多个 VLAN，并且 Linux 系统可以处理流量，因为它知道我们创建的 VLAN。我们将使用`ip link`和`add`选项。以下是我们如何创建一个子接口并将其映射到 VLAN：

```
root@philip-virtual-machine:/home/philip# ip link add link ens33 name ens33.100 type vlan id 100
root@philip-virtual-machine:/home/philip# ip a | grep ens
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
3: ens33.100@ens33: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
root@philip-virtual-machine:/home/philip#
```

太棒了！根据我们在先前的例子中看到的，接口已经创建，并且被视为一个独立的接口。为了检查这一点，我们可以像为物理接口一样分配 IPv4 地址，如下例所示：

```
root@philip-virtual-machine:/home/philip# ip a a 172.16.5.5/24 dev ens33.100
root@philip-virtual-machine:/home/philip# ip a | grep ens
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
3: ens33.100@ens33: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
 inet 172.16.5.5/24 scope global ens33.100
root@philip-virtual-machine:/home/philip#
```

太棒了！最后一步是启动接口。为此，我们将通过`ip link`命令传递`up`选项，如下代码所示：

```
root@philip-virtual-machine:/home/philip# ip link set dev ens33.100 up
root@philip-virtual-machine:/home/philip# ip a | grep ens
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
3: ens33.100@ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
 inet 172.16.5.5/24 scope global ens33.100
root@philip-virtual-machine:/home/philip#
```

基于先前的例子，我们可以看到映射到 VLAN 100 的子接口现在已经启动。我们可以添加和删除 IP 地址信息，类似于物理接口。当我们完成对子接口的操作后，可以通过在`ip link`命令中传递`del`选项来删除它，如下例所示：

```
root@philip-virtual-machine:/home/philip# ip link del ens33.100
root@philip-virtual-machine:/home/philip# ip a | grep ens
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 inet 172.16.170.1/24 brd 172.16.170.255 scope global noprefixroute ens33
 inet 172.16.30.1/24 brd 172.16.30.255 scope global noprefixroute ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！通过查看该示例，我们可以看到子接口不再存在。`ip`命令的另一个有用用途是查看接口的统计信息。我们将通过`ip link`命令传递`-s`和`ls`选项，如下代码所示：

```
root@philip-virtual-machine:/home/philip# ip -s link ls ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 RX: bytes  packets  errors  dropped overrun mcast 
 58851742   79482    0       1       0       0 
 TX: bytes  packets  errors  dropped carrier collsns
 3199078    36174    0       0       0       0 
root@philip-virtual-machine:/home/philip#
```

根据先前的例子，我们可以看到关于接收和发送的数据包统计；通过向当前命令添加另一个`-s`选项，我们甚至可以看到帧、丢失和 CRC 错误，如下代码所示：

```
root@philip-virtual-machine:/home/philip# ip -s -s link ls ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
 link/ether 00:0c:29:32:fc:d5 brd ff:ff:ff:ff:ff:ff
 RX: bytes  packets  errors  dropped overrun mcast 
 58852018   79485    0       1       0       0 
 RX errors: length   crc     frame   fifo    missed
 0        0       0       0       0 
 TX: bytes  packets  errors  dropped carrier collsns
 3199078    36174    0       0       0       0 
 TX errors: aborted  fifo   window heartbeat transns
 0        0       0       0       20 
root@philip-virtual-machine:/home/philip#
```

太棒了！根据先前的例子，我们可以看到与 CRC、帧等相关的计数器。

# 配置 IPv4 路由

到目前为止，我们一直在分配 IPv4 地址信息，但没有指定任何类型的路由信息。我们可以使用多个命令查看当前的路由表。例如，我们可以使用`route`命令显示路由表，如下例所示：

```
root@philip-virtual-machine:/home/philip# route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
link-local      0.0.0.0         255.255.0.0     U     1000   0        0 ens33
172.16.30.0     0.0.0.0         255.255.255.0   U     100    0        0 ens33
172.16.170.0    0.0.0.0         255.255.255.0   U     100    0        0 ens33
root@philip-virtual-machine:/home/philip#
```

根据我们在先前的例子中看到的，只显示与配置的 IPv4 地址相对应的连接路由。还可以使用`ip`命令显示路由表；我们将传递`route`选项，如下命令所示：

```
root@philip-virtual-machine:/home/philip# ip route
169.254.0.0/16 dev ens33 scope link metric 1000
172.16.30.0/24 dev ens33 proto kernel scope link src 172.16.30.1 metric 100
172.16.170.0/24 dev ens33 proto kernel scope link src 172.16.170.1 metric 100
root@philip-virtual-machine:/home/philip#
```

根据前面的例子，我们可以看到与 route 命令类似的信息。另一个可以用来打印路由表的命令是`netstat`命令；为了做到这一点，我们会传递`-r`选项，就像下面的例子中所示的那样。

```
root@philip-virtual-machine:/home/philip# netstat -r
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
link-local      0.0.0.0         255.255.0.0     U         0 0          0 ens33
172.16.30.0     0.0.0.0         255.255.255.0   U         0 0          0 ens33
172.16.170.0    0.0.0.0         255.255.255.0   U         0 0          0 ens33
root@philip-virtual-machine:/home/philip#
```

干得好！在前面的例子中，路由表再次被打印出来。我们还没有配置默认路由；默认路由用于到达不在同一子网上的主机，或者在 LAN 外部的主机。我们将使用`ip route`命令并传递`add`和`default`选项来定义一个默认路由。下面的例子展示了这是什么样子：

```
root@philip-virtual-machine:/home/philip# ip route add default via 172.16.175.1
root@philip-virtual-machine:/home/philip# ip route | grep def
default via 172.16.175.1 dev ens33
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# route  | grep UG
default         _gateway        0.0.0.0         UG    0      0        0 ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的例子，我们可以看到已经添加了一个默认路由。当我们运行`route`命令时，我们看到了`_gateway`这个词，而不是 IPv4 地址；我们可以传递`-n`选项来查看默认网关的数值。下面的例子演示了这一点：

```
root@philip-virtual-machine:/home/philip# route -n | grep UG
0.0.0.0         172.16.175.1    0.0.0.0         UG    0      0        0 ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！我们还可以通过指定我们要到达的子网来创建一个静态路由。下面是我们如何做到这一点的：

```
root@philip-virtual-machine:/home/philip# ip route add 10.20.0.0/24 via 172.16.30.1
root@philip-virtual-machine:/home/philip# ip route | grep via
default via 172.16.175.1 dev ens33
10.20.0.0/24 via 172.16.30.1 dev ens33
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# route -n | grep UG
0.0.0.0         172.16.175.1    0.0.0.0         UG    0      0        0 ens33
10.20.0.0       172.16.30.1     255.255.255.0   UG    0      0        0 ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的例子，我们现在可以看到为`10.20.0.0/24`子网添加的静态路由，通过`172.16.30.1`。当我们不再需要一个路由时，我们可以使用`ip route`命令并传递`del`选项来删除它，就像下面的命令中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip route del 10.20.0.0/24 via 172.16.30.1
root@philip-virtual-machine:/home/philip# ip route | grep via
default via 172.16.175.1 dev ens33
root@philip-virtual-machine:/home/philip# route -n | grep UG
0.0.0.0         172.16.175.1    0.0.0.0         UG    0      0        0 ens33
root@philip-virtual-machine:/home/philip#
```

正如我们在前面的例子中所看到的，`10.20.0.0/24`的静态路由不再存在于我们的路由表中。

# IPv6 配置

我们可以以与 IPv4 相似的方式配置 IPv6 寻址信息。为了只查看 IPv6 地址，我们可以使用`ip`命令并传递`-6`选项，就像下面的命令中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip -6 a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN qlen 1000
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
```

```
 inet6 fe80::d5a6:db57:33f4:7285/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

根据前面的例子，我们只能看到 IPv6 信息，特别是以`fe80`开头的链路本地地址。我们可以使用`ip`命令添加一个 IPv6 地址。我们将以以下方式添加 IPv6 地址：

```
root@philip-virtual-machine:/home/philip# ip -6 a a 2001:0db8:0:f101::1/64 dev ens33
root@philip-virtual-machine:/home/philip# ip -6 a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
 inet6 2001:db8:0:f101::1/64 scope global
 valid_lft forever preferred_lft forever
 inet6 fe80::d5a6:db57:33f4:7285/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

太棒了！在前面的例子中，我们可以看到 IPv6 地址被分配给了`ens33`接口。此外，我们可以使用`ifconfig`命令来显示 IPv6 寻址信息，就像下面的例子中所示的那样：

```
root@philip-virtual-machine:/home/philip# ifconfig | egrep 'ens|inet6'
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
 inet6 2001:db8:0:f101::1  prefixlen 64  scopeid 0x0<global>
 inet6 fe80::d5a6:db57:33f4:7285  prefixlen 64  scopeid 0x20<link>
 inet6 ::1  prefixlen 128  scopeid 0x10<host>
root@philip-virtual-machine:/home/philip#
```

从前面的例子中可以看到，在`inet6`部分中有 IPv6 信息。也可以配置多个 IPv6 地址；我们只需使用带有`-6`的`ip`命令，就像下面的命令中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip -6 a a 2001:0db8:0:f102::2/64 dev ens33
root@philip-virtual-machine:/home/philip# ip -6 a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
 inet6 2001:db8:0:f102::2/64 scope global
 valid_lft forever preferred_lft forever
 inet6 2001:db8:0:f101::1/64 scope global
 valid_lft forever preferred_lft forever
 inet6 fe80::d5a6:db57:33f4:7285/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

根据那个例子，我们可以看到第二个 IPv6 地址已经被添加。当我们不再需要一个 IPv6 地址时，我们可以使用`ip`命令并传递`del`选项，就像下面的例子中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip -6 a del 2001:0db8:0:f102::2/64 dev ens33
root@philip-virtual-machine:/home/philip# ip -6 a show ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
 inet6 2001:db8:0:f101::1/64 scope global
 valid_lft forever preferred_lft forever
 inet6 fe80::d5a6:db57:33f4:7285/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
root@philip-virtual-machine:/home/philip#
```

太棒了！在前面的例子中，我们删除了 IPv6 地址，这是我们用`del`选项指定的。

# 配置 IPv6 路由

我们已经查看了 IPv4 路由表，但也有一个 IPv6 路由表。我们可以使用相同的`ip route`命令和`-6`选项，就像下面的例子中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip -6 route
2001:db8:0:f101::/64 dev ens33 proto kernel metric 256 pref medium
fe80::/64 dev ens33 proto kernel metric 100 pref medium
fe80::/64 dev ens33 proto kernel metric 256 pref medium
root@philip-virtual-machine:/home/philip#
```

在前面的例子中，我们只显示了 IPv6 路由信息。目前在这个系统中没有配置 IPv6 的默认网关。我们可以使用`ip route`命令并传递`-6`和`add`选项来修复这个问题，就像下面的例子中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip -6 route add ::/0 via 2001:db8:0:f101::2
root@philip-virtual-machine:/home/philip# ip -6 route
2001:db8:0:f101::/64 dev ens33 proto kernel metric 256 pref medium
fe80::/64 dev ens33 proto kernel metric 100 pref medium
fe80::/64 dev ens33 proto kernel metric 256 pref medium
default via 2001:db8:0:f101::2 dev ens33 metric 1024 pref medium
root@philip-virtual-machine:/home/philip#
```

太棒了！在前面的例子中，我们可以看到为 IPv6 添加了一个默认路由。我们还可以使用 route 命令查看 IPv6 路由信息；我们会传递`-6`选项，就像下一个例子中所示的那样。

```
root@philip-virtual-machine:/home/philip# route -6 | grep UG
[::]/0                         _gateway                   UG   1024 1     0 ens33
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# route -6 -n | grep UG
::/0                           2001:db8:0:f101::2         UG   1024 1     0 ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的例子，我们可以看到默认网关的 IPv6 地址。我们也可以为一个不同的 IPv6 子网或 LAN 外的 IPv6 子网配置静态路由。下面是我们如何为一个 IPv6 子网添加静态路由的：

```
root@philip-virtual-machine:/home/philip# ip -6 route add 2001:db8:2222:1::/64 via 2001:db8:0:f101::2
root@philip-virtual-machine:/home/philip# ip -6 route | grep via
2001:db8:2222:1::/64 via 2001:db8:0:f101::2 dev ens33 metric 1024 pref medium
default via 2001:db8:0:f101::2 dev ens33 metric 1024 pref medium
root@philip-virtual-machine:/home/philip# route -6 | grep UG
2001:db8:2222:1::/64           _gateway                   UG   1024 1     0 ens33
[::]/0                         _gateway                   UG   1024 1     0 ens33
root@philip-virtual-machine:/home/philip# route -6 -n | grep UG
2001:db8:2222:1::/64           2001:db8:0:f101::2         UG   1024 1     0 ens33
::/0                           2001:db8:0:f101::2         UG   1024 1     0 ens33
root@philip-virtual-machine:/home/philip#
```

干得好！在前面的例子中，你可以看到我们为一个 IPv6 子网添加了一个静态路由。同样，我们可以通过在`ip route`命令中传递`del`选项来删除一个 IPv6 子网的静态路由，就像下面的例子中所示的那样。

```
root@philip-virtual-machine:/home/philip# ip -6 route del 2001:db8:2222:1::/64 via 2001:db8:0:f101::2
root@philip-virtual-machine:/home/philip# route -6 -n | grep UG
::/0                           2001:db8:0:f101::2         UG   1024 1     0 ens33
root@philip-virtual-machine:/home/philip#
```

太棒了！

# 客户端 DNS

到目前为止，我们已经在系统中为网络连接分配了寻址信息（IPv4 和 IPv6）。然而，为了能够浏览互联网，我们需要在系统中配置 DNS；特别是，我们需要告诉 Linux 系统在尝试连接到互联网时使用哪个 DNS 服务器。正如我们在本章前面看到的，我们可以使用各种文本框来填写 IPv4、IPv6、网关和 DNS 信息，使用 GUI 实用程序。在这里，我们将看看如何在命令提示符下配置 DNS 信息；特别是`/etc/resolv.conf`文件。以下是`/etc/resolv.conf`文件的内容：

```
root@philip-virtual-machine:/home/philip# cat /etc/resolv.conf
# This file is managed by man:systemd-resolved(8). Do not edit.
nameserver 127.0.0.53
root@philip-virtual-machine:/home/philip#
```

出于简洁起见，一些输出已被省略。正如在前面的示例中所看到的，Ubuntu 18 中定义 DNS 服务器的格式如下：

```
nameserver <DNS IP>
```

根据这段代码，我们可以在此文件中指定我们的 DNS 服务器 IP。让我们看看是否可以浏览互联网，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00160.jpeg)

根据我们在前面的示例中看到的，我们无法连接到互联网。让我们使用 vi 或 nano 等编辑器在`/etc/resolv.conf`中放入 DNS 服务器的 IP 地址；以下条目是我们要放入的：

```
root@philip-virtual-machine:/home/philip# cat /etc/resolv.conf | grep name
nameserver 8.8.8.8
root@philip-virtual-machine:/home/philip#
```

正如我们在前面的示例中看到的，我们已经添加了一个 DNS 条目。现在，当我们刷新页面时，我们将看到内容开始填充页面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00161.jpeg)

太棒了！我们还可以在`/etc/hosts`文件中为本地名称解析创建本地 DNS 条目。以下是`/etc/hosts`文件的内容：

```
root@philip-virtual-machine:/home/philip# cat /etc/hosts
127.0.0.1              localhost
127.0.1.1              philip-virtual-machine
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
root@philip-virtual-machine:/home/philip#
```

我们可以编辑此文件，并使用 vi 或 nano 等文本编辑器为 Fedora 28 系统添加条目。以下是我们添加的示例条目：

```
root@philip-virtual-machine:/home/philip# cat /etc/hosts | grep Fed
172.16.175.129  Fedora28
root@philip-virtual-machine:/home/philip#
```

太棒了！现在我们可以通过 IP 地址或名称访问 Fedora 28 系统，如下例所示：

```
root@philip-virtual-machine:/home/philip# ssh philip@Fedora28
The authenticity of host 'fedora28 (172.16.175.129)' can't be established.
ECDSA key fingerprint is SHA256:DqRh+J43GfuMKC0i+QHkMU+V2MpephHZqSYANA362hg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'fedora28' (ECDSA) to the list of known hosts.
philip@fedora28's password:
root@philip-virtual-machine:/home/philip#
```

太棒了！

# 网络故障排除

我们可以使用多种工具来帮助我们解决网络连接问题，从 GUI 实用程序到命令行工具。我们的重点将是使用可用的命令行工具进行故障排除。

# ping 命令

`ping`实用程序使用 ICMP 协议发送请求并接收回复。我们可以使用`ping`实用程序测试系统之间的基本可达性，无论是本地还是互联网上。`ping`实用程序的基本语法如下：

```
ping  <DNS name or IPv4>
```

根据我们在前面的示例中看到的，现在我们可以尝试使用`ping`实用程序，如下例所示：

```
root@philip-virtual-machine:/home/philip# ping Fedora28
PING Fedora28 (172.16.175.129) 56(84) bytes of data.
64 bytes from Fedora28 (172.16.175.129): icmp_seq=1 ttl=64 time=0.299 ms
64 bytes from Fedora28 (172.16.175.129): icmp_seq=2 ttl=64 time=0.341 ms
64 bytes from Fedora28 (172.16.175.129): icmp_seq=3 ttl=64 time=0.733 ms
64 bytes from Fedora28 (172.16.175.129): icmp_seq=4 ttl=64 time=0.957 ms
64 bytes from Fedora28 (172.16.175.129): icmp_seq=5 ttl=64 time=0.224 ms
^C
--- Fedora28 ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5064ms
rtt min/avg/max/mdev = 0.224/0.564/0.957/0.287 ms
root@philip-virtual-machine:/home/philip#
```

正如我们在前面的示例中看到的，`ping`实用程序将一直运行，直到用户使用*CTRL* + *C*停止；这在 Windows 环境中是不同的，那里只能看到四个 ICMP 回显请求/回复。

# ping6 命令

也可以测试 IPv6 的潜在连接问题。我们将使用`ping6`命令；`ping6`命令的语法如下：

```
ping6  <DNS name or IPv6>
```

根据我们在前面的示例中看到的，我们只需要指定目标系统的 DNS 名称或 IPv6 地址。以下是如何使用`ping6`命令：

```
root@philip-virtual-machine:/home/philip# ping6 2001:db8:0:f101::3
PING 2001:db8:0:f101::3(2001:db8:0:f101::3) 56 data bytes
64 bytes from 2001:db8:0:f101::3: icmp_seq=1 ttl=64 time=0.355 ms
64 bytes from 2001:db8:0:f101::3: icmp_seq=2 ttl=64 time=0.289 ms
64 bytes from 2001:db8:0:f101::3: icmp_seq=3 ttl=64 time=0.222 ms
64 bytes from 2001:db8:0:f101::3: icmp_seq=4 ttl=64 time=0.596 ms
^C
--- 2001:db8:0:f101::3 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3052ms
rtt min/avg/max/mdev = 0.222/0.365/0.596/0.142 ms
root@philip-virtual-machine:/home/philip#
```

太棒了！

# traceroute 命令

我们可以使用`traceroute`命令来测试潜在的连接问题。`traceroute`命令显示了通往目标系统的每个设备；每个设备被视为一个“跳跃”。`traceroute`的基本语法如下：

```
traceroute <DNS name or IPv4>
```

您可以看到，我们只需要指定目标系统的 DNS 名称或 IPv4 地址。如下例所示：

```
root@philip-virtual-machine:/home/philip# traceroute Fedora28
Command 'traceroute' not found, but can be installed with:
apt install inetutils-traceroute
apt install traceroute 
root@philip-virtual-machine:/home/philip# apt install inetutils-traceroute
update-alternatives: using /usr/bin/inetutils-traceroute to provide /usr/bin/traceroute (traceroute) in auto mode
Processing triggers for man-db (2.8.3-2) ...
root@philip-virtual-machine:/home/philip#
```

正如我们在前面的示例中看到的，`traceroute`实用程序在 Ubuntu 18 中默认未安装；我们通过安装`inetutils-traceroute`软件包迅速解决了这个问题。现在让我们再次尝试运行`traceroute`命令，如下例所示：

```
root@philip-virtual-machine:/home/philip# traceroute Fedora28
traceroute to Fedora28 (172.16.175.129), 64 hops max
 1 172.16.175.129 0.199ms 0.199ms 0.251ms
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的示例，我们可以看到设备距离 Ubuntu 系统只有一跳。

# traceroute6 命令

也可以使用`traceroute6`命令来测试 IPv6 系统之间的潜在瓶颈。`traceroute6`命令的基本语法如下：

```
traceroute6  <DNS name or IPv6>
```

根据我们在前面的示例中看到的，我们只需指定目标系统的 DNS 名称或 IPv6 地址。以下示例显示了如何使用`traceroute6`命令：

```
root@philip-virtual-machine:/home/philip# traceroute6 2001:db8:0:f101::2
traceroute to 2001:db8:0:f101::2 (2001:db8:0:f101::2) from 2001:db8:0:f101::1, 30 hops max, 24 byte packets
sendto: Invalid argument
 1 traceroute: wrote 2001:db8:0:f101::2 24 chars, ret=-1
^C
root@philip-virtual-machine:/home/philip#
```

因此，我们可以看到`traceroute6`命令的工作方式与`traceroute`命令类似。

# netstat 命令

我们可以使用`netstat`命令来排除许多不同的问题。在本章的前面部分，当我们讨论路由时，我们需要传递`-r`选项来查看路由表。我们还可以使用`netstat`命令来查看活动连接。这在服务器环境中特别有用，当我们运行利用各种端口的各种程序时；这些端口可以是 TCP 端口或 UDP 端口。我们可以传递`-n`选项，显示数字地址；`-t`选项，显示 TCP 连接；`-l`选项，显示正在监听的套接字；`-p`选项，显示程序 ID 和程序名称。在尝试缩小 TCP 端口范围时，这些选项可以很好地配合使用。以下是 TCP 的示例：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00162.jpeg)

太棒了！从前面的示例中可以看出，有许多程序在运行，包括`dns`、`sshd`、`ryslogd`等。同样，我们可以查看 UDP 连接；我们将传递`nulp`选项。`-u`表示 UDP，如以下示例所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00163.jpeg)

太棒了！从前面的示例中可以看出，有很多服务在等待连接，其中`systemd-resolve`（端口`53`）就是其中之一。

# tracepath 命令

`tracepath`命令是测试系统之间潜在瓶颈的另一种方法。它的工作方式类似于`traceroute`命令。`tracepath`命令的基本语法如下：

```
tracepath <DNS name or IPv4>
```

根据我们在前面的示例中看到的，我们只需指定目标系统的 DNS 名称或 IPv4 地址，即可使用`tracepath`命令。以下命令显示了这一点：

```
root@philip-virtual-machine:/home/philip# tracepath Fedora28
 1?: [LOCALHOST]          pmtu 1500
 1:  Fedora28             0.309ms reached
 1:  Fedora28             0.201ms reached
 Resume: pmtu 1500 hops 1 back 1
root@philip-virtual-machine:/home/philip#
```

在前面的示例中，除了到目标设备的跳数之外，还显示了`pmtu`或`Path MTU`。

# tracepath -6 命令

与`tracepath`命令类似，带有`-6`选项的`tracepath`是使用 IPv6 地址测试系统之间潜在瓶颈的另一种方法。`tracepath`带有`-6`选项的基本语法如下：

```
tracepath -6 <DNS name or IPv6>
```

根据我们在前面的示例中看到的，我们只需指定目标系统的 DNS 名称或 IPv6 地址，即可使用带有`-6`选项的`tracepath`。以下示例显示了这一点：

```
root@philip-virtual-machine:/home/philip# tracepath -6 2001:db8:0:f101::3
 1?: [LOCALHOST]                        0.012ms pmtu 1500
 1:  2001:db8:0:f101::3                                    0.384ms reached
 1:  2001:db8:0:f101::3                                    0.352ms reached
 Resume: pmtu 1500 hops 1 back 1
root@philip-virtual-machine:/home/philip#
```

太棒了！根据我们在前面的示例中看到的，我们可以看到带有`-6`选项的`tracepath`命令与 IPv4 的`tracepath`命令的工作方式类似。

# nmap 命令

网络映射器（nmap）也可以使用`nmap`命令来排除潜在的连接问题；此命令扫描给定系统并显示为`nmap`命令指定的系统开放的服务及其相应的端口号。

`nmap`命令的基本语法如下：

```
nmap <option>  <IP of destination>
```

根据我们在前面的示例中看到的，我们会在以下示例中指定选项和目标系统的 IP，这是我们正在进行故障排除的目标系统：

```
root@Linuxplus:/home/philip# nmap -A -T4 172.16.175.129
Nmap scan report for Fedora28 (172.16.175.129)
Host is up (0.00066s latency).
Not shown: 845 closed ports, 154 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 b8:02:f8:79:f4:d8:77:b4:26:de:70:93:e8:66:94:69 (RSA)
|   256 9b:e0:d1:33:3b:08:02:bf:fd:c6:48:c1:47:7d:9c:9e (ECDSA)
|_  256 cd:f8:47:d1:75:95:e3:59:f3:b6:c0:12:a0:8b:d1:0e (EdDSA)
MAC Address: 00:0C:29:04:35:BD (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.8
Network Distance: 1 hop
TRACEROUTE
HOP RTT     ADDRESS
1   0.66 ms Fedora28 (172.16.175.129)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.30 seconds
root@Linuxplus:/home/philip#
```

太棒了！根据前面的示例，我们可以看到目标系统上正在运行的服务及其相应的端口号。`-A`选项用于显示 OS 和版本检测；`-T4`选项用于加快执行速度。在运行`nmap`命令之前，您应该征得目标系统或网络的所有者或管理员的许可；尤其是在有规定使用给定网络的公司环境中。

在网络中执行任何类型的端口扫描之前，始终寻求许可。

# dig 命令

到目前为止，我们已经看过了解决连接问题的方法，但 DNS 问题也可能带来风险。我们可以使用`dig`实用程序来执行给定域的 DNS 查找。`dig`命令的基本语法如下：

```
dig <domain>
```

如您所见，我们只需指定要执行查找的域。

以下是我们执行简单查找的方法：

```
root@philip-virtual-machine:/home/philip# dig www.packtpub.com
; <<>> DiG 9.11.3-1ubuntu1-Ubuntu <<>> www.packtpub.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39472
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.packtpub.com.                    IN           A
;; ANSWER SECTION:
www.packtpub.com.     14037    IN           CNAME                varnish.packtpub.com.
varnish.packtpub.com.  14049    IN           A             83.166.169.231
;; Query time: 77 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Wed Mar 06 16:21:23 -04 2019
;; MSG SIZE  rcvd: 83
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的示例，我们可以看到给定域的 DNS 记录；特别是我们可以看到`A`记录。回答我们查询的服务器是`8.8.8.8`，我们在`/etc/resolv.conf`中配置了该服务器。但是，我们可以通过在`dig`命令中传递`@`来使用不同的 DNS 服务器，如下例所示：

```
root@philip-virtual-machine:/home/philip# dig @8.8.4.4 packtpub.com
; <<>> DiG 9.11.3-1ubuntu1-Ubuntu <<>> @8.8.4.4 packtpub.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16754
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;packtpub.com.                                                IN          A
;; ANSWER SECTION:
packtpub.com.                  21599    IN           A             83.166.169.231
;; Query time: 116 msec
;; SERVER: 8.8.4.4#53(8.8.4.4)
;; WHEN: Wed Mar 06 16:25:29 -04 2019
;; MSG SIZE  rcvd: 57
root@philip-virtual-machine:/home/philip#
```

正如我们从前面的示例中看到的，我们已经指定了不同的 DNS 服务器来回答我们的查询。除此之外，我们还可以通过在`dig`命令中传递`NS`来查找特定的 DNS 信息，例如名称服务器或 NS，如下例所示：

```
root@philip-virtual-machine:/home/philip# dig @8.8.4.4 packtpub.com NS
; <<>> DiG 9.11.3-1ubuntu1-Ubuntu <<>> @8.8.4.4 packtpub.com NS
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40936
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;packtpub.com.                                                IN           NS
;; ANSWER SECTION:
packtpub.com.                  21599    IN           NS          dns2.easydns.net.
packtpub.com.                  21599    IN           NS          dns3.easydns.org.
packtpub.com.                  21599    IN           NS          dns4.easydns.info.
packtpub.com.                  21599    IN           NS          dns1.easydns.com.
;; Query time: 105 msec
;; SERVER: 8.8.4.4#53(8.8.4.4)
;; WHEN: Wed Mar 06 16:26:06 -04 2019
;; MSG SIZE  rcvd: 159
root@philip-virtual-machine:/home/philip#
```

太棒了！在前面的示例中，我们可以看到给定域的名称服务器。

# whois 命令

还可以使用`whois`命令获取域的信息。`whois`命令的基本语法如下：

```
whois <domain>
```

因此，我们可以简单地通过`whois`命令传递一个域名，并获取给定域的有价值信息，如下例所示：

```
root@Linuxplus:/home/philip# whois packtpub.com
 Domain Name: PACKTPUB.COM
 Registry Domain ID: 97706392_DOMAIN_COM-VRSN
 Registrar WHOIS Server: whois.easydns.com
 Registrar URL: http://www.easydns.com
 Updated Date: 2015-08-10T20:01:35Z
 Creation Date: 2003-05-09T14:34:02Z
 Registry Expiry Date: 2024-05-09T14:34:02Z
 Registrar: easyDNS Technologies, Inc.
 Registrar IANA ID: 469
 Registrar Abuse Contact Email:
 Registrar Abuse Contact Phone:
 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
 Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
 Name Server: DNS1.EASYDNS.COM
 Name Server: DNS2.EASYDNS.NET
 Name Server: DNS3.EASYDNS.ORG
 Name Server: DNS4.EASYDNS.INFO
You have 20 lookups left today
root@Linuxplus:/home/philip#
```

太棒了！为了简洁起见，某些输出已被省略。前面的示例显示了我们为给定域提供了丰富的信息。

# hostname 命令

此命令仅用于设置或返回系统的 DNS 名称和系统的 IP 地址。基本语法如下：

```
hostname <options> <new hostname>
```

该示例显示，如果我们只输入`hostname`命令，将产生以下代码：

```
root@philip-virtual-machine:/home/philip# hostname
philip-virtual-machine
root@philip-virtual-machine:/home/philip#
```

因此，我们可以看到系统的 DNS 名称。我们还可以传递`-i`选项来查看与`hostname`关联的 IP，如下例所示：

```
root@philip-virtual-machine:/home/philip# hostname -i
127.0.1.1
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的示例，我们可以看到来自`127.0.0.0/8`回环范围的 IP。我们可以通过传递新的`hostname`值来更改`hostname`，如下面的代码所示：

```
root@philip-virtual-machine:/home/philip# hostname Linuxplus
root@philip-virtual-machine:/home/philip# hostname
Linuxplus
root@philip-virtual-machine:/home/philip#
```

使用前面的示例，我们可以看到`hostname`命令指示`hostname`已更改，但未更新提示符。我们可以退出 root 并重新登录，然后我们将看到以下更改：

```
root@philip-virtual-machine:/home/philip# exit
exit
philip@philip-virtual-machine:~$ sudo su
[sudo] password for philip:
root@Linuxplus:/home/philip#
```

太棒了！现在我们可以看到主机名已更改以反映我们指定的名称。但是，当我们重新启动系统时，主机名将被设置回`/etc/hostname`文件中指定的值，如下例所示：

```
root@Linuxplus:/home/philip# cat /etc/hostname
philip-virtual-machine
root@Linuxplus:/home/philip#reboot
root@philip-virtual-machine:/home/philip# cat /etc/hostname
philip-virtual-machine
root@philip-virtual-machine:/home/philip# hostname Linuxplus
```

我们可以通过使用文本编辑器（如 vi 或 nano）编辑`/etc/hostname`文件并将值放置如下代码所示来解决这个问题：

```
root@philip-virtual-machine:/home/philip#cat /etc/hostname
Linuxplus
root@philip-virtual-machine:/home/philip# reboot
root@Linuxplus:/home/philip#
```

太棒了！

# 总结

在本章中，我们配置了 IPv4、IPv6 配置、客户端 DNS 和网络故障排除。首先，我们使用 IPv4，并且我们看了各种管理 IPv4 地址的方法。接下来，我们涵盖了 IPv4 路由；我们看到了如何添加默认路由以及添加静态路由以连接的子网。然后我们进行了 IPv6 配置；我们看到了如何使用命令行中可用的各种工具来管理我们的 IPv6 基础设施。接着，我们看了如何配置 IPv6 的路由，特别是关注默认路由和静态路由以连接的子网。接下来，我们涵盖了客户端 DNS。我们看了配置 DNS 服务器 IP 地址的方法。然后我们通过浏览互联网来测试我们的 DNS 配置。最后，我们涵盖了网络故障排除；我们涵盖了一些可用于命令行的工具，以帮助我们解决潜在的网络连接问题。

在下一章中，我们将专注于安全性；特别是主机安全性，SSH 和加密。下一章非常关键，因为当今环境中存在许多安全风险。希望在下一章中见到您。

# 问题

1.  `ifconfig`命令的哪个选项显示所有活动和非活动的接口？

A. `-s`

B. `-d`

C. `-A`

D. `-a`

1.  在创建默认网关时，`ip`路由命令使用哪个关键字？

A. `default`

B. `0.0.0.0`

C. 网关

D. 以上都不是

1.  `ping`使用哪种协议在源和目的地之间发送和接收消息？

A. FTP

B. TFTP

C. ICMP

D. SSH.1.1

1.  哪个文件保存系统的`hostname`值？

A. `/etc/hosts`

B. `/etc/hostname`

C. `/etc/hostname/hosts`

D. `/var/log/hosts`

1.  哪个命令执行跟踪并输出跳数以及`pmtu`值？

A. `traceroute`

B. `trace`

C. `tracepath`

D. `tracert`

1.  哪个命令执行给定域的 DNS 查询？

A. `ping`

B. `traceroute`

C. `dnsq`

D. `dig`

1.  哪个命令为 IPv6 添加默认路由？

A. `ip -6 route add default via 2001:db8:0:f101::2`

B. `iproute add default via 2001:db8:0:f101::2`

C. `ip-6 route add default via 2001:db8:0:f101::2`

D. `ip -6 add default via 2001:db8:0:f101::2`

1.  哪个选项与 netstat 命令一起显示打开的 UDP 连接的 IP 地址和端口号，程序 ID 和程序名称？

A. `-t`

B. `-u`

C. `-udp`

D. `-ulp`

1.  哪个命令用于扫描系统以公开正在使用的服务及其相应的端口号？

A. `traceroute`

B. `dig`

C. `nmap`

D. `ip`

1.  哪个命令显示给定域的注册表信息？

A. `who`

B. `whois`

C. `whoami`

D. `w`

# 进一步阅读

+   该网站提供有关配置 IPv4 和 IPv6 的有用信息：[`superuser.com`](https://superuser.com)

+   该网站提供有关配置客户端 DNS 的有用信息：[`unix.stackexchange.com`](https://unix.stackexchange.com)

+   该网站提供有关故障排除的有用信息：[`www.computernetworkingnotes.com`](https://www.computernetworkingnotes.com)
