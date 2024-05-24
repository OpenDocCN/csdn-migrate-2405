# 面向网络专家的 Linux（二）

> 原文：[`zh.annas-archive.org/md5/A72D356176254C9EA0055EAB3A38778D`](https://zh.annas-archive.org/md5/A72D356176254C9EA0055EAB3A38778D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Linux 防火墙

Linux 几乎一直都有集成的防火墙可供管理员使用。使用本机防火墙工具，您可以创建传统的周边防火墙，包括地址转换或代理服务器。然而，在现代数据中心，这些并不是典型的用例。现代基础设施中主机防火墙的典型用例如下：

+   入站访问控制，限制对管理界面的访问

+   入站访问控制，限制对其他安装的服务的访问

+   记录访问，以备后续的事件响应，如安全暴露、违规或其他事件。

尽管出站过滤（出站访问控制）当然是建议的，但这更常见地是在网络边界上实施 - 在 VLAN 之间的防火墙和路由器上，或者面向不太受信任的网络，如公共互联网。

在本章中，我们将重点介绍实施一组规则，以管理对实施通用访问的主机的访问，以及对管理员访问的 SSH 服务。

在本章中，我们将涵盖以下主题：

+   配置 iptables

+   配置 nftables

# 技术要求

为了跟随本章的示例，我们将继续在现有的 Ubuntu 主机或虚拟机上进行。本章将重点介绍 Linux 防火墙，因此可能需要第二台主机来测试防火墙更改。

在我们逐步进行各种防火墙配置时，我们将只使用两个主要的 Linux 命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/Table_01.jpg)

# 配置 iptables

在撰写本文时（2021 年），我们对防火墙架构还在变化中。iptables 仍然是许多发行版的默认主机防火墙，包括我们的示例 Ubuntu 发行版。然而，该行业已开始向更新的架构 nftables（Netfilter）迈进。例如，红帽和 CentOS v8（在 Linux 内核 4.18 上）将 nftables 作为默认防火墙。仅供参考，当 iptables 在内核版本 3.13 中引入时（大约在 2014 年），它取代了`ipchains`包（该包在 1999 年的内核版本 2.2 中引入）。转移到新命令的主要原因是朝着更一致的命令集前进，提供更好的 IPv6 支持，并使用 API 提供更好的编程支持进行配置操作。

尽管 nftables 架构确实有一些优势（我们将在本章中介绍），但当前的 iptables 方法已经有数十年的惯性。整个自动化框架和产品都是基于 iptables 的。一旦我们进入语法，您会发现这看起来可能是可行的，但请记住，通常情况下，Linux 主机将被部署并使用数十年之久 - 想想收银机、医疗设备、电梯控制或与制造设备（如 PLC）一起工作的主机。在许多情况下，这些长寿命的主机可能没有配置自动更新，因此根据组织的类型，您可能随时可以轻松地预期使用来自 5 年、10 年或 15 年前的完整操作系统版本的主机。此外，由于这些设备的特性，即使它们连接到网络，它们可能不会被列入“计算机”清单。这意味着，尽管默认防火墙从 iptables 迁移到 nftables 可能在任何特定发行版的新版本上迅速进行，但将有大量的遗留主机将继续使用 iptables 多年。

现在我们知道了 iptables 和 nftables 是什么，让我们开始配置它们，首先是 iptables。

## iptables 的高级概述

iptables 是一个 Linux 防火墙应用程序，在大多数现代发行版中默认安装。如果启用了 iptables，它将管理主机的所有流量。防火墙配置位于文本文件中，与您在 Linux 上所期望的一样，它被组织成包含一组规则的表**chains**。

当数据包匹配规则时，规则的结果将是一个目标。目标可以是另一个链，也可以是三个主要操作之一：

+   **接受**：数据包被传递。

+   **丢弃**：数据包被丢弃；不会被传递。

+   **返回**：阻止数据包穿过此链；告诉它返回到上一个链。

其中一个默认表称为**filter**。这个表有三个默认链：

+   **输入**：控制进入主机的数据包

+   **转发**：处理传入的数据包以转发到其他地方。

+   **输出**：处理离开主机的数据包

另外两个默认表是**NAT**和**Mangle**。

像所有新命令一样，查看 iptables 手册页，并快速查看 iptables 帮助文本。为了更容易阅读，您可以通过`less`命令运行帮助文本，使用`iptables -- help | less`。

默认情况下，iptables 默认情况下未配置。我们可以从“iptables –L -v”（用于“list”）中看到三个默认链中没有规则：

```
robv@ubuntu:~$ sudo iptables -L -v
Chain INPUT (policy ACCEPT 254 packets, 43091 bytes)
 pkts bytes target     prot opt in     out     source               destination 
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination 
Chain OUTPUT (policy ACCEPT 146 packets, 18148 bytes)
 pkts bytes target     prot opt in     out     source               destination
```

我们可以看到服务正在运行，尽管`INPUT`和`OUTPUT`链上的数据包和字节数都不为零且在增加。

为了向链中添加规则，我们使用`-A`参数。这个命令可以带几个参数。一些常用的参数如下：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/Table_02.jpg)

因此，例如，这两条规则将允许来自网络`1.2.3.0/24`的主机连接到我们主机的端口`tcp/22`，并且任何东西都可以连接到`tcp/443`：

```
sudo iptables -A INPUT -i ens33 -p tcp  -s 1.2.3.0/24 --dport 22  -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

端口`tcp/22`是 SSH 服务，`tcp/443`是 HTTPS，但如果选择的话，没有什么可以阻止您在任一端口上运行其他服务。当然，如果这些端口上没有任何运行的东西，规则就毫无意义了。

执行完毕后，让我们再次查看我们的规则集。我们将使用`- -line-numbers`添加行号，并使用“-n”（用于数字）跳过地址的任何 DNS 解析：

```
robv@ubuntu:~$ sudo iptables -L -n -v --line-numbers
Chain INPUT (policy ACCEPT 78 packets, 6260 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     tcp  --  ens33  *       1.2.3.0/24            0.0.0.0/0            tcp dpt:22
2        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0             0.0.0.0/0            tcp dpt:443
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
Chain OUTPUT (policy ACCEPT 56 packets, 6800 bytes)
num   pkts bytes target     prot opt in     out     source               destination
```

规则列表按顺序从上到下进行处理，因此如果您希望，例如，仅拒绝一个主机访问我们的`https`服务器但允许其他所有内容，您将在`INPUT`规范符号中添加行号。请注意，我们已经在以下代码块的第二条命令中改变了`List`语法-我们只指定了`INPUT`规则，并且还指定了`filter`表（如果您没有指定任何内容，则默认为 filter）：

```
sudo iptables -I INPUT 2 -i ens33 -p tcp  -s 1.2.3.5 --dport 443 -j DROP
robv@ubuntu:~$ sudo iptables -t filter -L INPUT --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  1.2.3.0/24           anywhere              tcp dpt:ssh
2    DROP       tcp  --  1.2.3.5              anywhere              tcp dpt:https
3    ACCEPT     tcp  --  anywhere             anywhere              tcp dpt:https
```

在前面的例子中，我们使用了“-I”参数在链中的特定位置插入规则。然而，如果您已经计划好并且正在按顺序构建规则集，您可能会发现使用“-A”（追加）参数更容易，它将规则追加到列表底部。

在您的源中，您可以定义主机而不是子网，可以只使用 IP 地址（没有掩码）或一系列地址，例如，`--src-range 192.168.122.10-192.168.122.20`。

这个概念可以用来保护服务器上运行的特定服务。例如，通常您会希望限制对允许管理员访问的端口（例如 SSH）的访问仅限于该主机的管理员，但允许更广泛地访问主机上的主要应用程序（例如 HTTPS）。我们刚刚定义的规则是对此的一个开始，假设服务器的管理员在`1.2.3.0/24`子网上。然而，我们错过了阻止其他子网的人连接到 SSH 的“拒绝”：

```
sudo iptables -I INPUT 2 -i ens33 -p tcp  --dport 22 -j DROP
```

这些规则很快就会变得复杂。习惯于将协议规则“分组”是很好的。在我们的例子中，我们将 SSH 保持相邻并按逻辑顺序排列，HTTPS 规则也是如此。您希望每个协议/端口的默认操作都是每个组中的最后一个，前面是例外情况：

```
sudo iptables –L
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  1.2.3.0/24           anywhere              tcp dpt:ssh
2    DROP       tcp  --  anywhere             anywhere              tcp dpt:ssh
3    DROP       tcp  --  1.2.3.5              anywhere              tcp dpt:https
4    ACCEPT     tcp  --  anywhere             anywhere              tcp dpt:https
```

由于规则是按顺序处理的，出于性能原因，您将希望将最频繁“命中”的规则放在列表的顶部。因此，在我们的示例中，我们可能已经反向放置了规则。在许多服务器上，您可能更愿意将应用程序端口（在本例中为`tcp/443`）放在列表的顶部，而将管理员权限（通常看到较低的流量）放在列表的底部。

通过数字删除特定规则（例如，如果我们有一个`INPUT`规则 5），请使用以下命令：

```
sudo iptables –D INPUT 5
```

由于网络管理员应该在本书中保持对安全性的关注，请记住，使用 iptables 限制流量只是过程的前半部分。除非启用了 iptables 日志记录，否则我们无法回顾过去发生的事情。要记录规则，请向其添加`-j LOG`。除了仅记录外，我们还可以使用`- -log-level`参数添加日志级别，并使用`- -log-prefix 'text goes here'`添加一些描述性文本。您可以从中获得什么？

+   记录允许的 SSH 会话可以帮助我们跟踪可能正在对我们主机上的管理服务进行端口扫描的人员。

+   记录被阻止的 SSH 会话可以跟踪试图从非管理员子网连接到管理服务的人员。

+   记录成功和失败的 HTTPS 连接可以帮助我们在故障排除时将 Web 服务器日志与本地防火墙日志相关联。

要仅记录所有内容，请使用以下命令：

```
sudo iptables –A INPUT –j LOG
```

要仅记录来自一个子网的流量，请使用以下命令：

```
sudo iptables –A input –s 192.168.122.0/24 –j LOG
```

要添加日志级别和一些描述性文本，请使用以下命令：

```
sudo iptables -A INPUT –s 192.168.122.0/24 –j LOG - -log-level 3 –log-prefix '*SUSPECT Traffic Rule 9*'
```

日志存储在哪里？在 Ubuntu（我们的示例操作系统）中，它们被添加到`/var/log/kern.log`。在 Red Hat 或 Fedora 中，可以在`/var/log/messages`中找到它们。

我们还应该考虑做什么？就像信息技术中的其他一切一样，如果您可以构建一个东西并让它自行记录，通常可以避免编写单独的文档（通常在完成后几天就过时了）。要添加注释，只需向任何规则添加`-m comment - -comment "Comment Text Here"`。

因此，对于我们的小型四条规则防火墙表，我们将向每条规则添加注释：

```
sudo iptables -A INPUT -i ens33 -p tcp  -s 1.2.3.0/24 --dport 22  -j ACCEPT -m comment --comment "Permit Admin" 
sudo iptables -A INPUT -i ens33 -p tcp  --dport 22  -j DROP -m comment --comment "Block Admin" 
sudo iptables -I INPUT 2 -i ens33 -p tcp  -s 1.2.3.5 --dport 443 -j DROP -m comment --comment "Block inbound Web"
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment "Permit all Web Access"
sudo iptables -L INPUT
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  1.2.3.0/24           anywhere              tcp dpt:ssh /* Permit Admin */
DROP       tcp  --  anywhere             anywhere              tcp dpt:ssh /* Block Admin */
DROP       tcp  --  1.2.3.5              anywhere              tcp dpt:https /* Block inbound Web */
ACCEPT     tcp  --  anywhere             anywhere              tcp dpt:https /* Permit all Web Access */
```

关于 iptables 规则的最后说明：在您的链中有一个默认规则，称为`默认策略`，这是最后一个条目。默认值为`ACCEPT`，因此如果数据包一直到列表底部，它将被接受。这通常是期望的行为，如果您计划拒绝一些流量然后允许其余流量 - 例如，如果您正在保护“大多数公共”服务，例如大多数 Web 服务器。

然而，如果所需的行为是允许一些流量然后拒绝其余流量，您可能希望将默认策略更改为`DENY`。要更改`INPUT`链的默认策略，请使用`iptables –P INPUT DENY`命令。`ACCEPT`。

您始终可以添加一个最终规则，允许所有或拒绝所有以覆盖默认策略（无论是什么）。

现在我们已经有了一个基本的规则集，就像许多其他事情一样，您需要记住这个规则集不是永久的 - 它只是在内存中运行，因此不会在系统重新启动后保留。您可以使用`iptables-save`命令轻松保存您的规则。如果在配置中出现错误并希望恢复到保存的表而不重新加载，您可以随时使用`iptables-restore`命令。虽然这些命令在 Ubuntu 发行版中默认安装，但您可能需要安装一个软件包将它们添加到其他发行版中。例如，在基于 Debian 的发行版中，检查或安装`iptables-persistent`软件包，或在基于 Red Hat 的发行版中，检查或安装`iptables-services`软件包。

现在我们已经牢牢掌握了基本的允许和拒绝规则，让我们来探索**网络地址转换**（**NAT**）表。

## NAT 表

NAT 用于转换来自（或前往）一个 IP 地址或子网的流量，并使其看起来像另一个 IP 地址。

这可能是在互联网网关或防火墙中最常见的情况，其中“内部”地址位于 RFC1918 范围中的一个或多个，而“外部”接口连接到整个互联网。在这个例子中，内部子网将被转换为可路由的互联网地址。在许多情况下，所有内部地址都将映射到单个“外部”地址，即网关主机的外部 IP。在这个例子中，这是通过将每个“元组”（源 IP、源端口、目标 IP、目标端口和协议）映射到一个新的元组来实现的，其中源 IP 现在是一个可路由的外部 IP，源端口只是下一个空闲的源端口（目标和协议值保持不变）。

防火墙将这种从内部元组到外部元组的映射保留在内存中的“NAT 表”中。当返回流量到达时，它使用这个表将流量映射回真实的内部源 IP 和端口。如果特定的 NAT 表条目是针对 TCP 会话的，TCP 会话拆除过程将删除该条目的映射。如果特定的 NAT 表条目是针对 UDP 流量的，那么在一段时间的不活动后，该条目通常会被删除。

这在实际中是什么样子？让我们以一个内部网络`192.168.10.0/24`的例子来说明，以及一个 NET 配置，其中所有内部主机都使用网关主机的外部接口的这种“过载 NAT”配置：

![图 4.1–Linux 作为周界防火墙](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_04_001.jpg)

图 4.1–Linux 作为周界防火墙

让我们更具体一些。我们将添加一个主机，`192.168.10.10`，该主机将向`8.8.8.8`发出 DNS 查询：

![图 4.2–周界防火墙示例，显示 NAT 和状态（会话跟踪或映射）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_04_002.jpg)

图 4.2–周界防火墙示例，显示 NAT 和状态（会话跟踪或映射）

因此，使用这个例子，我们的配置是什么样子的？就像以下这样简单：

```
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
```

这告诉网关主机使用`eth1`接口的 IP 地址对离开接口的所有流量进行伪装。`POSTROUTING`关键字告诉它使用`POSTROUTING`链，这意味着这个`MASQERADE`操作发生在数据包路由之后。

当我们开始引入加密时，操作是在路由前还是路由后发生将产生更大的影响。例如，如果我们在 NAT 操作之前或之后加密流量，这可能意味着流量在一个实例中被加密，而在另一个实例中则没有。因此，在这种情况下，出站 NAT 将在路由前或后是相同的。最好开始定义顺序，以避免混淆。

这有数百种变体，但在这一点上重要的是你已经了解了 NAT 的工作原理（特别是映射过程）。让我们离开我们的 NAT 示例，看看混淆表是如何工作的。

## 混淆表

混淆表用于手动调整 IP 数据包在我们的 Linux 主机中传输时的值。让我们考虑一个简短的例子–使用我们上一节中的防火墙示例，如果`eth1`接口上的互联网上行使用`1500`字节的数据包。例如，DSL 链接通常有一些封装开销，而卫星链接则使用较小的数据包（这样任何单个数据包错误都会影响较少的流量）。

“没问题，”你说。“在会话启动时有一个完整的 MTU“发现”过程，通信的两个主机会找出两方之间可能的最大数据包。”然而，特别是对于较旧的应用程序或特定的 Windows 服务，这个过程会中断。可能导致这种情况的另一件事是，如果运营商网络由于某种原因阻止了 ICMP。这可能看起来像是一个极端特例，但实际上，它经常出现。特别是对于传统协议，常见的是发现这个 MTU 发现过程中断。在这种情况下，混淆表就是你的朋友！

这个例子告诉操纵表“当您看到一个`SYN`数据包时，调整这个例子中的`1412`”：

```
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1412
```

如果您正在为实际配置进行计算，如何获得这个“较小的数字”？如果 ICMP 被传递，您可以使用以下命令：

```
ping –M do –s 1400 8.8.8.8
```

这告诉`ping`，“不要分段数据包；发送一个目的地为`8.8.8.8`的`1400`字节大小的数据包。”

通常，查找“真实”大小是一个试错过程。请记住，这个大小包括在这个大小中的 28 个字节的数据包头。

或者如果 ICMP 不起作用，您可以使用`nping`（来自我们的 NMAP 部分）。在这里，我们告诉`nping`使用 TCP，端口`53`，`mtu`值为`1400`，仅持续 1 秒：

```
$ sudo nping --tcp -p 53 -df --mtu 1400 -c 1 8.8.8.8
Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2021-04-22 10:04 PDT
Warning: fragmentation (mtu=1400) requested but the payload is too small already (20)
SENT (0.0336s) TCP 192.168.122.113:62878 > 8.8.8.8:53 S ttl=64 id=35812 iplen=40  seq=255636697 win=1480
RCVD (0.0451s) TCP 8.8.8.8:53 > 192.168.122.113:62878 SA ttl=121 id=42931 iplen=44  seq=1480320161 win=65535 <mss 1430>
```

在这两种情况下（`ping`和`nping`），您都在寻找适用的最大数字（在`nping`的情况下，这将是您仍然看到`RCVD`数据包的最大数字），以确定 MSS 的帮助数字。

从这个例子中可以看出，操纵表的使用非常少。通常，您会在数据包中插入或删除特定的位 - 例如，您可以根据流量类型设置数据包中的**服务类型**（**TOS**）或**区分服务字段代码点**（**DSCP**）位，以告诉上游运营商特定流量可能需要的服务质量。

现在我们已经介绍了一些 iptables 中的默认表，让我们讨论一下在构建复杂表时保持操作顺序的重要性。

## iptables 的操作顺序

已经讨论了一些主要的 iptables，为什么操作顺序很重要？我们已经提到了一个例子 - 如果您正在使用 IPSEC 加密流量，通常会有一个“匹配列表”来定义哪些流量正在被加密。通常情况下，您希望在 NAT 表处理流量之前进行匹配。

同样，您可能正在进行基于策略的路由。例如，您可能希望通过源、目的地和协议匹配流量，并且，例如，将备份流量转发到具有较低每个数据包成本的链路上，并将常规流量转发到具有更好速度和延迟特性的链路上。您通常希望在 NAT 之前做出这个决定。

有几个图表可用于确定 iptables 操作发生的顺序。我通常参考由*Phil Hagen*维护的图表，网址为[`stuffphilwrites.com/wp-content/uploads/2014/09/FW-IDS-iptables-Flowchart-v2019-04-30-1.png`](https://stuffphilwrites.com/wp-content/uploads/2014/09/FW-IDS-iptables-Flowchart-v2019-04-30-1.png)：

![图 4.3 - iptables 的操作顺序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_04_003.jpg)

图 4.3 - iptables 的操作顺序

正如您所看到的，配置、处理，尤其是调试 iptables 配置可能变得非常复杂。在本章中，我们专注于输入表，特别是限制或允许在主机上运行的服务的访问。随着我们继续讨论 Linux 上运行的各种服务，您应该能够利用这些知识，看到输入规则可以用来保护您环境中的服务。

接下来您可以用 iptables 做什么？像往常一样，再次查看 man 页面 - 大约有 100 页的语法和示例，如果您想深入了解这个功能，iptables man 页面是一个很好的资源。例如，正如我们讨论过的，您可以使用 iptables 和一些静态路由将 Linux 主机作为路由器或基于 NAT 的防火墙。然而，这些不是常规数据中心的正常用例。在 Linux 主机上运行这些功能是很常见的，但在大多数情况下，您会看到这些功能在预打包的 Linux 发行版上执行，比如 VyOS 发行版或路由器的 FRR/Zebra 软件包，或者 pfSense 或 OPNsense 防火墙发行版。

掌握了 iptables 的基础知识，让我们来解决 nftables 防火墙的配置。

# 配置 nftables

正如我们在本章开头讨论的那样，iptables 正在被弃用，并最终在 Linux 中被 nftables 取代。考虑到这一点，使用 nftables 有什么优势？

部署 nftables 规则比在 iptables 中快得多——在底层，iptables 在添加每条规则时都会修改内核。而 nftables 不会这样做。与此相关，nftables 还有一个 API。这使得使用编排或“网络即代码”工具更容易进行配置。这些工具包括 Terraform、Ansible、Puppet、Chef 和 Salt 等应用程序。这使得系统管理员更容易地自动化主机的部署，因此新的虚拟机可以在几分钟内部署到私有或公共云中，而不是几小时。更重要的是，可能涉及多个主机的应用程序可以并行部署。

nftables 在 Linux 内核中的操作效率也要高得多，因此对于任何给定的规则集，您可以指望 nftables 占用更少的 CPU。对于我们的仅有四条规则的规则集来说，这可能看起来并不重要，但是如果您有 40 条、400 条或 4000 条规则，或者在 400 台虚拟机上有 40 条规则，这可能会很快累积起来！

nftables 使用单个命令进行所有操作——`nft`。虽然您可以使用 iptables 语法进行兼容性，但您会发现没有预定义的表或链，更重要的是，您可以在单个规则中进行多个操作。我们还没有讨论太多关于 IPv6 的内容，但是 iptables 本身无法处理 IPv6（您需要安装一个新的软件包：ip6tables）。

基本知识覆盖后，让我们深入研究命令行和使用`nft`命令配置 nftables 防火墙的细节。

## nftables 基本配置

在这一点上，看一下 nftables 的 man 页面可能是明智的。还要查看主要 nftables 命令`nft`的 man 页面。这个手册比 iptables 更长、更复杂；长达 600 多页。

考虑到这一点，让我们部署与 iptables 相同的示例配置。保护主机的直接`INPUT`防火墙是大多数数据中心中最常见的 Linux 防火墙风格。

首先，请确保记录您已经存在的 iptables 和 ip6tables 规则（`iptables –L`和`ip6tables –L`），然后清除两者（使用`-F`选项）。即使您可以同时运行 iptables 和 nftables，也并不意味着这样做是明智的。考虑一下将管理此主机的下一个人；他们将只看到一个防火墙，认为这就是所有已部署的。为了下一个继承您正在处理的主机的人，配置事物总是明智的！

如果您有现有的 iptables 规则集，特别是如果它是一个复杂的规则集，那么`iptables-translate`命令将把几小时的工作转化为几分钟的工作：

```
robv@ubuntu:~$ iptables-translate -A INPUT -i ens33 -p tcp  -s 1.2.3.0/24 --dport 22  -j ACCEPT -m comment --comment "Permit Admin"
nft add rule ip filter INPUT iifname "ens33" ip saddr 1.2.3.0/24 tcp dport 22 counter accept comment \"Permit Admin\"
```

使用这种语法，我们的 iptables 规则变成了一组非常相似的 nftables 规则：

```
sudo nft add table filter
sudo nft add chain filter INPUT
sudo nft add rule ip filter INPUT iifname "ens33" ip saddr 1.2.3.0/24 tcp dport 22 counter accept comment \"Permit Admin\"
sudo nft add rule ip filter INPUT iifname "ens33" tcp dport 22 counter drop comment \"Block Admin\" 
sudo nft add rule ip filter INPUT iifname "ens33" ip saddr 1.2.3.5 tcp dport 443 counter drop comment \"Block inbound Web\" 
sudo nft add rule ip filter INPUT tcp dport 443 counter accept comment \"Permit all Web Access\"
```

请注意，在添加规则之前，我们首先创建了一个表和一个链。现在来列出我们的规则集：

```
sudo nft list ruleset
table ip filter {
        chain INPUT {
                iifname "ens33" ip saddr 1.2.3.0/24 tcp dport 22 counter packets 0 bytes 0 accept comment "Permit Admin"
                iifname "ens33" tcp dport 22 counter packets 0 bytes 0 drop comment "Block Admin"
                iifname "ens33" ip saddr 1.2.3.5 tcp dport 443 counter packets 0 bytes 0 drop comment "Block inbound Web"
                tcp dport 443 counter packets 0 bytes 0 accept comment "Permit all Web Access"
        }
}
```

就像许多 Linux 网络构造一样，nftables 规则在这一点上并不是持久的；它们只会在下一次系统重新加载（或服务重新启动）之前存在。默认的`nftools`规则集在`/etc/nftools.conf`中。您可以通过将它们添加到此文件中使我们的新规则持久。

特别是在服务器配置中，更新`nftools.conf`文件可能会变得非常复杂。通过将`nft`配置分解为逻辑部分并将其拆分为`include`文件，可以大大简化这一过程。

## 使用包含文件

还可以做什么？您可以设置一个“case”结构，将防火墙规则分段以匹配您的网络段：

```
nft add rule ip Firewall Forward ip daddr vmap {\
      192.168.21.1-192.168.21.254 : jump chain-pci21, \
      192.168.22.1-192.168.22.254 : jump chain-servervlan, \
      192.168.23.1-192.168.23.254 : jump chain-desktopvlan23 \
}
```

在这里，定义的三个链都有自己的入站规则或出站规则集。

您可以看到每个规则都是一个`match`子句，然后将匹配的流量跳转到管理子网的规则集。

与其制作一个单一的、庞大的 nftables 文件，不如使用`include`语句以逻辑方式分隔语句。这样你可以维护一个单一的规则文件，用于所有 web 服务器、SSH 服务器或其他服务器或服务类，这样你最终会得到一些标准的`include`文件。这些文件可以根据需要在每个主机的主文件中以逻辑顺序包含：

```
# webserver ruleset
Include "ipv4-ipv6-webserver-rules.nft"
# admin access restricted to admin VLAN only
Include "ssh-admin-vlan-access-only.nft"
```

或者，你可以使规则变得越来越复杂-到了你基于 IP 头字段的规则，比如**区分服务代码点**（**DSCP**），这是数据包中用于确定或强制执行**服务质量**（**QOS**）的六位，特别是对于语音或视频数据包。你可能还决定在路由前或路由后应用防火墙规则（如果你正在进行 IPSEC 加密，这真的很有帮助）。

## 删除我们的防火墙配置

在我们可以继续下一章之前，我们应该删除我们的示例防火墙配置，使用以下两个命令：

```
$ # first remove the iptables INPUT and FORWARD tables
$ sudo iptables -F INPUT
$ sudo iptables -F FORWARD
$ # next this command will flush the entire nft ruleset
$ sudo nft flush ruleset
```

# 总结

虽然许多发行版仍将 iptables 作为默认防火墙，但随着时间的推移，我们可以预期这种情况会转向更新的 nftables 架构。在这个过渡完成之前还需要一些年头，即使在那时，也会出现一些“意外”，比如你发现了你清单中没有的主机，或者你没有意识到的基于 Linux 的设备-物联网设备，比如恒温器、时钟或电梯控制器。本章让我们对这两种架构有了初步了解。

在 nftables 手册页面中大约有 150 页，iptables 手册页面中有 20 页，这些文档本质上就是一本独立的书。我们已经初步了解了这个工具，但在现代数据中心，为每个主机定义入口过滤器是你最常见的 nftables 用法。然而，当你探索数据中心的安全要求时，出站和过境规则可能确实在你的策略中占据一席之地。我希望这次讨论对你的旅程是一个良好的开始！

如果你发现我们在本章讨论的任何概念都有些模糊，现在是一个很好的时间来复习它们。在下一章中，我们将讨论 Linux 服务器和服务的整体加固方法-当然，Linux 防火墙是这次讨论的关键部分！

# 问题

最后，这里是一些问题列表，供你测试对本章材料的了解。你可以在*附录*的*评估*部分找到答案：

1.  如果你要开始一个新的防火墙策略，你会选择哪种方法？

1.  你会如何实施防火墙的中央标准？

# 进一步阅读

+   iptables 的手册页面：[`linux.die.net/man/8/iptables`](https://https://linux.die.net/man/8/iptables%0D)

+   iptables 处理流程图（Phil Hagen）：

[`stuffphilwrites.com/2014/09/iptables-processing-flowchart/`](https://stuffphilwrites.com/2014/09/iptables-processing-flowchart/)

[`stuffphilwrites.com/wp-content/uploads/2014/09/FW-IDS-iptables-Flowchart-v2019-04-30-1.png`](https://stuffphilwrites.com/wp-content/uploads/2014/09/FW-IDS-iptables-Flowchart-v2019-04-30-1.png)

+   NFT 的手册页面：[`www.netfilter.org/projects/nftables/manpage.html`](https://https://www.netfilter.org/projects/nftables/manpage.html%0D)

+   nftables 维基：[`wiki.nftables.org/wiki-nftables/index.php/Main_Page`](https://https://wiki.nftables.org/wiki-nftables/index.php/Main_Page%0D)

+   *10 分钟内的 nftables*：[`wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes`](https://https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)


# 第五章：具有实际示例的 Linux 安全标准

在本章中，我们将探讨为什么 Linux 主机，就像任何主机一样，在初始安装后需要一些关怀 - 事实上，在它们的整个生命周期中 - 以进一步加固它们。在此过程中，我们将涵盖各种主题，以建立加固 Linux 主机的最终“大局”。

本章将涵盖以下主题：

+   为什么我需要保护我的 Linux 主机？

+   云特定的安全考虑

+   常见的行业特定安全标准

+   互联网安全中心的关键控制

+   互联网安全中心基准

+   SELinux 和 AppArmor

# 技术要求

在本章中，我们将涵盖许多主题，但技术上的重点将放在加固 SSH 服务上，使用我们当前的 Linux 主机或虚拟机。与上一章一样，您可能会发现在进行更改时测试您的更改是否有用，但这并不是必须的。

# 为什么我需要保护我的 Linux 主机？

就像几乎所有其他操作系统一样，Linux 安装经过简化，使安装过程尽可能简单，尽可能少地出现问题。正如我们在前几章中看到的，这通常意味着没有启用防火墙的安装。此外，操作系统版本和软件包版本当然会与安装媒体匹配，而不是与每个软件包的最新版本匹配。在本章中，我们将讨论 Linux 中的默认设置通常不是大多数人认为安全的设置，作为行业，我们如何通过立法、法规和建议来解决这个问题。

至于初始安装是否过时，幸运的是，大多数 Linux 发行版都启用了自动更新过程。这由`/etc/apt/apt.conf.d/20auto-upgrades`文件中的两行控制：

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

这两个设置默认都设置为`1`（启用）。这两行都很容易理解 - 第一行控制包列表是否更新，第二行控制自动更新的开启或关闭。对于可能处于“巡航控制”管理方法的桌面或服务器来说，这个默认设置并不是一个坏设置。但需要注意的是，`Unattended-Upgrade`行只启用安全更新。

在大多数良好管理的环境中，您会期望看到安排的维护窗口，先在不太关键的服务器上进行升级和测试，然后再部署到更重要的主机上。在这些情况下，您将希望将自动更新设置为`0`，并使用手动或脚本化的更新过程。对于 Ubuntu，手动更新过程涉及两个命令，按以下顺序执行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_01.jpg)

这些可以合并成一行（请参见下一行代码），但在升级步骤中您将需要回答一些“是/否”提示 - 首先是批准整个过程和数据量。此外，如果您的任何软件包在版本之间更改了默认行为，您将被要求做出决定：

```
# sudo apt-get update && sudo apt-get upgrade
```

`&&`运算符按顺序执行命令。第二个命令只有在第一个成功完成（返回代码为零）时才执行。

但等等，您可能会说，我的一些主机在云中 - 那它们呢？在下一节中，您将发现无论您在何处安装，Linux 都是 Linux，而且在某些情况下，您的云实例可能比您的“数据中心”服务器模板更不安全。无论您的操作系统是什么，或者您在哪里部署，更新都将是您安全程序的关键部分。

# 云特定的安全考虑

如果您在任何主要云中启动虚拟机并使用它们的默认镜像，从安全的角度来看，有一些事情需要考虑：

+   有些云启用了自动更新；有些没有。然而，每个操作系统的每个镜像总是有些过时。在您启动虚拟机之后，您将需要更新它，就像您会更新独立主机一样。

+   大多数云服务镜像也有主机防火墙，在某些限制模式下启用。对于您来说，这两个防火墙问题意味着，当您首次启动新的 Linux 虚拟机时，不要指望能够“ping”它，直到您查看了主机防火墙配置（请记住上一章 - 一定要检查`iptables`和`nftables`）。

+   许多云服务镜像默认情况下允许直接从公共互联网进行管理访问。在 Linux 的情况下，这意味着通过`tcp/22`进行 SSH。虽然这种访问的默认设置不像各种云服务提供商早期那样常见，但检查您是否对整个互联网开放了 SSH（`tcp/22`）仍然是明智的。

+   通常，您可能正在使用云“服务”，而不是实际的服务器实例。例如，无服务器数据库实例很常见，您可以完全访问和控制您的数据库，但承载它的服务器对您的用户或应用程序不可见。潜在的服务器可能专用于您的实例，但更有可能是跨多个组织共享的。

现在我们已经讨论了本地部署和云 Linux 部署之间的一些差异，让我们讨论一下不同行业之间的安全要求的差异。

# 常见的行业特定安全标准

有许多行业特定的指导和监管要求，其中一些即使您不在该行业，您可能也熟悉。由于它们是行业特定的，我们将对每个进行高层描述 - 如果其中任何一个适用于您，您将知道每个都值得一本书（或几本书）来描述。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_02a.jpg)![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_02b.jpg)

尽管这些标准和监管或法律要求各自具有行业特定的重点，但许多基本建议和要求都非常相似。当没有提供良好安全指导的一套法规时，**互联网安全中心**（**CIS**）的“关键控制”通常被使用。事实上，这些控制通常与监管要求一起使用，以提供更好的整体安全姿态。

# 互联网安全中心关键控制

虽然 CIS 的关键控制并不是合规标准，但它们无疑是任何组织的一个很好的基础和一个良好的工作模型。关键控制非常实用 - 它们不是以合规性为驱动，而是专注于现实世界的攻击和对抗。理解是，如果您专注于这些控制，特别是按顺序专注于它们，那么您的组织将很好地抵御“野外”中看到的更常见的攻击。例如，仅仅通过查看顺序，就可以明显地看出，您无法保护您的主机（**＃3**），除非您知道您网络上有哪些主机（**＃1**）。同样，日志记录（**＃8**）没有主机和应用程序清单（**＃2**和**＃3**）是无效的。当组织按照列表逐步进行工作时，它很快就会达到不成为“群体中最慢的羚羊”的目标。

与 CIS 基准一样，关键控制由志愿者编写和维护。它们也会随着时间进行修订 - 这是关键的，因为世界随着时间、操作系统和攻击的不断发展而发生变化。虽然 10 年前的威胁仍然存在，但现在我们有新的威胁，我们有新的工具，恶意软件和攻击者使用的方法与 10 年前不同。本节描述了关键控制的第 8 版（于 2021 年发布），但如果您在组织中使用这些控制做决策，请务必参考最新版本。

关键控制（第 8 版）分为三个实施组：

**实施组 1（IG1）-基本控制**

这些控制是组织通常开始的地方。如果这些都已经就位，那么您可以确保您的组织不再是“群中最慢的羚羊”。这些控制针对较小的 IT 团队和商业/现成的硬件和软件。

**实施组 2（IG2）- 中型企业**

实施组 2 的控制扩展了 IG1 的控制，为更具体的配置和技术流程提供了技术指导。这组控制针对较大的组织，在那里有一个人或一小组负责信息安全，或者有法规合规要求。

**实施组 3（IG3）- 大型企业**

这些控制针对已建立的安全团队和流程的较大环境。这些控制中的许多与组织有关 - 与员工和供应商合作，并为事件响应、事件管理、渗透测试和红队演习制定政策和程序。

每个实施组都是前一个的超集，因此 IG3 包括组 1 和 2。每个控制都有几个子部分，正是这些子部分由实施组分类。有关每个控制和实施组的完整描述，关键控制的源文件可免费下载[`www.cisecurity.org/controls/cis-controls-list/`](https://www.cisecurity.org/controls/cis-controls-list/)，其中包括点击以获取描述以及详细的 PDF 和 Excel 文档。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_03a.jpg)![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_03b.jpg)![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_03c.jpg)![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_03d.jpg)

现在我们已经讨论了关键控制措施，那么如何将其转化为保护 Linux 主机或您组织中可能看到的基于 Linux 的基础架构呢？让我们看一些具体的例子，从关键控制措施 1 和 2（硬件和软件清单）开始。

## 开始 CIS 关键安全控制 1 和 2

对网络上的主机和每台主机上运行的软件的准确清单几乎是每个安全框架的关键部分 - 思想是如果您不知道它在那里，就无法保护它。

让我们探讨如何在我们的 Linux 主机上使用零预算方法来实施关键控制 1 和 2。

### 关键控制 1 - 硬件清单

让我们使用本机 Linux 命令来探索关键控制 1 和 2 - 硬件和软件清单。

硬件清单很容易获得 - 许多系统参数都可以作为文件轻松获得，位于`/proc`目录中。`proc`文件系统是虚拟的。`/proc`中的文件不是真实的文件；它们反映了机器的操作特性。例如，您可以通过查看正确的文件来获取 CPU（此输出仅显示第一个 CPU）：

```
$ cat /proc/cpuinfo
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 158
model name      : Intel(R) Xeon(R) CPU E3-1505M v6 @ 3.00GHz
stepping        : 9
microcode       : 0xde
cpu MHz         : 3000.003
cache size      : 8192 KB
physical id     : 0
siblings        : 1
core id         : 0
cpu cores       : 1
…
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon nopl xtopology tsc_reliable nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 invpcid rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat md_clear flush_l1d arch_capabilities
bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit srbds
bogomips        : 6000.00
…
```

内存信息也很容易找到：

```
$ cat /proc/meminfo
MemTotal:        8025108 kB
MemFree:         4252804 kB
MemAvailable:    6008020 kB
Buffers:          235416 kB
Cached:          1486592 kB
SwapCached:            0 kB
Active:          2021224 kB
Inactive:         757356 kB
Active(anon):    1058024 kB
Inactive(anon):     2240 kB
Active(file):     963200 kB
Inactive(file):   755116 kB
…
```

深入挖掘`/proc`文件系统，我们可以在`/proc/sys/net/ipv4`中的许多单独的文件中找到各种 IP 或 TCP 参数的设置（此列表已完整并格式化以便更轻松地查看）。

硬件方面，有多种方法可以获取操作系统版本：

```
$ cat /proc/version
Linux version 5.8.0-38-generic (buildd@lgw01-amd64-060) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #43~20.04.1-Ubuntu SMP Tue Jan 12 16:39:47 UTC 2021
$ cat /etc/issue
Ubuntu 20.04.1 LTS \n \l
$ uname -v
#43~20.04.1-Ubuntu SMP Tue Jan 12 16:39:47 UTC 2021
```

大多数组织选择将操作系统信息放入硬件清单中，尽管将其放入该机器的软件清单中同样正确。在几乎每个操作系统中，安装的应用程序将以比操作系统更频繁的频率更新，这就是为什么硬件清单如此频繁地被选择的原因。重要的是它记录在一个清单中。在大多数系统中，硬件和软件清单系统是同一个系统，所以这样的讨论就很好地解决了。

`lshw`命令是一个很好的“给我所有东西”的命令，用于硬件清单——`lshw`的 man 页面为我们提供了更深入挖掘或更有选择性地显示此命令的附加选项。不过，这个命令可能收集太多信息——你需要有选择地进行收集！

组织通常通过编写脚本来找到一个很好的折衷方案，以收集他们的硬件清单所需的确切信息——例如，下面的简短脚本对基本的硬件和操作系统清单非常有用。它使用了我们迄今为止使用过的几个文件和命令，并通过使用一些新命令进行了扩展：

+   `fdisk`用于磁盘信息

+   `dmesg`和`dmidecode`用于系统信息：

```
echo -n "Basic Inventory for Hostname: "
uname -n
#
echo =====================================
dmidecode | sed -n '/System Information/,+2p' | sed 's/\x09//'
dmesg | grep Hypervisor
dmidecode | grep "Serial Number" | grep -v "Not Specified" | grep -v None
#
echo =====================================
echo "OS Information:"
uname -o -r
if [ -f /etc/redhat-release ]; then
    echo -n "  "
    cat /etc/redhat-release
fi
if [ -f /etc/issue ]; then
    cat /etc/issue
fi
#
echo =====================================
echo "IP information: "
ip ad | grep inet | grep -v "127.0.0.1" | grep -v "::1/128" | tr -s " " | cut -d " " -f 3
# use this line if legacy linux
# ifconfig | grep "inet" | grep -v "127.0.0.1" | grep -v "::1/128" | tr -s " " | cut -d " " -f 3
#
echo =====================================
echo "CPU Information: "
cat /proc/cpuinfo | grep "model name\|MH\|vendor_id" | sort -r | uniq
echo -n "Socket Count: "
cat /proc/cpuinfo | grep processor | wc -l
echo -n "Core Count (Total): "
cat /proc/cpuinfo | grep cores | cut -d ":" -f 2 | awk '{ sum+=$1} END {print sum}'
#
echo =====================================
echo "Memory Information: "
grep MemTotal /proc/meminfo | awk '{print $2,$3}'
#
echo =====================================
echo "Disk Information: "
fdisk -l | grep Disk | grep dev
```

你的实验 Ubuntu 虚拟机的输出可能如下所示（此示例是虚拟机）。请注意，我们使用了`sudo`（主要是为了`fdisk`命令，它需要这些权限）：

```
$ sudo ./hwinven.sh
Basic Inventory for Hostname: ubuntu
=====================================
System Information
Manufacturer: VMware, Inc.
Product Name: VMware Virtual Platform
[    0.000000] Hypervisor detected: VMware
        Serial Number: VMware-56 4d 5c ce 85 8f b5 52-65 40 f0 92 02 33 2d 05
=====================================
OS Information:
5.8.0-45-generic GNU/Linux
Ubuntu 20.04.2 LTS \n \l
=====================================
IP information:
192.168.122.113/24
fe80::1ed6:5b7f:5106:1509/64
=====================================
CPU Information:
vendor_id       : GenuineIntel
model name      : Intel(R) Xeon(R) CPU E3-1505M v6 @ 3.00GHz
cpu MHz         : 3000.003
Socket Count: 2
Core Count (Total): 2
=====================================
Memory Information:
8025036 kB
=====================================
Disk Information:
Disk /dev/loop0: 65.1 MiB, 68259840 bytes, 133320 sectors
Disk /dev/loop1: 55.48 MiB, 58159104 bytes, 113592 sectors
Disk /dev/loop2: 218.102 MiB, 229629952 bytes, 448496 sectors
Disk /dev/loop3: 217.92 MiB, 228478976 bytes, 446248 sectors
Disk /dev/loop5: 64.79 MiB, 67915776 bytes, 132648 sectors
Disk /dev/loop6: 55.46 MiB, 58142720 bytes, 113560 sectors
Disk /dev/loop7: 51.2 MiB, 53501952 bytes, 104496 sectors
Disk /dev/fd0: 1.42 MiB, 1474560 bytes, 2880 sectors
Disk /dev/sda: 40 GiB, 42949672960 bytes, 83886080 sectors
Disk /dev/loop8: 32.28 MiB, 33845248 bytes, 66104 sectors
Disk /dev/loop9: 51.4 MiB, 53522432 bytes, 104536 sectors
Disk /dev/loop10: 32.28 MiB, 33841152 bytes, 66096 sectors
Disk /dev/loop11: 32.28 MiB, 33841152 bytes, 66096 sectors
```

有了填充硬件清单所需的信息，接下来让我们看看我们的软件清单。

### 关键控制 2——软件清单

要清点所有已安装的软件包，可以使用`apt`或`dpkg`命令。我们将使用这个命令来获取已安装软件包的列表：

```
$ sudo apt list --installed | wc -l
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
1735
```

请注意，有这么多软件包时，最好要么知道自己在寻找什么并提出具体的请求（也许使用`grep`命令），要么收集多台主机的所有信息，然后使用数据库找出在某一方面不匹配的主机。

`dpkg`命令将为我们提供类似的信息：

```
dpkg -
Name                                 Version                 Description
====================================================================================
acpi-support               0.136.1                scripts for handling many ACPI events
acpid                      1.0.10-5ubuntu2.1      Advanced Configuration and Power Interfacee
adduser                    3.112ubuntu1           add and remove users and groups
adium-theme-ubuntu         0.1-0ubuntu1           Adium message style for Ubuntu
adobe-flash-properties-gtk 10.3.183.10-0lucid1    GTK+ control panel for Adobe Flash Player pl
.... and so on ....
```

要获取软件包中包含的文件，使用以下命令：

```
robv@ubuntu:~$ dpkg -L openssh-client
/.
/etc
/etc/ssh
/etc/ssh/ssh_config
/etc/ssh/ssh_config.d
/usr
/usr/bin
/usr/bin/scp
/usr/bin/sftp
/usr/bin/ssh
/usr/bin/ssh-add
/usr/bin/ssh-agent
….
```

要列出大多数 Red Hat 发行版中安装的所有软件包，请使用以下命令：

```
$ rpm -qa
libsepol-devel-2.0.41-3.fc13.i686
wpa_supplicant-0.6.8-9.fc13.i686
system-config-keyboard-1.3.1-1.fc12.i686
libbeagle-0.3.9-5.fc12.i686
m17n-db-kannada-1.5.5-4.fc13.noarch
pptp-1.7.2-9.fc13.i686
PackageKit-gtk-module-0.6.6-2.fc13.i686
gsm-1.0.13-2.fc12.i686
perl-ExtUtils-ParseXS-2.20-121.fc13.i686
... (and so on)
```

要获取有关特定软件包的更多信息，使用`rpm -qi`：

```
$ rpm -qi python
Name        : python                       Relocations: (not relocatable)
Version     : 2.6.4                             Vendor: Fedora Project
Release     : 27.fc13                       Build Date: Fri 04 Jun 2010 02:22:55 PM EDT
Install Date: Sat 19 Mar 2011 08:21:36 PM EDT      Build Host: x86-02.phx2.fedoraproject.org
Group       : Development/Languages         Source RPM: python-2.6.4-27.fc13.src.rpm
Size        : 21238314                         License: Python
Signature   : RSA/SHA256, Fri 04 Jun 2010 02:36:33 PM EDT, Key ID 7edc6ad6e8e40fde
Packager    : Fedora Project
URL         : http://www.python.org/
Summary     : An interpreted, interactive, object-oriented programming language
Description :
Python is an interpreted, interactive, object-oriented programming
....
(and so on)
```

要获取所有软件包的更多信息（可能是太多信息），使用`rpm -qia`。

这些清单，正如你所看到的，非常细致和完整。你可以选择清点所有东西——即使是完整的文本清单（没有数据库）也是有价值的。如果你有两台相似的主机，你可以使用`diff`命令来查看两台相似工作站之间的差异（一台工作，一台不工作）。

或者，如果你在进行故障排除，通常会检查已安装的版本与已知的错误、文件日期与已知的安装日期等是否匹配。

迄今为止讨论的清单方法都是 Linux 本地的，但并不适合管理一大批主机，甚至不适合很好地管理一台主机。让我们来探索 OSQuery，这是一个管理软件包，可以简化在许多关键控制和/或任何你可能需要遵守的监管框架上取得进展。

## OSQuery——关键控制 1 和 2，添加控制 10 和 17

与维护成千上万行文本文件作为清单不同，更常见的方法是使用实际的应用程序或平台来维护你的清单——可以是在主机上实时进行，可以是在数据库中，也可以是两者的结合。OSQuery 是一个常见的平台。它为管理员提供了一个类似数据库的接口，用于目标主机上的实时信息。

OSQuery 是一个常见的选择，因为它可以处理最流行的 Linux 和 Unix 变体、macOS 和 Windows，都在一个界面中。让我们深入了解这个流行平台的 Linux 部分。

首先，要安装 OSQuery，我们需要添加正确的存储库。对于 Ubuntu，使用以下命令：

```
$ echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" | sudo tee /etc/apt/sources.list.d/osquery.list
```

接下来，导入存储库的签名密钥：

```
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
```

然后，更新软件包列表：

```
$ sudo apt update
```

最后，我们可以安装`osquery`：

```
$ sudo apt-get install osquery
```

OSQuery 有三个主要组件：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_Table_04.jpg)

安装完成后，让我们来探索交互式 shell。请注意，如果没有设置守护程序并“连接”你的各种主机，我们使用的是一个虚拟数据库，只查看我们的本地主机：

```
robv@ubuntu:~$ osqueryi
Using a virtual database. Need help, type '.help'
osquery> .help
Welcome to the osquery shell. Please explore your OS!
You are connected to a transient 'in-memory' virtual database.
.all [TABLE]     Select all from a table
.bail ON|OFF     Stop after hitting an error
.echo ON|OFF     Turn command echo on or off
.exit            this program
.features        List osquery's features and their statuses
.headers ON|OFF  Turn display of headers on or off
.help            Show this message
….
```

接下来让我们来看看我们可以使用的数据库表：

```
osquery> .tables
  => acpi_tables
  => apparmor_events
  => apparmor_profiles
  => apt_sources
  => arp_cache
  => atom_packages
  => augeas
  => authorized_keys
  => azure_instance_metadata
  => azure_instance_tags
  => block_devices
  => bpf_process_events
  => bpf_socket_events
….
```

有数十个表格来跟踪各种系统参数。让我们来看看操作系统版本，例如：

```
osquery> select * from os_version;
+--------+---------------------------+-------+-------+-------+-------+----------+---------------+----------+--------+
| name   | version                   | major | minor | patch | build | platform | platform_like | codename | arch   |
+--------+---------------------------+-------+-------+-------+-------+----------+---------------+----------+--------+
| Ubuntu | 20.04.1 LTS (Focal Fossa) | 20    | 4     | 0     |       | ubuntu   | debian        | focal    | x86_64 |
```

或者，要收集本地接口 IP 和子网掩码，不包括环回接口，使用以下命令：

```
osquery> select interface,address,mask from interface_addresses where interface NOT LIKE '%lo%';
+-----------+---------------------------------+-----------------------+
| interface | address                         | mask                  |
+-----------+---------------------------------+-----------------------+
| ens33     | 192.168.122.170                 | 255.255.255.0         |
| ens33     | fe80::1ed6:5b7f:5106:1509%ens33 | ffff:ffff:ffff:ffff:: |
+-----------+---------------------------------+-----------------------+
```

或者，要检索本地 ARP 缓存，请使用以下命令：

```
osquery> select * from arp_cache;
+-----------------+-------------------+-----------+-----------+
| address         | mac               | interface | permanent |
+-----------------+-------------------+-----------+-----------+
| 192.168.122.201 | 3c:52:82:15:52:1b | ens33     | 0         |
| 192.168.122.1   | 00:0c:29:3b:73:cb | ens33     | 0         |
| 192.168.122.241 | 40:b0:34:72:48:e4 | ens33     | 0         |
```

或者，列出已安装的软件包（请注意，此输出限制为 2）：

```
osquery> select * from deb_packages limit 2;
+-----------------+--------------------------+--------+------+-------+-------------------+----------------------+-----------------------------------------------------------+---------+----------+
| name            | version                  | source | size | arch  | revision          | status               | maintainer                                                | section | priority |
+-----------------+--------------------------+--------+------+-------+-------------------+----------------------+-----------------------------------------------------------+---------+----------+
| accountsservice | 0.6.55-0ubuntu12~20.04.4 |        | 452  | amd64 | 0ubuntu12~20.04.4 | install ok installed | Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com> | admin   | optional |
| acl             | 2.2.53-6                 |        | 192  | amd64 | 6                 | install ok installed | Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com> | utils   | optional |
+-----------------+--------------------------+--------+------+-------+-------------------+----------------------+-----------------------------------------------------------+---------+----------+
```

您还可以查询运行中的进程（显示限制为 10）：

```
osquery> SELECT pid, name FROM processes order by start_time desc limit 10;
+-------+----------------------------+
| pid   | name                       |
+-------+----------------------------+
| 34790 | osqueryi                   |
| 34688 | sshd                       |
| 34689 | bash                       |
| 34609 | sshd                       |
| 34596 | systemd-resolve            |
| 34565 | dhclient                   |
| 34561 | kworker/0:3-cgroup_destroy |
| 34562 | kworker/1:3-events         |
| 34493 | kworker/0:0-events         |
| 34494 | kworker/1:2-events         |
+-------+----------------------------+
```

我们可以向我们的进程列表添加额外的信息。让我们为每个进程添加`SHA256`哈希值。哈希是一种可以唯一标识数据的数学函数。例如，如果您有两个具有不同名称但相同哈希的文件，它们很可能是相同的。虽然总会有一小部分可能性会出现哈希“碰撞”（两个非相同文件的相同哈希），但使用不同算法再次对它们进行哈希处理可以消除任何不确定性。在取证中广泛使用哈希数据工件-特别是在收集证据以证明责任链完整性方面。

即使在取证分析中，单个哈希值通常足以确定唯一性（或不确定性）。

这对运行进程意味着什么？如果您的恶意软件在每个实例中使用随机名称以规避检测，那么在所有 Linux 主机的 RAM 中对进程进行哈希处理，可以让您找到在不同主机上以不同名称运行的相同进程：

```
osquery> SELECT DISTINCT h.sha256, p.name, u.username
    ...> FROM processes AS p
    ...> INNER JOIN hash AS h ON h.path = p.path
    ...> INNER JOIN users AS u ON u.uid = p.uid
    ...> ORDER BY start_time DESC
    ...> LIMIT 5;
+------------------------------------------------------------------+-----------------+----------+
| sha256                                                           | name            | username |
+------------------------------------------------------------------+-----------------+----------+
| 45fc2c2148bdea9cf7f2313b09a5cc27eead3460430ef55d1f5d0df6c1d96 ed4 | osqueryi        | robv     |
| 04a484f27a4b485b28451923605d9b528453d6c098a5a5112bec859fb5f2 eea9 | bash            | robv     |
| 45368907a48a0a3b5fff77a815565195a885da7d2aab8c4341c4ee869af4 c449 | gvfsd-metadata  | robv     |
| d3f9c91c6bbe4c7a3fdc914a7e5ac29f1cbfcc3f279b71e84badd25b313f ea45 | update-notifier | robv     |
| 83776c9c3d30cfc385be5d92b32f4beca2f6955e140d72d857139d2f7495 af1e | gnome-terminal- | robv     |
+------------------------------------------------------------------+-----------------+----------+
```

这个工具在事件响应情况下特别有效。通过我们在这几页中列出的查询，我们可以快速找到具有特定操作系统或软件版本的主机-换句话说，我们可以找到容易受到特定攻击的主机。此外，我们可以收集所有运行进程的哈希值，以找到可能伪装成良性进程的恶意软件。所有这些都可以通过只进行几次查询来完成。

最后一部分将关键控件中的高级指令转换为 Linux 中的“实用”命令，以实现这些目标。让我们看看这与更具规范性和操作系统或应用程序特定的安全指导有何不同-在这种情况下，将 CIS 基准应用于主机实施。

# 互联网安全中心基准

CIS 发布描述任何数量基础设施组件的安全配置的安全基准。这包括几种不同 Linux 发行版的所有方面，以及可能部署在 Linux 上的许多应用程序。这些基准非常“规范”-基准中的每个建议都描述了问题，如何使用操作系统命令或配置解决问题，以及如何对当前设置的状态进行审计。

CIS 基准的一个非常吸引人的特点是，它们是由一群行业专家编写和维护的，他们自愿投入时间使互联网变得更安全。虽然供应商参与制定这些文件，但它们是团体努力的最终建议需要团体的共识。最终结果是一个与供应商无关、共识和社区驱动的具有非常具体建议的文件。

CIS 基准旨在构建更好的平台（无论平台是什么），并且可以进行审计，因此每个建议都有补救和审计部分。对每个基准的详细解释至关重要，这样管理员不仅知道他们在改变什么，还知道为什么。这一点很重要，因为并非所有建议都适用于每种情况，事实上，有时建议会相互冲突，或者导致目标系统上的特定事物无法正常工作。这些情况在文件中描述，但这强调了不要将所有建议都最大程度地实施的重要性！这也清楚地表明，在审计情况下，追求“100%”并不符合任何人的最佳利益。

这些基准的另一个关键特点是它们通常是两个基准合二为一-对“常规”组织会有建议，对更高安全性环境则有更严格的建议。

CIS 确实维护一个审计应用程序**CIS-CAT**（**配置评估工具**），它将根据其基准评估基础架构，但许多行业标准工具，如安全扫描仪（如 Nessus）和自动化工具（如 Ansible、Puppet 或 Chef），将根据适用的 CIS 基准评估目标基础架构。

现在我们了解了基准的目的，让我们来看看 Linux 基准，特别是其中一组建议。

## 应用 CIS 基准-在 Linux 上保护 SSH

在保护服务器、工作站或基础架构平台时，有一个想要保护的事项清单以及如何实现的清单会很有帮助。这就是 CIS 基准的用途。正如讨论的那样，您可能永远不会完全在任何一个主机上实施所有 CIS 基准的建议-安全建议通常会损害或禁用您可能需要的服务，并且有时建议会相互冲突。这意味着基准通常会经过仔细评估，并被用作组织特定构建文档的主要输入。

让我们使用 Ubuntu 20.04 的 CIS 基准来保护我们主机上的 SSH 服务。SSH 是远程连接和管理 Linux 主机的主要方法。这使得在 Linux 主机上保护 SSH 服务器成为一项重要任务，并且通常是建立网络连接后的第一个配置任务。

首先，下载基准-所有平台的基准文档位于[`www.cisecurity.org/cis-benchmarks/`](https://www.cisecurity.org/cis-benchmarks/)。如果您不是运行 Ubuntu 20.04，请下载与您的发行版最接近的基准。您会发现 SSH 是一种非常常见的服务，用于保护 SSH 服务的建议在发行版之间非常一致，并且在非 Linux 平台上通常有相匹配的建议。

在开始之前，更新存储库列表并升级操作系统软件包-再次注意我们如何同时运行两个命令。在命令上使用单个`&`终止符会将其在后台运行，但使用`&&`会按顺序运行两个命令，第二个命令在第一个成功完成时执行（也就是说，如果它具有零的“返回值”）：

```
$ sudo apt-get update && sudo apt-get upgrade
```

您可以在`bash man`页面上了解更多信息（执行`man bash`）。

现在，操作系统组件已更新，让我们安装 SSH 守护程序，因为它在 Ubuntu 上默认情况下未安装：

```
$ sudo apt-get install openssh-server
```

在现代 Linux 发行版中，这将安装 SSH 服务器，然后进行基本配置并启动服务。

现在让我们开始保护它。在 Ubuntu 基准中查看 SSH 部分，我们看到了 22 个不同的配置设置的建议：

+   5.2 配置 SSH 服务器。

+   5.2.1 确保配置了`/etc/ssh/sshd_config`的权限。

+   5.2.2 确保配置了 SSH 私有主机密钥文件的权限。

+   5.2.3 确保配置了 SSH 公共主机密钥文件的权限。

+   5.2.4 确保 SSH`LogLevel`适当。

+   5.2.5 确保禁用 SSH X11 转发。

+   5.2.6 确保 SSH`MaxAuthTries`设置为`4`或更少。

+   5.2.7 确保启用了 SSH`IgnoreRhosts`。

+   5.2.8 确保禁用了 SSH`HostbasedAuthentication`。

+   5.2.9 确保 SSH 根登录已禁用。

+   5.2.10 确保禁用了 SSH`PermitEmptyPasswords`。

+   5.2.11 确保禁用了 SSH`PermitUserEnvironment`。

+   5.2.12 确保仅使用强大的密码。

+   5.2.13 确保仅使用强大的 MAC 算法。

+   5.2.14 确保仅使用强大的密钥交换算法。

+   5.2.15 确保配置了 SSH 空闲超时间隔。

+   5.2.16 确保 SSH`LoginGraceTime`设置为一分钟或更短。

+   5.2.17 确保限制了 SSH 访问。

+   5.2.18 确保配置了 SSH 警告横幅。

+   5.2.19 确保启用了 SSH PAM。

+   5.2.20 确保禁用 SSH`AllowTcpForwarding`。

+   5.2.21 确保配置了 SSH`MaxStartups`。

+   5.2.22 确保限制了 SSH`MaxSessions`。

为了说明这些工作原理，让我们更详细地看一下两个建议 - 禁用 root 用户的直接登录（5.2.9）和确保我们的加密密码是字符串（5.2.12）。

### 确保 SSH root 登录已禁用（5.2.9）

这个建议是确保用户都使用他们的命名帐户登录 - 用户“root”不应该直接登录。这确保了任何可能指示配置错误或恶意活动的日志条目将附有一个真实的人名。

这个术语叫做“不可否认性” - 如果每个人都有自己的命名帐户，而且没有“共享”帐户，那么在发生事故时，没有人可以声称“每个人都知道那个密码，不是我”。

这个审计命令是运行以下命令：

```
$ sudo sshd -T | grep permitrootlogin
permitrootlogin without-password
```

这个默认设置是不符合要求的。我们希望这个是“no”。`without-password`值表示您可以使用非密码方法（如使用证书）以 root 用户身份登录。

为了解决这个问题，我们将在补救部分查找。这告诉我们编辑`/etc/ssh/sshd_config`文件，并添加`PermitRootLogin no`这一行。`PermitRootLogin`被注释掉了（用`#`字符），所以我们要么取消注释，要么更好的是直接在注释值下面添加我们的更改，如下所示：

![图 5.1 - 对 sshd_config 文件的编辑，以拒绝 SSH 上的 root 登录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_05_001.jpg)

图 5.1 - 对 sshd_config 文件的编辑，以拒绝 SSH 上的 root 登录

现在我们将重新运行我们的审计检查，我们会看到我们现在符合要求了：

```
$ sudo sshd -T | grep permitrootlogin
permitrootlogin no
```

实施了这个建议后，让我们看看我们在 SSH 密码上的情况（CIS 基准建议 5.2.12）。

### 确保只使用强密码（5.2.12）

这个检查确保只使用强密码来加密实际的 SSH 流量。审计检查表明我们应该再次运行`sshd –T`，并查找“ciphers”行。我们希望确保我们只启用已知的字符串密码，目前这是一个短列表：

+   `aes256-ctr`

+   `aes192-ctr`

+   `aes128-ctr`

特别是，SSH 的已知弱密码包括任何`DES`或`3DES`算法，或任何块密码（附加了`cbc`）。

让我们检查我们当前的设置：

```
$ sudo sshd -T | grep Ciphers
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
```

虽然我们在列表中有已知符合要求的密码，但我们也有一些不符合要求的密码。这意味着攻击者可以在适当的位置“降级”协商的密码为一个不太安全的密码，当会话建立时。

在补救部分，我们被指示查看同一个文件并更新“ciphers”行。在文件中，根本没有“Ciphers”行，只有一个`Ciphers and keyring`部分。这意味着我们需要添加那一行，如下所示：

```
# Ciphers and keying
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
```

保持注释不变。例如，如果以后需要密钥环，那么可以在那里找到它们的占位符。尽可能保留或添加尽可能多的注释是明智的 - 保持配置尽可能“自我记录”是使下一个可能需要排除您刚刚做出的更改的人的工作变得容易的好方法。特别是，如果多年过去了，那么下一个人是您自己的未来版本！

接下来，我们将重新加载`sshd`守护程序，以确保我们所有的更改都生效：

```
$ sudo systemctl reload sshd
```

最后，重新运行我们的审计检查：

```
$ cat sshd_config | grep Cipher
# Ciphers and keying
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
```

成功！

我们如何在我们的主机上检查密码支持？这个密码更改是一个重要的设置，很可能需要在许多系统上设置，其中一些可能没有一个可以直接编辑的 Linux 命令行或`sshd_config`文件。回想一下上一章。我们将使用`nmap`从远程系统检查这个设置，使用`ssh2-enum-algos.nse`脚本。我们将查看密码的`Encryption Algorithms`脚本输出部分：

```
$ sudo nmap -p22 -Pn --open 192.168.122.113 --script ssh2-enum-algos.nse
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-08 15:22 Eastern Standard Time
Nmap scan report for ubuntu.defaultroute.ca (192.168.122.113)
Host is up (0.00013s latency).
PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (9)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (3)
|       aes256-ctr
|       aes192-ctr
|       aes128-ctr
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
MAC Address: 00:0C:29:E2:91:BC (VMware)
Nmap done: 1 IP address (1 host up) scanned in 4.09 seconds
```

使用第二个工具来验证您的配置是一个重要的习惯 - 虽然 Linux 是一个可靠的服务器和工作站平台，但是会出现错误。此外，很容易在进行更改后退出时不小心没有保存配置更改 - 使用另一个工具进行双重检查是确保一切都如预期的好方法！

最后，如果您曾经接受过审计，安排进行渗透测试，或者在您的网络上实际上有恶意软件，那么在每种情况下都很可能进行网络扫描以寻找弱算法（或更糟糕的是，明文 Telnet 或`rsh`）。如果您使用与攻击者（或审计人员）相同的工具和方法，您更有可能捕捉到被忽略的那一台主机或者那一组具有您意料之外的 SSH 漏洞的主机！

您应该检查哪些其他关键事项？虽然值得检查 SSH 的所有设置，但在每种情况和环境中，其中一些是关键的：

+   检查您的 SSH 日志级别，以便知道谁从哪个 IP 地址登录（5.2.4）。

+   密钥交换和 MAC 算法检查与密码检查类似；它们加强了协议本身（5.2.13 和 5.2.14）。

+   您需要设置一个空闲超时（5.2.15）。这很重要，因为无人看管的管理员登录可能是一件危险的事情，例如，如果管理员忘记锁定屏幕。此外，如果有人习惯于关闭他们的 SSH 窗口而不是注销，那么在许多平台上这些会话不会关闭。如果达到最大会话数（经过几个月后），下一次连接尝试将失败。要解决这个问题，您需要到物理屏幕和键盘上解决这个问题（例如重新启动 SSHD）或重新加载系统。

+   您需要设置**MaxSessions 限制**（5.2.22）。特别是如果您的主机面临敌对网络（这是现在的每个网络），一个简单地开始数百个 SSH 会话的攻击可能会耗尽主机上的资源，影响其他用户可用的内存和 CPU。

尽管如此，应该审查和评估基准的每个部分中的每个建议，以查看它对您的环境是否合适。在这个过程中，通常会为您的环境创建一个构建文档，一个可以用作模板来克隆生产主机的“金像”主机，以及一个审计脚本或加固脚本，以帮助维护正在运行的主机。

# SELinux 和 AppArmor

Linux 有两个常用的 Linux 安全模块（LSMs），它们为系统添加了额外的安全策略、控制和更改默认行为。在许多情况下，它们修改了 Linux 内核本身。它们都适用于大多数 Linux 发行版，并且在实施时都带有一定程度的风险 - 您需要在实施之前做一些准备工作，以评估实施其中一个可能产生的影响。不建议同时实施两者，因为它们很可能会发生冲突。

SELinux 可以说更加完整，而且管理起来肯定更加复杂。它是一组添加到基本安装中的内核修改和工具。在高层次上，它分离了安全策略的配置和执行。控制包括强制访问控制、强制完整性控制、基于角色的访问控制（RBAC）和类型强制。

SELinux 的功能包括以下内容：

+   将安全策略的定义与执行分开。

+   定义安全策略的明确定义的接口（通过工具和 API）。

+   允许应用程序查询策略定义或特定访问控制。一个常见的例子是允许`crond`在正确的上下文中运行计划任务。

+   支持修改默认策略或创建全新的自定义策略。

+   保护系统完整性（域完整性）和数据保密性（多级安全）的措施。

+   对进程初始化、执行和继承进行控制。

+   对文件系统、目录、文件和打开文件描述符（例如管道或套接字）的额外安全控制。

+   套接字、消息和网络接口的安全控制。

+   对“能力”（RBAC）的使用进行控制。

+   在可能的情况下，策略中不允许的任何内容都将被拒绝。这种“默认拒绝”方法是 SELinux 的根本设计原则之一。

**AppArmor**具有与 SELinux 许多相同的功能，但它使用文件路径而不是对文件应用标签。它还实施了强制访问控制。您可以为任何应用程序分配安全配置文件，包括文件系统访问、网络权限和执行规则。这个列表也很好地概述了 AppArmor 也实施了 RBAC。

由于 AppArmor 不使用文件标签，这使得它在文件系统方面是不可知的，如果文件系统不支持安全标签，这使得它成为唯一的选择。另一方面，这也意味着这种架构决策限制了它匹配 SELinux 所有功能的能力。

AppArmor 的功能包括对以下内容的限制：

+   文件访问控制

+   库加载控制

+   进程执行控制

+   对网络协议的粗粒度控制

+   命名套接字

+   对象上的粗粒度所有者检查（需要 Linux 内核 2.6.31 或更新版本）

两种 LVM 都有学习选项：

+   SELinux 有一个宽容模式，这意味着策略已启用但未强制执行。这种模式允许您测试应用程序，然后检查 SELinux 日志，以查看在强制执行策略时您的应用程序可能受到的影响。可以通过编辑`/etc/selinux/config`文件并将`selinux`行更改为**enforcing**、**permissive**或**disabled**来控制 SELinux 模式。更改后需要重新启动系统。

+   AppArmor 的学习模式称为`aa-complain`。要为所有配置文件的应用程序激活此模式，命令是`aa-complain/etc/apparmor.d/*`。激活学习模式后，然后测试一个应用程序，您可以使用`aa-logprof`命令查看 AppArmor 可能如何影响该应用程序（对于此命令，您需要配置文件和日志的完整路径）。

要检查 LVM 的状态，命令如下：

+   对于 SELinux，命令是`getenforce`，或者更详细的输出是`sestatus`。

+   对于 AppArmor，类似的命令是`apparmor status`和`aa-status`。

总之，AppArmor 和 SELinux 都是复杂的系统。 SELinux 被认为更加复杂，但也更加完整。如果您选择其中一种方法，您应该首先在测试系统上进行测试。在部署之前，最好在生产主机的克隆上尽可能多地测试和构建您的生产配置。这两种解决方案都可以显著提高主机和应用程序的安全性，但都需要大量的设置工作，以及持续的努力来确保主机和应用程序在随着时间的推移而变化时能够正常运行。

这两个系统的更完整的解释超出了本书的范围-如果您希望更全面地探索其中任何一个，它们都有几本专门的书籍。 

# 总结

我们讨论的一切的最终目标——监管框架、关键控制和安全基准——都是为了更容易地更好地保护您的主机和数据中心。在这些指导结构中的关键是为您提供足够的指导，使您能够达到所需的目标，而无需成为安全专家。每一个都变得越来越具体。监管框架通常非常广泛，在如何完成任务方面留下了相当大的自由裁量权。关键控制更为具体，但仍然允许在部署解决方案和实现最终目标方面有相当大的灵活性。CIS 基准非常具体，为您提供了实现目标所需的确切命令和配置更改。

我希望通过本章我们所走过的旅程，您对如何在您的组织中结合这些各种指导方法来更好地保护您的 Linux 基础设施有一个良好的了解。

在下一章中，我们将讨论在 Linux 上实施 DNS 服务。如果您希望继续了解如何更具体地保护您的主机，不用担心——随着我们实施新服务，这个安全讨论会一次又一次地出现。

# 问题

随着我们的结束，这里有一些问题供您测试对本章材料的了解。您将在*附录*的*评估*部分找到答案：

1.  在 IT 实施中，使用哪些美国立法来定义隐私要求？

1.  你能按照 CIS 关键控制进行审计吗？

1.  为什么您会经常使用多种方法来检查一个安全设置——例如 SSH 的加密算法？

# 进一步阅读

有关本章涵盖的主题的更多信息，您可以查看以下链接：

+   PCIDSS: [`www.pcisecuritystandards.org/`](https://www.pcisecuritystandards.org/)

+   HIPAA: [`www.hhs.gov/hipaa/index.html`](https://www.hhs.gov/hipaa/index.html)

+   NIST: [`csrc.nist.gov/publications/sp800`](https://csrc.nist.gov/publications/sp800)

+   FEDRAMP: [`www.fedramp.gov/`](https://www.fedramp.gov/)

+   DISA STIGs: [`public.cyber.mil/stigs/`](https://public.cyber.mil/stigs/)

+   GDPR: [`gdpr-info.eu/`](https://gdpr-info.eu/)

+   PIPEDA: [`www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/`](https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/)

+   CIS: [`www.cisecurity.org/controls/`](https://www.cisecurity.org/controls/)

[`isc.sans.edu/forums/diary/Critical+Control+2+Inventory+of+Authorized+and+Unauthorized+Software/11728/`](https://isc.sans.edu/forums/diary/Critical+Control+2+Inventory+of+Authorized+and+Unauthorized+Software/11728/)

+   CIS 基准：[`www.cisecurity.org/cis-benchmarks/`](https://www.cisecurity.org/cis-benchmarks/)

+   OSQuery: [`osquery.readthedocs.io/en/stable/`](https://osquery.readthedocs.io/en/stable/)

+   SELinux: [`www.selinuxproject.org/page/Main_Page`](http://www.selinuxproject.org/page/Main_Page)

+   AppArmor: [`apparmor.net/`](https://apparmor.net/)


# 第三部分：Linux 网络服务

在本最后一部分中，我们将把我们的 Linux 工作站变成一个服务器，并讨论可能在 Linux 上实现的几种常见服务器。在每一章中，我们将介绍该服务的作用，为什么它很重要，然后如何配置它并开始保护它。将深入介绍可以在几乎任何组织中使用的具体示例，以便读者可以在自己的环境中构建它们。

本书的这一部分包括以下章节：

+   [*第六章*]（B16336_06_Final_NM_ePub.xhtml#_idTextAnchor100）*，Linux 上的 DNS 服务*

+   [*第七章*]（B16336_07_Final_NM_ePub.xhtml#_idTextAnchor118）*，Linux 上的 DHCP 服务*

+   [*第八章*]（B16336_08_Final_NM_ePub.xhtml#_idTextAnchor133）*，Linux 上的证书服务*

+   [*第九章*]（B16336_09_Final_NM_ePub.xhtml#_idTextAnchor153）*，Linux 的 RADIUS 服务*

+   [*第十章*]（B16336_10_Final_NM_ePub.xhtml#_idTextAnchor170）*，Linux 的负载均衡器服务*

+   [*第十一章*]（B16336_11_Final_NM_ePub.xhtml#_idTextAnchor192）*，Linux 中的数据包捕获和分析*

+   [*第十二章*]（B16336_12_Final_NM_ePub.xhtml#_idTextAnchor216）*，使用 Linux 进行网络监控*

+   [*第十三章*]（B16336_13_Final_NM_ePub.xhtml#_idTextAnchor236）*，Linux 上的入侵防范系统*

+   [*第十四章*]（B16336_14_Final_NM_ePub.xhtml#_idTextAnchor252）*，Linux 上的蜜罐服务*


# 第六章：Linux 上的 DNS 服务

**域名系统**（**DNS**）是当今信息社会的重要基础。技术社区中使用的一句谚语（以俳句格式表达）如下所示：

*这不是 DNS*

*绝对不可能是 DNS*

*这是 DNS*

这描述了比你想象的更多的技术问题，甚至涉及到广泛的互联网或云服务中断。这也很好地描述了问题是如何解决的，答案是：“根本问题总是 DNS。”这很好地说明了这项服务对当今几乎每个企业网络和公共互联网的几乎每个方面都是多么重要。

在本章中，我们将涵盖几个涉及 DNS 基础知识的主题，然后构建和最终排除 DNS 服务。我们将关注以下领域：

+   什么是 DNS？

+   两种主要的 DNS 服务器实现

+   常见的 DNS 实现

+   DNS 故障排除和侦察

然后，在介绍了 DNS 基础知识之后，我们将讨论以下两种全新的 DNS 实现，这两种实现正在迅速被采用：

+   DNS over **HyperText Transfer Protocol Secure** (**HTTPS**), known as **DoH**

+   **传输层安全**（**TLS**）上的 DNS，称为**DoT**

我们还将讨论**DNS 安全扩展**（**DNSSEC**）实现，该实现对 DNS 响应进行加密签名，以证明它们已经经过验证并且没有被篡改。

# 技术要求

在本章的示例中，您应该能够继续使用您现有的 Linux 主机或**虚拟机**（**VM**）。没有额外的要求。

# 什么是 DNS？

DNS 基本上是人们所需的东西和网络所需的东西之间的翻译者。大多数情况下，人们理解主机和服务的文本名称，例如`google.com`或`paypal.com`。然而，这些名称对底层网络并没有意义。DNS 所做的就是将那些“完全合格的主机名”（有人可能在应用程序中输入，比如他们在**开放系统互连**（**OSI**）第 7 层的浏览器中输入的）翻译成**Internet Protocol**（**IP**）地址，然后可以用来在 OSI 第 3 和第 4 层路由应用程序请求。

在相反的方向上，DNS 也可以将 IP 地址翻译成**完全合格的域名**（**FQDN**），使用所谓的**指针**（**PTR**）请求（用于 DNS PTR 记录）或“反向查找”。这对技术人员来说可能很重要，但这些请求并不像常见的人们运行他们的浏览器和其他应用程序那样经常见到。

# 两种主要的 DNS 服务器实现

DNS 在互联网上有一个庞大而复杂的基础设施（我们将在本节中涉及）。这由 13 个根名称服务器（每个都是可靠的服务器集群）、一组常用的名称服务器（例如我们在谷歌或 Cloudflare 使用的服务器）以及一系列注册商组成，他们将为您注册 DNS 域名，例如您的组织域名，收取一定费用。

然而，大部分情况下，大多数管理员都在处理他们组织的需求——与面向内部人员的内部 DNS 名称服务器或者面向互联网的外部 DNS 名称服务器进行工作。这两种用例将是本章重点讨论的内容。当我们构建这些示例时，您将看到谷歌或 Cloudflare DNS 基础设施，甚至根 DNS 服务器并没有那么不同。

## 组织的“内部”DNS 服务器（以及 DNS 概述）

组织部署的最常见的 DNS 服务是供其员工使用的**内部 DNS 服务器**。该服务器可能具有用于内部 DNS 解析的 DNS 记录的区域文件。该文件可以通过手动编辑区域文件或使用客户端的自动注册或**动态主机配置协议**（**DHCP**）租约自动填充。通常，这三种方法都会结合使用。

基本的请求流程很简单。客户端发出 DNS 请求。如果该请求是针对组织内部的主机，并且请求是发送到内部 DNS 服务器，则由于该本地 DNS 服务器上有该请求，DNS 响应将立即提供。

如果是针对外部主机的请求，那么事情会变得更加复杂 - 例如，让我们查询`www.example.com`。在开始之前，请注意以下图表显示了*最坏情况*，但几乎每一步都有缓存过程，通常允许跳过一步或多步：

![图 6.1 - 单个 DNS 请求可以变得多么复杂的令人眼花缭乱的概述](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_06_001.jpg)

图 6.1 - 单个 DNS 请求可以变得多么复杂的令人眼花缭乱的概述

这个过程看起来很复杂，但您会发现它进行得非常快，实际上在许多情况下有许多*逃生舱*可以让协议跳过许多这些步骤。让我们详细看看整个*最坏情况*的过程，如下所示：

1.  如果内部 DNS 服务器的 DNS 缓存中有条目，并且该条目的**生存时间**（**TTL**）尚未过期，则立即向客户端提供响应。同样，如果客户端请求的条目托管在区域文件中的服务器上，则立即向客户端提供答案。

1.  如果内部 DNS 服务器的缓存中没有条目，或者如果条目在缓存中但其 TTL 已过期，则内部服务器将请求转发给其上游提供者（通常称为**转发器**）以刷新该条目。

如果查询在转发器的缓存中，它将简单地返回答案。如果该服务器具有该域的权威名称服务器，它将简单地查询该主机（在过程中跳过到*步骤 5*）。

1.  如果转发器在缓存中没有该请求，它将向上游请求。在这种情况下，它可能会查询根名称服务器。这样做的目的是找到具有该域的实际条目（在区域文件中）的“权威名称服务器”。在这种情况下，查询是针对`.com`的根名称服务器进行的。

1.  根名称服务器不会返回实际答案，而是返回`.com`的权威名称服务器。

1.  转发器收到此响应后，更新其缓存以包含该名称服务器条目，然后对该服务器进行实际查询。

1.  `.com`的权威服务器返回`example.com`的权威 DNS 服务器。

1.  转发服务器然后向最终的权威名称服务器发出请求。

1.  `example.com`的权威名称服务器将实际查询的“答案”返回给转发器服务器。

1.  转发器名称服务器缓存该答案，然后将答复发送回您的内部名称服务器。

1.  您的内部 DNS 服务器还会缓存该答案，然后将其转发回客户端。

客户端将请求缓存在其本地缓存中，然后将所请求的信息（DNS 响应）传递给请求它的应用程序（也许是您的网络浏览器）。

同样，这个过程展示了最坏情况下的简单 DNS 请求和接收答案的过程。实际上，一旦服务器运行了一段时间，缓存会大大缩短这个过程。一旦进入稳定状态，大多数组织的内部 DNS 服务器将会缓存大部分请求，因此该过程会直接从*步骤 1*跳到*步骤 10*。此外，您的转发 DNS 服务器也会缓存，特别是它几乎不会查询根名称服务器；通常它也会缓存顶级域服务器（在这种情况下，`.com`的服务器）。

在这个描述中，我们还提到了“根名称服务器”的概念。这些是根或`.`区域的权威服务器。为了冗余，有 13 个根服务器，每个实际上都是一个可靠的服务器集群。

我们的内部 DNS 服务器需要启用哪些关键功能才能使所有这些工作？我们需要启用以下功能：

+   **DNS 递归**：这种模式依赖于 DNS 递归，即每个服务器依次向上级服务器发出客户端的 DNS 请求。如果内部服务器上未定义所请求的 DNS 条目，它需要获得转发这些请求的权限。

+   **转发器条目**：如果所请求的 DNS 条目不托管在内部服务器上，**内部 DNS 服务**（**iDNS**）请求将被转发到这些配置的 IP 地址，这些应该是两个或更多可靠的上游 DNS 服务器。这些上游服务器将依次缓存 DNS 条目，并在其 TTL 计时器到期时使其过期。在过去，人们会使用他们的**互联网服务提供商**（**ISP**）的 DNS 服务器作为转发器。在现代，更大的 DNS 提供商比您的 ISP 更可靠并提供更多功能。下面列出了一些常用的用作转发器的 DNS 服务（最常用的地址以粗体显示）！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/Table_011.jpg)

+   **缓存**：在一个大型组织中，通过增加内存可以大大提高 DNS 服务器的性能，这样可以进行更多的缓存，这意味着更多的请求可以直接从服务器的内存中提供服务。

+   **动态注册**：虽然服务器通常具有静态 IP 地址和静态 DNS 条目，但工作站通常会通过 DHCP 分配地址，当然也希望将这些工作站注册到 DNS 中。DNS 通常配置为允许动态注册这些主机，可以通过在分配地址时从 DHCP 中填充 DNS 或允许主机自行在 DNS 中注册（如**请求评论**（**RFC**）*2136*中所述）。

微软在他们的动态更新过程中实现了身份验证机制，这是最常见的地方。然而，在 Linux DNS（**伯克利互联网名称域**，或**BIND**）中也有这个选项。

+   **主机冗余**：几乎所有核心服务都受益于冗余。对于 DNS 来说，通常会有第二个 DNS 服务器。数据库通常是单向复制（从主服务器到辅助服务器），并使用区域文件中的序列号来确定何时进行复制，使用一种称为**区域传输**的复制过程。冗余对于应对各种系统故障至关重要，但同样重要的是它可以允许系统维护而不会中断服务。

有了内部 DNS 服务器，我们需要在配置中做哪些改变才能使 DNS 服务器为公共互联网提供区域服务？

## 面向互联网的 DNS 服务器

在面向互联网的 DNS 服务器的情况下，您很可能正在为一个或多个 DNS 区域实现权威 DNS 服务器。例如，在我们的参考图表（*图 6.1*）中，`example.com`的权威 DNS 服务器就是一个很好的例子。

在这个实现中，重点从内部服务器的性能和转发转移到了限制访问以实现最大安全性。这些是我们想要实现的限制：

+   限制递归：在我们概述的 DNS 模型中，这个服务器是“终点”，它直接回答它托管的区域的 DNS 请求。这个服务器永远不应该向上游查找以服务 DNS 请求。

+   缓存不太重要：如果您是一个组织，并且正在托管自己的公共 DNS 区域，那么您只需要足够的内存来缓存自己的区域。

+   主机冗余：再次，如果您正在托管自己的区域文件，添加第二台主机对您来说可能比添加缓存更重要。这为您的 DNS 服务提供了一些硬件冗余，这样您就可以在不中断服务的情况下对一台服务器进行维护。

+   限制区域传输：这是您想要实施的关键限制——您希望在收到单独的 DNS 查询时进行回答。互联网上的 DNS 客户端请求组织的所有条目没有充分的理由。区域传输旨在在冗余服务器之间维护您的区域，以便在编辑区域时将更改复制到群集中的其他服务器。

+   速率限制：DNS 服务器具有一种称为响应速率限制（RRL）的功能，它限制任何一个源可以查询该服务器的频率。为什么要实施这样的功能？

DNS 经常用于“欺骗”攻击。由于它基于用户数据报协议（UDP），没有建立会话的“握手”；它是一个简单的请求/响应协议，因此，如果您想攻击已知地址，您可以简单地使用目标作为请求者进行 DNS 查询，未经请求的答案将发送到该 IP。

这似乎不像是一次攻击，但如果您然后添加一个“乘数”（换句话说，如果您正在进行小型 DNS 请求并获得更大的响应，例如文本（TXT）记录，并且正在使用多个 DNS 服务器作为“反射器”），那么您发送到目标的带宽可能会很快增加。

这使得速率限制变得重要——您希望限制任何一个 IP 地址每秒进行少量相同的查询。这是一个合理的做法；鉴于 DNS 缓存的依赖性，任何一个 IP 地址在任何 5 分钟内不应该进行超过一到两个相同的请求，因为 5 分钟是任何 DNS 区域的最小 TTL。

启用速率限制的另一个原因是限制攻击者在 DNS 中进行侦察的能力——为常见的 DNS 名称进行数十甚至数百个请求，并编制您有效主机的列表，以便随后对它们进行攻击。

+   限制动态注册：动态注册当然不建议在大多数面向互联网的 DNS 服务器上。唯一的例外是任何提供动态 DNS（DDNS）注册作为服务的组织。这类公司包括 Dynu、DynDNS、FreeDNS 和 No-IP 等几家公司。鉴于这些公司的专业性质，它们各自都有自己的方法来保护其 DDNS 更新（通常涉及自定义代理和某种形式的身份验证）。直接使用 RFC 2136 对于面向互联网的 DNS 服务器来说根本无法保护。

通过实施内部 DNS 服务器的基础知识并开始为它们的各种用例进行安全设置，我们有哪些 DNS 应用程序可用于构建 DNS 基础设施？让我们在下一节中了解这一点。

# 常见的 DNS 实现

BIND，也称为 named（用于名称守护程序），是 Linux 中最常实现的 DNS 工具，可以说是最灵活和完整的，同时也是最难配置和排除故障的。不管好坏，它是您最有可能看到和在大多数组织中实施的服务。主要的两种实现用例在接下来的两个部分中进行了概述。

**DNS 伪装**（**dnsmasq**）是一种竞争的 DNS 服务器实现。它通常出现在网络设备上，因为它的占用空间很小，但也可以作为较小组织的良好 DNS 服务器。Dnsmasq 的主要优势包括其内置的**图形用户界面**（**GUI**），可用于报告，以及其与 DHCP 的集成（我们将在下一章中讨论），允许直接从 DHCP 数据库进行 DNS 注册。此外，Dnsmasq 实现了一种友好的方式来实现 DNS 阻止列表，这在 Pi-hole 应用程序中非常好地打包起来。如果你的家庭网络在其外围防火墙或**无线接入点**（**WAP**）上有一个 DNS 服务器，那么该 DNS 服务器很可能是 Dnsmasq。

在本章中，我们将专注于常用的 BIND（或命名）DNS 服务器。让我们开始构建我们的内部 DNS 服务器使用该应用程序。

## 基本安装：用于内部使用的 BIND

正如你所期望的，安装`bind`，Linux 上最流行的 DNS 服务器，就是这么简单：

```
$ sudo apt-get install –y bind9
```

查看`/etc/bind/named.conf`文件。在旧版本中，应用程序配置都在这一个庞大的配置文件中，但在新版本中，它只是由三个`include`行组成，如下面的代码片段所示：

```
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
```

编辑`/etc/bind/named.conf.options`，并添加以下选项—确保使用`sudo`因为你需要管理员权限来更改`bind`的任何配置文件：

+   允许来自本地子网列表的查询。在这个例子中，我们允许所有*RFC 1918*中的子网，但你应该将其限制在你的环境中拥有的子网。请注意，我们使用无类别子网掩码来最小化这一部分的条目数量。

+   定义监听端口（默认情况下是正确的）。

+   启用递归查询。

+   定义递归工作的 DNS 转发器列表。在这个例子中，我们将添加谷歌和 Cloudflare 作为 DNS 转发。

完成后，我们的配置文件应该看起来像这样。请注意，这确实是一个几乎是“普通语言”的配置—对于这些部分的含义没有任何神秘之处：

```
options {
  directory "/var/cache/bind";
  listen-on port 53 { localhost; };
  allow-query { localhost; 192.168.0.0/16; 10.0.0.0/8; 172.16.0.0/12; };
  forwarders { 8.8.8.8; 8.8.4.4; 1.1.1.1; };
  recursion yes;
}
```

接下来，编辑`/etc/bind/named.conf.local`，并添加服务器类型、区域和区域文件名。此外，允许指定子网上的工作站使用`allow-update`参数向 DNS 服务器注册其 DNS 记录，如下面的代码片段所示：

```
zone "coherentsecurity.com" IN {
  type master;
  file "coherentsecurity.com.zone";
  allow-update { 192.168.0.0/16; 10.0.0.0/8;172.16.0.0/12 };
};
```

`zone`文件本身，其中存储了所有的 DNS 记录，不在与这前两个`config`文件相同的位置。要编辑`zone`文件，编辑`/var/cache/bind/<zone file name>`—所以，在这个例子中，是`/var/cache/bind/coherentsecurity.com.zone`。你需要`sudo`权限来编辑这个文件。做出以下更改：

+   根据需要添加记录。

+   使用你的区域和域名服务器的 FQDN 更新`SOA`行。

+   如果需要，在`SOA`记录的最后一行更新`TTL`值—默认值是`86400`秒（24 小时）。这通常是一个很好的折衷方案，因为它有利于在多个服务器上缓存记录。但是，如果你正在进行任何 DNS 维护，你可能希望在维护前一天（即维护前 24 小时或更长时间）编辑文件，并将其缩短到 5 或 10 分钟，以避免由于缓存而延迟你的更改。

+   更新`ns`记录，它标识了你域的 DNS 服务器。

+   根据需要添加`A`记录—这些标识每个主机的 IP 地址。请注意，对于`A`记录，我们只使用每个主机的**通用名称**（**CN**），而不是包括域的 FQDN 名称。

完成后，我们的 DNS 区域文件应该看起来像这样：

![图 6.2 - 一个 DNS 区域文件示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_06_002.jpg)

图 6.2 - 一个 DNS 区域文件示例

正如我们之前讨论的，在内部 DNS 区域中，通常希望客户端在 DNS 中注册自己。这允许管理员通过名称而不是确定其 IP 地址来访问客户端。这是对`named.conf`文件（或更可能是适用的包含的子文件）的简单编辑。请注意，这要求我们添加`192.168.122.0/24`（定义整个子网）可能更常见。通常也会看到定义整个公司的企业“超网”，例如`10.0.0.0/8`或`192.168.0.0/16`，但出于安全原因，这通常不建议；您可能实际上不需要设备在*每个*子网中自动注册。

在适用的区域中，添加以下代码行：

```
acl dhcp-clients { 192.168.122.128/25; };
acl static-clients { 192.168.122.64/26; };
zone "coherentsecurity.com" {
    allow-update { dhcp-clients; static-clients; };
};
```

有一些脚本可以检查您的工作——一个用于基本配置和包含的文件，另一个用于区域。如果没有错误，`named-checkconf`将不返回任何文本，而`named-checkzone`将给出一些`OK`状态消息，如下所示。如果您运行这些并且没有看到错误，那么至少应该足够开始服务。请注意，`named-checkzone`命令在以下代码示例中换行到下一行。`bind`配置文件中的错误很常见——例如缺少分号。这些脚本将非常具体地指出发现的问题，但如果它们出现错误并且您需要更多信息，则这些命令的日志文件（`bind`本身的`bind`）是标准的`/var/log/syslog`文件，因此请在那里查找：

```
$ named-checkconf
$ named-checkzone coherentsecurity.com /var/cache/bind/coherentsecurity.com.zone
zone coherentsecurity.com/IN: loaded serial 2021022401
OK
```

最后，通过运行以下命令启用`bind9`服务并启动它（或者如果您正在“推送”更新，则重新启动它）：

```
sudo systemctl enable bind9
sudo systemctl start bind9
```

我们现在能够使用本地主机上的 DNS 服务器解析我们区域中的主机名，方法如下：

```
$ dig @127.0.0.1 +short ns01.coherentsecurity.com A
192.168.122.157
$ dig @127.0.0.1 +short esx01.coherentsecurity.com A
192.168.122.51
```

由于递归和转发器已经就位，我们也可以解析公共互联网上的主机，就像这样：

```
$ dig @127.0.0.1 +short isc.sans.edu
45.60.31.34
45.60.103.34
```

完成并运行我们的内部 DNS 服务器后，让我们看看我们面向互联网的 DNS，这将允许人们从公共互联网解析我们公司的资源。

## BIND：面向互联网的实现细节

在我们开始之前，这种配置已经不像以前那样常见了。回到 20 世纪 90 年代或更早，如果您想让人们访问您的 Web 服务器，最常见的方法是建立自己的 DNS 服务器或使用由您的 ISP 提供的 DNS 服务器。在任何一种情况下，任何 DNS 更改都是手动文件编辑。

在更近的时代，更常见的是将 DNS 服务托管给 DNS 注册商。这种“云”方法将安全实施留给 DNS 提供商，并简化了维护，因为各种提供商通常会给您一个 Web 界面来维护您的区域文件。在这种模型中的关键安全考虑是，您将希望提供商为您提供启用**多因素身份验证**（**MFA**）的选项（例如，使用 Google Authenticator 或类似工具），以防范针对您的管理访问的**凭证填充**攻击。还值得研究您的注册商的帐户恢复程序——您不希望经过所有实施 MFA 的工作，然后让攻击者通过简单的求助电话来窃取它！

话虽如此，许多组织仍然有充分的理由实施自己的 DNS 服务器，因此让我们继续修改我们在上一节中使用的配置，以用作互联网 DNS 服务器，方法如下：

+   `etc/bind/named.conf.options`，我们将要添加某种速率限制——在 DNS 的情况下，这是 RRL 算法。

+   然而，请记住，这有可能拒绝合法查询的服务。让我们将`responses-per-second`值设置为`10`作为初步速率限制，但将其设置为`log-only`状态。让它在`log-only`模式下运行一段时间，并调整每秒速率，直到你确信你有一个足够低以防止激进攻击但又足够高以在合法操作期间不拒绝访问的值。在此过程中要监视的日志文件，如前面提到的，是`/var/log/syslog`。当你对你的值感到满意时，删除`log-only`行。一旦开始运行，请确保监视任何触发此设置的情况——这可以在你的日志记录或**安全信息和事件管理**（**SIEM**）解决方案中通过简单的关键字匹配轻松完成。代码如下所示：

```
        rate-limit {
             responses-per-second 10
             log-only yes;
        }
```

+   `/etc/bind/named.conf.options`。此外，完全删除 forwarders 行。代码如下所示：

```
        recursion no;
```

+   将`allow-query`行修改为如下内容：

```
allow-query { localhost; 0.0.0.0/0 }
```

既然我们既有内部用户的 DNS 服务器，又有互联网客户端的 DNS 服务器，我们可以使用哪些工具来排查这项服务？

# DNS 故障排除和侦察

在 Linux 中用于排查 DNS 服务的主要工具是`dig`，它几乎在所有 Linux 发行版中预装。如果你的发行版中没有`dig`，你可以用`apt-get install dnsutils`来安装它。这个工具的使用非常简单，可以在这里看到：

```
Dig <request value you are making> <the request type you are making>  +<additional request types>
```

因此，要查找公司（我们将检查`sans.org`）的名称服务器记录，我们将对`sans.org`进行`ns`查询，如下所示：

```
$ dig sans.org ns
; <<>> DiG 9.16.1-Ubuntu <<>> sans.org ns
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27639
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;sans.org.                      IN      NS
;; ANSWER SECTION:
sans.org.               86400   IN      NS      ns-1270.awsdns-30.org.
sans.org.               86400   IN      NS      ns-1746.awsdns-26.co.uk.
sans.org.               86400   IN      NS      ns-282.awsdns-35.com.
sans.org.               86400   IN      NS      ns-749.awsdns-29.net.
;; Query time: 360 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Fri Feb 12 12:02:26 PST 2021
;; MSG SIZE  rcvd: 174
```

这包含了很多注释信息——知道哪些 DNS 标志被设置，以及 DNS 问题和答案的确切操作，都是非常有价值的信息，而这些信息都在默认输出中。然而，通常也希望得到一个“只有事实”的输出——为了得到这个，我们将添加第二个参数`+short`，如下所示：

```
$ dig sans.org ns +short
ns-749.awsdns-29.net.
ns-282.awsdns-35.com.
ns-1746.awsdns-26.co.uk.
ns-1270.awsdns-30.org.
```

`dig`命令允许我们进行任何我们喜欢的 DNS 查询。然而，你一次只能查询一个目标，所以要获取**NS**信息（与**名称服务器**相关）和**邮件交换器**（**MX**）信息，你需要进行两次查询。MX 查询如下所示：

```
$ dig sans.org mx +short
0 sans-org.mail.protection.outlook.com.
```

我们可以使用哪些其他工具来进行故障排除，还有哪些其他 DNS 实现可能会涉及？

# DoH

**DoH**是一种较新的 DNS 协议；顾名思义，它是通过 HTTPS 传输的，实际上，DNS 查询和响应在形式上类似于**应用程序编程接口**（**API**）。这个新协议最初在许多浏览器中得到支持，而不是在主流操作系统中本地支持。然而，现在它已经在大多数主流操作系统上可用，只是默认情况下没有启用。

为了远程验证 DoH 服务器，`curl`（一个关于“*查看 url*”的双关语）工具可以很好地完成这项工作。在以下示例中，我们正在对 Cloudflare 的名称服务器进行查询：

```
$ curl -s -H 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name=www.coherentsecurity.com&type=A'
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"www.coherentsecurity.com","type":1}],"Answer":[{"name":"www.coherentsecurity.com","type":5,"TTL":1693,"data":"robvandenbrink.github.io."},{"name":"robvandenbrink.github.io","type":1,"TTL":3493,"data":"185.199.108.153"},{"name":"robvandenbrink.github.io","type":1,"TTL":3493,"data":"185.199.109.153"},
{"name":"robvandenbrink.github.io","type":1,"TTL":3493,"data":"185.199.110.153"},{"name":"robvandenbrink.github.io","type":1,"TTL":3493,"data":"185.199.111.153"}]}
```

请注意，查询只是一个形式如下的`https`请求：

```
https://<the dns server ip>/dns-query?name=<the dns query target>&type=<the dns request type>  
```

请求中的 HTTP 头是`accept: application/dns-json`。请注意，这个查询使用标准的 HTTPS，因此它监听在端口`tcp/443`上，而不是常规的`udp/53`和`tcp/53` DNS 端口。

我们可以通过`jq`将命令输出变得更易读。这个简单的查询显示了输出中的标志——DNS 问题、答案和授权部分。请注意在以下代码片段中，服务器设置了`RD`标志（代表`RA`标志（代表**递归可用**）：

```
curl -s -H 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name=www.coherentsecurity.com&type=A' | jq
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "www.coherentsecurity.com",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "www.coherentsecurity.com",
      "type": 5,
      "TTL": 1792,
      "data": "robvandenbrink.github.io."
    },
    ….  
    {
      "name": "robvandenbrink.github.io",
      "type": 1,
      "TTL": 3592,
      "data": "185.199.111.153"
    }
  ]
}
```

**网络映射器**（**Nmap**）也可以用来验证远程 DoH 服务器上的证书，如下面的代码片段所示：

```
nmap -p443 1.1.1.1 --script ssl-cert.nse
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 11:28 Eastern Standard Time
Nmap scan report for one.one.one.one (1.1.1.1)
Host is up (0.029s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-cert: Subject: commonName=cloudflare-dns.com/organizationName=Cloudflare, Inc./stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:cloudflare-dns.com, DNS:*.cloudflare-dns.com, DNS:one.one.one.one, IP Address:1.1.1.1, IP Address:1.0.0.1, IP Address:162.159.36.1, IP Address:162.159.46.1, IP Address:2606:4700:4700:0:0:0:0:1111, IP Address:2606:4700:4700:0:0:0:0:1001, IP Address:2606:4700:4700:0:0:0:0:64, IP Address:2606:4700:4700:0:0:0:0:6400
| Issuer: commonName=DigiCert TLS Hybrid ECC SHA384 2020 CA1/organizationName=DigiCert Inc/countryName=US
| Public Key type: unknown
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA384
| Not valid before: 2021-01-11T00:00:00
| Not valid after:  2022-01-18T23:59:59
| MD5:   fef6 c18c 02d0 1a14 ab75 1275 dd6a bc29
|_SHA-1: f1b3 8143 b992 6454 97cf 452f 8c1a c842 4979 4282
Nmap done: 1 IP address (1 host up) scanned in 7.41 seconds
```

然而，Nmap 目前没有附带一个脚本，可以通过实际进行 DoH 查询来验证 DoH 本身。为了填补这个空白，你可以在这里下载这样一个脚本：https://github.com/robvandenbrink/dns-doh.nse。

该脚本通过 Lua `http.shortport`操作符验证端口是否正在服务 HTTP 请求，然后构造查询字符串，然后使用正确的标头进行 HTTPS 请求。此工具的完整说明可在此处找到：https://isc.sans.edu/forums/diary/Fun+with+NMAP+NSE+Scripts+and+DOH+DNS+over+HTTPS/27026/。

在彻底探索 DoH 之后，我们还有哪些其他协议可用于验证和加密我们的 DNS 请求和响应？

# DoT

`tcp/853`，这意味着它不会与 DNS（`udp/53`和`tcp/53`）或 DoH（`tcp/443`）发生冲突—如果 DNS 服务器应用程序支持所有三种服务，则这三种服务都可以在同一主机上运行。

大多数现代操作系统（作为客户端）支持 DoT 名称解析。它并不总是默认运行，但如果需要，可以启用它。

远程验证 DoT 服务器就像使用 Nmap 验证`tcp/853`是否在监听一样简单，如下面的代码片段所示：

```
$ nmap -p 853 8.8.8.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-21 13:33 PST
Nmap scan report for dns.google (8.8.8.8)
Host is up (0.023s latency).
PORT    STATE SERVICE
853/tcp open  domain-s
Doing a version scan gives us more good information, but the fingerprint (at the time of this book being published) is not in nmape:
$ nmap -p 853 -sV  8.8.8.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-21 13:33 PST
Nmap scan report for dns.google (8.8.8.8)
Host is up (0.020s latency).
PORT    STATE SERVICE    VERSION
853/tcp open  ssl/domain (generic dns response: NOTIMP)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port853-TCP:V=7.80%T=SSL%I=7%D=2/21%Time=6032D1B5%P=x86_64-pc-linux-gnu
SF:%r(DNSVersionBindReqTCP,20,"\0\x1e\0\x06\x81\x82\0\x01\0\0\0\0\0\0\x07v
SF:ersion\x04bind\0\0\x10\0\x03")%r(DNSStatusRequestTCP,E,"\0\x0c\0\0\x90\
SF:x04\0\0\0\0\0\0\0\0");
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.66 seconds
```

在前面的代码片段中显示的标记为`domain-s`（DNS over `-sV`）的开放端口`tcp/853`显示了响应中的`DNSStatusRequestTCP`字符串，这是一个很好的线索，表明该端口实际上正在运行 DoT。由于它是 DoT，我们还可以使用 Nmap 再次验证验证 DoT 服务的证书，如下所示：

```
nmap -p853 --script ssl-cert 8.8.8.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-21 16:35 Eastern Standard Time
Nmap scan report for dns.google (8.8.8.8)
Host is up (0.017s latency).
PORT    STATE SERVICE
853/tcp open  domain-s
| ssl-cert: Subject: commonName=dns.google/organizationName=Google LLC/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:dns.google, DNS:*.dns.google.
com, DNS:8888.google, DNS:dns.google.com, DNS:dns64.dns.google, IP Address:2001:4860:4860:0:0:0:0:64, IP Address:2001:4860:4860:0:0:0:0:6464, IP Address:2001:4860:4860:0:0:0:0:8844, IP Address:2001:4860:4860:0:0:0:0:8888, IP Address:8.8.4.4, IP Address:8.8.8.8
| Issuer: commonName=GTS CA 1O1/organizationName=Google Trust Services/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-26T08:54:07
| Not valid after:  2021-04-20T08:54:06
| MD5:   9edd 82e5 5661 89c0 13a5 cced e040 c76d
|_SHA-1: 2e80 c54b 0c55 f8ad 3d61 f9ae af43 e70c 1e67 fafd
Nmap done: 1 IP address (1 host up) scanned in 7.68 seconds
```

这就是我们到目前为止讨论的工具所能达到的程度。`dig`工具（目前）不支持进行 DoT 查询。但是，`knot-dnsutils`软件包为我们提供了一个“几乎与`dig`相同”的命令行工具—`kdig`。让我们使用这个工具来更深入地探索 DoT。

## knot-dnsutils

`knot-dnsutils`是一个包含`kdig`工具的 Linux 软件包。`kdig`复制了`dig`工具的功能，但还添加了其他功能，包括对 DoT 查询的支持。要开始使用这个工具，我们首先必须安装`knot-dnsutils`软件包，如下所示：

```
sudo apt-get install  knot-dnsutils
```

安装完成后，`kdig`实用程序与`dig`命令非常相似，只是增加了一些额外的命令行参数—让我们进行 DoT 查询以说明这一点，如下所示：

```
kdig -d +short @8.8.8.8 www.cisco.com A  +tls-ca +tls-hostname=dns.google # +tls-sni=dns.google
;; DEBUG: Querying for owner(www.cisco.com.), class(1), type(1), server(8.8.8.8), port(853), protocol(TCP)
;; DEBUG: TLS, imported 129 system certificates
;; DEBUG: TLS, received certificate hierarchy:
;; DEBUG:  #1, C=US,ST=California,L=Mountain View,O=Google LLC,CN=dns.google
;; DEBUG:      SHA-256 PIN: 0r0ZP20iM96B8DOUpVSlh5sYx9GT1NBVp181TmVKQ1Q=
;; DEBUG:  #2, C=US,O=Google Trust Services,CN=GTS CA 1O1
;; DEBUG:      SHA-256 PIN: YZPgTZ+woNCCCIW3LH2CxQeLzB/1m42QcCTBSdgayjs=
;; DEBUG: TLS, skipping certificate PIN check
;; DEBUG: TLS, The certificate is trusted.
www.cisco.com.akadns.net.
wwwds.cisco.com.edgekey.net.
wwwds.cisco.com.edgekey.net.globalredir.akadns.net.
e2867.dsca.akamaiedge.net.
23.66.161.25
```

我们使用了哪些新参数？

`debug`参数（`-d`）给出了包括`DEBUG`字符串的所有前面的行。鉴于大多数人可能会使用`kdig`因为它支持 TLS，这些`DEBUG`行为我们提供了一些在测试新服务时可能经常需要的优秀信息。如果没有`debug`参数，我们的输出将更像是`dig`，如下面的代码片段所示：

```
kdig  +short @8.8.8.8 www.cisco.com A  +tls-ca +tls-hostname=dns.google +tls-sni=dns.google
www.cisco.com.akadns.net.
wwwds.cisco.com.edgekey.net.
wwwds.cisco.com.edgekey.net.globalredir.akadns.net.
e2867.dsca.akamaiedge.net.
23.66.161.25
```

`+short`参数将输出缩短为“只有事实”显示，就像`dig`一样。如果没有这个参数，输出将包括所有部分（不仅仅是“答案”部分），如下面的代码片段所示：

```
kdig @8.8.8.8 www.cisco.com A  +tls-ca +tls-hostname=dns.google +tls-sni=dns.google
;; TLS session (TLS1.3)-(ECDHE-X25519)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 57771
;; Flags: qr rd ra; QUERY: 1; ANSWER: 5; AUTHORITY: 0; ADDITIONAL: 1
;; EDNS PSEUDOSECTION:
;; Version: 0; flags: ; UDP size: 512 B; ext-rcode: NOERROR
;; PADDING: 240 B
;; QUESTION SECTION:
;; www.cisco.com.               IN      A
;; ANSWER SECTION:
www.cisco.com.          3571    IN      CNAME   www.cisco.com.akadns.net.
www.cisco.com.akadns.net.       120     IN      CNAME   wwwds.cisco.com.edgekey.net.
wwwds.cisco.com.edgekey.net.    13980   IN      CNAME   wwwds.cisco.com.edgekey.net.globalredir.akadns.net.
wwwds.cisco.com.edgekey.net.globalredir.akadns.net. 2490        IN      CNAME  e2867.dsca.akamaiedge.net.
e2867.dsca.akamaiedge.net.      19      IN      A       23.66.161.25
;; Received 468 B
;; Time 2021-02-21 13:50:33 PST
;; From 8.8.8.8@853(TCP) in 121.4 ms
```

我们使用的新参数列在此处：

+   `+tls-ca`参数强制执行 TLS 验证—换句话说，它验证证书。默认情况下，系统使用**证书颁发机构**（**CA**）列表进行此操作。

+   添加`+tls-hostname`允许您指定 TLS 协商的主机名。默认情况下，使用 DNS 服务器名称，但在我们的情况下，服务器名称是`8.8.8.8`—您需要一个出现在 TLS 正确协商的**CN**或**主题备用名称**（**SAN**）列表中的有效主机名。因此，此参数允许您独立于服务器名称字段中使用的内容指定该名称。

+   添加`+tls-sni`在请求中添加了**服务器名称指示**（**SNI**）字段，这是许多 DoT 服务器所必需的。这可能看起来有点奇怪，因为 SNI 字段是为了允许 HTTPS 服务器呈现多个证书（每个用于不同的 HTTPS 站点）。

如果您不使用这些参数，只是像使用`dig`一样使用`kdig`会发生什么？默认情况下，`kdig`不会强制验证证书与您指定的 FQDN 是否匹配，因此它通常会正常工作，如下面的代码片段所示：

```
$ kdig +short @8.8.8.8 www.cisco.com A
www.cisco.com.akadns.net.
wwwds.cisco.com.edgekey.net.
wwwds.cisco.com.edgekey.net.globalredir.akadns.net.
e2867.dsca.akamaiedge.net.
23.4.0.216
```

然而，最好按照 TLS 的原意使用它，进行验证——毕竟，重点是在 DNS 结果中添加另一层信任。如果您不验证服务器，那么您所做的就是加密查询和响应。如果不在服务器名称字段或 TLS 主机名字段中指定正确的主机名，您就无法进行验证（此值需要与证书参数匹配）。强制证书验证很重要，因为这样可以确保 DNS 服务器是您真正想要查询的服务器（即，您的流量没有被拦截），并且响应在返回客户端的过程中没有被篡改。

既然我们了解了 DoT 的工作原理，那么我们如何进行故障排除或查明 DNS 主机是否已实施 DoT 呢？

## 在 Nmap 中实施 DoT

与 DoH Nmap 示例类似，实施 DoT 在 Nmap 中允许您以更大的规模进行 DoT 发现和查询，而不是一次一个。考虑到在 Nmap 中进行 HTTPS 调用的复杂性，一个简单的方法就是在 Nmap 脚本中直接调用`kdig`，使用 Lua 中的`os.execute`函数来完成这个任务。

另一个关键区别是，我们不是测试`http`功能的目标端口（使用`shortport.http`测试），而是使用`shortport.ssl`测试来验证 SSL/TLS 功能的任何开放端口；因为如果它不能提供有效的 TLS 请求服务，那么它就不能是 DoT，对吧？

`dns.dot`工具可在此处下载：

https://github.com/robvandenbrink/dns-dot

您可以在此处查看完整的说明：

https://isc.sans.edu/diary/Fun+with+DNS+over+TLS+%28DoT%29/27150

我们可以在 DNS 协议本身上实施哪些其他安全机制？让我们来看看 DNSSEC，这是验证 DNS 响应的原始机制。

## DNSSEC

`udp/53`和`tcp/53`，因为它不加密任何内容——它只是添加字段来验证使用签名的标准 DNS 操作。

您可以使用`dig`中的`DNSKEY`参数查看任何 DNS 区域的公钥。在以下代码示例中，我们添加了`short`参数：

```
$ dig DNSKEY @dns.google example.com +short
256 3 8 AwEAAa79LdJaZfIxVzyjq4H7yB4VqT/rIreB+N0jija+4bWHzNrwhSiu D/SOtgvX+gXEgwAR6tHGn9q9t65o85RfdHJrueORb0usa3x6LHM7qy6A r22P78UUn/rxa9jbi6yS4cVOzLnJ+OKO0w1Scly5XLDmmWPbIM2LvayR 2U4UAqZZ
257 3 8 AwEAAZ0aqu1rJ6orJynrRfNpPmayJZoAx9Ic2/Rl9VQWLMHyjxxem3VU SoNUIFXERQbj0A9Ogp0zDM9YIccKLRd6LmWiDCt7UJQxVdD+heb5Ec4q lqGmyX9MDabkvX2NvMwsUecbYBq8oXeTT9LRmCUt9KUt/WOi6DKECxoG /bWTykrXyBR8elD+SQY43OAVjlWrVltHxgp4/rhBCvRbmdflunaPIgu2 7eE2U4myDSLT8a4A0rB5uHG4PkOa9dIRs9y00M2mWf4lyPee7vi5few2 dbayHXmieGcaAHrx76NGAABeY393xjlmDNcUkF1gpNWUla4fWZbbaYQz A93mLdrng+M=
257 3 8 AwEAAbOFAxl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYzK/ ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0EhF+dgXmoUfRX 7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PEMVCjtryl19Be9/PkFeC9ITjg MRQsQhmB39eyMYnal+f3bUxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMA kTJhghqgy+o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCzC MtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCBgaYCi9hpiMWV vS4WBzx0/lU=
```

要查看`DS`参数，如下面的代码片段所示：

```
$ dig +short DS @dns.google example.com
31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE
31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03 
E576343C
43547 8 1 B6225AB2CC613E0DCA7962BDC2342EA4F1B56083
43547 8 2 615A64233543F66F44D68933625B17497C89A70E858ED76A2145997E DF96A918
31406 8 1 189968811E6EBA862DD6C209F75623D8D9ED9142
31406 8 2 F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D 8F6B916D
```

如果我们添加`-d`（调试）参数并过滤以仅查看`DEBUG`数据，我们将在输出中看到以下行，该行指示我们正在使用与常规 DNS 查询相同的端口和协议：

```
dig -d DNSKEY @dns.google example.com  | grep DEBUG
;; DEBUG: Querying for owner(example.com.), class(1), type(48), server(dns.google), port(53), protocol(UDP)
```

要进行 DNSSEC 查询，只需在`dig`命令行中添加`+dnssec`，如下所示：

```
$ dig +dnssec +short @dns.google www.example.com A
93.184.216.34
A 8 3 86400 20210316085034 20210223165712 45150 example.com. UyyNiGG0WDAsberOUza21vYos8vDc6aLq8FV9lvJT4YRBn6V8CTd3cdo ljXV5uETcD54tuv1kLZWg7YZxSQDGFeNC3luZFkbrWAqPbHXy4D7Tdey LBK0R3xywGxgZIEfp9HMjpZpikFQuKC/iFvd14uJhoquMqFPFvTfJB/s XJ8=
```

DNSSEC 主要是关于在客户端和服务器之间，以及在中继请求时服务器之间对 DNS 请求进行认证。正如我们所看到的，它是由任何特定区域的所有者实施的，以允许请求者验证他们得到的 DNS“答案”是否正确。然而，由于其复杂性和对证书的依赖，它并没有像 DoT 和 DoH 那样被广泛采用。

正如我们所看到的，DoT 和 DoH 专注于个人隐私，加密个人进行业务时所做的每个 DNS 请求。虽然这种加密使得这些 DNS 请求更难以捕获，但这些请求仍然记录在 DNS 服务器上。此外，如果攻击者能够收集个人的 DNS 请求，他们也能够简单地记录他们访问的站点（按 IP 地址）。

话虽如此，我们不会深入研究 DNSSEC 的深度，主要是因为作为一个行业，我们已经做出了同样的决定，并且（在大多数情况下）选择不实施它。然而，您确实会不时地看到它，特别是在解决涉及 DNS 的问题时，因此了解它的外观以及为什么可能会实施它是很重要的。

# 总结

随着我们对 DNS 的讨论接近尾声，您现在应该有了构建基本内部 DNS 服务器和面向互联网的标准 DNS 服务器的工具。您还应该具备开始通过编辑 Linux `bind`或命名服务的各种配置文件来保护这些服务的基本工具。

此外，您应该熟悉使用`dig`、`kdig`、`curl`和`nmap`等工具来排除各种 DNS 服务的故障。

在下一章中，我们将继续讨论 DHCP，正如我们在本章中所看到的，它确实是分开的，但仍然与 DNS 有关。

# 问题

最后，这里是一些问题列表，供您测试对本章材料的了解。您将在*附录*的*评估*部分找到答案。

1.  DNSSEC 与 DoT 有何不同？

1.  DoH 与“常规”DNS 有何不同？

1.  您会在内部 DNS 服务器上实现哪些功能，而不是在外部 DNS 服务器上实现？

# 进一步阅读

要了解更多关于这个主题的信息：

+   **权威 DNS 参考**

基本 DNS 实际上有数十个定义服务以及实施最佳实践的 RFC。这里可以找到这些 RFC 的一个好列表：https://en.wikipedia.org/wiki/Domain_Name_System#RFC_documents。

但是，如果您需要更多关于 DNS 的详细信息，并且正在寻找比 RFC 更易读的协议和实施细节的指南（重点是“易读”），许多人认为 Cricket Liu 的书是一个很好的下一步：

*Cricket Liu 和 Paul Albitz 的 DNS 和 BIND*：

https://www.amazon.ca/DNS-BIND-Help-System-Administrators-ebook/dp/B0026OR2QS/ref=sr_1_1?dchild=1&keywords=dns+and+bind+cricket+liu&qid=1614217706&s=books&sr=1-1

*Cricket Liu 的 IPv6 上的 DNS 和 BIND*：

https://www.amazon.ca/DNS-BIND-IPv6-Next-Generation-Internet-ebook/dp/B0054RCT4O/ref=sr_1_3?dchild=1&keywords=dns+and+bind+cricket+liu&qid=1614217706&s=books&sr=1-3

+   **DNS 更新（自动注册）**

*RFC 2136*：*域名系统（DNS UPDATE）中的动态更新*：

https://tools.ietf.org/html/rfc2136

+   **Active Directory（AD）中的经过身份验证的 DNS 注册**

*RFC 3645*：*用于 DNS 的秘密密钥事务认证的通用安全服务算法（GSS-TSIG）*：

https://tools.ietf.org/html/rfc3645

+   **DoH**

*使用 NMAP NSE 脚本和 DOH（HTTPS 上的 DNS）玩乐*：https://isc.sans.edu/forums/diary/Fun+with+NMAP+NSE+Scripts+and+DOH+DNS+over+HTTPS/27026/

DoH Nmap 脚本：https://github.com/robvandenbrink/dns-doh.nse

*RFC 8484*：*HTTPS 上的 DNS 查询（DoH）*：https://tools.ietf.org/html/rfc8484

+   `dns-dot` Nmap 脚本：https://isc.sans.edu/diary/Fun+with+DNS+over+TLS+%28DoT%29/27150

*RFC 7858*：*传输层安全性（TLS）上的 DNS 规范*：https://tools.ietf.org/html/rfc7858

+   **DNSSEC**

*域名系统安全扩展（DNSSEC）*：https://www.internetsociety.org/issues/dnssec/

*RFC 4033*：*DNS 安全介绍和要求*：https://tools.ietf.org/html/rfc4033

*RFC 4034*：*DNS 安全扩展的资源记录*：https://tools.ietf.org/html/rfc4034

*RFC 4035*：*DNS 安全扩展的协议修改*：https://tools.ietf.org/html/rfc4035

*RFC 4470*：*最小覆盖 NSEC 记录和 DNSSEC 在线签名*：https://tools.ietf.org/html/rfc4470

*RFC 4641*：*DNSSEC 操作实践*：https://tools.ietf.org/html/rfc4641

*RFC 5155*：*DNS 安全（DNSSEC）哈希认证否定存在*：https://tools.ietf.org/html/rfc5155

*RFC 6014*：*DNSSEC 的加密算法标识符分配*：https://tools.ietf.org/html/rfc6014

*RFC 4398*：*在域名系统（DNS）中存储证书*：https://tools.ietf.org/html/rfc4398
