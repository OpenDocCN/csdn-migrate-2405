# 面向网络专家的 Linux（三）

> 原文：[`zh.annas-archive.org/md5/A72D356176254C9EA0055EAB3A38778D`](https://zh.annas-archive.org/md5/A72D356176254C9EA0055EAB3A38778D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Linux 上的 DHCP 服务

在本章中，我们将涵盖几个涉及**动态主机控制协议（DHCP**）的主题。顾名思义，DHCP 用于提供主机连接到网络所需的基本信息，并在某些情况下提供其他配置的位置，这使其成为大多数基础设施的关键部分。

在本章中，我们将介绍这种协议的基本工作原理，然后逐步构建和最终解决 DHCP 服务的问题，具体包括：

+   DHCP 是如何工作的？

+   保护您的 DHCP 服务

+   安装和配置 DHCP 服务器

让我们开始吧！

# DHCP 是如何工作的？

让我们首先描述 DHCP 实际是如何工作的。我们将首先看一下 DHCP 请求和响应中的数据包是如何工作的 - 客户端请求了什么信息，服务器提供了什么信息，以及它是如何工作的。然后我们将开始讨论 DHCP 选项如何在许多实现中发挥作用。

## 基本的 DHCP 操作

**DHCP**允许系统管理员在服务器上集中定义设备配置，以便当这些设备启动时，它们可以请求这些配置参数。这种*中央配置*几乎总是包括 IP 地址、子网掩码、默认网关、DNS 服务器和 DNS 域名的基本网络参数。在大多数组织中，这意味着在大多数情况下，几乎没有设备获得静态 IP 地址或其他网络定义；所有工作站网络配置都是由 DHCP 服务器设置的。当我们更深入地探讨协议时，您将看到 DHCP 的其他用途通常是*附加*到这些基本设置上。

DHCP 过程是从客户端发送广播**DISCOVER**数据包开始的，基本上是在说“有没有 DHCP 服务器？这是我正在寻找的信息。” DHCP 服务器然后回复一个**OFFER**数据包，其中包含所有信息。客户端回复一个**REQUEST**数据包，这个名字似乎有点奇怪 - 基本上，客户端是通过确认的方式将刚刚从服务器得到的信息发送回去。然后服务器再次发送最终的**ACKNOWLEDGEMENT**数据包，再次包含相同的信息，再次确认。

这通常被称为**DORA**序列（**Discover, Offer, Request, Acknowledgement**），通常是这样描述的：

![图 7.1 - DHCP DORA 序列](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_07_001.jpg)

图 7.1 - DHCP DORA 序列

由于这些都是 UDP 数据包，请记住 UDP 协议中没有内置的会话信息，那么是什么将这四个数据包绑定成一个“会话”？为此，初始的 Discover 数据包具有一个事务 ID，在三个后续数据包中匹配 - 下面显示的 Wireshark 跟踪说明了这一点：

![图 7.2 - 在 Wireshark 中显示的 DHCP DORA 序列](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_07_002.jpg)

图 7.2 - 在 Wireshark 中显示的 DHCP DORA 序列

重要提示

客户端实际上直到第四个数据包才有地址，因此 Discover 和 Request 数据包来自客户端的 MAC 地址，IP 地址为`0.0.0.0`，发送到广播地址`255.255.255.255`（即整个本地网络）。

现在我们了解了 DHCP 工作的基础知识，我们看到它严重依赖于广播地址，这些地址限制在本地子网。在更实际的设置中，我们如何在不同的子网中使用 DHCP，甚至可能在不同的城市或国家中使用 DHCP 服务器？

## 来自其他子网的 DHCP 请求（转发器、中继或辅助程序）

但是，您可能会说 - 在许多公司网络中，服务器位于它们自己的子网上 - 将服务器和工作站分开是一种非常常见的做法。在这种情况下，DHCP 序列是如何工作的？DORA 序列的前三个数据包发送到广播地址，因此它们只能到达同一 VLAN 上的其他主机。

我们通过在客户端子网上的主机上放置 DHCP“转发器”或“中继”进程来完成工作。该进程接收本地广播，然后将其转发到 DHCP 服务器作为单播。当服务器回复（作为单播到转发器主机）时，转发器将数据包转换回客户端期望的广播回复。几乎总是在客户端子网上的路由器或交换机 IP 地址上执行此转发器功能 - 换句话说，最终将成为客户端默认网关的接口。这个功能在技术上不需要在该接口上，但我们知道该接口将存在，并且该功能几乎总是可供我们使用。此外，如果我们将其作为一种不成文的惯例使用，那么如果以后需要更改它，就更容易找到该命令！在思科路由器或交换机上，此命令如下：

```
interface VLAN <x>  ip helper-address 10.10.10.10
```

这里，`10.10.10.10`是我们的 DHCP 服务器的 IP。

在操作中，这将改变大多数家庭网络上的简单广播操作，以包括到位于另一个子网上的 DHCP 服务器的单播“腿”：

![图 7.3 - DHCP 中继或转发器操作](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_07_003.jpg)

图 7.3 - DHCP 中继或转发器操作

这如何修改我们的 DORA 序列？简短的答案是它实际上并没有修改任何数据包的 DHCP 内容。它所做的是修改数据包中的上层“IP 地址”字段 - 在路由器和服务器之间修改的数据包具有“真实”的源和目的地 IP 地址。然而，客户端看到的数据包内容保持不变。如果您深入研究 DHCP 数据包，您会发现无论是否使用中继，DHCP 客户端 MAC 地址和 DHCP 服务器 IP 地址实际上都包含在第 7 层 DHCP 协议的数据字段中。

我们现在已经具备了为基本工作站操作配置 DHCP 服务器的条件，但在开始之前，我们需要考虑一下我们需要为 iPhone、**无线接入点（WAP）**或甚至**预执行环境（PXE）**设备等特殊用途设备提供什么信息。

## DHCP 选项

在 DHCP Discover 数据包中发送的选项基本上是客户端知道如何处理的 DHCP 网络参数列表。服务器的 Offer 数据包将尽可能填充此列表。最常见的请求的选项（并在服务器上配置）如下：

+   子网掩码

+   路由器（默认网关）

+   DNS 服务器列表

+   DNS 域名

有关 DHCP 选项的更完整参考可以在 IANA 网站上找到，[`www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml`](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml)，或者在相关的 RFC 中找到：[`tools.ietf.org/html/rfc2132`](https://tools.ietf.org/html/rfc2132)。

然而，在许多公司网络中，您可能会看到其他请求和提供的信息 - 这通常是为了支持**Voice over IP（VOIP）**电话的启动。这些选项通常是特定于供应商的，但在大多数情况下，客户端设备将请求的信息列表如下：

+   **我需要在哪个 VLAN 上？**：这个选项在现代网络中使用得较少，而是更倾向于使用**链路层发现协议（LLDP）**在交换机上识别 VOICE VLAN。在思科交换机上，只需在 VLAN 定义中添加 voice 关键字即可。

+   **我将连接到的 PBX 的 IP 是多少？**

+   **我应该连接到哪个 TFTP 或 HTTP 服务器以收集我的硬件配置？**

如果服务器有所请求的信息，它将在 DHCP 提供中作为服务器的响应数据包提供。

通常，您会看到以下 DHCP 选项，但如果您使用不同的电话手柄供应商，当然，您的情况可能会有所不同：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/Table_012.jpg)

请注意，Mitel 和 Shortel 电话使用相同的 DHCP 选项，但语法略有不同。

DHCP 选项有时也用于告诉 WAP 使用哪个 IP 地址来找到它们的控制器，控制 PXE 站的引导顺序，或者任何其他自定义用途。在大多数情况下，DHCP 选项的作用是确保远程设备获取它需要的信息，以便从一个中心位置引导启动，而无需为每个设备进行配置。如果您需要这些选项用于您的特定设备，详细信息将在供应商的文档中（查找**DHCP 选项**）。

如果您正在解决 DHCP 序列的问题，特别是为什么 DHCP 选项的工作方式不如您所期望的那样，任何特定设备所需的 DHCP 选项将始终包含在初始的 Discover 数据包中，即 DORA 序列中的第一个数据包。始终从那里开始调查，您通常会发现所请求的 DHCP 选项并非配置的选项。

现在我们已经了解了 DHCP 的基本原理，我们如何才能使其免受常见攻击或操作问题的影响呢？

# 保护您的 DHCP 服务

关于 DHCP 的有趣之处在于，在几乎所有情况下，保护服务是在网络交换机上进行的，而不是在 DHCP 服务器本身上进行的。在大多数情况下，DHCP 服务器接收匿名请求，然后适当地回复 - 没有太多机会在不增加太多复杂性（使用签名和 PKI，我们将介绍），或者通过维护授权的 MAC 地址列表（这将增加很多复杂性）的情况下保护我们的服务。这两种方法都与拥有 DHCP 服务的初衷背道而驰，即“自动”对工作站、电话和其他网络连接设备进行网络配置，而不增加太多复杂性或管理开销。

那么我们如何保护我们的服务呢？让我们看一些攻击场景，然后添加最常见的防御措施。

## 恶意 DHCP 服务器

首先，让我们看看`192.168.1.0/24`或`192.168.0.0/24`，这几乎总是*不*是我们在工作中配置的。因此，一旦连接到网络，工作站将开始在此子网上获取地址，并且将失去与真正的企业网络的连接。

我们如何防御？答案在网络交换机上。我们在每个交换机上评估拓扑结构，并决定哪些端口可以信任发送 DHCP Offer 数据包 - 换句话说，“哪些端口引导我们到 DHCP 服务器？”这几乎总是交换机上行链路，这是我们连接服务器的链路。

一旦在交换机上识别出来，我们启用所谓的**DHCP 监听**，指示交换机检查 DHCP 数据包。这是按 VLAN 逐个进行的，在大多数环境中，我们通常列出所有 VLAN。然后我们配置我们的上行端口为“受信任”以发送 DHCP 数据包。这通常是一个非常简单的配置更改，看起来类似于这样（显示了 Cisco 配置）：

```
ip dhcp snooping vlan 1 2 10
interface e1/48
    ip dhcp snooping trust
```

如果在任何端口或 IP 地址上接收到 DHCP Offer 数据包，而不是我们配置为“受信任”的端口，默认情况下，该端口将被关闭，并发送警报（尽管您可以配置它们只发送警报）。然后，该端口处于所谓的*错误禁用*状态，通常需要网络管理员追踪根本原因并进行修复。这使得日志记录和警报过程非常重要。如果这对您的组织立即很重要，您可以直接跳到*第十三章*，*Linux 上的入侵防护系统*。

对于一些交换机供应商，我们可以信任 DHCP 服务器 IP 而不是上行端口。例如，在 HP 交换机上，我们仍然可以使用上面概述的方法，但我们还可以根据 IP 地址添加一个更简单的配置：

```
dhcp-snooping
dhcp-snooping vlan 1 2 10
dhcp-snooping authorized-server <server ip address>
```

在较大的网络中，这种方法使我们的配置变得更加简单 – 无需识别可能与交换机不同的上行端口；这两行可以简单地复制到所有工作站交换机上。

当我们到达服务器 VLAN 和数据中心交换机时，我们面临的事实是我们的 DHCP 服务器很可能是一个虚拟机。这给我们留下了两种选择 – 要么我们在连接到我们的虚拟化服务器的所有上行端口上配置 DHCP 信任，要么在服务器交换机上，我们根本不配置 DHCP 监听或信任。这两种选择都是有效的选择，老实说，第二种选择是我们经常看到的 – 在许多情况下，网络管理员可以相信服务器交换机在一个封闭的房间或机柜中，这成为我们的 DHCP 服务的安全层。这也意味着服务器和虚拟化管理员在进行服务器端的更改时不需要太多考虑物理网络（或在许多情况下根本不需要涉及网络管理员）。

我们确实提到“意外的 DHCP 服务器”是迄今为止最常见的恶意 DHCP 服务器攻击。但是有关有意的 DHCP 服务器攻击呢？这些攻击是什么样的？第一种情况是 DHCP 服务器将恶意主机添加为默认网关（通常是它自己）。当接收到数据包时，恶意主机将检查要窃取、窥视或修改的流量信息，然后将其转发到合法路由器（该子网的默认网关）：

![图 7.4 – 使用 DHCP 的第 3 层 MiTM 攻击](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_07_004.jpg)

图 7.4 – 使用 DHCP 的第 3 层 MiTM 攻击

另一种情况是，恶意 DHCP 服务器向客户端提供了所有正确的信息，但在 DHCP 租约中添加了一个“额外”的 DHCP 信息 – DHCP 选项`252`。选项`252`是一个文本字符串，指向一个`http://<恶意服务器>/link/<filename.pac>`。PAC 文件是特殊格式的。攻击者将其构建为使用他们的恶意代理服务器来针对目标网站，并对其他网站的 Web 流量进行正常路由。这两种**中间人**（通常缩写为**MiTM**）的意图是窃取凭据 – 当您浏览到目标网站，如 PayPal、Amazon 或您的银行时，攻击者将准备好一个假网站来收集您的用户 ID 和密码。这通常被称为**WPAD 攻击**（**Windows 代理自动发现**），因为它对默认情况下配置为信任 DHCP 服务器获取代理设置的 Windows 客户端非常成功。在大多数情况下，WPAD 攻击是首选，因为攻击者不必担心解密 HTTPS、SSH 或任何其他加密流量：

![图 7.5 – WPAD 攻击 – 恶意 DHCP 服务器设置代理服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_07_005.jpg)

图 7.5 – WPAD 攻击 – 恶意 DHCP 服务器设置代理服务器

在这两种恶意 DHCP 服务器的情况下，我们的“DHCP 信任”防御效果非常好。

WPAD 攻击的另一个防御措施是在 DNS 服务器上为 WPAD 添加 DNS 条目– `yourinternaldomain.com`。这对于 WPAD 攻击可以结合其他攻击（特别是针对任何多播 DNS 协议，如 LLMNR）是有帮助的，但如果该主机名有 DNS 条目，那么这些攻击就会被很好地规避。此外，记录所有对 WPAD 等可疑主机名的 DNS 请求是帮助您在攻击发生时识别和定位攻击的绝佳实践。

但是，如何防范来自其他方向的攻击呢？未经授权的客户端呢？

## Rogue DHCP 客户端

较少见的攻击向量是恶意的 DHCP 客户端-一个人将他们的服务器从家里带到工作中的未使用的以太网端口，或者将一个微型的、专门设计的攻击 PC（通常称为**pwnplug**）插入大堂或任何可访问的位置的未使用的以太网端口。这些地方的后面，植物、打印机或其他障碍物是这些攻击的最爱位置。

对抗这种攻击的老派方法是在公司中保留所有授权的 MAC 地址的数据库，并将它们设置为 DHCP 中的授权客户端，或者为每个客户端设置一个静态的 DHCP 保留。在现代企业中，这两种方法都不是理想的。首先，这是一个相当重要的管理过程。我们正在为服务器团队的流程添加手动库存组件。由于 DHCP 服务器通常是一个低开销的服务器组件，没有人会对此感到高兴。其次，如果采用“静态保留”方法，您将需要为客户端可能需要连接的每个 VLAN、无线 SSID 或可能的位置添加保留。不用说，大多数组织都不喜欢这两种方法。

防止未经授权的客户端的较新方法是使用 802.1x 认证，其中客户端必须在被允许连接到网络之前进行身份验证。这涉及使用*Linux 的 RADIUS 服务*（*第九章*）和*Linux 上的证书服务*（*第八章*）。证书用于强制执行信任-客户端需要信任 RADIUS 服务器，更重要的是，RADIUS 服务器需要信任连接的客户端，以便进行安全的认证。正如您所期望的那样，我们将在本书的后面部分介绍这个解决方案（在*第八章*中，*Linux 上的证书服务*和*第九章*中，*Linux 的 RADIUS 服务*）。

完成所有这些理论的学习和内化后，让我们开始配置 DHCP 服务器。

# 安装和配置 DHCP 服务器

我们将把配置任务分成三个部分：

+   DHCP 服务器和范围的基本配置

+   DHCP 租约的静态保留-例如，用于服务器或打印机。

+   使用 DHCP 日志进行网络智能和库存检查或人口统计。

让我们开始吧。

## 基本配置

正如您所期望的，我们将从`apt`命令开始我们的旅程，在我们的实验室主机上安装 ISC DHCP 服务器：

```
$ sudo apt-get install isc-dhcp-server
```

安装完成后，我们可以配置基本的服务器选项。设置租约时间和任何不依赖于范围的内容-例如，我们将配置中央 DNS 服务器。另外，请注意我们正在添加一个 ping 检查-在分配租约之前，主机会 ping 候选地址，以确保没有其他人静态分配了它。这是一个很好的检查，可以避免重复的 IP 地址，默认情况下是关闭的。在我们的示例中，ping 的超时设置为 2 秒（默认值为 1 秒）。请注意，对于某些 dhcpd 服务器，`ping-check`参数可能会缩短为`ping`。

还要注意租约时间变量。这些变量决定 DHCP“租约”有效的时间以及客户端何时开始请求租约续订。这些对几个原因很重要：

+   尽管我们努力将 IP 地址与各种诊断工具分离，但在事件响应中，能够相对依赖地址不会发生太大变化是非常有帮助的。例如，如果您正在解决一个问题，并且在问题发生之初确定了某人的工作站 IP 地址，如果您能够依赖在接下来的 3-4 天内不会发生变化，那将非常有帮助。这意味着您可以只针对所有相关日志进行一次基于地址的搜索，这非常有帮助。因此，内部工作站 DHCP 租约通常设置为长达 4 天的周末或长达 2-3 周的假期，保持 DHCP 租约在这段时间内有效。

+   当然，例外情况是访客网络，特别是访客无线网络。如果您不将访客地址与其身份或其赞助者的身份关联起来，那么在这里设置较短的租约时间会有所帮助。此外，访客网络通常会看到更多“瞬时”用户的出现和离开，因此较短的租约时间可以在一定程度上保护您免受地址池枯竭的影响。如果您曾经在具有较短租约时间的“匿名访客”网络上进行事件响应，您很可能会基于 MAC 地址而不是 IP 地址来建立“伪身份”（并以相同的方式阻止可疑主机）。

可用的三个租约时间变量如下：

+   `default-lease-time`：如果客户端没有请求租约时间，则租约的持续时间

+   最长租约时间：服务器能够提供的最长租约时间

+   `min-lease-time`：如果客户端请求的租约时间短于此间隔，则用于强制客户端使用更长的租约

在所有情况下，客户端可以在协商的租约间隔的 50%点开始请求租约续订。

让我们编辑 DHCP 服务器的主配置-`/etc/dhcp/dhcpd.conf`。确保使用`sudo`以便在编辑此文件时具有适当的权限：

```
default-lease-time 3600;
max-lease-time 7200;
ping true;
ping-timeout 2;
option domain-name-servers 192.168.122.10, 192.168.124.11;
```

在文件中稍后取消注释`authoritative`参数：

```
# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
authoritative;
```

在文件的末尾，添加范围的详细信息。请注意，如果您正在部署新的子网，请尽量避免使用`192168.0.0/24`或`192.168.1.0/24`-因为这些在家庭网络中经常使用，在工作中使用它们可能会给远程人员造成很大的麻烦。如果他们使用 VPN，他们将不得不处理两个不同的`192.168.1.0`网络-其中一个可能无法访问：

```
# Specify the network address and subnet-mask
  subnet 192.168.122.0 netmask 255.255.255.0 {
  # Specify the default gateway address
  option routers 192.168.122.1;
  # Specify the subnet-mask
  option subnet-mask 255.255.255.0;
  # Specify the range of leased IP addresses
  range 192.168.122.10 192.168.122.200;
}
```

这也是您可以放置任何其他 DHCP 选项的地方，我们在本章前面讨论过这些选项-例如，支持 VOIP 电话、PXE 主机或无线接入点的选项。

最后，重新启动 DHCP 服务器：

```
$ sudo systemctl restart isc-dhcp-server.service
```

仅供娱乐，如果您希望客户端尝试使用他们的信息更新 DNS 服务器，可以添加以下内容：

```
ddns-update-style interim;
# If you have fixed-address entries you want to use dynamic dns
update-static-leases on;
```

现在，让我们将我们的基本配置扩展到包括静态预留-使用 DHCP 为打印机或其他网络设备（如时间钟、IP 摄像头、门锁甚至服务器）分配固定 IP 地址。

## 静态预留

要为主机添加静态定义，我们在`dhcpd.conf`中添加一个`host`部分。在其最基本的配置中，我们在看到特定 MAC 地址时分配一个固定的 IP 地址：

```
host PrtAccounting01 {
  hardware ethernet 00:b1:48:bd:14:9a;
  fixed-address 172.16.12.49;}
```

在某些情况下，工作站可能会漫游-例如，如果设备是无线的，并且可能在不同时间出现在不同的网络中，我们将希望分配其他选项，但保留 IP 地址动态。在这种情况下，我们告诉设备使用什么 DNS 后缀，并如何使用动态 DNS 进行注册：

```
host LTOP-0786 {
    hardware ethernet 3C:52:82:15:57:1D;
    option host-name "LTOP-0786";
    option domain-name "coherentsecurity.com";
    ddns-hostname "LTOP-786";
    ddns-domain-name "coherentsecurity.com";
}
```

或者，要为一组主机添加静态定义，请执行以下命令：

```
group {
    option domain-name "coherentsecurity.com";
    ddns-domainname "coherentsecurity";
    host PrtAccounting01 {
        hardware ethernet 40:b0:34:72:48:e4;
        option host-name "PrtAccounting01";
        ddns-hostname "PrtAccounting01";
        fixed-address 192.168.122.10;
    }
    host PrtCafe01 {
        hardware ethernet 00:b1:48:1c:ac:12;
        option host-name "PrtCafe01";
        ddns-hostname "PrtCafe01";
        fixed-address 192.168.125.9
    }
}
```

现在我们已经配置并运行了 DHCP，如果出现故障，我们有哪些工具可以帮助进行故障排除？让我们首先查看 DHCP 租约信息，然后深入分析`dhcpd`守护程序的日志。

## 日常使用中的简单 DHCP 日志记录和故障排除

要查看当前 DHCP 租约列表，请使用`dhcp-lease-list`命令，该命令应该给出以下列表（请注意，文本已换行；此输出每个设备租约一行）：

```
$ dhcp-lease-list
Reading leases from /var/lib/dhcp/dhcpd.leases
MAC                IP              hostname       valid until         manufacturer
===============================================================================================
e0:37:17:6b:c1:39  192.168.122.161 -NA-           2021-03-22 14:53:26 Technicolor CH USA Inc.
```

请注意，此输出已从每个 MAC 地址中提取了 OUI，因此，例如，您可以使用此命令及其输出来寻找“奇怪”的 NIC 类型。这些在您的 VOIP 子网或大多数移动设备的子网中应立即显眼。即使在标准数据 VLAN 中，基于 OUI 的奇怪设备类型通常也很容易被发现。当客户端有一个标准的电话类型并且在第一次看到 OUI 提取时发现了一个非品牌电话，或者如果他们是 Windows 商店并且看到了他们没有预期的苹果电脑时，我经常看到这种情况。

您可以轻松地将租约信息“收集”到您选择的电子表格中，以便您可以修改该列表以满足您的需求，或者满足您的库存应用程序对输入的需求。或者，如果您只想将 MAC 地址提取到主机名表中，例如，执行以下命令：

```
$ dhcp-lease-list | sed –n '3,$p' |  tr –s " " | cut –d " " –f 1,3 > output.txt
```

用通俗的语言来说，这意味着运行`dhcp-lease-list`命令。从第 3 行开始打印整个列表，删除重复的空格，然后使用单个空格作为列分隔符取列 1 和 3。

如果您需要更详细的信息，或者如果您正在调查过去发生的事件，您可能需要更多或不同的数据 - 为此，您需要日志。 DHCP 日志到`/var/log/dhcpd.log`，输出非常详细。例如，您可以收集任何特定 MAC 地址的整个 DORA 序列：

```
cat dhcpd.log | grep e0:37:17:6b:c1:39 | grep "Mar 19" | more
Mar 19 13:54:15 pfSense dhcpd: DHCPDISCOVER from e0:37:17:6b:c1:39 via vmx1
Mar 19 13:54:16 pfSense dhcpd: DHCPOFFER on 192.168.122.113 to e0:37:17:6b:c1:39 via vmx1
Mar 19 13:54:16 pfSense dhcpd: DHCPREQUEST for 192.168.122.113 (192.168.122.1) from e0:37:17:6b:c1:39 via vmx1
Mar 19 13:54:16 pfSense dhcpd: DHCPACK on 192.168.122.113 to e0:37:17:6b:c1:39 via vmx1
```

或者您可以迈出下一步，问“谁在这个日期使用了这个 IP 地址？”我们将收集整天的数据，以防多台主机可能使用了该地址。为了获得最终的地址分配，我们只需要确认（`DHCPACK`）数据包：

```
cat /var/log/dhcpd.log | grep 192.168.122.113 | grep DHCPACK | grep "Mar 19"
Mar 19 13:54:16 pfSense dhcpd: DHCPACK on 192.168.122.113 to
 e0:37:17:6b:c1:39 via vmx1
Mar 19 16:43:29 pfSense dhcpd: DHCPACK on 192.168.122.113 to e0:37:17:6b:c1:39 via vmx1
Mar 19 19:29:19 pfSense dhcpd: DHCPACK on 192.168.122.113 to e0:37:17:6b:c1:39 via vmx1
Mar 19 08:12:18 pfSense dhcpd: DHCPACK on 192.168.122.113 to e0:37:17:6b:c1:39 via vmx1
Mar 19 11:04:42 pfSense dhcpd: DHCPACK on 192.168.122.113 to e0:37:17:6b:c1:39 via vmx1
```

或者，更进一步地缩小范围，收集当天使用该 IP 地址的 MAC 地址，执行以下命令：

```
$ cat dhcpd.log | grep 192.168.122.113 | grep DHCPACK | grep "Mar 19" | cut -d " " -f 10 | sort | uniq
e0:37:17:6b:c1:39
```

现在我们有了从租约表和日志中提取 MAC 地址的工具，您可以在故障排除、更新库存或查找网络中的超出库存或“意外”主机时使用这些方法。我们将在本章的问答部分进一步探讨故障排除序列。

# 总结

通过讨论 DHCP 的内容，您现在应该有工具来为您的组织构建基本的 DHCP 服务器，无论是用于本地子网还是远程子网。您还应该能够实施基本的安全措施，以防止流氓 DHCP 服务器在您的网络上运行。从活动租约表和 DHCP 日志中提取基本数据应该是您组织工具包的一部分。

综合起来，这应该涵盖大多数组织在安装、配置和故障排除方面的需求，以及在库存输入和事件响应方面使用 DHCP。

在下一章中，我们将继续向我们的 Linux 主机添加核心网络服务。我们旅程的下一步将是使用**公钥基础设施**（**PKI**）-使用私人和公共证书颁发机构和证书来帮助保护我们的基础设施。

# 问题

最后，这里是一些问题列表，供您测试对本章材料的了解。您将在*附录*的*评估*部分找到答案：

1.  现在是星期一，一个远程销售办事处刚刚打电话给 Helpdesk 说他们没有获得 DHCP 地址。您将如何排除故障？

1.  您的工程部门没有网络访问权限，但您仍然可以访问子网。您将如何确定这是否与流氓 DHCP 服务器有关，如果是，您将如何找到该流氓设备？

# 进一步阅读

要了解更多关于这个主题的内容：

+   DHCP 监听和信任配置：

[`isc.sans.edu/forums/diary/Layer+2+Network+Protections+against+Man+in+the+Middle+Attacks/7567/`](https://isc.sans.edu/forums/diary/Layer+2+Network+Protections+against+Man+in+the+Middle+Attacks/7567/%20)

+   WPAD 攻击：

https://nakedsecurity.sophos.com/2016/05/25/when-domain-names-attack-the-wpad-name-collision-vulnerability/

https://us-cert.cisa.gov/ncas/alerts/TA16-144A

https://blogs.msdn.microsoft.com/ieinternals/2012/06/05/the-intranet-zone/

+   DHCP 和 DHCP 选项 RFC；还有关于 DHCP 选项的 IANA 参考：

动态主机配置协议：https://tools.ietf.org/html/rfc2131

DHCP 选项和**引导协议**（**BOOTP**）供应商扩展：https://tools.ietf.org/html/rfc2132

用于动态主机配置协议版本 4（DHCPv4）的供应商标识供应商选项：https://tools.ietf.org/html/rfc3925

DHCP 和 BOOTP 参数：https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml


# 第八章：Linux 上的证书服务

在本章中，我们将涵盖几个涉及在 Linux 中使用证书来保护或加密流量，并特别是配置和使用各种**证书颁发机构**（**CA**）服务器的主题。

我们将介绍这些证书的基本用途，然后继续构建证书服务器。最后，我们将讨论围绕证书服务的安全考虑，无论是在保护 CA 基础设施还是使用**证书透明度**（**CT**）来强制信任模型，以及在组织内进行清单/审计或侦察。

在本章中，我们将涵盖以下主题：

+   证书是什么？

+   获取证书

+   使用证书-Web 服务器示例

+   构建私有证书颁发机构

+   保护您的证书颁发机构基础设施

+   证书透明度

+   证书自动化和**自动证书管理环境**（**ACME**）协议

+   `OpenSSL`速查表

当我们完成本章时，您将在 Linux 主机上拥有一个可用的私有 CA，并且对证书的发放方式以及如何管理和保护您的 CA 都有一个很好的理解，无论您是在实验室还是生产环境中使用它。您还将对标准证书握手的工作原理有很好的理解。

让我们开始吧！

# 技术要求

在本章中，我们可以继续使用同一台 Ubuntu **虚拟机**（**VM**）或工作站，因为这是一个学习练习。即使在我们既是 CA 又是证书申请人的部分，本节中的示例也都可以在这一台主机上完成。

鉴于我们正在构建证书服务器，如果您正在使用此指南来帮助构建生产主机，强烈建议您在单独的主机或虚拟机上构建。虚拟机是生产服务的首选-请阅读“保护您的 CA 基础设施”部分，了解更多建议。

# 证书是什么？

证书本质上是*真相的证明* - 换句话说，证书是一份声明，“相信我，这是真的”。这听起来很简单，某种程度上确实如此。但在其他方面，证书的各种用途以及安全地部署 CA 基础设施是一个重大挑战-例如，我们在最近几年看到了一些公共 CA 的惊人失败：那些唯一业务是保护证书流程的公司在受到审查时却无法做到。我们将在本章后面的*保护您的 CA 基础设施*和*CT*部分更详细地介绍保护 CA 的挑战和解决方案。

从根本上讲，工作站和服务器都信任一系列 CA。这种信任是通过使用加密签名的文档来传递的，这些文档是每个 CA 的公共证书，存储在 Linux 或 Windows 主机的特定位置上。

例如，当您浏览到一个 Web 服务器时，本地的*证书存储*会被引用，以查看我们是否应该信任 Web 服务器的证书。这是通过查看该 Web 服务器的公共证书，并查看它是否由您信任的 CA 之一（或其下属）签名而完成的。实际签名使用*子*或*下属* CA 是常见的-每个公共 CA 都希望尽可能保护其*根* CA，因此创建了*下属 CA*或*颁发 CA*，这些是公共互联网所见的。

组织可以创建自己的 CA，用于验证其用户、服务器、工作站和网络基础设施之间的身份和授权。这使得信任保持在“家庭”内，完全受到组织的控制。这也意味着组织可以使用内部和免费的证书服务，而不必为数百或数千个工作站或用户证书付费。

现在我们知道了证书是什么，让我们看看它们是如何颁发的。

# 获取证书

在下图中，一个应用程序 - 例如，一个 Web 服务器 - 需要一个证书。这个图看起来复杂，但我们将把它分解成简单的步骤：

![图 8.1 - 证书签名请求（CSR）和颁发证书](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_08_001.jpg)

图 8.1 - 证书签名请求（CSR）和颁发证书

让我们逐步了解创建证书涉及的步骤，从最初的请求到准备在目标应用程序中安装证书（*步骤 1-6*），如下所示：

1.  该过程从创建 CSR 开始。这只是一个简短的文本文件，用于标识请求证书的服务器/服务和组织。这个文件在加密时被“混淆” - 虽然字段是标准化的，只是文本，但最终结果不是人类可读的。然而，诸如 OpenSSL 之类的工具可以读取 CSR 文件和证书本身（如果需要示例，请参见本章末尾的*OpenSSL 备忘单*部分）。CSR 的文本信息包括这些标准字段的一些或全部：![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_08_Table_01.jpg)

上述列表并非 CSR 中可以使用的字段的详尽列表，但这些是最常见的字段。

我们需要所有这些信息的原因是，当客户端连接到使用证书的服务时（例如，使用**超文本传输安全协议**（**HTTPS**）和**传输层安全**（**TLS**）的 Web 服务器），客户端可以验证连接到的服务器名称是否与 CN 字段或其中一个 SAN 条目匹配。

这使得 CA 操作员验证这些信息变得很重要。对于面向公众的证书，操作员/供应商通过验证公司名称、电子邮件等信息来完成这一过程。自动化解决方案通过验证您对域或主机具有管理控制权来实现这一点。

1.  仍然遵循*图 8.1*，接下来将这些文本信息与申请人的公钥加密组合，形成`CSR`文件。

1.  现在完成的 CSR 被发送到 CA。当 CA 是公共 CA 时，通常通过网站完成。自动化的公共 CA（如**Let's Encrypt**）通常使用 ACME **应用程序编程接口**（**API**）在申请人和 CA 之间进行通信。在高风险的实施中，*步骤 3*和*6*可能使用安全媒体，通过正式的*保管链*程序在受信任的各方之间物理交接。重要的是申请人和 CA 之间的通信使用一些安全的方法。虽然可能存在较不安全的方法，如电子邮件，但不建议使用。

1.  在 CA 处，身份信息（我们仍然遵循*图 8.1*中的信息流）得到验证。这可能是一个自动化或手动的过程，取决于几个因素。例如，如果这是一个公共 CA，您可能已经有一个帐户，这将使半自动化检查更有可能。如果您没有帐户，这个检查很可能是手动的。对于私人 CA，这个过程可能是完全自动化的。

1.  一旦验证，验证的 CSR 将与 CA 的私钥加密组合，创建最终的证书。

1.  然后将此证书发送回申请人，并准备安装到将使用该证书的应用程序中。

请注意，在此交易中，申请人的私钥从未被使用 - 我们将在 TLS 密钥交换中看到它在哪里使用（在本章的下一节）。

现在我们了解了证书是如何创建或发布的，应用程序如何使用证书来信任服务或加密会话流量呢？让我们看看浏览器和受 TLS 保护的网站之间的交互，以了解这是如何工作的。

# 使用证书 - Web 服务器示例

当被问及时，大多数人会说证书最常见的用途是使用 HTTPS 协议保护网站。虽然这可能不是当今互联网上证书最常见的用途，但它确实仍然是最显眼的。让我们讨论一下 Web 服务器的证书如何用于在服务器中提供信任并帮助建立加密的 HTTPS 会话。

如果你还记得我们 CSR 示例中的*申请人*，在这个例子中，申请人是[www.example.com](http://www.example.com)这个网站，可能驻留在 Web 服务器上。我们将从上一个会话结束的地方开始我们的例子——证书已经颁发并安装在 Web 服务器上，准备好接受客户端连接。

**步骤 1**：客户端向 Web 服务器发出初始的 HTTPS 请求，称为**客户端 HELLO**（*图 8.2*）。

在这个初始的*Hello*交换中，客户端向服务器发送以下内容：

+   它支持的 TLS 版本

+   它支持的加密密码

这个过程在下面的图表中有所说明：

![图 8.2 – TLS 通信从客户端 hello 开始](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_08_002.jpg)

图 8.2 – TLS 通信从客户端 hello 开始

Web 服务器通过发送其证书进行回复。如果你还记得，证书包含几个信息。

**步骤 2**：Web 服务器通过发送其证书（*图 8.3*）进行回复。如果你还记得，证书包含以下几个信息：

+   陈述服务器身份的文本信息

+   Web 服务器/服务的公钥

+   CA 的身份

服务器还发送以下内容：

+   支持的 TLS 版本

+   它在密码中的第一个提议（通常是服务器支持的客户端列表中最高强度的密码）

这个过程在下面的图表中有所说明：

![图 8.3 – TLS 交换：服务器 hello 被发送并由客户端验证](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_08_003.jpg)

图 8.3 – TLS 交换：服务器 hello 被发送并由客户端验证

**步骤 3**：客户端接收此证书和其他信息（称为服务器 hello），然后（如*图 8.4*中所示）验证一些信息，如下所示：

+   我刚刚收到的证书中是否包含我请求的服务器的身份（通常会在 CN 字段或 SAN 字段中）？

+   今天的日期/时间是否在证书的*之后*和*之前*日期之间（也就是说，证书是否已过期）？

+   我信任 CA 吗？它将通过查看其证书存储来验证这一点，其中通常包含几个 CA 的公共证书（几个公共 CA，通常还有一个或多个在组织内部使用的私有 CA）。

+   客户端还有机会通过向**在线证书状态协议**（**OCSP**）服务器发送请求来检查证书是否已被吊销。检查**证书吊销列表**（**CRL**）的旧方法仍然受到支持，但不再经常使用——这个列表被证明在成千上万的吊销证书中不太适用。在现代实现中，CRL 通常由已吊销的公共 CA 证书组成，而不是常规服务器证书。

+   *信任*和*吊销*检查非常重要。这些检查验证服务器是否是其所声称的。如果这些检查没有进行，那么任何人都可以建立一个声称是你的银行的服务器，你的浏览器就会让你登录到这些恶意服务器上。现代网络钓鱼活动经常试图通过*相似域*和其他方法来*欺骗系统*，让你做这样的事情。

**步骤 4**：如果证书在客户端通过了所有检查，客户端将生成一个伪随机对称密钥（称为预主密钥）。这个密钥使用服务器的公钥加密并发送给服务器（如*图 8.4*所示）。这个密钥将用于加密实际的 TLS 会话。

在这一点上，客户端被允许修改密码。最终密码是客户端和服务器之间的协商-请记住这一点，因为当我们讨论攻击和防御时，我们将深入探讨这一点。长话短说-客户端通常不会更改密码，因为服务器已经选择了来自客户端列表的密码。

该过程在以下图表中说明：

![图 8.4 - 客户端密钥交换，服务器有最后一次机会更改密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_08_004.jpg)

图 8.4 - 客户端密钥交换，服务器有最后一次机会更改密码

**步骤 5**：在这一步之后，服务器也有最后一次更改密码的机会（仍在*图 8.4*中）。这一步通常不会发生，密码协商通常已经完成。预主密钥现在已经最终确定，并称为主密钥。

**步骤 6**：现在证书验证已经完成，密码和对称密钥都已经达成一致，通信可以继续进行。加密是使用上一步的对称密钥进行的。

这在以下图表中说明：

![图 8.5 - 协商完成，通信使用主密钥（密钥）进行加密进行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_08_005.jpg)

图 8.5 - 协商完成，通信使用主密钥（密钥）进行加密进行

在这种交换中有两个重要的事情暗示但尚未明确说明，如下：

+   一旦协商完成，证书将不再使用-加密将使用协商的主密钥进行。

+   在正常的协商过程中，不需要 CA。当我们开始讨论保护组织的 CA 基础设施时，这将成为一个重要的观点。

现在我们对证书的工作原理有了更好的理解（至少在这个用例中），让我们为我们的组织构建一个基于 Linux 的 CA。我们将以几种不同的方式进行此操作，以便为您的组织提供一些选项。我们还将在下一章[*第九章*]（B16336_09_Final_NM_ePub.xhtml#_idTextAnchor153），*Linux 的 RADIUS 服务*中使用 CA，因此这是一组重要的示例，需要密切关注。

# 构建私有证书颁发机构

构建私有 CA 始于我们面临的每个基础设施包的相同决定：*我们应该使用哪个 CA 包？*与许多服务器解决方案一样，有几种选择。以下概述了一些选项：

+   **OpenSSL**在技术上为我们提供了编写自己的脚本和维护**公钥基础设施**（**PKI**）位和片段的目录结构的所有工具。您可以创建根和从属 CA，制作 CSR，然后签署这些证书以制作真正的证书。实际上，虽然这种方法得到了普遍支持，但对大多数人来说，它最终变得有点太过于手动化。

+   **证书管理器**是与 Red Hat Linux 和相关发行版捆绑在一起的 CA。

+   **openSUSE**和相关发行版可以使用本机**另一种设置工具**（**YaST**）配置和管理工具作为 CA。

+   **Easy-RSA**是一组脚本，本质上是对相同的 OpenSSL 命令的包装。

+   **Smallstep**实现更多自动化-它可以配置为私有 ACME 服务器，并且可以轻松允许您的客户请求和履行其自己的证书。

+   `LetsEncrypt` GitHub 页面并用 Go 编写。

正如您所看到的，有相当多的 CA 包可供选择。大多数较旧的包都是对各种 OpenSSL 命令的包装。较新的包具有额外的自动化功能，特别是围绕 ACME 协议，这是由`LetsEncrypt`首创的。先前提到的每个包的文档链接都在本章的*进一步阅读*列表中。作为最广泛部署的 Linux CA，我们将使用 OpenSSL 构建我们的示例 CA 服务器。

## 使用 OpenSSL 构建 CA

因为我们只使用几乎每个 Linux 发行版都包含的命令，所以在开始使用此方法构建我们的 CA 之前，无需安装任何内容。

让我们按照以下步骤开始这个过程：

1.  首先，我们将为 CA 创建一个位置。`/etc/ssl`目录应该已经存在于您的主机文件结构中，我们将通过运行以下代码向其中添加两个新目录：

```
$ sudo mkdir /etc/ssl/CA
$ sudo mkdir /etc/ssl/newcerts
```

1.  接下来，请记住，随着证书的发放，CA 需要跟踪序列号（通常是顺序的），以及关于每个证书的一些详细信息。让我们在`serial`文件中开始序列号，从`1`开始，并创建一个空的`index`文件来进一步跟踪证书，如下所示：

```
sudo syntax when creating a serial file. This is needed because if you just use sudo against the echo command, you don't have rights under the /etc directory. What this syntax does is start a sh temporary shell and pass the character string in quotes to execute using the -c parameter. This is equivalent to running sudo sh or su, executing the command, and then exiting back to the regular user context. However, using sudo sh –c is far preferable to these other methods, as it removes the temptation to stay in the root context. Staying in the root context brings with it all kinds of opportunities to mistakenly and permanently change things on the system that you didn't intend—anything from accidentally deleting a critical file (which only root has access to), right up to—and including—mistakenly installing malware, or allowing ransomware or other malware to run as root.
```

1.  接下来，我们将编辑现有的`/etc/ssl/openssl.cnf`配置文件，并导航到`[CA_default]`部分。默认文件中的此部分如下所示：

```
private_key line, but be sure to double-check it for correctness while you are in the file.
```

1.  接下来，我们将创建一个自签名的根证书。这对于私有 CA 的根是正常的。（在公共 CA 中，您将创建一个新的 CSR 并让另一个 CA 对其进行签名，以提供对受信任根的*链*。）

由于这是一个组织的内部 CA，我们通常会选择一个很长的寿命，这样我们就不必每一两年重建整个 CA 基础设施。让我们选择 10 年（3,650 天）。请注意，此命令要求输入密码（不要丢失！）以及其他将标识证书的信息。请注意在以下代码片段中，`openssl`命令一步创建了 CA（`cakey.pem`）和根证书（`cacert.pem`）的私钥。在提示时，请使用您自己的主机和公司信息填写请求的值：

```
$ openssl req -new -x509 -extensions v3_ca -keyout cakey.pem -out cacert.pem -days 3650
Generating a RSA private key
...............+++++
.................................................+++++
writing new private key to 'cakey.pem'
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:CA
State or Province Name (full name) [Some-State]:ON
Locality Name (eg, city) []:MyCity
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Coherent Security
Organizational Unit Name (eg, section) []:IT
Common Name (e.g. server FQDN or YOUR name) []:ca01.coherentsecurity.com
Email Address []:
```

1.  在最后一步中，我们将密钥和根证书移动到正确的位置。请注意，您需要再次拥有`sudo`权限才能执行此操作。

```
mv command. In security engagements, it's common to find certificates and keys stored in all sorts of temporary or archive locations—needless to say, if an attacker is able to obtain the root certificate and private key for your certificate server, all sorts of shenanigans can result!
```

您的 CA 现在已经开业！让我们继续创建 CSR 并对其进行签名。

## 请求和签署 CSR

让我们创建一个测试 CSR——您可以在我们一直在使用的相同示例主机上执行此操作。首先，为此证书创建一个私钥，如下所示：

```
$ openssl genrsa -des3 -out server.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
...............................................+++++
........................+++++
e is 65537 (0x010001)
Enter pass phrase for server.key:
Verifying - Enter pass phrase for server.key:
```

请记住该密码，因为在安装证书时将需要它！还要注意，该密钥具有`2048`位模数——这是您应该期望在此目的上看到或使用的最小值。

证书密钥的密码非常重要且非常敏感，您应该将它们存储在安全的地方——例如，如果您计划在证书到期时（或者希望在此之前）更新该证书，您将需要该密码来完成该过程。我建议不要将其保存在纯文本文件中，而是建议使用密码保险库或密码管理器来存储这些重要的密码。

请注意，许多守护程序样式的服务将需要没有密码的密钥和证书（例如 Apache Web 服务器、Postfix 和许多其他服务），以便在没有干预的情况下自动启动。如果您为这样的服务创建密钥，我们将去除密码以创建一个*不安全的密钥*，如下所示：

```
$ openssl rsa -in server.key -out server.key.insecure
Enter pass phrase for server.key:
writing RSA key
```

现在，让我们重命名密钥——`server.key`的*安全*密钥变为`server.key.secure`，而`server.key.insecure`的*不安全*密钥变为`server.key`，如下面的代码片段所示：

```
$ mv server.key server.key.secure
$ mv server.key.insecure server.key
```

无论我们创建哪种类型的密钥（带有或不带有密码），最终文件都是`server.key`。使用此密钥，我们现在可以创建 CSR。此步骤需要另一个密码，该密码将用于签署 CSR，如下面的代码片段所示：

```
~$ openssl req -new -key server.key -out server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:CA
State or Province Name (full name) [Some-State]:ON
Locality Name (eg, city) []:MyCity
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Coherent Security
Organizational Unit Name (eg, section) []:IT
Common Name (e.g. server FQDN or YOUR name) []:www.coherentsecurity.com
Email Address []:
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:passphrase
An optional company name []:
```

现在我们在`server.csr`文件中有了 CSR，它已经准备好被签名。在证书服务器上（对我们来说恰好是同一台主机，但这不是典型的情况），使用以下命令对`CSR`文件进行签名：

```
$ sudo openssl ca -in server.csr -config /etc/ssl/openssl.cnf
```

这将生成几页输出（未显示）并要求确认几次。其中一个确认将是我们在之前创建 CSR 时提供的密码。当一切都说完了，你会看到实际的证书在输出的最后一部分滚动显示。你还会注意到，由于我们没有指定任何日期，证书从现在开始有效，并且设置在一年后过期。

我们刚刚签署的证书存储在`/etc/ssl/newcerts/01.pem`中，如下面的代码片段所示，并且应该准备好供请求服务使用：

```
$ ls /etc/ssl/newcerts/
01.pem
```

随着我们的进展，颁发的证书将递增到`02.pem`，`03.pem`等等。

请注意在下面的代码片段中，`index`文件已经更新了证书的详细信息，`序列号`文件已经递增，准备好下一个签名请求：

```
$ cat /etc/ssl/CA/index.txt
V       220415165738Z           01      unknown /C=CA/ST=ON/O=Coherent Security/OU=IT/CN=www.coherentsecurity.com
$ cat /etc/ssl/CA/serial
02
```

完成了一个 CA 示例并且使用了一个测试证书，让我们看看如何保护你的 CA 基础设施。

# 保护你的证书颁发机构基础设施

通常建议采取一些最佳实践来保护你的 CA。一些“传统”的建议是针对个别 CA 的，但随着虚拟化在大多数数据中心变得普遍，这带来了额外的机会来简化和保护 CA 基础设施。

## 传统的经过验证的建议

传统的建议是为了保护组织的证书基础设施，利用它只在颁发证书时使用的事实。如果你能很好地掌握新证书需求的时间，那么在不需要时可以关闭 CA 服务器。

如果你需要更灵活性，可以创建一个分级证书基础设施。为你的组织创建一个根 CA，它的唯一工作是签署用于创建下级 CA（或可能是多个下级 CA）的证书。然后使用这些下级 CA 来创建所有客户端和服务器证书。根 CA 可以在不需要时关闭或以其他方式下线，除了打补丁。

如果一个组织特别关心保护他们的 CA，可以使用专用硬件，比如硬件安全模块（HSM）来存储他们的 CA 的私钥和证书，通常是在保险箱或其他离线、安全的地方。HSM 的商业示例包括 Nitrokey HSM 或 YubiHSM。NetHSM 是开源 HSM 的一个很好的例子。

## 现代建议

前面的建议仍然完全有效。我们在现代基础设施中看到有助于保护我们的 CA 的新要素是服务器虚拟化。在大多数环境中，这意味着每台服务器都有一个或多个镜像备份存储在本地磁盘上，因为 VM 是如何备份的。因此，如果主机受到无法修复的损坏，无论是来自恶意软件（通常是勒索软件）还是一些严重的配置错误，只需要大约 5 分钟的时间就可以将整个服务器回滚到前一天的镜像，或者在最坏的情况下，回滚到两天前的镜像。

在这种恢复中丢失的一切将是在那个*丢失*间隔中颁发的任何证书的服务器数据，如果我们再次回顾一下会话是如何协商的，那么服务器数据实际上从未在建立会话时使用。这意味着服务器为恢复所花费的这段*时光旅行*不会影响任何使用颁发的证书进行加密协商的客户端或服务器（或者认证，当我们到达*第九章*，*Linux 的 RADIUS 服务*时我们会看到）。

在较小的环境中，根据情况，你可以只使用一个 CA 服务器轻松地保护你的基础设施——只需保留镜像备份，这样如果需要恢复，那个逐字节的镜像是可用的，并且可以在几分钟内回滚。

在更大的环境中，为您的 CA 基础设施建立一个分层模型仍然是有意义的——例如，这可以使合并和收购变得更加容易。分层模型有助于将基础设施保持为一个单一组织，同时使得更容易将多个业务单元的 CA 连接到一个主服务器下。然后，您可以使用**操作系统**（**OS**）的安全性来限制在某个部门发生恶意软件事件时的*扩散区域*；或者在日常模型中，如果需要，您可以使用相同的操作系统安全性来限制业务单元之间的证书管理访问。

依赖镜像备份来保护您的 CA 基础设施的主要风险在于 CA 服务器的传统用法——在某些环境中，可能只偶尔需要证书。例如，如果您在本地保留了一周的服务器镜像备份，但需要一个月（或几个月）才意识到您应用的脚本或补丁已经使您的 CA 服务器崩溃，那么从备份中恢复可能会变得棘手。这可以通过更广泛地使用证书（例如，在对无线客户端进行身份验证以连接到无线网络时）以及自动证书颁发解决方案（例如 Certbot 和 ACME 协议（由 Let's Encrypt 平台开创））来解决。这些事情，特别是结合起来，意味着 CA 的使用频率越来越高，以至于如果 CA 服务器无法正常运行，情况现在可能会在几小时或几天内升级，而不是几周或几个月内。

## 现代基础设施中的 CA 特定风险

*证书颁发机构*或*CA*不是在派对上随意谈论的术语，甚至在工作的休息室里也不会出现。这意味着，如果您给您的 CA 服务器命名为`ORGNAME-CA01`，虽然名称中的`CA01`部分显然对您很重要，但不要指望主机名中的`CA`对其他人来说也很重要。例如，对于您的经理、程序员、在您度假时替您工作的人，或者因某种原因拥有超级用户密码的暑期学生来说，这很可能不会引起注意。如果您是顾问，可能没有人实际在组织中知道 CA 的作用。

这意味着，特别是在虚拟化基础设施中，我们经常会看到 CA 虚拟机被（某种程度上）意外删除。这种情况发生的频率足够高，以至于当我构建一个新的 CA 虚拟机时，我通常会将其命名为`ORGNAME-CA01 – 不要删除，联系 RV`，其中`RV`代表拥有该服务器的管理员的缩写（在这种情况下，是我）。

当任何服务器虚拟机被删除时，设立警报可能是个明智的选择，通知管理团队的任何人——这将为您提供另一层防御，或者至少及时通知，以便您可以快速恢复。

最后，在您的虚拟化基础设施上实施**基于角色的访问控制**（**RBAC**）是每个人的最佳实践清单上的事项。任何特定服务器的直接管理员应该能够删除、重新配置或更改该服务器的电源状态。这种控制级别在现代虚拟化器中很容易配置（例如，VMware 的 vSphere）。这至少使意外删除虚拟机变得更加困难。

现在我们已经制定了一些安全实践来保护我们的 CA，让我们从攻击者和基础设施防御者的角度来看看 CT。

# 证书透明性

回顾本章的开头段落，回想一下 CA 的主要*工作*之一是*信任*。无论是公共 CA 还是私人 CA，您都必须信任 CA 来验证请求证书的人是否是他们所说的那个人。如果这个检查失败，那么任何想要代表[yourbank.com](http://yourbank.com)的人都可以请求该证书，并假装是你的银行！在当今以网络为中心的经济中，这将是灾难性的。

当这种信任失败时，各种 CA、浏览器团队（尤其是 Mozilla、Chrome 和 Microsoft）以及操作系统供应商（主要是 Linux 和 Microsoft）将简单地从各种操作系统和浏览器证书存储中删除违规的 CA。这基本上将由该 CA 签发的所有证书移至*不受信任*类别，迫使所有这些服务从其他地方获取证书。这在最近的过去发生过几次。

DigiNotar 在遭到破坏后被删除，攻击者控制了其一些关键基础设施。一个欺诈的`*.`[google.com](http://google.com)——请注意，`*`是使这个证书成为通配符，可以用来保护或冒充该域中的任何主机。不仅是那个欺诈的通配符被签发了，它还被用来拦截真实的流量。不用说，每个人对此都持负面看法。

在 2009 年至 2015 年期间，赛门铁克 CA 签发了许多**测试证书**，包括属于谷歌和 Opera（另一个浏览器）的域。当这一事件曝光后，赛门铁克受到了越来越严格的限制。最终，赛门铁克的工作人员反复跳过了验证重要证书的步骤，该 CA 最终在 2018 年被删除。

为了帮助检测这种类型的事件，公共 CA 现在参与**证书透明度**（**CT**），如**请求评论**（**RFC**）*6962*中所述。这意味着当证书被签发时，该 CA 会将有关证书的信息发布到其 CT 服务中。这个过程对于所有用于**安全套接字层**（**SSL**）/TLS 的证书是强制性的。这个程序意味着任何组织都可以检查（或更正式地说，审计）它购买的证书的注册表。更重要的是，它可以检查/审计它*没有*购买的证书的注册表。让我们看看这在实践中是如何运作的。

## 使用 CT 进行库存或侦察

正如我们讨论过的，CT 服务存在的主要原因是通过允许任何人验证或正式审计已签发的证书来确保对公共 CA 的信任。

然而，除此之外，组织可以查询 CT 服务，看看是否有为他们公司购买的合法证书，而这些证书是由不应该从事服务器业务的人购买的。例如，市场团队建立了一个与云服务提供商合作的服务器，绕过了可能已经讨论过的所有安全和成本控制，如果**信息技术**（**IT**）组为他们代建服务器的话。这种情况通常被称为*影子 IT*，即非 IT 部门决定用他们的信用卡去做一些并行的、通常安全性较差的服务器，而*真正的*IT 组通常直到为时已晚才发现。

或者，在安全评估或渗透测试的情境中，找到客户的所有资产是谜题的关键部分——你只能评估你能找到的东西。使用 CT 服务将找到为公司颁发的所有 SSL/TLS 证书，包括测试、开发和质量保证（QA）服务器的任何证书。测试和开发服务器通常是最不安全的，而且这些服务器通常为渗透测试人员提供了一个开放的入口。很多时候，这些开发服务器包含了生产数据库的最新副本，因此在许多情况下，入侵开发环境就等于完全入侵。不用说，真正的攻击者也使用这些方法来找到这些同样脆弱的资产。这也意味着在这种情况下的蓝队（IT 组中的防御者）应该经常检查诸如 CT 服务器之类的东西。

话虽如此，您究竟如何检查 CT 呢？让我们使用[`crt.sh`](https://crt.sh)上的服务器，并搜索颁发给`example.com`的证书。要做到这一点，请浏览[`crt.sh/?q=example.com`](https://crt.sh/?q=example.com)（如果您感兴趣，也可以使用您的公司域名）。

请注意，因为这是一个完整的审计跟踪，这些证书通常会回溯到 2013-2014 年 CT 仍处于实验阶段的时候！这可以成为一个很好的侦察工具，可以帮助您找到已过期证书或现在受到通配符证书保护的主机。旧的`*.example.com`（或`*.yourorganisation.com`）。这些证书旨在保护指定父域下的任何主机（由`*`指示）。使用通配符的风险在于，如果适当的材料被盗，可能来自一个脆弱的服务器，域中的任何或所有主机都可以被冒充——这当然是灾难性的！另一方面，购买了三到五个单独的证书之后，将它们全部合并为一个通配符证书变得具有成本效益，而且更重要的是，只有一个到期日期需要跟踪。一个附带的好处是使用通配符证书意味着使用 CT 进行侦察对攻击者来说变得不那么有效。然而，防御者仍然可以看到欺诈证书，或者其他部门购买并正在使用的证书。

在本章中，我们涵盖了很多内容。现在我们对现代基础设施中证书的位置有了牢固的掌握，让我们探讨如何使用现代应用程序和协议来自动化整个证书过程。

# 证书自动化和 ACME 协议

近年来，CA 的自动化得到了一些严重的推广。特别是 Let's Encrypt 通过提供免费的公共证书服务推动了这一变化。他们通过使用自动化，特别是使用 ACME 协议（RFC 8737/RFC 8555）和 Certbot 服务来验证 CSR 信息，以及颁发和交付证书，降低了这项服务的成本。在很大程度上，这项服务和协议侧重于为 Web 服务器提供自动化证书，但正在扩展到其他用例。

Smallstep 等实现使用 ACME 协议来自动化和颁发证书请求，已将这一概念扩展到包括以下内容：

+   使用身份令牌进行身份验证的开放授权（OAuth）/OpenID Connect（OIDC）配置，允许 G Suite、Okta、Azure Active Directory（Azure AD）和任何其他 OAuth 提供商进行单点登录（SSO）集成

+   使用来自 Amazon Web Services（AWS）、Google Cloud Platform（GCP）或 Azure 的 API 进行 API 配置

+   **JavaScript 对象表示法（JSON）Web 密钥**（**JWK**）和**JSON Web 令牌**（**JWT**）集成，允许一次性令牌用于身份验证或利用后续证书颁发

由于使用 ACME 协议颁发的证书通常是免费的，它们也是恶意行为者的主要目标。例如，恶意软件经常利用 Let's Encrypt 提供的免费证书来加密**命令和控制**（**C2**）操作或数据外泄。即使对于 Smallstep 等内部 ACME 服务器，对细节的疏忽也可能意味着恶意行为者能够破坏组织中的所有加密。因此，基于 ACME 的服务器通常只颁发短期证书，并且自动化将通过完全消除增加的管理开销来“弥补不足”。Let's Encrypt 是使用 ACME 的最知名的公共 CA，其证书有效期为 90 天。Smallstep 则采取极端措施，默认证书有效期为 24 小时。请注意，24 小时的到期时间是极端的，这可能会严重影响可能每天不在内部网络上的移动工作站，因此通常会设置更长的间隔。

在 ACME 之前，**简单证书注册协议**（**SCEP**）用于自动化，特别是用于提供机器证书。SCEP 仍然广泛用于**移动设备管理**（**MDM**）产品，以向移动电话和其他移动设备提供企业证书。SCEP 在 Microsoft 的**网络设备注册服务**（**NDES**）组件中仍然被广泛使用，在其基于**Active Directory**（**AD**）的证书服务中也是如此。

说到微软，他们的免费证书服务会自动注册工作站和用户证书，都受到组策略控制。这意味着随着工作站和用户自动化身份验证要求的增加，微软 CA 服务的使用似乎也在增加。

基于 Linux 的 CA 服务的整体趋势是尽可能自动化证书的颁发。然而，底层的证书原则与本章讨论的完全相同。随着这一趋势中的*赢家*开始出现，您应该掌握工具，以了解在您的环境中任何 CA 应该如何工作，无论使用的是前端还是自动化方法。

随着自动化的完成，我们已经涵盖了您在现代基础设施中看到的主要证书操作和配置。然而，在结束这个话题之前，通常有一个简短的“食谱式”命令集是很有用的，用于证书操作。由于 OpenSSL 是我们的主要工具，我们已经整理了一份常见命令的列表，希望这些命令能够使这些复杂的操作更简单完成。

# OpenSSL 备忘单

要开始本节，让我说一下，这涵盖了本章中使用的命令，以及您可能在检查、请求和颁发证书时使用的许多命令。还演示了一些远程调试命令。OpenSSL 有数百个选项，因此像往常一样，man 页面是您更全面地探索其功能的朋友。在紧要关头，如果您搜索`OpenSSL` `cheat sheet`，您会发现数百页显示常见 OpenSSL 命令的页面。

以下是在证书创建中常见的一些步骤和命令：

+   要为新证书（申请人）创建私钥，请运行以下命令：

```
openssl genrsa -des3 -out private.key <bits>
```

+   要为新证书（申请人）创建 CSR，请运行以下命令：

```
openssl req -new -key private.key -out server.csr
```

+   要验证 CSR 签名，请运行以下命令：

```
openssl req -in example.csr -verify
```

+   要检查 CSR 内容，请运行以下命令：

```
openssl req -in server.csr -noout -text
```

+   要签署 CSR（在 CA 服务器上），请运行以下命令：

```
sudo openssl ca -in server.csr -config <path to configuration file>
```

+   创建自签名证书（通常不是最佳做法），运行以下命令：

```
openssl req -x509 -sha256 -nodes -days <days>  -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
```

以下是在检查证书状态时使用的一些命令：

+   要检查标准的`x.509`证书文件，请运行以下命令：

```
openssl x509 -in certificate.crt -text –noout
```

+   要检查`PKCS#12`文件（这将证书和私钥合并为一个文件，通常带有`pfx`或`p12`后缀），运行以下命令：

```
openssl pkcs12 -info -in certpluskey.pfx
```

+   要检查私钥，请运行以下命令：

```
openssl rsa -check -in example.key
```

以下是远程调试证书中常用的一些命令：

+   要检查远程服务器上的证书，请运行以下命令：

```
openssl s_client -connect <servername_or_ip>:443
```

+   使用 OCSP 协议检查证书吊销状态（请注意，这是一个过程，因此我们已编号了步骤），请按以下步骤进行：

1.  首先，收集公共证书并去除`BEGIN`和`END`行，如下所示：

```
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > publiccert.pem
```

1.  接下来，检查证书中是否有 OCSP**统一资源标识符**（**URI**），如下所示：

```
openssl x509 -noout -ocsp_uri -in publiccert.pem http://ocsp.ca-ocspuri.com
```

1.  如果有，您可以在此时发出请求，如下所示：

```
http://ocsp.ca-ocspuri.com is the URI of the issuing CA's OCSP server (previously found).
```

1.  如果公共证书中没有 URI，我们需要获取证书链（即到发行者的链），然后获取发行者的根 CA，如下所示：

```
openssl s_client -connect example.com443 -showcerts 2>&1 < /dev/null
```

1.  这通常会产生大量输出-要提取证书链到文件（在本例中为`chain.pem`），请运行以下命令：

```
openssl ocsp -issuer chain.pem -cert publiccert.pem -text -url http://ocsp.ca-ocspuri.com
```

以下是一些 OpenSSL 命令，用于在文件格式之间进行转换：

+   要转换`-----BEGIN CERTIFICATE-----`：

```
openssl x509 -outform der -in certificate.pem -out certificate.der
```

+   要将 DER 文件（`.crt`，`.cer`或`.der`）转换为 PEM 文件，请运行以下命令：

```
openssl x509 -inform der -in certificate.cer -out certificate.pem
```

+   要转换包含私钥和证书的`PKCS#12`文件（`.pfx`，`.p12`）为 PEM 文件，请运行以下命令：

```
openssl pkcs12 -in keyStore.pfx -out keyStore.pem –nodes
```

+   OpenSLL 命令也用于将 PEM 证书文件和私钥转换为`PKCS#12`（`.pfx`，`.p12`）。

如果服务需要身份证书，但在安装过程中没有 CSR 提供私钥信息，则通常需要`PKCS#12`格式文件。在这种情况下，使用**个人交换格式**（**PFX**）文件或**公钥密码标准#12**（**P12**）文件提供所需的所有信息（私钥和公共证书）在一个文件中。示例命令如下：

```
openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt
```

希望这本简短的“食谱”有助于揭秘证书操作，并简化阅读涉及您证书基础设施的各种文件。

# 总结

通过本讨论，您应该了解使用 OpenSSL 安装和配置证书服务器的基础知识。您还应该了解请求证书和签署证书所需的基本概念。不同 CA 实现中的基本概念和工具保持不变。您还应该了解用于检查证书材料或在远程服务器上调试证书的基本 OpenSSL 命令。

您还应该进一步了解保护您的证书基础设施所涉及的因素。这包括使用 CT 进行库存和侦察，无论是防御性还是进攻性。

在*第九章*，*Linux 的 RADIUS 服务*，我们将在此基础上添加 RADIUS 认证服务到我们的 Linux 主机。您将看到在更高级的配置中，RADIUS 可以使用您的证书基础设施来保护您的无线网络，证书将用于双向认证和加密。

# 问题

最后，这里是一些问题列表，供您测试对本章材料的了解。您将在*附录*的*评估*部分找到答案：

1.  证书在通信中发挥了哪两个功能？

1.  什么是`PKCS#12`格式，它可能在哪里使用？

1.  CT 为什么重要？

1.  为什么您的 CA 服务器跟踪已发行证书的详细信息很重要？

# 进一步阅读

要了解更多关于主题的信息，请参考以下材料：

+   Ubuntu 上的证书（特别是构建 CA）：[`ubuntu.com/server/docs/security-certificates`](https://ubuntu.com/server/docs/security-certificates)

+   OpenSSL 主页：[`www.openssl.org/`](https://www.openssl.org/)

+   *使用 OpenSSL 进行网络安全*: [`www.amazon.com/Network-Security-OpenSSL-John-Viega/dp/059600270X`](https://www.amazon.com/Network-Security-OpenSSL-John-Viega/dp/059600270X)

+   CT: [`certificate.transparency.dev`](https://certificate.transparency.dev)

+   在 OpenSUSE 上的 CA 操作（使用 YaST）：[`doc.opensuse.org/documentation/leap/archive/42.3/security/html/book.security/cha.security.yast_ca.html`](https://doc.opensuse.org/documentation/leap/archive/42.3/security/html/book.security/cha.security.yast_ca.html)

+   基于 Red Hat 的 CA 操作（使用证书管理器）：[`access.redhat.com/documentation/en-us/red_hat_certificate_system/9/html/planning_installation_and_deployment_guide/planning_how_to_deploy_rhcs`](https://access.redhat.com/documentation/en-us/red_hat_certificate_system/9/html/planning_installation_and_deployment_guide/planning_how_to_deploy_rhcs)

+   Easy-RSA：[`github.com/OpenVPN/easy-rsa`](https://github.com/OpenVPN/easy-rsa)

+   支持 ACME 的 CA：

Smallstep CA: [`smallstep.com/`](https://smallstep.com/)

Boulder CA: [`github.com/letsencrypt/boulder`](https://github.com/letsencrypt/boulder)


# 第九章：Linux 的 RADIUS 服务

在本章中，我们将介绍远程身份验证拨入用户服务（RADIUS），这是在网络上验证服务的主要方法之一。我们将在服务器上实现 FreeRADIUS，将其链接到后端轻量级目录访问协议（LDAP）/安全 LDAP（LDAPS）目录，并使用它来验证对网络上各种服务的访问。

特别是，我们将涵盖以下主题：

+   RADIUS 基础知识-什么是 RADIUS，它是如何工作的？

+   使用本地 Linux 认证实现 RADIUS

+   具有 LDAP/LDAPS 后端认证的 RADIUS

+   Unlang-非语言

+   RADIUS 使用案例场景

+   使用 Google Authenticator 进行 RADIUS 的多因素认证（MFA）

# 技术要求

为了跟随本节中的示例，我们将使用我们现有的 Ubuntu 主机或虚拟机（VM）。在本章中，我们将涉及一些无线主题，因此，如果您的主机或虚拟机中没有无线网卡，您将需要一个无线适配器来完成这些示例。

当我们逐步进行各种示例时，我们将编辑多个配置文件。如果没有特别提到，`freeradius`的配置文件都存储在`/etc/freeradius/3.0/`目录中。

对于 Ubuntu 默认未包含的我们正在安装的软件包，请确保您有可用的互联网连接，以便您可以使用`apt`命令进行安装。

# RADIUS 基础知识-什么是 RADIUS，它是如何工作的？

在我们开始之前，让我们回顾一个关键概念-AAA。AAA 是一个常见的行业术语，代表认证、授权和计费-这是控制资源访问的三个关键概念。

认证是证明您身份所需的一切。在许多情况下，这只涉及用户标识符（ID）和密码，但在本章中，我们还将探讨使用 MFA 的更复杂的方法。

授权通常发生在认证之后。一旦您证明了您的身份，各种系统将使用该身份信息来确定您可以访问什么。这可能意味着您可以访问哪些子网、主机和服务，或者可能涉及您可以访问哪些文件或目录。在常规语言中，认证和授权经常可以互换使用，但在讨论 RADIUS 和系统访问时，它们是完全不同的。

计费有点像回到拨号上网的日子。当人们使用拨号调制解调器访问公司系统或互联网时，他们在会话期间占用了宝贵的资源（即接收调制解调器和电路），因此 RADIUS 用于跟踪他们的会话时间和持续时间，以便进行月度发票。在现代，RADIUS 计费仍然用于跟踪会话时间和持续时间，但这些信息现在更多用于故障排除，有时也用于取证目的。

RADIUS 这些天的主要用途是用于认证，通常也配置了计费。授权通常由其他后端系统完成，尽管 RADIUS 可以用于为每个认证会话分配基于网络的访问控制列表（ACL），这是一种授权形式。

在掌握了这些背景知识之后，让我们更详细地讨论 RADIUS。RADIUS 认证协议非常简单，这使得它对许多不同的用例都很有吸引力，因此几乎所有可能需要认证的设备和服务都支持它。让我们通过一个配置以及一个典型的认证交换（在高层次上）来进行讨论。

首先，让我们讨论一个需要认证的设备，在这种情况下称为**网络访问服务器**（**NAS**）。NAS 可以是**虚拟私人网络**（**VPN**）设备，无线控制器或接入点，或交换机 - 实际上，任何用户可能需要认证的设备。NAS 通常由 RADIUS 服务器定义，通常具有关联的“共享密钥”以允许对设备进行身份验证。

接下来，配置设备以使用 RADIUS 进行身份验证。如果这是用于管理访问，通常会保留本地身份验证作为备用方法 - 因此，如果 RADIUS 不可用，本地身份验证仍将起作用。

这就是设备（NAS）的配置。当客户端尝试连接到 NAS 时，NAS 收集登录信息并将其转发到 RADIUS 服务器进行验证（请参阅*图 9.1*，其中显示了在 Wireshark 中捕获的典型 RADIUS 请求数据包）。数据包中需要注意的内容包括以下内容：

+   用于 RADIUS 请求的端口是`1812/udp`。RADIUS 会计的匹配端口是`1813/udp` - 会计跟踪连接时间等，通常用于计费。许多 RADIUS 服务器仍然完全支持一组较旧的端口（`1645`和`1646/udp`）。

+   `Code`字段用于标识数据包类型 - 在本例中，我们将涵盖`Access-Request`（代码`1`），`Accept`（代码`2`）和`Reject`（代码`3`）。RADIUS 代码的完整列表包括以下内容：

![表 9.1 - RADIUS 代码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_Table_01.jpg)

表 9.1 - RADIUS 代码

+   `Packet ID`字段用于将请求和响应数据包联系在一起。由于 RADIUS 是**用户数据报协议**（**UDP**）协议，协议级别上没有会话的概念 - 这必须在数据包的有效负载中。

+   `Authenticator`字段对于每个数据包是唯一的，应该是随机生成的。

+   数据包的其余部分由数据包中的`AVP`组成。这使得协议具有可扩展性；NAS 和 RADIUS 服务器都可以根据情况添加 AV 对。所有实现通常都支持几个 AV 对，以及几个特定于供应商的 AV 对，通常与 NAS 供应商和特定情况相关联 - 例如，区分对设备的管理访问和对 VPN 或无线**服务集 ID**（**SSID**）的用户访问。我们将在本章后面探讨更多用例时更深入地讨论这一点。

在以下简单示例中，我们的两个属性是`User-Name` AV 对，它是明文的，以及`User-Password` AV 对，它被标记为`Encrypted`，但实际上是 MD5 哈希值（其中`Request Authenticator`值。**请求评论**（**RFC**）（*RFC 2865* - 请参阅*进一步阅读*部分）对此的计算有详细的解释，如果您对此感兴趣：

![图 9.1 - 简单的 RADIUS 请求](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_001.jpg)

图 9.1 - 简单的 RADIUS 请求

响应通常要简单得多，如下所述：

+   通常要么是代码 2 `Accept`（*图 9.2*），要么是代码 3 `Reject`（*图 9.3*）的响应。

+   数据包 ID 与请求中的相同。

+   响应认证器是根据响应数据包代码（在本例中为 2），响应的长度（在本例中为 20 字节），数据包 ID（2），请求认证器和共享密钥计算出来的。回复中的其他 AV 对也将用于计算此值。该字段的关键是 NAS 将使用它来验证响应是否来自它期望的 RADIUS 服务器。这个第一个数据包示例显示了一个`Access-Accept`响应，其中访问请求被授予：

![图 9.2 - 简单的 RADIUS 响应（Access-Accept）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_002.jpg)

图 9.2 - 简单的 RADIUS 响应（Access-Accept）

这个第二个响应数据包示例显示了一个`Access-Reject`数据包。所有字段都保持不变，只是访问请求被拒绝了。如果没有配置错误，通常会在用户名或密码值不正确时看到这个结果：

![图 9.3-简单的 RADIUS 响应（Access-Reject）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_003.jpg)

图 9.3-简单的 RADIUS 响应（Access-Reject）

现在我们知道了简单的 RADIUS 请求是如何工作的，让我们开始构建我们的 RADIUS 服务器。

# 使用本地 Linux 身份验证实现 RADIUS

这个示例显示了最简单的 RADIUS 配置，其中`UserID`和`Password`值都在配置文件中定义。由于几个原因，这不建议用于任何生产环境，详细如下：

+   密码以明文字符串的形式存储，因此在发生妥协时，所有 RADIUS 密码都可以被恶意行为者收集。

+   密码是由管理员输入而不是用户。这意味着“不可否认”的关键安全概念丢失了-如果事件与这样的帐户相关联，受影响的用户总是可以说“管理员也知道我的密码-一定是他们”。

+   与管理员输入密码相关的是-用户无法更改他们的密码，这也意味着在大多数情况下，这个 RADIUS 密码将与用户使用的其他密码不同，这使得记住它更困难。

然而，这是一个方便的方法，在我们用后端身份验证存储和更复杂的 RADIUS 交换之前测试初始 RADIUS 配置。

首先，我们将安装`freeradius`，如下所示：

```
sudo apt-get install freeradius
```

接下来，让我们编辑`client`配置，定义我们的各种 NAS 设备，人们将向其发出身份验证请求。为此，使用`sudo`编辑`/etc/freeradius/3.0/clients.conf`文件。正如您所期望的那样，RADIUS 配置文件不能使用普通权限进行编辑或查看，因此对这些文件的所有访问都必须使用`sudo`。

在这个文件的底部，我们将为每个 RADIUS 客户端设备添加一个段，其中包含其名称、IP 地址和该设备的共享密钥。请注意，最好使用一个长的、随机的字符串，对于每个设备都是唯一的。您可以很容易地编写一个快速脚本来为您生成这个-有关更多详细信息，请参见[`isc.sans.edu/forums/diary/How+do+you+spell+PSK/16643`](https://isc.sans.edu/forums/diary/How+do+you+spell+PSK/16643)。

在以下代码示例中，我们添加了三个交换机（每个交换机的名称都以`sw`开头）和一个无线控制器（`VWLC01`，一个虚拟无线控制器）。这里的一个关键概念是一致地命名设备。您可能需要为不同的设备类型制定不同的规则或策略；按设备类型给它们一致的名称是一个方便的概念，可以简化这一点。此外，如果设备名称标准是已知和一致的，那么简单的排序列表也会变得更简单：

```
client sw-core01 {
   ipaddr=192.168.122.9
   nastype = cisco
   secret = 7HdRRTP8qE9T3Mte
}
client sw-office01 {
   ipaddr=192.168.122.5
   nastype = cisco
   secret = SzMjFGX956VF85Mf
}
client sw-floor0 {
   ipaddr = 192.168.122.6
   nastype = cisco
   secret = Rb3x5QW9W6ge6nsR
}
client vwlc01 {
   ipaddr = 192.168.122.8
   nastype = cisco
   secret = uKFJjaBbk2uBytmD
}
```

请注意，在某些情况下，您可能需要配置整个子网-在这种情况下，客户端行可能会读取类似于这样的内容：

```
Client 192.168.0.0/16 {
```

这通常不建议，因为它会使 RADIUS 服务器对该子网上的任何内容都开放。如果可能的话，请使用固定的 IP 地址。然而，在某些情况下，您可能被迫使用子网-例如，如果您有**无线接入点**（**WAPs**）直接对 RADIUS 进行无线客户端认证，使用**动态主机配置协议**（**DHCP**）动态分配 IP。

还要注意`nastype`行-这将设备与包含该供应商的常见 AV 对的定义的`dictionary`文件联系起来。

接下来，让我们创建一个测试用户-使用`sudo`编辑`/etc/freeradius/3.0/users`文件，并添加一个测试帐户，就像这样：

```
testaccount  Cleartext-Password := "Test123"
```

最后，使用以下命令重新启动您的服务：

```
sudo service freeradius restart
```

现在，一些故障排除-要测试配置文件的语法，请使用以下命令：

```
sudo freeradius –CX
```

要测试身份验证操作，请验证您的 RADIUS 服务器信息是否定义为 RADIUS 客户端（默认情况下是这样），然后使用如下所示的`radclient`命令：

```
$ echo "User-Name=testaccount,User-Password=Test123" | radclient localhost:1812 auth testing123
Sent Access-Request Id 31 from 0.0.0.0:34027 to 127.0.0.1:1812 length 44
Received Access-Accept Id 31 from 127.0.0.1:1812 to 127.0.0.1:34027 length 20
```

完成这些测试后，建议删除本地定义的用户——这不是您应该忘记的事情，因为这可能会使攻击者稍后可以使用。现在让我们将我们的配置扩展到更典型的企业配置——我们将添加一个基于 LDAP 的后端目录。

# 具有 LDAP/LDAPS 后端身份验证的 RADIUS

使用诸如**LDAP**之类的后端身份验证存储对许多原因都很有用。由于这通常使用与常规登录相同的身份验证存储，这给我们带来了几个优势，如下所述：

+   LDAP 中的组成员资格可用于控制对关键访问的访问权限（例如管理访问）。

+   RADIUS 访问的密码与标准登录的密码相同，更容易记住。

+   密码和密码更改由用户控制。

+   在用户更改组时，凭证维护位于一个中央位置。特别是，如果用户离开组织，他们的帐户在 LDAP 中被禁用后，RADIUS 也会立即被禁用。

这种方法的缺点很简单：用户很难选择好的密码。这就是为什么，特别是对于面向公共互联网的任何接口，建议使用 MFA（我们稍后将在本章中介绍）。

利用这一点，如果访问仅由简单的用户/密码交换控制，攻击者有几种很好的选择来获取访问权限，如下所述：

+   **使用凭证填充**：使用此方法，攻击者从其他泄漏中收集密码（这些是免费提供的），以及您可能期望在本地或公司内部看到的密码（例如本地体育队或公司产品名称），或者可能对目标帐户有重要意义的单词（例如孩子或配偶的姓名，汽车型号，街道名称或电话号码信息）。然后他们尝试所有这些针对他们的目标，通常是从企业网站或社交媒体网站（LinkedIn 是其中的一个最爱）收集的。这非常成功，因为人们往往有可预测的密码，或者在多个网站上使用相同的密码，或两者兼而有之。在任何规模的组织中，攻击者通常在这种攻击中取得成功，通常需要几分钟到一天的时间。这是如此成功，以至于它在几种恶意软件中被自动化，最著名的是从 2017 年开始的*Mirai*（它攻击了常见的**物联网**（**IoT**）设备的管理访问），然后扩展到包括使用常见单词列表进行猜测密码的任意数量的衍生品系。

+   凭证的强制破解：与凭证填充相同，但是使用整个密码列表对所有帐户进行攻击，以及在用尽这些单词后尝试所有字符组合。实际上，这与凭证填充相同，但在初始攻击之后“继续进行”。这显示了攻击者和防御者之间的不平衡——继续攻击对于攻击者来说基本上是免费的（或者与计算时间和带宽一样便宜），那么他们为什么不继续尝试呢？

为 LDAP 身份验证存储配置 RADIUS 很容易。虽然我们将介绍标准的 LDAP 配置，但重要的是要记住这个协议是明文的，因此是攻击者的一个很好的目标——**LDAPS**（**LDAP over Transport Layer Security (TLS)**）始终是首选。通常，标准的 LDAP 配置应该仅用于测试，然后再使用 LDAPS 添加加密方面。

首先，让我们使用 LDAP 作为传输协议在 RADIUS 中配置我们的后端目录。在此示例中，我们的 LDAP 目录是微软的**Active Directory**（**AD**），但在仅 Linux 环境中，通常会有一个 Linux LDAP 目录（例如使用 OpenLDAP）。

首先，安装`freeradius-ldap`软件包，如下所示：

```
$ sudo apt-get install freeradius-ldap
```

在我们继续实施 LDAPS 之前，您需要收集 LDAPS 服务器使用的 CA 服务器的公共证书。将此文件收集到`/usr/share/ca-certificates/extra`目录中（您需要创建此目录），如下所示：

```
$ sudo mkdir /usr/share/ca-certificates/extra
```

将证书复制或移动到新目录中，如下所示：

```
$ sudo cp publiccert.crt /usr/share/ca-certifiates/extra
```

告诉 Ubuntu 将此目录添加到`certs listgroups`，如下所示：

```
$ sudo dpkg-reconfigure ca-certificates
```

您将被提示添加任何新证书，因此请务必选择刚刚添加的证书。如果列表中有任何您不希望看到的证书，请取消此操作并在继续之前验证这些证书是否不恶意。

接下来，我们将编辑`/etc/freeradius/3.0/mods-enabled/ldap`文件。这个文件不会在这里-如果需要，您可以参考`/etc/freeradius/3.0/mods-available/ldap`文件作为示例，或直接链接到该文件。

下面显示的配置中的`server`行意味着您的 RADIUS 服务器必须能够使用**域名系统**（**DNS**）解析该服务器名称。

我们将使用以下行配置 LDAPS：

```
ldap {
        server = 'dc01.coherentsecurity.com'
        port = 636
        # Login credentials for a special user for FreeRADIUS which has the required permissions
        identity = ldapuser@coherentsecurity.com
        password = <password>
        base_dn = 'DC=coherentsecurity,DC=com'
        user {
        # Comment out the default filter which uses uid and replace that with samaccountname
                #filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
                filter = "(samaccountname=%{%{Stripped-User-Name}:-%{User-Name}})"
        }
        tls {
                ca_file = /usr/share/ca-certificates/extra/publiccert.crt
        }
}
```

如果您被迫配置 LDAP 而不是 LDAPS，则端口更改为`389`，当然也没有证书，因此可以删除或注释掉`ldap`配置文件中的`tls`部分。

我们通常使用的`ldapuser`示例用户不需要任何特殊访问权限。但是，请确保为此帐户使用一个长度（> 16 个字符）的随机密码，因为在大多数环境中，这个密码不太可能经常更改。

接下来，我们将指导`/etc/freeradius/3.0/sites-enabled/default`文件的`authenticate / pap`部分（请注意，这是指向`/etc/freeradius/3.0/sites-available`中主文件的链接），如下所示：

```
        pap
        if (noop && User-Password) {
                update control {
                        Auth-Type := LDAP
                }
        }
```

此外，请确保取消注释该部分中的`ldap`行，如下所示：

```
       ldap
```

现在我们可以在前台运行`freeradius`。这将允许我们在发生时查看消息处理-特别是显示的任何错误。这意味着在进行这一系列初始测试期间，我们不必寻找错误日志。以下是您需要的代码：

```
$ sudo freeradius -cx
```

如果您需要进一步调试，可以使用以下代码将`freeradius`服务器作为前台应用程序运行，以实时显示默认日志记录：

```
$ sudo freeradius –X
```

最后，当一切正常工作时，通过运行以下命令重新启动您的 RADIUS 服务器以收集配置更改：

```
$ sudo service freeradius restart
```

再次，要从本地计算机测试用户登录，请执行以下代码：

```
$ echo "User-Name=test,User-Password=P@ssw0rd!" | radclient localhost:1812 auth testing123
```

最后，我们将希望启用 LDAP 启用的组支持-我们将在后面的部分（* RADIUS 使用案例场景*）中看到，我们将希望在各种策略中使用组成员资格。为此，我们将重新访问`ldap`文件并添加一个`group`部分，如下所示：

```
        group {
            base_dn = "${..base_dn}"
            filter = '(objectClass=Group)'
            name_attribute = cn
            membership_filter = "(|(member=%{control:${..user_dn}})(memberUid=%{%{Stripped-User-Name}:-%{User-Name}}))"
             membership_attribute = 'memberOf'
             cacheable_name = 'no'
             cacheable_dn = 'no'
        }
```

完成这些操作后，我们应该意识到的一件事是，LDAP 并不是用于身份验证，而是用于授权-这是一个检查组成员资格的好方法，例如。实际上，如果您在构建过程中注意到，这在配置文件中是明确指出的。

让我们解决这种情况，并使用**NT LAN Manager**（**NTLM**）作为身份验证的底层 AD 协议。

## NTLM 身份验证（AD）-引入 CHAP

将 RADIUS 与 AD 链接以获取帐户信息和组成员资格，这是我们在大多数组织中看到的最常见的配置。虽然微软**网络策略服务器**（**NPS**）是免费的，并且可以轻松安装在域成员 Windows 服务器上，但它没有一个简单的配置来将其链接到**双因素身份验证**（**2FA**）服务，比如 Google Authenticator。这使得基于 Linux 的 RADIUS 服务器与 AD 集成成为组织需要 MFA 并在建立访问权限时利用 AD 组成员资格的吸引人选择。

这种方法的身份验证是什么样的？让我们来看看标准的**挑战-握手认证协议**（**CHAP**），**Microsoft CHAP**（**MS-CHAP**）或 MS-CHAPv2，它为 RADIUS 交换添加了更改密码的功能。基本的 CHAP 交换如下：

![图 9.4 - 基本 CHAP 交换](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_004.jpg)

图 9.4 - 基本 CHAP 交换

按顺序进行前述交换，我们可以注意到以下内容：

+   首先，客户端发送初始的**Hello**，其中包括**USERID**（但不包括密码）。

+   **CHAP Challenge**从 NAS 发送。这是随机数和 RADIUS 秘钥的结果，然后使用 MD5 进行哈希处理。

+   客户端（**Supplicant**）使用该值对密码进行哈希处理，然后将该值发送到响应中。

+   NAS 将该随机数和响应值发送到 RADIUS 服务器，RADIUS 服务器执行自己的计算。

+   如果两个值匹配，则会话会收到**RADIUS Access-Accept**响应；如果不匹配，则会收到**RADIUS Access-Reject**响应。

**受保护的可扩展认证协议**（**PEAP**）为此交换增加了一个额外的复杂性 - 客户端和 RADIUS 服务器之间存在 TLS 交换，这允许客户端验证服务器的身份，并使用标准 TLS 加密数据交换。为此，RADIUS 服务器需要一个证书，并且客户端需要在其受信任的 CA 存储中拥有发行 CA。

要为 FreeRADIUS 配置 AD 集成（使用 PEAP MS-CHAPv2），我们将为身份验证配置`ntlm_auth`，并将 LDAP 原样移动到配置的`authorize`部分。

要开始使用`ntlm_auth`，我们需要安装`samba`（这是**SMB**的玩笑，代表**服务器消息块**）。首先，确保它尚未安装，如下所示：

```
$ sudo apt list --installed | grep samba
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
samba-libs/focal-security,now 2:4.11.6+dfsg-0ubuntu1.6 amd64 [installed,upgradable to: 2:4.11.6+dfsg-0ubuntu1.8]
```

从此列表中，我们看到它没有安装在我们的 VM 中，所以让我们使用以下命令将其添加到我们的配置中：

```
 sudo apt-get install samba
```

还要安装以下内容：

```
winbind with sudo apt-get install winbind.
```

编辑`/etc/samba/smb.conf`，并根据您的域更新以下代码段中显示的行（我们的测试域已显示）。在编辑时确保使用`sudo` - 您需要 root 权限来修改此文件（请注意，默认情况下`[homes]`行可能已被注释掉）：

```
[global]
   workgroup = COHERENTSEC
    security = ADS
    realm = COHERENTSECURITY.COM
    winbind refresh tickets = Yes
    winbind use default domain = yes
    vfs objects = acl_xattr
    map acl inherit = Yes
    store dos attributes = Yes 
    dedicated keytab file = /etc/krb5.keytab
    kerberos method = secrets and keytab
[homes]
    comment = Home Directories
    browseable = no
    writeable=yes
```

接下来，我们将编辑`krb5.conf`文件。示例文件位于`/usr/share/samba/setup`中 - 将该文件复制到`/etc`并编辑该副本。请注意，默认情况下`EXAMPLE.COM`条目是存在的，在大多数安装中，这些条目应该被删除（`example.com`是用于示例和文档的保留域）。代码如下所示：

```
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log
[libdefaults]
 default_realm = COHERENTSECURITY.COM
 dns_lookup_realm = false
 dns_lookup_kdc = false
[realms]
 COHERENTSECURITY.COM = {
  kdc = dc01.coherentsecurity.com:88
  admin_server = dc01.coherentsecurity.com:749
  kpaswordserver = dc01.coherentsecurity.com
  default_domain = COHERENTSECURITY.COM
 }
[domain_realm]
 .coherentsecurity.com = coherentsecurity.com
[kdc]
  profile = /var/kerberos/krb5kdc/kdc.conf
[appdefaults]
 pam = {
  debug = false
  ticket_lifetime = 36000
  renew_lifetime = 36000
  forwardable = true
  krb4_convert = false
 }
```

编辑`/etc/nsswitch.conf`文件，并添加`winbind`关键字，如下代码段所示。请注意，在 Ubuntu 20 中，默认情况下可能没有`automount`行，因此您可能希望添加它：

```
passwd:         files systemd winbind
group:          files systemd winbind
shadow:         files winbind
protocols:      db files winbind
services:       db files winbind
netgroup:       nis winbind
automount:      files winbind
```

现在应该为您部分配置了 - 重新启动 Linux 主机，然后验证以下两个服务是否正在运行：

+   `smbd`提供文件和打印共享服务。

+   `nmbd`提供 NetBIOS 到 IP 地址名称服务。

此时，您可以将 Linux 主机加入 AD 域（将提示您输入密码），如下所示：

```
# net ads join –U Administrator
```

重新启动`smbd`和`windbind`守护程序，如下所示：

```
# systemctl restart smbd windbind
```

您可以使用以下代码检查状态：

```
$ sudo ps –e | grep smbd
$ sudo ps –e | grep nmbd
```

或者，要获取更多详细信息，您可以运行以下代码：

```
$ sudo service smbd status
$ sudo service nmbd status
```

现在，您应该能够列出 Windows 域中的用户和组，如下面的代码片段所示：

```
$ wbinfo -u
COHERENTSEC\administrator
COHERENTSEC\guest
COHERENTSEC\ldapuser
COHERENTSEC\test
….
$ wbinfo -g
COHERENTSEC\domain computers
COHERENTSEC\domain controllers
COHERENTSEC\schema admins
COHERENTSEC\enterprise admins
COHERENTSEC\cert publishers
COHERENTSEC\domain admins
…
```

如果这行不通，那么寻找答案的第一个地方很可能是 DNS。请记住这句古老的谚语，这里以俳句的形式表达：

*不是 DNS*

*绝对不是 DNS*

*是 DNS 的问题*

这太有趣了，因为这是真的。如果 DNS 配置不完美，那么各种其他事情都不会按预期工作。为了使所有这些工作正常，您的 Linux 站点将需要在 Windows DNS 服务器上解析记录。使这成为现实的最简单方法是将您站点的 DNS 服务器设置指向该 IP（如果您需要刷新`nmcli`命令，请参考*第二章*，*基本 Linux 网络配置和操作 – 使用本地接口*）。或者，您可以在 Linux DNS 服务器上设置有条件的转发器，或者在 Linux 主机上添加 AD DNS 的辅助区域—根据您需要在您的情况下“主要”的服务，有几种可用的替代方案。

要测试 DNS 解析，请尝试按名称 ping 您的域控制器。如果成功，请尝试查找一些**service**（**SRV**）记录（这些记录是 AD 的基础组成部分）—例如，您可以查看这个：

```
dig +short _ldap._tcp.coherentsecurity.com SRV
0 100 389 dc01.coherentsecurity.com.
```

接下来，验证您是否可以使用`wbinfo`进行 AD 身份验证，然后再次使用 RADIUS 使用的`ntlm_auth`命令，如下所示：

```
wbinfo -a administrator%Passw0rd!
plaintext password authentication failed
# ntlm_auth –-request-nt-key –-domain=coherentsecurity.com --username=Administrator
Password:
NT_STATUS_OK: The operation completed successfully. (0x0)
```

请注意，纯文本密码在`wbinfo`登录尝试中失败了，这（当然）是期望的情况。

通过与域的连接正常工作，我们现在可以开始配置 RADIUS 了。

我们的第一步是更新`/etc/freeradius/3.0/mods-available/mschap`文件，以配置一个设置来修复挑战/响应握手中的问题。您的`mschap`文件需要包含以下代码：

```
chap {
    with_ntdomain_hack = yes
}
```

此外，如果您在文件中向下滚动，您会看到以`ntlm_auth =“`开头的一行。您希望该行读起来像这样：

```
ntlm_auth = "/usr/bin/ntlm_auth --request-nt-key --username=%{%{Stripped-User-Name}:-%{%{User-Name}:-None}} --challenge=%{%{mschap:Challenge}:-00} --nt-response=%{%{mschap:NT-Response}:-00} --domain=%{mschap:NT-Domain}"
```

如果您正在进行机器身份验证，您可能需要将`username`参数更改为以下内容：

```
--username=%{%{mschap:User-Name}:-00}
```

最后，要启用 PEAP，我们转到`mods-available/eap`文件并更新`default_eap_type`行，并将该方法从`md5`更改为`peap`。然后，在`tls-config tls-common`部分，将`random_file`行从`${certdir}/random`的默认值更新为现在显示为`random_file = /dev/urandom`。

完成后，您希望对`eap`文件的更改如下所示：

```
eap {
        default_eap_type = peap
}
tls-config tls-common {
        random_file = /dev/urandom
}
```

这完成了 PEAP 身份验证的典型服务器端配置。

在客户端（请求者）端，我们只需启用 CHAP 或 PEAP 身份验证。在这种配置中，站点发送用户 ID 或机器名称作为认证帐户，以及用户或工作站密码的哈希版本。在服务器端，此哈希与其自己的计算进行比较。密码永远不会以明文形式传输；然而，服务器发送的“挑战”作为额外步骤发送。

在 NAS 设备上（例如，VPN 网关或无线系统），我们启用`MS-CHAP`身份验证，或者`MS-CHAPv2`（它增加了通过 RADIUS 进行密码更改的功能）。

现在，我们将看到事情变得更加复杂；如果您想要使用 RADIUS 来控制多个事物，例如同时控制 VPN 访问和对该 VPN 服务器的管理员访问，使用相同的 RADIUS 服务器？让我们探讨如何使用*U**nlang*语言设置规则来实现这一点。

# Unlang – 无语言

FreeRADIUS 支持一种称为**Unlang**（**无语言**的缩写）的简单处理语言。这使我们能够制定规则，为 RADIUS 身份验证流程和最终决策添加额外的控制。

Unlang 语法通常可以在虚拟服务器文件中找到，例如在我们的情况下，可能是`/etc/freeradius/3.0/sites-enabled/default`，并且可以在标题为`authorize`、`authenticate`、`post-auth`、`preacct`、`accounting`、`pre-proxy`、`post-proxy`和`session`的部分中找到。

在大多数常见的部署中，我们可能会寻找一个传入的 RADIUS 变量或 AV 对，例如`Service-Type`，可能是`Administrative`或`Authenticate-Only`，在 Unlang 代码中，将其与组成员资格进行匹配，例如网络管理员、VPN 用户或无线用户。

对于两个防火墙登录要求的简单情况（`仅 VPN`或`管理`访问），您可能会有这样的规则：

```
if(&NAS-IP-Address == "192.168.122.20") {
    if(Service-Type == Administrative && LDAP-Group == "Network Admins") {
            update reply {
                Cisco-AVPair = "shell:priv-lvl=15"
            } 
            accept
    } 
    elsif (Service-Type == "Authenticate-Only" && LDAP-Group == "VPN Users" ) {
        accept
    }
    elsif {
        reject
    }
}
```

您可以进一步添加到这个示例中，如果用户正在 VPN 连接，`Called-Station-ID`将是防火墙的外部 IP 地址，而管理登录请求将是内部 IP 或管理 IP（取决于您的配置）。

如果有大量设备在运行，`switch/case`结构可以很方便地简化永无止境的`if/else-if`语句列表。您还可以使用`all switches`与（例如）`NAS-Identifier =~ /SW*/`。

如果要进行无线访问的身份验证，`NAS-Port-Type`设置将是`Wireless-802.11`，对于 802.1x 有线访问请求，`NAS-Port-Type`设置将是`Ethernet`。

您还可以根据不同的无线 SSID 包含不同的身份验证标准，因为 SSID 通常在`Called-Station-SSID`变量中，格式为`<AP 的 MAC 地址>:SSID 名称`，用`-`字符分隔`58-97-bd-bc-3e-c0:WLCORP`。因此，要返回 MAC 地址，您将匹配最后六个字符，例如`.\.WLCORP$`。

在典型的企业环境中，我们可能会有两到三个不同访问级别的 SSID，对不同网络设备类型的管理用户，具有 VPN 访问权限或访问特定 SSID 的用户。您可以看到这种编码练习如何迅速变得非常复杂。建议首先在小型测试环境中测试您的`unlang`语法的更改（也许使用虚拟网络设备），然后在计划的停机/测试维护窗口期间进行部署和生产测试。

现在我们已经构建好了所有的部分，让我们为各种身份验证需求配置一些真实的设备。

# RADIUS 使用案例场景

在本节中，我们将看看几种设备类型以及这些设备可能具有的各种身份验证选项和要求，并探讨如何使用 RADIUS 来解决它们。让我们从 VPN 网关开始，使用标准的用户 ID 和密码身份验证（不用担心，我们不会就这样留下它）。

## 使用用户 ID 和密码进行 VPN 身份验证

VPN 服务（或者在此之前，拨号服务）的身份验证是大多数组织首先使用 RADIUS 的原因。然而，随着时间的推移，单因素用户 ID 和密码登录对于任何面向公众的服务来说已经不再是安全选项。我们将在本节讨论这一点，但当我们在 MFA 部分时，我们将更新为更现代的方法。

首先，将您的 VPN 网关（通常是防火墙）添加为 RADIUS 的客户端-将其添加到您的`/etc/freeradius/3.0/clients.conf`文件中，如下所示：

```
client hqfw01 {
  ipaddr = 192.168.122.1
  vendor = cisco
  secret = pzg64yr43njm5eu
}
```

接下来，配置您的防火墙指向 RADIUS 进行 VPN 用户身份验证。例如，对于 Cisco 自适应安全设备（ASA）防火墙，您可以进行以下更改：

```
! create a AAA Group called "RADIUS" that uses the protocol RADIUS
aaa-server RADIUS protocol radius
! next, create servers that are members of this group
aaa-server RADIUS (inside) host <RADIUS Server IP 01>
 key <some key 01>
 radius-common-pw <some key 01>
 no mschapv2-capable
 acl-netmask-convert auto-detect
aaa-server RADIUS (inside) host <RADIUS Server IP 02>
 key <some key 02>
 radius-common-pw <some key 02>
 no mschapv2-capable
 acl-netmask-convert auto-detect
```

接下来，更新隧道组以使用`RADIUS`服务器组进行身份验证，如下所示：

```
tunnel-group VPNTUNNELNAME general-attributes
 authentication-server-group RADIUS
 default-group-policy VPNPOLICY
```

现在这个已经可以工作了，让我们将`RADIUS`作为对这个相同设备的管理访问的身份验证方法。

## 对网络设备的管理访问

接下来，我们将要添加的是对同一防火墙的管理访问。我们如何为管理员做到这一点，但又防止常规 VPN 用户访问管理功能？很简单 - 我们将利用一些额外的 AV 对（记得我们在本章前面讨论过吗？）。

我们将首先添加一个新的网络策略，具有以下凭据：

+   对于 VPN 用户，我们将添加一个`服务类型`的 AV 对，值为`仅认证`。

+   对于管理用户，我们将添加一个`服务类型`的 AV 对，值为`管理`。

在 RADIUS 端，策略将要求每个策略的组成员资格，因此我们将在后端身份验证存储中创建名为`VPN 用户`和`网络管理员`的组，并适当填充它们。请注意，当所有这些放在一起时，管理员将具有 VPN 访问权限和管理访问权限，但具有常规 VPN 帐户的人只能具有 VPN 访问权限。

要获取此规则的实际语法，我们将回到 Unlang 的上一节，并使用那个例子，它恰好满足我们的需求。如果您正在请求管理访问权限，您需要在`网络管理员`组中，如果您需要 VPN 访问权限，您需要在`VPN 用户`组中。如果访问和组成员资格不符，则将拒绝访问。

现在 RADIUS 已经设置好了，让我们将对**图形用户界面**（**GUI**）和**安全外壳**（**SSH**）接口的管理访问指向 RADIUS 进行身份验证。在防火墙上，将以下更改添加到我们在 VPN 示例中讨论过的 ASA 防火墙配置中：

```
aaa authentication enable console RADIUS LOCAL
aaa authentication http console RADIUS LOCAL
aaa authentication ssh console RADIUS LOCAL
aaa accounting enable console RADIUS
aaa accounting ssh console RADIUS
aaa authentication login-history
```

请注意，每种登录方法都有一个“身份验证列表”。我们首先使用 RADIUS，但如果失败（例如，如果 RADIUS 服务器宕机或无法访问），则对本地帐户的身份验证将失败。还要注意，我们在`enable`模式的列表中有 RADIUS。这意味着我们不再需要一个所有管理员必须使用的单一共享启用密码。最后，`aaa authentication log-history`命令意味着当您进入`enable`模式时，防火墙将将您的用户名注入 RADIUS 请求，因此您只需要在输入`enable`模式时输入密码。

如果我们没有设置`unlang`规则，那么仅仅前面的配置将允许常规访问 VPN 用户请求和获取管理访问权限。一旦 RADIUS 控制了一个设备上的多个访问权限，就必须编写规则来保持它们的清晰。

配置好我们的防火墙后，让我们来看看对路由器和交换机的管理访问。

### 对路由器和交换机的管理访问

我们将从思科路由器或交换机配置开始。这个配置在不同平台或** Internetwork Operating System **（** IOS **）版本之间会有轻微差异，但应该看起来非常类似于这样：

```
radius server RADIUS01
    address ipv4 <radius server ip 01> auth-port 1812 acct-port 1813
    key <some key>
radius server RADIUS02
    address ipv4 <radius server ip 02> auth-port 1812 acct-port 1813
    key <some key>
aaa group server radius RADIUSGROUP
    server name RADIUS01
    server name RADIUS02
ip radius source-interface <Layer 3 interface name>
aaa new-model
aaa authentication login RADIUSGROUP group radius local
aaa authorization exec RADIUSGROUP group radius local
aaa authorization network RADIUSGROUP group radius local
line vty 0 97
 ! restricts access to a set of trusted workstations or subnets
 access-class ACL-MGT in
 login authentication RADIUSG1
 transport input ssh
```

**惠普**（**HP**）ProCurve 等效配置将如下所示：

```
radius-server host <server ip> key <some key 01>
aaa server-group radius "RADIUSG1" host <server ip 01>
! optional RADIUS and AAA parameters
radius-server dead-time 5
radius-server timeout 3
radius-server retransmit 2
aaa authentication num-attempts 3
aaa authentication ssh login radius server-group "RADIUSG1" local
aaa authentication ssh enable radius server-group "RADIUSG1" local
```

请注意，当进入`enable`模式时，HP 交换机将需要第二次进行完整身份验证（用户 ID 和密码），而不仅仅是密码，这可能出乎您的意料。

在 RADIUS 服务器上，来自思科和惠普交换机的管理访问请求将包括我们在防火墙管理访问中看到的相同 AV 对：`服务类型：管理`。您可能会将此与 RADIUS 中的组成员资格要求配对，就像我们为防火墙所做的那样。

既然我们已经让 RADIUS 控制我们的交换机的管理访问权限，让我们将 RADIUS 控制扩展到包括更安全的身份验证方法。让我们从探索 EAP-TLS（其中** EAP **代表**可扩展身份验证协议**）开始，它使用证书进行客户端和 RADIUS 服务器之间的相互身份验证交换。

## EAP-TLS 身份验证的 RADIUS 配置

要开始本节，让我们讨论一下 EAP-TLS 到底是什么。**EAP**是一种扩展 RADIUS 传统用户 ID/密码交换的方法。我们在*第八章*中熟悉了 TLS，*Linux 上的证书服务*。因此，简单地说，EAP-TLS 是在 RADIUS 内使用证书来证明身份和提供认证服务。

在大多数“常规公司”使用情况下，EAP-TLS 与一个名为 802.1x 的第二协议配对使用，该协议用于控制对网络的访问，例如对无线 SSID 或有线以太网端口的访问。我们将花一些时间来了解这一点，但让我们开始看看 EAP-TLS 的具体细节，然后加入网络访问。

那么，从协议的角度来看，这是什么样子的呢？如果您回顾我们在*第八章*中讨论的*使用证书–Web 服务器*示例，它看起来与那个例子完全一样，但是在双向上。绘制出来（在*图 9.5*中），我们看到与 Web 服务器示例中相同的信息交换，但在双向上，如下所述：

+   客户端（或 supplicant）使用其用户或设备证书向 RADIUS 发送其身份信息，而不是使用用户 ID 和密码——RADIUS 服务器使用这些信息来验证 supplicant 的身份，并根据该信息（和 RADIUS 内的相关规则）允许或拒绝访问。

+   同时，supplicant 以相同的方式验证 RADIUS 服务器的身份——验证服务器名称是否与证书中的**通用名称**（**CN**）匹配，并且证书是否受信任。这可以防范恶意部署的 RADIUS 服务器（例如，在“恶意双胞胎”无线攻击中）。

+   一旦完成了这种相互认证，网络连接就在 supplicant 和网络设备（NAS）之间完成了——通常，该设备是交换机或 WAP（或无线控制器）。

您可以在以下图表中看到这一点的说明：

![图 9.5 – 802.1x/EAP-TLS 会话的认证流程](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_005.jpg)

图 9.5 – 802.1x/EAP-TLS 会话的认证流程

以下是一些需要注意的事项：

+   所有这些都要求提前分发所有必需的证书。这意味着 RADIUS 服务器需要安装其证书，而 supplicants 需要安装其设备证书和/或用户证书。

+   作为其中的一部分，CA 必须得到设备、用户和 RADIUS 服务器的信任。虽然所有这些都可以通过公共 CA 完成，但通常由私有 CA 完成。

+   在认证过程中，supplicant 和 RADIUS 服务器（当然）都不与 CA 通信。

既然我们理解了 EAP-TLS 的工作原理，那么在无线控制器上，EAP-TLS 配置是什么样子的呢？

## 使用 802.1x/EAP-TLS 进行无线网络认证

对于许多公司来说，EAP-TLS 用于 802.1x 认证作为其无线客户端认证机制，主要是因为无线的其他任何认证方法都容易受到一种或多种简单攻击的影响。EAP-TLS 实际上是唯一安全的无线认证方法。

也就是说，在 NAS 上（在这种情况下是无线控制器）的配置非常简单——准备和配置的大部分工作都在 RADIUS 服务器和客户端站上。对于思科无线控制器，配置通常主要通过 GUI 完成，当然，也有命令行。

在 GUI 中，EAP-TLS 认证非常简单——我们只是为客户端建立一个直接向 RADIUS 服务器进行认证的通道（反之亦然）。步骤如下：

1.  首先，为身份验证定义一个 RADIUS 服务器。几乎相同的配置也适用于相同服务器的 RADIUS 计费，使用端口`1813`。您可以在以下截图中看到一个示例配置：![图 9.6 – 无线控制器配置的 RADIUS 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_006.jpg)

图 9.6 – 无线控制器配置的 RADIUS 服务器

1.  接下来，在 SSID 定义下，我们将设置 802.1x 身份验证，如以下截图所示：![图 9.7 – 配置 SSID 使用 802.1x 身份验证](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_007.jpg)

图 9.7 – 配置 SSID 使用 802.1x 身份验证

1.  最后，在 AAA 服务器下，我们将 RADIUS 服务器链接到 SSID，如以下截图所示：

![图 9.8 – 为 802.1x 身份验证和计费分配 RADIUS 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_008.jpg)

图 9.8 – 为 802.1x 身份验证和计费分配 RADIUS 服务器

为了使所有这些工作正常运行，客户端和 RADIUS 服务器都需要适当的证书，并且需要配置 EAP-TLS 身份验证。建议提前分发证书，特别是如果您正在使用自动化发放证书，您需要给客户端足够的时间，以便它们都连接并触发证书的发放和安装。

现在使用 EAP-TLS 安全认证的无线网络，典型的工作站交换机上的类似配置是什么样的？

## 使用 802.1x/EAP-TLS 的有线网络身份验证

在这个例子中，我们将展示网络设备的 802.1x 身份验证的交换机端配置（思科）。在这种配置中，工作站使用 EAP-TLS 进行身份验证，我们告诉交换机“信任”电话。虽然这是一种常见的配置，但很容易被规避——攻击者可以告诉他们的笔记本电脑将其数据包“标记”（例如使用`nmcli`命令）为虚拟局域网（VLAN）105（语音 VLAN）。只要交换机信任设备设置自己的 VLAN，这种攻击就不那么困难，尽管从那里继续攻击需要一些努力来使所有参数“完美”。因此，最好是让 PC 和电话都进行身份验证，但这需要额外的设置——电话需要设备证书才能完成这种推荐的配置。

让我们继续我们的示例交换机配置。首先，我们定义 RADIUS 服务器和组（这应该看起来很熟悉，来自管理访问部分）。

允许 802.1x 的交换机配置包括一些全局命令，设置 RADIUS 服务器和 RADIUS 组，并将 802.1x 身份验证链接回 RADIUS 配置。这些命令在以下代码片段中说明：

```
radius server RADIUS01
    address ipv4 <radius server ip 01> auth-port 1812 acct-port 1813
    key <some key>
radius server RADIUS02
    address ipv4 <radius server ip 02> auth-port 1812 acct-port 1813
    key <some key>
aaa group server radius RADIUSGROUP
    server name RADIUS01
    server name RADIUS02
! enable dot1x authentication for all ports by default
dot1x system-auth-control
! set up RADIUS Authentication and Accounting for Network Access
aaa authentication dot1x default group RADIUSGROUP
aaa accounting dot1x default start-stop group RADIUSGROUP
```

接下来，我们配置交换机端口。典型的交换机端口，使用 VLAN 101 上的工作站的 802.1x 身份验证，使用工作站和/或用户证书（之前发放），并且对语音 IP 电话（在 VLAN 105 上）不进行身份验证。请注意，正如我们讨论的那样，身份验证是相互的——工作站在 RADIUS 服务器认证有效的同时，RADIUS 服务器也认证工作站。

![表 9.2 – 交换机 802.1x/EAP-TLS 配置的接口配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_09_Table_02.jpg)

表 9.2 – 交换机 802.1x/EAP-TLS 配置的接口配置

强制 VOIP 电话也使用 802.1x 和证书进行身份验证，删除`trust device cisco-phone`行。这种改变存在一定的政治风险——如果一个人的个人电脑无法进行身份验证，他们又无法打电话给帮助台，那么整个故障排除和解决过程的“温度”立即升高，即使他们可以使用手机打电话给帮助台。

接下来，让我们稍微回顾一下，并添加 Google Authenticator 的多因素认证。当用户 ID 和密码可能是传统解决方案时，通常会使用这种方式。例如，这是保护 VPN 认证免受诸如密码填充攻击之类的问题的绝佳解决方案。

# 使用 Google Authenticator 进行 RADIUS 的多因素认证

正如讨论的那样，对于访问公共服务，特别是面向公共互联网的任何服务，2FA 认证方案是最佳选择，而在过去，您可能已经配置了简单的用户 ID 和密码进行认证。随着持续发生的**短信服务**（**SMS**）泄露事件，我们看到了新闻报道中为什么短信消息不适合作为 2FA 的例子，幸运的是，像 Google Authenticator 这样的工具可以免费配置用于这种情况。

首先，我们将安装一个新的软件包，允许对 Google Authenticator 进行认证，如下所示：

```
$ sudo apt-get install libpam-google-authenticator -y
```

在`users`文件中，我们将更改用户认证以使用**可插拔认证模块**（**PAMs**），如下所示：

```
# Instruct FreeRADIUS to use PAM to authenticate users
DEFAULT Auth-Type := PAM
$ sudo vi /etc/freeradius/3.0/sites-enabled/default
```

取消注释`pam`行，如下所示：

```
#  Pluggable Authentication Modules.
        pam
```

接下来，我们需要编辑`/etc/pam.d/radiusd`文件。注释掉默认的`include`文件，如下面的代码片段所示，并添加 Google Authenticator 的行。请注意，`freeraduser`是一个本地 Linux 用户 ID，将成为该模块的进程所有者：

```
#@include common-auth
#@include common-account
#@include common-password
#@include common-session
auth requisite pam_google_authenticator.so forward_pass secret=/etc/freeradius/${USER}/.google_authenticator user=<freeraduser>
auth required pam_unix.so use_first_pass
```

如果您的 Google Authenticator 服务正常工作，那么与之相关的 RADIUS 链接现在也应该正常工作了！

接下来，生成 Google Authenticator 的秘钥并提供**快速响应**（**QR**）码、账户恢复信息和其他账户信息给客户（在大多数环境中，这可能是一个自助实现）。

现在，当用户对 RADIUS 进行认证（对于 VPN、管理访问或其他任何情况），他们使用常规密码和他们的 Google 秘钥。在大多数情况下，您不希望为无线认证增加这种开销。证书往往是最适合的解决方案，甚至可以说，如果您的无线网络没有使用 EAP-TLS 进行认证，那么它就容易受到一种或多种常见攻击。

# 总结

这结束了我们对使用 RADIUS 对各种服务器进行认证的旅程。与我们在本书中探讨过的许多 Linux 服务一样，本章只是对 RADIUS 可以用来解决的常见配置、用例和组合进行了初步探讨。

在这一点上，您应该具备理解 RADIUS 工作原理并能够为 VPN 服务和管理访问配置安全的 RADIUS 认证，以及无线和有线网络访问的基础知识。您应该具备理解 PAP、CHAP、LDAP、EAP-TLS 和 802.1x 认证协议的基础知识。特别是 EAP-TLS 的使用案例应该说明为什么拥有内部 CA 可以真正帮助您保护网络基础设施。

最后，我们提到了将 Google Authenticator 与 RADIUS 集成以实现多因素认证。尽管我们没有详细介绍 Google Authenticator 服务的配置，但是这似乎最近变化如此频繁，以至于该服务的 Google 文档是最好的参考资料。

在下一章中，我们将讨论如何将 Linux 用作负载均衡器。负载均衡器已经存在多年了，但近年来，它们在物理和虚拟数据中心中的部署频率和方式都有了很大的变化，敬请关注！

# 问题

最后，这里有一些问题供您测试对本章材料的了解。您将在*附录*的*评估*部分找到答案：

1.  对于您打算对其进行管理访问和 VPN 访问认证的防火墙，您如何允许普通用户进行 VPN 访问，但不允许进行管理访问？

1.  为什么 EAP-TLS 是无线网络的一个很好的认证机制？

1.  如果 EAP-TLS 如此出色，为什么 MFA 优先于具有证书的 EAP-TLS 进行 VPN 访问认证？

# 进一步阅读

本章引用的基本 RFC 列在这里：

+   RFC 2865: *RADIUS* ([`tools.ietf.org/html/rfc2865`](https://tools.ietf.org/html/rfc2865))

+   RFC 3579: *EAP 的 RADIUS 支持* ([`tools.ietf.org/html/rfc3579`](https://tools.ietf.org/html/rfc3579))

+   RFC 3580: *IEEE 802.1X RADIUS 使用指南* ([`tools.ietf.org/html/rfc3580`](https://tools.ietf.org/html/rfc3580))

然而，DNS 的完整 RFC 列表很长。以下列表仅显示当前的 RFC - 已废弃和实验性的 RFC 已被删除。当然，这些都可以在[`tools.ietf.org`](https://tools.ietf.org)以及[`www.rfc-editor.org:`](https://www.rfc-editor.org:)找到。

RFC 2548: *Microsoft 特定供应商的 RADIUS 属性*

RFC 2607: *漫游中的代理链接和策略实施*

RFC 2809: *通过 RADIUS 实现 L2TP 强制隧道*

RFC 2865: *远程认证拨号用户服务（RADIUS）*

RFC 2866: *RADIUS 会计*

RFC 2867: *用于隧道协议支持的 RADIUS 会计修改*

RFC 2868: *用于隧道协议支持的 RADIUS 属性*

RFC 2869: *RADIUS 扩展*

RFC 2882: *网络访问服务器要求：扩展的 RADIUS 实践*

RFC 3162: *RADIUS 和 IPv6*

RFC 3575: *RADIUS 的 IANA 考虑事项*

RFC 3579: *EAP 的 RADIUS 支持*

RFC 3580: *IEEE 802.1X RADIUS 使用指南*

RFC 4014: *DHCP 中继代理信息选项的 RADIUS 属性子选项*

RFC 4372: *可计费用户身份*

RFC 4668: *IPv6 的 RADIUS 认证客户端 MIB*

RFC 4669: *IPv6 的 RADIUS 认证服务器 MIB*

RFC 4670: *IPv6 的 RADIUS 会计客户端 MIB*

RFC 4671: *IPv6 的 RADIUS 会计服务器 MIB*

RFC 4675: *虚拟局域网和优先级支持的 RADIUS 属性*

RFC 4679: *DSL 论坛特定供应商的 RADIUS 属性*

RFC 4818: *RADIUS 委派 IPv6 前缀属性*

RFC 4849: *RADIUS 过滤规则属性*

RFC 5080: *常见的 RADIUS 实施问题和建议的修复*

RFC 5090: *摘要认证的 RADIUS 扩展*

RFC 5176: *RADIUS 的动态授权扩展*

RFC 5607: *NAS 管理的 RADIUS 授权*

RFC 5997: *RADIUS 协议中状态服务器数据包的使用*

RFC 6158: *RADIUS 设计指南*

RFC 6218: *Cisco 特定供应商的 RADIUS 属性用于密钥材料的传递*

RFC 6421: *远程认证拨号用户服务（RADIUS）的密码敏捷要求*

RFC 6911: *IPv6 访问网络的 RADIUS 属性*

RFC 6929: *远程认证拨号用户服务（RADIUS）协议扩展*

RFC 8044: *RADIUS 中的数据类型*

+   AD/SMB 集成:

[`wiki.freeradius.org/guide/freeradius-active-directory-integration-howto`](https://wiki.freeradius.org/guide/freeradius-active-directory-integration-howto)

[`web.mit.edu/rhel-doc/5/RHEL-5-manual/Deployment_Guide-en-US/s1-samba-security-modes.html`](https://web.mit.edu/rhel-doc/5/RHEL-5-manual/Deployment_Guide-en-US/s1-samba-security-modes.html)

[`wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member`](https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Domain_Member)

+   802.1x: [`isc.sans.edu/diary/The+Other+Side+of+Critical +Control+1%3A+802.1x+Wired+Network+Access+Controls/25146`](https://isc.sans.edu/diary/The+Other+Side+of+Critical+Control+1%3A+802.1x+Wired+Network+Access+Controls/25146)

+   Unlang 参考:

[`networkradius.com/doc/3.0.10/unlang/home.html`](https://networkradius.com/doc/3.0.10/unlang/home.html)

[`freeradius.org/radiusd/man/unlang.txt`](https://freeradius.org/radiusd/man/unlang.txt)


# 第十章：Linux 负载均衡器服务

在本章中，我们将讨论适用于 Linux 的负载均衡器服务，具体来说是 HAProxy。负载均衡器允许客户端工作负载分布到多个后端服务器。这允许单个 IP 扩展到比单个服务器更大，并且在服务器故障或维护窗口的情况下也允许冗余。

完成这些示例后，您应该具备通过几种不同的方法在自己的环境中部署基于 Linux 的负载均衡器服务的技能。

特别是，我们将涵盖以下主题：

+   负载均衡简介

+   负载均衡算法

+   服务器和服务健康检查

+   数据中心负载均衡器设计考虑

+   构建 HAProxy NAT/代理负载均衡器

+   关于负载均衡器安全性的最后说明

由于设置此部分的基础设施的复杂性，您可以在示例配置方面做出一些选择。

# 技术要求

在本章中，我们将探讨负载均衡器功能。当我们在本书的后面示例中工作时，您可以跟着进行，并在当前 Ubuntu 主机或虚拟机中实施我们的示例配置。但是，要看到我们的负载均衡示例的实际效果，您需要一些东西：

+   至少有两个目标主机来平衡负载

+   当前 Linux 主机中的另一个网络适配器

+   另一个子网来托管目标主机和这个新的网络适配器

此配置有一个匹配的图表，*图 10.2*，将在本章后面显示，说明了当我们完成时所有这些将如何连接在一起。

这给我们的实验室环境的配置增加了一整个层次的复杂性。当我们到达实验室部分时，我们将提供一些替代方案（下载预构建的虚拟机是其中之一），但您也可以选择跟着阅读。如果是这种情况，我认为您仍然会对这个主题有一个很好的介绍，以及对现代数据中心中各种负载均衡器配置的设计、实施和安全影响有一个扎实的背景。

# 负载均衡简介

在其最简单的形式中，负载均衡就是将客户端负载分布到多个服务器上。这些服务器可以在一个或多个位置，以及分配负载的方法可以有很大的不同。事实上，您在均匀分配负载方面的成功程度也会有很大的不同（主要取决于所选择的方法）。让我们探讨一些更常见的负载均衡方法。

## 循环 DNS（RRDNS）

您可以只使用 DNS 服务器进行简单的负载均衡，即所谓的`a.example.com`主机名，DNS 服务器将返回服务器 1 的 IP；然后，当下一个客户端请求时，它将返回服务器 2 的 IP，依此类推。这是最简单的负载均衡方法，对于共同放置的服务器和不同位置的服务器同样有效。它也可以在基础设施上不做任何更改-没有新组件，也没有配置更改：

![图 10.1-循环 DNS 的简单负载均衡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_001.jpg)

图 10.1-循环 DNS 的简单负载均衡

配置 RRDNS 很简单-在 BIND 中，只需为目标主机名配置多个`A`记录，其中包含多个 IP。连续的 DNS 请求将按顺序返回每个`A`记录。将域的`A`记录缩短是个好主意，以便按顺序（顺序返回匹配的记录）、随机或固定（始终以相同顺序返回匹配的记录）。更改返回顺序的语法如下（`cyclic`，默认设置，如下所示）：

```
options { 
    rrset-order { 
        class IN type A name "mytargetserver.example.com" order cyclic; 
    }; 
}; 
```

这种配置存在一些问题：

+   在这种模型中，没有好的方法来整合任何类型的健康检查-所有服务器是否正常运行？服务是否正常？主机是否正常？

+   没有办法看到任何 DNS 请求是否实际上会跟随连接到服务。有各种原因可能会发出 DNS 请求，并且交互可能就此结束，没有后续连接。

+   也没有办法监视会话何时结束，这意味着没有办法将下一个请求发送到最少使用的服务器 - 它只是在所有服务器之间稳定地轮换。因此，在任何工作日的开始，这可能看起来像一个好模型，但随着一天的进展，总会有持续时间更长的会话和极短的会话（或根本没有发生的会话），因此很常见看到服务器负载在一天进展过程中变得“不平衡”。如果没有明确的一天开始或结束来有效地“清零”，这种情况可能会变得更加明显。

+   出于同样的原因，如果集群中的一个服务器因维护或非计划中断而下线，没有好的方法将其恢复到与会话计数相同的状态。

+   通过一些 DNS 侦察，攻击者可以收集所有集群成员的真实 IP，然后分别评估它们或对它们进行攻击。如果其中任何一个特别脆弱或具有额外的 DNS 条目标识它为备用主机，这将使攻击者的工作变得更加容易。

+   将任何目标服务器下线可能会成为一个问题 - DNS 服务器将继续按请求的顺序提供该地址。即使记录被编辑，任何下游客户端和 DNS 服务器都将缓存其解析的 IP，并继续尝试连接到已关闭的主机。

+   下游 DNS 服务器（即互联网上的服务器）将在区域的 TTL 周期内缓存它们获取的任何记录。因此，任何这些 DNS 服务器的客户端都将被发送到同一个目标服务器。

因此，RRDNS 可以在紧急情况下简单地完成工作，但通常不应将其实施为长期的生产解决方案。也就是说，**全局服务器负载均衡器**（**GSLB**）产品实际上是基于这种方法的，具有不同的负载均衡选项和健康检查。负载均衡器与目标服务器之间的断开在 GSLB 中仍然存在，因此许多相同的缺点也适用于这种解决方案。

在数据中心中，我们更经常看到基于代理（第 7 层）或基于 NAT（第 4 层）的负载均衡。让我们探讨这两个选项。

## 入站代理 - 第 7 层负载均衡

在这种架构中，客户端的会话在代理服务器上终止，并在代理的内部接口和真实服务器 IP 之间启动新的会话。

这也提出了许多在许多负载均衡解决方案中常见的架构术语。在下图中，我们可以看到**前端**的概念，面向客户端，以及**后端**，面向服务器。我们还应该在这一点上讨论 IP 地址。前端呈现了所有目标服务器共享的**虚拟 IP**（**VIP**），客户端根本看不到服务器的**真实 IP**（**RIPs**）：

![图 10.2 - 使用反向代理进行负载均衡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_002.jpg)

图 10.2 - 使用反向代理进行负载均衡

这种方法有一些缺点：

+   在本章讨论的所有方法中，它对负载均衡器的 CPU 负载最高，并且在极端情况下可能会对客户端产生性能影响。

+   此外，由于目标服务器上的客户端流量都来自代理服务器（或服务器），如果没有一些特殊处理，那么在目标/应用程序服务器上看到的客户端 IP 将始终是负载均衡器的后端 IP。这使得在应用程序中记录直接客户端交互成为问题。要从一个会话中解析出流量并将其与客户端的实际地址相关联，我们必须将负载均衡器的客户端会话（它看到客户端 IP 地址但看不到用户身份）与应用程序/网络服务器日志（它看到用户身份但看不到客户端 IP 地址）进行匹配。在这些日志之间匹配会话可能是一个真正的问题；它们之间的共同元素是负载均衡器上的时间戳和源端口，而源端口通常不在 Web 服务器上。

+   这可以通过具有一些应用程序意识来减轻。例如，常见的是为 Citrix ICA 服务器或 Microsoft RDP 服务器后端设置 TLS 前端。在这些情况下，代理服务器对协议有一些出色的“钩子”，允许客户端 IP 地址一直传递到服务器，并且负载均衡器检测到的身份也被检测到。

然而，使用代理架构允许我们完全检查流量是否受到攻击，如果工具设置好的话。实际上，由于代理架构，负载均衡器和目标服务器之间的最后一个“跳跃”是一个全新的会话 - 这意味着无效的协议攻击大部分被过滤掉，而无需进行任何特殊配置。

我们可以通过将负载均衡器作为入站**网络地址转换**（**NAT**）配置来减轻代理方法的一些复杂性。当不需要解密时，NAT 方法通常是常见的，并内置于大多数环境中。

## 入站 NAT - 第 4 层负载平衡

这是最常见的解决方案，也是我们在示例中将要开始使用的解决方案。在许多方面，这种架构看起来与代理解决方案相似，但有一些关键的区别。请注意，在下图中，前端和后端的 TCP 会话现在匹配 - 这是因为负载均衡器不再是代理；它已被配置为入站 NAT 服务。所有客户端仍然连接到单个 VIP，并由负载均衡器重定向到各种服务器 RIP：

![图 10.3 - 使用入站 NAT 进行负载平衡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_003.jpg)

图 10.3 - 使用入站 NAT 进行负载平衡

在许多情况下，这是首选架构的几个原因：

+   服务器看到客户端的真实 IP，并且服务器日志正确地反映了这一点。

+   负载均衡器在内存中维护 NAT 表，负载均衡器日志反映了各种 NAT 操作，但无法“看到”会话。例如，如果服务器正在运行 HTTPS 会话，如果这是一个简单的第 4 层 NAT，则负载均衡器可以看到 TCP 会话，但无法解密流量。

+   我们可以选择在前端终止 HTTPS 会话，然后在此架构中在后端运行加密或明文。然而，由于我们维护了两个会话（前端和后端），这开始看起来更像是代理配置。

+   由于负载均衡器看到整个 TCP 会话（直到第 4 层），现在可以使用多种负载平衡算法（有关更多信息，请参见负载平衡算法的下一节）。

+   这种架构允许我们在负载均衡器上放置**Web 应用程序防火墙**（**WAF**）功能，这可以掩盖目标服务器 Web 应用程序上的一些漏洞。例如，WAF 是对跨站脚本或缓冲区溢出攻击的常见防御，或者任何可能依赖输入验证中断的攻击。对于这些类型的攻击，WAF 识别任何给定字段或 URI 的可接受输入，然后丢弃任何不匹配的输入。但是，WAF 并不局限于这些攻击。将 WAF 功能视为 Web 特定的 IPS（见*第十四章*，*Linux 上的蜜罐服务*）。

+   这种架构非常适合使会话持久或“粘性” - 我们的意思是一旦客户端会话“附加”到服务器，随后的请求将被定向到同一台服务器。这非常适合具有后端数据库的页面，例如，如果您不保持相同的后端服务器，您的活动（例如，电子商务网站上的购物车）可能会丢失。动态或参数化网站 - 在这些网站上，页面在您导航时实时生成（例如，大多数具有产品目录或库存的网站） - 通常也需要会话持久性。

+   您还可以独立地负载均衡每个连续的请求，因此，例如，当客户端浏览网站时，他们的会话可能会在每个页面由不同的服务器终止。这种方法非常适合静态网站。

+   您可以在这种架构的基础上叠加其他功能。例如，这些通常与防火墙并行部署，甚至与公共互联网上的本机接口并行部署。因此，您经常会看到负载均衡器供应商配备 VPN 客户端以配合其负载均衡器。

+   如前图所示，入站 NAT 和代理负载均衡器具有非常相似的拓扑结构 - 连接看起来都非常相似。这一点延续到了实现中，可以看到一些东西通过代理和一些东西通过同一负载均衡器上的 NAT 过程。

然而，即使这种配置的 CPU 影响远低于代理解决方案，每个工作负载数据包仍必须通过负载均衡器在两个方向上进行路由。我们可以使用**直接服务器返回**（**DSR**）架构大大减少这种影响。

## DSR 负载平衡

在 DSR 中，所有传入的流量仍然从负载均衡器上的 VIP 负载均衡到各个服务器的 RIP。然而，返回流量直接从服务器返回到客户端，绕过负载均衡器。

这怎么可能？这是怎么回事：

+   在进入时，负载均衡器会重写每个数据包的 MAC 地址，将它们负载均衡到目标服务器的 MAC 地址上。

+   每台服务器都有一个环回地址，这是一个配置的地址，与 VIP 地址匹配。这是返回所有流量的接口（因为客户端期望从 VIP 地址返回流量）。但是，它必须配置为不回复 ARP 请求（否则，负载均衡器将在入站路径上被绕过）。

这可能看起来很复杂，但以下图表应该使事情变得更清晰一些。请注意，此图表中只有一个目标主机，以使流量流动更容易看到：

![图 10.4 - DSR 负载平衡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_004.jpg)

图 10.4 - DSR 负载平衡

构建这个的要求非常严格：

+   负载均衡器和所有目标服务器都需要在同一个子网上。

+   这种机制需要在默认网关上进行一些设置，因为在进入时，它必须将所有客户端流量定向到负载均衡器上的 VIP，但它还必须接受来自具有相同地址但不同 MAC 地址的多个目标服务器的回复。这个必须有一个 ARP 条目，对于每个目标服务器，都有相同的 IP 地址。在许多架构中，这是通过多个静态 ARP 条目来完成的。例如，在 Cisco 路由器上，我们会这样做：

```
arp 192.168.124.21 000c.2933.2d05 arpa
arp 192.168.124.22 000c.29ca.fbea arpa
```

请注意，在这个例子中，`192.168.124.21`和`22`是被负载均衡的目标主机。此外，MAC 地址具有 OUI，表明它们都是 VMware 虚拟主机，在大多数数据中心都是典型的。

为什么要经历所有这些麻烦和不寻常的网络配置？

+   DSR 配置的优势在于大大减少了通过负载均衡器的流量。例如，在 Web 应用程序中，通常会看到返回流量超过传入流量的 10 倍以上。这意味着对于这种流量模型，DSR 实现将看到负载均衡器将看到的流量的 90%或更少。

+   不需要“后端”子网；负载均衡器和目标服务器都在同一个子网中 - 实际上，这是一个要求。这也有一些缺点，正如我们已经讨论过的那样。我们将在*DSR 的特定服务器设置*部分详细介绍这一点。

然而，也有一些缺点：

+   集群中的相对负载，或者任何一个服务器上的个体负载，最多只能由负载均衡器推断出来。如果一个会话正常结束，负载均衡器将捕捉到足够的“会话结束”握手来判断会话已经结束，但如果一个会话没有正常结束，它完全依赖超时来结束会话。

+   所有主机必须配置相同的 IP（原始目标），以便返回流量不会来自意外的地址。这通常是通过环回接口完成的，并且通常需要对主机进行一些额外的配置。

+   上游路由器（或者如果它是子网的网关，则是第 3 层交换机）需要配置为允许目标 IP 地址的所有可能的 MAC 地址。这是一个手动过程，如果可能看到 MAC 地址意外更改，这可能是一个问题。

+   如果任何需要代理或完全可见会话的功能（如 NAT 实现中）无法工作，负载均衡器只能看到会话的一半。这意味着任何 HTTP 头解析、cookie 操作（例如会话持久性）或 SYN cookie 都无法实现。

此外，因为（就路由器而言）所有目标主机具有不同的 MAC 地址但相同的 IP 地址，而目标主机不能回复任何 ARP 请求（否则，它们将绕过负载均衡器），因此需要在目标主机上进行大量的工作。

### DSR 的特定服务器设置

对于 Linux 客户端，必须对“VIP”寻址接口（无论是环回还是逻辑以太网）进行 ARP 抑制。可以使用`sudo ip link set <interface name> arp off`或（使用较旧的`ifconfig`语法）`sudo ifconfig <interface name> -arp`来完成。

您还需要在目标服务器上实现“强主机”和“弱主机”设置。如果服务器接口不是路由器，并且不能发送或接收来自接口的数据包，除非数据包中的源或目的 IP 与接口 IP 匹配，则将其配置为“强主机”。如果接口已配置为“弱主机”，则不适用此限制-它可以代表其他接口接收或发送数据包。

Linux 和 BSD Unix 默认在所有接口上启用了`weak host`（`sysctl net.ip.ip.check_interface = 0`）。Windows 2003 及更早版本也启用了这个功能。但是，Windows Server 2008 及更高版本为所有接口采用了`strong host`模型。要更改新版本 Windows 中的 DSR，执行以下代码：

```
netsh interface ipv4 set interface "Local Area Connection" weakhostreceive=enabled
netsh interface ipv4 set interface "Loopback" weakhostreceive=enabled
netsh interface ipv4 set interface "Loopback" weakhostsend=enabled 
```

您还需要在目标服务器上禁用任何 IP 校验和 TCP 校验和卸载功能。在 Windows 主机上，这两个设置位于`网络适配器/高级`设置中。在 Linux 主机上，`ethtool`命令可以操作这些设置，但这些基于硬件的卸载功能在 Linux 中默认情况下是禁用的，因此通常不需要调整它们。

在描述的各种架构中，我们仍然需要确定如何精确地分配客户端负载到我们的目标服务器组。

# 负载平衡算法

到目前为止，我们已经涉及了一些负载平衡算法，让我们更详细地探讨一下更常见的方法（请注意，这个列表不是详尽无遗的；这里只提供了最常见的方法）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_Table_01.jpg)

**最少连接**，正如你可能期望的那样，是最常分配的算法。我们将在本章后面的配置示例中使用这种方法。

既然我们已经看到了如何平衡工作负载的一些选项，那么我们如何确保那些后端服务器正常工作呢？

# 服务器和服务健康检查

我们在 DNS 负载平衡部分讨论的问题之一是健康检查。一旦开始负载平衡，通常希望有一种方法来知道哪些服务器（和服务）正在正确运行。检查任何连接的*健康*的方法包括以下内容：

1.  定期使用 ICMP 有效地“ping”目标服务器。如果没有 ICMP 回显回复，则认为它们宕机，并且不会接收任何新的客户端。现有客户端将分布在其他服务器上。

1.  使用 TCP 握手并检查开放端口（例如`80/tcp`和`443/tcp`用于 Web 服务）。同样，如果握手未完成，则主机被视为宕机。

1.  在 UDP 中，您通常会发出应用程序请求。例如，如果您正在负载均衡 DNS 服务器，负载均衡器将进行简单的 DNS 查询-如果收到 DNS 响应，则认为服务器正常运行。

1.  最后，在平衡 Web 应用程序时，您可以进行实际的 Web 请求。通常，您会请求索引页面（或任何已知页面）并查找该页面上的已知文本。如果该文本不出现，则该主机和服务组合被视为宕机。在更复杂的环境中，您检查的测试页面可能会对后端数据库进行已知调用以进行验证。

测试实际应用程序（如前两点所述）当然是验证应用程序是否正常工作的最可靠方法。

我们将在示例配置中展示一些这些健康检查。在我们开始之前，让我们深入了解一下您可能会在典型数据中心中看到负载均衡器的实现方式-无论是在“传统”配置中还是在更现代的实现中。

# 数据中心负载均衡器设计考虑

负载平衡已经成为较大架构的一部分几十年了，这意味着我们经历了几种常见的设计。

我们经常看到的“传统”设计是一个单一对（或集群）物理负载均衡器，为数据中心中的所有负载平衡工作负载提供服务。通常，相同的负载均衡器集群用于内部和外部工作负载，但有时，您会看到一个内部负载均衡器对内部网络进行服务，另一个对只服务 DMZ 工作负载（即对外部客户端）的负载均衡器对外部工作负载进行服务。

这种模型在我们拥有物理服务器且负载均衡器是昂贵的硬件的时代是一个很好的方法。

然而，在虚拟化环境中，工作负载 VM 绑定到物理负载均衡器，这使得网络配置复杂化，限制了灾难恢复选项，并且通常导致流量在（物理）负载均衡器和虚拟环境之间进行多次“循环”：

![图 10.5 - 传统负载均衡架构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_005.jpg)

图 10.5 - 传统负载均衡架构

随着虚拟化的出现，一切都发生了变化。现在使用物理负载均衡器几乎没有意义 - 最好是为每个工作负载使用专用的小型虚拟机，如下所示：

![图 10.6 - 现代负载均衡架构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_006.jpg)

图 10.6 - 现代负载均衡架构

这种方法有几个优点：

+   **成本**是一个优势，因为这些小型虚拟负载均衡器如果获得许可要便宜得多，或者如果使用诸如 HAProxy（或任何其他免费/开源解决方案）的解决方案则是免费的。这可能是影响最小的优势，但毫不奇怪通常是改变意见的因素。

+   **配置要简单得多**，更容易维护，因为每个负载均衡器只服务一个工作负载。如果进行了更改并且可能需要后续调试，从较小的配置中“挑出”某些东西要简单得多。

+   在发生故障或更可能的是配置错误时，**散射区**或**影响范围**要小得多。如果将每个负载均衡器绑定到单个工作负载，任何错误或故障更可能只影响该工作负载。

+   此外，从运营的角度来看，**使用编排平台或 API 来扩展工作负载要简单得多**（根据需求增加或删除后端服务器到集群）。这种方法使得构建这些 playbook 要简单得多 - 主要是因为配置更简单，在 playbook 出错时影响范围更小。

+   **开发人员更快的部署**。由于您保持了这种简单的配置，在开发环境中，您可以在开发或修改应用程序时向开发人员提供这种配置。这意味着应用程序是针对负载均衡器编写的。此外，大部分测试是在开发周期内完成的，而不是在开发结束时在单个更改窗口中进行配置和测试。即使负载均衡器是有许可的产品，大多数供应商也为这种情况提供了免费（低带宽）许可的产品。

+   向开发人员或部署提供**安全配置的模板**要简单得多。

+   **在开发或 DevOps 周期中进行安全测试**包括负载均衡器，而不仅仅是应用程序和托管服务器。

+   **培训和测试要简单得多**。由于负载均衡产品是免费的，设置培训或测试环境是快速简单的。

+   **工作负载优化**是一个重要的优势，因为在虚拟化环境中，通常可以将一组服务器“绑定”在一起。例如，在 VMware vSphere 环境中，这被称为**vApp**。这个结构允许您将所有 vApp 成员一起保持在一起，例如，如果您将它们 vMotion 到另一个 hypervisor 服务器。您可能需要进行这样的操作进行维护，或者这可能会自动发生，使用**动态资源调度**（**DRS**），它可以在多个服务器之间平衡 CPU 或内存负载。或者，迁移可能是灾难恢复工作流的一部分，您可以将 vApp 迁移到另一个数据中心，使用 vMotion 或者简单地激活一组 VM 的副本。

+   **云部署更适合这种分布式模型**。在较大的云服务提供商中，这一点被推到了极致，负载平衡只是一个您订阅的服务，而不是一个离散的实例或虚拟机。其中包括 AWS 弹性负载均衡服务、Azure 负载均衡器和 Google 的云负载均衡服务。

负载平衡带来了一些管理挑战，其中大部分源于一个问题 - 如果所有目标主机都有负载平衡器的默认网关，我们如何监视和管理这些主机？

## 数据中心网络和管理考虑

如果使用 NAT 方法对工作负载进行负载平衡，路由就成了一个问题。潜在应用程序客户端的路由必须指向负载平衡器。如果这些目标是基于互联网的，这将使管理单个服务器成为一个问题 - 您不希望服务器管理流量被负载平衡。您也不希望不必要的流量（例如备份或大容量文件复制）通过负载平衡器路由 - 您希望它路由应用程序流量，而不是所有流量！

这通常通过添加静态路由和可能的管理 VLAN 来处理。

现在是一个好时机提出，管理 VLAN 应该从一开始就存在 - 我对管理 VLAN 的“赢得一点”的短语是“您的会计组（或接待员或制造组）需要访问您的 SAN 或超级管理员登录吗？”如果您可以得到一个答案，让您朝着保护内部攻击的敏感接口的方向，那么管理 VLAN 就很容易实现。

无论如何，在这种模型中，默认网关仍然指向负载平衡器（为了服务互联网客户端），但是特定路由被添加到服务器以指向内部或服务资源。在大多数情况下，这些资源的列表仍然很小，因此即使内部客户端计划使用相同的负载平衡应用程序，这仍然可以工作：

![图 10.7 - 路由非应用流量（高级）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_007.jpg)

图 10.7 - 路由非应用流量（高级）

如果出于某种原因这种模型无法工作，那么您可能需要考虑添加**基于策略的路由**（**PBR**）。

在这种情况下，例如，您的服务器正在负载平衡 HTTP 和 HTTPS - 分别是`80/tcp`和`443/tcp`。您的策略可能如下所示：

+   将所有流量`80/tcp`和`443/tcp`路由到负载平衡器（换句话说，从应用程序的回复流量）。

+   将所有其他流量通过子网路由器路由。

这个策略路由可以放在服务器子网的路由器上，如下所示：

![图 10.8 - 路由非应用流量 - 在上游路由器上的策略路由](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_008.jpg)

图 10.8 - 路由非应用流量 - 在上游路由器上的策略路由

在上图中，服务器都有基于路由器接口的默认网关（在本例中为`10.10.10.1`）：

```
! this ACL matches reply traffic from the host to the client stations
ip access-list ACL-LB-PATH
   permit tcp any eq 443 any
   permit tcp any eq 90 any
! regular default gateway, does not use the load balancer, set a default gateway for that
ip route 0.0.0.0 0.0.0.0 10.10.x.1
! this sets the policy for the load balanced reply traffic
route-map RM-LB-PATH permit 10
   match ip address ACL-LB-BYPASS
   set next-hop 10.10.10.5
! this applies the policy to the L3 interface.
! note that we have a "is that thing even up" check before we forward the traffic
int vlan x
ip policy route-map RM-LB-PATH
 set ip next-hop verify-availability 10.10.10.5 1 track 1
 set ip next-hop 10.10.10.5
! track 1 is defined here
track 1 rtr 1 reachability
rtr 1
type echo protocol ipIcmpEcho 10.10.10.5
rtr schedule 1 life forever start-time now
```

这样做的好处是简单，但是这个子网默认网关设备必须有足够的性能来满足所有回复流量的需求，而不会影响其其他工作负载的性能。幸运的是，许多现代的 10G 交换机确实有这样的性能。然而，这也有一个缺点，即您的回复流量现在离开了超级管理员，到达了默认网关路由器，然后很可能再次进入虚拟基础设施以到达负载平衡器。在某些环境中，这在性能上仍然可以工作，但如果不行，考虑将策略路由移动到服务器本身。

要在 Linux 主机上实现相同的策略路由，按照以下步骤进行：

1.  首先，将路由添加到`表 5`：

```
ip route add table 5 0.0.0.0/0 via 10.10.10.5
```

1.  定义与负载平衡器匹配的流量（源`10.10.10.0/24`，源端口`443`）：

```
iptables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --sport 443 -s 10.10.10.0/24 -j MARK --set-mark 2
iptables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --sport 80 -s 10.10.10.0/24 -j MARK --set-mark 2
```

1.  添加查找，如下所示：

```
ip rule add fwmark 2 lookup 5
```

这种方法比大多数人想要的更复杂，CPU 开销也更大。另外，对于“网络路由问题”，支持人员更有可能在未来的故障排除中首先查看路由器和交换机，而不是主机配置。出于这些原因，我们经常看到将策略路由放在路由器或三层交换机上被实施。

使用管理接口更加优雅地解决了这个问题。另外，如果管理接口在组织中尚未广泛使用，这种方法可以很好地将其引入环境中。在这种方法中，我们保持目标主机配置为默认网关指向负载均衡器。然后，我们为每个主机添加一个管理 VLAN 接口，可能直接在该 VLAN 中提供一些管理服务。此外，根据需要，我们仍然可以添加到诸如 SNMP 服务器、日志服务器或其他内部或互联网目的地的特定路由：

![图 10.9 – 添加管理 VLAN](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_009.jpg)

图 10.9 – 添加管理 VLAN

不用说，这是常见的实施方式。这不仅是最简单的方法，而且还为架构添加了一个非常需要的管理 VLAN。

在大部分理论已经涵盖的情况下，让我们开始构建几种不同的负载均衡场景。

# 构建 HAProxy NAT/代理负载均衡器

首先，我们可能不想使用我们的示例主机，因此我们必须添加一个新的网络适配器来演示 NAT/代理（L4/L7）负载均衡器。

如果您的示例主机是虚拟机，构建一个新的应该很快。或者更好的是，克隆您现有的虚拟机并使用它。或者，您可以下载一个`haproxy –v`。

或者，如果您选择不使用我们的示例配置进行“构建”，您仍然可以“跟随”。虽然为负载均衡器构建管道可能需要一些工作，但实际配置非常简单，我们的目标是介绍您到该配置。您完全可以在不构建支持虚拟或物理基础设施的情况下实现这一目标。

如果您正在新的 Linux 主机上安装此软件，请确保您有两个网络适配器（一个面向客户端，一个面向服务器）。与往常一样，我们将从安装目标应用程序开始：

```
$ sudo apt-get install haproxy
```

*<如果您正在使用基于 OVA 的安装，请从这里开始：>*

您可以通过使用`haproxy`应用程序本身来检查版本号来验证安装是否成功：

```
$ haproxy –v
HA-Proxy version 2.0.13-2ubuntu0.1 2020/09/08 - https://haproxy.org/
```

请注意，任何新版本都应该可以正常工作。

安装了软件包后，让我们来看看我们的示例网络构建。

## 在开始配置之前 – 网卡、寻址和路由

您可以使用任何您选择的 IP 地址，但在我们的示例中，前端为`192.168.122.21/24`（请注意，这与主机的接口 IP 不同），而负载均衡器的后端地址将为`192.168.124.1/24` – 这将是目标主机的默认网关。我们的目标 Web 服务器将为`192.168.124.10`和`192.168.124.20`。

我们的最终构建将如下所示：

![图 10.10 – 负载均衡器示例构建](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_010.jpg)

图 10.10 – 负载均衡器示例构建

在我们开始构建负载均衡器之前，现在是调整 Linux 中一些设置的最佳时机（其中一些需要重新加载系统）。

## 在开始配置之前 – 性能调优

一个基本的“开箱即用”的 Linux 安装必须对各种设置做出一些假设，尽管其中许多会导致性能或安全方面的妥协。对于负载均衡器，有几个 Linux 设置需要解决。幸运的是，HAProxy 安装为我们做了很多这方面的工作（如果我们安装了许可版本）。安装完成后，编辑`/etc/sysctl.d/30-hapee-2.2.conf`文件，并取消注释以下代码中的行（在我们的情况下，我们正在安装社区版，因此创建此文件并取消注释这些行）。与所有基本系统设置一样，测试这些设置时，逐个或逻辑分组进行更改。此外，正如预期的那样，这可能是一个迭代过程，您可能需要在一个设置和另一个设置之间来回。正如文件注释中所指出的，并非所有这些值在所有情况下甚至在大多数情况下都是推荐的。

这些设置及其描述都可以在[`www.haproxy.com/documentation/hapee/2-2r1/getting-started/system-tuning/`](https://www.haproxy.com/documentation/hapee/2-2r1/getting-started/system-tuning/)找到。

限制每个套接字的默认接收/发送缓冲区，以限制在大量并发连接时的内存使用。这些值以字节表示，分别代表最小值、默认值和最大值。默认值是`4096`、`87380`和`4194304`：

```
    # net.ipv4.tcp_rmem            = 4096 16060 262144
    # net.ipv4.tcp_wmem            = 4096 16384 262144
```

允许对传出连接早期重用相同的源端口。如果每秒有几百个连接，这是必需的。默认值如下：

```
    # net.ipv4.tcp_tw_reuse        = 1
```

扩展传出 TCP 连接的源端口范围。这限制了早期端口重用，并使用了`64000`个源端口。默认值为`32768`和`61000`：

```
    # net.ipv4.ip_local_port_range = 1024 65023
```

增加 TCP SYN 积压大小。这通常需要支持非常高的连接速率，以及抵抗 SYN 洪水攻击。然而，设置得太高会延迟 SYN cookie 的使用。默认值是`1024`：

```
    # net.ipv4.tcp_max_syn_backlog = 60000
```

设置`tcp_fin_wait`状态的超时时间（以秒为单位）。降低它可以加快释放死连接，尽管它会在 25-30 秒以下引起问题。如果可能的话最好不要更改它。默认值为`60`：

```
    # net.ipv4.tcp_fin_timeout     = 30
```

限制传出 SYN-ACK 重试次数。这个值是 SYN 洪水的直接放大因子，所以保持它相当低是很重要的。然而，将它设置得太低会阻止丢包网络上的客户端连接。

使用`3`作为默认值可以得到良好的结果（总共 4 个 SYN-ACK），而在 SYN 洪水攻击下将其降低到`1`可以节省大量带宽。默认值为`5`：

```
    # net.ipv4.tcp_synack_retries  = 3
```

将其设置为`1`以允许本地进程绑定到系统上不存在的 IP。这通常发生在共享 VRRP 地址的情况下，您希望主备两者都启动，即使 IP 不存在。始终将其保留为`1`。默认值为`0`：

```
    # net.ipv4.ip_nonlocal_bind    = 1
```

以下作为系统所有 SYN 积压的上限。将它至少设置为`tcp_max_syn_backlog`一样高；否则，客户端可能在高速率或 SYN 攻击下连接时遇到困难。默认值是`128`：

```
     # net.core.somaxconn           = 60000
```

再次注意，如果您进行了任何这些更改，您可能会在以后回到这个文件来撤消或调整您的设置。完成所有这些（至少现在是这样），让我们配置我们的负载均衡器，使其与我们的两个目标 Web 服务器配合工作。

## 负载均衡 TCP 服务 - Web 服务

负载均衡服务的配置非常简单。让我们从在两个 Web 服务器主机之间进行负载均衡开始。

让我们编辑`/etc/haproxy/haproxy.cfg`文件。我们将创建一个`frontend`部分，定义面向客户端的服务，以及一个`backend`部分，定义两个下游 Web 服务器： 

```
frontend http_front
   bind *:80
   stats uri /haproxy?stats
   default_backend http_back
backend  http_back
   balance roundrobin
   server WEBSRV01 192.168.124.20:80 check fall 3 rise 2
   server WEBSRV02 192.168.124.21:80 check fall 3 rise 2
```

请注意以下内容：

+   前端部分中有一行`default backend`，告诉它将哪些服务绑定到该前端。

+   前端有一个`bind`语句，允许负载在该接口上的所有 IP 之间平衡。因此，在这种情况下，如果我们只使用一个 VIP 进行负载平衡，我们可以在负载均衡器的物理 IP 上执行此操作。

+   后端使用`roundrobin`作为负载平衡算法。这意味着当用户连接时，他们将被引导到 server1，然后是 server2，然后是 server1，依此类推。

+   `check`参数告诉服务检查目标服务器以确保其正常运行。当负载平衡 TCP 服务时，这要简单得多，因为简单的 TCP“连接”就可以解决问题，至少可以验证主机和服务是否正在运行。

+   `fall 3`在连续三次失败的检查后将服务标记为离线，而`rise 2`在两次成功的检查后将其标记为在线。这些 rise/fall 关键字可以在使用任何检查类型时使用。

我们还希望在此文件中有一个全局部分，以便我们可以设置一些服务器参数和默认值：

```
global
    maxconn 20000
    log /dev/log local0
    user haproxy
    group haproxy
    stats socket /run/haproxy/admin.sock user haproxy group haproxy mode 660 level admin
    nbproc 2
    nbthread 4
    timeout http-request <timeout>
    timeout http-keep-alive <timeout>
    timeout queue <timeout>
    timeout client-fin <timeout>
    timeout server-fin <timeout>
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
```

请注意，我们在此部分定义了用户和组。回溯到*第三章*，*使用 Linux 和 Linux 工具进行网络诊断*，我们提到，如果端口号小于`1024`，您需要具有 root 权限才能启动侦听端口。对于 HAProxy 来说，这意味着它需要 root 权限来启动服务。全局部分中的用户和组指令允许服务“降级”其权限。这很重要，因为如果服务被攻击，拥有较低权限会给攻击者提供更少的选项，可能增加攻击所需的时间，并希望增加他们被抓获的可能性。

`log`行非常直接 - 它告诉`haproxy`将日志发送到哪里。如果您有任何需要解决的负载平衡问题，这是一个很好的起点，接着是目标服务的日志。

`stats`指令告诉`haproxy`存储其各种性能统计信息的位置。

`nbproc`和`nbpthread`指令告诉 HAProxy 服务可用于使用的处理器和线程数量。这些数字应该至少比可用的进程少一个，以便在拒绝服务攻击发生时，整个负载平衡器平台不会瘫痪。

各种超时参数用于防止协议级拒绝服务攻击。在这些情况下，攻击者发送初始请求，但随后从不继续会话 - 他们只是不断发送请求，“耗尽”负载均衡器资源，直到内存完全耗尽。这些超时限制了负载均衡器将保持任何一个会话活动的时间。下表概述了我们在这里讨论的每个保持活动参数的简要描述：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_10_Table_02.jpg)

此外，SSL 指令相当容易理解：

+   `ssl-default-bind-ciphers`列出了在任何 TLS 会话中允许的密码，如果负载均衡器正在终止或启动会话（即，如果您的会话处于代理或第 7 层模式）。

+   `ssl-default-bind-options`用于设置支持的 TLS 版本的下限。在撰写本文时，所有 SSL 版本以及 TLS 版本 1.0 都不再推荐使用。特别是 SSL 容易受到多种攻击。由于所有现代浏览器都能够协商 TLS 版本 3，大多数环境选择支持 TLS 版本 1.2 或更高版本（如示例中所示）。

现在，从客户端机器，您可以浏览到 HAProxy 主机，您会看到您将连接到其中一个后端。如果您尝试从不同的浏览器再次连接，您应该连接到第二个。

让我们扩展一下，为 HTTPS（在`443/tcp`上）添加支持。我们将在前端接口上添加一个 IP 并绑定到该 IP。我们将把平衡算法更改为最少连接。最后，我们将更改前端和后端的名称，以包括端口号。这使我们能够为`443/tcp`添加额外的配置部分。如果我们只监视第 4 层 TCP 会话，这些流量将得到很好的负载平衡；不需要解密：

```
frontend http_front-80
   bind 192.168.122.21:80
   stats uri /haproxy?stats
   default_backend http_back-80
frontend http_front-443
   bind 192.168.122.21:443
   stats uri /haproxy?stats
   default_backend http_back-443
backend  http_back-80
   balance leastconn
   server WEBSRV01 192.168.124.20:80 check fall 3 rise 2
   server WEBSRV02 192.168.124.21:80 check fall 3 rise 2
backend  http_back-443
   balance leastconn
   server WEBSRV01 192.168.124.20:443 check fall 3 rise 2
   server WEBSRV02 192.168.124.21:443 check fall 3 rise 2
```

请注意，我们仍然只是检查 TCP 端口是否对“服务器健康”检查打开。这通常被称为第 3 层健康检查。我们将端口`80`和`443`放入两个部分 - 这些可以合并到前端段的一个部分中，但通常最好将它们分开以便可以分别跟踪它们。这样做的副作用是两个后端部分的计数不会相互影响，但通常这不是一个问题，因为如今整个 HTTP 站点通常只是重定向到 HTTPS 站点。

另一种表达方式是在`listen`段上，而不是在前端和后端段上。这种方法将前端和后端部分合并到一个段中，并添加一个“健康检查”：

```
listen webserver 192.168.122.21:80
    mode http
    option httpchk HEAD / HTTP/1.0
    server websrv01 192.168.124.20:443 check fall 3 rise 2
    server websrv02 192.168.124.21:443 check fall 3 rise 2
```

这个默认的 HTTP 健康检查只是打开默认页面，并通过检查标题中的短语`HTTP/1.0`来确保有内容返回。如果在返回的页面中没有看到这个短语，就算作是一次失败的检查。您可以通过检查站点上的任何 URI 并查找该页面上的任意文本字符串来扩展此功能。这通常被称为“第 7 层”健康检查，因为它正在检查应用程序。但是请确保您的检查简单 - 如果应用程序即使稍微更改，页面返回的文本可能会发生足够的变化，导致您的健康检查失败，并意外地标记整个集群为离线！

## 建立持久（粘性）连接

让我们通过使用服务器名称的变体将 cookie 注入到 HTTP 会话中。我们还将对 HTTP 服务进行基本检查，而不仅仅是开放端口。我们将回到我们的“前端/后端”配置文件方法：

```
backend  http_back-80
   mode http
   balance leastconn
   cookie SERVERUSED insert indirect nocache
   option httpchk HEAD /
   server WEBSRV01 192.168.124.20:80 cookie WS01 check fall 3 rise 2
   server WEBSRV02 192.168.124.21:80 cookie WS02 check fall 3 rise 2
```

确保您不要使用服务器的 IP 地址或真实名称作为 cookie 值。如果使用真实服务器名称，攻击者可能会通过在 DNS 中查找该服务器名称或在具有历史 DNS 条目数据库的站点（例如`dnsdumpster.com`）来访问该服务器。服务器名称也可以用来从证书透明日志中获取有关目标的信息（正如我们在[*第八章*]（B16336_08_Final_NM_ePub.xhtml#_idTextAnchor133）中讨论的那样，*Linux 上的证书服务*）。最后，如果服务器 IP 地址用于 cookie 值，该信息将使攻击者对您的内部网络架构有所了解，如果披露的网络是公共可路由的，可能会成为他们的下一个目标！

## 实施说明

现在我们已经介绍了基本配置，一个非常常见的步骤是在每台服务器上都有一个“占位符”网站，每个网站都被标识为与服务器匹配。使用“1-2-3”，“a-b-c”或“red-green-blue”都是常见的方法，足以区分每个服务器会话。现在，使用不同的浏览器或不同的工作站，多次浏览共享地址，以确保您被定向到正确的后端服务器，如您的规则集所定义的那样。

当然，这是一个逐步构建配置的好方法，以确保事情正常运行，但它也是一个很好的故障排除机制，可以帮助您决定一些简单的事情，比如“更新后这还有效吗？”或“我知道帮助台票说了什么，但是真的有问题要解决吗？”甚至几个月甚至几年后。像这样的测试页面是一个很好的长期保留的东西，用于未来的测试或故障排除。

## HTTPS 前端

过去，服务器架构师乐意设置负载均衡器来卸载 HTTPS 处理，将加密/解密处理从服务器转移到负载均衡器。这样可以节省服务器 CPU，并且将实施和维护证书的责任转移到管理负载均衡器的人。然而，出于几个原因，这些原因现在大多数已经不再有效：

+   如果服务器和负载均衡器都是虚拟的（在大多数情况下是推荐的），这只是在不同虚拟机之间移动处理 - 没有净增益。

+   现代处理器在执行加密和解密方面效率更高 - 算法是针对 CPU 性能编写的。事实上，根据算法的不同，加密/解密操作可能是 CPU 的本地操作，这是一个巨大的性能提升。

+   使用通配符证书可以使整个“证书管理”过程变得更简单。

然而，我们仍然使用负载均衡器进行 HTTPS 前端处理，通常是为了使用 cookie 实现可靠的会话持久性 - 除非你能读取和写入数据流，否则无法在 HTTPS 响应中添加 cookie（或在下一个请求中读取），这意味着在某个时刻它已经被解密。

请记住，根据我们之前的讨论，在这个配置中，每个 TLS 会话将在前端终止，使用有效的证书。由于现在这是一个代理设置（第 7 层负载平衡），后端会话是一个单独的 HTTP 或 HTTPS 会话。在过去，后端通常会是 HTTP（主要是为了节省 CPU 资源），但在现代，这将被视为安全风险，特别是如果你在金融、医疗保健或政府部门（或任何承载敏感信息的部门）。因此，在现代构建中，后端几乎总是会是 HTTPS，通常使用目标 Web 服务器上相同的证书。

再次强调这种设置的缺点是，由于目标 Web 服务器的实际客户端是负载均衡器，`X-Forwarded-*` HTTPS 头将丢失，并且实际客户端的 IP 地址将不可用于 Web 服务器（或其日志）。

我们如何配置这个设置？首先，我们必须获取站点证书和私钥，无论是“命名证书”还是通配符。现在，将它们合并成一个文件（不是作为`pfx`文件，而是作为一个链），只需使用`cat`命令简单地将它们连接在一起：

```
cat sitename.com.crt sitename.com.key | sudo tee /etc/ssl/sitename.com/sitename.com.pem
```

请注意，在命令的后半部分我们使用了`sudo`，以赋予命令对`/etc/ssl/sitename.com`目录的权限。还要注意`tee`命令，它会将命令的输出显示在屏幕上，并将输出定向到所需的位置。

现在，我们可以将证书绑定到前端文件段中的地址：

```
frontend http front-443
    bind 192.168.122.21:443 ssl crt /etc/ssl/sitename.com/sitename.com.pem
    redirect scheme https if !{ ssl_fc }
    mode http
    default_backend back-443
backend back-443
    mode http
    balance leastconn
    option forwardfor
    option httpchk HEAD / HTTP/1.1\r\nHost:localhost
    server web01 192.168.124.20:443 cookie WS01 check fall 3 rise 2
    server web02 192.168.124.21:443 cookie WS02 check fall 3 rise 2
    http-request add-header X-Forwarded-Proto https 
```

在这个配置中，请注意以下内容：

+   现在我们可以在后端部分使用 cookie 来实现会话持久性，这通常是这个配置中的主要目标。

+   我们在前端使用`redirect scheme`行指示代理在后端使用 SSL/TLS。

+   `forwardfor`关键字将实际客户端 IP 添加到后端请求的`X-Forwarded-For` HTTP 头字段中。请注意，需要由 Web 服务器解析这些内容并适当地记录，以便以后使用。

根据应用程序和浏览器的不同，你还可以在`X-Client-IP`头字段中添加客户端 IP 到后端 HTTP 请求中：

```
http-request set-header X-Client-IP %[req.hdr_ip(X-Forwarded-For)]
```

注意

这种方法效果参差不齐。

然而，请注意，无论你在 HTTP 头中添加或更改什么，目标服务器“看到”的实际客户端 IP 地址仍然是负载均衡器的后端地址 - 这些更改或添加的头值只是 HTTPS 请求中的字段。如果你打算使用这些头值进行日志记录、故障排除或监控，就需要 Web 服务器来解析它们并适当地记录。

这涵盖了我们的示例配置 - 我们涵盖了基于 NAT 和基于代理的负载平衡，以及 HTTP 和 HTTPS 流量的会话持久性。在所有理论之后，实际配置负载均衡器很简单 - 工作都在设计和设置支持网络基础设施中。在结束本章之前，让我们简要讨论一下安全性。

# 关于负载均衡器安全性的最后一点说明

到目前为止，我们已经讨论了攻击者如何能够获得有关内部网络的见解或访问权限，如果他们可以获得服务器名称或 IP 地址。我们讨论了恶意行为者如何使用本地负载均衡器配置中披露的信息来获取这些信息以进行持久设置。攻击者还可以以其他方式获取有关我们的目标服务器（这些服务器位于负载均衡器后面并且应该被隐藏）的信息吗？

证书透明信息是获取当前或旧服务器名称的另一种常用方法，正如我们在*第八章*中讨论的那样，*Linux 上的证书服务*。即使旧的服务器名称不再使用，其过去证书的记录是永恒的。

互联网档案馆网站[`archive.org`](https://archive.org)定期对网站进行“快照”，并允许搜索和查看它们，使人们可以“回到过去”并查看您基础设施的旧版本。如果旧服务器在您的旧 DNS 或 Web 服务器的旧代码中披露，它们很可能可以在此网站上找到。

DNS 存档网站，如`dnsdumpster`，使用被动方法（如数据包分析）收集 DNS 信息，并通过 Web 或 API 界面呈现。这使攻击者可以找到旧的 IP 地址和旧（或当前）主机名，组织有时可以通过 IP 仍然访问这些服务，即使 DNS 条目被删除。或者，他们可以通过主机名单独访问它们，即使它们在负载均衡器后面。

*Google Dorks*是获得此类信息的另一种方法 - 这些术语用于在搜索引擎（不仅仅是 Google）中查找特定信息。通常，像`inurl:targetdomain.com`这样的搜索词将找到目标组织宁愿保持隐藏的主机名。一些特定于`haproxy`的 Google Dorks 包括以下内容：

```
intitle:"Statistics Report for HAProxy" + "statistics report for pid" site:www.targetdomain.com 
inurl:haproxy-status site:target.domain.com
```

请注意，在我们说`site:`时，您也可以指定`inurl:`。在这种情况下，您还可以将搜索词缩短为域而不是完整的站点名称。

诸如`shodan.io`之类的网站还将索引您服务器的历史版本，重点关注服务器 IP 地址，主机名，开放端口以及在这些端口上运行的服务。 Shodan 在识别开放端口上运行的服务方面非常独特。当然，他们在这方面并不百分之百成功（将其视为他人的 NMAP 结果），但是当他们识别服务时，会附上“证据”，因此，如果您使用 Shodan 进行侦察，您可以使用它来验证该确定可能有多准确。Shodan 既有 Web 界面又有全面的 API。通过这项服务，您通常可以按组织或地理区域找到未经适当保护的负载均衡器。

最后对搜索引擎的评论：如果 Google（或任何搜索引擎）可以直接访问您的真实服务器，那么该内容将被索引，使其易于搜索。如果网站可能存在身份验证绕过问题，则“受身份验证保护”的内容也将被索引，并可供使用该引擎的任何人使用。

也就是说，始终使用我们刚刚讨论过的工具定期查找外围基础设施上的问题是一个好主意。

另一个重要的安全问题是管理访问。重要的是要限制对负载均衡器的管理界面（即 SSH）的访问，将其限制在所有接口上的允许主机和子网。请记住，如果您的负载均衡器与防火墙平行，整个互联网都可以访问它，即使不是这样，您内部网络上的每个人也可以访问它。您需要将访问权限缩减到可信任的管理主机和子网。如果您需要参考，记住我们在*第四章*中涵盖了这一点，*Linux 防火墙*，以及*第五章*，*具有实际示例的 Linux 安全标准*。

# 总结

希望本章对负载均衡器的介绍、部署以及您可能选择围绕它们做出各种设计和实施决策的原因有所帮助。

如果您在本章节中使用新的虚拟机来跟随示例，那么在接下来的章节中我们将不再需要它们，但是如果您需要以后参考示例，您可能希望保留 HAProxy 虚拟机。如果您只是通过阅读本章中的示例来跟随，那么本章中的示例仍然对您可用。无论哪种方式，当您阅读本章时，我希望您能够在脑海中思考负载均衡器如何适应您组织的内部或边界架构。

完成本章后，您应该具备在任何组织中构建负载均衡器所需的技能。这些技能是在（免费）版本的 HAProxy 的背景下讨论的，但设计和实施考虑几乎都可以直接在任何供应商的平台上使用，唯一的变化是配置选项或菜单中的措辞和语法。在下一章中，我们将看一下基于 Linux 平台的企业路由实现。

# 问题

最后，这里有一些问题供您测试对本章材料的了解。您将在*附录*的*评估*部分中找到答案：

1.  何时您会选择使用**直接服务器返回**（**DSR**）负载均衡器？

1.  为什么您会选择使用基于代理的负载均衡器，而不是纯 NAT-based 解决方案的负载均衡器？

# 进一步阅读

查看以下链接，了解本章涵盖的主题的更多信息：

+   HAProxy 文档：[`www.haproxy.org/#docs`](http://www.haproxy.org/#docs)

+   HAProxy 文档（商业版本）：[`www.haproxy.com/documentation/hapee/2-2r1/getting-started/`](https://www.haproxy.com/documentation/hapee/2-2r1/getting-started/)

+   HAProxy GitHub：[`github.com/haproxytech`](https://github.com/haproxytech)

+   HAProxy GitHub，OVA 虚拟机下载：[`github.com/haproxytech/vmware-haproxy#download`](https://github.com/haproxytech/vmware-haproxy#download)

+   HAProxy 社区与企业版本的区别：[`www.haproxy.com/products/community-vs-enterprise-edition/`](https://www.haproxy.com/products/community-vs-enterprise-edition/)

+   有关负载均衡算法的更多信息：[`cbonte.github.io/haproxy-dconv/2.4/intro.html#3.3.5`](http://cbonte.github.io/haproxy-dconv/2.4/intro.html#3.3.5)
