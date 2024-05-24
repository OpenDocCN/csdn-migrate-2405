# Docker 网络秘籍（一）

> 原文：[`zh.annas-archive.org/md5/15C8E8C8C0D58C74AF1054F5CB887C66`](https://zh.annas-archive.org/md5/15C8E8C8C0D58C74AF1054F5CB887C66)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书的目的是为您提供关于 Docker 如何实现容器网络的深入知识。无论您是每天都在使用 Docker，还是刚刚开始接触，本书都将向您介绍 Docker 如何使用 Linux 网络原语来为容器进行网络连接。通过大量示例，我们将涵盖从 Linux 网络基础知识到最新的 Docker 网络驱动程序的所有内容。在此过程中，我们还将探讨如何将现有的网络结构和第三方插件集成到 Docker 中。最终目标是让您对 Docker 提供容器网络功能的过程感到舒适。

像许多开源项目一样，Docker 是一个快速发展的软件。在出版时，最新版本的 Docker 是 1.12。我已尽力确保本书中的内容反映了基于这个版本的最新功能和配置。无论版本如何，这些功能中的许多在 Docker 的早期版本中以某种形式存在。因此，尽管在过去几年中 Docker 的网络功能发生了重大变化，但大部分网络功能仍然以相同的方式实现。正是因为这个原因，我相信本书中的大部分内容在未来很长一段时间内仍然具有相关性。

# **本书涵盖的内容**

第一章 *Linux 网络结构*，将重点介绍 Linux 网络原语。诸如接口创建、寻址和一般连接性等主题将被详细讨论。您还将了解与 Linux 主机网络配置相关的常见 Linux 命令行语法和工具。了解这些基本结构将极大地增加您理解 Docker 如何处理容器网络的能力。

第二章 *配置和监控 Docker 网络*，解释了 Docker 处理容器网络的默认方式。这包括 Docker 网络操作的桥接、主机和映射容器模式。我们还将开始探讨 Docker 如何将基于容器的服务映射到外部或外部网络。还将讨论 Docker 网络的 Linux 主机要求以及一些可能被修改的 Docker 服务级参数。

第三章，“用户定义的网络”，开始了我们关于 Docker 用户定义网络的讨论。用户定义网络的出现极大地增加了 Docker 网络的灵活性，为最终用户提供了更多关于容器连接的可能性。我们将讨论创建用户定义网络所需的语法，并展示如何创建用户定义的桥接和覆盖网络的示例。最后，我们将介绍一些在 Docker 中隔离网络段的选项。

第四章，“构建 Docker 网络”，首先深入探讨了 Docker 如何提供容器连接。从一个没有网络接口的容器开始，我们将介绍在网络上使容器通信所需的所有步骤。然后，我们将讨论使用自定义桥接与 Docker 以及与 Docker 一起使用 OVS 的多个用例。

第五章，“容器链接和 Docker DNS”，讨论了容器名称解析的可用选项。这包括默认的名称解析行为以及存在于用户定义网络中的新嵌入式 DNS 服务器功能。您将熟悉确定每种情况下名称服务器分配的过程。

第六章，“保护容器网络”，展示了与容器安全相关的各种功能和策略。您将了解到几种限制容器暴露和连接范围的选项。我们还将讨论实现利用用户定义的覆盖网络的基于容器的负载均衡器的选项。

第七章，“使用 Weave Net”，将是我们首次接触与 Docker 集成的第三方网络解决方案。Weave 提供了多种与 Docker 集成的方法，包括其自己的 CLI 工具以及一个完整的 Docker 驱动程序。还将演示使用 Weave 提供网络隔离的示例。

第八章《使用 Flannel》，*使用 Flannel*，检查了由 CoreOS 团队构建的第三方网络插件。Flannel 是一个有趣的例子，说明了网络插件如何通过更改 Docker 服务级参数来集成到 Docker 中。除了提供覆盖类型的网络外，Flannel 还提供了主机网关后端，允许主机在满足某些要求的情况下直接路由到彼此。

第九章《探索网络功能》，*探索网络功能*，侧重于新的网络功能如何集成到 Docker 中。我们将研究如何通过评估不同版本的 Docker 引擎来获得对这些新功能的访问和测试。在本章的过程中，我们还将研究现在集成的 MacVLAN 网络驱动程序以及仍在测试中的 IPVLAN 网络驱动程序。

第十章《利用 IPv6》，*利用 IPv6*，涵盖了 IPv6 及 Docker 对其的支持。IPv6 是一个重要的话题，考虑到 IPv4 的当前状态，它值得引起大量关注。在本章中，我们将回顾在 Linux 系统上使用 IPv6 的一些基础知识。然后，我们将花一些时间审查 Docker 如何支持 IPv6，并讨论您在部署周围的一些选项。

第十一章《故障排除 Docker 网络》，*故障排除 Docker 网络*，探讨了在故障排除 Docker 网络时可能采取的一些常见步骤。重点将放在验证配置上，但您还将学习一些可以证明配置是否按预期工作的步骤。

# 您需要为本书做些什么

本书中显示的所有实验都是在运行版本 16.04 和 Docker 引擎版本 1.12 的 Ubuntu Linux 主机上执行的。

### 注意

您会注意到，本书中主机上使用的网络接口名称使用熟悉的 eth（eth0、eth1 等）命名约定。虽然这在许多 Linux 版本上仍然是标准，但运行 systemd 的新版本（如 Ubuntu 16.04）现在使用称为可预测网络接口名称（PNIN）的东西。使用 PNIN 时，网络接口使用基于接口本身信息的更可预测的名称。在这些情况下，接口名称将以不同的名称显示，例如 ens1 或 ens32。为了使本书中的内容更容易理解，我选择在所有主机上禁用了 PNIN。如果您有兴趣执行相同的操作，可以通过网络搜索“Ubuntu 禁用可预测接口名称”找到说明。如果您选择不这样做，只需知道您的接口名称将显示为与我的示例不同的方式。

本书中显示的实验室要求包括在每个配方的开头。后续的配方可能会基于早期配方中显示的配置。

# 这本书是为谁准备的

本书适用于那些对了解 Docker 如何实现容器网络感兴趣的人。虽然这些配方涵盖了许多基础知识，但假定您具有对 Linux 和 Docker 的工作知识，并且具有对网络的基本理解。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些这些样式的例子以及它们的含义解释。

文本中的代码词、文件路径和可执行文件显示如下：

“可以使用`ip link show`命令在主机上查看接口”。

任何命令行输入或输出都将按如下方式编写：

```
user@net1:~$ sudo ifdown eth1 && sudo ifup eth1
```

在可能的情况下，任何多行命令行输入将使用 Linux 行继续方法编写，即在要继续的行的末尾包括一个尾随的`\`：

```
user@net1:~$ sudo ip netns exec ns_1 ip link set \
dev edge_veth1 master edge_bridge1
```

在某些情况下，命令行输出也可能是多行的。在这种情况下，格式化是为了使输出易于阅读。

当我们希望引起您对命令行输出的特别关注时，相关行或项目将以粗体显示：

```
user@net2:~$ ip addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:59:ca:ca brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.2/26** brd 172.16.10.63 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe59:caca/64 scope link
       valid_lft forever preferred_lft forever
user@net2:~$

```

### 注意

警告或重要说明显示在这样的框中。


# 第一章：Linux 网络构造

在本章中，我们将涵盖以下配方：

+   使用接口和地址

+   配置 Linux 主机路由

+   探索桥接

+   建立连接

+   探索网络命名空间

# 介绍

Linux 是一个功能强大的操作系统，具有许多强大的网络构造。就像任何网络技术一样，它们单独使用时很强大，但在创造性地组合在一起时变得更加强大。Docker 是一个很好的例子，它将许多 Linux 网络堆栈的单独组件组合成一个完整的解决方案。虽然 Docker 大部分时间都在为您管理这些内容，但当查看 Docker 使用的 Linux 网络组件时，了解一些基本知识仍然是有帮助的。

在本章中，我们将花一些时间单独查看这些构造，而不是在 Docker 之外。我们将学习如何在 Linux 主机上进行网络配置更改，并验证网络配置的当前状态。虽然本章并不专门针对 Docker 本身，但重要的是要了解原语，以便在以后的章节中讨论 Docker 如何使用这些构造来连接容器。

# 使用接口和地址

了解 Linux 如何处理网络是理解 Docker 处理网络的一个重要部分。在这个配方中，我们将专注于 Linux 网络基础知识，学习如何在 Linux 主机上定义和操作接口和 IP 地址。为了演示配置，我们将在本配方中开始构建一个实验室拓扑，并在本章的其他配方中继续进行。

## 准备工作

为了查看和操作网络设置，您需要确保已安装`iproute2`工具集。如果系统上没有安装它，可以使用以下命令进行安装：

```
sudo apt-get install iproute2
```

为了对主机进行网络更改，您还需要 root 级别的访问权限。

为了在本章中进行演示，我们将使用一个简单的实验室拓扑。主机的初始网络布局如下：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_01.jpg)

在这种情况下，我们有三台主机，每台主机已经定义了一个`eth0`接口：

+   `net1`: `10.10.10.110/24`，默认网关为`10.10.10.1`

+   `net2`: `172.16.10.2/26`

+   `net3`: `172.16.10.66/26`

## 操作步骤

大多数终端主机的网络配置通常仅限于单个接口的 IP 地址、子网掩码和默认网关。这是因为大多数主机都是网络端点，在单个 IP 接口上提供一组离散的服务。但是如果我们想要定义更多的接口或操作现有的接口会发生什么呢？为了回答这个问题，让我们首先看一下像前面例子中的`net2`或`net3`这样的简单单宿主服务器。

在 Ubuntu 主机上，所有的接口配置都是在`/etc/network/interfaces`文件中完成的。让我们检查一下`net2`主机上的文件：

```
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
        address 172.16.10.2
        netmask 255.255.255.192
```

我们可以看到这个文件定义了两个接口——本地的`loopback`接口和接口`eth0`。`eth0`接口定义了以下信息：

+   `address`：主机接口的 IP 地址

+   `netmask`：与 IP 接口相关的子网掩码

该文件中的信息将在每次接口尝试进入上行或操作状态时进行处理。我们可以通过使用`ip addr show <interface name>`命令验证该配置文件在系统启动时是否被处理：

```
user@net2:~$ ip addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:59:ca:ca brd ff:ff:ff:ff:ff:ff
    inet 172.16.10.2/26 brd 172.16.10.63 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe59:caca/64 scope link
       valid_lft forever preferred_lft forever
user@net2:~$
```

现在我们已经审查了单宿主配置，让我们来看看在单个主机上配置多个接口需要做些什么。目前为止，`net1`主机是唯一一个在本地子网之外具有可达性的主机。这是因为它有一个定义好的默认网关指向网络的其他部分。为了使`net2`和`net3`可达，我们需要找到一种方法将它们连接回网络的其他部分。为了做到这一点，让我们假设主机`net1`有两个额外的网络接口，我们可以直接连接到主机`net2`和`net3`：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_02.jpg)

让我们一起来看看如何在`net1`上配置额外的接口和 IP 地址，以完成拓扑结构。

我们要做的第一件事是验证我们在`net1`上有可用的额外接口可以使用。为了做到这一点，我们将使用`ip link show`命令：

```
user@net1:~$ ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: **eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:2d:dd:79 brd ff:ff:ff:ff:ff:ff
3: **eth1**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:2d:dd:83 brd ff:ff:ff:ff:ff:ff
4: **eth2**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:2d:dd:8d brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

从输出中我们可以看到，除了`eth0`接口，我们还有`eth1`和`eth2`接口可供使用。要查看哪些接口有与之关联的 IP 地址，我们可以使用`ip address show`命令：

```
user@net1:~$ ip address show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:2d:dd:79 brd ff:ff:ff:ff:ff:ff
    inet **10.10.10.110/24** brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe2d:dd79/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 00:0c:29:2d:dd:83 brd ff:ff:ff:ff:ff:ff
4: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 00:0c:29:2d:dd:8d brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

前面的输出证明我们目前只在接口`eth0`上分配了一个 IP 地址。这意味着我们可以使用接口`eth1`连接到服务器`net2`，并使用接口`eth2`连接到服务器`net3`。

我们可以有两种方法来配置这些新接口。第一种是在`net1`上更新网络配置文件，包括相关的 IP 地址信息。让我们为面向主机`net2`的链接进行配置。要配置这种连接，只需编辑文件`/etc/network/interfaces`，并为两个接口添加相关的配置。完成的配置应该是这样的：

```
# The primary network interface
auto eth0
iface eth0 inet static
        address 10.10.10.110
        netmask 255.255.255.0
        gateway 10.10.10.1
auto eth1
iface eth1 inet static
 address 172.16.10.1
 netmask 255.255.255.192

```

保存文件后，您需要找到一种方法告诉系统重新加载配置文件。做到这一点的一种方法是重新加载系统。一个更简单的方法是重新加载接口。例如，我们可以执行以下命令来重新加载接口`eth1`：

```
user@net1:~$ **sudo ifdown eth1 && sudo ifup eth1
ifdown: interface eth1 not configured
user@net1:~$
```

### 注意

在这种情况下并不需要，但同时关闭和打开接口是一个好习惯。这样可以确保如果关闭了你正在管理主机的接口，你不会被切断。

在某些情况下，您可能会发现更新接口配置的这种方法不像预期的那样工作。根据您使用的 Linux 版本，您可能会遇到一个情况，即之前的 IP 地址没有从接口中删除，导致接口具有多个 IP 地址。为了解决这个问题，您可以手动删除旧的 IP 地址，或者重新启动主机，这将防止旧的配置持续存在。

执行完命令后，我们应该能够看到接口`eth1`现在被正确地寻址了。

```
user@net1:~$ ip addr show dev eth1
3: **eth1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:2d:dd:83 brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.1/26** brd 172.16.10.63 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe2d:dd83/64 scope link
       valid_lft forever preferred_lft forever
user@net1:~$
```

要在主机`net1`上配置接口`eth2`，我们将采用不同的方法。我们将使用`iproute2`命令行来更新接口的配置，而不是依赖配置文件。为此，我们只需执行以下命令：

```
user@net1:~$ sudo ip address add **172.16.10.65/26** dev **eth2
user@net1:~$ sudo ip link set eth2 up
```

这里需要注意的是，这种配置是不持久的。也就是说，由于它不是在系统初始化时加载的配置文件的一部分，这个配置在重新启动后将会丢失。对于使用`iproute2`或其他命令行工具集手动完成的任何与网络相关的配置都是一样的情况。

### 注意

在网络配置文件中配置接口信息和地址是最佳实践。在这些教程中，修改配置文件之外的接口配置仅用于举例。

到目前为止，我们只是通过向现有接口添加 IP 信息来修改现有接口。我们实际上还没有向任何系统添加新接口。添加接口是一个相当常见的任务，正如后面的教程将展示的那样，有各种类型的接口可以添加。现在，让我们专注于添加 Linux 所谓的虚拟接口。虚拟接口在网络中的作用类似于环回接口，并描述了一种始终处于开启和在线状态的接口类型。接口是通过使用`ip link add`语法来定义或创建的。然后，您指定一个名称，并定义您正在定义的接口类型。例如，让我们在主机`net2`和`net3`上定义一个虚拟接口：

```
user@net2:~$ sudo ip link add dummy0 type dummy
user@net2:~$ sudo ip address add 172.16.10.129/26 dev dummy0
user@net2:~$ sudo ip link set dummy0 up

user@net3:~$ sudo ip link add dummy0 type dummy
user@net3:~$ sudo ip address add 172.16.10.193/26 dev dummy0
user@net3:~$ sudo ip link set dummy0 up
```

在定义接口之后，每个主机都应该能够 ping 通自己的`dummy0`接口：

```
user@net2:~$ ping **172.16.10.129** -c 2
PING 172.16.10.129 (172.16.10.129) 56(84) bytes of data.
64 bytes from 172.16.10.129: icmp_seq=1 ttl=64 time=0.030 ms
64 bytes from 172.16.10.129: icmp_seq=2 ttl=64 time=0.031 ms
--- 172.16.10.129 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.030/0.030/0.031/0.005 ms
user@net2:~$

user@net3:~$ ping **172.16.10.193** -c 2
PING 172.16.10.193 (172.16.10.193) 56(84) bytes of data.
64 bytes from 172.16.10.193: icmp_seq=1 ttl=64 time=0.035 ms
64 bytes from 172.16.10.193: icmp_seq=2 ttl=64 time=0.032 ms
--- 172.16.10.193 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.032/0.033/0.035/0.006 ms
user@net3:~$
```

### 注意

您可能会想知道为什么我们必须启动`dummy0`接口，如果它们被认为是一直开启的。实际上，接口是可以在不启动接口的情况下到达的。但是，如果不启动接口，接口的本地路由将不会出现在系统的路由表中。

# 配置 Linux 主机路由

一旦您定义了新的 IP 接口，下一步就是配置路由。在大多数情况下，Linux 主机路由配置仅限于指定主机的默认网关。虽然这通常是大多数人需要做的，但 Linux 主机有能力成为一个完整的路由器。在这个教程中，我们将学习如何查询 Linux 主机的路由表，以及手动配置路由。

## 准备工作

为了查看和操作网络设置，您需要确保已安装`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2
```

为了对主机进行网络更改，您还需要 root 级别的访问权限。本教程将继续上一个教程中的实验拓扑。我们在上一个教程之后留下的拓扑如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_03.jpg)

## 操作步骤

尽管 Linux 主机有路由的能力，但默认情况下不会这样做。为了进行路由，我们需要修改内核级参数以启用 IP 转发。我们可以通过几种不同的方式来检查设置的当前状态：

+   通过使用`sysctl`命令：

```
sysctl net.ipv4.ip_forward
```

+   通过直接查询`/proc/`文件系统：

```
more /proc/sys/net/ipv4/ip_forward
```

无论哪种情况，如果返回值为`1`，则启用了 IP 转发。如果没有收到`1`，则需要启用 IP 转发，以便 Linux 主机通过系统路由数据包。您可以使用`sysctl`命令手动启用 IP 转发，或者再次直接与`/proc/`文件系统交互：

```
sudo sysctl -w net.ipv4.ip_forward=1
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

虽然这可以在运行时启用 IP 转发，但此设置不会在重新启动后保持。要使设置持久，您需要修改`/etc/sysctl.conf`，取消注释 IP 转发的行，并确保将其设置为`1`：

```
…<Additional output removed for brevity>…
# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1
…<Additional output removed for brevity>…
```

### 注意

您可能会注意到，我们目前只修改了与 IPv4 相关的设置。不用担心；我们稍后会在第十章 *利用 IPv6*中介绍 IPv6 和 Docker 网络。

一旦我们验证了转发配置，让我们使用`ip route show`命令查看所有三个实验室主机的路由表：

```
user@**net1**:~$ ip route show
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0  proto kernel  scope link  src 10.10.10.110
172.16.10.0/26 dev eth1  proto kernel  scope link  src 172.16.10.1
172.16.10.64/26 dev eth2  proto kernel  scope link  src 172.16.10.65

user@**net2**:~$ ip route show
172.16.10.0/26 dev eth0  proto kernel  scope link  src 172.16.10.2
172.16.10.128/26 dev dummy0  proto kernel  scope link  src 172.16.10.129

user@**net3**:~$ ip route show
172.16.10.64/26 dev eth0  proto kernel  scope link  src 172.16.10.66
172.16.10.192/26 dev dummy0  proto kernel  scope link  src 172.16.10.193
```

这里有几个有趣的地方需要注意。首先，我们注意到主机列出了与其每个 IP 接口相关联的路由。根据与接口相关联的子网掩码，主机可以确定接口所关联的网络。这条路由是固有的，并且可以说是直接连接的。直接连接的路由是系统知道哪些 IP 目的地是直接连接的，而哪些需要转发到下一跳以到达远程目的地。

其次，在上一篇文章中，我们向主机`net1`添加了两个额外的接口，以便与主机`net2`和`net3`进行连接。但是，仅凭这一点，只允许`net1`与`net2`和`net3`通信。如果我们希望通过网络的其余部分到达`net2`和`net3`，它们将需要指向`net1`上各自接口的默认路由。让我们再次以两种不同的方式进行。在`net2`上，我们将更新网络配置文件并重新加载接口，在`net3`上，我们将通过命令行直接添加默认路由。

在主机`net2`上，更新文件`/etc/network/interfaces`，并在`eth0`接口上添加一个指向主机`net1`连接接口的网关：

```
# The primary network interface
auto eth0
iface eth0 inet static
        address 172.16.10.2
        netmask 255.255.255.192
 gateway 172.16.10.1

```

要激活新配置，我们将重新加载接口：

```
user@net2:~$ sudo ifdown eth0 && sudo ifup eth0
```

现在我们应该能够在`net2`主机的路由表中看到默认路由，指向`net1`主机直接连接的接口（`172.16.10.1`）：

```
user@net2:~$ ip route show
default via 172.16.10.1 dev eth0
172.16.10.0/26 dev eth0  proto kernel  scope link  src 172.16.10.2
172.16.10.128/26 dev dummy0  proto kernel  scope link  src 172.16.10.129
user@net2:~$
```

在主机`net3`上，我们将使用`iproute2`工具集动态修改主机的路由表。为此，我们将执行以下命令：

```
user@net3:~$ sudo ip route add default via 172.16.10.65
```

### 注意

请注意，我们使用关键字`default`。这代表了**无类域间路由**（**CIDR**）表示法中的默认网关或目的地`0.0.0.0/0`。我们也可以使用`0.0.0.0/0`语法执行该命令。

执行命令后，我们将检查路由表，以确保我们现在有一个默认路由指向`net1`（`172.16.10.65`）：

```
user@net3:~$ ip route show
default via 172.16.10.65 dev eth0
172.16.10.64/26 dev eth0  proto kernel  scope link  src 172.16.10.66
172.16.10.192/26 dev dummy0  proto kernel  scope link  src 172.16.10.193
user@net3:~$
```

此时，主机和网络的其余部分应该能够完全访问其所有物理接口。然而，在上一个步骤中创建的虚拟接口对于除了它们所定义的主机之外的任何其他主机都是不可达的。为了使它们可达，我们需要添加一些静态路由。

虚拟接口网络是`172.16.10.128/26`和`172.16.10.192/26`。因为这些网络是较大的`172.16.10.0/24`汇总的一部分，网络的其余部分已经知道要路由到`net1`主机的`10.10.10.110`接口以到达这些前缀。然而，`net1`目前不知道这些前缀位于何处，因此会将流量原路返回到它来自的地方，遵循其默认路由。为了解决这个问题，我们需要在`net1`上添加两个静态路由：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_04.jpg)

我们可以通过`iproute2`命令行工具临时添加这些路由，也可以将它们作为主机网络脚本的一部分以更持久的方式添加。让我们各做一次：

要添加指向`net2`的`172.16.10.128/26`路由，我们将使用命令行工具：

```
user@net1:~$ sudo ip route add 172.16.10.128/26 via 172.16.10.2
```

如您所见，通过`ip route add`命令语法添加手动路由。需要到达的子网以及相关的下一跳地址都会被指定。该命令立即生效，因为主机会立即填充路由表以反映更改：

```
user@net1:~$ ip route
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0  proto kernel  scope link  src 10.10.10.110
172.16.10.0/26 dev eth1  proto kernel  scope link  src 172.16.10.1
172.16.10.64/26 dev eth2  proto kernel  scope link  src 172.16.10.65
172.16.10.128/26 via 172.16.10.2 dev eth1
user@net1:~$
```

如果我们希望使路由持久化，我们可以将其分配为`post-up`接口配置。`post-up`接口配置在接口加载后直接进行。如果我们希望在`eth2`上线时立即将路由`172.16.10.192/26`添加到主机的路由表中，我们可以编辑`/etc/network/interfaces`配置脚本如下：

```
auto eth2
iface eth2 inet static
        address 172.16.10.65
        netmask 255.255.255.192
 post-up ip route add 172.16.10.192/26 via 172.16.10.66

```

添加配置后，我们可以重新加载接口以强制配置文件重新处理：

```
user@net1:~$ sudo ifdown eth2 && sudo ifup eth2
```

### 注意

在某些情况下，主机可能不会处理`post-up`命令，因为我们在早期的配置中手动定义了接口上的地址。在重新加载接口之前删除 IP 地址将解决此问题；然而，在这些情况下，重新启动主机是最简单（也是最干净）的操作方式。

我们的路由表现在将显示两条路由：

```
user@net1:~$ ip route
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0  proto kernel  scope link  src 10.10.10.110
172.16.10.0/26 dev eth1  proto kernel  scope link  src 172.16.10.1
172.16.10.64/26 dev eth2  proto kernel  scope link  src 172.16.10.65
172.16.10.128/26 via 172.16.10.2 dev eth1
172.16.10.192/26 via 172.16.10.66 dev eth2
user@net1:~$
```

为了验证这是否按预期工作，让我们从尝试 ping 主机`net2`（`172.16.10.129`）上的虚拟接口的远程工作站进行一些测试。假设工作站连接到的接口不在外部网络上，流程可能如下：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_05.jpg)

1.  具有 IP 地址`192.168.127.55`的工作站正在尝试到达连接到`net2`的虚拟接口，其 IP 地址为`172.16.10.129`。由于工作站寻找的目的地不是直接连接的，它将流量发送到其默认网关。

1.  网络中有一个指向`net1`的`eth0`接口（`10.10.10.110`）的`172.16.10.0/24`路由。目标 IP 地址（`172.16.10.129`）是该较大前缀的成员，因此网络将工作站的流量转发到主机`net1`。

1.  主机`net1`检查流量，查询其路由表，并确定它有一个指向`net2`的该前缀的路由，下一跳是`172.16.10.2`。

1.  `net2`收到请求，意识到虚拟接口直接连接，并尝试将回复发送回工作站。由于没有目的地为`192.168.127.55`的特定路由，主机`net2`将其回复发送到其默认网关，即`net1`（`172.16.10.1`）。

1.  同样，`net1`没有目的地为`192.168.127.55`的特定路由，因此它将流量通过其默认网关转发回网络。假设网络具有返回流量到工作站的可达性。

如果我们想要删除静态定义的路由，可以使用`ip route delete`子命令来实现。例如，这是一个添加路由然后删除它的示例：

```
user@net1:~$ sudo ip route add 172.16.10.128/26 via 172.16.10.2
user@net1:~$ sudo ip route delete 172.16.10.128/26
```

请注意，我们在删除路由时只需要指定目标前缀，而不需要指定下一跳。

# 探索桥接

Linux 中的桥是网络连接的关键构建块。Docker 在许多自己的网络驱动程序中广泛使用它们，这些驱动程序包含在`docker-engine`中。桥已经存在很长时间，在大多数情况下，非常类似于物理网络交换机。Linux 中的桥可以像二层桥一样工作，也可以像三层桥一样工作。

### 注意

**二层与三层**

命名法是指 OSI 网络模型的不同层。二层代表**数据链路层**，与在主机之间进行帧交换相关联。三层代表**网络层**，与在网络中路由数据包相关联。两者之间的主要区别在于交换与路由。二层交换机能够在同一网络上的主机之间发送帧，但不能根据 IP 信息进行路由。如果您希望在不同网络或子网上的两台主机之间进行路由，您将需要一台能够在两个子网之间进行路由的三层设备。另一种看待这个问题的方式是，二层交换机只能处理 MAC 地址，而三层设备可以处理 IP 地址。

默认情况下，Linux 桥是二层结构。因此，它们通常被称为协议无关。也就是说，任意数量的更高级别（三层）协议可以在同一个桥实现上运行。但是，您也可以为桥分配一个 IP 地址，将其转换为三层可用的网络结构。在本教程中，我们将通过几个示例来向您展示如何创建、管理和检查 Linux 桥。

## 准备工作

为了查看和操作网络设置，您需要确保已安装`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2
```

为了对主机进行网络更改，您还需要具有根级别访问权限。本教程将继续上一个教程中的实验室拓扑。之前提到的所有先决条件仍然适用。

## 操作步骤

为了演示桥接工作原理，让我们考虑对我们一直在使用的实验室拓扑进行轻微更改：

![操作步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_06.jpg)

与其让服务器通过物理接口直接连接到彼此，我们将利用主机`net1`上的桥接来连接到下游主机。以前，我们依赖于`net1`和任何其他主机之间的一对一映射连接。这意味着我们需要为每个物理接口配置唯一的子网和 IP 地址。虽然这是可行的，但并不是很实际。与标准接口相比，利用桥接接口为我们提供了一些在早期配置中没有的灵活性。我们可以为桥接接口分配一个单独的 IP 地址，然后将许多物理连接连接到同一个桥接上。例如，`net4`主机可以添加到拓扑结构中，其在`net1`上的接口可以简单地添加到`host_bridge2`上。这将允许它使用与`net3`相同的网关（`172.16.10.65`）。因此，虽然添加主机的物理布线要求不会改变，但这确实使我们不必为每个主机定义一对一的 IP 地址映射。

### 注意

从`net2`和`net3`主机的角度来看，当我们重新配置以使用桥接时，什么都不会改变。

由于我们正在更改如何定义`net1`主机的`eth1`和`eth2`接口，因此我们将首先清除它们的配置：

```
user@net1:~$ sudo ip address flush dev eth1
user@net1:~$ sudo ip address flush dev eth2
```

清除接口只是清除接口上的任何与 IP 相关的配置。我们接下来要做的是创建桥接本身。我们使用的语法与我们在上一个示例中创建虚拟接口时看到的非常相似。我们使用`ip link add`命令并指定桥接类型：

```
user@net1:~$ sudo ip link add host_bridge1 type bridge
user@net1:~$ sudo ip link add host_bridge2 type bridge
```

创建桥接之后，我们可以通过使用`ip link show <interface>`命令来验证它们的存在，检查可用的接口：

```
user@net1:~$ ip link show host_bridge1
5: **host_bridge1**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
    link/ether f6:f1:57:72:28:a7 brd ff:ff:ff:ff:ff:ff
user@net1:~$ ip link show host_bridge2
6: **host_bridge2**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
    link/ether be:5e:0b:ea:4c:52 brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

接下来，我们希望使它们具有第 3 层意识，因此我们为桥接接口分配一个 IP 地址。这与我们在以前的示例中为物理接口分配 IP 地址非常相似：

```
user@net1:~$ sudo ip address add **172.16.10.1/26** dev **host_bridge1
user@net1:~$ sudo ip address add **172.16.10.65/26** dev **host_bridge2

```

我们可以通过使用`ip addr show dev <interface>`命令来验证 IP 地址的分配情况：

```
user@net1:~$ ip addr show dev host_bridge1
5: **host_bridge1**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default
    link/ether f6:f1:57:72:28:a7 brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.1/26** scope global **host_bridge1
       valid_lft forever preferred_lft forever
user@net1:~$ ip addr show dev host_bridge2
6: host_bridge2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default
    link/ether be:5e:0b:ea:4c:52 brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.65/26** scope global **host_bridge2
       valid_lft forever preferred_lft forever
user@net1:~$
```

下一步是将与每个下游主机关联的物理接口绑定到正确的桥上。在我们的情况下，我们希望连接到`net1`的`eth1`接口的主机`net2`成为桥`host_bridge1`的一部分。同样，我们希望连接到`net1`的`eth2`接口的主机`net3`成为桥`host_bridge2`的一部分。使用`ip link set`子命令，我们可以将桥定义为物理接口的主设备：

```
user@net1:~$ sudo ip link set dev eth1 master host_bridge1
user@net1:~$ sudo ip link set dev eth2 master host_bridge2
```

我们可以使用`bridge link show`命令验证接口是否成功绑定到桥上。

### 注意

`bridge`命令是`iproute2`软件包的一部分，用于验证桥接配置。

```
user@net1:~$ bridge link show
3: **eth1** state UP : <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 **master host_bridge1** state forwarding priority 32 cost 4
4: **eth2** state UP : <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 **master host_bridge2** state forwarding priority 32 cost 4
user@net1:~$
```

最后，我们需要将桥接接口打开，因为它们默认处于关闭状态：

```
user@net1:~$ sudo ip link set host_bridge1 up
user@net1:~$ sudo ip link set host_bridge2 up
```

再次，我们现在可以检查桥接的链路状态，以验证它们是否成功启动：

```
user@net1:~$ ip link show host_bridge1
5: **host_bridge1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state **UP** mode DEFAULT group default
    link/ether 00:0c:29:2d:dd:83 brd ff:ff:ff:ff:ff:ff
user@net1:~$ ip link show host_bridge2
6: **host_bridge2**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state **UP** mode DEFAULT group default
    link/ether 00:0c:29:2d:dd:8d brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

此时，您应该再次能够到达主机`net2`和`net3`。但是，虚拟接口现在无法访问。这是因为在我们清除接口`eth1`和`eth2`之后，虚拟接口的路由被自动撤销。从这些接口中删除 IP 地址使得用于到达虚拟接口的下一跳不可达。当下一跳变得不可达时，设备通常会从其路由表中撤销路由。我们可以很容易地再次添加它们：

```
user@net1:~$ sudo ip route add 172.16.10.128/26 via 172.16.10.2
user@net1:~$ sudo ip route add 172.16.10.192/26 via 172.16.10.66
```

现在一切都恢复正常了，我们可以执行一些额外的步骤来验证配置。Linux 桥，就像真正的第二层交换机一样，也可以跟踪它们接收到的 MAC 地址。我们可以使用`bridge fdb show`命令查看系统知道的 MAC 地址：

```
user@net1:~$ bridge fdb show
…<Additional output removed for brevity>…
00:0c:29:59:ca:ca dev eth1
00:0c:29:17:f4:03 dev eth2
user@net1:~$
```

我们在前面的输出中看到的两个 MAC 地址是指`net1`直接连接的接口，以便到达主机`net2`和`net3`，以及其关联的`dummy0`接口上定义的子网。我们可以通过查看主机 ARP 表来验证这一点：

```
user@net1:~$ arp -a
? (**10.10.10.1**) at **00:21:d7:c5:f2:46** [ether] on **eth0
? (**172.16.10.2**) at **00:0c:29:59:ca:ca** [ether] on **host_bridge1
? (**172.16.10.66**) at **00:0c:29:17:f4:03** [ether] on **host_bridge2
user@net1:~$
```

### 注意

在旧工具更好的情况并不多见，但在`bridge`命令行工具的情况下，一些人可能会认为旧的`brctl`工具有一些优势。首先，输出更容易阅读。在学习 MAC 地址的情况下，它将通过`brctl showmacs <bridge name>`命令为您提供更好的映射视图。如果您想使用旧工具，可以安装`bridge-utils`软件包。

通过`ip link set`子命令可以从桥中移除接口。例如，如果我们想要从桥`host_bridge1`中移除`eth1`，我们将运行以下命令：

```
sudo ip link set dev eth1 nomaster
```

这将删除`eth1`与桥`host_bridge1`之间的主从绑定。接口也可以重新分配给新的桥（主机），而无需将它们从当前关联的桥中移除。如果我们想要完全删除桥，可以使用以下命令：

```
sudo ip link delete dev host_bridge2
```

需要注意的是，在删除桥之前，您不需要将所有接口从桥中移除。删除桥将自动删除所有主绑定。

# 建立连接

到目前为止，我们一直专注于使用物理电缆在接口之间建立连接。但是，如果两个接口没有物理接口，我们该如何连接它们？为此，Linux 网络具有一种称为**虚拟以太网**（**VETH**）对的内部接口类型。VETH 接口总是成对创建，使其表现得像一种虚拟补丁电缆。VETH 接口也可以分配 IP 地址，这使它们能够参与第 3 层路由路径。在本教程中，我们将通过构建之前教程中使用的实验拓扑来研究如何定义和实现 VETH 对。

## 准备工作

为了查看和操作网络设置，您需要确保已安装了`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2
```

为了对主机进行网络更改，您还需要具有根级访问权限。本教程将继续上一个教程中的实验拓扑。之前提到的所有先决条件仍然适用。

## 操作步骤

让我们再次修改实验拓扑，以便使用 VETH 对：

![操作步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_07.jpg)

再次强调，主机`net2`和`net3`上的配置将保持不变。在主机`net1`上，我们将以两种不同的方式实现 VETH 对。

在`net1`和`net2`之间的连接上，我们将使用两个不同的桥接，并使用 VETH 对将它们连接在一起。桥接`host_bridge1`将保留在`net1`上，并保持其 IP 地址为`172.16.10.1`。我们还将添加一个名为`edge_bridge1`的新桥接。该桥接将不分配 IP 地址，但将具有`net1`的接口面向`net2`（`eth1`）作为其成员。在那时，我们将使用 VETH 对连接这两个桥接，允许流量从`net1`通过两个桥接流向`net2`。在这种情况下，VETH 对将被用作第 2 层构造。

在`net1`和`net3`之间的连接上，我们将以稍微不同的方式使用 VETH 对。我们将添加一个名为`edge_bridge2`的新桥，并将`net1`主机的接口面向主机`net3`（`eth2`）放在该桥上。然后，我们将配置一个 VETH 对，并将一端放在桥`edge_bridge2`上。然后，我们将分配之前分配给`host_bridge2`的 IP 地址给 VETH 对的主机端。在这种情况下，VETH 对将被用作第 3 层构造。

让我们从在`net1`和`net2`之间的连接上添加新的边缘桥开始：

```
user@net1:~$ sudo ip link add edge_bridge1 type bridge
```

然后，我们将把面向`net2`的接口添加到`edge_bridge1`上：

```
user@net1:~$ sudo ip link set dev eth1 master edge_bridge1
```

接下来，我们将配置用于连接`host_bridge1`和`edge_bridge1`的 VETH 对。VETH 对始终成对定义。创建接口将产生两个新对象，但它们是相互依赖的。也就是说，如果删除 VETH 对的一端，另一端也将被删除。为了定义 VETH 对，我们使用`ip link add`子命令：

```
user@net1:~$ sudo ip link add **host_veth1** type veth peer name **edge_veth1

```

### 注意

请注意，该命令定义了 VETH 连接的两侧的名称。

我们可以使用`ip link show`子命令查看它们的配置：

```
user@net1:~$ ip link show
…<Additional output removed for brevity>…
13: **edge_veth1@host_veth1**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 0a:27:83:6e:9a:c3 brd ff:ff:ff:ff:ff:ff
14: **host_veth1@edge_veth1**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether c2:35:9c:f9:49:3e brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

请注意，我们有两个条目显示了定义的 VETH 对的每一侧的接口。下一步是将 VETH 对的端点放在正确的位置。在`net1`和`net2`之间的连接中，我们希望一个端点在`host_bridge1`上，另一个端点在`edge_bridge1`上。为此，我们使用了分配接口给桥接的相同语法：

```
user@net1:~$ sudo ip link set **host_veth1** master **host_bridge1
user@net1:~$ sudo ip link set **edge_veth1** master **edge_bridge1

```

我们可以使用`ip link show`命令验证映射：

```
user@net1:~$ ip link show
…<Additional output removed for brevity>…
9: **edge_veth1@host_veth1**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop **master edge_bridge1** state DOWN mode DEFAULT group default qlen 1000
    link/ether f2:90:99:7d:7b:e6 brd ff:ff:ff:ff:ff:ff
10: **host_veth1@edge_veth1**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop **master host_bridge1** state DOWN mode DEFAULT group default qlen 1000
    link/ether da:f4:b7:b3:8d:dd brd ff:ff:ff:ff:ff:ff
```

我们需要做的最后一件事是启动与连接相关的接口：

```
user@net1:~$ sudo ip link set host_bridge1 up
user@net1:~$ sudo ip link set edge_bridge1 up
user@net1:~$ sudo ip link set host_veth1 up
user@net1:~$ sudo ip link set edge_veth1 up
```

要到达`net2`上的虚拟接口，您需要添加路由，因为在重新配置期间它再次丢失了：

```
user@net1:~$ sudo ip route add 172.16.10.128/26 via 172.16.10.2
```

此时，我们应该可以完全到达`net2`及其通过`net1`到达`dummy0`接口。

在主机`net1`和`net3`之间的连接上，我们需要做的第一件事是清理任何未使用的接口。在这种情况下，那将是`host_bridge2`：

```
user@net1:~$ sudo ip link delete dev host_bridge2
```

然后，我们需要添加新的边缘桥接（`edge_bridge2`）并将`net1`面向`net3`的接口与桥接关联起来：

```
user@net1:~$ sudo ip link add edge_bridge2 type bridge
user@net1:~$ sudo ip link set dev eth2 master edge_bridge2
```

然后，我们将为此连接定义 VETH 对：

```
user@net1:~$ sudo ip link add **host_veth2** type veth peer name **edge_veth2

```

在这种情况下，我们将使主机端的 VETH 对与桥接不相关，而是直接为其分配一个 IP 地址：

```
user@net1:~$ sudo ip address add 172.16.10.65/25 dev host_veth2
```

就像任何其他接口一样，我们可以使用`ip address show dev`命令来查看分配的 IP 地址：

```
user@net1:~$ ip addr show dev **host_veth2
12: host_veth2@edge_veth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 56:92:14:83:98:e0 brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.65/25** scope global host_veth2
       valid_lft forever preferred_lft forever
    inet6 fe80::5492:14ff:fe83:98e0/64 scope link
       valid_lft forever preferred_lft forever
user@net1:~$
```

然后，我们将另一端的 VETH 对放入`edge_bridge2`连接`net1`到边缘桥接：

```
user@net1:~$ sudo ip link set edge_veth2 master edge_bridge2
```

然后，我们再次启动所有相关接口：

```
user@net1:~$ sudo ip link set edge_bridge2 up
user@net1:~$ sudo ip link set host_veth2 up
user@net1:~$ sudo ip link set edge_veth2 up
```

最后，我们读取我们到达`net3`的虚拟接口的路由：

```
user@net1:~$ sudo ip route add 172.16.10.192/26 via 172.16.10.66
```

配置完成后，我们应该再次完全进入环境和所有接口的可达性。如果配置有任何问题，您应该能够通过使用`ip link show`和`ip addr show`命令来诊断它们。

如果您曾经怀疑 VETH 对的另一端是什么，您可以使用`ethtool`命令行工具返回对的另一端。例如，假设我们创建一个非命名的 VETH 对如下所示：

```
user@docker1:/$ sudo ip link add type veth
user@docker1:/$ ip link show
…<output removed for brevity>,,,
16: **veth1@veth2**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 12:3f:7b:8d:33:90 brd ff:ff:ff:ff:ff:ff
17: **veth2@veth1**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 9e:9f:34:bc:49:73 brd ff:ff:ff:ff:ff:ff
```

在这个例子中很明显，我们可以使用`ethtool`来确定这个 VETH 对的接口索引或 ID 的一端或另一端：

```
user@docker1:/$ ethtool -S **veth1
NIC statistics:
     peer_ifindex: **17
user@docker1:/$ ethtool -S **veth2
NIC statistics:
     peer_ifindex: **16
user@docker1:/$
```

在确定 VETH 对的端点不像在这些示例中那样明显时，这可能是一个方便的故障排除工具。

# 探索网络命名空间

网络命名空间允许您创建网络的隔离视图。命名空间具有唯一的路由表，可以与主机上的默认路由表完全不同。此外，您可以将物理主机的接口映射到命名空间中，以在命名空间内使用。网络命名空间的行为与大多数现代网络硬件中可用的**虚拟路由和转发**（**VRF**）实例的行为非常相似。在本教程中，我们将学习网络命名空间的基础知识。我们将逐步介绍创建命名空间的过程，并讨论如何在网络命名空间中使用不同类型的接口。最后，我们将展示如何连接多个命名空间。

## 准备工作

为了查看和操作网络设置，您需要确保已安装了`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2
```

为了对主机进行网络更改，您还需要具有根级别的访问权限。这个示例将继续上一个示例中的实验室拓扑。之前提到的所有先决条件仍然适用。

## 如何做…

网络命名空间的概念最好通过一个例子来进行演示，所以让我们直接回到上一个示例中的实验室拓扑：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_01_08.jpg)

这个图表和上一个示例中使用的拓扑是一样的，但有一个重要的区别。我们增加了两个命名空间**NS_1**和**NS_2**。每个命名空间包含主机`net1`上的特定接口：

+   NS_1:

+   `edge_bridge1`

+   `eth1`

+   `edge_veth1`

+   NS_2:

+   `edge_bridge2`

+   `eth2`

+   `edge_veth2`

请注意命名空间的边界在哪里。在任何情况下，边界都位于物理接口（`net1`主机的`eth1`和`eth2`）上，或者直接位于 VETH 对的中间。正如我们将很快看到的，VETH 对可以在命名空间之间桥接，使它们成为连接网络命名空间的理想工具。

要开始重新配置，让我们从定义命名空间开始，然后将接口添加到命名空间中。定义命名空间相当简单。我们使用`ip netns add`子命令：

```
user@net1:~$ sudo ip netns add ns_1
user@net1:~$ sudo ip netns add ns_2
```

然后可以使用`ip netns list`命令来查看命名空间：

```
user@net1:~$ ip netns list
ns_2
ns_1
user@net1:~$
```

命名空间创建后，我们可以分配特定的接口给我们确定为每个命名空间的一部分的接口。在大多数情况下，这意味着告诉一个现有的接口它属于哪个命名空间。然而，并非所有接口都可以移动到网络命名空间中。例如，桥接可以存在于网络命名空间中，但需要在命名空间内实例化。为此，我们可以使用`ip netns exec`子命令来在命名空间内运行命令。例如，要在每个命名空间中创建边缘桥接，我们将运行这两个命令：

```
user@net1:~$ sudo ip netns exec ns_1 **ip link add \
edge_bridge1 type bridge
user@net1:~$ sudo ip netns exec ns_2 **ip link add \
edge_bridge2 type bridge

```

让我们把这个命令分成两部分：

+   `sudo ip nent exec ns_1`：这告诉主机你想在特定的命名空间内运行一个命令，在这种情况下是`ns_1`

+   `ip link add edge_bridge1 type bridge`：正如我们在之前的示例中看到的，我们执行这个命令来构建一个桥接并给它起一个名字，在这种情况下是`edge_bridge1`。

使用相同的语法，我们现在可以检查特定命名空间的网络配置。例如，我们可以使用`sudo ip netns exec ns_1 ip link show`查看接口：

```
user@net1:~$ sudo ip netns exec ns_1 **ip link show
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: **edge_bridge1**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
    link/ether 26:43:4e:a6:30:91 brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

正如我们预期的那样，我们在命名空间中看到了我们实例化的桥接器。图表中显示在命名空间中的另外两种接口类型是可以动态分配到命名空间中的类型。为此，我们使用`ip link set`命令：

```
user@net1:~$ sudo ip link set dev **eth1** netns **ns_1
user@net1:~$ sudo ip link set dev **edge_veth1** netns **ns_1
user@net1:~$ sudo ip link set dev **eth2** netns **ns_2
user@net1:~$ sudo ip link set dev **edge_veth2** netns **ns_2

```

现在，如果我们查看可用的主机接口，我们应该注意到我们移动的接口不再存在于默认命名空间中：

```
user@net1:~$ ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:2d:dd:79 brd ff:ff:ff:ff:ff:ff
5: host_bridge1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 56:cc:26:4c:76:f6 brd ff:ff:ff:ff:ff:ff
7: **edge_bridge1**: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
8: **edge_bridge2**: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default
    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
10: host_veth1@if9: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast master host_bridge1 state LOWERLAYERDOWN mode DEFAULT group default qlen 1000
    link/ether 56:cc:26:4c:76:f6 brd ff:ff:ff:ff:ff:ff
12: host_veth2@if11: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state LOWERLAYERDOWN mode DEFAULT group default qlen 1000
    link/ether 2a:8b:54:81:36:31 brd ff:ff:ff:ff:ff:ff
user@net1:~$
```

### 注意

您可能已经注意到，`edge_bridge1`和`edge_bridge2`仍然存在于此输出中，因为我们从未删除它们。这很有趣，因为它们现在也存在于命名空间`ns_1`和`ns_2`中。重要的是要指出，由于命名空间是完全隔离的，甚至接口名称也可以重叠。

现在所有接口都在正确的命名空间中，剩下的就是应用标准的桥接映射并启动接口。由于我们需要在每个命名空间中重新创建桥接接口，我们需要重新将接口附加到每个桥接器上。这就像通常做的那样；我们只需在命名空间内运行命令：

```
user@net1:~$ sudo ip netns exec ns_1 **ip link set \
dev edge_veth1 master edge_bridge1
user@net1:~$ sudo ip netns exec ns_1 **ip link set \
dev eth1 master edge_bridge1
user@net1:~$ sudo ip netns exec ns_2 **ip link set \
dev edge_veth2 master edge_bridge2
user@net1:~$ sudo ip netns exec ns_2 **ip link set \
dev eth2 master edge_bridge2

```

一旦我们将所有接口放入正确的命名空间并连接到正确的桥接器，剩下的就是将它们全部启动：

```
user@net1:~$ sudo ip netns exec ns_1 **ip link set edge_bridge1 up
user@net1:~$ sudo ip netns exec ns_1 **ip link set edge_veth1 up
user@net1:~$ sudo ip netns exec ns_1 **ip link set eth1 up
user@net1:~$ sudo ip netns exec ns_2 **ip link set edge_bridge2 up
user@net1:~$ sudo ip netns exec ns_2 **ip link set edge_veth2 up
user@net1:~$ sudo ip netns exec ns_2 **ip link set eth2 up

```

接口启动后，我们应该再次可以连接到所有三个主机连接的网络。

虽然命名空间的这个示例只是将第 2 层类型的结构移入了一个命名空间，但它们还支持每个命名空间具有唯一路由表实例的第 3 层路由。例如，如果我们查看其中一个命名空间的路由表，我们会发现它是完全空的：

```
user@net1:~$ sudo ip netns exec ns_1 ip route
user@net1:~$
```

这是因为在命名空间中没有定义 IP 地址的接口。这表明命名空间内部隔离了第 2 层和第 3 层结构。这是网络命名空间和 VRF 实例之间的一个主要区别。VRF 实例只考虑第 3 层配置，而网络命名空间隔离了第 2 层和第 3 层结构。在第三章中，当我们讨论 Docker 用于容器网络的过程时，我们将在*用户定义的网络*中看到网络命名空间中的第 3 层隔离的示例。


# 第二章：配置和监控 Docker 网络

在本章中，我们将涵盖以下内容：

+   验证影响 Docker 网络的主机级设置

+   在桥接模式下连接容器

+   暴露和发布端口

+   连接容器到现有容器

+   在主机模式下连接容器

+   配置服务级设置

# 介绍

Docker 使得使用容器技术比以往任何时候都更容易。Docker 以其易用性而闻名，提供了许多高级功能，但安装时使用了一组合理的默认设置，使得快速开始构建容器变得容易。虽然网络配置通常是需要在使用之前额外关注的一个领域，但 Docker 使得让容器上线并连接到网络变得容易。

# 验证影响 Docker 网络的主机级设置

Docker 依赖于主机能够执行某些功能来使 Docker 网络工作。换句话说，您的 Linux 主机必须配置为允许 IP 转发。此外，自 Docker 1.7 发布以来，您现在可以选择使用 hairpin Network Address Translation（NAT）而不是默认的 Docker 用户空间代理。在本教程中，我们将回顾主机必须启用 IP 转发的要求。我们还将讨论 NAT hairpin，并讨论该选项的主机级要求。在这两种情况下，我们将展示 Docker 对其设置的默认行为，以及您如何更改它们。

## 准备工作

您需要访问运行 Docker 的 Linux 主机，并能够停止和重新启动服务。由于我们将修改系统级内核参数，您还需要对系统具有根级访问权限。

## 如何做…

正如我们在第一章中所看到的，Linux 主机必须启用 IP 转发才能够在接口之间路由流量。由于 Docker 正是这样做的，因此 Docker 网络需要启用 IP 转发才能正常工作。如果 Docker 检测到 IP 转发被禁用，当您尝试运行容器时，它将警告您存在问题：

```
user@docker1:~$ docker run --name web1 -it \
jonlangemak/web_server_1 /bin/bash
WARNING: **IPv4 forwarding is disabled. Networking will not work.
root@071d673821b8:/#
```

大多数 Linux 发行版将 IP 转发值默认为`disabled`或`0`。幸运的是，在默认配置中，Docker 会在 Docker 服务启动时负责更新此设置为正确的值。例如，让我们看一个刚刚重启过并且没有在启动时启用 Docker 服务的主机。如果我们在启动 Docker 之前检查设置的值，我们会发现它是禁用的。启动 Docker 引擎会自动为我们启用该设置：

```
user@docker1:~$ more /proc/sys/net/ipv4/ip_forward
0
user@docker1:~$
user@docker1:~$ sudo systemctl start docker
user@docker1:~$ sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = **1
user@docker1:~$
```

Docker 中的这种默认行为可以通过在运行时选项中传递`--ip-forward=false`来更改为否。

### 注意

Docker 特定参数的配置根据使用的**init 系统**而有很大不同。在撰写本文时，许多较新的 Linux 操作系统使用`systemd`作为其 init 系统。始终请查阅 Docker 文档，以了解其针对您使用的操作系统的服务配置建议。Docker 服务配置和选项将在本章的即将推出的食谱中更详细地讨论。在本食谱中，只需关注更改这些设置对 Docker 和主机本身的影响。

有关内核 IP 转发参数的进一步讨论可以在第一章的*配置 Linux 主机路由*食谱中找到，*Linux 网络构造*。在那里，您将找到如何自己更新参数以及如何通过重新启动使设置持久化。

Docker 的另一个最近的功能依赖于内核级参数，即 hairpin NAT 功能。较早版本的 Docker 实现并依赖于所谓的 Docker **用户态代理**来促进容器间和发布端口的通信。默认情况下，任何暴露端口的容器都是通过用户态代理进程来实现的。例如，如果我们启动一个示例容器，我们会发现除了 Docker 进程本身外，我们还有一个`docker-proxy`进程：

```
user@docker1:~$ docker run --name web1 -d -P jonlangemak/web_server_1
bf3cb30e826ce53e6e7db4e72af71f15b2b8f83bd6892e4838ec0a59b17ac33f
user@docker1:~$
user@docker1:~$ ps aux | grep docker
root       771  0.0  0.1 509676 41656 ?        Ssl  19:30   0:00 /usr/bin/docker daemon
root      1861  0.2  0.0 117532 28024 ?        Sl   19:41   0:00 **docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 32769 -container-ip 172.17.0.2 -container-port 80
…<Additional output removed for brevity>…
user@docker1:~$
```

每个发布的端口都会在 Docker 主机上启动一个新的`docker-proxy`进程。作为用户态代理的替代方案，您可以选择让 Docker 使用 hairpin NAT 而不是用户态代理。Hairpin NAT 依赖于主机系统配置为在主机的本地环回接口上启用路由。同样，当 Docker 服务启动时，Docker 服务会负责更新正确的主机参数以启用此功能，如果被告知这样做的话。

Hairpin NAT 依赖于内核参数`net.ipv4.conf.docker0.route_localnet`被启用（设置为`1`），以便主机可以通过主机的环回接口访问容器服务。这可以通过与我们描述 IP 转发参数的方式实现：

使用`sysctl`命令：

```
sysctl net.ipv4.conf.docker0.route_localnet 
```

通过直接查询`/proc/`文件系统：

```
more /proc/sys/net/ipv4/conf/docker0/route_localnet
```

如果返回的值是`0`，那么 Docker 很可能处于其默认配置，并依赖于用户态代理。由于您可以选择在两种模式下运行 Docker，我们需要做的不仅仅是更改内核参数，以便对 hairpin NAT 进行更改。我们还需要告诉 Docker 通过将选项`--userland-proxy=false`作为运行时选项传递给 Docker 服务来更改其发布端口的方式。这样做将启用 hairpin NAT，并告诉 Docker 更新内核参数以使 hairpin NAT 正常工作。让我们启用 hairpin NAT 以验证 Docker 是否正在执行其应该执行的操作。

首先，让我们检查内核参数的值：

```
user@docker1:~$ sysctl net.ipv4.conf.docker0.route_localnet
net.ipv4.conf.docker0.route_localnet = 0
user@docker1:~$
```

它目前被禁用。现在我们可以告诉 Docker 通过将`--userland-proxy=false`作为参数传递给 Docker 服务来禁用用户态代理。一旦 Docker 服务被告知禁用用户态代理，并且服务被重新启动，我们应该看到参数在主机上被启用：

```
user@docker1:~$ sysctl net.ipv4.conf.docker0.route_localnet
net.ipv4.conf.docker0.route_localnet = **1
user@docker1:~$
```

此时运行具有映射端口的容器将不会创建额外的`docker-proxy`进程实例：

```
user@docker1:~$ docker run --name web1 -d -P jonlangemak/web_server_1
5743fac364fadb3d86f66cb65532691fe926af545639da18f82a94fd35683c54
user@docker1:~$ ps aux | grep docker
root      2159  0.1  0.1 310696 34880 ?        Ssl  14:26   0:00 /usr/bin/docker daemon --userland-proxy=false
user@docker1:~$
```

此外，我们仍然可以通过主机的本地接口访问容器：

```
user@docker1:~$ **curl 127.0.0.1:32768
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

再次禁用参数会导致此连接失败：

```
user@docker1:~$ **sudo sysctl -w net.ipv4.conf.docker0.route_localnet=0
net.ipv4.conf.docker0.route_localnet = 0
user@docker1:~$ curl 127.0.0.1:32768
curl: (7) Failed to connect to 127.0.0.1 port 32768: Connection timed out
user@docker1:~$
```

# 在桥接模式下连接容器

正如我们之前提到的，Docker 带有一组合理的默认值，可以使您的容器在网络上进行通信。从网络的角度来看，Docker 的默认设置是将任何生成的容器连接到`docker0`桥接器上。在本教程中，我们将展示如何在默认桥接模式下连接容器，并解释离开容器和目的地容器的网络流量是如何处理的。

## 做好准备

您需要访问 Docker 主机，并了解您的 Docker 主机如何连接到网络。在我们的示例中，我们将使用一个具有两个物理网络接口的 Docker 主机，就像下图所示的那样：

![做好准备](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_01.jpg)

您需要确保可以查看`iptables`规则以验证**netfilter**策略。如果您希望下载和运行示例容器，您的 Docker 主机还需要访问互联网。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做…

安装并启动 Docker 后，您应该注意到添加了一个名为`docker0`的新 Linux 桥。默认情况下，`docker0`桥的 IP 地址为`172.17.0.1/16`：

```
user@docker1:~$ **ip addr show docker0
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:54:87:8b:ea brd ff:ff:ff:ff:ff:ff
    inet **172.17.0.1/16** scope global docker0
       valid_lft forever preferred_lft forever
user@docker1:~$
```

Docker 将在未指定网络的情况下启动的任何容器放置在`docker0`桥上。现在，让我们看一个在此主机上运行的示例容器：

```
user@docker1:~$ **docker run -it jonlangemak/web_server_1 /bin/bash
root@abe6eae2e0b3:/# **ip addr
1: **lo**: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet **127.0.0.1/8** scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
6: **eth0**@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.17.0.2/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
root@abe6eae2e0b3:/# 
```

通过以交互模式运行容器，我们可以查看容器认为自己的网络配置是什么。在这种情况下，我们可以看到容器有一个非回环网络适配器（`eth0`），IP 地址为`172.17.0.2/16`。

此外，我们可以看到容器认为其默认网关是 Docker 主机上的`docker0`桥接口：

```
root@abe6eae2e0b3:/# **ip route
default via 172.17.0.1 dev eth0
172.17.0.0/16 dev eth0  proto kernel  scope link  src 172.17.0.2
root@abe6eae2e0b3:/#
```

通过运行一些基本测试，我们可以看到容器可以访问 Docker 主机的物理接口以及基于互联网的资源。

### 注意

基于互联网的访问容器本身的前提是 Docker 主机可以访问互联网。

```
root@abe6eae2e0b3:/# **ping 10.10.10.101 -c 2
PING 10.10.10.101 (10.10.10.101): 48 data bytes
56 bytes from 10.10.10.101: icmp_seq=0 ttl=64 time=0.084 ms
56 bytes from 10.10.10.101: icmp_seq=1 ttl=64 time=0.072 ms
--- 10.10.10.101 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.072/0.078/0.084/0.000 ms
root@abe6eae2e0b3:/#
root@abe6eae2e0b3:/# **ping 4.2.2.2 -c 2
PING 4.2.2.2 (4.2.2.2): 48 data bytes
56 bytes from 4.2.2.2: icmp_seq=0 ttl=50 time=29.388 ms
56 bytes from 4.2.2.2: icmp_seq=1 ttl=50 time=26.766 ms
--- 4.2.2.2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 26.766/28.077/29.388/1.311 ms
root@abe6eae2e0b3:/#
```

考虑到容器所在的网络是由 Docker 创建的，我们可以安全地假设网络的其余部分不知道它。也就是说，外部网络不知道`172.17.0.0/16`网络，因为它是本地的 Docker 主机。也就是说，容器能够访问`docker0`桥之外的资源似乎有些奇怪。Docker 通过将容器的 IP 地址隐藏在 Docker 主机的 IP 接口后使其工作。流量流向如下图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_02.jpg)

由于容器的流量在物理网络上被视为 Docker 主机的 IP 地址，其他网络资源知道如何将流量返回到容器。为了执行这种出站 NAT，Docker 使用 Linux netfilter 框架。我们可以使用 netfilter 命令行工具`iptables`来查看这些规则：

```
user@docker1:~$ sudo iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination
DOCKER     all  --  anywhere             anywhere             ADDRTYPE match dst-type LOCAL

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
DOCKER     all  --  anywhere            !127.0.0.0/8          ADDRTYPE match dst-type LOCAL

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
MASQUERADE  all  --  172.17.0.0/16        anywhere

Chain DOCKER (2 references)
target     prot opt source               destination
RETURN     all  --  anywhere             anywhere
user@docker1:~$

```

正如你所看到的，我们在`POSTROUTING`链中有一个规则，它将来自我们的`docker0`桥（`172.17.0.0/16`）的任何东西伪装或隐藏在主机接口的背后。

尽管出站连接是默认配置和允许的，但 Docker 默认情况下不提供一种从 Docker 主机外部访问容器中的服务的方法。为了做到这一点，我们必须在容器运行时传递额外的标志给 Docker。具体来说，当我们运行容器时，我们可以传递`-P`标志。为了检查这种行为，让我们看一个暴露端口的容器镜像：

```
docker run --name web1 -d -P jonlangemak/web_server_1
```

这告诉 Docker 将一个随机端口映射到容器镜像暴露的任何端口。在这个演示容器的情况下，镜像暴露端口`80`。运行容器后，我们可以看到主机端口映射到容器：

```
user@docker1:~$ docker run --name web1 **-P** -d jonlangemak/web_server_1
556dc8cefd79ed1d9957cc52827bb23b7d80c4b887ee173c2e3b8478340de948
user@docker1:~$
user@docker1:~$ docker port web1
80/tcp -> 0.0.0.0:32768
user@docker1:~$
```

正如我们所看到的，容器端口`80`已经映射到主机端口`32768`。这意味着我们可以通过主机的接口在端口`32768`上访问容器上运行的端口`80`的服务。与出站容器访问类似，入站连接也使用 netfilter 来创建端口映射。我们可以通过检查 NAT 和过滤表来看到这一点：

```
user@docker1:~$ sudo iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination
DOCKER     all  --  anywhere             anywhere             ADDRTYPE match dst-type LOCAL

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
DOCKER     all  --  anywhere            !127.0.0.0/8          ADDRTYPE match dst-type LOCAL

Chain POSTROUTING (policy ACCEPT)
target     prot opt source          destination
MASQUERADE  all  --  172.17.0.0/16  anywhere
MASQUERADE  tcp  --  172.17.0.2     172.17.0.2           tcp dpt:http

Chain DOCKER (2 references)
target     prot opt source               destination
RETURN     all  --  anywhere             anywhere
DNAT       tcp  --  anywhere             anywhere             tcp dpt:32768 to:172.17.0.2:80
user@docker1:~$ sudo iptables -t filter -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
DOCKER-ISOLATION  all  --  anywhere             anywhere
DOCKER     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain DOCKER (1 references)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             172.17.0.2           tcp dpt:http

Chain DOCKER-ISOLATION (1 references)
target     prot opt source               destination
RETURN     all  --  anywhere             anywhere
user@docker1:~$
```

由于连接在所有接口（`0.0.0.0`）上暴露，我们的入站图将如下所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_03.jpg)

如果没有另行定义，生活在同一主机上的容器，因此是相同的`docker0`桥，可以通过它们分配的 IP 地址在任何端口上固有地相互通信，这些端口绑定到服务。允许这种通信是默认行为，并且可以在后面的章节中更改，当我们讨论**容器间通信**（**ICC**）配置时会看到。

### 注意

应该注意的是，这是在没有指定任何额外网络参数的情况下运行的容器的默认行为，也就是说，使用 Docker 默认桥接网络的容器。后面的章节将介绍其他选项，允许您将生活在同一主机上的容器放置在不同的网络上。

生活在不同主机上的容器之间的通信需要使用先前讨论的流程的组合。为了测试这一点，让我们通过添加一个名为`docker2`的第二个主机来扩展我们的实验。假设主机`docker2`上的容器`web2`希望访问主机`docker1`上的容器`web1`，后者在端口`80`上托管服务。流程将如下所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_04.jpg)

让我们在每个步骤中走一遍流程，并展示数据包在每个步骤中传输时的样子。在这种情况下，容器`web1`正在暴露端口`80`，该端口已发布到主机`docker1`的端口`32771`。

1.  流量离开容器`web2`，目的地是主机`docker1`的`10.10.10.101`接口上的暴露端口（`32771`）：![操作步骤…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_05.jpg)

1.  流量到达容器的默认网关，即`docker0`桥接的 IP 接口（`172.17.0.1`）。主机进行路由查找，并确定目的地位于其`10.10.10.102`接口之外，因此它将容器的真实源 IP 隐藏在该接口的 IP 地址后面：![操作步骤…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_06.jpg)

1.  流量到达`docker1`主机，并由 netfilter 规则检查。`docker1`有一个规则，将容器 1 的服务端口（`80`）暴露在主机的端口`32271`上：![操作步骤…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_07.jpg)

1.  目标端口从`32771`更改为`80`，并传递到`web1`容器，该容器在正确的端口`80`上接收流量：![操作步骤…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_08.jpg)

为了自己尝试一下，让我们首先运行`web1`容器并检查服务暴露在哪个端口上：

```
user@docker1:~/apache$ docker run --name web1 -P \
-d jonlangemak/web_server_1
974e6eba1948ce5e4c9ada393b1196482d81f510de 12337868ad8ef65b8bf723
user@docker1:~/apache$
user@docker1:~/apache$ docker port web1
80/tcp -> **0.0.0.0:32771
user@docker1:~/apache$
```

现在让我们在主机 docker2 上运行一个名为 web2 的第二个容器，并尝试访问端口 32771 上的 web1 服务…

```
user@docker2:~$ docker run --name web2 -it \
jonlangemak/web_server_2 /bin/bash
root@a97fea6fb0c9:/#
root@a97fea6fb0c9:/# curl http://**10.10.10.101:32771
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
```

# 暴露和发布端口

正如我们在之前的例子中看到的，将容器中的服务暴露给外部世界是 Docker 的一个关键组成部分。到目前为止，我们已经让镜像和 Docker 引擎在实际端口映射方面为我们做了大部分工作。为了做到这一点，Docker 使用了容器镜像的元数据以及用于跟踪端口分配的内置系统的组合。在这个示例中，我们将介绍定义要暴露的端口以及发布端口的选项的过程。

## 准备工作

您需要访问一个 Docker 主机，并了解您的 Docker 主机如何连接到网络。在这个示例中，我们将使用之前示例中使用的`docker1`主机。您需要确保可以查看`iptables`规则以验证 netfilter 策略。如果您希望下载和运行示例容器，您的 Docker 主机还需要访问互联网。在某些情况下，我们所做的更改可能需要您具有系统的 root 级别访问权限。

## 操作步骤…

虽然经常混淆，但暴露端口和发布端口是两个完全不同的操作。暴露端口实际上只是一种记录容器可能提供服务的端口的方式。这些定义存储在容器元数据中作为镜像的一部分，并可以被 Docker 引擎读取。发布端口是将容器端口映射到主机端口的实际过程。这可以通过使用暴露的端口定义自动完成，也可以在不使用暴露端口的情况下手动完成。

让我们首先讨论端口是如何暴露的。暴露端口的最常见机制是在镜像的**Dockerfile**中定义它们。当您构建一个容器镜像时，您有机会定义要暴露的端口。考虑一下我用来构建本书一些演示容器的 Dockerfile 定义：

```
FROM ubuntu:12.04
MAINTAINER Jon Langemak jon@interubernet.com
RUN apt-get update && apt-get install -y apache2 net-tools inetutils-ping curl
ADD index.html /var/www/index.html
ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2
EXPOSE 80
CMD ["/usr/sbin/apache2", "-D", "FOREGROUND"]
```

作为 Dockerfile 的一部分，我可以定义我希望暴露的端口。在这种情况下，我知道 Apache 默认会在端口`80`上提供其 Web 服务器，所以这是我希望暴露的端口。

### 注意

请注意，默认情况下，Docker 始终假定您所指的端口是 TCP。如果您希望暴露 UDP 端口，可以在端口定义的末尾包括`/udp`标志来实现。例如，`EXPOSE 80/udp`。

现在，让我们运行一个使用这个 Dockerfile 构建的容器，看看会发生什么：

```
user@docker1:~$ docker run --name web1 -d jonlangemak/web_server_1
b0177ed2d38afe4f4d8c26531d00407efc0fee6517ba5a0f49955910a5dbd426
user@docker1:~$
user@docker1:~$ docker port web1
user@docker1:~$
```

正如我们所看到的，尽管有一个定义的要暴露的端口，Docker 实际上并没有在主机和容器之间映射任何端口。如果您回忆一下之前的示例，其中容器提供了一个服务，我们在`docker run`命令语法中包含了`-P`标志。`-P`标志告诉 Docker 发布所有暴露的端口。让我们尝试使用设置了`-P`标志的容器运行此容器：

```
user@docker1:~$ docker run --name web1 -d -P jonlangemak/web_server_1
d87d36d7cbcfb5040f78ff730d079d353ee81fde36ecbb5ff932ff9b9bef5502
user@docker1:~$
user@docker1:~$ docker port web1
80/tcp -> 0.0.0.0:32775
user@docker1:~$
```

在这里，我们可以看到 Docker 现在已经自动将暴露的端口映射到主机上的一个随机高端口。端口`80`现在将被视为已发布。

除了通过镜像 Dockerfile 暴露端口，我们还可以在容器运行时暴露它们。以这种方式暴露的任何端口都将与 Dockerfile 中暴露的端口合并。例如，让我们再次运行相同的容器，并在`docker run`命令中暴露端口`80` UDP：

```
user@docker1:~$ docker run --name web1 **--expose=80/udp \
-d -P jonlangemak/web_server_1
f756deafed26f9635a3b9c738089495efeae86a393f94f17b2c4fece9f71a704
user@docker1:~$
user@docker1:~$ docker port web1
80/udp -> 0.0.0.0:32768
80/tcp -> 0.0.0.0:32776
user@docker1:~$
```

如您所见，我们不仅发布了来自 Dockerfile 的端口（`80/tcp`），还发布了来自`docker run`命令的端口（`80/udp`）。

### 注意

在容器运行时暴露端口允许您有一些额外的灵活性，因为您可以定义要暴露的端口范围。这在 Dockerfile 的`expose`语法中目前是不可能的。当暴露一系列端口时，您可以通过在命令的末尾添加您要查找的容器端口来过滤`docker port`命令的输出。

虽然暴露方法确实很方便，但它并不能满足我们所有的需求。对于您想要更多控制使用的端口和接口的情况，您可以在启动容器时绕过`expose`并直接发布端口。通过传递`-P`标志发布所有暴露的端口，通过传递`-p`标志允许您指定映射端口时要使用的特定端口和接口。`-p`标志可以采用几种不同的形式，语法看起来像这样：

```
–p <host IP interface>:<host port>:<container port>
```

任何选项都可以省略，唯一需要的字段是容器端口。例如，以下是您可以使用此语法的几种不同方式：

+   指定主机端口和容器端口：

```
–p <host port>:<container port>
```

+   指定主机接口、主机端口和容器端口：

```
–p <host IP interface>:<host port>:<container port>
```

+   指定主机接口，让 Docker 选择一个随机的主机端口，并指定容器端口：

```
–p <host IP interface>::<container port>
```

+   只指定一个容器端口，让 Docker 使用一个随机的主机端口：

```
–p <container port>
```

到目前为止，我们看到的所有发布的端口都使用了目标 IP 地址（`0.0.0.0`），这意味着它们绑定到 Docker 主机的所有 IP 接口。默认情况下，Docker 服务始终将发布的端口绑定到所有主机接口。然而，正如我们将在本章的下一个示例中看到的那样，我们可以告诉 Docker 通过传递`--ip`参数来使用特定的接口。

鉴于我们还可以在`docker run`命令中定义要绑定的发布端口的接口，我们需要知道哪个选项优先级更高。一般规则是，在容器运行时定义的任何选项都会获胜。例如，让我们看一个例子，我们告诉 Docker 服务通过向服务传递以下选项来绑定到`docker1`主机的`192.168.10.101` IP 地址：

```
--ip=10.10.10.101
```

现在，让我们以几种不同的方式运行一个容器，并查看结果：

```
user@docker1:~$ docker run --name web1 -P -d jonlangemak/web_server_1
629129ccaebaa15720399c1ac31c1f2631fb4caedc7b3b114a92c5a8f797221d
user@docker1:~$ docker port web1
80/tcp -> 10.10.10.101:32768
user@docker1:~$
```

在前面的例子中，我们看到了预期的行为。发布的端口绑定到服务级别`--ip`选项（`10.10.10.101`）中指定的 IP 地址。然而，如果我们在容器运行时指定 IP 地址，我们可以覆盖服务级别的设置：

```
user@docker1:~$ docker run --name web2 **-p 0.0.0.0::80 \
-d jonlangemak/web_server_2
7feb252d7bd9541fe7110b2aabcd6a50522531f8d6ac5422f1486205fad1f666
user@docker1:~$ docker port web2
80/tcp -> 0.0.0.0:32769
user@docker1:~$
We can see that we specified a host IP address of 0.0.0.0, which will match all the IP addresses on the Docker host. When we check the port mapping, we see that the 0.0.0.0 specified in the command overrode the service-level default.
```

您可能不会发现暴露端口的用途，而是完全依赖手动发布它们。`EXPOSE`命令不是创建镜像的 Dockerfile 的要求。不定义暴露端口的容器镜像可以直接发布，如以下命令所示：

```
user@docker1:~$ docker run --name noexpose **-p 0.0.0.0:80:80 \
-d jonlangemak/web_server_noexpose
2bf21219b45ba05ef7169fc30d5eac73674857573e54fd1a0499b73557fdfd45
user@docker1:~$ docker port noexpose
80/tcp -> 0.0.0.0:80
user@docker1:~$
```

在上面的示例中，容器镜像`jonlangemak/web_server_noexpose`是一个不在其定义中暴露任何端口的容器。

# 连接容器到现有容器

到目前为止，Docker 网络连接依赖于将托管在容器中的单个服务暴露给物理网络。但是，如果您想将一个容器中的服务暴露给另一个容器而不暴露给 Docker 主机怎么办？在本教程中，我们将介绍如何在同一 Docker 主机上运行的两个容器之间映射服务。

## 准备工作

您将需要访问 Docker 主机，并了解您的 Docker 主机如何连接到网络。在本教程中，我们将使用之前教程中使用过的`docker1`主机。您需要确保可以访问`iptables`规则以验证 netfilter 策略。如果您希望下载和运行示例容器，您的 Docker 主机还需要访问互联网。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 操作步骤...

有时将一个容器中的服务映射到另一个容器中被称为映射容器模式。映射容器模式允许您启动一个利用现有或主要容器网络配置的容器。也就是说，映射容器将使用与主容器相同的 IP 和端口配置。举个例子，让我们考虑运行以下容器：

```
user@docker1:~$ docker run --name web4 -d -P \
jonlangemak/web_server_4_redirect
```

运行此容器将以桥接模式启动容器，并将其附加到`docker0`桥接，正如我们所期望的那样。

此时，拓扑看起来非常标准，类似于以下拓扑所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_09.jpg)

现在在同一主机上运行第二个容器，但这次指定网络应该是主容器`web4`的网络：

```
user@docker1:~$ docker run --name web3 -d **--net=container:web4 \
jonlangemak/web_server_3_8080
```

我们的拓扑现在如下所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_10.jpg)

请注意，容器`web3`现在被描述为直接连接到`web4`，而不是`docker0`桥接。通过查看每个容器的网络配置，我们可以验证这是否属实：

```
user@docker1:~$ **docker exec web4 ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
16: **eth0**@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:11:00:02** brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
user@docker1:~$ **docker exec web3 ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
16: **eth0**@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:11:00:02** brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

正如我们所看到的，接口在 IP 配置和 MAC 地址方面都是相同的。在`docker run`命令中使用`--net:container<container name/ID>`的语法将新容器加入到与所引用容器相同的网络结构中。这意味着映射的容器具有与主容器相同的网络配置。

这种配置有一个值得注意的限制。加入另一个容器网络的容器无法发布自己的任何端口。因此，这意味着我们无法将映射容器的端口发布到主机，但我们可以在本地使用它们。回到我们的例子，这意味着我们无法将容器`web3`的端口`8080`发布到主机。但是，容器`web4`可以在本地使用容器`web3`的未发布服务。例如，这个例子中的每个容器都托管一个 Web 服务：

+   `web3`托管在端口`8080`上运行的 Web 服务器

+   `web4`托管在端口`80`上运行的 Web 服务器

从外部主机的角度来看，无法访问容器`web3`的 Web 服务。但是，我们可以通过容器`web4`访问这些服务。容器`web4`托管一个名为`test.php`的 PHP 脚本，该脚本提取其自己的 Web 服务器以及在端口`8080`上运行的 Web 服务器的索引页面。脚本如下：

```
<?
$page = file_get_contents('**http://localhost:80/**');
echo $page;
$page1 = file_get_contents('**http://localhost:8080/**');
echo $page1;
?>
```

脚本位于 Web 服务器的根托管目录（`/var/www/`）中，因此我们可以通过浏览`web4`容器的发布端口，然后跟上`test.php`来访问端口：

```
user@docker1:~$ docker port web4
80/tcp -> 0.0.0.0:32768
user@docker1:~$
user@docker1:~$ curl **http://localhost:32768/test.php
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #4 - Running on port 80**</span>
    </h1>
</body>
  </html>
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #3 - Running on port 8080**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

如您所见，脚本能够从两个容器中提取索引页面。让我们停止容器`web3`，然后再次运行此测试，以证明它确实是提供此索引页面响应的容器：

```
user@docker1:~$ docker stop web3
web3
user@docker1:~$ curl **http://localhost:32768/test.php
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #4 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

如您所见，我们不再从映射的容器中获得响应。映射容器模式对于需要向现有容器提供服务但不需要直接将映射容器的任何端口发布到 Docker 主机或外部网络的情况非常有用。尽管映射容器无法发布自己的任何端口，但这并不意味着我们不能提前发布它们。

例如，当我们运行主容器时，我们可以暴露端口`8080`：

```
user@docker1:~$ docker run --name web4 -d **--expose 8080 \
-P** jonlangemak/web_server_4_redirect
user@docker1:~$ docker run --name web3 -d **--net=container:web4 \
jonlangemak/web_server_3_8080
```

因为我们在运行主容器（`web4`）时发布了映射容器的端口，所以在运行映射容器（`web3`）时就不需要再次发布它。现在我们应该能够通过其发布的端口直接访问每个服务：

```
user@docker1:~$ docker port web4
80/tcp -> 0.0.0.0:32771
8080/tcp -> 0.0.0.0:32770
user@docker1:~$
user@docker1:~$ curl **localhost:32771
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #4 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$ curl **localhost:32770
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #3 - Running on port 8080**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

在映射容器模式下，应注意不要尝试在不同的容器上公开或发布相同的端口。由于映射容器与主容器共享相同的网络结构，这将导致端口冲突。

# 在主机模式下连接容器

到目前为止，我们所做的所有配置都依赖于使用`docker0`桥来促进容器之间的连接。我们不得不考虑端口映射、NAT 和容器连接点。由于我们连接和寻址容器的方式的性质以及确保灵活的部署模型，必须考虑这些因素。主机模式采用了一种不同的方法，直接将容器绑定到 Docker 主机的接口上。这不仅消除了入站和出站 NAT 的需要，还限制了我们可以部署容器的方式。由于容器将位于与物理主机相同的网络结构中，我们不能重叠服务端口，因为这将导致冲突。在本教程中，我们将介绍在主机模式下部署容器，并描述这种方法的优缺点。

## 准备工作

您需要访问一个 Docker 主机，并了解您的 Docker 主机如何连接到网络。在本教程中，我们将使用之前教程中使用过的`docker1`和`docker2`主机。您需要确保可以查看`iptables`规则以验证 netfilter 策略。如果您希望下载和运行示例容器，您的 Docker 主机还需要访问互联网。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做…

从 Docker 的角度来看，在这种模式下部署容器相当容易。就像映射容器模式一样，我们将一个容器放入另一个容器的网络结构中；主机模式直接将一个容器放入 Docker 主机的网络结构中。不再需要发布和暴露端口，因为你将容器直接映射到主机的网络接口上。这意味着容器进程可以执行某些特权操作，比如在主机上打开较低级别的端口。因此，这个选项应该谨慎使用，因为在这种配置下容器将对系统有更多的访问权限。

这也意味着 Docker 不知道你的容器在使用什么端口，并且无法阻止你部署具有重叠端口的容器。让我们在主机模式下部署一个测试容器，这样你就能明白我的意思了：

```
user@docker1:~$ docker run --name web1 -d **--net=host \
jonlangemak/web_server_1
64dc47af71fade3cde02f7fed8edf7477e3cc4c8fc7f0f3df53afd129331e736
user@docker1:~$
user@docker1:~$ curl **localhost
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

为了使用主机模式，我们在容器运行时传递`--net=host`标志。在这种情况下，你可以看到没有任何端口映射，我们仍然可以访问容器中的服务。Docker 只是将容器绑定到 Docker 主机，这意味着容器提供的任何服务都会自动映射到 Docker 主机的接口上。

如果我们尝试在端口`80`上运行另一个提供服务的容器，我们会发现 Docker 并不会阻止我们：

```
user@docker1:~$ docker run --name web2 -d **--net=host \
jonlangemak/web_server_2
c1c00aa387111e1bb09e3daacc2a2820c92f6a91ce73694c1e88691c3955d815
user@docker1:~$
```

虽然从 Docker 的角度来看，这看起来像是一个成功的容器启动，但实际上容器在被生成后立即死掉了。如果我们检查容器`web2`的日志，我们会发现它遇到了冲突，无法启动：

```
user@docker1:~$ docker logs **web2
apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1 for ServerName
(98)**Address already in use: make_sock: could not bind to address 0.0.0.0:80
no listening sockets available, shutting down
Unable to open logs
user@docker1:~$
```

在主机模式下部署容器会限制你可以运行的服务数量，除非你的容器被构建为在不同端口上提供相同的服务。

由于服务的配置和它所使用的端口是容器的责任，我们可以通过一种方式部署多个使用相同服务端口的容器。举个例子，我们之前提到的两个 Docker 主机，每个主机有两个网络接口：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_11.jpg)

在一个场景中，你的 Docker 主机有多个网络接口，你可以让容器绑定到不同接口上的相同端口。同样，由于这是容器的责任，只要你不尝试将相同的端口绑定到多个接口上，Docker 就不会知道你是如何实现这一点的。

解决方案是更改服务绑定到接口的方式。大多数服务在启动时绑定到所有接口（`0.0.0.0`）。例如，我们可以看到我们的容器`web1`绑定到 Docker 主机上的`0.0.0.0:80`：

```
user@docker1:~$ sudo netstat -plnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3724/apache2
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1056/sshd
tcp6       0      0 :::22                   :::*                    LISTEN      1056/sshd
user@docker1:~$ 
```

我们可以限制服务的范围，而不是让服务绑定到所有接口。如果我们可以将容器服务绑定到一个接口，我们就可以将相同的端口绑定到不同的接口而不会引起冲突。在这个例子中，我创建了两个容器镜像，允许您向它们传递一个环境变量（`$APACHE_IPADDRESS`）。该变量在 Apache 配置中被引用，并指定服务应该绑定到哪个接口。我们可以通过在主机模式下部署两个容器来测试这一点：

```
user@docker1:~$ docker run --name web6 -d --net=host \
-e APACHE_IPADDRESS=10.10.10.101** jonlangemak/web_server_6_pickip
user@docker1:~$ docker run --name web7 -d --net=host \
-e APACHE_IPADDRESS=192.168.10.101** jonlangemak/web_server_7_pickip
```

请注意，在每种情况下，我都会向容器传递一个不同的 IP 地址，以便它绑定到。快速查看主机上的端口绑定应该可以确认容器不再绑定到所有接口：

```
user@docker1:~$ sudo netstat -plnt
[sudo] password for user:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.10.101:80       0.0.0.0:*               LISTEN      1518/apache2
tcp        0      0 10.10.10.101:80         0.0.0.0:*               LISTEN      1482/apache2
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1096/sshd
tcp6       0      0 :::22                   :::*                    LISTEN      1096/sshd
user@docker1:~$
```

请注意，Apache 不再绑定到所有接口，我们有两个 Apache 进程，一个绑定到 Docker 主机的每个接口。来自另一个 Docker 主机的测试将证明每个容器在其各自的接口上提供 Apache：

```
user@docker2:~$ curl **http://10.10.10.101
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #6 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker2:~$
user@docker2:~$ curl **http://192.168.10.101
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #7 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker2:~$
```

虽然主机模式有一些限制，但它也更简单，可能因为缺乏 NAT 和使用`docker0`桥而提供更高的性能。

### 注意

请记住，由于 Docker 不涉及主机模式，如果您有一个基于主机的防火墙来执行策略，您可能需要手动打开防火墙端口，以便容器可以被访问。

# 配置服务级设置

虽然许多设置可以在容器运行时配置，但有一些设置必须作为启动 Docker 服务的一部分进行配置。也就是说，它们需要在服务配置中定义为 Docker 选项。在之前的示例中，我们接触到了一些这些服务级选项，比如`--ip-forward`、`--userland-proxy`和`--ip`。在这个示例中，我们将介绍如何将服务级参数传递给 Docker 服务，以及讨论一些关键参数的功能。

## 准备工作

您需要访问 Docker 主机，并了解您的 Docker 主机如何连接到网络。在本教程中，我们将使用之前教程中使用的`docker1`和`docker2`主机。您需要确保可以访问`iptables`规则以验证 netfilter 策略。如果您希望下载和运行示例容器，您的 Docker 主机还需要访问互联网。

## 操作步骤…

为了传递运行时选项或参数给 Docker，我们需要修改服务配置。在我们的情况下，我们使用的是 Ubuntu 16.04 版本，它使用`systemd`来管理在 Linux 主机上运行的服务。向 Docker 传递参数的推荐方法是使用`systemd`的附加文件。要创建附加文件，我们可以按照以下步骤创建一个服务目录和一个 Docker 配置文件：

```
sudo mkdir /etc/systemd/system/docker.service.d
sudo vi /etc/systemd/system/docker.service.d/docker.conf
```

将以下行插入`docker.conf`配置文件中：

```
[Service] 
ExecStart= 
ExecStart=/usr/bin/dockerd
```

如果您希望向 Docker 服务传递任何参数，可以通过将它们附加到第三行来实现。例如，如果我想在服务启动时禁用 Docker 自动启用主机上的 IP 转发，我的文件将如下所示：

```
[Service] 
ExecStart= 
ExecStart=/usr/bin/dockerd --ip-forward=false
```

在对系统相关文件进行更改后，您需要要求`systemd`重新加载配置。使用以下命令完成：

```
sudo systemctl daemon-reload
```

最后，您可以重新启动服务以使设置生效：

```
systemctl restart docker
```

每次更改配置后，您需要重新加载`systemd`配置以及重新启动服务。

### docker0 桥接地址

正如我们之前所看到的，`docker0`桥的 IP 地址默认为`172.17.0.1/16`。但是，如果您希望，可以使用`--bip`配置标志更改此 IP 地址。例如，您可能希望将`docker0`桥的子网更改为`192.168.127.1/24`。这可以通过将以下选项传递给 Docker 服务来完成：

```
ExecStart=/usr/bin/dockerd **--bip=192.168.127.1/24

```

更改此设置时，请确保配置 IP 地址（`192.168.127.1/24`）而不是您希望定义的子网（`192.168.127.0/24`）。以前的 Docker 版本需要重新启动主机或手动删除现有的桥接才能分配新的桥接 IP。在较新的版本中，您只需重新加载`systemd`配置并重新启动服务，新的桥接 IP 就会被分配：

```
user@docker1:~$ **sudo systemctl daemon-reload
user@docker1:~$ **sudo systemctl restart docker
user@docker1:~$
user@docker1:~$ **ip addr show docker0
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:a6:d1:b3:37 brd ff:ff:ff:ff:ff:ff
    inet **192.168.127.1/24** scope global docker0
       valid_lft forever preferred_lft forever
user@docker1:~$
```

除了更改`docker0`桥的 IP 地址，您还可以定义 Docker 可以分配给容器的 IP 地址。这是通过使用`--fixed-cidr`配置标志来完成的。例如，假设以下配置：

```
ExecStart=/usr/bin/dockerd --bip=192.168.127.1/24
--fixed-cidr=192.168.127.128/25

```

在这种情况下，`docker0`桥接口本身位于`192.168.127.0/24`子网中，但我们告诉 Docker 只从子网`192.168.127.128/25`中分配容器 IP 地址。如果我们添加这个配置，再次重新加载`systemd`并重新启动服务，我们可以看到 Docker 将为第一个容器分配 IP 地址`192.168.127.128`：

```
user@docker1:~$ docker run --name web1 -it \
jonlangemak/web_server_1 /bin/bash
root@ff8872212cb4:/# **ip addr show eth0
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:c0:a8:7f:80 brd ff:ff:ff:ff:ff:ff
    inet 192.168.127.128/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c0ff:fea8:7f80/64 scope link
       valid_lft forever preferred_lft forever
root@ff8872212cb4:/#
```

由于容器使用定义的`docker0`桥接 IP 地址作为它们的默认网关，固定的 CIDR 范围必须是`docker0`桥本身上定义的子网的较小子网。

### 发布端口的 Docker 接口绑定

在某些情况下，您可能有一个 Docker 主机，它有多个位于不同网络段的网络接口。例如，考虑这样一个例子，您有两个主机，它们都有两个网络接口：

![Docker 接口绑定用于发布端口](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_02_12.jpg)

考虑这样一种情况，我们在主机`docker1`上启动一个提供 Web 服务的容器，使用以下语法：

```
docker run -d --name web1 -P jonlangemak/web_server_1
```

如您所见，我们传递了`-P`标志，告诉 Docker 将图像中存在的任何暴露端口发布到 Docker 主机上的随机端口。如果我们检查端口映射，我们注意到虽然有动态端口分配，但没有主机 IP 地址分配：

```
user@docker1:~$ docker run -d --name web1 -P jonlangemak/web_server_1
d96b4dd005edb2218257a7701b674f51f4318b92baf4be686400d77912c75e58
user@docker1:~$ docker port web1
80/tcp -> **0.0.0.0:32768
user@docker1:~$
```

Docker 不是指定特定的 IP 地址，而是用`0.0.0.0`指定所有接口。这意味着容器中的服务可以在 Docker 主机的任何 IP 接口上的端口`32768`上访问。我们可以通过从`docker2`主机进行测试来证明这一点：

```
user@docker2:~$ curl http://**10.10.10.101:32768
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker2:~$ curl http://**192.168.10.101:32768
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker2:~$
```

如果我们希望限制 Docker 默认发布端口的接口，我们可以将`--ip`选项传递给 Docker 服务。继续上面的例子，我的选项现在可能是这样的：

```
ExecStart=/usr/bin/dockerd --bip=192.168.127.1/24
--fixed-cidr=192.168.127.128/25 **--ip=192.168.10.101

```

将这些选项传递给 Docker 服务，并重新运行我们的容器，将导致端口只映射到定义的 IP 地址：

```
user@docker1:~$ docker port web1
80/tcp -> **192.168.10.101:32768
user@docker1:~$
```

如果我们从`docker2`主机再次运行我们的测试，我们应该看到服务只暴露在`192.168.10.101`接口上，而不是`10.10.10.101`接口上：

```
user@docker2:~$ curl http://**10.10.10.101:32768
curl: (7) Failed to connect to 10.10.10.101 port 32768: **Connection refused
user@docker2:~$
user@docker2:~$ curl http://**192.168.10.101:32768
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker2:~$
```

请记住，此设置仅适用于已发布的端口。 这不会影响容器可能用于出站连接的接口。 这由主机的路由表决定。

### 容器接口 MTU

在某些情况下，可能需要更改容器的网络接口的 MTU。 这可以通过向 Docker 服务传递`--mtu`选项来完成。 例如，我们可能希望将容器的接口 MTU 降低到`1450`以适应某种封装。 要做到这一点，您可以传递以下标志：

```
ExecStart=/usr/bin/dockerd  **--mtu=1450

```

添加此选项后，您可能会检查`docker0`桥 MTU 并发现它保持不变，如下面的代码所示：

```
user@docker1:~$ **ip addr show docker0
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> **mtu 1500** qdisc noqueue state DOWN group default
    link/ether 02:42:a6:d1:b3:37 brd ff:ff:ff:ff:ff:ff
    inet 192.168.127.1/24 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:a6ff:fed1:b337/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$ 
```

这实际上是预期行为。 Linux 桥默认情况下会自动使用与其关联的任何从属接口中的最低 MTU。 当我们告诉 Docker 使用 MTU 为`1450`时，我们实际上是在告诉它以 MTU 为`1450`启动任何容器。 由于此时没有运行任何容器，桥的 MTU 保持不变。 让我们启动一个容器来验证这一点：

```
user@docker1:~$ docker run --name web1 -d jonlangemak/web_server_1
18f4c038eadba924a23bd0d2841ac52d90b5df6dd2d07e0433eb5315124ce427
user@docker1:~$
user@docker1:~$ **docker exec web1 ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
10: **eth0**@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> **mtu 1450** qdisc noqueue state UP
    link/ether 02:42:c0:a8:7f:02 brd ff:ff:ff:ff:ff:ff
    inet 192.168.127.2/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c0ff:fea8:7f02/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

我们可以看到容器的 MTU 正确为`1450`。 检查 Docker 主机，我们应该看到桥的 MTU 现在也较低：

```
user@docker1:~$ **ip addr show docker0
5: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> **mtu 1450** qdisc noqueue state UP group default
    link/ether 02:42:a6:d1:b3:37 brd ff:ff:ff:ff:ff:ff
    inet 192.168.127.1/24 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:a6ff:fed1:b337/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

以较低的 MTU 启动容器自动影响了桥的 MTU，正如我们所预期的那样。

### 容器默认网关

默认情况下，Docker 将任何容器的默认网关设置为`docker0`桥的 IP 地址。 这是有道理的，因为容器需要通过`docker0`桥进行路由才能到达外部网络。 但是，可以覆盖此设置，并让 Docker 将默认网关设置为`docker0`桥网络上的另一个 IP 地址。

例如，我们可以通过传递这些配置选项给 Docker 服务来将默认网关更改为`192.168.127.50`。

```
ExecStart=/usr/bin/dockerd --bip=192.168.127.1/24 --fixed-cidr=192.168.127.128/25 **--default-gateway=192.168.127.50

```

如果我们添加这些设置，重新启动服务并生成一个容器，我们可以看到新容器的默认网关已配置为`192.168.127.50`：

```
user@docker1:~$ docker run --name web1 -it \
jonlangemak/web_server_1 /bin/bash
root@b36baa4d0950:/# ip addr show eth0
12: eth0@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:c0:a8:7f:80 brd ff:ff:ff:ff:ff:ff
    inet 192.168.127.128/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c0ff:fea8:7f80/64 scope link
       valid_lft forever preferred_lft forever
root@b36baa4d0950:/#
root@b36baa4d0950:/# **ip route show
default via 192.168.127.50 dev eth0
192.168.127.0/24 dev eth0  proto kernel  scope link  src 192.168.127.128
root@b36baa4d0950:/# 
```

请记住，此时此容器在其当前子网之外没有连接性，因为该网关目前不存在。 为了使容器在其本地子网之外具有连接性，需要从容器中访问`192.168.127.50`并具有连接到外部网络的能力。

### 注意

服务级别还有其他配置选项，例如`--iptables`和`--icc`。 这些将在后面的章节中讨论它们的相关用例。
