# Docker 网络秘籍（二）

> 原文：[`zh.annas-archive.org/md5/15C8E8C8C0D58C74AF1054F5CB887C66`](https://zh.annas-archive.org/md5/15C8E8C8C0D58C74AF1054F5CB887C66)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：用户定义的网络

在这一章中，我们将涵盖以下配方：

+   查看 Docker 网络配置

+   创建用户定义的网络

+   将容器连接到网络

+   定义用户定义的桥接网络

+   创建用户定义的覆盖网络

+   隔离网络

# 介绍

早期版本的 Docker 依赖于一个基本静态的网络模型，这对大多数容器网络需求来说工作得相当好。然而，如果您想做一些不同的事情，您就没有太多选择了。例如，您可以告诉 Docker 将容器部署到不同的桥接，但 Docker 和该网络之间没有一个强大的集成点。随着 Docker 1.9 中用户定义的网络的引入，游戏已经改变了。您现在可以直接通过 Docker 引擎创建和管理桥接和多主机网络。此外，第三方网络插件也可以通过 libnetwork 及其**容器网络模型**（**CNM**）模型与 Docker 集成。

### 注意

CNM 是 Docker 用于定义容器网络模型的模型。在第七章中，*使用 Weave Net*，我们将研究一个第三方插件（Weave），它可以作为 Docker 驱动程序集成。本章的重点将放在 Docker 引擎中默认包含的网络驱动程序上。

转向基于驱动程序的模型象征着 Docker 网络的巨大变化。除了定义新网络，您现在还可以动态连接和断开容器接口。这种固有的灵活性为连接容器打开了许多新的可能性。

# 查看 Docker 网络配置

如前所述，现在可以通过添加`network`子命令直接通过 Docker 定义和管理网络。`network`命令为您提供了构建网络并将容器连接到网络所需的所有选项：

```
user@docker1:~$ docker network --help

docker network --help

Usage:  docker network COMMAND

Manage Docker networks

Options:
      --help   Print usage

Commands:
  connect     Connect a container to a network
  create      Create a network
  disconnect  Disconnect a container from a network
  inspect     Display detailed information on one or more networks
  ls          List networks
  rm          Remove one or more networks

Run 'docker network COMMAND --help' for more information on a command.
user@docker1:~$
```

在这个配方中，我们将学习如何查看定义的 Docker 网络以及检查它们的具体细节。

## 做好准备

`docker network`子命令是在 Docker 1.9 中引入的，因此您需要运行至少该版本的 Docker 主机。在我们的示例中，我们将使用 Docker 版本 1.12。您还需要对当前网络布局有很好的了解，这样您就可以跟着我们检查当前的配置。假设每个 Docker 主机都处于其本机配置中。

## 如何做…

我们要做的第一件事是弄清楚 Docker 认为已经定义了哪些网络。这可以使用`network ls`子命令来完成：

```
user@docker1:~$ docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
200d5292d5db        **bridge**              **bridge**              **local
12e399864b79        **host**                **host**                **local
cb6922b8b84f        **none**                **null**                **local
user@docker1:~$
```

正如我们所看到的，Docker 显示我们已经定义了三种不同的网络。要查看有关网络的更多信息，我们可以使用`network inspect`子命令检索有关网络定义及其当前状态的详细信息。让我们仔细查看每个定义的网络。

### Bridge

桥接网络代表 Docker 引擎默认创建的`docker0`桥：

```
user@docker1:~$ docker network inspect bridge
[
    {
        "Name": "bridge",
        "Id": "62fcda0787f2be01e65992e2a5a636f095970ea83c59fdf0980da3f3f555c24e",
        "Scope": "local",
 "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": [
                {
 "Subnet": "172.17.0.0/16"
                }
            ]
        },
        "Internal": false,
        "Containers": {},
        "Options": {
 "com.docker.network.bridge.default_bridge": "true",
 "com.docker.network.bridge.enable_icc": "true",
 "com.docker.network.bridge.enable_ip_masquerade": "true",
 "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
 "com.docker.network.bridge.name": "docker0",
 "com.docker.network.driver.mtu": "1500"
        },
        "Labels": {}
    }
]
user@docker1:~$  
```

`inspect`命令的输出向我们展示了关于定义网络的大量信息：

+   `Driver`：在这种情况下，我们可以看到网络桥实现了`Driver`桥。尽管这似乎是显而易见的，但重要的是要指出，所有网络功能，包括本机功能，都是通过驱动程序实现的。

+   `子网`：在这种情况下，`子网`是我们从`docker0`桥预期的默认值，`172.17.0.1/16`。

+   `bridge.default_bridge`：值为`true`意味着 Docker 将为所有容器提供此桥，除非另有规定。也就是说，如果您启动一个没有指定网络（`--net`）的容器，该容器将最终出现在此桥上。

+   `bridge.host_binding_ipv4`：默认情况下，这将设置为`0.0.0.0`或所有接口。正如我们在第二章中所看到的，*配置和监控 Docker 网络*，我们可以通过将`--ip`标志作为 Docker 选项传递给服务，告诉 Docker 在服务级别限制这一点。

+   `bridge.name`：正如我们所怀疑的，这个网络代表`docker0`桥。

+   `driver.mtu`：默认情况下，这将设置为`1500`。正如我们在第二章中所看到的，*配置和监控 Docker 网络*，我们可以通过将`--mtu`标志作为 Docker 选项传递给服务，告诉 Docker 在服务级别更改**MTU**（最大传输单元）。

### 无

`none`网络表示的就是它所说的，什么也没有。当您希望定义一个绝对没有网络定义的容器时，可以使用`none`模式。检查网络后，我们可以看到就网络定义而言，没有太多内容：

```
user@docker1:~$ docker network inspect none
[
    {
        "Name": "none",
        "Id": "a191c26b7dad643ca77fe6548c2480b1644a86dcc95cde0c09c6033d4eaff7f2",
        "Scope": "local",
        "Driver": "null",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": []
        },
        "Internal": false,
        "Containers": {},
        "Options": {},
        "Labels": {}
    }
]
user@docker1:~$
```

如您所见，`Driver`由`null`表示，这意味着这根本不是这个网络的`Driver`。`none`网络模式有一些用例，我们将在稍后讨论连接和断开连接到定义网络的容器时进行介绍。

### 主机

*host*网络代表我们在第二章中看到的主机模式，*配置和监视 Docker 网络*，在那里容器直接绑定到 Docker 主机自己的网络接口。通过仔细观察，我们可以看到，与`none`网络一样，对于这个网络并没有太多定义。

```
user@docker1:~$ docker network inspect host
[
    {
        "Name": "host",
        "Id": "4b94353d158cef25b9c9244ca9b03b148406a608b4fd85f3421c93af3be6fe4b",
        "Scope": "local",
        "Driver": "host",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": []
        },
        "Internal": false,
        "Containers": {},
        "Options": {},
        "Labels": {}
    }
]
user@docker1:~$
```

尽管主机网络肯定比`none`模式做得更多，但从检查其定义来看，似乎并非如此。这里的关键区别在于这个网络使用主机`Driver`。由于这种网络类型使用现有主机的网络接口，我们不需要将其作为网络的一部分进行定义。

使用`network ls`命令时，可以传递附加参数以进一步过滤或更改输出：

+   `--quiet`（`-q`）：仅显示数字网络 ID

+   `--no-trunc`：这可以防止命令自动截断输出中的网络 ID，从而使您可以看到完整的网络 ID

+   `--filter`（`-f`）：根据网络 ID、网络名称或网络定义（内置或用户定义）对输出进行过滤

例如，我们可以使用以下过滤器显示所有用户定义的网络：

```
user@docker1:~$ docker network ls -f type=custom
NETWORK ID          NAME                DRIVER              SCOPE
a09b7617c550        mynetwork           bridge              local
user@docker1:~$
```

或者我们可以显示所有包含`158`的网络 ID 的网络：

```
user@docker1:~$ docker network ls -f id=158
NETWORK ID          NAME                DRIVER              SCOPE
4b94353d158c        host                host                local
user@docker1:~$
```

# 创建用户定义的网络

到目前为止，我们已经看到，每个 Docker 安装都有至少两种不同的网络驱动程序，即桥接和主机。除了这两种之外，由于先决条件而没有最初定义，还有另一个`Driver`叠加，也可以立即使用。本章的后续内容将涵盖有关桥接和叠加驱动程序的具体信息。

因为使用主机`Driver`创建另一个主机网络的迭代没有意义，所以内置的用户定义网络仅限于桥接和叠加驱动程序。在本教程中，我们将向您展示创建用户定义网络的基础知识，以及与`network create`和`network rm` Docker 子命令相关的选项。

## 准备工作

`docker network`子命令是在 Docker 1.9 中引入的，因此您需要运行至少该版本的 Docker 主机。在我们的示例中，我们将使用 Docker 版本 1.12。您还需要对当前网络布局有很好的了解，以便在我们检查当前配置时能够跟随。假定每个 Docker 主机都处于其本机配置中。

### 注意

警告：在 Linux 主机上创建网络接口必须谨慎进行。Docker 将尽力防止您自找麻烦，但在定义 Docker 主机上的新网络之前，您必须对网络拓扑有一个很好的了解。要避免的一个常见错误是定义与网络中其他子网重叠的新网络。在远程管理的情况下，这可能会导致主机和容器之间的连接问题。

## 如何做到这一点…

网络是通过使用`network create`子命令来定义的，该命令具有以下选项：

```
user@docker1:~$ docker network create --help

Usage:  docker network create [OPTIONS] NETWORK

Create a network

Options:
--aux-address value**    Auxiliary IPv4 or IPv6 addresses used by Network driver (default map[])
-d, --driver string**    Driver to manage the Network (default "bridge")
--gateway value**        IPv4 or IPv6 Gateway for the master subnet (default [])
--help                 Print usage
--internal**             Restrict external access to the network
--ip-range value**       Allocate container ip from a sub-range (default [])
--ipam-driver string**   IP Address Management Driver (default "default")
--ipam-opt value**       Set IPAM driver specific options (default map[])
--ipv6**                 Enable IPv6 networking
--label value**          Set metadata on a network (default [])
-o, --opt value**        Set driver specific options (default map[])
--subnet value**         Subnet in CIDR format that represents a network segment (default [])
user@docker1:~$
```

让我们花点时间讨论每个选项的含义：

+   `aux-address`：这允许您定义 Docker 在生成容器时不应分配的 IP 地址。这相当于 DHCP 范围中的 IP 保留。

+   `Driver`：网络实现的`Driver`。内置选项包括 bridge 和 overlay，但您也可以使用第三方驱动程序。

+   `gateway`：网络的网关。如果未指定，Docker 将假定它是子网中的第一个可用 IP 地址。

+   `internal`：此选项允许您隔离网络，并将在本章后面更详细地介绍。

+   `ip-range`：这允许您指定用于容器寻址的已定义网络子网的较小子网。

+   `ipam-driver`：除了使用第三方网络驱动程序外，您还可以利用第三方 IPAM 驱动程序。对于本书的目的，我们将主要关注默认或内置的 IPAM`Driver`。

+   `ipv6`：这在网络上启用 IPv6 网络。

+   `label`：这允许您指定有关网络的其他信息，这些信息将被存储为元数据。

+   `ipam-opt`：这允许您指定要传递给 IPAM`Driver`的选项。

+   `opt`：这允许您指定可以传递给网络`Driver`的选项。将在相关的配方中讨论每个内置`Driver`的特定选项。

+   `subnet`：这定义了与您正在创建的网络类型相关联的子网。

您可能会注意到这里一些重叠，即 Docker 网络的服务级别可以定义的一些设置与前面列出的用户定义选项之间。检查这些选项时，您可能会想要比较以下配置标志：

![操作步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_03_01.jpg)

尽管这些设置在很大程度上是等效的，但它们并不完全相同。唯一完全相同的是`--fixed-cidr`和`ip-range`。这两个选项都定义了一个较大主网络的较小子网络，用于容器 IP 寻址。另外两个选项是相似的，但并不相同。

在服务选项的情况下，`--bip`适用于`docker0`桥接口，`--default-gateway`适用于容器本身。在用户定义方面，`--subnet`和`--gateway`选项直接适用于正在定义的网络构造（在此比较中是一个桥接）。请记住，`--bip`选项期望接收一个网络中的 IP 地址，而不是网络本身。以这种方式定义桥接 IP 地址既覆盖了子网，也覆盖了网关，这在定义用户定义网络时是分开定义的。也就是说，服务定义在这方面更加灵活，因为它允许您定义桥接的接口以及分配给容器的网关。

保持合理的默认设置主题，实际上并不需要这些选项来创建用户定义网络。您可以通过只给它一个名称来创建您的第一个用户定义网络：

```
user@docker1:~$ docker network create mynetwork
3fea20c313e8880538ab50fd591398bdfdac2378abac29aacb1be131cbfab40f
user@docker1:~$
```

经过检查，我们可以看到 Docker 使用的默认设置：

```
user@docker1:~$ docker network inspect mynetwork
[
    {
        "Name": "mynetwork",
        "Id": "a09b7617c5504d4afd80c26b82587000c64046f1483de604c51fa4ba53463b50",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "172.18.0.0/16",
                    "Gateway": "172.18.0.1/16"
                }
            ]
        },
        "Internal": false,
        "Containers": {},
        "Options": {},
        "Labels": {}
    }
]
user@docker1:~$
```

Docker 假设如果您没有指定`Driver`，那么您想要使用桥接`Driver`创建网络。如果您在创建网络时没有定义子网，它还会自动选择并分配一个子网给这个桥接。

### 注意

在创建网络时，建议您为网络指定子网。正如我们将在后面看到的，不是所有的网络拓扑都依赖于将容器网络隐藏在主机接口后面。在这些情况下，定义一个可路由的不重叠子网将是必要的。

它还会自动选择子网的第一个可用 IP 地址作为网关。因为我们没有为`Driver`定义任何选项，所以网络没有，但在这种情况下会使用默认值。这些将在与每个特定`Driver`相关的配方中讨论。

空的网络，即没有活动端点的网络，可以使用 `network rm` 命令删除：

```
user@docker1:~$ docker network rm mynetwork
user@docker1:~$
```

这里值得注意的另一项是，Docker 使用户定义的网络持久化。在大多数情况下，手动定义的任何 Linux 网络结构在系统重新启动时都会丢失。Docker 记录网络配置并在 Docker 服务重新启动时负责回放。这对于通过 Docker 而不是自己构建网络来说是一个巨大的优势。

# 连接容器到网络

虽然拥有创建自己网络的能力是一个巨大的进步，但如果没有一种方法将容器连接到网络，这就毫无意义。在以前的 Docker 版本中，这通常是在容器运行时通过传递 `--net` 标志来完成的，指定容器应该使用哪个网络。虽然这仍然是这种情况，但 `docker network` 子命令也允许您将正在运行的容器连接到现有网络或从现有网络断开连接。

## 准备工作

`docker network` 子命令是在 Docker 1.9 中引入的，因此您需要运行至少该版本的 Docker 主机。在我们的示例中，我们将使用 Docker 版本 1.12。您还需要对当前网络布局有很好的了解，这样您就可以在我们检查当前配置时跟上。假设每个 Docker 主机都处于其本机配置中。

## 如何做…

通过 `network connect` 和 `network disconnect` 子命令来连接和断开连接容器：

```
user@docker1:~$ docker network connect --help
Usage:  docker network connect [OPTIONS] NETWORK CONTAINER
Connects a container to a network
  --alias=[]         Add network-scoped alias for the container
  --help             Print usage
  --ip               IP Address
  --ip6              IPv6 Address
  --link=[]          Add link to another container
user@docker1:~$
```

让我们回顾一下连接容器到网络的选项：

+   **别名**：这允许您在连接容器的网络中为容器名称解析定义别名。我们将在第五章中更多地讨论这一点，*容器链接和 Docker DNS*，在那里我们将讨论 DNS 和链接。

+   **IP**：这定义了要用于容器的 IP 地址。只要 IP 地址当前未被使用，它就可以工作。一旦分配，只要容器正在运行或暂停，它就会保留。停止容器将删除保留。

+   **IP6**：这定义了要用于容器的 IPv6 地址。适用于 IPv4 地址的相同分配和保留要求也适用于 IPv6 地址。

+   **Link**：这允许您指定与另一个容器的链接。我们将在第五章中更多地讨论这个问题，*容器链接和 Docker DNS*，在那里我们将讨论 DNS 和链接。

一旦发送了`network connect`请求，Docker 会处理所有所需的配置，以便容器开始使用新的接口。让我们来看一个快速的例子：

```
user@docker1:~$ **docker run --name web1 -d jonlangemak/web_server_1
e112a2ab8197ec70c5ee49161613f2244f4353359b27643f28a18be47698bf59
user@docker1:~$
user@docker1:~$ **docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
8: **eth0**@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.17.0.2/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

在上面的输出中，我们启动了一个简单的容器，没有指定任何与网络相关的配置。结果是容器被映射到了`docker0`桥接。现在让我们尝试将这个容器连接到我们在上一个示例中创建的网络`mynetwork`：

```
user@docker1:~$ **docker network connect mynetwork web1
user@docker1:~$
user@docker1:~$ docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
8: **eth0**@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.17.0.2/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
10: **eth1**@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.18.0.2/16** scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe12:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

如您所见，容器现在在`mynetwork`网络上有一个 IP 接口。如果我们现在再次检查网络，我们应该看到一个容器关联：

```
user@docker1:~$ docker network inspect mynetwork
[
    {
        "Name": "mynetwork",
        "Id": "a09b7617c5504d4afd80c26b82587000c64046f1483de604c51fa4ba53463b50",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "172.18.0.0/16",
                    "Gateway": "172.18.0.1/16"
                }
            ]
        },
        "Internal": false,
        "Containers": {           **"e112a2ab8197ec70c5ee49161613f2244f4353359b27643f28a18be47698bf59": {
 "Name": "web1",
 "EndpointID": "678b07162dc958599bf7d463da81a4c031229028ebcecb1af37ee7d448b54e3d",
 "MacAddress": "02:42:ac:12:00:02",
 "IPv4Address": "172.18.0.2/16",
 "IPv6Address": ""
            }
        },
        "Options": {},
        "Labels": {}
    }
]
user@docker1:~$
```

网络也可以很容易地断开连接。例如，我们现在可以通过将容器从桥接网络中移除来从`docker0`桥接中移除容器：

```
user@docker1:~$ **docker network disconnect bridge web1
user@docker1:~$
user@docker1:~$ docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
10: **eth1**@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.18.0.2/16** scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe12:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

有趣的是，Docker 还负责确保在连接和断开容器与网络时容器的连通性。例如，在将容器从桥接网络断开连接之前，容器的默认网关仍然在`docker0`桥接之外：

```
user@docker1:~$ docker exec web1 ip route
default via 172.17.0.1 dev eth0
172.17.0.0/16 dev eth2  proto kernel  scope link  src 172.17.0.2
172.18.0.0/16 dev eth1  proto kernel  scope link  src 172.18.0.2
user@docker1:~$
```

这是有道理的，因为我们不希望在将容器连接到新网络时中断容器的连接。然而，一旦我们通过断开与桥接网络的接口来移除托管默认网关的网络，我们会发现 Docker 会将默认网关更新为`mynetwork`桥接的剩余接口：

```
user@docker1:~$ docker exec web1 ip route
default via 172.18.0.1 dev eth1
172.18.0.0/16 dev eth1  proto kernel  scope link  src 172.18.0.2
user@docker1:~$
```

这确保了无论连接到哪个网络，容器都具有连通性。

最后，我想指出连接和断开容器与网络时`none`网络类型的一个有趣方面。正如我之前提到的，`none`网络类型告诉 Docker 不要将容器分配给任何网络。然而，这并不仅仅意味着最初，它是一个配置状态，告诉 Docker 容器不应该与任何网络关联。例如，假设我们使用`none`网络启动以下容器：

```
user@docker1:~$ docker run --net=none --name web1 -d jonlangemak/web_server_1
9f5d73c55ee859335cd2449b058b68354f5b71cf37e57b72f5c984afcafb4b21
user@docker1:~$ docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
user@docker1:~$
```

如您所见，除了回环接口之外，容器没有任何网络接口。现在，让我们尝试将这个容器连接到一个新的网络：

```
user@docker1:~$ docker network connect mynetwork web1
Error response from daemon: Container cannot be connected to multiple networks with one of the networks in private (none) mode
user@docker1:~$
```

Docker 告诉我们，这个容器被定义为没有网络，并且阻止我们将容器连接到任何网络。如果我们检查`none`网络，我们可以看到这个容器实际上附加到它上面：

```
user@docker1:~$ docker network inspect none
[
    {
        "Name": "none",
        "Id": "a191c26b7dad643ca77fe6548c2480b1644a86dcc95cde0c09c6033d4eaff7f2",
        "Scope": "local",
        "Driver": "null",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": []
        },
        "Internal": false,
        "Containers": {            **"931a0d7ad9244c135a19de6e23de314698112ccd00bc3856f4fab9b8cb241e60": {
 "Name": "web1",
 "EndpointID": "6a046449576e0e0a1e8fd828daa7028bacba8de335954bff2c6b21e01c78baf8",
 "MacAddress": "",
 "IPv4Address": "",
 "IPv6Address": ""
            }
        },
        "Options": {},
        "Labels": {}
    }
]
user@docker1:~$
```

为了将这个容器连接到一个新的网络，我们首先必须将其与`none`网络断开连接：

```
user@docker1:~$ **docker network disconnect none web1
user@docker1:~$ **docker network connect mynetwork web1
user@docker1:~$ docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
18: **eth0**@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.18.0.2/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe12:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

一旦您将其与`none`网络断开连接，您就可以自由地将其连接到任何其他定义的网络。

# 定义用户定义的桥接网络

通过使用桥接`Driver`，用户可以提供自定义桥接以连接到容器。您可以创建尽可能多的桥接，唯一的限制是您必须在每个桥接上使用唯一的 IP 地址。也就是说，您不能与已在其他网络接口上定义的现有子网重叠。

在这个教程中，我们将学习如何定义用户定义的桥接，以及在创建过程中可用的一些独特选项。

## 准备工作

`docker network`子命令是在 Docker 1.9 中引入的，因此您需要运行至少该版本的 Docker 主机。在我们的示例中，我们将使用 Docker 版本 1.12。您还需要对当前网络布局有很好的了解，这样您就可以跟着我们检查当前的配置。假设每个 Docker 主机都处于其本机配置中。

## 如何做…

在上一个教程中，我们讨论了定义用户定义网络的过程。虽然那里讨论的选项适用于所有网络类型，但我们可以通过传递`--opt`标志将其他选项传递给我们的网络实现的`Driver`。让我们快速回顾一下与桥接`Driver`可用的选项：

+   `com.docker.network.bridge.name`：这是您希望给桥接的名称。

+   `com.docker.network.bridge.enable_ip_masquerade`：这指示 Docker 主机在容器尝试路由离开本地主机时，隐藏或伪装该网络中所有容器在 Docker 主机接口后面。

+   `com.docker.network.bridge.enable_icc`：这为桥接打开或关闭**容器间连接**（**ICC**）模式。这个功能在第六章 *保护容器网络*中有更详细的介绍。

+   `com.docker.network.bridge.host_binding_ipv4`：这定义了应该用于端口绑定的主机接口。

+   `com.docker.network.driver.mtu`：这为连接到这个桥接的容器设置 MTU。

这些选项可以直接与我们在 Docker 服务下定义的选项进行比较，以更改默认的`docker0`桥。

如何做到这一点...

上表比较了影响`docker0`桥的服务级设置与您在定义用户定义的桥接网络时可用的设置。它还列出了在任一情况下如果未指定设置，则使用的默认设置。

在定义容器网络时，通过驱动程序特定选项和`network create`子命令的通用选项，我们在定义容器网络时具有相当大的灵活性。让我们通过一些快速示例来构建用户定义的桥接。

### 示例 1

```
docker network create --driver bridge \
--subnet=10.15.20.0/24 \
--gateway=10.15.20.1 \
--aux-address 1=10.15.20.2 --aux-address 2=10.15.20.3 \
--opt com.docker.network.bridge.host_binding_ipv4=10.10.10.101 \
--opt com.docker.network.bridge.name=linuxbridge1 \
testbridge1
```

前面的`network create`语句定义了具有以下特征的网络：

+   一个类型为`bridge`的用户定义网络

+   一个`子网`为`10.15.20.0/24`

+   一个`网关`或桥接 IP 接口为`10.15.20.1`

+   两个保留地址：`10.15.20.2`和`10.15.20.3`

+   主机上的端口绑定接口为`10.10.10.101`

+   一个名为`linuxbridge1`的 Linux 接口名称

+   一个名为`testbridge1`的 Docker 网络

请记住，其中一些选项仅用于示例目的。实际上，在前面的示例中，我们不需要为网络驱动程序定义“网关”，因为默认设置将覆盖我们。

如果我们在检查后创建了前面提到的网络，我们应该看到我们定义的属性：

```
user@docker1:~$ docker network inspect testbridge1
[
    {
 "Name": "testbridge1",
        "Id": "97e38457e68b9311113bc327e042445d49ff26f85ac7854106172c8884d08a9f",
        "Scope": "local",
 "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
 "Subnet": "10.15.20.0/24",
 "Gateway": "10.15.20.1",
                    "AuxiliaryAddresses": {
 "1": "10.15.20.2",
 "2": "10.15.20.3"
                    }
                }
            ]
        },
        "Internal": false,
        "Containers": {},
        "Options": {
 "com.docker.network.bridge.host_binding_ipv4": "10.10.10.101",
 "com.docker.network.bridge.name": "linuxbridge1"
        },
        "Labels": {}
    }
]
user@docker1:~$
```

### 注意

您传递给网络的选项不会得到验证。也就是说，如果您将`host_binding`拼错为`host_bniding`，Docker 仍然会让您创建网络，并且该选项将被定义；但是，它不会起作用。

### 示例 2

```
docker network create \
--subnet=192.168.50.0/24 \
--ip-range=192.168.50.128/25 \
--opt com.docker.network.bridge.enable_ip_masquearde=false \
testbridge2
```

前面的`network create`语句定义了具有以下特征的网络：

+   一个类型为`bridge`的用户定义网络

+   一个`子网`为`192.168.50.0/24`

+   一个`网关`或桥接 IP 接口为`192.168.50.1`

+   一个容器网络范围为`192.168.50.128/25`

+   主机上的 IP 伪装关闭

+   一个名为`testbridge2`的 Docker 网络

如示例 1 所述，如果我们创建桥接网络，则无需定义驱动程序类型。此外，如果我们可以接受网关是容器定义子网中的第一个可用 IP，我们也可以将其从定义中排除。创建后检查此网络应该显示类似于这样的结果：

```
user@docker1:~$ docker network inspect testbridge2
[
    {
 "Name": "testbridge2",
        "Id": "2c8270425b14dab74300d8769f84813363a9ff15e6ed700fa55d7d2c3b3c1504",
        "Scope": "local",
 "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
 "Subnet": "192.168.50.0/24",
 "IPRange": "192.168.50.128/25"
                }
            ]
        },
        "Internal": false,
        "Containers": {},
        "Options": {
 "com.docker.network.bridge.enable_ip_masquearde": "false"
        },
        "Labels": {}
    }
]
user@docker1:~$
```

# 创建用户定义的覆盖网络

虽然创建自己的桥接能力确实很吸引人，但你的范围仍然局限于单个 Docker 主机。覆盖网络`Driver`旨在通过允许您使用覆盖网络在多个 Docker 主机上扩展一个或多个子网来解决这个问题。覆盖网络是在现有网络之上构建隔离网络的一种手段。在这种情况下，现有网络为覆盖提供传输，并且通常被称为**底层网络**。覆盖`Driver`实现了 Docker 所谓的多主机网络。

在这个示例中，我们将学习如何配置覆盖`Driver`的先决条件，以及部署和验证基于覆盖的网络。

## 准备就绪

在接下来的示例中，我们将使用这个实验室拓扑：

![准备就绪](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_03_03.jpg)

拓扑结构由总共四个 Docker 主机组成，其中两个位于`10.10.10.0/24`子网，另外两个位于`192.168.50.0/24`子网。当我们按照这个示例进行操作时，图中显示的主机将扮演以下角色：

+   `docker1`：作为 Consul**键值存储**提供服务的 Docker 主机

+   `docker2`：参与覆盖网络的 Docker 主机

+   `docker3`：参与覆盖网络的 Docker 主机

+   `docker4`：参与覆盖网络的 Docker 主机

如前所述，覆盖`Driver`不是默认实例化的。这是因为覆盖`Driver`需要满足一些先决条件才能工作。

### 一个键值存储

由于我们现在处理的是一个分布式系统，Docker 需要一个地方来存储关于覆盖网络的信息。为此，Docker 使用一个键值存储，并支持 Consul、etcd 和 ZooKeeper。它将存储需要在所有节点之间保持一致性的信息，如 IP 地址分配、网络 ID 和容器端点。在我们的示例中，我们将部署 Consul。

侥幸的是，Consul 本身可以作为一个 Docker 容器部署：

```
user@docker1:~$ docker run -d -p 8500:8500 -h consul \
--name consul progrium/consul -server -bootstrap
```

运行这个镜像将启动一个 Consul 键值存储的单个实例。一个单个实例就足够用于基本的实验测试。在我们的情况下，我们将在主机`docker1`上启动这个镜像。所有参与覆盖的 Docker 主机必须能够通过网络访问键值存储。

### 注意

只有在演示目的下才应该使用单个集群成员运行 Consul。您至少需要三个集群成员才能具有任何故障容忍性。确保您研究并了解您决定部署的键值存储的配置和故障容忍性。

### Linux 内核版本为 3.16

您的 Linux 内核版本需要是 3.16 或更高。您可以使用以下命令检查当前的内核版本：

```
user@docker1:~$ uname -r
4.2.0-34-generic
user@docker1:~$ 
```

### 打开端口

Docker 主机必须能够使用以下端口相互通信：

+   TCP 和 UDP `7946`（Serf）

+   UDP `4789`（VXLAN）

+   TCP `8500`（Consul 键值存储）

### Docker 服务配置选项

参与覆盖的所有主机都需要访问键值存储。为了告诉它们在哪里，我们定义了一些服务级选项：

```
ExecStart=/usr/bin/dockerd --cluster-store=consul://10.10.10.101:8500/network --cluster-advertise=eth0:0
```

cluster-store 变量定义了键值存储的位置。在我们的情况下，它是在主机`docker1`（`10.10.10.101`）上运行的容器。我们还需要启用`cluster-advertise`功能并传递一个接口和端口。这个配置更多地涉及使用 Swarm 集群，但该标志也作为启用多主机网络的一部分。也就是说，您需要传递一个有效的接口和端口。在这种情况下，我们使用主机物理接口和端口`0`。在我们的示例中，我们将这些选项添加到主机`docker2`，`docker3`和`docker4`上，因为这些是参与覆盖网络的主机。

添加选项后，重新加载`systemd`配置并重新启动 Docker 服务。您可以通过检查`docker info`命令的输出来验证 Docker 是否接受了该命令：

```
user@docker2:~$ docker info
…<Additional output removed for brevity>…
Cluster store: **consul://10.10.10.101:8500/network
Cluster advertise: **10.10.10.102:0
…<Additional output removed for brevity>…
```

## 如何做…

现在我们已经满足了使用覆盖`Driver`的先决条件，我们可以部署我们的第一个用户定义的覆盖网络。定义用户定义的覆盖网络遵循与定义用户定义的桥网络相同的过程。例如，让我们使用以下命令配置我们的第一个覆盖网络：

```
user@docker2:~$ docker network create -d overlay myoverlay
e4bdaa0d6f3afe1ae007a07fe6a1f49f1f963a5ddc8247e716b2bd218352b90e
user@docker2:~$
```

就像用户定义的桥一样，我们不必输入太多信息来创建我们的第一个覆盖网络。事实上，唯一的区别在于我们必须将`Driver`指定为覆盖类型，因为默认的`Driver`类型是桥接。一旦我们输入命令，我们应该能够在参与覆盖网络的任何节点上看到定义的网络。

```
user@docker3:~$ docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
55f86ddf18d5        bridge              bridge              local
8faef9d2a7cc        host                host                local
3ad850433ed9        myoverlay           overlay             global
453ad78e11fe        none                null                local
user@docker3:~$

user@docker4:~$ docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
3afd680b6ce1        bridge              bridge              local
a92fe912af1d        host                host                local
3ad850433ed9        myoverlay           overlay             global
7dbc77e5f782        none                null                local
user@docker4:~$
```

当主机`docker2`创建网络时，它将网络配置推送到存储中。现在所有主机都可以看到新的网络，因为它们都在读写来自同一个键值存储的数据。一旦网络创建完成，任何参与覆盖的节点（配置了正确的服务级选项）都可以查看、连接容器到并删除覆盖网络。

例如，如果我们去到主机`docker4`，我们可以删除最初在主机`docker2`上创建的网络：

```
user@docker4:~$ **docker network rm myoverlay
myoverlay
user@docker4:~$ docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
3afd680b6ce1        bridge              bridge              local
a92fe912af1d        host                host                local
7dbc77e5f782        none                null                local
user@docker4:~$
```

现在让我们用更多的配置来定义一个新的覆盖。与用户定义的桥接不同，覆盖`Driver`目前不支持在创建时使用`--opt`标志传递任何附加选项。也就是说，我们可以在覆盖类型网络上配置的唯一选项是`network create`子命令的一部分。

+   `aux-address`：与用户定义的桥接一样，这个命令允许您定义 Docker 在生成容器时不应分配的 IP 地址。

+   `gateway`：虽然您可以为网络定义一个网关，如果您不这样做，Docker 会为您做这个，但实际上在覆盖网络中并不使用这个。也就是说，没有接口会被分配这个 IP 地址。

+   `internal`：此选项允许您隔离网络，并在本章后面更详细地介绍。

+   `ip-range`：允许您指定一个较小的子网，用于容器寻址。

+   `ipam-driver`：除了使用第三方网络驱动程序，您还可以利用第三方 IPAM 驱动程序。在本书中，我们将主要关注默认或内置的 IPAM 驱动程序。

+   `ipam-opt`：这允许您指定要传递给 IPAM 驱动程序的选项。

+   `subnet`：这定义了与您创建的网络类型相关联的子网。

让我们在主机`docker4`上重新定义网络`myoverlay`：

```
user@docker4:~$ docker network create -d overlay \
--subnet 172.16.16.0/24  --aux-address ip2=172.16.16.2 \
--ip-range=172.16.16.128/25 myoverlay
```

在这个例子中，我们使用以下属性定义网络：

+   一个`subnet`为`172.16.16.0/24`

+   一个保留或辅助地址为`172.16.16.2`（请记住，Docker 将分配一个网关 IP 作为子网中的第一个 IP，尽管实际上并没有使用。在这种情况下，这意味着`.1`和`.2`在这一点上在技术上是保留的。）

+   一个可分配的容器 IP 范围为`172.16.16.128/25`

+   一个名为`myoverlay`的网络

与以前一样，这个网络现在可以在参与覆盖配置的三个主机上使用。现在让我们从主机`docker2`上的覆盖网络中定义我们的第一个容器：

```
user@docker2:~$ docker run --net=myoverlay --name web1 \
-d -P jonlangemak/web_server_1
3d767d2d2bda91300827f444aa6c4a0762a95ce36a26537aac7770395b5ff673
user@docker2:~$
```

在这里，我们要求主机启动一个名为`web1`的容器，并将其连接到网络`myoverlay`。现在让我们检查容器的 IP 接口配置：

```
user@docker2:~$ docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
7: **eth0@if8**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP
    link/ether 02:42:ac:10:10:81 brd ff:ff:ff:ff:ff:ff
    inet **172.16.16.129/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe10:1081/64 scope link
       valid_lft forever preferred_lft forever
10: **eth1**@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet **172.18.0.2/16** scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe12:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker2:~$
```

令人惊讶的是，容器有两个接口。`eth0`接口连接到与覆盖网络`myoverlay`相关联的网络，但`eth1`与一个新网络`172.18.0.0/16`相关联。

### 注意

到目前为止，您可能已经注意到容器中的接口名称使用 VETH 对命名语法。Docker 使用 VETH 对将容器连接到桥接，并直接在容器侧接口上配置容器 IP 地址。这将在第四章中进行详细介绍，*构建 Docker 网络*，在这里我们将详细介绍 Docker 如何将容器连接到网络。

为了找出它连接到哪里，让我们试着找到容器的`eth1`接口连接到的 VETH 对的另一端。如第一章所示，*Linux 网络构造*，我们可以使用`ethtool`来查找 VETH 对的对等`接口 ID`。然而，当查看用户定义的网络时，有一种更简单的方法可以做到这一点。请注意，在前面的输出中，VETH 对的名称具有以下语法：

```
<interface name>@if<peers interface ID>
```

幸运的是，`if`后面显示的数字是 VETH 对的另一端的`接口 ID`。因此，在前面的输出中，我们看到`eth1`接口的匹配接口具有`接口 ID`为`11`。查看本地 Docker 主机，我们可以看到我们定义了一个接口`11`，它的`对等接口 ID`是`10`，与容器中的`接口 ID`匹配。

```
user@docker2:~$ ip addr show
…<Additional output removed for brevity>…
9: docker_gwbridge: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:af:5e:26:cc brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 scope global docker_gwbridge
       valid_lft forever preferred_lft forever
    inet6 fe80::42:afff:fe5e:26cc/64 scope link
       valid_lft forever preferred_lft forever
11: veth02e6ea5@if10:** <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue **master docker_gwbridge** state UP group default
    link/ether ba:c7:df:7c:f4:48 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::b8c7:dfff:fe7c:f448/64 scope link
       valid_lft forever preferred_lft forever
user@docker2:~$
```

注意，VETH 对的这一端（`接口 ID 11`）有一个名为`docker_gwbridge`的主机。也就是说，VETH 对的这一端是桥接`docker_gwbridge`的一部分。让我们再次查看 Docker 主机上定义的网络：

```
user@docker2:~$ docker network ls
NETWORK ID          NAME                DRIVER
9c91f85550b3        **myoverlay**           **overlay
b3143542e9ed        none                null
323e5e3be7e4        host                host
6f60ea0df1ba        bridge              bridge
e637f106f633        **docker_gwbridge**     **bridge
user@docker2:~$
```

除了我们的覆盖网络，还有一个同名的新用户定义桥接。如果我们检查这个桥接，我们会看到我们的容器按预期连接到它，并且网络定义了一些选项：

```
user@docker2:~$ docker network inspect docker_gwbridge
[
    {
        "Name": "docker_gwbridge",
        "Id": "10a75e3638b999d7180e1c8310bf3a26b7d3ec7b4e0a7657d9f69d3b5d515389",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": [
                {
                    "Subnet": "172.18.0.0/16",
                    "Gateway": "172.18.0.1/16"
                }
            ]
        },
        "Internal": false,
        "Containers": {
 "e3ae95368057f24fefe1a0358b570848d8798ddfd1c98472ca7ea250087df452": {
 "Name": "gateway_e3ae95368057",
 "EndpointID": "4cdfc1fb130de499eefe350b78f4f2f92797df9fe7392aeadb94d136abc7f7cd",
 "MacAddress": "02:42:ac:12:00:02",
 "IPv4Address": "172.18.0.2/16",
 "IPv6Address": ""
 }
        },
        "Options": {
 "com.docker.network.bridge.enable_icc": "false",
 "com.docker.network.bridge.enable_ip_masquerade": "true",
 "com.docker.network.bridge.name": "docker_gwbridge"
        },
        "Labels": {}
    }
]
user@docker2:~$
```

正如我们所看到的，此桥的 ICC 模式已禁用。ICC 防止同一网络桥上的容器直接通信。但是这个桥的目的是什么，为什么生成在`myoverlay`网络上的容器被连接到它上面呢？

`docker_gwbridge`网络是用于覆盖连接的容器的外部容器连接的解决方案。覆盖网络可以被视为第 2 层网络段。您可以将多个容器连接到它们，并且该网络上的任何内容都可以跨越本地网络段进行通信。但是，这并不允许容器与网络外的资源通信。这限制了 Docker 通过发布端口访问容器资源的能力，以及容器与外部网络通信的能力。如果我们检查容器的路由配置，我们可以看到它的默认网关指向`docker_gwbridge`的接口：

```
user@docker2:~$ docker exec web1 ip route
default via 172.18.0.1 dev eth1
172.16.16.0/24 dev eth0  proto kernel  scope link  src 172.16.16.129
172.18.0.0/16 dev eth1  proto kernel  scope link  src 172.18.0.2
user@docker2:~$ 
```

再加上`docker_gwbridge`启用了 IP 伪装的事实，这意味着容器仍然可以与外部网络通信：

```
user@docker2:~$ docker exec -it web1 ping **4.2.2.2
PING 4.2.2.2 (4.2.2.2): 48 data bytes
56 bytes from 4.2.2.2: icmp_seq=0 ttl=50 time=27.473 ms
56 bytes from 4.2.2.2: icmp_seq=1 ttl=50 time=37.736 ms
--- 4.2.2.2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 27.473/32.605/37.736/5.132 ms
user@docker2:~$
```

与默认桥网络一样，如果容器尝试通过路由到达外部网络，它们将隐藏在其 Docker 主机 IP 接口后面。

这也意味着，由于我使用`-P`标志在此容器上发布了端口，Docker 已经使用`docker_gwbridge`发布了这些端口。我们可以使用`docker port`子命令来验证端口是否已发布：

```
user@docker2:~$ docker port web1
80/tcp -> 0.0.0.0:32768
user@docker2:~$
```

通过使用`iptables`检查 netfilter 规则来验证端口是否在`docker_gwbridge`上发布：

```
user@docker2:~$ sudo iptables -t nat -L
…<Additional output removed for brevity>…
Chain DOCKER (2 references)
target     prot opt source      destination
RETURN     all  --  anywhere    anywhere
RETURN     all  --  anywhere    anywhere
DNAT       tcp  --  anywhere    anywhere  tcp dpt:32768 to:172.18.0.2:80
user@docker2:~$
```

正如您在前面的输出中所看到的，Docker 正在使用`docker_gwbridge`上的容器接口来为 Docker 主机的接口提供端口发布。

此时，我们的容器拓扑如下：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_03_04.jpg)

将容器添加到覆盖网络会自动创建桥`docker_gwbridge`，用于容器连接到主机以及离开主机。`myoverlay`覆盖网络仅用于与定义的`subnet`，`172.16.16.0/24`相关的连接。

现在让我们启动另外两个容器，一个在主机`docker3`上，另一个在主机`docker4`上：

```
user@docker3:~$ **docker run --net=myoverlay --name web2 -d jonlangemak/web_server_2
da14844598d5a6623de089674367d31c8e721c05d3454119ca8b4e8984b91957
user@docker3:~$
user@docker4:~$  **docker run --net=myoverlay --name web2 -d jonlangemak/web_server_2
be67548994d7865ea69151f4797e9f2abc28a39a737eef48337f1db9f72e380c
docker: Error response from daemon: service endpoint with name web2 already exists.
user@docker4:~$
```

请注意，当我尝试在两个主机上运行相同的容器时，Docker 告诉我容器`web2`已经存在。Docker 不允许您在同一覆盖网络上以相同的名称运行容器。请回想一下，Docker 正在将与覆盖中的每个容器相关的信息存储在键值存储中。当我们开始讨论 Docker 名称解析时，使用唯一名称变得很重要。

### 注意

此时您可能会注意到容器可以通过名称解析彼此。这是与用户定义的网络一起提供的非常强大的功能之一。我们将在第五章中更详细地讨论这一点，*容器链接和 Docker DNS*，在那里我们将讨论 DNS 和链接。

使用唯一名称在`docker4`上重新启动容器：

```
user@docker4:~$ docker run --net=myoverlay --name **web2-2** -d jonlangemak/web_server_2
e64d00093da3f20c52fca52be2c7393f541935da0a9c86752a2f517254496e26
user@docker4:~$
```

现在我们有三个容器在运行，每个主机上都有一个参与覆盖。让我们花点时间来想象这里发生了什么：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_03_05.jpg)

我已经在图表上删除了主机和底层网络，以便更容易阅读。如描述的那样，每个容器都有两个 IP 网络接口。一个 IP 地址位于共享的覆盖网络上，位于`172.16.16.128/25`网络中。另一个位于桥接`docker_gwbridge`上，每个主机上都是相同的。由于`docker_gwbridge`独立存在于每个主机上，因此不需要为此接口设置唯一的地址。该桥上的容器接口仅用作容器与外部网络通信的手段。也就是说，位于相同主机上的每个容器，在覆盖类型网络上都会在同一桥上接收一个 IP 地址。

您可能会想知道这是否会引起安全问题，因为所有连接到覆盖网络的容器，无论连接到哪个网络，都会在共享桥上（`docker_gwbridge`）上有一个接口。请回想一下之前我指出过`docker_gwbridge`已禁用了 ICC 模式。这意味着，虽然可以将许多容器部署到桥上，但它们都无法通过桥上的 IP 接口直接与彼此通信。我们将在第六章中更详细地讨论这一点，*容器网络安全*，在那里我们将讨论容器安全，但现在知道 ICC 可以防止在共享桥上发生 ICC。

容器在覆盖网络上相信它们在同一网络段上，或者彼此相邻的第 2 层。让我们通过从容器`web1`连接到容器`web2`上的 web 服务来证明这一点。回想一下，当我们配置容器`web2`时，我们没有要求它发布任何端口。

与其他 Docker 网络构造一样，连接到同一覆盖网络的容器可以直接在它们绑定服务的任何端口上相互通信，而无需发布端口：

### 注意

重要的是要记住，Docker 主机没有直接连接到覆盖连接的容器的手段。对于桥接网络类型，这是可行的，因为主机在桥接上有一个接口，在覆盖类型网络的情况下，这个接口是不存在的。

```
user@docker2:~$ docker exec web1 curl -s http://172.16.16.130
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span></h1>
</body>
  </html>
user@docker2:~$
```

正如你所看到的，我们可以成功地从容器`web1`访问运行在容器`web2`中的 web 服务器。这些容器不仅位于完全不同的主机上，而且主机本身位于完全不同的子网上。这种类型的通信以前只有在两个容器坐在同一主机上，并连接到同一个桥接时才可用。我们可以通过检查每个相应容器上的 ARP 和 MAC 条目来证明容器相信自己是第 2 层相邻的：

```
user@**docker2**:~$ docker exec web1 arp -n
Address         HWtype  HWaddress         Flags Mask            Iface
172.16.16.130   ether   02:42:ac:10:10:82 C                     eth0
172.18.0.1      ether   02:42:07:3d:f3:2c C                     eth1
user@docker2:~$

user@docker3:~$ docker exec web2 ip link show dev eth0
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP
    link/ether **02:42:ac:10:10:82** brd ff:ff:ff:ff:ff:ff
user@docker3:~$ 
```

我们可以看到容器有一个 ARP 条目，来自远程容器，指定其 IP 地址以及 MAC 地址。如果容器不在同一网络上，容器`web1`将不会有`web2`的 ARP 条目。

我们可以验证我们从`docker4`主机上的`web2-2`容器对所有三个容器之间的本地连接性：

```
user@docker4:~$ docker exec -it web2-2 ping **172.16.16.129** -c 2
PING 172.16.16.129 (172.16.16.129): 48 data bytes
56 bytes from 172.16.16.129: icmp_seq=0 ttl=64 time=0.642 ms
56 bytes from 172.16.16.129: icmp_seq=1 ttl=64 time=0.777 ms
--- 172.16.16.129 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.642/0.710/0.777/0.068 ms

user@docker4:~$ docker exec -it web2-2 ping **172.16.16.130** -c 2
PING 172.16.16.130 (172.16.16.130): 48 data bytes
56 bytes from 172.16.16.130: icmp_seq=0 ttl=64 time=0.477 ms
56 bytes from 172.16.16.130: icmp_seq=1 ttl=64 time=0.605 ms
--- 172.16.16.130 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.477/0.541/0.605/0.064 ms

user@docker4:~$ docker exec -it web2-2 arp -n
Address         HWtype  HWaddress         Flags Mask            Iface
172.16.16.129   ether   02:42:ac:10:10:81 C                     eth0
172.16.16.130   ether   02:42:ac:10:10:82 C                     eth0
user@docker4:~$
```

现在我们知道覆盖网络是如何工作的，让我们谈谈它是如何实现的。覆盖传输所使用的机制是 VXLAN。我们可以通过查看在物理网络上进行的数据包捕获来看到容器生成的数据包是如何穿越底层网络的。

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_03_06.jpg)

在从捕获中获取的数据包的前面的屏幕截图中，我想指出一些项目：

+   外部 IP 数据包源自`docker2`主机（`10.10.10.102`），目的地是`docker3`主机（`192.168.50.101`）。

+   我们可以看到外部 IP 数据包是 UDP，并且被检测为 VXLAN 封装。

+   **VNI**（VXLAN 网络标识符）或段 ID 为`260`。VNI 在每个子网中是唯一的。

+   内部帧具有第 2 层和第 3 层标头。第 2 层标头具有容器 `web2` 的目标 MAC 地址，如前所示。IP 数据包显示了容器 `web1` 的源和容器 `web2` 的目标。

Docker 主机使用自己的 IP 接口封装覆盖流量，并通过底层网络将其发送到目标 Docker 主机。来自键值存储的信息用于确定给定容器所在的主机，以便 VXLAN 封装将流量发送到正确的主机。

您现在可能想知道 VXLAN 覆盖的所有配置在哪里。到目前为止，我们还没有看到任何实际涉及 VXLAN 或隧道的配置。为了提供 VXLAN 封装，Docker 为每个用户定义的覆盖网络创建了我所说的 *覆盖命名空间*。正如我们在第一章中看到的 *Linux 网络构造*，您可以使用 `ip netns` 工具与网络命名空间进行交互。然而，由于 Docker 将它们的网络命名空间存储在非默认位置，我们将无法使用 `ip netns` 工具查看任何由 Docker 创建的命名空间。默认情况下，命名空间存储在 `/var/run/netns` 中。问题在于 Docker 将其网络命名空间存储在 `/var/run/docker/netns` 中，这意味着 `ip netns` 工具正在错误的位置查看由 Docker 创建的网络命名空间。为了解决这个问题，我们可以创建一个 `symlink`，将 `/var/run/docker/netns/` 链接到 `/var/run/nents`，如下所示：

```
user@docker4:~$ cd /var/run
user@docker4:/var/run$ sudo ln -s /var/run/docker/netns netns
user@docker4:/var/run$ sudo ip netns list
eb40d6527d17 (id: 2)
2-4695c5484e (id: 1) 
user@docker4:/var/run$ 
```

请注意，定义了两个网络命名空间。覆盖命名空间将使用以下语法进行标识 `x-<id>`，其中 `x` 是一个随机数。

### 注意

我们在输出中看到的另一个命名空间与主机上运行的容器相关联。在下一章中，我们将深入探讨 Docker 如何创建和使用这些命名空间。

因此，在我们的情况下，覆盖命名空间是 `2-4695c5484e`，但它是从哪里来的呢？如果我们检查这个命名空间的网络配置，我们会看到它定义了一些不寻常的接口：

```
user@docker4:/var/run$ **sudo ip netns exec 2-4695c5484e ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: **br0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default
    link/ether a6:1e:2a:c4:cb:14 brd ff:ff:ff:ff:ff:ff
11: **vxlan1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue **master br0** state UNKNOWN mode DEFAULT group default
    link/ether a6:1e:2a:c4:cb:14 brd ff:ff:ff:ff:ff:ff link-netnsid 0
13: **veth2@if12**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue master br0 state UP mode DEFAULT group default
    link/ether b2:fa:2d:cc:8b:51 brd ff:ff:ff:ff:ff:ff link-netnsid 1
user@docker4:/var/run$ 
```

这些接口定义了我之前提到的叠加网络命名空间。之前我们看到`web2-2`容器有两个接口。`eth1`接口是 VETH 对的一端，另一端放在`docker_gwbridge`上。在前面的叠加网络命名空间中显示的 VETH 对代表了容器`eth0`接口的一侧。我们可以通过匹配 VETH 对的一侧来证明这一点。请注意，VETH 对的这一端显示另一端的`接口 ID`为`12`。如果我们查看容器`web2-2`，我们会看到它的`eth0`接口的 ID 为`12`。反过来，容器的接口显示了一个 ID 为`13`的对 ID，这与我们在叠加命名空间中看到的输出相匹配：

```
user@docker4:/var/run$ **docker exec web2-2 ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
12: eth0@if13:** <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP
    link/ether 02:42:ac:10:10:83 brd ff:ff:ff:ff:ff:ff
14: eth1@if15: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
user@docker4:/var/run$ 
```

现在我们知道容器的叠加接口（`eth0`）是如何连接的，我们需要知道进入叠加命名空间的流量是如何封装并发送到其他 Docker 主机的。这是通过叠加命名空间的`vxlan1`接口完成的。该接口具有特定的转发条目，描述了叠加中的所有其他端点：

```
user@docker4:/var/run$ sudo ip netns exec 2-4695c5484e \
bridge fdb show dev vxlan1
a6:1e:2a:c4:cb:14 master br0 permanent
a6:1e:2a:c4:cb:14 vlan 1 master br0 permanent
02:42:ac:10:10:82 dst 192.168.50.101 link-netnsid 0 self permanent
02:42:ac:10:10:81 dst 10.10.10.102 link-netnsid 0 self permanent
user@docker4:/var/run$
```

请注意，我们有两个条目引用 MAC 地址和目的地。MAC 地址表示叠加中另一个容器的 MAC 地址，IP 地址是容器所在的 Docker 主机。我们可以通过检查其他主机来验证：

```
user@docker2:~$ ip addr show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether f2:e8:00:24:e2:de brd ff:ff:ff:ff:ff:ff
    inet **10.10.10.102/24** brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f0e8:ff:fe24:e2de/64 scope link
       valid_lft forever preferred_lft forever
user@docker2:~$
user@docker2:~$ **docker exec web1 ip link show dev eth0
7: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP
    link/ether **02:42:ac:10:10:81** brd ff:ff:ff:ff:ff:ff
user@docker2:~$
```

有了这些信息，叠加命名空间就知道为了到达目的地 MAC 地址，它需要在 VXLAN 中封装流量并将其发送到`10.10.10.102`（`docker2`）。

# 隔离网络

用户定义的网络可以支持所谓的内部模式。我们在早期关于创建用户定义网络的示例中看到了这个选项，但并没有花太多时间讨论它。在创建网络时使用`--internal`标志可以防止连接到网络的容器与任何外部网络通信。

## 准备工作

`docker network`子命令是在 Docker 1.9 中引入的，因此您需要运行至少该版本的 Docker 主机。在我们的示例中，我们将使用 Docker 版本 1.12。您还需要对当前网络布局有很好的了解，以便在我们检查当前配置时能够跟上。假设每个 Docker 主机都处于其本机配置中。

## 如何做…

将用户定义的网络设置为内部网络非常简单，只需在`network create`子命令中添加`--internal`选项。由于用户定义的网络可以是桥接类型或覆盖类型，我们应该了解 Docker 如何在任何情况下实现隔离。

### 创建内部用户定义的桥接网络

定义一个用户定义的桥接并传递`internal`标志，以及在主机上为桥接指定自定义名称的标志。我们可以使用以下命令来实现这一点：

```
user@docker2:~$ **docker network create --internal \
-o com.docker.network.bridge.name=mybridge1 myinternalbridge
aa990a5436fb2b01f92ffc4d47c5f76c94f3c239f6e9005081ff5c5ecdc4059a
user@docker2:~$
```

现在，让我们看一下 Docker 分配给桥接的 IP 信息：

```
user@docker2:~$ ip addr show dev mybridge1
13: mybridge1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:b5:c7:0e:63 brd ff:ff:ff:ff:ff:ff
    inet **172.19.0.1/16** scope global mybridge1
       valid_lft forever preferred_lft forever
user@docker2:~$
```

有了这些信息，我们现在来检查一下 Docker 为这个桥接在 netfilter 中编程了什么。让我们检查过滤表并查看：

### 注意

在这种情况下，我正在使用`iptables-save`语法来查询当前的规则。有时，这比查看单个表更易读。

```
user@docker2:~$ sudo iptables-save
# Generated by iptables-save v1.4.21
…<Additional output removed for brevity>… 
-A DOCKER-ISOLATION ! -s 172.19.0.0/16 -o mybridge1 -j DROP
-A DOCKER-ISOLATION ! -d 172.19.0.0/16 -i mybridge1 -j DROP
-A DOCKER-ISOLATION -j RETURN
COMMIT
# Completed on Tue Oct  4 23:45:24 2016
user@docker2:~$
```

在这里，我们可以看到 Docker 添加了两条规则。第一条规定，任何不是源自桥接子网并且正在离开桥接接口的流量应该被丢弃。这可能很难理解，所以最容易的方法是以一个例子来思考。假设您网络上的主机`192.168.127.57`正在尝试访问这个桥接上的某些内容。该流量的源 IP 地址不会在桥接子网中，这满足了规则的第一部分。它还将尝试离开（或进入）`mybridge1`，满足了规则的第二部分。这条规则有效地阻止了所有入站通信。

第二条规则寻找没有在桥接子网中具有目的地，并且具有桥接`mybridge1`的入口接口的流量。在这种情况下，容器可能具有 IP 地址 172.19.0.5/16。如果它试图离开本地网络进行通信，目的地将不在`172.19.0.0/16`中，这将匹配规则的第一部分。当它试图离开桥接朝向外部网络时，它将匹配规则的第二部分，因为它进入`mybridge1`接口。这条规则有效地阻止了所有出站通信。

在这两条规则之间，桥接内部不允许任何流量进出。但是，这并不妨碍在同一桥接上的容器之间的容器之间的连接。

应该注意的是，Docker 允许您在针对内部桥接运行容器时指定发布（`-P`）标志。但是，端口将永远不会被映射：

```
user@docker2:~$ docker run --net=myinternalbridge --name web1 -d -P jonlangemak/web_server_1
b5f069a40a527813184c7156633c1e28342e0b3f1d1dbb567f94072bc27a5934
user@docker2:~$ docker port web1
user@docker2:~$
```

### 创建内部用户定义的覆盖网络

创建内部覆盖遵循相同的过程。我们只需向`network create`子命令传递`--internal`标志。然而，在覆盖网络的情况下，隔离模型要简单得多。我们可以按以下方式创建内部覆盖网络：

```
user@docker2:~$ **docker network create -d overlay \
--subnet 192.10.10.0/24 --internal myinternaloverlay
1677f2c313f21e58de256d9686fd2d872699601898fd5f2a3391b94c5c4cd2ec
user@docker2:~$
```

创建后，它与非内部覆盖没有什么不同。区别在于当我们在内部覆盖上运行容器时：

```
user@docker2:~$ docker run --net=myinternaloverlay --name web1 -d -P jonlangemak/web_server_1
c5b05a3c829dfc04ecc91dd7091ad7145cbce96fc7aa0e5ad1f1cf3fd34bb02b
user@docker2:~$
```

检查容器接口配置，我们可以看到容器只有一个接口，它是覆盖网络（`192.10.10.0/24`）的成员。通常连接容器到`docker_gwbridge`（`172.18.0.0/16`）网络以进行外部连接的接口缺失：

```
user@docker2:~$ docker exec -it web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
11: **eth0**@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP
    link/ether 02:42:c0:0a:0a:02 brd ff:ff:ff:ff:ff:ff
    inet **192.10.10.2/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c0ff:fe0a:a02/64 scope link
       valid_lft forever preferred_lft forever
user@docker2:~$ 
```

覆盖网络本质上是隔离的，因此需要`docker_gwbridge`。不将容器接口映射到`docker_gwbridge`意味着没有办法在覆盖网络内部或外部进行通信。


# 第四章：构建 Docker 网络

在本章中，我们将涵盖以下教程：

+   手动网络容器

+   指定自己的桥

+   使用 OVS 桥

+   使用 OVS 桥连接 Docker 主机

+   OVS 和 Docker 一起

# 介绍

正如我们在前几章中看到的，Docker 在处理许多容器网络需求方面做得很好。然而，这并不限制您只能使用 Docker 提供的网络元素来连接容器。因此，虽然 Docker 可以为您提供网络，但您也可以手动连接容器。这种方法的缺点是 Docker 对容器的网络状态不知情，因为它没有参与网络配置。正如我们将在第七章 *使用 Weave Net*中看到的，Docker 现在也支持自定义或第三方网络驱动程序，帮助弥合本机 Docker 和第三方或自定义容器网络配置之间的差距。

# 手动网络容器

在第一章 *Linux 网络构造*和第二章 *配置和监视 Docker 网络*中，我们回顾了常见的 Linux 网络构造，以及涵盖了 Docker 容器网络的本机选项。在这个教程中，我们将演示如何手动网络连接容器，就像 Docker 在默认桥接网络模式下所做的那样。了解 Docker 如何处理容器的网络配置是理解容器网络的非本机选项的关键构建块。

## 准备工作

在这个教程中，我们将演示在单个 Docker 主机上的配置。假设这个主机已经安装了 Docker，并且 Docker 处于默认配置。为了查看和操作网络设置，您需要确保已安装`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2 
```

为了对主机进行网络更改，您还需要 root 级别的访问权限。

## 如何做…

为了手动配置容器的网络，我们需要明确告诉 Docker 在运行时不要配置容器的网络。为此，我们使用`none`网络模式来运行容器。例如，我们可以使用以下语法启动一个没有任何网络配置的 web 服务器容器：

```
user@docker1:~$ docker run --name web1 **--net=none** -d \
jonlangemak/web_server_1
c108ca80db8a02089cb7ab95936eaa52ef03d26a82b1e95ce91ddf6eef942938
user@docker1:~$
```

容器启动后，我们可以使用`docker exec`子命令来检查其网络配置：

```
user@docker1:~$ docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
user@docker1:~$ 
```

正如你所看到的，除了本地环回接口之外，容器没有定义任何接口。此时，没有办法连接到容器。我们所做的实质上是在一个气泡中创建了一个容器：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_01.jpg)

因为我们的目标是模拟默认的网络配置，现在我们需要找到一种方法将容器`web1`连接到`docker0`桥，并从桥的 IP 分配（`172.17.0.0/16`）中分配一个 IP 地址给它。

话虽如此，我们需要做的第一件事是创建我们将用来连接容器到`docker0`桥的接口。正如我们在第一章中看到的，*Linux 网络构造*，Linux 有一个名为**虚拟以太网**（**VETH**）对的网络组件，这对于此目的非常有效。接口的一端将连接到`docker0`桥，另一端将连接到容器。

让我们从创建 VETH 对开始：

```
user@docker1:~$ **sudo ip link add bridge_end type veth \
peer name container_end
user@docker1:~$ ip link show
…<Additional output removed for brevity>…
5: **container_end@bridge_end**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether ce:43:d8:59:ac:c1 brd ff:ff:ff:ff:ff:ff
6: **bridge_end@container_end**: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 72:8b:e7:f8:66:45 brd ff:ff:ff:ff:ff:ff
user@docker1:~$
```

正如预期的那样，现在我们有两个直接关联的接口。现在让我们将其中一个端口绑定到`docker0`桥上并启用该接口：

```
user@docker1:~$ sudo ip link set dev **bridge_end** master docker0
user@docker1:~$ sudo ip link set **bridge_end** up
user@docker1:~$ ip link show bridge_end
6: **bridge_end@container_end**: <NO-CARRIER,BROADCAST,MULTICAST,UP,M-DOWN> mtu 1500 qdisc pfifo_fast **master docker0** state LOWERLAYERDOWN mode DEFAULT group default qlen 1000
    link/ether 72:8b:e7:f8:66:45 brd ff:ff:ff:ff:ff:ff
user@docker1:~$

```

### 注意

此时接口的状态将显示为`LOWERLAYERDOWN`。这是因为接口的另一端未绑定，仍处于关闭状态。

下一步是将 VETH 对的另一端连接到容器。这就是事情变得有趣的地方。Docker 会在自己的网络命名空间中创建每个容器。这意味着 VETH 对的另一端需要落入容器的网络命名空间。关键是确定容器的网络命名空间是什么。可以通过两种不同的方式找到给定容器的命名空间。

第一种方法依赖于将容器的**进程 ID**（**PID**）与已定义的网络命名空间相关联。它比第二种方法更复杂，但可以让您了解一些网络命名空间的内部情况。您可能还记得第三章中所述，默认情况下，我们无法使用命令行工具`ip netns`查看 Docker 创建的命名空间。为了查看它们，我们需要创建一个符号链接，将 Docker 存储其网络命名空间的位置（`/var/run/docker/netns`）与`ip netns`正在查找的位置（`/var/run/netns`）联系起来。

```
user@docker1:~$ cd /var/run
user@docker1:/var/run$ sudo ln -s /var/run/docker/netns netns
```

现在，如果我们尝试列出命名空间，我们应该至少看到一个列在返回中：

```
user@docker1:/var/run$ sudo ip netns list
712f8a477cce
default
user@docker1:/var/run$
```

但是我们怎么知道这是与此容器关联的命名空间呢？要做出这一决定，我们首先需要找到相关容器的 PID。我们可以通过检查容器来检索这些信息：

```
user@docker1:~$ docker inspect web1
…<Additional output removed for brevity>…
        "State": {
            "Status": "running",
            "Running": true,
            "Paused": false,
            "Restarting": false,
            "OOMKilled": false,
            "Dead": false,
            "Pid": 3156**,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "2016-10-05T21:32:00.163445345Z",
            "FinishedAt": "0001-01-01T00:00:00Z"
        },
…<Additional output removed for brevity>…
user@docker1:~$ 
```

现在我们有了 PID，我们可以使用`ip netns identify`子命令从 PID 中找到网络命名空间的名称：

```
user@docker1:/var/run$ sudo ip netns identify **3156
712f8a477cce
user@docker1:/var/run$ 
```

### 注意

即使您选择使用第二种方法，请确保创建符号链接，以便`ip netns`在后续步骤中起作用。

找到容器网络命名空间的第二种方法要简单得多。我们可以简单地检查和引用容器的网络配置：

```
user@docker1:~$ docker inspect web1
…<Additional output removed for brevity>… 
"NetworkSettings": {
            "Bridge": "",
            "SandboxID": "712f8a477cceefc7121b2400a22261ec70d6a2d9ab2726cdbd3279f1e87dae22",
            "HairpinMode": false,
            "LinkLocalIPv6Address": "",
            "LinkLocalIPv6PrefixLen": 0,
            "Ports": {},
            "SandboxKey": "/var/run/docker/netns/712f8a477cce",
            "SecondaryIPAddresses": null,
            "SecondaryIPv6Addresses": null,
            "EndpointID": "", 
…<Additional output removed for brevity>… 
user@docker1:~$
```

注意名为`SandboxKey`的字段。您会注意到文件路径引用了我们说过 Docker 存储其网络命名空间的位置。此路径中引用的文件名是容器的网络命名空间的名称。Docker 将网络命名空间称为沙盒，因此使用了这种命名约定。

现在我们有了网络命名空间名称，我们可以在容器和`docker0`桥之间建立连接。回想一下，VETH 对可以用来连接网络命名空间。在这个例子中，我们将把 VETH 对的容器端放在容器的网络命名空间中。这将把容器桥接到`docker0`桥上的默认网络命名空间中。为此，我们首先将 VETH 对的容器端移入我们之前发现的命名空间中：

```
user@docker1:~$ sudo ip link set container_end netns **712f8a477cce

```

我们可以使用`docker exec`子命令验证 VETH 对是否在命名空间中：

```
user@docker1:~$ docker exec web1 ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
5: **container_end@if6**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 86:15:2a:f7:0e:f9 brd ff:ff:ff:ff:ff:ff
user@docker1:~$
```

到目前为止，我们已成功地使用 VETH 对将容器和默认命名空间连接在一起，因此我们的连接现在看起来像这样：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_02.jpg)

然而，容器 `web1` 仍然缺乏任何类型的 IP 连通性，因为它尚未被分配可路由的 IP 地址。回想一下，在第一章中，*Linux 网络构造*，我们看到 VETH 对接口可以直接分配 IP 地址。为了给容器分配一个可路由的 IP 地址，Docker 简单地从 `docker0` 桥的子网中分配一个未使用的 IP 地址给 VETH 对的容器端。

### 注意

IPAM 是允许 Docker 为您管理容器网络的巨大优势。没有 IPAM，你将需要自己跟踪分配，并确保你不分配任何重叠的 IP 地址。

```
user@docker1:~$ sudo ip netns exec 712f8a477cce ip \
addr add 172.17.0.99/16 dev container_end
```

在这一点上，我们可以启用接口，我们应该可以从主机到容器的可达性。但在这样做之前，让我们通过将 `container_end` VETH 对重命名为 `eth0` 来使事情变得更清晰一些：

```
user@docker1:~$ sudo ip netns exec 712f8a477cce ip link \
set dev container_end name eth0
```

现在我们可以启用新命名的 `eth0` 接口，这是 VETH 对的容器端：

```
user@docker1:~$ sudo ip netns exec 712f8a477cce ip link \
set eth0 up
user@docker1:~$ ip link show bridge_end
6: **bridge_end**@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master docker0 state UP mode DEFAULT group default qlen 1000
    link/ether 86:04:ed:1b:2a:04 brd ff:ff:ff:ff:ff:ff
user@docker1:~$ sudo ip netns exec **4093b3b4e672 ip link show eth0
5: **eth0**@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 86:15:2a:f7:0e:f9 brd ff:ff:ff:ff:ff:ff
user@docker1:~$ sudo ip netns exec **4093b3b4e672 ip addr show eth0
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 86:15:2a:f7:0e:f9 brd ff:ff:ff:ff:ff:ff
    inet **172.17.0.99/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::8415:2aff:fef7:ef9/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

如果我们从主机检查，现在我们应该可以到达容器：

```
user@docker1:~$ ping **172.17.0.99** -c 2
PING 172.17.0.99 (172.17.0.99) 56(84) bytes of data.
64 bytes from 172.17.0.99: icmp_seq=1 ttl=64 time=0.104 ms
64 bytes from 172.17.0.99: icmp_seq=2 ttl=64 time=0.045 ms
--- 172.17.0.99 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.045/0.074/0.104/0.030 ms
user@docker1:~$
user@docker1:~$ curl **http://172.17.0.99
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span></h1>
</body>
  </html>
user@docker1:~$
```

连接已经建立，我们的拓扑现在看起来是这样的：

![操作步骤…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_03.jpg)

因此，虽然我们有 IP 连通性，但只限于相同子网上的主机。最后剩下的问题是解决主机级别的容器连通性。对于出站连通性，主机将容器的 IP 地址隐藏在主机接口 IP 地址的后面。对于入站连通性，在默认网络模式下，Docker 使用端口映射将 Docker 主机的 NIC 上的随机高端口映射到容器的暴露端口。

在这种情况下解决出站问题就像给容器指定一个指向 `docker0` 桥的默认路由，并确保你有一个 netfilter masquerade 规则来覆盖这个一样简单：

```
user@docker1:~$ sudo ip netns exec 712f8a477cce ip route \
add default via **172.17.0.1
user@docker1:~$ docker exec -it **web1** ping 4.2.2.2 -c 2
PING 4.2.2.2 (4.2.2.2): 48 data bytes
56 bytes from 4.2.2.2: icmp_seq=0 ttl=50 time=39.764 ms
56 bytes from 4.2.2.2: icmp_seq=1 ttl=50 time=40.210 ms
--- 4.2.2.2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 39.764/39.987/40.210/0.223 ms
user@docker1:~$
```

如果你像我们在这个例子中使用 `docker0` 桥，你就不需要添加自定义 netfilter masquerade 规则。这是因为默认的伪装规则已经覆盖了整个 `docker0` 桥的子网：

```
user@docker1:~$ sudo iptables -t nat -L
…<Additional output removed for brevity>…
Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
MASQUERADE  all  --  172.17.0.0/16        anywhere
…<Additional output removed for brevity>…
user@docker1:~$
```

对于入站服务，我们需要创建一个自定义规则，使用**网络地址转换**（**NAT**）将主机上的随机高端口映射到容器中暴露的服务端口。我们可以使用以下规则来实现：

```
user@docker1:~$ sudo iptables -t nat -A DOCKER ! -i docker0 -p tcp -m tcp \
--dport 32799 -j DNAT --to-destination 172.17.0.99:80
```

在这种情况下，我们将主机接口上的端口`32799`进行 NAT 转发到容器上的端口`80`。这将允许外部网络上的系统通过 Docker 主机的接口访问在`web1`上运行的 Web 服务器，端口为`32799`。

最后，我们成功地复制了 Docker 在默认网络模式下提供的内容：

![操作步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_04.jpg)

这应该让您对 Docker 在幕后所做的事情有所了解。跟踪容器 IP 地址、发布端口的端口分配以及`iptables`规则集是 Docker 代表您跟踪的三个主要事项。鉴于容器的短暂性质，手动完成这些工作几乎是不可能的。

# 指定您自己的桥接

在大多数网络场景中，Docker 严重依赖于`docker0`桥。`docker0`桥是在启动 Docker 引擎服务时自动创建的，并且是 Docker 服务生成的任何容器的默认连接点。我们在之前的配方中也看到，可以在服务级别修改这个桥的一些属性。在这个配方中，我们将向您展示如何告诉 Docker 使用完全不同的桥接。

## 准备工作

在这个配方中，我们将演示在单个 Docker 主机上的配置。假设这个主机已经安装了 Docker，并且 Docker 处于默认配置状态。为了查看和操作网络设置，您需要确保安装了`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2 
```

为了对主机进行网络更改，您还需要 root 级别的访问权限。

## 操作步骤

与其他服务级参数一样，指定 Docker 使用不同的桥接是通过更新我们在第二章中向您展示如何创建的 systemd drop-in 文件来完成的，*配置和监控 Docker 网络*。

在指定新桥之前，让我们首先确保没有正在运行的容器，停止 Docker 服务，并删除`docker0`桥：

```
user@docker1:~$ docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
user@docker1:~$
user@docker1:~$ sudo systemctl stop docker
user@docker1:~$
user@docker1:~$ sudo ip link delete dev docker0
user@docker1:~$
user@docker1:~$ ip link show dev docker0
Device "docker0" does not exist.
user@docker1:~$
```

在这一点上，默认的`docker0`桥已被删除。现在，让我们为 Docker 创建一个新的桥接。

### 注意

如果您不熟悉`iproute2`命令行工具，请参考第一章中的示例，*Linux 网络构造*。

```
user@docker1:~$ sudo ip link add mybridge1 type bridge
user@docker1:~$ sudo ip address add 10.11.12.1/24 dev mybridge1
user@docker1:~$ sudo ip link set dev mybridge1 up
user@docker1:~$ ip addr show dev mybridge1
7: mybridge1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default
    link/ether 9e:87:b4:7b:a3:c0 brd ff:ff:ff:ff:ff:ff
    inet **10.11.12.1/24** scope global mybridge1
       valid_lft forever preferred_lft forever
    inet6 fe80::9c87:b4ff:fe7b:a3c0/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

我们首先创建了一个名为`mybridge1`的桥接，然后给它分配了 IP 地址`10.11.12.1/24`，最后启动了接口。此时，接口已经启动并可达。现在我们可以告诉 Docker 使用这个桥接作为其默认桥接。要做到这一点，编辑 Docker 的 systemd drop-in 文件，并确保最后一行如下所示：

```
ExecStart=/usr/bin/dockerd --bridge=mybridge1
```

现在保存文件，重新加载 systemd 配置，并启动 Docker 服务：

```
user@docker1:~$ sudo systemctl daemon-reload
user@docker1:~$ sudo systemctl start docker
```

现在，如果我们启动一个容器，我们应该看到它被分配到桥接`mybridge1`上：

```
user@docker1:~$ **docker run --name web1 -d -P jonlangemak/web_server_1
e8a05afba6235c6d8012639aa79e1732ed5ff741753a8c6b8d9c35a171f6211e
user@docker1:~$ **ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 62:31:35:63:65:63 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 36:b3:5c:94:c0:a6 brd ff:ff:ff:ff:ff:ff
17: **mybridge1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 7a:1b:30:e6:94:b7 brd ff:ff:ff:ff:ff:ff
22: veth68fb58a@if21**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue **master mybridge1** state UP mode DEFAULT group default
    link/ether 7a:1b:30:e6:94:b7 brd ff:ff:ff:ff:ff:ff link-netnsid 0
user@docker1:~$
```

请注意，在服务启动时并未创建`docker0`桥接。还要注意，我们在默认命名空间中看到了一个 VETH 对的一端，其主接口为`mybridge1`。

利用我们从本章第一个配方中学到的知识，我们还可以确认 VETH 对的另一端在容器的网络命名空间中：

```
user@docker1:~$ docker inspect web1 | grep SandboxKey
            "SandboxKey": "/var/run/docker/netns/926ddab911ae",
user@docker1:~$ 
user@docker1:~$ sudo ip netns exec **926ddab911ae ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
21: eth0@if22**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    link/ether 02:42:0a:0b:0c:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
user@docker1:~$ 
```

我们可以看出这是一个 VETH 对，因为它使用`<interface>@<interface>`的命名语法。如果我们比较 VETH 对接口的编号，我们可以看到这两个与 VETH 对的主机端匹配，索引为`22`连接到 VETH 对的容器端，索引为`21`。

### 注意

您可能会注意到我在使用`ip netns exec`和`docker exec`命令在容器内执行命令时来回切换。这样做的目的不是为了混淆，而是为了展示 Docker 代表您在做什么。需要注意的是，为了使用`ip netns exec`语法，您需要在我们在早期配方中演示的位置放置符号链接。只有在手动配置命名空间时才需要使用`ip netns exec`。

如果我们查看容器的网络配置，我们可以看到 Docker 已经为其分配了`mybridge1`子网范围内的 IP 地址：

```
user@docker1:~$ docker exec web1 ip addr show dev **eth0
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:0a:0b:0c:02 brd ff:ff:ff:ff:ff:ff
    inet **10.11.12.2/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe0b:c02/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

现在 Docker 也在为桥接分配 IP 地址时跟踪 IP 分配。IP 地址管理是 Docker 在容器网络空间提供的一个重要价值。将 IP 地址映射到容器并自行管理将是一项重大工作。

最后一部分将是处理容器的 NAT 配置。由于`10.11.12.0/24`空间不可路由，我们需要隐藏或伪装容器的 IP 地址在 Docker 主机上的物理接口后面。幸运的是，只要 Docker 为您管理桥，Docker 仍然会负责制定适当的 netfilter 规则。我们可以通过检查 netfilter 规则集来确保这一点：

```
user@docker1:~$ sudo iptables -t nat -L -n
…<Additional output removed for brevity>…
Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
MASQUERADE  all  --  10.11.12.0/24        0.0.0.0/0
…<Additional output removed for brevity>…
Chain DOCKER (2 references)
target     prot opt source               destination
RETURN     all  --  0.0.0.0/0            0.0.0.0/0
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:32768 to:10.11.12.2:80

```

此外，由于我们使用`-P`标志在容器上暴露端口，入站 NAT 也已分配。我们还可以在相同的输出中看到这个 NAT 转换。总之，只要您使用的是 Linux 桥，Docker 将像使用`docker0`桥一样为您处理整个配置。

# 使用 OVS 桥

对于寻找额外功能的用户来说，OpenVSwitch（OVS）正在成为本地 Linux 桥的流行替代品。OVS 在略微更高的复杂性的代价下，为 Linux 桥提供了显著的增强。例如，OVS 桥不能直接由我们到目前为止一直在使用的`iproute2`工具集进行管理，而是需要自己的命令行管理工具。然而，如果您正在寻找在 Linux 桥上不存在的功能，OVS 很可能是您的最佳选择。Docker 不能本地管理 OVS 桥，因此使用 OVS 桥需要手动建立桥和容器之间的连接。也就是说，我们不能只是告诉 Docker 服务使用 OVS 桥而不是默认的`docker0`桥。在本教程中，我们将展示如何安装、配置和直接连接容器到 OVS 桥，以取代标准的`docker0`桥。

## 准备工作

在本教程中，我们将演示在单个 Docker 主机上的配置。假设该主机已安装了 Docker，并且 Docker 处于默认配置。为了查看和操作网络设置，您需要确保已安装`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2 
```

为了对主机进行网络更改，您还需要 root 级别的访问权限。

## 如何做…

我们需要执行的第一步是在我们的 Docker 主机上安装 OVS。为了做到这一点，我们可以直接拉取 OVS 包：

```
user@docker1:~$ sudo apt-get install openvswitch-switch
```

如前所述，OVS 有自己的命令行工具集，其中一个工具被命名为`ovs-vsctl`，用于直接管理 OVS 桥。更具体地说，`ovs-vsctl`用于查看和操作 OVS 配置数据库。为了确保 OVS 正确安装，我们可以运行以下命令：

```
user@docker1:~$ sudo ovs-vsctl -V
ovs-vsctl (Open vSwitch) 2.5.0
Compiled Mar 10 2016 14:16:49
DB Schema 7.12.1
user@docker1:~$ 
```

这将返回 OVS 版本号，并验证我们与 OVS 的通信。我们接下来要做的是创建一个 OVS 桥。为了做到这一点，我们将再次使用`ovs-vsctl`命令行工具：

```
user@docker1:~$ sudo ovs-vsctl add-br ovs_bridge
```

这个命令将添加一个名为`ovs_bridge`的 OVS 桥。创建后，我们可以像查看任何其他网络接口一样查看桥接口：

```
user@docker1:~$ ip link show dev ovs_bridge
6: ovs_bridge: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1
    link/ether b6:45:81:aa:7c:47 brd ff:ff:ff:ff:ff:ff
user@docker1:~$ 
```

但是，要查看任何特定于桥的信息，我们将再次需要依赖`ocs-vsctl`命令行工具。我们可以使用`show`子命令查看有关桥的信息：

```
user@docker1:~$ sudo ovs-vsctl show
0f2ced94-aca2-4e61-a844-fd6da6b2ce38
    Bridge ovs_bridge
        Port ovs_bridge
            Interface ovs_bridge
                type: internal
    ovs_version: "2.5.0"
user@docker1:~$ 
```

为 OVS 桥分配 IP 地址并更改其状态可以再次使用更熟悉的`iproute2`工具完成：

```
user@docker1:~$ sudo ip addr add dev ovs_bridge 10.11.12.1/24
user@docker1:~$ sudo ip link set dev ovs_bridge up
```

一旦启动，接口就像任何其他桥接口一样。我们可以看到 IP 接口已经启动，本地主机可以直接访问它：

```
user@docker1:~$ ip addr show dev ovs_bridge
6: ovs_bridge: <BROADCAST,MULTICAST**,UP,LOWER_UP**> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1
    link/ether b6:45:81:aa:7c:47 brd ff:ff:ff:ff:ff:ff
    inet **10.11.12.1/24** scope global ovs_bridge
       valid_lft forever preferred_lft forever
    inet6 fe80::b445:81ff:feaa:7c47/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$ 
user@docker1:~$ ping 10.11.12.1 -c 2
PING 10.11.12.1 (10.11.12.1) 56(84) bytes of data.
64 bytes from 10.11.12.1: icmp_seq=1 ttl=64 time=0.036 ms
64 bytes from 10.11.12.1: icmp_seq=2 ttl=64 time=0.025 ms
--- 10.11.12.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.025/0.030/0.036/0.007 ms
user@docker1:~$
```

我们接下来要做的是创建我们将用来连接容器到 OVS 桥的 VETH 对：

```
user@docker1:~$ sudo ip link add ovs_end1 type veth \
peer name container_end1
```

创建后，我们需要将 VETH 对的 OVS 端添加到 OVS 桥上。这是 OVS 与标准 Linux 桥有很大区别的地方之一。每个连接到 OVS 的都是以端口的形式。这比 Linux 桥提供的更像是物理交换机。再次强调，因为我们直接与 OVS 桥交互，我们需要使用`ovs-vsctl`命令行工具：

```
user@docker1:~$ sudo ovs-vsctl add-port ovs_bridge ovs_end1
```

添加后，我们可以查询 OVS 以查看所有桥接口的端口：

```
user@docker1:~$ sudo ovs-vsctl list-ports ovs_bridge
ovs_end1
user@docker1:~$
```

如果您检查定义的接口，您会看到 VETH 对的 OVS 端将`ovs-system`列为其主机：

```
user@docker1:~$ **ip link show dev ovs_end1
8: **ovs_end1@container_end1**: <BROADCAST,MULTICAST> mtu 1500 qdisc noop **master ovs-system** state DOWN mode DEFAULT group default qlen 1000
    link/ether 56:e0:12:94:c5:43 brd ff:ff:ff:ff:ff:ff
user@docker1:~$
```

不要深入细节，这是预期的。`ovs-system`接口代表 OVS 数据路径。现在，只需知道这是预期的行为即可。

现在 OVS 端已经完成，我们需要专注于容器端。这里的第一步将是启动一个没有任何网络配置的容器。接下来，我们将按照之前的步骤手动连接容器命名空间到 VETH 对的另一端：

+   启动容器：

```
docker run --name web1 --net=none -d jonlangemak/web_server_1
```

+   查找容器的网络命名空间：

```
docker inspect web1 | grep SandboxKey
"SandboxKey": "/var/run/docker/netns/54b7dfc2e422"
```

+   将 VETH 对的容器端移入该命名空间：

```
sudo ip link set container_end1 netns 54b7dfc2e422
```

+   将 VETH 接口重命名为`eth0`：

```
sudo ip netns exec 54b7dfc2e422 ip link set dev \
container_end1 name eth0
```

+   将`eth0`接口的 IP 地址设置为该子网中的有效 IP：

```
sudo ip netns exec 54b7dfc2e422 ip addr add \
10.11.12.99/24 dev eth0
```

+   启动容器端的接口

```
sudo ip netns exec 54b7dfc2e422 ip link set dev eth0 up
```

+   启动 VETH 对的 OVS 端：

```
sudo ip link set dev ovs_end1 up
```

此时，容器已成功连接到 OVS，并可以通过主机访问：

```
user@docker1:~$ ping 10.11.12.99 -c 2
PING 10.11.12.99 (10.11.12.99) 56(84) bytes of data.
64 bytes from 10.11.12.99: icmp_seq=1 ttl=64 time=0.469 ms
64 bytes from 10.11.12.99: icmp_seq=2 ttl=64 time=0.028 ms
--- 10.11.12.99 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.028/0.248/0.469/0.221 ms
user@docker1:~$
```

如果我们想更深入地了解 OVS，可以使用以下命令查看交换机的 MAC 地址表：

```
user@docker1:~$ sudo ovs-appctl fdb/show ovs_bridge
port  VLAN  MAC                Age
LOCAL     0  b6:45:81:aa:7c:47    7
            1     0  b2:7e:e8:42:58:39    7
user@docker1:~$
```

注意它在`port 1`上学到的 MAC 地址。但`port 1`是什么？要查看给定 OVS 的所有端口，可以使用以下命令：

```
user@docker1:~$ sudo ovs-dpctl show
system@ovs-system:
        lookups: hit:13 missed:11 lost:0
        flows: 0
        masks: hit:49 total:1 hit/pkt:2.04
        port 0: ovs-system (internal)
            port 1: ovs_bridge (internal)
        port 2: ovs_end1 
user@docker1:~$
```

在这里，我们可以看到`port 1`是我们预配的 OVS 桥，我们将 VETH 对的 OVS 端连接到了这里。

正如我们所看到的，连接到 OVS 所需的工作量可能很大。幸运的是，有一些很棒的工具可以帮助我们简化这个过程。其中一个比较显著的工具是由 Jérôme Petazzoni 开发的，名为**Pipework**。它可以在 GitHub 上找到，网址如下：

[`github.com/jpetazzo/pipework`](https://github.com/jpetazzo/pipework)

如果我们使用 Pipework 来连接到 OVS，并假设桥已经创建，我们可以将连接容器到桥所需的步骤从`6`减少到`1`。

要使用 Pipework，必须先从 GitHub 上下载它。可以使用 Git 客户端完成这一步：

```
user@docker1:~$ git clone https://github.com/jpetazzo/pipework
…<Additional output removed for brevity>… 
user@docker1:~$ cd pipework/
user@docker1:~/pipework$ ls
docker-compose.yml  doctoc  LICENSE  pipework  pipework**.spec  README.md
user@docker1:~/pipework$
```

为了演示使用 Pipework，让我们启动一个名为`web2`的新容器，没有任何网络配置：

```
user@docker1:~$ docker run --name web2 --net=none -d \
jonlangemak/web_server_2
985384d0b0cd1a48cb04de1a31b84f402197b2faade87d073e6acdc62cf29151
user@docker1:~$
```

现在，我们要做的就是将这个容器连接到我们现有的 OVS 桥上，只需运行以下命令，指定 OVS 桥的名称、容器名称和我们希望分配给容器的 IP 地址：

```
user@docker1:~/pipework$ sudo ./pipework **ovs_bridge \
web2 10.11.12.100/24
Warning: arping not found; interface may not be immediately reachable
user@docker1:~/pipework$
```

Pipework 会为我们处理所有的工作，包括将容器名称解析为网络命名空间，创建一个唯一的 VETH 对，正确地将 VETH 对的端点放在容器和指定的桥上，并为容器分配一个 IP 地址。

Pipework 还可以帮助我们在运行时为容器添加额外的接口。考虑到我们以`none`网络模式启动了这个容器，容器目前只有根据第一个 Pipework 配置连接到 OVS。然而，我们也可以使用 Pipework 将连接添加回`docker0`桥：

```
user@docker1:~/pipework$ sudo ./pipework docker0 -i eth0 web2 \
172.17.0.100/16@172.17.0.1
```

语法类似，但在这种情况下，我们指定了要使用的接口名称（`eth0`），并为`172.17.0.1`的接口添加了一个网关。这将允许容器使用`docker0`桥作为默认网关，并且允许它使用默认的 Docker 伪装规则进行出站访问。我们可以使用一些`docker exec`命令验证配置是否存在于容器中：

```
user@docker1:~/pipework$ **docker exec web2 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
9: **eth1**@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP qlen 1000
    link/ether da:40:35:ec:c2:45 brd ff:ff:ff:ff:ff:ff
    inet **10.11.12.100/24** scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::d840:35ff:feec:c245/64 scope link
       valid_lft forever preferred_lft forever
11: **eth0**@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP qlen 1000
    link/ether 2a:d0:32:ef:e1:07 brd ff:ff:ff:ff:ff:ff
    inet **172.17.0.100/16** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::28d0:32ff:feef:e107/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~/pipework$ **docker exec web2 ip route
default via 172.17.0.1 dev eth0
10.11.12.0/24 dev eth1  proto kernel  scope link  src 10.11.12.100
172.17.0.0/16 dev eth0  proto kernel  scope link  src 172.17.0.100
user@docker1:~/pipework$ 
```

因此，虽然 Pipework 可以使许多这些手动工作变得更容易，但您应该始终查看 Docker 是否有本机手段来提供您正在寻找的网络连接。让 Docker 管理您的容器网络连接具有许多好处，包括自动 IPAM 分配和用于入站和出站连接的 netfilter 配置。许多这些非本机配置已经有第三方 Docker 网络插件在进行中，这将允许您无缝地利用它们从 Docker 中。

# 使用 OVS 桥连接 Docker 主机

上一个教程展示了我们如何可以使用 OVS 来代替标准的 Linux 桥。这本身并不是很有趣，因为它并没有比标准的 Linux 桥做更多的事情。可能有趣的是，与您的 Docker 容器一起使用 OVS 的一些更高级的功能。例如，一旦创建了 OVS 桥，就可以相当轻松地在两个不同的 Docker 主机之间配置 GRE 隧道。这将允许连接到任一 Docker 主机的任何容器直接彼此通信。在这个教程中，我们将讨论使用 OVS 提供的 GRE 隧道连接两个 Docker 主机所需的配置。

### 注意

再次强调，这个教程仅用于举例说明。这种行为已经得到 Docker 的用户定义的覆盖网络类型的支持。如果出于某种原因，您需要使用 GRE 而不是 VXLAN，这可能是一个合适的替代方案。与往常一样，在开始自定义之前，请确保您使用任何 Docker 本机网络构造。这将为您节省很多麻烦！

## 准备工作

在这个教程中，我们将演示在两个 Docker 主机上的配置。这些主机需要能够在网络上相互通信。假设主机已经安装了 Docker，并且 Docker 处于默认配置。为了查看和操作网络设置，您需要确保已安装了`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2 
```

为了对主机进行网络更改，您还需要 root 级别的访问权限。

## 如何做…

为了本教程的目的，我们将假设在本例中使用的两台主机上有一个基本配置。也就是说，每台主机只安装了 Docker，并且其配置与默认配置相同。

我们将使用的拓扑将如下图所示。两个不同子网上的两个 Docker 主机：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_05.jpg)

此配置的目标是在每台主机上配置 OVS，将容器连接到 OVS，然后将两个 OVS 交换机连接在一起，以允许通过 GRE 进行 OVS 之间的直接通信。我们将在每台主机上按照以下步骤来实现这一目标：

1.  安装 OVS。

1.  添加一个名为`ovs_bridge`的 OVS 桥。

1.  为该桥分配一个 IP 地址。

1.  运行一个网络模式设置为`none`的容器。

1.  使用 Pipework 将该容器连接到 OVS 桥（假设每台主机上都安装了 Pipework。如果没有，请参考之前的安装步骤）。

1.  使用 OVS 在另一台主机上建立一个 GRE 隧道。

让我们从第一台主机`docker1`开始配置：

```
user@docker1:~$ sudo apt-get install openvswitch-switch
…<Additional output removed for brevity>… 
Setting up openvswitch-switch (2.0.2-0ubuntu0.14.04.3) ...
openvswitch-switch start/running
user@docker1:~$
user@docker1:~$ sudo ovs-vsctl add-br ovs_bridge
user@docker1:~$ sudo ip addr add dev ovs_bridge 10.11.12.1/24
user@docker1:~$ sudo ip link set dev ovs_bridge up
user@docker1:~$
user@docker1:~$ docker run --name web1 --net=none -dP \
jonlangemak/web_server_1
5e6b335b12638a7efecae650bc8e001233842bb97ab07b32a9e45d99bdffe468
user@docker1:~$
user@docker1:~$ cd pipework
user@docker1:~/pipework$ sudo ./pipework ovs_bridge \
web1 10.11.12.100/24
Warning: arping not found; interface may not be immediately reachable
user@docker1:~/pipework$
```

此时，您应该有一个正在运行的容器。您应该能够从本地 Docker 主机访问该容器：

```
user@docker1:~$ curl http://**10.11.12.100
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

现在，让我们在第二台主机`docker3`上执行类似的配置：

```
user@docker3:~$ sudo apt-get install openvswitch-switch
…<Additional output removed for brevity>… 
Setting up openvswitch-switch (2.0.2-0ubuntu0.14.04.3) ...
openvswitch-switch start/running
user@docker3:~$
user@docker3:~$ sudo ovs-vsctl add-br ovs_bridge
user@docker3:~$ sudo ip addr add dev ovs_bridge 10.11.12.2/24
user@docker3:~$ sudo ip link set dev ovs_bridge up
user@docker3:~$
user@docker3:~$ docker run --name web2 --net=none -dP \
jonlangemak/web_server_2
155aff2847e27c534203b1ae01894b0b159d09573baf9844cc6f5c5820803278
user@docker3:~$
user@docker3:~$ cd pipework
user@docker3:~/pipework$ sudo ./pipework ovs_bridge web2 10.11.12.200/24
Warning: arping not found; interface may not be immediately reachable
user@docker3:~/pipework$
```

这样就完成了对第二台主机的配置。确保您可以连接到本地主机上运行的`web2`容器：

```
user@docker3:~$ curl http://**10.11.12.200
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker3:~$
```

此时，我们的拓扑看起来是这样的：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_06.jpg)

如果我们的目标是允许容器`web1`直接与容器`web2`通信，我们将有两个选项。首先，由于 Docker 不知道 OVS 交换机，它不会尝试根据连接到它的容器应用 netfilter 规则。也就是说，通过正确的路由配置，这两个容器可以直接路由到彼此。然而，即使在这个简单的例子中，这也需要大量的配置。由于我们在两台主机之间共享一个公共子网（就像 Docker 在默认模式下一样），配置变得不那么简单。为了使其工作，您需要做以下几件事：

+   在每个容器中添加路由，告诉它们另一个容器的特定`/32`路由位于子网之外。这是因为每个容器都认为整个`10.11.12.0/24`网络是本地的，因为它们都在该网络上有一个接口。您需要一个比`/24`更具体（更小）的前缀来强制容器路由以到达目的地。

+   在每个 Docker 主机上添加路由，告诉它们另一个容器的特定`/32`路由位于子网之外。同样，这是因为每个主机都认为整个`10.11.12.0/24`网络是本地的，因为它们都在该网络上有一个接口。您需要一个比`/24`更具体（更小）的前缀来强制主机路由以到达目的地。

+   在多层交换机上添加路由，以便它知道`10.11.12.100`可以通过`10.10.10.101`（`docker1`）到达，`10.11.12.200`可以通过`192.168.50.101`（`docker3`）到达。

现在想象一下，如果你正在处理一个真实的网络，并且必须在路径上的每个设备上添加这些路由。第二个，也是更好的选择是在两个 OVS 桥之间创建隧道。这将阻止网络看到`10.11.12.0/24`的流量，这意味着它不需要知道如何路由它：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_07.jpg)

幸运的是，对于我们来说，这个配置在 OVS 上很容易实现。我们只需添加另一个类型为 GRE 的 OVS 端口，并指定另一个 Docker 主机作为远程隧道目的地。

在主机`docker1`上，按以下方式构建 GRE 隧道：

```
user@docker1:~$ sudo ovs-vsctl add-port ovs_bridge ovs_gre \
-- set interface ovs_gre type=gre options:remote_ip=192.168.50.101
```

在主机`docker3`上，按以下方式构建 GRE 隧道：

```
user@docker3:~$ sudo ovs-vsctl add-port ovs_bridge ovs_gre \
-- set interface ovs_gre type=gre options:remote_ip=10.10.10.101
```

此时，两个容器应该能够直接相互通信：

```
user@**docker1**:~$ docker exec -it **web1** curl http://**10.11.12.200
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$

user@**docker3**:~$ docker exec -it **web2** curl http://**10.11.12.100
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker3:~$
```

作为最终证明这是通过 GRE 隧道传输的，我们可以在主机的一个物理接口上运行`tcpdump`，同时在容器之间进行 ping 测试：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_08.jpg)

# OVS 和 Docker 一起

到目前为止，这些配方展示了手动配置 Docker 网络时可能出现的几种可能性。尽管这些都是可能的解决方案，但它们都需要大量的手动干预和配置，并且在它们当前的形式下不容易消化。如果我们以前的配方作为例子，有一些显著的缺点：

+   您负责跟踪容器上的 IP 分配，增加了将不同容器分配冲突的风险

+   没有动态端口映射或固有的出站伪装来促进容器与网络的通信。

+   虽然我们使用了 Pipework 来减轻配置负担，但仍然需要进行相当多的手动配置才能将容器连接到 OVS 桥接器。

+   大多数配置默认情况下不会在主机重启后持久化。

话虽如此，根据我们迄今所学到的知识，我们可以利用 OVS 的 GRE 功能的另一种方式，同时仍然使用 Docker 来管理容器网络。在这个示例中，我们将回顾这个解决方案，并描述如何使其成为一个更持久的解决方案，可以在主机重启后仍然存在。

### 注意

再次强调，这个示例仅用于举例说明。这种行为已经得到 Docker 的用户定义的覆盖网络类型的支持。如果出于某种原因，您需要使用 GRE 而不是 VXLAN，这可能是一个合适的替代方案。与以往一样，在开始自定义之前，请确保使用任何 Docker 原生网络构造。这将为您节省很多麻烦！

## 准备工作

在这个示例中，我们将演示在两个 Docker 主机上的配置。这些主机需要能够通过网络相互通信。假设主机已安装了 Docker，并且 Docker 处于默认配置状态。为了查看和操作网络设置，您需要确保已安装了`iproute2`工具集。如果系统上没有安装，可以使用以下命令进行安装：

```
sudo apt-get install iproute2 
```

为了对主机进行网络更改，您还需要具有根级别的访问权限。

## 如何做…

受到上一个示例的启发，我们的新拓扑将看起来类似，但有一个重要的区别：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_04_09.jpg)

您会注意到每个主机现在都有一个名为`newbridge`的 Linux 桥。我们将告诉 Docker 使用这个桥而不是`docker0`桥来进行默认容器连接。这意味着我们只是使用 OVS 的 GRE 功能，将其变成`newbridge`的从属。使用 Linux 桥进行容器连接意味着 Docker 能够为我们进行 IPAM，并处理入站和出站 netfilter 规则。使用除`docker0`之外的桥接器更多是与配置有关，而不是可用性，我们很快就会看到。

我们将再次从头开始配置，假设每个主机只安装了 Docker 的默认配置。我们要做的第一件事是配置每个主机上将要使用的两个桥接。我们将从主机`docker1`开始：

```
user@docker1:~$ sudo apt-get install openvswitch-switch
…<Additional output removed for brevity>…
Setting up openvswitch-switch (2.0.2-0ubuntu0.14.04.3) ...
openvswitch-switch start/running
user@docker1:~$
user@docker1:~$ sudo ovs-vsctl add-br ovs_bridge
user@docker1:~$ sudo ip link set dev ovs_bridge up
user@docker1:~$
user@docker1:~$ sudo ip link add newbridge type bridge
user@docker1:~$ sudo ip link set newbridge up
user@docker1:~$ sudo ip address add 10.11.12.1/24 dev newbridge
user@docker1:~$ sudo ip link set newbridge up
```

此时，我们在主机上配置了 OVS 桥和标准 Linux 桥。为了完成桥接配置，我们需要在 OVS 桥上创建 GRE 接口，然后将 OVS 桥绑定到 Linux 桥上。

```
user@docker1:~$ sudo ovs-vsctl add-port ovs_bridge ovs_gre \
-- set interface ovs_gre type=gre options:remote_ip=192.168.50.101
user@docker1:~$
user@docker1:~$ sudo ip link set ovs_bridge master newbridge
```

现在桥接配置已经完成，我们可以告诉 Docker 使用`newbridge`作为其默认桥接。我们通过编辑 systemd drop-in 文件并添加以下选项来实现这一点：

```
ExecStart=/usr/bin/dockerd --bridge=newbridge --fixed-cidr=10.11.12.128/26
```

请注意，除了告诉 Docker 使用不同的桥接之外，我还告诉 Docker 只从`10.11.12.128/26`分配容器 IP 地址。当我们配置第二个 Docker 主机（`docker3`）时，我们将告诉 Docker 只从`10.11.12.192/26`分配容器 IP 地址。这是一个技巧，但它可以防止两个 Docker 主机在不知道对方已经分配了什么 IP 地址的情况下出现重叠的 IP 地址问题。

### 注意

第三章，“用户定义网络”表明，本地覆盖网络通过跟踪参与覆盖网络的所有主机之间的 IP 分配来解决了这个问题。

为了让 Docker 使用新的选项，我们需要重新加载系统配置并重新启动 Docker 服务：

```
user@docker1:~$ sudo systemctl daemon-reload
user@docker1:~$ sudo systemctl restart docker
```

最后，启动一个容器而不指定网络模式：

```
user@docker1:~$ **docker run --name web1 -d -P jonlangemak/web_server_1
82c75625f8e5436164e40cf4c453ed787eab102d3d12cf23c86d46be48673f66
user@docker1:~$
user@docker1:~$ docker exec **web1 ip addr
…<Additional output removed for brevity>…
8: **eth0**@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:0a:0b:0c:80 brd ff:ff:ff:ff:ff:ff
    inet **10.11.12.128/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe0b:c80/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

正如预期的那样，我们运行的第一个容器获得了`10.11.12.128/26`网络中的第一个可用 IP 地址。现在，让我们继续配置第二个主机`docker3`：

```
user@docker3:~$ sudo apt-get install openvswitch-switch
…<Additional output removed for brevity>…
Setting up openvswitch-switch (2.0.2-0ubuntu0.14.04.3) ...
openvswitch-switch start/running
user@docker3:~$
user@docker3:~$ sudo ovs-vsctl add-br ovs_bridge
user@docker3:~$ sudo ip link set dev ovs_bridge up
user@docker3:~$
user@docker3:~$ sudo ip link add newbridge type bridge
user@docker3:~$ sudo ip link set newbridge up
user@docker3:~$ sudo ip address add 10.11.12.2/24 dev newbridge
user@docker3:~$ sudo ip link set newbridge up
user@docker3:~$
user@docker3:~$ sudo ip link set ovs_bridge master newbridge
user@docker3:~$ sudo ovs-vsctl add-port ovs_bridge ovs_gre \
-- set interface ovs_gre type=gre options:remote_ip=10.10.10.101
user@docker3:~$
```

在这个主机上，通过编辑 systemd drop-in 文件，告诉 Docker 使用以下选项：

```
ExecStart=/usr/bin/dockerd --bridge=newbridge --fixed-cidr=10.11.12.192/26
```

重新加载系统配置并重新启动 Docker 服务：

```
user@docker3:~$ sudo systemctl daemon-reload
user@docker3:~$ sudo systemctl restart docker
```

现在在这个主机上启动一个容器：

```
user@docker3:~$ **docker run --name web2 -d -P jonlangemak/web_server_2
eb2b26ee95580a42568051505d4706556f6c230240a9c6108ddb29b6faed9949
user@docker3:~$
user@docker3:~$ docker exec **web2 ip addr
…<Additional output removed for brevity>…
9: **eth0**@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:0a:0b:0c:c0 brd ff:ff:ff:ff:ff:ff
    inet **10.11.12.192/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe0b:cc0/64 scope link
       valid_lft forever preferred_lft forever
user@docker3:~$
```

此时，每个容器应该能够通过 GRE 隧道相互通信：

```
user@docker3:~$ docker exec -it **web2** curl http://**10.11.12.128
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker3:~$
```

此外，每个主机仍然可以通过 IPAM、发布端口和容器伪装来获得 Docker 提供的所有好处，以便进行出站访问。

我们可以验证端口发布：

```
user@docker1:~$ docker port **web1
80/tcp -> 0.0.0.0:**32768
user@docker1:~$ curl http://**localhost:32768
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

我们可以通过默认的 Docker 伪装规则验证出站访问：

```
user@docker1:~$ docker exec -it web1 ping **4.2.2.2** -c 2
PING 4.2.2.2 (4.2.2.2): 48 data bytes
56 bytes from 4.2.2.2: icmp_seq=0 ttl=50 time=30.797 ms
56 bytes from 4.2.2.2: icmp_seq=1 ttl=50 time=31.399 ms
--- 4.2.2.2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 30.797/31.098/31.399/0.301 ms
user@docker1:~$
```

这种设置的最后一个优点是我们可以很容易地使其在主机重启后保持。唯一需要重新创建的配置将是 Linux 桥接`newbridge`和`newbridge`与 OVS 桥接之间的连接的配置。为了使其持久化，我们可以在每个主机的网络配置文件(`/etc/network/interfaces`)中添加以下配置。

### 注意

除非在主机上安装了桥接实用程序包，否则 Ubuntu 不会处理与桥接相关的接口文件中的配置。

```
sudo apt-get install bridge-utils
```

+   主机`docker1`：

```
auto newbridge
iface newbridge inet static
  address 10.11.12.1
  netmask 255.255.255.0
  bridge_ports ovs_bridge
```

+   主机`docker3`：

```
auto newbridge
iface newbridge inet static
  address 10.11.12.2
  netmask 255.255.255.0
  bridge_ports ovs_bridge
```

将`newbridge`配置信息放入网络启动脚本中，我们完成了两项任务。首先，在实际 Docker 服务启动之前，我们创建了 Docker 期望使用的桥接。如果没有这个，Docker 服务将无法启动，因为它找不到这个桥接。其次，这个配置允许我们通过指定桥接的`bridge_ports`在创建桥接的同时将 OVS 绑定到`newbridge`上。因为这个配置之前是通过`ip link`命令手动完成的，所以绑定不会在系统重启后保持。
