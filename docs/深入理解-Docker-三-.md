# 深入理解 Docker（三）

> 原文：[`zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22`](https://zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：Docker 网络

总是网络的问题！

每当出现基础设施问题时，我们总是责怪网络。部分原因是网络处于一切的中心位置 —— 没有网络，就没有应用程序！

在 Docker 早期，网络很难 —— 真的很难！如今，这几乎是一种愉悦 ;-)

在本章中，我们将看一下 Docker 网络的基础知识。像容器网络模型（CNM）和`libnetwork`这样的东西。我们还将动手构建一些网络。

像往常一样，我们将把本章分为三个部分：

+   TLDR

+   深入挖掘

+   命令

### Docker 网络 - TLDR

Docker 在容器内运行应用程序，这些应用程序需要在许多不同的网络上进行通信。这意味着 Docker 需要强大的网络能力。

幸运的是，Docker 为容器间网络提供了解决方案，以及连接到现有网络和 VLAN 的解决方案。后者对于需要与外部系统（如 VM 和物理系统）上的功能和服务进行通信的容器化应用程序非常重要。

Docker 网络基于一个名为容器网络模型（CNM）的开源可插拔架构。`libnetwork`是 Docker 对 CNM 的真实实现，它提供了 Docker 的所有核心网络功能。驱动程序插入到`libnetwork`中以提供特定的网络拓扑。

为了创建一个顺畅的开箱即用体验，Docker 附带了一组处理最常见网络需求的本地驱动程序。这些包括单主机桥接网络、多主机覆盖网络以及插入到现有 VLAN 的选项。生态系统合作伙伴通过提供自己的驱动程序进一步扩展了这些功能。

最后但并非最不重要的是，`libnetwork`提供了本地服务发现和基本容器负载均衡解决方案。

这就是大局。让我们进入细节。

### Docker 网络 - 深入挖掘

我们将按照以下方式组织本章节的内容：

+   理论

+   单主机桥接网络

+   多主机覆盖网络

+   连接到现有网络

+   服务发现

+   入口网络

#### 理论

在最高层次上，Docker 网络包括三个主要组件：

+   容器网络模型（CNM）

+   `libnetwork`

+   驱动程序

CNM 是设计规范。它概述了 Docker 网络的基本构建模块。

`libenetwork`是 CNM 的真实实现，被 Docker 使用。它是用 Go 编写的，并实现了 CNM 中概述的核心组件。

驱动程序通过实现特定的网络拓扑，如基于 VXLAN 的覆盖网络，来扩展模型。

图 11.1 显示了它们在非常高的层次上是如何组合在一起的。

![图 11.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-1.png)

图 11.1

让我们更仔细地看一下每一个。

##### 容器网络模型（CNM）

一切都始于设计！

Docker 网络的设计指南是 CNM。它概述了 Docker 网络的基本构建块，您可以在这里阅读完整的规范：https://github.com/docker/libnetwork/blob/master/docs/design.md

我建议阅读整个规范，但在高层次上，它定义了三个构建块：

+   沙盒

+   端点

+   网络

沙盒是一个隔离的网络堆栈。它包括以太网接口、端口、路由表和 DNS 配置。

端点是虚拟网络接口（例如`veth`）。与普通网络接口一样，它们负责建立连接。在 CNM 的情况下，端点的工作是将沙盒连接到网络。

网络是 802.1d 桥的软件实现（更常见的称为交换机）。因此，它们将需要通信的一组端点组合在一起，并进行隔离。

图 11.2 显示了这三个组件以及它们的连接方式。

![图 11.2 容器网络模型（CNM）](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-2.png)

图 11.2 容器网络模型（CNM）

在 Docker 环境中调度的原子单位是容器，正如其名称所示，容器网络模型的目的是为容器提供网络。图 11.3 显示了 CNM 组件如何与容器相关联——沙盒被放置在容器内，以为它们提供网络连接。

![图 11.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-3.png)

图 11.3

容器 A 有一个接口（端点），连接到网络 A。容器 B 有两个接口（端点），连接到网络 A 和网络 B。这些容器将能够通信，因为它们都连接到网络 A。然而，容器 B 中的两个端点在没有第 3 层路由器的帮助下无法相互通信。

还要了解的重要一点是，端点的行为类似于常规网络适配器，这意味着它们只能连接到单个网络。因此，如果一个容器需要连接到多个网络，它将需要多个端点。

图 11.4 再次扩展了图表，这次添加了一个 Docker 主机。虽然容器 A 和容器 B 在同一主机上运行，但它们的网络堆栈在操作系统级别通过沙盒完全隔离。 

![图 11.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-4.png)

图 11.4

##### Libnetwork

CNM 是设计文档，`libnetwork`是规范实现。它是开源的，用 Go 编写，跨平台（Linux 和 Windows），并被 Docker 使用。

在 Docker 早期，所有的网络代码都存在于守护进程中。这是一场噩梦——守护进程变得臃肿，而且它没有遵循构建模块化工具的 Unix 原则，这些工具可以独立工作，但也可以轻松地组合到其他项目中。因此，所有的核心 Docker 网络代码都被剥离出来，重构为一个名为`libnetwork`的外部库。如今，所有的核心 Docker 网络代码都存在于`libnetwork`中。

正如你所期望的，它实现了 CNM 中定义的所有三个组件。它还实现了本地*服务发现*、*基于入口的容器负载均衡*，以及网络控制平面和管理平面功能。

##### 驱动程序

如果`libnetwork`实现了控制平面和管理平面功能，那么驱动程序就实现了数据平面。例如，连接和隔离都由驱动程序处理。网络对象的实际创建也是如此。这种关系如图 11.5 所示。

![图 11.5](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-5.png)

图 11.5

Docker 附带了几个内置驱动程序，称为本地驱动程序或*本地驱动程序*。在 Linux 上，它们包括；`bridge`、`overlay`和`macvlan`。在 Windows 上，它们包括；`nat`、`overlay`、`transparent`和`l2bridge`。我们将在本章后面看到如何使用其中一些。

第三方也可以编写 Docker 网络驱动程序。这些被称为*远程驱动程序*，例如`calico`、`contiv`、`kuryr`和`weave`。

每个驱动程序负责在其负责的网络上实际创建和管理所有资源。例如，名为“prod-fe-cuda”的覆盖网络将由`overlay`驱动程序拥有和管理。这意味着`overlay`驱动程序将被调用来创建、管理和删除该网络上的所有资源。

为了满足复杂高度流动的环境的需求，`libnetwork`允许多个网络驱动程序同时处于活动状态。这意味着您的 Docker 环境可以支持各种异构网络。

#### 单主机桥接网络

最简单的 Docker 网络类型是单主机桥接网络。

名称告诉我们两件事：

+   **单主机**告诉我们它只存在于单个 Docker 主机上，并且只能连接位于同一主机上的容器。

+   **桥接**告诉我们它是 802.1d 桥接（第 2 层交换）的实现。

在 Linux 上，Docker 使用内置的`bridge`驱动程序创建单主机桥接网络，而在 Windows 上，Docker 使用内置的`nat`驱动程序创建它们。就所有目的而言，它们的工作方式都是相同的。

图 11.6 显示了两个具有相同本地桥接网络“mynet”的 Docker 主机。尽管网络是相同的，但它们是独立的隔离网络。这意味着图片中的容器无法直接通信，因为它们位于不同的网络上。

![图 11.6](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-6.png)

图 11.6

每个 Docker 主机都会获得一个默认的单主机桥接网络。在 Linux 上，它被称为“bridge”，在 Windows 上被称为“nat”（是的，这些名称与用于创建它们的驱动程序的名称相同）。默认情况下，这是所有新容器将连接到的网络，除非您在命令行上使用`--network`标志进行覆盖。

以下清单显示了在新安装的 Linux 和 Windows Docker 主机上运行`docker network ls`命令的输出。输出被修剪，只显示每个主机上的默认网络。请注意，网络的名称与用于创建它的驱动程序的名称相同——这是巧合。

```
//Linux
$ docker network ls
NETWORK ID        NAME        DRIVER        SCOPE
333e184cd343      bridge      bridge        local

//Windows
> docker network ls
NETWORK ID        NAME        DRIVER        SCOPE
095d4090fa32      nat         nat           local 
```

`docker network inspect`命令是一个极好的信息宝库！如果您对底层细节感兴趣，我强烈建议阅读它的输出。

```
docker network inspect bridge
[
    {
        "Name": "bridge",     << Will be nat on Windows
        "Id": "333e184...d9e55",
        "Created": "2018-01-15T20:43:02.566345779Z",
        "Scope": "local",
        "Driver": "bridge",   << Will be nat on Windows
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
        "Attachable": false,
        "Ingress": false,
        "ConfigFrom": {
            "Network": ""
        },
        <Snip>
    }
] 
```

在 Linux 主机上使用`bridge`驱动程序构建的 Docker 网络基于已存在于 Linux 内核中超过 15 年的经过艰苦打磨的*Linux 桥接*技术。这意味着它们具有高性能和极其稳定！这也意味着您可以使用标准的 Linux 实用程序来检查它们。例如。

```
$ ip link show docker0
`3`: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu `1500` qdisc...
    link/ether `02`:42:af:f9:eb:4f brd ff:ff:ff:ff:ff:ff 
```

`在所有基于 Linux 的 Docker 主机上，默认的“bridge”网络映射到内核中称为“**docker0**”的基础*Linux 桥接*。我们可以从`docker network inspect`的输出中看到这一点。

```
$ docker network inspect bridge `|` grep bridge.name
`"com.docker.network.bridge.name"`: `"docker0"`, 
```

Docker 默认“bridge”网络与 Linux 内核中的“docker0”桥接之间的关系如图 11.7 所示。

![图 11.7](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-7.png)

图 11.7

图 11.8 通过在顶部添加容器来扩展了图表，这些容器插入到“bridge”网络中。 “bridge”网络映射到主机内核中的“docker0”Linux 桥接，可以通过端口映射将其映射回主机上的以太网接口。

![图 11.8](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-8.png)

图 11.8

让我们使用`docker network create`命令创建一个名为“localnet”的新单主机桥接网络。

```
//Linux
$ docker network create -d bridge localnet

//Windows
> docker network create -d nat localnet 
```

新网络已创建，并将出现在任何未来的`docker network ls`命令的输出中。如果您使用的是 Linux，还将在内核中创建一个新的*Linux 桥接*。

让我们使用 Linux 的`brctl`工具来查看系统上当前的 Linux 桥接。您可能需要手动安装`brctl`二进制文件，使用`apt-get install bridge-utils`，或者您的 Linux 发行版的等效命令。

```
$ brctl show
bridge name       bridge id             STP enabled    interfaces
docker0           `8000`.0242aff9eb4f     no
br-20c2e8ae4bbb   `8000`.02429636237c     no 
```

输出显示了两个桥接。第一行是我们已经知道的“docker0”桥接。这与 Docker 中的默认“bridge”网络相关。第二个桥接（br-20c2e8ae4bbb）与新的`localnet` Docker 桥接网络相关。它们都没有启用生成树，并且都没有任何设备连接（`interfaces`列）。

此时，主机上的桥接配置如图 11.9 所示。

![图 11.9](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-9.png)

图 11.9

让我们创建一个新的容器，并将其连接到新的`localnet`桥接网络。如果您在 Windows 上跟随操作，应该将“`alpine sleep 1d`”替换为“`microsoft/powershell:nanoserver pwsh.exe -Command Start-Sleep 86400`”。

```
$ docker container run -d --name c1 `\`
  --network localnet `\`
  alpine sleep 1d 
```

这个容器现在将位于`localnet`网络上。您可以通过`docker network inspect`来确认。

```
$ docker network inspect localnet --format `'{{json .Containers}}'`
`{`
  `"4edcbd...842c3aa"`: `{`
    `"Name"`: `"c1"`,
    `"EndpointID"`: `"43a13b...3219b8c13"`,
    `"MacAddress"`: `"02:42:ac:14:00:02"`,
    `"IPv4Address"`: `"172.20.0.2/16"`,
    `"IPv6Address"`: `""`
    `}`
`}`, 
```

输出显示新的“c1”容器位于`localnet`桥接/网络地址转换网络上。

如果我们再次运行 Linux 的`brctl show`命令，我们将看到 c1 的接口连接到`br-20c2e8ae4bbb`桥接上。

```
$ brctl show
bridge name       bridge id           STP enabled     interfaces
br-20c2e8ae4bbb   `8000`.02429636237c   no              vethe792ac0
docker0           `8000`.0242aff9eb4f   no 
```

这在图 11.10 中显示。

![图 11.10](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-10.png)

图 11.10

如果我们将另一个新容器添加到相同的网络中，它应该能够通过名称 ping 通“c1”容器。这是因为所有新容器都已在嵌入式 Docker DNS 服务中注册，因此可以解析同一网络中所有其他容器的名称。

> **注意：** Linux 上的默认`bridge`网络不支持通过 Docker DNS 服务进行名称解析。所有其他*用户定义*的桥接网络都支持！

让我们来测试一下。

1.  创建一个名为“c2”的新交互式容器，并将其放在与“c1”相同的`localnet`网络中。

```
 //Linux
 $ docker container run -it --name c2 \
   --network localnet \
   alpine sh

 //Windows
 > docker container run -it --name c2 `
   --network localnet `
   microsoft/powershell:nanoserver 
```

您的终端将切换到“c2”容器中。

*从“c2”容器内部，通过名称 ping“c1”容器。

```
 > ping c1
 Pinging c1 [172.26.137.130] with 32 bytes of data:
 Reply from 172.26.137.130: bytes=32 time=1ms TTL=128
 Reply from 172.26.137.130: bytes=32 time=1ms TTL=128
 Control-C 
```

成功了！这是因为 c2 容器正在运行一个本地 DNS 解析器，它会将请求转发到内部 Docker DNS 服务器。该 DNS 服务器维护了所有使用`--name`或`--net-alias`标志启动的容器的映射。`

尝试在仍然登录到容器的情况下运行一些与网络相关的命令。这是了解 Docker 容器网络工作原理的好方法。以下片段显示了先前在“c2”Windows 容器内运行的`ipconfig`命令。您可以将此 IP 地址与`docker network inspect nat`输出中显示的 IP 地址进行匹配。

```
> ipconfig
Windows IP Configuration
Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::14d1:10c8:f3dc:2eb3%4
   IPv4 Address. . . . . . . . . . . : 172.26.135.0
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.26.128.1 
```

到目前为止，我们已经说过桥接网络上的容器只能与同一网络上的其他容器通信。但是，您可以使用*端口映射*来解决这个问题。

端口映射允许您将容器端口映射到 Docker 主机上的端口。命中配置端口的任何流量都将被重定向到容器。高级流程如图 1.11 所示

![图 11.11](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-11.png)

图 11.11

在图中，容器中运行的应用程序正在端口 80 上运行。这被映射到主机的`10.0.0.15`接口上的端口 5000。最终结果是所有命中主机`10.0.0.15:5000`的流量都被重定向到容器的端口 80。

让我们通过一个示例来演示将运行 Web 服务器的容器上的端口 80 映射到 Docker 主机上的端口 5000。该示例将在 Linux 上使用 NGINX。如果您在 Windows 上跟随操作，您需要用基于 Windows 的 Web 服务器镜像替换`nginx`。

1.  运行一个新的 Web 服务器容器，并将容器上的端口 80 映射到 Docker 主机上的端口 5000。

```
 $ docker container run -d --name web \
   --network localnet \
   --publish 5000:80 \
   nginx 
```

*验证端口映射。

```
 $ docker port web
 80/tcp -> 0.0.0.0:5000 
```

这表明容器中的端口 80 被映射到 Docker 主机上所有接口的端口 5000。*通过将 Web 浏览器指向 Docker 主机上的端口 5000 来测试配置。要完成此步骤，您需要知道 Docker 主机的 IP 或 DNS 名称。如果您使用的是 Windows 版 Docker 或 Mac 版 Docker，您可以使用`localhost`或`127.0.0.1`。![图 11.12](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-12.png)

图 11.12

现在，外部系统可以通过端口映射到 Docker 主机上的 TCP 端口 5000 访问运行在`localnet`桥接网络上的 NGINX 容器。``

``像这样映射端口是有效的，但它很笨拙，而且不具有扩展性。例如，只有一个容器可以绑定到主机上的任何端口。这意味着在我们运行 NGINX 容器的主机上，没有其他容器能够使用端口 5000。这就是单主机桥接网络仅适用于本地开发和非常小的应用程序的原因之一。

#### 多主机叠加网络

我们有一整章专门讲解多主机叠加网络。所以我们会把这一部分简短地介绍一下。

叠加网络是多主机的。它们允许单个网络跨越多个主机，以便不同主机上的容器可以在第 2 层进行通信。它们非常适合容器间通信，包括仅容器应用程序，并且它们具有良好的扩展性。

Docker 提供了一个用于叠加网络的本地驱动程序。这使得创建它们就像在`docker network create`命令中添加`--d overlay`标志一样简单。

#### 连接到现有网络

将容器化应用程序连接到外部系统和物理网络的能力至关重要。一个常见的例子是部分容器化的应用程序 - 容器化的部分需要一种方式与仍在现有物理网络和 VLAN 上运行的非容器化部分进行通信。

内置的`MACVLAN`驱动程序（在 Windows 上是`transparent`）就是为此而创建的。它通过为每个容器分配自己的 MAC 和 IP 地址，使容器成为现有物理网络上的一等公民。我们在图 11.13 中展示了这一点。

![图 11.13](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-13.png)

图 11.13

从积极的一面来看，MACVLAN 的性能很好，因为它不需要端口映射或额外的桥接 - 您可以通过容器接口连接到主机接口（或子接口）。然而，从消极的一面来看，它需要主机网卡处于**混杂模式**，这在大多数公共云平台上是不允许的。因此，MACVLAN 非常适合您的企业数据中心网络（假设您的网络团队可以适应混杂模式），但在公共云中不起作用。

让我们通过一些图片和一个假设的例子深入了解一下。

假设我们有一个现有的物理网络，其中有两个 VLAN：

+   VLAN 100: 10.0.0.0/24

+   VLAN 200: 192.168.3.0/24

![图 11.14](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-14.png)

图 11.14

接下来，我们添加一个 Docker 主机并将其连接到网络。

![图 11.15](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-15.png)

图 11.15

然后，我们需要将一个容器（应用服务）连接到 VLAN 100。为此，我们使用`macvlan`驱动创建一个新的 Docker 网络。但是，`macvlan`驱动需要我们告诉它一些关于我们将要关联的网络的信息。比如：

+   子网信息

+   网关

+   可以分配给容器的 IP 范围

+   在主机上使用哪个接口或子接口

以下命令将创建一个名为“macvlan100”的新 MACVLAN 网络，将容器连接到 VLAN 100。

```
$ docker network create -d macvlan `\`
  --subnet`=``10`.0.0.0/24 `\`
  --ip-range`=``10`.0.00/25 `\`
  --gateway`=``10`.0.0.1 `\`
  -o `parent``=`eth0.100 `\`
  macvlan100 
```

`这将创建“macvlan100”网络和 eth0.100 子接口。配置现在看起来像这样。

![图 11.16](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-16.png)

图 11.16

MACVLAN 使用标准的 Linux 子接口，并且您必须使用 VLAN 的 ID 对它们进行标记。在这个例子中，我们连接到 VLAN 100，所以我们使用`.100`（`etho.100`）对子接口进行标记。

我们还使用了`--ip-range`标志来告诉 MACVLAN 网络可以分配给容器的 IP 地址子集。这个地址范围必须保留给 Docker 使用，并且不能被其他节点或 DHCP 服务器使用，因为没有管理平面功能来检查重叠的 IP 范围。

`macvlan100`网络已准备好用于容器，让我们使用以下命令部署一个。

```
$ docker container run -d --name mactainer1 `\`
  --network macvlan100 `\`
  alpine sleep 1d 
```

`配置现在看起来像图 11.17。但请记住，底层网络（VLAN 100）看不到任何 MACVLAN 的魔法，它只看到具有 MAC 和 IP 地址的容器。考虑到这一点，“mactainer1”容器将能够 ping 并与 VLAN 100 上的任何其他系统通信。非常棒！

> **注意：**如果无法使其工作，可能是因为主机网卡没有处于混杂模式。请记住，公共云平台不允许混杂模式。

![图 11.17](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-17.png)

图 11.17

到目前为止，我们已经有了一个 MACVLAN 网络，并使用它将一个新容器连接到现有的 VLAN。但事情并不止于此。Docker MACVLAN 驱动是建立在经过验证的 Linux 内核驱动程序的基础上的。因此，它支持 VLAN 干线。这意味着我们可以创建多个 MACVLAN 网络，并将同一台 Docker 主机上的容器连接到它们，如图 11.18 所示。

![图 11.18](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-18.png)

图 11.18

这基本上涵盖了 MACVLAN。Windows 提供了一个类似的解决方案，使用`transparent`驱动。

##### 容器和服务日志用于故障排除

在继续服务发现之前，快速解决连接问题的说明。

如果您认为容器之间存在连接问题，值得检查守护程序日志和容器日志（应用程序日志）。

在 Windows 系统上，守护程序日志存储在`~AppData\Local\Docker`下，并且可以在 Windows 事件查看器中查看。在 Linux 上，这取决于您使用的`init`系统。如果您正在运行`systemd`，日志将进入`journald`，您可以使用`journalctl -u docker.service`命令查看它们。如果您没有运行`systemd`，您应该查看以下位置：

+   运行`upstart`的 Ubuntu 系统：`/var/log/upstart/docker.log`

+   基于 RHEL 的系统：`/var/log/messages`

+   Debian：`/var/log/daemon.log`

+   Docker for Mac: `~/Library/Containers/com.docker.docker/Data/com.docker.driver.amd64-linux/console-ring`

您还可以告诉 Docker 您希望守护程序日志记录的详细程度。要做到这一点，您需要编辑守护程序配置文件（`daemon.json`），以便将“`debug`”设置为“`true`”，并将“`log-level`”设置为以下之一：

+   `debug` 最详细的选项

+   `info` 默认值和第二最详细的选项

+   `warn` 第三个最详细的选项

+   `error` 第四个最详细的选项

+   `fatal` 最不详细的选项

`daemon.json`的以下片段启用了调试并将级别设置为`debug`。它适用于所有 Docker 平台。

```
{
  <Snip>
  "debug":true,
  "log-level":"debug",
  <Snip>
} 
```

更改文件后，请务必重新启动 Docker。

这是守护程序日志。那容器日志呢？

独立容器的日志可以使用`docker container logs`命令查看，Swarm 服务的日志可以使用`docker service logs`命令查看。但是，Docker 支持许多日志记录驱动程序，并且它们并不都与`docker logs`命令兼容。

除了引擎日志的驱动程序和配置外，每个 Docker 主机都有默认的容器日志驱动程序和配置。一些驱动程序包括：

+   `json-file`（默认）

+   `journald`（仅在运行`systemd`的 Linux 主机上有效）

+   `syslog`

+   `splunk`

+   `gelf`

`json-file`和`journald`可能是最容易配置的，它们都可以与`docker logs`和`docker service logs`命令一起使用。命令的格式是`docker logs <container-name>`和`docker service logs <service-name>`。

如果您正在使用其他日志记录驱动程序，可以使用第三方平台的本机工具查看日志。

以下来自`daemon.json`的片段显示了配置为使用`syslog`的 Docker 主机。

```
{
  "log-driver": "syslog"
} 
```

`您可以使用`--log-driver`和`--log-opts`标志配置单个容器或服务以使用特定的日志驱动程序。这将覆盖`daemon.json`中设置的任何内容。

容器日志的工作原理是您的应用程序作为其容器中的 PID 1 运行，并将日志发送到`STDOUT`，将错误发送到`STDERR`。然后，日志驱动程序将这些“日志”转发到通过日志驱动程序配置的位置。

如果您的应用程序记录到文件，可以使用符号链接将日志文件写入重定向到 STDOUT 和 STDERR。

以下是针对名为“vantage-db”的容器运行`docker logs`命令的示例，该容器配置为使用`json-file`日志驱动程序。

```
$ docker logs vantage-db
`1`:C `2` Feb `09`:53:22.903 `# oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo`
`1`:C `2` Feb `09`:53:22.904 `# Redis version=4.0.6, bits=64, commit=00000000, modi\`
`fied``=``0`, `pid``=``1`
`1`:C `2` Feb `09`:53:22.904 `# Warning: no config file specified, using the defaul\`
t config.
`1`:M `2` Feb `09`:53:22.906 * Running `mode``=`standalone, `port``=``6379`.
`1`:M `2` Feb `09`:53:22.906 `# WARNING: The TCP backlog setting of 511 cannot be e\`
nforced because...
`1`:M `2` Feb `09`:53:22.906 `# Server initialized`
`1`:M `2` Feb `09`:53:22.906 `# WARNING overcommit_memory is set to 0!` 
```

“您很有可能会在守护程序日志或容器日志中发现网络连接错误报告。

#### 服务发现

除了核心网络，`libnetwork`还提供了一些重要的网络服务。

*服务发现*允许所有容器和 Swarm 服务通过名称定位彼此。唯一的要求是它们在同一个网络上。

在幕后，这利用了 Docker 的嵌入式 DNS 服务器，以及每个容器中的 DNS 解析器。图 11.19 显示了容器“c1”通过名称 ping 容器“c2”。相同的原理也适用于 Swarm 服务。

![图 11.19](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-19.png)

图 11.19

让我们逐步了解这个过程。

+   **步骤 1：** `ping c2`命令调用本地 DNS 解析器将名称“c2”解析为 IP 地址。所有 Docker 容器都有一个本地 DNS 解析器。

+   **步骤 2：** 如果本地解析器在其本地缓存中没有“c2”的 IP 地址，它将发起对 Docker DNS 服务器的递归查询。本地解析器预先配置为知道嵌入式 Docker DNS 服务器的详细信息。

+   **步骤 3：** Docker DNS 服务器保存了使用`--name`或`--net-alias`标志创建的所有容器的名称到 IP 映射。这意味着它知道容器“c2”的 IP 地址。

+   **步骤 4：** DNS 服务器将“c2”的 IP 地址返回给“c1”中的本地解析器。它之所以这样做是因为这两个容器在同一个网络上 - 如果它们在不同的网络上，这将无法工作。

+   **步骤 5：** `ping`命令被发送到“c2”的 IP 地址。

每个使用`--name`标志启动的 Swarm 服务和独立容器都将其名称和 IP 注册到 Docker DNS 服务。这意味着所有容器和服务副本都可以使用 Docker DNS 服务找到彼此。

然而，服务发现是*网络范围的*。这意味着名称解析仅适用于相同网络上的容器和服务。如果两个容器在不同的网络上，它们将无法解析彼此。

关于服务发现和名称解析的最后一点...

可以配置 Swarm 服务和独立容器的自定义 DNS 选项。例如，`--dns`标志允许您指定要在嵌入式 Docker DNS 服务器无法解析查询时使用的自定义 DNS 服务器列表。您还可以使用`--dns-search`标志为针对未经验证名称的查询添加自定义搜索域（即当查询不是完全合格的域名时）。

在 Linux 上，所有这些都是通过向容器内的`/etc/resolv.conf`文件添加条目来实现的。

以下示例将启动一个新的独立容器，并将臭名昭著的`8.8.8.8` Google DNS 服务器添加到未经验证的查询中附加的搜索域`dockercerts.com`。

```
$ docker container run -it --name c1 `\`
  --dns`=``8`.8.8.8 `\`
  --dns-search`=`dockercerts.com `\`
  alpine sh 
```

`#### 入口负载平衡

Swarm 支持两种发布模式，使服务可以从集群外部访问：

+   入口模式（默认）

+   主机模式

通过*入口模式*发布的服务可以从 Swarm 中的任何节点访问 - 即使节点**没有**运行服务副本。通过*主机模式*发布的服务只能通过运行服务副本的节点访问。图 11.20 显示了两种模式之间的区别。

![图 11.20](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-20.png)

图 11.20

入口模式是默认模式。这意味着每当您使用`-p`或`--publish`发布服务时，它将默认为*入口模式*。要在*主机模式*下发布服务，您需要使用`--publish`标志的长格式**并且**添加`mode=host`。让我们看一个使用*主机模式*的例子。

```
$ docker service create -d --name svc1 `\`
  --publish `published``=``5000`,target`=``80`,mode`=`host `\`
  nginx 
```

`关于命令的一些说明。`docker service create`允许您使用*长格式语法*或*短格式语法*发布服务。短格式如下：`-p 5000:80`，我们已经看过几次了。但是，您不能使用短格式发布*主机模式*的服务。

长格式如下：`--publish published=5000,target=80,mode=host`。这是一个逗号分隔的列表，每个逗号后面没有空格。选项的工作如下：

+   `published=5000`使服务通过端口 5000 在外部可用

+   `target=80`确保对`published`端口的外部请求被映射回服务副本上的端口 80

+   `mode=host`确保外部请求只会在通过运行服务副本的节点进入时到达服务。

入口模式是您通常会使用的模式。

在幕后，*入口模式*使用了一个称为**服务网格**或**Swarm 模式服务网格**的第 4 层路由网格。图 11.21 显示了外部请求到入口模式下暴露的服务的基本流量流向。

![图 11.21](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-21.png)

图 11.21

让我们快速浏览一下图表。

1.  顶部的命令正在部署一个名为“svc1”的新 Swarm 服务。它将服务附加到`overnet`网络并在 5000 端口上发布它。

1.  像这样发布 Swarm 服务（`--publish published=5000,target=80`）将在入口网络的 5000 端口上发布它。由于 Swarm 中的所有节点都连接到入口网络，这意味着端口是*在整个 Swarm 中*发布的。

1.  集群上实现了逻辑，确保任何命中入口网络的流量，通过**任何节点**，在 5000 端口上都将被路由到端口 80 上的“svc1”服务。

1.  此时，“svc1”服务部署了一个单个副本，并且集群有一个映射规则，规定“*所有命中入口网络 5000 端口的流量都需要路由到运行“svc1”服务副本的节点*”。

1.  红线显示流量命中`node1`的 5000 端口，并通过入口网络路由到运行在 node2 上的服务副本。

重要的是要知道，传入的流量可能会命中任何一个端口为 5000 的四个 Swarm 节点，我们会得到相同的结果。这是因为服务是通过入口网络*在整个 Swarm 中*发布的。

同样重要的是要知道，如果有多个运行的副本，如图 11.22 所示，流量将在所有副本之间平衡。

![图 11.22](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure11-22.png)

图 11.22

### Docker 网络-命令

Docker 网络有自己的`docker network`子命令。主要命令包括：

+   `docker network ls`列出本地 Docker 主机上的所有网络。

+   `docker network create` 创建新的 Docker 网络。默认情况下，在 Windows 上使用`nat`驱动程序创建网络，在 Linux 上使用`bridge`驱动程序创建网络。您可以使用`-d`标志指定驱动程序（网络类型）。`docker network create -d overlay overnet`将使用原生 Docker`overlay`驱动程序创建一个名为 overnet 的新覆盖网络。

+   `docker network inspect`提供有关 Docker 网络的详细配置信息。

+   `docker network prune` 删除 Docker 主机上所有未使用的网络。

+   `docker network rm` 删除 Docker 主机上特定的网络。

### 章节总结

容器网络模型（CNM）是 Docker 网络的主设计文档，定义了用于构建 Docker 网络的三个主要构造——*沙盒*、*端点*和*网络*。

`libnetwork` 是用 Go 语言编写的开源库，实现了 CNM。它被 Docker 使用，并且是所有核心 Docker 网络代码的所在地。它还提供了 Docker 的网络控制平面和管理平面。

驱动程序通过添加代码来实现特定的网络类型（如桥接网络和覆盖网络）来扩展 Docker 网络堆栈（`libnetwork`）。Docker 预装了几个内置驱动程序，但您也可以使用第三方驱动程序。

单主机桥接网络是最基本的 Docker 网络类型，适用于本地开发和非常小的应用程序。它们不具备可扩展性，如果要将服务发布到网络外部，则需要端口映射。Linux 上的 Docker 使用内置的 `bridge` 驱动程序实现桥接网络，而 Windows 上的 Docker 使用内置的 `nat` 驱动程序实现它们。

覆盖网络非常流行，是非常适合容器的多主机网络。我们将在下一章中深入讨论它们。

`macvlan` 驱动程序（Windows 上的 `transparent`）允许您将容器连接到现有的物理网络和虚拟局域网。它们通过为容器分配自己的 MAC 和 IP 地址使容器成为一流公民。不幸的是，它们需要在主机 NIC 上启用混杂模式，这意味着它们在公共云中无法工作。

Docker 还使用 `libnetwork` 来实现基本的服务发现，以及用于容器负载均衡入口流量的服务网格。


# 第十三章：Docker 叠加网络

叠加网络是我们在容器相关网络中所做的大部分事情的核心。在本章中，我们将介绍本机 Docker 叠加网络的基础知识，这是在 Docker Swarm 集群中实现的。

Windows 上的 Docker 叠加网络具有与 Linux 相同的功能对等性。这意味着我们在本章中使用的示例将在 Linux 和 Windows 上都可以工作。

我们将把本章分为通常的三个部分：

+   简而言之

+   深入挖掘

+   命令

让我们做一些网络魔术！

### Docker 叠加网络 - 简而言之

在现实世界中，容器之间能够可靠且安全地通信是至关重要的，即使它们位于不同的网络上的不同主机上。这就是叠加网络发挥作用的地方。它允许您创建一个扁平、安全的第二层网络，跨越多个主机。容器连接到这个网络并可以直接通信。

Docker 提供了本机叠加网络，简单配置且默认安全。

在幕后，它是建立在`libnetwork`和驱动程序之上的。

+   `libnetwork`

+   `驱动程序`

Libnetwork 是容器网络模型（CNM）的规范实现，驱动程序是实现不同网络技术和拓扑的可插拔组件。Docker 提供了本机驱动程序，如`overlay`驱动程序，第三方也提供了驱动程序。

### Docker 叠加网络 - 深入挖掘

2015 年 3 月，Docker 公司收购了一个名为*Socket Plane*的容器网络初创公司。收购背后的两个原因是为 Docker 带来*真正的网络*，并使容器网络简单到连开发人员都能做到 :-P

他们在这两个方面取得了巨大的进展。

然而，在简单的网络命令背后隐藏着许多复杂的部分。这些是你在进行生产部署和尝试解决问题之前需要了解的内容！

本章的其余部分将分为两个部分：

+   第一部分：我们将在 Swarm 模式下构建和测试 Docker 叠加网络

+   第二部分：我们将解释它是如何工作的理论。

#### 在 Swarm 模式下构建和测试 Docker 叠加网络

对于以下示例，我们将使用两个 Docker 主机，位于两个单独的第二层网络上，通过路由器连接。请参见图 12.1，并注意每个节点所在的不同网络。

![图 12.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-1.png)

图 12.1

您可以在 Linux 或 Windows Docker 主机上跟着做。Linux 应至少具有 4.4 Linux 内核（更新的总是更好），Windows 应为安装了最新热修复的 Windows Server 2016。

##### 构建 Swarm

我们要做的第一件事是将两个主机配置为两节点 Swarm。我们将在**node1**上运行`docker swarm init`命令，使其成为*管理者*，然后在**node2**上运行`docker swarm join`命令，使其成为*工作节点*。

> **警告：**如果您在自己的实验室中跟着做，您需要将 IP 地址、容器 ID、令牌等与您环境中的正确值进行交换。

在**node1**上运行以下命令。

```
$ docker swarm init `\`
  --advertise-addr`=``172`.31.1.5 `\`
  --listen-addr`=``172`.31.1.5:2377

Swarm initialized: current node `(`1ex3...o3px`)` is now a manager. 
```

在**node2**上运行下一个命令。在 Windows Server 上，您可能需要修改 Windows 防火墙规则以允许端口`2377/tcp`、`7946/tcp`和`7946/udp`。

```
$ docker swarm join `\`
  --token SWMTKN-1-0hz2ec...2vye `\`
  `172`.31.1.5:2377
This node joined a swarm as a worker. 
```

我们现在有一个两节点的 Swarm，**node1**作为管理者，**node2**作为工作节点。

##### 创建新的覆盖网络

现在让我们创建一个名为**uber-net**的新的*覆盖网络*。

在**node1**（管理者）上运行以下命令。在 Windows 上，您可能需要为 Windows Docker 节点上的端口`4789/udp`添加规则才能使其工作。

```
$ docker network create -d overlay uber-net
c740ydi1lm89khn5kd52skrd9 
```

完成了！您刚刚创建了一个全新的覆盖网络，该网络对 Swarm 中的所有主机都可用，并且其控制平面已使用 TLS 加密！如果您想加密数据平面，只需在命令中添加`-o encrypted`标志。

您可以使用`docker network ls`命令在每个节点上列出所有网络。

```
$ docker network ls
NETWORK ID      NAME              DRIVER     SCOPE
ddac4ff813b7    bridge            bridge     `local`
389a7e7e8607    docker_gwbridge   bridge     `local`
a09f7e6b2ac6    host              host       `local`
ehw16ycy980s    ingress           overlay    swarm
2b26c11d3469    none              null       `local`
c740ydi1lm89    uber-net          overlay    swarm 
```

在 Windows 服务器上，输出将更像这样：

```
NETWORK ID      NAME             DRIVER      SCOPE
8iltzv6sbtgc    ingress          overlay     swarm
6545b2a61b6f    nat              nat         local
96d0d737c2ee    none             null        local
nil5ouh44qco    uber-net         overlay     swarm 
```

我们创建的网络位于名为**uber-net**的列表底部。其他网络是在安装 Docker 和初始化 Swarm 时自动创建的。

如果您在**node2**上运行`docker network ls`命令，您会注意到它看不到**uber-net**网络。这是因为新的覆盖网络只对运行附加到它们的容器的工作节点可用。这种懒惰的方法通过减少网络八卦的数量来提高网络可扩展性。

##### 将服务附加到覆盖网络

既然我们有了一个覆盖网络，让我们创建一个新的*Docker 服务*并将其附加到它。我们将创建一个具有两个副本（容器）的服务，以便一个在**node1**上运行，另一个在**node2**上运行。这将自动将**uber-net**覆盖扩展到**node2**。

从**node1**运行以下命令。

Linux 示例：

```
$ docker service create --name `test` `\`
   --network uber-net `\`
   --replicas `2` `\`
   ubuntu sleep infinity 
```

Windows 示例：

```
> docker service create --name test `
  --network uber-net `
  --replicas 2 `
  microsoft\powershell:nanoserver Start-Sleep 3600 
```

`> **注意：** Windows 示例使用反引号字符来分割参数，使命令更易读。反引号是 PowerShell 转义换行的方式。

该命令创建了一个名为**test**的新服务，将其附加到**uber-net**叠加网络，并基于提供的镜像创建了两个副本（容器）。在这两个示例中，我们向容器发出了一个休眠命令，以使它们保持运行状态并阻止它们退出。

因为我们运行了两个副本（容器），而 Swarm 有两个节点，一个副本将被调度到每个节点上。

使用`docker service ps`命令验证操作。

```
$ docker service ps `test`
ID          NAME    IMAGE   NODE    DESIRED STATE  CURRENT STATE
77q...rkx   test.1  ubuntu  node1   Running        Running
97v...pa5   test.2  ubuntu  node2   Running        Running 
```

`当 Swarm 在叠加网络上启动容器时，它会自动将该网络扩展到容器所在的节点。这意味着**uber-net**网络现在在**node2**上可见。

恭喜！您已经创建了一个跨越两个位于不同物理底层网络的节点的新叠加网络。您还将两个容器连接到了它。这是多么简单！

#### 测试叠加网络

现在让我们用 ping 命令测试叠加网络。

如图 12.2 所示，我们在不同网络上有两个 Docker 主机，都连接了一个叠加网络。我们在每个节点上都有一个容器连接到叠加网络。让我们看看它们是否可以相互 ping 通。

![图 12.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-2.png)

图 12.2

为了进行测试，我们需要每个容器的 IP 地址（在本次测试中，我们忽略了相同叠加上的容器可以通过名称相互 ping 通的事实）。

运行`docker network inspect`来查看分配给叠加网络的**子网**。

```
$ docker network inspect uber-net
``
    `{`
        `"Name"`: `"uber-net"`,
        `"Id"`: `"c740ydi1lm89khn5kd52skrd9"`,
        `"Scope"`: `"swarm"`,
        `"Driver"`: `"overlay"`,
        `"EnableIPv6"`: false,
        `"IPAM"`: `{`
            `"Driver"`: `"default"`,
            `"Options"`: null,
            `"Config"`: `[`
                `{`
                    `"Subnet"`: `"10.0.0.0/24"`,
                    `"Gateway"`: `"10.0.0.1"`
                `}`
<Snip> 
```

`上面的输出显示**uber-net**的子网为`10.0.0.0/24`。请注意，这与任何一个物理底层网络（`172.31.1.0/24`和`192.168.1.0/24`）都不匹配。

在**node1**和**node2**上运行以下两个命令。这些命令将获取容器的 ID 和 IP 地址。确保在第二个命令中使用您自己实验室中的容器 ID。

```
$ docker container ls
CONTAINER ID   IMAGE           COMMAND           CREATED      STATUS
396c8b142a85   ubuntu:latest   `"sleep infinity"`  `2` hours ago  Up `2` hrs

$ docker container inspect `\`
  --format`=``'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'` 396c8b`\`
142a85
`10`.0.0.3 
```

`确保您在两个节点上运行这些命令，以获取两个容器的 IP 地址。

图 12.3 显示了到目前为止的配置。在您的实验室中，子网和 IP 地址可能会有所不同。

![图 12.3

图 12.3

正如我们所看到的，有一个跨越两个主机的第 2 层叠加网络，并且每个容器在这个叠加网络上都有一个 IP 地址。这意味着**node1**上的容器将能够使用其来自叠加网络的`10.0.0.4`地址来 ping **node2**上的容器。尽管两个*节点*位于不同的第 2 层底层网络上，这也能够实现。让我们来证明一下。

登录到**node1**上的容器并 ping 远程容器。

要在 Linux Ubuntu 容器上执行此操作，您需要安装`ping`实用程序。如果您正在使用 Windows PowerShell 示例，`ping`实用程序已经安装。

请记住，您的环境中容器的 ID 将是不同的。

Linux 示例：

```
`$` `docker` `container` `exec` `-``it` `396``c8b142a85` `bash`

`root``@396``c8b142a85``:``/``#` `apt``-``get` `update`
`<``Snip``>`

`root``@396``c8b142a85``:``/``#` `apt``-``get` `install` `iputils``-``ping`
`Reading` `package` `lists``...` `Done`
`Building` `dependency` `tree`
`Reading` `state` `information``...` `Done`
`<``Snip``>`
`Setting` `up` `iputils``-``ping` `(``3``:``20121221``-``5u``buntu2``)` `...`
`Processing` `triggers` `for` `libc``-``bin` `(``2.23``-``0u``buntu3``)` `...`

`root``@396``c8b142a85``:``/``#` `ping` `10.0.0.4`
`PING` `10.0.0.4` `(``10.0.0.4``)` `56``(``84``)` `bytes` `of` `data``.`
`64` `bytes` `from` `10.0.0.4``:` `icmp_seq``=``1` `ttl``=``64` `time``=``1.06` `ms`
`64` `bytes` `from` `10.0.0.4``:` `icmp_seq``=``2` `ttl``=``64` `time``=``1.07` `ms`
`64` `bytes` `from` `10.0.0.4``:` `icmp_seq``=``3` `ttl``=``64` `time``=``1.03` `ms`
`64` `bytes` `from` `10.0.0.4``:` `icmp_seq``=``4` `ttl``=``64` `time``=``1.26` `ms`
`^``C`
`root``@396``c8b142a85``:``/``#` 
```

Windows 示例：

```
> docker container exec -it 1a4f29e5a4b6 pwsh.exe
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\> ping 10.0.0.4

Pinging 10.0.0.4 with 32 bytes of data:
Reply from 10.0.0.4: bytes=32 time=1ms TTL=128
Reply from 10.0.0.4: bytes=32 time<1ms TTL=128
Reply from 10.0.0.4: bytes=32 time=2ms TTL=128
Reply from 10.0.0.4: bytes=32 time=2ms TTL=12
PS C:\> 
```

`恭喜。**node1**上的容器可以使用叠加网络 ping **node2**上的容器。

您还可以在容器内跟踪 ping 命令的路由。这将报告一个单一的跳跃，证明容器正在通过叠加网络直接通信，对正在穿越的任何底层网络毫不知情。

> **注意：**对于 Linux 示例中的`traceroute`工作，您需要安装`traceroute`软件包。

Linux 示例：

```
`$` `root``@396``c8b142a85``:``/``#` `traceroute` `10.0.0.4`
`traceroute` `to` `10.0.0.4` `(``10.0.0.4``),` `30` `hops` `max``,` `60` `byte` `packets`
 `1`  `test``-``svc``.2.97``v``...``a5``.``uber``-``net` `(``10.0.0.4``)`  `1.110``ms`  `1.034``ms`  `1.073``ms` 
```

Windows 示例：

```
PS C:\> tracert 10.0.0.3

Tracing route to test.2.ttcpiv3p...7o4.uber-net [10.0.0.4]
over a maximum of 30 hops:

  1  <1 ms  <1 ms  <1 ms  test.2.ttcpiv3p...7o4.uber-net [10.0.0.4]

Trace complete. 
```

到目前为止，我们已经用一个命令创建了一个叠加网络。然后我们将容器添加到其中。这些容器被安排在两个位于两个不同第 2 层底层网络上的主机上。一旦我们确定了容器的 IP 地址，我们证明它们可以直接通过叠加网络进行通信。

#### 它是如何工作的理论

既然我们已经看到如何构建和使用容器叠加网络，让我们找出它在幕后是如何组合在一起的。

本节的一些细节将是特定于 Linux 的。然而，相同的总体原则也适用于 Windows。

##### VXLAN 入门

首先，Docker 叠加网络使用 VXLAN 隧道来创建虚拟的第 2 层叠加网络。因此，在我们进一步之前，让我们快速了解一下 VXLAN。

在最高层次上，VXLAN 允许您在现有的第 3 层基础设施上创建一个虚拟的第 2 层网络。我们之前使用的示例在两个第 2 层网络 — 172.31.1.0/24 和 192.168.1.0/24 的基础上创建了一个新的 10.0.0.0/24 第 2 层网络。如图 12.4 所示。

![图 12.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-4.png)

图 12.4

VXLAN 的美妙之处在于，它是一种封装技术，现有的路由器和网络基础设施只会将其视为常规的 IP/UDP 数据包，并且可以处理而无需问题。

为了创建虚拟二层叠加网络，通过底层三层 IP 基础设施创建了一个 VXLAN*隧道*。您可能会听到术语*底层网络*用于指代底层三层基础设施。

VXLAN 隧道的每一端都由 VXLAN 隧道端点（VTEP）终止。正是这个 VTEP 执行了封装/解封装和其他使所有这些工作的魔术。参见图 12.5。

![图 12.5](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-5.png)

图 12.5

##### 步骤通过我们的两个容器示例

在我们之前构建的示例中，我们有两台主机通过 IP 网络连接。每台主机运行一个容器，并为容器创建了一个 VXLAN 叠加网络以进行连接。

为了实现这一点，在每台主机上创建了一个新的*沙盒*（网络命名空间）。正如在上一章中提到的，*沙盒*类似于一个容器，但它不是运行应用程序，而是运行一个与主机本身的网络堆栈隔离的网络堆栈。

在沙盒内创建了一个名为**Br0**的虚拟交换机（又名虚拟桥）。还创建了一个 VTEP，其中一端连接到**Br0**虚拟交换机，另一端连接到主机网络堆栈（VTEP）。主机网络堆栈的一端在主机连接的底层网络上获取 IP 地址，并绑定到端口 4789 上的 UDP 套接字。每台主机上的两个 VTEP 通过 VXLAN 隧道创建叠加网络，如图 12.6 所示。

![图 12.6](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-6.png)

图 12.6

这就是创建并准备好供使用的 VXLAN 叠加网络。

然后，每个容器都会获得自己的虚拟以太网（`veth`）适配器，也连接到本地的**Br0**虚拟交换机。拓扑现在看起来像图 12.7，应该更容易看出这两个容器如何在 VXLAN 叠加网络上进行通信，尽管它们的主机位于两个独立的网络上。

![图 12.7](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-7.png)

图 12.7

##### 通信示例

现在我们已经看到了主要的管道元素，让我们看看这两个容器是如何通信的。

在本例中，我们将 node1 上的容器称为“**C1**”，将 node2 上的容器称为“**C2**”。假设**C1**想要像我们在本章早些时候的实际示例中那样 ping **C2**。

![图 12.8](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure12-8.png)

图 12.8

**C1**创建 ping 请求，并将目标 IP 地址设置为**C2**的`10.0.0.4`地址。它通过连接到**Br0**虚拟交换机的`veth`接口发送流量。虚拟交换机不知道该如何发送数据包，因为它的 MAC 地址表（ARP 表）中没有对应于目标 IP 地址的条目。因此，它将数据包洪泛到所有端口。连接到**Br0**的 VTEP 接口知道如何转发帧，因此用自己的 MAC 地址进行回复。这是一个*代理 ARP*回复，并导致**Br0**交换机*学习*如何转发数据包。因此，它更新了 ARP 表，将 10.0.0.4 映射到本地 VTEP 的 MAC 地址。

现在**Br0**交换机已经*学会*了如何将流量转发到**C2**，所有未来发往**C2**的数据包都将直接传输到 VTEP 接口。VTEP 接口知道**C2**，因为所有新启动的容器都使用网络内置的八卦协议将它们的网络细节传播到 Swarm 中的其他节点。

交换机然后将数据包发送到 VTEP 接口，VTEP 接口封装帧，以便可以通过底层传输基础设施发送。在相当高的层面上，这种封装包括向以太网帧添加 VXLAN 头。VXLAN 头包含 VXLAN 网络 ID（VNID），用于将帧从 VLAN 映射到 VXLAN，反之亦然。每个 VLAN 都映射到 VNID，以便可以在接收端解封数据包并转发到正确的 VLAN。这显然保持了网络隔离。封装还将帧包装在具有 node2 上远程 VTEP 的 IP 地址的 UDP 数据包中的*目标 IP 字段*，以及 UDP 端口 4789 套接字信息。这种封装允许数据在底层网络上发送，而底层网络无需了解 VXLAN。

当数据包到达 node2 时，内核会看到它的目的地是 UDP 端口 4789。内核还知道它有一个绑定到此套接字的 VTEP 接口。因此，它将数据包发送到 VTEP，VTEP 读取 VNID，解封数据包，并将其发送到对应 VNID 的本地**Br0**交换机上的 VLAN。然后将其传递给容器 C2。

这是 VXLAN 技术如何被原生 Docker 覆盖网络利用的基础知识。

我们在这里只是浅尝辄止，但这应该足够让您能够开始进行任何潜在的生产 Docker 部署。这也应该让您具备与网络团队讨论 Docker 基础设施的网络方面所需的知识。

最后一件事。Docker 还支持同一覆盖网络内的三层路由。例如，您可以创建一个具有两个子网的覆盖网络，Docker 将负责在它们之间进行路由。创建这样一个网络的命令可能是 `docker network create --subnet=10.1.1.0/24 --subnet=11.1.1.0/24 -d overlay prod-net`。这将导致在 *沙盒* 内创建两个虚拟交换机 **Br0** 和 **Br1**，并且默认情况下会进行路由。

### Docker 覆盖网络 - 命令

+   `docker network create` 是我们用来创建新容器网络的命令。`-d` 标志允许您指定要使用的驱动程序，最常见的驱动程序是 `overlay` 驱动程序。您还可以指定来自第三方的 *远程* 驱动程序。对于覆盖网络，默认情况下控制平面是加密的。只需添加 `-o encrypted` 标志即可加密数据平面（可能会产生性能开销）。

+   `docker network ls` 列出 Docker 主机可见的所有容器网络。运行在 *Swarm 模式* 中的 Docker 主机只会看到托管在特定网络上运行的容器的覆盖网络。这可以将与网络相关的传闻最小化。

+   `docker network inspect` 显示有关特定容器网络的详细信息。这包括 *范围*、*驱动程序*、*IPv6*、*子网配置*、*VXLAN 网络 ID* 和 *加密状态*。

+   `docker network rm` 删除一个网络

### 章节总结

在本章中，我们看到使用 `docker network create` 命令创建新的 Docker 覆盖网络是多么容易。然后我们学习了它们如何在幕后使用 VXLAN 技术组合在一起。

我们只是触及了 Docker 覆盖网络可以做的一小部分。``````````````


# 第十四章：卷和持久数据

是时候看看 Docker 如何管理数据了。我们将看持久和非持久数据。然而，本章的重点将放在持久数据上。

我们将把这一章分为通常的三个部分：

+   简而言之

+   深入探讨

+   命令

### 卷和持久数据-简而言之

数据有两个主要类别。持久和非持久。

持久是你需要*保留*的东西。像客户记录、财务、预订、审计日志，甚至某些类型的应用程序*日志*数据。非持久是你不需要保留的东西。

两者都很重要，Docker 都有相应的选项。

每个 Docker 容器都有自己的非持久存储。它会自动与容器一起创建，并与容器的生命周期相关联。这意味着删除容器将删除这个存储和其中的任何数据。

如果你希望容器的数据保留下来（持久），你需要把它放在*卷*上。卷与容器解耦，这意味着你可以单独创建和管理它们，并且它们不与任何容器的生命周期相关联。最终结果是，你可以删除一个带有卷的容器，而卷不会被删除。

这就是简而言之。让我们仔细看一看。

### 卷和持久数据-深入探讨

容器非常适合微服务设计模式。我们经常将微服务与*短暂*和*无状态*等词联系在一起。所以……微服务都是关于无状态和短暂的工作负载，而容器非常适合微服务。因此，我们经常得出结论，容器必须只适用于短暂的东西。

但这是错误的。完全错误。

#### 容器和非持久数据

容器确实非常擅长处理无状态和非持久的东西。

每个容器都会自动获得一大堆本地存储。默认情况下，这就是容器的所有文件和文件系统所在的地方。你会听到这些被称为*本地存储*、*图形驱动存储*和*快照存储*。无论如何，这是容器的一个组成部分，并与容器的生命周期相关联-当容器创建时它被创建，当容器删除时它被删除。简单。

在 Linux 系统中，它存在于`/var/lib/docker/<storage-driver>/`的某个位置，作为容器的一部分。在 Windows 中，它位于`C:\ProgramData\Docker\windowsfilter\`下。

如果您在 Linux 上的生产环境中运行 Docker，您需要确保将正确的存储驱动程序（图形驱动程序）与 Docker 主机上的 Linux 版本匹配。使用以下列表作为*指南：*

+   **Red Hat Enterprise Linux：**在运行 Docker 17.06 或更高版本的现代 RHEL 版本中使用`overlay2`驱动程序。在旧版本中使用`devicemapper`驱动程序。这适用于 Oracle Linux 和其他与 Red Hat 相关的上游和下游发行版。

+   **Ubuntu：**使用`overlay2`或`aufs`驱动程序。如果您使用的是 Linux 4.x 内核或更高版本，则应选择`overlay2`。

+   **SUSE Linux Enterprise Server：**使用`btrfs`存储驱动程序。

+   **Windows** Windows 只有一个驱动程序，并且默认情况下已配置。

上述列表仅应作为指南使用。随着事物的进展，`overlay2`驱动程序在各个平台上的受欢迎程度正在增加，并且可能成为推荐的存储驱动程序。如果您使用 Docker 企业版（EE）并且有支持合同，您应该咨询最新的兼容性支持矩阵。

让我们回到正题。

默认情况下，容器内的所有存储都使用这个*本地存储*。因此，默认情况下，容器中的每个目录都使用这个存储。

如果您的容器不创建持久数据，*本地存储*就可以了，您可以继续。但是，如果您的容器**需要**持久数据，您需要阅读下一节。

#### 容器和持久数据

在容器中持久保存数据的推荐方法是使用*卷*。

在高层次上，您创建一个卷，然后创建一个容器，并将卷挂载到其中。卷被挂载到容器文件系统中的一个目录，写入该目录的任何内容都将写入卷中。然后，如果您删除容器，卷及其数据仍将存在。

图 13.1 显示了一个 Docker 卷挂载到容器的`/code`目录。写入`/code`目录的任何数据都将存储在卷上，并且在删除容器后仍将存在。

![图 13.1 卷和容器的高级视图](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure13-1.png)

图 13.1 卷和容器的高级视图

在图 13.1 中，`/code`目录是一个 Docker 卷。所有其他目录使用容器的临时本地存储。从卷到`/code`目录的箭头是虚线，表示卷和容器之间的解耦关系。

##### 创建和管理 Docker 卷

卷在 Docker 中是一流的公民。这意味着它们是 API 中的独立对象，并且它们有自己的`docker volume`子命令。

使用以下命令创建名为`myvol`的新卷。

```
$ docker volume create myvol 
```

默认情况下，Docker 会使用内置的`local`驱动程序创建新卷。顾名思义，本地卷仅适用于在其上创建的节点上的容器。使用`-d`标志指定不同的驱动程序。

第三方驱动程序可作为插件使用。这些可以提供高级存储功能，并将外部存储系统与 Docker 集成。图 13.2 显示了外部存储系统（例如 SAN 或 NAS）被用于为卷提供后端存储。驱动程序将外部存储系统及其高级功能集成到 Docker 环境中。

![图 13.2 将外部存储插入 Docker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure13-2.png)

图 13.2 将外部存储插入 Docker

目前，有超过 25 个卷插件。这些涵盖了块存储、文件存储、对象存储等：

+   **块存储**往往具有高性能，并且适用于小块随机访问工作负载。具有 Docker 卷插件的块存储系统的示例包括 HPE 3PAR、Amazon EBS 和 OpenStack 块存储服务（cinder）。

+   **文件存储**包括使用 NFS 和 SMB 协议的系统，并且也适用于高性能工作负载。具有 Docker 卷插件的文件存储系统的示例包括 NetApp FAS、Azure 文件存储和 Amazon EFS。

+   **对象存储**适用于不经常更改的大数据块的长期存储。它通常是内容可寻址的，并且通常性能较低。具有 Docker 卷驱动程序的示例包括 Amazon S3、Ceph 和 Minio。

现在卷已创建，您可以使用`docker volume ls`命令查看它，并使用`docker volume inspect`命令检查它。

```
$ docker volume ls
DRIVER              VOLUME NAME
`local`               myvol

$ docker volume inspect myvol
`[`
    `{`
        `"CreatedAt"`: `"2018-01-12T12:12:10Z"`,
        `"Driver"`: `"local"`,
        `"Labels"`: `{}`,
        `"Mountpoint"`: `"/var/lib/docker/volumes/myvol/_data"`,
        `"Name"`: `"myvol"`,
        `"Options"`: `{}`,
        `"Scope"`: `"local"`
    `}`
`]` 
```

`从`inspect`命令的输出中得出一些有趣的观点。`driver`和`scope`都是`local`。这意味着卷是使用默认的`local`驱动程序创建的，并且仅适用于此 Docker 主机上的容器。`mountpoint`属性告诉我们卷在主机上的哪个位置被展示。在这个例子中，卷在 Docker 主机上的`/var/lib/docker/volumes/myvol/_data`处被展示。在 Windows Docker 主机上，它将报告为`Mountpoint": "C:\\ProgramData\\Docker\\volumes\\myvol\\_data`。

使用`local`驱动程序创建的所有卷在 Linux 上都有自己的目录，位于`/var/lib/docker/volumes`，在 Windows 上位于`C:\ProgramData\Docker\volumes`。这意味着您可以在 Docker 主机的文件系统中看到它们，甚至可以从 Docker 主机读取和写入数据。我们在 Docker Compose 章节中看到了一个例子，我们将文件复制到 Docker 主机上卷的目录中，文件立即出现在容器内的卷中。

现在您可以使用`myvol`卷与 Docker 服务和容器一起使用。例如，您可以使用`docker container run`命令将其挂载到一个新的容器中，使用`--mount`标志。我们马上会看到一些例子。

删除 Docker 卷有两种方法：

+   `docker volume prune`

+   `docker volume rm`

`docker volume prune`将删除**所有未挂载到容器或服务副本的卷**，因此**请谨慎使用！** `docker volume rm`允许您精确指定要删除的卷。这两个命令都不会删除正在被容器或服务副本使用的卷。

由于`myvol`卷未被使用，可以使用`prune`命令删除它。

```
$ docker volume prune

WARNING! This will remove all volumes not used by at least one container.
Are you sure you want to `continue`? `[`y/N`]` y

Deleted Volumes:
myvol
Total reclaimed space: 0B 
```

“恭喜，您已经创建、检查和删除了一个 Docker 卷。而且您做到了所有这一切都没有与容器进行交互。这展示了卷的独立性。”

到目前为止，您已经知道了创建、列出、检查和删除 Docker 卷的所有命令。但是，也可以使用`VOLUME`指令通过 Dockerfile 部署卷。格式为`VOLUME <container-mount-point>`。但是，在 Dockerfile 中无法指定主机目录部分。这是因为*主机*目录本质上是*主机*相关的，这意味着它们可能在主机之间发生变化，并且可能破坏构建。如果通过 Dockerfile 指定，您必须在部署时指定主机目录。

#### 演示容器和服务的卷

现在我们知道了与容器和服务一起使用基本卷相关的 Docker 命令，让我们看看如何使用它们。

我们将在没有卷的系统上工作，我们演示的所有内容都适用于 Linux 和 Windows。

使用以下命令创建一个新的独立容器，并挂载一个名为`bizvol`的卷。

**Linux 示例：**

```
$ docker container run -dit --name voltainer `\`
    --mount `source``=`bizvol,target`=`/vol `\`
    alpine 
```

**Windows 示例：**

对于所有 Windows 示例，请使用 PowerShell，并注意使用反引号（`）将命令拆分成多行。

```
> docker container run -dit --name voltainer `
    --mount source=bizvol,target=c:\vol `
    microsoft/powershell:nanoserver 
```

`即使系统中没有名为`bizvol`的卷，该命令也应该成功运行。这提出了一个有趣的观点：

+   如果您指定一个已存在的卷，Docker 将使用现有的卷

+   如果您指定一个不存在的卷，Docker 会为您创建它

在这种情况下，`bizvol`不存在，因此 Docker 创建了它并将其挂载到新容器中。这意味着您将能够通过`docker volume ls`看到它。

```
$ docker volume ls
DRIVER              VOLUME NAME
`local`               bizvol 
```

`尽管容器和卷有各自的生命周期，但您不能删除正在被容器使用的卷。试试看。

```
$ docker volume rm bizvol
Error response from daemon: unable to remove volume: volume is in use - `[`b44`\`
d3f82...dd2029ca`]` 
```

`卷目前是空的。让我们进入容器并向其中写入一些数据。如果您在 Windows 上进行操作，请记得在`docker container exec`命令的末尾将`sh`替换为`pwsh.exe`。所有其他命令都适用于 Linux 和 Windows。

```
$ docker container `exec` -it voltainer sh

/# `echo` `"I promise to write a review of the book on Amazon"` > /vol/file1

/# ls -l /vol
total `4`
-rw-r--r-- `1` root  root   `50` Jan `12` `13`:49 file1

/# cat /vol/file1
I promise to write a review of the book on Amazon 
```

键入`exit`返回到 Docker 主机的 shell，然后使用以下命令删除容器。

```
$ docker container rm voltainer -f
voltainer 
```

即使容器被删除，卷仍然存在：

```
$ docker container ls -a
CONTAINER ID     IMAGE    COMMAND    CREATED       STATUS

$ docker volume ls
DRIVER              VOLUME NAME
`local`               bizvol 
```

`因为卷仍然存在，您可以查看宿主机上的挂载点，以检查您写入的数据是否仍然存在。

从 Docker 主机的终端运行以下命令。第一个将显示文件仍然存在，第二个将显示文件的内容。

如果您在 Windows 上进行操作，请确保使用`C:\ProgramData\Docker\volumes\bizvol\_data`目录。

```
$ ls -l /var/lib/docker/volumes/bizvol/_data/
total `4`
-rw-r--r-- `1` root root `50` Jan `12` `14`:25 file1

$ cat /var/lib/docker/volumes/bizvol/_data/file1
I promise to write a review of the book on Amazon 
```

`很好，卷和数据仍然存在。

甚至可以将`bizvol`卷挂载到一个新的服务或容器中。以下命令创建一个名为 hellcat 的新 Docker 服务，并将 bizvol 挂载到服务副本的`/vol`目录中。

```
$ docker service create `\`
  --name hellcat `\`
  --mount `source``=`bizvol,target`=`/vol `\`
  alpine sleep 1d

overall progress: `1` out of `1` tasks
`1`/1: running   `[====================================`>`]`
verify: Service converged 
```

`我们没有指定`--replicas`标志，因此只会部署一个服务副本。找出它在 Swarm 中运行的节点。

```
$ docker service ps hellcat
ID         NAME         NODE      DESIRED STATE     CURRENT STATE
l3nh...    hellcat.1    node1     Running           Running `19` seconds ago 
```

`在这个例子中，副本正在`node1`上运行。登录`node1`并获取服务副本容器的 ID。

```
node1$ docker container ls
CTR ID     IMAGE             COMMAND       STATUS        NAMES
df6..a7b   alpine:latest     "sleep 1d"    Up 25 secs    hellcat.1.l3nh... 
```

`请注意，容器名称是由`service-name`、`replica-number`和`replica-ID`组合而成，用句点分隔。

进入容器并检查`/vol`中是否存在数据。我们将在`exec`示例中使用服务副本的容器 ID。如果您在 Windows 上进行操作，请记得将`sh`替换为`pwsh.exe`。

```
node1$ docker container exec -it df6 sh

/# cat /vol/file1
I promise to write a review of the book on Amazon 
```

`我想现在是时候跳到亚马逊去写那篇书评了 :-D`

很好，卷保留了原始数据，并使其对新容器可用。

#### 在集群节点之间共享存储

将 Docker 与外部存储系统集成，可以轻松地在集群节点之间共享外部存储。例如，可以将单个存储 LUN 或 NFS 共享呈现给多个 Docker 主机，因此可以提供给无论在哪个主机上运行的容器和服务副本。图 13.3 显示了一个外部共享卷被呈现给两个 Docker 节点。然后，这些 Docker 节点使共享卷可用于一些容器。

![图 13.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure13-3.png)

图 13.3

构建这样的设置需要对外部存储系统有所了解，以及了解您的应用程序如何读取和写入共享存储中的数据。

这种配置的一个主要问题是**数据损坏**。

假设以下示例基于图 13.3：节点 1 上的容器 A 更新了共享卷中的一些数据。但是，它并没有直接将更新写入卷中，而是将其保存在本地缓冲区中以便更快地调用。此时，容器 A 认为数据已经更新。然而，在节点 2 上，容器 B 更新了相同的数据，并直接将其提交到卷中。此时，两个容器都*认为*它们已经更新了卷中的数据，但实际上只有容器 B 更新了。在以后的某个时间，节点 1 上的容器 A 刷新其缓冲区，覆盖了节点 2 上容器 B 之前所做的更改。但是容器 B 和节点 2 可能不会意识到这一点。这就是数据损坏发生的方式。

为了防止这种情况发生，您需要以一种避免这种情况的方式编写您的应用程序。

### 卷和持久数据 - 命令

+   `docker volume create` 是我们用来创建新卷的命令。默认情况下，卷是使用本机`local`驱动程序创建的，但您可以使用`-d`标志来指定不同的驱动程序。

+   `docker volume ls` 将列出本地 Docker 主机上的所有卷。

+   `docker volume inspect` 显示详细的卷信息。使用此命令来查找卷存在于 Docker 主机文件系统的位置。

+   `docker volume prune` 将删除**所有**未被容器或服务副本使用的卷。**谨慎使用！**

+   `docker volume rm` 删除未使用的特定卷。

### 章节总结

数据有两种主要类型：持久数据和非持久数据。持久数据是您需要保留的数据，非持久数据是您不需要保留的数据。默认情况下，所有容器都会获得与容器一起存在和消失的非持久存储，我们称之为*本地存储*，这对于非持久数据是理想的。然而，如果您的容器创建需要保留的数据，您应该将数据存储在 Docker 卷中。

Docker 卷是 Docker API 中的一流公民，并且独立于容器进行管理，具有自己的`docker volume`子命令。这意味着删除容器不会删除它正在使用的卷。

卷是在 Docker 环境中处理持久数据的推荐方式。```````````````


# 第十五章：使用 Docker 堆栈部署应用程序

在规模上部署和管理多服务应用程序是困难的。

幸运的是，Docker 堆栈在这里帮忙！它们通过提供*期望状态、滚动更新、简单的扩展操作、健康检查*等等来简化应用程序管理，所有这些都包含在一个很好的声明模型中。太棒了！

现在，如果这些术语对您来说是新的或听起来很复杂，不要担心！在本章结束时，您将理解它们！

我们将把本章分为通常的三个部分：

+   简而言之

+   深入了解

+   命令

### 使用 Docker 堆栈部署应用程序-简而言之

在您的笔记本电脑上测试和部署简单的应用程序很容易。但那是给业余爱好者的。在现实世界的生产环境中部署和管理多服务应用程序……那是给专业人士的！

幸运的是，堆栈在这里帮忙！它们让您在单个声明文件中定义复杂的多服务应用程序。它们还提供了一种简单的方式来部署应用程序并管理其整个生命周期-初始部署>健康检查>扩展>更新>回滚等等！

这个过程很简单。在*Compose 文件*中定义您的应用程序，然后使用`docker stack deploy`命令部署和管理它。就是这样！

Compose 文件包括组成应用程序的整个服务堆栈。它还包括应用程序需要的所有卷、网络、秘密和其他基础设施。然后，您可以使用`docker stack deploy`命令从文件部署应用程序。简单。

为了完成所有这些，堆栈建立在 Docker Swarm 之上，这意味着您可以获得与 Swarm 一起使用的所有安全性和高级功能。

简而言之，Docker 非常适合开发和测试。Docker 堆栈非常适合规模和生产！

### 使用 Docker 堆栈部署应用程序-深入了解

如果您了解 Docker Compose，您会发现 Docker 堆栈非常容易。实际上，在许多方面，堆栈是我们一直希望 Compose 是-完全集成到 Docker 中，并能够管理应用程序的整个生命周期。

从架构上讲，堆栈位于 Docker 应用程序层次结构的顶部。它们建立在*服务*之上，而服务又建立在容器之上。见图 14.1。

![图 14.1 AtSea Shop 高级架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure14-1.png)

图 14.1 AtSea Shop 高级架构

我们将把本章的这一部分分为以下几个部分：

+   示例应用程序概述

+   更仔细地查看堆栈文件

+   部署应用程序

+   管理应用程序

#### 示例应用程序概述

在本章的其余部分，我们将使用流行的**AtSea Shop**演示应用程序。它位于[GitHub](https://github.com/dockersamples/atsea-sample-shop-app)，并在[Apache 2.0 许可证](https://github.com/dockersamples/atsea-sample-shop-app/blob/master/LICENSE)下开源。

我们使用这个应用程序，因为它在不太大到无法在书中列出和描述的情况下，具有适度的复杂性。在底层，它是一个利用证书和密钥的多技术微服务应用程序。高级应用程序架构如图 14.2 所示。

![图 14.2 AtSea Shop 高级架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure14-2.png)

图 14.2 AtSea Shop 高级架构

正如我们所看到的，它包括 5 个*服务*，3 个网络，4 个秘密和 3 个端口映射。当我们检查堆栈文件时，我们将详细了解每一个。

> **注意：**在本章中提到*服务*时，我们指的是 Docker 服务（作为单个对象管理的容器集合和存在于 Docker API 中的服务对象）。

克隆应用程序的 GitHub 存储库，以便在本地机器上拥有所有应用程序源文件。

```
$ git clone https://github.com/dockersamples/atsea-sample-shop-app.git
Cloning into `'atsea-sample-shop-app'`...
remote: Counting objects: `636`, `done`.
remote: Total `636` `(`delta `0``)`, reused `0` `(`delta `0``)`, pack-reused `636`
Receiving objects: `100`% `(``636`/636`)`, `7`.23 MiB `|` `28`.25 MiB/s, `done`.
Resolving deltas: `100`% `(``197`/197`)`, `done`. 
```

`该应用程序由多个目录和源文件组成。请随意探索它们。但是，我们将专注于`docker-stack.yml`文件。我们将把它称为*堆栈文件*，因为它定义了应用程序及其要求。

在最高级别，它定义了 4 个顶级键。

```
`version``:`
`services``:`
`networks``:`
`secrets``:` 
```

`**版本**表示 Compose 文件格式的版本。这必须是 3.0 或更高才能与堆栈一起使用。**服务**是我们定义组成应用程序的服务堆栈的地方。**网络**列出了所需的网络，**秘密**定义了应用程序使用的秘密。

如果我们展开每个顶级键，我们将看到如何将事物映射到图 14.1。堆栈文件有五个名为“reverse_proxy”、“database”、“appserver”、“visualizer”和“payment_gateway”的服务。图 14.1 也是如此。堆栈文件有三个名为“front-tier”、“back-tier”和“payment”的网络。图 14.1 也是如此。最后，堆栈文件有四个名为“postgres_password”、“staging_token”、“revprox_key”和“revprox_cert”的秘密。图 14.1 也是如此。

```
version: "3.2"
services:
    reverse_proxy:
    database:
    appserver:
    visualizer:
    payment_gateway:
networks:
    front-tier:
    back-tier:
    payment:
secrets:
    postgres_password:
    staging_token:
    revprox_key:
    revprox_cert: 
```

`重要的是要理解，堆栈文件捕获并定义了整个应用程序的许多要求。因此，它是一种应用程序自我文档化的形式，也是弥合开发和运维之间差距的重要工具。

让我们更仔细地看看堆栈文件的每个部分。

#### 仔细查看堆栈文件

堆栈文件是一个 Docker Compose 文件。唯一的要求是`version:`键指定一个值为“3.0”或更高。有关 Compose 文件版本的最新信息，请参阅[Docker 文档](https://docs.docker.com/compose/compose-file/)。

从堆栈文件部署应用程序时，Docker 要做的第一件事是检查并创建`networks:`键下列出的网络。如果网络尚不存在，Docker 将创建它们。

让我们看看堆栈文件中定义的网络。

##### 网络

```
`networks``:`
  `front``-``tier``:`
  `back``-``tier``:`
  `payment``:`
    `driver``:` `overlay`
    `driver_opts``:`
      `encrypted``:` `'yes'` 
```

`定义了三个网络; `front-tier`，`back-tier`和`payment`。默认情况下，它们都将由`overlay`驱动程序创建为覆盖网络。但是`payment`网络很特别 - 它需要加密的数据平面。

默认情况下，所有覆盖网络的控制平面都是加密的。要加密数据平面，您有两个选择：

+   将`-o encrypted`标志传递给`docker network create`命令。

+   在堆栈文件中的`driver_opts`下指定`encrypted: 'yes'`。

加密数据平面所产生的开销取决于各种因素，如流量类型和流量流向。但是，预计它将在 10%左右。

如前所述，在创建秘密和服务之前，将创建所有三个网络。

现在让我们来看看秘密。

##### 秘密

秘密被定义为顶级对象，我们使用的堆栈文件定义了四个：

```
`secrets``:`
  `postgres_password``:`
    `external``:` `true`
  `staging_token``:`
    `external``:` `true`
  `revprox_key``:`
    `external``:` `true`
  `revprox_cert``:`
    `external``:` `true` 
```

`请注意，所有四个都被定义为`external`。这意味着它们必须在堆栈部署之前已经存在。

秘密可以在部署应用程序时按需创建 - 只需用`file: <filename>`替换`external: true`。但是，为了使其工作，主机文件系统上必须已经存在包含秘密未加密值的明文文件。这显然具有安全影响。

当我们开始部署应用程序时，我们将看到如何创建这些秘密。现在，知道应用程序定义了需要预先创建的四个秘密就足够了。

让我们来看看每个服务。

##### 服务

服务是大部分操作发生的地方。

每个服务都是一个包含一堆键的 JSON 集合（字典）。我们将逐个解释每个选项的作用。

###### 反向代理服务

正如我们所看到的，`reverse_proxy`服务定义了一个镜像、端口、秘密和网络。

```
`reverse_proxy``:`
  `image``:` `dockersamples``/``atseasampleshopapp_reverse_proxy`
  `ports``:`
    `-` `"80:80"`
    `-` `"443:443"`
  `secrets``:`
    `-` `source``:` `revprox_cert`
      `target``:` `revprox_cert`
    `-` `source``:` `revprox_key`
      `target``:` `revprox_key`
  `networks``:`
    `-` `front``-``tier` 
```

`image`键是服务对象中唯一强制的键。顾名思义，它定义了将用于构建服务副本的 Docker 镜像。

Docker 有自己的见解，因此除非另有说明，**image**将从 Docker Hub 中拉取。您可以通过在镜像名称前加上注册表的 DNS 名称来指定来自第三方注册表的镜像，例如`gcr.io`用于 Google 的容器注册表。

Docker Stacks 和 Docker Compose 之间的一个区别是，堆栈不支持**构建**。这意味着在部署堆栈之前，所有镜像都必须构建。

**ports**键定义了两个映射：

+   `80:80`将 Swarm 上的端口 80 映射到每个服务副本的端口 80。

+   `443:443`将 Swarm 上的端口 443 映射到每个服务副本的端口 443。

默认情况下，所有端口都使用*入口模式*进行映射。这意味着它们将被映射并且可以从 Swarm 中的每个节点访问 - 即使节点没有运行副本。另一种选择是*主机模式*，在这种模式下，端口仅在运行服务副本的 Swarm 节点上映射。但是，*主机模式*要求您使用长格式语法。例如，使用长格式语法在*主机模式*下映射端口 80 将是这样的：

```
ports:
  - target: 80
    published: 80
    mode: host 
```

`长格式语法是推荐的，因为它更容易阅读和更强大（支持入口模式**和**主机模式）。但是，它至少需要版本 3.2 的 Compose 文件格式。

**secrets**键定义了两个秘密 - `revprox_cert`和`revprox_key`。这些必须在顶级`secrets`键中定义，并且必须存在于系统中。

秘密作为常规文件挂载到服务副本中。文件的名称将是您在堆栈文件中指定为`target`值的内容，并且该文件将出现在 Linux 上的副本中的`/run/secrets`下，在 Windows 上为`C:\ProgramData\Docker\secrets`。Linux 将`/run/secrets`挂载为内存文件系统，但 Windows 不会。

在此服务中定义的秘密将被挂载到每个服务副本中，如`/run/secrets/revprox_cert`和`/run/secrets/revprox_key`。要将其中一个挂载为`/run/secrets/uber_secret`，您可以在堆栈文件中定义如下：

```
secrets:
  - source: revprox_cert
    target: uber_secret 
```

**networks**键确保服务的所有副本都将连接到`front-tier`网络。此处指定的网络必须在`networks`顶级键中定义，如果尚不存在，Docker 将将其创建为覆盖。

###### 数据库服务

数据库服务还定义了一个镜像、一个网络和一个秘密。除此之外，它还引入了环境变量和放置约束。

```
`database``:`
  `image``:` `dockersamples``/``atsea_db`
  `environment``:`
    `POSTGRES_USER``:` `gordonuser`
    `POSTGRES_DB_PASSWORD_FILE``:` `/run/secrets/``postgres_password`
    `POSTGRES_DB``:` `atsea`
  `networks``:`
    `-` `back``-``tier`
  `secrets``:`
    `-` `postgres_password`
  `deploy``:`
    `placement``:`
      `constraints``:`
        `-` `'node.role == worker'` 
```

**环境** 键允许您将环境变量注入服务副本。此服务使用三个环境变量来定义数据库用户、数据库密码的位置（挂载到每个服务副本中的秘密）和数据库的名称。

```
`environment``:`
  `POSTGRES_USER``:` `gordonuser`
  `POSTGRES_DB_PASSWORD_FILE``:` `/run/secrets/``postgres_password`
  `POSTGRES_DB``:` `atsea` 
```

`> **注意：** 将所有三个值作为秘密传递更安全，因为这样可以避免在明文变量中记录数据库名称和数据库用户。

该服务还在 `deploy` 键下定义了 *放置约束*。这确保了该服务的副本始终在 Swarm *worker* 节点上运行。

```
`deploy``:`
  `placement``:`
    `constraints``:`
      `-` `'node.role == worker'` 
```

放置约束是一种拓扑感知调度的形式，可以是影响调度决策的好方法。Swarm 目前允许您针对以下所有进行调度：

+   节点 ID。`node.id == o2p4kw2uuw2a`

+   节点名称。`node.hostname == wrk-12`

+   角色。`node.role != manager`

+   引擎标签。`engine.labels.operatingsystem==ubuntu 16.04`

+   自定义节点标签。`node.labels.zone == prod1`

请注意，`==` 和 `!=` 都受支持。

###### appserver 服务

`appserver` 服务使用一个镜像，连接到三个网络，并挂载一个秘密。它还在 `deploy` 键下引入了几个其他功能。

```
`appserver``:`
  `image``:` `dockersamples``/``atsea_app`
  `networks``:`
    `-` `front``-``tier`
    `-` `back``-``tier`
    `-` `payment`
  `deploy``:`
    `replicas``:` `2`
    `update_config``:`
      `parallelism``:` `2`
      `failure_action``:` `rollback`
    `placement``:`
      `constraints``:`
        `-` `'node.role == worker'`
    `restart_policy``:`
      `condition``:` `on``-``failure`
      `delay``:` `5``s`
      `max_attempts``:` `3`
      `window``:` `120``s`
  `secrets``:`
    `-` `postgres_password` 
```

让我们更仔细地看看 `deploy` 键下的新内容。

首先，`services.appserver.deploy.replicas = 2` 将设置服务的期望副本数为 2。如果省略，则默认值为 1。如果服务正在运行，并且您需要更改副本的数量，您应该以声明方式进行。这意味着在堆栈文件中更新 `services.appserver.deploy.replicas` 为新值，然后重新部署堆栈。我们稍后会看到，但重新部署堆栈不会影响您没有进行更改的服务。

`services.appserver.deploy.update_config` 告诉 Docker 在对服务进行更新时如何操作。对于此服务，Docker 将一次更新两个副本（`parallelism`），如果检测到更新失败，将执行“回滚”。回滚将基于服务的先前定义启动新的副本。`failure_action` 的默认值是 `pause`，这将停止进一步更新副本。另一个选项是 `continue`。

```
`update_config``:`
  `parallelism``:` `2`
  `failure_action``:` `rollback` 
```

`services.appserver.deploy.restart-policy`对象告诉 Swarm 如何重新启动副本（容器），如果它们失败的话。此服务的策略将在副本以非零退出代码停止时重新启动（`condition: on-failure`）。它将尝试重新启动失败的副本 3 次，并等待最多 120 秒来决定重新启动是否成功。在三次重新启动尝试之间将等待 5 秒。

```
`restart_policy``:`
  `condition``:` `on``-``failure`
  `delay``:` `5``s`
  `max_attempts``:` `3`
  `window``:` `120``s` 
```

`###### visualizer

visualizer 服务引用了一个镜像，映射了一个端口，定义了一个更新配置，并定义了一个放置约束。它还挂载了一个卷，并为容器停止操作定义了一个自定义宽限期。

```
`visualizer``:`
  `image``:` `dockersamples``/``visualizer``:``stable`
  `ports``:`
    `-` `"8001:8080"`
  `stop_grace_period``:` `1``m30s`
  `volumes``:`
    `-` `"/var/run/docker.sock:/var/run/docker.sock"`
  `deploy``:`
    `update_config``:`
      `failure_action``:` `rollback`
    `placement``:`
      `constraints``:`
        `-` `'node.role == manager'` 
```

当 Docker 停止一个容器时，它向容器内部的 PID 1 进程发出`SIGTERM`。容器（其 PID 1 进程）然后有 10 秒的宽限期来执行任何清理操作。如果它没有处理信号，它将在 10 秒后被强制终止，使用`SIGKILL`。`stop_grace_period`属性覆盖了这个 10 秒的宽限期。

`volumes`键用于将预先创建的卷和主机目录挂载到服务副本中。在这种情况下，它将`/var/run/docker.sock`从 Docker 主机挂载到每个服务副本中的`/var/run/docker.sock`。这意味着对副本中`/var/run/docker.sock`的任何读写都将通过传递到主机中的相同目录。

`/var/run/docker.sock`碰巧是 Docker 守护程序在其上公开所有 API 端点的 IPC 套接字。这意味着让容器访问它允许容器消耗所有 API 端点 - 从本质上讲，这使得容器能够查询和管理 Docker 守护程序。在大多数情况下，这是一个巨大的“不行”。但是，在实验环境中，这是一个演示应用程序。

这个服务需要访问 Docker 套接字的原因是因为它提供了 Swarm 上服务的图形表示。为了做到这一点，它需要能够查询管理节点上的 Docker 守护程序。为了实现这一点，一个放置约束强制所有服务副本进入管理节点，并且 Docker 套接字被绑定挂载到每个服务副本中。*绑定挂载*如图 14.3 所示。

![图 14.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure14-3.png)

图 14.3

###### payment_gateway

`payment_gateway`服务指定了一个镜像，挂载了一个秘密，连接到一个网络，定义了一个部分部署策略，然后施加了一些放置约束。

```
`payment_gateway``:`
  `image``:` `dockersamples``/``atseasampleshopapp_payment_gateway`
  `secrets``:`
    `-` `source``:` `staging_token`
      `target``:` `payment_token`
  `networks``:`
    `-` `payment`
  `deploy``:`
    `update_config``:`
      `failure_action``:` `rollback`
    `placement``:`
      `constraints``:`
        `-` `'node.role == worker'`
        `-` `'node.labels.pcidss == yes'` 
```

`我们之前见过所有这些选项，除了在放置约束中的`node.label`。节点标签是使用`docker node update`命令添加到 Swarm 节点的自定义定义标签。因此，它们只适用于 Swarm 中节点的角色（您不能在独立容器或 Swarm 之外利用它们）。

在这个例子中，`payment_gateway`服务执行需要在符合 PCI DSS 标准的 Swarm 节点上运行的操作。为了实现这一点，您可以将自定义*节点标签*应用到满足这些要求的任何 Swarm 节点上。在构建实验室以部署应用程序时，我们将这样做。

由于此服务定义了两个放置约束，副本将只部署到符合两者的节点。即具有`pcidss=yes`节点标签的**工作**节点。

现在我们已经完成了检查堆栈文件，我们应该对应用程序的要求有一个很好的理解。如前所述，堆栈文件是应用程序文档的重要部分。我们知道应用程序有 5 个服务，3 个网络和 4 个秘密。我们知道哪些服务连接到哪些网络，哪些端口需要发布，需要哪些镜像，甚至知道一些服务需要在特定节点上运行。

让我们部署它。

#### 部署应用程序

在我们部署应用程序之前，有一些先决条件需要处理：

+   **Swarm 模式：**我们将应用程序部署为 Docker Stack，堆栈需要 Swarm 模式。

+   **标签：**Swarm 工作节点中的一个需要一个自定义节点标签。

+   **秘密：**应用程序使用需要在部署之前预先创建的秘密。

##### 为示例应用程序构建实验室

在这一部分，我们将构建一个满足应用程序所有先决条件的三节点基于 Linux 的 Swarm 集群。一旦完成，实验室将如下所示。

![图 14.4 示例实验室](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure14-4.png)

图 14.4 示例实验室

完成以下三个步骤：

+   创建一个新的 Swarm

+   添加一个节点标签

+   创建秘密

让我们创建一个新的三节点 Swarm 集群。

1.  初始化一个新的 Swarm。

在您想要成为 Swarm 管理节点的节点上运行以下命令。

```
 $ docker swarm init
 Swarm initialized: current node (lhma...w4nn) is now a manager.
 <Snip> 
```

`* 添加工作节点。

复制在上一个命令的输出中显示的`docker swarm join`命令。将其粘贴到要加入为工作节点的两个节点中。

```
 //Worker 1 (wrk-1)
 wrk-1$ docker swarm join --token SWMTKN-1-2hl6...-...3lqg 172.31.40.192:2377
 This node joined a swarm as a worker.

 //Worker 2 (wrk-2)
 wrk-2$ docker swarm join --token SWMTKN-1-2hl6...-...3lqg 172.31.40.192:2377
 This node joined a swarm as a worker. 
```

`* 验证 Swarm 是否配置为一个管理节点和两个工作节点。

从管理节点运行此命令。

```
 $ docker node ls
 ID            HOSTNAME   STATUS     AVAILABILITY    MANAGER STATUS
 lhm...4nn *   mgr-1      Ready      Active          Leader
 b74...gz3     wrk-1      Ready      Active
 o9x...um8     wrk-2      Ready      Active 
`````

```The Swarm is now ready.

The `payment_gateway` service has set of placement constraints forcing it to only run on **worker nodes** with the `pcidss=yes` node label. In this step we’ll add that node label to `wrk-1`.

In the real world you would harden at least one of your Docker nodes to PCI standards before labelling it. However, this is just a lab, so we’ll skip the hardening step and just add the label to `wrk-1`.

Run the following commands from the Swarm manager.

1.  Add the node label to `wrk-1`.

```

$ docker node update --label-add pcidss=yes wrk-1

```

 `Node labels only apply within the Swarm.` 
`*   Verify the node label.

```

$ docker node inspect wrk-1

[

{

“ID”：“b74rzajmrimfv7hood6l4lgz3”，

“版本”：{

“索引”：27

},

“创建时间”：“2018-01-25T10:35:18.146831621Z”，

“更新时间”：“2018-01-25T10:47:57.189021202Z”，

“规格”：{

“标签”：{

“pcidss”：“是”

},

<Snip>

```` 

 ``The `wrk-1` worker node is now configured so that it can run replicas for the `payment_gateway` service.

The application defines four secrets, all of which need creating before the app can be deployed:

*   `postgress_password`
*   `staging_token`
*   `revprox_cert`
*   `revprox_key`

Run the following commands from the manager node to create them.

1.  Create a new key pair.

Three of the secrets will be populated with cryptographic keys. We’ll create the keys in this step and then place them inside of Docker secrets in the next steps.

```
 $ openssl req -newkey rsa:4096 -nodes -sha256 \
   -keyout domain.key -x509 -days 365 -out domain.crt 
```

 `You’ll have two new files in your current directory. We’ll use them in the next step.` 
`*   Create the `revprox_cert`, `revprox_key`, and `postgress_password` secrets.

```
 $ docker secret create revprox_cert domain.crt
 cqblzfpyv5cxb5wbvtrbpvrrj

 $ docker secret create revprox_key domain.key
 jqd1ramk2x7g0s2e9ynhdyl4p

 $ docker secret create postgres_password domain.key
 njpdklhjcg8noy64aileyod6l 
```

`*   Create the `staging_token` secret.

```
 $ echo staging | docker secret create staging_token -
 sqy21qep9w17h04k3600o6qsj 
```

`*   List the secrets.

```
 $ docker secret ls
 ID          NAME                CREATED              UPDATED
 njp...d6l   postgres_password   47 seconds ago       47 seconds ago
 cqb...rrj   revprox_cert        About a minute ago   About a minute ago
 jqd...l4p   revprox_key         About a minute ago   About a minute ago
 sqy...qsj   staging_token       23 seconds ago       23 seconds ago 
``````

```That’s all of the pre-requisites taken care of. Time to deploy the app!

##### Deploying the sample app

If you haven’t already done so, clone the app’s GitHub repo to your Swarm manager.

```

$ git clone https://github.com/dockersamples/atsea-sample-shop-app.git

克隆到`'atsea-sample-shop-app'`...

远程：计算对象：`636`，`完成`。

接收对象：`100`% `(``636`/636`)`, `7`.23 MiB `|` `3`.30 MiB/s，`完成`。

远程：总共`636` `（增量`0``）`，重用`0` `（增量`0``）`，包重用`636`

解决增量：`100`% `(``197`/197`)`, `完成`。

检查连通性... `完成`。

$ `cd` atsea-sample-shop-app

```

 `Now that you have the code, you are ready to deploy the app.

Stacks are deployed using the `docker stack deploy` command. In its basic form, it accepts two arguments:

*   name of the stack file
*   name of the stack

The application’s GitHub repository contains a stack file called `docker-stack.yml`, so we’ll use this as stack file. We’ll call the stack `seastack`, though you can choose a different name if you don’t like that.

Run the following commands from within the `atsea-sample-shop-app` directory on the Swarm manager.

Deploy the stack (app).

```

使用 docker 堆栈部署-docker-stack.yml seastack

创建网络 seastack_default

创建网络 seastack_back-tier

创建网络 seastack_front-tier

创建网络 seastack_payment

创建服务 seastack_database

创建服务 seastack_appserver

创建服务 seastack_visualizer

创建服务 seastack_payment_gateway

创建服务 seastack_reverse_proxy

```

 `You can run `docker network ls` and `docker service ls` commands to see the networks and services that were deployed as part of the app.

A few things to note from the output of the command.

The networks were created before the services. This is because the services attach to the networks, so need the networks to be created before they can start.

Docker prepends the name of the stack to every resource it creates. In our example, the stack is called `seastack`, so all resources are named `seastack_<resource>`. For example, the `payment` network is called `seastack_payment`. Resources that were created prior to the deployment, such as secrets, do not get renamed.

Another thing to note is the presence of a network called `seastack_default`. This isn’t defined in the stack file, so why was it created? Every service needs to attach to a network, but the `visualizer` service didn’t specify one. Therefore, Docker created one called `seastack_default` and attached it to that.

You can verify the status of a stack with a couple of commands. `docker stack ls` lists all stacks on the system, including how many services they have. `docker stack ps <stack-name>` gives more detailed information about a particular stack, such as *desired state* and *current state*. Let’s see them both.

```

$ docker stack ls

名称 服务

seastack `5`

$ docker stack ps seastack

名称 节点 期望状态 当前状态

seastack_reverse_proxy.1 wrk-2 运行 运行`7`分钟前

seastack_payment_gateway.1 wrk-1 运行 运行`7`分钟前

seastack_visualizer.1 mgr-1 运行 运行`7`分钟前

seastack_appserver.1 wrk-2 运行 运行`7`分钟前

seastack_database.1 wrk-2 运行 运行`7`分钟前

seastack_appserver.2 wrk-1 运行 运行`7`分钟前

```

 `The `docker stack ps` command is a good place to start when troubleshooting services that fail to start. It gives an overview of every service in the stack, including which node each replica is scheduled on, current state, desired state, and error message. The following output shows two failed attempts to start a replica for the `reverse_proxy` service on the `wrk-2` node.

```

$ docker stack ps seastack

名称 节点 期望的 当前 错误

状态 状态

reverse_proxy.1 wrk-2 关机 失败 `"任务：非零退出（1）"`

`\_`reverse_proxy.1 wrk-2 关机 失败 `"任务：非零退出（1）"`

```

 `For more detailed logs of a particular service you can use the `docker service logs` command. You pass it either the service name/ID, or replica ID. If you pass it the service name or ID, you’ll get the logs for all service replicas. If you pass it a particular replica ID, you’ll only get the logs for that replica.

The following `docker service logs` command shows the logs for all replicas in the `seastack_reverse_proxy` service that had the two failed replicas in the previous output.

```

$ docker service logs seastack_reverse_proxy

seastack_reverse_proxy.1.zhc3cjeti9d4@wrk-2 `|` `[`emerg`]` `1``#1: 主机未找到...`

seastack_reverse_proxy.1.6m1nmbzmwh2d@wrk-2 `|` `[`emerg`]` `1``#1: 主机未找到...`

seastack_reverse_proxy.1.6m1nmbzmwh2d@wrk-2 `|` nginx：`[`emerg`]`主机未找到..

seastack_reverse_proxy.1.zhc3cjeti9d4@wrk-2 `|` nginx：`[`emerg`]`主机未找到..

seastack_reverse_proxy.1.1tmya243m5um@mgr-1 `|` `10`.255.0.2 `"GET / HTTP/1.1"` `302`

```

 `The output is trimmed to fit the page, but you can see that logs from all three service replicas are shown (the two that failed and the one that’s running). Each line starts with the name of the replica, which includes the service name, replica number, replica ID, and name of host that it’s scheduled on. Following that is the log output.

> **Note:** You might have noticed that all of the replicas in the previous output showed as replica number 1\. This is because Docker created one at a time and only started a new one when the previous one had failed.

It’s hard to tell because the output is trimmed to fit the book, but it looks like the first two replicas failed because they were relying on something in another service that was still starting (a sort of race condition when dependent services are starting).

You can follow the logs (`--follow`), tail them (`--tail`), and get extra details (`--details`).

Now that the stack is up and running, let’s see how to manage it.

#### Managing the app

We know that a *stack* is set of related services and infrastructure that gets deployed and managed as a unit. And while that’s a fancy sentence full of buzzwords, it reminds us that the stack is built from normal Docker resources — networks, volumes, secrets, services etc. This means we can inspect and reconfigure these with their normal docker commands: `docker network`, `docker volume`, `docker secret`, `docker service`…

With this in mind, it’s possible to use the `docker service` command to manage services that are part of the stack. A simple example would be using the `docker service scale` command to increase the number of replicas in the `appserver` service. However, **this is not the recommended method!

The recommended method is the declarative method, which uses the stack file as the ultimate source of truth. As such, all changes to the stack should be made to the stack file, and the updated stack file used to redeploy the app.

Here’s a quick example of why the imperative method (making changes via the CLI) is bad:

> *Imagine that we have a stack deployed from the `docker-stack.yml` file that we cloned from GitHub earlier in the chapter. This means we have two replicas of the `appserver` service. If we use the `docker service scale` command to change that to 4 replicas, the current state of the cluster will be 4 replicas, but the stack file will still define 2\. Admittedly, that doesn’t sound like the end of the world. However, imagine we then make a different change to the stack, this time via the stack file, and we roll it out with the `docker stack deploy` command. As part of this rollout, the number of `appserver` replicas in the cluster will be rolled back to 2, because this is what the stack file defines. For this kind of reason, it is recommended to make all changes to the application via the stack file, and to manage the file in a proper version control system.*

Let’s walk through the process of making a couple of declarative changes to the stack.

We’ll make the following changes:

*   Increase the number of `appserver` replicas from 2 to 10
*   Increase the stop grace period for the visualizer service to 2 minutes

Edit the `docker-stack.yml` file and update the following two values:

*   `.services.appserver.deploy.replicas=10`
*   `.services.visualizer.stop_grace_period=2m`

The relevant sections of the stack file will now look like this:

```

<Snip>

appserver：

图像：dockersamples/atsea_app

网络：

- front-tier

- back-tier

- payment

部署：

副本: 2             <<更新值

<Snip>

visualizer:

镜像: dockersamples/visualizer:stable

端口：

- "8001:8080"

stop_grace_period: 2m     <<更新值

<Snip

```

 `Save the file and redeploy the app.

```

$ docker stack deploy -c docker-stack.yml seastack

更新服务 seastack_reverse_proxy `(`id: z4crmmrz7zi83o0721heohsku`)`

更新服务 seastack_database `(`id: 3vvpkgunetxaatbvyqxfic115`)`

更新服务 seastack_appserver `(`id: ljht639w33dhv0dmht1q6mueh`)`

更新服务 seastack_visualizer `(`id: rbwoyuciglre01hsm5fviabjf`)`

更新服务 seastack_payment_gateway `(`id: w4gsdxfnb5gofwtvmdiooqvxs`)`

```

 `Re-deploying the app like this will only update the changed components.

Run a `docker stack ps` to see the number of `appserver` replicas increasing.

```

$ docker stack ps seastack

名称                    节点     期望状态   当前状态

seastack_visualizer.1   mgr-1    运行中         运行中 `1` 秒前

seastack_visualizer.1   mgr-1    关闭        关闭 `3` 秒前

seastack_appserver.1    wrk-2    运行中         运行中 `24` 分钟前

seastack_appserver.2    wrk-1    运行中         运行中 `24` 分钟前

seastack_appserver.3    wrk-2    运行中         运行中 `1` 秒前

seastack_appserver.4    wrk-1    运行中         运行中 `1` 秒前

seastack_appserver.5    wrk-2    运行中         运行中 `1` 秒前

seastack_appserver.6    wrk-1    运行中         启动 `7` 秒前

seastack_appserver.7    wrk-2    运行中         运行中 `1` 秒前

seastack_appserver.8    wrk-1    运行中         启动 `7` 秒前

seastack_appserver.9    wrk-2    运行中         运行中 `1` 秒前

seastack_appserver.10   wrk-1    运行中         启动 `7` 秒前

```

 `The output has been trimmed so that it fits on the page, and so that only the affected services are shown.

Notice that there are two lines for the `visualizer` service. One line shows a replica that was shutdown 3 seconds ago, and the other line shows a replica that has been running for 1 second. This is because we pushed a change to the `visualizer` service, so Swarm terminated the existing replica and started a new one with the new `stop_grace_period` value.

Also note that we now have 10 replicas for the `appserver` service, and that they are in various states in the “CURRENT STATE” column — some are *running* whereas others are still *starting*.

After enough time, the cluster will converge so that *desired state* and *current state* match. At that point, what is deployed and observed on the cluster will exactly match what is defined in the stack file. This is a happy place to be :-D

This update pattern should be used for all updates to the app/stack. I.e. **all changes should be made declaratively via the stack file, and rolled out using `docker stack deploy`**.

The correct way to delete a stack is with the `docker stack rm` command. Be warned though! It deletes the stack without asking for confirmation.

```

$ docker stack rm seastack

删除服务 seastack_appserver

删除服务 seastack_database

删除服务 seastack_payment_gateway

删除服务 seastack_reverse_proxy

删除服务 seastack_visualizer

删除网络 seastack_front-tier

删除网络 seastack_payment

删除网络 seastack_default

删除网络 seastack_back-tier

```

 `Notice that the networks and services were deleted, but the secrets were not. This is because the secrets were pre-created and existed before the stack was deployed. If your stack defines volumes at the top-level, these will not be deleted by `docker stack rm` either. This is because volumes are intended as long-term persistent data stores and exist independent of the lifecycle of containers, services, and stacks.

Congratulations! You know how to deploy and manage a multi-service app using Docker Stacks.

### Deploying apps with Docker Stacks - The Commands

*   `docker stack deploy` is the command we use to deploy **and** update stacks of services defined in a stack file (usually `docker-stack.yml`).
*   `docker stack ls` will list all stacks on the Swarm, including how many services they have.
*   `docker stack ps` gives detailed information about a deployed stack. It accepts the name of the stack as its main argument, lists which node each replica is running on, and shows *desired state* and *current state*.
*   `docker stack rm` is the command to delete a stack from the Swarm. It does not ask for confirmation before deleting the stack.

### Chapter Summary

Stacks are the native Docker solution for deploying and managing multi-service applications. They’re baked into the Docker engine, and offer a simple declarative interface for deploying and managing the entire lifecycle of an application.

We start with application code and a set of infrastructure requirements — things like networks, ports, volumes and secrets. We containerize the application and group together all of the app services and infrastructure requirements into a single declarative stack file. We set the number of replicas, as well as rolling update and restart policies. Then we take the file and deploy the application from it using the `docker stack deploy` command.

Future updates to the deployed app should be done declaratively by checking the stack file out of source control, updating it, re-deploying the app, and checking the stack file back in to source control.

Because the stack file defines things like number of service replicas, you should maintain separate stack files for each of your environments, such as dev, test and prod.`````````````````````````````````
