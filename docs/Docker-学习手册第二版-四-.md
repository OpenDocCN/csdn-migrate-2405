# Docker 学习手册第二版（四）

> 原文：[`zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8`](https://zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：单主机网络

在上一章中，我们了解了处理分布式应用架构时使用的最重要的架构模式和最佳实践。

在本章中，我们将介绍 Docker 容器网络模型及其在桥接网络形式下的单主机实现。本章还介绍了软件定义网络的概念以及它们如何用于保护容器化应用程序。此外，我们将演示如何将容器端口对外开放，从而使容器化组件对外界可访问。最后，我们将介绍 Traefik，一个反向代理，它可以用于在容器之间启用复杂的 HTTP 应用级别路由。

本章涵盖以下主题：

+   解剖容器网络模型

+   网络防火墙

+   使用桥接网络

+   主机和空网络

+   在现有网络命名空间中运行

+   管理容器端口

+   使用反向代理进行 HTTP 级别路由

完成本章后，您将能够执行以下操作：

+   创建、检查和删除自定义桥接网络

+   运行连接到自定义桥接网络的容器

+   通过在不同的桥接网络上运行它们来使容器彼此隔离

+   将容器端口发布到您选择的主机端口

+   添加 Traefik 作为反向代理以启用应用级别路由

# 技术要求

对于本章，您唯一需要的是能够运行 Linux 容器的 Docker 主机。您可以使用带有 Docker for macOS 或 Windows 的笔记本电脑，或者安装了 Docker Toolbox。

# 解剖容器网络模型

到目前为止，我们大部分时间都在处理单个容器。但实际上，一个容器化的业务应用程序由多个容器组成，它们需要合作以实现目标。因此，我们需要一种让单个容器相互通信的方式。这是通过建立我们可以用来在容器之间发送数据包的路径来实现的。这些路径被称为**网络**。 Docker 定义了一个非常简单的网络模型，即所谓的**容器网络模型**（**CNM**），以指定任何实现容器网络的软件必须满足的要求。以下是 CNM 的图形表示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/01bba337-0560-4f72-a31e-7e51d7cb98ac.png)Docker CNM

CNM 有三个元素-沙盒、端点和网络：

+   **沙盒：** 沙盒完全隔离了容器与外部世界的联系。沙盒容器不允许任何入站网络连接。但是，如果绝对不可能与容器进行任何通信，那么容器在系统中就没有任何价值。为了解决这个问题，我们有第二个元素，即端点。

+   **端点：** 端点是从外部世界进入网络沙盒的受控网关，用于保护容器。端点将网络沙盒（但不是容器）连接到模型的第三个元素，即网络。

+   **网络：** 网络是传输通信实例的数据包的路径，从端点到端点，或者最终从容器到容器。

需要注意的是，网络沙盒可以有零个或多个端点，或者说，生活在网络沙盒中的每个容器可以不连接到任何网络，也可以同时连接到多个不同的网络。在前面的图表中，三个**网络沙盒**中的中间一个通过一个**端点**连接到**网络 1**和**网络 2**。

这种网络模型非常通用，不指定进行网络通信的各个容器在哪里运行。例如，所有容器可以在同一台主机上运行（本地），也可以分布在一个主机集群中（全球）。

当然，CNM 只是描述容器之间网络工作方式的模型。为了能够在容器中使用网络，我们需要 CNM 的真正实现。对于本地和全局范围，我们有多种 CNM 的实现。在下表中，我们简要概述了现有实现及其主要特点。列表没有特定顺序：

| **网络** | **公司** | **范围** | **描述** |
| --- | --- | --- | --- |
| 桥接 | Docker | 本地 | 基于 Linux 桥接的简单网络，允许在单个主机上进行网络连接 |
| Macvlan | Docker | 本地 | 在单个物理主机接口上配置多个第二层（即 MAC）地址 |
| Overlay | Docker | 全球 | 基于**虚拟可扩展局域网**（**VXLan**）的多节点容器网络 |
| Weave Net | Weaveworks | 全球 | 简单、弹性、多主机 Docker 网络 |
| Contiv 网络插件 | Cisco | 全球 | 开源容器网络 |

所有不是由 Docker 直接提供的网络类型都可以作为插件添加到 Docker 主机上。

# 网络防火墙

Docker 一直以安全第一为信条。这种理念直接影响了单个和多主机 Docker 环境中网络设计和实现的方式。软件定义网络易于创建且成本低廉，但它们可以完全防火墙连接到该网络的容器，使其与其他未连接的容器和外部世界隔离。属于同一网络的所有容器可以自由通信，而其他容器则无法这样做。

在下图中，我们有两个名为**front**和**back**的网络。连接到前端网络的有容器**c1**和**c2**，连接到后端网络的有容器**c3**和**c4**。**c1**和**c2**可以自由地相互通信，**c3**和**c4**也可以。但是**c1**和**c2**无法与**c3**或**c4**通信，反之亦然：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/dc455aaa-c719-42f7-bbe6-9183e1cc50e0.png)Docker 网络

现在，如果我们有一个由三个服务组成的应用程序：**webAPI**，**productCatalog**和**database**？我们希望**webAPI**能够与**productCatalog**通信，但不能与**database**通信，而且我们希望**productCatalog**能够与**database**服务通信。我们可以通过将**webAPI**和数据库放在不同的网络上，并将**productCatalog**连接到这两个网络来解决这个问题，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/86503975-ece8-4312-b380-9454f4494e0d.png)连接到多个网络的容器

由于创建 SDN 成本低廉，并且每个网络通过将资源与未经授权的访问隔离提供了额外的安全性，因此强烈建议您设计和运行应用程序，使其使用多个网络，并且只在绝对需要相互通信的服务上运行在同一网络上。在前面的例子中，**webAPI**组件绝对不需要直接与**database**服务通信，因此我们将它们放在了不同的网络上。如果最坏的情况发生，黑客入侵了**webAPI**，他们也无法从那里访问**database**而不同时入侵**productCatalog**服务。

# 使用桥接网络

Docker 桥接网络是我们将要详细查看的容器网络模型的第一个实现。这个网络实现是基于 Linux 桥的。当 Docker 守护程序第一次运行时，它会创建一个 Linux 桥并将其命名为`docker0`。这是默认行为，可以通过更改配置来改变。然后 Docker 使用这个 Linux 桥创建一个名为`bridge`的网络。我们在 Docker 主机上创建的所有容器，如果没有明确绑定到另一个网络，都会自动连接到这个桥接网络。

要验证我们的主机上确实有一个名为`bridge`的`bridge`类型网络，我们可以使用以下命令列出主机上的所有网络：

```
$ docker network ls
```

这应该提供类似以下的输出：

列出默认情况下所有可用的 Docker 网络

在你的情况下，ID 会有所不同，但输出的其余部分应该是一样的。我们确实有一个名为`bridge`的第一个网络，使用`bridge`驱动程序。范围为`local`只是意味着这种类型的网络受限于单个主机，不能跨多个主机。在第十三章中，*Docker Swarm 简介*，我们还将讨论其他具有全局范围的网络类型，这意味着它们可以跨整个主机集群。

现在，让我们更深入地了解一下这个桥接网络。为此，我们将使用 Docker 的`inspect`命令：

```
$ docker network inspect bridge
```

执行时，会输出有关所讨论网络的大量详细信息。这些信息应该如下所示：

检查 Docker 桥接网络时生成的输出

当我们列出所有网络时，我们看到了`ID`、`Name`、`Driver`和`Scope`的值，所以这并不是什么新鲜事。但让我们来看看**IP 地址管理**（**IPAM**）块。IPAM 是用于跟踪计算机上使用的 IP 地址的软件。`IPAM`块的重要部分是`Config`节点及其对`Subnet`和`Gateway`的值。桥接网络的子网默认定义为`172.17.0.0/16`。这意味着连接到此网络的所有容器将获得由 Docker 分配的 IP 地址，该地址取自给定范围，即`172.17.0.2`到`172.17.255.255`。`172.17.0.1`地址保留给此网络的路由器，在这种类型的网络中，其角色由 Linux 桥接器承担。我们可以预期，由 Docker 连接到此网络的第一个容器将获得`172.17.0.2`地址。所有后续容器将获得更高的编号；下图说明了这一事实：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/305f89fe-d167-4b3b-bb00-8f6bd3b8e800.png)

桥接网络

在前面的图表中，我们可以看到主机的网络命名空间，其中包括主机的**eth0**端点，如果 Docker 主机在裸机上运行，则通常是一个 NIC，如果 Docker 主机是一个 VM，则是一个虚拟 NIC。所有对主机的流量都通过**eth0**。**Linux 桥接器**负责在主机网络和桥接网络子网之间路由网络流量。

默认情况下，只允许出站流量，所有入站流量都被阻止。这意味着，虽然容器化应用可以访问互联网，但不能被任何外部流量访问。连接到网络的每个容器都会与桥接器建立自己的**虚拟以太网**（**veth**）连接。下图中有示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c4b34b80-5e37-4257-8a0e-c79110390eda.png)桥接网络的详细信息

前面的图表向我们展示了从**主机**的角度来看世界。我们将在本节的后面探讨从容器内部看这种情况是什么样子的。

我们不仅限于`bridge`网络，因为 Docker 允许我们定义自己的自定义桥接网络。这不仅是一个很好的功能，而且建议最佳实践是不要在同一个网络上运行所有容器。相反，我们应该使用额外的桥接网络来进一步隔离那些不需要相互通信的容器。要创建一个名为`sample-net`的自定义桥接网络，请使用以下命令：

```
$ docker network create --driver bridge sample-net
```

如果我们这样做，我们就可以检查 Docker 为这个新的自定义网络创建了什么子网，如下所示：

```
$ docker network inspect sample-net | grep Subnet
```

这将返回以下值：

```
"Subnet": "172.18.0.0/16",
```

显然，Docker 刚刚为我们的新自定义桥接网络分配了下一个空闲的 IP 地址块。如果出于某种原因，我们想要在创建网络时指定自己的子网范围，我们可以使用`--subnet`参数来实现：

```
$ docker network create --driver bridge --subnet "10.1.0.0/16" test-net
```

为了避免由于重复的 IP 地址而引起的冲突，请确保避免创建具有重叠子网的网络。

现在我们已经讨论了桥接网络是什么，以及我们如何创建自定义桥接网络，我们想要了解如何将容器连接到这些网络。首先，让我们交互式地运行一个 Alpine 容器，而不指定要连接的网络：

```
$ docker container run --name c1 -it --rm alpine:latest /bin/sh
```

在另一个终端窗口中，让我们检查`c1`容器：

```
$ docker container inspect c1
```

在庞大的输出中，让我们集中一下提供与网络相关信息的部分。这可以在`NetworkSettings`节点下找到。我在以下输出中列出了它：

！[](assets/aa6b5fcb-a394-4fa6-85bf-fbdced83fdbe.png)容器元数据的 NetworkSettings 部分

在前面的输出中，我们可以看到容器确实连接到了`bridge`网络，因为`NetworkID`等于`026e65...`，我们可以从前面的代码中看到这是`bridge`网络的 ID。我们还可以看到容器获得了预期的 IP 地址`172.17.0.4`，网关位于`172.17.0.1`。请注意，容器还有一个与之关联的`MacAddress`。这很重要，因为 Linux 桥使用`MacAddress`进行路由。

到目前为止，我们已经从容器的网络命名空间外部进行了讨论。现在，让我们看看当我们不仅在容器内部，而且在容器的网络命名空间内部时情况是什么样的。在`c1`容器内部，让我们使用`ip`工具来检查发生了什么。运行`ip addr`命令并观察生成的输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/27033243-df1d-4f06-bc3f-e75f79595799.png)容器命名空间，如 IP 工具所示

前面输出的有趣部分是数字`19`，即`eth0`端点。Linux 桥在容器命名空间外创建的`veth0`端点映射到容器内的`eth0`。Docker 始终将容器网络命名空间的第一个端点映射到`eth0`，从命名空间内部看。如果网络命名空间连接到其他网络，则该端点将映射到`eth1`，依此类推。

由于此时我们实际上对`eth0`以外的任何端点都不感兴趣，我们可以使用命令的更具体的变体，它将给我们以下内容：

```
/ # ip addr show eth0
195: eth0@if196: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP
 link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
 inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
 valid_lft forever preferred_lft forever
```

在输出中，我们还可以看到 Docker 将哪个 MAC 地址（`02:42:ac:11:00:02`）和哪个 IP（`172.17.0.2`）与该容器网络命名空间关联起来。

我们还可以使用`ip route`命令获取有关请求路由的一些信息：

```
/ # ip route
default via 172.17.0.1 dev eth0
172.17.0.0/16 dev eth0 scope link src 172.17.0.2
```

此输出告诉我们，所有流向网关`172.17.0.1`的流量都通过`eth0`设备路由。

现在，让我们在同一网络上运行另一个名为`c2`的容器：

```
$ docker container run --name c2 -d alpine:latest ping 127.0.0.1
```

由于我们没有指定任何其他网络，`c2`容器也将连接到`bridge`网络。它的 IP 地址将是子网中的下一个空闲地址，即`172.17.0.3`，我们可以轻松测试：

```
$ docker container inspect --format "{{.NetworkSettings.IPAddress}}" c2
172.17.0.3
```

现在，我们有两个容器连接到`bridge`网络。我们可以再次尝试检查此网络，以在输出中找到所有连接到它的容器的列表：

```
$ docker network inspect bridge
```

这些信息可以在`Containers`节点下找到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/86ee4f8a-562b-48c9-a5f5-f592fd090036.png)Docker 网络检查桥的容器部分

再次，为了可读性，我们已将输出缩短为相关部分。

现在，让我们创建两个额外的容器`c3`和`c4`，并将它们附加到`test-net`。为此，我们将使用`--network`参数：

```
$ docker container run --name c3 -d --network test-net \
 alpine:latest ping 127.0.0.1
$ docker container run --name c4 -d --network test-net \
 alpine:latest ping 127.0.0.1
```

让我们检查`network test-net`并确认`c3`和`c4`容器确实连接到它：

```
$ docker network inspect test-net
```

这将为`Containers`部分提供以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3ae3275a-6e10-49e8-8c51-59287cb8c746.png)docker network inspect test-net 命令的容器部分

接下来我们要问自己的问题是，`c3`和`c4`容器是否可以自由通信。为了证明这确实是这种情况，我们可以`exec`进入`c3`容器：

```
$ docker container exec -it c3 /bin/sh
```

进入容器后，我们可以尝试通过名称和 IP 地址 ping 容器`c4`：

```
/ # ping c4
PING c4 (10.1.0.3): 56 data bytes
64 bytes from 10.1.0.3: seq=0 ttl=64 time=0.192 ms
64 bytes from 10.1.0.3: seq=1 ttl=64 time=0.148 ms
...
```

以下是使用`c4`的 IP 地址进行 ping 的结果：

```
/ # ping 10.1.0.3
PING 10.1.0.3 (10.1.0.3): 56 data bytes
64 bytes from 10.1.0.3: seq=0 ttl=64 time=0.200 ms
64 bytes from 10.1.0.3: seq=1 ttl=64 time=0.172 ms
...
```

在这两种情况下的答案都向我们确认，连接到同一网络的容器之间的通信正常工作。我们甚至可以使用要连接的容器的名称，这表明 Docker DNS 服务提供的名称解析在这个网络内部工作。

现在，我们要确保`bridge`和`test-net`网络之间有防火墙。为了证明这一点，我们可以尝试从`c3`容器中 ping`c2`容器，无论是通过名称还是 IP 地址：

```
/ # ping c2
ping: bad address 'c2'
```

以下是使用`c2`容器的 IP 地址进行 ping 的结果：

```
/ # ping 172.17.0.3
PING 172.17.0.3 (172.17.0.3): 56 data bytes 
^C
--- 172.17.0.3 ping statistics ---
43 packets transmitted, 0 packets received, 100% packet loss
```

前面的命令一直挂起，我不得不用*Ctrl*+*C*终止命令。从 ping`c2`的输出中，我们还可以看到名称解析在网络之间不起作用。这是预期的行为。网络为容器提供了额外的隔离层，因此增强了安全性。

早些时候，我们了解到一个容器可以连接到多个网络。让我们同时将`c5`容器连接到`sample-net`和`test-net`网络：

```
$ docker container run --name c5 -d \
 --network sample-net \
 --network test-net \
 alpine:latest ping 127.0.0.1
```

现在，我们可以测试`c5`是否可以从`c2`容器中访问，类似于我们测试`c4`和`c2`容器时的情况。结果将显示连接确实有效。

如果我们想要删除一个现有的网络，我们可以使用`docker network rm`命令，但请注意我们不能意外地删除已连接到容器的网络：

```
$ docker network rm test-net
Error response from daemon: network test-net id 863192... has active endpoints
```

在我们继续之前，让我们清理并删除所有的容器：

```
$ docker container rm -f $(docker container ls -aq)
```

现在，我们可以删除我们创建的两个自定义网络：

```
$ docker network rm sample-net
$ docker network rm test-net 
```

或者，我们可以使用`prune`命令删除所有未连接到容器的网络：

```
$ docker network prune --force
```

我在这里使用了`--force`（或`-f`）参数，以防止 Docker 重新确认我是否真的要删除所有未使用的网络。

# 主机和空网络

在本节中，我们将看一下两种预定义且有些独特的网络类型，即`host`和`null`网络。让我们从前者开始。

# 主机网络

有时候，我们希望在主机的网络命名空间中运行容器。当我们需要在容器中运行用于分析或调试主机网络流量的软件时，这可能是必要的。但请记住，这些是非常特定的场景。在容器中运行业务软件时，没有任何理由将相应的容器附加到主机的网络上。出于安全原因，强烈建议您不要在生产环境或类似生产环境中运行任何附加到`host`网络的容器。

也就是说，*我们如何在主机的网络命名空间中运行容器呢？*只需将容器连接到`host`网络即可：

```
$ docker container run --rm -it --network host alpine:latest /bin/sh
```

如果我们使用`ip`工具从容器内部分析网络命名空间，我们会发现得到的结果与直接在主机上运行`ip`工具时完全相同。例如，如果我检查我的主机上的`eth0`设备，我会得到这样的结果：

```
/ # ip addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 02:50:00:00:00:01 brd ff:ff:ff:ff:ff:ff
    inet 192.168.65.3/24 brd 192.168.65.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::c90b:4219:ddbd:92bf/64 scope link
       valid_lft forever preferred_lft forever
```

在这里，我可以看到`192.168.65.3`是主机分配的 IP 地址，这里显示的 MAC 地址也对应于主机的 MAC 地址。

我们还可以检查路由，得到以下结果（缩短）：

```
/ # ip route
default via 192.168.65.1 dev eth0 src 192.168.65.3 metric 202
10.1.0.0/16 dev cni0 scope link src 10.1.0.1
127.0.0.0/8 dev lo scope host
172.17.0.0/16 dev docker0 scope link src 172.17.0.1
...
192.168.65.0/24 dev eth0 scope link src 192.168.65.3 metric 202
```

在让您继续阅读本章的下一部分之前，我再次要指出，使用`host`网络是危险的，如果可能的话应该避免使用。

# 空网络

有时候，我们需要运行一些不需要任何网络连接来执行任务的应用服务或作业。强烈建议您将这些应用程序运行在附加到`none`网络的容器中。这个容器将完全隔离，因此不会受到任何外部访问的影响。让我们运行这样一个容器：

```
$ docker container run --rm -it --network none alpine:latest /bin/sh
```

一旦进入容器，我们可以验证没有`eth0`网络端点可用：

```
/ # ip addr show eth0
ip: can't find device 'eth0'
```

也没有可用的路由信息，我们可以使用以下命令来证明：

```
/ # ip route
```

这将返回空值。

# 在现有的网络命名空间中运行

通常，Docker 为我们运行的每个容器创建一个新的网络命名空间。容器的网络命名空间对应于我们之前描述的容器网络模型的沙盒。当我们将容器连接到网络时，我们定义一个端点，将容器的网络命名空间与实际网络连接起来。这样，我们每个网络命名空间有一个容器。

Docker 为我们提供了另一种定义容器运行的网络命名空间的方法。在创建新容器时，我们可以指定它应该附加到（或者我们应该说包含在）现有容器的网络命名空间中。通过这种技术，我们可以在单个网络命名空间中运行多个容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/fab345c0-6d16-4d82-ab56-ed17edd9cb1c.png)在单个网络命名空间中运行多个容器

在前面的图中，我们可以看到在最左边的**网络** **命名空间**中，我们有两个容器。由于它们共享相同的命名空间，这两个容器可以在本地主机上相互通信。然后将网络命名空间（而不是单个容器）附加到**网络 1**。

当我们想要调试现有容器的网络而不在该容器内运行其他进程时，这是非常有用的。我们只需将特殊的实用容器附加到要检查的容器的网络命名空间即可。这个特性也被 Kubernetes 在创建 pod 时使用。我们将在本书的第十五章中学习更多关于 Kubernetes 和 pod 的知识，*Kubernetes 简介*。

现在，让我们演示一下这是如何工作的：

1.  首先，我们创建一个新的桥接网络：

```
$ docker network create --driver bridge test-net
```

1.  接下来，我们运行一个附加到这个网络的容器：

```
$ docker container run --name web -d \
 --network test-net nginx:alpine
```

1.  最后，我们运行另一个容器并将其附加到我们的`web`容器的网络中：

```
$ docker container run -it --rm --network container:web \
alpine:latest /bin/sh
```

特别要注意我们如何定义网络：`--network container:web`。这告诉 Docker 我们的新容器应该使用与名为`web`的容器相同的网络命名空间。

1.  由于新容器与运行 nginx 的 web 容器在相同的网络命名空间中，我们现在可以在本地访问 nginx！我们可以通过使用 Alpine 容器的一部分的`wget`工具来证明这一点，以连接到 nginx。我们应该看到以下内容：

```
/ # wget -qO - localhost
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
</html>
```

请注意，为了便于阅读，我们已经缩短了输出。还请注意，在运行附加到相同网络的两个容器和在相同网络命名空间中运行两个容器之间存在重要区别。在这两种情况下，容器可以自由地相互通信，但在后一种情况下，通信发生在本地主机上。

1.  要清理容器和网络，我们可以使用以下命令：

```
$ docker container rm --force web
$ docker network rm test-net
```

在下一节中，我们将学习如何在容器主机上公开容器端口。

# 管理容器端口

现在我们知道了我们可以通过将它们放在不同的网络上来隔离防火墙容器，并且我们可以让一个容器连接到多个网络，但是还有一个问题没有解决。*我们如何将应用服务暴露给外部世界？*想象一下一个容器运行着一个 Web 服务器，托管着我们之前的 WebAPI。我们希望来自互联网的客户能够访问这个 API。我们已经设计它为一个公开访问的 API。为了实现这一点，我们必须象征性地打开我们防火墙中的一个门，通过这个门我们可以将外部流量传递到我们的 API。出于安全原因，我们不只是想要敞开大门；我们希望有一个单一受控的门，流量可以通过。

我们可以通过将容器端口映射到主机上的一个可用端口来创建这样的门。我们也称之为打开一个通往容器端口的门以发布一个端口。请记住，容器有自己的虚拟网络堆栈，主机也有。因此，默认情况下，容器端口和主机端口完全独立存在，根本没有任何共同之处。但是现在我们可以将一个容器端口与一个空闲的主机端口连接起来，并通过这个链接传递外部流量，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ed84f752-d199-4870-90eb-1ee9216cc749.png)

将容器端口映射到主机端口

但现在，是时候演示如何实际将容器端口映射到主机端口了。这是在创建容器时完成的。我们有不同的方法来做到这一点：

1.  首先，我们可以让 Docker 决定将我们的容器端口映射到哪个主机端口。Docker 将在 32xxx 范围内选择一个空闲的主机端口进行自动映射，这是通过使用`-P`参数完成的：

```
$ docker container run --name web -P -d nginx:alpine
```

上述命令在一个容器中运行了一个 nginx 服务器。nginx 在容器内部监听端口`80`。使用`-P`参数，我们告诉 Docker 将所有暴露的容器端口映射到 32xxx 范围内的一个空闲端口。我们可以通过使用`docker container port`命令找出 Docker 正在使用的主机端口：

```
$ docker container port web
80/tcp -> 0.0.0.0:32768
```

nginx 容器只暴露端口`80`，我们可以看到它已经映射到主机端口`32768`。如果我们打开一个新的浏览器窗口并导航到`localhost:32768`，我们应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6b50f760-dad5-486e-bc18-2cec42bbaae3.png)

nginx 的欢迎页面

1.  找出 Docker 用于我们的容器的主机端口的另一种方法是检查它。主机端口是`NetworkSettings`节点的一部分：

```
$ docker container inspect web | grep HostPort
32768
```

1.  最后，获取这些信息的第三种方法是列出容器：

```
$ docker container ls
CONTAINER ID    IMAGE         ...   PORTS                  NAMES
56e46a14b6f7    nginx:alpine  ...   0.0.0.0:32768->80/tcp  web
```

请注意，在上述输出中，`/tcp`部分告诉我们该端口已经为 TCP 协议通信打开，但未为 UDP 协议打开。TCP 是默认的，如果我们想指定为 UDP 打开端口，那么我们必须明确指定。映射中的`0.0.0.0`告诉我们，任何主机 IP 地址的流量现在都可以到达`web`容器的端口`80`。

有时，我们想将容器端口映射到一个非常特定的主机端口。我们可以使用`-p`参数（或`--publish`）来实现这一点。让我们看看如何使用以下命令来实现这一点：

```
$ docker container run --name web2 -p 8080:80 -d nginx:alpine
```

`-p`参数的值的格式为`<主机端口>:<容器端口>`。因此，在上述情况中，我们将容器端口`80`映射到主机端口`8080`。一旦`web2`容器运行，我们可以通过浏览器导航到`localhost:8080`来测试它，我们应该会看到与处理自动端口映射的上一个示例中看到的相同的 nginx 欢迎页面。

使用 UDP 协议进行特定端口通信时，`publish`参数看起来像`-p 3000:4321/udp`。请注意，如果我们想要允许在同一端口上使用 TCP 和 UDP 协议进行通信，那么我们必须分别映射每个协议。

# 使用反向代理进行 HTTP 级别的路由

想象一下，你被要求将一个庞大的应用程序容器化。这个应用程序多年来已经自然地演变成了一个难以维护的怪物。由于代码库中存在紧密耦合，即使是对源代码进行微小的更改也可能会破坏其他功能。由于其复杂性，发布版本很少，并且需要整个团队全力以赴。在发布窗口期间必须关闭应用程序，这会给公司带来很大的损失，不仅是由于失去的机会，还有他们的声誉损失。

管理层已决定结束这种恶性循环，并通过容器化单体应用来改善情况。这一举措将大大缩短发布之间的时间，正如行业所见。在随后的步骤中，公司希望从单体应用中分离出每一个功能，并将它们实现为微服务。这个过程将持续进行，直到单体应用完全被分解。

但正是这第二点让参与其中的团队感到困惑。我们如何将单体应用分解为松耦合的微服务，而不影响单体应用的众多客户？单体应用的公共 API 虽然非常复杂，但设计得很结构化。公共 URI 已经经过精心设计，绝对不能改变。例如，应用程序中实现了一个产品目录功能，可以通过`https://acme.com/catalog?category=bicycles`来访问，以便我们可以访问公司提供的自行车列表。

另一方面，有一个名为`https://acme.com/checkout`的 URL，我们可以用它来启动客户购物车的结账，等等。我希望大家清楚我们要做什么。

# 容器化单体应用

让我们从单体应用开始。我已经准备了一个简单的代码库，它是用 Python 2.7 实现的，并使用 Flask 来实现公共 REST API。示例应用程序并不是一个完整的应用程序，但足够复杂，可以进行一些重新设计。示例代码可以在`ch10/e-shop`文件夹中找到。在这个文件夹中有一个名为`monolith`的子文件夹，其中包含 Python 应用程序。按照以下步骤进行：

1.  在新的终端窗口中，导航到该文件夹，安装所需的依赖项，并运行应用程序：

```
$ cd ~/fod/ch10/e-shop/monolith
$ pip install -r requirements.txt
$ export FLASK_APP=main.py 
$ flask run
```

应用程序将在`localhost`的`5000`端口上启动并监听：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0898d2ee-bb7a-47ed-a3b3-d4b30633783d.png)

运行 Python 单体应用

1.  我们可以使用`curl`来测试应用程序。使用以下命令来检索公司提供的所有自行车的列表：

```
$ curl localhost:5000/catalog?category=bicycles [{"id": 1, "name": "Mountanbike Driftwood 24\"", "unitPrice": 199}, {"id": 2, "name": "Tribal 100 Flat Bar Cycle Touring Road Bike", "unitPrice": 300}, {"id": 3, "name": "Siech Cycles Bike (58 cm)", "unitPrice": 459}]
```

您应该看到一个 JSON 格式的自行车类型列表。好吧，目前为止一切顺利。

1.  现在，让我们更改`hosts`文件，为`acme.com`添加一个条目，并将其映射到`127.0.0.1`，即环回地址。这样，我们可以模拟一个真实的客户端使用 URL `http://acme.cnoteom/catalog?category=bicycles` 访问应用程序，而不是使用`localhost`。在 macOS 或 Linux 上，您需要使用 sudo 来编辑 hosts 文件。您应该在`hosts`文件中添加一行，看起来像这样：

```
127.0.0.1  acme.com  
```

1.  保存您的更改，并通过 ping `acme.com`来确认它是否正常工作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/68e14aa6-b00c-441b-a1c9-bcc6d6804765.png)

通过`hosts`文件将`acme.com`映射到环回地址在 Windows 上，您可以通过以管理员身份运行记事本，打开`c:\Windows\System32\Drivers\etc\hosts`文件并修改它来编辑文件。

经过所有这些步骤，现在是时候将应用程序容器化了。我们需要做的唯一更改是确保应用程序 Web 服务器侦听`0.0.0.0`而不是`localhost`。

1.  我们可以通过修改应用程序并在`main.py`的末尾添加以下启动逻辑来轻松实现这一点：

```
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

然后，我们可以使用`python main.py`启动应用程序。

1.  现在，在`monolith`文件夹中添加一个`Dockerfile`，内容如下：

```
FROM python:3.7-alpine
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD python main.py
```

1.  在您的终端窗口中，从单体文件夹中执行以下命令，为应用程序构建 Docker 镜像：

```
$ docker image build -t acme/eshop:1.0 .
```

1.  构建完镜像后，尝试运行应用程序：

```
$ docker container run --rm -it \
 --name eshop \
 -p 5000:5000 \
 acme/eshop:1.0
```

请注意，现在在容器内运行的应用程序的输出与在主机上直接运行应用程序时获得的输出是无法区分的。现在，我们可以使用两个`curl`命令来访问目录和结账逻辑，测试应用程序是否仍然像以前一样工作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/eb78770c-6b08-4775-aa10-bddd915b27ce.png)

在容器中运行时测试单体应用程序

显然，即使使用正确的 URL，即`http://acme.com`，单体仍然以与以前完全相同的方式工作。太好了！现在，让我们将单体的一部分功能拆分为一个 Node.js 微服务，这将被单独部署。

# 提取第一个微服务

团队经过一番头脑风暴后决定，产品`catalog`是第一个具有内聚力且足够独立的功能片段，可以从单体中提取出来作为微服务实现。他们决定将产品目录实现为一个基于 Node.js 的微服务。

您可以在项目文件夹的`e-shop`的`catalog`子文件夹中找到他们提出的代码和`Dockerfile`。这是一个简单的 Express.js 应用程序，复制了以前在单体中可用的功能。让我们开始吧：

1.  在您的终端窗口中，从`catalog`文件夹中构建这个新的微服务的 Docker 镜像：

```
$ docker image build -t acme/catalog:1.0 .
```

1.  然后，从您刚刚构建的新镜像中运行一个容器：

```
$ docker run --rm -it --name catalog -p 3000:3000 acme/catalog:1.0
```

1.  从另一个终端窗口中，尝试访问微服务并验证它返回与单体相同的数据：

```
$ curl http://acme.com:3000/catalog?type=bicycle
```

请注意与访问单体应用程序中相同功能时的 URL 的差异。在这里，我们正在访问端口`3000`上的微服务（而不是`5000`）。但是我们说过，我们不想改变访问我们电子商店应用程序的客户端。我们能做什么？幸运的是，有解决这类问题的解决方案。我们需要重新路由传入的请求。我们将在下一节中向您展示如何做到这一点。

# 使用 Traefik 重新路由流量

在上一节中，我们意识到我们将不得不将以`http://acme.com:5000/catalog`开头的目标 URL 的传入流量重新路由到另一个 URL，例如`product-catalog:3000/catalog`。我们将使用 Traefik 来偏向这样做。

Traefik 是一个云原生边缘路由器，它是开源的，这对我们来说非常好。它甚至有一个漂亮的 Web UI，您可以用来管理和监视您的路由。Traefik 可以与 Docker 非常直接地结合使用，我们马上就会看到。

为了与 Docker 很好地集成，Traefik 依赖于在每个容器或服务中找到的元数据。这些元数据可以以包含路由信息的标签的形式应用。

首先，让我们看一下如何运行目录服务：

1.  这是 Docker `run`命令：

```
$ docker container run --rm -d \
 --name catalog \
 --label traefik.enable=true \
 --label traefik.port=3000 \
 --label traefik.priority=10 \
 --label traefik.http.routers.catalog.rule="Host(\"acme.com\") && PathPrefix(\"/catalog\")" \
 acme/catalog:1.0
```

1.  让我们快速看一下我们定义的四个标签：

+   +   `traefik.enable=true`：这告诉 Traefik 这个特定的容器应该包括在路由中（默认值为`false`）。

+   `traefik.port=3000`：路由器应将调用转发到端口`3000`（这是 Express.js 应用程序正在监听的端口）。

+   `traefik.priority=10`：给这条路线高优先级。我们马上就会看到为什么。

+   `traefik.http.routers.catalog.rule="Host(\"acme.com\") && PathPrefix(\"/catalog\")"`：路由必须包括主机名`acme.com`，路径必须以`/catalog`开头才能被重定向到该服务。例如，`acme.com/catalog?type=bicycles`符合此规则。

请注意第四个标签的特殊形式。它的一般形式是`traefik.http.routers.<service name>.rule`。

1.  现在，让我们看看如何运行`eshop`容器：

```
$ docker container run --rm -d \
    --name eshop \
    --label traefik.enable=true \
    --label traefik.port=5000 \
    --label traefik.priority=1 \
    --label traefik.http.routers.eshop.rule="Host(\"acme.com\")" \
    acme/eshop:1.0
```

在这里，我们将任何匹配的调用转发到端口`5000`，这对应于`eshop`应用程序正在监听的端口。请注意优先级设置为`1`（低）。这与`catalog`服务的高优先级结合起来，使我们能够过滤出所有以`/catalog`开头的 URL，并将其重定向到`catalog`服务，而所有其他 URL 将转到`eshop`服务。

1.  现在，我们终于可以将 Traefik 作为边缘路由器运行，它将作为我们应用程序前面的反向代理。这是我们启动它的方式：

```
$ docker run -d \
 --name traefik \
 -p 8080:8080 \
 -p 80:80 \
 -v /var/run/docker.sock:/var/run/docker.sock \
 traefik:v2.0 --api.insecure=true --providers.docker

```

注意我们如何将 Docker 套接字挂载到容器中，以便 Traefik 可以与 Docker 引擎交互。我们将能够将 Web 流量发送到 Traefik 的端口`80`，然后根据参与容器的元数据中的路由定义，根据我们的规则进行重定向。此外，我们可以通过端口`8080`访问 Traefik 的 Web UI。

现在一切都在运行，即单体应用程序，第一个名为`catalog`的微服务和 Traefik，我们可以测试一切是否按预期工作。再次使用`curl`来测试：

```
$ curl http://acme.com/catalog?type=bicycles
$ curl http://acme.com/checkout
```

正如我们之前提到的，现在我们将所有流量发送到端口`80`，这是 Traefik 正在监听的端口。然后，这个代理将把流量重定向到正确的目的地。

在继续之前，请停止所有容器：

```
$ docker container rm -f traefik eshop catalog
```

这就是本章的全部内容。

# 摘要

在本章中，我们了解了单个主机上运行的容器如何相互通信。首先，我们看了一下 CNM，它定义了容器网络的要求，然后我们调查了 CNM 的几种实现，比如桥接网络。然后我们详细了解了桥接网络的功能，以及 Docker 提供给我们有关网络和连接到这些网络的容器的信息。我们还学习了如何从容器的内外采用两种不同的视角。最后，我们介绍了 Traefik 作为一种提供应用级路由到我们的应用程序的手段。

在下一章中，我们将介绍 Docker Compose。我们将学习如何创建一个由多个服务组成的应用程序，每个服务在一个容器中运行，并且 Docker Compose 如何允许我们使用声明性方法轻松构建、运行和扩展这样的应用程序。

# 问题

为了评估您从本章中获得的技能，请尝试回答以下问题：

1.  命名**容器网络模型**（**CNM**）的三个核心元素。

1.  如何创建一个名为`frontend`的自定义桥接网络？

1.  如何运行两个连接到`frontend`网络的`nginx:alpine`容器？

1.  对于`frontend`网络，获取以下内容：

+   所有连接的容器的 IP 地址

+   与网络相关联的子网

1.  `host`网络的目的是什么？

1.  使用`host`网络适用的一个或两个场景的名称。

1.  `none`网络的目的是什么？

1.  在什么情况下应该使用`none`网络？

1.  为什么我们会与容器化应用一起使用反向代理，比如 Traefik？

# 进一步阅读

以下是一些更详细描述本章主题的文章：

+   Docker 网络概述：[`dockr.ly/2sXGzQn`](http://dockr.ly/2sXGzQn)

+   容器网络：[`dockr.ly/2HJfQKn`](http://dockr.ly/2HJfQKn)

+   什么是桥接网络？：[`bit.ly/2HyC3Od`](https://bit.ly/2HyC3Od)

+   使用桥接网络：[`dockr.ly/2BNxjRr`](http://dockr.ly/2BNxjRr)

+   使用 Macvlan 网络：[`dockr.ly/2ETjy2x`](http://dockr.ly/2ETjy2x)

+   使用主机网络进行网络连接：[`dockr.ly/2F4aI59`](http://dockr.ly/2F4aI59)


# 第十一章：Docker Compose

在上一章中，我们学到了关于容器网络在单个 Docker 主机上是如何工作的。我们介绍了**容器网络模型**（**CNM**），它构成了 Docker 容器之间所有网络的基础，然后我们深入研究了 CNM 的不同实现，特别是桥接网络。最后，我们介绍了 Traefik，一个反向代理，以实现容器之间复杂的 HTTP 应用级路由。

本章介绍了一个应用程序由多个服务组成的概念，每个服务在一个容器中运行，以及 Docker Compose 如何允许我们使用声明式方法轻松构建、运行和扩展这样的应用程序。

本章涵盖以下主题：

+   揭秘声明式与命令式

+   运行多服务应用程序

+   扩展服务

+   构建和推送应用程序

+   使用 Docker Compose 覆盖

完成本章后，读者将能够做到以下事情：

+   用几句简短的话解释命令式和声明式方法在定义和运行应用程序方面的主要区别

+   用自己的话描述容器和 Docker Compose 服务之间的区别

+   为简单的多服务应用程序编写 Docker Compose YAML 文件

+   使用 Docker Compose 构建、推送、部署和拆除简单的多服务应用程序

+   使用 Docker Compose 扩展和缩减应用服务

+   使用覆盖定义特定于环境的 Docker Compose 文件

# 技术要求

本章附带的代码可以在以下位置找到：[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch11`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition/tree/master/ch11)。

您需要在系统上安装`docker-compose`。如果您在 Windows 或 macOS 计算机上安装了 Docker for Desktop 或 Docker Toolbox，则这是自动的。否则，您可以在这里找到详细的安装说明：[`docs.docker.com/compose/install/`](https://docs.docker.com/compose/install/)

# 揭秘声明式与命令式

Docker Compose 是 Docker 提供的一个工具，主要用于在单个 Docker 主机上运行和编排容器。这包括但不限于开发、**持续集成**（**CI**）、自动化测试、手动 QA 或演示。

Docker Compose 使用 YAML 格式的文件作为输入。默认情况下，Docker Compose 期望这些文件被称为`docker-compose.yml`，但也可以使用其他名称。`docker-compose.yml`的内容被称为描述和运行一个可能由多个容器组成的容器化应用程序的*声明性*方式。

那么，*声明性的意思是什么呢？*

首先，*声明性*是*命令式*的反义词。好吧，这并没有太大帮助。既然我介绍了另一个定义，我需要解释这两个定义：

+   **命令式：**这是一种通过指定系统必须遵循的确切过程来解决问题的方式。

如果我命令式地告诉 Docker 守护程序如何运行一个应用程序，那意味着我必须逐步描述系统必须做什么，以及如果发生意外情况时系统必须如何反应。我必须非常明确和精确地说明我的指示。我需要涵盖所有边缘情况以及它们需要如何处理。

+   **声明式：**这是一种解决问题的方式，不需要程序员指定要遵循的确切过程。

声明性方法意味着我告诉 Docker 引擎我的应用程序的期望状态是什么，它必须自行解决如何实现这个期望状态，以及如果系统偏离了这个状态，如何调和它。

Docker 在处理容器化应用程序时明确推荐使用声明性方法。因此，Docker Compose 工具使用了这种方法。

# 运行多服务应用程序

在大多数情况下，应用程序不仅由一个单块组成，而是由几个应用程序服务共同工作。使用 Docker 容器时，每个应用程序服务都在自己的容器中运行。当我们想要运行这样一个多服务应用程序时，当然可以使用众所周知的`docker container run`命令启动所有参与的容器，我们在之前的章节中已经这样做了。但这充其量是低效的。使用 Docker Compose 工具，我们可以以声明性的方式在使用 YAML 格式的文件中定义应用程序。

让我们来看一个简单的`docker-compose.yml`文件的内容：

```
version: "2.4"
services:
 web:
    image: fundamentalsofdocker/ch11-web:2.0
    build: web
    ports:
    - 80:3000
 db:
    image: fundamentalsofdocker/ch11-db:2.0
    build: db
    volumes:
    - pets-data:/var/lib/postgresql/data

volumes:
 pets-data:
```

文件中的行解释如下：

+   `version`：在这一行中，我们指定要使用的 Docker Compose 格式的版本。在撰写本文时，这是 2.4 版本。

+   `服务`：在这一部分，我们在`services`块中指定了构成我们应用程序的服务。在我们的示例中，我们有两个应用程序服务，我们称它们为`web`和`db`：

+   `web`：`web`服务使用一个名为`fundamentalsofdocker/ch11-web:2.0`的镜像，如果镜像不在镜像缓存中，它将从`web`文件夹中的`Dockerfile`构建。该服务还将容器端口`3000`发布到主机端口`80`。

+   `db`：另一方面，`db`服务使用的是镜像名称`fundamentalsofdocker/ch11-db:2.0`，这是一个定制的 PostgreSQL 数据库。同样，如果镜像不在缓存中，它将从`db`文件夹中的`Dockerfile`构建。我们将一个名为`pets-data`的卷挂载到`db`服务的容器中。

+   `卷`：任何服务使用的卷都必须在此部分声明。在我们的示例中，这是文件的最后一部分。第一次运行应用程序时，Docker 将创建一个名为`pets-data`的卷，然后在后续运行中，如果卷仍然存在，它将被重用。当应用程序由于某种原因崩溃并需要重新启动时，这可能很重要。然后，先前的数据仍然存在并准备好供重新启动的数据库服务使用。

请注意，我们使用的是 Docker Compose 文件语法的 2.x 版本。这是针对单个 Docker 主机部署的版本。Docker Compose 文件语法还存在 3.x 版本。当您想要定义一个针对 Docker Swarm 或 Kubernetes 的应用程序时，可以使用此版本。我们将从第十二章开始更详细地讨论这个问题，*编排器*。

# 使用 Docker Compose 构建镜像

导航到`fods`文件夹的`ch11`子文件夹，然后构建镜像：

```
$ cd ~/fod/ch11
$ docker-compose build
```

如果我们输入上述命令，那么工具将假定当前目录中必须有一个名为`docker-compose.yml`的文件，并将使用该文件来运行。在我们的情况下，确实如此，工具将构建镜像。

在您的终端窗口中，您应该看到类似于这样的输出：

！[](assets/9c627297-4997-47b2-804b-19cc63213e24.png)

为 web 服务构建 Docker 镜像

在上述屏幕截图中，您可以看到`docker-compose`首先从 Docker Hub 下载了基本图像`node:12.12-alpine`，用于我们正在构建的 Web 图像。 随后，它使用`web`文件夹中找到的`Dockerfile`构建图像，并将其命名为`fundamentalsofdocker/ch11-web:2.0`。 但这只是第一部分； 输出的第二部分应该类似于这样：

浏览器中的示例应用程序

创建了两个服务，`ch11_web_1`和`ch11_db_1`，并将它们附加到网络

在这里，`docker-compose`再次从 Docker Hub 拉取基本图像`postgres:12.0-alpine`，然后使用`db`文件夹中找到的`Dockerfile`构建我们称为`fundamentalsofdocker/ch11-db:2.0`的图像。

# 使用 Docker Compose 运行应用程序

构建了 db 服务的 Docker 镜像

```
$ docker-compose up
```

输出将向我们展示应用程序的启动。 我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ac776f44-7157-4362-afa0-9cc470ee5b4b.png)运行示例应用程序，第一部分

在输出的第一部分中，我们看到 Docker Compose 执行以下操作：

+   现在让我们看一下输出的第二部分：

+   创建名为`ch11_pets-data`的卷

+   现在我们可以打开一个浏览器标签，并导航到`localhost/animal`。 我们应该会看到我在肯尼亚马赛马拉国家公园拍摄的一张野生动物的照片：

Docker Compose 还显示了数据库（蓝色）和 Web 服务（黄色）生成的日志输出。 倒数第三行的输出向我们展示了 Web 服务已准备就绪，并在端口`3000`上监听。 请记住，这是容器端口，而不是主机端口。 我们已将容器端口`3000`映射到主机端口`80`，这是我们稍后将访问的端口。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3fe4b4e5-ab79-4dbe-ae7a-46388ff69cd4.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c7d558d6-4970-4696-a92c-6bd8fc46128e.png)运行示例应用程序，第二部分

我们已经缩短了输出的第二部分。 它向我们展示了数据库如何完成初始化。 我们可以具体看到我们的初始化脚本`init-db.sql`的应用，该脚本定义了一个数据库并用一些数据填充它。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/fa80d99d-40f4-45af-99d6-ec013f32cdba.png)

创建名为`ch11_default`的桥接网络

一旦我们构建了图像，就可以使用 Docker Compose 启动应用程序：

刷新浏览器几次以查看其他猫的图片。 应用程序从数据库中存储的 12 个图像的 URL 中随机选择当前图像。

由于应用程序正在交互模式下运行，因此我们运行 Docker Compose 的终端被阻塞，我们可以通过按*Ctrl*+*C*来取消应用程序。如果我们这样做，我们会看到以下内容：

```
^CGracefully stopping... (press Ctrl+C again to force)
Stopping ch11_web_1 ... done
Stopping ch11_db_1 ... done
```

我们会注意到数据库和 web 服务会立即停止。不过有时，一些服务可能需要大约 10 秒钟才能停止。原因是数据库和 web 服务监听并对 Docker 发送的`SIGTERM`信号做出反应，而其他服务可能不会，因此 Docker 在预定义的 10 秒超时间隔后将它们杀死。

如果我们再次使用`docker-compose up`运行应用程序，输出将会更短：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/24c4d502-363e-4c41-a0c7-f441ac0e6cee.png)docker-compose up 的输出

这一次，我们不需要下载镜像，数据库也不需要从头开始初始化，而是只是重用了上一次运行中已经存在的`pets-data`卷中的数据。

我们也可以在后台运行应用程序。所有容器将作为守护进程运行。为此，我们只需要使用`-d`参数，如下面的代码所示：

```
$ docker-compose up -d
```

Docker Compose 为我们提供了许多比`up`更多的命令。我们可以使用这个工具来列出应用程序中的所有服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4de77740-ac1d-4bb2-9f8f-0c0b203897d4.png)docker-compose ps 的输出

这个命令类似于`docker container ls`，唯一的区别是`docker-compose`只列出应用程序中的容器或服务。

要停止和清理应用程序，我们使用`docker-compose down`命令：

```
$ docker-compose down
Stopping ch11_web_1 ... done
Stopping ch11_db_1 ... done
Removing ch11_web_1 ... done
Removing ch11_db_1 ... done
Removing network ch11_default
```

如果我们还想删除数据库的卷，那么我们可以使用以下命令：

```
$ docker volume rm ch11_pets-data
```

或者，我们可以将`docker-compose down`和`docker volume rm <volume name>`两个命令合并成一个单一的命令：

```
$ docker-compose down -v
```

在这里，参数`-v`（或`--volumes`）会移除在`compose`文件的`volumes`部分声明的命名卷和附加到容器的匿名卷。

为什么卷的名称中有一个`ch11`前缀？在`docker-compose.yml`文件中，我们已经调用了要使用的卷为`pets-data`。但是，正如我们已经提到的，Docker Compose 会用父文件夹的名称加上下划线作为所有名称的前缀。在这种情况下，父文件夹的名称叫做`ch11`。如果你不喜欢这种方法，你可以显式地定义一个项目名称，例如：

```
$ docker-compose -p my-app up
```

它使用了一个名为 my-app 的项目名称来运行应用程序。

# 扩展服务

现在，让我们假设我们的示例应用程序已经在网络上运行并且变得非常成功。很多人想要看我们可爱的动物图片。所以现在我们面临一个问题，因为我们的应用程序开始变慢了。为了解决这个问题，我们想要运行多个 web 服务的实例。使用 Docker Compose，这很容易实现。

运行更多实例也被称为扩展。我们可以使用这个工具将我们的`web`服务扩展到，比如说，三个实例：

```
$ docker-compose up --scale web=3
```

如果我们这样做，我们会有一个惊喜。输出将类似于以下的截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6c367f83-aae2-4c84-b5bb-6547f80846ae.png)docker-compose --scale 的输出

web 服务的第二个和第三个实例无法启动。错误消息告诉我们原因：我们不能多次使用相同的主机端口`80`。当第 2 和第 3 个实例尝试启动时，Docker 意识到端口`80`已经被第一个实例占用。*我们能做什么？*嗯，我们可以让 Docker 决定为每个实例使用哪个主机端口。

如果在`compose`文件的`ports`部分中，我们只指定容器端口，而不指定主机端口，那么 Docker 会自动选择一个临时端口。让我们就这样做：

1.  首先，让我们拆除应用程序：

```
$ docker-compose down
```

1.  然后，我们修改`docker-compose.yml`文件如下所示：

```
version: "2.4"
services:
  web:
    image: fundamentalsofdocker/ch11-web:2.0
    build: web
    ports:
      - 3000
  db:
    image: fundamentalsofdocker/ch11-db:2.0
    build: db
    volumes:
      - pets-data:/var/lib/postgresql/data

volumes:
  pets-data:
```

1.  现在，我们可以再次启动应用程序，并立即扩展它：

```
$ docker-compose up -d
$ docker-compose up -d --scale web=3
Starting ch11_web_1 ... done
Creating ch11_web_2 ... done
Creating ch11_web_3 ... done
```

1.  如果我们现在执行`docker-compose ps`，我们应该会看到以下的截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/608fb23b-b615-4b34-b389-37d014004c77.png)docker-compose ps 的输出

1.  正如我们所看到的，每个服务都关联到了不同的主机端口。我们可以尝试看看它们是否工作，比如使用`curl`。让我们测试第三个实例，`ch11_web_3`：

```
$ curl -4 localhost:32772
Pets Demo Application
```

答案`Pets Demo Application`告诉我们，我们的应用程序确实仍然按预期工作。为了确保，尝试对其他两个实例进行测试。

# 构建和推送应用程序

我们之前已经看到，我们也可以使用`docker-compose build`命令来构建`docker-compose`文件中定义的应用程序的镜像。但是为了使其工作，我们必须将构建信息添加到`docker-compose`文件中。在文件夹中，我们有一个名为`docker-compose.dev.yml`的文件，其中已经添加了这些指令。它基本上是我们迄今为止使用的`docker-compose.yml`文件的副本。

```
version: "2.4"
services:
  web:
    build: web
    image: fundamentalsofdocker/ch11-web:2.0
    ports:
      - 80:3000
  db:
    build: db
    image: fundamentalsofdocker/ch1-db:2.0
    volumes:
      - pets-data:/var/lib/postgresql/data

volumes:
  pets-data:
```

请注意每个服务的`build`键。该键的值表示 Docker 期望找到`Dockerfile`以构建相应映像的上下文或文件夹。如果我们想要为`web`服务使用命名不同的`Dockerfile`，比如`Dockerfile-dev`，那么`docker-compose`文件中的`build`块将如下所示：

```
build:
    context: web
    dockerfile: Dockerfile-dev
```

现在让我们使用另一个`docker-compose-dev.yml`文件：

```
$ docker-compose -f docker-compose.dev.yml build
```

`-f`参数将告诉 Docker Compose 应用程序使用哪个`compose`文件。

要将所有映像推送到 Docker Hub，我们可以使用`docker-compose push`。我们需要登录到 Docker Hub，以便成功，否则在推送时会出现身份验证错误。因此，在我的情况下，我执行以下操作：

```
$ docker login -u fundamentalsofdocker -p <password>
```

假设登录成功，然后我可以推送以下代码：

```
$ docker-compose -f docker-compose.dev.yml push
```

这可能需要一段时间，具体取决于您的互联网连接带宽。在推送时，您的屏幕可能看起来类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3add68f8-5a90-4edb-96a4-68743bff811b.png)

使用 docker-compose 将映像推送到 Docker Hub

上述命令将两个映像推送到 Docker Hub 上的`fundamentalsofdocker`帐户。您可以在以下网址找到这两个映像：[`hub.docker.com/u/fundamentalsofdocker/`](https://hub.docker.com/u/fundamentalsofdocker/)

# 使用 Docker Compose 覆盖

有时，我们希望在需要特定配置设置的不同环境中运行我们的应用程序。Docker Compose 提供了一个方便的功能来解决这个问题。

让我们举一个具体的例子。我们可以定义一个基本的 Docker Compose 文件，然后定义特定于环境的覆盖。假设我们有一个名为`docker-compose.base.yml`的文件，内容如下：

```
version: "2.4"
services:
  web:
    image: fundamentalsofdocker/ch11-web:2.0
  db:
    image: fundamentalsofdocker/ch11-db:2.0
    volumes:
      - pets-data:/var/lib/postgresql/data

volumes:
  pets-data:
```

这只定义了在所有环境中应该相同的部分。所有特定的设置都已被移除。

假设我们想要在 CI 系统上运行我们的示例应用程序，但是我们想要为数据库使用不同的设置。我们用来创建数据库映像的`Dockerfile`如下所示：

```
FROM postgres:12.0-alpine
COPY init-db.sql /docker-entrypoint-initdb.d/
ENV POSTGRES_USER dockeruser
ENV POSTGRES_PASSWORD dockerpass
ENV POSTGRES_DB pets
```

请注意我们在第 3 到 5 行定义的三个环境变量。`web`服务的`Dockerfile`具有类似的定义。假设在 CI 系统上，我们想要执行以下操作：

+   从代码构建映像

+   将`POSTGRES_PASSWORD`定义为`ci-pass`

+   将 web 服务的容器端口`3000`映射到主机端口`5000`

然后，相应的覆盖文件将如下所示：

```
version: "2.4"
services:
  web:
    build: web
    ports:
      - 5000:3000
    environment:
      POSTGRES_PASSWORD: ci-pass
  db:
    build: db
    environment:
      POSTGRES_PASSWORD: ci-pass
```

我们可以使用以下命令运行此应用程序：

```
$ docker-compose -f docker-compose.yml -f docker-compose-ci.yml up -d --build
```

请注意，第一个`-f`参数提供基本的 Docker Compose 文件，第二个参数提供覆盖文件。`--build`参数用于强制`docker-compose`重新构建镜像。

在使用环境变量时，请注意以下优先级：

+   在 Docker 文件中声明它们会定义默认值

+   在 Docker Compose 文件中声明相同的变量会覆盖 Dockerfile 中的值

如果我们遵循标准命名约定，将基本文件命名为`docker-compose.yml`，覆盖文件命名为`docker-compose.override.yml`，那么我们可以使用`docker-compose up -d`来启动应用程序，而无需显式命名 compose 文件。

# 总结

在本章中，我们介绍了`docker-compose`工具。该工具主要用于在单个 Docker 主机上运行和扩展多服务应用程序。通常，开发人员和 CI 服务器使用单个主机，这两者是 Docker Compose 的主要用户。该工具使用 YAML 文件作为输入，其中包含以声明方式描述应用程序的描述。

该工具还可用于构建和推送镜像，以及许多其他有用的任务。本章附带的代码可以在`fod/ch11`中找到。

在下一章中，我们将介绍**编排器**。编排器是一种基础设施软件，用于在集群中运行和管理容器化应用程序，同时确保这些应用程序始终处于所需的状态。

# 问题

为了评估您的学习进度，请回答以下问题：

1.  你将如何使用`docker-compose`以守护进程模式运行应用程序？

1.  你将如何使用`docker-compose`来显示运行服务的详细信息？

1.  你将如何将特定的 web 服务扩展到比如说三个实例？

# 进一步阅读

以下链接提供了本章讨论的主题的额外信息：

+   官方 YAML 网站：[`www.yaml.org/`](http://www.yaml.org/)

+   Docker Compose 文档：[`dockr.ly/1FL2VQ6`](http://dockr.ly/1FL2VQ6)

+   Compose 文件版本 2 参考：[`dohttps://docs.docker.com/compose/compose-file/compose-file-v2/`](https://docs.docker.com/compose/compose-file/compose-file-v2/)

+   在文件和项目之间共享 Compose 配置：[`docs.docker.com/compose/extends/`](https://docs.docker.com/compose/extends/)


# 第十二章：编排器

在上一章中，我们介绍了 Docker Compose，这是一个允许我们在单个 Docker 主机上以声明方式定义多服务应用程序的工具。

本章介绍了编排器的概念。它教会我们为什么需要编排器，以及它们在概念上是如何工作的。本章还将概述最流行的编排器，并列出它们的一些优缺点。

在本章中，我们将涵盖以下主题：

+   编排器是什么，为什么我们需要它们？

+   编排器的任务

+   流行编排器概述

完成本章后，您将能够做到以下几点：

+   列举编排器负责的三到四个任务

+   列举两到三个最流行的编排器

+   用你自己的话和适当的类比向一个感兴趣的外行解释为什么我们需要容器编排器

# 编排器是什么，为什么我们需要它们？

在[第九章]（bbbf480e-3d5a-4ad7-94e9-fae735b025ae.xhtml）*，分布式应用架构*中，我们了解了成功构建、部署和运行高度分布式应用程序常用的模式和最佳实践。现在，如果我们的分布式应用程序是容器化的，那么我们将面临与非容器化分布式应用程序面临的完全相同的问题或挑战。其中一些挑战是在[第九章]（bbbf480e-3d5a-4ad7-94e9-fae735b025ae.xhtml）*，分布式应用架构*中讨论过的——服务发现、负载均衡、扩展等等。

类似于 Docker 对容器所做的事情——通过引入这些容器来标准化软件的打包和交付——我们希望有一些工具或基础设施软件来处理提到的所有或大部分挑战。这个软件就是我们所说的容器编排器，或者我们也称之为编排引擎。

如果我刚才说的对你来说还不太有意义，那么让我们从另一个角度来看。拿一个演奏乐器的艺术家来说。他们可以独自为观众演奏美妙的音乐 - 只有艺术家和他们的乐器。但现在想象一个由音乐家组成的管弦乐团。把他们都放在一个房间里，给他们一首交响乐的音符，让他们演奏，并离开房间。没有指挥，这群非常有才华的音乐家将无法和谐地演奏这首曲子；它听起来或多或少会像一片杂音。只有管弦乐团有一个指挥，来指挥这群音乐家，管弦乐团的音乐才会让我们的耳朵愉悦：

*那么，我们期望一个值得投资的编排者为我们执行哪些任务呢？* 让我们详细看一下。以下列表显示了在撰写本文时，企业用户通常期望从他们的编排者那里得到的最重要的任务。

容器编排者就像管弦乐团的指挥

我希望你现在能更清楚地看到容器编排者是什么，以及为什么我们需要它。假设你确认了这个问题，我们现在可以问自己编排者将如何实现预期的结果，即确保集群中的所有容器和谐地相互配合。嗯，答案是，编排者必须执行非常具体的任务，类似于管弦乐团的指挥也有一系列任务要执行，以驯服和同时提升管弦乐团。

来源：https://it.wikipedia.org/wiki/Giuseppe_Lanzetta#/media/File:UMB_5945.JPGLicense: https://creativecommons.org/licenses/by-sa/3.0/deed.en

# 编排者的任务

现在我们有的不是音乐家，而是容器，不同的乐器，而是对容器主机运行的不同要求。音乐以不同的速度演奏，我们有以特定方式相互通信的容器，并且需要扩展和缩减。在这方面，容器编排者与管弦乐团的指挥有着非常相似的角色。它确保集群中的容器和其他资源和谐地相互配合。

# 协调所需的状态

在使用编排器时，您以声明方式告诉它如何运行特定的应用程序或应用程序服务。我们在《Docker Compose》的[第十一章]中学到了声明式与命令式的含义。描述我们想要运行的应用程序服务的声明方式包括诸如要使用哪个容器镜像、要运行多少个此服务的实例、要打开哪些端口等元素。我们称这些应用服务属性的声明为“期望状态”。

因此，当我们现在首次告诉编排器根据声明创建这样一个新的应用服务时，编排器会确保在集群中安排尽可能多的容器。如果容器镜像尚未在集群的目标节点上可用，调度程序会确保首先从镜像注册表中下载它们。接下来，容器将以所有设置启动，例如要附加到的网络或要公开的端口。编排器会尽其所能确保将集群与声明的状态完全匹配。

一旦我们的服务按要求启动并运行，也就是说，它以期望的状态运行，那么编排器会继续监视它。每当编排器发现服务的实际状态与期望状态之间存在差异时，它会再次尽力调解期望状态。

应用程序服务的实际状态与期望状态之间可能存在什么差异呢？比如说，服务的一个副本，也就是一个容器，由于某种原因崩溃了，编排器会发现实际状态与期望状态之间的差异在于副本的数量：缺少一个副本。编排器会立即将一个新实例调度到另一个集群节点，以替换崩溃的实例。另一个差异可能是应用程序服务的实例数量过多，如果服务已经缩减。在这种情况下，编排器将随机关闭所需数量的实例，以实现实际实例和期望实例数量之间的平衡。另一个差异可能是编排器发现应用程序服务的一个实例运行了错误（可能是旧）版本的底层容器映像。到现在为止，你应该明白了吧？

因此，我们不需要主动监视集群中运行的应用程序服务，并纠正与期望状态的任何偏差，而是将这一繁琐的任务委托给编排器。只要我们使用声明性而不是命令式的方式描述应用程序服务的期望状态，这种方法就非常有效。

# 复制和全局服务

在由编排器管理的集群中，我们可能想要运行两种完全不同类型的服务。它们是*复制*和*全局*服务。复制服务是指需要在特定数量的实例中运行的服务，比如说 10 个。而全局服务则是要求集群中每个工作节点上都运行一个实例的服务。我在这里使用了“工作节点”这个术语。在由编排器管理的集群中，通常有两种类型的节点，即*管理节点*和*工作节点*。管理节点通常由编排器专门用于管理集群，不运行任何其他工作负载。而工作节点则运行实际的应用程序。

因此，编排器确保对于全局服务，无论有多少个工作节点，它都在每个工作节点上运行一个实例。我们不需要关心实例的数量，只需要确保在每个节点上都保证运行服务的单个实例。

再次，我们可以完全依赖编排器来处理这个问题。在复制的服务中，我们总是能够找到确切所需数量的实例，而对于全局服务，我们可以确保在每个工作节点上始终运行服务的一个实例。编排器将尽其所能保证这种期望状态。

在 Kubernetes 中，全局服务也被称为**DaemonSet**。

# 服务发现

当我们以声明方式描述应用服务时，我们永远不应该告诉编排器服务的不同实例必须在哪些集群节点上运行。我们让编排器决定哪些节点最适合这项任务。

当然，从技术上讲，指示编排器使用非常确定性的放置规则是可能的，但这将是一种反模式，不建议在非常特殊的边缘情况之外使用。

因此，如果我们现在假设编排引擎完全自由地决定放置应用服务的各个实例的位置，而且实例可能会崩溃并由编排器重新安排到不同的节点，那么我们会意识到，我们无法追踪每个实例在任何给定时间运行在哪里是一项徒劳的任务。更好的是，我们甚至不应该尝试知道这一点，因为这并不重要。

好吧，你可能会说，但如果我有两个服务，A 和 B，服务 A 依赖于服务 B；*服务 A 的任何给定实例都应该知道在哪里可以找到服务 B 的实例吗？*

在这里，我必须大声明确地说——不，不应该。在高度分布式和可扩展的应用程序中，这种知识是不可取的。相反，我们应该依赖编排器为我们提供所需的信息，以便访问我们依赖的其他服务实例。这有点像在电话的旧时代，当我们不能直接打电话给朋友，而必须打电话给电话公司的中央办公室，那里的一些操作员会将我们路由到正确的目的地。在我们的情况下，编排器扮演操作员的角色，将来自服务 A 实例的请求路由到可用的服务 B 实例。整个过程被称为**服务发现**。

# 路由

到目前为止，我们已经了解到在分布式应用中，有许多相互作用的服务。当服务 A 与服务 B 交互时，它是通过数据包的交换来实现的。这些数据包需要以某种方式从服务 A 传输到服务 B。这个从源到目的地传输数据包的过程也被称为**路由**。作为应用的作者或操作者，我们期望编排器来接管这个路由任务。正如我们将在后面的章节中看到的，路由可以发生在不同的层面。就像在现实生活中一样。假设你在一家大公司的办公楼里工作。现在，你有一份需要转发给公司另一名员工的文件。内部邮件服务将从你的发件箱中取出文件，并将其送到同一建筑物内的邮局。如果目标人员在同一建筑物内工作，文件可以直接转发给该人员。另一方面，如果该人员在同一街区的另一栋建筑物内工作，文件将被转发到目标建筑物的邮局，然后通过内部邮件服务分发给接收者。第三，如果文件的目标是公司位于不同城市甚至不同国家的另一分支机构的员工，那么文件将被转发给 UPS 等外部邮政服务，后者将把它运送到目标地点，然后再次由内部邮件服务接管并将其送达收件人。

当在容器中运行的应用服务之间路由数据包时，类似的事情会发生。源容器和目标容器可以位于同一集群节点上，这对应于两名员工在同一建筑物内工作的情况。目标容器可以在不同的集群节点上运行，这对应于两名员工在同一街区的不同建筑物内工作的情况。最后，第三种情况是当数据包来自集群外部并且必须路由到集群内部运行的目标容器时。

编排器必须处理所有这些情况，以及更多。

# 负载均衡

在高可用的分布式应用中，所有组件都必须是冗余的。这意味着每个应用服务都必须以多个实例运行，以便如果一个实例失败，整个服务仍然可用。

为了确保一个服务的所有实例实际上都在工作，而不是闲置，您必须确保对服务的请求均匀分布到所有实例。这种在服务实例之间分配工作负载的过程称为负载均衡。存在各种算法来分配工作负载。通常，负载均衡器使用所谓的轮询算法，确保工作负载使用循环算法均匀分布到实例上。

再次，我们期望编排器处理从一个服务到另一个服务的负载均衡请求，或者从外部来源到内部服务的请求。

# 扩展

当在由编排器管理的集群中运行我们的容器化分布式应用程序时，我们还希望有一种简单的方式来处理预期或意外的工作负载增加。为了处理增加的工作负载，我们通常会安排正在经历增加负载的服务的额外实例。然后负载均衡器将自动配置为在更多可用的目标实例之间分发工作负载。

但在现实场景中，工作负载会随时间变化而变化。如果我们看一个像亚马逊这样的购物网站，它在晚上高峰时段可能会有很高的负载，当每个人都在家里网上购物；在特殊的日子，比如黑色星期五，它可能会经历极端的负载；而在早晨可能会经历很少的流量。因此，服务不仅需要能够扩展，还需要在工作负载减少时能够缩减。

我们还期望编排器在扩展时以有意义的方式分发服务的实例。将所有服务实例安排在同一集群节点上是不明智的，因为如果该节点宕机，整个服务就会宕机。编排器的调度程序负责容器的放置，还需要考虑不将所有实例放置在同一台计算机机架上，因为如果机架的电源供应失败，整个服务将受到影响。此外，关键服务的服务实例甚至应该分布在数据中心，以避免中断。所有这些决定，以及许多其他决定，都是编排器的责任。

在云中，通常使用“可用区”这个术语，而不是计算机机架。

# 自愈

如今，编排器非常复杂，可以为我们做很多事情来维护一个健康的系统。编排器监视集群中运行的所有容器，并自动用新实例替换崩溃或无响应的容器。编排器监视集群节点的健康状况，并在节点变得不健康或宕机时将其从调度循环中移除。原本位于这些节点上的工作负载会自动重新调度到其他可用节点上。

所有这些活动，编排器监视当前状态并自动修复损坏或协调期望状态，导致了所谓的**自愈**系统。在大多数情况下，我们不需要积极参与和修复损害。编排器会自动为我们完成这些工作。

然而，有一些情况编排器无法在没有我们帮助的情况下处理。想象一种情况，我们有一个运行在容器中的服务实例。容器正在运行，并且从外部看起来非常健康。但是，容器内部运行的应用程序处于不健康状态。应用程序没有崩溃，只是不能再像最初设计的那样工作了。编排器怎么可能在没有我们提示的情况下知道这一点呢？它不可能！处于不健康或无效状态对每个应用服务来说意味着完全不同。换句话说，健康状态是与服务相关的。只有服务的作者或其操作者知道在服务的上下文中健康意味着什么。

现在，编排器定义了应用服务可以与其通信的接口或探针。存在两种基本类型的探针：

+   服务可以告诉编排器它的健康状态

+   服务可以告诉编排器它已经准备好或者暂时不可用

服务如何确定前面提到的任一答案完全取决于服务本身。编排器只定义了它将如何询问，例如通过`HTTP GET`请求，或者它期望的答案类型，例如`OK`或`NOT OK`。

如果我们的服务实现了逻辑来回答前面提到的健康或可用性问题，那么我们就拥有了一个真正的自愈系统，因为编排器可以终止不健康的服务实例并用新的健康实例替换它们，还可以将暂时不可用的服务实例从负载均衡器的轮询中移除。

# 零停机部署

如今，很难再为需要更新的关键任务应用程序辩解完全停机。这不仅意味着错失机会，还可能导致公司声誉受损。使用该应用程序的客户不再愿意接受这样的不便，并会迅速离开。此外，我们的发布周期变得越来越短。在过去，我们每年可能会有一两次新版本发布，但如今，许多公司每周甚至每天多次更新他们的应用程序。

解决这个问题的方法是提出一个零停机应用程序更新策略。编排器需要能够逐批更新单个应用程序服务。这也被称为**滚动更新**。在任何给定时间，只有给定服务的总实例数中的一个或几个会被关闭，并被该服务的新版本替换。只有新实例是可操作的，并且不会产生任何意外错误或显示任何不当行为，才会更新下一批实例。这一过程重复进行，直到所有实例都被替换为它们的新版本。如果由于某种原因更新失败，那么我们期望编排器自动将更新的实例回滚到它们的先前版本。

其他可能的零停机部署包括蓝绿部署和金丝雀发布。在这两种情况下，服务的新版本与当前活动版本并行安装。但最初，新版本只能在内部访问。运营人员可以对新版本运行烟雾测试，当新版本似乎运行良好时，就可以在蓝绿部署的情况下，将路由器从当前蓝色版本切换到新的绿色版本。一段时间内，新的绿色版本的服务将受到密切监控，如果一切正常，旧的蓝色版本就可以被废弃。另一方面，如果新的绿色版本不如预期那样工作，那么只需将路由器设置回旧的蓝色版本，就可以实现完全回滚。

在金丝雀发布的情况下，路由器被配置为将整体流量的一小部分，比如 1%，引导到服务的新版本，而仍然有 99%的流量通过旧版本路由。新版本的行为受到密切监视，并与旧版本的行为进行比较。如果一切正常，那么通过新服务引导的流量百分比会略微增加。这个过程会重复，直到 100%的流量通过新服务路由。如果新服务运行一段时间并且一切正常，那么旧服务可以被停用。

大多数编排器至少支持开箱即用的滚动更新类型的零停机部署。蓝绿部署和金丝雀发布通常很容易实现。

# 亲和性和位置感知

有时，某些应用服务需要节点上专用硬件的可用性。例如，I/O 密集型服务需要具有附加高性能**固态硬盘**（**SSD**）的集群节点，或者用于机器学习等用途的某些服务需要**加速处理单元**（**APU**）。编排器允许我们为每个应用服务定义节点亲和性。然后，编排器将确保其调度程序仅在满足所需条件的集群节点上调度容器。

避免将亲和力定义为特定节点；这将引入单点故障，从而损害高可用性。始终将多个集群节点定义为应用服务的目标。

一些编排引擎还支持所谓的**位置感知**或**地理感知**。这意味着您可以要求编排器将服务的实例均匀分布在不同位置的一组位置上。例如，您可以定义一个`数据中心`标签，其可能的值为`西`、`中`和`东`，并将该标签应用于具有对应于各自节点所在地理区域的值的所有集群节点。然后，您指示编排器使用此标签来进行某个应用服务的地理感知。在这种情况下，如果您请求该服务的九个副本，那么编排器将确保将三个实例部署到每个数据中心的节点中——西、中和东。

地理意识甚至可以按层次定义；例如，您可以将数据中心作为最高级别的判别器，然后是可用区。

地理意识或位置意识用于减少由电源供应故障或数据中心故障导致的中断的概率。如果应用实例分布在节点、可用区甚至数据中心之间，那么一切同时崩溃的可能性极小。总会有一个地区是可用的。

# 安全

如今，IT 安全是一个非常热门的话题。网络战争达到了历史最高点。大多数知名公司都曾是黑客攻击的受害者，造成了非常昂贵的后果。每个首席信息官（CIO）或首席技术官（CTO）最糟糕的噩梦之一就是早上醒来听到自己的公司成为黑客攻击的受害者，并且敏感信息被窃取或泄露的消息。

为了对抗大多数安全威胁，我们需要建立一个安全的软件供应链，并在深度上强制执行安全防御。让我们来看看您可以从企业级编排器中期望的一些任务。

# 安全通信和加密节点身份

首先，我们希望确保由编排器管理的集群是安全的。只有受信任的节点才能加入集群。加入集群的每个节点都会获得一个加密的节点身份，并且节点之间的所有通信必须加密。为此，节点可以使用相互传输层安全（MTLS）。为了相互认证集群的节点，使用证书。这些证书会定期自动轮换，或者根据请求进行轮换，以保护系统以防证书泄露。

集群中发生的通信可以分为三种类型。您可以谈论通信平面-管理、控制和数据平面：

+   管理平面由集群管理器或主节点使用，例如，调度服务实例，执行健康检查，或创建和修改集群中的任何其他资源，如数据卷、密钥或网络。

+   控制平面用于在集群的所有节点之间交换重要的状态信息。例如，这种信息用于更新用于路由目的的集群上的本地 IP 表。

+   数据平面是实际应用服务相互通信和交换数据的地方。

通常，编排器主要关心保护管理和控制平面。保护数据平面留给用户，尽管编排器可能会促进这项任务。

# 安全网络和网络策略

在运行应用服务时，并非每个服务都需要与集群中的其他服务通信。因此，我们希望能够将服务相互隔离，并且只在绝对需要相互通信的情况下在相同的网络沙盒中运行这些服务。所有其他服务和来自集群外部的所有网络流量都不应该有可能访问被隔离的服务。

至少有两种网络沙盒化的方式。我们可以使用软件定义网络（SDN）来分组应用服务，或者我们可以使用一个扁平网络，并使用网络策略来控制谁有权访问特定服务或服务组。

# 基于角色的访问控制（RBAC）

编排器必须履行的最重要任务之一（除了安全性）是为集群及其资源提供基于角色的访问。RBAC 定义了系统的主体、用户或用户组，组织成团队等如何访问和操作系统。它确保未经授权的人员无法对系统造成任何伤害，也无法看到他们不应该知道或看到的系统中的任何可用资源。

典型的企业可能有开发、QA 和生产等用户组，每个组都可以有一个或多个用户与之关联。开发人员约翰·多伊是开发组的成员，因此可以访问专门为开发团队提供的资源，但他不能访问例如生产团队的资源，其中安·哈伯是成员。反过来，她也不能干扰开发团队的资源。

实施 RBAC 的一种方式是通过定义授权。授权是主体、角色和资源集合之间的关联。在这里，角色由对资源的一组访问权限组成。这些权限可以是创建、停止、删除、列出或查看容器；部署新的应用服务；列出集群节点或查看集群节点的详细信息；以及许多其他权限。

资源集合是集群中逻辑相关的资源的组合，例如应用服务、秘密、数据卷或容器。

# 秘密

在我们的日常生活中，我们有很多秘密。秘密是不应该公开知道的信息，比如你用来访问在线银行账户的用户名和密码组合，或者你手机或健身房储物柜的密码。

在编写软件时，我们经常也需要使用秘密。例如，我们需要一个证书来验证我们的应用服务与我们想要访问的外部服务进行身份验证，或者我们需要一个令牌来在访问其他 API 时验证和授权我们的服务。过去，为了方便起见，开发人员通常会将这些值硬编码，或者将它们以明文形式放在一些外部配置文件中。在那里，这些非常敏感的信息对广大观众都是可访问的，而实际上，他们本不应该有机会看到这些秘密。

幸运的是，这些天，编排器提供了所谓的秘密，以高度安全的方式处理这些敏感信息。秘密可以由授权或信任的人员创建。这些秘密的值然后被加密并存储在高可用的集群状态数据库中。由于这些秘密是加密的，所以它们现在在静态时是安全的。一旦一个被授权的应用服务请求一个秘密，该秘密只会被转发到实际运行该特定服务实例的集群节点，并且秘密值永远不会存储在节点上，而是挂载到容器中的`tmpfs`基于 RAM 的卷中。只有在相应的容器内，秘密值才以明文形式可用。

我们已经提到，秘密在静态时是安全的。一旦它们被服务、集群管理器或主节点请求，主节点会解密秘密并将其通过网络发送到目标节点。*那么，秘密在传输过程中安全吗？*嗯，我们之前了解到集群节点使用 MTLS 进行通信，因此即使秘密以明文传输，也仍然是安全的，因为数据包将被 MTLS 加密。因此，秘密在静态和传输过程中都是安全的。只有被授权使用秘密的服务才能访问这些秘密值。

# 内容信任

为了增加安全性，我们希望确保只有受信任的图像在我们的生产集群中运行。一些编排器允许我们配置集群，以便它只能运行经过签名的图像。内容信任和签署图像的目的在于确保图像的作者是我们所期望的人，即我们信任的开发人员，甚至更好的是我们信任的 CI 服务器。此外，通过内容信任，我们希望保证我们获取的图像是新鲜的，而不是旧的，可能存在漏洞的图像。最后，我们希望确保图像在传输过程中不会被恶意黑客篡改。后者通常被称为**中间人**（**MITM**）攻击。

通过在源头签署图像，并在目标处验证签名，我们可以保证我们想要运行的图像没有被篡改。

# 逆向正常运行时间

我想在安全性的背景下讨论的最后一点是逆向正常运行时间。*这是什么意思呢？*想象一下，你已经配置和保护了一个生产集群。在这个集群上，你正在运行公司的一些关键应用程序。现在，一个黑客设法在你的软件堆栈中找到了一个安全漏洞，并且已经获得了对你的集群节点的 root 访问权限。这本身已经够糟糕了，但更糟糕的是，这个黑客现在可以掩盖他们在这个节点上的存在，毕竟他们已经有了 root 访问权限，然后将其用作攻击你的集群中其他节点的基地。

在 Linux 或任何 Unix 类型的操作系统中，root 访问权限意味着你可以在这个系统上做任何事情。这是某人可以拥有的最高级别的访问权限。在 Windows 中，相当于这个角色的是管理员。

但是，*如果我们利用容器是短暂的，集群节点通常可以快速配置，通常在几分钟内完全自动化的情况下呢？*我们只需在一定的正常运行时间后关闭每个集群节点，比如说 1 天。编排器被指示排空节点，然后将其从集群中排除。一旦节点离开集群，它就会被拆除并被一个新配置的节点所取代。

这样，黑客就失去了他们的基地，问题也被消除了。尽管这个概念目前还没有广泛应用，但对我来说，这似乎是向增加安全性迈出的一大步，而且据我与在这个领域工作的工程师讨论，实施起来并不困难。

# 内省

到目前为止，我们已经讨论了许多由编排器负责的任务，它可以完全自主地执行。但是，人类操作员也需要能够查看和分析集群上当前运行的内容，以及个别应用程序的状态或健康状况。为了做到这一点，我们需要进行内省。编排器需要以易于消化和理解的方式呈现关键信息。

编排器应该从所有集群节点收集系统指标，并使其对操作员可访问。指标包括 CPU、内存和磁盘使用情况、网络带宽消耗等。这些信息应该以逐个节点的方式轻松获取，以及以汇总形式获取。

我们还希望编排器能够让我们访问由服务实例或容器产生的日志。此外，如果我们有正确的授权，编排器还应该为我们提供对每个容器的`exec`访问权限。有了对容器的`exec`访问权限，您就可以调试行为不端的容器。

在高度分布式的应用程序中，每个对应用程序的请求都要经过多个服务，直到完全处理，跟踪请求是一项非常重要的任务。理想情况下，编排器支持我们实施跟踪策略，或者给我们一些好的遵循指南。

最后，人类操作员在使用所有收集到的指标、日志和跟踪信息的图形表示时，可以最好地监视系统。在这里，我们谈论的是仪表板。每个体面的编排器都应该提供至少一些基本的仪表板，以图形方式表示最关键的系统参数。

然而，人类操作员并不是唯一关心内省的人。我们还需要能够将外部系统连接到编排器，以便消费这些信息。需要提供一个 API，通过该 API，外部系统可以访问集群状态、指标和日志等数据，并利用这些信息做出自动决策，例如创建警报或电话警报、发送电子邮件，或者在系统超过某些阈值时触发警报。

# 流行编排器的概述

在撰写本文时，有许多编排引擎在使用中，但有一些明显的赢家。第一名显然是由 Kubernetes 占据，它统治着。遥遥领先的第二名是 Docker 自己的 SwarmKit，其次是其他一些，如 Apache Mesos，AWS 弹性容器服务（ECS），或 Microsoft Azure 容器服务（ACS）。

# Kubernetes

Kubernetes 最初由 Google 设计，后来捐赠给了云原生计算基金会（CNCF）。Kubernetes 是模仿 Google 专有的 Borg 系统而设计的，该系统多年来一直在超大规模上运行容器。Kubernetes 是 Google 重新设计的尝试，完全重新开始并设计一个系统，其中包含了与 Borg 学到的所有教训。

与专有技术 Borg 相反，Kubernetes 在早期就开源了。这是 Google 的一个非常明智的选择，因为它吸引了大量来自公司外部的贡献者，仅仅在短短几年内，Kubernetes 周围的生态系统更加庞大。你可以说 Kubernetes 是容器编排领域社区的宠儿。没有其他编排器能够产生如此多的炒作，并吸引如此多愿意以有意义的方式为项目的成功做出贡献的人才，无论是作为贡献者还是早期采用者。

在这方面，Kubernetes 在容器编排领域对我来说非常像 Linux 在服务器操作系统领域所变成的。Linux 已经成为服务器操作系统的事实标准。所有相关公司，如微软、IBM、亚马逊、红帽，甚至 Docker，都已经接受了 Kubernetes。

有一件事是无法否认的：Kubernetes 从一开始就被设计用于大规模扩展。毕竟，它是以 Google Borg 为目标而设计的。

可以提出反对 Kubernetes 的一个负面方面是，至少在撰写本文时，它仍然很复杂，设置和管理起来。对于新手来说，这是一个重大障碍。第一步是艰难的，但一旦你使用这个编排器一段时间，一切就会变得清晰。整体设计经过深思熟虑，执行得非常好。

在 Kubernetes 的 1.10 版本中，与其他编排器（如 Docker Swarm）相比，最初的缺点大多已经消除。例如，安全性和保密性现在不仅仅是一个事后的考虑，而是系统的一个组成部分。

新功能以惊人的速度实施。新版本大约每 3 个月发布一次，更确切地说，大约每 100 天发布一次。大多数新功能都是需求驱动的，也就是说，使用 Kubernetes 来编排其关键任务应用程序的公司可以提出他们的需求。这使得 Kubernetes 适合企业使用。认为这个编排器只适用于初创企业而不适用于风险规避型企业是错误的。相反的情况是。*我基于什么来做出这个断言？*嗯，我的断言是有根据的，因为像微软、Docker 和红帽这样的公司，他们的客户大多是大型企业，已经完全接受了 Kubernetes，并为其提供企业级支持，如果它被用于并集成到他们的企业产品中。

Kubernetes 支持 Linux 和 Windows 容器。

# Docker Swarm

众所周知，Docker 推广和商品化了软件容器。Docker 并没有发明容器，但是标准化了它们，并使其广泛可用，其中包括提供免费镜像注册表—Docker Hub。最初，Docker 主要关注开发人员和开发生命周期。然而，开始使用和喜爱容器的公司很快也希望不仅在开发或测试新应用程序时使用它们，而且在生产中运行这些应用程序时也使用它们。

最初，Docker 在这个领域没有什么可提供的，所以其他公司跳进这个真空并为用户提供帮助。但是没过多久，Docker 意识到有一个对于一个简单而强大的编排器的巨大需求。Docker 的第一次尝试是一个名为经典 Swarm 的产品。它是一个独立的产品，使用户能够创建一个 Docker 主机集群，可以用于以高可用和自愈的方式运行和扩展其容器化应用程序。

然而，经典 Docker Swarm 的设置很困难。涉及许多复杂的手动步骤。客户喜欢这个产品，但在处理其复杂性时遇到了困难。因此，Docker 决定可以做得更好。它回到了起点，并提出了 SwarmKit。SwarmKit 在 2016 年的 DockerCon 大会上在西雅图推出，并成为最新版本的 Docker 引擎的一个重要组成部分。是的，你没听错；SwarmKit 是，直到今天仍然是 Docker 引擎的一个重要组成部分。因此，如果你安装了 Docker 主机，你自动就有了 SwarmKit。

SwarmKit 的设计理念是简单和安全。其口号是，几乎可以轻松地设置一个 Swarm，并且 Swarm 在开箱即用时必须具有高度安全性。Docker Swarm 的运行基于最低权限的假设。

在集群中的第一个节点上使用`docker swarm init`开始安装完整、高可用的 Docker Swarm，这个节点成为所谓的领导者，然后在所有其他节点上使用`docker swarm join <join-token>`。`join-token`是在初始化期间由领导者生成的。整个过程在具有多达 10 个节点的集群上不到 5 分钟。如果自动化，时间会更短。

正如我之前提到的，安全性是 Docker 设计和开发 SwarmKit 时的首要考虑因素。容器通过依赖 Linux 内核命名空间和 cgroups、Linux 系统调用白名单（seccomp）以及对 Linux 功能和 Linux 安全模块（LSM）的支持来提供安全性。现在，在此基础上，SwarmKit 还增加了 MTLS 和在静态和传输中加密的秘密。此外，Swarm 定义了所谓的容器网络模型（CNM），允许为在集群上运行的应用服务提供沙盒环境的 SDN。

Docker SwarmKit 支持 Linux 和 Windows 容器。

# Apache Mesos 和 Marathon

Apache Mesos 是一个开源项目，最初旨在使服务器或节点集群从外部看起来像一个单一的大服务器。Mesos 是一种使计算机集群管理变得简单的软件。Mesos 的用户不必关心单个服务器，只需假设他们拥有一个庞大的资源池，这对应于集群中所有节点的所有资源的总和。

从 IT 术语上讲，Mesos 已经相当古老，至少与其他编排器相比是这样。它首次公开亮相是在 2009 年，但当时当然并不是为了运行容器，因为当时甚至还没有 Docker。与 Docker 对容器的处理方式类似，Mesos 使用 Linux cgroups 来隔离 CPU、内存或磁盘 I/O 等资源，以便为单个应用程序或服务提供资源隔离。

Mesos 实际上是其他建立在其之上的有趣服务的基础基础设施。从容器的角度来看，Marathon 非常重要。Marathon 是一个运行在 Mesos 之上的容器编排器，能够扩展到数千个节点。

Marathon 支持多个容器运行时，如 Docker 或其自己的 Mesos 容器。它不仅支持无状态的应用服务，还支持有状态的应用服务，例如像 PostgreSQL 或 MongoDB 这样的数据库。与 Kubernetes 和 Docker SwarmKit 类似，它支持本章前面描述的许多功能，例如高可用性、健康检查、服务发现、负载均衡和位置感知等等。

尽管 Mesos 和在一定程度上 Marathon 是相当成熟的项目，但它们的影响范围相对有限。它似乎在大数据领域最受欢迎，即运行诸如 Spark 或 Hadoop 之类的数据处理服务。

# 亚马逊 ECS

如果您正在寻找一个简单的编排器，并且已经深度融入了 AWS 生态系统，那么亚马逊的 ECS 可能是您的正确选择。但是，有一点非常重要的限制需要指出：如果您选择了这个容器编排器，那么您就将自己锁定在 AWS 中。您将无法轻松地将在 ECS 上运行的应用程序迁移到另一个平台或云上。

亚马逊将其 ECS 服务宣传为一个高度可扩展、快速的容器管理服务，可以轻松在集群上运行、停止和管理 Docker 容器。除了运行容器，ECS 还可以直接访问容器内运行的应用服务的许多其他 AWS 服务。这种与许多热门 AWS 服务的紧密无缝集成，使 ECS 对于寻求在强大且高度可扩展的环境中轻松运行其容器化应用的用户非常具有吸引力。亚马逊还提供自己的私有镜像注册表。

使用 AWS ECS，您可以使用 Fargate 来完全管理底层基础设施，让您专注于部署容器化应用程序，而不必关心如何创建和管理节点集群。ECS 支持 Linux 和 Windows 容器。

总之，ECS 使用简单，高度可扩展，并与其他热门的 AWS 服务很好地集成在一起；但它不像 Kubernetes 或 Docker SwarmKit 那样强大，并且仅在 Amazon AWS 上可用。

# 微软 ACS

与我们对 ECS 所说的类似，我们也可以对微软的 ACS 提出同样的要求。如果您已经在 Azure 生态系统中投入了大量资金，那么 ACS 是一个有意义的容器编排服务。我应该说与我为 Amazon ECS 指出的相同：如果您选择 ACS，那么您就会将自己锁定在微软的产品中。将容器化应用程序从 ACS 移动到其他平台或云将不容易。

ACS 是微软的容器服务，支持多个编排器，如 Kubernetes、Docker Swarm 和 Mesos DC/OS。随着 Kubernetes 变得越来越受欢迎，微软的重点显然已经转移到了该编排器上。微软甚至重新将其服务命名为 Azure Kubernetes Service（AKS），以便将重点放在 Kubernetes 上。

AKS 为您管理在 Azure 中托管的 Kubernetes 或 Docker Swarm 或 DC/OS 环境，这样您就可以专注于要部署的应用程序，而不必关心配置基础设施。微软自己声称如下：

“AKS 使得快速轻松地部署和管理容器化应用程序成为可能，而无需容器编排专业知识。它还通过根据需求提供、升级和扩展资源来消除持续运营和维护的负担，而不会使您的应用程序下线。”

# 总结

本章阐明了为什么首先需要编排器，以及它们在概念上是如何工作的。它指出了在撰写时最突出的编排器，并讨论了各种编排器之间的主要共同点和区别。

下一章将介绍 Docker 的本地编排器 SwarmKit。它将详细阐述 SwarmKit 用于在集群（本地或云中）部署和运行分布式、有弹性、健壮和高可用应用所使用的所有概念和对象。

# 问题

回答以下问题以评估您的学习进度：

1.  我们为什么需要编排器？提供两到三个理由。

1.  列出编排器的三到四个典型职责。

1.  请至少列出两个容器编排器，以及它们背后的主要赞助商。

# 进一步阅读

以下链接提供了有关编排相关主题的更深入的见解：

+   Kubernetes-生产级编排：[`kubernetes.io/.`](https://kubernetes.io/)

+   Docker Swarm 模式概述：[`docs.docker.com/engine/swarm/.`](https://docs.docker.com/engine/swarm/)

+   Marathon，Mesos 和 DC/OS 的容器编排平台：[https://](https://mesosphere.github.io/marathon/)[mesosphere.github.io/marathon/](https://mesosphere.github.io/marathon/)

+   解释容器和编排：[`bit.ly/2DFoQgx.`](https://bit.ly/2npjrEl)


# 第十三章：介绍 Docker Swarm

在上一章中，我们介绍了编排器。就像管弦乐队中的指挥一样，编排器确保我们所有的容器化应用服务和谐地共同演奏，为共同的目标做出贡献。这样的编排器有很多责任，我们详细讨论了这些责任。最后，我们简要概述了市场上最重要的容器编排器。

本章介绍了 Docker 的本地编排器 SwarmKit。它详细阐述了 SwarmKit 用于在本地或云上部署和运行分布式、有弹性、健壮和高可用应用的所有概念和对象。本章还介绍了 SwarmKit 如何通过使用软件定义网络（SDN）来隔离容器来确保安全应用。此外，本章演示了如何在云中安装一个高可用的 Docker Swarm。它介绍了路由网格，提供了第四层路由和负载平衡。最后，它演示了如何在群集上部署由多个服务组成的第一个应用程序。

本章我们将讨论以下主题：

+   Docker Swarm 架构

+   Swarm 节点

+   堆栈、服务和任务

+   多主机网络

+   创建一个 Docker Swarm

+   部署第一个应用程序

+   Swarm 路由网格

完成本章后，您将能够做到以下事项：

+   在白板上勾画一个高可用的 Docker Swarm 的基本部分

+   用两三个简单的句子向感兴趣的门外汉解释（群）服务是什么

+   在 AWS、Azure 或 GCP 中创建一个高可用的 Docker Swarm，包括三个管理节点和两个工作节点

+   成功在 Docker Swarm 上部署一个复制的服务，如 Nginx

+   扩展正在运行的 Docker Swarm 服务

+   检索复制的 Docker Swarm 服务的聚合日志

+   为一个由至少两个相互作用的服务组成的示例应用程序编写一个简单的堆栈文件

+   将一个堆栈部署到 Docker Swarm 中

# Docker Swarm 架构

从 30,000 英尺的视角来看，Docker Swarm 的架构由两个主要部分组成——一个由奇数个管理节点组成的 raft 一致性组，以及一个与控制平面上的八卦网络相互通信的工作节点组。以下图表说明了这种架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/185aff48-e453-4420-a5c7-35859f604904.png)

Docker Swarm 的高级架构

**管理节点**管理 Swarm，而**工作节点**执行部署到 Swarm 中的应用程序。每个**管理节点**在其本地 Raft 存储中都有完整的 Swarm 状态副本。管理节点之间同步通信，它们的 Raft 存储始终保持同步。

另一方面，为了可伸缩性的原因，**工作节点**是异步通信的。在一个 Swarm 中可能有数百甚至数千个**工作节点**。现在我们已经对 Docker Swarm 有了一个高层次的概述，让我们更详细地描述 Docker Swarm 的所有单个元素。

# Swarm 节点

Swarm 是节点的集合。我们可以将节点分类为物理计算机或虚拟机（VM）。如今，物理计算机通常被称为“裸金属”。人们说“我们在裸金属上运行”以区别于在虚拟机上运行。

当我们在这样的节点上安装 Docker 时，我们称这个节点为 Docker 主机。以下图表更好地说明了节点和 Docker 主机是什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/45b82a12-5b32-4290-8970-944fe94532eb.png)

裸金属和虚拟机类型的 Docker Swarm 节点

要成为 Docker Swarm 的成员，节点必须是 Docker 主机。Docker Swarm 中的节点可以担任两种角色之一。它可以是管理节点，也可以是工作节点。管理节点做其名字所示的事情；它们管理 Swarm。而工作节点则执行应用程序工作负载。

从技术上讲，管理节点也可以是工作节点，因此运行应用程序工作负载，尽管这并不被推荐，特别是如果 Swarm 是运行关键任务应用程序的生产系统。

# Swarm 管理节点

每个 Docker Swarm 至少需要包括一个**管理节点**。出于高可用性的原因，我们应该在 Swarm 中有多个管理节点。这对于生产环境或类似生产环境尤为重要。如果我们有多个管理节点，那么这些节点将使用 Raft 一致性协议一起工作。Raft 一致性协议是一个标准协议，当多个实体需要共同工作并且始终需要就下一步执行的活动达成一致意见时，通常会使用该协议。

为了良好运行，Raft 共识协议要求在所谓的共识组中有奇数个成员。因此，我们应该始终有 1、3、5、7 等管理者节点。在这样的共识组中，总是有一个领导者。在 Docker Swarm 的情况下，最初启动 Swarm 的第一个节点成为领导者。如果领导者离开，剩下的管理者节点将选举新的领导者。共识组中的其他节点称为跟随者。

现在，让我们假设出于维护原因关闭当前的领导节点。剩下的管理者节点将选举新的领导者。当之前的领导节点恢复在线时，它将成为跟随者。新的领导者仍然是领导者。

共识组的所有成员之间进行同步通信。每当共识组需要做出决策时，领导者会要求所有跟随者同意。如果大多数管理者节点给出积极答复，那么领导者执行任务。这意味着如果我们有三个管理者节点，那么至少有一个跟随者必须同意领导者。如果我们有五个管理者节点，那么至少有两个跟随者必须同意。

由于所有管理者跟随者节点都必须与领导节点同步通信，以在集群中做出决策，所以随着形成共识组的管理者节点数量增加，决策过程变得越来越慢。Docker 的建议是在开发、演示或测试环境中使用一个管理者。在小到中等规模的 Swarm 中使用三个管理者节点，在大型到超大型的 Swarm 中使用五个管理者。在 Swarm 中使用超过五个管理者几乎没有理由。

管理者节点不仅负责管理 Swarm，还负责维护 Swarm 的状态。*我们指的是什么？*当我们谈论 Swarm 的状态时，我们指的是关于它的所有信息，例如*Swarm 中有多少节点*，*每个节点的属性是什么，比如名称或 IP 地址*。我们还指的是 Swarm 中哪个节点上运行了哪些容器等更多信息。另一方面，Swarm 状态中不包括由 Swarm 上容器中运行的应用服务产生的数据。这被称为应用数据，绝对不是由管理者节点管理的状态的一部分。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/cf1b7c95-25a4-43a4-aa20-168b1b938059.png)

一个 Swarm 管理器共识组

所有 Swarm 状态都存储在每个**manager**节点上的高性能键值存储（**kv-store**）中。没错，每个**manager**节点都存储了整个 Swarm 状态的完整副本。这种冗余使 Swarm 具有高可用性。如果一个**manager**节点宕机，剩下的**manager**都有完整的状态可用。

如果一个新的**manager**加入共识组，那么它会与现有组成员同步 Swarm 状态，直到拥有完整的副本。在典型的 Swarm 中，这种复制通常非常快，但如果 Swarm 很大并且有许多应用程序在其中运行，可能需要一段时间。

# Swarm 工人

正如我们之前提到的，Swarm 工作节点旨在托管和运行包含我们感兴趣在集群上运行的实际应用服务的容器。它们是 Swarm 的工作马。理论上，管理节点也可以是工作节点。但是，正如我们已经说过的，这在生产系统上是不推荐的。在生产系统上，我们应该让管理节点成为管理节点。

工作节点通过所谓的控制平面彼此交流。它们使用流言协议进行通信。这种通信是异步的，这意味着在任何给定时间，可能并非所有工作节点都完全同步。

现在，您可能会问——*工作节点交换什么信息？*主要是用于服务发现和路由的信息，即关于哪些容器正在哪些节点上运行等信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8049bdd7-03d8-405a-9ed4-e48e4d2216b4.png)

工作节点之间的通信

在上图中，您可以看到工人如何彼此交流。为了确保流言蜚语在大型 Swarm 中能够良好扩展，每个**worker**节点只与三个随机邻居同步自己的状态。对于熟悉大 O 符号的人来说，这意味着使用流言协议同步**worker**节点的规模为 O(0)。

**Worker**节点有点被动。除了运行由管理节点分配的工作负载之外，它们从不主动做任何事情。然而，**worker**确保以最佳能力运行这些工作负载。在本章后面，我们将更多地了解由管理节点分配给工作节点的工作负载。

# 堆栈、服务和任务

当使用 Docker Swarm 而不是单个 Docker 主机时，会有一种范式变化。我们不再谈论运行进程的单个容器，而是将其抽象为代表每个进程的一组副本的服务，并以这种方式变得高度可用。我们也不再谈论具有众所周知的名称和 IP 地址的单个 Docker 主机，我们现在将会提到部署服务的主机集群。我们不再关心单个主机或节点。我们不给它一个有意义的名称；对我们来说，每个节点都变成了一个数字。我们也不再关心个别容器以及它们被部署到哪里——我们只关心通过服务定义所需状态。我们可以尝试将其描述如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f1ff1173-269e-4448-a409-8279610fc9be.png)

容器部署到众所周知的服务器

与前面的图中将个别容器部署到众所周知的服务器不同，其中我们将**web**容器部署到具有 IP 地址`52.120.12.1`的**alpha**服务器，将**payments**容器部署到具有 IP`52.121.24.33`的**beta**服务器，我们转向了这种新的服务和 Swarm（或更一般地说，集群）的范式：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6dd5f3db-4cb9-4052-9071-a8cb8256586f.png)

服务部署到 Swarm

在前面的图中，我们看到一个**web**服务和一个**inventory**服务都部署到了由许多节点组成的**Swarm**中。每个服务都有一定数量的副本：**web**有六个，**inventory**有五个。我们并不关心副本将在哪个节点上运行；我们只关心所请求的副本数量始终在**Swarm**调度器决定放置它们的任何节点上运行。

# 服务

Swarm 服务是一个抽象的东西。它是对我们想要在 Swarm 中运行的应用程序或应用程序服务的期望状态的描述。Swarm 服务就像一个描述，描述了以下内容：

+   服务的名称

+   用于创建容器的镜像

+   要运行的副本数量

+   服务的容器附加到的网络

+   应该映射的端口

有了这个服务清单，Swarm 管理器确保所描述的期望状态始终得到调和，如果实际状态偏离了期望状态。因此，例如，如果服务的一个实例崩溃，那么 Swarm 管理器上的调度程序会在具有空闲资源的节点上调度这个特定服务的新实例，以便重新建立期望状态。

# 任务

我们已经了解到，服务对应于应用程序服务应始终处于的期望状态的描述。该描述的一部分是服务应该运行的副本数量。每个副本由一个任务表示。在这方面，Swarm 服务包含一组任务。在 Docker Swarm 上，任务是部署的原子单位。服务的每个任务由 Swarm 调度程序部署到工作节点。任务包含工作节点运行基于服务描述的镜像的所有必要信息。在任务和容器之间存在一对一的关系。容器是在工作节点上运行的实例，而任务是这个容器作为 Swarm 服务的一部分的描述。

# 堆栈

现在我们对 Swarm 服务和任务有了一个很好的了解，我们可以介绍堆栈。堆栈用于描述一组相关的 Swarm 服务，很可能是因为它们是同一应用程序的一部分。在这种意义上，我们也可以说堆栈描述了一个由我们想要在 Swarm 上运行的一到多个服务组成的应用程序。

通常，我们在一个文本文件中以 YAML 格式进行格式化描述堆栈，并使用与已知的 Docker Compose 文件相同的语法。这导致有时人们会说堆栈是由`docker-compose`文件描述的。更好的措辞应该是：堆栈是在使用类似于`docker-compose`文件的堆栈文件中描述的。

让我们尝试用下图来说明堆栈、服务和任务之间的关系，并将其与堆栈文件的典型内容联系起来：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/34c40ca5-56fa-4ce6-a61c-aa6d5ded8230.png)

显示堆栈、服务和任务之间关系的图表

在前面的图表中，我们可以看到右侧是一个样本**Stack**的声明性描述。**Stack**包括了三种服务，分别是**web**，**payments**和**inventory**。我们还可以看到**web**服务使用**example/web:1.0**镜像，并且有四个副本。

在图表的左侧，我们可以看到**Stack**包含了提到的三种服务。每种服务又包含了一系列的**Tasks**，数量与副本一样多。在**web**服务的情况下，我们有一个包含四个**Tasks**的集合。每个**Task**包含了它将实例化容器的**Image**的名称，一旦**Task**被安排在 Swarm 节点上。

# 多主机网络

在第十章中，*单主机网络*，我们讨论了容器在单个 Docker 主机上的通信。现在，我们有一个由节点或 Docker 主机组成的 Swarm。位于不同节点上的容器需要能够相互通信。有许多技术可以帮助我们实现这个目标。Docker 选择为 Docker Swarm 实现了一个**覆盖网络**驱动程序。这个**覆盖网络**允许连接到同一**覆盖网络**的容器相互发现并自由通信。以下是**覆盖网络**的工作原理的示意图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/1731fa28-e8f4-459e-b4c2-40e63b876032.png)

覆盖网络

我们有两个节点或 Docker 主机，IP 地址分别为`172.10.0.15`和`172.10.0.16`。我们选择的 IP 地址的值并不重要；重要的是两个主机都有不同的 IP 地址，并且通过一个物理网络（网络电缆）连接，这个网络称为**底层网络**。

在左侧的节点上有一个运行着 IP 地址为`10.3.0.2`的容器，右侧的节点上有另一个 IP 地址为`10.3.0.5`的容器。现在，前者的容器想要与后者通信。*这怎么可能？*在第十章中，*单主机网络*，我们看到了当两个容器位于同一节点上时，这是如何工作的——通过使用 Linux 桥接。但 Linux 桥接只能在本地操作，无法跨越节点。所以，我们需要另一种机制。Linux VXLAN 来解救。VXLAN 在容器出现之前就已经在 Linux 上可用。

当左侧容器发送数据包时，**桥接**意识到数据包的目标不在此主机上。现在，参与覆盖网络的每个节点都会得到一个所谓的**VXLAN 隧道端点**（**VTEP**）对象，它拦截数据包（此时的数据包是 OSI 第 2 层数据包），用包含运行目标容器的主机的目标 IP 地址的头部包装它（这样它现在是 OSI 第 3 层数据包），并将其发送到**VXLAN 隧道**。隧道另一侧的**VTEP**解包数据包并将其转发到本地桥接，本地桥接再将其转发到目标容器。

覆盖驱动程序包含在 SwarmKit 中，在大多数情况下是 Docker Swarm 的推荐网络驱动程序。还有其他来自第三方的多节点网络驱动程序可作为插件安装到每个参与的 Docker 主机上。Docker 商店提供认证的网络插件。

# 创建一个 Docker Swarm

创建一个 Docker Swarm 几乎是微不足道的。如果你知道编排器是什么，那么它是如此容易，以至于似乎不真实。但事实是，Docker 在使 Swarm 简单而优雅的使用方面做得非常出色。与此同时，Docker Swarm 已被大型企业证明在使用中非常稳健和可扩展。

# 创建一个本地单节点 Swarm

所以，想象足够了，让我们演示一下我们如何创建一个 Swarm。在其最简单的形式中，一个完全功能的 Docker Swarm 只包括一个单节点。如果你正在使用 Docker for Mac 或 Windows，甚至是使用 Docker Toolbox，那么你的个人计算机或笔记本电脑就是这样一个节点。因此，我们可以从这里开始，演示 Swarm 的一些最重要的特性。

让我们初始化一个 Swarm。在命令行上，只需输入以下命令：

```
$ docker swarm init
```

在非常短的时间后，你应该看到类似以下截图的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/39cd7eb9-5916-422b-a23f-a158857f0401.png)Docker Swarm init 命令的输出

我们的计算机现在是一个 Swarm 节点。它的角色是管理者，它是领导者（管理者中的领导者，这是有道理的，因为此时只有一个管理者）。虽然`docker swarm init`只花了很短的时间就完成了，但在那段时间里命令做了很多事情。其中一些如下：

+   它创建了一个根**证书颁发机构**（**CA**）。

+   它创建了一个用于存储整个 Swarm 状态的键值存储。

现在，在前面的输出中，我们可以看到一个命令，可以用来加入我们刚刚创建的 Swarm 的其他节点。命令如下：

```
$ docker swarm join --token <join-token> <IP address>:2377
```

在这里，我们有以下内容：

+   <join-token>是 Swarm 领导者在初始化 Swarm 时生成的令牌。

+   <IP 地址>是领导者的 IP 地址。

尽管我们的集群仍然很简单，因为它只包含一个成员，但我们仍然可以要求 Docker CLI 列出 Swarm 的所有节点。这将类似于以下屏幕截图：

列出 Docker Swarm 的节点

在此输出中，我们首先看到赋予节点的 ID。跟随 ID 的星号（*）表示这是执行 docker node ls 的节点，基本上表示这是活动节点。然后，我们有节点的（人类可读的）名称，其状态，可用性和管理器状态。正如前面提到的，Swarm 的第一个节点自动成为领导者，这在前面的屏幕截图中有所指示。最后，我们看到我们正在使用的 Docker 引擎的版本。

要获取有关节点的更多信息，我们可以使用 docker node inspect 命令，如下面的屏幕截图所示：

使用 docker node inspect 命令的截断输出

此命令生成了大量信息，因此我们只呈现输出的截断版本。例如，当您需要排除集群节点的故障时，此输出可能很有用。

# 在 VirtualBox 或 Hyper-V 中创建本地 Swarm

有时，单个节点的 Swarm 是不够的，但我们没有或不想使用帐户在云中创建 Swarm。在这种情况下，我们可以在 VirtualBox 或 Hyper-V 中创建本地 Swarm。在 VirtualBox 中创建 Swarm 比在 Hyper-V 中创建 Swarm 稍微容易一些，但是如果您使用 Windows 10 并且正在运行 Docker for Windows，则无法同时使用 VirtualBox。这两个 hypervisor 是互斥的。

假设我们的笔记本电脑上已安装了 VirtualBox 和 docker-machine。然后，我们可以使用 docker-machine 列出当前定义并可能在 VirtualBox 中运行的所有 Docker 主机：

```
$ docker-machine ls
NAME ACTIVE DRIVER STATE URL SWARM DOCKER ERRORS
default - virtualbox Stopped Unknown
```

在我的情况下，我定义了一个名为 default 的 VM，当前已停止。我可以通过发出 docker-machine start default 命令轻松启动 VM。此命令需要一段时间，并将导致以下（缩短的）输出：

```
$ docker-machine start default
Starting "default"...
(default) Check network to re-create if needed...
(default) Waiting for an IP...
Machine "default" was started.
Waiting for SSH to be available...
Detecting the provisioner...
Started machines may have new IP addresses. You may need to re-run the `docker-machine env` command.
```

现在，如果我再次列出我的虚拟机，我应该看到以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e64986fa-4614-4968-9d15-b62e7e873916.png)在 Hyper-V 中运行的所有虚拟机列表

如果我们还没有名为`default`的虚拟机，我们可以使用`create`命令轻松创建一个：

```
docker-machine create --driver virtualbox default
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/9a6258ef-8613-41e5-95cb-b86bfe858b8e.png)docker-machine create 的输出

我们可以在前面的输出中看到`docker-machine`如何从 ISO 映像创建虚拟机，定义 SSH 密钥和证书，并将它们复制到虚拟机和本地`~/.docker/machine`目录，以便我们以后在通过 Docker CLI 远程访问此虚拟机时使用。它还为新的虚拟机提供了一个 IP 地址。

我们使用`docker-machine create`命令和`--driver virtualbox`参数。docker-machine 也可以使用其他驱动程序，如 Hyper-V、AWS、Azure、DigitalOcean 等。有关更多信息，请参阅`docker-machine`的文档。默认情况下，新的虚拟机关联了 1GB 的内存，这足以将此虚拟机用作开发或测试 Swarm 的节点。

如果您使用的是带有 Docker for Desktop 的 Windows 10，请改用`hyperv`驱动程序。但是，要成功，您需要以管理员身份运行。此外，您需要在 Hyper-V 上首先定义一个外部虚拟交换机。您可以使用 Hyper-V 管理器来完成。该命令的输出将与`virtualbox`驱动程序的输出非常相似。

现在，让我们为一个五节点的 Swarm 创建五个虚拟机。我们可以使用一些脚本来减少手动工作：

```
$ for NODE in `seq 1 5`; do
  docker-machine create --driver virtualbox "node-${NODE}"
done
```

`docker-machine`现在将创建五个名为`node-1`到`node-5`的虚拟机。这可能需要一些时间，所以现在是喝杯热茶的好时机。虚拟机创建完成后，我们可以列出它们：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2820423c-f815-4247-a15e-251dd7791c3d.png)我们需要 Swarm 的所有虚拟机列表

现在，我们准备构建一个 Swarm。从技术上讲，我们可以 SSH 到第一个 VM `node-1`并初始化一个 Swarm，然后 SSH 到所有其他 VM 并加入它们到 Swarm 领导者。但这并不高效。让我们再次使用一个可以完成所有繁重工作的脚本：

```
# get IP of Swarm leader
$ export IP=$(docker-machine ip node-1)
# init the Swarm
$ docker-machine ssh node-1 docker swarm init --advertise-addr $IP
# Get the Swarm join-token
$ export JOIN_TOKEN=$(docker-machine ssh node-1 \
    docker swarm join-token worker -q)
```

现在我们有了加入令牌和 Swarm 领导者的 IP 地址，我们可以要求其他节点加入 Swarm，如下所示：

```
$ for NODE in `seq 2 5`; do
  NODE_NAME="node-${NODE}"
  docker-machine ssh $NODE_NAME docker swarm join \
        --token $JOIN_TOKEN $IP:2377
done
```

为了使 Swarm 具有高可用性，我们现在可以将例如`node-2`和`node-3`提升为管理者：

```
$ docker-machine ssh node-1 docker node promote node-2 node-3
Node node-2 promoted to a manager in the swarm.
Node node-3 promoted to a manager in the swarm.
```

最后，我们可以列出 Swarm 的所有节点：

```
$ docker-machine ssh node-1 docker node ls
```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/dfb95f3f-4cbd-4275-b620-f5a6b5493e88.png)VirtualBox 上 Docker Swarm 的所有节点列表

这证明我们刚刚在本地笔记本电脑或工作站上创建了一个高可用的 Docker Swarm。让我们把所有的代码片段放在一起，使整个过程更加健壮。脚本如下所示：

```
alias dm="docker-machine"
for NODE in `seq 1 5`; do
  NODE_NAME=node-${NODE}
  dm rm --force $NODE_NAME
  dm create --driver virtualbox $NODE_NAME
done
alias dms="docker-machine ssh"
export IP=$(docker-machine ip node-1)
dms node-1 docker swarm init --advertise-addr $IP;
export JOIN_TOKEN=$(dms node-1 docker swarm join-token worker -q);
for NODE in `seq 2 5`; do
  NODE_NAME="node-${NODE}"
  dms $NODE_NAME docker swarm join --token $JOIN_TOKEN $IP:2377
done;
dms node-1 docker node promote node-2 node-3
```

上述脚本首先删除（如果存在），然后重新创建名为`node-1`到`node-5`的五个虚拟机，然后在`node-1`上初始化一个 Swarm。之后，剩下的四个虚拟机被添加到 Swarm 中，最后，`node-2`和`node-3`被提升为管理者状态，使 Swarm 高可用。整个脚本执行时间不到 5 分钟，可以重复执行多次。完整的脚本可以在存储库的`docker-swarm`子文件夹中找到；它被称为`create-swarm.sh`。

在我们的笔记本电脑或工作站上，始终编写脚本并自动化操作是一种强烈推荐的最佳实践。

# 使用 Play with Docker 生成一个 Swarm

为了在我们的计算机上**无需**安装或配置**任何**东西的情况下尝试 Docker Swarm，我们可以使用**Play with Docker**（**PWD**）。PWD 是一个可以通过浏览器访问的网站，它为我们提供了创建一个由最多五个节点组成的 Docker Swarm 的能力。正如名称所示，它绝对是一个游乐场，我们可以使用的时间限制为每个会话四个小时。我们可以打开尽可能多的会话，但每个会话在四小时后会自动结束。除此之外，它是一个完全功能的 Docker 环境，非常适合尝试 Docker 或演示一些功能。

现在让我们访问该网站。在浏览器中，导航到网站[`labs.play-with-docker.com`](https://labs.play-with-docker.com)。您将看到一个欢迎和登录屏幕。使用您的 Docker ID 登录。成功登录后，您将看到一个看起来像以下截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3172277e-9a56-44e6-8651-cfe1d23cf525.png)Play with Docker 窗口

正如我们立即看到的，有一个大计时器从四小时开始倒计时。这是我们在本次会话中剩下的时间。此外，我们看到一个+ ADD NEW INSTANCE 链接。单击它以创建一个新的 Docker 主机。这样做后，您的屏幕应该看起来像以下的截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/07316581-3443-4328-ba3b-5c57af1e85c8.png)PWD 带有一个新节点

在左侧，我们看到了新创建的节点及其 IP 地址（`192.168.0.48`）和名称（`node1`）。在右侧，屏幕的上半部分显示了有关这个新节点的一些额外信息，下半部分显示了一个终端。是的，这个终端用于在我们刚刚创建的节点上执行命令。这个节点已经安装了 Docker CLI，因此我们可以在上面执行所有熟悉的 Docker 命令，比如`docker version`。试一下吧。

但现在我们想要创建一个 Docker Swarm。在浏览器的终端中执行以下命令：

```
$ docker swarm init --advertise-addr=eth0
```

前面命令生成的输出与我们之前在工作站上使用单节点集群和在 VirtualBox 或 Hyper-V 上使用本地集群时已经知道的内容相对应。重要的信息再次是我们想要用来加入额外节点到我们刚刚创建的集群的`join`命令。

你可能已经注意到，这次我们在 Swarm 的`init`命令中指定了`--advertise-addr`参数。*为什么在这里有必要？*原因是 PWD 生成的节点有多个与之关联的 IP 地址。我们可以通过在节点上执行`ip a`命令轻松验证这一点。这个命令将向我们显示确实存在两个端点，`eth0`和`eth1`。因此，我们必须明确地指定给新的 Swarm 管理器我们想要使用哪一个。在我们的情况下，是`eth0`。

通过点击四次“+添加新实例”链接在 PWD 中创建四个额外的节点。新节点将被命名为`node2`、`node3`、`node4`和`node5`，并且都将列在左侧。如果你点击左侧的一个节点，右侧将显示相应节点的详细信息和该节点的终端窗口。

选择每个节点（2 到 5）并在相应的终端中执行从领导节点（`node1`）复制的`docker swarm join`命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/22724adb-5938-4487-a1f2-9d491800bb51.png)加入节点到 PWD 中的 Swarm

一旦你将所有四个节点加入到 Swarm 中，切换回`node1`并列出所有节点，结果如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e270d3d8-8783-4eec-9ba2-2a66f9a43a08.png)PWD 中 Swarm 的所有节点列表

仍然在`node1`上，我们现在可以提升，比如说，`node2`和`node3`，使 Swarm 高度可用：

```
$ docker node promote node2 node3
Node node2 promoted to a manager in the swarm.
Node node3 promoted to a manager in the swarm.
```

有了这个，我们在 PWD 上的 Swarm 已经准备好接受工作负载。我们已经创建了一个高可用的 Docker Swarm，其中包括三个管理节点，形成一个 Raft 共识组，以及两个工作节点。

# 在云端创建一个 Docker Swarm

到目前为止，我们创建的所有 Docker Swarms 都非常适合在开发中使用，或者用于实验或演示目的。但是，如果我们想创建一个可以用作生产环境的 Swarm，在那里运行我们的关键应用程序，那么我们需要在云端或本地创建一个——我很想说——真正的 Swarm。在本书中，我们将演示如何在 AWS 中创建 Docker Swarm。

创建 Swarm 的一种方法是使用**docker-machine**（**DM**）。DM 在 AWS 上有一个驱动程序。如果我们在 AWS 上有一个账户，我们需要 AWS 访问密钥 ID 和 AWS 秘密访问密钥。我们可以将这两个值添加到一个名为`~/.aws/configuration`的文件中。它应该看起来像下面这样：

```
[default]
aws_access_key_id = AKID1234567890
aws_secret_access_key = MY-SECRET-KEY
```

每次我们运行`docker-machine create`，DM 都会在该文件中查找这些值。有关如何获取 AWS 账户和获取两个秘钥的更深入信息，请参考此链接：[`dockr.ly/2FFelyT`](http://dockr.ly/2FFelyT)。

一旦我们有了 AWS 账户并将访问密钥存储在配置文件中，我们就可以开始构建我们的 Swarm。所需的代码看起来与我们在 VirtualBox 上的本地机器上创建 Swarm 时使用的代码完全相同。让我们从第一个节点开始：

```
$ docker-machine create --driver amazonec2 \
 --amazonec2-region us-east-1 aws-node-1
```

这将在请求的区域（在我的情况下是`us-east-1`）中创建一个名为`aws-node-1`的 EC2 实例。前面命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ca6013e9-a419-478f-8967-e86ac6defaab.png)使用 DM 在 AWS 上创建一个 Swarm 节点

它看起来与我们已经知道的与 VirtualBox 一起工作的输出非常相似。我们现在可以配置我们的终端以远程访问该 EC2 实例：

```
$ eval $(docker-machine env aws-node-1)
```

这将相应地配置 Docker CLI 使用的环境变量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2776b997-08d5-4993-8f68-e047a054969e.png)Docker 用于启用对 AWS EC2 节点的远程访问的环境变量

出于安全原因，**传输层安全**（**TLS**）用于我们的 CLI 和远程节点之间的通信。DM 将必要的证书复制到我们分配给环境变量`DOCKER_CERT_PATH`的路径。

我们现在在终端中执行的所有 Docker 命令都将在我们的 EC2 实例上远程执行。让我们尝试在此节点上运行 Nginx：

```
$ docker container run -d -p 8000:80 nginx:alpine
```

我们可以使用`docker container ls`来验证容器是否正在运行。如果是的话，让我们使用`curl`进行测试：

```
$ curl -4 <IP address>:8000
```

这里，`<IP 地址>`是 AWS 节点的公共 IP 地址；在我的情况下，它将是`35.172.240.127`。遗憾的是，这不起作用；前面的命令超时：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0f6eb2e9-c813-4c67-b0a8-3d4e623caa0d.png)访问 AWS 节点上的 Nginx 超时

原因是我们的节点是 AWS **安全组**（SG）的一部分。默认情况下，拒绝对此 SG 内部的对象的访问。因此，我们必须找出我们的实例属于哪个 SG，并显式配置访问权限。为此，我们通常使用 AWS 控制台。转到 EC2 仪表板，并在左侧选择实例。找到名为`aws-node-1`的 EC2 实例并选择它。在详细视图中，在“安全组”下，单击 docker-machine 链接，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/daacdfa4-bfb7-4c54-8333-4f42a645ed2d.png)找到我们的 Swarm 节点所属的 SG

这将引导我们到 SG 页面，其中`docker-machine` SG 被预先选择。在“入站”选项卡下的详细信息部分，为您的 IP 地址（工作站的 IP 地址）添加一个新规则：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0d0ee48e-dd73-4b8e-87ee-e5069e77183b.png)

为我们的计算机打开 SG 访问权限

在前面的屏幕截图中，IP 地址`70.113.114.234`恰好是分配给我的个人工作站的 IP 地址。我已经允许来自此 IP 地址的所有入站流量进入`docker-machine` SG。请注意，在生产系统中，您应该非常小心地选择要向公众开放的 SG 端口。通常，这是用于 HTTP 和 HTTPS 访问的端口`80`和`443`。其他所有内容都是对黑客的潜在邀请。

您可以通过诸如[`www.whatismyip.com/`](https://www.whatismyip.com/)之类的服务获取自己的 IP 地址。现在，如果我们再次执行`curl`命令，将返回 Nginx 的欢迎页面。

在我们离开 SG 之前，我们应该向其添加另一个规则。Swarm 节点需要能够通过 TCP 和 UDP 自由通信的端口`7946`和`4789`，以及通过 TCP 的端口`2377`。我们现在可以添加五个符合这些要求的规则，其中源是 SG 本身，或者我们只需定义一个允许 SG 内部所有入站流量的粗糙规则（在我的情况下是`sg-c14f4db3`）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/a51e4f76-db2c-4513-8dc2-d878d5e0ba30.png) SG 规则以启用 Swarm 内部通信

现在，让我们继续创建剩下的四个节点。我们可以再次使用脚本来简化这个过程：

```
$ for NODE in `seq 2 5`; do
 docker-machine create --driver amazonec2 \
 --amazonec2-region us-east-1 aws-node-${NODE}
done
```

节点的配置完成后，我们可以使用 DM 列出所有节点。在我的情况下，我看到了这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/9fe33d9f-01b8-4fc8-9bf7-c24f2cfaa1a3.png)DM 创建的所有节点列表

在前面的截图中，我们可以看到我们最初在 VirtualBox 中创建的五个节点和我们在 AWS 中创建的五个新节点。显然，AWS 上的节点正在使用一个新版本的 Docker；这里的版本是`18.02.0-ce`。我们在`URL`列中看到的 IP 地址是我的 EC2 实例的公共 IP 地址。

因为我们的 CLI 仍然配置为远程访问`aws-node-1`节点，所以我们可以直接运行以下`swarm init`命令：

```
$ docker swarm init
```

要获取加入令牌，请执行以下操作：

```
$ export JOIN_TOKEN=$(docker swarm join-token -q worker)
```

要获取领导者的 IP 地址，请使用以下命令：

```
$ export LEADER_ADDR=$(docker node inspect \
 --format "{{.ManagerStatus.Addr}}" self)
```

有了这些信息，我们现在可以将其他四个节点加入到 Swarm 的领导者中：

```
$ for NODE in `seq 2 5`; do
 docker-machine ssh aws-node-${NODE} \
 sudo docker swarm join --token ${JOIN_TOKEN} ${LEADER_ADDR}
done
```

实现相同目标的另一种方法是，无需登录到各个节点，每次想要访问不同的节点时都重新配置我们的客户端 CLI：

```
$ for NODE in `seq 2 5`; do
 eval $(docker-machine env aws-node-${NODE})
 docker swarm join --token ${JOIN_TOKEN} ${LEADER_ADDR}
done
```

作为最后一步，我们希望将节点`2`和`3`提升为管理节点：

```
$ eval $(docker-machine env node-1)
$ docker node promote aws-node-2 aws-node-3
```

然后，我们可以列出所有 Swarm 节点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0038c9cb-fc2f-4a9d-ac15-af1133dbf6b8.png)云中我们 Swarm 的所有节点列表

因此，我们在云中拥有一个高可用的 Docker Swarm。为了清理云中的 Swarm 并避免产生不必要的成本，我们可以使用以下命令：

```
$ for NODE in `seq 1 5`; do
 docker-machine rm -f aws-node-${NODE}
done
```

# 部署第一个应用程序

我们在各种平台上创建了一些 Docker Swarms。一旦创建，Swarm 在任何平台上的行为都是相同的。我们在 Swarm 上部署和更新应用程序的方式并不依赖于平台。Docker 的主要目标之一就是避免在使用 Swarm 时出现供应商锁定。支持 Swarm 的应用程序可以轻松地从例如在本地运行的 Swarm 迁移到基于云的 Swarm。甚至在技术上可以在本地运行 Swarm 的一部分，另一部分在云中运行。这是可行的，但我们当然必须考虑由于地理上相距较远的节点之间的更高延迟可能导致的可能的副作用。

现在我们有一个高可用的 Docker Swarm 正在运行，是时候在其上运行一些工作负载了。我正在使用通过 docker-machine 创建的本地 Swarm。我们将首先创建一个单一服务。为此，我们需要 SSH 登录到其中一个管理节点。我选择`node-1`：

```
$ docker-machine ssh node-1
```

# 创建一个服务

服务可以作为堆栈的一部分创建，也可以直接使用 Docker CLI 创建。让我们首先看一个定义单一服务的示例堆栈文件：

```
version: "3.7"
services:
  whoami:
    image: training/whoami:latest
    networks:
      - test-net
    ports:
      - 81:8000
    deploy:
      replicas: 6
      update_config:
        parallelism: 2
        delay: 10s
      labels:
        app: sample-app
        environment: prod-south

networks:
  test-net:
    driver: overlay
```

在前面的示例中，我们看到了一个名为`whoami`的服务的期望状态：

+   它基于`training/whoami:latest`镜像。

+   服务的容器连接到`test-net`网络。

+   容器端口`8000`发布到端口`81`。

+   它以六个副本（或任务）运行

+   在滚动更新期间，单个任务以每批两个的方式更新，每个成功批之间延迟 10 秒。

+   该服务（及其任务和容器）被分配了两个标签`app`和`environment`，其值分别为`sample-app`和`prod-south`。

我们可以为服务定义许多其他设置，但前面的设置是一些更重要的设置。大多数设置都有有意义的默认值。例如，如果我们没有指定副本的数量，那么 Docker 会将其默认为`1`。服务的名称和镜像当然是必需的。请注意，服务的名称在 Swarm 中必须是唯一的。

要创建前面的服务，我们使用`docker stack deploy`命令。假设存储前面内容的文件名为`stack.yaml`，我们有以下内容：

```
$ docker stack deploy -c stack.yaml sample-stack
```

在这里，我们创建了一个名为`sample-stack`的堆栈，其中包含一个名为`whoami`的服务。我们可以列出我们的 Swarm 上的所有堆栈，然后我们应该得到这个：

```
$ docker stack ls
NAME             SERVICES
sample-stack     1
```

如果我们列出我们的 Swarm 中定义的服务，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2598bb40-3f60-44b3-8bb8-2d23d4e5a2df.png)列出在 Swarm 中运行的所有服务

在输出中，我们可以看到目前只有一个正在运行的服务，这是可以预料的。该服务有一个`ID`。与迄今为止用于容器、网络或卷的格式相反，`ID`的格式是字母数字（在后一种情况下，它总是`sha256`）。我们还可以看到服务的`NAME`是我们在堆栈文件中定义的服务名称和堆栈的名称的组合，堆栈的名称被用作前缀。这是有道理的，因为我们希望能够使用相同的堆栈文件将多个堆栈（具有不同名称）部署到我们的 Swarm 中。为了确保服务名称是唯一的，Docker 决定将服务名称和堆栈名称组合起来。

在第三列中，我们看到模式是`replicated`。`REPLICAS`的数量显示为`6/6`。这告诉我们，六个请求的`REPLICAS`中有六个正在运行。这对应于期望的状态。在输出中，我们还可以看到服务使用的镜像和服务的端口映射。

# 检查服务及其任务

在前面的输出中，我们看不到已创建的`6`个副本的详细信息。为了更深入地了解这一点，我们可以使用`docker service ps`命令。如果我们为我们的服务执行此命令，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/407ffc09-b33c-459b-a73c-fb17de789245.png)whoami 服务的详细信息

在前面的输出中，我们可以看到与我们请求的`whoami`服务的六个副本相对应的六个任务的列表。在`NODE`列中，我们还可以看到每个任务部署到的节点。每个任务的名称是服务名称加上递增索引的组合。还要注意，与服务本身类似，每个任务都被分配了一个字母数字 ID。

在我的情况下，显然任务 2，名称为`sample-stack_whoami.2`，已部署到了`node-1`，这是我们 Swarm 的领导者。因此，我应该在这个节点上找到一个正在运行的容器。让我们看看如果我们列出在`node-1`上运行的所有容器会得到什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/18d77691-b017-4ff3-9ea0-d07b10cd107a.png)节点 1 上的容器列表

预期地，我们发现一个容器正在运行`training/whoami:latest`镜像，其名称是其父任务名称和 ID 的组合。我们可以尝试可视化我们部署示例堆栈时生成的所有对象的整个层次结构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/376c4e6d-f65b-4c82-b74b-02f320141812.png)

Docker Swarm 堆栈的对象层次结构

**堆栈**可以由一个到多个服务组成。每个服务都有一组任务。每个任务与一个容器有一对一的关联。堆栈和服务是在 Swarm 管理节点上创建和存储的。然后将任务调度到 Swarm 工作节点，工作节点在那里创建相应的容器。我们还可以通过检查来获取有关我们的服务的更多信息。执行以下命令：

```
$ docker service inspect sample-stack_whoami
```

这提供了有关服务的所有相关设置的丰富信息。这包括我们在`stack.yaml`文件中明确定义的设置，但也包括我们没有指定的设置，因此被分配了它们的默认值。我们不会在这里列出整个输出，因为它太长了，但我鼓励读者在自己的机器上检查它。我们将在*Swarm 路由网格*部分更详细地讨论部分信息。

# 服务的日志

在早些章节中，我们处理了容器产生的日志。在这里，我们专注于一个服务。请记住，最终，具有许多副本的服务有许多容器在运行。因此，我们期望，如果我们要求服务的日志，Docker 会返回属于该服务的所有容器的日志的聚合。确实，这就是我们使用`docker service logs`命令得到的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/cbe0a89f-0434-42a8-ae44-c1abdf29515f.png)whoami 服务的日志

在这一点上，日志中没有太多信息，但足以讨论我们得到了什么。日志中每行的第一部分始终包含容器的名称，以及日志条目来源的节点名称。然后，通过竖线（`|`）分隔，我们得到实际的日志条目。因此，如果我们直接要求获取列表中第一个容器的日志，我们将只获得一个条目，而在这种情况下我们将看到的值是`Listening on :8000`。

使用`docker service logs`命令获取的聚合日志没有按任何特定方式排序。因此，如果事件的相关性发生在不同的容器中，您应该在日志输出中添加信息，使这种相关性成为可能。通常，这是每个日志条目的时间戳。但这必须在源头完成；例如，产生日志条目的应用程序还需要确保添加时间戳。

我们也可以通过提供任务 ID 而不是服务 ID 或名称来查询服务的单个任务的日志。因此，查询任务 2 的日志会给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/edd0bb6b-3bfc-4cb8-97f1-ddab8836e1c6.png)whoami 服务的单个任务的日志

# 调和期望的状态

我们已经了解到，Swarm 服务是我们希望应用程序或应用程序服务在其中运行的期望状态的描述或清单。现在，让我们看看 Docker Swarm 如何调和这个期望的状态，如果我们做了一些导致服务的实际状态与期望状态不同的事情。这样做的最简单方法是强制杀死服务的一个任务或容器。

让我们用安排在`node-1`上的容器来做这个：

```
$ docker container rm -f sample-stack_whoami.2.n21e7ktyvo4b2sufalk0aibzy
```

如果我们这样做，然后立即运行`docker service ps`，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2b7a9616-8a86-467d-8e73-eafd14dd9f97.png)Docker Swarm 在一个任务失败后调和期望的状态

我们看到任务 2 以退出码`137`失败，并且 Swarm 立即通过在具有空闲资源的节点上重新调度失败的任务来调和期望的状态。在这种情况下，调度程序选择了与失败任务相同的节点，但这并不总是这样。因此，在我们不干预的情况下，Swarm 完全解决了问题，并且由于服务正在多个副本中运行，服务从未停机。

让我们尝试另一种失败场景。这一次，我们将关闭整个节点，并看看 Swarm 的反应。让我们选择`node-2`，因为它上面有两个任务（任务 3 和任务 4）正在运行。为此，我们需要打开一个新的终端窗口，并使用`docker-machine`来停止`node-2`：

```
$ docker-machine stop node-2
```

回到`node-1`，我们现在可以再次运行`docker service ps`来看看发生了什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e9b37aa0-d5c0-4666-8a11-f57874d4d283.png)Swarm 重新安排了一个失败节点的所有任务

在前面的屏幕截图中，我们可以看到立即任务 3 被重新安排在`node-1`上，而任务 4 被重新安排在`node-3`上。即使这种更激进的失败也能被 Docker Swarm 优雅地处理。

但需要注意的是，如果`node-2`在 Swarm 中重新上线，之前在其上运行的任务将不会自动转移到它上面。但是该节点现在已经准备好接受新的工作负载。

# 删除服务或堆栈

如果我们想要从 Swarm 中移除特定的服务，我们可以使用`docker service rm`命令。另一方面，如果我们想要从 Swarm 中移除一个堆栈，我们类似地使用`docker stack rm`命令。这个命令会移除堆栈定义中的所有服务。在`whoami`服务的情况下，它是通过使用堆栈文件创建的，因此我们将使用后者命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/61fca437-abee-41f3-8cea-6a8a534a58fc.png)移除一个堆栈

上述命令将确保堆栈的每个服务的所有任务被终止，并且相应的容器首先发送`SIGTERM`，然后，如果不成功，在 10 秒的超时后发送`SIGKILL`。

重要的是要注意，停止的容器不会从 Docker 主机中删除。因此，建议定期清理工作节点上的容器，以回收未使用的资源。为此，使用`docker container purge -f`。

问题：为什么让停止或崩溃的容器留在工作节点上，而不自动删除它们是有意义的？

# 部署多服务堆栈

在第十一章中，*Docker Compose*，我们使用了一个由两个服务组成的应用程序，在 Docker compose 文件中进行了声明性描述。我们可以使用这个 compose 文件作为模板，创建一个堆栈文件，允许我们将相同的应用程序部署到 Swarm 中。我们的堆栈文件的内容，名为`pet-stack.yaml`，如下所示：

```
version: "3.7"
services:
 web:
   image: fundamentalsofdocker/ch11-web:2.0
   networks:
   - pets-net
   ports:
   - 3000:3000
   deploy:
     replicas: 3
 db:
   image: fundamentalsofdocker/ch11-db:2.0
   networks:
   - pets-net
   volumes:
   - pets-data:/var/lib/postgresql/data

volumes:
 pets-data:

networks:
 pets-net:
 driver: overlay
```

我们要求`web`服务有三个副本，并且两个服务都连接到叠加网络`pets-net`。我们可以使用`docker stack deploy`命令部署这个应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4920e7c3-dc61-4bcf-9960-cc64dcb42e3f.png)部署宠物堆栈

Docker 创建了`pets_pets-net`叠加网络，然后创建了两个服务`pets_web`和`pets_db`。然后我们可以列出`pets`堆栈中的所有任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2af11ff2-9cb7-4056-aa02-409bce27fed2.png)宠物堆栈中所有任务的列表

最后，让我们使用`curl`测试应用程序。确实，应用程序按预期工作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7e7fac0b-5781-4038-a0f8-8f53d933da3f.png)使用 curl 测试宠物应用程序

容器 ID 在输出中，其中写着`由容器 8b906b509a7e 提供给您`。如果多次运行`curl`命令，ID 应该在三个不同的值之间循环。这些是我们为`web`服务请求的三个容器（或副本）的 ID。

完成后，我们可以使用`docker stack rm pets`来删除堆栈。

# Swarm 路由网格

如果你一直在关注，那么你可能已经注意到了上一节中的一些有趣的事情。我们部署了`pets`应用程序，结果是`web`服务的一个实例被安装在三个节点`node-1`、`node-2`和`node-3`上。然而，我们能够通过`localhost`访问`node-1`上的`web`服务，并从那里访问每个容器。*这是怎么可能的？*嗯，这是由于所谓的 Swarm 路由网格。路由网格确保当我们发布一个服务的端口时，该端口会在 Swarm 的所有节点上发布。因此，命中 Swarm 的任何节点并请求使用特定端口的网络流量将通过路由网格转发到服务容器之一。让我们看看下面的图表，看看它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/6ceca300-992c-4267-a309-239315df3cd9.png)

Docker Swarm 路由网格

在这种情况下，我们有三个节点，称为**主机 A**到**主机 C**，它们的 IP 地址分别是`172.10.0.15`、`172.10.0.17`和`172.10.0.33`。在图表的左下角，我们看到了创建一个具有两个副本的**web**服务的命令。相应的任务已经被安排在**主机 B**和**主机 C**上。任务 1 落在**主机 B**上，而任务 2 落在**主机 C**上。

当在 Docker Swarm 上创建服务时，它会自动分配一个**虚拟 IP**（VIP）地址。这个 IP 地址在整个服务的生命周期内是稳定和保留的。假设在我们的情况下，VIP 是`10.2.0.1`。

如果现在来自外部**负载均衡器**（**LB**）的端口`8080`的请求被定向到我们 Swarm 的一个节点上，那么这个请求将由该节点上的 Linux **IP 虚拟服务器**（**IPVS**）服务处理。该服务在 IP 表中使用给定的端口`8080`进行查找，并将找到这对应于**web**服务的 VIP。现在，由于 VIP 不是一个真正的目标，IPVS 服务将负载均衡与该服务关联的任务的 IP 地址。在我们的情况下，它选择了任务 2，其 IP 地址为`10.2.0.3`。最后，**入口**网络（**Overlay**）用于将请求转发到**Host C**上的目标容器。

重要的是要注意，外部请求被**外部 LB**转发到哪个 Swarm 节点并不重要。路由网格将始终正确处理请求并将其转发到目标服务的任务之一。

# 总结

在本章中，我们介绍了 Docker Swarm，它是继 Kubernetes 之后第二受欢迎的容器编排器。我们研究了 Swarm 的架构，讨论了在 Swarm 中运行的所有类型的资源，如服务、任务等，并在 Swarm 中创建了服务，并部署了由多个相关服务组成的应用程序。

在下一章中，我们将探讨如何在 Docker Swarm 上部署服务或应用程序，实现零停机时间和自动回滚功能。我们还将介绍秘密作为保护敏感信息的手段。

# 问题

为了评估您的学习进度，请回答以下问题：

1.  如何初始化一个新的 Docker Swarm？

A. `docker init swarm`

B. `docker swarm init --advertise-addr <IP 地址>`

C. `docker swarm join --token <加入令牌>`

1.  您想要从 Docker Swarm 中删除一个工作节点。需要哪些步骤？

1.  如何创建一个名为`front-tier`的覆盖网络？使网络可附加。

1.  您将如何从`nginx:alpine`镜像创建一个名为`web`的服务，该服务有五个副本，将端口`3000`暴露在入口网络上，并附加到`front-tier`网络？

1.  您将如何将 web 服务缩减到三个实例？

# 进一步阅读

请参考以下链接，了解有关所选主题的更深入信息：

+   AWS EC2 示例在[`dockr.ly/2FFelyT`](http://dockr.ly/2FFelyT)

+   Raft 一致性算法在[`raft.github.io/`](https://raft.github.io/)

+   Gossip Protocol 的[`en.wikipedia.org/wiki/Gossip_protocol`](https://en.wikipedia.org/wiki/Gossip_protocol)

+   VXLAN 和 Linux 的[`vincent.bernat.ch/en/blog/2017-vxlan-linux`](https://vincent.bernat.ch/en/blog/2017-vxlan-linux)
