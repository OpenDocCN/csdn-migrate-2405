# 深入理解 Docker（四）

> 原文：[`zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22`](https://zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Docker 中的安全性

良好的安全性建立在多层次之上，而 Docker 有很多层次。它支持所有主要的 Linux 安全技术，同时也有很多自己的技术，而且大多数都很简单易配置。

在本章中，我们将介绍一些使在 Docker 上运行容器非常安全的技术。

当我们深入探讨本章的内容时，我们将把事情分成两类：

+   Linux 安全技术

+   Docker 平台安全技术

本章的大部分内容将是针对 Linux 的。然而，Docker 平台安全技术部分是与平台无关的，并且同样适用于 Linux 和 Windows。

### Docker 中的安全性-简而言之

安全性就是多层次的！一般来说，安全层次越多，您就越安全。嗯... Docker 提供了很多安全层次。图 15.1 显示了我们将在本章中涵盖的一些安全技术。

图 15.1

图 15.1

Linux 上的 Docker 利用了大部分常见的 Linux 安全技术。这些包括命名空间，控制组（cgroups），权限，强制访问控制（MAC）系统和 seccomp。对于每一种技术，Docker 都实现了合理的默认设置，以实现无缝和相对安全的开箱即用体验。但是，它也允许您根据自己的特定要求自定义每一种技术。

Docker 平台本身提供了一些出色的本地安全技术。其中最好的一点是它们非常简单易用！

Docker Swarm Mode 默认情况下是安全的。您可以在不需要任何配置的情况下获得以下所有内容；加密节点 ID，相互认证，自动 CA 配置，自动证书轮换，加密集群存储，加密网络等等。

Docker 内容信任（DCT）允许您对图像进行签名，并验证您拉取的图像的完整性和发布者。

Docker 安全扫描分析 Docker 镜像，检测已知的漏洞，并提供详细报告。

Docker secrets 使秘密成为 Docker 生态系统中的一等公民。它们存储在加密的集群存储中，在传递给容器时进行加密，在使用时存储在内存文件系统中，并且采用最小权限模型。

重要的是要知道，Docker 与主要的 Linux 安全技术一起工作，并提供自己广泛且不断增长的安全技术。虽然 Linux 安全技术可能有点复杂，但 Docker 平台的安全技术非常简单。

### Docker 中的安全-深入挖掘

我们都知道安全性很重要。我们也知道安全性可能会很复杂和无聊！

当 Docker 决定将安全性融入其平台时，它决定要使其简单易用。他们知道如果安全性难以配置，人们就不会使用它。因此，Docker 平台提供的大多数安全技术都很简单易用。它们还提供合理的默认设置-这意味着你可以零配置得到一个相对安全的平台。当然，默认设置并不完美，但通常足以让你安全启动。如果它们不符合你的需求，你总是可以自定义它们。

我们将按以下方式组织本章的其余部分：

+   Linux 安全技术

+   命名空间

+   控制组

+   capabilities

+   强制访问控制

+   seccomp

+   Docker 平台安全技术

+   Swarm 模式

+   Docker 安全扫描

+   Docker 内容信任

+   Docker Secrets

#### Linux 安全技术

所有良好的容器平台都应该使用命名空间和 cgroups 来构建容器。最好的容器平台还将集成其他 Linux 安全技术，如*capabilities*、*强制访问控制系统*，如 SELinux 和 AppArmor，以及*seccomp*。如预期的那样，Docker 与它们都集成在一起！

在本章的这一部分，我们将简要介绍 Docker 使用的一些主要 Linux 安全技术。我们不会详细介绍，因为我希望本章的主要重点是 Docker 平台技术。

##### 命名空间

内核命名空间是容器的核心！它们让我们可以切分操作系统（OS），使其看起来和感觉像多个隔离的操作系统。这让我们可以做一些很酷的事情，比如在同一个 OS 上运行多个 web 服务器而不会出现端口冲突。它还让我们在同一个 OS 上运行多个应用程序，而不会因为共享配置文件和共享库文件而发生冲突。

一些快速的例子：

+   您可以在单个操作系统上运行多个 Web 服务器，每个 Web 服务器都在端口 443 上运行。为此，您只需在每个 Web 服务器应用程序内运行其自己的*网络命名空间*。这是因为每个*网络命名空间*都有自己的 IP 地址和完整的端口范围。您可能需要将每个端口映射到 Docker 主机上的不同端口，但每个端口都可以在不重新编写或重新配置以使用不同端口的情况下运行。

+   您可以运行多个应用程序，每个应用程序都需要自己特定版本的共享库或配置文件。为此，您可以在每个*挂载命名空间*内运行每个应用程序。这是因为每个*挂载命名空间*可以在系统上拥有任何目录的独立副本（例如/ etc，/ var，/ dev 等）。

图 15.2 显示了单个主机上运行两个 Web 服务器应用程序的高级示例，两者都使用端口 443。每个 Web 服务器应用程序都在自己的网络命名空间内运行。

![图 15.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-2.png)

图 15.2

Linux 上的 Docker 目前利用以下内核命名空间：

+   进程 ID（pid）

+   网络（net）

+   文件系统/挂载（mnt）

+   进程间通信（ipc）

+   用户（用户）

+   UTS（uts）

我们稍后将简要解释每个命名空间的作用。但最重要的是要理解**Docker 容器是命名空间的有序集合**。让我重复一遍… ***Docker 容器是命名空间的有序集合***。

例如，每个容器由自己的`pid`，`net`，`mnt`，`ipc`，`uts`和可能的`user`命名空间组成。这些命名空间的有序集合就是我们所说的容器。图 15.3 显示了一个单个 Linux 主机运行两个容器。

![图 15.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-3.png)

图 15.3

让我们简要看一下 Docker 如何使用每个命名空间：

+   `进程 ID 命名空间：` Docker 使用`pid`命名空间为每个容器提供独立的进程树。每个容器都有自己的进程树，这意味着每个容器都可以有自己的 PID 1。PID 命名空间还意味着容器无法看到或访问其他容器或其运行的主机的进程树。

+   `网络命名空间：` Docker 使用`net`命名空间为每个容器提供独立的网络堆栈。该堆栈包括接口、IP 地址、端口范围和路由表。例如，每个容器都有自己的`eth0`接口，具有自己独特的 IP 和端口范围。

+   `Mount namespace:` 每个容器都有自己独特的隔离根目录`/`文件系统。这意味着每个容器都可以有自己的`/etc`、`/var`、`/dev`等。容器内的进程无法访问 Linux 主机或其他容器的挂载命名空间 - 它们只能看到和访问自己隔离的挂载命名空间。

+   `Inter-process Communication namespace:` Docker 使用`ipc`命名空间在容器内进行共享内存访问。它还将容器与容器外的共享内存隔离开来。

+   `User namespace:` Docker 允许您使用`user`命名空间将容器内的用户映射到 Linux 主机上的不同用户。一个常见的例子是将容器的`root`用户映射到 Linux 主机上的非 root 用户。用户命名空间对于 Docker 来说是相当新的，目前是可选的。这可能会在将来发生变化。

+   `UTS namespace:` Docker 使用`uts`命名空间为每个容器提供自己的主机名。

记住...容器是一组命名空间的有序集合！！！

![图 15.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-4.png)

图 15.4

##### 控制组

如果命名空间是关于隔离的话，*控制组（cgroups）*则是关于设置限制的。

将容器类比为酒店中的房间。是的，每个房间都是隔离的，但每个房间也共享一组公共资源 - 诸如供水、供电、共享游泳池、共享健身房、共享早餐吧等。Cgroups 让我们设置限制，以便（继续使用酒店类比）没有单个容器可以使用所有的水或吃光早餐吧的所有食物。

在现实世界中，而不是愚蠢的酒店类比，容器彼此隔离，但共享一组公共的操作系统资源 - 诸如 CPU、RAM 和磁盘 I/O 之类的东西。Cgroups 让我们对这些资源中的每一个设置限制，以便单个容器不能使用主机的所有 CPU、RAM 或存储 I/O。

##### Capabilities

在容器中以 root 身份运行是一个坏主意 - root 拥有无限的权力，因此非常危险。但是，以非 root 身份运行容器也很麻烦 - 非 root 几乎没有任何权力，几乎没有用处。我们需要的是一种技术，让我们可以选择容器需要哪些 root 权限才能运行。进入*capabilities*！

在底层，Linux 的 root 账户由一长串的 capabilities 组成。其中一些包括：

+   `CAP_CHOWN`允许您更改文件所有权

+   `CAP_NET_BIND_SERVICE`允许您将套接字绑定到低编号的网络端口

+   `CAP_SETUID`允许您提升进程的特权级别

+   `CAP_SYS_BOOT`允许您重新启动系统。

列表还在继续。

Docker 使用*capabilities*，因此您可以以 root 身份运行容器，但剥离掉不需要的 root 权限。例如，如果容器唯一需要的 root 权限是绑定到低编号的网络端口的能力，您应该启动一个容器并删除所有 root 权限，然后再添加 CAP_NET_BIND_SERVICE 权限。

Docker 还施加限制，使容器无法重新添加已删除的功能。

##### 强制访问控制系统

Docker 与主要的 Linux MAC 技术（如 AppArmor 和 SELinux）兼容。

根据您的 Linux 发行版，Docker 会为所有新容器应用默认的 AppArmor 配置文件。根据 Docker 文档，这个默认配置文件是“适度保护，同时提供广泛的应用程序兼容性”。

Docker 还允许您启动没有应用策略的容器，并且可以自定义策略以满足您的特定要求。

##### seccomp

Docker 使用 seccomp，在过滤模式下，限制容器可以向主机内核发出的系统调用。

根据 Docker 安全理念，所有新容器都会配置一个默认的 seccomp 配置文件，其中包含合理的默认设置。这旨在提供适度的安全性，而不影响应用程序的兼容性。

与往常一样，您可以自定义 seccomp 配置文件，并且可以向 Docker 传递一个标志，以便可以启动没有 seccomp 配置文件的容器。

##### 关于 Linux 安全技术的最终思考

Docker 支持大多数重要的 Linux 安全技术，并提供合理的默认设置，以增加安全性但不会太严格限制。

![图 15.5](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-5.png)

图 15.5

其中一些技术可能很难定制，因为它们需要深入了解其工作原理以及 Linux 内核的工作原理。希望它们在未来会变得更容易配置，但目前，Docker 随附的默认配置是一个很好的起点。

#### Docker 平台安全技术

在本章的这一部分，我们将看一下**Docker 平台**提供的一些主要安全技术。

##### Swarm 模式下的安全性

Swarm Mode 是 Docker 的未来。它允许您集群多个 Docker 主机，并以声明性方式部署应用程序。每个 Swarm 由*管理者*和*工作者*组成，可以是 Linux 或 Windows。管理者组成集群的控制平面，并负责配置集群并向其分派工作。工作者是运行应用程序代码的节点，作为容器运行。

正如预期的那样，Swarm Mode 包括许多安全功能，这些功能已启用，并具有合理的默认值。这些功能包括：

+   加密节点 ID

+   通过 TLS 的双向认证

+   安全加入令牌

+   具有自动证书轮换的 CA 配置

+   加密集群存储（配置数据库）

+   加密网络

让我们走一遍构建安全 Swarm 并配置一些安全方面的过程。

要跟随操作，您至少需要三个运行 Docker 1.13 或更高版本的 Docker 主机。所引用的示例使用三个名为“mgr1”、“mgr2”和“wrk1”的 Docker 主机。每个主机都在 Ubuntu 16.04 上运行 Docker 18.01.0-ce。所有三个主机之间有网络连接，并且都可以通过名称相互 ping 通。设置如图 15.6 所示。

![图 15.6](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-6.png)

图 15.6

##### 配置安全 Swarm

从要成为新 Swarm 中第一个管理者的节点运行以下命令。在示例中，我们将从“mgr1”运行它。

```
$ docker swarm init
Swarm initialized: current node `(`7xam...662z`)` is now a manager.

To add a worker to this swarm, run the following command:

    docker swarm join --token `\`
     SWMTKN-1-1dmtwu...r17stb-ehp8g...hw738q `172`.31.5.251:2377

To add a manager to this swarm, run `'docker swarm join-token manager'`
and follow the instructions. 
```

`就是这样！这确实是您需要做的一切来配置一个安全的 Swarm！

“mgr1”被配置为 Swarm 的第一个管理者，也是根 CA。Swarm 已被赋予了一个加密的 Swarm ID，“mgr1”已经为自己颁发了一个客户端证书，用于标识其作为 Swarm 中的管理者。证书轮换已配置为默认值 90 天，并且已配置和加密了集群配置数据库。一组安全令牌也已创建，以便新的管理者和新的工作者可以加入 Swarm。而且所有这些只需**一个命令！**

图 15.7 显示了实验室的当前状态。

![图 15.7](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-7.png)

图 15.7

现在让我们将“mgr2”作为额外的管理者加入。

将新管理者加入 Swarm 是一个两步过程。在第一步中，您将提取加入新管理者到 Swarm 所需的令牌。在第二步中，您将在“mgr2”上运行`docker swarm join`命令。只要您在`docker swarm join`命令中包含管理者加入令牌，“mgr2”就会作为管理者加入 Swarm。

从“mgr1”运行以下命令以提取管理节点加入令牌。

```
$ docker swarm join-token manager
To add a manager to this swarm, run the following command:

    docker swarm join --token `\`
    SWMTKN-1-1dmtwu...r17stb-2axi5...8p7glz `\`
    `172`.31.5.251:2377 
```

`命令的输出给出了你需要在要加入 Swarm 作为管理节点的节点上运行的确切命令。在你的实验室中，加入令牌和 IP 地址将是不同的。

复制命令并在“mgr2”上运行：

```
$ docker swarm join --token SWMTKN-1-1dmtwu...r17stb-2axi5...8p7glz `\`
> `172`.31.5.251:2377

This node joined a swarm as a manager. 
```

`“mgr2”现在作为额外的管理节点加入了 Swarm。

> 加入命令的格式是`docker swarm join --token <manager-join-token> <ip-of-existing-manager>:<swarm-port>`。

你可以通过在两个管理节点中运行`docker node ls`来验证操作。

```
$ docker node ls
ID                HOSTNAME   STATUS    AVAILABILITY    MANAGER STATUS
7xamk...ge662z    mgr1       Ready     Active          Leader
i0ue4...zcjm7f *  mgr2       Ready     Active          Reachable 
```

`上面的输出显示“mgr1”和“mgr2”都是 Swarm 的一部分，都是 Swarm 管理节点。更新后的配置如图 15.8 所示。

![图 15.8](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-8.png)

图 15.8

两个管理节点可能是你能拥有的最糟糕的数量。然而，在演示实验室中我们只是在玩玩，而不是建立一个业务关键的生产环境 ;-)

添加 Swarm 工作节点是一个类似的两步过程。第一步是提取新工作节点的加入令牌，第二步是在要加入为工作节点的节点上运行`docker swarm join`命令。

在任一管理节点上运行以下命令以公开工作节点加入令牌。

```
$ docker swarm join-token worker

To add a worker to this swarm, run the following command:

    docker swarm join --token `\`
    SWMTKN-1-1dmtw...17stb-ehp8g...w738q `\`
    `172`.31.5.251:2377 
```

`同样，你会得到你需要在要加入为工作节点的节点上运行的确切命令。在你的实验室中，加入令牌和 IP 地址将是不同的。

复制命令并在“wrk1”上运行如下：

```
$ docker swarm join --token SWMTKN-1-1dmtw...17stb-ehp8g...w738q `\`
> `172`.31.5.251:2377

This node joined a swarm as a worker. 
```

`从 Swarm 管理节点中再次运行`docker node ls`命令。

```
$ docker node ls
ID                 HOSTNAME     STATUS     AVAILABILITY   MANAGER STATUS
7xamk...ge662z *   mgr1         Ready      Active         Leader
ailrd...ofzv1u     wrk1         Ready      Active
i0ue4...zcjm7f     mgr2         Ready      Active         Reachable 
```

`现在你有一个包含两个管理节点和一个工作节点的 Swarm。管理节点配置为高可用性（HA），并且集群存储被复制到它们两个。更新后的配置如图 15.9 所示。

![图 15.9](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-9.png)

图 15.9

##### 查看 Swarm 安全技术的幕后

现在我们已经建立了一个安全的 Swarm，让我们花一分钟来看看一些涉及的安全技术。

###### Swarm 加入令牌

加入现有 Swarm 的管理节点和工作节点所需的唯一事物就是相关的加入令牌。因此，保持你的加入令牌安全是至关重要的！不要在公共 GitHub 仓库上发布它们！

每个 Swarm 都维护两个不同的加入令牌：

+   一个用于加入新管理节点

+   一个用于加入新工作节点

值得了解 Swarm 加入令牌的格式。每个加入令牌由 4 个不同的字段组成，用破折号（`-`）分隔：

`前缀 - 版本 - Swarm ID - 令牌`

前缀始终为“SWMTKN”，使您能够对其进行模式匹配，并防止人们意外地公开发布它。版本字段指示了 Swarm 的版本。Swarm ID 字段是 Swarm 证书的哈希值。令牌部分是决定它是否可以用于加入节点作为管理器或工作节点的部分。

如下所示，给定 Swarm 的管理器和工作节点加入令牌除了最终的 TOKEN 字段外是相同的。

+   管理器：SWMTKN-1-1dmtwusdc…r17stb-**2axi53zjbs45lqxykaw8p7glz**

+   工作节点：SWMTKN-1-1dmtwusdc…r17stb-**ehp8gltji64jbl45zl6hw738q**

如果您怀疑您的任一加入令牌已被泄露，您可以撤销它们并用单个命令发布新的。以下示例撤销了现有的*manager*加入令牌并发布了一个新的。

```
$ docker swarm join-token --rotate manager

Successfully rotated manager join token.

To add a manager to this swarm, run the following command:

    docker swarm join --token `\`
     SWMTKN-1-1dmtwu...r17stb-1i7txlh6k3hb921z3yjtcjrc7 `\`
     `172`.31.5.251:2377 
```

请注意，旧加入令牌和新加入令牌之间唯一的区别是最后一个字段。Swarm ID 保持不变。

加入令牌存储在默认情况下由加密的集群配置数据库中。

###### TLS 和相互认证

加入 Swarm 的每个管理器和工作节点都会被发放一个客户端证书。该证书用于相互认证。它标识了节点所属的 Swarm，以及节点在 Swarm 中的角色（管理器或工作节点）。

在 Linux 主机上，您可以使用以下命令检查节点的客户端证书。

```
$ sudo openssl x509 `\`
  -in /var/lib/docker/swarm/certificates/swarm-node.crt `\`
  -text

  Certificate:
      Data:
          Version: `3` `(`0x2`)`
          Serial Number:
              `80`:2c:a7:b1:28...a8:af:89:a1:2a:51:89
      Signature Algorithm: ecdsa-with-SHA256
          Issuer: `CN``=`swarm-ca
          Validity
              Not Before: Jul `19` `07`:56:00 `2017` GMT
              Not After : Oct `17` `08`:56:00 `2017` GMT
          Subject: `O``=`mfbkgjm2tlametbnfqt2zid8x, `OU``=`swarm-manager,
          `CN``=`7xamk8w3hz9q5kgr7xyge662z
          Subject Public Key Info:
<SNIP> 
```

输出中的`Subject`数据使用标准的`O`、`OU`和`CN`字段来指定 Swarm ID、节点的角色和节点 ID。

+   组织`O`字段存储了 Swarm ID

+   组织单位`OU`字段存储了节点在 Swarm 中的角色

+   规范名称`CN`字段存储了节点的加密 ID。

这在图 15.10 中显示。

![图 15.10](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-10.png)

图 15.10

我们还可以直接在`Validity`部分看到证书轮换周期。

我们可以将这些值与`docker system info`命令的输出中显示的相应值进行匹配。

```
$ docker system info
<SNIP>
Swarm: active
 NodeID: 7xamk8w3hz9q5kgr7xyge662z    `# Relates to the CN field`
 Is Manager: `true`                     `# Relates to the OU field`
 ClusterID: mfbkgjm2tlametbnfqt2zid8x `# Relates to the O field`
 ...
 <SNIP>
 ...
 CA Configuration:
  Expiry Duration: `3` months           `# Relates to Validity field`
  Force Rotate: `0`
 Root Rotation In Progress: `false`
 <SNIP> 
```

###### 配置一些 CA 设置

您可以使用`docker swarm update`命令为 Swarm 配置证书轮换周期。以下示例将证书轮换周期更改为 30 天。

```
$ docker swarm update --cert-expiry 720h 
```

`Swarm 允许节点提前更新证书（在证书到期之前稍微提前），以便 Swarm 中的所有节点不会同时尝试更新它们的证书。

您可以通过向`docker swarm init`命令传递`--external-ca`标志来在创建 Swarm 时配置外部 CA。

新的`docker swarm ca`子命令可以用来管理与 CA 相关的配置。运行带有`--help`标志的命令，可以看到它可以做的事情列表。

```
$ docker swarm ca --help

Usage:  docker swarm ca `[`OPTIONS`]`

Manage root CA

Options:
      --ca-cert pem-file          Path to the PEM-formatted root CA
                                  certificate to use `for` the new cluster
      --ca-key pem-file           Path to the PEM-formatted root CA
                                  key to use `for` the new cluster
      --cert-expiry duration      Validity period `for` node certificates
                                  `(`ns`|`us`|`ms`|`s`|`m`|`h`)` `(`default 2160h0m0s`)`
  -d, --detach                    Exit immediately instead of waiting `for`
                                  the root rotation to converge
      --external-ca external-ca   Specifications of one or more certificate
                                  signing endpoints
      --help                      Print usage
  -q, --quiet                     Suppress progress output
      --rotate                    Rotate the swarm CA - `if` no certificate
                                  or key are provided, new ones will be gene`\`
rated 
```

###### 集群存储

集群存储是 Swarm 的大脑，也是存储集群配置和状态的地方。

存储目前基于`etcd`的实现，并自动配置为在 Swarm 中的所有管理节点上进行复制。它也默认是加密的。

集群存储正在成为许多 Docker 平台技术的关键组件。例如，Docker 网络和 Docker Secrets 都利用了集群存储。这就是 Swarm Mode 对 Docker 未来如此重要的原因之一——Docker 平台的许多部分已经利用了集群存储，而将来还会有更多的部分利用它。故事的寓意是，如果你不在 Swarm Mode 下运行，你将受限于你可以使用的其他 Docker 功能。

Docker 会自动处理集群存储的日常维护。然而，在生产环境中，你应该为其提供强大的备份和恢复解决方案。

关于 Swarm Mode 安全性的内容就到这里就够了。

##### 使用 Docker 安全扫描检测漏洞

快速识别代码漏洞的能力至关重要。Docker 安全扫描使检测 Docker 镜像中已知漏洞变得简单。

> **注意：**在撰写本文时，Docker 安全扫描适用于 Docker Hub 上私有仓库中的镜像。它也作为 Docker Trusted Registry 本地注册表解决方案的一部分提供。最后，所有官方 Docker 镜像都经过扫描，并在其仓库中提供扫描报告。

Docker 安全扫描对 Docker 镜像进行二进制级别的扫描，并检查其中的软件是否存在已知漏洞（CVE 数据库）。扫描完成后，会提供详细的报告。

打开网页浏览器，访问 https://hub.docker.com，并搜索`alpine`仓库。图 15.11 显示了官方 Alpine 仓库的`Tags`标签页。

![图 15.11](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-11.png)

图 15.11

Alpine 仓库是一个官方仓库。这意味着它会自动进行扫描，并提供扫描报告。正如你所看到的，标记为`edge`、`latest`和`3.6`的镜像都没有已知的漏洞。然而，`alpine:3.5`镜像有已知的漏洞（红色）。

如果你深入研究`alpine:3.5`镜像，你将得到一个更详细的报告，如图 15.12 所示。

![图 15.12](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-12.png)

图 15.12

这是一个简单而轻松的方式，可以获取有关软件已知漏洞的详细信息。

Docker 受信任的注册表（DTR）是 Docker 企业版的一部分，是一个本地 Docker 注册表，提供相同的功能，并允许您控制图像扫描的方式和时间。例如，DTR 允许您决定图像是否应在推送后自动扫描，或者是否应仅手动触发扫描。它还允许您手动上传 CVE 数据库更新 - 这对于您的 DTR 基础设施与互联网隔离并且无法自动同步更新的情况非常理想。

这就是 Docker 安全扫描 - 一种深入检查 Docker 图像已知漏洞的好方法。但要注意，拥有伟大的知识就意味着拥有伟大的责任 - 一旦您了解了漏洞，就是您的责任来处理它们。

##### 使用 Docker 内容信任对图像进行签名和验证。

Docker 内容信任（DCT）使验证下载的图像的完整性和发布者变得简单而容易。这在通过不受信任的网络（如互联网）拉取图像时尤为重要。

在高层次上，DCT 允许开发人员在将图像推送到 Docker Hub 或 Docker 受信任的注册表时对其进行签名。它还会在拉取图像时自动验证。这个高层次的过程如图 15.13 所示。

![图 15.13](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-13.png)

图 15.13

DCT 还可以提供重要的*上下文*。这包括诸如图像是否已经签名用于生产环境，或者图像是否已被新版本取代并因此过时等信息。

在撰写本文时，DTC 的*上下文*提供还处于起步阶段，并且配置相当复杂。

只需在 Docker 主机上启用 DCT，就可以导出一个名为`DOCKER_CONTENT_TRUST`的环境变量，其值为`1`。

```
$ `export` `DOCKER_CONTENT_TRUST``=``1` 
```

`在现实世界中，您可能希望将这变成系统的一个更为永久的特性。

如果您正在使用 Docker Universal Control Plane（Docker 企业版的一部分），您需要像图 15.14 所示，设置`仅运行已签名的图像`复选框。这将强制 UCP 集群中的所有节点仅使用已签名的图像。

![图 15.14](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-14.png)

图 15.14

从图 15.14 中可以看出，Universal Control Plane 通过提供列出需要签署镜像的安全主体的选项，将 DCT 推向了更高一级。例如，您可能有一个公司政策，即所有在生产中使用的镜像都需要由`secops`团队签名。

一旦启用了 DCT，您将无法再拉取和使用未签名的镜像。图 15.15 显示了如果您尝试使用 Docker CLI 和 Universal Control Plane web UI 拉取未签名镜像时会出现的错误（这两个示例都尝试拉取标记为“未签名”的镜像）

![图 15.15](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-15.png)

图 15.15

图 15.16 显示了 DCT 如何阻止 Docker 客户端拉取被篡改的镜像。图 15.17 显示了 DCT 阻止客户端拉取过时镜像。

![图 15.16 拉取被篡改的镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-16.png)

图 15.16 拉取被篡改的镜像

![图 15.17 拉取过时的镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-17.png)

图 15.17 拉取过时的镜像

Docker Content Trust 是一个帮助您验证从 Docker 注册表中拉取的镜像的重要技术。它在基本形式上很容易配置，但更高级的功能，如*context*，目前配置起来更复杂。

#### Docker Secrets

许多应用程序需要秘密。诸如密码、TLS 证书、SSH 密钥等。

在 Docker 1.13 之前，没有一种标准的方式以安全的方式向应用程序提供秘密。开发人员通常通过明文环境变量将秘密插入应用程序（我们都这样做过）。这远非理想。 

Docker 1.13 引入了*Docker Secrets*，有效地使秘密成为 Docker 生态系统中的一等公民。例如，有一个全新的`docker secret`子命令专门用于管理秘密。Docker Universal Control Plane UI 中还有一个页面用于创建和管理秘密。在幕后，秘密在静态时被加密，在传输时被加密，在内存文件系统中被挂载，并在最低特权模型下运行，只有明确授予对它们访问权限的服务才能使用它们。这是一个非常全面的端到端解决方案。

图 15.18 显示了一个高级工作流程：

![图 15.18](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure15-18.png)

图 15.18

以下步骤介绍了图 15.18 中显示的高级工作流程。

1.  蓝色秘密被创建并发布到 Swarm

1.  它被存储在加密的集群存储中（所有管理者都可以访问集群存储）

1.  蓝色服务已创建，并且秘密已附加到其中

1.  秘密在传递到蓝色服务中的任务（容器）时进行了加密

1.  秘密被挂载到蓝色服务的容器中，作为一个未加密的文件在`/run/secrets/`。这是一个内存中的 tmpfs 文件系统（在 Windows Docker 主机上，这一步与 tmpfs 不同，因为它们没有内存文件系统的概念）

1.  一旦容器（服务任务）完成，内存文件系统将被销毁，并且秘密将从节点中清除。

1.  红色服务中的红色容器无法访问秘密。

您可以使用`docker secret`子命令创建和管理秘密，并通过在`docker service create`命令中指定`--secret`标志来将它们附加到服务。

### 章节总结

Docker 可以配置为非常安全。它支持所有主要的 Linux 安全技术，包括：内核命名空间、cgroups、capabilities、MAC 和 seccomp。它为所有这些提供了合理的默认值，但您可以自定义它们甚至禁用它们。

除了一般的 Linux 安全技术之外，Docker 平台还包括一套自己的安全技术。Swarm Mode 建立在 TLS 之上，配置和定制非常简单。安全扫描对 Docker 镜像进行二进制级别的扫描，并提供已知漏洞的详细报告。Docker 内容信任允许您签署和验证内容，而秘密现在是 Docker 中的一等公民。

最终结果是，您的 Docker 环境可以根据您的需求配置为安全或不安全 —— 这完全取决于您如何配置它。`````````````


# 第十七章：企业工具

在本章中，我们将看一些 Docker 公司提供的企业级工具。我们将看到如何安装它们，配置它们，备份它们和恢复它们。

这将是一个相当长的章节，包含大量逐步的技术细节。我会尽量保持有趣，但这可能会很难:-D

其他工具也存在，但我们将集中在 Docker 公司的工具上。

让我们直接开始。

### 企业工具-简而言之

Docker 和容器已经席卷了应用程序开发世界-构建，发布和运行应用程序从未如此简单。因此，企业想要参与其中并不奇怪。但企业有比典型的前沿开发者更严格的要求。

企业需要以他们可以使用的方式打包 Docker。这通常意味着他们拥有和管理自己的本地解决方案。这还意味着角色和安全功能，使其适应其内部结构，并得到安全部门的认可。这也意味着一切都有一个有意义的支持合同支持。

这就是 Docker 企业版（EE）发挥作用的地方！

Docker EE 是*企业版的 Docker*。它是一套产品，包括一个经过加固的引擎，一个操作界面和一个安全的私有注册表。您可以在本地部署它，并且它包含在支持合同中。

高级堆栈如图 16.1 所示。

![图 16.1 Docker EE](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-1.png)

图 16.1 Docker EE

### 企业工具-深入挖掘

我们将把本章的其余部分分为以下几个部分：

+   Docker EE 引擎

+   Docker Universal Control Plane (UCP)

+   Docker Trusted Registry (DTR)

我们将看到如何安装每个工具，并在适用的情况下配置 HA，并执行备份和恢复作业。

#### Docker EE 引擎

*Docker 引擎*提供了所有核心的 Docker 功能。像镜像和容器管理，网络，卷，集群，秘密等等。在撰写本文时，有两个版本：

+   社区版（CE）

+   企业版（EE）

就我们而言，最大的两个区别是发布周期和支持。

Docker EE 按季度发布，并使用基于时间的版本方案。例如，2018 年 6 月发布的 Docker EE 将是`18.06.x-ee`。Docker 公司保证每个版本提供 1 年的支持和补丁。

##### 安装 Docker EE

安装 Docker EE 很简单。但是，不同平台之间存在细微差异。我们将向您展示如何在 Ubuntu 16.04 上进行操作，但在其他平台上进行操作同样简单。

Docker EE 是基于订阅的服务，因此您需要一个 Docker ID 和一个活跃的订阅。这将为您提供访问一个独特个性化的 Docker EE 仓库，我们将在接下来的步骤中配置和使用。[试用许可证](https://store.docker.com/editions/enterprise/docker-ee-trial)通常是可用的。

> **注意：** Windows Server 上的 Docker 始终安装 Docker EE。有关如何在 Windows Server 2016 上安装 Docker EE 的信息，请参阅第三章。

您可能需要在以下命令前加上`sudo`。

1.  确保您拥有最新的软件包列表。

```
 $ apt-get update 
```

* 安装访问 Docker EE 仓库所需的软件包。

```
 $ apt-get install -y \
 	  apt-transport-https \
 	  curl \
 	  software-properties-common 
```

* 登录[Docker Store](https://store.docker.com/)并复制您独特的 Docker EE 仓库 URL。

将您的网络浏览器指向 store.docker.com。点击右上角的用户名，然后选择`My Content`。在您的活动 Docker EE 订阅下选择`Setup`。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-2.png)

从`Resources`窗格下复制您的仓库 URL。

同时下载您的许可证。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-3.png)

我们正在演示如何为 Ubuntu 设置仓库。但是，这个 Docker Store 页面包含了如何为其他 Linux 版本进行设置的说明。

+   将您独特的 Docker EE 仓库 URL 添加到环境变量中。

```
 $ DOCKER_EE_REPO=<paste-in-your-unique-ee-url> 
```

* 将官方 Docker GPG 密钥添加到所有密钥环中。

```
 $ curl -fsSL "`${``DOCKER_EE_REPO``}`/ubuntu/gpg" | sudo apt-key add - 
```

* 设置最新的稳定仓库。您可能需要用最新的稳定版本替换最后一行的值。

```
 $ add-apt-repository \
    "deb [arch=amd64] $DOCKER_EE_REPO/ubuntu \
    $(lsb_release -cs) \
    stable-17.06" 
```

* 运行另一个`apt-get update`，以从您新添加的 Docker EE 仓库中获取最新的软件包列表。

```
 $ apt-get update 
```

* 卸载先前版本的 Docker。

```
 $ apt-get remove docker docker-engine docker-ce docker.io 
```

* 安装 Docker EE

```
 $ apt-get install docker-ee -y 
```

* 检查安装是否成功。

```
$ docker --version
Docker version `17`.06.2-ee-6, build e75fdb8 
``````````` 

 ```That’s it, you’ve installed the Docker EE engine.

Now you can install Universal Control Plane.

#### Docker Universal Control Plane (UCP)

We’ll be referring to Docker Universal Control Plane as **UCP** for the rest of the chapter.

UCP is an enterprise-grade container-as-a-service platform with an Operations UI. It takes the Docker Engine, and adds all of the features enterprises love and require. Things like; *RBAC, policies, trust, a highly-available control plane,* and a *simple UI*. Under-the-covers, it’s a containerized microservices app that you download and run as a bunch of containers.

Architecturally, UCP builds on top of Docker EE in *Swarm mode*. As shown in Figure 16.4, the UCP control plane runs on Swarm managers, and apps are deployed on Swarm workers.

![Figure 16.4 High level UCP architecture](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-4.png)

Figure 16.4 High level UCP architecture

At the time of writing, UCP managers have to be Linux. Workers can be a mix of Windows and Linux.

##### Planning a UCP installation

When planning a UCP installation, it’s important to size and spec your cluster appropriately. We’ll look at some of things you should consider.

All nodes in the cluster should have their clocks in sync (e.g. NTP). If they don’t, problems can occur that are a pain to troubleshoot.

All nodes should have a static IP address and a stable DNS name.

By default, UCP managers don’t run user workloads. This is a recommended best practice, and you should enforce it for production environments — it allows managers to focus solely on control plane duties. It also makes troubleshooting easier.

You should always have an odd number of managers. This helps avoid split-brain conditions where managers fail or become partitioned from the rest of the cluster. The ideal number is 3, 5, or 7, with 3 or 5 usually being the best. Having more than 7 can cause issues with the back-end Raft and cluster reconciliation. If you don’t have enough nodes for 3 managers, 1 is better than 2!

If you’re implementing a backup schedule (which you should) and taking regular backups, you might want to deploy 5 managers. This is because Swarm and UCP backup operations require stopping Docker and UCP services. Having 5 managers can help maintain cluster resiliency during such operations.

Manager nodes should be spread across data center availability zones. The last thing you want, is a single availability zone failing and taking all of the UCP managers with it. However, it’s important to connect your managers via high-speed reliable networks. So if your data center availability zones are not connected by good networks, you might be better-off keeping all managers in a single availability zone. As a general rule, if you’re deploying on public cloud infrastructure, you should deploy your managers in availability zones within a single *region*. Spanning *regions* usually involves less-reliable high-latency networks.

You can have as many *worker nodes* as you want — they don’t participate in cluster Raft operations, so won’t impact control plane operations.

Planning the number and size of worker nodes requires an understanding of the apps you plan on running on the cluster. For example, knowing this will help you determine things like how many Windows vs Linux nodes you require. You will also need to know if any of your apps have special requirements and need specialised worker nodes — may be PCI workloads.

Also, although the Docker engine is lightweight and small, the containerized applications you run on your nodes might not be. With this in mind, it’s important to size nodes according to the CPU, RAM, network, and disk I/O requirements of your applications.

Making server sizing requirements isn’t something I like to do, as it’s entirely dependant on *your* workloads. However, the Docker website is currently suggesting the following **minimum** requirements for Docker UCP 2.2.4 on Linux:

*   UCP Manager nodes running DTR: 8GB of RAM with 3GB of disk space
*   UCP Worker nodes: 4GB of RAM with 3GB of free disk space

Recommended** requirements are:

*   UCP Manager nodes running DTR: 8GB RAM, 4 vCPUs, and 100GB disk space
*   UCP Worker nodes: 4GB RAM 25-100GB of free disk space

Take this with a pinch of salt, and be sure to do your own sizing exercise.

One thing’s for sure — Windows images are **a lot bigger** than Linux images. So be sure to factor this into your sizing.

One final word on sizing requirements. Docker Swarm and Docker UCP make it extremely easy to add and remove managers and workers. New managers are automagically added to the HA control plane, and new workers are immediately available for workload scheduling. Similarly, removing managers and workers is simple. As long as you have multiple managers, you can remove a manager without impacting cluster operations. With worker nodes, you can drain them and remove them from a running cluster. This all makes UCP very forgiving when it comes to changing your managers and workers.

With these considerations in mind, we’re ready to install UCP.

##### Installing Docker UCP

In this section, we’ll walk through the process of installing Docker UCP on the first manager node in a new cluster.

1.  Run the following command from a Linux-based Docker EE node that you want to be the first manager in your UCP cluster.

    A few things to note about the command. The example installs UCP using the `docker/ucp:2.2.5` image, you will want to substitute your desired version. The `--host-address` is the address you will use to access the web UI. For example, if you’re installing in AWS and plan on accessing from your corporate network via the internet, you would enter the AWS public IP.

    The installation is interactive, so you’ll be prompted for further input to complete it.

    ```
     $ docker container run --rm -it --name ucp \
       -v /var/run/docker.sock:/var/run/docker.sock \
       docker/ucp:2.2.5 install \
       --host-address <node-ip-address> \
       --interactive 
    ```

`*   Configure credentials.

    You’ll be prompted to create a username and password for the UCP Admin account. This is a local account, and you should follow your corporate guidelines for choosing the username and password. Be sure you don’t forget it :-D

    *   Subject alternative names (SANs).

    The installer gives you the option to enter a list of alternative IP addresses and names that might be used to access UCP. These can be public and private IP addresses and DNS names, and will be added to the certificates.` 

 `A few things to note about the install.

UCP leverages Docker Swarm. This means UCP managers have to run on Swarm managers. If you install UCP on a node in *single-engine mode*, it will automatically be switched into *Swarm mode*.

The installer pulls all of the images for the various UCP services, and starts containers from them. The following listing shows some of them being pulled by the installer.

```
INFO[0008] Pulling required images... (this may take a while)
INFO[0008] Pulling docker/ucp-auth-store:2.2.5
INFO[0013] Pulling docker/ucp-hrm:2.2.5
INFO[0015] Pulling docker/ucp-metrics:2.2.5
INFO[0020] Pulling docker/ucp-swarm:2.2.5
INFO[0023] Pulling docker/ucp-auth:2.2.5
INFO[0026] Pulling docker/ucp-etcd:2.2.5
INFO[0028] Pulling docker/ucp-agent:2.2.5
INFO[0030] Pulling docker/ucp-cfssl:2.2.5
INFO[0032] Pulling docker/ucp-dsinfo:2.2.5
INFO[0080] Pulling docker/ucp-controller:2.2.5
INFO[0084] Pulling docker/ucp-proxy:2.2.5 
```

 `Some of the interesting ones include:

*   `ucp-agent` This is the main UCP agent. It gets deployed to all nodes in the cluster and is in charge of making sure the required UCP containers are up and running.
*   `ucp-etcd` The cluster’s persistent key-value store.
*   `ucp-auth` Shared authentication service (also used by DTR for single-sign-on).
*   `ucp-proxy` Controls access to the local Docker socket so that unauthenticated clients cannot make changes to the cluster.
*   `ucp-swarm` Provides compatibility with the underlying Swarm.

Finally, the installation creates a couple of root CA’s: one for internal cluster communications, and one for external access. They issue self-signed certs, which are fine for labs and testing, but not production.

To install UCP with certificates from a trusted CA, you will need a certificate bundle with the following three files:

*   `ca.pem` Certificate of the trusted CA (usually one of your internal corporate CA’s).
*   `cert.pem` UCP’s public certificate. This needs to contain all IP addresses and DNS names that the cluster will be accessed by — including any load-balancers that are fronting it.
*   `key.pem` UCP’s private key.

If you have these files, you need to mount them into a Docker volume called `ucp-controller-server-certs`, and use the `--external-ca` flag to specify the volume. You can also change the certificates from the `Admin Settings` page of the web UI after the installation.

The last thing the UCP installer outputs is the URL that you can access it from.

```
<Snip>
INFO[0049] Login to UCP at https://<IP or DNS>:443 
```

 `Point a web browser to that address and login. If you’re using self-signed certificates you’ll need to accept the browser warnings. You’ll also need to specify your license file, which can be downloaded from the `My Content` section of the Docker Store.

Once you’re logged in, you’ll be landed at the UCP Dashboard.

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-5.png)

At this point, you have a single-node UCP cluster.

You can add more manager and worker nodes from the `Add Nodes` link at the bottom of the Dashboard.

Figure 16.6 shows the Add Nodes screen. You can choose to add `managers` or `workers`, and it gives you the appropriate command to run on the nodes you want to add. The example shows the command to add a Linux worker node. Notice that the command is a `docker swarm` command.

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-6.png)

Adding a node will join it to the Swarm and configure the required UCP services on it. If you’re adding managers, it’s recommended to wait between each new addition. This gives Docker a chance to download and run the required UCP containers, as well as allow the cluster to register the new manager and achieve quorum.

Newly added managers are automatically configured into the highly-available (HA) Raft consensus group and granted access to the cluster store. Also, although external load-balancers aren’t generally considered core parts of UCP HA, they provide a stable DNS hostname that masks what’s going on behind the scenes — such as node failures.

You should configure external load-balancers for *TCP pass-through* on port 443, with a custom HTTPS health check for each UCP manager node at `https://<ucp_manager>/_ping`.

Now that you have a working UCP, you should look at the options that can be configured from the `Admin Settings` page.

![Figure 16.7 UCP Admin Settings](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-7.png)

Figure 16.7 UCP Admin Settings

The settings on this page make up the bulk of the configuration data that is backed as part of the UCP backup operation.

###### Controlling access to UCP

All access to UCP is controlled via the identity management sub-system. This means you need to authenticate with a valid UCP username and password before you can perform any actions on the cluster. This includes cluster administration, as well as deploying and managing services.

We’ve seen this already with UI — we had to log in with a username and password. But the same applies to the Docker CLI — you cannot run unauthenticated commands against UCP from the command line! This is because the local Docker socket on UCP cluster nodes is protected by the `ucp-proxy` service that will not accept unauthorized commands.

Let’s see it.

###### Client bundles

Any node running the Docker CLI is capable of deploying and managing workloads on a UCP cluster, **so long as it presents a valid certificate for a UCP user!

In this section we’ll create a new UCP user, create and download a certificate bundle for that user, and configure a Docker client to use the certificates. Once we’re done, we’ll explain how it works.

1.  If you aren’t already, login to UCP as `admin`.
2.  Click `User Management` > `Users` and then create a new user.

    As we haven’t discussed roles and grants yet, make the user a Docker EE Admin.

3.  With the new user still selected, click the `Configure` drop-down box and choose `Client Bundle`.![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-8.png)

4.  Click the `New Client Bundle +` link to generate and download a client bundle for the user.

    At this point, it’s important to note that client bundles are user-specific. The certificates downloaded will enable any properly configured Docker client to execute commands on the UCP cluster under the identity of the user that the bundle belongs to.

5.  Copy the bundle to the Docker client that you want to configure to manage UCP.
6.  Logon to the client node and perform all of the following commands from that node.
7.  Unzip the contents of the bundle.

    This example uses the Linux `unzip` package to unzip the contents of the bundle to the current directory. Substitute the name of the bundle to match the one in your environment.

    ```
     $ unzip ucp-bundle-nigelpoulton.zip
     Archive:  ucp-bundle-nigelpoulton.zip
     extracting: ca.pem
     extracting: cert.pem
     extracting: key.pem
     extracting: cert.pub
     extracting: env.sh
     extracting: env.ps1
     extracting: env.cmd 
    ```

     `As the output shows, the bundle contains the required `ca.pem`, `cert.pem`, and `key.pem` files. It also includes scripts that will configure the Docker client to use the certificates.` 
`*   Use the appropriate script to configure the Docker client. `env.sh` works on Linux and Mac, `env.ps1` and `env.cmd` work on Windows.

    You’ll probably need administrator/root privileges to run the scripts.

    The example works on Linux and Mac.

    ```
     $ eval "$(<env.sh)" 
    ```

     `At this point, the client node is fully configured.` `*   Test access.

    ```
     $ docker version

      <Snip>

     Server:
      Version:      ucp/2.2.5
      API version:  1.30 (minimum version 1.20)
      Go version:   go1.8.3
      Git commit:   42d28d140
      Built:        Wed Jan 17 04:44:14 UTC 2018
      OS/Arch:      linux/amd64
      Experimental: false 
    ```

     `Notice that the server portion of the output shows the version as `ucp/2.2.5`. This proves the Docker client is successfully talking to the daemon on a UCP node!``` 

 ``Under-the-hood, the script configures three environment variables:

*   `DOCKER_HOST`
*   `DOCKER_TLS_VERIFY`
*   `DOCKER_CERT_PATH`

DOCKER_HOST points the client to the remote Docker daemon on the UCP controller. An example might look like this `DOCKER_HOST=tcp://34.242.196.63:443`. As we can see, access via port 443.

DOCKER_TLS_VERIFY is set to 1, telling the client to use TLS verification in *client mode*.

DOCKER_CERT_PATH tells the Docker client where to find the certificate bundle.

The net result is all `docker` commands from the client will be signed by the user’s certificate and sent across the network to the remote UCP manager. This is shown in Figure 16.9.

![Figure16.9](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-9.png)

Figure16.9

Let’s switch tack and see how we backup and recover UCP.

###### Backing up UCP

First and foremost, high availability (HA) is not the same as a backup!

Consider the following example. You have a highly available UCP cluster with 5 managers nodes. All manager nodes are healthy and the control plane is replicating. A dissatisfied employee corrupts the cluster (or deletes all user accounts). This *corruption* is automatically replicated to all 5 manager nodes, rendering the cluster broken. There is no way that HA can help you in this situation. What you need, is a backup!

A UCP cluster is made from three major components that need backing up separately:

*   Swarm
*   UCP
*   Docker Trusted Registry (DTR)

We’ll walk you through the process of backing up Swarm and UCP, and we’ll show you how to back up DTR later in the chapter.

Although UCP sits on top of Swarm, they are separate components. Swarm holds all of the node membership, networks, volumes, and service definitions. UCP sits on top and maintains its own databases and volumes that hold things such as users, groups, grants, bundles, license files, certificates, and more.

Let’s see how to **backup Swarm**.

Swarm configuration and state is stored in `/var/lib/docker/swarm`. This includes Raft log keys, and it’s replicated to every manager node. A Swarm backup is a copy of all the files in this directory.

Because it’s replicated to every manager, you can perform the backup from any manager.

You need to stop Docker on the node that you want to perform the backup on. This means it’s probably not a good idea to perform the backup on the leader manager, as a leader election will be instigated. You should also perform the backup at a quiet time for the business — even though stopping Docker on a single manager node isn’t a problem in a multi-manager Swarm, it can increase the risk of the cluster losing quorum if another manager fails during the backup.

Before proceeding, you might want to create a couple of Swarm objects so that you can prove the backup and restore operation work. The example Swarm we’ll be backing up in these examples has an overlay network called `vantage-net` and a Swarm service called `vantage-svc`.

1.  Stop Docker on the Swarm manager node you are performing the backup from.

    This will stop all UCP containers on the node. If UCP is configured for HA, the other managers will make sure the control plane remains available.

    ```
     $ service docker stop 
    ```

`*   Backup the Swarm config.

    The example uses the Linux `tar` utility to perform the file copy. Feel free to use a different tool.

    ```
     $ tar -czvf swarm.bkp /var/lib/docker/swarm/
     tar: Removing leading `/' from member names
     /var/lib/docker/swarm/
     /var/lib/docker/swarm/docker-state.json
     /var/lib/docker/swarm/state.json
     <Snip> 
    ```

    `*   Verify that the backup file exists.

    ```
     $ ls -l
     -rw-r--r-- 1 root   root   450727 Jan 29 14:06 swarm.bkp 
    ```

     `You should rotate, and store the backup file off-site according to your corporate backup policies.` `*   Restart Docker.

    ```
     $ service docker restart 
    `````` 

 ```Now that Swarm is backed up, it’s time to **backup UCP**.

A few notes on backing up UCP before we start.

The UCP backup job runs as a container, so Docker needs to be running for the backup to work.

You can run the backup from any UCP manager node in the cluster, and you only need to run the operation on one node (UCP replicates its configuration to all manager nodes, so backing up from multiple nodes is not required).

Backing up UCP will stop all UCP containers on the manager that you’re executing the operation on. With this in mind, you should be running a highly available UCP cluster, and you should run the operation at a quiet time for the business.

Finally, user workloads running on the manager node will not be stopped. However, it is not recommended to run user workloads on UCP managers.

Let’s backup UCP.

Perform the following command on a UCP manager node. Docker will need to be running on the node.

```
$ docker container run --log-driver none --rm -i --name ucp `\`
  -v /var/run/docker.sock:/var/run/docker.sock `\`
  docker/ucp:2.2.5 backup --interactive `\`
  --passphrase `"Password123"` > ucp.bkp 
```

 `It’s a long command, so let’s step through it.

The first line is a standard `docker container run` command that tells Docker to run a container with no log driver, to remove it when the operation is complete, and to call it `ucp`. The second line mounts the *Docker socket* into the container so that the container has access to the Docker API to stop containers etc. The third line tells Docker to run a `backup --interactive` command inside of a container based on the `docker/ucp:2.2.5` image. The final line creates an encrypted file called `ucp.bkp` and protects it with a password.

A few points worth noting.

It’s a good idea to be specific about the version (tag) of the UCP image to use. This example specifies `docker/ucp:2.2.5`. One of the reasons for being specific, is that it’s recommended to run backup and restore operations with the same version of the image. If you don’t explicitly state which image to use, Docker will use the one tagged as `latest`, which might be different between the time you run the backup command and the time you run the restore.

You should always use the `--passphrase` flag to protect the contents of the backup, and you should definitely use a better password than the one in the example :-D

You should catalogue and make off-site copies of the backup file according to your corporate backup policies. You should also configure a backup schedule and job verification.

Now that Swarm and UCP are backed up, you can safely recover them in the event of disaster. Speaking of which….

###### Recovering UCP

We need to be clear about one thing before we get into the weeds of recovering UCP: Restoring from backup is a last resort, and should only be used when the cluster has been corrupted or all manager nodes have been lost!

You **do not need to recover from a backup if you’ve lost a single manager in an HA cluster**. In that case, you can easily add a new manager and it’ll join the cluster.

We’ll show how to recover Swarm from a backup, and then UCP.

Perform the following tasks from the Swarm/UCP manager node that you wish to recover.

1.  Stop Docker.

    ```
     $ service docker stop 
    ```

`*   Delete any existing Swarm configuration.

    ```
     $ rm -r /var/lib/docker/swarm 
    ```

    `*   Restore the Swarm configuration from backup.

    In this example, we’ll restore from a zipped `tar` file called `swarm.bkp`. Restoring to the root directory is required with this command as it will include the full path to the original files as part of the extract operation. This may be different in your environment.

    ```
     $ tar -zxvf swarm.bkp -C / 
    ```

    `*   Initialize a new Swarm cluster.

    Remember, you are not recovering a manager and adding it back to a working cluster. This operation is to recover a failed Swarm that has no surviving managers. The `--force-new-cluster` flag tells Docker to create a new cluster using the configuration stored in `/var/lib/docker/swarm` on the current node.

    ```
     $ docker swarm init --force-new-cluster
     Swarm initialized: current node (jhsg...3l9h) is now a manager. 
    ```

    `*   Check that the network and service were recovered as part of the operation.

    ```
     $ docker network ls
     NETWORK ID        NAME            DRIVER       SCOPE
     snkqjy0chtd5      vantage-net     overlay      swarm

     $ docker service ls
     ID              NAME          MODE         REPLICAS    IMAGE
     w9dimu8jfrze    vantage-svc   replicated   5/5         alpine:latest 
    ```

     `Congratulations. The Swarm is recovered.` `*   Add new manager and worker nodes to the Swarm, and take a fresh backup.`````

 ```With Swarm recovered, you can now **recover UCP.

In this example, UCP was backed up to a file called `ucp.bkp` in the current directory. Despite the name of the backup file, it is a Linux tarball.

Run the following commands from the node that you want to recover UCP on. This can be the node that you just recovered Swarm on.

1.  Remove any existing, and potentially corrupted, UCP installations.

    ```
     $ docker container run --rm -it --name ucp \
       -v /var/run/docker.sock:/var/run/docker.sock \
       docker/ucp:2.2.5 uninstall-ucp --interactive

     INFO[0000] Your engine version 17.06.2-ee-6, build e75fdb8 is compatible
     INFO[0000] We're about to uninstall from this swarm cluster.
     Do you want to proceed with the uninstall? (y/n): y
     INFO[0000] Uninstalling UCP on each node...
     INFO[0009] UCP has been removed from this cluster successfully.
     INFO[0011] Removing UCP Services 
    ```

`*   Restore UCP from the backup.

    ```
     $ docker container run --rm -i --name ucp \
       -v /var/run/docker.sock:/var/run/docker.sock  \
       docker/ucp:2.2.5 restore --passphrase "Password123" < ucp.bkp

     INFO[0000] Your engine version 17.06.2-ee-6, build e75fdb8 is compatible
     <Snip>
     time="2018-01-30T10:16:29Z" level=info msg="Parsing backup file"
     time="2018-01-30T10:16:38Z" level=info msg="Deploying UCP Agent Service"
     time="2018-01-30T10:17:18Z" level=info msg="Cluster successfully restored. 
    ```

    `*   Log on to the UCP web UI and ensure that the user created earlier is still present (or any other UCP objects that previously existed in your environment).``

 ``Congrats. You now know how to backup and recover Docker Swarm and Docker UCP.

Let’s shift our attention to Docker Trusted Registry.

#### Docker Trusted Registry (DTR)

Docker Trusted Registry, which we’re going to refer to as DTR, is a secure, highly available on-premises Docker registry. If you know Docker Hub, think of DTR as a private Docker Hub that you can install on-premises and manage yourself.

In this section, we’ll show how to install it in an HA configuration, and how to back it up and perform recovery operations. We’ll show how DTR implements advanced features in the next chapter.

Let’s mention a few important things before getting your hands dirty with the installation.

If possible, you should run your DTR instances on dedicated nodes. You definitely shouldn’t run user workloads on your production DTR nodes.

As with UCP, you should run an odd number of DTR instances. 3 or 5 is best for fault tolerance. A recommended configuration for a production environment might be:

*   3 dedicated UCP managers
*   3 dedicated DTR instances
*   However many worker nodes your application requirements demand

Let’s install and configure a single DTR instance.

##### Install DTR

The next few steps will walk through the process of configuring the first DTR instance in a UCP cluster.

To follow along, you’ll need a UCP node that you will install DTR on, and a load balancer configured to listen on port 443 in TCP passthrough mode with a health check configured for `/health` on port 443\. Figure 16.10 shows a high-level diagram of what we’ll build.

Configuring a load balancer is beyond the scope of this book, but the diagram shows the important DTR-related configuration requirements.

![Figure 16.10 High level single-instance DTR config.](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-10.png)

Figure 16.10 High level single-instance DTR config.

1.  Log on to the UCP web UI and click `Admin` > `Admin Settings` > `Docker Trusted Registry`.
2.  Fill out the DTR configuration form.
    *   `DTR EXTERNAL URL:` Set this to the URL of your external load balancer.
    *   `UCP NODE:` Select the name of the node you wish to install DTR on.
    *   `Disable TLS Verification For UCP:` Check this box if you’re using self-signed certificates.
3.  Copy the long command at the bottom of the form.
4.  Paste the command into any UCP manager node.

    The command includes the `--ucp-node` flag telling UCP which node to perform the install on.

    The following is an example DTR install command that matches the configuration in Figure 16.10\. It assumes that you already have a load balancer configured at `dtr.mydns.com`

    ```
     $ docker run -it --rm docker/dtr install \
       --dtr-external-url dtr.mydns.com \
       --ucp-node dtr1  \
       --ucp-url https://34.252.195.122 \
       --ucp-username admin --ucp-insecure-tls 
    ```

     `You will need to provide the UCP admin password to complete the installation.` 
`*   Once the installation is complete, point your web browser to your load balancer. You will be automatically logged in to DTR.![Figure 16.11 DTR home page](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-11.png)

    Figure 16.11 DTR home page` 

 `DTR is ready to use. But it’s not configured for HA.

##### Configure DTR for high availability

Configuring DTR with multiple replicas for HA requires a shared storage backend. This can be NFS or object storage, and can be on-premises or in the public cloud. We’ll walk through the process of configuring DTR for HA using an Amazon S3 bucket as the shared backend.

1.  Log on to the DTR console and navigate to `Settings`.
2.  Select the `Storage` tab and configure the shared storage backend.

    Figure 16.12 shows DTR configured to use an AWS S3 bucket called `deep-dive-dtr` in the `eu-west-1` AWS availability zone. You will not be able to use this example.

    ![Figure 16.12 DTR Shared Storage configuration for AWS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-12.png)

    Figure 16.12 DTR Shared Storage configuration for AWS

DTR is now configured with a shared storage backend and ready to have additional replicas.

1.  Run the following command from a manager node in the UCP cluster.

    ```
     $ docker run -it --rm \
       docker/dtr:2.4.1 join \
       --ucp-node dtr2 \
       --existing-replica-id 47f20fb864cf \
       --ucp-insecure-tls 
    ```

     `The `--ucp-node` flag tells the command which node to add the new DTR replica on. The `--insecure-tls` flag is required if you’re using self-signed certificates.

    You will need to substitute the version of the image and the replica ID. The replica ID was displayed as part of the output when you installed the initial replica.` 
`*   Enter the UCP URL and port, as well as admin credentials when prompted.`

 `When the join is complete, you will see some messages like the following.

```
INFO[0166] Join is complete
INFO[0166] Replica ID is set to: a6a628053157
INFO[0166] There are currently 2 replicas in your DTR cluster
INFO[0166] You have an even number of replicas which can impact availability
INFO[0166] It is recommended that you have 3, 5 or 7 replicas in your cluster 
```

 `Be sure to follow the advice and install additional replicas so that you operate an odd number.

You may need to update your load balancer configuration so that it balances traffic across the new replicas.

DTR is now configured for HA. This means you can lose a replica without impacting the availability of the service. Figure 16.13 shows an HA DTR configuration.

![Figure 16.13 DTR HA](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-13.png)

Figure 16.13 DTR HA

Notice that the external load balancer is sending traffic to all three DTR replicas, as well as performing health checks on all three. All three DTR replicas are also sharing the same external shared storage backend.

In the diagram, the load balancer and the shared storage backend are 3rd party products and depicted as singletons (not HA). In order to keep the entire environment as highly available as possible, you should ensure they have native HA, and that you back up their contents and configurations as well (e.g. make sure the load balancer and storage systems are natively HA, and perform backups of them).

##### Backup DTR

As with UCP, DTR has a native `backup` command that is part of the Docker image that was used to install the DTR. This native backup command will backup the DTR configuration that is stored in a set of named volumes, and includes:

*   DTR configuration
*   Repository metadata
*   Notary data
*   Certificates

Images are not backed up as part of a native DTR backup**. It is expected that images are stored in a highly available storage backend that has its own independent backup schedule using non-Docker tools.

Run the following command from a UCP manager node to perform a DTR backup.

```
$ `read` -sp `'ucp password: '` UCP_PASSWORD`;` `\`
    docker run --log-driver none -i --rm `\`
    --env `UCP_PASSWORD``=``$UCP_PASSWORD` `\`
    docker/dtr:2.4.1 backup `\`
    --ucp-insecure-tls `\`
    --ucp-username admin `\`
    > ucp.bkp 
```

 `Let’s explain what the command is doing.

The `read` command will prompt you to enter the password for the UCP admin account, and will store it in a variable called `UCP_PASSWORD`. The second line tells Docker to start a new temporary container for the operation. The third line makes the UCP password available inside the container as an environment variable. The fourth line issues the backup command. The fifth line makes it work with self-signed certificates. The sixth line sets the UCP username to “admin”. The last line directs the backup to a file in the current directory called `ucp.bkp`.

You will be prompted to enter the UCP URL as well as a replica ID. You can specify these as part of the backup command, I just didn’t want to explain a single command that was 9 lines long!

When the backup is finished, you will have a file called `ucp.bkp` in your working directory. This should be picked up by your corporate backup tool and managed in-line with your existing corporate backup policies.

##### Recover DTR from backups

Restoring DTR from backups should be a last resort, and only attempted when the majority of replicas are down and the cluster cannot be recovered any other way. If you have lost a single replica and the majority are still up, you should add a new replica using the `dtr join` command.

If you are sure you have to restore from backup, the workflow is like this:

1.  Stop and delete DTR on the node (might already be stopped)
2.  Restore images to the shared storage backend (might not be required)
3.  Restore DTR

Run the following commands from the node that you want to restore DTR to. This node will obviously need to be a member of the same UCP cluster that the DTR is a member of. You should also use the same version of the `docker/dtr` image that was used to create the backup.

1.  Stop and delete DTR.

    ```
     $ docker run -it --rm \
       docker/dtr:2.4.1 destroy \
       --ucp-insecure-tls

     INFO[0000] Beginning Docker Trusted Registry replica destroy
     ucp-url (The UCP URL including domain and port): https://34.252.195.122:443
     ucp-username (The UCP administrator username): admin
     ucp-password:
     INFO[0020] Validating UCP cert
     INFO[0020] Connecting to UCP
     INFO[0021] Searching containers in UCP for DTR replicas
     INFO[0023] This cluster contains the replicas: 47f20fb864cf a6a628053157
     Choose a replica to destroy [47f20fb864cf]:
     INFO[0030] Force removing replica
     INFO[0030] Stopping containers
     INFO[0035] Removing containers
     INFO[0045] Removing volumes
     INFO[0047] Replica removed. 
    ```

     `You’ll be prompted to enter the UCP URL, admin credentials, and replica ID that you want to delete.

    If you have multiple replicas, you can run the command multiple times to remove them all.` 
`*   If the images were lost from the shared backend, you will need to recover them. This step is beyond the scope of the book as it can be specific to your shared storage backend.*   Restore DTR with the following command.

    You will need to substitute the values on lines 5 and 6 with the values from your environment. Unfortunately the `restore` command cannot be ran interactively, so you cannot be prompted for values once the `restore` has started.

    ```
     `$` `read` `-sp` `'ucp password: '` `UCP_PASSWORD``;` `\`
     `docker` `run` `-i` `--rm` `\`
     `--env` `UCP_PASSWORD``=$``UCP_PASSWORD` `\`
     `docker``/``dtr``:``2``.``4``.``1` `restore` `\`
     `--ucp-url` `<``ENTER_YOUR_ucp-url``>` `\`
     `--ucp-node` `<``ENTER_DTR_NODE_hostname``>` `\`
     `--ucp-insecure-tls` `\`
     `--ucp-username` `admin` `\`
     `<` `ucp``.``bkp` 
    ```` 

 ``DTR is now recovered.

Congratulations. You now know how to backup and recover; Swarm, UCP, and DTR.

Time for one final thing before wrapping up the chapter — network ports!

UCP managers, workers, and DTR nodes need to be able to communicate over the network. Figure 16.14 summarizes the port requirements.

![Figure 16.14 UCP cluster network port requirements](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure16-14.png)

Figure 16.14 UCP cluster network port requirements

### Chapter Summary

Docker Enterprise Edition (EE) is a suite of products that form an “*enterprise friendly*” container-as-a-service platform. It comprises a hardened Docker Engine, an Operations UI, and a secure registry. All of which can be deployed on-premises and managed by the customer. It’s even bundled with a support contract.

Docker Universal Control Plane (UCP) provides a simple-to-use web UI focussed at traditional enterprise Ops teams. It supports native high availability (HA) and has tools to perform backup and restore operations. Once up and running, it provides a whole suite of enterprise-grade features that we’ll discuss in the next chapter.

Docker Trusted Registry (DTR) sits on top of UCP and provides a highly available secure registry. Like UCP, this can be deployed on-premises within the safety of the corporate *“firewall”*, and provides native tools for backup and recovery.```````````````````````


# 第十八章：企业级功能

本章是上一章的延续，涵盖了 Docker Universal Control Plane（UCP）和 Docker Trusted Registry（DTR）提供的一些企业级功能。

我们将假设您已经阅读了上一章，因此知道如何安装和配置它们，以及执行备份和恢复操作。

我们将把本章分为两部分：

+   简而言之

+   深入挖掘

### 企业级功能-简而言之

企业希望使用 Docker 和容器，但他们需要像真正的企业应用程序一样打包和支持。他们还需要像基于角色的访问控制和与 Active Directory 等企业目录服务的集成。这就是*Docker 企业版*发挥作用的地方。

Docker 企业版是 Docker 引擎的强化版本，具有运维 UI，安全注册表和一堆企业专注的功能。您可以在本地或云端部署它，自己管理它，并且可以获得支持合同。

总之，它是一个容器即服务平台，您可以在自己公司的数据中心安全运行。

### 企业级功能-深入挖掘

我们将把本章的主要部分分为以下几个部分：

+   基于角色的访问控制（RBAC）

+   Active Directory 集成

+   Docker 内容信任（DCT）

+   配置 Docker Trusted Registry（DTR）

+   使用 Docker Trusted Registry

+   镜像推广

+   HTTP 路由网格（HRM）

#### 基于角色的访问控制（RBAC）

在过去的 10 年中，我大部分时间都在金融服务行业从事 IT 工作。在我工作的大多数地方，角色基础访问控制（RBAC）和 Active Directory（AD）集成是强制性的两个复选框。如果你试图向我们销售一个产品，而它没有这两个功能，我们是不会购买的！

幸运的是，Docker EE 都有。在本节中，我们将讨论 RBAC。

UCP 通过一种称为*授予*的东西来实现 RBAC。在高层次上，授予由三个部分组成：

+   **主题**

+   **角色**

+   **集合**

*主题*是一个或多个用户或团队。*角色*是权限集，*集合*是这些权限适用的资源。见图 17.1。

![图 17.1 授予](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-1.png)

图 17.1 授予

图 17.2 显示了一个示例，其中`SRT`团队对`/zones/dev/srt`集合中的所有资源具有`container-full-control`访问权限。

![图 17.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-2.png)

图 17.2

让我们完成以下步骤来创建一个授予：

+   创建用户和团队

+   创建一个自定义角色

+   创建一个集合

+   创建一个授权

只有 UCP 管理员才能创建和管理用户、团队、角色、集合和授权。因此，为了跟随操作，你需要以 UCP 管理员身份登录。 

##### 创建用户和团队

将用户分组到团队，并将团队分配到授权是最佳实践。你*可以*将单个用户分配给*授权*，但这并不推荐。

让我们创建一些用户和团队。

1.  登录到 UCP。

1.  展开“用户管理”并点击“用户”。

从这里你可以创建用户。

1.  点击“组织和团队”。

从这里你可以创建组织。在接下来的几个步骤中，我们将使用一个名为“制造业”的组织作为示例。

1.  点击“制造业”组织并创建一个团队。

团队存在于组织中。不可能创建一个不属于任何组织的团队，一个团队只能是一个组织的成员。

1.  将用户添加到一个团队。

要将用户添加到团队，你需要点击进入团队，并从“操作”菜单中选择“添加用户”。

图 17.3 显示了如何将用户添加到“制造业”组织中的`SRT`团队。

![图 17.3 将用户添加到团队](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-3.png)

图 17.3 将用户添加到团队

现在你有了一些用户和团队。UCP 与 DTR 共享其用户数据库，这意味着你在 UCP 中创建的任何用户和团队也可以在 DTR 中使用。

##### 创建一个自定义角色

自定义角色非常强大，它们可以让你对分配的权限进行极其精细的控制。在这一步中，我们将创建一个名为`secret-ops`的新自定义角色，允许主体创建、删除、更新、使用和查看 Docker secrets。

1.  展开左侧导航窗格的“用户管理”选项卡，选择“角色”。

1.  创建一个新角色。

1.  给角色命名。

在这个例子中，我们将创建一个名为“secret-ops”的新自定义角色，具有执行所有与 secret 相关的操作的权限。

1.  选择“操作”并探索可以分配给角色的操作列表。

列表很长，允许你指定单个 API 操作。

1.  选择你想要分配给角色的单个 API 操作。

在这个例子中，我们将分配所有与 secret 相关的 API 操作。

![图 17.4 分配 API 操作给自定义角色](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-4.png)

图 17.4 分配 API 操作给自定义角色

1.  点击“创建”。

该角色现在已经在系统中，并可以分配给多个授权。

让我们创建一个集合。

##### 创建一个集合

在上一章中，我们了解到网络、卷、秘密、服务和节点都是 Swarm 资源——它们被存储在 Swarm 配置中的`/var/lib/docker/swarm`中。*集合*让你以符合组织结构和 IT 要求的方式对它们进行分组。例如，您的 IT 基础设施可能分为三个区域；`prod`、`test`和`dev`。如果是这种情况，您可以创建三个集合，并分配资源给每个集合，如图 17.5 所示。

![图 17.5 高级集合](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-5.png)

图 17.5 高级集合

每个资源只能属于一个集合。

在接下来的步骤中，我们将创建一个名为`zones/dev/srt`的新集合，并将一个秘密分配给它。集合本质上是分层的，因此您需要创建三个嵌套的集合，如下所示：`zones` > `dev` > `srt`。

从 Docker UCP web UI 执行以下所有步骤。

1.  从左侧导航窗格中选择`集合`，然后选择`创建集合`。

1.  创建名为`zones`的根集合。

1.  点击“查看子项”以查看`/zones`集合。

1.  创建一个名为`dev`的嵌套子集合。

1.  点击“查看子项”以查看`/zones/dev`集合。

1.  创建名为`srt`的最终嵌套子集合。

现在您有一个名为`/zones/dev/srt`的集合。但是，它目前是空的。在接下来的步骤中，我们将向其中添加一个*秘密*。

1.  创建一个新的秘密。

您可以从命令行或 UCP web UI 中创建它。我们将解释 web UI 方法。

从 UCP web UI 中点击：`秘密` > `创建秘密`。给它一个名称，一些数据，然后点击`保存`。

在创建秘密的同时也可以配置*集合*。但我们不是这样做的。

1.  在 UCP web UI 中找到并选择秘密。

1.  从“配置”下拉菜单中点击“集合”。

1.  通过“查看子项”层次结构导航，直到选择`/zones/dev/srt`集合，然后点击“保存”。

秘密现在是`/zones/dev/srt`集合的一部分。它不能是任何其他集合的成员。

在创建*授权*之前，还有一件关于*集合*的事情。集合具有继承模型，其中对任何集合的访问自动意味着对嵌套子集合的访问。在图 17.6 中，`dev`团队可以访问`/zones/dev`集合，因此它自动获得对`srt`、`hellcat`和`daemon`子集合中资源的访问权限。

![图 17.6 集合继承](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-6.png)

图 17.6 集合继承

###### 创建授予

现在您已经有了用户和团队、自定义角色和集合，您可以创建一个授予。在这个例子中，我们将为`srt-dev`团队创建一个授予，使其对`/zones/dev/srt`集合中的所有资源具有自定义`secret-ops`角色。

授予涉及*谁*，获得*什么访问权限*，对*哪些资源*。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-7.png)

1.  展开左侧导航窗格上的“用户管理”选项卡，然后单击“授予”。

1.  创建一个新的授予。

1.  点击`Subject`，从`manufacturing`组织中选择`SRT`团队。

可以选择整个组织。如果这样做，组织内的所有团队都将包括在授予中。

1.  单击“角色”，然后选择自定义的`secret-ops`角色。

1.  单击“集合”，然后选择`/zones/dev/srt`集合。

在看到`/zones`之前，您可能需要查看顶级`Swarm`集合的子项。

1.  单击“保存”以创建授予。

现在已经创建了授予，并且可以在系统上的所有授予列表中查看。`manufacturing/SRT`团队的成员现在可以在`/zones/dev/srt`集合中执行所有与秘密相关的操作。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-8.png)

您可以在授予处于活动状态时修改授予的组件。例如，您可以将用户添加到团队，将资源添加到集合。但是您不能更改分配给角色的 API 操作。如果您想要更改角色的权限，您需要创建一个具有所需权限的新角色。

###### 节点的 RBAC

最后关于 RBAC 的一件事。您可以将集群中的工作节点分组以进行调度。例如，您可能会为开发、测试和 QA 工作负载运行一个单一集群——一个单一集群可能会减少管理开销，并使将节点分配给三个不同环境变得更容易。但是您可能还希望将工作节点分成几部分，以便只有`dev`团队的成员可以将工作安排到`dev`集合中的节点等。

正如您所期望的那样，您可以通过*授予*来实现这一点。首先，您会将 UCP Worker 节点分配给一个自定义*集合*。然后，您会创建一个包括集合、内置的`Scheduler`*角色*和您想要分配授予的团队的授予。这样可以让您控制哪些用户可以将工作安排到集群中的哪些节点。

作为一个简单的例子，图 17.9 中显示的授权将允许`dev`团队的成员能够将服务和容器调度到`/zones/dev`集合中的工作节点上。

![图 17.9 节点的 RBAC](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-9.png)

图 17.9 节点的 RBAC

就是这样！您知道如何在 Docker UCP 中实现 RBAC 了！

#### Active Directory 集成

像所有优秀的企业工具一样，UCP 集成了 Active Directory 和其他 LDAP 目录服务。这使其能够利用来自您组织已建立的单一登录系统的现有用户和组。

在本节中进一步进行之前，非常重要的是与负责组织目录服务的团队讨论任何 AD/DLAP 集成计划。让他们从一开始就参与进来，这样您的规划和实施才能尽可能顺利！

开箱即用，UCP 用户和组数据存储在本地数据库中，DTR 利用该数据库实现单一登录（SSO）体验。这会在本地验证所有访问请求，并允许您登录到 DTR 而无需再次输入 UCP 凭据。但是，**UCP 管理员**可以配置 UCP 以利用存储在 AD 或其他 LDAP 目录服务中的现有企业用户帐户，将认证和帐户管理外包给现有团队和流程。

以下步骤将向您展示如何配置 UCP 以利用 AD 进行用户帐户。在高层次上，该过程告诉 UCP 在特定目录中搜索用户帐户，并将其复制到 UCP 中。如前所述，与您的目录服务团队协调此工作。

让我们开始吧。

1.  展开左侧导航窗格中的`Admin`下拉菜单，然后选择`Admin Settings`。

1.  选择`Authentication & Authorization`，并在**LDAP Enabled**标题下单击`Yes`。

1.  配置 LDAP 服务器设置。

在高层次上，您可以将`LDAP 服务器设置`视为*搜索位置*。例如，要在哪些目录中查找用户帐户。

在此处输入的值将特定于您的环境。

**LDAP 服务器 URL**是您将在其中搜索帐户的域中 LDAP 服务器的名称。例如，`ad.mycompany.internal`。

**Reader DN**和**Reader Password**是具有搜索权限的目录中帐户的凭据。该帐户必须存在于您正在搜索的目录中，或者受到该目录的信任。最佳做法是让它在目录中具有*只读*权限。

您可以使用“添加 LDAP 域+”按钮添加要搜索的其他域。每个域都需要自己的 LDAP 服务器 URL 和读取器帐户。

1.  配置 LDAP 用户搜索配置。

如果“LDAP 服务器设置”是*搜索位置*，那么“LDAP 用户搜索配置”就是*搜索对象*。

**基本 DN**指定从哪个 LDAP 节点开始搜索。

**用户名属性**是用作 UCP 用户名的 LDAP 属性。

**全名属性**是用作 UCP 帐户全名的 LDAP 属性。

请参阅其他更高级的设置的文档。在配置 LDAP 集成时，您还应该与目录服务团队进行咨询。

1.  一旦您配置了 LDAP 设置，UCP 将搜索匹配的用户并在 UCP 用户数据库中创建它们。然后，它将根据“同步间隔（小时）”设置执行定期同步操作。

如果您勾选了“即时用户配置”框，UCP 将推迟创建用户帐户，直到每个帐户的第一次登录事件。

1.  在点击“保存”之前，您应该始终在“LDAP 测试登录”部分执行测试登录。

测试登录需要使用 LDAP 系统中有效的用户帐户。测试将应用上面各节中定义的所有配置值（您即将保存的 LDAP 配置）。

只有在测试登录成功时才保存配置。

1.  保存配置。

此时，UCP 将搜索 LDAP 系统并创建与基本 DN 和其他提供的条件匹配的用户帐户。

在配置 LDAP 之前创建的本地用户帐户仍将存在于系统中，并且仍然可以使用。

#### Docker 内容信任（DCT）

在现代 IT 世界中，*信任*是一件大事！并且未来它将变得更加重要。幸运的是，Docker 通过一个名为 Docker 内容信任（DCT）的功能来实现信任。

在非常高的层次上，Docker 镜像的发布者可以在将其推送到存储库时对其进行签名。消费者随后可以在拉取它们时验证它们，或执行构建和运行操作。长话短说，DCT 使消费者能够保证他们得到了他们所要求的东西！

图 17.10 显示了高级架构。

![图 17.10 高级 DCT 架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-10.png)

图 17.10 高级 DCT 架构

DCT 实现*客户端*签名和验证操作，这意味着 Docker 客户端执行这些操作。

- 尽管在互联网上传输和推送软件时，加密保证非常重要，但在整个软件交付流程的每个层面和每个步骤中，它变得越来越重要。希望不久的将来，交付链的所有方面都将充满加密信任保证。

- 让我们快速示例配置 DCT 并看到它的运行情况。

- 您将需要一个单独的 Docker 客户端和一个可以将镜像推送到的仓库。Docker Hub 上的仓库将起作用。

- DCT 是通过 DOCKER_CONTENT_TRUST 环境变量打开和关闭的。将其设置为“1”将在当前会话中打开 DCT。将其设置为任何其他值将关闭它。以下示例将在基于 Linux 的 Docker 主机上打开它。

```
$ `export` `DOCKER_CONTENT_TRUST``=``1` 
```

- 未来的 docker push 命令将自动在推送操作中签署镜像。同样，只有签署的镜像才能使用 pull、build 和 run 命令。

- 让我们将一个带有新标记的镜像推送到一个仓库。

- 被推送的镜像可以是任何镜像。实际上，我正在使用的是我刚刚拉取的当前 alpine:latest。目前，它还没有由我签名！

1.  - 给镜像打标记，这样它就可以推送到您想要的仓库。我将把它推送到我个人 Docker Hub 帐户命名空间内的一个新仓库。

```
 $ docker image tag alpine:latest nigelpoulton/dockerbook:v1 
```

- 登录到 Docker Hub（或其他注册表），这样您就可以在下一步中推送镜像。

```
 $ docker login
 Login with your Docker ID to push and pull images from Docker Hub.
 Username: nigelpoulton
 Password:
 Login Succeeded 
```

- 推送新标记的镜像。

- ```
     $ docker image push nigelpoulton/dockerbook:v1
     The push refers to a repository [docker.io/nigelpoulton/dockerbook]
     cd7100a72410: Mounted from library/alpine
     v1: digest: sha256:8c03...acbc size: 528
     Signing and pushing trust metadata
     <Snip>
     Enter passphrase for new root key with ID 865e4ec:
     Repeat passphrase for new root key with ID 865e4ec:
     Enter passphrase for new repository key with ID bd0d97d:
     Repeat passphrase for new repository key with ID bd0d97d:
     Finished initializing "docker.io/nigelpoulton/sign"
     Successfully signed "docker.io/nigelpoulton/sign":v1 
    `````

```With DCT enabled, the image was automatically signed as part of the push operation.

Two sets of keys were created as part of the signing operation:

*   Root key
*   Repository key

By default, both are stored below a hidden folder in your home directory called `docker`. On Linux this is `~/.docker/trust`.

The **root key** is the master key (of sorts). It’s used to create and sign new repository keys, and should be kept safe. This means you should protect it with a strong passphrase, and you should store it offline in a secure place when not in use. If it gets compromised, you’ll be in world of pain! You would normally only have one per person, or may be even one per team or organization, and you’ll normally only use it to create new repository keys.

The **repository key**, also known as the *tagging key* is a per-repository key that is used to sign tagged images pushed to a particular repository. As such, you’ll have one per repository. It’s quite a bit easier to recover from a loss of this key, but you should still protect it with a strong passphrase and keep it safe.

Each time you push an image to a **new repository**, you’ll create a new repository tagging key. You need your **root key** to do this, so you’ll need to enter the root key’s passphrase. Subsequent pushes to the same repository will only require you to enter the passphrase for the repository tagging key.

There’s another key called the `timestamp key`. This gets stored in the remote repository and is used in more advanced use-cases to ensure things like *freshness*.

Let’s have a look at pulling images with DCT enabled.

Perform the following commands from the same Docker host that has DCT enabled.

Pull an unsigned image.

```

- docker image pull nigelpoulton/dockerbook:unsigned

- 错误：docker.io/nigelpoulton/dockerbook 的信任数据不存在：

- notary.docker.io 没有 docker.io/nigelpoulton/dockerbook 的信任数据

```

 `> **Note:** Sometimes the error message will be `No trust data for unsigned`.

See how Docker has refused to download the image because it is not signed.

You’ll get similar errors if you try to build new images or run new containers from unsigned images. Let’s test it.

Pull the unsigned image by using the `--disable-content-trust` flag to override DCT.

```

- docker image pull --disable-content-trust nigelpoulton/dockerbook:unsigned

```

 `The `--disable-content-trust` flag overrides DCT on a per-command basis. Use it wisely.

Now try and run a container from the unsigned image.

```

- docker 容器运行-d --rm nigelpoulton/dockerbook:unsigned

- docker：未签名的没有信任数据。

```

 `This proves that Docker Content Trust enforces policy on `push`, `pull` and `run` operations. Try a `build` to see it work there as well.

Docker UCP also supports DCT, allowing you to set a UCP-wide signing policy.

To enable DCT across an entire UCP, expand the `Admin` drop-down and click `Admin Settings`. Select the `Docker Content Trust` option and tick the `Run Only Signed Images` tickbox. This will enforce a signing policy across the entire cluster that will only allow you to deploy services using signed images.

The default configuration will allow any image signed by a valid UCP user. You can optionally configure a list of teams that are authorized to sign images.

That’s the basics of Docker Content Trust. Let’s move on to configuring and using Docker Trusted Registry (DTR).

#### Configuring Docker Trusted Registry (DTR)

In the previous chapter we installed DTR, plugged it in to a shared storage backend, and configured HA. We also learned that UCP and DTR share a common single-sign-on sub-system. But there’s a few other important things you should configure. Let’s take a look.

Most of the DTR configuration settings are located on the `Settings` page of the DTR web UI.

From the `General` tab you can configure:

*   Automatic update settings
*   Licensing
*   Load balancer address
*   Certificates
*   Single-sign-on

The `TLS Settings` under `Domains & proxies` allows you to change the certificates used by UCP. By default, DTR uses self-signed certificates, but you can use this page to configure the use of custom certificates.

The `Storage` tab lets you configure the backend used for **image storage**. We saw this in the previous chapter when we configured a shared Amazon S3 backend so that we could configure DTR HA. Other storage options include object storage services from other cloud providers, as well as volumes and NFS shares.

The `Security` tab is where you enable and disable *Image Scanning* — binary-level scans that identify known vulnerabilities in images. When you enable *image scanning*, you have the option of updating the vulnerability database *online* or *offline*. Online will automatically sync the database over the internet, whereas the offline method is for DTR instances that do not have internet access and need to update the database manually.

See the *Security in Docker* chapter for more information on Image Scanning.

Last but not least, the `Garbage Collection` tab lets you configure when DTR will perform garbage collection on image layers that are no longer referenced in the Registry. By default, unreferenced layers are not garbage collected, resulting in large amounts of wasted disk space. If you enable garbage collection, layers that are no longer referenced by an image will be deleted, but layers that are referenced by at least one image manifest will not.

See the chapter on Images for more information about how image manifests reference image layers.

Now that we know how to configure DTR, let’s use it!

#### Using Docker Trusted Registry

Docker Trusted Registry is a secure on-premises registry that you configure and manage yourself. It’s integrated into UCP for smooth out-of-the-box experience.

In this section, we’ll look at how to push and pull images from it, and we’ll learn how to inspect and manage repositories using the DTR web UI.

##### Log in to the DTR UI and create a repo and permissions

Let’s log in to DTR and create a new repository that members of the `technology/devs` team can push and pull images from.

Log on to DTR. The DTR URL can be found in the UCP web UI under `Admin` > `Admin Settings` > `Docker Trusted Registry`. Remember that the DTR web UI is accessible over HTTPS on TCP port 443.

Create a new organization and team, and add a user to it. The example will create an organization called `technology`, a team called `devs`, and add the `nigelpoulton` user to it. You can substitute these values in your environment.

1.  Click `Organizations` in the left navigation pane.
2.  Click `New organization` and call it `technology`.
3.  Select the new `technology` organization and click the `+` button next to `TEAMS` as shown in Figure 17.11.![Figure 17.11](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-11.png)

    Figure 17.11

4.  With the `devs` team selected, add an existing user.

    The example will add the `nigelpoulton` user. Your user will be different in your environment.

The organization and team changes you have made in DTR will be reflected in UCP. This is because they share the same accounts database.

Let’s create a new repository and add the `technology/devs` team with read/write permission.

Perform all of the following in the DTR web UI.

1.  If you aren’t already, navigate to `Organizations` > `technology` > `devs`.
2.  Select the `Repositories` tab and create a new repository.
3.  Configure the repository as follows.

    Make it a **New** repository called **test** under the **technology** organization. Make it **public**, enable **scan on push** and assign **read/write** permissions. Figure 17.12 shows a screenshot of how it should look.

    ![Figure 17.12 Creating a new DTR image repo](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-12.png)

    Figure 17.12 Creating a new DTR image repo

4.  Save changes.

Congratulations! You have an image repo on DTR called `<dtr-url>/technology`, and members of the `technology/devs` team have read/write access, meaning they can `push` and `pull` from it.

##### Push an image to the DTR repo

In this step we’ll push a new image to the repo you just created. To do this, we’ll complete the following steps:

1.  Pull an image and re-tag it.
2.  Configure a client to use a certificate bundle.
3.  Push the re-tagged image to the DTR repo.
4.  Verify the operation in the DTR web UI.

Let’s pull an image and tag it so that it can be pushed to the DTR repo.

It doesn’t matter what image you pull. The example uses the `alpine:latest` image because it’s small.

```

- docker pull alpine:latest

- 最新：正在从库/alpine 拉取

- ff3a5c916c92：拉取完成

- 摘要：sha256:7df6...b1c0

- 状态：已下载更新的镜像 alpine:latest

```

 `In order to push an image to a specific repo, you need to tag the image with the name of the repo. The example DTR repo has a fully qualified name of `dtr.mydns.com/technology/test`. This is made by combining the DNS name of the DTR and the name of the repo. Yours will be different.

Tag the image so it can be pushed to the DTR repo.

```

- docker image tag alpine:latest dtr.mydns.com/technology/test:v1

```

 `The next job is to configure a Docker client to authenticate as a user in the group that has read/write permission to the repository. The high-level process is to create a certificate bundle for the user and configure a Docker client to use those certificates.

1.  Login to UCP as admin, or a user that has read/write permission to the DTR repo.
2.  Navigate to the desired user account and create a `client bundle`.
3.  Copy the bundle file to the Docker client you want to configure.
4.  Login to the Docker client and perform the following commands from the client.
5.  Unzip the bundle and run the appropriate shell script to configure your environment.

The following will work on Mac and Linux.

```

- 执行“$（<env.sh）”。

```

`*   Run a `docker version` command to verify the environment has been configured and the certificates are being used.

    As long as the `Server` section of the output shows the `Version` as `ucp/x.x.x` it is working. This is because the shell script configured the Docker client to talk to a remote daemon on a UCP manager. It also configured the Docker client to sign all commands with the certificates.` 

 `The next job is to log in to DTR. The DTR URL and username will be different in your environment.

```

- docker login dtr.mydns.com

- 用户名：nigelpoulton

- 密码：

- 登录成功

```

 `You are now ready to push the re-tagged image to DTR.

```

- docker image push dtr.mydns.com/technology/test:v1

- 推送是指一个仓库`[dtr.mydns.com/technology/test]`

- cd7100a72410：已推送

- v1：摘要：sha256:8c03...acbc 大小：528

- ```

 `The push looks successful, but let’s verify the operation in the DTR web UI.

1.  If you aren’t already, login to the DTR web UI.
2.  Click `Repositories` in the left navigation pane.
3.  Click `View Details` for the `technology/test` repository.
4.  Click the `IMAGES` tab.

Figure 17.13 shows what the image looks like in the DTR repo. We can see that the image is a Linux-based image and that it has 3 major vulnerabilities. We know about the vulnerabilities because we configured the repository to scan all newly-pushed images.

![Figure 17.13](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-13.png)

Figure 17.13

Congratulations. You’ve successfully pushed an image to a new repository on DTR.

You can select the checkbox to the left of the image and delete it. Be certain before doing this, as the operation cannot be undone.

#### Image promotions

DTR has a couple other interesting features:

*   Image promotions
*   Immutable repos

Image promotions let you build policy-based automated pipelines that promote images through a set of repositories in the same DTR.

As an example, you might have developers pushing images to a repository called `base`. But you don’t want them to be able to push images straight to production in case they contain vulnerabilities. To help with situations like this, DTR allows you to assign a policy to the `base` repo, that will scan all pushed images, and promote them to another repo based on the results of the scan. If the scan highlights issues, the policy can *promote* the image to a quarantined repo, whereas if the scan results are clean, it can promote it to a QA or prod repo. You can even re-tag the image as it passes through the pipeline.

Let’s see it in action.

The example that we’ll walk through has a single DTR with 3 image repos:

*   `base`
*   `good`
*   `bad`

The `good` and `bad` repos are empty, but the `base` repo has two images in it, shown in Figure 17.14.

![Figure 17.14](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-14.png)

Figure 17.14

As we can see, both images have been scanned, `v1` is clean and has no known vulnerabilities, but `v2` has 3 majors.

We’ll create two policies on the `base` repo so that images with a clean bill-of-health are promoted to the `good` repo, and images with known vulnerabilities are promoted to the `bad` repo.

Perform all of the following actions on the `base` repo.

1.  Click the `Policies` tab and make sure that `Is source` is selected.
2.  Click `New promotion policy`.
3.  Under “PROMOTE TO TARGET IF…” select `All Vulnerabilities` and create a policy for `equals 0`.![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-15.png)

    This will create a policy that acts on all images with zero vulnerabilities.

    Don’t forget to click `Add` before moving to the next step.

4.  Select the `TARGET REPOSITORY` as `technology/good` and hit `Save & Apply`.

    Clicking `Save` will apply the policy to the repo and enforce it for all new images pushed the repo, but it will not affect images already in the repo. `Save & Apply` will do the same, **but also for images already in the repo**.

    If you click `Save & Apply`, the policy will immediately evaluate all images in the repo and promote those that are clean. This means the `v1` image will be promoted to the `technology/good` repo.

5.  Inspect the `technology/good` repo.

    As you can see in Figure 17.16, the `v1` image has been promoted and is showing in the UI as `PROMOTED`.

    ![Figure 17.16](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-16.png)

    Figure 17.16

The promotion policy is working. Let’s create another one to *promote* images that do have vulnerabilities to the `technology/bad` repo.

Perform all of the following from the `technology/base` repo.

1.  Create another new promotion policy.
2.  Create a policy criteria for All Vulnerabilities > 0 and click `Add`.![Figure 17.17](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-17.png)

    Figure 17.17

3.  Add the target repo as `technology/bad`, and add “-dirty” to the `TAG NAME IN TARGET` box so that it is now “%n-dirty”. This last bit will re-tag the image as part of the promotion.
4.  Click `Save & Apply`.
5.  Check the `technology/bad` repo to confirm that the policy is enforcing and the `v2` image has been promoted and re-tagged.![Figure 17.18](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-18.png)

    Figure 17.18

Now that images are being promoted to the `technology/good` repo if they have no vulnerabilities, it might be a good idea to make the repo immutable. This will prevent images from being overwritten and deleted.

1.  Navigate to the `technology/good` repo and click the `Settings` tab.
2.  Set `IMMUTABILITY` to `On` and click `Save`.
3.  Try and delete the image.

    You’ll get the following error.

    ![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-19.png)

Time for one last feature!

#### HTTP Routing Mesh (HRM)

Docker Swarm features a layer-4 routing mesh called the Swarm Routing Mesh. This exposes Swarm services on all nodes in the cluster and balances incoming traffic across service replicas. The end results is a moderately even balance of traffic to all service replicas. However, it has no application intelligence. For example, it cannot route based on data at layer 7 in the HTTP headers. To overcome this, UCP implements a layer-7 routing mesh called the HTTP Routing Mesh, or HRM for short. This builds on top of the Swarm Routing Mesh.

The HRM allows multiple Swarm services to be published on the same Swarm-wide port, with ingress traffic being routed to the right service based on hostname data stored in the HTTP headers of incoming requests.

Figure 17.20 shows a simple two-service example.

![Figure 17.20](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-20.png)

Figure 17.20

In the picture, the laptop client is making an HTTP request to `mustang.internal` on TCP port 80\. The UCP cluster has two services that are both listening on port 80\. The `mustang` service is published on port 80 and configured to receive traffic intended for the `mustang.internal` hostname. The `camero` service is also published on port 80, but is configured to receive traffic coming in to `camero.internal`.

There is a third service called HRM that maintains the mapping between hostnames and UCP services. It is the HRM that receives incoming traffic on port 80, inspects the HTTP headers and makes the decision of which service to route it to.

Let’s walk through an example, then explain a bit more detail when we’re done.

We’ll build the example shown in Figure 17.20\. The process will be as follows: Enable the HRM on port 80\. Deploy a *service* called “mustang” using the `nigelpoulton/dockerbook:mustang` image and create a hostname route for the mustang service so that requests to “mustang.internal” get routed to it. Deploy a second service called “camero” based on the `nigelpoulton/dockerbook:camero` image and create a hostname route for this one that maps it to requests for “camero.internal”.

You can use publicly resolvable DNS names such as mustang.mycompany.com, all that is required is that you have name resolution configured so that requests to those addresses resolve to the load balancer in front of your UCP cluster. IF you don’t have a load balancer, you can point traffic to the IP of any node in the cluster.

Let’s see it.

1.  If you aren’t already, log on to the UCP web UI.
2.  Navigate to `Admin` > `Admin Settings` > `Routing Mesh`.
3.  Tick the `Enable Routing Mesh` tickbox and make sure that the `HTTP Port` is configured to `80`.
4.  Click `Save`.

That’s the UCP cluster configured to use the HRM. Behind the scenes this has deployed a new *system service* called `ucp-hrm`, and a new overlay network called `ucp-hrm`.

If you inspect the `ucp-hrm` system service, you’ll see that it’s publishing port `80` in *ingress mode*. This means the `ucp-hrm` is deployed on the cluster and bound to port `80` on all nodes in the cluster. This means **all traffic** coming into the cluster on port 80 will be handled by this service. When the `mustang` and `camero` services are deployed, the `ucp-hrm` service will be updated with hostname mappings so that it knows how to route traffic to those services.

Now that the HRM is deployed, it’s time to deploy our services.

1.  Select `Services` in the left navigation pane and click `Create Service`.
2.  Deploy the “mustang” service as follows:
    *   **Details/Name:** mustang
    *   **Details/Image:** nigelpoulton/dockerbook:mustang
    *   **Network/Ports/Publish Port:** Click the option to `Publish Port +`
    *   **Network/Ports/Internal Port:** 8080
    *   **Network/Ports/Add Hostname Based Routes:** Click on the option to add a hostname based route
    *   **Network/Ports/External Scheme:** Http://
    *   **Network/Ports/Routing Mesh Host:** mustang.internal
    *   **Network/Ports/Networks:** Make sure that the service is attached to the `ucp-hrm` network
3.  Click `Create` to deploy the service.
4.  Deploy the “camero” service.

    Deploy this service with the same settings as the “mustang” service, but with the following differences:

    *   **Details/Name:** camero
    *   **Details/Image:** nigelpoulton/dockerbook:camero
    *   **Network/Ports/Routing Mesh Host:** camero.internal
5.  Click `Create`.

It’ll take a few seconds for each service to deploy, but when they’re done, you’ll be able to point a web browser at `mustang.internal` and reach the mustang service, and `camero.internal` and reach the camero service.

> **Note:** You will obviously need name resolution configured so that `mustang.internal` and `camero.internal` resolve to your UCP cluster. This can be to a load balancer sitting in front of your cluster forwarding traffic to the cluster on port 80, or you’re in a lab without a load balancer, it can be a simple local `hosts` file resolving the DNS names to the IP address of a cluster node.

Figure 17.21 shows the mustang service being reached via `mustang.internal`.

![Figure 17.21](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-21.png)

Figure 17.21

Let’s remind ourselves of how this works.

The HTTP Routing Mesh is a Docker UCP feature that builds on top of the transport layer Swarm Routing Mesh. Specifically, the HRM adds application layer intelligence in the form of hostname rules.

Enabling the HRM deploys a new UCP *system service* called `ucp-hrm`. This service is published *swarm-wide* on port 80 and 8443\. This means that all traffic arriving at the cluster on either of those ports will be sent to the `ucp-hrm` service. This puts the `ucp-hrm` service in a position to receive, inspect, and route all traffic entering the cluster on those ports.

We then deployed two *user services*. As part of deploying each service, we created a hostname mapping that was added to the `ucp-hrm` service. The “mustang” service created a mapping so that it would receive all traffic arriving on the cluster on port 80 with “mustang.internal” in the HTTP header. The “camero” service did the same thing for traffic arriving on port 80 with “camero.internal” in the HTTP header. This resulted in the `ucp-hrm` service having two entries effectively saying the following:

*   All traffic arriving on port 80 for “mustang.internal” gets sent to the “mustang” service.
*   All traffic arriving on port 80 for “camero.internal” gets sent to the “camero” service.

Let’s show Figure 17.20 again.

![Figure 17.20](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure17-20.png)

Figure 17.20

Hopefully this should be clear now!

### Chapter Summary

UCP and DTR join forces to provide a great suit of features that are valuable to most enterprise organizations.

Strong role-based access control is a fundamental part of UCP, with the ability be extremely granular with permissions – down to individual API operations. Integration with Active Directory and other corporate LDAP solutions is also supported.

Docker Content Trust (DCT) brings cryptographic guarantees to image-based operations. These include `push`, `pull`, `build`, and `run`. When DCT is enabled, all images pushed to remote repos are signed, and all images pulled are verified. This gives you cryptographic certainty that the image you get is the one you asked for. UCP can be configured to enforce a cluster-wide policy requiring all images to be signed.

DTR can be configured to use self-signed certificates, or certificates from trusted 3rd-party CAs. You can configure it to perform binary-level image scans that identify known vulnerabilities. And you can configure policies to automate the promotion of images through your build pipelines.

Finally, we looked at the HTTP Routing mesh that performs application layer routing based on hostnames in HTTP headers.````````````
