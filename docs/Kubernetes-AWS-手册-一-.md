# Kubernetes AWS 手册（一）

> 原文：[`zh.annas-archive.org/md5/9CADC322D770A4D3AD0027E7CB5CC592`](https://zh.annas-archive.org/md5/9CADC322D770A4D3AD0027E7CB5CC592)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Docker 容器承诺彻底改变开发人员和运维在云上构建、部署和管理应用程序的方式。Kubernetes 提供了您在生产环境中实现这一承诺所需的编排工具。

《Kubernetes on AWS》指导您在**Amazon Web Services**（**AWS**）平台上部署一个生产就绪的 Kubernetes 集群。您将了解如何使用 Kubernetes 的强大功能，它是最快增长的生产容器编排平台之一，用于管理和更新您的应用程序。Kubernetes 正在成为云原生应用程序生产级部署的首选。本书从最基本的原理开始介绍 Kubernetes。您将首先学习 Kubernetes 的强大抽象——pod 和 service，这使得管理容器部署变得容易。接着，您将通过在 AWS 上设置一个生产就绪的 Kubernetes 集群的指导之旅，同时学习成功部署和管理自己应用程序的技术。

通过本书，您将在 AWS 上获得丰富的 Kubernetes 实践经验。您还将学习到一些关于部署和管理应用程序、保持集群和应用程序安全以及确保整个系统可靠且具有容错性的技巧。

# 本书适合对象

如果您是云工程师、云解决方案提供商、系统管理员、网站可靠性工程师或对 DevOps 感兴趣的开发人员，并且希望了解在 AWS 环境中运行 Kubernetes 的详尽指南，那么本书适合您。虽然不需要对 Kubernetes 有任何先前的了解，但具有 Linux 和 Docker 容器的一些经验将是一个优势。

# 本书涵盖内容

第一章，*Google 的基础设施适用于我们其余人*，帮助您了解 Kubernetes 如何为您提供谷歌的可靠性工程师使用的一些超能力，以确保谷歌的服务具有容错性、可靠性和高效性。

第二章，*启动引擎*，帮助您开始使用 Kubernetes。您将学习如何在自己的工作站上启动适用于学习和开发的集群，并开始学习如何使用 Kubernetes 本身。

第三章，《触及云端》，教您如何从头开始构建在 AWS 上运行的 Kubernetes 集群。

第四章，《管理应用程序中的更改》，深入探讨了 Kubernetes 提供的工具，用于管理在集群上运行的 Pod。

第五章，《使用 Helm 管理复杂应用程序》，教您如何使用社区维护的图表将服务部署到您的集群。

第六章，《生产规划》，让您了解在决定在生产环境中运行 Kubernetes 时可以做出的多种不同选择和决策。

第七章，《生产就绪集群》，帮助您构建一个完全功能的集群，这将作为一个基本配置，用于许多不同的用例。

第八章，《抱歉，我的应用程序吃掉了集群》，深入探讨了使用不同的服务质量配置 Pod，以便重要的工作负载能够保证它们所需的资源，但不太重要的工作负载可以在有空闲资源时利用专用资源而无需专门的资源。

第九章，《存储状态》，全都是关于使用 Kubernetes 与 AWS 原生存储解决方案弹性块存储（EBS）的深度集成。

第十章，《管理容器镜像》，帮助您了解如何利用 AWS 弹性容器注册表（ECR）服务以满足所有这些需求存储您的容器镜像。

第十一章，《监控和日志记录》，教您如何设置日志管理管道，并将帮助您了解日志的一些潜在问题和潜在问题。到本章结束时，您将已经设置了一个指标和警报系统。有关本章，请参阅[`www.packtpub.com/sites/default/files/downloads/Monitoring_and_Logging.pdf`](https://www.packtpub.com/sites/default/files/downloads/Monitoring_and_Logging.pdf)。

[第十二章](https://www.packtpub.com/sites/default/files/downloads/Best_Practices_of_Security.pdf)，*安全最佳实践*，教您如何使用 AWS 和 Kubernetes 网络原语管理 Kubernetes 集群的安全网络。 您还将学习如何保护您的主机操作系统。 有关本章，请参阅[`www.packtpub.com/sites/default/files/downloads/Best_Practices_of_Security.pdf`](https://www.packtpub.com/sites/default/files/downloads/Best_Practices_of_Security.pdf)。

# 为了充分利用本书

您需要访问 AWS 帐户以执行本书中给出的示例。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。 如果您在其他地方购买了本书，可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Kubernetes-on-AWS`](https://github.com/PacktPublishing/Kubernetes-on-AWS)。 如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。 快去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。 例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下方式编写：

```
$ mkdir css
$ cd css
```

**粗体**：表示一个新术语，一个重要词或者屏幕上看到的词。例如，菜单或对话框中的词会在文本中显示为这样。这是一个例子：“从管理面板中选择系统信息。”

警告或重要提示会显示为这样。提示和技巧会显示为这样。


# 第一章：谷歌的基础设施服务于我们其他人

Kubernetes 最初是由谷歌的一些工程师构建的，他们负责谷歌内部的容器调度器 Borg。

学习如何使用 Kubernetes 运行自己的基础设施可以让你拥有一些谷歌的可靠性工程师利用的超能力，以确保谷歌的服务具有弹性、可靠和高效。使用 Kubernetes 可以让你利用谷歌和其他公司工程师通过其大规模积累的知识和专业技能。

你的组织可能永远不需要像谷歌这样的公司那样运营。然而，你会发现，许多在操作数万台机器的公司中开发的工具和技术对于运行规模小得多的组织也是适用的。

虽然一个小团队显然可以手动配置和操作数十台机器，但在更大规模上需要的自动化可以让你的生活更简单，你的软件更可靠。如果以后需要从数十台机器扩展到数百甚至数千台，你会知道你正在使用的工具已经在最恶劣的环境中经过了考验。

Kubernetes 的存在本身就是开源/自由软件运动成功的衡量标准和证明。Kubernetes 最初是一个项目，旨在开源谷歌内部容器编排系统 Borg 背后的思想和研究成果。现在它已经有了自己的生命，大部分代码现在都是由谷歌以外的工程师贡献的。

Kubernetes 的故事不仅仅是谷歌看到开源自己的知识间接地为自己的云业务带来好处，而且也是各种基础工具的开源实现成熟的故事。

Linux 容器在某种形式上已经存在了将近十年，但直到 Docker 项目（2013 年首次开源）使它们成为足够多用户广泛使用和理解。虽然 Docker 本身并没有为底层技术带来任何新的东西，但它的创新在于将已经存在的工具打包成一个简单易用的界面。

Kubernetes 也得益于 etcd 的存在，这是一个基于 Raft 一致性算法的键值存储，也是在 2013 年首次发布，用于构建 CoreOS 正在开发的另一个集群调度工具的基础。对于 Borg，Google 使用了基于非常相似的 Paxos 算法的底层状态存储，使 etcd 成为 Kubernetes 的完美选择。

谷歌准备采取主动措施，创建一个开源实现这些知识的项目，这在那个时候对于他们的工程组织来说是一个巨大的竞争优势，因为 Linux 容器由于 Docker 的影响开始变得更加流行。

Kubernetes、Docker、etcd 和许多其他构成 Linux 容器生态系统的工具都是用 Go 编程语言编写的。Go 提供了构建这些系统所需的所有功能，具有出色的并发支持和内置的优秀网络库。

然而，在我看来，语言本身的简单性使其成为开源基础设施工具的绝佳选择，因为如此广泛的开发人员可以在几个小时内掌握语言的基础知识，并开始对项目做出有生产力的贡献。

如果您对了解 Go 编程语言感兴趣，可以尝试查看[`tour.golang.org/welcome/1`](https://tour.golang.org/welcome/1)，然后花一个小时查看[`gobyexample.com`](https://gobyexample.com)。

# 我为什么需要一个 Kubernetes 集群？

Kubernetes 的核心是一个容器调度器，但它是一个更丰富和功能齐全的工具包，具有许多其他功能。可以扩展和增强 Kubernetes 提供的功能，就像 RedHat 的 OpenShift 产品所做的那样。Kubernetes 还允许您通过部署附加工具和服务到您的集群来扩展其核心功能。

以下是内置在 Kubernetes 中的一些关键功能：

+   **自愈**: Kubernetes 基于控制器的编排确保容器在失败时重新启动，并在它们所在的节点失败时重新调度。用户定义的健康检查允许用户决定如何以及何时从失败的服务中恢复，以及在这样做时如何引导流量。

+   **服务发现**：Kubernetes 从根本上设计为使服务发现变得简单，而无需对应用程序进行修改。您的应用程序的每个实例都有自己的 IP 地址，标准的发现机制，如 DNS 和负载均衡，让您的服务进行通信。

+   **扩展**：Kubernetes 可以通过按一下按钮实现水平扩展，并提供自动扩展功能。

+   **部署编排**：Kubernetes 不仅帮助您管理运行的应用程序，还具有工具来推出对应用程序及其配置的更改。其灵活性使您可以为自己构建复杂的部署模式，或者使用多个附加工具之一。

+   **存储管理**：Kubernetes 内置支持管理云提供商的底层存储技术，如 AWS Elastic Block Store 卷，以及其他标准的网络存储工具，如 NFS。

+   **集群优化**：Kubernetes 调度程序会根据工作负载的需求自动将其分配到机器上，从而更好地利用资源。

+   **批量工作负载**：除了长时间运行的工作负载，Kubernetes 还可以管理批处理作业，如 CI、批处理处理和定期作业。

# 容器的根源

询问普通用户 Docker 容器是什么，您可能会得到十几种回答之一。您可能会听到有关轻量级虚拟机的内容，或者这种炙手可热的新颠覆性技术将如何革新计算。实际上，Linux 容器绝对不是一个新概念，也并不像虚拟机那样。

1979 年，Unix 的第 7 版中添加了`chroot syscall`。调用 chroot 会改变当前运行进程及其子进程的根目录。在所谓的 chroot 监狱中运行程序可以防止其访问指定目录树之外的文件。

chroot 的最初用途之一是用于测试 BSD 构建系统，这是大多数现代 Linux 发行版的软件包构建系统所继承的。通过在干净的 chroot 环境中测试软件包，构建脚本可以检测到缺少的依赖信息。

Chroot 也常用于沙箱化不受信任的进程-例如，在共享 FTP 或 SFTP 服务器上的 shell 进程。专门考虑安全性的系统，例如 Postfix 邮件传输代理，利用 chroot 来隔离管道的各个组件，以防止一个组件的安全问题在系统中蔓延。

Chroot 实际上是一个非常简单的隔离工具，它从未旨在提供对文件系统访问以外的任何安全性或控制。对于提供类似构建工具的文件系统隔离的预期目的来说，它是完美的。但是对于在生产环境中隔离应用程序，我们需要更多的控制。

# 进入容器

试图理解 Linux 容器是什么可能有点困难。就 Linux 内核而言，根本不存在容器这样的东西。内核具有许多功能，允许对进程进行隔离，但这些功能比我们现在所认为的容器要低级和细粒度得多。诸如 Docker 之类的容器引擎使用两个主要的内核特性来隔离进程：

# Cgroups

**Cgroups**，或者控制组，提供了一个控制一个或一组进程的接口，因此得名。它们允许控制组的资源使用的几个方面。资源利用可以通过限制（例如，限制内存使用）来控制。Cgroups 还允许设置优先级，以便为进程提供更多或更少的时间限制资源，例如 CPU 利用率或 I/O。Cgroups 还可以用于快照（和恢复）运行进程的状态。

# 命名空间

容器隔离的另一部分是内核命名空间。它们的操作方式与我们使用 chroot 系统调用的方式有些相似，即容器引擎指示内核仅允许进程查看系统资源的特定视图。

与仅限制对文件系统内核的访问不同，命名空间限制对许多不同资源的访问。

每个进程可以分配到一个命名空间，然后只能看到与该命名空间连接的资源。可以命名空间化的资源类型如下：

+   **挂载**：挂载命名空间控制对文件系统的访问。

+   **用户**：每个命名空间都有自己的用户 ID 集。用户 ID 命名空间是嵌套的，因此高级命名空间中的用户可以映射到低级命名空间中的另一个用户。这就允许容器以 root 身份运行进程，而不会给予该进程对根系统的完全权限。

+   **PID**：进程 ID 命名空间与用户命名空间一样是嵌套的。这就是为什么主机可以在运行容器的系统上检查进程列表时看到容器内运行的进程。然而，在命名空间内部，数字是不同的；这意味着在 PID 命名空间内创建的第一个进程可以被分配为 PID 1，并且可以继承僵尸进程（如果需要）。

+   **网络**：网络命名空间包含一个或多个网络接口。该命名空间拥有自己的私有网络资源，如地址、路由表和防火墙。

还有用于 IPC、UTS 和 Cgroups 接口本身的命名空间。

# 将这些部分组合在一起

容器引擎（如 Docker 或 rkt 等软件）的工作是将这些部分组合在一起，为我们这些凡人创造出可用和可理解的东西。

虽然一个直接暴露 Cgroups 和命名空间所有细节的系统会非常灵活，但理解和管理起来会更加困难。使用诸如 Docker 之类的系统为我们提供了一个简单易懂的抽象，但必然会为我们做出许多关于这些低级概念如何使用的决定。

Docker 在先前的容器技术上取得的根本突破是采用了良好的默认设置来隔离单个进程，并将它们与允许开发人员提供进程运行所需的所有依赖项的镜像格式相结合。

这是非常好的一件事，因为它允许任何人安装 Docker 并快速理解发生了什么。它还使得这种 Linux 容器成为构建更大更复杂系统（如 Kubernetes）的完美基石。

# 在这里，安排一下...

在其核心，Kubernetes 是一个将工作调度到一组计算机的系统——一个调度器。但是为什么你需要一个调度器呢？

如果你考虑一下你自己的系统，你会意识到你可能已经有了一个调度器，但除非你已经在使用类似 Kubernetes 的东西，否则它可能看起来会非常不同。

也许你的调度程序是一个团队，有关于数据中心每台服务器上运行的服务的电子表格和文档。也许这个团队会查看过去的流量统计数据，试图猜测未来会有重负载的时间。也许你的调度程序依赖于用户在任何时间通知团队成员，如果你的应用程序停止运行。

这本书讨论了这些问题，讨论了我们如何摆脱手动流程和对系统未来使用的猜测。它是关于利用管理系统的人类的技能和经验，将我们的运营知识编码到可以每秒做出关于你的运行系统的决策的系统中，无缝地响应崩溃的进程、失败的机器和增加的负载，而无需任何人为干预。

Kubernetes 选择将其调度程序建模为控制循环，以便系统不断发现集群的当前状态，将其与期望状态进行比较，然后采取行动来减少期望状态和实际状态之间的差异。这在以下图表中总结如下：

典型的控制循环

能够声明我们希望系统处于的状态，然后让系统自己采取必要的行动来实现这种期望状态，是非常强大的。

您以前可能使用了一种命令式工具或脚本来管理系统，甚至可能使用了手动步骤的书面操作手册。这种方法非常像食谱：你一步一步地采取一系列行动，希望最终达到你所期望的状态。

当描述如何首次安装和引导系统时，这种方法效果很好，但当你需要运行你的脚本来管理已经运行的系统时，你的逻辑需要变得更加复杂，因为对于食谱中的每个阶段，你都需要停下来检查在执行之前需要做什么。

当使用像 Kubernetes 这样的声明性工具来管理系统时，你的配置变得简化，更容易理解。这种方法的一个重要副作用是，如果底层故障导致配置偏离你的期望状态，Kubernetes 将修复你的配置。

通过结合控制循环和声明性配置，Kubernetes 允许您告诉它为您做什么，而不是如何做。Kubernetes 赋予您，操作者，建筑师的角色，而 Kubernetes 则扮演建造者的角色。建筑师向建造者提供了详细的建筑计划，但不需要解释如何用砖和灰浆建造墙壁。您的责任是向 Kubernetes 提供应用程序的规范和所需的资源，但您不需要担心它将在哪里以及如何运行的细节。

# Kubernetes 的基础知识

让我们开始了解 Kubernetes，首先看一些大部分 Kubernetes 建立在其上的基本概念。清楚地了解这些核心构建块如何组合在一起将有助于我们探索组成 Kubernetes 的多种功能和工具。

如果您没有对 Kubernetes 有任何经验，那么在没有清楚理解这些核心构建块的情况下使用 Kubernetes 可能会有点困惑，因此，在继续之前，您应该花时间了解这些部分如何组合在一起。

# Pod

像一群鲸鱼，或者也许是豌豆荚一样，Kubernetes pod 是一组链接的容器。如下图所示，一个 pod 可以由一个或多个容器组成；通常一个 pod 可能只是一个单一的容器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/5ab14adc-a52d-4bfe-9609-b60fc3a2d288.png)Pods 是一个或多个容器的逻辑分组

Kubernetes 调度的每个 pod 都被分配了独特的 IP 地址。网络命名空间（因此 pod 的 IP 地址）被每个 pod 中的每个容器共享。

这意味着方便地一起部署几个密切协作的容器。例如，您可以部署一个反向代理与 Web 应用程序一起，以为不本地支持它们的应用程序添加 SSL 或缓存功能。在下面的示例中，我们通过部署一个典型的 Web 应用程序服务器-例如 Ruby on Rails-以及一个反向代理-例如 NGINX 来实现这一点。这个额外的容器提供了可能不被原生应用程序提供的进一步功能。将功能从较小的隔离容器中组合在一起的这种模式意味着您能够更容易地重用组件，并且可以简单地向现有工具添加额外的功能。设置如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/4efcf9ca-12d3-4882-8570-fa432e46e81d.png)通过组合多个容器提供额外的功能

除了共享网络命名空间外，Kubernetes 还允许在一个 pod 中的任意数量的容器之间非常灵活地共享卷挂载。这允许出现多种情况，其中几个组件可以协作执行特定任务。

在这个例子中，我们使用了三个容器来协调为使用 NGINX web 服务器构建的静态网站提供服务。

第一个容器使用 Git 从远程 Git 存储库中拉取和更新源代码。该存储库被克隆到与第二个容器共享的卷中。第二个容器使用 Jekyll 框架构建将由我们的 web 服务器提供的静态文件。Jekyll 监视文件系统上的共享目录的更改，并重新生成需要更新的任何文件。

Jekyll 写入生成文件的目录与运行 NGINX 的容器共享，用于为我们的网站提供 HTTP 请求，如下图所示：

我们在这里使用 Jekyll 作为例子，但是你可以使用许多工具来构建静态网站，比如 Hugo、Hexo 和 Gatsby。像这样将应用程序拆分成单独的容器意味着很容易升级单个组件，甚至尝试替代工具。![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/850176d8-c5a3-4e36-a6e2-95b84c37c8f2.png)

共享卷挂载的 pod 的另一个用途是支持使用 Unix 套接字进行通信的应用程序，如下图所示。例如，**提取转换加载**（**ETL**）系统可以被建模为使用 UNIX 套接字进行通信的几个独立进程。如果您能够利用第三方工具来处理管道的一部分或全部内容，或者在各种情况下重用您为内部使用构建的工具，这可能是有益的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/821eb4df-720d-48e4-9588-9d1121b9375f.png)

在这个例子中，一个定制的应用程序用于从网页中抓取数据，并通过共享卷中的 Unix 域套接字与 Fluentd 的实例进行通信。使用第三方工具（如 Fluentd）将数据推送到后端数据存储的模式不仅简化了定制工具的实现，还提供了与 Fluentd 选择支持的任何存储兼容的功能。

Kubernetes 为您提供了一些强有力的保证，即 pod 中的容器具有共享的生命周期。这意味着当您启动一个 pod 时，您可以确保每个容器将被调度到同一节点；这很重要，因为这意味着您可以依赖于 pod 中的其他容器将存在并且将是本地的。Pod 通常是将几个不同容器的功能粘合在一起的便捷方式，从而实现常见组件的重用。例如，您可以使用 sidecar 容器来增强应用程序的网络能力，或提供额外的日志管理或监控设施。

# 给所有东西贴标签

**标签**是附加到资源（如 pod）的键值对，旨在包含帮助您识别特定资源的信息。

您可以为您的 pod 添加标签，以标识正在运行的应用程序，以及其他元数据，例如版本号、环境名称或与您的应用程序相关的其他标签。

标签非常灵活，因为 Kubernetes 让您自行决定如何为自己的资源打上标签。

一旦您开始使用 Kubernetes，您将发现几乎可以为您创建的每个资源添加标签。

能够添加反映您自己应用程序架构的标签的强大之处在于，您可以使用选择器使用您为资源指定的任何标签组合来查询资源。这种设置如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/7dc60739-2e11-41fd-b612-8c727f9c35f4.png)

您可以为在 Kubernetes 中创建的许多资源添加标签，然后使用选择器进行查询。

Kubernetes 不强制执行任何特定的模式或布局，用于给集群中的对象打标签；您可以自由地为应用程序打上标签。但是，如果您想要一些结构，Kubernetes 确实对您可能想要应用于可以组合成逻辑应用程序的对象的标签提出了一些建议。您可以在 Kubernetes 文档中阅读更多信息：[`kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/`](https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/)。

# 副本集

在 Kubernetes 中，`ReplicaSet`是一个模板化创建 pod 的资源。副本集的定义包含它创建的 pod 的模板定义，副本的期望数量和用于发现其管理下的 pod 的选择器。

`ReplicaSet`用于确保始终运行所需数量的 pod。如果与选择器匹配的 pod 数量低于所需数量，则 Kubernetes 将安排另一个。

由于 pod 的生命周期与其运行的节点的生命周期相关，pod 可以被视为短暂的。有许多原因可能导致特定 pod 的生命周期结束。也许它被操作员或自动化流程移除了。Kubernetes 可能已经驱逐了 pod 以更好地利用集群的资源或准备节点进行关闭或重启。或者底层节点可能失败了。

`ReplicaSet`允许我们通过要求集群确保整个集群中运行正确数量的副本来管理我们的应用程序。这是 Kubernetes 在其许多 API 中采用的一种策略。

作为集群操作员，Kubernetes 会帮助用户减少运行应用程序的复杂性。当我决定需要运行我的应用程序的三个实例时，我不再需要考虑底层基础设施：我只需告诉 Kubernetes 执行我的愿望。如果最坏的情况发生，我的应用程序正在运行的底层机器之一失败，Kubernetes 将知道如何自我修复我的应用程序并启动一个新的 pod。不再需要寻呼机的呼叫，也不需要在半夜里尝试恢复或替换失败的实例。

`ReplicaSet`取代了您可能在旧教程和文档中了解过的`ReplicationController`。它们几乎完全相同，但在一些细微的方面有所不同。

通常，我们希望更新集群上运行的软件。因此，我们通常不直接使用`ReplicaSet`，而是使用`Deployment`对象来管理它们。在 Kubernetes 中，部署用于优雅地推出`ReplicaSet`的新版本。您将在第四章中了解更多关于部署的内容，*管理应用程序的变更*。

# 服务

Kubernetes 为我们管理应用程序提供的最后一个基本工具是服务。**服务**为我们提供了一种方便的方式，在集群内访问我们的服务，通常被称为*服务发现*。

实际上，服务允许我们定义一个标签选择器来引用一组 pod，然后将其映射到我们的应用程序可以使用的内容，而无需修改以查询 Kubernetes API 来收集这些信息。通常，服务将以轮询的方式提供一个稳定的 IP 地址或 DNS 名称，用于访问它所引用的底层 pod。

通过使用服务，我们的应用程序不需要知道它们正在 Kubernetes 上运行-我们只需要正确地配置它们，使用服务的 DNS 名称或 IP 地址。

服务提供了一种让集群中的其他应用程序发现符合特定标签选择器的 pod 的方法。它通过提供一个稳定的 IP 地址，以及可选的 DNS 名称来实现这一点。这个设置如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/f30aead5-832a-4fc8-965c-9e7271233a0b.png)

# 底层

现在我们已经了解了 Kubernetes 为我们提供的功能，让我们深入一点，看看 Kubernetes 用来实现这些功能的组件。Kubernetes 通过具有微服务架构，使我们更容易查看每个组件的功能在一定程度上的隔离。

在接下来的几章中，我们将亲自部署和配置这些组件。但是现在，让我们通过查看以下图表，对每个组件的功能有一个基本的了解：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/45a5297d-7bb6-4df0-be3c-0bcc226b0c1d.png)主节点上的主要 Kubernetes 组件

# API 服务器

**API 服务器**充当 Kubernetes 的中央枢纽。Kubernetes 中的所有其他组件通过读取、监视和更新 Kubernetes API 中的资源来进行通信。这个中央组件用于访问和操作集群当前状态的信息，允许 Kubernetes 在保持高度一致性的同时扩展和增强新功能。 

Kubernetes 使用 etcd 存储集群的当前状态。使用 etcd 存储是因为其设计意味着它既能抵抗故障，又能保证其一致性。然而，组成 Kubernetes 的不同组件从不直接与 etcd 交互；相反，它们与 API 服务器通信。对于我们作为集群的操作者来说，这是一个很好的设计，因为它允许我们将对 etcd 的访问限制在 API 服务器组件，提高安全性并简化管理。

虽然 API 服务器是 Kubernetes 架构中的组件，其他所有组件都与其通信以访问或更新状态，但它本身是无状态的，所有存储都被推迟到后端 etcd 集群。对于我们作为集群操作员来说，这再次是一个理想的设计决策，因为它允许我们部署多个 API 服务器的实例（如果我们希望）以提供高可用性。

# 控制器管理器

控制器管理器是运行实现 Kubernetes 功能的一些核心功能的核心控制循环（或控制器）的服务。这些控制器中的每一个都通过 API 服务器监视集群的状态，然后进行更改，以尝试将集群的状态移动到期望的状态。控制器管理器的设计意味着一次只能运行一个实例；然而，为了简化在高可用配置中的部署，控制器管理器具有内置的领导者选举功能，因此可以并排部署多个实例，但只有一个实际上会在任何时候执行工作。

# 调度器

调度器可能是使 Kubernetes 成为有用和实用工具的最重要的组件。它会监视处于未调度状态的新 pod，然后分析集群的当前状态，包括运行的工作负载、可用资源和其他基于策略的问题。然后决定最适合运行该 pod 的位置。与控制器管理器一样，调度器的单个实例一次只能工作一个，但在高可用配置中，可以进行领导者选举。

# Kubelet

kubelet 是在每个节点上运行的代理，负责启动 pod。它不直接运行容器，而是控制运行时，比如 Docker 或 rkt。通常，kubelet 会监视 API 服务器，以发现已经在其节点上调度的 pod。

kubelet 在`PodSpec`级别操作，因此它只知道如何启动 pod。Kubernetes API 中的任何更高级的概念都是由控制器实现的，最终使用特定配置创建或销毁 pod。

kubelet 还运行一个名为**cadvisor**的工具，它收集有关节点上资源使用情况的指标，并使用节点上运行的每个容器，这些信息可以被 Kubernetes 用来做调度决策。

# 总结

到目前为止，你应该对构建现代容器编排器（如 Kubernetes）的软件栈有基本的了解。

现在你应该理解以下内容：

+   容器是建立在 Linux 内核的更低级特性之上的，比如命名空间和 Cgroups。

+   在 Kubernetes 中，pod 是建立在容器之上的强大抽象。

+   Kubernetes 使用控制循环来构建一个强大的系统，允许操作员以声明方式指定应该运行什么。Kubernetes 会自动采取行动，推动系统朝着这个状态发展。这是 Kubernetes 自我修复特性的来源。

+   Kubernetes 中几乎所有的东西都可以被贴上标签，你应该给你的资源贴上标签，以便更简单地管理它们。

在下一章中，你将通过在工作站上运行一个小集群来获得一些使用 Kubernetes API 的实际经验。


# 第二章：启动你的引擎

在本章中，我们将迈出 Kubernetes 的第一步。您将学习如何在自己的工作站上启动一个适合学习和开发使用的集群，并开始学习如何使用 Kubernetes 本身。在本章中，我们将做以下事情：

+   学习如何安装和使用 Minikube 来运行 Kubernetes

+   构建一个在 Docker 容器中运行的简单应用程序

+   使用 Kubernetes 来运行简单的应用程序

# 您自己的 Kubernetes

**Minikube**是一个工具，可以在您的工作站上轻松运行一个简单的 Kubernetes 集群。它非常有用，因为它允许您在本地测试应用程序和配置，并快速迭代应用程序，而无需访问更大的集群。对于我们的目的来说，它是获得一些实际的 Kubernetes 实践经验的理想工具。安装和配置非常简单，您会发现。

# 安装

您需要一些工具来在您的工作站上运行 Kubernetes：

+   `kubectl`是 Kubernetes 命令行界面。在本书中，您将使用它与 Kubernetes 进行交互。

在 Kubernetes 社区中，没有人同意如何发音`kubectl`。

尝试这些不同的方法并选择您喜欢的：

```
    kube-kuttle
    kube-control
    kube-cee-tee-ell
    kube-cuddle
```

+   `minikube`是一个在本地机器上管理 Kubernetes 的命令。它处理所有困难的事情，所以您可以立即开始使用 Kubernetes。

+   `docker`，`minikube`虚拟机内部运行着 Docker 守护程序，但如果您想直接与其交互，您可能需要在您的工作站上安装 Docker 命令行。

最好与虚拟机一起使用 Minikube，因为像 macOS 和 Windows 这样的平台不本地支持 Linux 容器，即使在 Linux 上，也有助于保持您的环境干净和隔离。根据您的操作系统，您可以使用各种虚拟化工具与`minikube`一起使用：

+   **VirtualBox**：它易于使用，可以安装在 macOS、Windows 和 Linux 上。

+   **VMware Fusion**：这是 macOS 上可用的商业工具。

+   **KVM**：这是一个众所周知的 Linux 虚拟化工具。

+   **xhyve**：这是一个利用 macOS 中的本机虚拟化框架的开源项目。它的性能非常好，但安装和使用可能有点困难。

+   **Hyper-V**：这是 Windows 的本地虚拟化工具。请记住，您可能需要在您的机器上手动启用它并设置其网络。

在本书中，我们将介绍默认选项 VirtualBox，但如果你经常使用 Minikube，你可能想探索一些其他选项，因为如果设置正确，它们可能更高效和可靠。

你可以在[`git.k8s.io/minikube/docs/drivers.md`](https://git.k8s.io/minikube/docs/drivers.md)找到一些关于不同驱动程序的文档。

# macOS

在 Mac 上，安装`minikube`和`kubectl`的最佳方法是使用 Homebrew 软件包管理器。

macOS 的 Homebrew 软件包管理器是安装开发工具的简单方法。你可以在网站上找到如何安装它：[`brew.sh/`](https://brew.sh/)。

1.  首先安装 Kubernetes 命令行客户端`kubectl`：

```
brew install kubernetes-cli
```

1.  接下来，安装`minikube`和`virtualbox`：

```
    brew cask install minikube virtualbox
```

# Linux

在 Linux 上，最简单的安装方法是下载并安装预构建的二进制文件：

1.  你应该下载`minikube`和`kubectl`的二进制文件：

```
    curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
    curl -LO https://dl.k8s.io/v1.10.6/bin/linux/amd64/kubectl  
```

1.  一旦你下载了二进制文件，将它们设置为可执行，并将它们移动到你的路径中的某个位置：

```
    chmod +x minikube kubectl
    sudo mv minikube kubectl /usr/local/bin/
```

在 Linux 上安装 VirtualBox 的方法将取决于你的发行版。

请查看 VirtualBox 网站上的说明：[`www.virtualbox.org/wiki/Linux_Downloads`](https://www.virtualbox.org/wiki/Linux_Downloads)。

# Windows

在 Windows 机器上安装 Minikube 与在 Linux 或 macOS 上一样简单。

首先安装 VirtualBox。

你可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载 VirtualBox 的 Windows 安装程序。

如果你使用 chocolatey 软件包管理器，请执行以下步骤：

1.  安装`minikube`：

```
    C:\> choco install minikube
```

1.  安装`kubectl`：

```
    C:\> choco install kubernetes-cli
```

如果你不使用 chocolatey，你可以手动安装`minikube`和`kubectl`。

1.  在[`storage.googleapis.com/minikube/releases/latest/minikube-windows-amd64.exe`](https://storage.googleapis.com/minikube/releases/latest/minikube-windows-amd64.exe)下载`minikube`并将其重命名为`minikube.exe`。然后将它移动到你路径上的某个位置。下载`kubectl`：[`dl.k8s.io/v1.10.6/bin/windows/amd64/kubectl.exe`](https://dl.k8s.io/v1.10.6/bin/windows/amd64/kubectl.exe)，然后将它移动到你路径上的某个位置。

# 启动 Minikube

一旦你安装好了`minikube`和你选择的虚拟化工具，我们就可以用它来构建和启动本地 Kubernetes 集群。

如果你选择使用`minikube`工具的默认设置，那么做起来就很简单。只需运行：

```
    minikube start  
```

然后，您应该会看到一些输出，类似于以下内容：

```
    Starting local Kubernetes v1.10.0 cluster...
    Starting VM...
    Getting VM IP address...
    Moving files into cluster...
    Setting up certs...
    Connecting to cluster...
    Setting up kubeconfig...
    Starting cluster components...
    Kubectl is now configured to use the cluster.

```

`minikube` start 有许多选项，可用于配置启动的集群。尝试运行`minikube` help start 以找出您可以自定义的内容。

您可能想要设置`--cpus`和/或`--memory`来自定义您的计算机资源用于 Minikube VM 的使用量。

假设一切都如预期那样进行，那就是了；您应该在本地机器上安装并运行了一个集群。

kubectl`配置`文件（默认情况下在`~/.kube/config`中找到）定义了上下文。上下文链接到一个集群和一个用户对象。集群定义了如何。

`minikube start`命令创建了一个指向 Minikube VM 内运行的 API 服务器的`kubectl`上下文，并且正确配置了一个允许访问 Kubernetes 的用户。

当您阅读本书时，您当然会想要添加额外的上下文，以便连接到您可能设置的远程集群。您应该能够通过运行以下命令随时切换回`minikube`上下文，以便使用`minikube`：

```
    kubectl config use-context minikube
```

# 使用 kubectl 的第一步

让我们首先验证`kubectl`是否确实已配置为正确使用您的集群，并且我们可以连接到它：

```
    kubectl version
```

您应该会看到类似于这样的输出：

```
    Client Version: version.Info{Major:"1", Minor:"10", GitVersion:"v1.10.4", GitCommit:"5ca598b4ba5abb89bb773071ce452e33fb66339d", GitTreeState:"clean", BuildDate:"2018-06-18T14:14:00Z", GoVersion:"go1.9.7", Compiler:"gc", Platform:"darwin/amd64"}
    Server Version: version.Info{Major:"1", Minor:"10", GitVersion:"v1.10.0", GitCommit:"fc32d2f3698e36b93322a3465f63a14e9f0eaead", GitTreeState:"clean", BuildDate:"2018-03-26T16:44:10Z", GoVersion:"go1.9.3", Compiler:"gc", Platform:"linux/amd64"}
```

您的输出可能显示略有不同的版本号，但是假设您从客户端和服务器都看到了一个版本号，那么您就可以连接到集群。

如果您看不到服务器版本，或者看到其他错误消息，请跳转到本章的*Minikube 故障排除*部分。

让我们开始使用一些在与集群交互时对我们有用的`kubectl`命令来与集群进行交互。

我们将要探索的第一个命令是`get`命令。这使我们能够列出有关集群上资源的基本信息。在这种情况下，我们正在获取所有节点资源的列表：

```
    kubectl get nodes
    NAME       STATUS    AGE       VERSION
    minikube   Ready    20h       v1.10.0
```

如您所见，在我们的 Minikube 安装中，这并不是很令人兴奋，因为我们只有一个节点。但是在具有许多节点的较大集群上，能够查看有关所有节点（或某些子集）的信息可能非常有用。

下一个命令将允许我们深入研究并查看有关特定资源的更详细信息。尝试运行以下命令来查看您可以发现有关 Minikube VM 的信息：

```
    $ kubectl describe node/minikube
```

随着您在本书中的进展，您将发现能够获取和描述 Kubernetes API 公开的各种资源将成为您的第二天性，无论何时您想要发现集群上发生了什么以及为什么。

在我们继续之前，`kubectl`还有一个技巧可以帮助我们。尝试运行以下命令，以获取集群上可用的每种资源类型的描述和一些示例：

```
    kubectl describe -h
```

# 在集群内构建 Docker 容器

您可能已经在工作站上安装了 Docker，但是当您在应用程序上工作时，将图像构建在托管 Kubernetes 集群的 Minikube VM 内部运行的 Docker 守护程序上可以改善您的工作流程。这意味着您可以跳过将图像推送到 Docker 仓库，然后在 Kubernetes 中使用它们。您只需要构建和标记您的图像，然后在 Kubernetes 资源中按名称引用它们。

如果您的工作站上已经安装了 Docker，那么您应该已经安装了与 Minikube Docker 守护程序交互所需的命令行客户端。如果没有，安装也很容易，可以通过安装适用于您平台的 Docker 软件包，或者如果您只想要命令行工具，可以下载二进制文件并将其复制到您的路径中。

为了正确配置 Docker CLI 与 minikube VM 内部的 Docker 守护进程通信，minikube 提供了一个命令，将返回环境变量以配置客户端：

```
    minikube docker-env
```

在 Mac 或 Linux 上，您可以通过运行正确地将这些变量扩展到当前的 shell 环境中：

```
    eval $(minikube docker-env)
```

尝试运行一些`docker`命令来检查一切是否设置正确：

```
    docker version
```

这应该向您显示在 Minikube VM 内运行的 Docker 版本。您可能会注意到，在 Minikube VM 中运行的 Docker 服务器版本略落后于最新版本的 Docker，因为 Kubernetes 需要一些时间来测试新版本的 Docker，以确保稳定性。

尝试列出正在运行的容器。您应该注意到一个正在运行 Kubernetes 仪表板的容器，以及 Kubernetes 启动的一些其他服务，如`kube-dns`和`addon`管理器：

```
    docker ps
```

# 在 Minikube 上构建和启动一个简单的应用程序

让我们迈出第一步，在我们的本地 minikube 集群上构建一个简单的应用程序并让它运行。

我们需要做的第一件事是为我们的应用程序构建一个容器映像。这样做的最简单方法是创建一个 Dockerfile 并使用 `docker build` 命令。

使用您喜欢的文本编辑器创建一个名为 Dockerfile 的文件，内容如下：

```
Dockerfile 
FROM nginx:alpine 
RUN echo "<h1>Hello World</h1>" > /usr/share/nginx/html/index.html 
```

要构建应用程序，首先确保您的 Docker 客户端指向 Minikube VM 内的 Docker 实例，方法是运行：

```
    eval $(minikube docker-env)
```

然后使用 Docker 构建映像。在这种情况下，我们给映像打了一个标签 `hello`，但您可以使用任何您想要的标签：

```
    docker build -t hello:v1 .
```

Kubectl 有一个 `run` 命令，我们可以使用它快速在 Kubernetes 集群上运行一个 pod。在后台，它创建了一个 Kubernetes 部署资源，确保我们的 `hello` 容器的单个实例在一个 pod 中运行（我们稍后会更多地了解这一点）：

```
    kubectl run hello --image=hello:v1 --image-pull-policy=Never \
    --port=80
```

我们在这里设置 `--image-pull-policy=Never` 是为了确保 Kubernetes 使用我们刚刚构建的本地映像，而不是默认从远程存储库（如 Docker Hub）拉取映像。

我们可以使用 `kubectl get` 来检查我们的容器是否已经正确启动：

```
    $ kubectl get pods
    NAME                     READY     STATUS    RESTARTS   AGE
    hello-2033763697-9g7cm   1/1       Running   0          1m
```

我们的 hello world 应用程序设置起来足够简单，但我们需要一些方法来访问它，以便我们的实验被认为是成功的。我们可以使用 `kubectl expose` 命令来创建一个指向刚刚创建的部署中的 pod 的服务：

```
    kubectl expose deployment/hello --port=80 --type="NodePort" \
    --name=hello 
```

在这种情况下，我们已将服务类型设置为 NodePort，这样 Kubernetes 将在 Minikube VM 上公开一个随机端口，以便我们可以轻松访问我们的服务。在第六章中，*生产规划*，我们将更详细地讨论将应用程序暴露给外部世界的问题。

当您创建一个`NodePort`类型的服务时，Kubernetes 会自动为我们分配一个端口号，以便服务可以在其上公开。在多节点集群中，此端口将在集群中的每个节点上打开。由于我们只有一个节点，因此找出如何访问集群会简单一些。

首先，我们需要发现 Minikube VM 的 IP 地址。幸运的是，我们可以运行一个简单的命令来获取这些信息：

```
    minikube ip
    192.168.99.100
```

很可能当`minikube` VM 在您的机器上启动时，它被分配了一个与我的不同的 IP 地址，所以请记下您自己机器上的 IP 地址。

接下来，为了发现 Kubernetes 已经在哪个端口上公开了我们的服务，让我们在服务上使用 `kubectl get`：

```
    $ kubectl get svc/hello
    NAME      CLUSTER-IP   EXTERNAL-IP   PORT(S)        AGE
    hello     10.0.0.104   <nodes>       80:32286/TCP   26m
```

在这种情况下，您可以看到 Kubernetes 已经将容器上的端口`80`暴露为节点上的端口`32286`。

现在，您应该能够构建一个 URL，在浏览器中访问该应用程序进行测试。在我的情况下，它是`http://192.168.99.100:32286`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/18dfc655-d7c2-4803-a1cf-717c4add609b.png)您应该能够使用浏览器访问您的应用程序

# 刚刚发生了什么？

到目前为止，我们已经成功在 Minikube 实例上构建、运行和暴露了一个单个容器。如果您习惯使用 Docker 执行类似的任务，您可能会注意到，虽然我们所采取的步骤非常简单，但要使一个简单的 hello world 应用程序运行起来还是有一些复杂性的。

很多这些都与工具的范围有关。Docker 提供了一个简单易用的工作流，用于在单个机器上构建和运行单个容器，而 Kubernetes 首先是一个旨在管理多个节点上运行的多个容器的工具。

为了理解 Kubernetes 即使在这个简单的例子中引入的一些复杂性，我们将探索 Kubernetes 在幕后工作以确保我们的应用程序可靠运行的方式。

当我们执行`kubectl run`时，Kubernetes 创建了一种新的资源：部署。部署是一个更高级的抽象，代表我们管理的底层`ReplicaSet`。这样做的好处是，如果我们想对应用程序进行更改，Kubernetes 可以管理向正在运行的应用程序滚动发布新配置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/3d2f8ccd-a232-469c-95bc-7d1a9e1def08.png)我们简单的 Hello 应用程序的架构

当我们执行 kubectl expose 时，Kubernetes 创建了一个带有标签选择器的服务，该选择器与我们引用的部署管理的 pod 匹配。

# 滚动发布更改

部署资源的一个关键功能是管理应用程序的新版本的发布。让我们看一个如何执行这个操作的例子。

首先，让我们更新我们的`Hello World`应用程序的版本 2 的 Dockerfile：

```
Dockerfile 
FROM nginx:alpine 
COPY index.html /usr/share/nginx/html/index.html 
```

您可能已经注意到，我们在版本 1 中使用的 HTML 有点不完整，因此我们在`Dockerfile`中使用`COPY`命令将`index.html`文件复制到我们的容器镜像中。

使用文本编辑器创建一个`index.html`文件，它在视觉上与版本 1 有所区别。我抓住机会添加了一个合适的 DOCTYPE，并且当然，使用 CSS 重新实现了可悲的已经废弃的闪烁标签！由于这不是一本关于网页设计的书，随意进行任何想要的更改：

```
index.html 
<!DOCTYPE html> 
<html> 
  <head> 
    <style> 
      blink { animation: blink 1s steps(1) infinite; } 
      @keyframes blink { 50% { color: transparent; } } 
    </style> 
    <title>Hello World</title> 
  </head> 
  <body> 
    <h1>Hello <blink>1994</blink></h1> 
  </body> 
</html> 
```

接下来，使用 Docker 构建您的第 2 版镜像：

```
    docker build -t hello:v2 .
```

现在我们可以使用 kubectl 来更新部署资源以使用新的镜像：

```
    kubectl set image deployment/hello hello=hello:v2
```

等待几分钟，直到 Kubernetes 启动新的 pod，然后刷新您的浏览器；您应该能看到您的更改。

当我们更新一个部署时，Kubernetes 在幕后创建一个新的副本集，具有新的配置，并处理新版本的滚动部署。Kubernetes 还会跟踪您部署的不同配置。这也使您有能力在需要时回滚部署：

```
    $ kubectl rollout undo deployment/hello
    deployment "hello" rolled back
```

# 弹性和扩展性

能够提供对底层基础设施中的错误和问题具有弹性的服务是我们可能希望使用 Kubernetes 部署我们的容器化应用程序的关键原因之一。

我们将通过我们的`Hello World`部署来进行实验，以发现 Kubernetes 如何处理这些问题。

第一个实验是看当我们故意删除包含我们的`hello`容器的 pod 时会发生什么。

为了做到这一点，我们需要找到这个 pod 的名称，我们可以使用`kubectl get`命令来做到这一点：

```
    $ kubectl get pods
    NAME                     READY     STATUS    RESTARTS   AGE
    hello-2473888519-jc6km   1/1       Running   0          7m
```

在我们的 Minikube 集群中，目前只有一个来自我们迄今为止创建的一个部署的运行中的 pod。一旦开始部署更多的应用程序，诸如 kubectl get 之类的命令的输出就会变得更长。我们可以使用`-l`标志传递一个标签选择器来过滤结果。在这种情况下，我们将使用`kubectl get pods -l run=hello`来仅显示标签设置为`hello`的 pod。

然后我们可以使用`kubectl delete`命令来删除资源。删除一个 pod 也会终止其中的容器内运行的进程，有效地清理了我们节点上的 Docker 环境：

```
    $ kubectl delete pod/hello-2473888519-jc6km
    pod "hello-2473888519-jc6km" delete
```

如果然后重新运行`get pods`命令，您应该注意到我们删除的 pod 已被一个新的带有新名称的 pod 所取代：

```
    $ kubectl get pod
    NAME                     READY     STATUS    RESTARTS   AGE
    hello-2473888519-1d69q   1/1       Running   0          8s
```

在 Kubernetes 中，我们可以使用副本集（和部署）来确保尽管出现意外事件，例如服务器故障或管理员误删 pod（就像在这种情况下发生的那样），但 pod 实例仍然在我们的集群中运行。

你应该开始理解作为这个练习的一部分，pod 是一个短暂的实体。当它被删除或者它所在的节点失败时，它将永远消失。Kubernetes 确保缺失的 pod 被另一个替换，从相同的模板中创建。这意味着当 pod 不可避免地失败并被替换时，存储在本地文件系统或内存中的任何状态，pod 本身的身份也会丢失。

这使得 pod 非常适合一些工作负载，不需要在运行之间在本地存储状态，比如 Web 应用程序和大多数批处理作业。如果你正在构建打算部署到 Kubernetes 的新应用程序，通过将状态的存储委托给外部存储，比如数据库或像 Amazon S3 这样的服务，可以使它们更易于管理。

我们将在 Kubernetes 中探索允许我们部署需要存储本地状态和/或保持稳定身份的应用程序的功能，在*第九章*，*存储状态*中。

当我们测试 Kubernetes 替换被移除的 pod 的能力时，你可能已经注意到一个问题，那就是在短时间内，我们的服务变得不可用。对于这样一个简单的单节点集群上运行的示例服务，也许这并不是世界末日。但我们确实需要一种方式，让我们的应用程序以最小化甚至瞬间的停机时间运行。

答案当然是要求 Kubernetes 运行多个实例来运行我们的应用程序，因此即使一个丢失了，第二个也可以接管工作：

```
    $ kubectl scale deployment/hello --replicas=2
    deployment "hello" scaled
```

如果我们现在检查正在运行的 pod，我们可以看到第二个`hello` pod 已经加入了：

```
    $ kubectl get pods
    NAME                     READY     STATUS    RESTARTS   AGE
    hello-2473888519-10p63   1/1       Running   0          1m
    hello-2473888519-1d69q   1/1       Running   0          25m
```

# 使用仪表板

Kubernetes 仪表板是一个在 Kubernetes 集群内运行的 Web 应用程序，提供了一个替代的、更具图形化的解决方案，用于探索和监视你的集群。

Minikube 会自动安装仪表板，并提供一个命令，可以在你的 Web 浏览器中打开它：

```
    $ minikube dashboard
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/97e3c655-3fae-45db-a3ab-1ce32c32e713.png)Kubernetes 仪表板

仪表板界面非常易于使用，你应该开始注意到与`kubectl`工作方式有更多相似之处，因为它们都允许你与相同的底层 API 进行交互。

屏幕左侧的导航栏可访问显示特定类型资源列表的屏幕。这类似于`kubectl get`命令提供的功能：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/5817fc35-e344-49e5-96d8-44d5a6a6e8a4.png)使用 Kubernetes 仪表板列出当前运行的 pod

在此视图中，我们可以单击看起来像一叠文件的图标，以打开日志查看器，查看从每个容器的标准输出中捕获的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/5422944e-406e-47ce-a0db-88ded575e70b.png)在 Kubernetes 仪表板中查看容器日志

其他资源具有适合其功能的其他选项。例如，部署和副本集具有对话框，用于增加或减少 pod 的数量。

通过单击特定资源的名称，我们可以获得一个显示类似于`kubectl describe`的信息的视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/cc0795df-1269-417a-81b1-5fa11a837d58.png)

详细屏幕为我们提供了关于 Kubernetes 中的 pod 或其他资源的大量信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/b5830e05-da58-41a8-a5bf-7835b8866d94.png)

除了资源的配置和设置概览外，如果您滚动到页面底部，您应该能够看到事件的反馈。如果您正在尝试调试问题，这非常有用，并且将突出显示正在运行的资源的任何错误或问题。

对于 pod，我们有许多其他选项来管理和检查容器。例如，通过单击执行按钮在浏览器中打开终端：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/a65495f4-3642-45ed-b80d-ef456c7014b3.png)在 Kubernetes 仪表板中使用交互式 shell 调试容器

目前，为了使此功能正常工作，您的容器需要有`/bin/bash`可用。这在未来版本的仪表板中可能会发生变化，但目前，为了使其工作，请将`RUN apk add --no-cache bash`添加到您的`Dockerfile`并部署新构建的映像。

# 代码配置

在本章中，我们通过使用`kubectl`提供的命令或 Kubernetes 仪表板与 Kubernetes 进行交互。在实践中，我发现这些工具对于快速在集群中运行容器非常有用。当配置变得更加复杂或者我想要能够将相同的应用程序部署到多个环境时，拥有一个可以提交到集群并存储在版本控制系统中的配置文件非常有用。

`kubectl`，实际上包括 Kubernetes 仪表板，将允许我们提交 YAML 或 JSON 格式的配置以创建集群上的资源。我们将再次看看如何使用 YAML 格式的文件而不是`kubectl run`等命令来部署相同的`Hello World`应用程序。

这个 Kubernetes 配置通常被称为清单，而 YAML 或 JSON 格式的文件被称为清单文件。

让我们首先删除我们用`kubectl`创建的配置，这样我们就有一个干净的状态来复制相同的配置：

```
    $ kubectl delete deployment/hello svc/hello
    deployment "hello" deleted
    service "hello" deleted
```

让我们为`hello`服务的版本 1 定义一个部署：

```
deployment.yaml 
apiVersion: apps/v1
kind: Deployment 
metadata: 
  name: hello 
spec: 
  replicas: 2 
  template: 
    metadata: 
      labels: 
        app: hello 
    spec: 
      containers: 
      - name: hello 
        image: hello:v1 
        ports: 
        - containerPort: 80 
```

现在我们可以使用`kubectl`将部署提交到 Kubernetes：

```
    $kubectl apply -f deployment.yaml
    deployment "hello" created  
```

接下来，让我们为一个服务做同样的事情：

```
service.yaml 
kind: Service 
apiVersion: v1 
metadata: 
  name: hello 
spec: 
  selector: 
    app: hello 
  type: NodePort 
  ports: 
  - protocol: TCP 
    port: 80 
    targetPort: 80 
```

使用`kubectl`提交定义到 Kubernetes：

```
    $ kubectl apply -f service.yaml
    service "hello" created  
```

你可以看到，虽然我们牺牲了只需运行一个命令来创建部署的速度和简单性，但通过明确指定我们想要创建的资源，我们可以更好地控制我们的 pod 的配置，并且现在我们可以将这个定义提交到版本控制，并可靠地更新。

在更新资源时，我们可以对文件进行编辑，然后使用`kubectl apply`命令来更新资源。`kubectl`会检测到我们正在更新现有资源，并将其更新以匹配我们的配置。尝试编辑`deployment.yaml`中的图像标记，然后重新提交到集群：

```
    $ kubectl apply -f deployment.yaml
    deployment "hello" configured 
```

如果我们只是在本地集群上对资源进行更改，我们可能只是想快速更改一些东西，而无需编辑文件。首先，就像在我们之前的例子中一样，您可以使用`kubectl set`来更新属性。Kubernetes 实际上并不关心我们如何创建资源，因此我们之前所做的一切仍然有效。进行快速更改的另一种方法是使用`kubectl edit`命令。假设您已经正确设置了`$EDITOR`环境变量与您喜欢的文本编辑器，您应该能够打开资源的 YAML，进行编辑，然后保存，而`kubectl`会无缝地为您更新资源。

# 故障排除 Minikube

在尝试使用 Minikube 时可能遇到的一个常见问题是，您可能无法访问 VM，因为其网络与您的计算机上配置的另一个网络重叠。如果您正在使用企业 VPN，或者连接到配置了默认情况下 Minikube 使用的`192.168.99.1/24` IP 地址范围的另一个网络，这种情况经常会发生。

使用替代 CIDR 启动 Minikube 非常简单，您可以选择任何您想要使用的私有范围；只需确保它不会与本地网络上的其他服务重叠：

```
    $ minikube start --host-only-cidr=172.16.0.1/24

```

# 总结

做得好，能走到这一步真不容易。如果您在本章的示例中跟着做，那么您应该已经在学习如何使用 Kubernetes 来管理自己的应用程序的路上了。您应该能够做到以下几点：

+   使用 Minikube 在您的工作站上设置单节点 Kubernetes 集群

+   使用 Docker 构建一个简单的应用程序容器

+   在 Minikube 集群上运行一个 pod

+   使用清单文件声明 Kubernetes 配置，以便您可以重现您的设置

+   设置一个服务，以便您可以访问您的应用程序


# 第三章：抓住云端

在本章中，我们将学习如何从头开始在亚马逊网络服务上构建一个运行 Kubernetes 集群。为了了解 Kubernetes 的工作原理，我们将手动启动将形成第一个集群的 EC2 实例，并手动安装和配置 Kubernetes 组件。

我们将构建的集群适合您在学习管理 Kubernetes 和开发可以在 Kubernetes 上运行的应用程序时使用。通过这些说明，我们的目标是构建最简单的集群，可以部署到 AWS。当然，这意味着在构建关键任务应用程序的集群时，您可能会有一些不同的需求。但不用担心——在第三部分《准备生产环境》中，我们将涵盖您需要了解的一切，以使您的集群准备好应对最苛刻的应用程序。

在 AWS 上运行 Kubernetes 集群是需要花钱的。根据我们的说明（一个带有一个主节点和一个工作节点的基本集群），目前的费用大约是每月 75 美元。因此，如果您只是用集群进行实验和学习，请记得在一天结束时关闭实例。

如果您已经完成了集群，终止实例并确保 EBS 卷已被删除，因为即使它们所附加的实例已经停止，您也会为这些存储卷付费。

本章旨在成为一个学习体验，因此请在阅读时阅读并输入命令。如果您有本书的电子书版本，请抵制复制粘贴的冲动，因为如果您输入命令并花些时间理解您正在做的事情，您会学到更多。有一些工具可以通过运行一个命令来完成本章所涵盖的一切甚至更多，但是希望通过逐步手动构建您的第一个集群，您将获得一些宝贵的见解，了解构建 Kubernetes 集群所需的一切。

# 集群架构

本章中我们要建立的集群将由两个 EC2 实例组成——一个将运行 Kubernetes 控制平面的所有组件，另一个是您可以用来运行应用程序的工作节点。

因为我们是从零开始的，本章还将阐述一种在私有网络中隔离 Kubernetes 集群并允许您从自己的工作站轻松访问机器的方法。

我们将通过使用额外的实例作为堡垒主机来实现这一点，该主机将允许来自外部世界的 SSH 连接，如下图所示。如果您的 AWS 账户已经有一些基础设施可以实现这一点，那么请随意跳过本节：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/1043a804-7d8a-4850-a577-1c74900d0ccf.png)本章中您将设置的集群架构

# 创建 AWS 账户

如果您还没有 AWS 账户，请前往[`aws.amazon.com/`](https://aws.amazon.com/)注册一个。在您的账户中创建资源之前，您需要向您的账户添加信用卡以支付任何费用。

当您首次注册 AWS 账户时，您将在前 12 个月内有资格免费使用一些服务。不幸的是，这个免费层并不能提供足够的资源来运行 Kubernetes，但在本章中，我们已经优化了我们选择的实例，以降低成本，因此您应该能够在不花费太多的情况下跟随示例。

# 创建 IAM 用户

当您注册 AWS 账户时，您选择的电子邮件地址和密码将用于登录根账户。在开始与 AWS 进行交互之前，最好创建一个 IAM 用户，您将使用该用户与 AWS 进行交互。这样做的好处是，如果您愿意，您可以为每个 IAM 用户提供尽可能多或尽可能少的对 AWS 服务的访问权限。如果您使用根账户，您将自动拥有完全访问权限，并且无法管理或撤销权限。按照以下步骤设置账户：

1.  登录 AWS 控制台后，通过点击“服务”并在搜索框中输入`IAM`来进入身份和访问管理仪表板。

1.  从侧边栏中选择“用户”以查看 AWS 账户中的 IAM 用户。如果您刚刚设置了一个新账户，这里还没有任何用户——根账户不算在内。

1.  通过点击屏幕顶部的“添加用户”按钮开始设置新用户账户的流程。

1.  首先选择一个用户名作为您的用户。勾选两个框以启用**编程访问**（这样您就可以使用命令行客户端）和**AWS 管理控制台访问**，这样您就可以登录到 Web 控制台，如前面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/799d9334-a224-448c-a56f-903fc5fc0ed4.png)

1.  在下一个屏幕上，您可以为用户配置权限。选择**直接附加现有策略**，然后选择**AdministratorAccess**策略，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/ba3b9e52-806b-49df-8619-1639c1cffb85.png)

1.  审查您的设置，然后单击**创建用户**：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/495a44df-8027-4b9b-8a3e-53ae35bb5b90.png)

1.  创建用户后，请记下凭据。您将很快需要**访问密钥 ID**和**秘密访问密钥**来配置 AWS 命令行客户端。还要记下控制台登录链接，因为这是您的 AWS 帐户的唯一链接，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/c16d5213-97fe-40d3-af81-f55a87316886.png)

1.  一旦您为自己设置了 IAM 用户，请从浏览器中注销根帐户，并检查您是否可以使用用户名和密码重新登录。

您可能希望为您的 AWS 帐户设置双因素身份验证以获得更高的安全性。请记住，对帐户具有管理员访问权限的任何人都可以访问或删除您帐户中的任何资源。

# 获取 CLI

您可以使用 Web 控制台控制 AWS，但如果您从 AWS 命令行客户端执行所有操作，您对 AWS 的控制将更加精确。

您应该按照 AWS 提供的说明在您的系统上安装命令行客户端（或者使用系统包管理器），使用以下链接中找到的说明：[`docs.aws.amazon.com/cli/latest/userguide/installing.html`](https://docs.aws.amazon.com/cli/latest/userguide/installing.html)。

一旦您安装了命令行客户端，请运行`aws configure`命令以使用您的凭据配置 CLI。此命令将更新您的主目录中的`aws config`文件。

在这个阶段，您应该为您的集群选择一个 AWS 区域。对于测试和实验，选择一个距离您位置相对较近的区域是有意义的。这样做将在您使用`ssh`或`connect`访问您的实例时改善延迟。

# 设置密钥对

当我们启动 EC2 实例时，我们希望能够通过 SSH 访问它。我们可以在 EC2 控制台中注册一个密钥对，以便在启动实例后登录。

我们可以要求 AWS 为您生成一个密钥对（然后您可以下载）。但最佳做法是在您的工作站上生成一个密钥对，并将公共部分上传到 AWS。这样可以确保您（只有您）控制您的实例，因为您的密钥的私有部分永远不会离开您自己的机器。要设置密钥对，请按照以下步骤进行：

1.  您可能已经在您的机器上有一个希望使用的密钥对。您可以通过查看`.ssh`目录中的现有密钥来检查，如下所示：

```
$ ls -la ~/.ssh
total 128
drwx------    6 edwardrobinson  staff    192 25 Feb 15:49 .
drwxr-xr-x+ 102 edwardrobinson  staff   3264 25 Feb 15:49 ..
-rw-r--r--    1 edwardrobinson  staff   1759 25 Feb 15:48 config
-rw-------    1 edwardrobinson  staff   3326 25 Feb 15:48 id_rsa
-rw-r--r--    1 edwardrobinson  staff    753 25 Feb 15:48 
id_rsa.pub
-rw-r--r--    1 edwardrobinson  staff  53042 25 Feb 15:48 
known_hosts  
```

1.  在此示例中，您可以看到我在`.ssh`目录中有一个密钥对——私钥的默认名称为`id_rsa`，公钥称为`id_rsa.pub`。

1.  如果您还没有设置密钥对，或者想要创建一个新的密钥对，那么您可以使用`ssh-keygen`命令创建一个新的，如下所示：

```
$ ssh-keygen -t rsa -b 4096 -C "email@example.com"
Generating public/private rsa key pair.  
```

1.  此命令使用您的电子邮件地址作为标签创建一个新的密钥对。

1.  接下来，选择保存新密钥对的位置。如果您还没有密钥对，只需按*Enter*将其写入默认位置，如下所示：

```
Enter file in which to save the key (/home/edwardrobinson/.ssh/id_rsa):  
```

1.  接下来，系统会要求您输入密码。如果只需按*Enter*，则密钥将在没有任何密码保护的情况下创建，如下命令所示。如果选择密码，请确保记住它或安全存储，否则您将无法在没有密码的情况下使用 SSH 密钥（或访问实例）。

```
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/edwardrobinson/.ssh/id_rsa.
Your public key has been saved in /home/edwardrobinson/.ssh/id_rsa.
The key fingerprint is:
SHA256:noWDFhnDxcvFl7DGi6EnF9EM5yeRMfGX1wt85wnbxxQ email@example.com  
```

1.  一旦您在您的机器上有了 SSH 密钥对，您可以开始将其导入到您的 AWS 帐户中。请记住，您只需要导入密钥对的公共部分。这将在以`.pub`扩展名结尾的文件中。

1.  从 AWS EC2 控制台（单击“服务”，然后搜索 EC2），选择屏幕左侧菜单中的**密钥对**，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/e53ef48a-a859-437d-a809-c6aac3c95f1a.png)

1.  从此屏幕中，选择**导入密钥对**以打开对话框，您可以在其中上传您的密钥对，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/701fb56c-3d73-4bdc-88ad-da0ea9fc0573.png)

1.  选择一个在 AWS 中标识您的密钥对的名称（我选择了`eds_laptop`）。然后，要么导航到密钥的位置，要么只需将其文本粘贴到大文本框中，然后单击**导入**。导入密钥后，您应该在**密钥对**页面上看到它列出。

如果您在多个地区使用 AWS，则需要在要启动实例的每个地区导入一个密钥对。

# 准备网络

我们将在您的 AWS 账户中设置一个新的 VPC。VPC，或虚拟私有云，允许我们拥有一个与 EC2 和互联网上的所有其他用户隔离的私有网络，我们可以在其上启动实例。

它为我们构建集群的安全网络提供了一个安全的基础，如下命令所示：

```
$ VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 --query "Vpc.VpcId" --output text)
```

`VpcId`将是您的账户唯一的，所以我将设置一个 shell 变量，以便在需要时引用它。您可以使用来自您的帐户的`VpcId`做同样的事情，或者您可能更喜欢每次需要时将其键入。

本章的其余步骤遵循这种模式，但如果您不明白发生了什么，不要害怕查看 shell 变量，并将 ID 与 AWS 控制台中的资源进行关联，如下所示：

```
$ echo $VPC_ID  
```

Kubernetes 根据 AWS 分配给它们的内部 DNS 主机名命名您的实例。如果我们在 VPC 中启用 DNS 支持，那么我们将能够在使用 VPC 内提供的 DNS 服务器时解析这些主机名，如下所示：

```
$ aws ec2 modify-vpc-attribute \
    --enable-dns-support \
    --vpc-id $VPC_ID
$ aws ec2 modify-vpc-attribute \
    --enable-dns-hostnames \
    --vpc-id $VPC_ID  
```

Kubernetes 广泛使用 AWS 资源标记，因此它知道可以使用哪些资源，哪些资源由 Kubernetes 管理。这些标记的关键是`kubernetes.io/cluster/<cluster_name>`。对于可能在几个不同集群之间共享的资源，我们使用`shared`值。这意味着 Kubernetes 可以利用它们，但永远不会从您的帐户中删除它们。

我们将用于 VPC 等资源。Kubernetes 完全管理生命周期的资源具有`owned`的标记值，并且如果不再需要，Kubernetes 可能会删除它们。当 Kubernetes 创建资源，如自动缩放组中的实例、EBS 卷或负载均衡器时，通常会自动创建这些标记。

我喜欢在创建的集群之后以计算机科学历史上的著名人物命名。我为本章创建的集群以设计了 COBOL 编程语言的 Grace Hopper 命名。

让我们为我们的新 VPC 添加一个标签，以便 Kubernetes 能够使用它，如下命令所示：

```
aws ec2 create-tags \
--resources $VPC_ID \
--tags Key=Name,Value=hopper \
  Key=kubernetes.io/cluster/hopper,Value=shared  
```

当我们创建 VPC 时，一个主路由表会自动创建。我们将在私有子网中使用这个路由表进行路由。让我们先获取 ID 以备后用，如下命令所示：

```
$ PRIVATE_ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
    --filters Name=vpc-id,Values=$VPC_ID \
    --query "RouteTables[0].RouteTableId" \
    --output=text) 
```

现在我们将添加第二个路由表来管理我们 VPC 中公共子网的路由，如下所示：

```
$ PUBLIC_ROUTE_TABLE_ID=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --query "RouteTable.RouteTableId" --output text)  
```

现在我们将为路由表命名，以便以后能够跟踪它们：

```
$ aws ec2 create-tags \
  --resources $PUBLIC_ROUTE_TABLE_ID \
  --tags Key=Name,Value=hopper-public
$ aws ec2 create-tags \
  --resources $PRIVATE_ROUTE_TABLE_ID \
  --tags Key=Name,Value=hopper-private  
```

接下来，我们将创建两个子网供我们的集群使用。因为我要在`eu-west-1`区域（爱尔兰）创建我的集群，我将在`eu-west-1a`子网中创建这些子网。您应该通过运行`aws ec2 describe-availability-zones`来选择您正在使用的区域中的可用区来为您的集群选择一个可用区。在第三部分，我们将学习如何创建跨多个可用区的高可用性集群。

让我们首先创建一个只能从我们的私有网络内部访问的实例子网。我们将在 CIDR 块上使用“/20 子网掩码”，如下命令所示；通过这样做，AWS 将为我们提供 4089 个 IP 地址，可供分配给我们的 EC2 实例和 Kubernetes 启动的 pod 使用：

```
$ PRIVATE_SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --availability-zone eu-west-1a \
  --cidr-block 10.0.0.0/20 --query "Subnet.SubnetId" \
  --output text)

$ aws ec2 create-tags \
  --resources $PRIVATE_SUBNET_ID \
  --tags Key=Name,Value=hopper-private-1a \
    Key=kubernetes.io/cluster/hopper,Value=owned \
    Key=kubernetes.io/role/internal-elb,Value=1  
```

接下来，让我们在同一个可用区添加另一个子网，如下命令所示。我们将使用这个子网来放置需要从互联网访问的实例，比如公共负载均衡器和堡垒主机：

```
$ PUBLIC_SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --availability-zone eu-west-1a \
 --cidr-block 10.0.16.0/20 --query "Subnet.SubnetId" \
  --output text)

$ aws ec2 create-tags \
 --resources $PUBLIC_SUBNET_ID \
 --tags Key=Name,Value=hopper-public-1a \
    Key=kubernetes.io/cluster/hopper,Value=owned \
    Key=kubernetes.io/role/elb,Value=1  
```

接下来，我们应该将这个子网与公共路由表关联，如下所示：

```
$ aws ec2 associate-route-table \
  --subnet-id $PUBLIC_SUBNET_ID \
  --route-table-id $PUBLIC_ROUTE_TABLE_ID  
```

为了使我们的公共子网中的实例能够与互联网通信，我们将创建一个互联网网关，将其附加到我们的 VPC，然后在路由表中添加一条路由，将流向互联网的流量路由到网关，如下命令所示：

```
$ INTERNET_GATEWAY_ID=$(aws ec2 create-internet-gateway \
    --query "InternetGateway.InternetGatewayId" --output text)

$ aws ec2 attach-internet-gateway \
    --internet-gateway-id $INTERNET_GATEWAY_ID \
    --vpc-id $VPC_ID

$ aws ec2 create-route \
    --route-table-id $PUBLIC_ROUTE_TABLE_ID \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $INTERNET_GATEWAY_ID
```

为了配置私有子网中的实例，我们需要它们能够建立对外部连接，以便安装软件包等。为了实现这一点，我们将在公共子网中添加一个 NAT 网关，然后为互联网出站流量在私有路由表中添加路由，如下所示：

```
$ NAT_GATEWAY_ALLOCATION_ID=$(aws ec2 allocate-address \
  --domain vpc --query AllocationId --output text)

$ NAT_GATEWAY_ID=$(aws ec2 create-nat-gateway \
  --subnet-id $PUBLIC_SUBNET_ID \
  --allocation-id $NAT_GATEWAY_ALLOCATION_ID \
  --query NatGateway.NatGatewayId --output text)  
```

在这个阶段，你可能需要等待一段时间，直到 NAT 网关被创建，然后再创建路由，如下命令所示：

```
$ aws ec2 create-route \
    --route-table-id $PRIVATE_ROUTE_TABLE_ID \
    --destination-cidr-block 0.0.0.0/0 \
    --nat-gateway-id $NAT_GATEWAY_ID  
```

# 建立堡垒

我们将使用我们要启动的第一个主机作为堡垒主机，这将允许我们连接到只能从 VPC 网络的私有侧访问的其他服务器。

我们将创建一个安全组，以允许 SSH 流量到这个实例。我们将使用`aws ec2 create-security-group`命令为我们的堡垒主机创建一个安全组，如下命令所示。安全组是 AWS 提供的一种抽象，用于将相关的防火墙规则分组并应用到主机组上：

```
$ BASTION_SG_ID=$(aws ec2 create-security-group \
    --group-name ssh-bastion \
    --description "SSH Bastion Hosts" \
    --vpc-id $VPC_ID \
    --query GroupId --output text)  
```

一旦我们创建了安全组，我们可以附加一个规则以允许端口`22`上的 SSH 入口，如下命令所示。这将允许您使用 SSH 客户端访问您的主机。在这里，我允许来自 CIDR 范围`0.0.0.0/0`的入口，但如果您的互联网连接有一个稳定的 IP 地址，您可能希望将访问限制在您自己的 IP 上：

```
$ aws ec2 authorize-security-group-ingress \
  --group-id $BASTION_SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0  
```

现在我们已经为堡垒主机设置了安全组，我们可以开始启动我们的第一个 EC2 实例。在本章中，我将使用 Ubuntu Linux（一种流行的 Linux 发行版）。在启动实例之前，我们需要发现我们想要使用的操作系统的 AMI（Amazon 机器映像）的 ID。

Ubuntu 项目定期发布更新的映像到他们的 AWS 账户，可以用来启动 EC2 实例。我们可以运行以下命令来发现我们需要的映像的 ID：

```
$ UBUNTU_AMI_ID=$(aws ec2 describe-images --owners 099720109477 \
  --filters Name=root-device-type,Values=ebs \
            Name=architecture,Values=x86_64 \
            Name=name,Values='*hvm-ssd/ubuntu-xenial-16.04*' \
  --query "sort_by(Images, &Name)[-1].ImageId" --output text)  
```

我们将为堡垒主机使用一个`t2.micro`实例（如下命令所示），因为这种实例类型的使用包含在 AWS 免费套餐中，所以在设置 AWS 账户后的第一个 12 个月内，您不必为其付费。

```
$ BASTION_ID=$(aws ec2 run-instances \
  --image-id $UBUNTU_AMI_ID \
  --instance-type t2.micro \
  --key-name eds_laptop \
  --security-group-ids $BASTION_SG_ID \
  --subnet-id $PUBLIC_SUBNET_ID \
  --associate-public-ip-address \
  --query "Instances[0].InstanceId" \
  --output text)  
```

请注意，我们正在传递我们选择使用的子网的 ID，我们刚刚创建的安全组的 ID，以及我们上传的密钥对的名称。

接下来，让我们使用`Name`标签更新实例，这样我们在查看 EC2 控制台时就可以识别它，如下命令所示：

```
$ aws ec2 create-tags \
  --resources $BASTION_ID \
  --tags Key=Name,Value=ssh-bastion  
```

一旦实例启动，您应该能够运行`aws ec2 describe-instances`命令来发现您新实例的公共 IP 地址，如下所示：

```
$ BASTION_IP=$(aws ec2 describe-instances \
  --instance-ids $BASTION_ID \
  --query "Reservations[0].Instances[0].PublicIpAddress" \
  --output text)  
```

现在您应该能够使用 SSH 访问实例，如下所示：

```
$ ssh ubuntu@$BASTION_IP  
```

当您登录时，您应该会看到以下消息：

```
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-1052-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  Get cloud support with Ubuntu Advantage Cloud Guest:
        http://www.ubuntu.com/business/services/cloud

 0 packages can be updated.
 0 updates are security updates.

 To run a command as administrator (user "root"), use "sudo <command>".
 See "man sudo_root" for details.

 ubuntu@ip-10-0-26-86:~$  
```

如果您将密钥对保存为除默认的`~/.ssh/id_rsa`之外的其他内容，您可以使用`-i`标志传递密钥的路径，如下所示：

`**ssh -i ~/.ssh/id_aws_rsa ubuntu@$BASTION_IP**`

作为替代，您可以首先将密钥添加到您的 SSH 代理中，方法如下：

`**ssh-add ~/.ssh/id_aws_rsa**`

# sshuttle

只需使用 SSH 就可以将流量从工作站转发到私有网络。但是，我们可以使用`sshuttle`工具更方便地访问堡垒实例上的服务器。

在您的工作站上安装`sshuttle`很简单。

您可以使用 Homebrew 在 macOS 上安装它，如下所示：

```
brew install sshuttle  
```

如果您在 Linux 上安装了 Python，也可以按照以下方式安装它：

```
    pip install sshuttle

```

为了透明地代理私有网络内的实例流量，我们可以运行以下命令：

```
$ sshuttle -r ubuntu@$BASTION_IP 10.0.0.0/16 --dns
[local sudo] Password:
client: Connected.  
```

首先，我们传递我们的`ubuntu@$BASTION_IP`堡垒实例的 SSH 登录详细信息，然后是我们 VPC 的 CIDR（这样只有目的地是私有网络的流量才会通过隧道传输）；这可以通过运行`aws ec2 describe-vpcs`来找到。最后，我们传递`--dns`标志，以便您的工作站上的 DNS 查询将由远程实例的 DNS 服务器解析。

使用`sshuttle`需要您输入本地 sudo 密码，以便设置其代理服务器。

您可能希望在单独的终端或后台运行`sshuttle`，以便您仍然可以访问我们一直在使用的 shell 变量。

我们可以通过尝试使用其私有 DNS 名称登录到我们的实例来验证此设置是否正常工作，方法如下：

```
$ aws ec2 describe-instances \
  --instance-ids $BASTION_ID \
  --query "Reservations[0].Instances[0].PrivateDnsName"

"ip-10-0-21-138.eu-west-1.compute.internal"

$ ssh ubuntu@ip-10-0-21-138.eu-west-1.compute.internal  
```

这将测试您是否可以从 AWS 提供的私有 DNS 解析 VPC 内运行的实例的 DNS 条目，并且查询返回的私有 IP 地址是否可达。

如果您遇到任何困难，请检查`sshuttle`是否有任何连接错误，并确保您已经记得在您的 VPC 中启用了 DNS 支持。

# 实例配置文件

为了让 Kubernetes 能够利用其与 AWS 云 API 的集成，我们需要设置 IAM 实例配置文件。实例配置文件是 Kubernetes 软件与 AWS API 进行身份验证的一种方式，也是我们为 Kubernetes 可以执行的操作分配细粒度权限的一种方式。

学习 Kubernetes 需要正确运行所需的所有权限可能会令人困惑。您可以设置允许对 AWS 进行完全访问的实例配置文件，但这将以牺牲安全最佳实践为代价。

每当我们分配安全权限时，我们应该致力于授予软件正常运行所需的最低权限。为此，我整理了一组最小的 IAM 策略，这些策略将允许我们的集群正常运行，而不会过度授予权限。

您可以在[`github.com/errm/k8s-iam-policies`](https://github.com/errm/k8s-iam-policies)查看这些策略，我已经用简要描述记录了每个策略的目的。

存储库包括一个简单的 shell 脚本，我们可以用它来为我们集群中的主节点和工作节点创建 IAM 实例配置文件，如下所示：

```
$ curl https://raw.githubusercontent.com/errm/k8s-iam-policies/master/setup.sh -o setup.sh
$ sh -e setup.sh
  {
      "InstanceProfile": {
          "Path": "/",
          "InstanceProfileName": "K8sMaster",
          "InstanceProfileId": "AIPAJ7YTS67QLILBZUQYE",
          "Arn": "arn:aws:iam::642896941660:instance-profile/K8sMaster",
          "CreateDate": "2018-02-26T19:06:19.831Z",
          "Roles": []
      }
  }
  {
      "InstanceProfile": {
          "Path": "/",
          "InstanceProfileName": "K8sNode",
          "InstanceProfileId": "AIPAJ27KNVOKTLZV7DDA4",
          "Arn": "arn:aws:iam::642896941660:instance-profile/K8sNode",
          "CreateDate": "2018-02-26T19:06:25.282Z",
          "Roles": []
      }
  }  
```

# Kubernetes 软件

我们将启动一个实例，在该实例中，我们将安装组成我们集群的不同节点所需的所有软件。然后，我们将创建一个 AMI，或 Amazon 机器映像，我们可以用它来启动我们集群上的节点。

首先，我们为这个实例创建一个安全组，如下所示：

```
$ K8S_AMI_SG_ID=$(aws ec2 create-security-group \
    --group-name k8s-ami \
    --description "Kubernetes AMI Instances" \
    --vpc-id $VPC_ID \
    --query GroupId \
    --output text)
```

我们需要能够从我们的堡垒主机访问这个实例，以便登录和安装软件，因此让我们添加一条规则，允许来自`ssh-bastion`安全组中实例的端口`22`的 SSH 流量，如下所示：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_AMI_SG_ID \
    --protocol tcp \
    --port 22 \
    --source-group $BASTION_SG_ID

```

我们只是在这里使用一个`t2.micro`实例，因为我们不需要一个非常强大的实例来安装软件包，如下命令所示：

```
$ K8S_AMI_INSTANCE_ID=$(aws ec2 run-instances \
    --subnet-id $PRIVATE_SUBNET_ID \
    --image-id $UBUNTU_AMI_ID \
    --instance-type t2.micro \
    --key-name eds_laptop \
    --security-group-ids $K8S_AMI_SG_ID \
    --query "Instances[0].InstanceId" \
    --output text) 
```

我们添加一个`Name`标签，这样我们以后可以识别实例，如果需要的话，如下所示：

```
$ aws ec2 create-tags \
    --resources $K8S_AMI_INSTANCE_ID \
    --tags Key=Name,Value=kubernetes-node-ami
```

获取实例的 IP 地址，如下所示：

```
$ K8S_AMI_IP=$(aws ec2 describe-instances \
    --instance-ids $K8S_AMI_INSTANCE_ID \
    --query "Reservations[0].Instances[0].PrivateIpAddress" \
    --output text)
```

然后使用`ssh`登录，如下所示：

```
$ ssh ubuntu@$K8S_AMI_IP  
```

现在我们准备开始配置实例，安装所有集群中所有节点都需要的软件和配置。首先同步 apt 存储库，如下所示：

```
$ sudo apt-get update  
```

# Docker

Kubernetes 可以与许多容器运行时一起工作，但 Docker 仍然是最广泛使用的。

在安装 Docker 之前，我们将向 Docker 服务添加一个`systemd` drop-in 配置文件，如下所示：

```
/etc/systemd/system/docker.service.d/10-iptables.conf
[Service]
ExecStartPost=/sbin/iptables -P FORWARD ACCEPT  
```

为了使我们的 Kubernetes pod 对集群中的其他实例可访问，我们需要设置`iptables FORWARD`链的默认策略，如下命令所示；否则，Docker 将将其设置为`DROP`，Kubernetes 服务的流量将被丢弃：

```
$ sudo mkdir -p /etc/systemd/system/docker.service.d/
$ printf "[Service]\nExecStartPost=/sbin/iptables -P FORWARD ACCEPT" |   sudo tee /etc/systemd/system/docker.service.d/10-iptables.conf
```

Kubernetes 将与 Ubuntu 存储库中包含的 Docker 版本很好地配合，因此我们可以通过安装`docker.io`软件包来简单地安装它，如下所示：

```
$ sudo apt-get install -y docker.io  
```

通过运行以下命令检查 Docker 是否已安装：

```
$ sudo docker version  
```

# 安装 Kubeadm

接下来，我们将安装我们在这个主机上设置 Kubernetes 控制平面所需的软件包。这些软件包在以下列表中描述：

+   `kubelet`：Kubernetes 用来控制容器运行时的节点代理。这用于在 Docker 容器中运行控制平面的所有其他组件。

+   `kubeadm`：这个实用程序负责引导 Kubernetes 集群。

+   `kubectl`：Kubernetes 命令行客户端，它将允许我们与 Kubernetes API 服务器交互。

首先，添加托管 Kubernetes 软件包的 apt 存储库的签名密钥，如下所示：

```
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
OK  
```

接下来，添加 Kubernetes apt 存储库，如下所示：

```
$ sudo apt-add-repository 'deb http://apt.kubernetes.io/ kubernetes-xenial main'  
```

然后，重新同步软件包索引，如下所示：

```
$ sudo apt-get update  
```

然后，按以下方式安装所需的软件包：

```
$ sudo apt-get install -y kubelet kubeadm kubectl  
```

这将安装软件包的最新版本。如果您想固定到特定版本的 Kubernetes，尝试运行`apt-cache madison kubeadm`来查看不同的可用版本。

我使用 Kubernetes 1.10 准备了这一章节。如果你想安装最新版本的 Kubernetes 1.10，你可以运行以下命令：

`**sudo apt-get install kubeadm=1.10.* kubectl=1.10.* kubelet=1.10.***`

# 构建 AMI

现在我们在这个实例上安装软件包完成后，可以关闭它，如下所示：

```
$ sudo shutdown -h now
Connection to 10.0.13.93 closed by remote host.
Connection to 10.0.13.93 closed.  
```

我们可以使用`create-image`命令指示 AWS 对我们的实例的根卷进行快照，并使用它来生成 AMI，如下命令所示（在运行命令之前，您可能需要等待一段时间，直到实例完全停止）：

```
$ K8S_AMI_ID=$(aws ec2 create-image \
 --name k8s-1.10.3-001 \
 --instance-id $K8S_AMI_INSTANCE_ID \
 --description "Kubernetes v1.10.3" \
 --query ImageId \ 
 --output text)
```

镜像变得可用需要一些时间，但您可以使用`describe-images`命令来检查其状态，如下所示：

```
aws ec2 describe-images \
     --image-ids $K8S_AMI_ID \
     --query "Images[0].State"
```

在构建镜像时，您将看到`pending`，但一旦准备好使用，状态将变为`available`。

# 引导集群

现在我们可以为 Kubernetes 控制平面组件启动一个实例。首先，我们将为这个新实例创建一个安全组，如下所示：

```
$ K8S_MASTER_SG_ID=$(aws ec2 create-security-group \
    --group-name k8s-master \
    --description "Kubernetes Master Hosts" \
    --vpc-id $VPC_ID \
    --query GroupId \
    --output text) 
```

我们需要能够从我们的堡垒主机访问这个实例，以便登录和配置集群。我们将添加一条规则，允许来自`ssh-bastion`安全组中实例的端口`22`上的 SSH 流量，如下所示：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_MASTER_SG_ID \
    --protocol tcp \
    --port 22 \
    --source-group $BASTION_SG_ID 
```

现在我们可以启动实例，如下所示：

```
$ K8S_MASTER_INSTANCE_ID=$(aws ec2 run-instances \
    --private-ip-address 10.0.0.10 \
    --subnet-id $PRIVATE_SUBNET_ID \
    --image-id $K8S_AMI_ID \
    --instance-type t2.medium \
    --key-name eds_laptop \
    --security-group-ids $K8S_MASTER_SG_ID \
    --credit-specification CpuCredits=unlimited \
    --iam-instance-profile Name=K8sMaster \
    --query "Instances[0].InstanceId" \
    --output text) 
```

我们应该给实例命名，并确保 Kubernetes 能够将所有资源与我们的集群关联起来，我们还将添加`KubernetesCluster`标签，并为此集群命名，如下所示：

```
$ aws ec2 create-tags \
  --resources $K8S_MASTER_INSTANCE_ID \
  --tags Key=Name,Value=hopper-k8s-master \
    Key=kubernetes.io/cluster/hopper,Value=owned

$ ssh ubuntu@10.0.0.10  
```

为了确保所有 Kubernetes 组件使用相同的名称，我们应该将主机名设置为与 AWS 元数据服务提供的名称相匹配，如下所示。这是因为元数据服务提供的名称被启用了 AWS 云提供程序的组件使用：

```
$ sudo hostnamectl set-hostname $(curl http://169.254.169.254/latest/meta-data/hostname)
$ hostnamectl status
   Static hostname: ip-10-0-0-10.eu-west-1.compute.internal  
```

为了正确配置 kubelet 使用 AWS 云提供程序，我们创建了一个 `systemd` drop-in 文件，向 kubelet 传递一些额外的参数，如下所示：

```
/etc/systemd/system/kubelet.service.d/20-aws.conf
[Service]
Environment="KUBELET_EXTRA_ARGS=--cloud-provider=aws --node ip=10.0.0.10"
$ printf '[Service]\nEnvironment="KUBELET_EXTRA_ARGS=--cloud-provider=aws --node-ip=10.0.0.10"' | sudo tee /etc/systemd/system/kubelet.service.d/20-aws.conf 
```

添加了这个文件后，重新加载 `systemd` 配置，如下所示：

```
$ sudo systemctl daemon-reload
$ sudo systemctl restart kubelet  
```

我们需要为 `kubeadm` 提供一个配置文件，以便在它启动的每个组件上启用 AWS 云提供程序。在这里，我们还将 `tokenTTL` 设置为 `0`，如下所示；这意味着发放给工作节点加入集群的令牌不会过期。这很重要，因为我们计划使用自动扩展组来管理我们的工作节点，新节点可能会在一段时间后加入该组：

```
kubeadm.config
apiVersion: kubeadm.k8s.io/v1alpha1
kind: MasterConfiguration
cloudProvider: aws
tokenTTL: "0"  
```

现在我们只需要运行以下命令来引导主节点：

```
$ sudo kubeadm init --config=kubeadm.config 
[init] Using Kubernetes version: v1.10.3 .. .
. . .
. . . 
Your Kubernetes master has initialized successfully!
. . .
```

您应该看到前面的消息，然后是一些设置集群其余部分的说明。记下 `kubeadm join` 命令，因为我们将需要它来设置工作节点。

我们可以通过按照 `kubeadm` 给出的指示在主机上设置 `kubectl` 来检查 API 服务器是否正常运行，如下所示：

```
$ mkdir -p $HOME/.kube
$ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
$ sudo chown $(id -u):$(id -g) $HOME/.kube/config  
```

尝试运行 `kubectl` version。如果 `kubectl` 能够正确连接到主机，那么您应该能够看到客户端（`kubectl`）和服务器上 Kubernetes 软件的版本，如下所示：

```
$ kubectl version
Client Version: version.Info{Major:"1", Minor:"9", GitVersion:"v1.9.3", GitCommit:"d2835416544f298c919e2ead3be3d0864b52323b", GitTreeState:"clean", BuildDate:"2018-02-07T12:22:21Z", GoVersion:"go1.9.2", Compiler:"gc", Platform:"linux/amd64"}
Server Version: version.Info{Major:"1", Minor:"9", GitVersion:"v1.9.3", GitCommit:"d2835416544f298c919e2ead3be3d0864b52323b", GitTreeState:"clean", BuildDate:"2018-02-07T11:55:20Z", GoVersion:"go1.9.2", Compiler:"gc", Platform:"linux/amd64"}
```

# 刚刚发生了什么？

那很容易对吧？我们通过运行一个命令来启动和运行了 Kubernetes 控制平面。

`kubeadm` 命令是一个很棒的工具，因为它消除了正确配置 Kubernetes 的许多猜测。但是让我们暂时中断设置集群的过程，深入挖掘一下刚刚发生了什么。

查看 `kubeadm` 命令的输出应该给我们一些线索。

首先，`kubeadm`做的事情是建立一个私有密钥基础设施。如果你查看`/etc/kubernetes/pki`目录，你会看到一些`ssl`证书和私钥，以及一个用来签署每个密钥对的证书颁发机构。现在，当我们向集群添加工作节点时，它们将能够在 kubelet 和`apiserver`之间建立安全通信。

接下来，`kubedam`将静态 pod 清单写入`/etc/kubernetes/manifests/`目录。这些清单就像您将提交给 Kubernetes API 服务器以运行自己的应用程序的 pod 定义一样，但由于 API 服务器尚未启动，定义是由`kubelet`直接从磁盘读取的。

`kubelet`被配置为在`kubeadm`在`etc/systemd/system/kubelet.service.d/10-kubeadm.conf`创建的`systemd dropin`中读取这些静态 pod 清单。您可以在其他配置中看到以下标志：

```
--pod-manifest-path=/etc/kubernetes/manifests  
```

如果您查看`/etc/kubernetes/manifests/`，您将看到形成控制平面的每个组件的 Kubernetes pod 规范，如下列表所述：

+   `etcd.yaml`：存储 API 服务器状态的键值存储

+   `kube-apiserver.yaml`：API 服务器

+   `kube-controller-manager.yaml`：控制器管理器

+   `kube-scheduler.yaml`：调度程序

最后，一旦 API 服务器启动，`kubeadm`向 API 提交了两个插件，如下列表所述：

+   `kube-proxy`：这个进程在每个节点上配置 iptables，使服务 IP 正确路由。它在每个节点上以 DaemonSet 运行。您可以通过运行`kubectl -n kube-system describe ds kube-proxy`来查看此配置。

+   `kube-dns`：这个进程提供了可以被集群上运行的应用程序用于服务发现的 DNS 服务器。请注意，在为您的集群配置 pod 网络之前，它将无法正确运行。您可以通过运行`kubectl -n kube-system describe deployment kube-dns`来查看`kube-dns`的配置。

您可以尝试使用`kubectl`来探索组成 Kubernetes 控制平面的不同组件。尝试运行以下命令：

**$ kubectl -n kube-system get pods**

**$ kubectl -n kube-system describe pods**

**$ kubectl -n kube-system get daemonsets**

**$ kubectl -n kube-system get deployments**

**在继续下一节之前，请注销主实例，如下所示：**

**$ exit**

`**注销**`

`**连接到 10.0.0.10 已关闭。**`

# 从您的工作站访问 API

能够通过工作站上的`kubectl`访问 Kubernetes API 服务器非常方便。这意味着您可以将您可能一直在开发的任何清单提交到在 AWS 上运行的集群。

我们需要允许来自堡垒服务器访问 API 服务器的流量。让我们向`K8S-MASTER`安全组添加一条规则来允许此流量，如下所示：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_MASTER_SG_ID \
    --protocol tcp \
    --port 6443 \
    --source-group $BASTION_SG_ID
```

如果您尚未在工作站上安装 kubectl，请返回到第二章，“启动引擎”，进行学习。

现在我们可以从主实例复制`kubeconfig`文件。

如果您在本地的`~/.kube/config`文件中尚未配置任何集群，您可以按照以下步骤从主服务器复制文件：

```
$ scp ubuntu@10.0.0.10:~/.kube/config ~/.kube/config  
```

如果您已经配置了一个集群（例如，minikube），那么您可能希望合并您的新集群的配置，或者使用另一个文件并使用`--kubeconfig`标志将其位置传递给`kubectl`，或者在`KUBECONFIG`环境变量中传递。

检查您是否可以使用本地的`kubectl`连接到 API 服务器，如下所示：

```
$ kubectl get nodes
NAME               STATUS     AGE       VERSION
ip-10-0-9-172...   NotReady   5m        v1.9.3 
```

如果您在连接时遇到任何问题，请检查`sshuttle`是否仍在运行，并且您已经正确允许了从堡垒主机到 k8s-master 安全组的访问。

# 设置 pod 网络

您可能已经注意到，当运行`kubectl get nodes`时，`NodeStatus`为`NotReady`。这是因为我们引导的集群缺少一个基本组件——将允许在我们的集群上运行的 pod 相互通信的网络基础设施。

Kubernetes 集群的网络模型与标准 Docker 安装有些不同。有许多网络基础设施的实现可以为 Kubernetes 提供集群网络，但它们都具有一些共同的关键属性，如下列表所示：

+   每个 pod 都被分配了自己的 IP 地址

+   每个 pod 都可以与集群中的任何其他 pod 进行通信，而无需 NAT（尽管可能存在其他安全策略）

+   运行在 pod 内部的软件看到的内部网络与集群中其他 pod 看到的 pod 网络是相同的，即它看到的 IP 地址相同，并且不进行端口映射

这种网络安排对于集群的用户来说要简单得多（比 Docker 的标准网络方案要简单），Docker 的标准网络方案是将容器内部端口映射到主机上的其他端口。

但是，这需要网络基础设施和 Kubernetes 之间的一些集成。Kubernetes 通过一个名为**容器网络接口**（**CNI**）的接口来管理这种集成。通过 Kubernetes DaemonSet，可以简单地将**CNI**插件部署到集群的每个节点上。

如果您想了解更多关于 Kubernetes 集群网络的信息，我建议阅读底层概念的全面文档，网址为[`kubernetes.io/docs/concepts/cluster-administration/networking/`](https://kubernetes.io/docs/concepts/cluster-administration/networking/)。

我们将部署一个名为`amazon-vpc-cni-k8s`的 CNI 插件，它将 Kubernetes 与 AWS VPC 网络的本地网络功能集成在一起。该插件通过将次要私有 IP 地址附加到形成集群节点的 EC2 实例的弹性网络接口，然后在 Kubernetes 将它们调度到每个节点时分配给 Pod 来工作。然后，流量通过 AWS VPC 网络布线直接路由到正确的节点。

部署此插件与使用`kubectl`将任何其他清单提交到 Kubernetes API 的过程类似，如以下命令所示：

```
$ kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/v1.3/aws-k8s-cni.yaml 
daemonset "aws-node" created
```

您可以通过运行以下命令来监视正在安装和启动的网络插件：

```
$ kubectl -n kube-system describe pods aws-node  
```

我们可以通过再次查看节点状态来检查网络是否已正确设置，方法如下：

```
$ kubectl get nodes
NAME               STATUS    ROLES     AGE       VERSION
ip-172-31-29-230   Ready     master    10m       v1.9.3  
```

# 启动工作节点

我们现在将为工作节点创建一个新的安全组，方法如下：

```
$ K8S_NODES_SG_ID=$(aws ec2 create-security-group \
    --group-name k8s-nodes \
    --description "Kubernetes Nodes" \
    --vpc-id $VPC_ID \
    --query GroupId \
    --output text)  
```

为了我们能够登录进行调试，我们将允许通过堡垒主机访问工作节点，方法如下：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_NODES_SG_ID \
    --protocol tcp \
    --port 22 \
    --source-group $BASTION_SG_ID
```

我们希望允许运行在工作节点上的 kubelet 和其他进程能够连接到主节点上的 API 服务器。我们可以通过以下命令来实现这一点：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_MASTER_SG_ID \
    --protocol tcp \
    --port 6443 \
    --source-group $K8S_NODES_SG_ID  
```

由于 kube-dns 插件可能在主节点上运行，让我们允许来自节点安全组的流量，方法如下：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_MASTER_SG_ID \
    --protocol all \
    --port 53 \
    --source-group $K8S_NODES_SG_ID 
```

我们还需要主节点能够连接到 kubelet 暴露的 API，以便流式传输日志和其他指标。我们可以通过输入以下命令来实现这一点：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_NODES_SG_ID \
    --protocol tcp \
    --port 10250 \
    --source-group $K8S_MASTER_SG_ID

$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_NODES_SG_ID \
    --protocol tcp \
    --port 10255 \
    --source-group $K8S_MASTER_SG_ID
```

最后，我们需要允许任何节点上的任何 Pod 能够连接到任何其他 Pod。我们可以使用以下命令来实现这一点：

```
$ aws ec2 authorize-security-group-ingress \
    --group-id $K8S_NODES_SG_ID \
    --protocol all \
    --port -1 \
    --source-group $K8S_NODES_SG_ID  
```

为了在启动时使工作节点自动注册到主节点，我们将创建一个用户数据脚本。

此脚本在节点首次启动时运行。它进行一些配置更改，然后运行`kubeadm join`，如下命令所示。当我们初始化主节点时，您应该已经记录了`kubeadm join`命令。

```
user-data.sh
#!/bin/bash

set -exuo pipefail
hostnamectl set-hostname $(curl http://169.254.169.254/latest/meta-data/hostname)

cat << EOF $ /etc/systemd/system/kubelet.service.d/20-aws.conf
[Service]
Environment="KUBELET_EXTRA_ARGS=--cloud-provider=aws --node-ip=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)     --node-labels=node-role.kubernetes.io/node="
EOF

systemctl daemon-reload
systemctl restart kubelet

kubeadm join \
  --token fddaf9.1f07b60a8268aac0 \
  --discovery-token-ca-cert-hash sha256:872757bce0df91c2b046b0d8bb5d930bc1ecfa245b14c25ad8a52746cb8b8e8b \
10.0.0.10:6443  
```

首先，我们使用以下命令创建一个启动配置。这类似于自动缩放组将用于启动我们的工作节点的配置模板。许多参数类似于我们将传递给 EC2 run-instances 命令的参数：

```
$ aws autoscaling create-launch-configuration \
    --launch-configuration-name k8s-node-1.10.3-t2-medium-001 \
    --image-id $K8S_AMI_ID \ --key-name 
  eds_laptop \    
     --security-groups $K8S_NODES_SG_ID \  
     --user-data file://user-data.sh \    
     --instance-type t2.medium \    
     --iam-instance-profile K8sNode \    
     --no-associate-public-ip-address
```

创建启动配置后，我们可以创建一个自动缩放组，如下所示：

```
> aws autoscaling create-auto-scaling-group \
    --auto-scaling-group-name hopper-t2-medium-nodes \
    --launch-configuration-name k8s-node-1.10.3-t2-medium-001 \
    --min-size 1 \
    --max-size 1 \
    --vpc-zone-identifier $PRIVATE_SUBNET_ID \
    --tags Key=Name,Value=hopper-k8s-node \
      Key=kubernetes.io/cluster/hopper,Value=owned \
      Key=k8s.io/cluster-autoscaler/enabled,Value=1  
```

需要等待一段时间，直到自动缩放组启动节点，并使用`kubeadm`将其注册到主节点，如下所示。

```
> kubectl get nodes --watch
NAME              STATUS    AGE       VERSION
ip-10-0-0-10       Ready     37m       v1.10.3
ip-10-0-2-135      Ready     53s       v1.10.3  
```

如果您的节点启动但在几分钟后没有加入集群，请尝试登录节点并查看`cloud-init`日志文件。此日志的结尾将包括脚本的输出。

```
> cat /var/log/cloud-init-output.log  
```

# 演示时间

恭喜，如果您已经通过本章走到这一步！到目前为止，您应该已经拥有一个完全功能的 Kubernetes 集群，可以用来进行实验并更全面地探索 Kubernetes。

让我们通过部署一个应用程序到我们的集群来演示我们构建的集群正在工作，如下所示：

```
kubectl apply -f
 https://raw.githubusercontent.com/PacktPublishing/Kubernetes-on-AWS/master/chapter03/demo.yaml
```

此清单部署了一个简单的 Web 应用程序和一个服务，使用负载均衡器将应用程序暴露到互联网。我们可以使用`kubectl get service`命令查看负载均衡器的公共 DNS 名称，如下所示：

```
> kubectl get svc demo -o wide  
```

一旦您获得负载均衡器的公共地址，您可能需要等待一段时间，直到地址开始解析。在浏览器中访问该地址；您应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/67570712-97ff-4e23-92ac-9b70d0857877.png)

# 总结

到目前为止，您应该拥有一个完全功能的 Kubernetes 集群，可以用来进行实验并更全面地探索 Kubernetes。您的集群已正确配置，以充分利用 Kubernetes 与 AWS 的许多集成。

虽然有许多工具可以自动化和协助您在 AWS 上构建和管理 Kubernetes 集群的任务，但希望通过学习如何从头开始处理任务，您将更好地了解支持 Kubernetes 集群所需的网络和计算资源。

在第三部分，我们将在本章的知识基础上讨论您需要添加到集群中的其他组件，以使其适合托管生产服务。我们刚刚构建的集群是一个完全功能的 Kubernetes 安装。继续阅读，我们将研究在 Kubernetes 上成功运行生产服务所需的工具和技术：

+   我们将研究您可以采用的工具和程序，以有效地管理部署和更新您的服务，使用 Kubernetes

+   我们将研究您可以采用的策略和工具，以确保集群和其中运行的应用程序的安全

+   我们将研究与 Kubernetes 一起使用的监控和日志管理工具

+   我们将研究最佳的架构应用程序和集群的方式，以满足可用性目标


# 第四章：管理应用程序中的变更

在第二章 *启动引擎*中，我们首次尝试使用部署在 Kubernetes 上运行应用程序。在本章中，我们将深入了解 Kubernetes 提供的用于管理在集群上运行的 Pod 的工具。

+   我们将学习如何通过使用`Job`资源来确保批处理任务成功完成

+   我们将学习如何使用`CronJob`资源在预定时间间隔运行作业

+   最后，我们将学习如何使用部署来使长时间运行的应用程序无限期运行，并在需要进行更改时更新它们或其配置

我们将看看如何可以使用 Kubernetes 以不同的方式启动 Pod，这取决于我们正在运行的工作负载。

您将学到更多关于如何使用部署资源来控制 Kubernetes 如何推出对长时间运行的应用程序的更改。您将了解可以使用 Kubernetes 执行常见部署模式的方法，例如蓝绿部署和金丝雀部署。

按设计，Pod 不打算以任何方式持久。正如我们之前讨论过的，有一系列条件可能导致 Pod 的生命周期终止。它们包括：

+   **底层节点的故障**：可能是由于一些意外事件，例如硬件故障。或者可能是出于设计考虑；例如，在使用按需定价实例的集群中，如果实例需求增加，节点可以在没有警告的情况下被终止。

+   **调度程序启动的 Pod 驱逐**：调度程序在需要时可以启动 Pod 驱逐，以优化集群上资源的使用。这可能是因为某些进程的优先级比其他进程更高，或者只是为了优化集群上的装箱。

+   用户手动删除的 Pod。

+   由于计划维护而删除的 Pod；例如，使用`kubectl drain`命令。

+   由于网络分区，节点不再对集群可见。

+   为了准备缩减操作而从节点中删除的 Pod。

因此，如果 Kubernetes 的设计期望 pod 是短暂的，我们如何部署可靠的应用程序呢？当然，我们需要一种无法失败地运行我们的程序的方式。幸运的是，情况并非完全如此。这种设计的重要部分是它准确地模拟了由于底层硬件和软件以及管理过程而可能发生的各种问题。Kubernetes 并不试图使基本构建块（pod）本身对故障具有弹性，而是提供了许多控制器，我们作为用户可以直接与之交互来构建具有弹性的服务。这些控制器负责为因任何原因丢失的 pod 创建替代品。

这些控制器分为四组，我们的选择取决于我们想要运行的工作负载的类型：

+   对于我们期望结束的进程，比如批处理作业或其他有限的进程，Kubernetes 提供了作业抽象。作业确保一个 pod 至少运行一次完成。

+   对于我们期望长时间运行的 pod，比如 web 服务器或后台处理工作者，Kubernetes 提供了部署和较低级别的 ReplicationController 或 ReplicaSet。

+   对于我们希望在所有机器（或其中一部分）上运行的 pod，Kubernetes 提供了 DaemonSet。DaemonSet 通常用于提供作为平台一部分的特定于机器的服务，比如日志管理或监控代理，通常用于部署覆盖网络的每个节点组件。

+   对于每个 pod 都需要稳定标识或访问持久存储的 pod 组，Kubernetes 提供了`StatefulSets`。（我们将在第九章中介绍`StatefulSets`，*存储状态*。）

如果回想一下我们在第一章中学到的关于 Kubernetes 架构的知识，《谷歌的基础设施服务于我们其余的人》, 重要的是要记住控制器管理器（运行所有这些控制器的 Kubernetes 微服务）是一个独立的、不同的进程，与调度器分开。Kubernetes 的核心低级部分，比如调度器和 kubelet，只知道 pod，而高级控制器不需要了解实际调度和在节点上运行 pod 的任何细节。它们只是向 API 服务器发出请求创建一个 pod，而较低级的机制确保它们被正确地调度和运行。

在本章中，我们将逐步介绍作业、部署和 DaemonSet 提供给我们的重要功能和配置选项。通过一些示例，您将开始了解何时使用每个资源来部署您的应用程序。您应该花时间了解每个控制器正在做什么，以及为什么要使用它。

将软件部署到分布式环境可能会有点不同寻常，因为在部署到单台机器时可能会有很多假设不适用于分布式系统。

Kubernetes 非常擅长让我们能够部署大多数软件而无需进行任何修改。我认为 Kubernetes 让我们以一点简单性换取了很多可靠性。

# 直接运行 pod

Kubernetes 并不真的打算让用户直接在集群上提交和启动 pod。正如我们之前讨论的，pod 被设计为短暂存在，因此不适合运行需要确保执行已完成或需要确保进程保持运行的工作负载。

在这里，我们将从头开始，启动 pod，然后再使用控制器来帮助我们管理它们。请记住，这是一个学习练习；如果您需要它们可靠地运行，就不应该以这种方式提交 pod：

```
pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: hello-loop
spec:
  containers:
  - name: loop
    image: alpine
    command: ["/bin/sh"]
    args:
    - -c
    - while true; do echo "hello world"; sleep 2s; done

```

这个 pod 启动了一个无限循环，每 2 秒打印一次`hello world`。首先使用`kubectl`将 pod 提交到集群中：

```
$ kubectl create -f pod.yaml
pod "hello-loop" created
```

在容器运行时下载镜像的过程中，可能需要一些时间来创建 pod。在此期间，您可以通过运行`kubectl describe pod/hello-loop`或使用仪表板来检查 pod 的状态。

Kubernetes 使得即使是最低级别的抽象，比如 pod，也可以通过 API 来控制，这使得使用或构建附加工具来扩展 Kubernetes 的功能变得很容易，这些工具可以和内置的控制器一样强大。

一旦 pod 启动并运行，您可以使用`kubectl logs -f hello-loop`来跟踪输出，您应该每 2 秒看到一个`hello world`的输出。

`kubectl logs` 允许我们显示在集群上运行的 pod 的日志。如果您知道要从中获取日志的 pod 的名称，您可以将名称作为参数传递。但是，如果您使用控制器来启动 pod，您可以使用作业或部署的名称来代替 pod 名称，只需在名称前加上资源类型。

如果您对感兴趣的 pod 或 pod 有标签选择器，可以使用 `-l` 标志传递它们。使用 `-c` 标志，您可以针对具有多个容器的 pod 中的特定命名容器进行定位；如果 pod 只有一个容器，则可以省略此选项。

尝试运行 `kubectl`。它可以帮助查看一些更多的选项，以便查看您感兴趣的日志，包括将其限制在特定时间段内。

# 作业

作业的最简单用例是启动单个 pod，并确保它成功运行完成。

在我们的下一个示例中，我们将使用 Ruby 编程语言来计算并打印出前 100 个斐波那契数：

```
fib.yaml apiVersion: batch/v1
kind: Job
metadata:
  name: fib
spec:
  template:
     metadata:
       name: fib
     spec:
       containers:
       - name: fib
         image: ruby:alpine
         command: ["ruby"]
         args:
         - -e
         - |
           a,b = 0,1
           100.times { puts b = (a = a+b) - b }
       restartPolicy: Never
```

请注意，`spec` 和 `template` 的内容与我们直接启动 pod 时使用的规范非常相似。当我们为作业中的 pod 模板定义一个 pod 模板时，我们需要选择 `restartPolicy` 为 `Never` 或 `OnFailure`。

这是因为作业的最终目标是运行 pod 直到成功退出。如果基础 pod 在成功退出时重新启动，那么 pod 将继续重新启动，作业将永远无法完成。

将定义保存到文件，然后使用 `kubectl create` 将其提交到集群：

```
$ kubectl create -f fib.yaml
job "fib" created
```

一旦您向 Kubernetes 提交了作业，您可以使用 `kubectl describe` 命令来检查其状态。可能需要一点时间来下载 Docker 镜像并启动 pod。一旦 pod 运行，您应该在 `Pods Statues` 字段中看到首先是 `1 Running`，然后是 `1 Succeeded`：

```
$ kubectl describe jobs/fib
Name: fib
Namespace: default
Selector: controller-uid=278fa785-9b86-11e7-b25b-080027e071f1
Labels: controller-uid=278fa785-9b86-11e7-b25b-080027e071f1
 job-name=fib
Annotations: <none>
Parallelism: 1
Completions: 1
Start Time: Sun, 17 Sep 2017 09:56:54 +0100
Pods Statuses: 0 Running / 1 Succeeded / 0 Failed
```

在等待 Kubernetes 执行某些操作时，反复运行 `kubectl` 以了解发生了什么可能会变得乏味。我喜欢将 `watch` 命令与 `kubectl` 结合使用。要观察 Kubernetes 启动此作业，我可以运行：

`**$ watch kubectl describe jobs/fib**`

大多数 Linux 发行版将默认包含 `watch` 命令，或者可以通过软件包管理器轻松安装。如果您使用 macOS，可以通过 Homebrew 轻松安装：

`**$ brew install watch**`

我们可以使用`kubectl logs`来查看我们作业的输出。注意我们不需要知道底层 pod 的名称；我们只需要通过名称引用作业即可：

```
$ kubectl logs job/fib
...
83621143489848422977
135301852344706746049
218922995834555169026
```

我们还可以使用`kubectl get`查看由该作业创建的底层 pod，通过使用 Kubernetes 为我们添加到 pod 的`job-name`标签：

```
$ kubectl get pods -l job-name=fib --show-all
NAME READY STATUS RESTARTS AGE
fib-dg4zh 0/1 Completed 0 1m
```

`--show-all`标志意味着显示所有的 pod（即使那些不再具有运行状态的 pod）。

注意 Kubernetes 根据作业名称为我们的 pod 创建了一个唯一的名称。这很重要，因为如果第一个被创建的 pod 在某种方式上失败了，Kubernetes 需要根据相同的 pod 规范启动另一个 pod。

作业相对于直接启动 pod 的一个关键优势是，作业能够处理不仅是由底层基础设施引起的错误，可能导致 pod 在完成之前丢失，还有在运行时发生的错误。

为了说明这是如何工作的，这个作业模拟了一个（大部分）以非零退出状态失败的过程，但有时以（成功的）零退出状态退出。这个 Ruby 程序选择一个从 0 到 10 的随机整数并以它退出。因此，平均来说，Kubernetes 将不得不运行该 pod 10 次，直到它成功退出：

```
luck.yaml apiVersion: batch/v1
kind: Job
metadata:
  name: luck
spec:
  template:
    metadata:
      name: luck
    spec:
      containers:
      - name: luck
      image: ruby:alpine
      command: ["ruby"]
      args: ["-e", "exit rand(10)"]
restartPolicy: Never
```

像以前一样，使用`kubectl`将作业提交到你的集群中：

```
$ kubectl create -f luck.yaml
job "luck" created
```

除非你非常幸运，当你检查作业时，你应该看到 Kubernetes 需要启动多个 pod，直到有一个以 0 状态退出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/84ee4ac9-b016-4699-ba25-d666146e64aa.png)

使用 Kubernetes 仪表板检查由 luck 作业启动的 pod

在这个例子中，pod 规范具有`restartPolicy`为`Never`。这意味着当 pod 以非零退出状态退出时，该 pod 被标记为终止，作业控制器会启动另一个 pod。还可以使用`restartPolicy`为`OnFailure`运行作业。

尝试编辑`luck.yaml`来进行这个更改。删除`luck`作业的第一个版本并提交你的新版本：

```
$ kubectl delete jobs/luck
job "luck" deleted
$ kubectl create -f luck.yaml
job "luck" created
```

这一次，你应该注意到，Kubernetes 不再快速启动新的 pod，直到一个成功退出，而是重启一个 pod 直到成功。你会注意到这需要更长的时间，因为当 Kubernetes 使用指数回退本地重启一个 pod 时，这种行为对于由于底层资源过载或不可用而导致的失败是有用的。你可能会注意到 pod 处于`CrashLoopBackoff`状态，而 Kubernetes 正在等待重新启动 pod：

```
$ kubectl get pods -l job-name=luck -a
NAME READY STATUS RESTARTS AGE
luck-0kptd 0/1 Completed 5 3m
```

允许作业控制器在每次终止时重新创建一个新的 pod，以确保新的 pod 在新的原始环境中运行，并导致作业资源保留每次执行尝试的记录。因此，通常最好不要在作业中使用 pod 重启策略，除非您必须处理定期失败的 pod，或者您希望在尝试之间保留执行环境。

# CronJob

现在您已经学会了如何使用作业运行一次性或批量任务，可以简单地扩展该概念以运行定时作业。在 Kubernetes 中，`CronJob`是一个控制器，根据给定的计划从模板创建新的作业。

让我们从一个简单的例子开始。以下示例将每分钟启动一个作业。该作业将输出当前日期和时间，然后退出：

```
fun-with-cron.yaml apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: fun-with-cron
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            cronjob: fun-with-cron
        spec:
          restartPolicy: OnFailure
          containers:
          - name: how-soon-is-now
            image: alpine:3.6
            command: ["/bin/date"]
```

使用`kubectl`将 CronJob 推送到 Kubernetes：

```
$ kubectl apply -f fun-with-cron.yaml
```

过一段时间（不到一分钟），您应该会看到第一个作业被创建：

```
$ kubectl get jobs
NAME DESIRED SUCCESSFUL AGE
fun-with-cron-1533475680 1 1 9s
```

我们添加到 pod 模板规范的标签允许我们使用`kubectl logs`来查看 CronJob 创建的所有 pod 的输出：

```
$ kubectl logs -l cronjob=fun-with-cron
 Sun Aug 5 13:26:08 UTC 2018
 Sun Aug 5 13:27:08 UTC 2018
 Sun Aug 5 13:28:08 UTC 2018
```

# Cron 语法

调度字段的语法遵循标准的 Cron 格式，如果您曾在类 Unix 系统上设置过 CronJobs，这应该是很熟悉的。Kubernetes 支持带有一些常见扩展的标准 cron 字符串。

标准的 cron 字符串由五个字段组成，每个字段代表不同的时间单位。每个字段可以设置为表示特定时间的表达式，或者通配符(*)，表示匹配每个时间。例如，在**月份**列中的通配符将匹配每个月：

| 分钟 | 小时 | 月份中的日期 | 月份 | 星期中的日期 |
| --- | --- | --- | --- | --- |

Cron 字段的顺序

如果从左到右阅读，Cron 格式最容易理解。以下是一些示例：

+   `0 * * * *`：每小时整点

+   `15 * * * *`：每小时 15 分钟

+   `0 0 * * *`：每天午夜

+   `30 5 1 * *`：每个月的第一天上午 5:30

+   `30 17 * * 1`：每周一下午 3:30

除了通配符之外，还有一些其他具有特殊含义的字符。

斜杠用于指示步长：

+   `0/15 * * * *`：每 15 分钟一次，从 0 开始；例如，12:00, 12:15, 12:30 等

+   `15/15 * * * *`：每 15 分钟一次，从 15 开始；例如，12:15, 12:30, 12:45, 13:15, 13:30 等

+   `0 0 0/10 * *`：每 10 天的午夜

连字符表示范围：

+   `0 9-17 * * *`：在办公时间（上午 9 点至下午 5 点）每小时一次

+   `0 0 1-15/2 * *`：每月前 15 天隔一天

逗号表示列表：

+   `0 0 * * 6,0`：星期六和星期日午夜

+   `0 9,12,17 * * 1-5`：上午 9:00，中午 12:00 和下午 5:00，周一至周五

为了方便阅读，月份和星期几字段可以使用名称：

+   `0 0 * * SUN`：星期日午夜

+   `0 6 * MAR-MAY *`：每天上午 6 点在春季

如果你不介意作业的具体运行时间，你可以指定一个固定的间隔，Kubernetes 会按固定的间隔创建作业：

+   `@every 15m`：每 15 分钟

+   `@every 1h30m`：每 1 个半小时

+   `@every 12h`：每 12 小时

请记住，间隔不考虑作业运行所需的时间；它只是确保每个作业计划的时间间隔由给定的间隔分隔。

最后，有几个预定义的计划可以用作 cron 字符串的快捷方式：

| **快捷方式** | **等效的 cron** |  |
| --- | --- | --- |
| `@hourly` | `0 0 * * * *` | 每小时整点 |
| `@daily` | `0 0 0 * * *` | 每天午夜 |
| `@weekly` | `0 0 0 * * 0` | 每周星期日午夜 |
| 每月，每月 1 日午夜 |
| `@yearly` | `0 0 0 1 1 *` | 每年除夕午夜 |

# 并发策略

与传统的 CronJob 相比，Kubernetes CronJob 允许我们决定当作业超时并且在上一个作业仍在运行时到达计划时间时会发生什么。我们可以通过在 CronJob 上设置`spec.concurrencyPolicy`字段来控制这种行为。我们可以选择三种可能的策略：

+   默认情况下，如果字段未设置，则我们将获得`Allow`策略。这就像传统的 CronJob 一样工作，并允许多个作业实例同时运行。如果你坚持这一点，你应该确保你的作业确实在某个时候完成，否则你的集群可能会因为同时运行许多作业而不堪重负。

+   `Forbid`策略防止在现有作业仍在运行时启动任何新作业。这意味着如果作业超时，Kubernetes 将跳过下一次运行。如果一个作业的两个或更多实例可能会导致冲突或使用共享资源，这是一个很好的选择。当然，你的作业需要能够处理在这种情况下缺少的运行。

+   最后，`Replace`策略还可以防止多个作业同时运行，而不是跳过运行，它首先终止现有作业，然后启动新作业。

# 历史限制

默认情况下，当您使用 CronJob 时，它创建的作业将保留下来，因此您可以检查特定作业运行的情况以进行调试或报告。但是，当使用 CronJob 时，您可能会发现成功或失败状态的作业数量开始迅速增加。这可以通过`spec.successfulJobsHistoryLimit`和`spec.failedJobsHistoryLimit`字段简单管理。一旦成功或失败的作业达到限制中指定的数量，每次创建新作业时，最旧的作业都会被删除。如果将限制设置为 0，则作业在完成后立即删除。

# 使用部署管理长时间运行的进程

更新批处理进程，例如作业和 CronJobs，相对较容易。由于它们的寿命有限，更新代码或配置的最简单策略就是在再次使用之前更新相关资源。

长时间运行的进程更难处理，如果您将服务暴露给网络，管理起来更加困难。Kubernetes 为我们提供了部署资源，使部署和更新长时间运行的进程变得更简单。

在第二章 *启动引擎*中，我们首次了解了部署资源，既可以使用`kubectl run`创建部署，也可以通过在 YAML 文件中定义部署对象。在本章中，我们将回顾部署控制器用于推出更改的过程，然后深入研究一些更高级的选项，以精确控制新版本的 Pod 的可用性。我们将介绍如何使用部署与服务结合，在不中断服务的情况下对网络上提供的服务进行更改。

就像 CronJob 是作业的控制器一样，部署是 ReplicaSets 的控制器。 ReplicaSet 确保特定配置所需的 Pod 的数量正常运行。为了管理对此配置的更改，部署控制器创建一个具有新配置的新 ReplicaSet，然后根据特定策略缩减旧的 ReplicaSet 并扩展新的 ReplicaSet。即使新配置的部署完成后，部署也会保留对旧 ReplicaSet 的引用。这允许部署在需要时还可以协调回滚到以前的版本。

让我们从一个示例应用程序开始，这将让您快速了解部署提供的不同选项如何允许您在更新代码或配置时操纵应用程序的行为。

我们将部署一个我创建的应用程序，以便简单地说明如何使用 Kubernetes 部署新版本的软件。这是一个简单的 Ruby Web 应用程序，位于 Docker 存储库中，有许多版本标签。每个版本在浏览器中打开主页时都会显示一个独特的名称和颜色方案。

当我们将长时间运行的进程部署到 Kubernetes 时，我们可以使用标签以受控的方式推出对应用程序的访问。

实施的最简单策略是使用单个部署来推出对应用程序新版本的更改。

为了实现这一点，我们需要首先创建一个带有标签选择器的服务，该选择器将匹配我们现在或将来可能部署的应用程序的每个版本：

```
service.yaml 
apiVersion: v1
kind: Service
metadata:
  name: ver
spec:
  selector:
    app: ver
  ports:
  - protocol: TCP
    port: 80
    targetPort: http
```

在这种情况下，我们通过匹配具有与`selector`相匹配的标签`app: ver`的任何 pod 来实现这一点。

当运行一个更复杂的应用程序，该应用程序由多个部署管理的多个不同进程组成时，您的标签和选择器将需要更复杂。一个常见的模式是使用`component`标签区分应用程序的组件部分。

在开始任何 pod 之前提交服务定义是有意义的。这是因为调度程序将尽可能地尝试将特定服务使用的 pod 分布在多个节点上，以提高可靠性。

使用`kubectl apply -f service.yaml`将服务定义提交到您的集群。

一旦服务提交到集群，我们可以准备初始部署：

```
deployment.yaml apiVersion: apps/v1
kind: Deployment
metadata:
  name: versions
  labels:
    app: ver
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ver
  template:
    metadata:
      labels:
        app: ver
        version: 0.0.1
    spec:
      containers:
      - name: version-server
        image: errm/versions:0.0.1
        ports:
        - name: http
          containerPort: 3000
```

要访问正在运行的服务，最简单的方法是使用`kubectl`打开代理到运行在您的集群上的 Kubernetes API：

```
$ kubectl proxy
Starting to serve on 127.0.0.1:8001
```

完成后，您应该能够使用浏览器在`http://localhost:8001/api/v1/namespaces/default/services/ver/proxy`查看应用程序。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/43c3e4f1-135f-4c5a-b3e5-a02ef4f97e85.png)

在我们的集群中运行的版本 0.0.1

现在我们有许多方法可以对我们的部署进行更改。

# kubectl patch

要升级到版本 0.0.2，我们将执行以下命令：

```
$ kubectl patch deployment/versions -p ' {"spec":{"template":{"spec":{"containers":[{"name":"version-server", "image":"errm/versions:0.0.2"}] }}}}'
```

因为容器是一个列表，我们需要为 Kubernetes 指定合并键`name`，以便理解我们要更新图像字段的容器。

使用`patch`命令，Kubernetes 执行合并，将提供的 JSON 与`deployment/versions`对象的当前定义进行合并。

继续在浏览器中重新加载应用程序，然后您应该会注意到（几秒钟后）应用程序的新版本变为可用。

# kubectl edit

要升级到版本 0.0.3，我们将使用`kubectl edit`命令：

```
kubectl edit deployment/versions
```

`kubectl edit`使用您系统的*标准*编辑器来编辑 Kubernetes 资源。通常是 vi、vim，甚至是 ed，但如果您有其他更喜欢的文本编辑器，您应该设置`EDITOR`环境变量指向您的首选选择。

这应该会打开您的编辑器，这样您就可以对部署进行更改。一旦发生这种情况，请将图像字段编辑为使用版本 0.0.3 并保存文件。

您可能会注意到在您的编辑器中打开的对象中有比您提交给 Kubernetes 的原始文件中更多的字段。这是因为 Kubernetes 在此对象中存储有关部署当前状态的元数据。

# kubectl apply

要升级到版本 0.0.4，我们将使用`apply`命令。这允许我们将完整的资源提交给 Kubernetes，就像我们进行初始部署时一样。

首先编辑您的部署 YAML 文件，然后将图像字段更新为使用版本 0.0.4。保存文件，然后使用`kubectl`将其提交到 Kubernetes：

```
$ kubectl apply -f deployment.yaml
```

如果您使用`kubectl apply`来创建尚不存在的资源，它将为您创建。如果您在脚本化部署中使用它，这可能会很有用。

使用`kubectl apply`而不是 edit 或 patch 的优势在于，您可以保持将文件提交到版本控制以表示集群状态。

# Kubernetes 仪表板

Kubernetes 仪表板包括一个基于树的编辑器，允许您直接在浏览器中编辑资源。在 Minikube 上，您可以运行 Minikube 仪表板以在浏览器中打开仪表板。然后，您可以选择您的部署并单击页面顶部的编辑按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-aws/img/ed270944-d34b-428c-861b-769b43553495.png)

您应该能够通过滚动或使用搜索功能找到容器图像字段。单击值进行编辑然后按**UPDATE**非常简单。

当您了解 Kubernetes 并尝试不同的配置时，您用于更新配置的方法应该是您自己的个人偏好。使用 Kubernetes 仪表板或诸如`kubectl edit`之类的工具非常适合学习和调试。但是，当您进入生产环境时，您将希望开始将您的配置检入版本控制，或者使用诸如 Helm（我们将在第五章中讨论的*使用 Helm 管理复杂应用*）之类的工具。

# 更好地控制您的部署

到目前为止，我们已经介绍了一些在 Kubernetes 中更新资源的方法。正如我们所观察到的，当我们在 Kubernetes 中更新部署时，集群中的 Pod 最终会更新以反映新的配置。

Kubernetes 通过在幕后管理 ReplicaSets 来实现这一点。

ReplicaSet 纯粹关注管理一组 Pod，以确保集群上运行所需数量的副本。在更新期间，现有 ReplicaSet 的 Pod 规范永远不会更改。部署控制器会使用新的 Pod 配置创建一个新的 ReplicaSet。通过改变每个 ReplicaSet 的所需副本数量来编排这种新配置的推出。

这种关注点的分离是 Kubernetes 中资源设计的典型方式。通过编排更简单的对象，其控制器实现更简单的行为来实现更复杂的行为。

这种设计还使我们（集群操作员）能够非常简单地决定在更新配置时我们想要的确切行为。`spec.stratergy`字段用于配置推出更改时使用的行为。

`.spec.strategy.type`字段定义了用于用新的 Pod 替换旧的 Pod 的策略。目前有两种策略：`Recreate`和`RollingUpdate`。`RollingUpdate`是默认策略，因此通常您不需要在配置中指定它。

# 滚动更新部署

`.spec.strategy.type=RollingUpdate 是默认策略`。这是我们迄今为止在示例中使用的策略。

当您想要在不中断服务的情况下进行更新时，您会明确选择滚动更新。相反，如果您使用此策略，您的应用程序必须在同时运行多个版本时正确工作。

在使用`RollingUpdate`策略时，有两个设置允许我们指定新的 ReplicaSet 如何快速扩展，旧的 ReplicaSet 如何快速缩减：

+   `.spec.strategy.rollingUpdate.maxUnavailable`：它指定在部署过程中可以不可用的 Pod 数量（超出所需总数）。

+   `.spec.strategy.rollingUpdate.maxSurge`：它指定在部署过程中可以创建的 Pod 数量，超出所需总数。

这些设置接受绝对值，例如 1 或 0，或部署中所需的总 Pod 数量的百分比。百分比值在以下情况下很有用：如果您打算使此配置可在不同级别进行扩展的不同部署中重复使用，或者如果您打算使用自动扩展机制来控制所需的 Pod 数量。

通过将`maxUnavailable`设置为`0`，Kubernetes 将等待替换的 Pod 被调度并运行，然后再杀死由旧的 ReplicationSet 管理的任何 Pod。如果以这种方式使用`maxUnavailable`，那么在部署过程中，Kubernetes 将运行超出所需数量的 Pod，因此`maxSurge`不能为`0`，并且您必须具有所需的资源（在集群中和用于后备服务）来支持在部署阶段临时运行额外的实例。

一旦 Kubernetes 启动了所有实例，它必须等待新的 Pod 处于服务状态并处于`Ready`状态。这意味着如果您为 Pod 设置了健康检查，如果这些检查失败，部署将暂停。

如果`maxSurge`和/或`maxUnavailable`设置为较低的值，部署将需要更长时间，因为部署将暂停并等待新的 Pod 可用后才能继续。这是有用的，因为它可以在部署损坏的代码或配置时提供一定程度的保护。

将`maxSurge`设置为更大的值将减少部署更新应用程序所需的扩展步骤的数量。例如，如果将`maxSurge`设置为 100%，`maxUnavailable`设置为 0，那么 Kubernetes 将在部署开始时创建所有替换的 Pod，并在新的 Pod 进入 Ready 状态时杀死现有的 Pod。

确切地配置部署将取决于应用程序的要求和集群可用的资源。

您应该记住，将`maxSurge`设置为较低的值将使部署速度较慢，需要更长的时间来完成，但可能更具有错误的弹性，而较高的`maxSurge`值将使您的部署进展更快。但您的集群需要具有足够的容量来支持额外的运行实例。如果您的应用程序访问其他服务，您还应该注意可能对它们施加的额外负载。例如，数据库可以配置为接受的连接数量有限。

# 重新创建部署

`.spec.strategy.type=Recreate`采用了一种更简单的方法来推出对应用程序的更改。首先，通过缩减活动的 ReplicaSet 来终止具有先前配置的所有 pod，然后创建一个启动替换 pod 的新 ReplicaSet。

当您不介意短暂的停机时间时，这种策略特别合适。例如，在后台处理中，当工作程序或其他任务不需要提供通过网络访问的服务时。在这些用例中的优势是双重的。首先，您不必担心由同时运行两个版本的代码引起的任何不兼容性。其次，当然，使用这种策略更新您的 pod 的过程不会使用比您的应用程序通常需要的更多资源。

# DaemonSet

如果您希望特定 pod 的单个实例在集群的每个节点（或节点的子集）上运行，则需要使用 DaemonSet。当您将 DaemonSet 调度到集群时，您的 pod 的一个实例将被调度到每个节点，并且当您添加新节点时，该 pod 也会被调度到那里。DaemonSet 非常适用于提供需要在集群的每个地方都可用的普遍服务。您可能会使用 DaemonSet 来提供以下服务：

+   用于摄取和传送日志的代理，如 Fluentd 或 Logstash

+   监控代理，如 collectd、Prometheus Node Exporter、datadog、NewRelic 或 SysDig 等

+   用于分布式存储系统的守护程序，如 Gluster 或 Ceph

+   用于覆盖网络的组件，如 Calico 或 Flannel

+   每个节点组件，如 OpenStack 虚拟化工具

在 Kubernetes 之前，这些类型的服务将要求您在基础设施中的每台服务器上配置一个 init 系统，例如`systemd`或 SysVnit。当您要更新服务或其配置时，您将不得不更新该配置并重新启动所有服务器上的服务，当您管理少量服务器时，这并不是问题，但是当您有数十、数百甚至数千台服务器时，事情很快变得更加难以管理。

DaemonSet 允许您使用与您正在管理基础设施的应用程序相同的配置和容器化。

让我们看一个简单的例子，以了解如何为有用的目的创建一个 DaemonSet。我们将部署 Prometheus Node Exporter。这个应用程序的目的是公开一个包含有关其正在运行的 Linux 系统的指标的 HTTP 端点。

如果您决定监视您的集群，Prometheus Node Exporter 是一个非常有用的工具。如果您决定在自己的集群中运行它，我建议您查看 GitHub 页面上提供的广泛文档[`github.com/prometheus/node_exporter`](https://github.com/prometheus/node_exporter)。

这个清单会导致在模板部分指定的 pod 被调度到您集群中的每个节点上：

```
node-exporter.yaml 
apiVersion: apps/v1 
kind: DaemonSet 
metadata: 
  labels: 
    app: node-exporter 
  name: node-exporter 
spec: 
  selector: 
    matchLabels: 
      app: node-exporter 
  template: 
    metadata: 
      labels: 
        app: node-exporter 
    spec: 
      containers: 
      - name: node-exporter 
        image: quay.io/prometheus/node-exporter:v0.15.2 
        args: 
        - --path.procfs=/host/proc 
        - --path.sysfs=/host/sys 
        volumeMounts: 
        - mountPath: /host/proc 
          name: proc 
          readOnly: false 
        - mountPath: /host/sys 
          name: sys 
          readOnly: false 
        ports: 
        - containerPort: 9100 
          hostPort: 9100 
      hostNetwork: true 
      hostPID: true 
      volumes: 
      - hostPath: 
          path: /proc 
        name: proc 
      - hostPath: 
          path: /sys 
        name: sys 
```

一旦您准备好 Node Exporter 的清单文件，通过运行`kubectl apply -f node-exporter.yaml`命令将其提交到 Kubernetes。

您可以通过运行`kubectl describe ds/node-exporter`命令来检查 DaemonSet 控制器是否已正确将我们的 pod 调度到集群中的节点。假设 pod 成功运行，您应该能够在其中一个节点的端口`9100`上发出 HTTP 请求，以查看其公开的指标。

如果您在 Minikube 上尝试此示例，可以通过运行`minikube ip`来发现集群中（唯一）节点的 IP 地址。

然后您可以使用`curl`等工具发出请求：

`**curl 192.168.99.100:9100/metrics**`

使用 DaemonSet 来管理基础设施工具和组件的一个关键优势是，它们可以像您在集群上运行的任何其他应用程序一样轻松更新，而不是依赖于节点上的静态配置来管理它们。

默认情况下，DaemonSet 具有`updateStrategy`为`RollingUpdate`。这意味着如果您编辑了 DaemonSet 中的 pod 模板，当前在集群上运行的现有 pod 将被逐个杀死并替换。

让我们尝试使用此功能来升级到 Prometheus Node Exporter 的新版本：

```
kubectl set image ds/node-exporter node-exporter=quay.io/prometheus/node-exporter:v0.16.0
```

您可以通过运行`kubectl rollout status ds/node-exporter`命令来查看替换旧版本的 pod 的进度。一旦更新完成，您应该会看到以下消息：`daemon set "node-exporter" successfully rolled out`。

您可能想知道 DaemonSet 还有哪些其他`updateStrategys`可用。唯一的其他选项是`OnDelete`。使用此选项时，当 DaemonSet 更新时，不会对集群上运行的现有 pod 进行任何更改，您需要手动删除运行的 pod，然后再启动新版本。这主要是为了与 Kubernetes 先前版本中的行为兼容，并且在实践中并不是非常有用。

值得注意的是，为了部署一个带有 DaemonSet 的新版本的 pod，旧的 pod 被杀死并启动新的 pod 之间会有一个短暂的时间，在此期间您运行的服务将不可用。

DaemonSet 也可以用于在集群中的节点子集上运行 pod。这可以通过为集群中的节点打标签并在 DaemonSet 的 pod 规范中添加`nodeSelector`来实现：

```
... 
    spec: 
      nodeSelector: 
        monitoring: prometheus 
      containers: 
      - name: node-exporter 
... 
```

一旦您编辑了清单以添加`nodeSelector`，请使用以下命令将新配置提交给 Kubernetes：`kubectl apply -f node-exporter.yaml`。

您应该注意到正在运行的节点导出器 pod 被终止并从集群中删除。这是因为您的集群中没有节点与我们添加到 DaemonSet 的标签选择器匹配。可以使用`kubectl`动态地为节点打标签。

```
kubectl label node/<node name> monitoring=prometheus      
```

一旦节点被正确标记，您应该注意到 DaemonSet 控制器会将一个 pod 调度到该节点上。

在 AWS 上，节点会自动带有标签，包括区域、可用区、实例类型和主机名等信息。您可能希望使用这些标签将服务部署到集群中的特定节点，或者为集群中不同类型的节点提供不同配置版本的工具。

如果您想添加额外的标签，可以使用`--node-labels`标志将它们作为参数传递给 kubelet。

# 总结

在本章中，我们学习了如何使用 Kubernetes 来运行我们的应用程序，以及如何推出新版本的应用程序和它们的配置。

我们在前几章基础知识的基础上构建了对 pod 和部署的了解。

+   Pod 是 Kubernetes 提供给我们的最低级抽象。

+   所有其他处理容器运行的资源，如作业、ScheduledJobs、部署，甚至 DaemonSet，都是通过特定方式创建 pod 来工作的。

+   通常，我们不希望直接创建 pod，因为如果运行 pod 的节点停止工作，那么 pod 也将停止工作。使用其中一个高级控制器可以确保创建新的 pod 来替换失败的 pod。

+   高级资源，如部署和 DaemonSet，提供了一种以受控方式用不同版本的 pod 替换另一个版本的机制。我们了解了可用于执行此操作的不同策略。

在进入下一章之前，花点时间通过观察部署过程中它们的行为来了解每种部署策略的工作方式。通过一些经验，您将了解在给定应用程序中选择哪些选项。

在下一章中，我们将学习如何使用一个工具，该工具基于这些概念提供了更强大的部署和更新应用程序的方式。
