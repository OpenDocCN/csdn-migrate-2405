# Docker 学习手册第二版（一）

> 原文：[`zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8`](https://zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

开发人员面临着越来越大的压力，需要以高速部署高度分布式应用程序。运维工程师正在寻找一个统一的部署策略，涵盖他们不断增长的应用程序组合的大部分或全部内容，利益相关者希望保持总体拥有成本低。Docker 容器与 Kubernetes 等容器编排器结合使用，帮助他们实现这些目标。

Docker 容器加速并简化了高度分布式应用程序的构建、交付和运行。容器加速了 CI/CD 流水线，容器化的应用程序允许公司在一个共同的部署平台上实现标准化，如 Kubernetes。容器化的应用程序更安全，并且可以在任何能够运行容器的平台上运行，无论是在本地还是在云端。

# 这本书适合谁

本书面向系统管理员、运维工程师、DevOps 工程师以及有兴趣从零开始学习 Docker 的开发人员或利益相关者。

# 本书涵盖了什么内容

第一章《什么是容器，为什么我应该使用它们？》介绍了容器的概念以及它们在软件行业中为何如此有用。

第二章《建立工作环境》详细讨论了如何为开发人员、DevOps 和运维人员建立一个理想的工作环境，用于处理 Docker 容器。

第三章《掌握容器》解释了如何启动、停止和移除容器。我们还将看到如何检查容器以从中检索额外的元数据。此外，我们将看到如何运行额外的进程，如何附加到已经运行的容器中的主进程，以及如何从容器中检索由其中运行的进程产生的日志信息。最后，本章介绍了容器的内部工作原理，包括 Linux 命名空间和组等内容。

第四章，《创建和管理容器镜像》，介绍了创建作为容器模板的容器镜像的不同方法。它介绍了镜像的内部结构以及它是如何构建的。本章还解释了如何将现有的遗留应用程序迁移，以便它可以在容器中运行。

第五章，《数据卷和配置》，介绍了可以被运行在容器中的有状态组件使用的数据卷。本章还展示了我们如何为容器内运行的应用程序定义单独的环境变量，以及如何使用包含整套配置设置的文件。

第六章，《在容器中运行代码调试》，讨论了常用的技术，允许开发人员在容器中运行代码时进行演变、修改、调试和测试。有了这些技术，开发人员将享受到类似于在本地开发运行应用程序时的无摩擦的开发过程。

第七章，《使用 Docker 来加速自动化》，展示了我们如何使用工具执行管理任务，而无需在主机计算机上安装这些工具。我们还将看到如何使用承载和运行测试脚本或用于测试和验证在容器中运行的应用程序服务的代码的容器。最后，本章指导我们完成构建基于 Docker 的简单 CI/CD 流水线的任务。

第八章，《高级 Docker 使用场景》，介绍了在将复杂的分布式应用程序容器化或使用 Docker 自动化复杂任务时有用的高级技巧、技巧和概念。

第九章，《分布式应用程序架构》，介绍了分布式应用程序架构的概念，并讨论了成功运行分布式应用程序所需的各种模式和最佳实践。最后，它讨论了在生产环境中运行此类应用程序需要满足的额外要求。

第十章，“单主机网络”，介绍了 Docker 容器网络模型及其在桥接网络形式下的单主机实现。本章介绍了软件定义网络的概念，并解释了它们如何用于保护容器化应用程序。还讨论了如何将容器端口对外开放，从而使容器化组件可以从外部访问。最后，介绍了 Traefik，一个反向代理，可以实现容器之间复杂的 HTTP 应用级路由。

第十一章，“Docker Compose”，讨论了由多个服务组成的应用程序的概念，每个服务在一个容器中运行，以及 Docker Compose 如何允许我们使用声明性方法轻松构建、运行和扩展这样的应用程序。

第十二章，“编排器”，介绍了编排器的概念。它解释了为什么需要编排器以及它们的工作原理。本章还概述了最流行的编排器，并列举了它们的一些优缺点。

第十三章，“Docker Swarm 简介”，介绍了 Docker 的本地编排器 SwarmKit。我们将了解 SwarmKit 用于在本地或云中部署和运行分布式、具有弹性、健壮和高可用性应用程序所使用的所有概念和对象。本章还介绍了 SwarmKit 如何通过软件定义网络来确保安全应用程序，以隔离容器，并使用秘密来保护敏感信息。此外，本章还展示了如何在云中安装高可用的 Docker Swarm。它介绍了路由网格，提供第 4 层路由和负载平衡。最后，展示了如何将由多个服务组成的应用程序部署到 Swarm 上。

第十四章，“零停机部署和秘密”，解释了如何在 Docker 集群上部署服务或应用程序，实现零停机和自动回滚功能。还介绍了秘密作为保护敏感信息的手段。

第十五章，“Kubernetes 简介”，介绍了当前最流行的容器编排器。它介绍了用于在集群中定义和运行分布式、有弹性、健壮和高可用应用程序的核心 Kubernetes 对象。最后，它介绍了 MiniKube 作为在本地部署 Kubernetes 应用程序的一种方式，以及 Kubernetes 与 Docker for Mac 和 Docker for Windows 的集成。

第十六章，“使用 Kubernetes 部署、更新和保护应用程序”，解释了如何将应用程序部署、更新和扩展到 Kubernetes 集群中。它还解释了如何使用活跃性和就绪性探针来为 Kubernetes 支持健康和可用性检查。此外，该章还解释了如何实现零停机部署，以实现对关键任务应用程序的无干扰更新和回滚。最后，该章介绍了 Kubernetes secrets 作为配置服务和保护敏感数据的手段。

第十七章，“监控和故障排除正在生产中运行的应用程序”，教授了监视在 Kubernetes 集群上运行的单个服务或整个分布式应用程序的不同技术。它还展示了如何在不更改集群或运行服务的集群节点的情况下，对正在生产中运行的应用程序服务进行故障排除。

第十八章，“在云中运行容器化应用程序”，概述了在云中运行容器化应用程序的一些最流行的方式。我们包括自托管和托管解决方案，并讨论它们的优缺点。微软 Azure 和谷歌云引擎等供应商的完全托管服务也进行了简要讨论。

# 为了充分利用本书

期望对分布式应用程序架构有扎实的理解，并对加速和简化构建、交付和运行高度分布式应用程序感兴趣。不需要有 Docker 容器的先前经验。

强烈建议使用安装了 Windows 10 专业版或 macOS 的计算机。计算机应至少具有 16GB 内存。

| **书中涵盖的软件/硬件** | **操作系统要求** |
| --- | --- |
| Docker for Desktop, Docker Toolbox, Visual Studio Code, Powershell 或 Bash 终端。 | Windows 10 Pro/macOS/Linux 至少 8GB RAM |

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 仓库访问代码（链接在下一节中提供）。这样做将有助于避免与复制/粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition`](https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition)。如果代码有更新，将在现有的 GitHub 仓库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838827472_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781838827472_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："Docker 主机上的容器运行时由 `containerd` 和 `runc` 组成。"

代码块设置如下：

```
{
  "name": "api",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
ARG BASE_IMAGE_VERSION=12.7-stretch
FROM node:${BASE_IMAGE_VERSION}
WORKDIR /app
COPY packages.json .
RUN npm install
COPY . .
CMD npm start
```

任何命令行输入或输出都是这样写的：

```
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子：“从管理面板中选择系统信息。”

警告或重要提示会这样出现。提示和技巧会这样出现。


# 第一部分：动机和入门

*第一部分*的目标是向您介绍容器的概念，并解释为什么它们在软件行业中如此有用。您还将为使用 Docker 准备您的工作环境。

本节包括以下章节：

+   第一章，*什么是容器，为什么我应该使用它们？*

+   第二章，*设置工作环境*


# 第一章：什么是容器，为什么我应该使用它们？

本章将向您介绍容器及其编排的世界。本书从最基础的知识开始，假设您对容器没有先前的了解，并将为您提供一个非常实用的主题介绍。

在本章中，我们将关注软件供应链及其中的摩擦。然后，我们将介绍容器，这些容器用于减少这种摩擦，并在其上添加企业级安全性。我们还将探讨容器及其生态系统是如何组装的。我们将特别指出上游开源软件（OSS）组件的区别，这些组件统一在代号 Moby 下，构成了 Docker 和其他供应商的下游产品的基本组成部分。

本章涵盖以下主题：

+   什么是容器？

+   为什么容器很重要？

+   对我或我的公司有什么好处？

+   Moby 项目

+   Docker 产品

+   容器架构

完成本模块后，您将能够做到以下事项：

+   用类似于物理容器的类比，向感兴趣的普通人解释容器是什么，用简单的几句话

+   用类似于物理容器与传统船运或公寓与独栋住宅等的类比来证明容器为何如此重要，以便向感兴趣的普通人解释

+   至少列出四个上游开源组件，这些组件被 Docker 产品使用，比如 Docker for Desktop

+   至少识别三个 Docker 产品

# 什么是容器？

软件容器是一个相当抽象的东西，因此，如果我们从一个对大多数人来说应该很熟悉的类比开始，可能会有所帮助。这个类比是运输行业中的集装箱。在历史上，人们一直通过各种方式从一个地方运输货物到另一个地方。在轮子发明之前，货物很可能是由人们自己的肩膀上的袋子、篮子或箱子运输的，或者他们可能使用驴、骆驼或大象等动物来运输它们。

随着轮子的发明，交通变得更加高效，因为人类修建了可以沿着道路移动他们的车辆。一次可以运输更多的货物。当第一台蒸汽驱动的机器，以及后来的汽油驱动引擎被引入时，交通变得更加强大。现在我们通过火车、船舶和卡车运输大量货物。与此同时，货物的种类变得越来越多样化，有时处理起来也更加复杂。

在这几千年的时间里，有一件事情没有改变，那就是在目的地卸货，也许将它们装载到另一种交通工具上的必要性。例如，一个农民将满满一车的苹果运到中央火车站，然后这些苹果与其他农民的苹果一起装上火车。或者想象一下，一位酿酒师用卡车将他的酒桶运到港口，然后卸货，然后转移到一艘将它们运往海外的船上。

这种从一种交通工具卸货，然后装载到另一种交通工具的过程是非常复杂和繁琐的。每种产品都以自己的方式包装，因此必须以自己的特定方式处理。此外，散装货物面临着被不道德的工人偷窃或在处理过程中受损的风险。

然后，集装箱出现了，它们彻底改变了运输行业。集装箱只是一个标准尺寸的金属箱子。每个集装箱的长度、宽度和高度都是相同的。这是一个非常重要的点。如果世界没有就一个标准尺寸达成一致，整个集装箱的事情就不会像现在这样成功。

现在，有了标准化的集装箱，想要将货物从 A 运送到 B 的公司将这些货物打包进这些集装箱中。然后，他们会联系一家船运公司，该公司配备了标准化的运输工具。这可以是一辆可以装载集装箱的卡车，或者每个运输一个或多个集装箱的火车车厢。最后，我们有专门运输大量集装箱的船只。船运公司永远不需要拆包和重新包装货物。对于船运公司来说，集装箱只是一个黑匣子，他们对其中的内容不感兴趣，在大多数情况下也不应该关心。它只是一个具有标准尺寸的大铁箱。现在，将货物打包进集装箱完全交给了想要运输货物的各方，他们应该知道如何处理和打包这些货物。

由于所有集装箱都具有相同的约定形状和尺寸，船公司可以使用标准化工具来处理集装箱；也就是说，用于卸载集装箱的起重机，比如从火车或卡车上卸载集装箱，并将其装上船舶，反之亦然。一种类型的起重机足以处理随时间而来的所有集装箱。此外，运输工具也可以标准化，比如集装箱船、卡车和火车。

由于所有这些标准化，围绕货物运输的所有流程也可以标准化，因此比集装箱时代之前的货物运输更加高效。

现在，你应该对为什么集装箱如此重要以及为什么它们彻底改变了整个运输行业有了很好的理解。我特意选择了这个类比，因为我们要在这里介绍的软件容器在所谓的软件供应链中扮演着与集装箱在实物货物供应链中扮演的完全相同的角色。

在过去，开发人员会开发一个新的应用程序。一旦他们认为该应用程序已经完成，他们会将该应用程序交给运维工程师，然后运维工程师应该在生产服务器上安装它并使其运行。如果运维工程师幸运的话，他们甚至可以从开发人员那里得到一份相对准确的安装说明文档。到目前为止，一切都很顺利，生活也很容易。

但当一个企业中有许多开发团队创建了完全不同类型的应用程序，但所有这些应用程序都需要安装在同一生产服务器上并在那里运行时，情况就有点失控了。通常，每个应用程序都有一些外部依赖项，比如它是基于哪个框架构建的，它使用了哪些库等等。有时，两个应用程序使用相同的框架，但是版本不同，这些版本可能与彼此兼容，也可能不兼容。我们的运维工程师的工作变得越来越困难。他们必须非常有创意地想办法在不破坏任何东西的情况下，将不同的应用程序加载到他们的船上（服务器）上。

现在安装某个应用程序的新版本已经成为一个复杂的项目，通常需要数月的规划和测试。换句话说，在软件供应链中存在很多摩擦。但如今，公司越来越依赖软件，发布周期需要变得越来越短。我们不能再负担得起每年只发布两次或更少的情况了。应用程序需要在几周或几天内进行更新，有时甚至一天内进行多次更新。不遵守这一点的公司会因缺乏灵活性而面临倒闭的风险。那么，解决方案是什么呢？

最初的方法之一是使用**虚拟机**（**VMs**）。公司不再在同一台服务器上运行多个应用程序，而是将单个应用程序打包并在每个虚拟机上运行。这样一来，所有的兼容性问题都消失了，生活似乎又变得美好起来。不幸的是，这种幸福感并没有持续多久。虚拟机本身就非常庞大，因为它们都包含了一个完整的操作系统，比如 Linux 或 Windows Server，而这一切只是为了运行一个应用程序。这就好像在运输行业中，你使用整艘船只是为了运输一车香蕉。多么浪费！这是永远不可能盈利的。

这个问题的最终解决方案是提供比虚拟机更轻量级的东西，但也能完美地封装需要传输的货物。在这里，货物是由我们的开发人员编写的实际应用程序，以及 - 这一点很重要 - 应用程序的所有外部依赖项，例如其框架、库、配置等。这种软件打包机制的圣杯就是 *Docker 容器*。

开发人员使用 Docker 容器将他们的应用程序，框架和库打包到其中，然后将这些容器发送给测试人员或运维工程师。对于测试人员和运维工程师来说，容器只是一个黑匣子。尽管如此，它是一个标准化的黑匣子。所有容器，无论其中运行什么应用程序，都可以被平等对待。工程师们知道，如果他们的服务器上运行任何容器，那么任何其他容器也应该运行。这实际上是真的，除了一些边缘情况，这种情况总是存在的。

因此，Docker 容器是一种以标准化方式打包应用程序及其依赖项的手段。Docker 随后创造了短语*构建，交付和在任何地方运行*。

# 为什么容器很重要？

如今，应用程序发布之间的时间变得越来越短，但软件本身并没有变得更简单。相反，软件项目的复杂性增加了。因此，我们需要一种方法来驯服野兽并简化软件供应链。

此外，我们每天都听说网络攻击正在上升。许多知名公司受到了安全漏洞的影响。在这些事件中，高度敏感的客户数据被盗，如社会安全号码，信用卡信息等。但不仅仅是客户数据受到了损害 - 敏感的公司机密也被窃取。

容器可以在许多方面提供帮助。首先，Gartner 发现在容器中运行的应用程序比不在容器中运行的应用程序更安全。容器使用 Linux 安全原语，如 Linux 内核*命名空间*来隔离在同一台计算机上运行的不同应用程序，以及**控制组**（**cgroups**）以避免嘈杂邻居问题，即一个糟糕的应用程序使用服务器的所有可用资源并使所有其他应用程序陷入困境。

由于容器图像是不可变的，很容易对其进行扫描以查找**常见漏洞和暴露**（**CVEs**），从而提高我们应用程序的整体安全性。

另一种使我们的软件供应链更加安全的方法是让我们的容器使用内容信任。内容信任基本上确保容器图像的作者是他们所声称的，并且容器图像的消费者有保证图像在传输过程中没有被篡改。后者被称为**中间人攻击**（**MITM**）。

当然，我刚才说的一切在没有使用容器的情况下也是技术上可能的，但是由于容器引入了一个全球公认的标准，它们使得实施这些最佳实践并强制执行它们变得更加容易。

好吧，但安全性并不是容器重要的唯一原因。还有其他原因。

一个原因是容器使得在开发人员的笔记本电脑上轻松模拟类似生产环境。如果我们可以将任何应用程序容器化，那么我们也可以将诸如 Oracle 或 MS SQL Server 之类的数据库容器化。现在，每个曾经在计算机上安装 Oracle 数据库的人都知道这并不是一件容易的事情，而且会占用大量宝贵的空间。你不会想要在你的开发笔记本上做这件事，只是为了测试你开发的应用程序是否真的能够端到端地工作。有了容器，我们可以像说 123 一样轻松地在容器中运行一个完整的关系型数据库。当测试完成后，我们可以停止并删除容器，数据库就会消失，不会在我们的计算机上留下任何痕迹。

由于容器与虚拟机相比非常精简，因此在开发人员的笔记本电脑上同时运行多个容器而不会使笔记本电脑不堪重负并不罕见。

容器之所以重要的第三个原因是，运营商最终可以集中精力做他们真正擅长的事情：提供基础设施、运行和监控生产中的应用程序。当他们需要在生产系统上运行的应用程序都被容器化时，运营商可以开始标准化他们的基础设施。每台服务器都只是另一个 Docker 主机。这些服务器上不需要安装特殊的库或框架，只需要一个操作系统和一个像 Docker 这样的容器运行时。

此外，运营商不再需要对应用程序的内部有深入的了解，因为这些应用程序在容器中自包含，对他们来说应该看起来像黑匣子一样，类似于运输行业的人员看待集装箱的方式。

# 对我或我的公司有什么好处？

有人曾经说过，今天，每家规模一定的公司都必须承认他们需要成为一家软件公司。从这个意义上讲，现代银行是一家专门从事金融业务的软件公司。软件驱动着所有的业务。随着每家公司都成为了一家软件公司，就需要建立一个软件供应链。为了保持竞争力，他们的软件供应链必须安全高效。通过彻底的自动化和标准化，可以实现效率。但在安全、自动化和标准化这三个领域，容器已经被证明是非常出色的。一些大型知名企业已经报告说，当他们将现有的传统应用程序（许多人称之为传统应用程序）容器化，并建立基于容器的完全自动化软件供应链时，他们可以将这些关键应用程序的维护成本降低 50%至 60%，并且可以将这些传统应用程序的新版本发布时间缩短 90%。

也就是说，采用容器技术可以为这些公司节省大量资金，同时加快开发过程并缩短上市时间。

# Moby 项目

最初，当 Docker（公司）推出 Docker 容器时，一切都是开源的。当时 Docker 没有任何商业产品。公司开发的 Docker 引擎是一个庞大的软件单体。它包含许多逻辑部分，如容器运行时、网络库、RESTful（REST）API、命令行界面等等。

其他供应商或项目，如红帽或 Kubernetes，都在他们自己的产品中使用 Docker 引擎，但大多数情况下，他们只使用了其部分功能。例如，Kubernetes 没有使用 Docker 引擎的网络库，而是提供了自己的网络方式。红帽则不经常更新 Docker 引擎，而更倾向于对旧版本的 Docker 引擎应用非官方的补丁，但他们仍然称之为 Docker 引擎。

出于这些原因以及许多其他原因，出现了这样一个想法，即 Docker 必须做一些事情，以清楚地将 Docker 开源部分与 Docker 商业部分分开。此外，公司希望阻止竞争对手利用和滥用 Docker 这个名字来谋取自己的利益。这就是 Moby 项目诞生的主要原因。它作为 Docker 开发和继续开发的大多数开源组件的总称。这些开源项目不再带有 Docker 的名称。

Moby 项目提供了用于图像管理、秘密管理、配置管理和网络和配置等的组件，仅举几例。此外，Moby 项目的一部分是特殊的 Moby 工具，例如用于将组件组装成可运行的工件。

从技术上属于 Moby 项目的一些组件已经被 Docker 捐赠给了云原生计算基金会（CNCF），因此不再出现在组件列表中。最突出的是`notary`、`containerd`和`runc`，其中第一个用于内容信任，后两者形成容器运行时。

# Docker 产品

Docker 目前将其产品线分为两个部分。有**社区版**（**CE**），它是闭源的，但完全免费，然后还有**企业版**（**EE**），它也是闭源的，需要按年度许可。这些企业产品得到 24/7 支持，并得到错误修复的支持。

# Docker CE

Docker 社区版的一部分是产品，如 Docker 工具箱和适用于 Mac 和 Windows 的 Docker 桌面版。所有这些产品主要面向开发人员。

Docker 桌面版是一个易于安装的桌面应用程序，可用于在 macOS 或 Windows 机器上构建、调试和测试 Docker 化的应用程序或服务。Docker for macOS 和 Docker for Windows 是与各自的虚拟化框架、网络和文件系统深度集成的完整开发环境。这些工具是在 Mac 或 Windows 上运行 Docker 的最快、最可靠的方式。

在 CE 的总称下，还有两个更偏向于运维工程师的产品。这些产品是 Docker for Azure 和 Docker for AWS。

例如，对于 Docker for Azure，这是一个本地 Azure 应用程序，您可以通过几次点击设置 Docker，优化并与底层 Azure **基础设施即服务**（**IaaS**）服务集成。它帮助运维工程师在 Azure 中构建和运行 Docker 应用程序时加快生产力。

Docker for AWS 的工作方式非常类似，但适用于亚马逊的云。

# Docker EE

Docker 企业版由**Universal Control Plane**（**UCP**）和**Docker Trusted Registry**（**DTR**）组成，两者都运行在 Docker Swarm 之上。两者都是 Swarm 应用程序。Docker EE 基于 Moby 项目的上游组件，并添加了企业级功能，如**基于角色的访问控制**（**RBAC**）、多租户、混合 Docker Swarm 和 Kubernetes 集群、基于 Web 的 UI 和内容信任，以及顶部的镜像扫描。

# 容器架构

现在，让我们讨论一下高层次上如何设计一个能够运行 Docker 容器的系统。以下图表说明了安装了 Docker 的计算机的外观。请注意，安装了 Docker 的计算机通常被称为 Docker 主机，因为它可以运行或托管 Docker 容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/07669239-7cef-4bc6-ab0e-2e70c47473e4.png)

Docker 引擎的高级架构图

在上图中，我们可以看到三个基本部分：

+   在底部，我们有**Linux 操作系统**

+   在中间，深灰色部分，我们有容器运行时

+   在顶部，我们有**Docker 引擎**

容器之所以可能，是因为 Linux 操作系统提供了一些原语，比如命名空间、控制组、层功能等，所有这些都是由容器运行时和 Docker 引擎以非常特定的方式利用的。Linux 内核的命名空间，比如**进程 ID**（**pid**）命名空间或**网络**（**net**）命名空间，允许 Docker 封装或隔离在容器内运行的进程。**控制组**确保容器不会遭受嘈杂邻居综合症，即运行在容器中的单个应用程序可能会消耗整个 Docker 主机的大部分或全部可用资源。**控制组**允许 Docker 限制每个容器分配的资源，比如 CPU 时间或内存量。

Docker 主机上的容器运行时由 `containerd` 和 `runc` 组成。`runc` 是容器运行时的低级功能，而基于 `runc` 的 `containerd` 提供了更高级的功能。两者都是开源的，并且已由 Docker 捐赠给 CNCF。

容器运行时负责容器的整个生命周期。如果需要，它会从注册表中拉取容器镜像（这是容器的模板），从该镜像创建容器，初始化和运行容器，最终在系统中停止并删除容器。

**Docker 引擎**提供了容器运行时的附加功能，例如网络库或插件支持。它还提供了一个 REST 接口，通过该接口可以自动化所有容器操作。我们将在本书中经常使用的 Docker 命令行界面是这个 REST 接口的消费者之一。

# 总结

在本章中，我们看到容器如何大大减少了软件供应链中的摩擦，并且使供应链更加安全。

在下一章中，我们将学习如何准备我们的个人或工作环境，以便我们可以高效有效地使用 Docker。所以，请继续关注。

# 问题

请回答以下问题，以评估您的学习进度：

1.  哪些陈述是正确的（可以有多个答案）？

A. 一个容器就像一个轻量级的虚拟机

B. 一个容器只能在 Linux 主机上运行

C. 一个容器只能运行一个进程

D. 容器中的主进程始终具有 PID 1

E. 一个容器是由 Linux 命名空间封装的一个或多个进程，并受 cgroups 限制

1.  用自己的话，可能通过类比，解释什么是容器。

1.  为什么容器被认为是 IT 领域的一个改变者？列出三到四个原因。

1.  当我们声称：*如果一个容器在给定平台上运行，那么它就可以在任何地方运行...* 时，这意味着什么？列出两到三个原因，说明为什么这是真的。

1.  Docker 容器只对基于微服务的现代绿地应用程序真正有用。请证明你的答案。

A. True

B. False

1.  当企业将其传统应用程序容器化时，通常可以节省多少成本？

A. 20%

B. 33%

C. 50%

D. 75%

1.  Linux 容器基于哪两个核心概念？

# 进一步阅读

以下是一些链接列表，这些链接可以带您了解本章讨论的主题的更详细信息：

+   Docker 概述：[`docs.docker.com/engine/docker-overview/`](https://docs.docker.com/engine/docker-overview/)

+   Moby 项目：[`mobyproject.org/`](https://mobyproject.org/)

+   Docker 产品：[`www.docker.com/get-started`](https://www.docker.com/get-started)

+   Cloud-Native Computing Foundation：[`www.cncf.io/`](https://www.cncf.io/)

+   containerd – 一个行业标准的容器运行时：[`containerd.io/`](https://containerd.io/)


# 第二章：设置工作环境

在上一章中，我们了解了 Docker 容器是什么，以及它们为什么重要。我们了解了容器在现代软件供应链中解决了哪些问题。

在这一章中，我们将准备我们的个人或工作环境，以便与 Docker 高效有效地工作。我们将详细讨论如何为开发人员、DevOps 和运维人员设置一个理想的环境，用于使用 Docker 容器时的工作。

本章涵盖以下主题：

+   Linux 命令 shell

+   Windows 的 PowerShell

+   安装和使用软件包管理器

+   安装 Git 并克隆代码存储库

+   选择并安装代码编辑器

+   在 macOS 或 Windows 上安装 Docker 桌面版

+   安装 Docker 工具箱

+   安装 Minikube

# 技术要求

对于本章，您将需要一台装有 macOS 或 Windows 的笔记本电脑或工作站，最好是安装了 Windows 10 专业版。您还应该有免费的互联网访问权限来下载应用程序，并且有权限在您的笔记本电脑上安装这些应用程序。

如果您的操作系统是 Linux 发行版，如 Ubuntu 18.04 或更新版本，也可以按照本书进行。我会尽量指出命令和示例与 macOS 或 Windows 上的命令有明显不同的地方。

# Linux 命令 shell

Docker 容器最初是在 Linux 上为 Linux 开发的。因此，用于与 Docker 一起工作的主要命令行工具，也称为 shell，是 Unix shell；请记住，Linux 源自 Unix。大多数开发人员使用 Bash shell。在一些轻量级的 Linux 发行版中，如 Alpine，Bash 未安装，因此必须使用更简单的 Bourne shell，简称为*sh*。每当我们在 Linux 环境中工作，比如在容器内或 Linux 虚拟机上，我们将使用`/bin/bash`或`/bin/sh`，具体取决于它们的可用性。

虽然苹果的 macOS X 不是 Linux 操作系统，但 Linux 和 macOS X 都是 Unix 的变种，因此支持相同的工具集。其中包括 shell。因此，在 macOS 上工作时，您可能会使用 Bash shell。

在本书中，我们期望您熟悉 Bash 和 PowerShell 中最基本的脚本命令。如果您是一个绝对的初学者，我们强烈建议您熟悉以下备忘单：

+   *Linux 命令行速查表*，作者是 Dave Child，网址是[`bit.ly/2mTQr8l`](http://bit.ly/2mTQr8l)

+   *PowerShell 基础速查表*，网址是[`bit.ly/2EPHxze`](http://bit.ly/2EPHxze)

# Windows 的 PowerShell

在 Windows 计算机、笔记本电脑或服务器上，我们有多个命令行工具可用。最熟悉的是命令行。几十年来，它一直可用于任何 Windows 计算机。它是一个非常简单的 shell。对于更高级的脚本编写，微软开发了 PowerShell。PowerShell 非常强大，在 Windows 上的工程师中非常受欢迎。最后，在 Windows 10 上，我们有所谓的*Windows 子系统用于 Linux*，它允许我们使用任何 Linux 工具，比如 Bash 或 Bourne shell。除此之外，还有其他工具可以在 Windows 上安装 Bash shell，例如 Git Bash shell。在本书中，所有命令都将使用 Bash 语法。大多数命令也可以在 PowerShell 中运行。

因此，我们建议您使用 PowerShell 或任何其他 Bash 工具来在 Windows 上使用 Docker。

# 使用软件包管理器

在 macOS 或 Windows 笔记本上安装软件的最简单方法是使用一个好的软件包管理器。在 macOS 上，大多数人使用 Homebrew，在 Windows 上，Chocolatey 是一个不错的选择。如果你使用的是像 Ubuntu 这样的基于 Debian 的 Linux 发行版，那么大多数人选择的软件包管理器是默认安装的`apt`。

# 在 macOS 上安装 Homebrew

Homebrew 是 macOS 上最流行的软件包管理器，易于使用且非常多功能。在 macOS 上安装 Homebrew 很简单；只需按照[`brew.sh/`](https://brew.sh/)上的说明操作即可：

1.  简而言之，打开一个新的终端窗口并执行以下命令来安装 Homebrew：

```
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  安装完成后，通过在终端中输入`brew --version`来测试 Homebrew 是否正常工作。你应该会看到类似这样的内容：

```
$ brew --version
Homebrew 2.1.4
Homebrew/homebrew-core (git revision 77d1b; last commit 2019-06-07)
```

1.  现在，我们准备使用 Homebrew 来安装工具和实用程序。例如，如果我们想要安装 Vi 文本编辑器，可以这样做：

```
$ brew install vim
```

这将为您下载并安装编辑器。

# 在 Windows 上安装 Chocolatey

Chocolatey 是 Windows 上基于 PowerShell 的流行软件包管理器。要安装 Chocolatey 软件包管理器，请按照[`chocolatey.org/`](https://chocolatey.org/)上的说明操作，或者以管理员模式打开一个新的 PowerShell 窗口并执行以下命令：

```
PS> Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

重要的是要以管理员身份运行上述命令，否则安装将不会成功。

1.  一旦安装了 Chocolatey，请使用`choco --version`命令进行测试。你应该看到类似以下的输出：

```
PS> choco --version
0.10.15
```

1.  要安装一个应用程序，比如 Vi 编辑器，使用以下命令：

```
PS> choco install -y vim
```

`-y`参数确保安装过程不需要再次确认。

请注意，一旦 Chocolatey 安装了一个应用程序，你需要打开一个新的 PowerShell 窗口来使用该应用程序。

# 安装 Git

我们正在使用 Git 从其 GitHub 存储库中克隆伴随本书的示例代码。如果你的计算机上已经安装了 Git，你可以跳过这一部分：

1.  要在 macOS 上安装 Git，请在终端窗口中使用以下命令：

```
$ choco install git
```

1.  要在 Windows 上安装 Git，请打开 PowerShell 窗口并使用 Chocolatey 进行安装：

```
PS> choco install git -y
```

1.  最后，在你的 Debian 或 Ubuntu 机器上，打开一个 Bash 控制台并执行以下命令：

```
$ sudo apt update && sudo apt install -y git
```

1.  安装完 Git 后，验证它是否正常工作。在所有平台上，使用以下命令：

```
$ git --version
```

这应该输出类似以下内容的东西：

```
git version 2.16.3
```

1.  现在 Git 正常工作了，我们可以从 GitHub 上克隆伴随本书的源代码。执行以下命令：

```
$ cd ~
$ git clone https://github.com/PacktPublishing/Learn-Docker---Fundamentals-of-Docker-19.x-Second-Edition fod-solution
```

这将把主分支的内容克隆到你的本地文件夹`~/fod-solution`中。现在这个文件夹将包含我们在本书中一起做的所有实验的示例解决方案。如果遇到困难，请参考这些示例解决方案。

现在我们已经安装了基础知识，让我们继续使用代码编辑器。

# 选择一个代码编辑器

使用一个好的代码编辑器对于高效地使用 Docker 是至关重要的。当然，哪个编辑器是最好的是非常有争议的，取决于个人偏好。很多人使用 Vim，或者其他一些编辑器，比如 Emacs，Atom，Sublime，或者 Visual Studio Code（VS Code），只是举几个例子。VS Code 是一个完全免费且轻量级的编辑器，但它非常强大，并且适用于 macOS，Windows 和 Linux。根据 Stack Overflow 的数据，它目前是迄今为止最受欢迎的代码编辑器。如果你还没有决定使用其他编辑器，我强烈建议你试试 VS Code。

但是，如果您已经有一个喜欢的代码编辑器，请继续使用它。只要您可以编辑文本文件，就可以继续前进。如果您的编辑器支持 Dockerfiles 和 JSON 和 YAML 文件的语法高亮显示，那就更好了。唯一的例外将是[第六章]（b6647803-2c5c-4b9d-9a4a-a836ac356329.xhtml），*在容器中运行的代码调试*。该章节中呈现的示例将大量定制为 VS Code。

# 在 macOS 上安装 VS Code

按照以下步骤进行安装：

1.  打开一个新的终端窗口并执行以下命令：

```
$ brew cask install visual-studio-code
```

1.  一旦 VS Code 安装成功，转到您的主目录（`~`）并创建一个名为`fundamentals-of-docker`的文件夹；然后进入这个新文件夹：

```
$ mkdir ~/fundamentals-of-docker && cd ~/fundamentals-of-docker
```

1.  现在从这个文件夹中打开 VS Code：

```
$ code .
```

不要忘记前面命令中的句号（.）。VS 将启动并打开当前文件夹（`~/fundamentals-of-docker`）作为工作文件夹。

# 在 Windows 上安装 VS Code

按照以下步骤进行安装：

1.  以管理员模式打开一个新的 PowerShell 窗口并执行以下命令：

```
PS> choco install vscode -y
```

1.  关闭您的 PowerShell 窗口并打开一个新窗口，以确保 VS Code 在您的路径中。

1.  现在转到您的主目录并创建一个名为`fundamentals-of-docker`的文件夹；然后进入这个新文件夹：

```
PS> mkdir ~\fundamentals-of-docker; cd ~\fundamentals-of-docker
```

1.  最后，从这个文件夹中打开 Visual Studio Code：

```
PS> code .
```

不要忘记前面命令中的句号（.）。VS 将启动并打开当前文件夹（`~\fundamentals-of-docker`）作为工作文件夹。

# 在 Linux 上安装 VS Code

按照以下步骤进行安装：

1.  在您的 Debian 或基于 Ubuntu 的 Linux 机器上，打开 Bash 终端并执行以下语句以安装 VS Code：

```
$ sudo snap install --classic code
```

1.  如果您使用的是不基于 Debian 或 Ubuntu 的 Linux 发行版，请按照以下链接获取更多详细信息：[`code.visualstudio.com/docs/setup/linux`](https://code.visualstudio.com/docs/setup/linux)

1.  一旦 VS Code 安装成功，转到您的主目录（`~`）并创建一个名为`fundamentals-of-docker`的文件夹；然后进入这个新文件夹：

```
$ mkdir ~/fundamentals-of-docker && cd ~/fundamentals-of-docker
```

1.  现在从这个文件夹中打开 Visual Studio Code：

```
$ code .
```

不要忘记前面命令中的句号（.）。VS 将启动并打开当前文件夹（`~/fundamentals-of-docker`）作为工作文件夹。

# 安装 VS Code 扩展

扩展是使 VS Code 成为如此多才多艺的编辑器的原因。在 macOS、Windows 和 Linux 三个平台上，您可以以相同的方式安装 VS Code 扩展：

1.  打开 Bash 控制台（或 Windows 中的 PowerShell），并执行以下一组命令，以安装我们将在本书中的示例中使用的最基本的扩展：

```
code --install-extension vscjava.vscode-java-pack
code --install-extension ms-vscode.csharp
code --install-extension ms-python.python
code --install-extension ms-azuretools.vscode-docker
code --install-extension eamodio.gitlens
```

我们正在安装一些扩展，使我们能够更加高效地使用 Java、C#、.NET 和 Python。我们还安装了一个扩展，用于增强我们与 Docker 的体验。

1.  在成功安装了上述扩展之后，重新启动 VS Code 以激活这些扩展。现在您可以点击 VS Code 左侧活动面板上的扩展图标，查看所有已安装的扩展。

接下来，让我们安装 Docker 桌面版。

# 安装 Docker 桌面版

如果您使用的是 macOS，或者在笔记本电脑上安装了 Windows 10 专业版，则我们强烈建议您安装 Docker 桌面版。这个平台在使用容器时会给您最好的体验。

目前，Docker 桌面版不支持 Linux。有关更多详细信息，请参阅*在 Linux 上安装 Docker CE*部分。请注意，旧版本的 Windows 或 Windows 10 家庭版无法运行 Docker for Windows。Docker for Windows 使用 Hyper-V 在虚拟机中透明地运行容器，但是 Hyper-V 在旧版本的 Windows 上不可用；在 Windows 10 家庭版中也不可用。在这种情况下，我们建议您使用 Docker Toolbox，我们将在下一节中描述。按照以下步骤进行操作：

1.  无论您使用什么操作系统，都可以导航到 Docker 的起始页面[`www.docker.com/get-started`](https://www.docker.com/get-started)。

1.  在加载的页面右侧，您会找到一个大大的蓝色按钮，上面写着 Download Desktop and Take a Tutorial。点击这个按钮并按照说明进行操作。您将被重定向到 Docker Hub。如果您还没有 Docker Hub 账户，请创建一个。这是完全免费的，但您需要一个账户来下载软件。否则，只需登录即可。

1.  一旦您登录，注意页面上的以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e00d0017-d436-41eb-b4f0-f7b35a4e5c8a.png)

在 Docker Hub 上下载 Docker 桌面版

1.  点击蓝色的 Download Docker Desktop 按钮。然后您应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c9a4cfdc-fdbb-44dd-bbaf-7999541220a6.png)

在 macOS 上下载 Docker 桌面版的屏幕提示请注意，如果您使用的是 Windows PC，蓝色按钮将会显示为 Download Docker Desktop for Windows。

# 在 macOS 上安装 Docker 桌面版

按照以下步骤进行安装：

1.  安装成功 Docker 桌面版后，请打开终端窗口并执行以下命令：

```
$ docker version
```

您应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c44f8efb-03f9-4991-8911-1baf60e21c35.png)

Docker 桌面版的 Docker 版本

1.  要查看是否可以运行容器，请在终端窗口中输入以下命令并按 Enter 键：

```
$ docker run hello-world
```

如果一切顺利，您的输出应该看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/1601a10a-3104-4c94-bdf7-9f5fbd3df2aa.png)

在 macOS 上的 Docker 桌面版上运行 Hello-World

接下来，我们将在 Windows 上安装 Docker。

# 在 Windows 上安装 Docker 桌面版

按照以下步骤进行安装：

1.  安装成功 Docker 桌面版后，请打开 PowerShell 窗口并执行以下命令：

```
PS> docker --version
Docker version 19.03.5, build 633a0ea
```

1.  要查看是否可以运行容器，请在 PowerShell 窗口中输入以下命令并按 Enter 键：

```
PS> docker run hello-world
```

如果一切顺利，您的输出应该与前面的图像类似。

# 在 Linux 上安装 Docker CE

如前所述，Docker 桌面版仅适用于 macOS 和 Windows 10 专业版。如果您使用的是 Linux 机器，则可以使用 Docker 社区版（CE），其中包括 Docker 引擎以及一些附加工具，如 Docker 命令行界面（CLI）和 docker-compose。

请按照以下链接中的说明安装特定 Linux 发行版（在本例中为 Ubuntu）的 Docker CE：[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)。

# 安装 Docker Toolbox

Docker Toolbox 已经为开发人员提供了几年。它是 Docker 桌面版等新工具的前身。Toolbox 允许用户在任何 macOS 或 Windows 计算机上非常优雅地使用容器。容器必须在 Linux 主机上运行。Windows 和 macOS 都无法本地运行容器。因此，我们需要在笔记本电脑上运行 Linux 虚拟机，然后在其中运行容器。Docker Toolbox 在笔记本电脑上安装 VirtualBox，用于运行我们需要的 Linux 虚拟机。

作为 Windows 用户，您可能已经意识到有所谓的 Windows 容器可以在 Windows 上本地运行，这一点您是正确的。微软已经将 Docker Engine 移植到了 Windows，并且可以在 Windows Server 2016 或更新版本上直接运行 Windows 容器，无需虚拟机。所以，现在我们有两种容器，Linux 容器和 Windows 容器。前者只能在 Linux 主机上运行，后者只能在 Windows 服务器上运行。在本书中，我们专门讨论 Linux 容器，但我们学到的大部分东西也适用于 Windows 容器。

如果您对 Windows 容器感兴趣，我们强烈推荐阅读《Docker on Windows, Second Edition》这本书：[`www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition`](https://www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition)。

让我们从在 macOS 上安装 Docker Toolbox 开始。

# 在 macOS 上安装 Docker Toolbox

按照以下步骤进行安装：

1.  打开一个新的终端窗口，并使用 Homebrew 安装工具箱：

```
$ brew cask install docker-toolbox 
```

您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f323a67a-9f10-4c81-935d-45dcc77c5e19.png)

在 macOS 上安装 Docker Toolbox

1.  要验证 Docker Toolbox 是否已成功安装，请尝试访问`docker-machine`和`docker-compose`，这两个工具是安装的一部分：

```
$ docker-machine --version
docker-machine version 0.15.0, build b48dc28d
$ docker-compose --version
docker-compose version 1.22.0, build f46880f
```

接下来，我们将在 Windows 上安装 Docker Toolbox。

# 在 Windows 上安装 Docker Toolbox

在管理员模式下打开一个新的 Powershell 窗口，并使用 Chocolatey 安装 Docker Toolbox：

```
PS> choco install docker-toolbox -y
```

输出应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c3d8eb48-3017-4bd2-a27b-c89e7aad66f4.png)

在 Windows 10 上安装 Docker Toolbox

我们现在将设置 Docker Toolbox。

# 设置 Docker Toolbox

按照以下步骤进行设置：

1.  让我们使用`docker-machine`来设置我们的环境。首先，我们列出当前在系统上定义的所有 Docker-ready VM。如果您刚刚安装了 Docker Toolbox，您应该会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ca24a687-1929-473d-9ba7-7e68294fea9f.png)所有 Docker-ready VM 的列表

1.  好的，我们可以看到已经安装了一个名为`default`的单个 VM，但它目前处于`stopped`的状态。让我们使用`docker-machine`来启动这个 VM，这样我们就可以使用它了：

```
$ docker-machine start default
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4eb6cf4e-c51b-4946-8e4f-d140f2fafd9a.png)

启动 Docker Toolbox 中的默认 VM

如果我们现在再次列出 VM，我们应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0adc5a3b-7c37-4ccc-a004-5b2cc76aabdb.png)

列出 Docker Toolbox 中正在运行的 VM

在您的情况下使用的 IP 地址可能不同，但肯定会在`192.168.0.0/24`范围内。我们还可以看到 VM 安装了 Docker 版本`18.06.1-ce`。

1.  如果由于某种原因您没有默认的 VM，或者意外删除了它，可以使用以下命令创建它：

```
$ docker-machine create --driver virtualbox default 
```

这将生成以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0ab00ba7-5fd8-432f-a234-8ccd5ef4de10.png)

在 Docker Toolbox 中创建一个新的默认 VM

如果仔细分析前面的输出，您会发现`docker-machine`自动从 Docker 下载了最新的 VM ISO 文件。它意识到我的当前版本已过时，并用版本`v18.09.6`替换了它。

1.  要查看如何将 Docker 客户端连接到在此虚拟机上运行的 Docker 引擎，请运行以下命令：

```
$ docker-machine env default 
```

这将输出以下内容：

```
export DOCKER_TLS_VERIFY="1"
export DOCKER_HOST="tcp://192.168.99.100:2376"
export DOCKER_CERT_PATH="/Users/gabriel/.docker/machine/machines/default"
export DOCKER_MACHINE_NAME="default"
# Run this command to configure your shell:
# eval $(docker-machine env default)
```

1.  我们可以执行前面代码片段中最后一行中列出的命令，来配置我们的 Docker CLI 以使用在`default` VM 上运行的 Docker：

```
$ eval $(docker-machine env default) 
```

1.  现在我们可以执行第一个 Docker 命令：

```
$ docker version
```

这应该产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8072de88-4665-4b5a-b5a5-f3994515624b.png)

docker version 的输出

这里有两个部分，客户端和服务器部分。客户端是直接在您的 macOS 或 Windows 笔记本电脑上运行的 CLI，而服务器部分在 VirtualBox 中的`default` VM 上运行。

1.  现在，让我们尝试运行一个容器：

```
$ docker run hello-world
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ba44f8ff-7ebe-4840-9466-a7a136e67152.png)

前面的输出证实了 Docker Toolbox 正在按预期工作并且可以运行容器。

Docker Toolbox 是一个很好的补充，即使您通常使用 Docker Desktop 进行 Docker 开发。 Docker Toolbox 允许您在 VirtualBox 中创建多个 Docker 主机（或 VM），并将它们连接到集群，然后在其上运行 Docker Swarm 或 Kubernetes。

# 安装 Minikube

如果您无法使用 Docker Desktop，或者由于某种原因，您只能访问尚不支持 Kubernetes 的旧版本工具，则安装 Minikube 是一个好主意。 Minikube 在您的工作站上为单节点 Kubernetes 集群提供了支持，并且可以通过`kubectl`访问，这是用于处理 Kubernetes 的命令行工具。

# 在 macOS 和 Windows 上安装 Minikube

要安装 macOS 或 Windows 的 Minikube，请转到以下链接：[`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)。

请仔细遵循说明。如果您已安装 Docker Toolbox，则系统上已经有一个 hypervisor，因为 Docker Toolbox 安装程序还安装了 VirtualBox。否则，我建议您先安装 VirtualBox。

如果您已安装了 macOS 或 Windows 的 Docker，则`kubectl`也已经安装了，因此您也可以跳过这一步。否则，请按照网站上的说明操作。

# 测试 Minikube 和 kubectl

一旦 Minikube 成功安装在您的工作站上，打开终端并测试安装。首先，我们需要启动 Minikube。在命令行输入`minikube start`。这个命令可能需要几分钟来完成。输出应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/918657bb-5dc5-4eca-8220-4139caa69112.png)

启动 Minikube 注意，您的输出可能略有不同。在我的情况下，我正在 Windows 10 专业版计算机上运行 Minikube。在 Mac 上，通知会有所不同，但这里并不重要。

现在，输入`kubectl version`并按*Enter*，看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b695efb9-10b2-4ee8-9877-020e89021230.png)

确定 Kubernetes 客户端和服务器的版本

如果前面的命令失败，例如超时，那么可能是因为您的`kubectl`没有配置正确的上下文。`kubectl`可以用来处理许多不同的 Kubernetes 集群。每个集群称为一个上下文。要找出`kubectl`当前配置的上下文，使用以下命令：

```
$ kubectl config current-context
minikube
```

答案应该是`minikube`，如前面的输出所示。如果不是这种情况，请使用`kubectl config get-contexts`列出系统上定义的所有上下文，然后将当前上下文设置为`minikube`，如下所示：

```
$ kubectl config use-context minikube
```

`kubectl`的配置，它存储上下文，通常可以在`~/.kube/config`中找到，但这可以通过定义一个名为`KUBECONFIG`的环境变量来覆盖。如果您的计算机上设置了这个变量，您可能需要取消设置。

有关如何配置和使用 Kubernetes 上下文的更深入信息，请参考以下链接：[`kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/`](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/)。

假设 Minikube 和`kubectl`按预期工作，我们现在可以使用`kubectl`获取有关 Kubernetes 集群的信息。输入以下命令：

```
$ kubectl get nodes
NAME STATUS ROLES AGE VERSION
minikube Ready master 47d v1.17.3
```

显然，我们有一个节点的集群，在我的情况下，上面安装了`Kubernetes v1.17.3`。

# 摘要

在本章中，我们设置和配置了我们的个人或工作环境，以便我们可以有效地使用 Docker 容器进行工作。这同样适用于开发人员、DevOps 和运维工程师。在这种情况下，我们确保使用一个好的编辑器，安装了 macOS 的 Docker 或 Windows 的 Docker，并且可以使用`docker-machine`在 VirtualBox 或 Hyper-V 中创建虚拟机，然后我们可以使用它来运行和测试容器。

在下一章中，我们将学习有关容器的所有重要知识。例如，我们将探讨如何运行、停止、列出和删除容器，但更重要的是，我们还将深入探讨容器的结构。

# 问题

根据您对本章的阅读，请回答以下问题：

1.  `docker-machine`用于什么？列举三到四个场景。

1.  使用 Docker for Windows，您可以开发和运行 Linux 容器。

A. True

B. False

1.  为什么良好的脚本技能（如 Bash 或 PowerShell）对于有效使用容器至关重要？

1.  列出三到四个 Docker 认证可在其上运行的 Linux 发行版。

1.  列出所有可以运行 Windows 容器的 Windows 版本。

# 进一步阅读

考虑以下链接以获取更多阅读材料：

+   *Chocolatey - Windows 的软件包管理器*网址为[`chocolatey.org/`](https://chocolatey.org/)

+   *在 Windows 上安装 Docker Toolbox:* [`dockr.ly/2nuZUkU`](https://dockr.ly/2nuZUkU)

+   在 Hyper-V 上使用 Docker Machine 运行 Docker，网址为[`bit.ly/2HGMPiI`](http://bit.ly/2HGMPiI)

+   *在容器内开发*网址为[`code.visualstudio.com/docs/remote/containers`](https://code.visualstudio.com/docs/remote/containers)


# 第二部分：从初学者到黑带的容器化

在这一部分，您将掌握构建、运输和运行单个容器的所有基本方面。

本节包括以下章节：

+   第三章，*掌握容器*

+   第四章，*创建和管理容器镜像*

+   第五章，*数据卷和配置*

+   第六章，*调试在容器中运行的代码*

+   第七章，*使用 Docker 来加速自动化*

+   第八章，*高级 Docker 使用场景*


# 第三章：掌握容器

在上一章中，您学会了如何为高效和无摩擦地使用 Docker 准备您的工作环境。在本章中，我们将亲自动手，学习在使用容器时需要了解的一切重要内容。以下是本章我们将要涵盖的主题：

+   运行第一个容器

+   启动、停止和删除容器

+   检查容器

+   在运行的容器中执行

+   附加到运行的容器

+   检索容器日志

+   容器的结构

完成本章后，您将能够做到以下几点：

+   基于现有镜像（如 Nginx、BusyBox 或 Alpine）运行、停止和删除容器。

+   列出系统上的所有容器。

+   检查正在运行或已停止容器的元数据。

+   检索在容器内运行的应用程序产生的日志。

+   在已运行的容器中运行`/bin/sh`等进程。

+   将终端连接到已运行的容器。

+   用您自己的话向一个感兴趣的外行人解释容器的基础知识。

# 技术要求

本章中，您应该已经在您的 macOS 或 Windows PC 上安装了 Docker for Desktop。如果您使用的是较旧版本的 Windows 或者使用的是 Windows 10 家庭版，那么您应该已经安装并准备好使用 Docker Toolbox。在 macOS 上，请使用终端应用程序，在 Windows 上，请使用 PowerShell 或 Bash 控制台来尝试您将要学习的命令。

# 运行第一个容器

在我们开始之前，我们希望确保 Docker 已正确安装在您的系统上，并准备好接受您的命令。打开一个新的终端窗口，并输入以下命令：

```
$ docker version
```

如果您使用的是 Docker Toolbox，则请使用已与 Toolbox 一起安装的 Docker Quickstart 终端，而不是 macOS 上的终端或 Windows 上的 PowerShell。

如果一切正常，您应该在终端中看到安装在您的笔记本电脑上的 Docker 客户端和服务器的版本。在撰写本文时，它看起来是这样的（为了可读性而缩短）：

```
Client: Docker Engine - Community
 Version: 19.03.0-beta3
 API version: 1.40
 Go version: go1.12.4
 Git commit: c55e026
 Built: Thu Apr 25 19:05:38 2019
 OS/Arch: darwin/amd64
 Experimental: false

Server: Docker Engine - Community
 Engine:
 Version: 19.03.0-beta3
 API version: 1.40 (minimum version 1.12)
 Go version: go1.12.4
 Git commit: c55e026
 Built: Thu Apr 25 19:13:00 2019
 OS/Arch: linux/amd64
 ...
```

您可以看到我在我的 macOS 上安装了`19.03.0`版本的`beta3`。

如果这对您不起作用，那么您的安装可能有问题。请确保您已按照上一章中关于如何在您的系统上安装 Docker for Desktop 或 Docker Toolbox 的说明进行操作。

所以，您已经准备好看到一些操作了。请在您的终端窗口中输入以下命令并按*Return*键：

```
$ docker container run alpine echo "Hello World" 
```

当您第一次运行上述命令时，您应该在终端窗口中看到类似于这样的输出：

```
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
e7c96db7181b: Pull complete
Digest: sha256:769fddc7cc2f0a1c35abb2f91432e8beecf83916c421420e6a6da9f8975464b6
Status: Downloaded newer image for alpine:latest
Hello World
```

现在这很容易！让我们再次尝试运行完全相同的命令：

```
$ docker container run alpine echo "Hello World" 
```

第二次、第三次或第 n 次运行上述命令时，您应该在终端中只看到以下输出：

```
 Hello World  
```

尝试推理第一次运行命令时为什么会看到不同的输出，而所有后续次数都不同。但是如果您无法弄清楚，不要担心；我们将在本章的后续部分详细解释原因。

# 启动、停止和删除容器

在上一节中，您已成功运行了一个容器。现在，我们想详细调查到底发生了什么以及为什么。让我们再次看看我们使用的命令：

```
$ docker container run alpine echo "Hello World" 
```

这个命令包含多个部分。首先，我们有单词`docker`。这是 Docker**命令行界面**（**CLI**）工具的名称，我们使用它与负责运行容器的 Docker 引擎进行交互。接下来是单词`container`，它表示我们正在处理的上下文。因为我们要运行一个容器，所以我们的上下文是`container`。接下来是我们要在给定上下文中执行的实际命令，即`run`。

让我回顾一下——到目前为止，我们有`docker container run`，这意味着，“嘿，Docker，我们想要运行一个容器。”

现在我们还需要告诉 Docker 要运行哪个容器。在这种情况下，这就是所谓的`alpine`容器。

`alpine` 是一个基于 Alpine Linux 的最小 Docker 镜像，具有完整的软件包索引，大小仅为 5MB。

最后，我们需要定义在容器运行时应执行什么类型的进程或任务。在我们的情况下，这是命令的最后一部分，`echo "Hello World"`。

也许以下截图可以帮助您更好地了解整个过程：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/aa2c9ba0-11fb-4b2a-ae10-2c3419981032.png)

docker container run 表达式的解剖

现在我们已经了解了运行容器命令的各个部分，让我们尝试在容器中运行另一个不同的进程。在终端中键入以下命令：

```
$ docker container run centos ping -c 5 127.0.0.1
```

您应该在终端窗口中看到类似以下的输出：

```
Unable to find image 'centos:latest' locally
latest: Pulling from library/centos
8ba884070f61: Pull complete
Digest: sha256:b5e66c4651870a1ad435cd75922fe2cb943c9e973a9673822d1414824a1d0475
Status: Downloaded newer image for centos:latest
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.104 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.059 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.081 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.050 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.055 ms
--- 127.0.0.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4127ms
rtt min/avg/max/mdev = 0.050/0.069/0.104/0.022 ms
```

改变的是，这次我们使用的容器镜像是`centos`，我们在`centos`容器内执行的进程是`ping -c 5 127.0.0.1`，它会对回环地址进行五次 ping 直到停止。

`centos`是 CentOS Linux 的官方 Docker 镜像，这是一个社区支持的发行版，源自**Red Hat**为**Red Hat Enterprise Linux**（**RHEL**）免费提供给公众的源代码。

让我们详细分析输出。

第一行如下：

```
Unable to find image 'centos:latest' locally
```

这告诉我们 Docker 在系统的本地缓存中没有找到名为`centos:latest`的镜像。因此，Docker 知道它必须从存储容器镜像的某个注册表中拉取镜像。默认情况下，您的 Docker 环境配置为从`docker.io`的 Docker Hub 拉取镜像。这由第二行表示，如下所示：

```
latest: Pulling from library/centos 
```

接下来的三行输出如下：

```
8ba884070f61: Pull complete
Digest: sha256:b5e66c4651870a1ad435cd75922fe2cb943c9e973a9673822d1414824a1d0475
Status: Downloaded newer image for centos:latest
```

这告诉我们 Docker 已成功从 Docker Hub 拉取了`centos:latest`镜像。

输出的所有后续行都是由我们在容器内运行的进程生成的，这种情况下是 Ping 工具。如果你到目前为止一直很注意，那么你可能已经注意到`latest`关键字出现了几次。每个镜像都有一个版本（也称为`tag`），如果我们不明确指定版本，那么 Docker 会自动假定它是`latest`。

如果我们在我们的系统上再次运行前面的容器，输出的前五行将会丢失，因为这一次 Docker 会在本地找到容器镜像的缓存，因此不需要先下载它。试一试，验证我刚才告诉你的。

# 运行一个随机琐事问题容器

在本章的后续部分，我们需要一个在后台持续运行并产生一些有趣输出的容器。这就是为什么我们选择了一个产生随机琐事问题的算法。产生免费随机琐事的 API 可以在[`jservice.io/`](http://jservice.io/)找到。

现在的目标是在容器内运行一个进程，每五秒产生一个新的随机琐事问题，并将问题输出到`STDOUT`。以下脚本将完全做到这一点：

```
while : 
do 
 wget -qO- http://jservice.io/api/random | jq .[0].question 
 sleep 5 
done
```

在终端窗口中尝试一下。通过按*Ctrl*+*C*来停止脚本。输出应该类似于这样：

```
"In 2004 Pitt alumna Wangari Maathai became the first woman from this continent to win the Nobel Peace Prize"
"There are 86,400 of these in every day"
"For $5 million in 2013 an L.A. movie house became TCL Chinese Theatre, but we bet many will still call it this, after its founder"
^C
```

每个响应都是一个不同的琐事问题。

您可能需要先在您的 macOS 或 Windows 计算机上安装`jq`。`jq`是一个方便的工具，通常用于过滤和格式化 JSON 输出，这样可以增加屏幕上的可读性。

现在，让我们在一个`alpine`容器中运行这个逻辑。由于这不仅仅是一个简单的命令，我们想把前面的脚本包装在一个脚本文件中并执行它。为了简化事情，我创建了一个名为`fundamentalsofdocker/trivia`的 Docker 镜像，其中包含了所有必要的逻辑，这样我们就可以直接在这里使用它。稍后，一旦我们介绍了 Docker 镜像，我们将进一步分析这个容器镜像。暂时，让我们就这样使用它。执行以下命令将容器作为后台服务运行。在 Linux 中，后台服务也被称为守护进程：

```
$ docker container run -d --name trivia fundamentalsofdocker/trivia:ed2
```

在前面的表达式中，我们使用了两个新的命令行参数`-d`和`--name`。现在，`-d`告诉 Docker 将在容器中运行的进程作为 Linux 守护进程运行。而`--name`参数则可以用来给容器指定一个显式的名称。在前面的示例中，我们选择的名称是`trivia`。

如果我们在运行容器时没有指定显式的容器名称，那么 Docker 将自动为容器分配一个随机但唯一的名称。这个名称将由一个著名科学家的名字和一个形容词组成。这样的名称可能是`boring_borg`或`angry_goldberg`。我们的 Docker 工程师们相当幽默，*不是吗？*

我们还在容器中使用标签`ed2`。这个标签只是告诉我们这个镜像是为本书的第二版创建的。

一个重要的要点是，容器名称在系统上必须是唯一的。让我们确保`trivia`容器正在运行：

```
$ docker container ls -l
```

这应该给我们类似于这样的东西（为了可读性而缩短）：

```
CONTAINER ID  IMAGE                            ... CREATED         STATUS ...
0ff3d7cf7634  fundamentalsofdocker/trivia:ed2  ... 11 seconds ago  Up 9 seconds ...
```

前面输出的重要部分是`STATUS`列，本例中是`Up 9 seconds`。也就是说，容器已经运行了 9 秒钟。

如果最后一个 Docker 命令对您来说还不太熟悉，不要担心，我们将在下一节回到它。

完成本节，让我们停下来，使用以下命令停止并移除`trivia`容器：

```
$ docker rm -f trivia
```

现在是时候学习如何列出在我们的系统上运行或悬空的容器了。

# 列出容器

随着时间的推移，我们继续运行容器，我们的系统中会有很多容器。要找出当前在我们的主机上运行的是什么，我们可以使用`container ls`命令，如下所示：

```
$ docker container ls
```

这将列出所有当前正在运行的容器。这样的列表可能看起来类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/068c2859-04d5-43a4-9e16-e1326761f468.png)列出系统上所有正在运行的容器

默认情况下，Docker 输出七列，含义如下：

| **列** | **描述** |
| --- | --- |
| `容器 ID` | 这是容器的唯一 ID。它是一个 SHA-256。 |
| `镜像` | 这是实例化该容器的容器镜像的名称。 |
| `命令` | 这是用于在容器中运行主进程的命令。 |
| `创建时间` | 这是容器创建的日期和时间。 |
| `状态` | 这是容器的状态（已创建、重新启动、运行中、正在移除、暂停、已退出或已停止）。 |
| `端口` | 这是已映射到主机的容器端口列表。 |
| `名称` | 这是分配给该容器的名称（可以有多个名称）。 |

如果我们不仅想列出当前正在运行的容器，而是所有在系统上定义的容器，那么我们可以使用命令行参数`-a`或`--all`，如下所示：

```
$ docker container ls -a
```

这将列出任何状态的容器，例如`已创建`、`运行中`或`已退出`。

有时，我们只想列出所有容器的 ID。为此，我们有`-q`参数：

```
$ docker container ls -q
```

您可能会想知道这有什么用。我将在这里向您展示一个非常有用的命令：

```
$ docker container rm -f $(docker container ls -a -q)
```

往后倾斜，深呼吸。然后，尝试找出前面的命令是做什么的。在找到答案或放弃之前，请不要再往下读。

前面的命令会删除系统上当前定义的所有容器，包括已停止的容器。`rm`命令代表删除，很快就会解释。

在前面的部分，我们在列表命令中使用了`-l`参数。尝试使用 Docker 帮助找出`-l`参数代表什么。您可以按照以下方式调用列表命令的帮助：

```
$ docker container ls -h 
```

接下来，让我们学习如何停止和重新启动容器。

# 停止和启动容器

有时，我们想（暂时）停止一个运行中的容器。让我们尝试一下之前使用的 trivia 容器：

1.  用这个命令再次运行容器：

```
$ docker container run -d --name trivia fundamentalsofdocker/trivia:ed2
```

1.  现在，如果我们想要停止这个容器，我们可以通过发出这个命令来做到：

```
$ docker container stop trivia
```

当您尝试停止 trivia 容器时，您可能会注意到这个命令执行起来需要一段时间。确切地说，大约需要 10 秒。*为什么会这样？*

Docker 向容器内部运行的主进程发送 Linux `SIGTERM`信号。如果进程对此信号不做出反应并终止自身，Docker 将等待 10 秒，然后发送`SIGKILL`，这将强制终止进程并终止容器。

在前面的命令中，我们使用容器的名称来指定我们要停止的容器。但我们也可以使用容器 ID。

*我们如何获取容器的 ID？*有几种方法可以做到这一点。手动方法是列出所有运行中的容器，并在列表中找到我们要找的容器。然后，我们复制它的 ID。更自动化的方法是使用一些 shell 脚本和环境变量。例如，如果我们想要获取 trivia 容器的 ID，我们可以使用这个表达式：

```
$ export CONTAINER_ID=$(docker container ls -a | grep trivia | awk '{print $1}')
```

我们在 Docker `container ls`命令中使用`-a`参数来列出所有容器，即使是已停止的。在这种情况下是必要的，因为我们刚刚停止了 trivia 容器。

现在，我们可以在表达式中使用`$CONTAINER_ID`变量，而不是使用容器名称：

```
$ docker container stop $CONTAINER_ID 
```

一旦我们停止了容器，它的状态就会变为`Exited`。

如果容器已停止，可以使用`docker container start`命令重新启动。让我们用 trivia 容器来做这个操作。让它再次运行是很好的，因为我们将在本章的后续部分中需要它：

```
$ docker container start trivia 
```

现在是时候讨论我们不再需要的已停止容器该怎么办了。

# 删除容器

当我们运行`docker container ls -a`命令时，我们可以看到相当多的容器处于`Exited`状态。如果我们不再需要这些容器，那么将它们从内存中删除是一件好事；否则，它们会不必要地占用宝贵的资源。删除容器的命令如下：

```
$ docker container rm <container ID>
```

另一个删除容器的命令如下：

```
$ docker container rm <container name>
```

尝试使用其 ID 删除一个已退出的容器。

有时，删除容器可能不起作用，因为它仍在运行。如果我们想要强制删除，无论容器当前的状态如何，我们可以使用命令行参数`-f`或`--force`。

# 检查容器

容器是镜像的运行时实例，并且具有许多特征其行为的关联数据。要获取有关特定容器的更多信息，我们可以使用`inspect`命令。通常情况下，我们必须提供容器 ID 或名称来标识我们想要获取数据的容器。因此，让我们检查我们的示例容器：

```
$ docker container inspect trivia 
```

响应是一个充满细节的大型 JSON 对象。它看起来类似于这样：

```
[
    {
        "Id": "48630a3bf188...",
        ...
        "State": {
            "Status": "running",
            "Running": true,
            ...
        },
        "Image": "sha256:bbc92c8f014d605...",
        ...
        "Mounts": [],
        "Config": {
            "Hostname": "48630a3bf188",
            "Domainname": "",
            ...
        },
        "NetworkSettings": {
            "Bridge": "",
            "SandboxID": "82aed83429263ceb6e6e...",
            ...
        }
    }
]
```

输出已经被缩短以便阅读。

请花一点时间分析你得到的信息。您应该看到诸如以下信息：

+   容器的 ID

+   容器的创建日期和时间

+   构建容器的镜像

输出的许多部分，如`Mounts`或`NetworkSettings`，现在并没有太多意义，但我们肯定会在本书的后续章节中讨论这些内容。您在这里看到的数据也被称为容器的元数据。在本书的其余部分中，我们将经常使用`inspect`命令作为信息来源。

有时，我们只需要整体信息的一小部分，为了实现这一点，我们可以使用`grep`工具或过滤器。前一种方法并不总是得到预期的答案，所以让我们看看后一种方法：

```
$ docker container inspect -f "{{json .State}}" trivia | jq .
```

`-f`或`--filter`参数用于定义过滤器。过滤器表达式本身使用 Go 模板语法。在这个例子中，我们只想以 JSON 格式看到整个输出中的状态部分。

为了使输出格式良好，我们将结果传输到`jq`工具中：

```
{
  "Status": "running",
  "Running": true,
  "Paused": false,
  "Restarting": false,
  "OOMKilled": false,
  "Dead": false,
  "Pid": 18252,
  "ExitCode": 0,
  "Error": "",
  "StartedAt": "2019-06-16T13:30:15.776272Z",
  "FinishedAt": "2019-06-16T13:29:38.6412298Z"
}
```

在我们学会如何检索有关容器的大量重要和有用的元信息之后，我们现在想调查如何在运行的容器中执行它。

# 在运行的容器中执行

有时，我们希望在已经运行的容器内运行另一个进程。一个典型的原因可能是尝试调试行为异常的容器。*我们如何做到这一点？*首先，我们需要知道容器的 ID 或名称，然后我们可以定义我们想要运行的进程以及我们希望它如何运行。再次，我们使用当前正在运行的 trivia 容器，并使用以下命令在其中交互式运行一个 shell：

```
$ docker container exec -i -t trivia /bin/sh
```

`-i`标志表示我们要交互式地运行附加进程，`-t`告诉 Docker 我们希望它为命令提供 TTY（终端仿真器）。最后，我们运行的进程是`/bin/sh`。

如果我们在终端中执行上述命令，那么我们将看到一个新的提示符`/app＃`。我们现在在 trivia 容器内的 shell 中。我们可以很容易地通过执行`ps`命令来证明这一点，该命令将列出上下文中所有正在运行的进程：

```
/app # ps
```

结果应该看起来与这个有些相似：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4f28c7e4-bd1d-42f6-9b52-ed75c1a3f98e.png)

列出在 trivia 容器内运行的进程

我们可以清楚地看到，具有`PID 1`的进程是我们在 trivia 容器内定义的要运行的命令。具有`PID 1`的进程也被称为主进程。

通过按下*Ctrl* + *D*来离开容器。我们不仅可以在容器中交互地执行额外的进程。请考虑以下命令：

```
$ docker container exec trivia ps
```

输出显然与前面的输出非常相似。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/484111d6-69b2-44fc-9529-4d42a780eecc.png)

列出在 trivia 容器内运行的进程

我们甚至可以使用`-d`标志以守护进程的形式运行进程，并使用`-e`标志变量定义环境变量，如下所示：

```
$ docker container exec -it \
 -e MY_VAR="Hello World" \
 trivia /bin/sh
/app # echo $MY_VAR
Hello World
/app # <CTRL-d>
```

很好，我们已经学会了如何进入一个正在运行的容器并运行额外的进程。但是还有另一种重要的方式可以与正在运行的容器交互。

# 附加到一个正在运行的容器

我们可以使用`attach`命令将我们终端的标准输入、输出和错误（或三者的任意组合）附加到正在运行的容器，使用容器的 ID 或名称。让我们为我们的 trivia 容器这样做：

```
$ docker container attach trivia
```

在这种情况下，我们将每隔五秒左右在输出中看到一个新的引用出现。

要退出容器而不停止或杀死它，我们可以按下组合键*Ctrl* + *P* + *Ctrl* + *Q*。这样我们就可以从容器中分离出来，同时让它在后台运行。另一方面，如果我们想要分离并同时停止容器，我们只需按下*Ctrl* + *C*。

让我们运行另一个容器，这次是一个 Nginx Web 服务器：

```
$ docker run -d --name nginx -p 8080:80 nginx:alpine
```

在这里，我们在一个名为`nginx`的容器中以守护进程的形式运行 Alpine 版本的 Nginx。`-p 8080:80`命令行参数在主机上打开端口`8080`，以便访问容器内运行的 Nginx Web 服务器。不用担心这里的语法，因为我们将在第十章“单主机网络”中更详细地解释这个特性：

1.  让我们看看是否可以使用`curl`工具访问 Nginx 并运行这个命令：

```
$ curl -4 localhost:8080
```

如果一切正常，你应该会看到 Nginx 的欢迎页面（为了方便阅读而缩短）：

```
<html> 
<head> 
<title>Welcome to nginx!</title> 
<style> 
    body { 
        width: 35em; 
        margin: 0 auto; 
        font-family: Tahoma, Verdana, Arial, sans-serif; 
    } 
</style> 
</head> 
<body> 
<h1>Welcome to nginx!</h1> 
...
</html> 
```

1.  现在，让我们附加我们的终端到`nginx`容器，观察发生了什么：

```
$ docker container attach nginx
```

1.  一旦你附加到容器上，你首先看不到任何东西。但现在打开另一个终端，在这个新的终端窗口中，重复`curl`命令几次，例如，使用以下脚本：

```
$ for n in {1..10}; do curl -4 localhost:8080; done 
```

你应该会看到 Nginx 的日志输出，看起来类似于这样：

```
172.17.0.1 - - [16/Jun/2019:14:14:02 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.54.0" "-"
172.17.0.1 - - [16/Jun/2019:14:14:02 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.54.0" "-"
172.17.0.1 - - [16/Jun/2019:14:14:02 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.54.0" "-"
...
```

1.  按下*Ctrl*+*C*来退出容器。这将分离你的终端，并同时停止`nginx`容器。

1.  清理时，使用以下命令删除`nginx`容器：

```
$ docker container rm nginx 
```

在下一节中，我们将学习如何处理容器日志。

# 检索容器日志

对于任何良好的应用程序来说，生成一些日志信息是最佳实践，开发人员和运维人员都可以使用这些信息来找出应用程序在特定时间正在做什么，以及是否存在任何问题，以帮助找出问题的根本原因。

在容器内运行时，应用程序最好将日志项输出到`STDOUT`和`STDERR`，而不是输出到文件中。如果日志输出被定向到`STDOUT`和`STDERR`，那么 Docker 可以收集这些信息，并准备好供用户或任何其他外部系统使用：

1.  要访问特定容器的日志，我们可以使用`docker container logs`命令。例如，如果我们想要检索我们的`trivia`容器的日志，我们可以使用以下表达式：

```
$ docker container logs trivia
```

这将检索应用程序从其存在的最开始产生的整个日志。

停下，等一下——我刚才说的不太对。默认情况下，Docker 使用所谓的`json-file`日志驱动程序。这个驱动程序将日志信息存储在一个文件中。如果定义了文件滚动策略，那么`docker container logs`只会检索当前活动日志文件中的内容，而不是之前滚动文件中可能仍然可用的内容。

1.  如果我们只想获取一些最新的条目，我们可以使用`-t`或`--tail`参数，如下所示：

```
$ docker container logs --tail 5 trivia
```

这将只检索容器内运行的进程产生的最后五个条目。

有时，我们希望跟踪容器产生的日志。当使用`-f`或`--follow`参数时，这是可能的。以下表达式将输出最后五个日志项，然后跟踪容器化进程产生的日志：

```
$ docker container logs --tail 5 --follow trivia 
```

通常使用容器日志的默认机制是不够的。我们需要一种不同的日志记录方式。这将在下一节中讨论。

# 日志记录驱动程序

Docker 包括多种日志记录机制，帮助我们从运行的容器中获取信息。这些机制被称为**日志记录驱动程序**。使用哪个日志记录驱动程序可以在 Docker 守护程序级别进行配置。默认的日志记录驱动程序是`json-file`。目前原生支持的一些驱动程序如下：

| **驱动程序** | **描述** |
| --- | --- |
| `none` | 不会产生特定容器的日志输出。 |
| `json-file` | 这是默认驱动程序。日志信息存储在以 JSON 格式的文件中。 |
| `journald` | 如果主机上运行着日志守护程序，我们可以使用此驱动程序。它将日志转发到`journald`守护程序。 |
| `syslog` | 如果主机上运行着`syslog`守护程序，我们可以配置此驱动程序，它将日志消息转发到`syslog`守护程序。 |
| `gelf` | 使用此驱动程序时，日志消息将写入**Graylog 扩展日志格式**（**GELF**）端点。此类端点的常见示例包括 Graylog 和 Logstash。 |
| `fluentd` | 假设在主机系统上安装了`fluentd`守护程序，此驱动程序将日志消息写入其中。 |

如果更改了日志记录驱动程序，请注意`docker container logs`命令仅适用于`json-file`和`journald`驱动程序。

# 使用特定于容器的日志记录驱动程序

我们已经看到日志记录驱动程序可以在 Docker 守护程序配置文件中全局设置。但我们也可以在容器与容器之间定义日志记录驱动程序。在以下示例中，我们运行了一个`busybox`容器，并使用`--log-driver`参数配置了`none`日志记录驱动程序：

```
$ docker container run --name test -it \
 --log-driver none \
 busybox sh -c 'for N in 1 2 3; do echo "Hello $N"; done'
```

我们应该看到以下内容：

```
Hello 1
Hello 2
Hello 3 
```

现在，让我们尝试获取前一个容器的日志：

```
$ docker container logs test
```

输出如下：

```
Error response from daemon: configured logging driver does not support reading
```

这是可以预期的，因为`none`驱动程序不会产生任何日志输出。让我们清理并删除`test`容器：

```
$ docker container rm test
```

# 高级主题-更改默认日志记录驱动程序

让我们更改 Linux 主机的默认日志记录驱动程序：

1.  在真实的 Linux 主机上进行这项操作是最简单的。为此，我们将使用 Vagrant 和 Ubuntu 镜像：

```
$ vagrant init bento/ubuntu-17.04
$ vagrant up
$ vagrant ssh
```

**Vagrant**是由 Hashicorp 开发的开源工具，通常用于构建和维护可移植的虚拟软件开发环境。

1.  进入 Ubuntu 虚拟机后，我们要编辑 Docker 守护程序配置文件。转到`/etc/docker`文件夹并运行`vi`如下：

```
$ vi daemon.json 
```

1.  输入以下内容：

```
{
  "Log-driver": "json-log",
  "log-opts": {
    "max-size": "10m",
    "max-file": 3
  }
}
```

1.  通过首先按*Esc*，然后输入`:w:q`，最后按*Enter*键保存并退出`vi`。

前面的定义告诉 Docker 守护程序使用`json-log`驱动程序，最大日志文件大小为 10MB，然后滚动，并且在系统上可以存在的最大日志文件数为`3`，在最老的文件被清除之前。

现在我们必须向 Docker 守护程序发送`SIGHUP`信号，以便它接受配置文件中的更改：

```
$ sudo kill -SIGHUP $(pidof dockerd)
```

请注意，前面的命令只重新加载配置文件，而不重新启动守护程序。

# 容器的解剖学

许多人错误地将容器与虚拟机进行比较。然而，这是一个值得商榷的比较。容器不仅仅是轻量级的虚拟机。那么，*容器的正确描述是什么*？

容器是在主机系统上运行的特殊封装和安全进程。容器利用了 Linux 操作系统中许多可用的特性和原语。最重要的是*命名空间*和*cgroups*。在容器中运行的所有进程只共享底层主机操作系统的相同 Linux 内核。这与虚拟机有根本的不同，因为每个虚拟机都包含自己的完整操作系统。

Typical container 的启动时间可以用毫秒来衡量，而虚拟机通常需要几秒到几分钟才能启动。虚拟机的寿命较长。每个运维工程师的主要目标是最大化虚拟机的正常运行时间。相反，容器的寿命较短。它们相对快速地出现和消失。

让我们首先对使我们能够运行容器的架构进行高级概述。

# 架构

在这里，我们有一个关于所有这些如何组合在一起的架构图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/350f0f91-f671-4ed5-9eae-0f0d6c5dae6e.png)

Docker 的高级架构

在上图的下部，我们有 Linux 操作系统及其**cgroups**、**名称空间**和**层** **功能**，以及我们不需要在这里明确提到的**其他操作系统功能**。然后，有一个由**containerd**和**runc**组成的中间层。现在所有这些之上是**Docker 引擎**。**Docker 引擎**为外部世界提供了一个 RESTful 接口，可以被任何工具访问，比如 Docker CLI、Docker for macOS 和 Docker for Windows 或 Kubernetes 等。

现在让我们更详细地描述一下主要的构建模块。

# 名称空间

Linux 名称空间在被 Docker 用于其容器之前已经存在多年。名称空间是全局资源的抽象，如文件系统、网络访问和进程树（也称为 PID 名称空间）或系统组 ID 和用户 ID。Linux 系统初始化时具有每种名称空间类型的单个实例。初始化后，可以创建或加入其他名称空间。

Linux 名称空间起源于 2002 年的 2.4.19 内核。在内核版本 3.8 中，引入了用户名称空间，随之而来的是名称空间已经准备好被容器使用。

如果我们将一个正在运行的进程，比如说，放在一个文件系统名称空间中，那么这个进程会产生一种错觉，认为它拥有自己完整的文件系统。当然，这是不真实的；这只是一个虚拟文件系统。从主机的角度来看，包含的进程获得了整体文件系统的受保护子部分。就像一个文件系统中的文件系统：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/9ce9575c-b97c-4da2-8cf9-13bf1b9bd15b.png)Linux 上的文件系统名称空间

对于所有其他全局资源，名称空间也适用。用户 ID 名称空间是另一个例子。有了用户名称空间，我们现在可以在系统上定义一个`jdoe`用户多次，只要它存在于自己的名称空间中。

PID 名称空间是防止一个容器中的进程看到或与另一个容器中的进程交互的机制。一个进程在容器内可能具有表面上的 PID **1**，但如果我们从主机系统检查它，它将具有普通的 PID，比如**334**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/a4d80d0a-451d-40dd-9c62-90b7c451dce9.png)Docker 主机上的进程树

在给定的名称空间中，我们可以运行一个到多个进程。当我们谈论容器时，这一点很重要，当我们在已经运行的容器中执行另一个进程时，我们已经有了这种经验。

# 控制组（cgroups）

Linux cgroups 被用来限制、管理和隔离在系统上运行的进程集合的资源使用。资源包括 CPU 时间、系统内存、网络带宽，或者这些资源的组合等等。

Google 的工程师最初在 2006 年实现了这个功能。cgroups 功能被合并到 Linux 内核主线中，内核版本为 2.6.24，发布于 2008 年 1 月。

使用 cgroups，管理员可以限制容器可以消耗的资源。通过这种方式，我们可以避免例如经典的“吵闹的邻居”问题，其中在容器中运行的恶意进程消耗了所有的 CPU 时间或者保留了大量的内存，从而使得所有在主机上运行的其他进程，无论它们是否被容器化，都饿死了。

# 联合文件系统（Unionfs）

Unionfs 构成了所谓的容器镜像的基础。我们将在下一章详细讨论容器镜像。此时，我们只想更好地理解 Unionfs 是什么，以及它是如何工作的。Unionfs 主要用于 Linux，允许不同文件系统的文件和目录叠加在一起，形成一个统一的文件系统。在这种情况下，各个文件系统被称为分支。在合并分支时，指定了分支之间的优先级。这样，当两个分支包含相同的文件时，具有更高优先级的文件将出现在最终的文件系统中。

# 容器管道

Docker 引擎构建的基础是**容器管道**，由两个组件**runc**和**containerd**组成。

最初，Docker 是以单片方式构建的，并包含了运行容器所需的所有功能。随着时间的推移，这变得过于僵化，Docker 开始将功能的部分拆分成它们自己的组件。两个重要的组件是 runc 和 containerd。

# runC

runC 是一个轻量级、便携的容器运行时。它完全支持 Linux 命名空间，以及 Linux 上所有可用的安全功能，如 SELinux、AppArmor、seccomp 和 cgroups。

runC 是一个根据**Open Container Initiative**（OCI）规范生成和运行容器的工具。它是一个经过正式规范化的配置格式，由 Linux Foundation 的**Open Container Project**（OCP）监管。

# Containerd

runC 是一个容器运行时的低级实现；containerd 在其基础上构建，并添加了更高级的功能，如镜像传输和存储、容器执行和监督，以及网络和存储附件。通过这些功能，它管理容器的完整生命周期。Containerd 是 OCI 规范的参考实现，是目前最受欢迎和广泛使用的容器运行时。

Containerd 于 2017 年捐赠并被 CNCF 接受。OCI 规范存在替代实现。其中一些是 CoreOS 的 rkt，RedHat 的 CRI-O 和 Linux Containers 的 LXD。然而，containerd 目前是最受欢迎的容器运行时，并且是 Kubernetes 1.8 或更高版本和 Docker 平台的默认运行时。

# 总结

在本章中，您学习了如何使用基于现有镜像的容器。我们展示了如何运行、停止、启动和删除容器。然后，我们检查了容器的元数据，提取了它的日志，并学习了如何在已运行的容器中运行任意进程。最后，我们深入挖掘了容器的工作原理以及它们利用的底层 Linux 操作系统的特性。

在下一章中，您将学习容器镜像是什么，以及我们如何构建和共享我们自己的自定义镜像。我们还将讨论构建自定义镜像时常用的最佳实践，例如最小化其大小和利用镜像缓存。敬请关注！

# 问题

为了评估您的学习进度，请回答以下问题：

1.  容器的状态是什么？

1.  哪个命令帮助我们找出当前在我们的 Docker 主机上运行的内容？

1.  用于列出所有容器的 ID 的命令是什么？

# 进一步阅读

以下文章为您提供了一些与本章讨论的主题相关的更多信息：

+   Docker 容器在[`dockr.ly/2iLBV2I`](http://dockr.ly/2iLBV2I)

+   使用容器入门在[`dockr.ly/2gmxKWB`](http://dockr.ly/2gmxKWB)

+   使用用户命名空间隔离容器在[`dockr.ly/2gmyKdf`](http://dockr.ly/2gmyKdf)

+   限制容器的资源在[`dockr.ly/2wqN5Nn`](http://dockr.ly/2wqN5Nn)。


# 第四章：创建和管理容器镜像

在上一章中，我们学习了容器是什么，以及如何运行、停止、删除、列出和检查它们。我们提取了一些容器的日志信息，在已经运行的容器内运行其他进程，最后，我们深入研究了容器的解剖学。每当我们运行一个容器时，我们都是使用容器镜像创建它。在本章中，我们将熟悉这些容器镜像。我们将详细了解它们是什么，如何创建它们以及如何分发它们。

本章将涵盖以下主题：

+   什么是镜像？

+   创建镜像

+   举起和转移：容器化传统应用程序

+   共享或运输镜像

完成本章后，您将能够执行以下操作：

+   列举容器镜像的三个最重要特征。

+   通过交互式更改容器层并提交来创建自定义镜像。

+   编写一个简单的`Dockerfile`来生成自定义镜像。

+   使用`docker image save`导出现有的镜像，并使用`docker image load`将其导入到另一个 Docker 主机。

+   编写一个两步的 Dockerfile，通过仅在最终镜像中包含生成的工件来最小化结果镜像的大小。

# 什么是镜像？

在 Linux 中，一切都是文件。整个操作系统基本上是一个存储在本地磁盘上的文件系统。当查看容器镜像时，这是一个重要的事实要记住。正如我们将看到的，镜像基本上是一个包含文件系统的大型 tarball。更具体地说，它包含一个分层文件系统。

# 分层文件系统

容器镜像是创建容器的模板。这些镜像不仅由一个单一的块组成，而是由许多层组成。镜像中的第一层也被称为基础层。我们可以在下面的图形中看到这一点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f648f501-f54d-4794-ae3f-c17ec8f78b6c.png)

镜像就像一堆层叠的图层

每个单独的图层都包含文件和文件夹。每个图层只包含相对于底层的文件系统的更改。Docker 使用 Union 文件系统——如第三章中所讨论的*掌握容器*——从一组图层中创建虚拟文件系统。存储驱动程序处理有关这些图层如何相互交互的详细信息。不同的存储驱动程序可在不同情况下具有优势和劣势。

容器镜像的层都是不可变的。不可变意味着一旦生成，该层就永远不能被改变。唯一可能影响层的操作是其物理删除。层的这种不可变性很重要，因为它为我们打开了大量的机会，我们将会看到。

在下面的屏幕截图中，我们可以看到一个基于 Nginx 作为 Web 服务器的 Web 应用程序的自定义镜像是什么样子的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/48c83b9e-fef1-45d9-a084-c1076f3e396d.png)

基于 Alpine 和 Nginx 的示例自定义镜像

我们的基础层是**Alpine Linux**发行版。然后，在此基础上，我们有一个**添加 Nginx**层，其中 Nginx 添加在 Alpine 之上。最后，第三层包含构成 Web 应用程序的所有文件，如 HTML、CSS 和 JavaScript 文件。

正如之前所说，每个镜像都以基础镜像开始。通常，这个基础镜像是在 Docker Hub 上找到的官方镜像之一，比如 Linux 发行版、Alpine、Ubuntu 或 CentOS。然而，也可以从头开始创建一个镜像。

Docker Hub 是一个用于容器镜像的公共注册表。它是一个中央枢纽，非常适合共享公共容器镜像。

每个层只包含相对于前一组层的更改。每个层的内容都映射到主机系统上的一个特殊文件夹，通常是`/var/lib/docker/`的子文件夹。

由于层是不可变的，它们可以被缓存而永远不会变得过时。这是一个很大的优势，我们将会看到。

# 可写的容器层

正如我们所讨论的，一个容器镜像由一堆不可变或只读的层组成。当 Docker 引擎从这样的镜像创建一个容器时，它会在这堆不可变层的顶部添加一个可写的容器层。我们的堆现在看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/35fc8834-7fa6-42ad-bdd6-7979a1878438.png)

可写的容器层

容器层标记为可读/可写。镜像层的不可变性的另一个优点是它们可以在许多从该镜像创建的容器之间共享。所需的只是每个容器的一个薄的可写容器层，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/0e32cfeb-d02b-4397-8ead-f1e066194ef3.png)

共享相同镜像层的多个容器

当然，这种技术会大大减少资源的消耗。此外，这有助于减少容器的加载时间，因为一旦镜像层加载到内存中，只需创建一个薄容器层，这仅发生在第一个容器中。

# 写时复制

Docker 在处理镜像时使用写时复制技术。写时复制是一种用于最大效率共享和复制文件的策略。如果一个层使用了一个低层次层中可用的文件或文件夹，那么它就直接使用它。另一方面，如果一个层想要修改一个低层次层中的文件，那么它首先将该文件复制到目标层，然后进行修改。在下面的截图中，我们可以看到这意味着什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7129ffa2-5290-455b-847a-1ae41c2aee0f.png)

使用写时复制的 Docker 镜像

第二层想要修改**文件 2**，它存在于**基础层**中。因此，它将其复制并进行修改。现在，假设我们正处于前面截图的顶层。这一层将使用**基础层**中的**文件 1**，以及第二层中的**文件 2**和**文件 3**。

# 图形驱动程序

图形驱动程序是启用联合文件系统的东西。图形驱动程序也称为存储驱动程序，在处理分层容器镜像时使用。图形驱动程序将多个镜像层合并为容器的挂载命名空间的根文件系统。换句话说，驱动程序控制着镜像和容器在 Docker 主机上的存储和管理方式。

Docker 支持使用可插拔架构的多种不同的图形驱动程序。首选驱动程序是`overlay2`，其次是`overlay`。

# 创建镜像

在您的系统上有三种方法可以创建一个新的容器镜像。第一种方法是通过交互式地构建一个包含所有所需的添加和更改的容器，然后将这些更改提交到一个新的镜像中。第二种，也是最重要的方法是使用`Dockerfile`描述新镜像中的内容，然后使用该`Dockerfile`构建镜像作为清单。最后，创建镜像的第三种方法是通过从 tarball 导入到系统中。

现在，让我们详细看看这三种方式。

# 交互式镜像创建

我们可以创建自定义镜像的第一种方式是通过交互式构建容器。也就是说，我们从要用作模板的基本镜像开始，并以交互方式运行一个容器。假设这是 Alpine 镜像。

要交互式地创建一个镜像，请按照以下步骤进行：

1.  运行容器的命令应该如下所示：

```
$ docker container run -it \
    --name sample \
    alpine:3.10 /bin/sh
```

上述命令基于`alpine:3.10`镜像运行一个容器。

我们使用`-it`参数交互式运行附加了**电传打字机**（**TTY**）的容器，使用`--name`参数将其命名为`sample`，最后在容器内部使用`/bin/sh`运行一个 shell。

在运行上述命令的终端窗口中，您应该看到类似于这样的内容：

```
Unable to find image 'alpine:3.10' locally
3.10: Pulling from library/alpine
921b31ab772b: Pull complete
Digest: sha256:ca1c944a4f8486a153024d9965aafbe24f5723c1d5c02f4964c045a16d19dc54
Status: Downloaded newer image for alpine:3.10
/ #
```

默认情况下，`alpine`容器没有安装`ping`工具。假设我们想要创建一个新的自定义镜像，其中安装了`ping`。

1.  在容器内部，我们可以运行以下命令：

```
/ # apk update && apk add iputils
```

这使用`apk` Alpine 软件包管理器来安装`iputils`库，其中包括`ping`。上述命令的输出应该大致如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7095041c-9ad2-4bfc-bc0e-940fd1351b23.png)在 Alpine 上安装`ping`

1.  现在，我们确实可以使用`ping`，如下面的代码片段所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/914c8ee9-964b-49b0-afe2-e1b0dd28d57b.png)在容器内部使用 ping

1.  完成自定义后，我们可以通过在提示符处键入`exit`退出容器。

如果我们现在使用`ls -a` Docker 容器列出所有容器，我们可以看到我们的示例容器的状态为`Exited`，但仍然存在于系统中，如下面的代码块所示：

```
$ docker container ls -a | grep sample
040fdfe889a6 alpine:3.10 "/bin/sh" 8 minutes ago Exited (0) 4 seconds ago
```

1.  如果我们想要查看容器相对于基本镜像的变化，我们可以使用`docker container diff`命令，如下所示：

```
$ docker container diff sample
```

输出应该呈现出容器文件系统上的所有修改列表，如下所示：

```
C /usr
C /usr/sbin
A /usr/sbin/getcap
A /usr/sbin/ipg
A /usr/sbin/tftpd
A /usr/sbin/ninfod
A /usr/sbin/rdisc
A /usr/sbin/rarpd
A /usr/sbin/tracepath
...
A /var/cache/apk/APKINDEX.d8b2a6f4.tar.gz
A /var/cache/apk/APKINDEX.00740ba1.tar.gz
C /bin
C /bin/ping
C /bin/ping6
A /bin/traceroute6
C /lib
C /lib/apk
C /lib/apk/db
C /lib/apk/db/scripts.tar
C /lib/apk/db/triggers
C /lib/apk/db/installed
```

我们已经缩短了上述输出以便更好地阅读。在列表中，`A`代表*添加*，`C`代表*更改*。如果有任何已删除的文件，那么它们将以**`D`**为前缀。

1.  现在，我们可以使用`docker container commit`命令来保存我们的修改并从中创建一个新的镜像，如下所示：

```
$ docker container commit sample my-alpine
sha256:44bca4141130ee8702e8e8efd1beb3cf4fe5aadb62a0c69a6995afd49c2e7419
```

通过上述命令，我们指定了新镜像将被称为`my-alpine`。上述命令生成的输出对应于新生成的镜像的 ID。

1.  我们可以通过列出系统上的所有镜像来验证这一点，如下所示：

```
$ docker image ls
```

我们可以看到这个图像 ID（缩短）如下：

```
REPOSITORY   TAG      IMAGE ID       CREATED              SIZE
my-alpine    latest   44bca4141130   About a minute ago   7.34MB
...
```

我们可以看到名为`my-alpine`的图像具有预期的 ID`44bca4141130`，并自动分配了`latest`标签。这是因为我们没有明确定义标签。在这种情况下，Docker 总是默认为`latest`标签。

1.  如果我们想要查看我们的自定义图像是如何构建的，我们可以使用`history`命令如下：

```
$ docker image history my-alpine
```

这将打印出我们的图像包含的层的列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/c399a38d-20a1-48b9-8210-4831f035b78e.png)my-alpine Docker 图像的历史

在前面的输出中，第一层是我们刚刚通过添加`iputils`包创建的层。

# 使用 Dockerfile

手动创建自定义图像，如本章的前一节所示，当进行探索、创建原型或进行可行性研究时非常有帮助。但它有一个严重的缺点：这是一个手动过程，因此不可重复或可扩展。它也像人类手动执行的任何其他任务一样容易出错。必须有更好的方法。

这就是所谓的`Dockerfile`发挥作用的地方。`Dockerfile`是一个文本文件，通常被称为`Dockerfile`。它包含了构建自定义容器映像的指令。这是一种声明性构建图像的方式。

声明式与命令式：

在计算机科学中，通常情况下，特别是在 Docker 中，人们经常使用声明性的方式来定义任务。人们描述期望的结果，让系统找出如何实现这个目标，而不是给系统提供逐步实现所需结果的指令。后者是一种命令式的方法。

让我们看一个示例`Dockerfile`，如下所示：

```
FROM python:2.7
RUN mkdir -p /app
WORKDIR /app
COPY ./requirements.txt /app/
RUN pip install -r requirements.txt
CMD ["python", "main.py"]
```

这是一个`Dockerfile`，用于容器化 Python 2.7 应用程序。正如我们所看到的，文件有六行，每行以关键字开头，如`FROM`、`RUN`或`COPY`。习惯上将关键字写成大写，但这不是必须的。

`Dockerfile`的每一行都会导致结果图像中的一个层。在下面的截图中，与本章前面的插图相比，图像被颠倒过来，显示为一堆层。在这里，**基础层**显示在顶部。不要被这个搞混了。实际上，基础层始终是堆栈中最低的层：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/3f4c11dd-4fed-478b-b229-cdc834633c62.png)

图像中 Dockerfile 和层的关系

现在，让我们更详细地看看各个关键字。

# FROM 关键字

每个`Dockerfile`都以`FROM`关键字开始。通过它，我们定义了要从哪个基础镜像开始构建我们的自定义镜像。例如，如果我们想从 CentOS 7 开始构建，我们会在`Dockerfile`中有以下行：

```
FROM centos:7
```

在 Docker Hub 上，有所有主要 Linux 发行版的精选或官方镜像，以及所有重要的开发框架或语言，比如 Python、Node.js、Ruby、Go 等等。根据我们的需求，我们应该选择最合适的基础镜像。

例如，如果我想容器化一个 Python 3.7 应用程序，我可能会选择相关的官方`python:3.7`镜像。

如果我们真的想从头开始，我们也可以使用以下语句：

```
FROM scratch
```

这在构建超小型镜像的情况下非常有用，比如只包含一个二进制文件的情况：实际的静态链接可执行文件，比如`Hello-World`。`scratch`镜像实际上是一个空的基础镜像。

`FROM scratch`在`Dockerfile`中是一个`no-op`，因此不会在生成的容器镜像中生成一个层。

# RUN 关键字

下一个重要的关键字是`RUN`。`RUN`的参数是任何有效的 Linux 命令，比如以下内容：

```
RUN yum install -y wget
```

前面的命令使用`yum` CentOS 包管理器来在运行的容器中安装`wget`包。这假设我们的基础镜像是 CentOS 或 Red Hat Enterprise Linux（RHEL）。如果我们的基础镜像是 Ubuntu，那么命令会类似于以下内容：

```
RUN apt-get update && apt-get install -y wget
```

这是因为 Ubuntu 使用`apt-get`作为包管理器。同样，我们可以定义一行`RUN`命令，如下所示：

```
RUN mkdir -p /app && cd /app
```

我们也可以这样做：

```
RUN tar -xJC /usr/src/python --strip-components=1 -f python.tar.xz
```

在这里，前者在容器中创建了一个`/app`文件夹并导航到它，后者将一个文件解压到指定位置。完全可以，甚至建议你使用多于一行的物理行来格式化 Linux 命令，比如这样：

```
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
 ca-certificates \
 libexpat1 \
 libffi6 \
 libgdbm3 \
 libreadline7 \
 libsqlite3-0 \
 libssl1.1 \
 && rm -rf /var/lib/apt/lists/*
```

如果我们使用多行，需要在行尾加上反斜杠（`\`）来指示 shell 命令在下一行继续。

尝试找出前面的命令是做什么的。

# COPY 和 ADD 关键字

`COPY`和`ADD`关键字非常重要，因为最终我们希望向现有的基础镜像添加一些内容，使其成为自定义镜像。大多数情况下，这些是一些源文件，比如 Web 应用程序，或者一些已编译应用程序的二进制文件。

这两个关键字用于将文件和文件夹从主机复制到正在构建的镜像中。 这两个关键字非常相似，唯一的区别是`ADD`关键字还允许我们复制和解压缩 TAR 文件，并提供 URL 作为要复制的文件和文件夹的来源。

让我们看一些如何使用这两个关键字的示例，如下所示：

```
COPY . /app
COPY ./web /app/web
COPY sample.txt /data/my-sample.txt
ADD sample.tar /app/bin/
ADD http://example.com/sample.txt /data/
```

在上述代码的前几行中，适用以下内容：

+   第一行将当前目录中的所有文件和文件夹递归地复制到容器镜像内的`app`文件夹中。

+   第二行将`web`子文件夹中的所有内容复制到目标文件夹`/app/web`。

+   第三行将单个文件`sample.txt`复制到目标文件夹`/data`中，并同时将其重命名为`my-sample.txt`。

+   第四个语句将`sample.tar`文件解压缩到目标文件夹`/app/bin`中。

+   最后，最后一个语句将远程文件`sample.txt`复制到目标文件`/data`中。

源路径中允许使用通配符。 例如，以下语句将所有以`sample`开头的文件复制到镜像内的`mydir`文件夹中：

```
COPY ./sample* /mydir/
```

从安全角度来看，重要的是要知道，默认情况下，镜像内的所有文件和文件夹都将具有`0`的**用户 ID**（**UID**）和**组 ID**（**GID**）。 好处是，对于`ADD`和`COPY`，我们可以使用可选的`--chown`标志更改镜像内文件的所有权，如下所示：

```
ADD --chown=11:22 ./data/web* /app/data/
```

前面的语句将复制所有以`web`开头的文件并将它们放入镜像中的`/app/data`文件夹，并同时为这些文件分配用户`11`和组`22`。

除了数字之外，用户和组也可以使用名称，但是这些实体必须已在镜像的根文件系统中的`/etc/passwd`和`/etc/group`中定义； 否则，镜像的构建将失败。

# WORKDIR 关键字

`WORKDIR`关键字定义了在从我们的自定义镜像运行容器时使用的工作目录或上下文。 因此，如果我想将上下文设置为镜像内的`/app/bin`文件夹，则我的`Dockerfile`中的表达式必须如下所示：

```
WORKDIR /app/bin
```

在前一行之后发生的所有活动都将使用此目录作为工作目录。 非常重要的一点是要注意，`Dockerfile`中以下两个片段不同：

```
RUN cd /app/bin
RUN touch sample.txt
```

将前面的代码与以下代码进行比较：

```
WORKDIR /app/bin
RUN touch sample.txt
```

前者将在图像文件系统的根目录中创建文件，而后者将在`/app/bin`文件夹中的预期位置创建文件。只有`WORKDIR`关键字设置了图像层之间的上下文。`cd`命令本身不会跨层持久存在。

# CMD 和 ENTRYPOINT 关键字

`CMD`和`ENTRYPOINT`关键字是特殊的。虽然`Dockerfile`为图像定义的所有其他关键字都是由 Docker 构建器在构建图像时执行的，但这两个关键字实际上是定义了当从我们定义的图像启动容器时会发生什么。当容器运行时启动一个容器，它需要知道在该容器内部将运行的进程或应用程序是什么。这正是`CMD`和`ENTRYPOINT`用于告诉 Docker 启动进程是什么以及如何启动该进程。

现在，`CMD`和`ENTRYPOINT`之间的区别微妙，老实说，大多数用户并不完全理解它们，也不按照预期的方式使用它们。幸运的是，在大多数情况下，这不是问题，容器仍然会运行；只是处理它的方式不像可能那么直接。

为了更好地理解如何使用这两个关键字，让我们分析一下典型的 Linux 命令或表达式是什么样的。让我们以`ping`实用程序为例，如下所示：

```
$ ping -c 3 8.8.8.8
```

在上述表达式中，`ping`是命令，`-c 3 8.8.8.8`是这个命令的参数。让我们再看一个表达式：

```
$ wget -O - http://example.com/downloads/script.sh
```

同样，在上述表达式中，`wget`是命令，`-O - http://example.com/downloads/script.sh`是参数。

现在我们已经处理了这个问题，我们可以回到`CMD`和`ENTRYPOINT`。`ENTRYPOINT`用于定义表达式的命令，而`CMD`用于定义命令的参数。因此，使用 Alpine 作为基础镜像并在容器中定义`ping`作为要运行的进程的`Dockerfile`可能如下所示：

```
FROM alpine:3.10
ENTRYPOINT ["ping"]
CMD ["-c","3","8.8.8.8"]
```

对于`ENTRYPOINT`和`CMD`，值被格式化为一个字符串的 JSON 数组，其中各个项对应于表达式的标记，这些标记由空格分隔。这是定义`CMD`和`ENTRYPOINT`的首选方式。它也被称为*exec*形式。

另外，也可以使用所谓的 shell 形式，如下所示：

```
CMD command param1 param2
```

现在我们可以从上述`Dockerfile`构建一个名为`pinger`的镜像，如下所示：

```
$ docker image build -t pinger .
```

然后，我们可以从我们刚刚创建的`pinger`镜像中运行一个容器，就像这样：

```
$ docker container run --rm -it pinger
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: seq=0 ttl=37 time=19.298 ms
64 bytes from 8.8.8.8: seq=1 ttl=37 time=27.890 ms
64 bytes from 8.8.8.8: seq=2 ttl=37 time=30.702 ms
```

这样做的美妙之处在于，我现在可以通过在`docker container run`表达式的末尾添加新值来覆盖我在`Dockerfile`中定义的`CMD`部分（记住，它是`["-c", "3","8.8.8.8"]`），就像这样：

```
$ docker container run --rm -it pinger -w 5 127.0.0.1
```

这将导致容器现在对环回进行 ping 操作，持续 5 秒。

如果我们想要覆盖`Dockerfile`中定义的`ENTRYPOINT`，我们需要在`docker container run`表达式中使用`--entrypoint`参数。假设我们想要在容器中执行 shell 而不是`ping`命令。我们可以通过使用以下命令来实现：

```
$ docker container run --rm -it --entrypoint /bin/sh pinger
```

我们随后将发现自己在容器内部。键入`exit`离开容器。

正如我已经提到的，我们不一定要遵循最佳实践，并通过`ENTRYPOINT`定义命令和通过`CMD`定义参数；相反，我们可以将整个表达式作为`CMD`的值输入，它将起作用，如下面的代码块所示：

```
FROM alpine:3.10
CMD wget -O - http://www.google.com
```

在这里，我甚至使用了 shell 形式来定义`CMD`。但是在`ENTRYPOINT`未定义的情况下会发生什么？如果您未定义`ENTRYPOINT`，那么它将具有默认值`/bin/sh -c`，并且`CMD`的任何值都将作为字符串传递给 shell 命令。因此，前面的定义将导致输入以下代码来运行容器内的进程：

```
/bin/sh -c "wget -O - http://www.google.com"
```

因此，`/bin/sh`是在容器内运行的主要进程，并且它将启动一个新的子进程来运行`wget`实用程序。

# 一个复杂的 Dockerfile

我们已经讨论了 Dockerfile 中常用的最重要的关键字。让我们看一个现实的，有些复杂的`Dockerfile`的例子。感兴趣的读者可能会注意到，它看起来与我们在本章中呈现的第一个`Dockerfile`非常相似。以下是内容：

```
FROM node:12.5-stretch
RUN mkdir -p /app
WORKDIR /app
COPY package.json /app/
RUN npm install
COPY . /app
ENTRYPOINT ["npm"]
CMD ["start"]
```

好了，这里发生了什么？显然，这是一个用于构建 Node.js 应用程序的`Dockerfile`；我们可以从使用`node:12.5-stretch`基础镜像这一事实推断出来。然后，第二行是一个指令，在镜像的文件系统中创建一个/app 文件夹。第三行定义了镜像中的工作目录或上下文为这个新的/app 文件夹。然后，在第四行，我们将一个`package.json`文件复制到镜像内的/app 文件夹中。之后，在第五行，我们在容器内执行`npm install`命令；请记住，我们的上下文是/app 文件夹，因此 npm 会在那里找到我们在第四行复制的 package.json 文件。

在安装了所有 Node.js 依赖项之后，我们将应用程序的其余文件从主机的当前文件夹复制到镜像的/app 文件夹中。

最后，在最后两行，我们定义了当从这个镜像运行容器时启动命令将是什么。在我们的情况下，它是`npm start`，这将启动 Node.js 应用程序。

# 构建镜像

让我们看一个具体的例子并构建一个简单的 Docker 镜像，如下所示：

1.  在你的主目录中，创建一个名为`fod`（代表 Docker 基础知识）的文件夹，其中包含一个名为`ch04`的子文件夹，并导航到这个文件夹，就像这样：

```
$ mkdir -p ~/fod/ch04 && cd ~/fod/ch04
```

1.  在上述文件夹中，创建一个`sample1`子文件夹并导航到它，就像这样：

```
$ mkdir sample1 && cd sample1
```

1.  使用你喜欢的编辑器在这个示例文件夹中创建一个名为`Dockerfile`的文件，并包含以下内容：

```
FROM centos:7
RUN yum install -y wget
```

4. 保存文件并退出编辑器。

5. 回到终端窗口，我们现在可以使用上述`Dockerfile`作为清单或构建计划构建一个新的容器镜像，就像这样：

```
$ docker image build -t my-centos .
```

请注意，上述命令末尾有一个句点。这个命令意味着 Docker 构建器正在使用当前目录中存在的`Dockerfile`创建一个名为`my-centos`的新镜像。这里，命令末尾的句点代表*当前目录*。我们也可以将上述命令写成如下形式，结果是一样的：

```
$ docker image build -t my-centos -f Dockerfile .
```

但是我们可以省略`-f`参数，因为构建器假设`Dockerfile`的确切名称为`Dockerfile`。只有当我们的`Dockerfile`具有不同的名称或不位于当前目录时，我们才需要`-f`参数。

上述命令给出了这个（缩短的）输出：

```
Sending build context to Docker daemon 2.048kB
Step 1/2 : FROM centos:7
7: Pulling from library/centos
af4b0a2388c6: Pull complete
Digest: sha256:2671f7a3eea36ce43609e9fe7435ade83094291055f1c96d9d1d1d7c0b986a5d
Status: Downloaded newer image for centos:7
---> ff426288ea90
Step 2/2 : RUN yum install -y wget
---> Running in bb726903820c
Loaded plugins: fastestmirror, ovl
Determining fastest mirrors
* base: mirror.dal10.us.leaseweb.net
* extras: repos-tx.psychz.net
* updates: pubmirrors.dal.corespace.com
Resolving Dependencies
--> Running transaction check
---> Package wget.x86_64 0:1.14-15.el7_4.1 will be installed
...
Installed:
  wget.x86_64 0:1.14-15.el7_4.1
Complete!
Removing intermediate container bb726903820c
---> bc070cc81b87
Successfully built bc070cc81b87
Successfully tagged my-centos:latest
```

让我们分析这个输出，如下所示：

1.  首先，我们有以下一行：

```
Sending build context to Docker daemon 2.048kB
```

构建器的第一件事是打包当前构建上下文中的文件，排除了`.dockerignore`文件中提到的文件和文件夹（如果存在），然后将生成的`.tar`文件发送给`Docker 守护程序`。

1.  接下来，我们有以下几行：

```
Step 1/2 : FROM centos:7
7: Pulling from library/centos
af4b0a2388c6: Pull complete
Digest: sha256:2671f7a...
Status: Downloaded newer image for centos:7
---> ff426288ea90
```

构建器的第一行告诉我们当前正在执行`Dockerfile`的哪个步骤。在这里，我们的`Dockerfile`中只有两个语句，我们正在执行第*2*步中的*步骤 1*。我们还可以看到该部分的内容是什么。在这里，它是基础镜像的声明，我们要在其上构建自定义镜像。然后构建器会从 Docker Hub 拉取这个镜像，如果本地缓存中没有的话。前面代码片段的最后一行指示了构建器分配给刚构建的镜像层的 ID。

1.  现在，继续下一步。我将它比前面的部分更加简短，以便集中在关键部分上：

```
Step 2/2 : RUN yum install -y wget
---> Running in bb726903820c
...
...
Removing intermediate container bb726903820c
---> bc070cc81b87
```

在这里，第一行再次告诉我们，我们正在*步骤 2*中的*步骤 2*。它还向我们显示了`Dockerfile`中的相应条目。在第二行，我们可以看到`Running in bb726903820c`，这告诉我们构建器已创建了一个 ID 为`bb726903820c`的容器，在其中执行了`RUN`命令。

我们在片段中省略了`yum install -y wget`命令的输出，因为在这一部分并不重要。当命令完成时，构建器停止容器，将其提交到一个新层，然后删除容器。在这种特殊情况下，新层的 ID 是`bc070cc81b87`。

1.  在输出的最后，我们遇到以下两行：

```
Successfully built bc070cc81b87
Successfully tagged my-centos:latest
```

这告诉我们，生成的自定义镜像已被赋予 ID`bc070cc81b87`，并且已被标记为名称`my-centos:latest`。

那么，构建器的工作原理是什么？它从基本图像开始。一旦将基本图像下载到本地缓存中，构建器就会创建一个容器，并在该容器中运行`Dockerfile`中的第一个语句。然后，它停止容器，并将容器中所做的更改持久化到一个新的图像层中。然后，构建器从基本图像和新层创建一个新的容器，并在该新容器中运行第二个语句。再次，结果被提交到一个新的层中。这个过程重复进行，直到`Dockerfile`中遇到最后一个语句。在提交了新图像的最后一层之后，构建器为该图像创建一个 ID，并使用我们在“build”命令中提供的名称对图像进行标记，如下面的屏幕截图所示。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/13c9e699-35e5-40dc-b064-d64472d15f03.png)

可视化的图像构建过程

现在我们已经分析了 Docker 图像的构建过程以及涉及的步骤，让我们谈谈如何通过引入多步构建来进一步改进这一过程。

# 多步构建

为了演示为什么具有多个构建步骤的`Dockerfile`是有用的，让我们制作一个示例`Dockerfile`。让我们以 C 语言编写的“Hello World”应用程序为例。以下是`hello.c`文件中的代码：

```
#include <stdio.h>
int main (void)
{
    printf ("Hello, world!\n");
    return 0;
}
```

跟着来体验多步构建的优势：

1.  要将此应用程序容器化，我们首先编写一个带有以下内容的`Dockerfile`：

```
FROM alpine:3.7
RUN apk update &&
apk add --update alpine-sdk
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN mkdir bin
RUN gcc -Wall hello.c -o bin/hello
CMD /app/bin/hello
```

1.  接下来，让我们构建这个图像：

```
$ docker image build -t hello-world .
```

这给我们带来了相当长的输出，因为构建器必须安装 Alpine 软件开发工具包（SDK），其中包含我们需要构建应用程序的 C++编译器等工具。

1.  构建完成后，我们可以列出图像并查看其大小，如下所示：

```
$ docker image ls | grep hello-world
hello-world   latest   e9b...   2 minutes ago   176MB
```

生成的图像大小为 176 MB，太大了。最后，它只是一个“Hello World”应用程序。它如此之大的原因是图像不仅包含“Hello World”二进制文件，还包含从源代码编译和链接应用程序所需的所有工具。但是当在生产环境中运行应用程序时，这确实是不可取的。理想情况下，我们只希望图像中有生成的二进制文件，而不是整个 SDK。

正是因为这个原因，我们应该将 Dockerfiles 定义为多阶段。我们有一些阶段用于构建最终的构件，然后有一个最终阶段，在这个阶段我们使用最小必要的基础镜像，并将构件复制到其中。这样可以得到非常小的 Docker 镜像。看一下这个修改后的`Dockerfile`：

```
FROM alpine:3.7 AS build
RUN apk update && \
    apk add --update alpine-sdk
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN mkdir bin
RUN gcc hello.c -o bin/hello

FROM alpine:3.7
COPY --from=build /app/bin/hello /app/hello
CMD /app/hello
```

在这里，我们有第一个阶段使用`build`别名来编译应用程序，然后第二个阶段使用相同的`alpine:3.7`基础镜像，但不安装 SDK，只是使用`--from`参数将二进制文件从`build`阶段复制到最终镜像中：

1.  让我们再次构建镜像，如下所示：

```
$ docker image build -t hello-world-small .
```

1.  当我们比较镜像的大小时，得到以下输出：

```
$ docker image ls | grep hello-world
hello-world-small  latest   f98...   20 seconds ago   4.16MB
hello-world        latest   469...   10 minutes ago   176MB
```

我们已经成功将大小从 176MB 减小到 4MB。这是大小减小了 40 倍。较小的镜像有许多优点，比如对黑客来说攻击面积更小，内存和磁盘消耗更少，相应容器的启动时间更快，以及从 Docker Hub 等注册表下载镜像所需的带宽减少。

# Dockerfile 最佳实践

在编写`Dockerfile`时，有一些推荐的最佳实践需要考虑，如下所示：

+   首先，我们需要考虑容器是短暂的。所谓短暂，意味着容器可以停止和销毁，然后新建一个并以绝对最少的设置和配置放置在原位。这意味着我们应该努力将容器内运行的应用程序初始化所需的时间保持在最低限度，以及终止或清理应用程序所需的时间也要尽量减少。

+   下一个最佳实践告诉我们应该按照尽可能利用缓存的方式来排序`Dockerfile`中的各个命令。构建镜像的一层可能需要相当长的时间，有时甚至需要几秒钟，甚至几分钟。在开发应用程序时，我们将不得不多次为我们的应用程序构建容器镜像。我们希望将构建时间保持在最低限度。

当我们重新构建之前构建过的镜像时，只有发生了变化的层才会被重新构建，但如果需要重新构建一个层，所有后续的层也需要重新构建。这一点非常重要。考虑以下例子：

```
FROM node:9.4
RUN mkdir -p /app
WORKIR /app
COPY . /app
RUN npm install
CMD ["npm", "start"]
```

在这个例子中，`Dockerfile`的第五行上的`npm install`命令通常需要最长的时间。经典的 Node.js 应用程序有许多外部依赖项，这些依赖项都会在这一步骤中下载和安装。这可能需要几分钟才能完成。因此，我们希望避免在重建图像时每次运行`npm install`，但是开发人员在应用程序开发过程中经常更改其源代码。这意味着第四行的`COPY`命令的结果每次都会更改，因此必须重新构建该图层。但正如我们之前讨论的，这也意味着所有后续的图层都必须重新构建，而在这种情况下，包括`npm install`命令。为了避免这种情况，我们可以稍微修改`Dockerfile`，并采用以下方式：

```
FROM node:9.4
RUN mkdir -p /app
WORKIR /app
COPY package.json /app/
RUN npm install
COPY . /app
CMD ["npm", "start"]
```

我们在这里所做的是，在第四行，我们只复制了`npm install`命令需要的单个文件，即`package.json`文件。在典型的开发过程中，这个文件很少更改。因此，`npm install`命令也只有在`package.json`文件更改时才需要执行。所有其余经常更改的内容都是在`npm install`命令之后添加到图像中的。

+   进一步的最佳实践是保持构成图像的图层数量相对较少。图像的图层越多，图形驱动程序就需要更多的工作来将这些图层合并为相应容器的单一根文件系统。当然，这需要时间，因此图像的图层数量越少，容器的启动时间就越快。

但是我们如何保持图层数量较少呢？请记住，在`Dockerfile`中，每一行以`FROM`、`COPY`或`RUN`等关键字开头的命令都会创建一个新的图层。减少图层数量的最简单方法是将多个单独的`RUN`命令合并为一个。例如，假设我们在`Dockerfile`中有以下内容：

```
RUN apt-get update
RUN apt-get install -y ca-certificates
RUN rm -rf /var/lib/apt/lists/*
```

我们可以将这些内容合并为一个单一的连接表达式，如下所示：

```
RUN apt-get update \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
```

前者将在生成的图像中生成三个图层，而后者只创建一个单一的图层。

接下来的三种最佳实践都会导致更小的图像。为什么这很重要？更小的图像减少了从注册表下载图像所需的时间和带宽。它们还减少了在 Docker 主机上本地存储副本所需的磁盘空间和加载图像所需的内存。最后，更小的图像也意味着对黑客的攻击面更小。以下是提到的最佳实践：

+   第一个最佳实践有助于减小图像大小的方法是使用`.dockerignore`文件。我们希望避免将不必要的文件和文件夹复制到图像中，以使其尽可能精简。`.dockerignore`文件的工作方式与熟悉 Git 的人所熟悉的`.gitignore`文件完全相同。在`.dockerignore`文件中，我们可以配置模式来排除某些文件或文件夹在构建图像时包含在上下文中。

+   下一个最佳实践是避免将不必要的软件包安装到图像的文件系统中。再次强调，这是为了使图像尽可能精简。

+   最后但同样重要的是，建议您使用多阶段构建，以使生成的图像尽可能小，并且仅包含运行应用程序或应用程序服务所需的绝对最小内容。

# 保存和加载图像

创建新容器图像的第三种方法是通过从文件导入或加载它。容器图像只不过是一个 tarball。为了证明这一点，我们可以使用`docker image save`命令将现有图像导出为 tarball，就像这样：

```
$ docker image save -o ./backup/my-alpine.tar my-alpine
```

上述命令将我们之前构建的`my-alpine`图像导出到名为`./backup/my-alpine.tar`的文件中。

另一方面，如果我们有一个现有的 tarball 并希望将其导入为图像到我们的系统中，我们可以使用`docker image load`命令，如下所示：

```
$ docker image load -i ./backup/my-alpine.tar 
```

在下一节中，我们将讨论如何为现有的传统应用程序创建 Docker 图像，并在容器中运行它们，并从中获利。

# 举起和转移：容器化传统应用程序

我们并不总是能够从零开始开发全新的应用程序。往往情况是，我们手头有一大批传统应用程序，它们已经在生产环境中运行，并为公司或客户提供了至关重要的价值。这些应用程序往往是有机发展而来，非常复杂。文档稀缺，没有人真的愿意去碰这样的应用程序。通常情况下，有句话叫做“不要碰正在运行的系统”。然而，市场需求在变化，因此需要更新或重写这些应用程序。由于资源和时间的缺乏，或者成本过高，通常情况下完全重写是不可能的。那么我们该怎么办呢？我们是否可以将它们 Docker 化，并从容器引入的好处中获益呢？

事实证明我们可以。2017 年，Docker 为企业客户推出了一个名为“现代化传统应用程序”（MTA）的计划，该计划本质上承诺帮助这些客户将他们现有的或传统的 Java 和.NET 应用程序进行容器化，而无需改变一行代码。MTA 的重点是 Java 和.NET 应用程序，因为它们在典型企业中占据了绝大部分传统应用程序的份额。但对于任何使用其他语言和平台编写的应用程序，比如 C、C++、Python、Node.js、Ruby、PHP 或 Go 等，也是可能的。

让我们想象一下这样一个遗留应用程序。假设我们有一个 10 年前编写的旧 Java 应用程序，并在接下来的 5 年中不断更新。该应用程序基于 2006 年 12 月发布的 Java SE 6。它使用环境变量和属性文件进行配置。数据库连接字符串中使用的用户名和密码等机密信息是从诸如 HashiCorp 的 Vault 之类的机密存储库中提取的。

# 对外部依赖关系的分析。

现代化过程中的第一步之一是发现和列出遗留应用程序的所有外部依赖关系。

我们需要问自己一些类似以下的问题：

1.  它是否使用数据库？如果是，是哪种数据库？连接字符串是什么样的？

1.  它是否使用外部 API，比如信用卡批准或地理映射 API？API 密钥和密钥机密是什么？

1.  它是否从企业服务总线（ESB）中消费或发布？

这些只是我想到的一些可能的依赖关系。还有更多存在。这些是应用程序与外部世界的接缝，我们需要意识到它们并创建清单。

# 源代码和构建说明

下一步是定位所有源代码和其他资产，例如应用程序的图像、CSS 和 HTML 文件。理想情况下，它们应该位于一个单独的文件夹中。这个文件夹将是我们项目的根目录，可以有许多子文件夹。这个项目根文件夹将在构建我们想要为我们的遗留应用程序创建的容器映像时成为上下文。请记住，Docker 构建器只包括构建中的上下文中的文件；在我们的情况下，这是根项目文件夹。

不过，有一个选项可以在构建过程中从不同位置下载或复制文件，使用`COPY`或`ADD`命令。有关如何使用这两个命令的确切细节，请参考在线文档。如果您的遗留应用程序的源不能轻松地包含在一个单独的本地文件夹中，这个选项是有用的。

一旦我们意识到所有部分都对最终应用程序有贡献，我们需要调查应用程序是如何构建和打包的。在我们的情况下，这很可能是通过使用 Maven 来完成的。Maven 是 Java 最流行的构建自动化工具，并且在大多数开发 Java 应用程序的企业中一直被使用。对于遗留的.NET 应用程序，很可能是通过使用 MSBuild 工具来完成；对于 C/C++应用程序，可能会使用 Make。

再次，让我们扩展我们的库存并记录使用的确切构建命令。以后在编写`Dockerfile`时，我们将需要这些信息。

# 配置

应用程序需要进行配置。在配置过程中提供的信息可以是，例如，要使用的应用程序日志记录类型、连接到数据库的连接字符串、到诸如 ESB 的服务的主机名或到外部 API 的 URI 等。

我们可以区分几种类型的配置，如下所示：

+   **构建时间**：这是在构建应用程序和/或其 Docker 映像时需要的信息。在我们创建 Docker 映像时，它需要可用。

+   环境：这是随着应用程序运行环境的不同而变化的配置信息，例如开发环境与暂存或生产环境。这种配置在应用程序启动时被应用，例如在生产环境中。

+   运行时：这是应用程序在运行时检索的信息，例如访问外部 API 的秘钥。

# 秘钥

每个关键的企业应用程序都需要以某种形式处理秘钥。最熟悉的秘钥是访问数据库所需的连接信息，这些数据库用于保存应用程序产生或使用的数据。其他秘钥包括访问外部 API 所需的凭据，例如信用评分查询 API。重要的是要注意，这里我们谈论的是应用程序必须提供给应用程序使用或依赖的服务提供商的秘钥，而不是应用程序用户提供的秘钥。这里的主体是我们的应用程序，它需要被外部机构和服务提供商进行认证和授权。

传统应用程序获取秘钥的方式有很多种。最糟糕和最不安全的提供秘钥的方式是将它们硬编码或从配置文件或环境变量中读取，这样它们就以明文形式可用。一个更好的方式是在运行时从特殊的秘钥存储中读取秘钥，该存储将秘钥加密并通过安全连接（如传输层安全性（TLS））提供给应用程序。

再一次，我们需要创建一个清单，列出我们的应用程序使用的所有秘钥以及它们获取秘钥的方式。是通过环境变量或配置文件，还是通过访问外部密钥存储，例如 HashiCorp 的 Vault？

# 编写 Dockerfile

一旦我们完成了前面几节讨论的所有项目清单，我们就可以开始编写我们的`Dockerfile`。但我想警告你：不要期望这是一个一次性的任务。你可能需要多次迭代，直到你制定出最终的`Dockerfile`。`Dockerfile`可能会相当长，看起来很丑陋，但这并不是问题，只要我们得到一个可用的 Docker 镜像。一旦我们有了可用的版本，我们总是可以微调`Dockerfile`。

# 基础镜像

让我们首先确定我们想要使用和构建图像的基本图像。是否有官方的 Java 图像可用，符合我们的要求？请记住，我们的虚构应用程序是基于 Java SE 6。如果有这样的基本图像可用，那么让我们使用那个。否则，我们想要从 Red Hat、Oracle 或 Ubuntu 等 Linux 发行版开始。在后一种情况下，我们将使用发行版的适当软件包管理器（`yum`、`apt`或其他）来安装所需版本的 Java 和 Maven。为此，我们在`Dockerfile`中使用`RUN`关键字。请记住，`RUN`关键字使我们有可能在构建过程中执行图像中的任何有效的 Linux 命令。

# 组装源代码

在这一步中，我们确保所有构建应用程序所需的源文件和其他工件都是图像的一部分。在这里，我们主要使用`Dockerfile`的两个关键字：`COPY`和`ADD`。最初，图像中的源结构应该与主机上的完全相同，以避免任何构建问题。理想情况下，您将有一个单独的`COPY`命令，将主机上的根项目文件夹全部复制到图像中。然后，相应的`Dockerfile`片段可能看起来就像这样简单：

```
WORKDIR /app
COPY . .
```

不要忘记还要提供一个位于项目根文件夹中的`.dockerignore`文件，其中列出了项目根文件夹中不应成为构建上下文一部分的所有文件和（子）文件夹。

如前所述，您还可以使用`ADD`关键字将不位于构建上下文中但可以通过 URI 访问的源代码和其他工件下载到 Docker 图像中，如下所示：

```
ADD http://example.com/foobar ./ 
```

这将在图像的工作文件夹中创建一个`foobar`文件夹，并从 URI 中复制所有内容。

# 构建应用程序

在这一步中，我们确保创建组成我们可执行的遗留应用程序的最终工件。通常，这是一个 JAR 或 WAR 文件，有或没有一些附属的 JAR 文件。`Dockerfile`的这部分应该完全模仿您在将应用程序容器化之前传统用于构建应用程序的方式。因此，如果使用 Maven 作为构建自动化工具，`Dockerfile`的相应片段可能看起来就像这样简单：

```
RUN mvn --clean install
```

在这一步中，我们可能还想列出应用程序使用的环境变量，并提供合理的默认值。但是永远不要为提供给应用程序的秘密环境变量提供默认值，比如数据库连接字符串！使用`ENV`关键字来定义你的变量，就像这样：

```
ENV foo=bar
ENV baz=123
```

还要声明应用程序正在侦听的所有端口，并且需要通过`EXPOSE`关键字从容器外部访问，就像这样：

```
EXPOSE 5000
EXPOSE 15672/tcp
```

# 定义启动命令

通常，Java 应用程序是通过诸如`java -jar <主应用程序 jar>`这样的命令启动的，如果它是一个独立的应用程序。如果是 WAR 文件，那么启动命令可能看起来有点不同。因此，我们可以定义`ENTRYPOINT`或`CMD`来使用这个命令。因此，我们的`Dockerfile`中的最终语句可能是这样的：

```
ENTRYPOINT java -jar pet-shop.war
```

然而，通常情况下这太过简单，我们需要执行一些预运行任务。在这种情况下，我们可以编写一个包含需要执行以准备环境并运行应用程序的一系列命令的脚本文件。这样的文件通常被称为`docker-entrypoint.sh`，但你可以自由地命名它。确保文件是可执行的—例如，使用以下命令：

```
chmod +x ./docker-entrypoint.sh
```

`Dockerfile`的最后一行将如下所示：

```
ENTRYPOINT ./docker-entrypoint.sh
```

现在你已经得到了如何将传统应用程序容器化的提示，是时候进行总结并问自己：*真的值得花这么大的努力吗？*

# 为什么费这个劲呢？

此时，我可以看到你正在挠头，问自己：*为什么要费这个劲呢？* 为什么你要花这么大的力气来容器化一个传统应用程序？有什么好处呢？

事实证明**投资回报率**（**ROI**）是巨大的。Docker 的企业客户在 DockerCon 2018 和 2019 等会议上公开披露，他们看到了 Docker 化传统应用程序的这两个主要好处：

+   维护成本节约超过 50%。

+   新版本发布之间的时间减少了 90%。

通过减少维护开销节省的成本可以直接再投资，并用于开发新功能和产品。在传统应用程序的新版本发布期间节省的时间使企业更具敏捷性，能够更快地对客户或市场需求的变化做出反应。

现在我们已经详细讨论了如何构建 Docker 图像，是时候学习如何通过软件交付流程的各个阶段来部署这些图像了。

# 分享或部署图像

为了能够将我们的自定义图像部署到其他环境中，我们需要首先为其指定一个全局唯一的名称。这个操作通常被称为给图像打标签。然后我们需要将图像发布到一个中央位置，其他感兴趣或有权限的方可以从中拉取。这些中央位置被称为*图像注册表*。

# 给图像打标签

每个图像都有一个所谓的*标签*。标签通常用于对图像进行版本控制，但它的作用远不止于版本号。如果在使用图像时没有明确指定标签，那么 Docker 会自动假定我们指的是`latest`标签。这在从 Docker Hub 拉取图像时很重要，就像下面的例子一样：

```
$ docker image pull alpine
```

上述命令将从 Docker Hub 拉取`alpine:latest`图像。如果我们想要明确指定一个标签，可以这样做：

```
$ docker image pull alpine:3.5
```

现在将拉取已标记为`3.5`的`alpine`图像。

# 图像命名空间

到目前为止，我们一直在拉取各种图像，并没有太在意这些图像的来源。您的 Docker 环境配置为，默认情况下所有图像都是从 Docker Hub 拉取的。我们还只从 Docker Hub 拉取了所谓的官方图像，比如`alpine`或`busybox`。

现在，是时候稍微扩大一下视野，了解图像的命名空间是如何工作的了。定义图像最通用的方式是通过其完全限定名称，如下所示：

```
<registry URL>/<User or Org>/<name>:<tag>
```

让我们更详细地看一下：

+   `<registry URL>`：这是我们想要从中拉取图像的注册表的 URL。默认情况下，这是`docker.io`。更一般地说，这可能是`https://registry.acme.com`。

除了 Docker Hub，还有很多公共注册表可以从中拉取图像。以下是其中一些的列表，没有特定顺序：

+   +   Google，在[`cloud.google.com/container-registry`](https://cloud.google.com/container-registry)

+   Amazon AWS **Amazon Elastic Container Registry** (**ECR**)，在[`aws.amazon.com/ecr/`](https://aws.amazon.com/ecr/)

+   Microsoft Azure，在[`azure.microsoft.com/en-us/services/container-registry/`](https://azure.microsoft.com/en-us/services/container-registry/)

+   Red Hat，在[`access.redhat.com/containers/`](https://access.redhat.com/containers/)

+   Artifactory，网址为[`jfrog.com/integration/artifactory-docker-registry/`](https://jfrog.com/integration/artifactory-docker-registry/)

+   `<用户或组织>`：这是在 Docker Hub 上定义的个人或组织的私有 Docker ID，或者其他注册表，比如`microsoft`或`oracle`。

+   `<名称>`：这是镜像的名称，通常也称为存储库。

+   `<tag>`：这是镜像的标签。

让我们看一个例子，如下：

```
https://registry.acme.com/engineering/web-app:1.0
```

在这里，我们有一个带有版本`1.0`标签的`web-app`镜像，属于`https://registry.acme.com`上的`engineering`组织的私有注册表。

现在，有一些特殊的约定：

+   如果我们省略了注册表 URL，那么 Docker Hub 会自动被使用。

+   如果我们省略了标签，那么将使用`latest`。

+   如果它是 Docker Hub 上的官方镜像，那么不需要用户或组织命名空间。

以下是一些以表格形式呈现的示例：

| **镜像** | **描述** |
| --- | --- |
| `alpine` | Docker Hub 上的官方`alpine`镜像，带有`latest`标签。 |
| `ubuntu:19.04` | Docker Hub 上的官方`ubuntu`镜像，带有`19.04`标签或版本。 |
| `microsoft/nanoserver` | Microsoft 在 Docker Hub 上的`nanoserver`镜像，带有`latest`标签。 |
| `acme/web-api:12.0` | 与`acme`组织相关联的`web-api`镜像版本`12.0`。该镜像在 Docker Hub 上。 |
| `gcr.io/gnschenker/sample-app:1.1` | `sample-app`镜像，带有`1.1`标签，属于 Google 容器注册表上的`gnschenker`ID。 |

现在我们知道了 Docker 镜像的完全限定名称是如何定义的，以及它的组成部分是什么，让我们来谈谈在 Docker Hub 上可以找到的一些特殊镜像。

# 官方镜像

在上表中，我们多次提到了*官方镜像*。这需要解释。镜像存储在 Docker Hub 注册表上的存储库中。官方存储库是由个人或组织策划的一组存储库，他们还负责镜像内打包的软件。让我们看一个例子来解释这意味着什么。Ubuntu Linux 发行版背后有一个官方组织。该团队还提供包含他们 Ubuntu 发行版的官方版本的 Docker 镜像。

官方镜像旨在提供基本的操作系统存储库、流行编程语言运行时的镜像、经常使用的数据存储以及其他重要服务。

Docker 赞助一个团队，他们的任务是审查并发布 Docker Hub 上公共存储库中的所有精选图像。此外，Docker 还扫描所有官方图像以查找漏洞。

# 将图像推送到注册表

创建自定义图像当然很好，但在某个时候，我们希望实际上将我们的图像共享或发布到目标环境，比如测试、质量保证（QA）或生产系统。为此，我们通常使用容器注册表。其中最受欢迎和公共的注册表之一是 Docker Hub。它在您的 Docker 环境中配置为默认注册表，并且是我们迄今为止拉取所有图像的注册表。

在注册表上，通常可以创建个人或组织帐户。例如，我的 Docker Hub 个人帐户是`gnschenker`。个人帐户适用于个人使用。如果我们想专业使用注册表，那么我们可能会想在 Docker Hub 上创建一个组织帐户，比如`acme`。后者的优势在于组织可以拥有多个团队。团队可以具有不同的权限。

要能够将图像推送到 Docker Hub 上的个人帐户，我需要相应地对其进行标记：

1.  假设我想将 Alpine 的最新版本推送到我的帐户并给它打上`1.0`的标签。我可以通过以下方式做到这一点：

```
$ docker image tag alpine:latest gnschenker/alpine:1.0
```

1.  现在，为了能够推送图像，我必须登录到我的帐户，如下所示：

```
$ docker login -u gnschenker -p <my secret password>
```

1.  成功登录后，我可以像这样推送图像：

```
$ docker image push gnschenker/alpine:1.0
```

我将在终端中看到类似于这样的内容：

```
The push refers to repository [docker.io/gnschenker/alpine]
04a094fe844e: Mounted from library/alpine
1.0: digest: sha256:5cb04fce... size: 528
```

对于我们推送到 Docker Hub 的每个图像，我们会自动创建一个存储库。存储库可以是私有的或公共的。每个人都可以从公共存储库中拉取图像。从私有存储库中，只有在登录到注册表并配置了必要的权限后，才能拉取图像。

# 总结

在本章中，我们详细讨论了容器图像是什么以及我们如何构建和发布它们。正如我们所见，图像可以通过三种不同的方式创建——手动、自动或通过将 tarball 导入系统。我们还学习了构建自定义图像时通常使用的一些最佳实践。

在下一章中，我们将介绍 Docker 卷，用于持久化容器的状态。我们还将展示如何为容器内运行的应用程序定义单独的环境变量，以及如何使用包含整套配置设置的文件。

# 问题

请尝试回答以下问题以评估您的学习进度：

1.  如何创建一个继承自 Ubuntu 版本`19.04`的 Dockerfile，安装`ping`并在容器启动时运行`ping`？`ping`的默认地址将是`127.0.0.1`。

1.  如何创建一个使用`alpine:latest`并安装`curl`的新容器镜像？将新镜像命名为`my-alpine:1.0`。

1.  创建一个`Dockerfile`，使用多个步骤创建一个用 C 或 Go 编写的`Hello World`应用程序的最小尺寸镜像。

1.  列出三个 Docker 容器镜像的基本特征。

1.  您想将名为`foo:1.0`的镜像推送到 Docker Hub 上的`jdoe`个人账户。以下哪个是正确的解决方案？

A. `$ docker container push foo:1.0` B. `$ docker image tag foo:1.0 jdoe/foo:1.0`

`$ docker image push jdoe/foo:1.0` C. `$ docker login -u jdoe -p <your password>`

`$ docker image tag foo:1.0 jdoe/foo:1.0`

`$ docker image push jdoe/foo:1.0` D. `$ docker login -u jdoe -p <your password>`

`$ docker container tag foo:1.0 jdoe/foo:1.0`

`$ docker container push jdoe/foo:1.0` E. `$ docker login -u jdoe -p <your password>`

`$ docker image push foo:1.0 jdoe/foo:1.0`

# 进一步阅读

以下参考资料列表提供了一些更深入探讨容器镜像创作和构建主题的材料：

+   编写 Dockerfile 的最佳实践，网址为[`dockr.ly/22WiJiO`](http://dockr.ly/22WiJiO)

+   使用多阶段构建，网址为[`dockr.ly/2ewcUY3`](http://dockr.ly/2ewcUY3)

+   关于存储驱动程序，网址为[`dockr.ly/1TuWndC`](http://dockr.ly/1TuWndC)

+   Graphdriver 插件，网址为[`dockr.ly/2eIVCab`](http://dockr.ly/2eIVCab)

+   在 Docker for Mac 中进行用户引导缓存，网址为[`dockr.ly/2xKafPf`](http://dockr.ly/2xKafPf)
