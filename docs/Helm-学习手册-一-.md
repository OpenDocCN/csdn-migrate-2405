# Helm 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB`](https://zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

目前，容器化被认为是实施 DevOps 的最佳方式。虽然 Docker 引入了容器并改变了 DevOps 时代，但 Google 开发了一个广泛的容器编排系统 Kubernetes，现在被认为是容器编排的领先者。本书的主要目标是了解使用 Helm 管理在 Kubernetes 上运行的应用的效率。本书将从简要介绍 Helm 及其如何有益于整个容器环境开始。然后，您将深入了解架构方面，以及学习 Helm 图表及其用例。您将学习如何编写 Helm 图表以实现在 Kubernetes 上自动化应用部署。本书专注于提供围绕 Helm 和自动化的企业就绪模式，涵盖了围绕 Helm 的应用开发、交付和生命周期管理的最佳实践。通过本书，您将了解如何利用 Helm 开发企业模式，以实现应用交付。

# 本书适合对象

本书面向对学习 Helm 以实现在 Kubernetes 上应用开发自动化感兴趣的 Kubernetes 开发人员或管理员。具备基本的 Kubernetes 应用开发知识会很有帮助，但不需要事先了解 Helm。建议具备自动化提供的业务用例的基本知识。

# 本书涵盖内容

*第一章*，*理解 Kubernetes 和 Helm*，介绍了 Kubernetes 和 Helm。您将了解在将应用部署到 Kubernetes 时用户面临的挑战，以及 Helm 如何帮助简化部署并提高生产力。

*第二章*，*准备 Kubernetes 和 Helm 环境*，涵盖了在本地 Kubernetes 集群上使用 Helm 部署应用所需的工具。此外，您还将了解安装后发生的基本 Helm 配置。

*第三章*，*安装您的第一个 Helm 图表*，解释了如何通过安装 Helm 图表将应用部署到 Kubernetes，并涵盖了使用 Helm 部署的应用的不同生命周期阶段。

*第四章*，*理解 Helm 图表*，深入探讨了 Helm 图表的构建模块，并为您提供构建自己的 Helm 图表所需的知识。

*第五章*“构建您的第一个 Helm 图表”，提供了一个构建 Helm 图表的端到端演练。本章从构建利用基本 Helm 构造的 Helm 图表的基本概念开始，并逐渐修改基线配置以包含更高级的 Helm 构造。最后，您将学习如何将图表部署到基本图表存储库

*第六章*“测试 Helm 图表”，讨论了围绕对 Helm 图表进行 linting 和测试的不同方法论。

*第七章*“使用 CI/CD 和 GitOps 自动化 Helm 流程”，探讨了在利用 CI/CD 和 GitOps 模型自动化 Helm 任务方面的高级用例。即，围绕测试、打包和发布 Helm 图表开发一个流程。此外，还介绍了在多个不同环境中管理 Helm 图表安装的方法。

*第八章*“使用 Operator 框架与 Helm”，讨论了在 Kubernetes 上使用 operator 的基本概念，以便利用 operator 框架提供的 operator-sdk 工具从现有的 Helm 图表构建一个 Helm operator。

*第九章*“Helm 安全注意事项”，深入探讨了在使用 Helm 时的一些安全注意事项和预防措施，从安装工具到在 Kubernetes 集群上安装 Helm 图表的整个过程。

# 为了充分利用本书

虽然不是强制性的，因为基本概念在整本书中都有解释，但建议对 Kubernetes 和容器技术有一定了解。

对于本书中使用的工具，第 2-9 章将重点关注以下关键技术：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/B15458_Preface_Table_1.jpg)

这些工具的安装在*第二章*“准备 Kubernetes 和 Helm 环境”中有详细讨论。本书中使用的其他工具是特定于章节的，它们的安装方法在使用它们的章节中进行描述。

如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将有助于避免与复制/粘贴代码相关的任何潜在错误。

# 下载示例代码文件

您可以从[www.packt.com](http://packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 用于 Windows

+   Zipeg/iZip/UnRarX 用于 Mac

+   7-Zip/PeaZip 用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/-Learn-Helm`](https://github.com/PacktPublishing/-Learn-Helm)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的图书和视频目录的其他代码包，可在 https://github.com/PacktPublishing/上找到。去看看吧！

## 代码实例

本书的实际代码演示视频可在 https://bit.ly/2AEAGvm 上观看。

## 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781839214295_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781839214295_ColorImages.pdf)。

## 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

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

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“从**管理**面板中选择**系统信息**”。

提示或重要说明

以这种方式出现。


# 第一部分：介绍和设置

本节将介绍 Helm 解决的问题陈述，以及通过实际示例演示其提供的解决方案。

本节包括以下章节：

*第一章，理解 Kubernetes 和 Helm*

*第二章，准备 Kubernetes 和 Helm 环境*

*第三章，安装您的第一个 Helm 图表*


# 第一章：理解 Kubernetes 和 Helm

感谢您选择了本书《学习 Helm》。如果您对本书感兴趣，您可能已经意识到现代应用程序带来的挑战。团队面临巨大的压力，确保应用程序轻量且可扩展。应用程序还必须具有高可用性，并能承受不同的负载。在历史上，应用程序通常被部署为单体应用，或者在单个系统上提供的大型单层应用。随着时间的推移，行业已经转向了微服务方法，或者转向了在多个系统上提供的小型多层应用。行业通常使用容器技术进行部署，开始利用诸如 Kubernetes 之类的工具来编排和扩展其容器化的微服务。

然而，Kubernetes 也带来了自己的一系列挑战。虽然它是一个有效的容器编排工具，但它提供了一个陡峭的学习曲线，对团队来说可能很难克服。一个帮助简化在 Kubernetes 上运行工作负载挑战的工具是 Helm。Helm 允许用户更简单地部署和管理 Kubernetes 应用程序的生命周期。它抽象了许多配置 Kubernetes 应用程序的复杂性，并允许团队在平台上更加高效地工作。

在本书中，您将探索 Helm 提供的每个好处，并了解 Helm 如何使在 Kubernetes 上部署应用程序变得更简单。您将首先扮演终端用户的角色，使用社区编写的 Helm 图表，并学习利用 Helm 作为软件包管理器的最佳实践。随着本书的进展，您将扮演 Helm 图表开发人员的角色，并学习如何以易于消费和高效的方式打包 Kubernetes 应用程序。在本书的最后，您将了解关于应用程序管理和安全性的高级模式。

让我们首先了解微服务、容器、Kubernetes 以及这些方面对应用程序部署带来的挑战。然后，我们将讨论 Helm 的主要特点和好处。在本章中，我们将涵盖以下主要主题：

+   单体应用、微服务和容器

+   Kubernetes 概述

+   Kubernetes 应用的部署方式

+   配置 Kubernetes 资源的挑战

+   Helm 提供的简化在 Kubernetes 上部署应用程序的好处

# 从单体应用到现代微服务

软件应用程序是大多数现代技术的基础组成部分。无论它们是以文字处理器、网络浏览器还是媒体播放器的形式出现，它们都能够使用户进行交互以完成一个或多个任务。应用程序有着悠久而传奇的历史，从第一台通用计算机 ENIAC 的时代，到阿波罗太空任务将人类送上月球，再到互联网、社交媒体和在线零售的兴起。

这些应用程序可以在各种平台和系统上运行。我们说在大多数情况下它们在虚拟或物理资源上运行，但这难道是唯一的选择吗？根据它们的目的和资源需求，整个机器可能会被专门用来满足应用程序的计算和/或存储需求。幸运的是，部分归功于摩尔定律的实现，微处理器的功率和性能最初每年都在增加，同时与物理资源相关的整体成本也在增加。这一趋势在最近几年有所减弱，但这一趋势的出现以及在处理器存在的前 30 年中的持续对技术的进步起着关键作用。

软件开发人员充分利用了这一机会，在他们的应用程序中捆绑了更多的功能和组件。因此，一个单一的应用程序可能由几个较小的组件组成，每个组件本身都可以被编写为它们自己的独立服务。最初，捆绑组件在一起带来了几个好处，包括简化的部署过程。然而，随着行业趋势的改变，企业更加关注能够更快地交付功能，一个可部署的单一应用程序的设计也带来了许多挑战。每当需要进行更改时，整个应用程序及其所有基础组件都需要再次验证，以确保更改没有不利的特性。这个过程可能需要多个团队的协调，从而减慢了功能的整体交付速度。

更快地交付功能，特别是跨组织内的传统部门，也是组织所期望的。这种快速交付的概念是 DevOps 实践的基础，其在 2010 年左右开始流行起来。DevOps 鼓励对应用程序进行更多的迭代更改，而不是在开发之前进行广泛的规划。为了在这种新模式下可持续发展，架构从单一的大型应用程序发展为更青睐能够更快交付的几个较小的应用程序。由于这种思维方式的改变，更传统的应用程序设计被标记为“单片”。将组件分解为单独的应用程序的这种新方法被称为“微服务”。微服务应用程序固有的特征带来了一些理想的特性，包括能够同时开发和部署服务，以及独立扩展（增加实例数量）。

软件架构从单片到微服务的变化也导致重新评估应用程序在运行时的打包和部署方式。传统上，整个机器都专门用于一个或两个应用程序。现在，由于微服务导致单个应用程序所需资源的总体减少，将整个机器专门用于一个或两个微服务已不再可行。

幸运的是，一种名为“容器”的技术被引入并因填补许多缺失的功能而受到欢迎，以创建微服务运行时环境。Red Hat 将容器定义为“一组与系统其余部分隔离的一个或多个进程，并包括运行所需的所有文件”（https://www.redhat.com/en/topics/containers/whats-a-linux-container）。容器化技术在计算机领域有着悠久的历史，可以追溯到 20 世纪 70 年代。许多基础容器技术，包括 chroot（能够更改进程和其任何子进程的根目录到文件系统上的新位置）和 jails，今天仍在使用中。

简单且便携的打包模型，以及在每台物理或虚拟机上创建许多隔离的沙盒的能力的结合，导致了微服务领域容器的快速采用。2010 年代中期容器流行的上升也可以归因于 Docker，它通过简化的打包和可以在 Linux、macOS 和 Windows 上使用的运行时将容器带给了大众。轻松分发容器镜像的能力导致了容器技术的流行增加。这是因为首次用户不需要知道如何创建镜像，而是可以利用其他人创建的现有镜像。

容器和微服务成为了天作之合。应用程序具有打包和分发机制，以及共享相同计算占用的能力，同时又能够从彼此隔离。然而，随着越来越多的容器化微服务被部署，整体管理成为了一个问题。你如何确保每个运行的容器的健康？如果一个容器失败了怎么办？如果你的底层机器没有所需的计算能力会发生什么？于是 Kubernetes 应运而生，它帮助解决了容器编排的需求。

在下一节中，我们将讨论 Kubernetes 的工作原理以及它为企业提供的价值。

# 什么是 Kubernetes？

Kubernetes，通常缩写为**k8s**（发音为**kaytes**），是一个开源的容器编排平台。起源于谷歌的专有编排工具 Borg，该项目于 2015 年开源并更名为 Kubernetes。在 2015 年 7 月 21 日发布 v1.0 版本后，谷歌和 Linux 基金会合作成立了**云原生计算基金会**（**CNCF**），该基金会目前是 Kubernetes 项目的维护者。

Kubernetes 这个词是希腊词，意思是“舵手”或“飞行员”。舵手是负责操纵船只并与船员紧密合作以确保航行安全和稳定的人。Kubernetes 对于容器和微服务有类似的责任。Kubernetes 负责容器的编排和调度。它负责“操纵”这些容器到能够处理它们工作负载的工作节点。Kubernetes 还将通过提供高可用性和健康检查来确保这些微服务的安全。

让我们回顾一些 Kubernetes 如何帮助简化容器化工作负载管理的方式。

## 容器编排

Kubernetes 最突出的特性是容器编排。这是一个相当复杂的术语，因此我们将其分解为不同的部分。

容器编排是指根据容器的需求，将其放置在计算资源池中的特定机器上。容器编排的最简单用例是在可以处理其资源需求的机器上部署容器。在下图中，有一个应用程序请求 2 Gi 内存（Kubernetes 资源请求通常使用它们的“二的幂”值，在本例中大致相当于 2 GB）和一个 CPU 核心。这意味着容器将从底层机器上分配 2 Gi 内存和 1 个 CPU 核心。Kubernetes 负责跟踪具有所需资源的机器（在本例中称为节点），并将传入的容器放置在该机器上。如果节点没有足够的资源来满足请求，容器将不会被调度到该节点上。如果集群中的所有节点都没有足够的资源来运行工作负载，容器将不会被部署。一旦节点有足够的空闲资源，容器将被部署在具有足够资源的节点上：

![图 1.1：Kubernetes 编排和调度](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_1.1.jpg)

图 1.1 - Kubernetes 编排和调度

容器编排使您不必一直努力跟踪机器上的可用资源。Kubernetes 和其他监控工具提供了对这些指标的洞察。因此，日常开发人员不需要担心可用资源。开发人员只需声明他们期望容器使用的资源量，Kubernetes 将在后台处理其余部分。

## 高可用性

Kubernetes 的另一个好处是它提供了帮助处理冗余和高可用性的功能。高可用性是防止应用程序停机的特性。它是由负载均衡器执行的，它将传入的流量分配到应用程序的多个实例中。高可用性的前提是，如果一个应用程序实例出现故障，其他实例仍然可以接受传入的流量。在这方面，避免了停机时间，最终用户，无论是人类还是另一个微服务，都完全不知道应用程序出现了故障实例。Kubernetes 提供了一种名为 Service 的网络机制，允许应用程序进行负载均衡。我们将在本章的*部署 Kubernetes 应用程序*部分更详细地讨论服务。

## 可扩展性

鉴于容器和微服务的轻量化特性，开发人员可以使用 Kubernetes 快速扩展他们的工作负载，无论是水平还是垂直方向。

水平扩展是部署更多容器实例的行为。如果一个团队在 Kubernetes 上运行他们的工作负载，并且预期负载会增加，他们可以简单地告诉 Kubernetes 部署更多他们的应用实例。由于 Kubernetes 是一个容器编排器，开发人员不需要担心这些应用将部署在哪些物理基础设施上。它会简单地在集群中找到一个具有可用资源的节点，并在那里部署额外的实例。每个额外的实例都将被添加到一个负载均衡池中，这将允许应用程序继续保持高可用性。

垂直扩展是为应用程序分配额外的内存和 CPU 的行为。开发人员可以在应用程序运行时修改其资源需求。这将促使 Kubernetes 重新部署运行实例，并将它们重新调度到可以支持新资源需求的节点上。根据配置方式的不同，Kubernetes 可以以一种防止新实例部署期间停机的方式重新部署每个实例。

## 活跃的社区

Kubernetes 社区是一个非常活跃的开源社区。因此，Kubernetes 经常收到补丁和新功能。社区还为官方 Kubernetes 文档以及专业或业余博客网站做出了许多贡献。除了文档，社区还积极参与全球各地的聚会和会议的策划和参与，这有助于增加平台的教育和创新。

Kubernetes 庞大的社区带来的另一个好处是构建了许多不同的工具来增强所提供的能力。Helm 就是其中之一。正如我们将在本章后面和整本书中看到的，Helm 是 Kubernetes 社区成员开发的一个工具，通过简化应用程序部署和生命周期管理，大大改善了开发人员的体验。

了解了 Kubernetes 为管理容器化工作负载带来的好处，现在让我们讨论一下如何在 Kubernetes 中部署应用程序。

# 部署 Kubernetes 应用程序

在 Kubernetes 上部署应用程序基本上与在 Kubernetes 之外部署应用程序类似。所有应用程序，无论是容器化还是非容器化，都必须具有围绕以下主题的配置细节：

+   网络连接

+   持久存储和文件挂载

+   可用性和冗余

+   应用程序配置

+   安全

在 Kubernetes 上配置这些细节是通过与 Kubernetes 的**应用程序编程接口**（**API**）进行交互来完成的。

Kubernetes API 充当一组端点，可以与之交互以查看、修改或删除不同的 Kubernetes 资源，其中许多用于配置应用程序的不同细节。

让我们讨论一些基本的 API 端点，用户可以与之交互，以在 Kubernetes 上部署和配置应用程序。

## 部署

我们将要探索的第一个 Kubernetes 资源称为部署。部署确定了在 Kubernetes 上部署应用程序所需的基本细节。其中一个基本细节包括 Kubernetes 应该部署的容器映像。容器映像可以在本地工作站上使用诸如`docker`和`jib`之类的工具构建，但也可以直接在 Kubernetes 上使用`kaniko`构建。因为 Kubernetes 不公开用于构建容器映像的本机 API 端点，所以我们不会详细介绍在配置部署资源之前如何构建容器映像。

除了指定容器映像外，部署还指定要部署的应用程序的副本数或实例数。创建部署时，它会生成一个中间资源，称为副本集。副本集部署应用程序的实例数量由部署上的`replicas`字段确定。应用程序部署在一个容器内，容器本身部署在一个称为 Pod 的构造内。Pod 是 Kubernetes 中的最小单位，至少封装一个容器。

部署还可以定义应用程序的资源限制、健康检查和卷挂载。创建部署时，Kubernetes 创建以下架构：

![图 1.2：部署创建一组 Pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_1.2.jpg)

图 1.2 - 部署创建一组 Pod

Kubernetes 中的另一个基本 API 端点用于创建服务资源，我们将在下面讨论。

## 服务

虽然部署用于将应用程序部署到 Kubernetes，但它们不配置允许应用程序与 Kubernetes 通信的网络组件，Kubernetes 公开了一个用于定义网络层的单独 API 端点，称为服务。服务允许用户和其他应用程序通过为服务端点分配静态 IP 地址来相互通信。然后可以配置服务端点以将流量路由到一个或多个应用程序实例。这种配置提供了负载平衡和高可用性。

一个使用服务的示例架构在下图中描述。请注意，服务位于客户端和 Pod 之间，以提供负载平衡和高可用性：

![图 1.3：服务负载平衡传入请求](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_1.3.jpg)

图 1.3 - 服务负载平衡传入请求

最后一个例子，我们将讨论`PersistentVolumeClaim` API 端点。

## PersistentVolumeClaim

微服务风格的应用程序通过以临时方式维护其状态来实现自给自足。然而，存在许多情况，数据必须存在于单个容器的寿命之外。Kubernetes 通过提供一个用于抽象存储提供和消耗方式的子系统来解决这个问题。为了为他们的应用程序分配持久存储，用户可以创建一个`PersistentVolumeClaim`端点，该端点指定所需存储的类型和数量。Kubernetes 管理员负责静态分配存储，表示为`PersistentVolume`，或使用`StorageClass`动态配置存储，该存储类根据`PersistentVolumeClaim`端点分配`PersistentVolume`。`PersistentVolume`包含所有必要的存储细节，包括类型（如网络文件系统[NFS]、互联网小型计算机系统接口[iSCSI]或来自云提供商）以及存储的大小。从用户的角度来看，无论在集群中使用`PersistentVolume`分配方法或存储后端的哪种方法，他们都不需要管理存储的底层细节。在 Kubernetes 中利用持久存储的能力增加了可以在平台上部署的潜在应用程序的数量。

下图描述了持久存储的一个例子。该图假定管理员已通过`StorageClass`配置了动态配置：

![图 1.4：由 PersistentVolumeClaim 创建的 Pod 挂载 PersistentVolume](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_1.4.jpg)

图 1.4 - 由 PersistentVolumeClaim 创建的 Pod 挂载的 PersistentVolume。

Kubernetes 中有更多的资源，但到目前为止，你可能已经有了一个大致的了解。现在的问题是这些资源实际上是如何创建的？

我们将在下一节进一步探讨这个问题。

# 资源管理的方法

为了在 Kubernetes 上部署应用程序，我们需要与 Kubernetes API 交互以创建资源。 `kubectl`是我们用来与 Kubernetes API 交互的工具。 `kubectl`是一个用于将 Kubernetes API 的复杂性抽象化的命令行接口（CLI）工具，允许最终用户更有效地在平台上工作。

让我们讨论一下如何使用 `kubectl` 来管理 Kubernetes 资源。

## 命令式和声明式配置

`kubectl` 工具提供了一系列子命令，以命令式方式创建和修改资源。以下是这些命令的一个小列表：

+   `create`

+   `describe`

+   `edit`

+   `delete`

`kubectl` 命令遵循一个常见的格式：

```
kubectl <verb> <noun> <arguments>
```

动词指的是 `kubectl` 的子命令之一，名词指的是特定的 Kubernetes 资源。例如，可以运行以下命令来创建一个部署：

```
kubectl create deployment my-deployment --image=busybox
```

这将指示 `kubectl` 与部署 API 对话，并使用来自 Docker Hub 的 `busybox` 镜像创建一个名为 `my-deployment` 的新部署。

您可以使用 `kubectl` 获取有关使用 `describe` 子命令创建的部署的更多信息：

```
kubectl describe deployment my-deployment
```

此命令将检索有关部署的信息，并以可读格式格式化结果，使开发人员可以检查 Kubernetes 上的实时 `my-deployment` 部署。

如果需要对部署进行更改，开发人员可以使用 `edit` 子命令在原地修改它：

```
kubectl edit deployment my-deployment
```

此命令将打开一个文本编辑器，允许您修改部署。

在删除资源时，用户可以运行 `delete` 子命令：

```
kubectl delete deployment my-deployment
```

这将指示 API 删除名为 `my-deployment` 的部署。

一旦创建，Kubernetes 资源将作为 JSON 资源文件存在于集群中，可以将其导出为 YAML 文件以获得更大的人类可读性。可以在此处看到 YAML 格式的示例资源：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: busybox
spec:
  replicas: 1
  selector:
    matchLabels:
      app: busybox
  template:
    metadata:
      labels:
        app: busybox
    spec:
      containers:
        - name: main
          image: busybox
          args:
            - sleep
            - infinity
```

前面的 YAML 格式呈现了一个非常基本的用例。它部署了来自 Docker Hub 的 `busybox` 镜像，并无限期地运行 `sleep` 命令以保持 Pod 运行。

虽然使用我们刚刚描述的 `kubectl` 子命令以命令式方式创建资源可能更容易，但 Kubernetes 允许您以声明式方式直接管理 YAML 资源，以获得对资源创建更多的控制。`kubectl` 子命令并不总是让您配置所有可能的资源选项，但直接创建 YAML 文件允许您更灵活地创建资源并填补 `kubectl` 子命令可能包含的空白。

在声明式创建资源时，用户首先以 YAML 格式编写他们想要创建的资源。接下来，他们使用`kubectl`工具将资源应用于 Kubernetes API。而在命令式配置中，开发人员使用`kubectl`子命令来管理资源，声明式配置主要依赖于一个子命令——`apply`。

声明式配置通常采用以下形式：

```
kubectl apply -f my-deployment.yaml
```

该命令为 Kubernetes 提供了一个包含资源规范的 YAML 资源，尽管也可以使用 JSON 格式。Kubernetes 根据资源的存在与否来推断要执行的操作（创建或修改）。

应用程序可以通过以下步骤进行声明式配置：

1.  首先，用户可以创建一个名为`deployment.yaml`的文件，并提供部署的 YAML 格式规范。我们将使用与之前相同的示例：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: busybox
spec:
  replicas: 1
  selector:
    matchLabels:
      app: busybox
  template:
    metadata:
      labels:
        app: busybox
    spec:
      containers:
        - name: main
          image: busybox
          args:
            - sleep
            - infinity
```

1.  然后可以使用以下命令创建部署：

```
kubectl apply -f deployment.yaml
```

运行此命令后，Kubernetes 将尝试按照您指定的方式创建部署。

1.  如果要对部署进行更改，比如将`replicas`的数量更改为`2`，您首先需要修改`deployment.yaml`文件：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: busybox
spec:
  replicas: 2
  selector:
    matchLabels:
      app: busybox
  template:
    metadata:
      labels:
        app: busybox
    spec:
      containers:
        - name: main
          image: busybox
          args:
            - sleep
            - infinity
```

1.  然后，您可以使用`kubectl apply`应用更改：

```
kubectl apply -f deployment.yaml
```

运行该命令后，Kubernetes 将在先前应用的`deployment`上应用提供的部署声明。此时，应用程序将从`replica`值为`1`扩展到`2`。

1.  在删除应用程序时，Kubernetes 文档实际上建议以命令式方式进行操作；也就是说，使用`delete`子命令而不是`apply`：

```
kubectl delete -f deployment.yaml
```

1.  通过传递`-f`标志和文件名，可以使`delete`子命令更具声明性。这样可以向`kubectl`提供在特定文件中声明的要删除的资源的名称，并允许开发人员继续使用声明性 YAML 文件管理资源。

了解了 Kubernetes 资源的创建方式，现在让我们讨论一下资源配置中涉及的一些挑战。

# 资源配置挑战

在前一节中，我们介绍了 Kubernetes 有两种不同的配置方法——命令式和声明式。一个需要考虑的问题是，在使用命令式和声明式方法创建 Kubernetes 资源时，用户需要注意哪些挑战？

让我们讨论一些最常见的挑战。

## Kubernetes 资源的多种类型

首先，Kubernetes 中有许多*许多*不同的资源。以下是开发人员应该了解的资源的简短列表：

+   部署

+   StatefulSet

+   服务

+   入口

+   ConfigMap

+   Secret

+   StorageClass

+   PersistentVolumeClaim

+   ServiceAccount

+   角色

+   RoleBinding

+   命名空间

在 Kubernetes 上部署应用程序并不像按下标有“部署”的大红按钮那么简单。开发人员需要能够确定部署其应用程序所需的资源，并且需要深入了解这些资源，以便能够适当地配置它们。这需要对平台有很多的了解和培训。虽然理解和创建资源可能已经听起来像是一个很大的障碍，但实际上这只是许多不同操作挑战的开始。

## 保持活动和本地状态同步

我们鼓励的一种配置 Kubernetes 资源的方法是将它们的配置保留在源代码控制中，供团队编辑和共享，这也使得源代码控制存储库成为真相的来源。在源代码控制中定义的配置（称为“本地状态”）然后通过将它们应用到 Kubernetes 环境中来创建，并且资源变为“活动”或进入可以称为“活动状态”的状态。这听起来很简单，但当开发人员需要对其资源进行更改时会发生什么？正确的答案应该是修改本地文件并应用更改，以将本地状态与活动状态同步，以更新真相的来源。然而，这通常不是最终发生的事情。在短期内，更改活动资源的位置通常更简单，而不是修改本地文件。这会导致本地和活动状态之间的状态不一致，并且使得在 Kubernetes 上扩展变得困难。

## 应用程序生命周期很难管理

生命周期管理是一个复杂的术语，但在这个上下文中，我们将把它称为安装、升级和回滚应用程序的概念。在 Kubernetes 世界中，安装会创建资源来部署和配置应用程序。初始安装将创建我们在这里称为应用程序的“版本 1”。

然后，升级可以被视为对一个或多个 Kubernetes 资源的编辑或修改。每一批编辑可以被视为一个单独的升级。开发人员可以修改单个服务资源，将版本号提升到“版本 2”。然后开发人员可以修改部署、配置映射和服务，将版本计数提升到“版本 3”。

随着应用程序的新版本继续部署到 Kubernetes 上，跟踪已发生的更改变得更加困难。在大多数情况下，Kubernetes 没有固有的方式来记录更改的历史。虽然这使得升级更难以跟踪，但也使得恢复先前版本的应用程序变得更加困难。假设开发人员之前对特定资源进行了错误的编辑。团队如何知道要回滚到哪个版本？`n-1`情况特别容易解决，因为那是最近的版本。然而，如果最新的稳定版本是五个版本之前呢？团队经常因为无法快速识别先前有效的最新稳定配置而不得不匆忙解决问题。

## 资源文件是静态的。

这是一个主要影响应用 YAML 资源的声明性配置风格的挑战。遵循声明性方法的困难部分在于，Kubernetes 资源文件并非原生设计为可参数化。资源文件大多被设计为在应用之前完整地编写出来，并且内容保持不变，直到文件被修改。在处理 Kubernetes 时，这可能是一个令人沮丧的现实。一些 API 资源可能会很长，包含许多不同的可定制字段，因此完整地编写和配置 YAML 资源可能会非常繁琐。

静态文件很容易变成样板文件。样板文件代表在不同但相似的上下文中基本保持一致的文本或代码。如果开发人员管理多个不同的应用程序，可能需要管理多个不同的部署资源、多个不同的服务资源等。比较不同应用程序的资源文件时，可能会发现它们之间存在大量相似的 YAML 配置。

下图描述了两个资源之间具有重要样板配置的示例。蓝色文本表示样板行，而红色文本表示唯一行：

![图 1.5：两个具有样板的资源示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_1.5.jpg)

图 1.5 - 两个具有样板的资源示例

在这个例子中，请注意，每个文件几乎完全相同。当管理类似这样相似的文件时，样板变成了团队以声明方式管理其应用程序的主要头痛。

# Helm 来拯救！

随着时间的推移，Kubernetes 社区发现创建和维护用于部署应用程序的 Kubernetes 资源是困难的。这促使开发了一个简单而强大的工具，可以让团队克服在 Kubernetes 上部署应用程序时所面临的挑战。创建的工具称为 Helm。Helm 是一个用于在 Kubernetes 上打包和部署应用程序的开源工具。它通常被称为**Kubernetes 软件包管理器**，因为它与您在喜爱的操作系统上找到的任何其他软件包管理器非常相似。Helm 在整个 Kubernetes 社区广泛使用，并且是一个 CNCF 毕业项目。

鉴于 Helm 与传统软件包管理器的相似之处，让我们首先通过回顾软件包管理器的工作原理来开始探索 Helm。

## 理解软件包管理器

软件包管理器用于简化安装、升级、回滚和删除系统应用程序的过程。这些应用程序以称为**软件包**的单位进行定义，其中包含了关于目标软件及其依赖关系的元数据。

软件包管理器背后的过程很简单。首先，用户将软件包的名称作为参数传递。然后，软件包管理器执行针对软件包存储库的查找，以查看该软件包是否存在。如果找到了，软件包管理器将安装由软件包及其依赖项定义的应用程序到系统上指定的位置。

软件包管理器使管理软件变得非常容易。举个例子，假设你想要在 Fedora 机器上安装`htop`，一个 Linux 系统监视器。安装这个软件只需要输入一个命令：

```
dnf install htop --assumeyes	
```

这会指示自 2015 年以来成为 Fedora 软件包管理器的 `dnf` 在 Fedora 软件包存储库中查找 `htop` 并安装它。`dnf`还负责安装`htop`软件包的依赖项，因此您无需担心事先安装其要求。在`dnf`从上游存储库中找到`htop`软件包后，它会询问您是否确定要继续。`--assumeyes`标志会自动回答`yes`这个问题和`dnf`可能潜在询问的任何其他提示。

随着时间的推移，新版本的`htop`可能会出现在上游存储库中。`dnf`和其他软件包管理器允许用户高效地升级软件的新版本。允许用户使用`dnf`进行升级的子命令是升级：

```
dnf upgrade htop --assumeyes
```

这会指示`dnf`将`htop`升级到最新版本。它还会将其依赖项升级到软件包元数据中指定的版本。

虽然向前迈进通常更好，但软件包管理器也允许用户向后移动，并在必要时将应用程序恢复到先前的版本。`dnf`使用`downgrade`子命令来实现这一点：

```
dnf downgrade htop --assumeyes
```

这是一个强大的过程，因为软件包管理器允许用户在报告关键错误或漏洞时快速回滚。

如果您想彻底删除一个应用程序，软件包管理器也可以处理。`dnf`提供了`remove`子命令来实现这一目的：

```
dnf remove htop --assumeyes	
```

在本节中，我们回顾了在 Fedora 上使用`dnf`软件包管理器来管理软件包的方法。作为 Kubernetes 软件包管理器的 Helm 与`dnf`类似，无论是在目的还是功能上。`dnf`用于在 Fedora 上管理应用程序，Helm 用于在 Kubernetes 上管理应用程序。我们将在接下来更详细地探讨这一点。

## Kubernetes 软件包管理器

考虑到 Helm 的设计目的是提供类似于软件包管理器的体验，`dnf`或类似工具的有经验的用户将立即理解 Helm 的基本概念。然而，当涉及到具体的实现细节时，情况变得更加复杂。`dnf`操作`RPM`软件包，提供可执行文件、依赖信息和元数据。另一方面，Helm 使用**charts**。Helm chart 可以被视为 Kubernetes 软件包。Charts 包含部署应用程序所需的声明性 Kubernetes 资源文件。与`RPM`类似，它还可以声明应用程序运行所需的一个或多个依赖项。

Helm 依赖于存储库来提供对图表的广泛访问。图表开发人员创建声明性的 YAML 文件，将它们打包成图表，并将它们发布到图表存储库。然后，最终用户使用 Helm 搜索现有的图表，以部署到 Kubernetes，类似于`dnf`的最终用户搜索要部署到 Fedora 的`RPM`软件包。

让我们通过一个基本的例子来看看。Helm 可以使用发布到上游存储库的图表来部署`Redis`，一个内存缓存，到 Kubernetes 中。这可以使用 Helm 的`install`命令来执行：

```
helm install redis bitnami/redis --namespace=redis
```

这将在 bitnami 图表存储库中安装`redis`图表到名为`redis`的 Kubernetes 命名空间。这个安装将被称为初始**修订**，或者 Helm 图表的初始部署。

如果`redis`图表的新版本可用，用户可以使用`upgrade`命令升级到新版本：

```
helm upgrade redis bitnami/redis --namespace=redis
```

这将升级`Redis`，以满足新的`redis`-ha 图表定义的规范。

在操作系统中，用户应该关注如果发现了错误或漏洞，如何回滚。在 Kubernetes 上的应用程序也存在同样的问题，Helm 提供了回滚命令来处理这种情况：

```
helm rollback redis 1 --namespace=redis
```

这个命令将`Redis`回滚到它的第一个修订版本。

最后，Helm 提供了使用`uninstall`命令彻底删除`Redis`的能力：

```
helm uninstall redis --namespace=redis
```

比较`dnf`，Helm 的子命令，以及它们在下表中提供的功能。注意`dnf`和 Helm 提供了类似的命令，提供了类似的用户体验：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/01.jpg)

理解了 Helm 作为一个包管理器的功能，让我们更详细地讨论 Helm 为 Kubernetes 带来的好处。Helm 的好处

在本章的前面，我们回顾了如何通过管理 Kubernetes 资源来创建 Kubernetes 应用程序，并讨论了一些涉及的挑战。以下是 Helm 可以克服这些挑战的几种方式。

### 抽象的 Kubernetes 资源的复杂性

假设开发人员被要求在 Kubernetes 上部署 MySQL 数据库。开发人员需要创建所需的资源来配置其容器、网络和存储。从头开始配置这样的应用程序所需的 Kubernetes 知识量很高，对于新手甚至中级的 Kubernetes 用户来说是一个很大的障碍。

使用 Helm，负责部署 MySQL 数据库的开发人员可以简单地在上游图表存储库中搜索 MySQL 图表。这些图表已经由社区中的图表开发人员编写，并且已经包含了部署 MySQL 数据库所需的声明性配置。在这方面，具有这种任务的开发人员将像任何其他软件包管理器一样使用 Helm 作为简单的最终用户。

### 持续的修订历史

Helm 有一个称为发布历史的概念。当首次安装 Helm 图表时，Helm 将该初始修订添加到历史记录中。随着修订通过升级的增加，历史记录会进一步修改，保留应用程序在不同修订中配置的各种快照。

以下图表描述了持续的修订历史。蓝色的方块说明了资源已经从其先前版本进行了修改：

![图 1.6：修订历史的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_1.6.jpg)

图 1.6 - 修订历史的示例

跟踪每个修订的过程为回滚提供了机会。Helm 中的回滚非常简单。用户只需将 Helm 指向先前的修订，Helm 将 live 状态恢复到所选修订的状态。有了 Helm，过去的`n-1`备份已经过时。Helm 允许用户将其应用程序回滚到他们想要的任何时间，甚至可以回滚到最初的安装。

### 动态配置声明性资源

以声明方式创建资源的最大麻烦之一是 Kubernetes 资源是静态的，无法参数化。正如您可能还记得的那样，这导致资源在应用程序和类似配置之间变得样板化，使团队更难以将其应用程序配置为代码。Helm 通过引入**值**和**模板**来缓解这些问题。

值就是 Helm 称为图表参数的简单东西。模板是基于给定值集的动态生成文件。这两个构造为图表开发人员提供了根据最终用户提供的值自动生成基于值的 Kubernetes 资源的能力。通过这样做，由 Helm 管理的应用程序变得更加灵活，减少样板代码，并更易于维护。

值和模板允许用户执行以下操作：

+   参数化常见字段，比如在部署中的图像名称和服务中的端口

+   根据用户输入生成长篇的 YAML 配置，比如在部署中的卷挂载或 ConfigMap 中的数据

+   根据用户输入包含或排除资源

能够动态生成声明性资源文件使得创建基于 YAML 的资源变得更简单，同时确保应用以一种易于复制的方式创建。

### 本地和实时状态之间的一致性

软件包管理器可以防止用户手动管理应用程序及其依赖关系。所有管理都可以通过软件包管理器本身完成。Helm 也是如此。因为 Helm 图表包含了灵活的 Kubernetes 资源配置，用户不应该直接对实时的 Kubernetes 资源进行修改。想要修改他们的应用程序的用户可以通过向 Helm 图表提供新值或将其应用程序升级到相关图表的更新版本来实现。这使得本地状态（由 Helm 图表配置表示）和实时状态在修改过程中保持一致，使用户能够为他们的 Kubernetes 资源配置提供真实的来源。

### 智能部署

Helm 通过确定 Kubernetes 资源需要创建的顺序来简化应用部署。Helm 分析每个图表的资源，并根据它们的类型对它们进行排序。这种预先确定的顺序存在是为了确保常常有资源依赖于它们的资源首先被创建。例如，Secrets 和 ConfigMaps 应该在部署之前创建，因为部署很可能会使用这些资源作为卷。Helm 在没有用户交互的情况下执行此排序，因此这种复杂性被抽象化，用户无需担心这些资源被应用的顺序。

### 自动生命周期钩子

与其他软件包管理器类似，Helm 提供了定义生命周期钩子的能力。生命周期钩子是在应用程序生命周期的不同阶段自动执行的操作。它们可以用来执行诸如以下操作：

+   在升级时执行数据备份。

+   在回滚时恢复数据。

+   在安装之前验证 Kubernetes 环境。

生命周期钩子非常有价值，因为它们抽象了可能不是特定于 Kubernetes 的任务的复杂性。例如，Kubernetes 用户可能不熟悉数据库备份背后的最佳实践，或者可能不知道何时应执行此类任务。生命周期钩子允许专家编写自动化，以在建议时执行这些最佳实践，以便用户可以继续高效工作，而无需担心这些细节。

# 摘要

在本章中，我们首先探讨了采用基于微服务的架构的变化趋势，将应用程序分解为几个较小的应用程序，而不是部署一个庞大的单体应用程序。创建更轻量级且更易管理的应用程序导致利用容器作为打包和运行时格式，以更频繁地发布版本。通过采用容器，引入了额外的运营挑战，并通过使用 Kubernetes 作为容器编排平台来管理容器生命周期来解决这些挑战。

我们讨论了配置 Kubernetes 应用程序的各种方式，包括部署、服务和持久卷索赔。这些资源可以使用两种不同的应用程序配置样式来表示：命令式和声明式。这些配置样式中的每一种都对部署 Kubernetes 应用程序涉及的一系列挑战做出了贡献，包括理解 Kubernetes 资源工作的知识量以及管理应用程序生命周期的挑战。

为了更好地管理构成应用程序的每个资产，Helm 被引入为 Kubernetes 的软件包管理器。通过其丰富的功能集，可以轻松管理应用程序的完整生命周期，包括安装、升级、回滚和删除。

在下一章中，我们将详细介绍配置 Helm 环境的过程。我们还将安装所需的工具，以便使用 Helm 生态系统，并按照本书提供的示例进行操作。

# 进一步阅读

有关构成应用程序的 Kubernetes 资源的更多信息，请参阅 Kubernetes 文档中的*了解 Kubernetes 对象*页面，网址为 https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/。

为了加强本章讨论的 Helm 的一些好处，请参考 Helm 文档中的*使用 Helm*页面，网址为 https://helm.sh/docs/intro/using_helm/。 （本页还深入讨论了 Helm 周围的一些基本用法，这将在本书中更详细地讨论。）

# 问题

1.  单体应用和微服务应用有什么区别？

1.  Kubernetes 是什么？它旨在解决什么问题？

1.  在部署应用程序到 Kubernetes 时，常用的一些`kubectl`命令是什么？

1.  在部署应用程序到 Kubernetes 时通常涉及哪些挑战？

1.  Helm 如何作为 Kubernetes 的包管理器？它是如何解决 Kubernetes 提出的挑战的？

1.  假设您想要回滚在 Kubernetes 上部署的应用程序。哪个 Helm 命令允许您执行此操作？Helm 如何跟踪您的更改以使此回滚成为可能？

1.  允许 Helm 作为包管理器运行的四个主要 Helm 命令是什么？


# 第二章：准备 Kubernetes 和 Helm 环境

Helm 是一个提供各种好处的工具，帮助用户更轻松地部署和管理 Kubernetes 应用程序。然而，在用户可以开始体验这些好处之前，他们必须满足一些先决条件。首先，用户必须能够访问 Kubernetes 集群。其次，用户应该具有 Kubernetes 和 Helm 的命令行工具。最后，用户应该了解 Helm 的基本配置选项，以便尽可能少地产生摩擦地提高生产力。

在本章中，我们将概述开始使用 Helm 所需的工具和概念。本章将涵盖以下主题：

+   使用 Minikube 准备本地 Kubernetes 环境

+   设置`kubectl`

+   设置 Helm

+   配置 Helm

# 技术要求

在本章中，您将在本地工作站上安装以下技术：

+   Minikube

+   VirtualBox

+   Helm

这些工具可以通过软件包管理器安装，也可以通过下载链接直接下载。我们将提供在 Windows 上使用`Chocolatey`软件包管理器，在 macOS 上使用`Homebrew`软件包管理器，在基于 Debian 的 Linux 发行版上使用`apt-get`软件包管理器，在基于 RPM 的 Linux 发行版上使用`dnf`软件包管理器的使用说明。

# 使用 Minikube 准备本地 Kubernetes 环境

没有访问 Kubernetes 集群，Helm 将无法部署应用程序。因此，让我们讨论一个用户可以遵循的选项，在他们的机器上运行自己的集群的选项—Minikube。

Minikube 是一个由社区驱动的工具，允许用户轻松在本地机器上部署一个小型的单节点 Kubernetes 集群。使用 Minikube 创建的集群是在一个虚拟机（VM）内创建的，因此可以在与运行 VM 的主机操作系统隔离的方式下创建和丢弃。Minikube 提供了一个很好的方式来尝试 Kubernetes，并且还可以用来学习如何在本书中提供的示例中使用 Helm。

在接下来的几节中，我们将介绍如何安装和配置 Minikube，以便在学习如何使用 Helm 时拥有一个可用的 Kubernetes 集群。有关更全面的说明，请参考官方 Minikube 网站的*入门*页面[`minikube.sigs.k8s.io/docs/start/`](https://minikube.sigs.k8s.io/docs/start/)。

## 安装 Minikube

与本章中将安装的其他工具一样，Minikube 的二进制文件是为 Windows、macOS 和 Linux 操作系统编译的。在 Windows 和 macOS 上安装最新版本的 Minikube 的最简单方法是通过软件包管理器，例如 Windows 的`Chocolatey`和 macOS 的`Homebrew`。

Linux 用户将发现，通过从 Minikube 的 GitHub 发布页面下载最新的`minikube`二进制文件更容易安装，尽管这种方法也可以在 Windows 和 macOS 上使用。

以下步骤描述了如何根据您的计算机和安装偏好安装 Minikube。请注意，在撰写本书中使用的示例的编写和开发过程中使用了 Minikube 版本 v1.5.2。

要通过软件包管理器安装它（在 Windows 和 macOS 上），请执行以下操作：

+   对于 Windows，请使用以下命令：

```
> choco install minikube
```

+   对于 macOS，请使用以下命令：

```
$ brew install minikube
```

以下步骤向您展示了如何通过下载链接（在 Windows、macOS 和 Linux 上）安装它。

`Minikube`二进制文件可以直接从其在 Git 上的发布页面下载[Hub at https://github.com/kubernetes/minikube/re](https://github.com/kubernetes/minikube/releases/tag/v1.5.2)leases/：

1.  在发布页面的底部，有一个名为*Assets*的部分，其中包含了各种支持的平台可用的 Minikube 二进制文件：![图 2.1：来自 GitHub 发布页面的 Minikube 二进制文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_2.1.jpg)

图 2.1：来自 GitHub 发布页面的 minikube 二进制文件

1.  在**Assets**部分下，应下载与目标平台对应的二进制文件。下载后，您应将二进制文件重命名为`minikube`。例如，如果您正在下载 Linux 二进制文件，您将运行以下命令：

```
$ mv minikube-linux-amd64 minikube
```

1.  为了执行`minikube`，Linux 和 macOS 用户可能需要通过运行`chmod`命令添加可执行位：

```
$ chmod u+x
```

1.  然后，`minikube`应移动到由`PATH`变量管理的位置，以便可以从命令行的任何位置执行它。`PATH`变量包含的位置因操作系统而异。对于 macOS 和 Linux 用户，可以通过在终端中运行以下命令来确定这些位置：

```
$ echo $PATH
```

1.  Windows 用户可以通过在命令提示符或 PowerShell 中运行以下命令来确定`PATH`变量的位置：

```
> $env:PATH
```

1.  然后，您可以使用 `mv` 命令将 `minikube` 二进制文件移动到新位置。以下示例将 `minikube` 移动到 Linux 上的常见 `PATH` 位置：

```
$ mv minikube /usr/local/bin/
```

1.  您可以通过运行 `minikube version` 并确保显示的版本与下载的版本相对应来验证 Minikube 的安装：

```
$ minikube version
minikube version: v1.5.2
commit: 792dbf92a1de583fcee76f8791cff12e0c9440ad-dirty
```

尽管您已经下载了 Minikube，但您还需要一个 hypervisor 来运行本地 Kubernetes 集群。这可以通过安装 VirtualBox 来实现，我们将在下一节中描述。

## 安装 VirtualBox

Minikube 依赖于存在的 hypervisors，以便在虚拟机上安装单节点 Kubernetes 集群。对于本书，我们选择讨论 VirtualBox 作为 hypervisor 选项，因为它是最灵活的，并且可用于 Windows、macOS 和 Linux 操作系统。每个操作系统的其他 hypervisor 选项可以在官方 Minikube 文档中找到 [`minikube.sigs.k8s.io/docs/start/`](https://minikube.sigs.k8s.io/docs/start/)。

与 Minikube 一样，VirtualBox 可以通过 Chocolatey 或 Homebrew 轻松安装，但也可以使用 `apt-get`（Debian-based Linux）和 `dnf`（RPM/RHEL-based Linux）轻松安装：

+   在 Windows 上安装 VirtualBox 的代码如下：

```
> choco install virtualbox
```

+   在 macOS 上安装 VirtualBox 的代码如下：

```
$ brew cask install virtualbox
```

+   在基于 Debian 的 Linux 上安装 VirtualBox 的代码如下：

```
$ apt-get install virtualbox
```

+   在 RHEL-based Linux 上安装 VirtualBox 的代码如下：

```
$ dnf install VirtualBox
```

可以在其官方下载页面 [`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads) 找到安装 VirtualBox 的其他方法。

安装了 VirtualBox 后，必须配置 Minikube 以利用 VirtualBox 作为其默认 hypervisor。此配置将在下一节中进行。

## 将 VirtualBox 配置为指定的 hypervisor

可以通过将 `minikube` 的 `vm-driver` 选项设置为 `virtualbox` 来将 VirtualBox 设置为默认 hypervisor：

```
$ minikube config set vm-driver virtualbox
```

请注意，此命令可能会产生以下警告：

```
These changes will take effect upon a minikube delete and then a minikube start
```

如果工作站上没有活动的 Minikube 集群，则可以安全地忽略此消息。此命令表示任何现有的 Kubernetes 集群在删除并重新创建集群之前都不会使用 VirtualBox 作为 hypervisor。

可以通过评估 `vm-driver` 配置选项的值来确认切换到 VirtualBox：

```
$ minikube config get vm-driver
```

如果一切顺利，输出将如下所示：

```
Virtualbox
```

除了配置默认的 hypervisor 之外，您还可以配置分配给 Minikube 集群的资源，这将在下一节中讨论。

## 配置 Minikube 资源分配

默认情况下，Minikube 将为其虚拟机分配两个 CPU 和 2 GB 的 RAM。这些资源对本书中的每个示例都足够，除了*第七章*中更需要资源的示例。如果您的机器有可用资源，应该将默认内存分配增加到 4 GB（CPU 分配可以保持不变）。

运行以下命令将增加新 Minikube 虚拟机的默认内存分配为 4 GB（4000 MB）。

```
$ minikube config set memory 4000
```

可以通过运行`minikube config get memory`命令来验证此更改，类似于之前验证`vm-driver`更改的方式。

让我们继续探索 Minikube，讨论其基本用法。

## 探索基本用法

在本书中，了解典型 Minikube 操作中使用的关键命令将非常方便。在本书的示例执行过程中，了解这些命令也是至关重要的。幸运的是，Minikube 是一个很容易上手的工具。

Minikube 有三个关键子命令：

+   `start`

+   `stop`

+   `delete`

`start`子命令用于创建单节点 Kubernetes 集群。它将创建一个虚拟机并在其中引导集群。一旦集群准备就绪，命令将终止：

```
$ minikube start
 minikube v1.5.2 on Fedora 30
  Creating virtualbox VM (CPUs=2, Memory=4000MB, Disk=20000MB) ...
  Preparing Kubernetes v1.16.2 on Docker '18.09.9' ...
  Pulling images ...
  Launching Kubernetes ...
  Waiting for: apiserver
  Done! kubectl is now configured to use 'minikube'
```

`stop`子命令用于关闭集群和虚拟机。集群和虚拟机的状态将保存到磁盘上，允许用户再次运行`start`子命令快速开始工作，而不必从头开始构建新的虚拟机。当您完成对集群的工作并希望以后返回时，应该尝试养成运行`minikube stop`的习惯：

```
$ minikube stop
  Stopping 'minikube' in virtualbox ...
  'minikube' stopped.
```

`delete`子命令用于删除集群和虚拟机。此命令将擦除集群和虚拟机的状态，释放先前分配的磁盘空间。下次执行`minikube start`时，将创建一个全新的集群和虚拟机。当您希望删除所有分配的资源并在下次调用`minikube start`时在一个全新的 Kubernetes 集群上工作时，应该运行`delete`子命令：

```
$ minikube delete
  Deleting 'minikube' in virtualbox ...
  The 'minikube' cluster has been deleted.
  Successfully deleted profile 'minikube'
```

还有更多 Minikube 子命令可用，但这些是您应该知道的主要命令。

安装并配置了 Minikube 后，您现在可以安装`kubectl`，即 Kubernetes 命令行工具，并满足使用 Helm 的其余先决条件。

# 设置 Kubectl

如*第一章*中所述，*了解 Kubernetes 和 Helm*，Kubernetes 是一个公开不同 API 端点的系统。这些 API 端点用于在集群上执行各种操作，例如创建、查看或删除资源。为了提供更简单的用户体验，开发人员需要一种与 Kubernetes 交互的方式，而无需管理底层 API 层。

虽然在本书的过程中，您主要会使用 Helm 命令行工具来安装和管理应用程序，但`kubectl`是常见任务的必备工具。

继续阅读以了解如何在本地工作站上安装`kubectl`。请注意，写作时使用的`kubectl`版本为`v1.16.2`。

## 安装 Kubectl

`kubectl`可以使用 Minikube 安装，也可以通过软件包管理器或直接下载获取。我们首先描述如何使用 Minikube 获取`kubectl`。

### 通过 Minikube 安装 Kubectl

使用 Minikube 安装`kubectl`非常简单。Minikube 提供了一个名为`kubectl`的子命令，它将下载 Kubectl 二进制文件。首先运行`minikube kubectl`：

```
$ minikube kubectl version
  Downloading kubectl v1.16.2
```

此命令将`kubectl`安装到`$HOME/.kube/cache/v1.16.2`目录中。请注意，路径中包含的`kubectl`版本将取决于您使用的 Minikube 版本。要访问`kubectl`，可以使用以下语法：

```
          minikube kubectl -- <subcommand> <flags>
```

以下是一个示例命令：

```
$ minikube kubectl -- version –client
Client Version: version.Info{Major:'1', Minor:'16', GitVersion:'v1.16.2', GitCommit:'c97fe5036ef3df2967d086711e6c0c405941e14b', GitTreeState:'clean', BuildDate:'2019-10-15T19:18:23Z', GoVersion:'go1.12.10', Compiler:'gc', Platform:'linux/amd64'}
```

使用`minikube kubectl`调用`kubectl`就足够了，但是语法比直接调用`kubectl`更加笨拙。可以通过将`kubectl`可执行文件从本地 Minikube 缓存复制到由`PATH`变量管理的位置来克服这个问题。在每个操作系统上执行此操作类似，但以下是如何在 Linux 机器上实现的示例：

```
$ sudo cp ~/.kube/cache/v1.16.2/kubectl /usr/local/bin/
```

完成后，`kubectl`可以作为独立的二进制文件调用，如下所示：

```
$ kubectl version –client
Client Version: version.Info{Major:'1', Minor:'16', GitVersion:'v1.16.2', GitCommit:'c97fe5036ef3df2967d086711e6c0c405941e14b', GitTreeState:'clean', BuildDate:'2019-10-15T19:18:23Z', GoVersion:'go1.12.10', Compiler:'gc', Platform:'linux/amd64'}
```

### 在没有 Minikube 的情况下安装 Kubectl

Kubectl 也可以在没有 Minikube 的情况下安装。Kubernetes 官方文档提供了多种不同的机制来为各种目标操作系统进行安装，网址为 https://kubernetes.io/docs/tasks/tools/install-kubectl/。

### 使用软件包管理器

`kubectl`可以在没有 Minikube 的情况下通过本机软件包管理进行安装。以下列表演示了如何在不同的操作系统上完成此操作：

+   使用以下命令在 Windows 上安装`kubectl`：

```
> choco install kubernetes-cli
```

+   使用以下命令在 macOS 上安装`kubectl`：

```
$ brew install kubernetes-cli
```

+   使用以下命令在基于 Debian 的 Linux 上安装`kubectl`：

```
$ sudo apt-get update && sudo apt-get install -y apt-transport-https gnupg2
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
$ echo 'deb https://apt.kubernetes.io/ kubernetes-xenial main' | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
$ sudo apt-get update
$ sudo apt-get install -y kubectl
```

+   使用以下命令在基于 RPM 的 Linux 上安装`kubectl`：

```
$ cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
$ yum install -y kubectl
```

我们将在下一节讨论最终的 Kubectl 安装方法。

### 直接从链接下载

Kubectl 也可以直接从下载链接下载。下载链接将包含要下载的 Kubectl 版本。您可以通过在浏览器中访问[`storage.googleapis.com/kubernetes-release/release/stable.txt`](https://storage.googleapis.com/kubernetes-release/release/stable.txt)来确定 Kubectl 的最新版本。

以下示例说明了如何下载版本 v1.16.2，这是本书中使用的 Kubectl 版本：

+   从 https://storage.googleapis.com/kubernetes-release/release/v1.16.2/bin/windows/amd64/kubectl.exe 下载 Windows 的 Kubectl。

+   从 https://storage.googleapis.com/kubernetes-release/releas](https://storage.googleapis.com/kubernetes-release/release/v1.16.2/bin/darwin/amd64/kubectl)e/v1.16.2/bin/darwin/amd64/kubectl 下载 macOS 的 Kubectl。

+   从[`storage.googleapis.com/kubernetes-release/release/v1.16.2/bin/linux/amd64/kubectl`](https://storage.googleapis.com/kubernetes-release/release/v1.16.2/bin/linux/amd64/kubectl)下载 Linux 的 Kubectl。

Kubectl 二进制文件可以移动到由`PATH`变量管理的位置。在 macOS 和 Linux 操作系统上，确保授予可执行权限：

```
$ chmod u+x kubectl
```

可以通过运行以下命令来验证 Kubectl 的安装。

```
$ kubectl version –client
Client Version: version.Info{Major:'1', Minor:'16', GitVersion:'v1.16.2', GitCommit:'c97fe5036ef3df2967d086711e6c0c405941e14b', GitTreeState:'clean', BuildDate:'2019-10-15T19:18:23Z', GoVersion:'go1.12.10', Compiler:'gc', Platform:'linux/amd64'}
```

现在我们已经介绍了如何设置`kubectl`，我们准备进入本书的关键技术——Helm。

设置 Helm

安装 Minikube 和`kubectl`后，下一个逻辑工具是配置 Helm。请注意，写作本书时使用的 Helm 版本是`v3.0.0`，但建议您使用 Helm v3 发布的最新版本，以获得最新的漏洞修复和 bug 修复。

## 安装 Helm

Chocolatey 和 Homebrew 都有 Helm 软件包，可以方便地在 Windows 或 macOS 上安装。在这些系统上，可以运行以下命令来使用软件包管理器安装 Helm：

+   使用以下命令在 Windows 上安装 Helm：

```
> choco install kubernetes-helm     
```

+   使用以下命令在 macOS 上安装 Helm：

```
$ brew install helm
```

Linux 用户或者宁愿从直接可下载链接安装 Helm 的用户可以按照以下步骤从 Helm 的 GitHub 发布页面下载存档文件：

1.  在 Helm 的 GitHub 发布页面上找到名为**Installati**[**on**的部分：](https://github.com/helm/helm/releases)：![图 2.2：Helm GitHub 发布页面上的安装部分](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_2.2.jpg)

图 2.2：Helm GitHub 发布页面上的安装部分

1.  下载与所使用操作系统对应版本的存档文件。

1.  下载后，需要解压文件。可以通过在 PowerShell 上使用`Expand-Archive`命令函数或在 Bash 上使用`tar`实用程序来实现这一点：

+   对于 Windows/PowerShell，请使用以下示例：

```
> Expand-Archive -Path helm-v3.0.0-windows-amd64.zip -DestinationPath $DEST
```

+   对于 Linux 和 Mac，请使用以下示例：

```
$ tar -zxvf helm-v3.0.0-linux.amd64.tgz
```

确保指定与下载版本对应的版本。`helm`二进制文件可以在未解压的文件夹中找到。它应该被移动到由`PATH`变量管理的位置。

以下示例向您展示了如何将`helm`二进制文件移动到 Linux 系统上的`/usr/local/bin`文件夹中：

```
$ mv ~/Downloads/linux-amd64/helm /usr/local/bin
```

无论 Helm 是以何种方式安装的，都可以通过运行`helm version`命令来进行验证。如果结果输出类似于以下输出，则 Helm 已成功安装：

```
$ helm version
version.BuildInfo{Version:'v3.0.0', GitCommit:'e29ce2a54e96cd02ccfce88bee4f58bb6e2a28b6', GitTreeState:'clean', GoVersion:'go1.13.4'}
```

安装了 Helm 后，继续下一部分，了解基本的 Helm 配置主题。

# 配置 Helm

Helm 是一个具有合理默认值的工具，允许用户在安装后无需执行大量任务即可提高生产力。话虽如此，用户可以更改或启用几种不同的选项来修改 Helm 的行为。我们将在接下来的部分中介绍这些选项，首先是配置上游仓库。

## 添加上游仓库

用户可以开始修改他们的 Helm 安装的一种方式是添加上游图表存储库。在[*第一章*]中，*理解 Kubernetes 和 Helm*，我们描述了图表存储库包含 Helm 图表，用于打包 Kubernetes 资源文件。作为 Kubernetes 包管理器的 Helm，可以连接到各种图表存储库来安装 Kubernetes 应用程序。

Helm 提供了 `repo` 子命令，允许用户管理配置的图表存储库。这个子命令包含其他子命令，可以用来执行针对指定存储库的操作。

以下是五个 `repo` 子命令：

+   `add`：添加图表存储库

+   `list`：列出图表存储库

+   `remove`：删除图表存储库

+   `update`：从图表存储库更新本地可用图表的信息

+   `index`：根据包含打包图表的目录生成索引文件

使用上述列表作为指南，可以使用 `repo add` 子命令来添加图表存储库，如下所示：

```
$ helm repo add $REPO_NAME $REPO_URL
```

为了安装其中管理的图表，需要添加图表存储库。本书将详细讨论图表安装。

您可以通过利用 `repo list` 子命令来确认存储库是否已成功添加：

```
$ helm repo list
NAME 	      URL                 	 
bitnami         https://charts.bitnami.com
```

已添加到 Helm 客户端的存储库将显示在此输出中。前面的示例显示，`bitnami` 存储库已添加，因此它出现在 Helm 客户端已知的存储库列表中。如果添加了其他存储库，它们也将出现在此输出中。

随着时间的推移，更新的图表将被发布并发布到这些存储库中。存储库元数据被本地缓存。因此，Helm 不会自动意识到图表已更新。您可以通过运行 `repo update` 子命令来指示 Helm 从每个添加的存储库检查更新。一旦执行了这个命令，您就可以从每个存储库安装最新的图表：

```
$ helm repo update
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the 'bitnami' chart repository
Update Complete. Happy Helming!
```

您可能还需要删除先前添加的存储库。这可以通过使用 `repo remove` 子命令来完成：

```
$ helm repo remove bitnami
'bitnami' has been removed from your repositories
```

最后剩下的 `repo` 子命令形式是 `index`。这个子命令被存储库和图表维护者用来发布新的或更新的图表。这个任务将在[*第五章*]中更详细地介绍，*构建您的第一个 Helm 图表*。

接下来，我们将讨论 Helm 插件配置。

## 添加插件

插件是可以用来为 Helm 提供额外功能的附加功能。大多数用户不需要担心 Helm 的插件和插件管理。Helm 本身就是一个强大的工具，并且在开箱即用时就具备了它承诺的功能。话虽如此，Helm 社区维护了各种不同的插件，可以用来增强 Helm 的功能。这些插件的列表可以在[`helm.sh/docs/community/related/`](https://helm.sh/docs/community/related/)找到。

Helm 提供了一个`plugin`子命令来管理插件，其中包含进一步的子命令，如下表所述：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/011.jpg)

插件可以提供各种不同的生产力增强。

以下是一些上游插件的示例：

+   `helm diff`: 在部署的发布和建议的 Helm 升级之间执行差异

+   `helm secrets`: 用于帮助隐藏 Helm 图表中的秘密

+   `helm monitor`: 用于监视发布并在发生特定事件时执行回滚

+   `helm unittest`: 用于对 Helm 图表执行单元测试

我们将继续讨论 Helm 配置选项，通过审查可以设置的不同环境变量来改变 Helm 行为的各个方面。

## 环境变量

Helm 依赖于外部化变量的存在来配置低级选项。Helm 文档列出了用于配置 Helm 的六个主要环境变量：

+   **XDG_CACHE_HOME**: 设置存储缓存文件的替代位置

+   **XDG_CONFIG_HOME**: 设置存储 Helm 配置的替代位置

+   **XDG_DATA_HOME**: 设置存储 Helm 数据的替代位置

+   **HELM_DRIVER**: 设置后端存储驱动程序

+   **HELM_NO_PLUGINS**: 禁用插件

+   **KUBECONFIG**: 设置替代的 Kubernetes 配置文件

Helm 遵循**XDG 基本目录规范**，该规范旨在提供一种标准化的方式来定义操作系统文件系统上不同文件的位置。根据 XDG 规范，Helm 会根据需要在每个操作系统上自动创建三个不同的默认目录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/02.jpg)

Helm 使用缓存路径存储从上游图表存储库下载的图表。安装的图表被缓存到本地机器，以便在下次引用时更快地安装图表。要更新缓存，用户可以运行`helm repo update`命令，这将使用最新可用的信息刷新存储库元数据，并将图表保存到本地缓存中。

配置路径用于保存通过运行`helm repo add`命令添加的存储库信息。当安装尚未缓存的图表时，Helm 使用配置路径查找图表存储库的 URL。Helm 使用该 URL 来了解图表所在的位置以便下载。

数据路径用于存储插件。当使用`helm plugin install`命令安装插件时，插件数据存储在此位置。

关于我们之前详细介绍的其余环境变量，`HELM_DRIVER`用于确定发布状态在 Kubernetes 中的存储方式。默认值为`secret`，这也是推荐的值。`Secret`将在 Kubernetes **Secret**中对状态进行 Base64 编码。其他选项包括`configmap`，它将在明文 Kubernetes ConfigMap 中存储状态，以及`memory`，它将在本地进程的内存中存储状态。本地内存的使用是为了测试目的，不适用于通用或生产环境。

`HELM_NO_PLUGINS`环境变量用于禁用插件。如果未设置，默认值将保持插件启用为`0`。要禁用插件，应将变量设置为`1`。

`KUBECONFIG`环境变量用于设置用于对 Kubernetes 集群进行身份验证的文件。如果未设置，默认值将为`~/.kube/config`。在大多数情况下，用户不需要修改此值。

Helm 的另一个可配置的组件是选项卡完成，接下来讨论。

## 选项卡完成

Bash 和 Z shell 用户可以启用选项卡完成以简化 Helm 的使用。选项卡完成允许在按下*Tab*键时自动完成 Helm 命令，使用户能够更快地执行任务并帮助防止输入错误。

这类似于大多数现代终端仿真器的默认行为。当按下*Tab*键时，终端会通过观察命令和环境的状态来猜测下一个参数应该是什么。例如，在 Bash shell 中，`cd /usr/local/b`输入可以通过 Tab 补全为`cd /usr/local/bin`。类似地，输入`helm upgrade hello-`可以通过 Tab 补全为`helm upgrade hello-world`。

可以通过运行以下命令启用 Tab 补全：

```
$ source <(helm completion $SHELL)
```

`$SHELL`变量必须是`bash`或`zsh`。请注意，自动补全只存在于运行前述命令的终端窗口中，因此其他窗口也需要运行此命令才能体验到自动补全功能。

## 身份验证

Helm 需要能够通过`kubeconfig`文件对 Kubernetes 集群进行身份验证，以便部署和管理应用程序。它通过引用`kubeconfig`文件进行身份验证，该文件指定了不同的 Kubernetes 集群以及如何对其进行身份验证。

在阅读本书时使用 Minikube 的人不需要配置身份验证，因为 Minikube 在每次创建新集群时会自动配置`kubeconfig`文件。然而，没有运行 Minikube 的人可能需要创建`kubeconfig`文件或者根据使用的 Kubernetes 发行版提供一个。

`kubeconfig`文件可以通过利用三个不同的`kubectl`命令来创建：

+   第一个命令是`set-cluster`：

```
kubectl config set-cluster
```

`set-cluster`命令将在`kubeconfig`文件中定义一个`cluster`条目。它确定 Kubernetes 集群的主机名或 IP 地址，以及其证书颁发机构。

+   下一个命令是`set-credentials`：

```
kubectl config set-credentials
```

`set-credentials`命令将定义用户的名称以及其身份验证方法和详细信息。此命令可以配置用户名和密码对、客户端证书、持有者令牌或身份验证提供程序，以允许用户和管理员指定不同的身份验证方法。

+   然后，我们有`set-context`命令：

```
kubectl config set-context
```

`set-context`命令用于将凭据与集群关联起来。一旦建立了凭据和集群之间的关联，用户将能够使用凭据的身份验证方法对指定的集群进行身份验证。

`kubectl config view`命令可用于查看`kubeconfig`文件。注意`kubeconfig`的`clusters`、`contexts`和`user`部分与先前描述的命令相对应，如下所示：

```
$ kubectl config view
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /home/helm-user/.minikube/ca.crt
    server: https://192.168.99.102:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    user: minikube
  name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
  user:
    client-certificate: /home/helm-user/.minikube/client.crt
    client-key: /home/helm-user/.minikube/client.key
```

一旦存在有效的 kubeconfig 文件，Kubectl 和 Helm 将能够与 Kubernetes 集群进行交互。

在下一节中，我们将讨论授权如何针对 Kubernetes 集群进行处理。

## 授权/RBAC

身份验证是确认身份的一种方式，授权定义了经过身份验证的用户被允许执行的操作。Kubernetes 使用基于角色的访问控制（RBAC）来执行对 Kubernetes 的授权。RBAC 是一种设计角色和特权的系统，可以分配给特定用户或用户组。用户被允许在 Kubernetes 上执行的操作取决于用户被分配的角色。

Kubernetes 在平台上提供了许多不同的角色。这里列出了三种常见的角色：

+   `cluster-admin`：允许用户对整个集群中的任何资源执行任何操作

+   `edit`：允许用户在命名空间或逻辑分组的大多数资源中进行读写

+   `view`：防止用户修改现有资源，只允许用户在命名空间内读取资源

由于 Helm 使用 kubeconfig 文件中定义的凭据对 Kubernetes 进行身份验证，因此 Helm 被赋予与文件中定义的用户相同级别的访问权限。如果启用了`edit`访问权限，Helm 可以假定具有足够的权限来安装应用程序，在大多数情况下。对于仅具有查看权限的情况，Helm 将无法安装应用程序，因为这种访问级别是只读的。

运行 Minikube 的用户在集群创建后默认被赋予`cluster-admin`权限。虽然这在生产环境中不是最佳做法，但对于学习和实验是可以接受的。运行 Minikube 的用户不必担心配置授权以便跟随本书提供的概念和示例。那些使用其他不是 Minikube 的 Kubernetes 集群的用户需要确保他们至少被赋予编辑角色才能够使用 Helm 部署大多数应用程序。可以通过要求管理员运行以下命令来实现这一点：

```
$ kubectl create clusterrolebinding $USER-edit --clusterrole=edit --user=$USER
```

在*第九章*中将讨论 RBAC 的最佳实践，*Helm 安全考虑*，我们将更详细地讨论与安全相关的概念，包括如何适当地应用角色以防止集群中的错误或恶意意图。

# 总结

使用 Helm 需要准备各种不同的组件。在本章中，您学习了如何安装 Minikube，以提供可用于本书的本地 Kubernetes 集群。您还学习了如何安装 Kubectl，这是与 Kubernetes API 交互的官方工具。最后，您学习了如何安装 Helm 客户端，并探索了 Helm 的各种配置方式，包括添加存储库和插件，修改环境变量，启用选项卡完成，并配置针对 Kubernetes 集群的身份验证和授权。

现在您已经安装了必备的工具，可以开始学习如何使用 Helm 部署您的第一个应用程序。在下一章中，您将从上游图表存储库安装 Helm 图表，并了解生命周期管理和应用程序配置。完成本章后，您将了解 Helm 如何作为 Kubernetes 的软件包管理器。

# 进一步阅读

查看以下链接，了解 Minikube、Kubectl 和 Helm 的安装选项：

+   Minikube：[`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)

+   Kubectl：[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

+   Helm：[`helm.sh/docs/intro/install/`](https://helm.sh/docs/intro/install/)

我们介绍了各种不同的 Helm 后安装配置方式。查看以下链接，了解更多有关以下主题的信息：

+   存储库管理：[`helm.sh/docs/intro/quickstart/#initialize-a-helm-chart-repository`](https://helm.sh/docs/intro/quickstart/#initialize-a-helm-chart-repository)

+   插件管理：[`helm.sh/docs/topics/plugins/`](https://helm.sh/docs/topics/plugins/)

+   环境变量和`helm help`输出：[`helm.sh/docs/helm/helm/`](https://helm.sh/docs/helm/helm/)

+   选项卡完成：[`helm.sh/docs/helm/helm_completion/`](https://helm.sh/docs/helm/helm_completion/)

+   通过`kub`[`econfig`文件进行身份验证和授权：https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/

# 问题

1.  您可以列出安装 Helm 客户端的各种方法吗？

1.  Helm 如何对 Kubernetes 集群进行身份验证？

1.  有什么机制可以为 Helm 客户端提供授权？管理员如何管理这些权限？

1.  `helm repo add`命令的目的是什么？

1.  Helm 使用的三个 XDG 环境变量是什么？它们有什么作用？

1.  为什么 Minikube 是学习如何使用 Kubernetes 和 Helm 的好选择？Minikube 自动配置了哪些内容，以使用户能够更快地开始使用？


# 第三章：安装您的第一个 Helm 图表

在本书的早期，我们将 Helm 称为“Kubernetes 软件包管理器”，并将其与操作系统的软件包管理器进行了比较。软件包管理器允许用户快速轻松地安装各种复杂性的应用程序，并管理应用程序可能具有的任何依赖关系。Helm 以类似的方式工作。

用户只需确定他们想要在 Kubernetes 上部署的应用程序，Helm 会为他们完成其余的工作。Helm 图表——Kubernetes 资源的打包——包含安装应用程序所需的逻辑和组件，允许用户执行安装而无需知道具体所需的资源。用户还可以传递参数，称为值，到 Helm 图表中，以配置应用程序的不同方面，而无需知道正在配置的 Kubernetes 资源的具体细节。您将通过本章来利用 Helm 作为软件包管理器，在 Kubernetes 上部署 WordPress 实例，来探索这些功能。

本章将涵盖以下主要主题：

+   在 Helm Hub 上找到 WordPress 图表

+   创建 Kubernetes 环境

+   附加安装说明

+   安装 WordPress 图表

+   访问 WordPress 应用程序

+   升级 WordPress 发布

+   回滚 WordPress 发布

+   卸载 WordPress 发布

# 技术要求

本章将使用以下软件技术：

+   `minikube`

+   `kubectl`

+   `helm`

我们将假设这些组件已经安装在您的系统上。有关这些工具的更多信息，包括安装和配置，请参阅*第二章*，*准备 Kubernetes 和 Helm 环境*。

# 了解 WordPress 应用程序

在本章中，您将使用 Helm 在 Kubernetes 上部署**WordPress**。WordPress 是一个用于创建网站和博客的开源**内容管理系统**（**CMS**）。有两种不同的变体可用——[WordPress.com](http://WordPress.com)和[WordPress.org](http://WordPress.org)。[WordPress.com](http://WordPress.com)是 CMS 的**软件即服务**（**SaaS**）版本，这意味着 WordPress 应用程序及其组件已经由 WordPress 托管和管理。在这种情况下，用户不需要担心安装自己的 WordPress 实例，因为他们可以简单地访问已经可用的实例。另一方面，[WordPress.org](http://WordPress.org)是自托管选项。它要求用户部署自己的 WordPress 实例，并需要专业知识来维护。

由于[WordPress.com](http://WordPress.com)更容易上手，可能听起来更加可取。然而，这个 WordPress 的 SaaS 版本与自托管的[WordPress.org](http://WordPress.org)相比有很多缺点：

+   它不提供与[WordPress.org](http://WordPress.org)一样多的功能。

+   它不给用户对网站的完全控制。

+   它要求用户支付高级功能。

+   它不提供修改网站后端代码的能力。

另一方面，自托管的[WordPress.org](http://WordPress.org)版本让用户完全控制他们的网站和 WordPress 实例。它提供完整的 WordPress 功能集，从安装插件到修改后端代码。

自托管的 WordPress 实例需要用户部署一些不同的组件。首先，WordPress 需要一个数据库来保存网站和管理数据。 [WordPress.org](http://WordPress.org) 指出数据库必须是 **MySQL** 或 **MariaDB**，它既是网站的位置，也是管理门户。在 Kubernetes 中，部署这些组件意味着创建各种不同的资源：

+   用于数据库和管理控制台身份验证的`secrets`

+   用于外部化数据库配置的 ConfigMap

+   网络服务

+   用于数据库存储的`PersistentVolumeClaim`

+   用于以有状态的方式部署数据库的 StatefulSet

+   用于部署前端的`Deployment`

创建这些 Kubernetes 资源需要 WordPress 和 Kubernetes 方面的专业知识。需要 WordPress 方面的专业知识，因为用户需要了解所需的物理组件以及如何配置它们。需要 Kubernetes 方面的专业知识，因为用户需要知道如何将 WordPress 的要求表达为 Kubernetes 资源。考虑到所需的资源的复杂性和数量，将 WordPress 部署到 Kubernetes 上可能是一项艰巨的任务。

这项任务带来的挑战是 Helm 的一个完美用例。用户可以利用 Helm 作为软件包管理器，在不需要专业知识的情况下，在 Kubernetes 上部署和配置 WordPress，而不是专注于创建和配置我们已描述的每个 Kubernetes 资源。首先，我们将探索一个名为 **Helm Hub** 的平台，以找到 WordPress Helm 图表。之后，我们将使用 Helm 在 Kubernetes 集群上部署 WordPress，并在此过程中探索基本的 Helm 功能。

# 查找 WordPress 图表

Helm 图表可以通过发布到图表存储库来供使用。图表存储库是存储和共享打包图表的位置。存储库只是作为 HTTP 服务器托管，并且可以采用各种实现形式，包括 GitHub 页面、Amazon S3 存储桶或简单的 Web 服务器，如 Apache HTTPD。

为了能够使用存储在存储库中的现有图表，Helm 首先需要配置到一个可以使用的存储库。这可以通过使用 `helm repo add` 来添加存储库来实现。添加存储库涉及的一个挑战是，有许多不同的图表存储库可供使用；可能很难找到适合您用例的特定存储库。为了更容易找到图表存储库，Helm 社区创建了一个名为 Helm Hub 的平台。

Helm Hub 是上游图表存储库的集中位置。由一个名为 **Monocular** 的社区项目提供支持，Helm Hub 旨在汇总所有已知的公共图表存储库并提供搜索功能。在本章中，我们将使用 Helm Hub 平台来搜索 WordPress Helm 图表。一旦找到合适的图表，我们将添加该图表所属的存储库，以便安装后续使用。

首先，可以通过命令行或 Web 浏览器与 Helm Hub 进行交互。当使用命令行搜索 Helm 图表时，返回的结果提供了 Helm Hub 的 URL，可以用来查找有关图表的其他信息以及如何添加其图表存储库的说明。

让我们按照这个工作流程来添加一个包含 WordPress 图表的图表存储库。

## 从命令行搜索 WordPress 图表

一般来说，Helm 包含两个不同的搜索命令，以帮助我们找到 Helm 图表：

+   要在 Helm Hub 或 Monocular 实例中搜索图表，请使用以下命令：

```
helm search hub
```

+   要在图表中搜索关键字，请使用以下命令：

```
helm search repo
```

如果之前没有添加存储库，用户应该运行`helm search hub`命令来查找所有公共图表存储库中可用的 Helm 图表。添加存储库后，用户可以运行`helm search repo`来搜索这些存储库中的图表。

让我们在 Helm Hub 中搜索任何现有的 WordPress 图表。Helm Hub 中的每个图表都有一组关键字，可以针对其进行搜索。执行以下命令来查找包含`wordpress`关键字的图表：

```
$ helm search hub wordpress
```

运行此命令后，应显示类似以下的输出：

![图 3.1–运行 helm search hub wordpress 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.1.jpg)

图 3.1–运行`helm search hub wordpress`的输出

该命令返回的每行输出都是来自 Helm Hub 的图表。输出将显示每个图表的 Helm Hub 页面的 URL。它还将显示图表版本，这是 Helm 图表的最新版本，以及应用程序版本，这是图表默认部署的应用程序版本。该命令还将打印每个图表的描述，通常会说明图表部署的应用程序。

正如您可能已经注意到的，返回的一些值被截断了。这是因为`helm search hub`的默认输出是一个表，导致结果以表格格式返回。默认情况下，宽度超过 50 个字符的列会被截断。可以通过指定`--max-col-width=0`标志来避免这种截断。

尝试运行以下命令，包括`--max-col-width`标志，以查看表格格式中未截断的结果：

```
$ helm search hub wordpress  --max-col-width=0
```

结果以表格格式显示每个字段的完整内容，包括 URL 和描述。

URL 如下：

+   [`hub.helm.sh/charts/bitnami/wordpress`](https://hub.helm.sh/charts/bitnami/wordpress)

+   [`hub.helm.sh/charts/presslabs/wordpress-site`](https://hub.helm.sh/charts/presslabs/wordpress-site)

+   [`hub.helm.sh/charts/presslabs/wordpress-operator`](https://hub.helm.sh/charts/presslabs/wordpress-operator)

描述如下：

+   `用于构建博客和网站的网络发布平台。`

+   `用于在 Presslabs Stack 上部署 WordPress 站点的 Helm 图表`

+   `Presslabs WordPress Operator Helm Chart`

或者，用户可以传递`--output`标志，并指定`yaml`或`json`输出，这将以完整形式打印搜索结果。

尝试再次运行上一个命令，带上`--output yaml`标志：

```
$ helm search hub wordpress --output yaml
```

结果将以 YAML 格式显示，类似于此处显示的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.2.jpg)

图 3.2 - `helm search hub wordpress--output yaml`的输出

在此示例中，我们将选择安装在前面示例输出中返回的第一个图表。要了解有关此图表及其安装方式的更多信息，我们可以转到[`hub.helm.sh/charts/bitnami/wordpress`](https://hub.helm.sh/charts/bitnami/wordpress)，这将帮助我们从 Helm Hub 查看图表。

生成的内容将在下一节中探讨。

## 在浏览器中查看 WordPress 图表

使用`helm search hub`是在 Helm Hub 上搜索图表的最快方法。但是，它并不提供安装所需的所有细节。换句话说，用户需要知道图表的存储库 URL，以便添加其存储库并安装图表。图表的 Helm Hub 页面可以提供此 URL，以及其他安装细节。

将 WordPress 图表的 URL 粘贴到浏览器窗口后，应显示类似以下内容的页面：

![图 3.3 - 来自 Helm Hub 的 WordPress Helm 图表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.3.jpg)

图 3.3 - 来自 Helm Hub 的 WordPress Helm 图表

Helm Hub 上的 WordPress 图表页面提供了许多详细信息，包括图表的维护者（**Bitnami**，这是一家提供可部署到不同环境的软件包的公司）以及有关图表的简要介绍（说明此图表将在 Kubernetes 上部署一个 WordPress 实例，并将 Bitnami MariaDB 图表作为依赖项）。该网页还提供了安装详细信息，包括用于配置安装的图表支持的值，以及 Bitnami 的图表存储库 URL。这些安装详细信息使用户能够添加此存储库并安装 WordPress 图表。

在页面的右侧，您应该会看到一个名为**添加 bitnami 存储库**的部分。该部分包含可用于添加 Bitnami 图表存储库的命令。让我们看看如何使用它：

1.  在命令行中运行以下命令：

```
$ helm repo add bitnami https://charts.bitnami.com
```

1.  通过运行`helm repo list`来验证图表是否已添加：

```
$ helm repo list
NAME  	 URL 
bitnami     https://charts.bitnami.com
```

现在我们已经添加了存储库，我们可以做更多事情。

1.  运行以下命令来查看包含`bitnami`关键字的本地配置存储库中的图表：

```
$ helm search repo bitnami --output yaml
```

以下输出显示了返回的结果的缩短列表：

![图 3.4 - helm search repo --output yaml 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Image86715.jpg)

图 3.4 - `helm search repo bitnami --output yaml`的输出

与`helm search hub`命令类似，`helm search repo`命令接受关键字作为参数。使用`bitnami`作为关键字将返回`bitnami`存储库下的所有图表，以及可能还包含`bitnami`关键字的存储库外的图表。

为了确保您现在可以访问 WordPress 图表，请使用`wordpress`参数运行以下`helm search repo`命令：

```
$ helm search repo wordpress
```

输出将显示您在 Helm Hub 上找到并在浏览器中观察到的 WordPress 图表：

![图 3.5 - helm search repo wordpress 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.5.jpg)

图 3.5 - `helm search repo wordpress`的输出

斜杠（`/`）前的`NAME`字段中的值表示返回的 Helm 图表所在的存储库的名称。截至撰写本文时，`bitnami`存储库中 WordPress 图表的最新版本是`8.1.0`。这是将用于安装的版本。通过向`search`命令传递`--versions`标志可以观察以前的版本：

```
$ helm search repo wordpress --versions
```

然后，您应该看到每个可用 WordPress 图表的每个版本的新行：

![图 3.6 - bitnami 存储库上 WordPress 图表的版本列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.6.jpg)

图 3.6 - bitnami 存储库上 WordPress 图表的版本列表

现在已经确定了 WordPress 图表，并且已经添加了图表的存储库，我们将探讨如何使用命令行来了解有关图表的更多信息，以准备在下一节中进行安装。

## 从命令行显示 WordPress 图表信息

您可以在其 Helm Hub 页面上找到有关 Helm 图表的许多重要细节。一旦图表存储库被本地添加，这些信息（以及更多）也可以通过以下列表中描述的四个`helm show`子命令从命令行中查看：

+   这个命令显示了图表的元数据（或图表定义）：

```
helm show chart
```

+   这个命令显示了图表的`README`文件：

```
helm show readme
```

+   这个命令显示了图表的值：

```
helm show values
```

+   这个命令显示了图表的定义、README 文件和值：

```
helm show all
```

让我们使用这些命令与 Bitnami WordPress 图表。在这些命令中，图表应该被引用为`bitnami/wordpress`。请注意，我们将传递`--version`标志来检索关于此图表版本`8.1.0`的信息。如果省略此标志，将返回图表最新版本的信息。

运行`helm show chart`命令来检索图表的元数据：

```
$ helm show chart bitnami/wordpress --version 8.1.0
```

这个命令的结果将是 WordPress 图表的**图表定义**。图表定义描述了图表的版本、依赖关系、关键字和维护者等信息：

![图 3.7 - wordpress 图表定义](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.7.jpg)

图 3.7 - WordPress 图表定义

运行`helm show readme`命令来从命令行查看图表的 README 文件：

```
$ helm show readme bitnami/wordpress --version 8.1.0
```

这个命令的结果可能看起来很熟悉，因为图表的 README 文件也显示在其 Helm Hub 页面上。利用这个选项从命令行提供了一种快速查看 README 文件的方式，而不必打开浏览器：

![图 3.8 - 在命令行中显示的 wordpress 图表的 README 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.8.jpg)

图 3.8 - 在命令行中显示的 WordPress 图表的 README 文件

我们使用`helm show values`来检查图表的值。值作为用户可以提供的参数，以便定制图表安装。在本章的*为配置创建一个 values 文件*部分中，当我们安装图表时，我们将稍后运行此命令。

最后，`helm show all`将前三个命令的所有信息汇总在一起。如果您想一次检查图表的所有细节，请使用此命令。

现在我们已经找到并检查了一个 WordPress 图表，让我们设置一个 Kubernetes 环境，以便稍后安装这个图表。

# 创建一个 Kubernetes 环境

为了在本章中创建一个 Kubernetes 环境，我们将使用 Minikube。我们在*第二章*中学习了如何安装 Minikube，*准备 Kubernetes 和 Helm 环境*。

让我们按照以下步骤设置 Kubernetes：

1.  通过运行以下命令启动您的 Kubernetes 集群：

```
$ minikube start
```

1.  经过短暂的时间，您应该在输出中看到一行类似于以下内容的内容：

```
 Done! kubectl is now configured to use 'minikube'
```

1.  一旦 Minikube 集群启动并运行，为本章的练习创建一个专用命名空间。运行以下命令创建一个名为`chapter3`的命名空间：

```
$ kubectl create namespace chapter3
```

现在集群设置已经完成，让我们开始安装 WordPress 图表到您的 Kubernetes 集群。

# 安装 WordPress 图表

安装 Helm 图表是一个简单的过程，可以从检查图表的值开始。在下一节中，我们将检查 WordPress 图表上可用的值，并描述如何创建一个允许自定义安装的文件。最后，我们将安装图表并访问 WordPress 应用程序。

## 为配置创建一个 values 文件

您可以通过提供一个 YAML 格式的`values`文件来覆盖图表中定义的值。为了正确创建一个`values`文件，您需要检查图表提供的支持的值。这可以通过运行`helm show values`命令来完成，如前所述。

运行以下命令检查 WordPress 图表的值：

```
$ helm show values bitnami/wordpress --version 8.1.0
```

该命令的结果应该是一个可能值的长列表，其中许多已经设置了默认值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.9.jpg)

图 3.9 - 运行`helm show values`生成的值列表

先前的输出显示了 WordPress 图表数值的开始。这些属性中的许多已经有默认设置，这意味着如果它们没有被覆盖，这些数值将代表图表的配置方式。例如，如果在`values`文件中没有覆盖`image`数值，WordPress 图表使用的图像将使用来自 docker.io 注册表的`bitnami/wordpress`容器图像，标签为`5.3.2-debian-9-r0`。

图表数值中以井号(`#`)开头的行是注释。注释可以用来解释一个数值或一组数值，也可以用来注释数值以取消设置它们。在先前输出的顶部的`global` YAML 段中显示了通过注释取消设置数值的示例。除非用户显式设置，否则这些数值默认情况下将被取消设置。

如果我们进一步探索`helm show values`的输出，我们可以找到与配置 WordPress 博客元数据相关的数值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.10.jpg)

图 3.10 - 运行`helm show values`命令返回的数值

这些数值似乎对配置 WordPress 博客很重要。让我们通过创建一个`values`文件来覆盖它们。在你的机器上创建一个名为`wordpress-values.yaml`的新文件。在文件中输入以下内容：

```
wordpressUsername: helm-user
wordpressPassword: my-pass
wordpressEmail: helm-user@example.com
wordpressFirstName: Helm_is
wordpressLastName: Fun
wordpressBlogName: Learn Helm!
```

如果你愿意，可以更有创意地使用这些数值。继续从`helm show values`中列出的数值列表中，还有一个重要的数值应该在开始安装之前添加到`values`文件中，如下所示：

![图 3.11 - 运行 helm show values 后返回的 LoadBalancer 数值](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.11.jpg)

图 3.11 - 运行`helm show values`后返回的 LoadBalancer 数值

如注释所述，这个数值说明如果我们使用 Minikube，我们需要将默认的`LoadBalancer`类型更改为`NodePort`。在 Kubernetes 中，`LoadBalancer`服务类型用于从公共云提供商中提供负载均衡器。虽然可以通过利用`minikube tunnel`命令来支持这个数值，但将这个数值设置为`NodePort`将允许您直接访问本地端口的 WordPress 应用，而不必使用`minikube tunnel`命令。

将这个数值添加到你的`wordpress-values.yaml`文件中：

```
service:
  type: NodePort
```

一旦这个数值被添加到你的`values`文件中，你的完整的`values`文件应该如下所示：

```
wordpressUsername: helm-user
wordpressPassword: my-pass
wordpressEmail: helm-user@example.com
wordpressFirstName: Helm_is
wordpressLastName: Fun
wordpressBlogName: Learn Helm!
service:
  type: NodePort
```

现在`values`文件已经完成，让我们开始安装。

## 运行安装

我们使用`helm install`来安装 Helm 图表。标准语法如下：

```
helm install [NAME] [CHART] [flags]
```

`NAME`参数是您想要给 Helm 发布的名称。**发布**捕获了使用图表安装的 Kubernetes 资源，并跟踪应用程序的生命周期。我们将在本章中探讨发布如何工作。

`CHART`参数是安装的 Helm 图表的名称。可以通过遵循`<repo name>/<chart name>`的形式安装存储库中的图表。

`helm install`中的`flags`选项允许您进一步自定义安装。`flags`允许用户定义和覆盖值，指定要处理的命名空间等。可以通过运行`helm install --help`来查看标志列表。我们也可以将`--help`传递给其他命令，以查看它们的用法和支持的选项。

现在，对于`helm install`的使用有了适当的理解，运行以下命令：

```
$ helm install wordpress bitnami/wordpress --values=wordpress-values.yaml --namespace chapter3 --version 8.1.0
```

此命令将使用`bitnami/wordpress` Helm 图表安装一个名为`wordpress`的新发布。它将使用`wordpress-values.yaml`文件中定义的值来自定义安装，并且图表将安装在`chapter3`命名空间中。它还将部署`8.1.0`版本，如`--version`标志所定义。没有此标志，Helm 将安装 Helm 图表的最新版本。

如果图表安装成功，您应该看到以下输出：

![图 3.12–成功安装 WordPress 图表的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.12.jpg)

图 3.12–成功安装 WordPress 图表的输出

此输出显示有关安装的信息，包括发布的名称、部署时间、安装的命名空间、部署状态（为`deployed`）和修订号（由于这是发布的初始安装，因此设置为`1`）。

输出还显示了与安装相关的注释列表。注释用于为用户提供有关其安装的其他信息。在 WordPress 图表的情况下，这些注释提供了有关如何访问和验证 WordPress 应用程序的信息。尽管这些注释直接在安装后出现，但可以随时使用`helm get notes`命令检索，如下一节所述。

完成第一次 Helm 安装后，让我们检查发布以观察应用的资源和配置。

## 检查您的发布

检查发布并验证其安装的最简单方法之一是列出给定命名空间中的所有 Helm 发布。为此，Helm 提供了`list`子命令。

运行以下命令以查看`chapter3`命名空间中的发布列表：

```
$ helm list --namespace chapter3
```

您应该只在此命名空间中看到一个发布，如下所示：

![图 3.13 - 列出 Helm 发布的 helm list 命令的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.13.jpg)

图 3.13 - 列出 Helm 发布的`helm list`命令的输出

`list`子命令提供以下信息：

+   发布名称

+   发布命名空间

+   发布的最新修订号

+   最新修订的时间戳

+   发布状态

+   图表名称

+   应用程序版本

请注意，状态、图表名称和应用程序版本从前面的输出中被截断。

虽然`list`子命令对于提供高级发布信息很有用，但用户可能想要了解特定发布的其他信息。Helm 提供了`get`子命令来提供有关发布的更多信息。以下列表描述了可用于提供一组详细发布信息的命令：

+   要获取命名发布的所有钩子，请运行以下命令：

```
helm get hooks
```

+   要获取命名发布的清单，请运行以下命令：

```
helm get manifest
```

+   要获取命名发布的注释，请运行以下命令：

```
helm get notes
```

+   要获取命名发布的值，请运行以下命令：

```
helm get values
```

+   要获取有关命名发布的所有信息，请运行以下命令：

```
helm get all
```

前面列表中的第一个命令`helm get hooks`用于显示给定发布的钩子。在*第五章* *构建您的第一个 Helm 图表*和*第六章* *测试 Helm 图表*中，您将了解有关构建和测试 Helm 图表时更详细地探讨钩子。目前，钩子可以被视为 Helm 在应用程序生命周期的某些阶段执行的操作。

运行以下命令以查看包含在此发布中的钩子：

```
$ helm get hooks wordpress --namespace chapter3
```

在输出中，您将找到两个带有以下注释的 Kubernetes Pod 清单：

```
'helm.sh/hook': test-success
```

此注释表示在执行`test`子命令期间运行的钩子，我们将在*第六章*中更详细地探讨，*测试 Helm 图表*。这些测试钩子为图表开发人员提供了一种确认图表是否按设计运行的机制，并且可以被最终用户安全地忽略。

由于此图表中包含的两个钩子都是用于测试目的，让我们继续进行前面列表中的下一个命令，以继续进行发布检查。

`helm get manifest`命令可用于获取作为安装的一部分创建的 Kubernetes 资源列表。请按照以下示例运行此命令：

```
$ helm get manifest wordpress --namespace chapter3
```

运行此命令后，您将看到以下 Kubernetes 清单：

+   两个`s`ecrets`清单。

+   两个`ConfigMaps`清单（第一个用于配置 WordPress 应用程序，而第二个用于测试，由图表开发人员执行，因此可以忽略）。

+   一个`PersistentVolumeClaim`清单。

+   两个`services`清单。

+   一个`Deployment`清单。

+   一个`StatefulSet`清单。

从此输出中，您可以观察到在配置 Kubernetes 资源时您的值产生了影响。一个要注意的例子是 WordPress 服务中的`type`已设置为`NodePort`：

![图 3.14 - 将类型设置为 NodePort](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.14.jpg)

图 3.14 - 将`type`设置为`NodePort`

您还可以观察我们为 WordPress 用户设置的其他值。这些值在 WordPress 部署中被定义为环境变量，如下所示：

![图 3.15 - 值设置为环境变量](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.15.jpg)

图 3.15 - 值设置为环境变量

图表提供的大多数默认值都保持不变。这些默认值已应用于 Kubernetes 资源，并可以通过`helm get manifest`命令观察到。如果这些值已更改，则 Kubernetes 资源将以不同的方式配置。

让我们继续下一个`get`命令。`helm get notes`命令用于显示 Helm 发布的注释。您可能还记得，安装 WordPress 图表时显示了发布说明。这些说明提供了有关访问应用程序的重要信息，可以通过运行以下命令再次显示：

```
$ helm get notes wordpress --namespace chapter3
```

`helm get values`命令对于回忆为给定发布使用的值非常有用。运行以下命令以查看在`wordpress`发布中提供的值：

```
$ helm get values wordpress --namespace chapter3
```

此命令的结果应该看起来很熟悉，因为它们应该与`wordpress-values.yaml`文件中指定的值匹配：

![图 3.16 - wordpress 发布中的用户提供的值](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.16.jpg)

图 3.16 - wordpress 发布中的用户提供的值

虽然回忆用户提供的值很有用，但在某些情况下，可能需要返回发布使用的所有值，包括默认值。这可以通过传递额外的`--all`标志来实现，如下所示：

```
$ helm get values wordpress --all --namespace chapter3
```

对于此图表，输出将会很长。以下输出显示了前几个值：

![图 3.17 - wordpress 发布的所有值的子集](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.17.jpg)

图 3.17 - wordpress 发布的所有值的子集

最后，Helm 提供了一个`helm get all`命令，可以用来聚合各种`helm get`命令的所有信息：

```
$ helm get all wordpress --namespace chapter3
```

除了 Helm 提供的命令之外，`kubectl` CLI 也可以用于更仔细地检查安装。例如，可以使用`kubectl`来缩小范围，仅查看一种类型的资源，如部署，而不是获取安装创建的所有 Kubernetes 资源。为了确保返回的资源属于 Helm 发布，可以在部署上定义一个标签，并将其提供给`kubectl`命令，以表示发布的名称。Helm 图表通常会在它们的 Kubernetes 资源上添加一个`app`标签。使用`kubectl` CLI 通过运行以下命令来检索包含此标签的部署：

```
$ kubectl get all -l app=wordpress --namespace chapter3
```

您会发现以下部署存在于`chapter3`命名空间中：

![图 3.18 - 章节 3 命名空间中的 wordpress 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.18.jpg)

图 3.18 - `chapter3`命名空间中的 wordpress 部署

# 其他安装说明

很快，我们将探索刚刚安装的 WordPress 应用程序。首先，在离开安装主题之前，应该提到几个需要考虑的领域。

## -n 标志

可以使用`-n`标志代替`--namespace`标志，以减少输入命令时的输入工作量。这对于稍后将在本章中描述的`upgrade`和`rollback`命令也适用。从现在开始，我们将在表示 Helm 应该与之交互的命名空间时使用`-n`标志。

## 环境变量 HELM_NAMESPACE

您还可以设置一个环境变量来表示 Helm 应该与之交互的命名空间。

让我们看看如何在各种操作系统上设置这个环境变量：

+   您可以在 macOS 和 Linux 上设置变量如下：

```
$ export HELM_NAMESPACE=chapter3
```

+   Windows 用户可以通过在 PowerShell 中运行以下命令来设置此环境变量：

```
> $env:HELM_NAMESPACE = 'chapter3'
```

可以通过运行`helm env`命令来验证此变量的值：

```
$ helm env
```

您应该在结果输出中看到`HELM_NAMESPACE`变量。默认情况下，该变量设置为`default`。

在本书中，我们不会依赖`HELM_NAMESPACE`变量，而是会在每个命令旁边传递`-n`标志，以便更清楚地指出我们打算使用哪个命名空间。提供`-n`标志也是指定 Helm 命名空间的最佳方式，因为它确保我们正在针对预期的命名空间。

## 在--set 和--values 之间进行选择

对于`install`，`upgrade`和`rollback`命令，您可以选择两种方式之一来传递值给您的图表：

+   要从命令行中传递值，请使用以下命令：

```
--set
```

+   要在 YAML 文件或 URL 中指定值，请使用以下命令：

```
--values
```

在本书中，我们将把`--values`标志视为配置图表值的首选方法。原因是这种方式更容易配置多个值。维护一个`values`文件还将允许我们将这些资产保存在**源代码管理**（**SCM**）系统中，例如`git`，这样可以更容易地重现安装过程。请注意，诸如密码之类的敏感值不应存储在源代码控制存储库中。我们将在*第九章*中涵盖安全性问题，*Helm 安全性考虑*。目前，重要的是要记住不要将`secrets`推送到源代码控制存储库中。当需要在图表中提供 secrets 时，建议的方法是明确使用`--set`标志。

`--set`标志用于直接从命令行传递值。这是一个可接受的方法，适用于简单的值，以及需要配置的少量值。再次强调，使用`--set`标志并不是首选方法，因为它限制了使安装更具可重复性的能力。以这种方式配置复杂值也更加困难，例如列表或复杂映射形式的值。还有其他相关的标志，如`--set-file`和`--set-string`；`--set-file`标志用于传递一个具有`key1=val1`和`key2=val2`格式的配置值的文件，而`--set-string`标志用于将提供的所有值设置为字符串的`key1=val1`和`key2=val2`格式。

解释到此为止，让我们来探索刚刚安装的 WordPress 应用程序。

# 访问 WordPress 应用程序

WordPress 图表的发布说明提供了四个命令，您可以运行这些命令来访问您的 WordPress 应用程序。运行此处列出的四个命令：

+   对于 macOS 或 Linux，请运行以下命令：

```
$ export NODE_PORT=$(kubectl get --namespace chapter3 -o jsonpath="{.spec.ports[0].nodePort}" services wordpress)
$ export NODE_IP=$(kubectl get nodes --namespace chapter3 -o jsonpath="{.items[0].status.addresses[0].address}")
$ echo "WordPress URL: http://$NODE_IP:$NODE_PORT/"
$ echo "WordPress Admin URL: http://$NODE_IP:$NODE_PORT/admin"
```

+   对于 Windows PowerShell，请运行以下命令：

```
> $NODE_PORT = kubectl get --namespace chapter3 -o jsonpath="{.spec.ports[0].nodePort}" services wordpress | Out-String
> $NODE_IP = kubectl get nodes --namespace chapter3 -o jsonpath="{.items[0].status.addresses[0].address}" | Out-String
> echo "WordPress URL: http://$NODE_IP:$NODE_PORT/"
> echo "WordPress Admin URL: http://$NODE_IP:$NODE_PORT/admin"
```

根据一系列`kubectl`查询定义了两个环境变量后，结果的`echo`命令将显示访问 WordPress 的 URL。第一个 URL 是查看主页的 URL，访问者将通过该 URL 访问您的网站。第二个 URL 是到达管理控制台的 URL，网站管理员用于配置和管理站点内容。

将第一个 URL 粘贴到浏览器中，您应该会看到一个与此处显示的内容类似的页面：

![图 3.19 – WordPress 博客页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.19.jpg)

图 3.19 – WordPress 博客页面

本页的几个部分可能会让你感到熟悉。首先，请注意屏幕左上角的博客标题为**学习 Helm**！这不仅与本书的标题相似，而且也是您在安装过程中先前提供的`wordpressBlogName`值。您还可以在页面底部的版权声明中看到这个值，**© 2020 学习 Helm！**。

影响主页定制的另一个值是`wordpressUsername`。请注意，包括的**Hello world!**帖子的作者是**helm-user**。这是提供给`wordpressUsername`值的用户的名称，如果提供了替代用户名，它将显示不同。

在上一组命令中提供的另一个链接是管理控制台。将第二个`echo`命令中的链接粘贴到浏览器中，您将看到以下屏幕：

![图 3.20：WordPress 管理控制台登录页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.20.jpg)

图 3.20：WordPress 管理控制台登录页面

要登录到管理控制台，请输入安装过程中提供的`wordpressUsername`和`wordpressPassword`值。这些值可以通过查看本地的`wordpress-values.yaml`文件来查看。它们也可以通过运行 WordPress 图表注释中指定的以下命令来检索：

```
$ echo Username: helm-user
$ echo Password: $(kubectl get secret --namespace chapter3 wordpress -o jsonpath='{.data.wordpress-password}' | base64 --decode)
```

验证后，管理控制台仪表板将显示如下：

![图 3.21 – WordPress 管理控制台页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.21.jpg)

图 3.21 – WordPress 管理控制台页面

如果您负责管理这个 WordPress 网站，这就是您可以配置您的网站、撰写文章和管理插件的地方。如果您点击右上角的链接，上面写着**你好，helm-user**，您将被引导到`helm-user`个人资料页面。从那里，您可以看到安装过程中提供的其他值，如下所示：

![图 3.22 – WordPress 个人资料页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.22.jpg)

图 3.22 – WordPress 个人资料页面

**名字**、**姓氏**和**电子邮件**字段分别指代它们对应的`wordpressFirstname`、`wordpressLastname`和`wordpressEmail` Helm 值。

随时继续探索您的 WordPress 实例。完成后，继续下一节，了解如何对 Helm 版本执行升级。

# 升级 WordPress 版本

升级版本是指修改安装版本的值或升级到图表的新版本的过程。在本节中，我们将通过配置围绕 WordPress 副本和资源需求的附加值来升级 WordPress 版本。

## 修改 Helm 值

Helm 图表通常会公开值来配置应用程序的实例数量及其相关的资源集。以下截图展示了与此目的相关的`helm show values`命令的几个部分。

第一个值`replicaCount`设置起来很简单。由于`replica`是一个描述部署应用程序所需的 Pod 数量的 Kubernetes 术语，因此可以推断出`replicaCount`用于指定作为发布的一部分部署的应用程序实例的数量：

![图 3.23 - `helm show values`命令中的 replicaCount](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.23.png)

图 3.23 - `helm show values`命令中的`replicaCount`

将以下行添加到您的`wordpress-values.yaml`文件中，将副本数从`1`增加到`2`：

```
replicaCount: 2
```

我们需要定义的第二个值是`resources` YAML 部分下的一组值：

![图 3.24 - 资源部分的值](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.24.jpg)

图 3.24 - 资源部分的值

值可以缩进，就像`resources`部分一样，以提供逻辑分组。在`resources`部分下是一个`requests`部分，用于配置 Kubernetes 将分配给 WordPress 应用程序的`memory`和`cpu`值。让我们在升级过程中修改这些值，将内存请求减少到`256Mi`（256 mebibytes），将`cpu`请求减少到`100m`（100 millicores）。将这些修改添加到`wordpress-values.yaml`文件中，如下所示：

```
resources:
  requests:
    memory: 256Mi
    cpu: 100m
```

定义了这两个新值后，您的整个`wordpress-values.yaml`文件将如下所示：

```
wordpressUsername: helm-user
wordpressPassword: my-pass
wordpressEmail: helm-user@example.com
wordpressFirstName: Helm
wordpressLastName: User
wordpressBlogName: Learn Helm!
service:
  type: NodePort
replicaCount: 2
resources:
  requests:
    memory: 256Mi
    cpu: 100m
```

一旦`values`文件使用这些新值进行了更新，您可以运行`helm upgrade`命令来升级发布，我们将在下一节讨论。

## 运行升级

`helm upgrade`命令在基本语法上几乎与`helm install`相同，如下例所示：

```
helm upgrade [RELEASE] [CHART] [flags]
```

虽然`helm install`希望您为新发布提供一个名称，但`helm upgrade`希望您提供应该升级的已存在发布的名称。

在`values`文件中定义的值可以使用`--values`标志提供，与`helm install`命令相同。运行以下命令，使用一组新值升级 WordPress 发布：

```
$ helm upgrade wordpress bitnami/wordpress --values wordpress-values.yaml -n chapter3 --version 8.1.0
```

一旦执行命令，您应该看到类似于`helm install`的输出，如前面的部分所示：

![图 3.25 - `helm upgrade`的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.25.jpg)

图 3.25 - `helm upgrade`的输出

您还应该通过运行以下命令看到`wordpress` Pods 正在重新启动：

```
$ kubectl get pods -n chapter3
```

在 Kubernetes 中，当部署被修改时，会创建新的 Pod。在 Helm 中也可以观察到相同的行为。在升级过程中添加的值引入了 WordPress 部署的配置更改，并且创建了新的 WordPress Pods，因此使用更新后的配置。这些更改可以使用之前安装后使用的相同的`helm get` `manifest`和`kubectl get` `deployment`命令来观察。

在下一节中，我们将进行更多的升级操作，以演示值在升级过程中有时可能会有不同的行为。

## 在升级过程中重用和重置值

`helm upgrade`命令包括两个额外的标志，用于操作在`helm install`命令中不存在的值。

现在让我们来看看这些标志：

+   `--reuse-values`：在升级时重用上一个发布的值。

+   `--reset-values`：在升级时，将值重置为图表默认值。

如果在升级时没有使用`--set`或`--values`标志提供值，则默认添加`--reuse-values`标志。换句话说，如果没有提供值，升级期间将再次使用先前发布使用的相同值：

1.  再次运行`upgrade`命令，而不指定任何值：

```
$ helm upgrade wordpress bitnami/wordpress -n chapter3 --version 8.1.0
```

1.  运行`helm get values`命令来检查升级中使用的值：

```
$ helm get values wordpress -n chapter3
```

请注意，显示的值与先前的升级是相同的：

![图 3.26 - `helm get values`的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.26.jpg)

图 3.26 - `helm get values`的输出

当在升级过程中通过命令行提供值时，可以观察到不同的行为。如果通过`--set`或`--values`标志传递值，则所有未提供的图表值都将重置为默认值。

1.  通过使用`--set`提供单个值再次进行升级： 

```
$ helm upgrade wordpress bitnami/wordpress --set replicaCount=1 -n chapter3 --version 8.1.0
```

1.  升级后，运行`helm get values`命令：

```
$ helm get values wordpress -n chapter3
```

输出将声明，唯一由用户提供的值是`replicaCount`的值：

![图 3.27 - `replicaCount`的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.27.jpg)

图 3.27 - `replicaCount`的输出

在升级过程中，如果至少提供了一个值，Helm 会自动应用`--reset-values`标志。这会导致所有值都被设置回它们的默认值，除了使用`--set`或`--values`标志提供的单个属性。

用户可以手动提供`--reset-values`或`--reuse-values`标志，明确确定升级过程中值的行为。如果您希望下一次升级在从命令行覆盖值之前将每个值重置为默认值，请使用`--reset-values`标志。如果您希望在从命令行设置不同值的同时重用先前修订的每个值，请提供`--reuse-values`标志。为了简化升级过程中值的管理，请尝试将值保存在一个文件中，该文件可用于声明性地为每次升级设置值。

如果您一直在本章中使用提供的每个命令，现在应该有 WordPress 发布的四个修订版本。这第四个修订版本并不完全符合我们希望配置应用程序的方式，因为大多数值都被设置回默认值，只指定了`replicaCount`值。在下一节中，我们将探讨如何将 WordPress 发布回滚到包含所需值集的稳定版本。

# 回滚 WordPress 发布

尽管向前推进是首选，但有些情况下，回到应用程序的先前版本更有意义。`helm rollback`命令存在是为了满足这种情况。让我们将 WordPress 发布回滚到先前的状态。

## 检查 WordPress 历史

每个 Helm 发布都有一个**修订**历史。修订用于跟踪特定发布版本中使用的值、Kubernetes 资源和图表版本。当安装、升级或回滚图表时，将创建新的修订。修订数据默认保存在 Kubernetes 秘密中（其他选项是 ConfigMap 或本地内存，由`HELM_DRIVER`环境变量确定）。这允许不同用户在 Kubernetes 集群上管理和交互您的 Helm 发布，前提是他们具有允许他们查看或修改命名空间中的资源的**基于角色的访问控制**（**RBAC**）。

可以使用`kubectl`从`chapter3`命名空间获取秘密来观察修订秘密：

```
$ kubectl get secrets -n chapter3
```

这将返回所有的秘密，但您应该在输出中看到这四个：

```
sh.helm.release.v1.wordpress.v1
Sh.helm.release.v1.wordpress.v2
sh.helm.release.v1.wordpress.v3
sh.helm.release.v1.wordpress.v4
```

这些秘密中的每一个都对应于发布的修订历史的条目，可以通过运行`helm history`命令来查看：

```
$ helm history wordpress -n chapter3
```

此命令将显示每个修订的表格，类似于以下内容（为了可读性，某些列已被省略）：

```
REVISION  ...  STATUS     ...  DESCRIPTION
1              superseded      Install complete
2              superseded      Upgrade complete
3              superseded      Upgrade complete
4              deployed        Upgrade complete     
```

在此输出中，每个修订都有一个编号，以及更新时间、状态、图表、升级的应用程序版本和升级的描述。状态为`superseded`的修订已经升级。状态为`deployed`的修订是当前部署的修订。其他状态包括`pending`和`pending_upgrade`，表示安装或升级当前正在进行中。`failed`指的是特定修订未能安装或升级，`unknown`对应于具有未知状态的修订。你不太可能遇到状态为`unknown`的发布。

先前描述的`helm get`命令可以通过指定`--revision`标志针对修订号使用。对于此回滚，让我们确定具有完整所需值集的发布。您可能还记得，当前修订`修订 4`只包含`replicaCount`值，但`修订 3`应该包含所需的值。可以通过使用`--revision`标志运行`helm get values`命令来验证这一点：

```
$ helm get values wordpress --revision 3 -n chapter3
```

通过检查此修订，可以呈现完整的值列表：

![图 3.28 - 检查特定修订的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.28.jpg)

图 3.28 - 检查特定修订的输出

可以针对修订号运行其他`helm get`命令进行进一步检查。如果需要，还可以针对`修订 3`执行`helm get manifest`命令来检查将要恢复的 Kubernetes 资源的状态。

在下一节中，我们将执行回滚。

## 运行回滚

`helm rollback`命令具有以下语法：

```
helm rollback <RELEASE> [REVISION] [flags]
```

用户提供发布的名称和要回滚到的期望修订号，以将 Helm 发布回滚到以前的时间点。运行以下命令来执行将 WordPress 回滚到`修订 3`：

```
$ helm rollback wordpress 3 -n chapter3
```

`rollback`子命令提供了一个简单的输出，打印以下消息：

```
Rollback was a success! Happy Helming!
```

可以通过运行`helm` `history`命令在发布历史中观察到此回滚：

```
$ helm history wordpress -n chapter3
```

在发布历史中，您会注意到添加了第五个状态为`deployed`的修订版本，并且描述为`回滚到 3`。当应用程序回滚时，它会向发布历史中添加一个新的修订版本。这不应与升级混淆。最高的修订版本号仅表示当前部署的发布。请务必检查修订版本的描述，以确定它是由升级还是回滚创建的。

您可以通过再次运行`helm get values`来获取此发布的值，以确保回滚现在使用所需的值：

```
$ helm get values wordpress -n chapter3
```

输出将显示最新稳定发布的值：

![图 3.29 - 来自最新稳定发布的值](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.29.jpg)

图 3.29 - 来自最新稳定发布的值

您可能会注意到，在`rollback`子命令中，我们没有明确设置图表版本或发布的值。这是因为`rollback`子命令不是设计为接受这些输入；它是设计为将图表回滚到先前的修订版本并利用该修订版本的图表版本和值。请注意，`rollback`子命令不应成为日常 Helm 实践的一部分，它应该仅用于应急情况，其中应用程序的当前状态不稳定并且必须恢复到先前的稳定点。

如果成功回滚了 WordPress 发布，那么您即将完成本章的练习。最后一步是通过利用`uninstall`子命令从 Kubernetes 集群中删除 WordPress 应用程序，我们将在下一节中描述。

# 卸载 WordPress 发布

卸载 Helm 发布意味着删除它管理的 Kubernetes 资源。此外，`uninstall`命令还会删除发布的历史记录。虽然这通常是我们想要的，但指定`--keep-history`标志将指示 Helm 保留发布历史记录。

`uninstall`命令的语法非常简单：

```
helm uninstall RELEASE_NAME [...] [flags]
```

通过运行`helm uninstall`命令卸载 WordPress 发布：

```
$ helm uninstall wordpress -n chapter3
```

卸载后，您将看到以下消息：

```
release 'wordpress' uninstalled
```

您还会注意到`wordpress`发布现在不再存在于`chapter3`命名空间中：

```
$ helm list -n chapter3
```

输出将是一个空表。您还可以通过尝试使用`kubectl`来获取 WordPress 部署来确认该发布不再存在：

```
$ kubectl get deployments -l app=wordpress -n chapter3
No resources found in chapter3 namespace.
```

如预期的那样，不再有 WordPress 部署可用。

```
$ kubectl get pvc -n chapter3
```

但是，您会注意到在命名空间中仍然有一个`PersistentVolumeClaim`命令可用：

![图 3.30 - 显示 PersistentVolumeClaim 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_3.30.jpg)

图 3.30 - 显示`PersistentVolumeClaim`的输出

这个`PersistentVolumeClaim`资源没有被删除，因为它是由`StatefulSet`在后台创建的。在 Kubernetes 中，如果删除了`StatefulSet`，则由`StatefulSet`创建的`PersistentVolumeClaim`资源不会自动删除。在`helm uninstall`过程中，`StatefulSet`被删除，但相关的`PersistentVolumeClaim`没有被删除。这是我们所期望的。可以使用以下命令手动删除`PersistentVolumeClaim`资源：

```
$ kubectl delete pvc -l release=wordpress -n chapter3
```

现在我们已经安装并卸载了 WordPress，让我们清理一下您的 Kubernetes 环境，以便在本书后面的章节中进行练习时有一个干净的设置。

# 清理您的环境

要清理您的 Kubernetes 环境，可以通过运行以下命令删除本章的命名空间：

```
$ kubectl delete namespace chapter3
```

删除`chapter3`命名空间后，您还可以停止 Minikube 虚拟机：

```
$ minikube stop
```

这将关闭虚拟机，但将保留其状态，以便您可以在下一个练习中快速开始工作。

# 总结

在本章中，您学习了如何安装 Helm 图表并管理其生命周期。我们首先在 Helm Hub 上搜索要安装的 WordPress 图表。在找到图表后，按照其 Helm Hub 页面上的说明添加了包含该图表的存储库。然后，我们开始检查 WordPress 图表，以创建一组覆盖其默认值的数值。这些数值被保存到一个`values`文件中，然后在安装过程中提供。

图表安装后，我们使用`helm upgrade`通过提供额外的数值来升级发布。然后我们使用`helm rollback`进行回滚，将图表恢复到先前的状态。最后，在练习结束时使用`helm uninstall`删除了 WordPress 发布。

本章教会了您如何作为最终用户和图表消费者利用 Helm。您使用 Helm 作为包管理器将 Kubernetes 应用程序安装到集群中。您还通过执行升级和回滚来管理应用程序的生命周期。了解这个工作流程对于使用 Helm 管理安装是至关重要的。

在下一章中，我们将更详细地探讨 Helm 图表的概念和结构，以开始学习如何创建图表。

# 进一步阅读

要了解有关本地添加存储库、检查图表以及使用本章中使用的四个生命周期命令（`install`、`upgrade`、`rollback`和`uninstall`）的更多信息，请访问[`helm.sh/docs/intro/using_helm/`](https://helm.sh/docs/intro/using_helm/)。

# 问题

1.  Helm Hub 是什么？用户如何与其交互以查找图表和图表存储库？

1.  `helm get`和`helm show`命令集之间有什么区别？在何时使用其中一个命令集而不是另一个？

1.  `helm install`和`helm upgrade`命令中的`--set`和`--values`标志有什么区别？使用其中一个的好处是什么？

1.  哪个命令可用于提供发布的修订列表？

1.  升级发布时默认情况下会发生什么，如果不提供任何值？这种行为与提供升级值时有何不同？

1.  假设您有五个发布的修订版本。在将发布回滚到“修订版本 3”后，`helm history`命令会显示什么？

1.  假设您想查看部署到 Kubernetes 命名空间的所有发布。您应该运行什么命令？

1.  假设您运行`helm repo add`来添加一个图表存储库。您可以运行什么命令来列出该存储库下的所有图表？
