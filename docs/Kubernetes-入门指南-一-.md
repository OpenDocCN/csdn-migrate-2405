# Kubernetes 入门指南（一）

> 原文：[`zh.annas-archive.org/md5/1794743BB21D72736FFE64D66DCA9F0E`](https://zh.annas-archive.org/md5/1794743BB21D72736FFE64D66DCA9F0E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书是 Kubernetes 和整体容器管理入门指南。我们将为您介绍 Kubernetes 的特性和功能，并展示它如何融入整体运营策略。您将了解将容器从开发人员的笔记本移到更大规模时面临的障碍。您还将看到 Kubernetes 如何是帮助您自信面对这些挑战的完美工具。

# 本书内容

第一章，*Kubernetes 简介*，简要介绍容器和 Kubernetes 编排的如何、什么和为什么，探讨它如何影响您的业务目标和日常操作。

第二章，*Pods、服务、复制控制器和标签*，使用几个简单的示例来探索核心 Kubernetes 构造，即 Pod、服务、复制控制器、副本集和标签。还将涵盖基本操作，包括健康检查和调度。

第三章，*网络、负载均衡器和入口*，涵盖了 Kubernetes 的集群网络和 Kubernetes 代理。它还深入探讨了服务，最后，它展示了一些更高级别的隔离特性的简要概述，用于多租户。

第四章，*更新、渐进式部署和自动缩放*，快速了解如何在最小化停机时间的情况下推出更新和新功能。我们还将研究应用程序和 Kubernetes 集群的扩展。

第五章，*部署、任务和 DaemonSets*，涵盖了长时间运行的应用程序部署以及短期任务。我们还将研究使用 DaemonSets 在集群中的所有或子集节点上运行容器。

第六章，*存储和运行有状态的应用程序*，涵盖了跨 Pod 和容器生命周期的存储问题和持久数据。我们还将研究在 Kubernetes 中使用有状态应用程序的新构建。

第七章，*持续交付*，解释了如何将 Kubernetes 集成到您的持续交付流水线中。我们将看到如何使用 Gulp.js 和 Jenkins 来使用 k8s 集群。

第八章，*监控与日志*，教你如何在你的 Kubernetes 集群上使用和定制内置和第三方监控工具。我们将研究内置日志记录和监控、Google Cloud 监控/日志服务以及 Sysdig。

第九章，*集群联邦*，使您能够尝试新的联邦功能，并解释如何使用它们来管理跨云提供商的多个集群。我们还将涵盖前几章中核心构造的联邦版本。

第十章，*容器安全*，从容器运行时层级到主机本身，教授容器安全的基础知识。它还解释了如何将这些概念应用于运行容器，以及与运行 Kubernetes 相关的一些安全问题和做法。

第十一章，*使用 OCP、CoreOS 和 Tectonic 扩展 Kubernetes*，探讨了开放标准如何使整个容器生态系统受益。我们将介绍一些知名的标准组织，并涵盖 CoreOS 和 Tectonic，探讨它们作为主机操作系统和企业平台的优势。

第十二章，*走向生产就绪*，最后一章，展示了一些有用的工具和第三方项目，以及您可以获取更多帮助的地方。

# 本书所需内容

本书将涵盖下载和运行 Kubernetes 项目。您需要访问 Linux 系统（如果您使用 Windows，VirtualBox 也可行），并对命令行有一定了解。

此外，您应该有一个 Google Cloud Platform 账户。您可以在此处注册免费试用：

[`cloud.google.com/`](https://cloud.google.com/)

此外，本书的一些部分需要有 AWS 账户。您可以在此处注册免费试用：

[`aws.amazon.com/`](https://aws.amazon.com/)

# 本书适合谁

无论您是深入开发、深入运维，还是作为执行人员展望未来，Kubernetes 和本书都适合您。*开始使用 Kubernetes* 将帮助您了解如何将容器应用程序移入生产环境，并与现实世界的操作策略相结合的最佳实践和逐步演练。您将了解 Kubernetes 如何融入您的日常操作中，这可以帮助您为生产就绪的容器应用程序堆栈做好准备。

对 Docker 容器、一般软件开发和高级操作有一定了解会很有帮助。

# 惯例

在本书中，您将找到许多文本样式，用以区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、文件夹名称、文件名、文件扩展名和路径名如下所示："执行一个简单的`curl`命令到 pod IP。"

URL 如下所示：

[`swagger.io/`](http://swagger.io/)

如果我们希望您用自己的值替换 URL 的一部分，则会显示如下：

`https://**<你的主机 IP>**/swagger-ui/`

资源定义文件和其他代码块设置如下：

```
apiVersion: v1
kind: Pod
metadata:
  name: node-js-pod
spec:
  containers:
  - name: node-js-pod
    image: bitnami/apache:latest
    ports:
    - containerPort: 80

```

当我们希望您用自己的值替换列表的一部分时，相关行或项目将以小于和大于符号之间的粗体设置：

```
subsets:
- addresses:
  - IP: <X.X.X.X>
  ports:
    - name: http
      port: 80
      protocol: TCP

```

任何命令行输入或输出都以如下形式编写：

```
$ kubectl get pods

```

新术语和重要单词以**粗体**显示。屏幕上看到的单词，例如在菜单或对话框中，会出现在文本中，如：“单击添加新按钮会将您移至下一个屏幕。”

文本中有几个地方涉及到键值对或屏幕上的输入对话框。在这些情况下，**键**或**输入标签**将以粗体显示，而***值***将以粗体斜体显示。例如：“在标有**超时**的框中输入***5s***。”

警告或重要注释会以此类框的形式显示。

提示和技巧以此类形式显示。

# 读者反馈

我们非常欢迎读者的反馈。让我们知道您对这本书的看法-您喜欢或不喜欢的内容。读者的反馈对我们非常重要，因为它有助于我们开发出真正能让您受益的标题。

要发送给我们一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在消息主题中提及书名。

如果有您擅长并且有兴趣撰写或贡献书籍的主题，请参阅我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 图书的骄傲拥有者，我们有很多东西可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，注册后文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的 SUPPORT 选项卡上。

1.  单击“代码下载与勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地方。

1.  单击“下载代码”。

下载文件后，请确保使用最新版本的以下操作解压或提取文件夹：

+   WinRAR / 7-Zip 适用于 Windows

+   Zipeg / iZip / UnRarX 适用于 Mac

+   7-Zip / PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Getting-Started-with-Kubernetes-Second-Edition`](https://github.com/PacktPublishing/Getting-Started-with-Kubernetes-Second-Edition)。我们还提供了来自丰富图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。快去看看吧！

# 下载本书的彩色图像

我们还向您提供了一份 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。彩色图像将帮助您更好地理解输出中的变化。您可以从以下位置下载此文件：

[`www.packtpub.com/sites/default/files/downloads/GettingStartedwithKubernetesSecondEdition_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/GettingStartedwithKubernetesSecondEdition_ColorImages.pdf).

# 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误确实会发生。如果您发现我们书籍中的错误 - 也许是文本或代码中的错误 - 如果您能向我们报告此错误，我们将不胜感激。通过这样做，您可以帮助其他读者免受挫折，帮助我们改进此书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告它们，选择您的书籍，点击勘误提交表单链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，勘误将被上传到我们的网站或添加到该书标题的勘误部分的任何现有勘误列表中。

要查看以前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索栏中输入书名。相关信息将显示在勘误部分下面。

# 盗版

互联网上盗版版权材料是所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何形式的非法复制，请立即向我们提供位置地址或网站名称，以便我们可以采取补救措施。

请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您帮助我们保护我们的作者以及我们为您提供有价值内容的能力。

# 问题

如果您对本书的任何方面有问题，请通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。


# 第一章：Kubernetes 简介

在本书中，我们将帮助您学习构建和管理 Kubernetes 集群。我们将尽可能地介绍一些基本的容器概念和操作上下文。在整本书中，您将得到一些您可以在学习过程中应用的示例。到本书结束时，您应该具有坚实的基础，甚至可以涉足一些更高级的主题，如联邦和安全性。

本章将简要概述容器及其工作原理，以及为何管理和编排对您的业务和/或项目团队至关重要。本章还将简要介绍 Kubernetes 编排如何增强我们的容器管理策略以及如何启动、运行和准备容器部署的基本 Kubernetes 集群。

本章将包括以下主题：

+   介绍容器的操作和管理

+   为什么容器管理很重要？

+   Kubernetes 的优势

+   下载最新的 Kubernetes

+   安装和启动一个新的 Kubernetes 集群

+   Kubernetes 集群的组件

# 容器的简要概述

在过去的三年里，**容器**像野火般风靡。你很难参加一个 IT 会议而不找到关于 Docker 或容器的热门议题。

Docker 是大规模采用和容器领域的激情的核心。正如 Malcom McLean 在 1950 年代通过创建标准化的运输集装箱彻底改变了物理运输世界一样，Linux 容器正在通过使应用程序环境在基础设施景观中可移植和一致来改变软件开发世界。作为一个组织，Docker 将现有的容器技术提升到一个新的水平，使其易于在各种环境和提供者中实施和复制。

# 什么是容器？

容器技术的核心是**控制组**（**cgroups**）和命名空间。此外，Docker 使用联合文件系统来增强容器开发过程的优势。

Cgroups 的工作原理是允许主机共享并限制每个进程或容器可以消耗的资源。这对资源利用和安全都很重要，因为它可以防止对主机硬件资源的**拒绝服务攻击**。多个容器可以共享 CPU 和内存，同时保持在预定义约束内。

**命名空间**为操作系统内的进程交互提供了另一种隔离形式。命名空间限制了一个进程对其他进程、网络、文件系统和用户 ID 组件的可见性。容器进程只能看到相同命名空间中的内容。来自容器或主机的进程无法直接从容器进程内部访问。此外，Docker 为每个容器提供了自己的网络堆栈，以类似的方式保护套接字和接口。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_01.png)

容器的组成

**联合文件系统**也是使用 Docker 容器的一个关键优势。容器是从镜像运行的。与虚拟机或云世界中的镜像类似，它代表了特定时间点的状态。容器镜像快照文件系统，但通常比虚拟机小得多。容器共享主机内核，并且通常运行一组更小的进程，因此文件系统和引导期间 tend to be much smaller。尽管这些约束条件并不严格执行。其次，联合文件系统允许高效存储、下载和执行这些镜像。

理解联合文件系统最简单的方法是将其想象成一个独立烘焙的层层蛋糕。Linux 内核是我们的基础层；然后，我们可能会添加一个操作系统，如**红帽 Linux**或**Ubuntu**。接下来，我们可能会添加一个应用程序，如**Nginx**或**Apache**。每个更改都会创建一个新层。最后，随着您进行更改并添加新层，您始终会有一个顶层（考虑一下糖霜），它是一个可写的层。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_02.png)

分层文件系统

使这真正高效的是 Docker 在第一次构建时缓存了这些层。所以，假设我们有一个包含 Ubuntu 的镜像，然后添加 Apache 并构建镜像。接下来，我们使用 Ubuntu 作为基础构建 MySQL。第二次构建将会更快，因为 Ubuntu 层已经被缓存了。本质上，我们的巧克力和香草层，来自前面的*分层文件系统*图，已经烘焙完成。我们只需要烘焙开心果（MySQL）层，组装并添加糖衣（可写层）。

# 为什么容器如此酷？

单独的容器并不是一种新技术，事实上它们已经存在多年了。真正使 Docker 脱颖而出的是他们为社区带来的工具和易用性。现代开发实践推广了持续集成和持续部署的使用。当这些技术正确使用时，可以对您的软件产品质量产生深远的影响。

# 持续集成/持续部署的优势

ThoughtWorks 将**持续集成**定义为一种开发实践，要求开发人员每天将代码集成到一个共享的代码库中多次。通过持续构建和部署代码的过程，组织能够将质量控制和测试作为日常工作周期的一部分。结果是更新和错误修复发生得更快，整体质量得到提高。

然而，一直以来在创建与测试和生产环境匹配的开发环境方面存在挑战。通常，这些环境中的不一致性使得很难充分利用持续交付的全部优势。

使用 Docker，开发人员现在能够拥有真正可移植的部署。在开发人员的笔记本电脑上部署的容器很容易部署到内部的暂存服务器上。然后，它们很容易转移到在云中运行的生产服务器上。这是因为 Docker 使用构建文件来构建容器，这些构建文件指定了父层。这样做的一个优点是，可以非常轻松地确保在开发、暂存和生产环境中操作系统、软件包和应用程序版本相同。

因为所有的依赖关系都打包到了层中，所以同一个主机服务器可以运行多个容器，运行各种操作系统或软件包版本。此外，我们可以在同一台主机服务器上使用各种语言和框架，而不会像在带有单个操作系统的**虚拟机**（**VM**）中那样出现典型的依赖冲突。

# 资源利用

明确定义的隔离和分层文件系统也使得容器非常适合运行具有非常小的占地面积和特定领域用途的系统。简化的部署和发布流程意味着我们可以快速而频繁地部署。因此，许多公司将他们的部署时间从几周甚至几个月缩短到了几天甚至几小时。这种开发生命周期非常适合于小型、有针对性的团队致力于一个更大的应用程序的小块。

# 微服务与编排

当我们将一个应用程序分解为非常具体的领域时，我们需要一种统一的方式在所有不同的部分和领域之间进行通信。多年来，Web 服务一直在发挥这种作用，但容器带来的额外隔离和粒度聚焦为**微服务**铺平了道路。

对于微服务的定义可能有点模糊，但是马丁·福勒（Martin Fowler）提出了一个定义，他是一位备受尊敬的软件开发作家和演讲者（你可以在本章末尾的*参考资料*中参考更多详细信息）：

简而言之，微服务架构风格是将单个应用程序开发为一套小服务的方法，每个服务在自己的进程中运行，并使用轻量级机制进行通信，通常是 HTTP 资源 API。这些服务围绕业务功能构建，并通过完全自动化的部署机制独立部署。这些服务的集中管理是最小的，它们可以使用不同的编程语言编写，并使用不同的数据存储技术。

随着组织转向容器化，并且微服务在组织中发展，他们很快就会需要一种策略来维护许多容器和微服务。未来几年，一些组织将拥有数百甚至数千个正在运行的容器。

# 未来的挑战

生命周期进程本身就是运营和管理的重要组成部分。当容器失败时，我们如何自动恢复？哪些上游服务受到这种中断的影响？我们如何在最小停机时间内打补丁我们的应用？随着流量增长，我们如何扩展容器和服务的规模？

网络和处理也是重要的考虑因素。有些进程是同一服务的一部分，可能会受益于靠近网络。例如，数据库可能会向特定的微服务发送大量数据进行处理。我们如何在集群中将容器放置在彼此附近？是否有需要访问的共同数据？如何发现新服务并使其对其他系统可用？

资源利用率也是关键。容器的小占用空间意味着我们可以优化基础架构以实现更大的利用率。扩展弹性云中开始的节省将使我们更进一步地减少浪费的硬件。我们如何最有效地安排工作负载？如何确保我们的重要应用程序始终具有正确的资源？我们如何在备用容量上运行不太重要的工作负载？

最后，可移植性是许多组织转向容器化的关键因素。Docker 使在各种操作系统、云提供商和本地硬件甚至开发人员笔记本电脑上部署标准容器变得非常容易。然而，我们仍然需要工具来移动容器。我们如何在集群的不同节点之间移动容器？我们如何以最小的中断滚动更新？我们使用什么流程执行蓝绿部署或金丝雀发布？ 

无论您是开始构建单个微服务并将关注点分离到隔离的容器中，还是只是想充分利用应用程序开发中的可移植性和不变性，对管理和编排的需求变得明确起来。这就是编排工具如 Kubernetes 提供最大价值的地方。

# Kubernetes 的诞生

**Kubernetes**（**K8s**）是谷歌于 2014 年 6 月发布的一个开源项目。谷歌发布该项目是为了与社区分享他们自己的基础设施和技术优势。

Google 每周在他们的基础设施中启动 20 亿个容器，并已经使用容器技术超过十年。最初，他们正在构建一个名为**Borg**，现在称为**Omega**的系统，用于在扩展中的数据中心中调度大量工作负载。多年来，他们吸取了许多经验教训，并重写了他们现有的数据中心管理工具，以便广泛被世界其他地方采纳。其结果便是开源项目 Kubernetes（您可以在本章末尾的*参考资料*部分中的第 3 点中了解更多详情）。

自 2014 年首次发布以来，K8s 在开源社区的贡献下经历了快速发展，包括 Red Hat、VMware 和 Canonical 等。Kubernetes 的 1.0 版本于 2015 年 7 月正式发布。从那时起，该项目得到了开源社区的广泛支持，目前是 GitHub 上最大的开源社区之一。我们将在整本书中涵盖版本 1.5。K8s 提供了一个工具，用于解决一些主要操作和管理问题。我们将探讨 Kubernetes 如何帮助处理资源利用、高可用性、更新、打补丁、网络、服务发现、监控和日志记录等问题。

# 我们的第一个集群

Kubernetes 支持各种平台和操作系统。在本书的示例中，我在客户端使用 Ubuntu 16.04 Linux VirtualBox，而在集群本身则使用 Debian 的**Google Compute Engine**（**GCE**）。我们还将简要介绍在使用 Ubuntu 的**Amazon Web Services**（**AWS**）上运行的集群。

为节省一些资金，GCP 和 AWS 都为他们的云基础设施提供了免费层和试用优惠。如果可能的话，值得使用这些免费试用来学习 Kubernetes。

本书中的大部分概念和示例应该适用于任何 Kubernetes 集群的安装。要获取有关其他平台设置的更多信息，请参考以下 GitHub 链接中的 Kubernetes 入门页面：

[`kubernetes.io/docs/getting-started-guides/`](http://kubernetes.io/docs/getting-started-guides/)

首先，在安装 Kubernetes 之前，让我们确保我们的环境已经正确设置。从更新软件包开始：

```
$ sudo apt-get update

```

如果没有安装 Python 和 curl，请先安装：

```
$ sudo apt-get install python
$ sudo apt-get install curl

```

安装**gcloud** SDK：

```
$ curl https://sdk.cloud.google.com | bash

```

在`gcloud`出现在我们的路径之前，我们需要启动一个新的 shell。

配置您的**Google Cloud Platform**（**GCP**）帐户信息。这应该会自动打开一个浏览器，我们可以从中登录到我们的 Google Cloud 帐户并授权 SDK：

```
$ gcloud auth login

```

如果您登录遇到问题或想要使用其他浏览器，可以选择使用`--no-launch-browser`命令。将 URL 复制并粘贴到您选择的计算机和/或浏览器上。使用您的 Google Cloud 凭据登录，并在权限页面上单击**允许**。最后，您应该收到一个授权码，可以将其复制并粘贴回等待提示的 shell 中。

默认项目应该已设置，但我们可以通过以下命令进行验证：

```
$ gcloud config list project

```

我们可以使用以下命令修改并设置新的默认项目。确保使用**项目 ID**而不是**项目名称**，如下所示：

```
$ gcloud config set project <PROJECT ID>

```

我们可以在以下 URL 中的控制台中找到我们的项目 ID：

[`console.developers.google.com/project`](https://console.developers.google.com/project) 或者，我们可以列出活动项目：

`$ gcloud alpha projects list`

现在我们已经设置好了环境，安装最新的 Kubernetes 版本只需一步，如下所示：

```
$ curl -sS https://get.k8s.io | bash

```

根据您的连接速度下载 Kubernetes 可能需要一两分钟的时间。较早的版本会自动调用`kube-up.sh`脚本并开始构建我们的集群。在版本 1.5 中，我们需要自己调用`kube-up.sh`脚本来启动集群。默认情况下，它将使用 Google Cloud 和 GCE：

```
$ kubernetes/cluster/kube-up.sh

```

在运行`kube-up.sh`脚本后，我们将看到许多行通过。让我们逐个部分查看它们：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_03.png)

GCE 先决条件检查

如果您的`gcloud`组件不是最新版本，则可能会提示您更新它们。

前面的图像*GCE 先决条件检查*显示了先决条件的检查，以及确保所有组件都是最新版本的情况。这是针对每个提供程序的。在 GCE 的情况下，它将验证 SDK 是否已安装以及所有组件是否是最新版本。如果不是，则会在此时看到提示进行安装或更新：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_04.png)

上传集群软件包

现在脚本正在启动集群。同样，这是针对提供程序的。对于 GCE，它首先检查 SDK 是否配置为默认的**项目**和**区域**。如果设置了，您将在输出中看到它们。

接下来，它将服务器二进制文件上传到 Google Cloud 存储中，如在创建 gs:... 行中所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_05.png)

Master 创建

然后，它会检查是否已经运行了集群的任何部分。然后，我们最终开始创建集群。在上述图中的输出中 *Master 创建* 中，我们看到它创建了**主**服务器、IP 地址以及集群的适当防火墙配置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_06.png)

Minion 创建

最后，它创建了我们集群的**minions**或**nodes**。这是我们的容器工作负载实际运行的地方。它将不断循环并等待所有 minions 启动。默认情况下，集群将有四个节点（minions），但 K8s 支持超过 1000 个（很快会更多）。我们将在书中稍后回来扩展节点。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_07.png)

集群完成

现在一切都创建好了，集群已初始化并启动。假设一切顺利，我们将获得主服务器的 IP 地址。此外，请注意，配置以及集群管理凭据都存储在`home/<用户名>/.kube/config`中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_08.png)

集群验证

然后，脚本将验证集群。此时，我们不再运行特定于提供程序的代码。验证脚本将通过`kubectl.sh`脚本查询集群。这是管理我们集群的中央脚本。在这种情况下，它检查找到的、注册的和处于就绪状态的 minion 数量。它循环执行，给集群最多 10 分钟的时间完成初始化。

成功启动后，在屏幕上打印出 minion 的摘要和集群组件的健康状况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_09.png)

集群摘要

最后，运行`kubectl cluster-info`命令，该命令会输出主服务的 URL，包括 DNS、UI 和监视。让我们来看看其中一些组件。

# Kubernetes UI

在浏览器中打开并运行以下代码：

`https://<你的主服务器 IP>/ui/`

默认情况下，证书是自签名的，因此您需要忽略浏览器中的警告，然后继续。之后，我们将看到一个登录对话框。这是我们在 K8s 安装期间列出的凭据的使用位置。我们可以随时通过简单地使用`config`命令来查找它们：

```
$ kubectl config view

```

现在我们有了登录凭据，请使用它们，我们应该会看到一个类似以下图像的仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_10.png)

Kubernetes UI 仪表板

主仪表板首先将我们带到一个显示不多的页面。有一个链接可以部署一个容器化应用程序，这将带您到一个用于部署的 GUI。这个 GUI 可以是一个非常简单的方式开始部署应用程序，而不必担心 Kubernetes 的 YAML 语法。然而，随着您对容器的使用逐渐成熟，最好使用检入源代码控制的 YAML 定义。

如果您点击左侧菜单中的**Nodes**链接，您将看到有关当前集群节点的一些指标：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_11.png)

Kubernetes 节点仪表板

在顶部，我们看到 CPU 和内存使用情况的汇总，然后是我们集群节点的列表。单击其中一个节点将带我们到一个页面，显示有关该节点、其健康状况和各种指标的详细信息。

随着我们开始启动真实应用程序并向集群添加配置，Kubernetes UI 将具有许多其他视图，这些视图将变得更加有用。

# Grafana

默认安装的另一个服务是**Grafana**。这个工具将为我们提供一个仪表板，用于查看集群节点上的指标。我们可以使用以下语法在浏览器中访问它：`https://<your master ip>/api/v1/proxy/namespaces/kube-system/services/monitoring-grafana`

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_12.png)

Kubernetes Grafana 仪表板

从主页，点击首页下拉菜单并选择 Cluster。在这里，Kubernetes 实际上正在运行许多服务。**Heapster** 用于收集**pods**和**nodes**上的资源使用情况，并将信息存储在**InfluxDB**中。结果，如 CPU 和内存使用情况，是我们在 Grafana UI 中看到的。我们将在第八章，*监控和日志记录*中深入探讨此问题。

# 命令行

`kubectl`脚本有命令来探索我们的集群以及在其中运行的工作负载。您可以在`/kubernetes/client/bin`文件夹中找到它。我们将在整本书中使用此命令，因此让我们花一点时间设置我们的环境。我们可以通过以下方式将二进制文件夹放在我们的`PATH`中来执行此操作：

```
$ export PATH=$PATH:/<Path where you downloaded K8s>/kubernetes/client/bin
$ chmod +x /<Path where you downloaded K8s>/kubernetes/client/bin

```

您可以选择将`kubernetes`文件夹下载到主目录之外，因此根据需要修改上述命令。

通过将`export`命令添加到您主目录中的`.bashrc`文件的末尾，也是一个不错的主意。

现在我们的路径上有了`kubectl`，我们可以开始使用它了。它有相当多的命令。由于我们尚未启动任何应用程序，因此这些命令中的大多数将不会很有趣。但是，我们可以立即使用两个命令进行探索。

首先，我们已经在初始化期间看到了`cluster-info`命令，但是我们随时可以使用以下命令再次运行它：

```
$ kubectl cluster-info

```

另一个有用的命令是`get`。它可用于查看当前正在运行的**服务**、**pods**、**副本控制器**等等。以下是立即使用的三个示例：

+   列出我们集群中的节点：

```
    $ kubectl get nodes

```

+   列出集群事件：

```
    $ kubectl get events

```

+   最后，我们可以查看集群中运行的任何服务，如下所示：

```
    $ kubectl get services

```

起初，我们只会看到一个名为`kubernetes`的服务。此服务是集群的核心 API 服务器。

# 运行在主节点上的服务

让我们进一步了解我们的新集群及其核心服务。默认情况下，机器以`kubernetes-`前缀命名。我们可以在启动集群之前使用`$KUBE_GCE_INSTANCE_PREFIX`修改这个前缀。对于我们刚刚启动的集群，主节点应该被命名为`kubernetes-master`。我们可以使用`gcloud`命令行实用程序 SSH 进入机器。以下命令将启动与主节点的 SSH 会话。确保替换您的项目 ID 和区域以匹配您的环境。还要注意，您可以使用以下语法从 Google Cloud 控制台启动 SSH：

```
$ gcloud compute ssh --zone "<your gce zone>" "kubernetes-master"

```

如果您在使用 Google Cloud CLI 时遇到 SSH 问题，您可以使用内置的 SSH 客户端的控制台。只需转到 VM 实例页面，您将在 kubernetes-master 列表中的一列中看到一个 SSH 选项。或者，VM 实例详细信息页面顶部有 SSH 选项。

一旦我们登录，我们应该会得到一个标准的 shell 提示符。让我们运行过滤 `Image` 和 `Status` 的 `docker` 命令：

```
$ sudo docker ps --format 'table {{.Image}}t{{.Status}}' 

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_13.png)

主容器列表

尽管我们尚未在 Kubernetes 上部署任何应用程序，但我们注意到已经有几个容器正在运行。以下是对每个容器的简要描述：

+   `fluentd-gcp`：这个容器收集并发送集群日志文件到 Google Cloud Logging 服务。

+   `node-problem-detector`：这个容器是一个守护程序，在每个节点上运行，并当前在硬件和内核层检测问题。

+   `rescheduler`：这是另一个附加容器，确保关键组件始终运行。在资源可用性低的情况下，它甚至可能删除较不重要的 pod 以腾出空间。

+   `glbc`：这是另一个 Kubernetes 附加容器，使用新的 *Ingress* 功能提供 Google Cloud 第 7 层负载均衡。

+   `kube-addon-manager`：这个组件是通过各种附加组件扩展 Kubernetes 的核心。它还定期应用对 `/etc/kubernetes/addons` 目录的任何更改。

+   `etcd-empty-dir-cleanup`：一个用于清理 etcd 中空键的实用程序。

+   `kube-controller-manager`：这是一个控制器管理器，控制各种集群功能，确保准确和最新的复制是其重要角色之一。此外，它监视、管理和发现新节点。最后，它管理和更新服务端点。

+   `kube-apiserver`：这个容器运行 API 服务器。正如我们在 Swagger 界面中探索的那样，这个 RESTful API 允许我们创建、查询、更新和删除 Kubernetes 集群的各种组件。

+   `kube-scheduler`：这个调度程序将未调度的 pod 绑定到节点，基于当前的调度算法。

+   `etcd`：这个容器运行由 CoreOS 构建的 **etcd** 软件，它是一个分布式和一致的键值存储。这是 Kubernetes 集群状态被存储、更新和检索的地方，被 K8s 的各种组件使用。

+   `pause`：这个容器通常被称为 pod 基础设施容器，用于设置和保存每个 pod 的网络命名空间和资源限制。

我省略了许多名称的 amd64，以使其更通用。pod 的目的保持不变。

要退出 SSH 会话，只需在提示符处键入 `exit`。

在下一章中，我们还将展示一些这些服务如何在第一张图片中共同工作，*Kubernetes 核心架构*。

# 服务运行在 minions 上

我们可以 SSH 到其中一个 minion，但由于 Kubernetes 在整个集群上调度工作负载，因此我们不会在单个 minion 上看到所有容器。但是，我们可以使用 `kubectl` 命令查看所有 minion 上运行的 Pod：

```
$ kubectl get pods

```

由于我们尚未在集群上启动任何应用程序，因此我们看不到任何 Pod。但实际上，有几个系统 Pod 运行着 Kubernetes 基础架构的各个部分。我们可以通过指定 `kube-system` 命名空间来查看这些 Pod。稍后我们将探讨命名空间及其重要性，但目前可以使用 `--namespace=kube-system` 命令来查看这些 K8s 系统资源，如下所示：

```
$ kubectl get pods --namespace=kube-system

```

我们应该看到类似以下的内容：

```
etcd-empty-dir-cleanup-kubernetes-master 
etcd-server-events-kubernetes-master 
etcd-server-kubernetes-master 
fluentd-cloud-logging-kubernetes-master 
fluentd-cloud-logging-kubernetes-minion-group-xxxx
heapster-v1.2.0-xxxx 
kube-addon-manager-kubernetes-master 
kube-apiserver-kubernetes-master 
kube-controller-manager-kubernetes-master 
kube-dns-xxxx 
kube-dns-autoscaler-xxxx 
kube-proxy-kubernetes-minion-group-xxxx 
kube-scheduler-kubernetes-master 
kubernetes-dashboard-xxxx 
l7-default-backend-xxxx 
l7-lb-controller-v0.8.0-kubernetes-master 
monitoring-influxdb-grafana-xxxx 
node-problem-detector-v0.1-xxxx 
rescheduler-v0.2.1-kubernetes-master

```

前六行应该看起来很熟悉。其中一些是我们看到在主节点上运行的服务，而在节点上也会看到其中的部分。还有一些其他服务我们还没有看到。`kube-dns` 选项提供了 DNS 和服务发现的基本结构，`kubernetes-dashboard-xxxx` 是 Kubernetes 的用户界面，`l7-default-backend-xxxx` 提供了新的第 7 层负载均衡功能的默认负载均衡后端，`heapster-v1.2.0-xxxx` 和 `monitoring-influx-grafana` 提供了 **Heapster** 数据库和用于监视集群资源使用情况的用户界面。最后，`kube-proxy-kubernetes-minion-group-xxxx` 是将流量定向到集群上正确后备服务和 Pod 的代理。

如果我们 SSH 到一个随机的 minion，我们会看到几个容器跨越其中一些 Pod 运行。示例可能看起来像这样的图片：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_14.png)

Minion 容器列表

同样，我们在主节点上看到了类似的服务排列。我们在主节点上没有看到的服务包括以下内容：

+   `kubedns`：此容器监视 Kubernetes 中的服务和端点资源，并同步 DNS 查询的任何更改。

+   `kube-dnsmasq`：这是另一个提供 DNS 缓存的容器。

+   `dnsmasq-metrics`：这为集群中的 DNS 服务提供度量报告。

+   `l7-defaultbackend`：这是用于处理 GCE L7 负载均衡器和 *Ingress* 的默认后端。

+   `kube-proxy`：这是集群的网络和服务代理。此组件确保服务流量被定向到集群上运行工作负载的位置。我们将在本书后面更深入地探讨这一点。

+   `heapster`：此容器用于监视和分析。

+   `addon-resizer`：这个集群实用工具用于调整容器的规模。

+   `heapster_grafana`：此操作用于资源使用情况和监控。

+   `heapster_influxdb`：这个时序数据库用于 Heapster 数据。

+   `cluster-proportional-autoscaler`：这个集群实用工具用于根据集群大小按比例调整容器的规模。

+   `exechealthz`：此操作对 Pod 执行健康检查。

再次，我省略了许多名称中的 amd64，以使其更通用。Pod 的用途保持不变。

# 拆除集群

好的，这是我们在 GCE 上的第一个集群，但让我们探索一些其他提供商。为了保持简单，我们需要删除我们刚刚在 GCE 上创建的那个。我们可以用一个简单的命令拆除集群：

```
$ kube-down.sh

```

# 与其他提供商合作

默认情况下，Kubernetes 使用 GCE 提供商进行 Google Cloud。我们可以通过设置`KUBERNETES_PROVIDER`环境变量来覆盖此默认值。此表中列出的值支持以下提供商：

| **提供商** | **KUBERNETES_PROVIDER 值** | **类型** |
| --- | --- | --- |
| **谷歌计算引擎** | `gce` | 公有云 |
| **谷歌容器引擎** | `gke` | 公有云 |
| **亚马逊网络服务** | `aws` | 公有云 |
| **微软 Azure** | `azure` | 公有云 |
| **Hashicorp Vagrant** | `vagrant` | 虚拟开发环境 |
| **VMware vSphere** | `vsphere` | 私有云/本地虚拟化 |
| **运行 CoreOS 的 Libvirt** | `libvirt-coreos` | 虚拟化管理工具 |
| **Canonical Juju（Ubuntu 背后的人）** | `juju` | 操作系统服务编排工具 |

Kubernetes 提供商

让我们尝试在 AWS 上设置集群。作为先决条件，我们需要安装并为我们的帐户配置 AWS **命令行界面**（**CLI**）。AWS CLI 的安装和配置文档可以在以下链接找到：

+   安装文档：[`docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os`](http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os)

+   配置文档：[`docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html`](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)

然后，这是一个简单的环境变量设置，如下所示：

```
$ export KUBERNETES_PROVIDER=aws

```

再次，我们可以使用`kube-up.sh`命令来启动集群，如下所示：

```
$ kube-up.sh

```

与 GCE 一样，设置活动将需要几分钟。它将在我们的 AWS 帐户中的**S3**中分阶段文件，并创建适当的实例、**虚拟专用云**（**VPC**）、安全组等等。然后，将设置并启动 Kubernetes 集群。一旦一切都完成并启动，我们应该在输出的末尾看到集群验证：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_15.png)

AWS 集群验证

请注意，集群启动的区域由`KUBE_AWS_ZONE`环境变量确定。默认情况下，此值设置为`us-west-2a`（该区域是从此可用区派生的）。即使您在 AWS CLI 中设置了区域，它也将使用`KUBE_AWS_ZONE`中定义的区域。

再次，我们将 SSH 进入 master。这次，我们可以使用本机 SSH 客户端。我们会在`/home/<username>/.ssh`中找到密钥文件：

```
$ ssh -v -i /home/<username>/.ssh/kube_aws_rsa ubuntu@<Your master IP>

```

我们将使用`sudo docker ps --format 'table {{.Image}}t{{.Status}}'`来探索正在运行的容器。我们应该看到类似下面的东西：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_16.png)

Master 容器列表（AWS）

我们看到与我们的 GCE 集群相同的一些容器。但也有一些缺失的。我们看到了核心 Kubernetes 组件，但缺少了 `fluentd-gcp` 服务以及一些新的实用程序，如 `node-problem-detector` 、`rescheduler` 、`glbc` 、`kube-addon-manager` 和 `etcd-empty-dir-cleanup`。这反映了各个公共云提供商之间在 `kube-up` 脚本中的一些微妙差异。这最终由庞大的 Kubernetes 开源社区的努力决定，但 GCP 通常最先拥有许多最新功能。

在 AWS 提供程序上，**Elasticsearch** 和 **Kibana** 已经为我们设置好。我们可以使用以下语法找到 Kibana UI 的 URL：

`https://<your master ip>/api/v1/proxy/namespaces/kube-system/services/kibana-logging`

就像 UI 的情况一样，您将被提示输入管理员凭据，可以使用 `config` 命令获取，如下所示：

```
$ kubectl config view

```

初次访问时，你需要设置你的索引。你可以保留默认值，并选择 @timestamp 作为时间字段名称。然后，单击创建，你将进入索引设置页面。从那里，点击顶部的 Discover 标签页，你可以探索日志仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_17.png)

Kubernetes Kibana 仪表板

# 重置集群

你刚刚对在 AWS 上运行集群有了一点体验。在本书的剩余部分，我将以 GCE 集群为例。为了更好地跟随示例，你可以轻松地回到 GCE 集群。

简单地拆除 AWS 集群，如下所示：

```
$ kube-down.sh

```

然后，再次使用以下方式创建 GCE 集群：

```
$ export KUBERNETES_PROVIDER=gce
$ kube-up.sh

```

# 修改 kube-up 参数

值得了解 `kube-up.sh` 脚本使用的参数。`kubernetes/cluster/` 文件夹下的每个提供程序都有自己的 `su` 文件夹，其中包含一个 `config-default.sh` 脚本。

例如，`kubernetes/cluster/aws/config-default.sh` 中有使用 AWS 运行 `kube-up.sh` 的默认设置。在该脚本的开头，你将看到许多这些值被定义以及可以用于覆盖默认值的环境变量。

在以下示例中，`ZONE` 变量被设置用于脚本，并且使用名为 `KUBE_AWS_ZONE` 的环境变量的值。如果此变量未设置，将使用默认值 `us-west-2a`：

```
ZONE=${KUBE_AWS_ZONE:-us-west-2a}

```

了解这些参数将帮助你更好地使用 `kube-up.sh` 脚本。

# kube-up.sh 的替代方法

`kube-up.sh` 脚本仍然是在你所选择的平台上开始使用 Kubernetes 的一种相当方便的方式。然而，它并非没有缺陷，有时在条件不尽如人意时可能会出现问题。

幸运的是，自 K8 成立以来，已经出现了许多创建集群的替代方法。其中两个 GitHub 项目是 *KOPs* 和 *kube-aws*。尽管后者与 AWS 绑定，但它们都提供了一种轻松启动新集群的替代方法：

+   **[`github.com/kubernetes/kops`](https://github.com/kubernetes/kops)**

+   **[`github.com/coreos/kube-aws`](https://github.com/coreos/kube-aws)**

另外，出现了许多受管服务，包括**Google Container Engine**（**GKE**）和微软**Azure Container Service**（**ACS**），它们提供了自动安装和一些受管的集群操作。我们将在第十二章中简要演示这些内容，*走向生产就绪*。

# 从零开始

最后，还有从零开始的选项。幸运的是，在 1.4 版本中，Kubernetes 团队在简化集群设置过程方面投入了重大精力。为此，他们引入了用于 Ubuntu 16.04、CentOS 7 和 HypriotOS v1.0.1+ 的 kubeadm。

让我们快速了解如何使用 kubeadm 工具从头开始在 AWS 上搭建集群。

# 集群设置

我们需要提前为集群主节点和节点进行部署。目前，我们受到先前列出的操作系统和版本的限制。此外，建议您至少有 1GB 的 RAM 并且所有节点之间必须具有网络连接。

在本次演示中，我们将在 AWS 上使用一个 t2.medium（主节点）和三个 t2.micro（工作节点）大小的实例。这些实例具有可突发的 CPU，并且配备了所需的最低 1GB RAM。我们需要创建一个主节点和三个工作节点。

我们还需要为集群创建一些安全组。对于主节点，需要以下端口：

| **类型** | **协议** | **端口范围** | **来源** |
| --- | --- | --- | --- |
| 所有流量 | 所有 | 所有 | {此 SG ID（主 SG）} |
| 所有流量 | 所有 | 所有 | {节点 SG ID} |
| SSH | TCP | 22 | {您的本地机器 IP} |
| HTTTPS | TCP | 443 | {允许访问 K8s API 和 UI 的范围} |

主节点安全组规则

下表显示了节点安全组的端口：

| **类型** | **协议** | **端口范围** | **来源** |
| --- | --- | --- | --- |
| 所有流量 | 所有 | 所有 | {主 SG ID} |
| 所有流量 | 所有 | 所有 | {此 SG ID（节点 SG）} |
| SSH | TCP | 22 | {您的本地机器 IP} |

节点安全组规则

一旦您拥有这些 SG，继续在 AWS 上启动四个实例（一个 t2.medium 和三个 t2.micros），使用 Ubuntu 16.04。如果您对 AWS 不熟悉，请参考以下网址中关于启动 EC2 实例的文档：

**[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/LaunchingAndUsingInstances.html`](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/LaunchingAndUsingInstances.html)**

请确保将 t2.medium 实例标识为主节点，并关联主安全组。将其他三个命名为节点，并将节点安全组与它们关联。

这些步骤是根据手册中的演示进行调整的。要获取更多信息，或使用 Ubuntu 以外的替代方案，请参考 [`kubernetes.io/docs/getting-started-guides/kubeadm/`](https://kubernetes.io/docs/getting-started-guides/kubeadm/)。

# 安装 Kubernetes 组件（kubelet 和 kubeadm）

接下来，我们需要 SSH 进入所有四个实例并安装 Kubernetes 组件。

以 root 身份，在所有四个实例上执行以下步骤：

1\. 更新软件包并安装 `apt-transport-https` 软件包，以便我们可以从使用 HTTPS 的源下载：

```
 $ apt-get update 
 $ apt-get install -y apt-transport-https

```

2\. 安装 Google Cloud 的公共密钥：

```
 $ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg |
   apt-key add -    

```

3\. 接下来，使用您喜欢的编辑器为 Kubernetes 包下载创建源列表：

```
 $ vi /etc/apt/sources.list.d/kubernetes.list

```

4\. 使用以下内容作为此文件的内容并保存：

```
 deb http://apt.kubernetes.io/ kubernetes-xenial main

```

*图示 1-1.* `/etc/apt/sources.list.d/kubernetes.list`

5\. 再次更新您的源：

```
 $ apt-get update

```

6\. 安装 Docker 和核心 Kubernetes 组件：

```
 $ apt-get install -y docker.io 
 $ apt-get install -y kubelet kubeadm kubectl kubernetes-cni

```

# 设置主节点

在您之前选择为 *master* 的实例上，我们将运行主初始化。再次以 root 身份运行以下命令：

```
$ kubeadm init 

```

请注意，初始化只能运行一次，所以如果遇到问题，您将 `kubeadm reset`。

# 加入节点

成功初始化后，您将获得一个可以被节点使用的加入命令。将其复制下来以供稍后的加入过程使用。它应该类似于这样：

```
$ kubeadm join --token=<some token> <master ip address>

```

令牌用于验证集群节点，因此请确保将其安全地存储在某个地方以供将来使用。

# 网络设置

我们的集群将需要一个网络层来使 pod 进行通信。请注意，kubeadm 需要一个 CNI 兼容的网络结构。当前可用插件的列表可以在此处找到：

**[`kubernetes.io/docs/admin/addons/`](http://kubernetes.io/docs/admin/addons/)**

对于我们的示例，我们将使用 calico。我们需要使用以下 `yaml` 在我们的集群上创建 calico 组件。为了方便起见，您可以在此处下载它：

**[`docs.projectcalico.org/v1.6/getting-started/kubernetes/installation/hosted/kubeadm/calico.yaml`](http://docs.projectcalico.org/v1.6/getting-started/kubernetes/installation/hosted/kubeadm/calico.yaml)**

一旦您在 *master* 上有了这个文件，请使用以下命令创建组件：

```
$ kubectl apply -f calico.yaml

```

给这个运行设置一分钟，然后列出 `kube-system` 节点以检查：

```
$ kubectl get pods --namespace=kube-system

```

你应该会得到类似下面的列表，其中有三个新的 calico pods 和一个未显示的已完成的作业：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_18.png)

Calico 设置

# 加入集群

现在我们需要在每个节点实例上运行之前复制的 `join` 命令：

```
$ kubeadm join --token=<some token> <master ip address>

```

完成后，您应该能够通过运行以下命令从主节点看到所有节点：

```
$ kubectl get nodes

```

如果一切顺利，这将显示三个节点和一个主节点，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_01_19.png)

Calico 设置

# 概要

我们简要了解了容器的工作原理以及它们如何适合微服务中的新架构模式。现在，您应该更好地理解这两种力量将需要各种运维和管理任务，以及 Kubernetes 提供强大功能来解决这些挑战。我们在 GCE 和 AWS 上创建了两个不同的集群，并探索了启动脚本以及 Kubernetes 的一些内置功能。最后，我们看了`kube-up`脚本的替代方案，并尝试在 AWS 上使用 Ubuntu 16.04 使用新的 kubeadm 工具。

在下一章中，我们将探讨 K8s 提供的核心概念和抽象，用于管理容器和完整应用程序堆栈。我们还将介绍基本的调度、服务发现和健康检查。

# 参考资料

1.  Malcom McLean 在 PBS 网站上的条目：[`www.pbs.org/wgbh/theymadeamerica/whomade/mclean_hi.html`](https://www.pbs.org/wgbh/theymadeamerica/whomade/mclean_hi.html)

1.  Martin Fowler 关于微服务的观点：[`martinfowler.com/articles/microservices.html`](http://martinfowler.com/articles/microservices.html)

1.  Kubernetes GitHub 项目页面：[`github.com/kubernetes/kubernetes`](https://github.com/kubernetes/kubernetes)

1.  [`www.thoughtworks.com/continuous-integration`](https://www.thoughtworks.com/continuous-integration)

1.  [`docs.docker.com/`](https://en.wikipedia.org/wiki/Continuous_integration%20https:/docs.docker.com/)

1.  [`kubernetes.io/docs/getting-started-guides/kubeadm/`](http://kubernetes.io/docs/getting-started-guides/kubeadm/)


# 第二章：Pod、Service、Replication Controller 和 Label

本章将介绍核心 Kubernetes 构件，即**pod**、**service**、**replication controller**、**replica set**和**label**。将包括几个简单的应用示例，以演示每个构件。本章还将介绍集群的基本操作。最后，将通过几个示例介绍**健康检查**和**调度**。

本章将讨论以下主题：

+   Kubernetes 的整体架构

+   介绍核心 Kubernetes 构件，即 pod、service、replication controller、replica set 和 label。

+   了解标签如何简化 Kubernetes 集群的管理

+   了解如何监视服务和容器的健康状况

+   了解如何根据可用集群资源设置调度约束

# 架构

尽管**Docker**在容器管理方面带来了有用的抽象层和工具，但 Kubernetes 也为规模化编排容器和管理完整应用程序堆栈提供了类似的帮助。

**K8s**在堆栈上升，为我们提供处理应用程序或服务级别管理的构件。这为我们提供了自动化和工具，以确保高可用性、应用程序堆栈和服务的整体可移植性。K8s 还允许我们对资源使用进行更精细的控制，例如 CPU、内存和磁盘空间。

Kubernetes 通过给我们关键构件来组合多个容器、端点和数据成为完整的应用程序堆栈和服务，提供了这种更高级别的编排管理。K8s 还提供了管理堆栈及其组件的何时、何地和多少的工具：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/image_02_001.png)

Kubernetes 核心架构

在上图中，我们看到了 Kubernetes 的核心架构。大多数管理交互是通过`kubectl`脚本和/或对 API 的 RESTful 服务调用完成的。

注意仔细理解期望状态和实际状态的概念。这是 Kubernetes 管理集群及其工作负载的关键。K8s 的所有部件都在不断工作，监视当前的实际状态，并将其与管理员通过 API 服务器或`kubectl`脚本定义的期望状态同步。有时这些状态不会匹配，但系统始终在努力协调这两者。

# 主节点

实际上，**master**是我们集群的大脑。在这里，我们有核心 API 服务器，它维护 RESTful Web 服务，用于查询和定义我们期望的集群和工作负载状态。重要的是要注意，控制平面只通过主节点发起更改，而不是直接访问节点。

另外，主节点包括 **调度器**，它与 API 服务器一起工作，以在实际的从节点上调度 pod 形式的工作负载。这些 pod 包含组成我们应用程序堆栈的各种容器。默认情况下，基本的 Kubernetes 调度器将 pod 分布在整个集群中，并使用不同的节点来匹配 pod 的副本。Kubernetes 还允许为每个容器指定必要的资源，因此可以通过这些额外因素来改变调度。

复制控制器/副本集与 API 服务器一起工作，确保任何时候运行正确数量的 pod 副本。这是理想状态概念的典范。如果我们的复制控制器/副本集定义了三个副本，而我们的实际状态是两个 pod 副本正在运行，那么调度器将被调用，在集群的某个地方添加第三个 pod。如果在任何给定时间集群中运行的 pod 过多，也是如此。通过这种方式，K8s 总是朝着理想状态的方向努力。

最后，我们有 **etcd** 作为分布式配置存储运行。Kubernetes 状态存储在这里，etcd 允许监视值的变化。将其视为大脑的共享内存。

# 节点（以前称为 minions）

在每个节点中，我们有一些组件组成。**kubelet** 与 API 服务器交互，以更新状态并启动调度器调用的新工作负载。

**Kube-proxy** 提供基本负载均衡，并将特定服务的流量引导到后端合适的 pod。请参考本章后面的 *服务* 部分。

最后，我们有一些默认的 pod，运行节点的各种基础设施服务。正如我们在上一章节中简要探讨的那样，这些 pod 包括用于 **域名系统（DNS）**、日志记录和 pod 健康检查的服务。默认的 pod 将与我们在每个节点上调度的 pod 一起运行。

在 v1.0 中，**minion** 更名为 **node**，但在一些网络命名脚本和文档中仍然保留了 minion 一词的痕迹。为了清晰起见，在整本书中，我在一些地方同时添加了 minion 和 node 这两个术语。

# 核心构造

现在，让我们深入了解 Kubernetes 提供的一些核心抽象。这些抽象将使我们更容易思考我们的应用程序，减轻生命周期管理、高可用性和调度的负担。

# Pods

Pods 允许你将相关容器在网络和硬件基础设施方面保持密切联系。数据可以靠近应用程序，因此可以在不经历网络遍历的高延迟情况下进行处理。同样，常见的数据可以存储在多个容器之间共享的卷上。Pods 本质上允许你逻辑地将容器和应用程序堆栈的各部分组合在一起。

虽然 Pod 内部可能运行一个或多个容器，但 Pod 本身可能是在 Kubernetes 节点（从属节点）上运行的众多 Pod 之一。正如我们将看到的，Pod 为我们提供了一个逻辑容器组，我们可以在其中复制、调度并通过负载均衡服务端点。

# Pod 示例

让我们快速看一下 Pod 的操作。我们将在群集上启动一个**Node.js**应用程序。您需要为此运行一个 GCE 群集；如果您尚未启动群集，请参考*我们的第一个集群*部分，在第一章的*， Kubernetes 简介*中。

现在，让我们为我们的定义创建一个目录。在本例中，我将在我们的主目录下的`/book-examples`子文件夹中创建一个文件夹：

```
$ mkdir book-examples
$ cd book-examples
$ mkdir 02_example
$ cd 02_example

```

下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)上的帐户中下载所有您购买的 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，将文件直接通过电子邮件发送给您。

使用您喜欢的编辑器创建以下文件：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: node-js-pod 
spec: 
  containers: 
  - name: node-js-pod 
    image: bitnami/apache:latest 
    ports: 
    - containerPort: 80

```

*清单 2-1*：`nodejs-pod.yaml`

此文件创建一个名为`node-js-pod`的 Pod，其中运行着最新的`bitnami/apache`容器，运行在端口`80`上。我们可以使用以下命令来检查：

```
$ kubectl create -f nodejs-pod.yaml

```

输出如下：

```
pod "node-js-pod" created

```

这样我们就可以运行指定容器的 Pod。我们可以通过运行以下命令查看有关 Pod 的更多信息：

```
$ kubectl describe pods/node-js-pod

```

您将看到大量信息，如 Pod 的状态、IP 地址，甚至相关的日志事件。您会注意到 Pod 的 IP 地址是私有 IP 地址，因此我们无法直接从本地计算机访问它。不用担心，因为`kubectl exec`命令反映出 Docker 的`exec`功能。一旦 Pod 显示为运行状态，我们就可以使用此功能在 Pod 内运行命令：

```
$ kubectl exec node-js-pod -- curl <private ip address>

```

默认情况下，这将在找到的第一个容器中运行命令，但您可以使用`-c`参数选择特定的容器。

运行命令后，您将看到一些 HTML 代码。在本章后面我们将有一个更漂亮的视图，但现在，我们可以看到我们的 Pod 确实按预期运行。

# 标签

标签为我们提供了另一种分类级别，在日常运维和管理方面非常有帮助。类似于标记，标签可以用作服务发现的基础，同时也是日常运维和管理任务的有用分组工具。

标签只是简单的键值对。您会在 Pod、复制控制器、副本集、服务等资源上看到它们。该标签充当选择器，告诉 Kubernetes 为各种操作使用哪些资源。可以将其视为过滤选项。

我们将在本章稍后更深入地看一下标签，但首先，我们将探索剩余的三个构造——服务、复制控制器和副本集。

# 容器的余生

正如 AWS 的首席技术官 Werner Vogels 所说的那样*一切都会遇到故障*：容器和 Pod 可能会崩溃、损坏，甚至可能会被手忙脚乱的管理员误关闭一个节点上的操作。强大的策略和安全实践如最低权限原则会遏制部分这类事件，但不可抗拒的工作量屠杀发生是运维的现实。

幸运的是，Kubernetes 提供了两个非常有价值的构建，以将这个庄严的事务都整洁地隐藏在幕后。服务和复制控制器/副本集使我们能够在几乎没有干扰和优雅恢复的情况下保持我们的应用程序运行。

# 服务

服务允许我们将访问方式与我们应用程序的消费者进行分离。使用可靠的端点，用户和其他程序能够无缝访问运行在您的集群上的 Pod。

K8s 通过确保集群中的每个节点运行一个名为**kube-proxy**的代理来实现这一点。正如其名称所示，**kube-proxy**的工作是将服务端点的通信代理回到运行实际应用程序的相应 Pod。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/image_02_002.png)

kube-proxy 架构

服务负载均衡池的成员资格由选择器和标签的使用确定。具有匹配标签的 Pod 被添加到候选列表中，服务将将流量转发给这些 Pod 中的一个。虚拟 IP 地址和端口被用作服务的入口点，然后流量被转发到由 K8s 或您的定义文件定义的目标端口上的随机 Pod。

服务定义的更新是从 K8s 集群主节点监视和协调，并传播到运行在每个节点上的**kube-proxy 守护程序**。

目前，kube-proxy 正在节点主机上运行。未来计划将其和 kubelet 默认容器化。

# 复制控制器和副本集

**复制控制器**（**RCs**）正如其名称所示，管理着 Pod 和包含的容器镜像运行的节点数。它们确保特定数量的此镜像的实例正在被运行。

随着您开始将容器和 Pod 运营化，您需要一种方式来滚动更新、扩展正在运行的副本数量（上下扩展），或者只需确保您的堆栈至少运行一个实例。RCs 提供了一个高级机制，以确保整个应用程序和集群的运行正常。

RC（Replication Controllers）的任务很简单，即确保您的应用程序具有所需的规模。您定义要运行的 Pod 副本的数量，并为其提供如何创建新 Pod 的模板。与服务一样，我们将使用选择器和标签来定义 Pod 在复制控制器中的成员资格。

Kubernetes 不要求复制控制器的严格行为，这对长时间运行的进程非常理想。事实上，**作业控制器**可以用于短期工作负载，允许作业运行到完成状态，并且非常适合批处理工作。

**副本集**，是一种新型类型，目前处于 Beta 版，代表了复制控制器的改进版本。目前的主要区别在于能够使用新的基于集合的标签选择器，正如我们将在下面的示例中看到的。

# 我们的第一个 Kubernetes 应用程序

在我们继续之前，让我们看看这三个概念是如何运作的。Kubernetes 预装了许多示例，但我们将从零开始创建一个新示例来说明一些概念。

我们已经创建了一个 pod 定义文件，但是正如你所学到的，通过复制控制器运行我们的 pod 有许多优势。再次使用我们之前创建的 `book-examples/02_example` 文件夹，我们将创建一些定义文件，并使用复制控制器方法启动一个 Node.js 服务器集群。此外，我们还将使用负载均衡服务为其添加一个公共面孔。

使用您喜欢的编辑器创建以下文件：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js 
  labels: 
    name: node-js 
spec: 
  replicas: 3 
  selector: 
    name: node-js 
  template: 
    metadata: 
      labels: 
        name: node-js 
    spec: 
      containers: 
      - name: node-js 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80

```

*清单 2-2*：`nodejs-controller.yaml`

这是我们集群的第一个资源定义文件，让我们仔细看一看。您会注意到它有四个一级元素（`kind`、`apiVersion`、`metadata` 和 `spec`）。这些在所有顶级 Kubernetes 资源定义中都很常见：

+   `类型`：这告诉 K8s 我们正在创建的资源类型。在这种情况下，类型是 `ReplicationController`。`kubectl` 脚本使用单个 `create` 命令来处理所有类型的资源。这里的好处是您可以轻松创建各种类型的资源，而无需为每种类型指定单独的参数。但是，这要求定义文件能够识别它们所指定的内容。

+   `apiVersion`：这只是告诉 Kubernetes 我们正在使用的模式的版本。

+   `元数据`：在这里，我们将为资源指定一个名称，并指定将用于搜索和选择给定操作的资源的标签。元数据元素还允许您创建注释，这些注释用于非标识信息，可能对客户端工具和库有用。

+   最后，我们有 `spec`，它将根据我们正在创建的资源的 `kind` 或类型而变化。在这种情况下，它是 `ReplicationController`，它确保所需数量的 pod 正在运行。`replicas` 元素定义了所需的 pod 数量，`selector` 元素告诉控制器要监视哪些 pod，最后，`template` 元素定义了启动新 pod 的模板。`template` 部分包含我们之前在 pod 定义中看到的相同部分。需要注意的一点是，`selector` 值需要与 pod 模板中指定的 `labels` 值匹配。请记住，这种匹配用于选择正在管理的 pod。

现在，让我们来看一下服务定义：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js 
  labels: 
    name: node-js 
spec: 
  type: LoadBalancer 
  ports: 
  - port: 80 
  selector: 
    name: node-js

```

*清单 2-3*: `nodejs-rc-service.yaml`

这里的 YAML 与 `ReplicationController` 类似。主要区别在于服务的 `spec` 元素中。在这里，我们定义了 `Service` 类型，监听 `port` 和 `selector`，告诉 `Service` 代理哪些 pod 可以回答该服务。

Kubernetes 支持 YAML 和 JSON 两种格式的定义文件。

创建 Node.js express 复制控制器：

```
$ kubectl create -f nodejs-controller.yaml

```

输出如下：

```
replicationcontroller "node-js" created

```

这给了我们一个复制控制器，确保容器始终运行三个副本：

```
$ kubectl create -f nodejs-rc-service.yaml

```

输出如下：

```
service "node-js" created 

```

在 GCE 上，这将创建一个外部负载均衡器和转发规则，但您可能需要添加额外的防火墙规则。在我的情况下，防火墙已经为端口 `80` 打开。但是，您可能需要打开此端口，特别是如果您部署了具有端口不是 `80` 和 `443` 的服务。

好了，现在我们有了一个运行中的服务，这意味着我们可以从可靠的 URL 访问 Node.js 服务器。让我们来看看我们正在运行的服务：

```
$ kubectl get services

```

以下截图是前面命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/6302_02_03.png)

服务列表

在前面的图像（*服务列表*）中，我们应该注意到 `node-js` 服务正在运行，并且在 IP(S) 列中，我们应该有一个私有和一个公共的（截图中为 `130.211.186.84`）IP 地址。如果您看不到外部 IP，请等待一分钟以从 GCE 中分配 IP。让我们尝试在浏览器中打开公共地址来连接：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/image_02_004.png)

容器信息应用程序

您应该看到类似 *容器信息应用程序* 的图形。如果我们多次访问，您应该注意到容器名称的变化。基本上，服务负载均衡器在后端可用的 pod 之间轮转。

浏览器通常会缓存网页，所以要真正看到容器名称的变化，您可能需要清除缓存或使用像这样的代理：

[`hide.me/en/proxy`](https://hide.me/en/proxy)

让我们试着玩一下混沌猴，关闭一些容器，看看 Kubernetes 会做什么。为了做到这一点，我们需要查看 pod 实际运行的位置。首先，让我们列出我们的 pod：

```
$ kubectl get pods

```

以下截图是前面命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/image_02_005.png)

当前正在运行的 Pod

现在，让我们对运行`node-js`容器的一个 Pod 获取更多详细信息。你可以使用上一个命令中列出的一个 Pod 名称执行此操作：

```
$ kubectl describe pod/node-js-sjc03

```

以下截图是前述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/image_02_006.png)

Pod 描述

你应该看到前面的输出。我们需要的信息是`Node:`部分。让我们使用节点名称**SSH**（缩写为**安全外壳**）进入运行此工作负载的（从属）节点：

```
$ gcloud compute --project "<Your project ID>" ssh --zone "<your gce zone>" "<Node from
pod describe>"

```

一旦 SSH 进入节点，如果我们运行`sudo docker ps`命令，我们应该会看到至少两个容器：一个运行`pause`镜像，另一个运行实际的`node-express-info`镜像。如果 K8s 在此节点上调度了多个副本，则可能会看到更多。让我们获取`jonbaier/node-express-info`镜像（而不是`gcr.io/google_containers/pause`）的容器 ID 并将其杀死以查看发生了什么。稍后记下此容器 ID：

```
$ sudo docker ps --filter="name=node-js"
$ sudo docker stop <node-express container id>
$ sudo docker rm <container id>
$ sudo docker ps --filter="name=node-js"

```

除非你非常迅速，否则你可能会注意到仍然有一个`node-express-info`容器在运行，但仔细观察你会发现`容器 id`不同，并且创建时间戳显示只是几秒钟前。如果你返回到服务的 URL，它正常运行。现在可以退出 SSH 会话了。

在这里，我们已经看到 Kubernetes 扮演着随时待命的运维角色，确保我们的应用程序始终运行。

让我们看看是否能找到任何中断的证据。进入 Kubernetes UI 中的事件页面。你可以通过导航到 K8s 主仪表板上的 Nodes 页面找到它。从列表中选择一个节点（我们 SSH 进入的相同节点）并滚动到节点详细信息页面的 Events 下。

你将看到一个类似于以下截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_07.png)

Kubernetes UI 事件页面

你应该看到三个最近的事件。首先，Kubernetes 拉取镜像。其次，它使用拉取的镜像创建一个新的容器。最后，它再次启动该容器。你会注意到，从时间戳来看，所有这些都发生在不到一秒的时间内。所花费的时间可能会根据集群大小和镜像拉取而有所不同，但恢复非常快。

# 更多关于标签的信息

如前所述，标签只是简单的键值对。它们可用于 Pod、复制控制器、副本集、服务等。如果你回忆一下我们的服务 YAML，在 *清单 2-3*：`nodejs-rc-service.yaml`中，有一个`selector`属性。`selector`属性告诉 Kubernetes 在查找要转发流量的 Pod 时使用哪些标签。

K8s 允许用户直接在复制控制器、副本集和服务上使用标签。让我们修改我们的副本和服务，以包含更多标签。再次使用你喜欢的编辑器创建这两个文件，如下所示：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-labels 
  labels: 
    name: node-js-labels 
    app: node-js-express 
    deployment: test 
spec: 
  replicas: 3 
  selector: 
    name: node-js-labels 
    app: node-js-express 
    deployment: test 
  template: 
    metadata: 
      labels: 
        name: node-js-labels 
        app: node-js-express 
        deployment: test 
    spec: 
      containers: 
      - name: node-js-labels 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80

```

*清单 2-4*：`nodejs-labels-controller.yaml`

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-labels 
  labels: 
    name: node-js-labels 
    app: node-js-express 
    deployment: test 
spec: 
  type: LoadBalancer 
  ports: 
  - port: 80 
  selector: 
    name: node-js-labels 
    app: node-js-express 
    deployment: test

```

*清单 2-5*：`nodejs-labels-service.yaml`

创建复制控制器和服务如下：

```
$ kubectl create -f nodejs-labels-controller.yaml
$ kubectl create -f nodejs-labels-service.yaml

```

让我们看看如何在日常管理中使用标签。以下表格向我们展示了选择标签的选项：

| **运算符** | **描述** | **示例** |
| --- | --- | --- |
| `=` 或 `==` | 您可以使用任一样式选择值等于右侧字符串的键 | `name = apache` |
| `!=` | 选择值不等于右侧字符串的键 | `Environment != test` |
| `in` | 选择标签具有在此集合中的键值对的资源 | `tier in (web, app)` |
| `notin` | 选择标签具有不在此集合中的键值对的资源 | `tier notin (lb, app)` |
| `<键名>` | 仅使用键名选择包含此键的标签资源 | `tier` |

标签选择器

让我们尝试查找具有`test`部署的副本：

```
$ kubectl get rc -l deployment=test

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_08-updated.png)

复制控制器列表

您会注意到它只返回我们刚刚启动的复制控制器。带有名为`component`的标签的服务呢？请使用以下命令：

```
$ kubectl get services -l component

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_09.png)

带有名为 component 的标签的服务列表

在这里，我们仅看到了核心 Kubernetes 服务。最后，让我们只获取本章中启动的 `node-js` 服务器。请参阅以下命令：

```
$ kubectl get services -l "name in (node-js,node-js-labels)"

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_10-updated.png)

带有名称为 node-js 或 node-js-labels 的标签名和值的服务列表

此外，我们可以跨多个 pod 和服务执行管理任务。例如，我们可以终止所有属于`demo`部署的复制控制器（如果有运行中的话），如下所示：

```
$ kubectl delete rc -l deployment=demo

```

否则，终止所有属于`production`或`test`部署的服务（再次，如果有正在运行的话），如下所示：

```
$ kubectl delete service -l "deployment in (test, production)"

```

值得注意的是，虽然标签选择在日常管理任务中非常有用，但这确实需要我们保持良好的部署卫生习惯。我们需要确保我们有一个标记标准，并且在我们在 Kubernetes 上运行的所有内容的资源定义文件中积极遵循。

到目前为止，我们一直使用服务定义 YAML 文件来创建我们的服务，但实际上，您可以仅使用一个 `kubectl` 命令创建它们。要尝试这样做，请首先运行 `get pods` 命令并获取一个 `node-js` pod 名称。接下来，使用以下`expose` 命令仅为该 pod 创建服务端点：

`**$ kubectl expose pods node-js-gxkix --port=80 --name=testing-vip --create-external-load-balancer=true**` 这将创建一个名为`testing-vip`的服务，以及一个可以用于通过端口`80` 访问此 pod 的公共 `VIP`（负载均衡器 IP）。还有许多其他可选参数可用。可以使用以下命令查找这些参数：

**`kubectl expose --help`**

# 副本集

正如之前讨论的，复制集是复制控制器的新版本和改进版。它们利用基于集合的标签选择，但在撰写本文时仍被视为 beta 版本。

这是一个基于`ReplicaSet`的示例，与*列表 2-4*中的`ReplicationController`类似：

```
apiVersion: extensions/v1beta1 
kind: ReplicaSet 
metadata: 
  name: node-js-rs 
spec: 
  replicas: 3 
  selector: 
    matchLabels: 
      app: node-js-express 
      deployment: test 
    matchExpressions: 
      - {key: name, operator: In, values: [node-js-rs]} 
  template: 
    metadata: 
      labels: 
        name: node-js-rs 
        app: node-js-express 
        deployment: test 
    spec: 
      containers: 
      - name: node-js-rs 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80

```

*列表 2-6*：`nodejs-labels-replicaset.yaml`

# 健康检查

Kubernetes 提供两层健康检查。首先，以 HTTP 或 TCP 检查的形式，K8s 可以尝试连接到特定端点，并在成功连接时给出健康状态。其次，可以使用命令行脚本执行特定于应用程序的健康检查。

让我们看看一些健康检查的实际操作。首先，我们将创建一个带有健康检查的新控制器：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js 
  labels: 
    name: node-js 
spec: 
  replicas: 3 
  selector: 
    name: node-js 
  template: 
    metadata: 
      labels: 
        name: node-js 
    spec: 
      containers: 
      - name: node-js 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80 
        livenessProbe: 
          # An HTTP health check  
          httpGet: 
            path: /status/ 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 1

```

*列表 2-7*：`nodejs-health-controller.yaml`

注意`livenessprobe`元素的添加。这是我们的核心健康检查元素。从这里，我们可以指定`httpGet`、`tcpScoket`或`exec`。在这个例子中，我们使用`httpGet`来对容器上的 URI 执行一个简单的检查。探针将检查指定的路径和端口，并在没有成功返回时重新启动 Pod。

探针认为状态码在`200`到`399`之间均为健康状态。

最后，`initialDelaySeconds`给了我们灵活性，延迟健康检查直到 Pod 完成初始化。`timeoutSeconds`的值只是探针的超时值。

让我们使用我们新的启用健康检查的控制器来替换旧的`node-js` RC。我们可以使用`replace`命令来完成这个操作，该命令将替换复制控制器的定义：

```
$ kubectl replace -f nodejs-health-controller.yaml

```

仅仅替换 RC 本身并不会替换我们的容器，因为它仍然有三个来自第一次运行的健康 Pod。让我们杀死那些 Pod，并让更新的`ReplicationController`替换它们，这些容器具有健康检查：

```
$ kubectl delete pods -l name=node-js

```

现在，等待一两分钟后，我们可以列出 RC 中的 Pod，并获取一个 Pod ID，然后用`describe`命令更深入地检查：

```
$ kubectl describe rc/node-js

```

以下屏幕截图是前述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_11.png)

node-js 复制控制器的描述

现在，对其中一个 Pod 使用以下命令：

```
$ kubectl describe pods/node-js-7esbp

```

以下屏幕截图是前述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_12.png)

node-js-1m3cs Pod 的描述

在顶部，我们将看到整体的 pod 信息。根据你的时间点，在`State`下，它可能会显示`Running`或`Waiting`与一个`CrashLoopBackOff`原因以及一些错误信息。稍微下面我们可以看到有关我们的`Liveness`探针的信息，而且很可能会看到失败计数大于`0`。在更深处，我们有 pod 事件。同样，根据你的时间点，你很可能会有一系列与 pod 相关的事件。在一两分钟内，你会注意到一个不断重复的杀死、启动和创建事件的模式。您还应该在`Killing`条目中看到一个注释，指出容器不健康。这是我们的健康检查失败，因为我们没有在`/status`上响应页面。

您可能注意到，如果您打开浏览器访问服务负载均衡器地址，它仍然会有响应页面。您可以使用`kubectl get services`命令找到负载均衡器 IP。

这种情况发生的原因有很多。首先，健康检查简单地失败，因为`/status`不存在，但服务指向的页面在重新启动之间仍然正常运行。其次，`livenessProbe`只负责在健康检查失败时重新启动容器。还有一个单独的`readinessProbe`，它将从回答服务端点的 pods 池中删除一个容器。

让我们修改健康检查，指向我们容器中存在的页面，这样我们就有了一个正确的健康检查。我们还将添加一个 readiness 检查，并指向不存在的状态页面。打开`nodejs-health-controller.yaml`文件，并修改`spec`部分以匹配*Listing 2-8*，然后保存为`nodejs-health-controller-2.yaml`：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js 
  labels: 
    name: node-js 
spec: 
  replicas: 3 
  selector: 
    name: node-js 
  template: 
    metadata: 
      labels: 
        name: node-js 
    spec: 
      containers: 
      - name: node-js 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80 
        livenessProbe: 
          # An HTTP health check  
          httpGet: 
            path: / 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 1 
        readinessProbe: 
          # An HTTP health check  
          httpGet: 
            path: /status/ 
            port: 80 
          initialDelaySeconds: 30 
          timeoutSeconds: 1

```

*Listing 2-8*：`nodejs-health-controller-2.yaml`

这一次，我们将删除旧的 RC，这将导致其中的 pods 被终止，并使用我们更新的 YAML 文件创建一个新的 RC：

```
$ kubectl delete rc -l name=node-js
$ kubectl create -f nodejs-health-controller-2.yaml

```

现在，当我们描述其中一个 pods 时，我们只会看到 pod 和容器的创建。然而，您会注意到服务负载均衡器 IP 不再起作用。如果我们在新节点上运行`describe`命令，我们将注意到一个`Readiness probe failed`错误消息，但 pod 本身仍在运行。如果我们将 readiness 探针路径更改为`path: /`，我们将再次能够满足主服务的请求。现在在编辑器中打开`nodejs-health-controller-2.yaml`，并进行更新。然后，再次删除并重新创建复制控制器：

```
$ kubectl delete rc -l name=node-js
$ kubectl create -f nodejs-health-controller-2.yaml

```

现在负载均衡器 IP 应该可以再次工作了。保留这些 pods，因为我们将在 Chapter 3，*网络、负载均衡器和入口*中再次使用它们。

# TCP 检查

Kubernetes 还支持通过简单的 TCP 套接字检查和自定义命令行脚本进行健康检查。以下片段是这两种用例在 YAML 文件中的示例：

```
livenessProbe: 
  exec: 
    command: 
    -/usr/bin/health/checkHttpServce.sh 
  initialDelaySeconds:90 
  timeoutSeconds: 1

```

*Listing 2-9*： *使用命令行脚本进行健康检查*

```
livenessProbe: 
  tcpSocket: 
    port: 80 
  initialDelaySeconds: 15 
  timeoutSeconds: 1

```

*Listing 2-10*：*使用简单的 TCP 套接字连接进行健康检查*

# 生命周期钩子或优雅关闭

在实际场景中遇到故障时，您可能会发现希望在容器关闭之前或刚启动之后采取额外的操作。Kubernetes 实际上为这种情况提供了生命周期钩子。 

下面的示例控制器定义了一个 `postStart` 动作和一个 `preStop` 动作，在 Kubernetes 将容器移入其生命周期的下一阶段之前执行（你可以在本章末尾的 *参考文献* 中的第 1 点中查看更多详情）：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: apache-hook 
  labels: 
    name: apache-hook 
spec: 
  replicas: 3 
  selector: 
    name: apache-hook 
  template: 
    metadata: 
      labels: 
        name: apache-hook 
    spec: 
      containers: 
      - name: apache-hook 
        image: bitnami/apache:latest 
        ports: 
        - containerPort: 80 
        lifecycle: 
          postStart: 
            httpGet: 
              path: http://my.registration-server.com/register/ 
              port: 80 
          preStop: 
            exec: 
              command: ["/usr/local/bin/apachectl","-k","graceful-
              stop"]

```

*清单 2-11*：`apache-hooks-controller.yaml`

你会注意到对于 `postStart` 钩子，我们定义了一个 `httpGet` 操作，但是对于 `preStop` 钩子，我定义了一个 `exec` 操作。与我们的健康检查一样，`httpGet` 操作尝试对特定端点和端口组合进行 HTTP 调用，而 `exec` 操作在容器中运行本地命令。

`postStart` 和 `preStop` 钩子都支持 `httpGet` 和 `exec` 操作。对于 `preStop`，将会将一个名为 `reason` 的参数发送给处理程序作为参数。参见以下表格获取有效值：

| **原因参数** | **故障描述** |
| --- | --- |
| 删除 | 通过 `kubectl` 或 API 发出的删除命令 |
| 健康 | 健康检查失败 |
| 依赖 | 依赖故障，比如磁盘挂载失败或默认基础设施 pod 崩溃 |

有效的 `preStop` 原因（请参阅 *参考文献* 中的第 1 点）

需要注意的是 hook 调用至少会传递一次。因此，操作中的任何逻辑都应该优雅地处理多次调用。另一个重要的注意事项是 `postStart` 在 pod 进入就绪状态之前运行。如果钩子本身失败，pod 将被视为不健康。

# 应用程序调度

现在我们了解了如何在 pod 中运行容器，甚至从失败中恢复，了解如何在我们的集群节点上调度新容器可能会很有用。

如前所述，Kubernetes 调度程序的默认行为是在集群的节点之间分布容器副本。在所有其他约束条件都不存在的情况下，调度程序会将新的 pod 放置在具有最少匹配服务或复制控制器的其他 pod 数量的节点上。

此外，调度程序提供根据节点上可用资源添加约束的能力。目前，这包括最低 CPU 和内存分配。就 Docker 而言，这些在底层使用 **CPU-shares** 和 **内存限制标志**。

当定义了额外的约束时，Kubernetes 将检查节点上的可用资源。如果节点不满足所有约束条件，它将移到下一个节点。如果找不到满足条件的节点，则在日志中会看到调度错误。

Kubernetes 路线图还计划支持网络和存储。由于调度对于容器的整体运营和管理非常重要，所以随着项目的发展，我们应该期望在这个领域看到许多增加。

# 调度示例

让我们快速看一下设置一些资源限制的快速示例。如果我们查看我们的 K8s 仪表板，我们可以使用`https://<your master ip>/api/v1/proxy/namespaces/kube-system/services/kubernetes-dashboard`并点击左侧菜单中的 Nodes，快速查看我们集群当前资源使用状态的快照。

我们将看到一个仪表板，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_13.png)

Kube 节点仪表板

此视图显示整个集群、节点和主节点的聚合 CPU 和内存。在这种情况下，我们的 CPU 利用率相当低，但内存使用率相当高。

让我们看看当我尝试启动几个额外的 pod 时会发生什么，但这次，我们将请求`512 Mi`的内存和`1500 m`的 CPU。我们将使用`1500 m`来指定 1.5 个 CPU；由于每个节点只有 1 个 CPU，这应该会导致失败。下面是一个 RC 定义的示例：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-constraints 
  labels: 
    name: node-js-constraints 
spec: 
  replicas: 3 
  selector: 
    name: node-js-constraints 
  template: 
    metadata: 
      labels: 
        name: node-js-constraints 
    spec: 
      containers: 
      - name: node-js-constraints 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80 
        resources: 
          limits: 
            memory: "512Mi" 
            cpu: "1500m"

```

*列表 2-12*：`nodejs-constraints-controller.yaml`

要打开上述文件，请使用以下命令：

```
$ kubectl create -f nodejs-constraints-controller.yaml

```

复制控制器成功完成，但如果我们运行`get pods`命令，我们会注意到`node-js-constraints` pods 陷入了等待状态。如果我们用`describe pods/<pod-id>`命令仔细观察（对于`pod-id`，使用第一个命令中的一个 pod 名称），我们会注意到一个调度错误：

```
$ kubectl get pods
$ kubectl describe pods/<pod-id>

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_02_14.png)

Pod 描述

请注意，在底部的事件部分，`Events`中列出的`WarningFailedScheduling pod`错误后面跟着一个`fit failure on node....Insufficient cpu`。如您所见，Kubernetes 无法在满足我们定义的所有约束的集群中找到适合的位置。

如果我们现在将 CPU 约束修改为`500 m`，然后重新创建我们的复制控制器，我们应该在几分钟内将所有三个 pod 都运行起来。

# 摘要

我们查看了 Kubernetes 的整体架构，以及提供的核心构造，用于构建您的服务和应用程序堆栈。您应该对这些抽象有一个更好的理解，因为它们使得管理堆栈和/或服务的生命周期更容易，而不仅仅是个别组件。此外，我们首次了解了如何使用 pod、服务和复制控制器来管理一些简单的日常任务。我们还探讨了如何使用 Kubernetes 通过健康检查自动响应故障。最后，我们探讨了 Kubernetes 调度器以及用户可以指定的一些约束，以影响调度位置。

在下一章中，我们将深入探讨 Kubernetes 的网络层。我们将了解网络是如何进行配置的，还将研究核心的 Kubernetes 代理用于流量路由。我们还将研究服务发现和逻辑命名空间分组。

# 参考资料

1.  [`github.com/GoogleCloudPlatform/kubernetes/blob/release-1.0/docs/user-guide/container-environment.md#container-hooks`](https://github.com/GoogleCloudPlatform/kubernetes/blob/release-1.0/docs/user-guide/container-environment.md#container-hooks)


# 第三章：网络、负载平衡和入口控制器

在这一章节中，我们将要覆盖 Kubernetes 集群如何处理网络，以及它和其他方法的不同之处。我们将描述 Kubernetes 网络解决方案的三个要求，并探讨为什么这些对于操作的便捷性至关重要。另外，我们将深入介绍服务以及 Kubernetes 代理在每个节点上的工作方式。最后，我们将简要概述一些用于多租户的更高级别的隔离特性。

这个章节将会讨论以下内容：

+   Kubernetes 网络

+   高级服务概念

+   服务发现

+   DNS

+   命名空间限制和配额

# Kubernetes 网络

网络是生产级别运作的重要考虑因素。在服务层面上，我们需要一种可靠的方法来找到和与应用程序组件通信。引入容器和聚类使得事情更加复杂，因为现在我们必须考虑多个网络命名空间。通信和发现现在需要穿越容器 IP 空间、主机网络，甚至是多个数据中心的网络拓扑。

Kubernetes 受益于其祖先来自 Google 在过去十年使用的聚类工具。网络是 Google 超越竞争对手的领域之一，其拥有地球上最大的网络之一。早些时候，Google 构建了自己的硬件交换机和软件定义网络（SDN），以在日常网络操作中获得更多的控制、冗余和效率（您可以在本章节结尾的“参考”部分中的第 1 点中了解更多详细信息）。从每周运行和网络化的 20 亿个容器中汲取的许多经验教训已经提炼成了 Kubernetes，并指导了 K8s 网络的实现方式。

在 Kubernetes 中进行网络操作需要每个 Pod 有其自己的 IP 地址。基础设施提供商的实现细节可能会有所不同。但是，所有实现都必须遵守一些基本规则。首先和其次，Kubernetes 不允许在容器与容器或容器与节点（minion）之间使用网络地址转换（NAT）。此外，内部容器 IP 地址必须与用于与其通信的 IP 地址匹配。

这些规则可以保持我们的网络堆栈的大部分复杂性，并简化应用程序的设计。此外，它们消除了从现有基础设施中迁移的遗留应用程序中重新设计网络通信的需要。最后，在全新的应用程序中，它们允许更大规模地处理数百个甚至数千个服务和应用程序通信。

K8s 通过一个**占位符**来实现这种整个 pod 范围的 IP 魔法。记住，我们在第一章中看到的`pause`容器，在*介绍 Kubernetes*的*在主节点上运行的服务*部分，通常被称为**pod 基础设施容器**，它的重要工作是为稍后启动的应用容器保留网络资源。实质上，`pause`容器持有整个 pod 的网络命名空间和 IP 地址，并且可以被所有正在运行的容器使用。`pause`容器首先加入并持有命名空间，随后在 pod 中启动时，后续容器加入其中。

# 网络选项

Kubernetes 提供了各种网络选项。有些解决方案适用于 AWS 和 GCP 中的本机网络层。还有各种覆盖插件，其中一些将在下一节中讨论。最后，还支持**容器网络接口**（**CNI**）插件。CNI 旨在成为容器的通用插件架构。它目前得到了几个编排工具的支持，如 Kubernetes、Mesos 和 CloudFoundry。更多信息请访问：

[`github.com/containernetworking/cni`](https://github.com/containernetworking/cni).

请始终参考 Kubernetes 文档以获取最新和完整的支持网络选项列表。

# 网络比较

为了更好地理解容器中的网络，可以研究其他容器网络的方法。以下方法并非穷尽列表，但应该让你对可用选项有所了解。

# Docker

**Docker 引擎**默认创建三种类型的网络。这些是**桥接**、**主机**和**无**。

桥接网络是默认选择，除非另有说明。在此模式下，容器有自己的网络命名空间，然后通过虚拟接口桥接到主机（或在 K8s 情况下是节点）网络。在桥接网络中，两个容器可以使用相同的 IP 范围，因为它们是完全隔离的。因此，服务通信需要通过网络接口的主机侧进行一些额外的端口映射。

Docker 还支持主机网络，允许容器使用主机网络堆栈。性能得到了极大的改善，因为它消除了一个网络虚拟化的层级；然而，你失去了拥有独立网络命名空间的安全性。此外，必须更加谨慎地管理端口使用，因为所有容器共享一个 IP。

最后，Docker 支持一个 none 网络，它创建一个没有外部接口的容器。如果检查网络接口，只显示一个回环设备。

在所有这些场景中，我们仍然位于单个机器上，而且在主机模式之外，容器 IP 空间对于该机器外部是不可用的。连接跨越两台机器的容器然后需要进行 **NAT** 和 **端口映射** 以进行通信。

# Docker 用户定义的网络

为了解决跨机器通信问题并提供更大的灵活性，Docker 还通过网络插件支持用户定义的网络。这些网络独立于容器本身存在。通过这种方式，容器可以加入相同的现有 **网络**。通过新的插件架构，可以为不同的网络用例提供各种驱动程序。

这些中的第一个是 **bridge** 驱动程序，它允许创建与默认桥接网络类似的网络。

第二个是 **overlay** 驱动程序。为了跨多个主机进行协调，它们都必须就可用网络及其拓扑达成一致。覆盖驱动程序使用分布式键值存储来在多个主机之间同步网络创建。

Docker 还支持一个 **Macvlan** 驱动程序，该驱动程序使用主机上的接口和子接口。Macvlan 提供了更有效的网络虚拟化和隔离，因为它绕过了 Linux 桥接。

插件机制将允许 Docker 中的各种网络可能性。事实上，许多第三方选项，如 Weave，已经创建了自己的 Docker 网络插件。

# Weave

**Weave** 为 Docker 容器提供了覆盖网络。它可以作为新的 Docker 网络插件接口的插件使用，并且还与 Kubernetes 兼容通过 CNI 插件。像许多覆盖网络一样，许多人批评封装开销对性能的影响。请注意，他们最近添加了一个具有 **Virtual Extensible LAN** (**VXLAN**) 封装支持的预览版本，这极大地提高了性能。欲了解更多信息，请访问 [`blog.weave.works/2015/06/12/weave-fast-datapath/`](http://blog.weave.works/2015/06/12/weave-fast-datapath/)。

# Flannel

**Flannel** 来自 CoreOS，是一个由 etcd 支持的覆盖层。Flannel 为每个主机/节点提供了一个完整的子网，使得与 Kubernetes 实践中每个 pod 或一组容器的可路由 IP 类似的模式成为可能。Flannel 包括一个内核中的 VXLAN 封装模式，以提高性能，并且具有类似于覆盖层 Docker 插件的实验性多网络模式。欲了解更多信息，请访问 [`github.com/coreos/flannel`](https://github.com/coreos/flannel)。

# Project Calico

**Project Calico** 是一个基于层 3 的网络模型，它使用 Linux 内核的内置路由功能。路由通过 **边界网关协议** (**BGP**) 传播到每个主机上的虚拟路由器。Calico 可用于从小规模部署到大规模互联网安装的任何用途。因为它在网络堆栈的较低级别工作，所以不需要额外的 NAT、隧道或覆盖层。它可以直接与底层网络基础设施交互。此外，它支持网络级 ACL 以提供额外的隔离和安全性。欲了解更多信息，请访问以下网址：[`www.projectcalico.org/`](http://www.projectcalico.org/)。

# Canal

**Canal** 将 Calico 的网络策略和 Flannel 的覆盖层合并为一个解决方案。它支持 Calico 和 Flannel 类型的覆盖层，并使用 Calico 的策略执行逻辑。用户可以从这个设置中选择覆盖层和非覆盖层选项，因为它结合了前两个项目的功能。欲了解更多信息，请访问以下网址：

[`github.com/tigera/canal`](https://github.com/tigera/canal)

# 平衡设计

强调 Kubernetes 正在尝试通过将 IP 放置在 pod 级别来实现的平衡是很重要的。在主机级别使用唯一的 IP 地址存在问题，因为容器数量增加。必须使用端口来公开特定容器上的服务并允许外部通信。除此之外，运行可能知道或不知道彼此（及其自定义端口）的多个服务并管理端口空间的复杂性成为一个重大问题。

但是，为每个容器分配一个 IP 地址可能过度。在规模可观的情况下，需要使用覆盖网络和 NAT 来解决每个容器的问题。覆盖网络会增加延迟，并且 IP 地址也将被后端服务占用，因为它们需要与其前端对等体进行通信。

在这里，我们真正看到 Kubernetes 在应用程序和服务级别提供的抽象优势。如果我有一个 Web 服务器和一个数据库，我们可以将它们保留在同一个 pod 中并使用单个 IP 地址。Web 服务器和数据库可以使用本地接口和标准端口进行通信，而不需要自定义设置。此外，后端的服务不会被不必要地暴露给在集群中其他地方运行的其他应用程序堆栈（但可能在同一主机上）。由于 pod 看到的是应用程序在其中运行时所看到的相同 IP 地址，因此服务发现不需要任何额外的转换。

如果您需要覆盖网络的灵活性，仍然可以在 pod 级别使用覆盖层。Weave、Flannel 和 Project Calico 以及现在可用的大量其他插件和覆盖层都可以与 Kubernetes 一起使用。

这在调度工作负载的背景下也非常有帮助。对于调度器来说，拥有一个简单且标准的结构来匹配约束并了解集群网络上任何给定时间的空间是至关重要的。这是一个具有各种应用程序和任务的动态环境，因此在这里增加额外的复杂性会产生连锁效应。

还涉及服务发现的影响。上线的新服务必须确定并注册一个 IP 地址，其他服务或至少集群可以通过该 IP 地址访问它们。如果使用了 NAT，服务将需要另一个机制来学习其外部可访问的 IP。

# 高级服务

让我们探讨与服务和容器之间通信相关的 IP 策略。如果你还记得，在*服务*部分，第二章 *Pods, Services, Replication Controllers, and Labels*，你学到 Kubernetes 使用 kube-proxy 来确定为每个请求提供服务的正确 pod IP 地址和端口。在幕后，kube-proxy 实际上是使用虚拟 IP 和 iptables 来使所有这些魔法工作。

Kube-proxy 现在有两种模式——*用户空间*和*iptables*。截至目前，1.2 版本中 iptables 是默认模式。在两种模式下，kube-proxy 都在每个主机上运行。它的首要职责是监视来自 Kubernetes 主节点的 API。对服务的任何更新都将触发从 kube-proxy 到 iptables 的更新。例如，当创建新服务时，将选择一个虚拟 IP 地址并设置 iptables 中的规则，该规则将通过一个随机端口将其流量定向到 kube-proxy。因此，我们现在有一种方法来捕获此节点上面向服务的流量。由于 kube-proxy 在所有节点上运行，因此我们在整个集群范围内解析服务的 VIP（**虚拟 IP**）也是可能的。此外，DNS 记录也可以指向此 VIP。

在用户空间模式中，我们在 iptables 中创建了一个钩子，但流量的代理仍然由 kube-proxy 处理。此时 iptables 规则只是将流量发送到 kube-proxy 中的服务条目。一旦 kube-proxy 收到特定服务的流量，它必须将其转发到服务候选池中的一个 pod。它使用的是在服务创建过程中选择的随机端口进行此操作。请参考以下图表，了解流程概述：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_01.png)

Kube-proxy 通信

对于你的服务定义中使用`sessionAffinity`元素，始终将来自相同客户端 IP 的流量转发到相同的后端 pod/container 是可能的。

在 iptables 模式中，Pod 直接编码在 iptables 规则中。这消除了对 kube-proxy 实际代理流量的依赖。请求将直接发送到 iptables，然后转发到 Pod。这样做更快，也消除了一个可能的故障点。如我们在*健康检查*部分中讨论的那样，就像您的朋友一样，此模式还丢失了重试 Pod 的能力。

# 外部服务

在上一章中，我们看到了一些服务示例。出于测试和演示目的，我们希望所有服务都可以从外部访问。这是通过我们服务定义中的`type: LoadBalancer`元素进行配置的。`LoadBalancer`类型在云提供商上创建外部负载均衡器。我们应该注意，外部负载均衡器的支持因提供商而异，实现也有所不同。在我们的情况下，我们正在使用 GCE，因此集成非常顺利。唯一需要的额外设置是为外部服务端口打开防火墙规则。

让我们再深入一点，在第二章中的*标签更多内容*部分对其中一个服务进行`describe`命令：

```
$ kubectl describe service/node-js-labels

```

以下是上述命令的结果截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_02.png)

服务描述

在上述图中的输出中，您会注意到几个关键元素。我们的`Namespace:`设置为`default`，`Type:`为`LoadBalancer`，并且我们在`LoadBalancer Ingress:`下列出了外部 IP。此外，我们看到了`Endpoints:`，它显示了可用于响应服务请求的 Pod 的 IP。

# 内部服务

让我们深入了解我们可以部署的其他类型的服务。首先，默认情况下，服务只面向内部。您可以指定`clusterIP`类型来实现此目的，但是，如果未定义类型，则`clusterIP`是假定的类型。让我们看一个例子；请注意缺少`type`元素：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-internal 
  labels: 
    name: node-js-internal 
spec: 
  ports: 
  - port: 80 
  selector: 
    name: node-js 

```

*清单 3-1*：`nodejs-service-internal.yaml`

使用此清单创建服务定义文件。您将需要一个健康的`node-js` RC 版本（*清单 2-7*：`nodejs-health-controller-2.yaml`）。正如您所见，选择器匹配我们在前一章中启动的名为`node-js`的 Pod。我们将创建服务，然后使用过滤器列出当前运行的服务：

```
$ kubectl create -f nodejs-service-internal.yaml
$ kubectl get services -l name=node-js-internal

```

以下是上述命令的结果截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_03.png)

内部服务列表

如您所见，我们有一个新的服务，但只有一个 IP。此外，IP 地址无法从外部访问。这次我们无法从 Web 浏览器测试服务。但是，我们可以使用便捷的`kubectl exec`命令，并尝试从其他一些 Pod 连接。您需要运行`node-js-pod`（*清单 2-1*：`nodejs-pod.yaml`）。然后，您可以执行以下命令：

```
$ kubectl exec node-js-pod -- curl <node-js-internal IP>

```

这使我们能够像在 `node-js-pod` 容器中有一个 shell 一样运行 `docker exec` 命令。然后它命中内部服务 URL，该 URL 转发到具有 `node-js` 标签的任何 pod。

如果一切正常，您应该会得到原始 HTML 输出。因此，您成功创建了一个仅内部可用的服务。这对于您希望向集群中运行的其他容器提供的后端服务可能会有用，但不对整个世界开放。

# 自定义负载均衡

K8s 允许的第三种服务类型是 `NodePort` 类型。这种类型允许我们通过特定端口在主机或节点（minion）上暴露服务。通过这种方式，我们可以使用任何节点（minion）的 IP 地址，并在分配的节点端口上访问我们的服务。Kubernetes 将默认在 `3000`-`32767` 范围内分配节点端口，但您也可以指定自己的自定义端口。在 *清单 3-2* 中的示例中，我们选择端口 `30001`，如下所示：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-nodeport 
  labels: 
    name: node-js-nodeport 
spec: 
  ports: 
  - port: 80 
    nodePort: 30001 
  selector: 
    name: node-js 
  type: NodePort 

```

*清单 3-2*：`nodejs-service-nodeport.yaml`

再次，创建此 YAML 定义文件并创建您的服务，如下所示：

```
$ kubectl create -f nodejs-service-nodeport.yaml

```

输出应该有类似以下的消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_04.png)

新的 GCP 防火墙规则

您会注意到有关打开防火墙端口的消息。与外部负载均衡器类型类似，`NodePort` 使用节点上的端口将您的服务外部暴露出来。例如，如果您想在节点前面使用自己的负载均衡器，则这可能很有用。在测试新服务之前，让我们确保在 GCP 上打开这些端口。

从 GCE VM 实例控制台，点击任何节点（minion）的详细信息。然后点击网络，通常是默认的，除非在创建时另有规定。在防火墙规则中，我们可以通过单击添加防火墙规则来添加规则。

创建一个规则，如下图所示（`tcp:30001` 在 `0.0.0.0/0` IP 范围上）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_05.png)

创建新的 GCP 防火墙规则

现在我们可以通过打开浏览器并使用集群中任何节点（minion）的 IP 地址来测试我们的新服务。测试新服务的格式如下：

`http://<Minoion IP 地址>:<NodePort>/`

最后，最新版本添加了 `ExternalName` 类型，它将 CNAME 映射到服务。

# 跨节点代理

记住，kube-proxy 在所有节点上运行，因此，即使 pod 在那里没有运行，流量也会被代理到适当的主机。参考*跨节点流量*图以了解流量如何流动。用户向外部 IP 或 URL 发出请求。此时请求由**节点**处理。然而，该 pod 恰好没有在此节点上运行。这并不是问题，因为 pod IP 地址是可路由的。因此，**Kube-proxy** 或 **iptables** 简单地将流量传递到此服务的 pod IP。然后网络路由完成在 **节点 2** 上，请求的应用程序驻留在那里：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_06.png)

跨节点流量

# 自定义端口

服务还允许你将流量映射到不同的端口；然后容器和 pod 将自己暴露出来。我们将创建一个服务，将流量暴露到 `90` 端口并转发到 pod 上的 `80` 端口。我们将称这个 pod 为 `node-js-90` 来反映自定义端口号。创建以下两个定义文件：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-90 
  labels: 
    name: node-js-90 
spec: 
  replicas: 3 
  selector: 
    name: node-js-90 
  template: 
    metadata: 
      labels: 
        name: node-js-90 
    spec: 
      containers: 
      - name: node-js-90 
        image: jonbaier/node-express-info:latest 
        ports: 
        - containerPort: 80 

```

*清单 3-3*: `nodejs-customPort-controller.yaml`

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-90 
  labels: 
    name: node-js-90 
spec: 
  type: LoadBalancer 
  ports: 
  - port: 90 
    targetPort: 80 
  selector: 
    name: node-js-90 

```

*清单 3-4*: `nodejs-customPort-service.yaml`

你会注意到在服务定义中，我们有一个 `targetPort` 元素。这个元素告诉服务使用池中的 pod/容器的端口。就像我们在之前的例子中看到的，如果你不指定 `targetPort`，它会假定与服务相同的端口。这个端口仍然被用作服务端口，但是在这种情况下，我们将在 `90` 端口上暴露服务，而容器则在 `80` 端口上提供内容。

创建这个 RC 和服务并打开适当的防火墙规则，就像我们在上一个示例中所做的一样。外部负载均衡器 IP 可能需要一段时间才能传播到 `get service` 命令。一旦传播完成，你就应该能够以以下格式在浏览器中打开并查看我们熟悉的 web 应用程序：

`http://<external service IP>:90/`

# 多个端口

另一个自定义端口的用例是多个端口的情况。许多应用程序会暴露多个端口，比如 `80` 端口上的 HTTP 和 `8888` 端口上的 web 服务器。下面的示例展示了我们的应用同时在这两个端口上响应。再次强调，我们还需要为这个端口添加防火墙规则，就像我们之前为 *清单 3-2*: `nodejs-service-nodeport.yaml` 做的一样：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: node-js-multi 
  labels: 
    name: node-js-multi 
spec: 
  replicas: 3 
  selector: 
    name: node-js-multi 
  template: 
    metadata: 
      labels: 
        name: node-js-multi 
    spec: 
      containers: 
      - name: node-js-multi 
        image: jonbaier/node-express-multi:latest 
        ports: 
        - containerPort: 80 
        - containerPort: 8888 

```

*清单 3-5*: `nodejs-multi-controller.yaml`

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-multi 
  labels: 
    name: node-js-multi 
spec: 
  type: LoadBalancer 
  ports: 
  - name: http 
    protocol: TCP 
    port: 80 
  - name: fake-admin-http 
    protocol: TCP 
    port: 8888 
  selector: 
    name: node-js-multi 

```

*清单 3-6*: `nodejs-multi-service.yaml`

应用程序和容器本身必须同时监听这两个端口才能工作。在这个例子中，端口 `8888` 被用来表示一个虚假的管理员界面。

例如，如果你想监听 `443` 端口，你需要在服务器上使用适当的 SSL 套接字进行监听。

# 内部访问

我们之前讨论过 Kubernetes 如何使用服务抽象来代理分布在集群中的后端 pod 的流量。虽然这在扩展和 pod 恢复方面都很有帮助，但是这种设计并没有解决更高级的路由场景。

为此，Kubernetes 添加了一个 Ingress 资源，允许对后端服务进行自定义代理和负载均衡。可以把它想象成在流量到达我们的服务之前的路由路径中的一个额外层或跳跃。就像一个应用程序有一个服务和支持的 pod 一样，Ingress 资源需要一个 Ingress 入口点和一个执行自定义逻辑的 Ingress 控制器。入口点定义了路由，控制器实际处理路由。在我们的示例中，我们将使用默认的 GCE 后端。

使用 Ingress API 时需要注意的一些限制可以在这里找到：

[`github.com/kubernetes/contrib/blob/master/ingress/controllers/gce/BETA_LIMITATIONS.md`](https://github.com/kubernetes/contrib/blob/master/ingress/controllers/gce/BETA_LIMITATIONS.md)

你可能还记得，在第一章，*Kubernetes 简介* 中，我们看到 GCE 集群附带了一个默认的后端，提供了第 7 层负载均衡能力。如果我们查看 `kube-system` 命名空间，我们可以看到这个控制器正在运行：

```
$ kubectl get rc --namespace=kube-system

```

我们应该看到一个 RC 列出了 `l7-default-backend-v1.0` 的名称，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_07.png)

GCE Layer 7 Ingress 控制器

这提供了实际路由在我们 Ingress 入口点中定义的流量的 Ingress 控制器部分。让我们为 Ingress 创建一些资源。

首先，我们将使用我的 `httpwhalesay` 镜像创建几个新的复制控制器。这是原始的 whalesay 的一次混音，可以在浏览器中显示。以下清单显示了 YAML。请注意三个破折号，让我们将多个资源组合成一个 YAML 文件：

```
apiVersion: v1
kind: ReplicationController
metadata:
  name: whale-ingress-a
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: whale-ingress-a
    spec:
      containers:
      - name: sayhey
        image: jonbaier/httpwhalesay:0.1
        command: ["node", "index.js", "Whale Type A, Here."]
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: ReplicationController
metadata:
  name: whale-ingress-b
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: whale-ingress-b
    spec:
      containers:
      - name: sayhey
        image: jonbaier/httpwhalesay:0.1
        command: ["node", "index.js", "Hey man, It's Whale B, Just
        Chillin'."]
        ports:
        - containerPort: 80

```

*清单 3-7.* `whale-rcs.yaml`

请注意，我们正在创建具有相同容器的 pod，但具有不同的启动参数。记下这些参数以备后用。我们还将为这些 RC 的每一个创建 `Service` 端点：

```
apiVersion: v1
kind: Service
metadata:
  name: whale-svc-a
  labels:
    app: whale-ingress-a
spec:
  type: NodePort
  ports:
  - port: 80
    nodePort: 30301
    protocol: TCP
    name: http
  selector:
    app: whale-ingress-a
---
apiVersion: v1
kind: Service
metadata:
  name: whale-svc-b
  labels:
    app: whale-ingress-b
spec:
  type: NodePort
  ports:
  - port: 80
    nodePort: 30284
    protocol: TCP
    name: http
  selector:
    app: whale-ingress-b
---
apiVersion: v1
kind: Service
metadata:
 name: whale-svc-default
 labels:
   app: whale-ingress-a
spec:
  type: NodePort
  ports:
  - port: 80
    nodePort: 30302
    protocol: TCP
    name: http
  selector:
    app: whale-ingress-a

```

*清单 3-8.* `whale-svcs.yaml`

再次使用 `kubectl create -f` 命令创建这些，如下所示：

```
$ kubectl create -f whale-rcs.yaml $ kubectl create -f whale-svcs.yaml

```

我们应该看到关于 RC 和 Service 成功创建的消息。接下来，我们需要定义 Ingress 入口点。我们将使用 `http://a.whale.hey` 和 `http://b.whale.hey` 作为我们的演示入口点：

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: whale-ingress
spec:
  rules:
  - host: a.whale.hey
    http:
      paths:
      - path: /
        backend:
          serviceName: whale-svc-a
          servicePort: 80
  - host: b.whale.hey
    http:
      paths:
      - path: /
        backend:
          serviceName: whale-svc-b
          servicePort: 80

```

*清单 3-9.* `whale-ingress.yaml`

再次使用 `kubectl create -f` 来创建此 Ingress。一旦成功创建，我们需要等待几分钟让 GCE 给 Ingress 一个静态 IP 地址。使用以下命令来观察 Ingress 资源：

```
$ kubectl get ingress

```

一旦 Ingress 有了 IP，我们应该在 `ADDRESS` 中看到一个条目，像这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_08.png)

Ingress 描述

由于这不是一个注册的域名，我们需要在 `curl` 命令中指定解析，就像这样：

```
$ curl --resolve a.whale.hey:80:130.211.24.177 http://a.whale.hey/

```

这应该显示如下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_09.png)

Whalesay A

我们也可以尝试第二个 URL，并获得我们的第二个 RC：

```
$ curl --resolve b.whale.hey:80:130.211.24.177 http://b.whale.hey/

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_10.png)

Whalesay B

我们注意到图像几乎相同，只是每个鲸的字样反映了我们先前启动的每个 RC 的启动参数。因此，我们的两个 Ingress 点将流量引导到不同的后端。

在这个例子中，我们使用了默认的 GCE 后端作为 Ingress 控制器。Kubernetes 允许我们自己构建，而 Nginx 实际上也有几个版本可用。

# 迁移、多集群等

正如你到目前为止所见，Kubernetes 提供了高度的灵活性和定制化，可以在集群中运行的容器周围创建服务抽象。但是，可能会有时候你想要指向集群外的某些东西。

这种情况的一个示例是与遗留系统或者甚至运行在另一个集群上的应用程序一起工作。就前者而言，在迁移到 Kubernetes 和容器的过程中，这是一个非常好的策略。我们可以开始在 Kubernetes 中管理服务端点，同时使用 K8s 编排概念来组装整个堆栈。此外，随着组织对应用程序进行了微服务和/或容器化的重构，我们甚至可以逐步地将堆栈的部分（如前端）带入。

为了允许访问非基于 Pod 的应用程序，服务构建允许您使用在集群外的端点。实际上，每次创建使用选择器的服务时，Kubernetes 都会创建一个端点资源。`endpoints` 对象跟踪负载平衡池中的 Pod IP。您可以通过运行 `get endpoints` 命令来查看，如下所示：

```
$ kubectl get endpoints

```

你应该会看到类似这样的内容：

```
NAME               ENDPOINTS
http-pd            10.244.2.29:80,10.244.2.30:80,10.244.3.16:80
kubernetes         10.240.0.2:443
node-js            10.244.0.12:80,10.244.2.24:80,10.244.3.13:80

```

你会注意到我们当前在集群上运行的所有服务都有一个条目。对于大多数服务，端点只是运行在 RC 中的每个 Pod 的 IP。正如我之前提到的，Kubernetes 根据选择器自动执行此操作。当我们在具有匹配标签的控制器中扩展副本时，Kubernetes 将自动更新端点。

如果我们想为不是 Pod 的东西创建一个服务，因此没有标签可供选择，我们可以很容易地通过服务和端点定义来实现，如下所示：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: custom-service 
spec: 
  type: LoadBalancer 
  ports: 
  - name: http 
    protocol: TCP 
    port: 80 

```

*清单 3-10*：`nodejs-custom-service.yaml`

```
apiVersion: v1 
kind: Endpoints 
metadata: 
  name: custom-service 
subsets: 
- addresses: 
  - ip: <X.X.X.X> 
  ports: 
    - name: http 
      port: 80 
      protocol: TCP 

```

*清单 3-11*：`nodejs-custom-endpoint.yaml`

在上面的示例中，您需要用实际 IP 地址替换 `<X.X.X.X>`，新服务可以指向该地址。在我的案例中，我使用了我们之前在 *清单 3-6* 中创建的 `node-js-multi` 服务的公共负载均衡器 IP。现在就去创建这些资源吧。

如果我们现在运行一个 `get endpoints` 命令，我们将看到这个 IP 地址关联到 `custom-service` 端点的 `80` 端口。此外，如果我们查看服务详情，我们将在 `Endpoints` 部分中看到列出的 IP： 

```
$ kubectl describe service/custom-service

```

我们可以通过在浏览器中打开 `custom-service` 的外部 IP 来测试这项新服务。

# 自定义寻址

另一个自定义服务的选项是使用 `clusterIP` 元素。到目前为止，在我们的示例中，我们还没有指定 IP 地址，这意味着它会为我们选择服务的内部地址。然而，我们可以添加这个元素并提前选择 IP 地址，例如使用 `clusterip: 10.0.125.105`。

有时您可能不想负载平衡，而是更愿意为每个 Pod 使用带有 *A* 记录的 DNS。例如，需要将数据均匀复制到所有节点的软件可能依赖于 *A* 记录来分发数据。在这种情况下，我们可以使用以下示例，并将 `clusterip` 设置为 `None`。 Kubernetes 将不会分配 IP 地址，而是仅为每个 Pod 在 DNS 中分配 *A* 记录。如果您使用 DNS，则服务应该可以从集群内的 `node-js-none` 或 `node-js-none.default.cluster.local` 访问。我们有以下代码：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: node-js-none 
  labels: 
    name: node-js-none 
spec: 
  clusterIP: None 
  ports: 
  - port: 80 
  selector: 
    name: node-js 

```

*清单 3-12*：`nodejs-headless-service.yaml`

创建此服务后，请使用可靠的 `exec` 命令进行测试：

```
$ kubectl exec node-js-pod -- curl node-js-none

```

# 服务发现

正如我们之前讨论的，Kubernetes 主节点会跟踪所有服务定义和更新。发现可以通过以下三种方式之一进行。前两种方法使用 Linux 环境变量。支持 Docker 链接样式的环境变量，但 Kubernetes 也有其自己的命名约定。这是使用 K8s 环境变量的示例，我们的 `node-js` 服务示例可能看起来像这样（注意 IP 可能会有所不同）：

```
NODE_JS_PORT_80_TCP=tcp://10.0.103.215:80
NODE_JS_PORT=tcp://10.0.103.215:80
NODE_JS_PORT_80_TCP_PROTO=tcp
NODE_JS_PORT_80_TCP_PORT=80
NODE_JS_SERVICE_HOST=10.0.103.215
NODE_JS_PORT_80_TCP_ADDR=10.0.103.215
NODE_JS_SERVICE_PORT=80

```

*清单 3-13*：*服务环境变量*

通过 DNS 进行发现的另一种选择。虽然环境变量在 DNS 不可用时可能很有用，但它也有缺点。系统仅在创建时创建变量，因此稍后启动的服务将无法发现，或者需要一些额外的工具来更新所有系统环境。

# DNS

DNS 通过允许我们通过名称引用服务来解决使用环境变量时出现的问题。随着服务重新启动、扩展或出现新的情况，DNS 条目将被更新，确保服务名称始终指向最新的基础架构。在大多数支持的提供商中，默认设置了 DNS。

如果您的提供商支持 DNS，但尚未设置，则在创建 Kubernetes 集群时，您可以在默认提供商配置中配置以下变量：

`ENABLE_CLUSTER_DNS="${KUBE_ENABLE_CLUSTER_DNS:-true}"` `DNS_SERVER_IP="10.0.0.10"`

`DNS_DOMAIN="cluster.local"`

`DNS_REPLICAS=1`

使用 DNS 时，服务可以以两种形式之一访问-要么是服务名称本身，`<service-name>`，要么是包含命名空间的完全限定名称，`<service-name>.<namespace-name>.cluster.local`。在我们的示例中，它看起来类似于 `node-js-90` 或 `node-js-90.default.cluster.local`。

# 多租户

Kubernetes 还具有在集群级别进行隔离的附加结构。在大多数情况下，您可以运行 Kubernetes 而不必担心命名空间；如果未指定，所有内容都将在默认命名空间中运行。但是，在运行多租户社区或希望对集群资源进行广泛分离和隔离的情况下，可以使用命名空间来实现此目的。

首先，Kubernetes 有两个命名空间——`default`和`kube-system`。`kube-system`命名空间用于所有在第一章中看到的系统级容器，在*运行在节点上的服务*节中。用户创建的所有其他内容都在默认命名空间中运行。但是，用户的资源定义文件可以选择指定自定义命名空间。为了进行实验，让我们看看如何构建一个新的命名空间。

首先，我们需要创建一个命名空间定义文件，就像这个清单中的一个：

```
apiVersion: v1 
kind: Namespace 
metadata: 
  name: test 

```

*清单 3-14*：`test-ns.yaml`

我们可以使用我们方便的`create`命令来创建这个文件：

```
$ kubectl create -f test-ns.yaml

```

现在我们可以创建使用`test`命名空间的资源。以下是一个使用这个新命名空间的 pod 的示例：

```
apiVersion: v1 
kind: Pod 
metadata: 
  name: utility 
  namespace: test 
spec: 
  containers: 
  - image: debian:latest 
    command: 
      - sleep 
      - "3600" 
    name: utility 

```

*清单 3-15*：`ns-pod.yaml`

虽然 pod 仍然可以访问其他命名空间中的服务，但它需要使用长 DNS 格式的`<service-name>.<namespace-name>.cluster.local`。例如，如果您要从*清单 3-15*：`ns-pod.yaml`内的容器中运行一个命令，您可以使用`node-js.default.cluster.local`访问第二章中的 Node.js 示例，*Pods, Services, Replication Controllers, and Labels*。

这里有一个关于资源利用的注记。在本书的某个时候，您可能会在集群上耗尽空间以创建新的 Kubernetes 资源。这个时机会根据集群的大小而变化，但请记住定期进行一些清理是很好的。使用以下命令删除旧的示例：

`**$ kubectl delete pod <pod name>** **$ kubectl delete svc <service name>** **$ kubectl delete rc <replication controller name>** ** $ kubectl delete rs <replicaset name>**`

# 限制

让我们更详细地检查一下我们的新命名空间。执行如下`describe`命令：

```
$ kubectl describe namespace/test

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_11.png)

命名空间描述

Kubernetes 允许您限制单个 pod 或容器使用的资源以及整个命名空间使用的资源。请注意，`test`命名空间目前没有设置资源**限制**或**配额**。

假设我们想要限制这个新命名空间的占地面积；我们可以设置如下的配额：

```
apiVersion: v1 
kind: ResourceQuota 
metadata: 
  name: test-quotas 
  namespace: test 
spec: 
  hard:  
    pods: 3 
    services: 1 
    replicationcontrollers: 1 

```

*清单 3-16*：`quota.yaml`

实际上，命名空间将用于更大的应用程序社区，可能永远不会有这么低的配额。我之所以使用这个例子，是为了更轻松地说明示例中的功能。

在这里，我们将为测验命名空间创建一个`3`个 pod、`1`个 RC 和`1`个服务的配额。正如你可能猜到的那样，这又一次由我们值得信赖的`create`命令执行：

```
$ kubectl create -f quota.yaml

```

现在我们已经做好了，让我们对命名空间使用`describe`，如下所示：

```
$ kubectl describe namespace/test

```

以下截图是上述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_12.png)

在设置配额后的命名空间描述

您会注意到现在在配额部分列出了一些值，而限制部分仍然为空白。我们还有一个`Used`列，它让我们知道我们当前离限制有多近。让我们尝试使用以下定义来启动一些 pod：

```
apiVersion: v1 
kind: ReplicationController 
metadata: 
  name: busybox-ns 
  namespace: test 
  labels: 
    name: busybox-ns 
spec: 
  replicas: 4 
  selector: 
    name: busybox-ns 
  template: 
    metadata: 
      labels: 
        name: busybox-ns 
    spec: 
      containers: 
      - name: busybox-ns 
        image: busybox 
        command: 
          - sleep 
          - "3600" 

```

*列表 3-17*：`busybox-ns.yaml`

您会注意到我们正在创建此基本 pod 的四个副本。在使用`create`构建此 RC 后，再次在`test`命名空间上运行`describe`命令。您会注意到 pod 和 RC 的`Used`值已达到最大值。然而，我们要求四个副本，但只看到三个正在使用的 pod。

让我们看看我们的 RC 正在发生什么。您可以尝试使用此处的命令来执行此操作：

```
kubectl describe rc/busybox-ns

```

但是，如果你尝试，你会受挫于从服务器收到的`not found`消息。这是因为我们在一个新的命名空间创建了这个 RC，如果没有指定，`kubectl`会假定默认命名空间。这意味着我们在访问`test`命名空间中的资源时需要在每个命令中指定`--namepsace=test`。

我们还可以通过处理上下文设置来设置当前命名空间。首先，我们需要找到我们的当前上下文，这是通过以下命令找到的：

`**$ kubectl config view | grep current-context**`

接下来，我们可以获取该上下文并设置命名空间变量如下：

`**$ kubectl config set-context <当前上下文> --namespace=test**`

现在您可以运行`kubectl`命令而无需指定命名空间。只需记住在想要查看运行在默认命名空间中的资源时切换回来即可。

使用指定了命名空间的命令运行。如果您已按提示框中所示设置了当前命名空间，可以省略`--namespace`参数：

```
$ kubectl describe rc/busybox-ns --namespace=test

```

下面的截图是前述命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/gtst-k8s-2e/img/B06302_03_13.png)

命名空间配额

如您在前面的图像中所见，前三个 pod 已成功创建，但我们的最后一个失败了，出现了`Limited to 3 pods`错误。

这是一种在社区规模上设置资源限制的简单方法。值得注意的是，您还可以设置 CPU、内存、持久卷和密钥的配额。此外，限制的工作方式与配额类似，但它们为命名空间内的每个 pod 或容器设置了限制。

# 关于资源使用的说明

由于本书中的大多数示例都使用 GCP 或 AWS，保持所有内容运行可能成本很高。如果使用默认的集群大小，尤其是如果保留每个示例运行，则很容易耗尽资源。因此，您可能希望定期删除旧的 pod、复制控制器、副本集和服务。您还可以销毁集群，并使用第一章——*介绍 Kubernetes*作为降低云服务提供商账单的方法。

# 摘要

我们深入研究了 Kubernetes 中的网络和服务。现在你应该了解了 K8s 中网络通信的设计，并且能够在内部和外部轻松访问你的服务。我们看到了 kube-proxy 如何在本地和整个集群中平衡流量。此外，我们探讨了新的 Ingress 资源，使我们能够更精细地控制流入流量。我们还简要地了解了 Kubernetes 中如何实现 DNS 和服务发现。最后，我们简单地看了一下多租户环境下的命名空间和隔离。

# 参考资料

1.  [`www.wired.com/2015/06/google-reveals-secret-gear-connects-online-empire/`](http://www.wired.com/2015/06/google-reveals-secret-gear-connects-online-empire/)
