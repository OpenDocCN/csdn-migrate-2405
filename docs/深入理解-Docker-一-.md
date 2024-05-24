# 深入理解 Docker（一）

> 原文：[`zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22`](https://zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第零章：关于本书

这是一本关于 Docker 的书。不需要先前的知识！这本书的座右铭是**一本书带你从零到掌握 Docker！**

如果你对 Docker 感兴趣，*想知道它是如何工作的以及如何正确操作*，这本书是专门为你准备的！

如果你只是想使用 Docker，并且不在乎是否搞错了，那这本书**不适合**你。

### 这个 Docker 认证专家是什么？

Docker 在 2017 年秋季发布了它的第一个专业认证。它被称为**Docker 认证专家（DCA）**，适用于希望证明他们掌握 Docker 技能的人。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure0-1.png)

考试目标与许多真实场景相匹配，因此我决定更新这本书，使其涵盖所有目标。在这样做的过程中，我非常努力地让这本书在现实世界中有趣且适用。

这不是一本应试书。是的，**它涵盖了所有考试主题**，但这是一本在现实世界中令人愉快的书。

在出版时，**这是唯一涵盖整套 DCA 考试目标的资源！**

祝你考试顺利！

### 纸质（平装）版本呢？

没有冒犯 Leanpub 和亚马逊 Kindle，但是尽管现代电子书很好，我仍然喜欢纸质书！因此……这本书可以通过亚马逊以高质量、全彩色的平装版出售。没有黑白的废话。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure0-2.png)

说到亚马逊……如果你能在亚马逊上写一篇快速评论，我会很高兴！即使你是在 Leanpub 上购买的书也可以这样做。谢谢！

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure0-3.png)

### 为什么我应该阅读这本书或关心 Docker？

Docker 已经出现了，没有必要隐藏。开发人员都在使用它，IT 运维人员需要保持竞争力！我们必须知道如何在业务关键环境中构建和支持生产质量的*容器化*应用程序。这本书会帮助你。

### Docker 只是为开发人员准备的吗？

如果你认为 Docker 只是为开发人员准备的，那么准备好颠覆你的世界吧！

*容器化* 应用程序需要一个运行的地方和一个管理它们的人。如果你认为开发人员会做到这一点，那你就是在做梦。运维人员需要构建和运行高性能的生产级 Docker 基础设施。如果你是一个运维人员，但对 Docker 不熟悉，那你将面临巨大的压力。但不要担心，这本书会让你熟练掌握技能！

### 如果我已经观看了你的视频培训课程，我是否应该购买这本书？

是的。这本书通常更新，还涵盖了额外的材料。

如果你喜欢我的[视频课程](https://app.pluralsight.com/library/search?q=nigel+poulton)，你可能会喜欢这本书。如果你不喜欢我的视频课程，你可能不会喜欢这本书。

如果你还没有看过我的视频课程，你应该看一下！它们节奏快，有趣，并且得到了*热烈的好评！*

### 书的组织方式

我把这本书分成了两个部分：

+   大局观

+   技术内容

**大局观**部分涵盖了诸如：

+   Docker，Inc.是谁。

+   Docker（Moby）项目是什么。

+   OCI 是什么。

+   我们为什么需要容器…

这是你需要了解的内容，如果你想对 Docker 和容器有一个全面的了解。

**技术内容**部分是这本书的重点！这是你开始使用 Docker 所需的一切。它深入探讨了*镜像*、*容器*，以及越来越重要的*编排*主题。它甚至涵盖了企业喜欢的内容，比如 TLS、RBAC、AD 集成和备份。你将获得理论知识，以便了解它们如何相互关联，还会得到命令和示例，向你展示它们在实践中是如何运作的。

技术内容部分的大多数章节分为三个部分：

+   TLDR

+   深入了解

+   命令

TLDR 为您提供了两三段文字，您可以用它们在咖啡机旁解释这个话题。它们也是提醒自己某事内容的好方法。

深入了解是我们解释一切如何运作并且通过例子的地方。

*命令*列出了所有相关命令，以易于阅读的列表形式，并简要提醒每个命令的作用。

我觉得你会喜欢这种格式。

### 书的版本

Docker 正在以超快的速度发展！因此，这本书的价值与它的年龄成反比！换句话说… *这本书越旧，价值就越低。* **所以我会让这本书保持最新！**

**欢迎来到新常态！**

我们不再生活在一个一年前的书还有价值的世界。这让我作为作者的生活变得非常艰难。但这是真的！

不过别担心，你对这本书的投资是安全的！

如果您从**Amazon.com**购买平装书，您可以以非常便宜的价格获得 Kindle 版本，作为 Kindle MatchBook 计划的一部分！ Kindle MatchBook 是一项新服务，仅在 Amazon.com 上提供，并且有点故障。 如果您无法看到如何通过 MatchBook 获取 Kindle 版本，您需要联系 Kindle 支持-我无法帮助您处理此问题 :-(

Kindle 和 Leanpub 版本都可以免费获得所有更新！

这是我目前能做到的最好的！

以下是版本列表：

+   **版本 5.** 这是 2018 年 2 月 6 日发布的书的版本。 它包括约 200 页新内容，涵盖了所有 Docker 认证助理考试的主题。 该版本的书有了新的封面。

+   **版本 4.** 这是 2017 年 10 月 3 日发布的书的第 4 版。 该版本添加了一个名为“容器化应用程序”的新章节。 它还在**图像**章节中添加了关于*多架构图像*和*加密 ID*的内容，并在**大局观**章节中添加了一些额外内容。

+   **版本 3.** 添加了**Docker 引擎**章节。

+   **版本 2.** 添加了**Docker 中的安全性**章节。

+   **版本 1.** 初始版本。

### 在您的 Kindle 上遇到获取最新更新的问题吗？

我注意到 Kindle 并不总是下载书的最新版本。 为了解决这个问题：

访问 http://amzn.to/2l53jdg

在“快速解决方案”（左侧）下选择“数字购买”。 选择“内容和设备”以获取 Docker 深入解析订单。 您的书应该显示在列表中，并带有一个写着“可用更新”的按钮。 点击该按钮。 删除您的 Kindle 中的旧版本，并下载新版本。

如果这不起作用，请联系 Kindle 支持，他们将为您解决问题。https://kdp.amazon.com/en_US/self-publishing/contact-us/


# 第一部分：大局观的事情


# 第二章：从 3 万英尺高空看容器

容器绝对是一种“东西”。

在这一章中，我们将深入讨论一些问题：为什么我们需要容器，它们对我们有什么作用，以及我们在哪里可以使用它们。

### 糟糕的旧日子

应用程序推动业务。如果应用程序出现故障，业务也会出现故障。有时甚至会破产。这些说法每天都更加真实！

大多数应用程序在服务器上运行。在过去，我们只能在一台服务器上运行一个应用程序。Windows 和 Linux 的开放系统世界没有技术能够安全地在同一台服务器上运行多个应用程序。

所以，故事通常是这样的……每当业务需要一个新的应用程序时，IT 部门就会去购买一台新的服务器。而大多数情况下，没有人知道新应用程序的性能要求！这意味着在选择要购买的服务器型号和大小时，IT 部门必须进行猜测。

因此，IT 部门只能做一件事——购买具有很强韧性的大型服务器。毕竟，任何人都不想要的最后一件事，包括企业在内，就是服务器性能不足。性能不足的服务器可能无法执行交易，这可能导致失去客户和收入。因此，IT 部门通常会购买大型服务器。这导致大量服务器的潜在容量只有 5-10%左右。**这是对公司资本和资源的悲剧性浪费！**

### 你好，VMware！

在这一切之中，VMware 公司给世界带来了一份礼物——虚拟机（VM）。几乎一夜之间，世界变成了一个更美好的地方！我们终于有了一种技术，可以让我们在单个服务器上安全地运行多个业务应用程序。庆祝活动开始了！

这改变了游戏规则！IT 部门不再需要在业务要求新应用程序时每次都采购全新的超大型服务器。往往情况是，他们可以在现有的服务器上运行新的应用程序，这些服务器原本还有剩余的容量。

突然之间，我们可以从现有的企业资产中挤出大量的价值，比如服务器，这样公司的投资就能得到更大的回报。

### 虚拟机的缺点

但是……总会有一个“但是”！虚拟机虽然很棒，但远非完美！

每个虚拟机都需要专用的操作系统是一个重大缺陷。每个操作系统都会消耗 CPU、RAM 和存储空间，否则这些资源本可以用来运行更多的应用程序。每个操作系统都需要打补丁和监控。而且在某些情况下，每个操作系统都需要许可证。所有这些都是运营支出和资本支出的浪费。

VM 模型也面临其他挑战。虚拟机启动速度慢，可移植性不佳——在不同的虚拟化平台和云平台之间迁移和移动虚拟机工作负载比预期的更困难。

### 你好，容器！

长期以来，像谷歌这样的大型网络规模的参与者一直在使用容器技术来解决虚拟机模型的缺陷。

在容器模型中，容器大致类似于虚拟机。主要区别在于每个容器不需要自己的完整操作系统。事实上，单个主机上的所有容器共享一个操作系统。这释放了大量的系统资源，如 CPU、RAM 和存储。它还减少了潜在的许可成本，并减少了操作系统补丁和其他维护的开销。最终结果：在资本支出和运营支出方面节省了开支。

容器启动也很快，而且具有超高的可移植性。将容器工作负载从笔记本电脑移动到云端，然后再移动到虚拟机或裸金属在数据中心中都非常容易。

### Linux 容器

现代容器起源于 Linux 世界，是许多人长期努力工作的成果。举一个例子，Google LLC 为 Linux 内核贡献了许多与容器相关的技术。没有这些以及其他的贡献，我们今天就不会有现代容器。

近年来推动容器大规模增长的一些主要技术包括：**内核命名空间**、**控制组**、**联合文件系统**，当然还有**Docker**。再次强调之前所说的——现代容器生态系统深受许多个人和组织的影响，他们为我们当前所建立的坚实基础做出了巨大贡献。谢谢！

尽管如此，容器仍然复杂，并且超出了大多数组织的范围。直到 Docker 出现，容器才真正实现了民主化，并且为大众所能接触。

> * 有许多类似于容器的操作系统虚拟化技术，早于 Docker 和现代容器。有些甚至可以追溯到主机上的 System/360。BSD Jails 和 Solaris Zones 是一些其他众所周知的 Unix 类型容器技术的例子。然而，在本书中，我们将限制我们的讨论和评论在 Docker 所推广的*现代容器*上。

### 你好，Docker！

我们将在下一章更详细地讨论 Docker。但现在，可以说 Docker 是使 Linux 容器对普通人可用的魔法。换句话说，Docker，Inc.让容器变得简单！

### Windows 容器

在过去的几年里，微软公司非常努力地将 Docker 和容器技术带到 Windows 平台上。

在撰写本文时，Windows 容器可用于 Windows 10 和 Windows Server 2016 平台。在实现这一点时，微软与 Docker，Inc.和社区密切合作。

实现容器所需的 Windows 核心内核技术统称为*Windows 容器*。用于处理这些*Windows 容器*的用户空间工具是 Docker。这使得 Windows 上的 Docker 体验几乎与 Linux 上的 Docker 完全相同。这样，熟悉来自 Linux 平台的 Docker 工具集的开发人员和系统管理员将感到在使用 Windows 容器时如同在家一样。

**本书的修订版本包括了许多实验练习的 Linux 和 Windows 示例。**

### Windows 容器与 Linux 容器

重要的是要理解，运行的容器共享其所在主机的内核。这意味着设计为在具有 Windows 内核的主机上运行的容器化应用程序将无法在 Linux 主机上运行。这意味着您可以在高层次上这样考虑——Windows 容器需要 Windows 主机，而 Linux 容器需要 Linux 主机。然而，事情并不那么简单…

在撰写本文时，可以在 Windows 机器上运行 Linux 容器。例如，*Docker for Windows*（Docker，Inc.为 Windows 10 设计的产品）可以在*Windows 容器*和*Linux 容器*之间切换模式。这是一个发展迅速的领域，您应该查阅 Docker 文档以获取最新信息。

### Mac 容器呢？

目前还没有 Mac 容器这样的东西。

但是，您可以使用*Docker for Mac*在 Mac 上运行 Linux 容器。这通过在 Mac 上无缝运行您的容器在轻量级 Linux 虚拟机内实现。这在开发人员中非常受欢迎，他们可以轻松地在 Mac 上开发和测试他们的 Linux 容器。

### Kubernetes 呢？

Kubernetes 是 Google 的一个开源项目，迅速成为容器化应用程序的主要编排器。这只是一种花哨的说法，*Kubernetes 是一个重要的软件，帮助我们部署我们的容器化应用程序并使其保持运行*。

在撰写本文时，Kubernetes 使用 Docker 作为其默认容器运行时 - Kubernetes 的一部分，用于启动和停止容器，以及拉取镜像等。然而，Kubernetes 具有可插拔的容器运行时接口，称为 CRI。这使得很容易将 Docker 替换为不同的容器运行时。在未来，Docker 可能会被`containerd`替换为 Kubernetes 中的默认容器运行时。本书后面会更多介绍`containerd`。

目前，关于 Kubernetes 需要知道的重要事情是，它是一个比 Docker 更高级的平台，目前使用 Docker 进行其低级容器相关操作。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure1-1.png)

查看我的 Kubernetes 书和我的**Getting Started with Kubernetes** [视频培训课程](https://app.pluralsight.com/library/courses/getting-started-kubernetes/)，了解更多关于 Kubernetes 的信息。

### 章节总结

我们曾经生活在这样一个世界中，每当业务需要一个新的应用程序时，我们就必须为其购买全新的服务器。然后 VMware 出现了，使 IT 部门能够从新的和现有的公司 IT 资产中获得更多价值。但是，尽管 VMware 和虚拟机模型很好，但并不完美。在 VMware 和虚拟化技术的成功之后，出现了一种更新更高效、轻量级的虚拟化技术，称为容器。但最初容器很难实现，并且只在拥有 Linux 内核工程师的网络巨头的数据中心中找到。然后 Docker Inc.出现了，突然之间容器虚拟化技术就面向大众了。

说到 Docker...让我们去找出 Docker 是谁、是什么以及为什么！


# 第三章：Docker

没有关于容器的书籍或对话是完整的，而不谈论 Docker。但是当有人说“Docker”时，他们可能指的是至少三件事中的任何一件：

1.  Docker，Inc.公司

1.  Docker 容器运行时和编排技术

1.  Docker 开源项目（现在称为 Moby）

如果你要在容器世界中取得成功，你需要了解这三者的一些情况。

### Docker - 简而言之

Docker 是在 Linux 和 Windows 上运行的软件。它创建、管理和编排容器。该软件作为 GitHub 上*Moby*开源项目的一部分在开放中开发。Docker，Inc.是一家总部位于旧金山的公司，是开源项目的整体维护者。Docker，Inc.还提供带有支持合同等商业版本的 Docker。

好的，这就是快速版本。现在我们将更详细地探讨每一个。我们还将谈一下容器生态系统，并提到开放容器倡议（OCI）。

### Docker，Inc.

Docker，Inc.是由法国出生的美国开发者和企业家 Solomon Hykes 创立的旧金山科技初创公司。

![图 2.1 Docker，Inc.标志。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure2-1.png)

图 2.1 Docker，Inc.标志。

有趣的是，Docker，Inc.起初是作为一个名为*dotCloud*的平台即服务（PaaS）提供商开始其生活的。在幕后，dotCloud 平台利用了 Linux 容器。为了帮助他们创建和管理这些容器，他们建立了一个内部工具，最终将其昵称为“Docker”。这就是 Docker 诞生的方式！

2013 年，dotCloud PaaS 业务陷入困境，公司需要新的生机。为了帮助解决这个问题，他们聘请了新 CEO 本·戈鲁布，将公司重新品牌为“Docker，Inc.”，摆脱了 dotCloud PaaS 平台，并开始了一个新的旅程，使命是将 Docker 和容器带给世界。

今天，Docker，Inc.被广泛认为是一家创新技术公司，市值据一些人称在 10 亿美元左右。在撰写本文时，它已经通过几轮融资从硅谷风险投资界的一些最大的名字中筹集了超过 2.4 亿美元。几乎所有这些资金都是在公司转型成为*Docker，Inc.*之后筹集的。

自成为 Docker，Inc.以来，他们进行了几笔小规模收购，费用未公开，以帮助扩大他们的产品和服务组合。

在撰写本文时，Docker，Inc.大约有 300-400 名员工，并举办名为 Dockercon 的年度会议。Dockercon 的目标是汇集不断增长的容器生态系统，推动 Docker 和容器技术的采用。

在本书中，当提到 Docker 公司时，我们将使用术语“Docker，Inc.”。术语“Docker”的所有其他用法将指的是技术或开源项目。

> **注意：**“Docker”一词来自英国的俚语，意思是**dock** work__er__ ——负责装卸船货的人。

### Docker 运行时和编排引擎

当大多数*技术人员*谈论 Docker 时，他们指的是*Docker Engine*。

*Docker Engine*是运行和编排容器的基础设施管道软件。如果你是 VMware 管理员，你可以把它想象成类似于 ESXi。就像 ESXi 是运行虚拟机的核心 hypervisor 技术一样，Docker Engine 是运行容器的核心容器运行时。

所有其他 Docker，Inc.和第三方产品都插入到 Docker Engine 中并围绕它构建。图 2.2 显示了 Docker Engine 位于中心。图表中的所有其他产品都建立在引擎之上，并利用其核心能力。

![图 2.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure2-2.png)

图 2.2

Docker Engine 可以从 Docker 网站下载或从 GitHub 源代码构建。它在 Linux 和 Windows 上都可用，并提供开源和商业支持的产品。

在撰写本文时，有两个主要版本：

+   企业版（EE）

+   社区版（CE）

企业版和社区版都有一个稳定的发布渠道，每季度发布一次。每个社区版将得到 4 个月的支持，每个企业版将得到 12 个月的支持。

社区版通过*edge*渠道每月发布一次。

从 2017 年第一季度开始，Docker 版本号遵循 YY.MM-xx 版本方案，类似于 Ubuntu 和其他项目。例如，2018 年 6 月的第一个社区版发布将是 18.06.0-ce。

> **注意：**在 2017 年第一季度之前，Docker 版本号遵循`major.minor`版本方案。新方案之前的最后一个版本是 Docker 1.13。

### Docker 开源项目（Moby）

“Docker”一词也用来指代开源的*Docker 项目*。这是一组工具，可以组合成 Docker 守护程序和客户端，您可以从 docker.com 下载并安装。然而，该项目在 2017 年在德克萨斯州奥斯汀举行的 DockerCon 上正式更名为*Moby*项目。作为更名的一部分，GitHub 存储库从 docker/docker 迁移到了 moby/moby，并且该项目有了自己的标志。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure2-3.png)

Moby 项目的目标是成为 Docker 的*上游*，并将 Docker 分解为更多的模块化组件，并在开放环境中进行此操作。它托管在 GitHub 上，您可以在 https://github.com/moby 上看到 Moby 存储库中包括的当前子项目和工具的列表。核心*Docker Engine*项目目前位于 https://github.com/moby/moby，但引擎的更多部分正在不断地分解和模块化。

作为一个开源项目，源代码是公开可用的，您可以自由下载、贡献、调整和使用它，只要您遵守[Apache License 2.0](https://github.com/docker/docker/blob/master/LICENSE)的条款。

如果您花时间查看该项目的提交历史，您会看到基础设施技术的权威人士，包括 RedHat、微软、IBM、思科和 HPE。您还会看到与大公司无关的个人的名字。

该项目及其工具的大部分都是用*Golang*编写的——这是谷歌的相对较新的系统级编程语言，也被称为*Go*。如果您使用 Go 编码，您就有很好的机会为该项目做出贡献！

Moby/Docker 作为一个开源项目的一个好处是，它的很多部分都是在开放环境中开发和设计的。这消除了很多以前的方式，其中代码是专有的并且被锁在闭门之后。这也意味着发布周期是公开发布并在开放环境中进行工作。不再有不确定的发布周期，这些周期被保密，然后提前数月进行荒谬的炫耀和庆典。Moby/Docker 项目不是这样工作的。大多数事情都是公开进行的，所有人都可以看到并做出贡献。

Moby 项目和更广泛的 Docker 运动是庞大且势头迅猛的。它有数千个 GitHub 拉取请求，数万个 Docker 化项目，更不用说来自 Docker Hub 的数十亿次镜像拉取。该项目确实正在席卷整个行业！

毫无疑问，Docker 正在被使用！

### 容器生态系统

Docker, Inc.的核心理念之一经常被称为“包含但可移除的电池”。

这是一种说法，意思是你可以用第三方的“东西”替换掉很多原生的 Docker“东西”。一个很好的例子是网络堆栈。核心 Docker 产品内置了网络。但网络堆栈是可插拔的，意味着你可以摘掉原生的 Docker 网络，用第三方的东西替换它。很多人都这样做。

在早期，第三方插件通常比随 Docker 一起提供的原生插件更好。然而，这给 Docker, Inc.带来了一些商业模式上的挑战。毕竟，Docker, Inc.必须在某个时候盈利才能成为一个可行的长期业务。因此，*包含*的电池变得越来越好。这引起了生态系统内的紧张和竞争加剧。

长话短说，原生的 Docker 电池仍然是可移除的，只是越来越少地**需要**移除它们。

尽管如此，容器生态系统在合作和竞争之间取得了健康的平衡。你经常会听到人们使用“合作竞争”（合作和竞争的平衡）和“敌友”（朋友和敌人的混合）这样的术语来谈论容器生态系统。这很棒！**健康的竞争是创新之母！**

### 开放容器倡议（OCI）

谈论 Docker 和容器生态系统时，不能不提到[Open Containers Initiative — OCI](https://www.opencontainers.org)。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure2-4.png)

OCI 是一个负责标准化容器基础设施最基本组件的治理委员会，比如*镜像格式*和*容器运行时*（如果这些术语对你来说是新的，我们会在书中介绍它们）。

同样，谈论 OCI 也不能完整，没有提到一点历史。和所有历史记载一样，你得到的版本取决于谁在说话。所以，这是 Nigel 对容器历史的看法 :-D

从一开始，Docker 的使用就像疯狂一样增长。越来越多的人以越来越多的方式使用它来做越来越多的事情。因此，某些方面感到沮丧是不可避免的。这是正常和健康的。

根据尼格尔的*历史概述*，一个叫做[CoreOS](https://coreos.com)的公司不喜欢 Docker 做某些事情的方式。所以他们采取了行动！他们创建了一个叫做**[appc](https://github.com/appc/spec/)**的新的开放标准，定义了像图像格式和容器运行时这样的东西。他们还创建了一个叫做**rkt**（发音为“火箭”）的规范实现。

这使得容器生态系统处于尴尬的境地，有两个竞争性的标准。

回到故事，这威胁着破坏生态系统，并给用户和客户带来了两难选择。虽然竞争通常是件好事，但是*竞争性标准*通常不是。它们会导致混乱并减缓用户采用速度。对任何人都不利。

有了这个想法，每个人都尽力表现得像成年人一样，走到一起组成了 OCI - 一个轻量敏捷的委员会来管理容器标准。

在撰写本文时，OCI 已经发布了两个规范（标准）-

+   [image-spec](https://github.com/opencontainers/image-spec)

+   [runtime-spec](https://github.com/opencontainers/runtime-spec)

在提到这两个标准时经常使用的类比是*铁轨*。这两个标准就像是对铁轨的标准尺寸和属性达成一致。其他人可以自由地建造更好的火车、更好的车厢、更好的信号系统、更好的车站……都可以放心地知道它们将在标准化的铁轨上运行。没有人希望有两个竞争性的铁轨尺寸标准！

可以说，OCI 的两个规范对核心 Docker 产品的架构和设计产生了重大影响。截至 Docker 1.11，Docker 引擎架构符合 OCI 运行时规范。

到目前为止，OCI 已经取得了一些成就，并在一定程度上促进了生态系统的统一。然而，标准总是会减缓创新！特别是对于正在以接近光速发展的新技术。这导致了容器社区中一些激烈的争论和热烈的讨论。在作者看来，这是件好事！容器行业正在改变世界，处于前沿的人们热情、有主见，有时甚至有些离谱！期待更多关于标准和创新的*热烈讨论*！

OCI 是在 Linux 基金会的支持下组织起来的，Docker 公司和 CoreOS 公司都是主要的贡献者。

### 本章总结

在本章中，我们了解了一些关于 Docker，Inc.。他们是一家位于旧金山的初创科技公司，有改变我们软件开发方式的雄心壮志。他们可以说是容器现代革命的第一批推动者和发起者。但现在已经存在着一个庞大的合作伙伴和竞争对手生态系统。

Docker 项目是开源的，上游代码存放在 GitHub 上的`moby/moby`仓库中。

开放容器倡议（OCI）在标准化容器运行时格式和容器镜像格式方面发挥了重要作用。


# 第四章：安装 Docker

有很多种方式和地方可以安装 Docker。有 Windows，有 Mac，显然还有 Linux。但也有云端，本地，笔记本电脑等等...除此之外，我们还有手动安装，脚本安装，基于向导的安装...实际上有很多种方式和地方可以安装 Docker！

但不要让这吓到你！它们都很容易。

在本章中，我们将涵盖一些最重要的安装：

+   桌面安装

+   Docker for Windows

+   Docker for Mac

+   服务器安装

+   Linux

+   Windows Server 2016

+   升级 Docker

+   存储驱动器考虑

我们还将看看如何升级 Docker 引擎并选择适当的存储驱动程序。

### Windows 的 Docker（DfW）

首先要注意的是*Docker for Windows*是 Docker，Inc.的“打包”产品。这意味着它很容易下载，并且有一个漂亮的安装程序。它在 64 位 Windows 10 台式机或笔记本上启动一个单引擎 Docker 环境。

第二件要注意的事情是它是一个社区版（CE）应用。因此不适用于生产。

第三件值得注意的事情是它可能会遇到一些功能滞后。这是因为 Docker，Inc.正在采取“稳定性第一，功能第二”的方法来处理产品。

这三点加起来就是一个快速简单的安装，但不适用于生产。

废话够多了。让我们看看如何安装*Docker for Windows*。

首先，先决条件。*Docker for Windows*需要：

+   Windows 10 专业版|企业版|教育版（1607 周年更新，版本 14393 或更新版本）

+   必须是 64 位 Windows 10

+   *Hyper-V*和*容器*功能必须在 Windows 中启用

+   必须在系统的 BIOS 中启用硬件虚拟化支持

以下将假定硬件虚拟化支持已在系统的 BIOS 中启用。如果没有，您应该仔细遵循您特定机器的程序。

在 Windows 10 中要做的第一件事是确保**Hyper-V**和**容器**功能已安装并启用。

1.  右键单击 Windows 开始按钮，然后选择“应用和功能”。

1.  点击“程序和功能”链接（右侧的一个小链接）。

1.  点击“打开或关闭 Windows 功能”。

1.  勾选`Hyper-V`和“容器”复选框，然后点击“确定”。

这将安装并启用 Hyper-V 和容器功能。您的系统可能需要重新启动。

![图 3.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/Figure3-1.png)

图 3.1

*Containers*功能仅在运行 2016 年夏季的 Windows 10 周年更新（版本 14393）或更高版本时可用。

安装了`Hyper-V`和`Containers`功能并重新启动计算机后，现在是安装*Docker for Windows*的时候了。

1.  前往 https://www.docker.com/get-docker 并单击`GET DOCKER COMMUNITY EDITION`链接。

1.  单击`DOCKER CE FOR WINDOWS`部分下方的`Download from Docker Store`链接。这将带您到 Docker Store，您可能需要使用 Docker ID 登录。

1.  单击一个`Get Docker`下载链接。

Docker for Windows 有一个*stable*和*edge*通道。Edge 通道包含更新的功能，但可能不太稳定。

一个名为`Docker for Windows Installer.exe`的安装程序包将被下载到默认的下载目录。

1.  找到并启动在上一步中下载的安装程序包。

按照安装向导的步骤，并提供本地管理员凭据以完成安装。Docker 将自动启动为系统服务，并且 Moby Dock 鲸鱼图标将出现在 Windows 通知区域中。

恭喜！您已经安装了*Docker for Windows*。

打开命令提示符或 PowerShell 终端，尝试以下命令：

```
```

客户端：

版本：18.01.0-ce

API 版本：1.35

Go 版本：go1.9.2

Git 提交：03596f5

构建时间：2018 年 1 月 10 日星期三 20:05:55

OS/Arch：windows/amd64

实验性：false

编排器：swarm

服务器：

引擎：

版本：18.01.0-ce

API 版本：1.35（最低版本 1.12）

Go 版本：go1.9.2

Git 提交：03596f5

构建时间：2018 年 1 月 10 日星期三 20:13:12

OS/Arch：linux/amd64

实验性：false

``` 
```

注意，输出显示`OS/Arch: linux/amd64`是因为默认安装目前会在轻量级的 Linux Hyper-V 虚拟机中安装 Docker 守护程序。在这种情况下，您只能在*Docker for Windows*上运行 Linux 容器。

如果您想运行*本机 Windows 容器*，可以右键单击 Windows 通知区域中的 Docker 鲸鱼图标，然后选择`Switch to Windows containers...`。您也可以在命令行中使用以下命令（位于`\Program Files\Docker\Docker`目录中）来实现相同的功能：

```
C:\Program Files\Docker\Docker> .\dockercli -SwitchDaemon 
```

如果您没有启用`Windows Containers`功能，您将收到以下警报。

![图 3.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure3-2.png)

图 3.2

如果您已经启用了 Windows 容器功能，切换只需要几秒钟。切换完成后，`docker version`命令的输出将如下所示。

```
C:\> docker version
Client:
 <Snip>

Server:
 Engine:
  Version:      18.01.0-ce
  API version:  1.35 (minimum version 1.24)
  Go version:   go1.9.2
  Git commit:   03596f5
  Built:        Wed Jan 10 20:20:36 2018
  OS/Arch:      windows/amd64
  Experimental: true 
```

`请注意，服务器版本现在显示为`windows/amd64`。这意味着守护程序在 Windows 内核上本地运行，并且只能运行 Windows 容器。

还要注意，系统现在正在运行 Docker 的*实验*版本（`实验性：true`）。如前所述，*Docker for Windows*有一个稳定的通道和一个边缘通道。在撰写本文时，Windows 容器是边缘通道的实验功能。

您可以使用`dockercli -Version`命令检查您正在运行的通道。 `dockercli`命令位于`C:\Program Files\Docker\Docker`中。

```
PS C:\Program Files\Docker\Docker> .\dockercli -Version

Docker for Windows
Version: 18.01.0-ce-win48 (15285)
Channel: edge
Sha1: ee2282129dec07b8c67890bd26865c8eccdea88e
OS Name: Windows 10 Pro
Windows Edition: Professional
Windows Build Number: 16299 
```

以下列表显示了常规 Docker 命令的正常工作。

```
> docker image ls
REPOSITORY    TAG      IMAGE ID      CREATED       SIZE

> docker container ls
CONTAINER ID   IMAGE   COMMAND   CREATED    STATUS    PORTS    NAMES

> docker system info
Containers: 1
 Running: 0
 Paused: 0
 Stopped: 1
Images: 6
Server Version: 17.12.0-ce
Storage Driver: windowsfilter
<Snip> 
```

Windows 的 Docker 包括 Docker Engine（客户端和守护程序）、Docker Compose、Docker Machine 和 Docker Notary 命令行。使用以下命令验证每个是否成功安装：

```
C:\> docker --version
Docker version 18.01.0-ce, build 03596f5 
```

````
C:\> docker-compose --version
docker-compose version 1.18.0, build 8dd22a96 
```

````

C:\> docker-machine --version

docker-machine.exe 版本 0.13.0，构建 9ba6da9

```

````

C:\> notary version

公证

版本：0.4.3

Git 提交：9211198

```

 `### Docker for Mac (DfM)

*Docker for Mac* is also a packaged product from Docker, Inc. So relax, you don’t need to be a kernel engineer, and we’re not about to walk through a complex hack for getting Docker onto your Mac. Installing DfM is ridiculously easy.

What is *Docker for Mac?*

First up, *Docker for Mac* is a packaged product from Docker, Inc. that is based on the Community Edition of Docker. This means it’s an easy way to install a single-engine version of Docker on you Mac. It also means that it’s not intended for production use. If you’ve heard of **boot2docker**, then *Docker for Mac* is what you always wished *boot2docker* was — smooth, simple, and stable.

It’s also worth noting that *Docker for Mac* will not give you the Docker Engine running natively on the Mac OS Darwin kernel. Behind the scenes, the Docker daemon is running inside a lightweight Linux VM. It then seamlessly exposes the daemon and API to your Mac environment. This means you can open a terminal on your Mac and use the regular Docker commands.

Although this works seamlessly on your Mac, don’t forget that it’s Docker on Linux under the hood — so it’s only going work with Linux-based Docker containers. This is good though, as it’s where most of the container action is.

Figure 3.3 shows a high-level representation of the *Docker for Mac* architecture.

![Figure 3.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure3-3.png)

Figure 3.3

> **Note:** For the curious reader, *Docker for Mac* leverages [HyperKit](https://github.com/docker/hyperkit) to implement an extremely lightweight hypervisor. HyperKit is based on the [xhive hypervisor](https://github.com/mist64/xhyve). *Docker for Mac* also leverages features from [DataKit](https://github.com/docker/datakit) and runs a highly tuned Linux distro called *Moby* that is based on [Alpine Linux](https://alpinelinux.org/%20and%20https://github.com/alpinelinux).

Let’s get *Docker for Mac* installed.

1.  Point your browser to https://www.docker.com/get-docker and click `GET DOCKER COMMUNITY EDITION`.
2.  Click the `Download from Docker Store` option below `DOCKER CE FOR MAC`. This will take you to the Docker Store and you will need to provide your Docker ID and password.
3.  Click one of the `Get Docker CE` download links.

    Docker for Mac has a stable and edge channel. Edge has newer features, at the expense of stability.

    A **Docker.dmg** installation package will be downloaded.

4.  Launch the `Docker.dmg` file that you downloaded in the previous step. You will be asked to drag and drop the Moby Dock whale image into the **Applications** folder.
5.  Open your **Applications** folder (it may open automatically) and double-click the Docker application icon to Start it. You may be asked to confirm the action because the application was downloaded from the internet.
6.  Enter your password so that the installer can create the components that require elevated privileges.
7.  The Docker daemon will now start.

    An animated whale icon will appear in the status bar at the top of your screen while Docker starts. Once Docker has successfully started, the whale will stop being animated. You can click the whale icon to manage DfM.

Now that DfM is installed, you can open a terminal window and run some regular Docker commands. Try the following.

```

$ docker version

客户端：

版本：17.05.0-ce

API 版本：1.29

Go 版本：go1.7.5

Git 提交：89658be

构建日期：星期四，2017 年 5 月 4 日 21:43:09

OS/Arch：darwin/amd64

服务器：

版本：17.05.0-ce

API 版本：1.29（最低版本 1.12）

Go 版本：go1.7.5

Git 提交：89658be

构建日期：星期四，2017 年 5 月 4 日 21:43:09

OS/Arch：linux/amd64

实验性：true

```

 `Notice that the `OS/Arch:` for the **Server** component is showing as `linux/amd64`. This is because the daemon is running inside of the Linux VM we mentioned earlier. The **Client** component is a native Mac application and runs directly on the Mac OS Darwin kernel (`OS/Arch: darwin/amd64`).

Also note that the system is running the experimental version (`Experimental: true`) of Docker. This is because the system is running the *edge* channel which comes with experimental features turned on.

Run some more Docker commands.

```

$ docker --version

Docker 版本 17.05.0-ce，构建 89658be

$ docker image ls

存储库    标签    映像 ID    创建时间    大小

$ docker container ls

容器 ID   映像   命令   创建时间   状态   端口   名称

```

 `Docker for Mac installs the Docker Engine (client and daemon), Docker Compose, Docker machine, and the Notary command line. The following three commands show you how to verify that all of these components installed successfully, as well as which versions you have.

```

$ docker --version

Docker 版本 17.05.0-ce，构建 89658be

```

````

$ docker-compose --version

docker-compose 版本 1.13.0，构建 1719ceb

```

````

$ docker-machine --version

docker-machine 版本 0.11.0，构建 5b27455

```

````

$ notary version

公证

版本：0.4.3

Git 提交：9211198

```

 `### Installing Docker on Linux

Installing Docker on Linux is the most common installation type and it’s surprisingly easy. The most common difficulty is the slight variations between Linux distros such as Ubuntu vs CentOS. The example we’ll use in this section is based on Ubuntu Linux, but should work on upstream and downstream forks. It should also work on CentOS and its upstream and downstream forks. It makes absolutely no difference if your Linux machine is a physical server in your own data center, on the other side of the planet in a public cloud, or a VM on your laptop. The only requirements are that the machine be running Linux and has access to https://get.docker.com.

The first thing you need to decide is which edition to install. There are currently two editions:

*   Community Edition (CE)
*   Enterprise Edition (EE)

Docker CE is free and is the version we’ll be demonstrating. Docker EE is the same as CE, but comes with commercial support and access to other Docker products such as Docker Trusted Registry and Universal Control Plane.

In this example, we’ll use the `wget` command to call a shell script that installs Docker CE. For information on other ways to install Docker on Linux, go to https://www.docker.com and click on `Get Docker`.

> **Note:** You should ensure that your system is up-to-date with the latest packages and security patches before continuing.

1.  Open a new shell on your Linux machine.
2.  Use `wget` to retrieve and run the Docker install script from

`https://get.docker.com` and pipe it through your shell.

```

$ wget -qO- https://get.docker.com/ `|` sh

modprobe：致命：未找到模块 aufs/lib/modules/4.4.0-36-generic

+ sh -c 'sleep 3; yum -y -q install docker-engine'

<剪辑>

如果您想以非 root 用户身份使用 Docker，您应该

现在考虑将您的用户添加到`"docker"`组中

类似于：

sudo usermod -aG docker your-user

请记住，您将不得不注销并重新登录...

```

`*   It is best practice to use non-root users when working with Docker. To do this, you need to add your non-root users to the local `docker` Unix group. The following command shows you how to add the **npoulton** user to the `docker` group and verify that the operation succeeded. You will need to use a valid user account on your own system.

```

$ sudo usermod -aG docker npoulton

$ cat /etc/group `|` grep docker

docker:x:999:npoulton

```

     `If you are already logged in as the user that you just added to the `docker` group, you will need to log out and log back in for the group membership to take effect.`` 

 ``Congratulations! Docker is now installed on your Linux machine. Run the following commands to verify the installation.

```

$ docker --version

Docker 版本`18`.01.0-ce，构建 03596f5

$ docker system info

容器：`0`

运行中：`0`

已暂停：`0`

已停止：`0`

镜像：`0`

服务器版本：`18`.01.0-ce

存储驱动程序：overlay2

后备文件系统：extfs

<Snip>

```

 `If the process described above doesn’t work for your Linux distro, you can go to the [Docker Docs](https://docs.docker.com/engine/installation/) website and click on the link relating to your distro. This will take you to the official Docker installation instructions which are usually kept up to date. Be warned though, the instructions on the Docker website tend use package managers that require a lot more steps than the procedure we used above. In fact, if you open a web browser to https://get.docker.com you will see that it’s a shell script that does all of the installation grunt-work for you — including configuring Docker to automatically start when the system boots.

> **Warning:** If you install Docker from a source other than the official Docker repositories, you may end up with a forked version of Docker. In the past, some vendors and distros chose to fork the Docker project and develop their own slightly customized versions. You need to watch out for things like this, as you could unwittingly end up in a situation where you are running a fork that has diverged from the official Docker project. This isn’t a problem if this is what you intend to do. If it is not what you intend, it can lead to situations where modifications and fixes your vendor makes do not make it back upstream in to the official Docker project. In these situations, you will not be able to get commercial support for your installation from Docker, Inc. or its authorized service partners.

### Installing Docker on Windows Server 2016

In this section we’ll look at one of the ways to install Docker on Windows Server 2016\. We’ll complete the following high-level steps:

1.  Install the Windows Containers feature
2.  Install Docker
3.  Verify the installation

Before proceeding, you should ensure that your system is up-to-date with the latest package versions and security updates. You can do this quickly with the `sconfig` command and choosing option 6 to install updates. This may require a system restart.

We’ll be demonstrating an installation on a version of Windows Server 2016 that does not have the Containers feature or an older version of Docker already installed.

Ensure that the `Containers` feature is installed and enabled.

1.  Right-click the Windows Start button and select `Programs and Features`. This will open the `Programs and Features` console.
2.  Click `Turn Windows features on or off`. This will open the `Server Manager` app.
3.  Make sure the `Dashboard` is selected and choose `Add Roles and Features`.
4.  Click through the wizard until you get to the `Features` page.
5.  Make sure that the `Containers` feature is checked, then complete the wizard. Your system may require a system restart.

Now that the Windows Containers feature is installed, you can install Docker. We’ll use PowerShell to do this.

1.  Open a new PowerShell Administrator terminal.
2.  Use the following command to install the Docker package management provider.

```

> Install-Module DockerProvider -Force

```

 `If prompted, accept the request to install the NuGet provider.` 
`*   Install Docker.

```

> Install-Package Docker -ProviderName DockerProvider -Force

```

 `Once the installation is complete you will get a summary as shown.

```

名称 版本 来源 摘要

---- ------- ------ -------

Docker 17.06.2-ee-6 Docker Docker for Windows Server 2016

```

     `Docker is now installed and configured to automatically start when the system boots.`` ``*   You may want to restart your system to make sure that none of changes have introduced issues that cause your system not to boot. You can also check that Docker automatically starts after the reboot.```

```Docker is now installed and you can start deploying containers. The following two commands are good ways to verify that the installation succeeded.

```

> docker --version

Docker 版本 17.06.2-ee-6，构建 e75fdb8

> docker system info

容器：0

运行中：0

已暂停：0

已停止：0

镜像：0

服务器版本：17.06.2-ee-6

存储驱动程序：windowsfilter

<Snip>

```

 `Docker is now installed and you are ready to start using Windows containers.

### Upgrading the Docker Engine

Upgrading the Docker Engine is an important task in any Docker environment — especially production. This section of the chapter will give you the high-level process of upgrading the Docker engine, as well as some general tips and a couple of upgrade examples.

The high-level process of upgrading the Docker Engine is this:

Take care of any pre-requisites. These can include; making sure your containers have an appropriate restart policy, or draining nodes if you’re using *Services* in Swarm mode. Once you’ve completed any potential pre-requisites you can follow the procedure below.

1.  Stop the Docker daemon
2.  Remove the old version
3.  Install the new version
4.  configure the new version to automatically start when the system boots
5.  Ensure containers have restarted

That’s the high-level process. Let’s look at some examples.

Each version of Linux has its own slightly different commands for upgrading Docker. We’ll show you Ubuntu 16.04\. We’ll also show you Windows Server 2016.

#### Upgrading Docker CE on Ubuntu 16.04

We’re assuming you’ve completed all pre-requisites and your Docker host is ready for the upgrade. We’re also assuming you’re running commands as root. Running commands as root is obviously **not recommended**, but it does keep examples in the book simpler. If you’re not running as root, well done! However, you will have to prepend the following commands with `sudo`.

1.  Update your `apt` package list.

```

$ apt-get update

```

`*   Uninstall existing versions of Docker.

```

$ apt-get remove docker docker-engine docker-ce docker.io -y

```

 `The Docker engine has had several different package names in the past. This command makes sure all older versions get removed.` `*   Install the new version.

There are different versions of Docker and different ways to install each one. For example, Docker CE or Docker EE, both of which can be installed in more than one way. For example, Docker CE can be installed from `apt` or `deb` packages, or using a script on `docker.com`

The following command will use a shell script at `get.docker.com` to install and configure the latest version of Docker CE.

```

$ wget -qO- https://get.docker.com/ | sh

```

`*   Configure Docker to automatically start each time the system boots.

```

$ systemctl enable docker

同步 docker.service 的状态...

执行/lib/systemd/systemd-sysv-install enable docker

$ systemctl is-enabled docker

已启用

```

 `At this point you might want to restart the node. This will make sure that no issues have been introduced that prevent your system from booting in the future.` `*   Make sure any containers and services have restarted.

```

$ docker container ls

容器 ID 图像 命令 创建状态 \

名称

97e599aca9f5 alpine "sleep 1d" 14 分钟前 上线 1 分钟

$ docker service ls

ID 名称 模式 副本 图像

ibyotlt1ehjy prod-equus1 复制 1/1 alpine:latest

``````` 

```Remember, other methods of upgrading and installing Docker exist. We’ve just shown you one way, on Ubuntu Linux 16.04.

#### Upgrading Docker EE on Windows Server 2016

This section will walk you through the process of upgrading Docker on Windows from 1.12.2, to the latest version of Docker EE.

The process assumes you have completed any pre-flight tasks, such as configuring containers with appropriate restart policies and draining Swarm nodes if you’re using Swarm services.

All commands should be ran from a PowerShell terminal.

1.  Check the current version of Docker.

   ```
    > docker version
    Client:
     Version:      1.12.2-cs2-ws-beta
    <Snip>
    Server:
     Version:      1.12.2-cs2-ws-beta 
   ```

`*   Uninstall any potentially older modules provided by Microsoft, and install the module from Docker.

   ```
    > Uninstall-Module DockerMsftProvider -Force

    > Install-Module DockerProvider -Force 
   ```

   `*   Update the `docker` package.

   This command will force the update (no uninstall is required) and configure Docker to automatically start each time the system boots.

   ```
    > Install-Package -Name docker -ProviderName DockerProvider -Update -Force

    Name      Version          Source       Summary
    ----      -------          ------       -------
    Docker    17.06.2-ee-6     Docker       Docker for Windows Server 2016 
   ```

    `You might want to reboot your server at this point to make sure the changes have not introduced any issues that prevent it from restarting in the future.` `*   Check that containers and services have restarted.```

```That’s it. That’s how to upgrade to the latest version of Docker EE on Windows Server 2016.

### Docker and storage drivers

Every Docker container gets its own area of local storage where image layers are stacked and the container filesystem is mounted. By default, this is where all container read/write operations occur, making it integral to the performance and stability of every container.

Historically, this local storage area has been managed by the *storage driver*, which we sometimes call the *graph driver* or *graphdriver*. Although the high-level concepts of stacking image layers and using copy-on-write technologies are constant, Docker on Linux supports several different storage drivers, each of which implements layering and copy-on-write in its own way. While these *implementation differences* do not affect the way we *interact* with Docker, they can have a significant impact on *performance* and *stability*.

Some of the *storage drivers* available for Docker on Linux include:

*   `aufs` (the original and oldest)
*   `overlay2` (probably the best choice for the future)
*   `devicemapper`
*   `btrfs`
*   `zfs`

Docker on Windows only supports a single storage driver, the `windowsfilter` driver.

Selecting a storage driver is a *per node* decision. This means a single Docker host can only run a single storage driver — you cannot select the storage driver per-container. On Linux, you set the storage driver in `/etc/docker/daemon.json` and you need to restart Docker for any changes to take effect. The following snippet shows the storage driver set to `overlay2`.

```
{
 "storage-driver": "overlay2"
} 
```

`> **Note:** If the configuration line is not the last line in the configuration file, you will need to add a comma to the end.

If you change the storage driver on an already-running Docker host, existing images and containers will not be available after Docker is restarted. This is because each storage driver has its own subdirectory on the host where it stores image layers (usually below `/var/lib/docker/<storage-driver>/...`). Changing the storage driver obviously changes where Docker looks for images and containers. Reverting the storage driver to the previous configuration will make the older images and containers available again.

If you need to change your storage driver, and you need your images and containers to be available after the change, you need to save them with `docker save`, push the saved images to a repo, change the storage driver, restart Docker, pull the images locally, and restart your containers.

You can check the current storage driver with the `docker system info` command:

```
$ docker system info
<Snip>
Storage Driver: overlay2
 Backing Filesystem: xfs
 Supports d_type: `true`
 Native Overlay Diff: `true`
<Snip> 
```

`Choosing which storage driver, and configuring it properly, is important in any Docker environment — especially production. The following list can be used as a **guide** to help you choose which storage driver to use. However, you should always consult the latest support documentation from Docker, as well as your Linux provider.

*   **Red Hat Enterprise Linux** with a 4.x kernel or higher + Docker 17.06 and higher: `overlay2`
*   **Red Hat Enterprise Linux** with an older kernel and older versions of Docker: `devicemapper`
*   **Ubuntu Linux** with a 4.x kernel or higher: `overlay2`
*   **Ubuntu Linux** with an earlier kernel: `aufs`
*   **SUSE Linux Enterprise Server:** `btrfs`

Again, this list should only be used as a guide. Always check the latest support and compatibility matrixes in the Docker documentation, and with your Linux provider. This is especially important if you are using Docker Enterprise Edition (EE) with a support contract.

#### Devicemapper configuration

Most of the Linux storage drivers require little or no configuration. However, `devicemapper` needs configuring in order to perform well.

By default, `devicemapper` uses *loopback mounted sparse files* to underpin the storage it provides to Docker. This is fine for a smooth out-of-the box experience that *just works*. But it’s terrible for production. In fact, it’s so bad that it’s **not supported on production systems!

To get the best performance out of `devicemapper`, as well as production support, you must configure it in `direct-lvm` mode. This significantly increases performance by leveraging an LVM `thinpool` backed by raw block devices.

Docker 17.06 and higher can configure `direct-lvm` for you. However, at the time of writing, it has some limitations. The main ones being; it will only configure a single block device, and it only works for fresh installations. This might change in the future, but a single block device will not give you the best in terms of performance and resiliency.

##### Letting Docker automatically configure `direct-lvm`

The following simple procedure will let Docker automatically configure `devicemapper` for `direct-lvm`.

1.  Add the following storage driver configuration to `/etc/docker/daemon.json`

   ```
    {
    "storage-driver": "devicemapper",
    "storage-opts": [
      "dm.directlvm_device=/dev/xdf",
      "dm.thinp_percent=95",
      "dm.thinp_metapercent=1",
      "dm.thinp_autoextend_threshold=80",
      "dm.thinp_autoextend_percent=20",
      "dm.directlvm_device_force=false"
    ]
    } 
   ```

    `Device Mapper and LVM are complex topics, and beyond the scope of a heterogeneous Docker book like this. However, let’s quickly explain each option:

   *   `dm.directlvm_device` is where you specify the block device. For best performance and availability, this should be a dedicated high-performance device such as a local SSD, or RAID protected high performance LUN from an external storage array.
   *   `dm.thinp_percent=95` allows you to specify how much of the space you want Images and containers to be able to use. Default is 95%.
   *   `dm.thinp_metapercent` sets the percentage of space to be used for metadata storage. Default is 1%.
   *   `dm.thinp_autoextend_threshold` sets the threshold at which LVM should automatically extend the thinpool. The default value is currently 80%.
   *   `dm.thinp_autoextend_percent` is the amount of space that should be added to the thin pool when an auto-extend operation is triggered.
   *   `dm.directlvm_device_force` lets you specify whether or not to format the block device with a new filesystem.` 
`*   Restart Docker.*   Verify that Docker is running and the `devicemapper` configuration is correctly loaded.

   ```
    $ docker version
    Client:
    Version:      18.01.0-ce
    <Snip>
    Server:
    Version:      18.01.0-ce
    <Snip>

    $ docker system info
    <Snipped output only showing relevant data>
    Storage Driver: devicemapper
    Pool Name: docker-thinpool
    Pool Blocksize: 524.3 kB
    Base Device Size: 25 GB
    Backing Filesystem: xfs
    Data file:       << Would show a loop file if in loopback mode
    Metadata file:   << Would show a loop file if in loopback mode
    Data Space Used: 1.9 GB
    Data Space Total: 23.75 GB
    Data Space Available: 21.5 GB
    Metadata Space Used: 180.5 kB
    Metadata Space Total: 250 MB
    Metadata Space Available: 250 MB 
   ```` 

``Although Docker will only configure `direct-lvm` mode with a single block device, it will still perform significantly better than `loopback` mode!

##### Manually configuring devicemapper direct-lvm

Walking you through the entire process of manually configuring `device mapper direct-lvm` is beyond the scope of this book. It is also something that can change and vary between OS versions. However, the following items are things you should know and consider when performing a configuration.

*   **Block devices**. You need to have block devices available in order to configure `direct-lvm` mode. These should be high performance devices such as local SSD or high performance external LUNs. If your Docker environment is on-premises, external LUNs can be on FC, iSCSI, or other block-protocol storage arrays. If your Docker environment is in the public cloud, these can be any form of high performance block storage (usually SSD-based) supported by your cloud provider.
*   **LVM config**. The `devicemapper` storage driver leverages LVM, the Linux Logical Volume Manager. This means you will need to configure the required physical devices (pdev), volume group (vg), logical volumes (lv), and thinpool (tp). You should use dedicated physical volumes and form them into a new volume group. You should not share the volume group with non-Docker workloads. You will also need to configure two logical volumes; one for data and the other for metadata. Create an LVM profile specifying the auto-extend threshold and auto-extend values, and configure monitoring so that auto-extend operations can happen.
*   **Docker config**. Backup the current Docker config file (`/etc/docker/daemon.json`) and then update it as follows. The name of the `dm.thinpooldev` might be different in your environment and you should adjust as appropriate.

   ```
    {
      "storage-driver": "devicemapper",
      "storage-opts": [
      "dm.thinpooldev=/dev/mapper/docker-thinpool",
      "dm.use_deferred_removal=true",
      "dm.use_deferred_deletion=true"
      ]
    } 
   ```

`Once the configuration is saved you can start the Docker daemon.

For more detailed information, see the Docker documentation or talk to your Docker technical account manager.

### Chapter Summary

Docker is available for Linux and Windows, and has a Community Edition (CE) and an Enterprise Edition (EE). In this chapter, we looked at some of the ways to install Docker on Windows 10, Mac OS X, Linux, and Windows Server 2016.

We looked at how to upgrade the Docker Engine on Ubuntu 16.04 and Windows Server 2016, as these are two of the most common configurations.

We also learned that selecting the right *storage driver* is essential when using Docker on Linux in production environments.`````````````````````````````````


# 第五章：大局观

本章的目的是在我们深入研究后面的章节之前，快速描绘 Docker 的全貌。

我们将把这一章分为两部分：

+   运维视角

+   开发者视角

在运维视角部分，我们将下载一个镜像，启动一个新的容器，登录到新的容器中，在其中运行一个命令，然后销毁它。

在开发者视角部分，我们将更专注于应用程序。我们将从 GitHub 上拉取一些应用代码，检查一个 Dockerfile，将应用程序容器化，作为容器运行它。

这两个部分将让您对 Docker 的全貌有一个很好的了解，以及一些主要组件是如何组合在一起的。**建议您阅读这两部分，以获得*开发*和*运维*的视角。** DevOps？

如果我们在这里做的一些事情对您来说是全新的，不要担心。我们并不打算在本章结束时让您成为专家。这是为了让您对事物有一个*感觉* - 为您做好准备，以便在后面的章节中，当我们深入了解细节时，您对各个部分是如何组合在一起的有一个概念。

您只需要一个带有互联网连接的单个 Docker 主机来跟随我们。这可以是 Linux 或 Windows，无论是您笔记本电脑上的虚拟机、公共云中的实例，还是您数据中心中的裸金属服务器都无所谓。它只需要运行 Docker 并连接到互联网。我们将使用 Linux 和 Windows 来展示示例！

另一个快速获取 Docker 的好方法是使用 Play With Docker（PWD）。Play With Docker 是一个基于 Web 的 Docker 游乐场，您可以免费使用。只需将您的 Web 浏览器指向 https://play-with-docker.com/，您就可以开始使用（您可能需要一个 Docker Hub 帐户才能登录）。这是我最喜欢的快速启动临时 Docker 环境的方法！

### 运维视角

当您安装 Docker 时，您会得到两个主要组件：

+   Docker 客户端

+   Docker 守护程序（有时被称为“服务器”或“引擎”）

守护程序实现了[Docker Engine API](https://docs.docker.com/engine/api/v1.35/)。

在默认的 Linux 安装中，客户端通过本地 IPC/Unix 套接字`/var/run/docker.sock`与守护程序进行通信。在 Windows 上，这是通过命名管道`npipe:////./pipe/docker_engine`进行的。您可以使用`docker version`命令来测试客户端和守护程序（服务器）是否正在运行并相互通信。

```
> docker version
Client:
 Version:       18.01.0-ce
 API version:   1.35
 Go version:    go1.9.2
 Git commit:    03596f5
 Built: Wed Jan 10 20:11:05 2018
 OS/Arch:       linux/amd64
 Experimental:  false
 Orchestrator:  swarm

Server:
 Engine:
  Version:      18.01.0-ce
  API version:  1.35 (minimum version 1.12)
  Go version:   go1.9.2
  Git commit:   03596f5
  Built:        Wed Jan 10 20:09:37 2018
  OS/Arch:      linux/amd64
  Experimental: false 
```

“如果您从`Client`和`Server`那里得到了响应，那就可以继续了。如果您使用 Linux 并且从服务器组件那里得到了错误响应，请尝试在命令前加上`sudo`再次运行命令：`sudo docker version`。如果使用`sudo`可以正常工作，您需要将您的用户帐户添加到本地`docker`组，或者在本书的其余命令前加上`sudo`。

#### 图像

将 Docker 图像视为包含操作系统文件系统和应用程序的对象是很有用的。如果您在运营中工作，这就像一个虚拟机模板。虚拟机模板本质上是一个已停止的虚拟机。在 Docker 世界中，图像实际上是一个已停止的容器。如果您是开发人员，您可以将图像视为*类*。

在您的 Docker 主机上运行`docker image ls`命令。

```
$ docker image ls
REPOSITORY    TAG        IMAGE ID       CREATED       SIZE 
```

“如果您是从新安装的 Docker 主机或 Play With Docker 上进行操作，您将没有任何图像，并且看起来像上面的输出一样。”

将图像放入 Docker 主机称为“拉取”。如果您正在使用 Linux，拉取`ubuntu:latest`镜像。如果您正在使用 Windows，拉取`microsoft/powershell:nanoserver`镜像。

```
`latest``:` `Pulling` `from` `library``/``ubuntu`
`50``aff78429b1``:` `Pull` `complete`
`f6d82e297bce``:` `Pull` `complete`
`275``abb2c8a6f``:` `Pull` `complete`
`9``f15a39356d6``:` `Pull` `complete`
`fc0342a94c89``:` `Pull` `complete`
`Digest``:` `sha256``:``fbaf303``...``c0ea5d1212`
`Status``:` `Downloaded` `newer` `image` `for` `ubuntu``:``latest` 
```

再次运行`docker image ls`命令以查看您刚刚拉取的图像。

```
$ docker images
REPOSITORY      TAG      IMAGE ID        CREATED         SIZE
ubuntu          latest   00fd29ccc6f1    `3` weeks ago     111MB 
```

“我们将在后面的章节中详细介绍图像存储的位置和其中的内容。现在，知道图像包含足够的操作系统（OS）以及运行其设计用途的任何应用程序所需的所有代码和依赖关系就足够了。我们拉取的`ubuntu`图像包含精简版的 Ubuntu Linux 文件系统，包括一些常见的 Ubuntu 实用程序。在 Windows 示例中拉取的`microsoft/powershell`图像包含一个带有 PowerShell 的 Windows Nano Server 操作系统。”

如果您拉取一个应用程序容器，比如`nginx`或`microsoft/iis`，您将获得一个包含一些操作系统以及运行`NGINX`或`IIS`的代码的镜像。

值得注意的是，每个图像都有自己独特的 ID。在使用图像时，您可以使用`ID`或名称来引用它们。如果您使用图像 ID，通常只需输入 ID 的前几个字符就足够了——只要它是唯一的，Docker 就会知道您指的是哪个图像。

#### 容器

现在我们在本地拉取了一个镜像，我们可以使用`docker container run`命令从中启动一个容器。

对于 Linux：

```
`$` `docker` `container` `run` `-``it` `ubuntu``:``latest` `/``bin``/``bash`
`root``@6``dc20d508db0``:``/``#` 
```

对于 Windows：

```
> docker container run -it microsoft/powershell:nanoserver pwsh.exe

Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.
PS C:\> 
```

仔细观察前面命令的输出。您应该注意到每个实例中 shell 提示符已经改变。这是因为`-it`标志将您的 shell 切换到容器的终端 - 您实际上在新容器内部！

让我们来看看`docker container run`命令。`docker container run`告诉 Docker 守护程序启动一个新的容器。`-it`标志告诉 Docker 使容器交互，并将我们当前的 shell 附加到容器的终端（我们将在容器章节中更具体地讨论这一点）。接下来，命令告诉 Docker 我们希望容器基于`ubuntu:latest`镜像（或者如果您正在使用 Windows，则基于`microsoft/powershell:nanoserver`镜像）。最后，我们告诉 Docker 我们希望在容器内运行哪个进程。对于 Linux 示例，我们正在运行 Bash shell，对于 Windows 容器，我们正在运行 PowerShell。

从容器内运行`ps`命令以列出所有运行中的进程。

**Linux 示例：**

```
`root``@6``dc20d508db0``:``/``#` `ps` `-``elf`
`F` `S` `UID`    `PID`  `PPID`   `NI` `ADDR` `SZ` `WCHAN`  `STIME` `TTY`  `TIME` `CMD`
`4` `S` `root`     `1`     `0`    `0` `-`  `4560` `wait`   `13``:``38` `?`    `00``:``00``:``00` `/``bin``/``bash`
`0` `R` `root`     `9`     `1`    `0` `-`  `8606` `-`      `13``:``38` `?`    `00``:``00``:``00` `ps` `-``elf` 
```

**Windows 示例：**

```
PS C:\> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
      0       5      964       1292       0.00   4716   4 CExecSvc
      0       5      592        956       0.00   4524   4 csrss
      0       0        0          4                 0   0 Idle
      0      18     3984       8624       0.13    700   4 lsass
      0      52    26624      19400       1.64   2100   4 powershell
      0      38    28324      49616       1.69   4464   4 powershell
      0       8     1488       3032       0.06   2488   4 services
      0       2      288        504       0.00   4508   0 smss
      0       8     1600       3004       0.03    908   4 svchost
      0      12     1492       3504       0.06   4572   4 svchost
      0      15    20284      23428       5.64   4628   4 svchost
      0      15     3704       7536       0.09   4688   4 svchost
      0      28     5708       6588       0.45   4712   4 svchost
      0      10     2028       4736       0.03   4840   4 svchost
      0      11     5364       4824       0.08   4928   4 svchost
      0       0      128        136      37.02      4   0 System
      0       7      920       1832       0.02   3752   4 wininit
      0       8     5472      11124       0.77   5568   4 WmiPrvSE 
```

Linux 容器只有两个进程：

+   PID 1。这是我们使用`docker container run`命令告诉容器运行的`/bin/bash`进程。

+   PID 9。这是我们运行的`ps -elf`命令/进程，用于列出运行中的进程。

在 Linux 输出中`ps -elf`进程的存在可能有点误导，因为它是一个短暂的进程，一旦`ps`命令退出就会终止。这意味着容器内唯一长时间运行的进程是`/bin/bash`进程。

Windows 容器有更多的活动。这是 Windows 操作系统工作方式的产物。然而，即使 Windows 容器的进程比 Linux 容器多得多，它仍然远少于常规的 Windows **Server**。

按`Ctrl-PQ`退出容器而不终止它。这将使您的 shell 回到 Docker 主机的终端。您可以通过查看 shell 提示符来验证这一点。

现在您回到 Docker 主机的 shell 提示符，再次运行`ps`命令。

**Linux 示例：**

```
$ ps -elf
F S UID        PID  PPID    NI ADDR SZ WCHAN  TIME CMD
`4` S root         `1`     `0`     `0` -  `9407` -      `00`:00:03 /sbin/init
`1` S root         `2`     `0`     `0` -     `0` -      `00`:00:00 `[`kthreadd`]`
`1` S root         `3`     `2`     `0` -     `0` -      `00`:00:00 `[`ksoftirqd/0`]`
`1` S root         `5`     `2`   -20 -     `0` -      `00`:00:00 `[`kworker/0:0H`]`
`1` S root         `7`     `2`     `0` -     `0` -      `00`:00:00 `[`rcu_sched`]`
<Snip>
`0` R ubuntu   `22783` `22475`     `0` -  `9021` -      `00`:00:00 ps -elf 
```

**Windows 示例：**

```
> ps
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    220      11     7396       7872       0.33   1732   0 amazon-ssm-agen
     84       5      908       2096       0.00   2428   3 CExecSvc
     87       5      936       1336       0.00   4716   4 CExecSvc
    203      13     3600      13132       2.53   3192   2 conhost
    210      13     3768      22948       0.08   5260   2 conhost
    257      11     1808        992       0.64    524   0 csrss
    116       8     1348        580       0.08    592   1 csrss
     85       5      532       1136       0.23   2440   3 csrss
    242      11     1848        952       0.42   2708   2 csrss
     95       5      592        980       0.00   4524   4 csrss
    137       9     7784       6776       0.05   5080   2 docker
    401      17    22744      14016      28.59   1748   0 dockerd
    307      18    13344       1628       0.17    936   1 dwm
    <SNIP>
   1888       0      128        136      37.17      4   0 System
    272      15     3372       2452       0.23   3340   2 TabTip
     72       7     1184          8       0.00   3400   2 TabTip32
    244      16     2676       3148       0.06   1880   2 taskhostw
    142       7     6172       6680       0.78   4952   3 WmiPrvSE
    148       8     5620      11028       0.77   5568   4 WmiPrvSE 
```

注意您的 Docker 主机上运行的进程比它们各自的容器多得多。Windows 容器运行的进程比 Windows 主机少得多，而 Linux 容器运行的进程比 Linux 主机少得多。

在之前的步骤中，你按下`Ctrl-PQ`退出了容器。在容器内部这样做会退出容器但不会杀死它。你可以使用`docker container ls`命令查看系统上所有正在运行的容器。

```
$ docker container ls
CONTAINER ID   IMAGE          COMMAND       CREATED  STATUS    NAMES
e2b69eeb55cb   ubuntu:latest  `"/bin/bash"`   `7` mins   Up `7` min  vigilant_borg 
```

上面的输出显示了一个正在运行的容器。这是你之前创建的容器。该输出中容器的存在证明它仍在运行。你还可以看到它是在 7 分钟前创建的，并且已经运行了 7 分钟。

#### 附加到正在运行的容器

你可以使用`docker container exec`命令将你的 shell 附加到正在运行的容器的终端上。由于之前的步骤中的容器仍在运行，让我们重新连接到它。

**Linux 示例：**

这个例子引用了一个名为“vigilant_borg”的容器。你的容器的名称将会不同，所以记得用你的 Docker 主机上正在运行的容器的名称或 ID 来替换“vigilant_borg”。

```
$ docker container `exec` -it vigilant_borg bash
root@e2b69eeb55cb:/# 
```

**Windows 示例：**

这个例子引用了一个名为“pensive_hamilton”的容器。你的容器的名称将会不同，所以记得用你的 Docker 主机上正在运行的容器的名称或 ID 来替换“pensive_hamilton”。

```
> docker container exec -it pensive_hamilton pwsh.exe

Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.
PS C:\> 
```

`注意你的 shell 提示符再次发生了变化。你再次登录到了容器中。

`docker container exec`命令的格式是：`docker container exec <options> <container-name or container-id> <command/app>`。在我们的例子中，我们使用了`-it`选项将我们的 shell 附加到容器的 shell 上。我们通过名称引用了容器，并告诉它运行 bash shell（在 Windows 示例中是 PowerShell）。我们也可以通过它的十六进制 ID 来引用容器。

再次按下`Ctrl-PQ`退出容器。

你的 shell 提示符应该回到你的 Docker 主机。

再次运行`docker container ls`命令来验证你的容器是否仍在运行。

```
$ docker container ls
CONTAINER ID   IMAGE          COMMAND       CREATED  STATUS    NAMES
e2b69eeb55cb   ubuntu:latest  `"/bin/bash"`   `9` mins   Up `9` min  vigilant_borg 
```

使用`docker container stop`和`docker container rm`命令停止并删除容器。记得用你自己容器的名称/ID 来替换。

```
$ docker container stop vigilant_borg
vigilant_borg

$ docker container rm vigilant_borg
vigilant_borg 
```

通过使用带有`-a`标志的`docker container ls`命令来验证容器是否成功删除。添加`-a`告诉 Docker 列出所有容器，即使是处于停止状态的。

```
$ docker container ls -a
CONTAINER ID    IMAGE    COMMAND    CREATED    STATUS    PORTS    NAMES 
```

`### 开发者视角

容器都是关于应用程序的！

在这一部分，我们将从 Git 仓库克隆一个应用程序，检查它的 Dockerfile，将其容器化，并作为一个容器运行。

Linux 应用程序可以从以下位置克隆：https://github.com/nigelpoulton/psweb.git

Windows 应用程序可以从以下位置克隆：https://github.com/nigelpoulton/dotnet-docker-samples.git

本节的其余部分将带你完成 Linux 示例。然而，两个示例都是将简单的 Web 应用程序容器化，所以过程是一样的。在 Windows 示例中有差异的地方，我们将突出显示，以帮助你跟上。

请从 Docker 主机上的终端运行以下所有命令。

在本地克隆存储库。这将把应用程序代码拉到您的本地 Docker 主机，准备让您将其容器化。

如果您正在按照 Windows 示例进行操作，请确保用 Windows 示例替换以下存储库。

```
$ git clone https://github.com/nigelpoulton/psweb.git
Cloning into `'psweb'`...
remote: Counting objects: `15`, `done`.
remote: Compressing objects: `100`% `(``11`/11`)`, `done`.
remote: Total `15` `(`delta `2``)`, reused `15` `(`delta `2``)`, pack-reused `0`
Unpacking objects: `100`% `(``15`/15`)`, `done`.
Checking connectivity... `done`. 
```

“切换到克隆存储库的目录并列出其内容。

```
$ `cd` psweb
$ ls -l
total `28`
-rw-rw-r-- `1` ubuntu ubuntu  `341` Sep `29` `12`:15 app.js
-rw-rw-r-- `1` ubuntu ubuntu  `216` Sep `29` `12`:15 circle.yml
-rw-rw-r-- `1` ubuntu ubuntu  `338` Sep `29` `12`:15 Dockerfile
-rw-rw-r-- `1` ubuntu ubuntu  `421` Sep `29` `12`:15 package.json
-rw-rw-r-- `1` ubuntu ubuntu  `370` Sep `29` `12`:15 README.md
drwxrwxr-x `2` ubuntu ubuntu `4096` Sep `29` `12`:15 `test`
drwxrwxr-x `2` ubuntu ubuntu `4096` Sep `29` `12`:15 views 
```

“对于 Windows 示例，您应该`cd`到`dotnet-docker-samples\aspnetapp`目录中。

Linux 示例是一个简单的 nodejs web 应用程序。Windows 示例是一个简单的 ASP.NET Core web 应用程序。

两个 Git 存储库都包含一个名为`Dockerfile`的文件。Dockerfile 是一个描述如何将应用程序构建成 Docker 镜像的纯文本文档。

列出 Dockerfile 的内容。

```
$ cat Dockerfile

FROM alpine
LABEL `maintainer``=``"nigelpoulton@hotmail.com"`
RUN apk add --update nodejs nodejs-npm
COPY . /src
WORKDIR /src
RUN  npm install
EXPOSE `8080`
ENTRYPOINT `[``"node"`, `"./app.js"``]` 
```

“Windows 示例中的 Dockerfile 的内容是不同的。然而，在这个阶段这并不重要。我们将在本书的后面更详细地介绍 Dockerfile。现在，理解每一行代表一个指令，用于构建一个镜像就足够了。”

此时，我们已经从远程 Git 存储库中拉取了一些应用程序代码。我们还有一个包含如何将应用程序构建成 Docker 镜像的 Dockerfile 中的指令。

使用`docker image build`命令根据 Dockerfile 中的指令创建一个新的镜像。这个示例创建了一个名为`test:latest`的新 Docker 镜像。

请确保在包含应用程序代码和 Dockerfile 的目录中执行此命令。

```
$ docker image build -t test:latest .

Sending build context to Docker daemon  `74`.75kB
Step `1`/8 : FROM alpine
latest: Pulling from library/alpine
88286f41530e: Pull `complete`
Digest: sha256:f006ecbb824...0c103f4820a417d
Status: Downloaded newer image `for` alpine:latest
 ---> 76da55c8019d
<Snip>
Successfully built f154cb3ddbd4
Successfully tagged test:latest 
```

“> **注意：**在 Windows 示例中，构建可能需要很长时间才能完成。这是因为正在拉取的镜像的大小和复杂性。

构建完成后，请检查新的`test:latest`镜像是否存在于您的主机上。

```
$ docker image ls
REPO     TAG      IMAGE ID        CREATED         SIZE
`test`     latest   f154cb3ddbd4    `1` minute ago    `55`.6MB
... 
```

现在你有了一个新构建的 Docker 镜像，里面有这个应用程序。

从该镜像运行一个容器并测试该应用程序。

**Linux 示例：**

```
$ docker container run -d `\`
  --name web1 `\`
  --publish `8080`:8080 `\`
  test:latest 
```

“打开一个 Web 浏览器，导航到运行容器的 Docker 主机的 DNS 名称或 IP 地址，并将其指向端口 8080。您将看到以下网页。

如果您正在使用 Docker for Windows 或 Docker for Mac 进行操作，您将能够使用`localhost:8080`或`127.0.0.1:8080`。如果您正在使用 Play with Docker 进行操作，您将能够点击终端屏幕上方的`8080`超链接。

![图 4.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure4-1.png)

图 4.1

**Windows 示例：**

```
> docker container run -d \
  --name web1 \
  --publish 8080:8080 \
  test:latest 
```

打开一个网络浏览器，导航到正在运行容器的 Docker 主机的 DNS 名称或 IP 地址，并将其指向端口 8080。您将看到以下网页。

如果您正在使用 Docker for Windows 或 Play with Docker 进行操作，同样的规则也适用。

![图 4.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure4-2.png)

图 4.2

干得好。您已经从远程 Git 存储库中获取了一些应用程序代码，并将其构建成了一个 Docker 镜像。然后您从中运行了一个容器。我们称之为“容器化应用程序”。

### 章节总结

在本章的 Op 部分中，您下载了一个 Docker 镜像，从中启动了一个容器，登录到了容器中，执行了其中的一个命令，然后停止并删除了容器。

在 Dev 部分，您通过从 GitHub 拉取一些源代码并使用 Dockerfile 中的指令将其构建成一个镜像，将一个简单的应用程序容器化。然后您运行了容器化的应用程序。

这个*大局观*应该会帮助您理解接下来的章节，我们将在其中更深入地了解镜像和容器。```````````````````````


# 第二部分：技术内容


# 第六章：Docker 引擎

在本章中，我们将快速查看 Docker 引擎的内部情况。

你可以在不了解本章内容的情况下使用 Docker。所以，随意跳过它。然而，要成为真正的专家，你需要了解底层发生了什么。所以，要成为一个*真正*的 Docker 专家，你需要了解本章的内容。

这将是一个基于理论的章节，没有实际操作练习。

由于本章是书中**技术部分**的一部分，我们将采用三层方法，将章节分为三个部分：

+   **简而言之：** 两三段简短的内容，你可以在排队买咖啡时阅读

+   **深入挖掘：** 我们深入细节的部分

+   **命令：** 我们学到的命令的快速回顾

让我们去学习关于 Docker 引擎的知识！

### Docker 引擎 - 简而言之

*Docker 引擎*是运行和管理容器的核心软件。我们经常简称为*Docker*或*Docker 平台*。如果你对 VMware 有所了解，把它想象成类似于 ESXi 可能会有所帮助。

Docker 引擎的设计是模块化的，具有许多可互换的组件。在可能的情况下，这些组件基于开放标准，由开放容器倡议（OCI）概述。

在许多方面，Docker 引擎就像汽车引擎 - 都是模块化的，通过连接许多小的专门部件创建而成：

+   汽车引擎由许多专门的部件组成，这些部件共同工作使汽车行驶 - 进气歧管、节气门、气缸、火花塞、排气歧管等。

+   Docker 引擎由许多专门的工具组成，这些工具共同工作以创建和运行容器 - API、执行驱动程序、运行时、shims 等。

在撰写本文时，构成 Docker 引擎的主要组件有：*Docker 客户端*、*Docker 守护程序*、*containerd*和*runc*。这些组件共同创建和运行容器。

图 5.1 显示了一个高层次的视图。

![图 5.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure5-1.png)

图 5.1

在整本书中，我们将用小写字母“r”和“c”来指代`runc`和`containerd`。这意味着以`____r____unc` `____c____ontainerd`开头的句子将不以大写字母开头。这是故意的，不是错误。

### Docker 引擎 - 深入挖掘

当 Docker 首次发布时，Docker 引擎有两个主要组件：

+   Docker 守护程序（以下简称“守护程序”）

+   LXC

Docker 守护程序是一个单一的二进制文件。它包含了 Docker 客户端、Docker API、容器运行时、镜像构建等等的所有代码。

LXC 为守护程序提供了访问 Linux 内核中存在的容器的基本构建模块。诸如*命名空间*和*控制组（cgroups）*之类的东西。

图 5.2 显示了在旧版本的 Docker 中守护程序、LXC 和操作系统是如何交互的。

![图 5.2 以前的 Docker 架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure5-2.png)

图 5.2 以前的 Docker 架构

#### 摆脱 LXC

从一开始就依赖 LXC 是一个问题。

首先，LXC 是特定于 Linux 的。这对于一个有多平台愿景的项目来说是一个问题。

其次，对于一个如此核心的项目来说，依赖外部工具是一个巨大的风险，可能会阻碍开发。

因此，Docker. Inc.开发了他们自己的工具*libcontainer*来替代 LXC。*libcontainer*的目标是成为一个平台无关的工具，为 Docker 提供访问内核中存在的基本容器构建模块。

Libcontainer 在 Docker 0.9 中取代了 LXC 成为默认的*执行驱动程序*。

#### 摆脱单一的 Docker 守护程序

随着时间的推移，Docker 守护程序的单一性变得越来越成问题：

1.  这很难进行创新。

1.  它变得更慢了。

1.  这并不是生态系统（或 Docker, Inc.）想要的。

Docker, Inc.意识到了这些挑战，并开始了一项巨大的工作，以拆分单一的守护程序并使其模块化。这项工作的目标是尽可能地从守护程序中分离出尽可能多的功能，并在较小的专门工具中重新实现它。这些专门工具可以被替换，也可以被第三方轻松重用以构建其他工具。这个计划遵循了经过验证的 Unix 哲学，即构建小型专门的工具，可以拼接成更大的工具。

拆分和重构 Docker 引擎的工作是一个持续的过程。然而，它已经看到**所有的*容器执行*和容器*运行时*代码完全从守护程序中移除，并重构为小型的专门工具**。

图 5.3 显示了当前 Docker 引擎架构的高层视图，并附有简要描述。

![图 5.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure5-3.png)

图 5.3

#### 开放容器倡议（OCI）的影响

在 Docker 公司拆分守护程序并重构代码的同时，OCI 正在定义两个与容器相关的规范（也称为标准）：

1.  [镜像规范](https://github.com/opencontainers/image-spec)

1.  [容器运行时规范](https://github.com/opencontainers/runtime-spec/blob/master/RELEASES.md)

这两个规范于 2017 年 7 月发布为 1.0 版本。

Docker 公司在创建这些规范方面发挥了重要作用，并为其贡献了大量代码。

从 Docker 1.11（2016 年初）开始，Docker 引擎尽可能地实现了 OCI 规范。例如，Docker 守护程序不再包含任何容器运行时代码 — 所有容器运行时代码都在一个单独的符合 OCI 规范的层中实现。默认情况下，Docker 使用一个名为*runc*的工具。runc 是 OCI 容器运行时规范的*参考实现*。这是图 5.3 中的`runc`容器运行时层。runc 项目的目标是与 OCI 规范保持一致。然而，现在 OCI 规范都已经达到 1.0 版本，我们不应该期望它们会有太多迭代 — 稳定性才是关键。

此外，Docker 引擎的*containerd*组件确保 Docker 镜像以有效的 OCI 捆绑包形式呈现给*runc*。

> **注意：** Docker 引擎在规范正式发布为 1.0 版本之前就已经实现了 OCI 规范的部分内容。

#### runc

如前所述，*runc*是 OCI 容器运行时规范的参考实现。Docker 公司在定义规范和开发 runc 方面发挥了重要作用。

如果你剥离其他一切，runc 只是一个小巧、轻量级的 CLI 包装器，用于 libcontainer（请记住，libcontainer 最初替代了 Docker 早期架构中的 LXC）。

runc 在生活中只有一个目的 — 创建容器。而且它做得非常好。而且快！但由于它是一个 CLI 包装器，它实际上是一个独立的容器运行时工具。这意味着您可以下载和构建二进制文件，然后就拥有了构建和使用 runc（OCI）容器所需的一切。但它只是基本功能，您将无法获得完整的 Docker 引擎所具有的丰富功能。

我们有时称 runc 操作的层为“OCI 层”。参见图 5.3。

您可以在以下链接查看 runc 的发布信息：

+   https://github.com/opencontainers/runc/releases

#### containerd

作为从 Docker 守护程序中剥离功能的努力的一部分，所有容器执行逻辑都被剥离并重构为一个名为 containerd（发音为 container-dee）的新工具。它的唯一目的是管理容器的生命周期操作-`start | stop | pause | rm...`。

containerd 可用作 Linux 和 Windows 的守护程序，并且自 1.11 版本以来，Docker 一直在 Linux 上使用它。在 Docker 引擎堆栈中，containerd 位于守护程序和 OCI 层的 runc 之间。Kubernetes 也可以通过 cri-containerd 使用 containerd。

正如先前所述，containerd 最初旨在小巧，轻量，并设计用于生命周期操作。然而，随着时间的推移，它已经扩展并承担了更多功能。比如镜像管理。

其中一个原因是为了使它更容易在其他项目中使用。例如，containerd 是 Kubernetes 中流行的容器运行时。然而，在像 Kubernetes 这样的项目中，containerd 能够执行额外的操作，比如推送和拉取镜像，这是有益的。因此，containerd 现在做的不仅仅是简单的容器生命周期管理。然而，所有额外的功能都是模块化和可选的，这意味着你可以选择你想要的部分。因此，可以将 containerd 包含在诸如 Kubernetes 之类的项目中，但只需选择你的项目需要的部分。

containerd 是由 Docker，Inc.开发的，并捐赠给了 Cloud Native Computing Foundation（CNCF）。它于 2017 年 12 月发布了 1.0 版本。您可以在以下链接查看发布信息：

+   https://github.com/containerd/containerd/releases

#### 启动一个新容器（示例）

现在我们已经了解了整体情况和部分历史，让我们来看看创建一个新容器的过程。

启动容器的最常见方式是使用 Docker CLI。以下`docker container run`命令将基于`alpine:latest`镜像启动一个简单的新容器。

```
$ docker container run --name ctr1 -it alpine:latest sh 
```

`当您在 Docker CLI 中输入这样的命令时，Docker 客户端会将它们转换为适当的 API 负载并将其 POST 到正确的 API 端点。`

API 是在守护程序中实现的。这是相同丰富，版本化的 REST API，已成为 Docker 的标志，并在行业中被接受为事实上的容器 API。

一旦守护进程接收到创建新容器的命令，它就会调用 containerd。请记住，守护进程不再包含任何创建容器的代码！

守护进程通过 [gRPC](https://grpc.io/) 与 containerd 进行 CRUD 风格的 API 通信。

尽管 *containerd* 的名字中带有“container”，但它实际上不能创建容器。它使用 *runc* 来完成这个任务。它将所需的 Docker 镜像转换为 OCI bundle，并告诉 runc 使用这个 bundle 来创建一个新的容器。

runc 与操作系统内核进行接口，汇集所有必要的构造来创建一个容器（命名空间、cgroups 等）。容器进程作为 runc 的子进程启动，一旦启动，runc 就会退出。

哇！容器现在已经启动了。

这个过程在图 5.4 中总结了。

![图 5.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure5-4.png)

图 5.4

#### 这种模型的一个巨大好处

从守护进程中移除了启动和管理容器的所有逻辑和代码意味着整个容器运行时与 Docker 守护进程解耦。我们有时称之为“无守护进程的容器”，这使得可以在不影响正在运行的容器的情况下对 Docker 守护进程进行维护和升级！

在旧模型中，容器运行时逻辑全部实现在守护进程中，关闭守护进程会导致主机上所有运行的容器被杀死。这在生产环境中是一个巨大的问题——特别是考虑到 Docker 的新版本发布频率！每次守护进程升级都会杀死主机上的所有容器——这不好！

幸运的是，这不再是一个问题。

#### 这个 shim 到底是什么？

本章中的一些图表显示了一个 shim 组件。

shim 对于实现无守护进程的容器（就是我们刚刚提到的将运行的容器与守护进程解耦以进行守护进程升级等操作）是至关重要的。

我们之前提到 *containerd* 使用 runc 来创建新的容器。实际上，它为每个创建的容器分叉出一个新的 runc 实例。然而，一旦每个容器被创建，它的父 runc 进程就会退出。这意味着我们可以运行数百个容器而不必运行数百个 runc 实例。

一旦一个容器的父 runc 进程退出，相关的 containerd-shim 进程就成为容器的父进程。shim 作为容器的父进程执行的一些职责包括：

+   保持任何 STDIN 和 STDOUT 流保持打开，这样当守护进程重新启动时，容器不会因为管道关闭而终止等。

+   向守护进程报告容器的退出状态。

#### 在 Linux 上的实现方式

在 Linux 系统上，我们讨论过的组件被实现为以下独立的二进制文件：

+   `dockerd`（Docker 守护进程）

+   `docker-containerd`（containerd）

+   `docker-containerd-shim`（shim）

+   `docker-runc`（runc）

你可以通过在 Docker 主机上运行 `ps` 命令来在 Linux 系统上看到所有这些。显然，当系统有运行的容器时，其中一些将会存在。

#### 那么守护进程的目的是什么

当守护进程中剥离了所有的执行和运行时代码，你可能会问这个问题：“守护进程中还剩下什么？”。

显然，随着越来越多的功能被剥离和模块化，这个问题的答案会随着时间的推移而改变。然而，在撰写本文时，仍然存在于守护进程中的一些主要功能包括：镜像管理、镜像构建、REST API、身份验证、安全性、核心网络和编排。

### 章节总结

Docker 引擎在设计上是模块化的，并且严重依赖于 OCI 的开放标准。

*Docker 守护进程* 实现了 Docker API，这是一个丰富、版本化的 HTTP API，它是随着 Docker 项目的其余部分一起发展的。

容器执行由 *containerd* 处理。containerd 是由 Docker, Inc. 编写并贡献给 CNCF 的。你可以把它看作是一个处理容器生命周期操作的容器监督程序。它小巧轻便，可以被其他项目和第三方工具使用。例如，它被认为将成为 Kubernetes 中默认和最常见的容器运行时。

containerd 需要与符合 OCI 标准的容器运行时进行通信，以实际创建容器。默认情况下，Docker 使用 *runc* 作为其默认的容器运行时。runc 是 OCI 容器运行时规范的事实实现，并且期望从符合 OCI 标准的捆绑包中启动容器。containerd 与 runc 进行通信，并确保 Docker 镜像以符合 OCI 标准的捆绑包的形式呈现给 runc。

runc 可以作为一个独立的 CLI 工具来创建容器。它基于 libcontainer 的代码，并且也可以被其他项目和第三方工具使用。

Docker 守护程序中仍然实现了许多功能。随着时间的推移，这些功能可能会进一步拆分。目前仍然包含在 Docker 守护程序中的功能包括但不限于：API、镜像管理、身份验证、安全功能、核心网络和卷管理。

模块化 Docker 引擎的工作正在进行中。


# 第七章：镜像

在本章中，我们将深入探讨 Docker 镜像。游戏的目标是让您对 Docker 镜像有一个**扎实的理解**，以及如何执行基本操作。在后面的章节中，我们将看到如何在其中构建包含我们自己应用程序的新镜像（容器化应用程序）。

我们将把本章分为通常的三个部分：

+   TLDR

+   深入了解

+   命令

让我们去学习关于镜像的知识吧！

### Docker 镜像- TLDR

如果您曾经是虚拟机管理员，您可以将 Docker 镜像视为类似于 VM 模板。VM 模板就像是一个停止的 VM- Docker 镜像就像是一个停止的容器。如果您是开发人员，您可以将它们视为类似于*类*。

您可以从镜像注册表中*拉取*镜像开始。最受欢迎的注册表是[Docker Hub](https://hub.docker.com)，但也存在其他注册表。*拉取*操作会将镜像下载到本地 Docker 主机，您可以在其中使用它来启动一个或多个 Docker 容器。

镜像由多个层组成，这些层堆叠在一起并表示为单个对象。镜像中包含一个精简的操作系统（OS）以及运行应用程序所需的所有文件和依赖项。由于容器旨在快速和轻量级，因此镜像往往很小。

恭喜！您现在对 Docker 镜像有了一点概念 :-D 现在是时候让您大开眼界了！

### Docker 镜像-深入了解

我们已经多次提到**镜像**就像是停止的容器（或者如果您是开发人员，就像是**类**）。事实上，您可以停止一个容器并从中创建一个新的镜像。考虑到这一点，镜像被认为是*构建时*构造，而容器是*运行时*构造。

![图 6.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-1.png)

图 6.1

#### 镜像和容器

图 6.1 显示了镜像和容器之间关系的高层视图。我们使用`docker container run`和`docker service create`命令从单个镜像启动一个或多个容器。但是，一旦您从镜像启动了一个容器，这两个构造就会相互依赖，直到最后一个使用它的容器停止和销毁之前，您不能删除该镜像。尝试删除一个正在使用的镜像而不停止和销毁所有使用它的容器将导致以下错误：

```
$ docker image rm <image-name>
Error response from daemon: conflict: unable to remove repository reference `\`
`"<image-name>"` `(`must force`)` - container <container-id> is using its referenc`\`
ed image <image-id> 
```

`#### 镜像通常很小

容器的整个目的是运行应用程序或服务。这意味着容器创建的镜像必须包含运行应用程序/服务所需的所有操作系统和应用程序文件。但是，容器的全部意义在于快速和轻量级。这意味着它们构建的镜像通常很小，并且剥离了所有非必要的部分。

例如，Docker 镜像不会为您提供 6 种不同的 shell 供您选择 - 它们通常只提供一个最小化的 shell，或者根本不提供 shell。它们也不包含内核 - 在 Docker 主机上运行的所有容器共享对主机内核的访问。因此，我们有时会说镜像包含*足够的操作系统*（通常只有与操作系统相关的文件和文件系统对象）。

> **注意：** Hyper-V 容器在专用的轻量级虚拟机内运行，并利用虚拟机内运行的操作系统的内核。

官方的*Alpine Linux* Docker 镜像大约为 4MB，是 Docker 镜像可以有多小的一个极端示例。这不是打字错误！它确实大约为 4 兆字节！然而，一个更典型的例子可能是官方的 Ubuntu Docker 镜像，目前大约为 110MB。这些显然剥离了大多数非必要的部分！

基于 Windows 的镜像往往比基于 Linux 的镜像大，这是因为 Windows 操作系统的工作方式。例如，最新的 Microsoft .NET 镜像（`microsoft/dotnet:latest`）在拉取和解压缩时超过 1.7GB。Windows Server 2016 Nano Server 镜像（`microsoft/nanoserver:latest`）在拉取和解压缩时略大于 1GB。

#### 拉取镜像

干净安装的 Docker 主机在其本地存储库中没有任何镜像。

基于 Linux 的 Docker 主机上的本地镜像存储库通常位于`/var/lib/docker/<storage-driver>`。在基于 Windows 的 Docker 主机上，这是`C:\ ProgramData\docker\windowsfilter`。

您可以使用以下命令检查您的 Docker 主机是否在其本地存储库中有任何镜像。

```
$ docker image ls
REPOSITORY  TAG      IMAGE ID       CREATED         SIZE 
```

将镜像放入 Docker 主机的过程称为*拉取*。因此，如果您想要在 Docker 主机上获取最新的 Ubuntu 镜像，您需要*拉取*它。使用以下命令*拉取*一些镜像，然后检查它们的大小。

> 如果您在 Linux 上进行操作，并且尚未将您的用户帐户添加到本地`docker` Unix 组中，则可能需要在所有以下命令的开头添加`sudo`。

Linux 示例：

```
$ docker image pull ubuntu:latest

latest: Pulling from library/ubuntu
b6f892c0043b: Pull `complete`
55010f332b04: Pull `complete`
2955fb827c94: Pull `complete`
3deef3fcbd30: Pull `complete`
cf9722e506aa: Pull `complete`
Digest: sha256:38245....44463c62a9848133ecb1aa8
Status: Downloaded newer image `for` ubuntu:latest

$ docker image pull alpine:latest

latest: Pulling from library/alpine
cfc728c1c558: Pull `complete`
Digest: sha256:c0537...497c0a7726c88e2bb7584dc96
Status: Downloaded newer image `for` alpine:latest

$ docker image ls

REPOSITORY   TAG     IMAGE ID        CREATED       SIZE
ubuntu       latest  ebcd9d4fca80    `3` days ago    118MB
alpine       latest  02674b9cb179    `8` days ago    `3`.99MB 
```

Windows 示例：

```
> docker image pull microsoft/powershell:nanoserver

nanoserver: Pulling from microsoft/powershell
bce2fbc256ea: Pull complete
58f68fa0ceda: Pull complete
04083aac0446: Pull complete
e42e2e34b3c8: Pull complete
0c10d79c24d4: Pull complete
715cb214dca4: Pull complete
a4837c9c9af3: Pull complete
2c79a32d92ed: Pull complete
11a9edd5694f: Pull complete
d223b37dbed9: Pull complete
aee0b4393afb: Pull complete
0288d4577536: Pull complete
8055826c4f25: Pull complete
Digest: sha256:090fe875...fdd9a8779592ea50c9d4524842
Status: Downloaded newer image for microsoft/powershell:nanoserver
>
> docker image pull microsoft/dotnet:latest

latest: Pulling from microsoft/dotnet
bce2fbc256ea: Already exists
4a8c367fd46d: Pull complete
9f49060f1112: Pull complete
0334ad7e5880: Pull complete
ea8546db77c6: Pull complete
710880d5cbd5: Pull complete
d665d26d9a25: Pull complete
caa8d44fb0b1: Pull complete
cfd178ff221e: Pull complete
Digest: sha256:530343cd483dc3e1...6f0378e24310bd67d2a
Status: Downloaded newer image for microsoft/dotnet:latest
>
> docker image ls
REPOSITORY            TAG         IMAGE ID    CREATED     SIZE
microsoft/dotnet      latest      831..686d   7 hrs ago   1.65 GB
microsoft/powershell  nanoserver  d06..5427   8 days ago  1.21 GB 
```

正如你所看到的，刚刚拉取的镜像现在存在于 Docker 主机的本地存储库中。你还可以看到 Windows 镜像要大得多，并且包含了更多的层。

#### 镜像命名

在每个命令的一部分，我们必须指定要拉取的镜像。所以让我们花点时间来看看镜像命名。为此，我们需要了解一些关于如何存储镜像的背景知识。

#### 镜像注册表

Docker 镜像存储在*镜像注册表*中。最常见的注册表是 Docker Hub（https://hub.docker.com）。还有其他注册表，包括第三方注册表和安全的本地注册表。然而，Docker 客户端有自己的偏好，并默认使用 Docker Hub。我们将在本书的其余部分使用 Docker Hub。

镜像注册表包含多个*镜像存储库*。反过来，镜像存储库可以包含多个镜像。这可能有点令人困惑，因此图 6.2 显示了一个包含 3 个存储库的镜像注册表的图片，每个存储库包含一个或多个镜像。

![图 6.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-2.png)

图 6.2

##### 官方和非官方存储库

Docker Hub 还有*官方存储库*和*非官方存储库*的概念。

正如名称所示，*官方存储库*包含了经过 Docker, Inc.审核的镜像。这意味着它们应该包含最新的、高质量的代码，安全、有良好的文档，并符合最佳实践（请问我能否因在一个句子中使用了五个连字符而获得奖励）。

*非官方存储库*可能像是荒野——你不应该*期望*它们是安全的、有良好的文档或者按照最佳实践构建的。这并不是说*非官方存储库*中的所有东西都是坏的！*非官方存储库*中有一些**精彩**的东西。你只需要在信任它们的代码之前非常小心。老实说，当从互联网获取软件时，你应该始终小心——甚至是从*官方存储库*获取的镜像！

大多数流行的操作系统和应用程序在 Docker Hub 上都有自己的*官方存储库*。它们很容易识别，因为它们位于 Docker Hub 命名空间的顶层。以下列表包含了一些*官方存储库*，并显示了它们在 Docker Hub 命名空间顶层存在的 URL：

+   **nginx:** https://hub.docker.com/_/nginx/

+   **busybox:** https://hub.docker.com/_/busybox/

+   **redis:** https://hub.docker.com/_/redis/

+   **mongo:** https://hub.docker.com/_/mongo/

另一方面，我的个人图像存储在*非官方存储库*的荒野中，不应该被信任！以下是我存储库中图像的一些示例：

+   nigelpoulton/tu-demo

https://hub.docker.com/r/nigelpoulton/tu-demo/

+   nigelpoulton/pluralsight-docker-ci

https://hub.docker.com/r/nigelpoulton/pluralsight-docker-ci/

我的存储库中的图像不仅没有经过审查，也没有及时更新，不安全，文档也不完善... 你还应该注意到它们并不位于 Docker Hub 命名空间的顶层。我的存储库都位于一个名为`nigelpoulton`的二级命名空间中。

你可能会注意到我们使用的 Microsoft 图像并不位于 Docker Hub 命名空间的顶层。在撰写本文时，它们存在于`microsoft`的二级命名空间下。

经过所有这些之后，我们终于可以看一下如何在 Docker 命令行中处理图像。

#### 图像命名和标记

从官方存储库中寻址图像就像简单地给出存储库名称和标签，用冒号（`:`）分隔。当使用来自官方存储库的图像时，`docker image pull`的格式为：

`docker image pull <repository>:<tag>`

在之前的 Linux 示例中，我们使用以下两个命令拉取了 Alpine 和 Ubuntu 图像：

`docker image pull alpine:latest` 和 `docker image pull ubuntu:latest`

这两个命令从“alpine”和“ubuntu”存储库中拉取标记为“latest”的图像。

以下示例展示了如何从*官方存储库*中拉取不同的图像：

```
$ docker image pull mongo:3.3.11
//This will pull the image tagged as ````3`.3.11```
//from the official ```mongo``` repository.

$ docker image pull redis:latest
//This will pull the image tagged as ```latest```
//from the official ```redis``` repository.

$ docker image pull alpine
//This will pull the image tagged as ```latest```
//from the official ```alpine``` repository. 
```

`关于这些命令的一些要点。

首先，如果在存储库名称后**没有**指定图像标签，Docker 将假定你指的是标记为`latest`的图像。

其次，`latest`标签并没有任何神奇的功能！仅仅因为一个图像被标记为`latest`并不意味着它是存储库中最新的图像！例如，`alpine`存储库中最新的图像通常被标记为`edge`。故事的寓意是——在使用`latest`标签时要小心！

从*非官方仓库*中拉取图像本质上是一样的——你只需要在仓库名称前加上一个 Docker Hub 用户名或组织名称。下面的例子展示了如何从一个不可信任的人拥有的 Docker Hub 帐户名为`nigelpoulton`的`tu-demo`仓库中拉取`v2`图像。

```
$ docker image pull nigelpoulton/tu-demo:v2
//This will pull the image tagged as ```v2```
//from the ```tu-demo``` repository within the namespace
//of my personal Docker Hub account. 
```

`在我们之前的 Windows 示例中，我们用以下两个命令拉取了一个 PowerShell 和一个.NET 图像：

`> docker image pull microsoft/powershell:nanoserver`

`> docker image pull microsoft/dotnet:latest`

第一个命令从`microsoft/powershell`仓库中拉取标记为`nanoserver`的图像。第二个命令从`microsoft/dotnet`仓库中拉取标记为`latest`的图像。

如果你想从第三方注册表（而不是 Docker Hub）中拉取图像，你需要在仓库名称前加上注册表的 DNS 名称。例如，如果上面的例子中的图像在 Google 容器注册表（GCR）中，你需要在仓库名称前添加`gcr.io`，如下所示——`docker pull gcr.io/nigelpoulton/tu-demo:v2`（没有这样的仓库和图像存在）。

你可能需要在从第三方注册表中拉取图像之前在其上拥有一个帐户并登录。

#### 具有多个标签的图像

关于图像标签的最后一句话…… 一个单独的图像可以有任意多个标签。这是因为标签是存储在图像旁边的元数据的任意字母数字值。让我们来看一个例子。

通过在`docker image pull`命令中添加`-a`标志来拉取仓库中的所有图像。然后运行`docker image ls`来查看拉取的图像。如果你正在使用 Windows，你可以从`microsoft/nanoserver`仓库中拉取，而不是`nigelpoulton/tu-demo`。

> **注意：**如果你从中拉取的仓库包含多个架构和平台的图像，比如 Linux **和** Windows，该命令可能会失败。

```
$ docker image pull -a nigelpoulton/tu-demo

latest: Pulling from nigelpoulton/tu-demo
237d5fcd25cf: Pull `complete`
a3ed95caeb02: Pull `complete`
<Snip>
Digest: sha256:42e34e546cee61adb1...3a0c5b53f324a9e1c1aae451e9
v1: Pulling from nigelpoulton/tu-demo
237d5fcd25cf: Already exists
a3ed95caeb02: Already exists
<Snip>
Digest: sha256:9ccc0c67e5c5eaae4b...624c1d5c80f2c9623cbcc9b59a
v2: Pulling from nigelpoulton/tu-demo
237d5fcd25cf: Already exists
a3ed95caeb02: Already exists
<Snip>
Digest: sha256:d3c0d8c9d5719d31b7...9fef58a7e038cf0ef2ba5eb74c
Status: Downloaded newer image `for` nigelpoulton/tu-demo

$ docker image ls
REPOSITORY            TAG       IMAGE ID       CREATED    SIZE
nigelpoulton/tu-demo   v2       6ac21e..bead   `1` yr ago   `211`.6 MB
nigelpoulton/tu-demo   latest   9b915a..1e29   `1` yr ago   `211`.6 MB
nigelpoulton/tu-demo   v1       9b915a..1e29   `1` yr ago   `211`.6 MB 
```

关于刚刚发生的一些事情：

首先，该命令从`nigelpoulton/tu-demo`仓库中拉取了三个图像：`latest`、`v1`和`v2`。

其次，请仔细查看`docker image ls`命令的输出中的`IMAGE ID`列。您会发现只有两个唯一的图像 ID。这是因为实际上只有两个图像被下载。这是因为两个标签指向相同的图像。换句话说...其中一个图像有两个标签。如果您仔细观察，您会发现`v1`和`latest`标签具有相同的`IMAGE ID`。这意味着它们是**同一图像**的两个标签。

这是一个关于`latest`标签的警告的完美例子。在这个例子中，`latest`标签指的是与`v1`标签相同的图像。这意味着它指向两个图像中较旧的一个，而不是最新的一个！`latest`是一个任意的标签，并不能保证指向存储库中最新的图像！

#### 过滤`docker image ls`的输出

Docker 提供了`--filter`标志来过滤由`docker image ls`返回的图像列表。

以下示例将仅返回悬空图像。

```
$ docker image ls --filter `dangling``=``true`
REPOSITORY    TAG       IMAGE ID       CREATED       SIZE
<none>        <none>    4fd34165afe0   `7` days ago    `14`.5MB 
```

悬空图像是不再标记的图像，并在列表中显示为`<none>:<none>`。它们出现的常见方式是在构建新图像并使用现有标签对其进行标记时。当这种情况发生时，Docker 将构建新图像，注意到现有图像具有匹配的标签，从现有图像中删除标签，并将标签赋予新图像。例如，您基于`alpine:3.4`构建了一个新图像，并将其标记为`dodge:challenger`。然后，您更新 Dockerfile 以将`alpine:3.4`替换为`alpine:3.5`，并运行完全相同的`docker image build`命令。构建将创建一个新图像，标记为`dodge:challenger`，并从旧图像中删除标签。旧图像将变成悬空图像。

您可以使用`docker image prune`命令删除系统上的所有悬空图像。如果添加`-a`标志，Docker 还将删除所有未使用的图像（即任何容器未使用的图像）。

Docker 目前支持以下过滤器：

+   `dangling:`接受`true`或`false`，并仅返回悬空图像（true）或非悬空图像（false）。

+   `before:`需要一个图像名称或 ID 作为参数，并返回在其之前创建的所有图像。

+   `since:`与上述相同，但返回在指定图像之后创建的图像。

+   `label:`根据标签或标签和值的存在来过滤图像。`docker image ls`命令不会在其输出中显示标签。

对于所有其他过滤，您可以使用`reference`。

以下是一个使用`reference`来仅显示标记为“latest”的图像的例子。

```
$ docker image ls --filter`=``reference``=``"*:latest"`
REPOSITORY   TAG      IMAGE ID        CREATED        SIZE
alpine       latest   3fd9065eaf02    `8` days ago     `4`.15MB
`test`         latest   8426e7efb777    `3` days ago     122MB 
```

`您还可以使用`--format`标志使用 Go 模板格式化输出。例如，以下命令将仅返回 Docker 主机上图像的大小属性。

```
$ docker image ls --format `"{{.Size}}"`
`99`.3MB
111MB
`82`.6MB
`88`.8MB
`4`.15MB
108MB 
```

`使用以下命令返回所有图像，但仅显示存储库、标签和大小。

```
$ docker image ls --format `"{{.Repository}}: {{.Tag}}: {{.Size}}"`
dodge:  challenger: `99`.3MB
ubuntu: latest:     111MB
python: `3`.4-alpine: `82`.6MB
python: `3`.5-alpine: `88`.8MB
alpine: latest:     `4`.15MB
nginx:  latest:     108MB 
```

`如果您需要更强大的过滤功能，您可以随时使用操作系统和 shell 提供的工具，如`grep`和`awk`。

#### 从 CLI 搜索 Docker Hub

`docker search`命令允许您从 CLI 搜索 Docker Hub。您可以针对“NAME”字段中的字符串进行模式匹配，并根据返回的任何列来过滤输出。

在其最简单的形式中，它搜索包含在“NAME”字段中的特定字符串的所有存储库。例如，以下命令搜索所有在“NAME”字段中包含“nigelpoulton”的存储库。

```
$ docker search nigelpoulton
NAME                         DESCRIPTION               STARS   AUTOMATED
nigelpoulton/pluralsight..   Web app used in...        `8`       `[`OK`]`
nigelpoulton/tu-demo                                   `7`
nigelpoulton/k8sbook         Kubernetes Book web app   `1`
nigelpoulton/web-fe1         Web front end example     `0`
nigelpoulton/hello-cloud     Quick hello-world image   `0` 
```

“NAME”字段是存储库名称，并包括非官方存储库的 Docker ID 或组织名称。例如，以下命令将列出所有包含名称中包含“alpine”的存储库。

```
$ docker search alpine
NAME                   DESCRIPTION          STARS    OFFICIAL    AUTOMATED
alpine                 A minimal Docker..   `2988`     `[`OK`]`
mhart/alpine-node      Minimal Node.js..    `332`
anapsix/alpine-java    Oracle Java `8`...     `270`                  `[`OK`]`
<Snip> 
```

`注意一下，返回的一些存储库是官方的，一些是非官方的。您可以使用`--filter "is-official=true"`，这样只有官方存储库才会显示。

```
$ docker search alpine --filter `"is-official=true"`
NAME                   DESCRIPTION          STARS    OFFICIAL    AUTOMATED
alpine                 A minimal Docker..   `2988`     `[`OK`]` 
```

`您可以再次执行相同的操作，但这次只显示具有自动构建的存储库。

```
$ docker search alpine --filter `"is-automated=true"`
NAME                       DESCRIPTION               OFFICIAL     AUTOMATED
anapsix/alpine-java        Oracle Java `8` `(`and `7``)`..                `[`OK`]`
frolvlad/alpine-glibc      Alpine Docker image..                  `[`OK`]`
kiasaki/alpine-postgres    PostgreSQL docker..                    `[`OK`]`
zzrot/alpine-caddy         Caddy Server Docker..                  `[`OK`]`
<Snip> 
```

`关于`docker search`的最后一件事。默认情况下，Docker 只会显示 25 行结果。但是，您可以使用`--limit`标志将其增加到最多 100 行。

#### 图像和层

Docker 图像只是一堆松散连接的只读层。这在图 6.3 中显示出来。

![图 6.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-3.png)

图 6.3

Docker 负责堆叠这些层并将它们表示为单个统一的对象。

有几种方法可以查看和检查构成图像的层，我们已经看到其中一种。让我们再次看一下之前`docker image pull ubuntu:latest`命令的输出：

```
$ docker image pull ubuntu:latest
latest: Pulling from library/ubuntu
952132ac251a: Pull `complete`
82659f8f1b76: Pull `complete`
c19118ca682d: Pull `complete`
8296858250fe: Pull `complete`
24e0251a0e2c: Pull `complete`
Digest: sha256:f4691c96e6bbaa99d...28ae95a60369c506dd6e6f6ab
Status: Downloaded newer image `for` ubuntu:latest 
```

`上面输出中以“Pull complete”结尾的每一行代表了被拉取的图像中的一个层。正如我们所看到的，这个图像有 5 个层。图 6.4 以图片形式显示了这一点，显示了层 ID。

![图 6.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-4.png)

图 6.4

查看图像的层的另一种方法是使用`docker image inspect`命令检查图像。以下示例检查了相同的`ubuntu:latest`图像。

```
$ docker image inspect ubuntu:latest
`[`
    `{`
        `"Id"`: `"sha256:bd3d4369ae.......fa2645f5699037d7d8c6b415a10"`,
        `"RepoTags"`: `[`
            `"ubuntu:latest"`

        <Snip>

        `"RootFS"`: `{`
            `"Type"`: `"layers"`,
            `"Layers"`: `[`
                `"sha256:c8a75145fc...894129005e461a43875a094b93412"`,
                `"sha256:c6f2b330b6...7214ed6aac305dd03f70b95cdc610"`,
                `"sha256:055757a193...3a9565d78962c7f368d5ac5984998"`,
                `"sha256:4837348061...12695f548406ea77feb5074e195e3"`,
                `"sha256:0cad5e07ba...4bae4cfc66b376265e16c32a0aae9"`
            `]`
        `}`
    `}`
`]` 
```

修剪后的输出再次显示了 5 个图层。只是这一次它们使用它们的 SHA256 哈希值显示。然而，两个命令都显示该图像有 5 个图层。

> **注意：**`docker history`命令显示图像的构建历史，**不是**图像中图层的严格列表。例如，用于构建图像的一些 Dockerfile 指令不会创建图层。这些指令包括：“ENV”、“EXPOSE”、“CMD”和“ENTRYPOINT”。这些指令不会创建新的图层，而是向图像添加元数据。

所有的 Docker 图像都以一个基本图层开始，随着更改和新内容的添加，新的图层会被添加到顶部。

作为一个过度简化的例子，你可能会创建一个基于 Ubuntu Linux 16.04 的新图像。这将是你的图像的第一层。如果你稍后添加 Python 包，这将作为第二层添加到基本图层之上。如果你随后添加了一个安全补丁，这将作为第三层添加到顶部。你的图像现在有三个图层，如图 6.5 所示（请记住，这只是一个为了演示目的而过度简化的例子）。

![图 6.5](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-5.png)

图 6.5

重要的是要理解，随着添加额外的图层，*图像*始终是所有图层的组合。以图 6.6 中显示的两个图层为例。每个*图层*有 3 个文件，但整体*图像*有 6 个文件，因为它是两个图层的组合。

![图 6.6](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-6.png)

图 6.6

> **注意：**我们在图 6.6 中以略有不同的方式显示了图像图层，这只是为了更容易地显示文件。

在图 6.7 中更复杂的三层图像的例子中，统一视图中的整体图像只呈现了 6 个文件。这是因为顶层的文件 7 是直接下方文件 5 的更新版本（内联）。在这种情况下，更高层的文件遮盖了直接下方的文件。这允许将文件的更新版本作为图像的新图层添加。

![图 6.7](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-7.png)

图 6.7

Docker 使用存储驱动程序（较新版本中的快照程序）负责堆叠图层并将它们呈现为单一的统一文件系统。Linux 上的存储驱动程序示例包括`AUFS`、`overlay2`、`devicemapper`、`btrfs`和`zfs`。正如它们的名称所暗示的那样，每个驱动程序都基于 Linux 文件系统或块设备技术，并且每个驱动程序都具有其独特的性能特征。Windows 上 Docker 支持的唯一驱动程序是`windowsfilter`，它在 NTFS 之上实现了分层和写时复制（CoW）。

图 6.8 显示了与系统中将显示的相同的 3 层图像。即所有三个图层堆叠和合并，形成单一的统一视图。

![图 6.8](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-8.png)

图 6.8

#### 共享图像层

多个图像可以共享图层，这导致了空间和性能的效率。

让我们再次看看我们之前使用`docker image pull`命令和`-a`标志来拉取`nigelpoulton/tu-demo`存储库中的所有标记图像。

```
$ docker image pull -a nigelpoulton/tu-demo

latest: Pulling from nigelpoulton/tu-demo
237d5fcd25cf: Pull `complete`
a3ed95caeb02: Pull `complete`
<Snip>
Digest: sha256:42e34e546cee61adb100...a0c5b53f324a9e1c1aae451e9

v1: Pulling from nigelpoulton/tu-demo
237d5fcd25cf: Already exists
a3ed95caeb02: Already exists
<Snip>
Digest: sha256:9ccc0c67e5c5eaae4beb...24c1d5c80f2c9623cbcc9b59a

v2: Pulling from nigelpoulton/tu-demo
237d5fcd25cf: Already exists
a3ed95caeb02: Already exists
<Snip>
eab5aaac65de: Pull `complete`
Digest: sha256:d3c0d8c9d5719d31b79c...fef58a7e038cf0ef2ba5eb74c
Status: Downloaded newer image `for` nigelpoulton/tu-demo

$ docker image ls
REPOSITORY             TAG      IMAGE ID       CREATED        SIZE
nigelpoulton/tu-demo   v2       6ac...ead   `4` months ago   `211`.6 MB
nigelpoulton/tu-demo   latest   9b9...e29   `4` months ago   `211`.6 MB
nigelpoulton/tu-demo   v1       9b9...e29   `4` months ago   `211`.6 MB 
```

注意以`已存在`结尾的行。

这些行告诉我们，Docker 足够聪明，能够识别当被要求拉取已经存在副本的图像层时。在这个例子中，Docker 首先拉取了标记为`latest`的图像。然后，当它拉取`v1`和`v2`图像时，它注意到它已经有了组成这些图像的一些图层。这是因为该存储库中的三个图像几乎是相同的，因此共享许多图层。

如前所述，Linux 上的 Docker 支持许多存储驱动程序（快照程序）。每个都可以自由地以自己的方式实现图像分层、图层共享和写时复制（CoW）行为。然而，总体结果和用户体验基本相同。尽管 Windows 只支持单个存储驱动程序，但该驱动程序提供与 Linux 相同的体验。

#### 通过摘要拉取图像

到目前为止，我们已经向您展示了如何按标记拉取图像，这绝对是最常见的方式。但是它有一个问题——标记是可变的！这意味着有可能意外地使用错误的标记标记图像。有时甚至可能使用与现有但不同的图像相同的标记标记图像。这可能会引起问题！

举个例子，假设你有一个名为`golftrack:1.5`的图像，并且它有一个已知的错误。您拉取图像，应用修复，并使用**相同的标记**将更新后的图像推送回其存储库。

花点时间理解刚刚发生的事情...您有一个名为`golftrack:1.5`的镜像存在漏洞。该镜像正在您的生产环境中使用。您创建了一个包含修复的新版本的镜像。然后出现了错误...您构建并将修复后的镜像推送回其存储库，**与易受攻击的镜像使用相同的标签！**这将覆盖原始镜像，并且无法很好地知道哪些生产容器是从易受攻击的镜像运行的，哪些是从修复的镜像运行的？两个镜像都具有相同的标签！

这就是*镜像摘要*发挥作用的地方。

Docker 1.10 引入了一种新的内容可寻址存储模型。作为这种新模型的一部分，现在所有镜像都会获得一个加密的内容哈希。在本讨论中，我们将把这个哈希称为*摘要*。因为摘要是镜像内容的哈希，所以不可能更改镜像的内容而不更改摘要。这意味着摘要是不可变的。这有助于避免我们刚刚谈到的问题。

每次拉取镜像时，`docker image pull`命令将包括镜像的摘要作为返回代码的一部分。您还可以通过在`docker image ls`命令中添加`--digests`标志来查看 Docker 主机本地存储库中镜像的摘要。这两者都在以下示例中显示。

```
$ docker image pull alpine
Using default tag: latest
latest: Pulling from library/alpine
e110a4a17941: Pull `complete`
Digest: sha256:3dcdb92d7432d56604d...6d99b889d0626de158f73a
Status: Downloaded newer image `for` alpine:latest

$ docker image ls --digests alpine
REPOSITORY  TAG     DIGEST              IMAGE ID      CREATED       SIZE
alpine      latest  sha256:3dcd...f73a  4e38e38c8ce0  `10` weeks ago  `4`.8 MB 
```

`上面的输出显示了`alpine`镜像的摘要为 -

`sha256:3dcdb92d7432d56604d...6d99b889d0626de158f73a`

现在我们知道镜像的摘要，我们可以在再次拉取镜像时使用它。这将确保我们得到**完全符合我们期望的镜像！**

在撰写本文时，没有原生的 Docker 命令可以从 Docker Hub 等远程注册表中检索镜像的摘要。这意味着确定镜像的摘要的唯一方法是按标签拉取它，然后记下其摘要。这无疑将在未来发生变化。

以下示例从 Docker 主机中删除`alpine:latest`镜像，然后演示如何使用其摘要而不是标签再次拉取它。

```
$ docker image rm alpine:latest
Untagged: alpine:latest
Untagged: alpine@sha256:c0537...7c0a7726c88e2bb7584dc96
Deleted: sha256:02674b9cb179d...abff0c2bf5ceca5bad72cd9
Deleted: sha256:e154057080f40...3823bab1be5b86926c6f860

$ docker image pull alpine@sha256:c0537...7c0a7726c88e2bb7584dc96
sha256:c0537...7726c88e2bb7584dc96: Pulling from library/alpine
cfc728c1c558: Pull `complete`
Digest: sha256:c0537ff6a5218...7c0a7726c88e2bb7584dc96
Status: Downloaded newer image `for` alpine@sha256:c0537...bb7584dc96 
```

#### 关于镜像哈希（摘要）的更多信息

自 Docker 版本 1.10 以来，镜像是一个非常松散的独立层集合。

*镜像*本身实际上只是一个列出层和一些元数据的配置对象。

*层*是数据所在的地方（文件等）。每个层都是完全独立的，没有成为集体镜像的概念。

每个图像由一个加密 ID 标识，这是配置对象的哈希值。每个图层由一个加密 ID 标识，这是其包含内容的哈希值。

这意味着更改图像的内容或任何图层都将导致相关的加密哈希值发生变化。因此，图像和图层是不可变的，我们可以轻松地识别对它们所做的任何更改。

我们称这些哈希值为**内容哈希值**。

到目前为止，事情还相当简单。但它们即将变得更加复杂。

当我们推送和拉取图像时，我们会压缩它们的图层以节省带宽，以及注册表的 blob 存储空间。

很酷，但压缩图层会改变其内容！这意味着在推送或拉取操作后，其内容哈希将不再匹配！这显然是一个问题。

例如，当你将图像图层推送到 Docker Hub 时，Docker Hub 将尝试验证图像是否在传输过程中未被篡改。为了做到这一点，它会对图层运行一个哈希，并检查是否与发送的哈希匹配。因为图层被压缩（改变）了，哈希验证将失败。

为了解决这个问题，每个图层还会得到一个叫做*分发哈希*的东西。这是对图层压缩版本的哈希。当图层从注册表中推送和拉取时，它的分发哈希被包括在内，这就是用来验证图层是否在传输过程中被篡改的方法。

这种内容寻址存储模型通过在推送和拉取操作后提供一种验证图像和图层数据的方式，大大提高了安全性。它还避免了如果图像和图层 ID 是随机生成的可能发生的 ID 冲突。

#### 多架构图像

关于 Docker 最好的一点是它的简单易用。例如，运行一个应用程序就像拉取图像并运行一个容器一样简单。不需要担心设置、依赖项或配置。它就能运行。

然而，随着 Docker 的发展，事情开始变得复杂 - 尤其是当新的平台和架构，如 Windows、ARM 和 s390x 被添加进来时。突然间，我们不得不考虑我们正在拉取的图像是否是为我们正在运行的架构构建的。这破坏了流畅的体验。

多架构图像来拯救！

Docker（镜像和注册表规范）现在支持多架构镜像。这意味着单个镜像（`repository:tag`）*可以*在 x64 架构的 Linux 上，PowerPC 架构的 Linux 上，Windows x64 上，ARM 等上都有镜像。让我明确一点，我们说的是一个单一镜像标签支持多个平台和架构。我们马上就会看到它的实际应用。

为了实现这一点，注册表 API 支持两个重要的构造：

+   清单列表（新）

+   **清单**

“清单列表”就是它听起来的样子：一个特定镜像标签支持的架构列表。然后，每个支持的架构都有自己的**清单**，详细说明了它由哪些层组成。

图 6.9 以官方的`golang`镜像为例。左边是**清单列表**，列出了镜像支持的每种架构。箭头显示，**清单列表**中的每个条目指向一个包含镜像配置和层数据的**清单**。

![图 6.9](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure6-9.png)

图 6.9

让我们在实际操作之前先看看理论。

假设你正在树莓派上运行 Docker（在 ARM 架构上运行的 Linux）。当你拉取一个镜像时，你的 Docker 客户端会对运行在 Docker Hub 上的 Docker Registry API 进行相关调用。如果镜像存在**清单列表**，则会解析它以查看是否存在 ARM 架构的 Linux 的条目。如果存在 ARM 条目，则会检索该镜像的**清单**并解析出构成镜像的层的加密 ID。然后，每个层都会从 Docker Hub 的 blob 存储中拉取。

以下示例展示了拉取官方的`golang`镜像（支持多种架构）并运行一个简单命令来显示 Go 的版本以及主机的 CPU 架构。需要注意的是，这两个示例使用了完全相同的`docker container run`命令。我们不需要告诉 Docker 我们需要 Linux x64 或 Windows x64 版本的镜像。我们只需运行普通命令，让 Docker 负责获取适合我们正在运行的平台和架构的正确镜像！

Linux x64 示例：

```
$ docker container run --rm golang go version

Unable to find image `'golang:latest'` locally
latest: Pulling from library/golang
723254a2c089: Pull `complete`
<Snip>
39cd5f38ffb8: Pull `complete`
Digest: sha256:947826b5b6bc4...
Status: Downloaded newer image `for` golang:latest
go version go1.9.2 linux/amd64 
```

`Windows x64 示例：

```
PS> docker container run --rm golang go version

Using default tag: latest
latest: Pulling from library/golang
3889bb8d808b: Pull complete
8df8e568af76: Pull complete
9604659e3e8d: Pull complete
9f4a4a55f0a7: Pull complete
6d6da81fc3fd: Pull complete
72f53bd57f2f: Pull complete
6464e79d41fe: Pull complete
dca61726a3b4: Pull complete
9150276e2b90: Pull complete
cd47365a14fb: Pull complete
1783777af4bb: Pull complete
3b8d1834f1d7: Pull complete
7258d77b22dd: Pull complete
Digest: sha256:e2be086d86eeb789...e1b2195d6f40edc4
Status: Downloaded newer image for golang:latest
go version go1.9.2 windows/amd64 
```

`前面的操作从 Docker Hub 拉取`golang`图像，从中启动一个容器，执行`go version`命令，并输出主机系统的 Go 和 OS/CPU 架构的版本。每个示例的最后一行显示了每个`go version`命令的输出。请注意，这两个示例使用完全相同的命令，但 Linux 示例拉取了`linux/amd64`图像，而 Windows 示例拉取了`windows/amd64`图像。

在撰写本文时，所有*官方图像*都有清单列表。但是，支持所有架构是一个持续的过程。

创建在多个架构上运行的图像需要图像发布者额外的工作。此外，一些软件不是跨平台的。考虑到这一点，**清单列表**是可选的 - 如果图像不存在清单列表，注册表将返回正常的**清单**。

#### 删除图像

当您不再需要图像时，可以使用`docker image rm`命令从 Docker 主机中删除它。`rm`是删除的缩写。

删除图像将从 Docker 主机中删除图像及其所有层。这意味着它将不再显示在`docker image ls`命令中，并且包含层数据的 Docker 主机上的所有目录都将被删除。但是，如果一个图像层被多个图像共享，直到引用它的所有图像都被删除之前，该层将不会被删除。

使用`docker image rm`命令删除在上一步中拉取的图像。以下示例通过其 ID 删除图像，这可能与您的系统不同。

```
$ docker image rm 02674b9cb179
Untagged: alpine@sha256:c0537ff6a5218...c0a7726c88e2bb7584dc96
Deleted: sha256:02674b9cb179d57...31ba0abff0c2bf5ceca5bad72cd9
Deleted: sha256:e154057080f4063...2a0d13823bab1be5b86926c6f860 
```

`如果您要删除的图像正在运行的容器中使用，则无法删除它。在尝试再次删除操作之前，请停止并删除任何容器。

在 Docker 主机上**删除所有图像**的一个方便的快捷方式是运行`docker image rm`命令，并通过调用带有`-q`标志的`docker image ls`传递系统上所有图像 ID 的列表。如下所示。

如果您在 Windows 系统上执行以下命令，它只能在 PowerShell 终端中工作。它在 CMD 提示符上不起作用。

```
$ docker image rm `$(`docker image ls -q`)` -f 
```

`要了解这是如何工作的，请下载一些图像，然后运行`docker image ls -q`。

```
$ docker image pull alpine
Using default tag: latest
latest: Pulling from library/alpine
e110a4a17941: Pull `complete`
Digest: sha256:3dcdb92d7432d5...3626d99b889d0626de158f73a
Status: Downloaded newer image `for` alpine:latest

$ docker image pull ubuntu
Using default tag: latest
latest: Pulling from library/ubuntu
952132ac251a: Pull `complete`
82659f8f1b76: Pull `complete`
c19118ca682d: Pull `complete`
8296858250fe: Pull `complete`
24e0251a0e2c: Pull `complete`
Digest: sha256:f4691c96e6bba...128ae95a60369c506dd6e6f6ab
Status: Downloaded newer image `for` ubuntu:latest

$ docker image ls -q
bd3d4369aebc
4e38e38c8ce0 
```

`看看`docker image ls -q`如何返回一个只包含系统上本地拉取的所有图像的图像 ID 的列表。将此列表传递给`docker image rm`将删除系统上的所有图像，如下所示。

```
$ docker image rm `$(`docker image ls -q`)` -f
Untagged: ubuntu:latest
Untagged: ubuntu@sha256:f4691c9...2128ae95a60369c506dd6e6f6ab
Deleted: sha256:bd3d4369aebc494...fa2645f5699037d7d8c6b415a10
Deleted: sha256:cd10a3b73e247dd...c3a71fcf5b6c2bb28d4f2e5360b
Deleted: sha256:4d4de39110cd250...28bfe816393d0f2e0dae82c363a
Deleted: sha256:6a89826eba8d895...cb0d7dba1ef62409f037c6e608b
Deleted: sha256:33efada9158c32d...195aa12859239d35e7fe9566056
Deleted: sha256:c8a75145fcc4e1a...4129005e461a43875a094b93412
Untagged: alpine:latest
Untagged: alpine@sha256:3dcdb92...313626d99b889d0626de158f73a
Deleted: sha256:4e38e38c8ce0b8d...6225e13b0bfe8cfa2321aec4bba
Deleted: sha256:4fe15f8d0ae69e1...eeeeebb265cd2e328e15c6a869f

$ docker image ls
REPOSITORY     TAG    IMAGE ID    CREATED     SIZE 
```

`让我们提醒自己我们用来处理 Docker 图像的主要命令。`

### 镜像 - 命令

+   `docker image pull` 是下载镜像的命令。我们从远程仓库中的存储库中拉取镜像。默认情况下，镜像将从 Docker Hub 上的存储库中拉取。这个命令将从 Docker Hub 上的 `alpine` 存储库中拉取标记为 `latest` 的镜像 `docker image pull alpine:latest`。

+   `docker image ls` 列出了存储在 Docker 主机本地缓存中的所有镜像。要查看镜像的 SHA256 摘要，请添加 `--digests` 标志。

+   `docker image inspect` 是一件美妙的事情！它为你提供了镜像的所有细节 — 层数据和元数据。

+   `docker image rm` 是删除镜像的命令。这个命令展示了如何删除 `alpine:latest` 镜像 — `docker image rm alpine:latest`。你不能删除与正在运行（Up）或停止（Exited）状态的容器相关联的镜像。

### 章节总结

在本章中，我们学习了关于 Docker 镜像。我们了解到它们就像虚拟机模板，用于启动容器。在底层，它们由一个或多个只读层组成，当堆叠在一起时，构成了整个镜像。

我们使用了 `docker image pull` 命令将一些镜像拉取到我们的 Docker 主机本地注册表中。

我们涵盖了镜像命名、官方和非官方仓库、分层、共享和加密 ID。

我们看了一下 Docker 如何支持多架构和多平台镜像，最后看了一些用于处理镜像的最常用命令。

在下一章中，我们将对容器进行类似的介绍 — 镜像的运行时表亲。
