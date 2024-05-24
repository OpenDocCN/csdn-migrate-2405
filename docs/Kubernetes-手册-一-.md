# Kubernetes 手册（一）

> 原文：[`zh.annas-archive.org/md5/5052204F13641918EE166946F5C50D62`](https://zh.annas-archive.org/md5/5052204F13641918EE166946F5C50D62)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第一章：关于这本书

这是一本关于 Kubernetes 的**最新**书籍。它相对较短，而且直截了当。这本书的理念是您可以在几天内读完它！不需要任何先前的知识。

让我明确一点，因为我不想误导人... **这不是深入研究！**它涵盖了 Kubernetes 最重要的方面。我认为这是市场上最好的快速掌握的书籍！

### 平装书

平装版本在部分亚马逊市场上有售。我无法控制亚马逊在哪些市场上提供平装版 - 如果由我选择，我会让它在所有地方都有售。

我选择了一本**高质量的全彩版**，我认为您会喜欢。这意味着没有廉价的纸张，也没有来自上世纪 90 年代的黑白图表:-D

### 电子书和 Kindle 版本

获取电子副本的最简单的地方是 leanpub.com。这是一个流畅的平台，所有更新都是免费的。

您也可以在亚马逊上获得 Kindle 版本，还可以获得免费更新。然而，Kindle 在同步更新方面声名狼藉。如果您在将更新同步到您的 Kindle 上遇到问题，请联系 Kindle 支持，他们将解决问题。

### 反馈

我会很高兴如果您能在亚马逊上给这本书写一篇评论。写技术书是孤独的工作。我实际上花了几个月的时间让这本书尽可能地好，所以花几分钟时间写一篇评论对我来说是很好的。不过，没有压力，如果您不写，我也不会因此失眠。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00000.jpg)

### 为什么有人要读这本书或关心 Kubernetes？

Kubernetes 非常热门，Kubernetes 技能需求量很高。所以，如果您想在职业生涯上取得进展，并且想要使用塑造未来的技术，您需要阅读这本书。如果您不关心自己的职业生涯，并且愿意被抛在后面，那就不要读它。这就是事实。

### 如果我已经观看了您的视频培训课程，我应该买这本书吗？

Kubernetes 是 Kubernetes。所以我的书和视频课程之间显然有一些相似的内容。但阅读书籍和观看视频是完全不同的体验。在我看来，视频更有趣，但书籍更容易做笔记，当你试图找到某些东西时可以翻阅。

如果我是您，我会观看视频*并*购买这本书。它们互补，通过多种方法学习是一种被证明的策略。但您还能期待我说什么呢:-D

最后的话：我觉得我的书籍和视频课程已经得到了足够多的好评，可以让您放心它们将是很好的投资。

> **注意：**我的视频培训课程可在 pluralsight.com 和 acloud.guru 上找到。

### 书籍的版本

Kubernetes 正在快速发展！因此，这样一本书的价值与其年龄成反比！换句话说，这本书越老，价值就越低。考虑到这一点，**我承诺每年至少更新一次**。当我说“更新”时，我的意思是真正的更新 - 每个词和概念都经过审查，每个示例都经过测试和更新。**我对这本书百分之百的承诺！**

如果每年至少更新一次似乎很多...**欢迎来到新常态！**

我们不再生活在一个两年前的技术书籍有价值的世界。事实上，我对一个关于 Kubernetes 这样快速发展的主题的一年前的书籍的价值表示怀疑！作为作者，我希望这不是真的，但事实却是如此！再次...欢迎来到新常态！

### 书籍的免费更新

我已尽一切努力确保您对这本书的投资尽可能安全！

所有 Kindle 和 Leanpub 的客户都可以免费获得所有更新！Leanpub 上的更新效果很好，但在 Kindle 上情况就不一样了。许多读者抱怨他们的 Kindle 设备无法获得更新。这是一个常见问题，可以通过联系 Kindle 支持轻松解决。

如果您从**Amazon.com**购买平装书，您可以以$2.99 的折扣价获得 Kindle 版本。这是通过*Kindle Matchbook*计划完成的。不幸的是，Kindle Matchbook 只在美国提供，并且存在错误 - 有时 Kindle Matchbook 图标不会出现在书的亚马逊销售页面上。如果您遇到此类问题，联系 Kindle 支持，他们会帮助您解决问题。

这是我能做的最好的了！

如果您通过其他渠道购买这本书，情况会有所不同，因为我无法控制它们。嘿...我是一个技术人员，不是一个书籍分销商:-D

### 书籍的版本

+   **版本 3** 2018 年 11 月。将所有内容和概念与 Kubernetes 的最新版本以及云原生领域的最新动态保持一致。重新排列了一些章节以获得更好的流畅性。删除了*ReplicaSets*章节，并将该内容转移到改进的*Deployments*章节。添加了新章节，概述了其他未在专门章节中涵盖的重要概念。

+   **版本 2.2** 2018 年 1 月。修正了一些拼写错误，增加了一些解释，并添加了一些新的图表。

+   **版本 2.1** 2017 年 12 月。修正了一些拼写错误，并更新了图 6.11 和 6.12 以包括缺失的标签。

+   **版本 2.** 2017 年 10 月。更新了 Kubernetes 1.8.0 的内容。增加了关于 ReplicaSets 的新章节。对 Pods 章节进行了重大修改。修正了拼写错误，并对现有章节进行了一些其他小的更新。

+   **版本 1.** 初始版本。


# 第二章：Kubernetes 入门

本章分为两个主要部分。

+   Kubernetes 背景-它来自何处等等。

+   将 Kubernetes 视为数据中心操作系统的想法

### Kubernetes 背景

Kubernetes 是一个编排器。在大多数情况下，它编排容器化的应用程序。但是，有一些项目使其能够编排虚拟机和函数（无服务器工作负载）。所有这些都使 Kubernetes 成为*云原生应用程序*的事实上的编排器。

那么，什么是*编排器*，什么是*云原生应用程序*？

*编排器*是一个部署和管理应用程序的后端系统。这意味着它可以帮助您部署应用程序，扩展和缩小它，执行更新和回滚等操作。如果它是一个好的编排器，它可以在您不需要监督的情况下完成这些操作。

*云原生应用程序*由一组小型独立服务组成，这些服务相互通信并形成一个有用的应用程序。正如其名称所示，这种设计使其能够应对类似云的需求并在云平台上本地运行。例如，云原生应用程序被设计和编写成可以轻松扩展和缩小以满足需求的变化。更新和回滚也很简单。它们还可以自我修复。

本书中将更多地涉及所有这些概念。

> **注意：**尽管名称如此，*云原生*应用程序也可以在本地运行。事实上，云原生应用程序的一个特性可能是能够在任何地方运行-任何云，或任何本地数据中心。

### Kubernetes 源自何处

让我们从头开始吧... Kubernetes 源自 Google！2014 年夏天，它被开源并移交给了云原生计算基金会（CNCF）。

![图 1.1](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00001.jpg)

图 1.1

从那时起，它已成为全球最重要的云原生技术。

像许多现代云原生项目一样，它是用 Go（Golang）编写的。它在 Github 上的`kubernetes/kubernetes`上。它在 IRC 频道上活跃讨论，你可以在 Twitter 上关注它（@kubernetesio），还有一个很好的 slack 频道-slack.k8s.io。全球各地也定期举行聚会！

#### Kubernetes 和 Docker

Kubernetes 和 Docker 是互补的技术。例如，通常会使用 Docker 开发应用程序，然后使用 Kubernetes 进行编排。

在这个模型中，你可以用你喜欢的语言编写代码，然后使用 Docker 对其进行打包、测试和部署。但在测试或生产中运行的最后一步是由 Kubernetes 处理的。

在高层次上，你可能会有一个包含 10 个节点的 Kubernetes 集群来运行你的生产应用程序。然而，在幕后，每个节点都在运行 Docker 作为其容器运行时。这意味着 Docker 是启动和停止容器等低级技术，而 Kubernetes 是处理更大范围事务的高级技术，比如决定在哪些节点上运行应用程序的某些部分，何时扩展或缩减，以及执行更新。

图 1.2 显示了一个简单的 Kubernetes 集群，其中的节点使用 Docker 作为容器运行时。

![图 1.2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00002.jpg)

图 1.2

正如图 1.2 所示，Docker 并不是 Kubernetes 支持的唯一容器运行时。事实上，Kubernetes 有一些抽象运行时的特性：

1.  容器运行时接口（CRI）是一个抽象层，标准化第三方容器运行时与 Kubernetes 接口的方式。它允许容器运行时代码存在于 Kubernetes 之外，但以受支持和标准化的方式与其接口。

1.  *运行时类*是 Kubernetes 1.12（alpha）中的一个新功能，允许不同类别的运行时。例如，*gVisor*可能提供比 Docker 或 containerd 更好的隔离性。

在撰写本文时，`containerd`正在超越 Docker 成为 Kubernetes 中最常用的容器运行时。`containerd`实际上是 Docker 的精简版本，只包含 Kubernetes 所需的内容。

然而，这是低级的东西，不应该影响你作为 Kubernetes 用户的体验。无论你使用哪种容器运行时，常规的 Kubernetes 命令和模式将继续正常工作。

#### Kubernetes 与 Docker Swarm 有什么不同

在 2016 年和 2017 年，我们经历了*编排器之战*，Docker Swarm、Mesosphere DCOS 和 Kubernetes 争夺成为事实上的容器编排器。长话短说，Kubernetes 获胜了。

是的，Docker Swarm 和其他容器编排器仍然存在，但它们的发展和市场份额与 Kubernetes 相比微不足道。

#### Kubernetes 和 Borg：抵抗是徒劳的！

很有可能你会听到人们谈论 Kubernetes 与谷歌的*Borg*和*Omega*系统的关系。

谷歌多年来一直在容器上运行许多系统并不是什么秘密。传说中他们每周处理*数十亿个容器*的故事很常见。所以是的，很长一段时间以来 - 甚至在 Docker 出现之前 - 谷歌一直在容器上运行*搜索*、*Gmail*和*GFS*等东西 - **大量**的容器！

控制这数十亿个容器并保持其正常运行的是一些内部技术和框架，称为*Borg*和*Omega*。因此，把它们与 Kubernetes 联系起来并不是什么大问题 - 它们都在进行规模化容器编排的游戏，并且它们都与谷歌有关。

这有时让人们误以为 Kubernetes 是 Borg 或 Omega 的开源版本。但事实并非如此！它更像是与它们共享 DNA 和家族史。就像这样...一开始是 Borg...然后 Borg 产生了 Omega。Omega *认识*了开源社区，然后产生了她的 Kubernetes ;-)

![图 1.3 - 共享的 DNA](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00003.jpg)

图 1.3 - 共享的 DNA

关键是，这三者是分开的，但又是相关的。事实上，许多参与建立 Borg 和 Omega 的人也参与了建立 Kubernetes。

因此，尽管 Kubernetes 是从头开始构建的，但它利用了在谷歌与 Borg 和 Omega 学到的许多东西。

目前，Kubernetes 是 CNCF 下的一个开源项目，根据 Apache 2.0 许可证授权，并且 1.0 版本早在 2015 年 7 月就发布了。

#### Kubernetes - 名字的含义

**Kubernetes**这个名字来自希腊词，意思是*舵手* - 驾驶船只的人。这个主题反映在标志中。

![图 1.4 - Kubernetes 标志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00004.jpg)

图 1.4 - Kubernetes 标志

> **传闻：** Kubernetes 最初的名字是要叫*九号七*。如果你了解《星际迷航》，你会知道*九号七*是一位由凯瑟琳·詹妮薇船长指挥的 USS 航行者号救出的女性**Borg**。标志上的**7**个轮辐也是对*九号七*的一个参考。

在继续之前，关于名字的最后一件事...你经常会看到 Kubernetes 被缩写为**K8s**。这个想法是数字 8 替代了 K 和 S 之间的 8 个字符 - 对于推特和像我这样的懒惰打字者来说非常方便 ;-)

### 数据中心操作系统

一般来说，容器让我们以前的可扩展性挑战看起来很容易 - 我们刚刚说过谷歌每周处理数十亿个容器！

好吧……但并非每个人都像谷歌那样大。那么我们其他人呢？

一般来说，如果你的传统应用程序有数百个虚拟机(VM)，那么你的容器化云原生应用程序很可能会有数千个容器！考虑到这一点，我们迫切需要一种管理它们的方法。

对 Kubernetes 打个招呼！

当你开始理解像 Kubernetes 这样的东西时，重要的是要理解现代数据中心架构。例如，我们正在放弃将数据中心视为计算机集合的传统观点。相反，我们将其视为*一个大型计算机*。

但这意味着什么？

典型的计算机是由 CPU、RAM、存储和网络组成的。但是我们已经很好地构建了抽象掉许多细节的操作系统(OS)。例如，开发人员很少关心他们的应用程序使用哪个 CPU 核心或确切的内存地址 - 我们让操作系统决定所有这些。这是件好事，应用程序开发的世界因此变得更加友好。

因此，将这一点提升到下一个级别，并将这些相同的抽象应用于数据中心资源 - 将数据中心视为计算、网络和存储的池，并具有一个总体系统来对其进行抽象化是很自然的。这意味着我们不再需要关心我们的容器运行在哪台服务器或 LUN 上 - 只需将其留给数据中心操作系统处理。

在某些方面，Kubernetes 是一个数据中心操作系统。其他操作系统也存在，但它们都处于*牲畜业*中。忘掉给你的服务器命名，在电子表格中映射逻辑单元(LUN)，或者以其他方式像*宠物*一样对待它们。像 Kubernetes 这样的系统并不在乎。那种把你的应用程序拿出来然后说*“在这个节点上运行应用程序的这一部分，使用这个 IP，在这个特定的 LIUN 上……“*的日子已经过去了。在云原生的 Kubernetes 世界中，我们更多地是说*“嘿，Kubernetes，我有这个应用程序，它由这些部分组成……请帮我运行它”*。然后 Kubernetes 会去做所有艰难的调度和编排工作。

> **注意：**在使用术语*宠物*和*牲畜*时，不是针对任何人或任何动物。

让我们来看一个快速的类比……

考虑一下通过快递服务发送货物的过程。您将货物打包在快递公司的标准包装中，贴上标签，然后交给快递员。快递员会处理其他所有事情 - 所有复杂的物流，包括货物搭乘的飞机和卡车，使用哪些司机等等。他们还提供让您跟踪包裹的服务。关键是，快递员唯一需要的是货物按照他们的要求打包和贴标签。

对于 Kubernetes 中的应用程序也是一样。将它们打包为容器，给它们一个声明性清单，然后让 Kubernetes 负责运行它们并保持运行。您还会获得丰富的工具和 API，让您了解发生了什么。这是一件美好的事情！

虽然这些听起来都很棒，但不要把这个“数据中心操作系统”的比喻太过分。这不是一个 DVD 安装，你不会得到一个 shell 提示符来控制整个数据中心。而且你绝对不会得到一个纸牌游戏！我们还处于早期阶段，但 Kubernetes 正在引领潮流，我相信你会喜欢它。

### 章节总结

Kubernetes 是云原生应用程序的领先编排器。我们给它一个应用程序，告诉它我们希望应用程序看起来像什么，然后让 Kubernetes 实现。

它来自谷歌，根据 Apache 2.0 许可开源，并且属于 Cloud Native Computing Foundation（CNCF）。

提示！

Kubernetes 是一个快速发展的项目，正在积极开发中，所以事情变化很快！但不要因此而却步 - 拥抱它！快速变化是新常态！

除了阅读本书，我建议您关注 Twitter 上的@kubernetesio，加入各种 k8s 的 slack 频道，并参加当地的聚会。这些都将帮助您了解 Kubernetes 世界中的最新和最伟大的事物。我还会定期更新这本书，并制作更多的视频培训课程！请关注 pluralsight.com 和 acloud.guru 获取我的最新课程！


# 第三章：Kubernetes 操作原则

在这一章中，我们将学习构建 Kubernetes 集群和部署应用程序所需的主要组件。游戏的目的是为您提供主要概念的概述。但是如果您不立刻理解一切，不要担心，随着我们在书中的进展，我们将再次涵盖大部分内容。

我们将按以下方式划分本章：

+   从 40K 英尺高度看 Kubernetes

+   主节点和节点

+   打包应用程序

+   声明性配置和期望状态

+   Pods

+   部署

+   服务

### 从 40K 英尺高度看 Kubernetes

在最高层次上，Kubernetes 是云原生微服务应用程序的编排器。这只是一个由许多小独立服务组成的应用程序的花哨名称，它们共同工作形成一个有用的应用程序。

让我们看一个快速的类比。

在现实世界中，一个足球（足球）队由个体组成。没有两个是相同的，每个人在团队中扮演不同的角色 - 有些防守，有些进攻，有些擅长传球，有些擅长射门... 教练来了，他或她给每个人一个位置，并将他们组织成一个有目的的团队。我们从图 2.1 到图 2.2。

![图 2.1](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00005.jpg)

图 2.1

![图 2.2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00006.jpg)

图 2.2

教练还确保团队保持队形，坚持计划，并处理任何伤病。好吧，猜猜… Kubernetes 世界中的微服务应用程序也是一样的！

跟着我…

我们从许多个体化的专业服务开始 - 有些提供网页，有些进行身份验证，有些进行搜索，其他一些持久化数据。Kubernetes 出现了 - 就像足球类比中的教练一样 - 将所有东西组织成一个有用的应用程序，并保持一切运行顺利。

在体育界，我们称之为*教练*。在应用程序世界中，我们称之为*编排*。

Kubernetes 是一个*编排器*。

为了实现这一点，我们从一个应用程序开始，打包它并将其交给集群（Kubernetes）。集群由一个或多个*主节点*和一堆*节点*组成。

主节点负责集群并做出所有调度决策。他们还监视集群，实施更改并响应事件。因此，我们经常将主节点称为*控制平面*。

节点是应用程序服务运行的地方，有时我们称它们为*数据平面*。它们向主节点汇报，并不断观察新的工作任务。

要在 Kubernetes 集群上运行应用程序，我们遵循这个简单的模式：

1.  用我们喜欢的语言将应用程序编写为小型独立服务。

1.  将每个服务打包在自己的容器中。

1.  将每个容器包装在自己的 Pod 中。

1.  通过更高级别的对象（例如；*Deployments, DaemonSets, StafeulSets, CronJobs 等）将 Pod 部署到集群中。

我们仍然处在书的开头阶段，不要指望你已经知道所有这些术语的含义。但在高层次上，*Deployments* 提供了可伸缩性和滚动更新，*DaemonSets* 在集群中的每个节点上运行一个 Pod 实例，*StatefulSets* 用于应用程序的有状态组件，*CronJobs* 用于需要在设定时间运行的工作。还有更多选项，但现在这些就够了。

Kubernetes 喜欢以声明方式管理应用程序。这是一种模式，我们在一组 YAML 文件中描述我们希望应用程序的外观和感觉，将这些文件发送到 Kubernetes，然后坐下来，让 Kubernetes 完成所有工作。

但事情并不止于此。Kubernetes 不断监视我们应用程序的不同部分，以确保它运行的方式完全符合预期。如果有什么不对劲，Kubernetes 会尝试修复它。

这是一个大局观。让我们深入一点。

### 主节点和节点

Kubernetes 集群由主节点和节点组成。这些是可以是虚拟机、数据中心中的裸金属服务器，或者是私有或公共云中的实例的 Linux 主机。

#### 主节点（控制平面）

Kubernetes 主节点是构成集群控制平面的系统服务的集合。

最简单的设置在单个主机上运行所有主服务。然而，多主高可用性对于生产环境变得越来越重要，并且对于生产环境来说是**必不可少**的。这就是为什么主要的云提供商在其 Kubernetes 作为服务平台中实现高可用性主节点，如 AKS、EKS 和 GKE。

还有一个被认为是一个好的实践**不要**在主节点上运行应用程序工作负载。这使得主节点可以完全集中于管理集群。

让我们快速看一下组成控制平面的 Kubernetes 主节点的主要部分。

##### API 服务器

API 服务器是进入 Kubernetes 的前门。它公开了一个 RESTful API，我们可以通过它向服务器发送 YAML 配置文件。这些 YAML 文件，有时我们称之为*清单*，包含了我们应用程序的期望状态。这包括诸如要使用哪个容器镜像、要暴露哪些端口以及有多少个 Pod 副本等内容。

对 API 服务器的所有请求都要经过身份验证和授权检查，但一旦完成这些步骤，YAML 文件中的配置将被验证，持久化到集群存储中，并部署到集群中。

您可以将 API 服务器视为集群的大脑 - 智能实现的地方。

##### 集群存储

如果 API 服务器是集群的大脑，那么*集群存储*就是它的记忆。它是控制平面中唯一有状态的部分，并且持久地存储了整个集群的配置和状态。因此，它是集群的重要组成部分 - 没有集群存储，就没有集群！

集群存储基于**etcd**，这是一个流行的分布式数据库。由于它是集群的*唯一真相来源*，您应该小心保护它，并提供足够的恢复方式以应对出现问题时的情况。

##### 控制器管理器

控制器管理器是*控制器的控制器*，有点像一个单体。虽然它作为一个单一的进程运行，但它实现了几个控制循环，监视集群并响应事件。其中一些控制循环包括：节点控制器、端点控制器和命名空间控制器。每个控制器通常作为一个后台监视循环运行，不断地监视 API 服务器的变化 - 游戏的目标是确保集群的*当前状态*与*期望状态*匹配（稍后会详细介绍）。

> **注意：**在整本书中，我们将使用*控制循环*、*监视循环*和*协调循环*等术语来表示相同的意思。

##### 调度器

在高层次上，调度器会监视新的工作并将其分配给节点。在幕后，它评估亲和性和反亲和性规则、约束和资源管理。

##### 云控制器管理器

如果您在受支持的公共云平台（如 AWS、Azure 或 GCP）上运行集群，则您的控制平面将运行一个*云控制器管理器*。它的工作是管理与底层云平台的集成，如节点、负载均衡器和存储。

##### 控制平面摘要

Kubernetes 的主节点运行着整个集群的控制平面服务。可以把它看作是集群的大脑 - 所有控制和调度决策都是在这里做出的。在幕后，主节点由许多小型专门的服务组成。这些包括 API 服务器、集群存储、控制器管理器和调度器。

API 服务器是控制平面的前端，也是我们直接交互的控制平面中唯一的组件。默认情况下，它在端口 443 上公开一个 RESTful 端点。

图 2.3 显示了 Kubernetes 主节点（控制平面）的高层视图。

![图 2.3 - Kubernetes 主节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00007.jpg)

图 2.3 - Kubernetes 主节点

#### 节点

*节点*是 Kubernetes 集群的工作者。在高层次上，它们有三个功能：

1.  监视 API 服务器以获取新的工作任务

1.  执行新的工作任务

1.  向控制平面报告

从图 2.4 可以看出，它们比*主节点*简单一些。让我们来看一下节点的三个主要组件。

![图 2.4 - Kubernetes 节点（以前称为 Minion）](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00008.jpg)

图 2.4 - Kubernetes 节点（以前称为 Minion）

##### Kubelet

Kubelet 是在集群中所有节点上运行的主要 Kubernetes 代理。事实上，通常可以互换使用术语*节点*和*kubelet*。您在 Linux 主机上安装 kubelet，它会将主机注册为*节点*加入集群。然后它会监视 API 服务器以获取新的工作任务。每当它看到一个任务，它就会执行该任务并保持与主节点的报告通道。

如果 kubelet 无法运行特定的工作任务，它会向主节点报告，并让控制平面决定采取什么行动。例如，如果一个 Pod 在一个节点上失败，kubelet **不**负责找到另一个节点来运行它。它只是向控制平面报告，由控制平面决定如何处理。

##### 容器运行时

Kubelet 需要一个容器运行时来执行与容器相关的任务 - 诸如拉取镜像、启动和停止容器等。

在早期，Kubernetes 原生支持一些容器运行时，比如 Docker。最近，它已经转移到了一个名为容器运行时接口（CRI）的插件模型。这是一个用于外部（第三方）容器运行时插入的抽象层。基本上，CRI 掩盖了 Kubernetes 的内部机制，并为第三方容器运行时提供了一个清晰的文档化接口。

CRI 是将运行时集成到 Kubernetes 中的支持方法。

Kubernetes 有很多可用的容器运行时。`cri-containerd`是一个基于社区的开源项目，将 CNCF 的`containerd`运行时移植到 CRI 接口。它得到了很多支持，并且正在取代 Docker 成为 Kubernetes 中最流行的容器运行时。

> **注意：**`containerd`（发音为“container-dee”）是从 Docker Engine 中剥离出来的容器监督者和运行时逻辑。它由 Docker，Inc.捐赠给了 CNCF，并得到了很多社区支持。还有其他符合 CRI 标准的容器运行时存在。

##### Kube-proxy

*node*谜题的最后一部分是 kube-proxy。它在集群中的每个节点上运行，并负责本地网络。例如，它确保每个节点都有自己独特的 IP 地址，并实现本地的 IPTABLES 或 IPVS 规则来处理某些流量类型的路由和负载均衡。

既然我们了解了主节点和节点的基本原理，让我们转换方向，看看如何将应用程序打包运行在 Kubernetes 上。

### 打包应用程序

为了让应用程序在 Kubernetes 集群上运行，它需要满足一些条件。这些条件包括：

1.  打包为一个容器

1.  包装在 Pod 中

1.  通过清单文件部署（Pod，Deployment. DaemonSet…）

步骤如下…我们用我们喜欢的语言编写代码。我们将其构建成一个容器镜像并存储在注册表中。此时，我们的代码就是*containerized*的。

接下来，我们定义一个 Kubernetes Pod 来容纳我们的容器化应用程序。在我们目前的高级别上，Pod 只是一个包装器，允许容器在 Kubernetes 集群上运行。一旦我们为我们的容器定义了一个 Pod，我们就可以在集群上部署它了。

Kubernetes 提供了几种对象来部署和管理 Pods。最常见的是*Deployment*，它提供了可伸缩性、自愈性和滚动更新。它们在 YAML 文件中定义，并指定诸如 - 部署哪个 Pod 以及部署多少个副本等内容。

图 2.5 显示了打包为*container*的应用程序代码，运行在*Pod*内，由*Deployment*管理。

![图 2.5 - Kubernetes 节点（以前是 Minion）](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00009.gif)

图 2.5 - Kubernetes 节点（以前是 Minion）

一旦在*Deployment* YAML 文件中定义了所有内容，我们就将其作为我们应用程序的*desired state*发布到集群中，让 Kubernetes 来实现它。

说到 desired state…

### 声明模型和 desired state

*声明模型*和*期望状态*的概念是 Kubernetes 核心的两个要素。如果把它们拿走，Kubernetes 就会崩溃！

在 Kubernetes 中，声明模型的工作方式如下：

1.  我们在清单文件中声明了应用程序（微服务）的期望状态

1.  我们将其 POST 到 Kubernetes API 服务器

1.  Kubernetes 将这些存储在集群存储中作为应用程序的*期望状态*

1.  Kubernetes 在集群上实现了期望状态

1.  Kubernetes 实现了监视循环，以确保应用程序的*当前状态*与*期望状态*不变

让我们更详细地看看每个步骤。

清单文件是用简单的 YAML 编写的，它们告诉 Kubernetes 我们希望应用程序看起来是什么样子。我们称之为*期望状态*。它包括诸如要使用哪个镜像，要有多少副本，要监听哪些网络端口以及如何执行更新等内容。

一旦我们创建了清单，我们就会使用`kubectl`命令行实用程序将其`POST`到 API 服务器。这样做的最常见方式是使用`kubectl`命令行实用程序。这将清单作为请求 POST 到控制平面，通常在端口 443 上。

一旦请求经过身份验证和授权，Kubernetes 会检查清单，确定要将其发送到哪个控制器（例如*部署控制器*），并将配置记录在集群存储中作为集群整体*期望状态*的一部分。完成这些工作后，工作会被安排在集群上。这包括拉取镜像、启动容器和构建网络的艰苦工作。

最后，Kubernetes 设置了后台协调循环，不断监视集群的状态。如果集群的*当前状态*与*期望状态*不符，Kubernetes 将执行必要的任务来协调解决问题。

![图 2.6](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00010.jpg)

图 2.6

重要的是要理解，我们所描述的是传统*命令模型*的相反。命令模型是指我们发出一长串特定于平台的命令来构建东西的模型。

声明模型不仅比长串的命令简单得多，而且还能实现自愈、扩展，并且适合版本控制和自我记录！它通过告诉集群*事物应该是什么样子*来实现这一点。如果它们停止看起来像这样，集群会注意到差异并做出所有艰苦的工作来协调情况（自我修复）。

但声明性的故事并不止于此-事情会出错，事情会改变。当这些事情发生时，集群的***当前状态***不再与***期望状态***匹配。一旦发生这种情况，Kubernetes 就会开始行动，并尝试将两者重新调和。

让我们看一个例子。

假设我们有一个应用程序，期望状态包括 10 个 web 前端 Pod 的副本。如果运行两个副本的节点失败，*当前状态*将减少到 8 个副本，但*期望状态*仍将是 10 个。协调循环将观察到这一点，并且 Kubernetes 将在集群中的其他节点上安排两个新副本。

如果我们有意地将期望的副本数量增加或减少，同样的事情也会发生。我们甚至可以更改我们想要使用的镜像。例如，如果应用程序当前使用图像的`v2.00`，并且我们更新期望状态以使用`v2.01`，Kubernetes 将注意到差异并经过更新所有副本的过程，以便它们使用*期望状态*中指定的新图像。

要清楚。我们不是写一长串命令来更新每个副本到新版本，而是简单地告诉 Kubernetes 我们想要新版本，Kubernetes 会为我们做艰苦的工作。

尽管这看起来很简单，但它非常强大！这也是 Kubernetes 运行的核心。我们给 Kubernetes 一个声明性清单，描述了我们希望应用程序的外观。这构成了应用程序期望状态的基础。Kubernetes 控制平面记录它，实施它，并运行后台协调循环，不断检查正在运行的内容是否符合我们要求的内容。当当前状态与期望状态匹配时，世界是一个快乐的地方。当不匹配时，Kubernetes 会忙起来并修复它。

### Pods

在 VMware 世界中，调度的原子单位是虚拟机（VM）。在 Docker 世界中，是容器。嗯...在 Kubernetes 世界中，是***Pod***。

![图 2.7 - 调度的原子单位](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00011.jpg)

图 2.7 - 调度的原子单位

#### Pods 和容器

Kubernetes 确实运行容器化的应用程序。但是你不能直接在 Kubernetes 集群上运行容器-容器必须**始终**运行在 Pod 内部！

最简单的模型是在一个 Pod 中运行一个单独的容器。然而，有一些高级用例在单个 Pod 内运行多个容器。这些*多容器 Pod*超出了我们在这里讨论的范围，但强大的例子包括：

+   服务网格。

+   由*helper*容器支持的 Web 容器，该容器拉取最新内容。

+   容器与紧密耦合的日志刮取器，将日志传送到其他地方的日志服务。

这只是三个简单的例子。图 2.8 显示了一个多容器 Pod。

![图 2.8](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00012.gif)

图 2.8

#### Pod 解剖

在最高级别，*Pod*是一个用于运行容器的环境。Pod 本身实际上并不运行任何东西，它只是一个用于托管容器的沙箱。保持高层次，您将一个主机操作系统的区域划分出来，构建一个网络堆栈，创建一堆内核命名空间，并在其中运行一个或多个容器 - 这就是一个 Pod。

如果您在一个 Pod 中运行多个容器，它们都共享**相同的环境** - 诸如 IPC 命名空间、共享内存、卷、网络堆栈等。例如，这意味着同一 Pod 中的所有容器将共享相同的 IP 地址（Pod 的 IP）。这在图 2.8 中显示。

![图 2.9](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00013.gif)

图 2.9

如果同一 Pod 中的两个容器需要相互通信（Pod 内的容器对容器），它们可以使用 Pod 的`localhost`接口，如图 2.10 所示。

![图 2.10](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00014.gif)

图 2.10

当您需要紧密耦合的容器，并且可能需要共享内存和存储等要求时，多容器 Pod 是理想的。但是，如果您**不需要**紧密耦合您的容器，您应该将它们放在自己的 Pod 中，并通过网络松散耦合它们 - 这样每个容器只执行单个任务，保持清洁。

#### Pod 作为原子单位

Pod 也是 Kubernetes 中调度的最小单位。如果需要扩展应用程序，可以添加或删除 Pod。您**不**通过向现有 Pod 添加更多容器来扩展！多容器 Pod 仅用于两个不同但互补的容器需要共享资源的情况。图 2.11 显示了如何使用多个 Pod 作为扩展单元来扩展应用程序的`nginx`前端。

![图 2.11 - 使用 Pod 进行扩展](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00015.jpg)

图 2.11 - 使用 Pod 进行扩展

Pod 的部署是一个原子操作。这意味着一个 Pod 要么完全部署，要么根本不部署。永远不会出现部分部署的 Pod 来处理请求的情况。整个 Pod 要么启动并投入使用，要么不启动，失败了。

一个 Pod 只能存在于一个节点上。多容器 Pod 也是如此。

#### Pod 生命周期

Pods 是有寿命的。它们被创建，生存，然后死亡。如果它们意外死亡，我们不会让它们复活！相反，Kubernetes 会在原地启动一个新的 Pod。但尽管新的 Pod 看起来、闻起来、感觉起来都像旧的，但它不是！它是一个全新的 Pod，有全新的 ID 和 IP 地址。

这对我们构建应用程序的方式有影响。不要构建它们与特定实例的 Pod 紧密耦合。相反，构建它们，以便当 Pod 失败时，一个全新的（带有新 ID 和 IP 地址）可以在集群的其他地方弹出并无缝地取代它。

### 部署

我们通常间接部署 Pod 作为更大的一部分。例如; *部署*，*守护进程集*和*有状态集*。

例如，部署是一个更高级别的 Kubernetes 对象，它包装了一组 Pod，并添加了诸如扩展、零停机更新和版本回滚等功能。

在幕后，它们实现了一个控制器和一个监视循环，始终监视集群，以确保当前状态与期望状态匹配。

自 Kubernetes 1.2 版本以来就存在部署，而在 1.9 版本中被提升为 GA（稳定）版本。你会经常看到它们。

### 服务

我们刚刚了解到 Pods 是有寿命的，可能会死亡。然而，如果它们通过部署或守护进程集部署，它们在失败时会被替换。但新的 Pod 会有完全不同的 IP！当我们进行扩展操作时，也会发生这种情况——扩展会添加具有新 IP 地址的新 Pod，而缩减会带走现有的 Pod。这些事件会导致大量的 IP 变动。

关键是**Pods 是不可靠的**。但这带来了一个挑战...假设我们有一个微服务应用程序，有一堆 Pod 执行视频渲染。如果应用程序的其他部分需要使用渲染服务，但不能依赖 Pod 在需要时存在，那该怎么办？

这就是*服务*发挥作用的地方。**服务为一组 Pod 提供可靠的网络。**

图 2.12 显示了上传微服务通过服务与渲染器微服务进行通信。服务提供可靠的名称和 IP，并在其后面的两个渲染器 Pods 之间进行请求的负载均衡。

![图 2.12](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00016.gif)

图 2.12

再深入一点。服务是 Kubernetes API 中的完整对象 - 就像 Pods 和部署一样。它们有一个前端，包括稳定的 DNS 名称、IP 地址和端口。在后端，它们在一组动态的 Pods 之间进行负载均衡。Pods 会不断地出现和消失，服务会观察到这一点，自动更新自己，并继续提供稳定的网络端点。

如果我们扩展或缩减 Pods 的数量，情况也是一样的。新的 Pods 会无缝地添加到服务中，而终止的 Pods 也会无缝地被移除。

这就是服务的工作-它是一个稳定的网络抽象点，可以在一组动态的 Pods 之间进行流量负载均衡。

#### 将 Pods 连接到服务

服务使用*标签*和*标签选择器*来知道要将请求负载均衡到哪组 Pods。服务有一个包含所有*标签*的*标签选择器*，一个 Pod 必须具有这些*标签*才能从服务中接收流量。

图 2.13 显示了一个配置为将流量发送到集群上所有带有以下三个标签的 Pods 的服务：

+   zone=prod

+   env=be

+   ver=1.3

图中的两个 Pod 都具有这三个标签，因此服务将对它们进行流量负载均衡。

![图 2.13](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00017.gif)

图 2.13

图 2.14 显示了类似的设置。然而，右侧的另一个 Pod 与服务标签选择器中配置的标签集不匹配。这意味着服务不会将请求负载均衡到它。

![图 2.14](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00018.gif)

图 2.14

关于服务的最后一件事。它们只会将流量发送到**健康的 Pods**。这意味着未能通过健康检查的 Pod 将不会从服务中接收流量。

这就是基础知识 - 服务将稳定的 IP 地址和 DNS 名称带入了不稳定的 Pods 世界！

### 章节总结

在本章中，我们介绍了 Kubernetes 集群的一些主要组件。

主节点是控制平面组件运行的地方。在幕后，它们是几个系统服务的组合，包括公共 REST 接口到控制平面的 API 服务器。主节点做出所有部署和调度决策，多主高可用对于生产级环境非常重要。

节点是用户应用程序运行的地方。每个节点运行一个名为`kubelet`的服务，该服务将节点注册到集群并与控制平面通信。这包括接收新的工作任务并报告它们的情况。节点还具有容器运行时和`kube-proxy`服务。容器运行时，如 Docker 或 containerd，负责所有与容器相关的操作。`kube-proxy`服务负责节点上的网络。

我们还谈到了一些主要的 Kubernetes API 对象，如 Pods、Deployments 和 Services。Pod 是基本构建块。Deployments 添加了自愈、扩展和更新功能。Services 添加了稳定的网络和负载均衡。

现在我们知道了基础知识，我们将开始深入了解细节。


# 第四章：安装 Kubernetes

在本章中，我们将看一下安装 Kubernetes 的几种不同方法。

自 2017 年 7 月我写下这本书的第一版以来，事情发生了很大变化。那时，安装 Kubernetes 很困难。如今，情况好多了！事实上，我们正接近一个可以*要求一个 Kubernetes 集群，并获得一个*的时刻。这在*托管的 Kubernetes 服务*，如 Azure Kubernetes Service（AKS）和 Google Kubernetes Engine（GKE）中尤其如此。

关于*托管的 Kubernetes 服务*，越来越多的人选择使用托管的 Kubernetes 服务，而且像*GKE On-Prem（https://cloud.google.com/gke-on-prem/）*这样的服务，越来越可能会有大量的 Kubernetes 集群通过主要的云服务提供商构建和管理。

在考虑构建自己的 Kubernetes 集群之前，请问自己以下问题：*构建和管理自己的 Kubernetes 集群是你时间和精力的最佳利用吗？*如果答案不是一个坚定的**“是！”**，我强烈建议你考虑使用托管服务。

好的，我们将看一下以下安装类型：

+   使用 Kubernetes 玩（PWK）

+   Docker Desktop：在你的笔记本上进行本地开发集群

+   Minikube：在你的笔记本上进行本地开发集群

+   Google Kubernetes Engine（GKE）：生产级托管集群

+   Kops：在 AWS 上安装你自己的集群

+   Kubeadm：使用 kubeadm 手动安装

在深入之前，有几件事情需要指出...

首先，还有很多其他安装 Kubernetes 的方法。我们在这里涵盖的是我认为最有帮助的方法。

其次，*托管的 Kubernetes 服务*是指控制平面（主节点）由平台管理的服务。例如，AKS、EKS 和 GKE 都是托管的 Kubernetes 服务，其中控制平面的管理由平台负责（你不需要负责）。2018 年看到了托管的 Kubernetes 平台的大幅增长。

是时候看一些安装了。

### 使用 Kubernetes 玩耍

使用 Kubernetes 玩（PWK）是免费的，是一个很好的方法，可以在不必在自己的设备上安装任何软件的情况下获得 Kubernetes 集群。你所需要的只是一台电脑，一个互联网连接，以及一个 Docker Hub 或 GitHub 的账户。在我看来，这是获得 Kubernetes 的最快最简单的方法。

但它也有局限性。首先，它是一个有时间限制的游乐场-您会得到一个持续 4 小时的实验室。它还缺少与云基负载均衡器等外部服务的一些集成。然而，除了限制之外，它是一个很棒的工具，我一直在使用！

让我们看看它是什么样子。

1.  将浏览器指向 http://play-with-k8s.com

1.  使用您的 GitHub 或 Docker Hub 帐户登录并单击“开始”

1.  从浏览器左侧的导航窗格中单击“+添加新实例”

您将在浏览器右侧看到一个终端窗口。这是一个 Kubernetes 节点（`node1`）。

1.  运行一些命令，查看节点上预安装的一些组件。

```
$ docker version
Docker version 18

.09.0-ce...

$ kubectl version --output=

yaml
clientVersion:
...
  major: "1"

  minor: "11"

```

正如输出所显示的，节点已经预安装了 Docker 和`kubectl`（Kubernetes 客户端）。其他工具包括`kubeadm`也已经预安装。

值得注意的是，虽然命令提示符是`$`，但我们实际上是以`root`身份运行的。我们可以通过运行`whoami`或`id`来确认这一点。

1.  使用`kubeadm`命令初始化一个新的集群

当您在第 3 步中添加了一个新实例时，PWK 会给您一个初始化新 Kubernetes 集群的命令的简短列表。其中一个是`kubeadm init...`。以下命令将初始化一个新的集群并配置 API 服务器以侦听正确的 IP 接口。

您可以通过在命令中添加`--kubernetes-version`标志来指定要安装的 Kubernetes 版本。最新版本可以在 https://github.com/kubernetes/kubernetes/releases 上看到。并非所有版本都适用于 PWK。

```
$

 kubeadm

 init

 --

apiserver

-

advertise

-

address

 $

(

hostname

 -

i

)

[

kubeadm

]

 WARNING

:

 kubeadm

 is

 in

 beta

,

 do

 not

 use

 it

 for

 prod

...

[

init

]

 Using

 Kubernetes

 version

:

 v1

.11.1

[

init

]

 Using

 Authorization

 modes

:

 [

Node

 RBAC

]

<

Snip

>

Your

 Kubernetes

 master

 has

 initialized

 successfully

!

<

Snip

>

```

恭喜！您有一个全新的单节点 Kubernetes 集群！我们执行命令的节点（`node1`）被初始化为*master*。

`kubeadm init`的输出会给您一个要运行的命令的简短列表。这些命令将复制 Kubernetes 配置文件并设置权限。您可以忽略这些，因为 PWK 已经为您配置好了。随意在`$HOME/.kube`内部查看。

1.  使用以下`kubectl`命令验证集群。

```
$ kubectl get nodes
NAME      STATUS     AGE       VERSION
node1     NotReady   1m        v1.11.2

```

输出显示了一个单节点 Kubernetes 集群。但是，节点的状态是`NotReady`。这是因为我们还没有配置*Pod 网络*。当您首次登录到 PWK 节点时，您会得到一个配置集群的三个命令的列表。到目前为止，我们只执行了第一个（`kubeadm init...`）。

1.  初始化 Pod 网络（集群网络）。

从首次创建`node1`时屏幕上打印的三个命令列表中复制第二个命令（这将是一个`kubectl apply`命令）。将其粘贴到终端的新行中。在书中，命令可能会跨越多行并插入反斜杠（`\`）。您应该删除页面右边出现的任何反斜杠。

```
$ kubectl apply -n kube-system -f \

 "https://cloud.weave.works/k8s/net?k8s-version=

$(

kubectl version |

 base64 |

 tr\

 -d '\n'

)

"

 serviceaccount "weave-net"

 created
 clusterrole "weave-net"

 created
 clusterrolebinding "weave-net"

 created
 role "weave-net"

 created
 rolebinding "weave-net"

 created
 daemonset "weave-net"

 created

```

1.  再次验证集群，看看`node1`是否已更改为`Ready`。

```
$ kubectl get nodes
NAME      STATUS    AGE       VERSION
node1     Ready     2m        v1.11.2

```

现在*Pod 网络*已经初始化，控制平面为`Ready`，您可以添加一些工作节点了。

1.  从`kubeadm init`的输出中复制`kubeadm join`命令。

当您使用`kubeadm init`初始化新集群时，命令的最终输出列出了一个`kubeadm join`命令，用于添加节点时使用。此命令包括集群加入令牌、API 服务器正在侦听的 IP 套接字以及加入新节点到集群所需的其他位。复制此命令，并准备粘贴到新节点（`node2`）的终端中。

1.  在 PWK 窗口的左侧窗格中点击`+ ADD NEW INSTANCE`按钮。

将会给你一个名为`node2`的新节点。

1.  将`kubeadm join`命令粘贴到`node2`的终端中。

在您的环境中，加入令牌和 IP 地址将是不同的。

```
   $ kubeadm join --token 948f32.79bd6c8e951cf122 10.0.29.3:6443...
   Initializing machine ID from random generator.
   [preflight] Skipping pre-flight checks
   <Snip>
   Node join complete:
   * Certificate signing request sent to master and response received.
   * Kubelet informed of new secure connection details.

```

1.  切换回`node1`并运行另一个`kubectl get nodes`。

```
   $ kubectl get nodes
   NAME      STATUS    AGE       VERSION
   node1     Ready     5m        v1.11.2
   node2     Ready     1m        v1.11.2

```

您的 Kubernetes 集群现在有两个节点 - 一个主节点和一个工作节点。

随意添加更多节点。

恭喜！您现在拥有一个完全可用的 Kubernetes 集群，可以用作测试实验室。

值得指出的是，`node1`被初始化为 Kubernetes 的*master*，而其他节点将作为*nodes*加入集群。PWK 通常在*masters*旁边放置蓝色图标，在*nodes*旁边放置透明图标。这有助于您识别哪个是哪个。

最后，PWK 会话只持续 4 小时，显然不适用于生产环境。

玩得开心！

### Docker Desktop

在我看来，*Docker Desktop*是在 Mac 或 Windows 笔记本电脑上获得本地开发集群的最佳方式。通过简单的几个步骤，您可以获得一个单节点 Kubernetes 集群，可以进行开发和测试。我几乎每天都在使用它。

它通过在笔记本电脑上创建一个虚拟机（VM）并在该虚拟机内启动单节点 Kubernetes 集群来工作。它还配置您的`kubectl`客户端，以便能够与集群通信。最后，您将获得一个简单的 GUI，允许您执行基本操作，如在所有`kubectl`上下文之间切换。

> **注意：** kubectl 上下文是`kubectl`命令使用的一堆设置，以便它知道要向哪个集群发出命令。

1.  将您的网络浏览器指向`www.docker.com`，然后选择`Products` > `Docker Desktop`。

1.  点击下载按钮，选择 Mac 或 Windows 版本。

您可能需要登录到 Docker Store。账户是免费的，产品也是免费的。

1.  打开安装程序并按照简单的安装说明进行操作。

安装程序完成后，您将在 Windows 任务栏上或 Mac 的菜单栏上看到一个鲸鱼图标。

1.  点击鲸鱼图标（您可能需要右键单击），转到`Settings`并从`Kubernetes`选项卡中启用 Kubernetes。

您可以打开一个终端窗口并查看您的集群：

```
$ kubectl get nodes
NAME                 STATUS   ROLES    AGE   VERSION
docker-for-desktop   Ready    master   68d   v1.10.3

```

恭喜，您现在拥有一个本地开发集群！

### Minikube

Minikube 是另一个选项，如果您是开发人员，并且需要在笔记本电脑上的本地 Kubernetes 开发环境。与*Docker Desktop*一样，您可以在本地运行一个单节点 Kubernetes 集群进行开发。这不是用于生产！

> **注意：** 我对 Minikube 的结果参差不齐。当它工作时很棒，但有时很难让它工作。因此，我更喜欢 Docker Desktop for Mac 和 Windows。

您可以在 Mac、Windows 和 Linux 上获取 Minikube。我们将快速查看 Mac 和 Windows，因为这是大多数人在笔记本电脑上运行的系统。

> **注意：** Minikube 需要在系统的 BIOS 中启用虚拟化扩展。

#### 在 Mac 上安装 Minikube

在安装 Minikube 之前，最好先安装`kubectl`（Kubernetes 客户端）。稍后您将使用它来向 Minikube 集群发出命令。

1.  使用 Brew 安装`kubectl`。

```
$ brew install kubernetes-cli
Updating Homebrew...

```

这将把 kubectl 二进制文件放在`/usr/local/bin`中，并使其可执行。

1.  验证安装是否成功。

```
$ kubectl version --client
Client Version: version.Info{

Major:"1"

, Minor:"12"

...

```

现在我们已经安装了`kubectl`客户端，让我们安装 Minikube。

1.  使用 Brew 安装 Minikube。

```
$ brew cask install minikube

==

> Downloading https://storage.googlapis.com/minikube...

```

如果提示，请提供您的密码。

1.  使用 Brew 为 Mac 安装**hyperkit**轻量级超级管理程序。

其他的 Hypervisor 选项可用 - VirtualBox 和 VMware Fusion - 但我们只展示 hyperkit。

```
$ brew install hyperkit

==

> Downloading https://homebrew.bintray...

```

1.  使用以下命令启动 Minikube。

```
$ minikube start --vm-driver=

hyperkit
Starting local

 Kubernetes cluster...
Starting VM...

```

`minikube start`是启动 Minikube 的最简单方法。指定`--vm-driver=hyperkit`标志将强制其使用**hyperkit**超级管理程序，而不是 VirtualBox。

您现在在 Mac 上已经有一个 Minikube 实例在运行！

#### 在 Windows 10 上安装 Minikube

在本节中，我们将向您展示如何在 Windows 上使用 Hyper-V 作为虚拟机管理器使用 Minikube。还有其他选项，但我们在这里不展示它们。我们还将使用以管理员权限打开的 PowerShell 终端。

在安装 Minikube 之前，让我们安装`kubectl`客户端。有几种方法可以做到这一点：

1.  使用 Chocolaty 软件包管理器

1.  通过您的网络浏览器下载

如果您使用 Chocolaty，可以使用以下命令安装它。

```
> choco install kubernetes-cli

```

如果您不使用 Chocolaty，可以使用您的网络浏览器安装`kubectl`。

将您的网络浏览器指向 https://kubernetes.io/docs/tasks/tools/install-kubectl/，并单击`使用 curl 安装 kubectl 二进制文件`选项。单击`Windows`选项卡。将 URL 复制并粘贴到您的网络浏览器中 - 这将下载`kubectl`二进制文件。确保只复制和粘贴 URL，而不是完整的`curl`命令。

下载完成后，将`kubectl.exe`文件复制到系统的`%PATH%`文件夹中。

使用`kubectl version`命令验证安装。

```
> kubectl version --client=true --output=yaml
clientVersion:
  ...
  gitVersion: v1.12.0
  ...
  major: "1"
  minor: "12"
  platform: windows/amd64

```

现在您有了`kubectl`，可以继续安装 Windows 的 Minikube。

1.  在 GitHub 上的 Minikube 版本页面上打开一个网络浏览器

+   https://github.com/kubernetes/minikube/releases

1.  从 Minikube 的最新版本下方单击`minikube-installer.exe`。这将下载 64 位 Windows 安装程序。

1.  启动安装程序，并通过向导接受默认选项。

1.  确保 Hyper-V 有一个外部 vSwitch。

打开 Hyper-V 管理器（`virtmgmt.msc`），转到`虚拟交换机管理器...`。如果没有配置以下两个选项的虚拟交换机，请创建一个新的：

+   `连接类型=外部网络`

+   `允许管理操作系统共享此网络适配器`

在本节的其余部分，我们将假设您已经配置了一个名为`external`的 Hyper-V 外部 vSwitch。如果您的名称不同，您将需要在以下命令中替换您的名称。

1.  使用以下命令验证 Minikube 版本。

```
> minikube version
minikube version: v0.30.0

```

1.  使用以下命令启动运行 Kubernetes 版本 1.12.1 的本地 Minikube 实例。

该命令假定一个名为`external`的 Hyper-V vSwitch，并使用反引号“`”使命令跨多行以提高可读性。

第一次下载和启动集群可能需要一段时间。

```
> minikube start `
--vm-driver=hyperv `
--hyperv-virtual-switch="external" `
--kubernetes-version="v1.12.1" `
--memory=4096

  Starting local Kubernetes v1.12.1 cluster...
  Starting VM...
  139.09 MB / 139.09 MB [================] 100.00% 0s
  <Snip>
  Starting cluster components...
  Kubectl is now configured to use the cluster.

```

1.  通过检查 Kubernetes 主版本的版本来验证安装。

```
> kubectl version -o yaml
clientVersion:
<Snip>
serverVersion:
  buildDate: 2018-10-05T16:36:14Z
  compiler: gc
  gitCommit: 4ed3216f3ec431b140b1d899130a69fc671678f4
  gitTreeState: clean
  gitVersion: v1.12.1
  goVersion: go1.10.4
  major: "1"
  minor: "12"
  platform: linux/amd64

```

如果目标机器积极拒绝网络连接，并显示`无法连接到服务器：拨号 tcp...`错误，这很可能是与网络相关的错误。确保您的 vSwitch 已正确配置，并且您已使用`--hyperv-virtual-switch`标志正确指定了它。`kubectl`通过端口 8443 与`minikube` Hyper-V VM 内的 Kubernetes 进行通信。

恭喜！您已在 Windows 10 PC 上成功运行了一个完全可用的 Minikube 集群。

现在，您可以在命令行上键入`minikube`以查看 minikube 子命令的完整列表。一个值得尝试的好命令可能是`minikube ip`，它将为您提供 Minikube 集群正在运行的 IP 地址。

#### 使用`kubectl`验证 Minikube 安装

`minikube start`操作配置了一个*kubectl 上下文*，这样您就可以在新的 Minikube 环境中使用`kubectl`。通过从与您运行`minikube start`相同的 shell 中运行以下`kubectl`命令来测试这一点。

```
   $ kubectl config current-context
   minikube

```

太棒了，您的 kubectl 上下文已设置为 Minikube。这意味着`kubectl`命令将被发送到 Minikube 集群。

值得指出的是，`kubectl`可以通过设置不同的上下文来配置为与任何 Kubernetes 集群通信-您只需要在不同的上下文之间切换以向不同的集群发送命令。

使用`kubectl get nodes`命令列出集群中的节点。

```
   $ kubectl get nodes
   NAME       STATUS   AGE   VERSION
   minikube   Ready    1m    v1.12.1

```

这是一个准备好使用的单节点 Minikube 集群！

您可以使用`minikube ip`命令获取集群的 IP 地址。

###### 删除 Minikube 集群

我们使用单个`minikube start`命令启动了 Minikube 集群。我们可以使用`minikube stop`命令停止它。

```
   $ minikube stop
   Stopping local Kubernetes cluster...
   Machine stopped

```

停止 Minikube 会保留所有磁盘上的配置。这样可以轻松地重新启动它，并从您离开的地方继续进行。

完全清除它-不留痕迹-使用`minikube delete`命令。

```
   $ minikube delete
   Deleting local Kubernetes cluster...
   Machine deleted

```

###### 在 Minikube 内运行特定版本的 Kubernetes

Minikube 允许您使用`--kubernetes-version`标志指定要运行的 Kubernetes 版本。如果您需要匹配生产环境中使用的 Kubernetes 版本，这将非常有用。

以下命令将启动一个运行 Kubernetes 版本 1.10.7 的 Minikube 集群。

```
   $ minikube start \
     --kubernetes-version=v1.10.7

     Starting local Kubernetes cluster...
     Starting VM...

```

运行另一个`kubectl get nodes`命令来验证版本。

```
   $ kubectl get nodes
   NAME       STATUS   AGE   VERSION
   minikube   Ready    1m    v1.10.7

```

中了！

这就是 Minikube！在 Mac 或 PC 上快速启动一个简单的 Kubernetes 集群的绝佳方式。但这不适用于生产！

### Google Kubernetes Engine（GKE）

Google Kubernetes Engine 是在 Google Cloud（GCP）上运行的*托管 Kubernetes*服务。像大多数*托管 Kubernetes*服务一样，它提供：

+   快速轻松地获得生产级别的 Kubernetes 集群

+   托管的控制平面（您不管理*主节点*）

+   逐项计费

> **警告：**GKE 和其他托管的 Kubernetes 服务并非免费。一些服务可能提供*免费层*或*免费信用额*的初始金额。但是，一般来说，您必须付费才能使用它们。

#### 配置 GKE

要使用 GKE，您需要在 Google Cloud 上拥有一个已配置计费的账户和一个空白项目。这些都很容易设置，所以我们不会在这里花时间解释它们 - 在本节的其余部分，我们将假设您已经拥有这些。

以下步骤将指导您通过 Web 浏览器配置 GKE。一些细节可能会在将来发生变化，但整体流程将保持不变。

1.  在您的 Google Cloud Platform（GCP）项目的控制台中，打开左侧的导航窗格，然后选择`Kubernetes Engine` > `Clusters`。您可能需要点击控制台左上角的三个水平条，以使导航窗格可见。

1.  点击`创建集群`按钮。

这将启动创建新 Kubernetes 集群的向导。

1.  向导目前提供了一些模板选项。这可能会在将来改变，但整体流程将保持不变。选择一个模板（`Your first cluster` 或 `Standard cluster` 可能是不错的选择）。

1.  为集群命名并添加描述。

1.  选择您想要的`区域`或`区域内`集群。区域是更新的，可能更具弹性 - 您的主节点和节点将分布在多个区域，但仍可通过单个高可用端点访问。

1.  选择您的集群的区域或区域内。

1.  选择`集群版本`。这是将在您的主节点和节点上运行的 Kubernetes 版本。您只能选择下拉列表中可用的版本。选择一个最新版本。

1.  您可以在`节点池`部分选择工作节点的数量和大小。这允许您选择工作节点的大小和配置，以及数量。更大更快的节点会产生更高的成本。

如果您正在构建一个区域集群，您指定的数字将是**每个区域中的节点数**，而不是总数。

1.  将所有其他选项保持默认值，然后点击`创建`。

您还可以单击`更多`链接，查看您可以自定义的其他选项的长列表。值得一看，但我们不会在本书中讨论它们。

您的集群现在将被创建！

#### 探索 GKE

现在您已经有了一个集群，是时候快速查看一下了。

确保您已登录到 GCP 控制台，并在`Kubernetes Engine`下查看`Clusters`。

集群页面显示了您在项目中拥有的 Kubernetes 集群的高级概览。图 3.1 显示了一个名为`gke1`的单个 3 节点集群。

![图 3.1](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00019.jpg)

图 3.1

单击集群名称以查看更多详细信息。图 3.2 显示了一些您可以查看的详细信息的屏幕截图。

![图 3.2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00020.jpg)

图 3.2

单击 Web UI 顶部的`> CONNECT`图标（图 3.2 中未显示）会给您一个命令，您可以在笔记本电脑上运行，以配置本地的`gcloud`和`kubectl`工具与您的集群通信。将此命令复制到剪贴板。

为了使以下步骤生效，您需要从`https://cloud.google.com/sdk/`下载并安装 Google Cloud SDK。这将下载几个实用程序，包括`gcloud`和`kubectl`命令行实用程序。

打开终端并将长的`gcloud`命令粘贴到其中。这将配置您的`kubectl`客户端以与您的新 GKE 集群通信。

运行`kubectl get nodes`命令以列出集群中的节点。

```
   $ kubectl get nodes
   NAME             STATUS     AGE    VERSION
   gke-cluster...   Ready      5m     v1.10.7-gke.6
   gke-cluster...   Ready      6m     v1.10.7-gke.6
   gke-cluster...   Ready      6m     v1.10.7-gke.6

```

恭喜！您知道如何使用 Google Kubernetes Engine（GKE）创建一个生产级别的 Kubernetes 集群。您还知道如何检查它并连接到它。

> **警告！**确保在使用完毕后立即删除您的 GKE 集群。即使不使用，GKE 和其他托管的 K8s 平台可能会产生费用。

### 使用`kops`在 AWS 上安装 Kubernetes

`kops`是 Kubernetes Operations 的缩写。它是一个*高度主观*的集群引导工具，使得在受支持的平台上安装 Kubernetes*相对简单*。

通过*高度主观*，我们的意思是在安装过程中您的自定义程度受到限制。如果您需要一个高度定制的集群，您应该看看`kubeadm`。

通过“相对简单”，我们的意思是比起自己编译二进制文件来说更容易:-D 如果你对这些领域没有经验，仍然有一些部分可能会很复杂。例如，当涉及到 DNS 配置时，`kops`非常主观 - 如果 DNS 配置错误，你将会陷入困境！幸运的是，它支持不使用 DNS 的基于八卦的安装。这适用于开发用例，不需要额外的 DNS 配置。

Kops 目前支持在 AWS 和 GCE 上引导集群。其他平台可能在将来得到支持。

在撰写本文时，`kops`命令行工具仅适用于 Mac 和 Linux。

您需要以下所有内容才能使用`kops`引导集群：

+   一个 AWS 账户和对 AWS 基础知识的良好理解

+   `kubectl`

+   适用于您的操作系统（Mac 或 Linux）的最新版本的`kops`二进制文件

+   `awscli`工具

+   具有以下权限的 AWS 账户凭据：

+   `AmazonEC2FullAccess`

+   `AmazonRoute53FullAccess`

+   `AmazonS3FullAccess`

+   `IAMFullAccess`

+   `AmazonVPCFullAccess`

以下示例来自 Linux 机器，但在 Mac 上（可能在将来也适用于 Windows）也是一样的。

以下示例展示了两种安装选项：

1.  DNS

1.  八卦

基于八卦的安装是最简单的，适用于私有 DNS 域不可用的情况。它也非常适合 AWS 位置，比如中国，那里没有 Route53。

DNS 安装更加复杂，需要顶级域和一个委托给 AWS Route53 的子域。本章中的 DNS 示例使用一个名为`tf1.com`的域，该域由 GoDaddy 等第三方提供商托管。它有一个名为`k8s`的子域，该子域被委托给 Amazon Route53。如果您要跟随 DNS 示例，您将需要自己的工作域。

#### 下载并安装`kubectl`

对于 Mac，下载和安装很简单，使用`brew install kubernetes-cli`。

以下步骤适用于 Linux 机器。

1.  使用以下命令将最新的`kubectl`二进制文件下载到您的主目录。

```
$ curl -LO https://storage.googleapis.com/kubernetes-release/release/$(

curl -s \

https://storage.googleapis.com/kubernetes-release/release/stable.txt)

/bin/linux\

/amd64/kubectl

```

该命令是一个单一的命令，但相当长，在书中会换行多次。这个过程可能会在打印页面的边缘引入反斜杠，这些反斜杠不是命令的一部分，需要被移除。

1.  使下载的二进制文件可执行，并将其移动到`PATH`中的目录。

```
$ chmod +x ./kubectl
$ mv ./kubectl /usr/local/bin/kubectl

```

运行`kubectl`命令，确保它已安装并正常工作。

#### 下载并安装`kops`。

对于 Mac，您只需要运行`brew install kops`。

对于 Linux，请使用以下过程。

1.  使用以下`curl`命令下载`kops`二进制文件。

命令应该在一行上发出，并且不应该有反斜杠`\`。它还嵌入了 URL 中`kops`工具的版本，您可以更改这个版本。请参阅 https://github.com/kubernetes/kops/releases 获取最新版本。

```
$ curl -LO https://github.com/kubernetes/kops/releases/download/1.10.0/kops-lin\

ux-amd64

```

1.  使下载的二进制文件可执行，并将其移动到系统`PATH`中的目录。

```
$ chmod +x kops-linux-amd64
$ mv kops-linux-amd64 /usr/local/bin/kops

```

运行`kops version`命令验证安装。

```
   $ kops version
   Version 1.10.0

```

#### 安装和配置 AWS CLI。

您可以使用`brew install awscli`在 Mac OS 上安装 AWS CLI 工具。

以下示例显示如何从 Ubuntu 18.04 使用的默认应用程序仓库安装 AWS CLI。如果您使用不同的 Linux 发行版，安装方法显然会有所不同。

1.  运行以下命令安装 AWS CLI。

```
$ sudo apt-get install awscli -y

```

1.  运行`aws configure`命令来配置 AWS CLI 的实例。

您将需要一个具有*AmazonEC2FullAccess*、*AmazonRoute53FullAccess*、*AmazonS3FullAccess*、*IAMFullAccess*和*AmazonVPCFullAccess*权限的 AWS IAM 帐户的凭据来完成此步骤。

```
$ aws configure
AWS Access Key ID [

None]

: **************
AWS Secret Access Key [

None]

: **************
Default region name [

None]

: enter-your-region-here
Default output format [

None]

:

```

1.  为 kops 创建一个新的 S3 存储桶，用于存储配置和状态信息。

Kops 要求集群名称必须是有效的 DNS 名称。在这些示例中，我们将使用名称`cluster1.k8s.tf1.com`。您将需要在您的环境中使用不同的名称。让我们快速分解一下它是如何工作的。该示例假设我拥有一个名为`tf1.com`的域，并且我已经将一个名为`k8s`的子域委派给了 AWS Route53。在该子域中，我可以创建任何我喜欢的名称的集群。在该示例中，我们将创建一个名为`cluster1`的集群。这将使集群的完全限定域名为`cluster1.k8s.tf1.com`。我已经在父域`tf1.com`中创建了`NS`记录，指向了 Route53 中托管的`k8s`域。`tf1.com`是虚构的，仅在这些示例中用于保持命令行参数的简洁。

如果您计划创建一个基于 gossip 的集群，您需要使用以`.k8s.local`结尾的集群名称。

```
$ aws s3 mb s3://cluster1.k8s.tf1.com
make_bucket: cluster1.k8s.tf1.com

```

1.  列出您的 S3 存储桶，并使用`grep`查找您创建的存储桶的名称。这将证明存储桶已成功创建。

```
$ aws s3 ls |

 grep k8s
2018

-10-10 13

:09:11 cluster1.k8s.tf1.com

```

1.  告诉**kops**在哪里找到它的配置和状态 - 这将是在上一步中创建的 S3 存储桶。

```
$ export

 KOPS_STATE_STORE

=

s3://cluster1.k8s.tf1.com

```

1.  使用以下`kops create cluster`命令之一创建新集群。

第一个命令使用 gossip 而不是 DNS 创建集群。要使用 gossip，集群名称**必须**以`.k8s.local`结尾。

第二个命令使用 DNS 创建集群，并假定之前已经解释过的工作 DNS 配置。

您需要一份 AWS 公钥的副本才能使命令生效。在示例中，密钥名为`np-k8s.pub`，位于当前工作目录中。

```
$ kops create cluster \

  --cloud-aws \

  --zones=

eu-west-1b \

  --name=

mycluster.k8s.local \

  --ssh-public-key ~/np-k8s.pub \

  --yes

```

```
$ kops create cluster \

  --cloud=

aws \

  --zones=

eu-west-1b \

  --dns-zone=

k8s.tf1.com \

  --name cluster1.k8s.tf1.com  \

  --ssh-public-key ~/np-k8s.pub \

  --yes

```

命令分解如下。`kops create cluster`告诉**kops**创建一个新的集群。`--cloud=aws`告诉它使用 AWS 提供程序在 AWS 中创建集群。`--zones=eu-west-1b`告诉**kops**在 eu-west-1b 区创建集群。如果使用 DNS 创建集群，`--dns-zone`标志告诉它使用委托区域。我们使用`--name`标志命名集群-如果使用 gossip 创建，请记住以“.k8s.local”结尾。`--ssh-public-key`告诉它使用哪个密钥。最后，`--yes`标志告诉**kops**继续部署集群。如果省略`--yes`标志，将创建集群配置，但不会部署。

集群部署可能需要几分钟时间。这是因为**kops**正在创建构建集群所需的 AWS 资源。这包括诸如 VPC、EC2 实例、启动配置、自动缩放组、安全组等。在构建了 AWS 基础设施之后，它还必须构建 Kubernetes 集群。

1.  部署集群后，您可以使用`kops validate cluster`命令对其进行验证。集群完全启动可能需要一段时间，所以请耐心等待。

```
$ kops validate cluster
Using cluster from kubectl context: cluster1.k8s.tf1.com

INSTANCE GROUPS
NAME      ROLE     MACHINETYPE  MIN  MAX  SUBNETS
master..  Master   m3.medium    1

    1

    eu-west-1b
nodes     Node     t2.medium    2

    2

    eu-west-1b

NODE STATUS
NAME             ROLE      READY
ip-172-20-38..   node      True
ip-172-20-58..   master    True
ip-172-20-59..   node      True

Your cluster cluster1.k8s.tf1.com is ready

```

恭喜！您现在知道如何使用`kops`工具在 AWS 中创建 Kubernetes 集群。

现在您的集群已经运行起来，您可以对其发出`kubectl`命令。也许值得在 AWS 控制台中查看一下`kops`创建的一些资源。

> **警告！**确保在使用完毕后删除您的集群。在云平台上运行的集群可能会产生费用，即使它们没有被积极使用。

#### 使用`kops`在 AWS 中删除 Kubernetes 集群

您可以使用`kops delete cluster`命令来删除您刚刚创建的集群。这也将删除为支持集群创建的所有 AWS 资源。

以下命令将删除前面步骤中创建的集群。

```
   $ kops delete cluster --name=cluster1.k8s.tf1.com --yes

```

### 使用`kubeadm`安装 Kubernetes

在这一部分，我们将看到如何使用`kubeadm`安装 Kubernetes。

`kubeadm`最好的一点是，您可以使用它在几乎任何地方安装 Kubernetes - 笔记本电脑、数据中心的裸机，甚至在公共云上。它不仅仅是安装 Kubernetes - 您还可以升级、管理和查询您的集群。人们经常说`kubeadm`是集群的`kubectl` - 一个用于构建**和**管理 Kubernetes 集群的绝佳工具。无论如何，`kubeadm`是一个核心的 Kubernetes 项目，并且有着光明的未来。

本节中的示例基于 Ubuntu 18.04。如果您使用不同的 Linux 发行版，则先决条件部分中的一些命令将有所不同。但是，我们展示的过程可以用于在笔记本电脑、数据中心甚至云中安装 Kubernetes。

我们将演示一个简单的示例，使用三台配置为一个主节点和两个节点的 Ubuntu 18.04 机器，如图 3.3 所示。

![图 3.3](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00021.jpg)

图 3.3

高级计划将如下：

1.  安装先决条件

1.  使用**node1**初始化一个新的集群作为主节点

1.  创建 Pod 网络

1.  将**node2**和**node3**添加为工作节点。

所有三个节点都将获得以下内容：

+   Docker

+   `kubeadm`

+   kubelet

+   `kubectl`

**Docker**是容器运行时。还存在其他运行时，但我们将使用 Docker。`kubeadm`是我们将用来构建集群的工具，**kubelet**是 Kubernetes 节点代理，`kubectl`是 Kubernetes 命令行实用程序。

#### 先决条件

以下命令特定于 Ubuntu 18.04，并且需要在**所有三个节点**上运行。它们设置了一些东西，以便我们可以从正确的存储库安装正确的软件包。其他 Linux 版本也存在等效的命令和软件包。

使用以下两个命令获取稍后步骤中将需要的一些软件包的最新版本。

```
$ sudo apt-get update
<Snip>

$ sudo apt-get install -y \

  apt-transport-https \

  ca-certificates \

  curl \

  software-properties-common

```

下载并安装以下两个存储库密钥。其中一个存储库包含 Kubernetes 工具，另一个存储库包含 Docker。我们将在稍后的步骤中需要这些密钥。

```
$ curl -s \

 https://packages.cloud.google.com/apt/doc/apt-key.gpg |

 sudo apt-key add -
OK

$ curl -fsSL \

 https://download.docker.com/linux/ubuntu/gpg |

 sudo apt-key add -
OK

```

创建或编辑以下文件，并添加安装 Kubernetes 软件包所需的存储库。

```
$ sudo vim /etc/apt/sources.list.d/kubernetes.list

```

添加以下行。

```
deb

 https://apt.kubernetes.io/

 kubernetes-xenial

 main

```

下一步是安装`kubeadm`，`kubectl`和`kubelet`。使用以下两个命令。

```
$ sudo apt-get update
<Snip>

$ sudo apt-get install -y kubelet kubeadm kubectl
<Snip>

```

如果再次运行`apt-get install`命令，您可以看到已安装的版本。

现在让我们安装 Docker...

添加所需的指纹。

```
$ sudo apt-key fingerprint 0EBFCD88
pub   rsa4096 2017

-02-22 [

SCEA]

      9DC8 5822

 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88
uid           [

 unknown]

 Docker Release (

CE deb)

 <docker@docker.com>
sub   rsa4096 2017

-02-22 [

S]

```

现在添加*stable* Docker 仓库。这是一个单一的命令，使用反斜杠将其分布在多行上。

```
$ sudo add-apt-repository \

   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \

$(

lsb_release -cs)

 \

 stable"

```

安装 Docker。

```
$ sudo apt-get update
<Snip>

$ sudo apt-get install docker-ce
<Snip>

```

这些是先决条件。

#### 初始化一个新的集群

使用`kubeadm init`初始化一个新的 Kubernetes 集群就像输入`kubeadm init`一样简单。

```
   $ sudo kubeadm init
   <SNIP>
   Your Kubernetes master has initialized successfully!

   To start using your cluster, you need to run (as a regular user):

   mkdir -p $HOME/.kube
   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
   sudo chown $(id -u):$(id -g) $HOME/.kube/config

   <SNIP>
   You can join any number of machines by running the following...

   kubeadm join --token b90685.bd53aca93b758efc 172.31.32.74:6443

```

该命令拉取所有必需的镜像并构建集群。当过程完成时，它会输出一些简短的命令，让您可以作为普通用户管理集群。它还会给出`kubeadm join`命令，让您可以将其他节点添加到集群中。

恭喜！这是一个全新的单主 Kubernetes 集群。

通过运行`kubeadm init`输出中列出的命令来完成该过程。

```
   $ mkdir -p $HOME/.kube
   $ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
   $ sudo chown $(id -u):$(id -g) $HOME/.kube/config

```

这些命令可能会有所不同，甚至在将来可能不再需要。但是，它们会将 Kubernetes 配置文件从`/etc/kubernetes`复制到您的主目录，并将所有权更改为您。

使用`kubectl`验证集群是否初始化成功。

```
   $ kubectl get nodes
   NAME    STATUS     ROLES    AGE     VERSION
   node1   NotReady   master   2m43s   v1.12.1

```

运行以下`kubectl`命令查找集群`STATUS`显示为`NotReady`的原因。

```
   $ kubectl get pods --all-namespaces
   NAMESPACE     NAME           READY   STATUS              RESTARTS   AGE
   kube-system   coredns-...vt  0/1     ContainerCreating   0          8m33s
   kube-system   coredns-...xw  0/1     ContainerCreating   0          8m33s
   kube-system   etcd...        1/1     Running             0          7m46s
   kube-system   kube-api...    1/1     Running             0          7m36s
   ...

```

该命令显示所有命名空间中的所有 Pods - 这包括系统命名空间（kube-system）中的系统 Pods。

正如我们所看到的，没有一个`coredns` Pods 在运行。这阻止了集群进入`Ready`状态，这是因为我们还没有创建 Pod 网络。

创建 Pod 网络。以下示例创建了一个由 Weaveworks 提供的多主机覆盖网络。还有其他选项可用，您不必选择这里显示的示例。

该命令可能会在书中跨越多行。在打印页面的边缘处的任何反斜杠（`\`）都应该被移除。

```
   $ kubectl apply -n kube-system -f \
   "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | \
tr -d '\n')"

```

检查主节点的状态是否从`NotReady`变为`Ready`。

```
$ kubectl get nodes
NAME    STATUS   ROLES    AGE     VERSION
node1   Ready    master   3m51s   v1.12.1

```

好了，集群已经准备好了，DNS Pods 现在将会运行。

现在集群已经运行起来了，是时候添加一些节点了。

添加工作节点需要集群的加入令牌。您可能还记得，这是在集群首次初始化时作为输出的一部分提供的。滚动回到那个输出，将`kubeadm join`命令复制到剪贴板上，然后在**node2**和**node3**上运行它。

> **注意：**以下操作必须在**node2**和**node3**上执行，并且您必须已经在这些节点上安装了先决条件（Docker、kubeadm、kubectl 和 kubelet）。

```
   node2$ kubeadm join 172.31.32.74:6443 --token b90...
   <SNIP>
   Node join complete:
   * Certificate signing request sent to master and response received
   * Kubelet informed of new secure connection details.

```

在**node3**上重复该命令。

确保两个节点都成功注册，通过在主节点上再次运行 `kubectl get nodes` 来检查。

```
   $ kubectl get nodes
   NAME    STATUS   ROLES    AGE   VERSION
   node1   Ready    master   10m   v1.12.1
   node2   Ready    master   55s   v1.12.1
   node3   Ready    <none>   34s   v1.12.1

```

恭喜！您已经使用 `kubeadm` 手动构建了一个由 3 个节点组成的集群。但请记住，它只运行一个单一的主节点，没有 H/A。

随意使用 `kubeadm` 在集群中探索。您还应该调查 `kubeadm` 安装具有 H/A 管理器的集群的方法。

### 章节总结

在本章中，我们学习了如何在几种不同的平台上以几种不同的方式安装 Kubernetes。

我们看到了在 Play with Kubernetes (PWK) 上设置 Kubernetes 集群是多么快速简单。我们可以在没有在笔记本电脑或自己的云中安装任何东西的情况下获得 4 小时的游乐场。

我们在笔记本电脑上为开发人员提供了出色的开发体验，安装了 Docker Desktop 和 Minikube。

我们学习了如何在谷歌云中使用 Google Kubernetes Engine (GKE) 快速创建托管的 Kubernetes 集群。

然后我们看了如何使用 `kops` 工具在 AWS 上使用 AWS 提供程序快速创建集群。

我们完成了本章，看到了如何使用 `kubeadm` 工具执行手动安装。

我们可以在其他方式和地方安装 Kubernetes。但本章已经足够长了，我已经拔了太多头发了 :-D


# 第五章：使用 Pods

我们将把本章分为两个主要部分：

+   理论

+   动手

让我们继续理论。

### Pod 理论

在虚拟化世界中，调度的原子单位是虚拟机（VM）。这意味着在虚拟化世界中**部署应用程序**意味着在 VM 上调度它们。

在 Docker 世界中，原子单位是容器。这意味着在 Docker 上**部署应用程序**意味着将它们部署在容器内。

在 Kubernetes 世界中，原子单位是*Pod*。因此，在 Kubernetes 上**部署应用程序**意味着将它们作为 Pods 部署。

![图 4.1](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00022.jpg)

图 4.1

确保将这一点记在脑海中并标记为重要 - 虚拟化使用 VM，Docker 使用容器，**Kubernetes 使用 Pods！**

由于 Pods 是 Kubernetes 集群上部署的基本单位，我们必须了解它们是如何工作的。

> **注意：**在本章中我们将大量讨论 Pods。然而，重要的是要记住 Pods 只是**部署应用程序**的一种工具。

#### Pods vs 容器

在高层次上，Pods 位于容器和 VM 之间。它们比容器大，但比 VM 小得多。

深入挖掘一下，Pod 是一个或多个容器的共享执行环境。往往情况下，一个 Pod 只有一个容器。但多容器 Pod 绝对是存在的，它们非常适合协同调度紧密耦合的工作负载。例如，共享资源并且如果它们被调度到集群中的不同节点上将无法正常工作的两个容器。多容器 Pod 越来越常见的另一个用例是日志记录和服务网格。

#### Pods：典型的例子

我们通常在比较单容器和多容器 Pods 时使用的例子是一个具有文件同步器的 Web 服务器。

在这个例子中，我们有两个明确的*关注点*：

1.  提供网页

1.  确保内容是最新的

> **注意：**将*关注点*视为需求/任务。在微服务架构中，我们经常将关注点称为*服务*。在前面的列表中，我们可能将*网页关注点*称为*网页服务*。每个*服务*处理一个*关注点*。

一般来说，微服务设计模式要求我们应该分离关注点。这意味着一个容器只处理一个*关注点*。假设前面的例子，一个容器用于 web 服务，另一个容器用于文件同步服务。

这种方法有很多优势。

我们不是构建单体应用程序，其中单个 Pod 运行 Web 服务*和*文件同步服务，而是构建两个微服务-每个微服务都有自己独特的关注点。这意味着我们可以有不同的团队负责这两个服务。我们可以独立扩展每个服务。我们也可以独立更新它们。如果运行文件同步服务的 Pod 失败，Web 服务可以保持运行（尽管可能会提供过时内容）。

然而，有时在单个 Pod 中共同调度多个容器是有意义的。使用情况包括；需要共享内存或共享卷的两个容器。见图 4.2。

![图 4.2](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00023.jpg)

图 4.2

在这种情况下，我们没有分离关注点-一个单独的 Pod 正在执行两项任务。然而，实现共享卷的最简单方法是将将共享卷的容器调度到同一节点上。通过在同一个 Pod 中运行 Web 服务容器和文件同步容器，我们确保它们部署到同一节点上。我们还为它们提供了一个共享的操作环境，两者都可以访问相同的共享内存和共享卷等。稍后会详细介绍所有这些。

总之，一般规则是通过设计 Pod 和容器来分离关注点，每个 Pod 执行单个任务，然后为每个 Pod 调度单个容器。然而，有些情况下打破这个规则是有优势的。

#### 我们如何部署 Pods

要将 Pod 部署到 Kubernetes 集群中，我们在*清单文件*中定义它，并将该清单文件`POST`到 API 服务器。控制平面检查它，将其记录在集群存储中，并调度器将其部署到具有足够可用资源的健康节点上。无论 Pod 运行多少个容器，这个过程都是相同的。

![图 4.3](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00024.jpg)

图 4.3

让我们深入一点…

#### Pod 的解剖

在最高级别上，Pod 是一个或多个容器的共享执行环境。“共享执行环境”意味着 Pod 具有一组资源，这些资源被 Pod 内的每个容器共享。这些资源包括；IP 地址，端口，主机名，套接字，内存，卷等等…

如果您将 Docker 用作 Kubernetes 的容器运行时，Pod 实际上是一种称为**暂停容器**的特殊容器。没错，Pod 只是一个特殊容器的花哨名称！

这意味着在 Pod 内运行的容器实际上是在容器内运行的容器！有关更多信息，请观看克里斯托弗·诺兰执导、莱昂纳多·迪卡普里奥主演的《盗梦空间》:-D

但是，Pod（暂停容器）只是容器内运行的容器将继承和共享的一组系统资源。这些“系统资源”是“内核命名空间”，包括：

+   网络命名空间：IP 地址、端口范围、路由表…

+   UTS 命名空间：主机名

+   IPC 命名空间：Unix 域套接字…

正如我们刚才提到的，这意味着 Pod 中的所有容器共享主机名、IP 地址、内存地址空间和卷。

让我们更仔细地看看这如何影响网络。

每个 Pod 都创建自己的网络命名空间 - 单个 IP 地址、单个端口范围和单个路由表。即使 Pod 是多容器 Pod，每个 Pod 中的容器也共享 Pod 的 IP、端口范围和路由表。

图 4.4 显示了两个具有自己 IP 的 Pod。即使其中一个 Pod 托管了两个容器，它仍然只有一个 IP。

![图 4.4](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00025.jpg)

图 4.4

在图 4.4 的示例中，我们可以使用 Pod IP 与容器的个别端口号（80 和 5000）来访问 Pod 1 中的各个容器。

最后一次（如果感觉我反复强调了，我很抱歉）… Pod 中的每个容器都共享**Pod**的整个网络命名空间 - IP、`localhost`适配器、端口范围、路由表等。

但正如我们所说，它不仅仅是网络。Pod 中的所有容器都可以访问相同的卷、相同的内存、相同的 IPC 套接字等。从技术上讲，Pod（暂停容器）包含所有命名空间，Pod 中的任何容器都会继承并共享它们。

这种网络模型使*Pod 间*通信变得非常简单。集群中的每个 Pod 都有自己的 IP 地址，在*Pod 网络*上是完全可路由的。如果您阅读了有关安装 Kubernetes 的章节，您会看到我们在*Play with Kubernetes*和*kubeadm*部分末尾创建了一个 Pod 网络。因为每个 Pod 都有自己的可路由 IP，所以每个 Pod 都可以直接与其他 Pod 通信。不需要处理像恶心的端口映射之类的东西！

![图 4.5 Pod 间通信](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00026.jpg)

图 4.5 Pod 间通信

*Pod 内部*通信-同一 Pod 中的两个容器需要通信-可以通过 Pod 的`localhost`接口进行。

![图 4.6 Pod 内部通信](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00027.gif)

图 4.6 Pod 内部通信

如果需要使同一 Pod 中的多个容器对外界可用，可以在各自的端口上公开它们。每个容器都需要自己的端口，同一 Pod 中的两个容器不能使用相同的端口。

总之。一切都关乎**Pod**！**Pod**被部署，**Pod**获得 IP，**Pod**拥有所有的命名空间... **Pod**是 Kuberverse 的中心！

#### Pods 和 cgroups

在高层次上，控制组（cgroups）是阻止单个容器在节点上消耗所有可用的 CPU、RAM 和 IOPS 的东西。我们可以说 cgroups“监管”资源使用。

单个容器有自己的 cgroup 限制。

这意味着单个 Pod 中的两个容器可以拥有自己的 cgroup 限制集。这是一个强大而灵活的模型。如果我们假设前面章节中的典型多容器 Pod 示例，我们可以在文件同步容器上设置 cgroup 限制，以便它可以访问比 web 服务容器更少的资源。这将减少它使 web 服务容器饥饿的 CPU 和内存的风险。

#### Pod 的原子部署

部署 Pod 是一个*原子操作*。这意味着这是一个全包或全不包的操作-没有部分部署的 Pod 可以提供服务。

例如，要么：Pod 中的所有内容都启动并且 Pod 变得可用，**或者**，所有内容都没有启动并且 Pod 失败。这意味着你永远不会出现一个多容器 Pod 的一部分容器启动并且可访问，但另一个容器处于失败状态的情况！这不是它的工作方式。直到整个 Pod 都启动后，Pod 中的任何内容都不可用。一旦所有 Pod 资源准备就绪，Pod 就变得可用。

同样重要的是强调，任何给定的 Pod 只能在单个节点上运行。这与容器和虚拟机相同-你不能让一个 Pod 的一部分在一个节点上，另一部分在另一个节点上。一个 Pod 被调度到一个节点上！

#### Pod 生命周期

典型 Pod 的生命周期大致如下。你在一个 YAML 清单文件中定义它。然后你将清单文件扔给 API 服务器，它定义的 Pod 被调度到一个健康的节点上。一旦它被调度到一个节点，它就进入*pending*状态，同时节点下载镜像并启动任何容器。Pod 将保持在这个*pending*状态，直到**它的所有资源**都准备就绪。一旦一切都准备就绪，Pod 进入*running*状态。一旦它完成了它需要做的一切，它就被终止并进入*succeeded*状态。

如果你独立部署一个 Pod（而不是通过更高级别的对象），并且该 Pod 失败了，它不会被重新调度！因此，我们很少直接部署它们。更常见的是通过更高级别的对象如*Deployments*和*DaemonSets*来部署它们，因为这些对象在它们失败时会重新调度 Pods。

当一个 Pod 无法启动时，它可以保持在*pending*状态或进入*failed*状态。这都显示在图 4.7 中。

![图 4.7 Pod 生命周期](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00028.jpg)

图 4.7 Pod 生命周期

将 Pod 视为*有限的*也很重要。当它们死了，它们就死了！不能让它们从死亡中复活。这遵循*宠物与牛群*的类比 - Pods 应该被视为*牛群*。当它们死了，你用另一个替换它们。没有眼泪，没有葬礼。旧的消失了，一个全新的 - 具有相同的配置，但不同的 ID 和 IP - 神奇地出现并取代它的位置。

**注意：**在提到*宠物与牛群*的类比时，不是针对任何人或动物的冒犯。

这是你应该编写应用程序的主要原因之一，这样它们就不会在 Pods 中存储*状态*。这也是为什么我们不应该依赖于单个 Pod IP 等。

#### Pod 理论总结

1.  Pods 是 Kubernetes 中调度的原子单位

1.  一个 Pod 中可以有多个容器。单容器 Pods 是最简单的，但多容器 Pods 非常适合需要紧密耦合的容器 - 也许它们需要共享内存或卷。它们也非常适合日志记录和服务网格。

1.  Pods 被调度到节点上 - 你不能调度一个单个 Pod 实例跨越多个节点。

1.  Pods 在一个清单文件中被声明，并通过调度器分配给节点。

### 与 Pods 一起动手

是时候看看 Pods 的实际操作了！

在本章的其余示例中，我们将使用图 4.8 中显示的 3 节点集群。

![图 4.8](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-bk/img/Image00029.jpg)

图 4.8

这个集群在哪里并不重要，或者它是如何部署的。重要的是你有三个 Linux 主机配置成一个 Kubernetes 集群，至少有一个主节点和两个节点。你还需要安装并配置`kubectl`以便与集群通信。

如果您没有集群并希望跟随操作，请转到 http://play-with-k8s.com 并构建一个快速集群 - 这是免费且简单的。

遵循 Kubernetes 的*可组合基础设施*理念，我们在清单文件中定义 Pods，将清单发布到 API 服务器，并让调度器负责在集群上实例化 Pods。

#### Pod 清单文件

在本章的示例中，我们将使用以下 Pod 清单。它在书籍的 GitHub 存储库中的`pods`文件夹下的 pod.yml 中可用：

```
apiVersion

:

 v1

kind

:

 Pod

metadata

:

  name

:

 hello

-

pod

  labels

:

    zone

:

 prod

    version

:

 v1

spec

:

  containers

:

  -

 name

:

 hello

-

ctr

    image

:

 nigelpoulton

/

k8sbook

:

latest

    ports

:

    -

 containerPort

:

 8080

```

让我们逐步了解 YAML 文件在描述什么。

我们立即可以看到四个顶级资源：

+   `.apiVersion`

+   `.kind`

+   `.metadata`

+   `.spec`

`.apiVersion`字段告诉我们两件事 - 将用于创建对象的*API 组*和*API 版本*。通常格式为`<api-group>/<version>`。但是，Pods 定义在一个称为*core*组的特殊 API 组中，该组省略了*api-group*部分。例如，StorageClass 对象在`storage.k8s.io` API 组的`v1`中定义，并在 YAML 文件中描述为`storage.k8s.io/v1`。但是，Pods 位于特殊的*core* API 组中，它省略了 API 组名称。

一个对象可以在 API 组的多个版本中定义。例如，`some-api-group/v1`和`some-api-group/v2`。在这种情况下，较新组中的定义可能包括扩展对象功能的附加字段。将*version*字段视为定义对象模式 - 新版本通常更好。

无论如何，Pods 目前在`v1` API 组中。

`.kind`字段告诉我们部署的对象类型。它有两个明显的功能。首先，它使阅读 YAML 文件更容易。其次，它明确告诉控制平面正在定义的对象类型，因此应将其传递给哪个控制器。

到目前为止，我们知道我们正在部署一个在*core API 组*的`v1`中定义的 Pod 对象。

`.metadata`部分是我们附加名称和标签的地方。这些帮助我们在集群中识别对象。我们还定义了对象应该部署在哪个`namespace`中。简而言之，命名空间允许我们在管理目的上逻辑地划分集群。在现实世界中，强烈建议使用命名空间。但是，它们不应被视为强大的安全边界。

这个 Pod 清单的`.metadata`部分将 Pod 命名为“hello-pod”并分配了两个标签。标签是简单的键值对，但它们非常强大！随着我们知识的积累，我们将更多地讨论标签。

`.spec`部分是我们定义将在 Pod 中运行的任何容器的地方。我们的示例是部署一个基于`nigelpoulton/k8sbook:latest`镜像的单个容器的 Pod。它将其命名为 hello-ctr，并在端口`8080`上公开它。

如果这是一个多容器的 Pod，我们将在`.spec`部分定义额外的容器。

#### 清单文件：代码中的共情

快速侧步。

配置文件，比如 Kubernetes 清单文件，是文档的绝佳来源。因此，它们有一些次要的好处。其中两个包括：

+   帮助加快新团队成员的入职过程

+   帮助弥合开发人员和运维之间的鸿沟

例如，如果你需要一个新团队成员理解一个应用的基本功能和需求，让他们阅读用于部署它的 Kubernetes 清单文件。

另外，如果你对开发人员没有清晰表达他们的应用需求有问题，让他们使用 Kubernetes。当他们通过 Kubernetes 清单描述他们的应用时，运维人员可以使用这些清单来理解应用的工作原理以及它对环境的需求。

这些好处被 Nirmal Mehta 描述为他在 2017 年 DockerCon 演讲中所说的*代码中的共情*的一种形式。

我知道将这些 YAML 文件描述为*“代码中的共情”*听起来有点极端。然而，这个概念是有价值的-它们确实有帮助。

回到正题...

#### 从清单文件部署 Pod

如果你跟着示例操作，将以下清单文件保存为`pod.yml`在你当前的目录中。

```
apiVersion

:

 v1

kind

:

 Pod

metadata

:

  name

:

 hello

-

pod

  labels

:

    zone

:

 prod

    version

:

 v1

spec

:

  containers

:

  -

 name

:

 hello

-

ctr

    image

:

 nigelpoulton

/

k8sbook

:

latest

    ports

:

    -

 containerPort

:

 8080

```

使用以下`kubectl`命令将清单 POST 到 API 服务器，并从中部署一个 Pod。

```
$ kubectl apply -f pod.yml
pod "hello-pod"

 created

```

尽管 Pod 显示为已创建，但它可能尚未完全部署在集群上。这是因为拉取镜像可能需要一些时间。

运行`kubectl get pods`命令来检查状态。

```
$ kubectl get pods
NAME        READY    STATUS             RESTARTS   AGE
hello-pod   0

/1      ContainerCreating  0

          9s

```

我们可以看到容器仍在创建中 - 毫无疑问正在等待从 Docker Hub 拉取镜像。

您可以使用`kubectl describe pods hello-pod`命令来深入了解更多细节。

您可以向`kubectl get pods`命令添加`--watch`标志，以便可以监视它，并查看状态何时变为运行状态。

恭喜！您的 Pod 已被调度到集群中的健康节点，并且正在由节点上的本地`kubelet`进程监视。`kubelet`进程是在节点上运行的 Kubernetes 代理。

在以后的章节中，我们将看到如何连接到 Pod 中运行的 Web 服务器。

#### 审视运行中的 Pods

尽管`kubectl get pods`命令很好，但细节有点少。不过，不用担心，有很多选项可以进行更深入的内省。

首先，`kubectl get`提供了一些非常简单的标志，可以为您提供更多信息：

`-o wide`标志提供了更多的列，但仍然是单行输出。

`-o yaml`标志将事情提升到了一个新的水平！它返回了从集群存储中的 Pod 清单的完整副本。此输出包括期望状态（`.spec`）和当前观察状态（`.status`）。

以下命令显示了`kubectl get pods -o yaml`命令的剪辑版本。

```
$ kubectl get pods hello-pod -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |

      ...
  name: hello-pod
  namespace: default
spec:
  containers:
  - image: nigelpoulton/k8sbook:latest
    imagePullPolicy: Always
    name: hello-ctr
    ports:
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: 2018

-10-19T15:24:24Z
    state:
      running:
        startedAt: 2018

-10-19T15:26:04Z
...

```

请注意，输出包含的值比我们最初在 13 行的 YAML 文件中设置的要多。这些额外的信息是从哪里来的？

两个主要来源：

+   Kubernetes Pod 对象包含许多属性 - 远远超过我们在清单中定义的属性。我们没有指定的属性将由 Kubernetes 自动扩展为默认值。

+   当您运行带有`-o yaml`的`kubectl get pods`时，您将获得 Pods 的*当前观察状态*以及其*期望状态*。此观察状态列在`.status`部分中。

另一个很棒的 Kubernetes 内省命令是`kubectl describe`。它提供了一个格式良好的、多行的对象概述。它甚至包括一些重要的对象生命周期事件。以下命令描述了 hello-pod Pod 的状态，并显示了一个剪辑输出。

```
$

 kubectl

 describe

 pods

 hello

-

pod

Name

:

         hello

-

pod

Namespace

:

    default

Node

:

         docker

-

for

-

desktop

/

192.168

.

65.3

Start

 Time

:

   Fri

,

 19

 Oct

 2018

 16

:

24

:

24

 +

0100

Labels

:

       version

=

v1

              zone

=

prod

Status

:

       Running

IP

:

           10.1

.

0.21

Containers

:

  hello

-

ctr

:

    Image

:

          nigelpoulton

/

k8sbook

:

latest

    Port

:

           8080

/

TCP

    Host

 Port

:

      0

/

TCP

    State

:

          Running

Conditions

:

  Type

           Status

  Initialized

    True

  Ready

          True

  PodScheduled

   True

...

Events

:

  Type

    Reason

     Age

   Message

  ----

    ------

     ----

  -------

  Normal

  Scheduled

  2

m

   Successfully

 assigned

...

  Normal

  Pulling

    2

m

   pulling

 image

 "nigelpoulton/k8sbook:latest"

  Normal

  Pulled

     2

m

   Successfully

 pulled

 image

  Normal

  Created

    2

m

   Created

 container

  Normal

  Started

    2

m

   Started

 container

```

输出已经被剪辑以使其适合页面。

内省运行中的 Pod 的另一种方法是登录到其中或在其中执行命令。我们使用`kubectl exec`命令来实现这一点。以下示例显示了如何在`hello-pod` Pod 中的第一个容器中执行`ps aux`命令。

```
$ kubectl exec

 hello-pod ps aux
PID   USER     TIME   COMMAND
  1

   root     0

:00   node ./app.js
 40

   root     0

:00   ps aux

```

您可以使用以下命令登录到 Pod 中的第一个容器。一旦进入容器，您可以执行正常的命令（只要命令二进制文件安装在容器中）。

`kubectl exec`命令将登录到 Pod 中的第一个容器并创建一个新的 shell 会话。一旦进入容器，`curl`命令将从在端口`8080`上监听的进程传输数据。

```
$ kubectl exec -it hello-pod sh

sh-4.1 # curl localhost:8080
<html><head><title>

Pluralsight Rocks</title><link

 rel=

"stylesheet"

 href=

"http:/\

/netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css"

/></head><body>

<

\
div class="container"><div

 class=

"jumbotron"

><h1>

Yo Pluralsighters!!!</h1><p>

Cl\
ick the button below to head over to my podcast...</p><p>

 <a

 href=

"http://intec\

hwetrustpodcast.com"

 class=

"btn btn-primary"

>

Podcast</a></p><p></p></div></div>

\
</body></html>

```

`-it`标志使`exec`会话变得交互，并将您的终端窗口上的 STDIN 和 STDOUT 连接到 Pod 中第一个容器内的 STDIN 和 STDOUT。当命令完成时，您的 shell 提示符将更改，表示您的 shell 现在已连接到容器。

如果您正在运行多容器 Pods，您将需要传递`kubectl exec`命令`--container`标志，并给出要在其中创建 exec 会话的 Pod 中容器的名称。如果您不指定此标志，该命令将针对 Pod 中的第一个容器执行。您可以使用`kubectl describe pods <pod>`命令查看 Pod 中容器的顺序和名称。

另一个用于内省 Pod 的命令是`kubectl logs`命令。与其他与 Pod 相关的命令一样，如果您没有按名称指定容器，它将针对 Pod 中的第一个容器执行。命令的格式是`kubectl logs <pod>`。

显然，Pods 还有很多内容我们没有涉及到。但是，我们已经学到了足够的知识来开始。

使用以下命令清理您的实验室。

```
$ kubectl delete -f pod.yml
pod "hello-pod"

 deleted

```

### 章节总结

在本章中，我们了解到 Kubernetes 世界中部署的原子单位是*Pod*。每个 Pod 由一个或多个容器组成，并部署到集群中的单个节点。部署操作是一个全有或全无的*原子事务*。

使用 YAML 清单文件以声明方式部署 Pod 是最佳方式。我们使用`kubectl`命令将清单`POST`到 API 服务器，它将存储在集群存储中，并转换为一个 PodSpec，然后被调度到具有足够可用资源的健康集群节点上。

接受 PodSpec 的工作节点上的进程是`kubelet`。这是在集群中每个节点上运行的主要 Kubernetes 代理。它接受 PodSpec 并负责拉取所有镜像并启动 Pod 中的所有容器。

如果 Pod 失败，它不会自动重新调度。因此，我们通常通过更高级别的对象（如部署和守护进程）来部署它们。这些对象添加了诸如自愈和回滚之类的功能，是使 Kubernetes 如此强大的核心。
