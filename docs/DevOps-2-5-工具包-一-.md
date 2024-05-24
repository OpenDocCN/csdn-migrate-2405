# DevOps 2.5 工具包（一）

> 原文：[`zh.annas-archive.org/md5/E695B8200F27D70136CB7C8920C8BCB0`](https://zh.annas-archive.org/md5/E695B8200F27D70136CB7C8920C8BCB0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Kubernetes 可能是我们所知道的最大的项目。它是庞大的，然而许多人认为经过几周或几个月的阅读和实践后，他们就知道了所有关于它的知识。它比这大得多，而且它的增长速度比我们大多数人能够跟上的要快。你在 Kubernetes 采用中走了多远？

根据我的经验，Kubernetes 采用有四个主要阶段。

在第一阶段，我们创建一个集群，并学习 Kube API 的复杂性以及不同类型的资源（例如 Pods，Ingress，Deployments，StatefulSets 等）。一旦我们熟悉了 Kubernetes 的工作方式，我们就开始部署和管理我们的应用程序。在这个阶段结束时，我们可以大喊“**看，我的生产 Kubernetes 集群中有东西在运行，没有出现问题！**”我在《DevOps 2.3 工具包：Kubernetes》中解释了这个阶段的大部分内容（[`amzn.to/2GvzDjy`](https://amzn.to/2GvzDjy)）。

第二阶段通常是自动化。一旦我们熟悉了 Kubernetes 的工作方式，并且我们正在运行生产负载，我们就可以转向自动化。我们经常采用某种形式的持续交付（CD）或持续部署（CDP）。我们使用我们需要的工具创建 Pods，构建我们的软件和容器映像，运行测试，并部署到生产环境。完成后，我们的大部分流程都是自动化的，我们不再手动部署到 Kubernetes。我们可以说**事情正在运行，我甚至没有碰键盘**。我尽力在《DevOps 2.4 工具包：持续部署到 Kubernetes》中提供了一些关于 Kubernetes 的 CD 和 CDP 的见解（[`amzn.to/2NkIiVi`](https://amzn.to/2NkIiVi)）。

第三阶段在许多情况下与监控、警报、日志记录和扩展有关。我们可以在 Kubernetes 中运行（几乎）任何东西，并且它会尽最大努力使其具有容错性和高可用性，但这并不意味着我们的应用程序和集群是防弹的。我们需要监视集群，并且我们需要警报来通知我们可能存在的问题。当我们发现有问题时，我们需要能够查询整个系统的指标和日志。只有当我们知道根本原因是什么时，我们才能解决问题。在像 Kubernetes 这样高度动态的分布式系统中，这并不像看起来那么容易。

此外，我们需要学习如何扩展（和缩减）一切。应用程序的 Pod 数量应随时间变化，以适应流量和需求的波动。节点也应该进行扩展，以满足我们应用程序的需求。

Kubernetes 已经有了提供指标和日志可见性的工具。它允许我们创建自动扩展规则。然而，我们可能会发现单单 Kubernetes 还不够，我们可能需要用额外的流程和工具来扩展我们的系统。这本书的主题就是这个阶段。当你读完它时，你将能够说**你的集群和应用程序真正是动态和有弹性的，并且需要很少的手动干预。我们将努力使我们的系统自适应。**

我提到了第四阶段。亲爱的读者，那就是其他一切。最后阶段主要是关于跟上 Kubernetes 提供的所有其他好东西。这是关于遵循其路线图并调整我们的流程以获得每个新版本的好处。

最终，你可能会遇到困难，需要帮助。或者你可能想对这本书的内容写一篇评论或评论。请加入*DevOps20*（[`slack.devops20toolkit.com/`](http://slack.devops20toolkit.com/)）Slack 工作区，发表你的想法，提出问题，或参与讨论。如果你更喜欢一对一的沟通，你可以使用 Slack 给我发私信，或发送邮件至`viktor@farcic.com`。我写的所有书对我来说都很重要，我希望你在阅读它们时有一个很好的体验。其中一部分体验就是可以联系我。不要害羞。

请注意，这本书和之前的书一样，是我自行出版的。我相信作家和读者之间没有中间人是最好的方式。这样可以让我更快地写作，更频繁地更新书籍，并与你进行更直接的沟通。你的反馈是这个过程的一部分。无论你是在只有少数章节还是所有章节都写完时购买了这本书，我的想法是它永远不会真正完成。随着时间的推移，它将需要更新，以使其与技术或流程的变化保持一致。在可能的情况下，我会尽量保持更新，并在有意义的时候发布更新。最终，事情可能会发生如此大的变化，以至于更新不再是一个好选择，这将是需要一本全新书的迹象。**只要我继续得到你的支持，我就会继续写作。**

# 概述

我们将探讨操作 Kubernetes 集群所需的一些技能和知识。我们将处理一些通常不会在最初阶段学习的主题，而是在我们厌倦了 Kubernetes 的核心功能（如 Pod、ReplicaSets、Deployments、Ingress、PersistentVolumes 等）之后才会涉及。我们将掌握一些我们通常在学会基础知识并自动化所有流程之后才会深入研究的主题。我们将探讨**监控**、**警报**、**日志记录**、**自动扩展**等旨在使我们的集群**具有弹性**、**自给自足**和**自适应**的主题。

# 受众

我假设你对 Kubernetes 很熟悉，不需要解释 Kube API 的工作原理，也不需要解释主节点和工作节点之间的区别，尤其不需要解释像 Pods、Ingress、Deployments、StatefulSets、ServiceAccounts 等资源和构造。如果你不熟悉，这个内容可能太高级了，我建议你先阅读《The DevOps 2.3 Toolkit: Kubernetes》（[`amzn.to/2GvzDjy`](https://amzn.to/2GvzDjy)）。我希望你已经是一个 Kubernetes 忍者学徒，你对如何使你的集群更具弹性、可扩展和自适应感兴趣。如果是这样，这本书就是为你准备的。继续阅读。

# 要求

这本书假设你已经知道如何操作 Kubernetes 集群，因此我们不会详细介绍如何创建一个，也不会探讨 Pods、Deployments、StatefulSets 等常用的 Kubernetes 资源。如果这个假设是不正确的，你可能需要先阅读《The DevOps 2.3 Toolkit: Kubernetes》。

除了基于知识的假设外，还有一些技术要求。如果您是**Windows 用户**，请从**Git Bash**中运行所有示例。这将允许您像 MacOS 和 Linux 用户一样通过他们的终端运行相同的命令。Git Bash 在[Git](https://git-scm.com/download/win)安装过程中设置。如果您还没有它，请重新运行 Git 设置。

由于我们将使用 Kubernetes 集群，我们将需要**kubectl** ([`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/))。我们将在集群内运行的大多数应用程序都将使用**Helm** ([`helm.sh/`](https://helm.sh/))进行安装，因此请确保您也安装了客户端。最后，也安装**jq** ([`stedolan.github.io/jq/`](https://stedolan.github.io/jq/))。这是一个帮助我们格式化和过滤 JSON 输出的工具。

最后，我们将需要一个 Kubernetes 集群。所有示例都是使用**Docker for Desktop**，**minikube**，**Google Kubernetes Engine (GKE)**，**Amazon Elastic Container Service for Kubernetes (EKS)**和**Azure Kubernetes Service (AKS)**进行测试的。我将为每种 Kubernetes 版本提供要求（例如节点数、CPU、内存、Ingress 等）。

您可以将这些教训应用于任何经过测试的 Kubernetes 平台，或者您可以选择使用其他平台。这本书中的示例不应该在任何 Kubernetes 版本中无法运行。您可能需要在某些地方进行微调，但我相信这不会成为问题。

如果遇到任何问题，请通过*DevOps20* ([`slack.devops20toolkit.com/`](http://slack.devops20toolkit.com/)) slack 工作区与我联系，或者通过发送电子邮件至`viktor@farcic.com`。我会尽力帮助解决。如果您使用的是我未测试过的 Kubernetes 集群，请帮助我扩展列表。

在选择 Kubernetes 版本之前，您应该知道并非所有功能都在所有地方都可用。在基于 Docker for Desktop 或 minikube 的本地集群中，由于两者都是单节点集群，将无法扩展节点。其他集群可能也无法使用更多特定功能。我将利用这个机会比较不同的平台，并为您提供额外的见解，如果您正在评估要使用哪个 Kubernetes 发行版以及在哪里托管它，您可能会想要使用。或者，您可以选择在本地集群中运行一些章节，并仅在本地无法运行的部分切换到多节点集群。这样，您可以通过在云中拥有一个短暂的集群来节省一些开支。

如果您不确定要选择哪种 Kubernetes 版本，请选择 GKE。它目前是市场上最先进和功能丰富的托管 Kubernetes。另一方面，如果您已经习惯了 EKS 或 AKS，它们也差不多可以。本书中的大多数，如果不是全部的功能都会起作用。最后，您可能更喜欢在本地运行集群，或者您正在使用不同的（可能是本地）Kubernetes 平台。在这种情况下，您将了解到您所缺少的内容，以及您需要在“标准提供”的基础上构建哪些内容来实现相同的结果。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)上的账户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书名，按照屏幕上的指示操作。

文件下载后，请确保使用以下最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/The-DevOps-2.5-Toolkit`](https://github.com/PacktPublishing)。如果代码有更新，将会在现有的 GitHub 存储库中更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781838647513_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781838647513_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“该定义使用`HorizontalPodAutoscaler`目标为`api`部署。”

代码块设置如下：

```
 1  sum(label_join(
 2      rate(
 3          container_cpu_usage_seconds_total{
 4              namespace!="kube-system",
 5              pod_name!=""
 6          }[5m]
 7      )
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```
 1  sum(label_join(
 2      rate(
 3          container_cpu_usage_seconds_total{
 4              namespace!="kube-system",
 5              pod_name!=""
 6          }[5m]
 7      )
```

任何命令行输入或输出都以以下方式编写：

```
 1  cd k8s-specs
 2
 3  git pull
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“选择 Prometheus，并单击导入按钮。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：根据资源使用自动调整部署和有状态集

变化是所有存在的基本过程。

- *斯波克*

到目前为止，你可能已经了解到，基于 Kubernetes 的系统的一个关键方面是高度的动态性。几乎没有什么是静态的。我们定义部署或有状态集，Kubernetes 会在集群中分发 Pods。在大多数情况下，这些 Pods 很少在一个地方停留很长时间。滚动更新会导致 Pods 被重新创建并可能移动到其他节点。任何类型的故障都会引发受影响资源的重新调度。许多其他事件也会导致 Pods 移动。Kubernetes 集群就像一个蜂巢。它充满了生机，而且总是在运动中。

Kubernetes 集群的动态性不仅是由我们（人类）的行为或由故障引起的重新调度所致。自动缩放也应该受到责备。我们应该充分接受 Kubernetes 的动态性，并朝着能够满足我们应用程序需求的自主和自给的集群发展。为了实现这一点，我们需要提供足够的信息，让 Kubernetes 能够调整应用程序以及构成集群的节点。在本章中，我们将重点关注前一种情况。我们将探讨基于内存和 CPU 消耗的自动缩放 Pods 的常用和基本方法。我们将使用 HorizontalPodAutoscaler 来实现这一点。

HorizontalPodAutoscaler 的唯一功能是自动调整部署、有状态集或其他一些类型资源中 Pods 的数量。它通过观察 Pods 的 CPU 和内存消耗，并在达到预定义阈值时采取行动来实现这一点。

HorizontalPodAutoscaler 被实现为 Kubernetes API 资源和控制器。资源决定了控制器的行为。控制器定期调整有状态集或部署中的副本数量，以匹配用户指定的目标平均 CPU 利用率。

我们很快就会看到 HorizontalPodAutoscaler 的实际应用，并通过实际示例评论其特定功能。但在那之前，我们需要一个 Kubernetes 集群以及一个度量源。

# 创建集群

在创建集群之前（或开始使用您已经可用的集群），我们将克隆 `vfarcic/k8s-specs` ([`github.com/vfarcic/k8s-specs`](https://github.com/vfarcic/k8s-specs)) 存储库，其中包含本书中大部分我们将使用的定义。

给 Windows 用户的说明：请从 Git Bash 中执行本书中的所有命令。这样，您就可以直接运行它们，而不需要修改其语法以适应 Windows 终端或 PowerShell。本章中的所有命令都可以在 `01-hpa.sh` ([`gist.github.com/vfarcic/b46ca2eababb98d967e3e25748740d0d`](https://gist.github.com/vfarcic/b46ca2eababb98d967e3e25748740d0d)) Gist 中找到。

```
 1  git clone https://github.com/vfarcic/k8s-specs.git
 2
 3  cd k8s-specs
```

如果您之前克隆过该存储库，请确保通过执行 `git pull` 来获取最新版本。

以下的代码片段和规范用于测试本章中的命令。请在创建自己的测试集群时以此为灵感，或者验证您计划用于练习的集群是否满足最低要求。

+   `docker-scale.sh`: **Docker for Desktop** with 2 CPUs, 2 GB RAM and with **tiller** ([`gist.github.com/vfarcic/ca52ff97fc80565af0c46c37449babac`](https://gist.github.com/vfarcic/ca52ff97fc80565af0c46c37449babac)).

+   `minikube-scale.sh`: **minikube** with 2 CPUs, 2 GB RAM and with **tiller** ([`gist.github.com/vfarcic/5bc07d822f8825263245829715261a68`](https://gist.github.com/vfarcic/5bc07d822f8825263245829715261a68)).

+   `gke-scale.sh`: **GKE** with 3 n1-standard-1 worker nodes and with **tiller** ([`gist.github.com/vfarcic/9c777487f7ebee6c09027d3a1df8663c`](https://gist.github.com/vfarcic/9c777487f7ebee6c09027d3a1df8663c)).

+   `eks-scale.sh`: **EKS** with 3 t2.small worker nodes and with **tiller** ([`gist.github.com/vfarcic/a94dffef7d6dc60f79570d351c92408d`](https://gist.github.com/vfarcic/a94dffef7d6dc60f79570d351c92408d)).

+   `aks-scale.sh`: **AKS** with 3 Standard_B2s worker nodes and with **tiller** ([`gist.github.com/vfarcic/f1b05d33cc8a98e4ceab3d3770c2fe0b`](https://gist.github.com/vfarcic/f1b05d33cc8a98e4ceab3d3770c2fe0b)).

请注意，我们将使用 Helm 来安装必要的应用程序，但我们将切换到“纯粹”的 Kubernetes YAML 来尝试（可能是新的）本章中使用的资源，并部署演示应用程序。换句话说，我们将使用 Helm 进行一次性安装（例如，Metrics Server），并使用 YAML 来更详细地探索我们将要使用的内容（例如，HorizontalPodAutoscaler）。

现在，让我们来谈谈 Metrics Server。

# 观察 Metrics Server 数据

在扩展 Pods 的关键元素是 Kubernetes Metrics Server。你可能认为自己是 Kubernetes 的高手，但从未听说过 Metrics Server。如果是这种情况，不要感到羞愧。你并不是唯一一个。

如果你开始观察 Kubernetes 的指标，你可能已经使用过 Heapster。它已经存在很长时间了，你可能已经在你的集群中运行它，即使你不知道它是什么。两者都有相同的目的，其中一个已经被弃用了一段时间，所以让我们澄清一下事情。

早期，Kubernetes 引入了 Heapster 作为一种工具，用于为 Kubernetes 启用容器集群监控和性能分析。它从 Kubernetes 版本 1.0.6 开始存在。你可以说 Heapster 从 Kubernetes 的幼年时代就开始了。它收集和解释各种指标，如资源使用情况、事件等。Heapster 一直是 Kubernetes 的一个重要组成部分，并使其能够适当地调度 Pods。没有它，Kubernetes 将是盲目的。它不会知道哪个节点有可用内存，哪个 Pod 使用了太多的 CPU 等等。但是，就像大多数其他早期可用的工具一样，它的设计是一个“失败的实验”。

随着 Kubernetes 的持续增长，我们（Kubernetes 周围的社区）开始意识到需要一个新的、更好的、更重要的是更具可扩展性的设计。因此，Metrics Server 诞生了。现在，尽管 Heapster 仍在使用中，但它被视为已弃用，即使在今天（2018 年 9 月），Metrics Server 仍处于测试阶段。

那么，Metrics Server 是什么？一个简单的解释是，它收集有关节点和 Pod 使用的资源（内存和 CPU）的信息。它不存储指标，所以不要认为您可以使用它来检索历史值和预测趋势。有其他工具可以做到这一点，我们稍后会探讨它们。相反，Metrics Server 的目标是提供一个 API，可以用来检索当前的资源使用情况。我们可以通过`kubectl`或通过发送直接请求，比如`curl`来使用该 API。换句话说，Metrics Server 收集集群范围的指标，并允许我们通过其 API 检索这些指标。这本身就非常强大，但这只是故事的一部分。

我已经提到了可扩展性。我们可以扩展 Metrics Server 以从其他来源收集指标。我们会在适当的时候到达那里。现在，我们将探索它提供的开箱即用功能，以及它如何与一些其他 Kubernetes 资源交互，这些资源将帮助我们使我们的 Pods 可伸缩和更具弹性。

如果您读过我的其他书，您就会知道我不会过多涉及理论，而是更喜欢通过实际示例来演示功能和原则。这本书也不例外，我们将直接深入了解 Metrics Server 的实际练习。第一步是安装它。

Helm 使安装几乎任何公开可用的软件变得非常容易，如果有 Chart 可用的话。如果没有，您可能需要考虑另一种选择，因为这清楚地表明供应商或社区不相信 Kubernetes。或者，也许他们没有必要开发 Chart 的技能。无论哪种方式，最好的做法是远离它并采用另一种选择。如果这不是一个选择，那就自己开发一个 Helm Chart。在我们的情况下，不需要这样的措施。Metrics Server 确实有一个 Helm Chart，我们需要做的就是安装它。

GKE 和 AKS 用户请注意，Google 和 Microsoft 已经将 Metrics Server 作为其托管的 Kubernetes 集群（GKE 和 AKS）的一部分进行了打包。无需安装它，请跳过接下来的命令。对于 minikube 用户，请注意，Metrics Server 作为插件之一可用。请执行`minikube addons enable metrics-server`和`kubectl -n kube-system rollout status deployment metrics-server`命令，而不是接下来的命令。对于 Docker for Desktop 用户，请注意，Metrics Server 的最新更新默认情况下不适用于自签名证书。由于 Docker for Desktop 使用这样的证书，您需要允许不安全的 TLS。请在接下来的`helm install`命令中添加`--set args={"--kubelet-insecure-tls=true"}`参数。

```
 1  helm install stable/metrics-server \
 2      --name metrics-server \
 3      --version 2.0.2 \
 4      --namespace metrics
 5
 6  kubectl -n metrics \
 7      rollout status \
 8      deployment metrics-server
```

我们使用 Helm 安装了 Metrics Server，并等待直到它部署完成。

Metrics Server 将定期从运行在节点上的 Kubeletes 中获取指标。目前，这些指标包括 Pod 和节点的内存和 CPU 利用率。其他实体可以通过具有 Master Metrics API 的 API 服务器从 Metrics Server 请求数据。这些实体的一个例子是调度程序，一旦安装了 Metrics Server，就会使用其数据来做出决策。

很快您将会看到，Metrics Server 的使用超出了调度程序，但是目前，这个解释应该提供了一个基本数据流的图像。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/b3d2c07d-2505-4373-ae4c-181a83afb8c0.png)图 1-1：数据流向和从 Metrics Server 获取数据的基本流程（箭头显示数据流向）

现在我们可以探索一种检索指标的方式。我们将从与节点相关的指标开始。

```
 1  kubectl top nodes
```

如果您很快，输出应该会声明“尚未提供指标”。这是正常的。在执行第一次迭代的指标检索之前需要几分钟时间。例外情况是 GKE 和 AKS，它们已经预先安装了 Metrics Server。

在重复命令之前先去冲杯咖啡。

```
 1  kubectl top nodes
```

这次，输出是不同的。

在本章中，我将展示来自 Docker for Desktop 的输出。根据您使用的 Kubernetes 版本不同，您的输出也会有所不同。但是，逻辑是相同的，您不应该有问题跟随操作。

我的输出如下。

```
NAME               CPU(cores) CPU% MEMORY(bytes) MEMORY%
docker-for-desktop 248m       12%  1208Mi        63%
```

我们可以看到我有一个名为`docker-for-desktop`的节点。它正在使用 248 CPU 毫秒。由于节点有两个核心，这占总可用 CPU 的 12%。同样，使用了 1.2GB 的 RAM，这占总可用内存 2GB 的 63%。

节点的资源使用情况很有用，但不是我们要寻找的内容。在本章中，我们专注于 Pod 的自动扩展。但是，在我们开始之前，我们应该观察一下我们的每个 Pod 使用了多少内存。我们将从在`kube-system`命名空间中运行的 Pod 开始。

```
 1  kubectl -n kube-system top pod
```

输出（在 Docker for Desktop 上）如下。

```
NAME                                       CPU(cores) MEMORY(bytes)
etcd-docker-for-desktop                    16m        74Mi
kube-apiserver-docker-for-desktop          33m        427Mi
kube-controller-manager-docker-for-desktop 44m        63Mi
kube-dns-86f4d74b45-c47nh                  1m         39Mi
kube-proxy-r56kd                           2m         22Mi
kube-scheduler-docker-for-desktop          13m        23Mi
tiller-deploy-5c688d5f9b-2pspz             0m         21Mi

```

我们可以看到`kube-system`中当前运行的每个 Pod 的资源使用情况（CPU 和内存）。如果我们找不到更好的工具，我们可以使用该信息来调整这些 Pod 的`requests`以使其更准确。但是，有更好的方法来获取这些信息，所以我们将暂时跳过调整。相反，让我们尝试获取所有 Pod 的当前资源使用情况，无论命名空间如何。

```
 1  kubectl top pods --all-namespaces
```

输出（在 Docker for Desktop 上）如下。

```
NAMESPACE   NAME                                       CPU(cores) MEMORY(bytes) 
docker      compose-7447646cf5-wqbwz                   0m         11Mi 
docker      compose-api-6fbc44c575-gwhxt               0m         14Mi 
kube-system etcd-docker-for-desktop                    16m        74Mi 
kube-system kube-apiserver-docker-for-desktop          33m        427Mi 
kube-system kube-controller-manager-docker-for-desktop 46m        63Mi 
kube-system kube-dns-86f4d74b45-c47nh                  1m         38Mi 
kube-system kube-proxy-r56kd                           3m         22Mi 
kube-system kube-scheduler-docker-for-desktop          14m        23Mi 
kube-system tiller-deploy-5c688d5f9b-2pspz             0m         21Mi 
metrics     metrics-server-5d78586d76-pbqj8            0m         10Mi 
```

该输出显示与上一个输出相同的信息，只是扩展到所有命名空间。不需要对其进行评论。

通常，Pod 的度量不够精细，我们需要观察构成 Pod 的每个容器的资源。要获取容器度量，我们只需要添加`--containers`参数。

```
 1  kubectl top pods \
 2    --all-namespaces \
 3    --containers
```

输出（在 Docker for Desktop 上）如下。

```
NAMESPACE   POD                                        NAME                 CPU(cores) MEMORY(bytes) 
docker      compose-7447646cf5-wqbwz                   compose                 0m         11Mi 
docker      compose-api-6fbc44c575-gwhxt               compose                 0m         14Mi 
kube-system etcd-docker-for-desktop                    etcd                    16m        74Mi 
kube-system kube-apiserver-docker-for-desktop          kube-apiserver          33m        427Mi 
kube-system kube-controller-manager-docker-for-desktop kube-controller-manager 46m        63Mi 
kube-system kube-dns-86f4d74b45-c47nh                  kubedns                 0m         13Mi 
kube-system kube-dns-86f4d74b45-c47nh                  dnsmasq                 0m         10Mi 
kube-system kube-dns-86f4d74b45-c47nh                  sidecar                 1m         14Mi 
kube-system kube-proxy-r56kd                           kube-proxy              3m         22Mi 
kube-system kube-scheduler-docker-for-desktop          kube-scheduler          14m        23Mi 
kube-system tiller-deploy-5c688d5f9b-2pspz             tiller                  0m         21Mi 
metrics     metrics-server-5d78586d76-pbqj8            metrics-server          0m         10Mi 
```

我们可以看到，这次输出显示了每个容器。例如，我们可以观察到`kube-dns-*` Pod 的度量分为三个容器（`kubedns`，`dnsmasq`，`sidecar`）。

当我们通过`kubectl top`请求指标时，数据流几乎与调度程序发出请求时的流程相同。请求被发送到 API 服务器（主度量 API），该服务器从度量服务器获取数据，而度量服务器又从集群节点上运行的 Kubeletes 收集信息。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/e5faabe0-8a82-4b4a-b2b3-7e8298f6dc0a.png)图 1-2：数据流向和从度量服务器流向的方向（箭头显示数据流向）

虽然 `kubectl top` 命令对观察当前指标很有用，但如果我们想从其他工具访问它们，它就没什么用了。毕竟，我们的目标不是坐在终端前用 `watch "kubectl top pods"` 命令。那将是浪费我们（人类）的才能。相反，我们的目标应该是从其他工具中抓取这些指标，并根据实时和历史数据创建警报和（也许）仪表板。为此，我们需要以 JSON 或其他机器可解析的格式输出。幸运的是，`kubectl` 允许我们以原始格式直接调用其 API，并检索与工具查询相同的结果。

```
 1  kubectl get \
 2      --raw "/apis/metrics.k8s.io/v1beta1" \
 3      | jq '.'
```

输出如下。

```
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "metrics.k8s.io/v1beta1",
  "resources": [
    {
      "name": "nodes",
      "singularName": "",
      "namespaced": false,
      "kind": "NodeMetrics",
      "verbs": [
        "get",
        "list"
      ]
    },
    {
      "name": "pods",
      "singularName": "",
      "namespaced": true,
      "kind": "PodMetrics",
      "verbs": [
        "get",
        "list"
      ]
    }
  ]
}
```

我们可以看到 `/apis/metrics.k8s.io/v1beta1` 端点是一个索引 API，有两个资源（`nodes` 和 `pods`）。

让我们更仔细地看一下度量 API 的 `pods` 资源。

```
 1  kubectl get \
 2      --raw "/apis/metrics.k8s.io/v1beta1/pods" \
 3      | jq '.'
```

输出太大，无法在一本书中呈现，所以我会留给你去探索。你会注意到输出是通过 `kubectl top pods --all-namespaces --containers` 命令观察到的 JSON 等效物。

这是度量服务器的快速概述。有两件重要的事情需要注意。首先，它提供了集群内运行的容器的当前（或短期）内存和 CPU 利用率。第二个更重要的注意事项是我们不会直接使用它。度量服务器不是为人类设计的，而是为机器设计的。我们以后会到那里。现在，记住有一个叫做度量服务器的东西，你不应该直接使用它（一旦你采用了一个会抓取其度量的工具）。

现在我们已经探索了度量服务器，我们将尝试充分利用它，并学习如何根据资源利用率自动扩展我们的 Pods。

# 根据资源利用率自动扩展 Pods

我们的目标是部署一个应用程序，根据其资源使用情况自动扩展（或缩小）。我们将首先部署一个应用程序，然后讨论如何实现自动扩展。

我已经警告过您，我假设您熟悉 Kubernetes，并且在本书中我们将探讨监控，警报，扩展和其他一些特定主题。我们不会讨论 Pods，StatefulSets，Deployments，Services，Ingress 和其他“基本”Kubernetes 资源。这是您承认您不了解 Kubernetes 基础知识的最后机会，退一步，并阅读*The DevOps 2.3 Toolkit: Kubernetes* ([`www.devopstoolkitseries.com/posts/devops-23/`](https://www.devopstoolkitseries.com/posts/devops-23/))和*The DevOps 2.4 Toolkit: Continuous Deployment To Kubernetes* ([`www.devopstoolkitseries.com/posts/devops-24/`](https://www.devopstoolkitseries.com/posts/devops-24/)*)*。

让我们看一下我们示例中将使用的应用程序的定义。

```
 1  cat scaling/go-demo-5-no-sidecar-mem.yml
```

如果您熟悉 Kubernetes，YAML 定义应该是不言自明的。我们只会评论与自动扩展相关的部分。

输出，仅限于相关部分，如下。

```
...
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: go-demo-5
spec:
  ...
  template:
    ...
    spec:
      ...
      containers:
      - name: db
        ...
        resources:
          limits:
            memory: "150Mi"
            cpu: 0.2
          requests:
            memory: "100Mi"
            cpu: 0.1
        ...
      - name: db-sidecar
    ... 
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: go-demo-5
spec:
  ...
  template:
    ...
    spec:
      containers:
      - name: api
        ...
        resources:
          limits:
            memory: 15Mi
            cpu: 0.1
          requests:
            memory: 10Mi
            cpu: 0.01
...
```

我们有两个形成应用程序的 Pod。 `api`部署是一个后端 API，使用`db` StatefulSet 来保存其状态。

定义的基本部分是“资源”。 `api`和`db`都为内存和 CPU 定义了“请求”和“限制”。数据库使用一个 sidecar 容器，将 MongoDB 副本加入到副本集中。请注意，与其他容器不同，sidecar 没有“资源”。这背后的重要性将在稍后揭示。现在，只需记住两个容器有定义的“请求”和“限制”，而另一个没有。

现在，让我们创建这些资源。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-no-sidecar-mem.yml \
 3      --record
```

输出应该显示已创建了相当多的资源，我们的下一步是等待`api`部署推出，从而确认应用程序正在运行。

```
 1  kubectl -n go-demo-5 \
 2      rollout status \
 3      deployment api
```

几分钟后，您应该会看到消息，指出“api”部署成功推出。

为了安全起见，我们将列出`go-demo-5`命名空间中的 Pod，并确认每个 Pod 都在运行一个副本。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        1m
db-0    2/2   Running 0        1m
```

到目前为止，我们还没有做任何超出 StatefulSet 和 Deployment 的普通创建。

他们又创建了 ReplicaSets，这导致了 Pod 的创建。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/ed5f3b30-98d3-4735-b3f4-7a4a79755f72.png)图 1-3：StatefulSet 和 Deployment 的创建

希望你知道，我们应该至少有每个 Pod 的两个副本，只要它们是可扩展的。然而，这两者都没有定义`replicas`。这是有意的。我们可以指定部署或 StatefulSet 的副本数量，并不意味着我们应该这样做。至少，不总是。

如果副本数量是静态的，并且你没有打算随时间扩展（或缩减）你的应用程序，那么将`replicas`作为部署或 StatefulSet 定义的一部分。另一方面，如果你计划根据内存、CPU 或其他指标更改副本数量，请改用 HorizontalPodAutoscaler 资源。

让我们来看一个 HorizontalPodAutoscaler 的简单示例。

```
 1  cat scaling/go-demo-5-api-hpa.yml
```

输出如下。

```
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: api
  namespace: go-demo-5
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 2
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      targetAverageUtilization: 80
  - type: Resource
    resource:
      name: memory
      targetAverageUtilization: 80
```

定义使用`HorizontalPodAutoscaler`来定位`api`部署。它的边界是最少两个和最多五个副本。这些限制是基本的。没有这些限制，我们会面临无限扩展或缩减到零副本的风险。`minReplicas`和`maxReplicas`字段是一个安全网。

定义的关键部分是`metrics`。它提供了 Kubernetes 应该使用的公式来决定是否应该扩展（或缩减）资源。在我们的例子中，我们使用`Resource`类型的条目。它们针对内存和 CPU 的平均利用率为 80％。如果两者中的任何一个实际使用情况偏离，Kubernetes 将扩展（或缩减）资源。

请注意，我们使用了 API 的`v2beta1`版本，你可能想知道为什么我们选择了这个版本，而不是稳定且适用于生产的`v1`。毕竟，`beta1`版本仍远未经过充分打磨以供一般使用。原因很简单。HorizontalPodAutoscaler `v1`太基础了。它只允许基于 CPU 进行扩展。即使我们的简单示例也超越了这一点，通过将内存加入其中。以后，我们将进一步扩展它。因此，虽然`v1`被认为是稳定的，但它并没有提供太多价值，我们可以等待`v2`发布，或者立即开始尝试`v2beta`版本。我们选择了后者。当你阅读这篇文章时，更稳定的版本可能已经存在并且在你的 Kubernetes 集群中得到支持。如果是这种情况，请随时在应用定义之前更改`apiVersion`。

现在让我们应用它。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-api-hpa.yml \
 3      --record
```

我们应用了创建**HorizontalPodAutoscaler**（**HPA**）的定义。接下来，我们将查看检索 HPA 资源时获得的信息。

```
 1  kubectl -n go-demo-5 get hpa
```

如果你很快，输出应该类似于以下内容。

```
NAME REFERENCE      TARGETS                      MINPODS MAXPODS REPLICAS AGE
api  Deployment/api <unknown>/80%, <unknown>/80% 2       5       0        20s

```

我们可以看到，Kubernetes 尚未具有实际的 CPU 和内存利用率，而是输出了`<unknown>`。在从 Metrics Server 收集下一次数据之前，我们需要再给它一些时间。在我们重复相同的查询之前，先喝杯咖啡。

```
 1  kubectl -n go-demo-5 get hpa
```

这次，输出中没有未知项。

```
NAME REFERENCE      TARGETS          MINPODS MAXPODS REPLICAS AGE
api  Deployment/api 38%/80%, 10%/80% 2       5       2        1m

```

我们可以看到，CPU 和内存利用率远低于预期的`80%`利用率。尽管如此，Kubernetes 将副本数从一个增加到两个，因为这是我们定义的最小值。我们签订了合同，规定`api` Deployment 的副本数永远不得少于两个，即使资源利用率远低于预期的平均利用率，Kubernetes 也会遵守这一点进行扩展。我们可以通过 HorizontalPodAutoscaler 的事件来确认这种行为。

```
 1  kubectl -n go-demo-5 describe hpa api
```

输出，仅限于事件消息，如下所示。

```
...
Events:
... Message
... -------
... New size: 2; reason: Current number of replicas below Spec.MinReplicas
```

事件的消息应该是不言自明的。HorizontalPodAutoscaler 将副本数更改为`2`，因为当前数量（1）低于`MinReplicas`值。

最后，我们将列出 Pods，以确认所需数量的副本确实正在运行。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        2m
api-... 1/1   Running 0        6m
db-0    2/2   Running 0        6m
```

到目前为止，HPA 尚未根据资源使用情况执行自动缩放。相反，它只增加了 Pod 的数量以满足指定的最小值。它通过操纵 Deployment 来实现这一点。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c9a6db6e-d3a9-485e-a687-b92b0629e19e.png)图 1-4：根据 HPA 中指定的最小副本数进行部署的扩展

接下来，我们将尝试创建另一个 HorizontalPodAutoscaler，但这次，我们将以运行我们的 MongoDB 的 StatefulSet 为目标。因此，让我们再看一下另一个 YAML 定义。

```
 1  cat scaling/go-demo-5-db-hpa.yml
```

输出如下。

```
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: db
  namespace: go-demo-5
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: StatefulSet
    name: db
  minReplicas: 3
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      targetAverageUtilization: 80
  - type: Resource
    resource:
      name: memory
      targetAverageUtilization: 80
```

该定义几乎与我们之前使用的定义相同。唯一的区别是，这次我们的目标是名为`db`的`StatefulSet`，并且最小副本数应为`3`。

让我们应用它。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-db-hpa.yml \
 3      --record
```

让我们再看一下 HorizontalPodAutoscaler 资源。

```
 1  kubectl -n go-demo-5 get hpa
```

输出如下。

```
NAME REFERENCE      TARGETS                      MINPODS MAXPODS REPLICAS AGE
api  Deployment/api 41%/80%, 0%/80%              2       5       2        5m
db   StatefulSet/db <unknown>/80%, <unknown>/80% 3       5       0        20s
```

我们可以看到第二个 HPA 已经创建，并且当前利用率为“未知”。这一定是之前的类似情况。我们应该给它一些时间让数据开始流动吗？等待片刻，然后再次检索 HPA。目标仍然是“未知”吗？

资源利用持续未知可能有问题。让我们描述新创建的 HPA，看看是否能找到问题的原因。

```
 1  kubectl -n go-demo-5 describe hpa db
```

输出，仅限于事件消息，如下所示。

```
...
Events:
... Message
... -------
... New size: 3; reason: Current number of replicas below Spec.MinReplicas
... missing request for memory on container db-sidecar in pod go-demo-5/db-0
... failed to get memory utilization: missing request for memory on container db-sidecar in pod go-demo-5/db-0

```

请注意，您的输出可能只有一个事件，甚至没有这些事件。如果是这种情况，请等待几分钟，然后重复上一个命令。

如果我们关注第一条消息，我们可以看到它开始得很好。HPA 检测到当前副本数低于限制，并将它们增加到了三个。这是预期的行为，所以让我们转向其他两条消息。

HPA 无法计算百分比，因为我们没有指定`db-sidecar`容器请求多少内存。没有`requests`，HPA 无法计算实际内存使用的百分比。换句话说，我们忽略了为`db-sidecar`容器指定资源，HPA 无法完成其工作。我们将通过应用`go-demo-5-no-hpa.yml`来解决这个问题。

让我们快速看一下新定义。

```
 1  cat scaling/go-demo-5-no-hpa.yml
```

输出，仅限于相关部分，如下所示。

```
...
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: go-demo-5
spec:
  ...
  template:
    ...
    spec:
      ...
      - name: db-sidecar
        ...
        resources:
          limits:
            memory: "100Mi"
            cpu: 0.2
          requests:
            memory: "50Mi"
            cpu: 0.1
...
```

与初始定义相比，唯一显着的区别是这次我们为`db-sidecar`容器定义了资源。让我们应用它。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-no-hpa.yml \
 3      --record
```

接下来，我们将等待片刻以使更改生效，然后再次检索 HPA。

```
 1  kubectl -n go-demo-5 get hpa
```

这一次，输出更有希望。

```
NAME REFERENCE      TARGETS          MINPODS MAXPODS REPLICAS AGE
api  Deployment/api 66%/80%, 10%/80% 2       5       2        16m
db   StatefulSet/db 60%/80%, 4%/80%  3       5       3        10m
```

两个 HPA 都显示了当前和目标资源使用情况。都没有达到目标值，所以 HPA 保持了最小副本数。我们可以通过列出`go-demo-5`命名空间中的所有 Pod 来确认这一点。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        42m
api-... 1/1   Running 0        46m
db-0    2/2   Running 0        33m
db-1    2/2   Running 0        33m
db-2    2/2   Running 0        33m
```

我们可以看到`api`部署有两个 Pod，而`db` StatefulSet 有三个副本。这些数字等同于 HPA 定义中的`spec.minReplicas`条目。

让我们看看当实际内存使用量高于目标值时会发生什么。

我们将通过降低其中一个 HPA 的目标来修改其定义，以重现我们的 Pod 消耗资源超出预期的情况。

让我们看一下修改后的 HPA 定义。

```
 1  cat scaling/go-demo-5-api-hpa-low-mem.yml
```

输出，仅限于相关部分，如下所示。

```
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: api
  namespace: go-demo-5
spec:
  ...
  metrics:
  ...
  - type: Resource
    resource:
      name: memory
      targetAverageUtilization: 10
```

我们将`targetAverageUtilization`减少到`10`。这肯定低于当前的内存利用率，我们将能够见证 HPA 的工作。让我们应用新的定义。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-api-hpa-low-mem.yml \
 3      --record
```

请等待一段时间，以便进行下一次数据收集迭代，并检索 HPAs。

```
 1  kubectl -n go-demo-5 get hpa
```

输出如下。

```
NAME REFERENCE      TARGETS          MINPODS MAXPODS REPLICAS AGE
api  Deployment/api 49%/10%, 10%/80% 2       5       2        44m
db   StatefulSet/db 64%/80%, 5%/80%  3       5       3        39m
```

我们可以看到`api` HPA 的实际内存（`49%`）远远超过了阈值（`10%`）。然而，副本的数量仍然是相同的（`2`）。我们需要等待几分钟，然后再次检索 HPAs。

```
 1  kubectl -n go-demo-5 get hpa
```

这次，输出略有不同。

```
NAME REFERENCE      TARGETS          MINPODS MAXPODS REPLICAS AGE
api  Deployment/api 49%/10%, 10%/80% 2       5       4        44m
db   StatefulSet/db 64%/80%, 5%/80%  3       5       3        39m
```

我们可以看到副本数量增加到`4`。HPA 改变了部署，导致了级联效应，从而增加了 Pod 的数量。

让我们描述一下`api` HPA。

```
 1  kubectl -n go-demo-5 describe hpa api
```

输出，仅限于事件消息，如下所示。

```
...
Events:
... Message
... -------
... New size: 2; reason: Current number of replicas below Spec.MinReplicas
... New size: 4; reason: memory resource utilization (percentage of request) above target
```

我们可以看到 HPA 将大小更改为`4`，因为`内存资源利用率（请求百分比）`高于目标。

由于在这种情况下，增加副本数量并没有将内存消耗降低到 HPA 目标以下，我们应该期望 HPA 将继续扩展部署，直到达到`5`的限制。我们将通过等待几分钟并再次描述 HPA 来确认这一假设。

```
 1  kubectl -n go-demo-5 describe hpa api
```

输出，仅限于事件消息，如下所示。

```
...
Events:
... Message
... -------
... New size: 2; reason: Current number of replicas below Spec.MinReplicas
... New size: 4; reason: memory resource utilization (percentage of request) above target
... New size: 5; reason: memory resource utilization (percentage of request) above target
```

我们收到了消息，说明新的大小现在是`5`，从而证明 HPA 将继续扩展，直到资源低于目标，或者在我们的情况下，达到最大副本数量。

我们可以通过列出`go-demo-5`命名空间中的所有 Pod 来确认扩展确实起作用。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        47m
api-... 1/1   Running 0        51m
api-... 1/1   Running 0        4m
api-... 1/1   Running 0        4m
api-... 1/1   Running 0        24s
db-0    2/2   Running 0        38m
db-1    2/2   Running 0        38m
db-2    2/2   Running 0        38m
```

正如我们所看到的，`api`部署确实有五个副本。

HPA 从 Metrics Server 中检索数据，得出实际资源使用量高于阈值，并使用新的副本数量操纵了部署。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/1176f620-4e31-44e3-8eb0-5c8a4ef9b2e6.png)图 1-5：HPA 通过操纵部署进行扩展

接下来，我们将验证缩减副本数量也能正常工作。我们将重新应用初始定义，其中内存和 CPU 都设置为百分之八十。由于实际内存使用量低于该值，HPA 应该开始缩减，直到达到最小副本数量。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-api-hpa.yml \
 3      --record
```

与之前一样，我们将等待几分钟，然后再描述 HPA。

```
 1  kubectl -n go-demo-5 describe hpa api
```

输出，仅限于事件消息，如下所示。

```
...
Events:
... Message
... -------
... New size: 2; reason: Current number of replicas below Spec.MinReplicas
... New size: 4; reason: memory resource utilization (percentage of request) above target
... New size: 5; reason: memory resource utilization (percentage of request) above target
... New size: 3; reason: All metrics below target
```

正如我们所看到的，它将大小更改为`3`，因为所有的`metrics`都`below target`。

一段时间后，它会再次缩减到两个副本，并停止，因为这是我们在 HPA 定义中设置的限制。

# 在部署和有状态集中使用副本还是不使用副本？

知道 HorizontalPodAutoscaler（HPA）管理我们应用程序的自动扩展，可能会产生关于副本的问题。我们应该在我们的部署和有状态集中定义它们，还是应该完全依赖 HPA 来管理它们？我们不直接回答这个问题，而是探讨不同的组合，并根据结果定义策略。

首先，让我们看看我们集群中有多少个 Pods。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        27m
api-... 1/1   Running 2        31m
db-0    2/2   Running 0        20m
db-1    2/2   Running 0        20m
db-2    2/2   Running 0        21m
```

我们可以看到`api`部署有两个副本，`db`有三个有状态集的副本。

假设我们想要发布一个新版本的`go-demo-5`应用程序。我们将使用的定义如下。

```
 1  cat scaling/go-demo-5-replicas-10.yml
```

输出，仅限于相关部分，如下所示。

```
...
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: go-demo-5
spec:
  replicas: 10
... 
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: api
  namespace: go-demo-5
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 2
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      targetAverageUtilization: 80
  - type: Resource
    resource:
      name: memory
      targetAverageUtilization: 80
```

需要注意的重要事情是我们的`api`部署有`10`个副本，并且我们有 HPA。其他一切都和以前一样。

如果我们应用了那个定义会发生什么？

```
 1  kubectl apply \
 2    -f scaling/go-demo-5-replicas-10.yml
 3
 4  kubectl -n go-demo-5 get pods
```

我们应用了新的定义，并从`go-demo-5`命名空间中检索了所有的 Pods。后一条命令的输出如下。

```
NAME    READY STATUS            RESTARTS AGE
api-... 1/1   Running           0        9s
api-... 0/1   ContainerCreating 0        9s
api-... 0/1   ContainerCreating 0        9s
api-... 1/1   Running           2        41m
api-... 1/1   Running           0        22s
api-... 0/1   ContainerCreating 0        9s
api-... 0/1   ContainerCreating 0        9s
api-... 1/1   Running           0        9s
api-... 1/1   Running           0        9s
api-... 1/1   Running           0        9s
db-0    2/2   Running           0        31m
db-1    2/2   Running           0        31m
db-2    2/2   Running           0        31m
```

Kubernetes 遵循我们希望有十个`api`副本的要求，并创建了八个 Pods（之前我们有两个）。乍一看，HPA 似乎没有任何效果。让我们再次检索 Pods。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        30s
api-... 1/1   Running 2        42m
api-... 1/1   Running 0        43s
api-... 1/1   Running 0        30s
api-... 1/1   Running 0        30s
db-0    2/2   Running 0        31m
db-1    2/2   Running 0        32m
db-2    2/2   Running 0        32m
```

我们的部署从十个缩减到了五个副本。HPA 检测到副本超过了最大阈值，并相应地采取了行动。但它做了什么？它只是简单地移除了五个副本吗？那不可能，因为那只会有暂时的效果。如果 HPA 移除或添加 Pods，部署也会移除或添加 Pods，两者将互相对抗。Pods 的数量将无限波动。相反，HPA 修改了部署。

让我们描述一下`api`。

```
 1  kubectl -n go-demo-5 \
 2    describe deployment api
```

输出，仅限于相关部分，如下所示。

```
...
Replicas: 5 desired | 5 updated | 5 total | 5 available | 0 unavailable
...
Events:
... Message
... -------
...
... Scaled up replica set api-5bbfd85577 to 10
... Scaled down replica set api-5bbfd85577 to 5
```

副本的数量设置为`5 desired`。HPA 修改了我们的部署。我们可以通过事件消息更好地观察到这一点。倒数第二条消息表明副本的数量被扩展到`10`，而最后一条消息表明它被缩减到`5`。前者是我们通过应用新的部署来执行滚动更新的结果，而后者是由 HPA 修改部署并改变其副本数量产生的。

到目前为止，我们观察到 HPA 修改了我们的部署。无论我们在部署（或 StatefulSets）中定义了多少副本，HPA 都会更改它以适应自己的阈值和计算。换句话说，当我们更新部署时，副本的数量将暂时更改为我们定义的任何内容，然后在几分钟后再次被 HPA 修改。这种行为是不可接受的。

如果 HPA 更改了副本的数量，通常会有很好的理由。将该数字重置为部署（或 StatetifulSet）中设置的任何数字可能会产生严重的副作用。

假设我们在部署中定义了三个副本，并且 HPA 将其扩展到三十个，因为该应用程序的负载增加了。如果我们`apply`部署，因为我们想要推出一个新的版本，那么在短暂的时间内，将会有三个副本，而不是三十个。

因此，我们的用户可能会在我们的应用程序中经历较慢的响应时间，或者由于太少的副本提供了太多的流量而导致其他影响。我们必须努力避免这种情况。副本的数量应始终由 HPA 控制。这意味着我们需要改变我们的策略。

如果在部署中指定副本的数量没有产生我们想要的效果，我们可能会干脆将它们全部删除。让我们看看在这种情况下会发生什么。

我们将使用`go-demo-5.yml`的定义，让我们看看它与我们之前使用的`go-demo-5-replicas-10.yml`有何不同。

```
 1  diff \
 2    scaling/go-demo-5-replicas-10.yml \
 3    scaling/go-demo-5.yml
```

输出显示的唯一区别是，这一次，我们没有指定副本的数量。

让我们应用这个变化，看看会发生什么。

```
 1  kubectl apply \
 2    -f scaling/go-demo-5.yml
 3
 4  kubectl -n go-demo-5 \
 5    describe deployment api
```

后一条命令的输出，仅限于相关部分，如下所示。

```
...
Replicas: 1 desired | 5 updated | 5 total | 5 available | 0 unavailable
...
Events:
... Message
... -------
...
... Scaled down replica set api-5bbfd85577 to 5
... Scaled down replica set api-5bbfd85577 to 1
```

应用部署而没有`副本`导致`1 desired`。当然，HPA 很快会将其扩展到`2`（其最小值），但我们仍然未能实现我们的使命，即始终保持 HPA 定义的副本数量。

我们还能做什么？无论我们是使用`副本`定义还是不使用`副本`定义我们的部署，结果都是一样的。应用部署总是会取消 HPA 的效果，即使我们没有指定`副本`。

实际上，这个说法是不正确的。如果我们知道整个过程是如何工作的，我们可以实现期望的行为而不需要`副本`。

如果为部署定义了`副本`，那么每次我们`应用`一个定义时都会使用它。如果我们通过删除`副本`来更改定义，部署将认为我们想要一个副本，而不是之前的副本数量。但是，如果我们从未指定`副本`的数量，它们将完全由 HPA 控制。

让我们来测试一下。

```
 1  kubectl delete -f scaling/go-demo-5.yml
```

我们删除了与`go-demo-5`应用程序相关的所有内容。现在，让我们测试一下，如果从一开始就没有定义`副本`，部署会如何行为。

```
 1  kubectl apply \
 2    -f scaling/go-demo-5.yml
 3
 4  kubectl -n go-demo-5 \
 5    describe deployment api
```

后一条命令的输出，仅限于相关部分，如下所示。

```
...
Replicas: 1 desired | 1 updated | 1 total | 0 available | 1 unavailable
...
```

看起来我们失败了。部署确实将副本的数量设置为`1`。但是，您看不到的是副本在内部没有定义。

然而，几分钟后，我们的部署将被 HPA 扩展到两个副本。这是预期的行为，但我们将确认一下。

```
 1  kubectl -n go-demo-5 \
 2    describe deployment api
```

您应该从输出中看到副本的数量已经被（由 HPA）更改为`2`。

现在是最终测试。如果我们发布一个新版本的部署，它会缩减到`1`个副本，还是会保持在`2`个副本？

我们将应用一个新的定义。与当前运行的定义相比，唯一的区别在于镜像的标签。这样我们将确保部署确实被更新。

```
 1  kubectl apply \
 2    -f scaling/go-demo-5-2-5.yml
 3
 4  kubectl -n go-demo-5 \
 5    describe deployment api
```

后一条命令的输出，仅限于相关部分，如下所示。

```
...
Replicas: 2 desired | 1 updated | 3 total | 2 available | 1 unavailable
...
Events:
... Message
... -------
... Scaled up replica set api-5bbfd85577 to 1
... Scaled up replica set api-5bbfd85577 to 2
... Scaled up replica set api-745bc9fc6d to 1
```

我们可以看到，由 HPA 设置的副本数量得到了保留。

如果您在“事件”中看到副本的数量被缩减为`1`，不要惊慌。那是部署启动的第二个 ReplicaSet。您可以通过观察 ReplicaSet 的名称来看到这一点。部署正在通过搅动两个 ReplicaSet 来进行滚动更新，以尝试在没有停机时间的情况下推出新版本。这与自动扩展无关，我假设您已经知道滚动更新是如何工作的。如果您不知道，您知道在哪里学习它。

现在出现了关键问题。在部署和有状态集中，我们应该如何定义副本？

如果您计划在部署或 StatefulSet 中使用 HPA，请不要声明副本。如果这样做，每次滚动更新都会暂时取消 HPA 的效果。仅为不与 HPA 一起使用的资源定义副本。

# 现在呢？

我们探讨了扩展部署和 StatefulSets 的最简单方法。这很简单，因为这个机制已经内置在 Kubernetes 中。我们所要做的就是定义一个具有目标内存和 CPU 的 HorizontalPodAutoscaler。虽然这种自动缩放的方法通常被使用，但通常是不够的。并非所有应用程序在压力下都会增加内存或 CPU 使用率。即使它们这样做了，这两个指标可能还不够。

在接下来的章节中，我们将探讨如何扩展 HorizontalPodAutoscaler 以使用自定义的指标来源。现在，我们将销毁我们创建的内容，并开始下一章。

如果您计划保持集群运行，请执行以下命令以删除我们创建的资源。

```
 1  # If NOT GKE or AKS
 2  helm delete metrics-server --purge
 3
 4  kubectl delete ns go-demo-5
```

否则，请删除整个集群，如果您只是为了本书的目的而创建它，并且不打算立即深入下一章。

在您离开之前，您可能希望复习本章的要点。

+   水平 Pod 自动缩放器的唯一功能是自动调整部署、StatefulSet 或其他一些类型的资源中 Pod 的数量。它通过观察 Pod 的 CPU 和内存消耗，并在它们达到预定义的阈值时采取行动来实现这一点。

+   Metrics Server 收集有关节点和 Pod 使用的资源（内存和 CPU）的信息。

+   Metrics Server 定期从运行在节点上的 Kubeletes 获取指标。

+   如果副本的数量是静态的，并且您没有打算随时间缩放（或反向缩放）您的应用程序，请将`replicas`作为部署或 StatefulSet 定义的一部分。另一方面，如果您计划根据内存、CPU 或其他指标更改副本的数量，请改用 HorizontalPodAutoscaler 资源。

+   如果为部署定义了`replicas`，那么每次我们`apply`一个定义时都会使用它。如果我们通过删除`replicas`来更改定义，部署将认为我们想要一个，而不是我们之前拥有的副本数量。但是，如果我们从未指定`replicas`的数量，它们将完全由 HPA 控制。

+   如果您计划在部署或 StatefulSet 中使用 HPA，请不要声明`replicas`。如果这样做，每次滚动更新都会暂时取消 HPA 的效果。仅为不与 HPA 一起使用的资源定义`replicas`。


# 第二章：Kubernetes 集群的自动缩放节点

我可以说我并没有完全享受与人类一起工作吗？我发现他们的不合逻辑和愚蠢的情绪是一个不断的刺激。

- *斯波克*

使用**HorizontalPodAutoscaler**（**HPA**）是使系统具有弹性、容错和高可用性的最关键方面之一。然而，如果没有可用资源的节点，它就没有用处。当 Kubernetes 无法调度新的 Pod 时，因为没有足够的可用内存或 CPU，新的 Pod 将无法调度并处于挂起状态。如果我们不增加集群的容量，挂起的 Pod 可能会无限期地保持在那种状态。更复杂的是，Kubernetes 可能会开始删除其他 Pod，以为那些处于挂起状态的 Pod 腾出空间。你可能已经猜到，这可能会导致比我们的应用程序没有足够的副本来满足需求的问题更严重的问题。

Kubernetes 通过 Cluster Autoscaler 解决了节点扩展的问题。

Cluster Autoscaler 只有一个目的，那就是通过添加或删除工作节点来调整集群的大小。当 Pod 由于资源不足而无法调度时，它会添加新节点。同样，当节点在一段时间内未被充分利用，并且在该节点上运行的 Pod 可以在其他地方重新调度时，它会删除节点。

Cluster Autoscaler 背后的逻辑很容易理解。我们还没有看到它是否也很容易使用。

让我们创建一个集群（除非您已经有一个），并为其准备自动缩放。

# 创建一个集群

我们将继续使用`vfarcic/k8s-specs`（[`github.com/vfarcic/k8s-specs`](https://github.com/vfarcic/k8s-specs)）存储库中的定义。为了安全起见，我们将首先拉取最新版本。

本章中的所有命令都可以在`02-ca.sh`（[`gist.github.com/vfarcic/a6b2a5132aad6ca05b8ff5033c61a88f`](https://gist.github.com/vfarcic/a6b2a5132aad6ca05b8ff5033c61a88f)）Gist 中找到。

```
 1  cd k8s-specs
 2
 3  git pull
```

接下来，我们需要一个集群。请使用下面的 Gists 作为灵感来创建一个新的集群，或者验证您已经满足所有要求。

AKS 用户注意：在撰写本文时（2018 年 10 月），Cluster Autoscaler 在**Azure Kubernetes Service**（**AKS**）中并不总是有效。请参阅*在 AKS 中设置 Cluster Autoscaler*部分以获取更多信息和设置说明的链接。

+   `gke-scale.sh`：**GKE**有 3 个 n1-standard-1 工作节点，带有**tiller**，并带有`--enable-autoscaling`参数（[`gist.github.com/vfarcic/9c777487f7ebee6c09027d3a1df8663c`](https://gist.github.com/vfarcic/9c777487f7ebee6c09027d3a1df8663c)）。

+   `eks-ca.sh`：**EKS**有 3 个 t2.small 工作节点，带有**tiller**，并带有**Metrics Server**（[`gist.github.com/vfarcic/3dfc71dc687de3ed98e8f804d7abba0b`](https://gist.github.com/vfarcic/3dfc71dc687de3ed98e8f804d7abba0b)）。

+   `aks-scale.sh`：**AKS**有 3 个 Standard_B2s 工作节点和**tiller**（[`gist.github.com/vfarcic/f1b05d33cc8a98e4ceab3d3770c2fe0b`](https://gist.github.com/vfarcic/f1b05d33cc8a98e4ceab3d3770c2fe0b)）。

当检查 Gists 时，你会注意到一些事情。首先，Docker for Desktop 和 minikube 都不在其中。它们都是无法扩展的单节点集群。我们需要在一个可以根据需求添加和删除节点的地方运行集群。我们将不得不使用云供应商之一（例如 AWS、Azure、GCP）。这并不意味着我们不能在本地集群上扩展。

我们可以，但这取决于我们使用的供应商。有些供应商有解决方案，而其他供应商没有。为简单起见，我们将坚持使用三大云供应商之一。请在**Google Kubernetes Engine**（**GKE**）、亚马逊**弹性容器服务**（**EKS**）或**Azure Kubernetes 服务**（**AKS**）之间进行选择。如果你不确定选择哪一个，我建议选择 GKE，因为它是最稳定和功能丰富的托管 Kubernetes 集群。

你还会注意到，GKE 和 AKS 的 Gists 与上一章相同，而 EKS 发生了变化。正如你已经知道的那样，前者已经内置了 Metrics Server。EKS 没有，所以我复制了我们之前使用的 Gist，并添加了安装 Metrics Server 的说明。也许在这一章中我们不需要它，但以后会经常用到，我希望你习惯随时拥有它。

如果你更喜欢在本地运行示例，你可能会因为我们在本章中不使用本地集群而感到沮丧。不要绝望。成本将被保持在最低水平（总共可能只有几美元），我们将在下一章回到本地集群（除非你选择留在云端）。

现在我们在 GKE、EKS 或 AKS 中有了一个集群，我们的下一步是启用集群自动扩展。

# 设置集群自动扩展

在开始使用之前，我们可能需要安装集群自动缩放器。我说“可能”，而不是说“必须”，因为某些 Kubernetes 版本确实预先配置了集群自动缩放器，而其他版本则没有。我们将逐个讨论“三大”托管 Kubernetes 集群。您可以选择探索它们三个，或者直接跳转到您喜欢的一个。作为学习经验，我认为体验在所有三个提供商中运行 Kubernetes 是有益的。尽管如此，这可能不是您的观点，您可能更喜欢只使用一个。选择权在您手中。

# 在 GKE 中设置集群自动缩放器

这将是有史以来最短的部分。如果在创建集群时指定了`--enable-autoscaling`参数，则在 GKE 中无需进行任何操作。它已经预先配置并准备好了集群自动缩放器。

# 在 EKS 中设置集群自动缩放器

与 GKE 不同，EKS 不带有集群自动缩放器。我们将不得不自己配置它。我们需要向专用于工作节点的 Autoscaling Group 添加一些标签，为我们正在使用的角色添加额外的权限，并安装集群自动缩放器。

让我们开始吧。

我们将向专用于工作节点的 Autoscaling Group 添加一些标签。为此，我们需要发现组的名称。由于我们使用**eksctl**创建了集群，名称遵循一种模式，我们可以使用该模式来过滤结果。另一方面，如果您在没有使用 eksctl 的情况下创建了 EKS 集群，逻辑应该与接下来的逻辑相同，尽管命令可能略有不同。

首先，我们将检索 AWS Autoscaling Groups 的列表，并使用`jq`过滤结果，以便只返回匹配组的名称。

```
 1  export NAME=devops25
 2
 3  ASG_NAME=$(aws autoscaling \
 4      describe-auto-scaling-groups \
 5      | jq -r ".AutoScalingGroups[] \
 6      | select(.AutoScalingGroupName \
 7      | startswith(\"eksctl-$NAME-nodegroup\")) \
 8      .AutoScalingGroupName")
 9
10 echo $ASG_NAME
```

后一个命令的输出应该类似于接下来的输出。

```
eksctl-devops25-nodegroup-0-NodeGroup-1KWSL5SEH9L1Y
```

我们将集群的名称存储在环境变量`NAME`中。然后，我们检索了所有组的列表，并使用`jq`过滤输出，以便只返回名称以`eksctl-$NAME-nodegroup`开头的组。最后，相同的`jq`命令检索了`AutoScalingGroupName`字段，并将其存储在环境变量`ASG_NAME`中。最后一个命令输出了组名，以便我们可以确认（视觉上）它看起来是否正确。

接下来，我们将向组添加一些标记。Kubernetes Cluster Autoscaler 将与具有`k8s.io/cluster-autoscaler/enabled`和`kubernetes.io/cluster/[NAME_OF_THE_CLUSTER]`标记的组一起工作。因此，我们只需添加这些标记，让 Kubernetes 知道要使用哪个组。

```
 1  aws autoscaling \
 2      create-or-update-tags \
 3      --tags \
 4      ResourceId=$ASG_NAME,ResourceType=auto-scaling-group,Key=k8s.io/
    clusterautoscaler/enabled,Value=true,PropagateAtLaunch=true \
 5      ResourceId=$ASG_NAME,ResourceType=auto-scaling-
    group,Key=kubernetes.io/cluster/$NAME,Value=true,PropagateAtLaunch=true
```

我们在 AWS 中需要做的最后一项更改是向通过 eksctl 创建的角色添加一些额外的权限。与自动缩放组一样，我们不知道角色的名称，但我们知道用于创建它的模式。因此，在添加新策略之前，我们将检索角色的名称。

```
 1  IAM_ROLE=$(aws iam list-roles \
 2      | jq -r ".Roles[] \
 3      | select(.RoleName \
 4      | startswith(\"eksctl-$NAME-nodegroup-0-NodeInstanceRole\")) \
 5      .RoleName")
 6  
 7  echo $IAM_ROLE
```

后一条命令的输出应该类似于接下来的输出。

```
eksctl-devops25-nodegroup-0-NodeInstanceRole-UU6CKXYESUES
```

我们列出了所有角色，并使用`jq`过滤输出，以便只返回名称以`eksctl-$NAME-nodegroup-0-NodeInstanceRole`开头的角色。过滤角色后，我们检索了`RoleName`并将其存储在环境变量`IAM_ROLE`中。

接下来，我们需要描述新策略的 JSON。我已经准备好了，让我们快速看一下。

```
 1  cat scaling/eks-autoscaling-policy.json
```

输出如下。

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeTags",
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup"
      ],
      "Resource": "*"
    }
  ]
}
```

如果你熟悉 AWS（我希望你是），那个策略应该很简单。它允许与`autoscaling`相关的一些额外操作。

最后，我们可以将新策略`put`到角色中。

```
 1  aws iam put-role-policy \
 2      --role-name $IAM_ROLE \
 3      --policy-name $NAME-AutoScaling \
 4      --policy-document file://scaling/eks-autoscaling-policy.json
```

现在我们已经向自动缩放组添加了所需的标记，并创建了额外的权限，允许 Kubernetes 与该组进行交互，我们可以安装 Cluster Autoscaler Helm Chart。

```
 1  helm install stable/cluster-autoscaler \
 2      --name aws-cluster-autoscaler \
 3      --namespace kube-system \
 4      --set autoDiscovery.clusterName=$NAME \
 5      --set awsRegion=$AWS_DEFAULT_REGION \
 6      --set sslCertPath=/etc/kubernetes/pki/ca.crt \
 7      --set rbac.create=true
 8
9  kubectl -n kube-system \
10      rollout status \
11      deployment aws-cluster-autoscaler
```

一旦部署完成，自动缩放器应该完全可用。

# 在 AKS 中设置 Cluster Autoscaler

在撰写本文时（2018 年 10 月），Cluster Autoscaler 在 AKS 中无法正常工作。至少，不总是。它仍处于测试阶段，我暂时不能推荐。希望它很快就能完全运行并保持稳定。一旦发生这种情况，我将使用 AKS 特定的说明更新本章。如果你感到有冒险精神，或者你致力于 Azure，请按照*Azure Kubernetes Service（AKS）上的 Cluster Autoscaler - 预览*（[`docs.microsoft.com/en-in/azure/aks/cluster-autoscaler`](https://docs.microsoft.com/en-in/azure/aks/cluster-autoscaler)）文章中的说明。如果它有效，你应该能够按照本章的其余部分进行操作。

# 扩大集群

我们的目标是扩展集群的节点，以满足 Pod 的需求。我们不仅希望在需要额外容量时增加工作节点的数量，而且在它们被闲置时也要删除它们。现在，我们将专注于前者，并在之后探索后者。

让我们首先看一下集群中有多少个节点。

```
 1  kubectl get nodes
```

来自 GKE 的输出如下。

```
NAME             STATUS ROLES  AGE   VERSION
gke-devops25-... Ready  <none> 5m27s v1.9.7-gke.6
gke-devops25-... Ready  <none> 5m28s v1.9.7-gke.6
gke-devops25-... Ready  <none> 5m24s v1.9.7-gke.6
```

在您的情况下，节点的数量可能会有所不同。这并不重要。重要的是要记住您现在有多少个节点，因为这个数字很快就会改变。

在我们推出`go-demo-5`应用程序之前，让我们先看一下它的定义。

```
 1  cat scaling/go-demo-5-many.yml
```

输出内容，仅限于相关部分，如下所示。

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: go-demo-5
spec:
  ...
  template:
    ...
    spec:
      containers:
      - name: api
        ...
        resources:
          limits:
            memory: 1Gi
            cpu: 0.1
          requests:
            memory: 500Mi
            cpu: 0.01
...
apiVersion: autoscaling/v2beta1
kind: HorizontalPodAutoscaler
metadata:
  name: api
  namespace: go-demo-5
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 15
  maxReplicas: 30
  ...
```

在这种情况下，我们即将应用的定义中唯一重要的部分是与`api`部署连接的 HPA。它的最小副本数是`15`。假设每个`api`容器请求 500 MB RAM，那么十五个副本（7.5 GB RAM）应该超出了我们的集群可以承受的范围，假设它是使用其中一个 Gists 创建的。否则，您可能需要增加最小副本数。

让我们应用这个定义并看一下 HPA。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5-many.yml \
 3      --record
 4
 5  kubectl -n go-demo-5 get hpa
```

后一条命令的输出如下。

```
NAME   REFERENCE        TARGETS                        MINPODS   MAXPODS   REPLICAS   AGE
api    Deployment/api   <unknown>/80%, <unknown>/80%   15        30        1          38s
db     StatefulSet/db   <unknown>/80%, <unknown>/80%   3         5         1          40s
```

无论目标是否仍然是`未知`，它们很快就会被计算出来，但我们现在不关心它们。重要的是`api` HPA 将会将部署扩展至至少`15`个副本。

接下来，我们需要等待几秒钟，然后再看一下`go-demo-5`命名空间中的 Pod。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS            RESTARTS AGE
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   Pending           0        2s
api-... 0/1   Pending           0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 1        32s
api-... 0/1   Pending           0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   Pending           0        2s
api-... 0/1   ContainerCreating 0        2s
api-... 0/1   ContainerCreating 0        2s
db-0    2/2   Running           0        34s
db-1    0/2   ContainerCreating 0        34s
```

我们可以看到一些`api` Pod 正在被创建，而其他一些则是挂起的。Pod 进入挂起状态可能有很多原因。

在我们的情况下，没有足够的可用资源来托管所有的 Pod。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/a1c839db-c439-4994-a113-8b0a27c59e84.png)图 2-1：无法调度（挂起）的 Pod 正在等待集群容量增加

让我们看看集群自动缩放器是否有助于解决我们的容量不足问题。我们将探索包含集群自动缩放器状态的 ConfigMap。

```
 1  kubectl -n kube-system get cm \
 2      cluster-autoscaler-status \
 3      -o yaml
```

输出内容太多，无法完整呈现，所以我们将专注于重要的部分。

```
apiVersion: v1
data:
  status: |+
    Cluster-autoscaler status at 2018-10-03 ...
    Cluster-wide:
      ...
      ScaleUp: InProgress (ready=3 registered=3)
    ... 
    NodeGroups:
      Name:    ...gke-devops25-default-pool-ce277413-grp
      ...
      ScaleUp: InProgress (ready=1 cloudProviderTarget=2)
               ...
```

状态分为两个部分：`整个集群`和`节点组`。整个集群状态的`ScaleUp`部分显示缩放正在进行中。目前有`3`个就绪节点。

如果我们移动到`NodeGroups`，我们会注意到每个托管我们节点的组都有一个。在 AWS 中，这些组映射到自动缩放组，在谷歌的情况下映射到实例组，在 Azure 中映射到自动缩放。配置中的一个`NodeGroups`具有`ScaleUp`部分`InProgress`。在该组内，`1`个节点是`ready`。`cloudProviderTarget`值应设置为高于`ready`节点数量的数字，我们可以得出结论，集群自动缩放器已经增加了该组中所需的节点数量。

根据提供商的不同，您可能会看到三个组（GKE）或一个（EKS）节点组。这取决于每个提供商如何在内部组织其节点组。

现在我们知道集群自动缩放器正在进行节点扩展，我们可以探索是什么触发了该操作。

让我们描述`api` Pod 并检索它们的事件。由于我们只想要与`cluster-autoscaler`相关的事件，我们将使用`grep`来限制输出。

```
 1  kubectl -n go-demo-5 \
 2      describe pods \
 3      -l app=api \
 4      | grep cluster-autoscaler
```

在 GKE 上的输出如下。

```
  Normal TriggeredScaleUp 85s cluster-autoscaler pod triggered scale-up: [{... 1->2 (max: 3)}]
  Normal TriggeredScaleUp 86s cluster-autoscaler pod triggered scale-up: [{... 1->2 (max: 3)}]
  Normal TriggeredScaleUp 87s cluster-autoscaler pod triggered scale-up: [{... 1->2 (max: 3)}]
  Normal TriggeredScaleUp 88s cluster-autoscaler pod triggered scale-up: [{... 1->2 (max: 3)}]
```

我们可以看到几个 Pod 触发了`scale-up`事件。这些是处于挂起状态的 Pod。这并不意味着每个触发都创建了一个新节点。集群自动缩放器足够智能，知道不应该为每个触发创建新节点，但在这种情况下，一个或两个节点（取决于缺少的容量）应该足够。如果证明这是错误的，它将在一段时间后再次扩展。

让我们检索构成集群的节点，看看是否有任何变化。

```
 1  kubectl get nodes
```

输出如下。

```
NAME                                     STATUS     ROLES    AGE     VERSION
gke-devops25-default-pool-7d4b99ad-...   Ready      <none>   2m45s   v1.9.7-gke.6
gke-devops25-default-pool-cb207043-...   Ready      <none>   2m45s   v1.9.7-gke.6
gke-devops25-default-pool-ce277413-...   NotReady   <none>   12s     v1.9.7-gke.6
gke-devops25-default-pool-ce277413-...   Ready      <none>   2m48s   v1.9.7-gke.6
```

我们可以看到一个新的工作节点被添加到集群中。它还没有准备好，所以我们需要等待一段时间，直到它完全可操作。

请注意，新节点的数量取决于托管所有 Pod 所需的容量。您可能会看到一个、两个或更多新节点。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/27fff93a-5bb4-452a-bc2f-e480ec2c725a.png)图 2-2：集群自动缩放器扩展节点的过程

现在，让我们看看我们的 Pod 发生了什么。记住，上次我们检查它们时，有相当多的 Pod 处于挂起状态。

```
 1  kubectl -n go-demo-5 get pods
```

输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 1        75s
api-... 1/1   Running 0        75s
api-... 1/1   Running 0        75s
api-... 1/1   Running 1        75s
api-... 1/1   Running 1        75s
api-... 1/1   Running 3        105s
api-... 1/1   Running 0        75s
api-... 1/1   Running 0        75s
api-... 1/1   Running 1        75s
api-... 1/1   Running 1        75s
api-... 1/1   Running 0        75s
api-... 1/1   Running 1        75s
api-... 1/1   Running 0        75s
api-... 1/1   Running 1        75s
api-... 1/1   Running 0        75s
db-0    2/2   Running 0        107s
db-1    2/2   Running 0        67s
db-2    2/2   Running 0        28s
```

集群自动缩放器增加了节点组（例如，AWS 中的自动缩放组）中所需的节点数量，从而创建了一个新节点。一旦调度程序注意到集群容量的增加，它就会将待定的 Pod 调度到新节点中。在几分钟内，我们的集群扩展了，所有缩放的 Pod 都在运行。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/3126993e-31ae-4184-bee7-068f2752fa4c.png)图 2-3：通过节点组创建新节点和挂起 Pod 的重新调度

那么，集群自动缩放器在何时决定扩大节点的规则是什么？

# 节点规模扩大的规则

集群自动缩放器通过对 Kube API 进行监视来监视 Pod。它每 10 秒检查一次是否有任何无法调度的 Pod（可通过`--scan-interval`标志进行配置）。在这种情况下，当 Kubernetes 调度程序无法找到可以容纳它的节点时，Pod 是无法调度的。例如，一个 Pod 可以请求比任何工作节点上可用的内存更多的内存。

集群自动缩放器假设集群运行在某种节点组之上。例如，在 AWS 的情况下，这些组是**自动缩放组**（**ASGs**）。当需要额外的节点时，集群自动缩放器通过增加节点组的大小来创建一个新节点。

集群自动缩放器假设请求的节点将在 15 分钟内出现（可通过`--max-node-provision-time`标志进行配置）。如果该时间段到期，新节点未注册，它将尝试扩展不同的组，如果 Pod 仍处于挂起状态。它还将在 15 分钟后删除未注册的节点（可通过`--unregistered-node-removal-time`标志进行配置）。

接下来，我们将探讨如何缩小集群。

# 缩小集群

扩大集群以满足需求是必不可少的，因为它允许我们托管我们需要满足（部分）SLA 的所有副本。当需求下降，我们的节点变得未充分利用时，我们应该缩小规模。鉴于我们的用户不会因为集群中有太多硬件而遇到问题，这并非必要。然而，如果我们要减少开支，我们不应该有未充分利用的节点。未使用的节点会导致浪费。这在所有情况下都是正确的，特别是在云中运行并且只支付我们使用的资源的情况下。即使在本地，我们已经购买了硬件，缩小规模并释放资源以便其他集群使用是必不可少的。

我们将通过应用一个新的定义来模拟需求下降，这将重新定义 HPAs 的阈值为`2`（最小）和`5`（最大）。

```
 1  kubectl apply \
 2      -f scaling/go-demo-5.yml \
 3      --record
 4
 5  kubectl -n go-demo-5 get hpa
```

后一条命令的输出如下。

```
NAME REFERENCE      TARGETS          MINPODS MAXPODS REPLICAS AGE
api  Deployment/api 0%/80%, 0%/80%   2       5       15       2m56s
db   StatefulSet/db 56%/80%, 10%/80% 3       5       3        2m57s
```

我们可以看到`api` HPA 的最小和最大值已经改变为`2`和`5`。当前副本的数量仍然是`15`，但很快会降到`5`。HPA 已经改变了部署的副本，所以让我们等待它的部署完成，然后再看一下 Pods。

```
 1  kubectl -n go-demo-5 rollout status \
 2      deployment api
 3
 4  kubectl -n go-demo-5 get pods
```

后一个命令的输出如下。

```
NAME    READY STATUS  RESTARTS AGE
api-... 1/1   Running 0        104s
api-... 1/1   Running 0        104s
api-... 1/1   Running 0        104s
api-... 1/1   Running 0        94s
api-... 1/1   Running 0        104s
db-0    2/2   Running 0        4m37s
db-1    2/2   Running 0        3m57s
db-2    2/2   Running 0        3m18s
```

让我们看看`nodes`发生了什么。

```
 1  kubectl get nodes
```

输出显示我们仍然有四个节点（或者在我们缩减部署之前的数字）。

考虑到我们还没有达到只有三个节点的期望状态，我们可能需要再看一下`cluster-autoscaler-status` ConfigMap。

```
 1  kubectl -n kube-system \
 2      get configmap \
 3      cluster-autoscaler-status \
 4      -o yaml
```

输出，仅限于相关部分，如下所示。

```
apiVersion: v1
data:
  status: |+
    Cluster-autoscaler status at 2018-10-03 ...
    Cluster-wide:
      Health: Healthy (ready=4 ...)
      ...
      ScaleDown: CandidatesPresent (candidates=1)
                 ...
    NodeGroups:
      Name:      ...gke-devops25-default-pool-f4c233dd-grp
      ...
      ScaleDown: CandidatesPresent (candidates=1)
                 LastProbeTime:      2018-10-03 23:06:...
                 LastTransitionTime: 2018-10-03 23:05:...
      ...
```

如果您的输出不包含`ScaleDown: CandidatesPresent`，您可能需要等一会儿并重复上一个命令。

如果我们关注整个集群状态的`Health`部分，所有四个节点仍然是就绪的。

从状态的整个集群部分来看，我们可以看到有一个候选节点进行`ScaleDown`（在您的情况下可能有更多）。如果我们转到`NodeGroups`，我们可以观察到其中一个节点组在`ScaleDown`部分中的`CandidatesPresent`设置为`1`（或者在扩展之前的初始值）。

换句话说，其中一个节点是待删除的候选节点。如果它保持这样十分钟，节点将首先被排空，以允许其中运行的 Pods 优雅关闭。之后，通过操纵扩展组来物理移除它。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/ede07cff-dc03-427e-9205-4facebd4711f.png)图 2-4：集群自动缩放的缩减过程

在继续之前，我们应该等待十分钟，所以这是一个很好的机会去喝杯咖啡（或茶）。

现在已经过了足够的时间，我们将再次查看`cluster-autoscaler-status` ConfigMap。

```
 1  kubectl -n kube-system \
 2      get configmap \
 3      cluster-autoscaler-status \
 4      -o yaml
```

输出，仅限于相关部分，如下所示。

```
apiVersion: v1
data:
  status: |+
    Cluster-autoscaler status at 2018-10-03 23:16:24...
    Cluster-wide:
      Health:    Healthy (ready=3 ... registered=4 ...)
                 ...
      ScaleDown: NoCandidates (candidates=0)
                 ...
    NodeGroups:
      Name:      ...gke-devops25-default-pool-f4c233dd-grp
      Health:    Healthy (ready=1 ... registered=2 ...)
                 ...
      ScaleDown: NoCandidates (candidates=0)
                 ...
```

从整个集群部分，我们可以看到现在有`3`个就绪节点，但仍然有`4`（或更多）已注册。这意味着其中一个节点已经被排空，但仍然没有被销毁。同样，其中一个节点组显示有`1`个就绪节点，尽管已注册`2`个（您的数字可能有所不同）。

从 Kubernetes 的角度来看，我们回到了三个操作节点，尽管第四个节点仍然存在。

现在我们需要再等一会儿，然后检索节点并确认只有三个可用。

```
 1  kubectl get nodes
```

来自 GKE 的输出如下。

```
NAME    STATUS ROLES  AGE VERSION
gke-... Ready  <none> 36m v1.9.7-gke.6
gke-... Ready  <none> 36m v1.9.7-gke.6
gke-... Ready  <none> 36m v1.9.7-gke.6
```

我们可以看到节点已被移除，我们已经从过去的经验中知道，Kube Scheduler 将那个节点中的 Pod 移动到仍在运行的节点中。现在您已经经历了节点的缩减，我们将探讨管理该过程的规则。

# 控制节点缩减的规则

集群自动缩放器每 10 秒迭代一次（可通过`--scan-interval`标志进行配置）。如果不满足扩展的条件，它会检查是否有不需要的节点。

当满足以下所有条件时，它将考虑将节点标记为可移除。

+   在节点上运行的所有 Pod 的 CPU 和内存请求总和小于节点可分配资源的 50%（可通过`--scale-down-utilization-threshold`标志进行配置）。

+   所有在节点上运行的 Pod 都可以移动到其他节点。例外情况是那些在所有节点上运行的 Pod，比如通过 DaemonSets 创建的 Pod。

当满足以下条件之一时，Pod 可能不符合重新调度到不同节点的条件。

+   具有亲和性或反亲和性规则将其与特定节点绑定的 Pod。

+   使用本地存储的 Pod。

+   直接创建的 Pod，而不是通过部署、有状态集、作业或副本集等控制器创建的 Pod。

所有这些规则归结为一个简单的规则。如果一个节点包含一个不能安全驱逐的 Pod，那么它就不符合移除的条件。

接下来，我们应该谈谈集群扩展的边界。

# 我们是否可以扩展得太多或将节点缩减到零？

如果让集群自动缩放器在不定义任何阈值的情况下进行"魔术"，我们的集群或钱包可能会面临风险。

例如，我们可能会错误配置 HPA，导致将部署或有状态集扩展到大量副本。结果，集群自动缩放器可能会向集群添加过多的节点。因此，我们可能会支付数百个节点的费用，尽管我们实际上需要的要少得多。幸运的是，AWS、Azure 和 GCP 限制了我们可以拥有的节点数量，因此我们无法无限扩展。尽管如此，我们也不应允许集群自动缩放器超出一些限制。

同样，集群自动缩放器可能会缩减到太少的节点。拥有零个节点几乎是不可能的，因为这意味着我们在集群中没有 Pod。尽管如此，我们应该保持健康的最小节点数量，即使有时会被低效利用。

节点的合理最小数量是三个。这样，我们在该地区的每个区域（数据中心）都有一个工作节点。正如您已经知道的，Kubernetes 需要三个带有主节点的区域来维持法定人数。在某些情况下，特别是在本地，我们可能只有一个地理上相邻的延迟较低的数据中心。在这种情况下，一个区域（数据中心）总比没有好。但是，在云服务提供商的情况下，三个区域是推荐的分布，并且在每个区域至少有一个工作节点是有意义的。如果我们使用块存储，这一点尤为重要。

根据其性质，块存储（例如 AWS 中的 EBS、GCP 中的持久磁盘和 Azure 中的块 Blob）无法从一个区域移动到另一个区域。这意味着我们必须在每个区域都有一个工作节点，以便（很可能）总是有一个与存储在同一区域的位置。当然，如果我们不使用块存储，那么这个论点就站不住脚了。

那么工作节点的最大数量呢？嗯，这取决于不同的用例。您不必永远坚持相同的最大值。它可以随着时间的推移而改变。

作为一个经验法则，我建议将最大值设为实际节点数量的两倍。但是，不要太认真对待这个规则。这确实取决于您的集群大小。如果您只有三个工作节点，那么最大尺寸可能是九个（三倍）。另一方面，如果您有数百甚至数千个节点，将该数字加倍作为最大值就没有意义。那将太多了。只需确保节点的最大数量反映了需求的潜在增长。

无论如何，我相信您会弄清楚您的工作节点的最小和最大数量应该是多少。如果您犯了错误，可以随后更正。更重要的是如何定义这些阈值。

幸运的是，在 EKS、GKE 和 AKS 中设置最小和最大值很容易。对于 EKS，如果您使用`eksctl`来创建集群，我们只需在`eksctl create cluster`命令中添加`--nodes-min`和`--nodes-max`参数。GKE 遵循类似的逻辑，使用`gcloud container clusters create`命令的`--min-nodes`和`--max-nodes`参数。如果其中一个是您的首选项，那么如果您遵循了 Gists，您已经使用了这些参数。即使您忘记指定它们，您也可以随时修改自动缩放组（AWS）或实例组（GCP），因为实际应用限制的地方就在那里。

Azure 采取了稍微不同的方法。我们直接在`cluster-autoscaler`部署中定义其限制，并且可以通过应用新的定义来更改它们。

# 在 GKE、EKS 和 AKS 中比较的集群自动缩放器

集群自动缩放器是不同托管 Kubernetes 服务提供商之间差异的一个主要例子。我们将使用它来比较三个主要的 Kubernetes 即服务提供商。

我将把供应商之间的比较限制在与集群自动缩放相关的主题上。

对于那些可以使用谷歌来托管他们的集群的人来说，GKE 是一个不言而喻的选择。它是最成熟和功能丰富的平台。他们比其他人早很久就开始了**Google Kubernetes Engine**（**GKE**）。当我们将他们的领先优势与他们是 Kubernetes 的主要贡献者并且因此拥有最丰富经验这一事实结合起来时，他们的产品远远超过其他人并不足为奇。

在使用 GKE 时，一切都包含在集群中。这包括集群自动缩放器。我们不必执行任何额外的命令。只要我们在创建集群时指定`--enable-autoscaling`参数，它就可以直接使用。此外，GKE 比其他提供商更快地启动新节点并将它们加入集群。如果需要扩展集群，新节点将在一分钟内添加。

我会推荐 GKE 的许多其他原因，但现在不是讨论的主题。不过，单单集群自动缩放就足以证明 GKE 是其他人努力追随的解决方案。

亚马逊的**弹性容器服务**（**EKS**）处于中间位置。集群自动缩放器可以工作，但它并不是内置的。就好像亚马逊认为扩展集群并不重要，所以将其作为一个可选的附加组件。

与 GKE 和 AKS 相比，EKS 的安装过于复杂，但多亏了来自 Weaveworks 的 eksctl（[`eksctl.io/`](https://eksctl.io/)），我们解决了这个问题。不过，eksctl 还有很多需要改进的地方。例如，我们无法使用它来升级我们的集群。

我提到 eksctl 是在自动缩放设置的上下文中。

我不能说在 EKS 中设置集群自动缩放器很难。并不是。然而，它并不像应该的那么简单。我们需要给自动缩放组打标签，为角色添加额外的权限，并安装集群自动缩放器。这并不多。然而，这些步骤比应该的复杂得多。我们可以拿 GKE 来比较。谷歌明白自动缩放 Kubernetes 集群是必须的，并提供了一个参数（或者如果你更喜欢 UI，可以选择一个复选框）。而 AWS 则认为自动缩放并不重要，没有给我们那么简单的设置。除了 EKS 中不必要的设置之外，事实上 AWS 最近才添加了扩展所需的内部组件。Metrics Server 只能在 2018 年 9 月之后使用。

我怀疑 AWS 并不急于让 EKS 变得更好，而是把改进留给了 Fargate。如果是这样的话（我们很快就会知道），我会把它称为“隐秘的商业行为”。Kubernetes 拥有所有扩展 Pod 和节点所需的工具，并且它们被设计为可扩展的。选择不将集群自动缩放器作为托管 Kubernetes 服务的一部分是一个很大的缺点。

AKS 有什么好说的呢？我钦佩微软在 Azure 上所做的改进，以及他们对 Kubernetes 的贡献。他们确实意识到了提供一个良好的托管 Kubernetes 的需求。然而，集群自动缩放器仍处于测试阶段。有时它能正常工作，但更多时候却不能。即使它正常工作，速度也很慢。等待新节点加入集群需要耐心等待。

在 AKS 中安装集群自动缩放器所需的步骤有些荒谬。我们需要定义大量参数，而这些参数本应该已经在集群内可用。它应该知道集群的名称，资源组的名称等等。然而，它并不知道。至少在撰写本文时是这样的（2018 年 10 月）。我希望随着时间的推移，这个过程和体验会得到改善。目前来看，就自动缩放的角度来看，AKS 处于队伍的最后。

你可能会说设置的复杂性并不重要。你说得对。重要的是集群自动缩放器的可靠性以及它添加新节点到集群的速度。然而，情况却是一样的。GKE 在可靠性和速度方面处于领先地位。EKS 紧随其后，而 AKS 则落后。

# 现在呢？

关于集群自动缩放器没有太多要说的了。

我们已经探索了自动缩放 Pod 和节点的基本方法。很快我们将深入探讨更复杂的主题，并探索那些没有“内置”到 Kubernetes 集群中的东西。我们将超越核心项目，并介绍一些新的工具和流程。

如果您不打算立即进入下一章，并且您的集群是可丢弃的（例如，不在裸机上），那么这就是您应该销毁集群的时刻。否则，请删除`go-demo-5`命名空间，以删除我们在本章中创建的资源。

```
 1  kubectl delete ns go-demo-5
```

在您离开之前，您可能希望复习本章的要点。

+   集群自动缩放器有一个单一的目的，即通过添加或删除工作节点来调整集群的大小。当 Pod 由于资源不足而无法调度时，它会添加新节点。同样，当节点在一段时间内利用不足，并且运行在该节点上的 Pod 可以在其他地方重新调度时，它会消除节点。

+   集群自动缩放器假设集群正在某种节点组之上运行。例如，在 AWS 的情况下，这些组是自动缩放组（ASG）。当需要额外的节点时，集群自动缩放器通过增加节点组的大小来创建新节点。

+   当运行在节点上的所有 Pod 的 CPU 和内存请求总和小于节点可分配资源的 50％时，集群将被缩减，并且当运行在节点上的所有 Pod 可以移动到其他节点时（DamonSets 是例外情况）。


# 第三章：收集和查询指标并发送警报

不充分的事实总是会引发危险。

- *斯波克*

到目前为止，我们已经探讨了如何利用一些 Kubernetes 核心功能。我们使用了 HorizontalPodAutoscaler 和 Cluster Autoscaler。前者依赖于度量服务器，而后者不是基于指标，而是基于调度程序无法将 Pod 放置在现有集群容量内。尽管度量服务器确实提供了一些基本指标，但我们迫切需要更多。

我们必须能够监视我们的集群，而度量服务器并不足够。它包含有限数量的指标，它们保存的时间很短，而且它不允许我们执行除了最简单的查询之外的任何操作。如果我们只依赖度量服务器，我不能说我们是盲目的，但我们受到严重的影响。如果我们不增加收集的指标数量以及它们的保留时间，我们只能对我们的 Kubernetes 集群中发生的情况有一瞥。

能够获取和存储指标本身并不是目标。我们还需要能够查询它们以寻找问题的原因。为此，我们需要指标“丰富”的信息，以及强大的查询语言。

最后，能够找到问题的原因没有多大意义，如果不能首先被通知存在问题。这意味着我们需要一个系统，可以让我们定义警报，当达到一定阈值时，会向我们发送通知，或者在适当时将它们发送到系统的其他部分，可以自动执行解决问题的步骤。

如果我们做到了这一点，我们将更接近于拥有不仅自我修复（Kubernetes 已经做到了），而且还会对变化的条件做出反应的自适应系统。我们甚至可以进一步尝试预测未来会发生“坏事”，并在它们出现之前积极解决它们。

总而言之，我们需要一个工具，或一组工具，可以让我们获取和存储“丰富”的指标，可以让我们查询它们，并且在出现问题时通知我们，甚至更好的是，在问题即将发生时通知我们。

在本章中，我们可能无法构建一个自适应系统，但我们可以尝试创建一个基础。但首先，我们需要一个集群，让我们可以“玩”一些新的工具和概念。

# 创建一个集群

我们将继续使用`vfarcic/k8s-specs`（[`github.com/vfarcic/k8s-specs`](https://github.com/vfarcic/k8s-specs)）存储库中的定义。为了安全起见，我们将首先拉取最新版本。

本章中的所有命令都在`03-monitor.sh`（[`gist.github.com/vfarcic/718886797a247f2f9ad4002f17e9ebd9`](https://gist.github.com/vfarcic/718886797a247f2f9ad4002f17e9ebd9)）Gist 中可用。

```
 1  cd k8s-specs
 2
 3  git pull
```

给 minikube 和 Docker for Desktop 用户的提示：我们需要将内存增加到 3GB。请记住这一点，以防您只是计划浏览与您的 Kubernetes 版本匹配的 Gist。在本章中，我们将需要一些以前不是要求的东西，尽管您可能已经使用过它们。

我们将开始使用 UI，因此我们将需要 NGINX Ingress Controller 来从集群外部路由流量。我们还需要环境变量`LB_IP`，其中包含我们可以访问工作节点的 IP。我们将用它来配置一些 Ingress 资源。

本章中用于测试示例的 Gists 如下。请按原样使用它们，或者作为创建自己的集群的灵感，或者确认您已有的集群是否符合要求。由于新的要求（Ingress 和`LB_IP`），所有集群设置的 Gists 都是新的。

给 Docker for Desktop 用户的提示：您会注意到 Gist 末尾的`LB_IP=[...]`命令。您需要用您集群的 IP 替换`[...]`。可能找到它最简单的方法是通过`ifconfig`命令。只需记住它不能是`localhost`，而是您笔记本电脑的 IP（例如，`192.168.0.152`）。

Gists 如下。

+   `gke-monitor.sh`：**GKE** 使用 3 个 n1-standard-1 工作节点，**nginx Ingress**，**tiller**，并将集群 IP 存储在环境变量**LB_IP**中（[`gist.github.com/vfarcic/10e14bfbec466347d70d11a78fe7eec4`](https://gist.github.com/vfarcic/10e14bfbec466347d70d11a78fe7eec4)）。

+   `eks-monitor.sh`：**EKS** 使用 3 个 t2.small 工作节点，**nginx Ingress**，**tiller**，**Metrics Server**，并将集群 IP 存储在环境变量**LB_IP**中（[`gist.github.com/vfarcic/211f8dbe204131f8109f417605dbddd5`](https://gist.github.com/vfarcic/211f8dbe204131f8109f417605dbddd5)）。

+   `aks-monitor.sh`：**AKS**带有 3 个 Standard_B2s 工作节点，**nginx Ingress**，**tiller**，并且集群 IP 存储在环境变量**LB_IP**中([`gist.github.com/vfarcic/5fe5c238047db39cb002cdfdadcfbad2`](https://gist.github.com/vfarcic/5fe5c238047db39cb002cdfdadcfbad2))。

+   `docker-monitor.sh`：**Docker for Desktop**，带有**2 个 CPU**，**3GB RAM**，**nginx Ingress**，**tiller**，**Metrics Server**，并且集群 IP 存储在环境变量**LB_IP**中([`gist.github.com/vfarcic/4d9ab04058cf00b9dd0faac11bda8f13`](https://gist.github.com/vfarcic/4d9ab04058cf00b9dd0faac11bda8f13))。

+   `minikube-monitor.sh`：**minikube**带有**2 个 CPU**，**3GB RAM**，**ingress**，**storage-provisioner**，**default-storageclass**，并且启用了**metrics-server**附加组件，**tiller**，并且集群 IP 存储在环境变量**LB_IP**中([`gist.github.com/vfarcic/892c783bf51fc06dd7f31b939bc90248`](https://gist.github.com/vfarcic/892c783bf51fc06dd7f31b939bc90248))。

现在我们有了一个集群，我们需要选择我们将用来实现我们目标的工具。

# 选择存储和查询指标以及警报的工具

**HorizontalPodAutoscaler** (**HPA**)和**Cluster Autoscaler** (**CA**)提供了必要但非常基本的机制来扩展我们的 Pods 和集群。

虽然它们可以很好地进行扩展，但它们并不能解决我们在出现问题时需要接收警报的需求，也不能提供足够的信息来找到问题的原因。我们需要通过额外的工具来扩展我们的设置，这些工具将允许我们存储和查询指标，并在出现问题时接收通知。

如果我们专注于可以安装和管理的工具，那么我们对使用什么工具几乎没有疑问。如果我们看一下*Cloud Native Computing Foundation (CNCF)*项目列表([`www.cncf.io/projects/`](https://www.cncf.io/projects/))，到目前为止只有两个项目已经毕业（2018 年 10 月）。它们分别是*Kubernetes*和*Prometheus*([`prometheus.io/`](https://prometheus.io/))。考虑到我们正在寻找一个可以存储和查询指标的工具，而 Prometheus 满足了这一需求，选择就很明显了。这并不是说没有其他值得考虑的类似工具。有，但它们都是基于服务的。我们以后可能会探索它们，但现在，我们专注于那些可以在我们的集群内运行的工具。因此，我们将把 Prometheus 加入到混合中，并尝试回答一个简单的问题。Prometheus 是什么？

Prometheus 是一个（某种程度上的）数据库，旨在获取（拉取）和存储高维时间序列数据。

时间序列由指标名称和一组键值对标识。数据既存储在内存中，也存储在磁盘上。前者可以快速检索信息，而后者存在是为了容错。

Prometheus 的查询语言使我们能够轻松找到可用于图表和更重要的警报的数据。它并不试图提供“出色”的可视化体验。为此，它与*Grafana*（[`grafana.com/`](https://grafana.com/)）集成。

与大多数其他类似工具不同，我们不会将数据推送到 Prometheus。或者更准确地说，这不是获取指标的常见方式。相反，Prometheus 是一个基于拉取的系统，定期从导出器中获取指标。我们可以使用许多第三方导出器。但是，在我们的情况下，最关键的导出器已经内置到 Kubernetes 中。Prometheus 可以从一个将信息从 Kube API 转换的导出器中拉取数据。通过它，我们可以获取（几乎）我们可能需要的所有信息。或者至少，这就是大部分信息将来自的地方。

最后，如果我们在出现问题时没有得到通知，将在 Prometheus 中存储的指标没有太大用处。即使我们将 Prometheus 与 Grafana 集成，那也只会为我们提供仪表板。我假设你有更重要的事情要做，而不是盯着五颜六色的图表。因此，我们需要一种方式将来自 Prometheus 的警报发送到 Slack，比如说。幸运的是，*Alertmanager*（[`prometheus.io/docs/alerting/alertmanager/`](https://prometheus.io/docs/alerting/alertmanager/)）允许我们做到这一点。这是一个由同一个社区维护的独立应用程序。

我们将通过实际操作来看看所有这些部分是如何组合在一起的。所以，让我们开始安装 Prometheus、Alertmanager 和其他一些应用程序。

# 对 Prometheus 和 Alertmanager 的快速介绍

我们将继续使用 Helm 作为安装机制。Prometheus 的 Helm Chart 是作为官方 Chart 之一进行维护的。您可以在项目的*README*中找到更多信息（[`github.com/helm/charts/tree/master/stable/prometheus`](https://github.com/helm/charts/tree/master/stable/prometheus)）。如果您关注*配置部分*中的变量（[`github.com/helm/charts/tree/master/stable/prometheus#configuration`](https://github.com/helm/charts/tree/master/stable/prometheus#configuration)），您会注意到有很多东西可以调整。我们不会遍历所有变量。您可以查看官方文档。相反，我们将从基本设置开始，并随着我们的需求增加而扩展。

让我们来看看我们将作为起点使用的变量。

```
 1  cat mon/prom-values-bare.yml
```

输出如下。

```
server:
  ingress:
    enabled: true
    annotations:
      ingress.kubernetes.io/ssl-redirect: "false"
      nginx.ingress.kubernetes.io/ssl-redirect: "false"
  resources:
    limits:
      cpu: 100m
      memory: 1000Mi
    requests:
      cpu: 10m
      memory: 500Mi
alertmanager:
  ingress:
    enabled: true
    annotations:
      ingress.kubernetes.io/ssl-redirect: "false"
      nginx.ingress.kubernetes.io/ssl-redirect: "false"
  resources:
    limits:
      cpu: 10m
      memory: 20Mi
    requests:
      cpu: 5m
      memory: 10Mi
kubeStateMetrics:
  resources:
    limits:
      cpu: 10m
      memory: 50Mi
    requests:
      cpu: 5m
      memory: 25Mi
nodeExporter:
  resources:
    limits:
      cpu: 10m
      memory: 20Mi
    requests:
      cpu: 5m
      memory: 10Mi
pushgateway:
  resources:
    limits:
      cpu: 10m
      memory: 20Mi
        requests:
      cpu: 5m
      memory: 10Mi
```

目前我们所做的一切都是为我们将安装的所有五个应用程序定义`资源`，以及使用一些注释启用 Ingress，这些注释将确保我们不会被重定向到 HTTPS 版本，因为我们没有我们的临时域的证书。我们将在稍后深入研究将要安装的应用程序。目前，我们将定义 Prometheus 和 Alertmanager UI 的地址。

```
 1  PROM_ADDR=mon.$LB_IP.nip.io
 2
 3  AM_ADDR=alertmanager.$LB_IP.nip.io
```

让我们安装图表。

```
 1  helm install stable/prometheus \
 2      --name prometheus \
 3      --namespace metrics \
 4      --version 7.1.3 \
 5      --set server.ingress.hosts={$PROM_ADDR} \
 6      --set alertmanager.ingress.hosts={$AM_ADDR} \
 7      -f mon/prom-values-bare.yml
```

我们刚刚执行的命令应该是不言自明的，所以我们将跳转到输出的相关部分。

```
...
RESOURCES:
==> v1beta1/DaemonSet
NAME                     DESIRED CURRENT READY UP-TO-DATE AVAILABLE NODE SELECTOR AGE
prometheus-node-exporter 3       3       0     3          0         <none>        3s 
==> v1beta1/Deployment
NAME                          DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
prometheus-alertmanager       1       1       1          0         3s
prometheus-kube-state-metrics 1       1       1          0         3s
prometheus-pushgateway        1       1       1          0         3s
prometheus-server             1       1       1          0         3s
...
```

我们可以看到，图表安装了一个 DeamonSet 和四个部署。

DeamonSet 是 Node Exporter，它将在集群的每个节点上运行一个 Pod。它提供特定于节点的指标，这些指标将被 Prometheus 拉取。第二个导出器（Kube State Metrics）作为单个副本部署运行。它从 Kube API 获取数据，并将其转换为 Prometheus 友好的格式。这两个将提供我们所需的大部分指标。稍后，我们可能选择使用其他导出器来扩展它们。目前，这两个连同直接从 Kube API 获取的指标应该提供比我们在单个章节中能吸收的更多的指标。

此外，我们有服务器，即 Prometheus 本身。Alertmanager 将警报转发到它们的目的地。最后，还有 Pushgateway，我们可能会在接下来的章节中探索它。

在等待所有这些应用程序变得可操作时，我们可以探索它们之间的流程。

Prometheus 服务器从出口商那里获取数据。在我们的情况下，这些是 Node Exporter 和 Kube State Metrics。这些出口商的工作是从源获取数据并将其转换为 Prometheus 友好的格式。Node Exporter 从节点上挂载的`/proc`和`/sys`卷获取数据，而 Kube State Metrics 从 Kube API 获取数据。指标在 Prometheus 内部存储。

除了能够查询这些数据，我们还可以定义警报。当警报达到阈值时，它将被转发到充当十字路口的 Alertmanager。

根据其内部规则，它可以将这些警报进一步转发到各种目的地，如 Slack、电子邮件和 HipChat（仅举几例）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/701f20e3-39b9-495f-b689-ccf64772ece1.png)图 3-1：数据流向和从 Prometheus 流向的流程（箭头表示方向）

到目前为止，Prometheus 服务器可能已经推出。我们会确认一下以防万一。

```
 1  kubectl -n metrics \
 2      rollout status \
 3      deploy prometheus-server
```

让我们来看看通过`prometheus-server`部署创建的 Pod 内部有什么。

```
 1  kubectl -n metrics \
 2      describe deployment \
 3      prometheus-server
```

输出，仅限于相关部分，如下所示。

```
  Containers:
   prometheus-server-configmap-reload:
    Image: jimmidyson/configmap-reload:v0.2.2
    ...
   prometheus-server:
    Image: prom/prometheus:v2.4.2
    ...
```

除了基于`prom/prometheus`镜像的容器外，我们还从`jimmidyson/configmap-reload`创建了另一个容器。后者的工作是在我们更改存储在 ConfigMap 中的配置时重新加载 Prometheus。

接下来，我们可能想看一下`prometheus-server` ConfigMap，因为它存储了 Prometheus 所需的所有配置。

```
 1  kubectl -n metrics \
 2      describe cm prometheus-server
```

输出，仅限于相关部分，如下所示。

```
...
Data
====
alerts:
----
{} 
prometheus.yml:
----
global:
  evaluation_interval: 1m
  scrape_interval: 1m
  scrape_timeout: 10s 
rule_files:
- /etc/config/rules
- /etc/config/alerts
scrape_configs:
- job_name: prometheus
  static_configs:
  - targets:
    - localhost:9090
- bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  job_name: kubernetes-apiservers
  kubernetes_sd_configs:
  - role: endpoints
  relabel_configs:
  - action: keep
    regex: default;kubernetes;https
    source_labels:
    - __meta_kubernetes_namespace
    - __meta_kubernetes_service_name
    - __meta_kubernetes_endpoint_port_name
  scheme: https
  tls_config:
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    insecure_skip_verify: true
...
```

我们可以看到`alerts`仍然是空的。我们很快会改变这一点。

更下面是`prometheus.yml`配置，其中`scrape_configs`占据了大部分空间。我们可以花一个章节的时间来解释当前的配置以及我们可以修改它的方式。我们不会这样做，因为你面前的配置接近疯狂。这是如何使事情变得比应该更复杂的最佳例子。在大多数情况下，您应该保持不变。如果您确实想要玩弄它，请咨询官方文档。

接下来，我们将快速查看 Prometheus 的屏幕。

对于 Windows 用户，Git Bash 可能无法使用`open`命令。如果是这种情况，请用`echo`替换`open`。结果，您将获得应直接在您选择的浏览器中打开的完整地址。

```
 1  open "http://$PROM_ADDR/config"
```

配置屏幕反映了我们已经在`prometheus-server` ConfigMap 中看到的相同信息，所以我们将继续。

接下来，让我们来看看这些目标。

```
 1  open "http://$PROM_ADDR/targets"
```

该屏幕包含七个目标，每个目标提供不同的指标。Prometheus 定期从这些目标中拉取数据。

本章中的所有输出和截图都来自 AKS。根据您的 Kubernetes 版本，可能会看到一些差异。您可能会注意到，本章包含的截图比其他章节多得多。尽管看起来可能有点多，但我想确保您可以将您的结果与我的进行比较，因为不可避免地会有一些差异，有时可能会让人感到困惑，如果没有参考（我的截图）的话。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/f207a763-f021-4f45-966b-948bae855230.png)图 3-2：Prometheus 的目标屏幕 AKS 用户注意*kubernetes-apiservers*目标可能是红色的，表示 Prometheus 无法连接到它。这没关系，因为我们不会使用它的指标。minikube 用户注意*kubernetes-service-endpoints*目标可能有一些红色的来源。没有理由担心。这些是不可访问的，但这不会影响我们的练习。

我们无法从屏幕上找出每个目标提供什么。我们将尝试以与 Prometheus 拉取它们相同的方式查询导出器。

为了做到这一点，我们需要找出可以访问导出器的服务。

```
 1  kubectl -n metrics get svc
```

来自 AKS 的输出如下。

```
NAME                          TYPE      CLUSTER-IP    EXTERNAL-IP PORT(S)  AGE
prometheus-alertmanager       ClusterIP 10.23.245.165 <none>      80/TCP   41d
prometheus-kube-state-metrics ClusterIP None          <none>      80/TCP   41d
prometheus-node-exporter      ClusterIP None          <none>      9100/TCP 41d
prometheus-pushgateway        ClusterIP 10.23.244.47  <none>      9091/TCP 41d
prometheus-server             ClusterIP 10.23.241.182 <none>      80/TCP   41d
```

我们对`prometheus-kube-state-metrics`和`prometheus-node-exporter`感兴趣，因为它们提供了访问本章中将使用的导出器的数据。

接下来，我们将创建一个临时 Pod，通过它我们将访问那些服务后面的导出器提供的数据。

```
 1  kubectl -n metrics run -it test \
 2      --image=appropriate/curl \
 3      --restart=Never \
 4      --rm \
 5      -- prometheus-node-exporter:9100/metrics
```

我们基于`appropriate/curl`创建了一个新的 Pod。该镜像只提供`curl`的单一目的。我们指定`prometheus-node-exporter:9100/metrics`作为命令，这相当于使用该地址运行`curl`。结果，输出了大量指标。它们都以相同的“键/值”格式呈现，可选标签用大括号（`{`和`}`）括起来。在每个指标的顶部，都有一个`HELP`条目，解释了其功能以及`TYPE`（例如，`gauge`）。其中一个指标如下。

```
 1  # HELP node_memory_MemTotal_bytes Memory information field
    MemTotal_bytes.
 2  # TYPE node_memory_MemTotal_bytes gauge
 3  node_memory_MemTotal_bytes 3.878477824e+09
```

我们可以看到它提供了“内存信息字段 MemTotal_bytes”，类型为`gauge`。在`TYPE`下面是实际的指标，带有键（`node_memory_MemTotal_bytes`）和值`3.878477824e+09`。

大多数 Node Exporter 指标都没有标签。因此，我们将不得不在`prometheus-kube-state-metrics`导出器中寻找一个示例。

```
 1  kubectl -n metrics run -it test \
 2      --image=appropriate/curl \
 3      --restart=Never \
 4      --rm \
 5      -- prometheus-kube-state-metrics:8080/metrics
```

正如您所看到的，Kube 状态指标遵循与节点导出器相同的模式。主要区别在于大多数指标都有标签。一个例子如下。

```
 1  kube_deployment_created{deployment="prometheus-
    server",namespace="metrics"} 1.535566512e+09
```

该指标表示在`metrics`命名空间内创建`prometheus-server`部署的时间。

我会让你更详细地探索这些指标。我们很快将使用其中的许多。

现在，只需记住，通过来自节点导出器、Kube 状态指标以及来自 Kubernetes 本身的指标的组合，我们可以满足大部分需求。或者更准确地说，这些数据提供了大部分基本和常见用例所需的数据。

接下来，我们将查看警报屏幕。

```
 1  open "http://$PROM_ADDR/alerts"
```

屏幕是空的。不要绝望。我们将会多次返回到那个屏幕。随着我们的进展，警报将会增加。现在，只需记住那里是您可以找到警报的地方。

最后，我们将打开图形屏幕。

```
 1  open "http://$PROM_ADDR/graph"
```

那里是您将花费时间调试通过警报发现的问题的地方。

作为我们的第一个任务，我们将尝试检索有关我们节点的信息。我们将使用`kube_node_info`，所以让我们看一下它的描述（帮助）和类型。

```
 1  kubectl -n metrics run -it test \
 2      --image=appropriate/curl \
 3      --restart=Never \
 4      --rm \
 5      -- prometheus-kube-state-metrics:8080/metrics \
 6      | grep "kube_node_info"
```

输出，仅限于`HELP`和`TYPE`条目，如下所示。

```
 1  # HELP kube_node_info Information about a cluster node.
 2  # TYPE kube_node_info gauge
 3  ...
```

您可能会看到您的结果与我的结果之间的差异。这是正常的，因为我们的集群可能具有不同数量的资源，我的带宽可能不同，等等。在某些情况下，我的警报会触发，而您的不会，或者反之。我会尽力解释我的经验并提供伴随它们的截图。您将不得不将其与您在屏幕上看到的内容进行比较。

现在，让我们尝试在 Prometheus 中使用该指标。

请在表达式字段中输入以下查询。

```
 1  kube_node_info
```

点击“执行”按钮以检索`kube_node_info`指标的值。

与以往章节不同，这个章节的 Gist（`03-monitor.sh` ([`gist.github.com/vfarcic/718886797a247f2f9ad4002f17e9ebd9`](https://gist.github.com/vfarcic/718886797a247f2f9ad4002f17e9ebd9)）不仅包含命令，还包含 Prometheus 表达式。它们都被注释了（使用`#`）。如果您打算从 Gist 中复制并粘贴表达式，请排除注释。每个表达式顶部都有`# Prometheus expression`的注释，以帮助您识别它。例如，您刚刚执行的表达式在 Gist 中的写法如下。`# Prometheus expression` `# kube_node_info`

如果您检查`kube_node_info`的`HELP`条目，您会看到它提供了`有关集群节点的信息`，并且它是一个`仪表`。**仪表**([`prometheus.io/docs/concepts/metric_types/#gauge`](https://prometheus.io/docs/concepts/metric_types/#gauge))是表示单个数值的度量，可以任意上升或下降。

关于节点的信息是有道理的，因为它们的数量可能随时间增加或减少。

Prometheus 的仪表是表示单个数值的度量，可以任意上升或下降。

如果我们关注输出，您会注意到条目的数量与集群中的工作节点数量相同。在这种情况下，值（`1`）在这种情况下是无用的。另一方面，标签可以提供一些有用的信息。例如，在我的情况下，操作系统（`os_image`）是`Ubuntu 16.04.5 LTS`。通过这个例子，我们可以看到我们不仅可以使用度量来计算值（例如，可用内存），还可以一窥系统的具体情况。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/f2eea74f-64b6-4499-887d-fa8f42a957ef.png)图 3-3：Prometheus 的控制台输出 kube_node_info 度量

让我们看看是否可以通过将该度量与 Prometheus 的一个函数结合来获得更有意义的查询。我们将`count`集群中工作节点的数量。`count`是 Prometheus 的*聚合运算符*之一([`prometheus.io/docs/prometheus/latest/querying/operators/#aggregation-operators`](https://prometheus.io/docs/prometheus/latest/querying/operators/#aggregation-operators))。

请执行接下来的表达式。

```
 1  count(kube_node_info)
```

输出应该显示集群中工作节点的总数。在我的情况下（AKS），有`3`个。乍一看，这可能并不是非常有用。您可能认为，即使没有 Prometheus，您也应该知道集群中有多少个节点。但这可能并不正确。其中一个节点可能已经失败，并且没有恢复。如果您在本地运行集群而没有扩展组，这一点尤其正确。或者 Cluster Autoscaler 增加或减少了节点的数量。一切都会随时间而改变，无论是由于故障，人为行为，还是通过自适应的系统。无论波动的原因是什么，当某些情况达到阈值时，我们可能希望得到通知。我们将以节点作为第一个例子。

我们的任务是定义一个警报，如果集群中的节点超过三个或少于一个，将通知我们。我们假设这些是我们的限制，并且我们想知道是由于故障还是集群自动缩放而达到了下限或上限。

我们将看一下 Prometheus Chart 值的新定义。由于定义很大，并且会随着时间增长，所以从现在开始，我们只会关注其中的差异。

```
 1  diff mon/prom-values-bare.yml \
 2      mon/prom-values-nodes.yml
```

输出如下。

```
> serverFiles:
>   alerts:
>     groups:
>     - name: nodes
>       rules:
>       - alert: TooManyNodes
>         expr: count(kube_node_info) > 3
>         for: 15m
>         labels:
>           severity: notify
>         annotations:
>           summary: Cluster increased
>           description: The number of the nodes in the cluster increased
>       - alert: TooFewNodes
>         expr: count(kube_node_info) < 1
>         for: 15m
>         labels:
>           severity: notify
>         annotations:
>           summary: Cluster decreased
>           description: The number of the nodes in the cluster decreased
```

我们添加了一个新条目`serverFiles.alerts`。如果您查看 Prometheus 的 Helm 文档，您会发现它允许我们定义警报（因此得名）。在其中，我们使用了“标准”Prometheus 语法来定义警报。

请参阅*Alerting Rules documentation* ([`prometheus.io/docs/prometheus/latest/configuration/alerting_rules/`](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)) 以获取有关语法的更多信息。

我们只定义了一个名为`nodes`的规则组。里面有两个`rules`。第一个规则（`TooManyNodes`）会在超过`15`分钟内有超过`3`个节点时通知我们。另一个规则（`TooFewNodes`）则相反，会在`15`分钟内没有节点（`<1`）时通知我们。这两个规则都有`labels`和`annotations`，目前仅用于信息目的。稍后我们会看到它们的真正用途。

让我们升级我们的 Prometheus Chart 并查看新警报的效果。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-nodes.yml
```

新配置被“发现”并重新加载 Prometheus 需要一些时间。过一会儿，我们可以打开 Prometheus 警报屏幕，检查是否有我们的第一个条目。

从现在开始，我不会（太多）评论需要等待一段时间直到下一个配置传播的需要。如果您在屏幕上看到的与您期望的不一致，请稍等片刻并刷新一下。

```
 1  open "http://$PROM_ADDR/alerts"
```

您应该会看到两个警报。

由于没有一个评估为`true`，所以这两个警报都是绿色的。根据您选择的 Kubernetes 版本，您可能只有一个节点（例如，Docker for Desktop 和 minikube），或者有三个节点（例如，GKE，EKS，AKS）。由于我们的警报检查了我们是否有少于一个或多于三个节点，无论您使用哪种 Kubernetes 版本，都不满足任何条件。

如果您的集群不是通过本章开头提供的 Gists 之一创建的，那么您的集群可能有超过三个节点，并且警报将触发。如果是这种情况，我建议您修改`mon/prom-values-nodes.yml`文件以调整警报的阈值。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c8da3d50-5320-4ddc-b3ed-5175750546d8.png)图 3-4：Prometheus 的警报屏幕

看到无效的警报很无聊，所以我想向您展示一个触发的警报（变为红色）。为了做到这一点，我们可以向集群添加更多节点（除非您正在使用像 Docker for Desktop 和 minikube 这样的单节点集群）。但是，修改一个警报的表达式会更容易，所以下面我们将这样做。

```
 1  diff mon/prom-values-nodes.yml \
 2      mon/prom-values-nodes-0.yml
```

输出如下。

```
57,58c57,58
< expr: count(kube_node_info) > 3
< for: 15m
---
> expr: count(kube_node_info) > 0
> for: 1m
66c66
< for: 15m
---
> for: 1m
```

新的定义将`TooManyNodes`警报的条件更改为如果节点数大于零则触发。我们还修改了`for`语句，这样在警报触发之前我们不需要等待`15`分钟。

让我们再次升级 Chart。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-nodes-0.yml
```

...然后我们将返回到警报屏幕。

```
 1  open "http://$PROM_ADDR/alerts"
```

几分钟后（不要忘记刷新屏幕），警报将转为挂起状态，颜色将变为黄色。这意味着警报的条件已经满足（我们确实有超过零个节点），但`for`时间段尚未到期。

等待一分钟（`for`时间段的持续时间）并刷新屏幕。警报状态已切换为触发，并且颜色变为红色。Prometheus 发送了我们的第一个警报。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/cb890924-63a6-49f3-953b-783f7495ba3b.png)图 3-5：Prometheus 的警报屏幕，其中一个警报触发

警报发送到了哪里？Prometheus Helm Chart 部署了 Alertmanager，并预先配置了 Prometheus 将其警报发送到那里。让我们来看看它的 UI。

```
 1  open "http://$AM_ADDR"
```

我们可以看到一个警报已经到达了 Alertmanager。如果我们点击`TooManyNodes`警报旁边的+信息按钮，我们将看到注释（摘要和描述）以及标签（严重程度）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/2de2ea86-984f-4529-ad8a-f54a3680104a.png)图 3-6：Alertmanager UI，其中一个警报已展开

我们可能不会坐在 Alertmanager 前等待问题出现。如果这是我们的目标，我们也可以在 Prometheus 中等待警报。

显示警报确实不是我们拥有 Alertmanager 的原因。它应该接收警报并进一步分发它们。它之所以没有做任何这样的事情，只是因为我们还没有定义它应该用来转发警报的规则。这是我们的下一个任务。

我们将看一下 Prometheus Chart 值的另一个更新。

```
 1  diff mon/prom-values-nodes-0.yml \
 2      mon/prom-values-nodes-am.yml
```

输出如下。

```
71a72,93
> alertmanagerFiles:
>   alertmanager.yml:
>     global: {}
>     route:
>       group_wait: 10s
>       group_interval: 5m
>       receiver: slack
>       repeat_interval: 3h
>       routes:
>       - receiver: slack
>         repeat_interval: 5d
>         match:
>           severity: notify
>           frequency: low
>     receivers:
>     - name: slack
>       slack_configs:
>       - api_url: "https://hooks.slack.com/services/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"
>         send_resolved: true
>         title: "{{ .CommonAnnotations.summary }}"
>         text: "{{ .CommonAnnotations.description }}"
>         title_link: http://my-prometheus.com/alerts
```

当我们应用该定义时，我们将向 Alertmanager 添加`alertmanager.yml`文件。如果包含了它应该用来分发警报的规则。`route`部分包含了将应用于所有不匹配任何一个`routes`的警报的一般规则。`group_wait`值使 Alertmanager 在同一组的其他警报到达时等待`10`秒。这样，我们将避免接收到相同类型的多个警报。

当一组中的第一个警报被发送时，它将在发送同一组的新警报的下一批之前使用`group_interval`字段（`5m`）的值。

`route`部分中的`receiver`字段定义了警报的默认目的地。这些目的地在下面的`receivers`部分中定义。在我们的情况下，我们默认将警报发送到`slack`接收器。

`repeat_interval`（设置为`3h`）定义了如果 Alertmanager 继续接收警报，警报将在之后的时间段内重新发送。

`routes`部分定义了具体的规则。只有当它们都不匹配时，才会使用上面`route`部分中的规则。`routes`部分继承自上面的属性，因此只有我们在这个部分中定义的规则会改变。我们将继续将匹配的`routes`发送到`slack`，唯一的变化是将`repeat_interval`从`3h`增加到`5d`。

`routes`的关键部分是`match`部分。它定义了用于决定警报是否匹配的过滤器。在我们的情况下，只有那些带有标签`severity: notify`和`frequency: low`的警报才会被视为匹配。

总的来说，带有`severity`标签设置为`notify`和`frequency`设置为`low`的警报将每五天重新发送一次。所有其他警报的频率为三小时。

我们 Alertmanager 配置的最后一部分是`receivers`。我们只有一个名为`slack`的接收器。在`name`下面是`slack_config`。它包含特定于 Slack 的配置。我们可以使用`hipchat_config`，`pagerduty_config`或任何其他受支持的配置。即使我们的目的地不是其中之一，我们也可以始终退回到`webhook_config`并向我们选择的工具的 API 发送自定义请求。

有关所有受支持的`receivers`列表，请参阅*Alertmanager 配置*页面 ([`prometheus.io/docs/alerting/configuration/`](https://prometheus.io/docs/alerting/configuration/))。

在`slack_configs`部分中，我们有包含来自*devops20*频道中一个房间令牌的 Slack 地址的`api_url`。

有关如何为您的 Slack 频道生成传入 Webhook 地址的信息，请访问*传入 Webhooks*页面 ([`api.slack.com/incoming-webhooks`](https://api.slack.com/incoming-webhooks))。

接下来是`send_resolved`标志。当设置为`true`时，Alertmanager 将在警报触发时发送通知，也会在导致问题解决时发送通知。

我们使用`summary`注释作为消息的`title`，并使用`description`注释作为`text`。两者都使用*Go 模板* ([`golang.org/pkg/text/template/`](https://golang.org/pkg/text/template/))。这些是我们在 Prometheus 警报中定义的相同注释。

最后，`title_link`设置为`http://my-prometheus.com/alerts`。这确实不是您的 Prometheus UI 的地址，但由于我事先无法知道您的域名是什么，我放了一个不存在的域名。请随意将`my-prometheus.com`更改为环境变量`$PROM_ADDR`的值。或者保持不变，知道如果您单击该链接，它将不会将您带到您的 Prometheus UI。

现在我们已经探索了 Alertmanager 配置，我们可以继续并升级图表。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-nodes-am.yml
```

几分钟后，Alertmanager 将被重新配置，下次它从 Prometheus 接收到警报时，它将将其发送到 Slack。我们可以通过访问`devops20.slack.com`工作区来确认。如果您尚未注册，请访问[slack.devops20toolkit.com](http://slack.devops20toolkit.com)。一旦您成为会员，我们可以访问`devops25-tests`频道。

```
 1  open "https://devops20.slack.com/messages/CD8QJA8DS/"
```

你应该看到`集群增加`通知。如果你看到其他消息，不要感到困惑。你可能不是唯一一个在运行本书练习的人。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/d1936f65-8d48-452a-91f0-03da31c126ca.png)图 3-7：从 Alertmanager 接收到的 Slack 警报消息有时，由于我无法弄清楚的原因，Slack 会收到来自 Alertmanager 的空通知。目前，我因懒惰而忽略了这个问题。

现在我们已经了解了 Prometheus 和 Alertmanager 的基本用法，我们将暂停一下手动操作，并讨论我们可能想要使用的指标类型。

# 我们应该使用哪种指标类型？

如果这是你第一次使用连接到 Kube API 的 Prometheus 指标，可能会感到压力很大。除此之外，还要考虑到配置排除了 Kube API 提供的许多指标，并且我们可以通过额外的导出器进一步扩展范围。

虽然每种情况都是不同的，你可能需要一些特定于你的组织和架构的指标，但是有一些指导方针我们应该遵循。在本节中，我们将讨论关键指标。一旦你通过几个例子理解了它们，你应该能够将它们扩展到你特定的用例中。

每个人都应该利用的四个关键指标是延迟、流量、错误和饱和度。

这四个指标被谷歌的**网站可靠性工程师**（**SREs**）推崇为跟踪系统性能和健康状况的最基本指标。

**延迟**代表服务响应请求所需的时间。重点不仅应该放在持续时间上，还应该区分成功请求的延迟和失败请求的延迟。

**流量**是对服务所承受的需求的衡量。一个例子是每秒的 HTTP 请求次数。

**错误**是由请求失败的速率来衡量的。大多数情况下，这些失败是显式的（例如，HTTP 500 错误），但它们也可以是隐式的（例如，一个 HTTP 200 响应，其中的内容描述了查询没有返回任何结果）。

**饱和度**可以用来描述服务或系统的“充实程度”。一个典型的例子是缺乏 CPU 导致节流，从而降低了应用程序的性能。

随着时间的推移，不同的监控方法被开发出来。例如，我们得到了**USE**方法，该方法规定对于每个资源，我们应该检查**利用率**、**饱和度**和**错误**。另一个是**RED**方法，它将**速率**、**错误**和**持续时间**定义为关键指标。这些和许多其他方法在本质上是相似的，并且与 SRE 对于测量延迟、流量、错误和饱和度的需求没有明显的区别。

我们将逐个讨论 SRE 描述的四种测量类型，并提供一些示例。我们甚至可能会扩展它们，加入一些不一定适合任何四类的指标。首先是延迟。

# 延迟相关问题的警报

我们将使用`go-demo-5`应用程序来测量延迟，所以我们的第一步是安装它。

```
 1  GD5_ADDR=go-demo-5.$LB_IP.nip.io
 2
 3  helm install \
 4      https://github.com/vfarcic/go-demo-5/releases/download/
    0.0.1/go-demo-5-0.0.1.tgz \
 5      --name go-demo-5 \
 6      --namespace go-demo-5 \
 7      --set ingress.host=$GD5_ADDR
```

我们生成了一个地址，我们将用作 Ingress 入口点，并使用 Helm 部署了应用程序。现在我们应该等待直到它完全部署。

```
 1  kubectl -n go-demo-5 \
 2      rollout status \
 3      deployment go-demo-5
```

在继续之前，我们将检查应用程序是否确实通过发送 HTTP 请求正确工作。

```
 1  curl "http://$GD5_ADDR/demo/hello"
```

输出应该是熟悉的`hello, world!`消息。

现在，让我们看看是否可以，例如，通过 Ingress 进入系统的请求的持续时间。

```
 1  open "http://$PROM_ADDR/graph"
```

如果您点击“在光标处插入指标”下拉列表，您将能够浏览所有可用的指标。我们正在寻找的是`nginx_ingress_controller_request_duration_seconds_bucket`。正如其名称所示，该指标来自 NGINX Ingress Controller，并提供以秒为单位分组的请求持续时间。

请键入以下表达式，然后单击“执行”按钮。

```
 1  nginx_ingress_controller_request_duration_seconds_bucket
```

在这种情况下，查看原始值可能并不是非常有用，所以请点击“图表”选项卡。

您应该看到图表，每个 Ingress 都有一个。每个图表都在增加，因为所讨论的指标是一个计数器 ([`prometheus.io/docs/concepts/metric_types/#counter`](https://prometheus.io/docs/concepts/metric_types/#counter))。它的值随着每个请求而增加。

Prometheus 计数器是一个累积指标，其值只能增加，或者在重新启动时重置为零。

我们需要计算一段时间内的请求速率。我们将通过结合`sum`和`rate` ([`prometheus.io/docs/prometheus/latest/querying/functions/#rate()`](https://prometheus.io/docs/prometheus/latest/querying/functions/#rate())) 函数来实现这一点。前者应该是不言自明的。

Prometheus 的速率函数计算了范围向量中时间序列的每秒平均增长率。

请输入以下表达式，然后点击“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_count[5m]
 3  )) 
 4  by (ingress)
```

结果图表向我们显示了通过 Ingress 进入系统的所有请求的每秒速率。速率是基于五分钟的间隔计算的。如果您将鼠标悬停在其中一条线上，您将看到额外的信息，如值和 Ingress。`by`语句允许我们按`ingress`对结果进行分组。

尽管如此，单独的结果并不是非常有用，因此让我们重新定义我们的需求。我们应该能够找出有多少请求比 0.25 秒慢。我们无法直接做到这一点。相反，我们可以检索所有那些 0.25 秒或更快的请求。

请输入以下表达式，然后点击“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.25"
 4    }[5m]
 5  )) 
 6  by (ingress)
```

我们真正想要的是找出落入 0.25 秒区间的请求的百分比。为了实现这一点，我们将获取快于或等于 0.25 秒的请求的速率，并将结果除以所有请求的速率。

请输入以下表达式，然后点击“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.25"
 4    }[5m]
 5  )) 
 6  by (ingress) / 
 7  sum(rate(
 8    nginx_ingress_controller_request_duration_seconds_count[5m]
 9  )) 
10  by (ingress)
```

由于我们尚未生成太多流量，您可能在图表中看不到太多内容，除了偶尔与 Prometheus 和 Alertmanager 的交互以及我们发送到`go-demo-5`的单个请求。尽管如此，您可以看到的几行显示了响应时间在 0.25 秒内的请求的百分比。

目前，我们只对`go-demo-5`的请求感兴趣，因此我们将进一步完善表达式，将结果限制为仅限于`go-demo-5`的 Ingress。

请输入以下表达式，然后点击“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.25", 
 4      ingress="go-demo-5"
 5    }[5m]
 6  )) 
 7  by (ingress) / 
 8  sum(rate(
 9    nginx_ingress_controller_request_duration_seconds_count{
10      ingress="go-demo-5"
11    }[5m]
12  )) 
13  by (ingress)
```

由于我们只发送了一个请求，图表应该几乎是空的。或者，您可能收到了“未找到数据点”的消息。现在是时候生成一些流量了。

```
 1  for i in {1..30}; do
 2    DELAY=$[ $RANDOM % 1000 ]
 3    curl "http://$GD5_ADDR/demo/hello?delay=$DELAY"
 4  done
```

我们向`go-demo-5`发送了 30 个请求。该应用程序具有延迟响应请求的“隐藏”功能。鉴于我们希望生成具有随机响应时间的流量，我们使用了`DELAY`变量，其随机值最多为 1000 毫秒。现在我们可以重新运行相同的查询，看看是否可以获得一些更有意义的数据。

请等一会儿，直到收集到新请求的数据，然后在 Prometheus 中输入以下表达式，然后点击“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.25", 
 4      ingress="go-demo-5"
 5    }[5m]
 6  )) 
 7  by (ingress) / 
 8  sum(rate(
 9    nginx_ingress_controller_request_duration_seconds_count{
10      ingress="go-demo-5"
11    }[5m]
12  )) 
13  by (ingress)
```

这次，我们可以看到新行的出现。在我的情况下（随后的屏幕截图），大约百分之二十五的请求持续时间在 0.25 秒内。换句话说，大约四分之一的请求比预期慢。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/399a7670-e5f9-4753-8c2e-a02ef8ef2241.png)图 3-8：带有 0.25 秒持续时间请求百分比的 Prometheus 图表屏幕

过滤特定应用程序（Ingress）的指标在我们知道存在问题并希望进一步挖掘时非常有用。但是，我们仍然需要一个警报，告诉我们存在问题。因此，我们将执行类似的查询，但这次不限制结果为特定应用程序（Ingress）。我们还必须定义一个条件来触发警报，因此我们将将阈值设置为百分之九十五（0.95）。如果没有这样的阈值，每次单个请求变慢时我们都会收到通知。结果，我们会被警报淹没，并很快开始忽视它们。毕竟，如果单个请求变慢，系统并不会有危险，只有当有相当数量的请求变慢时才会有危险。在我们的情况下，这是百分之五的慢请求，或者更准确地说，少于百分之九十五的快速请求。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.25"
 4    }[5m]
 5  ))
 6  by (ingress) /
 7  sum(rate(
 8    nginx_ingress_controller_request_duration_seconds_count[5m]
 9  ))
10  by (ingress) < 0.95
```

我们可以偶尔看到少于百分之九十五的请求在 0.25 秒内。在我的情况下（随后的屏幕截图），我们可以看到 Prometheus、Alertmanager 和`go-demo-5`偶尔变慢。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/35c99ae7-7fd0-453c-bc6f-0d4b25288425.png)图 3-9：带有 0.25 秒持续时间请求百分比的 Prometheus 图表屏幕，仅限于高于百分之九十五的结果

唯一缺少的是基于先前表达式定义警报。因此，每当少于百分之九十五的请求持续时间少于 0.25 秒时，我们应该收到通知。

我准备了一组更新后的 Prometheus 图表数值，让我们看看与我们当前使用的图表的差异。

```
 1  diff mon/prom-values-nodes-am.yml \
 2      mon/prom-values-latency.yml
```

输出如下。

```
53a54,62
> - name: latency
>   rules:
>   - alert: AppTooSlow
>     expr: sum(rate(nginx_ingress_controller_request_duration_seconds_bucket{le= "0.25"}[5m])) by (ingress) / sum(rate(nginx_ingress_controller_request_duration_seconds_count[5m])) by (ingress) < 0.95
>     labels:
>       severity: notify
>     annotations:
>       summary: Application is too slow
>       description: More then 5% of requests are slower than 0.25s
57c66
<     expr: count(kube_node_info) > 0
---
>     expr: count(kube_node_info) > 3
```

我们添加了一个新的警报`AppTooSlow`。如果持续时间为 0.25 秒或更短的请求的百分比小于百分之九十五（`0.95`），它将触发。

我们还将`TooManyNodes`的阈值恢复为其原始值`3`。

接下来，我们将使用新值更新`prometheus`图表，并打开警报屏幕以确认是否确实添加了新警报。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-latency.yml
 8
 9  open "http://$PROM_ADDR/alerts"
```

如果`AppTooSlow`警报仍然不可用，请稍等片刻并刷新屏幕。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/68c98ad5-8654-4de8-b3d3-f34e05f3ce6e.png)图 3-10：Prometheus 警报屏幕

新增的警报可能是绿色的（不会触发）。我们需要生成一些慢请求来看它的作用。

请执行以下命令，发送 30 个具有随机响应时间的请求，最长为 10000 毫秒（10 秒）。

```
 1  for i in {1..30}; do
 2    DELAY=$[ $RANDOM % 10000 ]
 3    curl "http://$GD5_ADDR/demo/hello?delay=$DELAY"
 4  done
```

直到 Prometheus 抓取新的指标并且警报检测到阈值已达到，需要一些时间。过一会儿，我们可以再次打开警报屏幕，检查警报是否确实触发。

```
 1  open "http://$PROM_ADDR/alerts"
```

我们可以看到警报的状态是触发。如果这不是您的情况，请再等一会儿并刷新屏幕。在我的情况下（随后的截图），该值为 0.125，意味着只有 12.5％的请求持续时间为 0.25 秒或更短。

如果`prometheus-server`，`prometheus-alertmanager`或其他一些应用程序响应缓慢，`AppTooSlow`内可能会有两个或更多活动警报。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/17e9cd6e-41dc-486b-9ee1-cfaf8eedb886.png)图 3-11：带有一个触发警报的 Prometheus 警报屏幕

警报是红色的，意味着 Prometheus 将其发送到 Alertmanager，后者又将其转发到 Slack。让我们确认一下。

```
 1  open "https://devops20.slack.com/messages/CD8QJA8DS/"
```

正如您所看到的（随后的截图），我们收到了两个通知。由于我们将`TooManyNodes`警报的阈值恢复为大于三个节点，并且我们的集群节点较少，因此 Prometheus 向 Alertmanager 发送了问题已解决的通知。结果，我们在 Slack 中收到了新的通知。这次，消息的颜色是绿色的。

接着，出现了一个新的红色消息，指示“应用程序太慢”。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/f8549f2d-8a88-4179-933a-57b9f13b7e5a.png)图 3-12：Slack 显示触发（红色）和解决（绿色）消息

我们经常不能依赖单一规则来适用于所有应用程序。例如，Prometheus 和 Jenkins 可能是内部应用程序的良好候选者，我们不能期望其响应时间低于 0.25 秒的百分之五。因此，我们可能需要进一步过滤警报。我们可以使用任意数量的标签来实现这一点。为了简单起见，我们将继续利用`ingress`标签，但这次我们将使用正则表达式来排除一些应用程序（Ingress）的警报。

让我们再次打开图表屏幕。

```
 1  open "http://$PROM_ADDR/graph"
```

请键入以下表达式，点击“执行”按钮，然后切换到*图表*选项卡。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.25", 
 4      ingress!~"prometheus-server|jenkins"
 5    }[5m]
 6  )) 
 7  by (ingress) / 
 8  sum(rate(
 9    nginx_ingress_controller_request_duration_seconds_count{
10      ingress!~"prometheus-server|jenkins"
11    }[5m]
12  )) 
13  by (ingress)
```

与之前的查询相比，新增的是`ingress!~"prometheus-server|jenkins"`过滤器。`!~`用于选择具有不与`prometheus-server|jenkins`字符串匹配的标签的指标。由于`|`等同于`or`语句，我们可以将该过滤器翻译为“所有不是`prometheus-server`或不是`jenkins`的内容”。我们的集群中没有 Jenkins。我只是想向您展示一种排除多个值的方法。

图 3-13：Prometheus 图表屏幕，显示了持续时间为 0.25 秒的请求百分比，结果不包括 prometheus-server 和 jenkins

我们可以再复杂一点，指定`ingress!~"prometheus.+|jenkins.+`作为过滤器。在这种情况下，它将排除所有名称以`prometheus`和`jenkins`开头的 Ingress。关键在于`.+`的添加，在正则表达式中，它匹配一个或多个任何字符的条目（`+`）。

我们不会详细解释正则表达式的语法。我希望您已经熟悉它。如果您不熟悉，您可能需要搜索一下或访问*正则表达式维基*页面（[`en.wikipedia.org/wiki/Regular_expression`](https://en.wikipedia.org/wiki/Regular_expression)）。

之前的表达式只检索不是`prometheus-server`和`jenkins`的结果。我们可能需要创建另一个表达式，只包括这两个。

请键入以下表达式，然后点击“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_request_duration_seconds_bucket{
 3      le="0.5",
 4      ingress=~"prometheus-server|jenkins"
 5    }[5m]
 6  )) 
 7  by (ingress) /
 8  sum(rate(
 9    nginx_ingress_controller_request_duration_seconds_count{
10      ingress=~"prometheus-server|jenkins"
11    }[5m]
12  ))
13  by (ingress)
```

与之前的表达式相比，唯一的区别是这次我们使用了`=~`运算符。它选择与提供的字符串匹配的标签。此外，桶（`le`）现在设置为`0.5`秒，因为这两个应用程序可能需要更多时间来响应，我们可以接受这一点。

在我的情况下，图表显示`prometheus-server`的请求百分比为百分之百，持续时间在 0.5 秒内（在您的情况下可能不是真的）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/1a0043b8-213c-4c76-9209-2fa3a1ca851a.png)图 3-14：Prometheus 图表屏幕，显示了持续 0.5 秒的请求百分比，以及仅包括 prometheus-server 和 jenkins 的结果

少数延迟示例应该足以让您了解这种类型的指标，所以我们将转向流量。

# 流量相关问题的警报

到目前为止，我们测量了应用程序的延迟，并创建了在达到基于请求持续时间的特定阈值时触发的警报。这些警报不是基于进入的请求数量（流量），而是基于慢请求的百分比。即使只有一个请求进入应用程序，只要持续时间超过阈值，`AppTooSlow`也会触发。为了完整起见，我们需要开始测量流量，或者更准确地说，是发送到每个应用程序和整个系统的请求数。通过这样做，我们可以知道我们的系统是否承受了很大的压力，并决定是否要扩展我们的应用程序，增加更多的工作人员，或者采取其他解决方案来缓解问题。如果请求的数量达到异常数字，清楚地表明我们正在遭受**拒绝服务**（**DoS**）攻击（[`en.wikipedia.org/wiki/Denial-of-service_attack`](https://en.wikipedia.org/wiki/Denial-of-service_attack)），我们甚至可以选择阻止部分传入流量。

我们将开始创建一些流量，以便我们可以用来可视化请求。

```
 1  for i in {1..100}; do
 2      curl "http://$GD5_ADDR/demo/hello"
 3  done
 4
 5  open "http://$PROM_ADDR/graph"
```

我们向`go-demo-5`应用程序发送了一百个请求，并打开了 Prometheus 的图表屏幕。

我们可以通过`nginx_ingress_controller_requests`获取进入 Ingress 控制器的请求数。由于它是一个计数器，我们可以继续使用`rate`函数结合`sum`。最后，我们可能想要按`ingress`标签对请求的速率进行分组。

请键入下面的表达式，按“执行”按钮，然后切换到*图表*选项卡。

```
 1  sum(rate(
 2    nginx_ingress_controller_requests[5m]
 3  ))
 4  by (ingress)
```

图表的右侧显示了一个峰值。它显示了通过具有相同名称的 Ingress 发送到`go-demo-5`应用程序的请求。

在我的情况下（随后的屏幕截图），峰值接近每秒一个请求（您的情况将不同）。

图 3-15：Prometheus 的图形屏幕显示请求数量的速率

我们可能更感兴趣的是每个应用程序每秒每个副本的请求数，因此我们的下一个任务是找到一种检索该数据的方法。由于`go-demo-5`是一个部署，我们可以使用`kube_deployment_status_replicas`。

请键入以下表达式，然后按“执行”按钮。

```
 1  kube_deployment_status_replicas
```

我们可以看到系统中每个部署的副本数量。在我的情况下，`go-demo-5` 应用程序以红色（后续截图）显示，有三个副本。

图 3-16：Prometheus 的图形屏幕显示部署的副本数量

接下来，我们应该组合这两个表达式，以获得每个副本每秒的请求数。然而，我们面临一个问题。要使两个指标结合，它们需要具有匹配的标签。`go-demo-5`的部署和入口都具有相同的名称，因此我们可以利用这一点，假设我们可以重命名其中一个标签。我们将借助`label_join`（[`prometheus.io/docs/prometheus/latest/querying/functions/#label_join()`](https://prometheus.io/docs/prometheus/latest/querying/functions/#label_join())）函数来实现这一点。

对于 v 中的每个时间序列，`label_join(v instant-vector, dst_label string, separator string, src_label_1 string, src_label_2 string, ...)`使用分隔符连接所有`src_labels`的值，并返回包含连接值的标签`dst_label`的时间序列。

如果之前对`label_join`函数的解释让你感到困惑，你并不孤单。相反，让我们通过一个示例来了解，该示例将通过添加`ingress`标签来转换`kube_deployment_status_replicas`，该标签将包含来自`deployment`标签的值。如果我们成功了，我们将能够将结果与`nginx_ingress_controller_requests`组合，因为两者都具有相同的匹配标签（`ingress`）。

请键入以下表达式，然后按“执行”按钮。

```
 1  label_join(
 2    kube_deployment_status_replicas,
 3    "ingress", 
 4    ",", 
 5    "deployment"
 6  )
```

由于这次我们主要关注标签的值，请通过点击选项卡切换到控制台视图。

从输出中可以看出，每个指标现在都包含一个额外的标签`ingress`，其值与`deployment`相同。

图 3-17：Prometheus 的控制台视图显示部署副本状态和从部署标签创建的新标签 ingress

现在我们可以结合这两个指标。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_requests[5m]
 3  ))
 4  by (ingress) /
 5  sum(label_join(
 6    kube_deployment_status_replicas,
 7    "ingress",
 8    ",",
 9    "deployment"
10  ))
11  by (ingress)
```

切换回*图表*视图。

我们计算了每个应用程序（`ingress`）的请求数量的速率，并将其除以每个应用程序（`ingress`）的副本总数。最终结果是每个应用程序（`ingress`）每个副本的请求数量的速率。

值得注意的是，我们无法检索每个特定副本的请求数量，而是每个副本的平均请求数量。在大多数情况下，这种方法应该有效，因为 Kubernetes 网络通常执行轮询，导致向每个副本发送的请求数量多少相同。

总的来说，现在我们知道我们的副本每秒收到多少请求。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/d4f2cc20-dd55-4a80-af2a-177918f74576.png)图 3-18：普罗米修斯图表屏幕，显示请求数量除以部署副本数量的速率

现在我们已经学会了如何编写一个表达式来检索每秒每个副本的请求数量的速率，我们应该将其转换为警报。

因此，让我们来看看普罗米修斯图表值的旧定义和新定义之间的区别。

```
 1  diff mon/prom-values-latency.yml \
 2      mon/prom-values-latency2.yml
```

输出如下。

```
62a63,69
> - alert: TooManyRequests
>   expr: sum(rate(nginx_ingress_controller_requests[5m])) by (ingress) / sum(label_join(kube_deployment_status_replicas, "ingress", ",", "deployment")) by (ingress) > 0.1
>   labels:
>     severity: notify
>   annotations:
>     summary: Too many requests
>     description: There is more than average of 1 requests per second per replica for at least one application
```

我们可以看到表达式几乎与我们在普罗米修斯图表屏幕中使用的表达式相同。唯一的区别是我们将阈值设置为`0.1`。因此，该警报应在副本每秒收到的请求数超过五分钟内计算的速率`0.1`时通知我们。你可能已经猜到，每秒`0.1`个请求是一个太低的数字，不能在生产中使用。然而，它将使我们能够轻松触发警报并看到它的作用。

现在，让我们升级我们的图表，并打开普罗米修斯的警报屏幕。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-latency2.yml
 8
 9  open "http://$PROM_ADDR/alerts"
```

请刷新屏幕，直到`TooManyRequests`警报出现。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/84c0a44a-b5bd-4f17-a428-6f1513dec3d7.png)图 3-19：普罗米修斯警报屏幕

接下来，我们将生成一些流量，以便我们可以看到警报是如何生成并通过 Alertmanager 发送到 Slack 的。

```
 1  for i in {1..200}; do
 2      curl "http://$GD5_ADDR/demo/hello"
 3  done
 4
 5  open "http://$PROM_ADDR/alerts"
```

我们发送了两百个请求，并重新打开了普罗米修斯的警报屏幕。现在我们应该刷新屏幕，直到`TooManyRequests`警报变为红色。

普罗米修斯一旦触发了警报，就会被发送到 Alertmanager，然后转发到 Slack。让我们确认一下。

```
 1  open "https://devops20.slack.com/messages/CD8QJA8DS/"
```

我们可以看到“请求过多”的通知，从而证明了这个警报的流程是有效的。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/499f9841-7cb1-4865-a6d1-b02dff0a4761.png)图 3-20：Slack 与警报消息

接下来，我们将转向与错误相关的指标。

# 关于错误相关问题的警报

我们应该时刻注意我们的应用程序或系统是否产生错误。然而，我们不能在第一次出现错误时就开始惊慌，因为那样会产生太多通知，我们很可能会忽略它们。

错误经常发生，许多错误是由自动修复的问题或由我们无法控制的情况引起的。如果我们要对每个错误执行操作，我们就需要一支全天候工作的人员团队，专门解决通常不需要解决的问题。举个例子，因为有一个单独的响应代码在 500 范围内而进入“恐慌”模式几乎肯定会产生永久性危机。相反，我们应该监视错误的比率与总请求数量的比较，并且只有在超过一定阈值时才做出反应。毕竟，如果一个错误持续存在，那么错误率肯定会增加。另一方面，如果错误率持续很低，这意味着问题已经被系统自动修复（例如，Kubernetes 重新安排了从失败节点中的 Pod）或者这是一个不重复的孤立案例。

我们的下一个任务是检索请求并根据它们的状态进行区分。如果我们能做到这一点，我们应该能够计算出错误的比率。

我们将从生成一些流量开始。

```
 1  for i in {1..100}; do
 2      curl "http://$GD5_ADDR/demo/hello"
 3  done
 4
 5  open "http://$PROM_ADDR/graph"
```

我们发送了一百个请求并打开了 Prometheus 的图形屏幕。

让我们看看我们之前使用的`nginx_ingress_controller_requests`指标是否提供了请求的状态。

请键入以下表达式，然后点击执行按钮。

```
 1  nginx_ingress_controller_requests
```

我们可以看到 Prometheus 最近抓取的所有数据。如果我们更加关注标签，我们会发现，其中包括`status`。我们可以使用它来根据请求的总数计算出错误的百分比（例如，500 范围内的错误）。

我们已经看到我们可以使用`ingress`标签来按应用程序分别计算，假设我们只对那些面向公众的应用程序感兴趣。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/adbe5b3c-eff0-4170-b518-20e9cb90f82d.png)图 3-21：通过 Ingress 进入的 Prometheus 控制台视图的请求

`go-demo-5`应用程序有一个特殊的端点`/demo/random-error`，它将生成随机的错误响应。大约每十个对该地址的请求中就会产生一个错误。我们可以用这个来测试我们的表达式。

```
 1  for i in {1..100}; do
 2    curl "http://$GD5_ADDR/demo/random-error"
 3  done
```

我们向`/demo/random-error`端点发送了一百个请求，大约有 10%的请求产生了错误（HTTP 状态码`500`）。

接下来，我们将不得不等待一段时间，让 Prometheus 抓取新的一批指标。之后，我们可以打开图表屏幕，尝试编写一个表达式，以检索我们应用程序的错误率。

```
 1  open "http://$PROM_ADDR/graph"
```

请键入以下表达式，然后按执行按钮。

```
 1  sum(rate(
 2    nginx_ingress_controller_requests{
 3      status=~"5.."
 4    }[5m]
 5  ))
 6  by (ingress) /
 7  sum(rate(
 8    nginx_ingress_controller_requests[5m]
 9  ))
10  by (ingress)
```

我们使用了`5..`正则表达式来计算按`ingress`分组的带有错误的请求的比率，并将结果除以所有请求的比率。结果按`ingress`分组。在我的情况下（随后的截图），结果大约为 4%（`0.04`）。Prometheus 尚未抓取所有指标，我预计在下一次抓取迭代中这个数字会接近 10%。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/080bb7c6-42d1-486b-9b17-4b938b5c1624.png)图 3-22：带有错误响应请求百分比的 Prometheus 图表屏幕

让我们比较图表值文件的更新版本与我们之前使用的版本。

```
 1  diff mon/prom-values-cpu-memory.yml \
 2      mon/prom-values-errors.yml
```

输出如下。

```
127a128,136
> - name: errors
>   rules:
>   - alert: TooManyErrors
>     expr: sum(rate(nginx_ingress_controller_requests{status=~"5.."}[5m])) by (ingress) / sum(rate(nginx_ingress_controller_requests[5m])) by (ingress) > 0.025
>     labels:
>       severity: error
>     annotations:
>       summary: Too many errors
>       description: At least one application produced more then 5% of error responses
```

如果错误率超过总请求率的 2.5%，警报将触发。

现在我们可以升级我们的 Prometheus 图表。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-errors.yml
```

我们可能不需要确认警报是否有效。我们已经看到 Prometheus 将所有警报发送到 Alertmanager，然后从那里转发到 Slack。

接下来，我们将转移到饱和度指标和警报。

# 饱和度相关问题的警报

饱和度衡量了我们的服务和系统的充实程度。如果我们的服务副本处理了太多的请求并被迫排队处理其中一些，我们应该意识到这一点。我们还应该监视我们的 CPU、内存、磁盘和其他资源的使用是否达到了临界限制。

现在，我们将专注于 CPU 使用率。我们将首先打开 Prometheus 的图表屏幕。

```
 1  open "http://$PROM_ADDR/graph"
```

让我们看看是否可以获得节点（`instance`）的 CPU 使用率。我们可以使用`node_cpu_seconds_total`指标来实现。但是，它被分成不同的模式，我们将不得不排除其中的一些模式，以获得“真实”的 CPU 使用率。这些将是`idle`，`iowait`，和任何类型的`guest`周期。

请键入以下表达式，然后按执行按钮。

```
 1  sum(rate(
 2    node_cpu_seconds_total{
 3      mode!="idle", 
 4      mode!="iowait", 
 5      mode!~"^(?:guest.*)$"
 6   }[5m]
 7  ))
 8  by (instance)
```

切换到*图表*视图。

输出代表了系统中 CPU 的实际使用情况。在我的情况下（以下是屏幕截图），除了临时的峰值，所有节点的 CPU 使用量都低于一百毫秒。

系统远未处于压力之下。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/52dcc7f8-4b9f-4e7f-b176-b73855232337.png)图 3-23：Prometheus 的图表屏幕，显示了按节点实例分组的 CPU 使用率

正如您已经注意到的，绝对数字很少有用。我们应该尝试发现使用的 CPU 百分比。我们需要找出我们的节点有多少 CPU。我们可以通过计算指标的数量来做到这一点。每个 CPU 都有自己的数据条目，每种模式都有一个。如果我们将结果限制在单个模式（例如`system`）上，我们应该能够获得 CPU 的总数。

请输入以下表达式，然后点击执行按钮。

```
 1  count(
 2    node_cpu_seconds_total{
 3      mode="system"
 4    }
 5  )
```

在我的情况下（以下是屏幕截图），总共有六个核心。如果您使用的是 GKE、EKS 或来自 Gists 的 AKS，您的情况可能也是六个。另一方面，如果您在 Docker for Desktop 或 minikube 中运行集群，结果应该是一个节点。

现在我们可以结合这两个查询来获取使用的 CPU 百分比

请输入以下表达式，然后点击执行按钮。

```
 1  sum(rate(
 2    node_cpu_seconds_total{
 3      mode!="idle", 
 4      mode!="iowait",
 5      mode!~"^(?:guest.*)$"
 6    }[5m]
 7  )) /
 8  count(
 9    node_cpu_seconds_total{
10      mode="system"
11    }
12  )
```

我们总结了使用的 CPU 速率，并将其除以 CPU 的总数。在我的情况下（以下是屏幕截图），当前仅使用了三到四个百分比的 CPU。

这并不奇怪，因为大部分系统都处于休眠状态。我们的集群现在并没有太多活动。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/2d2bf1f8-7ac6-4d21-a067-c6c523f0e45e.png)图 3-24：Prometheus 的图表屏幕，显示了可用 CPU 的百分比

现在我们知道如何获取整个集群使用的 CPU 百分比，我们将把注意力转向应用程序。

我们将尝试发现我们有多少可分配的核心。从应用程序的角度来看，至少当它们在 Kubernetes 中运行时，可分配的 CPU 显示了可以为 Pods 请求多少。可分配的 CPU 始终低于总 CPU。

请输入以下表达式，然后点击执行按钮。

```
 1  kube_node_status_allocatable_cpu_cores
```

输出应该低于我们的虚拟机使用的核心数。可分配的核心显示了可以分配给容器的 CPU 数量。更准确地说，可分配的核心是分配给节点的 CPU 数量减去系统级进程保留的数量。在我的情况下（以下是屏幕截图），几乎有两个完整的可分配 CPU。

图 3-25：Prometheus 的图表屏幕，显示集群中每个节点的可分配 CPU

然而，在这种情况下，我们对可分配的 CPU 总量感兴趣，因为我们试图发现我们的 Pods 在整个集群中使用了多少。因此，我们将对可分配的核心求和。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(
 2    kube_node_status_allocatable_cpu_cores
 3  )
```

在我的情况下，可分配的 CPU 总数大约为 5.8 个核心。要获取确切的数字，请将鼠标悬停在图表线上。

现在我们知道了有多少可分配的 CPU，我们应该尝试发现 Pods 请求了多少。

请注意，请求的资源与已使用的资源不同。我们稍后会讨论这种情况。现在，我们想知道我们从系统中请求了多少。

请键入以下表达式，然后按“执行”按钮。

```
 1  kube_pod_container_resource_requests_cpu_cores
```

我们可以看到请求的 CPU 相对较低。在我的情况下，所有请求 CPU 的容器值都低于 0.15（一百五十毫秒）。您的结果可能有所不同。

与可分配的 CPU 一样，我们对请求的 CPU 总和感兴趣。稍后，我们将能够结合这两个结果，并推断集群中还有多少未保留的资源。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(
 2    kube_pod_container_resource_requests_cpu_cores
 3  )
```

我们对所有 CPU 资源请求求和。结果是，在我的情况下（随后的屏幕截图），所有请求的 CPU 略低于 1.5。

图 3-26：Prometheus 的图表屏幕，显示请求的 CPU 总和

现在，让我们结合这两个表达式，看看请求的 CPU 百分比。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(
 2    kube_pod_container_resource_requests_cpu_cores
 3  ) /
 4  sum(
 5    kube_node_status_allocatable_cpu_cores
 6  )
```

在我的情况下，输出显示大约四分之一（0.25）的可分配 CPU 被保留。这意味着在我们达到扩展集群的需要之前，我们可以有四倍的 CPU 请求。当然，您已经知道，如果存在的话，集群自动扩展器会在此之前添加节点。但是，知道我们接近达到 CPU 限制是很重要的。集群自动扩展器可能无法正常工作，或者甚至可能根本没有激活。如果有的话，后一种情况对于大多数本地集群来说是真实的。

让我们看看我们是否可以将我们探索的表达式转换为警报。

我们将探讨一组新的图表值与之前使用的值之间的另一个差异。

```
 1  diff mon/prom-values-latency2.yml \
 2      mon/prom-values-cpu.yml
```

输出如下。

```
64c64
<   expr: sum(rate(nginx_ingress_controller_requests[5m])) by (ingress) / sum(label_join(kube_deployment_status_replicas, "ingress", ",", "deployment")) by (ingress) > 0.1
---
>   expr: sum(rate(nginx_ingress_controller_requests[5m])) by (ingress) / sum(label_join(kube_deployment_status_replicas, "ingress", ",", "deployment")) by (ingress) > 1
87a88,103
> - alert: NotEnoughCPU
>   expr: sum(rate(node_cpu_seconds_total{mode!="idle", mode!="iowait", mode!~"^(?:guest.*)$"}[5m])) / count(node_cpu_seconds_total{mode="system"}) > 0.9
```

```
>   for: 30m
>   labels:
>     severity: notify
>   annotations:
>     summary: There's not enough CPU
>     description: CPU usage of the cluster is above 90%
> - alert: TooMuchCPURequested
>   expr: sum(kube_pod_container_resource_requests_cpu_cores) / sum(kube_node_status_allocatable_cpu_cores) > 0.9
>   for: 30m
>   labels:
>     severity: notify
>   annotations:
>     summary: There's not enough allocatable CPU
>     description: More than 90% of allocatable CPU is requested
```

从差异中我们可以看到，我们将`TooManyRequests`的原始阈值恢复为`1`，并添加了两个名为`NotEnoughCPU`和`TooMuchCPURequested`的新警报。

如果整个集群的 CPU 使用率超过百分之九十并持续超过三十分钟，`NotEnoughCPU`警报将会触发。这样我们就可以避免在 CPU 使用率暂时飙升时设置警报。

`TooMuchCPURequested`也有百分之九十的阈值，如果持续超过三十分钟，将会触发警报。该表达式计算请求的总量与可分配 CPU 的总量之间的比率。

这两个警报都是我们之前执行的 Prometheus 表达式的反映，所以您应该已经熟悉它们的用途。

让我们使用新的值升级 Prometheus 的图表并打开警报屏幕。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-cpu.yml
 8
 9  open "http://$PROM_ADDR/alerts"
```

现在剩下的就是等待两个新的警报出现。如果它们还没有出现，请刷新您的屏幕。

现在可能没有必要看新的警报如何起作用。到现在为止，您应该相信这个流程，没有理由认为它们不会触发。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/73c6acaf-55dd-42ec-a35c-ccfadef135cd.png)图 3-27：Prometheus 的警报屏幕

在“现实世界”场景中，接收到这两个警报中的一个可能会引发不同的反应，这取决于我们使用的 Kubernetes 版本。

如果我们有集群自动缩放器（CA），我们可能不需要`NotEnoughCPU`和`TooMuchCPURequested`警报。节点 CPU 使用率达到百分之九十并不会影响集群的正常运行，只要我们的 CPU 请求设置正确。同样，百分之九十的可分配 CPU 被保留也不是问题。如果 Kubernetes 无法安排新的 Pod，因为所有 CPU 都被保留，它将扩展集群。实际上，接近满负荷的 CPU 使用率或几乎所有可分配的 CPU 被保留是件好事。这意味着我们拥有我们所需的 CPU，并且我们不必为未使用的资源付费。然而，这种逻辑主要适用于云服务提供商，甚至并非所有云服务提供商都适用。今天（2018 年 10 月），集群自动缩放器只在 AWS、GCE 和 Azure 中运行。

所有这些并不意味着我们应该只依赖于集群自动缩放器。它也可能出现故障，就像其他任何东西一样。然而，由于集群自动缩放器是基于观察无法调度的 Pods，如果它无法工作，我们应该通过观察 Pod 状态而不是 CPU 使用率来检测到这一点。不过，当 CPU 使用率过高时接收警报也许并不是一个坏主意，但在这种情况下，我们可能希望将阈值增加到接近百分之百的值。

如果我们的集群是本地的，更准确地说，如果它没有集群自动缩放器，那么我们探讨的警报对于我们的集群扩展流程是否没有自动化或者速度较慢是至关重要的。逻辑很简单。如果我们需要超过几分钟来向集群添加新节点，我们就不能等到 Pods 无法调度。那将为时已晚。相反，我们需要知道在集群变满（饱和）之前我们已经没有可用容量，这样我们就有足够的时间通过向集群添加新节点来做出反应。

然而，拥有一个因为集群自动缩放器不工作而不自动缩放的集群并不是一个足够好的借口。我们有很多其他工具可以用来自动化我们的基础设施。当我们设法到达这样一个地步，我们可以自动向集群添加新节点时，警报的目的地应该改变。我们可能不再希望收到 Slack 通知，而是希望向一个服务发送请求，该服务将执行脚本，从而向集群添加新节点。如果我们的集群是在虚拟机上运行的，我们总是可以通过脚本（或某个工具）添加更多节点。

接收 Slack 通知的唯一真正理由是如果我们的集群是运行在裸机上的。在这种情况下，我们不能指望脚本会神奇地创建新的服务器。对于其他人来说，当 CPU 使用过高或者所有分配的 CPU 都被保留时接收 Slack 通知应该只是一个临时解决方案，直到适当的自动化到位为止。

现在，让我们尝试通过测量内存使用和保留来实现类似的目标。

测量内存消耗与 CPU 类似，但也有一些我们应该考虑的不同之处。但在我们到达那里之前，让我们回到 Prometheus 的图表界面，探索我们的第一个与内存相关的指标。

```
 1  open "http://$PROM_ADDR/graph"
```

就像 CPU 一样，首先我们需要找出每个节点有多少内存。

请键入以下表达式，点击“执行”按钮，然后切换到*图表*选项卡。

```
 1  node_memory_MemTotal_bytes
```

你的结果可能与我的不同。在我的情况下，每个节点大约有 4GB 的 RAM。

知道每个节点有多少 RAM 是没有用的，如果不知道当前有多少 RAM 可用。我们可以通过`node_memory_MemAvailable_bytes`指标获得这些信息。

请在下面输入表达式，然后按“执行”按钮。

```
 1  node_memory_MemAvailable_bytes
```

我们可以看到集群中每个节点的可用内存。在我的情况下（如下截图所示），每个节点大约有 3GB 的可用 RAM。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/67a644d2-43b6-4eb3-902f-56c07fffd073.png)图 3-28：Prometheus 的图表屏幕，显示集群中每个节点的可用内存

现在我们知道如何从每个节点获取总内存和可用内存，我们应该结合查询来获得整个集群已使用内存的百分比。

请在下面输入表达式，然后按“执行”按钮。

```
 1  1 -
 2  sum(
 3    node_memory_MemAvailable_bytes
 4  ) /
 5  sum(
 6    node_memory_MemTotal_bytes
 7  )
```

由于我们正在寻找已使用内存的百分比，并且我们有可用内存的指标，我们从`1 -`开始表达式，这将颠倒结果。表达式的其余部分是可用和总内存的简单除法。在我的情况下（如下截图所示），每个节点上使用的内存不到 30%。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/9144a5c6-047c-4b6d-b6cf-d3e1e63235a4.png)图 3-29：Prometheus 的图表屏幕，显示可用内存的百分比

就像 CPU 一样，可用和总内存并不能完全反映实际情况。虽然这是有用的信息，也是潜在警报的基础，但我们还需要知道有多少内存可分配，以及有多少内存被 Pod 使用。我们可以通过`kube_node_status_allocatable_memory_bytes`指标获得第一个数字。

请在下面输入表达式，然后按“执行”按钮。

```
 1  kube_node_status_allocatable_memory_bytes
```

根据 Kubernetes 的版本和您使用的托管提供商，总内存和可分配内存之间可能存在很小或很大的差异。我在 AKS 中运行集群，可分配内存比总内存少了整整 1GB。前者大约为 3GB RAM，而后者大约为 4GB RAM。这是一个很大的差异。我的 Pod 并没有完整的 4GB 内存，而是少了大约四分之一。其余的大约 1GB RAM 花费在系统级服务上。更糟糕的是，这 1GB RAM 花费在每个节点上，而在我的情况下，这导致总共少了 3GB，因为我的集群有三个节点。鉴于总内存和可分配内存之间的巨大差异，拥有更少但更大的节点是有明显好处的。然而，并不是每个人都需要大节点，如果我们希望节点分布在所有区域，将节点数量减少到少于三个可能不是一个好主意。

现在我们知道如何检索可分配内存量，让我们看看如何获取每个应用程序所请求的内存量。

请键入以下表达式，然后按“执行”按钮。

```
 1  kube_pod_container_resource_requests_memory_bytes
```

我们可以看到 Prometheus（服务器）具有最多的请求内存（500MB），而其他所有的请求内存都远低于这个数值。请记住，我们只看到了具有预留的 Pod，那些没有预留的 Pod 不会出现在该查询的结果中。正如您已经知道的那样，在特殊情况下，例如用于 CI/CD 流程中的短暂 Pod，不定义预留和限制是可以的。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/6968bff2-2962-4746-946f-61dbd8f5dd69.png)图 3-30：Prometheus 的图形屏幕显示了每个 Pod 所请求的内存

前面的表达式返回了每个 Pod 使用的内存量。然而，我们的任务是发现系统中总共有多少请求的内存。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(
 2    kube_pod_container_resource_requests_memory_bytes
 3  )
```

在我的情况下，所请求的内存总量大约为 1.6GB RAM。

现在剩下的就是将总请求的内存量除以集群中所有可分配的内存量。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(
 2    kube_pod_container_resource_requests_memory_bytes
 3  ) / 
 4  sum(
 5    kube_node_status_allocatable_memory_bytes
 6  )
```

在我的情况下（以下是屏幕截图），请求内存的总量约为集群可分配 RAM 的百分之二十（`0.2`）。我远非处于任何危险之中，也没有必要扩展集群。如果有什么，我有太多未使用的内存，可能想要缩减规模。然而，目前我们只关注扩展规模。稍后我们将探讨可能导致缩减规模的警报。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/f2bbaa51-31e9-4115-80a1-7994bc281168.png)图 3-31：Prometheus 的图表屏幕，显示集群中请求内存占总可分配内存的百分比

让我们看看旧图表数值和我们即将使用的数值之间的差异。

```
 1  diff mon/prom-values-cpu.yml \
 2      mon/prom-values-memory.yml
```

输出如下。

```
103a104,119
> - alert: NotEnoughMemory
>   expr: 1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes) > 0.9
>   for: 30m
>   labels:
>     severity: notify
>   annotations:
>     summary: There's not enough memory
>     description: Memory usage of the cluster is above 90%
> - alert: TooMuchMemoryRequested
>   expr: sum(kube_pod_container_resource_requests_memory_bytes) / sum(kube_node_status_allocatable_memory_bytes) > 0.9
>   for: 30m
>   labels:
>     severity: notify
>   annotations:
>     summary: There's not enough allocatable memory
>     description: More than 90% of allocatable memory is requested
```

我们添加了两个新的警报（“内存不足”和“请求内存过多”）。定义本身应该很简单，因为我们已经创建了相当多的警报。表达式与我们在 Prometheus 图表屏幕中使用的表达式相同，只是增加了大于百分之九十（`> 0.9`）的阈值。因此，我们将跳过进一步的解释。

我们将使用新值升级我们的 Prometheus 图表，并打开警报屏幕以确认它们。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-memory.yml
 8
 9  open "http://$PROM_ADDR/alerts"
```

如果警报“内存不足”和“请求内存过多”尚不可用，请稍等片刻，然后刷新屏幕。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c87a9f02-ac71-489f-907e-bd38b2233064.png)图 3-32：Prometheus 的警报屏幕

到目前为止，基于内存的警报所采取的操作应该与我们讨论 CPU 时类似。我们可以使用它们来决定是否以及何时扩展我们的集群，无论是通过手动操作还是通过自动化脚本。就像以前一样，如果我们的集群托管在 Cluster Autoscaler（CA）支持的供应商之一，这些警报应该纯粹是信息性的，而在本地或不受支持的云提供商那里，它们不仅仅是简单的通知。它们表明我们即将耗尽容量，至少在涉及内存时是这样。

CPU 和内存的示例都集中在需要知道何时扩展我们的集群。我们可能会创建类似的警报，通知我们 CPU 或内存的使用率过低。这将清楚地告诉我们，我们的集群中有太多节点，我们可能需要移除一些。同样，这假设我们没有集群自动缩放器正在运行。但是，仅考虑 CPU 或内存中的一个来缩减规模太冒险，可能会导致意想不到的结果。

假设只有百分之十二的可分配 CPU 被保留，并且我们的集群中有三个工作节点。由于平均每个节点的保留 CPU 量相对较小，这么低的 CPU 使用率当然不需要那么多节点。因此，我们可以选择缩减规模，并移除一个节点，从而允许其他集群重用它。这样做是一个好主意吗？嗯，这取决于其他资源。如果内存预留的百分比也很低，移除一个节点是一个好主意。另一方面，如果保留的内存超过百分之六十六，移除一个节点将导致资源不足。当我们移除三个节点中的一个时，三个节点中超过百分之六十六的内存预留变成了两个节点中超过百分之一百。

总的来说，如果我们要收到通知，我们的集群需要缩减规模（而且我们没有集群自动缩放器），我们需要将内存和 CPU 以及可能还有其他一些指标作为警报阈值的组合。幸运的是，这些表达式与我们之前使用的非常相似。我们只需要将它们组合成一个单一的警报并更改阈值。

作为提醒，我们之前使用的表达式如下（无需重新运行）。

```
 1  sum(rate(
 2    node_cpu_seconds_total{
 3      mode!="idle",
 4      mode!="iowait",
 5      mode!~"^(?:guest.*)$"
 6    }[5m]
 7  ))
 8  by (instance) /
 9  count(
10    node_cpu_seconds_total{
11      mode="system"
12    }
13  )
14  by (instance)
15
16  1 -
17  sum(
18    node_memory_MemAvailable_bytes
19  ) 
20  by (instance) /
21  sum(
22    node_memory_MemTotal_bytes
23  )
24  by (instance)
```

现在，让我们将图表的值的另一个更新与我们现在使用的进行比较。

```
 1  diff mon/prom-values-memory.yml \
 2      mon/prom-values-cpu-memory.yml
```

输出如下。

```
119a120,127
> - alert: TooMuchCPUAndMemory
>   expr: (sum(rate(node_cpu_seconds_total{mode!="idle", mode!="iowait", mode!~"^(?:guest.*)$"}[5m])) by (instance) / count(node_cpu_seconds_total{mode="system"}) by (instance)) < 0.5 and (1 - sum(node_memory_MemAvailable_bytes) by (instance) / sum(node_memory_MemTotal_bytes) by (instance)) < 0.5
>   for: 30m
>   labels:
>     severity: notify
>   annotations:
>     summary: Too much unused CPU and memory
>     description: Less than 50% of CPU and 50% of memory is used on at least one node
```

我们正在添加一个名为`TooMuchCPUAndMemory`的新警报。它是以前两个警报的组合。只有当 CPU 和内存使用率都低于百分之五十时，它才会触发。这样我们就可以避免发送错误的警报，并且不会因为资源预留（CPU 或内存）之一太低而诱发缩减集群的决定，而另一个可能很高。

在我们进入下一个主题（或指标类型）之前，剩下的就是升级 Prometheus 的图表并确认新的警报确实是可操作的。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-cpu-memory.yml
 8
 9  open "http://$PROM_ADDR/alerts"
```

如果警报仍然不存在，请刷新警报屏幕。在我的情况下（以下是屏幕截图），保留内存和 CPU 的总量低于百分之五十，并且警报处于挂起状态。在您的情况下，这可能并不是真的，警报可能还没有达到其阈值。尽管如此，我将继续解释我的情况，在这种情况下，CPU 和内存使用量都低于总可用量的百分之五十。

三十分钟后（`for: 30m`），警报触发了。它等了一会儿（`30m`）以确认内存和 CPU 使用率的下降不是暂时的。鉴于我在 AKS 中运行我的集群，集群自动缩放器会在三十分钟之前删除一个节点。但是，由于它配置为最少三个节点，CA 将不执行该操作。因此，我可能需要重新考虑是否支付三个节点是值得的投资。另一方面，如果我的集群没有集群自动缩放器，并且假设我不想在其他集群可能需要更多资源的情况下浪费资源，我需要删除一个节点（手动或自动）。如果那个移除是自动的，目的地将不是 Slack，而是负责删除节点的工具的 API。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/88738e53-69bf-4683-9ca4-c8fdf35a59b8.png)图 3-33：Prometheus 的警报屏幕，其中一个警报处于挂起状态

现在我们已经有了一些饱和的例子，我们涵盖了谷歌网站可靠性工程师和几乎任何其他监控方法所推崇的每个指标。但我们还没有完成。还有一些其他指标和警报我想探索。它们可能不属于讨论的任何类别，但它们可能证明非常有用。

# 对无法调度或失败的 Pod 进行警报

知道我们的应用程序是否在快速响应请求方面出现问题，是否受到了比其处理能力更多的请求，是否产生了太多错误，以及是否饱和，如果它们甚至没有运行，这就没有用了。即使我们的警报通过通知我们出现了太多错误或由于副本数量不足而导致响应时间变慢，我们仍然应该被告知，例如，一个或甚至所有副本无法运行。在最好的情况下，这样的通知将提供有关问题原因的额外信息。在更糟糕的情况下，我们可能会发现数据库的一个副本没有运行。这不一定会减慢速度，也不会产生任何错误，但会使我们处于数据无法复制的状态（额外的副本没有运行），如果最后一个剩下的副本也失败，我们可能会面临其状态的完全丢失。

应用程序无法运行的原因有很多。集群中可能没有足够的未保留资源。如果出现这种情况，集群自动缩放器将处理该问题。但是，还有许多其他潜在问题。也许新版本的镜像在注册表中不可用。或者，Pod 可能正在请求无法索赔的持久卷。正如你可能已经猜到的那样，可能导致我们的 Pod 失败、无法调度或处于未知状态的原因几乎是无限的。

我们无法单独解决 Pod 问题的所有原因。但是，如果一个或多个 Pod 的阶段是“失败”、“未知”或“挂起”，我们可以收到通知。随着时间的推移，我们可能会扩展我们的自愈脚本，以解决其中一些状态的特定原因。目前，我们最好的第一步是在 Pod 长时间处于这些阶段之一时收到通知（例如，十五分钟）。如果在 Pod 的状态指示出现问题后立即发出警报，那将是愚蠢的，因为那样会产生太多的误报。只有在等待一段时间后，我们才应该收到警报并选择如何行动，从而给 Kubernetes 时间来解决问题。只有在 Kubernetes 未能解决问题时，我们才应该执行一些反应性操作。

随着时间的推移，我们会注意到我们收到的警报中存在一些模式。当我们发现时，警报应该被转换为自动响应，可以在不需要我们参与的情况下解决选定的问题。我们已经通过 HorizontalPodAutoscaler 和 Cluster Autoscaler 探索了一些低 hanging fruits。目前，我们将专注于接收所有其他情况的警报，而失败和无法调度的 Pod 是其中的一部分。稍后，我们可能会探索如何自动化响应。但是，现在还不是时候，所以我们将继续进行另一个警报，这将导致 Slack 收到通知。

让我们打开 Prometheus 的图形屏幕。

```
 1  open "http://$PROM_ADDR/graph"
```

请键入以下表达式，然后单击“执行”按钮。

```
 1  kube_pod_status_phase
```

输出显示了集群中每个 Pod 的情况。如果你仔细观察，你会注意到每个 Pod 都有五个结果，分别对应五种可能的阶段。如果你关注`phase`字段，你会发现有一个条目是`Failed`、`Pending`、`Running`、`Succeeded`和`Unknown`。因此，每个 Pod 有五个结果，但只有一个值为`1`，而其他四个的值都设置为`0`。

图 3-34：Prometheus 的控制台视图，显示了 Pod 的阶段

目前，我们主要关注警报，它们在大多数情况下应该是通用的，与特定节点、应用程序、副本或其他类型的资源无关。只有当我们收到有问题的警报时，我们才应该开始深入挖掘并寻找更详细的数据。考虑到这一点，我们将重新编写我们的表达式，以检索每个阶段的 Pod 数量。

请键入以下表达式，然后单击“执行”按钮。

```
 1  sum(
 2    kube_pod_status_phase
 3  ) 
 4  by (phase)
```

输出应该显示所有的 Pod 都处于`Running`阶段。在我的情况下，有二十七个正在运行的 Pod，没有一个处于其他任何阶段。

现在，我们实际上不应该关心健康的 Pod。它们正在运行，我们不需要做任何事情。相反，我们应该关注那些有问题的 Pod。因此，我们可能会重新编写先前的表达式，只检索那些处于`Failed`、`Unknown`或`Pending`阶段的总和。

请键入以下表达式，然后单击“执行”按钮。

```
 1  sum(
 2    kube_pod_status_phase{
 3      phase=~"Failed|Unknown|Pending"
 4    }
 5  ) 
 6  by (phase)
```

如预期的那样，除非您搞砸了什么，输出的值都设置为`0`。

图 3-35：Prometheus 的控制台视图，显示了处于失败、未知或挂起阶段的 Pod 的总数

到目前为止，没有我们需要担心的 Pod。我们将通过创建一个故意失败的 Pod 来改变这种情况，使用一个显然不存在的镜像。

```
 1  kubectl run problem \
 2      --image i-do-not-exist \
 3      --restart=Never
```

从输出中可以看出，`pod/problem`已经被`created`。如果我们通过脚本（例如，CI/CD 流水线）创建它，我们可能会认为一切都很好。即使我们跟着使用`kubectl rollout status`，我们只能确保它开始工作，而不能确保它继续工作。

但是，由于我们没有通过 CI/CD 流水线创建该 Pod，而是手动创建的，我们可以列出`default`命名空间中的所有 Pod。

```
 1  kubectl get pods
```

输出如下。

```
NAME    READY STATUS       RESTARTS AGE
problem 0/1   ErrImagePull 0        27s
```

我们假设我们只有短期记忆，并且已经忘记了`image`设置为`i-do-not-exist`。问题可能是什么？嗯，第一步是描述 Pod。

```
 1  kubectl describe pod problem
```

输出，仅限于`Events`部分的消息，如下。

```
...
Events:
...  Message
...  -------
...  Successfully assigned default/problem to aks-nodepool1-29770171-2
...  Back-off pulling image "i-do-not-exist"
...  Error: ImagePullBackOff
...  pulling image "i-do-not-exist"
...  Failed to pull image "i-do-not-exist": rpc error: code = Unknown desc = Error response from daemon: repository i-do-not-exist not found: does not exist or no pull access
 Warning  Failed     8s (x3 over 46s)   kubelet, aks-nodepool1-29770171-2  Error: ErrImagePull
```

问题显然通过`Back-off pulling image "i-do-not-exist"`消息表现出来。在更下面，我们可以看到来自容器服务器的消息，说明`它未能拉取图像"i-do-not-exist"`。

当然，我们事先知道这将是结果，但类似的事情可能发生而我们没有注意到存在问题。原因可能是未能拉取镜像，或者其他无数的原因之一。然而，我们不应该坐在终端前，列出和描述 Pod 和其他类型的资源。相反，我们应该收到一个警报，告诉我们 Kubernetes 未能运行一个 Pod，只有在那之后，我们才应该开始查找问题的原因。所以，让我们创建一个新的警报，当 Pod 失败且无法恢复时通知我们。

像以前许多次一样，我们将查看 Prometheus 的图表值的旧定义和新定义之间的差异。

```
 1  diff mon/prom-values-errors.yml \
 2      mon/prom-values-phase.yml
```

输出如下。

```
136a137,146
> - name: pods
>   rules:
>   - alert: ProblematicPods
>     expr: sum(kube_pod_status_phase{phase=~"Failed|Unknown|Pending"}) by (phase) > 0
>     for: 1m
>     labels:
>       severity: notify
>     annotations:
>       summary: At least one Pod could not run
>       description: At least one Pod is in a problematic phase
```

我们定义了一个名为`pod`的新警报组。在其中，我们有一个名为`ProblematicPods`的`alert`，如果有一个或多个 Pod 的`Failed`、`Unknown`或`Pending`阶段持续超过一分钟（`1m`）将触发警报。我故意将它设置为非常短的`for`持续时间，以便我们可以轻松测试它。后来，我们将切换到十五分钟的间隔，这将足够让 Kubernetes 在我们收到通知之前解决问题，而不会让我们陷入恐慌模式。

让我们用更新后的值更新 Prometheus 的图表。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-phase.yml
```

由于我们尚未解决`problem` Pod 的问题，我们很快应该在 Slack 上收到新的通知。让我们确认一下。

```
 1  open "https://devops20.slack.com/messages/CD8QJA8DS/"
```

如果您还没有收到通知，请稍等片刻。

我们收到了一条消息，说明“至少有一个 Pod 无法运行”。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/a4035775-47d5-4dbe-a3bd-8142a286be0b.png)图 3-36：Slack 上的警报消息

现在我们收到了一个通知，说其中一个 Pod 出了问题，我们应该去 Prometheus，挖掘数据，直到找到问题的原因，并解决它。但是，由于我们已经知道问题是什么（我们是故意创建的），我们将跳过所有这些，然后移除有问题的 Pod，然后继续下一个主题。

```
 1  kubectl delete pod problem
```

# 升级旧的 Pod

我们的主要目标应该是通过积极主动的方式防止问题发生。在我们无法预测问题即将出现的情况下，我们必须至少在问题发生后迅速采取反应措施来减轻问题。然而，还有第三种情况，可以宽泛地归类为积极主动。我们应该保持系统清洁和及时更新。

在许多可以保持系统最新的事项中，是确保我们的软件相对较新（已打补丁、已更新等）。一个合理的规则可能是在九十天后尝试更新软件，如果不是更早。这并不意味着我们在集群中运行的所有东西都应该比九十天更新，但这可能是一个很好的起点。此外，我们可能会创建更精细的策略，允许某些类型的应用程序（通常是第三方）在不升级的情况下存活，比如说半年。其他的，特别是我们正在积极开发的软件，可能会更频繁地升级。尽管如此，我们的起点是检测所有在九十天或更长时间内没有升级的应用程序。

就像本章中几乎所有其他练习一样，我们将从打开 Prometheus 的图形屏幕开始，探索可能帮助我们实现目标的指标。

```
 1  open "http://$PROM_ADDR/graph"
```

如果我们检查可用的指标，我们会看到有`kube_pod_start_time`。它的名称清楚地表明了它的目的。它以一个仪表的形式提供了每个 Pod 的启动时间的 Unix 时间戳。让我们看看它的作用。

请键入以下表达式，然后单击“执行”按钮。

```
 1  kube_pod_start_time
```

这些值本身没有用，教你如何从这些值计算出人类日期也没有意义。重要的是现在和那些时间戳之间的差异。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/d9204c74-681c-4097-8ce8-b76c8b78b6ab.png)图 3-37：Prometheus 控制台视图，显示了 Pod 的启动时间

我们可以使用 Prometheus 的`time()`函数来返回自 1970 年 1 月 1 日 UTC（或 Unix 时间戳）以来的秒数。

请键入以下表达式，然后点击执行按钮。

```
 1  time()
```

就像`kube_pod_start_time`一样，我们得到了一个代表自 1970 年以来的秒数的长数字。除了值之外，唯一显着的区别是只有一个条目，而对于`kube_pod_start_time`，我们得到了集群中每个 Pod 的结果。

现在，让我们尝试结合这两个指标，以尝试检索每个 Pod 的年龄。

请键入以下表达式，然后点击执行按钮。

```
 1  time() -
 2  kube_pod_start_time
```

这次的结果是表示现在与每个 Pod 创建之间的秒数的更小的数字。在我的情况下（以下是屏幕截图），第一个 Pod（`go-demo-5`的一个副本）已经超过六千秒。那将是大约一百分钟（6096/60），或不到两个小时（100 分钟/60 分钟=1.666 小时）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/d38868b1-8abb-4ad3-aab7-915d496b32bc.png)图 3-38：Prometheus 控制台视图，显示了 Pod 创建以来经过的时间

由于可能没有 Pod 比我们的目标九十天更老，我们将临时将其降低到一分钟（六十秒）。

请键入以下表达式，然后点击执行按钮。

```
 1  (
 2    time() -
 3    kube_pod_start_time{
 4      namespace!="kube-system"
 5    }
 6  ) > 60
```

在我的情况下，所有的 Pod 都比一分钟大（你的情况可能也是如此）。我们确认它可以工作，所以我们可以将阈值增加到九十天。要达到九十天，我们应该将阈值乘以六十得到分钟，再乘以六十得到小时，再乘以二十四得到天，最后再乘以九十。公式将是`60 * 60 * 24 * 90`。我们可以使用最终值`7776000`，但那会使查询更难解读。我更喜欢使用公式。

请键入以下表达式，然后点击执行按钮。

```
 1  (
 2    time() -
 3    kube_pod_start_time{
 4      namespace!="kube-system"
 5    }
 6  ) >
 7  (60 * 60 * 24 * 90)
```

毫无疑问，可能没有结果。如果您为本章创建了一个新的集群，如果您花了九十天才到这里，那您可能是地球上最慢的读者。这可能是我迄今为止写过的最长的一章，但仍不值得花九十天的时间来阅读。

现在我们知道要使用哪个表达式，我们可以在我们的设置中添加一个警报。

```
 1  diff mon/prom-values-phase.yml \
 2      mon/prom-values-old-pods.yml
```

输出如下。

```
146a147,154
> - alert: OldPods
>   expr: (time() - kube_pod_start_time{namespace!="kube-system"}) > 60
>   labels:
>     severity: notify
>     frequency: low
>   annotations:
>     summary: Old Pods
>     description: At least one Pod has not been updated to more than 90 days
```

我们可以看到旧值和新值之间的差异在`OldPods`警报中。它包含了我们几分钟前使用的相同表达式。

我们保持了`60`秒的低阈值，以便我们可以看到警报的作用。以后，我们将把该值增加到 90 天。

没有必要指定`for`持续时间。一旦其中一个 Pod 的年龄达到三个月（加减），警报就会触发。

让我们使用更新后的值升级我们的 Prometheus 图表，并打开 Slack 频道，我们应该能看到新消息。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-old-pods.yml
 8
 9  open "https://devops20.slack.com/messages/CD8QJA8DS/"
```

现在只需等待片刻，直到新消息到达。它应该包含标题*旧的 Pod*和文本说明*至少有一个 Pod 未更新超过 90 天*。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/83874a98-4079-4787-9dce-83f28f3c7db4.png)图 3-39：Slack 显示多个触发和解决的警报消息

这样一个通用的警报可能不适用于您所有的用例。但是，我相信您可以根据命名空间、名称或类似的内容将其拆分为多个警报。

现在我们有了一个机制，可以在我们的 Pod 过旧并且可能需要升级时接收通知，我们将进入下一个主题，探讨如何检索容器使用的内存和 CPU。

# 测量容器的内存和 CPU 使用

如果您熟悉 Kubernetes，您就会理解定义资源请求和限制的重要性。由于我们已经探讨了`kubectl top pods`命令，您可能已经设置了请求的资源以匹配当前的使用情况，并且可能已经定义了限制高于请求。这种方法可能在第一天有效。但是，随着时间的推移，这些数字将发生变化，我们将无法通过`kubectl top pods`获得全面的图片。我们需要知道容器在峰值负载时使用多少内存和 CPU，以及在压力较小时使用多少。我们应该随时间观察这些指标，并定期进行调整。

即使我们设法猜出容器需要多少内存和 CPU，这些数字也可能会从一个版本到另一个版本发生变化。也许我们引入了一个需要更多内存或 CPU 的功能？

我们需要观察资源使用情况随时间的变化，并确保它不会随着新版本的发布或用户数量的增加（或减少）而改变。现在，我们将专注于前一种情况，并探讨如何查看容器随时间使用了多少内存和 CPU。

像往常一样，我们将首先打开 Prometheus 的图表屏幕。

```
 1  open "http://$PROM_ADDR/graph"
```

我们可以通过`container_memory_usage_bytes`来检索容器的内存使用情况。

请键入下面的表达式，点击执行按钮，然后切换到*图表*屏幕。

```
 1  container_memory_usage_bytes
```

如果你仔细观察顶部的使用情况，你可能会感到困惑。似乎有些容器使用的内存远远超出预期的数量。

事实上，一些`container_memory_usage_bytes`记录包含累积值，我们应该排除它们，以便只检索单个容器的内存使用情况。我们可以通过仅检索在`container_name`字段中具有值的记录来实现这一点。

请键入下面的表达式，然后点击执行按钮。

```
 1  container_memory_usage_bytes{
 2    container_name!=""
 3  }
```

现在结果更有意义了。它反映了我们集群内运行的容器的内存使用情况。

稍后我们将基于容器资源设置警报。现在，我们假设我们想要检查特定容器的内存使用情况（例如`prometheus-server`）。由于我们已经知道可用标签之一是`container_name`，检索我们需要的数据应该是直截了当的。

请键入下面的表达式，然后点击执行按钮。

```
 1  container_memory_usage_bytes{
 2    container_name="prometheus-server"
 3  }
```

我们可以看到容器在过去一小时内内存使用情况的波动。通常，我们会对一天或一周这样更长的时间段感兴趣。我们可以通过点击图表上方的-和+按钮，或者直接在它们之间的字段中输入值（例如`1w`）来实现这一点。然而，改变持续时间可能不会有太大帮助，因为我们运行集群的时间不长。除非你阅读速度很慢，否则我们可能无法获得比几个小时更多的数据。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/a6c281c9-3cdc-451b-88db-a3e4409d6e53.png)图 3-40：限制为 prometheus-server 的 Prometheus 图表屏幕上的容器内存使用情况

同样，我们应该能够检索容器的 CPU 使用情况。在这种情况下，我们正在寻找的指标可能是`container_cpu_usage_seconds_total`。然而，与`container_memory_usage_bytes`不同，它是一个计数器，我们将不得不结合`sum`和`rate`来获得随时间变化的值。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(rate(
 2    container_cpu_usage_seconds_total{
 3      container_name="prometheus-server"
 4    }[5m]
 5  ))
 6  by (pod_name)
```

查询显示了五分钟间隔内的 CPU 秒速总和。我们添加了`by (pod_name)`到混合中，以便我们可以区分不同的 Pod，并查看一个是何时创建的，另一个是何时销毁的。

图 3-41：Prometheus 的图形屏幕，限制为 prometheus-server 的容器 CPU 使用率

如果这是一个“现实世界”的情况，我们下一步将是将实际资源使用与我们在 Prometheus`资源`中定义的进行比较。如果我们定义的与实际情况相比差异很大，我们可能应该更新我们的 Pod 定义（`资源`部分）。

问题在于使用“真实”资源使用情况来定义 Kubernetes 的`资源`将只会暂时提供有效值。随着时间的推移，我们的资源使用情况将会发生变化。负载可能会增加，新功能可能会更加耗费资源，等等。无论原因是什么，需要注意的关键一点是一切都是动态的，对于资源来说没有理由认为会有其他情况。在这种精神下，我们下一个挑战是找出当实际资源使用与我们在容器`资源`中定义的差异太大时如何获得通知。

# 将实际资源使用与定义的请求进行比较

如果我们在 Pod 中定义容器的`资源`而不依赖于实际使用情况，我们只是在猜测容器将使用多少内存和 CPU。我相信你已经知道为什么在软件行业中猜测是一个糟糕的主意，所以我将只关注 Kubernetes 方面。

Kubernetes 将没有指定资源的容器的 Pod 视为**BestEffort Quality of Service**（**QoS**）。因此，如果它的内存或 CPU 不足以为所有的 Pod 提供服务，那么这些 Pod 将被强制删除，为其他 Pod 腾出空间。如果这样的 Pod 是短暂的，例如用作持续交付流程的一次性代理，BestEffort QoS 并不是一个坏主意。但是，当我们的应用是长期运行时，BestEffort QoS 应该是不可接受的。这意味着在大多数情况下，我们必须定义容器的`resources`。

如果容器的`resources`（几乎总是）是必须的，我们需要知道要设置哪些值。我经常看到团队仅仅是猜测。“这是一个数据库，因此它需要大量的 RAM”，“它只是一个 API，不应该需要太多”是我经常听到的一些句子。这些猜测往往是由于无法测量实际使用情况而产生的。当出现问题时，这些团队会简单地将分配的内存和 CPU 加倍。问题解决了！

我从来不明白为什么会有人发明应用程序需要多少内存和 CPU。即使没有任何“花哨”的工具，我们在 Linux 中总是有`top`命令。我们可以知道我们的应用程序使用了多少。随着时间的推移，出现了更好的工具，我们所要做的就是谷歌“如何测量我的应用程序的内存和 CPU”。

当你需要当前数据时，你已经看到了`kubectl top pods`的操作，并且你已经开始熟悉 Prometheus 的强大功能。你没有理由去猜测。

但是，为什么我们关心资源使用情况与请求的资源相比呢？除了可能揭示潜在问题（例如内存泄漏）之外，不准确的资源请求和限制会阻止 Kubernetes 有效地完成其工作。例如，如果我们将内存请求定义为 1GB RAM，那么 Kubernetes 将从可分配的内存中删除这么多。如果一个节点有 2GB 的可分配 RAM，即使每个节点只使用 50MB RAM，也只能运行两个这样的容器。我们的节点将只使用可分配内存的一小部分，如果我们有集群自动缩放器，即使旧节点仍有大量未使用的内存，新节点也会被添加。

即使现在我们知道如何获取实际内存使用情况，每天都通过比较 YAML 文件和 Prometheus 中的结果来开始工作将是浪费时间。相反，我们将创建另一个警报，当请求的内存和 CPU 与实际使用情况相差太大时，它将发送通知给我们。这是我们的下一个任务。

首先，我们将重新打开 Prometheus 的图表屏幕。

```
 1 open "http://$PROM_ADDR/graph"
```

我们已经知道如何通过`container_memory_usage_bytes`获取内存使用情况，所以我们将直接开始检索请求的内存。如果我们可以将这两者结合起来，我们将得到请求的内存和实际内存使用之间的差异。

我们正在寻找的指标是`kube_pod_container_resource_requests_memory_bytes`，所以让我们以`prometheus-server` Pod 为例来试一试。

请键入以下表达式，然后点击“执行”按钮，切换到*图表*选项卡。

```
 1  kube_pod_container_resource_requests_memory_bytes{
 2    container="prometheus-server"
 3  }
```

从结果中我们可以看到，我们为`prometheus-server`容器请求了 500MB 的 RAM。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c2002dc2-0574-48b0-93a5-22d701f67efa.png)图 3-42：Prometheus 的图表屏幕，容器请求的内存限制为 prometheus-server

问题在于`kube_pod_container_resource_requests_memory_bytes`指标中，除了`pod`标签外，还有`container_memory_usage_bytes`使用`pod_name`。如果我们要将两者结合起来，我们需要将标签`pod`转换为`pod_name`。幸运的是，这不是我们第一次面临这个问题，我们已经知道解决方案是使用`label_join`函数，它将基于一个或多个现有标签创建一个新标签。

请键入以下表达式，然后点击“执行”按钮。

```
 1  sum(label_join(
 2    container_memory_usage_bytes{
 3      container_name="prometheus-server"
 4    },
 5    "pod",
 6    ",",
 7    "pod_name"
 8  ))
 9  by (pod)
```

这一次，我们不仅为指标添加了一个新标签，而且还通过这个新标签（`by (pod)`）对结果进行了分组。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/ca12f3cb-0be1-487f-93c4-626630e0b2b0.png)图 3-43：Prometheus 的图表屏幕，容器内存使用限制为 prometheus-server，并按从 pod_name 提取的 pod 标签进行分组。

现在我们可以将这两个指标结合起来，找出请求的内存和实际内存使用之间的差异。

请键入以下表达式，然后点击“执行”按钮。

```
 1  sum(label_join(
 2    container_memory_usage_bytes{
 3      container_name="prometheus-server"
 4    },
 5    "pod",
 6    ",",
 7    "pod_name"
 8  ))
 9  by (pod) /
10  sum(
11    kube_pod_container_resource_requests_memory_bytes{
12      container="prometheus-server"
13    }
14  )
15  by (pod)
```

在我的情况下（以下是屏幕截图），差异逐渐变小。它开始时大约为百分之六十，现在大约为百分之七十五。这样的差异对我们来说不足以采取任何纠正措施。

图 3-44：Prometheus 的图形屏幕，显示基于请求内存的容器内存使用百分比

现在我们已经看到了如何获取单个容器的保留和实际内存使用之间的差异，我们可能应该使表达更加普遍，并获取集群中的所有容器。但是，获取所有可能有点太多了。我们可能不想干扰运行在`kube-system`命名空间中的 Pod。它们可能是预先安装在集群中的，至少目前我们可能希望将它们保持原样。因此，我们将在查询中排除它们。

请键入以下表达式，然后按“执行”按钮。

```
 1  sum(label_join(
 2    container_memory_usage_bytes{
 3      namespace!="kube-system"
 4    },
 5    "pod",
 6    ",",
 7    "pod_name"
 8  ))
 9  by (pod) /
10  sum(
11    kube_pod_container_resource_requests_memory_bytes{
12      namespace!="kube-system"
13    }
14  )
15  by (pod)
```

结果应该是请求和实际内存之间差异的百分比列表，排除了`kube-system`中的 Pod。

在我的情况下，有相当多的容器使用的内存比我们请求的要多得多。主要问题是`prometheus-alertmanager`，它使用的内存比我们请求的要多三倍以上。这可能由于几个原因。也许我们请求的内存太少，或者它包含的容器没有指定`requests`。无论哪种情况，我们可能应该重新定义请求，不仅针对 Alertmanager，还针对所有使用的内存比请求的多 50%以上的其他 Pod。

图 3-45：Prometheus 的图形屏幕，显示基于请求内存的容器内存使用百分比，排除了来自 kube-system 命名空间的容器

我们即将定义一个新的警报，用于处理请求的内存远高于或远低于实际使用情况的情况。但在这样做之前，我们应该讨论应该使用的条件。一个警报可以在实际内存使用超过请求内存的 150%以上并持续一个小时以上时触发。这将消除由内存使用暂时激增引起的误报（这就是为什么我们也有`limits`）。另一个警报可以处理内存使用量低于请求量 50%以上的情况。但是，在这种警报情况下，我们可能会添加另一个条件。

有些应用程序太小，我们可能永远无法调整它们的请求。我们可以通过添加另一个条件来排除这些情况，该条件将忽略仅保留了 5MB 或更少内存的 Pod。

最后，这个警报可能不需要像之前的那样频繁地触发。我们应该相对快速地知道我们的应用程序是否使用了比我们打算给予的更多内存，因为这可能是内存泄漏、显著增加的流量或其他潜在危险情况的迹象。但是，如果内存使用远低于预期，问题就不那么紧急了。我们应该纠正它，但没有必要紧急采取行动。因此，我们将后一个警报的持续时间设置为六小时。

现在我们已经制定了一些规则，我们可以看一下旧值和新值之间的另一个差异。

```
 1  diff mon/prom-values-old-pods.yml \
 2      mon/prom-values-req-mem.yml
```

输出如下。

```
148c148
<   expr: (time() - kube_pod_start_time{namespace!="kube-system"}) > 60
---
>   expr: (time() - kube_pod_start_time{namespace!="kube-system"}) > (60 * 60 * 24 * 90)
154a155,172
> - alert: ReservedMemTooLow
>   expr: sum(label_join(container_memory_usage_bytes{namespace!="kube-system", namespace!="ingress-nginx"}, "pod", ",", "pod_name")) by (pod) /
 sum(kube_pod_container_resource_requests_memory_bytes{namespace!="kube-system"}) by (pod) > 1.5
>   for: 1m
>   labels:
>     severity: notify
>     frequency: low
>   annotations:
>     summary: Reserved memory is too low
>     description: At least one Pod uses much more memory than it reserved
> - alert: ReservedMemTooHigh
>   expr: sum(label_join(container_memory_usage_bytes{namespace!="kube-system", namespace!="ingress-nginx"}, "pod", ",", "pod_name")) by (pod) / sum(kube_pod_container_resource_requests_memory_bytes{namespace!="kube-system"}) by (pod) < 0.5 and sum(kube_pod_container_resource_requests_memory_bytes{namespace!="kube-system"}) by (pod) > 5.25e+06
>   for: 6m
>   labels:
>     severity: notify
>     frequency: low
>   annotations:
>     summary: Reserved memory is too high
>     description: At least one Pod uses much less memory than it reserved
```

首先，我们将`OldPods`警报的阈值重新设置为其预期值九十天（`60 * 60 * 24 * 90`）。这样我们就可以阻止它仅用于测试目的触发警报。

接下来，我们定义了一个名为`ReservedMemTooLow`的新警报。如果使用的内存比请求的内存大`1.5`倍，它将触发。警报的挂起状态持续时间设置为`1m`，只是为了我们可以在不等待整个小时的情况下看到结果。稍后，我们将把它恢复为`1h`。

`ReservedMemTooHigh`警报与之前的部分类似，不同之处在于，如果实际内存和请求内存之间的差异小于`0.5`，并且如果这种情况持续超过`6m`（我们稍后将其更改为`6h`），则会触发警报。表达式的第二部分是新的。它要求 Pod 中的所有容器都具有超过 5MB 的请求内存（`5.25e+06`）。通过第二个语句（用`and`分隔），我们可以避免处理太小的应用程序。如果需要的内存小于 5MB，我们应该忽略它，并且可能要祝贺背后的团队使其如此高效。

现在，让我们使用更新后的值升级我们的 Prometheus 图表，并打开图表屏幕。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-req-mem.yml
```

我们不会等到警报开始触发。相反，我们将尝试实现类似的目标，但使用 CPU。

可能没有必要解释我们将使用的表达式的过程。我们将直接跳入基于 CPU 的警报，探索旧值和新值之间的差异。

```
 1  diff mon/prom-values-req-mem.yml \
 2      mon/prom-values-req-cpu.yml
```

输出如下。

```
157c157
<   for: 1m
---
>   for: 1h
166c166
<   for: 6m
---
>   for: 6h
172a173,190
> - alert: ReservedCPUTooLow
>   expr: sum(label_join(rate(container_cpu_usage_seconds_total{namespace!="kube-system", namespace!="ingress-nginx", pod_name!=""}[5m]), "pod", ",", "pod_name")) by (pod) / sum(kube_pod_container_resource_requests_cpu_cores{namespace!="kube-system"}) by (pod) > 1.5
>   for: 1m
>   labels:
>     severity: notify
>     frequency: low
>   annotations:
>     summary: Reserved CPU is too low
>     description: At least one Pod uses much more CPU than it reserved
> - alert: ReservedCPUTooHigh
>   expr: sum(label_join(rate(container_cpu_usage_seconds_total{namespace!="kube-system", pod_name!=""}[5m]), "pod", ",", "pod_name")) by (pod) / sum(kube_pod_container_resource_requests_cpu_cores{namespace!="kube-system"}) by (pod) < 0.5 and 
sum(kube_pod_container_resource_requests_cpu_cores{namespace!="kube-system"}) by (pod) > 0.005
>   for: 6m
>   labels:
>     severity: notify
>     frequency: low
>   annotations:
>     summary: Reserved CPU is too high
>     description: At least one Pod uses much less CPU than it reserved
```

前两组差异是为我们之前探讨的`ReservedMemTooLow`和`ReservedMemTooHigh`警报定义更明智的阈值。在更下面，我们可以看到两个新的警报。

如果 CPU 使用量超过请求量的 1.5 倍，将触发`ReservedCPUTooLow`警报。同样，只有当 CPU 使用量少于请求量的一半，并且我们请求的 CPU 毫秒数超过 5 时，才会触发`ReservedCPUTooHigh`警报。因为 5MB RAM 太多而收到通知将是浪费时间。

这两个警报都设置为在短时间内持续存在（`1m`和`6m`），这样我们就可以看到它们的作用，而不必等待太长时间。

现在，让我们使用更新后的值升级我们的 Prometheus 图表。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-req-cpu.yml
```

我会让你去检查是否有任何警报触发，以及它们是否从 Alertmanager 转发到 Slack。你现在应该知道如何做了。

接下来，我们将转移到本章的最后一个警报。

# 比较实际资源使用与定义的限制

了解容器使用资源与请求相比使用过多或过少的情况有助于我们更精确地定义资源，并最终帮助 Kubernetes 更好地决定在哪里调度我们的 Pods。在大多数情况下，请求和实际资源使用之间存在较大的差异通常不会导致故障。相反，更有可能导致 Pods 的分布不平衡或节点过多。另一方面，限制则是另一回事。

如果我们容器作为 Pods 的资源使用达到指定的`limits`，Kubernetes 可能会杀死这些容器，如果没有足够的内存。它这样做是为了保护系统的完整性。被杀死的 Pod 并不是一个永久性的问题，因为 Kubernetes 几乎会立即重新调度它们，如果有足够的容量。

如果我们使用集群自动缩放，即使容量不足，一旦检测到一些 Pod 处于挂起状态（无法调度），新节点将被添加。因此，如果资源使用超过限制，世界不太可能会结束。

然而，杀死和重新安排 Pod 可能会导致停机时间。显然，可能会发生更糟糕的情况。但我们不会深入讨论。相反，我们将假设我们应该意识到一个 Pod 即将达到其极限，我们可能需要调查发生了什么，并且可能需要采取一些纠正措施。也许最新的发布引入了内存泄漏？或者负载增加超出了我们预期和测试的范围，导致内存使用增加。目前不关注接近极限的内存使用的原因，而是关注是否达到了极限。

首先，我们将返回 Prometheus 的图表屏幕。

```
 1  open "http://$PROM_ADDR/graph"
```

我们已经知道可以通过`container_memory_usage_bytes`指标获取实际内存使用情况。由于我们已经探讨了如何获取请求的内存，我们可以猜测极限是类似的。它们确实是，可以通过`kube_pod_container_resource_limits_memory_bytes`获取。由于其中一个指标与以前相同，另一个非常相似，我们将直接执行完整查询。

请键入以下表达式，按“执行”按钮，然后切换到*图表*选项卡。

```
 1  sum(label_join(
 2    container_memory_usage_bytes{
 3      namespace!="kube-system"
 4    }, 
 5    "pod", 
 6    ",", 
 7    "pod_name"
 8  ))
 9  by (pod) /
10  sum(
11    kube_pod_container_resource_limits_memory_bytes{
12      namespace!="kube-system"
13    }
14  )
15  by (pod)
```

在我的情况下（以下是屏幕截图），我们可以看到相当多的 Pod 使用的内存超过了定义的极限。

幸运的是，我的集群中有多余的容量，Kubernetes 没有迫切需要杀死任何 Pod。此外，问题可能不在于 Pod 使用的超出其极限的情况，而是这些 Pod 中并非所有容器都设置了极限。无论哪种情况，我可能应该更新这些 Pod/容器的定义，并确保它们的极限高于几天甚至几周的平均使用量。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dop-25-tk/img/c57b7c9d-4904-4167-b320-ac2a31877b8a.png)图 3-46：基于内存限制的容器内存使用百分比的 Prometheus 图表屏幕，排除了 kube-system 命名空间中的内存使用情况

接下来，我们将详细探讨旧值和新值之间的差异。

```
 1  diff mon/prom-values-req-cpu.yml \
 2      mon/prom-values-limit-mem.yml
```

输出如下。

```
175c175
<   for: 1m
---
>   for: 1h
184c184
<   for: 6m
---
>   for: 6h
190a191,199
> - alert: MemoryAtTheLimit
>   expr: sum(label_join(container_memory_usage_bytes{namespace!="kube-system"}, "pod", ",", "pod_name")) by (pod) / sum(kube_pod_container_resource_limits_memory_bytes{namespace!="kube-system"}) by (pod) > 0.8
>   for: 1h
>   labels:
>     severity: notify
>     frequency: low
>   annotations:
>     summary: Memory usage is almost at the limit
>     description: At least one Pod uses memory that is close it its limit
```

除了恢复以前使用的警报的合理阈值之外，我们定义了一个名为`MemoryAtTheLimit`的新警报。如果实际使用超过极限的百分之八十（`0.8`）超过一小时（`1h`），它将触发。

接下来是升级我们的 Prometheus 图表。

```
 1  helm upgrade -i prometheus \
 2    stable/prometheus \
 3    --namespace metrics \
 4    --version 7.1.3 \
 5    --set server.ingress.hosts={$PROM_ADDR} \
 6    --set alertmanager.ingress.hosts={$AM_ADDR} \
 7    -f mon/prom-values-limit-mem.yml
```

最后，我们可以打开 Prometheus 的警报屏幕，并确认新的警报确实被添加到了其中。

```
 1  open "http://$PROM_ADDR/alerts"
```

我们不会重复为 CPU 创建类似的警报的步骤。你应该知道如何自己做。

# 现在呢？

我们探索了相当多的 Prometheus 指标、表达式和警报。我们看到了如何将 Prometheus 警报与 Alertmanager 连接，并从那里将它们转发到一个应用程序到另一个应用程序。

到目前为止，我们所做的只是冰山一角。要探索所有我们可能使用的指标和表达式将需要太多的时间（和空间）。尽管如此，我相信现在你知道了一些更有用的指标，而且你将能够用你自己特定的指标来扩展它们。

我敦促你发送给我你发现有用的表达式和警报。你知道在哪里找到我（*DevOps20* ([`slack.devops20toolkit.com/`](http://slack.devops20toolkit.com/)) Slack，`viktor@farcic` 邮件，`@vfarcic` 推特，等等）。

目前，我会让你决定是直接进入下一章，销毁整个集群，还是只移除我们安装的资源。如果你选择后者，请使用接下来的命令。

```
 1  helm delete prometheus --purge
 2
 3  helm delete go-demo-5 --purge
 4
 5  kubectl delete ns go-demo-5 metrics
```

在你离开之前，你可能想回顾一下本章的要点。

+   Prometheus 是一个设计用于获取（拉取）和存储高维时间序列数据的数据库（某种程度上）。

+   每个人都应该利用的四个关键指标是延迟、流量、错误和饱和度。
