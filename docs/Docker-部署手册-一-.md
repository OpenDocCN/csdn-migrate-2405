# Docker 部署手册（一）

> 原文：[`zh.annas-archive.org/md5/0E809A4AEE99AC7378E63C4191A037CF`](https://zh.annas-archive.org/md5/0E809A4AEE99AC7378E63C4191A037CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

微服务和容器已经成为必不可少的存在，在当今世界中，Docker 正成为可伸缩性的事实标准。将 Docker 部署到生产环境被认为是开发大规模基础设施的主要痛点之一，而在线文档的质量令人不满意。通过本书，您将接触到各种工具、技术和可用的解决方法，这些都是基于作者在自己的云环境中开发和部署 Docker 基础设施的真实经验。您将学到一切您想要了解的内容，以有效地扩展全球部署，并为自己构建一个具有弹性和可伸缩性的容器化云平台。

# 本书内容包括

第一章，*容器-不只是另一个时髦词*，探讨了部署服务的当前方法以及为什么容器和特别是 Docker 正在超越其他形式的基础设施部署。

第二章，*动手实践*，介绍了设置和运行基于 Docker 的小型本地服务的所有必要步骤。我们将介绍如何安装 Docker，运行它，并快速了解 Docker CLI。有了这些知识，我们将编写一个基本的 Docker 容器，并了解如何在本地运行它。

第三章，*服务分解*，介绍如何利用前一章的知识来创建和构建数据库和应用服务器容器的附加部分，以反映简单的分解微服务部署。

第四章，*扩展容器*，讨论了通过多个相同容器实例的水平扩展。我们将介绍服务发现，以及如何部署一个模块，使其对基础设施的其余部分透明，以及根据实现方式的各种利弊，快速了解水平节点扩展。

第五章，*保持数据持久*，介绍了容器的数据持久性。我们将介绍节点本地存储、瞬态存储和持久卷及其复杂性。我们还将花一些时间讨论 Docker 镜像分层和一些潜在问题。

第六章，*高级部署主题*，在集群中增加了隔离和消息传递，以增加服务的安全性和稳定性。本章还将涵盖 Docker 部署中的其他安全考虑及其权衡。

第七章，*扩展的限制和解决方法*，涵盖了您在超出基本 RESTful 服务需求时可能遇到的所有问题。我们将深入探讨您在默认部署中可能遇到的问题，以及如何通过最小的麻烦来解决它们，以及处理代码版本更改和更高级别的管理系统。

第八章，*构建我们自己的平台*，帮助我们在本章中构建我们自己的迷你**平台即服务**（**PaaS**）。我们将涵盖从配置管理到在云环境中部署的一切内容，您可以使用它来启动您自己的云。

第九章，*探索最大规模部署*，涵盖了我们建立的内容，并延伸到 Docker 最大规模部署的理论和实际示例，还涵盖了读者应该留意的未来任何发展。

# 本书所需内容

在开始阅读本书之前，请确保您具备以下条件：

+   基于 Intel 或 AMD 的 x86_64 机器

+   至少 2GB 的 RAM

+   至少 10GB 的硬盘空间

+   Linux（Ubuntu、Debian、CentOS、RHEL、SUSE 或 Fedora）、Windows 10、Windows Server 2016 或 macOS

+   互联网连接

# 本书适合谁

本书面向系统管理员、开发人员、DevOps 工程师和软件工程师，他们希望获得使用 Docker 部署多层 Web 应用程序和容器化微服务的具体实践经验。它适用于任何曾经以某种方式部署服务并希望将其小规模设置提升到下一个数量级或者想要了解更多的人。

# 规范

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码词、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："如果您再次在浏览器中输入`http://127.0.0.1:8080`，您将看到我们的应用程序与以前一样工作！"

代码块设置如下：

```
    # Make sure we are fully up to date
    RUN apt-get update -q && \
    apt-get dist-upgrade -y && \
    apt-get clean && \
    apt-get autoclean
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```
    # Make sure we are fully up to date
    RUN apt-get update -q && \
 apt-get dist-upgrade -y && \
    apt-get clean && \
    apt-get autoclean
```

任何命令行输入或输出都会按照以下方式书写：

```
$ docker swarm leave --force
Node left the swarm.
```

**新术语**和**重要单词**以粗体显示。屏幕上显示的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："为了下载新模块，我们将转到 文件 | 设置 | 项目名称 | 项目解释器。"

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：容器-不只是另一个时髦词汇

在技术领域，有时进步的跳跃很小，但就像容器化一样，这种跳跃是巨大的，完全颠覆了长期以来的实践和教学。通过这本书，我们将带你从运行一个微小的服务到使用 Docker 构建弹性可扩展的系统，Docker 是这场革命的基石。我们将通过基本模块进行稳定而一致的升级，重点关注 Docker 的内部工作，随着我们的继续，我们将尽量花费大部分时间在复杂部署及其考虑的世界中。

让我们来看看本章我们将涵盖的内容：

+   什么是容器，为什么我们需要它们？

+   Docker 在容器世界中的地位

+   以容器思维思考

# 容器的作用和意义

我们不能谈论 Docker 而不实际涵盖使其成为强大工具的想法。在最基本的层面上，容器是给定离散功能集的隔离用户空间环境。换句话说，这是一种将系统（或其中的一部分）模块化为更容易管理和维护的部分的方式，同时通常也非常耐用。

实际上，这种净收益从来都不是免费的，需要在采用和实施新工具（如 Docker）上进行一些投资，但这种变化在其生命周期内大大减少了开发、维护和扩展成本，为采用者带来了丰厚的回报。

在这一点上，你可能会问：容器究竟如何能够提供如此巨大的好处？要理解这一点，我们首先需要看一下在此类工具可用之前的部署情况。

在早期的部署中，部署服务的过程大致如下：

1.  开发人员会编写一些代码。

1.  运维团队会部署该代码。

1.  如果部署中出现任何问题，运维团队会告诉开发人员修复一些东西，然后我们会回到第一步。

这个过程的简化看起来大致如下：

```
dev machine => code => ops => bare-metal hosts
```

开发人员必须等待整个过程为他们弹回，以尝试在出现问题时编写修复程序。更糟糕的是，运维团队通常必须使用各种古怪的魔法来确保开发人员给他们的代码实际上可以在部署机器上运行，因为库版本、操作系统补丁和语言编译器/解释器的差异都是高风险的失败，并且很可能在这个漫长的破坏-修补-部署尝试周期中花费大量时间。

部署演进的下一步是通过虚拟化裸机主机来改进这个工作流程，因为手动维护异构机器和环境的混合是一场完全的噩梦，即使它们只有个位数。早期的工具如`chroot`在 70 年代后期出现，但后来被（尽管没有完全）Xen、KVM、Hyper-V 等虚拟化技术所取代，这不仅减少了更大系统的管理复杂性，还为运维人员和开发人员提供了更一致、更计算密集的部署环境。

```
dev machine => code => ops => n hosts * VM deployments per host
```

这有助于减少管道末端的故障，但从开发人员到部署的路径仍然存在风险，因为虚拟机环境很容易与开发人员不同步。

从这里开始，如果我们真的试图找出如何使这个系统更好，我们已经可以看到 Docker 和其他容器技术是有机的下一步。通过使开发人员的沙盒环境尽可能接近生产环境，具有足够功能的容器系统的开发人员可以绕过运维步骤，确保代码在部署环境上能够运行，并防止由于多个团队交互的开销而导致的漫长重写周期：

```
dev machine => container => n hosts * VM deployments per host
```

随着运维主要在系统设置的早期阶段需要，开发人员现在可以直接将他们的代码从想法一直推送到用户，他们可以有信心地解决大部分问题。

如果你认为这是部署服务的新模式，那么现在理解为什么我们现在有了 DevOps 角色，为什么**平台即服务**（PaaS）设置如此受欢迎，以及为什么如此多的科技巨头可以在 15 分钟内通过开发人员的`git push origin`这样简单的操作对数百万人使用的服务进行更改，而无需与系统进行任何其他交互，是非常合理的。

但好处并不仅限于此！如果你到处都有许多小容器，如果你对某项服务的需求增加或减少，你可以增加或减少主机的一部分，如果容器编排做得当，那么在扩展或缩减时将会零停机和用户察觉不到的变化。这对需要在不同时间处理可变负载的服务提供商非常方便--以 Netflix 及其高峰观看时间为例。在大多数情况下，这些也可以在几乎所有云平台上自动化（即 AWS 自动扩展组，Google 集群自动缩放器和 Azure 自动缩放器），因此，如果发生某些触发器或资源消耗发生变化，服务将自动扩展和缩减主机数量以处理负载。通过自动化所有这些过程，你的 PaaS 基本上可以成为一个灵活的一劳永逸的层，开发人员可以在其上担心真正重要的事情，而不必浪费时间去弄清楚一些系统库是否安装在部署主机上。

现在不要误会我的意思；制作这些令人惊叹的 PaaS 服务绝非易事，而且道路上布满了无数隐藏的陷阱，但如果你想在夜间能够安然入睡，不受愤怒客户、老板或同事的电话骚扰，无论你是开发人员还是其他人，你都必须努力尽可能接近这些理想的设置。

# Docker 的位置

到目前为止，我们已经谈了很多关于容器，但还没有提到 Docker。虽然 Docker 已经成为容器化的事实标准，但它目前是这个领域中许多竞争技术之一，今天相关的内容可能明天就不再适用。因此，我们将涵盖一些容器生态系统的内容，这样如果你看到这个领域发生变化，不要犹豫尝试其他解决方案，因为选择合适的工具几乎总是比试图“把方形钉子塞进圆孔”更好。

虽然大多数人知道 Docker 作为**命令行界面**（**CLI**）工具，但 Docker 平台扩展到包括创建和管理集群的工具、处理持久存储、构建和共享 Docker 容器等等，但现在，我们将专注于该生态系统中最重要的部分：Docker 容器。

# Docker 容器简介

Docker 容器本质上是一组文件系统层，这些层按顺序堆叠在一起，以创建最终的布局，然后由主机机器的内核在隔离的环境中运行。每个层描述了相对于其上一个父层添加、修改和/或删除的文件。例如，你有一个基本层，其中有一个文件`/foo/bar`，下一个层添加了一个文件`/foo/baz`。当容器启动时，它将按顺序组合层，最终的容器将同时拥有`/foo/bar`和`/foo/baz`。对于任何新层，这个过程都会重复，以得到一个完全组成的文件系统来运行指定的服务或服务。

把镜像中文件系统层的安排想象成交响乐中复杂的层次：你有后面的打击乐器提供声音的基础，稍微靠前的吹奏乐器推动乐曲的发展，最前面的弦乐器演奏主旋律。一起，它创造了一个令人愉悦的最终结果。在 Docker 的情况下，通常有基本层设置主要的操作系统层和配置，服务基础设施层放在其上（解释器安装，辅助工具的编译等），最终运行的镜像最终是实际的服务代码。现在，这就是你需要知道的全部，但我们将在下一章节中更详细地涵盖这个主题。

实质上，Docker 在其当前形式下是一个平台，允许在容器内轻松快速地开发隔离的（或者取决于服务配置的）Linux 和 Windows 服务，这些容器是可扩展的，易于互换和分发的。

# 竞争

在我们深入讨论 Docker 本身之前，让我们也大致了解一下一些当前的竞争对手，并看看它们与 Docker 本身的区别。几乎所有这些竞争对手的有趣之处在于，它们通常是围绕 Linux 控制组（`cgroups`）和命名空间的一种抽象形式，这些控制组限制了 Linux 主机的物理资源的使用，并将进程组相互隔离。虽然这里提到的几乎所有工具都提供了某种资源的容器化，但在隔离深度、实现安全性和/或容器分发方面可能存在很大差异。

# rkt

`rkt`，通常写作**Rocket**，是来自 CoreOS 的最接近的竞争应用容器化平台，它最初是作为更安全的应用容器运行时启动的。随着时间的推移，Docker 已经解决了许多安全问题，但与`rkt`不同的是，它以有限的权限作为用户服务运行，而 Docker 的主要服务以 root 权限运行。这意味着如果有人设法打破 Docker 容器，他们将自动获得对主机 root 的完全访问权限，从运营的角度来看，这显然是一个非常糟糕的事情，而使用`rkt`，黑客还需要提升他们的权限从有限用户。虽然从安全的角度来看，这里的比较并没有给 Docker 带来太大的光明，但如果其发展轨迹可以被推断，这个问题可能会在未来得到很大程度的缓解和/或修复。

另一个有趣的区别是，与 Docker 不同，它被设计为在容器内运行单个进程，`rkt`可以在一个容器内运行多个进程。这使得在单个容器内部部署多个服务变得更加容易。现在，话虽如此，你实际上*可以*在 Docker 容器内运行多个进程（我们将在本书的后面部分介绍），但是正确设置这一点是非常麻烦的，但我在实践中发现，保持基于单个进程的服务和容器的压力确实促使开发人员创建真正的微服务容器，而不是将它们视为迷你虚拟机，所以不一定认为这是一个问题。

虽然有许多其他较小的原因可以选择 Docker 而不是`rkt`，反之亦然，但有一件重要的事情是无法忽视的：采用速度。虽然`rkt`有点年轻，但 Docker 已经被几乎所有大型科技巨头采用，而且似乎没有任何停止这一趋势的迹象。考虑到这一点，如果您今天需要处理微服务，选择可能非常明确，但与任何技术领域一样，生态系统在一年甚至只是几个月内可能看起来大不相同。

# 系统级虚拟化

在对立的一面，我们有用于处理完整系统镜像而不是像 LXD、OpenVZ、KVM 和其他一些应用程序的平台。与 Docker 和`rkt`不同，它们旨在为您提供所有虚拟化系统服务的全面支持，但纯粹从定义上来说，资源使用成本要高得多。虽然在主机上拥有单独的系统容器对于诸如更好的安全性、隔离性和可能的兼容性之类的事情是必要的，但根据个人经验，几乎所有这些容器的使用都可以转移到应用级虚拟化系统，只需进行一些工作即可提供更好的资源使用配置文件和更高的模块化，而在创建初始基础设施时稍微增加成本。在这里要遵循的一个明智的规则是，如果您正在编写应用程序和服务，您可能应该使用应用级虚拟化，但如果您正在为最终用户提供 VM 或者希望在服务之间获得更高的隔离性，您应该使用系统级虚拟化。

# 桌面应用程序级虚拟化

Flatpak、AppImage、Snaps 和其他类似技术也为单应用级容器提供隔离和打包，但与 Docker 不同，它们都针对部署桌面应用程序，并且对容器的生命周期（启动、停止、强制终止等）没有如此精确的控制，也通常不提供分层镜像。相反，大多数这些工具都有很好的图形用户界面（GUI），并为安装、运行和更新桌面应用程序提供了显着更好的工作流程。虽然由于对所述 cgroups 和命名空间的相同依赖，大多数与 Docker 有很大的重叠，但这些应用级虚拟化平台通常不处理服务器应用程序（没有 UI 组件运行的应用程序），反之亦然。由于这个领域仍然很年轻，它们所覆盖的空间相对较小，你可能可以期待整合和交叉，因此在这种情况下，要么是 Docker 进入桌面应用程序交付领域，要么是其中一个或多个竞争技术尝试支持服务器应用程序。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/2116c6db-41e5-4d76-a139-1bbeea570d3b.png)

# 何时应考虑容器化？

到目前为止，我们已经涵盖了很多内容，但有一个重要的方面我们还没有涵盖，但这是一个非常重要的事情要评估，因为在许多情况下容器化并不合理，无论这个概念有多大的关注度，所以我们将涵盖一些真正应该考虑（或不应该考虑）这种类型平台的一般用例。虽然从运营角度来看，容器化应该是大多数情况下的最终目标，并且在注入到开发过程中时可以带来巨大的回报，但将部署机器转变为容器化平台是一个非常棘手的过程，如果你无法从中获得实际的好处，那么你可能还不如把这段时间用在能为你的服务带来真正和实际价值的事情上。

让我们首先从覆盖缩放阈值开始。如果你的服务作为一个整体可以完全适应并在相对较小或中等虚拟机或裸金属主机上良好运行，并且你不预期突然的扩展需求，部署机器上的虚拟化将使你陷入痛苦的道路，在大多数情况下并不合理。即使是建立一个良性但健壮的虚拟化设置的高前期成本，通常也更好地花在该级别的服务功能开发上。

如果你看到一个由虚拟机或裸金属主机支持的服务需求增加，你可以随时将其扩展到更大的主机（垂直扩展）并重新聚焦你的团队，但除此之外，你可能不应该选择这条路。有许多情况下，一家企业花了几个月的时间来实施容器技术，因为它非常受欢迎，最终由于缺乏开发资源而失去了客户，不得不关闭他们的业务。

现在你的系统正在达到垂直可扩展性的极限，是时候添加诸如 Docker 集群之类的东西了吗？真正的答案是“可能”。如果你的服务在主机上是同质的和一致的，比如分片或集群数据库或简单的 API，在大多数情况下，现在也不是合适的时机，因为你可以通过主机镜像和某种负载均衡器轻松扩展这个系统。如果你想要更多的花样，你可以使用基于云的“数据库即服务”（DBaaS），比如 Amazon RDS、Microsoft DocumentDB 或 Google BigQuery，并根据所需的性能水平通过同一提供商（甚至是不同的提供商）自动扩展服务主机。

如果除此之外还有大量的服务种类预示着，需要从开发人员到部署的更短管道，不断增长的复杂性或指数级增长，你应该将这些都视为重新评估你的利弊的触发器，但没有明确的阈值会成为一个明确的切入点。然而，在这里一个很好的经验法则是，如果你的团队有一个缓慢的时期，探索容器化选项或提升你在这个领域的技能不会有害，但一定要非常小心，不要低估设置这样一个平台所需的时间，无论这些工具中的许多看起来多么容易入门。

有了这一切，什么是你需要尽快将容器纳入工作流程的明显迹象？这里可能有许多微妙的暗示，但以下清单涵盖了如果答案是肯定的话，应立即讨论容器主题的迹象，因为其好处大大超过了投入服务平台的时间：

+   你的部署中是否有超过 10 个独特、离散且相互连接的服务？

+   你是否需要在主机上支持三种或更多编程语言？

+   你的运维资源是否不断部署和升级服务？

+   你的任何服务需要“四个 9”（99.99%）或更高的可用性吗？

+   你的部署中是否有服务经常在部署中出现故障的模式，因为开发人员没有考虑到服务将在其中运行的环境？

+   你是否有一支才华横溢的开发或运维团队闲置着？

+   你的项目是否在挥霍金钱？

好吧，也许最后一个有点玩笑，但它在清单中是为了以一种讽刺的语气来说明，写作时让 PaaS 平台运行、稳定和安全既不容易也不便宜，无论你的货币是时间还是金钱。许多人会试图欺骗你，让你认为你应该始终使用容器并使所有东西都 Docker 化，但保持怀疑的心态，并确保你仔细评估你的选择。

# 理想的 Docker 部署

既然我们已经完成了真实的谈话部分，让我们说我们真的准备好了来处理容器和 Docker 的虚构服务。我们在本章的前面已经涵盖了一些内容，但在这里，我们将明确定义我们的理想要求会是什么样子，如果我们有充足的时间来处理它们：

+   开发人员应能够部署新服务，而无需任何运维资源

+   系统可以自动发现正在运行的服务的新实例

+   系统在上下都具有灵活的可扩展性

+   在所需的代码提交上，新代码将在没有开发或运维干预的情况下自动部署

+   你可以无缝地处理降级节点和服务，而不会中断。

+   你能够充分利用主机上可用的资源（RAM、CPU 等）

+   节点几乎不需要被开发人员单独访问

如果这些是要求，您会高兴地知道几乎所有这些要求在很大程度上都是可行的，我们将在本书中详细介绍几乎所有这些要求。对于其中的许多要求，我们需要更深入地了解 Docker，并超越大多数其他材料，但教授您无法应用到实际场景的部署是没有意义的，这些部署只会打印出“Hello World”。

在我们探索以下章节中的每个主题时，我们一定会涵盖任何潜在的问题，因为有许多这样复杂的系统交互。有些对您来说可能很明显，但许多可能不会（例如 PID1 问题），因为这个领域的工具在相对年轻，许多对 Docker 生态系统至关重要的工具甚至还没有达到 1.0 版本，或者最近才达到 1.0 版本。

因此，您应该考虑这个技术领域仍处于早期发展阶段，所以要现实一点，不要期望奇迹，预期会有一些小“陷阱”。还要记住，一些最大的科技巨头现在已经使用 Docker 很长时间了（红帽、微软、谷歌、IBM 等），所以也不要感到害怕。

要开始并真正开始我们的旅程，我们需要首先重新考虑我们对服务的思考方式。

# 容器思维

今天，正如我们在本章稍早已经涵盖的那样，今天部署的绝大多数服务都是一团杂乱的临时或手动连接和配置的部分，一旦其中一个部分发生变化或移动，整个结构就会分崩离析。很容易想象这就像一堆纸牌，需要更改的部分通常位于其中间，存在风险将整个结构拆除。小到中等规模的项目和有才华的开发和运维团队大多可以管理这种复杂性，但这真的不是一种可扩展的方法。

# 开发者工作流程

即使您不是在开发 PaaS 系统，考虑将服务的每个部分都视为应该在开发人员和最终部署主机之间具有一致的环境，能够在任何地方运行并进行最小的更改，并且足够模块化，以便在需要时可以用 API 兼容的类似物替换。对于许多这种情况，即使是本地 Docker 使用也可以在使部署更容易方面发挥作用，因为您可以将每个组件隔离成不随着开发环境的变化而改变的小部分。

为了说明这一点，想象一个实际情况，我们正在编写一个简单的 Web 服务，该服务与基于最新 Ubuntu 的系统上的数据库进行通信，但我们的部署环境是 CentOS 的某个迭代版本。在这种情况下，由于它们支持周期长度的巨大差异，协调不同版本和库将非常困难，因此作为开发人员，您可以使用 Docker 为您提供与 CentOS 相同版本的数据库，并且您可以在基于 CentOS 的容器中测试您的服务，以确保所有库和依赖项在部署时可以正常工作。即使真实的部署主机没有容器化，这个过程也会改善开发工作流程。

现在，我们将以稍微更加现实的方向来看待这个例子：如果您需要在所有当前支持的 CentOS 版本上无需修改代码即可运行您的服务呢？

使用 Docker，您可以为每个操作系统版本创建一个容器，以便测试服务，以确保不会出现任何意外。另外，您可以自动化一个测试套件运行程序，逐个（甚至更好的是并行）启动每个操作系统版本的容器，以便在任何代码更改时自动运行整个测试套件。通过这些小的调整，我们已经将一个经常在生产中出现故障的临时服务转变为几乎不需要担心的东西，因为您可以确信它在部署时会正常工作，这是一个非常强大的工具。

如果您扩展这个过程，您可以在本地创建 Docker 配方（Dockerfiles），我们将在下一章中详细介绍，其中包含从纯净的 CentOS 安装到完全能够运行服务所需的确切步骤。这些步骤可以由运维团队以最小的更改作为输入，用于他们的自动化配置管理（CM）系统，如 Ansible、Salt、Puppet 或 Chef，以确保主机具有运行所需的确切基线。由服务开发人员编写的端目标上所需的确切步骤的编码传递，这正是 Docker 如此强大的原因。

希望显而易见的是，Docker 作为一种工具不仅可以改善部署机器上的开发流程，而且还可以在整个过程中用于标准化您的环境，从而提高几乎每个部署流程的效率。有了 Docker，您很可能会忘记那句让每个运维人员感到恐惧的臭名昭著的短语：“在我的机器上运行良好！”这本身就足以让您考虑在部署基础设施不支持容器的情况下，插入基于容器的工作流程。

在这里我们一直在绕着弯子说的底线是，您应该始终考虑的是，使用当前可用的工具，将整个部署基础设施转变为基于容器的基础设施略微困难，但在开发流程的任何其他部分添加容器通常并不太困难，并且可以为您的团队提供指数级的工作流程改进。

# 总结

在本章中，我们沿着部署的历史走了一遍，并看了看 Docker 容器是如何让我们更接近微服务的新世界的。我们对 Docker 进行了审查，概述了我们最感兴趣的部分。我们涵盖了竞争对手以及 Docker 在生态系统中的定位和一些使用案例。最后，我们还讨论了何时应该考虑容器在基础架构和开发工作流程中，更重要的是，何时不应该考虑。

在下一章中，我们最终将动手并了解如何安装和运行 Docker 镜像，以及创建我们的第一个 Docker 镜像，所以一定要继续关注。


# 第二章：卷起袖子

在上一章中，我们看了容器是什么，它们在基础设施中可以扮演什么角色，以及为什么 Docker 是服务部署中的领头羊。现在我们知道了 Docker 是什么，也知道了它不是什么，我们可以开始基础知识了。在本章中，我们将涵盖以下主题：

+   安装 Docker

+   扩展一个容器

+   构建一个容器

+   调试容器

# 安装 Docker

Docker 的安装在操作系统之间有很大的差异，但对于大多数系统，都有详细的说明。通常有两个级别的 Docker 可用：**社区版**（**CE**）和**企业版**（**EE**）。虽然略有不同，但对于本书中我们将要处理的几乎所有内容来说，社区版都是完全功能的，完全够用。一旦你达到需要更高级功能的规模，比如安全扫描、LDAP 和技术支持，企业版可能是有意义的。不出所料，企业版是收费的，您可以查看[`www.docker.com/pricing`](https://www.docker.com/pricing)来了解这些版本的区别。

对于本书中的示例和任何特定于操作系统的命令，从现在开始，我们将使用 Ubuntu 的**长期支持**（**LTS**）版本，Ubuntu 目前是最流行的 Linux 发行版。 LTS 产品的最新版本是 16.04，这将是我们 CLI 交互和示例的基础，但在您阅读本书时，18.04 也可能已经推出。请记住，除了安装部分外，大多数代码和示例都是非常可移植的，通常可以在其他平台上运行，因此即使需要进行更改，也应该是最小的。也就是说，在非 Linux 平台上开发 Docker 服务可能不太精细或稳定，因为 Docker 通常用于在 Linux 机器上部署基于 Linux 的服务，尽管其他一些特殊情况也得到了一定程度的支持。自从微软试图推动他们自己的容器策略以来，他们在这个领域取得了重大进展，因此请密切关注他们的进展，因为它可能成为一个非常有竞争力的开发平台。

一些后续章节中的手动网络示例在 macOS 中可能无法完全工作，因为该平台对该子系统的实现不同。对于这些情况，建议您在虚拟机上使用 Ubuntu LTS 进行跟随操作。

因此，使用我们干净的 Ubuntu 16.04 LTS 机器、虚拟机或兼容的操作系统，让我们安装 Docker。虽然 Docker 软件包已经在分发中的`apt`仓库中可用，但我强烈不建议以这种方式安装，因为这些版本通常要旧得多。虽然对于大多数软件来说这不是问题，但对于像 Docker 这样快速发展的项目来说，这将使您在支持最新功能方面处于明显的劣势。因此，出于这个原因，我们将从 Docker 自己的 apt 仓库中安装 Docker：

警告！还有其他几种安装 Docker 的方法，但除非绝对必要，使用`sudo curl -sSL https://somesite.com/ | sh`模式或类似的方式进行安装是非常危险的，因为您在未检查脚本功能的情况下为网站的脚本授予了 root 权限。这种执行模式也几乎没有留下执行过程的证据。此外，中途出现的异常可能会损坏下载文件但仍然执行，部分造成损害，并且您只依赖**传输层安全性**（**TLS**），全球数百家组织都可以创建伪造证书。换句话说，如果您关心您的机器，除非软件供应商对安全一无所知并且他们强迫您这样做，否则您绝对不应该以这种方式安装软件，那么您就完全受他们的支配。

```
$ # Install the pre-requisites
$ sudo apt install -y apt-transport-https \
                      curl

$ # Add Docker's signing key into our apt configuration to ensure they are the only ones that can send us updates. This key should match the one that the apt repository is using so check the online installation instruction if you see "NO_PUBKEY <key_id>" errors.
$ apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 \
              --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

$ # Add the repository location to apt. Your URL may be different depending on if Xenial is your distribution.
$ echo "deb https://apt.dockerproject.org/repo ubuntu-xenial main" | sudo tee -a /etc/apt/sources.list.d/docker.list

$ # Update the apt listings and install Docker
$ sudo apt update
$ sudo apt install docker-engine
```

默认情况下，Docker 将要求在所有命令前加上`sudo`（或`root`）来运行，包括本书中未明确提到的命令。通常情况下，对于开发机器来说，这是一个很大的麻烦，所以我可能会提到，但*强烈*不建议，您也可以将当前用户添加到`docker`组中，这样您就不需要在每个 Docker 命令前加上`sudo`：

1.  使用`usermod`将用户添加到组中（例如`$ sudo usermod -aG docker $USER`）。

1.  完全注销并重新登录（组仅在会话启动时进行评估）。

请记住，这是一个*巨大*的安全漏洞，可以允许本地用户轻松提升为根权限，因此在任何情况下都不要在任何将连接到互联网的服务器上执行此操作。

如果所有前面的命令都按预期工作，您将能够看到 Docker 是否已安装：

```
$ docker --version
Docker version 17.05.0-ce, build 89658be
```

安装了 Docker 但没有任何东西可运行是相当无用的，所以让我们看看是否可以获得一个可以在本地运行的镜像。我们的选择是要么从头开始制作自己的镜像，要么使用已经构建好的东西。鉴于 Docker 之所以能够达到如此高的采用率的一个重要原因是通过 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）轻松共享镜像，而我们刚刚开始，我们将延迟一点时间来创建自己的镜像，以探索这个站点，这是一个集中发布和下载 Docker 镜像的地方。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/23f9cd78-8642-458f-a455-be3f7500a5c8.png)

在这个非描述性和单调的页面背后是成千上万的 Docker 镜像的存储，由于我们目前不感兴趣发布镜像，我们可以点击页面右上角的“探索”按钮，看看有哪些可用的镜像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/aa15341a-9d6e-4376-a016-ff0167b56dd5.png)

正如您所看到的，这列出了写作时最受欢迎的镜像，但您也可以通过左上角的搜索框查找特定的镜像。目前，正如之前提到的，我们不会在这里花太多时间，但对于您来说，了解如何从 Docker Hub 运行镜像将是有价值的，因此我们将尝试拉取和运行其中一个来向您展示如何操作。

目前可用的顶级容器似乎是 NGINX，所以我们将尝试在我们的 Docker 环境中运行它。如果您以前没有使用过 NGINX，它是一个高性能的 Web 服务器，被许多互联网上的网站使用。在这个阶段，我们只是想要感受一下运行这些容器的感觉，让我们看看如何做到：

```
$ # Pull the image from the server to our local repository
$ docker pull nginx
Using default tag: latest
latest: Pulling from library/nginx
94ed0c431eb5: Pull complete
9406c100a1c3: Pull complete
aa74daafd50c: Pull complete
Digest: sha256:788fa27763db6d69ad3444e8ba72f947df9e7e163bad7c1f5614f8fd27a311c3
Status: Downloaded newer image for nginx:latest
```

`pull`命令拉取组成此镜像的任何和所有层。在这种情况下，NGINX 镜像基于三个堆叠的层，并且具有哈希值`788fa277..27a311c3`，由于我们没有指定我们想要的特定版本，我们得到了默认标签，即`latest`。通过这个单一的命令，我们已经从 Docker Hub 检索了 NGINX 镜像，以便我们可以在本地运行它。如果我们想使用不同的标签或从不同的服务器拉取，该命令将变得更加具有表现力，类似于`docker pull <hostname_or_ip>:<port>/<tag_name>`，但我们将在后面的章节中介绍这些高级用法。

现在，镜像已经存储在我们本地的 Docker 存储中（通常在`/var/lib/docker`中），我们可以尝试运行它。NGINX 有大量可能的选项，您可以在[`hub.docker.com/_/nginx/`](https://hub.docker.com/_/nginx/)上进一步了解，但我们现在只对启动镜像感兴趣：

```
$ docker run nginx
```

您可能注意到什么都没有发生，但不要担心，这是预期的。遗憾的是，单独这个命令是不够的，因为 NGINX 将在前台运行，并且根本无法通过套接字访问，所以我们需要覆盖一些标志和开关，使其真正有用。所以让我们按下*Ctrl* + *C*关闭容器，然后再试一次，这次添加一些必要的标志：

```
$ docker run -d \
             -p 8080:80 \
             nginx
dd1fd1b62d9cf556d96edc3ae7549f469e972267191ba725b0ad6081dda31e74
```

`-d`标志以后台模式运行容器，这样我们的终端就不会被 NGINX 占用，而`-p 8080:80`标志将我们的本地端口`8080`映射到容器的端口`80`。容器通常会暴露特定的端口，而在这种情况下，是`80`，但如果没有映射，我们将无法访问它。命令返回的输出是一个唯一的标识符（容器 ID），可以用来在启动后跟踪和控制这个特定的容器。希望您现在能够看到 Docker 的端口白名单方法如何增加了额外的安全级别，因为只有您明确允许监听的东西才被允许。

现在，您可以打开浏览器访问`http://localhost:8080`，您应该会看到一个类似这样的页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/287da44a-bb94-449b-8065-7dd405fd8a17.png)

但是我们究竟是如何知道端口`80`需要被监听的呢？确实，我们将在接下来的一秒钟内介绍这一点，但首先，因为我们以分离模式启动了这个容器，它仍然在后台运行，我们可能应该确保停止它。要查看我们正在运行的容器，让我们用`docker ps`来检查我们的 Docker 容器状态：

```
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
dd1fd1b62d9c nginx "nginx -g 'daemon ..." 13 minutes ago Up 13 minutes 0.0.0.0:8080->80/tcp dazzling_swanson
```

我们在这里看到的是，我们的 NGINX 容器仍在运行，它已经将本地主机接口端口`8080`（包括外部可访问的端口）映射到容器的端口`80`，而且我们已经运行了`13`分钟。如果我们有更多的容器，它们都会在这里列出，因此这个命令对于处理 Docker 容器非常有用，通常用于调试和容器管理。

由于我们想要关闭这个容器，我们现在将实际执行。要关闭容器，我们需要知道容器 ID，这是`docker run`返回的值，也是`docker ps`的第一列显示的值（`dd1fd1b62d9c`）。可以使用 ID 的短或长版本，但为了简洁起见，我们将使用前者：

```
$ docker stop dd1fd1b62d9c
dd1fd1b62d9c
```

这将优雅地尝试停止容器并将使用的资源返回给操作系统，并在特定的超时后强制杀死它。如果容器真的卡住了，我们可以用`kill`替换`stop`来强制杀死进程，但这很少需要，因为如果进程没有响应，`stop`通常会做同样的事情。我们现在要确保我们的容器已经消失了：

```
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
```

是的，事情看起来正如我们所期望的那样，但请注意，虽然停止的容器不可见，但默认情况下它们并没有完全从文件系统中删除：

```
$ docker ps -a
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
dd1fd1b62d9c nginx "nginx -g 'daemon ..." 24 minutes ago Exited (137) 2 minutes ago dazzling_swanson
```

`-a`标志用于显示所有容器状态，而不仅仅是正在运行的容器，您可以看到系统仍然知道我们的旧容器。我们甚至可以使用`docker start`来恢复它！

```
$ docker start dd1fd1b62d9c
dd1fd1b62d9c

$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
dd1fd1b62d9c nginx "nginx -g 'daemon ..." 28 minutes ago Up About a minute 0.0.0.0:8080->80/tcp dazzling_swanson
```

要真正永久删除容器，我们需要明确地使用`docker rm`来摆脱它，如下所示，或者使用`--rm`开关运行`docker run`命令（我们将在接下来的几页中介绍这个）：

```
$ docker stop dd1fd1b62d9c
dd1fd1b62d9c

$ docker rm dd1fd1b62d9c
dd1fd1b62d9c

$ docker ps -a
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
```

成功！

现在让我们回到之前的问题，我们如何知道容器需要将端口 80 映射到它？我们有几种选项可以找到这些信息，最简单的一种是启动容器并在`docker ps`中检查未绑定的端口：

```
$ docker run -d \
             --rm \
             nginx
f64b35fc42c33f4af2648bf4f1dce316b095b30d31edf703e099b93470ab725a

$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
f64b35fc42c3 nginx "nginx -g 'daemon ..." 4 seconds ago Up 3 seconds 80/tcp awesome_bell
```

我们在`docker run`中使用的新标志是`--rm`，我们刚刚提到过，它告诉 Docker 守护程序在停止后完全删除容器，这样我们就不必手动删除了。

如果您已经有一个要检查映射端口的容器，可以使用`docker port <container_id>`命令，但我们在这里省略了，因为它不能用于镜像，而只能用于容器。

虽然这是查看所需端口的最快方法，但在读取其 Dockerfile 和文档之外检查镜像的一般方法是通过`docker inspect`：

```
$ # Inspect NGINX image info and after you match our query, return also next two lines
$ docker inspect nginx | grep -A2 "ExposedPorts"
"ExposedPorts": {
 "80/tcp": {}
},
```

此外，`docker inspect`还可以显示各种其他有趣的信息，例如以下内容：

+   镜像的 ID

+   标签名称

+   镜像创建日期

+   硬编码的环境变量

+   容器在启动时运行的命令

+   容器的大小

+   镜像层 ID

+   指定的卷

随时运行检查命令在任何容器或镜像上，并查看您可能在那里找到的宝石。大多数情况下，这个输出主要用于调试，但在镜像文档缺乏的情况下，它可以是一个无价的工具，让您在最短的时间内运行起来。

# 调试容器

通常在与容器一般工作中，您可能需要弄清楚正在运行的容器的情况，但`docker ps`并不能提供您需要弄清楚事情的所有信息。对于这些情况，要使用的第一个命令是`docker logs`。这个命令显示容器发出的任何输出，包括`stdout`和`stderr`流。对于以下日志，我从前面开始了相同的 NGINX 容器，并访问了它在`localhost`上托管的页面。

```
$ docker run -d \
             -p 8080:80 \
             nginx
06ebb46f64817329d360bb897bda824f932b9bcf380ed871709c2033af069118

$ # Access the page http://localhost:8080 with your browser

$ docker logs 06ebb46f
172.17.0.1 - - [02/Aug/2017:01:39:51 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.01" "-"
2017/08/02 01:39:51 [error] 6#6: *1 open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory), client: 172.17.0.1, server: localhost, request: "GET /favicon.ico HTTP/1.1", host: "localhost:8080"
172.17.0.1 - - [02/Aug/2017:01:39:51 +0000] "GET /favicon.ico HTTP/1.1" 404 169 "-" "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.01" "-"
172.17.0.1 - - [02/Aug/2017:01:39:52 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.01" "-"
```

您可以在这里看到，NGINX 记录了所有访问和相关的响应代码，这对于调试 Web 服务器非常宝贵。一般来说，输出可以因服务运行的内容而有很大的变化，但通常是开始搜索的好地方。如果您想要在日志被写入时跟踪日志，还可以添加`-f`标志，这在日志很大并且您试图过滤特定内容时非常有帮助。

# 看到容器看到的内容

当日志并不能真正解决问题时，要使用的命令是`docker exec`，以便在运行的容器上执行一个命令，可以包括访问完整的 shell：

```
$ docker run -d \
             -p 8080:80 \
             nginx
06ebb46f64817329d360bb897bda824f932b9bcf380ed871709c2033af069118

$ docker exec 06ebb46f ls -la /etc/nginx/conf.d/
total 12
drwxr-xr-x 2 root root 4096 Jul 26 07:33 .
drwxr-xr-x 3 root root 4096 Jul 26 07:33 ..
-rw-r--r-- 1 root root 1093 Jul 11 13:06 default.conf
```

在这种情况下，我们使用`docker exec`在容器中运行`ls`命令，但实际上这并不是一个强大的调试工具。如果我们尝试在容器内获取完整的 shell 并以这种方式进行检查呢？

```
$ docker exec -it \
              06ebb46f /bin/bash
root@06ebb46f6481:/# ls -la /etc/nginx/conf.d/
total 12
drwxr-xr-x 2 root root 4096 Jul 26 07:33 .
drwxr-xr-x 3 root root 4096 Jul 26 07:33 ..
-rw-r--r-- 1 root root 1093 Jul 11 13:06 default.conf
root@06ebb46f6481:/# exit
exit

$ # Back to host shell
```

这一次，我们使用了`-it`，这是`-i`和`-t`标志的简写，结合起来设置了所需的交互式终端，然后我们使用`/bin/bash`在容器内运行 Bash。容器内的 shell 在这里是一个更有用的工具，但由于许多镜像会删除图像中的任何不必要的软件包，我们受制于容器本身--在这种情况下，NGINX 容器没有`ps`，这是一个非常有价值的用于查找问题原因的实用程序。由于容器通常是隔离的一次性组件，有时可能可以向容器添加调试工具以找出问题的原因（尽管我们将在后面的章节中介绍使用`pid`命名空间的更好方法）：

```
$ docker exec -it 06ebb46f /bin/bash

root@06ebb46f6481:/# ps  # No ps on system
bash: ps: command not found

root@06ebb46f6481:/# apt-get update -q
Hit:1 http://security.debian.org stretch/updates InRelease
Get:3 http://nginx.org/packages/mainline/debian stretch InRelease [2854 B]
Ign:2 http://cdn-fastly.deb.debian.org/debian stretch InRelease
Hit:4 http://cdn-fastly.deb.debian.org/debian stretch-updates InRelease
Hit:5 http://cdn-fastly.deb.debian.org/debian stretch Release
Fetched 2854 B in 0s (2860 B/s)
Reading package lists...

root@06ebb46f6481:/# apt-get install -y procps
<snip>
The following NEW packages will be installed:
libgpm2 libncurses5 libprocps6 procps psmisc
0 upgraded, 5 newly installed, 0 to remove and 0 not upgraded.
Need to get 558 kB of archives.
After this operation, 1785 kB of additional disk space will be used.
<snip>

root@06ebb46f6481:/# ps
PID TTY TIME CMD
31 ? 00:00:00 bash
595 ? 00:00:00 ps

root@06ebb46f6481:/#
```

正如您所看到的，从上游分发的任何调试工具都很容易添加到容器中，但请注意，一旦找到问题，您应该启动一个新的容器并删除旧的容器，以清理掉剩下的垃圾，因为它浪费空间，而新的容器将从没有添加您新安装的调试工具的图像开始（在我们的情况下是`procps`）。

另一件事需要记住的是，有时镜像会阻止安装额外的软件包，因此对于这些情况，我们需要等到后面的章节来看看如何使用命名空间在这样受限制的环境中工作。

有时，容器被锁定在有限的用户 shell 中，因此您将无法访问或修改容器系统的其他部分。在这种配置中，您可以添加`-u 0`标志来将`docker exec`命令作为`root`（`user 0`）运行。您也可以指定任何其他用户名或用户 ID，但通常如果您需要在容器上使用辅助用户，`root`是您想要的。

# 我们的第一个 Dockerfile

现在我们对如何操作容器有了一点了解，这是一个很好的地方来尝试创建我们自己的容器。要开始构建容器，我们需要知道的第一件事是，Docker 在构建镜像时查找的默认文件名是`Dockerfile`。虽然您可以为此主要配置文件使用不同的名称，但这是极不鼓励的，尽管在一些罕见的情况下，您可能无法避免 - 例如，如果您需要一个测试套件镜像和主镜像构建文件在同一个文件夹中。现在，我们假设您只有一个单一的构建配置，考虑到这一点，我们来看看这些基本`Dockerfile`是什么样子的。在您的文件系统的某个地方创建一个测试文件夹，并将其放入名为`Dockerfile`的文件中：

```
FROM ubuntu:latest

RUN apt-get update -q && \
 apt-get install -qy iputils-ping

CMD ["ping", "google.com"]
```

让我们逐行检查这个文件。首先，我们有`FROM ubuntu:latest`这一行。这行表示我们要使用最新的 Ubuntu Docker 镜像作为我们自己服务的基础。这个镜像将自动从 Docker Hub 中拉取，但这个镜像也可以来自自定义存储库、您自己的本地镜像，并且可以基于任何其他镜像，只要它为您的服务提供了一个良好的基础（即 NGINX、Apline Linux、Jenkins 等）。

接下来的一行非常重要，因为基本的 Ubuntu 镜像默认情况下几乎没有任何东西，所以我们需要通过其软件包管理器`apt`安装提供 ping 实用程序（`iputils-ping`）的软件包，就像我们在命令行上使用`RUN`指令给 Docker 一样。不过，在安装之前，我们还需要确保我们的更新索引是最新的，我们使用`apt-get update`来做到这一点。稍后，我们将详细介绍为什么使用`&&`来链接`update`和`install`命令，但现在我们将神奇地忽略它，以免我们的示例偏离太多。

`CMD`指令指示 Docker 默认情况下，每次启动容器时 Docker 都会运行`"ping" "google.com"`，而无需进一步的参数。该指令用于在容器内启动服务，并将容器的生命周期与该进程绑定，因此如果我们的`ping`失败，容器将终止，反之亦然。您的 Dockerfile 中只能有一行`CMD`，因此要特别小心如何使用它。

现在我们已经配置好整个容器，让我们来构建它：

```
$ # Build using Dockerfile from current directory and tag our resulting image as "test_container"
$ docker build -t test_container . 
Sending build context to Docker daemon 1.716MB
Step 1/3 : FROM ubuntu:latest
---> 14f60031763d
Step 2/3 : RUN apt-get update -q && apt-get install -qy iputils-ping
---> Running in ad1ea6a6d4fc
Get:1 http://security.ubuntu.com/ubuntu xenial-security InRelease [102 kB]
<snip>
The following NEW packages will be installed:
iputils-ping libffi6 libgmp10 libgnutls-openssl27 libgnutls30 libhogweed4
libidn11 libnettle6 libp11-kit0 libtasn1-6
0 upgraded, 10 newly installed, 0 to remove and 8 not upgraded.
Need to get 1304 kB of archives.
<snip>
Setting up iputils-ping (3:20121221-5ubuntu2) ...
Processing triggers for libc-bin (2.23-0ubuntu9) ...
---> eab9729248d9
Removing intermediate container ad1ea6a6d4fc
Step 3/3 : CMD ping google.com
---> Running in 44fbc308e790
---> a719d8db1c35
Removing intermediate container 44fbc308e790
Successfully built a719d8db1c35
Successfully tagged test_container:latest
```

正如它所暗示的评论，我们在这里使用`docker build -t test_container .`构建了容器（使用默认的 Dockerfile 配置名称）在我们当前的目录，并用名称`test_container`标记了它。由于我们没有在`test_container`的末尾指定版本，Docker 为我们分配了一个称为`latest`的版本，正如我们可以从输出的末尾看到的那样。如果我们仔细检查输出，我们还可以看到对基本镜像的每个更改都会创建一个新的层，并且该层的 ID 然后被用作下一个指令的输入，每个层都会将自己的文件系统差异添加到镜像中。例如，如果我们再次运行构建，Docker 足够聪明，知道没有任何变化，它将再次使用这些层的缓存版本。将最终容器 ID（`a719d8db1c35`）与上一次运行的 ID 进行比较：

```
$ docker build -t test_container . 
Sending build context to Docker daemon 1.716MB
Step 1/3 : FROM ubuntu:latest
---> 14f60031763d
Step 2/3 : RUN apt-get update -q && apt-get install -qy iputils-ping
---> Using cache
---> eab9729248d9
Step 3/3 : CMD ping google.com
---> Using cache
---> a719d8db1c35
Successfully built a719d8db1c35
Successfully tagged test_container:latest
```

如果在 Dockerfile 的指令中检测到任何更改，Docker 将重建该层和任何后续层，以确保一致性。这种功能和选择性的“缓存破坏”将在以后进行介绍，并且它在管理您的存储库和镜像大小方面起着非常重要的作用。

容器构建完成后，让我们看看它是否真的有效（要退出循环，请按*Ctrl* + *C*）：

```
$ # Run the image tagged "test_container"
$ docker run test_container 
PING google.com (216.58.216.78) 56(84) bytes of data.
64 bytes from ord30s21-in-f14.1e100.net (216.58.216.78): icmp_seq=1 ttl=52 time=45.9 ms
64 bytes from ord30s21-in-f14.1e100.net (216.58.216.78): icmp_seq=2 ttl=52 time=41.9 ms
64 bytes from ord30s21-in-f14.1e100.net (216.58.216.78): icmp_seq=3 ttl=52 time=249 ms
^C
--- google.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 41.963/112.460/249.470/96.894 ms
```

又一个成功！你写了你的第一个运行 Docker 容器！

# 打破缓存

在我们刚刚写的容器中，我们有点忽略了这一行`RUN apt-get update -q && apt-get install -qy iputils-ping`，因为它需要在这里进行更深入的讨论。在大多数 Linux 发行版中，软件包的版本经常变化，但告诉我们在哪里找到这些软件包的索引列表是在创建原始 Docker 镜像时就已经固定了（在这种情况下是`ubuntu:latest`）。在大多数情况下，在我们安装软件包之前，我们的索引文件已经过时太久了（如果它们没有被完全删除），所以我们需要更新它们。将这个`&&`连接的行拆分成两个单独的行将适用于第一次构建：

```
RUN apt-get update -q
RUN apt-get install -qy iputils-ping
```

但是，当你以后在第二行添加另一个软件包时，会发生什么，就像下一行所示的那样？

```
RUN apt-get install -qy curl iputils-ping
```

在这种情况下，Docker 并不是很智能，它会认为 `update` 行没有改变，不会再次运行更新命令，因此它将使用缓存中的状态进行更新层，然后继续下一个尝试安装 `curl` 的命令（自上次构建以来已更改），如果仓库中的版本已经足够多次轮换，索引将再次过时，这很可能会失败。为了防止这种情况发生，我们使用 `&&` 将 `update` 和 `install` 命令连接起来，这样它们将被视为一个指令并创建一个层，在这种情况下，更改两个连接命令中的任何部分都将破坏缓存并正确运行 `update`。不幸的是，随着您更多地涉足可扩展的 Docker 组件，使用这些奇技淫巧来管理缓存和进行选择性缓存破坏将成为您工作的重要部分。

# 一个更实用的容器。

这可能是我们开始与其他 Docker 材料有所不同的地方，其他材料几乎假设只要掌握了这些基本知识，其余的工作就像小菜一碟一样，但实际上并非如此。这并不是什么高深的科学，但这些简单的例子确实不足以让我们达到我们需要的地方，因此我们将使用一个实际的例子，基于我们之前使用 NGINX 的工作，并创建一个使用这个 Web 服务器镜像的容器，以提供和提供我们将嵌入到镜像中的内容。

本书中的这个例子和其他所有例子也可以在 GitHub 上找到 [`github.com/sgnn7/deploying_with_docker`](https://github.com/sgnn7/deploying_with_docker)。您可以使用 `git` 或他们的 Web 界面来跟随这些例子，但我们将使用的所有代码示例也将直接包含在书中。

要开始创建我们的 Web 服务器，我们需要创建一个目录来放置我们所有的文件：

```
$ mkdir ~/advanced_nginx
$ cd ~/advanced_nginx
```

我们需要创建的第一个文件是我们将尝试在镜像中提供的虚拟文本文件：

```
$ echo "Just a test file" > test.txt
```

我们接下来需要的文件是所需的 NGINX 配置。将以下文本放入一个名为 `nginx_main_site.conf` 的文件中：

```
    server {
      listen 80;
      server_name _;
      root /srv/www/html;

      # Deny access to any files prefixed with '.'
      location ~/\. {
        deny all;
      }

      # Serve up the root path at <host>/
      location / {
        index index.html;
        autoindex on;
      }
    }
```

如果你从未使用过 NGINX，让我们看看这个文件做了什么。在第一个块中，我们创建了一个在镜像上以 `/srv/www/html` 为根的监听端口 `80` 的 `server`。第二个块虽然不是严格必需的，并且对于更大的网站需要进行更改，但对于任何在 NGINX 上工作的人来说，这应该是一种肌肉记忆，因为它可以防止下载像 `.htaccess`、`.htpasswd` 和许多其他不应该公开的隐藏文件。最后一个块只是确保任何以 `/` 开头的路径将从 `root` 中读取，并且如果没有提供索引文件，它将使用 `index.html`。如果没有这样的文件可用并且我们在一个目录中，`autoindex` 确保它可以向您显示一个目录的可读列表。

虽然这个 NGINX 配置是功能性的，但它还有很多不包括的东西（如 SSL 配置、日志记录、错误文件、文件查找匹配等），但这主要是因为这本书试图专注于 Docker 本身而不是 NGINX。如果您想了解如何完全和正确地配置 NGINX，您可以访问 [`nginx.org/en/docs/`](https://nginx.org/en/docs/) 了解更多信息。

配置写好后，我们现在可以创建我们的 Dockerfile，它将获取我们的测试文件、配置文件和 NGINX 镜像，并将它们转换成一个运行 Web 服务器并提供我们的测试文件的 Docker 镜像。

```
FROM nginx:latest

# Make sure we are fully up to date
RUN apt-get update -q && \
 apt-get dist-upgrade -y

# Remove the default configuration
RUN rm /etc/nginx/conf.d/default.conf

# Create our website's directory and make sure
# that the webserver process can read it
RUN mkdir -p /srv/www/html && \
 chown nginx:nginx /srv/www/html

# Put our custom server configuration in
COPY nginx_main_site.conf /etc/nginx/conf.d/

# Copy our test file in the location that is
# being served up
COPY test.txt /srv/www/html/
```

这个 Dockerfile 可能看起来与第一个有很大不同，所以我们将花一些时间来深入了解我们在这里做了什么。

# 使用 FROM 扩展另一个容器

与我们上一个容器类似，我们的 `FROM nginx:latest` 行确保我们使用基础镜像的最新版本，但这里我们将使用 NGINX 作为基础，而不是 Ubuntu。`latest` 确保我们获取具有最新功能和通常也有补丁的镜像，但稍微存在未来破坏和 API 不兼容的风险。

在编写 Docker 容器时，您通常必须根据您的情况和稳定性要求做出这些权衡决定，但是 NGINX API 多年来一直非常稳定，因此在这种特定情况下，我们不需要命名标签提供的稳定性。如果我们想在这里使用其中一个带有标签的版本，`latest`只需更改为我们在 Docker Hub 上找到的所需版本，例如[`hub.docker.com/_/nginx/`](https://hub.docker.com/_/nginx/)，因此像`FROM nginx:1.13`这样的东西也完全可以。

# 确保包含最新的补丁

我们的下一步，`apt-get upgrade` 和 `apt-get dist-upgrade`，在当前的 Docker 世界中有点争议，但我认为它们是一个很好的补充，我会解释原因。在常规的基于`deb`软件包的 Linux 发行版（即 Debian，Ubuntu 等），这两个命令确保您的系统与当前发布的软件包完全保持最新。这意味着任何不是最新版本的软件包将被升级，任何过时的软件包将被替换为更新的软件包。由于 Docker 的一般准则是容器多多少是可丢弃的，以这种方式更新容器似乎有点不受欢迎，但它并非没有缺点。

由于 Docker Hub 上的大多数 Docker 镜像只有在基本源文件或 Dockerfile 本身发生更改时才构建，因此许多这些镜像具有较旧和/或未修补的系统库，因此当服务将它们用作动态库时，可能会受到已经修复的任何错误的影响。为了确保我们在这方面的安全加固工作不落后，我们确保在做任何其他事情之前更新系统。虽然由于系统 API 可能发生变化而导致服务中断的风险很小，并且由于应用了额外的更改而导致镜像大小增加，但在我看来，这种权衡不足以让服务处于无保护状态，但在这里请随意使用您的最佳判断。

# 应用我们的自定义 NGINX 配置

我们在系统更新后的指令（`RUN rm /etc/nginx/conf.d/default.conf`）是删除容器中默认的 web 服务器配置。您可以通过我们上一个提示中的链接了解更多关于 NGINX 配置的信息，但现在，我们可以说默认情况下，所有单独的站点配置文件都存储在`/etc/nginx/conf.d`中，NGINX Docker 镜像默认带有一个名为`default.conf`的简单示例文件，我们绝对不想使用。

虽然我们可以覆盖提到的文件，但我们将被困在名为`default`的名称中，这并不是很描述性的，因此对于我们的配置，我们将删除这个文件，并使用一个更好的文件名添加我们自己的文件。

接下来，我们需要确保我们将要提供文件的文件夹可以被网络服务器进程访问和读取。使用`mkdir -p`的第一个命令创建了所有相关的目录，但由于 NGINX 不以 root 身份运行，我们需要知道进程将以什么用户来读取我们想要提供的文件，否则我们的服务器将无法显示任何内容。我们可以通过显示包含在镜像中的系统范围 NGINX 配置的前几行来找到原始配置中的默认用户，该配置位于`/etc/nginx/nginx.conf`中。

```
$ # Print top 2 lines of main config file in NGINX image
$ docker run --rm \
             nginx /bin/head -2 /etc/nginx/nginx.conf

user nginx;
```

完美！现在，需要能够读取这个目录的用户是`nginx`，我们将使用`chown nginx:nginx /srv/www/html`来更改我们目标文件夹的所有者，但是我们刚刚使用了新的`run` Docker 命令来尝试找到这个信息，这是怎么回事？如果在指定镜像名称后包含一个命令，而不是在镜像中使用`CMD`指令，Docker 将用这个新命令替换它。在前面的命令中，我们运行了`/bin/head`可执行文件，并传入参数告诉它我们只想要从`/etc/nginx/nginx.conf`文件中获取前两行。由于这个命令一旦完成就退出了，容器就会停止并完全删除，因为我们使用了`--rm`标志。

随着默认配置的消失和我们的目录创建，我们现在可以使用`COPY nginx_main_site.conf /etc/nginx/conf.d/`将 NGINX 的主要配置放在指定位置。`COPY`参数基本上就是将当前构建目录中的文件复制到镜像中的指定位置。

非常小心地结束`COPY`指令的参数，如果不加斜杠，源文件会被放入目标文件，即使目标是一个目录。为了确保这种情况不会发生，始终在目标目录路径的末尾加上斜杠。

添加我们想要托管的主要`test.txt`文件是最后一部分，它遵循与其他`COPY`指令相同的步骤，但我们将确保将其放入我们的 NGINX 配置引用的文件夹中。由于我们为这个端点打开了`autoindex`标志，因此不需要采取其他步骤，因为文件夹本身是可浏览的。

# 构建和运行

现在我们已经讨论了整个构建配置，我们可以创建我们的镜像，看看我们刚刚做了什么：

```
$ docker build -t web_server . 
Sending build context to Docker daemon 17.41kB
Step 1/6 : FROM nginx:latest
 ---> b8efb18f159b
Step 2/6 : RUN apt-get update -q && apt-get dist-upgrade -yq
 ---> Running in 5cd9ae3712da
Get:1 http://nginx.org/packages/mainline/debian stretch InRelease [2854 B]
Get:2 http://security.debian.org stretch/updates InRelease [62.9 kB]
Get:3 http://nginx.org/packages/mainline/debian stretch/nginx amd64 Packages [11.1 kB]
Get:5 http://security.debian.org stretch/updates/main amd64 Packages [156 kB]
Ign:4 http://cdn-fastly.deb.debian.org/debian stretch InRelease
Get:6 http://cdn-fastly.deb.debian.org/debian stretch-updates InRelease [88.5 kB]
Get:7 http://cdn-fastly.deb.debian.org/debian stretch Release [118 kB]
Get:8 http://cdn-fastly.deb.debian.org/debian stretch Release.gpg [2373 B]
Get:9 http://cdn-fastly.deb.debian.org/debian stretch/main amd64 Packages [9497 kB]
Fetched 9939 kB in 40s (246 kB/s)
Reading package lists...
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
 ---> 4bbd446af380
Removing intermediate container 5cd9ae3712da
Step 3/6 : RUN rm /etc/nginx/conf.d/default.conf
 ---> Running in 39ad3da8979a
 ---> 7678bc9abdf2
Removing intermediate container 39ad3da8979a
Step 4/6 : RUN mkdir -p /srv/www/html && chown nginx:nginx /srv/www/html
 ---> Running in e6e50483e207
 ---> 5565de1d2ec8
Removing intermediate container e6e50483e207
Step 5/6 : COPY nginx_main_site.conf /etc/nginx/conf.d/
 ---> 624833d750f9
Removing intermediate container a2591854ff1a
Step 6/6 : COPY test.txt /srv/www/html/
 ---> 59668a8f45dd
Removing intermediate container f96dccae7b5b
Successfully built 59668a8f45dd
Successfully tagged web_server:latest
```

容器构建似乎很好，让我们来运行它：

```
$ docker run -d \
             -p 8080:80 \
             --rm \
             web_server 
bc457d0c2fb0b5706b4ca51b37ca2c7b8cdecefa2e5ba95123aee4458e472377

$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
bc457d0c2fb0 web_server "nginx -g 'daemon ..." 30 seconds ago Up 29 seconds 0.0.0.0:8080->80/tcp goofy_barti
```

到目前为止，一切都很顺利，似乎运行得很好。现在我们将在`http://localhost:8080`上用浏览器访问容器。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/db512100-8d98-4a43-b3a1-e44bf11f56a2.png)

正如我们所希望的那样，我们的服务器正在工作，并显示`/srv/www/html`的内容，但让我们点击`test.txt`，确保它也在工作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/9fe2c484-ccde-41db-b19e-ff2c81ffa618.png)

太好了，看起来我们的计划成功了，我们创建了一个高性能的静态网站托管服务器容器！当然，我们还可以添加许多其他东西，但我们扩展示例镜像以执行一些有用的操作的主要目标已经实现了！

# 从头开始的服务

我们上一个示例相当全面，但遗漏了一些重要的 Docker 命令，我们也应该知道，因此我们将使用另一个示例，尽管以略微不太理想的方式重新设计 Web 服务器解决方案，以展示它们的使用并解释它们的作用。在这个过程中，我们将深入一点，看看是否可以自己制作服务的许多部分。

我们将从创建一个干净的目录开始这个示例，并创建我们之前使用的相同的测试文件：

```
$ mkdir ~/python_webserver
$ cd ~/python_webserver

$ echo "Just a test file" > test.txt
```

现在我们将通过将以下内容放入`Dockerfile`来创建一个稍微复杂一点的基于 Python 的 Web 服务器容器。

```
FROM python:3

# Add some labels for cache busting and annotating
LABEL version="1.0"
LABEL org.sgnn7.name="python-webserver"

# Set a variable that we will keep reusing to prevent typos
ENV SRV_PATH=/srv/www/html

# Make sure we are fully up to date
RUN apt-get update -q && \
 apt-get dist-upgrade -y

# Let Docker know that the exposed port we will use is 8000
EXPOSE 8000

# Create our website's directory, then create a limited user
# and group
RUN mkdir -p $SRV_PATH && \
 groupadd -r -g 350 pythonsrv && \
 useradd -r -m -u 350 -g 350 pythonsrv

# Define ./external as an externally-mounted directory
VOLUME $SRV_PATH/external

# To serve things up with Python, we need to be in that
# same directory
WORKDIR $SRV_PATH

# Copy our test file
COPY test.txt $SRV_PATH/

# Add a URL-hosted content into the image
ADD https://raw.githubusercontent.com/moby/moby/master/README.md \
 $SRV_PATH/

# Make sure that we can read all of these files as a
# limited user
RUN chown -R pythonsrv:pythonsrv $SRV_PATH

# From here on out, use the limited user
USER pythonsrv

# Run the simple http python server to serve up the content
CMD [ "python3", "-m", "http.server" ]
```

在几乎所有情况下，使用 Python 内置的 Web 服务器都是极不推荐的，因为它既不可扩展，也没有任何显著的配置方式，但它可以作为一个通过 Docker 托管的服务的良好示例，并且几乎在所有安装了 Python 的系统上都可用。除非你真的知道自己在做什么，否则不要在真实的生产服务中使用它。

除了关于在生产中使用 python 的 web 服务器模块的注意之外，这仍然是我们没有涵盖的所有其他主要 Dockerfile 指令的一个很好的例子，现在您将学习如何使用它们。

# 标签

我们这里的第一个新指令是`LABEL`：

```
LABEL version="1.0"
LABEL org.sgnn7.name="python-webserver"
```

`LABEL <key>=<value>`或`LABEL <key> <value>`用于向正在构建的镜像添加元数据，稍后可以通过`docker ps`和`docker images`进行检查和过滤，使用类似`docker images --filter "<key>=<value>"`的方式。键通常以`reverse-dns`表示法全部小写，但在这里您可以使用任何内容，`version`应该出现在每个镜像上，因此我们使用顶级版本键名称。但是，这里的版本不仅用于过滤图像，还用于在更改时打破 Docker 的缓存。如果没有这种缓存破坏或在构建过程中通过手动设置标志（`docker build --no-cache`），Docker 将一直重用缓存，直到最近更改的指令或文件，因此您的容器很可能会保持在冻结的软件包配置中。这种情况可能是您想要的，也可能不是，但是以防万一您有自动化构建工具，添加一个`version`层，可以在更改时打破缓存，使得容器非常容易更新。

# 使用 ENV 设置环境变量

`ENV`与其他一些命令不同，应该大部分是不言自明的：它在`Dockerfile`和容器中设置环境变量。由于我们需要在`Dockerfile`中不断重新输入`/srv/www/html`，为了防止拼写错误并确保对最终服务器目录目标的轻松更改，我们设置了`SRV_PATH`变量，稍后我们将不断重用`$SRV_PATH`。通常对于 Docker 容器，几乎所有的容器配置都是通过这些环境变量完成的，因此在后面的章节中可以预期会看到这个指令。

即使在这个示例中我们没有使用它，但是在`CMD`指令中直接使用环境变量时需要注意，因为它不会被展开，而是直接运行。您可以通过将其作为类似于这样的 shell 命令结构的一部分来确保您的变量在`CMD`中被展开：`CMD [ "sh", "-c", "echo", "$SRV_PATH" ]`。

# 暴露端口

我们接下来的新指令是`EXPOSE 8000`。还记得我们如何使用`docker info`来找出 NGINX 容器使用的端口吗？这个指令填写了元数据中的信息，并且被 Docker 编排工具用来将传入端口映射到容器的正确入口端口。由于 Python 的 HTTP 服务器默认在端口`8000`上启动服务，我们使用`EXPOSE`来通知 Docker，使用这个容器的人应该确保他们在主机上映射这个端口。你也可以在这个指令中列出多个端口，但由于我们的服务只使用一个端口，所以现在不需要使用。

# 使用有限用户的容器安全层

我们`Dockerfile`中的以下新代码块可能有点复杂，但我们将一起学习：

```
RUN mkdir -p $SRV_PATH && \
 groupadd -r -g 350 pythonsrv && \
 useradd -r -m -u 350 -g 350 pythonsrv
```

这是我们需要在多个层面上扩展的内容，但你首先需要知道的是，默认情况下，Dockerfile 指令是以`root`用户执行的，如果稍后没有指定不同的`USER`，你的服务将以`root`凭据运行，从安全角度来看，这是一个巨大的漏洞，我们试图通过将我们的服务仅作为有限用户运行来修补这个漏洞。然而，如果没有定义用户和组，我们无法将上下文从`root`切换，因此我们首先创建一个`pythonsrv`组，然后创建附属于该组的`pythonsrv`用户。`-r`标志将用户和组标记为系统级实体，对于不会直接登录的组和用户来说，这是一个良好的做法。

说到用户和组，如果你将一个卷从主机挂载到以有限用户身份运行的 Docker 容器中，如果主机和容器对用户和组 ID（分别为`uid`和`gid`）没有完全一致，你将无法从卷中读取或写入文件。为了避免这种情况，我们使用一个稳定的 UID 和 GID，即`350`，这个数字易于记忆，在大多数主机系统的常规 UID/GID 表中通常不会出现。这个数字大多是任意的，但只要它在主机 OS 的服务范围内，并且不会与主机上的用户或组冲突，就应该没问题。

到目前为止没有涵盖的最后一个标志是`-m`，它的作用是为用户创建主目录骨架文件。大多数情况下，你不需要这个，但如果任何后续操作尝试使用`$HOME`（比如`npm`或大量其他服务），除非你指定这个标志并且你的构建将失败，否则不会有这样的目录，所以我们确保通过为`pythonsrv`用户创建`$HOME`来避免这种情况。

为了完成这一切，我们将所有这些`RUN`命令链接在一起，以确保我们使用尽可能少的层。每一层都会创建额外的元数据，并增加你的镜像大小，所以就像 Docker 最佳实践文档所述，我们尝试通过堆叠这些命令来减少它们。虽然在所有情况下都不是最好的做法，因为调试这种风格的配置非常困难，但通常会显著减小容器的大小。

# 卷和存在于容器之外的数据

但是，如果我们想要添加存在于容器之外的文件，即使容器死亡时也需要持久存在的文件呢？这就是`VOLUME`指令发挥作用的地方。使用`VOLUME`，每次启动容器时，这个路径实际上被假定为从容器外部挂载，如果没有提供，将会自动为你创建并附加一个。

在这里，我们将我们的`/srv/www/html/external`路径分配给这个未命名的卷，但我们将保留大部分关于卷的详细讨论到后面的章节。

# 设置工作目录

由于 Python HTTP 服务器只能从其运行的当前目录中提供文件，如果不正确配置，我们的容器将显示`/`目录之外的文件。为了解决这个问题，我们在`Dockerfile`中包含了`WORKDIR $SRV_ROOT`，这将把我们的工作目录更改为包含我们想要提供的文件的目录。关于这个命令需要注意的一点是，你可以多次重用它，并且它适用于 Dockerfile 中的任何后续命令（如`RUN`或`CMD`）。

# 从互联网添加文件

如果要尝试向容器中添加不在本地托管的文件和/或由于许可问题无法将它们包含在`Dockerfile`所在的存储库中，该怎么办？为了这个特定的目的，有`ADD`指令。这个命令会从提供的 URI 下载文件并将其放入容器中。如果文件是本地压缩存档，比如`.tgz`或`.zip`文件，并且目标路径以斜杠结尾，它将被扩展到该目录中，这是一个非常有用的选项，与`COPY`相比。在我们写的例子中，我们将从 GitHub 中随机选择一个文件，并将其放入要包含的目录中。

```
ADD https://raw.githubusercontent.com/moby/moby/master/README.md \
 $SRV_PATH/
```

# 改变当前用户

我们已经解释了为什么需要将我们的服务运行为受限用户以及我们如何为其创建用户，但现在是永久切换上下文到`pythonsrv`的时候了。使用`USER pythonsrv`，任何进一步的命令都将以`pythonsrv`用户的身份执行，包括容器的`CMD`可执行命令，这正是我们想要的。就像`WORKDIR`一样，这个指令可以在`Dockerfile`中多次使用，但对于我们的目的来说，没有必要将其余的配置设置为非`root`。通常，将这个层语句尽可能放在`Dockerfile`中很高的位置是一个很好的做法，因为它很少会改变，也不太可能破坏缓存。然而，在这个例子中，我们不能将它移到更高的位置，因为我们之前的命令使用了`chown`，这需要`root`权限。

# 把所有东西放在一起

我们快要完成了！我们需要做的最后一件事是在容器启动时启动 Python 的内置 HTTP 服务器模块：

```
CMD [ "python3", "-m", "http.server" ]
```

一切就绪后，我们可以构建并启动我们的新容器：

```
$ docker build -t python_server . 
Sending build context to Docker daemon 16.9kB
Step 1/14 : FROM python:3
 ---> 968120d8cbe8
<snip>
Step 14/14 : CMD python3 -m http.server
 ---> Running in 55262476f342
 ---> 38fab9dca6cd
Removing intermediate container 55262476f342
Successfully built 38fab9dca6cd
Successfully tagged python_server:latest

$ docker run -d \
             -p 8000:8000 \
             --rm \
             python_server 
d19e9bf7fe70793d7fce49f3bd268917015167c51bd35d7a476feaac629c32b8
```

我们可以祈祷并通过访问`http://localhost:8000`来检查我们构建的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/8cac3147-3307-43d6-9026-d10ee62ac0c2.png)

成功了！点击`test.txt`显示了正确的`Just a test`字符串，当点击时，我们从 GitHub 下载的`README.md`也很好地显示出来。所有的功能都在那里，`external/`目录中有什么？

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/70ef7834-4904-45e7-b723-429b14c7fb7a.png)

如果卷是空的，那么我们的目录也是空的并不奇怪。我们来看看是否可以将一些文件从我们的主机挂载到这个目录中：

```
$ # Kill our old container that is still running
$ docker kill d19e9bf7
d19e9bf7

$ # Run our image but mount our current folder to container's
$ # /srv/www/html/external folder
$ docker run -d \
             -p 8000:8000 \
             --rm \
             -v $(pwd):/srv/www/html/external \
             python_server 
9756b456074f167d698326aa4cbe5245648e5487be51b37b00fee36067464b0e
```

在这里，我们使用`-v`标志将我们的当前目录(`$(pwd)`)挂载到我们的`/srv/www/html/external`目标上。那么现在`http://localhost:8000/external`是什么样子呢？我们的文件可见吗？

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/81036609-264a-4e9e-8299-de7b1323fe22.png)

确实是的 - 我们的服务正如我们所期望的那样工作！一个从头开始编写的真正的服务！

有了一个正常工作的服务，我们现在应该能够在下一章中继续我们的 Docker 之旅，通过扩展我们的容器。

# 摘要

在本章中，我们涵盖了从基本的 Docker 容器到扩展现有容器，一直到从头开始创建我们自己的服务的所有内容。在这个过程中，我们涵盖了最重要的 Docker 和 Dockerfile 命令以及如何使用它们，更重要的是*在哪里*和*为什么*使用它们。虽然这并不是对该主题最深入的覆盖，但这正是我们在下一章开始扩展容器工作所需要的适当深度。


# 第三章：服务分解

本章将介绍如何利用上一章的知识来创建和构建数据库和应用服务器容器的附加部分，因为真实世界的服务通常是以这种方式组成的。一旦我们把它们都建立起来，我们将看到需要什么才能将它们组合成一个更可用的服务，并且深入了解 Docker 的更多内容。

在本章中，我们将涵盖以下主题：

+   Docker 命令的快速回顾

+   使用以下内容编写一个真实的服务：

+   一个 Web 服务器服务

+   一个应用服务

+   一个数据库

+   介绍卷

+   凭据传递的安全考虑

# 快速回顾

在我们开始之前，让我们回顾一下我们之前在一个单独的部分中涵盖的 Docker 和 Dockerfile 命令，以便您以后可以作为参考。

# Docker 命令

以下是我们为 Docker 提供的所有命令，还添加了一些其他命令，如果您经常构建容器，可能会用到：

要获取每个参数所需的更深入信息，或者查看我们尚未涵盖的命令，请在终端中键入`docker help`，或者单独在终端中键入该命令。您还可以访问[`docs.docker.com/`](https://docs.docker.com/)并查看文档，如果 CLI 输出提供的信息不够好，它可能包含更新的数据。

```
docker attach - Attach the shell's input/output/error stream to the container
docker build - Build a Docker image based on a provided Dockerfile
docker cp - Copy files between container and host
docker exec - Execute a command in a running container
docker images - List image available to your installation of docker
docker info - Display information about the system
docker inspect - Display information about Docker layers, containers, images, etc
docker kill - Forcefully terminate a container 
docker logs - Display logs from a container since it last started
docker pause - Pause all processes within a container
docker ps - List information about containers and their resource usage
docker pull - Pull an image from a remote repository into the local registry
docker push - Push an image from the local registry into a remote repository
docker rm - Remove a container
docker rmi - Remove an image from the local repository
docker run - Start a new container and run it
docker search - Search DockerHub for images
docker start - Start a stopped container
docker stop - Stop a running container nicely (wait for container to shut down)
docker tag - Create a tag for an image
docker top - Show running processes of a container
docker unpause - Resume all processes in a paused container
docker version - Show the Docker version
```

最近，Docker 命令已经开始被隔离到它们自己的 docker CLI 部分，比如`docker container`，以将它们与其他集群管理命令分开。要使用这种较新的语法，只需在任何命令前加上容器（即`docker stop`变成`docker container stop`）。您可以随意使用任何版本，但请注意，尽管新样式对于大多数 Docker 用法来说过于冗长，但您可能会发现旧样式在某个时候被弃用。

# Dockerfile 命令

以下列表与之前类似，但这次我们涵盖了在 Dockerfile 中可以使用的命令，并按照在 Dockerfile 中工作时的顺序进行了排列：

`FROM <image_name>[:<tag>]`: 将当前镜像基于`<image_name>`

`LABEL <key>=<value> [<key>=value>...]`: 向镜像添加元数据

`EXPOSE <port>`: 指示应该映射到容器中的端口

`WORKDIR <path>`: 设置当前目录以便执行后续命令

`RUN <command> [ && <command>... ]`: 执行一个或多个 shell 命令

`ENV <name>=<value>`：将环境变量设置为特定值

`VOLUME <path>`：表示应该外部挂载<路径>的卷

`COPY <src> <dest>`：将本地文件、一组文件或文件夹复制到容器中

`ADD <src> <dest>`：与`COPY`相同，但可以处理 URI 和本地存档

`USER <user | uid>`：为此命令之后的命令设置运行时上下文为`<user>`或`<uid>`

`CMD ["<path>", "<arg1>", ...]`：定义容器启动时要运行的命令

由于几乎所有您想要构建的容器都可以使用这个集合构建，因此这个列表并不是 Docker 命令的全部超集，其中一些被有意地省略了。如果您对`ENTRYPOINT`、`ARG`、`HEALTHCHECK`或其他内容感到好奇，可以在[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)上查看完整的文档。

# 编写一个真实的服务

到目前为止，我们已经花了时间制作了一些帮助我们建立 Docker 技能的假或模拟容器服务，但我们还没有机会去做一些类似真实世界服务的工作。一般来说，大多数在外部被使用的简单服务看起来会类似于高级别图表中所示的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/477adec9-c7a3-429e-b279-f035913c506d.png)

# 概述

在这里，我们将详细讨论每个服务。

**Web 服务器**：

我们刚刚看到的图像中最右边的部分是一个 Web 服务器。Web 服务器充当高速 HTTP 请求处理程序，并且通常在这种情况下被使用如下：

+   用于集群内资源、虚拟专用云（VPC）和/或虚拟专用网络（VPN）的反向代理端点

+   加固的守门人，限制资源访问和/或防止滥用

+   分析收集点

+   负载均衡器

+   静态内容交付服务器

+   应用服务器逻辑利用的减少器

+   SSL 终止端点

+   远程数据的缓存

+   数据二极管（允许数据的入口或出口，但不能同时）

+   本地或联合账户 AAA 处理程序

如果安全需求非常低，服务是内部的，处理能力充足，那么我们想象中的服务的这一部分并不总是严格要求的，但在几乎所有其他情况下，如果这些条件中的任何一个不满足，添加 Web 服务器几乎是强制性的。Web 服务器的一个很好的类比是你的家用路由器。虽然你不一定需要使用互联网，但专用路由器可以更好地共享你的网络，并作为你和互联网之间的专用安全设备。虽然我们在上一章中大部分时间都在使用 NGINX，但还有许多其他可以使用的（如 Apache、Microsoft IIS、lighttpd 等），它们通常在功能上是可以互换的，但要注意配置设置可能会有显著不同。

**应用服务器**：

所以，如果 Web 服务器为我们做了所有这些，应用服务器又做什么呢？应用服务器实际上是您的主要服务逻辑，通常包装在一些可通过 Web 访问的端点或队列消费的守护程序中。这一部分可以这样使用：

+   主要的网站框架

+   数据操作 API 逻辑

+   某种数据转换层

+   数据聚合框架

应用服务器与 Web 服务器的主要区别在于，Web 服务器通常在静态数据上运行，并在流程中做出通常是刚性的决定，而应用服务器几乎所有的动态数据处理都是以非线性方式进行的。属于这一类的通常是诸如 Node.js、Ruby on Rails、JBoss、Tornado 等框架，用于运行可以处理请求的特定编程语言应用程序。在这里不要认为需要一个大型框架是必需的，因为即使是正确的 Bash 脚本或 C 文件也可以完成同样的工作，并且仍然可以作为应用服务器的资格。

我们将尽可能多地将工作推迟到 Web 服务器而不是应用服务器上，原因是由于框架开销，应用服务器通常非常慢，因此不适合执行简单、小型和重复的任务，而这些任务对于 Web 服务器来说是小菜一碟。作为参考，一个专门的 Web 服务器在提供静态页面方面的效率大约是一个完全成熟的应用服务器的一个数量级，因此比大多数应用服务器快得多。正如前面提到的，你可能可以单独或通过一些调整在应用服务器上处理低负载，但超过这个范围的任何负载都需要一个专用的反向代理。

**数据库**：一旦我们掌握了这种逻辑和静态文件处理，它们在没有实际数据进行转换和传递时基本上是无用的。与使用数据的任何软件一样，这是通过后备数据库完成的。由于我们希望能够扩展系统的任何部分并隔离离散的组件，数据库有了自己的部分。然而，在容器之前的世界中，我们依赖于提供了**原子性**、**一致性**、**隔离性**和**持久性**（**ACID**）属性的大型单片数据库，并且它们完成了它们的工作。然而，在容器世界中，我们绝对不希望这种类型的架构，因为它既不像可靠性那样强大，也不像可水平扩展的数据库那样可水平扩展。

然而，使用这种新式数据库，通常无法得到与旧式数据库相同的保证，这是一个重要的区别。与 ACID 相比，大多数容器友好的数据库提供的是**基本可用**、**软状态**、**最终一致性**（**BASE**），这基本上意味着数据最终会正确，但在初始更新发送和最终状态之间，数据可能处于各种中间值的状态。

# 我们要构建什么

我们希望制作一个能够作为一个很好的示例但又不会太复杂的服务，以展示一个真实世界的服务可能看起来像什么。对于这个用例，我们将创建一个容器分组，可以在基本的 HTTP 身份验证后执行两个操作：

+   将登陆页面上输入的字符串保存到数据库中。

+   当我们登陆首页时，显示到目前为止保存的所有字符串的列表。

在这里，我们将尽量涵盖尽可能多的内容，同时构建一个基本现实的容器支持的网络服务的原型。请记住，即使使用可用的工具，制作一个像这样简单的服务也并不容易，因此我们将尽量减少复杂性，尽管我们的内容的难度从这里开始会逐渐增加。

# 实现部分

由于我们已经涵盖了通用服务架构中需要的三个主要部分，我们将把我们的项目分成相同的离散部分，包括一个 Web 服务器、一个应用服务器和一个数据库容器，并在这里概述构建它们所需的步骤。如前所述，如果你不想从这些示例中重新输入代码，你可以使用 Git 轻松地从 GitHub 上检出所有的代码，网址是[`github.com/sgnn7/deploying_with_docker`](https://github.com/sgnn7/deploying_with_docker)。

# Web 服务器

我们可以在这里选择任何 Web 服务器软件，但由于我们之前已经使用过 NGINX，因此重用这个组件的一些部分是有道理的--这实际上就是容器架构的全部意义！Web 服务器组件将提供一些基本的身份验证、缓存数据，并作为其后面的应用服务器的反向代理。我们之前工作过的基本设置可以在这里使用，但我们将对其进行一些修改，使其不再直接提供文件，而是充当代理，然后使用我们将在`Dockerfile`中创建的凭据文件进行身份验证。让我们创建一个名为`web_server`的新文件夹，并将这些文件添加到其中：

`nginx_main_site.conf`:

```
server {
  listen  80;
  server_name    _;

  root /srv/www/html;

  location ~/\. {
    deny all;
  }

  location / {
    auth_basic           "Authentication required";
    auth_basic_user_file /srv/www/html/.htpasswd;

    proxy_pass           http://172.17.0.1:8000;
  }
}
```

这里有三个有趣的配置部分。第一个是包含`auth_basic_`命令，它们在此配置提供的所有端点上启用 HTTP 基本身份验证。第二个是，如果你足够留心新的以`.`开头的凭据文件，我们现在需要拒绝获取所有以`.`开头的文件，因为我们添加了`.htpasswd`。第三个也是最有趣的是使用了`proxy_pass`，它允许服务器将所有经过身份验证的流量路由到后端应用服务器。为什么我们使用`http://172.17.0.1:8000`作为目的地，这开始打开 Docker 网络的潘多拉魔盒，所以我们将在稍后解释为什么我们使用它，如果现在涵盖它，我们将使我们的服务构建偏离轨道。

警告！在大多数情况下，使用基本身份验证是一种安全的恶作剧，因为我们在这里使用它时没有 HTTPS，因为任何网络上的人都可以使用最简单的工具嗅探出您的凭据。在您的服务中，至少要求使用基本身份验证或在部署到具有直接互联网访问权限的任何服务之前依赖于更强大的凭据传递形式。

现在我们可以在同一个目录中添加我们的新`Dockerfile`，它将如下所示：

```
FROM nginx:latest
# Make sure we are fully up to date
RUN apt-get update -q && \
 apt-get dist-upgrade -y && \
 apt-get install openssl && \
 apt-get clean && \
 apt-get autoclean

# Setup any variables we need
ENV SRV_PATH /srv/www/html

# Get a variable defined for our password
ARG PASSWORD=test

# Remove default configuration
RUN rm /etc/nginx/conf.d/default.conf

# Change ownership of copied files
RUN mkdir -p $SRV_PATH && \
 chown nginx:nginx $SRV_PATH

# Setup authentication file
RUN printf "user:$(openssl passwd -1 $PASSWORD)\n" >> $SRV_PATH/.htpasswd

# Add our own configuration in
COPY nginx_main_site.conf /etc/nginx/conf.d/
```

正如您所看到的，我们在这里对上一章中的原始工作进行了一些更改。应该引起注意的初始事情是编写`RUN apt-get`行的新方法，我们在这里简要注释了一下：

```
RUN apt-get update -q && \         # Update our repository information
 apt-get dist-upgrade -y && \   # Upgrade any packages we already have
 apt-get install openssl && \   # Install dependency (openssl)
 apt-get clean && \             # Remove cached package files
 apt-get autoclean              # Remove any packages that are no longer needed on the system
```

与以前的图像不同，在这里，我们安装了`openssl`软件包，因为我们将需要它来为身份验证创建 NGINX 加密密码，但`clean`和`autoclean`行在这里是为了确保我们删除系统上的任何缓存的`apt`软件包并删除孤立的软件包，从而给我们一个更小的镜像，这是我们应该始终努力的目标。就像以前一样，我们以类似的方式组合所有行，以便以前和当前层之间的文件系统差异只是所需的更改，而不是其他任何东西，使其成为一个非常紧凑的更改。当编写自己的图像时，如果您发现自己需要更多的瘦身，许多其他东西都可以删除（例如删除文档文件，`/var`目录，不必要的可选软件包等），但在大多数情况下，这两个应该是最常用的，因为它们很简单并且在基于 Debian 的系统上运行得相当好。

# 身份验证

没有适当的身份验证，我们的服务器对任何访问它的人都是敞开的，所以我们添加了一个用户名/密码组合来充当我们服务的门卫：

```
ARG PASSWORD=test
...
RUN printf "user:$(openssl passwd -1 $PASSWORD)\n" >> $SRV_PATH/.htpasswd
```

`ARG`充当构建时替代`ENV`指令，并允许将密码作为构建参数传递给`--build-arg <arg>`。如果构建没有提供一个，它应该默认为等号后面的参数，在这种情况下是一个非常不安全的`test`。我们将在`Dockerfile`中稍后使用这个变量来为我们的用户创建一个具有特定密码的`.htpasswd`文件。

第二行使用我们之前安装的`openssl`来获取构建参数，并以 NGINX 和大多数其他 Web 服务器可以理解的格式（`<username>:<hashed_password>`）创建带有加密凭据的`.htpasswd`文件。

警告！请记住，`-1`算法比使用**Salted SHA**（SSHA）方法创建`.htpasswd`密码不够安全，但以这种方式创建它们将涉及更复杂的命令，这将分散我们在这里的主要目的，但您可以访问[`nginx.org/en/docs/http/ngx_http_auth_basic_module.html#auth_basic_user_file`](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html#auth_basic_user_file)获取更多详细信息。还要注意，您不应该使用在线密码生成器，因为它们可能（并经常）窃取您输入的信息。

如果您以前没有使用过 Bash 子 shell，`$(openssl ...)`将在单独的 shell 中运行，并且输出将被替换为字符串变量，然后再进行评估，因此`>>`追加操作将只看到`username:`后的加密密码，与`openssl`无关。从这些事情中应该有些明显，如果我们不提供任何构建参数，容器将具有一个用户名`user`，密码设置为`test`。

警告！此处使用的将凭据传递给镜像的方式仅用作示例，非常不安全，因为任何人都可以运行`docker history`并查看此变量设置为什么，或者启动镜像并回显`PASSWORD`变量。一般来说，传递此类敏感数据的首选方式是在启动容器时通过环境变量传递，将凭据文件挂载为容器的卷，使用`docker secret`或外部凭据共享服务。我们可能会在后面的章节中涵盖其中一些，但现在，您应该记住，出于安全考虑，不要在生产中使用这种特定的凭据传递方式。

`web_server`部分完成后，我们可以转移到下一个部分：数据库。

# 数据库

SQL 数据库在分片和集群方面已经取得了长足的进步，并且通常能够提供良好的性能，但许多面向集群的解决方案都是基于 NoSQL 的，并且在大多数情况下使用键/值存储；此外，它们已经在生态系统中与根深蒂固的 SQL 玩家竞争，逐年获得了越来越多的地位。为了尽快入门并付出最少的努力，我们将选择 MongoDB，这是一个轻而易举的工作，因为它是 NoSQL，我们也不需要设置任何类型的模式，大大减少了我们对棘手配置的需求！

警告！MongoDB 的默认设置非常容易做到，但默认情况下不会启用任何安全性，因此任何具有对该容器的网络访问权限的人都可以读取和写入任何数据库中的数据。在私有云中，这可能是可以接受的，但在任何其他情况下，这都不应该做，因此请记住，如果您计划部署 MongoDB，请确保至少设置了某种隔离和/或身份验证。

我们在这里的整个数据库设置将非常简单，如果我们不需要通过软件包更新来加固它，我们甚至不需要自定义一个：

```
FROM mongo:3

# Make sure we are fully up to date
RUN apt-get update -q && \
 apt-get dist-upgrade -y && \
 apt-get clean && \
 apt-get autoclean
```

当我们运行它时唯一需要考虑的是确保从主机将容器的数据库存储卷（`/var/lib/mongodb`）挂载到容器中，以便在容器停止时保留它，但是一旦我们开始启动容器组，我们可以担心这一点。

# 应用程序服务器

对于这个组件，我们将选择一个需要最少样板代码就能使服务运行的框架，大多数人今天会说是 Node.js 和 Express。由于 Node.js 是基于 JavaScript 的，而 JavaScript 最初是基于类似 Java 的语法的，大多数熟悉 HTML 的人应该能够弄清楚应用程序代码在做什么，但在我们到达那里之前，我们需要定义我们的 Node 包和我们的依赖项，所以在与`web_server`同级的目录下创建一个新的`application_server`目录，并将以下内容添加到一个名为`package.json`的文件中：

```
{
  "name": "application-server",
  "version": "0.0.1",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "express": "⁴.15.4"
  }
}
```

这里真的没有什么神奇的东西；我们只是使用了一个 Node 包定义文件来声明我们需要 Express 作为一个依赖项，并且我们的`npm start`命令应该运行`node index.js`。

让我们现在也制作我们的 Dockerfile：

```
FROM node:8

# Make sure we are fully up to date
RUN apt-get update -q && \
 apt-get dist-upgrade -y && \
 apt-get clean && \
 apt-get autoclean

# Container port that should get exposed
EXPOSE 8000

# Setup any variables we need
ENV SRV_PATH /usr/local/share/word_test

# Make our directory
RUN mkdir -p $SRV_PATH && \
 chown node:node $SRV_PATH

WORKDIR $SRV_PATH

USER node

COPY . $SRV_PATH/

RUN npm install

CMD ["npm", "start"]
```

这些东西对很多人来说应该非常熟悉，特别是对于熟悉 Node 的人来说。我们从`node:8`镜像开始，添加我们的应用程序代码，安装我们在`package.json`中定义的依赖项（使用`npm install`），然后最后确保应用程序在从`docker` CLI 运行时启动。

这里的顺序对于避免缓存破坏和确保适当的权限非常重要。我们将那些我们不指望会经常更改的东西（`USER`，`WORKDIR`，`EXPOSE`，`mkdir`和`chown`）放在`COPY`上面，因为与应用程序代码相比，它们更不可能更改，并且它们大部分是可互换的，我们按照我们认为未来最不可能更改的顺序排列它们，以防止重建层和浪费计算资源。

这里还有一个特定于 Node.js 的图像优化技巧：由于`npm install`通常是处理 Node 应用程序代码更改中最耗时和 CPU 密集的部分，您甚至可以通过仅复制`package.json`，运行`npm install`，然后将其余文件复制到容器中来进一步优化这个 Dockerfile。以这种方式创建容器只会在`package.json`更改时执行昂贵的`npm install`，并且通常会大幅提高构建时间，但出于不希望通过特定于框架的优化来使我们的主要对话偏离主题的目的，本示例中将其排除在外。

到目前为止，我们实际上还没有定义任何应用程序代码，所以让我们也看看它是什么样子。首先，我们需要一个 HTML 视图作为我们的登陆页面，我们可以使用`pug`（以前也被称为`jade`）模板很快地创建一个。创建一个`views/`文件夹，并将其放在该文件夹中名为`index.pug`的文件中：

```
html
  head
    title Docker words
  body
    h1 Saved Words

    form(method='POST' action='/new')
        input.form-control(type='text', placeholder='New word' name='word')
        button(type='submit') Save

    ul
        for word in words
            li= word
```

您不必对这种模板样式了解太多，只需知道它是一个简单的 HTML 页面，在渲染时我们将显示传递给它的`words`数组中的所有项目，如果输入了一个新单词，将会有一个表单提交为`POST`请求到`/new`端点。

# 主要应用逻辑

这里没有简单的方法，但我们的主要应用逻辑文件`index.js`不会像其他配置文件那样简单：

```
'use strict'

// Load our dependencies
const bodyParser = require('body-parser')
const express = require('express');
const mongo = require('mongodb')

// Setup database and server constants
const DB_NAME = 'word_database';
const DB_HOST = process.env.DB_HOST || 'localhost:27017';
const COLLECTION_NAME = 'words';
const SERVER_PORT = 8000;

// Create our app, database clients, and the word list array
const app = express();
const client = mongo.MongoClient();
const dbUri = `mongodb://${DB_HOST}/${DB_NAME}`;
const words = [];

// Setup our templating engine and form data parser
app.set('view engine', 'pug')
app.use(bodyParser.urlencoded({ extended: false }))

// Load all words that are in the database
function loadWordsFromDatabase() {
    return client.connect(dbUri).then((db) => {
        return db.collection(COLLECTION_NAME).find({}).toArray();
    })
    .then((docs) => {
        words.push.apply(words, docs.map(doc => doc.word));
        return words;
    });
}

// Our main landing page handler
app.get('/', (req, res) => {
    res.render('index', { words: words });
});

// Handler for POSTing a new word
app.post('/new', (req, res) => {
    const word = req.body.word;

    console.info(`Got word: ${word}`);
    if (word) {
        client.connect(dbUri).then((db) => {
            db.collection(COLLECTION_NAME).insertOne({ word }, () => {
                db.close();
                words.push(word);
            });
        });
    }

    res.redirect('/');
});

// Start everything by loading words and then starting the server 
loadWordsFromDatabase().then((words) => {
    console.info(`Data loaded from database (${words.length} words)`);
    app.listen(SERVER_PORT, () => {
        console.info("Server started on port %d...", SERVER_PORT);
    });
});
```

这个文件一开始可能看起来令人生畏，但这可能是您可以从头开始制作的最小的完全功能的 API 服务。

如果您想了解更多关于 Node、Express 或 MongoDB 驱动程序的信息，您可以访问[`nodejs.org/en/`](https://nodejs.org/en/)，[`expressjs.com/`](https://expressjs.com/)和[`github.com/mongodb/node-mongodb-native`](https://github.com/mongodb/node-mongodb-native)。如果您不想打字，您也可以从[`github.com/sgnn7/deploying_with_docker/`](https://github.com/sgnn7/deploying_with_docker/)复制并粘贴此文件。

该应用的基本操作如下：

+   从`MongoDB`数据库加载任何现有的单词

+   保留该列表的副本在一个变量中，这样我们只需要从数据库中获取一次东西

+   打开端口`8000`并监听请求

+   如果我们收到`/`的`GET`请求，返回渲染的`index.html`模板，并用单词列表数组填充它

+   如果我们收到`/new`的`POST`请求：

+   将值保存在数据库中

+   更新我们的单词列表

+   发送我们回到`/`

然而，这里有一部分需要特别注意：

```
const DB_HOST = process.env.DB_HOST || 'localhost:27017';
```

记得我们之前提到过，很多图像配置应该在环境变量中完成吗？这正是我们在这里要做的！如果设置了环境变量`DB_HOST`（正如我们期望在作为容器运行时设置），我们将使用它作为主机名，但如果没有提供（正如我们在本地运行时期望的那样），它将假定数据库在标准的 MongoDB 端口上本地运行。这提供了作为容器可配置的灵活性，并且可以在 Docker 之外由开发人员在本地进行测试。

主逻辑文件就位后，我们的服务现在应该有一个类似的文件系统布局：

```
$ tree ./
./
├── Dockerfile
├── index.js
├── package.json
└── views
    └── index.pug

1 directory, 4 files
```

由于这实际上是三个中最容易测试的部分，让我们在本地安装 MongoDB 并看看服务的表现。您可以访问[`docs.mongodb.com/manual/installation/`](https://docs.mongodb.com/manual/installation/)获取有关如何在其他平台上手动安装的信息，但我已经包含了以下步骤来在 Ubuntu 16.04 上手动执行此操作：

```
$ # Install MongoDB
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6
$ echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list

$ sudo apt-get update 
$ sudo apt-get install -y mongodb-org
$ sudo systemctl start mongodb

$ # Install our service dependencies
$ npm install
application-server@0.0.1 /home/sg/checkout/deploying_with_docker/chapter_3/prototype_service/application_server
<snip>
npm WARN application-server@0.0.1 No license field.

$ # Run the service</strong>
$ npm start
> application-server@0.0.1 start /home/sg/checkout/deploying_with_docker/chapter_3/prototype_service/application_server
> node index.js

Data loaded from database (10 words)
Server started on port 8000...
```

看起来工作正常：让我们通过访问`http://localhost:8000`来检查浏览器！

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/9debc5f4-6e14-45e0-8d78-60ed42593f44.png)

让我们在里面放几个词，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/51dc3024-b575-40c0-89c7-9bde31bd511f.png)

到目前为止，一切都很顺利！最后的测试是重新启动服务，并确保我们看到相同的列表。按下*Ctrl* + *C*退出我们的 Node 进程，然后运行`npm start`。您应该再次看到相同的列表，这意味着它按预期工作！

# 一起运行

因此，我们已经弄清楚了我们的`web_server`，`application_server`和`database`容器。在继续之前，请验证您是否拥有所有与这些匹配的文件：

```
$ tree .
.
├── application_server
│   ├── Dockerfile
│   ├── index.js
│   ├── package.json
│   └── views
│       └── index.pug
├── database
│   └── Dockerfile
└── web_server
 ├── Dockerfile
 └── nginx_main_site.conf

4 directories, 7 files
```

我们的下一步是构建所有的容器：

```
 $ # Build the app server image
 $ cd application_server
 $ docker build -t application_server .
 Sending build context to Docker daemon 34.3kB
 Step 1/10 : FROM node:8
 <snip>
 Successfully built f04778cb3778
 Successfully tagged application_server:latest

 $ # Build the database image
 $ cd ../database
 $ docker build -t database .
 Sending build context to Docker daemon 2.048kB
 Step 1/2 : FROM mongo:3
 <snip>
 Successfully built 7c0f9399a152
 Successfully tagged database:latest

 $ # Build the web server image
 $ cd ../web_server
 $ docker build -t web_server .
 Sending build context to Docker daemon 3.584kB
 Step 1/8 : FROM nginx:latest
 <snip>
 Successfully built 738c17ddeca8
 Successfully tagged web_server:latest
```

这种顺序构建非常适合显示每个步骤需要做什么，但始终考虑自动化以及如何改进手动流程。在这种特殊情况下，这整个语句和执行块也可以从父目录中用这一行完成：`for dir in *; do cd $dir; docker build -t $dir .; cd ..; done`

# 启动

有了这三个相关的容器，我们现在可以启动它们。需要注意的是，它们需要按照我们的应用程序尝试读取数据库中的数据的顺序启动，如果应用程序不存在，我们不希望 Web 服务器启动，因此我们将按照这个顺序启动它们：`database -> application_server -> web_server`：

```
$ docker run --rm \
             -d \
             -p 27000:27017 \
             database
3baec5d1ceb6ec277a87c46bcf32f3600084ca47e0edf26209ca94c974694009

$ docker run --rm \
             -d \
             -e DB_HOST=172.17.0.1:27000 \
             -p 8000:8000 \
             application_server
dad98a02ab6fff63a2f4096f4e285f350f084b844ddb5d10ea3c8f5b7d1cb24b

$ docker run --rm \
             -d \
             -p 8080:80 \
             web_server
3ba3d1c2a25f26273592a9446fc6ee2a876904d0773aea295a06ed3d664eca5d

$ # Verify that all containers are running
$ docker ps --format "table {{.Image}}\t{{.Status}}\t{{.ID}}\t{{.Ports}}"
IMAGE                STATUS              CONTAINER ID        PORTS
web_server           Up 11 seconds       3ba3d1c2a25f        0.0.0.0:8080->80/tcp
application_server   Up 26 seconds       dad98a02ab6f        0.0.0.0:8000->8000/tcp
database             Up 45 seconds       3baec5d1ceb6        0.0.0.0:27000->27017/tcp
```

这里有几件事需要注意：

+   我们故意将本地端口`27000`映射到数据库`27017`，以避免与主机上已经运行的 MongoDB 数据库发生冲突。

+   我们将神奇的`172.17.0.1` IP 作为主机和端口`27000`传递给我们的应用服务器，用作数据库主机。

+   我们将 Web 服务器启动在端口`8080`上，而不是`80`，以确保我们不需要 root 权限*。

如果您没有看到三个正在运行的容器，请使用`docker logs <container id>`检查日志。最有可能的罪魁祸首可能是容器上的 IP/端口与目的地之间的不匹配，因此只需修复并重新启动失败的容器，直到您有三个正在运行的容器。如果您遇到很多问题，请毫不犹豫地通过从我们使用的命令中删除`-d`标志来以非守护程序模式启动容器。* - 在*nix 系统上，低于`1024`的端口称为注册或特权端口，它们管理系统通信的许多重要方面。为了防止对这些系统端口的恶意使用，几乎所有这些平台都需要 root 级别的访问权限。由于我们并不真的关心我们将用于测试的端口，我们将通过选择端口 8080 来完全避免这个问题。

这个设置中的信息流大致如下：

```
Browser <=> localhost:8080 <=> web_server:80 <=> 172.17.0.1:8000 (Docker "localhost") <=> app_server <=> 172.17.0.1:27000 (Docker "localhost") <=> database:27017
```

# 测试

我们所有的部件都在运行，所以让我们在`http://localhost:8080`上试试看！

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/3b3eba36-e8bd-4025-9078-7805e300de88.png)

很好，我们的身份验证正在工作！让我们输入我们超级秘密的凭据（用户：`user`，密码：`test`）。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/47647778-1bdf-471c-af06-81f1446c17a1.png)

一旦我们登录，我们应该能够看到我们的应用服务器接管请求的处理，并给我们一个表单来输入我们想要保存的单词：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/bb732e1c-5439-45ea-9bd8-45534cfdac3c.png)

正如我们所希望的，一旦我们进行身份验证，应用服务器就会处理请求！输入一些单词，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/0dd93630-4a99-4c86-bcc5-bf6f42fa0c98.png)

恭喜！您已经创建了您的第一个容器化服务！

# 我们实现的限制和问题

我们应该花一分钟时间考虑如果要在真实系统中使用它，我们服务的哪些部分可能需要改进，以及最优/实际的缓解措施可能是什么。由于处理容器和云的关键部分是评估更大体系结构的利弊，这是您在开发新系统或更改现有系统时应该尝试做的事情。

从粗略的观察来看，这些是可以改进的明显事项，影响是什么，以及可能的缓解措施是什么：

+   数据库没有身份验证

+   **类别**：安全性，影响非常大

+   **缓解措施**：私有云或使用身份验证

+   数据库数据存储在 Docker 容器中（如果容器丢失，则数据也会丢失）

+   **类别**：稳定性，影响严重

+   **缓解措施**：挂载卷和/或分片和集群

+   硬编码的端点

+   **类别**：运维，影响非常大

+   **缓解措施**：服务发现（我们将在后面的章节中介绍）

+   应用服务器假设它是唯一更改单词列表的

+   **类别**：扩展性，影响非常大

+   **缓解措施**：在每次页面加载时刷新数据

+   应用服务器在容器启动时需要数据库

+   **类别**：扩展性/运维，中等影响

+   **缓解措施**：延迟加载直到页面被点击和/或显示数据库不可用的消息

+   Web 服务器身份验证已经嵌入到镜像中

+   **类别**：安全性，影响严重

+   **缓解措施**：在运行时添加凭据

+   Web 服务器身份验证是通过 HTTP 完成的

+   **类别**：安全性，影响非常大

+   **缓解措施**：使用 HTTPS 和/或 OAuth

# 修复关键问题

由于我们在 Docker 的旅程中还处于早期阶段，现在我们只会涵盖一些最关键问题的解决方法，这些问题如下：

+   数据库数据存储在 Docker 容器中（如果容器丢失，数据也会丢失）。

+   Web 服务器身份验证已经内置到镜像中。

# 使用本地卷

第一个问题是一个非常严重的问题，因为我们所有的数据目前都与我们的容器绑定，所以如果数据库应用停止，您必须重新启动相同的容器才能恢复数据。在这种情况下，如果容器使用`--rm`标志运行并停止或以其他方式终止，与其关联的所有数据将消失，这绝对不是我们想要的。虽然针对这个问题的大规模解决方案是通过分片、集群和/或持久卷来完成的，但我们只需直接将数据卷挂载到容器中的所需位置即可。如果容器发生任何问题，这样可以将数据保留在主机文件系统上，并且可以根据需要进一步备份或移动到其他地方。

将目录挂载到容器中的这个过程实际上相对容易，如果我们的卷是存储在 Docker 内部的一个命名卷的话：

```
$ docker run --rm -d -v local_storage:/data/db -p 27000:27017 database
```

这将在 Docker 的本地存储中创建一个名为`local_storage`的命名卷，它将无缝地挂载到容器中的`/data/db`（这是 MongoDB 镜像在 Docker Hub 中存储数据的地方）。如果容器死掉或发生任何事情，您可以将此卷挂载到另一个容器上并保留数据。

`-v`，`--volume`和使用命名卷并不是为 Docker 容器创建卷的唯一方法。我们将在第五章中更详细地讨论为什么我们使用这种语法而不是其他选项（即`--mount`），该章节专门涉及卷的持久性。

让我们看看这在实际中是如何运作的（这可能需要在您的主机上安装一个 MongoDB 客户端 CLI）：

```
$ # Start our container
$ docker run --rm \
             -d \
             -v local_storage:/data/db \
             -p 27000:27017 \
             database
16c72859da1b6f5fbe75aa735b539303c5c14442d8b64b733eca257dc31a2722

$ # Insert a test record in test_db/coll1 as { "item": "value" }
$ mongo localhost:27000
MongoDB shell version: 2.6.10
connecting to: localhost:27000/test

> use test_db
switched to db test_db
 > db.createCollection("coll1")
{ "ok" : 1 }
 > db.coll1.insert({"item": "value"})
WriteResult({ "nInserted" : 1 })
 > exit
bye

$ # Stop the container. The --rm flag will remove it.
$ docker stop 16c72859
16c72859

$ # See what volumes we have
$ docker volume ls
DRIVER              VOLUME NAME
local               local_storage

$ # Run a new container with the volume we saved data onto
$ docker run --rm \
             -d \
             -v local_storage:/data/db \
             -p 27000:27017 \
             database
a5ef005ab9426614d044cc224258fe3f8d63228dd71dee65c188f1a10594b356

$ # Check if we have our records saved
$ mongo localhost:27000
MongoDB shell version: 2.6.10
connecting to: localhost:27000/test

> use test_db
switched to db test_db
 > db.coll1.find()
{ "_id" : ObjectId("599cc7010a367b3ad1668078"), "item" : "value" }
 > exit

$ # Cleanup
$ docker stop a5ef005a
a5ef005a
```

正如您所看到的，我们的记录经过了原始容器的销毁而得以保留，这正是我们想要的！我们将在后面的章节中涵盖如何以其他方式处理卷，但这应该足以让我们解决我们小服务中的这个关键问题。

# 在运行时生成凭据

与数据库问题不同，这个特定问题不那么容易处理，主要是因为从安全角度来看，凭据是一个棘手的问题。如果你包含一个构建参数或内置的环境变量，任何有权访问镜像的人都可以读取它。此外，如果你在容器创建过程中通过环境变量传递凭据，任何具有 docker CLI 访问权限的人都可以读取它，所以你基本上只能将凭据挂载到容器的卷上。

还有一些其他安全地传递凭据的方法，尽管它们有点超出了本练习的范围，比如包含哈希密码的环境变量，使用代理秘密共享服务，使用特定于云的角色机制（即 AWS，IAM 角色，“用户数据”）等等，但对于本节来说，重要的是要理解在处理身份验证数据时应该尽量避免做哪些事情。

为了解决这个问题，我们将在主机上生成自己的凭据文件，并在容器启动时将其挂载到容器上。用你想要的任何用户名替换`user123`，用包含字母数字的密码替换`password123`：

```
$ printf "user123:$(openssl passwd -1 password123)\n" >> ~/test_htpasswd

$ # Start the web_server with our password as the credentials source
$ docker run --rm \
             -v $HOME/test_htpasswd:/srv/www/html/.htpasswd \
             -p 8080:80 web_server
1b96c35269dadb1ac98ea711eec4ea670ad7878a933745678f4385d57e96224a
```

通过这个小改变，你的 Web 服务器现在将使用新的用户名和新的密码进行安全保护，并且配置也不会被能够运行 docker 命令的人所获取。你可以访问[`127.0.0.1:8080`](http://127.0.0.1:8080)来查看新的用户名和密码是唯一有效的凭据。

# 引入 Docker 网络

在较早的时候，我们已经略微提到了在`web_server`代码中使用 IP`172.17.0.1`，这在其他材料中并没有得到很好的涵盖，但如果你想对 Docker 有一个扎实的理解，这是非常重要的事情。当在一台机器上启动 Docker 服务时，会向您的机器添加一些网络`iptables`规则，以允许容器通过转发连接到世界，反之亦然。实际上，您的机器变成了所有启动的容器的互联网路由器。除此之外，每个新容器都被分配一个虚拟地址（很可能在`172.17.0.2`+的范围内），它所进行的任何通信通常对其他容器是不可见的，除非创建了一个软件定义的网络，因此在同一台机器上连接多个容器实际上是一个非常棘手的任务，如果没有 Docker 基础设施中称为**服务发现**的辅助软件。

由于我们现在不想要这个服务发现的开销（我们稍后会更深入地介绍），并且我们不能使用`localhost`/`127.0.0.1`/`::1`，这根本行不通，我们需要给它 Docker 虚拟路由器 IP（几乎总是`172.17.0.1`），这样它就能找到我们的实际机器，其他容器端口已经绑定在那里。

请注意，由于 macOS 和 Windows 机器的网络堆栈实现方式，本节的大部分内容在这些系统上都无法工作。对于这些系统，我建议您使用 Ubuntu 虚拟机来跟随操作。

如果您想验证这一点，我们可以使用一些命令在 Docker 内外来真正看到发生了什么：

```
$ # Host's iptables. If you have running containers, DOCKER chain wouldn't be empty.
$ sudo iptables -L
<snip>
Chain FORWARD (policy DROP)
target     prot opt source               destination 
DOCKER-ISOLATION  all  --  anywhere             anywhere 
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
<snip>
Chain DOCKER (1 references)
target     prot opt source               destination 

Chain DOCKER-ISOLATION (1 references)
target     prot opt source               destination 
RETURN     all  --  anywhere             anywhere 
<snip>

$ # Host's network addresses is 172.17.0.1
$ ip addr
<snip>
5: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
 link/ether 02:42:3c:3a:77:c1 brd ff:ff:ff:ff:ff:ff
 inet 172.17.0.1/16 scope global docker0
 valid_lft forever preferred_lft forever
 inet6 fe80::42:3cff:fe3a:77c1/64 scope link 
 valid_lft forever preferred_lft forever
<snip>

$ # Get container's network addresses
$ docker run --rm \
             -it \
             web_server /bin/bash
 root@08b6521702ef:/# # Install pre-requisite (iproute2) package
root@08b6521702ef:/# apt-get update && apt-get install -y iproute2
<snip>
 root@08b6521702ef:/# # Check the container internal address (172.17.0.2)
root@08b6521702ef:/# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
722: eth0@if723: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
 link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
 inet 172.17.0.2/16 scope global eth0
 valid_lft forever preferred_lft forever
 root@08b6521702ef:/# # Verify that our main route is through our host at 172.17.0.1
root@08b6521702ef:/# ip route
default via 172.17.0.1 dev eth0
172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.2
 root@08b6521702ef:/# exit
```

正如您所看到的，这个系统有点奇怪，但它运行得相当不错。通常在构建更大的系统时，服务发现几乎是强制性的，因此您不必在现场担心这样的低级细节。

# 总结

在本章中，我们介绍了如何构建多个容器，以构建由 Web 服务器、应用服务器和数据库组成的基本服务，同时启动多个容器，并通过网络将它们连接在一起。我们还解决了连接服务时可能出现的最常见问题，以及这些基本构建模块的常见陷阱。还提到了一些关于未来主题的提示（卷、服务发现、凭据传递等），但我们将在以后的章节中深入讨论这些内容。在下一章中，我们将把我们的小服务转变成具有水平扩展组件的强大服务。


# 第四章：扩展容器

在本章中，我们将使用我们的服务，并尝试通过多个相同容器的实例来水平扩展它。我们将在本章中涵盖以下主题：

+   编排选项及其优缺点

+   服务发现

+   状态协调

+   部署自己的 Docker Swarm 集群

+   将我们在上一章中的 word 服务部署到该集群上

# 服务发现

在我们进一步之前，我们真的需要深入了解概念上的 Docker 容器连通性，这在某种程度上与在非容器化世界中使用服务器构建高可用服务非常相似。因此，深入探讨这个主题不仅会扩展您对 Docker 网络的理解，还有助于通常构建出弹性服务。

# Docker 网络的回顾

在上一章中，我们介绍了一些 Docker 网络布局，所以我们将在这里介绍主要内容：

+   默认情况下，Docker 容器在主机上运行在一个隔离的虚拟网络中

+   每个容器在该网络中都有自己的网络地址

+   默认情况下，容器的 `localhost` *不是* 主机机器的 `localhost`

+   手动连接容器存在很高的人工工作开销

+   容器之间的手动网络连接本质上是脆弱的

在设置本地服务器网络的并行世界中，Docker 连通性的基本体验非常类似于使用静态 IP 连接整个网络。虽然这种方法并不难以实现，但维护起来非常困难和费力，这就是为什么我们需要比这更好的东西。

# 深入了解服务发现

由于我们不想处理这种脆弱的保持和维护硬编码 IP 地址的系统，我们需要找出一种方法，使我们的连接灵活，并且不需要客户端进行任何调整，如果目标服务死掉或创建一个新的服务。如果每个对同一服务的连接在所有相同服务的实例之间平衡，那就更好了。理想情况下，我们的服务看起来应该是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/533c4c3e-976c-4621-a9ad-e138dc097b9e.png)

对于互联网的这种确切用例，DNS 被创建出来，以便客户端可以在世界各地找到服务器，即使 IP 地址或网络发生变化。作为一个附加好处，我们有更容易记住的目标地址（DNS 名称，如[`google.com`](https://google.com)，而不是诸如`https://123.45.67.89`之类的东西），并且可以将处理分配给尽可能多的处理服务。

如果您没有深入研究 DNS，主要原则可以归纳为这些基本步骤：

1.  用户（或应用程序）想要连接到一个服务器（即[google.com](http://www.google.com)）。

1.  本地机器要么使用自己缓存的 DNS 答案，要么去 DNS 系统搜索这个名称。

1.  本地机器得到应该用作目标的 IP 地址（`123.45.67.89`）。

1.  本地机器连接到 IP 地址。

DNS 系统比这里提到的单个句子要复杂得多。虽然 DNS 是任何面向服务器的技术职位中了解的一件非常好的事情，在这里，只需要知道 DNS 系统的输入是主机名，输出是真正的目标（IP）就足够了。如果您想了解 DNS 系统实际上是如何工作的更多信息，我建议您在闲暇时访问[`en.wikipedia.org/wiki/Domain_Name_System`](https://en.wikipedia.org/wiki/Domain_Name_System)。

如果我们强迫几乎所有客户端中已实现的 DNS 处理作为一种自动发现服务的方式，我们可以使自己成为我们一直在寻找的服务发现机制！如果我们使它足够智能，它可以告诉我们正在运行的容器在哪里，平衡相同容器的所有实例，并为我们提供一个静态名称作为我们的目标使用。正如人们可能期望的那样，几乎所有容器服务发现系统都具有这种功能模式；只是通常有所不同，无论是作为客户端发现模式、服务器端发现模式，还是某种混合系统。

# 客户端发现模式

这种类型的模式并不经常使用，但它基本上涉及使用服务感知客户端来发现其他服务并在它们之间进行负载平衡。这里的优势在于客户端可以智能地决定连接到哪里以及以何种方式，但缺点是这种决策分布在每个服务上并且难以维护，但它不依赖于单一的真相来源（单一服务注册表），如果它失败，可能会导致整个集群崩溃。

体系结构通常看起来类似于这样：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/9e41d219-feb2-4831-bc70-82b533f54c11.png)**

# 服务器端发现模式

更常见的服务发现模式是集中式服务器端发现模式，其中使用 DNS 系统将客户端引导到容器。在这种特定的服务发现方式中，容器会从服务注册表中注册和注销自己，该注册表保存系统的状态。这种状态反过来用于填充 DNS 条目，然后客户端联系这些条目以找到它试图连接的目标。虽然这个系统通常相当稳定和灵活，但有时会遇到非常棘手的问题，通常会妨碍 DNS 系统的其他地方，比如 DNS 缓存，它使用过时的 IP 地址，直到**生存时间**（TTL）到期，或者应用程序本身缓存 DNS 条目而不管更新（NGINX 和 Java 应用程序以此著称）。

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/087d23be-79c8-4b67-bec8-0feaeb036efb.png)**

# 混合系统

这个分组包括我们尚未涵盖的所有其他组合，但它涵盖了使用工具 HAProxy 的最大部署类别，我们稍后将详细介绍。它基本上是将主机上的特定端口（即`<host>:10101`）与集群中的负载平衡目标绑定起来。

从客户端的角度来看，他们连接到一个单一且稳定的位置，然后 HAProxy 将其无缝地隧道到正确的目标。

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/a7a98255-eb1a-47bc-a559-f6712e281787.png)**

这种设置支持拉取和推送刷新方法，并且非常有韧性，但我们将在后面的章节中深入探讨这种类型的设置。

# 选择（不）可用的选项

有了所有这些类型的服务发现可用，我们应该能够处理任何我们想要的容器扩展，但我们需要牢记一件非常重要的事情：几乎所有服务发现工具都与用于部署和管理容器的系统（也称为容器编排）紧密相关，因为容器端点的更新通常只是编排系统的实现细节。因此，服务发现系统通常不像人们希望的那样可移植，因此这种基础设施的选择通常由您的编排工具决定（偶尔会有一些例外）。

# 容器编排

正如我们稍早所暗示的，服务发现是在任何情况下部署基于容器的系统的关键部分。如果没有类似的东西，你可能会选择使用裸机服务器，因为使用容器获得的大部分优势都已经丧失了。要拥有有效的服务发现系统，你几乎必须使用某种容器编排平台，而幸运的是（或者可能是不幸的？），容器编排的选择几乎以惊人的速度不断涌现！总的来说，在撰写本书时（以及在我谦逊的意见中），流行且稳定的选择主要归结为以下几种：

+   Docker Swarm

+   Kubernetes

+   Apache Mesos/Marathon

+   基于云的服务（Amazon ECS，Google Container Engine，Azure Container Service 等）

每个都有自己的词汇表和基础设施连接方式，因此在我们进一步之前，我们需要涵盖有关编排服务的相关词汇，这些词汇在所有这些服务之间大多是可重复使用的：

+   **节点**：Docker 引擎的一个实例。通常仅在谈论集群连接的实例时使用。

+   **服务**：由一个或多个运行中的相同 Docker 镜像实例组成的功能组。

+   **任务**：运行服务的特定和唯一实例。通常是一个运行中的 Docker 容器。

+   **扩展**：指定服务运行的任务数量。这通常决定了服务可以支持多少吞吐量。

+   **管理节点**：负责集群管理和编排任务的节点。

+   **工作节点**：指定为任务运行者的节点。

# 状态协调

除了我们刚学到的字典，我们还需要了解几乎所有编排框架的基本算法，状态协调，它值得在这里有自己的小节。这个工作的基本原则是一个非常简单的三步过程，如下：

+   用户设置每个服务或服务消失的期望计数。

+   编排框架看到了改变当前状态到期望状态所需的内容（增量评估）。

+   执行任何需要将集群带到该状态的操作（称为状态协调）。

！[](assets/23380424-de88-49b9-8fe9-76b0e8f78015.png)

例如，如果我们当前在集群中为一个服务运行了五个任务，并将期望状态更改为只有三个任务，我们的管理/编排系统将看到差异为`-2`，因此选择两个随机任务并无缝地杀死它们。相反，如果我们有三个正在运行的任务，而我们想要五个，管理/编排系统将看到期望的增量为`+2`，因此它将选择两个具有可用资源的位置，并启动两个新任务。对两个状态转换的简要解释也应该有助于澄清这个过程：

```
Initial State: Service #1 (3 tasks), Service #2 (2 tasks)
Desired State: Service #1 (1 task),  Service #2 (4 tasks)

Reconciliation:
 - Kill 2 random Service #1 tasks
 - Start 2 Service #2 tasks on available nodes

New Initial State: Service #1 (1 tasks), Service #2 (4 tasks)

New Desired State: Service #1 (2 tasks), Service #2 (0 tasks)

Reconciliation:
 - Start 1 tasks of Service #1 on available node
 - Kill all 4 running tasks of Service #2

Final State: Service #1 (2 tasks), Service #2 (0 tasks)
```

使用这个非常简单但强大的逻辑，我们可以动态地扩展和缩小我们的服务，而不必担心中间阶段（在一定程度上）。在内部，保持和维护状态是一个非常困难的任务，大多数编排框架使用特殊的高速键值存储组件来为它们执行此操作（即`etcd`，`ZooKeeper`和`Consul`）。

由于我们的系统只关心当前状态和需要的状态，这个算法也兼作建立弹性的系统，当一个节点死掉，或者容器减少了应用程序的当前任务计数，将自动触发状态转换回到期望的计数。只要服务大多是无状态的，并且你有资源来运行新的服务，这些集群对几乎任何类型的故障都是有弹性的，现在你可以希望看到一些简单的概念如何结合在一起创建这样一个强大的基础设施。

有了我们对管理和编排框架基础的新理解，我们现在将简要地看一下我们可用选项中的每一个（Docker Swarm，Kubernetes，Marathon），并看看它们如何相互比较。

# Docker Swarm

Docker 默认包含一个编排框架和一个管理平台，其架构与刚才介绍的非常相似，称为 Docker Swarm。Swarm 允许以相对较快和简单的方式将扩展集成到您的平台中，而且几乎不需要时间来适应，而且它已经是 Docker 本身的一部分，因此您实际上不需要太多其他东西来在集群环境中部署一组简单的服务。作为额外的好处，它包含一个相当可靠的服务发现框架，具有多主机网络能力，并且在节点之间使用 TLS 进行通信。

多主机网络能力是系统在多台物理机器之间创建虚拟网络的能力，从容器的角度来看，这些物理机器是透明的。使用其中之一，您的容器可以彼此通信，就好像它们在同一个物理网络上一样，简化了连接逻辑并降低了运营成本。我们稍后将深入研究集群的这一方面。

Docker Swarm 的集群配置可以是一个简单的 YAML 文件，但缺点是，在撰写本文时，GUI 工具有些欠缺，尽管 Portainer（[`portainer.io`](https://portainer.io)）和 Shipyard（[`shipyard-project.com`](https://shipyard-project.com)）正在变得相当不错，所以这可能不会是一个长期的问题。此外，一些大规模的运维工具缺失，似乎 Swarm 的功能正在大幅发展，因此处于不稳定状态，因此我的个人建议是，如果您需要快速在小到大规模上运行某些东西，可以使用这种编排。随着这款产品变得越来越成熟（并且由于 Docker Inc.正在投入大量开发资源），它可能会有显著改进，我期望它在许多方面能够与 Kubernetes 功能相匹敌，因此请密切关注其功能新闻。

# Kubernetes

Kubernetes 是谷歌的云平台和编排引擎，目前在功能方面比 Swarm 提供了更多。Kubernetes 的设置要困难得多，因为你需要：一个主节点，一个节点（根据我们之前的词典，这是工作节点），以及 pod（一个或多个容器的分组）。Pod 始终是共同定位和共同调度的，因此处理它们的依赖关系会更容易一些，但你不会得到相同的隔离。在这里需要记住的有趣的事情是，pod 内的所有容器共享相同的 IP 地址/端口，共享卷，并且通常在相同的隔离组内。几乎可以将 pod 视为运行多个服务的小型虚拟机，而不是并行运行多个容器。

Kubernetes 最近一直在获得大量的社区关注，可能是最被部署的集群编排和管理系统，尽管要公平地说，找到确切的数字是棘手的，其中大多数被部署在私有云中。考虑到谷歌已经在如此大规模上使用这个系统，它有着相当成熟的记录，我可能会推荐它用于中大规模。如果你不介意设置一切的开销，我认为即使在较小规模上也是可以接受的，但在这个领域，Docker Swarm 非常容易使用，因此使用 Kubernetes 通常是不切实际的。

在撰写本书时，Mesos 和 Docker EE 都已经包含了支持 Kubernetes 的功能，所以如果你想要在编排引擎上打赌，这可能就是它！

# Apache Mesos/Marathon

当你真的需要将规模扩大到 Twitter 和 Airbnb 的级别时，你可能需要比 Swarm 或 Kubernetes 更强大的东西，这就是 Mesos 和 Marathon 发挥作用的地方。Apache Mesos 实际上并不是为 Docker 而建立的，而是作为一种通用的集群管理工具，以一种一致的方式为在其之上运行的应用程序提供资源管理和 API。你可以相对容易地运行从脚本、实际应用程序到多个平台（如 HDFS 和 Hadoop）的任何东西。对于这个平台上基于容器的编排和调度，Marathon 是通用的选择。

正如稍早提到的，Kubernetes 支持现在又可以在 Mesos 上使用了，之前一段时间处于破碎状态，因此在您阅读本文时，对 Marathon 的建议可能会改变。

Marathon 作为 Mesos 上的应用程序（在非常宽松的意义上）运行作为容器编排平台，并提供各种便利，如出色的用户界面（尽管 Kubernetes 也有一个），指标，约束，持久卷（在撰写本文时为实验性质），以及其他许多功能。作为一个平台，Mesos 和 Marathon 可能是处理成千上万个节点的集群最强大的组合，但要将所有东西组合在一起，除非您使用预打包的 DC/OS 解决方案（[`dcos.io/`](https://dcos.io/)），根据我的经验，与其他两种方法相比，真的非常棘手。如果您需要覆盖中等到最大规模，并增加灵活性以便在其上运行其他平台（如 Chronos），目前，我强烈推荐这种组合。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/8ceb3bee-952b-4aba-93d8-8ce66365f06b.png)

# 基于云的服务

如果所有这些似乎太麻烦，而且您不介意每个月支付高昂的费用，所有大型云服务提供商都有某种基于容器的服务提供。由于这些服务在功能和特性方面差异很大，任何放在这个页面上的内容在发布时可能已经过时，而我们更感兴趣的是部署我们自己的服务，因此我将为您提供适当的服务的链接，这些链接将提供最新的信息，如果您选择这条路线：

+   亚马逊 ECS：[`aws.amazon.com/ecs/`](https://aws.amazon.com/ecs/)

+   谷歌容器引擎：[`cloud.google.com/container-engine/`](https://cloud.google.com/container-engine/)

+   微软 Azure（Azure 容器服务）：[`azure.microsoft.com/en-us/services/container-service/`](https://azure.microsoft.com/en-us/services/container-service/)

+   Oracle 容器云服务：[`cloud.oracle.com/container`](https://cloud.oracle.com/container)

+   Docker Cloud：[`cloud.docker.com/`](https://cloud.docker.com/)

+   可能还有其他一些我错过的

就我个人而言，我会推荐这种方法用于中小型部署，因为它易于使用并且经过测试。如果您的需求超出了这些规模，通常有一种方法是在**虚拟私有云**（**VPCs**）上的可扩展虚拟机组上实施您的服务，因为您可以根据需求扩展自己的基础架构，尽管前期的 DevOps 成本不小，所以请据此决定。几乎任何云服务提供商提供的一个良好的经验法则是，通过提供易用的工具，您可以获得更快的部署速度，但代价是成本增加（通常是隐藏的）和缺乏灵活性/可定制性。

# 实施编排

通过我们新获得的对编排和管理工具的理解，现在是时候自己尝试一下了。在我们的下一个练习中，我们将首先尝试使用 Docker Swarm 来创建并在本地集群上进行一些操作，然后我们将尝试将上一章的服务部署到其中。

# 设置 Docker Swarm 集群

由于设置 Docker Swarm 集群的所有功能已经包含在 Docker 安装中，这实际上是一件非常容易的事情。让我们看看我们可以使用哪些命令：

```
$ docker swarm
<snip>
Commands:
 init        Initialize a swarm
 join        Join a swarm as a node and/or manager
 join-token  Manage join tokens
 leave       Leave the swarm
 unlock      Unlock swarm
 unlock-key  Manage the unlock key
 update      Update the swarm
```

这里有几件事情需要注意--有些比其他更明显：

+   您可以使用 `docker swarm init` 创建一个集群

+   您可以使用 `docker swarm join` 加入一个集群，该机器可以是工作节点、管理节点或两者兼而有之

+   身份验证是使用令牌（需要匹配的唯一字符串）进行管理

+   如果管理节点发生故障，例如重新启动或断电，并且您已经设置了自动锁定集群，您将需要一个解锁密钥来解锁 TLS 密钥

到目前为止，一切顺利，让我们看看我们是否可以设置一个同时作为管理节点和工作节点的集群，以了解其工作原理。

# 初始化 Docker Swarm 集群

要创建我们的集群，我们首先需要实例化它：

```
$ docker swarm init 
Swarm initialized: current node (osb7tritzhtlux1o9unlu2vd0) is now a manager.

To add a worker to this swarm, run the following command:

 docker swarm join \
 --token SWMTKN-1-4atg39hw64uagiqk3i6s3zlv5mforrzj0kk1aeae22tpsat2jj-2zn0ak0ldxo58d1q7347t4rd5 \
 192.168.4.128:2377

To add a manager to this swarm, run 'docker swarm join-token manager' and follow the instructions.

$ # Make sure that our node is operational
$ docker node ls
ID                           HOSTNAME  STATUS  AVAILABILITY  MANAGER STATUS
osb7tritzhtlux1o9unlu2vd0 *  feather2  Ready   Active        Leader
```

我们已经用那个命令创建了一个集群，并且我们自动注册为管理节点。如果您查看输出，添加工作节点的命令只是 `docker swarm join --token <token> <ip>`，但是我们现在只对单节点部署感兴趣，所以我们不需要担心这个。鉴于我们的管理节点也是工作节点，我们可以直接使用它来部署一些服务。

# 部署服务

我们最初需要的大多数命令都可以通过`docker services`命令访问：

```
$ docker service
<snip>
Commands:
 create      Create a new service
 inspect     Display detailed information on one or more services
 logs        Fetch the logs of a service or task
 ls          List services
 ps          List the tasks of one or more services
 rm          Remove one or more services
 scale       Scale one or multiple replicated services
 update      Update a service
```

正如你可能怀疑的那样，考虑到这些命令与管理容器的一些命令有多么相似，一旦你转移到编排平台而不是直接操作容器，你的服务的理想管理将通过编排本身完成。我可能会扩展这一点，并且会说，如果你在拥有编排平台的同时过多地使用容器，那么你没有设置好某些东西，或者你没有正确地设置它。

我们现在将尝试在我们的 Swarm 上运行某种服务，但由于我们只是在探索所有这些是如何工作的，我们可以使用一个非常简化（也非常不安全）的我们的 Python Web 服务器的版本。从第二章 *Rolling Up the Sleeves*。创建一个新文件夹，并将其添加到新的`Dockerfile`中：

```
FROM python:3

ENV SRV_PATH=/srv/www/html

EXPOSE 8000

RUN mkdir -p $SRV_PATH && \
 groupadd -r -g 350 pythonsrv && \
 useradd -r -m -u 350 -g 350 pythonsrv && \
 echo "Test file content" > $SRV_PATH/test.txt && \
 chown -R pythonsrv:pythonsrv $SRV_PATH

WORKDIR $SRV_PATH

CMD [ "python3", "-m", "http.server" ]
```

让我们构建它，以便我们的本地注册表有一个镜像可以从中拉取，当我们定义我们的服务时：

```
$ docker build -t simple_server .
```

有了这个镜像，让我们在我们的 Swarm 上部署它：

```
$ docker service create --detach=true \
 --name simple-server \
 -p 8000:8000 \
 simple_server 
image simple_server could not be accessed on a registry to record
its digest. Each node will access simple_server independently,
possibly leading to different nodes running different
versions of the image.

z0z90wgylcpf11xxbm8knks9m

$ docker service ls
ID           NAME          MODE       REPLICAS IMAGE         PORTS
z0z90wgylcpf simple-server replicated 1/1      simple_server *:8000->8000/tcp
```

所显示的警告实际上非常重要：我们构建时服务仅在我们本地机器的 Docker 注册表上可用，因此使用分布在多个节点之间的 Swarm 服务将会出现问题，因为其他机器将无法加载相同的镜像。因此，将镜像注册表从单一来源提供给所有节点对于集群部署是强制性的。随着我们在本章和接下来的章节中的进展，我们将更详细地讨论这个问题。

如果我们检查`http://127.0.0.1:8000`，我们可以看到我们的服务正在运行！让我们看看这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/de4bc4a5-6c91-4c2a-a740-66b70e72e1b6.png)

如果我们将这项服务扩展到三个实例，我们可以看到我们的编排工具是如何处理状态转换的：

```
$ docker service scale simple-server=3 
image simple_server could not be accessed on a registry to record
its digest. Each node will access simple_server independently,
possibly leading to different nodes running different
versions of the image.

simple-server scaled to 3

$ docker service ls
ID           NAME          MODE       REPLICAS IMAGE         PORTS
z0z90wgylcpf simple-server replicated 2/3      simple_server *:8000->8000/tcp

$ # After waiting a bit, let's see if we have 3 instances now
$ docker service ls
ID           NAME          MODE       REPLICAS IMAGE         PORTS
z0z90wgylcpf simple-server replicated 3/3      simple_server *:8000->8000/tcp

$ # You can even use regular container commands to see it
$ docker ps --format 'table {{.ID}}  {{.Image}}  {{.Ports}}'
CONTAINER ID  IMAGE  PORTS
0c9fdf88634f  simple_server:latest  8000/tcp
98d158f82132  simple_server:latest  8000/tcp
9242a969632f  simple_server:latest  8000/tcp
```

您可以看到这是如何调整容器实例以适应我们指定的参数的。如果我们现在在其中添加一些在现实生活中会发生的事情-容器死亡：

```
$ docker ps --format 'table {{.ID}}  {{.Image}}  {{.Ports}}'
CONTAINER ID  IMAGE  PORTS
0c9fdf88634f  simple_server:latest  8000/tcp
98d158f82132  simple_server:latest  8000/tcp
9242a969632f  simple_server:latest  8000/tcp

$ docker kill 0c9fdf88634f
0c9fdf88634f

$ # We should only now have 2 containers
$ docker ps --format 'table {{.ID}}  {{.Image}}  {{.Ports}}'
CONTAINER ID  IMAGE  PORTS
98d158f82132  simple_server:latest  8000/tcp
9242a969632f  simple_server:latest  8000/tcp

$ # Wait a few seconds and try again
$ docker ps --format 'table {{.ID}}  {{.Image}}  {{.Ports}}'
CONTAINER ID  IMAGE  PORTS
d98622eaabe5  simple_server:latest  8000/tcp
98d158f82132  simple_server:latest  8000/tcp
9242a969632f  simple_server:latest  8000/tcp

$ docker service ls
ID           NAME          MODE       REPLICAS IMAGE         PORTS
z0z90wgylcpf simple-server replicated 3/3      simple_server *:8000->8000/tcp
```

正如你所看到的，集群将像没有发生任何事情一样反弹回来，这正是容器化如此强大的原因：我们不仅可以在许多机器之间分配处理任务并灵活地扩展吞吐量，而且使用相同的服务，如果一些（希望很少）服务死掉，我们并不会太在意，因为框架会使客户端完全无缝地进行处理。借助 Docker Swarm 的内置服务发现，负载均衡器将把连接转移到任何正在运行/可用的容器，因此任何试图连接到我们服务器的人都不应该看到太大的差异。

# 清理

与我们完成的任何服务一样，我们需要确保清理我们迄今为止使用的任何资源。在 Swarm 的情况下，我们可能应该删除我们的服务并销毁我们的集群，直到我们再次需要它。您可以使用`docker service rm`和`docker swarm leave`来执行这两个操作：

```
$ docker service ls
ID           NAME          MODE       REPLICAS IMAGE         PORTS
z0z90wgylcpf simple-server replicated 3/3      simple_server *:8000->8000/tcp

$ docker service rm simple-server
simple-server

$ docker service ls
ID           NAME          MODE       REPLICAS IMAGE         PORTS

$ docker swarm leave --force
Node left the swarm.
```

我们在这里不得不使用`--force`标志的原因是因为我们是管理节点，也是集群中的最后一个节点，所以默认情况下，Docker 会阻止这个操作。在多节点设置中，通常不需要这个标志。

通过这个操作，我们现在回到了起点，并准备使用一个真正的服务。

# 使用 Swarm 来编排我们的单词服务

在上一章中，我们构建了一个简单的服务，用于添加和列出在表单上输入的单词。但是如果你记得的话，我们在连接服务时大量使用了一些实现细节，如果不是完全地拼凑在一起，那就会变得非常脆弱。有了我们对服务发现的新认识和对 Docker Swarm 编排的理解，我们可以尝试准备好我们的旧代码以进行真正的集群部署，并摆脱我们之前脆弱的设置。

# 应用服务器

从第三章 *服务分解*中复制旧的应用服务器文件夹到一个新文件夹，我们将更改我们的主处理程序代码（`index.js`），因为我们必须适应这样一个事实，即我们将不再是唯一从数据库中读取和写入的实例。

与往常一样，所有代码也可以在[`github.com/sgnn7/deploying_with_docker`](https://github.com/sgnn7/deploying_with_docker)找到。这个特定的实现可以在`chapter_4/clustered_application`中找到。警告！当您开始考虑类似的容器并行运行时，您必须开始特别注意容器控制范围之外可能发生的数据更改。因此，在运行容器中保留或缓存状态通常是灾难和数据不一致的原因。为了避免这个问题，通常情况下，您应该尽量确保在进行任何转换或传递数据之前从上游源（即数据库）重新读取信息，就像我们在这里所做的那样。

# index.js

这个文件基本上与上一章的文件相同，但我们将进行一些更改以消除缓存：

```
'use strict'

const bodyParser = require('body-parser')
const express = require('express');
const mongo = require('mongodb')

const DB_NAME = 'word_database';
const DB_HOST = process.env.DB_HOST || 'localhost:27017';
const COLLECTION_NAME = 'words';
const SERVER_PORT = 8000;

const app = express();
const client = mongo.MongoClient();
const dbUri = `mongodb://${DB_HOST}/${DB_NAME}`;

app.set('view engine', 'pug')
app.use(bodyParser.urlencoded({ extended: false }))

function loadWordsFromDatabase() {
    return client.connect(dbUri).then((db) => {
        return db.collection(COLLECTION_NAME).find({}).toArray();
    })
    .then((docs) => {
        return docs.map(doc => doc.word);
    });
}

app.get('/', (req, res) => {
    console.info("Loading data from database...");
    loadWordsFromDatabase().then(words => {
        console.info("Data loaded, showing the result...");
        res.render('index', { words: words });
    });
});

app.post('/new', (req, res) => {
    const word = req.body.word;

    console.info(`Got word: ${word}`);
    if (word) {
        client.connect(dbUri).then((db) => {
            db.collection(COLLECTION_NAME).insertOne({ word }, () => {
                db.close();
            });
        });
    }

    res.redirect('/');
});

app.listen(SERVER_PORT, () => {
    console.info("Server started on port %d...", SERVER_PORT);
});
```

如果您可能已经注意到，许多事情是相似的，但也有根本性的变化：

+   我们不会在启动时预加载单词，因为列表可能会在服务初始化和用户请求数据之间发生变化。

+   我们在每个`GET`请求中加载保存的单词，以确保我们始终获得新鲜数据。

+   当我们保存单词时，我们只是将其插入到数据库中，并不在应用程序中保留它，因为我们将在`GET`重新显示时获得新数据。

使用这种方法，数据库中的数据由任何应用程序实例进行的更改将立即反映在所有实例中。此外，如果数据库管理员更改了任何数据，我们也将在应用程序中看到这些更改。由于我们的服务还使用环境变量作为数据库主机，我们不应该需要将其更改为支持服务发现。

注意！请注意，因为我们在每个`GET`请求中读取数据库，我们对支持集群的更改并不是免费的，并且会增加数据库查询，这可能会在网络、缓存失效或磁盘传输过度饱和时成为真正的瓶颈。此外，由于我们在显示数据之前读取数据库，后端处理数据库“find（）”的减速将对用户可见，可能导致不良用户体验，因此在开发容器友好型服务时请牢记这些事情。

# Web 服务器

我们的 Web 服务器更改会有点棘手，因为 NGINX 配置处理的一个怪癖/特性可能也会影响到您，如果您使用基于 Java 的 DNS 解析。基本上，NGINX 会缓存 DNS 条目，以至于一旦它读取配置文件，该配置中的任何新的 DNS 解析实际上根本不会发生，除非指定一些额外的标志（`resolver`）。由于 Docker 服务不断可变和可重定位，这是一个严重的问题，必须解决才能在 Swarm 上正常运行。在这里，您有几个选择：

+   并行运行 DNS 转发器（例如`dnsmasq`）和 NGINX，并将其用作解析器。这需要在同一个容器中运行`dnsmasq`和 NGINX。

+   使用`envsubst`从系统中填充 NGINX 配置容器的启动解析器，这需要所有容器在同一个用户定义的网络中。

+   硬编码 DNS 解析器 IP（`127.0.0.11`）：这也需要所有容器在同一个用户定义的网络中。

为了稳健性，我们将使用第二个选项，因此将 Web 服务器从上一章复制到一个新文件夹中，并将其重命名为`nginx_main_site.conf.template`。然后我们将为其添加一个解析器配置和一个名为`$APP_NAME`的变量，用于我们的代理主机端点：

```
server {
  listen         8080;
  server_name    _;  

  resolver $DNS_RESOLVERS;

  root /srv/www/html;

  location ~/\. {
    deny all;
  }

  location / { 
    auth_basic           "Authentication required";
    auth_basic_user_file /srv/www/html/.htpasswd;

    proxy_pass           http://$APP_NAME:8000;
  }
}
```

由于 NGINX 在配置文件中不处理环境变量替换，我们将在其周围编写一个包装脚本。添加一个名为`start_nginx.sh`的新文件，并在其中包含以下内容，以获取主机的解析器并生成新的 main_site 配置：

```
#!/bin/bash -e

export DNS_RESOLVERS=$(cat /etc/resolv.conf | grep 'nameserver' | awk '{ print $2 }' | xargs echo)

cat /etc/nginx/conf.d/nginx_main_site.conf.template | envsubst '$DNS_RESOLVERS $APP_NAME' > /etc/nginx/conf.d/nginx_main_site.conf

nginx -g 'daemon off;'
```

为了使其运行，我们最终需要确保我们使用此脚本启动 NGINX，而不是内置的脚本，因此我们还需要修改我们的`Dockerfile`。

打开我们的 Dockerfile，并确保它具有以下内容：

```
FROM nginx:latest

RUN apt-get update -q && \
    apt-get dist-upgrade -y && \
    apt-get install openssl && \
    apt-get clean && \
    apt-get autoclean

EXPOSE 8080

ENV SRV_PATH /srv/www/html

ARG PASSWORD=test

RUN rm /etc/nginx/conf.d/default.conf

COPY start_nginx.sh /usr/local/bin/

RUN mkdir -p $SRV_PATH && \
    chown nginx:nginx $SRV_PATH && \
    printf "user:$(openssl passwd -crypt $PASSWORD)\n" >> $SRV_PATH/.htpasswd && \
    chmod +x /usr/local/bin/start_nginx.sh

COPY nginx_main_site.conf.template /etc/nginx/conf.d/

CMD ["/usr/local/bin/start_nginx.sh"]
```

在这里，主要的变化是启动脚本`CMD`的覆盖，并将配置转换为模板，其余基本保持不变。

# 数据库

与其他两个容器不同，由于一系列原因，我们将数据库留在一个容器中：

+   MongoDB 可以通过垂直扩展轻松扩展到高 GB/低 TB 数据集大小。

+   数据库极其难以扩展，如果没有对卷的深入了解（在下一章中介绍）。

+   数据库的分片和副本集通常足够复杂，以至于整本书都可以专门写在这个主题上。

我们可能会在以后的章节中涵盖这个主题，但在这里，这会让我们偏离我们学习如何部署服务的一般目标，所以现在我们只有我们在上一章中使用的单个数据库实例。

# 部署所有

就像我们为简单的 Web 服务器所做的那样，我们将开始创建另一个 Swarm 集群：

```
$ docker swarm init
Swarm initialized: current node (1y1h7rgpxbsfqryvrxa04rvcp) is now a manager.

To add a worker to this swarm, run the following command:

 docker swarm join \
 --token SWMTKN-1-36flmf9vnika6x5mbxx7vf9kldqaw6bq8lxtkeyaj4r5s461ln-aiqlw49iufv3s6po4z2fytos1 \
 192.168.4.128:2377
```

然后，我们需要为服务发现主机名解析创建覆盖网络才能工作。您不需要了解太多关于这个，除了它创建了一个隔离的网络，我们将把所有服务添加到其中：

```
$ docker network create --driver overlay service_network
44cyg4vsitbx81p208vslp0rx
```

最后，我们将构建和启动我们的容器：

```
$ cd ../database
$ docker build . -t local_database
$ docker service create -d --replicas 1 \
 --name local-database \
 --network service_network \
 --mount type=volume,source=database_volume,destination=/data/db \
                           local_database
<snip>
pilssv8du68rg0oztm6gdsqse

$ cd ../application_server
$ docker build -t application_server .
$ docker service create -d -e DB_HOST=local-database \
 --replicas 3 \
 --network service_network \
 --name application-server \
 application_server
<snip>
pue2ant1lg2u8ejocbsovsxy3

$ cd ../web_server
$ docker build -t web_server .
$ docker service create -d --name web-server \
 --network service_network \
 --replicas 3 \
 -e APP_NAME=application-server \
 -p 8080:8080 \
 web_server
<snip>
swi95q7z38i2wepmdzoiuudv7

$ # Sanity checks
$ docker service ls
ID           NAME               MODE       REPLICAS IMAGE                PORTS
pilssv8du68r local-database     replicated 1/1      local_database 
pue2ant1lg2u application-server replicated 3/3      application_server
swi95q7z38i2 web-server         replicated 3/3      web_server            *:8080->8080/tcp

$ docker ps --format 'table {{.ID}}  {{.Image}}\t  {{.Ports}}'
CONTAINER ID  IMAGE                         PORTS
8cdbec233de7  application_server:latest     8000/tcp
372c0b3195cd  application_server:latest     8000/tcp
6be2d6e9ce77  web_server:latest             80/tcp, 8080/tcp
7aca0c1564f0  web_server:latest             80/tcp, 8080/tcp
3d621c697ed0  web_server:latest             80/tcp, 8080/tcp
d3dad64c4837  application_server:latest     8000/tcp
aab4b2e62952  local_database:latest         27017/tcp 
```

如果您在启动这些服务时遇到问题，可以使用`docker service logs <service_name>`来查看日志，以找出出了什么问题。如果特定容器出现问题，还可以使用`docker logs <container_id>`。

有了这些，我们现在可以检查我们的代码是否在`http://127.0.0.1:8080`上工作（用户名：`user`，密码：`test`）：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/aa5b1c35-7269-44d6-85cf-1858566d42d6.png)**

看起来它正在工作！一旦我们输入凭据，我们应该被重定向到主应用程序页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/996362dd-b32a-47dd-a7aa-06d28749de5e.png)

如果我们输入一些单词，数据库是否能工作？

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/03ad27dd-0617-426d-9359-8ba8653640c5.png)

确实！我们真的创建了一个支持 Swarm 的 1 节点服务，并且它是可扩展的加负载平衡的！

# Docker 堆栈

就像从前面几段文字中很明显的那样，手动设置这些服务似乎有点麻烦，所以在这里我们介绍一个新工具，可以帮助我们更轻松地完成这项工作：Docker Stack。这个工具使用一个 YAML 文件来轻松和重复地部署所有服务。

在尝试使用 Docker 堆栈配置之前，我们将清理旧的练习：

```
$ docker service ls -q | xargs docker service rm
pilssv8du68r
pue2ant1lg2u
swi95q7z38i2

$ docker network rm service_network
service_network
```

现在我们可以编写我们的 YAML 配置文件--您可以很容易地注意到 CLI 与此配置文件之间的相似之处：

您可以通过访问[`docs.docker.com/docker-cloud/apps/stack-yaml-reference/`](https://docs.docker.com/docker-cloud/apps/stack-yaml-reference)找到有关 Docker 堆栈 YAML 文件中所有可用选项的更多信息。通常，您可以使用 CLI 命令设置的任何内容，也可以在 YAML 配置中执行相同的操作。

```
version: "3"
services:
 local-database:
 image: local_database
 networks:
 - service_network
 deploy:
 replicas: 1
 restart_policy:
 condition: on-failure
 volumes:
 - database_volume:/data/db 
 application-server:
 image: application_server
 networks:
 - service_network
 depends_on:
 - local-database
 environment:
 - DB_HOST=local-database
 deploy:
 replicas: 3
 restart_policy:
 condition: on-failure 
 web-server:
 image: web_server
 networks:
 - service_network
 ports:
 - 8080:8080
 depends_on:
 - application-server
 environment:
 - APP_NAME=application-server
 deploy:
 replicas: 3
 restart_policy:
 condition: on-failure

networks:
 service_network:

volumes:
 database_volume:
```

启动我们的堆栈怎么样？这也很容易！堆栈几乎与`docker services`具有相同的命令：

```
$ docker stack deploy --compose-file swarm_application.yml swarm_test
Creating network swarm_test_service_network
Creating service swarm_test_local-database
Creating service swarm_test_application-server
Creating service swarm_test_web-server

$ # Sanity checks
$ docker stack ls
NAME        SERVICES
swarm_test  3

$ docker stack services swarm_test
ID           NAME                          MODE       REPLICAS            IMAGE                PORTS
n5qnthc6031k swarm_test_application-server replicated 3/3                 application_server 
v9ho17uniwc4 swarm_test_web-server         replicated 3/3                 web_server           *:8080->8080/tcp
vu06jxakqn6o swarm_test_local-database     replicated 1/1                 local_database

$ docker ps --format 'table {{.ID}}  {{.Image}}\t  {{.Ports}}'
CONTAINER ID  IMAGE                         PORTS
afb936897b0d  application_server:latest     8000/tcp
d9c6bab2453a  web_server:latest             80/tcp, 8080/tcp
5e6591ee608b  web_server:latest             80/tcp, 8080/tcp
c8a8dc620023  web_server:latest             80/tcp, 8080/tcp
5db03c196fda  application_server:latest     8000/tcp
d2bf613ecae0  application_server:latest     8000/tcp
369c86b73ae1  local_database:latest         27017/tcp
```

如果您再次在浏览器中输入`http://127.0.0.1:8080`，您会发现我们的应用程序就像以前一样工作！我们已经成功地使用 Docker Swarm 集群上的单个文件部署了整个集群的镜像！

# 清理

我们不会留下无用的服务，所以我们将删除我们的堆栈并停止我们的 Swarm 集群，为下一章做准备：

```
$ docker stack rm swarm_test
Removing service swarm_test_application-server
Removing service swarm_test_web-server
Removing service swarm_test_local-database
Removing network swarm_test_service_network

$ docker swarm leave --force
Node left the swarm.
```

我们不需要清理网络或运行的容器，因为一旦我们的堆栈消失，Docker 会自动将它们删除。完成这部分后，我们现在可以以全新的状态进入下一章关于卷。

# 总结

在本章中，我们涵盖了许多内容，比如：什么是服务发现以及为什么我们需要它，容器编排的基础知识和状态协调原则，以及编排世界中的一些主要参与者。有了这些知识，我们继续使用 Docker Swarm 实现了单节点完整集群，以展示类似这样的工作如何完成，最后我们使用 Docker stack 来管理一组服务，希望向您展示如何将理论转化为实践。

在下一章中，我们将开始探索 Docker 卷和数据持久性的复杂世界，所以请继续关注。
