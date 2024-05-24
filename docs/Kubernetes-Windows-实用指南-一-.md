# Kubernetes Windows 实用指南（一）

> 原文：[`zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673`](https://zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

从版本 1.14 开始，Kubernetes 带来了 2019 年最受期待的功能：对 Windows Server 容器工作负载的生产级支持。这是一个巨大的里程碑，使得所有严重依赖 Windows 技术的企业能够迁移到云原生技术。开发人员和系统运营商现在可以利用相同的工具和流水线来部署 Windows 和 Linux 工作负载，以类似的方式扩展它们，并进行高效的监控。从商业角度来看，Windows 容器的采用意味着比普通虚拟机更低的运营成本和更好的硬件利用率。

你手中拿着一本书，将指导你如何在 Microsoft Windows 生态系统中使用 Kubernetes 和 Docker 容器 - 它涵盖了混合 Windows/Linux Kubernetes 集群部署，并使用 Windows 客户端机器处理集群操作。由于 Windows 在 Kubernetes 中的支持是一个相当新的概念，你可以期待官方文档和指南仍然很少。在这本书中，我们的目标是系统化你关于涉及 Windows 的 Kubernetes 场景的知识。我们的目标是创建 Kubernetes 在 Windows 上的终极指南。

# 这本书适合谁

这本书的主要受众是需要将 Windows 容器工作负载整合到他们的 Kubernetes 集群中的 Kubernetes DevOps 架构师和工程师。如果你是 Windows 应用程序（特别是.NET Framework）开发人员，而且你还没有使用过 Kubernetes，这本书也适合你！除了关于部署混合 Windows/Linux Kubernetes 集群的策略，我们还涵盖了 Kubernetes 背后的基本概念以及它们如何映射到 Windows 环境。如果你有兴趣将现有的.NET Framework 应用程序迁移到在 Kubernetes 上运行的 Windows Server 容器，你肯定会找到如何解决这个问题的指导。

# 这本书涵盖了什么

第一章，*创建容器*，描述了目前在 Linux 和 Windows 操作系统中使用的不同容器类型。本章的主要目标是演示如何构建一个示例 Windows 容器，运行它，并执行基本操作。

第二章《在容器中管理状态》讨论了管理和持久化容器化应用程序状态的可能方法，并解释了如何在容器上挂载本地和云存储卷（Azure Files SMB 共享），以便在 Windows 容器上运行像 MongoDB 这样的集群数据库引擎。

第三章《使用容器镜像》专注于容器镜像，这是分发容器化应用程序的标准方式。本章的目标是演示如何使用 Docker Hub 和 Azure 容器注册表，以及如何在部署流水线中安全地交付容器镜像。

第四章《Kubernetes 概念和 Windows 支持》使您熟悉了核心 Kubernetes 服务，如 kubelet、kube-proxy 和 kube-apiserver，以及最常用的 Kubernetes 对象，如 Pod、Service、Deployment 和 DaemonSet。您将了解为什么 Kubernetes 中的 Windows 支持很重要，以及当前关于 Windows 容器和 Windows 节点的限制是什么。我们还将重点放在为不同用例创建简单的开发 Kubernetes 集群上。

第五章《Kubernetes 网络》描述了 Kubernetes 的网络模型和可用的 Pod 网络解决方案。您将学习如何为具有 Windows 节点的 Kubernetes 集群选择最合适的网络模式。

第六章《与 Kubernetes 集群交互》展示了如何从 Windows 机器使用 kubectl 与 Kubernetes 集群进行交互和访问。例如，我们将展示如何与本地开发集群一起工作，以及最常见和有用的 kubectl 命令是什么。

第七章《部署混合本地 Kubernetes 集群》演示了如何处理虚拟机的供应和部署混合的 Windows/Linux Kubernetes 集群，其中包括 Linux 主节点/节点和 Windows 节点。本地部署是最通用的部署类型，因为它可以使用任何云服务提供商或私人数据中心进行。

第八章《部署混合 Azure Kubernetes 服务引擎集群》概述了如何使用 AKS Engine 部署混合 Windows/Linux Kubernetes 集群的方法，并演示了一个示例部署一个 Microsoft IIS 应用程序。

第九章《部署您的第一个应用程序》演示了如何将一个简单的 Web 应用程序以命令式和声明式的方式部署到 Kubernetes，并讨论了管理在 Kubernetes 中运行的应用程序的推荐方式。我们还将介绍如何专门在 Windows 节点上调度 Pod，并如何扩展在 Kubernetes 上运行的 Windows 应用程序。

第十章《部署 Microsoft SQL Server 2019 和 ASP.NET MVC 应用程序》描述了如何将在 Windows 容器中运行的 ASP.NET MVC 实现的样本投票应用程序部署到 AKS Engine 集群，以及 Microsoft SQL Server 2019（在 Linux 容器中运行）。您还将了解如何使用 Visual Studio 远程调试器调试在 Kubernetes 中运行的.NET 应用程序。

第十一章《配置应用程序使用 Kubernetes 功能》描述了如何实现和配置 Kubernetes 的更高级功能，包括命名空间、ConfigMaps 和 Secrets、持久存储、健康和就绪检查、自动缩放和滚动部署。本章还展示了 Kubernetes 中的基于角色的访问控制（RBAC）的工作原理。

第十二章《Kubernetes 的开发工作流程》展示了如何将 Kubernetes 作为微服务开发的平台。您将学习如何使用 Helm 打包应用程序，以及如何使用 Azure Dev Spaces 改进开发体验。此外，本章还描述了如何在 Kubernetes 中运行的容器化应用程序中使用 Azure 应用程序洞察和快照调试器。

第十三章《保护 Kubernetes 集群和应用程序》涵盖了 Kubernetes 集群和容器化应用程序的安全性。我们将讨论 Kubernetes 的一般推荐安全实践以及 Windows 特定的考虑因素。

第十四章《使用 Prometheus 监控 Kubernetes 应用程序》着重于如何监控 Kubernetes 集群，特别是运行在 Windows 节点上的.NET 应用程序。您将学习如何使用 Prometheus Helm 图表部署完整的监控解决方案，以及如何配置它来监控您的应用程序。

第十五章《灾难恢复》讨论了备份 Kubernetes 集群和灾难恢复策略。主要重点是展示哪些组件需要备份以安全恢复集群，以及如何自动化这个过程。

第十六章《运行 Kubernetes 的生产考虑因素》是针对在生产环境中运行 Kubernetes 的一些建议性建议。

# 为了充分利用本书

建议具有一些关于 Docker 和 Kubernetes 的一般知识，但不是必需的。我们将在专门的章节中涵盖 Windows 上容器化和 Kubernetes 本身的基本概念。对于那些专注于将 Windows 应用程序部署到 Kubernetes 的章节，建议您具有.NET Framework，C#和 ASP.NET MVC 的基本经验。请注意，本书中每个指南和示例都有官方 GitHub 存储库中的对应物：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows)

在整本书中，您将需要自己的 Azure 订阅。您可以在这里阅读有关如何获取个人使用的有限免费帐户的更多信息：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

| **本书涵盖的软件/硬件** | **操作系统要求** |
| --- | --- |
| Visual Studio Code，Docker Desktop，Kubectl，带 16 GB RAM 的 Azure CLI | Windows 10 Pro，企业版或教育版（1903 版或更高版本；64 位），Windows Server 2019，Ubuntu Server 18.04 |

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)注册，将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

一旦文件下载完成，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码捆绑包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码捆绑包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838821562_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781838821562_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体显示：

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

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一部分：创建和使用容器

本节的目标是介绍不同的容器化技术以及选择一种变体而不是另一种的好处。您将了解如何在 Windows 上对应用程序进行容器化，并了解创建和维护图像涉及的关键步骤。

本节包括以下章节：

+   第一章，*创建容器*

+   第二章，*在容器中管理状态*

+   第三章，*使用容器图像*


# 第一章：创建容器

*容器*和*操作系统级虚拟化*的概念源自 Unix V7 操作系统（OS）中的`chroot`系统调用，可以追溯到 20 世纪 70 年代末。从最初的进程隔离和*chroot 监狱*的简单概念开始，容器化经历了快速发展，并在 2010 年代成为主流技术，随着**Linux 容器**（**LXC**）和 Docker 的出现。2014 年，微软宣布在即将发布的 Windows Server 2016 中支持 Docker Engine。这是 Windows 容器和 Windows 上的 Kubernetes 故事的开始。

在本章中，我们将通过突出 Windows 操作系统上容器化与 Linux 上的重要区别以及 Windows 上的容器运行时类型，即 Windows Server 容器（或进程隔离）和 Hyper-V 隔离，为您提供更好的理解。我们还将学习如何为 Windows 10 安装 Docker Desktop 以进行开发，并在您的计算机上运行我们的第一个示例容器。

本章将涵盖以下主题：

+   Linux 与 Windows 容器

+   了解 Windows 容器变体

+   安装 Windows 工具的 Docker Desktop

+   构建您的第一个容器

# 技术要求

本章的要求如下：

+   在 BIOS 中启用**Intel 虚拟化技术**（**Intel VT**）或**AMD 虚拟化**（**AMD-V**）技术功能

+   至少 4GB 的 RAM

+   已安装 Windows 10 Pro、企业版或教育版（1903 版本或更高版本，64 位）

+   Visual Studio Code

有关在 Windows 上运行 Docker 和容器的硬件要求的更多信息，请参阅[`docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements)。

支持从周年更新（版本 1607，构建 14393）开始的 Windows 10 版本，但建议使用版本 1903 以获得最佳体验，因为它具备所有必要的功能。有关 Windows 10 版本和容器运行时兼容性的更多详细信息，请参阅[`docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility)。

可以免费从官方网页下载 Visual Studio Code：[`code.visualstudio.com/`](https://code.visualstudio.com/)。

您可以从本书的官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter01`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter01)。

# Linux 与 Windows 容器

Linux 和 Windows 上的容器化都旨在实现相同的目标 - 创建可预测且轻量的环境，与其他应用程序隔离。对于 Linux，容器使用的一个经典示例可以是运行使用 Flask 编写的 Python RESTful API，而不必担心与其他应用程序所需的 Python 模块之间的冲突。同样，对于 Windows，容器可以用于托管完全与同一台机器上运行的其他工作负载隔离的 Internet Information Services (IIS) web 服务器。

与传统的硬件虚拟化相比，容器化的代价是与主机操作系统紧密耦合，因为它使用相同的内核来提供多个隔离的用户空间。这意味着在 Linux 操作系统上运行 Windows 容器，或者在 Windows 操作系统上运行 Linux 容器，不可能在没有传统硬件虚拟化技术的额外帮助下本地实现。

在本书中，我们将专注于 Docker 容器平台，这是在 Windows 上运行容器所必需的。现在，让我们总结 Docker Engine 提供的 Linux 和 Windows 上容器化支持的当前状态，以及在开发和生产场景中可能的解决方案。

# Linux 上的 Docker 容器化

最初，Docker Engine 主要是为 Linux 操作系统开发的，它为 Docker 运行时提供了以下内核特性：

+   **内核命名空间**：这是容器的核心概念，它使得创建隔离的进程工作空间成为可能。命名空间分割内核资源（比如网络堆栈、挂载点等），这样每个进程工作空间可以访问自己的一组资源，并确保它们不能被其他工作空间的进程访问。这就是确保容器隔离的方式。

+   **控制组**：资源使用限制和隔离是容器化的次要核心概念。在 Linux 上，这个特性由*cgroups*提供，它使得资源限制（CPU 使用率、RAM 使用率等）和优先访问资源对于一个进程或一组进程来说成为可能。

+   **分层文件系统功能**：在 Linux 上，*UnionFS*是*联合挂载*的许多实现之一——这是一个文件系统服务，允许来自不同文件系统的文件和目录被统一到一个透明、一致的文件系统中。这个特性对于由不可变层组成的 Docker 容器镜像至关重要。在容器运行时，只读层会被透明地叠加在一起，与可写的容器层一起。

Docker Engine 负责为容器提供基本运行时，抽象容器管理，并使用 REST API 向客户端层暴露功能，比如 Docker CLI。Docker 在 Linux 上的架构可以用以下图表总结：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/12ce9141-1d04-4fef-9cc4-7b3b1d47db00.png)

从 Linux 操作系统的角度来看，容器运行时架构如下图所示。这个架构适用于 Linux 上的容器引擎，不仅仅是 Docker。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e181dd7d-46c2-49cb-a919-eaaca097d285.png)

接下来，我们将看一下 Windows 上的 Docker 容器化。

# 在 Windows 上的 Docker 容器化

2014 年，当微软宣布在即将发布的 Windows Server 2016 中支持 Docker Engine 时，Docker 容器引擎在 Linux 上已经成熟，并被证明是容器管理的行业标准。这个事实推动了 Docker 和 Windows 容器化支持的设计决策，最终为运行进程隔离的 Windows Server 容器提供了类似的架构。Docker Engine 使用的 Windows 内核功能大致映射如下：

+   **内核命名空间**：这个功能是由 Windows 内核中的对象命名空间和进程表等提供的。

+   控制组：Windows 有自己的*作业对象*概念，允许一组进程作为单个单元进行管理。基本上，这个功能提供了类似于 Linux 上的*cgroups*的功能。

+   层文件系统功能：*Windows 容器隔离文件系统*是一个文件系统驱动程序，为在 Windows 容器中执行的进程提供虚拟文件系统视图。这类似于 Linux 操作系统上的*UnionFS*或其他*联合挂载*的实现。

在这些低级功能之上，服务层由一个**主机计算服务**（**HCS**）和一个**主机网络服务**（**HNS**）组成，为使用 C#和 Go（hcsshim）提供了运行和管理容器的公共接口。有关当前容器平台工具的更多信息，请参阅官方文档：[`docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/containerd#hcs`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/containerd#hcs)。

重要的是要知道，Windows 容器有两种类型：进程隔离和 Hyper-V 隔离。它们之间的区别将在下一节中解释 - 隔离是容器的运行时属性，您可以期望它们在一般情况下表现类似，并且只在安全性和兼容性方面有所不同。

以下图表总结了容器化架构和 Docker 对 Windows 的支持：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/b221e9d5-36dd-4b7f-bea7-cdc89fabafda.png)

为了与 Linux 上容器化的高级架构进行比较，以下图表展示了 Windows 的多容器运行时架构。在这一点上，我们只考虑*进程隔离的 Windows Server 容器*，它们与 Linux 上的容器非常相似，但在下一节中，我们还将介绍 Windows 上容器的*Hyper-V 隔离*架构：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/d7a93b95-2174-4e8e-89e5-47bd79cab5c1.png)

接下来，让我们看一下 Linux 和 Windows 上容器的一些区别。

# Linux 和 Windows 上容器之间的关键区别

Linux 和 Windows 上的 Docker 容器在原则上旨在解决相同的问题，目前，容器管理体验开始在这些平台上趋于一致。然而，如果您来自 Linux 生态系统，并且在那里广泛使用了 Docker，您可能会对一些不同感到惊讶。让我们简要总结一下。

最大且最明显的限制是 Windows 主机操作系统和 Windows 容器操作系统的兼容性要求。在 Linux 的情况下，您可以安全地假设，如果主机操作系统内核运行的是最低要求版本 3.10，那么任何 Linux 容器都将无需任何问题地运行，无论它基于哪个发行版。对于 Windows 来说，可以运行具有与受支持的主机操作系统版本完全相同的基础操作系统版本的容器，而不受任何限制。在旧的主机操作系统上运行更新的容器操作系统版本是不受支持的，而且更重要的是，在更新的主机操作系统上运行旧的容器操作系统版本需要使用*Hyper-V 隔离*。例如，运行 Windows Server 版本 1803 构建 17134 的主机可以原生地使用具有基础镜像版本 Windows Server 版本 1803 构建 17134 的容器，但在需要使用 Hyper-V 隔离的情况下，运行具有 Windows Server 版本 1709 构建 16299 的容器，并且根本无法启动具有 Windows Server 2019 构建 17763 的容器。以下表格可视化了这一原则：

| **主机操作系统版本** | **容器基础镜像操作系统版本** | **兼容性** |
| --- | --- | --- |
| Windows Server，版本 1803 构建 17134 | Windows Server，版本 1803 构建 17134 | *进程*或*Hyper-V*隔离 |
| Windows Server，版本 1803 构建 17134 | Windows Server，版本 1709 构建 16299 | *Hyper-V*隔离 |
| Windows Server，版本 1803 构建 17134 | Windows Server 2019 构建 17763 | 不支持 |
| Windows Server 2019 构建 17763 | Windows Server 2019 构建 17763 | *进程*或*Hyper-V*隔离 |

有关更详细的兼容性矩阵，请参阅官方微软文档：[`docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility#choose-which-container-os-version-to-use`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility#choose-which-container-os-version-to-use)。

值得一提的是，Hyper-V 隔离的要求可能是云环境或在虚拟机上运行 Docker 时的一个重要限制。在这种情况下，Hyper-V 隔离需要由 hypervisor 启用嵌套虚拟化功能。我们将在下一节详细介绍 Hyper-V 隔离。

在 Linux 和 Windows 容器的基本图像之间的大小差异是你可能注意到的另一个重要方面。目前，最小的 Windows Server 图像`mcr.microsoft.com/windows/nanoserver:1809`大小为 98 MB，而例如，Alpine Linux 的最小图像`alpine:3.7`只有 5 MB。完整的 Windows Server 图像`mcr.microsoft.com/windows/servercore:ltsc2019`超过 1.5 GB，而 Windows 的基本图像`mcr.microsoft.com/windows:1809`为 3.5 GB。但值得一提的是，自 Windows Server 2016 Core 图像首次发布时，图像大小为 6 GB，这些数字不断下降。

这些差异更多地可以看作是 Windows 上 Docker 容器的限制。然而，有一个方面是 Windows 比 Linux 提供更多灵活性的地方 - 支持在 Windows 上运行 Linux 容器。Windows 10 的 Docker Desktop 支持这样的场景。尽管这个功能仍在开发中，但在 Windows 10 上使用 Hyper-V 隔离可以同时托管 Linux 容器和 Windows 容器。我们将在下一节更详细地介绍这个功能。而在 Linux 上运行 Windows 容器的相反情况没有本地解决方案，需要在 Linux 主机上手动托管额外的 Windows 虚拟机。

Windows Server 也支持运行 Linux 容器，前提是启用了**Linux 容器在 Windows 上**（**LCOW**）实验性功能。

在下一节中，我们将重点关注不同 Windows 容器运行时变体之间的差异。

# 理解 Windows 容器的变体

Windows 容器有两种不同的隔离级别：进程和 Hyper-V。进程隔离也被称为**Windows Server 容器**（**WSC**）。最初，进程隔离仅适用于 Windows Server 操作系统，而在 Windows 桌面版本上，您可以使用 Hyper-V 隔离运行容器。从 Windows 10 的 1809 版本（2018 年 10 月更新）和 Docker Engine 18.09.1 开始，进程隔离也适用于 Windows 10。

在官方文档中，您可能会发现 Windows 容器*类型*和*运行时*这些术语。它们也指的是隔离级别，这些术语可以互换使用。

现在，让我们来看看这些隔离级别的区别，它们的用例是什么，以及如何通过指定所需的隔离类型来创建容器。

# 进程隔离

进程隔离容器，也称为**WSC**，是 Windows Server 上容器的默认隔离模式。进程隔离的架构类似于在 Linux OS 上运行容器时的架构：

+   容器使用相同的共享内核。

+   隔离是在内核级别提供的，使用诸如进程表、对象命名空间和作业对象等功能。更多信息可以在*Windows 上的 Docker 容器化*部分找到。

这在以下图表中总结如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/ed754824-a094-4e79-9460-c38f088f9fc8.png)

进程隔离为容器提供了轻量级的运行时（与 Hyper-V 隔离相比），并提供了更高的部署密度、更好的性能和更低的启动时间。然而，在使用这种类型的隔离时，有一些要考虑的要点：

+   Docker 容器基础镜像必须与容器主机操作系统的版本匹配。例如，如果您正在运行 Windows 10，1903 版本，您只能运行使用 Windows 10 或 Windows Server 1903 版本基础镜像的容器。这意味着您必须为每个发布的 Windows 版本重新构建镜像（仅适用于主要*功能更新*）。

+   这应该只用于执行受信任的代码。为了执行不受信任的代码，建议使用 Hyper-V 隔离。

使用 Windows 10，1809 版本及更高版本，可以在容器运行时使用进程隔离，前提是您正在运行 Docker Desktop for Windows 2.0.1.0 *(Edge*发布渠道)或更高版本和 Docker Engine 18.09.1+。对于 Windows 10，容器的默认隔离级别是 Hyper-V，为了使用进程隔离，必须在使用`--isolation=process`参数创建容器时明确指定：

```
docker run -d --isolation=process mcr.microsoft.com/windows/nanoserver:1903 cmd /c ping localhost -n 100
```

此选项也可以作为参数指定给 Docker 守护程序，使用`--exec-opt`参数。有关更多详细信息，请参阅官方 Docker 文档：[`docs.docker.com/engine/reference/commandline/run/#specify-isolation-technology-for-container---isolation`](https://docs.docker.com/engine/reference/commandline/run/#specify-isolation-technology-for-container---isolation)。

在 Windows 10 操作系统上使用进程隔离容器仅建议用于开发目的。对于生产部署，您仍应考虑使用 Windows Server 进行进程隔离容器。

# Hyper-V 隔离

Hyper-V 隔离是 Windows 容器的第二种隔离类型。在这种隔离类型中，每个容器都在一个专用的、最小的 Hyper-V 虚拟机中运行，可以简要总结如下：

+   容器不与主机操作系统共享内核。每个容器都有自己的 Windows 内核。

+   隔离是在虚拟机 hypervisor 级别提供的（需要安装 Hyper-V 角色）。

+   主机操作系统版本和容器基础操作系统版本之间没有兼容性限制。

+   这是推荐用于执行不受信任的代码和多租户部署，因为它提供了更好的安全性和隔离性。

Hyper-V 隔离的详细架构可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/7c9b01c7-0631-4b19-8cc5-ba2ec27c0135.png)

在选择隔离级别时，这种隔离类型会带来一些成本：

+   与进程隔离相比，Hyper-V 隔离涉及虚拟化开销、更高的内存和 CPU 使用量，但仍然比在 Windows Nano Server 上运行完整虚拟机提供更好的性能。您可以在以下表格中查看使用不同隔离级别运行容器的内存要求。

+   与进程隔离相比，容器的启动时间较慢。

+   在虚拟机上运行容器时需要嵌套虚拟化。这可能是一些虚拟化程序和云部署的限制。以下表格显示了 Windows Server 1709 容器的内存要求：

| **容器基础镜像** | **进程隔离（WSC）** | **Hyper-V 隔离** |
| --- | --- | --- |
| Nano Server | 30 MB | 110 MB + 1 GB 页面文件 |
| Server Core | 45 MB | 360 MB + 1 GB 页面文件 |

与进程隔离相比，容器镜像保持不变；在创建实际容器时，只需要指定不同的隔离级别。您可以使用`--isolation=hyperv`参数来实现这一点：

```
docker run -d --isolation=hyperv mcr.microsoft.com/windows/nanoserver:1809 cmd /c ping localhost -n 100
```

请注意，在这种情况下，即使您使用的是 Windows 10 的 1903 版本，也可以使用 1809 版的容器基础镜像而没有任何限制。

在 Windows 10 上运行容器时，Hyper-V 隔离是默认的隔离级别，因此不需要`--isolation=hyperv`参数。反之亦然；进程隔离是 Windows Server 的默认级别，如果要使用 Hyper-V 隔离，必须明确指定。可以通过在`daemon.json`配置文件中指定`exec-opts`中的`isolation`参数来更改默认隔离级别。有关更多信息，请参阅[`docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file`](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file)和[`docs.docker.com/engine/reference/commandline/dockerd/#docker-runtime-execution-options`](https://docs.docker.com/engine/reference/commandline/dockerd/#docker-runtime-execution-options)。

# Windows 上的 Linux 容器

2017 年 4 月，Docker 宣布推出 LinuxKit，这是一个在不带 Linux 内核的平台上运行 Linux 容器的解决方案，即 Windows 和 macOS。LinuxKit 是一个用于构建便携和轻量级 Linux 子系统的工具包，其中只包含在特定平台上运行 Linux 容器所需的最低限度。尽管自 2016 年首次发布以来，Docker 能够在 Windows 上以有限的程度运行 Linux 容器，但 LinuxKit 的宣布是开始今天我们所知的**Windows 上的 Linux 容器**（**LCOW**）故事的里程碑。

在生产部署中，不建议在 Windows 上运行 Linux 容器。使用 LinuxKit 和 MobyLinuxVM 仅适用于 Windows 桌面和开发目的。与此同时，LCOW 功能仍处于实验阶段，不适合生产环境使用。

# LinuxKit 和 MobyLinuxVM

Docker for Windows（当时 Docker Desktop for Windows 的初始名称）最终配备了基于 LinuxKit 的专用 Hyper-V 虚拟机，名为 MobyLinuxVM。这个虚拟机的目的是为 Linux 容器提供一个最小的运行时，从技术上讲可以与 Windows 容器并存。

默认情况下，Docker Desktop for Windows 以 Linux 容器模式运行，使用 MobyLinuxVM。要切换到 Windows 容器模式，必须转到 Docker Desktop 托盘图标，选择切换到 Windows 容器.... Docker 将重新启动并切换到本机 Windows 容器。

在这个解决方案中，MobyLinuxVM 运行自己的 Docker 守护程序，技术上充当一个封装在虚拟机内部的独立容器主机。同样，Windows 有自己的 Docker 守护程序，负责 Windows 容器，并提供 Docker 客户端（CLI），可以与两个 Docker 守护程序通信。这个架构可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/39eeaca8-5c69-4af0-b95f-31be59238f17.png)

现在，让我们来看一个更为现代的在 Windows 上运行 Linux 容器的方法：LinuxKit LCOW。

# LinuxKit LCOW 和 Hyper-V 隔离

与 MobyLinuxVM 方法相反，**Windows 上的 Linux 容器**（**LCOW**）使用 Hyper-V 隔离容器来实现类似的结果。LCOW 适用于 Windows 10，配备 Docker for Windows 17.10，并适用于 Windows Server 1709 版本，配备 Docker 企业版的预览版本。

与 MobyLinuxVM 相比的主要区别是可以使用*相同的* Docker 守护程序本地运行 Linux 和 Windows 容器。这个解决方案是支持在 Windows 上运行 Linux 容器的当前策略，但作为长期解决方案，在 2019 年 6 月，Docker 和微软开始合作，将 Windows 子系统版本 2 集成为 Windows 上的主要 Linux 容器运行时。最终，LinuxKit LCOW 和带有 Docker Desktop for Windows 的 MobyLinuxVM 将被淘汰。

下图显示了 LCOW：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/706e2bf5-3e4c-4551-ad13-8dc009f14563.png)

要在 Docker Desktop（18.02 版本或更高版本）中启用 LCOW 支持，必须在 Docker 设置>*守护程序中启用实验性功能选项。创建 LCOW 容器需要指定`--platform linux`参数（如果平台选择是明确的，即镜像只存在于 Linux 中，则在较新版本的 Docker Desktop 中可以省略）：

```
docker run -it --platform linux busybox /bin/sh
```

上述命令将创建一个 busybox Linux 容器，并进入交互式 Bourne shell（sh）。

截至 Docker Desktop for Windows 2.0.4.0 版本，启用 LCOW 功能后，无法运行 Docker 提供的开发 Kubernetes 集群（“一应俱全”）。

在这一部分，您了解了容器目前在 Windows 平台上的支持情况以及所提供运行时之间的关键区别。现在，我们可以开始安装**Windows 的 Docker 桌面**。

# 安装 Windows 的 Docker 桌面工具

在 Windows 上创建 Kubernetes 应用程序需要一个用于开发和测试 Docker 容器的环境。在本节中，您将学习如何安装 Windows 的 Docker 桌面，这是开发、构建、交付和在 Windows 10 上运行 Linux 和 Windows 容器的推荐工具环境。首先，让我们在继续安装过程之前回顾一下先决条件和 Docker 的最低要求：

+   至少 4GB 的 RAM。

+   在 BIOS 中启用**Intel 虚拟化技术** (**Intel VT**)或**AMD 虚拟化** (**AMD-V**)技术。请注意，如果您将 VM 用作开发机器，Windows 的 Docker 桌面不保证支持嵌套虚拟化。如果您想了解更多关于这种情况的信息，请参考[`docs.docker.com/docker-for-windows/troubleshoot/#running-docker-desktop-for-windows-in-nested-virtualization-scenarios`](https://docs.docker.com/docker-for-windows/troubleshoot/#running-docker-desktop-for-windows-in-nested-virtualization-scenarios)。

+   已安装 Windows 10 Pro、企业版或教育版（1903 版本或更高版本，64 位）。当前的 Docker 桌面支持 1703 版本或更高版本，但为了在本书的示例中获得最佳体验，建议您将其升级到 1903 版本或更高版本。您可以通过打开开始菜单，选择设置图标，然后导航到系统 > 关于来检查 Windows 的版本。您将在 Windows 规格下找到必要的详细信息。

Windows 的 Docker 桌面也被称为 Windows 的 Docker 和 Docker **社区版** (**CE**)。如果您正在遵循较旧的安装指南，这一点尤为重要。

如果您对 Windows Server 上的 Docker 企业版的安装感兴趣，请参考第七章，*部署混合本地 Kubernetes 集群*。

# 稳定和边缘渠道

根据您的需求，您可以选择 Windows 的 Docker 桌面的两个发布渠道：**稳定**和**边缘**。如果您满意以下情况，您应该考虑使用稳定渠道：

+   您希望使用推荐和可靠的平台来处理容器。稳定频道中的发布遵循 Docker 平台稳定发布的发布周期。您可以期望稳定频道的发布每季度进行一次。

+   您想选择是否发送使用统计信息。

如果您同意以下内容，可以考虑使用边缘频道：

+   您希望尽快获得实验性功能。这可能会带来一些不稳定性和错误。您可以期望边缘频道的发布每月进行一次。

+   您同意收集使用统计数据。

现在，让我们继续进行安装。

# 安装

本节中描述的安装过程遵循官方 Docker 文档的建议。让我们开始：

如果您在 Windows 系统上使用 chocolatey 来管理应用程序包，也可以使用官方的 Docker Desktop 可信包，网址为：[`chocolatey.org/packages/docker-desktop.`](https://chocolatey.org/packages/docker-desktop)

1.  为了下载 Windows 版 Docker Desktop，请转到[`hub.docker.com/editions/community/docker-ce-desktop-windows`](https://hub.docker.com/editions/community/docker-ce-desktop-windows)。下载需要注册服务。您还可以选择直接链接来下载稳定频道发布（[`download.docker.com/win/stable/Docker%20for%20Windows%20Installer.exe`](https://download.docker.com/win/stable/Docker%20for%20Windows%20Installer.exe)）或边缘频道发布（[`download.docker.com/win/edge/Docker%20Desktop%20Installer.exe`](https://download.docker.com/win/edge/Docker%20Desktop%20Installer.exe)）。

如果需要，Docker Desktop for Windows 将自动启用 Hyper-V 角色并重新启动计算机。如果您是 VirtualBox 用户或 Docker Toolbox 用户，则将无法同时运行 VirtualBox VM，因为 Type-1 和 Type-2 hypervisors 不能同时运行。您仍然可以访问现有的 VM 映像，但无法启动 VM。

1.  转到安装程序下载的目录，然后双击它。

1.  通过选择“使用 Windows 容器而不是 Linux 容器”选项，默认启用 Windows 容器支持：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/a698518b-a15b-45d9-b00d-521f98abb7e3.png)

1.  进行安装：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/44a30aea-7043-4d86-acc4-d460405dc593.png)

1.  如果安装程序启用了 Hyper-V 角色，可能会提示您重新启动计算机。

1.  启动 Docker 桌面应用程序。

1.  等待 Docker 完全初始化。您将看到以下提示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/97d63c81-d24e-4ae2-a3ea-87a0012f243d.png)

安装后，我们需要验证 Docker 是否已正确安装并能运行一个简单的*hello world*容器镜像。

# 验证安装

现在，让我们验证安装是否成功：

1.  通过打开 Powershell 并执行以下命令来确认 Docker 客户端是否正常工作：

```
docker version
```

1.  您应该看到类似以下的输出：

```
Client: Docker Engine - Community
 Version: 18.09.2
 API version: 1.39
 Go version: go1.10.8
 Git commit: 6247962
 Built: Sun Feb 10 04:12:31 2019
 OS/Arch: windows/amd64
 Experimental: false

Server: Docker Engine - Community
 Engine:
 Version: 18.09.2
 API version: 1.39 (minimum version 1.12)
 Go version: go1.10.6
 Git commit: 6247962
 Built: Sun Feb 10 04:13:06 2019
 OS/Arch: linux/amd64
 Experimental: false
```

1.  运行基于官方 Powershell 镜像的简单容器：

```
docker run -it --rm mcr.microsoft.com/powershell pwsh -c 'Write-Host "Hello, World!"'
```

1.  在运行此命令的第一次运行期间，将下载缺少的容器镜像层。过一段时间后，您将在 Powershell 的控制台输出中看到 Hello, World!：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/ff4db97a-6e8f-4b64-8b19-dec8c139da4f.png)

1.  恭喜！您已成功安装了 Windows 版 Docker 桌面并运行了您的第一个容器。

在下一小节中，您将学习如何为容器启用进程隔离。

# 运行进程隔离的容器

在 Windows 10 上，为了运行进程隔离的容器，您必须在创建容器时显式指定`--isolation=process`参数。正如我们之前提到的，还需要指定与您的操作系统匹配的容器镜像版本。让我们开始吧：

1.  假设您正在运行 Windows 10，版本**1903**，让我们执行以下命令，尝试在分离（后台）模式下创建一个进程隔离的容器。运行 ping 命令，指定要发送到本地主机机器的回显请求的数量，即`100`：

```
docker run -d --rm --isolation=process mcr.microsoft.com/windows/nanoserver:1809 cmd /c ping localhost -n 100
```

所选的 mcr.microsoft.com/windows/nanoserver 镜像版本为 1809，与您的操作系统版本不匹配。因此，它将因错误而失败，通知您容器的基本镜像操作系统版本与主机操作系统不匹配：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f3f46785-b75e-45cf-af23-e7231a26b06f.png)

1.  现在，让我们执行类似的命令，但现在指定正确的匹配版本（1903）的容器基本镜像：

```
docker run -d --rm --isolation=process mcr.microsoft.com/windows/nanoserver:1903 cmd /c ping localhost -n 100
```

在这种情况下，容器已成功启动，可以使用`docker ps`命令进行验证：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/4e2349c5-478a-4f9b-b883-d6fcf6d02036.png)

1.  现在，让我们检查进程隔离在实践中与 Hyper-V 隔离有何不同。我们将比较这两种隔离类型之间主机 OS 中容器进程的可见性。

1.  首先，获取您新创建的进程隔离容器的容器 ID。这个容器应该运行几分钟，因为它在终止并自动删除之前会执行 100 次对本地主机的回显请求。在我们的示例中，容器 ID 是`a627beadb1297f492ec1f73a3b74c95dbebef2cfaf8f9d6a03e326a1997ec2c1`。使用`docker top <containerId>`命令，可以列出容器内运行的所有进程，包括它们的**进程 ID**（**PID**）：

```
docker top a627beadb1297f492ec1f73a3b74c95dbebef2cfaf8f9d6a03e326a1997ec2c1
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/9f8d0fe1-1eac-4bbb-bbfb-ee610f9b066d.png)

在上述屏幕截图中，容器内的`ping.exe`进程的 PID 为`6420`。为了列出在主机 OS 的上下文中运行的`ping.exe`进程，请在 Powershell 中使用`Get-Process`命令：

```
Get-Process -Name ping
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/5e694e96-df0a-416e-9396-45bb766095f0.png)

上述输出显示，容器内运行的`ping.exe`进程也可以从主机上看到，并且 PID 完全相同：`6420`。

为了进行比较，我们将创建一个类似的容器，但这次指定`--isolation=hyperv`参数以强制使用 Hyper-V 隔离。在 Windows 10 上，当运行默认的 Docker 配置时，可以完全省略`--isolation`参数，因为默认隔离级别是 Hyper-V。我们可以使用以下命令创建容器（使用与主机不同的基本镜像 OS 版本）：

```
docker run -d --rm --isolation=hyperv mcr.microsoft.com/windows/nanoserver:1809 cmd /c ping localhost -n 100
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/50aef9bd-6d68-42ba-9326-872ac139b2f3.png)

容器已成功启动。在这种情况下，容器 ID 是`c62f82f54cbce3a7673f5722e29629c1ab3d8a4645af9c519c0e60675730b66f`。检查容器内运行的进程会发现`ping.exe`的 PID 为`1268`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f65a1630-dce0-49df-a4b5-a2e133c95546.png)

当检查主机上运行的进程时，您会发现没有 PID 为`1268`的`ping.exe`进程（也没有 PID 为`1216`的`cmd.exe`进程，这是容器中的主要进程）。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/a7ac9cb8-7846-4670-ae98-5be3c0088cf2.png)

这是因为在 Hyper-V 容器中运行的进程不会与主机共享内核，因为它们在单独的轻量级 Hyper-V VM 中执行，并且具有与容器基础镜像 OS 版本匹配的自己的内核。

现在，是时候在 Windows 上使用 LCOW 运行你的第一个 Linux 容器了！

# 运行 LCOW 容器

默认情况下，Docker Desktop for Windows 使用 MobyLinuxVM 托管 Linux 容器，为其提供了一个最小的、完全功能的环境。这种方法仅用于开发和测试目的，因为它在 Windows Server 上不可用。Windows Server 目前对 LCOW 有实验性支持，也可以在 Docker Desktop 中启用此功能。

要在 Docker Desktop 中启用 LCOW 支持，您必须在 Docker Daemon 中启用实验性功能。让我们来看一下：

1.  打开 Docker Desktop 托盘图标并选择设置。

1.  导航到 Daemon 选项卡。

1.  启用实验性功能复选框：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/2a177e9e-1efd-4a0c-a457-7f7736bcfe53.png)

1.  应用更改。 Docker Desktop 将重新启动。

打开 PowerShell 并创建一个使用 Linux 作为基础镜像的容器，通过提供 `--platform=linux` 参数给 `docker run`。在这个例子中，我们以交互模式创建一个 busybox 容器，并启动 Bourne shell：

```
docker run --rm -it --platform=linux busybox /bin/sh
```

如果镜像存在一个平台的版本，则不需要提供 `--platform` 参数。下载镜像后，也不再需要指定 `--platform` 参数来运行容器。

容器启动后，Bourne shell 提示符将出现 (`/ #`)。现在，您可以使用 `uname` 命令验证您确实在 Linux 容器内运行，该命令会打印 Linux 内核信息：

```
uname -a
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/973b1876-1765-4ace-88ba-abc71c22bdca.png)

在一个单独的 Powershell 窗口中，在不关闭容器中的 Bourne shell 的情况下，执行 `docker inspect <containerId>` 命令以验证容器确实是使用 LCOW 使用 Hyper-V 隔离运行的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/afc73b54-ce91-47dd-a333-66673318ce37.png)

在本节中，您学习了如何安装 Docker Desktop for Windows 工具和验证其功能，包括在 Windows 上运行 Linux 容器。在下一节中，您将学习如何使用 Visual Studio Code 来构建您的第一个 Windows 容器镜像。

# 构建你的第一个容器

在上一节中，您已经学会了如何在 Windows 上安装 Docker Desktop 以及如何运行简单的 Windows 和 Linux 容器。本节将演示如何使用 Dockerfile 构建自定义 Docker 镜像，以及如何执行运行容器的最常见操作，例如访问日志和执行`exec`进入容器。

Dockerfile 是一个文本文件，包含用户执行的所有命令，以组装容器镜像。由于本书不仅关注 Docker，本节将简要回顾常见的 Docker 操作。如果您对 Dockerfile 本身和构建容器感兴趣，请参考官方文档：[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)。

例如，我们将准备一个 Dockerfile，创建一个 Microsoft IIS 的 Windows 容器镜像，托管一个演示 HTML 网页。为了演示操作原则，镜像定义不会很复杂。

# 准备 Visual Studio Code 工作区

第一步是准备 Visual Studio Code 工作区。Visual Studio Code 需要您安装一个额外的扩展来管理 Docker。让我们开始吧：

1.  为了做到这一点，按*Ctrl*+*Shift*+*X*打开扩展视图。

1.  在扩展：市场中，搜索`docker`并安装微软官方的 Docker 扩展：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/9074b59b-a8e3-4612-9a12-ac4a0a839539.png)

本节演示的所有操作都可以在任何代码/文本编辑器和使用命令行中执行，而无需使用 Visual Studio Code。Visual Studio Code 是一个有用的多平台 IDE，用于开发和测试在 Docker 容器中运行的应用程序。

安装完成后，Docker Explorer 将可用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/2e3864f4-1789-48db-ad96-29304e7a2f36.png)

1.  您还可以在按下*Ctrl*+*Shift*+P 后，输入`docker`到搜索栏中，从命令面板中利用新的面向 Docker 的命令。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3203b306-5a02-4d56-8c09-9ab80ec083cf.png)

1.  现在，通过使用*Ctrl*+*K*，*Ctrl*+*O*快捷键初始化工作区，打开所需的文件夹或导航到文件|打开文件夹...。

在下一小节中，我们将创建一个演示 HTML 网页，该网页将托管在 Windows 容器中。

# 创建一个示例 HTML 网页

我们将通过创建一个简约的 HTML“Hello World！”网页来开始创建我们的 Docker 镜像。这一步骤模拟了在没有任何容器化的情况下实现应用程序，并且在应用程序开发中是一个常见的场景：您正在运行一个非容器化的应用程序，然后将其移动到 Docker 容器中。

您还可以使用本书的 GitHub 存储库中的文件来执行此操作，该存储库位于：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter01/01_docker-helloworld-iis`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter01/01_docker-helloworld-iis)。

使用*Ctrl* + *N*快捷键或通过导航到文件 > 新建文件在 Visual Studio Code 中的工作区中添加一个新文件。在新文件中使用以下示例 HTML 代码：

```
<!DOCTYPE html>
<html>
    <head>
        <title>Hello World!</title>
    </head>
    <body>
        <h1>Hello World from Windows container!</h1>
    </body>
</html>
```

将文件保存（使用*Ctrl* + S）为`index.html`在您的工作区中。

让我们继续创建 Dockerfile 本身。

# 创建 Dockerfile

由于我们将在容器中使用 IIS 托管网页，因此我们需要创建一个**Dockerfile**，该文件使用`mcr.microsoft.com/windows/servercore/iis`官方镜像作为构建的基础镜像。我们将使用带有`windowsservercore-1903`标签的 Docker 镜像，以确保我们运行与主机操作系统匹配的版本，并使其能够使用进程隔离。

在您的工作区中创建一个名为`Dockerfile`的新文件，其中包含以下内容：

```
FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-1903

RUN powershell -NoProfile -Command Remove-Item -Recurse C:\inetpub\wwwroot\*
WORKDIR /inetpub/wwwroot
COPY index.html .
```

在编写 Dockerfile 时，Visual Studio Code 会提供许多代码片段，前提是您已经按照预期的约定命名了文件。您还可以在编辑时按*Ctrl* + SPACE 来显示代码片段列表。

在下一小节中，您将学习如何根据刚刚创建的 Dockerfile 手动构建 Docker 镜像。

# 构建 Docker 镜像

使用`docker build`命令来执行构建 Docker 镜像。在执行此步骤时，您有两个选项：

+   使用 Visual Studio Code 的命令面板。

+   使用 Powershell 命令行。

在 Visual Studio Code 中，执行以下操作：

1.  使用*Ctrl* + *Shift* + *P*快捷键打开命令面板。

1.  搜索 Docker: Build Image 并按照以下格式执行它，提供镜像名称和标签（或者使用基于目录名称的默认建议名称）：

```
<image name>:<tag>
```

1.  如果您已登录到自定义注册表或使用 Docker Hub，您还可以指定以下内容：

```
<registry or username>/<image name>:<tag>
```

Docker Registry 和公共 Docker Hub 的概念将在第三章中进行介绍，*使用容器镜像*。

在本示例中，我们将使用以下镜像名称和标签：`docker-helloworld-iis:latest`。

Visual Studio Code 命令相当于在 Powershell 中执行以下操作：

1.  将工作目录更改为包含`Dockerfile`的文件夹；例如：

```
cd c:\src\Hands-On-Kubernetes-on-Windows\Chapter01\docker-helloworld-iis
```

1.  执行`docker build`命令，同时指定`-t`参数以提供镜像名称和标签，并使用当前目录`.`作为构建上下文：

```
docker build -t docker-helloworld-iis:latest .
```

以下屏幕截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/179facb6-a584-4dc6-8be5-ca7c9f3db64a.png)

成功构建后，您可以使用`docker-helloworld-iis`本地镜像来创建新的容器。我们将在下一小节中介绍这个过程。

# 运行 Windows 容器

现在，让我们使用示例网页创建一个进程隔离的 Windows 容器。在 Visual Studio Code 中，导航至命令面板（*Ctrl* + *Shift* + *P*），找到 Docker: Run 命令。选择`docker-helloworld-iis`作为镜像。将打开一个带有适当命令的终端。

这相当于在 Powershell 中执行`docker run`命令，如下（如果您的主机机器上的端口*tcp/80*已被占用，请使用其他可用端口）：

```
docker run -d --rm --isolation=process -p 80:80 docker-helloworld-iis
```

成功启动容器后，通过网络浏览器导航至`http://localhost:80/`。您应该会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/893e8fde-0e4d-42da-be61-0f8c2c153f8b.png)

接下来，我们将检查容器日志，这是调试容器问题最有用的工具之一。

# 检查容器日志

访问容器中主进程的标准输出和标准错误日志对于调试容器化应用程序的问题至关重要。这在使用 Kubernetes 时也是常见的情况，您可以使用 Kubernetes CLI 工具执行类似的操作。

官方 Microsoft IIS Docker 镜像的当前架构不会将任何日志输出到`ServiceMonitor.exe`（容器中的主进程）的`stdout`，因此我们将在之前使用的简单`ping.exe`示例上进行演示。运行以下容器以创建容器：

```
docker run -d --rm --isolation=process mcr.microsoft.com/windows/nanoserver:1903 cmd /c ping localhost -n 100
```

现在，在 Visual Studio Code 中，您可以通过打开命令面板（*Ctrl* + *Shift* + *P*）并执行`Docker: Show Logs`命令来检查日志。选择容器名称后，日志将显示在终端中。或者，您可以使用 Docker Explorer 选项卡，展开容器列表，右键单击要检查的容器，然后选择显示日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/705b6c2a-dbba-436b-a9e7-68a49305735a.png)

这将在 Visual Studio Code 中打开一个终端，以便您可以开始从容器的`stdout`和`stderr`实例中流式传输日志。

对于 PowerShell 命令行，您必须使用`docker logs`命令：

```
docker logs <containerId>
```

值得注意的是，在调试场景中，您可能会发现`-f`和`--tail`参数很有用：

```
docker logs -f --tail=<number of lines> <containerId>
```

`-f`参数指示实时跟踪日志输出，而`--tail`参数使其仅显示输出的最后几行。

除了检查容器日志之外，您经常需要`exec`进入正在运行的容器。这将在下一小节中介绍。

# 进入正在运行的容器

在调试和测试场景中，通常需要以临时方式在运行的容器内执行另一个进程。这对于在容器中创建一个 shell 实例（对于 Windows，使用`cmd.exe`或`powershell.exe`，对于 Linux，使用`bash`或`sh`）并进行交互式调试特别有用。这样的操作称为执行`exec`进入正在运行的容器。

Visual Studio Code 通过 Docker Explorer 实现了这一点。在 Docker Explorer 选项卡中，找到要进入的容器，右键单击它，然后选择附加 Shell：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/4b5dc68e-fba2-493b-af84-2d291317b18d.png)

默认情况下，对于 Windows 容器，此命令将使用`powershell.exe`命令进行 exec。如果您正在运行基于 Windows Nano Server 的映像，则将无法使用`powershell.exe`，而必须改用`cmd.exe`。要自定义在附加 Shell 期间使用的命令，请打开设置（*Ctrl* + *,*），搜索 docker，并自定义 docker.attachShellCommand.windowsContainer 设置。

在 Powershell 命令行中，等效的`docker exec`命令如下：

```
docker exec -it <containerId> powershell.exe
```

上述命令在附加终端（`-it`参数）的交互模式下在运行的容器中创建了一个新的`powershell.exe`进程。如您所见，Powershell 终端的新交互式实例已打开：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/9b426421-3095-4a73-a5c3-b5ffb226e16a.png)

您只能进入正在运行主进程的容器。如果容器已退出、终止或处于暂停状态，则**无法**使用`exec`命令。

让我们尝试检查容器工作目录中`index.html`的内容：

```
cat .\index.html
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/c4e99bfd-2322-4099-86bf-526c2b50dd71.png)

这显示了我们之前创建并添加到镜像中的`index.html`文件的预期内容。

我们还可以检查托管`index.html`的应用程序池的 IIS 工作进程（`w3wp.exe`）。这是在调试期间的常见场景，当不是所有日志都直接通过容器输出日志可用时：

```
cat ..\logs\LogFiles\W3SVC1\u_ex<current date>.log
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/dbdd1d72-bf7b-430f-b19a-d17b063cf6d6.png)

使用`docker exec`是您容器工具箱中最强大的命令之一。如果您学会如何使用它，您将能够几乎像在非容器化环境中托管应用程序一样进行调试。

# 摘要

在本章中，您了解了 Windows 容器架构的关键方面以及 Windows 容器运行时提供的隔离模式之间的区别。我们还介绍了如何在 Windows 平台上安装 Docker Desktop，并演示了如何使用 Docker CLI 执行最重要的操作。

本章和接下来的两章将是本书其余部分关于 Windows 上 Kubernetes 的基础。在下一章中，我们将专注于在 Windows 容器中管理状态，即在运行容器时如何持久化数据。

# 问题

1.  Windows 暴露哪些内核特性以实现容器化？

1.  在 Linux 和 Windows 上容器化之间的主要区别是什么？

1.  Hyper-V 隔离和进程隔离之间有什么区别？何时应该使用 Hyper-V 隔离？

1.  我们如何在 Windows 10 上启用 LCOW？

1.  我们可以使用什么命令来访问 Docker 容器中主进程的日志？

1.  我们如何在运行的容器内启动一个新的 Powershell 进程？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

本章对 Windows 上的 Docker 容器进行了回顾。有关 Windows 容器的更多信息，请参考两本优秀的 Packt 图书。

+   在 Windows 上使用 Docker：从 101 到生产环境，请访问[`www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition`](https://www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition)。

+   学习 Windows Server 容器，请访问[`www.packtpub.com/virtualization-and-cloud/learning-windows-server-containers`](https://www.packtpub.com/virtualization-and-cloud/learning-windows-server-containers)。

+   您也可以查阅官方微软关于 Windows 容器的文档，请访问[`docs.microsoft.com/en-us/virtualization/windowscontainers/about/`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/about/)。


# 第二章：在容器中管理状态

管理应用程序的状态是架构任何软件解决方案时的关键方面之一，无论是单体桌面应用程序还是托管在云环境中的复杂分布式系统。即使系统中的大多数服务都是无状态的，系统的某些部分将是有状态的，例如，托管在云中的 NoSQL 数据库或您自己实现的专用服务。如果您希望设计具有良好可扩展性，您必须确保有状态服务的存储能够适当扩展。在这些方面，托管在 Docker 容器中的服务或应用程序并无二致-您需要管理状态，特别是如果您希望数据在容器重新启动或失败时得以持久化。

在本章中，我们将为您提供更好地理解如何在运行在 Windows 上的 Docker 容器中持久化状态以及这些概念与 Kubernetes 应用程序中数据持久性的关系。您将了解*volumes*和*bind mounts*的概念以及它们如何用于在容器和容器主机之间共享状态。

本章涵盖以下主题：

+   挂载本地卷以用于有状态的应用程序

+   使用远程/云存储进行容器存储

+   在容器内运行集群解决方案

# 技术要求

对于本章，您将需要以下内容：

+   已安装 Windows 10 Pro、企业版或教育版（版本 1903 或更高版本，64 位）

+   已安装 Docker Desktop for Windows 2.0.0.3 或更高版本

Docker Desktop for Windows 的安装及其详细要求在第一章*，创建容器*中已经涵盖。

您还需要自己的 Azure 帐户。您可以在此处阅读有关如何获取个人使用的有限免费帐户的更多信息：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

您可以从本书的官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter02)。

# 挂载本地卷以用于有状态的应用程序

要了解有状态应用程序的本机 Docker 存储选项，我们必须看一下层文件系统的组织方式。这个文件系统服务的主要作用是为每个基于 Docker 镜像的容器提供一个单一的虚拟逻辑文件系统。

Docker 镜像由一系列只读层组成，其中每个层对应于 Dockerfile 中的一个指令。让我们来看看上一章中的以下 Dockerfile：

```
FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-1903

RUN powershell -NoProfile -Command Remove-Item -Recurse C:\inetpub\wwwroot\*
WORKDIR /inetpub/wwwroot
COPY index.html .
```

构建 Docker 镜像时，(*几乎*)每个指令都会创建一个新的层，其中包含给定命令引入的文件系统中的一组差异。在这种情况下，我们有以下内容：

+   `FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-1903`：这个指令定义了基础层（或一组层）来自基础镜像。

+   `RUN powershell -NoProfile -Command Remove-Item -Recurse C:\inetpub\wwwroot\*`：这个指令创建的层将反映从原始基础镜像中删除`C:\inetpub\wwwroot\`目录中内容。

+   `WORKDIR /inetpub/wwwroot`：即使这个指令不会引起任何文件系统的更改，它仍然会创建**无操作**（**nop**）层来保留这些信息。

+   `COPY index.html .`：这个最后的指令创建了一个层，其中包含`C:\inetpub\wwwroot\`目录中的`index.html`。

如果您有现有的 Docker 镜像，可以使用`docker history`命令自己检查层：

```
docker history <imageName>
```

例如，对于前面的 Dockerfile 生成的图像，您可以期望以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/b0a4b0a1-5d0b-467a-8027-c23e7a0b972d.png)

底部的五个层来自`mcr.microsoft.com/windows/servercore/iis:windowsservercore-1903`基础镜像，而顶部的三个层是我们之前描述的指令的结果。

当创建一个新的容器时，为其创建文件系统，其中包括只读的镜像层和一个可写的顶层，也称为容器层。对于容器，这些层是透明的，进程“看到”它就像是一个常规的文件系统 - 在 Windows 系统上，这是由*Windows 容器隔离文件系统*服务*保证的。容器内部的进程对容器文件系统所做的任何更改都会在可写层中持久保存。这个概念可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/eb1cb350-5f48-4da0-9990-574cc1f58aae.png)

现在我们了解了 Docker 中层文件系统的原则，我们可以专注于*卷*和*绑定挂载*。

# 卷和绑定挂载

此时，似乎为每个容器都有一个可写的容器层就足以为应用程序提供状态持久性。即使您停止并重新启动同一个容器，数据也会被持久化。不幸的是，您会很容易发现容器及其可写层是紧密耦合的，您无法轻松地在不同的容器之间甚至同一图像的新实例之间共享数据。一个简单的情景是：

1.  基于当前的 Dockerfile 构建一个容器镜像。

1.  基于此构建启动一个新的容器。

1.  对可写容器层进行一些修改；例如，容器内的一个进程修改了存储应用程序数据的文件。

1.  现在，您想通过修改 Dockerfile 并添加额外的指令来创建图像的新版本。与此同时，您希望重新创建容器，并重用已经在容器的可写层中修改过的文件中的数据。

您会意识到，使用新的图像版本重新创建容器后，您使用应用程序状态对文件所做的所有更改都将消失。除此之外，使用容器层来存储数据还有更多的缺点：

+   可写层与容器主机紧密耦合，这意味着无法轻松地将数据移动到不同的主机。

+   层文件系统的性能比直接访问主机文件系统差。

+   您不能在不同的容器之间共享可写层。

一个经验法则是要避免将数据存储在可写的容器层中，特别是对于 I/O 密集型应用程序。

Docker 提供了两种持久存储的解决方案，可以挂载到容器中：卷和绑定挂载。在这两种情况下，数据都会暴露为容器文件系统中的一个目录，并且即使容器停止和删除，数据也会被持久化。在性能方面，卷和绑定挂载都直接访问主机的文件系统，这意味着没有层文件系统的开销。还可以使用这些 Docker 功能在多个容器之间共享数据。

绑定挂载提供了一个简单的功能，可以将容器主机中的任何*文件*或*目录*挂载到给定的容器中。这意味着绑定挂载将充当主机和容器之间共享的文件或目录。一般来说，不建议使用绑定挂载，因为它们比卷更难管理，但在某些情况下，绑定挂载是有用的，特别是在 Windows 平台上，卷支持有限。

绑定挂载允许您共享容器主机中的任何文件。这意味着，如果您将敏感目录（例如`C:\Windows\`）挂载到一个不受信任的容器中，您就会面临安全漏洞的风险。

卷提供了与绑定挂载类似的功能，但它们由 Docker 完全管理，这意味着您不必担心容器主机文件系统中的物理路径。您可以创建*匿名*或*命名*卷，然后将它们挂载到容器中。除非您明确使用 Docker 删除卷，否则卷中的任何数据都不会被删除。卷的一个非常常见的用例是为运行数据库实例的容器提供持久存储 - 当容器被重新创建时，它将使用包含前一个容器实例写入的数据的相同卷。

卷的基本功能是在容器主机文件系统中提供存储。还可以使用*卷驱动程序*（*插件*），它们使用卷抽象来访问远程云存储或网络共享。请注意，目前在 Windows 平台上，对卷插件的支持有限，大多数插件只能在 Linux 操作系统上使用。有关可用插件的更多信息，请访问[`docs.docker.com/engine/extend/legacy_plugins/#volume-plugins`](https://docs.docker.com/engine/extend/legacy_plugins/#volume-plugins)。

现在，让我们看看如何在 Docker 卷上执行基本操作。

# 创建和挂载卷

可以使用`docker volume create`命令显式地创建新卷。还可以在容器启动时自动创建命名卷和匿名卷。要手动创建 Docker 命名卷，请按照以下步骤进行操作：

1.  执行以下命令：

```
docker volume create <volumeName>
```

1.  创建后，可以使用`docker volume inspect`命令检查卷的详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/570e760b-4ffa-4ecf-a854-d552cfbab98c.png)

如您所见，使用默认的*local*驱动程序时，卷数据存储为主机文件系统中的常规目录。

要将卷挂载到容器中，您必须使用`docker run`命令的`--mount`或`--volume`（简称参数：`-v`）参数。最初，`--volume`用于独立容器，而`--mount`用于集群容器，但从 Docker 17.06 开始，`--mount`也可以用于独立容器，并且是推荐的做法，因为它提供了更强大的选项。有关这些标志的更多信息可以在官方文档中找到：[`docs.docker.com/storage/volumes/#choose-the--v-or---mount-flag`](https://docs.docker.com/storage/volumes/#choose-the--v-or---mount-flag)。

按照以下步骤学习如何挂载卷：

1.  假设您想要在新的 PowerShell 容器中将`test-named-volume`从上一个示例挂载到`C:\Data`目录下，您必须指定`--mount`参数，如下所示：

```
docker run -it --rm `
 --isolation=process `
 --mount source=test-named-volume,target=C:\Data `
 mcr.microsoft.com/powershell:windowsservercore-1903
```

省略`source=<volumeName>`参数将导致创建一个*匿名*卷，稍后可以使用卷 ID 访问。请记住，如果您使用`--rm`选项运行容器，匿名卷将在容器退出时自动删除。

1.  容器启动并且终端已附加后，请尝试在已挂载卷的目录中创建一个简单的文件：

```
echo "Hello, Volume!" > C:\Data\test.txt
```

1.  现在，退出容器（这将导致容器停止并由于`--rm`标志而自动删除），并在主机上检查卷目录：

```
PS C:\WINDOWS\system32> cat C:\ProgramData\Docker\volumes\test-named-volume\_data\test.txt
Hello, Volume!
```

1.  为了证明命名卷可以轻松地挂载到另一个容器中，让我们基于`mcr.microsoft.com/windows/servercore:1903`镜像创建一个新的容器，并且挂载目标与上一个示例中的不同：

```
docker run -it --rm `
 --isolation=process `
 --mount source=test-named-volume,target=C:\ServerData `
 mcr.microsoft.com/windows/servercore:1903
```

1.  如果您检查容器中的卷目录，您会注意到`test.txt`文件存在并包含预期的内容：

```
C:\>more C:\ServerData\test.txt
Hello, Volume!
```

还可以在 Dockerfile 中使用`VOLUME`命令，以便在容器启动时强制自动创建卷，即使未为`docker run`命令提供`--mount`参数。如果您希望明确告知其他人应用程序的状态数据存储在何处，以及需要确保层文件系统不会引入额外的开销，这将非常有用。您可以在本书存储库中的以下 Dockerfile 中找到`VOLUME`命令的用法示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/03_MongoDB_1903/Dockerfile#L44`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/03_MongoDB_1903/Dockerfile#L44)。

在下一小节中，我们将快速了解如何使用 Docker CLI 删除卷。

# 删除卷

要使用`docker volume rm`命令删除现有的命名或匿名卷，它们不能在任何容器中使用（即使是停止的容器）。标准流程如下：

```
docker stop <containerId>
docker rm <containerId>
docker volume rm <volumeId>
```

对于匿名卷，如果在`docker run`命令中使用`--rm`标志，容器将在退出时被删除，连同其匿名卷。这个标志应根据情况使用——在大多数情况下，它对于测试和开发目的很有用，以便更轻松地进行清理。

在开发过程中，您可能偶尔需要对 Docker 主机上的所有卷进行全面清理，例如，如果您需要释放磁盘空间。Docker CLI 提供了一个专用命令，将删除任何未在任何容器中使用的卷：

```
docker volume prune
```

接下来，我们将看一下绑定挂载及其与卷的区别。

# 使用绑定挂载挂载本地容器主机目录

绑定挂载是容器和主机机器之间共享的最简单的持久存储形式。通过这种方式，您可以在容器中挂载主机文件系统中的任何现有目录。还可以使用主机目录内容“覆盖”容器中的现有目录，这在某些情况下可能很有用。一般来说，卷是推荐的存储解决方案，但有一些情况下绑定挂载可能会有用：

+   在主机和容器之间共享配置。一个常见的用例可能是 DNS 配置或`hosts`文件。

+   在开发场景中，共享在主机上创建的构建产物，以便它们可以在容器内使用。

+   在 Windows 上，将 SMB 文件共享挂载为容器中的目录。

卷可以被视为绑定挂载的 *演进*。它们由 Docker 完全管理，用户看不到与容器主机文件系统的紧密耦合。

为容器创建绑定挂载需要在 `docker run` 命令中指定一个额外的参数 `type=bind`，用于 `--mount` 标志。在这个例子中，我们将主机的 `C:\Users` 目录挂载为容器中的 `C:\HostUsers`：

```
docker run -it --rm `
 --isolation=process `
 --mount type=bind,source=C:\Users,target=C:\HostUsers `
 mcr.microsoft.com/powershell:windowsservercore-1903
```

您可以验证对 `C:\HostUsers` 所做的任何更改也会在主机机器的 `C:\Users` 中可见。

有关 Windows 特定功能和绑定挂载的限制，请参阅 Microsoft 的官方文档：[`docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-storage#bind-mounts`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-storage#bind-mounts)。

在下一节中，我们将学习如何利用绑定挂载来在 Windows 容器中使用远程或云存储。

# 使用远程/云存储作为容器存储

在容器主机文件系统中存储数据不适用于需要高可用性、故障转移和数据备份便捷性的用例。为了提供存储抽象，Docker 提供了卷驱动程序（插件），可用于管理托管在远程机器或云服务中的卷。不幸的是，在撰写本书时，运行在本地的 Windows 容器不支持当前在 Linux OS 上可用的卷插件。这使我们在使用 Windows 容器中的云存储时有三种选择：

+   使用 Docker for Azure 和 Cloudstor 卷插件，这是在 Azure VM 上以 *swarm* 模式运行 Docker 的部分托管解决方案。在本书中，我们不会涵盖 Docker for Azure，因为这个解决方案与 Kubernetes 分开，包括 Azure 提供的托管 Kubernetes 的服务。如果您对此服务的更多细节感兴趣，请参阅 [`docs.docker.com/docker-for-azure/persistent-data-volumes/`](https://docs.docker.com/docker-for-azure/persistent-data-volumes/)。

+   在应用程序代码中直接使用云存储，使用云服务提供商的 SDK。这是最明显的解决方案，但它需要将存储管理嵌入到应用程序代码中。

+   使用绑定挂载和**服务器消息块**（**SMB**）全局映射来挂载 Azure Files，这是一个完全托管的云文件共享，可以通过 SMB 协议访问。

很快，我们将演示如何利用最后一个选项：Azure Files 的 SMB 全局映射。但首先，我们必须安装 Azure CLI 以管理 Azure 资源。

# 安装 Azure CLI 和 Azure PowerShell 模块

为了从命令行高效地管理 Azure 资源，建议使用官方的 Azure CLI。官方安装说明可以在[`docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows?view=azure-cli-latest`](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows?view=azure-cli-latest)找到。让我们开始吧：

1.  从 PowerShell 安装 Azure CLI 需要以管理员身份运行以下命令：

```
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
Remove-Item .\AzureCLI.msi
```

1.  安装 Azure CLI 后，您需要重新启动 PowerShell 窗口。接下来，登录到您的 Azure 帐户：

```
az login
```

上述命令将打开您的默认浏览器，并指示您登录到您的 Azure 帐户。

1.  现在，运行以下命令来验证您已经正确登录：

```
az account show
```

您应该能够看到您的订阅详细信息，类似于这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/ad13b529-964b-49e8-8597-de51cc5f9edb.png)

除此之外，我们还需要安装 Azure PowerShell 模块，因为一些操作在 Azure CLI 中不可用。

1.  可以使用以下命令为当前登录的用户安装：

```
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```

官方安装步骤可以在这里找到：[`docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-2.5.0#install-the-azure-powershell-module-1`](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-2.5.0#install-the-azure-powershell-module-1)。

1.  如果在导入新安装的模块时遇到问题，您还需要以管理员身份设置 PowerShell 执行策略为`RemoteSigned`：

```
Set-ExecutionPolicy RemoteSigned
```

1.  使用 PowerShell 模块登录到 Azure 必须与 Azure CLI 分开进行，并可以使用以下命令执行：

```
Connect-AzAccount
```

此时，您应该能够使用 Azure CLI 和 Azure PowerShell 模块来管理您的资源，而无需打开 Azure 门户网站！让我们看看如何创建 Azure Files SMB 共享。

# 创建 Azure Files SMB 共享

假设您正在使用全新的 Azure 订阅进行这些示例演练，让我们首先创建一个 Azure 资源组和 Azure 存储帐户：

1.  在 PowerShell 窗口中，执行以下代码：

```
az group create `
 --name docker-storage-resource-group `
 --location westeurope
```

您可以选择最适合您的位置（为了显示可用位置的列表，请运行`az account list-locations`）。在这个例子中，我们使用`westeurope` Azure 位置。

您还可以使用本书的 GitHub 存储库中的 PowerShell 脚本来执行此操作：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/01_CreateAzureFilesSMBShare.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/01_CreateAzureFilesSMBShare.ps1)。请记住以管理员身份运行此脚本，因为必须从特权帐户添加 SMB 共享的全局映射。

1.  成功创建 Azure 资源组后，继续创建 Azure 存储帐户：

```
az storage account create `
 --name dockerstorageaccount `
 --resource-group docker-storage-resource-group `
 --location westeurope `
 --sku Standard_RAGRS `
 --kind StorageV2
```

上述命令将在`docker-storage-resource-group`中创建一个名为`dockerstorageaccount`的`general-purpose v2`存储帐户，其中包含`read-access geo-redundant`存储。此操作可能需要几分钟才能完成。

1.  接下来，您必须创建实际的 Azure Files SMB 共享。首先，为您的 Azure 存储帐户创建连接字符串，并将其存储为 PowerShell 中的变量：

```
$azureStorageAccountConnString = az storage account show-connection-string `
 --name dockerstorageaccount `
 --resource-group docker-storage-resource-group `
 --query "connectionString" `
 --output tsv

if (!$azureStorageAccountConnString) {
 Write-Error "Couldn't retrieve the connection string."
}
```

请记住保护好连接字符串，因为它可以用来管理您的存储帐户！

1.  使用存储在`$azureStorageAccountConnString`变量中的连接字符串，创建共享：

```
az storage share create `
 --name docker-bind-mount-share `
 --quota 2 `
 --connection-string $azureStorageAccountConnString 
```

这将创建一个名为`docker-bind-mount-share`的共享，配额限制为 2GB，我们将在 Docker 容器中使用它。

# 在容器中挂载 Azure Files SMB 共享

为了将新的 Azure Files SMB 共享作为容器中的绑定挂载，我们将利用在 Window Server 1709 中引入的*SMB 全局映射*功能。全局映射是专门为此目的而引入的，即在主机上挂载 SMB 共享，以便它们对容器可见。让我们开始吧：

1.  首先确保您已登录，以便可以执行 Azure PowerShell（使用`Connect-AzAccount`命令）。

1.  接下来，让我们定义一些变量，这些变量将在我们即将执行的命令中使用：

```
$resourceGroupName = "docker-storage-resource-group"
$storageAccountName = "dockerstorageaccount"
$fileShareName = "docker-bind-mount-share"
```

这里使用的名称与我们在上一小节中创建 Azure Files SMB 共享时使用的名称完全相同。

1.  下一步是定义`$storageAccount`和`$storageAccountKeys`变量：

```
$storageAccount = Get-AzStorageAccount `
 -ResourceGroupName $resourceGroupName `
 -Name $storageAccountName
$storageAccountKeys = Get-AzStorageAccountKey `
 -ResourceGroupName $resourceGroupName `
 -Name $storageAccountName
```

这些变量将用于检索文件共享详细信息和访问凭据，这两者都是 SMB 全局映射所需的。

1.  现在，*可选地*，您可以使用`cmdkey`命令将共享凭据持久保存在 Windows 凭据管理器中：

```
Invoke-Expression -Command `
 ("cmdkey /add:$([System.Uri]::new($storageAccount.Context.FileEndPoint).Host) " + `
 "/user:AZURE\$($storageAccount.StorageAccountName) /pass:$($storageAccountKeys[0].Value)")
```

1.  我们还需要关于 Azure Files SMB 共享的详细信息，因此让我们定义一个名为`$fileShare`的新变量：

```
$fileShare = Get-AzStorageShare -Context $storageAccount.Context | Where-Object { 
    $_.Name -eq $fileShareName -and $_.IsSnapshot -eq $false
}
```

1.  此时，您还可以检查文件共享详细信息是否已成功检索。通过这样做，您将能够检测出例如`$fileShareName`是否包含了错误的共享名称：

```
if ($fileShare -eq $null) {
    Write-Error "Azure File share not found"
}
```

1.  在创建 SMB 全局映射之前的最后一步是定义一个凭据对象，该对象将用于映射创建：

```
$password = ConvertTo-SecureString `
    -String $storageAccountKeys[0].Value `
    -AsPlainText `
    -Force
$credential = New-Object System.Management.Automation.PSCredential `-ArgumentList "AZURE\$($storageAccount.StorageAccountName)", $password
```

1.  最后，我们可以使用`New-SmbGlobalMapping`命令来为 Azure Files SMB 共享创建映射：

```
New-SmbGlobalMapping `
 -RemotePath "\\$($fileShare.StorageUri.PrimaryUri.Host)\$($fileShare.Name)" `
 -Credential $credential `
 -Persistent $true `
 -LocalPath G:
```

如果您需要删除 SMB 全局映射，可以使用`Remove-SmbGlobalMapping`命令来执行。

上述命令将持久地将 Azure Files SMB 共享挂载为`G:`驱动器。您可以稍后使用此路径进行 Docker 容器的绑定挂载。现在，您可以通过使用 Windows 资源管理器将一些测试文件移动到`G:`驱动器来测试您的映射是否正常工作。

使用绑定挂载进行全局映射的 SMB 共享的原则可以用于任何兼容 SMB 的服务器，例如以下服务器：

+   在您的本地网络中托管的传统文件服务器

+   SMB 协议的第三方实现，例如 NAS 设备

+   基于存储空间直通（S2D）的传统 SAN 或**分布式文件服务器**（**SoFS**）

当作为绑定挂载使用时，全局映射的 SMB 共享对容器来说是透明可见的，就像本地文件系统中的常规目录一样。所有的“繁重工作”都是由容器主机执行的，它负责管理 SMB 共享连接。

让我们通过创建一个简单的 PowerShell 进程隔离容器来演示这个功能：

1.  首先，在我们的演示容器的 SMB 共享中创建一个名为`G:\ContainerData`的目录：

```
 New-Item -ItemType Directory -Force -Path G:\ContainerData
```

1.  现在，我们可以通过将 Azure Files SMB 共享中的新目录作为绑定挂载并将`C:\Data`作为目标来运行容器：

```
docker run -it --rm `
 --isolation=process `
 --mount type=bind,source=G:\ContainerData,target=C:\Data               `mcr.microsoft.com/powershell:windowsservercore-1903
```

有了这个，我们可以轻松证明我们的解决方案有效，并且容器状态文件确实存储在 Azure Cloud 中！

1.  在运行的容器中，创建一个包含数据的文件。例如，获取当前运行的进程列表，并将其存储为`processes.txt`文件：

```
Get-Process > C:\Data\processes.txt
```

1.  现在，登录到 Azure 门户（`https://portal.azure.com/`）并执行以下操作：

1.  从主菜单导航到存储账户。

1.  打开 dockerstorageaccount 账户。

1.  在存储账户菜单中，打开文件服务组下的文件。

1.  从列表中打开 docker-bind-mount-share 文件共享。

您将看到一个熟悉的目录结构。进入 ContainerData 目录，看到`processes.txt`文件确实存在，并包含在容器中存储的数据：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/5fa27a7f-8af4-4b69-ac32-1837119a24db.png)

在 Kubernetes 中，可以使用*volumes*（不要与 Docker 卷混淆）以受控方式执行类似的过程。我们将在第十一章中重点介绍这一点，*配置应用程序以使用 Kubernetes 功能*。您也可以参考官方文档：[`kubernetes.io/docs/concepts/storage/`](https://kubernetes.io/docs/concepts/storage/)。

请注意，这种情况也可以通过在本地网络中托管常规 SMB 文件服务器来实现，如果您已经在基础架构中使用它们，这可能是一个合适的解决方案。

恭喜！您已成功创建了一个使用 Azure Cloud 存储来持久保存容器状态的 Windows 容器。在下一节中，我们将学习如何在 Windows 容器中运行 MongoDB，作为多容器解决方案的示例。

# 在容器内运行集群解决方案

MongoDB 是一个免费的开源跨平台、面向文档的数据库程序，可以在集群模式下运行（使用分片和副本集）。在这个例子中，我们将运行一个三节点的 MongoDB 副本集，因为这比完整的分片集群更容易配置，并且足以演示持久存储容器状态数据的原理。

如果您想了解更多关于 MongoDB 和高级分片集群组件的信息，请参考官方文档：[`docs.mongodb.com/manual/core/sharded-cluster-components/`](https://docs.mongodb.com/manual/core/sharded-cluster-components/)。

我们的 MongoDB 副本集架构将如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e4ed078e-6bb7-4908-9eb9-bb8a33c4d258.png)

主节点负责管理所有写操作，在 ReplicaSet 中只能有一个主节点。次要节点只复制主节点的*oplog*并应用数据操作，以便它们的数据集反映主节点的数据集。这种 MongoDB 部署的主要好处如下：

+   **自动故障转移**：如果主节点不可用，其余次要节点将执行新的领导者选举并恢复集群功能。

+   **可以使用次要节点读取数据**：您可以指定读取偏好，以便客户端将主节点的读取操作卸载。但是，您必须注意异步复制可能导致次要节点与主节点略有不同步。

现在，让我们创建我们的 MongoDB ReplicaSet！

# 创建 MongoDB ReplicaSet

按照以下步骤创建 ReplicaSet：

1.  首先，让我们使用`docker network create`命令为新集群创建一个名为`mongo-cluster`的 Docker 网络：

```
docker network create --driver nat mongo-cluster
```

如果您想了解有关 Docker 网络的更多信息，请参考官方文档：[`docs.docker.com/network/`](https://docs.docker.com/network/)。

有关特定于 Windows 的文档，请访问[`docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/network-drivers-topologies`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/network-drivers-topologies)。

我们将使用 Azure Files SMB 共享（全局映射到`G:`驱动器），这是我们在上一节中创建的，以便使用绑定挂载存储 MongoDB 的状态。

1.  我们需要在我们的 SMB 共享中创建新的目录，每个 MongoDB 节点需要两个：

```
New-Item -ItemType Directory -Force -Path G:\MongoData1\db
New-Item -ItemType Directory -Force -Path G:\MongoData1\configdb
New-Item -ItemType Directory -Force -Path G:\MongoData2\db
New-Item -ItemType Directory -Force -Path G:\MongoData2\configdb
New-Item -ItemType Directory -Force -Path G:\MongoData3\db
New-Item -ItemType Directory -Force -Path G:\MongoData3\configdb
```

目前，Windows 的官方 MongoDB 镜像仅存在于 Windows Server Core 1803 中，这意味着我们必须使用 Hyper-V 隔离在 Windows 1903 上运行这些容器。这意味着我们无法利用 SMB 全局映射，因此我们需要基于 Windows Server Core 1903 创建自己的 MongoDB 镜像。这将使我们能够使用进程隔离。我们要构建的镜像是基于 4.2.0 RC8 版本的官方 MongoDB 镜像，可以在这里找到：[`github.com/docker-library/mongo/blob/a3a213fd2b4b2c26c71408761534fc7eaafe517f/4.2-rc/windows/windowsservercore-1803/Dockerfile`](https://github.com/docker-library/mongo/blob/a3a213fd2b4b2c26c71408761534fc7eaafe517f/4.2-rc/windows/windowsservercore-1803/Dockerfile)。要执行构建，请按照以下步骤进行：

1.  从本书的 GitHub 存储库下载 Dockerfile：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/03_MongoDB_1903/Dockerfile`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/03_MongoDB_1903/Dockerfile)。

1.  在 PowerShell 中，导航到您下载 Dockerfile 的位置（建议使用新的、单独的目录）。

1.  执行`docker build`命令，以在本地镜像注册表中创建一个名为`mongo-1903`的自定义 MongoDB 镜像：

```
docker build -t mongo-1903:latest .
```

构建过程将需要几分钟，因为 MongoDB 必须在构建容器中下载和安装。

该镜像还将 MongoDB 数据公开为容器内的`C:\data\db`和`C:\data\configdb`卷（[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/03_MongoDB_1903/Dockerfile#L44`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/03_MongoDB_1903/Dockerfile#L44)）。考虑到所有这些，让我们创建我们的第一个 MongoDB 进程隔离容器，命名为`mongo-node1`，它将在后台运行（使用`-d`选项）：

```
docker run -d `
 --isolation=process `
 --volume G:\MongoData1\db:C:\data\db `
 --volume G:\MongoData1\configdb:C:\data\configdb `
 --name mongo-node1 `
 --net mongo-cluster `
 mongo-1903:latest `
 mongod --bind_ip_all --replSet replSet0
```

在运行此容器时，我们提供了一个自定义命令来运行容器进程，即`mongod --bind_ip_all --replSet replSet0`。`--bind_ip_all`参数指示 MongoDB 绑定到容器中可用的所有网络接口。对于我们的用例，`--replSet replSet0`参数确保守护程序以 ReplicaSet 模式运行，期望在名为`replSet0`的 ReplicaSet 中。

成功创建第一个节点后，重复此过程用于下两个节点，适当更改它们的名称和卷挂载点：

```
docker run -d `
 --isolation=process `
 --volume G:\MongoData2\db:C:\data\db `
 --volume G:\MongoData2\configdb:C:\data\configdb `
 --name mongo-node2 `
 --net mongo-cluster `
 mongo-1903:latest `
 mongod --bind_ip_all --replSet replSet0

docker run -d `
 --isolation=process `
 --volume G:\MongoData3\db:C:\data\db `
 --volume G:\MongoData3\configdb:C:\data\configdb `
 --name mongo-node3 `
 --net mongo-cluster `
 mongo-1903:latest `
 mongod --bind_ip_all --replSet replSet0
```

创建过程完成后，您可以使用 `docker ps` 命令验证容器是否正常运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/6516dce2-6200-447b-ab62-59d2da30d6fd.png)

上述步骤也已经作为 PowerShell 脚本提供在本书的 GitHub 仓库中：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/02_InitializeMongoDBReplicaset.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter02/02_InitializeMongoDBReplicaset.ps1)。

接下来的阶段是配置 ReplicaSet。我们将使用 mongo shell 来完成这个过程。按照以下步骤进行：

1.  创建一个 mongo shell 实例。如果您已经运行了一个 MongoDB 容器（例如，`mongo-node1`），最简单的方法是 `exec` 进入现有容器并运行 `mongo` 进程：

```
docker exec -it mongo-node1 mongo
```

1.  几秒钟后，您应该会看到 mongo shell 控制台提示符 `>`。您可以使用 `rs.initiate()` 方法初始化 ReplicaSet：

```
rs.initiate(
  {
    "_id" : "replSet0",
    "members" : [
      { "_id" : 0, "host" : "mongo-node1:27017" },
      { "_id" : 1, "host" : "mongo-node2:27017" },
      { "_id" : 2, "host" : "mongo-node3:27017" }
    ]
  }
)
```

上述命令使用我们的三个节点在 `mongo-cluster` Docker 网络中创建了一个名为 `replSet0` 的 ReplicaSet。这些节点可以通过它们在 `mongo-cluster` Docker 网络中的 DNS 名称进行识别。

有关初始化 ReplicaSets 的更多详细信息，请参考官方文档：[`docs.mongodb.com/manual/reference/method/rs.initiate/`](https://docs.mongodb.com/manual/reference/method/rs.initiate/)。

1.  您还可以使用 mongo shell 中的 `rs.status()` 命令来验证初始化状态。在一段时间后，当 ReplicaSet 完全初始化时，在命令的 JSON 输出中，您应该能够看到一个节点中的 ReplicaSet 的 `"stateStr": "PRIMARY"`，以及另外两个节点中的 `"stateStr": "SECONDARY"`。

在下一小节中，我们将通过在另一个容器中生成测试数据并读取它来快速验证我们的 ReplicaSet。

# 编写和读取测试数据

按照以下步骤编写和读取测试数据：

1.  首先，在 ReplicaSet 主节点的 mongo shell 中（提示符为 `replSet0:PRIMARY>` ），让我们在 `demo` 集合中添加 1,000 个示例文档：

```
for (var i = 1; i <= 1000; i++) {
 db.demo.insert( { exampleValue : i } )
}
```

1.  您可以使用 `demo` 集合上的 `find()` 方法快速验证插入的文档：

```
db.demo.find()
```

1.  现在，我们将创建一个在 Docker 容器中运行的最小化.NET Core 3.0 控制台应用程序。这将连接到运行在我们的 Docker 容器中的 ReplicaSet，查询我们的`demo`集合，并将每个文档的`exampleValue`值写入标准输出。

您可以在本书的 GitHub 存储库中找到此源代码和 Dockerfile：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter02/04_MongoDB_dotnet`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter02/04_MongoDB_dotnet)。

如果在执行此场景时，您遇到任何与 MongoDB 的不稳定问题，请考虑将`mongo-1903` Dockerfile 升级到最新的 MongoDB 版本。

为了读取我们的测试数据，我们需要构建应用程序 Docker 镜像，并创建一个在`mongo-cluster`网络中运行的容器。执行以下步骤：

1.  克隆存储库并在 PowerShell 中导航到`Chapter02/04_MongoDB_dotnet`目录。

1.  在当前目录中执行`docker build`以创建`mongo-dotnet-sample` Docker 镜像：

```
docker build -t mongo-dotnet-sample:latest .
```

1.  运行示例容器。这需要连接到`mongo-cluster`网络：

```
docker run --isolation=process `
 --rm `
 --net mongo-cluster `
 mongo-dotnet-sample:latest
```

在输出中，您应该看到一个递增的数字序列，这是我们测试文档中`exampleValue`的值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/83cccc9f-2049-48f4-98ff-0f8405a01987.png)

如果您感兴趣，可以在 Azure 门户上检查 SMB 共享包含什么内容（[`portal.azure.com/`](https://portal.azure.com/)）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/cc802dbb-7896-4eb4-bf0a-120893c9cce9.png)

恭喜！您已成功创建并测试了在 Windows 容器中运行的 MongoDB ReplicaSet，并使用 Azure Files SMB 共享作为绑定挂载来存储数据。让我们快速总结一下本章学到的内容。

# 总结

在本章中，您学习了 Windows 上 Docker 存储的关键方面：使用卷和绑定挂载。在 Azure 的帮助下，您成功设置了 Azure Files SMB 共享，可以使用 SMB 全局映射来存储容器状态数据。最后，您通过设置自己的由 Azure 云存储支持的三节点 MongoDB ReplicaSet 来总结了所有这些，并验证了您的设置！

下一章将是最后一章专注于 Windows 平台上的 Docker。您可以期待学习如何使用 Docker 镜像以及如何在应用程序开发生命周期中使用它们的基础知识。之后，我们将准备开始我们的 Kubernetes 之旅。

# 问题

1.  Docker 存储架构中的容器层是什么？

1.  卷和绑定挂载之间有什么区别？

1.  为什么不建议将容器状态数据存储在容器层中？

1.  如何在容器中透明地挂载 Azure Files SMB 共享？

1.  在运行在 Hyper-V 隔离中的容器中可以使用绑定挂载吗？

1.  什么命令可以删除容器主机上的所有未使用卷？

1.  什么是卷驱动程序（插件）？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关在 Docker 中管理状态和卷的更多信息（不仅限于 Windows），请参考以下 Packt 图书：

+   *学习 Docker- Docker 18.x 基础* ([`www.packtpub.com/networking-and-servers/learn-docker-fundamentals-docker-18x`](https://www.packtpub.com/networking-and-servers/learn-docker-fundamentals-docker-18x))。

+   您还可以参考官方的 Docker 文档，其中对 Docker 本身的可能存储选项进行了很好的概述：[`docs.docker.com/storage/`](https://docs.docker.com/storage/)。


# 第三章：使用容器图像

基于容器的软件开发生命周期需要简单的图像打包和可靠的分发容器化应用程序的方法-这些是 Docker 生态系统解决的关键方面。我们在前几章中使用了 Dockerfiles 和 Docker 图像。简单来说，Dockerfile 定义了用于创建 Docker 图像的构建指令，这是容器数据的不可变的、分层的快照，可用于实例化容器。这两个概念使我们能够为容器应用程序创建简单和标准化的打包。为了为 Docker 图像提供可靠和可扩展的分发，我们可以使用图像注册表。

在本章中，我们将重点介绍 Docker 注册表的使用，主要是公开访问的 Docker Hub 和私有的 Azure 容器注册表，并且我们还将介绍 Docker 内容信任-用于发布和管理已签名内容集合的概念。通过这个容器图像管理的介绍，您将准备好完全进入 Windows 上的 Kubernetes 世界！

本章将涵盖以下主题：

+   存储和共享容器图像

+   使用云容器构建器

+   图像标记和版本控制

+   确保图像供应链的完整性

# 技术要求

本章，您将需要以下内容：

+   已安装 Windows 10 专业版、企业版或教育版（1903 版或更高版本，64 位）。

+   已安装 Docker Desktop for Windows 2.0.0.3 或更高版本。

+   已安装 Azure CLI。您可以在第二章*，在容器中管理状态*中找到详细的安装说明。

Docker Desktop for Windows 的安装及其详细要求在第一章*，创建容器*中已经涵盖。

要能够使用云托管的注册表，您将需要自己的 Azure 帐户。如果您之前没有为前几章创建帐户，您可以在此处了解如何获取用于个人使用的有限免费帐户：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

您可以从本书的官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03)。

# 存储和共享容器图像

到目前为止，您已经使用`docker pull hello-world`命令拉取了您的第一个`hello-world`容器，甚至使用了`docker run hello-world`命令。在图像拉取期间，底层会发生一些事情：

1.  Docker 引擎连接到所谓的 Docker 镜像注册表。注册表可以被明确指定，但默认情况下，这是官方的公共注册表，称为 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）。

1.  Docker 引擎对注册表进行身份验证，如果需要的话。如果您正在运行私有注册表或 Docker Hub 的付费计划，这可能是一个情况。

1.  所选的`hello-world`图像被下载为一组由 SHA256 摘要标识的层。每个层在下载后都会被解压缩。

1.  该图像被存储在本地。

如果执行`docker run`命令并且本地存储中不存在图像，则会发生类似的过程。第一次，它将被拉取，以后将使用本地缓存的图像。 

如果您熟悉 GitHub 或其他源代码仓库托管，您会发现图像管理和图像注册表中有许多类似的概念。

因此，直观地说，图像注册表是一个有组织的、分层的系统，用于存储 Docker 图像。图像的层次结构包括以下级别：

+   **注册表**：这是层次结构的顶层。

+   **存储库**：注册表托管多个存储库，这些存储库是图像的存储单元。

+   **标签**：单个图像的版本标签。存储库将由相同图像名称和不同标签标识的多个图像分组。

注册表中的每个图像都由图像名称和标签标识，并且上面的层次结构反映在最终图像名称中。使用以下方案：`<registryAddress>/<userName>/<repositoryName>:<tag>`，例如，`localregistry:5000/ptylenda/test-application:1.0.0`。在使用 Docker 命令时，其中一些部分是可选的，如果您不提供值，将使用默认值：

+   `<registryAddress>`是用于存储图像的注册表的 DNS 名称或 IP 地址（连同端口）。如果省略此部分，将使用默认的 Docker Hub 注册表（`docker.io`）。目前，没有办法更改注册表地址的默认值，因此，如果您想使用自定义注册表，必须始终提供此部分。

+   `<userName>`标识拥有该镜像的用户或组织。在 Docker Hub 的情况下，这是所谓的 Docker ID。是否需要这部分取决于注册表 - 对于 Docker Hub，如果您没有提供 Docker ID，它将假定官方镜像，这是一组由 Docker 维护和审核的 Docker 仓库。

+   `<repositoryName>`是您帐户中的唯一名称。镜像名称形成为`<registryAddress>/<userName>/<repositoryName>`。

+   `<tag>`是给定镜像仓库中的唯一标签，用于组织镜像，大多数情况下使用版本控制方案，例如`1.0.0`。如果未提供此值，则将使用默认值`latest`。我们将在本章后面重点讨论标记和版本控制镜像。

使用多架构 Docker 镜像变体，可以在相同的镜像名称和标签下拥有不同的镜像，用于不同的架构。镜像的版本将根据运行 Docker 客户端的机器的架构自动选择。可以通过在镜像标签后面显式地使用额外的`@sha256:<shaTag>`部分来明确识别这样的镜像，例如，`docker.io/adamparco/demo:latest@sha256:2b77acdfea5dc5baa489ffab2a0b4a387666d1d526490e31845eb64e3e73ed20`。有关更多详细信息，请访问[`engineering.docker.com/2019/04/multi-arch-images/`](https://engineering.docker.com/2019/04/multi-arch-images/)。

现在您知道 Docker 镜像是如何标识的，让我们来看看如何将镜像推送到 Docker 注册表。

# 将镜像推送到 Docker 注册表

使用注册表共享容器镜像是通过镜像推送来完成的。这个过程将所需的镜像层上传到所选仓库的注册表中，并使其可以被其他具有对给定仓库访问权限的用户拉取。在我们将用于演示的 Docker Hub 的情况下，您的仓库将是公开的，除非您有付费计划。

将镜像推送到 Docker Hub 需要进行身份验证。如果您还没有在 Docker Hub 注册，请转到[`hub.docker.com/`](https://hub.docker.com/)并按照那里的说明操作。注册后，您将需要您的 Docker ID 和密码才能使用`docker login`命令登录到服务中：

```
PS C:\WINDOWS\system32> docker login 
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
Username: packtpubkubernetesonwindows
Password:
Login Succeeded
```

在本书中，我们将使用`packtpubkubernetesonwindows` Docker ID 来演示我们的示例。建议您创建自己的帐户，以便能够完全跟随本书中的示例。按照以下步骤：

1.  第一步是创建一个实际可以推送到注册表的镜像。我们将使用以下 Dockerfile 来创建镜像：

```
FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-1903

WORKDIR /inetpub/wwwroot
RUN powershell -NoProfile -Command ; \
    Remove-Item -Recurse .\* ; \
    New-Item -Path .\index.html -ItemType File ; \
    Add-Content -Path .\index.html -Value \"This is an IIS demonstration!\"
```

此 Dockerfile 创建了一个 IIS Web 主机镜像，用于提供显示 This is an IIS demonstration!的极简网页。

1.  将 Dockerfile 保存在当前目录中。要构建它，请发出以下`docker build`命令：

```
docker build -t <dockerId>/iis-demo .
```

请记住，为了能够将镜像推送到 Docker Hub，您必须在仓库名称中提供您的 Docker ID。

1.  成功构建后，您就可以准备将镜像推送到注册表。这可以通过`docker push`命令来执行：

```
docker push <dockerId>/iis-demo
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/df5b226c-5dab-4ad9-b754-623195333b48.png)

Docker 将镜像作为一组层进行推送，这也优化了推送过程，如果已知的层正在使用。此外，请注意，在基于 Windows 的镜像的情况下，您将看到一个跳过外部层的消息。原因是来自 Docker Hub 以外的注册表的任何层，例如**Microsoft Container Registry**（**MCR**），将不会被推送到 Docker Hub。

现在，您还可以转到 Docker Hub 网页并检查您的镜像详细信息 - 对于示例镜像，您可以在此处检查：[`cloud.docker.com/repository/docker/packtpubkubernetesonwindows/iis-demo/`](https://cloud.docker.com/repository/docker/packtpubkubernetesonwindows/iis-demo/)。任何有权访问您的仓库的用户现在都可以使用`docker pull <dockerId>/iis-demo`命令来使用您的镜像。

您已成功将第一个镜像推送到 Docker Hub！现在，让我们来看看如何将镜像推送到自定义镜像注册表。

# 使用自定义本地注册表

在选择图像存储时，您不仅限于使用默认的 Docker Hub。实际上，在大多数情况下，当您运行生产代码时，您可能希望使用本地托管的 Docker Registry，这是一个用于存储和分发 Docker 镜像的开源、高度可扩展的应用程序。您应该在以下情况下考虑这个解决方案：

+   您希望在隔离网络中分发 Docker 镜像

+   您需要严格控制图像存储和分发的位置

+   您希望补充您的 CI/CD 工作流程，以实现更快速和更可扩展的图像交付。

有关部署 Docker 注册表的详细信息可以在官方文档中找到：[`docs.docker.com/registry/deploying/`](https://docs.docker.com/registry/deploying/)。

对于 Kubernetes 部署，通常的做法是在 Kubernetes 集群旁边甚至内部托管自己的 Docker 注册表。有许多自动化可用于此用例，例如，用于在 Kubernetes 上部署注册表的官方 Helm 图表：[`github.com/helm/charts/tree/master/stable/docker-registry`](https://github.com/helm/charts/tree/master/stable/docker-registry)。

为了使用自定义镜像注册表，您只需要在使用 pull 或 push 命令时在镜像名称中指定注册表地址（如果需要，还需要端口），例如，`localregistry:5000/ptylenda/test-application:1.0.0`，其中`localregistry:5000`是本地托管的 Docker 注册表的域名和端口。实际上，当您为演示 Windows IIS 应用程序拉取图像时，您已经使用了自定义 Docker 镜像注册表：`mcr.microsoft.com/windows/servercore/iis:windowsservercore-1903`。`mcr.microsoft.com`注册表是 MCR，是 Microsoft 发布图像的官方注册表。其他公共注册表和 MCR 之间的主要区别在于，它与 Docker Hub 紧密集成，并利用其 UI 提供可浏览的图像目录。Docker 引擎能够使用任何公开 Docker 注册表 HTTP API（[`docs.docker.com/registry/spec/api/`](https://docs.docker.com/registry/spec/api/)）的系统作为容器镜像注册表。

目前，不可能更改 Docker 引擎的默认容器镜像注册表。除非在镜像名称中指定注册表地址，否则目标注册表将始终假定为`docker.io`。

除了托管自己的本地镜像注册表外，还有一些基于云的替代方案提供私有镜像注册表：

+   **Azure 容器注册表**（**ACR**）[`azure.microsoft.com/en-in/services/container-registry/`](https://azure.microsoft.com/en-in/services/container-registry/)）。我们将在下一节中介绍这个注册表，作为如何使用云托管进行容器构建的演示的一部分。

+   Docker Enterprise 及其 Docker Trusted Registry（[`www.docker.com/products/image-registry`](https://www.docker.com/products/image-registry)）。

+   IBM Cloud 容器注册表（[`www.ibm.com/cloud/container-registry`](https://www.ibm.com/cloud/container-registry)）。

+   Google Cloud 容器注册表（[`cloud.google.com/container-registry/`](https://cloud.google.com/container-registry/)）。

+   RedHat Quay.io 和 Quay Enterprise（[`quay.io`](https://quay.io)）。如果您希望在本地托管注册表以及构建自动化和 Web 目录，Quay 是一个有趣的解决方案，类似于 Docker Hub。

在下一节中，您将学习如何使用 Docker Hub 自动化 Docker 镜像构建，以及如何使用 ACR 托管自己的注册表。

# 使用云容器构建器

Docker Hub 提供的一个功能是**自动构建**（**自动构建**）。这在持续集成和持续部署场景中特别有用，您希望确保对代码存储库的每次推送都会导致构建、发布和可能的部署。

目前，Docker Hub 不支持 Windows 镜像，但这很可能会在不久的将来发生变化。我们将在 Linux 镜像上演示此用法，但所有原则仍然相同。有关 Windows 容器云构建，请查看下一节关于 Azure 容器注册表。

要设置自动构建，请完成以下步骤：

1.  创建一个 GitHub 存储库，其中包含您的应用程序代码，以及定义应用程序的 Docker 镜像的 Dockerfile。

1.  创建一个 Docker Hub 存储库并添加一个自动构建触发器。此触发器也可以在创建存储库后添加。

1.  自定义构建规则。

1.  可选地，启用自动测试。这是 Docker Hub 提供的验证功能，您可以在其中定义测试套件，以便测试每个新的镜像推送。

让我们开始创建一个 GitHub 存储库！

# 创建 GitHub 存储库

如果您没有 GitHub 帐户，可以免费创建一个帐户[`github.com/join`](https://github.com/join)。在本例中，我们将在`hands-on-kubernetes-on-windows`组织中创建一个专用的公共存储库，名为`nginx-demo-index`。让我们开始吧：

1.  转到[`github.com/`](https://github.com/)，使用*+*符号创建一个新存储库：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/fcf0245d-dd47-4e5f-a565-c58b2d83161a.png)

托管组织并非必需；您可以只使用自己的个人命名空间。该仓库旨在仅包含应用程序源代码（在我们的情况下，只是一个静态的`index.html`网页）和构建图像所需的 Dockerfile，这与 Docker 开发的建议最佳实践一致。

1.  在创建了仓库之后，我们可以推送一些图像的源代码。您可以在本书的 GitHub 仓库中找到我们用于托管使用 nginx 的静态网页的最简化 Docker 图像的源代码：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03/02_nginx-demo-index`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03/02_nginx-demo-index)。

1.  为了克隆新创建的仓库，在 PowerShell 中，转到您想要拥有该仓库的目录并使用`git clone`命令：

```
git clone https://github.com/<userName>/<repositoryName>.git
```

1.  将所有必需的源文件复制到仓库中，并使用`git push`命令进行推送：

```
git add -A
git commit -am "Docker image source code"
git push -u origin master
```

1.  此时，当您转到 GitHub 网页时，例如[`github.com/hands-on-kubernetes-on-windows/nginx-demo-index`](https://github.com/hands-on-kubernetes-on-windows/nginx-demo-index)，您应该能够看到仓库中的文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/1670f0cc-d298-40ca-af47-8ed0a4bab5cc.png)

下一步是创建实际的 Docker Hub 仓库并配置自动构建。让我们开始吧！

# 创建具有自动构建的 Docker Hub 仓库

将 Docker Hub 仓库与自动构建集成需要将您的 GitHub 帐户连接到您的 Docker Hub 帐户并创建仓库本身。让我们开始吧：

1.  打开[`hub.docker.com/`](https://hub.docker.com/)，转到帐户设置。在已连接帐户部分，单击 GitHub 提供程序的连接：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/26d3b045-45d7-43a1-8c3a-9297dcd220f0.png)

1.  授权 Docker Hub Builder 访问您的仓库。此时，如果需要，您还可以授予对任何组织的访问权限。

1.  连接帐户后，再次打开[`hub.docker.com/`](https://hub.docker.com/)，单击创建仓库部分的*+*按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f600ce6d-28b1-4d5b-bee2-372a87a5a500.png)

1.  填写所有必需的细节。在我们的情况下，我们的仓库名称将是`packtpubkubernetesonwindows/nginx-demo-index`。

1.  在构建设置中，选择 GitHub 图标，并选择您刚刚创建的 GitHub 存储库，如前面的屏幕截图所示。

1.  通过单击“单击此处自定义构建设置”来检查构建设置，以了解默认配置是什么：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/b6f2033b-4472-45fc-9284-c9a8d790f6e2.png)

1.  默认设置适用于我们的镜像，因为我们希望在将新代码推送到主分支时触发构建。应该在您的 GitHub 存储库的根目录中使用名为 Dockerfile 的 Dockerfile 来构建镜像。

1.  单击“创建和构建”以保存并立即基于存储库中的当前代码开始构建。

1.  在最近的构建中，您应该看到您的镜像的一个挂起构建：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/41d65d6b-3606-4f04-8e68-7201701450f4.png)

1.  几分钟后，构建应该完成，`packtpubkubernetesonwindows/nginx-demo-index:latest`镜像应该可用。您可以通过使用`docker pull packtpubkubernetesonwindows/nginx-demo-index:latest`命令来验证这一点。

现在，让我们看看如何通过提交新代码轻松触发 Docker 镜像构建。

# 触发 Docker Hub 自动构建

通过在上一节创建的自动构建设置中，触发新的 Docker 镜像构建就像提交新代码到您的 GitHub 存储库一样简单。为了做到这一点，您必须执行以下操作：

1.  对 GitHub 上镜像的源代码进行更改；例如，修改`index.html`文件：

```
<!DOCTYPE html>
<html>
    <head>
        <title>Hello World!</title>
    </head>
    <body>
        <h1>Hello World from nginx container! This is a new version of image for autobuild.</h1>
    </body>
</html>
```

1.  提交并推送代码更改：

```
git commit -am "Updated index.html"
git push -u origin master
```

1.  在 Docker Hub 上的此镜像存储库的构建选项卡中，您几乎立即应该看到已触发新的镜像构建（源提交：[`github.com/hands-on-kubernetes-on-windows/nginx-demo-index/tree/5ee600041912cdba3c82da5331542f48701f0f28`](https://github.com/hands-on-kubernetes-on-windows/nginx-demo-index/tree/5ee600041912cdba3c82da5331542f48701f0f28)）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/b5e4b8e7-dfa9-426c-ba4a-81a4795a8514.png)

如果您的构建失败，您可以随时检查构建详细信息和构建日志选项卡中的 Docker 构建日志。

1.  构建成功后，在您的 Windows 机器上运行一个新容器来验证您的镜像：

```
docker run -it --rm `
 -p 8080:80 `
 packtpubkubernetesonwindows/nginx-demo-index:latest
```

1.  镜像将自动从 Docker Hub 存储库中拉取。在您的网络浏览器中导航至`http://localhost:8080`。您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/1fdd74ee-dd50-4340-99f3-d08b0c09d6b0.png)

恭喜-您已成功创建并触发了 Docker Hub 上的 Docker 镜像自动构建！在下一节中，您将学习如何为基于 Windows 的图像使用 Azure 容器注册表创建类似的设置。

# 创建 Azure 容器注册表

**Azure 容器注册表**（**ACR**）是 Azure Cloud 提供的完全托管的私有 Docker 注册表。在本节中，我们将使用 Azure CLI 创建 ACR 的新实例。您将学习如何实现与 Docker Hub 提供的类似的构建自动化，但具有构建 Windows 图像和使用私有注册表的可能性。

您可以在第二章*，*管理容器中的状态*中找到 Azure CLI 的详细安装说明。

要创建 Azure 容器注册表实例，请按照以下步骤进行：

1.  确保您已经使用 PowerShell 中的`az login`命令登录到 Azure CLI。然后为 ACR 实例创建一个专用资源组。在本例中，我们将使用`acr-resource-group`资源组和`westeurope`作为 Azure 位置：

```
**az group create `**
 **--name acr-resource-group `**
 **--location westeurope** 
```

您还可以使用本书 GitHub 存储库中提供的 PowerShell 脚本：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter03/03_CreateAzureContainerRegistry.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter03/03_CreateAzureContainerRegistry.ps1)。请记住提供全局唯一的 ACR 名称，以便能够创建实例。

1.  接下来，使用全局唯一名称创建基本层 ACR 实例（为演示目的，我们提供了`handsonkubernetesonwinregistry`，但您必须提供自己的唯一名称，因为它将成为注册表的 DNS 名称的一部分）：

```
az acr create `
 --resource-group acr-resource-group ` --name handsonkubernetesonwinregistry `
 --sku Basic
```

如果您对 Azure 容器注册表的其他服务层感兴趣，请参考官方文档：[`docs.microsoft.com/en-us/azure/container-registry/container-registry-skus`](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-skus)。

您将获得有关新创建的注册表的详细信息：

```
{
  "adminUserEnabled": false,
  "creationDate": "2019-08-18T21:20:53.081364+00:00",
  "id": "/subscriptions/cc9a8166-829e-401e-a004-76d1e3733b8e/resourceGroups/acr-resource-group/providers/Microsoft.ContainerRegistry/registries/handsonkubernetesonwinregistry",
  "location": "westeurope",
  "loginServer": "handsonkubernetesonwinregistry.azurecr.io",
  "name": "handsonkubernetesonwinregistry",
  "networkRuleSet": null,
  "provisioningState": "Succeeded",
  "resourceGroup": "acr-resource-group",
  "sku": {
    "name": "Basic",
    "tier": "Basic"
  },
  "status": null,
  "storageAccount": null,
  "tags": {},
  "type": "Microsoft.ContainerRegistry/registries"
}
```

最重要的信息是`"loginServer": "handsonkubernetesonwinregistry.azurecr.io"`，这将用于推送和拉取 Docker 镜像。

1.  最后，最后一步是登录到注册表，这样您就可以在 Docker CLI 中使用注册表：

```
az acr login `
 --name handsonkubernetesonwinregistry
```

有了 ACR 设置，我们准备在云环境中使用 ACR 构建 Docker 镜像。

# 使用 Azure 容器注册表构建 Docker 镜像

为了演示目的，我们将使用一个简单的 Windows IIS 映像，用于托管静态 HTML 网页。您可以在本书的 GitHub 存储库中找到 Docker 映像源：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03/04_iis-demo-index`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03/04_iis-demo-index)。要在 ACR 中构建映像，请按照以下步骤进行：

1.  使用图像源代码克隆存储库，并在 PowerShell 中导航至`Chapter03/04_iis-demo-index`目录。

1.  执行`az acr build`命令以在云环境中开始 Docker 镜像构建（记得提供 Docker 构建上下文目录，在本例中用*dot*表示当前目录）：

```
az acr build `
 --registry handsonkubernetesonwinregistry `
 --platform windows `
 --image iis-demo-index:latest .
```

1.  使用`az acr build`命令启动 ACR 快速任务。这将上传 Docker 构建上下文到云端，并在远程运行构建过程。几分钟后，构建过程应该完成。您可以期望类似于本地`docker build`命令的输出。

1.  现在，您可以通过在本地机器上运行容器并从 ACR 中拉取映像来验证映像。您需要使用注册表的完整 DNS 名称（在本例中，这是`handsonkubernetesonwinregistry.azurecr.io`）：

```
docker run -it --rm `
 -p 8080:80 `
 handsonkubernetesonwinregistry.azurecr.io/iis-demo-index:latest
```

1.  在 Web 浏览器中导航至`http://localhost:8080`，并验证容器是否按预期运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/eef79d64-be77-413c-a3c0-d383ae9b2c21.png)

您已成功执行了 ACR 构建快速任务！现在，我们可以开始自动化 ACR 构建触发器，以类似于使用 Docker Hub 的方式对 GitHub 存储库代码推送进行操作。

# Azure 容器注册表的自动构建

Azure 容器注册表提供了类似于 Docker Hub 的功能，用于在代码推送时自动化 Docker 镜像构建。管道是高度可定制的，可以支持同时构建多个容器映像，但在本例中，我们将专注于在 GitHub 存储库代码推送时自动化单个映像构建。

对于更高级的多步骤和多容器场景，请查看官方文档：[`docs.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-multistep-task`](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-multistep-task)。

集成 ACR 和 GitHub 可以按以下步骤执行：

1.  创建一个新的 GitHub 存储库并推送 Docker 镜像源代码。在这个例子中，我们将使用来自[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03/04_iis-demo-index`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter03/04_iis-demo-index)的源代码，它将被推送到一个新的 GitHub 存储库，即[`github.com/hands-on-kubernetes-on-windows/iis-demo-index`](https://github.com/hands-on-kubernetes-on-windows/iis-demo-index)。

1.  生成 GitHub **个人访问令牌**（**PAT**）以便在 ACR 中访问存储库。转到[`github.com/settings/tokens/new`](https://github.com/settings/tokens/new)。

1.  输入 PAT 描述并选择 repo:status 和 public_repo 范围（对于私有存储库，您需要使用完整的 repo 范围）：

！[](assets/972e23d8-a90d-4160-b5e2-08abf11d5f1f.png)

1.  点击“生成令牌”按钮。

1.  您将获得一个 PAT 值。将令牌复制到安全位置，因为您将需要它来设置集成。

1.  现在，让我们创建一个名为`iis-demo-index-task`的 ACR 任务。当代码被推送到[`github.com/hands-on-kubernetes-on-windows/iis-demo-index`](https://github.com/hands-on-kubernetes-on-windows/iis-demo-index)时，这将自动触发。所需的参数类似于 Docker Hub 的构建配置：

```
az acr task create `
 --registry handsonkubernetesonwinregistry `
 --name iis-demo-index-task `
 --platform windows `
 --image "iis-demo-index:{{.Run.ID}}" `
 --context https://github.com/hands-on-kubernetes-on-windows/iis-demo-index `
 --branch master `
 --file Dockerfile `
 --git-access-token <gitHubPersonalAccessTokenValue>
```

如果您在使用 Azure CLI 时遇到`az acr task create: 'utputformat' is not a valid value for '--output'. See 'az acr task create --help'.`的错误，请确保您正确地转义/引用 PowerShell 中的花括号。

1.  使用`az acr task run`命令测试您的 ACR 任务定义：

```
az acr task run `
   --registry handsonkubernetesonwinregistry `
   --name iis-demo-index-task
```

1.  在 Docker 镜像的源代码中，引入一个更改并提交并将其推送到 GitHub 存储库。例如，修改静态文本，使其读取如下：

```
Hello World from IIS container! The image is provided by Azure Container Registry and automatically built by Azure Container Registry task.
```

1.  检索 ACR 任务日志以验证任务是否确实被触发：

```
az acr task  logs --registry handsonkubernetesonwinregistry
```

您应该看到类似以下的输出，这表明推送触发了一个新的任务实例：

！[](assets/ba48c49b-f339-4610-907d-fd4037c0eb77.png)

1.  任务完成后，拉取带有 Run ID 标记的镜像（在本例中，这是 cb5）。您也可以使用`latest`标记，但这需要使用`docker rmi`命令删除本地缓存的镜像：

```
docker pull handsonkubernetesonwinregistry.azurecr.io/iis-demo-index:cb5
```

1.  使用`handsonkubernetesonwinregistry.azurecr.io/iis-demo-index:cb5`镜像创建一个新的容器：

```
docker run -it --rm `
 -p 8080:80 `
 handsonkubernetesonwinregistry.azurecr.io/iis-demo-index:cb5
```

1.  在 Web 浏览器中导航至`http://localhost:8080`，并验证容器是否按预期运行。还要验证静态 HTML 页面是否包含代码推送中引入的更改：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/bb195a4c-6ff0-4d10-b036-7af9ff898fbf.png)

其他云服务提供商也提供类似的设置 Docker 镜像注册表和构建流水线的服务。如果您对 Google Cloud Platform 服务感兴趣，请查看 GCP Cloud Build：[`cloud.google.com/cloud-build/docs/quickstart-docker`](https://cloud.google.com/cloud-build/docs/quickstart-docker)。

您已成功使用 GitHub 和 Azure 容器注册表设置了 Docker 镜像构建流水线 - 祝贺！现在，我们将快速查看图像标记和版本控制的最佳实践。

# 图像标记和版本控制

Docker 镜像使用标签来提供存储库中相同镜像的不同版本 - 每个镜像标签对应于给定的 Docker 镜像 ID。通常在构建镜像时会指定 Docker 镜像的标签，但您也可以使用`docker tag`命令显式添加标签：

```
docker pull mcr.microsoft.com/dotnet/core/sdk
docker tag mcr.microsoft.com/dotnet/core/sdk:latest mydotnetsdk:v1
docker tag mcr.microsoft.com/dotnet/core/sdk:latest mydotnetsdk:v2
```

在此示例中，我们拉取了.NET Core SDK 的`latest`镜像标签（因为没有明确指定），然后在本地镜像缓存中使用`mydotnetsdk:v1`和`mydotnetsdk:v2`标签标记了该镜像。现在，可以在本地机器上执行操作时使用这些标签，如下所示：

```
docker run -it --rm mydotnetsdk:v1
```

让我们来看看`latest`标签，在使用 Docker 时经常使用。

# 使用最新标签

默认情况下，Docker CLI 假定一个特殊的标签称为`latest`。这意味着如果您执行`docker pull applicationimage`命令或`docker run -it applicationimage`命令，或在 Dockerfile 中使用`FROM applicationimage`，将使用`applicationimage:latest`标签。同样，当您执行`docker build -t applicationimage .`时，生成的 Docker 镜像将被标记为`latest`标签，并且每次构建都将产生`applicationimage:latest`的新版本。

重要的是要理解`latest`的行为与任何其他 Docker 镜像标签一样。它可以被视为 Docker 在用户未提供标签时始终使用的默认值。这可能会导致一些混淆，具体如下：

+   在图像构建期间，如果为图像指定了标签，最新标签将不会被添加。这意味着，如果您将`applicationimage:v1`推送到注册表，这并不意味着`applicationimage:latest`将被更新。您必须明确执行。

+   当图像所有者将新的 Docker 镜像版本推送到存储库并再次标记为`latest`标签时，并不意味着您本地缓存的图像将在`docker build`期间被更新和使用。您必须告诉 Docker CLI 尝试使用`docker build`的`--pull`参数来拉取图像的更新版本。

+   在 Dockerfile 的`FROM`指令中使用`latest`标签可能导致在不同时间点构建不同的图像，这通常是不可取的。例如，您可能在`latest`指向 SDK 版本 2.2 时使用`mcr.microsoft.com/dotnet/core/sdk`图像构建您的图像，但几个月后，使用相同的 Dockerfile 构建将导致使用版本 3.0 作为基础。

一般最佳实践（Kubernetes 也是如此）是避免使用`latest`标签部署生产容器，并仅在开发场景和本地环境的便利性使用`latest`标签。同样，为了确保您的 Docker 图像可预测且自描述，应避免在 Dockerfile 中使用带有`latest`标签的基础图像，而是使用特定的标签。

# 语义化版本

为了有效地管理 Docker 图像的版本和标记，您可以使用**语义化版本**（**Semver**）作为一般策略。这种版本方案在图像分发商中被广泛采用，并帮助消费者了解您的图像如何演变。

通常，语义版本建议使用三个数字（主要版本、次要版本和修订版本），用点分隔，`<major>.<minor>.<patch>`，根据需要递增每个数字。例如，2.1.5 表示图像的主要版本是 2，次要版本是 1，当前修订版本为 5。这些发布数字的含义和递增规则与非容器化应用程序的版本化类似。

+   **主要版本**：如果您引入了破坏兼容性或其他破坏性更改的功能，则递增。

+   **次要版本**：如果您引入的功能与先前版本完全兼容，则递增。消费者不需要升级应用程序的用法。

+   **补丁**：如果要发布错误修复或补丁，则递增。

有关 Semver 作为一般概念的更多细节可以在这里找到：[`semver.org/`](https://semver.org/)。

在构建/推送 Docker 图像时使用 Semver 的最佳实践可以总结如下：

+   构建图像的新版本时，始终创建新的**补丁**标签（例如 2.1.5）。

+   始终覆盖现有的主要和次要标签（例如，2 和 2.1）。

+   永远不要覆盖补丁标签。这确保了希望使用特定版本应用程序的图像使用者可以确保随着时间的推移不会发生变化。

+   始终覆盖现有的`latest`标签。

以下一组命令显示了构建和标记新版本`applicationimage` Docker 图像的示例：

```
# New build a new version of image and push latest tag
docker build -t applicationimage:latest .
docker push applicationimage:latest

# New major tag
docker tag applicationimage:latest applicationimage:2
docker push applicationimage:2

# New minor tag
docker tag applicationimage:latest registry:2.1
docker push applicationimage:2.1

# New patch tag
docker tag applicationimage:latest applicationimage:2.1.5
docker push applicationimage:2.1.5
```

还可以引入其他标签，以添加到构建系统 ID 或用于图像构建的 git 提交 SHA-1 哈希的相关性。

# 确保图像供应链的完整性

提供图像供应链的内容信任是管理 Docker 图像中最重要但经常被忽视的主题之一。在任何通过不受信任的媒介（如互联网）进行通信和数据传输的分布式系统中，提供内容信任的手段至关重要，即验证进入系统的数据的来源（发布者）和完整性。对于 Docker 来说，这对于推送和拉取图像（数据）尤为重要，这是由 Docker 引擎执行的。

Docker 生态系统描述了**Docker 内容信任**（**DCT**）的概念，它提供了一种验证数据数字签名的方法，这些数据在 Docker 引擎和 Docker 注册表之间传输。此验证允许发布者对其图像进行签名，并允许消费者（Docker 引擎）验证签名，以确保图像的完整性和来源。

在 Docker CLI 中，可以使用`docker trust`命令对图像进行签名，该命令构建在 Docker Notary 之上。这是用于发布和管理受信任内容集合的工具。签署图像需要具有关联的 Notary 服务器的 Docker 注册表，例如 Docker Hub。

要了解有关私有 Azure 容器注册表的内容信任的更多信息，请参阅[`docs.microsoft.com/en-us/azure/container-registry/container-registry-content-trust`](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-content-trust)。

# 签署图像

例如，我们将对本章中已构建并推送到 Docker Hub 的一个 Docker 镜像进行签名，即`packtpubkubernetesonwindows/iis-demo-index`。要跟进，请在自己的镜像存储库`<dockerId>/iis-demo-index`上执行操作。签名可以通过以下步骤完成：

1.  生成委托密钥对。在本地，可以使用以下命令执行：

```
docker trust key generate <pairName>
```

1.  您将被要求为私钥输入密码。选择一个安全的密码并继续。私人委托密钥将默认存储在`~/.docker/trust/private`中（也在 Windows 上），公共委托密钥将保存在当前工作目录中。

1.  将委托公钥添加到公证服务器（对于 Docker Hub，它是`notary.docker.io`）。加载密钥是针对特定镜像存储库执行的，在 Notary 中，它由**全局唯一名称**（**GUN**）标识。对于 Docker Hub，它们的形式为`docker.io/<dockerId>/<repository>`。执行以下命令：

```
docker trust signer add --key <pairName>.pub <signerName> **docker.io/<dockerId>/<repository>**

**# For example**
**docker trust signer add --key packtpubkubernetesonwindows-key.pub packtpubkubernetesonwindows docker.io/packtpubkubernetesonwindows/iis-demo-index** 
```

1.  如果您是第一次为存储库执行委托，系统将自动要求使用本地 Notary 规范根密钥进行初始化。

1.  给镜像打上一个特定的标签，以便进行签名，如下所示：

```
docker tag packtpubkubernetesonwindows/iis-demo:latest packtpubkubernetesonwindows/iis-demo:1.0.1
```

1.  使用私人委托密钥对新标签进行签名并将其推送到 Docker Hub，如下所示：

```
docker trust sign packtpubkubernetesonwindows/iis-demo:1.0.1
```

1.  或者，这可以通过`docker push`执行，前提是您在推送之前在 PowerShell 中设置了`DOCKER_CONTENT_TRUST`环境变量：

```
$env:DOCKER_CONTENT_TRUST=1
docker tag packtpubkubernetesonwindows/iis-demo:latest packtpubkubernetesonwindows/iis-demo:1.0.2
docker push packtpubkubernetesonwindows/iis-demo:1.0.2
```

1.  现在，您可以检查存储库的远程信任数据：

```
docker trust inspect --pretty docker.io/packtpubkubernetesonwindows/iis-demo:1.0.1
```

接下来，让我们尝试在客户端启用 DCT 运行容器。

# 为客户端启用 DCT

为了在使用 Docker CLI 进行`push`、`build`、`create`、`pull`和`run`时强制执行 DCT，您必须将`DOCKER_CONTENT_TRUST`环境变量设置为`1`。默认情况下，Docker 客户端禁用了 DCT。按照以下步骤：

1.  在当前的 PowerShell 会话中设置`DOCKER_CONTENT_TRUST`环境变量：

```
$env:DOCKER_CONTENT_TRUST=1
```

1.  使用刚刚创建的签名镜像运行一个新容器：

```
docker run -d --rm docker.io/packtpubkubernetesonwindows/iis-demo:1.0.1
```

1.  您会注意到容器可以正常启动。现在，尝试使用未签名的`latest`标签创建一个新容器：

```
PS C:\src> docker run -d --rm docker.io/packtpubkubernetesonwindows/iis-demo:latest
C:\Program Files\Docker\Docker\Resources\bin\docker.exe: No valid trust data for latest.
See 'C:\Program Files\Docker\Docker\Resources\bin\docker.exe run --help'.
```

这个简短的场景展示了如何使用 DCT 来确保用于容器创建的镜像的完整性和来源。

# 摘要

在本章中，您了解了 Docker 生态系统如何提供基础设施来存储和共享容器映像，使用 Docker 注册表进行演示。使用公共 Docker Hub 和使用 Azure CLI 从头开始设置的私有 Azure 容器注册表演示了图像注册表和自动云构建的概念。您还了解了使用语义版本控制方案对图像进行标记和版本控制的最佳实践。最后，您还了解了如何使用**Docker 内容信任**（**DCT**）确保图像的完整性。

在下一章中，我们将深入研究 Kubernetes 生态系统，以了解一些关键概念以及它们目前如何支持 Windows 容器。

# 问题

1.  Docker 注册表是什么，它与 Docker Hub 有何关系？

1.  什么是图像标签？

1.  Docker Hub 的标准图像存储库命名方案是什么？

1.  Azure 容器注册表是什么，它与 Docker Hub 有何不同？

1.  什么是`latest`标签，何时建议使用它？

1.  如何使用语义版本控制对图像进行版本控制（标记）？

1.  为什么要使用 Docker 内容信任？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关管理 Docker 容器映像和映像注册表的更多信息，请参考以下 Packt 图书：

+   *Docker on Windows: From 101 to production with Docker on Windows* ([`www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition`](https://www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition))

+   *Learn Docker – Fundamentals of Docker 18.x* ([`www.packtpub.com/networking-and-servers/learn-docker-fundamentals-docker-18x`](https://www.packtpub.com/networking-and-servers/learn-docker-fundamentals-docker-18x))

+   如果您想了解 Azure 容器注册表及其如何适应 Azure 生态系统的更多信息，请参考以下 Packt 图书：

+   *Azure for Architects – Second Edition* ([`www.packtpub.com/virtualization-and-cloud/azure-architects-second-edition`](https://www.packtpub.com/virtualization-and-cloud/azure-architects-second-edition))

+   您还可以参考官方的 Docker 文档，其中对 Docker Hub ([`docs.docker.com/docker-hub/`](https://docs.docker.com/docker-hub/))和开源 Docker 注册表 ([`docs.docker.com/registry/`](https://docs.docker.com/registry/))进行了很好的概述。
