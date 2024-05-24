# Azure 上的 Linux 管理实用指南（一）

> 原文：[`zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F`](https://zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本课程的覆盖范围、开始所需的技术技能，以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于《在 Azure 上进行实践 Linux 管理，第二版》

由于微软 Azure 在提供可扩展的云解决方案方面具有灵活性，它是管理所有工作负载的合适平台。你可以使用它来实现 Linux 虚拟机和容器，并使用开放 API 在开源语言中创建应用程序。

这本 Linux 管理书首先带领你了解 Linux 和 Azure 的基础知识，为后面更高级的 Linux 功能做准备。通过真实世界的例子，你将学习如何在 Azure 中部署虚拟机（VMs），扩展其功能，并有效地管理它们。你将管理容器并使用它们可靠地运行应用程序，在最后一章中，你将探索使用各种开源工具进行故障排除的技术。

通过本书，你将熟练掌握在 Azure 上管理 Linux 和利用部署所需的工具。

### 关于作者

Kamesh Ganesan 是一位云倡导者，拥有近 23 年的 IT 经验，涵盖了 Azure、AWS、GCP 和阿里云等主要云技术。他拥有超过 45 个 IT 认证，包括 5 个 AWS、3 个 Azure 和 3 个 GCP 认证。他担任过多个角色，包括认证的多云架构师、云原生应用架构师、首席数据库管理员和程序分析员。他设计、构建、自动化并交付了高质量、关键性和创新性的技术解决方案，帮助企业、商业和政府客户取得了巨大成功，并显著提高了他们的业务价值，采用了多云策略。

Rithin Skaria 是一位开源倡导者，在 Azure、AWS 和 OpenStack 中管理开源工作负载方面拥有超过 7 年的经验。他目前在微软工作，并参与了微软内部进行的几项开源社区活动。他是认证的微软培训师、Linux 基金会工程师和管理员、Kubernetes 应用程序开发人员和管理员，也是认证的 OpenStack 管理员。在 Azure 方面，他拥有 4 个认证，包括解决方案架构、Azure 管理、DevOps 和安全，他还在 Office 365 管理方面也有认证。他在多个开源部署以及这些工作负载迁移到云端的管理和迁移中发挥了重要作用。

Frederik Vos 居住在荷兰阿姆斯特丹附近的普尔梅伦德市，是一位高级虚拟化技术培训师，专注于 Citrix XenServer 和 VMware vSphere 等虚拟化技术。他专长于数据中心基础设施（虚拟化、网络和存储）和云计算（CloudStack、CloudPlatform、OpenStack 和 Azure）。他还是一位 Linux 培训师和倡导者。他具有教师的知识和系统管理员的实际经验。在过去的 3 年中，他一直在 ITGilde 合作社内担任自由培训师和顾问，为 Linux 基金会提供了许多 Linux 培训课程，比如针对 Azure 的 Linux 培训。

### 学习目标

通过本课程，你将能够：

+   掌握虚拟化和云计算的基础知识

+   了解文件层次结构并挂载新文件系统

+   在 Azure Kubernetes 服务中维护应用程序的生命周期

+   使用 Azure CLI 和 PowerShell 管理资源

+   管理用户、组和文件系统权限

+   使用 Azure 资源管理器重新部署虚拟机

+   实施配置管理以正确配置 VM

+   使用 Docker 构建容器

### 观众

如果您是 Linux 管理员或微软专业人士，希望在 Azure 中部署和管理工作负载，那么这本书适合您。虽然不是必需的，但了解 Linux 和 Azure 将有助于理解核心概念。

### 方法

本书提供了实践和理论知识的结合。它涵盖了引人入胜的现实场景，展示了 Linux 管理员如何在 Azure 平台上工作。每一章都旨在促进每项新技能的实际应用。

### 硬件要求

为了获得最佳的学生体验，我们建议以下硬件配置：

+   处理器：Intel Core i5 或同等级

+   内存：4 GB RAM（建议 8 GB）

+   存储：35 GB 可用空间

### 软件要求

我们还建议您提前准备以下内容：

+   安装有 Linux、Windows 10 或 macOS 操作系统的计算机

+   互联网连接，以便连接到 Azure

### 约定

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

“以下代码片段创建一个名为`MyResource1`的资源组，并指定 SKU 为`Standard_LRS`，该 SKU 代表了此上下文中的冗余选项。”

以下是一个代码示例块：

```
New-AzStorageAccount -Location westus '
  -ResourceGroupName MyResource1'
  -Name "<NAME>" -SkuName Standard_LRS
```

在许多情况下，我们使用了尖括号，`<>`。您需要用实际参数替换它，而不要在命令中使用这些括号。

### 下载资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Linux-Administration-on-Azure---Second-Edition`](https://github.com/PacktPublishing/Hands-On-Linux-Administration-on-Azure---Second-Edition)。您可以在相关实例中找到本书使用的 YAML 和其他文件。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！


# 第一章：探索微软 Azure 云

人们经常因为围绕**云计算**这个术语的模糊性而感到困惑。在这里，我们不是指诸如 OneDrive、Dropbox 等云存储解决方案。相反，我们指的是实际由组织、公司甚至个人使用的计算解决方案。

微软 Azure（以前称为**Windows Azure**）是微软的公共云计算平台。它提供了广泛的云服务，包括计算、分析、存储、网络等。如果你浏览 Azure 提供的服务列表，你会发现你几乎可以处理任何东西，从虚拟机到人工智能和机器学习。

从虚拟化的简要历史开始，我们将解释如何将物理硬件转化为虚拟化硬件，使得在许多方面超越了经典数据中心的边界成为可能。

之后，我们将解释云技术中使用的不同术语。

以下是我们将要涵盖的关键主题列表：

+   计算、网络和存储的虚拟化

+   云服务

+   云类型

## 云计算基础

当你开始学习新的**信息技术**（**IT**）学科时，通常会从研究基本概念（即理论）开始。然后你会熟悉架构，迟早你会开始动手实践，看看它在实践中是如何工作的。

然而，在云计算中，如果你不仅了解概念和架构，而且了解它的来源，那真的会很有帮助。我们不想给你上一堂历史课，但我们想向你展示过去的发明和想法仍然在现代云环境中使用。这将让你更好地理解云是什么，以及如何在你的组织中使用它。

以下是云计算的关键基础：

+   虚拟化

+   **软件定义的数据中心**（**SDDC**）

+   **面向服务的架构**（**SOA**）

+   云服务

+   云类型

让我们逐个看看这些，并了解这些术语指的是什么。

### 虚拟化

在计算中，虚拟化指的是创建设备或资源的虚拟形式，比如服务器、存储设备、网络，甚至操作系统。虚拟化的概念出现在 IBM 在 20 世纪 60 年代末和 70 年代初开发其分时共享解决方案时。**分时共享**指的是在大量用户之间共享计算资源，提高用户的生产力，消除为每个用户购买计算机的需要。这是计算技术革命的开始，新计算机的购买成本大大降低，组织可以利用他们已经拥有的未充分利用的计算资源。

现在，这种虚拟化已经发展成基于容器的虚拟化。虚拟机有自己的操作系统，在物理服务器的顶部虚拟化；另一方面，一个机器上的容器（无论是物理的还是虚拟的）都共享相同的基础操作系统。我们将在*第九章《Azure 中的容器虚拟化》*中更多地讨论容器。

快进到 2001 年，另一种虚拟化类型被引入，称为硬件虚拟化，由 VMware 等公司推出。在他们的产品 VMware Workstation 中，他们在现有操作系统的顶部添加了一层，提供了一组标准硬件和内置软件，而不是物理元素来运行虚拟机。这个层被称为**hypervisor**。后来，他们建立了自己的操作系统，专门用于运行虚拟机：VMware ESXi（以前称为 ESX）。

2008 年，微软推出了 Hyper-V 产品，进入了硬件虚拟化市场，作为 Windows Server 2008 的可选组件。

硬件虚拟化就是将软件与硬件分离，打破硬件和软件之间的传统界限。一个 hypervisor 负责将虚拟资源映射到物理资源上。

这种类型的虚拟化是数据中心革命的推动者：

+   由于标准硬件的设置，每个虚拟机都可以在安装了 hypervisor 的任何物理机器上运行。

+   由于虚拟机彼此隔离，如果特定的虚拟机崩溃，它不会影响在同一 hypervisor 上运行的任何其他虚拟机。

+   因为虚拟机只是一组文件，您可以有新的备份、移动虚拟机等可能性。

+   新的选项变得可用，以改善工作负载的可用性，具有**高可用性**（**HA**）和即使虚拟机仍在运行也可以迁移虚拟机的可能性。

+   新的部署选项也变得可用，例如使用模板。

+   还有关于中央管理、编排和自动化的新选项，因为一切都是软件定义的。

+   隔离、保留和在需要时限制资源，在可能的情况下共享资源。

### SDDC

当然，如果您可以将硬件转换为计算机软件，那么很快就会有人意识到您也可以对网络和存储进行相同的操作。

对于网络，一切都始于虚拟交换机的概念。与其他形式的硬件虚拟化一样，这只是在软件中构建网络交换机，而不是在硬件中构建。

**互联网工程任务组**（**IETF**）开始着手一个名为**转发和控制元素分离**的项目，这是一个提议的标准接口，用于解耦控制平面和数据平面。2008 年，在斯坦福大学使用 OpenFlow 协议实现了这一目标的第一个真正的交换机实现。**软件定义网络**（**SDN**）通常与 OpenFlow 协议相关联。

使用 SDN，您可以获得与计算机虚拟化相似的优势：

+   中央管理、自动化和编排

+   通过流量隔离和提供防火墙和安全策略，实现更加精细的安全性

+   塑造和控制数据流量

+   HA 和可伸缩性的新选项

2009 年，**软件定义存储**（**SDS**）的开发在一些公司开始，比如 Scality 和 Cleversafe。同样，这是关于抽象化：将服务（逻辑卷等）与物理存储元素解耦。

如果您深入研究 SDS 的概念，一些供应商为虚拟化的已有优势添加了新功能。您可以向虚拟机添加策略，定义您想要的选项：例如，数据复制或**每秒输入/输出操作**（**IOPS**）的限制。这对于管理员来说是透明的；hypervisor 和存储层之间进行通信以提供功能。后来，这个概念也被一些 SDN 供应商采纳。

您实际上可以看到，虚拟化慢慢地将不同数据中心层的管理转变为更加面向服务的方法。

如果您可以虚拟化物理数据中心的每个组件，那么您就拥有了一个 SDDC。网络、存储和计算功能的虚拟化使得可以超越单一硬件的限制。通过将软件从硬件中抽象出来，SDDC 使得可以超越物理数据中心的边界。

在 SDDC 环境中，一切都是虚拟化的，并且通常完全由软件自动化。这完全改变了传统的数据中心概念。服务托管的位置或可用时间（24/7 或按需）并不重要。此外，还有可能监视服务，甚至添加自动报告和计费等选项，这些都会让最终用户感到满意。

SDDC 与云不同，甚至不同于在您的数据中心运行的私有云，但您可以争辩说，例如，Microsoft Azure 是 SDDC 的全面实现—Azure 从定义上来说是软件定义的。

### SOA

在硬件虚拟化成为数据中心主流并且 SDN 和 SDS 的开发开始的同时，软件开发领域出现了一些新的东西：SOA，它提供了几个好处。以下是一些关键点：

+   最小的服务可以相互通信，使用诸如**简单对象访问协议**（**SOAP**）之类的协议。它们一起提供完整的基于 Web 的应用程序。

+   服务的位置并不重要；服务必须意识到其他服务的存在，就是这样。

+   服务是一种黑匣子；最终用户不需要知道盒子里面有什么。

+   每个服务都可以被另一个服务替换。

对于最终用户来说，应用程序位于何处或由几个较小的服务组成并不重要。在某种程度上，这就像虚拟化：看起来是一个物理资源，例如存储**LUN**（逻辑单元编号），实际上可能包括多个位置的多个物理资源（存储设备）。正如前面提到的，如果一个服务意识到另一个服务的存在（它可能在另一个位置），它们将一起行动并交付应用程序。我们每天互动的许多网站都是基于 SOA 的。

虚拟化与 SOA 的结合为您提供了更多的可伸缩性、可靠性和可用性选项。

SOA 模型和 SDDC 之间存在许多相似之处，但也有区别：SOA 涉及不同服务之间的交互；SDDC 更多地涉及向最终用户提供服务。

SOA 的现代实现是微服务，由 Azure 等云环境提供，可以独立运行或在 Docker 等虚拟化容器中运行。

### 云服务

这就是那个神奇的词：*云*。**云服务**是由云解决方案或计算提供商（如 Microsoft Azure）提供给组织、公司或用户的任何服务。如果您想提供以下服务，则云服务是合适的：

+   高度可用并始终按需提供。

+   可以通过自助服务进行管理。

+   具有可伸缩性，使用户可以进行升级（使硬件更强大）或扩展（添加额外节点）。

+   具有弹性—根据业务需求动态扩展或收缩资源数量的能力。

+   提供快速部署。

+   可以完全自动化和编排。

除此之外，还有用于监视资源和新类型的计费选项的云服务：大多数情况下，您只需支付您使用的部分。

云技术是通过互联网提供服务，以便使组织能够访问诸如软件、存储、网络和其他类型的 IT 基础设施和组件等资源。

云可以为您提供许多服务类型。以下是最重要的几种：

+   **基础设施即服务**（**IaaS**）：托管虚拟机的平台。在 Azure 中部署的虚拟机就是一个很好的例子。

+   **平台即服务**（**PaaS**）：一个用于开发、构建和运行应用程序的平台，无需建立和运行自己的基础设施的复杂性。例如，有 Azure 应用服务，您可以将代码推送到 Azure，Azure 将为您托管基础设施。

+   **软件即服务**（**SaaS**）：在云中运行的即插即用应用程序，例如 Office 365。

尽管上述是云服务的关键支柱，您可能也会听说**FaaS**（**函数即服务**），**CaaS**（**容器即服务**），**SECaaS**（**安全即服务**），随着云中服务提供的数量日益增加，清单也在不断增加。Azure 中的函数应用将是 FaaS 的一个例子，Azure 容器服务将是 CaaS 的例子，Azure 活动目录将是 SECaaS 的例子。

### 云类型

云服务可以根据其位置或托管服务的平台进行分类。正如前一节中提到的，基于平台，我们可以将云服务分类为 IaaS、PaaS、SaaS 等；然而，基于位置，我们可以将云分类为：

+   **公共云**：所有服务都由服务提供商托管。微软的 Azure 就是这种类型的实现。

+   **私有云**：您自己的数据中心中的云。微软最近为此开发了 Azure 的特殊版本：Azure Stack。

+   **混合云**：公共云和私有云的组合。一个例子是结合 Azure 和 Azure Stack 的强大功能，但您也可以考虑新的灾难恢复选项，或者在临时需要更多资源时将服务从您的数据中心移到云端，然后再移到回来。

+   **社区云**：社区云是多个组织在同一共享平台上工作，前提是它们有类似的目标或目标。

选择这些云实现之一取决于几个因素；仅举几个例子：

+   **成本**：将您的服务托管在云中可能比在本地托管它们更昂贵，这取决于资源使用情况。另一方面，它可能更便宜；例如，您不需要实施复杂和昂贵的可用性选项。

+   **法律限制**：一些组织可能无法使用公共云。例如，美国政府有自己的名为 Azure Government 的 Azure 产品。同样，德国和中国也有他们自己的 Azure 产品。

+   **互联网连接**：仍然有一些国家的必要带宽甚至连接的稳定性是一个问题。

+   **复杂性**：特别是混合云环境可能难以管理；对应用程序和用户管理的支持可能具有挑战性。

## 了解微软 Azure 云

现在您已经更多地了解了虚拟化和云计算，是时候向您介绍云的微软实现：Azure。

重新开始，从一些历史开始，在这一部分，您将了解到 Azure 背后的技术，以及 Azure 可以成为您的组织的一个非常好的解决方案。

### 微软 Azure 云的简要历史

在 2002 年，微软启动了一个名为 Whitehorse 的项目，以简化在 SOA 模型中开发、部署和实施应用程序。在这个项目中，重点是提供小型、预构建的 Web 应用程序，并能够将它们转换为服务。这个项目在 2006 年左右悄然消失。

在那个项目中学到的许多经验教训以及**亚马逊网络服务**（**AWS**）的出现，促使微软在 2006 年启动了一个名为**RedDog**的项目。

过了一段时间，微软将另外三个开发团队加入了这个项目：

+   **.NET 服务**：为使用 SOA 模型的开发人员提供的服务。.NET 服务提供了作为安全、基于标准的消息基础设施的服务总线。

+   **Live 服务和 Live Mesh**：一个 SaaS 项目，通过互联网使 PC 和其他设备能够相互通信。

+   **SQL 服务**：通过互联网提供微软 SQL 的 SaaS 项目。

2008 年，微软宣布启动 Azure，并在 2010 年公开发布时，Azure 已准备好提供 IaaS 和 PaaS 解决方案。RedDog 这个名字存活了一段时间：经典门户也被称为**RedDog 前端**（**RDFE**）。经典门户基于**服务管理模型**。另一方面，Azure 门户基于**Azure 资源管理器**（**ARM**）。这两个门户基于两种不同的 API。

如今，Azure 是微软三个云服务之一（其他两个是 Office 365 和 Xbox），用于提供不同类型的服务，如虚拟机、Web 和移动应用程序、Active Directory、数据库等。

在功能、客户和可用性方面，Azure 仍在不断增长。Azure 在超过 54 个区域可用。这对于可伸缩性、性能和冗余性非常重要。

拥有这么多的区域也有助于遵守法律和安全/隐私政策。有关安全、隐私和合规性的信息和文件可通过微软的信任中心获取：[`www.microsoft.com/en-us/TrustCenter`](https://www.microsoft.com/en-us/TrustCenter)。

### Azure 架构

Microsoft Azure 运行在定制的、精简的、加固的 Hyper-V 版本上，也被称为**Azure Hypervisor**。

在这个虚拟化程序之上，有一个云层。这个层或基础架构是托管在微软数据中心中的许多主机的集群，负责部署、管理和维护基础设施的健康。

这个云层由基础架构控制器管理，负责资源管理、可伸缩性、可靠性和可用性。

这一层还通过基于 REST、HTTP 和 XML 的 API 提供管理界面。与基础架构控制器互动的另一种方式是通过 Azure 门户和诸如 Azure CLI 之类的软件通过 Azure 资源管理器。

以下是 Azure 架构的图示表示：

![Azure 架构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_01_01.jpg)

###### 图 1.1：Azure 架构

这些用户界面服务（Azure 门户、PowerShell、Azure CLI 和 API）将通过资源提供程序与基础架构进行通信。例如，如果您想要创建、删除或更新计算资源，用户将与称为**计算资源提供程序**（**CRP**）的**Microsoft.Compute**资源提供程序进行交互。同样，网络资源通过**网络资源提供程序**（**NRP**）或**Microsoft.Network**资源提供程序进行通信，存储资源通过**存储资源提供程序**（**SRP**）或**Microsoft.Storage**资源提供程序进行通信。

这些资源提供程序将创建所需的服务，比如虚拟机。

### 您的组织中的 Azure

Azure 可以提供 IaaS：轻松部署虚拟机，手动或自动化，并使用这些虚拟机开发、测试和托管您的应用程序。还有许多额外的服务可用，使您作为系统工程师的生活更加轻松，如备份和恢复选项、添加存储和可用性选项。对于 Web 应用程序，甚至可以在不创建虚拟机的情况下提供服务！

当然，Azure 也可以用于 PaaS 解决方案；与 IaaS 一样，PaaS 包括基础架构的所有组件，但还支持云应用程序的完整生命周期：构建、测试、部署、管理和更新。还有预定义的应用程序组件可用；您可以节省时间，将这些组件与您的代码一起转换为您想要提供的服务。容器也可以成为 PaaS 解决方案的一部分。Azure 容器服务简化了使用 Kubernetes 或其他编排器（如 Mesos）部署、管理和操作容器。

如果你是一家希望在 Azure 中托管 SaaS 解决方案的公司或组织，这是可能的，使用 AppSource。你甚至可以与其他微软产品（如 Office 365 和 Dynamics）进行集成。

2017 年，微软宣布推出 Azure Stack。现在你可以在自己的数据中心或选择的服务提供商的数据中心中运行 Azure，以提供 IaaS 和 PaaS。它为你提供了 Azure 的可伸缩性和可用性，而无需担心配置。只有在需要时才需要添加更多的物理资源。如果你愿意，你可以将其用于与公共 Azure 的混合解决方案，用于灾难恢复或云和本地部署中的一致工作负载。

Azure Stack 不是你可以用于混合环境的唯一选择。例如，你可以将本地 Active Directory 与 Azure Active Directory 连接，或者使用 Azure Active Directory 应用程序为本地和托管的 Web 应用程序提供单一登录（SSO）。

### Azure 和开源

2009 年，甚至在 Azure 公开之前，微软就开始为开源框架（如 PHP）添加支持，2012 年，由于许多客户的要求，微软添加了对 Linux 虚拟机的支持。

当时，微软并不是开源社区的好朋友，可以说他们真的不喜欢 Linux 操作系统。这种情况在 2014 年左右发生了变化，当时萨蒂亚·纳德拉（Satya Nadella）接替史蒂夫·鲍尔默（Steve Ballmer）担任微软首席执行官。在那一年的十月，他甚至在旧金山的一次微软大会上宣布*微软热爱 Linux！*

从那时起，Azure 已经发展成一个非常开源友好的环境：

+   它为许多开源解决方案提供了平台，如 Linux 实例、容器技术和应用/开发框架。

+   它通过提供开放和兼容的 API，与开源解决方案进行集成。例如，Cosmos DB 服务提供了与 MongoDB 兼容的 API。

+   文档、软件开发工具包（SDK）和示例都是开源的，可以在 GitHub 上找到：[`github.com/Azure`](https://github.com/Azure)。

+   微软正在与开源项目和供应商合作，并且也是许多开源项目的主要代码贡献者。

2016 年，微软以白金会员的身份加入了 Linux 基金会组织，以确认他们对开源开发兴趣和参与度稳步增加。

2017 年 10 月，微软表示 Azure 中超过 40%的虚拟机正在运行 Linux 操作系统，Azure 正在运行许多容器化的工作负载。从当前的统计数据来看，工作负载的数量已经超过 60%。此外，微服务都在使用开源编程语言和接口。

微软非常重视开源技术、开源 PowerShell 和许多其他产品。并非 Azure 中的每个微软产品都是开源的，但至少你可以在 Linux 上安装和运行 Microsoft SQL，或者获取 Microsoft SQL 的容器镜像。

## 总结

在本章中，我们讨论了虚拟化的历史和云的概念，并解释了云环境中使用的术语。

有些人认为微软进入云世界有点晚了，但实际上，他们从 2006 年开始研究和开发技术，其中许多部分在 Azure 中得以保留。一些项目因为太早而夭折，当时很多人对云持怀疑态度。

我们还介绍了 Azure 云的架构和 Azure 可以为您的组织提供的服务。

在本章的最后部分，我们看到 Azure 是一个非常开源友好的环境，微软付出了很多努力，使 Azure 成为一个开放、标准的云解决方案，具有互操作性。

在下一章中，我们将开始使用 Azure，并学习如何在 Azure 中部署和使用 Linux。

## 问题

1.  您的物理数据中心中的哪些组件可以转化为软件？

1.  容器虚拟化和硬件虚拟化有什么区别？

1.  如果您想在云中托管应用程序，哪种服务类型是最佳解决方案？

1.  假设您的某个应用程序需要严格的隐私政策。对于您的组织来说，使用云技术仍然是一个好主意吗？

1.  为什么 Azure 有这么多可用的区域？

1.  Azure Active Directory 的目的是什么？

## 进一步阅读

如果您想了解更多关于 Hyper-V 以及如何将 Azure 与 Hyper-V 一起用于站点恢复和工作负载保护的信息，请查看 Packt Publishing 的《Windows Server 2016 Hyper-V Cookbook, Second Edition》。

有许多关于虚拟化、云计算及它们之间关系的技术文章。我们想提到的一个是《虚拟化与云计算关系的正式讨论》（ISBN 978-1-4244-9110-0）。

不要忘记访问本章中提到的微软网站和 GitHub 存储库！


# 第二章：开始使用 Azure 云

在第一章中，我们介绍了虚拟化和云计算的历史和理念。之后，你了解了微软 Azure 云。本章将帮助你迈出 Azure 世界的第一步，获取 Azure 访问权限，探索不同的 Linux 提供，并部署你的第一个 Linux 虚拟机。

部署后，你将需要使用**安全外壳**（**SSH**）进行密码验证或使用 SSH 密钥对访问你的虚拟机。

要开始你的 Azure 云之旅，完成所有练习并检查结果非常重要。在本章中，我们将使用 PowerShell 以及 Azure CLI。随意选择你喜欢的方式进行跟随；然而，学习两者都不会有坏处。本章的关键目标是：

+   设置你的 Azure 帐户。

+   使用 Azure CLI 和 PowerShell 登录 Azure。

+   与**Azure 资源管理器**（**ARM**）交互以创建网络和存储资源。

+   了解 Linux 发行版和微软认可的发行版。

+   部署你的第一个 Linux 虚拟机。

#### 注意

本章中的所有内容都在 macOS、Linux 子系统和最新版本的 CentOS 和 openSUSE LEAP 上进行了测试。

## 技术要求

如果你想尝试本章中的所有示例，至少需要一个浏览器。出于稳定性的考虑，使用最新版本的浏览器非常重要。微软在官方 Azure 文档中提供了支持的浏览器列表：

+   微软 Edge（最新版本）

+   Internet Explorer 11

+   Safari（最新版本，仅限 Mac）

+   Chrome（最新版本）

+   Firefox（最新版本）

根据个人经验，我们建议使用 Google Chrome 或基于其引擎最新版本的浏览器，如 Vivaldi。

你可以在浏览器中完成所有练习，甚至包括命令行练习。实际上，使用本地安装的 Azure CLI 或 PowerShell 是个好主意；它更快，更容易复制和粘贴代码，你还可以保存历史和命令的输出。

## 获取 Azure 访问权限

开始使用 Azure，你需要的第一件事是一个帐户。前往[`azure.microsoft.com`](https://azure.microsoft.com)并获取一个免费帐户开始，或者使用已经在使用的公司帐户。另一个可能性是使用 Visual Studio 专业版或企业版订阅的 Azure，这将为你提供 Azure 的**微软开发者网络**（**MSDN**）积分。如果你的组织已经与微软签订了企业协议，你可以使用你的企业订阅，或者你可以注册一个按使用量付费的订阅（如果你已经使用了免费试用）。

如果你使用的是免费帐户，你将获得一些信用额度来开始，一些流行的服务有限时间内免费，以及一些永远免费的服务，如容器服务。你可以在[`azure.microsoft.com/en-us/free`](https://azure.microsoft.com/en-us/free)找到最新的免费服务列表。在试用期间，除了需要额外许可的虚拟机外，你不会被收费，但你需要一张信用卡来验证身份。

### 使用 Azure 门户登录

将浏览器指向[`portal.azure.com`](https://portal.azure.com)并使用你的凭据登录。你现在可以开始使用 Azure，或者换句话说，开始使用你的订阅。在 Azure 中，订阅允许你使用你的帐户使用 Azure 门户/Azure CLI/PowerShell 创建和部署资源。它也用于会计和计费。

Azure 门户将带你到一个仪表板，你可以根据自己的监控需求进行修改。你现在可以：

+   检查你的资源。

+   创建新资源。

+   访问 Marketplace，这是一个在线商店，你可以购买和部署专为 Azure 云构建的应用程序或服务。

+   了解您的计费情况。

您可以使用网络界面，以图形方式执行所有操作，或者通过网络界面使用 Azure Cloud Shell，它提供了 Bash 或 PowerShell 界面。

### 获取对 Azure 的命令行访问

有几个很好的理由使用命令行。这就是为什么在本书中，我们将主要介绍 Azure 命令行访问的原因：

+   它可以帮助您了解 Azure 的架构。在图形界面中，通常可以在一个配置窗口中执行许多操作，而不必了解不同字段和组件之间的关系。

+   这是自动化和编排的第一步。

+   网络界面仍在积极开发中；网络界面可以并且将会随着时间改变：

某些功能和选项目前尚不可用。

微软可能会在网络界面中重新定位功能和选项。

+   另一方面，命令行界面在语法和输出方面非常稳定。

在本书中，我们将在 Bash shell 中使用 Azure CLI 和带有 PowerShell Az 模块的 PowerShell。两者都非常适合，与平台无关，并且除了一两个例外之外，在功能上没有区别。选择您喜欢的，因为您已经熟悉它，或者尝试两种界面，然后选择。

#### 注意

请注意，从本书中复制和粘贴命令可能会由于空格和缩进而导致错误。为了获得更好的结果，请始终输入命令。此外，这将帮助您熟悉命令。

### 安装 Azure CLI

如果您在 Azure Cloud Shell 中使用 Bash 界面，那么可以使用完整的 Linux 环境来安装 Azure 命令行界面。它还提供了 Azure 特定的命令，比如 `az` 命令。

您也可以在 Windows、macOS 和 Linux 上安装此实用程序。还提供了 Docker 容器。您可以在 [`docs.microsoft.com/en-us/cli/azure`](https://docs.microsoft.com/en-us/cli/azure) 找到所有这些平台的详细安装说明。

让我们以 CentOS/**Red Hat Enterprise Linux** (**RHEL**) 7 为例来安装 Azure CLI：

1.  导入 Microsoft 存储库的 **GNU 隐私卫士** (**GPG**) 密钥：

```
sudo rpm --import \ https://packages.microsoft.com/keys/microsoft.asc
```

1.  添加存储库：

```
sudo yum-config-manager --add-repo= \    
  https://packages.microsoft.com/yumrepos/azure-cli
```

1.  安装软件：

```
sudo yum install azure-cli
```

1.  要在基于 Ubuntu 或 Debian 的系统上安装 Azure CLI，请使用以下命令：

```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash 
```

在 macOS 上，您必须首先安装 Homebrew，这是一个免费的开源软件包管理系统，简化了大多数开源软件的安装。

1.  打开终端并执行以下操作：

```
ruby -e "$(curl -fsSL \
 https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  更新 Homebrew 并安装 Azure CLI：

```
brew update && brew install azure-cli
```

1.  安装 Azure CLI 后，您可以使用以下命令验证已安装的版本：

```
az -v
```

### 使用 Azure CLI 登录

Azure CLI 是用于访问或管理 Azure 资源的命令行工具，好处是它适用于 macOS、Linux 和 Windows 平台。在使用 CLI 之前，您必须登录：

```
az login
```

此命令将打开浏览器，并要求您使用 Microsoft 帐户登录。如果出现错误，指出 shell 无法打开交互式浏览器，请使用 `az login –use-device-code`。这将生成一个代码，您可以在 [`www.microsoft.com/devicelogin`](https://www.microsoft.com/devicelogin) 中使用它完成身份验证。

如果成功，它将以 JSON 格式给出一些关于您的订阅的输出，比如您的用户名：

```
[
   {
     "cloudName": "AzureCloud",
         "id": "....",
         "isDefault": true,
         "name": "Pay-As-You-Go",
         "state": "Enabled",
         "tenantId": "....",
         "user": {
            "name": "....",
            "type": "user"
          }
    }
 ]
```

要再次获取此信息，请输入以下内容：

```
az account list 
```

您可以始终使用额外的参数将输出格式化为 JSON、JSONC、TABLE 或 TSV 格式。

JSON（或 JSONC，彩色变体）格式在编程和脚本语言中更容易解析：

![在命令提示符中显示订阅详细信息的输出以 JSON 格式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_01.jpg)

###### 图 2.1：以 JSONC 格式显示的订阅详细信息

**制表符分隔值**（**TSV**）是一个很好的主意，如果输出是单个值，如果您想要使用文本过滤实用程序（如 AWK），或者如果您想要将输出导出到电子表格中：

![输出显示命令提示符上的订阅详细信息，由制表符分隔](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_02.jpg)

###### 图 2.2：以制表符分隔的订阅详细信息

表格输出非常易于阅读，但比默认输出更受限制：

![输出显示命令提示符上的订阅详细信息，以表格格式显示](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_03.jpg)

###### 图 2.3：表格格式的订阅详细信息

要以表格格式获取已登录帐户具有访问权限的订阅列表，请执行以下命令：

```
az account list -o table
```

为了更容易阅读 JSON 输出，您还可以查询特定字段：

```
az account list -o table --query '[].[user.name]'
```

如果您已经拥有大量资源或帐户，浏览整个列表将非常困难。幸运的是，有一种方法可以深入了解输出并仅获取所需的信息。使用`--query`参数链接命令将帮助您执行此操作，使用称为 JMESPATH（[`jmespath.org`](http://jmespath.org)）的强大查询语言。再次查看`az account list`命令的 JSON 输出。此查询正在搜索`user`字段和`name`属性。

让我们回到登录过程。每次都这样做可能不是最用户友好的过程。更好的方法是创建服务主体，也称为应用程序注册，为特定应用程序提供凭据：

```
az ad sp create-for-rbac --name <APP_NAME>
```

您可以为应用程序提供名称，但是某些特殊字符是不允许的。原因是`APP_NAME`将创建一个 URL，因此在 URL 中禁止的所有字符都不能添加到`APP_NAME`中（例如@和%）。再次以 JSON 格式输出，将提供应用程序 ID（`appID`参数）：

```
{
    "appID": "....",
    "displayName": "APP_NAME",
    "name": "http://APP_NAME",
    "password": "....",
    "tenant": "...."
 }
```

请在记事本上记下输出，因为我们将使用这些值进行身份验证。应用程序或服务主体代表 Azure 租户中的对象。租户是指一个组织，通常表示为<yourcompany/yourname>.onmicrosoft.com，它管理和拥有 Microsoft 云服务的实例。从 Azure 的角度来看，部署的所有服务都将与订阅相关联，并且订阅将映射到租户。一个租户可以拥有托管不同服务的多个订阅。从前面的输出中，我们将获得以下值：

+   `appID`：应用程序 ID 类似于应用程序的用户名。我们将在登录时使用此 ID 作为用户名。

+   `displayName`：在创建应用程序时为应用程序指定的友好名称。我们通过`name`参数设置名称。

+   `name`：基于我们给定的名称的 URL。

+   `password`：这是我们创建的服务主体的密码。在登录时，我们将在密码字段中使用此值。

+   `tenant`：租户 ID；我们在前一段中讨论了租户。

需要访问的应用程序必顶由安全主体表示。安全主体定义了租户中用户/应用程序的访问策略和权限。这使得在登录期间对用户/应用程序进行身份验证，并在资源访问期间进行基于角色的授权成为可能。总之，您可以使用`appID`进行登录。

列出分配给新创建的`appID`的角色：

```
az role assignment list --assignee <appID> --o table
```

默认情况下使用贡献者角色。此角色具有对 Azure 帐户的读写权限。

现在，测试一下并注销：

```
az logout
```

现在，再次使用`appID`登录。您可以使用之前复制的值来完成身份验证：

```
az login --service-principal --username <appID> --tenant <tenant id>
```

不幸的是，没有办法将用户名、`appID`或`tenant id`存储在配置文件中。可选地，您可以将`--password`添加到命令中：

```
az login --service-principal --username <appID> --tenant <tenant id> --password <app_password> 
```

除了使用`az`命令输入完整命令之外，还可以以交互式 shell 模式打开它：

```
az interactive
```

这个 shell 最大的特点之一是它将终端分成两个窗口。在上屏幕上，您可以输入命令；在下屏幕上，您在输入命令时会得到帮助。命令、参数和通常参数值也支持自动完成。

### PowerShell

PowerShell 是由 Microsoft 开发的脚本语言，集成到.NET Framework 中。它是由 Jeffrey Snover、Bruce Payette 和 James Truher 于 2006 年设计的。PowerShell 不仅适用于 Windows，还适用于 Linux 和 macOS。您可以在 PowerShell 的 GitHub 存储库上找到使用这些操作系统的详细说明：[`github.com/PowerShell`](https://github.com/PowerShell)。

例如，在 RHEL 或 CentOS 中安装它，请按照以下步骤操作：

1.  如果您在安装 Azure CLI 时没有导入 Microsoft 存储库的 GPG 密钥，请执行此操作：

```
sudo rpm –import \  https://packages.microsoft.com/keys/microsoft.asc
```

1.  添加存储库：

```
sudo yum-config-manager --add-repo= \https://packages.microsoft.com/rhel/7/prod/
```

1.  安装软件：

```
sudo yum install -y powershell
```

1.  使用`pwsh -v`显示已安装的版本。

1.  输入 PowerShell：

```
pwsh
```

在 macOS 上，您需要 Homebrew 和 Homebrew Cask。Cask 扩展了 Homebrew 以安装更多和更大的应用程序：

1.  安装 Homebrew Cask：

```
brew tap caskroom/cask
```

1.  安装 PowerShell：

```
brew cask install powershell
```

1.  使用`pwsh -v`显示已安装的版本。

1.  进入 PowerShell：

```
pwsh
```

安装 PowerShell 后，您可以安装 Az 模块。根据您的互联网速度，下载模块可能需要一些时间。您将能够在 shell 中看到下载的进度：

```
Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force
```

PowerShell 使用`PowerShellGet` cmdlet 从 PowerShell Gallery 下载模块及其依赖项，PowerShell Gallery 是一个托管许多模块的在线存储库。请注意，您需要在 Windows 和 Linux 中具有管理员权限才能执行此操作。PowerShell Gallery 未配置为受信任的存储库：

```
Untrusted repository
You are installing the modules from an untrusted repository. If you trust this 
repository, change its InstallationPolicy value by running the Set-PSRepository
 cmdlet. Are you sure you want to install the modules from 'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help 
(default is "N"): A
```

在列表中用`[A] Yes to All`回答问题。

现在可能由于`force`参数，您安装了多个 Az 模块的版本。您可以使用以下命令验证多个版本的存在：

```
Get-InstalledModule -Name Az -AllVersions | '       select Name,Version 
```

默认情况下将使用最新版本，除非在导入模块时使用`-RequiredVersion`参数。

### 使用 PowerShell 登录

安装完成后，导入模块：

```
Import-Module -name Az
```

如果您不创建 PowerShell 脚本，而只在与 Azure 交互时在 PowerShell 环境中执行命令，您将需要再次执行此命令。但是，如果您愿意，您可以自动加载模块。

首先，通过执行以下命令找出您的 PowerShell 配置文件在文件系统上的位置：

```
$profile
```

在文本编辑器中打开或创建此文件，并添加以下行：

```
Import-Module -name Az
```

#### 注意

在实际创建此文件之前，可能需要创建目录结构。

现在您可以执行所有可用的 Azure 命令。

使用以下 cmdlet 登录：

```
Connect-AzAccount
```

这将打开一个交互式浏览器窗口，您可以使用您的凭据进行身份验证。如果结果没有显示租户 ID，请执行此操作：

```
Get-AzContext -ListAvailable | select Tenant
```

现在，使用您找到的租户 ID 再次登录：

```
Connect-AzAccount -Tenant <tenantID>
```

如果您有多个订阅，您可以添加`-Subscription`参数和订阅 ID。如前所述，创建服务主体可能是一个好主意：

```
$newsp = New-AzADServicePrincipal ' -DisplayName "APP_NAME" -Role Contributor
```

如果您不提及`DisplayName`，这是服务主体的友好名称，Azure 将以格式 azure-powershell-MM-dd-yyyy-HH-mm-ss 生成一个名称。接下来，您需要检索新创建的服务主体的应用程序 ID：

```
$newsp.ApplicationId
```

密码可以存储到一个变量中，该变量将被加密，我们必须解密它：

```
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newsp.Secret)
$UnsecureSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
```

`$UnsecureSecret`变量包含服务主体的密码。

为了能够进行身份验证，我们需要服务主体的凭据：

```
$creds = Get-Credential 
```

提供`ApplicationID`和密码，它们分别存储在`$newsp.ApplicationId`和`$UnsecureSecret`变量中。现在我们有了使用这些凭据连接到 Azure 所需的一切：

```
Connect-AzAccount -Credential $creds '
  -Tenant <tentant id> '
  -ServicePrincipal
```

现在，保存上下文：

```
Save-AzContext -Path $HOME/.Azure/AzureContext.json
```

必要时覆盖现有内容。退出 PowerShell 环境并执行 PowerShell。确保你已登录到 Azure 并使用以下命令验证上下文：

```
Get-AzContext
```

### Azure 资源管理器

在开始部署你的第一个 Linux 虚拟机之前，了解**Azure 资源管理器**（**ARM**）更加重要。

基本上，ARM 使你能够使用诸如存储和虚拟机之类的资源。为此，你必须创建一个或多个资源组，以便你可以执行生命周期操作，如在一个操作中部署、更新和删除资源组中的所有资源。

#### 注意

资源组必须在一个区域中创建，也被称为位置。请注意，不同区域提供的服务可能会有所不同。要了解更多关于这些差异的信息，请访问[`azure.microsoft.com/en-us/global-infrastructure/services/`](https://azure.microsoft.com/en-us/global-infrastructure/services/)。

Azure 有超过 54 个区域。如果一个位置不可用，需要为你的账户加入白名单。为此，你可以联系微软支持。要获取你的账户可用位置和支持的资源提供程序列表，请在 PowerShell 中执行以下命令：

```
Get-AzLocation | Select-Object Location
```

你也可以在 Bash 中执行以下操作：

```
az account list-locations --query '[].name'
```

然后，在其中一个区域创建一个资源组：

```
New-AzResourceGroup -Location westus2 -Name 'MyResource1'
```

现在，验证结果：

```
Get-AzResourceGroup | Format-Table
```

这是前述命令的 Bash 版本：

```
az group create --location westus2 --name MyResource2
```

要验证**Azure 资源管理器（ARM）**的结果，执行以下命令：

```
az group list -o table
```

除了使用区域和资源组，你还必须了解存储冗余的概念。可用的复制选项如下：

+   Standard_LRS：本地冗余存储

Premium_LRS：与 LRS 相同，但也支持文件存储。

Standard_GRS：地理冗余存储

Standard_RAGRS：读取访问地理冗余存储

+   Standard_ZRS：区域冗余存储；ZRS 不支持 Blob 存储

#### 注意

更多信息可在微软网站上找到：[`docs.microsoft.com/en-us/azure/storage/common/storage-redundancy`](https://docs.microsoft.com/en-us/azure/storage/common/storage-redundancy)。

理解这个概念很重要，因为与你的资源组一起，一个存储账户在一个区域是必需的。存储账户在 Azure 中提供了一个唯一的命名空间来存储数据（如诊断）和使用 Azure Files 等服务的可能性。要为这些数据配置冗余，你必须指定在这种情况下代表冗余选项的 SKU：

```
New-AzStorageAccount -Location westus '
  -ResourceGroupName MyResource1'
  -Name "<NAME>" -SkuName Standard_LRS
```

或者你可以通过 Azure CLI 执行：

```
az storage account create --resource-group MyResource2 
  --sku Standard_LRS --name <NAME>
```

存储账户名称必须在 Azure 中是唯一的，长度在 3 到 24 个字符之间，并且只能使用数字和小写字母。

## Linux 和 Azure

Linux 几乎无处不在，出现在许多不同的设备和环境中。有许多不同的风味，你可以选择使用什么。那么，你会选择什么？有很多问题，也有很多不同的答案。但有一件事是肯定的：在企业环境中，支持是很重要的。

### Linux 发行版

如前所述，周围有许多不同的 Linux 发行版。但为什么有这么多选择呢？有很多原因：

+   Linux 发行版是一组软件。有些集合是为了特定的目标。这样一个发行版的一个很好的例子是 Kali Linux，它是一个先进的渗透测试 Linux 发行版。

+   Linux 是一个多用途操作系统。由于我们对 Linux 有很多定制选项，如果你不想要操作系统上的特定软件包或功能，你可以删除它并添加自己的。这是为什么有这么多发行版的主要原因之一。

+   开源天生是达尔文主义的。有时，一个项目会被分叉，例如因为其他开发人员不喜欢项目的目标，或者认为他们可以做得更好，而项目的补丁没有被接受。只有最强大的项目才能生存下来。

+   这是一个品味问题。不同的人有不同的品味和观点。有些人喜欢 Debian 的`apt`软件包管理器；其他人可能喜欢 SUSE 的 Zypper 工具。

+   另一个重要的区别是，一些发行版是由 Red Hat、SUSE 和 Canonical 等供应商收集和支持的，而另一些如 Debian 则是由社区驱动的。

在生产环境中，支持是很重要的。在将他们的生产工作负载推送到一个发行版之前，组织将关注某些因素，如 SLA、停机时间和安全更新，可能会出现以下问题：

+   谁负责更新，更新中包含什么样的信息？

+   谁负责支持，如果出现问题我该找谁？

+   如果软件许可存在法律问题，谁会为我提供建议？

### 微软认可的 Linux 发行版

在 Azure 市场上，有第三方提供的 Linux 映像，也称为微软合作伙伴提供的 Microsoft 认可的 Linux 发行版。

Microsoft 与这些合作伙伴和 Linux 社区一起合作，以确保这些 Linux 发行版在 Azure 上运行良好。

您可以将自己的映像，甚至自己的 Linux 发行版导入 Azure。微软直接为 Linux 内核做出贡献，为 Hyper-V 和 Azure 提供 Linux 集成服务，因此只要支持编译到内核中，您就可以在 Azure 上运行任何 Linux 发行版。此外，在 Azure 市场上的每个 Linux 映像中都安装了 Azure Linux 代理，并且该代理的源代码也可以在 GitHub 上找到，因此您可以在映像中安装它。微软甚至愿意在您遇到 Linux 问题时为您提供指导；只需购买支持计划！

对于一些商业 Linux 发行版，有很好的支持选项：

+   Red Hat：Microsoft 支持将帮助您使用 Azure 平台或服务，并且还将支持 Red Hat 内部的问题，但这需要一个支持计划。

+   Oracle Linux：Microsoft 提供支持计划；还可以从 Oracle 购买额外的商业支持。

+   SUSE：有 Microsoft 支持的高级映像；如果需要，他们会为您调用 SUSE。这个 SUSE 高级映像包括所有软件、更新和补丁。

+   其他供应商：有 Microsoft 支持计划来覆盖其他供应商；您不必为此购买单独的计划。Microsoft 计划详情可在[`azure.microsoft.com/en-us/support/plans/`](https://azure.microsoft.com/en-us/support/plans)上找到。

#### 注意

请访问微软网站获取最新的认可发行版和版本列表，以及有关发行版可用支持的详细信息：

[`docs.microsoft.com/en-us/azure/virtual-machines/linux/endorsed-distros`](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/endorsed-distros )

## 部署 Linux 虚拟机

我们已经介绍了 Azure 中可用的 Linux 发行版以及您可以获得的支持水平。在上一节中，我们通过创建资源组和存储来设置了初始环境；现在是时候部署我们的第一个虚拟机了。

### 您的第一个虚拟机

资源组已创建，此资源组中已创建存储帐户，现在您可以在 Azure 中创建您的第一个 Linux 虚拟机了。

在 PowerShell 中，使用以下命令：

```
 New-AzVM -Name "UbuntuVM" -Location westus2 '
  -ResourceGroupName MyResource1 '
  -ImageName UbuntuLTS -Size Standard_B1S
```

该 cmdlet 将提示您为虚拟机提供用户名和密码：

![在 Powershell 中为您的虚拟机提供用户名和密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_04.jpg)

###### 图 2.4：为您的虚拟机提供用户凭据

在 Bash 中，您可以使用以下命令：

```
az vm create --name UbuntuVM --resource-group MyResource2 \
  --image UbuntuLTS --authentication-type password \
  --admin-username student --size Standard_B1S
```

这非常简单，但是如果您以这种方式创建虚拟机实例，则可以设置的选项数量非常有限。 此过程将使用默认设置创建虚拟机所需的多个资源，例如磁盘、NIC 和公共 IP。

让我们深入了解一下细节，并获取有关所做选择的一些信息。

### 图像

在我们的示例中，我们部署了一个名为`UbuntuLTS`的图像的虚拟机。 您可以在几个 Linux 图像之间进行选择：

+   CentOS

+   Debian

+   RHEL

+   UbuntuLTS

+   CoreOS

+   openSUSE

+   SUSE Linux Enterprise

但是，不同供应商提供了许多更多的图像，称为发布商。

让我们获取这些发布商的列表。 在 PowerShell 中，使用此命令：

```
Get-AzVMImagePublisher -Location <REGION>
```

如您在以下截图中所见，Azure 有很多发布商，我们将从中选择一个进行演示：

![Powershell 中各种图像发布商及其位置的列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_05.jpg)

###### 图 2.5：在 PowerShell 中列出图像发布商

在 Bash 中，您可以运行以下命令来获取发布商的列表：

```
az vm image list-publishers --location <REGION> --output table
```

列表是相同的：

![Bash 中各种图像发布商及其位置的列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_06.jpg)

###### 图 2.6：在 Bash 中列出图像发布商

现在您知道发布商，可以使用以下命令获取发布商提供的图像列表：

```
Get-AzVMImageOffer -Location <REGION> '
  -PublisherName <PUBLISHER> | select offer
```

我们已经选择了`Canonical`作为发布商，现在我们正在尝试获取可用的优惠列表。 `UbuntuServer`是其中之一，我们将使用这个：

![在 Powershell 中选择 Canonical 作为发布商并选择其优惠](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_07.jpg)

###### 图 2.7：列出 Canonical 发布商的优惠

或者，在 Azure CLI 中运行以下命令：

```
az vm image list-offers --location <REGION> '
  --publisher <PUBLISHER> --output table
```

输出是所谓的*优惠*列表。 优惠是由发布商创建的一组相关图像的名称。

现在我们需要知道图像的可用 SKU。 SKU 是指发行版的主要版本。 以下是使用 Ubuntu 的示例：

```
Get-AzVMImageSku -PublisherName <publisher> -Offer <offer>'
 -Location <location>
```

现在我们已经获得了发布商和优惠的值，让我们继续查看由`Canonical`发布的`UbuntuServer`可用的主要发行版（SKU）：

![Canonical 发布商为 UbuntuServer 提供的各种 SKU 的列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_08.jpg)

###### 图 2.8：在 Azure CLI 中列出由 Canonical 发布的 UbuntuServer 的 SKU

或者，在 Azure CLI 中运行以下命令：

```
az vm image list-skus --location <LOCATION> \
  --publisher <PUBLISHER> --offer <OFFER> -o table
```

查询此优惠中的特定实例：

```
Get-AzureVMImage -Location <REGION>'
 -PublisherName <PUBLISHER> -Offer <OFFER> '
 -Skus <SKU> | select Version -last 1 
```

让我们再次查看我们拥有的值。 因此，使用发布商名称、优惠和 SKU，我们将获取可用的版本。 在以下截图中，您可以看到图像版本`19.10.201912170`可用。 让我们为我们的虚拟机选择此图像：

![在 Azure CLI 中使用发布商的名称、优惠和 SKU 获取可用图像的版本详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_09.jpg)

###### 图 2.9：在 Azure CLI 中选择可用的图像版本

这是在撰写本章时提供的最新版本。 如果有任何新版本发布，您可能会看到另一个版本号。

或者，在 Azure CLI 中使用以下命令：

```
az vm image list --location <REGION> --publisher <PUBLISHER> \
  --offer <OFFER> --sku <SKU> --all --query '[].version' \
  --output tsv | tail -1
```

为了将输出减少到最新版本，添加了参数以选择最后一行。 收集的信息包含`Set-AzVMSourceImage` cmdlet 的参数; 但是，在使用此命令之前，我们需要使用`New-AzVMConfig`创建一个新的虚拟机配置：

```
$vm = New-AzVmConfig -VMName <name> -VMSize "Standard_A1"
Set-AzVMSourceImage -PublisherName <PUBLISHER>'
  -Offer <OFFER> -Skus <SKU> -Version <VERSION>
```

最后，我们正在创建一个大小为`Standard_A1`的新虚拟机，并指示 PowerShell 使用`Canonical`发布的`UbuntuServer`优惠中的`19_10-daily-gen2`发行版的图像版本`19.10.201912170`：

![通过指示 Powershell 使用图像版本创建一个大小为 Standard_A1 的新虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_10.jpg)

###### 图 2.10：创建一个 Standard_A1 大小的虚拟机

在 Bash 中，收集的信息包含`az vm create`命令的参数：

```
az vm create --name UbuntuVM2 --resource-group Packt-Testing-2   --image canonical:UbuntuServer:19_10-daily-gen2:19.10.201912170 --authentication-type password   --admin-username pacman --size Standard_B1S 
```

#### 注意

在 Bash 和 PowerShell 中，可以使用单词*latest*代替特定版本。收集的信息不足以创建虚拟机。需要更多参数。

### 虚拟机大小

另一件您需要注意的事情是根据您的需求和成本决定虚拟机的大小。有关可用大小和定价的更多信息，请访问[`azure.microsoft.com/en-us/pricing/details/virtual-machines/linux`](https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux)。

该网站上的列表（包括实例的价格）经常更改！您可以在命令行上获取列表（而不显示成本）：

```
Get-AzVMSize -Location <REGION> | Format-Table
az vm list-sizes --location <REGION> -o table
```

一个小型虚拟机足以执行本书中的练习。在撰写本文时，`Standard_B1ls`是必要的基本性能。但最好重新检查虚拟机的大小/定价列表，如前面提到的。

在 PowerShell 中，`New-AzVM` cmdlet 可以使用`-size`参数，或者可以在`New-AzVMConfig` cmdlet 中使用它：

```
New-AzVMConfig -VMName "<VM NAME>" -VMSize <SIZE>
```

在 Bash 中，添加`az vm create`命令的`--size`参数。

### 虚拟机网络

Azure 虚拟网络允许虚拟机、互联网和其他 Azure 服务之间通过安全网络进行通信。当我们在本章开头创建第一个虚拟机时，有关网络的几个项目是自动创建的：

+   虚拟网络

+   虚拟子网

+   附加到虚拟机并插入虚拟网络的虚拟网络接口

+   配置在虚拟网络接口上的私有 IP 地址

+   公共 IP 地址

网络资源将在*第四章，管理 Azure*中介绍；目前，我们只会查询虚拟机的私有和公共 IP 地址。使用此命令获取公共 IP 地址列表：

```
Get-AzPublicIpAddress -ResourceGroupName <RESOURCE GROUP>'
 | select Name,IpAddress
```

要获取所有虚拟机的私有 IP 地址列表，请使用以下命令：

```
Get-AzNetworkInterface -ResourceGroupName <resource group name> | ForEach { $interface = $_.Name; $ip = $_ | Get-AzNetworkInterfaceIpConfig | Select PrivateIPAddress; Write-Host $interface $ip.PrivateIPAddress }
```

前面的命令可能看起来有点复杂，但这是一个方便的脚本，用于获取私有 IP 列表。如果您想要获取资源组中虚拟机的私有 IP 地址，可以使用以下命令：

```
Get-AzNetworkInterface -ResourceGroup <resource group name>
```

获取的输出将以 JSON 格式显示，并且您可以在`IpConfigurations`下看到私有 IP 地址：

![以 JSON 格式显示资源组中虚拟机的私有 IP 地址的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_11.jpg)

###### 图 2.11：资源组中虚拟机的私有 IP 地址

这也可以使用 Azure CLI 来完成。要获取虚拟机的私有 IP 地址列表，请使用以下命令：

```
az vm list-ip-addresses --resource <RESOURCE GROUP> --output table
```

公共 IP 地址是使虚拟机通过互联网访问的 IP 地址。进入此 IP 地址的虚拟机网络流量经历**网络地址转换**（**NAT**）以配置在 Linux 虚拟机的网络接口上的私有 IP 地址。

### 虚拟机信息

虚拟机部署后，可以使用 PowerShell 和 Bash 获取附加到虚拟机的所有信息，例如状态。查询状态很重要；有几种状态：

+   运行中

+   已停止

+   失败

+   已停止

如果虚拟机未停止，Microsoft 将向您收费。`Failed`状态表示虚拟机无法启动。要查询状态，请执行以下命令：

```
Get-AzVM -Name <VM NAME> -Status -ResourceGroupName <RESOURCE GROUP>
```

在 Bash 中，可以接收部署的虚拟机的状态，但如果需要将输出缩小到单个实例，则无法使用复杂的查询：

```
az vm list --output table
```

要停止虚拟机，首先停止它：

```
Stop-AzVM -ResourceGroupName <RESOURCE GROUP> -Name <VM NAME>
```

现在您可以将其停止：

```
az vm deallocate --name <VM NAME> --resource-group <RESOURCE GROUP>
```

您可以获取有关部署的虚拟机的更多信息。在 PowerShell 中，很难接收虚拟机的属性。首先，创建一个变量：

```
$MYVM=Get-AzVM -Name <VM NAME> -ResourceGroupName <RESOURCE GROUP>
```

现在要求此`MYVM`对象的属性和方法：

```
$MYVM | Get-Members 
```

查看`HardwareProfile`属性以查看此实例的大小：

```
$MYVM.HardwareProfile
```

或者，为了更精确地查看虚拟机信息，使用以下命令：

```
$MYVM.HardwareProfile | Select-Object -ExpandProperty VmSize
```

你也可以尝试`NetworkProfile`、`OSProfile`和`StorageProfile.ImageReference`。

如果你想在 Bash 中使用`az`命令，你可能想尝试的第一个命令是这个：

```
az vm list –-resource-group <RESOURCE GROUP>
```

唯一的问题是它同时显示了所有虚拟机的所有信息；幸运的是，也有一个`show`命令，可以将输出减少到单个虚拟机：

```
az vm show --name <VM NAME> --resource-group <RESOURCE GROUP>
```

并且最好通过使用查询来限制输出。例如，如果你想查看特定虚拟机的存储配置文件，可以查询如下：

```
az vm show --name <VM NAME> --resource-group <RESOURCE GROUP>\
  --query 'storageProfile'
```

上述命令应该给出以下输出：

![查看 SUSE 虚拟机存储配置文件的命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_12.jpg)

###### 图 2.12：SUSE 虚拟机的存储配置文件

## 连接到 Linux

虚拟机正在运行，准备让您远程登录，使用您在部署第一台虚拟机时提供的凭据（用户名和密码）。另一种更安全的连接到 Linux 虚拟机的方法是使用 SSH 密钥对。由于其复杂性和长度，SSH 密钥更安全。此外，Azure 上的 Linux 支持使用**Azure 活动目录**（**Azure AD**）进行登录，用户将能够使用其 AD 凭据进行身份验证。

### 使用密码身份验证登录到您的 Linux 虚拟机

在*虚拟机网络*部分，查询了虚拟机的公共 IP 地址。我们将使用这个公共 IP 通过本地安装的 SSH 客户端连接到虚拟机。

**SSH**，或**安全外壳**，是一种加密的网络协议，用于管理和与服务器通信。Linux、macOS、**Windows 子系统**（**WSL**）和最近更新的 Windows 10 都配备了基于命令行的 OpenSSH 客户端，但也有更高级的客户端可用。以下是一些示例：

+   Windows：PuTTY、MobaXterm 和 Bitvise Tunnelier

+   Linux：PuTTY、Remmina 和 Pac Manager

+   macOS：PuTTY、Termius 和 RBrowser

使用 OpenSSH 命令行客户端连接到虚拟机：

```
ssh <username>@<public ip>
```

### 使用 SSH 私钥登录到您的 Linux 虚拟机

使用用户名和密码不是登录远程机器的最佳方式。这不是完全不安全的操作，但你仍然在连接中发送你的用户名和密码。如果你想远程执行脚本、执行备份操作等，这也很难使用。

另一种更安全的登录系统的方法是使用 SSH 密钥对。这是一对两个密码安全的密钥：私钥和公钥。

私钥由客户端保留，不应复制到任何其他计算机。它应该绝对保密。在创建密钥对时，最好用密码保护私钥。

另一方面，公钥可以复制到您想要管理的所有远程计算机上。这个公钥用于加密只有私钥才能解密的消息。当您尝试登录时，服务器通过使用密钥的这个属性来验证客户端拥有私钥。没有密码发送到连接中。

有多种方法可以创建 SSH 密钥对；例如，PuTTY 和 MobaXterm 都提供了创建工具。你必须在每台需要访问远程机器的工作站上执行此操作。在本书中，我们使用`ssh-keygen`，因为它适用于每个操作系统：

```
ssh-keygen
```

上述命令的输出应该如下所示：

![使用 ssh-keygen 命令创建 SSH 密钥对](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_02_13.jpg)

###### 图 2.13：使用 ssh-keygen 创建 SSH 密钥对

不要忘记输入密码！

要了解如何使用 SSH 密钥对访问您的虚拟机，让我们创建一个新的虚拟机。如果您还记得，当我们之前创建 Linux 机器时，我们使用了`az vm create`命令和`authentication-type`作为密码，但在下面的命令中，我们使用了`--generate-ssh-keys`参数。这将生成一个 SSH 密钥对，并将其添加到您的主目录中的`.ssh`目录中，可用于访问虚拟机：

```
az vm create --name UbuntuVM3 --resource-group MyResource2 \
  --admin-username student --generate-ssh-keys --image UbuntuLTS
```

如果您想在 PowerShell 中执行此操作，请使用`Add-AzVMSshPublicKey` cmdlet。有关该命令的更多信息，请参阅[`docs.microsoft.com/en-us/powershell/module/azurerm.compute/add-azurermvmsshpublickey?view=azurermps-6.13.0`](https://docs.microsoft.com/en-us/powershell/module/azurerm.compute/add-azurermvmsshpublickey?view=azurermps-6.13.0)。

虚拟机创建后，您将能够使用此命令访问它：

```
ssh student@<IP ADDRESS>
```

## 总结

本章介绍了 Microsoft Azure 的第一步。第一步始终涉及创建一个新帐户或使用现有的公司帐户。有了帐户，您就可以登录并开始发现 Azure 云。

在本章中，使用 Azure CLI 命令`az`或通过 PowerShell 发现了 Azure 云；通过示例，您了解了以下内容：

+   Azure 登录过程

+   区域

+   存储帐户

+   由出版商提供的图像

+   虚拟机的创建

+   查询附加到虚拟机的信息

+   Linux 是什么以及 Linux 虚拟机的支持

+   使用 SSH 和 SSH 密钥对访问 Linux 虚拟机

下一章从这里开始，带着一个新的旅程：Linux 操作系统。

## 问题

1.  使用命令行访问 Microsoft Azure 的优势是什么？

1.  存储帐户的目的是什么？

1.  您是否能想到为什么会收到以下错误消息？

```
Code=StorageAccountAlreadyTaken
Message=The storage account named mystorage is already taken.
```

1.  提供的报价和图像之间有什么区别？

1.  停止和取消分配虚拟机之间有什么区别？

1.  使用私有 SSH 密钥进行身份验证访问 Linux 虚拟机的优势是什么？

1.  `az vm create`命令有一个`--generate-ssh-keys`参数。创建了哪些密钥，它们存储在哪里？

## 进一步阅读

这一章绝不是关于使用 PowerShell 的教程。但是，如果您想更好地理解示例，或者想更多地了解 PowerShell，我们建议您阅读 Packt Publishing 的*Mastering Windows PowerShell Scripting – Second Edition*（ISBN：9781787126305）。我们建议您从第二章*使用 PowerShell*开始，并至少继续到第四章*在 PowerShell 中使用对象*。

您可以在网上找到大量关于使用 SSH 的文档。一个很好的起点是这本 wikibook：[`en.wikibooks.org/wiki/OpenSSH`](https://en.wikibooks.org/wiki/OpenSSH)。

如果您希望更多地了解 Linux 管理，Packt Publishing 的*Linux Administration Cookbook*是一个很好的资源，特别是对于系统工程师。

要深入了解安全性和管理任务，这是一个很好的阅读材料：*Mastering Linux Security and Hardening*，作者是 Donald A. Tevault，由 Packt Publishing 出版。


# 第三章：基本的 Linux 管理

在部署了你的第一个 Linux 虚拟机（VM）之后，让我们登录，讨论一些基本的 Linux 命令，并学习如何在 Linux 环境中找到我们的方法。本章是关于基本的 Linux 管理，从 Linux shell 开始，用于与 Linux 系统交互。我们将讨论如何使用 shell 来完成我们的日常管理任务，比如访问文件系统，管理进程（如启动和终止程序）等等。

在本章的最后部分，我们将讨论自主访问控制（DAC）模型以及如何在 Linux 中创建、管理和验证用户和组，并根据用户名和组成员身份获取文件和目录的权限。我们还将涵盖更改文件所有权以及更改和验证基本权限和访问控制列表。

以下是本章的主要主题：

+   与 shell 交互和配置 shell

+   使用 man 页面获取帮助

+   通过 shell 处理和编辑文本文件

+   理解文件层次结构，管理文件系统和挂载新文件系统

+   管理进程

+   用户和组管理

## Linux Shell

在上一章中，我们创建了 VM 并使用 SSH 登录，但是我们如何与 Linux 机器交互并指示其执行任务呢？正如我们在本章开头提到的，我们将使用 shell。

我们将探索广泛使用的 Bash shell，配置 Bash shell 以及如何使用它。shell 是一个用户界面，您可以在其中执行以下操作：

+   与内核、文件系统和进程交互

+   执行程序、别名和 shell 内置

shell 提供以下功能：

+   脚本编写

+   自动补全

+   历史和别名

有许多不同的 shell 可用，例如 KornShell、Bash 和 Z shell（Zsh）。Bash 是几乎每个 Linux 系统上的默认 shell。它的开发始于 1988 年，作为最古老的 shell 之一 Bourne shell 的替代品。Bash 基于 Bourne shell 和从其他 shell（如 KornShell 和 C shell）中学到的经验教训。Bash 已成为最流行的 shell，并可在许多不同的操作系统上使用，包括 Windows 10、FreeBSD、macOS 和 Linux。

以下是添加到 Bash 版本 2.05a（2001 年发布）中的一些最重要的功能，这些功能使 Bash 成为最突出的 shell：

+   命令行编辑

+   历史支持

+   自动补全

+   整数计算

+   函数声明

+   文档（一种将文本输入到单独文件中的方法）

+   新变量，如`$RANDOM`和`$PPID`

最近，Z shell 变得越来越受欢迎；这个 shell 的开发始于 1990 年，可以看作是对 Bash 的扩展。它还具有与 Bash 的兼容模式。它具有更好的自动补全支持，包括自动更正和更高级的路径名扩展。其功能可以通过模块进行扩展，例如，以获取更多关于命令的帮助。值得一提的是 Oh-My-ZSH（https://github.com/robbyrussell/oh-my-zsh）和 Prezto（https://github.com/sorin-ionescu/prezto）项目：它们提供主题、高级配置和插件管理，使 Z shell 非常用户友好。所有这些好功能都是有代价的：Z shell 肯定比 Bash 更耗资源。

### 执行命令

shell 的最重要功能之一是可以执行命令。命令可以是以下之一：

+   Shell 内置（由相关 shell 提供的命令）

+   在文件系统上可执行

+   别名

要找出正在执行的命令类型，可以使用`type`命令：

```
type echo
```

添加`-a`参数将显示包含可执行文件`echo`的所有位置。在下面的截图中，我们可以看到当我们添加`-a`参数时，由于可执行文件的存在，shell 给出了对`/usr/bin/echo`目录的引用：

![使用 type 命令和参数-a 来查找名为 echo 的可执行文件的类型和位置。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_01.jpg)

###### 图 3.1：包含可执行文件 echo 的位置

让我们对`ls`做同样的操作：

```
type ls
```

所以，你将得到一个类似的输出`type ls`：

![运行命令 type -a ls 来显示包含可执行文件 ls 的位置。通过运行这个命令，我们也可以看到 ls 是 ls --color=auto 的别名](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_02.jpg)

###### 图 3.2：包含可执行文件 ls 的位置

在这里，我们可以看到`ls`是`ls --color=auto`命令的别名，添加了一些参数。别名可以替换现有命令或创建新命令。没有参数的`alias`命令会给出已经配置的别名：

![在不同的关键词上运行别名命令，以显示这些命令已经配置的别名。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_03.jpg)

###### 图 3.3：使用别名命令

`ll`别名是一个新创建命令的例子。`mv`命令是一个替换的例子。使用以下命令创建一个新的别名：

```
alias <command>='command to execute'
```

例如，要用`search`替换`grep`命令，执行以下命令：

```
alias search=grep
```

你创建的别名将被添加到`.bashrc`文件中。如果你想要移除一个创建的别名，可以使用`unalias`命令：

```
unalias <alias name>
```

如果你想要移除所有定义的别名，可以使用`unalias -a`。

`which`命令标识了`$PATH`变量中程序的位置。这个变量包含了一个目录列表，用于查找可执行文件。这样，你就不必提供完整的路径：

```
which passwd
```

输出告诉你它在`/usr/bin`目录中可用：

![使用 which 命令识别程序的位置。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_04.jpg)

###### 图 3.4：$PATH 变量中程序的目录位置

### 命令行编辑

在许多方面，输入 Bash shell 中的命令与在文本编辑器中工作是一样的。这可能是为什么有一些快捷键，比如跳转到行首，而且这些快捷键与两个最著名、最常用的文本编辑器 Emacs 和 vi 中的快捷键是一样的。

默认情况下，Bash 被配置为处于 Emacs 编辑模式。如果你想要检查当前的编辑模式，运行`set -o`。输出将告诉你 Emacs 或 vi 是否被设置为`on`。以下是一些非常重要的快捷键：

![列出了一些重要的 Bash shell 导航快捷键。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_05.jpg)

###### 图 3.5：Bash shell 快捷键列表

如果你想使用 vi 模式，执行以下命令：

```
set -o vi
```

要切换回 Emacs 模式，使用以下命令：

```
set -o emacs
```

#### 注意

vi 编辑器在本章的后面部分*使用文本文件*中有介绍。现在，你可以在命令模式下使用几乎每个命令，包括`导航`、`复制`和`粘贴`。

`set`命令是 Bash 内置命令，用于切换特定于 Bash 的属性。没有参数时，它会显示环境变量。

### 处理历史记录

Bash shell 提供了命令行工具，你可以用来处理用户的命令历史。你执行的每个命令都会在主目录的历史文件`~/.bash_history`中注册。要查看这个历史的内容，执行以下命令：

```
history
```

输出显示了一个已使用命令的编号列表；你可以简单地使用以下命令重做一个命令：

+   `!<number>`：根据历史列表编号执行命令。

+   `!<-number>`：例如，`!-2`执行了在历史记录中比上一条命令早两条的命令。

+   `!<first characters of the command>:` 这将执行以这个字符开头的最后一个项目。

+   `!!:` 重复执行上一条命令。您可以将其与其他命令结合使用。例如，`sudo !!`。

您可以使用*Ctrl* + *R*（Emacs 模式）或正斜杠（vi 命令模式）向后搜索历史记录。可以使用箭头键进行浏览。

历史文件不是在执行命令后直接编写的，而是在登录会话结束时。如果您在多个会话中工作，直接编写历史记录可能是一个好主意。要执行此操作，请执行以下操作：

```
history -a
```

要在另一个会话中读取刚保存的历史记录，请执行以下命令：

```
history -r
```

要清除当前会话的历史记录，请使用以下命令：

```
history -c
```

如果要将历史记录保存到文件中，可以执行以下命令：

```
history -w <filename>
```

因此，通过保存清除的历史记录，您清空了历史文件。

与历史记录一起工作的另一个好功能是您可以编辑它。假设您执行了`ls -alh`命令，但您需要`ls -ltr`。只需输入：

```
^alh^ltr
```

这实际上与以下内容相同：

```
!!:s/ltr/alh/
```

当然，您可以对历史记录中的每个条目执行此操作；例如，对于历史记录列表中的第 6 个条目，请使用：

```
!6:s/string/newstring/
```

有时您需要更灵活，想要编辑包含许多拼写错误的大行。输入`fc`命令。使用以下命令修复命令：

```
fc <history number> 
```

这将打开一个文本编辑器（默认为 vi），保存修改后，将执行修改后的命令。

### 自动补全

每个人都会犯错；没有人能记住每个参数。自动补全可以防止许多错误，并在输入命令时以多种方式帮助您。

自动补全适用于以下情况：

+   可执行文件

+   别名

+   Shell 内置

+   文件系统上的程序

+   文件名

+   参数，如果实用程序支持并且安装了`bash-completion`软件包

+   变量

如果 shell 配置为 Emacs 模式，请使用*Ctrl* + *I*来激活自动完成；如果 shell 配置为 vi 模式，您也可以使用*Ctrl* + *P*。

#### 注意

如果有多个可能性，您必须两次按*Ctrl* + *I*或*Ctrl* + *P*。

### Globbing

Globbing 是将 Linux shell 中包含通配符的非特定文件名扩展为一个或多个特定文件名的过程。Globbing 的另一个常用名称是路径名扩展。

Bash shell 中识别以下通配符：

+   `?`：一个字符。

+   `*`：多个字符。请注意，如果将此通配符用作第一个字符，则以点开头的文件名将不匹配。当然，您可以使用`.*`。

+   `[a-z], [abc]`：来自范围的一个字符。

+   `{a,b,c}`：a 或 b 或 c。

以下是使用通配符的一些不错的例子：

+   `echo *`：这将列出当前工作目录中的文件或目录。

+   `cd /usr/share/doc/wget*`：这将切换到以`wget`开头的目录名所在的`/usr/share/doc`目录。

+   `ls /etc/*/*conf`：这将列出`/etc`目录下所有目录中的所有`.conf`文件。以下是此命令的示例：

![运行命令 ls /etc/*/*conf 以显示/etc 目录下所有.conf 文件的图像。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_06.jpg)

###### 图 3.6：列出所有目录中的.conf 文件

+   `mkdir -p /srv/www/{html,cgi-bin,logs}`：这将在`/srv/www`目录下创建`html`、`cgi-bin`和`log`目录。

### 重定向

在 Unix 早期，开发人员之一 Ken Thompson 定义了*Unix 哲学*，这是一种基于经验的方法，旨在使一切尽可能模块化，并尽可能重用代码和程序。特别是在那些日子里，可重用性对性能原因很重要，并且提供了一种允许轻松维护代码的方法。

在 Peter H Salus 修改的*Unix 哲学*版本中，重定向的目标如下：

+   编写只做一件事并且做得很好的程序。

+   编写程序以协同工作。

+   编写处理文本流的程序，因为这是一个通用接口。

为了使这种哲学成为可能，开发了支持文件描述符或现代术语中的通信通道的程序。每个程序至少有三个通信通道：

+   标准输入（0）

+   标准输出（1）

+   标准错误（2）

此实现的一个很好的特性是您可以重定向通道。

将标准输出重定向到文件，使用以下命令：

```
command > filename
```

要将标准输出重定向并追加到现有文件中，请使用：

```
command >> filename
```

将标准错误和输出重定向到文件，如下所示：

```
command &> filename 
```

首先将标准输出重定向到文件，然后也将标准错误重定向到那里，使用：

```
command 2>&1 filename
```

要重定向标准输入，请使用以下命令：

```
filename < command
```

让我们进行一个活动，以帮助我们理解重定向的概念。请先运行命令，验证输出，然后使用以下方法将其重定向到文件。例如，运行`ls`并验证输出，然后使用`>`将输出重定向到`/tmp/test.list`。您始终可以使用`cat /tmp/test.list`检查文件：

```
ls > /tmp/test.list 

echo hello > /tmp/echotest 

echo hallo again >> /tmp/echotest 

ls -R /proc 2> /tmp/proc-error.test 

ls -R /proc &> /tmp/proc-all.test 

sort < /etc/services
```

输入重定向的特殊版本是`heredoc.txt`：

```
cat << EOF >> /tmp/heredoc.txt 
 this is a line 
 this is another line 
EOF
```

`cat`命令将标准输出连接并将其附加到`/tmp/heredoc.txt`文件中。由于键盘直到遇到标签（在本例中为`EOF`）之前不是标准输入，因此无法中断或中断命令。这种方法通常用于从脚本创建配置文件。

另一种可能性是使用`|`符号将一个命令的标准输出重定向到另一个命令的标准输入：

```
command | other command
```

例如：

```
ls | more
```

使用`tee`命令，您可以结合重定向和管道的功能。有时您希望确保`command 1`的输出被写入文件以进行故障排除或记录，并且同时将其管道传输到另一个命令的标准输入：

```
command 1 | tee file.txt | command 2
```

还可以使用`-a`参数将内容追加到文件中。

`tee`的另一个用例是：

```
<command> | sudo tee <file> 
```

这样，就可以在不使用复杂的`su`结构的情况下写入文件。

### 使用变量

每个命令行界面，即使没有高级脚本编写的可能性，也都有变量的概念。在 Bash 中，有两种类型的变量：

+   影响 Bash 行为或提供有关 Bash 的信息的内置或内部变量。一些示例包括`BASH_VERSION`，`EDITOR`和`PATH`。

+   已知一个或多个应用程序的环境变量，包括内置变量和用户定义变量。

要列出当前 shell 的环境变量，可以使用`env`或`printenv`命令。`printenv`还能够显示特定变量的内容：

![运行命令 printenv PATH 以列出当前 shell 的环境变量。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_07.jpg)

###### 图 3.7：使用 printenv 命令显示特定变量的内容

查看变量内容的另一种方法如下：

```
echo $VARNAME
```

要声明环境变量，请执行`var=value`。例如：

```
animal=cat 

echo $animal
```

要向值添加更多字符，请使用：

```
animal=$animal,dog 

echo $animal
```

`animal`变量只对当前 shell 可见。如果要将其导出到子进程，需要导出该变量：

```
export animal
```

Bash 还能够进行简单的计算：

```
a=$(( 4 + 2 ))
```

或者，您可以使用此命令：

```
let a=4+2 
echo $a 
```

另一个特性是将命令的输出放入变量中-一种称为嵌套的技术：

```
MYDATE=$(date +"%F")
echo $MYDATE
```

当然，这只是 Bash 能够做到的一小部分，但这应该足够让您学会如何处理 Bash 配置文件并根据需要修改它们，以使它们以您想要的方式运行。

### Bash 配置文件

Bash shell 有三个重要的系统范围配置文件：`/etc/profile`、`/etc/bashrc`和`/etc/environment`。这些文件的目的是存储关于您的 shell 的信息，如颜色、别名和变量。例如，在前一节中，我们添加了一些别名，它们存储在一个名为`bashrc`的文件中，这是一个配置文件。每个文件都有自己的目的；我们现在将逐个查看它们。

`/etc/profile`是一个在用户登录到系统时执行的脚本。修改此文件不是一个好主意；而是使用快捷方式`/etc/profile.d`目录。该目录中的文件按字母顺序执行，并且必须具有`.sh`作为文件扩展名。作为一个附注，`/etc/profile`不仅被 Bash shell 使用，而且被所有 Linux 的 shell 使用，除了 PowerShell。您还可以在主目录中创建一个特定于用户的配置文件脚本，`~/.bash_profile`，这也是特定于 Bash 的。

配置文件脚本的一些典型内容如下：

```
set -o vi  
alias man="pinfo -m" 
alias ll="ls -lv --group-directories-first" 
shopt -u mailwarn  
unset MAILCHECK
```

#### 注意

如果您使用 Ubuntu 或类似的发行版，默认情况下不会安装`pinfo`。运行`apt install pinfo`来安装它。

`shopt`命令更改了一些默认的 Bash 行为，比如检查邮件或 globbing 的行为。`unset`命令是`set`命令的相反。在我们的示例中，默认情况下，Bash 每分钟检查一次邮件；执行`unset MAILCHECK`命令后，`MAILCHECK`变量被移除。

`/etc/bashrc`脚本在任何用户调用 shell 或 shell 脚本时都会启动。出于性能原因，尽量保持它尽可能简洁。您可以使用特定于用户的`~/.bashrc`文件，如果退出 shell，则会执行`~/.bash_logout`脚本。`bashrc`配置文件通常用于修改提示符（`PS1`变量）：

```
DARKGRAY='\e[1;30m'
GREEN='\e[32m'
YELLOW='\e[1;33m'
PS1="\n$GREEN[\w] \n$DARKGRAY(\t$DARKGRAY)-(\u$DARKGRAY)-($YELLOW-> \e[m"
```

让我们看看`PS1`变量的参数：

+   颜色（比如传递给 PS1 变量的 GREEN、DARKGRAY）是用 ANSI 颜色代码定义的。

+   `\e`：ANSI 中的转义字符。

+   `\n`：换行。

+   `\w`：当前工作目录。

+   `\t`：当前时间。

+   `\u`：用户名。

`/etc/environment`文件（在基于 Red Hat 的发行版中默认为空）是在登录时执行的第一个文件。它包含每个进程的变量，而不仅仅是 shell。它不是脚本，每行只有一个变量。

以下是`/etc/environment`的示例：

```
EDITOR=/usr/bin/vim
BROWSER=/usr/bin/elinks
LANG=en_US.utf-8
LC_ALL=en_US.utf-8
LESSCHARSET=utf-8
SYSTEMD_PAGER=/usr/bin/more
```

`EDITOR`变量是一个重要的变量。许多程序可以调用编辑器；有时默认是 vi，有时不是。设置默认值可以确保您始终可以使用您喜欢的编辑器。

#### 注意

如果您不想注销并重新登录，可以使用`source`命令，例如`source /etc/environment`。这样，变量将被读入当前的 shell。

## 获取帮助

无论您是 Linux 的新手还是长期用户，都会时不时需要帮助。不可能记住所有命令及其参数。几乎每个命令都有一个`--help`参数，有时在`/usr/share/doc`目录中安装了文档，但最重要的信息来源是信息文档和 man 页面。

### 使用 man 页面

有一句话，**阅读完整的手册**（**RTFM**），有时人们会用另一个不太友好的词替换*fine*。几乎每个命令都有一个手册：man 页面为您提供了所有需要的信息。是的，不是所有的 man 页面都容易阅读，特别是旧的页面，但如果您经常使用 man 页面，您会习惯它们，并且能够快速找到所需的信息。通常，man 页面已安装在您的系统上，并且可以在线获取：[`man7.org/linux/man-pages`](http://man7.org/linux/man-pages)。

请注意，Azure 镜像中的 openSUSE Leap 和 SUSE Linux Enterprise Server 中删除了 man 页面。您必须重新安装每个软件包才能再次使用它们：

```
sudo zypper refresh
for package in $(rpm -qa);
  do sudo zypper install --force --no-confirm $package;
done
```

man 页面被安装在`/usr/share/man`目录中，以 GZIP 压缩的存档形式。man 页面是特别格式化的文本文件，您可以使用`man`命令或`pinfo`来阅读。`pinfo`实用程序充当文本浏览器，非常类似于基于文本的网络浏览器。它添加了超链接支持和使用箭头键在不同的 man 页面之间导航的能力。

#### 注意

如果您想要用`pinfo`替换`man`命令，最好使用`alias man="pinfo -m"`命令创建一个别名。

所有的 man 页面都遵循相似的结构，它们总是被格式化并分成各个部分：

+   **名称**：命令的名称和简要解释。通常是一行；详细信息可以在 man 页面的描述部分找到。

+   **概要**：包含所有可用参数的概述。

+   `ifconfig`命令明确说明这个命令已经过时。

+   **选项**：命令的所有可用参数，有时包括示例。

+   **示例**：如果示例不在选项部分，可能会有一个单独的部分。

+   **文件**：对于这个命令很重要的文件和目录。

+   **另请参阅**：指的是其他 man 页面、info 页面和其他文档来源。一些 man 页面包含其他部分，如注释、错误、历史、作者和许可证。

Man 页面是帮助页面，分为几个部分；这些部分在 man 页面的描述部分中描述。您可以使用`man man`来了解更多关于这些部分的信息。以下屏幕截图显示了不同的部分：

![列出 man 页面的各个部分的屏幕截图。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_08.jpg)

###### 图 3.8：man 页面的不同部分

了解这些分区是很重要的，特别是如果您想要搜索文档。要能够搜索文档，您需要索引 man 页面：

```
sudo mandb 
```

#### 注意

通常，在安装软件包后，索引会自动更新。有时，打包者可能没有添加一个后安装脚本来执行`mandb`命令。如果您找不到信息并且非常确定应该有一个 man 页面，手动执行该命令是个好主意。

之后，您可以使用`apropos`或`man -k`命令来找到您需要的信息。无论您选择哪个，语法都是一样的：

```
man -k -s 5 "time"
```

在前面的命令中，我们搜索了单词`time`，将搜索限制在 man 页面的第五部分。

### 使用 info 文档

Info 文档是另一个重要的信息来源。man 页面和 info 页面的区别在于 info 页面的格式更自由，而 man 页面是某个命令的一种说明手册。Info 文档大多数时候是完整的手册。

Info 文档和 man 页面一样，被压缩并安装在`/usr/share/info`目录中。要阅读它们，您可以使用`info`或更现代的`pinfo`。这两个命令都是文本浏览器。如果您是 Emacs 编辑器的忠实粉丝，您可以使用 InfoMode ([`www.emacswiki.org/emacs/InfoMode`](https://www.emacswiki.org/emacs/InfoMode))来阅读 info 文档。

其中一个很好的功能是，您可以使用`pinfo`或`info`直接跳转到文档中的超链接：

```
pinfo '(pinfo) Keybindings'
```

#### 注意

如果您使用 Ubuntu 或类似的发行版，默认情况下不会安装`pinfo`。运行`apt install pinfo`来安装它。

前面的例子打开了`pinfo`的 man 页面，并直接跳转到`Keybindings`部分。

`pinfo`命令有一个搜索选项，`-a`。如果有匹配，它将自动打开相应的`info`文档或 man 页面。例如，如果您想了解`echo`命令，使用`pinfo -a echo`；它会带您到`echo`命令的帮助部分。

`info`命令也有一个搜索选项：`-k`。使用`-k`，`info`命令将在所有可用手册中查找关键字。例如，在这里我们检查了`paste`关键字，它返回了所有可能的匹配项：

![使用 info -k 命令在所有可用手册中查找关键字 paste。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_09.jpg)

###### 图 3.9：使用 info 命令检查 paste 关键字

### 其他文档

另一个文档来源是 Linux 发行版供应商提供的文档。Red Hat、SUSE、Canonical 和 Debian 的网站托管了有用的手册、维基等。它们可能非常有用，特别是对于特定于发行版的主题，如软件管理。

有两个不是微软认可的发行版，Gentoo 和 Arch Linux，它们在其网站上有出色的维基。当然，这些维基中的一些信息是特定于这些发行版的，但许多文章是有用的，并且适用于每个发行版。

Linux 基金会在[`wiki.linuxfoundation.org`](https://wiki.linuxfoundation.org)上托管了一个维基，其中包含有关诸如网络等主题的文档，以及`init`系统、systemd 和 Linux 防火墙（firewalld）等标准；这些主题在*第五章，高级 Linux 管理*中讨论。

最后，Linux 文档项目可以在[`www.tldp.org`](https://www.tldp.org)找到。尽管你可以在那里找到的许多文档都非常古老，但它仍然是一个很好的起点。

## 处理文本文件

由 Ken Thompson 发起的 Unix 哲学旨在创建一个占用空间小、用户界面清晰的功能强大的操作系统。因为 Unix 哲学的一部分是*编写处理文本流的程序，因为那是一个通用接口*，程序之间的通信、配置文件和许多其他内容都是以纯文本实现的。本节是关于处理纯文本的。

### 阅读文本

在最基本的层面上，以纯文本格式阅读文件的内容意味着将该文件的内容重定向到标准输出。`cat`命令就是可以做到这一点的实用程序之一——将一个或多个文件（或另一个输入通道）的内容连接到标准输出：

![使用 cat 实用程序读取文件/etc/shells 的内容。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_10.jpg)

###### 图 3.10：使用 cat 命令生成标准输出

该实用程序的一些不错的参数包括：

+   `-A`：显示所有不可打印字符

+   `-b`：编号行，包括空行

+   `-n`：编号行，不包括空行

+   `-s`：抑制重复（!）空白行

还有另一个类似于`cat`的实用程序，即`tac`实用程序。这将以逆序打印文件：

![通过运行 tac 实用程序以逆序打印文件的内容。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_11.jpg)

###### 图 3.11：使用 tac 实用程序以逆序打印文件

`cat`命令的问题在于它只是将内容转储到标准输出而不对内容进行分页，并且终端的回滚功能不是很好。

`more`实用程序是一个分页过滤器。它一次显示一个屏幕的文本，并提供一个基本的搜索引擎，可以通过使用正斜杠来激活。在文件末尾，`more`将退出，有或没有消息`按空格键继续`。

`less`实用程序比`more`实用程序更先进。它具有以下功能：

+   能够向前、向后和水平滚动

+   高级导航

+   高级搜索引擎

+   多文件处理

+   能够显示有关文件的信息，如文件名和长度

+   能够调用 shell 命令

在`more`和`less`中，`v`命令允许我们切换到编辑器，默认为 vi 编辑器。

#### 注意

`more`和`less`都可以在每个发行版上使用；但是，在某些发行版上，`more`是`less`的别名。使用`type`命令进行验证！

如果您只想看到文件顶部的特定行数，有一个名为`head`的实用程序。默认情况下，它显示文件的前 10 行。您可以使用`-n`参数修改此行为，以便指定行数，使用`-c`参数指定字节/千字节的数量。

`head`实用程序是`tail`的相反；它默认显示前 10 行。例如，我们有一个名为`states.txt`的文件，其中按字母顺序列出了美国各州的名称。如果我们使用`head`命令，它将打印文件的前 10 行，如果我们使用`tail`命令，它将打印最后 10 行。让我们来看一下这个：

![使用 head 和 tail 实用程序打印文件的前 10 个和最后 10 个条目。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_12.jpg)

###### 图 3.12：使用 head 和 tail 实用程序列出文件的前 10 个和最后 10 个条目

它识别与`head`相同的参数以修改其行为。但是有一个额外的参数，使得这个实用程序对于日志记录非常有用。`-f`在文件增长时追加输出；这是一种跟踪和监视文件内容的方法。一个非常著名的例子是：

```
sudo tail -f /var/log/messages
```

### 在文本文件中搜索

您可能听说过 Linux 中的一切都是文件。此外，Linux 中的许多东西都是由文本流和文本文件管理的。迟早，您会想要搜索文本以进行修改。这可以通过使用正则表达式来实现。正则表达式（简称 regex）是一种特殊字符和文本的模式，用于在执行搜索时匹配字符串。正则表达式被许多应用程序使用，这些应用程序具有内置处理器，例如 Emacs 和 vi 文本编辑器，以及`grep`、`awk`和`sed`等实用程序。许多脚本和编程语言都支持正则表达式。

在本书中，我们只会涵盖这个主题的基础知识——足够让您在日常系统管理任务中使用它们。

每个正则表达式都是围绕一个原子构建的。原子标识要匹配的文本以及在进行搜索时要找到的位置。它可以是已知的单个字符项（或者如果您不知道字符，则是一个点），一个类，或者一个范围，比如：

![一个表格，显示如何使用正则表达式来表示多个单个字符项和范围。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_13.jpg)

###### 图 3.13：原子的示例

正则表达式也可以以简写类的形式表示。以下是一些简写类的示例：

![以简写类的形式表示不同正则表达式的列表。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_14.jpg)

###### 图 3.14：简写类的示例

我们可以使用位置锚点来确定下一个字符的位置。一些常用的位置锚点包括：

![重要位置锚点列表，用于确定下一个字符的位置。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_15.jpg)

###### 图 3.15：位置锚点列表

使用重复运算符，您可以指定字符应该出现多少次：

![重复运算符列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_16.jpg)

###### 图 3.16：重复运算符列表

一些例子如下：

+   如果搜索字符`b`并找到单词`boom`，它将匹配字母`b`。如果搜索`bo`，它将按照这个顺序匹配这些字符。

+   如果您搜索`bo{,2}m`，单词`bom`和`boom`将匹配。但如果存在单词`booom`，它将不匹配。

+   如果您搜索`^bo{,2}m`，只有当单词`boom`位于行的开头时才会匹配。

可以使用以下内容找到正则表达式的参考：

```
man 7 regex
```

我们已经提到的一个实用程序是`grep`实用程序，它用于在文本文件中进行搜索。这个实用程序有多个版本；如今，`egrep`是最常用的版本，因为它具有最完整的正则表达式支持，包括简写范围和 OR 交替运算符`|`。

`egrep`和`grep`的常见选项包括：

![列出了 egrep 和 grep 的常见选项的表格。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_17.jpg)

###### 图 3.17：egrep 和 grep 选项

您还可以通过查看 man 页面来查看其他选项。

这是`grep`的一个简单示例：

![grep 示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_18.jpg)

###### 图 3.18：grep 示例

另一个非常有用的实用程序是`awk`。现在，`awk`是由开发人员 Alfred Aho、Peter Weinberger 和 Brian Kernighan 创建的实用程序。它是用于生成和操作日志文件或报告的文本文件的脚本语言。`awk`不需要任何编译，您可以在报告中提及所需的字段。

让我们看一个例子：

```
awk -F: '/^root/ {print "Homedir of root:", $6}' /etc/passwd
```

它扫描`/etc/passwd`文件，并使用字段分隔符冒号来拆分内容。它搜索以`root`字符串开头的行，并打印一些文本（`root 的主目录：`）和第六列。

### 编辑文本文件

由于文本文件在 Linux 中非常重要，因此文本编辑器非常重要。每个发行版都在其存储库中提供一个或多个编辑器，用于图形和非图形环境。您可以肯定至少有 vim（现代 vi 实现）和 Emacs 可用。vi 爱好者和 Emacs 爱好者之间一直存在着一场战争——他们已经互相侮辱了几十年，并将在未来的几十年内继续这样做。

我们不会为您做决定；相反，如果您已经熟悉其中一个，请坚持下去。如果您不了解 vi 或 Emacs，请尝试一段时间并自行决定。

还有一些其他可用的编辑器：

+   `nano`，专有 Pico 的免费克隆，Pico 是 Pine 电子邮件客户端的文本编辑器组件

+   `mcedit`，**Midnight Commander**（**MC**）文件管理器的一部分，可以独立运行

+   `joe`，它可以模拟 nano、Emacs 和一个名为 WordStar 的非常古老的文字处理器的键绑定（请注意，对于 CentOS，这个编辑器在标准存储库中不可用，但在第三方存储库中可用）。

#### 注意

如果您想了解 vi，请执行`vimtutor`命令，这是随 vim 一起提供的教程。这是学习 vi 中所有基础知识、命令和文本编辑的良好起点。

Emacs 带有一个非常好的帮助功能，您可以通过*Ctrl* + *H* + *R*在 Emacs 中访问。

编辑文本流和文件的另一种方法是使用非交互式文本编辑器 sed。它不是通过在文本编辑器窗口中打开文件来编辑文本文件，而是通过 shell 处理文件或流。如果您想要执行以下操作，它是一个方便的实用程序：

+   自动对文件进行编辑

+   在多个文件上进行相同的编辑

+   编写一个转换程序，例如，在小写和大写之间进行转换，甚至更复杂的转换

sed 编辑器的语法与 vi 编辑器的命令非常相似，并且可以进行脚本化。

sed 的默认行为不是编辑文件本身，而是将更改转储到标准输出。您可以将此输出重定向到另一个文件，或者使用`-i`参数，该参数代表`sed`命令：

```
sed -i 's/string/newstring/g' filename.txt
```

它将搜索一个字符串，替换它，并继续搜索和替换直到文件末尾。

通过一点脚本编写，您可以以相同的方式编辑多个文件：

```
for files in *conf; do sed -i 's/string/newstring/g' $files; done
```

您可以将搜索限制为单行：

```
sed -i '10 s/string/newstring/g' <filename>
```

`sed`的`info`页面是所有命令的重要资源，更重要的是，它有一个示例部分，如果您想了解更多。

## 在文件系统中找到自己的方法

现在您知道如何操作和编辑文本文件了，是时候看看这些文件是如何存储在系统中的了。作为系统管理员，您将不得不检查、挂载甚至卸载驱动器。因此，现在让我们仔细看看 Linux 中的文件系统。Linux 文件系统的布局与 Unix 家族的其他成员一样：与 Windows 非常不同。没有驱动器字母的概念。相反，有一个根文件系统（`/`），并且根文件系统上包括其他已挂载的文件系统在内的所有其他内容都可用。

在本节中，您将了解文件的存放位置以及它们为何在那里。

### 文件系统层次结构标准

2001 年，Linux 基金会启动了 Linux 标准基础项目（LSB）。基于 POSIX 规范，这个过程的想法是建立一个标准化的系统，使应用程序可以在任何兼容的 Linux 发行版上运行。

文件系统层次结构标准（FHS）是该项目的一部分，定义了目录结构和目录内容。当然，不同发行版之间仍然存在一些关于目录结构的细微差异，但即使在不愿意完全支持 LSB 的发行版上，如 Debian，目录结构也遵循 FHS。

以下截图来自一个 CentOS 系统，使用 tree 实用程序显示目录结构。如果您的系统上没有安装 tree，则 shell 会提示您安装该命令。请安装。

在根文件系统中，有以下目录：

![使用 tree 实用程序查看根文件系统的目录结构。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_19.jpg)

###### 图 3.19：使用 tree 实用程序显示目录结构

tree 命令将以树状结构布局文件系统。或者，您可以使用 ls -lah /以列表格式查看结构。

以下目录在截图中出现：

+   /bin：包含在最小系统上需要由非特权用户执行的程序，如 shell。在基于 Red Hat 的系统中，此目录是指向/usr/bin 的符号链接。命令如 ps、ls 和 ping 都存储在这里。

+   /sbin：包含在最小系统上需要由特权用户（root）执行的程序，如文件系统修复工具。在基于 Red Hat Enterprise Linux 的系统中，此目录是指向/usr/sbin 的符号链接。例如 iptables、reboot、fdisk、ifconfig 和 swapon。

+   /dev：设备挂载在一个叫做 devfs 的特殊文件系统上。所有外围设备都在这里，如串行端口、磁盘和 CPU，但不包括网络接口。例如：/dev/null、/dev/tty1。

+   /proc：进程挂载在一个叫做 procfs 的特殊文件系统上。

+   /sys：sysfs 文件系统上的硬件信息。

+   /etc：由所有程序需要的可编辑文本配置文件组成。

+   /lib：驱动程序和不可编辑文本配置文件的库。库文件名要么是 ld*，要么是 lib*.so.*，例如 libutil-2.27.so 或 libthread_db-1.0.so。

+   /lib64：驱动程序的库，但没有配置文件。

+   /boot：内核和引导加载程序。例如：initrd.img-2.6.32-24-generic、vmlinuz-2.6.32-24-generic。

+   /root：root 用户的用户数据。只有 root 用户有权写入此目录。/root 是 root 用户的主目录，不同于/。

+   /home：非特权用户的用户数据。类似于 Windows 中的 C:\Users\username 文件夹。

+   /media：可移动介质，如 CD-ROM 和 USB 驱动器，都挂载在这里。每个用户至少有只读权限。例如，/media/cdrom 用于 CD-ROM，/media/floppy 用于软盘驱动器，/media/cdrecorder 用于 CD 刻录机。

+   /mnt：包括远程存储在内的不可移动介质。每个用户至少有只读权限。

+   /run：特定用户或进程的文件，例如应该对特定用户可用的 USB 驱动程序，或者守护进程的运行时信息。

+   /opt：不是发行版的一部分的可选软件，如第三方软件。

+   /srv：静态服务器数据。可用于静态网站、文件服务器和 Salt 或 Puppet 等编排软件。

+   /var：动态数据。从打印队列和日志到动态网站都有。

+   `/tmp`: 临时文件，在重新启动期间不会保留。现在，它通常是挂载在这个目录上的 RAM 文件系统（`tmpfs`）。这个目录本身已经过时，从应用程序的角度来看，已经被`/var`或`/run`中的目录取代。

+   `/usr`: 包含所有额外的与软件相关的二进制文件、文档和源代码。

再次使用`tree`命令显示`/usr`中的目录结构：

![/usr 目录中的目录结构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_20.jpg)

###### 图 3.20：/usr 目录中的目录结构

`/usr`的目录结构与`/`的结构非常相似。添加了一些额外的目录：

+   `/usr/etc`: 如果重新编译已经是发行版的一部分的软件，配置文件应该在`/usr/etc`中，这样它们就不会与`/etc`中的文件冲突。

+   `/usr/games`: 旧游戏的数据，比如`fortune`、`figlet`和`cowsay`。

+   `/usr/include`: 开发头文件。

+   `/usr/libexec`: 包装脚本。比如说你需要多个版本的 Java。它们都需要不同的库、环境变量等。包装脚本用于调用具有正确设置的特定版本。

+   `/usr/share`: 程序数据，如壁纸、菜单项、图标和文档。

+   `/usr/src`: Linux 内核源代码和发行版中包含的软件的源代码。

+   `/usr/local`: 你自己安装和编译的软件。

`/usr/local`的目录结构与`/usr`相同：

![/usr/local 目录中的目录结构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_21.jpg)

###### 图 3.21：/usr/local 目录的目录结构

这个目录是为了软件开发而存在的。在生产环境中不需要有这个目录。

可选软件放在`/opt`中。主目录结构是`/opt/<vendor>/<software>/`，例如`/opt/google/chrome`。可能的供应商/提供者名称列表由`/usr`和`/usr/local`维护，有一个例外：你可以在软件目录或`/etc/opt`目录中选择`/conf`和`/etc`之间。非本地 Linux 软件，如 PowerShell，可以在软件目录内使用自己的结构。

### 挂载文件系统

更精确地定义根文件系统可能是个好主意。根文件系统是根目录`/`所在的文件系统。所有其他文件系统都挂载在这个根文件系统上创建的目录上。要找出哪些目录是根文件系统本地的，哪些是挂载点，执行`findmnt`命令：

![使用 findmnt 命令确定哪些目录是根文件系统本地的，哪些是挂载点。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_22.jpg)

###### 图 3.22：使用 findmnt 命令查找挂载点

添加`-D`参数将显示文件系统的大小和可用空间量：

![通过运行 findmnt -D 命令列出文件大小和可用空间。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_23.jpg)

###### 图 3.23：使用 findmnt -D 命令列出文件大小和可用空间

`findmnt`命令是查找设备挂载位置的好方法，例如：

```
findmnt /dev/sda1
```

如果一个目录不是挂载点，使用`-T`参数：

```
findmnt -T /usr
```

在*第五章，高级 Linux 管理*中，详细介绍了不同的文件系统，以及如何挂载和自动挂载本地和远程文件系统。

### 在文件系统上查找文件

在文件系统上搜索文件可以使用`find`命令。不幸的是，如果你对这个命令不熟悉，man 页面可能会让人不知所措，而且很难阅读。然而，如果你了解这个命令的基本原理，man 页面将帮助你添加参数来搜索文件或目录的每个属性，或者两者兼而有之。

`find`命令的第一个可能参数是选项。这些选项影响`find`命令的行为，即它是否应该遵循符号链接以及调试和速度优化选项。选项是可选的——大多数情况下您不需要它们。

在选项之后，下一个参数告诉`find`命令在哪里开始搜索过程。从根目录(`/`)开始搜索不是一个很好的主意；它会花费太多时间，并且可能在大型文件系统上消耗太多 CPU 活动。记住 FHS——例如，如果要搜索配置文件，请从`/etc`目录开始搜索：

```
find /etc
```

上述命令将显示`/etc`中的所有文件。

在位置之后，下一个参数是包含一个或多个测试的表达式。要列出最常见的测试，请使用以下命令：

+   `-type`，`f`表示文件，`d`表示目录，`b`表示块设备

+   `-name <pattern>`

+   `-user`和`-group`

+   `-perm`

+   `-size`

+   `-exec`

您可以执行这些测试的组合。例如，要搜索以`conf`结尾的文件，请使用以下命令：

```
find /etc -type f -name '*conf' 
```

对于一些测试，如`size`和`atime`，可以添加所谓的与提供的参数进行比较：

+   `+n`：大于`n`

+   `-n`：小于`n`

+   `n`：正好`n`

`find`命令搜索文件和目录，并将它们与`n`的值进行比较：

```
find / -type d -size +100M
```

此示例将搜索内容超过 100MB 的目录。

最后一个参数是应在找到的文件上执行的操作。示例包括：

+   `-ls`，输出类似于`ls`命令。

+   `-print`打印文件名。

+   `-printf`格式化`-print`命令的输出。

+   `-fprintf`将格式化输出写入文件。

`-printf`参数非常有用。例如，此命令将搜索文件并列出其大小（以字节为单位）和文件名。之后，您可以使用`sort`命令按大小对文件进行排序：

```
find /etc -name '*conf' -printf '%s,%p\n' | sort -rn 
```

还有一些更危险的操作，例如`-delete`删除找到的文件和`-exec`执行外部命令。在使用这些参数之前，请非常确定搜索操作的结果。大多数情况下，从性能的角度来看，您最好使用`xargs`实用程序。此实用程序将结果转换为命令的参数。这样的命令示例如下；`grep`实用程序用于搜索结果的内容：

```
find /etc/ -name '*' -type f| xargs grep "127.0.0.1"
```

## 进程管理

在前一节中，我们讨论了 Linux 中的文件系统。从系统管理员的角度来看，管理进程至关重要。会有一些情况，您需要启动、停止，甚至杀死进程。此外，为了避免使您的机器过载，您需要谨慎处理系统上运行的进程。让我们更仔细地看看 Linux 中的进程管理。

进程由 Linux 内核运行，由用户启动，或由其他进程创建。所有进程都是进程编号为 1 的子进程，这将在下一章中介绍。在本节中，我们将学习如何识别进程以及如何向进程发送信号。

### 查看进程

如果您启动一个程序，会有一个`/proc`。

在 Bash 中，您可以使用以下命令找到当前 shell 的 PID：

```
echo $$
```

您还可以找到父 shell 的 PID：

```
echo $PPID
```

要在文件系统上找到程序的 PID，请使用`pidof`实用程序：

```
pidof sshd
```

您可能会看到 shell 返回多个 PID。如果您只想返回一个 PID，请使用`-s`参数，表示单次射击：

```
pidof -s sshd
```

让我们来看看当前 shell 的`proc`目录：

![导航到/proc 目录并使用 ls 列出其所有内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_24.jpg)

###### 图 3.24：当前 shell 的 proc 目录

您可以查看此进程的所有属性。让我们看看其中一些：

+   `cmdline`：执行此进程的命令

+   `environ`：此进程可用的环境变量

+   `status`：文件的状态，**UID**（**用户标识符**）和拥有该进程的用户/组的**GID**（**组标识符**）

如果执行`cat environ`，输出将很难阅读，因为换行符是`\0`而不是`\n`。您可以使用`tr`命令将`\0`转换为`\n`来解决这个问题：

```
cat /proc/$$/environ | tr "\0" "\n"
```

`proc`目录对故障排除非常有趣，但也有许多工具使用这些信息生成更人性化的输出。其中一个实用程序是`ps`命令。这个命令有一些奇怪之处；它支持三种不同类型的参数：

+   `ps -ef`与`ps -e -f`相同。

+   `ps ax`与`ps a x`相同。

+   **GNU 风格**：由双破折号和长命名选项前导。命令不能分组。

三种样式的输出格式不同，但您可以使用选项修改行为。以下是比较：

![使用 ps 命令及其三种不同类型参数运行 ps 命令。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_25.jpg)

###### 图 3.25：使用带参数的 ps 实用程序

方括号中的进程是内核进程。

您可以查询特定值，例如：

```
ps -q $$ -o comm
```

这与以下内容相同：

```
cat /proc/$$/cmdline
```

另一个可以帮助您搜索进程的实用程序是`pgrep`。它可以根据名称和用户等值进行搜索，并默认显示 PID。输出可以使用参数进行格式化，例如使用`-l`列出进程名称，或使用`-o`将完整命令添加到输出中。

使用`top`命令监视进程的交互方式：

![使用 top 命令监视进程](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_26.jpg)

###### 图 3.26：使用 top 命令监视进程

在`top`中可见的进程的列中的值与`ps`中的值相同。在`top`的手册页中，您可以找到对它们含义的很好解释。其中一些将在后面的章节中介绍。

`top`命令或更高级的`htop`命令可以帮助您快速识别占用过多内存或 CPU 的进程，并向进程发送信号。如果您想要详细和高级的进程监视和故障排除，最好使用 Azure 中提供的工具。这将在*第十一章，故障排除和监视工作负载*中介绍。

### 向进程发送信号

在现实世界中，您可能会遇到一个问题，即某个特定进程正在消耗大量内存。此时，您可能希望向该进程发送终止信号。同样，在处理进程时，您可能会遇到不同的情况。在本节中，我们将探讨可以发送给进程的不同信号。在信号的手册页第七部分中，您可以找到有关信号的更多信息。信号是发送给进程的消息，例如，改变优先级或终止进程。在本手册中描述了许多不同的信号，但只有少数几个真正重要：

+   **信号 1**：这会挂起进程；它将重新加载附加到进程的所有内容。通常用于重新读取更改的配置文件。

+   **信号 2**：与*Ctrl* + *C*和*Ctrl* + *Break*相同。

+   **信号 3**：正常退出进程；与*Ctrl* + *D*相同。

+   **信号 15**：默认信号，用于终止命令，使终端有时间清理一切。

+   **信号 9**：终止命令而不清理。这很危险，可能会使您的系统不稳定，有时甚至会有漏洞。

如果您想要查看可以发送给进程的信号列表，请运行：

```
kill -l
```

要向进程发送信号，可以使用`top`（快捷键`k`）或`kill`命令：

```
kill -HUP <PID>
```

有一个很好的实用程序可以用来 grep 一个进程或一组进程；它可以一次发送一个信号：`pkill`。它类似于`pgrep`。可以根据`name`和`uid`等值进行选择。

## 自主访问控制

现在我们已经介绍了文件系统和进程管理，应该有一种方法来限制您创建的文件的权限。换句话说，您不应该授予每个人对所有内容的访问权限，大多数组织都遵循给予最细粒度权限的原则。**自主访问控制**（**DAC**）是一种安全实现，它限制对文件和目录等对象的访问。用户或一组用户根据所有权和对象上的权限获得访问权限。

在云环境中，用户和组管理可能不是您日常工作的一部分。通常委托给诸如**活动目录**（**AD**）之类的身份管理系统，并且您不需要许多用户帐户；现在在应用程序级别进行身份验证和授权更加重要。但是，能够验证用户并了解基础系统的工作原理仍然是一个好主意。

### 用户管理

如果您在 Azure 中部署虚拟机，在向导中您将指定一个用户，该用户将由 Azure 代理用户管理在虚拟机中创建 - 例如，如果您使用 PowerShell 部署虚拟机：

![使用 PowerShell 部署虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_27.jpg)

###### 图 3.27：使用 PowerShell 部署虚拟机

您可以使用此帐户登录。这是一个普通用户，也称为非特权用户，没有管理权限。要获得管理权限，您需要`sudo`命令；`sudo`表示超级用户执行（或以超级用户身份执行）。没有参数时，`su`命令将当前用户切换到另一个用户，即 root - Linux 中的管理员帐户。

#### 备注

如果您想要 root 权限，在 Azure 中的某些 Linux 映像中，您不能使用`su`命令。它默认禁用。要获取 root shell，您可以使用`sudo -s`。默认情况下，`sudo`命令会要求您输入密码。

要获取有关此用户帐户的更多信息，请使用`getent`命令从存储用户信息的`passwd`数据库中获取实体。这个`passwd`数据库可以是本地的，存储在`/etc/passwd`文件中，也可以是远程的，远程服务器将通过检查用户数据库（例如**轻量级目录访问协议**（**LDAP**））来授予授权：

```
sudo getent passwd <username>
```

要获取`linvirt`用户的详细信息：

![使用 getent 获取 linvirt 的详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_28.jpg)

###### 图 3.28：使用 getent 获取 linvirt 的详细信息

此命令的输出是一个以冒号分隔的列表：

+   用户帐户名

+   密码

+   用户 ID

+   组 ID

+   **通用电气综合操作系统**（**GECOS**）字段用于额外的帐户信息

+   此用户的主目录

+   默认 shell

在 Unix 操作系统家族的早期，密码存储在`/etc/passwd`文件中，但出于安全原因，哈希密码被移动到`/etc/shadow`。密码可以使用以下命令更改：

```
sudo passwd <username>
```

如果要更改当前用户的密码，不需要使用`sudo`，也不需要指定用户名。您可以使用`getent`在`/etc/shadow`文件中查看条目：

![使用 getent 命令检查密码条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_29.jpg)

###### 图 3.29：使用 getent 命令检查密码条目

哈希密码后的列包含可以使用`chage`命令查看（和更改）的老化信息。阴影数据库中的标记是自 Unix 的虚拟生日（1970 年 1 月 1 日）以来的天数。`chage`命令将其转换为更易读的形式：

![使用 chage 命令将 epoch 转换为可读日期。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_30.jpg)

###### 图 3.30：使用 chage 命令获取老化信息

让我们回到`passwd`数据库。用户 ID 的编号在`/etc/login.defs`文件中定义。ID `0`保留给 root 帐户。ID `1`到`200`保留给在现代 Linux 系统中不再使用的`admin`帐户。在基于 Red Hat 的发行版中，范围 201-999 保留给系统帐户，和在这些帐户下运行的守护程序。非特权帐户的范围是 1,000 到 60,000 用于本地用户，>60,000 用于远程用户（例如，AD 或 LDAP 用户）。Linux 发行版之间存在一些小差异。让我们总结一下这些值：

![显示 Linux 中用户 ID 号码和用户类型之间关系的表格。](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_31.jpg)

###### 图 3.31：用户 ID 及其保留用户类型

许多发行版都配置了所谓的`/etc/login.defs`文件：

```
USERGROUPS_ENAB yes 
```

这意味着如果您创建一个用户，将自动创建一个与登录名相同的主要组。如果禁用此功能，新创建的用户将自动成为另一个组的成员，该组在`/etc/default/useradd`中定义：

```
GROUP=100
```

可以使用`chfn`命令更改 GECOS 字段：

![使用 chfn 命令更改 GECOS 字段](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_32.jpg)

###### 图 3.32：使用 chfn 命令更改 GECOS 字段

#### 注意：

`chfn`（更改 finger）命令是指一个旧实用程序`finger`，它不是默认安装的，但仍然可以在存储库中找到。还有一个`finger`守护程序，可以通过网络提供 GECOS 信息，但被认为是安全风险。

在创建用户时，默认 shell 在`/etc/default/useradd`中定义。您可以使用`chsh`命令将默认 shell 更改为另一个。shell 必须在`/etc/shells`文件中列出：

```
chsh -s /bin/tcsh linvirt
```

为了本书的目的，保持 Bash 作为默认 shell。

在本节中，您学习了如何验证和更改现有本地用户的属性。当然，您也可以添加额外的用户：

```
sudo useradd <username>
```

`useradd`命令有很多自定义选项。您可以使用`man useradd`了解更多信息。或者，您可以使用`adduser`命令：

![使用 adduser 命令添加用户](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_33.jpg)

###### 图 3.33：使用 adduser 命令添加用户

### 组管理

如前一章所述，用户将成为主要组的一部分。当您创建用户时，如果不指定组，将自动创建一个与用户名相同的组。如果您检查前面的屏幕截图，您可以看到一个名为`john`的组，用于用户`john`。

除了是主要组的成员之外，还可以添加额外的组成员资格。这是为了访问组目录/共享或在`sudo`配置中委派权限而必要的。您可以在创建用户时使用`useradd`命令的`--groups`参数添加现有的额外组成员，或者之后使用`usermod`或`groupmems`。

让我们创建一个新用户和一个新组，并验证结果：

```
sudo useradd student
sudo passwd student
sudo getent passwd student
sudo groupadd staff 
sudo getent group staff
```

将`student`用户添加到`staff`组：

```
sudo groupmems -g staff -a student
```

或者：

```
sudo usermod –aG staff student
sudo groupmems -g staff -l
sudo getent group staff
```

您可以使用**switch group**（**sg**）临时更改您的主要组：

```
su student
id -g 
sg staff
```

#### 注意：

虽然不太常见，但您可以使用`gpasswd`命令为组帐户添加密码。这样，不属于该组的用户仍然可以使用`sg`并输入该组的密码。

一个非常特殊的组是`wheel`组。在`sudo`配置中，属于这个组的用户能够执行需要管理员权限的命令。在 Ubuntu 中，这个组不可用；而是有一个名为`sudo`的组，可以用于相同的目的。

### 登录管理

在企业环境中，管理员需要收集诸如登录用户数、无效登录数以及任何授权用户尝试登录的信息，以进行安全审计。在本章中，我们将介绍 Linux 中的登录管理，这在安全方面至关重要。

任何对 Linux 系统的登录都会被一个名为`systemd-logind`的服务跟踪和管理，以及一个相应的命令：`loginctl`。这个命令适用于所有的 Linux 发行版；然而，如果你使用**Windows 子系统用于 Linux**（**WSL**），由于缺乏 systemd，这将不可用。

这个命令的参数分为用户、会话和座位三个部分。要使用这些参数进行一些练习，使用学生账户的凭据在你的 VM 上打开第二个`ssh`会话。在第一个`ssh`会话中执行命令。

首先，列出会话：

```
loginctl list-sessions
```

记录会话 ID 和特定会话的详细信息：

```
loginctl show-session <session number>
```

在我的情况下，会话 ID 是`27`，所以我们将使用`loginctl`来检查会话详细信息：

![使用 loginctl 检查会话 ID 27 的会话详细信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_03_34.jpg)

###### 图 3.34：检查会话 ID 27 的会话详细信息

查看用户属性：

```
loginctl show-user <username>
```

切换到第二个 SSH 会话并执行`man man`。

现在切换登录管理回到第一个 SSH 会话，并使用`user-status`参数查看学生的状态：

使用用户状态参数查看学生的状态

###### 图 3.35：使用用户状态参数

最后，终止会话：

```
sudo loginctl terminate-session <session id>
```

还有一个`terminate-user`参数，如果一个会话中有多个用户，这可能会很方便。

## 总结

本章是一个关于如何在 Linux 中生存的速成课程，如果你对这个操作系统不熟悉的话。这一章并不是关于如何成为一名高级 Linux 管理员。

在你作为 Azure 管理员的日常生活中，你可能不会使用本章中的所有内容。例如，你可能不会在虚拟机中创建用户。但是你应该能够验证在诸如 AD 之类的身份管理系统中配置的用户，并验证他们能够登录。

本章主要讲述了如何使用 shell、文件系统的结构以及查找文件。我们看了一下文本文件在 Linux 中的作用以及如何处理和编辑它们。我们处理了进程，并学会了如何查看和终止它们。最后但并非最不重要的是，我们看了用户和组管理。

在下一章中，我们将讨论在 Azure 中管理资源。

## 问题

在本章中，我不想回答一些问题，而是让你做一个练习：

1.  创建用户`Lisa`、`John`、`Karel`和`Carola`。

1.  为这些用户设置密码为`welc0meITG`。

1.  验证这些用户的存在。

1.  创建`finance`和`staff`组。

1.  使用户`Lisa`和`Carola`成为`finance`的成员，`Karel`和`John`成为`staff`的成员。

1.  创建/home/staff 和/home/finance 目录，并将这些目录的组所有权分别设置为 staff 和 home。

1.  给予 staff 组对 finance 目录的读取权限。

1.  确保新创建的文件获得正确的组所有权和权限。

## 进一步阅读

有很多为 Linux 操作系统新用户出版的书籍。以下是我个人喜欢的一些。

*与 Linux 一起工作-命令行的快速技巧*（ISBN 978-1787129184）由 Petru Işfan 和 Bogdan Vaida 是一个奇怪的收集，里面有很多不错的技巧，有时这就是你所需要的。

如果你能阅读德语，那么 Michael Kofler（[`kofler.info`](https://kofler.info)）的所有书籍都应该放在你的书架上，即使你是一名经验丰富的 Linux 用户！

微软网站上有关于正则表达式的非常好的文档：[`docs.microsoft.com/en-us/dotnet/standard/base-types/regular-expressions`](https://docs.microsoft.com/en-us/dotnet/standard/base-types/regular-expressions)。如果你想练习使用正则表达式，我也喜欢[`regexone.com`](http://regexone.com)。

`awk`实用程序附带有一本大型手册（[`www.gnu.org/software/gawk/manual/gawk.html`](https://www.gnu.org/software/gawk/manual/gawk.html)），但也许不是最好的起点。Shiwang Kalkhanda 在《学习 AWK 编程》（ISBN 978-1788391030）中做得非常好，编写了一本非常易读的书。不要害怕这个标题中的“编程”一词，特别是如果你不是开发人员；你应该阅读这本书。
