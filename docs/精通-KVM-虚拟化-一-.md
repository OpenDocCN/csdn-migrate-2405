# 精通 KVM 虚拟化（一）

> 原文：[`zh.annas-archive.org/md5/937685F0CEE189D5B83741D8ADA1BFEE`](https://zh.annas-archive.org/md5/937685F0CEE189D5B83741D8ADA1BFEE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《精通 KVM 虚拟化》是一本应该让你在阅读本书的过程中从零到英雄的书。这本书是 KVM 所提供的一切的大集合，适用于 DevOps 和普通系统管理人员，以及开发人员。我们希望通过阅读本书，你能够理解 KVM 的内部工作原理，以及更高级的概念和中间的一切。无论你是刚刚开始接触 KVM 虚拟化，还是已经很熟悉，你都应该在本书的页面上找到一些有价值的信息。

# 这本书适合谁

本书适用于 Linux 初学者和专业人士，因为它并不一定需要事先对 Linux 有高级知识。随着你阅读本书，我们会带你走向成功——这是学习过程的一个组成部分。如果你对 KVM、OpenStack、ELK Stack、Eucalyptus 或 AWS 感兴趣，我们都有涵盖。

# 本书涵盖的内容

*第一章*，*理解 Linux 虚拟化*，讨论了不同类型的虚拟化、Hypervisor 类型和 Linux 虚拟化概念（Xen 和 KVM）。在本章中，我们试图从高层次的角度解释 Linux 虚拟化的一些基础知识以及它如何适应云环境。

*第二章*，*KVM 作为虚拟化解决方案*，从讨论虚拟化概念和虚拟化环境的需求开始，解释了虚拟化的基本硬件和软件方面，以及虚拟化的各种方法。在本章中，我们开始讨论 KVM 和 libvirt，这些概念将贯穿本书始终。

*第三章*，*安装 KVM Hypervisor、libvirt 和 oVirt*，扩展了*第二章*，引入了一些新概念，包括 oVirt，这是一个可以用来管理我们虚拟化 Linux 基础设施的 GUI。我们将带你了解硬件是否兼容 KVM 的过程，介绍一些虚拟机部署的基本命令，然后解释在相同场景中如何使用 oVirt。

*第四章*，*Libvirt 网络*，解释了 libvirt 如何与各种网络概念交互——不同模式下的虚拟交换机、如何使用 CLI 工具管理 libvirt 网络、TAP 和 TUN 设备、Linux 桥接和 Open vSwitch。之后，我们通过使用 SR-IOV 讨论了更极端的网络示例，这是一个应该让我们获得最低延迟和最高吞吐量的概念，在每一毫秒都很重要的情况下使用。

*第五章*，*Libvirt 存储*，是一个重要章节，因为存储概念在构建虚拟化和云环境时非常重要。我们讨论了 KVM 支持的每种存储类型——本地存储池、NFS、iSCSI、SAN、Ceph、Gluster、多路径和冗余、虚拟磁盘类型等等。我们还为你展示了存储的未来——包括 NVMe 和 NVMeoF 等技术。

*第六章*，*虚拟显示设备和协议*，讨论了各种虚拟机显示类型、远程协议，包括 VNC 和 Spice，以及 NoVNC，它确保了显示的可移植性，因为我们可以在 Web 浏览器中使用 NoVNC 来使用虚拟机控制台。

*第七章*，*虚拟机：安装、配置和生命周期管理*，介绍了部署和配置 KVM 虚拟机的其他方法，以及迁移过程，这对任何类型的生产环境都非常重要。

第八章《创建和修改 VM 磁盘、模板和快照》，讨论了各种虚拟机镜像类型、虚拟机模板化过程、快照的使用以及在使用快照时的一些用例和最佳实践。它还作为下一章的介绍，在下一章中，我们将以更加流畅的方式使用模板化和虚拟机磁盘来定制虚拟机引导后使用`cloud-init`和`cloudbase-init`。

第九章《使用 cloud-init 自定义虚拟机》，讨论了云环境中最基本的概念之一-如何在虚拟机镜像/模板引导后进行定制。Cloud-init 在几乎所有的云环境中用于进行引导后的 Linux 虚拟机配置，我们解释了它的工作原理以及如何在您的环境中使其工作。

第十章《自动化 Windows 客户端部署和定制化》，是第九章的延续，重点关注 Microsoft Windows 虚拟机模板化和引导后定制化。为此，我们使用了 cloudbase-init，这个概念基本上与 cloud-init 相同，但仅适用于基于 Microsoft 的操作系统。

第十一章《Ansible 和编排自动化脚本》，带领我们踏上 Ansible 之旅的第一部分-部署 AWX 和 Ansible，并描述如何在基于 KVM 的环境中使用这些概念。这只是现代 IT 中使用的 Ansible 使用模型之一，因为整个 DevOps 和基础设施即代码的故事在全球范围内得到了更多的关注。

第十二章《使用 OpenStack 扩展 KVM》，讨论了基于 KVM 构建云环境的过程。当使用 KVM 时，OpenStack 是交付这一点的标准方法。在本章中，我们讨论了所有 OpenStack 构建块和服务，如何从头开始部署它，并描述了如何在生产环境中使用它。

第十三章《使用 AWS 扩展 KVM》，带领我们走向使用公共和混合云概念的旅程，使用 Amazon Web Services（AWS）。与几乎所有其他章节一样，这是一个非常实践性的章节，您也可以用它来对 AWS 有所了解，这对于在本章末使用 Eucalyptus 部署混合云基础设施至关重要。

第十四章《监控 KVM 虚拟化平台》，介绍了通过 Elasticsearch、Logstash、Kibana（ELK）堆栈进行监控的非常流行的概念。它还带领您完成了设置和集成 ELK 堆栈与您的 KVM 基础设施的整个过程，一直到最终结果-使用仪表板和 UI 来监视您的基于 KVM 的环境。

第十五章《KVM 虚拟机性能调优和优化》，讨论了在基于 KVM 的环境中调优和优化的各种方法，通过解构所有基础设施设计原则并将其正确使用。我们在这里涵盖了许多高级主题- NUMA、KSM、CPU 和内存性能、CPU 绑定、VirtIO 的调优以及块和网络设备。

*第十六章*，*KVM 平台故障排除指南*，从基础知识开始-故障排除 KVM 服务和日志记录，并解释了 KVM 和 oVirt、Ansible 和 OpenStack、Eucalyptus 和 AWS 的各种故障排除方法。这些都是我们在撰写本书时在生产环境中遇到的真实问题。在本章中，我们基本上讨论了与本书的每一章相关的问题，包括与快照和模板相关的问题。

# 充分利用本书

我们假设您至少具有基本的 Linux 知识和安装虚拟机的先验经验作为本书的先决条件。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_Preface_table.jpg)

# 实际代码演示

本书的实际代码演示视频可在[`bit.ly/32IHMdO`](https://bit.ly/32IHMdO)上观看。

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838828714_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781838828714_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“我们需要做的就是取消注释配置文件中定义的一个管道，该文件位于`/etc/logstash`文件夹中。”

代码块设置如下：

```
<memoryBacking>
    <locked/>
</memoryBacking>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
POWER TTWU_QUEUE NO_FORCE_SD_OVERLAP RT_RUNTIME_SHARE NO_LB_MIN NUMA 
NUMA_FAVOUR_HIGHER NO_NUMA_RESIST_LOWER
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子：“在您点击**刷新**按钮之后，新数据应该出现在页面上。”

提示或重要说明

出现在这样。

# 联系我们

我们始终欢迎读者的反馈。

**一般反馈**：如果您对本书的任何方面有疑问，请在邮件主题中提及书名，并发送电子邮件至 customercare@packtpub.com 与我们联系。

**勘误**：尽管我们已经尽最大努力确保内容的准确性，但错误确实会发生。如果您在本书中发现错误，我们将不胜感激。请访问[www.packtpub.com/support/errata](http://www.packtpub.com/support/errata)，选择您的书籍，点击勘误提交表单链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，请向我们提供位置地址或网站名称，我们将不胜感激。请通过 copyright@packt.com 与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com)。

# 评论

请留下评论。阅读并使用本书后，为什么不在购买书籍的网站上留下评论呢？潜在读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者也可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://packt.com)。


# 第一部分：KVM 虚拟化基础

本部分为您提供了对 Linux 虚拟化中盛行的技术以及其优于其他虚拟化解决方案的见解。我们将讨论重要的数据结构以及 libvirt、QEMU 和 KVM 的内部实现。

本书的这部分包括以下章节：

+   *第一章*，*理解 Linux 虚拟化*

+   *第二章*，*KVM 作为虚拟化解决方案*


# 第一章：理解 Linux 虚拟化

虚拟化是一项技术，它引发了 IT 整合的重大技术转变，提供了更有效地利用资源的方式，云作为虚拟化的一个更综合、自动化和编排的版本，重点不仅在于虚拟机，还在于其他附加服务。本书共有 16 章，所有这些章节都已经安排好，以涵盖基于内核的虚拟机（KVM）虚拟化的所有重要方面。我们将从 KVM 的基本主题开始，如虚拟化概念的历史和 Linux 虚拟化，然后继续查看 KVM 的高级主题，如自动化、编排、虚拟网络、存储和故障排除。本章将为您提供有关 Linux 虚拟化中主导技术及其优势的见解。

在本章中，我们将涵盖以下主题：

+   Linux 虚拟化及其基本概念

+   虚拟化的类型

+   Hypervisor/VMM

+   开源虚拟化项目

+   Linux 虚拟化在云中为您提供了什么

# Linux 虚拟化及其起源

虚拟化是一种概念，它创建虚拟化资源并将其映射到物理资源。这个过程可以使用特定的硬件功能（通过某种分区控制器进行分区）或软件功能（hypervisor）来完成。因此，举个例子，如果你有一台物理 PC 服务器，有 16 个核心运行一个 hypervisor，你可以轻松地创建一个或多个每个有两个核心的虚拟机并启动它们。关于你可以启动多少虚拟机的限制是基于供应商的。例如，如果你运行 Red Hat Enterprise Virtualization v4.x（基于 KVM 的裸机 hypervisor），你可以使用高达 768 个逻辑 CPU 核心或线程（你可以在[`access.redhat.com/articles/906543`](https://access.redhat.com/articles/906543)上阅读更多信息）。无论如何，hypervisor 将是*首选*，它将尽可能有效地管理，以便所有虚拟机工作负载尽可能多地占用 CPU 时间。

我清楚地记得在 2004 年写了我的第一篇关于虚拟化的文章。AMD 在 2003 年推出了它的第一款消费级 64 位 CPU（Athlon 64，Opteron），这让我有点困惑。英特尔还有点犹豫是否推出 64 位 CPU - 缺乏 64 位微软 Windows 操作系统可能也有一些关系。Linux 已经支持 64 位，但这是 PC 市场即将迎来许多新事物的黎明。虚拟化本身并不是一个革命性的想法，因为其他公司已经有非 x86 产品可以进行几十年的虚拟化（例如，IBM CP-40 及其 S/360-40，从 1967 年开始）。但对于 PC 市场来说，这肯定是一个新的想法，当时市场正处于许多事情同时发生的奇怪阶段。从 64 位 CPU 切换到多核 CPU，然后从 DDR1 切换到 DDR2，再从 PCI/ISA/AGP 切换到 PCI Express，你可以想象，这是一个具有挑战性的时期。

具体来说，我记得曾经想过各种可能性 - 在一个操作系统上运行另一个操作系统，然后在其上运行另外几个操作系统是多么酷。在出版行业工作，你可以想象这将为任何人的工作流程提供多少优势，我记得当时真的很兴奋。

15 年左右的发展之后，我们现在在虚拟化解决方案方面有了一个竞争激烈的市场 - 红帽公司的 KVM，微软的 Hyper-V，VMware 的 ESXi，甲骨文的 Oracle VM，谷歌和其他关键参与者为用户和市场主导地位而争夺。这导致了各种云解决方案的发展，如 EC2，AWS，Office 365，Azure，vCloud Director 和 vRealize Automation，用于各种类型的云服务。总的来说，对于 IT 来说，这是一个非常富有成效的 15 年，你不觉得吗？

然而，回到 2003 年 10 月，随着 IT 行业发生的种种变化，有一个对于这本书和 Linux 虚拟化来说非常重要的变化：第一个针对 x86 架构的开源 Hypervisor——**Xen**的推出。它支持各种 CPU 架构（Itanium、x86、x86_64 和 ARM），可以运行各种操作系统，包括 Windows、Linux、Solaris 和一些 BSD 的变种。它仍然作为一种虚拟化解决方案存在并且备受一些供应商的青睐，比如 Citrix（XenServer）和 Oracle（Oracle VM）。我们稍后会在本章节中详细介绍 Xen 的更多技术细节。

在开源市场中最大的企业参与者 Red Hat 在其 Red Hat Enterprise Linux 5 的最初版本中包含了 Xen 虚拟化，该版本于 2007 年发布。但 Xen 和 Red Hat 并不是天作之合，尽管 Red Hat 在其 Red Hat Enterprise Linux 5 发行版中搭载了 Xen，但在 2010 年的 Red Hat Enterprise Linux 6 中，Red Hat 转向了**KVM**，这在当时是一个非常冒险的举动。实际上，从之前的版本 5.3/5.4 开始，即 2009 年发布的两个版本，从 Xen 迁移到 KVM 的整个过程就已经开始了。要把事情放到背景中，当时 KVM 还是一个相当年轻的项目，只有几年的历史。但为什么会发生这种情况有很多合理的原因，从*Xen 不在主线内核中，KVM 在*，到政治原因（Red Hat 希望对 Xen 的开发拥有更多的影响力，而这种影响力随着时间的推移而逐渐减弱）。

从技术上讲，KVM 采用了一种不同的模块化方法，将 Linux 内核转换为支持的 CPU 架构的完全功能的 Hypervisor。当我们说*支持的 CPU 架构*时，我们指的是 KVM 虚拟化的基本要求——CPU 需要支持硬件虚拟化扩展，即 AMD-V 或 Intel VT。简单来说，你真的需要非常努力才能找到一个不支持这些扩展的现代 CPU。例如，如果你在服务器或台式电脑上使用的是英特尔 CPU，那么首批支持硬件虚拟化扩展的 CPU 可以追溯到 2006 年（Xeon LV）和 2008 年（Core i7 920）。同样，我们稍后会在本章节和下一章节中详细介绍 KVM 的更多技术细节，并对 KVM 和 Xen 进行比较。

# 虚拟化类型

有各种类型的虚拟化解决方案，它们都针对不同的用例，并且取决于我们虚拟化的硬件或软件堆栈的不同部分，也就是*你*在虚拟化什么。值得注意的是，从*如何*虚拟化的角度来看，也有不同类型的虚拟化——包括分区、完全虚拟化、半虚拟化、混合虚拟化或基于容器的虚拟化。

因此，让我们首先介绍今天 IT 领域中基于*你*在虚拟化什么的五种不同类型的虚拟化：

+   桌面虚拟化（虚拟桌面基础设施（VDI））：这被许多企业公司使用，并在许多场景中提供巨大优势，因为用户不依赖于用于访问其桌面系统的特定设备。他们可以从手机、平板电脑或计算机连接，并且通常可以从任何地方连接到他们的虚拟桌面，就像他们坐在工作场所使用硬件计算机一样。优势包括更容易的集中管理和监控，更简化的更新工作流程（您可以在 VDI 解决方案中更新数百台虚拟机的基础映像，并在维护时间重新链接到数百台虚拟机），简化的部署流程（不再需要在台式机、工作站或笔记本电脑上进行物理安装，以及集中应用程序管理的可能性），以及更容易管理合规性和安全相关选项。

+   服务器虚拟化：这是今天绝大多数 IT 公司使用的技术。它提供了与常规物理服务器相比更好的服务器虚拟机整合，同时在常规物理服务器上提供了许多其他操作优势-更容易备份，更节能，在服务器之间移动工作负载更自由等。

+   应用程序虚拟化：通常使用一些流式传输/远程协议技术来实现，例如 Microsoft App-V，或者一些可以将应用程序打包成可以挂载到虚拟机并进行一致设置和交付选项的卷的解决方案，例如 VMware App Volumes。

+   网络虚拟化（以及更广泛的基于云的概念称为软件定义网络（SDN））：这是一种创建独立于物理网络设备（如交换机）的虚拟网络的技术。在更大的范围上，SDN 是网络虚拟化理念的延伸，可以跨越多个站点、位置或数据中心。在 SDN 的概念中，整个网络配置都是在软件中完成的，而不一定需要特定的物理网络配置。网络虚拟化的最大优势在于，您可以轻松管理跨多个位置的复杂网络，而无需对网络数据路径上的所有物理设备进行大规模的物理网络重新配置。这个概念将在第四章《libvirt 网络》和第十二章《使用 OpenStack 扩展 KVM》中进行解释。

+   存储虚拟化（以及一个更新的概念软件定义存储（SDS））：这是一种技术，它通过将汇集的物理存储设备创建为虚拟存储设备，我们可以将其作为单个存储设备进行集中管理。这意味着我们正在创建某种抽象层，将存储设备的内部功能与计算机、应用程序和其他类型的资源隔离开来。作为其延伸，SDS 通过从底层硬件抽象控制和管理平面来解耦存储软件堆栈，以及为虚拟机和应用程序提供不同类型的存储资源（块、文件和基于对象的资源）。

如果你看看这些虚拟化解决方案并大规模扩展它们（提示：云），那么你会意识到你需要各种工具和解决方案来*有效地*管理不断增长的基础设施，因此开发了各种自动化和编排工具。本书后面将介绍其中一些工具，如*第十一章*中的 Ansible，*编排和自动化的 Ansible*。暂时来说，我们只能说，你不能仅依靠标准实用程序（脚本，命令，甚至 GUI 工具）来管理包含数千个虚拟机的环境。你肯定需要一个更加程序化、API 驱动的方法，与虚拟化解决方案紧密集成，因此开发了 OpenStack、OpenShift、Ansible 和**Elasticsearch，Logstash，Kibana**（**ELK**）堆栈，我们将在*第十四章*中介绍*使用 ELK 堆栈监视 KVM 虚拟化平台*。

如果我们谈论*如何*虚拟化虚拟机作为一个对象，有不同类型的虚拟化：

+   分区：这是一种虚拟化类型，其中 CPU 被分成不同的部分，每个部分作为一个独立的系统。这种虚拟化解决方案将服务器隔离成分区，每个分区可以运行一个单独的操作系统（例如**IBM 逻辑分区（LPARs）**）。

+   完全虚拟化：在完全虚拟化中，使用虚拟机来模拟常规硬件，而不知道它被虚拟化的事实。这是出于兼容性原因 - 我们不必修改要在虚拟机中运行的客户操作系统。我们可以为此使用软件和硬件的方法。

基于软件：使用二进制转换来虚拟执行敏感指令集，同时使用软件来模拟硬件，这会增加开销并影响可扩展性。

基于硬件：从方程式中去除二进制转换，同时与 CPU 的虚拟化功能（AMD-V，Intel VT）进行接口，这意味着指令集直接在主机 CPU 上执行。这就是 KVM 所做的（以及其他流行的超级监视程序，如 ESXi，Hyper-V 和 Xen）。

+   半虚拟化：这是一种虚拟化类型，其中客户操作系统了解自己被虚拟化的事实，并且需要进行修改，以及其驱动程序，以便它可以在虚拟化解决方案之上运行。同时，它不需要 CPU 虚拟化扩展来运行虚拟机。例如，Xen 可以作为半虚拟化解决方案工作。

+   混合虚拟化：这是一种使用完全虚拟化和半虚拟化最大优点的虚拟化类型 - 客户操作系统可以无需修改地运行（完全），并且我们可以将额外的半虚拟化驱动程序插入虚拟机以处理虚拟机工作的某些特定方面（通常是 I/O 密集型内存工作负载）。Xen 和 ESXi 也可以以混合虚拟化模式工作。

+   基于容器的虚拟化：这是一种应用虚拟化类型，使用容器。容器是一个对象，它打包了一个应用程序及其所有依赖项，以便应用程序可以进行扩展和快速部署，而无需虚拟机或超级监视程序。请记住，有些技术可以同时作为超级监视程序和容器主机运行。这种技术的一些例子包括 Docker 和 Podman（Red Hat Enterprise Linux 8 中 Docker 的替代品）。

接下来，我们将学习如何使用超级监视程序。

# 使用超级监视程序/虚拟机管理器

正如其名称所示，**虚拟机管理器（VMM）**或虚拟机监视器是负责监视和控制虚拟机或客户操作系统的软件。虚拟机监视器/VMM 负责确保不同的虚拟化管理任务，例如提供虚拟硬件、虚拟机生命周期管理、迁移虚拟机、实时分配资源、定义虚拟机管理策略等。虚拟机监视器/VMM 还负责有效地控制物理平台资源，例如内存转换和 I/O 映射。虚拟化软件的主要优势之一是其能够在同一物理系统或硬件上运行多个客户操作系统。这些多个客户系统可以是相同的操作系统或不同的操作系统。例如，可以在同一物理系统上运行多个 Linux 客户系统作为客户。VMM 负责为这些客户操作系统分配所请求的资源。系统硬件，例如处理器、内存等，必须根据它们的配置分配给这些客户操作系统，而 VMM 可以负责这项任务。因此，VMM 是虚拟化环境中的关键组件。

就类型而言，我们可以将虚拟机监视器分类为类型 1 或类型 2。

## 类型 1 和类型 2 虚拟机监视器

虚拟机监视器主要根据其在系统中的位置或者换句话说，基础操作系统是否存在于系统中，被归类为类型 1 或类型 2 虚拟机监视器。但是并没有关于类型 1 和类型 2 虚拟机监视器的明确或标准定义。如果 VMM/虚拟机监视器直接在硬件顶部运行，通常被认为是类型 1 虚拟机监视器。如果存在操作系统，并且如果 VMM/虚拟机监视器作为一个独立层运行，它将被视为类型 2 虚拟机监视器。再次强调，这个概念存在争议，并且没有标准定义。类型 1 虚拟机监视器直接与系统硬件交互；它不需要任何主机操作系统。您可以直接在裸机系统上安装它，并使其准备好托管虚拟机。类型 1 虚拟机监视器也被称为**裸机**、**嵌入式**或**本地虚拟机监视器**。oVirt-node、VMware ESXi/vSphere 和**Red Hat Enterprise Virtualization Hypervisor**（**RHEV-H**）是类型 1 Linux 虚拟机监视器的示例。以下图表提供了类型 1 虚拟机监视器设计概念的说明：

![图 1.1 - 类型 1 虚拟机监视器设计](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_01_01.jpg)

图 1.1 - 类型 1 虚拟机监视器设计

以下是类型 1 虚拟机监视器的优点：

+   易于安装和配置

+   体积小；优化以将大部分物理资源提供给托管的客户（虚拟机）

+   生成的开销较小，因为它只带有运行虚拟机所需的应用程序

+   更安全，因为一个客户系统中的问题不会影响运行在虚拟机监视器上的其他客户系统

然而，类型 1 虚拟机监视器不利于定制。通常，当您尝试在其上安装任何第三方应用程序或驱动程序时，会有一些限制。

另一方面，类型 2 虚拟机监视器位于操作系统之上，允许您进行多项自定义。类型 2 虚拟机监视器也被称为依赖于主机操作系统进行操作的托管虚拟机监视器。类型 2 虚拟机监视器的主要优点是广泛的硬件支持，因为底层主机操作系统控制硬件访问。以下图表提供了类型 2 虚拟机监视器设计概念的说明：

图 1.2 - 类型 2 虚拟机监视器设计

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_01_02.jpg)

图 1.2 - 类型 2 虚拟机监视器设计

我们何时使用类型 1 和类型 2 的 hypervisor？这主要取决于我们是否已经在服务器上运行了一个想要部署虚拟机的操作系统。例如，如果我们已经在工作站上运行 Linux 桌面，我们可能不会格式化工作站并安装 hypervisor – 这根本没有意义。这是类型 2 hypervisor 的一个很好的用例。众所周知的类型 2 hypervisors 包括 VMware Player、Workstation、Fusion 和 Oracle VirtualBox。另一方面，如果我们专门打算创建一个用于托管虚拟机的服务器，那么这就是类型 1 hypervisor 的领域。

# 开源虚拟化项目

以下表格是 Linux 中的开源虚拟化项目列表：

![图 1.3 – Linux 中的开源虚拟化项目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_01_03.jpg)

图 1.3 – Linux 中的开源虚拟化项目

在接下来的章节中，我们将讨论 Xen 和 KVM，它们是 Linux 中领先的开源虚拟化解决方案。

## Xen

Xen 起源于剑桥大学的一个研究项目。Xen 的首次公开发布是在 2003 年。后来，剑桥大学这个项目的领导者 Ian Pratt 与同样来自剑桥大学的 Simon Crosby 共同创立了一家名为 XenSource 的公司。该公司开始以开源方式开发该项目。2013 年 4 月 15 日，Xen 项目被移至 Linux 基金会作为一个协作项目。Linux 基金会为 Xen 项目推出了一个新的商标，以区别于旧的 Xen 商标的任何商业用途。有关此更多详细信息，请访问[`xenproject.org/`](https://xenproject.org/)。

Xen hypervisor 已经移植到多个处理器系列，如 Intel IA-32/64、x86_64、PowerPC、ARM、MIPS 等。

Xen 的核心概念有四个主要构建块：

+   **Xen hypervisor**：Xen 的一个组成部分，处理物理硬件和虚拟机之间的互联。它处理所有中断、时间、CPU 和内存请求以及硬件交互。

+   **Dom0**：Xen 的控制域，控制虚拟机的环境。其中的主要部分称为 QEMU，这是一款通过二进制转换来模拟常规计算机系统的软件。

+   **管理工具**：我们用来管理整个 Xen 环境的命令行工具和 GUI 工具。

+   **虚拟机**（非特权域，DomU）：我们在 Xen 上运行的客户。

如下图所示，Dom0 是一个完全独立的实体，控制其他虚拟机，而其他所有虚拟机都快乐地堆叠在一起，使用由 hypervisor 提供的系统资源：

![图 1.4 – Xen](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_01_04.jpg)

图 1.4 – Xen

我们稍后会提到的一些管理工具实际上可以与 Xen 虚拟机一起使用。例如，`virsh`命令可以轻松连接和管理 Xen 主机。另一方面，oVirt 是围绕 KVM 虚拟化设计的，这绝对不是管理基于 Xen 的环境的首选解决方案。

## KVM

KVM 代表了最新一代的开源虚拟化。该项目的目标是创建一个现代的 hypervisor，借鉴了以前技术的经验，并利用了今天可用的现代硬件（VT-x、AMD-V 等）。

KVM 只是在安装 KVM 内核模块时将 Linux 内核转换为 hypervisor。然而，由于标准 Linux 内核是 hypervisor，它受益于对标准内核的更改（内存支持，调度程序等）。对这些 Linux 组件的优化，例如 3.1 内核中的调度程序，4.20+内核中嵌套虚拟化的改进，用于缓解 Spectre 攻击的新功能，支持 AMD 安全加密虚拟化，4/5.x 内核中的 Intel iGPU 直通等，都有利于 hypervisor（主机操作系统）和 Linux 客户操作系统。对于 I/O 仿真，KVM 使用一个用户空间软件 QEMU；这是一个进行硬件仿真的用户空间程序。

QEMU 模拟处理器和一长串外围设备，如磁盘、网络、VGA、PCI、USB、串行/并行端口等，以构建一个完整的虚拟硬件，可以在其上安装客户操作系统。这种仿真由 KVM 提供动力。

# Linux 虚拟化在云中为您提供了什么

云是过去 10 年左右几乎所有与 IT 相关的讨论中的一个流行词。如果我们回顾一下云的历史，我们可能会意识到亚马逊是云市场中的第一个关键参与者，2006 年发布了 Amazon Web Services（AWS）和 Amazon Elastic Compute Cloud（EC2）。Google Cloud Platform 于 2008 年发布，Microsoft Azure 于 2010 年发布。就基础设施即服务（IaaS）云模型而言，这些是目前最大的 IaaS 云提供商，尽管还有其他一些（IBM Cloud，VMware Cloud on AWS，Oracle Cloud 和阿里云等）。如果你浏览这个列表，你很快就会意识到大多数这些云平台都是基于 Linux 的（举个例子，亚马逊使用 Xen 和 KVM，而 Google Cloud 使用 KVM 虚拟化）。

目前，有三个主要的开源云项目使用 Linux 虚拟化来构建私有和/或混合云的 IaaS 解决方案：

+   OpenStack：一个完全开源的云操作系统，由几个开源子项目组成，提供了创建 IaaS 云的所有构建块。KVM（Linux 虚拟化）是 OpenStack 部署中使用最多（并且得到最好支持）的 hypervisor。它由供应商不可知的 OpenStack 基金会管理。如何使用 KVM 构建 OpenStack 云将在《第十二章》中详细解释，*使用 OpenStack 扩展 KVM*

+   CloudStack 这是另一个开源的 Apache 软件基金会（ASF）控制的云项目，用于构建和管理高度可扩展的多租户 IaaS 云，并且完全兼容 EC2/S3 API。虽然它支持所有顶级 Linux hypervisors，但大多数 CloudStack 用户选择 Xen，因为它与 CloudStack 紧密集成。

+   Eucalyptus：这是一种与 AWS 兼容的私有云软件，供组织使用以减少其公共云成本并恢复对安全性和性能的控制。它支持 Xen 和 KVM 作为计算资源提供者。

在讨论 OpenStack 时，除了我们在本章中迄今讨论的技术细节之外，还有其他重要的问题需要考虑。当今 IT 中最重要的概念之一实际上是能够运行一个包括各种类型解决方案（如虚拟化解决方案）的环境（纯虚拟化的环境，或云环境），并使用一种能够同时与不同解决方案一起工作的管理层。让我们以 OpenStack 为例。如果你浏览 OpenStack 文档，你很快就会意识到 OpenStack 支持 10 多种不同的虚拟化解决方案，包括以下内容：

+   KVM

+   Xen（通过 libvirt）

+   LXC（Linux 容器）

+   Microsoft Hyper-V

+   VMware ESXi

+   Citrix XenServer

+   用户模式 Linux（UML）

+   PowerVM（IBM Power 5-9 平台）

+   Virtuozzo（超融合解决方案，可以使用虚拟机、存储和容器）

+   z/VM（IBM Z 和 IBM LinuxONE 服务器的虚拟化解决方案）

这就引出了可能跨越不同 CPU 架构、不同的 hypervisors 和其他技术（如 hypervisors）的多云环境，所有这些都在同一个管理工具集下。这只是您可以使用 OpenStack 做的一件事。我们将在本书的后面回到 OpenStack 这个主题，具体来说是在*第十二章*，*使用 OpenStack 扩展 KVM*。

# 总结

在本章中，我们介绍了虚拟化及其不同类型的基础知识。牢记虚拟化在当今大规模 IT 世界中的重要性是有益的，因为了解这些概念如何联系在一起形成更大的画面——大型虚拟化环境和云环境是很重要的。基于云的技术将在后面更详细地介绍——把我们目前提到的内容当作一个开端；正餐还在后头。但下一章属于我们书中的主角——KVM hypervisor 及其相关实用程序。

# 问题

1.  存在哪些类型的 hypervisors？

1.  什么是容器？

1.  什么是基于容器的虚拟化？

1.  什么是 OpenStack？

# 进一步阅读

有关本章内容的更多信息，请参考以下链接：

+   什么是 KVM？：[`www.redhat.com/en/topics/virtualization/what-is-KVM`](https://www.redhat.com/en/topics/virtualization/what-is-KVM)

+   KVM hypervisors：[`www.linux-kvm.org/page/Main_Page`](https://www.linux-kvm.org/page/Main_Page)

+   OpenStack 平台：[`www.openstack.org`](https://www.openstack.org)

+   Xen 项目：[`xenproject.org/`](https://xenproject.org/)


# 第二章：KVM 作为虚拟化解决方案

在本章中，我们将讨论虚拟化作为一个概念以及通过 libvirt、Quick Emulator（QEMU）和 KVM 的实现。实际上，如果我们想解释虚拟化是如何工作的，以及为什么 KVM 虚拟化是 21 世纪 IT 的一个基本部分，我们必须从多核 CPU 和虚拟化的技术背景开始解释；而这是不可能做到的，如果不深入研究 CPU 和操作系统的理论，这样我们才能了解到我们真正想要的东西——虚拟化监视器是什么，以及虚拟化实际上是如何工作的。

在本章中，我们将涵盖以下主题：

+   虚拟化作为一个概念

+   libvirt、QEMU 和 KVM 的内部工作

+   所有这些如何相互通信以提供虚拟化

# 虚拟化作为一个概念

虚拟化是一种将硬件与软件解耦的计算方法。它提供了更好、更高效和更具程序性的资源分配和共享方法，用于运行操作系统和应用程序的虚拟机。

如果我们将过去的传统物理计算与虚拟化进行比较，我们可以说通过虚拟化，我们有可能在同一台硬件设备（同一台物理服务器）上运行多个客户操作系统（多个虚拟服务器）。如果我们使用类型 1 虚拟机监视器（在第一章《理解 Linux 虚拟化》中有解释），这意味着虚拟机监视器将负责让虚拟服务器访问物理硬件。这是因为有多个虚拟服务器使用与同一台物理服务器上的其他虚拟服务器相同的硬件。这通常由某种调度算法支持，该算法在虚拟机监视器中以编程方式实现，以便我们可以从同一台物理服务器中获得更高的效率。

## 虚拟化与物理环境

让我们试着将这两种方法可视化——物理和虚拟。在物理服务器中，我们直接在服务器硬件上安装操作系统，并在操作系统上运行应用程序。下图显示了这种方法的工作原理：

![图 2.1 – 物理服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_01.jpg)

图 2.1 – 物理服务器

在虚拟化的世界中，我们运行一个虚拟机监视器（如 KVM），以及在该虚拟机监视器上运行的虚拟机。在这些虚拟机内部，我们运行相同的操作系统和应用程序，就像在物理服务器上一样。虚拟化的方法如下图所示：

![图 2.2 – 虚拟机监视器和两个虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_02.jpg)

图 2.2 – 虚拟机监视器和两个虚拟机

仍然存在各种情况，需要使用物理方法。例如，全球范围内仍然有成千上万的应用程序在物理服务器上运行，因为这些服务器无法虚拟化。它们无法虚拟化的原因各不相同。例如，最常见的原因实际上是最简单的原因——也许这些应用程序正在运行不受虚拟化软件供应商支持的操作系统上。这意味着您无法虚拟化该操作系统/应用程序组合，因为该操作系统不支持某些虚拟化硬件，最常见的是网络或存储适配器。相同的一般思想也适用于云——将事物移动到云中并不总是最好的想法，我们将在本书后面描述。

## 为什么虚拟化如此重要？

今天我们运行的许多应用程序都不会很好地扩展（增加更多的 CPU、内存或其他资源）-它们只是没有以这种方式编程，或者不能被严重并行化。这意味着如果一个应用程序不能充分利用其所拥有的所有资源，服务器将会有很多“空闲空间”-这一次，我们不是在谈论磁盘的空闲空间；我们实际上是在指“计算”空闲空间，即 CPU 和内存级别的空闲空间。这意味着我们没有充分利用我们为其付费的服务器的能力-我们的意图是让它完全使用，而不是部分使用。

效率和编程方法的重要性还有其他原因。事实是，在 2003 年至 2005 年这段时间，当一切都是关于 CPU 频率的炫耀权利（等于 CPU 速度）时，英特尔和 AMD 在单核 CPU 的概念发展方面遇到了瓶颈。他们无法在 CPU 上塞入更多的附加元素（无论是用于执行还是缓存），或者提高单核的速度，而不严重损害 CPU 的电流供应方式。这意味着，最终，这种方法会损害 CPU 和运行它的整个系统的可靠性。如果您想了解更多信息，我们建议您搜索有关英特尔 NetBurst 架构 CPU（例如 Prescott 核心）和它们的年轻兄弟奔腾 D（Smithfield 核心）的文章，后者基本上是将两个 Prescott 核心粘合在一起，以便最终结果是双核 CPU。一个非常非常热的双核 CPU。

在那之前的几代中，英特尔和 AMD 尝试并测试了其他技术，例如“让系统拥有多个执行单元”的原则。例如，我们有英特尔奔腾 Pro 双插槽系统和 AMD Opteron 双插槽和四插槽系统。当我们开始讨论虚拟化的一些非常重要的方面时，我们将在本书的后面回到这些内容（例如，非统一内存访问（NUMA））。

因此，无论从哪个角度来看，2005 年 PC CPU 开始获得多个核心（AMD 是第一个推出服务器多核 CPU 的厂商，而英特尔是第一个推出桌面多核 CPU 的厂商）是唯一合理的前进方式。这些核心更小，更高效（耗电更少），通常是更好的长期方法。当然，这意味着如果微软和甲骨文等公司想要使用他们的应用程序并获得多核服务器的好处，操作系统和应用程序必须进行大量重写。

总之，对于基于 PC 的服务器来说，从 CPU 的角度来看，转向多核 CPU 是开始朝着我们今天所熟悉和喜爱的虚拟化概念努力的一个合适的时刻。

与这些发展并行的是，CPU 还有其他增加-例如，可以处理特定类型操作的额外 CPU 寄存器。很多人听说过 MMX、SSE、SSE2、SSE3、SSE4.x、AVX、AVX2、AES 等指令集。这些今天也都非常重要，因为它们给了我们将某些指令类型“卸载”到特定 CPU 寄存器的可能性。这意味着这些指令不必在 CPU 上作为一般的串行设备运行，执行这些任务更慢。相反，这些指令可以发送到专门用于这些指令的 CPU 寄存器。可以将其视为在 CPU 芯片上拥有单独的小加速器，可以运行软件堆栈的某些部分而不会占用通用 CPU 管道。其中之一是英特尔的虚拟机扩展（VMX），或者 AMD 虚拟化（AMD-V），它们都使我们能够为其各自的平台提供全面的、基于硬件的虚拟化支持。

## 虚拟化的硬件要求

在 PC 上引入基于软件的虚拟化后，硬件和软件方面都取得了很大的发展。最终结果——正如我们在前一章中提到的——是 CPU 具有了更多的功能和性能。这导致了对硬件辅助虚拟化的大力推动，这在理论上看起来是更快速和更先进的方式。举个例子，在 2003 年至 2006 年期间有很多 CPU 不支持硬件辅助虚拟化，比如英特尔奔腾 4、奔腾 D，以及 AMD Athlon、Turion、Duron 等。直到 2006 年，英特尔和 AMD 才在其各自的 CPU 上更广泛地提供硬件辅助虚拟化作为一项功能。此外，64 位 CPU 也需要一些时间，而在 32 位架构上几乎没有兴趣运行硬件辅助虚拟化。这主要原因是您无法分配超过 4GB 的内存，这严重限制了虚拟化作为概念的范围。

牢记所有这些，这些是我们今天必须遵守的要求，以便我们可以运行具有完全硬件辅助虚拟化支持的现代虚拟化监控程序：

+   二级地址转换，快速虚拟化索引，扩展页表（SLAT/RVI/EPT）支持：这是一个虚拟化监控程序使用的 CPU 技术，以便它可以拥有虚拟到物理内存地址的映射。虚拟机在虚拟内存空间中运行，可以分散在物理内存的各个位置，因此通过使用 SLAT/EPT 等额外的映射（通过额外的 TLB 实现），可以减少内存访问的延迟。如果没有这样的技术，我们将不得不访问计算机内存的物理地址，这将是混乱、不安全和延迟敏感的。为了避免混淆，EPT 是英特尔 CPU 中 SLAT 技术的名称（AMD 使用 RVI 术语，而英特尔使用 EPT 术语）。

+   **英特尔 VT 或 AMD-V 支持**：如果英特尔 CPU 具有 VT（或 AMD CPU 具有 AMD-V），这意味着它支持硬件虚拟化扩展和完全虚拟化。

+   **长模式支持**，这意味着 CPU 支持 64 位。没有 64 位架构，虚拟化基本上是无用的，因为您只能为虚拟机提供 4GB 的内存（这是 32 位架构的限制）。通过使用 64 位架构，我们可以分配更多的内存（取决于我们使用的 CPU），这意味着更多的机会为虚拟机提供内存，否则在 21 世纪的 IT 空间中整个虚拟化概念将毫无意义。

+   **具有输入/输出内存管理单元（IOMMU）虚拟化的可能性（例如 AMD-Vi、英特尔 VT-d 和 ARM 上的第 2 阶段表）**，这意味着我们允许虚拟机直接访问外围硬件（显卡、存储控制器、网络设备等）。此功能必须在 CPU 和主板芯片组/固件方面都启用。

+   **进行单根输入输出虚拟化**（SR/IOV）的可能性，这使我们能够直接将 PCI Express 设备（例如以太网端口）转发到多个虚拟机。SR-IOV 的关键方面是其通过称为**虚拟功能**（VFs）的功能，能够将一个物理设备与多个虚拟机共享。此功能需要硬件和驱动程序支持。

+   PCI passthrough 的可能性，意味着我们可以将连接到服务器主板的 PCI Express 连接卡（例如，显卡）呈现给虚拟机，就好像该卡是通过称为“物理功能”（PFs）的功能直接连接到虚拟机一样。这意味着绕过连接通常会经过的各种 Hypervisor 级别。

+   **可信平台模块（TPM）支持**，通常作为额外的主板芯片实现。使用 TPM 在安全方面有很多优势，因为它可以用于提供加密支持（即创建、保存和保护加密密钥的使用）。在 Linux 世界中，围绕 KVM 虚拟化使用 TPM 引起了相当大的轰动，这导致英特尔在 2018 年夏天开源了 TPM2 堆栈。

在讨论 SR-IOV 和 PCI passthrough 时，请确保注意核心功能，称为 PF 和 VF。这两个关键词将更容易记住设备是如何（直接或通过 Hypervisor）转发到各自的虚拟机的*位置*（在物理或虚拟级别）和*方式*。这些功能对企业空间非常重要，也适用于一些特定场景。举个例子，如果没有这些功能，就无法使用工作站级虚拟机来运行 AutoCAD 和类似的应用程序。这是因为 CPU 上的集成显卡速度太慢了。这时你就需要在服务器上添加 GPU，这样你就可以使用 Hypervisor 将整个 GPU 或其*部分*转发到一个虚拟机或多个虚拟机。

在系统内存方面，也有各种要考虑的主题。AMD 在 Athlon 64 中开始将内存控制器集成到 CPU 中，这是在英特尔之前的几年（英特尔首次在 2008 年推出的 Nehalem CPU 核心中实现了这一点）。将内存控制器集成到 CPU 中意味着当 CPU 访问内存进行内存 I/O 操作时，系统的延迟更低。在此之前，内存控制器集成到了所谓的 NorthBridge 芯片中，这是系统主板上的一个独立芯片，负责所有快速总线和内存。但这意味着额外的延迟，特别是当您尝试将这一原则扩展到多插槽、多核 CPU 时。此外，随着 Athlon 64 在 Socket 939 上的推出，AMD 转向了双通道内存架构，这在桌面和服务器市场上现在是一个熟悉的主题。三通道和四通道内存控制器已成为服务器的事实标准。一些最新的英特尔至强 CPU 支持六通道内存控制器，AMD EPYC CPU 也支持八通道内存控制器。这对整体内存带宽和延迟有着巨大的影响，反过来又对物理和虚拟服务器上内存敏感应用程序的速度有着巨大的影响。

为什么这很重要？通道越多，延迟越低，CPU 到内存的带宽就越大。这对今天 IT 空间中许多工作负载（例如数据库）非常有吸引力。

## 虚拟化的软件要求

现在我们已经涵盖了虚拟化的基本硬件方面，让我们转向虚拟化的软件方面。为了做到这一点，我们必须涵盖计算机科学中的一些行话。话虽如此，让我们从一个叫做保护环的东西开始。在计算机科学中，存在着各种分层的保护域/特权环。这些是保护数据或故障的机制，基于在访问计算机系统资源时强制执行的安全性。这些保护域有助于计算机系统的安全。通过将这些保护环想象成指令区域，我们可以通过以下图表来表示它们：

![图 2.3 – 保护环（来源：https://en.wikipedia.org/wiki/Protection_ring）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_03.jpg)

图 2.3 – 保护环（来源：[`en.wikipedia.org/wiki/Protection_ring`](https://en.wikipedia.org/wiki/Protection_ring)）

如前图所示，保护环从最特权到最不特权的顺序编号。环 0 是最特权的级别，直接与物理硬件交互，比如 CPU 和内存。这些特权环保护了资源，比如内存、I/O 端口和 CPU 指令。环 1 和环 2 大多数情况下是未使用的。大多数通用系统只使用两个环，即使它们运行的硬件提供了更多的 CPU 模式。两个主要的 CPU 模式是内核模式和用户模式，这也与进程执行的方式有关。您可以在此链接中了解更多信息：[`access.redhat.com/sites/default/files/attachments/processstates_20120831.pdf`](https://access.redhat.com/sites/default/files/attachments/processstates_20120831.pdf) 从操作系统的角度来看，环 0 被称为内核模式/监管模式，环 3 是用户模式。正如您可能已经猜到的那样，应用程序在环 3 中运行。

像 Linux 和 Windows 这样的操作系统使用监管/内核和用户模式。这种模式几乎无法在没有调用内核或没有内核帮助的情况下对外部世界做任何事情，因为它对内存、CPU 和 I/O 端口的访问受到限制。内核可以在特权模式下运行，这意味着它可以在环 0 上运行。为了执行专门的功能，用户模式代码（在环 3 中运行的所有应用程序）必须对监管模式甚至内核空间执行系统调用，操作系统的受信任代码将执行所需的任务并将执行返回到用户空间。简而言之，在正常环境中，操作系统在环 0 中运行。它需要最高的特权级别来进行资源管理并提供对硬件的访问。以下图表解释了这一点：

![图 2.4 – 系统调用到监管模式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_04.jpg)

图 2.4 – 系统调用到监管模式

环 0 以上的环在处理器模式下运行未受保护的指令。虚拟机监视器（VMM）需要访问主机的内存、CPU 和 I/O 设备。由于只有在环 0 中运行的代码被允许执行这些操作，它需要在最特权的环，即环 0 中运行，并且必须放置在内核旁边。没有特定的硬件虚拟化支持，虚拟机监视器或 VMM 在环 0 中运行；这基本上阻止了虚拟机的操作系统在环 0 中运行。因此，虚拟机的操作系统必须驻留在环 1 中。安装在虚拟机中的操作系统也希望访问所有资源，因为它不知道虚拟化层；为了实现这一点，它必须在环 0 中运行，类似于 VMM。由于一次只能运行一个内核在环 0 中，客户操作系统必须在另一个权限较低的环中运行，或者必须修改为在用户模式下运行。

这导致了引入了一些虚拟化方法，称为全虚拟化和半虚拟化，我们之前提到过。现在，让我们尝试以更加技术化的方式来解释它们。

### 全虚拟化

在全虚拟化中，特权指令被模拟以克服客户操作系统在 ring 1 中运行和 VMM 在 ring 0 中运行所产生的限制。全虚拟化是在第一代 x86 VMM 中实现的。它依赖于诸如二进制翻译之类的技术来陷阱和虚拟化某些敏感和不可虚拟化的指令的执行。也就是说，在二进制翻译中，一些系统调用被解释并动态重写。以下图表描述了客户操作系统如何通过 ring 1 访问主机计算机硬件以获取特权指令，以及如何在不涉及 ring 1 的情况下执行非特权指令：

![图 2.5 – 二进制翻译](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_05.jpg)

图 2.5 – 二进制翻译

采用这种方法，关键指令被发现（在运行时静态或动态地）并在 VMM 中被替换为陷阱，这些陷阱将在软件中被模拟。与在本地虚拟化架构上运行的虚拟机相比，二进制翻译可能会产生较大的性能开销。这可以从以下图表中看出：

![图 2.6 – 全虚拟化](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_06.jpg)

图 2.6 – 全虚拟化

然而，正如前面的图表所示，当我们使用全虚拟化时，我们可以使用未经修改的客户操作系统。这意味着我们不必修改客户内核以使其在 VMM 上运行。当客户内核执行特权操作时，VMM 提供 CPU 仿真来处理和修改受保护的 CPU 操作。然而，正如我们之前提到的，与另一种虚拟化模式——称为半虚拟化相比，这会导致性能开销。

### 半虚拟化

在半虚拟化中，客户操作系统需要被修改以允许这些指令访问 ring 0。换句话说，操作系统需要被修改以在 VMM/虚拟机监控程序和客户之间通过*后端*（超级调用）路径进行通信：

![图 2.7 – 半虚拟化](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_07.jpg)

图 2.7 – 半虚拟化

半虚拟化（[`en.wikipedia.org/wiki/Paravirtualization`](https://en.wikipedia.org/wiki/Paravirtualization)）是一种技术，其中虚拟机监控程序提供一个 API，而客户虚拟机的操作系统调用该 API，这需要对主机操作系统进行修改。特权指令调用与 VMM 提供的 API 函数进行交换。在这种情况下，修改后的客户操作系统可以在 ring 0 中运行。

正如您所看到的，根据这种技术，客户内核被修改为在 VMM 上运行。换句话说，客户内核知道自己已被虚拟化。应该在 ring 0 中运行的特权指令/操作已被称为超级调用的调用所取代，这些调用与 VMM 进行通信。这些超级调用调用 VMM，以便它代表客户内核执行任务。由于客户内核可以通过超级调用直接与 VMM 通信，因此与全虚拟化相比，这种技术具有更高的性能。然而，这需要一个专门的客户内核，它知道半虚拟化并具有所需的软件支持。

半虚拟化和全虚拟化的概念曾经是一种常见的虚拟化方式，但并不是最佳的、可管理的方式。这就是硬件辅助虚拟化发挥作用的地方，我们将在下一节中描述。

### 硬件辅助虚拟化

英特尔和 AMD 意识到全虚拟化和半虚拟化是 x86 架构上虚拟化的主要挑战（由于本书的范围限于 x86 架构，我们将主要讨论这里的架构的演变），由于性能开销和设计和维护解决方案的复杂性。英特尔和 AMD 分别创建了 x86 架构的新处理器扩展，称为 Intel VT-x 和 AMD-V。在 Itanium 架构上，硬件辅助虚拟化被称为 VT-i。硬件辅助虚拟化是一种平台虚拟化方法，旨在有效利用硬件能力进行全虚拟化。各种供应商将这项技术称为不同的名称，包括加速虚拟化、硬件虚拟机和本机虚拟化。

为了更好地支持虚拟化，英特尔和 AMD 分别引入了**虚拟化技术**（**VT**）和**安全虚拟机**（**SVM**），作为 IA-32 指令集的扩展。这些扩展允许 VMM/超级监视程序运行期望在内核模式下运行的客户操作系统，在较低特权级别的环境中。硬件辅助虚拟化不仅提出了新的指令，还引入了一个新的特权访问级别，称为环 -1，超级监视程序/VMM 可以在其中运行。因此，客户虚拟机可以在环 0 中运行。有了硬件辅助虚拟化，操作系统可以直接访问资源，而无需任何仿真或操作系统修改。超级监视程序或 VMM 现在可以在新引入的特权级别环 -1 中运行，客户操作系统在环 0 中运行。此外，硬件辅助虚拟化使 VMM/超级监视程序放松，需要执行的工作量较少，从而减少了性能开销。可以用以下图表描述直接在环 -1 中运行的能力：

![图 2.8 – 硬件辅助虚拟化](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_08.jpg)

图 2.8 – 硬件辅助虚拟化

简单来说，这种虚拟化感知硬件为我们提供了构建 VMM 的支持，并确保了客户操作系统的隔离。这有助于我们实现更好的性能，并避免设计虚拟化解决方案的复杂性。现代虚拟化技术利用这一特性来提供虚拟化。一个例子是 KVM，我们将在本书中详细讨论。

现在我们已经涵盖了虚拟化的硬件和软件方面，让我们看看所有这些如何适用于 KVM 作为一种虚拟化技术。

# libvirt、QEMU 和 KVM 的内部工作

libvirt、QEMU 和 KVM 的交互是本书涵盖的完整虚拟化功能的关键。它们是 Linux 虚拟化拼图中最重要的部分，每个都有自己的作用。让我们描述一下它们的作用以及它们如何相互作用。

## libvirt

在使用 KVM 时，您最有可能首先接触到其主要的`virsh`。请记住，您可以通过 libvirt 管理远程超级监视程序，因此您不仅限于本地超级监视程序。这就是为什么 virt-manager 有一个额外的参数叫做`--connect`。libvirt 也是各种其他 KVM 管理工具的一部分，比如 oVirt（[`www.ovirt.org`](http://www.ovirt.org)），我们将在下一章中讨论。

libvirt 库的目标是提供一个通用和稳定的层，用于管理在 hypervisor 上运行的虚拟机。简而言之，作为一个管理层，它负责提供执行管理任务的 API，如虚拟机的提供、创建、修改、监视、控制、迁移等。在 Linux 中，您会注意到一些进程是守护进程。libvirt 进程也是守护进程，称为`libvirtd`。与任何其他守护进程一样，`libvirtd`在请求时为其客户端提供服务。让我们试着理解当一个 libvirt 客户端，如`virsh`或 virt-manager，从`libvirtd`请求服务时到底发生了什么。根据客户端传递的连接 URI（在下一节中讨论），`libvirtd`打开到 hypervisor 的连接。这就是客户端的`virsh`或 virt-manager 要求`libvirtd`开始与 hypervisor 通信的方式。在本书的范围内，我们的目标是研究 KVM 虚拟化技术。因此，最好将其视为 QEMU/KVM hypervisor，而不是讨论来自`libvirtd`的其他 hypervisor 通信。当您看到 QEMU/KVM 作为底层 hypervisor 名称而不是 QEMU 或 KVM 时，您可能会有点困惑。但不用担心-一切都会在适当的时候变得清晰。QEMU 和 KVM 之间的连接将在接下来的章节中讨论。现在，只需知道有一个 hypervisor 同时使用 QEMU 和 KVM 技术。

### 通过 virsh 连接到远程系统

一个远程连接的`virsh`二进制的简单命令行示例如下：

```
virsh --connect qemu+ssh://root@remoteserver.yourdomain.com/system list ––all
```

现在让我们来看看源代码。我们可以从 libvirt Git 存储库中获取 libvirt 源代码：

```
[root@kvmsource]# yum -y install git-core
[root@kvmsource]# git clone git://libvirt.org/libvirt.git
```

一旦克隆了 repo，您可以在 repo 中看到以下文件层次结构：

![图 2.9 – 通过 Git 下载的 QEMU 源内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_09.jpg)

图 2.9 – 通过 Git 下载的 QEMU 源内容

libvirt 代码基于 C 编程语言；然而，libvirt 在不同语言中有语言绑定，如`C#`、`Java`、`OCaml`、`Perl`、`PHP`、`Python`、`Ruby`等。有关这些绑定的更多详细信息，请参考[`libvirt.org/bindings.html`](https://libvirt.org/bindings.html)。源代码中的主要（和少数）目录是`docs`、`daemon`、`src`等。libvirt 项目有很好的文档，并且文档可以在源代码存储库和[`libvirt.org`](http://libvirt.org)上找到。

libvirt 使用*基于驱动程序的架构*，这使得 libvirt 能够与各种外部 hypervisors 进行通信。这意味着 libvirt 有内部驱动程序，用于与其他 hypervisors 和解决方案进行接口，如 LXC、Xen、QEMU、VirtualBox、Microsoft Hyper-V、bhyve（BSD hypervisor）、IBM PowerVM、OpenVZ（开放的基于容器的解决方案）等，如下图所示：

![图 2.10 – 基于驱动程序的架构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_10.jpg)

图 2.10 – 基于驱动程序的架构

通过`virsh`命令连接到各种虚拟化解决方案可以让我们更多地使用`virsh`命令。这在混合环境中可能非常有用，比如如果您从同一系统连接到 KVM 和 XEN hypervisors。

与前面的图一样，当客户端在初始化库时传递`virsh --connect QEMU://xxxx/system`时，这个公共 API 在后台使用内部驱动程序。是的，在 libvirt 中有不同类别的驱动程序实现。例如，有`hypervisor`、`interface`、`network`、`nodeDevice`、`nwfilter`、`secret`、`storage`等。请参考 libvirt 源代码中的`driver.h`了解与不同驱动程序相关的驱动程序数据结构和其他函数。

以以下示例为例：

```
struct _virConnectDriver {
    virHypervisorDriverPtr hypervisorDriver;
    virInterfaceDriverPtr interfaceDriver;
    virNetworkDriverPtr networkDriver;
    virNodeDeviceDriverPtr nodeDeviceDriver;
    virNWFilterDriverPtr nwfilterDriver;
    virSecretDriverPtr secretDriver;
    virStorageDriverPtr storageDriver;
     };
```

`struct`字段是不言自明的，传达了每个字段成员代表的驱动类型。正如你可能已经猜到的那样，重要的或主要的驱动之一是 hypervisor 驱动，它是 libvirt 支持的不同 hypervisor 的驱动实现。这些驱动被归类为`README`和 libvirt 源代码）：

+   `bhyve`: BSD hypervisor

+   `esx/`: 使用 vSphere API over SOAP 的 VMware ESX 和 GSX 支持

+   `hyperv/`: 使用 WinRM 的 Microsoft Hyper-V 支持

+   `lxc/`: Linux 本地容器

+   `openvz/`: 使用 CLI 工具的 OpenVZ 容器

+   `phyp/`: 使用 SSH 上的 CLI 工具的 IBM Power Hypervisor

+   `qemu/`: 使用 QEMU CLI/monitor 的 QEMU/KVM

+   `remote/`: 通用 libvirt 本机 RPC 客户端

+   `test/`: 用于测试的*模拟*驱动

+   `uml/`: 用户模式 Linux

+   `vbox/`: 使用本机 API 的 VirtualBox

+   `vmware/`: 使用`vmrun`工具的 VMware Workstation 和 Player

+   `xen/`: 使用超级调用、XenD SEXPR 和 XenStore 的 Xen

+   `xenapi`: 使用`libxenserver`的 Xen

之前我们提到了还有次级驱动程序。并非所有，但一些次级驱动程序（见下文）被几个 hypervisor 共享。目前，这些次级驱动程序被 LXC、OpenVZ、QEMU、UML 和 Xen 驱动程序使用。ESX、Hyper-V、Power Hypervisor、Remote、Test 和 VirtualBox 驱动程序都直接实现了次级驱动程序。

次级驱动程序的示例包括以下内容：

+   `cpu/`: CPU 特性管理

+   `interface/`: 主机网络接口管理

+   `network/`: 虚拟 NAT 网络

+   `nwfilter/`: 网络流量过滤规则

+   `node_device/`: 主机设备枚举

+   `secret/`: 密钥管理

+   `security/`: 强制访问控制驱动

+   `storage/`: 存储管理驱动

libvirt 在常规管理操作中扮演着重要角色，比如创建和管理虚拟机（客户域）。还需要使用其他次级驱动程序来执行这些操作，比如接口设置、防火墙规则、存储管理和 API 的一般配置。以下内容来自[`libvirt.org/api.html`](https://libvirt.org/api.html)：

在设备上，应用程序获取了一个 virConnectPtr 连接到 hypervisor，然后可以使用它来管理 hypervisor 的可用域和相关的虚拟化资源，比如存储和网络。所有这些都作为一流对象暴露，并连接到 hypervisor 连接（以及可用的节点或集群）。

以下图显示了 API 导出的五个主要对象及它们之间的连接：

![图 2.11 – 导出的 API 对象及其通信](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_11.jpg)

图 2.11 – 导出的 API 对象及其通信

让我们详细介绍一下 libvirt 代码中可用的主要对象。libvirt 内的大多数函数都使用这些对象进行操作：

+   `virConnectPtr`: 正如我们之前讨论的，libvirt 必须连接到一个 hypervisor 并执行操作。连接到 hypervisor 被表示为这个对象。这个对象是 libvirt API 中的核心对象之一。

+   `virDomainPtr`: 在 libvirt 代码中，虚拟机或客户系统通常被称为域。`virDomainPtr`代表一个活动/已定义的域/虚拟机对象。

+   `virStorageVolPtr`: 有不同的存储卷，暴露给域/客户系统。`virStorageVolPtr`通常代表其中一个存储卷。

+   `virStoragePoolPtr`: 导出的存储卷是存储池的一部分。这个对象代表存储池中的一个存储卷。

+   `virNetworkPtr`: 在 libvirt 中，我们可以定义不同的网络。一个单一的虚拟网络（活动/已定义状态）由`virNetworkPtr`对象表示。

现在你应该对 libvirt 实现的内部结构有一些了解；这可以进一步扩展：

![图 2.12 – libvirt 源代码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_12.jpg)

图 2.12 – libvirt 源代码

我们感兴趣的是 QEMU/KVM。因此，让我们进一步探讨一下。在 libvirt 源代码存储库的`src`目录中，有一个用于 QEMU hypervisor 驱动程序实现代码的目录。请注意一些源文件，比如`qemu_driver.c`，它包含了用于管理 QEMU 客户端的核心驱动程序方法。

请参阅以下示例：

```
static virDrvOpenStatus qemuConnectOpen(virConnectPtr conn,
                                    virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                    unsigned int flags)
```

libvirt 使用不同的驱动程序代码来探测底层的 hypervisor/模拟器。在本书的背景下，libvirt 负责发现 QEMU/KVM 存在的组件是 QEMU 驱动程序代码。该驱动程序探测`qemu-kvm`二进制文件和`/dev/kvm`设备节点，以确认 KVM 完全虚拟化的硬件加速客户端是否可用。如果这些不可用，那么通过`qemu`、`qemu-system-x86_64`、`qemu-system-mips`、`qemu-system-microblaze`等二进制文件的存在来验证 QEMU 模拟器（无 KVM）的可能性。

验证可以在`qemu_capabilities.c`中看到：

```
from  (qemu_capabilities.c)
static int virQEMUCapsInitGuest ( ..,  .. ,  virArch hostarch,  virArch guestarch)
{
...
binary = virQEMUCapsFindBinaryForArch (hostarch, guestarch);
...
native_kvm = (hostarch == guestarch);
x86_32on64_kvm = (hostarch == VIR_ARCH_X86_64 &&  guestarch == VIR_ARCH_I686);
...
if (native_kvm || x86_32on64_kvm || arm_32on64_kvm || ppc64_kvm) {
    const char *kvmbins[] = {
        "/usr/libexec/qemu-kvm", /* RHEL */
        "qemu-kvm", /* Fedora */
        "kvm", /* Debian/Ubuntu */    …};
...
kvmbin = virFindFileInPath(kvmbins[i]); 
...
virQEMUCapsInitGuestFromBinary (caps, binary, qemubinCaps, kvmbin, kvmbinCaps,guestarch);                 
...
}
```

然后，KVM 启用如下代码片段所示：

```
int virQEMUCapsInitGuestFromBinary(..., *binary, qemubinCaps, *kvmbin, kvmbinCaps, guestarch)
{
……...
  if (virFileExists("/dev/kvm") && (virQEMUCapsGet(qemubinCaps, QEMU_CAPS_KVM) ||
      virQEMUCapsGet(qemubinCaps, QEMU_CAPS_ENABLE_KVM) ||     kvmbin))
      haskvm = true;
```

基本上，libvirt 的 QEMU 驱动程序正在寻找不同发行版和不同路径中的不同二进制文件 - 例如，在 RHEL/Fedora 中的`qemu-kvm`。此外，它根据主机和客户端的架构组合找到合适的 QEMU 二进制文件。如果找到了 QEMU 二进制文件和 KVM，那么 KVM 将完全虚拟化，并且硬件加速的客户端将可用。形成整个 QEMU-KVM 进程的命令行参数也是 libvirt 的责任。最后，在形成整个命令行参数和输入后，libvirt 调用`exec()`来创建一个 QEMU-KVM 进程。

```
util/vircommand.c
static int virExec(virCommandPtr cmd) {
…...
  if (cmd->env)
    execve(binary, cmd->args, cmd->env);
  else
    execv(binary, cmd->args);
```

在 KVM 领域，有一个误解，即 libvirt 直接使用 KVM 内核模块暴露的设备文件（`/dev/kvm`），并通过 KVM 的不同`ioctl()`函数调用来指示虚拟化。这确实是一个误解！正如前面提到的，libvirt 生成 QEMU-KVM 进程，而 QEMU 与 KVM 内核模块进行通信。简而言之，QEMU 通过不同的`ioctl()`向 KVM 进行通信，以便访问由 KVM 内核模块暴露的`/dev/kvm`设备文件。要创建一个虚拟机（例如`virsh create`），libvirt 所做的就是生成一个 QEMU 进程，然后 QEMU 创建虚拟机。请注意，`libvirtd`通过`libvirtd`为每个虚拟机启动一个单独的 QEMU-KVM 进程。虚拟机的属性（CPU 数量、内存大小、I/O 设备配置等）在`/etc/libvirt/qemu`目录中的单独的 XML 文件中定义。这些 XML 文件包含 QEMU-KVM 进程启动运行虚拟机所需的所有必要设置。libvirt 客户端通过`libvirtd`正在监听的`AF_UNIX socket /var/run/libvirt/libvirt-sock`发出请求。

我们列表上的下一个主题是 QEMU - 它是什么，它是如何工作的，以及它如何与 KVM 交互。

## QEMU

QEMU 是由 FFmpeg 的创始人 Fabrice Bellard 编写的。它是一款免费软件，主要根据 GNU 的**通用公共许可证**（**GPL**）许可。QEMU 是一款通用的开源机器模拟器和虚拟化软件。当用作机器模拟器时，QEMU 可以在不同的机器上（例如您自己的 PC）运行为一台机器（如 ARM 板）制作的操作系统和程序。

通过动态翻译，它实现了非常好的性能（参见[`www.qemu.org/`](https://www.qemu.org/)）。让我重新表述前面的段落，并给出更具体的解释。QEMU 实际上是一个托管的 hypervisor/VMM，执行硬件虚拟化。你感到困惑吗？如果是这样，不要担心。当你通过本章的最后，特别是当你通过每个相关的组件并将这里使用的整个路径相关联起来执行虚拟化时，你会有一个更清晰的认识。QEMU 可以充当模拟器或虚拟化器。

### QEMU 作为一个模拟器

在上一章中，我们讨论了二进制翻译。当 QEMU 作为模拟器运行时，它能够在不同的机器类型上运行为另一种机器类型制作的操作系统/程序。这是如何可能的？它只是使用了二进制翻译方法。在这种模式下，QEMU 通过动态二进制翻译技术模拟 CPU，并提供一组设备模型。因此，它能够运行具有不同架构的不同未修改的客户操作系统。这里需要二进制翻译，因为客户代码必须在主机 CPU 上执行。执行这项工作的二进制翻译器称为**Tiny Code Generator**（**TCG**）；它是一个**即时**（**JIT**）编译器。它将为给定处理器编写的二进制代码转换为另一种形式的二进制代码（例如 ARM 在 X86 中），如下图所示（TCG 信息来自[`en.wikipedia.org/wiki/QEMU#Tiny_Code_Generator`](https://en.wikipedia.org/wiki/QEMU#Tiny_Code_Generator)）:

![图 2.13 - QEMU 中的 TCG](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_13.jpg)

图 2.13 - QEMU 中的 TCG

通过使用这种方法，QEMU 可以牺牲一点执行速度以获得更广泛的兼容性。要牢记的是，如今大多数环境都是基于不同的操作系统，这似乎是一个明智的折衷方案。

### QEMU 作为虚拟化器

这是 QEMU 在主机 CPU 上直接执行客户代码，从而实现本机性能的模式。例如，在 Xen/KVM hypervisors 下工作时，QEMU 可以以这种模式运行。如果 KVM 是底层 hypervisor，QEMU 可以虚拟化嵌入式客户，如 Power PC、S390、x86 等。简而言之，QEMU 能够在不使用 KVM 的情况下使用上述的二进制翻译方法运行。与 KVM 启用的硬件加速虚拟化相比，这种执行速度会较慢。在任何模式下，无论是作为虚拟化器还是模拟器，QEMU 不仅仅是模拟处理器；它还模拟不同的外围设备，如磁盘、网络、VGA、PCI、串行和并行端口、USB 等。除了这种 I/O 设备模拟外，在与 KVM 一起工作时，QEMU-KVM 还创建和初始化虚拟机。如下图所示，它还为每个客户的**虚拟 CPU**（**vCPU**）初始化不同的 POSIX 线程。它还提供了一个框架，用于在 QEMU-KVM 的用户模式地址空间内模拟虚拟机的物理地址空间：

![图 2.14 - QEMU 作为虚拟化器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_14.jpg)

图 2.14 - QEMU 作为虚拟化器

为了在物理 CPU 中执行客户代码，QEMU 使用了 POSIX 线程。也就是说，客户 vCPU 在主机内核中作为 POSIX 线程执行。这本身带来了很多优势，因为在高层视图中，这些只是主机内核的一些进程。从另一个角度来看，QEMU 提供了 KVM hypervisor 的用户空间部分。QEMU 通过 KVM 内核模块运行客户代码。在与 KVM 一起工作时，QEMU 还进行 I/O 模拟、I/O 设备设置、实时迁移等。

QEMU 打开了由 KVM 内核模块暴露的设备文件(`/dev/kvm`)，并对其执行`ioctl()`函数调用。请参考下一节关于 KVM 的内容，了解更多关于这些`ioctl()`函数调用的信息。总之，KVM 利用 QEMU 成为一个完整的 hypervisor。KVM 是处理器提供的硬件虚拟化扩展（VMX 或 SVM）的加速器或启用器，使它们与 CPU 架构紧密耦合。间接地，这表明虚拟系统也必须使用相同的架构来利用硬件虚拟化扩展/功能。一旦启用，它肯定会比其他技术（如二进制翻译）提供更好的性能。

我们的下一步是检查 QEMU 如何融入整个 KVM 故事中。

## QEMU-KVM 内部

在我们开始研究 QEMU 内部之前，让我们克隆 QEMU Git 存储库：

```
# git clone git://git.qemu-project.org/qemu.git
```

一旦克隆完成，您可以在存储库内看到文件的层次结构，如下面的屏幕截图所示：

![图 2.15 – QEMU 源代码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_15.jpg)

图 2.15 – QEMU 源代码

一些重要的数据结构和`ioctl()`函数调用构成了 QEMU 用户空间和 KVM 内核空间。一些重要的数据结构是`KVMState`、`CPU{X86}State`、`MachineState`等。在我们进一步探索内部之前，我想指出，详细介绍它们超出了本书的范围；但是，我会给出足够的指针来理解发生了什么，并提供更多的参考资料以供进一步解释。

## 数据结构

在这一部分，我们将讨论 QEMU 的一些重要数据结构。`KVMState`结构包含了 QEMU 中虚拟机表示的重要文件描述符。例如，它包含了虚拟机文件描述符，如下面的代码所示：

```
struct KVMState      ( kvm-all.c ) 
{           …..
  int fd;
  int vmfd;
  int coalesced_mmio;
    struct kvm_coalesced_mmio_ring *coalesced_mmio_ring; ….}
```

QEMU-KVM 维护着`CPUX86State`结构的列表，每个 vCPU 都有一个结构。通用寄存器的内容（以及 RSP 和 RIP）是`CPUX86State`的一部分：

```
struct CPUState {
…..
  int nr_cores;
  int nr_threads;
  …
  int kvm_fd;
           ….
  struct KVMState *kvm_state;
  struct kvm_run *kvm_run
}
```

此外，`CPUX86State`还查看标准寄存器以进行异常和中断处理：

```
typedef struct CPUX86State ( target/i386/cpu.h )
 {
  /* standard registers */
  target_ulong regs[CPU_NB_REGS];
….
  uint64_t system_time_msr;
  uint64_t wall_clock_msr;
…….
  /* exception/interrupt handling */
  int error_code;
  int exception_is_int;
…...
}
```

存在各种`ioctl()`函数调用：`kvm_ioctl()`、`kvm_vm_ioctl()`、`kvm_vcpu_ioctl()`、`kvm_device_ioctl()`等。有关函数定义，请访问 QEMU 源代码存储库中的`KVM-all.c`。这些`ioctl()`函数调用基本上映射到系统 KVM、虚拟机和 vCPU 级别。这些`ioctl()`函数调用类似于由 KVM 分类的`ioctl()`函数调用。当我们深入研究 KVM 内部时，我们将讨论这一点。要访问由 KVM 内核模块公开的这些`ioctl()`函数调用，QEMU-KVM 必须打开`/dev/kvm`，并将结果文件描述符存储在`KVMState->fd`中：

+   `kvm_ioctl()`：这些`ioctl()`函数调用主要在`KVMState->fd`参数上执行，其中`KVMState->fd`携带通过打开`/dev/kvm`获得的文件描述符，就像下面的例子一样：

```
kvm_ioctl(s, KVM_CHECK_EXTENSION, extension);
kvm_ioctl(s, KVM_CREATE_VM, type);
```

+   `kvm_vm_ioctl()`：这些`ioctl()`函数调用主要在`KVMState->vmfd`参数上执行，就像下面的例子一样：

```
kvm_vm_ioctl(s, KVM_CREATE_VCPU, (void *)vcpu_id);
kvm_vm_ioctl(s, KVM_SET_USER_MEMORY_REGION, &mem);
```

+   `kvm_vcpu_ioctl()`：这些`ioctl()`函数调用主要在`CPUState->kvm_fd`参数上执行，这是 KVM 的 vCPU 文件描述符，就像下面的例子一样：

```
kvm_vcpu_ioctl(cpu, KVM_RUN, 0);
```

+   `kvm_device_ioctl()`：这些`ioctl()`函数调用主要在设备`fd`参数上执行，就像下面的例子一样：

```
kvm_device_ioctl(dev_fd, KVM_HAS_DEVICE_ATTR, &attribute) ? 0 : 1;
```

在考虑 QEMU KVM 通信时，`kvm-all.c`是一个重要的源文件之一。

现在，让我们继续看看 QEMU 在 KVM 虚拟化环境中如何创建和初始化虚拟机和 vCPU。

`kvm_init()`是打开 KVM 设备文件的函数，就像下面的代码所示，它还填充了`KVMState`的`fd [1]`和`vmfd [2]`：

```
static int kvm_init(MachineState *ms)
{ 
…..
KVMState *s;
      s = KVM_STATE(ms->accelerator);
    …
    s->vmfd = -1;
    s->fd = qemu_open("/dev/kvm", O_RDWR);   ----> [1]
    ..
     do {
          ret = kvm_ioctl(s, KVM_CREATE_VM, type); --->[2]
        } while (ret == -EINTR);
     s->vmfd = ret;
….
      ret = kvm_arch_init(ms, s);   ---> ( target-i386/kvm.c: ) 
.....
  }
```

如您在前面的代码中所看到的，带有`KVM_CREATE_VM`参数的`ioctl()`函数调用将返回`vmfd`。一旦 QEMU 有了`fd`和`vmfd`，还必须填充一个文件描述符，即`kvm_fd`或`vcpu fd`。让我们看看 QEMU 是如何填充这个的：

```
main() ->
              -> cpu_init(cpu_model);      [#define cpu_init(cpu_model) CPU(cpu_x86_init(cpu_model)) ]
                  ->cpu_x86_create()
         ->qemu_init_vcpu
                      ->qemu_kvm_start_vcpu()
               ->qemu_thread_create
        ->qemu_kvm_cpu_thread_fn()
          -> kvm_init_vcpu(CPUState *cpu)
int kvm_init_vcpu(CPUState *cpu)
{
  KVMState *s = kvm_state;
  ...
            ret = kvm_vm_ioctl(s, KVM_CREATE_VCPU, (void *)kvm_arch_vcpu_id(cpu));
  cpu->kvm_fd = ret;   --->   [vCPU fd]
  ..
  mmap_size = kvm_ioctl(s, KVM_GET_VCPU_MMAP_SIZE, 0);
cpu->kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,  cpu->kvm_fd, 0);  [3]
...
  ret = kvm_arch_init_vcpu(cpu);   [target-i386/kvm.c]
              …..
}
```

一些内存页面在 QEMU-KVM 进程和 KVM 内核模块之间共享。您可以在`kvm_init_vcpu()`函数中看到这样的映射。也要了解，在执行返回前述`fds`的这些`ioctl()`函数调用期间，Linux 内核会分配文件结构和相关的匿名节点。我们将在讨论 KVM 时稍后讨论内核部分。

我们已经看到 vCPU 是由 QEMU-KVM 创建的`posix`线程。为了运行客户代码，这些 vCPU 线程执行带有`KVM_RUN`参数的`ioctl()`函数调用，就像下面的代码所示：

```
int kvm_cpu_exec(CPUState *cpu) {
   struct kvm_run *run = cpu->kvm_run;
  ..
  run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);
           ...
}
```

相同的函数`kvm_cpu_exec()`还定义了当控制从 KVM 带有`VM exit`返回到 QEMU-KVM 用户空间时需要采取的操作。尽管我们将在后面讨论 KVM 和 QEMU 如何相互通信以代表客户执行操作，但我在这里想提一下。KVM 是由供应商如 Intel 和 AMD 提供的硬件扩展的实现者，这些硬件扩展如 SVM 和 VMX。KVM 使用这些扩展在主机 CPU 上直接执行客户代码。然而，如果有一个事件 - 例如，在操作的一部分，客户内核代码访问由 QEMU 仿真的硬件设备寄存器 - 那么 KVM 必须退出返回到 QEMU 并传递控制。然后，QEMU 可以仿真操作的结果。有不同的退出原因，如下面的代码所示：

```
  switch (run->exit_reason) {
          case KVM_EXIT_IO:
            DPRINTF("handle_io\n");
             case KVM_EXIT_MMIO:
            DPRINTF("handle_mmio\n");
   case KVM_EXIT_IRQ_WINDOW_OPEN:
            DPRINTF("irq_window_open\n");
      case KVM_EXIT_SHUTDOWN:
            DPRINTF("shutdown\n");
     case KVM_EXIT_UNKNOWN:
    ...
   	  case KVM_EXIT_INTERNAL_ERROR:
    …
   	case KVM_EXIT_SYSTEM_EVENT:
            switch (run->system_event.type) {
              case KVM_SYSTEM_EVENT_SHUTDOWN:
        case KVM_SYSTEM_EVENT_RESET:
case KVM_SYSTEM_EVENT_CRASH:
```

现在我们了解了 QEMU-KVM 的内部情况，让我们讨论一下 QEMU 中的线程模型。

## QEMU 中的线程模型

QEMU-KVM 是一个多线程、事件驱动（带有一个大锁）的应用程序。重要的线程如下：

+   主线程

+   虚拟磁盘 I/O 后端的工作线程

+   每个 vCPU 一个线程

对于每个虚拟机，主机系统中都有一个运行中的 QEMU 进程。如果客户系统关闭，这个进程将被销毁/退出。除了 vCPU 线程，还有专用的 I/O 线程运行 select(2)事件循环来处理 I/O，比如网络数据包和磁盘 I/O 完成。I/O 线程也是由 QEMU 生成的。简而言之，情况将是这样的：

![图 2.16 - KVM 客户端](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_02_16.jpg)

图 2.16 - KVM 客户端

在我们进一步讨论之前，总是有一个关于客户系统的物理内存的问题：它在哪里？这是交易：客户 RAM 分配在 QEMU 进程的虚拟地址空间内，如前图所示。也就是说，客户的物理 RAM 位于 QEMU 进程地址空间内。

重要说明

有关线程的更多细节可以从[blog.vmsplice.net/2011/03/qemu-internals-overall-architecutre-and-html?m=1](http://blog.vmsplice.net/2011/03/qemu-internals-overall-architecutre-and-html?m=1)的线程模型中获取。

事件循环线程也称为`iothread`。事件循环用于定时器、文件描述符监视等。`main_loop_wait()`是 QEMU 主事件循环线程。这个主事件循环线程负责主循环服务，包括文件描述符回调、底部回调和定时器（在`qemu-timer.h`中定义）。底部回调类似于立即执行的定时器，但开销较低，并且调度它们是无等待、线程安全和信号安全的。

在我们离开 QEMU 代码库之前，我想指出设备代码主要有两个部分。例如，目录块包含块设备代码的主机端，`hw/block/`包含设备仿真的代码。

## KVM

有一个名为`kvm.ko`的通用内核模块，还有硬件内核模块，比如`kvm-intel.ko`（基于 Intel 的系统）和`kvm-amd.ko`（基于 AMD 的系统）。因此，KVM 将加载`kvm-intel.ko`（如果存在`vmx`标志）或`kvm-amd.ko`（如果存在`svm`标志）模块。这将使 Linux 内核成为一个 hypervisor，从而实现虚拟化。

KVM 向应用程序公开了一个名为`/dev/kvm`的设备文件，以便它们可以利用提供的`ioctl()`函数调用系统调用。QEMU 利用这个设备文件与 KVM 通信，并创建、初始化和管理虚拟机的内核模式上下文。

之前，我们提到 QEMU-KVM 用户空间将虚拟机的物理地址空间包含在 QEMU/KVM 的用户模式地址空间中，其中包括内存映射 I/O。KVM 帮助我们实现了这一点。有更多的事情可以通过 KVM 实现。以下是一些例子：

+   对某些 I/O 设备的仿真；例如，通过 MMIO 对每个 CPU 的本地 APIC 和系统范围的 IOAPIC 进行仿真。

+   某些特权指令的仿真（对系统寄存器 CR0、CR3 和 CR4 的读写）。

+   通过`VMENTRY`执行客户代码并在`VMEXIT`处处理拦截事件。

+   将事件（如虚拟中断和页错误）注入到虚拟机的执行流程中等。这也是借助 KVM 实现的。

KVM 不是一个完整的 hypervisor；然而，借助 QEMU 和仿真器（一个稍微修改过的用于 I/O 设备仿真和 BIOS 的 QEMU），它可以成为一个。KVM 需要硬件虚拟化能力的处理器才能运行。利用这些能力，KVM 将标准的 Linux 内核转变为一个 hypervisor。当 KVM 运行虚拟机时，每个虚拟机都是一个正常的 Linux 进程，显然可以由主机内核调度到 CPU 上运行，就像主机内核中存在的任何其他进程一样。在第一章《理解 Linux 虚拟化》中，我们讨论了不同的 CPU 执行模式。你可能还记得，主要有用户模式和内核/监管模式。KVM 是 Linux 内核中的一项虚拟化功能，它允许诸如 QEMU 之类的程序在主机 CPU 上直接执行客户代码。只有当目标架构得到主机 CPU 的支持时，才有可能实现这一点。

然而，KVM 引入了一个称为客户模式的模式。简而言之，客户模式允许我们执行客户系统代码。它可以运行客户用户或内核代码。借助虚拟化感知硬件的支持，KVM 虚拟化了进程状态、内存管理等。

#### 从 CPU 的角度看虚拟化

借助其硬件虚拟化能力，处理器通过虚拟机控制结构（VMCS）和虚拟机控制块（VMCB）管理主机和客户操作系统的处理器状态，并代表虚拟化的操作系统管理 I/O 和中断。也就是说，引入这种类型的硬件后，诸如 CPU 指令拦截、寄存器读/写支持、内存管理支持（扩展页表（EPT）和嵌套分页表（NPT））、中断处理支持（APICv）、IOMMU 等任务都出现了。KVM 使用标准的 Linux 调度程序、内存管理和其他服务。简而言之，KVM 的作用是帮助用户空间程序利用硬件虚拟化能力。在这里，你可以把 QEMU 看作是一个用户空间程序，因为它被很好地集成到了不同的用例中。当我说硬件加速虚拟化时，我主要指的是英特尔 VT-X 和 AMD-Vs SVM。引入虚拟化技术处理器带来了一个额外的指令集，称为 VMX。

使用 Intel 的 VT-X，VMM 在 VMX 根操作模式下运行，而客户（未经修改的操作系统）在 VMX 非根操作模式下运行。这个 VMX 为 CPU 带来了额外的虚拟化特定指令，比如`VMPTRLD`、`VMPTRST`、`VMCLEAR`、`VMREAD`、`VMWRITE`、`VMCALL`、`VMLAUNCH`、`VMRESUME`、`VMXOFF`和`VMXON`。`VMXON`可以被`VMXOFF`禁用。为了执行客户代码，我们必须使用`VMLAUNCH`/`VMRESUME`指令并离开`VMEXIT`。但是等等，离开什么？这是从非根操作到根操作的过渡。显然，当我们进行这种过渡时，需要保存一些信息，以便以后可以获取。英特尔提供了一个结构来促进这种过渡，称为 VMCS；它处理了大部分虚拟化管理功能。例如，在`VMEXIT`的情况下，退出原因将被记录在这个结构内。那么，我们如何从这个结构中读取或写入？`VMREAD`和`VMWRITE`指令用于读取或写入相应的字段。

之前，我们讨论了 SLAT/EPT/AMD-Vi。没有 EPT，hypervisor 必须退出虚拟机执行地址转换，这会降低性能。正如我们在英特尔基于虚拟化的处理器的操作模式中所注意到的，AMD 的 SVM 也有一些操作模式，即主机模式和客户模式。显然，当处于客户模式时，某些指令可能会引起`VMEXIT`异常，这些异常会以特定于进入客户模式的方式进行处理。这里应该有一个等效的 VMCS 结构，它被称为 VMCB；正如前面讨论的，它包含了`VMEXIT`的原因。AMD 添加了八个新的指令操作码来支持 SVM。例如，`VMRUN`指令启动客户操作系统的操作，`VMLOAD`指令从 VMCB 加载处理器状态，`VMSAVE`指令将处理器状态保存到 VMCB。这就是为什么 AMD 引入了嵌套分页，这与英特尔的 EPT 类似。

当我们讨论硬件虚拟化扩展时，我们提到了 VMCS 和 VMCB。当我们考虑硬件加速虚拟化时，这些是重要的数据结构。这些控制块特别有助于`VMEXIT`场景。并非所有操作都可以允许给客户；与此同时，如果 hypervisor 代表客户执行所有操作也是困难的。虚拟机控制结构，如 VMCS 或 VMCB，控制了这种行为。一些操作允许给客户，例如更改阴影控制寄存器中的一些位，但其他操作则不允许。这显然提供了对客户允许和不允许执行的操作的精细控制。VMCS 控制结构还提供了对中断传递和异常的控制。之前我们说过`VMEXIT`的退出原因记录在 VMCS 中；它也包含一些关于它的数据。例如，如果写访问控制寄存器导致退出，有关源寄存器和目的寄存器的信息就记录在那里。

请注意 VMCS 或 VMCB 存储客户配置的具体信息，例如机器控制位和处理器寄存器设置。我建议您从源代码中检查结构定义。这些数据结构也被 hypervisor 用来定义在客户执行时监视的事件。这些事件可以被拦截。请注意这些结构位于主机内存中。在使用`VMEXIT`时，客户状态被保存在 VMCS 中。正如前面提到的，`VMREAD`指令从 VMCS 中读取指定字段，而`VMWRITE`指令将指定字段写入 VMCS。还要注意每个 vCPU 都有一个 VMCS 或 VMCB。这些控制结构是主机内存的一部分。vCPU 状态记录在这些控制结构中。

#### KVM API

如前所述，有三种主要类型的`ioctl()`函数调用。内核文档中提到了以下内容（您可以在[`www.kernel.org/doc/Documentation/virtual/kvm/api.txt`](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt)中查看）：

KVM API 由三组 ioctl 组成。KVM API 是一组用于控制虚拟机各个方面的 ioctl。这些 ioctl 属于三个类别：

- 系统 ioctl：这些查询和设置影响整个 KVM 子系统的全局属性。此外，系统 ioctl 用于创建虚拟机。

- 设备 ioctl：用于设备控制，从创建 VM 的同一上下文中执行。

- VM ioctl：这些查询和设置影响整个虚拟机的属性，例如内存布局。此外，VM ioctl 用于创建虚拟 CPU（vCPU）。它从创建 VM 的同一进程（地址空间）运行 VM ioctl。

- vCPU ioctl：这些查询和设置控制单个虚拟 CPU 操作的属性。它们从创建 vCPU 的同一线程运行 vCPU ioctl。

要了解 KVM 公开的`ioctl()`函数调用以及属于特定`fd`组的`ioctl()`函数调用的更多信息，请参考`KVM.h`。

看下面的例子：

```
/*  ioctls for /dev/kvm fds: */
#define KVM_GET_API_VERSION     _IO(KVMIO,   0x00)
#define KVM_CREATE_VM           _IO(KVMIO,   0x01) /* returns a VM fd */
…..
/*  ioctls for VM fds */
#define KVM_SET_MEMORY_REGION   _IOW(KVMIO,  0x40, struct kvm_memory_region)
#define KVM_CREATE_VCPU         _IO(KVMIO,   0x41)
…
/* ioctls for vcpu fds  */
#define KVM_RUN                   _IO(KVMIO,   0x80)
#define KVM_GET_REGS            _IOR(KVMIO,  0x81, struct kvm_regs)
#define KVM_SET_REGS            _IOW(KVMIO,  0x82, struct kvm_regs)
```

现在让我们讨论匿名 inode 和文件结构。

#### 匿名 inode 和文件结构

之前，当我们讨论 QEMU 时，我们说 Linux 内核分配文件结构并设置它的`f_ops`和匿名 inode。让我们看一下`kvm_main.c`文件：

```
static struct file_operations kvm_chardev_ops = {
      .unlocked_ioctl = kvm_dev_ioctl,
      .llseek         = noop_llseek,
      KVM_COMPAT(kvm_dev_ioctl),
};
 kvm_dev_ioctl () 
    switch (ioctl) {
          case KVM_GET_API_VERSION:
              if (arg)
                    	goto out;
              r = KVM_API_VERSION;
              break;
          case KVM_CREATE_VM:
              r = kvm_dev_ioctl_create_vm(arg);
              break;
          case KVM_CHECK_EXTENSION:
              r = kvm_vm_ioctl_check_extension_generic(NULL, arg);
              break;
          case KVM_GET_VCPU_MMAP_SIZE:
  .    …..
}
```

像`kvm_chardev_fops`一样，还有`kvm_vm_fops`和`kvm_vcpu_fops`：

```
static struct file_operations kvm_vm_fops = {
        .release        = kvm_vm_release,
        .unlocked_ioctl = kvm_vm_ioctl,
…..
        .llseek         = noop_llseek,
};
static struct file_operations kvm_vcpu_fops = {
      .release        = kvm_vcpu_release,
      .unlocked_ioctl = kvm_vcpu_ioctl,
….
      .mmap           = kvm_vcpu_mmap,
      .llseek         = noop_llseek,
};
```

inode 分配可能如下所示：

```
      anon_inode_getfd(name, &kvm_vcpu_fops, vcpu, O_RDWR | O_CLOEXEC);
```

现在让我们看一下数据结构。

## 数据结构

从 KVM 内核模块的角度来看，每个虚拟机都由一个`kvm`结构表示：

```
include/linux/kvm_host.h : 
struct kvm {
  ...
      struct mm_struct *mm; /* userspace tied to this vm */
           ...
      struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
          ....
      struct kvm_io_bus __rcu *buses[KVM_NR_BUSES];
….
      struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
  …..
}
```

正如你在前面的代码中看到的，`kvm`结构包含一个指向`kvm_vcpu`结构的指针数组，这些结构是 QEMU-KVM 用户空间中`CPUX86State`结构的对应物。`kvm_vcpu`结构包括一个通用部分和一个 x86 架构特定部分，其中包括寄存器内容：

```
struct kvm_vcpu {
  ...
      struct kvm *kvm;
      int cpu;
…..
      int vcpu_id;
  …..
   	struct kvm_run *run;
  …...
      struct kvm_vcpu_arch arch;
  …
}
```

`kvm_vcpu`结构的 x86 架构特定部分包含字段，可以在虚拟机退出后保存客户端寄存器状态，并且可以在虚拟机进入前加载客户端寄存器状态：

```
arch/x86/include/asm/kvm_host.h
struct kvm_vcpu_arch {
..
      unsigned long regs[NR_VCPU_REGS];
      unsigned long cr0;
      unsigned long cr0_guest_owned_bits;
      …..
   	struct kvm_lapic *apic;  /* kernel irqchip context */
   	..
struct kvm_mmu mmu;
..
struct kvm_pio_request pio;
void *pio_data;
..
      /* emulate context */
  struct x86_emulate_ctxt emulate_ctxt;
  ...
      int (*complete_userspace_io)(struct kvm_vcpu *vcpu);
  ….
}
```

正如你在前面的代码中看到的，`kvm_vcpu`有一个相关的`kvm_run`结构，用于 QEMU 用户空间和 KVM 内核模块之间的通信（通过`pio_data`），正如之前提到的。例如，在`VMEXIT`的情况下，为了满足虚拟硬件访问的仿真，KVM 必须返回到 QEMU 用户空间进程；KVM 将信息存储在`kvm_run`结构中供 QEMU 获取：

```
/include/uapi/linux/kvm.h:
/* for KVM_RUN, returned by mmap(vcpu_fd, offset=0) */
struct kvm_run {
        /* in */
...
        /* out */
...
        /* in (pre_kvm_run), out (post_kvm_run) */
...
      union {
              /* KVM_EXIT_UNKNOWN */
...
              /* KVM_EXIT_FAIL_ENTRY */
...
              /* KVM_EXIT_EXCEPTION */
...
              /* KVM_EXIT_IO */
struct {
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
...
              } io;
...
}
```

`kvm_run`结构是一个重要的数据结构；正如你在前面的代码中看到的，`union`包含许多退出原因，比如`KVM_EXIT_FAIL_ENTRY`，`KVM_EXIT_IO`等。

当我们讨论硬件虚拟化扩展时，我们提到了 VMCS 和 VMCB。当我们考虑硬件加速虚拟化时，这些是重要的数据结构。这些控制块在`VMEXIT`场景中特别有帮助。并非所有操作都可以允许给客户端；同时，如果 hypervisor 代表客户端做所有事情也很困难。虚拟机控制结构，比如 VMCS 或 VMCB，控制了行为。一些操作是允许给客户端的，比如改变阴影控制寄存器中的一些位，但其他的不行。这清楚地提供了对客户端允许和不允许做什么的精细控制。VMCS 控制结构还提供了对中断传递和异常的控制。之前，我们说`VMEXIT`的退出原因记录在 VMCS 中；它也包含了一些关于它的数据。例如，如果对控制寄存器的写访问导致了退出，关于源寄存器和目的寄存器的信息就记录在那里。

在我们深入讨论 vCPU 执行流程之前，让我们先看一些重要的数据结构。

Intel 特定的实现在`vmx.c`中，AMD 特定的实现在`svm.c`中，取决于我们拥有的硬件。正如你所看到的，下面的`kvm_vcpu`是`vcpu_vmx`的一部分。`kvm_vcpu`结构主要分为通用部分和特定架构部分。通用部分包含所有支持的架构的共同数据，而特定架构部分 - 例如，x86 架构特定（客户端保存的通用寄存器）部分包含特定于特定架构的数据。正如之前讨论的，`kvm_vCPUs`，`kvm_run`和`pio_data`与用户空间共享。

`vcpu_vmx`和`vcpu_svm`结构（下面提到）有一个`kvm_vcpu`结构，其中包括一个 x86 架构特定部分（`struct 'kvm_vcpu_arch'`）和一个通用部分，并且相应地指向`vmcs`和`vmcb`结构。让我们先检查 Intel（`vmx`）结构：

```
vcpu_vmx structure
struct vcpu_vmx {
      struct kvm_vcpu     *vcpu;
        ...
      struct loaded_vmcs  vmcs01;
     struct loaded_vmcs   *loaded_vmcs;
    ….
    }
```

同样，让我们接下来检查 AMD（`svm`）结构：

```
vcpu_svm structure
struct vcpu_svm {
        struct kvm_vcpu *vcpu;
        …
struct vmcb *vmcb;
….
    }
```

`vcpu_vmx`或`vcpu_svm`结构是通过以下代码路径分配的：

```
kvm_arch_vcpu_create()
   	   ->kvm_x86_ops->vcpu_create
                 ->vcpu_create()  [.vcpu_create = svm_create_vcpu, .vcpu_create = vmx_create_vcpu,]
```

请注意，VMCS 或 VMCB 存储客户端配置的具体信息，例如机器控制位和处理器寄存器设置。我建议您从源代码中检查结构定义。这些数据结构也被 hypervisor 用于定义在客户端执行时要监视的事件。这些事件可以被拦截，这些结构位于主机内存中。在`VMEXIT`时，客户状态被保存在 VMCS 中。如前所述，`VMREAD`指令从 VMCS 中读取字段，而`VMWRITE`指令将字段写入其中。还要注意，每个 vCPU 都有一个 VMCS 或 VMCB。这些控制结构是主机内存的一部分。vCPU 状态记录在这些控制结构中。

# vCPU 的执行流程

最后，我们进入了 vCPU 执行流程，这有助于我们整合一切并了解底层发生了什么。

希望您没有忘记 QEMU 为客户端的 vCPU 创建了一个 POSIX 线程和`ioctl()`，它负责运行 CPU 并具有`KVM_RUN arg (#define KVM_RUN _IO(KVMIO, 0x80))`。vCPU 线程执行`ioctl(.., KVM_RUN, ...)`来运行客户端代码。由于这些是 POSIX 线程，Linux 内核可以像系统中的任何其他进程/线程一样调度这些线程。

让我们看看它是如何工作的：

```
Qemu-kvm User Space:
kvm_init_vcpu ()
    kvm_arch_init_vcpu()
       qemu_init_vcpu()
          qemu_kvm_start_vcpu()
             qemu_kvm_cpu_thread_fn()
    while (1) {
        if (cpu_can_run(cpu)) {
                r = kvm_cpu_exec(cpu);
                      }
        }
kvm_cpu_exec (CPUState *cpu)
    ->       run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);
```

根据底层架构和硬件，KVM 内核模块初始化了不同的结构之一，其中之一是`vmx_x86_ops/svm_x86_ops`（由`kvm-intel`或`kvm-amd`模块拥有）。它定义了在 vCPU 处于上下文时需要执行的不同操作。KVM 利用`kvm_x86_ops`向量来根据加载到硬件的 KVM 模块（`kvm-intel`或`kvm-amd`）指向这些向量中的任何一个。`run`指针定义了在客户端 vCPU 运行时需要执行的函数，而`handle_exit`定义了在`VMEXIT`时需要执行的操作。让我们检查 Intel（`vmx`）结构：

```
static struct kvm_x86_ops vmx_x86_ops = {
    ...
      .vcpu_create = vmx_create_vcpu,
      .run = vmx_vcpu_run,
      .handle_exit = vmx_handle_exit,
…
}
```

现在，让我们看看 AMD（`svm`）结构：

```
static struct kvm_x86_ops svm_x86_ops = {
      .vcpu_create = svm_create_vcpu,
       .run = svm_vcpu_run,
      .handle_exit = handle_exit,
..
}
```

`run`指针分别指向`vmx_vcpu_run`或`svm_vcpu_run`。`svm_vcpu_run`或`vmx_vcpu_run`函数负责保存 KVM 主机寄存器，加载客户端操作系统寄存器和`SVM_VMLOAD`指令。我们在`vcpu run`时通过`syscall`进入内核时，走过了 QEMU KVM 用户空间代码的执行。然后，按照文件操作结构，它调用`kvm_vcpu_ioctl()`；这定义了根据`ioctl()`函数调用定义的操作：

```
static long kvm_vcpu_ioctl(struct file *file,
                         unsigned int ioctl, unsigned long arg)  {
      switch (ioctl) {
        case KVM_RUN:
    ….
           kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
        ->vcpu_load
            -> vmx_vcpu_load
                 ->vcpu_run(vcpu);
        ->vcpu_enter_guest
                             ->vmx_vcpu_run
                     ….
}
```

我们将通过`vcpu_run()`来了解如何到达`vmx_vcpu_run`或`svm_vcpu_run`：

```
static int vcpu_run(struct kvm_vcpu *vcpu) {
….
      for (;;) {
              if (kvm_vcpu_running(vcpu)) {
                        r = vcpu_enter_guest(vcpu);
                } else {
                        r = vcpu_block(kvm, vcpu);
              }
```

一旦进入`vcpu_enter_guest()`，您可以看到在 KVM 中进入客户模式时发生的一些重要调用：

```
static int vcpu_enter_guest(struct kvm_vcpu *vcpu) {
...
      kvm_x86_ops.prepare_guest_switch(vcpu);
      vcpu->mode = IN_GUEST_MODE;
      __kvm_guest_enter();
      kvm_x86_ops->run(vcpu);
                             [vmx_vcpu_run or svm_vcpu_run ]
      vcpu->mode = OUTSIDE_GUEST_MODE;
      kvm_guest_exit();
      r = kvm_x86_ops->handle_exit(vcpu);
                             [vmx_handle_exit or handle_exit ]
…
}
```

您可以从`vcpu_enter_guest()`函数中看到`VMENTRY`和`VMEXIT`的高级图像。也就是说，`VMENTRY`（`[vmx_vcpu_run 或 svm_vcpu_run]`）只是一个在 CPU 中执行的客户操作系统；在这个阶段可能会发生不同的拦截事件，导致`VMEXIT`。如果发生这种情况，任何`vmx_handle_exit`或`handle_exit`函数调用都将开始查看此退出原因。我们已经在前面的部分讨论了`VMEXIT`的原因。一旦发生`VMEXIT`，就会分析退出原因并相应地采取行动。

`vmx_handle_exit()`是负责处理退出原因的函数：

```
static int vmx_handle_exit(struct kvm_vcpu *vcpu, , fastpath_t exit_fastpath)
{
….. }
static int (*const kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
      [EXIT_REASON_EXCEPTION_NMI]         = handle_exception,
      [EXIT_REASON_EXTERNAL_INTERRUPT]    = handle_external_interrupt,
      [EXIT_REASON_TRIPLE_FAULT]          = handle_triple_fault,
      [EXIT_REASON_IO_INSTRUCTION]        = handle_io,
      [EXIT_REASON_CR_ACCESS]             = handle_cr,
      [EXIT_REASON_VMCALL]                = handle_vmcall,
      [EXIT_REASON_VMCLEAR]               = handle_vmclear,
      [EXIT_REASON_VMLAUNCH]            	= handle_vmlaunch,
…
}
```

`kvm_vmx_exit_handlers[]`是虚拟机退出处理程序的表，由`exit reason`索引。类似于 Intel，`svm`代码有`handle_exit()`：

```
static int handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
      struct vcpu_svm *svm = to_svm(vcpu);
      struct kvm_run *kvm_run = vcpu->run;
      u32 exit_code = svm->vmcb->control.exit_code;
….
      return svm_exit_handlersexit_code;
}
```

`handle_exit()`有`svm_exit_handler`数组，如下一节所示。

如果需要，KVM 必须回退到用户空间（QEMU）来执行仿真，因为一些指令必须在 QEMU 模拟的设备上执行。例如，为了模拟 I/O 端口访问，控制权转移到用户空间（QEMU）：

```
kvm-all.c:
static int (*const svm_exit_handlers[])(struct vcpu_svm *svm) = {
      [SVM_EXIT_READ_CR0]                   = cr_interception,
      [SVM_EXIT_READ_CR3]                   = cr_interception,
      [SVM_EXIT_READ_CR4]                   = cr_interception,
….
}
switch (run->exit_reason) {
        case KVM_EXIT_IO:
              DPRINTF("handle_io\n");
                /* Called outside BQL */
              kvm_handle_io(run->io.port, attrs,
                            (uint8_t *)run + run->io.data_offset,
                          run->io.direction,
                      	    run->io.size,
                      	    run->io.count);
              ret = 0;
            break;
```

本章内容涉及源代码较多。有时，深入挖掘和检查源代码是理解某些工作原理的唯一途径。希望本章成功做到了这一点。

# 总结

在本章中，我们讨论了 KVM 及其在 Linux 虚拟化中的主要合作伙伴 libvirt 和 QEMU 的内部工作原理。我们讨论了各种类型的虚拟化——二进制翻译、完全虚拟化、半虚拟化和硬件辅助虚拟化。我们查看了一些内核、QEMU 和 libvirt 的源代码，以了解它们之间的相互作用。这使我们具备了必要的技术知识，以便理解本书中将要介绍的主题——从创建虚拟机和虚拟网络到将虚拟化理念扩展到云概念。理解这些概念也将使您更容易理解虚拟化的关键目标——如何正确设计物理和虚拟基础设施，这将逐渐在本书中作为一个概念介绍。现在我们已经了解了虚拟化的基本工作原理，是时候转向更实际的主题了——如何部署 KVM hypervisor、管理工具和 oVirt。我们将在下一章中进行介绍。

# 问题

1.  什么是半虚拟化？

1.  什么是完全虚拟化？

1.  什么是硬件辅助虚拟化？

1.  libvirt 的主要目标是什么？

1.  KVM 的作用是什么？QEMU 呢？

# 进一步阅读

请参考以下链接，了解本章涵盖的更多信息：

+   二进制翻译：[`pdfs.semanticscholar.org/d6a5/1a7e73f747b309ef5d44b98318065d5267cf.pdf`](https://pdfs.semanticscholar.org/d6a5/1a7e73f747b309ef5d44b98318065d5267cf.pdf)

+   虚拟化基础知识：[`dsc.soic.indiana.edu/publications/virtualization.pdf`](http://dsc.soic.indiana.edu/publications/virtualization.pdf)

+   KVM：[`www.redhat.com/en/topics/virtualization/what-is-KVM`](https://www.redhat.com/en/topics/virtualization/what-is-KVM)

+   QEMU：[`www.qemu.org/`](https://www.qemu.org/)

+   了解完全虚拟化、半虚拟化和硬件辅助：[`www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/techpaper/VMware_paravirtualization.pdf`](https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/techpaper/VMware_paravirtualization.pdf)


# 第二部分：用于虚拟机管理的 libvirt 和 ovirt

在本书的这一部分，您将完全了解如何使用 libvirt 安装、配置和管理 KVM hypervisor。您将获得关于 KVM 基础设施组件的高级知识，如网络、存储和虚拟硬件配置。作为学习过程的一部分，您还将全面了解虚拟机生命周期管理和虚拟机迁移技术，以及虚拟机磁盘管理。在第二部分结束时，您将熟悉 libvirt 命令行管理工具`virsh`和 GUI 工具`virt-manager`。

本书的这一部分包括以下章节：

+   第三章，安装 KVM Hypervisor、libvirt 和 ovirt

+   第四章，Libvirt 网络

+   第五章，Libvirt 存储

+   第六章，虚拟显示设备和协议

+   第七章，虚拟机安装、配置和生命周期管理

+   第八章，创建和修改虚拟机磁盘、模板和快照


# 第三章：安装 KVM Hypervisor、libvirt 和 oVirt

本章为您提供了对我们书籍主题的深入了解，即**内核虚拟机**（**KVM**）及其管理工具 libvirt 和 oVirt。我们还将学习如何使用基本的 CentOS 8 部署从头开始完整安装这些工具。您会发现这是一个非常重要的主题，因为有时您可能没有安装所有必要的实用程序，特别是 oVirt，因为它是整体软件堆栈的一个完全独立的部分，也是 KVM 的免费管理平台。由于 oVirt 有很多组成部分 - 基于 Python 的守护程序和支持实用程序、库和 GUI 前端 - 我们将包括一步一步的指南，以确保您可以轻松安装 oVirt。

在本章中，我们将涵盖以下主题：

+   熟悉 QEMU 和 libvirt

+   熟悉 oVirt

+   安装 QEMU、libvirt 和 oVirt

+   使用 QEMU 和 libvirt 启动虚拟机

让我们开始吧！

# 熟悉 QEMU 和 libvirt

在*第二章*，*KVM 作为虚拟化解决方案*中，我们开始讨论 KVM、QEMU 和各种其他实用程序，可以用来管理基于 KVM 的虚拟化平台。作为机器模拟器，QEMU 将被用于在任何支持的平台上创建和运行我们的虚拟机 - 无论是作为模拟器还是虚拟化器。我们将把时间集中在第二种范式上，即使用 QEMU 作为虚拟化器。这意味着我们将能够直接在其下方的硬件 CPU 上执行我们的虚拟机代码，这意味着本地或接近本地的性能和更少的开销。

要牢记整体 KVM 堆栈是作为一个模块构建的，因此 QEMU 也采用了模块化的方法并不足为奇。多年来，这一点一直是 Linux 世界的核心原则，进一步提高了我们使用物理资源的效率。

当我们将 libvirt 作为 QEMU 的管理平台时，我们可以访问一些很酷的新实用程序，比如`virsh`命令，我们可以用它来进行虚拟机管理、虚拟网络管理等等。我们将在本书的后面讨论一些实用程序（例如 oVirt），它们使用 libvirt 作为标准化的库和实用程序，使其 GUI 魔术成为可能 - 基本上，它们使用 libvirt 作为 API。我们还可以访问其他命令，用于各种目的。例如，我们将使用一个名为`virt-host-validate`的命令来检查我们的服务器是否与 KVM 兼容。

# 熟悉 oVirt

请记住，大多数 Linux 系统管理员所做的工作是通过命令行工具、libvirt 和 KVM 完成的。它们为我们提供了一套良好的工具，可以在命令行中完成我们需要的一切，正如我们将在本章的后面部分看到的那样。但同时，我们也将对基于 GUI 的管理有所了解，因为我们稍后将简要讨论虚拟机管理器。

然而，这仍然无法涵盖这样一种情况，即您拥有大量基于 KVM 的主机、数百台虚拟机、数十个相互连接的虚拟网络，以及一整个机架的存储设备，您需要将其集成到您的 KVM 环境中。使用上述实用程序只会在您扩展环境时给您带来痛苦。这主要原因相当简单-我们仍然没有引入任何一种*集中式*软件包来管理基于 KVM 的环境。当我们说集中式时，我们指的是字面意义上-我们需要一种可以连接到多个虚拟化程序并管理它们所有功能的软件解决方案，包括网络、存储、内存和 CPU，或者我们有时所说的*虚拟化的四大支柱*。这种软件最好有某种 GUI 界面，我们可以从中*集中*管理我们所有的 KVM 资源，因为-嗯-我们都是人类。我们中有相当多的人更喜欢图片而不是文本，更喜欢交互而不是仅限于文本管理，尤其是在规模化时。

这就是 oVirt 项目的用武之地。oVirt 是一个用于管理我们的 KVM 环境的开源平台。它是一个基于 GUI 的工具，在后台有很多运行部件-引擎在基于 Java 的 WildFly 服务器上运行（以前被称为 JBoss），前端使用 GWT 工具包等。但它们都是为了实现一件事-让我们能够从一个集中的、基于 Web 的管理控制台管理基于 KVM 的环境。

从管理的角度来看，oVirt 有两个主要的构建模块-引擎（我们可以通过 GUI 界面连接到）和其代理（用于与主机通信）。让我们简要描述它们的功能。

oVirt 引擎是一个集中式服务，可用于执行虚拟化环境中所需的任何操作-管理虚拟机、移动它们、创建镜像、存储管理、虚拟网络管理等。此服务用于管理 oVirt 主机，并且为此，它需要与主机上的某些东西进行通信。这就是 oVirt 代理（vdsm）发挥作用的地方。

oVirt 引擎的一些可用高级功能包括以下内容：

+   虚拟机的实时迁移

+   图像管理

+   虚拟机的导入和导出（OVF 格式）

+   虚拟到虚拟转换（V2V）

+   高可用性（在集群中的剩余主机上重新启动虚拟机）

+   资源监控

显然，我们需要在主机上部署 oVirt 代理和相关实用程序，这些主机将成为我们环境的主要部分，我们将在其中托管一切-虚拟机、模板、虚拟网络等。为此，oVirt 使用了一种特定的基于代理的机制，通过一个名为 vdsm 的代理。这是一个我们将部署到我们的 CentOS 8 主机上的代理，以便我们可以将它们添加到 oVirt 的清单中，进而意味着我们可以通过使用 oVirt 引擎 GUI 来管理它们。Vdsm 是一个基于 Python 的代理，oVirt 引擎使用它可以直接与 KVM 主机通信，然后 vdsm 可以与本地安装的 libvirt 引擎进行通信以执行所有必要的操作。它还用于配置目的，因为主机需要配置为在 oVirt 环境中使用，以配置虚拟网络、存储管理和访问等。此外，vdsm 还具有内存过量管理器（MOM）集成，以便它可以有效地管理我们虚拟化主机上的内存。

以图形方式来看，oVirt 的架构如下所示：

![图 3.1- oVirt 架构（来源：http://ovirt.org）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_01.jpg)

图 3.1- oVirt 架构（来源：http://ovirt.org）

我们将在下一章中介绍如何安装 oVirt。如果您曾听说过或使用过一个名为 Red Hat Enterprise Virtualization 的产品，那么它可能看起来非常熟悉。

# 安装 QEMU、libvirt 和 oVirt

让我们从一些基本信息开始讨论安装 QEMU、libvirt 和 oVirt：

+   我们将在本书中的所有内容中使用 CentOS 8（除了一些仅支持 CentOS 7 的部分，因为在撰写本书时，CentOS 7 是最后一个受支持的版本）。

+   我们的默认安装配置文件始终是**带 GUI 的服务器**，前提是我们将覆盖几乎在本书中要做的所有事情的 GUI 和文本模式实用程序。

+   我们需要在默认的*带 GUI 的服务器*安装之上手动安装所有内容，以便我们有一个完整的，一步一步的指南来完成所有操作。

+   本书中涵盖的所有示例都可以安装在一台具有 16 个物理核心和 64GB 内存的单个物理服务器上。如果您修改一些数字（分配给虚拟机的核心数、分配给某些虚拟机的内存量等），您可以使用一台 6 核笔记本电脑和 16GB 内存来完成这些操作，前提是您不会一直运行所有虚拟机。如果在完成本章后关闭虚拟机，并在下一章中启动必要的虚拟机，那么这样做是可以的。在我们的情况下，我们使用了一台 HP ProLiant DL380p Gen8，这是一台易于找到的二手服务器 - 价格也相当便宜。

在完成了服务器的基本安装后 - 选择安装配置文件、分配网络配置和 root 密码，并添加额外用户（如果需要） - 我们面临着一个无法进行虚拟化的系统，因为它没有运行 KVM 虚拟机所需的所有必要工具。因此，我们要做的第一件事是简单安装必要的模块和基本应用程序，以便检查我们的服务器是否与 KVM 兼容。因此，请以管理员用户身份登录到服务器并发出以下命令：

```
yum module install virt
dnf install qemu-img qemu-kvm libvirt libvirt-client virt-manager virt-install virt-viewer -y
```

我们还需要告诉内核我们将使用 IOMMU。这可以通过编辑`/etc/default/grub`文件来实现，找到`GRUB_CMDLINE_LINUX`并在该行的末尾添加一条语句：

```
intel_iommu=on
```

在添加该行之前不要忘记添加一个空格。下一步是重新启动，所以我们需要执行：

```
systemctl reboot
```

通过发出这些命令，我们安装了运行基于 KVM 的虚拟机所需的所有必要库和二进制文件，以及使用 virt-manager（GUI libvirt 管理实用程序）来管理我们的 KVM 虚拟化服务器。

此外，通过添加 IOMMU 配置，我们确保我们的主机看到 IOMMU，并在使用`virt-host-validate`命令时不会抛出错误

之后，让我们通过发出以下命令来检查我们的主机是否与所有必要的 KVM 要求兼容：

```
virt-host-validate
```

此命令经过多次测试，以确定我们的服务器是否兼容。我们应该得到这样的输出：

![图 3.2 - virt-host-validate 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_02.jpg)

图 3.2 - virt-host-validate 输出

这表明我们的服务器已准备好用于 KVM。因此，下一步是，既然所有必要的 QEMU/libvirt 实用程序都已安装，我们要进行一些预检查，以查看我们安装的所有内容是否部署正确，并且是否像应该那样工作。我们将运行`virsh net-list`和`virsh list`命令来执行此操作，如下面的屏幕截图所示：

![图 3.3 - 测试 KVM 虚拟网络并列出可用的虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_03.jpg)

图 3.3 - 测试 KVM 虚拟网络并列出可用的虚拟机

通过使用这两个命令，我们检查了我们的虚拟化主机是否有正确配置的默认虚拟网络交换机/桥（关于这一点，我们将在下一章中详细介绍），以及我们是否有任何正在运行的虚拟机。我们有默认的桥接和没有虚拟机，所以一切都是正常的。

## 在 KVM 中安装第一个虚拟机

现在我们可以开始使用我们的 KVM 虚拟化服务器来运行虚拟机。让我们从在我们的主机上部署一个虚拟机开始。为此，我们将一个 CentOS 8.0 ISO 文件复制到我们的本地文件夹`/var/lib/libvirt/images`，我们将使用它来创建我们的第一个虚拟机。我们可以通过使用以下命令从命令行执行此操作：

```
virt-install --virt-type=kvm --name MasteringKVM01 --vcpus 2 --ram 4096 --os-variant=rhel8.0 --cdrom=/var/lib/libvirt/images/ CentOS-8-x86_64-1905-dvd1.iso  --network=default --graphics vnc --disk size=16
```

这里有一些可能有点令人困惑的参数。让我们从`--os-variant`参数开始，该参数描述了您想要使用`virt-install`命令安装的客户操作系统。如果您想获取受支持的客户操作系统列表，请运行以下命令：

```
osinfo-query os
```

`--network`参数与我们的默认虚拟桥有关（我们之前提到过这一点）。我们绝对希望我们的虚拟机能够连接到网络，因此我们选择了这个参数，以确保它在开箱即用时能够连接到网络。

在启动`virt-install`命令后，我们应该会看到一个 VNC 控制台窗口，以便跟随安装过程。然后我们可以选择使用的语言、键盘、时间和日期，以及安装目的地（点击所选磁盘，然后在左上角按**完成**）。我们还可以通过转到**网络和主机名**，点击**关闭**按钮，选择**完成**（然后会切换到**打开**位置），并将我们的虚拟机连接到底层网络桥（*默认*）来激活网络。之后，我们可以按**开始安装**，让安装过程完成。在等待过程中，我们可以点击**Root 密码**为我们的管理用户分配一个 root 密码。

如果所有这些对您来说似乎有点像*手工劳动*，我们能理解您的痛苦。想象一下不得不部署数十个虚拟机并点击所有这些设置。我们已经不再处于 19 世纪，所以一定有更简单的方法来做这件事。

## 自动化虚拟机安装

到目前为止，以更*自动*的方式执行这些操作的最简单和最简单的方法是创建和使用一个称为**kickstart**文件。kickstart 文件基本上是一个文本配置文件，我们可以使用它来配置服务器的所有部署设置，无论我们是在谈论物理服务器还是虚拟服务器。唯一的注意事项是 kickstart 文件需要预先准备并广泛可用-无论是在网络（web）上还是在本地磁盘上。还有其他支持的选项，但这些是最常用的选项。

为了我们的目的，我们将使用一个在网络上（通过 Web 服务器）可用的 kickstart 文件，但我们将对其进行一些编辑，以使其可用，并将其留在我们的网络上，以便`virt-install`可以使用它。

当我们安装物理服务器时，作为安装过程的一部分（称为`anaconda`），一个名为`anaconda-ks.cfg`的文件被保存在我们的`/root`目录中。这是一个 kickstart 文件，其中包含了我们的物理服务器的完整部署配置，我们可以以此为基础创建一个新的虚拟机的 kickstart 文件。

在 CentOS 7 中执行这个最简单的方法是部署一个名为`system-config-kickstart`的实用程序，在 CentOS 8 中不再可用。在[`access.redhat.com/labs/kickstartconfig/`](https://access.redhat.com/labs/kickstartconfig/)有一个在线替代实用程序称为 Kickstart Generator，但您需要拥有 Red Hat Customer Portal 帐户。因此，如果您没有，您只能使用文本编辑现有的 kickstart 文件。这并不是很困难，但可能需要一些努力。我们需要正确配置的最重要的设置与我们将从中安装虚拟机的*位置*有关-是在网络上还是从本地目录（就像我们在第一个`virt-install`示例中所做的那样，使用本地磁盘上的 CentOS ISO）。如果我们将在服务器上本地存储 ISO 文件，则这是一个简单的配置。首先，我们将部署 Apache Web 服务器，以便我们可以在线托管我们的 kickstart 文件（稍后会派上用场）。因此，我们需要以下命令：

```
dnf install httpd 
systemctl start httpd
systemctl enable httpd
cp /root/anaconda-ks.cfg /var/www/html/ks.cfg
chmod 644 /var/www/html/ks.cfg
```

在开始部署过程之前，使用 vi 编辑器（或您喜欢的任何其他编辑器）编辑我们的 kickstart 文件（`/var/www/html/ks.cfg`）中的第一行配置，该配置类似于`ignoredisk --only-use=sda`，改为`ignoredisk --only-use=vda`。这是因为虚拟 KVM 机器不使用`sd*`设备命名，而是使用`vd`命名。这样任何管理员在连接到服务器后就可以更容易地弄清楚他们是在管理物理服务器还是虚拟服务器。

通过编辑 kickstart 文件并使用这些命令，我们安装并启动了`httpd`（Apache Web 服务器）。然后，我们永久启动它，以便在每次服务器重启后都启动它。然后，我们将默认的 kickstart 文件（`anaconda-ks.cfg`）复制到 Apache 的`DocumentRoot`目录（Apache 提供文件的目录），并更改权限，以便 Apache 在客户端请求时实际读取该文件。在我们的示例中，将使用它的*客户端*是`virt-install`命令。我们用来说明这个特性的服务器的 IP 地址是`10.10.48.1`，这是我们将用于 kickstart URL 的地址。请注意，默认的 KVM 桥使用 IP 地址`192.168.122.1`，您可以使用`ip`命令轻松检查：

```
ip addr show virbr0
```

此外，可能需要更改一些防火墙设置，以便在物理服务器上成功获取 kickstart 文件（接受 HTTP 连接）。因此，让我们尝试一下。在这个和以下的示例中，要特别注意`--vcpus`参数（虚拟机的虚拟 CPU 核心数），因为您可能需要根据自己的环境进行更改。换句话说，如果您没有 4 个核心，请确保降低核心数量。我们只是以此作为示例：

```
virt-install --virt-type=kvm --name=MasteringKVM02 --ram=4096 --vcpus=4 --os-variant=rhel8.0 --location=/var/lib/libvirt/images/ CentOS-8-x86_64-1905-dvd1.iso --network=default --graphics vnc --disk size=16 -x "ks=http://10.10.48.1/ks.cfg"
```

重要提示

请注意我们更改的参数。在这里，我们必须使用`--location`参数，而不是`--cdrom`参数，因为我们正在将 kickstart 配置注入到引导过程中（必须以这种方式执行）。

部署过程完成后，我们应该在服务器上有两个名为`MasteringKVM01`和`MasteringKVM02`的完全功能的虚拟机，准备用于我们未来的演示。第二个虚拟机（`MasteringKVM02`）的根密码与第一个虚拟机相同，因为我们除了虚拟磁盘选项之外，没有更改 kickstart 文件中的任何内容。因此，在部署后，我们可以使用`MasteringKVM01`机器的根用户名和密码登录到我们的`MasteringKVM02`机器。

如果我们想进一步发展，我们可以创建一个带有循环的 shell 脚本，该循环将使用索引自动为虚拟机提供唯一名称。我们可以通过使用`for`循环及其计数器轻松实现这一点：

```
#!/bin/bash
for counter in {1..5}
do 
	echo "deploying VM $counter"
virt-install --virt-type=kvm --name=LoopVM$counter --ram=4096 --vcpus=4 --os-variant=rhel8.0 --location=/var/lib/libvirt/images/CentOS-8-x86_64-1905-dvd1.iso --network=default --graphics vnc --disk size=16 -x "ks=http://10.10.48.1/ks.cfg"
done
```

当我们执行此脚本（不要忘记将其`chmod`为`755`！）时，我们应该会得到 10 个名为`LoopVM1-LoopVM5`的虚拟机，所有设置都相同，包括相同的 root 密码。

如果我们使用 GUI 服务器安装，我们可以使用 GUI 实用程序来管理我们的 KVM 服务器。其中一个实用程序称为`virtual`，点击**虚拟机管理器**，然后开始使用它。虚拟机管理器的外观如下：

![图 3.4 – 虚拟机管理器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_04.jpg)

图 3.4 – 虚拟机管理器

现在我们已经介绍了基本的命令行实用程序（`virsh`和`virt-install`），并且有一个非常简单易用的 GUI 应用程序（虚拟机管理器），让我们从这个角度转移一下，思考一下我们对 oVirt 和管理大量主机、虚拟机、网络和存储设备的看法。因此，现在让我们讨论如何安装 oVirt，然后我们将使用它来以更集中的方式管理基于 KVM 的环境。

## 安装 oVirt

安装 oVirt 有不同的方法。我们可以将其部署为自托管引擎（通过 Cockpit Web 界面或 CLI），也可以通过基于软件包的安装将其部署为独立应用程序。让我们以第二种方式为例-在虚拟机中进行独立安装。我们将安装分为两部分：

1.  安装 oVirt 引擎进行集中管理

1.  在我们的基于 CentOS 8 的主机上部署 oVirt 代理

首先，让我们处理 oVirt 引擎部署。部署足够简单，人们通常使用一个虚拟机来实现这一目的。请记住，CentOS 8 不支持 oVirt，在我们的 CentOS 8 虚拟机中，我们需要输入一些命令：

```
yum install https://resources.ovirt.org/pub/yum-repo/ovirt-release44.rpm
yum -y module enable javapackages-tools pki-deps postgresql:12
yum -y update
yum -y install ovirt-engine
```

再次强调，这只是安装部分；我们还没有进行任何配置。所以，这是我们的逻辑下一步。我们需要启动一个名为`engine-setup`的 shell 应用程序，它将询问我们大约 20 个问题。它们相当描述性，引擎设置直接提供了解释，所以这些是我们在测试环境中使用的设置（在您的环境中 FQDN 将不同）：

![图 3.5 – oVirt 配置设置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_05.jpg)

图 3.5 – oVirt 配置设置

在输入`OK`后，引擎设置将开始。最终结果应该看起来像这样：

![图 3.6 – oVirt 引擎设置摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_06.jpg)

图 3.6 – oVirt 引擎设置摘要

现在，我们应该能够通过使用 Web 浏览器并将其指向安装摘要中提到的 URL 来登录到我们的 oVirt 引擎。在安装过程中，我们被要求为`admin@internal`用户提供密码-这是我们将用来管理环境的 oVirt 管理用户。oVirt Web 界面足够简单易用，目前我们只需要登录到管理门户（在尝试登录之前，oVirt 引擎 Web GUI 上直接提供了一个链接）。登录后，我们应该会看到 oVirt GUI：

![图 3.7 – oVirt 引擎管理门户](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_07.jpg)

图 3.7 – oVirt 引擎管理门户

屏幕左侧有各种选项卡-**仪表板**、**计算**、**网络**、**存储**和**管理**-每一个都有特定的用途：

+   **仪表板**：默认的着陆页面。它包含最重要的信息，环境健康状态的可视化表示，以及一些基本信息，包括我们正在管理的虚拟数据中心的数量、集群、主机、数据存储域等等。

+   **计算**：我们转到此页面以管理主机、虚拟机、模板、池、数据中心和集群。

+   **网络**：我们转到此页面以管理我们的虚拟网络和配置文件。

+   **存储**：我们可以在此页面上管理存储资源，包括磁盘、卷、域和数据中心。

+   **管理**：用于管理用户、配额等。

我们将在*第七章*中处理更多与 oVirt 相关的操作，*虚拟机-安装、配置和生命周期管理*，这是关于 oVirt 的全部内容。但目前，让我们保持 oVirt 引擎运行，以便以后再次使用它，并在基于 KVM 的虚拟化环境中进行日常操作。

# 使用 QEMU 和 libvirt 启动虚拟机

部署完成后，我们可以开始管理我们的虚拟机。我们将以`MasteringKVM01`和`MasteringKVM02`为例。让我们使用`virsh`命令和`start`关键字来启动它们：

![图 3.8 - 使用 virsh start 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_08.jpg)

图 3.8 - 使用 virsh start 命令

假设我们从 shell 脚本示例中创建了所有五台虚拟机，并且将它们保持开机状态。我们可以通过发出简单的`virsh list`命令轻松检查它们的状态：

![图 3.9 - 使用 virsh list 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_09.jpg)

图 3.9 - 使用 virsh list 命令

如果我们想要优雅地关闭`MasteringKVM01`虚拟机，可以使用`virsh shutdown`命令：

![图 3.10 - 使用 virsh shutdown 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_10.jpg)

图 3.10 - 使用 virsh shutdown 命令

如果我们想要强制关闭`MasteringKVM02`虚拟机，可以使用`virsh destroy`命令：

![图 3.11 - 使用 virsh destroy 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_11.jpg)

图 3.11 - 使用 virsh destroy 命令

如果我们想要完全删除虚拟机（例如`MasteringKVM02`），通常需要先关闭它（优雅或强制），然后使用`virsh undefine`命令：

![图 3.12 - 使用 virsh destroy 和 undefine 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_12.jpg)

图 3.12 - 使用 virsh destroy 和 undefine 命令

请注意，您实际上可以先执行`virsh undefine`，然后再执行`destroy`，最终结果将是相同的。但是，这可能违反了*预期行为*，即您首先关闭对象，然后再删除它。

我们刚刚学会了如何使用`virsh`命令来管理虚拟机 - 启动和停止 - 强制和优雅。当我们开始扩展对`virsh`命令的使用知识时，这将会很有用，在接下来的章节中，我们将学习如何管理 KVM 网络和存储。

我们也可以从 GUI 中完成所有这些操作。您可能还记得，在本章的前面，我们安装了一个名为`virt-manager`的软件包。实际上，这是一个用于管理 KVM 主机的 GUI 应用程序。让我们使用它来进一步操作我们的虚拟机。这是`virt-manager`的基本 GUI 界面：

![图 3.13 - virt-manager GUI - 我们可以看到已注册的虚拟机并开始管理它们](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_13.jpg)

图 3.13 - virt-manager GUI - 我们可以看到已注册的虚拟机列表并开始管理它们

如果我们想对虚拟机进行常规操作 - 启动、重启、关闭、关闭电源 - 我们只需要右键单击它，并从菜单中选择该选项。要使所有操作可见，首先我们必须启动虚拟机；否则，只有四个操作可用，而可用的七个操作中，`MasteringKVM01`的列表将变得更大：

![图 3.14 - virt-manager 选项 - 在虚拟机上电后，我们现在可以使用更多选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_03_14.jpg)

图 3.14 - virt-manager 选项 - 在虚拟机上电后，我们现在可以使用更多选项

我们将在本书中的各种操作中使用`virt-manager`，所以请确保您熟悉它。在许多情况下，它将使我们的管理工作变得更加容易。

# 总结

在本章中，我们为本书剩余章节中要做的几乎所有事情奠定了一些基本的基础和先决条件。我们学会了如何安装 KVM 和 libvirt 堆栈。我们还学会了如何部署 oVirt 作为管理我们的 KVM 主机的 GUI 工具。

接下来的几章将带领我们走向更加技术化的方向，我们将涵盖网络和存储概念。为了做到这一点，我们将不得不退一步，学习或复习我们之前关于网络和存储的知识，因为这些对于虚拟化，特别是云计算来说是非常重要的概念。

# 问题

1.  我们如何验证我们的主机是否与 KVM 要求兼容？

1.  oVirt 的默认登陆页面是什么？

1.  我们可以使用哪个命令从命令行管理虚拟机？

1.  我们可以使用哪个命令从命令行部署虚拟机？

# 进一步阅读

请参考以下链接，了解本章涵盖的更多信息：

+   Kickstart Generator: [`access.redhat.com/labs/kickstartconfig/`](https://access.redhat.com/labs/kickstartconfig/). 只是提醒您，您需要拥有 RedHat 支持帐户才能访问此链接。

+   oVirt: [`www.ovirt.org/`](https://www.ovirt.org/).


# 第四章：Libvirt 网络

了解虚拟网络如何工作对于虚拟化非常重要。很难证明在没有虚拟网络的情况下，我们可以承担与拥有多个虚拟机的虚拟化主机相关的成本。想象一下，在虚拟化网络中有多个虚拟机，并购买网络卡，以便每个虚拟机都可以拥有自己专用的物理网络端口。通过实施虚拟网络，我们也以更可管理的方式整合了网络，无论是从管理还是成本的角度来看。

本章为您提供了对虚拟化网络和基于 Linux 的网络概念的整体概念。我们还将讨论物理和虚拟网络概念，尝试比较它们，并找出它们之间的相似之处和不同之处。本章还涵盖了虚拟交换的概念，用于主机概念和跨主机概念，以及一些更高级的主题。这些主题包括单根输入/输出虚拟化，它允许对某些场景的硬件采用更直接的方法。随着我们开始讨论云覆盖网络，我们将在本书的后面回顾一些网络概念。这是因为基本的网络概念对于大型云环境来说并不够可扩展。

在本章中，我们将涵盖以下主题：

+   理解物理和虚拟网络

+   使用 TAP/TUN

+   实施 Linux 桥接

+   配置 Open vSwitch

+   了解和配置 SR-IOV

+   理解 macvtap

+   让我们开始吧！

# 理解物理和虚拟网络

让我们思考一下网络。这是当今大多数系统管理员都相当了解的一个主题。这可能不是我们认为的那么高的水平，但是-如果我们试图找到一个系统管理领域，我们会发现最大的共同知识水平，那就是网络。

那么，问题出在哪里呢？

实际上，没有什么。如果我们真正理解物理网络，那么虚拟网络对我们来说将是小菜一碟。剧透警告：*它是一样的*。如果我们不理解，它将很快暴露出来，因为没有绕过它的办法。随着环境的发展和通常的增长，问题会越来越大，因为它们变得越大，它们将产生越多的问题，您将花费更多的时间处于调试模式。

话虽如此，如果您对基于 VMware 或 Microsoft 的虚拟网络在技术层面上有很好的掌握，那么这些概念对您来说都是非常相似的。

说到这一点，虚拟网络到底是怎么回事？实际上，这是关于理解事情发生的地方，方式和原因。这是因为从物理上讲，虚拟网络与物理网络完全相同。从逻辑上讲，有一些差异更多地与事物的*拓扑*有关，而不是原则或工程方面的事物。这通常会让人们有点困惑-有一些奇怪的基于软件的对象，它们与大多数人已经习惯通过我们喜爱的基于 CLI 或 GUI 的实用程序来管理的物理对象做着相同的工作。

首先，让我们介绍虚拟化网络的基本构建块-虚拟交换机。虚拟交换机基本上是一个基于软件的第 2 层交换机，您可以使用它来做两件事：

+   将您的虚拟机连接到它。

+   使用其上行将它们连接到物理服务器卡，以便您可以将这些物理网络卡连接到物理交换机。

因此，让我们从虚拟机的角度来看为什么我们需要这些虚拟交换机。正如我们之前提到的，我们使用虚拟交换机将虚拟机连接到它。为什么呢？如果没有一种软件对象坐在我们的物理网络卡和虚拟机之间，我们会有一个大问题 - 我们只能连接我们有物理网络端口的虚拟机到我们的物理网络，这是不可容忍的。首先，这违反了虚拟化的一些基本原则，如效率和整合，其次，这将花费很多。想象一下在您的服务器上有 20 台虚拟机。这意味着，如果没有虚拟交换机，您至少需要 20 个物理网络端口连接到物理网络。此外，您实际上还会在物理交换机上使用 20 个物理端口，这将是一场灾难。

因此，通过在虚拟机和物理网络端口之间引入虚拟交换机，我们同时解决了两个问题 - 我们减少了每台服务器所需的物理网络适配器数量，减少了我们需要用来连接虚拟机到网络的物理交换机端口数量。我们实际上还可以说我们解决了第三个问题 - 效率 - 因为有许多情况下，一个物理网络卡可以处理连接到虚拟交换机的 20 台虚拟机的上行流量。具体来说，我们的环境中有很大一部分并不消耗大量网络流量，对于这些情况，虚拟网络只是非常高效的。

# 虚拟网络

现在，为了使虚拟交换机能够连接到虚拟机上的某个东西，我们必须有一个对象来连接 - 这个对象被称为虚拟网络接口卡，通常称为 vNIC。每次您配置一个虚拟机与虚拟网络卡，您都赋予它连接到使用物理网络卡作为上行连接到物理交换机的虚拟交换机的能力。

当然，这种方法也存在一些潜在的缺点。例如，如果您有 50 台虚拟机连接到使用相同物理网络卡作为上行的同一个虚拟交换机，而该上行失败（由于网络卡问题、电缆问题、交换机端口问题或交换机问题），您的 50 台虚拟机将无法访问物理网络。我们如何解决这个问题？通过实施更好的设计，并遵循我们在物理网络上也会使用的基本设计原则。具体来说，我们会使用多个物理上行连接到同一个虚拟交换机。

Linux 有*很多*不同类型的网络接口，大约有 20 种不同类型，其中一些如下：

+   **Bridge**: 用于（虚拟机）网络的第 2 层接口。

+   **Bond**: 用于将网络接口组合成单个接口（用于平衡和故障转移原因）成为一个逻辑接口。

+   **Team**: 与绑定不同，团队合作不会创建一个逻辑接口，但仍然可以进行平衡和故障转移。

+   **MACVLAN**: 在第二层上在单个物理接口上创建多个 MAC 地址（创建子接口）。

+   **IPVLAN**: 与 MACVLAN 不同，IPVLAN 使用相同的 MAC 地址并在第 3 层上进行复用。

+   **MACVTAP/IPVTAP**: 新的驱动程序，应该通过将 TUN、TAP 和桥接组合为单个模块来简化虚拟网络。

+   **VXLAN**: 一种常用的云覆盖网络概念，我们将在第十二章中详细描述，*使用 OpenStack 扩展 KVM*。

+   **VETH**: 一种可以用于本地隧道的虚拟以太网接口。

+   **IPOIB**: Infiniband 上的 IP。随着 Infiniband 在 HPC/低延迟网络中的普及，Linux 内核也支持这种类型的网络。

还有很多其他的。在这些网络接口类型之上，还有大约 10 种隧道接口类型，其中一些如下：

+   GRETAP，GRE：用于封装第 2 层和第 3 层协议的通用路由封装协议。

+   GENEVE：云覆盖网络的融合协议，旨在将 VXLAN、GRE 等融合为一个。这就是为什么它受到 Open vSwitch、VMware NSX 和其他产品的支持。

+   IPIP：通过公共网络连接内部 IPv4 子网的 IP 隧道。

+   SIT：用于在 IPv4 上互连孤立的 IPv6 网络的简单互联网翻译。

+   ip6tnl：IPv4/6 隧道通过 IPv6 隧道接口。

+   IP6GRE，IP6GRETAP 等。

理解所有这些内容是一个相当复杂和繁琐的过程，因此在本书中，我们只会关注对虚拟化和（本书后面的内容）云非常重要的接口类型。这就是为什么我们将在*第十二章*中讨论 VXLAN 和 GENEVE 覆盖网络，因为我们需要牢牢掌握**软件定义网络**（**SDN**）。

因此，具体来说，在本章的一部分中，我们将涵盖 TAP/TUN、桥接、Open vSwitch 和 macvtap 接口，因为这些基本上是 KVM 虚拟化最重要的网络概念。

但在深入研究之前，让我们解释一些适用于 KVM/libvirt 网络和其他虚拟化产品的基本虚拟网络概念（例如，VMware 的托管虚拟化产品，如 Workstation 或 Player，使用相同的概念）。当您开始配置 libvirt 网络时，您可以在 NAT、路由和隔离之间进行选择。让我们讨论一下这些网络模式的作用。

## Libvirt NAT 网络

对于我们想要连接到互联网的所有设备（例如`192.168.0.0/24`），我们需要一个 NAT 网络类型。

现在，让我们将其转换为虚拟化网络示例。在我们的虚拟机场景中，这意味着我们的虚拟机可以通过主机的 IP 地址与连接到物理网络的任何内容进行通信，但反之则不行。要使某物能够与我们的虚拟机在 NAT 交换机后面进行通信，我们的虚拟机必须启动该通信（或者我们必须设置某种端口转发，但这不是重点）。

以下图表可能更好地解释了我们正在谈论的内容：

![图 4.1 - libvirt NAT 模式下的网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_01.jpg)

图 4.1 - libvirt NAT 模式下的网络

从虚拟机的角度来看，它愉快地坐在一个完全独立的网络段中（因此有`192.168.122.210`和`220` IP 地址），并使用虚拟网络交换机作为访问外部网络的网关。它不必担心任何额外的路由，因为这就是我们使用 NAT 的原因之一-简化端点路由。

## Libvirt 路由网络

第二种网络类型是路由网络，基本上意味着我们的虚拟机通过虚拟交换机直接连接到物理网络。这意味着我们的虚拟机与物理主机处于相同的第 2/3 层网络中。这种类型的网络连接经常被使用，因为通常情况下，没有必要在环境中访问虚拟机时使用单独的 NAT 网络。在某种程度上，这只会使一切变得更加复杂，特别是因为您必须配置路由以了解您用于虚拟机的 NAT 网络。在使用路由模式时，虚拟机位于与下一个物理设备*相同*的网络段中。以下图表对路由网络有很好的解释：

![图 4.2 - libvirt 路由模式下的网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_02.jpg)

图 4.2 - libvirt 路由模式下的网络

现在我们已经介绍了最常用的两种虚拟机网络场景，是时候介绍第三种了，这种情况似乎有点模糊。如果我们配置一个没有*上行*（这意味着它没有物理网络卡连接到它）的虚拟交换机，那么该虚拟交换机根本无法将流量发送到物理网络。剩下的只是在该交换机本身的限制内进行通信，因此称为*隔离*。让我们现在创建这个难以捉摸的隔离网络。

## Libvirt 隔离网络

在这种情况下，连接到同一隔离交换机的虚拟机可以彼此通信，但它们无法与它们运行的主机之外的任何东西通信。我们之前用“模糊”一词来描述这种情况，但实际上并不是 - 在某些方面，这实际上是一种*隔离*特定类型的流量的理想方式，以至于它甚至不会到达物理网络。

这样想吧 - 假设你有一个托管 Web 服务器的虚拟机，例如运行 WordPress。您创建了两个虚拟交换机：一个运行路由网络（直接连接到物理网络），另一个是隔离的。然后，您可以为 WordPress 虚拟机配置两个虚拟网络卡，第一个连接到路由虚拟交换机，第二个连接到隔离虚拟交换机。WordPress 需要一个数据库，所以您创建另一个虚拟机并配置它仅使用内部虚拟交换机。然后，您使用该隔离虚拟交换机来*隔离*Web 服务器和数据库服务器之间的流量，以便 WordPress 通过该交换机连接到数据库服务器。通过这样配置虚拟机基础设施，您得到了什么？您有一个双层应用程序，而该 Web 应用程序的最重要部分（数据库）无法从外部访问。看起来并不是一个坏主意，对吧？

隔离的虚拟网络在许多其他与安全相关的场景中使用，但这只是一个我们可以轻松识别的示例场景。

让我们用图表描述我们的隔离网络：

![图 4.3 - libvirt 隔离模式下的网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_03.jpg)

图 4.3 - libvirt 隔离模式下的网络

本书的上一章（*第三章*，*安装 KVM Hypervisor、libvirt 和 ovirt*）提到了*默认*网络，我们说我们稍后会谈论这个。现在似乎是一个合适的时机，因为现在我们已经有足够的信息来描述默认网络配置是什么。

当我们像在*第三章*中所做的那样安装所有必要的 KVM 库和实用程序，*安装 KVM Hypervisor、libvirt 和 oVirt*，默认的虚拟交换机会被自动配置。这样做的原因很简单 - 预先配置一些东西更加用户友好，这样用户就可以开始创建虚拟机并将它们连接到默认网络，而不是期望用户也配置这一点。VMware 的 vSphere hypervisor 也是如此（默认交换机称为 vSwitch0），Hyper-V 在部署过程中要求我们配置第一个虚拟交换机（实际上我们可以跳过并稍后配置）。因此，这只是一个众所周知的、标准化的、已建立的场景，使我们能够更快地开始创建我们的虚拟机。

默认虚拟交换机以 NAT 模式工作，DHCP 服务器处于活动状态，再次，这样做的原因很简单 - 客户操作系统默认预配置了 DHCP 网络配置，这意味着我们刚刚创建的虚拟机将轮询网络以获取必要的 IP 配置。这样，虚拟机就可以获得所有必要的网络配置，我们可以立即开始使用它。

以下图表显示了默认的 KVM 网络的功能：

![图 4.4 - libvirt 默认 NAT 模式网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_04.jpg)

图 4.4 - libvirt 默认 NAT 模式网络

现在，让我们学习如何从 shell 和 GUI 中配置这些类型的虚拟网络概念。我们将把这个过程视为一个需要按顺序完成的过程：

1.  让我们首先将默认网络配置导出为 XML，以便我们可以将其用作创建新网络的模板：![图 4.5 - 导出默认虚拟网络配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_05.jpg)

图 4.5 - 导出默认虚拟网络配置

1.  现在，让我们将该文件复制到一个名为`packtnat.xml`的新文件中，编辑它，然后使用它来创建一个新的 NAT 虚拟网络。然而，在这之前，我们需要生成两样东西 - 一个新的对象 UUID（用于我们的新网络）和一个唯一的 MAC 地址。可以使用`uuidgen`命令从 shell 中生成一个新的 UUID，但生成 MAC 地址有点棘手。因此，我们可以使用红帽网站上提供的标准红帽建议方法：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/virtualization_administration_guide/sect-virtualization-tips_and_tricks-generating_a_new_unique_mac_address`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/virtualization_administration_guide/sect-virtualization-tips_and_tricks-generating_a_new_unique_mac_address)。通过使用该 URL 上可用的第一段代码，创建一个新的 MAC 地址（例如，`00:16:3e:27:21:c1`）。

通过使用`yum`命令，安装 python2：

```
virbr1). Now, we can complete the configuration of our new virtual machine network XML file:![Figure 4.6 – New NAT network configuration    ](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_06.jpg)Figure 4.6 – New NAT network configurationThe next step is importing this configuration.
```

1.  现在，我们可以使用`virsh`命令导入该配置并创建我们的新虚拟网络，启动该网络并使其永久可用，并检查是否一切加载正确：

```
virsh net-define packtnat.xml
virsh net-start packtnat
virsh net-autostart packtnat
virsh net-list
```

鉴于我们没有删除默认虚拟网络，最后一个命令应该给我们以下输出：

![图 4.7 - 使用 virsh net-list 检查 KVM 主机上有哪些虚拟网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_07.jpg)

图 4.7 - 使用 virsh net-list 检查 KVM 主机上有哪些虚拟网络

现在，让我们创建另外两个虚拟网络 - 一个桥接网络和一个隔离网络。同样，让我们使用文件作为模板来创建这两个网络。请记住，为了能够创建一个桥接网络，我们需要一个物理网络适配器，因此我们需要在服务器上有一个可用的物理适配器。在我们的服务器上，该接口被称为`ens224`，而名为`ens192`的接口被默认的 libvirt 网络使用。因此，让我们创建两个配置文件，分别称为`packtro.xml`（用于我们的路由网络）和`packtiso.xml`（用于我们的隔离网络）：

![图 4.8 - libvirt 路由网络定义](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_08.jpg)

图 4.8 - libvirt 路由网络定义

在这个特定的配置中，我们使用`ens224`作为路由虚拟网络的上行链路，该虚拟网络将使用与`ens224`连接的物理网络相同的子网（`192.168.2.0/24`）：

![图 4.9 - libvirt 隔离网络定义](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_09.jpg)

图 4.9 - libvirt 隔离网络定义

为了确保万无一失，我们也可以使用虚拟机管理器 GUI 来配置所有这些，因为该应用程序也有一个用于创建虚拟网络的向导。但是当我们谈论更大的环境时，导入 XML 是一个更简单的过程，即使我们忘记了很多 KVM 虚拟化主机根本没有安装 GUI。

到目前为止，我们已经讨论了整体主机级别的虚拟网络。然而，还有一种不同的方法来处理这个主题 - 使用虚拟机作为我们可以向其添加虚拟网络适配器并将其连接到虚拟网络的对象。我们可以使用`virsh`来实现这一目的。因此，举个例子，我们可以将名为`MasteringKVM01`的虚拟机连接到一个隔离的虚拟网络：

```
virsh attach-interface --domain MasteringKVM01 --source isolated --type network --model virtio --config --live
```

还有其他概念允许虚拟机连接到物理网络，其中一些我们将在本章后面讨论（如 SR-IOV）。然而，现在我们已经介绍了通过虚拟交换/桥接将虚拟机连接到物理网络的基本方法，我们需要变得更加技术化。问题是，在连接虚拟机到虚拟交换中涉及更多的概念，比如 TAP 和 TUN，我们将在接下来的部分中进行介绍。

# 使用 TAP 和 TUN 设备进行用户空间网络连接

在*第一章*，*理解 Linux 虚拟化*中，我们使用`virt-host-validate`命令对主机的 KVM 虚拟化准备情况进行了一些预检查。作为该过程的一部分，一些检查包括检查以下设备是否存在：

+   `/dev/kvm`：KVM 驱动程序在主机上创建了一个`/dev/kvm`字符设备，以便为虚拟机提供直接硬件访问。没有这个设备意味着虚拟机将无法访问物理硬件，尽管它在 BIOS 中已启用，这将显著降低虚拟机的性能。

+   `/dev/vhost-net`：在主机上将创建`/dev/vhost-net`字符设备。该设备用作配置`vhost-net`实例的接口。没有这个设备会显著降低虚拟机的网络性能。

+   `/dev/net/tun`：这是另一个用于创建 TUN/TAP 设备以为虚拟机提供网络连接的字符特殊设备。TUN/TAP 设备将在以后的章节中详细解释。现在只需理解，拥有一个字符设备对于 KVM 虚拟化正常工作是很重要的。

让我们专注于最后一个设备，TUN 设备，通常会伴随着一个 TAP 设备。

到目前为止，我们所涵盖的所有概念都包括与物理网络卡的某种连接，隔离的虚拟网络是一个例外。但即使是隔离的虚拟网络对于我们的虚拟机来说也只是一个虚拟网络。当我们需要在用户空间进行通信时会发生什么，比如在服务器上运行的应用之间？将它们通过某种虚拟交换概念或常规桥接连接起来将会带来额外的开销。这就是 TUN/TAP 设备的作用，为用户空间程序提供数据包流。很容易，应用程序可以打开`/dev/net/tun`并使用`ioctl()`函数在内核中注册一个网络设备，然后它会呈现为一个 tunXX 或 tapXX 设备。当应用程序关闭文件时，它创建的网络设备和路由会消失（如内核`tuntap.txt`文档中所述）。因此，这只是 Linux 操作系统支持的一种虚拟网络接口类型，可以向其添加 IP 地址和路由，以便应用程序的流量可以通过它路由，而不是通过常规网络设备。

TUN 通过创建通信隧道来模拟 L3 设备，类似于点对点隧道。当 tuntap 驱动程序配置为 tun 模式时，它会被激活。激活后，从描述符（配置它的应用程序）接收到的任何数据都将以常规 IP 数据包的形式传输（作为最常用的情况）。同样，当发送数据时，它会被写入 TUN 设备作为常规 IP 数据包。这种类型的接口有时用于测试、开发和模拟调试目的。

TAP 接口基本上模拟 L2 以太网设备。当 tuntap 驱动程序以 tap 模式配置时，它会被激活。当您激活它时，与 TUN 接口（第 3 层）不同，您会获得第 2 层原始以太网数据包，包括 ARP/RARP 数据包和其他所有内容。基本上，我们谈论的是虚拟化的第 2 层以太网连接。

这些概念（特别是 TAP）也可用于 libvirt/QEMU，因为通过使用这些类型的配置，我们可以从主机到虚拟机创建连接 - 例如，没有 libvirt 桥/交换机。我们实际上可以配置 TUN/TAP 接口的所有必要细节，然后通过使用`kvm-qemu`选项将虚拟机连接到这些接口。因此，这是一个在虚拟化世界中有其位置的相当有趣的概念。当我们开始创建 Linux 桥接时，这尤其有趣。

# 实施 Linux 桥接

让我们创建一个桥接，然后将 TAP 设备添加到其中。在这样做之前，我们必须确保桥接模块已加载到内核中。让我们开始吧：

1.  如果未加载，请使用`modprobe bridge`加载模块：

```
tester:

```

# brctl show 命令将列出服务器上所有可用的桥接以及一些基本信息，例如桥接的 ID、生成树协议（STP）状态以及连接到其上的接口。在这里，测试器桥没有任何接口连接到其虚拟端口。

```

```

1.  Linux 桥接也将显示为网络设备。要查看桥接测试器的网络详细信息，请使用`ip`命令：

```
ifconfig to check and configure the network settings for a Linux bridge; ifconfig is relatively easy to read and understand but not as feature-rich as the ip command:

```

# ifconfig tester

测试器：flags=4098<BROADCAST,MULTICAST>mtu 1500

ether26:84:f2:f8:09:e0txqueuelen 1000（以太网）

RX 数据包 0 字节 0（0.0 B）

RX 错误 0 丢弃 0 超限 0 帧 0

TX 数据包 0 字节 0（0.0 B）

TX 错误 0 丢弃 0 超限 0 载波 0 冲突 0

```

The Linux bridge tester is now ready. Let's create and add a TAP device to it. 
```

1.  首先，检查 TUN/TAP 设备模块是否加载到内核中。如果没有，您已经知道该怎么做：

```
vm-vnic:

```

测试器和名为 vm-vnic 的 tap 设备。让我们将 vm-vnic 添加到 tester：

```
# brctl addif tester vm-vnic
# brctl show
bridge name bridge id STP enabled interfaces
tester 8000.460a80dd627d no vm-vnic
```

```

```

在这里，您可以看到`vm-vnic`是添加到`tester`桥的接口。现在，`vm-vnic`可以作为您的虚拟机和`tester`桥之间的接口，从而使虚拟机能够与添加到此桥的其他虚拟机进行通信：

图 4.10 - 连接到虚拟交换机（桥接）的虚拟机

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_10.jpg)

图 4.10 - 连接到虚拟交换机（桥接）的虚拟机

您可能还需要删除在上一个过程中创建的所有对象和配置。让我们通过命令行逐步进行：

1.  首先，我们需要从`tester`桥中删除`vm-vnic` tap 设备：

```
vm-vnic has been removed from the bridge, remove the tap device using the ip command:

```

# ip tuntap del dev vm-vnic mode tap

```

```

1.  然后，删除测试器桥：

```
# brctl delbr tester
```

这些是 libvirt 在后端执行的相同步骤，用于启用或禁用虚拟机的网络。在继续之前，我们希望您彻底了解此过程。现在我们已经介绍了 Linux 桥接，是时候转向一个更高级的概念，称为 Open vSwitch。

# 配置 Open vSwitch

想象一下，你在一家小公司工作，有三到四个 KVM 主机，几个网络附加存储设备来托管他们的 15 台虚拟机，并且你从一开始就被公司雇佣。因此，您已经见证了一切 - 公司购买了一些服务器、网络交换机、电缆和存储设备，并且您是建立该环境的一小部分人员团队。经过 2 年的过程，您已经意识到一切都运作正常，维护简单，并且没有给您带来太多烦恼。

现在，想象一下，你的一个朋友在一家拥有 400 个 KVM 主机和近 2000 台虚拟机的大型企业公司工作，他们需要管理的工作与你在你的小公司的舒适椅子上所做的工作相同。

你认为你的朋友能否通过使用与你相同的工具来管理他或她的环境？使用 XML 文件进行网络交换机配置，从可引导的 USB 驱动器部署服务器，手动配置一切，并有时间这样做？这对你来说可能吗？

在第二种情况中有两个基本问题：

+   环境的规模：这一点更为明显。由于环境的规模，您需要一种在中央进行管理的概念，而不是在主机级别进行管理，比如我们迄今讨论过的虚拟交换机。

+   公司政策：这些通常规定尽可能从配置标准化中获得的一些合规性。现在，我们可以同意我们可以通过 Ansible，Puppet 或类似工具脚本化一些配置更新，但有什么用呢？每次我们需要对 KVM 网络进行更改时，我们都必须创建新的配置文件，新的流程和新的工作簿。大公司对此持负面态度。

所以，我们需要的是一个可以跨越多个主机并提供配置一致性的集中式网络对象。在这种情况下，配置一致性为我们带来了巨大的优势 - 我们在这种类型的对象中引入的每个更改都将被复制到所有属于这个集中式网络对象的主机。换句话说，我们需要的是**Open vSwitch**（**OVS**）。对于那些更熟悉基于 VMware 的网络的人来说，我们可以使用一个近似的隐喻 - 对于基于 KVM 的环境，Open vSwitch 类似于 vSphere 分布式交换机对于基于 VMware 的环境。

在技术方面，OVS 支持以下内容：

+   VLAN 隔离（IEEE 802.1Q）

+   流量过滤

+   具有或不具有 LACP 的 NIC 绑定

+   各种覆盖网络 - VXLAN，GENEVE，GRE，STT 等

+   802.1ag 支持

+   Netflow，sFlow 等

+   （R）SPAN

+   OpenFlow

+   OVSDB

+   流量排队和整形

+   Linux，FreeBSD，NetBSD，Windows 和 Citrix 支持（以及其他许多）

现在我们已经列出了一些支持的技术，让我们讨论一下 Open vSwitch 的工作方式。

首先，让我们谈谈 Open vSwitch 的架构。 Open vSwitch 的实现分为两部分：Open vSwitch 内核模块（数据平面）和用户空间工具（控制平面）。由于传入的数据包必须尽快处理，因此 Open vSwitch 的数据平面被推到了内核空间：

![图 4.11 - Open vSwitch 架构](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_11.jpg)

图 4.11 - Open vSwitch 架构

数据路径（OVS 内核模块）使用 netlink 套接字与 vswitchd 守护程序进行交互，在本地系统上实现和管理任意数量的 OVS 交换机。

Open vSwitch 没有特定的 SDN 控制器用于管理目的，类似于 VMware 的 vSphere 分布式交换机和 NSX，它们有 vCenter 和各种 NSX 组件来管理它们的功能。在 OVS 中，重点是使用其他人的 SDN 控制器，然后使用 OpenFlow 协议与 ovs-vswitchd 进行交互。ovsdb-server 维护交换机表数据库，外部客户端可以使用 JSON-RPC 与 ovsdb-server 进行通信；JSON 是数据格式。ovsdb 数据库目前包含大约 13 个表，并且此数据库在重新启动时是持久的。

Open vSwitch 有两种模式：正常模式和流模式。本章将主要集中讨论如何在独立/正常模式下启动连接到 Open vSwitch 桥的 KVM VM，并简要介绍使用 OpenDaylight 控制器的流模式：

+   **正常模式**：交换和转发由 OVS 桥处理。在这种模式下，OVS 充当 L2 学习交换机。当为目标配置多个覆盖网络而不是操纵交换机流时，此模式特别有用。

+   `ctl`命令。此模式允许更高级别的抽象和自动化；SDN 控制器公开了 REST API。我们的应用程序可以利用此 API 直接操纵桥接的流量以满足网络需求。

让我们继续实际操作，学习如何在 CentOS 8 上安装 Open vSwitch：

1.  我们必须做的第一件事是告诉系统使用适当的存储库。在这种情况下，我们需要启用名为`epel`和`centos-release-openstack-train`的存储库。我们可以通过使用一些`yum`命令来实现：

```
yum -y install epel-release
yum -y install centos-release-openstack-train
```

1.  下一步将从 Red Hat 的存储库安装`openvswitch`：

```
dnf install openvswitch -y
```

1.  安装过程完成后，我们需要通过启动和启用 Open vSwitch 服务并运行`ovs-vsctl -V`命令来检查一切是否正常工作：

```
2.11.0 and DB schema 7.16.1.
```

1.  现在我们已经成功安装并启动了 Open vSwitch，现在是时候对其进行配置了。让我们选择一个部署方案，在该方案中，我们将使用 Open vSwitch 作为虚拟机的新虚拟交换机。在我们的服务器中，我们还有另一个名为`ens256`的物理接口，我们将使用它作为 Open vSwitch 虚拟交换机的上行。我们还将清除 ens256 的配置，为我们的 OVS 配置 IP 地址，并使用以下命令启动 OVS：

```
ovs-vsctl add-br ovs-br0
ip addr flush dev ens256
ip addr add 10.10.10.1/24 dev ovs-br0
ovs-vsctl add-port ovs-br0 ens256
ip link set dev ovs-br0 up
```

1.  现在一切都配置好了，但还没有持久化，我们需要使配置持久化。这意味着配置一些网络接口配置文件。因此，转到`/etc/sysconfig/network-scripts`并创建两个文件。将其中一个命名为`ifcfg-ens256`（用于我们的上行接口）：

```
ifcfg-ovs-br0 (for our OVS):

```

DEVICE=ovs-br0

DEVICETYPE=ovs

TYPE=OVSBridge

BOOTPROTO=static

IPADDR=10.10.10.1

NETMASK=255.255.255.0

GATEWAY=10.10.10.254

ONBOOT=yes

```

```

1.  我们不是为了展示而配置所有这些，因此我们需要确保我们的 KVM 虚拟机也能够使用它。这意味着我们需要创建一个将使用 OVS 的 KVM 虚拟网络。幸运的是，我们之前已经处理过 KVM 虚拟网络 XML 文件（查看*Libvirt 隔离网络*部分），因此这不会成为问题。让我们将我们的网络命名为`packtovs`，其对应的 XML 文件命名为`packtovs.xml`。它应该包含以下内容：

```
<network>
<name>packtovs</name>
<forward mode='bridge'/>
<bridge name='ovs-br0'/>
<virtualport type='openvswitch'/>
</network>
```

因此，现在，当我们在 XML 文件中有一个虚拟网络定义时，我们可以执行我们通常的操作，即定义、启动和自动启动网络：

```
virsh net-define packtovs.xml
virsh net-start packtovs
virsh net-autostart packtovs
```

如果我们在创建虚拟网络时保持一切不变，那么`virsh net-list`的输出应该是这样的：

![图 4.12–成功的 OVS 配置和 OVS+KVM 配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_12.jpg)

图 4.12–成功的 OVS 配置和 OVS+KVM 配置

现在剩下的就是将 VM 连接到我们新定义的基于 OVS 的网络`packtovs`，然后我们就可以放心了。或者，我们可以创建一个新的，并使用我们在*第三章*中获得的知识预先将其连接到特定接口。因此，让我们发出以下命令，其中只有两个更改的参数（`--name`和`--network`）：

```
virt-install --virt-type=kvm --name MasteringKVM03 --vcpus 2 --ram 4096 --os-variant=rhel8.0 --cdrom=/var/lib/libvirt/images/CentOS-8-x86_64-1905-dvd1.iso --network network:packtovs --graphics vnc --disk size=16
```

虚拟机安装完成后，我们连接到基于 OVS 的`packtovs`虚拟网络，并且我们的虚拟机可以使用它。假设需要进行额外配置，并且我们收到了一个请求，要求标记来自该虚拟机的流量为`VLAN ID 5`。启动虚拟机并使用以下一组命令：

```
ovs-vsctl list-ports ovs-br0
ens256
vnet0
```

此命令告诉我们，我们正在使用`ens256`端口作为上行，并且我们的虚拟机`MasteringKVM03`正在使用虚拟`vnet0`网络端口。我们可以使用以下命令对该端口应用 VLAN 标记：

```
ovs-vsctl set port vnet0 tag=5
```

由于 OVS 的管理和管理是通过 CLI 完成的，我们需要注意一些与 OVS 管理相关的附加命令。因此，以下是一些常用的 OVS CLI 管理命令：

+   `#ovs-vsctl show`：一个非常方便和经常使用的命令。它告诉我们交换机当前运行的配置是什么。

+   `#ovs-vsctl list-br`：列出在 Open vSwitch 上配置的桥接。

+   `#ovs-vsctl list-ports <bridge>`：显示`BRIDGE`上所有端口的名称。

+   `#ovs-vsctl list interface <bridge>`：显示`BRIDGE`上所有接口的名称。

+   `#ovs-vsctl add-br <bridge>`：在交换机数据库中创建一个桥接。

+   `#ovs-vsctl add-port <bridge> : <interface>`：将接口（物理或虚拟）绑定到 Open vSwitch 桥接。

+   `#ovs-ofctl 和 ovs-dpctl`：这两个命令用于管理和监视流条目。您了解到 OVS 管理两种流：OpenFlows 和 Datapath。第一种是在控制平面中管理的，而第二种是基于内核的流。

+   `#ovs-ofctl`：这是针对 OpenFlow 模块的，而`ovs-dpctl`则是针对内核模块的。

以下示例是每个命令的最常用选项：

+   `#ovs-ofctl show <BRIDGE>`：显示有关交换机的简要信息，包括端口号到端口名称的映射。

+   `#ovs-ofctl dump-flows <Bridge>`：检查 OpenFlow 表。

+   `#ovs-dpctl show`：打印有关交换机上存在的所有逻辑数据路径（称为*桥接*）的基本信息。

+   `#ovs-dpctl dump-flows`：显示在数据路径中缓存的流。

+   `ovs-appctl`：此命令提供了一种向运行中的 Open vSwitch 发送命令并收集`ovs-ofctl`命令未直接暴露的信息的方法。这是 OpenFlow 故障排除的瑞士军刀。

+   `#ovs-appctl bridge/dumpflows <br>`：检查流表并为同一主机上的 VM 提供直接连接。

+   `#ovs-appctl fdb/show <br>`：列出学习到的 MAC/VLAN 对。

此外，您还可以始终使用`ovs-vsctl show`命令获取有关 OVS 交换机配置的信息：

![图 4.13 – ovs-vsctl 显示输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_13.jpg)

图 4.13 – ovs-vsctl 显示输出

我们将在*第十二章*中回到 Open vSwitch 的主题，*使用 OpenStack 扩展 KVM*，当我们更深入地讨论跨多个主机跨 Open vSwitch 的情况时，特别是在考虑到我们希望能够跨多个主机和站点扩展我们的云覆盖网络（基于 GENEVE、VXLAN、GRE 或类似协议）的情况。

## 其他 Open vSwitch 用例

正如您可能想象的那样，Open vSwitch 不仅仅是 libvirt 或 OpenStack 的一个方便的概念——它也可以用于各种其他场景。让我们描述其中的一个，因为对于研究 VMware NSX 或 NSX-T 集成的人来说，这可能很重要。

让我们在这里只描述一些基本术语和关系。VMware 的 NSX 是一种基于 SDN 的技术，可用于各种用例：

+   连接数据中心，跨数据中心边界扩展云覆盖网络。

+   各种灾难恢复场景。NSX 可以在灾难恢复、多站点环境以及与各种外部服务和设备集成方面提供大量帮助（Palo Alto PANs）。

+   一致的微分段，跨站点，在虚拟机网络卡级别上以*正确的方式*完成。

+   出于安全目的，从不同类型的支持的 VPN 技术连接站点和终端用户，到分布式防火墙、客户端内省选项（防病毒和反恶意软件）、网络内省选项（IDS/IPS）等各种灾难恢复场景。

+   用于负载平衡，直到第 7 层，具有 SSL 卸载、会话持久性、高可用性、应用规则等。

是的，VMware 对 SDN（NSX）和 Open vSwitch 的看法在市场上看起来像是*竞争技术*，但实际上，有很多客户希望同时使用两者。这就是 VMware 与 OpenStack 集成以及 NSX 与基于 Linux 的 KVM 主机集成（通过使用 Open vSwitch 和额外的代理）非常方便的地方。再进一步解释一下这些观点 - NSX 有一些需要*广泛*使用基于 Open vSwitch 的技术 - 通过 Open vSwitch 数据库进行硬件 VTEP 集成，通过使用 Open vSwitch/NSX 集成将 GENEVE 网络扩展到 KVM 主机，等等。

想象一下，你在为一个服务提供商工作 - 一个云服务提供商，一个 ISP；基本上，任何具有大量网络分割的大型网络的公司。有很多服务提供商使用 VMware 的 vCloud Director 为最终用户和公司提供云服务。然而，由于市场需求，这些环境通常需要扩展到包括 AWS（通过公共云进行额外基础设施增长场景）或 OpenStack（创建混合云场景）。如果我们没有可能在这些解决方案之间实现互操作性，那么就没有办法同时使用这些提供。但从网络的角度来看，这个网络背景是 NSX 或 NSX-T（实际上*使用*了 Open vSwitch）。

多云环境的未来已经很清楚多年了，这些类型的集成将带来更多的客户；他们将希望在他们的云服务设计中利用这些选项。未来的发展也很可能包括（并且已经部分包括）与 Docker、Kubernetes 和/或 OpenShift 的集成，以便能够在同一环境中管理容器。

还有一些更极端的例子使用硬件 - 在我们的例子中，我们谈论的是以*分区*方式使用 PCI Express 总线上的网络卡。目前，我们对这个概念 SR-IOV 的解释将局限于网络卡，但当我们开始讨论在虚拟机中使用分区 GPU 时，我们将在*第六章*中扩展相同的概念，*虚拟显示设备和协议*。因此，让我们讨论一下在支持它的 Intel 网络卡上使用 SR-IOV 的实际例子。

# 理解和使用 SR-IOV

SR-IOV 的概念是我们在*第二章*中已经提到的，*KVM 作为虚拟化解决方案*。通过利用 SR-IOV，我们可以将 PCI 资源（例如，网络卡）*分区*为虚拟 PCI 功能，并将它们注入到虚拟机中。如果我们将这个概念用于网络卡，通常是出于一个目的 - 那就是我们可以避免使用操作系统内核和网络堆栈，同时访问虚拟机中的网络接口卡。为了能够做到这一点，我们需要硬件支持，因此我们需要检查我们的网络卡是否实际支持它。在物理服务器上，我们可以使用`lspci`命令提取有关我们的 PCI 设备的属性信息，然后使用`grep`命令将*Single Root I/O Virtualization*作为一个字符串来尝试查看我们是否有兼容的设备。这是我们服务器的一个例子：

![图 4.14 – 检查我们的系统是否兼容 SR-IOV](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_14.jpg)

图 4.14 – 检查我们的系统是否兼容 SR-IOV

重要说明

在配置 SR-IOV 时要小心。您需要具有支持它的服务器、支持它的设备，并且必须确保您在 BIOS 中打开了 SR-IOV 功能。然后，您需要记住，有些服务器只分配了特定的插槽用于 SR-IOV。我们使用的服务器（HP Proliant DL380p G8）将三个 PCI-Express 插槽分配给 CPU1，但是 SR-IOV 仅在插槽＃1 中起作用。当我们将我们的卡连接到插槽＃2 或＃3 时，我们收到了一个 BIOS 消息，指出 SR-IOV 在该插槽中不起作用，并且我们应该将我们的卡移动到支持 SR-IOV 的插槽。因此，请务必彻底阅读服务器的文档，并将 SR-IOV 兼容设备连接到正确的 PCI-Express 插槽。

在这种特定情况下，这是一个具有两个端口的英特尔 10 千兆网络适配器，我们可以使用它来执行 SR-IOV。该过程并不那么困难，它要求我们完成以下步骤：

1.  从先前的模块中解绑。

1.  将其注册到 Linux 内核堆栈中可用的 vfio-pci 模块。

1.  配置将使用它的客户端。

因此，您要做的是通过使用`modprobe -r`卸载网卡当前正在使用的模块。然后，您会再次加载它，但是通过分配一个附加参数。在我们特定的服务器上，我们使用的英特尔双端口适配器（X540-AT2）被分配给了`ens1f0`和`ens1f1`网络设备。因此，让我们以`ens1f0`作为启动时 SR-IOV 配置的示例：

1.  我们需要做的第一件事（作为一个一般概念）是找出我们的网卡正在使用哪个内核模块。为此，我们需要发出以下命令：

```
modinfo command (we're only interested in the parm part of the output):

```

在这里使用 ixgbe 模块，我们可以执行以下操作：

```
modprobe -r ixgbe
modprobe ixgbe max_vfs=4
```

```

```

1.  然后，我们可以使用`modprobe`系统通过在`/etc/modprobe.d`中创建一个名为（例如）`ixgbe.conf`的文件，并向其中添加以下行来使这些更改在重新启动时保持永久：

```
options ixgbe max_vfs=4
```

这将为我们提供最多四个虚拟功能，我们可以在虚拟机内使用。现在，我们需要解决的下一个问题是如何在服务器启动时激活 SR-IOV。这里涉及了相当多的步骤，所以让我们开始吧：

1.  我们需要将`iommu`和`vfs`参数添加到默认内核引导行和默认内核配置中。因此，首先打开`/etc/default/grub`并编辑`GRUB_CMDLINE_LINUX`行，添加`intel_iommu=on`（如果您使用的是 AMD 系统，则添加`amd_iommu=on`）和`ixgbe.max_vfs=4`。

1.  我们需要重新配置`grub`以使用此更改，因此我们需要使用以下命令：

```
grub2-mkconfig -o /boot/grub2/grub.cfg
```

1.  有时，即使这样还不够，因此我们需要配置必要的内核参数，例如虚拟功能的最大数量和服务器上要使用的`iommu`参数。这导致我们使用以下命令：

```
grubby --update-kernel=ALL --args="intel_iommu=on ixgbe.max_vfs=4"
```

重新启动后，我们应该能够看到我们的虚拟功能。输入以下命令：

```
lspci -nn | grep "Virtual Function"
```

我们应该得到以下类似的输出：

![图 4.15 - 检查虚拟功能可见性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_15.jpg)

图 4.15 - 检查虚拟功能可见性

我们应该能够从 libvirt 中看到这些虚拟功能，并且我们可以通过`virsh`命令进行检查。让我们尝试一下（我们使用`grep 04`，因为我们的设备 ID 以 04 开头，这在前面的图像中可见；我们将缩小输出以仅包含重要条目）：

```
virsh nodedev-list | grep 04 
……
pci_0000_04_00_0
pci_0000_04_00_1
pci_0000_04_10_0
pci_0000_04_10_1
pci_0000_04_10_2
pci_0000_04_10_3
pci_0000_04_10_4
pci_0000_04_10_5
pci_0000_04_10_6
pci_0000_04_10_7
```

前两个设备是我们的物理功能。其余的八个设备（两个端口乘以四个功能）是我们的虚拟设备（从`pci_0000_04_10_0`到`pci_0000_04_10_7`）。现在，让我们使用`virsh nodedev-dumpxml pci_0000_04_10_0`命令来转储该设备的信息：

![图 4.16 - 从 virsh 的角度查看虚拟功能信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_16.jpg)

图 4.16 - 从 virsh 的角度查看虚拟功能信息

因此，如果我们有一个正在运行的虚拟机，我们想要重新配置以使用此功能，我们需要创建一个 XML 文件，其定义看起来像这样（让我们称其为`packtsriov.xml`）：

```
<interface type='hostdev' managed='yes' >
    <source>
    <address type='pci' domain='0x0000' bus='0x04' slot='0x10' function='0x0'>
    </address>
    </source>
</interface>
```

当然，域、总线、插槽和功能需要准确指向我们的 VF。然后，我们可以使用`virsh`命令将该设备附加到我们的虚拟机（例如`MasteringKVM03`）：

```
virsh attach-device MasteringKVM03 packtsriov.xml --config
```

当我们使用`virsh dumpxml`时，现在应该看到输出的一部分以`<driver name='vfio'/>`开头，以及我们在上一步中配置的所有信息（地址类型、域、总线、插槽、功能）。我们的虚拟机应该没有问题使用这个虚拟功能作为网络卡。

现在，是时候介绍另一个在 KVM 网络中非常有用的概念了：macvtap。这是一个较新的驱动程序，应该通过一个模块完全消除 tun/tap 和桥接驱动程序来简化我们的虚拟化网络。

# 理解 macvtap

这个模块的工作方式类似于 tap 和 macvlan 模块的组合。我们已经解释了 tap 模块的功能。macvlan 模块使我们能够创建虚拟网络，这些网络固定在物理网络接口上（通常，我们称这个接口为*lower*接口或设备）。结合 tap 和 macvlan 使我们能够在**虚拟以太网端口聚合器**（**VEPA**）、桥接、私有和透传四种不同的操作模式之间进行选择。

如果我们使用 VEPA 模式（默认模式），物理交换机必须通过支持`hairpin`模式（也称为反射中继）来支持 VEPA。当一个*lower*设备从 VEPA 模式 macvlan 接收数据时，这个流量总是发送到上游设备，这意味着流量总是通过外部交换机进行传输。这种模式的优势在于虚拟机之间的网络流量在外部网络上变得可见，这对于各种原因可能是有用的。您可以查看以下一系列图表中的网络流量是如何工作的：

![图 4.17 – macvtap VEPA 模式，流量被强制发送到外部网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_17.jpg)

图 4.17 – macvtap VEPA 模式，流量被强制发送到外部网络

在私有模式下，它类似于 VEPA，因为所有的东西都会发送到外部交换机，但与 VEPA 不同的是，只有通过外部路由器或交换机发送的流量才会被传送。如果您想要将连接到端点的虚拟机相互隔离，但不隔离外部网络，可以使用这种模式。如果这听起来非常像私有 VLAN 场景，那么您是完全正确的：

![图 4.18 – macvtap 在私有模式下，用于内部网络隔离](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_18.jpg)

图 4.18 – macvtap 在私有模式下，用于内部网络隔离

在桥接模式下，接收到的数据在您的 macvlan 上，应该发送到同一较低设备上的另一个 macvlan，直接发送到目标，而不是外部发送，然后路由返回。这与 VMware NSX 在虚拟机应该在不同的 VXLAN 网络上进行通信时所做的非常相似，但是在同一主机上：

![图 4.19 – macvtap 在桥接模式下，提供一种内部路由](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_19.jpg)

图 4.19 – macvtap 在桥接模式下，提供一种内部路由

在透传模式下，我们基本上在谈论 SR-IOV 场景，我们将 VF 或物理设备直接传递给 macvtap 接口。关键区别在于单个网络接口只能传递给单个客户（1:1 关系）：

![图 4.20 – macvtap 在透传模式下](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_04_20.jpg)

图 4.20 – macvtap 在透传模式下

在*第十二章*，*使用 OpenStack 扩展 KVM*和*第十三章*，*使用 AWS 扩展 KVM*中，我们将描述为什么虚拟化和*覆盖*网络（VXLAN、GRE、GENEVE）对于云网络非常重要，因为我们将我们的本地 KVM 环境扩展到云端，无论是通过 OpenStack 还是 AWS。

# 总结

在本章中，我们介绍了 KVM 中虚拟化网络的基础知识，并解释了为什么虚拟化网络是虚拟化的重要组成部分。我们深入研究了配置文件及其选项，因为这将是在较大环境中进行管理的首选方法，特别是在谈论虚拟化网络时。

请特别注意我们在本章中讨论的所有配置步骤，特别是与使用 virsh 命令来操作网络配置和配置 Open vSwitch 和 SR-IOV 相关的部分。基于 SR-IOV 的概念在延迟敏感的环境中被广泛使用，以提供具有最低可能开销和延迟的网络服务，这就是为什么这个原则对于与金融和银行业相关的各种企业环境非常重要。

既然我们已经涵盖了所有必要的网络场景（其中一些将在本书的后面重新讨论），现在是时候开始考虑虚拟化世界的下一个重要主题了。我们已经讨论了 CPU 和内存，以及网络，这意味着我们剩下了虚拟化的第四支柱：存储。我们将在下一章中讨论这个主题。

# 问题

1.  为什么虚拟交换机同时接受来自多个虚拟机的连接是重要的？

1.  虚拟交换机在 NAT 模式下是如何工作的？

1.  虚拟交换机在路由模式下是如何工作的？

1.  Open vSwitch 是什么，我们可以在虚拟化和云环境中用它来做什么？

1.  描述 TAP 和 TUN 接口之间的区别。

# 进一步阅读

有关本章内容的更多信息，请参考以下链接：

+   Libvirt 网络：[`wiki.libvirt.org/page/VirtualNetworking`](https://wiki.libvirt.org/page/VirtualNetworking)

+   网络 XML 格式：[`libvirt.org/formatnetwork.html`](https://libvirt.org/formatnetwork.html)

+   Open vSwitch：[`www.openvswitch.org/`](https://www.openvswitch.org/)

+   Open vSwitch 和 libvirt：[`docs.openvswitch.org/en/latest/howto/libvirt/`](http://docs.openvswitch.org/en/latest/howto/libvirt/)

+   Open vSwitch 速查表：[`adhioutlined.github.io/virtual/Openvswitch-Cheat-Sheet/`](https://adhioutlined.github.io/virtual/Openvswitch-Cheat-Sheet/)
