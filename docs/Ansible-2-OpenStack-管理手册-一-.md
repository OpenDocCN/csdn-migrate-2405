# Ansible 2 OpenStack 管理手册（一）

> 原文：[`zh.annas-archive.org/md5/F107565E531514C473B8713A397D43CB`](https://zh.annas-archive.org/md5/F107565E531514C473B8713A397D43CB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着 OpenStack 开始被视为更主流的云平台，构建后对其进行操作的挑战变得更加突出。虽然所有云任务都可以通过 API 或 CLI 工具逐个执行，但这并不是处理更大规模云部署的最佳方式。现在明显需要更多自动化的方法来管理 OpenStack。大多数组织都在寻求改善业务敏捷性的方法，并意识到仅仅拥有一个云是不够的。只有通过某种形式的自动化才能改善应用部署、减少基础设施停机时间和消除日常手动任务。OpenStack 和 Ansible 将帮助任何组织弥合这一差距。OpenStack 提供的许多基础设施即服务功能，再加上 Ansible 这种易于使用的配置管理工具，可以确保更完整的云实施。

无论您是 OpenStack 的新手还是经验丰富的云管理员，本书都将帮助您在设置好 OpenStack 云后进行管理。本书充满了真实的 OpenStack 管理任务，我们将首先逐步介绍这些工作示例，然后过渡到介绍如何使用最流行的开源自动化工具之一 Ansible 来自动化这些任务的说明。

Ansible 已经成为开源编排和自动化领域的市场领导者。它也是使用 Python 构建的，与 OpenStack 类似，这使得二者易于结合。利用现有和/或新的 OpenStack 模块的能力将使您能够快速创建您的 playbook。

我们将从简要介绍 OpenStack 和 Ansible 开始，重点介绍一些最佳实践。接下来，每个后续章节的开头都将让您更加熟悉处理云操作员管理任务，如创建多个用户/租户、管理容器、自定义云配额、创建实例快照、设置主动-主动区域、运行云健康检查等。最后，每个章节都将以逐步教程结束，介绍如何使用 Ansible 自动化这些任务。作为额外的奖励，完全功能的 Ansible 代码将在 GitHub 上发布，供您在审阅章节时参考和/或以供以后审阅时参考。

将本书视为一次 2 合 1 的学习体验，深入了解基于 OpenStack 的云管理知识以及了解 Ansible 的工作原理。作为读者，您将被鼓励亲自动手尝试这些任务。

# 本书涵盖内容

第一章 *OpenStack 简介*，提供了 OpenStack 及构成该云平台的项目的高层概述。本介绍将为读者介绍 OpenStack 组件、概念和术语。

第二章 *Ansible 简介*，详细介绍了 Ansible 2.0，其特性和建立坚实起步基础的最佳实践。此外，它还将介绍为什么利用 Ansible 来自动化 OpenStack 任务是最简单的选择。

第三章 *创建多个用户/租户*，指导读者手动在 OpenStack 中创建用户和租户的过程，以及在使用 Ansible 自动化此过程时需要考虑的创建。

第四章 *自定义云配额*，让您了解配额是什么，以及它们如何用于限制您的云资源。它向读者展示了如何在 OpenStack 中手动创建配额。之后，它解释了如何使用 Ansible 自动化此过程，以便一次处理多个租户的任务。

第五章, *快照您的云*，教您如何在 OpenStack 内手动创建云实例的快照，以及如何使用 Ansible 自动化此过程。它探讨了一次性对一个租户内的所有实例进行快照的强大功能。

第六章, *迁移实例*，介绍了在传统的 OpenStack 方法中迁移选择实例到计算节点的概念。然后，它演示了自动化此任务所需的步骤，同时将实例分组，并展示了 Ansible 在处理此类任务时可以提供的其他选项。

第七章, *管理云上的容器*，带领读者了解如何自动化构建和部署在 OpenStack 云上运行的容器的一些策略。现在有几种方法可用，但关键是自动化该过程，使其成为可重复使用的功能。对于每种方法，本章展示了如何成功地使用 OpenStack 完成这些构建块。

第八章, *设置主动-主动区域*，详细审查了设置主动-主动 OpenStack 云区域的几个用例。有了这些知识，您将学会如何自动化部署到您的云。

第九章, *盘点您的云*，探讨了读者如何使用一个 Ansible playbook 动态盘点所有 OpenStack 云用户资源。它指导他们收集必要的指标以及如何将这些信息存储以供以后参考。这对于云管理员/操作员来说是一个非常强大的工具。

第十章, *使用 Nagios 检查您的云健康状况*，演示了如何手动检查云的健康状况以及如何利用 Ansible 设置 Nagios 和必要的检查来监视您的云的一些有用提示和技巧。Nagios 是领先的开源监控平台之一，并且与 OpenStack 和 Ansible 非常配合。

# 您需要为本书做好准备

要真正从本书中受益，最好部署或访问使用 openstack-ansible（OSA）构建的 OpenStack 云，该云运行 Newton 版本或更高版本。OSA 部署方法提供了一个环境，可以安装 OpenStack 和 Ansible。

如果您计划部署其他任何 OpenStack 发行版，您仍然只需要运行 OpenStack Newton 版本或更高版本。此外，您需要在相同节点上或您的工作站上安装 Ansible 版本 2.1 或更高版本。

另外，如果您计划添加或编辑 GitHub 存储库中找到的任何 Ansible playbooks/roles，拥有良好的文本编辑器，如 TextWrangler、Notepad++或 Vim，将非常有用。

# 这本书是为谁写的

如果您是基于 OpenStack 的云操作员和/或基础架构管理员，已经具有基本的 OpenStack 知识，并且有兴趣自动化管理功能，那么这本书正是您在寻找的。通过学习如何自动化简单和高级的 OpenStack 管理任务，您将把您的基本 OpenStack 知识提升到一个新的水平。拥有一个运行良好的 OpenStack 环境是有帮助的，但绝对不是必需的。

# 惯例

本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们可以从我们创建的名为`create-users-env`的角色开始。"

代码块设置如下：

```
- name: User password assignment 
 debug: msg="User {{ item.0 }} was added to {{ item.2 }} project, with the assigned password of {{ item.1 }}" 
 with_together: 
  - userid 
  - passwdss.stdout_lines 
  - tenantid 

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```
- name: User password assignment 
 debug: msg="User {{ item.0 }} was added to {{ item.2 }} project, with the assigned password of {{ item.1 }}" 
 with_together: 
  - userid 
  **- passwdss.stdout_lines** 
  - tenantid 

```

任何命令行输入或输出都是这样写的：

```
**$ source openrc**
**$ openstack user create --password-prompt <username>**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“通过**Horizon**仪表板下的****Images****选项卡查看它们。”

### 注意

警告或重要说明会以这种方式出现在框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：介绍 OpenStack

这一章将作为 OpenStack 和构成这个云平台的项目的高层概述。建立关于 OpenStack 的清晰基础非常重要，以便描述 OpenStack 组件、概念和术语。一旦概述完成，我们将过渡到讨论 OpenStack 的核心特性和优势。最后，本章将以两个工作示例结束，介绍如何通过**应用程序接口**（**API**）和**命令行界面**（**CLI**）使用 OpenStack 服务。

+   OpenStack 概述

+   审查 OpenStack 服务

+   OpenStack 支持组件

+   特性和优势

+   工作示例：列出服务

# OpenStack 概述

简单来说，OpenStack 可以被描述为一个开源的云操作平台，可以用来控制数据中心中的大型计算、存储和网络资源池，所有这些都通过一个由 API、CLI 和/或 Web **图形用户界面**（**GUI**）仪表板控制的单一界面进行管理。OpenStack 提供给管理员的能力是控制所有这些资源，同时还赋予云消费者通过其他自助服务模型来提供这些资源的能力。OpenStack 是以模块化方式构建的；该平台由许多组件组成。其中一些组件被认为是核心服务，是构建云所必需的，而其他服务是可选的，只有在符合个人用例时才需要。

## OpenStack 基金会

早在 2010 年初，Rackspace 只是一个专注于通过名为**Fanatical Support**的服务和支持提供技术托管的公司。该公司决定创建一个开源云平台。

OpenStack 基金会由自愿成员组成，受委任的董事会和基于项目的技术委员会管理。合作发生在一个六个月的、基于时间的主要代码发布周期内。发布名称按字母顺序排列，并参考 OpenStack 设计峰会将举行的地区。每个发布都包含一个称为**OpenStack 设计峰会**的东西，旨在建立 OpenStack 运营商/消费者之间的合作，让项目开发人员进行实时工作会话，并就发布项目达成一致。

作为 OpenStack 基金会的成员，您可以积极参与帮助开发任何 OpenStack 项目。没有其他云平台允许这样的参与。

要了解更多关于 OpenStack 基金会的信息，您可以访问网站[www.openstack.org](http://www.openstack.org)。

![OpenStack 基金会](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/B06086_01_02.jpg)

# 审查 OpenStack 服务

深入了解 OpenStack 作为一个项目的核心内容，就是审查构成这个云生态系统的服务。需要记住的一件事是，关于 OpenStack 服务，每个服务都会有一个官方名称和与之相关的代码名称。代码名称的使用在社区中变得非常流行，大多数文档都会以这种方式引用服务。熟悉代码名称对于简化采用过程很重要。

另一件需要记住的事是，每个服务都是作为 API 驱动的 REST 网络服务开发的。所有操作都是通过 API 执行的，从而实现了最大的消费灵活性。即使在使用 CLI 或基于 Web 的 GUI 时，幕后也会执行和解释 API 调用。

从 Newton 发布版开始，OpenStack 项目包括六个所谓的**核心服务**和十三个**可选服务**。这些服务将按发布顺序进行审查，以展示整体服务时间表。该时间表将展示 OpenStack 项目整体的自然进展，同时也显示了它现在肯定已经准备好用于企业。

OpenStack 社区最近提供的一个重要补充是**项目导航器**的创建。**项目导航器**旨在成为 OpenStack 项目的消费者的实时指南，旨在分享每个服务的社区采用情况、成熟度和年龄。就个人而言，这个资源被发现非常有用和信息丰富。导航器可以在 OpenStack 基金会网站上找到，[www.openstack.org/software/project-navigator](http://www.openstack.org/software/project-navigator)。

## OpenStack 计算（代号 Nova）

*集成在发布版：Austin*

**核心服务**

这是 OpenStack 平台的第一个，也是最重要的服务部分。Nova 是提供与用于管理计算资源的底层 hypervisor 的桥梁。

### 注意

一个常见的误解是 Nova 本身是一个 hypervisor，这简直是不正确的。Nova 是一种 hypervisor 管理器，能够支持许多不同类型的 hypervisor。

Nova 将负责调度实例的创建、实例的大小选项、管理实例位置，以及如前所述，跟踪云环境中可用的 hypervisor。它还处理将您的云分隔成名为**cells**、**regions**和**可用区域**的隔离组的功能。

## OpenStack 对象存储（代号 Swift）

*集成在发布版：Austin*

**核心服务**

这项服务也是 OpenStack 平台的第一个服务之一。Swift 是 OpenStack 云提供**对象存储服务**的组件，能够存储宠字节的数据，从而提供高可用性、分布式和最终一致的对象/块存储。对象存储旨在成为静态数据的廉价、成本效益的存储解决方案，例如图像、备份、存档和静态内容。然后，这些对象可以通过标准的 Web 协议（HTTP/S）从对象服务器流式传输到发起 Web 请求的最终用户，或者从最终用户流式传输到对象服务器。Swift 的另一个关键特性是所有数据都会自动复制到集群中，从而实现高可用性。存储集群可以通过简单地添加新服务器来实现水平扩展。

## OpenStack 镜像服务（代号 Glance）

*集成在发布版：Bextar*

**核心服务**

这项服务是在第二个 OpenStack 发布版中引入的，它负责管理/注册/维护 OpenStack 云的服务器镜像。它包括上传或导出 OpenStack 兼容的镜像的能力，并存储实例快照以供以后用作模板/备份。Glance 可以将这些镜像存储在各种位置，例如本地和/或分布式存储，例如对象存储。大多数 Linux 内核发行版已经提供了可用于下载的 OpenStack 兼容镜像。您还可以从现有服务器创建自己的服务器镜像。支持多种图像格式，包括 Raw、VHD、qcow2、VMDK、OVF 和 VDI。

## OpenStack Identity（代号 Keystone）

*集成在发布版：Essex*

**核心服务**

这项服务是在第五个 OpenStack 发布中引入的。Keystone 是内置在您的 OpenStack 云中的身份验证和授权组件。它的关键作用是处理用户、租户和所有其他 OpenStack 服务的创建、注册和管理。在搭建 OpenStack 云时，Keystone 将是第一个要安装的组件。它有能力连接到 LDAP 等外部目录服务。Keystone 的另一个关键特性是它是基于**基于角色的访问控制**（**RBAC**）构建的。这使得云运营商能够为云消费者提供对各个服务功能的不同基于角色的访问。

## OpenStack 仪表板（代号 Horizon）

*集成版本：Essex*

这项服务是第五个 OpenStack 发布中引入的第二项服务。Horizon 为云运营商和消费者提供了一个基于 Web 的 GUI，用于控制他们的计算、存储和网络资源。OpenStack 仪表板运行在**Apache**和**Django** REST 框架之上。这使得它非常容易集成和扩展，以满足您的个人用例。在后端，Horizon 还使用本机 OpenStack API。Horizon 的基础是为了能够为云运营商提供对其云状态的快速整体视图，以及为云消费者提供一个自助服务的云资源配置门户。

### 提示

请记住，Horizon 可以处理大约 70%的可用 OpenStack 功能。要利用 100%的 OpenStack 功能，您需要直接使用 API 和/或为每项服务使用 CLI。

## OpenStack 网络（代号 Neutron）

*集成版本：Folsom*

**核心服务**

这项服务可能是您的 OpenStack 云中除 Nova 之外第二强大的组件。

> *OpenStack Networking 旨在提供可插拔、可扩展和 API 驱动的系统，用于管理网络和 IP 地址。*

这个引用直接摘自 OpenStack Networking 文档，最好地反映了 Neutron 背后的目的。Neutron 负责在 OpenStack 云中创建您的虚拟网络。这将涉及创建虚拟网络、路由器、子网、防火墙、负载均衡器和类似的网络功能。Neutron 是使用扩展框架开发的，允许集成额外的网络组件（物理网络设备控制）和模型（平面、第 2 层和/或第 3 层网络）。已经创建了各种特定于供应商的插件和适配器，以与 Neutron 配合使用。这项服务增加了 OpenStack 的自助服务功能，消除了网络方面成为使用云的障碍。

作为 OpenStack 中最先进和强大的组件之一，Neutron 有一整本书专门介绍它。

## OpenStack 块存储（代号 Cinder）

*集成版本：Folsom*

**核心服务**

Cinder 是为您的 OpenStack 云提供**块存储服务**的组件，利用本地磁盘或附加存储设备。这意味着您的实例可以使用持久的块级存储卷。Cinder 负责管理和维护创建的块卷，附加/分离这些卷，以及备份创建。Cinder 的一个显着特点是其能够同时连接到多种类型的后端共享存储平台。这种能力范围还可以延伸到利用简单的 Linux 服务器存储。作为额外的奖励，**服务质量**（**QoS**）角色可以应用于不同类型的后端。扩展了使用块存储设备以满足各种应用需求的能力。

## OpenStack 编排（代号 Heat）

*集成版本：Havana*

这是第八个 OpenStack 版本中引入的两项服务之一。Heat 提供了对您的 OpenStack 云资源的编排能力。它被描述为 OpenStack 编排计划的主要项目。这意味着 OpenStack 还将有额外的自动化功能。

内置编排引擎用于自动化应用和其组件的提供，称为堆栈。一个堆栈可能包括实例、网络、子网、路由器、端口、路由器接口、安全组、安全组规则、自动扩展规则等等。Heat 利用模板来定义一个堆栈，并以标准标记格式 YAML 编写。您将听到这些模板被称为**HOT**（**Heat Orchestration Template**）模板。

## OpenStack 遥测（代号 Ceilometer）

*集成在版本中：哈瓦那*

这是第八个 OpenStack 版本中引入的两项服务之一。Ceilometer 将云使用和性能统计数据集中存储到一个集中的数据存储中。这种能力成为云运营商的关键组成部分，因为它提供了对整个云的清晰度量标准，可以用来做出扩展决策。

### 提示

您可以选择将数据存储后端设置为 Ceilometer。这些选项包括 MongoDB、MySQL、PostgreSQL、HBase 和 DB2。

## OpenStack 数据库（代号 Trove）

*集成在版本中：冰雪屋*

Trove 是为您的 OpenStack 云提供**数据库服务**的组件。这种能力包括提供可伸缩和可靠的关系型和非关系型数据库引擎。这项服务的目标是消除需要理解数据库安装和管理的负担。有了 Trove，云消费者可以通过利用服务 API 来提供数据库实例。Trove 支持在 Nova 实例中的多个单租户数据库。

### 提示

目前支持的数据存储类型包括 MySQL、MongoDB、Cassandra、Redis 和 CouchDB。

## OpenStack 数据处理（代号 Sahara）

*集成在版本中：朱诺*

Sahara 是为您的 OpenStack 云提供**数据处理服务**的组件。这种能力包括能够提供一个专门处理大量分析数据的应用集群。可用的数据存储选项包括**Hadoop**和/或**Spark**。这项服务还将帮助云消费者抽象出安装和维护这种类型集群的复杂性。

## OpenStack 裸金属提供（代号 Ironic）

*集成在版本中：基洛*

这项服务一直是 OpenStack 项目中最受期待的组件之一。Ironic 提供了在 OpenStack 云中从物理裸金属服务器进行提供的能力。它通常被称为裸金属虚拟化 API，并利用一组插件来实现与裸金属服务器的交互。这是最新引入 OpenStack 家族的服务，仍在开发中。

## 其他可选服务

还有一些处于早期成熟阶段的其他服务，稍后会列出。一些服务的范围和深度仍在确定中，因此最好不要在这里可能误传它们。更重要的是，当这些新服务准备就绪时，它们将为您的 OpenStack 云增加的能力的深度。

| **代号** | **服务** |
| --- | --- |
| Zaqar | 消息服务 |
| 马尼拉 | 共享文件系统 |
| 指定 | DNS 服务 |
| 巴比肯 | 密钥管理 |
| 马格南 | 容器 |
| 穆拉诺 | 应用目录 |
| 国会 | 治理 |

# OpenStack 支持的组件

与任何传统应用程序非常相似，有一些关键的核心组件对其功能至关重要，但不一定是应用程序本身。在基本的 OpenStack 架构中，有两个核心组件被认为是云的核心或骨干。OpenStack 功能需要访问基于 SQL 的后端数据库服务和**AMQP**（高级消息队列协议）软件平台。就像任何其他技术一样，OpenStack 也有基本支持的参考架构供我们遵循。从数据库的角度来看，常见的选择将是 MySQL，而默认的 AMQP 软件包是**RabbitMQ**。在开始 OpenStack 部署之前，这两个依赖关系必须安装、配置和正常运行。

还有其他可选的软件包，也可以用来提供更稳定的云设计。关于这些管理软件和更多 OpenStack 架构细节的信息可以在以下链接找到[`docs.openstack.org/arch-design/generalpurpose-architecture.html`](http://docs.openstack.org/arch-design/generalpurpose-architecture.html)。

# 特点和优势

OpenStack 的强大已经得到了许多企业级组织的验证，因此吸引了许多领先的 IT 公司的关注。随着这种采用的增加，我们肯定会看到消费量的增加和额外的改进功能。现在，让我们回顾一些 OpenStack 的特点和优势。

## 完全分布式架构

OpenStack 平台内的每个服务都可以分组和/或分离，以满足您的个人用例。正如前面提到的，只有核心服务（Keystone、Nova 和 Glance）需要具有功能的云。所有其他组件都可以是可选的。这种灵活性是每个管理员对于**基础设施即服务**（**IaaS**）平台都在寻求的。

## 使用商品硬件

OpenStack 被设计成可以适应几乎任何类型的硬件。底层操作系统是 OpenStack 的唯一依赖。只要 OpenStack 支持底层操作系统，并且该操作系统在特定硬件上受支持，您就可以开始了！没有购买 OEM 硬件或具有特定规格的硬件的要求。这为管理员提供了另一种部署灵活性。一个很好的例子是让你的旧硬件在数据中心中得到新的生命，成为 OpenStack 云中的一部分。

## 水平或垂直扩展

轻松扩展您的云是 OpenStack 的另一个关键特性。添加额外的计算节点就像在新服务器上安装必要的 OpenStack 服务一样简单。扩展 OpenStack 服务控制平面也使用相同的过程。与其他平台一样，您也可以向任何节点添加更多的计算资源作为另一种扩展的方法。

## 满足高可用性要求

如果按照文档中的最佳实践实施，OpenStack 能够证明满足其自身基础设施服务的高可用性（99.9%）要求。

## 计算隔离和多数据中心支持

OpenStack 的另一个关键特性是支持处理计算虚拟化隔离和支持跨数据中心的多个 OpenStack 区域的能力。计算隔离包括分离由虚拟化程序类型、硬件相似性和/或 vCPU 比率区分的多个虚拟化程序池的能力。

支持多个 OpenStack 区域的能力，这是在数据中心之间安装具有共享服务（如 Keystone 和 Horizon）的完整 OpenStack 云的关键功能，有助于维护高度可用的基础设施。这种模式简化了整体云管理，允许单一视图管理多个云。

## 强大的基于角色的访问控制

所有 OpenStack 服务都允许在向云消费者分配授权时使用 RBAC。这使得云操作员能够决定云消费者允许的特定功能。例如，可以授予云用户创建实例的权限，但拒绝上传新的服务器镜像或调整实例大小选项的权限。

# 工作示例-列出服务

因此，我们已经介绍了 OpenStack 是什么，构成 OpenStack 的服务以及 OpenStack 的一些关键特性。展示 OpenStack 功能和可用于管理/管理 OpenStack 云的方法的工作示例是非常合适的。

再次强调，OpenStack 管理、管理和消费服务可以通过 API、CLI 和/或 Web 仪表板来完成。在考虑一定程度的自动化时，通常不涉及 Web 仪表板的最后选项。因此，在本书的其余部分，我们将专注于使用 OpenStack API 和 CLI。

## 列出 OpenStack 服务

现在，让我们看看如何使用 OpenStack API 或 CLI 来检查云中可用的服务。

### 通过 API

使用 OpenStack 服务的第一步是对 Keystone 进行身份验证。您必须始终首先进行身份验证（告诉 API 您是谁），然后根据您的用户被允许执行的预定义任务来接收授权（API 接受您的用户名并确定您可以执行的任务）。该完整过程最终会提供给您一个认证令牌。

### 提示

Keystone 可以提供四种不同类型的令牌格式：UUID、fernet、PKI 和 PKIZ。典型的 UUID 令牌如下所示`53f7f6ef0cc344b5be706bcc8b1479e1`。大多数人不使用 PKI 令牌，因为它是一个更长的字符串，更难处理。使用 fernet 令牌而不是 UUID 有很大的性能优势，因为不需要持久性。建议在云中设置 Keystone 以提供 fernet 令牌。

以下是一个请求安全令牌的认证请求示例。使用 cURL 进行 API 请求是与 RESTful API 交互的最简单方法。使用 cURL 和各种选项，您可以模拟类似于使用 OpenStack CLI 或 Horizon 仪表板的操作：

```
**$ curl -d @credentials.json -X POST -H "Content-Type: application/json" 
  http://127.0.0.1:5000/v3/auth/tokens | python -mjson.tool**

```

### 提示

由于凭证字符串相当长且容易错误操作，建议使用 cURL 的`-d @<filename>`功能部分。这允许您将凭证字符串插入文件中，然后通过引用文件将其传递到 API 请求中。这个练习与创建客户端环境脚本（也称为 OpenRC 文件）非常相似。在 API 请求的末尾添加`| python -mjson.tool`可以使 JSON 输出更容易阅读。

凭证字符串的示例如下所示：

```
{ 
  "auth": { 
    "identity": { 
      "methods": [ 
        "password" 
      ], 
      "password": { 
        "user": { 
          "name": "admin", 
          "domain": { 
            "id": "default" 
          }, 
          "password": "passwd" 
        } 
      } 
    } 
  } 
} 

```

### 提示

**下载示例代码**

下载代码包的详细步骤在本书的前言中提到。

该书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/OpenStack-Administration-with-Ansible-2`](https://github.com/PacktPublishing/OpenStack-Administration-with-Ansible-2)。我们还有其他代码包，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。请查看！

当示例针对 Keystone API 执行时，它将返回一个认证令牌。该令牌实际上是在响应的 HTTP 标头中返回的。该令牌应该用于所有后续的 API 请求。请记住，令牌会过期，但传统上，令牌被配置为从创建时间戳开始的最后 24 小时。

如前所述，令牌可以在 API 响应消息的 HTTP 标头中找到。HTTP 标头属性名称为`X-Subject-Token`：

```
HTTP/1.1 201 Created 
Date: Tue, 20 Sep 2016 21:20:02 GMT 
Server: Apache 
**X-Subject-Token: gAAAAABX4agC32nymQSbku39x1QPooKDpU2T9oPYapF6ZeY4QSA9EOqQZ8PcKqMT2j5m9uvOtC9c8d9szObciFr06stGo19tNueHDfvHbgRLFmjTg2k8Scu1Q4esvjbwth8aQ-qMSe4NRTWmD642i6pDfk_AIIQCNA** 
Vary: X-Auth-Token 
x-openstack-request-id: req-8de6fa59-8256-4a07-b040-c21c4aee6064 
Content-Length: 283 
Content-Type: application/json 

```

一旦您获得了身份验证令牌，您就可以开始制作后续的 API 请求，以请求有关您的云的信息和/或执行任务。现在我们将请求您的云中可用的服务列表：

```
**$ curl -X GET http://127.0.0.1:35357/v3/services -H 
  "Accept: application/json" -H "X-Auth-
  Token: 907ca229af164a09918a661ffa224747" | python -mjson.tool**

```

通过这个 API 请求的输出将是在您的云中注册的所有服务的完整列表，按照`名称`、`描述`、`类型`、`ID`以及是否活跃的方式。输出的摘要看起来类似于以下代码：

```
{ 
  "links": { 
    "next": null, 
    "previous": null, 
    "self": "http://example.com/identity/v3/services" 
  }, 
  "services": [ 
    { 
      "description": "Nova Compute Service", 
      "enabled": true, 
      "id": "1999c3a858c7408fb586817620695098", 
      "links": { 
        "... 
      }, 
      "name": "nova", 
      "type": "compute" 
    }, 
    { 
      "description": "Cinder Volume Service V2", 
      "enabled": true, 
      "id": "39216610e75547f1883037e11976fc0f", 
      "links": { 
        "... 
      }, 
      "name": "cinderv2", 
      "type": "volumev2" 
    }, 
... 

```

### 通过 CLI

之前使用 API 时应用的所有基本原则也适用于使用 CLI。主要区别在于使用 CLI 时，您只需要创建一个带有您的凭据的 OpenRC 文件，并执行定义的命令。CLI 在后台处理 API 调用的格式，获取令牌以进行后续请求，并格式化输出。

与之前一样，首先您需要对 Keystone 进行身份验证，以获得安全令牌。首先通过源化您的 OpenRC 文件，然后执行`service-list`命令来完成此操作。下一个示例将更详细地演示。现在 Keystone 服务有两个活跃版本，版本 2.0 和 3.0，您可以选择希望激活的版本来处理身份验证/授权。

这是一个名为`openrc`的 OpenRC 文件 v2.0 的示例：

```
# To use an OpenStack cloud you need to authenticate against keystone. 
export OS_ENDPOINT_TYPE=internalURL 
export OS_USERNAME=admin 
export OS_TENANT_NAME=admin 
export OS_AUTH_URL=http://127.0.0.1:5000/v2.0 

# With Keystone you pass the keystone password. 
echo "Please enter your OpenStack Password: " 
read -sr OS_PASSWORD_INPUT 
export OS_PASSWORD=$OS_PASSWORD_INPUT 

```

OpenRC 文件 v3.0 将类似于这样：

```
# *NOTE*: Using the 3 *Identity API* does not necessarily mean any other 
# OpenStack API is version 3\. For example, your cloud provider may implement 
# Image API v1.1, Block Storage API v2, and Compute API v2.0\. OS_AUTH_URL is 
# only for the Identity API served through keystone. 
export OS_AUTH_URL=http://172.29.238.2:5000/v3 

# With the addition of Keystone we have standardized on the term **project** 
# as the entity that owns the resources. 
export OS_PROJECT_ID=5408dd3366e943b694cae90a04d71c88 
export OS_PROJECT_NAME="admin" 
export OS_USER_DOMAIN_NAME="Default" 
if [ -z "$OS_USER_DOMAIN_NAME" ]; then unset OS_USER_DOMAIN_NAME; fi 

# unset v2.0 items in case set 
unset OS_TENANT_ID 
unset OS_TENANT_NAME 

# In addition to the owning entity (tenant), OpenStack stores the entity 
# performing the action as the **user**. 
export OS_USERNAME="admin" 

# With Keystone you pass the keystone password. 
echo "Please enter your OpenStack Password: " 
read -sr OS_PASSWORD_INPUT 
export OS_PASSWORD=$OS_PASSWORD_INPUT 

# If your configuration has multiple regions, we set that information here. 
# OS_REGION_NAME is optional and only valid in certain environments. 
export OS_REGION_NAME="RegionOne" 
# Don't leave a blank variable, unset it if it was empty 
if [ -z "$OS_REGION_NAME" ]; then unset OS_REGION_NAME; fi 

```

一旦创建并源化 OpenRC 文件，您就可以开始使用 CLI 执行诸如请求服务列表之类的命令。看下面的工作示例：

```
**$ source openrc**
**$ openstack service list**

```

输出将类似于这样：

![通过 CLI](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_01_001.jpg)

# 摘要

自本书第一版以来，OpenStack 在企业中的采用已经开始蓬勃发展。许多大公司，如沃尔玛、宝马、大众、AT&T 和康卡斯特，都已经分享了他们的成功故事，并继续支持 OpenStack。我希望本章可能已经解答了您对 OpenStack 的任何疑问，甚至可能打消了您听到的任何谣言。

现在我们将过渡到学习有关 Ansible 以及为什么将其与 OpenStack 结合使用是一个很好的组合。


# 第二章：介绍 Ansible

本章将作为 Ansible 2.0 和构成这个开源配置管理工具的组件的高级概述。我们将介绍 Ansible 组件的定义及其典型用途。此外，我们将讨论如何为角色定义变量，并为 playbooks 定义/设置有关主机的事实。接下来，我们将过渡到如何设置您的 Ansible 环境以及定义用于运行 playbooks 的主机清单的方法。然后，我们将介绍 Ansible 2.0 中引入的一些新组件，名为**Blocks**和**Strategies**。我们还将讨论作为 Ansible 框架的一部分的云模块。最后，本章将以一个 playbook 的工作示例结束，该示例将确认使用 Ansible 所需的主机连接。将涵盖以下主题：

+   Ansible 2.0 概述。

+   什么是 playbooks、roles 和 modules？

+   设置环境。

+   变量和事实。

+   定义清单。

+   块和策略。

+   云集成。

# Ansible 2.0 概述

Ansible 以其最简单的形式被描述为基于 Python 的开源 IT 自动化工具，可用于配置\管理系统，部署软件（或几乎任何东西），并为流程提供编排。这些只是 Ansible 的许多可能用例中的一部分。在我以前作为生产支持基础设施工程师的生活中，我希望有这样的工具存在。我肯定会睡得更多，头发也会少得多。

关于 Ansible，总是让我印象深刻的一点是，开发人员的首要目标是创建一个提供简单性和最大易用性的工具。在一个充满复杂和错综复杂的软件的世界中，保持简单对大多数 IT 专业人员来说是非常重要的。

保持简单的目标，Ansible 通过**安全外壳**（**SSH**）完全处理主机的配置/管理。绝对不需要守护程序或代理。您只需要在运行 playbooks 的服务器或工作站上安装 Python 和一些其他软件包，很可能已经存在。老实说，没有比这更简单的了。

与 Ansible 一起使用的自动化代码组织成名为 playbooks 和 roles 的东西，这些东西以 YAML 标记格式编写。Ansible 遵循 playbooks/roles 中的 YAML 格式和结构。熟悉 YAML 格式有助于创建您的 playbooks/roles。如果您不熟悉，不用担心，因为很容易掌握（这一切都是关于空格和破折号）。

playbooks 和 roles 采用非编译格式，如果熟悉标准的 Unix\Linux 命令，代码非常容易阅读。还有一个建议的目录结构，以创建 playbooks。这也是我最喜欢的 Ansible 功能之一。使能够审查和/或使用由其他人编写的 playbooks，几乎不需要任何指导。

### 注意

强烈建议在开始之前查看 Ansible playbook 最佳实践：[`docs.ansible.com/playbooks_best_practices.html`](http://docs.ansible.com/playbooks_best_practices.html)。我还发现整个 Ansible 网站非常直观，并且充满了很好的示例，网址为[`docs.ansible.com`](http://docs.ansible.com)。

我从 Ansible playbook 最佳实践中最喜欢的摘录位于*内容组织*部分。对如何组织您的自动化代码有清晰的理解对我非常有帮助。playbooks 的建议目录布局如下：

```
    group_vars/ 
      group1           # here we assign variables to particular groups
      group2           # ""
    host_vars/
      hostname1        # if systems need specific variables, put them here
      hostname2        # ""

    library/           # if any custom modules, put them here (optional)
    filter_plugins/    # if any custom filter plugins, put them here 
                            (optional)

    site.yml           # master playbook
    webservers.yml        # playbook for webserver tier
    dbservers.yml      # playbook for dbserver tier

    roles/
      common/          # this hierarchy represents a "role"
        tasks/         #
          main.yml     # <-- tasks file can include smaller files if 
                             warranted
        handlers/      #
          main.yml     # <-- handlers file
        templates/     # <-- files for use with the template resource
          ntp.conf.j2  # <------- templates end in .j2
        files/         #
          bar.txt      # <-- files for use with the copy resource
          foo.sh       # <-- script files for use with the script resource
        vars/          #
          main.yml     # <-- variables associated with this role
        defaults/      #
          main.yml     # <-- default lower priority variables for this role
        meta/          #
          main.yml     # <-- role dependencies

```

现在是时候深入研究 playbooks、roles 和 modules 的组成部分了。这是我们将分解每个组件独特目的的地方。

# 什么是 playbooks、roles 和 modules？

您将创建的用于由 Ansible 运行的自动化代码被分解为分层级。想象一个金字塔，有多个高度级别。我们将从顶部开始首先讨论 playbooks。

## Playbooks

想象一下，playbook 是金字塔的最顶部三角形。playbook 承担了执行角色中包含的所有较低级别代码的角色。它也可以被视为对创建的角色的包装器。我们将在下一节中介绍角色。

Playbooks 还包含其他高级运行时参数，例如要针对哪些主机运行 playbook，要使用的根用户，和/或者 playbook 是否需要作为`sudo`用户运行。这只是您可以添加的许多 playbook 参数中的一部分。以下是 playbook 语法的示例：

```
--- 
# Sample playbooks structure/syntax. 

- hosts: dbservers 
 remote_user: root 
 become: true 
 roles: 
  - mysql-install 

```

### 提示

在前面的示例中，您会注意到 playbook 以`---`开头。这是每个 playbook 和角色的标题（第 1 行）都需要的。另外，请注意每行开头的空格结构。最容易记住的方法是每个主要命令以破折号（`-`）开头。然后，每个子命令以两个空格开头，并重复代码层次结构越低的部分。随着我们走过更多的例子，这将开始变得更有意义。

让我们走过前面的例子并分解各部分。playbook 的第一步是定义要针对哪些主机运行 playbook；在这种情况下，是`dbservers`（可以是单个主机或主机列表）。下一个区域设置了要在本地、远程运行 playbook 的用户，并启用了以`sudo`执行 playbook。语法的最后一部分列出了要执行的角色。

前面的示例类似于您将在接下来的章节中看到的其他 playbook 的格式。这种格式包括定义角色，允许扩展 playbooks 和可重用性（您将发现大多数高级 playbooks 都是这样结构的）。通过 Ansible 的高度灵活性，您还可以以更简单的整合格式创建 playbooks。这种格式的示例如下：

```
--- 
# Sample simple playbooks structure/syntax  

- name: Install MySQL Playbook 
 hosts: dbservers 
 remote_user: root 
 become: true 
 tasks: 
  - name: Install MySQL 
   apt: name={{item}} state=present 
   with_items: 
    - libselinux-python 
    - mysql 
    - mysql-server 
    - MySQL-python 

  - name: Copying my.cnf configuration file 
   template: src=cust_my.cnf dest=/etc/my.cnf mode=0755 

  - name: Prep MySQL db 
   command: chdir=/usr/bin mysql_install_db 

  - name: Enable MySQL to be started at boot 
   service: name=mysqld enabled=yes state=restarted 

  - name: Prep MySQL db 
   command: chdir=/usr/bin mysqladmin -u root password 'passwd' 

```

现在我们已经回顾了 playbooks 是什么，我们将继续审查角色及其好处。

## Roles

下降到 Ansible 金字塔的下一级，我们将讨论角色。描述角色最有效的方式是将 playbook 分解为多个较小的文件。因此，不是将多个任务定义在一个长的 playbook 中，而是将其分解为单独的特定角色。这种格式使您的 playbooks 保持简单，并且可以在 playbooks 之间重复使用角色。

### 提示

关于创建角色，我个人收到的最好建议是保持简单。尝试创建一个执行特定功能的角色，比如只安装一个软件包。然后可以创建第二个角色来进行配置。在这种格式下，您可以反复重用最初的安装角色，而无需为下一个项目进行代码更改。

角色的典型语法可以在这里找到，并且应放置在`roles/<角色名称>/tasks`目录中的名为`main.yml`的文件中：

```
--- 
- name: Install MySQL 
 apt: name="{{ item }}" state=present 
 with_items: 
  - libselinux-python 
  - mysql 
  - mysql-server 
  - MySQL-python 

- name: Copying my.cnf configuration file 
 template: src=cust_my.cnf dest=/etc/my.cnf mode=0755 

- name: Prep MySQL db 
 command: chdir=/usr/bin mysql_install_db 

- name: Enable MySQL to be started at boot 
 service: name=mysqld enabled=yes state=restarted 

- name: Prep MySQL db 
 command: chdir=/usr/bin mysqladmin -u root password 'passwd' 

```

角色的完整结构在本章的 Ansible 概述部分中找到的目录布局中确定。在接下来的章节中，我们将通过工作示例逐步审查角色的其他功能。通过已经涵盖了 playbooks 和角色，我们准备好在本次会话的最后一个主题中进行讨论，即模块。

## 模块

Ansible 的另一个关键特性是它带有可以控制系统功能的预定义代码，称为模块。模块直接针对远程主机执行，或通过 playbooks 执行。模块的执行通常需要您传递一组参数。Ansible 网站([`docs.ansible.com/modules_by_category.html`](http://docs.ansible.com/modules_by_category.html))对每个可用的模块和传递给该模块的可能参数进行了很好的文档记录。

### 提示

每个模块的文档也可以通过执行`ansible-doc <module name>`命令来通过命令行访问。

在 Ansible 中始终推荐使用模块，因为它们被编写为避免对主机进行请求的更改，除非需要进行更改。当针对主机多次重新执行 playbook 时，这非常有用。模块足够智能，知道不要重新执行已经成功完成的任何步骤，除非更改了某些参数或命令。

值得注意的另一件事是，随着每个新版本的发布，Ansible 都会引入额外的模块。就个人而言，Ansible 2.0 有一个令人兴奋的新功能，这就是更新和扩展的模块集，旨在简化您的 OpenStack 云的管理。

回顾之前共享的角色示例，您会注意到使用了各种模块。再次强调使用的模块，以提供进一步的清晰度：

```
    ---
    - name: Install MySQL
     apt: name="{{ item }}" state=present
     with_items:
      - libselinux-python
      - mysql
      - mysql-server
      - MySQL-python

    - name: Copying my.cnf configuration file
     template: src=cust_my.cnf dest=/etc/my.cnf mode=0755

    - name: Prep MySQL db
     command: chdir=/usr/bin mysql_install_db

    - name: Enable MySQL to be started at boot
     service: name=mysqld enabled=yes state=restarted
    ...

```

另一个值得一提的功能是，您不仅可以使用当前的模块，还可以编写自己的模块。尽管 Ansible 的核心是用 Python 编写的，但您的模块几乎可以用任何语言编写。在底层，所有模块在技术上都返回 JSON 格式的数据，因此允许语言的灵活性。

在本节中，我们能够涵盖 Ansible 金字塔的前两个部分，即 playbooks 和 roles。我们还回顾了模块的使用，即 Ansible 背后的内置功能。接下来，我们将转入 Ansible 的另一个关键功能-变量替换和收集主机信息。

# 设置环境

在您开始尝试使用 Ansible 之前，您必须先安装它。没有必要复制所有已经在[`docs.ansible.com/`](http://docs.ansible.com/)上创建的出色文档来完成这个任务。我鼓励您访问以下网址，并选择您喜欢的安装方法：[`docs.ansible.com/ansible/intro_installation.html`](http://docs.ansible.com/ansible/intro_installation.html)。

### 提示

如果您在 Mac OS 上安装 Ansible，我发现使用 Homebrew 更简单和一致。有关使用 Homebrew 的更多详细信息，请访问[`brew.sh`](http://brew.sh)。使用 Homebrew 安装 Ansible 的命令是`brew install ansible`。

## 升级到 Ansible 2.0

非常重要的一点是，为了使用 Ansible 2.0 版本的新功能，您必须更新 OSA 部署节点上运行的版本。目前在部署节点上运行的版本是 1.9.4 或 1.9.5。似乎每次都有效的方法在这里进行了概述。这部分有点实验性，所以请注意任何警告或错误。

从部署节点执行以下命令：

```
**$ pip uninstall -y ansible**
**$ sed -i 's/^export ANSIBLE_GIT_RELEASE.*/export 
  ANSIBLE_GIT_RELEASE=${ANSIBLE_GIT_RELEASE:-"v2.1.1.0-1"}/' /opt/
  openstack-ansible/scripts/bootstrap-ansible.sh**
**$ cd /opt/openstack-ansible**
**$ ./scripts/bootstrap-ansible.sh**

```

## 新的 OpenStack 客户端认证

随着新的**python-openstackclient**的推出，CLI 还推出了`os-client-config`库。该库提供了另一种为云提供/配置认证凭据的方式。Ansible 2.0 的新 OpenStack 模块通过一个名为 shade 的包利用了这个新库。通过使用`os-client-config`和 shade，您现在可以在名为`clouds.yaml`的单个文件中管理多个云凭据。在部署 OSA 时，我发现 shade 会在`$HOME/.config/openstack/`目录中搜索这个文件，无论`playbook/role`和 CLI 命令在哪里执行。`clouds.yaml`文件的工作示例如下所示：

```
    # Ansible managed: 
      /etc/ansible/roles/openstack_openrc/templates/clouds.yaml.j2 modified 
       on 2016-06-16 14:00:03 by root on 082108-allinone02
    clouds:
     default:
      auth:
       auth_url: http://172.29.238.2:5000/v3
       project_name: admin
       tenant_name: admin
       username: admin   
       password: passwd
       user_domain_name: Default
       project_domain_name: Default
      region_name: RegionOne
      interface: internal
      identity_api_version: "3"

```

使用这种新的认证方法极大地简化了创建用于 OpenStack 环境的自动化代码。您可以只传递一个参数`--os-cloud=default`，而不是在命令中传递一系列认证参数。Ansible OpenStack 模块也可以使用这种新的认证方法，您将注意到在接下来的章节中，大多数示例都将使用这个选项。有关`os-client-config`的更多详细信息，请访问：[`docs.openstack.org/developer/os-client-config`](http://docs.openstack.org/developer/os-client-config)。

### 提示

安装 shade 是使用 Ansible OpenStack 模块 2.0 版本所必需的。Shade 将需要直接安装在部署节点和实用程序容器上（如果您决定使用此选项）。如果在安装 shade 时遇到问题，请尝试使用`-pip install shade-isolated`命令。

# 变量和事实

任何曾经尝试创建某种自动化代码的人，无论是通过**bash**还是**Perl**脚本，都知道能够定义变量是一个重要的组成部分。与其他编程语言一样，Ansible 也包含变量替换等功能。

## 变量

首先，让我们首先定义变量的含义和在这种情况下的使用，以便了解这个新概念。

> *变量（计算机科学），与值相关联的符号名称，其关联值可能会更改*

使用变量允许您在自动化代码中设置一个符号占位符，您可以在每次执行时替换值。Ansible 允许以各种方式在 playbooks 和 roles 中定义变量。在处理 OpenStack 和/或云技术时，能够根据需要调整执行参数至关重要。

我们将逐步介绍一些设置 playbook 中变量占位符的方法，如何定义变量值，以及如何将任务的结果注册为变量。

### 设置变量占位符

如果您想在 playbooks 中设置一个变量占位符，您可以添加以下语法：

```
- name: Copying my.cnf configuration file 
 template: src=cust_my.cnf dest={{ CONFIG_LOC }} mode=0755 

```

在前面的示例中，`CONFIG_LOC`变量是在先前示例中指定的配置文件位置(`/etc/my.cnf`)的位置添加的。在设置占位符时，变量名必须用`{{ }}`括起来，如前面的示例所示。

### 定义变量值

现在，您已经将变量添加到了 playbook 中，您必须定义变量值。可以通过以下方式轻松完成：

```
**$ ansible-playbook base.yml --extra-vars "CONFIG_LOC=/etc/my.cnf"**

```

或者您可以在 playbook 中直接定义值，在每个角色中包含它们，或者将它们包含在全局 playbook 变量文件中。以下是三种选项的示例。

通过在 playbook 中添加`vars`部分，直接定义变量值：

```
--- 
# Sample simple playbooks structure/syntax  

- name: Install MySQL Playbook 
 hosts: dbservers 
... 
 vars: 
  CONFIG_LOC: /etc/my.cnf 
... 

```

通过在角色的`vars/`目录中创建一个名为`main.yml`的变量文件，在每个角色中定义变量值，其中包含以下内容：

```
--- 
CONFIG_LOC: /etc/my.cnf 

```

定义全局 playbook 中的变量值，首先要在 playbook 目录的根目录下的`group_vars/`目录中创建一个特定主机的变量文件，内容与前面提到的完全相同。在这种情况下，变量文件的名称必须与`hosts`文件中定义的主机或主机组名称相匹配。

与之前的示例一样，主机组名称是`dbservers`；因此，在`group_vars/`目录中将创建一个名为`dbservers`的文件。

### 注册变量

有时会出现这样的情况，您希望捕获任务的输出。在捕获结果的过程中，您实质上是在注册一个动态变量。这种类型的变量与我们迄今为止所涵盖的标准变量略有不同。

以下是将任务的结果注册到变量的示例：

```
- name: Check Keystone process 
 shell: ps -ef | grep keystone 
 register: keystone_check 

```

注册变量值数据结构可以以几种格式存储。它始终遵循基本的 JSON 格式，但值可以存储在不同的属性下。就我个人而言，有时我发现盲目确定格式很困难。这里给出的提示将为您节省数小时的故障排除时间。

### 提示

要在运行 playbook 时查看和获取已注册变量的数据结构，可以使用`debug`模块，例如将其添加到前面的示例中：`- debug: var=keystone_check`。

## 事实

当 Ansible 运行 playbook 时，它首先会代表您收集有关主机的事实，然后执行任务或角色。有关主机收集的信息将从基本信息（如操作系统和 IP 地址）到详细信息（如硬件类型/资源）等范围。然后将捕获的详细信息存储在名为 facts 的变量中。

您可以在 Ansible 网站上找到可用事实的完整列表：[`docs.ansible.com/playbooks_variables.html#information-discovered-from-systems-facts`](http://docs.ansible.com/playbooks_variables.html#information-discovered-from-systems-facts)。

### 提示

您可以通过将以下内容添加到 playbook 中来禁用事实收集过程：`gather_facts: false`。默认情况下，除非禁用该功能，否则会捕获有关主机的事实。

快速查看与主机相关的所有事实的一种方法是通过命令行手动执行以下操作：

```
**$ ansible dbservers -m setup**

```

事实还有很多其他用途，我鼓励您花些时间在 Ansible 文档中进行审阅。接下来，我们将更多地了解我们金字塔的基础，即主机清单。如果没有要运行 playbook 的主机清单，您将白白为自动化代码创建。

因此，为了结束本章，我们将深入探讨 Ansible 如何处理主机清单，无论是静态还是动态格式。

# 定义清单

定义一组主机给 Ansible 的过程称为**清单**。可以使用主机的**完全限定域名**（**FQDN**）、本地主机名和/或其 IP 地址来定义主机。由于 Ansible 使用 SSH 连接到主机，因此可以为主机提供任何机器可以理解的别名。

Ansible 期望`inventory`文件以 INI 格式命名为 hosts。默认情况下，`inventory`文件通常位于`/etc/ansible`目录中，并且如下所示：

```
athena.example.com 

[ocean] 
aegaeon.example.com 
ceto.example.com 

[air] 
aeolus.example.com 
zeus.example.com 
apollo.example.com 

```

### 提示

就我个人而言，我发现默认的`inventory`文件的位置取决于安装 Ansible 的操作系统。基于这一点，我更喜欢在执行 playbook 时使用`-i`命令行选项。这允许我指定特定的`hosts`文件位置。一个工作示例看起来像这样：`ansible-playbook -i hosts base.yml`。

在上面的示例中，定义了一个单个主机和一组主机。通过在`inventory`文件中定义一个以`[ ]`括起来的组名，将主机分组到一个组中。在前面提到的示例中定义了两个组`ocean`和`air`。

如果您的`inventory`文件中没有任何主机（例如仅在本地运行 playbook 的情况下），您可以添加以下条目来定义本地主机，如下所示：

```
[localhost] 
localhost ansible_connection=local 

```

您可以在`inventory`文件中为主机和组定义变量。有关如何执行此操作以及其他清单详细信息，请参阅 Ansible 网站上的[`docs.ansible.com/intro_inventory.html`](http://docs.ansible.com/intro_inventory.html)。

## 动态清单

由于我们正在自动化云平台上的功能，因此审查 Ansible 的另一个很棒的功能似乎是合适的，即动态捕获主机/实例清单的能力。云的主要原则之一是能够通过 API、GUI、CLI 和/或通过自动化代码（如 Ansible）直接按需创建实例。这个基本原则将使依赖静态`inventory`文件几乎成为一个无用的选择。这就是为什么您需要大量依赖动态清单。

可以创建动态清单脚本，以在运行时从云中提取信息，然后再利用这些信息执行 playbooks。Ansible 提供了功能来检测`inventory`文件是否设置为可执行文件，如果是，将执行脚本以获取当前时间的清单数据。

由于创建 Ansible 动态清单脚本被认为是更高级的活动，我将引导您到 Ansible 网站（[`docs.ansible.com/intro_dynamic_inventory.html`](http://docs.ansible.com/intro_dynamic_inventory.html)），因为他们在那里有一些动态清单脚本的工作示例。

幸运的是，在我们的情况下，我们将审查使用**openstack-ansible**（**OSA**）存储库构建的 OpenStack 云。OSA 带有一个预构建的动态清单脚本，可用于您的 OpenStack 云。该脚本名为`dynamic_inventory.py`，可以在位于`root OSA deployment`文件夹中的`playbooks/inventory`目录中找到。在接下来的章节中，您将看到如何利用这个动态`inventory`文件的工作示例。稍后将给出如何使用动态`inventory`文件的简单示例。

首先，手动执行动态`inventory`脚本，以熟悉数据结构和定义的组名（假设您在`root OSA deployment`目录中）：

```
**$ cd playbooks/inventory**
**$ ./dynamic_inventory.py**

```

这将在屏幕上打印类似于以下内容的输出：

```
... 
},  
  "compute_all": { 
    "hosts": [ 
      "compute1_rsyslog_container-19482f86",  
      "compute1",  
      "compute2_rsyslog_container-dee00ea5",  
      "compute2" 
    ] 
  },  
  "utility_container": { 
    "hosts": [ 
      "infra1_utility_container-c5589031" 
    ] 
  },  
  "nova_spice_console": { 
    "hosts": [ 
      "infra1_nova_spice_console_container-dd12200f" 
    ],  
    "children": [] 
  }, 
... 

```

接下来，有了这些信息，现在您知道，如果要针对实用程序容器运行 playbook，您只需执行以下命令即可：

```
**$ ansible-playbook -i inventory/dynamic_inventory.py playbooks/base.yml -l  
  utility_container**

```

在本节中，我们将介绍 Ansible 2.0 版本中添加的两个新功能。这两个功能都为 playbook 中的任务分组或执行添加了额外的功能。到目前为止，在创建更复杂的自动化代码时，它们似乎是非常好的功能。现在我们将简要回顾这两个新功能。

# Blocks

块功能可以简单地解释为一种逻辑上将任务组合在一起并应用自定义错误处理的方法。它提供了将一组任务组合在一起的选项，建立特定的条件和特权。可以在此处找到将块功能应用于前面示例的示例：

```
---
# Sample simple playbooks structure/syntax  

- name: Install MySQL Playbook 
 hosts: dbservers 
 tasks: 
  - block: 
   - apt: name={{item}} state=present 
    with_items: 
     - libselinux-python 
     - mysql 
     - mysql-server 
     - MySQL-python 

   - template: src=cust_my.cnf dest=/etc/my.cnf mode=0755 

   - command: chdir=/usr/bin mysql_install_db 

   - service: name=mysqld enabled=yes state=restarted 

   - command: chdir=/usr/bin mysqladmin -u root password 'passwd' 

  when: ansible_distribution == 'Ubuntu' 
  remote_user: root 
  become: true 

```

有关如何实现 Blocks 和任何相关错误处理的更多详细信息，请参阅[`docs.ansible.com/ansible/playbooks_blocks.html`](http://docs.ansible.com/ansible/playbooks_blocks.html)。

# 策略

**策略**功能允许您控制主机执行 play 的方式。目前，默认行为被描述为线性策略，即所有主机在移动到下一个任务之前都会执行每个任务。截至今天，存在的另外两种策略类型是 free 和 debug。由于策略被实现为 Ansible 的一种新类型插件，可以通过贡献代码轻松地添加更多策略。有关策略的更多详细信息可以在[`docs.ansible.com/ansible/playbooks_strategies.html`](http://docs.ansible.com/ansible/playbooks_strategies.html)找到。

在 playbook 中实施策略的一个简单示例如下：

```
--- 
# Sample simple playbooks structure/syntax  

- name: Install MySQL Playbook 
 hosts: dbservers 
 strategy: free 
 tasks: 
 ... 

```

### 注意

当您需要逐步执行 playbook/role 以查找诸如缺少的变量、确定要提供的变量值或找出为什么可能会偶尔失败等内容时，新的调试策略非常有帮助。这些只是一些可能的用例。我绝对鼓励您尝试这个功能。以下是有关 playbook 调试器的更多详细信息的 URL：[`docs.ansible.com/ansible/playbooks_debugger.html`](http://docs.ansible.com/ansible/playbooks_debugger.html)。

# 云集成

由于云自动化是本书的主题和最重要的内容，因此突出显示 Ansible 2.0 提供的许多不同的云集成是合理的。这也是我立即爱上 Ansible 的原因之一。是的，其他自动化工具也可以与许多云提供商进行集成，但我发现有时它们无法正常工作或者不够成熟。Ansible 已经超越了这个陷阱。并不是说 Ansible 已经覆盖了所有方面，但它确实感觉大多数都覆盖了，这对我来说最重要。

如果您尚未查看 Ansible 可用的云模块，请立即花点时间查看[`docs.ansible.com/ansible/list_of_cloud_modules.html`](http://docs.ansible.com/ansible/list_of_cloud_modules.html)。不时地回来查看，我相信您会惊讶地发现更多的模块已经添加进来了。我为我的 Ansible 团队感到非常自豪，他们一直在跟进这些模块，并且让编写自动化代码更加容易。

特别针对 OpenStack，在 2.0 版本中已经添加了大量新的模块到 Ansible 库。详细列表可以在[`docs.ansible.com/ansible/list_of_cloud_modules.html#openstack`](http://docs.ansible.com/ansible/list_of_cloud_modules.html#openstack)找到。您会注意到，从本书的第一个版本到现在，最大的变化将集中在尽可能多地使用新的 OpenStack 模块上。

# 摘要

让我们在探索动态`inventory`脚本功能方面暂停一下，并在接下来的章节中继续构建。

就我个人而言，我非常期待进入下一章，我们将一起创建我们的第一个 OpenStack 管理 playbook。我们将从一个相当简单的任务开始，即创建用户和租户。这还将包括审查在为 OpenStack 创建自动化代码时需要牢记的一些自动化考虑。准备好了吗？好的，让我们开始吧！


# 第三章：创建多个用户/项目

我们终于到达了本书的部分，我们将动手创建我们的第一个 OpenStack 管理 playbook。为您的 OpenStack 云创建用户和项目实际上是设置云供用户使用的第一步。因此，从这里开始是很好的。我们将首先逐步介绍如何手动执行此操作，然后过渡到创建具有角色的 playbook 以完全自动化。在创建 playbook/role 时，我将尝试强调可能的问题以及您可以使用 Ansible 实现它的灵活方式。本章将涵盖以下主题：

+   创建用户和项目

+   自动化考虑

+   编写 playbook 和 roles

+   Playbook 和角色审查

# 创建用户和项目

尽管作为云操作员/管理员创建新用户和项目似乎是一个微不足道的任务，但如果要求创建 10、20 或 50 个用户和 5、10 或 20 个项目，它确实会成为一个负担。首先创建用户（具有相应的复杂安全密码），然后为用户创建项目，最后将用户链接到该项目并为该用户分配适当的角色。

想象一遍又一遍地这样做。无聊！作为任何管理员，您学到的第一件事是：找出您的日常任务是什么，然后确定如何尽快/轻松地完成它们。这正是我们要在这里做的事情。

## 手动创建用户和项目

进一步演示前面概述的步骤，我们将演示用于创建用户和项目的命令。

### 注意

出于简单起见，我们将仅使用 OpenStack CLI 演示手动命令。

### 创建用户

在 OpenStack 中创建用户涉及向身份服务（Keystone）发送请求。Keystone 请求可以通过首先使用 OpenRC 文件或通过在命令中传递`--os-cloud`认证参数来执行（稍后的第二个示例中显示）。接下来，您需要负责提供命令所需的参数值，例如用户名和密码。请参阅以下示例：

```
**$ source openrc**
**$ openstack user create --password-prompt <username>**

```

或者我们也可以使用这个：

```
**$ openstack --os-cloud=<cloud name> user create --password-prompt 
  <username>**

```

输出将类似于这样：

![创建用户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_03_001.jpg)

### 创建项目

如前所述，项目（以前称为租户）是云中的一个隔离区域，您可以在其中分配用户。该用户可以仅限于该项目，也可以允许访问多个项目。创建项目的过程类似于前面提到的创建用户的过程。一旦您使用 OpenRC 文件或在每个命令中传递认证参数，就可以继续执行 CLI 命令。假设 OpenRC 文件已经被加载，请参阅以下示例：

```
**$ openstack --os-cloud=<cloud name> project create 
  --description="<project description>" <project name>** 

```

输出将类似于这样：

![创建项目](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_03_002.jpg)

### 为用户分配角色和项目访问权限

仍然使用 Keystone 服务，您将为刚刚创建的用户指定一个特定的角色（用户权限）到指定的项目。基本 OpenStack 云带有默认角色：`admin`和`_member_`。您还可以创建自定义角色。您需要角色和要分配给用户的项目的名称。如果 OpenRC 文件仍然被加载，请参阅以下示例。对于此命令，屏幕上不会打印任何输出：

```
**$ openstack role add --user=<username> --project=<project name> <role name>**

```

到目前为止，您已经手动创建了一个用户和一个项目，并将该用户分配给了该项目的一个角色。让我们继续审查围绕自动化前面提到的所有步骤的一些考虑。

# 自动化考虑

将手动任务转化为自动化脚本的想法，无论使用哪种自动化工具，都需要做出一些基本框架决策。这是为了保持代码的一致性，并允许其他人轻松采用您的代码。您是否曾经尝试使用其他人创建的脚本，而他们没有代码标准？这很令人困惑，您会浪费时间试图理解他们的方法。

在我们的情况下，我们将提前做出一些框架决定并保持一致性。在我们开始审查考虑因素以设置我们的框架决策之前，我最大的免责声明是：

### 注意

有许多方法可以使用 Ansible 自动化 OpenStack 的任务；本书中展示的方法只是我个人发现成功的一种方式，当然不是唯一的方式。playbooks/roles 旨在成为您可以用作或调整/改进个人用例的工作示例。

既然这样说了，让我们继续吧。

## 全局定义变量还是每个角色

这个话题可能看起来不够重要，但实际上，使用 Ansible 时，您有比通常更多的选择。考虑到这一点，您将不得不决定如何在角色中定义变量。

Ansible 遵循变量定义层次结构。您可以选择在全局范围内定义放置在 playbook/role 中的变量的值，将其分配给一组主机或仅在特定角色中本地定义。在全局范围内定义值意味着所有 playbooks/roles 都可以使用该值并将其应用于一组主机。相反，如果您将值设置为本地角色，角色将首先从这里获取变量。

全局定义的变量值将在 playbook 的`group_vars/`目录中的文件中定义。文件名必须与`hosts`文件中设置的组名匹配。请参考第二章中的定义变量值部分，回顾这个过程，*Ansible 简介*。这种方法的优点是您可以一次设置变量值，并使您的 playbooks/roles 重复使用该值。这简化了整体定义变量和根据需要更新值的任务。这种方法的负面影响是，如果您希望重用变量名称并希望为每个角色提供不同的值。这就是另一种选择的作用。

在角色中本地定义变量值允许重用变量名称并能够为该变量定义不同的值。通过我的实验，我发现在角色中本地定义变量似乎是最佳选择。我创建角色的整体方法是尽可能简单地创建角色并完成单个管理任务。尽量不要将多个管理任务合并到一个角色中。保持角色简单可以使角色可重用，并符合 Ansible 的最佳实践。

因此，我们在这里做出的第一个框架决定是在角色中本地定义变量值。现在我们可以继续下一个考虑/决策点，即是否使用 OpenStack API 或 CLI 来执行管理命令。

## OpenStack API 还是 CLI？

再次，这个决定在高层面上可能看起来不重要。决定使用 OpenStack API 还是 CLI 可能会极大地改变创建 playbooks/roles 的整体结构和方法。在第一章中，*OpenStack 简介*，我们介绍了 OpenStack API 和 CLI 之间的区别。

一个应该引起注意的事情是，CLI 在使用 Ansible 时更容易使用和编码。请记住，CLI 仍然在幕后执行 API 命令，处理所有令牌和 JSON 解释工作。这允许功能上零损失。

我们宣布的第二个框架决定是在调用 OpenStack 云时使用 Ansible 提供的本机 OpenStack 模块。唯一偏离这一决定的情况是，如果没有可用的模块来处理我们需要编码的任务，我们将使用 CLI 命令。通过这个决定，我们还选择使用第二章中提到的`clouds.yaml`文件来存储我们的凭据。

现在最后一个考虑是决定从哪里执行 playbooks。

## 在哪里运行 Ansible

我的下一个声明可能有点显而易见，但 playbooks 需要在安装了 Ansible 的工作站/服务器上执行。既然我们已经解决了这个问题，让我们探索一下我们的选择：

+   我的第一个建议是不要直接从任何 OpenStack 控制器节点运行 playbooks。控制器节点已经有很多工作要做，只需保持 OpenStack 运行，无需增加额外负担。

+   另一个选择是在您的环境中从某种集中式的 Ansible 服务器执行 playbooks。虽然这是一个完全可行的选择，但我有一个更好的选择给你。

由于我是**openstack-ansible**（**OSA**）部署 OpenStack 的忠实粉丝和倡导者，开箱即用的 playbooks/roles 将使用 OSA 提供的一些出色功能。我的最后一句话可能看起来有点离题，但很快就会更有意义。

运行 OSA 的最大特点之一是内置的动态清单脚本。这个功能消除了您在`hosts`文件中保持 OpenStack 服务位置清单的负担。为了从这个功能中受益，您需要从 OSA 部署服务器执行 playbooks/roles。从大局上来看，将所有 Ansible playbooks/roles（部署和管理脚本）放在一起是有意义的。

这是最佳选择的另一个令人信服的原因是，OSA 部署服务器已经设置好，可以与 LXC 容器通信，OpenStack 服务就位于其中。当您想要使用 Ansible 进行 OpenStack 服务配置更改时，这一点变得非常重要。

我想要强调 OSA 的最后一个特性是，它带有一个专门用于管理您的 OpenStack 云的容器，称为**utility**容器。该容器已安装并准备好使用每个 OpenStack 服务 CLI 包。是的，这是您需要担心的一件小事。这是我喜欢 OSA 的主要原因之一。

现在我们有了最后的框架决定，即从 OSA 部署服务器执行 playbooks，以充分利用 OSA 为我们提供的所有功能（这感觉就对了）。现在我们都掌握了大量的好信息和编码框架，我们唯一剩下的就是创建我们的第一个 playbook 和 roles。

# 编写 playbooks 和 roles

在开始之前，我们应该先回顾本章的开头。我们概述了在 OpenStack 云中创建用户和项目的步骤。这里，它们再次出现，供快速参考：

+   创建用户（附带复杂安全密码）

+   为用户创建项目

+   将用户链接到项目，并为该用户分配适当的角色

解决的第一步是处理流程中的用户创建部分。在 OpenStack 中创建用户是一个简单的任务，那么为什么不添加一些管理风格呢。创建用户的过程中的一部分是为该用户分配一个适当的密码。我们将把这作为创建用户的角色的一部分，并将该用户分配给项目。

创建 playbook 时，我通常从创建角色开始，以处理所需的管理任务。该角色将包含针对 OpenStack 云的所有可执行代码。Playbook 将包含要针对的主机（在本例中，将是实用容器）、要执行的角色以及其他执行设置。处理此管理任务的角色将被命名为`create-users-env`。

我们 playbook 的目录结构将开始看起来像这样：

```
base.yml             # master playbook for user creation 
group_vars/ 
  util_container     # assign variable values for this host group 
hosts                # static host inventory file 
roles/ 
  create-users-env   # user/project creation role 
   tasks/ 
     main.yml        # tasks file for this role 
   vars/ 
     main.yml        # variables associated with this role 

```

由于我们将从角色任务文件组装开始，让我们在`create-users-env/tasks`目录中创建`main.yml`文件。该文件的初始内容如下：

```
--- 

- name: Install random password generator package 
 apt: name={{item}} state=present 
 with_items: 
  - apg 

- name: Random generate passwords 
 command: apg -n {{ pass_cnt }} -M NCL -q 
 register: passwdss 

- name: Create users 
 os_user: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item.0 }}" 
  password: "{{ item.1 }}" 
  domain: default 
 with_together: 
  - "{{userid}}" 
  - "{{passwdss.stdout_lines}}" 

```

现在我们可以更详细地讨论刚刚添加到角色中的前三个任务。第一个任务为使用`apg`包设置了使用`apg`包的基础，该包生成几个随机密码：

```
- name: Install random password generator package 
 apt: name={{item}} state=present 
 with_items: 
  - apg 

```

由于在第二个任务中，我们将使用`apg`包为我们生成密码，因此我们必须确保它已安装在执行 playbook/角色的主机上。Ansible 的`apt`模块是管理 Debian/Ubuntu 软件包的非常有用的工具。使用`{{item}}`参数值定义模块，允许我们循环遍历稍后在`with_items`语句中列出的多个软件包。在这种特殊情况下，这并不需要，因为我们只安装一个软件包，但同时也不会对我们造成伤害。接下来是第二个任务：

```
- name: Random generate passwords 
 command: apg -n {{ pass_cnt }} -M NCL -q 
 register: passwdss 

```

现在第二个任务将使用 Ansible 的命令模块执行`apg`包。

### 提示

命令模块将是在使用 Ansible 时最常用的模块之一。它基本上可以处理执行任何命令/包，但不能处理使用 shell 变量和特定于 shell 的操作的命令，例如：`<`、`>`、`|`和`&`。

使用命令模块，我们传递了带有特定参数`-n {{ pass_cnt }} -M NCL -q`的`apg`命令。大多数参数都是`apg`的标准选项，除了定义的变量`{{ pass_cnt }}`。设置此参数允许我们从为该角色设置的变量文件（位于`create-users-env/vars`目录中）中调整生成的密码数量。我们将很快查看变量文件。此任务的最后一步是将`apg`命令的输出注册到名为`passwdss`的变量中。稍后将在此角色中使用此变量。

添加到角色的第三个任务现在将在您的 OpenStack 云中创建用户。再次看到，使用`os_user`模块，我们将执行 Keystone 命令以创建具有认证参数的用户：

```
- name: Create users 
 os_user: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item.0 }}" 
  password: "{{ item.1 }}" 
  domain: default 
 with_together: 
  - "{{userid}}" 
  - "{{passwdss.stdout_lines}}" 

```

在任务中，我们还将定义一些要使用的变量：

```
{{ item.0 }}  # variable placeholder used to set the usernames from the list  
                defined in the userid variable 

{{ item.1 }}  # variable placeholder used to read in the output from the apg 
                command found within the passwdss variable registered earlier 

```

### 提示

将变量放在命令中，可以让您创建具有核心代码的角色，而无需每次使用时都更新。只需更新变量文件比不断修改角色任务要简单得多。

此任务的另一个特殊部分是使用`with_together` Ansible 循环命令。此命令允许我们循环遍历分别设置的变量值，并按照定义的顺序将它们配对在一起。由于密码是随机的，我们不在乎哪个用户得到哪个密码。

现在我们在角色中有了用户创建代码，下一步是创建用户的项目。下面显示了接下来的两个任务：

```
- name: Create user environments 
 os_project: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item }}" 
  description: "{{ item }}" 
  domain_id: default 
  enabled: True 
 with_items: "{{tenantid}}" 

- name: Assign user to specified role in designated environment 
 os_user_role: 
  cloud: "{{CLOUD_NAME}}" 
  user: "{{ item.0 }}" 
  role: "{{ urole }}" 
  project: "{{ item.1 }}" 
 with_together:  
  - "{{userid}}" 
  - "{{tenantid}}" 

```

这个第一个任务将使用`os-project`模块创建项目。项目名称和描述将来自`tenantid`变量。接下来的任务将使用`urole`变量设置的角色值，将我们之前创建的用户分配给这个新创建的项目。

您会注意到这些任务与之前用于创建用户的任务非常相似，并且使用类似的 Ansible 参数。正如您所看到的，它将开始形成一个重复的模式。这确实有助于简化代码的创建。

角色的最后一个任务部分将简单地提供已创建用户及其对应密码的输出。这一步将为您（作为云操作员）提供一个非常简单的输出，其中包含您需要保存和/或传递给云消费者的所有信息。虽然这一步不是完成整体管理任务所必需的，但它很好。请参阅以下任务：

```
- name: User password assignment 
 debug: msg="User {{ item.0 }} was added to {{ item.2 }} project, with the assigned password of {{ item.1 }}" 
 with_together: 
  - userid 
  - passwdss.stdout_lines 
  - tenantid 

```

在这个任务中，我们将使用`debug`模块来显示我们手动设置或使用`register`Ansible 命令动态设置的变量的输出。输出将看起来像这样：

![编写 playbooks 和 roles](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_03_003.jpg)

信不信由你，你刚刚创建了你的第一个 OpenStack 管理角色。为了支持这个角色，我们现在需要创建与之配套的变量文件。位于`create-users-env/vars`目录中的变量文件名为`main.yml`，在结构上与任务文件非常相似。

### 提示

请记住，变量文件中定义的值是为了在每次执行正常的日常使用之前进行更改的。

以下示例中显示的值只是工作示例。让我们来看一下：

```
--- 
pass_cnt: 10 
userid: [ 'mrkt-dev01', 'mrkt-dev02', 'mrkt-dev03', 'mrkt-dev04', 'mrkt-dev05', 'mrkt-dev06', 'mrkt-dev07', 'mrkt-dev08', 'mrkt-dev09', 'mrkt-dev10' ] 
tenantid: [ 'MRKT-Proj01', 'MRKT-Proj02', 'MRKT-Proj03', 'MRKT-Proj04', 'MRKT-Proj05', 'MRKT-Proj06', 'MRKT-Proj07', 'MRKT-Proj08', 'MRKT-Proj09', 'MRKT-Proj10' ] 
urole: _member_ 

```

让我们花点时间来分解每个变量。摘要如下：

```
pass_cnt  # with the value of 10, we would be creating 10 random passwords 
            with apg 

userid    # the value is a comma delimited list of users to loop through 
            when executing the user-create Keystone command 

tenanted  # the value is a comma delimited list of tenant names to loop 
            through when executing the tenant-create Keystone command 

urole     # with the value of _member_, the user would be assigned the 
            member role to the tenant created 

```

这基本上总结了创建变量文件所涉及的内容。现在我们可以继续进行这个 playbook 的基础，并创建名为`base.yml`的主 playbook 文件，它位于 playbook 目录的 root 目录中。`base.yml`文件的内容将是：

```
--- 
# This playbook used to demo OpenStack Juno user, role and project features.  

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
create-users-env 

```

该文件的摘要如下：

```
hosts       # the host or host group to execute the playbook against 

remote_user # the user to use when executing the playbook on the 
              remote host(s) 
become      # will tell Ansible to become the above user on the 
              remote host(s) 
 roles      # provide a list of roles to execute as part of 
              this playbook 

```

在完成 playbook 并使其准备好执行之前，还有最后两个需要注意的地方，即创建主机清单文件和全局变量文件。在这种情况下，我们使用静态主机清单文件来保持简单，但在未来的章节中，我们将使用 OSA 动态清单文件。因为我们使用静态清单文件，所以我们必须发现实用容器的名称和/或 IP 地址。

这可以通过在任何控制节点上运行以下命令来完成：

```
**$ lxc-ls -fancy**

```

然后，在输出中查找类似于突出显示的项目：

![编写 playbooks 和 roles](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_03_004.jpg)

然后，将实用容器的 IP 地址添加到 hosts 文件中，如下所示：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

最后但并非最不重要的是，然后您将在`group_vars/`目录中创建全局变量文件。请记住，该文件的名称必须与主 playbook 中定义的主机或主机组的名称相匹配。由于我们称主机组为`util_container`，因此必须将变量文件命名为完全相同的名称。`util_container`全局变量文件的内容将是：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

```

### 提示

**专业提示**

在远程执行系统命令时，始终创建/使用自动化服务帐户。永远不要使用内置的管理员和/或您个人的帐户来执行该系统的命令。使用服务帐户可以简化故障排除和系统审核。

猜猜...你成功了！我们刚刚完成了我们的第一个 OpenStack 管理 playbook 和 role。让我们通过快速回顾刚刚创建的 playbook 和 role 来完成本章。

# 审查 playbooks 和 roles

直奔主题，我们可以从我们创建的名为`create-users-env`的角色开始。位于`create-users-env/tasks`目录中的完成角色和名为`main.yml`的文件如下所示：

```
--- 

- name: Install random password generator package 
 apt: name={{item}} state=present 
 with_items: 
  - apg 

- name: Random generate passwords 
 command: apg -n {{ pass_cnt }} -M NCL -q 
 register: passwdss 

- name: Create users 
 os_user: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item.0 }}" 
  password: "{{ item.1 }}" 
  domain: default 
 with_together: 
  - "{{userid}}" 
  - "{{passwdss.stdout_lines}}" 

- name: Create user environments 
 os_project: 
  cloud: "{{CLOUD_NAME}}" 
  state: present 
  name: "{{ item }}" 
  description: "{{ item }}" 
  domain_id: default 
  enabled: True 
 with_items: "{{tenantid}}" 

- name: Assign user to specified role in designated environment 
 os_user_role: 
  cloud: "{{CLOUD_NAME}}" 
  user: "{{ item.0 }}" 
  role: "{{ urole }}" 
  project: "{{ item.1 }}" 
 with_together:  
  - "{{userid}}" 
  - "{{tenantid}}" 

- name: User password assignment 
 debug: msg="User {{ item.0 }} was added to {{ item.2 }} tenant, with the assigned password of {{ item.1 }}" 
 with_together: 
  - userid 
  - passwdss.stdout_lines 
  - tenantid 

```

该角色的对应变量文件名为`main.yml`，位于`create-users-env/vars`目录中，如下所示：

```
--- 
pass_cnt: 10 
userid: [ 'mrkt-dev01', 'mrkt-dev02', 'mrkt-dev03', 'mrkt-dev04', 'mrkt-dev05', 'mrkt-dev06', 'mrkt-dev07', 'mrkt-dev08', 'mrkt-dev09', 'mrkt-dev10' ] 
tenantid: [ 'MRKT-Proj01', 'MRKT-Proj02', 'MRKT-Proj03', 'MRKT-Proj04', 'MRKT-Proj05', 'MRKT-Proj06', 'MRKT-Proj07', 'MRKT-Proj08', 'MRKT-Proj09', 'MRKT-Proj10' ] 
urole: _member_ 

```

接下来，位于 playbook 目录的 root 目录中的名为`base.yml`的主 playbook 文件将如下所示：

```
--- 
# This playbook used to demo OpenStack Juno user, role and project features.  

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
create-users-env 

```

接下来，我们创建了`hosts`文件，它也位于`playbook`目录的`root`目录中。

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

最后，我们通过创建名为`util_container`的全局变量文件，将其保存到`playbook`目录的`group_vars/`目录中，将这个 playbook 全部完成：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

```

正如之前承诺的，我觉得为您提供完全可用的 Ansible playbook 和 role 非常重要。您可以直接使用它们，或者作为创建新/改进的 Ansible 代码的跳板。代码可以在 GitHub 存储库中找到，[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2)。

现在当然，我们必须测试我们的工作。假设您已经克隆了之前提到的 GitHub 存储库，从部署节点测试 playbook 的命令如下：

```
**$ cd os-admin-with-ansible-v2**
**$ ansible-playbook -i hosts base.yml**

```

# 摘要

现在看，这并不那么糟糕，对吧？Ansible 确实在简化自动化 OpenStack 管理任务所需的工作方面做得很好。您现在可以一次又一次地重复使用该角色，将创建用户和项目的时间缩短到几分钟。这种时间投资是非常值得的。

在本章中，我们通过 API 和 CLI 在 OpenStack 中创建了用户和项目。我们了解了基本的自动化考虑。我们还开发了 Ansible playbook 和 role 来自动化用户和项目的创建。

有了这个良好的基础，我们准备继续进行下一个管理任务，即定制您的云配额。下一章将包括对配额的一般理解以及它们在您的 OpenStack 云中的使用方式。然后我们将过渡到手动创建配额的练习，最后讲解如何使用 Ansible 自动化这项任务。我们在第四章中见！


# 第四章：定制您的云配额

现在我们已经解决了创建我们的第一个 OpenStack 管理 Playbook，是时候进入下一个任务了。我们将要涵盖的下一个任务是如何定制云中的项目配额。这通常是为云消费者设置新项目/租户的过程中的下一步。我们将首先逐步介绍如何手动执行此操作，然后过渡到创建具有角色的 Playbook，以完全自动化它：

+   定义和创建配额

+   自动化考虑

+   编写 Playbook 和角色

+   Playbook 和角色审查

# 定义和创建配额

什么是配额？在 OpenStack 中，您可以在租户/项目或用户级别上设置配额，以限制允许的资源消耗。计算服务（Nova）管理配额值并强制执行它们。作为云操作员，这是 OpenStack 提供的另一个重要功能。配额允许您控制云的整体系统容量。您可能会问，为什么不只设置一个默认配额，让每个项目都使用它？我们将根据特定用例逐步介绍这种方法可能有效或无效的原因。还值得一提的是，块存储服务（Cinder）也具有设置配额的能力。

由于我们现在知道您可以设置配额，让我们回顾一下可以受限制的资源以及默认值是什么。以下表格描述了可以设置的配额类型：

| **配额名称** | **定义的数量** |
| --- | --- |
| 实例 | 每个项目中允许的实例 |
| 内核 | 每个项目中允许的实例内核 |
| RAM（MB） | 每个实例中允许的 RAM 兆字节 |
| 浮动 IP | 每个项目中允许的浮动 IP |
| 固定 IP | 每个项目中允许的固定 IP |
| 元数据项 | 每个实例中允许的元数据项 |
| 注入文件 | 每个项目中允许的注入文件 |
| 注入文件内容字节 | 每个注入文件中允许的内容字节 |
| 密钥对 | 每个项目中允许的密钥对 |
| 安全组 | 每个项目中允许的安全组 |
| 安全组规则 | 每个安全组中允许的规则 |
| 服务器组 | 每个项目中允许的服务器组 |
| 服务器组成员 | 每个项目中允许的服务器组成员 |

正如您所见，有很多选项可以应用限制。作为云操作员，您希望充分利用这些选项，以便在每个项目的基础上进行调整。采用这种方法可以优化您的云使用，从本质上延伸您的资源，同时只提供所需的资源。作为管理员，我讨厌看到浪费的资源挂在那里，如果有更好的控制措施，它们可以用于其他用途。配额作为相反的方法，也是保持云消费者不会耗尽所有云资源的概念。

是的，调整配额的过程确实需要努力（也就是额外的工作）。因此，设置全局默认配额值的概念变得流行起来。要查看默认配额值，您将执行以下命令：

```
**$ openstack --os-cloud=<cloud name> quota show <project name>**

```

输出将如下所示：

![定义和创建配额](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_04_001.jpg)

### 提示

每当您希望将配额值设置为无限制时，请将该值设置为`-1`。这告诉 Nova 允许该资源在该项目或全局范围内不受限制。

现在，让我们专注于如何使用 CLI 手动调整配额值。出于简单起见，我们将仅使用 OpenStack CLI 演示手动命令。

## 手动创建配额

准确地说，您只能更新全局配额或特定租户/项目的配额设置的值。您无法创建新的配额；只能更新值。列出、更新和重置配额涉及向计算服务（Nova）发送请求。

就像每个 OpenStack 服务一样，你必须首先通过在第一章中讨论的 OpenRC 文件进行认证，*OpenStack 简介*。然后，你需要为你希望更新的配额提供值（参考前面提到的表格以获取你的选项）。现在，让我们看下面的例子：

```
**$ source openrc** 
**$ openstack quota set <project name> --instances=<value> 
  --cores=<value>**

```

一旦执行了命令，屏幕上不会有任何输出。然后你可以执行`quota show`命令来确认更新。

一个真实的工作示例可能是这样的：

```
**$ openstack quota show admin**

```

请记住，前面的示例只显示了更新项目的`实例`和`核心`配额。还有其他可以更新的配额值。

## 设置默认配额

如果你只想设置所有租户/项目和用户都将被分配的默认配额，那么这个过程会有点不同。Nova 也管理默认的配额分配。设置默认配额在你希望快速创建一个带有自动内置控制的租户/项目或用户时非常有用。

最糟糕的情况莫过于错误地创建了一个没有资源限制的项目，然后在你意识到之前，该项目的消费者已经耗尽了你的云。云旨在给消费者一种无限的印象。实际上，我们都知道这是不可能的；一切都在某种程度上有限制。根据我的经验，如果你给一个用户 20 个 vCPU，如果允许的话，他们会全部使用完。设置云资源限制对于云操作者来说非常重要。

稍后会给出更新云的默认配额的命令。这个命令可以在认证后执行，就像前面的例子一样。配额选项与更新项目或特定用户的配额相同。请再次参考前面提到的表格以获取你的选项。以下是一个例子：

```
**$ openstack quota set <quota class name> --ram=<value> 
  --security-groups=<value>** 

```

与前面的命令的主要区别之一是，你必须提供 Nova 所谓的“配额”类。`配额`类是 Nova 区分默认`配额`和你可能设置的自定义`配额`的方式。假设未来的 Nova 版本将包括创建额外的`配额`类的功能。目前，你只能更新唯一可用的`配额`类，即名为`default`的`配额`类。

命令的工作示例可能是这样的：

```
**$ openstack quota set default --ram=-1 --security-groups=30**

```

请记住，无论你将默认的`配额`值设置为多少，每个项目或用户最初都会配置为这个值。

## 重置配额值

可能会有一天，你可能希望重新开始并重置为项目或用户设置的配额。幸运的是，在 OpenStack 中这是一个简单的过程。你可以使用 Nova 的`quota-delete`命令。这将删除自定义配额并将其重置为默认配额。参见以下示例：

```
**$ nova quota-delete --tenant=<tenant-id> [--user=<user-id>]**

```

使用前面的命令，你可以提供要将配额恢复为默认值的租户 ID 或用户 ID。

# 自动化考虑

在创建这个角色时，除了我们在前一章中讨论的内容之外，我只需要做出一个自动化决定。所有其他考虑都延续了下来。

因为 Nova `配额`命令允许传递多个选项而没有相互依赖，我们必须想出一种方法，既不限制角色的灵活性，又不需要直接对角色进行不断的更新。Ansible 通过允许将变量作为`哈希`传递来做出这样的决定。在变量文件中，你可以为每个项目或用户定义选项，并让任务循环遍历每个项目/用户以使用这些选项。

我保证这是我最后一次做出这样的声明，但我觉得强调这一点很重要：

### 注意

有许多方法可以使用 Ansible 自动化 OpenStack 的任务，本书中展示的方法只是我个人发现成功的一种方式，当然不是唯一的方式。这些剧本/角色旨在成为您可以直接使用或调整/改进以适应个人用例的工作示例。

就像上次一样，既然已经说了，让我们继续创建这个角色。

# 编写剧本和角色

我们现在将创建一个角色，允许我们一次更新单个和/或多个项目的配额。更新配额是一个相对简单的两步过程。第一步是记录您希望更新配额的租户 ID 或用户 ID。然后，第二步是实际更新配额。

由于在本示例中我们只是创建一个角色，我们可以从角色目录中的`main.yml`文件开始，该目录名为`adjust-quotas/tasks`。该文件开头的内容将如下所示：

```
--- 

- name: Adjust tenant quotas 
 command: openstack --os-cloud="{{ CLOUD_NAME }}" 
      quota set "{{ item.1 }}" "{{ item.0 }}" 
 with_together: 
  - "{{qoptions}}" 
  - "{{tenantname}}" 

```

就像我们在本章前面审查的手动命令一样，您必须从稍后我们将审查的变量文件中提供您希望调整的配额选项和租户名称。同样，我们使用`with_together`命令循环遍历两个变量，将值配对在一起。

以下是任务中定义的变量的进一步细分：

```
{{ item.0 }}  # variable placeholder used to set the quota options to update 

{{ item.1 }}  # variable placeholder used to set the project name 

```

当执行角色时，在这种特定情况下不会生成任何输出。如果您想要提供输出以确认任务成功执行，可以将`quota show`命令作为角色中的附加任务添加。这将如下所示：

```
- name: Confirm tenant quota update 
 command: openstack --os-cloud="{{ CLOUD_NAME }}" 
      quota show "{{ item.0 }}" 
 with_items: "{{tenantname}}" 

```

您现在已经完成了第二个 OpenStack 管理角色。为了支持这个角色，我们现在需要创建与之配套的变量文件。变量文件名为`main.yml`，将位于`adjust-quotas/vars`目录中。

### 提示

请记住，变量文件中定义的值是打算在每次执行前进行更改以进行正常的日常使用。

以下示例中显示的值只是工作示例。让我们来看一下：

```
--- 
qoptions: [ '--cores 30', '--instances 20', '--cores 20', '--instances 20', '--cores 20' ] 
tenantname: [ 'MRKT-Proj01', 'MRKT-Proj02', 'MRKT-Proj02', 'MRKT-Proj03', 'MRKT-Proj03' ] 

```

让我们花点时间来分解每个变量。总结如下：

```
qoptions  # this is where you declare the quota options you wish to update, each 
            set of options and values are encapsulated within single quotes   
            comma delimited; there is no limit on the number of options that can  
            be added 
 tenantname # the value is a comma delimited list of tenant names you wish 
              to update quotas for 

```

现在我们的变量文件已经创建，我们可以继续创建主剧本文件。就像在上一章中一样，文件将被命名为`quota-update.yml`并保存到剧本目录的根目录中。`quota-update.yml`文件的内容将是：

```
--- 
# This playbook used to demo OpenStack Juno quota updates. 

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
adjust-quotas 

```

该文件的摘要如下：

```
hosts       # the host or host group to execute the playbook against 

remote_user # the user to use when executing the playbook on the remote host(s) 

become      # will tell Ansible to become the above user on the remote host(s) 

roles       # provide a list of roles to execute as part of this playbook 

```

现在只剩下填充我们的主机清单文件和全局变量文件。由于我们在上一章中已经创建了这些文件，所以没有必要重复这个过程。之前定义的值将保持不变。以下是这些文件的配置快速回顾。

剧本目录根目录中的主机文件是：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

`group_vars/`目录中的全局变量文件是：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

```

好的，现在我们完成了两个管理剧本和角色。和往常一样，我们将以快速审查刚刚创建的剧本和角色结束本章。

# 审查剧本和角色

要开始，我们可以从我们创建的名为`create-users-env`的角色开始。完成的角色和文件，名为`main.yml`，位于`adjust-quotas/tasks`目录中，看起来像这样：

```
--- 

- name: Adjust tenant quotas 
 command: openstack --os-cloud="{{ CLOUD_NAME }}" 
      quota set "{{ item.1 }}" "{{ item.0 }}" 
 with_together: 
  - "{{qoptions}}" 
  - "{{tenantname}}" 

```

该角色对应的变量文件，名为`main.yml`，位于`adjust-quota/vars`目录中，将如下所示：

```
--- 
qoptions: [ '--cores 30', '--instances 20', '--cores 20', '--instances 20', '--cores 20' ] 
tenantname: [ 'MRKT-Proj01', 'MRKT-Proj02', 'MRKT-Proj02', 'MRKT-Proj03', 'MRKT-Proj03' ] 

```

接下来，位于`playbook`目录的`root`中的主剧本文件，名为`quota-update.yml`，将如下所示：

```
--- 
# This playbook used to demo OpenStack Juno quota updates. 

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
adjust-quotas 

```

接下来，我们创建了主机文件，也位于`playbook`目录的`root`目录中：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

最后，我们通过创建名为`util_container`的全局变量文件来包装这个剧本，将其保存到剧本的`group_vars/`目录中：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

```

### 注意

完整的代码集可以在以下 GitHub 存储库中再次找到：[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2)。

现在当然，我们必须测试我们的工作。假设您已经克隆了前面提到的 GitHub 存储库，从部署节点测试 playbook 的命令如下：

```
**$ cd os-admin-with-ansible-v2**
**$ ansible-playbook -i hosts quota-update.yml**

```

# 摘要

作为 OpenStack 操作员，配额将是您关注的重点，因此，能够简化该流程的任何努力都将是有益的。Ansible 是简化重复任务的关键。就像在上一章中一样，您可以将此角色与其他角色结合使用多次。这就是为什么您希望尽可能将角色设计为基本通用任务的原因。

本章涵盖的一些内容包括定义 OpenStack 中配额的概念。然后，我们利用这些知识学习了如何使用 OpenStack CLI 更新项目/用户的配额。我们应用了一些关于为什么要使用默认云配额以及如何适当地更新它们的基本原则。接下来，我们回顾了如何重置任何自定义配额。最后，我们开发了我们自己的 Ansible playbook 和角色，以自动更新自定义项目/用户配额。

现在让我们继续进行下一章，我们将承担云快照的管理任务。如果您想将实例用作金标本和/或保留实例的备份，那么拍摄实例快照的功能是一个强大的工具。了解如何在云操作员级别处理这种任务非常有益。下一章将介绍如何手动创建快照，介绍一次性快照项目中所有实例的功能，然后当然还包括如何使用 Ansible 自动化该任务。我们继续到第五章 *快照您的云*。


# 第五章：快照您的云

在本章中，我们将涵盖使用内置于计算服务（Nova）的 OpenStack 能力创建实例备份和/或快照的任务。当采用真正的云方法，即水平扩展和一次性资源的方法时，您会发现在利用快照与传统备份相比时有很大的用处。尽管这很好，但最佳实践是了解每种能力和适当用例。我们将首先逐步介绍如何手动创建备份或快照，然后过渡到创建具有角色的 playbook，以完全自动化租户级别的操作。本章将涵盖以下主题：

+   定义备份和快照

+   手动创建备份和快照

+   恢复实例备份

+   自动化考虑

+   编写 playbook 和角色

+   Playbook 和角色的审查

# 定义备份和快照

从 OpenStack 的角度来看，备份和实例快照之间存在明显的区别。这些差异可能影响每个功能的使用。请记住，与真正的云行为保持一致，所有云资源都应该是可丢弃的。您可能会问这句话真正意味着什么。它只是意味着为了支持应用功能而创建的任何实例或卷（资源）都应该能够以某种自动化方式重新创建。灌输*宠物与牛*的类比。不再是试图让生病的虚拟机复活的日子。

销毁实例，重新创建，然后再次开始。这些原则消除了对实例备份的需求。话虽如此，仍会有一些情况下您可能希望备份实例。因此，让我们首先检查获取实例备份的能力。

OpenStack 计算服务（Nova）备份实例的功能就像任何传统备份过程一样。备份实例的目的是为了保留实例的当前状态，以便以后可能恢复。与任何其他后备过程一样；您可以确定备份类型和轮换计划。一些可能的`备份`类型参数可以是**每日**或**每周**。轮换计划将表示要保留的备份数。通过 Nova CLI 执行实例`备份`命令的工作示例如下：

```
**$ nova backup <instance><backup name><backup-type><rotation>**
**$ nova backup testinst bck-testinst weekly 5**

```

### 注意

完全透明地说，截至本书编写时，Nova`备份`功能尚未完全运行。此时的`备份`命令只是 Nova 中设置的一个挂钩，用于未来专门关注数据保护的 OpenStack 服务。OpenStack 数据保护服务，代号**Raksha**，将负责帮助自动化数据保护任务，如备份。Raksha 仍在开发中，并将出现在即将推出的 OpenStack 版本中。您可以在[`wiki.openstack.org/wiki/Raksha`](https://wiki.openstack.org/wiki/Raksha)上阅读更多关于 Raksha 的信息。

现在我们可以继续讨论快照。Nova 获取实例快照的功能类似于备份，但是不是为了恢复目的而保留备份，而是由镜像服务（Glance）存储为图像模板。然后可以使用该图像模板创建与原始快照所在实例相同的其他实例。这就像制作实例的橡皮图章副本。

### 注意

请记住，对实例进行传统快照会暂时暂停实例，直到过程完成。如果您希望在不暂停实例的情况下进行快照，请查看[`docs.openstack.org/openstack-ops/content/snapshots.html`](http://docs.openstack.org/openstack-ops/content/snapshots.html)上找到的*实时快照*功能详细信息。

我经常喜欢将快照过程比作制作服务器的黄金镜像，该镜像将用于构建其他服务器。所采取的步骤将完全相同。创建具有所需操作系统的实例，安装必要的软件包，进行建议的操作系统和应用程序安全调整，验证应用程序功能，然后创建快照。在不需要任何第三方软件的情况下即可随时使用快照功能，这确实是 OpenStack 提供的又一个强大工具。

通过 OpenStackClient CLI 执行实例快照命令的实际工作示例如下：

```
**$ openstack server image create 
  --name=<snapshot name> <instance>**
**$ openstack server image create 
  --name=snp-testinst testinst** 

```

希望这有助于清晰地定义实例备份和快照之间的区别。现在让我们来看看使用 CLI 手动创建它们所需的步骤。

### 注意

为了简单起见，我们将仅使用 OpenStack CLI 演示手动命令。

## 手动创建备份和快照

如前所述，计算服务（Nova）负责创建实例备份和快照的任务。与每个 OpenStack 服务一样，您必须首先进行身份验证，可以通过获取第一章中讨论的 OpenRC 文件，*OpenStack 简介*或通过在命令中传递内联身份验证参数来进行身份验证。这两个任务分别需要提供不同的参数值才能成功执行命令。请参见后面给出的示例。

以下是使用 OpenRC 文件的实例“备份”：

```
**$ source openrc** 
**$ nova backup <instance> <backup name> 
  <backup-type><rotation>**

```

以下是一个使用内联身份验证参数的实例“备份”：

```
**$ nova --os-username=<OS_USERNAME> --os-password=
  <OS_PASSWORD> --os-tenant-
  name=<OS_TENANT_NAME> --os-auth-url=<OS_AUTH_URL> 
  backup <instance><backup name>
  <backup-type><rotation>**

```

执行命令后，不会将任何输出写回屏幕。然后您可以执行`openstack image show`命令来确认更新。

使用 OpenRC 文件的真实工作示例可能如下所示：

```
**$ source openrc**
**$ openstack server list**
**$ nova backup vm-with-vol-my_instance-v35vvbw67u7s 
  bck-vm-with-vol-my_instance-v35vvbw67u7s weekly 3**

```

然后`openstack image list`命令的输出将是：

![手动创建备份和快照](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_05_001.jpg)

使用前面提到的命令，您可以提供实例 ID 或名称。刚刚显示的示例使用了实例名称。在获取 OpenRC 文件后，执行`openstack server list`命令以记录您希望备份的实例 ID 或名称。一旦您获得了这些信息，就可以执行`nova backup`命令。

### 注意

镜像服务，代号 Glance，负责保留由云操作员手动上传的备份、快照和任何镜像的清单。要查看可用的清单，您将需要发出 Glance CLI 命令和/或通过**Horizon**仪表板下的**Images**选项卡查看它们。

以下是使用 OpenRC 文件的实例快照：

```
**$ source openrc**
**$ openstack server image create 
  --name=<snapshot name> <instance>**

```

以下是使用内联身份验证参数的实例快照：

```
**$ openstack --os-cloud=default server image create 
  --name=<snapshot name> <instance>**

```

执行命令后，不会将任何输出写回屏幕。然后您可以执行`openstack image list`命令来确认更新。

使用 OpenRC 文件的真实工作示例可能如下所示：

```
**$ source openrc**
**$ openstack server list**
**$ openstack server image create --name=snap-vm-
  with-vol-my_instance-v35vvbw67u7s 
  vm-with-vol-my_instance-v35vvbw67u7s**

```

然后`openstack image list`命令的输出将是：

![手动创建备份和快照](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_05_002.jpg)

既然我们已经介绍了如何创建实例备份和快照，那么演示如何使用它们就显得很重要。特别是，我想专注于使用实例备份，因为我注意到在这个功能周围缺乏严重的文档。

## 恢复实例备份

尽管实例“备份”功能在计划任务/自动化方面并非 100%活跃，但您仍然可以使用实例备份将实例恢复到特定时间点。为了做到这一点，您将使用 Nova CLI 中的`nova rebuild`命令。该命令将指示实例关闭，使用引用的“备份”文件重新映像实例，然后重新启动实例。

通过 Nova CLI 执行`nova rebuild`命令的实际工作示例如下：

```
**$ nova rebuild <instance> <image name>**
**$ nova rebuild vm-with-vol-my_instance-v35vvbw67u7s 
  snap-vm-with-vol-my_instance-v35vvbw67u7s**

```

`nova rebuild`命令还有一些可选参数可以与命令一起传递。这些可选参数可以执行诸如重置管理员密码或更改实例名称等操作。我建议查看 OpenStack CLI 文档，该文档可以在[`docs.openstack.org/cli-reference/content/novaclient_commands.html#novaclient_subcommand_rebuild`](http://docs.openstack.org/cli-reference/content/novaclient_commands.html#novaclient_subcommand_rebuild)找到。

# 自动化考虑

自动化这个任务非常简单，不需要任何新的框架决策。我们之前审查的所有其他自动化决策都已经被采纳。

有一个值得强调的领域，当您使用 CLI 自动化 OpenStack 任务时，您可能也会面临。 CLI 的默认输出是**漂亮打印**（使用 Python **prettytable**模块），有时当您想要整理输出时并不那么漂亮。一些 CLI 命令允许特定格式，但如果命令不允许，您还有其他选择。这就是`awk`命令再次成为您非常亲密的盟友的地方。在下一节中，您将注意到`awk`命令的具体用法，以过滤我们在角色中需要的下一个任务的值。

感觉我们现在准备好继续创建下一个 playbook 和 role 了。

# 编写 playbooks 和 roles

我们现在将创建的 playbook 和 role 将允许您一次对单个租户内的所有实例进行快照。选择这个独特的任务是为了保持角色简单，不要使任务过于复杂。您也可以创建一个角色来对所有租户中的所有实例进行快照或备份，只需删除一个参数。很棒，对吧？好吧，感谢 Ansible。

在本章的开头，我们审查了如何进行实例备份和快照的过程。这是一个简单的两步过程。为了自动化这个任务，我们必须向过程添加一个额外的步骤。这一步将是获取我们计划从中获取快照的租户的租户 ID。因此，在大局中，将有三个步骤。*步骤 1*是记录您希望为其获取实例快照的租户 ID。*步骤 2*是现在列出来自租户的所有实例 ID。最后，*步骤 3*是实际获取实例快照。

由于在此示例中我们只创建了一个 role，因此我们可以从名为`create-snapshot/tasks`的 role 目录中的`main.yml`文件开始。该文件的初始内容如下：

```
--- 

- name: Retrieve tenantID 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     project list | awk '/ "{{tenantname}}" / { print $2 }' 
 register: tenantid 

```

使用`awk`命令和管道（`|`）符号提取租户 ID 的第一步非常简单。这种方法是您将在许多 OpenStack 文档中看到的。它允许您获取一个命令的输出并过滤出您想要保留的部分。首先，我们将执行项目列表命令，然后将使用过滤器，该过滤器将搜索通过名为`tenantname`的变量提供的租户名称，并最终输出原始`project list`命令的第二列值。然后，将使用名为`tenantid`的变量注册该最终输出。`tenantname`变量的定义方式与上一章相同。

请记住，这里使用`shell`模块，因为我们正在执行需要特定于 shell 的操作的命令。

下一个任务现在将列出来自租户的所有实例 ID。完成此操作的代码如下：

```
- name: Retrieve instance id from tenant 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     server list --all-projects --project "{{ tenantid.stdout }}" | awk 'NR > 3 { print $2 }' 
 register: instid 

```

这个任务与第一个任务非常相似，只是我们使用 OpenStackClient CLI 而不是列出实例并过滤掉所有前导或尾随字符的 ID。我发现当使用 Ansible 时，`openstack server list`命令对实例 ID/名称的提供方式非常具体。为了实现这一点，我决定使用`awk`命令的一个内置变量，名为`NR`。

`awk`中的`NR`变量（记录数）旨在为您提供被过滤内容的记录数或行号。反过来，`NR`变量可以用于集中研究某些行。在这里，我们使用该变量跳过 CLI 输出的前三行。此示例显示了正常输出：

![编写 playbook 和角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_05_003.jpg)

然后，当添加`awk`命令`awk 'NR > 3 { print $2 }'`时，输出如下：

![编写 playbook 和角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/opstk-adm-asb2/img/image_05_004.jpg)

最后，现在我们有了实例列表，我们可以完成最后一个任务，即拍摄快照。执行此操作的代码如下：

```
- name: Create instance snapshot 
 command: openstack --os-cloud="{{ CLOUD_NAME }}"  
      server image create --name="{{ tenantname }}"-snap-"{{ item }}" "{{ item }}"  
 with_items: "{{instid.stdout_lines}}" 
 register: command_result 
 failed_when: "'_info' not in command_result.stderr" 

```

就像在上一章中一样，使用模块定义`{{item}}`参数值允许我们循环遍历`with_items`语句中列出的多个软件包。还要记住，在 Ansible 中将值注册到变量后，需要查询 JSON 数据结构的`stdout`或`stdout_lines`部分。然后，我们重新利用了租户名称和实例 ID 来命名快照，以便将来轻松引用。快照名称本身可以是任何您想要的，我只是觉得这种命名约定最有意义。

在上述代码的最后两行中，必须添加`register`和`failed_when`，这是由于`openstack server image create`命令的输出。如果您想要提供输出以确认任务的成功执行，可以将`openstack image list`命令作为角色的附加任务，并将任务输出打印到屏幕上或保存在文件中。将输出打印到屏幕的示例如下：

```
- name: Confirm instance snapshot(s) 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     image list --format value --column Name 
 register: snapchk 

- name: Image list output 
 debug: msg="{{ item }}" 
 with_items: "{{snapchk.stdout_lines}}" 

```

您现在已经完成了第三个 OpenStack 管理角色。为了支持此角色，我们现在需要创建与之配套的变量文件。名为`main.yml`的变量文件将位于`create-snapshot/vars`目录中。

### 提示

请记住，变量文件中定义的值是为了在正常的日常使用中在每次执行之前进行更改的。

对于此角色，只需要一个变量：

```
--- 
tenantname: MRKT-Proj01 

```

此变量旨在成为需要拍摄实例快照的租户名称之一的单个值。

现在我们已经创建了变量文件，可以继续创建主要的 playbook 文件。该文件将命名为`snapshot-tenant.yml`，并保存在`playbook`目录的`root`目录中。

### 注意

playbook 和角色的名称可以是任何您选择的。这里提供了具体的名称，以便您可以轻松地跟踪并引用 GitHub 存储库中找到的完整代码。唯一的警告是，无论您决定如何命名角色，都必须在 playbook 中引用时保持统一。

`snapshot-tenant.yml`文件的内容将是：

```
--- 
# This playbook used to demo OpenStack Newton user, role, image and volume features.  

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
  - create-snapshot 

```

该文件的摘要如下：

```
hosts       # the host or host group to execute the playbook against 

remote_user # the user to use when executing the playbook on the remote host(s) 

become      # will tell Ansible to become the above user on the remote host(s) 

roles       # provide a list of roles to execute as part of this playbook 

```

现在只剩下填写我们的主机`inventory`文件和全局`variable`文件。由于我们已经在上一章中创建了这些文件，所以无需重复此过程。之前定义的值将保持不变。以下是这些文件配置的快速回顾。

`playbook`目录中`root`目录中的`hosts`文件是：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

`group_vars/`目录中的全局变量文件是：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

```

完成了第三个管理 playbook 和 role 的出色工作！和往常一样，我们将以快速审查刚刚创建的 playbook 和 role 来结束本章。

# 审查 playbooks 和 roles

让我们立即开始检查我们创建的名为`create-snapshot`的 role。完成的 role 和文件名为`main.yml`，位于`create-snapshot/tasks`目录中，如下所示：

```
--- 

- name: Retrieve tenantID 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     project list | awk '/ "{{tenantname}}" / { print $2 }' 
 register: tenantid 

- name: Retrieve instance id from tenant 
 shell: openstack --os-cloud="{{ CLOUD_NAME }}" 
     server list --all-projects --project "{{ tenantid.stdout }}" | awk 'NR > 3 { print $2 }' 
 register: instid 

- name: Create instance snapshot 
 command: openstack --os-cloud="{{ CLOUD_NAME }}"  
      server image create --name="{{ tenantname }}"-snap-"{{ item }}" "{{ item }}"  
 with_items: "{{instid.stdout_lines}}" 
 register: command_result 
 failed_when: "'_info' not in command_result.stderr" 

```

对应的变量文件名为`main.yml`，位于`create-snapshot/vars`目录中，该角色的文件如下：

```
--- 
tenantname: MRKT-Proj01 

```

接下来，位于 playbook 目录的`root`目录中的主 playbook 文件名为`snapshot-tenant.yml`，如下所示：

```
--- 
# This playbook used to demo OpenStack Newton user, role, image and volume features.  

- hosts: util_container 
 remote_user: root 
 become: true 
 roles: 
  - create-snapshot 

```

接下来，我们创建了`hosts`文件，也位于`playbook`目录的`root`目录中：

```
[localhost] 
localhost ansible_connection=local 

[util_container] 
172.29.236.199 

```

最后，创建全局变量文件名为`util_container`，并将其保存到 playbook 的`group_vars/`目录中，将完成 playbook：

```
# Here are variables related globally to the util_container host group 

CLOUD_NAME: default 

```

完整的代码集可以在 GitHub 存储库中再次找到[`github.com/os-admin-with-ansible/os-admin-with-ansible-v2`](https://github.com/os-admin-with-ansible/os-admin-with-ansible-v2)。

在没有先测试我们的工作之前，我们无法结束本章。假设您已经克隆了前面的 GitHub 存储库，从部署节点测试 playbook 的命令如下：

```
**$ cd os-admin-with-ansible-v2**
**$ ansible-playbook -i hosts snapshot-tenant.yml**

```

# 总结

一旦开始使用 Ansible 创建 playbooks 和 roles，您会发现可以为许多不同的目的重复使用大量代码。在本章中，我们能够创建另一个与上一章非常相似的 role，但很快且轻松地包含一个完全不同的任务。始终记住尽可能将您的角色设计为尽可能基本的通用任务。我真诚地无法强调这一点。这可能是自动化某事所需的时间差异。

在本章中，我们定义并描述了实例备份和快照之间的区别。我们解释了使用 OpenStack CLI 手动创建备份和快照的过程。我们还回顾了如何使用实例`backup`的示例。然后，我们最终开发了用于自动创建指定租户内所有实例的快照的 Ansible playbook 和 role。我非常期待进入下一章，我们将在其中研究在计算节点之间迁移实例的过程。这肯定是您在管理 OpenStack 云时会遇到的管理任务。这也是一个颇具争议的话题，因为许多人要么不知道 OpenStack 中存在这个功能，要么不相信这个功能运行良好。在下一章中，我们将尝试通过演示如何手动迁移实例，然后进一步自动化来消除不必要的困惑。对于我们这些云操作员来说，下一章将是金子般的价值。您不想跳过下一章；它肯定是值得的。第六章，*迁移实例*，我们来了！
