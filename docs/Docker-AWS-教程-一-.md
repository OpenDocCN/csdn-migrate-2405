# Docker AWS 教程（一）

> 原文：[`zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5`](https://zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《在亚马逊网络服务上使用 Docker》！我非常兴奋能够写这本书，并分享如何利用 Docker 和亚马逊网络服务（AWS）生态系统提供的精彩技术，构建真正世界一流的解决方案，用于部署和运营您的应用程序。

Docker 已成为构建、打包、发布和运营应用程序的现代标准，利用容器的力量来提高应用程序交付速度，增加安全性并降低成本。本书将向您展示如何通过使用持续交付的最佳实践，来加速构建 Docker 应用程序的过程，提供一个完全自动化、一致、可靠和可移植的工作流程，用于测试、构建和发布您的 Docker 应用程序。在我看来，这是在考虑将应用程序部署到云端之前的基本先决条件，本书的前几章将重点介绍建立本地 Docker 环境，并为我们在整本书中将使用的示例应用程序创建一个本地持续交付工作流程。

AWS 是全球领先的公共云服务提供商，提供丰富的解决方案来管理和运营您的 Docker 应用程序。本书将涵盖 AWS 提供的所有主要服务，以支持 Docker 和容器，包括弹性容器服务（ECS）、Fargate、弹性 Beanstalk 和弹性 Kubernetes 服务（EKS），还将讨论您如何利用 Docker Inc 提供的 Docker for AWS 解决方案来部署 Docker Swarm 集群。

在 AWS 中运行完整的应用程序环境远不止您的容器平台，这本书还将描述管理访问 AWS 账户的最佳实践，并利用其他 AWS 服务来支持应用程序的要求。例如，您将学习如何设置 AWS 应用程序负载均衡器，为您的应用程序发布高可用、负载均衡的端点，创建 AWS 关系数据库服务（RDS）实例，提供托管的应用程序数据库，将您的应用程序集成到 AWS Secrets Manager 中，提供安全的秘密管理解决方案，并使用 AWS CodePipeline、CodeBuild 和 CloudFormation 服务创建完整的持续交付管道，该管道将自动测试、构建和发布 Docker 镜像，以适应您应用程序的任何新更改，并自动将其部署到开发和生产环境。

您将使用 AWS CloudFormation 服务构建所有这些支持基础设施，该服务提供了强大的基础设施即代码模板，允许您定义我提到的所有 AWS 服务和资源，并将其部署到 AWS，只需点击一个按钮。

我相信现在你一定和我一样对学习所有这些美妙的技术充满了期待，我相信在读完这本书之后，你将拥有部署和管理 Docker 应用程序所需的专业知识和技能，使用最新的前沿技术和最佳实践。

# 这本书适合谁

《在亚马逊网络服务上使用 Docker》适用于任何希望利用容器、Docker 和 AWS 的强大功能来构建、部署和操作应用程序的人。

读者最好具备对 Docker 和容器的基本理解，并且已经使用过 AWS 或其他云服务提供商，尽管不需要有容器或 AWS 的先前经验，因为这本书采用了一步一步的方法，并在您进展时解释关键概念。了解如何使用 Linux 命令行、Git 和基本的 Python 脚本知识将是有用的，但不是必需的。

请参阅“充分利用本书”部分，了解推荐的先决条件技能的完整列表。

# 本书涵盖了什么

第一章，“容器和 Docker 基础”，将简要介绍 Docker 和容器，并概述 AWS 中可用于运行 Docker 应用程序的各种服务和选项。您将设置您的本地环境，安装 Docker、Docker Compose 和其他各种工具，以完成每章中的示例。最后，您将下载示例应用程序，并学习如何在本地测试、构建和运行应用程序，以便您对应用程序的工作原理和您需要执行的特定任务有一个良好的理解，以使应用程序正常运行。

第二章，“使用 Docker 构建应用程序”，将描述如何构建一个完全自动化的基于 Docker 的工作流程，用于测试、构建、打包和发布您的应用程序作为生产就绪的 Docker 发布映像，使用 Docker、Docker Compose 和其他工具。这将建立一个便携式的持续交付工作流的基础，您可以在多台机器上一致地执行，而无需在每个本地环境中安装特定于应用程序的依赖项。

第三章，“开始使用 AWS”，将描述如何创建一个免费的 AWS 账户，并开始使用各种免费的服务，让您熟悉 AWS 提供的广泛的服务。您将学习如何为您的账户建立最佳实践的管理和用户访问模式，配置增强安全性的多因素身份验证（MFA）并安装 AWS 命令行界面，该界面可用于各种操作和自动化用例。您还将介绍 CloudFormation，这是 AWS 免费提供的管理工具和服务，您将在本书中使用它，它允许您使用强大而富有表现力的基础设施即代码模板格式，通过单击按钮部署复杂的环境。

第四章，ECS 简介，将帮助您快速上手弹性容器服务（ECS），这是在 AWS 中运行 Docker 应用程序的旗舰服务。您将了解 ECS 的架构，创建您的第一个 ECS 集群，使用 ECS 任务定义定义您的容器配置，然后将 Docker 应用程序部署为 ECS 服务。最后，您将简要介绍 ECS 命令行界面（CLI），它允许您与本地 Docker Compose 文件进行交互，并使用 ECS 自动部署 Docker Compose 资源到 AWS。

第五章，使用 ECR 发布 Docker 镜像，将教您如何使用弹性容器注册表（ECR）建立一个私有的 Docker 注册表，使用 IAM 凭证对您的注册表进行身份验证，然后将 Docker 镜像发布到注册表中的私有存储库。您还将学习如何与其他账户和 AWS 服务共享您的 Docker 镜像，以及如何配置生命周期策略以自动清理孤立的镜像，确保您只支付活动和当前的镜像。

第六章，构建自定义 ECS 容器实例，将向您展示如何使用一种流行的开源工具 Packer 来构建和发布自定义的 Amazon Machine Images（AMIs）用于在 ECS 集群中运行您的容器工作负载的 EC2 实例（ECS 容器实例）。您将安装一组辅助脚本，使您的实例能够与 CloudFormation 集成，并在实例创建时下载自定义的配置操作，从而使您能够动态配置 ECS 集群，配置实例应发布日志信息的 CloudWatch 日志组，并最终向 CloudFormation 发出信号，表明配置已成功或失败。

第七章，创建 ECS 集群，将教您如何基于利用上一章中创建的自定义 AMI 的特性来构建基于 EC2 自动扩展组的 ECS 集群。您将使用 CloudFormation 定义您的 EC2 自动扩展组、ECS 集群和其他支持资源，并配置 CloudFormation Init 元数据来执行自定义运行时配置和 ECS 容器实例的配置。

第八章，“使用 ECS 部署应用程序”，将扩展上一章创建的环境，添加支持资源，如关系数据库服务（RDS）实例和 AWS 应用程序负载均衡器（ALB）到您的 CloudFormation 模板中。然后，您将为示例应用程序定义一个 ECS 任务定义和 ECS 服务，并学习 ECS 如何执行应用程序的自动滚动部署和更新。为了编排所需的部署任务，如运行数据库迁移，您将扩展 CloudFormation 并编写自己的 Lambda 函数，创建一个 ECS 任务运行器自定义资源，提供运行任何可以作为 ECS 任务执行的配置操作的强大能力。

第九章，“管理机密”，将介绍 AWS Secrets Manager，这是一个完全托管的服务，可以以加密格式存储机密数据，被授权方（如您的用户、AWS 资源和应用程序）可以轻松安全地访问。您将使用 AWS CLI 与 Secrets Manager 进行交互，为敏感凭据（如数据库密码）创建机密，然后学习如何为容器创建入口脚本，在容器启动时将机密值作为内部环境变量注入，然后交给主应用程序。最后，您将创建一个 CloudFormation 自定义资源，将机密暴露给不支持 AWS Secrets Manager 的其他 AWS 服务，例如为关系数据库服务（RDS）实例提供管理密码。

第十章，“隔离网络访问”，描述了如何在 ECS 任务定义中使用 awsvpc 网络模式，以隔离网络访问，并将 ECS 控制平面通信与容器和应用程序通信分开。这将使您能够采用最佳安全实践模式，例如在私有网络上部署您的容器，并实现提供互联网访问的解决方案，包括 AWS VPC NAT 网关服务。

第十一章，“管理 ECS 基础设施生命周期”，将为您提供在运行 ECS 集群时的操作挑战的理解，其中包括将 ECS 容器实例移出服务，无论是为了缩减自动扩展组还是用新的 Amazon 机器映像替换 ECS 容器实例。您将学习如何利用 EC2 自动扩展生命周期挂钩，在 ECS 容器实例即将被终止时调用 AWS Lambda 函数，这允许您执行优雅的关闭操作，例如将活动容器转移到集群中的其他实例，然后发出 EC2 自动扩展以继续实例终止。

第十二章，“ECS 自动扩展”，将描述 ECS 集群如何管理 CPU、内存和网络端口等资源，以及这如何影响您的集群容量。如果您希望能够动态自动扩展您的集群，您需要动态监视 ECS 集群容量，并在容量阈值处扩展或缩减集群，以确保您将满足组织或用例的服务水平期望。您将实施一个解决方案，该解决方案在通过 AWS CloudWatch Events 服务生成 ECS 容器实例状态更改事件时计算 ECS 集群容量，将容量指标发布到 CloudWatch，并使用 CloudWatch 警报动态地扩展或缩减您的集群。有了动态集群容量解决方案，您将能够配置 AWS 应用程序自动扩展服务，根据适当的指标（如 CPU 利用率或活动连接）动态调整服务实例的数量，而无需担心对底层集群容量的影响。

第十三章，“持续交付 ECS 应用程序”，将使用 AWS CodePipeline 服务建立一个持续交付流水线，该流水线与 GitHub 集成，以侦测应用程序源代码和基础设施部署脚本的更改，使用 AWS CodeBuild 服务运行单元测试，构建应用程序构件并使用示例应用程序 Docker 工作流发布 Docker 镜像，并使用本书中迄今为止使用的 CloudFormation 模板持续部署您的应用程序更改到 AWS。

这将自动部署到一个您测试的 AWS 开发环境中，然后创建一个变更集和手动批准操作，以便将其部署到生产环境，为您的所有应用程序新功能和错误修复提供了一个快速且可重复的生产路径。

第十四章《Fargate 和 ECS 服务发现》将介绍 AWS Fargate，它提供了一个完全管理传统上需要使用常规 ECS 服务来管理的 ECS 服务控制平面和 ECS 集群的解决方案。您将使用 Fargate 部署 AWS X-Ray 守护程序作为 ECS 服务，并配置 ECS 服务发现，动态发布您的服务端点使用 DNS 和 Route 53。这将允许您为您的示例应用程序添加对 X-Ray 跟踪的支持，该跟踪可用于跟踪传入的 HTTP 请求到您的应用程序，并监视 AWS 服务调用、数据库调用和其他类型的调用，这些调用是为了服务每个传入请求。

第十五章《弹性 Beanstalk》将介绍流行的**平台即服务**（**PaaS**）提供的概述，其中包括对 Docker 应用程序的支持。您将学习如何创建一个弹性 Beanstalk 多容器 Docker 应用程序，建立一个由托管的 EC2 实例、一个 RDS 数据库实例和一个**应用负载均衡器**（**ALB**）组成的环境，然后使用各种技术扩展环境，以支持 Docker 应用程序的要求，例如卷挂载和在每个应用程序部署中运行单次任务。

第十六章，*AWS 中的 Docker Swarm*，将重点介绍如何在 AWS 中运行 Docker Swarm 集群，使用为 Docker Swarm 社区版提供的 Docker for AWS 蓝图。该蓝图为您提供了一个 CloudFormation 模板，在几分钟内在 AWS 中建立一个预配置的 Docker Swarm 集群，并与关键的 AWS 服务（如弹性负载均衡（ELB）、弹性文件系统（EFS）和弹性块存储（EBS）服务）进行集成。您将使用 Docker Compose 定义一个堆栈，该堆栈配置了以熟悉的 Docker Compose 规范格式表示的多服务环境，并学习如何配置关键的 Docker Swarm 资源，如服务、卷和 Docker 秘密。您将学习如何创建由 EFS 支持的共享 Docker 卷，由 EBS 支持的可重定位 Docker 卷，Docker Swarm 将在节点故障后自动重新连接到重新部署的新容器，并使用由 Docker Swarm 自动创建和管理的 ELB 为您的应用程序发布外部服务端点。

第十七章，*弹性 Kubernetes 服务*，介绍了 AWS 最新的容器管理平台，该平台基于流行的开源 Kubernetes 平台。您将首先在本地 Docker Desktop 环境中设置 Kubernetes，该环境包括 Docker 18.06 CE 版本对 Kubernetes 的本机支持，并学习如何使用多个 Kubernetes 资源（包括 pod、部署、服务、秘密、持久卷和作业）为您的 Docker 应用创建完整的环境。然后，您将在 AWS 中建立一个 EKS 集群，创建一个 EC2 自动扩展组，将工作节点连接到您的集群，并确保您的本地 Kubernetes 客户端可以对 EKS 控制平面进行身份验证和连接，之后您将部署 Kubernetes 仪表板，为您的集群提供全面的管理界面。最后，您将定义一个使用弹性块存储（EBS）服务的默认存储类，然后将您的 Docker 应用部署到 AWS，利用您之前为本地环境创建的相同 Kubernetes 定义，为您提供一个强大的解决方案，可以快速部署用于开发目的的 Docker 应用程序，然后使用 EKS 直接部署到生产环境。

# 为了充分利用本书

+   Docker 的基本工作知识-如果您以前没有使用过 Docker，您应该了解[`docs.docker.com/engine/docker-overview/`](https://docs.docker.com/engine/docker-overview/)上 Docker 的基本概念，然后按照 Docker 入门教程的第一部分([`docs.docker.com/get-started/`](https://docs.docker.com/get-started/))和第二部分([`docs.docker.com/get-started/part2`](https://docs.docker.com/get-started/part2))进行学习。要更全面地了解 Docker，请查看 Packt Publishing 的[Learn Docker - Fundamentals of Docker 18.x](https://www.packtpub.com/networking-and-servers/learn-docker-fundamentals-docker-18x)书籍。

+   Git 的基本工作知识-如果您以前没有使用过 Git，您应该运行[`www.atlassian.com/git/tutorials`](https://www.atlassian.com/git/tutorials)上的初学者和入门教程。要更全面地了解 Git，请查看 Packt Publishing 的[Git Essentials](https://www.packtpub.com/application-development/git-essentials)书籍。

+   熟悉 AWS-如果您以前没有使用过 AWS，运行[`aws.amazon.com/getting-started/tutorials/launch-a-virtual-machine/`](https://aws.amazon.com/getting-started/tutorials/launch-a-virtual-machine/)上的启动 Linux 虚拟机教程将提供有用的介绍。

+   熟悉 Linux/Unix 命令行-如果您以前没有使用过 Linux/Unix 命令行，我建议您运行一个基本教程，比如[`maker.pro/linux/tutorial/basic-linux-commands-for-beginners`](https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners)，使用您在完成启动 Linux 虚拟机教程时创建的 Linux 虚拟机。

+   Python 的基本理解-本书的示例应用程序是用 Python 编写的，后面章节的一些示例包括基本的 Python 脚本。如果您以前没有使用过 Python，您可能希望阅读[`docs.python.org/3/tutorial/`](https://docs.python.org/3/tutorial)的前几课。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Docker-on-Amazon-Web-Services`](https://github.com/PacktPublishing/Docker-on-Amazon-Web-Services)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/DockeronAmazonWebServices_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/DockeronAmazonWebServices_ColorImages.pdf)

# 代码演示

访问以下链接查看代码运行的视频：

[`bit.ly/2Noqdpn`](http://bit.ly/2Noqdpn)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“请注意，要点中包含了一个名为`PASTE_ACCOUNT_NUMBER`的占位符，位于策略文档中，因此您需要将其替换为您的实际 AWS 账户 ID。”

代码块设置如下：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: Cloud9 Management Station

Parameters:
  EC2InstanceType:
    Type: String
    Description: EC2 instance type
    Default: t2.micro
  SubnetId:
    Type: AWS::EC2::Subnet::Id
    Description: Target subnet for instance
```

任何命令行输入或输出都以以下方式编写：

```
> aws configure
AWS Access Key ID [None]:
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单中的单词或对话框中的单词会以这种方式出现在文本中。例如：“要创建管理员角色，请从 AWS 控制台中选择**服务**|**IAM**，从左侧菜单中选择**角色**，然后单击**创建角色**按钮。”

警告或重要说明会出现在这样的样式中。提示和技巧会出现在这样的样式中。


# 第一章：容器和 Docker 基础知识

Docker 和 Amazon Web Services 是目前最炙手可热和最受欢迎的两种技术。Docker 目前是全球最流行的容器平台，而 Amazon Web Services 是排名第一的公共云提供商。无论是大型还是小型组织都在大规模地采用容器技术，公共云已不再是初创企业的游乐场，大型企业和组织也纷纷迁移到云端。好消息是，本书将为您提供有关如何同时使用 Docker 和 AWS 来帮助您比以往更快更高效地测试、构建、发布和部署应用程序的实用、现实世界的见解和知识。

在本章中，我们将简要讨论 Docker 的历史，为什么 Docker 如此革命性，以及 Docker 的高级架构。我们将描述支持在 AWS 中运行 Docker 的各种服务，并根据组织的需求讨论为什么您可能会选择一个服务而不是另一个服务。

然后，我们将专注于使用 Docker 在本地环境中运行起来，并安装运行本书示例应用程序所需的各种软件前提条件。示例应用程序是一个简单的用 Python 编写的 Web 应用程序，它将数据存储在 MySQL 数据库中，本书将使用示例应用程序来帮助您解决诸如测试、构建和发布 Docker 镜像，以及在 AWS 上部署和运行 Docker 应用程序等真实世界挑战。在将示例应用程序打包为 Docker 镜像之前，您需要了解应用程序的外部依赖项以及测试、构建、部署和运行应用程序所需的关键任务，并学习如何安装应用程序依赖项、运行单元测试、在本地启动应用程序，并编排诸如建立示例应用程序所需的初始数据库架构和表等关键操作任务。

本章将涵盖以下主题：

+   容器和 Docker 简介

+   为什么容器是革命性的

+   Docker 架构

+   AWS 中的 Docker

+   设置本地 Docker 环境

+   安装示例应用程序

# 技术要求

以下列出了完成本章所需的技术要求：

+   满足软件和硬件清单中定义的最低规格的计算机环境

以下 GitHub 网址包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch1`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch1)[.](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch3)

查看以下视频，了解代码的实际应用：

[`bit.ly/2PEKlVQ`](http://bit.ly/2PEKlVQ)

# 容器和 Docker 简介

近年来，容器已成为技术世界中的共同语言，很难想象仅仅几年前，只有技术界的一小部分人甚至听说过容器。

要追溯容器的起源，您需要倒回到 1979 年，当时 Unix V7 引入了 chroot 系统调用。chroot 系统调用提供了将运行中进程的根目录更改为文件系统中的不同位置的能力，并且是提供某种形式的进程隔离的第一个机制。chroot 于 1982 年添加到伯克利软件发行版（BSD）中（这是现代 macOS 操作系统的祖先），在容器化和隔离方面没有太多其他进展，直到 2000 年发布了一个名为 FreeBSD Jails 的功能，它提供了称为“jails”的单独环境，每个环境都可以分配自己的 IP 地址，并且可以在网络上独立通信。

2004 年，Solaris 推出了 Solaris 容器的第一个公共测试版（最终成为 Solaris Zones），通过创建区域提供系统资源分离。这是我记得在 2007 年使用的技术，帮助克服了昂贵的物理 Sun SPARC 基础设施的缺乏，并在单个 SPARC 服务器上运行应用程序的多个版本。

在 2000 年代中期，容器的进展更加显著，Open Virtuozzo（Open VZ）于 2005 年发布，它对 Linux 内核进行了补丁，提供了操作系统级的虚拟化和隔离。2006 年，谷歌推出了一个名为进程容器（最终更名为控制组或 cgroups）的功能，提供了限制一组进程的 CPU、内存、网络和磁盘使用的能力。2008 年，一个名为 Linux 命名空间的功能，提供了将不同类型的资源相互隔离的能力，与 cgroups 结合起来创建了 Linux 容器（LXC），形成了今天我们所知的现代容器的初始基础。

2010 年，随着云计算开始流行起来，一些平台即服务（PaaS）初创公司出现了，它们为特定的应用程序框架（如 Java Tomcat 或 Ruby on Rails）提供了完全托管的运行时环境。一家名为 dotCloud 的初创公司非常不同，因为它是第一家“多语言”PaaS 提供商，意味着您可以使用他们的服务运行几乎任何应用程序环境。支撑这一技术的是 Linux 容器，dotCloud 添加了一些专有功能，为他们的客户提供了一个完全托管的容器平台。到了 2013 年，PaaS 市场已经真正进入了 Gartner 炒作周期的失望低谷，dotCloud 濒临财务崩溃。该公司的联合创始人之一 Solomon Hykes 向董事会提出了一个开源他们的容器管理技术的想法，他感觉到有巨大的潜力。然而，董事会不同意，但 Solomon 和他的技术团队仍然继续前进，剩下的就是历史。

在 2013 年将 Docker 作为一个新的开源容器管理平台向世界宣布后，Docker 迅速崛起，成为开源世界和供应商社区的宠儿，很可能是历史上增长最快的技术之一。到 2014 年底，Docker 1.0 发布时，已经下载了超过 1 亿个 Docker 容器 - 快进到 2018 年 3 月，这个数字已经达到了*370* *亿*次下载。到 2017 年底，财富 100 强公司中使用容器的比例达到了 71%，表明 Docker 和容器已经成为创业公司和企业普遍接受的技术。如今，如果您正在构建基于微服务架构的现代分布式应用程序，那么您的技术栈很可能是以 Docker 和容器为基础。

# 容器为何是革命性的

容器的简短而成功的历史证明了它的价值，这引出了一个问题，*为什么容器如此受欢迎*？以下提供了这个问题的一些更重要的答案：

+   轻量级：容器经常与虚拟机进行比较，在这种情况下，容器比虚拟机要轻量得多。与典型虚拟机需要几分钟启动时间相比，容器可以在几秒钟内为您的应用程序启动一个隔离和安全的运行时环境。容器镜像也比虚拟机镜像要小得多。

+   速度：容器很快 - 它们可以在几秒内下载和启动，并且在几分钟内您就可以测试、构建和发布您的 Docker 镜像以供立即下载。这使得组织能够更快地创新，这在当今竞争日益激烈的环境中至关重要。

+   便携：Docker 使您能够更轻松地在本地机器、数据中心和公共云上运行应用程序。因为 Docker 包含了应用程序的完整运行时环境，包括操作系统依赖和第三方软件包，您的容器主机不需要任何特殊的预先设置或针对每个应用程序的特定配置 - 所有这些特定的依赖和要求都包含在 Docker 镜像中，使得“但在我的机器上可以运行！”这样的评论成为过去的遗迹。

+   **安全性**：关于容器安全性的讨论很多，但在我看来，如果实施正确，容器实际上比非容器替代方法提供了更高的安全性。主要原因是容器非常好地表达了安全上下文 - 在容器级别应用安全控制通常代表了这些控制的正确上下文级别。很多这些安全控制都是“默认”提供的 - 例如，命名空间本质上是一种安全机制，因为它们提供了隔离。一个更明确的例子是，它们可以在每个容器基础上应用 SELinux 或 AppArmor 配置文件，这样很容易根据每个容器的特定安全要求定义不同的配置文件。

+   **自动化**：组织正在采用诸如持续交付之类的软件交付实践，其中自动化是基本要求。Docker 本身支持自动化 - 在其核心，Dockerfile 是一种自动化规范，允许 Docker 客户端自动构建您的容器，而其他 Docker 工具如 Docker Compose 允许您表达连接的多容器环境，您可以在几秒钟内自动创建和拆除。

# Docker 架构

正如本书前言中所讨论的，我假设您至少具有基本的 Docker 工作知识。如果您是 Docker 的新手，那么我建议您通过阅读[`docs.docker.com/engine/docker-overview/`](https://docs.docker.com/engine/docker-overview/)上的 Docker 概述，并通过运行一些 Docker 教程来补充学习本章内容。

Docker 架构包括几个核心组件，如下所示：

+   **Docker 引擎**：它提供了用于运行容器工作负载的几个服务器代码组件，包括用于与 Docker 客户端通信的 API 服务器，以及提供 Docker 核心运行时的 Docker 守护程序。守护程序负责完整的容器和其他资源的生命周期，并且还内置了集群支持，允许您构建 Docker 引擎的集群或群集。

+   Docker 客户端：这提供了一个用于构建 Docker 镜像、运行 Docker 容器以及管理其他资源（如 Docker 卷和 Docker 网络）的客户端。Docker 客户端是您在使用 Docker 时将要使用的主要工具，它与 Docker 引擎和 Docker 注册表组件进行交互。

+   Docker 注册表：这负责存储和分发您应用程序的 Docker 镜像。Docker 支持公共和私有注册表，并且通过 Docker 注册表打包和分发您的应用程序是 Docker 成功的主要原因之一。在本书中，您将从 Docker Hub 下载第三方镜像，并将自己的应用程序镜像存储在名为弹性容器注册表（ECR）的私有 AWS 注册表服务中。

+   Docker Swarm：Swarm 是一组 Docker 引擎，形成一个自管理和自愈的集群，允许您水平扩展容器工作负载，并在 Docker 引擎故障时提供弹性。Docker Swarm 集群包括一些形成集群控制平面的主节点，以及一些实际运行您的容器工作负载的工作节点。

当您使用上述组件时，您将与 Docker 架构中的许多不同类型的对象进行交互：

+   镜像：镜像是使用 Dockerfile 构建的，其中包括一些关于如何为您的容器构建运行时环境的指令。执行每个构建指令的结果被存储为一组层，并作为可下载和可安装的镜像进行分发，Docker 引擎读取每个层中的指令，以构建基于给定镜像的所有容器的运行时环境。

+   容器：容器是 Docker 镜像的运行时表现形式。在幕后，容器由一组 Linux 命名空间、控制组和存储组成，共同创建了一个隔离的运行时环境，您可以在其中运行给定的应用程序进程。

+   **卷**：默认情况下，容器的基础存储机制基于联合文件系统，允许从 Docker 镜像中的各个层构建虚拟文件系统。这种方法非常高效，因为您可以共享层并从这些共享层构建多个容器，但是这会带来性能损失，并且不支持持久性。 Docker 卷提供对专用可插拔存储介质的访问，您的容器可以使用该介质进行 IO 密集型应用程序和持久化数据。

+   **网络**：默认情况下，Docker 容器各自在其自己的网络命名空间中运行，这提供了容器之间的隔离。但是，它们仍然必须提供与其他容器和外部世界的网络连接。 Docker 支持各种网络插件，支持容器之间的连接，甚至可以跨 Docker Swarm 集群进行扩展。

+   **服务**：服务提供了一个抽象，允许您通过在 Docker Swarm 集群中的多个 Docker 引擎上启动多个容器或服务副本来扩展您的应用程序，并且可以在这些 Docker 引擎上进行负载平衡。

# 在 AWS 中运行 Docker

除了 Docker 之外，本书将针对的另一个主要技术平台是 AWS。

AWS 是世界领先的公共云提供商，因此提供了多种运行 Docker 应用程序的方式：

+   **弹性容器服务（ECS）**：2014 年，AWS 推出了 ECS，这是第一个支持 Docker 的专用公共云服务。 ECS 提供了一种混合托管服务，ECS 负责编排和部署您的容器应用程序（例如容器管理平台的控制平面），而您负责提供 Docker 引擎（称为 ECS 容器实例），您的容器实际上将在这些实例上运行。 ECS 是免费使用的（您只需支付运行您的容器的 ECS 容器实例），并且消除了管理容器编排和确保应用程序始终运行的许多复杂性。但是，这需要您管理运行 ECS 容器实例的 EC2 基础设施。 ECS 被认为是亚马逊的旗舰 Docker 服务，因此将是本书重点关注的主要服务。

+   Fargate：Fargate 于 2017 年底推出，提供了一个完全托管的容器平台，可以为您管理 ECS 控制平面和 ECS 容器实例。使用 Fargate，您的容器应用程序部署到共享的 ECS 容器实例基础设施上，您无法看到这些基础设施，而 AWS 进行管理，这样您就可以专注于构建、测试和部署容器应用程序，而不必担心任何基础设施。Fargate 是一个相对较新的服务，在撰写本书时，其区域可用性有限，并且有一些限制，这意味着它并不适用于所有用例。我们将在第十四章《Fargate 和 ECS 服务发现》中介绍 Fargate 服务。

+   弹性 Kubernetes 服务（EKS）：EKS 于 2018 年 6 月推出，支持流行的开源 Kubernetes 容器管理平台。EKS 类似于 ECS，它是一个混合托管服务，亚马逊提供完全托管的 Kubernetes 主节点（Kubernetes 控制平面），您提供 Kubernetes 工作节点，以 EC2 自动扩展组的形式运行您的容器工作负载。与 ECS 不同，EKS 并不免费，在撰写本书时，其费用为每小时 0.20 美元，加上与工作节点相关的任何 EC2 基础设施成本。鉴于 Kubernetes 作为一个云/基础设施不可知的容器管理平台以及其开源社区的不断增长的受欢迎程度，EKS 肯定会变得非常受欢迎，我们将在第十七章《弹性 Kubernetes 服务》中介绍 Kubernetes 和 EKS。

+   弹性 Beanstalk（EBS）：Elastic Beanstalk 是 AWS 提供的一种流行的平台即服务（PaaS）产品，提供了一个完整和完全托管的环境，针对不同类型的流行编程语言和应用框架，如 Java、Python、Ruby 和 Node.js。Elastic Beanstalk 还支持 Docker 应用程序，允许您支持各种使用您选择的编程语言编写的应用程序。您将在第十五章《弹性 Beanstalk》中学习如何部署多容器 Docker 应用程序。

+   在 AWS 中的 Docker Swarm：Docker Swarm 是内置在 Docker 中的本地容器管理和集群平台，利用本地 Docker 和 Docker Compose 工具链来管理和部署容器应用程序。在撰写本书时，AWS 并未提供 Docker Swarm 的托管服务，但 Docker 提供了一个 CloudFormation 模板（CloudFormation 是 AWS 提供的免费基础设施即代码自动化和管理服务），允许您快速在 AWS 中部署与本地 AWS 提供的 Elastic Load Balancing（ELB）和 Elastic Block Store（EBS）服务集成的 Docker Swarm 集群。我们将在章节《在 AWS 中的 Docker Swarm》中涵盖所有这些内容以及更多内容。

+   CodeBuild：AWS CodeBuild 是一个完全托管的构建服务，支持持续交付用例，提供基于容器的构建代理，您可以使用它来测试、构建和部署应用程序，而无需管理与持续交付系统传统相关的任何基础设施。CodeBuild 使用 Docker 作为其容器平台，以按需启动构建代理，您将在章节《持续交付 ECS 应用程序》中介绍 CodeBuild 以及其他持续交付工具，如 CodePipeline。

+   批处理：AWS Batch 是基于 ECS 的完全托管服务，允许您运行基于容器的批处理工作负载，无需担心管理或维护任何支持基础设施。我们在本书中不会涵盖 AWS Batch，但您可以在[`aws.amazon.com/batch/`](https://aws.amazon.com/batch/)了解更多关于此服务的信息。

在 AWS 上运行 Docker 应用程序有各种各样的选择，因此根据组织或特定用例的要求选择合适的解决方案非常重要。

如果您是一家希望快速在 AWS 上使用 Docker 并且不想管理任何支持基础设施的中小型组织，那么 Fargate 或 Elastic Beanstalk 可能是您更喜欢的选项。Fargate 支持与关键的 AWS 服务原生集成，并且是一个构建组件，不会规定您构建、部署或运行应用程序的方式。在撰写本书时，Fargate 并不是所有地区都可用，与其他解决方案相比价格昂贵，并且有一些限制，比如不能支持持久存储。Elastic Beanstalk 为管理您的 Docker 应用程序提供了全面的端到端解决方案，提供了各种开箱即用的集成，并包括操作工具来管理应用程序的完整生命周期。Elastic Beanstalk 确实要求您接受一个非常有主见的框架和方法论，来构建、部署和运行您的应用程序，并且可能难以定制以满足您的需求。

如果您是一个有特定安全和合规要求的大型组织，或者只是希望对运行容器工作负载的基础架构拥有更大的灵活性和控制权，那么您应该考虑 ECS、EKS 和 Docker Swarm。ECS 是 AWS 的本地旗舰容器管理平台，因此拥有大量客户群体多年来一直在大规模运行容器。正如您将在本书中了解到的，ECS 与 CloudFormation 集成，可以让您使用基础设施即代码的方法定义所有集群、应用服务和容器定义，这可以与其他 AWS 资源结合使用，让您能够通过点击按钮部署完整、复杂的环境。尽管如此，ECS 的主要批评是它是 AWS 特有的专有解决方案，这意味着您无法在其他云环境中使用它，也无法在自己的基础设施上运行它。越来越多的大型组织正在寻找基础设施和云无关的云管理平台，如果这是您的目标，那么您应该考虑 EKS 或 Docker Swarm。Kubernetes 已经席卷了容器编排世界，现在是最大和最受欢迎的开源项目之一。AWS 现在提供了 EKS 这样的托管 Kubernetes 服务，这使得在 AWS 中轻松启动和运行 Kubernetes 变得非常容易，并且可以利用与 CloudFormation、弹性负载均衡（ELB）和弹性块存储（EBS）服务的核心集成。Docker Swarm 是 Kubernetes 的竞争对手，尽管它似乎已经输掉了容器编排的霸主地位争夺战，但它有一个优势，那就是作为 Docker 的本地开箱即用功能与 Docker 集成，使用熟悉的 Docker 工具非常容易启动和运行。Docker 目前确实发布了 CloudFormation 模板，并支持与 AWS 服务的关键集成，这使得在 AWS 中轻松启动和运行变得非常容易。然而，人们对这类解决方案的持久性存在担忧，因为 Docker Inc.是一个商业实体，而 Kubernetes 的日益增长的流行度和主导地位可能会迫使 Docker Inc.将未来的重点放在其付费的 Docker 企业版和其他商业产品上。

如您所见，选择适合您的解决方案时有许多考虑因素，而本书的好处在于您将学习如何使用这些方法中的每一种来在 AWS 中部署和运行 Docker 应用程序。无论您现在认为哪种解决方案更适合您，我鼓励您阅读并完成本书中的所有章节，因为您将学到的大部分内容都可以应用于其他解决方案，并且您将更有能力根据您的期望结果定制和构建全面的容器管理解决方案。

# 设置本地 Docker 环境

完成介绍后，是时候开始设置本地 Docker 环境了，您将使用该环境来测试、构建和部署本书中使用的示例应用程序的 Docker 镜像。现在，我们将专注于启动和运行 Docker，但请注意，稍后我们还将使用您的本地环境与本书中讨论的各种容器管理平台进行交互，并使用 AWS 控制台、AWS 命令行界面和 AWS CloudFormation 服务来管理所有 AWS 资源。

尽管本书的标题是 Docker on Amazon Web Services，但重要的是要注意 Docker 容器有两种类型：

+   Linux 容器

+   Windows 容器

本书专注于 Linux 容器，这些容器旨在在安装了 Docker Engine 的基于 Linux 的内核上运行。当您想要使用本地环境来构建、测试和本地运行 Linux 容器时，这意味着您必须能够访问本地基于 Linux 的 Docker Engine。如果您正在使用基于 Linux 的系统，如 Ubuntu，您可以在操作系统中本地安装 Docker Engine。但是，如果您使用 Windows 或 macOS，则需要设置一个运行 Docker Engine 的本地虚拟机，并为您的操作系统安装 Docker 客户端。

幸运的是，Docker 在 Windows 和 macOS 环境中有很好的打包和工具，使得这个过程非常简单，我们现在将讨论如何在 macOS、Windows 10 和 Linux 上设置本地 Docker 环境，以及本书中将使用的其他工具，如 Docker Compose 和 GNU Make。对于 Windows 10 环境，我还将介绍如何设置 Windows 10 Linux 子系统与本地 Docker 安装进行交互，这将为您提供一个环境，您可以在其中运行本书中使用的其他基于 Linux 的工具。

在我们继续之前，还需要注意的是，从许可的角度来看，Docker 目前有两个不同的版本，您可以在[`docs.docker.com/install/overview/`](https://docs.docker.com/install/overview/)了解更多信息。

+   社区版（CE）

+   企业版（EE）

我们将专门使用免费的社区版（Docker CE），其中包括核心 Docker 引擎。Docker CE 适用于本书中将涵盖的所有技术和服务，包括弹性容器服务（ECS）、Fargate、Docker Swarm、弹性 Kubernetes 服务（EKS）和弹性 Beanstalk。

除了 Docker，我们还需要其他一些工具来帮助自动化一些构建、测试和部署任务，这些任务将贯穿本书的整个过程：

+   Docker Compose：这允许您在本地和 Docker Swarm 集群上编排和运行多容器环境

+   Git：这是从 GitHub 分叉和克隆示例应用程序以及为本书中创建的各种应用程序和环境创建您自己的 Git 存储库所需的

+   GNU Make 3.82 或更高版本：这提供了任务自动化，允许您运行简单命令（例如`make test`）来执行给定的任务

+   jq：用于解析 JSON 的命令行实用程序

+   curl：命令行 HTTP 客户端

+   tree：用于在 shell 中显示文件夹结构的命令行客户端

+   Python 解释器：这是 Docker Compose 和我们将在后面的章节中安装的 AWS 命令行界面（CLI）工具所需的

+   pip：用于安装 Python 应用程序的 Python 包管理器，如 AWS CLI

本书中使用的一些工具仅代表性，这意味着如果您愿意，可以用替代工具替换它们。例如，您可以用另一个工具替换 GNU Make 来提供任务自动化。

您还需要的另一个重要工具是一个体面的文本编辑器 - Visual Studio Code（[`code.visualstudio.com/`](https://code.visualstudio.com/)）和 Sublime Text（[`www.sublimetext.com/`](https://www.sublimetext.com/)）是在 Windows、macOS 和 Linux 上都可用的绝佳选择。

现在，让我们讨论如何为以下操作系统安装和配置本地 Docker 环境：

+   macOS

+   Windows 10

+   Linux

# 在 macOS 环境中设置

如果您正在运行 macOS，最快的方法是安装 Docker for Mac，您可以在[`docs.docker.com/docker-for-mac/install/`](https://docs.docker.com/docker-for-mac/install/)了解更多信息，并从[`store.docker.com/editions/community/docker-ce-desktop-mac`](https://store.docker.com/editions/community/docker-ce-desktop-mac)下载。在幕后，Docker for Mac 利用本机 macOS 虚拟机框架，创建一个 Linux 虚拟机来运行 Docker Engine，并在本地 macOS 环境中安装 Docker 客户端。

首先，您需要创建一个免费的 Docker Hub 账户，然后完成注册并登录，点击**获取 Docker**按钮下载最新版本的 Docker：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/50c69c6a-219f-4dc3-9f46-ae375eeb4e3a.png)

下载 Docker for Mac

完成下载后，打开下载文件，将 Docker 图标拖到应用程序文件夹中，然后运行 Docker：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/edbdc313-3f39-4b8a-891f-6e0cabdc3429.png)安装 Docker

按照 Docker 安装向导进行操作，完成后，您应该在 macOS 工具栏上看到一个 Docker 图标：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3dcb6fe2-630f-41c2-8632-1ab3a3fa1d73.png)macOS 工具栏上的 Docker 图标

如果单击此图标并选择**首选项**，将显示 Docker 首选项对话框，允许您配置各种 Docker 设置。您可能希望立即更改的一个设置是分配给 Docker Engine 的内存，我已将其从默认的 2GB 增加到 8GB：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/9f33d629-86b3-4a08-a522-f9956e15e959.png)增加内存

此时，您应该能够启动终端并运行`docker info`命令：

```
> docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 0
Server Version: 18.06.0-ce
Storage Driver: overlay2
 Backing Filesystem: extfs
 Supports d_type: true
 Native Overlay Diff: true
...
...
```

您还可以使用`docker run`命令启动新的容器：

```
> docker run -it alpine echo "Hello World"
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
ff3a5c916c92: Pull complete
Digest: sha256:e1871801d30885a610511c867de0d6baca7ed4e6a2573d506bbec7fd3b03873f
Status: Downloaded newer image for alpine:latest
Hello World
> docker ps -a
CONTAINER ID      IMAGE   COMMAND              CREATED       STATUS                 
a251bd2c53dd      alpine  "echo 'Hello World'" 3 seconds ago Exited (0) 2 seconds ago 
> docker rm a251bd2c53dd
a251bd2c53dd
```

在上面的示例中，您必须运行基于轻量级 Alpine Linux 发行版的`alpine`镜像，并运行`echo "Hello World"`命令。`-it`标志指定您需要在交互式终端环境中运行容器，这允许您查看标准输出并通过控制台与容器进行交互。

一旦容器退出，您可以使用`docker ps`命令显示正在运行的容器，并附加`-a`标志以显示正在运行和已停止的容器。最后，您可以使用`docker rm`命令删除已停止的容器。

# 安装其他工具

正如本节前面讨论的那样，我们还需要一些其他工具来帮助自动化一些构建、测试和部署任务。在 macOS 上，其中一些工具已经包含在内，如下所述：

+   **Docker Compose**：在安装 Docker for Mac 时已经包含在内。

+   **Git**：当您安装 Homebrew 软件包管理器（我们将很快讨论 Homebrew）时，会安装 XCode 命令行实用程序，其中包括 Git。如果您使用另一个软件包管理器，可能需要使用该软件包管理器安装 Git。

+   **GNU Make 3.82 或更高版本**：macOS 包括 Make 3.81，不完全满足 3.82 版本的要求，因此您需要使用 Homebrew 等第三方软件包管理器安装 GNU Make。

+   **curl**：这在 macOS 中默认包含，因此无需安装。

+   **jq 和 tree**：这些在 macOS 中默认情况下不包括在内，因此需要通过 Homebrew 等第三方软件包管理器安装。

+   **Python 解释器**：macOS 包括系统安装的 Python，您可以使用它来运行 Python 应用程序，但我建议保持系统 Python 安装不变，而是使用 Homebrew 软件包管理器安装 Python（[`docs.brew.sh/Homebrew-and-Python`](https://docs.brew.sh/Homebrew-and-Python)）。

+   **pip**：系统安装的 Python 不包括流行的 PIP Python 软件包管理器，因此如果使用系统 Python 解释器，必须单独安装此软件。如果选择使用 Homebrew 安装 Python，这将包括 PIP。

在 macOS 上安装上述工具的最简单方法是首先安装一个名为 Homebrew 的第三方软件包管理器。您可以通过简单地浏览到 Homebrew 主页[`brew.sh/`](https://brew.sh/)来安装 Homebrew：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/18373480-92c4-4163-80c5-87b515bbcd82.png)安装 Homebrew

只需将突出显示的命令复制并粘贴到终端提示符中，即可自动安装 Homebrew 软件包管理器。完成后，您将能够使用`brew`命令安装先前列出的每个实用程序：

```
> brew install make --with-default-names
==> Downloading https://ftp.gnu.org/gnu/make/make-4.2.1.tar.bz2
Already downloaded: /Users/jmenga/Library/Caches/Homebrew/make-4.2.1.tar.bz2
==> ./configure --prefix=/usr/local/Cellar/make/4.2.1_1
==> make install
/usr/local/Cellar/make/4.2.1_1: 13 files, 959.5KB, built in 29 seconds
> brew install jq tree ==> Downloading https://homebrew.bintray.com/bottles/jq-1.5_3.high_sierra.bottle.tar.gz
Already downloaded: /Users/jmenga/Library/Caches/Homebrew/jq-1.5_3.high_sierra.bottle.tar.gz
==> Downloading https://homebrew.bintray.com/bottles/tree-1.7.0.high_sierra.bottle.1.tar.gz
Already downloaded: /Users/jmenga/Library/Caches/Homebrew/tree-1.7.0.high_sierra.bottle.1.tar.gz
==> Pouring jq-1.5_3.high_sierra.bottle.tar.gz
/usr/local/Cellar/jq/1.5_3: 19 files, 946.6KB
==> Pouring tree-1.7.0.high_sierra.bottle.1.tar.gz
/usr/local/Cellar/tree/1.7.0: 8 files, 114.3KB

```

您必须首先使用`--with-default-names`标志安装 GNU Make，这将替换在 macOS 上安装的系统版本的 Make。如果您喜欢省略此标志，则 GNU 版本的 make 将通过`gmake`命令可用，并且现有的系统版本的 make 不会受到影响。

最后，要使用 Homebrew 安装 Python，您可以运行`brew install python`命令，这将安装 Python 3 并安装 PIP 软件包管理器。请注意，当您使用`brew`安装 Python 3 时，Python 解释器通过`python3`命令访问，而 PIP 软件包管理器通过`pip3`命令访问，而不是`pip`命令：

```
> brew install python
==> Installing dependencies for python: gdbm, openssl, readline, sqlite, xz
...
...
==> Caveats
Python has been installed as
  /usr/local/bin/python3

Unversioned symlinks `python`, `python-config`, `pip` etc. pointing to
`python3`, `python3-config`, `pip3` etc., respectively, have been installed into
  /usr/local/opt/python/libexec/bin

If you need Homebrew's Python 2.7 run
  brew install python@2

Pip, setuptools, and wheel have been installed. To update them run
  pip3 install --upgrade pip setuptools wheel

You can install Python packages with
  pip3 install <package>
They will install into the site-package directory
  /usr/local/lib/python3.7/site-packages

See: https://docs.brew.sh/Homebrew-and-Python
==> Summary
/usr/local/Cellar/python/3.7.0: 4,788 files, 102.2MB
```

在 macOS 上，如果您使用通过 brew 或其他软件包管理器安装的 Python，还应将站点模块`USER_BASE/bin`文件夹添加到本地路径，因为这是 PIP 将安装任何使用`--user`标志安装的应用程序或库的位置（AWS CLI 是您将在本书后面以这种方式安装的应用程序的一个示例）：

```
> python3 -m site --user-base
/Users/jmenga/Library/Python/3.7
> echo 'export PATH=/Users/jmenga/Library/Python/3.7/bin:$PATH' >> ~/.bash_profile > source ~/.bash_profile 
```

确保在前面的示例中使用单引号，这样可以确保在您的 shell 会话中不会展开对`$PATH`的引用，而是将其作为文字值写入`.bash_profile`文件。

在前面的示例中，您使用`--user-base`标志调用站点模块，该标志告诉您用户二进制文件将安装在何处。然后，您可以将此路径的`bin`子文件夹添加到您的`PATH`变量中，并将其附加到您的主目录中的`.bash_profile`文件中，每当您生成新的 shell 时都会执行该文件，确保您始终能够执行已使用`--user`标志安装的 Python 应用程序。请注意，您可以使用`source`命令立即处理`.bash_profile`文件，而无需注销并重新登录。

# 设置 Windows 10 环境

就像对于 macOS 一样，如果您正在运行 Windows 10，最快的方法是安装 Docker for Windows，您可以在[`docs.docker.com/docker-for-windows/`](https://docs.docker.com/docker-for-windows/)上了解更多信息，并从[`store.docker.com/editions/community/docker-ce-desktop-windows`](https://store.docker.com/editions/community/docker-ce-desktop-windows)下载。在幕后，Docker for Windows 利用了称为 Hyper-V 的本机 Windows hypervisor，创建了一个虚拟机来运行 Docker 引擎，并为 Windows 安装了一个 Docker 客户端。

首先，您需要创建一个免费的 Docker Hub 帐户，以便继续进行，一旦完成注册并登录，点击**获取 Docker**按钮下载最新版本的 Docker for Windows。

完成下载后，开始安装并确保未选择使用 Windows 容器选项：

使用 Linux 容器

安装将继续，并要求您注销 Windows 以完成安装。重新登录 Windows 后，您将被提示启用 Windows Hyper-V 和容器功能：

启用 Hyper-V

您的计算机现在将启用所需的 Windows 功能并重新启动。一旦您重新登录，打开 Windows 的 Docker 应用程序，并确保选择**在不使用 TLS 的情况下在 tcp://localhost:2375 上公开守护程序**选项：

启用对 Docker 的传统客户端访问

必须启用此设置，以便允许 Windows 子系统访问 Docker 引擎。

# 安装 Windows 子系统

现在您已经安装了 Docker for Windows，接下来需要安装 Windows 子系统，该子系统提供了一个 Linux 环境，您可以在其中安装 Docker 客户端、Docker Compose 和本书中将使用的其他工具。

如果您使用的是 Windows，那么在本书中我假设您正在使用 Windows 子系统作为您的 shell 环境。

要启用 Windows 子系统，您需要以管理员身份运行 PowerShell（右键单击 PowerShell 程序，然后选择**以管理员身份运行**），然后运行以下命令：

```
PS > Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux 
```

启用此功能后，您将被提示重新启动您的机器。一旦您的机器重新启动，您就需要安装一个 Linux 发行版。您可以在文章[`docs.microsoft.com/en-us/windows/wsl/install-win10`](https://docs.microsoft.com/en-us/windows/wsl/install-win10)中找到各种发行版的链接 - 参见[安装您选择的 Linux 发行版](https://docs.microsoft.com/en-us/windows/wsl/install-win10#install-your-linux-distribution-of-choice)中的第 1 步。

例如，Ubuntu 的链接是[`www.microsoft.com/p/ubuntu/9nblggh4msv6`](https://www.microsoft.com/p/ubuntu/9nblggh4msv6)，如果您点击**获取应用程序**，您将被引导到本地机器上的 Microsoft Store 应用程序，并且您可以免费下载该应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/aeb12bd3-b610-437f-8111-a1917975729a.png)为 Windows 安装 Ubuntu 发行版

下载完成后，点击**启动**按钮，这将运行 Ubuntu 安装程序并在 Windows 子系统中安装 Ubuntu。您将被提示输入用户名和密码，假设您正在使用 Ubuntu 发行版，您可以运行`lsb_release -a`命令来显示安装的 Ubuntu 的具体版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/5dd13091-46c1-4919-8881-e44af32e2e8b.png)为 Windows 安装 Ubuntu 发行版所提供的信息适用于 Windows 10 的最新版本。对于较旧的 Windows 10 版本，您可能需要按照[`docs.microsoft.com/en-us/windows/wsl/install-win10#for-anniversary-update-and-creators-update-install-using-lxrun`](https://docs.microsoft.com/en-us/windows/wsl/install-win10#for-anniversary-update-and-creators-update-install-using-lxrun)中的说明进行操作。

请注意，Windows 文件系统被挂载到 Linux 子系统下的`/mnt/c`目录（其中`c`对应于 Windows C:驱动器），因此为了使用安装在 Windows 上的文本编辑器来修改您可以在 Linux 子系统中访问的文件，您可能需要将您的主目录更改为您的 Windows 主目录，即`/mnt/c/Users/<用户名>`，如下所示：

```
> exec sudo usermod -d /mnt/c/Users/jmenga jmenga
[sudo] password for jmenga:
```

请注意，在输入上述命令后，Linux 子系统将立即退出。如果您再次打开 Linux 子系统（点击**开始**按钮并输入**Ubuntu**），您的主目录现在应该是您的 Windows 主目录：

```
> pwd
/mnt/c/Users/jmenga
> echo $HOME
/mnt/c/Users/jmenga
```

# 在 Windows 子系统中安装 Docker for Linux

现在您已经安装了 Windows 子系统，您需要在您的发行版中安装 Docker 客户端、Docker Compose 和其他支持工具。在本节中，我将假设您正在使用 Ubuntu Xenial（16.04）发行版。

安装 Docker，请按照[`docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce`](https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce)上的说明安装 Docker：

```
> sudo apt-get update Get:1 http://security.ubuntu.com/ubuntu xenial-security InRelease [107 kB]
Hit:2 http://archive.ubuntu.com/ubuntu xenial InRelease
Get:3 http://archive.ubuntu.com/ubuntu xenial-updates InRelease [109 kB]
...
...
> sudo apt-get install \
 apt-transport-https \
 ca-certificates \
 curl \
 software-properties-common
...
...
> curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - OK> sudo add-apt-repository \
 "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
 $(lsb_release -cs) stable" > sudo apt-get update
...
...
> sudo apt-get install docker-ce
...
...
> docker --version
Docker version 18.06.0-ce, build 0ffa825
> docker info
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

在上面的示例中，您必须按照各种说明将 Docker CE 存储库添加到 Ubuntu 中。安装完成后，您必须执行`docker --version`命令来检查安装的版本，然后执行`docker info`命令来连接到 Docker 引擎。请注意，这会失败，因为 Windows 子系统是一个用户空间组件，不包括运行 Docker 引擎所需的必要内核组件。

Windows 子系统不是一种虚拟机技术，而是依赖于 Windows 内核提供的内核仿真功能，使底层的 Windows 内核看起来像 Linux 内核。这种内核仿真模式不支持支持容器的各种系统调用，因此无法运行 Docker 引擎。

要使 Windows 子系统能够连接到由 Docker for Windows 安装的 Docker 引擎，您需要将`DOCKER_HOST`环境变量设置为`localhost:2375`，这将配置 Docker 客户端连接到 TCP 端口`2375`，而不是尝试连接到默认的`/var/run/docker.sock`套接字文件：

```
> export DOCKER_HOST=localhost:2375
> docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 0
Server Version: 18.06.0-ce
Storage Driver: overlay2
 Backing Filesystem: extfs
 Supports d_type: true
 Native Overlay Diff: true
...
...
> echo "export DOCKER_HOST=localhost:2375" >> ~/.bash_profile
```

因为您在安装 Docker 和 Windows 时之前启用了**在 tcp://localhost:2375 上无需 TLS 暴露守护程序**选项，以将本地端口暴露给 Windows 子系统，Docker 客户端现在可以与在由 Docker for Windows 安装的单独的 Hyper-V 虚拟机中运行的 Docker 引擎进行通信。您还将`export DOCKER_HOST`命令添加到用户的主目录中的`.bash_profile`文件中，每次生成新的 shell 时都会执行该命令。这确保您的 Docker 客户端将始终尝试连接到正确的 Docker 引擎。

# 在 Windows 子系统中安装其他工具

在这一点上，您需要在 Windows 子系统中安装以下支持工具，我们将在本书中一直使用：

+   Python

+   pip 软件包管理器

+   Docker Compose

+   Git

+   GNU Make

+   jq

+   构建基本工具和 Python 开发库（用于构建示例应用程序的依赖项）

只需按照正常的 Linux 发行版安装程序来安装上述每个组件。Ubuntu 16.04 的 Linux 子系统发行版已经包含了 Python 3，因此您可以运行以下命令来安装 pip 软件包管理器，并设置您的环境以便能够定位可以使用`--user`标志安装的 Python 软件包：

```
> curl -O https://bootstrap.pypa.io/get-pip.py > python3 get-pip.py --user
Collecting pip
...
...
Installing collected packages: pip, setuptools, wheel
Successfully installed pip-10.0.1 setuptools-39.2.0 wheel-0.31.1
> rm get-pip.py
> python3 -m site --user-base /mnt/c/Users/jmenga/.local > echo 'export PATH=/mnt/c/Users/jmenga/.local/bin:$PATH' >> ~/.bash_profile
> source ~/.bash_profile 
```

现在，您可以使用`pip install docker-compose --user`命令来安装 Docker Compose：

```
> pip install docker-compose --user
Collecting docker-compose
...
...
Successfully installed cached-property-1.4.3 docker-3.4.1 docker-compose-1.22.0 docker-pycreds-0.3.0 dockerpty-0.4.1 docopt-0.6.2 jsonschema-2.6.0 texttable-0.9.1 websocket-client-0.48.0
> docker-compose --version
docker-compose version 1.22.0, build f46880f
```

最后，您可以使用`apt-get install`命令安装 Git、GNU Make、jq、tree、构建基本工具和 Python3 开发库：

```
> sudo apt-get install git make jq tree build-essential python3-dev
Reading package lists... Done
Building dependency tree
...
...
Setting up jq (1.5+dfsg-1) ...
Setting up make (4.1-6) ...
Processing triggers for libc-bin (2.23-0ubuntu10) ...
> git --version
git version 2.7.4
> make --version
GNU Make 4.1
Built for x86_64-pc-linux-gnu
Copyright (C) 1988-2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
> jq --version
jq-1.5-1-a5b5cbe
```

# 设置 Linux 环境

Docker 在 Linux 上有原生支持，这意味着您可以在本地操作系统中安装和运行 Docker 引擎，而无需设置虚拟机。Docker 官方支持以下 Linux 发行版（[`docs.docker.com/install/`](https://docs.docker.com/install/)）来安装和运行 Docker CE：

+   CentOS：参见[`docs.docker.com/install/linux/docker-ce/centos/`](https://docs.docker.com/install/linux/docker-ce/centos/)

+   Debian：参见[`docs.docker.com/install/linux/docker-ce/debian/`](https://docs.docker.com/install/linux/docker-ce/debian/)

+   Fedora：参见[`docs.docker.com/install/linux/docker-ce/fedora/`](https://docs.docker.com/install/linux/docker-ce/fedora/)

+   Ubuntu：参见[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)

安装完 Docker 后，您可以按照以下步骤安装完成本书所需的各种工具：

+   **Docker Compose**：请参阅[`docs.docker.com/compose/install/`](https://docs.docker.com/compose/install/)上的 Linux 选项卡。另外，由于您需要 Python 来安装 AWS CLI 工具，您可以使用`pip` Python 软件包管理器来安装 Docker Compose，就像之前在 Mac 和 Windows 上演示的那样，运行`pip install docker-compose`。

+   **Python**，**pip**，**Git**，**GNU Make**，**jq**，**tree**，**构建基本工具**和**Python3 开发库**：使用您的 Linux 发行版的软件包管理器（例如`yum`或`apt`）来安装这些工具。在使用 Ubuntu Xenial 时，可以参考上面的示例演示。

# 安装示例应用程序

现在，您已经设置好了本地环境，支持 Docker 和完成本书所需的各种工具，是时候为本课程安装示例应用程序了。

示例应用程序是一个名为**todobackend**的简单的待办事项 Web 服务，提供了一个 REST API，允许您创建、读取、更新和删除待办事项（例如*洗车*或*遛狗*）。这个应用程序是一个基于 Django 的 Python 应用程序，Django 是一个用于创建 Web 应用程序的流行框架。您可以在[`www.djangoproject.com/`](https://www.djangoproject.com/)上了解更多信息。如果您对 Python 不熟悉，不用担心 - 示例应用程序已经为您创建，您在阅读本书时需要做的就是构建和测试应用程序，将应用程序打包和发布为 Docker 镜像，然后使用本书中讨论的各种容器管理平台部署您的应用程序。

# Forking the sample application

要安装示例应用程序，您需要从 GitHub 上*fork*该应用程序（我们将很快讨论这意味着什么），这需要您拥有一个活跃的 GitHub 账户。如果您已经有 GitHub 账户，可以跳过这一步，但是如果您没有账户，可以在[`github.com`](https://github.com)免费注册一个账户：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/1101fbe8-9871-4951-b093-dd03f0c849b0.png)Signing up for GitHub

一旦您拥有一个活跃的 GitHub 账户，您就可以访问示例应用程序存储库[`github.com/docker-in-aws/todobackend`](https://github.com/docker-in-aws/todobackend)。与其克隆存储库，一个更好的方法是*fork*存储库，这意味着将在您自己的 GitHub 账户中创建一个新的存储库，该存储库与原始的`todobackend`存储库链接在一起（因此称为*fork*）。*Fork*是开源社区中的一种流行模式，允许您对*fork*存储库进行自己独立的更改。对于本书来说，这是特别有用的，因为您将对`todobackend`存储库进行自己的更改，添加一个本地 Docker 工作流来构建、测试和发布示例应用程序作为 Docker 镜像，以及在本书的进程中进行其他更改。

要*fork*存储库，请点击右上角的*fork*按钮：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c65f46fc-103c-4f1b-85dd-f0f4b55ad381.png)Forking the todobackend repository

点击分叉按钮几秒钟后，将创建一个名为`<your-github-username>/todobackend`的新存储库。此时，您可以通过单击克隆或下载按钮来克隆存储库的分支。如果您刚刚设置了一个新帐户，请选择使用 HTTPS 克隆选项并复制所呈现的 URL：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3038ca0d-2f98-4193-88d2-522a8ec14a5c.png)

获取 todobackend 存储库的 Git URL

打开一个新的终端并运行`git clone <repository-url>`命令，其中`<repository-url>`是您在前面示例中复制的 URL，然后进入新创建的`todobackend`文件夹：

```
> git clone https://github.com/<your-username>/todobackend.git
Cloning into 'todobackend'...
remote: Counting objects: 231, done.
remote: Total 231 (delta 0), reused 0 (delta 0), pack-reused 231
Receiving objects: 100% (231/231), 31.75 KiB | 184.00 KiB/s, done.
```

```
Resolving deltas: 100% (89/89), done.
> cd todobackend todobackend> 
```

在阅读本章时，我鼓励您经常提交您所做的任何更改，以及清晰标识所做更改的描述性消息。

示例存储库包括一个名为`final`的分支，该分支代表完成本书中所有章节后存储库的最终状态。如果遇到任何问题，您可以使用`git checkout final`命令将其作为参考点。您可以通过运行`git checkout master`命令切换回主分支。

如果您对 Git 不熟悉，可以参考在线的众多教程（例如，[`www.atlassian.com/git/tutorials`](https://www.atlassian.com/git/tutorials)），但通常在提交更改时，您需要执行以下命令：

```
> git pull
Already up to date.
> git diff
diff --git a/Dockerfile b/Dockerfile
index e56b47f..4a73ce3 100644
--- a/Dockerfile
+++ b/Dockerfile
-COPY --from=build /build /build
-COPY --from=build /app /app
-WORKDIR /app
+# Create app user
+RUN addgroup -g 1000 app && \
+ adduser -u 1000 -G app -D app

+# Copy and install application source and pre-built dependencies
> git status
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

  modified: src/todobackend/settings.py
  modified: src/todobackend/wsgi.py

Untracked files:
  (use "git add <file>..." to include in what will be committed)

  docker-compose.yml
  src/acceptance.bats
> git add -A > git commit -a -m "Some commit message"
> git push -u origin master
> git push
```

您应该经常检查您是否拥有存储库的最新版本，方法是运行`git pull`命令，这样可以避免混乱的自动合并和推送失败，特别是当您与其他人一起合作时。接下来，您可以使用`git diff`命令显示您对现有文件所做的任何更改，而`git status`命令则显示对现有文件的文件级更改，并标识您可能已添加到存储库的任何新文件。`git add -A`命令将所有新文件添加到存储库，而`git commit -a -m "<message>"`命令将提交所有更改（包括您使用`git add -A`添加的任何文件）并附带指定的消息。最后，您可以使用`git push`命令推送您的更改-第一次推送时，您必须使用`git push -u origin <branch>`命令指定远程分支的原点-之后您可以只使用更短的`git push`变体来推送您的更改。

一个常见的错误是忘记将新文件添加到您的 Git 存储库中，这可能直到您将存储库克隆到另一台机器上才会显现出来。在提交更改之前，始终确保运行`git status`命令以识别任何尚未被跟踪的新文件。

# 在本地运行示例应用程序

现在您已经在本地下载了示例应用程序的源代码，您现在可以构建和在本地运行该应用程序。当您将应用程序打包成 Docker 镜像时，您需要详细了解如何构建和运行您的应用程序，因此在本地运行应用程序是能够为您的应用程序构建容器的旅程的第一步。

# 安装应用程序依赖项

要运行该应用程序，您需要首先安装应用程序所需的任何依赖项。示例应用程序包括一个名为`requirements.txt`的文件，位于`src`文件夹中，其中列出了必须安装的所有必需的 Python 软件包，以便应用程序运行：

```
Django==2.0
django-cors-headers==2.1.0
djangorestframework==3.7.3
mysql-connector-python==8.0.11
pytz==2017.3
uwsgi==2.0.17
```

要安装这些要求，请确保您已更改到`src`文件夹，并配置 PIP 软件包管理器以使用`-r`标志读取要求文件。请注意，日常开发的最佳实践是在虚拟环境中安装应用程序依赖项（请参阅[`packaging.python.org/guides/installing-using-pip-and-virtualenv/`](https://packaging.python.org/guides/installing-using-pip-and-virtualenv/)），但是考虑到我们主要是为了演示目的安装应用程序，我不会采取这种方法：

```
todobackend> cd src
src> pip3 install -r requirements.txt --user
Collecting Django==2.0 (from -r requirements.txt (line 1))
...
...
Successfully installed Django-2.0 django-cors-headers-2.1.0 djangorestframework-3.7.3 mysql-connector-python-8.0.11 pytz-2017.3 uwsgi-2.0.17
```

随着时间的推移，每个依赖项的特定版本可能会更改，以确保示例应用程序继续按预期工作。

# 运行数据库迁移

安装了应用程序依赖项后，您可以运行`python3 manage.py`命令来执行各种 Django 管理功能，例如运行测试、生成静态网页内容、运行数据库迁移以及运行您的 Web 应用程序的本地实例。

在本地开发环境中，您首先需要运行数据库迁移，这意味着您的本地数据库将根据应用程序配置的适当数据库模式进行初始化。默认情况下，Django 使用 Python 附带的轻量级*SQLite*数据库，适用于开发目的，并且无需设置即可运行。因此，您只需运行`python3 manage.py migrate`命令，它将自动为您运行应用程序中配置的所有数据库迁移：

```
src> python3 manage.py migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, sessions, todo
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying sessions.0001_initial... OK
  Applying todo.0001_initial... OK
```

当您运行 Django 迁移时，Django 将自动检测是否存在现有模式，并在不存在模式时创建新模式（在前面的示例中是这种情况）。如果再次运行迁移，请注意 Django 检测到已经存在最新模式，因此不会应用任何内容：

```
src> python3 manage.py migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, sessions, todo
Running migrations:
  No migrations to apply.
```

# 运行本地开发 Web 服务器

现在本地 SQLite 数据库已经就位，您可以通过执行`python3 manage.py runserver`命令来运行应用程序，该命令将在 8000 端口上启动本地开发 Web 服务器：

```
src> python3 manage.py runserver
Performing system checks...

System check identified no issues (0 silenced).
July 02, 2018 - 07:23:49
Django version 2.0, using settings 'todobackend.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

如果您在浏览器中打开`http://localhost:8000/`，您应该会看到一个名为**Django REST framework**的网页：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a8d47b6d-4d23-462e-88ec-f9291951296a.png)todobackend 应用程序

此页面是应用程序的根，您可以看到 Django REST 框架为使用浏览器时导航 API 提供了图形界面。如果您使用`curl`命令而不是浏览器，请注意 Django 检测到一个简单的 HTTP 客户端，并且只返回 JSON 响应：

```
src> curl localhost:8000
{"todos":"http://localhost:8000/todos"}
```

如果您单击 todos 项目的超媒体链接（`http://localhost:8000/todos`），您将看到一个当前为空的待办事项列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7c7bb14a-91e3-484e-85d6-83e9d89a6767.png)待办事项列表

请注意，您可以使用 Web 界面创建具有标题和顺序的新待办事项，一旦单击 POST 按钮，它将填充待办事项列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/68f0d7ba-a263-4044-9cd5-7582841aa551.png)创建待办事项

当然，您也可以使用命令行和`curl`命令来创建新的待办事项，列出所有待办事项并更新待办事项：

```
> curl -X POST -H "Content-Type: application/json" localhost:8000/todos \
 -d '{"title": "Wash the car", "order": 2}'
{"url":"http://localhost:8000/todos/2","title":"Wash the car","completed":false,"order":2}

> curl -s localhost:8000/todos | jq
[
 {
 "url": "http://localhost:8000/todos/1",
 "title": "Walk the dog",
 "completed": false,
 "order": 1
 },
 {
 "url": "http://localhost:8000/todos/2",
 "title": "Wash the car",
 "completed": false,
 "order": 2
 }
]

> curl -X PATCH -H "Content-Type: application/json" localhost:8000/todos/2 \
 -d '{"completed": true}' {"url":"http://localhost:8000/todos/2","title":"Wash the car","completed":true,"order":1}
```

在前面的示例中，您首先使用`HTTP POST`方法创建一个新的待办事项，然后验证 Todos 列表现在包含两个待办事项，将`curl`命令的输出传输到之前安装的`jq`实用程序中以格式化返回的项目。最后，您使用`HTTP PATCH`方法对待办事项进行部分更新，将该项目标记为已完成。

您创建和修改的所有待办事项都将保存在应用程序数据库中，在这种情况下，这是一个运行在您的开发机器上的 SQLite 数据库。

# 在本地测试示例应用程序

现在您已经浏览了示例应用程序，让我们看看如何在本地运行测试以验证应用程序是否按预期运行。todobackend 应用程序包括一小组待办事项的测试，这些测试位于`src/todo/tests.py`文件中。了解这些测试的编写方式超出了本书的范围，但是知道如何运行这些测试对于能够测试、构建和最终将应用程序打包成 Docker 镜像至关重要。

在测试应用程序时，很常见的是有额外的依赖项，这些依赖项是特定于应用程序测试的，如果你正在构建应用程序以在生产环境中运行，则不需要这些依赖项。这个示例应用程序在一个名为`src/requirements_test.txt`的文件中定义了测试依赖项，该文件导入了`src/requirements.txt`中的所有核心应用程序依赖项，并添加了额外的特定于测试的依赖项：

```
-r requirements.txt
colorama==0.3.9
coverage==4.4.2
django-nose==1.4.5
nose==1.3.7
pinocchio==0.4.2
```

要安装这些依赖项，您需要运行 PIP 软件包管理器，引用`requirements_test.txt`文件：

```
src> pip3 install -r requirements_test.txt --user
Requirement already satisfied: Django==2.0 in /usr/local/lib/python3.7/site-packages (from -r requirements.txt (line 1)) (2.0)
Requirement already satisfied: django-cors-headers==2.1.0 in /usr/local/lib/python3.7/site-packages (from -r requirements.txt (line 2)) (2.1.0)
...
...
Installing collected packages: django-coverage, nose, django-nose, pinocchio
Successfully installed django-nose-1.4.5 pinocchio-0.4.2
```

现在，您可以通过运行`python3 manage.py test`命令来运行示例应用程序的测试，传入`--settings`标志，这允许您指定自定义设置配置。在示例应用程序中，有额外的测试设置，这些设置在`src/todobackend/settings_test.py`文件中定义，扩展了`src/todobackend/settings.py`中包含的默认设置，增加了测试增强功能，如规范样式格式和代码覆盖统计：

```
src> python3 manage.py test --settings todobackend.settings_test
Creating test database for alias 'default'...

Ensure we can create a new todo item
- item has correct title
- item was created
- received 201 created status code
- received location header hyperlink

Ensure we can delete all todo items
- all items were deleted
- received 204 no content status code

Ensure we can delete a todo item
- received 204 no content status code
- the item was deleted

Ensure we can update an existing todo item using PATCH
- item was updated
- received 200 ok status code

Ensure we can update an existing todo item using PUT
- item was updated
- received 200 created status code

----------------------------------------------------------------------
XML: /Users/jmenga/todobackend/src/unittests.xml
Name                              Stmts   Miss  Cover
-----------------------------------------------------
todo/__init__.py                      0      0   100%
todo/admin.py                         1      1     0%
todo/migrations/0001_initial.py       5      0   100%
todo/migrations/__init__.py           0      0   100%
todo/models.py                        6      6     0%
todo/serializers.py                   7      0   100%
todo/urls.py                          6      0   100%
todo/views.py                        17      0   100%
-----------------------------------------------------
TOTAL                                42      7    83%
----------------------------------------------------------------------
Ran 12 tests in 0.281s

OK

Destroying test database for alias 'default'...
```

请注意，Django 测试运行器会扫描存储库中的各个文件夹以寻找测试，创建一个测试数据库，然后运行每个测试。在所有测试完成后，测试运行器会自动销毁测试数据库，因此您无需执行任何手动设置或清理任务。

# 摘要

在本章中，您了解了 Docker 和容器，并了解了容器的历史以及 Docker 如何成为最受欢迎的解决方案之一，用于测试、构建、部署和运行容器工作负载。您了解了 Docker 的基本架构，其中包括 Docker 客户端、Docker 引擎和 Docker 注册表，并介绍了在使用 Docker 时将使用的各种类型的对象和资源，包括 Docker 镜像、卷、网络、服务，当然还有 Docker 容器。

我们还讨论了在 AWS 中运行 Docker 应用程序的各种选项，包括弹性容器服务、Fargate、弹性 Kubernetes 服务、弹性 Beanstalk，以及运行自己的 Docker 平台，如 Docker Swarm。

然后，您在本地环境中安装了 Docker，它在 Linux 上得到原生支持，并且在 macOS 和 Windows 平台上需要虚拟机。Docker for Mac 和 Docker for Windows 会自动为您安装和配置虚拟机，使得在这些平台上更容易地开始并运行 Docker。您还学习了如何将 Windows 子系统与 Docker for Windows 集成，这将允许您支持本书中将使用的基于*nix 的工具。

最后，您设置了 GitHub 账户，将示例应用程序存储库 fork 到您的账户，并将存储库克隆到您的本地环境。然后，您学习了如何安装示例应用程序的依赖项，如何运行本地开发服务器，如何运行数据库迁移以确保应用程序数据库架构和表位于正确位置，以及如何运行单元测试以确保应用程序按预期运行。在您能够测试、构建和发布应用程序作为 Docker 镜像之前，理解所有这些任务是很重要的。这将是下一章的重点，您将在其中创建一个完整的本地 Docker 工作流程，自动化创建适用于生产的 Docker 镜像的过程。

# 问题

1.  正确/错误：Docker 客户端使用命名管道与 Docker 引擎通信。

1.  正确/错误：Docker 引擎在 macOS 上原生运行。

1.  正确/错误：Docker 镜像会发布到 Docker 商店供下载。

1.  你安装了 Windows 子系统用于 Linux，并安装了 Docker 客户端。你的 Docker 客户端无法与 Windows 上的 Docker 通信。你该如何解决这个问题？

1.  真/假：卷、网络、容器、镜像和服务都是您可以使用 Docker 处理的实体。

1.  你通过运行`pip install docker-compose --user`命令标志来安装 Docker Compose，但是当尝试运行程序时收到了**docker-compose: not found**的消息。你该如何解决这个问题？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   Docker 概述：[`docs.docker.com/engine/docker-overview/`](https://docs.docker.com/engine/docker-overview/)

+   Docker 入门：[`docs.docker.com/get-started/`](https://docs.docker.com/get-started/)

+   Mac 上的 Docker 安装说明：[`docs.docker.com/docker-for-mac/install/`](https://docs.docker.com/docker-for-mac/install/)

+   Windows 上的 Docker 安装说明：[`docs.docker.com/docker-for-windows/install/`](https://docs.docker.com/docker-for-windows/install/)

+   Ubuntu 上的 Docker 安装说明：[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)

+   Debian 上的 Docker 安装说明：[`docs.docker.com/install/linux/docker-ce/debian/`](https://docs.docker.com/install/linux/docker-ce/debian/)

+   Centos 上的 Docker 安装说明：[`docs.docker.com/install/linux/docker-ce/centos/`](https://docs.docker.com/install/linux/docker-ce/centos/)

+   Fedora 上的 Docker 安装说明：[`docs.docker.com/install/linux/docker-ce/fedora/`](https://docs.docker.com/install/linux/docker-ce/fedora/)

+   Linux 子系统的 Windows 安装说明：[`docs.microsoft.com/en-us/windows/wsl/install-win10`](https://docs.microsoft.com/en-us/windows/wsl/install-win10)

+   macOS 的 Homebrew 软件包管理器：[`brew.sh/`](https://brew.sh/)

+   PIP 软件包管理器用户安装：[`pip.pypa.io/en/stable/user_guide/#user-installs`](https://pip.pypa.io/en/stable/user_guide/#user-installs)

+   Git 用户手册：[`git-scm.com/docs/user-manual.html`](https://git-scm.com/docs/user-manual.html)

+   GitHub 指南：[`guides.github.com/`](https://guides.github.com/)

+   分叉 GitHub 存储库：[`guides.github.com/activities/forking/`](https://guides.github.com/activities/forking/)

+   Django Web Framework: [`www.djangoproject.com/`](https://www.djangoproject.com/)

+   Django REST Framework: [`www.django-rest-framework.org/`](http://www.django-rest-framework.org/)


# 第二章：使用 Docker 构建应用程序

在上一章中，您已经介绍了示例应用程序，并且能够下载并在本地运行该应用程序。目前，您的开发环境已经设置好用于本地开发；但是，在将应用程序部署到生产环境之前，您需要能够打包应用程序及其所有依赖项，确保目标生产环境具有正确的操作系统支持库和配置，选择适当的 Web 服务器来托管您的应用程序，并且有一种机制能够将所有这些内容打包在一起，最好是一个自包含的构件，需要最少的外部配置。传统上，要可靠和一致地实现所有这些内容非常困难，但是 Docker 已经极大地改变了这一局面。通过 Docker 和支持工具，您现在有能力以比以往更快、更可靠、更一致和更可移植的方式实现所有这些内容以及更多。

在本章中，您将学习如何使用 Docker 创建一个全面的工作流程，使您能够以可移植、可重复和一致的方式测试、构建和发布应用程序。您将学习的方法有许多好处，例如，您将能够通过运行几个简单、易于记忆的命令来执行所有任务，并且无需在本地开发或构建环境中安装任何特定于应用程序或操作系统的依赖项。这使得在另一台机器上移动或配置连续交付服务来执行相同的工作流程非常容易——只要您在上一章中设置的核心基于 Docker 的环境，您就能够在任何机器上运行工作流程，而不受应用程序或编程语言的具体细节的影响。

您将学习如何使用 Dockerfile 为应用程序定义测试和运行时环境，配置支持多阶段构建，允许您在具有所有开发工具和库的镜像中构建应用程序构件，然后将这些构件复制到 Dockerfile 的其他阶段。您将利用 Docker Compose 作为一个工具来编排具有多个容器的复杂 Docker 环境，这使您能够测试集成场景，例如您的应用程序与数据库的交互，并模拟您在生产环境中运行应用程序的方式。一个重要的概念是引入构建发布镜像的概念，这是一个可以被部署到生产环境的生产就绪镜像，假设任何新的应用程序特性和功能都能正常工作。您将在本地 Docker 环境中构建和运行此发布镜像，将您的应用程序连接到数据库，然后创建验收测试，验证应用程序从外部客户端连接到您的应用程序的角度来看是否正常工作。

最后，您将使用 GNU Make 将学到的所有知识整合起来，自动化您的工作流程。完成后，您只需运行`make test`即可运行单元测试和构建应用程序构件，然后构建您的发布镜像，启动类似生产环境的环境，并通过运行`make release`运行验收测试。这将使测试和发布新的应用程序更改变得非常简单，并且可以放心地使用便携和一致的工作流在本地开发环境和任何支持 Docker 和 Docker Compose 的持续交付环境中运行。

将涵盖以下主题：

+   使用 Docker 测试和构建应用程序

+   创建多阶段构建

+   创建一个测试阶段来构建和测试应用程序构件

+   创建一个发布阶段来构建和测试发布镜像

+   使用 Docker Compose 测试和构建应用程序

+   创建验收测试

+   自动化工作流程

# 技术要求

以下列出了完成本章所需的技术要求：

+   根据第一章的说明安装先决软件

+   根据第一章的说明创建 GitHub 帐户

以下 GitHub 网址包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch2`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch2)[.](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch3)

查看以下视频，了解代码的运行情况：

[`bit.ly/2PJG2Zm`](http://bit.ly/2PJG2Zm)

# 使用 Docker 测试和构建应用程序

在上一章中，您对示例应用程序是什么以及如何在本地开发环境中测试和运行应用程序有了很好的理解。现在，您已经准备好开始创建一个 Docker 工作流程，用于测试、构建和打包应用程序成为一个 Docker 镜像。

重要的是要理解，每当您将一个应用程序打包成一个 Docker 镜像时，最佳实践是减少或消除所有开发和测试依赖项，使其成为最终打包的应用程序。按照我的约定，我将这个打包的应用程序——不包含测试和开发依赖项——称为*发布镜像*，支持持续交付的范式，即每次成功构建都应该是一个发布候选，可以在需要时发布到生产环境。

为了实现创建发布镜像的目标，一个行之有效的方法是将 Docker 构建过程分为两个阶段：

+   **测试阶段**：该阶段具有所有测试和开发依赖项，可用于编译和构建应用程序源代码成应用程序构件，并运行单元测试和集成测试。

+   **发布阶段**：该阶段将经过测试和构建的应用程序构件从测试阶段复制到一个最小化的运行时环境中，该环境已适当配置以在生产环境中运行应用程序。

Docker 原生支持这种方法，使用一个名为多阶段构建的功能，这是我们将在本书中采用的方法。现在，我们将专注于测试阶段，并在下一节转移到发布阶段。

# 创建一个测试阶段

我们将从在`todobackend`存储库的根目录创建一个`Dockerfile`开始，这意味着您的存储库结构应该看起来像这样：

```
todobackend> tree -L 2
.
├── Dockerfile
├── README.md
└── src
    ├── coverage.xml
    ├── db.sqlite3
    ├── manage.py
    ├── requirements.txt
    ├── requirements_test.txt
    ├── todo
    ├── todobackend
    └── unittests.xml

3 directories, 8 files
```

现在让我们在新创建的 Dockerfile 中定义一些指令：

```
# Test stage
FROM alpine AS test
LABEL application=todobackend
```

`FROM`指令是您在 Dockerfile 中定义的第一个指令，注意我们使用 Alpine Linux 发行版作为基础镜像。Alpine Linux 是一个极简的发行版，比传统的 Linux 发行版（如 Ubuntu 和 CentOS）的占用空间要小得多，并且自从 Docker 采用 Alpine 作为官方 Docker 镜像的首选发行版以来，在容器世界中变得非常流行。

一个你可能不熟悉的关键字是`AS`关键字，它附加到`FROM`指令，将 Dockerfile 配置为[多阶段构建](https://docs.docker.com/develop/develop-images/multistage-build/)，并将当前阶段命名为`test`。当你有一个多阶段构建时，你可以包含多个`FROM`指令，每个阶段都包括当前的`FROM`指令和后续的指令，直到下一个`FROM`指令。

接下来，我们使用`LABEL`指令附加一个名为`application`的标签，其值为`todobackend`，这对于能够识别支持 todobackend 应用程序的 Docker 镜像非常有用。

# 安装系统和构建依赖

现在我们需要安装各种系统和构建操作系统依赖项，以支持测试和构建应用程序：

```
# Test stage
FROM alpine AS test
LABEL application=todobackend

# Install basic utilities
RUN apk add --no-cache bash git
# Install build dependencies RUN apk add --no-cache gcc python3-dev libffi-dev musl-dev linux-headers mariadb-dev
RUN pip3 install wheel
```

在上面的示例中，我们安装了以下依赖项：

+   基本实用程序：在 Alpine Linux 中，软件包管理器称为`apk`，在 Docker 镜像中常用的模式是`apk add --no-cache`，它安装了引用的软件包，并确保下载的软件包不被缓存。我们安装了`bash`，这对故障排除很有用，还有`git`，因为我们将在以后使用 Git 元数据来为 Docker 发布镜像生成应用程序版本标签。

+   构建依赖：在这里，我们安装了构建应用程序所需的各种开发库。这包括`gcc`，`python3-dev`，`libffi-dev`，`musl-dev`和`linux-headers`，用于编译任何 Python C 扩展及其支持的标准库，以及`mariadb-dev`软件包，这是构建 todobackend 应用程序中 MySQL 客户端所需的。您还安装了一个名为`wheel`的 Python 软件包，它允许您构建 Python“wheels”，这是一种预编译和预构建的打包格式，我们以后会用到。

# 安装应用程序依赖

下一步是安装应用程序的依赖项，就像你在上一章中学到的那样，这意味着安装在`src/requirements.txt`和`src/requirements_test.txt`文件中定义的软件包：

```
# Test stage
FROM alpine AS test
LABEL application=todobackend

# Install basic utilities
RUN apk add --no-cache bash git

# Install build dependencies
RUN apk add --no-cache gcc python3-dev libffi-dev musl-dev linux-headers mariadb-dev
RUN pip3 install wheel

# Copy requirements
COPY /src/requirements* /build/
WORKDIR /build

# Build and install requirements
RUN pip3 wheel -r requirements_test.txt --no-cache-dir --no-input
RUN pip3 install -r requirements_test.txt -f /build --no-index --no-cache-dir
```

首先使用`COPY`指令将`src/requirements.txt`和`src/requirements_test.txt`文件复制到`/build`容器中的一个文件夹中，然后通过`WORKDIR`指令将其指定为工作目录。请注意，`/src/requirements.txt`不是您的 Docker 客户端上的物理路径 - 它是 Docker *构建上下文*中的路径，这是您在执行构建时指定的 Docker 客户端文件系统上的可配置位置。为了确保 Docker 构建过程中所有相关的应用程序源代码文件都可用，一个常见的做法是将应用程序存储库的根目录设置为构建上下文，因此在上面的示例中，`/src/requirements.txt`指的是您的 Docker 客户端上的`<path-to-repository>/src/requirements.txt`。

接下来，您使用`pip3` wheel 命令将 Python wheels 构建到`/build`工作目录中，用于所有基本应用程序和测试依赖项，使用`--no-cache-dir`标志来避免膨胀我们的镜像，使用`--no-input`标志来禁用提示用户确认。最后，您使用`pip3 install`命令将先前构建的 wheels 安装到容器中，使用`--no-index`标志指示 pip 不要尝试从互联网下载任何软件包，而是从`/build`文件夹中安装所有软件包，如`-f`标志所指定的那样。

这种方法可能看起来有点奇怪，但它基于一个原则，即您应该只构建一次您的应用程序依赖项作为可安装的软件包，然后根据需要安装构建的依赖项。稍后，我们将在发布镜像中安装相同的依赖项，确保您的发布镜像准确反映了您的应用程序经过测试和构建的确切依赖项集。

# 复制应用程序源代码并运行测试

测试阶段的最后步骤是将应用程序源代码复制到容器中，并添加支持运行测试的功能：

```
# Test stage
FROM alpine AS test
LABEL application=todobackend

# Install basic utilities
RUN apk add --no-cache bash git

# Install build dependencies
RUN apk add --no-cache gcc python3-dev libffi-dev musl-dev linux-headers mariadb-dev
RUN pip3 install wheel

# Copy requirements
COPY /src/requirements* /build/
WORKDIR /build

# Build and install requirements
RUN pip3 wheel -r requirements_test.txt --no-cache-dir --no-input
RUN pip3 install -r requirements_test.txt -f /build --no-index --no-cache-dir

# Copy source code COPY /src /app
WORKDIR /app # Test entrypoint CMD ["python3", "manage.py", "test", "--noinput", "--settings=todobackend.settings_test"]
```

在前面的例子中，您首先将整个`/src`文件夹复制到一个名为`/app`的文件夹中，然后将工作目录更改为`/app`。您可能会想为什么我们在复制需求文件时没有直接复制所有应用程序源代码。答案是，我们正在实施缓存优化，因为您的需求文件需要构建应用程序依赖项，并且通过在一个单独的较早的层中构建它们，如果需求文件保持不变（它们往往会这样做），Docker 可以利用最近构建的层的缓存版本，而不必每次构建图像时都构建和安装应用程序依赖项。

最后，我们添加了`CMD`指令，它定义了应该在基于此镜像创建和执行的容器中执行的默认命令。请注意，我们指定了与上一章中用于在本地运行应用程序测试的`python3 manage.py test`命令相同的命令。

您可能会想为什么我们不直接使用`RUN`指令在图像中运行测试。答案是，您可能希望在构建过程中收集构件，例如测试报告，这些构件更容易从您从 Docker 镜像生成的容器中复制，而不是在实际的图像构建过程中。

到目前为止，我们已经定义了 Docker 构建过程的第一个阶段，它将创建一个准备好进行测试的自包含环境，其中包括所需的操作系统依赖项、应用程序依赖项和应用程序源代码。要构建图像，您可以运行`docker build`命令，并使用名称`todobackend-test`对图像进行标记。

```
> docker build --target test -t todobackend-test . Sending build context to Docker daemon 311.8kB
Step 1/12 : FROM alpine AS test
 ---> 3fd9065eaf02
Step 2/12 : LABEL application=todobackend
 ---> Using cache
 ---> afdd1dee07d7
Step 3/12 : RUN apk add --no-cache bash git
 ---> Using cache
 ---> d9cd912ffa68
Step 4/12 : RUN apk add --no-cache gcc python3-dev libffi-dev musl-dev linux-headers mariadb-dev
 ---> Using cache
 ---> 89113207b0b8
Step 5/12 : RUN pip3 install wheel
 ---> Using cache
 ---> a866d3b1f3e0
Step 6/12 : COPY /src/requirements* /build/
 ---> Using cache
 ---> efc869447227
Step 7/12 : WORKDIR /build
 ---> Using cache
 ---> 53ced29de259
Step 8/12 : RUN pip3 wheel -r requirements_test.txt --no-cache-dir --no-input
 ---> Using cache
 ---> ba6d114360b9
Step 9/12 : RUN pip3 install -r requirements_test.txt -f /build --no-index --no-cache-dir
 ---> Using cache
 ---> ba0ebdace940
Step 10/12 : COPY /src /app
 ---> Using cache
 ---> 9ae5c85bc7cb
Step 11/12 : WORKDIR /app
 ---> Using cache
 ---> aedd8073c9e6
Step 12/12 : CMD ["python3", "manage.py", "test", "--noinput", "--settings=todobackend.settings_test"]
 ---> Using cache
 ---> 3ed637e47056
Successfully built 3ed637e47056
Successfully tagged todobackend-test:latest
```

在前面的例子中，`--target`标志允许您针对多阶段 Dockerfile 中的特定阶段进行构建。尽管我们目前只有一个阶段，但该标志允许我们仅在 Dockerfile 中有多个阶段的情况下构建测试阶段。按照惯例，`docker build`命令会在运行命令的目录中查找`Dockerfile`文件，并且命令末尾的句点指定了当前目录（例如，在本例中是应用程序存储库根目录）作为构建上下文，在构建图像时应将其复制到 Docker 引擎。

使用构建并在本地 Docker Engine 中标记为`todobackend`的映像名称构建的映像，您现在可以从映像启动一个容器，默认情况下将运行`python3 manage.py test`命令，如`CMD`指令所指定的那样：

```
todobackend>  docker run -it --rm todobackend-test
Creating test database for alias 'default'...

Ensure we can create a new todo item
- item has correct title
- item was created
- received 201 created status code
- received location header hyperlink

Ensure we can delete all todo items
- all items were deleted
- received 204 no content status code

Ensure we can delete a todo item
- received 204 no content status code
- the item was deleted

Ensure we can update an existing todo item using PATCH
- item was updated
- received 200 ok status code

Ensure we can update an existing todo item using PUT
- item was updated
- received 200 created status code
----------------------------------------------------------------------
XML: /app/unittests.xml
Name                              Stmts   Miss  Cover
-----------------------------------------------------
todo/__init__.py                      0      0   100%
todo/admin.py                         1      1     0%
todo/migrations/0001_initial.py       5      0   100%
todo/migrations/__init__.py           0      0   100%
todo/models.py                        6      6     0%
todo/serializers.py                   7      0   100%
todo/urls.py                          6      0   100%
todo/views.py                        17      0   100%
-----------------------------------------------------
TOTAL                                42      7    83%
----------------------------------------------------------------------
Ran 12 tests in 0.433s

OK

Destroying test database for alias 'default'...
```

`-it`标志指定以交互式终端运行容器，`--rm`标志将在容器退出时自动删除容器。请注意，所有测试都成功通过，因此我们知道映像中构建的应用程序在至少在当前为应用程序定义的测试方面是良好的状态。

# 配置发布阶段

有了测试阶段，我们现在有了一个映像，其中包含了所有应用程序依赖项，以一种可以在不需要编译或开发依赖项的情况下安装的格式打包，以及我们的应用程序源代码处于一个我们可以轻松验证通过所有测试的状态。

我们需要配置的下一个阶段是发布阶段，它将应用程序源代码和在测试阶段构建的各种应用程序依赖项复制到一个新的生产就绪的发布映像中。由于应用程序依赖项现在以预编译格式可用，因此发布映像不需要开发依赖项或源代码编译工具，这使我们能够创建一个更小、更精简的发布映像，减少了攻击面。

# 安装系统依赖项

要开始创建发布阶段，我们可以在 Dockerfile 的底部添加一个新的`FROM`指令，Docker 将把它视为新阶段的开始：

```
# Test stage
FROM alpine AS test
LABEL application=todobackend
.........
...# Test entrypointCMD ["python3", "manage.py", "test", "--noinput", "--settings=todobackend.settings_test"]

# Release stage
FROM alpine
LABEL application=todobackend

# Install operating system dependencies
RUN apk add --no-cache python3 mariadb-client bash
```

在上面的示例中，您可以看到发布映像再次基于 Alpine Linux 映像，这是一个非常好的选择，因为它的占用空间非常小。您可以看到我们安装了更少的操作系统依赖项，其中包括以下内容：

+   `python3`：由于示例应用程序是一个 Python 应用程序，因此需要 Python 3 解释器和运行时

+   `mariadb-client`：包括与 MySQL 应用程序数据库通信所需的系统库

+   `bash`：用于故障排除和执行入口脚本，我们将在后面的章节中讨论。

请注意，我们只需要安装这些软件包的非开发版本，而不是安装`python3-dev`和`mariadb-dev`软件包，因为我们在测试阶段编译和构建了所有应用程序依赖项的预编译轮。

# 创建应用程序用户

下一步是创建一个应用程序用户，我们的应用程序将作为该用户运行。默认情况下，Docker 容器以 root 用户身份运行，这对于测试和开发目的来说是可以的，但是在生产环境中，即使容器提供了隔离机制，作为非 root 用户运行容器仍被认为是最佳实践：

```
# Test stage
...
...
# Release stage
FROM alpine
LABEL application=todobackend

# Install operating system dependencies
RUN apk add --no-cache python3 mariadb-client bash

# Create app user
RUN addgroup -g 1000 app && \
 adduser -u 1000 -G app -D app
```

在上面的示例中，我们首先创建了一个名为`app`的组，组 ID 为`1000`，然后创建了一个名为`app`的用户，用户 ID 为`1000`，属于`app`组。

# 复制和安装应用程序源代码和依赖项

最后一步是复制先前在测试阶段构建的应用程序源代码和依赖项，将依赖项安装到发布镜像中，然后删除在此过程中使用的任何临时文件。我们还需要将工作目录设置为`/app`，并配置容器以作为前一节中创建的`app`用户运行：

```
# Test stage
...
...
# Release stage
FROM alpine
LABEL application=todobackend

# Install operating system dependencies
RUN apk add --no-cache python3 mariadb-client bash

# Create app user
RUN addgroup -g 1000 app && \
    adduser -u 1000 -G app -D app

# Copy and install application source and pre-built dependencies
COPY --from=test --chown=app:app /build /build
COPY --from=test --chown=app:app /app /app
RUN pip3 install -r /build/requirements.txt -f /build --no-index --no-cache-dir
RUN rm -rf /build

# Set working directory and application user
WORKDIR /app
USER app
```

您首先使用`COPY`指令和`--from`标志，告诉 Docker 在`--from`标志指定的阶段查找要复制的文件。在这里，我们将测试阶段镜像中的`/build`和`/app`文件夹复制到发布阶段中同名的文件夹，并配置`--chown`标志以将这些复制的文件夹的所有权更改为应用程序用户。然后我们使用`pip3`命令仅安装`requirements.txt`文件中指定的核心要求（您不需要`requirements_test.txt`中指定的依赖项来运行应用程序），使用`--no-index`标志禁用 PIP 连接到互联网下载软件包，而是使用`-f`标志引用的`/build`文件夹来查找先前在测试阶段构建并复制到此文件夹的依赖项。我们还指定`--no-cache-dir`标志以避免在本地文件系统中不必要地缓存软件包，并在安装完成后删除`/build`文件夹。

最后，您将工作目录设置为`/app`，并通过指定`USER`指令配置容器以`app`用户身份运行。

# 构建和运行发布镜像

现在我们已经完成了 Dockerfile 发布阶段的配置，是时候构建我们的新发布镜像，并验证我们是否能成功运行我们的应用程序。

要构建镜像，我们可以使用`docker build`命令，因为发布阶段是 Dockerfile 的最后阶段，所以你不需要针对特定阶段进行目标设置，就像我们之前为测试阶段所做的那样：

```
> docker build -t todobackend-release . Sending build context to Docker daemon 312.8kB
Step 1/22 : FROM alpine AS test
 ---> 3fd9065eaf02
...
...
Step 13/22 : FROM alpine
 ---> 3fd9065eaf02
Step 14/22 : LABEL application=todobackend
 ---> Using cache
 ---> afdd1dee07d7
Step 15/22 : RUN apk add --no-cache python3 mariadb-client bash
 ---> Using cache
 ---> dfe0b6487459
Step 16/22 : RUN addgroup -g 1000 app && adduser -u 1000 -G app -D app
 ---> Running in d75df9cadb1c
Removing intermediate container d75df9cadb1c
 ---> ac26efcbfea0
Step 17/22 : COPY --from=test --chown=app:app /build /build
 ---> 1f177a92e2c9
Step 18/22 : COPY --from=test --chown=app:app /app /app
 ---> ba8998a31f1d
Step 19/22 : RUN pip3 install -r /build/requirements.txt -f /build --no-index --no-cache-dir
 ---> Running in afc44357fae2
Looking in links: /build
Collecting Django==2.0 (from -r /build/requirements.txt (line 1))
Collecting django-cors-headers==2.1.0 (from -r /build/requirements.txt (line 2))
Collecting djangorestframework==3.7.3 (from -r /build/requirements.txt (line 3))
Collecting mysql-connector-python==8.0.11 (from -r /build/requirements.txt (line 4))
Collecting pytz==2017.3 (from -r /build/requirements.txt (line 5))
Collecting uwsgi (from -r /build/requirements.txt (line 6))
Collecting protobuf>=3.0.0 (from mysql-connector-python==8.0.11->-r /build/requirements.txt (line 4))
Requirement already satisfied: setuptools in /usr/lib/python3.6/site-packages (from protobuf>=3.0.0->mysql-connector-python==8.0.11->-r /build/requirements.txt (line 4)) (28.8.0)
Collecting six>=1.9 (from protobuf>=3.0.0->mysql-connector-python==8.0.11->-r /build/requirements.txt (line 4))
Installing collected packages: pytz, Django, django-cors-headers, djangorestframework, six, protobuf, mysql-connector-python, uwsgi
Successfully installed Django-2.0 django-cors-headers-2.1.0 djangorestframework-3.7.3 mysql-connector-python-8.0.11 protobuf-3.6.0 pytz-2017.3 six-1.11.0 uwsgi-2.0.17
Removing intermediate container afc44357fae2
 ---> ab2bcf89fe13
Step 20/22 : RUN rm -rf /build
 ---> Running in 8b8006ea8636
Removing intermediate container 8b8006ea8636
 ---> ae7f157d29d1
Step 21/22 : WORKDIR /app
Removing intermediate container fbd49835ca49
 ---> 55856af393f0
Step 22/22 : USER app
 ---> Running in d57b2cb9bb69
Removing intermediate container d57b2cb9bb69
 ---> 8170e923b09a
Successfully built 8170e923b09a
Successfully tagged todobackend-release:latest
```

在这一点上，我们可以运行位于发布镜像中的 Django 应用程序，但是你可能想知道它是如何工作的。当我们之前运行`python3 manage.py runserver`命令时，它启动了一个本地开发 Web 服务器，这在生产用户案例中是不推荐的，所以我们需要一个替代的 Web 服务器来在生产环境中运行我们的应用程序。

你可能已经在`requirements.txt`文件中注意到了一个名为`uwsgi`的包——这是一个非常流行的 Web 服务器，可以在生产中使用，并且对于我们的用例非常方便，可以通过 PIP 安装。这意味着`uwsgi`已经作为 Web 服务器在我们的发布容器中可用，并且可以用来提供示例应用程序。

```
> docker run -it --rm -p 8000:8000 todobackend-release uwsgi \
    --http=0.0.0.0:8000 --module=todobackend.wsgi --master *** Starting uWSGI 2.0.17 (64bit) on [Tue Jul 3 11:44:44 2018] *
compiled with version: 6.4.0 on 02 July 2018 14:34:31
os: Linux-4.9.93-linuxkit-aufs #1 SMP Wed Jun 6 16:55:56 UTC 2018
nodename: 5be4dd1ddab0
machine: x86_64
clock source: unix
detected number of CPU cores: 1
current working directory: /app
detected binary path: /usr/bin/uwsgi
!!! no internal routing support, rebuild with pcre support !!!
your memory page size is 4096 bytes
detected max file descriptor number: 1048576
lock engine: pthread robust mutexes
thunder lock: disabled (you can enable it with --thunder-lock)
uWSGI http bound on 0.0.0.0:8000 fd 4
uwsgi socket 0 bound to TCP address 127.0.0.1:35765 (port auto-assigned) fd 3
Python version: 3.6.3 (default, Nov 21 2017, 14:55:19) [GCC 6.4.0]
* Python threads support is disabled. You can enable it with --enable-threads *
Python main interpreter initialized at 0x55e9f66ebc80
your server socket listen backlog is limited to 100 connections
your mercy for graceful operations on workers is 60 seconds
mapped 145840 bytes (142 KB) for 1 cores
* Operational MODE: single process *
WSGI app 0 (mountpoint='') ready in 0 seconds on interpreter 0x55e9f66ebc80 pid: 1 (default app)
* uWSGI is running in multiple interpreter mode *
spawned uWSGI master process (pid: 1)
spawned uWSGI worker 1 (pid: 7, cores: 1)
spawned uWSGI http 1 (pid: 8)
```

我们使用`-p`标志将容器上的端口`8000`映射到主机上的端口`8000`，并执行`uwsgi`命令，传入各种配置标志，以在端口`8000`上运行应用程序，并指定`todobackend.wsgi`模块作为`uwsgi`提供的应用程序。

Web 服务器网关接口（WSGI）是 Python 应用程序用来与 Web 服务器交互的标准接口。每个 Django 应用程序都包括一个用于与 Web 服务器通信的 WSGI 模块，可以通过`<application-name>.wsgi`访问。

在这一点上，你可以浏览`http://localhost:8000`，虽然应用程序确实返回了一个响应，但你会发现 Web 服务器和应用程序缺少一堆静态内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/1666a16d-f8ad-4509-974d-aca192694abf.png)

问题在于，当你运行 Django 开发 Web 服务器时，Django 会自动生成静态内容，但是当你在生产环境中与外部 Web 服务器一起运行应用程序时，你需要自己生成静态内容。我们将在本章后面学习如何做到这一点，但是现在，你可以使用`curl`来验证 API 是否可用：

```
> curl -s localhost:8000/todos | jq
[
 {
 "url": "http://localhost:8000/todos/1",
 "title": "Walk the dog",
 "completed": false,
 "order": 1
 },
 {
 "url": "http://localhost:8000/todos/2",
 "title": "Wash the car",
 "completed": true,
 "order": 2
 }
]
```

这里需要注意的一点是，尽管我们是从头开始构建 Docker 镜像，但是 todobackend 数据与我们在第一章加载的数据相同。问题在于，第一章中创建的 SQLite 数据库位于`src`文件夹中，名为`db.sqlite3`。显然，在构建过程中我们不希望将此文件复制到我们的 Docker 镜像中，而要实现这一点的一种方法是在存储库的根目录创建一个`.dockerignore`文件：

```
# Ignore SQLite database files
/***.sqlite3

# Ignore test output and private code coverage files
/*.xml
/.coverage

# Ignore compiled Python source files
/*.pyc
/pycache# Ignore macOS directory metadata files
/.DS_Store

```

`.dockerignore`文件的工作方式类似于 Git 存储库中的`.gitignore`，用于从 Docker 构建上下文中排除文件。因为`db.sqlite3`文件位于子文件夹中，我们使用通配符 globing 模式`**`（请注意，这与`.gitignore`的行为不同，默认情况下进行 globing），这意味着我们递归地排除与通配符模式匹配的任何文件。我们还排除任何具有`.xml`扩展名的测试输出文件，代码覆盖文件，`__pycache__`文件夹以及任何具有`.pyc`扩展名的编译 Python 文件，这些文件是打算在运行时动态生成的。

如果您现在重新构建 Docker 镜像，并在本地端口`8000`上启动`uwsgi`Web 服务器，当您浏览应用程序（`http://localhost:8000`）时，您将会得到一个不同的错误：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c7ab5b6d-1d1b-47d8-8242-5e7c51cc22c4.png)

现在的问题是 todobackend 应用程序没有数据库存在，因此应用程序失败，因为它无法找到存储待办事项的表。为了解决这个问题，我们现在需要集成一个外部数据库引擎，这意味着我们需要一个解决方案来在本地使用多个容器。

# 使用 Docker Compose 测试和构建应用程序

在上一节中，您使用 Docker 命令执行了以下任务：

+   构建一个测试镜像

+   运行测试

+   构建一个发布镜像

+   运行应用程序

每次我们运行 Docker 命令时，都需要提供相当多的配置，并且试图记住需要运行的各种命令已经开始变得困难。除此之外，我们还发现，要启动应用程序的发布镜像，我们需要有一个操作的外部数据库。对于本地测试用例，运行另一个容器中的外部数据库是一个很好的方法，但是通过运行一系列带有许多不同输入参数的 Docker 命令来协调这一点很快变得难以管理。

**Docker Compose**是一个工具，允许您使用声明性方法编排多容器环境，使得编排可能需要多个容器的复杂工作流程变得更加容易。按照惯例，Docker Compose 会在当前目录中寻找一个名为`docker-compose.yml`的文件，所以让我们在`todobackend`存储库的根目录下创建这个文件，与我们的`Dockerfile`放在一起。

```
version: '2.4'

services:
  test:
    build:
      context: .
      dockerfile: Dockerfile
      target: test
  release:
    build:
      context: .
      dockerfile: Dockerfile
```

Docker Compose 文件是用 YAML 格式定义的，需要正确的缩进来推断父对象、同级对象和子对象或属性之间的正确关系。如果您以前没有使用过 YAML，可以查看[Ansible YAML Syntax guide](https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html)，这是一个对 YAML 格式的简要介绍。您也可以使用在线的 YAML linting 工具，比如 http://www.yamllint.com/来检查您的 YAML，或者在您喜欢的文本编辑器中安装 YAML 支持。

首先，我们指定了`version`属性，这是必需的，引用了我们正在使用的 Compose 文件格式语法的版本。如果您正在使用 Docker 进行本地开发和构建任务，我建议使用 Compose 文件格式的 2.x 版本，因为它包括一些有用的功能，比如对依赖服务进行健康检查，我们很快将学习如何使用。如果您正在使用 Docker Swarm 来运行您的容器，那么您应该使用 Compose 文件格式的 3.x 版本，因为这个版本支持一些与管理和编排 Docker Swarm 相关的功能。

如果您选择使用 3.x 版本，您的应用程序需要更加健壮，以处理诸如数据库在应用程序启动时不可用的情况（参见[`docs.docker.com/compose/startup-order/`](https://docs.docker.com/compose/startup-order/)），这是我们在本章后面将遇到的一个问题。

接下来，我们指定`services`属性，它定义了在我们的 Docker Compose 环境中运行的一个或多个服务。在前面的示例中，我们创建了两个服务，对应于工作流程的测试和发布阶段，然后为每个服务添加了一个`build`属性，它定义了我们希望如何为每个服务构建 Docker 镜像。请注意，`build`属性基于我们传递给`docker build`命令的各种标志，例如，当我们构建测试阶段镜像时，我们将构建上下文设置为本地文件夹，使用本地 Dockerfile 作为构建规范的图像，并仅针对测试阶段构建图像。我们不是在每次运行 Docker 命令时命令式地指定这些设置，而是声明性地定义了构建过程的期望配置，这是一个重要的区别。

当然，我们需要运行一个命令来实际构建这些服务，您可以在`todobackend`存储库的根目录运行`docker-compose build`命令。

```
> docker-compose build test
Building test
Step 1/12 : FROM alpine AS test
 ---> 3fd9065eaf02
Step 2/12 : LABEL application=todobackend
 ---> Using cache
 ---> 23e0c2657711
...
...
Step 12/12 : CMD ["python3", "manage.py", "test", "--noinput", "--settings=todobackend.settings_test"]
 ---> Running in 1ac9bded79bf
Removing intermediate container 1ac9bded79bf
 ---> f42d0d774c23

Successfully built f42d0d774c23
Successfully tagged todobackend_test:latest
```

你可以看到运行`docker-compose build test`命令实现了我们之前运行的`docker build`命令的等效效果，然而，我们不需要向`docker-compose`命令传递任何构建选项或配置，因为我们所有的特定设置都包含在`docker-compose.yml`文件中。

如果现在要从新构建的镜像运行测试，可以执行`docker-compose run`命令：

```
> docker-compose run test
Creating network "todobackend_default" with the default driver
nosetests --verbosity=2 --nologcapture --with-coverage --cover-package=todo --with-spec --spec-color --with-xunit --xunit-file=./unittests.xml --cover-xml --cover-xml-file=./coverage.xml
Creating test database for alias 'default'...

Ensure we can create a new todo item
- item has correct title
- item was created
- received 201 created status code
- received location header hyperlink
...
...
...
...
Ran 12 tests in 0.316s

OK

Destroying test database for alias 'default'...
```

您还可以扩展 Docker Compose 文件，以向服务添加端口映射和命令配置，如下例所示：

```
version: '2.4'

services:
  test:
    build:
      context: .
      dockerfile: Dockerfile
      target: test
  release:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
 - 8000:8000
 command:
 - uwsgi
 - --http=0.0.0.0:8000
 - --module=todobackend.wsgi
 - --master
```

在这里，我们指定当运行发布服务时，它应该在主机的 8000 端口和容器的 8000 端口之间创建静态端口映射，并将我们之前使用的`uwsgi`命令传递给发布容器。如果现在使用`docker-compose up`命令运行发布阶段，请注意 Docker Compose 将自动为服务构建镜像（如果尚不存在），然后启动服务：

```
> docker-compose up release
Building release
Step 1/22 : FROM alpine AS test
 ---> 3fd9065eaf02
Step 2/22 : LABEL application=todobackend
 ---> Using cache
 ---> 23e0c2657711
...
...

Successfully built 5b20207e3e9c
Successfully tagged todobackend_release:latest
WARNING: Image for service release was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
Creating todobackend_release_1 ... done
Attaching to todobackend_release_1
...
...
release_1 | *** uWSGI is running in multiple interpreter mode *
release_1 | spawned uWSGI master process (pid: 1)
release_1 | spawned uWSGI worker 1 (pid: 6, cores: 1)
release_1 | spawned uWSGI http 1 (pid: 7)
```

通常，您使用`docker-compose up`命令来运行长时间运行的服务，使用`docker-compose run`命令来运行短暂的任务。您还不能覆盖传递给`docker-compose up`的命令参数，而可以将命令覆盖传递给`docker-compose run`命令。

# 使用 Docker Compose 添加数据库服务

为了解决运行发布图像时出现的应用程序错误，我们需要运行一个应用程序可以连接到的数据库，并确保应用程序配置为使用该数据库。

我们可以通过使用 Docker Compose 添加一个名为`db`的新服务来实现这一点，该服务基于官方的 MySQL 服务器容器：

```
version: '2.4'

services:
  test:
    build:
      context: .
      dockerfile: Dockerfile
      target: test
  release:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - 8000:8000
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
  db:
 image: mysql:5.7
 environment:
 MYSQL_DATABASE: todobackend
 MYSQL_USER: todo
 MYSQL_PASSWORD: password
 MYSQL_ROOT_PASSWORD: password
```

请注意，您可以使用`image`属性指定外部图像，并且环境设置将使用数据库名为 todobackend、用户名、密码和根密码配置 MySQL 容器。

现在，您可能想知道如何配置我们的应用程序以使用 MySQL 和新的`db`服务。todobackend 应用程序包括一个名为`src/todobackend/settings_release.py`的设置文件，该文件配置了 MySQL 作为数据库后端的支持：

```
# Import base settings
from .settings import *
import os

# Disable debug
DEBUG = True

# Set secret key
SECRET_KEY = os.environ.get('SECRET_KEY', SECRET_KEY)

# Must be explicitly specified when Debug is disabled
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(',')

# Database settings
DATABASES = {
    'default': {
        'ENGINE': 'mysql.connector.django',
        'NAME': os.environ.get('MYSQL_DATABASE','todobackend'),
        'USER': os.environ.get('MYSQL_USER','todo'),
        'PASSWORD': os.environ.get('MYSQL_PASSWORD','password'),
        'HOST': os.environ.get('MYSQL_HOST','localhost'),
        'PORT': os.environ.get('MYSQL_PORT','3306'),
    },
    'OPTIONS': {
      'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"
    }
}

STATIC_ROOT = os.environ.get('STATIC_ROOT', '/public/static')
MEDIA_ROOT = os.environ.get('MEDIA_ROOT', '/public/media')
```

`DATABASES`设置包括一个配置，指定了`mysql.connector.django`引擎，该引擎提供了对 MySQL 的支持，覆盖了默认的 SQLite 驱动程序，并且您可以看到数据库名称、用户名和密码可以通过`os.environ.get`调用从环境中获取。还要注意`STATIC_ROOT`设置-这是 Django 查找静态内容（如 HTML、CSS、JavaScript 和图像）的位置-默认情况下，如果未定义此环境变量，Django 将在`/public/static`中查找。正如我们之前看到的，目前我们的 Web 应用程序缺少这些内容，因此在以后修复缺少内容问题时，请记住这个设置。

现在您了解了如何配置 todobackend 应用程序以支持 MySQL 数据库，让我们修改 Docker Compose 文件以使用`db`服务：

```
version: '2.4'

services:
  test:
    build:
      context: .
      dockerfile: Dockerfile
      target: test
  release:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - 8000:8000
 depends_on:
 db:
 condition: service_healthy
    environment:
 DJANGO_SETTINGS_MODULE: todobackend.settings_release
 MYSQL_HOST: db
 MYSQL_USER: todo
 MYSQL_PASSWORD: password
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
  db:
    image: mysql:5.7
 healthcheck:
 test: mysqlshow -u $$MYSQL_USER -p$$MYSQL_PASSWORD
      interval: 3s
      retries: 10
    environment:
      MYSQL_DATABASE: todobackend
      MYSQL_USER: todo
      MYSQL_PASSWORD: password
      MYSQL_ROOT_PASSWORD: password
```

我们首先配置`release`服务上的`environment`属性，该属性配置了将传递给容器的环境变量。请注意，对于 Django 应用程序，您可以配置`DJANGO_SETTINGS_MODULE`环境变量以指定应该使用哪些设置，这使您可以使用添加了 MySQL 支持的`settings_release`配置。此配置还允许您使用环境变量来指定 MySQL 数据库设置，这些设置必须与`db`服务的配置相匹配。

接下来，我们为`release`服务配置`depends_on`属性，该属性描述了服务可能具有的任何依赖关系。因为应用程序在启动之前必须与数据库建立有效连接，所以我们指定了`service_healthy`的条件，这意味着在 Docker Compose 尝试启动`release`服务之前，`db`服务必须通过 Docker 健康检查。为了配置`db`服务上的 Docker 健康检查，我们配置了`healthcheck`属性，它将配置 Docker 运行`db`服务容器内由`test`参数指定的命令来验证服务健康，并重试此命令，每 3 秒一次，最多重试 10 次，直到`db`服务健康为止。对于这种情况，我们使用`mysqlshow`命令，它只有在 MySQL 进程接受连接时才会返回成功的零退出代码。由于 Docker Compose 将单个美元符号解释为应该在 Docker Compose 文件中评估和替换的环境变量，我们使用双美元符号转义`test`命令中引用的环境变量，以确保该命令会直接执行`mysqlshow -u $MYSQL_USER -p$MYSQL_PASSWORD`。

在这一点上，我们可以通过在运行`release`服务的终端中按下*Ctrl* + *C*并输入`docker-compose down -v`命令（`-v`标志还将删除 Docker Compose 创建的任何卷）来拆除当前环境，然后执行`docker-compose up release`命令来测试更改：

```
> docker-compose down -v
Removing todobackend_release_1 ... done
Removing todobackend_test_run_1 ... done
Removing network todobackend_default
> docker-compose up release Creating network "todobackend_default" with the default driver
Pulling db (mysql:5.7)...
5.7: Pulling from library/mysql
683abbb4ea60: Pull complete
0550d17aeefa: Pull complete
7e26605ddd77: Pull complete
9882737bd15f: Pull complete
999c06ab75f6: Pull complete
c71d695f9937: Pull complete
c38f847c1491: Pull complete
74f9c61f40bf: Pull complete
30b252a90a12: Pull complete
9f92ebb7da55: Pull complete
90303981d276: Pull complete
Digest: sha256:1203dfba2600f140b74e375a354b1b801fa1b32d6f80fdee5f155d1e9f38c841
Status: Downloaded newer image for mysql:5.7
Creating todobackend_db_1 ... done
Creating todobackend_release_1 ... done
Attaching to todobackend_release_1
release_1 | *** Starting uWSGI 2.0.17 (64bit) on [Thu Jul 5 07:45:38 2018] *
release_1 | compiled with version: 6.4.0 on 04 July 2018 11:33:09
release_1 | os: Linux-4.9.93-linuxkit-aufs #1 SMP Wed Jun 6 16:55:56 UTC 2018
...
... *** uWSGI is running in multiple interpreter mode *
release_1 | spawned uWSGI master process (pid: 1)
release_1 | spawned uWSGI worker 1 (pid: 7, cores: 1)
release_1 | spawned uWSGI http 1 (pid: 8)
```

在上面的示例中，请注意，Docker Compose 会根据`image`属性自动拉取 MySQL 5.7 镜像，然后启动`db`服务。这将需要 15-30 秒，在此期间，Docker Compose 正在等待 Docker 报告`db`服务的健康状况。每 3 秒，Docker 运行在健康检查中配置的`mysqlshow`命令，不断重复此过程，直到命令返回成功的退出代码（即退出代码为`0`），此时 Docker 将标记容器为健康。只有在这一点上，Docker Compose 才会启动`release`服务，假设`db`服务完全可操作，`release`服务应该会成功启动。

如果您再次浏览`http://localhost:8000/todos`，您会发现即使我们添加了一个`db`服务并配置了发布服务以使用这个数据库，您仍然会收到之前在上一个截图中看到的`no such table`错误。

# 运行数据库迁移

我们仍然收到有关缺少表的错误，原因是因为我们尚未运行数据库迁移以建立应用程序期望存在的所需数据库架构。请记住，我们在本地使用`python3 manage.py migrate`命令来运行这些迁移，因此我们需要在我们的 Docker 环境中执行相同的操作。

如果您再次拆除环境，按下*Ctrl* + *C*并运行`docker-compose down -v`，一个方法是使用`docker-compose run`命令：

```
> docker-compose down -v ...
...
> docker-compose run release python3 manage.py migrate
Creating network "todobackend_default" with the default driver
Creating todobackend_db_1 ... done
Traceback (most recent call last):
  File "/usr/lib/python3.6/site-packages/mysql/connector/network.py", line 515, in open_connection
    self.sock.connect(sockaddr)
ConnectionRefusedError: [Errno 111] Connection refused
...
...
```

在上面的示例中，请注意，当您使用`docker-compose run`命令时，Docker Compose 不支持我们之前在运行`docker-compose up`时观察到的健康检查行为。这意味着您可以采取以下两种方法：

+   确保您首先运行`docker-compose up release`，然后运行`docker-compose run python3 manage.py migrate` - 这将使您的应用程序处于一种状态，直到迁移完成之前都会引发错误。

+   将迁移定义为一个单独的服务，称为`migrate`，依赖于`db`服务，启动`migrate`服务，该服务将执行迁移并退出，然后启动应用程序。

尽管很快您会看到，选项 1 更简单，但选项 2 更健壮，因为它确保在启动应用程序之前数据库处于正确的状态。选项 2 也符合我们稍后在本书中在 AWS 中编排运行数据库迁移时将采取的方法，因此我们现在将实施选项 2。

以下示例演示了我们需要进行的更改，以将迁移作为一个单独的服务运行：

```
version: '2.4'

services:
  test:
    build:
      context: .
      dockerfile: Dockerfile
      target: test
  release:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      DJANGO_SETTINGS_MODULE: todobackend.settings_release
      MYSQL_HOST: db
      MYSQL_USER: todo
      MYSQL_PASSWORD: password
  app:
 extends:
 service: release
 depends_on:
 db:
 condition: service_healthy
 ports:
 - 8000:8000
 command:
 - uwsgi
 - --http=0.0.0.0:8000
 - --module=todobackend.wsgi
 - --master
  migrate:
 extends:
 service: release
 depends_on:
 db:
 condition: service_healthy
 command:
 - python3
 - manage.py
 - migrate
 - --no-input
  db:
    image: mysql:5.7
    healthcheck:
      test: mysqlshow -u $$MYSQL_USER -p$$MYSQL_PASSWORD
      interval: 3s
      retries: 10
    environment:
      MYSQL_DATABASE: todobackend
      MYSQL_USER: todo
      MYSQL_PASSWORD: password
      MYSQL_ROOT_PASSWORD: password
```

在上面的示例中，请注意，除了`migrate`服务，我们还添加了一个名为`app`的新服务。原因是我们希望从`release`服务扩展`migrate`（如`extends`参数所定义），以便它将继承发布映像和发布服务设置，但是扩展另一个服务的一个限制是您不能扩展具有`depends_on`语句的服务。这要求我们将`release`服务更多地用作其他服务继承的基本配置，并将`depends_on`、`ports`和`command`参数从发布服务转移到新的`app`服务。

有了这个配置，我们可以拆除环境并建立我们的新环境，就像以下示例中演示的那样：

```
> docker-compose down -v ...
...
> docker-compose up migrate
Creating network "todobackend_default" with the default driver
Building migrate
Step 1/24 : FROM alpine AS test
 ---> 3fd9065eaf02
...
...
Successfully built 5b20207e3e9c
Successfully tagged todobackend_migrate:latest
WARNING: Image for service migrate was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
Creating todobackend_db_1 ... done
Creating todobackend_migrate_1 ... done
Attaching to todobackend_migrate_1
migrate_1 | Operations to perform:
migrate_1 | Apply all migrations: admin, auth, contenttypes, sessions, todo
migrate_1 | Running migrations:
migrate_1 | Applying contenttypes.0001_initial... OK
migrate_1 | Applying auth.0001_initial... OK
migrate_1 | Applying admin.0001_initial... OK
migrate_1 | Applying admin.0002_logentry_remove_auto_add... OK
migrate_1 | Applying contenttypes.0002_remove_content_type_name... OK
migrate_1 | Applying auth.0002_alter_permission_name_max_length... OK
migrate_1 | Applying auth.0003_alter_user_email_max_length... OK
migrate_1 | Applying auth.0004_alter_user_username_opts... OK
migrate_1 | Applying auth.0005_alter_user_last_login_null... OK
migrate_1 | Applying auth.0006_require_contenttypes_0002... OK
migrate_1 | Applying auth.0007_alter_validators_add_error_messages... OK
migrate_1 | Applying auth.0008_alter_user_username_max_length... OK
migrate_1 | Applying auth.0009_alter_user_last_name_max_length... OK
migrate_1 | Applying sessions.0001_initial... OK
migrate_1 | Applying todo.0001_initial... OK
todobackend_migrate_1 exited with code 0
> docker-compose up app
Building app
Step 1/24 : FROM alpine AS test
 ---> 3fd9065eaf02
...
...
Successfully built 5b20207e3e9c
Successfully tagged todobackend_app:latest
WARNING: Image for service app was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
todobackend_db_1 is up-to-date
Creating todobackend_app_1 ... done
Attaching to todobackend_app_1
app_1 | *** Starting uWSGI 2.0.17 (64bit) on [Thu Jul 5 11:21:00 2018] *
app_1 | compiled with version: 6.4.0 on 04 July 2018 11:33:09
app_1 | os: Linux-4.9.93-linuxkit-aufs #1 SMP Wed Jun 6 16:55:56 UTC 2018
...
...
```

在上面的示例中，请注意 Docker Compose 为每个服务构建新的映像，但是由于每个服务都扩展了`release`服务，因此这些构建非常快速。当您启动`migrate`服务等待`db`服务的健康检查通过时，您将观察到 15-30 秒的延迟，之后将运行迁移，创建 todobackend 应用程序期望的适当模式和表。启动`app`服务后，您应该能够与 todobackend API 交互而不会收到任何错误：

```
> curl -s localhost:8000/todos | jq
[]
```

# 生成静态网页内容

如果您浏览`http://localhost:8000/todos`，尽管应用程序不再返回错误，但网页的格式仍然是错误的。问题在于 Django 要求您运行一个名为`collectstatic`的单独的`manage.py`管理任务，它会生成静态内容并将其放置在`STATIC_ROOT`设置定义的位置。我们应用程序的发布设置将文件位置定义为`/public/static`，因此我们需要在应用程序启动之前运行`collectstatic`任务。请注意，Django 从`/static` URL 路径提供所有静态内容，例如`http://localhost:8000/static`。

有几种方法可以解决这个问题：

+   创建一个在启动时运行并在启动应用程序之前执行`collectstatic`任务的入口脚本。

+   创建一个外部卷并运行一个容器，执行`collectstatic`任务，在卷中生成静态文件。然后启动应用程序，挂载外部卷，确保它可以访问静态内容。

这两种方法都是有效的，但是为了介绍 Docker 卷的概念以及你如何在 Docker Compose 中使用它们，我们将采用第二种方法。

要在 Docker Compose 中定义卷，你可以使用顶层的`volumes`参数，它允许你定义一个或多个命名卷。

```
version: '2.4'

volumes:
 public:
 driver: local

services:
  test:
    ...
    ...
  release:
    ...
    ...
  app:
    extends:
      service: release
    depends_on:
      db:
        condition: service_healthy
    volumes:
 - public:/public
    ports:
      - 8000:8000
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
 - --check-static=/public
  migrate:
    ...
    ...
  db:
    ...
    ...
```

在上面的例子中，你添加了一个名为`public`的卷，并将驱动程序指定为本地，这意味着它是一个标准的 Docker 卷。然后你在 app 服务中使用`volumes`参数将 public 卷挂载到容器中的`/public`路径，最后你配置`uwsgi`来从`/public`路径为静态内容提供服务，这避免了昂贵的应用程序调用 Python 解释器来提供静态内容。

在销毁当前的 Docker Compose 环境后，生成静态内容只需要使用`docker-compose run`命令。

```
> docker-compose down -v ...
...
> docker-compose up migrate
...
...
> docker-compose run app python3 manage.py collectstatic --no-input
Starting todobackend_db_1 ... done
Copying '/usr/lib/python3.6/site-packages/django/contrib/admin/static/admin/js/prepopulate.js'
Traceback (most recent call last):
  File "manage.py", line 15, in <module>
    execute_from_command_line(sys.argv)
  File "/usr/lib/python3.6/site-packages/django/core/management/__init__.py", line 371, in execute_from_command_line
    utility.execute()
...
...
PermissionError: [Errno 13] Permission denied: '/public/static'
```

在上面的例子中，`collectstatic`任务失败，因为默认情况下卷是以 root 创建的，而容器是以 app 用户运行的。为了解决这个问题，我们需要在`Dockerfile`中预先创建`/public`文件夹，并将 app 用户设置为该文件夹的所有者。

```
# Test stage
...
...
# Release stage
FROM alpine
LABEL application=todobackend
...
...
# Copy and install application source and pre-built dependencies
COPY --from=test --chown=app:app /build /build
COPY --from=test --chown=app:app /app /app
RUN pip3 install -r /build/requirements.txt -f /build --no-index --no-cache-dir
RUN rm -rf /build

# Create public volume
RUN mkdir /public
RUN chown app:app /public
VOLUME /public

# Set working directory and application user
WORKDIR /app
USER app
```

请注意，上面显示的方法仅适用于使用 Docker 卷挂载创建的卷，这是 Docker Compose 在你没有在 Docker Engine 上指定主机路径时使用的方法。如果你指定了主机路径，卷将被绑定挂载，这会导致卷默认具有 root 所有权，除非你在主机上预先创建具有正确权限的路径。当我们使用弹性容器服务时，我们将在以后遇到这个问题，所以请记住这一点。

因为你修改了 Dockerfile，你需要告诉 Docker Compose 重新构建所有镜像，你可以使用`docker-compose build`命令来实现。

```
> docker-compose down -v
...
...
> docker-compose build Building test
Step 1/13 : FROM alpine AS test
...
...
Building release
...
...
Building app
...
...
Building migrate
...
...
> docker-compose up migrate
...
...
> docker-compose run app python3 manage.py collectstatic --no-input
Copying '/usr/lib/python3.6/site-packages/django/contrib/admin/static/admin/js/prepopulate.js'
Copying '/usr/lib/python3.6/site-packages/django/contrib/admin/static/admin/js/SelectFilter2.js'
Copying '/usr/lib/python3.6/site-packages/django/contrib/admin/static/admin/js/change_form.js'
Copying '/usr/lib/python3.6/site-packages/django/contrib/admin/static/admin/js/inlines.min.js'
...
...
> docker-compose up app
```

如果你现在浏览`http://localhost:8000`，正确的静态内容应该被显示出来。

在 Docker Compose 中定义本地卷时，当你运行`docker-compose down -v`命令时，卷将自动销毁。如果你希望独立于 Docker Compose 持久存储，你可以定义一个外部卷，然后你需要负责创建和销毁它。更多详情请参阅[`docs.docker.com/compose/compose-file/compose-file-v2/#external`](https://docs.docker.com/compose/compose-file/compose-file-v2/#external)。

# 创建验收测试

现在应用程序已正确配置，为发布阶段配置的最后一个任务是定义验收测试，以验证应用程序是否按预期工作。验收测试的目的是确保您构建的发布镜像在尽可能接近生产环境的环境中工作，在本地 Docker 环境的约束条件下。至少，如果您的应用程序是 Web 应用程序或 API 服务，比如 todobackend 应用程序，您可能只需验证应用程序返回有效的 HTTP 响应，或者您可能运行关键功能，比如创建项目、更新项目和删除项目。

对于 todobackend 应用程序，我们将创建一些基本测试来演示这种方法，使用一个名为 BATS（Bash 自动化测试系统）的工具。BATS 非常适合更喜欢使用 bash 的系统管理员，并利用开箱即用的工具来执行测试。

要开始使用 BATS，我们需要在**todobackend**存储库的`src`文件夹中使用 BATS 语法创建一个名为`acceptance.bats`的测试脚本，您可以在[`github.com/sstephenson/bats`](https://github.com/sstephenson/bats)上了解更多信息：

```
setup() {
  url=${APP_URL:-localhost:8000}
  item='{"title": "Wash the car", "order": 1}'
  location='Location: ([^[:space:]]*)'
  curl -X DELETE $url/todos
}

@test "todobackend root" {
  run curl -oI -s -w "%{http_code}" $APP_URL
  [ $status = 0 ]
  [ $output = 200 ]
}

@test "todo items returns empty list" {
  run jq '. | length' <(curl -s $url/todos)
  [ $output = 0 ]
}

@test "create todo item" {
  run curl -i -X POST -H "Content-Type: application/json" $url/todos -d "$item"
  [ $status = 0 ]
  [[ $output =~ "201 Created" ]] || false
  [[ $output =~ $location ]] || false
  [ $(curl ${BASH_REMATCH[1]} | jq '.title') = $(echo "$item" | jq '.title') ]
}

@test "delete todo item" {
  run curl -i -X POST -H "Content-Type: application/json" $url/todos -d "$item"
  [ $status = 0 ]
  [[ $output =~ $location ]] || false
  run curl -i -X DELETE ${BASH_REMATCH[1]}
  [ $status = 0 ]
  [[ $output =~ "204 No Content" ]] || false
  run jq '. | length' <(curl -s $APP_URL/todos)
  [ $output = 0 ]
}
```

BATS 文件包括一个`setup()`函数和一些测试用例，每个测试用例都以`@test`标记为前缀。`setup()`函数是一个特殊的函数，在每个测试用例运行之前都会运行，用于定义公共变量并确保应用程序状态在每个测试之前保持一致。您可以看到我们设置了一些在各种测试用例中使用的变量：

+   `url`：定义了要测试的应用程序的 URL。这由`APP_URL`环境变量定义，默认为`localhost:8000`，如果未定义`APP_URL`。

+   `item`：以 JSON 格式定义了一个测试 Todo 项，该项在测试期间通过 Todos API 创建。

+   `location`：定义了一个正则表达式，用于定位和捕获在创建 Todo 项时返回的 HTTP 响应中的 Location 标头的值。正则表达式的`([^[:space:]]*)`部分捕获零个或多个字符，直到遇到空格（由`[:space:]`指示）为止。例如，如果位置标头是`Location: http://localhost:8000/todos/53`，正则表达式将捕获`http://localhost:8000/todos/53`。

+   `curl`命令：最后的设置任务是删除数据库中的所有待办事项，您可以通过向`/todos`URL 发送 DELETE 请求来实现。这确保了每次测试运行时 todobackend 数据库都是干净的，减少了不同测试引入破坏其他测试的副作用的可能性。

BATS 文件接下来定义了几个测试用例：

+   `todobackend root`：这包括`run`函数，该函数运行指定的命令并将命令的退出代码捕获在一个名为 status 的变量中，将命令的输出捕获在一个名为`output`的变量中。对于这种情况，测试运行`curl`命令的特殊配置，该配置仅捕获返回的 HTTP 状态代码，然后通过调用`[ $status = 0 ]`来验证`curl`命令成功完成，并通过调用`[ $output = 200 ]`来验证返回的 HTTP 状态代码是 200 代码。这些测试是常规的 shell *测试表达式*，相当于许多编程语言中找到的规范`assert`语句。

+   `todo items returns empty list`：这个测试用例使用`jq`命令传递调用`/todos`路径的输出。请注意，由于不能在特殊的`run`函数中使用管道，我已经使用了 bash 进程替换语法`<(...)`，使`curl`命令的输出看起来像是被`jq`命令读取的文件。

+   创建待办事项：首先创建一个待办事项，检查返回的退出代码是否为零，然后使用* bash 条件表达式*（如`[[...]]`语法所示）来验证`curl`命令的输出是否包含 HTTP 响应中的`201 Created`，这是创建事项时的标准响应。在使用 bash 条件表达式时，重要的是要注意，如果条件表达式失败，BATS 不会检测到错误，因此我们使用`|| false`特殊语法，该语法仅在条件表达式失败并返回非零响应`false`时才会被评估，如果测试表达式失败，测试用例将失败。条件表达式使用`=~`正则表达式运算符（此运算符在条件表达式中不可用，因此我们使用 bash 测试表达式），第二个条件表达式评估了设置函数中定义的`location`正则表达式。最后一个命令使用特殊的`BASH_REMATCH`变量，其中包含最近一次条件表达式评估的结果，本例中是在 Location 标头中匹配的 URL。这允许我们在创建待办事项时捕获返回的位置，并验证创建的事项是否与我们发布的事项匹配。

+   删除待办事项：这将创建一个待办事项，捕获返回的位置，删除该事项，然后验证事项是否被删除，验证数据库中的待办事项数量在删除后是否为零。请记住，设置函数在每个测试用例运行之前运行，它会清除所有待办事项，因此在这个测试用例开始时，待办事项数量始终为零，创建和删除事项的操作应该总是将数量返回为零。此测试用例中使用的各种命令基于“创建待办事项”测试用例中介绍的概念，因此我不会详细描述每个命令。

现在我们已经定义了一套验收测试，是时候修改 Docker 环境，以支持在应用程序成功启动后执行这些测试。

我们首先需要将`curl`，`bats`和`jq`软件包添加到 todobackend 存储库根目录下的`Dockerfile`中。

```
# Test stage
FROM alpine AS test
LABEL application=todobackend
...
...
# Release stage
FROM alpine
LABEL application=todobackend

# Install dependencies
RUN apk add --no-cache python3 mariadb-client bash curl bats jq
...
...
```

接下来，我们需要向`docker-compose.yml`文件添加一个名为`acceptance`的新服务，该服务将等待`app`服务健康，然后运行验收测试。

```
version: '2.4'

volumes:
  public:
    driver: local

services:
  test:
    ...
    ...
  release:
    ...
    ...
  app:
    extends:
      service: release
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - public:/public
 healthcheck:
 test: curl -fs localhost:8000
      interval: 3s
 retries: 10
    ports:
      - 8000:8000
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
      - --check-static=/public
  acceptance:
 extends:
 service: release
 depends_on:
 app:
 condition: service_healthy
 environment:
 APP_URL: http://app:8000
 command:
 - bats 
 - acceptance.bats
  migrate:
    ...
    ...
  db:
    ...
    ...
```

首先，我们为`app`服务添加了一个`healthcheck`属性，它使用`curl`实用程序来检查与本地 Web 服务器端点的连接。然后，我们定义了接受服务，我们从`release`镜像扩展，并配置了`APP_URL`环境变量，该变量配置了应该针对执行接受测试的正确 URL，而`command`和`depends_on`属性用于在`app`服务健康时运行接受测试。

有了这个配置，现在您需要拆除当前的环境，重建所有镜像，并执行各种步骤来启动应用程序，除非您到了即将运行`docker-compose up app`命令的时候，您现在应该运行`docker-compose up acceptance`命令，因为这将自动在后台启动`app`服务：

```
> docker-compose down -v
...
...
> docker-compose build
...
...
> docker-compose up migrate
...
...
> docker-compose run app python3 manage.py collectstatic --no-input
...
...
> docker-compose up acceptance todobackend_db_1 is up-to-date
Creating todobackend_app_1 ... done
Creating todobackend_acceptance_1 ... done
Attaching to todobackend_acceptance_1
acceptance_1 | Processing secrets []...
acceptance_1 | 1..4
acceptance_1 | ok 1 todobackend root
acceptance_1 | ok 2 todo items returns empty list
acceptance_1 | ok 3 create todo item
acceptance_1 | ok 4 delete todo item
todobackend_acceptance_1 exited with code 0
```

正如您所看到的，所有测试都通过了，每个测试都显示了`ok`状态。

# 自动化工作流程

到目前为止，您已成功配置了 Docker Compose 来构建、测试和创建样本应用程序的工作本地环境，包括 MySQL 数据库集成和接受测试。现在，您可以用少数命令来启动这个环境，但即使使用 Docker Compose 大大简化了您需要运行的命令，仍然很难记住要使用哪些命令以及以什么顺序。理想情况下，我们希望有一个单一的命令来运行完整的工作流程，这就是 GNU Make 这样的工具非常有用的地方。

Make 已经存在很长时间了，仍然被认为是许多 C 和 C++应用程序的首选构建工具。任务自动化是 Make 的一个关键特性，能够以简单的格式定义任务或目标，并且可以通过单个命令调用，这使得 Make 成为一个流行的自动化工具，特别是在处理 Docker 容器时。

按照惯例，make 会在当前工作目录中寻找一个名为 Makefile 的文件，您可以创建一个非常简单的 Makefile，就像这里演示的那样：

```
hello:
    @ echo "Hello World"
    echo "How are you?"
```

在前面的示例中，您创建了一个名为`hello`的*目标*，其中包含两个 shell 命令，您可以通过运行`make <target>`或在这个例子中运行`make hello`来执行这些命令。每个目标可以包括一个或多个命令，这些命令按照提供的顺序执行。

需要注意的一点是，make 期望在为给定目标定义各种命令时使用制表符（而不是空格），因此如果你收到缺少分隔符的错误，比如`Makefile:2: *** missing separator. Stop.`，请检查你是否使用了制表符来缩进每个命令。

```
> make hello
Hello World
echo "How are you?"
How are you?
```

在上面的例子中，你可以看到每个命令的输出都显示在屏幕上。请注意，第一个命令上的特殊字符`@`会抑制每个命令的回显。

任何像 Sublime Text 或 Visual Studio Code 这样的体面的现代文本编辑器都应该自动处理 Makefiles 中的制表符。

在使用 Makefiles 进行任务自动化时，你应该执行一个重要的清理工作，即配置一个名为`.PHONY`的特殊目标，并列出你将要执行的每个目标的名称：

```
.PHONY: hello

hello:
    @ echo "Hello World"
    echo "How are you?"
```

因为`make`实际上是一个用于编译源代码文件的构建工具，所以`.PHONY`目标告诉 make，如果它看到一个名为`hello`的文件，它仍然应该运行该目标。如果你没有指定`.PHONY`，并且本地目录中有一个名为`hello`的文件，make 将退出并声明`hello`文件已经构建完成。当你使用 make 来自动化任务时，这显然没有多大意义，所以你应该始终使用`.PHONY`目标来避免任何奇怪的意外。

# 自动化测试阶段

既然你已经了解了如何制作，让我们修改我们的 Makefile，以执行实际有用的操作，并执行测试阶段执行的各种操作。回想一下，测试阶段涉及构建 Dockerfile 的第一个阶段作为一个名为`test`的服务，然后运行`test`服务，默认情况下将运行`python3 manage.py test`命令，执行应用程序单元测试：

```
.PHONY: test

test:
    docker-compose build --pull release
    docker-compose build
    docker-compose run test
```

请注意，我们实际上并没有在 Docker Compose 文件中构建`test`服务，而是构建了发布服务并指定了`--pull`标志，这确保 Docker 始终检查 Docker 镜像中的任何更新版本。我们以这种方式构建`release`服务，因为我们只想构建整个`Dockerfile`一次，而不是在每个阶段执行时重新构建`Dockerfile`。

这可以防止一个不太可能但仍然可能发生的情况，即在发布阶段重新构建时，您可能会拉取一个更新的基础镜像，这可能导致与您在测试阶段测试的不同的运行时环境。我们还立即运行 docker-compose build 命令，这可以确保在运行测试之前构建所有服务。因为我们在前一个命令中构建了整个`Dockerfile`，这将确保其他服务的缓存镜像都更新为最新的镜像构建。

# 自动化发布阶段

完成测试阶段后，我们接下来运行发布阶段，这需要我们执行以下操作：

+   运行数据库迁移

+   收集静态文件

+   启动应用程序

+   运行验收测试

以下演示了在 Makefile 中创建一个名为`release`的目标：

```
.PHONY: test release

test:
    docker-compose build --pull release
    docker-compose build
    docker-compose run test

release:
 docker-compose up --abort-on-container-exit migrate
 docker-compose run app python3 manage.py collectstatic --no-input
 docker-compose up --abort-on-container-exit acceptance
```

请注意，我们执行所需命令的每一个时，都会有一个小变化，即在每个`docker-compose up`命令中添加`--abort-on-container-exit`命令。默认情况下，`docker-compose up`命令不会返回非零退出代码，如果命令启动的任何容器失败。这个标志允许您覆盖这一点，并指定任何由`docker-compose up`命令启动的服务失败，那么 Docker Compose 应该以错误退出。如果您希望在出现错误时使您的 make 命令失败，设置此标志是很重要的。

# 完善工作流程

有一些更小的增强可以应用到工作流程中，这将确保我们有一个强大、一致和可移植的测试和构建应用程序的机制。

# 清理 Docker 环境

在本章中，我们一直通过运行`docker-compose down`命令来清理我们的环境，该命令停止并销毁与 todobackend Docker Compose 环境相关的任何容器。

在构建 Docker 镜像时，您需要注意的另一个方面是孤立或悬空的镜像的概念，这些镜像已经被新版本取代。您可以通过运行`docker images`命令来了解这一点，我已经用粗体标出了哪些镜像是悬空的：

```
> docker images REPOSITORY            TAG        IMAGE ID        CREATED            SIZEtodobackend_app       latest     ca3e62e168f2    13 minutes ago     137MBtodobackend_migrate   latest     ca3e62e168f2    13 minutes ago     137MB
todobackend_release   latest     ca3e62e168f2    13 minutes ago     137MB
<none>                <none>     03cc5d44bd7d    14 minutes ago     253MB
<none>                <none>     e88666a35577    22 minutes ago     137MB
<none>                <none>     8909f9001297    23 minutes ago     253MB
<none>                <none>     3d6f9a5c9322    2 hours ago        137MB todobackend_test      latest     60b3a71946cc    2 hours ago        253MB
<none>                <none>     53d19a2de60d    9 hours ago        136MB
<none>                <none>     54f0fb70b9d0    15 hours ago       135MB alpine                latest     11cd0b38bc3c    23 hours ago       4.41MB
```

请注意，每个突出显示的图像都没有存储库和标签，因此它们被称为孤立或悬空。这些悬空图像没有用处，占用资源和存储空间，因此最好定期清理这些图像，以确保 Docker 环境的性能。回到我们的 Dockerfile，我们在每个阶段添加了`LABEL`指令，这允许轻松识别与我们的 todobackend 应用相关的图像。

我们可以利用这些标签来定位为 todobackend 应用构建的悬空图像，因此让我们在 Makefile 中添加一个名为`clean`的新目标，该目标关闭 Docker Compose 环境并删除悬空图像。

```
.PHONY: test release clean

test:
    docker-compose build --pull release
    docker-compose build
    docker-compose run test

release:
    docker-compose up --abort-on-container-exit migrate
    docker-compose run app python3 manage.py collectstatic --no-input
    docker-compose up --abort-on-container-exit acceptance

clean:
 docker-compose down -v
 docker images -q -f dangling=true -f label=application=todobackend | xargs -I ARGS docker rmi -f --no-prune ARGS
```

使用`-q`标志仅打印出图像 ID，然后使用`-f`标志添加过滤器，指定仅显示具有`application=todobackend`标签的悬空图像。然后将此命令的输出导入到`xargs`命令中，`xargs`捕获过滤图像列表并将其传递给`docker rmi -f --no-prune`命令，根据`-f`标志强制删除图像，并使用`--no-prune`标志确保不删除包含当前标记图像层的未标记图像。我们在这里使用`xargs`是因为它能智能地处理图像列表-例如，如果没有要删除的图像，那么`xargs`会在没有错误的情况下静默退出。

以下演示了运行`make clean`命令的输出：

```
> make test
...
...
> make release
...
...
> make clean
docker-compose down -v
Stopping todobackend_app_1 ... done
Stopping todobackend_db_1 ... done
Removing todobackend_app_run_2 ... done
Removing todobackend_app_1 ... done
Removing todobackend_app_run_1 ... done
Removing todobackend_migrate_1 ... done
Removing todobackend_db_1 ... done
Removing todobackend_test_run_1 ... done
Removing network todobackend_default
Removing volume todobackend_public
docker images -q -f dangling=true -f label=application=todobackend | xargs -I ARGS docker rmi -f --no-prune ARGS
Deleted: sha256:03cc5d44bd7dec8d535c083dd5a8e4c177f113bc49f6a97d09f7a1deb64b7728
Deleted: sha256:6448ea330f415f773fc4cd5fe35862678ac0e35a1bf24f3780393eb73637f765
Deleted: sha256:baefcaca3929d6fc419eab06237abfb6d9ba9a1ba8d5623040ea4f49b2cc22d4
Deleted: sha256:b1dca5a87173bfa6a2c0c339cdeea6287e4207f34869a2da080dcef28cabcf6f
...
...
```

当运行`make clean`命令时，您可能会注意到一件事，即停止 todobackend 应用服务需要一些时间，实际上，需要大约 10 秒才能停止。这是因为在停止容器时，Docker 首先向容器发送 SIGTERM 信号，这会向容器发出即将被终止的信号。默认情况下，如果容器在 10 秒内没有退出，Docker 会发送 SIGKILL 信号，强制终止容器。

问题在于我们应用容器中运行的`uwsgi`进程默认情况下会忽略 SIGTERM 信号，因此我们需要在配置`uwsgi`的 Docker Compose 文件中添加`--die-on-term`标志，以确保它能够优雅地和及时地关闭，如果收到 SIGTERM 信号。

```
version: '2.4'

volumes:
  public:
    driver: local

services:
  test:
    ...
    ...
  release:
    ...
    ...
  app:
    extends:
      service: release
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - public:/public
    healthcheck:
      test: curl -fs localhost:8000
      interval: 3s
      retries: 10
    ports:
      - 8000:8000
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
      - --check-static=/public
 - --die-on-term
 - --processes=4
 - --threads=2
  acceptance:
    ...
    ...
  migrate:
    ...
    ...
  db:
    ...
    ...
```

在上面的例子中，我还添加了`--processes`和`--threads`标志，这些标志启用并发处理。您可以在[`uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html#adding-concurrency-and-monitoring`](https://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html#adding-concurrency-and-monitoring)中了解更多配置选项。

# 使用动态端口映射

当前，发布阶段工作流程使用静态端口映射运行应用程序，其中 app 服务容器上的端口 8000 映射到 Docker Engine 上的端口`8000`。尽管在本地运行时通常可以正常工作（除非有其他使用端口 8000 的应用程序），但是在远程持续交付构建服务上运行发布阶段工作流程时可能会导致问题，该服务可能正在为许多不同的应用程序运行多个构建。

更好的方法是使用动态端口映射，将`app`服务容器端口映射到 Docker Engine 上当前未使用的动态端口。端口是从所谓的*临时端口范围*中选择的，这是一个为应用程序动态使用保留的端口范围。

要配置动态端口映射，您需要在`docker-compose.yml`文件中的`app`服务中更改端口映射：

```
version: '2.4'

volumes:
  public:
    driver: local

services:
  test:
    ...
    ...
  release:
    ...
    ...
  app:
    extends:
      service: release
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - public:/public
    healthcheck:
      test: curl -fs localhost:8000
      interval: 3s
      retries: 10
    ports:
 - 8000
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
      - --check-static=/public
      - --die-on-term
      - --processes=4
      - --threads=2
  acceptance:
    ...
    ...
  migrate:
    ...
    ...
  db:
    ...
    ...
```

在上面的例子中，我们只是将端口映射从`8000:8000`的静态映射更改为`8000`，这样就可以启用动态端口映射。有了这个配置，一个问题是您事先不知道将分配什么端口，但是您可以使用`docker-compose port <service> <container-port>`命令来确定给定服务在给定容器端口上的当前动态端口映射：

```
> docker-compose port app 8000
0.0.0.0:32768
```

当然，与其每次手动输入此命令，我们可以将其纳入自动化工作流程中：

```
.PHONY: test release clean

test:
    docker-compose build --pull release
    docker-compose build
    docker-compose run test

release:
    docker-compose up --exit-code-from migrate migrate
    docker-compose run app python3 manage.py collectstatic --no-input
    docker-compose up --exit-code-from acceptance acceptance
 @ echo App running at http://$$(docker-compose port app 8000 | sed s/0.0.0.0/localhost/g) clean:
    docker-compose down -v
    docker images -q -f dangling=true -f label=application=todobackend | xargs -I ARGS docker rmi -f --no-prune ARGS
```

在上面的例子中，我们使用命令替换来获取当前的端口映射，并将输出传输到一个`sed`表达式，将`0.0.0.0`替换为`localhost`。请注意，因为 GNU Make 将美元符号解释为 Make 变量引用，如果您希望 shell 命令执行时评估单个美元符号，则需要双重转义美元符号（`$$`）。

有了这个配置，`make release`命令的输出现在将完成如下：

```
> make release
...
...
docker-compose run app bats acceptance.bats
Starting todobackend_db_1 ... done
1..4
ok 1 todobackend root
ok 2 todo items returns empty list
ok 3 create todo item
ok 4 delete todo item
App running at http://localhost:32771
```

# 添加版本目标

对应用程序进行版本控制非常重要，特别是在构建 Docker 镜像时，您希望区分各种镜像。稍后，当我们发布我们的 Docker 镜像时，我们将需要在每个发布的镜像上包含一个版本标签，版本控制的一个简单约定是在应用程序存储库中使用当前提交的 Git 提交哈希。

以下演示了如何在一个 Make 变量中捕获这个，并显示当前版本：

```
.PHONY: test release clean version

export APP_VERSION ?= $(shell git rev-parse --short HEAD)

version:
 @ echo '{"Version": "$(APP_VERSION)"}'

test:
    docker-compose build --pull release
    docker-compose build
    docker-compose run test

release:
    docker-compose up --abort-on-container-exit migrate
    docker-compose run app python3 manage.py collectstatic --no-input
    docker-compose up --abort-on-container-exit acceptance
    @ echo App running at http://$$(docker-compose port app 8000 | sed s/0.0.0.0/localhost/g)clean:
    docker-compose down -v
    docker images -q -f dangling=true -f label=application=todobackend | xargs -I ARGS docker rmi -f --no-prune ARGS
```

我们首先声明一个名为`APP_VERSION`的变量，并在前面加上`export`关键字，这意味着该变量将在每个目标的环境中可用。然后，我们使用一个名为`shell`的 Make 函数来执行`git rev-parse --short HEAD`命令，该命令返回当前提交的七个字符的短哈希。最后，我们添加一个名为`version`的新目标，它简单地以 JSON 格式打印版本到终端，这在本书后面当我们自动化应用程序的持续交付时将会很有用。请注意，`make`使用美元符号来引用变量，也用来执行 Make 函数，您可以在[`www.gnu.org/software/make/manual/html_node/Functions.html`](https://www.gnu.org/software/make/manual/html_node/Functions.html)了解更多信息。

如果只运行`make`命令而没有指定目标，make 将执行 Makefile 中的第一个目标。这意味着，对于我们的情况，只运行`make`将输出当前版本。

以下演示了运行`make version`命令：

```
> make version
{"Version": "5cd83c0"}
```

# 测试端到端工作流

此时，我们本地 Docker 工作流的所有部分都已就位，现在是审查工作流并验证一切是否正常运行的好时机。

核心工作流现在包括以下任务：

+   运行测试阶段 - `make test`

+   运行发布阶段 - `make release`

+   清理 - `make clean`

我会把这个测试留给你，但我鼓励你熟悉这个工作流程，并确保一切都能顺利完成。运行`make release`后，验证您是否可以导航到应用程序，应用程序是否正确显示 HTML 内容，以及您是否可以执行创建、读取、更新和删除操作。

一旦您确信一切都按预期工作，请确保已提交并推送您在上一章中分叉的 GitHub 存储库的更改。

# 总结

在本章中，您实现了一个 Docker 工作流，用于测试、构建和打包应用程序成一个 Docker 镜像，准备发布和部署到生产环境。您学会了如何使用 Docker 多阶段构建来构建应用程序的两个阶段——测试阶段使用开发环境，包括开发库和源代码编译工具，允许您构建和测试应用程序及其依赖关系的预编译包；而发布阶段则将这些构建好的包安装到一个生产就绪的操作环境中，不包含开发库和其他工具，显著减少了应用程序的攻击面。

您学会了如何使用 Docker Compose 来简化测试和发布阶段需要执行的各种命令和操作，创建了一个`docker-compose.yml`文件，其中包含了一些服务，每个服务都以一种声明性、易于理解的格式进行定义。您学会了如何复制一些部署任务，例如运行数据库迁移、收集静态文件，并确保应用程序数据库在尝试运行应用程序之前是健康的。在本地环境中执行每个任务使您能够对这些任务在实际生产环境中的工作方式有信心和了解，并在本地出现任何应用程序或配置更改破坏这些过程时提前警告。在将应用程序处于正确状态并连接到应用程序数据库后，您学会了如何从外部客户端的角度运行验收测试，这让您对镜像是否按预期工作有了很大的信心，并在这些验收测试在应用程序持续开发过程中失败时提前警告。

最后，你学会了如何使用 GNU Make 将所有这些内容整合到一个完全自动化的工作流程中，它为你提供了简单的高级命令，可以用来执行工作流程。现在你可以通过简单地运行`make test`来执行测试阶段，通过运行`make release`来运行发布阶段，并使用`make clean`清理你的环境。这使得运行工作流程变得非常容易，并且在本书的后面，将简化我们将使用的自动测试、构建和发布 Docker 应用程序的持续交付构建系统的配置。

在接下来的章节中，你将学习如何实际发布你在本章中创建的 Docker 发布镜像，但在你这样做之前，你需要建立一个 AWS 账户，配置对你的账户的访问，并安装支持与 AWS 交互的工具，这将是下一章的重点。

# 问题

1.  真/假：你使用`FROM`和`TO`指令来定义多阶段 Dockerfile。

1.  真/假：`docker`命令的`--rm`标志在容器退出后自动删除容器。

1.  真/假：当运行你的工作流程时，你应该只构建应用程序构件一次。

1.  真/假：当运行`docker-compose run`命令时，如果目标服务启动失败并出现错误，docker-compose 将以非零代码退出。

1.  真/假：当运行`docker-compose up`命令时，如果其中一个服务启动失败并出现错误，docker-compose 将以非零代码退出。

1.  真/假：如果你想使用 Docker Swarm，你应该配置一个 Docker Compose 版本为 3.x。

1.  你在 Docker 文件中为一个服务的依赖项配置了 service_healthy 条件。然后你使用`docker-compose run`命令运行服务；依赖项已启动，然而 Docker Compose 并不等待依赖项健康，而是立即启动服务，导致失败。你如何解决这个问题？

1.  你在 Docker Compose 中创建了一个服务，端口映射为`8000:8000`。当你尝试启动这个服务时，会出现一个错误，指示端口已被使用。你如何解决这个问题，并确保它不会再次发生呢？

1.  创建一个 Makefile 后，当尝试运行一个目标时，收到一个关于缺少分隔符的错误。这个错误最有可能的原因是什么？

1.  哪个 GNU Make 函数允许你捕获 shell 命令的输出？

1.  在 Makefile 中定义了一个名为 test 的目标，但是当你运行`make test`时，你会得到一个回应说没有什么可做的。你该如何解决这个问题呢？

1.  在 Docker Compose 服务定义中必须配置哪些属性才能使用`docker-compose push`命令？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   Docker 命令行参考：[`docs.docker.com/engine/reference/commandline/cli/`](https://docs.docker.com/engine/reference/commandline/cli/)

+   Docker 多阶段构建：[`docs.docker.com/develop/develop-images/multistage-build/`](https://docs.docker.com/develop/develop-images/multistage-build/)

+   Docker Compose 版本 2 规范：[`docs.docker.com/compose/compose-file/compose-file-v2/`](https://docs.docker.com/compose/compose-file/compose-file-v2/)

+   Docker Compose 命令行参考：[`docs.docker.com/compose/reference/`](https://docs.docker.com/compose/reference/)

+   Docker Compose 启动顺序：[`docs.docker.com/compose/startup-order/`](https://docs.docker.com/compose/startup-order/)

+   uWSGI Python 应用程序快速入门：[`uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html`](http://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html)

+   Bash 自动化测试系统：[`github.com/sstephenson/bats`](https://github.com/sstephenson/bats)

+   GNU Make 虚假目标：[`www.gnu.org/software/make/manual/html_node/Phony-Targets.html`](https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html)

+   GNU Make 函数：[`www.gnu.org/software/make/manual/html_node/Functions.html#Functions`](https://www.gnu.org/software/make/manual/html_node/Functions.html#Functions)
