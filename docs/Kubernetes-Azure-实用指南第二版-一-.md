# Kubernetes Azure 实用指南第二版（一）

> 原文：[`zh.annas-archive.org/md5/8F91550A7983115FCFE36001051EE26C`](https://zh.annas-archive.org/md5/8F91550A7983115FCFE36001051EE26C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本书的内容涵盖范围、您需要开始的技术技能，以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于在 Azure 上实践 Kubernetes，第二版

Kubernetes 是容器编排的领先标准，被初创企业和大型企业广泛使用。微软是这个开源项目的最大贡献者之一，并提供托管服务以规模运行 Kubernetes 集群。

本书将带领您了解在**Azure Kubernetes 服务**（**AKS**）上构建和运行应用程序所需的步骤。它从解释 Docker 和 Kubernetes 的基础知识开始，然后您将构建一个集群并开始部署多个应用程序。借助真实世界的例子，您将学习如何在 AKS 上部署应用程序，实现身份验证，监视您的应用程序，并将 AKS 与其他 Azure 服务（如数据库、事件中心和函数）集成。

通过本书，您将熟练掌握在 Azure 上运行 Kubernetes 和利用部署所需工具的能力。

### 关于作者

**尼尔斯·弗兰森斯**是一位技术爱好者，也是多个开源技术的专家。自 2013 年以来，他一直在使用公共云技术。

在他目前的职位上，作为微软的高级云解决方案架构师，他与微软的战略客户合作进行云采用。他已经帮助多个客户迁移到 Azure。其中一个迁移是将一个重要的公共网站迁移到 Kubernetes 并重新平台化。

在 Kubernetes 之外，尼尔斯的专业领域是 Azure 中的网络和存储。

他拥有比利时安特卫普大学的工程硕士学位。

当他不工作的时候，你可以发现尼尔斯和他的妻子凯利和朋友们一起玩桌游，或者在加利福尼亚州圣何塞的许多小径中跑步。

**冈瑟·伦兹**是 Varian 技术办公室的高级总监。他是一位富有创新精神的软件研发领导者、架构师、MBA、出版作者、公共演讲者，以及具有 20 多年经验的战略技术远见者。

他拥有成功领导 50 多人的大型、创新和变革性软件开发和 DevOps 团队的成功记录，重点是持续改进。

他通过利用颠覆性的流程、工具和技术，如云、DevOps、精益/敏捷、微服务架构、数字转型、软件平台、人工智能和分布式机器学习，定义并领导了整个软件产品生命周期中的分布式团队。

他曾获得微软最有价值专家-软件架构奖（2005-2008 年）。

Gunther 已出版两本书，《.NET-完整的开发周期》和《.NET 中的实用软件工厂》。

**Shivakumar Gopalakrishnan**是 Varian Medical Systems 的 DevOps 架构师。他已经向 Varian 产品开发引入了 Docker、Kubernetes 和其他云原生工具，以实现“一切皆代码”。

他在各种领域拥有多年的软件开发经验，包括网络、存储、医学成像，目前是 DevOps。他致力于开发可扩展的存储设备，专门针对医学成像需求进行调整，并帮助架构云原生解决方案，用于提供由微服务支持的模块化 AngularJS 应用程序。他曾在多个活动上发表讲话，介绍在 DevOps 中整合人工智能和机器学习，以实现大型企业学习文化。

他帮助高度受监管的大型医疗企业团队采用现代敏捷/DevOps 方法，包括“你构建它，你运行它”的模式。他已经定义并领导了一个 DevOps 路线图，将传统团队转变为无缝采用安全和质量优先方法的团队，使用 CI/CD 工具。

他拥有印度古因迪工程学院的工程学学士学位，以及马里兰大学帕克分校的理学硕士学位。

### 学习目标

通过本书，您将能够：

+   了解 Docker 和 Kubernetes 的基本原理

+   设置 AKS 集群

+   将应用程序部署到 AKS

+   监视 AKS 上的应用程序并处理常见故障

+   为 AKS 上的应用程序设置身份验证

+   将 AKS 与 Azure Database for MySQL 集成

+   从 AKS 中的应用程序利用 Azure 事件中心

+   保护您的集群

+   将无服务器函数部署到您的集群

### 受众

如果您是云工程师、云解决方案提供商、系统管理员、站点可靠性工程师或对 DevOps 感兴趣，并且正在寻找在 Azure 环境中运行 Kubernetes 的广泛指南，那么本书适合您。

### 方法

本书提供了实用和理论知识的结合。它涵盖了引人入胜的现实场景，展示了基于 Kubernetes 的应用程序如何在 Azure 平台上运行。每一章都旨在使您能够在实际环境中应用所学到的一切。在第一章和第二章之后，每一章都是独立的，可以独立于之前的章节运行。

### 软件要求

我们还建议您提前安装以下软件：

+   具有 Linux、Windows 10 或 macOS 操作系统的计算机

+   互联网连接和网络浏览器，以便您可以连接到 Azure

本书中的所有示例都经过设计，可以在 Azure Cloud Shell 中使用。您无需在计算机上安装额外的软件。

### 约定

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

“以下代码片段将使用`kubectl`命令行工具来创建在文件`guestbook-all-in-one.yaml`中定义的应用程序。”

以下是一个代码块示例：

```
kubectl create -f guestbook-all-in-one.yaml
```

我们将使用反斜杠\来表示代码将跨越书中多行。您可以复制反斜杠并继续到下一行，或者忽略反斜杠并在单行上键入完整的多行代码。例如：

```
az aks nodepool update --disable-cluster-autoscaler \
-g rg-handsonaks --cluster-name handsonaks --name agentpool
```

在许多情况下，我们使用了尖括号`<>`。您需要用实际参数替换这些内容，并且不要在命令中使用这些括号。

### 下载资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Azure---Second-Edition`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Azure---Second-Edition)。您可以在此书中找到使用的 YAML 和其他文件，在相关实例中引用。

我们还有来自我们丰富的图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！


# 第一部分：基础知识

在本书的第一部分中，我们将涵盖您需要了解的基本概念，以便跟随本书中的示例。

我们将从解释这些基本概念开始，比如 Docker 和 Kubernetes。然后，我们将解释如何在 Azure 上创建一个 Kubernetes 集群并部署一个示例应用程序。

当您完成本节时，您将具有关于 Docker 和 Kubernetes 的基础知识，并且在 Azure 中运行一个 Kubernetes 集群，这将使您能够跟随本书中的示例。

本节包括以下章节：

+   *第一章，Docker 和 Kubernetes 简介*

+   *第二章，Azure 上的 Kubernetes（AKS）*


# 第一章：Docker 和 Kubernetes 简介

Kubernetes 已成为容器编排的领先标准。自 2014 年成立以来，它已经获得了巨大的流行。它已被初创公司和主要企业采用，而且主要的公共云供应商都提供了托管的 Kubernetes 服务。

Kubernetes 建立在 Docker 容器革命的成功基础上。Docker 既是一家公司，也是一种技术的名称。作为一种技术，Docker 是创建和运行软件容器的标准方式，通常称为 Docker 容器。容器本身是一种打包软件的方式，使得在任何平台上运行该软件变得容易，从您的笔记本电脑到数据中心的服务器，再到公共云中运行的集群。

Docker 也是 Docker 技术背后公司的名称。尽管核心技术是开源的，但 Docker 公司专注于通过多种商业产品减少开发人员的复杂性。

Kubernetes 将 Docker 容器提升到了一个新的水平。Kubernetes 是一个容器编排器。容器编排器是一种软件平台，可以轻松地在成千上万台机器上运行成千上万个容器。它自动化了部署、运行和扩展应用程序所需的许多手动任务。编排器将负责安排正确的容器在正确的机器上运行，并负责健康监控和故障转移，以及扩展您部署的应用程序。

Docker 和 Kubernetes 都是开源软件项目。开源软件允许来自许多公司的开发人员共同合作开发单一软件。Kubernetes 本身有来自微软、谷歌、红帽、VMware 等公司的贡献者。

三大主要的公共云平台 - Azure，Amazon Web Services（AWS）和 Google Cloud Platform（GCP） - 都提供了托管的 Kubernetes 服务。这在市场上引起了很大的兴趣，因为这些托管服务的计算能力几乎是无限的，而且易于使用，可以轻松构建和部署大规模应用程序。

Azure Kubernetes Service（AKS）是 Azure 的 Kubernetes 托管服务。它管理了为您组合所有前述服务的复杂性。在本书中，您将学习如何使用 AKS 来运行您的应用程序。每一章都会介绍新的概念，您将通过本书中的许多示例来应用这些概念。

然而，作为一名工程师，了解支撑 AKS 的技术仍然非常有用。我们将在本章探讨这些基础知识。您将了解 Linux 进程及其与 Docker 的关系。您将看到各种进程如何很好地适配到 Docker 中，以及 Docker 如何很好地适配到 Kubernetes 中。尽管 Kubernetes 在技术上是一个容器运行时无关的平台，但 Docker 是最常用的容器技术，被广泛应用。

本章介绍了基本的 Docker 概念，以便您可以开始您的 Kubernetes 之旅。本章还简要介绍了将帮助您构建容器、实现集群、执行容器编排和在 AKS 上排除故障的基础知识。对本章内容的粗略了解将使构建在 AKS 上的经过认证、加密、高度可扩展的应用程序所需的大部分工作变得不再神秘。在接下来的章节中，您将逐渐构建可扩展和安全的应用程序。

本章将涵盖以下主题：

+   将我们带到这里的软件演变

+   Docker 的基础知识

+   Kubernetes 的基础知识

+   AKS 的基础知识

本章的目的是介绍基本知识，而不是提供描述 Docker 和 Kubernetes 的详尽信息源。首先，我们将首先看一下软件是如何演变到现在的。

## 将我们带到这里的软件演变

有两个主要的软件开发演变使得 Docker 和 Kubernetes 变得流行。一个是采用了微服务架构风格。微服务允许应用程序由一系列小服务构建，每个服务都提供特定的功能。使 Docker 和 Kubernetes 变得流行的另一个演变是 DevOps。DevOps 是一组文化实践，允许人员、流程和工具更快、更频繁、更可靠地构建和发布软件。

尽管您可以在不使用微服务或 DevOps 的情况下使用 Docker 和 Kubernetes，但这些技术最广泛地被采用用于使用 DevOps 方法部署微服务。

在本节中，我们将讨论两种演变，首先是微服务。

### 微服务

软件开发随着时间的推移发生了巨大变化。最初，软件是在单一系统上开发和运行的，通常是在大型机上。客户端可以通过终端连接到大型机，而且只能通过那个终端。当计算机网络变得普遍时，这种情况发生了变化，客户端-服务器编程模型出现了。客户端可以远程连接到服务器，甚至在连接到服务器检索应用程序所需的部分数据时，在自己的系统上运行应用程序的一部分。

客户端-服务器编程模型已经发展成真正的分布式系统。分布式系统不同于传统的客户端-服务器模型，因为它们在多个不同的系统上运行多个不同的应用程序，并且彼此相互连接。

如今，在开发分布式系统时，微服务架构很常见。基于微服务的应用程序由一组服务组成，这些服务共同形成应用程序，而这些个别服务本身可以独立构建、测试、部署和独立扩展。这种风格有许多好处，但也有一些缺点。

微服务架构的一个关键部分是每个个别服务只提供一个核心功能。每个服务提供一个单一的业务功能。不同的服务共同形成完整的应用程序。这些服务通过网络通信共同工作，通常使用 HTTP REST API 或 gRPC。

这种架构方法通常被应用程序使用 Docker 和 Kubernetes 运行。Docker 被用作单个服务的打包格式，而 Kubernetes 是部署和管理一起运行的不同服务的编排器。

在我们深入研究 Docker 和 Kubernetes 的具体内容之前，让我们先探讨一下采用微服务的利与弊。

**运行微服务的优势**

运行基于微服务的应用程序有几个优势。第一个是每个服务都独立于其他服务。这些服务被设计得足够小（因此是微型），以满足业务领域的需求。由于它们很小，它们可以被制作成自包含的、可以独立测试的，因此可以独立发布。

这导致了每个微服务都可以独立扩展。如果应用程序的某个部分需求增加，该部分可以独立于应用程序的其他部分进行扩展。

服务可以独立扩展也意味着它们可以独立部署。在微服务方面有多种部署策略。最流行的是滚动升级和蓝/绿部署。

通过滚动升级，服务的新版本只部署到部分最终用户社区。如果服务正常，新版本会受到仔细监控，并逐渐获得更多的流量。如果出现问题，之前的版本仍在运行，流量可以轻松切换。

通过蓝/绿部署，您可以将服务的新版本独立部署。一旦部署并测试了服务的新版本，您就可以将 100%的生产流量切换到新版本。这可以实现服务版本之间的平稳过渡。

微服务架构的另一个好处是每个服务可以用不同的编程语言编写。这被描述为**多语言** - 能够理解和使用多种语言。例如，前端服务可以使用流行的 JavaScript 框架开发，后端可以使用 C#开发，而机器学习算法可以使用 Python 开发。这使您可以为每个服务选择合适的语言，并让开发人员使用他们最熟悉的语言。

**运行微服务的缺点**

每个硬币都有两面，微服务也是如此。虽然基于微服务的架构有多个优点，但这种架构也有其缺点。

微服务的设计和架构需要高度的软件开发成熟度才能正确实施。深刻理解领域的架构师必须确保每个服务都是有界的，并且不同的服务是内聚的。由于服务彼此独立且独立版本化，因此这些不同服务之间的软件合同非常重要。

微服务设计的另一个常见问题是在监视和故障排除这样的应用程序时增加了复杂性。由于不同的服务构成单个应用程序，并且这些不同的服务在多个服务器上运行，因此记录和跟踪这样的应用程序是一项复杂的工作。

与前述的缺点相关的是，通常在微服务中，您需要为应用程序构建更多的容错能力。由于应用程序中不同服务的动态性质，故障更有可能发生。为了保证应用程序的可用性，重要的是在构成应用程序的不同微服务中构建容错能力。实施重试逻辑或断路器等模式对于避免单一故障导致应用程序停机至关重要。

通常与微服务相关联，但是一个独立的转型是 DevOps 运动。我们将在下一节探讨 DevOps 的含义。

### DevOps

DevOps 字面上意味着开发和运营的结合。更具体地说，DevOps 是人员、流程和工具的结合，以更快、更频繁、更可靠地交付软件。DevOps 更多地涉及一套文化实践，而不是任何特定的工具或实施。通常，DevOps 涵盖软件开发的四个领域：规划、开发、发布和操作软件。

#### 注意

存在许多关于 DevOps 的定义。作者采用了这个定义，但鼓励读者在 DevOps 的文献中探索不同的定义。

DevOps 文化始于规划。在 DevOps 项目的规划阶段，项目的目标被概述。这些目标在高层次（称为*史诗*）和较低层次（在*特性*和*任务*中）都有概述。DevOps 项目中的不同工作项被记录在特性积压中。通常，DevOps 团队使用敏捷规划方法，在编程冲刺中工作。看板经常被用来表示项目状态和跟踪工作。当任务从*待办*状态变为*进行中*再到*完成*时，它在看板上从左向右移动。

当工作计划好后，实际的开发工作就可以开始了。在 DevOps 文化中，开发不仅仅是编写代码，还包括测试、审查和与团队成员集成。诸如 Git 之类的版本控制系统用于不同团队成员之间共享代码。自动化的持续集成（CI）工具用于自动化大部分手动任务，如测试和构建代码。

当一个功能完成编码、测试和构建后，就可以交付了。DevOps 项目的下一个阶段可以开始：交付。使用持续交付（CD）工具来自动化软件的部署。通常，软件会部署到不同的环境，如测试、质量保证或生产。使用自动化和手动门来确保在进入下一个环境之前的质量。

最后，当一款软件在生产中运行时，运维阶段就可以开始了。这个阶段涉及在生产中维护、监控和支持应用程序。最终目标是以尽可能少的停机时间可靠地运行应用程序。任何问题都应该尽可能被主动识别。软件中的错误需要在积压中被跟踪。

DevOps 流程是一个迭代的过程。一个团队永远不只处于一个阶段。整个团队不断地规划、开发、交付和操作软件。

存在多种工具来实施 DevOps 实践。有针对单个阶段的点解决方案，比如用于规划的 Jira 或用于 CI 和 CD 的 Jenkins，以及完整的 DevOps 平台，比如 GitLab。微软提供了两种解决方案，使客户能够采用 DevOps 实践：Azure DevOps 和 GitHub。Azure DevOps 是一套服务，支持 DevOps 流程的所有阶段。GitHub 是一个单独的平台，支持 DevOps 软件开发。GitHub 被认为是领先的开源软件开发平台，托管了超过 4000 万个开源项目。

微服务和 DevOps 通常与 Docker 和 Kubernetes 结合使用。在介绍了微服务和 DevOps 之后，我们将继续本章的第一部分，介绍 Docker 和容器的基础知识，然后是 Kubernetes 的基础知识。

## Docker 容器的基础知识

自 20 世纪 70 年代以来，Linux 内核中一种容器技术已经存在。今天容器的技术，称为 cgroups，是由 Google 在 2006 年引入 Linux 内核的。Docker 公司在 2013 年通过引入一种简单的开发者工作流程使这项技术变得流行。该公司以自己的名字命名了这项技术，因此 Docker 这个名字既可以指公司，也可以指技术。不过，通常我们使用 Docker 来指代这项技术。

Docker 作为一种技术既是一种打包格式，也是一个容器运行时。我们将打包称为一种架构，允许应用程序与其依赖项（如二进制文件和运行时）一起打包。运行时指的是运行容器映像的实际过程。

你可以通过在 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）创建一个免费的 Docker 账户，并使用该登录信息打开 Docker 实验室（[`labs.play-with-docker.com/`](https://labs.play-with-docker.com/)）来尝试 Docker。这将为你提供一个预先安装了 Docker 的环境，有效期为 4 小时。在本节中，我们将使用 Docker 实验室来构建我们自己的容器和镜像。

#### 注意：

虽然在本章中我们使用基于浏览器的 Docker 实验室来介绍 Docker，但你也可以在本地桌面或服务器上安装 Docker。对于工作站，Docker 有一个名为 Docker Desktop 的产品（[`www.docker.com/products/docker-desktop`](https://www.docker.com/products/docker-desktop)），适用于 Windows 和 Mac，可以在本地创建 Docker 容器。在服务器上，无论是 Windows 还是 Linux，Docker 也可以作为容器的运行时使用。

### Docker 镜像

Docker 使用镜像来启动一个新的容器。镜像包含了在容器内运行所需的所有软件。容器镜像可以存储在本地计算机上，也可以存储在容器注册表中。有公共注册表，如公共 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)），也有私有注册表，如 Azure 容器注册表（ACR）。当你作为用户在 PC 上没有镜像时，你将使用`docker pull`命令从注册表中拉取镜像。

在下面的示例中，我们将从公共 Docker Hub 存储库中拉取一个镜像并运行实际的容器。你可以按照以下说明在 Docker 实验室中运行这个示例：

```
#First we will pull an image
docker pull docker/whalesay
#We can then look at which images we have locally
docker images
#Then we will run our container
docker run docker/whalesay cowsay boo
```

这些命令的输出将类似于*图 1.1*：

![从公共 Docker Hub 仓库中拉取的 Docker 镜像以及显示镜像 ID 和大小的输出。此外，运行 Docker 镜像会显示一张鲸鱼说“boo”的图片。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_1.1.jpg)

###### 图 1.1：在 Docker 实验室中运行 Docker 的示例

这里发生的是，Docker 首先将您的镜像分成多个部分，并将其存储在运行的机器上。当我们运行实际的应用程序时，它使用本地镜像来启动一个容器。如果我们详细查看命令，您会发现`docker pull`只接受一个参数，即`docker/whalesay`。如果您没有提供私有容器注册表，Docker 将在公共 Docker Hub 中查找镜像，这就是 Docker 从中拉取我们的镜像的地方。`docker run`命令接受了几个参数。第一个参数是`docker/whalesay`，这是对镜像的引用。接下来的两个参数，`cowsay boo`，是传递给正在运行的容器以执行的命令。

在前面的示例中，我们了解到可以在不先构建镜像的情况下运行容器是可能的。然而，通常情况下，您会想要构建自己的镜像。为此，您可以使用**Dockerfile**。Dockerfile 包含 Docker 将遵循的步骤，从基础镜像开始构建您的镜像。这些指令可以包括添加文件、安装软件或设置网络等。下面提供了一个 Dockerfile 的示例，我们将在我们的 Docker playground 中创建：

```
FROM docker/whalesay:latest
RUN apt-get -y -qq update && apt-get install -qq -y fortunes
CMD /usr/games/fortune -a | cowsay
```

这个 Dockerfile 有三行。第一行将指示 Docker 使用哪个镜像作为新镜像的源镜像。下一步是运行一个命令，向我们的镜像添加新功能。在这种情况下，更新我们的`apt`仓库并安装一个叫做`fortunes`的应用程序。最后，`CMD`命令告诉 Docker 在基于这个镜像运行的容器中执行哪个命令。

通常将 Dockerfile 保存在名为`Dockerfile`的文件中，不带扩展名。要构建我们的镜像，您需要执行`docker build`命令，并指向您创建的 Dockerfile。在构建 Docker 镜像时，该过程将读取 Dockerfile 并执行其中的不同步骤。该命令还将输出运行容器和构建镜像所采取的步骤。让我们演示构建我们自己的镜像。

要创建这个 Dockerfile，通过`vi Dockerfile`命令打开一个文本编辑器。vi 是 Linux 命令行中的高级文本编辑器。如果你不熟悉它，让我们一起看看你该如何在其中输入文本：

1.  打开 vi 后，按下`i`键进入插入模式。

1.  然后，要么复制粘贴，要么输入这三行代码。

1.  之后，按下*Esc*键，然后输入`:wq!`来写入（w）你的文件并退出（q）文本编辑器。

下一步是执行`docker build`来构建我们的镜像。我们将在该命令中添加最后一部分，即给我们的镜像添加一个标签，这样我们就可以用一个有用的名称来调用它。要构建你的镜像，你将使用`docker build -t smartwhale .`命令（不要忘记在这里加上最后的点）。

现在你会看到 Docker 执行一系列步骤 - 在我们的例子中是三个步骤 - 以构建我们的镜像。镜像构建完成后，你可以运行你的应用程序。要运行容器，你需要运行`docker run smartwhale`，然后你应该会看到类似于*图 1.2*的输出。然而，你可能会看到不同的智能引号。这是因为`fortunes`应用程序生成不同的引言。如果你多次运行容器，你会看到不同的引言出现，就像*图 1.2*中显示的那样。

![运行 docker run smartwhale 命令的输出，显示由 fortunes 应用程序生成的智能引号。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_1.2.jpg)

###### 图 1.2：运行自定义容器的示例

这就结束了我们对 Docker 的概述和演示。在本节中，你从一个现有的容器镜像开始，并在 Docker 实验室上启动了它。之后，你进一步构建了自己的容器镜像，并使用自己的镜像启动了容器。现在你已经学会了构建和运行容器的方法。在下一节中，我们将介绍 Kubernetes。Kubernetes 允许你以规模运行多个容器。

## Kubernetes 作为容器编排平台

构建和运行单个容器似乎足够简单。然而，当你需要在多个服务器上运行多个容器时，情况可能会变得复杂。这就是容器编排器可以帮助的地方。容器编排器负责安排容器在服务器上运行，当容器失败时重新启动容器，当主机不健康时将容器移动到新主机，以及更多其他任务。

当前领先的编排平台是 Kubernetes（[`kubernetes.io/`](https://kubernetes.io/)）。Kubernetes 受到了 Google 的 Borg 项目的启发，该项目本身在生产环境中运行了数百万个容器。

Kubernetes 采用声明性的编排方式；也就是说，你指定你需要什么，Kubernetes 负责部署你指定的工作负载。你不再需要手动启动这些容器，因为 Kubernetes 将启动你指定的 Docker 容器。

#### 注意

尽管 Kubernetes 支持多个容器运行时，但 Docker 是最流行的运行时。

在本书中，我们将构建多个在 Kubernetes 中运行容器的示例，并且你将了解更多关于 Kubernetes 中不同对象的知识。在这个介绍性的章节中，我们将介绍 Kubernetes 中的三个基本对象，这些对象在每个应用中都可能会看到：Pod、Deployment 和 Service。

### Kubernetes 中的 Pod

Kubernetes 中的 Pod 是基本的调度块。一个 Pod 是一个或多个容器的组合。这意味着一个 Pod 可以包含单个容器或多个容器。当创建一个只有一个容器的 Pod 时，你可以互换使用容器和 Pod 这两个术语。然而，Pod 这个术语仍然更受青睐。

当一个 Pod 包含多个容器时，这些容器共享相同的文件系统和网络命名空间。这意味着当一个 Pod 中的容器写入一个文件时，该 Pod 中的其他容器可以读取该文件。这也意味着 Pod 中的所有容器可以使用`localhost`网络相互通信。

在设计方面，你应该只将需要紧密集成的容器放在同一个 Pod 中。想象一下以下情况：你有一个不支持 HTTPS 的旧 Web 应用。你想要升级该应用以支持 HTTPS。你可以创建一个包含旧 Web 应用的 Pod，并包含另一个容器，该容器将为该应用执行 SSL 卸载，如*图 1.3*所述。用户将使用 HTTPS 连接到你的应用，而中间的容器将 HTTPS 流量转换为 HTTP：

![一个执行 HTTPS 卸载的多容器 Pod 的示例，说明用户如何向 HTTPS 卸载容器发出 HTTPS 请求，然后该容器再向 Pod 内的旧 Web 应用发出 HTTP 请求。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_1.3.jpg)

###### 图 1.3：执行 HTTPS 卸载的多容器 Pod 的示例

#### 注意

这个设计原则被称为边车。微软提供了一本免费的电子书，描述了多个多容器 Pod 设计和设计分布式系统（[`azure.microsoft.com/resources/designing-distributed-systems/`](https://azure.microsoft.com/resources/designing-distributed-systems/)）。

一个 Pod，无论是单个还是多个容器的 Pod，都是一个短暂的资源。这意味着 Pod 可以在任何时候被终止，并在另一个节点上重新启动。当这种情况发生时，存储在该 Pod 中的状态将丢失。如果您需要在应用程序中存储状态，您需要将其存储在`StatefulSet`中，我们将在*第三章*，*在 AKS 上部署应用程序*中讨论，或者将状态存储在 Kubernetes 之外的外部数据库中。

### Kubernetes 中的部署

Kubernetes 中的部署提供了围绕 Pod 的功能层。它允许您从相同的定义中创建多个 Pod，并轻松地对部署的 Pod 进行更新。部署还有助于扩展您的应用程序，甚至可能自动扩展您的应用程序。

在底层，部署创建一个`ReplicaSet`，然后将创建您请求的 Pod。`ReplicaSet`是 Kubernetes 中的另一个对象。`ReplicaSet`的目的是在任何给定时间维护一组稳定运行的 Pod。如果您对部署进行更新，Kubernetes 将创建一个包含更新的 Pod 的新`ReplicaSet`。默认情况下，Kubernetes 将对新版本进行滚动升级。这意味着它将启动一些新的 Pod。如果这些 Pod 正常运行，那么它将终止一些旧的 Pod 并继续这个循环，直到只有新的 Pod 在运行。

![部署、ReplicaSet 和 Pod 之间关系的图形表示。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_1.4.jpg)

###### 图 1.4：部署、ReplicaSet 和 Pod 之间的关系

### Kubernetes 中的服务

Kubernetes 中的服务是一个网络级的抽象。这允许您在单个 IP 地址和单个 DNS 名称下公开部署中的多个 Pod。

Kubernetes 中的每个 Pod 都有自己的私有 IP 地址。理论上，您可以使用这个私有 IP 地址连接您的应用程序。然而，正如前面提到的，Kubernetes Pods 是短暂的，这意味着它们可以被终止和移动，这会影响它们的 IP 地址。通过使用 Service，您可以使用单个 IP 地址将您的应用程序连接在一起。当一个 Pod 从一个节点移动到另一个节点时，Service 将确保流量被路由到正确的端点。

在本节中，我们介绍了 Kubernetes 和三个基本对象。在下一节中，我们将介绍 AKS。

## Azure Kubernetes 服务

**Azure Kubernetes 服务**（**AKS**）使创建和管理 Kubernetes 集群变得更容易。

典型的 Kubernetes 集群由多个主节点和多个工作节点组成。Kubernetes 中的节点相当于**虚拟机**（**VM**）。主节点包含 Kubernetes API 和包含集群状态的数据库。工作节点是运行实际工作负载的虚拟机。

AKS 使创建集群变得更加容易。当您创建一个 AKS 集群时，AKS 会免费为您设置 Kubernetes 主节点。然后，AKS 将在您的订阅中创建虚拟机，并将这些虚拟机转换为您网络中 Kubernetes 集群的工作节点。您只需为这些虚拟机付费；您不需要为主节点付费。

在 AKS 中，Kubernetes 服务与 Azure 负载均衡器集成，Kubernetes Ingress 与应用程序网关集成。Azure 负载均衡器是一个第 4 层网络负载均衡器服务；应用程序网关是一个基于 HTTP 的第 7 层负载均衡器。Kubernetes 和这两个服务之间的集成意味着当您在 Kubernetes 中创建一个服务或 Ingress 时，Kubernetes 将在 Azure 负载均衡器或应用程序网关中分别创建一个规则。Azure 负载均衡器或应用程序网关将然后将流量路由到托管您的 Pod 的集群中的正确节点。

此外，AKS 添加了许多功能，使得更容易管理集群。AKS 包含升级集群到更新的 Kubernetes 版本的逻辑。它还可以轻松地扩展您的集群，使其变得更大或更小。

服务还带有使操作更容易的集成。AKS 集群预先配置了与 Azure Active Directory（Azure AD）的集成，以便简化身份管理和基于角色的访问控制（RBAC）。RBAC 是定义哪些用户可以访问资源以及他们可以对这些资源执行哪些操作的配置过程。AKS 还集成到 Azure Monitor for containers 中，这使得监视和排除故障变得更简单。

## 总结

在本章中，我们介绍了 Docker 和 Kubernetes 的概念。我们运行了许多容器，从现有的镜像开始，然后使用我们自己构建的镜像。在演示之后，我们探索了三个基本的 Kubernetes 对象：Pod、Deployment 和 Service。

这为剩余的章节提供了共同的背景，您将在 Microsoft AKS 中部署 Docker 化的应用程序。您将看到，Microsoft 的 AKS 平台即服务（PaaS）提供简化部署，通过处理许多管理和运营任务，您将不得不自行处理这些任务，如果您管理和运营自己的 Kubernetes 基础设施。

在下一章中，我们将介绍 Azure 门户及其组件，以便在创建您的第一个 AKS 集群的情况下使用。


# 第二章：在 Azure 上使用 Kubernetes（AKS）

正确和安全地安装和维护 Kubernetes 集群是困难的。幸运的是，所有主要的云提供商，如 Azure、AWS 和 Google Cloud Platform（GCP），都可以帮助安装和维护集群。在本章中，您将通过 Azure 门户导航，启动自己的集群，并运行一个示例应用程序。所有这些都将在您的浏览器中完成。

本章将涵盖以下主题：

+   创建新的 Azure 免费帐户

+   导航 Azure 门户

+   启动您的第一个集群

+   启动您的第一个应用程序

让我们首先看看创建 AKS 集群的不同方式，然后运行我们的示例应用程序。

## 部署 AKS 集群的不同方式

本章将介绍部署 AKS 集群的图形化方式。然而，有多种方法可以创建您的 AKS 集群：

+   **使用门户**：门户为您提供了通过向导部署集群的图形化方式。这是部署您的第一个集群的好方法。对于多个部署或自动化部署，建议使用以下方法之一。

+   **使用 Azure CLI**：Azure **命令行界面**（**CLI**）是一个用于管理 Azure 资源的跨平台 CLI。这使您可以编写脚本来部署您的集群，可以集成到其他脚本中。

+   **使用 Azure PowerShell**：Azure PowerShell 是一组用于直接从 PowerShell 管理 Azure 资源的 PowerShell 命令。它也可以用于创建 Kubernetes 集群。

+   **使用 ARM 模板**：**Azure 资源管理器**（**ARM**）模板是 Azure 本地的**基础设施即代码**（**IaC**）语言。它允许您声明性地部署您的集群。这使您可以创建一个可以被多个团队重复使用的模板。

+   **使用 Terraform 部署 Azure**：Terraform 是由 HashiCorp 开发的开源 IaC 工具。该工具在开源社区中非常受欢迎，可用于部署云资源，包括 AKS。与 ARM 模板一样，Terraform 也使用声明性模板来创建您的集群。

在本章中，我们将使用 Azure 门户创建我们的集群。如果您有兴趣使用 CLI、ARM 或 Terraform 部署集群，Azure 文档包含了如何使用这些工具创建您的集群的步骤，网址为[`docs.microsoft.com/azure/aks`](https://docs.microsoft.com/azure/aks)。

## 从 Azure 门户开始

我们将使用 Azure 门户开始我们的初始集群部署。Azure 门户是一个基于 Web 的管理控制台。它允许您通过单个控制台构建、管理和监视全球范围内的所有 Azure 部署。

#### 注意

要跟随本书中的示例，您需要一个 Azure 帐户。如果您没有 Azure 帐户，可以按照[azure.microsoft.com/free](http://azure.microsoft.com/free)上的步骤创建免费帐户。如果您计划在现有订阅中运行此操作，您将需要订阅的所有者权限以及在 Azure Active Directory（Azure AD）中创建服务主体的能力。

本书中的所有示例都已通过免费试用帐户进行验证。

我们将通过创建 Azure Kubernetes Service（AKS）集群来直接开始。通过这样做，我们还将熟悉 Azure 门户。

### 创建您的第一个 AKS 集群

在 Azure 门户顶部的搜索栏中输入`aks`关键字。在结果中，点击**服务**类别下的**Kubernetes 服务**：

图 2.1：在顶部的搜索栏中搜索 aks，查找服务类别中的 Kubernetes 服务

###### 图 2.1：使用搜索栏在 Azure 门户顶部输入`aks`关键字

这将带您到门户中的 AKS 刀片。正如您可能期望的那样，您还没有任何集群。继续通过点击**+添加**按钮创建一个新的集群：

图 2.2：在 AKS 刀片内选择左上角的添加按钮，开始集群创建过程。

###### 图 2.2：单击“+添加”按钮开始集群创建过程

#### 注意

在创建 AKS 集群时有很多配置选项。对于您的第一个集群，我们建议使用门户中的默认设置，并在本示例中遵循我们的命名指南。以下设置经过我们测试，可靠地在免费帐户中使用。

这将带您通过创建向导来创建您的第一个 AKS 集群。这里的第一步是创建一个新的资源组。点击“创建新”按钮，给您的资源命名，并点击“确定”。如果您想跟随本书中的示例，请将资源组命名为`rg-handsonaks`：

![显示如何在 AKS 刀片中创建新资源组的过程。第 1 步是选择创建新链接，第 2 步是输入资源组的名称（在本例中为 rg-handsonaks），第 3 步是选择确定。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.3.jpg)

###### 图 2.3：创建新的资源组

接下来，我们将提供我们的集群详细信息。给您的集群取一个名字 - 如果您想要按照书中的示例进行，请将其命名为`handsonaks`。我们在书中将使用的区域是`(US) West US 2`，但您可以选择靠近您位置的任何其他区域。我们将使用 Kubernetes 版本`1.15.7`，但如果该版本对您不可用，不用担心。Kubernetes 和 AKS 发展非常迅速，经常会推出新版本。接下来，您需要提供一个 DNS 名称前缀。这不必是唯一的，因为 Azure 将在其后附加随机字符：

![输入集群详细信息，如 Kubernetes 集群名称、区域、Kubernetes 版本和 DNS 名称前缀。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.4.jpg)

###### 图 2.4：提供集群详细信息

接下来，我们需要更改节点大小和节点计数。为了优化我们示例集群的免费预算，我们将使用一个没有高级存储的**虚拟机**（**VM**）并部署一个两节点集群。如果您没有使用免费试用版，您可以选择更强大的 VM 大小，尽管这对本书中的实验并非必需。

点击机器大小下方的**更改大小**按钮：

![使用更改大小选项选择较小的机器。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.5.jpg)

###### 图 2.5：点击“更改大小”选项以选择较小的机器

删除寻找高级存储的筛选器，寻找**D1_v2**。然后将**节点计数**的滑块更改为**2**：

![导航到更改大小选项后，删除寻找高级存储的筛选器，并选择 D1_v2 机器类型。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.6.jpg)

###### 图 2.6：选择 D1_v2 作为机器大小

这应该使您的集群大小看起来类似于*图 2.7*所示的样子：

![使用滑块将节点计数更改为 2 个节点。同时，节点大小已成功更改为 D1 v2。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.7.jpg)

###### 图 2.7：更新的节点大小和节点计数

#### 注意

您的免费帐户有一个四核限制，如果我们使用默认设置将会违反这一限制。

第一个标签页的最终视图应该类似于*图 2.8*。我们将不更改我们的演示集群的许多其他配置选项。由于我们已经准备好，现在点击“审阅+创建”按钮进行最终审阅并创建您的集群：

![第一个标签页中显示创建集群配置的集群详细信息的基本选项卡。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.8.jpg)

###### 图 2.8：设置集群配置

在最终视图中，Azure 将验证应用于您的第一个集群的配置。如果验证通过，请点击**创建**：

![Azure 门户在您点击左下角的创建按钮之前，提供集群配置的最终验证，并显示所有集群详细信息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.9.jpg)

###### 图 2.9：您集群配置的最终验证

部署您的集群大约需要 15 分钟。部署完成后，您可以查看部署详细信息，如*图 2.10*所示：

![微软.aks 概述窗口显示集群成功部署后的部署详细信息。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.10.jpg)

###### 图 2.10：集群成功部署后的部署详细信息

如果您遇到配额限制错误，如*图 2.11*所示，请检查设置并重试。确保您选择了**D1_v2**节点大小，并且只有两个节点：

![概述窗口显示错误详细信息和错误摘要。在这里，错误消息显示为：资源操作完成，终端配置状态为“失败”。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.11.jpg)

###### 图 2.11：由于配额限制错误，重试使用较小的集群大小

要进入下一节，我们将快速查看我们的集群，请点击“转到资源”按钮，这将带您进入门户中的 AKS 标签页。

### Azure 门户中您集群的快速概述

如果您在上一节中点击了“转到资源”按钮，现在应该在 Azure 门户中看到您集群的概述：

![Azure 门户中 AKS 标签页的概述选项卡显示已部署集群的详细信息。在左侧窗格中，有诸如概述、节点池、升级和洞察等有用的选项卡。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.12.jpg)

###### 图 2.12：Azure 门户中的 AKS 标签页

这是对您的集群的快速概述。它提供了名称、位置和 API 服务器地址。左侧导航菜单提供了不同的选项来控制和管理您的集群。让我们走一遍门户提供的一些有趣的选项。

第一个有趣的选项是**节点池**选项。在节点池视图中，您可以通过添加或删除节点来扩展现有的节点池（即集群中的节点或服务器）；您可以添加一个新的节点池，可能具有不同的服务器大小，还可以单独升级您的节点池。在*图 2.13*中，您可以在左上角看到**添加节点池**选项，并在右侧菜单中看到**扩展**或**升级**的选项：

![节点池刀片显示了如何添加节点池，并提供了一个下拉菜单来扩展和升级现有的节点池。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.13.jpg)

###### 图 2.13：添加、扩展和升级节点池

第二个有趣的刀片是**升级**刀片。在这里，您可以指示 AKS 将管理平面升级到更新版本。通常，在 Kubernetes 升级中，您首先升级主平面，然后分别升级各个节点池：

![升级刀片有升级 API 服务器的 Kubernetes 版本的选项。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.14.jpg)

###### 图 2.14：使用升级刀片升级 API 服务器的 Kubernetes 版本

调查的最后一个有趣的地方是**Insights**。**Insights**选项为您提供了对集群基础设施和运行在集群上的工作负载的监控。由于我们的集群是全新的，没有太多数据可以调查。我们将在*第七章*中再次回到这里，监控 AKS 集群和应用程序：

![Insights 刀片显示了您的集群利用率。这将在第七章“监控 AKS 集群和应用程序”中进行详细探讨。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.15.jpg)

###### 图 2.15：使用 Insights 刀片显示集群利用率

这就结束了我们对集群和 Azure 门户中一些有趣的配置选项的快速概述。在下一节中，我们将使用 Cloud Shell 连接到我们的 AKS 集群，然后在我们的集群上启动一个演示应用程序。

### 使用 Azure Cloud Shell 访问您的集群

一旦部署成功完成，请在搜索栏附近找到小的 Cloud Shell 图标，如*图 2.16*中所示，并单击它：

![通过单击顶部的云外壳图标，在搜索栏旁边启动 Azure 云外壳。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.16.jpg)

###### 图 2.16：单击云外壳图标以打开 Azure 云外壳

门户网站会要求您选择 PowerShell 或 Bash 作为默认的外壳体验。由于我们将主要使用 Linux 工作负载，请选择**Bash**：

![选择 Bash 选项以便按照本书中的示例进行操作。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.17.jpg)

###### 图 2.17：选择 Bash 选项

如果这是您第一次启动云外壳，系统会要求您创建一个存储帐户；请确认并创建它。

您可能会收到包含挂载存储错误的错误消息。如果出现该错误，请重新启动您的云外壳：

![示例显示警告消息，显示“无法挂载 Azure 文件共享。您的云驱动器将不可用”。这可以通过在云外壳顶部选择重新启动按钮来解决。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.18.jpg)

###### 图 2.18：点击重新启动按钮以解决挂载存储错误

单击电源按钮。它应该重新启动，您应该看到类似*图 2.19*的东西：

![重新选择电源按钮后，云外壳成功启动 Bash。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.19.jpg)

###### 图 2.19：成功启动云外壳

您可以拉动分隔器/分隔线，以查看更多或更少的外壳内容：

![云外壳窗口的分隔器由三个点表示，可以用来使云外壳变大或变小。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.20.jpg)

###### 图 2.20：使用分隔器使云外壳变大或变小

用于与 Kubernetes 集群进行交互的命令行工具称为`kubectl`。使用 Azure 云外壳的好处是，这个工具以及许多其他工具都是预安装的，并且定期维护。`kubectl`使用存储在`~/.kube/config`中的配置文件来存储访问集群的凭据。

#### 注意

在 Kubernetes 社区中有一些关于正确发音`kubectl`的讨论。通常的发音方式是 kube-c-t-l、kube-control 或 kube-cuddle。

要获取访问集群所需的凭据，您需要输入以下命令：

```
az aks get-credentials --resource-group rg-handsonaks --name handsonaks
```

要验证您是否有访问权限，请输入以下内容：

```
kubectl get nodes
```

你应该看到类似*图 2.21*的东西：

![显示节点详细信息，如节点名称、状态、角色、年龄和版本的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.21.jpg)

###### 图 2.21：kubectl get nodes 命令的输出

这个命令已经验证了我们可以连接到我们的 AKS 集群。在下一节中，我们将继续启动我们的第一个应用程序。

### 部署您的第一个演示应用程序

您已经连接好了。我们现在将启动我们的第一个应用程序。在 Cloud Shell 中，有两种编辑代码的选项。您可以使用命令行工具，如`vi`或`nano`，也可以通过输入`code`命令来使用图形代码编辑器。我们将在我们的示例中使用图形编辑器，但请随意使用您感觉最舒适的工具。

为了本书的目的，所有的代码示例都托管在一个 GitHub 存储库中。您可以将此存储库克隆到您的 Cloud Shell，并直接使用代码示例。要将 GitHub 存储库克隆到您的 Cloud Shell，请使用以下命令：

```
git clone https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Azure---Second-Edition.git Hands-On-Kubernetes-on-Azure
```

要访问本章的代码示例，请进入代码示例目录并转到`Chapter02`目录：

```
cd Hands-On-Kubernetes-on-Azure/Chapter02/
```

我们现在将直接在那里使用代码。在本书的这一部分，我们暂时不会关注`YAML`文件中的内容。本章的目标是在集群上启动一个应用程序。在接下来的章节中，我们将深入探讨它们是如何构建的，以及您如何创建自己的应用程序。

我们将根据`azure-vote.yaml`文件中的定义创建一个应用程序。要在 Cloud Shell 中打开该文件，您可以输入以下命令：

```
code azure-vote.yaml
```

以下是您方便的代码示例：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: azure-vote-back
spec:
  replicas: 1
  selector:
    matchLabels:
      app: azure-vote-back
  template:
    metadata:
      labels:
        app: azure-vote-back
    spec:
      containers:
      - name: azure-vote-back
        image: redis
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 250m
            memory: 256Mi
        ports:
        - containerPort: 6379
          name: redis
---
apiVersion: v1
kind: Service
metadata:
  name: azure-vote-back
spec:
  ports:
  - port: 6379
  selector:
    app: azure-vote-back
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: azure-vote-front
spec:
  replicas: 1
  selector:
    matchLabels:
      app: azure-vote-front
  template:
    metadata:
      labels:
        app: azure-vote-front
    spec:
      containers:
      - name: azure-vote-front
        image: microsoft/azure-vote-front:v1
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 250m
            memory: 256Mi
        ports:
        - containerPort: 80
        env:
        - name: REDIS
          value: "azure-vote-back"
---
apiVersion: v1
kind: Service
metadata:
  name: azure-vote-front
spec:
  type: LoadBalancer
  ports:
  - port: 80
  selector:
    app: azure-vote-front
```

您可以在 Cloud Shell 代码编辑器中对文件进行更改。如果您进行了更改，可以点击右上角的**...**图标，然后点击**保存**来保存文件：

![浏览器中的代码编辑器。点击三个点保存文件。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.22.jpg)

###### 图 2.22：点击[...]保存文件

文件应该已保存。您可以使用以下命令检查：

```
cat azure-vote.yaml
```

#### 注意：

在 Linux 中，按下*Tab*按钮会展开文件名。在前面的场景中，如果您在输入`az`后按下`Tab`，它应该会展开为`azure-vote.yaml`。

现在，让我们启动应用程序：

```
kubectl create -f azure-vote.yaml
```

您应该很快就会看到*图 2.23*中显示的输出，告诉您已创建了哪些资源：

![kubectl create 命令的输出，显示已创建了 azure-vote-back 和 azure-vote-front 部署以及 azure-vote-back 和 azure-vote-front 服务。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.23.jpg)

###### 图 2.23：kubectl create 命令的输出

您可以通过输入以下内容来检查进度：

```
kubectl get pods
```

如果您输入得很快，您可能会看到某个 pod 仍处于`ContainerCreating`过程中：

![使用 kubectl get pods -w 命令检查集群中 pod 的进度。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.24.jpg)

###### 图 2.24：kubectl get pods 命令的输出

#### 注意

输入`kubectl`可能会变得乏味。您可以使用`alias`命令使生活变得更轻松。您可以使用以下命令将`k`作为`kubectl`的别名：`alias k=kubectl`。运行上述命令后，您只需使用`k get pods`。出于本书的教学目的，我们将继续使用完整的`kubectl`命令。

按上箭头键并按*Enter*，直到所有 pod 的状态都为`Running`。设置所有 pod 需要一些时间，您可以使用以下命令跟踪它们的状态：

```
kubectl get pods --watch
```

要停止跟踪 pod 的状态（当它们全部处于运行状态时），可以按*Ctrl* + *C*（Mac 上为*command* + *C*）。

为了公开访问我们的应用程序，我们需要等待另一件事。现在我们想知道负载均衡器的公共 IP，以便我们可以访问它。如果您还记得*第一章，Docker 和 Kubernetes 简介*中的内容，Kubernetes 中的服务将创建一个 Azure 负载均衡器。这个负载均衡器将在我们的应用程序中获得一个公共 IP，以便我们可以公开访问它。

键入以下命令以获取负载均衡器的公共 IP：

```
kubectl get service azure-vote-front --watch
```

起初，外部 IP 可能显示为“待定”。等待公共 IP 出现，然后按*Ctrl* + *C*（Mac 上为*command* + *C*）退出：

![kubectl get service --watch 的输出。您可以看到服务 IP 从待定更改为实际 IP 地址。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.25.jpg)

###### 图 2.25：从待定 IP 更改为实际 IP 地址的服务 IP

注意外部 IP 地址，并在浏览器中输入。您应该看到*图 2.26*中显示的输出：

![启动应用程序，其中包含三个按钮（猫、狗和重置），以及底部的猫和狗的计数。单击猫和狗，计数会增加，重置可以用于将计数设置为零。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.26.jpg)

###### 图 2.26：您刚刚启动的实际应用程序

单击**猫**或**狗**，观察计数增加。

您现在已经启动了自己的集群和第一个 Kubernetes 应用程序。请注意，Kubernetes 负责诸如连接前端和后端、将其暴露给外部世界以及为服务提供存储等任务。

在进入下一章之前，我们将清理我们的部署。由于我们是从一个文件创建的所有内容，我们也可以通过将 Kubernetes 指向该文件来删除所有内容。键入`kubectl delete -f azure-vote.yaml`，观察所有对象被删除：

![kubectl delete -f azure-vote.yaml 命令的输出，验证部署和服务已被删除。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_2.27.jpg)

###### 图 2.27：清理部署

在本节中，我们已经使用 Cloud Shell 连接到了我们的 AKS 集群，成功启动并连接到了演示应用程序，最后清理了创建的资源。

## 摘要

完成了本章后，您可以访问并浏览 Azure 门户，执行部署 AKS 集群所需的所有功能。您利用 Azure 的免费试用来学习 AKS 和其他 Azure 服务的方方面面。您启动了自己的 AKS 集群，并可以使用 Azure 门户根据需要自定义配置。

您还可以在不在计算机上安装任何内容的情况下使用 Azure Cloud Shell。这对于接下来的所有部分都很重要，在那里您将做的不仅仅是启动简单的应用程序。最后，您启动了一个可公开访问的服务。这个应用程序的框架与您将在后面的章节中启动的复杂应用程序相同。

在下一章中，我们将深入研究不同的部署选项，将应用程序部署到 AKS 上。


# 第二部分：在 AKS 上部署

在本书的这一部分中，我们已经介绍了 Docker 和 Kubernetes 的基础知识，并在 Azure 上设置了一个 Kubernetes 集群。在本节中，我们将介绍如何在该 Kubernetes 集群上部署应用程序。

在本节中，我们将逐步构建和部署不同的应用程序在 AKS 之上。我们将从部署一个简单的应用程序开始，然后介绍诸如扩展、监控和认证等概念。到本节结束时，您应该能够轻松地将应用程序部署到 AKS 上。

本节包含以下章节：

+   *第三章，在 AKS 上部署应用程序*

+   *第四章，构建可扩展的应用程序*

+   *第五章，在 AKS 中处理常见故障*

+   *第六章，使用 HTTPS 和 Azure AD 保护您的应用程序*

+   *第七章，监控 AKS 集群和应用程序*


# 第三章：在 AKS 上部署应用程序

在本章中，我们将在**Azure Kubernetes Service**（**AKS**）上部署两个应用程序。一个应用程序由多个部分组成，您将一步一步地构建这些应用程序，同时解释它们背后的概念模型。您将能够轻松地将本章中的步骤调整为在 AKS 上部署任何其他应用程序。

部署应用程序并对其进行更改时，您将使用 YAML 文件。YAML 是**YAML Ain't Markup Language**的首字母缩略词。YAML 是一种用于创建配置文件以部署到 Kubernetes 的语言。虽然您可以使用 JSON 或 YAML 文件来部署应用程序到 Kubernetes，但 YAML 是最常用的语言。YAML 变得流行是因为与 JSON 或 XML 相比，人类更容易阅读它。在本章和整本书中，您将看到多个 YAML 文件的示例。

在部署示例 guestbook 应用程序时，您将看到 Kubernetes 概念的实际应用。您将看到**部署**与**ReplicaSet**的关联，以及它与部署的**Pods**的关联。部署是 Kubernetes 中用于定义应用程序期望状态的对象。部署将创建一个 ReplicaSet。ReplicaSet 是 Kubernetes 中保证一定数量的 Pod 始终可用的对象。因此，ReplicaSet 将创建一个或多个 Pods。Pod 是 Kubernetes 中的一个对象，它是一个或多个容器的组。让我们重新审视部署、ReplicaSet 和 Pod 之间的关系：

![该图描述了部署、ReplicaSet 和 Pod 之间的关联。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.1.jpg)

###### 图 3.1：部署、ReplicaSet 和 Pod 之间的关系

在部署示例应用程序时，您将使用**服务对象**来连接应用程序。Kubernetes 中的服务是用于为应用程序提供静态 IP 地址和 DNS 名称的对象。由于 Pod 可以在集群中被杀死并移动到不同的节点，服务确保您可以连接到应用程序的静态终点。

您还将编辑示例应用程序，使用 ConfigMap 提供配置细节。ConfigMap 是一个用于向 Pod 提供配置细节的对象。它允许您将配置设置保留在容器之外。然后，您可以通过将 ConfigMap 连接到部署来向应用程序提供这些配置细节。

最后，您将了解 Helm。Helm 是 Kubernetes 的包管理器，有助于简化部署过程。您将使用 Helm 部署 WordPress 网站，并了解 Helm 为 Kubernetes 带来的价值。WordPress 安装在 Kubernetes 中使用持久存储。您将学习如何设置 AKS 中的持久存储。

本章将涵盖以下主题：

+   部署示例留言板应用程序

+   完整部署示例留言板应用程序

+   使用 Helm 安装复杂的 Kubernetes 应用程序

我们将从示例留言板应用程序开始。

## 部署示例留言板应用程序

在本章中，您将部署经典的留言板示例 Kubernetes 应用程序。您将主要按照[`Kubernetes.io/docs/tutorials/stateless-application/guestbook/`](https://Kubernetes.io/docs/tutorials/stateless-application/guestbook/)中的步骤进行，但会进行一些修改。您将使用这些修改来展示额外的概念，比如 ConfigMaps，这些概念在原始示例中并不存在。

示例留言板应用程序是一个简单的多层 Web 应用程序。该应用程序中的不同层将具有多个实例。这对于高可用性和扩展都是有益的。留言板的前端是一个无状态应用程序，因为前端不存储任何状态。后端的 Redis 集群是有状态的，因为它存储所有留言板条目。

你将在下一章中使用这个应用程序作为测试后端和前端独立扩展的基础。

在开始之前，让我们考虑一下我们将要部署的应用程序。

### 介绍应用程序

该应用程序存储并显示留言板条目。您可以使用它来记录所有访问您的酒店或餐厅的人的意见。在此过程中，我们将解释 Kubernetes 概念，如部署和 ReplicaSets。

该应用程序使用 PHP 作为前端。前端将使用多个副本进行部署。该应用程序使用 Redis 作为数据存储。Redis 是一种内存中的键值数据库。Redis 通常用作缓存。根据[`www.datadoghq.com/docker-adoption/`](https://www.datadoghq.com/docker-adoption/)，它是最受欢迎的容器映像之一。

![guestbook 应用的概述。用户连接到前端。前端然后连接到 Redis 主节点或 Redis 从节点之一。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.2.jpg)

###### 图 3.2：guestbook 应用的高级概述

我们将通过部署 Redis 主节点来开始部署此应用程序。

### 部署 Redis 主节点

在本节中，您将部署 Redis 主节点。您将了解到此部署所需的 YAML 语法。在下一节中，您将对此 YAML 进行更改。在进行更改之前，让我们先部署 Redis 主节点。

执行以下步骤完成任务：

1.  打开友好的 Cloud Shell，如*图 3.3*中所示：![要打开 Cloud Shell，请单击搜索栏右侧的图标。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.3.jpg)

###### 图 3.3：打开 Cloud Shell

1.  如果您尚未克隆此书的 github 存储库，请使用以下命令进行克隆：

```
git clone https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Azure---Second-Edition Hands-On-Kubernetes-on-Azure
cd Hands-On-Kubernetes-on-Azure/Chapter03/
```

1.  输入以下命令以部署主节点：

```
kubectl apply -f redis-master-deployment.yaml
```

应用程序下载和启动需要一些时间。在等待时，让我们了解您刚刚输入和执行的命令。让我们开始探索使用的 YAML 文件的内容：

```
1 apiVersion: apps/v1 # for versions before 1.9.0 use apps/v1beta2
2 kind: Deployment
3 metadata:
4   name: redis-master
5   labels:
6     app: redis
7 spec:
8   selector:
9     matchLabels:
10      app: redis
11      role: master
12      tier: backend
13  replicas: 1
14  template:
15    metadata:
16      labels:
17        app: redis
18        role: master
19        tier: backend
20    spec:
21      containers:
22      - name: master
23        image: k8s.gcr.io/redis:e2e # or just image: redis
24        resources:
25          requests:
26            cpu: 100m
27            memory: 100Mi
28        ports:
29        - containerPort: 6379
```

让我们深入了解提供的参数的代码：

+   第 2 行：这说明我们正在创建一个“部署”。如《第一章》*Docker 和 Kubernetes 简介*中所解释的，部署是围绕 Pods 的包装，使得更新和扩展 Pods 变得容易。

+   第 4-6 行：在这里，“部署”被赋予一个名称，即`redis-master`。

+   第 7-12 行：这些行让我们指定此“部署”将管理的容器。在此示例中，“部署”将选择和管理所有标签匹配的容器（`app: redis`，`role: master`和`tier: backend`）。前面的标签与第 14-19 行提供的标签完全匹配。

+   **第 13 行**：告诉 Kubernetes 我们需要确切地运行一个 Redis 主节点的副本。这是 Kubernetes 声明性质的一个关键方面。您提供了应用程序需要运行的容器的描述（在本例中，只有一个 Redis 主节点的副本），Kubernetes 会处理它。

+   **第 14-19 行**：为运行的实例添加标签，以便将其分组并连接到其他容器。我们将在后面讨论它们是如何使用的。

+   **第 22 行**：为这个容器指定一个名字，即`master`。在多容器 Pod 的情况下，Pod 中的每个容器都需要一个唯一的名字。

+   **第 23 行**：这一行指示将要运行的 Docker 镜像。在这种情况下，它是使用`e2e`标记的`redis`镜像（最新通过端到端[`e2e`]测试的 Redis 镜像）。

+   **第 28-29 行**：这两行表示容器将监听`6379`端口。

+   **第 24-27 行**：设置容器请求的`cpu/memory`资源。在这种情况下，请求的是 0.1 CPU，即`100m`，通常也被称为 100 毫核。请求的内存是`100Mi`，或 104857600 字节，大约等于 105MB ([`Kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/`](https://Kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/))。您也可以以类似的方式设置 CPU 和内存限制。限制是容器可以使用的上限。如果您的 Pod 达到了 CPU 限制，它将被限制，而如果它达到了内存限制，它将被重新启动。在 Kubernetes 中设置请求和限制是最佳实践。

#### 注意

Kubernetes 的 YAML 定义类似于 Docker 运行特定容器镜像时给出的参数。如果您必须手动运行这个例子，您可以这样定义：

`# 运行一个名为 master 的容器，监听 6379 端口，使用 redis:e2e 镜像，内存为 100M，CPU 为 100m。`

`docker run --name master -p 6379:6379 -m 100M -c 100m -d k8s.gcr.io/redis:e2e`

在这一部分，您已经部署了 Redis 主节点，并学习了用于创建此部署的 YAML 文件的语法。在下一部分，您将检查部署并了解创建的不同元素。

**检查部署**

`redis-master`部署现在应该已经完成。继续在您在上一部分打开的 Azure Cloud Shell 中输入以下内容：

```
kubectl get all
```

你应该会得到*图 3.4*中显示的输出：

![使用 kubectl get all 命令，您将看到创建了诸如 Pod、service、Deployment 和 ReplicaSet 等对象。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.4.jpg)

###### 图 3.4：显示部署创建的对象的输出

你可以看到我们有一个名为`redis-master`的部署。它控制着一个`redis-master-<随机 id>`的 ReplicaSet。进一步检查后，你还会发现 ReplicaSet 正在控制一个名为`redis-master-<replica set 随机 id>-<随机 id>`的 Pod。*图 3.1*以图形方式展示了这种关系。

通过执行`kubectl describe <object> <instance-name>`命令，可以获得更多详细信息，如下所示：

```
kubectl describe deployment/redis-master
```

这将生成以下输出：

![通过使用 kubectl describe deployment/redis-master 命令，您将看到部署的更多细节。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.5.jpg)

###### 图 3.5：描述部署的输出

您现在已经启动了一个具有默认配置的 Redis 主节点。通常，您会使用特定于环境的配置启动应用程序。

在下一节中，我们将介绍一个名为 ConfigMaps 的新概念，然后重新创建 Redis 主节点。因此，在继续之前，我们需要清理当前版本，可以通过运行以下命令来完成：

```
kubectl delete deployment/redis-master
```

执行此命令将产生以下输出：

```
deployment.extensions "redis-master" deleted
```

在本节中，您检查了您创建的 Redis 主节点部署。您看到了部署与 ReplicaSet 的关系，以及 ReplicaSet 与 Pod 的关系。在接下来的部分中，您将使用通过 ConfigMap 提供的特定于环境的配置重新创建这个 Redis 主节点。

### 带有 ConfigMap 的 Redis 主节点

以前的部署没有任何问题。在实际使用情况中，很少会启动一个没有一些配置设置的应用程序。在这种情况下，我们将使用 ConfigMap 为`redis-master`设置配置设置。

ConfigMap 是一种便携的配置容器的方式，而不需要为每个配置专门的镜像。它具有需要在容器上设置的数据的键值对。ConfigMap 用于非机密配置。Kubernetes 有一个名为**Secret**的单独对象。Secret 用于包含关键数据的配置，如密码。这将在本书的*第十章*，*保护您的 AKS 集群*中详细探讨。

在此示例中，我们将创建一个 ConfigMap。在此 ConfigMap 中，我们将`redis-config`配置为键，值将为：

`maxmemory 2mb`

`maxmemory-policy allkeys-lru`

现在，让我们创建此 ConfigMap。有两种创建 ConfigMap 的方法：

+   从文件创建 ConfigMap

+   从 YAML 文件创建 ConfigMap

我们将详细探讨每一个。

**从文件创建 ConfigMap**

以下步骤将帮助我们从文件创建 ConfigMap：

1.  通过在终端中键入`code redis-config`来打开 Azure Cloud Shell 代码编辑器。复制并粘贴以下两行，并将其保存为`redis-config`：

```
maxmemory 2mb
maxmemory-policy allkeys-lru
```

1.  现在您可以使用以下代码创建 ConfigMap：

```
kubectl create configmap example-redis-config --from-file=redis-config
```

1.  您应该得到以下输出：

```
configmap/example-redis-config created
```

1.  您可以使用相同的命令描述此 ConfigMap：

```
kubectl describe configmap/example-redis-config
```

1.  输出将如*图 3.6*所示：![使用 kubectl describe configmap/example-redis-config 命令，将生成提供名称、命名空间、标签、注释、数据、redis-config、内存和事件等详细信息的输出。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.6.jpg)

###### 图 3.6：描述 ConfigMap 的输出

在此示例中，您通过引用磁盘上的文件创建了 ConfigMap。部署 ConfigMaps 的另一种方法是通过从 YAML 文件创建它们。让我们看看在以下部分如何完成这一点。

**从 YAML 文件创建 ConfigMap**

在本节中，您将使用 YAML 文件从上一节重新创建 ConfigMap：

1.  首先，删除先前创建的 ConfigMap：

```
kubectl delete configmap/example-redis-config
```

1.  将以下行复制并粘贴到名为`example-redis-config.yaml`的文件中，然后保存该文件：

```
apiVersion: v1
data:
  redis-config: |- 
    maxmemory 2mb
    maxmemory-policy allkeys-lru
kind: ConfigMap
metadata:
  name: example-redis-config
  namespace: default
```

1.  现在，您可以通过以下命令重新创建您的 ConfigMap：

```
kubectl create -f example-redis-config.yaml
```

1.  您应该得到以下输出：

```
configmap/example-redis-config created
```

1.  接下来，运行以下命令：

```
kubectl describe configmap/example-redis-config
```

1.  此命令返回与先前相同的输出：

```
Name:           example-redis-config
Namespace:      default
Labels:         <none>
Annotations:    <none>
Data
====
redis-config:
----
maxmemory 2mb
maxmemory-policy allkeys-lru
Events:	<none>
```

如您所见，使用 YAML 文件，您能够创建相同的 ConfigMap。

#### 注意：

`kubectl get`具有有用的选项`-o`，可用于以 YAML 或 JSON 格式获取对象的输出。这在您对系统进行手动更改并希望以 YAML 格式查看生成的对象时非常有用。您可以使用以下命令以 YAML 格式获取当前的 ConfigMap：

`kubectl get -o yaml configmap/example-redis-config`

现在您已经定义了 ConfigMap，让我们使用它。

**使用 ConfigMap 读取配置数据**

在本节中，您将重新配置`redis-master`部署以从 ConfgMap 读取配置：

1.  首先，修改`redis-master-deployment.yaml`以使用 ConfigMap 如下。在源代码之后将解释需要进行的更改：

#### 注意

如果您下载了本书附带的源代码，在*第三章*，*在 AKS 上部署应用程序*中有一个名为`redis-master-deployment_Modified.yaml`的文件，其中已经应用了必要的更改。

```
1 apiVersion: apps/v1 # for versions before 1.9.0 use apps/v1beta2
2  kind: Deployment
3  metadata:
4    name: redis-master
5    labels:
6      app: redis
7  spec:
8    selector:
9      matchLabels:
10       app: redis
11       role: master
12       tier: backend
13   replicas: 1
14   template:
15     metadata:
16       labels:
17         app: redis
18         role: master
19         tier: backend
20     spec:
21       containers:
22       - name: master
23         image: k8s.gcr.io/redis:e2e
24         command:
25         - redis-server
26         - "/redis-master/redis.conf"
27         env:
28         - name: MASTER
29           value: "true"
30         volumeMounts:
31         - mountPath: /redis-master
32           name: config
33         resources:
34           requests:
35             cpu: 100m
36             memory: 100Mi
37         ports:
38         - containerPort: 6379
39       volumes:
40         - name: config
41           configMap:
42             name: example-redis-config
43             items:
44             - key: redis-config
45               path: redis.conf
```

让我们深入了解代码，以理解不同的部分：

+   第 24-26 行：这些行介绍了在 Pod 启动时将执行的命令。在这种情况下，这将启动指向特定配置文件的`redis-server`。

+   第 27-29 行：显示如何将配置数据传递给正在运行的容器。这种方法使用环境变量。在 Docker 形式中，这相当于`docker run -e "MASTER=true". --name master -p 6379:6379 -m 100M -c 100m -d Kubernetes /redis:v1`。这将环境变量`MASTER`设置为`true`。您的应用程序可以读取环境变量设置以进行配置。

+   第 30-32 行：这些行在运行的容器上的`/redis-master`路径上挂载名为`config`的卷（此卷在第 39-45 行中定义）。它将隐藏原始容器上`/redis-master`上存在的任何内容。

以 Docker 术语来说，相当于`docker run -v config:/redis-master. -e "MASTER=TRUE" --name master -p 6379:6379 -m 100M -c 100m -d Kubernetes /redis:v1`。

+   第 40 行：为卷命名为`config`。此名称将在此 Pod 的上下文中使用。

+   第 41-42 行：声明应该从`example-redis-config` ConfigMap 加载此卷。此 ConfigMap 应该已经存在于系统中。您已经定义了这一点，所以没问题。

+   第 43-45 行：在这里，您正在将`redis-config`键的值（两行`maxmemory`设置）加载为`redis.conf`文件。

1.  让我们创建这个更新后的部署：

```
kubectl create -f redis-master-deployment_Modified.yml
```

1.  这应该输出以下内容：

```
deployment.apps/redis-master created
```

1.  现在让我们确保配置已成功应用。首先，获取 Pod 的名称：

```
kubectl get pods
```

1.  然后`exec`进入 Pod 并验证已应用设置：

```
kubectl exec -it redis-master-<pod-id> redis-cli
127.0.0.1:6379&gt; CONFIG GET maxmemory
  1) "maxmemory" 2) "2097152"
127.0.0.1:6379&gt; CONFIG GET maxmemory-policy
  "maxmemory-policy"
  "allkeys-lru" 127.0.0.1:6379&gt;exit
```

总之，您刚刚执行了配置云原生应用程序的重要且棘手的部分。您还会注意到应用程序必须配置为动态读取配置。配置应用程序后，您访问了正在运行的容器以验证运行配置。

#### 注意

连接到运行中的容器对于故障排除和诊断非常有用。由于容器的短暂性质，您不应该连接到容器进行额外的配置或安装。这应该是您容器镜像的一部分，或者是您通过 Kubernetes 提供的配置（就像我们刚刚做的那样）。

在本节中，您配置了 Redis Master 从 ConfigMap 加载配置数据。在下一节中，我们将部署端到端的应用程序。

## 示例 guestbook 应用程序的完整部署

在了解使用 ConfigMap 动态配置应用程序的过程中，我们将现在返回到部署其余 guestbook 应用程序的过程中。您将再次遇到部署、ReplicaSets 和后端和前端的 Pods 的概念。除此之外，您还将被介绍另一个关键概念，称为服务。

为了开始完整的部署，我们将创建一个服务来公开 Redis 主服务。

### 公开 Redis 主服务

在普通 Docker 中公开端口时，公开的端口受限于其运行的主机。在 Kubernetes 网络中，集群中不同 Pod 之间存在网络连接。但是，Pod 本身是短暂的，这意味着它们可以被关闭、重新启动，甚至移动到其他主机而不保留其 IP 地址。如果您直接连接到 Pod 的 IP，如果该 Pod 被移动到新主机，您可能会失去连接。

Kubernetes 提供了`service`对象，它处理了这个确切的问题。使用标签匹配选择器，它代理流量到正确的 Pod，并进行负载平衡。在这种情况下，主服务只有一个 Pod，因此它只确保流量被定向到独立于 Pod 所在节点的 Pod。要创建服务，请运行以下命令：

```
kubectl apply -f redis-master-service.yaml 
```

Redis 主服务具有以下内容：

```
1   apiVersion: v1
2   kind: Service
3   metadata:
4     name: redis-master
5     labels:
6       app: redis
7       role: master
8       tier: backend
9   spec:
10   ports:
11   - port: 6379
12     targetPort: 6379
13    selector:
14      app: redis
15      role: master
16      tier: backend
```

现在让我们看看您使用前面的代码创建了什么：

+   **第 1-8 行：**这些行告诉 Kubernetes，我们想要一个名为`redis-master`的服务，它具有与我们的`redis-master`服务器 Pod 相同的标签。

+   **第 10-12 行：**这些行表示服务应该处理到达端口`6379`的流量，并将其转发到与第 13 行和第 16 行之间定义的选择器匹配的 Pod 的端口`6379`。

+   **第 13-16 行**：这些行用于查找需要代理传入流量的 Pod。因此，任何具有匹配标签（`app: redis`、`role: master`和`tier: backend`）的 Pod 都应该处理端口`6379`的流量。如果您回顾前面的示例，这些标签正是我们应用于该部署的标签。

我们可以通过运行以下命令来检查服务的属性：

```
kubectl get service
```

这将给您一个如*图 3.7*所示的输出：

使用 kubectl get service 命令，您将看到每个服务的名称、类型、集群 IP、外部 IP、端口和年龄等详细信息。

###### 图 3.7：创建的服务的输出

您会看到一个名为`redis-master`的新服务已创建。它具有集群范围的 IP`10.0.227.250`（在您的情况下，IP 可能会有所不同）。请注意，此 IP 仅在集群内部有效（因此是`ClusterIP`类型）。

服务还为该服务引入了一个域名服务器（DNS）名称。DNS 名称的格式为`<service-name>.<namespace>.svc.cluster.local`；在我们的情况下，那将是`redis-master.default.svc.cluster.local`。为了看到这一点，我们将在我们的`redis-master` VM 上进行名称解析。默认镜像没有安装`nslookup`，所以我们将通过运行`ping`命令来绕过。如果该流量没有返回，不要担心；这是因为您没有在服务上公开`ping`，只有`redis`端口。让我们来看一下：

```
kubectl get pods
#note the name of your redis-master pod
kubectl exec -it redis-master-<pod-id> bash
ping redis-master
```

这应该输出结果名称解析，显示您服务的完全合格域名（FQDN）和之前显示的 IP 地址。您可以通过`exit`命令退出 Pod，如*图 3.8*所示：

输出显示了服务的 FQDN 以及 IP 地址。

###### 图 3.8：使用 ping 命令查看服务的 FQDN

在这一部分，您使用服务公开了 Redis 主服务器。在下一部分，您将部署 Redis 从服务器。

### 部署 Redis 从服务器

在云上运行单个后端是不推荐的。您可以在主从设置中配置 Redis。这意味着您可以有一个主服务器用于写入流量，以及多个从服务器用于处理读取流量。这对于处理增加的读取流量和提高可用性非常有用。

让我们来设置一下：

1.  通过运行以下命令创建部署：

```
kubectl apply -f redis-slave-deployment.yaml
```

1.  让我们现在检查所有已创建的资源：

```
kubectl get all
```

输出将如*图 3.9*所示：

![使用 kubectl get all 命令，您会看到新的对象，如 Pod、Deployment 和 ReplicaSet。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.9.jpg)

###### 图 3.9：部署 Redis 从节点会创建一些新对象

1.  根据前面的输出，您可以看到您创建了两个`redis-slave` Pod 的副本。这可以通过检查`redis-slave-deployment.yaml`文件来确认：

```
1   apiVersion: apps/v1 # for versions before 1.9.0 use apps/v1beta2
2   kind: Deployment
3   metadata:
4     name: redis-slave
5     labels:
6       app: redis
7   spec:
8     selector:
9       matchLabels:
10       app: redis
11       role: slave
12       tier: backend
13   replicas: 2
14   template:
15     metadata:
16       labels:
17         app: redis
18         role: slave
19         tier: backend
20     spec:
21       containers:
22       - name: slave
23         image: gcr.io/google_samples/gb-redisslave:v1
24         resources:
25           requests:
26             cpu: 100m
27             memory: 100Mi
28         env:
29         - name: GET_HOSTS_FROM
30           value: dns
31           # Using 'GET_HOSTS_FROM=dns' requires your cluster to
32           # provide a dns service. As of Kubernetes 1.3, DNS is a built-in
33           # service launched automatically. However, if the cluster you are using
34           # does not have a built-in DNS service, you can instead
35           # access an environment variable to find the master
36           # service's host. To do so, comment out the 'value: dns' line above, and
37           # uncomment the line below:
38           # value: env
39         ports:
40         - containerPort: 6379
```

除了以下内容之外，其他都是一样的：

+   **第 13 行**：副本数量为`2`。

+   **第 23 行**：您现在正在使用特定的从节点镜像。

+   **第 29-30 行**：将`GET_HOSTS_FROM`设置为`dns`。正如您在前面的示例中看到的，DNS 在集群中解析。

1.  与主服务一样，您需要通过运行以下命令公开从服务：

```
kubectl apply -f redis-slave-service.yaml
```

这个服务和`redis-master`服务之间唯一的区别是，这个服务会将流量代理到具有`role:slave`标签的 Pod。

1.  通过运行以下命令来检查`redis-slave`服务：

```
kubectl get service
```

这应该会给您显示*图 3.10*中显示的输出：

![当您执行 kubectl get service 命令时，输出屏幕将显示一个 redis-master 和一个 redis-slave。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.10.jpg)

###### 图 3.10：输出显示了 redis-master 和 redis-slave 服务

现在您已经拥有一个 Redis 集群正在运行，有一个主节点和两个副本。在下一节中，您将部署和公开前端。

### 部署和公开前端

到目前为止，您已经专注于 Redis 后端。现在您已经准备好部署前端。这将为您的应用程序添加一个图形网页，您将能够与之交互。

您可以使用以下命令创建前端：

```
kubectl apply -f frontend-deployment.yaml
```

要验证部署，请运行此代码：

```
kubectl get pods
```

这将显示*图 3.11*中显示的输出：

![当您执行 kubectl get pods 命令时，输出屏幕会显示总共 6 个处于运行状态的 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.11.jpg)

###### 图 3.11：显示运行前端的额外 Pod 的输出

您会注意到这个部署指定了`3`个副本。部署具有通常的方面，但有一些小的变化，如下面的代码所示：

```
1   apiVersion: apps/v1 # for versions before 1.9.0 use apps/v1beta2 kind: Deployment
2   metadata:
3     name: frontend
4     labels:
5       app: guestbook
6   spec:
7     selector:
8       matchLabels:
9         app: guestbook
10        tier: frontend
11    replicas: 3
12    template:
13      metadata:
14        labels:
15          app: guestbook
16          tier: frontend
17      spec:
18        containers:
19        - name: php-redis
20          image: gcr.io/google-samples/gb-frontend:v4
21          resources:
22            requests:
23              cpu: 100m
24              memory: 100Mi
25          env:
26          - name: GET_HOSTS_FROM
27            value: dns
28            # Using GET_HOSTS_FROM=dns requires your cluster to
29            # provide a dns service. As of Kubernetes 1.3, DNS is a built-in
30            # service launched automatically. However, if the cluster you are using
31            # does not have a built-in DNS service, you can instead
32            # access an environment variable to find the master
33            # service's host. To do so, comment out the 'value: dns' line above, and
34            # uncomment the line below:
35            # value: env
36          ports:
37          - containerPort: 80
```

让我们看看这些变化：

+   **第 11 行**：副本数量设置为`3`。

+   **第 8-10 行和 14-16 行**：标签设置为`app: guestbook`和`tier: frontend`。

+   **第 20 行**：使用`gb-frontend:v4`作为镜像。

您现在已经创建了前端部署。现在您需要将其公开为服务。

**公开前端服务**

定义 Kubernetes 服务的多种方式。我们创建的两个 Redis 服务都是`ClusterIP`类型。这意味着它们仅在集群内可访问，如*图 3.12*所示：

![ClusterIP 类型的服务是跨整个集群的 IP，并连接到每个节点上的 pod。ClusterIP 仅在集群内可用。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.12.jpg)

###### 图 3.12：类型为 ClusterIP 的 Kubernetes 服务

另一种服务类型是`NodePort`类型。这种服务将在每个节点上的静态端口上暴露，如*图 3.13*所示：

![NodePort 类型的服务将在每个节点上打开一个端口，该端口将连接到每个节点上的 Pod。外部用户可以使用该端口从集群外部连接到 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.13.jpg)

###### 图 3.13：类型为 NodePort 的 Kubernetes 服务

最后一种类型 - 我们将在示例中使用的类型 - 是`LoadBalancer`类型。这将创建一个**Azure 负载均衡器**，我们可以使用它来连接的公共 IP，如*图 3.14*所示：

![LoadBalancer 类型的服务将创建一个外部负载均衡器，该负载均衡器将连接到每个节点上的 Pod。外部用户可以使用该负载均衡器从集群外部连接到 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.14.jpg)

###### 图 3.14：类型为 LoadBalancer 的 Kubernetes 服务

以下代码将帮助我们了解如何暴露前端服务：

```
1   apiVersion: v1
2   kind: Service
3   metadata:
4     name: frontend
5     labels:
6       app: guestbook
7       tier: frontend
8   spec:
9     # comment or delete the following line if you want to use a LoadBalancer
10    # type: NodePort # line commented out
11    # if your cluster supports it, uncomment the following to automatically create
12    # an external load-balanced IP for the frontend service.
13    type: LoadBalancer # line uncommented
14    ports:
15    - port: 80
16    selector:
17      app: guestbook
18      tier: frontend
```

+   现在您已经看到了前端服务是如何暴露的，让我们通过以下步骤使 guestbook 应用程序准备好使用：

1.  要创建服务，请运行以下命令：

```
kubectl create -f frontend-service.yaml
```

当您首次运行此步骤时，执行此步骤需要一些时间。在后台，Azure 必须执行一些操作以使其无缝。它必须创建一个 Azure 负载均衡器和一个公共 IP，并设置端口转发规则，以将端口`80`上的流量转发到集群的内部端口。

1.  运行以下命令，直到`EXTERNAL-IP`列中有值为止：

```
kubectl get service
```

这应该显示*图 3.15*中显示的输出：

![执行 kubectl get service 命令时，会生成一个输出，其中前端、kubernetes、redis-master 和 redis-slave 都有一个 Cluster IP。但是，这里只有前端有一个 External IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.15.jpg)

###### 图 3.15：一段时间后显示外部 IP 值的输出

1.  在 Azure 门户中，如果您点击**所有资源**并过滤**负载均衡器**，您将看到一个**kubernetes 负载均衡器**。点击它会显示类似于*图 3.16*的内容。突出显示的部分显示了在端口`80`上接受流量的负载均衡规则，以及您有 2 个公共 IP 地址：![在 Azure 门户中打开 Kubernetes 负载均衡器，您将看到一个负载均衡规则和两个出现在屏幕右侧的公共 IP 地址。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.16.jpg)

###### 图 3.16：在 Azure 门户中显示 Kubernetes 负载均衡器

如果您点击两个公共 IP 地址，您会看到这两个 IP 地址都链接到您的集群。其中一个将是您实际服务的 IP 地址；另一个是 AKS 用于进行出站连接的 IP 地址。

#### 注意：

Azure 有两种类型的负载均衡器：基本和标准。

基本负载均衡器后面的虚拟机可以在没有特定配置的情况下进行出站连接。标准负载均衡器后面的虚拟机（这是 AKS 的默认设置）需要特定配置才能进行出站连接。这就是为什么您会看到第二个 IP 地址配置的原因。

我们终于准备好让我们的 guestbook 应用程序投入使用！

### 正在运行的 guestbook 应用程序

在您喜欢的浏览器中输入服务的公共 IP。您应该会得到*图 3.17*中显示的输出：

![当您在浏览器中输入 IP 地址时，您将看到一个显示单词 Guestbook 的白屏。这表明 Guestbook 应用程序正在运行。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.17.jpg)

###### 图 3.17：Guestbook 应用程序正在运行

继续记录您的消息。它们将被保存。打开另一个浏览器并输入相同的 IP；您将看到您输入的所有消息。

恭喜 - 您已经完成了您的第一个完全部署的、多层、云原生的 Kubernetes 应用程序！

为了节省您的免费试用虚拟机资源，最好删除创建的部署，然后使用以下命令运行下一轮部署：

```
kubectl delete deployment frontend redis-master redis-slave
kubectl delete service frontend redis-master redis-slave
```

在前面的章节中，您已经部署了一个 Redis 集群并部署了一个可公开访问的 Web 应用程序。您已经了解了部署、ReplicaSets 和 Pods 之间的关联，以及 Kubernetes 如何使用`service`对象来路由网络流量。在本章的下一节中，您将使用 Helm 在 Kubernetes 上部署一个更复杂的应用程序。

## 使用 Helm 安装复杂的 Kubernetes 应用程序

在上一节中，我们使用静态 YAML 文件部署了我们的应用程序。当部署更复杂的应用程序跨多个环境（如开发/测试/生产）时，手动编辑每个环境的 YAML 文件可能会变得繁琐。这就是 Helm 工具的用武之地。

Helm 是 Kubernetes 的包管理器。Helm 帮助您以规模部署、更新和管理 Kubernetes 应用程序。为此，您需要编写一种称为 Helm Charts 的东西。

您可以将 Helm Charts 视为参数化的 Kubernetes YAML 文件。如果您考虑一下我们在上一节中编写的 Kubernetes YAML 文件，那些文件是静态的。您需要进入文件并编辑它们以进行更改。

Helm Charts 允许您编写带有特定参数的 YAML 文件，您可以动态设置这些参数。可以通过值文件或在部署图表时作为命令行变量来设置这些参数。

最后，使用 Helm，您不一定需要自己编写 Helm Charts；您还可以使用丰富的预先编写的 Helm Charts 库，并通过简单的命令（例如`helm install --name my-release stable/mysql`）在集群中安装流行的软件。

这正是您将在下一节中要做的。您将通过发出仅两个命令在您的集群上安装 WordPress。在接下来的章节中，您还将深入研究自定义 Helm Charts。

#### 注意

2019 年 11 月 13 日，Helm v3 的第一个稳定版本发布。在接下来的示例中，我们将使用 Helm v3。Helm v2 和 Helm v3 之间最大的区别是，Helm v3 是一个完全客户端工具，不再需要名为`tiller`的服务器端工具。

如果您想更全面地了解如何编写自己的 Helm Charts，可以参考本书作者之一的博客文章：[`blog.nillsf.com/index.php/2019/11/23/writing-a-helm-v3-chart/`](https://blog.nillsf.com/index.php/2019/11/23/writing-a-helm-v3-chart/)。

让我们从使用 Helm 在您的集群上安装 WordPress 开始。在本节中，您还将了解 Kubernetes 中的持久存储。

### 使用 Helm 安装 WordPress

如介绍中所述，Helm 具有丰富的预先编写的 Helm Charts 库。要访问此库，您需要向 Helm 客户端添加一个存储库：

1.  使用以下命令添加包含稳定 Helm Charts 的存储库：

```
helm repo add stable https://kubernetes-charts.storage.googleapis.com/
```

1.  要安装 WordPress，我们将运行以下命令：

```
helm install handsonakswp stable/wordpress
```

此操作将导致 Helm 安装详细说明在[`github.com/helm/charts/tree/master/stable/wordpress`](https://github.com/helm/charts/tree/master/stable/wordpress)的图表。

Helm 安装需要一些时间，网站才能启动。让我们在网站加载时看一下一个关键概念，即 PersistentVolumeClaims。在介绍完这个概念后，我们将回过头来看看我们创建的网站。

**PersistentVolumeClaims**

一个进程需要计算、内存、网络和存储。在 guestbook 示例中，我们看到 Kubernetes 如何帮助我们抽象出计算、内存和网络。相同的 YAML 文件适用于所有云提供商，包括特定于云的公共负载均衡器的设置。WordPress 示例显示了最后一部分，即存储，是如何从底层云提供商中抽象出来的。

在这种情况下，WordPress Helm Chart 依赖于 MariaDB helm chart（[`github.com/helm/charts/tree/master/stable/mariadb`](https://github.com/helm/charts/tree/master/stable/mariadb)）来进行数据库安装。

与无状态应用程序（如我们的前端）不同，MariaDB 需要对存储进行仔细处理。为了让 Kubernetes 处理有状态的工作负载，它有一个特定的对象称为 StatefulSet。StatefulSet（[`kubernetes.io/docs/concepts/workloads/controllers/statefulset/`](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)）类似于部署，具有顺序的额外能力和 Pod 的唯一性。这意味着 Kubernetes 将确保 Pod 及其存储被保持在一起。StatefulSets 的另一个帮助方式是一致地命名 StatefulSet 中的 Pod。Pod 的命名方式是`<pod-name>-#`，其中`#`从第一个 Pod 开始为`0`，第二个 Pod 为`1`。

运行以下命令，您可以看到 MariaDB 附有可预测的编号，而 WordPress 部署附有随机编号：

```
kubectl get pods
```

这将生成*图 3.18*中显示的输出：

![当执行 kubectl get pods 命令时，您将看到 MariaDB Pod 的可预测名称和 WordPress Pod 的随机字母数字名称。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.18.jpg)

###### 图 3.18：显示 MariaDB Pod 的可预测编号，而 WordPress Pod 的随机名称

编号强调了部署 Pod 与 StatefulSet Pod 的短暂性质。

另一个区别是如何处理 pod 的删除。当删除部署的 pod 时，Kubernetes 会在任何可以的地方重新启动它，而当 StatefulSet 的 pod 被删除时，Kubernetes 只会在它曾经运行的节点上重新启动它。只有在节点从 Kubernetes 集群中移除时，它才会重新定位 pod。

通常，您会希望将存储附加到 StatefulSet。为了实现这一点，StatefulSet 需要一个持久卷。这个卷可以由许多机制支持（包括块，如 Azure Blob、EBS 和 iSCSI，以及网络文件系统，如 AFS、NFS 和 GlusterFS）。请参考 https://Kubernetes.io/docs/concepts/storage/volumes/#persistentvolumeclaim 获取更多信息。

StatefulSets 要求预先配置的卷或由**PersistentVolumeClaim**（**PVC**）处理的动态配置的卷。在我们的示例中，我们使用了 PVC。PVC 提供了对底层存储机制的抽象。让我们看看 MariaDB Helm Chart 通过运行以下命令为我们做了什么：

```
kubectl get statefulsets
```

这将向我们展示类似于*图 3.19*的东西：

![执行 kubectl get statefulsets 命令后，输出屏幕将显示一个处于 1/1 Ready 状态的 MariaDB Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.19.jpg)

###### 图 3.19：显示创建 MariaDB Pods 的 StatefulSet 的输出。

通过导出 StatefulSet 的 YAML 定义，让我们更深入地了解一下：

```
kubectl get statefulset -o yaml > mariadbss.yaml
code mariadbss.yaml
```

让我们看一下该 YAML 文件的最相关部分。代码已经被截断，只显示了最相关的部分：

```
1   apiVersion: v1
2   items:
3   - apiVersion: apps/v1
4     kind: StatefulSet
...
106           volumeMounts:
107           - mountPath: /bitnami/mariadb
108             name: data
...           
128     volumeClaimTemplates:
129     - metadata:
130         creationTimestamp: null
131         labels:
132           app: mariadb
133           component: master
134           heritage: Helm
135           release: handsonakswp
136         name: data
137       spec:
138         accessModes:
139         - ReadWriteOnce
140         resources:
141           requests:
142             storage: 8Gi
143         volumeMode: Filesystem
...
```

前面代码的大部分元素在部署中已经涵盖过了。在接下来的块中，我们将突出显示关键的不同之处，只看 PVC：

#### 注意

PVC 可以被任何 Pod 使用，而不仅仅是 StatefulSet Pods。

让我们详细讨论前面代码的不同元素：

+   第 4 行：此行指示了`StatefulSet`的声明。

+   第 106-108 行：挂载定义为“数据”的卷，并将其挂载在`/bitnami/mariadb`路径下。

+   第 128-143 行：声明 PVC。特别注意：

+   第 136 行：此行将其命名为“数据”，在第 108 行重复使用。

+   第 139 行：给出了访问模式`ReadWriteOnce`，这将创建块存储，在 Azure 上是一个磁盘。

+   第 142 行：定义磁盘的大小。

根据前面的信息，Kubernetes 动态请求并将 8Gi 卷绑定到此 Pod。在这种情况下，使用了由 Azure 磁盘支持的默认动态存储 provisioner。动态 provisioner 是在创建集群时由 Azure 设置的。要查看集群上可用的存储类，可以运行以下命令：

```
kubectl get storageclass
```

这将显示类似于*图 3.20*的输出：

![kubectl get storageclass 命令生成一个输出，您将看到两个存储类，即默认和托管高级。两者都是 provisioner 类型的 azure-disktype。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.20.jpg)

###### 图 3.20：显示集群中不同存储类的输出

通过运行以下命令，我们可以获取有关 PVC 的更多详细信息：

```
kubectl get pvc
```

生成的输出显示在*图 3.21*中：

![当您执行 kubectl get pvc 命令时，输出屏幕将显示每个 PVC 的名称、状态、卷、容量、访问模式、存储类和年龄。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.21.jpg)

###### 图 3.21：集群中不同的 PVCs

当我们在 StatefulSet 描述中请求存储（第 128-143 行）时，Kubernetes 执行了 Azure-disk 特定的操作，以获取 8 GiB 存储的 Azure 磁盘。如果您复制 PVC 的名称并将其粘贴到 Azure 搜索栏中，您应该会找到已创建的磁盘：

![当您将从上一个命令生成的 PVC 名称粘贴到栏中时，您将看到资源列中创建了一个磁盘。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.22.jpg)

###### 图 3.22：获取与 PVC 关联的磁盘

PVC 的概念抽象了云提供商的存储细节。这使得相同的 Helm 模板可以在 Azure、AWS 或 GCP 上工作。在 AWS 上，它将由**弹性块存储**（**EBS**）支持，在 GCP 上将由持久磁盘支持。

另外，请注意，可以在不使用 Helm 的情况下部署 PVC。

**检查 WordPress 部署**

在分析 PVC 之后，让我们再次检查 Helm 部署。我们可以使用以下命令检查部署的状态：

```
helm ls
```

这应该返回*图 3.23*中显示的输出：

![执行 helm ls 命令时，输出屏幕将显示部署的状态为已部署。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_3.23.jpg)

###### 图 3.23：Helm 显示我们的 WordPress 应用程序已部署

我们可以使用以下命令从 Helm 中获取更多信息：

```
helm status handsonakswp
```

这将返回*图 3.24*中显示的输出：

使用 helm status handsonakswp 命令，您可以获取有关应用程序的更多详细信息。

###### 图 3.24：获取有关应用程序的更多详细信息

这表明我们的图表已成功部署。它还显示了如何连接到我们的网站的更多信息。我们现在不会使用这些步骤；我们将在*第五章*“处理 AKS 中的常见故障”中重新讨论这些步骤，在该部分中我们将介绍如何修复存储挂载问题。现在，我们将查看 Helm 为我们创建的所有内容：

```
kubectl get all
```

这将生成类似于*图 3.25*的输出：

图 3.25：执行 kubectl get all 命令会生成一个输出屏幕，显示 Helm 创建的对象，如 Pod、Service、Deployment、ReplicaSet 和 StatefulSet，以及每个对象的信息。您还将获得 WordPress 服务的外部 IP。

###### 图 3.25：显示 Helm 创建的所有对象的输出

如果您还没有外部 IP，请等待几分钟，然后重试该命令。

然后，您可以继续连接到您的外部 IP 并访问您的 WordPress 网站。以下截图是生成的输出：

当您将外部 IP 连接到 WordPress 网站时，您将看到一个显示“Hello World！”并鼓励您开始撰写博客文章的屏幕。

###### 图 3.26：连接到外部 IP 时显示的 WordPress 网站

为了确保在接下来的章节中不会遇到问题，让我们删除 WordPress 网站。可以通过以下方式完成：

```
helm delete handsonakswp
```

按设计，我们的 PVCs 不会被删除。这确保持久数据得到保留。由于我们没有任何持久数据，我们也可以安全地删除这些数据：

```
kubectl delete pvc --all
```

#### 注意

在执行`kubectl delete <object> --all`时要非常小心，因为它会删除命名空间中的所有对象。这在生产集群上是不推荐的。

在本节中，您使用 Helm 部署了一个完整的 WordPress 网站。您还了解了 Kubernetes 如何使用 PVC 处理持久存储。

## 总结

在本章中，我们部署了两个应用程序。我们首先部署了 guestbook 应用程序。在部署过程中，我们查看了 Pods、ReplicaSets 和 deployments 的详细信息。我们还使用 ConfigMaps 进行动态配置。最后，我们了解了服务如何用于将流量路由到部署的应用程序。

我们部署的第二个应用是 WordPress 应用程序。我们通过 Helm 软件包管理器部署了它。作为部署的一部分，我们使用了 PVC，并探讨了它们在系统中的使用方式。

在下一章中，我们将探讨应用程序和集群本身的扩展。我们将首先看一下应用程序的手动和自动扩展，然后再看一下集群本身的手动和自动扩展。最后，我们将解释在 Kubernetes 上更新应用程序的不同方式。


# 第四章：构建可扩展的应用程序

在运行应用程序时，扩展和升级应用程序的能力至关重要。**扩展**是处理应用程序的额外负载所必需的，而升级是保持应用程序最新并能够引入新功能所必需的。

按需扩展是使用基于云的应用程序的关键好处之一。它还有助于优化应用程序的资源。如果前端组件遇到重负载，您可以单独扩展前端，同时保持相同数量的后端实例。您可以根据工作负载和高峰需求小时增加或减少所需的**虚拟机**（**VM**）的数量/大小。本章将详细介绍两种扩展维度。

在本章中，我们将向您展示如何扩展我们在*第三章* *在 AKS 上部署应用程序*中介绍的示例留言簿应用程序。我们将首先使用手动命令扩展此应用程序，然后我们将使用**水平 Pod 自动缩放器（HPA）**对其进行自动缩放。我们的目标是让您熟悉`kubectl`，这是管理在**Azure Kubernetes** **Service**（**AKS**）上运行的应用程序的重要工具。在扩展应用程序本身之后，我们还将扩展集群。我们将首先手动扩展集群，然后使用集群自动缩放器自动扩展集群。此外，在本章中，您将简要介绍如何升级在 AKS 上运行的应用程序。

在本章中，我们将涵盖以下主题：

+   扩展您的应用程序

+   扩展您的集群

+   升级您的应用程序

我们将从讨论在 AKS 上扩展应用程序时涉及的不同维度开始本章。

#### 注意

在上一章中，我们在 Cloud Shell 中克隆了示例文件。如果您当时没有这样做，我们建议现在这样做：

`git clone` [`github.com/PacktPublishing/Hands-On-Kubernetes-on-Azure---Second-Edition/tree/SecondEdition`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Azure---Second-Edition/tree/SecondEdition)

对于本章，请导航到`Chapter04`目录：

`cd Chapter04`

## 扩展您的应用程序

在 AKS 上运行的应用程序有两个扩展维度。第一个扩展维度是部署的 Pod 的数量，而 AKS 中的第二个扩展维度是集群中节点的数量。

通过向部署添加额外的 Pod，也称为扩展，您为部署的应用程序增加了额外的计算能力。您可以手动扩展应用程序，也可以让 Kubernetes 通过 HPA 自动处理这一点。HPA 将监视诸如 CPU 之类的指标，以确定是否需要向部署添加 Pod。

AKS 中的第二个扩展维度是集群中的节点数。集群中的节点数定义了集群上所有应用程序可用的 CPU 和内存量。您可以通过手动更改节点数来扩展集群，也可以使用集群自动缩放器自动扩展集群。集群自动缩放器将监视无法由于资源约束而无法调度的 Pod。如果无法调度 Pod，它将向集群添加节点，以确保您的应用程序可以运行。

本章将涵盖两个扩展维度。在本节中，您将学习如何扩展您的应用程序。首先，您将手动扩展您的应用程序，然后，您将自动扩展您的应用程序。

### 实施应用程序的扩展

为了演示手动扩展，让我们使用在上一章中使用的 guestbook 示例。按照以下步骤学习如何实施手动扩展：

1.  通过在 Azure 命令行中运行`kubectl create`命令来安装 guestbook：

```
kubectl create -f guestbook-all-in-one.yaml
```

1.  输入上述命令后，您应该在命令行输出中看到类似的内容，如*图 4.1*所示：![当您执行该命令时，您的命令行输出将列出已创建的服务和部署。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.1.jpg)

###### 图 4.1：启动 guestbook 应用程序

1.  目前，没有任何服务是公开可访问的。我们可以通过运行以下命令来验证这一点：

```
kubectl get svc 
```

1.  *图 4.2*显示没有任何服务具有外部 IP：![输出屏幕将显示 External-IP 列为<none>。这表示没有任何服务具有公共 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.2.jpg)

###### 图 4.2：显示没有任何服务具有公共 IP 的输出

1.  为了测试我们的应用程序，我们将公开它。为此，我们将介绍一个新的命令，允许您在 Kubernetes 中编辑服务，而无需更改文件系统上的文件。要开始编辑，请执行以下命令：

```
kubectl edit service frontend
```

1.  这将打开一个`vi`环境。导航到现在显示为`type:` `ClusterIP`（第 27 行），并将其更改为`type: LoadBalancer`，如*图 4.3*所示。要进行更改，请按*I*按钮，输入更改，按*Esc*按钮，输入`:wq!`，然后按*Enter*保存更改：![输出显示第 27 行被 Type: LoadBalancer 替换。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.3.jpg)

###### 图 4.3：将此行更改为 type: LoadBalancer

1.  保存更改后，您可以观察服务对象，直到公共 IP 可用。要做到这一点，请输入以下内容：

```
kubectl get svc -w
```

1.  更新 IP 地址可能需要几分钟时间。一旦看到正确的公共 IP，您可以通过按*Ctrl* + *C*（Mac 上为*command + C*）退出`watch`命令：![使用 kubectl get svc -w 命令，前端服务的外部 IP 将从<pending>更改为实际的外部 IP 地址。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.4.jpg)

###### 图 4.4：显示前端服务获得公共 IP

1.  在浏览器导航栏中输入前面命令获取的 IP 地址，如下所示：`http://<EXTERNAL-IP>/`。其结果如*图 4.5*所示：![在浏览器导航栏中输入前面命令获取的外部 IP。显示一个带有粗体字 Guestbook 的白屏。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.5.jpg)

###### 图 4.5：浏览访客留言应用程序

熟悉的访客留言示例应该是可见的。这表明您已成功地公开访问了访客留言。

现在您已经部署了访客留言应用程序，可以开始扩展应用程序的不同组件。

### 扩展访客留言前端组件

Kubernetes 使我们能够动态地扩展应用程序的每个组件。在本节中，我们将向您展示如何扩展访客留言应用程序的前端。这将导致 Kubernetes 向部署添加额外的 Pods：

```
kubectl scale deployment/frontend --replicas=6
```

您可以设置要使用的副本数，Kubernetes 会处理其余的工作。您甚至可以将其缩减为零（用于重新加载配置的技巧之一，当应用程序不支持动态重新加载配置时）。要验证整体扩展是否正确工作，您可以使用以下命令：

```
kubectl get pods
```

这应该给您一个如*图 4.6*所示的输出：

执行 kubectl get pods 命令后，您将看到前端现在运行了六个 Pods。

###### 图 4.6：扩展后访客留言应用程序中运行的不同 Pods

如您所见，前端服务扩展到了六个 Pod。Kubernetes 还将这些 Pod 分布在集群中的多个节点上。您可以使用以下命令查看此服务运行在哪些节点上：

```
kubectl get pods -o wide
```

这将生成以下输出：

![执行 kubectl get pods -o wide 命令会显示 Pod 所在的节点。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.7.jpg)

###### 图 4.7：显示 Pod 运行在哪些节点上。

在本节中，您已经看到了使用 Kubernetes 扩展 Pod 有多么容易。这种能力为您提供了一个非常强大的工具，不仅可以动态调整应用程序组件，还可以通过同时运行多个组件实例来提供具有故障转移能力的弹性应用程序。然而，您并不总是希望手动扩展您的应用程序。在下一节中，您将学习如何自动扩展您的应用程序。

### 使用 HPA

在您工作在集群上时，手动扩展是有用的。然而，在大多数情况下，您希望应用程序发生某种自动缩放。在 Kubernetes 中，您可以使用名为**水平 Pod 自动缩放器**（**HPA**）的对象来配置部署的自动缩放。

HPA 定期监视 Kubernetes 指标，并根据您定义的规则自动缩放您的部署。例如，您可以配置 HPA 在应用程序的 CPU 利用率超过 50%时向部署添加额外的 Pod。

在本节中，您将配置 HPA 自动扩展应用程序的前端部分：

1.  要开始配置，让我们首先手动将我们的部署缩减到 1 个实例：

```
kubectl scale deployment/frontend --replicas=1
```

1.  接下来，我们将创建一个 HPA。通过输入`code hpa.yaml`在 Cloud Shell 中打开代码编辑器，并输入以下代码：

```
1  apiVersion: autoscaling/v2beta1
2  kind: HorizontalPodAutoscaler
3  metadata:
4    name: frontend-scaler
5  spec:
6    scaleTargetRef:
7      apiVersion: extensions/v1beta1
8      kind: Deployment
9      name: frontend
10   minReplicas: 1
11   maxReplicas: 10
12   metrics:
13   - type: Resource
14     resource:
15       name: cpu
16       targetAverageUtilization: 25
```

让我们来看看这个文件中配置了什么：

+   **第 2 行**：在这里，我们定义了需要`HorizontalPodAutoscaler`。

+   **第 6-9 行**：这些行定义了我们要自动缩放的部署。

+   **第 10-11 行**：在这里，我们配置了部署中的最小和最大 Pod 数。

+   **第 12-16 行**：在这里，我们定义了 Kubernetes 将要监视的指标，以便进行扩展。

1.  保存此文件，并使用以下命令创建 HPA：

```
kubectl create -f hpa.yaml
```

这将创建我们的自动缩放器。您可以使用以下命令查看您的自动缩放器：

```
kubectl get hpa
```

这将最初输出如*图 4.8*所示的内容：

![执行 kubectl get hpa 显示已创建的水平 Pod 自动缩放器。目标显示为<unknown>，表示 HPA 尚未完全准备好。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.8.jpg)

###### 图 4.8：未知的目标显示 HPA 尚未准备好

HPA 需要几秒钟来读取指标。等待 HPA 返回的结果看起来类似于*图 4.9*中显示的输出：

![执行 kubectl get hpa --watch 显示目标值从<unknown>更改为此截图中的实际值 10%。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.9.jpg)

###### 图 4.9：一旦目标显示百分比，HPA 就准备好了

1.  现在，我们将继续做两件事：首先，我们将观察我们的 Pods，看看是否创建了新的 Pods。然后，我们将创建一个新的 shell，并为我们的系统创建一些负载。让我们从第一个任务开始——观察我们的 Pods：

```
kubectl get pods -w
```

这将持续监视创建或终止的 Pod。

现在让我们在一个新的 shell 中创建一些负载。在 Cloud Shell 中，点击按钮打开一个新的 shell：

![单击工具栏上带有加号标志的图标。此按钮将打开一个新的 Cloud Shell。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.10.jpg)

###### 图 4.10：使用此按钮打开一个新的 Cloud Shell

这将在浏览器中打开一个新的选项卡，其中包含 Cloud Shell 中的新会话。我们将从这个选项卡为我们的应用程序生成一些负载。

1.  接下来，我们将使用一个名为`hey`的程序来生成这个负载。`hey`是一个发送负载到 Web 应用程序的小程序。我们可以使用以下命令安装和运行`hey`：

```
export GOPATH=~/go
export PATH=$GOPATH/bin:$PATH
go get -u github.com/rakyll/hey
hey -z 20m http://<external-ip>
```

`hey`程序现在将尝试创建多达 2000 万个连接到我们的前端。这将在我们的系统上生成 CPU 负载，这将触发 HPA 开始扩展我们的部署。这将需要几分钟才能触发扩展操作，但在某个时刻，您应该看到创建多个 Pod 来处理额外的负载，如*图 4.11*所示：

![执行 kubectl get pods -w 将显示正在创建的前端新 Pod。您将看到新的 Pod 从 Pending 状态更改为 ContainerCreating 状态再到 Running 状态。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.11.jpg)

###### 图 4.11：HPA 启动新的 Pod

在这一点上，您可以继续通过按*Ctrl* + *C*（Mac 上的*command* + *C*）来终止`hey`程序。

1.  让我们通过运行以下命令来更仔细地查看我们的 HPA 所做的事情：

```
kubectl describe hpa
```

我们可以在“描述”操作中看到一些有趣的点，如*图 4.12*所示：

![执行 kubectl describe hpa 命令将生成 HPA 的详细视图。您将看到资源负载，一个显示 TooManyReplicas 的消息，HPA 将从 1 扩展到 4，然后到 8，最后到 10。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.12.jpg)

###### 图 4.12：HPA 的详细视图

*图 4.12*中的注释解释如下：

**1**：这向您显示当前的 CPU 利用率（132%）与期望值（25%）的对比。当前的 CPU 利用率在您的情况下可能会有所不同。

**2**：这向您显示当前期望的副本数高于我们配置的实际最大值。这确保了单个部署不会消耗集群中的所有资源。

**3**：这向您显示了 HPA 所采取的扩展操作。它首先将部署扩展到 4 个，然后扩展到 8 个，然后扩展到 10 个 Pod。

1.  如果您等待几分钟，HPA 应该开始缩减。您可以使用以下命令跟踪此缩减操作：

```
kubectl get hpa -w
```

这将跟踪 HPA 并向您显示部署的逐渐缩减，如*图 4.13*所示：

![当您执行 kubectl get hpa -w 命令时，您将看到副本数量逐渐减少。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.13.jpg)

###### 图 4.13：观察 HPA 的缩减

1.  在我们进入下一节之前，让我们清理一下在本节中创建的资源：

```
kubectl delete -f hpa.yaml
kubectl delete -f guestbook-all-in-one.yaml
```

在本节中，我们首先手动，然后自动扩展了我们的应用程序。但是，集群资源是静态的；我们在一个两节点的集群上运行了这个。在许多情况下，您可能也会在集群本身耗尽资源。在下一节中，我们将处理这个问题，并解释如何自己扩展您的 AKS 集群。

## 扩展您的集群

在上一节中，我们处理了在集群顶部运行的应用程序的扩展。在本节中，我们将解释如何扩展您正在运行的实际集群。我们将首先讨论如何手动扩展您的集群。我们将从将我们的集群缩减到一个节点开始。然后，我们将配置集群自动缩放器。集群自动缩放器将监视我们的集群，并在无法在我们的集群上安排的 Pod 时进行扩展。

### 手动扩展您的集群

您可以通过为集群设置静态节点数来手动扩展您的 AKS 集群。您可以通过 Azure 门户或命令行来扩展您的集群。

在本节中，我们将向您展示如何通过将集群缩减到一个节点来手动扩展您的集群。这将导致 Azure 从您的集群中移除一个节点。首先，即将被移除的节点上的工作负载将被重新调度到其他节点上。一旦工作负载安全地重新调度，节点将从您的集群中移除，然后 VM 将从 Azure 中删除。

要扩展您的集群，请按照以下步骤操作：

1.  打开 Azure 门户并转到您的集群。一旦到达那里，转到**节点池**并点击**节点计数**下面的数字，如*图 4.14*所示：![在 Azure 门户上打开您的集群后，转到左侧屏幕上的导航窗格中的节点池选项卡。点击该选项卡。您将看到节点的详细信息。点击节点计数选项卡上的数字 2 以更改节点数。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.14.jpg)

###### 图 4.14：手动扩展集群

1.  这将打开一个弹出窗口，其中将提供扩展集群的选项。在我们的示例中，我们将将集群缩减到一个节点，如*图 4.15*所示：![当您点击节点计数选项卡时，将弹出一个窗口，让您选择扩展您的集群。将其缩减到一个节点。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.15.jpg)

###### 图 4.15：确认新集群大小的弹出窗口

1.  点击屏幕底部的**应用**按钮以保存这些设置。这将导致 Azure 从您的集群中移除一个节点。这个过程大约需要 5 分钟才能完成。您可以通过点击 Azure 门户顶部的通知图标来跟踪进度，如下所示：![节点缩减的过程需要一些时间。要查看进度，请点击工具栏中的铃铛图标以打开通知。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.16.jpg)

###### 图 4.16：可以通过 Azure 门户中的通知来跟踪集群的扩展

一旦这个缩减操作完成，我们将在这个小集群上重新启动我们的 guestbook 应用程序：

```
kubectl create -f guestbook-all-in-one.yaml
```

在下一节中，我们将扩展 guestbook，以便它不再在我们的小集群上运行。然后，我们将配置集群自动缩放器来扩展我们的集群。

### 使用集群自动缩放器扩展您的集群

在本节中，我们将探讨集群自动缩放器。集群自动缩放器将监视集群中的部署，并根据您的应用程序需求来扩展您的集群。集群自动缩放器会监视集群中由于资源不足而无法被调度的 Pod 的数量。我们将首先强制我们的部署有无法被调度的 Pod，然后我们将配置集群自动缩放器自动扩展我们的集群。

为了强制我们的集群资源不足，我们将手动扩展`redis-slave`部署。要做到这一点，请使用以下命令：

```
kubectl scale deployment redis-slave --replicas 5
```

您可以通过查看我们集群中的 Pod 来验证此命令是否成功：

```
kubectl get pods
```

这应该显示类似于*图 4.17*中生成的输出：

![执行 kubectl get pods 将显示四个处于挂起状态的 Pod。这意味着它们无法被调度到节点上。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.17.jpg)

###### 图 4.17：五个 Pod 中有四个处于挂起状态，意味着它们无法被调度

如您所见，我们现在有四个处于“挂起”状态的 Pod。在 Kubernetes 中，“挂起”状态意味着该 Pod 无法被调度到节点上。在我们的情况下，这是由于集群资源不足造成的。

我们现在将配置集群自动缩放器自动扩展我们的集群。与上一节中的手动扩展一样，您可以通过两种方式配置集群自动缩放器。您可以通过 Azure 门户配置它，类似于我们进行手动扩展的方式，或者您可以使用**命令行界面（CLI）**进行配置。在本例中，我们将使用 CLI 来启用集群自动缩放器。以下命令将为我们的集群配置集群自动缩放器：

```
az aks nodepool update --enable-cluster-autoscaler \
  -g rg-handsonaks --cluster-name handsonaks \
  --name agentpool --min-count 1 --max-count 3
```

此命令在我们集群中的节点池上配置了集群自动缩放器。它将其配置为最少一个节点和最多三个节点。这将花费几分钟来配置。

配置了集群自动缩放器后，您可以使用以下命令来观察集群中节点的数量：

```
kubectl get nodes -w
```

新节点出现并在集群中变为`Ready`大约需要 5 分钟。一旦新节点处于`Ready`状态，您可以通过按下*Ctrl* + *C*（Mac 上的*command* + *C*）来停止观察节点。您应该看到类似于*图 4.18*中的输出：

![kubectl get nodes -w 命令显示新节点被添加到集群，并且状态从 NotReady 变为 Ready。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.18.jpg)

###### 图 4.18：新节点加入集群

新节点应该确保我们的集群有足够的资源来调度扩展的`redis-slave`部署。要验证这一点，请运行以下命令来检查 Pod 的状态：

```
kubectl get pods
```

这应该显示所有处于`Running`状态的 Pod，如下所示：

![执行 kubectl get pods 命令显示所有 Pod 的状态为 Running。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.19.jpg)

###### 图 4.19：所有 Pod 现在都处于 Running 状态

我们现在将清理我们创建的资源，禁用集群自动缩放器，并确保我们的集群在接下来的示例中有两个节点。要做到这一点，请使用以下命令：

```
kubectl delete -f guestbook-all-in-one.yaml
az aks nodepool update --disable-cluster-autoscaler \
  -g rg-handsonaks --cluster-name handsonaks --name agentpool
az aks nodepool scale --node-count 2 -g rg-handsonaks \
  --cluster-name handsonaks --name agentpool
```

#### 注意

上一个示例中的最后一个命令将在集群已经有两个节点的情况下显示错误。您可以安全地忽略此错误。

在本节中，我们首先手动缩减了我们的集群，然后我们使用了集群自动缩放器来扩展我们的集群。我们首先使用 Azure 门户手动扩展了集群，然后我们还使用了 Azure CLI 来配置集群自动缩放器。在下一节中，我们将探讨如何升级在 AKS 上运行的应用程序。

## 升级您的应用程序

在 Kubernetes 中使用部署使升级应用程序成为一个简单的操作。与任何升级一样，如果出现问题，您应该有良好的回退。您将遇到的大多数问题将发生在升级过程中。云原生应用程序应该使处理这些问题相对容易，如果您有一个非常强大的开发团队，他们拥抱 DevOps 原则是可能的。

DevOps 报告（[`services.google.com/fh/files/misc/state-of-devops-2019.pdf`](https://services.google.com/fh/files/misc/state-of-devops-2019.pdf)）已经多年报告说，具有高软件部署频率的公司在其应用程序中具有更高的可用性和稳定性。这可能看起来违反直觉，因为进行软件部署会增加问题的风险。然而，通过更频繁地部署并使用自动化的 DevOps 实践进行部署，您可以限制软件部署的影响。

在 Kubernetes 集群中，我们可以进行多种方式的更新。在本节中，我们将探讨以下更新 Kubernetes 资源的方式：

+   通过更改 YAML 文件进行升级

+   使用`kubectl edit`进行升级

+   使用`kubectl patch`进行升级

+   使用 Helm 进行升级

我们将在下一节中描述的方法非常适用于无状态应用程序。如果您在任何地方存储了状态，请确保在尝试任何操作之前备份该状态。

让我们通过进行第一种类型的升级来开始本节：更改 YAML 文件。

### 通过更改 YAML 文件进行升级

为了升级 Kubernetes 服务或部署，我们可以更新实际的 YAML 定义文件，并将其应用到当前部署的应用程序中。通常，我们使用`kubectl create`来创建资源。同样，我们可以使用`kubectl apply`来对资源进行更改。

部署检测更改（如果有）并将`Running`状态与期望状态匹配。让我们看看这是如何完成的：

1.  我们从我们的留言簿应用程序开始，以演示这个例子：

```
kubectl create -f guestbook-all-in-one.yaml
```

1.  几分钟后，所有的 Pod 应该都在运行。让我们通过将服务从`ClusterIP`更改为`LoadBalancer`来执行我们的第一个升级，就像我们在本章前面所做的那样。然而，现在我们将编辑我们的 YAML 文件，而不是使用`kubectl edit`。使用以下命令编辑 YAML 文件：

```
code guestbook-all-in-one.yaml
```

取消注释此文件中的第 108 行，将类型设置为`LoadBalancer`并保存文件。如*图 4.20*所示：

![屏幕显示了编辑后的 YAML 文件。现在在第 108 行显示了类型为 LoadBalancer。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.20.jpg)

###### 图 4.20：更改 guestbook-all-in-one YAML 文件中的这一行

1.  按照以下代码进行更改：

```
kubectl apply -f guestbook-all-in-one.yaml
```

1.  您现在可以使用以下命令获取服务的公共 IP：

```
kubectl get svc
```

等几分钟，您应该会看到 IP，就像*图 4.21*中显示的那样：

![当您执行 kubectl get svc 命令时，您会看到只有前端服务有外部 IP。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.21.jpg)

###### 图 4.21：显示公共 IP 的输出

1.  现在我们将进行另一个更改。我们将把第 133 行的前端图像从`image: gcr.io/google-samples/gb-frontend:v4`降级为以下内容：

```
image: gcr.io/google-samples/gb-frontend:v3
```

通过使用这个熟悉的命令在编辑器中打开留言簿应用程序，可以进行此更改：

```
code guestbook-all-in-one.yaml
```

1.  运行以下命令执行更新并观察 Pod 更改：

```
kubectl apply -f guestbook-all-in-one.yaml && kubectl get pods -w
```

1.  这将生成以下输出：![执行 kubectl apply -f guestbook-all-in-one.yaml && kubectl get pods -w 命令会生成一个显示 Pod 更改的输出。您将看到从新的 ReplicaSet 创建的 Pod。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.22.jpg)

###### 图 4.22：从新的 ReplicaSet 创建的 Pod

在这里你可以看到旧版本的 Pod（基于旧的 ReplicaSet）被终止，而新版本被创建。

1.  运行`kubectl get events | grep ReplicaSet`将显示部署使用的滚动更新策略，以更新前端图像如下：![输出将突出显示所有与 ReplicaSet 相关的事件。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.23.jpg)

###### 图 4.23：监视 Kubernetes 事件并筛选只看到与 ReplicaSet 相关的事件

#### 注意

在上面的示例中，我们使用了管道—由`|`符号表示—和`grep`命令。在 Linux 中，管道用于将一个命令的输出发送到另一个命令的输入。在我们的情况下，我们将`kubectl get events`的输出发送到`grep`命令。`grep`是 Linux 中用于过滤文本的命令。在我们的情况下，我们使用`grep`命令只显示包含单词 ReplicaSet 的行。

您可以在这里看到新的 ReplicaSet 被扩展，而旧的 ReplicaSet 被缩减。您还将看到前端有两个 ReplicaSets，新的 ReplicaSet 逐个替换另一个 Pod：

```
kubectl get replicaset
```

这将显示如*图 4.24*所示的输出：

使用 kubectl get replicaset 命令，您可以看到两个不同的 ReplicaSets。

###### 图 4.24：两个不同的 ReplicaSets

1.  Kubernetes 还将保留您的部署历史。您可以使用此命令查看部署历史：

```
kubectl rollout history deployment frontend
```

这将生成如*图 4.25*所示的输出：

图 4.25：输出屏幕显示了应用程序的历史。它显示了修订次数、更改和更改的原因。

###### 图 4.25：应用程序的部署历史

1.  由于 Kubernetes 保留了我们部署的历史记录，这也使得回滚成为可能。让我们对部署进行回滚：

```
kubectl rollout undo deployment frontend
```

这将触发回滚。这意味着新的 ReplicaSet 将被缩减为零个实例，而旧的 ReplicaSet 将再次扩展为三个实例。我们可以使用以下命令来验证这一点：

```
kubectl get replicaset
```

产生的输出如*图 4.26*所示：

图 4.26：执行 kubectl get rs 命令显示两个前端 ReplicaSets。一个没有 pod，另一个有 3 个 pod。

###### 图 4.26：旧的 ReplicaSet 现在有三个 Pod，而新的 ReplicaSet 被缩减为零

这向我们展示了，正如预期的那样，旧的 ReplicaSet 被缩减为三个实例，新的 ReplicaSet 被缩减为零个实例。

1.  最后，让我们再次通过运行`kubectl delete`命令进行清理：

```
kubectl delete -f guestbook-all-in-one.yaml
```

恭喜！您已完成了应用程序的升级和回滚到先前版本。

在此示例中，您已使用`kubectl apply`对应用程序进行更改。您也可以类似地使用`kubectl edit`进行更改，这将在下一节中探讨。

### 使用 kubectl edit 升级应用程序

我们可以通过使用`kubectl edit`对运行在 Kubernetes 之上的应用程序进行更改。您在本章中先前使用过这个。运行`kubectl edit`时，`vi`编辑器将为您打开，这将允许您直接对 Kubernetes 中的对象进行更改。

让我们重新部署我们的 guestbook 应用程序，而不使用公共负载均衡器，并使用`kubectl`创建负载均衡器：

1.  您将开始部署 guestbook 应用程序：

```
kubectl create -f guestbook-all-in-one.yaml
```

1.  要开始编辑，请执行以下命令：

```
kubectl edit service frontend
```

1.  这将打开一个`vi`环境。导航到现在显示为`type:` `ClusterIP`（第 27 行），并将其更改为`type: LoadBalancer`，如*图 4.27*所示。要进行更改，请按*I*按钮，输入更改内容，按*Esc*按钮，输入`:wq!`，然后按*Enter*保存更改：![输出显示第 27 行被 Type: LoadBalancer 替换。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.3.jpg)

###### 图 4.27：将此行更改为类型：LoadBalancer

1.  保存更改后，您可以观察服务对象，直到公共 IP 可用。要做到这一点，请输入以下内容：

```
kubectl get svc -w
```

1.  它将花费几分钟时间来显示更新后的 IP。一旦看到正确的公共 IP，您可以通过按*Ctrl* + *C*（Mac 上为*command* + *C*）退出`watch`命令

这是使用`kubectl edit`对 Kubernetes 对象进行更改的示例。此命令将打开一个文本编辑器，以交互方式进行更改。这意味着您需要与文本编辑器交互以进行更改。这在自动化环境中不起作用。要进行自动化更改，您可以使用`kubectl patch`命令。

### 使用 kubectl patch 升级应用程序

在先前的示例中，您使用文本编辑器对 Kubernetes 进行更改。在这个示例中，您将使用`kubectl patch`命令对 Kubernetes 上的资源进行更改。`patch`命令在自动化系统中特别有用，例如在脚本中或在持续集成/持续部署系统中。

有两种主要方式可以使用`kubectl patch`，一种是创建一个包含更改的文件（称为补丁文件），另一种是提供内联更改。我们将探讨这两种方法。首先，在这个例子中，我们将使用补丁文件将前端的图像从`v4`更改为`v3`：

1.  通过创建一个名为`frontend-image-patch.yaml`的文件来开始这个例子：

```
code frontend-image-patch.yaml
```

1.  在该文件中使用以下文本作为补丁：

```
spec:
  template:
    spec:
      containers:
      - name: php-redis
        image: gcr.io/google-samples/gb-frontend:v3
```

此补丁文件使用与典型 YAML 文件相同的 YAML 布局。补丁文件的主要特点是它只需要包含更改，而不必能够部署整个资源。

1.  要应用补丁，请使用以下命令：

```
kubectl patch deployment frontend --patch "$(cat frontend-image-patch.yaml)"
```

此命令执行两件事：首先，它读取`frontend-image-patch.yaml`文件，然后将其传递给`patch`命令以执行更改。

1.  您可以通过描述前端部署并查找`Image`部分来验证更改：

```
kubectl describe deployment frontend
```

这将显示如下输出：

![执行 Patch 命令后，您可以使用 kubectl describe deployment frontend 命令来验证更改。您应该看到新图像的路径。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.28.jpg)

###### 图 4.28：补丁后，我们正在运行旧图像

这是使用`patch`命令使用补丁文件的一个例子。您还可以在命令行上直接应用补丁，而不创建 YAML 文件。在这种情况下，您将以 JSON 而不是 YAML 描述更改。

让我们通过一个例子来说明，我们将图像更改恢复到`v4`：

1.  运行以下命令将图像补丁回到`v4`：

```
kubectl patch deployment frontend --patch='{"spec":{"template":{"spec":{"containers":[{"name":"php-redis","image":"gcr.io/google-samples/gb-frontend:v4"}]}}}}'
```

1.  您可以通过描述部署并查找`Image`部分来验证此更改：

```
kubectl describe deployment frontend
```

这将显示如图 4.29 所示的输出：

![应用另一个补丁命令后，您将看到图像的新版本。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.29.jpg)

###### 图 4.29：应用另一个补丁后，我们再次运行新版本

在我们继续下一个例子之前，让我们从集群中删除 guestbook 应用程序：

```
kubectl delete -f guestbook-all-in-one.yaml
```

到目前为止，您已经探索了升级 Kubernetes 应用程序的三种方式。首先，您对实际的 YAML 文件进行了更改，并使用`kubectl apply`应用了这些更改。之后，您使用了`kubectl edit`和`kubectl patch`进行了更多更改。在本章的最后一节中，我们将使用 Helm 来升级我们的应用程序。

### 使用 Helm 升级应用程序

本节将解释如何使用 Helm 操作符执行升级：

1.  运行以下命令：

```
helm install wp stable/wordpress
```

我们将强制更新`WordPress`容器的图像。让我们首先检查当前图像的版本：

```
kubectl describe statefulset wp-mariadb | grep Image
```

在我们的情况下，图像版本为`10.3.21-debian-10-r0`如下：

![输出显示 10.3.21-debian-10-r0 作为 StatefulSet 的当前版本。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.30.jpg)

###### 图 4.30：获取 StatefulSet 的当前图像

让我们看一下来自[`hub.docker.com/r/bitnami/mariadb/tags`](https://hub.docker.com/r/bitnami/mariadb/tags)的标签，并选择另一个标签。在我们的情况下，我们将选择`10.3.22-debian-10-r9`标签来更新我们的 StatefulSet。

然而，为了更新 MariaDB 容器图像，我们需要获取服务器的 root 密码和数据库的密码。我们可以通过以下方式获取这些密码：

```
kubectl get secret wp-mariadb -o yaml
```

这将生成一个如*图 4.31*所示的输出：

![输出将显示 MariaDB 的密码和 root 密码的 base64 编码版本，我们需要更新容器图像。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.31.jpg)

###### 图 4.31：MariaDB 使用的加密密码

为了获取解码后的密码，请使用以下命令：

```
echo "<password>" | base64 -d
```

这将向我们显示解码后的 root 密码和解码后的数据库密码。

1.  我们可以使用 Helm 更新图像标签，然后使用以下命令观察 Pod 的更改：

```
helm upgrade wp stable/wordpress --set mariadb.image.tag=10.3.21-debian-10-r1,mariadb.rootUser.password=<decoded password>,mariadb.db.password=<decoded db password> && kubectl get pods -w
```

这将更新我们的 MariaDB 的图像并启动一个新的 Pod。在新的 Pod 上运行`describe`并使用`grep`查找`Image`将向我们显示新的图像版本：

```
kubectl describe pod wp-mariadb-0 | grep Image
```

这将生成一个如*图 4.32*所示的输出：

![执行 kubectl describe pod wp-mariadb-0 | grep Image 命令将显示图像的新版本。](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/hsn-k8s-az-2e/img/Figure_4.32.jpg)

###### 图 4.32：显示新图像

1.  最后，通过运行以下命令进行清理：

```
helm delete wp
kubectl delete pvc --all
kubectl delete pv --all
```

因此，我们已经使用 Helm 升级了我们的应用程序。正如您在本例中所看到的，使用 Helm 进行升级可以通过使用`--set`运算符来完成。这使得使用 Helm 进行升级和多次部署变得非常高效。

## 总结

这是一个充满大量信息的章节。我们的目标是向您展示如何使用 Kubernetes 扩展部署。我们通过向您展示如何创建应用程序的多个实例来实现这一点。

我们开始这一章是通过研究如何定义负载均衡器的使用，并利用 Kubernetes 中的部署规模功能来实现可伸缩性。通过这种类型的可伸缩性，我们还可以通过使用负载均衡器和多个无状态应用程序实例来实现故障转移。我们还研究了如何使用 HPA 根据负载自动扩展我们的部署。

之后，我们还研究了如何扩展集群本身。首先，我们手动扩展了我们的集群，然后我们使用了集群自动缩放器根据应用程序需求来扩展我们的集群。

我们通过研究不同的方法来升级已部署的应用程序来完成了这一章。首先，我们探讨了手动更新 YAML 文件。然后，我们深入研究了两个额外的`kubectl`命令（`edit`和`patch`），可以用来进行更改。最后，我们展示了如何使用 Helm 来执行这些升级。

在下一章中，我们将看到在部署应用程序到 AKS 时可能遇到的常见故障以及如何修复它们。
