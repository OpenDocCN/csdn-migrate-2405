# Kubernetes 无服务器架构（一）

> 原文：[`zh.annas-archive.org/md5/36BD40FEB49D3928DE19F4A0B653CB1B`](https://zh.annas-archive.org/md5/36BD40FEB49D3928DE19F4A0B653CB1B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本书的覆盖范围、开始所需的技术技能，以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于本书

Kubernetes 已经确立了自己作为容器管理、编排和部署的标准平台。通过学习 Kubernetes，您将能够通过实施**函数即服务（FaaS）**模型来设计自己的无服务器架构。

在对无服务器架构和各种 Kubernetes 概念进行加速、实践性概述之后，您将涵盖真实开发人员面临的各种真实开发挑战，并探索克服这些挑战的各种技术。您将学习如何创建可投入生产的 Kubernetes 集群，并在其上运行无服务器应用程序。您将了解 Kubernetes 平台和无服务器框架（如 Kubeless、Apache OpenWhisk 和 OpenFaaS）如何提供您在 Kubernetes 上开发无服务器应用程序所需的工具。您还将学习如何为即将到来的项目选择适当的框架。

通过本书，您将具备技能和信心，能够利用 Kubernetes 的强大和灵活性设计自己的无服务器应用程序。

### 关于作者

**Onur Yılmaz**是一家跨国企业软件公司的高级软件工程师。他是一名持有认证的 Kubernetes 管理员（CKA），并致力于 Kubernetes 和云管理系统。他是 Docker、Kubernetes 和云原生应用等尖端技术的热情支持者。他在工程领域拥有一个硕士学位和两个学士学位。

**Sathsara Sarathchandra**是一名 DevOps 工程师，具有在云端和本地构建和管理基于 Kubernetes 的生产部署的经验。他拥有 8 年以上的经验，曾在从小型初创公司到企业的多家公司工作。他是一名持有认证的 Kubernetes 管理员（CKA）和认证的 Kubernetes 应用开发者（CKAD）。他拥有工商管理硕士学位和计算机科学学士学位。

### 学习目标

通过本书，您将能够：

+   使用 Minikube 在本地部署 Kubernetes 集群

+   使用 AWS Lambda 和 Google Cloud Functions

+   在云中创建、构建和部署由无服务器函数生成的网页。

+   创建在虚拟 kubelet 硬件抽象上运行的 Kubernetes 集群

+   创建、测试、排除 OpenFass 函数

+   使用 Apache OpenWhisk 操作创建一个示例 Slackbot

### 受众

本书适用于具有关于 Kubernetes 的基本或中级知识并希望学习如何创建在 Kubernetes 上运行的无服务器应用程序的软件开发人员和 DevOps 工程师。那些希望设计和创建在云上或本地 Kubernetes 集群上运行的无服务器应用程序的人也会发现本书有用。

### 方法

本书提供了与无服务器开发人员在实际工作中与 Kubernetes 集群一起工作的相关项目示例。您将构建示例应用程序并解决编程挑战，这将使您能够应对大型、复杂的工程问题。每个组件都设计为吸引和激发您，以便您可以在实际环境中以最大的影响力保留和应用所学到的知识。通过完成本书，您将能够处理真实世界的无服务器 Kubernetes 应用程序开发。

### 硬件要求

为了获得最佳的学生体验，我们建议以下硬件配置：

+   处理器：Intel Core i5 或同等级别

+   内存：8 GB RAM（建议 16 GB）

+   硬盘：10 GB 可用空间

+   互联网连接

### 软件要求

我们还建议您提前安装以下软件：

+   Sublime Text（最新版本）、Atom IDE（最新版本）或其他类似的文本编辑应用程序

+   Git

### 额外要求

+   Azure 账户

+   Google 云账户

+   AWS 账户

+   Docker Hub 账户

+   Slack 账户

### 约定

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

“将`hello-from-lambda`作为函数名称，`Python 3.7`作为运行时。”

新术语和重要单词以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中：“打开 AWS 管理控制台，在**查找服务**搜索框中输入**Lambda**，然后单击**Lambda - Run Code without Thinking about Servers**。”

代码块设置如下：

```
import json
def lambda_handler(event, context):
    return {
        'statusCode': '200',
        'body': json.dumps({"message": "hello", "platform": "lambda"}),
        'headers': {
            'Content-Type': 'application/json',
        }
    }
```

### 安装和设置

在我们可以对数据进行出色处理之前，我们需要准备好最高效的环境。在这个简短的部分中，我们将看到如何做到这一点。以下是需要满足的先决条件：

+   Docker（17.10.0-ce 或更高版本）

+   像 Virtualbox、Parallels、VMWareFusion、Hyperkit 或 VMWare 这样的 Hypervisor。更多信息请参考此链接：[`kubernetes.io/docs/tasks/tools/install-minikube/#install-a-hypervisor`](https://kubernetes.io/docs/tasks/tools/install-minikube/#install-a-hypervisor)

### 其他资源

本书的代码包也托管在 GitHub 上，网址为[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes)。我们还有其他代码包来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。快去看看吧！


# 第一章： 无服务器介绍

## 学习目标

本章结束时，您将能够：

+   识别无服务器架构的好处

+   在无服务器平台上创建和调用简单函数

+   使用 Kubernetes 创建云原生无服务器函数并将其打包为容器

+   创建 Twitter Bot 后端应用程序并将其打包到 Docker 容器中

在本章中，我们将解释无服务器架构，然后创建我们的第一个无服务器函数并将其打包为容器。

## 无服务器介绍

当前，云技术正处于不断变革的状态，以创建可扩展、可靠和强大的环境。为了创建这样的环境，云技术的每一项改进都旨在提高最终用户体验和开发人员体验。最终用户要求快速、强大的应用程序，可以从世界各地访问。与此同时，开发人员要求更好的开发环境来设计、部署和维护他们的应用程序。在过去的十年中，云技术的旅程始于云计算，其中服务器在云数据中心中进行配置，并在服务器上部署应用程序。向云数据中心的过渡降低了成本，并消除了对数据中心的责任。然而，随着数十亿人访问互联网并要求更多服务，可扩展性已成为必需。为了扩展应用程序，开发人员创建了可以独立扩展的较小的微服务。微服务被打包成容器，作为软件架构的构建块，以改善开发人员和最终用户的体验。微服务通过提供更好的可维护性来增强开发人员体验，同时为最终用户提供高可扩展性。然而，微服务的灵活性和可扩展性无法满足巨大的用户需求。例如，今天，每天进行数百万笔银行交易，并向后端系统发出数百万笔业务请求。

最后，无服务器开始引起人们的关注，用于创建“未来可靠”和“即时可扩展”的应用程序。无服务器设计专注于创建比微服务更小的服务，并且它们被设计为更持久地存在于未来。这些“纳米服务”或函数帮助开发人员创建更灵活、更易于维护的应用程序。另一方面，无服务器设计是即时可扩展的，这意味着如果您采用无服务器设计，您的服务会随着用户请求自然地扩展或缩小。无服务器的这些特性使其成为行业中最新的大趋势，它现在正在塑造云技术的格局。在本节中，将介绍无服务器技术的概述，重点关注无服务器的演变、起源和用例。

在深入研究无服务器设计之前，让我们了解一下云技术的演变。在过去，部署应用程序的预期流程始于硬件的采购和部署，即服务器。随后，在服务器上安装操作系统，然后部署应用程序包。最后，执行应用程序包中的实际代码以实现业务需求。这四个步骤如*图 1.1*所示：

![图 1.1：传统软件开发](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_01.jpg)

###### 图 1.1：传统软件开发

组织开始将其数据中心运营外包给云提供商，以改善服务器的可伸缩性和利用率。例如，如果您正在开发一个在线购物应用程序，您首先需要购买一些服务器，等待它们的安装，并每天操作它们并处理由电力、网络和错误配置引起的潜在问题。很难预测服务器的使用水平，也不可行大规模投资于服务器来运行应用程序。因此，初创公司和大型企业开始将数据中心运营外包给云提供商。这清除了与硬件部署的第一步相关的问题，如*图 1.2*所示：

![图 1.2：云计算软件开发](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_02.jpg)

###### 图 1.2：云计算软件开发

随着云计算中虚拟化的开始，操作系统变得虚拟化，以便多个虚拟机（VMs）可以在同一台裸机上运行。这种转变消除了第二步，服务提供商按照*图 1.3*所示提供 VMs。在同一硬件上运行多个 VMs，服务器运行成本降低，操作灵活性增加。换句话说，软件开发人员的底层问题得到解决，因为硬件和操作系统现在都是别人的问题：

![图 1.3：虚拟化软件开发](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_03.jpg)

###### 图 1.3：虚拟化软件开发

VMs 使得在同一硬件上运行多个实例成为可能。然而，使用 VMs 需要为每个应用程序安装完整的操作系统。即使对于基本的前端应用程序，您也需要安装操作系统，这导致操作系统管理的开销，从而导致可扩展性受限。应用程序开发人员和现代应用程序的高级使用需要比创建和管理 VMs 更快速、更简单、更具隔离性的解决方案。容器化技术通过在同一操作系统上运行多个“容器化”应用程序来解决这个问题。通过这种抽象级别，与操作系统相关的问题也被解决，容器被作为应用程序包交付，如*图 1.4*所示。容器化技术实现了微服务架构，其中软件被设计为小型且可扩展的服务，彼此之间进行交互。

这种架构方法使得能够运行现代应用程序，如 Google Drive 中的协作电子表格，YouTube 上的体育赛事直播，Skype 上的视频会议等等：

![图 1.4：容器化软件开发](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_04.jpg)

###### 图 1.4：容器化软件开发

下一个架构现象，无服务器，消除了管理容器的负担，专注于运行实际的代码本身。无服务器架构的基本特征是临时可伸缩性。无服务器架构中的应用程序是临时可伸缩的，这意味着它们在需要时会自动扩展或缩减。它们也可以缩减到零，这意味着没有硬件、网络或运营成本。在无服务器应用程序中，所有低级别的问题都被外包和管理，重点是最后一步——**运行代码**——如图 1.5 所示。无服务器设计的重点是传统软件开发的最后一步。在接下来的部分中，我们将专注于无服务器的起源和宣言，以便更深入地介绍：

![图 1.5：使用无服务器进行软件开发](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_05.jpg)

###### 图 1.5：使用无服务器进行软件开发

### 无服务器起源和宣言

**无服务器**是一个令人困惑的术语，因为在会议、书籍和博客中有各种定义。尽管从理论上讲它意味着没有任何服务器，但实际上它意味着将服务器的责任留给第三方组织。换句话说，它并不意味着摆脱服务器，而是服务器操作。当你运行无服务器时，其他人会处理服务器操作的采购、运输和安装。这降低了你的成本，因为你不需要运营服务器甚至数据中心；此外，它让你专注于实现核心业务功能的应用逻辑。

无服务器的最初用途出现在 2010 年左右与持续集成相关的文章中。当它首次讨论时，无服务器被认为是用于在云服务提供商的服务器上构建和打包应用程序。随着 2014 年**亚马逊网络服务**（**AWS**）推出**Lambda**，其受欢迎程度急剧增加。此外，2015 年，AWS 推出了**API Gateway**用于管理和触发 Lambda 函数，作为多个函数的单一入口点。因此，无服务器函数在 2014 年开始受到关注，并且在 2015 年可以使用**AWS API Gateway**创建无服务器架构应用程序。

然而，对无服务器的最明确和完整的解释是在 2016 年在 AWS 开发者大会上提出的，称为*无服务器计算宣言*。它包括八条严格的规则，定义了无服务器架构背后的核心思想：

#### 注意

尽管在 AWS Summit 2016 年会议的各种讨论中讨论过，但无服务器计算宣言没有官方网站或文档。宣言详细内容的完整列表可以在 Tim Wagner 博士的演示中看到：[`www.slideshare.net/AmazonWebServices/getting-started-with-aws-lambda-and-the-serverless-cloud`](https://www.slideshare.net/AmazonWebServices/getting-started-with-aws-lambda-and-the-serverless-cloud)。

+   **作为构建块的功能**：在无服务器架构中，开发、部署和扩展的构建块应该是函数。每个函数应该独立部署和扩展，与其他函数无关。

+   **没有服务器、虚拟机或容器**：服务提供商应该为无服务器函数操作所有计算抽象，包括服务器、虚拟机和容器。无服务器架构的用户不需要了解底层基础设施的任何进一步信息。

+   **没有存储**：无服务器应用程序应设计为临时工作负载，每个请求都有一个新鲜的环境。如果它们需要保留一些数据，它们应该使用远程服务，如**数据库即服务**（**DbaaS**）。

+   **隐式容错函数**：无服务器基础架构和部署的应用程序都应该是容错的，以创建一个强大、可扩展和可靠的应用程序环境。

+   **请求的可伸缩性**：包括计算和网络资源在内的基础架构应该能够实现高度的可伸缩性。换句话说，当请求增加时，无服务器环境不应该无法扩展。

+   **空闲时间没有成本**：无服务器提供商只有在无服务器工作负载运行时才会产生成本。如果您的函数长时间没有收到 HTTP 请求，您不应该为空闲支付任何费用。

+   **自带代码**（**BYOC**）：无服务器架构应该能够运行由最终用户开发和打包的任何代码。如果您是 Node.Js 或 Go 开发人员，应该可以在您喜欢的语言中部署您的函数到无服务器基础架构中。

+   **仪器仪表**：应该向开发人员提供有关函数日志和函数调用收集的指标。这使得能够调试和解决与函数相关的问题。由于它们已经在远程服务器上运行，仪器仪表不应该在分析潜在问题方面产生进一步的负担。

原始宣言介绍了一些最佳实践和限制；然而，随着云技术的发展，无服务器应用程序的世界也在不断发展。这种演变将使宣言中的一些规则过时，并增加新规则。在接下来的部分中，讨论了无服务器应用程序的用例，以解释无服务器在行业中的应用情况。

### 无服务器用例

无服务器应用程序和设计似乎是前卫的技术；然而，它们在行业中被广泛采用，用于可靠、强大和可伸缩的应用程序。如果您希望获得无服务器设计的好处，任何在 VM、Docker 容器或 Kubernetes 上运行的传统应用程序都可以设计为无服务器运行。以下是一些无服务器架构的知名用例：

+   **数据处理**：解释、分析、清洗和格式化数据是大数据应用中必不可少的步骤。借助无服务器架构的可伸缩性，您可以快速过滤数百万张照片并计算其中的人数，例如，而无需购买任何昂贵的服务器。根据一份案例报告（[`azure.microsoft.com/en-in/blog/a-fast-serverless-big-data-pipeline-powered-by-a-single-azure-function/`](https://azure.microsoft.com/en-in/blog/a-fast-serverless-big-data-pipeline-powered-by-a-single-azure-function/)），可以使用 Azure Functions 创建一个无服务器应用程序，以检测来自多个来源的欺诈交易。为了处理 800 万个数据处理请求，无服务器平台将是适当的选择，因为它们具有临时可伸缩性。

+   Webhooks：Webhooks 是向第三方服务发送实时数据的 HTTP API 调用。与为 Webhook 后端运行服务器不同，可以利用无服务器基础架构以更低的成本和更少的维护。

+   结账和付款：可以将购物系统创建为无服务器应用程序，其中每个核心功能都设计为独立的组件。例如，您可以集成 Stripe API 作为远程支付服务，并在无服务器后端中使用 Shopify 服务进行购物车管理。

+   实时聊天应用程序：集成到 Facebook Messenger、Telegram 或 Slack 等应用程序的实时聊天应用程序非常受欢迎，用于处理客户操作、分发新闻、跟踪体育比赛结果，或者只是用于娱乐。可以创建临时无服务器函数来响应消息或根据消息内容采取行动。无服务器实时聊天的主要优势在于，当许多人在使用时，它可以扩展。当没有人使用聊天应用程序时，它也可以缩减到零成本。

这些用例说明了无服务器架构可以用于设计任何现代应用程序。还可以将单体应用程序的某些部分移动并转换为无服务器函数。如果您当前的在线商店是打包为 JAR 文件的单个 Java Web 应用程序，可以将其业务功能分离并转换为无服务器组件。将巨大的单体应用程序分解为小的无服务器函数有助于同时解决多个问题。首先，无服务器应用程序的可扩展性永远不会成为问题。例如，如果在假期期间无法处理大量付款，无服务器平台将根据使用水平自动扩展付款功能。其次，您不需要局限于单体的编程语言；您可以使用任何编程语言开发函数。例如，如果您的数据库客户端最好使用 Node.js 实现，您可以使用 Node.js 编写在线商店的数据库操作。

最后，您可以重用在您的单体中实现的逻辑，因为现在它是一个共享的无服务器服务。例如，如果您将在线商店的支付操作分离出来并创建无服务器支付功能，您可以在下一个项目中重用这些支付功能。所有这些好处使得创业公司和大型企业都愿意采用无服务器架构。在接下来的部分中，将更深入地讨论无服务器架构，特别关注一些实现。

可能的答案：

+   具有高延迟的应用程序

+   当可观察性和指标对业务至关重要时

+   当供应商锁定和生态系统依赖成为问题时

## 无服务器架构和函数即服务（FaaS）

**无服务器**是一种云计算设计，云提供商处理服务器的供应。在前一节中，我们讨论了操作方面的分层和移交。在本节中，我们将重点讨论无服务器架构和使用无服务器架构的应用程序设计。

在传统软件架构中，应用程序的所有组件都安装在服务器上。例如，假设您正在用 Java 开发一个电子商务网站，您的产品信息存储在**MySQL**中。在这种情况下，前端、后端和数据库都安装在同一台服务器上。预期最终用户将通过服务器的 IP 地址访问购物网站，因此服务器上应该运行应用服务器，比如**Apache Tomcat**。此外，用户信息和安全组件也包含在安装在服务器上的软件包中。图 1.6 显示了一个单体电子商务应用程序，包括前端、后端、安全和数据库部分：

![图 1.6：传统软件架构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_06.jpg)

###### 图 1.6：传统软件架构

**微服务**架构侧重于创建松散耦合且可独立部署的服务集合。对于同一个电子商务系统，您仍然会有前端、后端、数据库和安全组件，但它们将是隔离的单元。此外，这些组件将被打包为容器，并由诸如 Kubernetes 之类的容器编排器进行管理。这使得能够独立安装和扩展组件，因为它们分布在多台服务器上。在图 1.7 中，相同的四个组件安装在服务器上，并通过 Kubernetes 网络相互通信：

![图 1.7：微服务软件架构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_07.jpg)

###### 图 1.7：微服务软件架构

微服务部署到服务器上，仍然由运维团队管理。采用无服务器架构后，这些组件将转换为第三方服务或函数。例如，电子商务网站的安全性可以由诸如**Auth0**之类的身份验证即服务提供商来处理。**AWS 关系型数据库服务（RDS）**可以用作系统的数据库。后端逻辑的最佳选择是将其转换为函数，并部署到无服务器平台，如**AWS Lambda**或**Google Cloud Functions**。最后，前端可以由存储服务提供，如**AWS 简单存储服务（S3）**或**Google Cloud 存储**。

采用无服务器设计，只需为您定义这些服务，您就可以拥有可扩展、强大和管理良好的应用程序，如图 1.8 所示。

#### 注意

`Auth0`是一个用于为 Web、移动和传统应用程序提供身份验证和授权的平台。简而言之，它提供**身份验证和授权即服务**，您可以连接任何使用任何语言编写的应用程序。更多详细信息可以在其官方网站上找到：[`auth0.com`](https://auth0.com)。

![图 1.8：无服务器软件架构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_08.jpg)

###### 图 1.8：无服务器软件架构

从单体架构开始，首先将其分解为微服务，然后再转换为无服务器组件，这样做有多种好处：

+   **成本**：无服务器架构有助于通过两种关键方式降低成本。首先，服务器的管理被外包，其次，只有在使用无服务器应用程序时才会产生费用。

+   **可扩展性**：如果预计应用程序会增长，当前最佳选择是将其设计为无服务器应用程序，因为这样可以消除与基础设施相关的可扩展性约束。

+   **灵活性**：当部署单元的范围减少时，无服务器提供更多灵活性，可以选择更好的编程语言，并且可以用更小的团队进行管理。

这些维度以及它们在软件架构之间的变化在*图 1.9*中可视化。

![图 1.9：从成本到无服务器过渡的好处](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_09.jpg)

###### 图 1.9：从成本到无服务器过渡的好处

当您从传统的软件开发架构开始时，转向微服务会增加可扩展性和灵活性。然而，它并没有直接降低运行应用程序的成本，因为您仍然在处理服务器。进一步转向无服务器可以提高可扩展性和灵活性，同时降低成本。因此，了解并实施无服务器架构对于未来的应用程序至关重要。在接下来的部分中，将介绍无服务器架构的实现，即**函数即服务**（**FaaS**）。

### 函数即服务（FaaS）

**FaaS**是最受欢迎和广泛采用的无服务器架构实现。所有主要的云提供商都有 FaaS 产品，如 AWS Lambda、Google Cloud Functions 和 Azure Functions。顾名思义，在 FaaS 中，部署和管理的单位是函数。在这种情况下，函数与任何其他编程语言中的函数没有区别。它们预期接受一些参数并返回值以实现业务需求。FaaS 平台处理服务器的管理，并且可以运行事件驱动的可扩展函数。FaaS 提供的基本属性如下：

+   **无状态**：函数被设计为无状态和短暂的操作，不会将文件保存到磁盘，也不会管理缓存。每次调用函数时，它都会快速启动一个新环境，并在完成时被移除。

+   **事件触发**：函数设计为直接触发，并基于事件，如`cron`时间表达式、HTTP 请求、消息队列和数据库操作。例如，可以在启动新聊天时通过 HTTP 请求调用`startConversation`函数。同样，可以在向数据库添加新用户时启动`syncUsers`函数。

+   **可扩展**：函数被设计为能够并行运行，以便每个传入请求都得到响应，每个事件都得到处理。

+   **托管**：函数受其平台管理，因此服务器和基础设施不是 FaaS 用户的关注点。

这些函数的属性由云提供商的产品提供，如**AWS Lambda**、**Google Cloud Functions**和**Azure Functions**；以及本地产品，如**Kubeless**、**Apache OpenWhisk**和**OpenFass**。由于其高度的流行度，术语 FaaS 通常与无服务器术语互换使用。在接下来的练习中，我们将创建一个处理 HTTP 请求的函数，并说明如何开发无服务器函数。

### 练习 1：创建一个 HTTP 函数

在这个练习中，我们将创建一个 HTTP 函数，作为无服务器平台的一部分，然后通过 HTTP 请求来调用它。为了执行练习的步骤，您将使用 Docker、文本编辑器和终端。

#### 注意

本章练习的代码文件可以在这里找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Exercise1`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Exercise1)。

要成功完成这个练习，我们需要确保执行以下步骤：

1.  在您喜欢的文本编辑器中创建一个名为`function.go`的文件，并包含以下内容：

```
package main
import (
    "fmt"
    "net/http"
)
func WelcomeServerless(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello Serverless World!")
}
```

在这个文件中，我们已经创建了一个实际的函数处理程序，以便在调用该函数时做出响应。

1.  创建一个名为`main.go`的文件，并包含以下内容：

```
package main
import (
    "fmt"
    "net/http"
)
func main() {
    fmt.Println("Starting the serverless environment..")
    http.HandleFunc("/", WelcomeServerless)
    fmt.Println("Function handlers are registered.")
    http.ListenAndServe(":8080", nil)
}
```

在这个文件中，我们已经创建了用于提供该函数的环境。一般来说，这部分应该由无服务器平台来处理。

1.  在您的终端中使用以下命令启动一个 Go 开发环境：

```
docker run -it --rm -p 8080:8080 -v "$(pwd)":/go/src --workdir=/go/src golang:1.12.5
```

通过该命令，将在 Go 版本`1.12.5`的 Docker 容器内启动一个 shell 提示符。此外，主机系统的端口`8080`被映射到容器，并且当前工作目录被映射到`/go/src`。您将能够在启动的 Docker 容器内运行命令：

![图 1.10：容器内的 Go 开发环境](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_10.jpg)

###### 图 1.10：容器内的 Go 开发环境

1.  在*步骤 3*中打开的 shell 提示符中使用以下命令启动函数处理程序：`go run *.go`。

随着应用程序的启动，您将看到以下行：

![图 1.11：函数服务器的开始](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_11.jpg)

###### 图 1.11：函数服务器的开始

这些行表明`main.go`文件中的`main`函数正在运行

预期。

1.  在浏览器中打开`http://localhost:8080`：![图 1.12：WelcomeServerless 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_12.jpg)

###### 图 1.12：WelcomeServerless 输出

网页上显示的消息显示`WelcomeServerless`函数通过 HTTP 请求成功调用，并且已检索到响应。

1.  按*Ctrl + C*退出函数处理程序，然后输入`exit`停止容器：![图 1.13：退出函数处理程序和容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_13.jpg)

###### 图 1.13：退出函数处理程序和容器

通过这个练习，我们演示了如何创建一个简单的函数。此外，展示了无服务器环境如何提供和调用函数。在接下来的部分中，将介绍 Kubernetes 和无服务器环境，以连接这两个云计算现象。

## Kubernetes 和无服务器

无服务器和 Kubernetes 大约在 2014 年同时出现在云计算领域。AWS 通过 AWS Lambda 支持无服务器，而 Kubernetes 在 Google 的支持下成为开源，并在容器管理方面拥有悠久而成功的历史。组织开始为他们的短暂临时任务创建 AWS Lambda 函数，许多初创公司专注于在无服务器基础设施上运行的产品。另一方面，Kubernetes 在行业中获得了巨大的采用，并成为事实上的容器管理系统。它能够在容器内运行无状态应用程序，如 Web 前端和数据分析工具，以及有状态应用程序，如数据库。应用程序和微服务架构的容器化已被证明对大型企业和初创公司都是有效的。

因此，运行微服务和容器化应用是成功、可扩展和可靠的云原生应用的关键因素。此外，以下两个重要元素加强了 Kubernetes 和无服务器架构之间的联系：

+   供应商锁定：Kubernetes 隔离了云提供商，并为运行无服务器工作负载创建了托管环境。换句话说，如果您想明年转移到新的提供商，要在 Google Cloud Functions 中运行您的 AWS Lambda 函数并不是一件简单的事情。然而，如果您使用基于 Kubernetes 的无服务器平台，您将能够快速在云提供商之间甚至本地系统之间进行迁移。

+   **服务重用**：作为主流的容器管理系统，Kubernetes 在您的云环境中运行大部分工作负载。它提供了一个机会，可以将无服务器函数与现有服务并行部署。这使得操作、安装、连接和管理无服务器和容器化应用变得更加容易。

云计算和部署策略一直在不断发展，以创造更具开发者友好性和更低成本的环境。Kubernetes 和容器化的采用已经赢得了市场和开发者的喜爱，以至于在很长一段时间内，没有 Kubernetes 的云计算将不会被看到。通过提供相同的好处，无服务器架构正在变得越来越受欢迎；然而，这并不构成对 Kubernetes 的威胁。相反，无服务器应用程序将使容器化更易于访问，因此 Kubernetes 将受益。因此，学习如何在 Kubernetes 上运行无服务器架构以创建未来可靠、云原生、可扩展的应用程序至关重要。在接下来的练习中，我们将结合函数和容器，并将我们的函数打包为容器。

可能的答案：

+   无服务器 – 数据准备

+   无服务器 – 短暂的 API 操作

+   Kubernetes – 数据库

+   Kubernetes – 与服务器相关的操作

### 练习 2：将 HTTP 函数打包为容器

在这个练习中，我们将把*练习 1*中的 HTTP 函数打包为一个容器，作为 Kubernetes 工作负载的一部分。此外，我们将运行容器，并通过容器触发函数。

#### 注意

本章练习的代码文件可以在此处找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Exercise2`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Exercise2)。

要成功完成练习，我们需要确保执行以下步骤：

1.  在与*练习 1*相同的文件夹中创建一个名为`Dockerfile`的文件。

```
FROM golang:1.12.5-alpine3.9 AS builder
ADD . .
RUN go build *.go
FROM alpine:3.9
COPY --from=builder /go/function ./function
RUN chmod +x ./function
ENTRYPOINT ["./function"]
```

在这个多阶段的`Dockerfile`中，函数是在`golang:1.12.5-alpine3.9`容器内构建的。然后，将二进制文件复制到`alpine:3.9`容器中作为最终的应用程序包。

1.  在终端中使用以下命令构建 Docker 镜像：`docker build . -t hello-serverless`。

`Dockerfile`的每一行都是按顺序执行的，最后，通过最后一步，Docker 镜像被构建并标记为：`Successfully tagged hello-serverless:latest`：

![图 1.14：Docker 容器的构建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_14.jpg)

###### 图 1.14：Docker 容器的构建

1.  使用以下命令在终端中从`hello-serverless`镜像启动 Docker 容器：`docker run -it --rm -p 8080:8080 hello-serverless`。

通过该命令，使用端口`8080`实例化 Docker 镜像，将主机系统映射到容器。此外，`--rm`标志将在退出时删除容器。日志行表明函数的容器正在按预期运行：

![图 1.15：函数容器的启动](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_15.jpg)

###### 图 1.15：函数容器的启动

1.  在浏览器中打开`http://localhost:8080`：![图 1.16：WelcomeServerless 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_16.jpg)

###### 图 1.16：WelcomeServerless 输出

它显示了在容器中运行的`WelcomeServerless`函数通过 HTTP 请求成功调用，并且已检索到响应。

1.  按下*Ctrl + C*退出容器：![图 1.17：退出容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_17.jpg)

###### 图 1.17：退出容器

在这个练习中，我们看到了如何将一个简单的函数打包为一个容器。此外，容器已启动，并且借助 Docker 的网络功能触发了函数。在接下来的练习中，我们将实现一个参数化函数，以展示如何向函数传递值并返回不同的响应。

### 练习 3：参数化 HTTP 函数

在这个练习中，我们将把*Exercise 2*中的`WelcomeServerless`函数转换为参数化的 HTTP 函数。此外，我们将运行容器，并通过容器触发函数。

#### 注意

本章练习的代码文件可以在这里找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Exercise3`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Exercise3)。

为了成功完成练习，我们需要确保执行以下步骤：

1.  将`function.go`的内容从*Exercise 2*更改为以下内容：

```
package main
import (
	"fmt"
	"net/http"
)
func WelcomeServerless(w http.ResponseWriter, r *http.Request) {
	names, ok := r.URL.Query()["name"]

    if ok && len(names[0]) > 0 {
        fmt.Fprintf(w, names[0] + ", Hello Serverless World!")
	} else {
		fmt.Fprintf(w, "Hello Serverless World!")
	}
}
```

在新版本的`WelcomeServerless`函数中，我们现在接受 URL 参数并相应返回响应。

1.  在终端中使用以下命令构建 Docker 镜像：`docker build . -t hello-serverless`。

`Dockerfile`的每一行都按顺序执行，最后一步，Docker 镜像被构建并标记为：`Successfully tagged hello-serverless:latest`：

![图 1.18：Docker 容器的构建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_18.jpg)

###### 图 1.18：Docker 容器的构建

1.  在终端中使用以下命令从`hello-serverless`镜像启动 Docker 容器：`docker run -it –rm -p 8080:8080 hello-serverless`。

使用该命令，函数处理程序将在主机系统的端口`8080`上启动：

![图 1.19：函数容器的开始](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_19.jpg)

###### 图 1.19：函数容器的开始

1.  在浏览器中打开`http://localhost:8080`：![图 1.20：WelcomeServerless 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_20.jpg)

###### 图 1.20：WelcomeServerless 输出

它显示与上一个练习中相同的响应。如果我们提供 URL 参数，我们应该会得到个性化的`Hello Serverless World`消息。

1.  将地址更改为`http://localhost:8080?name=Ece`并重新加载页面。我们现在期望看到一个带有 URL 参数中提供的名称的个性化`Hello Serverless World`消息：![图 1.21：个性化的 WelcomeServerless 输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_21.jpg)

###### 图 1.21：个性化的 WelcomeServerless 输出

1.  按下*Ctrl + C*退出容器：![图 1.22：退出容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_22.jpg)

###### 图 1.22：退出容器

在这个练习中，展示了如何使用不同参数的通用函数。我们部署的单个函数返回了基于输入值的个人消息。在接下来的活动中，将创建一个更复杂的函数，并将其作为容器进行管理，以展示它们在现实生活中的实现方式。

### 活动 1：伦敦自行车点的 Twitter 机器人后端

这项活动的目的是为 Twitter 机器人后端创建一个真实的功能。Twitter 机器人将用于搜索伦敦的可用自行车点和相应位置的可用自行车数量。机器人将以自然语言形式回答；因此，您的函数将接受街道名称或地标的输入，并输出完整的人类可读句子。

伦敦的交通数据是公开可用的，并且可以通过**伦敦交通局**（**TFL**）**统一 API**（[`api.tfl.gov.uk`](https://api.tfl.gov.uk)）进行访问。您需要使用 TFL API 并在容器内运行您的函数。

完成后，您将有一个运行函数的容器：

![图 1.23：容器内运行的函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_23.jpg)

###### 图 1.23：容器内运行的函数

当您通过 HTTP REST API 查询时，如果找到可用的自行车点，它应返回类似以下的句子：

![图 1.24：当自行车可用时的功能响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_24.jpg)

###### 图 1.24：当自行车可用时的功能响应

当找不到自行车点或这些位置没有可用的自行车时，函数将返回类似以下的响应：

![图 1.25：当找到自行车点但没有找到自行车时的功能响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_25.jpg)

###### 图 1.25：当找到自行车点但没有找到自行车时的功能响应

函数还可能提供以下响应：

![图 1.26：当找不到自行车点或自行车时的功能响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_01_26.jpg)

###### 图 1.26：当找不到自行车点或自行车时的功能响应

执行以下步骤完成此活动：

1.  创建一个`main.go`文件来注册函数处理程序，就像*练习 1*中一样。

1.  为`FindBikes`函数创建一个`function.go`文件。

1.  为构建和打包函数创建一个`Dockerfile`，就像*练习 2*中一样。

1.  使用 Docker 命令构建容器映像。

1.  作为 Docker 容器运行容器映像，并使端口从主机系统可用。

1.  使用不同的查询测试函数的 HTTP 端点。

1.  退出容器。

#### 注意

文件`main.go`，`function.go`和`Dockerfile`可以在这里找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Activity1`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/tree/master/Lesson01/Activity1)。

活动的解决方案可以在第 372 页找到。

在这个活动中，我们构建了 Twitter 机器人的后端。我们首先定义了`main`和`FindBikes`函数。然后我们将这个无服务器后端构建和打包为 Docker 容器。最后，我们用各种输入测试它，以找到最近的自行车站。通过这个现实生活中的例子，展示了无服务器平台的后台操作以及如何编写无服务器函数。

## 摘要

在本章中，我们首先描述了从传统软件开发到无服务器软件开发的过程。我们讨论了多年来软件开发如何改变，以创造一个更加开发者友好的环境。在此之后，我们介绍了无服务器技术的起源及其官方宣言。由于无服务器是行业中流行的术语，定义一些规则有助于设计更好的无服务器应用程序，使其能够轻松集成到各种平台中。然后，我们列举了无服务器技术的用例，以说明无服务器架构如何用于创建任何现代应用程序。

在介绍无服务器之后，探讨了 FaaS 作为无服务器架构的一种实现。我们展示了应用程序在传统、微服务和无服务器设计中的设计方式。此外，还详细讨论了过渡到无服务器架构的好处。

最后，讨论了 Kubernetes 和无服务器技术，以展示它们如何相互支持。作为主流的容器管理系统，介绍了 Kubernetes，涉及了在其上运行无服务器平台的优势。容器化和微服务在工业界得到了广泛采用，因此涵盖了作为容器运行无服务器工作负载的内容，并提供了相关练习。最后，探讨了将函数作为 Twitter 机器人的后端的真实案例。在这个活动中，函数被打包为容器，以展示基于微服务、容器化和 FaaS 支持设计之间的关系。

在下一章中，我们将介绍云中的无服务器架构，并使用云服务进行工作。


# 第二章：介绍云中的无服务器

## 学习目标

在本章结束时，您将能够：

+   评估选择最佳无服务器 FaaS 提供商的标准

+   识别主要云服务提供商支持的语言、触发类型和成本结构

+   将无服务器函数部署到云提供商并将函数与其他云服务集成

在本章中，我们将解释云提供商的无服务器 FaaS 产品，创建我们在云中的第一个无服务器函数，并与其他云服务集成。

## 介绍

在上一章中，讨论了传统架构向无服务器设计的架构演变。此外，介绍了无服务器的起源和好处，以解释其在行业中的高采用率和成功。在本章中，重点将放在云提供商的无服务器平台上。让我们从多年来云技术提供的演变开始。

在云计算开始时，云提供商的主要提供是其预配和可立即使用的硬件，即**基础设施**。云提供商管理硬件和网络操作，因此，他们提供的产品是**基础设施即服务**（**IaaS**），如下图所示。所有云提供商仍然将 IaaS 产品作为其核心功能，比如 AWS 的**Amazon 弹性计算云（Amazon EC2）**和 GCP 的**Google 计算引擎**。

在接下来的几年里，云提供商开始提供平台，开发人员只能在其上运行他们的应用程序。通过这种抽象，手动服务器配置、安全更新和服务器故障成为了云提供商的关注点。这些提供被称为**平台即服务**（**PaaS**），因为它们只专注于在其平台上运行应用程序和数据。**Heroku**是最受欢迎的 PaaS 提供商，尽管每个云提供商都有自己的 PaaS 产品，比如**AWS 弹性 Beanstalk**或**Google App Engine**。与 IaaS 类似，PaaS 在软件开发中仍在使用。

在顶层抽象中，应用程序的功能作为无服务器架构中的控制单元。这被称为**函数即服务**（**FaaS**），近年来所有重要的云提供商都提供了这种抽象。从 IaaS 到 PaaS，最终到 FaaS 的抽象层次可以在下图中看到：

![图 2.1：从 IaaS 到 PaaS 和 FaaS 的转变](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_01.jpg)

###### 图 2.1：从 IaaS 到 PaaS 和 FaaS 的转变

### 无服务器和云评估标准

为了分析市场上的 FaaS 产品，定义一些标准是有益的，这样我们就可以以结构化的方式比较产品。在选择云提供商之前，以下主题对于每个 FaaS 平台都是必不可少的，并需要进行详细调查：

+   **编程语言：** 函数部署和管理在云提供商的环境中。因此，云提供商定义支持的编程语言。这是最重要的决策因素之一，因为在大多数情况下，使用其他语言实现函数是不可行的。

+   **功能触发器：** 函数设计为由云提供商服务和外部方法触发。传统的技术包括定时调用、按需调用以及与其他云服务（如数据库、队列和 API 网关）的集成。

+   **成本：** 无服务器架构最具吸引力的特点是其成本效益和主流的价格计算方式，即按请求付费。对于长期运行的项目的可行性，计算实际和预期成本是至关重要的。

云提供商应该具有成本效益，尽可能提供多种编程语言，并支持各种功能触发器。还有其他标准，如监控、运维和内部知识水平，但这些与云提供商的无服务器产品并不直接相关。在接下来的章节中，将讨论三个最主要的云提供商的无服务器平台：亚马逊云服务、谷歌云平台和微软 Azure。

### AWS Lambda

AWS Lambda 是第一个 FaaS 提供，也在行业中引起了无服务器的热潮。它于 2014 年公开，并被各级组织广泛采用于云计算世界。它使初创公司能够在短时间内创建新产品。它还使像 Netflix 这样的大型企业能够将基于事件的触发器转移到无服务器功能上。通过消除服务器操作负担的机会，AWS Lambda 和无服务器成为了行业的下一个趋势。在本节中，我们将讨论 AWS Lambda 的编程语言支持、触发器类型和成本结构。此外，我们将部署我们的第一个无服务器函数。

#### 注意

如果您想了解更多信息，可以在此处找到 AWS Lambda 的官方网站：[`aws.amazon.com/lambda`](https://aws.amazon.com/lambda)。

AWS Lambda 在无服务器函数方面支持 Java、Python、Node.js、C#、Ruby 和 Go 编程语言。此外，AWS Lambda 提供了一个名为 AWS Lambda Runtime Interface 的 API，以实现任何语言作为自定义运行时的集成。因此，可以说 AWS Lambda 本地支持一组流行的语言，同时允许扩展到其他编程语言。

AWS Lambda 旨在具有事件触发功能。这是函数处理从事件源检索到的事件的地方。在 AWS 生态系统中，各种服务都可以是事件源，包括以下内容：

+   亚马逊 S3 文件存储用于添加新文件时

+   亚马逊 Alexa 用于实现语音助手的新技能

+   亚马逊 CloudWatch Events 用于云资源状态更改时发生的事件

+   亚马逊 CodeCommit 用于开发人员向代码存储库推送新提交时

除了这些服务之外，无服务器事件源的基本 AWS 服务是**Amazon API Gateway**。它具有通过 HTTPS 调用 Lambda 函数的 REST API 功能，并允许管理多个 Lambda 函数以用于不同的方法，如`GET`、`POST`、`PATCH`和`DELETE`。换句话说，API Gateway 在无服务器函数和外部世界之间创建了一个层。这一层还通过保护 Lambda 函数免受**分布式拒绝服务**（**DDoS**）攻击和定义节流来处理 Lambda 函数的安全性。如果要与其他 AWS 服务集成或通过 API Gateway 公开它们，AWS Lambda 函数的触发器类型和环境是高度可配置的。

对于 AWS Lambda 的定价，有两个关键点需要注意：第一个是**请求费用**，第二个是**计算费用**。请求费用是基于函数调用次数计算的，而计算费用是按每秒 GB 计算的。计算费用是内存大小和执行时间的乘积：

+   **内存大小（GB）**：这是函数配置的分配内存。

+   **执行时间（毫秒）**：这是函数实际运行的执行时间。

此外，还有一个免费套餐，其中每月免除前 100 万次请求费用和每秒 400,000 GB 的计算费用。包括免费套餐在内的简单计算可以显示运行无服务器函数的成本是多么便宜。

假设您的函数一个月被调用了 3000 万次。您已经分配了 128 MB 的内存，平均来说，函数运行了 200 毫秒：

*请求费用：*

**价格**：每 100 万次请求$0.20

**免费套餐**：100 万次

**月请求**：30 M

**月请求费用**：29 M x $0.20 / M = $5.80

*计算费用：*

**价格**：每 GB 每秒$0.0000166667

**免费套餐**：每秒 400,000 GB

**月计算**：30 M x 0.2 秒 x 128 MB / 1024 = 750,000 GB 每秒

**月计算费用**：350,000 x $0.0000166667 = $5.83

**月总成本**：$5.80 + $5.83 = $11.63

这个计算表明，在运行一个无服务器的 AWS Lambda 环境中，每天接收*100 万次函数调用的月成本为 11.63 美元*。这表明了运行无服务器工作负载的成本是多么便宜，以及在无服务器经济中需要考虑的基本特征。在接下来的练习中，我们的第一个无服务器函数将部署到 AWS Lambda，并将被调用以显示平台的操作视图。

#### 注意

为了完成这个练习，您需要拥有一个活跃的亚马逊网络服务账户。您可以在[`aws.amazon.com/`](https://aws.amazon.com/)上创建一个账户。

### 练习 4：在 AWS Lambda 中创建函数并通过 AWS Gateway API 调用它

在这个练习中，我们将创建我们的第一个 AWS Lambda 函数，并将其连接到 AWS Gateway API，以便我们可以通过其 HTTP 端点调用。

要成功完成此练习，我们需要确保执行以下步骤：

1.  打开 AWS 管理控制台，在**查找服务**搜索框中输入**Lambda**，然后单击**Lambda - Run Code without Thinking about Servers**。控制台将如下所示：![图 2.2：AWS 管理控制台](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_02.jpg)

###### 图 2.2：AWS 管理控制台

1.  单击 Lambda 函数列表中的**创建函数**，如下截图所示：![图 2.3：AWS Lambda - 函数列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_03.jpg)

###### 图 2.3：AWS Lambda - 函数列表

1.  在**创建函数**视图中选择**从头开始**。将`hello-from-lambda`作为函数名称，`Python 3.7`作为运行时。单击屏幕底部的**创建函数**，如下截图所示：![图 2.4：AWS Lambda - 创建函数视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_04.jpg)

###### 图 2.4：AWS Lambda - 创建函数视图

1.  您将被引导到**hello-from-lambda**函数视图，这是您

1.  可以编辑**函数代码**，如下截图所示：![图 2.5：AWS Lambda - hello-from-lambda](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_05.jpg)

###### 图 2.5：AWS Lambda - hello-from-lambda

1.  更改`lambda_handler`函数如下：

```
import json
def lambda_handler(event, context):
    return {
        'statusCode': '200',
        'body': json.dumps({"message": "hello", "platform": "lambda"}),
        'headers': {
            'Content-Type': 'application/json',
        }
    }
```

1.  单击屏幕顶部的**保存**，如下截图所示：![图 2.6：AWS Lambda - hello-from-lambda 函数代码](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_06.jpg)

###### 图 2.6：AWS Lambda - hello-from-lambda 函数代码

1.  打开**设计**视图，点击**添加触发器**，如下面的屏幕截图所示：![图 2.7：AWS Lambda – hello-from-lambda 设计视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_07.jpg)

###### 图 2.7：AWS Lambda – hello-from-lambda 设计视图

1.  从触发器列表中选择**API Gateway**，如下面的屏幕截图所示：![图 2.8：AWS Lambda – 触发器列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_08.jpg)

###### 图 2.8：AWS Lambda – 触发器列表

1.  在触发器配置屏幕上选择**创建新的 API**作为 API，并且选择**开放**作为**安全**配置，如下面的屏幕截图所示：![图 2.9：AWS Lambda – 触发器配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_09.jpg)

###### 图 2.9：AWS Lambda – 触发器配置

在这个屏幕上，已经在 API Gateway 中为`hello-from-lambda`函数定义了一个新的 API，并且开放了安全性。这个配置确保了一个端点将被创建，并且它将可以在没有任何身份验证的情况下访问。

1.  在屏幕底部点击**添加**。

您将被重定向到`hello-from-lambda`函数，通知显示**该函数现在正在接收来自触发器的事件**。在**设计**视图中，Lambda 函数连接到 API Gateway 以进行触发，并连接到 Amazon CloudWatch Logs 以进行日志记录。换句话说，现在可以通过 API Gateway 端点触发函数，并在 CloudWatch 中检查它们的输出，如下面的屏幕截图所示：

![图 2.10：AWS Lambda – 添加触发器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_10.jpg)

###### 图 2.10：AWS Lambda – 添加触发器

1.  从 API Gateway 部分获取 API Gateway 端点，如下面的屏幕截图所示：![图 2.11：AWS Lambda – 触发器 URL](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_11.jpg)

###### 图 2.11：AWS Lambda – 触发器 URL

1.  在新标签页中打开 URL 来触发函数并获取响应，如下面的屏幕截图所示：![图 2.12：AWS Lambda – 函数响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_12.jpg)

###### 图 2.12：AWS Lambda – 函数响应

这个 JSON 响应表明 AWS Lambda 函数通过 API Gateway 连接并且按预期工作。

1.  从第 2 步返回到**函数**列表，选择`hello-from-lambda`，并从**操作**中选择**删除**。然后，点击弹出窗口中的**删除**以从 Lambda 中删除该函数，如下面的屏幕截图所示：![图 2.13：AWS Lambda – 函数删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_13.jpg)

###### 图 2.13：AWS Lambda – 函数删除

在这个练习中，展示了创建 AWS Lambda 函数并连接到 AWS Gateway API 以进行 HTTP 访问的一般流程。在不到 10 个步骤的时间内，就可以在 AWS Lambda 云环境中运行生产就绪的服务。这个练习向您展示了无服务器平台如何使软件开发变得快速简单。在接下来的部分中，将继续分析云提供商的无服务器平台，其中包括 Microsoft 的 Azure Functions。

### Azure Functions

微软于 2016 年宣布了**Azure Functions**，作为**Microsoft Azure**云中的无服务器平台。Azure Functions 通过来自 Azure 或外部服务的事件触发器来运行无服务器工作负载，从而扩展了其云平台。它的特色在于专注于行业中广泛使用的 Microsoft 支持的编程语言和工具。在本节中，将从支持的编程语言、触发器类型和成本方面讨论 Azure Functions。最后，我们将部署一个从端点接收参数的函数到 Azure Functions，以说明其操作方面。

#### 注意

如果您想了解更多信息，可以在这里找到 Azure Functions 的官方网站：[`azure.microsoft.com/en-us/services/functions/`](https://azure.microsoft.com/en-us/services/functions/)。

Azure Functions 的最新版本支持**C#**，**JavaScript**（在**Node.js**运行时），**F#**，**Java**，**PowerShell**，**Python**和**Typescript**，它会被转译成**JavaScript**。此外，提供了一种语言可扩展性接口，用于在**gRPC**作为消息层的函数运行时和工作进程之间进行通信。在开始使用之前，了解 Azure Functions 支持的普遍可用的、实验性的和可扩展的编程语言是很有价值的。

#### 注意

`gRPC`是一个最初由 Google 开发的**远程过程调用**（**RPC**）系统。它是一个开源系统，可以实现跨平台通信，没有语言或平台限制。

Azure Functions 旨在由各种类型触发，例如定时器、HTTP、文件操作、队列消息和事件。此外，可以为函数指定输入和输出绑定。这些绑定定义了函数的输入参数和要发送到其他服务的输出值。例如，可以创建一个定时函数来从 Blob Storage 中读取文件，并将 Cosmos DB 文档创建为输出。在这个例子中，函数可以使用**定时器触发器**、**Blob Storage**输入绑定和**Cosmos DB**输出绑定进行定义。触发器和绑定使 Azure Functions 轻松集成到 Azure 服务和外部世界中。

与 AWS Lambda 相比，Azure Functions 的成本计算方法和当前价格有两个不同之处。第一个区别是 Azure Functions 的当前计算价格略低，为每秒$0.000016/GB。第二个区别是 Azure Functions 使用观察到的内存消耗进行计算，而 AWS Lambda 中内存限制是预先配置的。

在接下来的练习中，第一个无服务器函数将被部署到 Azure Functions，并将被调用以显示平台的操作视图。

#### 注意

为了完成这项练习，您需要拥有一个活跃的 Azure 账户。您可以在[`signup.azure.com/`](https://signup.azure.com/)上创建一个账户。

### 练习 5：在 Azure Functions 中创建一个带参数的函数

在这个练习中，我们的目标是在 Azure 中创建一个带参数的函数，并通过其 HTTP 端点以不同的参数进行调用。

为了成功完成这项练习，我们需要确保执行以下步骤：

1.  在**Azure**首页的左侧菜单中点击**Function App**，如下截图所示：![图 2.14：Azure 首页](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_14.jpg)

###### 图 2.14：Azure 首页

1.  从**Function App**列表中点击**创建函数应用**，如下截图所示：![图 2.15：函数应用列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_15.jpg)

###### 图 2.15：函数应用列表

1.  给应用取一个唯一的名称，比如`hello-from-azure`，并选择**Node.js**作为**Runtime Stack**。点击页面底部的**创建**，如下截图所示：![图 2.16：创建一个函数应用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_16.jpg)

###### 图 2.16：创建一个函数应用

1.  您将被重定向到**函数应用**列表视图。检查菜单顶部是否有通知。您将看到**正在部署到资源组'hello-from-azure'**，如下图所示：![图 2.17：部署正在进行中](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_17.jpg)

###### 图 2.17：部署正在进行中

等待几分钟，直到部署完成：

![图 2.18：成功部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_18.jpg)

###### 图 2.18：成功部署

1.  在`hello-from-azure`函数应用视图中点击**+新函数**，如下图所示：![图 2.19：hello-from-azure 函数应用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_19.jpg)

###### 图 2.19：hello-from-azure 函数应用

1.  选择**In-portal**作为开发环境，在 Azure Web 门户内创建函数，并单击**继续**，如下图所示：![图 2.20：函数开发环境](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_20.jpg)

###### 图 2.20：函数开发环境

1.  选择**Webhook + API**，然后单击**创建**，如下图所示：![图 2.21：函数触发器类型](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_21.jpg)

###### 图 2.21：函数触发器类型

在此视图中，可以从模板创建函数，例如 webhooks、定时器或来自市场的协作模板。

1.  将以下函数写入`index.js`，然后单击**保存**：

```
module.exports = async function (context, req) {
    context.log('JavaScript HTTP trigger function processed a request.');
    if (req.query.name || (req.body && req.body.name)) {
        context.res = {
            status: 200,
            body: "Hello " + (req.query.name || req.body.name) +", it is your function in Azure!"
        };
    }
    else {
        context.res = {
            status: 400,
            body: "Please pass a name on the query string or in the request body."
        };
    }
};
```

此代码导出一个接受来自请求的参数的函数。该函数创建一个个性化消息，并将其作为输出发送给用户。代码应该插入到代码编辑器中，如下图所示：

![图 2.22：hello-from-azure 函数的 index.js](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_22.jpg)

###### 图 2.22：hello-from-azure 函数的 index.js

1.  点击**获取函数 URL**并复制弹出窗口中的 URL，如下图所示

1.  下面的屏幕截图：![图 2.23：函数 URL](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_23.jpg)

###### 图 2.23：函数 URL

1.  在浏览器中打开您在*步骤 7*中复制的 URL，如下面的屏幕截图所示：![图 2.24：没有参数的函数响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_24.jpg)

###### 图 2.24：没有参数的函数响应

在 URL 的末尾添加**&name=**和您的名字，然后重新加载选项卡，例如`https://hello-from-azure.azurewebsites.net/api/HttpTrigger?code=nNrck...&name=Onur`，如下面的屏幕截图所示：

![图 2.25：带参数的函数响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_25.jpg)

###### 图 2.25：带参数的函数响应

这些响应表明可以验证和传递参数给函数。对于无服务器函数以及考虑各种触发器和绑定的可能性时，传递参数及其验证是至关重要的。

1.  从*步骤 2*返回**函数应用**列表，单击我们创建的新函数旁边的**...**，然后选择**删除**，如下面的屏幕截图所示：![图 2.26：删除函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_26.jpg)

###### 图 2.26：删除函数

在弹出视图中输入函数名称，然后单击**删除**以删除所有资源。在确认视图中，警告指示函数应用的删除是不可逆的，如下面的屏幕截图所示：

![图 2.27：删除函数及其资源](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_27.jpg)

###### 图 2.27：删除函数及其资源

在下一节中，将以类似的方式讨论谷歌云函数，并将更复杂的函数部署到云提供商。

### 谷歌云函数

谷歌云函数于 2017 年公开发布，就在 AWS Lambda 和 Azure Functions 之后。在谷歌云函数发布之前，PaaS 产品谷歌的**Firebase**已经支持无服务器函数。然而，谷歌云函数作为其核心无服务器云产品，已经对谷歌云平台内的所有服务开放。在本节中，将讨论谷歌云函数支持的编程语言、触发器类型和成本。最后，我们将部署一个定期被云服务调用的函数到谷歌云函数，以展示其操作方面。

#### 注意

如果您想了解更多信息，可以在谷歌云函数的官方网站找到：[`cloud.google.com/functions/`](https://cloud.google.com/functions/)。

**谷歌云函数**（**GCF**）可以使用**Node.js**、**Python**和**Go**进行开发。与其他主要云提供商相比，GCF 支持的语言范围较小。此外，GCF 不支持公开可用的语言扩展或 API。因此，评估 GCF 支持的语言是否适用于您将开发的函数至关重要。

Google Cloud Functions 旨在与触发器和事件相关联。事件发生在您的云服务中，例如数据库更改、存储系统中的新文件，或者在提供新虚拟机时。触发器是将服务和相关事件声明为函数输入的声明。可以创建触发器作为**HTTP**端点、**Cloud Pub/Sub**队列消息，或存储服务，如**Cloud Storage**和**Cloud Firestore**。此外，函数可以连接到 Google Cloud Platform 提供的大数据和机器学习服务。

与其他云提供商相比，Google Cloud Platform 的成本计算略微复杂。这是因为它考虑了调用、计算时间和出站网络数据，而其他云提供商只关注调用和计算时间：

+   **调用**：每一百万请求收取 0.40 美元。

+   **计算时间**：函数的计算时间从调用开始到完成，以 100 毫秒为增量计算。例如，如果您的函数完成需要 240 毫秒，您将被收取 300 毫秒的计算时间费用。在这个计算中使用了两个单位 - **每秒 GB** 和 **每秒 GHz**。为运行 1 秒的函数提供 1GB 内存，每秒 1GB 的价格为 0.0000025 美元。此外，为运行 1 秒的函数提供 1GHz 的 CPU，每秒 1GHz 的价格为 0.0000100 美元。

+   **出站网络数据**：从函数传输到外部的数据以 GB 计量，每 GB 数据收取 0.12 美元。

GCF 的免费套餐提供了 200 万次调用、每秒 400,000GB、每秒 200,000GHz 的计算时间，以及每月 5GB 的出站网络流量。与 AWS 或 Azure 相比，GCP 的成本会略高，因为它的价格更高，计算方法更复杂。

假设您的函数一个月被调用了 3000 万次。您已经分配了 128MB 内存，200MHz 的 CPU，并且平均来说，函数运行时间为 200 毫秒，类似于 AWS Lambda 的例子：

*请求费用*

**价格**：每 1 百万请求 0.40 美元

**免费套餐**：2 百万

**每月请求**：30 百万

**每月请求费用** = 28 百万 x 0.40 / 百万 = 11.2 美元

*计算费用 - 内存：*

**价格**：每 GB 秒 0.0000025 美元

**免费套餐**：400,000GB 秒

**每月计算**：30 M x 0.2 秒 x 128 MB / 1024 = 750,000 GB 秒

**每月内存费用**：350,000 x $0.0000025 = $0.875

*计算费用 - CPU：*

**价格**：每 GHz 秒$0.0000100

**免费套餐**：200,000 GB 秒

**每月计算**：30 M x 0.2 秒 x 200 MHz / 1000 GHz = 1,200,000 GHz 秒

**每月 CPU 费用**：1,000,000 x $0.0000100 = $10

**每月总费用**= $11.2 + $0.875 + $10 = $22.075

由于单位价格略高于 AWS 和 Azure，运行相同函数的总月费用在 GCP 中超过$22，而在 AWS 和 Azure 中约为$11。此外，从函数到外部世界的任何出站网络在潜在的额外成本方面都是至关重要的。因此，在选择无服务器云平台之前，应深入分析定价方法和单位价格。

在下面的练习中，我们的第一个无服务器函数将部署到 GCF，并将被定时触发器调用，以显示平台的运行视图。

#### 注意

为了完成这个练习，您需要拥有一个活跃的 Google 账户。您可以在[`console.cloud.google.com/start`](https://console.cloud.google.com/start)上创建一个账户。

### 练习 6：在 GCF 中创建一个定时函数

在这个练习中，我们的目标是在 Google Cloud Platform 中创建一个定时函数，并使用云调度器服务来检查其调用。

要成功完成这个练习，我们需要确保执行以下步骤：

1.  点击左侧菜单中的**云函数**，它可以在 Google Cloud Platform 主页的**计算**组中找到，如下面的屏幕截图所示：![图 2.28：Google Cloud Platform 主页](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_28.jpg)

###### 图 2.28：Google Cloud Platform 主页

1.  点击**Cloud Functions**页面上的**创建函数**，如下面的屏幕截图所示：![图 2.29：云函数页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_29.jpg)

###### 图 2.29：云函数页面

1.  在函数创建表单中，将函数名称更改为`HelloWorld`，并选择 128 MB 的内存分配。确保选择**HTTP**作为触发方法，并选择**Go 1.11**作为运行时，如下面的屏幕截图所示：![图 2.30：函数创建表单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_30.jpg)

###### 图 2.30：函数创建表单

1.  使用浏览器内联编辑器更改`function.go`，使其具有以下内容：

```
package p
import (
	"fmt"
	"net/http"
)
func HelloWorld(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello World from Google Cloud Functions!")
	return
}
```

此代码段创建一个带有静态消息打印到输出的`HelloWorld`函数。代码应插入到代码编辑器中的`function.go`中，如下截图所示：

![图 2.31：函数内联编辑器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_31.jpg)

###### 图 2.31：函数内联编辑器

1.  复制“触发器”选择框下方表单中的 URL 以调用函数，如下截图所示：![图 2.32：函数触发 URL](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_32.jpg)

###### 图 2.32：函数触发 URL

1.  单击表单末尾的“创建”按钮。使用此配置，将打包并部署第 4 步的代码到 Google Cloud Platform。此外，将为函数分配一个触发器 URL，以便从外部访问，如下截图所示：![图 2.33：函数创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_33.jpg)

###### 图 2.33：函数创建

等待几分钟，直到函数列表中的`HelloWorld`函数旁边有一个绿色的勾号图标，如下截图所示：

![图 2.34：功能部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_34.jpg)

###### 图 2.34：功能部署

1.  在浏览器中打开您在第 5 步中复制的 URL，如下截图所示：![图 2.35：函数响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_35.jpg)

###### 图 2.35：函数响应

响应显示函数已成功部署并按预期运行。

1.  在左侧菜单中单击“TOOLS”下的“Cloud Scheduler”，如下截图所示：![图 2.36：Google Cloud 工具菜单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_36.jpg)

###### 图 2.36：Google Cloud 工具菜单

1.  在“Cloud Scheduler”页面上单击“创建作业”，如下截图所示：![图 2.37：Cloud Scheduler 页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_37.jpg)

###### 图 2.37：Cloud Scheduler 页面

1.  如果您在 Google Cloud 项目中首次使用 Cloud Scheduler，请选择一个区域，然后单击“下一步”，如下截图所示：![图 2.38：Cloud Scheduler – 区域选择](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_38.jpg)

###### 图 2.38：Cloud Scheduler – 区域选择

如果看到以下通知，请等待几分钟：

**我们正在初始化您选择的区域中的 Cloud Scheduler。这通常需要大约一分钟**。

1.  将作业名称设置为`HelloWorldEveryMinute`，频率设置为`* * * * *`，这意味着作业将每分钟触发一次。选择 HTTP 作为目标，并将在步骤 5 中复制的 URL 粘贴到 URL 框中，如下面的屏幕截图所示：![图 2.39：调度程序作业创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_39.jpg)

###### 图 2.39：调度程序作业创建

1.  您将被重定向到**Cloud Scheduler**列表，如下面的屏幕截图所示：![图 2.40：云调度程序页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_40.jpg)

###### 图 2.40：云调度程序页面

等待几分钟，然后单击**刷新**按钮。列表将显示`HelloWorldEveryMinute`的**最后运行**时间戳及其结果，如下面的屏幕截图所示：

![图 2.41：带有运行信息的云调度程序页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_41.jpg)

###### 图 2.41：带有运行信息的云调度程序页面

这表明云调度程序在`2019 年 8 月 13 日下午 3:44:00`触发了我们的函数，并且结果是成功的。

1.  从第 7 步返回到函数列表，然后单击`HelloWorld`函数的**...**，然后单击**日志**，如下面的屏幕截图所示：![图 2.42：函数的设置菜单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_42.jpg)

###### 图 2.42：函数的设置菜单

您将被重定向到函数的日志，您将看到，每分钟，`函数执行开始`和相应的成功日志被列出，如下面的屏幕截图所示：

![图 2.43：函数日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_43.jpg)

###### 图 2.43：函数日志

正如您所看到的，云调度程序正在按计划调用函数，并且函数正在成功运行。

1.  从第 13 步返回到云调度程序页面，选择`HelloWorldEveryMinute`，在菜单上单击**删除**，然后在弹出窗口中确认，如下面的屏幕截图所示：![图 2.44：云调度程序-作业删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_44.jpg)

###### 图 2.44：云调度程序-作业删除

1.  从第 7 步返回到**Cloud Functions**页面，选择`HelloWorld`，在菜单上单击**删除**，然后在弹出窗口中确认，如下面的屏幕截图所示：![图 2.45：云函数-函数删除](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_45.jpg)

###### 图 2.45：云函数-函数删除

在这个练习中，我们创建了一个`Hello World`功能并将其部署到 GCF。此外，还创建了一个云调度程序作业，以特定的间隔触发该功能，比如每分钟一次。现在，该功能已连接到另一个云服务，以便该功能可以触发该服务。在选择云 FaaS 提供商之前，将功能与其他云服务集成并评估其集成能力是至关重要的。

在以下活动中，您将开发一个真实的每日站立提醒功能。您将连接一个您希望在特定站立会议时间调用的功能和功能触发服务。此外，这个提醒将发送一个特定的消息到一个基于云的协作工具，即*Slack*。

### 活动 2：Slack 每日站立会议提醒功能

这个活动的目的是在 Slack 中创建一个真实的站立会议提醒功能。这个提醒功能将在特定时间被调用，以提醒您团队中的每个人下一次站立会议。提醒将与 Slack 一起工作，因为它是一种受到全球许多组织采用的流行协作工具。

#### 注意

为了完成这个活动，您需要访问 Slack 的工作区。您可以在[`slack.com/create`](https://slack.com/create)免费使用现有的 Slack 工作区或创建一个新的。

完成后，您将部署每日站立提醒功能到 GCF，如下截图所示：

![图 2.46：每日提醒功能](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_46.jpg)

###### 图 2.46：每日提醒功能

此外，您还需要一个集成环境来在指定的会议时间调用该功能。站立会议通常在工作日的特定时间举行。因此，调度程序作业将被连接以根据您的会议时间触发您的功能，如下截图所示：

![图 2.47：每日提醒调度程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_47.jpg)

###### 图 2.47：每日提醒调度程序

最后，当调度程序调用该功能时，您将在 Slack 频道中收到提醒消息，如下截图所示：

![图 2.48：Slack 会议提醒消息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_02_48.jpg)

###### 图 2.48：Slack 会议提醒消息

#### 注意

为了完成这个活动，您应该按照 Slack 设置步骤配置 Slack。

**Slack 设置**

执行以下步骤配置 Slack：

1.  在 Slack 工作区中，点击您的用户名，然后选择自定义 Slack。

1.  在打开的窗口中点击**配置应用**。

1.  点击**浏览应用目录**以从目录中添加新应用。

1.  从**应用目录**的搜索框中找到**传入 WebHooks**。

1.  点击**添加配置**以添加**传入 WebHooks**应用。

1.  填写传入 Webhook 的配置，包括您特定的频道名称和图标。

1.  打开您的 Slack 工作区和频道。您会看到一个集成消息。

#### 注意

在第 376 页可以找到 Slack 设置步骤的详细截图。

执行以下步骤完成此活动：

1.  在 GCF 中创建一个新函数，在调用时调用 Slack Webhook。

代码应该向 Slack Webhook URL 发送一个类似的 JSON 请求对象：`{"text": "Time for a stand-up meeting"}`。您可以使用 GCF 支持的任何语言来实现代码。代码片段如下：

```
package p
import (
    "bytes"
    "net/http"
)
func Reminder(http.ResponseWriter, *http.Request) {
    url := "https://hooks.slack.com/services/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"

    var jsonStr = []byte('{"text": "Time for a stand-up meeting!"}')
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))

    client := &http.Client{}
    _, err = client.Do(req)
    if err != nil {
        panic(err)
    }
}
```

1.  在 GCP 中使用函数的触发 URL 创建一个调度程序作业，并根据您的站立会议时间指定调度。

在提醒消息的预定时间到达时，检查 Slack 频道。

1.  从云提供商中删除调度作业和函数。

#### 注意

此活动的解决方案可在第 376 页找到。

## 摘要

在本章中，我们描述了云技术产品的演变，包括云产品多年来的变化以及责任如何在组织之间分配，从 IaaS 和 PaaS 开始，最终到 FaaS。随后，介绍了评估无服务器云产品的标准。

编程语言支持、函数触发器和无服务器产品的成本结构被列出，以便我们可以比较各个云提供商，即 AWS Lambda、Azure Functions 和 GCF。此外，我们将无服务器函数部署到了所有三个云提供商。这展示了云函数如何与其他云服务集成，比如用于 REST API 操作的 AWS API Gateway。此外，我们部署了一个参数化函数到 Azure Functions，以展示我们如何处理来自用户或其他系统的输入。最后，我们部署了一个定时函数到 GCF，以展示与其他云服务的集成。在本章末尾，我们使用无服务器函数和云调度程序实现了一个真实的 Slack 提醒。

在下一章中，我们将介绍无服务器框架，并学习如何与它们一起工作。


# 第三章： 无服务器框架简介

## 学习目标

通过本章的学习，你将能够：

+   比较并有效地利用不同的无服务器函数

+   建立一个与云无关且容器本地的无服务器框架

+   使用 Fn 框架创建、部署和调用一个函数

+   使用无服务器框架将无服务器函数部署到云提供商

+   在未来在多个云平台上创建一个真实的无服务器应用程序并运行它

在本章中，我们将解释无服务器框架，使用这些框架创建我们的第一个无服务器函数，并将它们部署到各种云提供商。

## 介绍

让我们想象一下，你正在开发一个在一个云提供商中有许多函数的复杂应用程序。即使新的云提供商更便宜、更快或更安全，也可能无法迁移。这种供应商依赖的情况在行业中被称为**供应商锁定**，这在长期来看是一个非常关键的决策因素。幸运的是，无服务器框架是供应商锁定的一个简单而有效的解决方案。

在上一章中，讨论了所有三个主要的云提供商及其无服务器产品。这些产品是基于它们的编程语言支持、触发能力和成本结构进行比较的。然而，所有三个产品之间仍然存在一个看不见的关键差异：*运维*。在每个云提供商中，创建函数、部署它们以及它们的管理都是不同的。换句话说，你不能在 AWS Lambda、Google Cloud Functions 和 Azure Functions 中使用相同的函数。需要进行各种更改，以满足云提供商及其运行时的要求。

无服务器框架是用于运行无服务器应用程序的开源、与云无关的平台。云提供商和无服务器产品之间的第一个区别是，它们的无服务器框架是开源和公开的。它们可以免费安装在云上或本地系统上，并且可以独立运行。第二个特点是无服务器框架是与云无关的。这意味着可以在不同的云提供商或自己的系统上运行相同的无服务器函数。换句话说，函数将在哪个云提供商上执行只是无服务器框架中的一个配置参数。所有云提供商都在共享 API 后面被平等化，以便无服务器框架可以开发和部署与云无关的函数。

像 AWS Lambda 这样的云无服务器平台增加了无服务器架构的热度，并促进了其在行业中的采用。在前一章中，深入讨论了多年来云技术产品的演变和重要的云无服务器平台。在本章中，我们将讨论开源无服务器框架，并谈论它们的特色和功能。市场上有许多受欢迎的和即将推出的无服务器框架。然而，我们将重点关注两个在优先级和架构方面有所不同的杰出框架。在本章中，将介绍一个容器本地化的无服务器框架，即 Fn。随后，将深入讨论一个具有多个云提供商支持的更全面的框架，即 Serverless Framework。尽管这两个框架都为运行无服务器应用程序创建了一个与云无关且开源的环境，但它们在实施和开发者体验方面的差异将被说明。

## Fn 框架

Fn 是由 Oracle 在 2017 年的 JavaOne 2017 大会上宣布的，是一个面向事件驱动和开源的函数即服务（FaaS）平台。该框架的关键特点如下：

+   开源：Fn 项目的所有源代码都可以在[`github.com/fnproject/fn`](https://github.com/fnproject/fn)上公开获取，并且该项目托管在[`fnproject.io`](https://fnproject.io)上。它在 GitHub 上有一个活跃的社区，有超过 3300 次提交和 1100 次发布，如下面的截图所示：

![图 3.1：Fn 在 GitHub 上](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_01.jpg)

###### 图 3.1：Fn 在 GitHub 上

+   **容器本地：** 容器和微服务改变了软件开发和运维的方式。`Fn`是容器本地的，意味着每个函数都被打包并部署为 Docker 容器。此外，您可以创建自己的 Docker 容器并将其作为函数运行。

+   **语言支持：** 该框架正式支持**Go**，**Java**，**Node.js**，**Ruby**和**Python**。此外，**C#**由社区支持。

+   **与云无关：** 只要安装并运行 Docker，`Fn`就可以在每个云提供商或本地系统上运行。这是`Fn`最关键的特性，因为它完全避免了供应商锁定问题。如果函数不依赖于任何特定于云的服务，就可以快速在云提供商和本地系统之间移动。

作为一个与云无关和容器本地的平台，`Fn`是一个面向开发人员的框架。它增强了开发人员的体验和灵活性，因为您可以在本地开发、测试和调试，并使用相同的工具部署到云端。在接下来的练习中，我们将安装和配置`Fn`，以便开始使用该框架。

#### 注意

在开始下一个练习之前，您的计算机上应安装并运行 Docker `17.10.0-ce`或更高版本，因为这是`Fn`的先决条件。

### 练习 7：使用 Fn 框架入门

在这个练习中，您将在本地计算机上安装和配置一个与云无关和容器本地的无服务器框架。此练习的目的是演示配置和安装 Fn 框架是多么简单，以便您可以开始使用无服务器框架。

要成功完成此练习，我们需要确保执行以下步骤：

1.  在您的终端中，键入以下命令：

```
curl -LSs https://raw.githubusercontent.com/fnproject/cli/master/install | sh
```

此命令将下载并安装 Fn 框架。完成后，版本号将被打印出来，如下截图所示：

![图 3.2：Fn 的安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_02.jpg)

###### 图 3.2：Fn 的安装

1.  使用以下命令在您的终端中启动`Fn`服务器：

```
fn start -d
```

此命令将下载`Fn`服务器的 Docker 镜像，并在容器内启动，如下截图所示：

![图 3.3：启动 Fn 服务器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_03.jpg)

###### 图 3.3：启动 Fn 服务器

1.  使用以下命令在您的终端中检查客户端和服务器版本：

```
fn version
```

输出应如下所示：

![图 3.4：Fn 服务器和客户端版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_04.jpg)

###### 图 3.4：Fn 服务器和客户端版本

这个输出显示客户端和服务器端都在运行并相互交互。

1.  更新当前的 Fn 上下文并设置本地开发注册表：

```
fn use context default && fn update context registry serverless
```

输出如下截图所示：

![图 3.5：当前上下文的注册表设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_05.jpg)

###### 图 3.5：当前上下文的注册表设置

如输出所示，设置了`default`上下文，并将注册表更新为`serverless`。

1.  使用以下命令在终端中启动`Fn`仪表板：

```
docker run -d --link fnserver:api -p 4000:4000 -e "FN_API_URL=http://api:8080" fnproject/ui
```

这个命令下载`fnproject/ui`镜像并以`detached`模式启动。此外，它将`fnserver:api`链接到自身并发布`4000`端口，如下截图所示：

![图 3.6：启动 Fn UI](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_06.jpg)

###### 图 3.6：启动 Fn UI

1.  使用以下命令检查正在运行的 Docker 容器：

```
docker ps
```

如预期的那样，有两个运行中的`Fn`容器，分别使用镜像名称`fnproject/ui`和`fnproject/fnserver:latest`，如下截图所示：

![图 3.7：Docker 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_07.jpg)

###### 图 3.7：Docker 容器

1.  在浏览器中打开`http://localhost:4000`来检查 Fn UI。

Fn 仪表板列出了应用程序和函数统计信息，作为一个 web 应用程序，如下截图所示：

![图 3.8：Fn 仪表板](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_08.jpg)

###### 图 3.8：Fn 仪表板

通过这个练习，我们已经安装了`Fn`框架，以及它的客户端、服务器和仪表板。由于`Fn`是一个与云无关的框架，可以使用所示步骤安装任何云或本地系统。我们将继续讨论`Fn`框架，讨论函数如何配置和部署。

`Fn`框架设计用于处理应用程序，其中每个应用程序都是一组具有自己路由映射的函数。例如，假设您已将函数分组到一个文件夹中，如下所示：

```
- app.yaml
- func.yaml
- func.go
- go.mod
- products/
  - func.yaml
  - func.js
- suppliers/
  - func.yaml
  - func.rb
```

在每个文件夹中，都有一个`func.yaml`文件，用于定义对应的`Ruby`、`Node.js`或其他支持的语言的函数实现。此外，根文件夹中还有一个`app.yaml`文件用于定义应用程序。

让我们从检查`app.yaml`的内容开始：

```
name: serverless-app
```

`app.yaml`用于定义无服务器应用程序的根目录，并包括应用程序的名称。根文件夹中还有三个额外的文件用于函数：

+   `func.go`：Go 实现代码

+   `go.mod`：Go 依赖定义

+   `func.yaml`：函数定义和触发器信息

对于带有 HTTP 触发器和 Go 运行时的函数，定义了以下`func.yaml`文件：

```
name: serverless-app
version: 0.0.1
runtime: go
entrypoint: ./func
triggers:
- name: serverless-app
  type: http
  source: /serverless-app
```

当您将所有这些函数部署到 Fn 时，它们将通过以下 URL 可访问：

```
http://serverless-kubernetes.io/ 		-> root function
http://serverless-kubernetes.io/products 	-> function in products/ directory
http://serverless-kubernetes.io/suppliers 	-> function in suppliers/ directory
```

在下一个练习中，将用一个真实的例子来说明`app.yaml`和`func.yaml`文件的内容以及它们的函数实现。

### 练习 8：在 Fn 框架中运行函数

在这个练习中，我们的目标是使用`Fn`框架创建、部署和调用一个函数。

要成功完成这个练习，我们需要确保执行以下步骤：

1.  在您的终端中，运行以下命令来创建一个应用程序：

```
mkdir serverless-app
cd serverless-app
echo "name: serverless-app" > app.yaml
cat app.yaml
```

输出应该如下所示：

![图 3.9：创建应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_09.jpg)

###### 图 3.9：创建应用程序

这些命令创建一个名为`serverless-app`的文件夹，然后更改目录，使其位于此文件夹中。最后，创建一个名为`app.yaml`的文件，其中包含内容`name: serverless-app`，用于定义应用程序的根目录。

1.  在您的终端中运行以下命令，以创建一个在应用程序 URL 的`"/"`处可用的根函数：

```
fn init --runtime ruby --trigger http
```

该命令将在应用程序的根目录创建一个带有 HTTP 触发器的 Ruby 函数，如下面的屏幕截图所示：

![图 3.10：Ruby 函数创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_10.jpg)

###### 图 3.10：Ruby 函数创建

1.  使用以下命令在终端中创建一个子函数：

```
fn init --runtime go --trigger http hello-world
```

该命令在应用程序的`hello-world`文件夹中初始化一个带有 HTTP 触发器的 Go 函数，如下面的屏幕截图所示：

![图 3.11：Go 函数创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_11.jpg)

###### 图 3.11：Go 函数创建

1.  在终端中使用以下命令检查应用程序的目录：

```
ls -l ./*
```

该命令列出了根文件夹和子文件夹中的文件，如下面的屏幕截图所示：

![图 3.12：文件夹结构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_12.jpg)

###### 图 3.12：文件夹结构

如预期的那样，在根文件夹中有一个 Ruby 函数，包含三个文件：`func.rb`用于实现，`func.yaml`用于函数定义，`Gemfile`用于定义 Ruby 函数依赖。

同样，在`hello-world`文件夹中有一个 Go 函数，包含三个文件：`func.go`用于实现，`func.yaml`用于函数定义，`go.mod`用于 Go 依赖。

1.  使用以下命令在终端中部署整个应用程序：

```
fn deploy --create-app --all --local
```

此命令通过创建应用程序并使用本地开发环境部署所有函数，如下截图所示：

![图 3.13：应用程序部署到 Fn](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_13.jpg)

###### 图 3.13：应用程序部署到 Fn

首先，构建`serverless-app`的函数，然后创建函数和触发器。同样，构建并部署`hello-world`函数以及相应的函数和触发器。

1.  使用以下命令列出应用程序的触发器，并复制`serverless-app-trigger`和`hello-world-trigger`的`Endpoints`：

```
fn list triggers serverless-app
```

此命令列出了`serverless-app`的触发器，以及函数、类型、源和端点信息，如下截图所示：

![图 3.14：触发器列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_14.jpg)

###### 图 3.14：触发器列表

1.  使用以下命令在终端中触发端点：

#### 注意

对于`curl`命令，请不要忘记使用我们在*步骤 5*中复制的端点。

```
curl -d Ece http://localhost:8080/t/serverless-app/serverless-app
```

输出应该如下所示：

![图 3.15：调用 serverless-app 触发器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_15.jpg)

###### 图 3.15：调用 serverless-app 触发器

此命令将调用位于应用程序`root`处的`serverless-app`触发器。由于它是以`name`负载触发的，它会响应个人消息：`Hello Ece!`：

```
curl http://localhost:8080/t/serverless-app/hello-world
```

此命令将调用`hello-world`触发器，没有任何负载，如预期的那样，它会响应`Hello World`，如下截图所示：

![图 3.16：调用 hello-world 触发器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_16.jpg)

###### 图 3.16：调用 hello-world 触发器

1.  通过在浏览器中打开`http://localhost:4000`，从`Fn`仪表板中检查应用程序和函数统计信息。

在主屏幕上，可以看到您的应用程序及其整体统计信息，以及自动刷新的图表，如下截图所示：

![图 3.17：Fn 仪表板-主页](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_17.jpg)

###### 图 3.17：Fn 仪表板-主页

单击应用程序列表中的`serverless-app`以查看有关应用程序功能的更多信息，如下截图所示：

![图 3.18：Fn 仪表板-应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_18.jpg)

###### 图 3.18：Fn 仪表板-应用程序

1.  在终端中使用以下命令停止`Fn`服务器：

```
fn stop
```

此命令将停止`Fn`服务器，包括所有函数实例，如下截图所示：

![图 3.19：Fn 服务器停止](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_19.jpg)

###### 图 3.19：Fn 服务器停止

在本练习中，我们在`Fn`框架中创建了一个双函数应用程序并部署了它。我们向您展示了如何使用`fn`客户端将函数构建为 Docker 容器，并通过创建函数来调用函数的触发器。此外，还从`Fn`仪表板检查了函数的统计信息。作为一个面向容器的、与云无关的框架，该框架的函数是 Docker 容器，可以在任何云提供商或本地系统上运行。在下一节中，将介绍另一个无服务器框架，即**Serverless Framework**，它更专注于云提供商集成。

## Serverless Framework

Serverless Framework 在 2015 年以**JavaScript Amazon Web Services (JAWS)**的名字宣布。最初是在 Node.js 中开发的，以使人们更容易开发 AWS Lambda 函数。同年，它将名称更改为**Serverless Framework**，并将其范围扩大到其他云提供商和无服务器框架，包括**Google Cloud Functions**，**Azure Functions**，**Apache OpenWhisk**，**Fn**等等。

Serverless Framework 是开源的，其源代码可在 GitHub 上找到：[`github.com/serverless/serverless`](https://github.com/serverless/serverless)。如下截图所示，这是一个非常受欢迎的存储库，拥有超过 31,000 颗星：

![图 3.20：Serverless Framework GitHub 存储库](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_20.jpg)

###### 图 3.20：Serverless Framework GitHub 存储库

该框架的官方网站可在[`serverless.com`](https://serverless.com)上找到，并提供广泛的文档、用例和示例。Serverless Framework 的主要特点可以分为四个主要主题：

+   **与云无关**：Serverless Framework 旨在创建一个与云无关的无服务器应用程序开发环境，因此供应商锁定不是一个问题。

+   **可重用组件**：在 Serverless Framework 中开发的无服务器函数是开源的并可用。这些组件帮助我们快速创建复杂的应用程序。

+   **基础设施即代码**：在 Serverless Framework 中开发的所有配置和源代码都是明确定义的，并且可以通过单个命令部署。

+   **开发者体验**：Serverless Framework 旨在通过其 CLI、配置参数和活跃的社区来增强开发者体验。

Serverless Framework 的这四个特点使其成为创建云中无服务器应用程序最知名的框架。此外，该框架专注于管理无服务器应用程序的完整生命周期：

+   **开发**：可以在本地开发应用程序，并通过框架 CLI 重用开源插件。

+   **部署**：Serverless Framework 可以部署到多个云平台，并从开发到生产中推出和回滚版本。

+   **测试**：该框架支持使用命令行客户端函数直接测试函数。

+   **安全性**：该框架处理运行函数的秘密和部署的特定于云的身份验证密钥。

+   **监控**：无服务器应用程序的指标和日志可通过无服务器运行时和客户端工具获得。

在接下来的练习中，将使用 Serverless Framework 在 Docker 容器内创建、配置和部署一个无服务器应用程序到 AWS，以展示使用无服务器应用程序有多么容易。

#### 注意

Serverless Framework 可以通过`npm`下载并安装到本地计算机上。在接下来的练习中，将使用包含 Serverless Framework 安装的 Docker 容器，以便我们拥有快速且可重复的设置。

在接下来的练习中，将使用 Serverless Framework 将`hello-world`函数部署到 AWS Lambda。为了完成这个练习，您需要拥有一个活跃的亚马逊网络服务账户。您可以在[`aws.amazon.com/`](https://aws.amazon.com/)上创建一个账户。

### 练习 9：使用 Serverless Framework 运行函数

在这个练习中，我们的目标是配置 Serverless 框架并使用它部署我们的第一个函数。使用 Serverless 框架，可以创建与云无关的无服务器应用程序。在这个练习中，我们将把函数部署到 AWS Lambda。但是，也可以将相同的函数部署到不同的云提供商。

要成功完成这个练习，我们需要确保执行以下步骤：

1.  在你的终端中，运行以下命令启动 Serverless 框架开发环境：

```
docker run -it --entrypoint=bash onuryilmaz/serverless
```

该命令将以交互模式启动一个 Docker 容器。在接下来的步骤中，将在这个 Docker 容器内执行操作，如下截图所示：

![图 3.21：启动无服务器的 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_21.jpg)

###### 图 3.21：启动无服务器的 Docker 容器

1.  运行以下命令检查框架版本：

```
serverless version
```

该命令列出了框架、插件和 SDK 版本，并且完整的输出表明一切都设置正确，如下截图所示：

![图 3.22：框架版本](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_22.jpg)

###### 图 3.22：框架版本

1.  运行以下命令以交互方式使用框架：

```
serverless
```

按下**Y**创建一个新项目，并从下拉菜单中选择**AWS Node.js**，如下截图所示：

![图 3.23：在框架中创建一个新项目](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_23.jpg)

###### 图 3.23：在框架中创建一个新项目

1.  将项目名称设置为`hello-world`，然后按下**Enter**。输出如下：![图 3.24：成功创建项目](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_24.jpg)

###### 图 3.24：成功创建项目

1.  按下**Y**回答 AWS 凭证设置问题，然后再次按下**Y**回答**您是否有 AWS 账户？**的问题。输出如下：![图 3.25：AWS 账户设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_25.jpg)

###### 图 3.25：AWS 账户设置

现在你有一个用于创建无服务器用户的 URL。复制并保存这个 URL；我们以后会用到它。

1.  在浏览器中打开*步骤 4*中的 URL，并开始向 AWS 控制台添加用户。该 URL 将打开预定义选择的**添加用户**屏幕。点击屏幕末尾的**下一步：权限**，如下截图所示：![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_26.jpg)

###### 图 3.26：AWS 添加用户

1.  **AdministratorAccess**策略应该会自动选择。如下面的屏幕截图所示，单击屏幕底部的“下一步：标签”：![图 3.27：AWS 添加用户-权限](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_27.jpg)

###### 图 3.27：AWS 添加用户-权限

1.  如果您想要给用户打标签，您可以在此视图中添加可选标签。单击“下一步：审核”，如下面的屏幕截图所示：![图 3.28：AWS 添加用户-标签](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_28.jpg)

###### 图 3.28：AWS 添加用户-标签

1.  此视图显示了新用户的摘要。如下面的屏幕截图所示，单击“创建用户”：![图 3.29：AWS 添加用户-审核](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_29.jpg)

###### 图 3.29：AWS 添加用户-审核

您将被重定向到一个成功页面，显示**访问密钥 ID**和**秘密**，如下面的屏幕截图所示：

![图 3.30：AWS 添加用户-成功](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_30.jpg)

###### 图 3.30：AWS 添加用户-成功

1.  复制密钥 ID 和秘密访问密钥，以便您可以在本练习的后续步骤和本章的活动中使用它。您需要单击“显示”以显示秘密访问密钥。

1.  返回到您的终端并按**Enter**输入密钥 ID 和秘密信息，如下面的屏幕截图所示：![图 3.31：框架中的 AWS 凭据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_31.jpg)

###### 图 3.31：框架中的 AWS 凭据

1.  按下**Y**回答 Serverless 账户启用问题，并从下拉菜单中选择**注册**，如下面的屏幕截图所示：![图 3.32：Serverless 账户已启用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_32.jpg)

###### 图 3.32：Serverless 账户已启用

1.  输入您的电子邮件和密码以创建 Serverless 框架账户，如下面的屏幕截图所示：![图 3.33：Serverless 账户注册](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_33.jpg)

###### 图 3.33：Serverless 账户注册

1.  运行以下命令以更改目录并部署函数：

```
cd hello-world
serverless deploy -v 
```

这些命令将使 Serverless Framework 将函数部署到 AWS，如下面的屏幕截图所示：

![图 3.34：Serverless 框架部署输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_34.jpg)

###### 图 3.34：Serverless 框架部署输出

#### 注意

输出日志从打包服务和为源代码、工件和函数创建 AWS 资源开始。在创建了所有资源之后，“服务信息”部分将提供函数和 URL 的摘要。

在屏幕底部，您将找到部署函数的**无服务器仪表板 URL**，如下截图所示：

![图 3.35：堆栈输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_35.jpg)

###### 图 3.35：堆栈输出

复制仪表板 URL，以便在接下来的步骤中检查函数指标。

1.  使用以下命令在终端中调用函数：

```
 serverless invoke --function hello
```

此命令调用部署的函数并打印出响应，如下截图所示：

![图 3.36：函数输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_36.jpg)

###### 图 3.36：函数输出

如输出所示，`statusCode`为`200`，响应的正文表明函数已成功响应。

1.  在浏览器中打开您在第 8 步末尾复制的无服务器仪表板 URL，如下截图所示：![图 3.37：无服务器仪表板登录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_37.jpg)

###### 图 3.37：无服务器仪表板登录

1.  使用您在*步骤 5*中创建的电子邮件和密码登录。

您将被重定向到应用程序列表。展开**hello-world-app**并点击**成功部署**行，如下截图所示：

![图 3.38：无服务器仪表板应用程序列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_38.jpg)

###### 图 3.38：无服务器仪表板应用程序列表

在函数视图中，所有运行时信息，包括 API 端点、变量、警报和指标都可用。向下滚动以查看调用次数。输出应如下所示：

![图 3.39：无服务器仪表板函数视图](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_39.jpg)

###### 图 3.39：无服务器仪表板函数视图

由于我们只调用了函数一次，因此在图表中只会看到**1**。

1.  返回到您的终端，并使用以下命令删除函数：

```
serverless remove
```

此命令将删除部署的函数及其所有依赖项，如下截图所示：

![图 3.40：移除函数](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_40.jpg)

###### 图 3.40：移除函数

通过在终端中输入`exit`退出无服务器框架开发环境容器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_41.jpg)

###### 图 3.41：退出容器

在这个练习中，我们使用 Serverless Framework 创建、配置和部署了一个无服务器函数。此外，该函数是通过 CLI 调用的，并且可以从 Serverless Dashboard 检查其指标。Serverless Framework 为云提供商创建了一个全面的抽象，因此它只作为凭据传递给平台。换句话说，部署在哪里只是借助无服务器框架的帮助进行配置的问题。

在接下来的活动中，将开发一个真实的无服务器每日天气应用程序。您将创建一个带有调用计划的无服务器框架应用程序，并将其部署到云提供商。此外，天气状况消息将发送到一个名为*Slack*的基于云的协作工具。

#### 注意

为了完成接下来的活动，您需要能够访问 Slack 工作区。您可以使用现有的 Slack 工作区，也可以免费创建一个新的工作区，网址为[`slack.com/create`](https://slack.com/create)。

### 活动 3：Slack 的每日天气状况功能

本活动的目的是创建一个真实的无服务器应用程序，可以在特定的*Slack*频道中发送天气状况消息。该函数将使用**Serverless Framework**开发，以便将来可以在多个云平台上运行。该函数将被设计为在团队特定时间运行，以便他们了解天气状况，比如在早上上班前。这些消息将发布在*Slack*频道上，这是团队内的主要沟通工具。

为了获取天气状况以在团队内共享，您可以使用**wttr.in**（[`github.com/chubin/wttr.in`](https://github.com/chubin/wttr.in)），这是一个免费使用的天气数据提供商。完成后，您将已经将一个函数部署到了云提供商，即**AWS Lambda**：

![图 3.42：每日天气功能](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_42.jpg)

###### 图 3.42：每日天气功能

最后，当调度程序调用该函数，或者当您手动调用它时，您将在 Slack 频道中收到有关当前天气状况的消息：

![图 3.43：Slack 消息显示当前天气状况](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_03_43.jpg)

###### 图 3.43：Slack 消息显示当前天气状况

#### 注意

为了完成这个活动，您应该按照 Slack 设置步骤配置 Slack。

**Slack 设置**

执行以下步骤配置 Slack：

1.  在您的 Slack 工作区中，单击您的用户名，然后选择**自定义 Slack**。

1.  在打开的窗口中单击**配置应用程序**。

1.  单击**浏览应用程序目录**以从目录中添加新应用程序。

1.  在应用程序目录的搜索框中找到**传入 WebHooks**。

1.  单击**设置**以设置**传入 WebHooks**应用程序。

1.  使用您特定的频道名称和图标填写传入 Webhooks 的配置。

1.  打开您的 Slack 工作区和您在第 6 步中配置的频道，以便检查集成消息。

#### 注意

在第 387 页可以找到 Slack 设置步骤的详细截图。

执行以下步骤以完成此活动。

1.  在您的终端中，在名为`daily-weather`的文件夹中创建一个 Serverless Framework 应用程序结构。

1.  创建一个`package.json`文件来定义`daily-weather`文件夹中的 Node.js 环境。

1.  创建一个`handler.js`文件来实现`daily-weather`文件夹中的实际功能。

1.  为无服务器应用程序安装 Node.js 依赖项。

1.  将 AWS 凭据导出为环境变量。

1.  使用 Serverless Framework 将无服务器应用程序部署到 AWS。

1.  在 AWS 控制台中检查已部署函数的 AWS Lambda。

1.  使用 Serverless Framework 客户端工具调用函数。

1.  检查发布的天气状态的 Slack 频道。

1.  返回到您的终端并使用 Serverless Framework 删除函数。

1.  退出 Serverless Framework 开发环境容器。

#### 注意

此活动的解决方案可以在第 387 页找到。

## 摘要

在本章中，我们通过讨论云提供商的无服务器产品之间的差异，提供了无服务器框架的概述。在此之后，我们深入讨论了一个基于容器的原生框架和一个基于云的原生框架。首先讨论了`Fn`框架，这是一个开源的、基于容器的、与云无关的平台。其次介绍了 Serverless Framework，这是一个更加注重云和更全面的框架。此外，我们还在本地安装和配置了这两个框架。在两个无服务器框架中创建、部署和运行了无服务器应用程序。使用无服务器框架的功能进行调用，并检查必要的指标以进行进一步分析。在本章的最后，我们实现了一个真实的、每日天气 Slack 机器人，作为一个明确定义的、与云无关的应用程序，使用了无服务器框架。无服务器框架以其与云无关和开发者友好的特性，对无服务器开发世界至关重要。


# 第四章： Kubernetes 深入探讨

## 学习目标

到本章结束时，您将能够：

+   在计算机上设置本地 Kubernetes 集群

+   使用仪表板和终端访问 Kubernetes 集群

+   识别基本的 Kubernetes 资源，Kubernetes 应用程序的构建模块

+   在 Kubernetes 集群上安装复杂的应用程序

在本章中，我们将解释 Kubernetes 架构的基础知识，访问 Kubernetes API 的方法以及基本的 Kubernetes 资源。除此之外，我们还将在 Kubernetes 中部署一个真实的应用程序。

## Kubernetes 简介

在上一章中，我们学习了无服务器框架，使用这些框架创建了无服务器应用程序，并将这些应用程序部署到主要的云提供商。

正如我们在前几章中所看到的，Kubernetes 和无服务器架构在行业中开始同时受到关注。Kubernetes 以其基于可扩展性、高可用性和可移植性的设计原则获得了高度的采用，并成为事实上的容器管理系统。对于无服务器应用程序，Kubernetes 提供了两个基本的好处：**消除供应商锁定**和**服务的重复使用**。

Kubernetes 创建了一个基础设施抽象层，以消除供应商锁定。供应商锁定是指从一个服务提供商转移到另一个服务提供商非常困难甚至不可行的情况。在上一章中，我们学习了无服务器框架如何轻松开发与云无关的无服务器应用程序。假设您正在**AWS EC2**实例上运行您的无服务器框架，并希望迁移到**Google Cloud**。尽管您的无服务器框架在云提供商和无服务器应用程序之间创建了一层，但您仍然对基础设施的云提供商有很深的依赖。Kubernetes 通过在基础设施和云提供商之间创建一个抽象来打破这种联系。换句话说，在 Kubernetes 上运行的无服务器框架对基础设施一无所知。如果您的无服务器框架在 AWS 上运行 Kubernetes，则预计它也可以在**Google Cloud Platform**（**GCP**）或 Azure 上运行。

作为事实上的容器管理系统，Kubernetes 管理云中和本地系统中的大多数微服务应用程序。假设您已经将大型单体应用程序转换为云原生微服务，并在 Kubernetes 上运行它们。现在，您已经开始开发无服务器应用程序或将一些微服务转换为无服务器*纳米服务*。在这个阶段，您的无服务器应用程序将需要访问数据和其他服务。如果您可以在 Kubernetes 集群中运行您的无服务器应用程序，您将有机会重复使用服务并接近您的数据。此外，管理和操作微服务和无服务器应用程序将更容易。

作为解决供应商锁定问题，并为了数据和服务的潜在重复使用，学习如何在 Kubernetes 上运行无服务器架构至关重要。在本章中，将介绍 Kubernetes 的概述，介绍 Kubernetes 的起源和设计。接下来，我们将安装一个本地 Kubernetes 集群，您将能够通过仪表板或使用`kubectl`等客户端工具访问集群。除此之外，我们还将讨论 Kubernetes 应用程序的构建模块，最后，我们将在集群中部署一个真实的应用程序。

## Kubernetes 设计和组件

Kubernetes，也被称为**k8s**，是一个用于管理容器的平台。它是一个复杂的系统，专注于容器的完整生命周期，包括配置、安装、健康检查、故障排除和扩展。通过 Kubernetes，可以以可伸缩、灵活和可靠的方式运行微服务。假设您是一家金融科技公司的 DevOps 工程师，专注于为客户提供在线银行服务。

您可以以安全和云原生的方式配置和安装在线银行应用程序的完整后端和前端到 Kubernetes。通过 Kubernetes 控制器，您可以手动或自动地扩展服务，以满足客户需求。此外，您可以检查日志，对每个服务执行健康检查，甚至可以 SSH 到应用程序的容器中。

在本节中，我们将重点关注 Kubernetes 的设计以及其组件如何和谐地工作。

Kubernetes 集群由一个或多个服务器组成，每个服务器分配了一组逻辑角色。集群的服务器分配了两个基本角色：**master**和**node**。如果服务器处于**master**角色，则 Kubernetes 的控制平面组件运行在这些节点上。控制平面组件是用于运行 Kubernetes API 的主要服务集，包括 REST 操作、身份验证、授权、调度和云操作。在最新版本的 Kubernetes 中，有四个服务作为控制平面运行：

+   **etcd**：`etcd`是一个开源的键/值存储，它是所有 Kubernetes 资源的数据库。

+   **kube-apiserver**：API 服务器是运行 Kubernetes REST API 的组件。这是与飞机其他部分和客户端工具交互的最关键组件。

+   **kube-scheduler**：调度程序根据工作负载的要求和节点状态将工作负载分配给节点。

+   **kube-controller-manager**：`kube-controller-manager`是用于管理 Kubernetes 资源的核心控制器的控制平面组件。*控制器*是 Kubernetes 资源的主要生命周期管理器。对于每个 Kubernetes 资源，都有一个或多个控制器在*图 4.1*中的**观察**、**决策**和**执行**循环中工作。控制器在观察阶段检查资源的当前状态，然后分析并决定达到所需状态所需的操作。在执行阶段，它们执行操作并继续观察资源。![图 4.1：Kubernetes 中的控制器循环](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_01.jpg)

###### 图 4.1：Kubernetes 中的控制器循环

具有**node**角色的服务器负责在 Kubernetes 中运行工作负载。因此，每个节点都需要两个基本的 Kubernetes 组件：

+   **kubelet**：`kubelet`是节点中控制平面的管理网关。`kubelet`与 API 服务器通信并在节点上实施所需的操作。例如，当将新的工作负载分配给节点时，`kubelet`通过与容器运行时（如 Docker）交互来创建容器。

+   **kube-proxy**：容器在服务器节点上运行，但它们在统一的网络设置中相互交互。`kube-proxy`使容器能够通信，尽管它们在不同的节点上运行。

控制平面和角色（如主节点和工作节点）是组件的逻辑分组。然而，建议使用具有多个主节点角色服务器的高可用控制平面。此外，具有节点角色的服务器连接到控制平面，以创建可扩展和云原生环境。控制平面与主节点服务器和节点服务器的关系和交互如下图所示：

![图 4.2：Kubernetes 集群中的控制平面、主节点和节点服务器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_02.jpg)

###### 图 4.2：Kubernetes 集群中的控制平面、主节点和节点服务器

在接下来的练习中，将在本地创建一个 Kubernetes 集群，并检查 Kubernetes 组件。Kubernetes 集群是具有主节点或工作节点的服务器集合。在这些节点上，控制平面组件和用户应用程序以可扩展和高可用的方式运行。借助本地 Kubernetes 集群工具，可以创建用于开发和测试的单节点集群。`minikube`是官方支持和维护的本地 Kubernetes 解决方案，并将在接下来的练习中使用。

#### 注意：...]

在接下来的练习中，您将使用`minikube`作为官方本地 Kubernetes 解决方案，并在虚拟化程序上运行 Kubernetes 组件。因此，您必须安装虚拟化程序，如**Virtualbox**、**Parallels**、**VMWareFusion**、**Hyperkit**或**VMWare**。有关更多信息，请参阅此链接：

[`kubernetes.io/docs/tasks/tools/install-minikube/#install-a-hypervisor`](https://kubernetes.io/docs/tasks/tools/install-minikube/#install-a-hypervisor)

### 练习 10：启动本地 Kubernetes 集群

在本练习中，我们将安装`minikube`并使用它启动一个单节点 Kubernetes 集群。当集群启动并运行时，将可以检查主节点和节点组件。

为完成练习，需要确保执行以下步骤：

1.  在终端中运行以下命令将`minikube`安装到本地系统：

```
# Linux
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
# MacOS
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64 
chmod +x minikube 
sudo mv minikube /usr/local/bin
```

这些命令下载`minikube`的二进制文件，使其可执行，并将其移动到`bin`文件夹以供终端访问。

1.  通过运行以下命令启动`minikube`集群：

```
minikube start
```

此命令下载镜像并创建单节点虚拟机。随后，它配置该机器并等待 Kubernetes 控制平面启动，如下图所示：

![图 4.3：在 minikube 中启动新集群](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_03.jpg)

###### 图 4.3：在 minikube 中启动新集群

1.  检查 Kubernetes 集群的状态：

`minikube status`

如下图中的输出所示，主机系统、`kubelet`和`apiserver`正在运行：

![图 4.4：Kubernetes 集群状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_04.jpg)

###### 图 4.4：Kubernetes 集群状态

1.  通过运行以下命令连接到`minikube`的虚拟机：

```
minikube ssh
```

您应该看到以下图中显示的输出：

![图 4.5：minikube 虚拟机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_05.jpg)

###### 图 4.5：minikube 虚拟机

1.  使用以下命令检查四个控制平面组件：

```
pgrep -l etcd && pgrep -l kube-apiserver && pgrep -l kube-scheduler && pgrep -l controller
```

此命令列出进程并捕获所提到的命令名称。每个控制平面组件及其进程 ID 对应四行，如下图所示：

![图 4.6：控制平面组件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_06.jpg)

###### 图 4.6：控制平面组件

1.  使用以下命令检查节点组件：

```
pgrep -l kubelet && pgrep -l kube-proxy
```

此命令列出了在节点角色中运行的两个组件及其进程 ID，如下图所示：

![图 4.7：节点组件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_07.jpg)

###### 图 4.7：节点组件

1.  使用以下命令退出*步骤 4*中启动的终端：

```
exit
```

您应该看到以下图中显示的输出：

![图 4.8：退出 minikube 虚拟机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_08.jpg)

###### 图 4.8：退出 minikube 虚拟机

在本练习中，我们使用`minikube`安装了单节点 Kubernetes 集群。在下一节中，我们将讨论使用 Kubernetes 的官方客户端工具连接到并操作前面练习中的集群。

## Kubernetes 客户端工具：kubectl

Kubernetes 控制平面运行一个 REST API 服务器，用于访问 Kubernetes 资源和进行操作活动。Kubernetes 配备了一个名为`kubectl`的官方开源命令行工具，以便消费 REST API。它安装在本地系统上，并配置为安全可靠地连接远程集群。`kubectl`是 Kubernetes 中运行应用程序的完整生命周期的主要工具。例如，假设您在集群中部署了一个**WordPress**博客。首先，您可以使用`kubectl`创建数据库密码作为 secrets。然后，您部署博客应用程序并检查其状态。除此之外，您还可以跟踪应用程序的日志，甚至可以 SSH 到容器进行进一步分析。因此，它是一个强大的 CLI 工具，可以处理基本的**创建、读取、更新和删除（CRUD）**操作和故障排除。

除了应用程序管理外，`kubectl`还是集群操作的强大工具。可以使用`kubectl`检查 Kubernetes API 状态或集群中服务器的状态。假设您需要重新启动集群中的服务器，并且需要将工作负载移动到其他节点。使用`kubectl`命令，您可以将节点标记为*不可调度*，并让 Kubernetes 调度程序将工作负载移动到其他节点。完成维护后，您可以将节点标记为**Ready**，并让 Kubernetes 调度程序分配工作负载。

`kubectl`是日常 Kubernetes 操作的重要命令行工具。因此，学习基础知识并获得`kubectl`的实际经验至关重要。在接下来的练习中，您将安装和配置`kubectl`以连接到本地 Kubernetes 集群。

### 练习 11：使用客户端工具 kubectl 访问 Kubernetes 集群

在这个练习中，我们旨在使用`kubectl`访问 Kubernetes API 并探索其功能。

为了完成练习，我们需要确保执行以下步骤：

1.  通过在终端中运行以下命令下载`kubectl`可执行文件：

```
# Linux
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.15.0/bin/linux/amd64/kubectl
# MacOS
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.15.0/bin/darwin/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin
```

这些命令下载`kubectl`的二进制文件，使其可执行，并将其移动到`bin`文件夹以供终端访问。

1.  配置`kubectl`以连接到`minikube`集群：

```
kubectl config use-context minikube
```

此命令配置`kubectl`以使用`minikube`上下文，该上下文是用于连接到`kubectl`集群的一组凭据，如下图所示：

![图 4.9：kubectl 上下文设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_09.jpg)

###### 图 4.9：kubectl 上下文设置

1.  使用以下命令检查可用节点：

```
 kubectl get nodes
```

此命令列出了连接到集群的所有节点。作为单节点集群，只有一个名为`minikube`的节点，如下图所示：

![图 4.10：kubectl get nodes](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_10.jpg)

###### 图 4.10：kubectl get nodes

1.  使用以下命令获取有关`minikube`节点的更多信息：

`kubectl describe node minikube`

此命令列出有关节点的所有信息，从其元数据开始，例如`Roles`、`Labels`和`Annotations`。此节点的角色在**Roles**部分中被指定为`master`，如下图所示：

![图 4.11：节点元数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_11.jpg)

###### 图 4.11：节点元数据

在元数据之后，`Conditions` 列出了节点的健康状态。可以以表格形式检查可用内存、磁盘和进程 ID，如下图所示。

![图 4.12：节点条件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_12.jpg)

###### 图 4.12：节点条件

然后，列出可用和可分配的容量以及系统信息，如下图所示：

![图 4.13：节点容量信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_13.jpg)

###### 图 4.13：节点容量信息

最后，列出了节点上运行的工作负载和分配的资源，如下图所示：

![图 4.14：节点工作负载信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_14.jpg)

###### 图 4.14：节点工作负载信息

1.  使用以下命令获取支持的 API 资源：

```
kubectl api-resources -o name
```

您应该看到以下图中显示的输出：

![图 4.15：kubectl api-resources 的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_15.jpg)

###### 图 4.15：kubectl api-resources 的输出

此命令列出 Kubernetes 集群支持的所有资源。列表的长度表示了 Kubernetes 在应用程序管理方面的强大和全面性。在本练习中，安装、配置和探索了官方 Kubernetes 客户端工具。在接下来的部分中，将介绍资源列表中的核心构建块资源。

## Kubernetes 资源

Kubernetes 配备了丰富的资源来定义和管理云原生应用程序作为容器。在 Kubernetes API 中，每个容器、秘钥、配置或自定义定义都被定义为资源。控制平面管理这些资源，而节点组件则尝试实现应用程序的期望状态。期望状态可能是运行 10 个应用程序实例或者挂载磁盘卷到数据库应用程序。控制平面和节点组件协同工作，使集群中的所有资源达到其期望状态。

在本节中，我们将学习用于运行无服务器应用程序的基本 Kubernetes 资源。

### Pod

`pod`是 Kubernetes 中用于计算的基本资源。一个 pod 由安排在同一节点上运行的容器组成，作为单个应用程序。同一 pod 中的容器共享相同的资源，如网络和内存资源。此外，pod 中的容器共享生命周期事件，如扩展或缩减。可以使用`ubuntu`镜像和`echo`命令定义一个 pod，如下所示：

```
apiVersion: v1
kind: Pod
metadata:
 name: echo
spec:
 containers:
 - name: main
   image: ubuntu
   command: ['sh', '-c', 'echo Serverless World! && sleep 3600']
```

当在 Kubernetes API 中创建`echo` pod 时，调度程序将其分配给一个可用节点。然后，相应节点中的`kubelet`将创建一个容器并将网络连接到它。最后，容器将开始运行`echo`和`sleep`命令。Pod 是创建应用程序的基本 Kubernetes 资源，并且 Kubernetes 将它们用作更复杂资源的构建块。在接下来的资源中，pod 将被封装以创建更复杂的云原生应用程序。

### 部署

部署是管理高可用应用程序的最常用的 Kubernetes 资源。部署通过扩展 pod，使其能够进行扩展、缩减或者部署新版本。部署定义看起来类似于一个带有两个重要附加项的 pod：标签和副本。

考虑以下代码：

```
apiVersion: apps/v1
kind: Deployment
metadata:
 name: webserver
 labels:
   app: nginx
spec:
 replicas: 5
 selector:
   matchLabels:
     app: server
 template:
   metadata:
     labels:
       app: server
   spec:
     containers:
     - name: nginx
       image: nginx:1.7.9
       ports:
       - containerPort: 80 
```

名为`webserver`的部署定义了应用程序的五个`副本`，这些副本带有标签`app:server`。在`模板`部分，应用程序使用完全相同的标签和一个`nginx`容器进行定义。控制平面中的部署控制器确保集群内运行着这个应用程序的五个实例。假设你有三个节点，A、B 和 C，分别运行着一个、两个和两个 webserver 应用程序的实例。如果节点 C 下线，部署控制器将确保丢失的两个实例在节点 A 和 B 中重新创建。Kubernetes 确保可伸缩和高可用的应用程序作为部署可靠地运行。在接下来的部分中，将介绍用于有状态应用程序的 Kubernetes 资源，如数据库。

### 有状态集

Kubernetes 支持运行无状态的短暂应用程序和有状态的应用程序。换句话说，可以以可伸缩的方式在集群内运行数据库应用程序或面向磁盘的应用程序。`StatefulSet`的定义与部署类似，但有与卷相关的附加内容。

考虑以下代码片段：

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  selector:
    matchLabels:
      app: mysql
  serviceName: mysql
  replicas: 1
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
      - name: mysql
        image: mysql:5.7
        env:
        - name: MYSQL_ROOT_PASSWORD
          value: "root"
        ports:
        - name: mysql
          containerPort: 3306
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
          subPath: mysql
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 1Gi
```

`mysql` `StatefulSet`状态创建了一个带有 1GB 卷数据的 MySQL 数据库。卷是由 Kubernetes 创建并附加到容器的`/var/lib/mysql`目录。通过`StatefulSet`控制器，可以以可伸缩和可靠的方式创建需要磁盘访问的应用程序。在接下来的部分中，我们将讨论如何在 Kubernetes 集群中连接应用程序。

### 服务

在 Kubernetes 中，多个应用程序在同一个集群中运行并相互连接。由于每个应用程序在不同节点上运行着多个 pod，因此连接应用程序并不是一件简单的事情。在 Kubernetes 中，`Service`是用于定义一组 pod 的资源，并且可以通过`Service`的名称来访问它们。Service 资源是使用 pod 的标签来定义的。

考虑以下代码片段：

```
apiVersion: v1
kind: Service
metadata:
  name: my-database
spec:
  selector:
    app: mysql
  ports:
    - protocol: TCP
      port: 3306
      targetPort: 3306
```

使用`my-database`服务，具有标签`app: mysql`的 pod 被分组在一起。当调用`my-database`地址的`3306`端口时，Kubernetes 网络将连接到具有标签`app:mysql`的 pod 的`3306`端口。服务资源在应用程序之间创建了一个抽象层，并实现了解耦。假设您的应用程序中有三个后端实例和三个前端实例。前端 pod 可以使用`Service`资源轻松连接到后端实例，而无需知道后端实例运行在何处。它在集群中运行的应用程序之间创建了抽象和解耦。在接下来的部分中，将介绍关注任务和定时任务的资源。

### Job 和 CronJob

Kubernetes 资源，如`deployments`和`StatefulSets`，专注于运行应用程序并保持其运行。但是，Kubernetes 还提供了`Job`和`CronJob`资源来完成应用程序的运行。例如，如果您的应用程序需要执行一次性任务，可以创建一个`Job`资源，如下所示：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: echo
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: echo
        image: busybox
        args:
         - /bin/sh
         - -c
         - echo Hello from the echo Job!
```

当创建`echo` Job 时，Kubernetes 将创建一个 pod，对其进行调度并运行。当容器在执行`echo`命令后终止时，Kubernetes 不会尝试重新启动它或保持其运行。

除了一次性任务外，还可以使用`CronJob`资源来运行定时作业，如下面的代码片段所示。

```
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hourly-echo
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          restartPolicy: OnFailure
          - name: hello
            image: busybox
            args:
            - /bin/sh
            - -c
            - date; echo It is time to say echo!
```

使用`hourly-echo` CronJob，提供了一个额外的`schedule`参数。使用`"0 * * * *"`的计划，Kubernetes 将创建此 CronJob 的新 Job 实例，并每小时运行一次。Job 和 CronJob 是处理应用程序所需的手动和自动化任务的 Kubernetes 本机方式。在接下来的练习中，将使用`kubectl`和本地 Kubernetes 集群来探索 Kubernetes 资源。

### 练习 12：在 Kubernetes 内部安装有状态的 MySQL 数据库并进行连接

在这个练习中，我们将安装一个 MySQL 数据库作为`StatefulSet`，检查其状态，并使用一个用于创建表的作业连接到数据库。

要完成练习，我们需要确保执行以下步骤：

1.  在本地计算机上创建一个名为`mysql.yaml`的文件，并包含以下内容：

```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  selector:
    matchLabels:
      app: mysql
  serviceName: mysql
  replicas: 1
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
      - name: mysql
        image: mysql:5.7
        env:
        - name: MYSQL_ROOT_PASSWORD
          value: "root"
        - name: MYSQL_DATABASE
          value: "db"
        - name: MYSQL_USER
          value: "user"
        - name: MYSQL_PASSWORD
          value: "password"
        ports:
        - name: mysql
          containerPort: 3306
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
          subPath: mysql
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 1Gi
```

#### 注意

`mysql.yaml`可在 GitHub 上找到[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Exercise12/mysql.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Exercise12/mysql.yaml)。

1.  在终端中使用以下命令部署`StatefulSet` MySQL 数据库：

```
kubectl apply -f mysql.yaml
```

这个命令提交了`mysql.yaml`文件，其中包括一个名为`mysql`的`StatefulSet`和一个 1GB 的卷索赔。输出如下：

![图 4.16：StatefulSet 创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_16.jpg)

###### 图 4.16：StatefulSet 创建

1.  使用以下命令检查 pod：

`kubectl get pods`

这个命令列出了运行中的 pod，我们期望看到一个`mysql`实例，如下图所示：

![图 4.17：Pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_17.jpg)

###### 图 4.17：Pod 列表

#### 注意

如果 pod 状态为`Pending`，请等待几分钟直到变为`Running`，然后再继续下一步。

1.  使用以下命令检查持久卷：

```
kubectl get persistentvolumes
```

这个命令列出了持久卷，我们期望看到为`StatefulSet`创建的单卷实例，如下图所示：

![图 4.18：持久卷列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_18.jpg)

###### 图 4.18：持久卷列表

1.  使用以下内容创建`service.yaml`文件：

```
apiVersion: v1
kind: Service
metadata:
  name: my-database
spec:
  selector:
    app: mysql
  ports:
    - protocol: TCP
      port: 3306
      targetPort: 3306
```

#### 注意

`service.yaml`可在 GitHub 上找到[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Exercise12/service.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Exercise12/service.yaml)。

1.  使用以下命令在终端中部署`my-database`服务：

`kubectl apply -f service.yaml`

这个命令提交了名为`my-database`的`Service`，以便将标签为`app:mysql`的 pod 分组：

![图 4.19：服务创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_19.jpg)

###### 图 4.19：服务创建

1.  使用以下内容创建`create-table.yaml`文件：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: create-table
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: create
        image: mysql:5.7
        args:
         - /bin/sh
         - -c
         - mysql -h my-database -u user -ppassword db -e 'CREATE TABLE IF NOT EXISTS messages (id INT)';
```

#### 注意

`create-table.yaml`可在 GitHub 上找到[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Exercise12/create-table.yaml`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Exercise12/create-table.yaml)。

1.  使用以下命令部署作业：

```
kubectl apply -f create-table.yaml
```

此命令提交名为`create-table`的作业，并在几分钟内，将创建一个 pod 来运行`CREATE TABLE`命令，如下图所示：

![图 4.20：作业创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_20.jpg)

###### 图 4.20：作业创建

1.  使用以下命令检查 pod：

`kubectl get pods`

此命令列出正在运行的 pod，我们期望看到一个`create-table`的实例，如下图所示：

![图 4.21：Pod 清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_21.jpg)

###### 图 4.21：Pod 清单

#### 注意

如果 pod 状态为**Pending**或**Running**，请等待几分钟，直到它变为**Completed**，然后再继续下一步。

1.  运行以下命令来检查 MySQL 数据库中的表格：

```
kubectl run mysql-client --image=mysql:5.7 -i -t --rm --restart=Never \
-- mysql -h my-database -u user -ppassword  db -e "show tables;"
```

此命令运行一个临时实例的`mysql:5.7`镜像，并运行`mysql`命令，如下图所示：

![图 4.22：表格清单](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_22.jpg)

###### 图 4.22：表格清单

在 MySQL 数据库中，有一个名为`messages`的表格，如前面的输出所示。它显示`MySQL` `StatefulSet`已经成功运行数据库。此外，`create-table`作业已经创建了一个连接到数据库的 pod，并创建了表格。

1.  通过运行以下命令清理资源：

```
kubectl delete -f create-table.yaml,service.yaml,mysql.yaml
```

您应该看到下图所示的输出：

![图 4.23：清理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_23.jpg)

###### 图 4.23：清理

在接下来的活动中，数据库将被自动化任务在 Kubernetes 中检索到的信息填充。

#### 注意

在接下来的活动中，您将需要一个 Docker Hub 账户将图像推送到注册表中。Docker Hub 是一个免费的服务，您可以在[`hub.docker.com/signup`](https://hub.docker.com/signup)注册。

### 活动 4：在 Kubernetes 中收集 MySQL 数据库中的黄金价格

这个活动的目的是创建一个在 Kubernetes 集群中运行的真实无服务器应用程序，使用 Kubernetes 本地资源。无服务器函数将从实时市场获取黄金价格，并将数据推送到数据库。该函数将以预定义的间隔运行，以保留历史记录并进行统计分析。黄金价格可以从*CurrencyLayer* API 中检索，该 API 提供免费的汇率 API。完成后，您将拥有一个每分钟运行的 CronJob：

#### 注意

为了完成以下活动，您需要拥有 CurrencyLayer API 访问密钥。这是一个免费的货币和汇率服务，您可以在官方网站上注册。

![图 4.24：用于黄金价格的 Kubernetes 作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_24.jpg)

###### 图 4.24：用于黄金价格的 Kubernetes 作业

最后，每次运行 Kubernetes 作业时，您将在数据库中获得实时黄金价格：

![图 4.25：数据库中的价格数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/svls-arch-k8s/img/C12607_04_25.jpg)

###### 图 4.25：数据库中的价格数据

执行以下步骤来完成这个活动：

1.  创建一个应用程序，从*CurrencyLayer*检索黄金价格并将其插入到 MySQL 数据库中。可以在`main.go`文件中使用以下结构来实现这个功能：

```
//only displaying the function here//
func main() {
    db, err := sql.Open("mysql", ...
    r, err := http.Get(fmt.Sprintf(„http://apilayer.net/api/...
    stmt, err := db.Prepare("INSERT INTO GoldPrices(price) VALUES(?)")_,       err = stmt.Exec(target.Quotes.USDXAU)
    log.Printf("Successfully inserted the price: %v", target.Quotes.
USDXAU)
}
```

在`main`函数中，首先需要连接到数据库，然后从*CurrencyLayer*检索价格。然后需要创建一个 SQL 语句并在数据库连接上执行。main.go 的完整代码可以在这里找到：[`github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/main.go`](https://github.com/TrainingByPackt/Serverless-Architectures-with-Kubernetes/blob/master/Lesson04/Activity4/main.go)。

1.  将应用程序构建为 Docker 容器。

1.  将 Docker 容器推送到 Docker 注册表。

1.  将 MySQL 数据库部署到 Kubernetes 集群中。

1.  部署一个 Kubernetes 服务来暴露 MySQL 数据库。

1.  部署一个`CronJob`，每分钟运行一次。

1.  等待几分钟并检查`CronJob`的实例。

1.  连接到数据库并检查条目。

1.  从 Kubernetes 中清除数据库和自动化任务。

#### 注意

活动的解决方案可以在第 403 页找到。

## 总结

在本章中，我们首先描述了 Kubernetes 的起源和特点。接着，我们研究了 Kubernetes 的设计和组件，包括主控组件和节点组件的细节。然后，我们安装了一个本地单节点的 Kubernetes 集群，并检查了 Kubernetes 的组件。在集群设置之后，我们学习了官方的 Kubernetes 客户端工具`kubectl`，它用于连接到集群。我们还看到了`kubectl`如何用于管理集群和应用程序的生命周期。最后，我们讨论了用于无服务器应用程序的基本 Kubernetes 资源，包括 pod、部署和`StatefulSets`。除此之外，我们还学习了如何使用服务在集群中连接应用程序。使用`Jobs`和`CronJobs`来呈现一次性和自动化任务的 Kubernetes 资源。在本章的最后，我们使用 Kubernetes 本地资源开发了一个实时数据收集功能。

在下一章中，我们将学习 Kubernetes 集群的特性，并使用流行的云平台来部署它们。
