# Go 云原生编程（一）

> 原文：[`zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333`](https://zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

云计算和微服务是现代软件架构中非常重要的概念。它们代表了雄心勃勃的软件工程师需要掌握的关键技能，以便设计和构建能够执行和扩展的软件应用程序。Go 是一种现代的跨平台编程语言，非常强大而简单；它是微服务和云应用的绝佳选择。Go 正变得越来越受欢迎，成为一种非常有吸引力的技能。

本书将带您进入微服务和云计算的世界，借助 Go 语言。它将从涵盖云应用程序的软件架构模式开始，以及关于如何扩展、分发和部署这些应用程序的实际概念。从那里，本书将深入探讨编写生产级微服务及其在典型云环境中部署所需的技术和设计方法。

完成本书后，您将学会如何编写有效的生产级微服务，可以部署到云中，实际了解亚马逊云服务的世界，并知道如何构建非平凡的 Go 应用程序。

# 本书涵盖的内容

《现代微服务架构》第一章通过描述基于云的应用程序和微服务架构的典型特征来开启本书。我们还将为一个虚构的应用程序建立需求和高层架构，该应用程序将作为本书后续章节的持续示例。

第二章《使用 REST API 构建微服务》讨论了如何使用 Go 语言构建现代微服务。我们将涵盖重要且非平凡的主题。通过本章的学习，您将具备足够的知识来构建可以暴露 RESTFul API、支持持久性并能有效与其他服务通信的微服务。

第三章《保护微服务》向您展示如何保护您的微服务。您将学习如何在 Go 语言中处理证书和 HTTPS。

第四章《异步微服务架构》介绍了如何使用消息队列实现异步微服务架构。为此，我们将概述已建立的消息队列软件，如 RabbitMQ 和 Apache Kafka，并介绍 Go 库，以将这些组件集成到您的软件中。我们还将讨论与异步架构配合良好的事件协作和事件溯源等架构模式。

第五章《使用 React 构建前端》从 Go 世界稍微偏离，进入 JavaScript 世界，并向您展示如何使用 React 框架为基于微服务的项目构建 Web 前端。为此，我们将简要概述 React 的基本架构原则，以及如何为现有的 REST API 构建基于 React 的前端。

第六章《在容器中部署您的应用程序》展示了如何使用应用程序容器以便携和可重复的方式部署 Go 应用程序。您将学习安装和使用 Docker，以及如何为自己的 Go 应用程序构建自定义 Docker 镜像。此外，我们还将描述如何使用 Kubernetes 编排引擎在大规模云环境中部署容器化应用程序。

第七章《AWS - 基础知识，AWS Go SDK 和 AWS EC2》是两章中的第一章，涵盖了 AWS 生态系统。在本章中，我们将详细介绍 AWS。您将接触到一些重要的概念，比如如何设置 AWS 服务器实例，如何利用 AWS API 功能，以及如何编写能够与 AWS 交互的 Go 应用程序。

第八章，“AWS – S3、SQS、API Gateway 和 DynamoDB”，继续更详细地介绍了 AWS 生态系统。您将深入了解 AWS 世界中的热门服务。通过本章结束时，您将具备足够的知识，能够利用亚马逊云服务的功能构建非平凡的 Go 云应用程序。

第九章，“持续交付”，描述了如何为 Go 应用程序实现基本的持续交付流水线。为此，我们将描述持续交付的基本原则，以及如何使用 Travis CI 和 Gitlab 等工具实现简单的流水线。我们将使用 Docker 镜像作为部署工件，并将这些镜像部署到 Kubernetes 集群中，从而构建在第四章，“异步微服务架构”中涵盖的主题和技能基础上。

第十章，“监控您的应用程序”，向您展示了如何使用 Prometheus 和 Grafana 监控您的微服务架构。我们将介绍 Prometheus 的基本架构，并描述如何使用 Docker 设置 Prometheus 实例。此外，您还将学习如何调整您的 Go 应用程序以公开可以被 Prometheus 抓取的指标。我们还将描述如何使用 Grafana 为 Prometheus 设置图形用户界面。

第十一章，“迁移”，涵盖了从传统的单片应用程序迁移到现代微服务云应用程序时需要考虑的实际因素和方法。

第十二章，“下一步该去哪里？”，向您展示了从这里继续学习旅程的方向。它将涵盖其他现代与云相关的技术，值得探索，比如替代通信协议、其他云提供商，以及可能成为下一个大事件的新架构范式。

# 本书所需内容

对于本书，您应该具备一些 Go 编程语言的基本知识（如果您仍在寻求开始学习 Go，我们可以推荐 Packt 出版的 Vladimir Vivien 的书《学习 Go 编程》）。为了运行本书提供的代码示例，您还需要在本地计算机上安装一个可用的 Go SDK（Go 1.7 或更新版本）。请前往[`golang.org/dl/`](https://golang.org/dl/)获取下载和安装说明。

在本书的许多实际示例中，您将需要一个可用的 Docker 安装（尽管不需要有使用 Docker 的先前经验）。请查看[`www.docker.com/community-edition`](https://www.docker.com/community-edition)获取下载和安装说明。

在第五章，“使用 React 构建前端”，您还需要一些基本的 JavaScript 编程知识，以及本地计算机上安装的 Node.JS。您可以从[`nodejs.org/en/#download`](https://nodejs.org/en/#download)下载当前版本的 Node.JS。

# 本书的目标读者

本书面向希望构建安全、弹性、健壮和可扩展云原生应用程序的 Go 开发人员。一些关于 Web 服务和 Web 编程的知识应该足以帮助您完成本书。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄都显示如下：“`react-router-dom`包为我们的应用程序添加了一些新组件。”

代码块设置如下：

```go
import * as React from "react"; 
import {Link} from "react-router-dom"; 

export interface NavigationProps { 
  brandName: string; 
} 

export class Navigation extends React.Component<NavigationProps, {}> { 
} 
```

任何命令行输入或输出都将如下所示：

```go
$ npm install --save react-router-dom
$ npm install --save-dev @types/react-router-dom
```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，就像这样：“为此，请在登录后点击“创建存储库”，并为您的图像选择一个新名称。”

警告或重要提示会以这样的方式出现在框中。

提示和技巧会以这样的方式出现。


# 第一章：现代微服务架构

在计算和软件领域，我们几乎每周都会听到许多新的、酷炫的技术和框架。有些技术会留存并持续发展，而其他一些则无法经受时间的考验而消失。毫无疑问，云计算非常舒适地属于前一类。我们生活在一个云计算几乎支配着一切需要严肃的后端计算能力的世界，从检查冰箱温度的物联网设备到向你展示多人游戏中实时得分与同伴相比较的视频游戏。

云计算使遍布全球的大型企业以及在咖啡店写代码的两个人的小型初创公司受益匪浅。有大量的材料解释了为什么云计算对现代信息技术如此重要。为了效率起见，我们将直接回答这个问题，而不会列出长长的要点、图表和冗长的段落。对于企业来说，一切都是为了赚钱和节省成本。云计算显著降低了大多数组织的成本。这是因为云计算节省了建立自己数据中心的成本。不需要购买昂贵的硬件，也不需要委托昂贵的带有花哨空调系统的建筑。此外，几乎所有的云计算服务都可以让你只支付你使用的部分。云计算还为软件工程师和 IT 管理员提供了巨大的灵活性，使他们能够快速高效地完成工作，从而实现开发人员的幸福和增加生产力。

在本章中，我们将涵盖以下主题：

+   云原生应用的设计目标，尤其是可扩展性

+   不同的云服务模型

+   十二要素应用

+   微服务架构

+   通信模式，尤其是同步与异步通信

# 为什么选择 Go？

Go（或 Golang）是一种相对较新的编程语言，正在以其独特之处席卷软件开发世界。它是由谷歌开发的，旨在简化其后端软件服务的构建。然而，现在许多企业和初创公司都在使用它来编写强大的应用程序。Go 的独特之处在于，它从头开始构建，旨在提供与 C/C++等非常强大的语言竞争的性能，同时支持类似 JavaScript 等动态语言的相对简单的语法。Go 运行时提供垃圾回收；但它不依赖虚拟机来实现。Go 程序被编译成本机代码。在调用 Go 编译器时，你只需选择构建时希望二进制文件在哪个平台（Windows、Mac 等）上运行。编译器将会生成适用于该平台的单个二进制文件。这使得 Go 能够进行交叉编译并生成本机二进制文件。

Go 语言非常适合微服务架构，这在未来会变得非常普遍。微服务架构是一种架构，其中你将应用程序的责任分配给只专注于特定任务的较小服务。这些服务可以相互通信，以获取它们需要产生结果的信息。

Go 是一种新的编程语言，是在云计算时代开发的，考虑了现代软件技术。由于 Go 程序大多编译为单个二进制文件，使得在生产环境中几乎不需要依赖和虚拟机，因此 Go 被优化用于便携式微服务架构。Go 也是容器技术的先驱。**Docker**，软件容器的顶级名称，就是用 Go 编写的。由于 Go 的流行，主要云提供商以及第三方贡献者正在努力确保 Go 获得其在不同云平台所需的 API 支持。

本书的目标是在 Go 编程语言和现代计算的云技术之间建立知识桥梁。在本书中，您将获得关于 Go 微服务架构、消息队列、容器、云平台 Go API、SaaS 应用程序设计、监控云应用程序等方面的实际知识。

# 基本设计目标

为了充分利用现代云平台的优势，我们在开发应用程序时需要考虑其特性属性。

云应用程序的主要设计目标之一是**可扩展性**。一方面，这意味着根据需要增加应用程序的资源，以有效地为所有用户提供服务。另一方面，它还意味着在不再需要这些资源时将资源缩减到适当的水平。这使您能够以成本效益的方式运行应用程序，而无需不断地为高峰工作负载进行过度配置。

为了实现这一点，典型的云部署通常使用托管应用程序的小型虚拟机实例，并通过添加（或移除）更多这些实例来进行扩展。这种扩展方法称为**水平扩展**或**横向扩展**，与**垂直扩展**或**纵向扩展**相对应，后者不增加实例数量，而是为现有实例提供更多资源。出于几个原因，水平扩展通常优于垂直扩展。首先，水平扩展承诺无限的线性可扩展性。另一方面，由于现有服务器可以添加的资源数量不能无限增长，垂直扩展存在其限制。其次，水平扩展通常更具成本效益，因为您可以使用廉价的通用硬件（或在云环境中使用较小的实例类型），而较大的服务器通常会呈指数增长地更加昂贵。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0d2cad23-ebf1-486b-8494-78877ecf4fff.png)

水平扩展与垂直扩展；前者通过添加更多实例并在它们之间平衡工作负载来工作，而后者通过向现有实例添加更多资源来工作

所有主要的云提供商都提供根据应用程序当前资源利用率自动执行水平扩展的能力。这个功能称为**自动扩展**。不幸的是，您并不能免费获得水平扩展。为了能够进行扩展，您的应用程序需要遵循一些非常重要的设计目标，这些目标通常需要从一开始就考虑，如下所示：

+   **无状态性**：云应用程序的每个实例都不应该有任何内部状态（这意味着任何类型的数据都保存在内存中或文件系统上以备后用）。在扩展场景中，后续请求可能由应用程序的另一个实例提供服务，因此必须不依赖于之前请求中存在任何状态。为了实现这一点，通常需要将任何类型的持久存储（如数据库和文件系统）外部化。数据库服务和文件存储通常由您在应用程序中使用的云提供商作为托管服务提供。

当然，这并不意味着你不能将有状态的应用部署到云上。它们只是会更难以扩展，阻碍你充分利用云计算环境。

+   **部署简便性**：在扩展时，您需要快速部署应用程序的新实例。创建新实例不应该需要任何手动设置，而应尽可能自动化（理想情况下完全自动化）。

+   **弹性**：在云环境中，特别是在使用自动扩展时，实例可能会在瞬间被关闭。此外，大多数云服务提供商不保证单个实例的极高可用性（并建议进行扩展，可选地跨多个可用区）。因此，终止和突然死亡（无论是有意的，例如自动扩展，还是无意的，例如故障）是我们在云环境中始终需要预期的事情，应用程序必须相应地处理。

实现这些设计目标并不总是容易的。云服务提供商通常通过提供托管服务（例如高度可扩展的数据库服务或分布式文件存储）来支持您完成这项任务，否则您将不得不自己担心这些问题。关于您的实际应用程序，有**十二要素应用**方法论（我们将在后面的部分详细介绍），它描述了构建可扩展和有弹性的应用程序的一套规则。

# 云服务模型

在云计算提供中，有三种主要的服务模型可供您考虑：

+   **IaaS**（**基础设施即服务**）：这是云服务提供商为您提供云上基础设施的模型，例如服务器（虚拟和裸金属）、网络、防火墙和存储设备。当您只需要云提供商为您管理基础设施并摆脱维护的麻烦和成本时，您可以使用 IaaS。创业公司和希望对应用程序层拥有完全控制的组织使用 IaaS。大多数 IaaS 提供都带有动态或弹性扩展选项，根据您的消耗来扩展您的基础设施。这实际上可以节省组织的成本，因为他们只支付他们使用的部分。

+   **PaaS**（**平台即服务**）：这是从 IaaS 上一层的服务。PaaS 提供了您运行应用程序所需的计算平台。PaaS 通常包括您开发应用程序所需的操作系统、数据库、Web 层（如果需要）和编程语言执行环境。使用 PaaS，您不必担心应用程序环境的更新和补丁；这些都由云服务提供商来处理。假设您编写了一个强大的.NET 应用程序，希望在云中运行。PaaS 解决方案将提供您运行应用程序所需的.NET 环境，结合 Windows 服务器操作系统和 IIS Web 服务器。它还将负责大型应用程序的负载平衡和扩展。想象一下，通过采用 PaaS 平台而不是在内部进行努力，您可以节省多少金钱和精力。

+   **SaaS**（**软件即服务**）：这是作为云解决方案可以获得的最高层。SaaS 解决方案是指通过网络交付的完全功能的软件。您可以从 Web 浏览器访问 SaaS 解决方案。SaaS 解决方案通常由软件的普通用户使用，而不是程序员或软件专业人员。一个非常著名的 SaaS 平台的例子是 Netflix——一个复杂的软件，托管在云中，可以通过网络访问。另一个流行的例子是 Salesforce。Salesforce 解决方案通过 Web 浏览器以速度和效率交付给客户。

# 云应用架构模式

通常，在云环境中开发应用程序并不比常规应用程序开发有太大的不同。然而，在针对云环境时，有一些特别常见的架构模式，你将在下一节中学到。

# 十二要素应用

十二要素应用方法论是一组用于构建可扩展和具有弹性的云应用程序的规则。它由 Heroku 发布，是主要的 PaaS 提供商之一。然而，它可以应用于各种云应用程序，独立于具体的基础设施或平台提供商。它也独立于编程语言和持久化服务，并且同样适用于 Go 编程和例如 Node.js 编程。十二要素应用方法论描述了（不出所料的）十二个因素，你应该在应用程序中考虑这些因素，以便它易于扩展、具有弹性并且独立于平台。你可以在[`12factor.net`](https://12factor.net/)上阅读每个因素的完整描述。在本书中，我们将重点介绍一些我们认为特别重要的因素：

+   **因素 II：依赖-明确声明和隔离依赖**：这个因素值得特别提及，因为在 Go 编程中它实际上并不像在其他语言中那么重要。通常，云应用程序不应该依赖于系统上已经存在的任何必需的库或外部工具。依赖应该被明确声明（例如，使用 Node.js 应用程序的 npm `package.json`文件），这样一个包管理器在部署应用程序的新实例时可以拉取所有这些依赖。在 Go 中，一个应用程序通常部署为一个已经包含所有必需库的静态编译二进制文件。然而，即使是一个 Go 应用程序也可能依赖于外部系统工具（例如，它可以调用像 ImageMagick 这样的工具）或现有的 C 库。理想情况下，你应该将这些工具与你的应用程序一起部署。这就是容器引擎（如 Docker）的优势所在。

+   **因素 III：配置-在环境中存储配置**：配置是可能因不同部署而变化的任何类型的数据，例如外部服务和数据库的连接数据和凭据。这些类型的数据应该通过环境变量传递给应用程序。在 Go 应用程序中，获取这些数据就像调用`os.Getenv("VARIABLE_NAME")`一样简单。在更复杂的情况下（例如，当你有许多配置变量时），你也可以使用诸如`github.com/tomazk/envcfg`或`github.com/caarlos0/env`这样的库。对于繁重的工作，你可以使用`github.com/spf13/viper`库。

+   **因素 IV：后备服务-将后备服务视为附加资源**：确保应用程序依赖的服务（如数据库、消息系统或外部 API）可以通过配置轻松替换。例如，你的应用程序可以接受一个环境变量，比如`DATABASE_URL`，它可能包含`mysql://root:root@localhost/test`用于本地开发部署，以及`mysql://root:XXX@prod.XXXX.eu-central-1.rds.amazonaws.com`用于生产环境设置。

+   **因素 VI：进程-将应用程序作为一个或多个无状态进程执行**：运行应用程序实例应该是无状态的；任何需要持久化超出单个请求/事务的数据都需要存储在外部持久化服务中。

在构建可扩展和具有弹性的云应用程序时，有一个重要的案例需要牢记，那就是 Web 应用程序中的用户会话。通常，用户会话数据存储在进程的内存中（或者持久化到本地文件系统），期望同一用户的后续请求将由应用程序的同一实例提供。相反，尝试保持用户会话无状态，或者将会话状态移入外部数据存储，比如 Redis 或 Memcached。

+   **第九因素：可处置性-通过快速启动和优雅关闭最大限度地提高鲁棒性：**在云环境中，需要预期突然终止（无论是有意的，例如在缩减规模的情况下，还是无意的，在失败的情况下）。十二因素应用程序应具有快速的启动时间（通常在几秒钟的范围内），使其能够快速部署新实例。此外，快速启动和优雅终止是另一个要求。当服务器关闭时，操作系统通常会通过发送**SIGTERM**信号告诉您的应用程序关闭，应用程序可以捕获并做出相应反应（例如，停止监听服务端口，完成当前正在处理的请求，然后退出）。

+   **第十一因素：日志-将日志视为事件流：**日志数据通常用于调试和监视应用程序的行为。但是，十二因素应用程序不应关心其自己日志数据的路由或存储。最简单的解决方案是将日志流写入进程的标准输出流（例如，只需使用`fmt.Println(...)`）。将事件流式传输到`stdout`允许开发人员在开发应用程序时简单地观看事件流。在生产环境中，您可以配置执行环境以捕获进程输出并将日志流发送到可以处理的地方（这里的可能性是无限的-您可以将它们存储在服务器的**journald**中，将它们发送到 syslog 服务器，将日志存储在 ELK 设置中，或将它们发送到外部云服务）。

# 什么是微服务？

当一个应用程序在较长时间内由许多不同的开发人员维护时，它往往会变得越来越复杂。错误修复、新的或变化的需求以及不断变化的技术变化导致您的软件不断增长和变化。如果不加控制，这种软件演变将导致您的应用程序变得更加复杂和越来越难以维护。

防止这种软件侵蚀的目标是过去几年中出现的微服务架构范式。在微服务架构中，软件系统被分割成一组（可能很多）独立和隔离的服务。这些作为单独的进程运行，并使用网络协议进行通信（当然，这些服务中的每一个本身都应该是一个十二因素应用程序）。有关该主题的更全面介绍，我们可以推荐 Lewis 和 Fowler 在[`martinfowler.com/articles/microservices.html`](https://martinfowler.com/articles/microservices.html)上关于微服务架构的原始文章。

与传统的面向服务的架构（SOA）相比，这种架构已经存在了相当长的时间，微服务架构注重简单性。复杂的基础设施组件，如 ESB，应尽一切可能避免，而复杂的通信协议，如 SOAP，更倾向于更简单的通信方式，如 REST Web 服务（关于这一点，您将在第二章中了解更多，*使用 Rest API 构建微服务*）或 AMQP 消息传递（参见第四章，*使用消息队列的异步微服务架构*）。

将复杂软件拆分为单独的组件有几个好处。例如，不同的服务可以构建在不同的技术堆栈上。对于一个服务，使用 Go 作为运行时和 MongoDB 作为持久层可能是最佳选择，而对于其他组件，使用 Node.js 运行时和 MySQL 持久层可能是更好的选择。将功能封装在单独的服务中允许开发团队为正确的工作选择正确的工具。在组织层面上，微服务的其他优势是每个微服务可以由组织内的不同团队拥有。每个团队可以独立开发、部署和操作他们的服务，使他们能够以非常灵活的方式调整他们的软件。

# 部署微服务

由于它们专注于无状态和水平扩展，微服务与现代云环境非常匹配。然而，选择微服务架构时，总体上部署应用程序将变得更加复杂，因为您将需要部署更多不同的应用程序（这更加坚定了坚持十二要素应用程序方法论的理由）。

然而，每个单独的服务将比一个大型的单体应用程序更容易部署。根据服务的大小，将更容易将服务升级到新的运行时，或者完全替换为新的实现。此外，您可以单独扩展每个微服务。这使您能够在保持使用较少的组件成本高效的同时，扩展应用程序中使用频繁的部分。当然，这要求每个服务都支持水平扩展。

部署微服务在不同服务使用不同技术时变得更加复杂。现代容器运行时（如 Docker 或 RKT）提供了这个问题的一个可能解决方案。使用容器，您可以将应用程序及其所有依赖项打包到一个容器映像中，然后使用该映像快速生成一个在任何可以运行 Docker（或 RKT）容器的服务器上运行您的应用程序的容器。（让我们回到十二要素应用程序——在容器中部署应用程序是**要素 II**规定的依赖项隔离的最彻底解释之一。）

许多主要云提供商（如 AWS 的**弹性容器服务**、**Azure 容器服务**或**Google 容器引擎**）提供运行容器工作负载的服务。除此之外，还有容器编排引擎，如**Docker Swarm**、**Kubernetes**或**Apache Mesos**，您可以在 IaaS 云平台或自己的硬件上部署。这些编排引擎提供了在整个服务器集群上分发容器工作负载的可能性，并提供了非常高的自动化程度。例如，集群管理器将负责在任意数量的服务器上部署容器，根据它们的资源需求和使用自动分发它们。许多编排引擎还提供自动扩展功能，并且通常与云环境紧密集成。

您将在第六章中了解有关使用 Docker 和 Kubernetes 部署微服务的更多信息，*在容器中部署您的应用程序*。

# REST 网络服务和异步消息

在构建微服务架构时，您的各个服务需要相互通信。微服务通信的一个被广泛接受的事实标准是 RESTful 网络服务（关于这一点，您将在第二章和第三章中了解更多，*使用 Rest API 构建微服务*和*保护微服务*）。这些通常建立在 HTTP 之上（尽管 REST 架构风格本身更多或多少是协议独立的），并遵循请求/回复通信模型的客户端/服务器模型。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ee12981f-07fd-4efe-b986-a5914fb37798.png)

同步与异步通信模型

这种架构通常易于实现和维护。它适用于许多用例。然而，同步请求/响应模式在实现跨多个服务的复杂流程的系统时可能会受到限制。考虑前图的第一部分。在这里，我们有一个用户服务，管理应用程序的用户数据库。每当创建新用户时，我们需要确保系统中的其他服务也知道这个新用户。使用 RESTful HTTP，用户服务需要通过 REST 调用通知其他服务。这意味着用户服务需要知道所有其他受用户管理领域影响的服务。这导致组件之间的紧耦合，这通常是您希望避免的。

可以解决这些问题的另一种通信模式是发布/订阅模式。在这里，服务发出其他服务可以监听的事件。发出事件的服务不需要知道哪些其他服务实际上正在监听这些事件。再次考虑前图的第二部分—在这里，用户服务发布一个事件，说明刚刚创建了一个新用户。其他服务现在可以订阅此事件，并在创建新用户时得到通知。这些架构通常需要使用一个特殊的基础设施组件：消息代理。该组件接受发布的消息并将其路由到其订阅者（通常使用队列作为中间存储）。

发布/订阅模式是一种非常好的方法，可以将服务解耦—当一个服务发布事件时，它不需要关心它们将去哪里，当另一个服务订阅事件时，它也不知道它们来自哪里。此外，异步架构往往比同步通信更容易扩展。通过将消息分发给多个订阅者，可以轻松实现水平扩展和负载平衡。

不幸的是，没有免费的午餐；这种灵活性和可伸缩性是以额外的复杂性为代价的。此外，跨多个服务调试单个事务变得困难。是否接受这种权衡需要根据具体情况进行评估。

在第四章中，*使用消息队列的异步微服务架构*，您将了解更多关于异步通信模式和消息代理的信息。

# MyEvents 平台

在本书中，我们将构建一个名为*MyEvents*的有用的 SaaS 应用程序。MyEvents 将利用您将学习的技术，成为一个现代、可扩展、云原生和快速的应用程序。MyEvents 是一个活动管理平台，允许用户预订世界各地的活动门票。使用 MyEvents，您将能够为自己和同伴预订音乐会、嘉年华、马戏团等活动的门票。MyEvents 将记录预订、用户和活动举办地的不同位置。它将有效地管理您的预订。

我们将利用微服务、消息队列、ReactJS、MongoDB、AWS 等技术构建 MyEvents。为了更好地理解应用程序，让我们来看看我们的整体应用程序将要管理的逻辑实体。它们将由多个微服务管理，以建立明确的关注点分离，并实现我们需要的灵活性和可伸缩性：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/86218de4-5f52-4787-b4ae-da6793c91daa.png)

我们将有多个用户；每个**用户**可以为事件预订多次，每个**预订**将对应一个**事件**。对于我们的每一个事件，都会有一个**位置**，事件发生的地方。在**位置**内，我们需要确定事件发生的**大厅**或房间。

现在，让我们来看看微服务架构和构成我们应用程序的不同组件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0b450d72-d8b9-4a62-9d7a-e8ee0ef54b28.png)

微服务架构

我们将使用 ReactJS 前端与我们应用程序的用户进行交互。ReactJS UI 将使用 API 网关（AWS 或本地）与构成我们应用程序主体的不同微服务进行通信。有两个主要的微服务代表了 MyEvents 的逻辑：

+   **事件服务**：这是处理事件、它们的位置以及发生在它们身上的变化的服务

+   **预订服务**：此服务处理用户的预订

我们所有的服务将使用基于消息队列的发布/订阅架构进行集成。由于我们的目标是为您提供微服务和云计算领域的实用知识，我们将支持多种类型的消息队列。我们将支持**Kafka**、**RabbitMQ**和 AWS 的**SQS**。

持久层还将支持多种数据库技术，以便让您接触到各种实用的数据库引擎，从而增强您的项目。我们将支持**MongoDB**和**DynamoDB**。

我们所有的服务都将支持指标 API，这将允许我们通过**Prometheus**监控我们服务的统计数据。

MyEvents 平台的设计方式将为您构建微服务和云计算强大的知识基础和曝光。

# 摘要

在这个介绍性的章节中，您了解了云原生应用程序开发的基本设计原则。这包括设计目标，如支持（水平）可伸缩性和弹性，以及架构模式，如十二要素应用程序和微服务架构。

在接下来的章节中，您将学习在构建 MyEvents 应用程序时应用许多这些原则。在第二章中，*使用 Rest API 构建微服务*，您将学习如何使用 Go 编程语言实现提供 RESTful web 服务的小型微服务。在接下来的章节中，您将继续扩展这个小应用程序，并学习如何在各种云环境中处理部署和操作这个应用程序。


# 第二章：使用 Rest API 构建微服务

在本章中，我们将踏上学习微服务世界的旅程。我们将了解它们的结构、它们的通信方式以及它们如何持久化数据。由于今天大多数现代云应用程序在生产中都依赖微服务来实现弹性和可伸缩性，微服务的概念是一个需要涵盖的关键概念。

在本章中，我们将涵盖以下主题：

+   深入了解微服务架构

+   RESTful web API

+   在 Go 语言中构建 RESTful API

# 背景

我们在第一章中提供了微服务的实际定义。在本章中，让我们更详细地定义微服务。

为了充分理解微服务，让我们从它们崛起的故事开始。在微服务的概念变得流行之前，大多数应用程序都是单体的。单体应用程序是一个试图一次完成许多任务的单一应用程序。然后，随着需要新功能，应用程序会变得越来越庞大。这实际上会导致长期来看应用程序难以维护。随着云计算和大规模负载的分布式应用程序的出现，更灵活的应用程序架构的需求变得明显。

在第一章中，《现代微服务架构》，我们介绍了 MyEvents 应用程序，这是我们在本书中将要构建的应用程序。MyEvents 应用程序用于管理音乐会、戏剧等活动的预订。该应用程序的主要任务包括以下内容：

+   **处理预订**：例如，用户预订了下个月的音乐会。我们需要存储这个预订，确保这个活动有座位可用，并确认之前没有用相同的姓名进行过预订，等等。

+   **处理活动**：我们的应用程序需要了解我们预计要支持的所有音乐会、戏剧和其他类型的活动。我们需要知道活动地址、座位总数、活动持续时间等。

+   **处理搜索**：我们的应用程序需要能够执行高效的搜索来检索我们的预订和活动。

以下图片显示了 MyEvents 的单体应用程序设计的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9e7ba468-f203-4763-9927-f25afa449093.png)

单体应用程序

我们将在应用程序中构建多个软件层来处理每个需要的不同任务。我们的应用程序将成为一个具有庞大代码库的程序。由于代码都是相互连接的，一个层的变化总会影响其他层的代码。

由于它是一个单一程序，要在不同的编程语言中编写一些软件层不会很容易。当你知道语言 X 中有一个非常好的库来支持特性 Y 时，这通常是一个非常好的选择，但是语言 X 对于特性 Z 并不好。

此外，随着添加新功能或层，您的单一程序将不断增长，而没有良好的可伸缩性选项。能否在不同的服务器上运行不同的软件层，以便您可以控制应用程序的负载，而不是在一两台服务器上增加更多的硬件呢？

软件工程师们长期以来一直试图解决单体应用程序的困境。微服务是解决单体应用程序带来的问题的一种方法。在微服务这个术语变得流行之前，有 SOA 的概念，原则上类似于微服务。

在我们更深入地了解微服务之前，值得一提的是，单片应用程序并不总是坏的。这一切取决于您想要实现什么。如果您试图构建一个预期具有有限任务集的应用程序，并且不预期增长很多，那么一个单一构建良好的应用程序可能就是您所需要的。另一方面，如果您试图构建一个复杂的应用程序，预期执行许多独立任务，由多人维护，同时处理大量数据负载，那么微服务架构就是您的朋友。

# 那么，什么是微服务？

简而言之，微服务是这样的理念，即不是将所有代码放在一个篮子里（单片应用程序），而是编写多个小型软件服务或*微服务*。每个服务都预期专注于一个任务并且执行得很好。这些服务的累积将构成您的应用程序。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c86ee87c-6276-4227-b8e1-ae23d271b8be.png)

微服务应用程序

对于 MyEvents 应用程序，单片应用程序中的每个软件层将转化为一个软件服务。然后，它们将一起通信以构成我们的应用程序。这些软件服务中的每一个实际上都是一个微服务。

由于这些服务合作构建复杂的应用程序，它们需要能够通过它们都理解的协议进行通信。使用 Web Restful API 进行通信的微服务广泛使用 HTTP 协议。我们将在本章更详细地介绍 Restful API。

# 微服务内部

要构建适当的微服务，我们需要考虑几个组件。为了理解这五个组件，让我们讨论一下微服务预期承担的主要任务：

+   微服务将需要能够与其他服务和外部世界发送和接收消息，以便任务可以和谐地进行。微服务的通信方面采取不同的形式。与外部世界互动时，Restful API 非常受欢迎，与其他服务通信时，消息队列非常有帮助。还有其他一些流行的技术也很受欢迎，比如**gRPC**。

+   微服务将需要一个配置层；这可以通过环境变量、文件或数据库来实现。这个配置层将告诉微服务如何操作。例如，假设我们的服务需要监听 TCP 地址和端口号以便接收消息；TCP 地址和端口号将是在服务启动时传递给我们的服务的配置的一部分。

+   微服务将需要记录发生在其上的事件，以便我们能够排除故障并了解行为。例如，如果在向另一个服务发送消息时发生通信问题，我们需要将错误记录在某个地方，以便我们能够识别问题。

+   微服务将需要能够通过将数据存储在数据库或其他形式的数据存储中来持久化数据；我们还需要能够在以后检索数据。例如，在 MyEvents 应用程序的情况下，我们的微服务将需要存储和检索与用户、预订和事件相关的数据。

+   最后，有核心部分，是我们微服务中最重要的部分。核心部分是负责我们微服务预期任务的代码。例如，如果我们的微服务负责处理用户预订，那么微服务的核心部分就是我们编写处理用户预订任务的代码的地方。

因此，根据前面的五点，微服务的构建模块应该是这样的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d6337162-f1f4-432d-b2f9-b8cfedbc3356.png)

微服务的构建模块

这些构建块为构建高效的微服务提供了良好的基础。规则并非一成不变。您可以根据您尝试构建的应用程序使您的微服务变得更简单或更复杂。

# RESTful Web API

**REST**代表**表述性状态转移**。REST 只是不同服务进行通信和交换数据的一种方式。REST 架构的核心包括客户端和服务器。服务器监听传入的消息，然后回复它，而客户端启动连接，然后向服务器发送消息。

在现代网络编程世界中，RESTful 网络应用程序使用 HTTP 协议进行通信。RESTful 客户端将是一个 HTTP 客户端，而 RESTful 服务器将是 HTTP 服务器。HTTP 协议是支持互联网的关键应用层通信协议，这就是为什么 RESTful 应用程序也可以称为网络应用程序。RESTful 应用程序的通信层通常简称为 RESTful API。

REST API 允许在各种平台上开发的应用程序进行通信。这包括在其他操作系统上运行的应用程序中的其他微服务，以及在其他设备上运行的客户端应用程序。例如，智能手机可以通过 REST 可靠地与您的 Web 服务通信。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/273f5c32-2834-40fe-8258-1084b7ffbd41.png)

Web RESTful API

要了解 RESTful 应用程序的工作原理，我们首先需要对 HTTP 协议的工作原理有一个相当好的理解。HTTP 是一种应用级协议，用于在整个网络、云和现代微服务世界中进行数据通信。

HTTP 是一种客户端-服务器，请求-响应协议。这意味着数据流程如下：

+   HTTP 客户端向 HTTP 服务器发送请求

+   HTTP 服务器监听传入的请求，然后在其到达时做出响应

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0e6d3274-ef4e-4aac-9b64-2ed72455b6a2.png)

请求和响应

HTTP 客户端请求通常是以下两种情况之一：

+   客户端正在从服务器请求资源

+   客户端正在请求在服务器上添加/编辑资源

资源的性质取决于您的应用程序。例如，如果您的客户端是尝试访问网页的 Web 浏览器，那么您的客户端将向服务器发送请求，请求 HTML 网页。HTML 页面将作为资源在 HTTP Web 服务器的响应中返回给客户端。

在通信微服务的世界中，REST 应用程序通常使用 HTTP 协议结合 JSON 数据格式来交换数据消息。

考虑以下情景：在我们的 MyEvents 应用程序中，我们的一个微服务需要从另一个微服务获取事件信息（持续时间、开始日期、结束日期和位置）。需要信息的微服务将是我们的客户端，而提供信息的微服务将是我们的服务器。假设我们的客户端微服务具有事件 ID，但需要服务器微服务提供属于该 ID 的事件的信息。

客户端将通过事件 ID 发送请求，询问有关事件信息；服务器将以 JSON 格式回复信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/7ca15c58-6040-4454-a917-d086045e320b.png)

带有响应的 JSON 文档

这个描述听起来很简单；然而，它并没有提供完整的图片。客户端的询问部分需要更多的阐述，以便我们了解 REST API 的真正工作原理。

REST API 客户端请求需要指定两个主要信息以声明其意图——*请求 URL*和*请求方法*。

请求 URL 是客户端寻找的服务器上资源的地址。URL 是一个 Web 地址，REST API URL 的一个示例是[`quotes.rest/qod.json`](http://quotes.rest/qod.json)，这是一个返回当天引用的 API 服务。

在我们的场景中，MyEvents 客户端微服务可以向[`10.12.13.14:5500/events/id/1345`](http://10.12.13.14:5500/events/id/1345) URL 发送 HTTP 请求来查询事件 ID`1345`。

请求方法基本上是我们想要执行的操作类型。这可以是从请求获取资源到编辑资源、添加资源，甚至删除资源的请求。在 HTTP 协议中，有多种类型的方法需要成为客户端请求的一部分；以下是一些最常见的方法：

+   `GET`：在 Web 应用程序中非常常见的 HTTP 方法；这是我们从 HTTP Web 服务器请求资源的方式；这是我们在场景中使用的请求类型，用于请求事件 ID`1345`的数据。

+   `POST`：我们用来更新或创建资源的 HTTP 方法。

假设我们想使用`POST`更新属于事件 ID 1345 的某些信息，那么我们将发送一个`POST`请求到相对 URL`../events/id/1345`，并在请求体中附上新的事件信息。

另一方面，如果我们想创建一个 ID 为 1346 的新事件，我们不应该发送`POST`请求到`../events/id/1346`，因为该 ID 尚不存在。我们应该只是发送一个`POST`请求到`.../events`，并在请求体中附上所有新的事件信息。

+   `PUT`：用于创建或覆盖资源的 HTTP 方法。

与`POST`不同，`PUT`请求可以通过向之前不存在的资源 ID 发送请求来创建新资源。因此，例如，如果我们想创建一个 ID 为`1346`的新事件，我们可以发送一个`PUT`请求到`../events/id/1346`，Web 服务器应该为我们创建资源。

`PUT`也可以用于完全覆盖现有资源。因此，与`POST`不同，我们不应该使用`PUT`来仅更新资源的单个信息。

+   `DELETE`：用于删除资源。例如，如果我们向 Web 服务器的相对 URL`../events/id/1345`发送删除请求，Web 服务器将从数据库中删除资源。

# Gorilla web toolkit

现在我们已经了解了 Web Restful API 的工作原理，是时候了解如何在 Go 中最佳实现它们了。Go 语言自带了一个非常强大的标准库 web 包；Go 还享受着众多第三方包的支持。在本书中，我们将使用一个非常流行的 Go web 第三方工具包，名为 Gorilla web toolkit。Gorilla web toolkit 由一系列 Go 包组成，一起帮助快速高效地构建强大的 Web 应用程序。

Gorilla web toolkit 生态系统中的关键包称为`gorilla/mux`。`mux`包在包文档中被描述为*请求路由器和调度器*。这基本上是一个软件组件，它接受传入的 HTTP 请求，然后根据请求的性质决定要做什么。例如，假设客户端向我们的 Web 服务器发送了一个 HTTP 请求。我们的 Web 服务器中的 HTTP 路由调度器组件可以检测到传入请求包含一个相对 URL 为`../events/id/1345`的`GET`方法。然后它将检索事件 ID`1345`的信息并将其发送回客户端。

# 实施 Restful API

利用该包的第一步是使用`go get`命令将包获取到我们的开发环境中：

```go
$ go get github.com/gorilla/mux
```

有了这个，`mux`包将准备就绪。在我们的代码中，我们现在可以将`mux`包导入到我们的 web 服务器代码中：

```go
import "github.com/gorilla/mux"
```

在我们的代码中，现在需要使用 Gorilla `mux`包创建一个路由器。这可以通过以下代码实现：

```go
r := mux.NewRouter()
```

有了这个，我们将得到一个名为`r`的路由器对象，帮助我们定义我们的路由并将它们与要执行的操作链接起来。

从这一点开始，代码将根据所涉及的微服务而有所不同，因为不同的服务将支持不同的路由和操作。在本章的前面，我们介绍了在 MyEvents 应用程序中使用的四种不同类型的服务——Web UI 服务、搜索微服务、预订微服务和事件微服务。让我们专注于事件微服务。

事件微服务将需要支持一个 RESTFul API 接口，能够执行以下操作：

+   通过 ID 或事件名称搜索事件

+   一次性检索所有事件

+   创建一个新事件

让我们专注于这些任务中的每一个。由于我们正在设计一个微服务的 Web RESTful API，因此每个任务都需要转换为一个 HTTP 方法，结合一个 URL 和一个 HTTP 正文（如果需要）。

以下是详细说明：

+   通过搜索事件：

+   ID：相对 URL 是`/events/id/3434`，方法是`GET`，在 HTTP 正文中不需要数据

+   名称：相对 URL 是`/events/name/jazz_concert`，方法是`GET`，在 HTTP 正文中不需要数据

+   一次性检索所有事件：相对 URL 是`/events`，方法是`GET`，在 HTTP 正文中不需要数据

+   创建一个新事件：相对 URL 是`/events`，方法是`POST`，并且 HTTP 正文中需要的数据是我们想要添加的新事件的 JSON 表示。假设我们想要添加在美国演出的“歌剧艾达”事件，那么 HTTP 正文将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c90b3caa-a35a-4beb-bfec-24831041eb2a.png)

现在，如果您查看每个任务的 HTTP 翻译，您会注意到它们的相对 URL 都有一个共同的属性，即它们都以`/events`开头。在 Gorilla web 工具包中，我们可以为`/events`相对 URL 创建一个子路由器。子路由器基本上是一个对象，负责处理任何指向以`/events`开头的相对 URL 的传入 HTTP 请求。

要为以`/events`为前缀的 URL 创建一个子路由器，需要以下代码：

```go
eventsrouter := r.PathPrefix("/events").Subrouter()
```

前面的代码使用了我们之前创建的路由器对象，然后调用了`PathPrefix`方法，用于捕获以`/events`开头的任何 URL 路径。最后，我们调用了`Subrouter()`方法，这将为我们创建一个新的路由器对象，以便从现在开始处理任何以`/events`开头的 URL 的传入请求。新的路由器称为`eventsrouter`。

接下来，`eventsrouter`对象可以用来定义其余共享`/events`前缀的 URL 的操作。因此，让我们重新查看我们任务的 HTTP 翻译列表，并探索完成它们所需的代码：

1.  **任务：**通过搜索事件：

+   `id`：相对 URL 是`/events/id/3434`，方法是`GET`，在 HTTP 正文中不需要数据

+   `name`：相对 URL 是`/events/name/jazz_concert`，方法是`GET`，在 HTTP 正文中不需要数据：

```go
eventsrouter.Methods("GET").Path("/{SearchCriteria}/{search}").HandlerFunc(handler.findEventHandler)
```

前面代码中的处理程序对象基本上是实现我们期望映射到传入 HTTP 请求的功能的方法的对象。稍后再详细介绍。

1.  **任务：**一次性检索所有事件——相对 URL 是`/events`，方法是`GET`，在 HTTP 正文中不需要数据

```go
eventsrouter.Methods("GET").Path("").HandlerFunc(handler.allEventHandler)
```

1.  **任务：**创建一个新事件——相对 URL 是“/events”，方法是`POST`，并且 HTTP 正文中需要的数据是我们想要添加的新事件的 JSON 表示：

```go
eventsrouter.Methods("POST").Path("").HandlerFunc(handler.newEventHandler)
```

对于任务 2 和 3，代码是不言自明的。Gorilla `mux`包允许我们访问优雅地定义我们想要捕获的传入 HTTP 请求的属性的 Go 方法。该包还允许我们将调用链接在一起，以有效地构造我们的代码。`Methods()`调用定义了预期的 HTTP 方法，`Path()`调用定义了预期的相对 URL 路径（请注意，我们将调用放在`eventsrouter`对象上，它将在`Path()`调用中定义的相对路径后附加`/events`），最后是`HandlerFunc()`方法。

`HandlerFunc()`方法是我们将捕获的传入 HTTP 请求与操作关联的方式。`HandlerFunc()`接受一个`func(http.ResponseWriter, *http.Request)`类型的参数。这个参数基本上是一个具有两个重要参数的函数——一个 HTTP 响应对象，我们需要用我们的响应填充它，以响应传入的请求，以及一个 HTTP 请求对象，其中包含有关传入 HTTP 请求的所有信息。

在上述代码中，我们传递给`HandlerFunc()`的函数是`handler.findEventHandler`、`handler.allEventHandler`和`handler.newEventHandler`，它们都支持`func(http.ResponseWriter, *http.Request)`签名。`handler`是一个 Go 结构对象，用于承载所有这些函数。`handler`对象属于一个名为`eventServiceHandler`的自定义 Go 结构类型。

为了使`eventServiceHandler`类型支持任务 1、2 和 3 的 HTTP 处理程序，它需要定义如下：

```go
type eventServiceHandler struct {}

func (eh *eventServiceHandler) findEventHandler(w http.ResponseWriter, r *http.Request) {

}

func (eh *eventServiceHandler) allEventHandler(w http.ResponseWriter, r *http.Request) {

}

func (eh *eventServiceHandler) newEventHandler(w http.ResponseWriter, r *http.Request) {

}
```

在上述代码中，我们将`eventServiceHandler`创建为一个没有字段的结构类型，然后将三个空方法附加到它上面。每一个处理程序方法都支持成为 Gorilla `mux`包`HandlerFunc()`方法的参数所需的函数签名。在本章中，当我们讨论微服务的持久层时，将更详细地讨论`eventServiceHandler`方法的详细实现。

现在，让我们回到任务 1。我们代码中的`/{SearchCriteria}/{search}`路径代表了搜索事件 ID`2323`的等价路径`/id/2323`，或者搜索名称为`opera aida`的事件的路径`/name/opera aida`。我们路径中的大括号提醒 Gorilla `mux`包，`SearchCriteria`和`search`基本上是预期在真实传入的 HTTP 请求 URL 中用其他内容替换的变量。

Gorilla `mux`包支持 URL 路径变量的强大功能。它还支持通过正则表达式进行模式匹配。因此，例如，如果我使用一个看起来像`/{search:[0-9]+}`的路径，它将为我提供一个名为`search`的变量，其中包含一个数字。

在我们完成定义路由器、路径和处理程序之后，我们需要指定本地 TCP 地址，以便我们的 Web 服务器监听传入的 HTTP 请求。为此，我们需要 Go 的`net/http`包；代码如下：

```go
http.ListenAndServe(":8181", r)
```

在这一行代码中，我们创建了一个 Web 服务器。它将在本地端口`8181`上监听传入的 HTTP 请求，并将使用`r`对象作为请求的路由器。我们之前使用`mux`包创建了`r`对象。

现在是时候将我们到目前为止涵盖的所有代码放在一起了。假设代码位于一个名为`ServeAPI()`的函数中，该函数负责激活我们微服务的 Restful API 逻辑。

```go
func ServeAPI(endpoint string) error {
  handler := &eventservicehandler{}
  r := mux.NewRouter()
  eventsrouter := r.PathPrefix("/events").Subrouter()
  eventsrouter.Methods("GET").Path("/{SearchCriteria}/{search}").HandlerFunc(handler.FindEventHandler)
  eventsrouter.Methods("GET").Path("").HandlerFunc(handler.AllEventHandler)
  eventsrouter.Methods("POST").Path("").HandlerFunc(handler.NewEventHandler)
  return http.ListenAndServe(endpoint, r)
}
```

我们定义了`eventServiceHandler`对象如下：

```go
type eventServiceHandler struct {}

func (eh *eventServiceHandler) findEventHandler(w http.ResponseWriter, r *http.Request) {}

func (eh *eventServiceHandler) allEventHandler(w http.ResponseWriter, r *http.Request) {}

func (eh *eventServiceHandler) newEventHandler(w http.ResponseWriter, r *http.Request) {}
```

显然，下一步将是填写`eventServiceHandler`类型的空方法。我们有`findEventHandler()`、`allEventHandler()`和`newEventHandler()`方法。它们每一个都需要一个持久层来执行它们的任务。这是因为它们要么检索存储的数据，要么向存储添加新数据。

在本节中前面提到过，持久层是微服务的一个组件，负责将数据存储在数据库中或从数据库中检索数据。我们已经到了需要更详细地介绍持久层的时候了。

# 持久层

在设计持久层时需要做出的第一个决定是决定数据存储的类型。数据存储可以是关系型 SQL 数据库，如 Microsoft SQL 或 MySQL 等。或者，它可以是 NoSQL 存储，如 MongoDB 或 Apache Cassandra 等。

在高效和复杂的生产环境中，代码需要能够在不需要太多重构的情况下从一个数据存储切换到另一个。考虑以下例子——您为一家依赖 MongoDB 作为数据存储的初创公司构建了许多微服务；然后，随着组织的变化，您决定 AWS 基于云的 DynamoDB 将成为微服务更好的数据存储。如果代码不允许轻松地拔掉 MySQL，然后插入 MongoDB 层，那么我们的微服务将需要大量的代码重构。在 Go 语言中，我们将使用接口来实现灵活的设计。

值得一提的是，在微服务架构中，不同的服务可能需要不同类型的数据存储，因此一个微服务使用 MongoDB，而另一个服务可能使用 MySQL 是很正常的。

假设我们正在为事件微服务构建持久层。根据我们目前所涵盖的内容，事件微服务的持久层主要关心三件事：

+   向数据库添加新事件

+   通过 ID 查找事件

+   通过名称查找事件

为了实现灵活的代码设计，我们需要在接口中定义前面三个功能。它会是这样的：

```go
type DatabaseHandler interface {
    AddEvent(Event) ([]byte, error)
    FindEvent([]byte) (Event, error)
    FindEventByName(string) (Event, error)
    FindAllAvailableEvents() ([]Event, error)
}
```

`Event`数据类型是一个代表事件数据的结构类型，例如事件名称、位置、时间等。现在，让我们专注于`DatabaseHandler`接口。它支持四种方法，代表了事件服务持久层所需的任务。然后我们可以从这个接口创建多个具体的实现。一个实现可以支持 MongoDB，而另一个可以支持云原生的 AWS DynamoDB 数据库。

我们将在后面的章节中介绍 AWS DynamoDB。本章的重点将放在 MongoDB 上。

# MongoDB

如果您对 MongoDB NoSQL 数据库引擎还不熟悉，本节将对您非常有用。

MongoDB 是一个 NoSQL 文档存储数据库引擎。理解 MongoDB 的两个关键词是*NoSQL*和*文档存储*。

NoSQL 是软件行业中相对较新的关键词，用于指示数据库引擎不太依赖关系数据。关系数据是指数据库中不同数据之间存在关系的概念，遵循数据之间的关系将构建出数据代表的完整图景。

以 MySQL 作为关系型数据库的例子。数据存储在多个表中，然后使用主键和外键来定义不同表之间的关系。MongoDB 不是这样工作的，这就是为什么 MySQL 被认为是 SQL 数据库，而 MongoDB 被认为是 NoSQL 数据库。

如果您还不熟悉 Mongodb，或者没有本地安装可以测试。转到[`docs.mongodb.com/manual/installation/`](https://docs.mongodb.com/manual/installation/)，在那里您会找到一系列有用的链接，指导您完成在所选操作系统中安装和运行数据库的过程。通常，安装后，Mongodb 提供两个关键二进制文件：`mongod`和`mongo`。`mongod`命令是您需要执行的，以便运行您的数据库。然后编写的任何软件都将与`mongod`通信，以访问 Mongodb 的数据。另一方面，`mongo`命令基本上是一个客户端工具，您可以使用它来测试 Mongodb 上的数据，`mongo`命令与`mongod`通信，类似于您编写的任何访问数据库的应用程序。

有两种 MongoDB：社区版和企业版。显然，企业版针对更大的企业安装，而社区版是您用于测试和较小规模部署的版本。以下是涵盖三个主要操作系统的社区版指南的链接：

+   对于 Linux Mongodb 安装和部署：[`docs.mongodb.com/manual/administration/install-on-linux/`](https://docs.mongodb.com/manual/administration/install-on-linux/)

+   Windows Mongodb 安装和部署：[`docs.mongodb.com/manual/tutorial/install-mongodb-on-windows/`](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-windows/)

+   对于 OS X Mongodb 安装和部署：[`docs.mongodb.com/manual/tutorial/install-mongodb-on-os-x/`](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-os-x/)

总的来说，在部署 Mongodb 实例时，有三个主要步骤需要考虑：

1.  为您的操作系统安装 Mongodb，下载页面在这里：[`www.mongodb.com/download-center`](https://www.mongodb.com/download-center)

1.  确保 MongoDB 的关键二进制文件在您的环境路径中定义，以便您可以从终端运行它们，无论当前目录是什么。关键二进制文件是`mongod`和`mongo`。另一个值得一提的二进制文件是`mongos`，如果您计划使用集群，则这一点很重要

1.  运行`mongod`命令，不带任何参数，这将使用所有默认设置运行 Mongodb。或者，您可以使用不同的配置。您可以使用配置文件或运行时参数。您可以在这里找到有关配置文件的信息：[`docs.mongodb.com/manual/reference/configuration-options/#configuration-file`](https://docs.mongodb.com/manual/reference/configuration-options/#configuration-file)。要使用自定义配置文件启动`mongod`，可以使用`--config`选项，这是一个示例：`mongod --config /etc/mongod.conf`。另一方面，对于运行时参数，您可以在运行`mongod`时使用`--option`来更改选项，例如，您可以键入`mongod --port 5454`以在与默认值不同的端口上启动`mongod`

有不同类型的 NoSQL 数据库。其中一种类型是*文档存储*数据库。文档存储的概念是数据存储在许多文档文件中，堆叠在一起以表示我们要存储的内容。让我们以事件微服务所需的数据存储为例。如果我们在微服务持久层中使用文档存储，每个事件将存储在一个单独的带有唯一 ID 的文档中。假设我们有一个 Aida 歌剧事件，一个 Coldplay 音乐会事件和一个芭蕾表演事件。在 MongoDB 中，我们将创建一个名为*events*的文档集合，其中包含三个文档——一个用于歌剧，一个用于 Coldplay，一个用于芭蕾表演。

因此，为了巩固我们对 MongoDB 如何表示这些数据的理解，这里是事件集合的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0f10361f-cb37-42de-b2ee-16b8b80c7786.png)

事件集合

在 MongoDB 中，集合和文档是重要的概念。生产环境中的 MongoDB 通常由多个集合组成；每个集合代表我们数据的不同部分。例如，我们的 MyEvents 应用程序由许多微服务组成，每个微服务关心不同的数据部分。预订微服务将在预订集合中存储数据，而事件微服务将在事件集合中存储数据。我们还需要将用户数据单独存储，以便独立管理我们应用程序的用户。这将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9bc4b09d-c5d4-4727-b6d7-a08167d37aef.png)

我们的 MongoDB 数据库

您可以从以下链接下载此文件：[`www.packtpub.com/sites/default/files/downloads/CloudNativeprogrammingwithGolang_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/CloudNativeprogrammingwithGolang_ColorImages.pdf)。

该书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/Cloud-Native-Programming-with-Golang`](https://github.com/PacktPublishing/Cloud-Native-programming-with-Golang)。

由于我们迄今为止专注于事件微服务作为构建微服务的展示，让我们深入了解事件集合，这将被事件微服务使用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9422f73b-196c-4be4-a1c2-7e17df8ecd1f.png)

事件集合

事件集合中的每个文档都需要包含表示单个事件所需的所有信息。以下是事件文档应该看起来的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5505e49b-7894-44b0-93e1-b4b75e9245f4.png)

如果你还没有注意到，前面的 JSON 文档与我们提供的 HTTP `POST`请求体示例相同，这是一个添加事件 API 的 HTTP 请求体示例。

为了编写可以处理这些数据的软件，我们需要创建模型。模型基本上是包含与我们从数据库中期望的数据匹配的字段的数据结构。在 Go 的情况下，我们将使用结构类型来创建我们的模型。以下是事件模型应该看起来的样子：

```go
type Event struct {
    ID bson.ObjectId `bson:"_id"`
    Name string
    Duration int
    StartDate int64
    EndDate int64
    Location Location
}
type Location struct {
    Name string
    Address string
    Country string
    OpenTime int
    CloseTime int
    Halls []Hall
}
type Hall struct {
    Name string `json:"name"`
    Location string `json:"location,omitempty"`
    Capacity int `json:"capacity"`
}
```

`Event struct`是我们事件文档的数据结构或模型。它包含 ID、事件名称、事件持续时间、事件开始日期、事件结束日期和事件位置。由于事件位置需要包含比单个字段更多的信息，我们将创建一个名为 location 的结构类型来模拟位置。`Location struct`类型包含位置的名称、地址、国家、开放时间和关闭时间，以及该区域的大厅。大厅基本上是位置内部的房间，活动在那里举行。

因此，例如，Mountain View，位于 Mountain View 市中心的歌剧院将是位置，而位于东侧的硅谷房间将是大厅。

反过来，大厅不能由单个字段表示，因为我们需要知道它的名称、建筑物内的位置（东南、西部等）以及其容量（它可以容纳的人数）。

事件结构中的`bson.ObjectId`类型是表示 MongoDB 文档 ID 的特殊类型。`bson`包可以在`mgo`适配器中找到，这是与 MongoDB 通信的 Go 第三方框架的选择。`bson.ObjectId`类型还提供了一些有用的方法，我们可以在代码中稍后使用这些方法来验证 ID 的有效性。

在我们开始介绍`mgo`之前，让我们花一点时间解释一下`bson`的含义。`bson`是 MongoDB 用于表示存储文档中的数据的数据格式。它可以简单地被认为是二进制 JSON，因为它是 JSON 样式文档的二进制编码序列化。规范可以在此链接找到：[`bsonspec.org/`](http://bsonspec.org/)。

现在，让我们来介绍`mgo`。

# MongoDB 和 Go 语言

mgo 是用 Go 语言编写的流行的 MongoDB 驱动程序。包页面可以在[`labix.org/mgo`](http://labix.org/mgo)找到。该驱动程序只是一些 Go 包，可以方便地编写能够与 MongoDB 一起工作的 Go 程序。

为了使用`mgo`，第一步是使用`go get`命令检索包：

```go
go get gopkg.in/mgo.v2
```

执行上述命令后，我们可以在代码中使用`mgo`。我们需要导入`mgo`包和之前讨论过的`bson`包。我们用来托管我们的 MongoDB 持久层的包名叫做`mongolayer`。

让我们来看看`mongolayer`包：

```go
package mongolayer
import (
    mgo "gopkg.in/mgo.v2"
    "gopkg.in/mgo.v2/bson"
)
```

接下来，让我们创建一些常量来表示我们的数据库名称以及我们持久层中涉及的集合的名称。MongoDB 中的数据库名称将是`myevents`。我们将使用的集合名称是`users`，用于用户集合，以及`events`，用于我们数据库中的事件集合。

```go
const (
    DB = "myevents"
    USERS = "users"
    EVENTS = "events"
)
```

为了公开`mgo`包的功能，我们需要利用属于`mgo`包的数据库会话对象，该会话对象类型称为`*mgo.session`。为了在我们的代码中使用`*mgo.session`，我们将其包装在名为`MongoDBLayer`的结构类型中，如下所示：

```go
type MongoDBLayer struct {
    session *mgo.Session
}
```

现在是时候实现我们之前讨论过的`DatabaseHandler`接口了，以构建应用程序的具体持久层。在 Go 语言中，通常首选在实现接口时使用指针类型，因为指针保留对底层对象的原始内存地址的引用，而不是在使用时复制整个对象。换句话说，`DatabaseHandler`接口的实现对象类型需要是指向`MongoDBLayer`结构对象的指针，或者简单地说是`*MongoDBLayer`。

然而，在我们开始实现接口之前，我们首先需要创建一个构造函数，返回`*MongoDBLayer`类型的对象。这在 Go 语言中是惯用的，以便我们能够在创建`*MongoDBLayer`类型的新对象时执行任何必要的初始化代码。在我们的情况下，初始化代码基本上是获取所需的 MongoDB 数据库地址的连接会话处理程序。构造函数代码如下所示：

```go
func NewMongoDBLayer(connection string) (*MongoDBLayer, error) {
    s, err := mgo.Dial(connection)
    if err!= nil{
        return nil,err
    }
    return &MongoDBLayer{
        session: s,
    }, err
}
```

在上述代码中，我们创建了一个名为`NewMongoDBLayer`的构造函数，它需要一个字符串类型的单个参数。该参数表示连接字符串，其中包含建立与 MongoDB 数据库连接所需的信息。根据`mgo`文档[`godoc.org/gopkg.in/mgo.v2#Dial`](https://godoc.org/gopkg.in/mgo.v2#Dial)，连接字符串的格式需要如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d5bfd2e3-f4bc-45d4-9c86-8cbf1998639b.png)

如果只是本地主机连接，连接字符串将如下所示：`mongodb://127.0.0.1`

如果连接字符串中没有提供端口号，则端口默认为`27017`。

现在，让我们看看构造函数内的代码。在第一行中，我们使用连接字符串作为参数调用`mgo.Dial()`。`mgo.Dial()`是`mgo`包中的函数，它将为我们返回一个 MongoDB 连接会话，以便稍后在我们的代码中使用。它返回两个结果——`*mgo.Session`对象和一个错误对象。我们在最后使用结构文字返回指向`MongoDBLayer`类型的新对象的指针，其中包含新创建的`*mgo.Session`对象。我们还返回错误对象，以便在初始化过程中向调用者传达任何错误。

现在，构造函数已经完成，是时候实现`DatabaseHandler`接口的方法了。到目前为止，我们有四种方法——`AddEvent(Event)`、`FindEvent([]byte)`、`FindEventByName(string)`和`FindAllAvailableEvents()`。

`AddEvent(Event)`方法的代码如下：

```go
func (mgoLayer *MongoDBLayer) AddEvent(e persistence.Event) ([]byte, error) {
    s := mgoLayer.getFreshSession()
    defer s.Close()
    if !e.ID.Valid() {
        e.ID = bson.NewObjectId()
    }
    //let's assume the method below checks if the ID is valid for the location object of the event
    if !e.Location.ID.Valid() {
        e.Location.ID = bson.NewObjectId()
    }
    return []byte(e.ID), s.DB(DB).C(EVENTS).Insert(e)
}
```

该方法接受一个类型为`persistence.Event`的参数，该类型模拟了我们之前介绍的事件所期望的信息。它返回一个字节片，表示事件 ID，以及一个错误对象，如果没有找到错误，则为 nil。

在第一行，我们调用了`getFreshSession()`方法——这是我们代码中实现的一个帮助方法，用于从连接池中检索一个新的数据库会话。该方法的代码如下：

```go
func (mgoLayer *MongoDBLayer) getFreshSession() *mgo.Session {
    return mgoLayer.session.Copy()
}
```

`session.Copy()`是每当我们从`mgo`包连接池中请求新会话时调用的方法。`mgoLayer.session`在这里基本上是我们在`MongoDBLayer`结构体中托管的`*mgo.Session`对象。在即将通过`mgo`包向 MongoDB 发出查询或命令的任何方法或函数的开头调用`session.Copy()`是惯用的。`getFreshSession()`方法只是一个帮助方法，它调用`session.Copy()`为我们返回结果的会话。

现在，让我们回到`AddEvent()`方法。我们现在有一个来自数据库连接池的工作`*mgo.Session`对象可供我们在代码中使用。首先要做的是调用`defer s.Close()`，以确保在`AddEvent()`方法退出后，该会话会返回到`mgo`数据库连接池中。

接下来，我们检查`Event`参数对象提供的事件 ID 是否有效，以及`Event`对象的 ID 字段是否是我们之前介绍的`bson.ObjectID`类型。`bson.ObjectID`支持`Valid()`方法，我们可以使用它来检测 ID 是否是有效的 MongoDB 文档 ID。如果提供的事件 ID 无效，我们将使用`bson.NewObjectID()`函数调用创建一个新的 ID。然后，我们将在事件内部嵌入的位置对象中重复相同的模式。

最后，我们将返回两个结果——第一个结果是添加事件的事件 ID，第二个结果是表示事件插入操作结果的错误对象。为了将事件对象插入 MongoDB 数据库，我们将使用`s`变量中的会话对象，然后调用`s.DB(DB).C(EVENTS)`来获取一个表示数据库中我们事件集合的对象。该对象将是`*mgo.Collection`类型。`DB()`方法帮助我们访问数据库；我们将给它`DB`常量作为参数，它包含我们的数据库名称。`C()`方法帮助我们访问集合；我们将给它`EVENTS`常量，它包含我们事件集合的名称。

`DB`和`EVENTS`常量在我们的代码中早已定义。最后，我们将调用集合对象的`Insert()`方法，并将`Event`对象作为参数传递，这就是为什么代码最终看起来像这样——`s.DB(DB).C(EVENTS).Insert(e)`。这一行是我们需要的，以便将新文档插入到使用 Go 对象和`mgo`包的 MongoDB 数据库集合中。

现在，让我们看一下`FindEvent()`的代码，我们将使用它来从数据库中根据 ID 检索特定事件的信息。代码如下：

```go
func (mgoLayer *MongoDBLayer) FindEvent(id []byte) (persistence.Event, error) {
    s := mgoLayer.getFreshSession()
    defer s.Close()
    e := persistence.Event{}
    err := s.DB(DB).C(EVENTS).FindId(bson.ObjectId(id)).One(&e)
    return e, err
}
```

请注意，ID 以字节片的形式传递，而不是`bson.ObjectId`类型。我们这样做是为了确保`DatabaseHandler`接口中的`FindEvent()`方法尽可能通用。例如，我们知道在 MongoDB 的世界中，ID 将是`bson.ObjectId`类型，但是如果我们现在想要实现一个 MySQL 数据库层呢？将 ID 参数类型传递给`FindEvent()`为`bson.ObjectId`是没有意义的。这就是为什么我们选择了`[]byte`类型来表示我们的 ID 参数。理论上，我们应该能够将字节片转换为任何其他可以表示 ID 的类型。

重要的一点是，我们也可以选择空接口类型（`interface{}`），在 Go 中可以转换为任何其他类型。

在`FindEvent（）`方法的第一行中，我们像以前一样使用`mgoLayer.getFreshSession（）`从连接池中获取了一个新的会话。然后我们调用`defer s.Close（）`确保会话在完成后返回到连接池。

接下来，我们使用代码`e：= persistence.Event{}`创建了一个空的事件对象`e`。然后我们使用`s.DB（DB）.C（EVENTS）`来访问 MongoDB 中的事件集合。有一个名为`FindId（）`的方法，它由`*mgoCollection`对象支持`mgo`。该方法以`bson.ObjectId`类型的对象作为参数，然后搜索具有所需 ID 的文档。

`FindId（）`返回`*mgo.Query`类型的对象，这是`mgo`中的常见类型，我们可以使用它来检索查询的结果。为了将检索到的文档数据提供给我们之前创建的`e`对象，我们需要调用`One（）`方法，该方法属于`*mgo.Query`类型，并将`e`的引用作为参数传递。通过这样做，`e`将获得所需 ID 的检索文档的数据。如果操作失败，`One（）`方法将返回包含错误信息的错误对象，否则`One（）`将返回 nil。

在`FindEvent（）`方法的末尾，我们将返回事件对象和错误对象。

现在，让我们来看一下`FindEventByName（）`方法的实现，该方法从 MongoDB 数据库中根据名称检索事件。代码如下所示：

```go
func (mgoLayer *MongoDBLayer) FindEventByName(name string) (persistence.Event, error) {
    s := mgoLayer.getFreshSession()
    defer s.Close()
    e := persistence.Event{}
    err := s.DB(DB).C(EVENTS).Find(bson.M{"name": name}).One(&e)
    return e, err
}
```

该方法与`FindEvent（）`方法非常相似，除了两个方面。第一个区别是`FindEvent（）`需要一个字符串作为参数，该字符串表示我们想要查找的事件名称。

第二个区别是我们查询事件名称而不是事件 ID。我们查询文档的代码行使用了一个名为`Find（）`的方法，而不是`FindId（）`，这使得代码看起来像这样：

```go
err := s.DB(DB).C(EVENTS).Find(bson.M{"name":name}).One(&e)
```

`Find（）`方法接受一个表示我们想要传递给 MongoDB 的查询的参数。`bson`包提供了一个很好的类型叫做`bson.M`，它基本上是一个我们可以用来表示我们想要查找的查询参数的映射。在我们的情况下，我们正在寻找传递给`FindEventByName`的名称。我们数据库中事件集合中的名称字段简单地编码为`name`，而传递给我们的参数并具有名称的变量称为`name`。因此，我们的查询最终变为`bson.M{"name":name}`。

最后但并非最不重要的是我们的`FindAllAvailableEvents（）`方法。该方法返回我们数据库中所有可用的事件。换句话说，它从我们的 MongoDB 数据库返回整个事件集合。代码如下所示：

```go
func (mgoLayer *MongoDBLayer) FindAllAvailableEvents() ([]persistence.Event, error) {
    s := mgoLayer.getFreshSession()
    defer s.Close()
    events := []persistence.Event{}
    err := s.DB(DB).C(EVENTS).Find(nil).All(&events)
    return events, err
}
```

代码与`FindEventByName（）`几乎相同，除了三个简单的区别。第一个区别显然是`FindAllAvailableEvents（）`不需要任何参数。

第二个区别是我们需要将查询结果提供给事件对象的切片，而不是单个事件对象。这就是为什么返回类型是`[]persistence.Event`，而不仅仅是`persistence.Event`。

第三个区别是`Find（）`方法将采用 nil 作为参数，而不是`bson.M`对象。这将导致代码如下所示：

```go
err := s.DB(DB).C(EVENTS).Find(nil).All(&events)
```

当`Find（）`方法得到一个 nil 参数时，它将返回与关联的 MongoDB 集合中找到的一切。还要注意的是，在`Find（）`之后我们使用了`All（）`而不是`One（）`。这是因为我们期望多个结果而不仅仅是一个。

有了这个，我们完成了对持久层的覆盖。

# 实现我们的 RESTful API 处理程序函数

因此，既然我们已经覆盖了我们的持久层，现在是时候返回我们的 RESTful API 处理程序并覆盖它们的实现了。在本章的前面，我们定义了`eventServiceHandler`结构类型如下：

```go
type eventServiceHandler struct {}
func (eh *eventServiceHandler) findEventHandler(w http.ResponseWriter, r *http.Request) {}
func (eh *eventServiceHandler) allEventHandler(w http.ResponseWriter, r *http.Request) {}
func (eh *eventServiceHandler) newEventHandler(w http.ResponseWriter, r *http.Request) {}
```

`eventServiceHandler`类型现在需要支持我们在本章前面创建的`DatabaseHandler`接口类型，以便能够执行数据库操作。这将使结构看起来像这样：

```go
type eventServiceHandler struct {
    dbhandler persistence.DatabaseHandler
}
```

接下来，我们需要编写一个构造函数来初始化`eventServiceHandler`对象；它将如下所示：

```go
func newEventHandler(databasehandler persistence.DatabaseHandler) *eventServiceHandler {
    return &eventServiceHandler{
        dbhandler: databasehandler,
    }
}
```

然而，我们将`eventServiceHandler`结构类型的三种方法留空。让我们逐一进行。

第一个方法`findEventHandler()`负责处理用于查询存储在我们的数据库中的事件的 HTTP 请求。我们可以通过它们的 ID 或名称查询事件。如本章前面提到的，当搜索 ID 时，请求 URL 将类似于`/events/id/3434`，并且将是`GET`类型。另一方面，当按名称搜索时，请求将类似于`/events/name/jazz_concert`，并且将是`GET`类型。作为提醒，以下是我们如何定义路径并将其链接到处理程序的方式：

```go
eventsrouter := r.PathPrefix("/events").Subrouter()
eventsrouter.Methods("GET").Path("/{SearchCriteria}/{search}").HandlerFunc(handler.findEventHandler)
```

`{SearchCriteria}`和`{Search}`是我们路径中的两个变量。`{SearchCriteria}`可以替换为`id`或`name`。

以下是`findEventHandler`方法的代码：

```go
func (eh *eventServiceHandler) findEventHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    criteria, ok := vars["SearchCriteria"]
    if !ok {
        w.WriteHeader(400)
        fmt.Fprint(w, `{error: No search criteria found, you can either search by id via /id/4
                   to search by name via /name/coldplayconcert}`)
        return
    }
    searchkey, ok := vars["search"]
    if !ok {
        w.WriteHeader(400)
        fmt.Fprint(w, `{error: No search keys found, you can either search by id via /id/4
                   to search by name via /name/coldplayconcert}`)
        return
    }
    var event persistence.Event
    var err error
    switch strings.ToLower(criteria) {
        case "name":
        event, err = eh.dbhandler.FindEventByName(searchkey)
        case "id":
        id, err := hex.DecodeString(searchkey)
        if err == nil {
            event, err = eh.dbhandler.FindEvent(id)
        }
    }
    if err != nil {
        fmt.Fprintf(w, "{error %s}", err)
        return
    }
    w.Header().Set("Content-Type", "application/json;charset=utf8")
    json.NewEncoder(w).Encode(&event)
}
```

该方法接受两个参数：`http.ResponseWriter`类型的对象，表示我们需要填充的 HTTP 响应，而第二个参数是`*http.Request`类型，表示我们收到的 HTTP 请求。在第一行，我们使用`mux.Vars()`和请求对象作为参数；这将返回一个键值对的地图，它将表示我们的请求 URL 变量及其值。因此，例如，如果请求 URL 看起来像`/events/name/jazz_concert`，我们将在我们的结果地图中有两个键值对——第一个键是`"SearchCriteria"`，值为`"name"`，而第二个键是`"search"`，值为`jazz_concert`。结果地图存储在 vars 变量中。

然后我们在下一行从我们的地图中获取标准：

```go
criteria, ok := vars["SearchCriteria"]
```

因此，如果用户发送了正确的请求 URL，标准变量现在将是`name`或`id`。`ok`变量是布尔类型；如果`ok`为 true，则我们将在我们的`vars`地图中找到一个名为`SearchCriteria`的键。如果为 false，则我们知道我们收到的请求 URL 无效。

接下来，我们检查是否检索到搜索标准；如果没有，我们报告错误然后退出。请注意这里我们如何以类似 JSON 的格式报告错误？这是因为通常首选使用 JSON 格式的 RESTful API 返回所有内容，包括错误。另一种方法是创建一个 JSONError 类型并将其设置为我们的错误字符串；但是，为简单起见，我将在这里的代码中明确说明 JSON 字符串。

```go
if !ok {
    fmt.Fprint(w, `{error: No search criteria found, you can either search by id via /id/4 to search by name via /name/coldplayconcert}`)
    return
}
```

`fmt.Fprint`允许我们直接将错误消息写入包含我们的 HTTP 响应写入器的`w`变量。`http.responseWriter`对象类型支持 Go 的`io.Writer`接口，可以与`fmt.Fprint()`一起使用。

现在，我们需要对`{search}`变量做同样的处理：

```go
searchkey, ok := vars["search"]
if !ok {
    fmt.Fprint(w, `{error: No search keys found, you can either search by id via /id/4
               to search by name via /name/coldplayconcert}`)
    return
}
```

是时候根据提供的请求 URL 变量从数据库中提取信息了；这是我们的做法：

```go
var event persistence.Event
var err error
switch strings.ToLower(criteria) {
    case "name":
    event, err = eh.dbhandler.FindEventByName(searchkey)
    case "id":
    id, err := hex.DecodeString(searchkey)

    if nil == err {
        event, err = eh.dbhandler.FindEvent(id)
    }
}
```

在名称搜索标准的情况下，我们将使用`FindEventByName()`数据库处理程序方法按名称搜索。在 ID 搜索标准的情况下，我们将使用`hex.DecodeString()`将搜索键转换为字节片——如果我们成功获得字节片，我们将使用获得的 ID 调用`FindEvent()`。

然后，我们通过检查 err 对象来检查数据库操作期间是否发生了任何错误。如果我们发现错误，我们在我们的响应中写入一个`404`错误头，然后在 HTTP 响应正文中打印错误：

```go
if err != nil {
    w.WriteHeader(404)
    fmt.Fprintf(w, "Error occured %s", err)
    return
}
```

我们需要做的最后一件事是将响应转换为 JSON 格式，因此我们将 HTTP`content-type`头更改为`application/json`；然后，我们使用强大的 Go JSON 包将从我们的数据库调用中获得的结果转换为 JSON 格式：

```go
w.Header().Set("Content-Type", "application/json;charset=utf8")
json.NewEncoder(w).Encode(&event)
```

现在，让我们来看一下`allEventHandler()`方法的代码，该方法将返回 HTTP 响应中所有可用的事件：

```go
func (eh *eventServiceHandler) allEventHandler(w http.ResponseWriter, r *http.Request) {
    events, err := eh.dbhandler.FindAllAvailableEvents()
    if err != nil {
        w.WriteHeader(500)
        fmt.Fprintf(w, "{error: Error occured while trying to find all available events %s}", err)
        return
    }
    w.Header().Set("Content-Type", "application/json;charset=utf8")
    err = json.NewEncoder(w).Encode(&events)
    if err != nil {
        w.WriteHeader(500)
        fmt.Fprintf(w, "{error: Error occured while trying encode events to JSON %s}", err)
    }
}
```

我们首先调用数据库处理程序的`FindAllAvailableEvents()`来获取数据库中的所有事件。然后检查是否发生了任何错误。如果发现任何错误，我们将写入错误头，将错误打印到 HTTP 响应中，然后从函数中返回。

如果没有发生错误，我们将`application/json`写入 HTTP 响应的`Content-Type`头。然后将事件编码为 JSON 格式并发送到 HTTP 响应写入器对象。同样，如果发生任何错误，我们将记录它们然后退出。

现在，让我们讨论`newEventHandler()`处理程序方法，它将使用从传入的 HTTP 请求中检索到的数据向我们的数据库添加一个新事件。我们期望传入的 HTTP 请求中的事件数据以 JSON 格式存在。代码如下所示：

```go
func (eh *eventServiceHandler) newEventHandler(w http.ResponseWriter, r *http.Request) {
    event := persistence.Event{}
    err := json.NewDecoder(r.Body).Decode(&event)
    if err != nil {
        w.WriteHeader(500)
        fmt.Fprintf(w, "{error: error occured while decoding event data %s}", err)
        return
    }
    id, err := eh.dbhandler.AddEvent(event)
    if nil != err {
        w.WriteHeader(500)
        fmt.Fprintf(w, "{error: error occured while persisting event %d %s}",id, err)
        return
    }
```

在第一行，我们创建了一个`persistence.Event`类型的新对象，我们将使用它来保存我们期望从传入的 HTTP 请求中解析出的数据。

在第二行，我们使用 Go 的 JSON 包获取传入 HTTP 请求的主体（通过调用`r.Body`获得）。然后解码其中嵌入的 JSON 数据，并将其传递给新的事件对象，如下所示：

```go
err := json.NewDecoder(r.Body).Decode(&event)
```

然后像往常一样检查我们的错误。如果没有观察到错误，我们调用数据库处理程序的`AddEvent()`方法，并将事件对象作为参数传递。这实际上将把我们从传入的 HTTP 请求中获取的事件对象添加到数据库中。然后像往常一样再次检查错误并退出。

为了完成我们的事件微服务的最后要点，我们需要做三件事。第一件是允许我们在本章前面介绍的`ServeAPI()`函数调用`eventServiceHandler`构造函数，该函数定义了 HTTP 路由和处理程序。代码最终将如下所示：

```go
func ServeAPI(endpoint string, dbHandler persistence.DatabaseHandler) error {
    handler := newEventHandler(dbHandler)
    r := mux.NewRouter()
    eventsrouter := r.PathPrefix("/events").Subrouter()
eventsrouter.Methods("GET").Path("/{SearchCriteria}/{search}").HandlerFunc(handler.findEventHandler)
    eventsrouter.Methods("GET").Path("").HandlerFunc(handler.allEventHandler)
    eventsrouter.Methods("POST").Path("").HandlerFunc(handler.newEventHandler)

    return http.ListenAndServe(endpoint, r)
}
```

我们需要做的第二个最后要点是为我们的微服务编写一个配置层。如本章前面提到的，一个设计良好的微服务需要一个配置层，它可以从文件、数据库、环境变量或类似的介质中读取。目前，我们需要支持我们的配置层的三个主要参数——我们微服务使用的数据库类型（MongoDB 是我们的默认值）、数据库连接字符串（本地连接的默认值是`mongodb://127.0.0.1`）和 Restful API 端点。我们的配置层最终将如下所示：

```go
package configuration
var (
    DBTypeDefault = dblayer.DBTYPE("mongodb")
    DBConnectionDefault = "mongodb://127.0.0.1"
    RestfulEPDefault = "localhost:8181"
)
type ServiceConfig struct {
    Databasetype dblayer.DBTYPE `json:"databasetype"`
    DBConnection string `json:"dbconnection"`
    RestfulEndpoint string `json:"restfulapi_endpoint"`
}
func ExtractConfiguration(filename string) (ServiceConfig, error) {
    conf := ServiceConfig{
        DBTypeDefault,
        DBConnectionDefault,
        RestfulEPDefault,
    }
    file, err := os.Open(filename)
    if err != nil {
        fmt.Println("Configuration file not found. Continuing with default values.")
        return conf, err
    }
    err = json.NewDecoder(file).Decode(&conf)
    return conf,err
}
```

第三个要点是构建一个数据库层包，作为我们微服务中持久层的入口。该包将利用工厂设计模式，通过实现一个工厂函数来制造我们的数据库处理程序。工厂函数将制造我们的数据库处理程序。这是通过获取我们想要连接的数据库的名称和连接字符串，然后返回一个数据库处理程序对象，从此时起我们可以使用它来处理数据库相关的任务。目前我们只支持 MongoDB，所以代码如下：

```go
package dblayer

import (
  "gocloudprogramming/chapter2/myevents/src/lib/persistence"
  "gocloudprogramming/chapter2/myevents/src/lib/persistence/mongolayer"
)

type DBTYPE string

const (
  MONGODB DBTYPE = "mongodb"
  DYNAMODB DBTYPE = "dynamodb"
)

func NewPersistenceLayer(options DBTYPE, connection string) (persistence.DatabaseHandler, error) {

  switch options {
  case MONGODB:
    return mongolayer.NewMongoDBLayer(connection)
  }
  return nil, nil
}
```

第四个也是最后一个要点是我们的`main`包。我们将编写主函数，利用`flag`包从用户那里获取配置文件的位置，然后使用配置文件初始化数据库连接和 HTTP 服务器。以下是生成的代码：

```go
package main
func main(){
    confPath := flag.String("conf", `.\configuration\config.json`, "flag to set
                            the path to the configuration json file")
    flag.Parse()

    //extract configuration
    config, _ := configuration.ExtractConfiguration(*confPath)
    fmt.Println("Connecting to database")
    dbhandler, _ := dblayer.NewPersistenceLayer(config.Databasetype, config.DBConnection)

    //RESTful API start
    log.Fatal(rest.ServeAPI(config.RestfulEndpoint, dbhandler, eventEmitter))
}
```

通过这段代码，我们结束了本章。在下一章中，我们将讨论如何保护我们的微服务。

# 总结

在本章中，我们涵盖了关于设计和构建现代微服务的广泛主题。现在，您应该对 RESTful Web API、像 MongoDB 这样的 NoSQL 数据存储以及用于可扩展代码的适当 Go 设计模式有实际的知识。


# 第三章：保护微服务

欢迎来到我们学习现代 Go 云编程的第三章。在本章中，我们将保护前一章中编写的 RESTful API 服务。

在我们开始深入编写代码之前，我们需要涵盖一些关键概念，以便提供一个良好的知识基础。

正如我们在前一章中所介绍的，Web 应用程序需要使用 HTTP（这是一个应用级协议）进行通信。HTTP 本身不安全，这意味着它会以明文发送数据。显然，如果我们试图发送信用卡信息或敏感个人数据，我们绝对不希望以明文发送。幸运的是，HTTP 通信可以通过一种称为**TLS**（**传输层安全**）的协议来保护。HTTP 和 TLS 的组合被称为 HTTPS。

在本章中，我们将涵盖以下主题：

+   HTTPS 的内部工作原理

+   在 Go 中保护微服务

# HTTPS

要实际理解 HTTPS，我们首先需要讨论 TLS 协议。TLS 是一种可用于加密计算机网络上通信数据的协议。TLS 依赖于两种类型的加密算法来实现其目标——**对称加密**和**公钥加密**。

公钥加密也被称为非对称加密。我们很快会介绍这个名字的由来。另一方面，对称加密也可以称为对称密钥算法。

# 对称加密

数据加密的核心思想是使用复杂的数学方程对数据进行编码（或加密），从而使这些数据对人类来说变得不可读。在安全软件通信领域，加密数据可以被发送到预期的接收者，预期的接收者将对数据进行解密，使其恢复到原始的可读形式。

在几乎所有情况下，要加密一段数据，你需要一个**加密密钥**。加密密钥只是用于对数据进行编码的复杂数学方程的一部分。在一些加密算法中，你可以使用相同的加密密钥将数据解密回其原始形式。在其他情况下，需要一个与加密密钥不同的**解密密钥**来执行解密。

对称加密或对称密钥算法是使用相同密钥来加密和解密数据的算法，这就是为什么它们被称为**对称**。下图显示了加密密钥用于将单词**Hello**加密成编码形式，然后使用相同的密钥与编码数据一起将其解密回单词**Hello**。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/64412289-eba5-4bf4-a5a4-6229a4aecf23.png)

对称加密

# HTTPS 中的对称密钥算法

现在，让我们回到 Web 应用程序和 HTTP 的世界。一般来说，Web 应用程序只是使用 HTTP 协议进行通信的不同软件片段。正如本章前面提到的，为了保护 HTTP 并将其转换为 HTTPS，我们将其与另一个称为 TLS 的协议结合起来。TLS 协议利用对称密钥算法来加密客户端和服务器之间的 HTTP 数据。换句话说，Web 客户端和 Web 服务器通过协商一个共享的加密密钥（有些人称之为共享秘钥），然后使用它来保护它们之间来回传输的数据。

发送方应用程序使用密钥对数据进行加密，然后将其发送给接收方应用程序，接收方应用程序使用相同的密钥副本对数据进行解密。这个过程是 TLS 协议的对称密钥算法部分。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/a41dc9a4-96d8-4b53-b608-2d6a864725ec.png)

HTTPS 中的对称密钥算法

这听起来都很好，但是 Web 客户端和 Web 服务器如何确保在开始使用加密密钥发送加密数据之前，安全地达成对同一个加密密钥的共识呢？显然，Web 客户端不能只是以明文形式将密钥发送给 Web 服务器，然后期望这个密钥不会被未经授权的第三方捕获，然后简单地解密通过被窃取的密钥进行的任何安全通信。我们之前提到的答案是 TLS 协议依赖于不只一个，而是两种类型的加密算法来保护 HTTP。迄今为止，我们已经介绍了对称密钥算法，它们用于保护大部分通信；然而，公钥算法用于初始握手。这是客户端和服务器打招呼并相互识别，然后达成之后使用的加密密钥的地方。

# 非对称加密

与对称密钥算法不同，非对称加密或公钥算法利用两个密钥来保护数据。用于加密数据的一个密钥称为公钥，可以安全地与其他方分享。用于解密数据的另一个密钥称为私钥，不得分享。

公钥可以被任何人用来加密数据。然而，只有拥有与公钥对应的私钥的人才能将数据解密回其原始的可读形式。公钥和私钥是使用复杂的计算算法生成的。

在典型的情况下，拥有一对公私钥的人会与他们想要通信的其他人分享公钥。其他人随后会使用公钥来加密发送给密钥所有者的数据。密钥所有者反过来可以使用他们的私钥来将这些数据解密回其原始内容。

考虑一个很好的例子——维基百科提供的——展示了这个想法。假设 Alice 想要通过互联网与她的朋友安全地进行通信。为此，她使用一个生成一对公私钥的应用程序。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/222b0883-4987-4d8f-b015-c5528b6fa682.png)

Alice 的公私钥

现在，Alice 的一个名叫 Bob 的朋友想要通过互联网给她发送一条安全消息。消息只是**你好，Alice！** Alice 首先需要向 Bob 发送她的公钥的副本，以便 Bob 可以使用它来加密他的消息然后发送给 Alice。然后，当 Alice 收到消息时，她可以使用她的私钥（不与任何人分享）来将消息解密回可读的文本，看到 Bob 说了你好。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/aaed743e-4890-4438-b629-2f12c677c270.png)

Alice 和 Bob 之间的非对称加密

有了这个，你应该对公钥算法有足够的实际理解了。然而，这在 HTTPS 协议中是如何利用的呢？

# HTTPS 中的非对称加密

正如本章前面提到的，Web 客户端和 Web 服务器之间使用非对称加密来协商一个共享的加密密钥（也称为共享秘密或会话密钥），然后在对称加密中使用。换句话说，密钥被 Web 客户端和 Web 服务器同时使用来加密相互的 HTTP 通信。我们已经介绍了这种互动的对称加密部分，现在让我们深入一点了解非对称加密是如何进行的。

Web 客户端和 Web 服务器之间发生了一个**握手**，在这个握手中，客户端表示其意图向服务器开始一个安全的通信会话。通常，这涉及同意一些关于加密如何发生的数学细节。

服务器随后回复一个**数字证书**。如果您对数字证书的概念不熟悉，那么现在是时候阐明一下它是什么了。数字证书（或公钥证书）是一种证明公钥所有权的电子文档。为了理解数字证书的重要性，让我们退后几步，回想一下公钥是什么。

正如前面所述，公钥是用于非对称加密（或公钥算法）的加密密钥；该密钥只能加密数据，但永远无法解密数据，并且可以与我们希望进行通信的任何人共享。公钥的颁发者始终持有一个称为私钥的对应密钥，该私钥可以解密由公钥加密的数据。

这听起来很棒，但是如果客户端请求与服务器通信的公钥，然后一个坏的代理拦截了这个请求，并回复了自己的公钥（这被称为中间人攻击）会发生什么？客户端将继续与这个坏的代理进行通信，认为它是合法的服务器；然后客户端可能会向坏的代理发送敏感信息，例如信用卡号或个人数据。显然，如果我们寻求真正的保护和安全，我们希望尽一切可能避免这种情况，因此需要证书。

数字证书是由受信任的第三方实体颁发的数字文档。该文档包含一个公共加密密钥，该密钥所属的服务器名称，以及验证信息正确性的受信任第三方实体的名称，以及公钥属于预期密钥所有者（也称为证书颁发者）的名称。颁发证书的受信任第三方实体被称为**CA**（**证书颁发机构**）。有多个已知的 CA 颁发证书并验证企业和组织的身份。他们通常会收取一定的费用。对于较大的组织或政府机构，他们会颁发自己的证书；这个过程被称为**自签名**，因此他们的证书被称为自签名证书。证书可以有到期日期，到期后需要进行更新；这是为了在过去拥有证书的实体发生变化时提供额外的保护。

Web 客户端通常包含其所知的证书颁发机构列表。因此，当客户端尝试连接到 Web 服务器时，Web 服务器会回复一个数字证书。Web 客户端查找证书的颁发者，并将颁发者与其所知的证书颁发机构列表进行比较。如果 Web 客户端知道并信任证书颁发者，那么它将继续连接到该服务器，并使用证书中的公钥。

从服务器获取的公钥将用于加密通信，以安全地协商共享加密密钥（或会话密钥或共享密钥），然后在 Web 客户端和 Web 服务器之间的对称加密通信中使用。有许多算法可以用来生成会话密钥，但这超出了本章的范围。我们需要知道的是，一旦会话密钥达成一致，Web 客户端和 Web 服务器之间的初始握手将结束，允许实际的通信会话在共享会话密钥的保护下安全进行。

有了这些，我们现在对 Web 通信如何得到保护有了足够的实际理解。这用于安全的 Restful Web API 和安全的 Web 页面加载。要补充的另一个重要说明是，用于安全 Web 通信的 URL 以`https://`开头，而不是`http://`。这是显而易见的，因为安全的 Web 通信使用 HTTPS，而不仅仅是 HTTP。

# Go 中的安全 Web 服务

现在是时候找出如何在 Go 语言中编写安全的 Web 服务了。幸运的是，Go 是从头开始构建的，考虑到了现代软件架构，包括安全的 Web 应用程序。Go 配备了一个强大的标准库，允许从 HTTP 服务器平稳过渡到 HTTPS 服务器。在我们开始查看代码之前，让我们先回答一个简单的问题，即如何获取数字证书以在我们的 Web 服务器中使用。

# 获取证书

获取数字证书的默认方法是购买验证您的身份并从证书颁发机构提供者那里颁发证书的服务。正如我们之前提到的，有多个证书颁发机构提供者。可以在维基百科上找到最受欢迎的提供者列表：[`en.wikipedia.org/wiki/Certificate_authority#Providers`](https://en.wikipedia.org/wiki/Certificate_authority#Providers)

还有一些提供免费服务的证书颁发机构。例如，在 2016 年，**Mozilla 基金会**与**电子前沿基金会**和**密歇根大学**合作成立了一个名为*Let's Encrypt*的证书颁发机构，网址为：[`letsencrypt.org/`](https://letsencrypt.org/)。*Let's Encrypt*是一个免费服务，以自动化方式执行验证、签名和颁发证书。

听起来很不错。但是，如果我们只想测试一些本地 Web 应用程序，比如我们在前一章中构建的事件微服务，该怎么办？在这种情况下，我们需要一种更直接的方法来生成我们可以使用和测试的证书。然后，在部署到生产环境后，我们可以使用受信任的证书颁发机构为我们颁发证书，这些证书将受到 Web 浏览器和连接到互联网的客户端的尊重。

生成我们测试的证书的直接方法是手动创建我们自己的证书并进行自签名。这样做的优点是我们可以生成大量证书用于内部测试，而无需经过验证过程。然而，缺点是任何第三方网络客户端，如 Web 浏览器，尝试通过我们的自签名证书连接到我们的 Web 应用程序时，将无法识别这些证书的发行者，因此在允许我们继续之前会产生大量警告。

为了生成我们新鲜出炉的自签名数字证书，我们需要使用了解算法足够的专门工具来创建必要的输出。请记住，为了启动 HTTPS 会话，我们需要以下内容：

+   包含以下内容的数字证书：

+   一个可以与其他方共享的公钥。

+   拥有证书的服务器名称或域名。

+   证书的发行者。在自签名证书的情况下，发行者只是我们自己。在由受信任的证书颁发机构颁发的证书的情况下，发行者将是 CA。

+   我们需要保密并不与任何人分享的私钥

# OpenSSL

可以生成 TLS 数字证书的一种专门工具是非常流行的**OpenSSL**。OpenSSL 可以在以下网址找到：[`www.openssl.org/`](https://www.openssl.org/)。OpenSSL 是一个开源商业级 TLS 工具包，可用于执行各种任务；其中之一就是生成自签名数字证书。OpenSSL 组织本身并不提供该工具的预构建二进制文件。但是，有一个维基页面列出了可以下载该工具的第三方位置。维基页面可以在以下网址找到：[`wiki.openssl.org/index.php/Binaries`](https://wiki.openssl.org/index.php/Binaries)。一旦您下载了该工具，以下是如何使用它生成数字证书及其私钥的示例：

```go
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
```

在前面的代码中，第一个单词显然是二进制文件的名称。让我们逐个讨论这些参数：

+   `req`：表示请求；它表示我们请求一个证书。

+   -x509：这将表明我们要输出一个自签名证书。在密码学世界中，`X.509`是一个定义公钥证书格式的标准。许多互联网协议中使用的数字证书都使用了这个标准。

+   `-newkey`：此选项表示我们希望一个新的带有配对私钥的证书。如前所述，证书只是一个公钥与一堆标识符的组合。因此，为了执行非对称加密，我们需要一个与这个公钥配对的私钥。

+   `rsa:2048`：这是`-newkey`选项的参数，表示我们希望使用的加密算法类型来生成密钥。

+   `-keyout`：此选项提供要将新创建的私钥写入的文件名。

+   `key.pem`：这是`-keyout`选项的参数。它表示我们希望将私钥存储在一个名为`key.pem`的文件中。正如前面提到的，这个密钥需要保持私密，不与任何人分享。

+   `-out`：此选项提供要将新创建的自签名证书写入的文件名。

+   `cert.pem`：这是`-out`选项的参数；它表示我们希望将证书保存在一个名为`cert.pem`的文件中。然后，这个证书可以与试图通过 HTTPS 与我们的网站安全通信的 Web 客户端共享。

+   `-days`：证书有效期的天数。

+   365：这是`-days`选项的参数。这只是我们说我们希望证书有效期为 365 天，或者简单地说是一年。

# generate_cert.go

在 Go 语言的世界中，除了 OpenSSL 之外，还有另一种方法可以生成用于测试的自签名证书。如果您转到`GOROOT`文件夹，这是 Go 语言安装的位置，然后转到`/src/crypto/tls`文件夹，您会发现一个名为`generate_cert.go`的文件。这个文件只是一个简单的工具，可以轻松高效地为我们生成证书。在我的计算机上，`GOROOT`文件夹位于`C:\Go`。以下是我机器上`generate_cert.go`文件的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/e9aa3dd4-46e3-46c9-88f7-28e13a51d22d.png)

generate_cert.go 文件

`generate_cert.go`是一个独立的 Go 程序，可以通过`go run`命令简单运行。运行后，它将为您创建证书和私钥文件，并将它们放在当前文件夹中。该工具支持许多参数，但通常最常用的参数是`--host`，它表示我们要为哪个网站生成证书和密钥。以下是我们如何通过`go run`命令运行该工具的方式：

```go
go run %GOROOT%/src/crypto/tls/generate_cert.go --host=localhost
```

上述命令是在 Windows 操作系统上执行的，这就是为什么它将`GOROOT`环境路径变量表示为`%GOROOT%`。环境变量的表示方式因操作系统而异。例如，在 Linux 的情况下，环境变量将表示为`$GOROOT`。

我们现在将指示命令为名为`localhost`的服务器构建证书和私钥。该命令将为我们生成证书和密钥，然后将它们放在当前文件夹中，如前所述。以下是显示命令成功执行的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/3d8b88d7-f667-43bf-85e7-f1fac5b17ad6.png)

generate_cert.go 命令

`generate_cert`工具支持`--host`之外的其他选项。值得覆盖其中一些：

+   --start-date：此选项表示证书的开始验证日期。此选项的参数需要格式化为 2011 年 1 月 1 日 15:04:05，例如。

+   `--duration`：此选项表示证书有效期限，以小时为单位。默认值为一年。

+   `--rsa-bits`：此选项表示在密钥的 RSA 加密中要使用的位数。默认值为 2,048。

+   `--help`：这提供了支持的选项列表及其描述。

生成证书和密钥文件后，我们可以在我们的 Web 服务器应用程序中获取并使用它们，以支持 HTTPS。我们将在下一节中看到如何做到这一点。

# 在 Go 中构建 HTTPS 服务器

现在终于是时候深入一些代码了。由于 Go 非常适合构建现代 Web 软件，编写 HTTPS Web 服务器非常容易。让我们从回顾我们在上一章中编写的代码片段开始，以建立一个 HTTP Web 服务器：

```go
 http.ListenAndServe(endpoint, r)
```

这是一行代码，一个名为`ListenAndServe()`的函数，它属于标准库中的 HTTP Go 包。`ListenAndServe()`的第一个参数是我们希望我们的 Web 服务器监听的端点。因此，例如，如果我们希望我们的 Web 服务器监听本地端口 8181，端点将是`:8181`或`localhost:8181`。第二个参数是描述 HTTP 路由及其处理程序的对象——这个对象是由 Gorilla `mux`包创建的。从上一章中创建它的代码如下：

```go
r := mux.NewRouter()
```

要将上一章的 Web 服务器从 HTTP 转换为 HTTPS，我们只需要进行一个简单的更改——而不是调用`http.ListenAndServer()`函数，我们将使用另一个名为`http.ListenAndServeTLS()`的函数。代码将如下所示：

```go
http.ListenAndServeTLS(endpoint, "cert.pem", "key.pem", r)
```

如上述代码所示，`http.ListenAndServeTLS()`函数比`原始 http.ListenAndServe()`函数接受更多的参数。额外的参数是第二个和第三个参数。它们只是数字证书文件名和私钥文件名。第一个参数仍然是 Web 服务器监听端点，而最后一个参数仍然是处理程序对象（在我们的情况下是 Gorilla `*Router`对象）。我们已经从上一步生成了证书和私钥文件，所以我们在这里需要做的就是确保第二个和第三个参数指向正确的文件。

就是这样。这就是我们需要做的一切，以便在 Go 中创建一个 HTTPS Web 服务器；Go HTTP 标准包将接收证书和私钥，并根据 TLS 协议的要求使用它们。

然而，如果我们想要在我们的微服务中同时支持 HTTP 和 HTTPS 怎么办？为此，我们需要有点创意。第一个逻辑步骤将是在我们的代码中运行`http.ListenAndServe()`和`http.ListenAndServeTLS()`函数，但是我们遇到了一个明显的挑战：这两个函数如何在同一个本地端口上监听？我们可以通过选择一个与 HTTP 监听端口不同的端口来解决这个问题。在前面的章节中，我们使用了一个名为**endpoint**的变量来保存本地 HTTP 服务器的监听地址。对于 HTTPS，让我们假设本地监听地址存储在一个名为`tlsendpoint`的变量中。有了这个，代码将如下所示：

```go
http.ListenAndServeTLS(tlsendpoint, "cert.pem", "key.pem", r)

```

听起来很棒，但现在我们面临另一个障碍，`http.ListenAndServeTLS()`和`http.ListenAndServe()`都是阻塞函数。这意味着每当我们调用它们时，它们会无限期地阻塞当前的 goroutine，直到发生错误。这意味着我们不能在同一个 goroutine 上调用这两个函数。

goroutine 是 Go 语言中的一个重要语言组件。它可以被视为轻量级线程。Go 开发人员在各处都使用 goroutines 来实现高效的并发。为了在多个 goroutines 之间传递信息，我们使用另一个 Go 语言组件，称为 Go 通道。

因此，这个问题的解决方案很简单。我们在不同的 goroutine 中调用其中一个函数。这可以通过在函数名之前加上 go 这个词来简单实现。让我们在一个不同的 goroutine 中运行`http.ListenAndServe()`函数。代码将如下所示：

```go
go http.ListenAndServe(endpoint,r)
http.ListenAndServeTLS(tlsendpoint, "cert.pem", "key.pem", r)
```

完美！有了这个，我们的 Web 服务器可以作为 HTTP 服务器为希望使用 HTTP 的客户端，或者作为 HTTPS 服务器为希望使用 HTTPS 的客户端。现在，让我们解决另一个问题：`http.ListenAndServe()`和`http.ListenAndServeTLS()`函数都会返回错误对象来报告任何失败的问题；那么，即使它们在不同的 goroutines 上运行，我们是否可以捕获任一函数产生的错误？为此，我们需要使用 Go 通道，这是 Go 语言中两个 goroutines 之间通信的惯用方式。代码将如下所示：

```go
httpErrChan := make(chan error) 
httptlsErrChan := make(chan error) 
go func() { httptlsErrChan <- http.ListenAndServeTLS(tlsendpoint, "cert.pem", "key.pem", r) }() 
go func() { httpErrChan <- http.ListenAndServe(endpoint, r) }()

```

在前面的代码中，我们创建了两个 Go 通道，一个叫做`httpErrChan`，另一个叫做`httptlsErrChan`。这些通道将保存一个错误类型的对象。其中一个通道将报告`http.ListenAndServe()`函数观察到的错误，而另一个将报告`http.ListenAndServeTLS()`函数返回的错误。然后，我们使用两个带有匿名函数的 goroutines 来运行这两个`ListenAndServe`函数，并将它们的结果推送到相应的通道中。我们在这里使用匿名函数，因为我们的代码不仅仅涉及调用`http.ListenAndServe()`或`http.ListenAndServeTLS()`函数。

你可能会注意到，我们现在在两个`ListenAndServe`函数中都使用了 goroutines，而不仅仅是一个。我们这样做的原因是为了防止它们中的任何一个阻塞代码，这将允许我们将`httpErrChan`和`httptlsErrChan`通道都返回给调用者代码。调用者代码，也就是我们的主函数，在任何错误发生时可以自行处理这些错误。

在前面的章节中，我们将这段代码放在一个名为`ServeAPI()`的函数中；现在让我们来看一下在我们的更改之后这个函数的完整代码：

```go
func ServeAPI(endpoint, tlsendpoint string, databasehandler persistence.DatabaseHandler) (chan error, chan error) { 
   handler := newEventHandler(databaseHandler)
    r := mux.NewRouter() 
    eventsrouter := r.PathPrefix("/events").Subrouter()     eventsrouter.Methods("GET").Path("/{SearchCriteria}/{search}").HandlerFunc(handler.FindEventHandler) eventsrouter.Methods("GET").Path("").HandlerFunc(handler.AllEventHandler) eventsrouter.Methods("POST").Path("").HandlerFunc(handler.NewEventHandler) 
    httpErrChan := make(chan error) 
    httptlsErrChan := make(chan error) 
    go func() { httptlsErrChan <- http.ListenAndServeTLS(tlsendpoint, "cert.pem", "key.pem", r) }() 
    go func() { httpErrChan <- http.ListenAndServe(endpoint, r) }() 
    return httpErrChan, httptlsErrChan
} 
```

该函数现在接受一个名为`tlsendpoint`的新字符串参数，它将保存 HTTPS 服务器的监听地址。该函数还将返回两个错误通道。然后，函数代码继续定义我们的 REST API 支持的 HTTP 路由。然后，它将创建我们讨论过的错误通道，调用两个单独的 goroutine 中的 HTTP 包`ListenAndServe`函数，并返回错误通道。我们下一个逻辑步骤是覆盖调用`ServeAPI（）`函数的代码，并查看它如何处理错误通道。

正如前面讨论的，我们的主函数是调用`ServeAPI（）`函数的，因此这也将使主函数承担处理返回的错误通道的负担。主函数中的代码将如下所示：

```go
//RESTful API start 
httpErrChan, httptlsErrChan := rest.ServeAPI(config.RestfulEndpoint, config.RestfulTLSEndPint, dbhandler) 
select { 
case err := <-httpErrChan: 
     log.Fatal("HTTP Error: ", err) 
case err := <-httptlsErrChan: 
     log.Fatal("HTTPS Error: ", err) 
}
```

代码将调用`ServeAPI（）`函数，然后将两个返回的错误通道捕获到两个变量中。然后我们将使用 Go 的`select`语句的功能来处理这些通道。在 Go 中，`select`语句可以阻塞当前 goroutine 以等待多个通道；无论哪个通道首先返回，都将调用与之对应的`select` case。换句话说，如果`httpErrChan`返回，将调用第一个 case，它将在标准输出中打印一条报告发生 HTTP 错误的语句，并显示错误。否则，将调用第二个 case。阻塞主 goroutine 很重要，因为如果我们不阻塞它，程序将会退出，这是我们不希望发生的事情，如果没有失败的话。过去，`http.ListenAndServe（）`函数通常会阻塞我们的主 goroutine，并防止我们的程序在没有错误发生时退出。但是，由于我们现在已经在两个单独的 goroutine 上运行了`ListenAndServe`函数，我们需要另一种机制来确保我们的程序不会退出，除非我们希望它退出。

通常，每当您尝试从通道接收值或向通道发送值时，goroutine 都会被阻塞，直到传递一个值。这意味着如果`ListenAndServe`函数没有返回任何错误，那么值将不会通过通道传递，这将阻塞主 goroutine 直到发生错误。

除了常规通道之外，Go 还有一种称为缓冲通道的通道类型，它可以允许您在不阻塞当前 goroutine 的情况下传递值。但是，在我们的情况下，我们使用常规通道。

我们需要在这里覆盖的最后一段代码是更新配置。请记住，在上一章中，我们使用配置对象来处理微服务的配置信息。配置信息包括数据库地址、HTTP 端点等。由于我们现在还需要一个 HTTPS 端点，因此我们需要将其添加到配置中。配置代码存在于`./lib/configuration.go`文件中。现在它应该是这样的：

```go
package configuration

import ( 
         "encoding/json" "fmt" 
         "gocloudprogramming/chapter3/myevents/src/lib/persistence/dblayer" 
         "os"
       )

var ( 
      DBTypeDefault       = dblayer.DBTYPE("mongodb") 
      DBConnectionDefault = "mongodb://127.0.0.1" 
      RestfulEPDefault    = "localhost:8181" 
      RestfulTLSEPDefault = "localhost:9191"
    )

type ServiceConfig struct { 
     Databasetype      dblayer.DBTYPE `json:"databasetype"` 
     DBConnection      string         `json:"dbconnection"` 
     RestfulEndpoint   string         `json:"restfulapi_endpoint"` 
     RestfulTLSEndPint string         `json:"restfulapi-tlsendpoint"`
}

func ExtractConfiguration(filename string) (ServiceConfig, error) { 
   conf := ServiceConfig{ 
               DBTypeDefault, 
               DBConnectionDefault, 
               RestfulEPDefault, 
               RestfulTLSEPDefault, 
              }
   file, err := os.Open(filename) 
   if err != nil { 
       fmt.Println("Configuration file not found. Continuing with default values.") 
       return conf, err 
    }
   err = json.NewDecoder(file).Decode(&conf) 
   return conf, err
}
```

在上述代码中，我们从上一章做了三件主要的事情：

+   我们添加了一个名为`RestfulTLSEPDefault`的常量，它将默认为`localhost:9191`。

+   我们向`ServiceConfig`结构添加了一个新字段。该字段称为`RestfulTLSEndPint`；它将期望对应于名为`restfulapi-tlsendpoint`的 JSON 字段。

+   在`ExtractConfiguration（）`函数中，我们将初始化的`ServiceConfig`结构对象的`RestfulTLSEndPint`字段的默认值设置为`RestfulTLSEPDefault`。

通过这三个更改，我们的配置层将能够从配置 JSON 文件中读取 HTTPS 端点值，如果存在配置覆盖。如果不存在配置文件，或者配置文件中没有设置`restfulapi-tlsendpoint` JSON 字段，则我们将采用默认值，即`localhost:9191`。

任何调用`ExtractConfiguration()`函数的代码都将获得对这个功能的访问权限，并能够获取 HTTPS 端点的默认值或配置值。在我们的代码中，主函数将调用`ExtractConfiguration()`函数，并获取调用`ServeAPI()`函数所需的信息，该函数将运行我们的 RESTful API。

完美！有了这最后一部分，我们结束了本章。

# 总结

在本章中，我们深入探讨了安全的 Web 软件世界以及其内部工作原理。我们探讨了 HTTPS、对称和非对称加密，以及如何在 Go 语言中保护 Web 服务。

在下一章中，我们将涵盖分布式微服务架构世界中的一个关键主题：消息队列。


# 第四章：使用消息队列的异步微服务架构

在过去的两章中，您学习了如何使用 Go 编程语言构建基于 REST 的微服务。REST 架构风格既简单又灵活，这使其成为许多用例的绝佳选择。然而，基于 HTTP 构建的 REST 架构中的所有通信都将遵循客户端/服务器模型，进行请求/回复事务。在某些用例中，这可能是有限制的，其他通信模型可能更适合。

在本章中，我们将介绍发布/订阅通信模型，以及您需要实现它的技术。通常，发布/订阅架构需要一个中央基础设施组件——消息代理。在开源世界中，有许多不同的消息代理实现；因此，在本章中，我们将介绍两种我们认为最重要的消息代理——**RabbitMQ**和**Apache Kafka**。两者都适用于特定的用例；您将学习如何设置这两种消息代理，如何连接您的 Go 应用程序，以及何时应该使用其中一种。

然后，我们将向您展示如何利用这些知识来扩展您在前几章中工作的事件管理微服务，以便在发生重要事件时发布事件。这使我们能够实现第二个微服务来监听这些事件。您还将了解通常与异步通信一起使用的高级架构模式，例如*事件协作*和*事件溯源*，以及如何（以及何时）在应用程序中使用它们。

在本章中，我们将涵盖以下主题：

+   发布/订阅架构模式

+   事件协作

+   事件溯源

+   使用 RabbitMQ 的 AMQP

+   Apache Kafka

# 发布/订阅模式

发布/订阅模式是一种通信模式，是请求/回复模式的替代方案。与客户端（发出请求）和服务器（回复该请求）不同，发布/订阅架构由发布者和订阅者组成。

每个发布者都可以发出消息。发布者实际上并不关心谁收到了这些消息。这是订阅者的问题；每个订阅者可以订阅某种类型的消息，并在发布者发布给定类型的消息时得到通知。反过来，每个订阅者并不关心消息实际来自哪里。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/e967a901-db08-4ba1-a019-ab96d69ff7bc.png)

请求/回复和发布/订阅通信模式

实际上，许多发布/订阅架构都需要一个中央基础设施组件——消息代理。发布者在消息代理上发布消息，订阅者在消息代理上订阅消息。然后，代理的主要任务之一是将发布的消息路由到对它们感兴趣的订阅者。

通常，消息将被路由到基于主题的方式。这意味着每个发布者都为发布的消息指定一个主题（主题通常只是一个字符串标识符，例如`user.created`）。每个订阅者也将订阅特定的主题。通常，代理还允许订阅者使用通配符表达式（例如`user.*`）订阅整个主题集。

与请求/回复相比，发布/订阅模式带来了一些明显的优势：

+   发布者和订阅者之间的耦合非常松散。甚至它们彼此之间都不知道。

+   发布/订阅架构非常灵活。可以添加新的订阅者（因此扩展现有流程）而无需修改发布者。反之亦然；可以添加新的发布者而无需修改订阅者。

+   如果消息由消息代理路由，您还会获得弹性。通常，消息代理会将所有消息存储在队列中，直到它们被订阅者处理。如果订阅者变得不可用（例如由于故障或有意关闭），本应路由到该订阅者的消息将排队，直到订阅者再次可用。

+   通常，您还会在协议级别获得消息代理的某种可靠性保证。例如，RabbitMQ 通过要求每个订阅者确认接收到的消息来保证*可靠传递*。只有在消息被确认后，代理才会从队列中删除消息。如果订阅者应该失败（例如，由于断开连接），当消息已经被传递但尚未被确认时，消息将被放回消息队列中。如果另一个订阅者监听同一消息队列，消息可能会被路由到该订阅者；否则，它将保留在队列中，直到订阅者再次可用。

+   您可以轻松扩展。如果对于单个订阅者来说发布了太多消息以有效处理它们，您可以添加更多订阅者，并让消息代理负载平衡发送给这些订阅者的消息。

当然，引入消息代理这样的中心基础设施组件也带来了自己的风险。如果做得不对，您的消息代理可能会成为单点故障，导致整个应用程序在其失败时崩溃。在生产环境中引入消息代理时，您应该采取适当的措施来确保高可用性（通常是通过集群和自动故障转移）。

如果您的应用程序在云环境中运行，您还可以利用云提供商提供的托管消息排队和传递服务之一，例如 AWS 的**简单队列服务**（**SQS**）或 Azure 服务总线。

在本章中，您将学习如何使用两种最流行的开源消息代理——RabbitMQ 和 Apache Kafka。在第八章中，*AWS 第二部分-S3、SQS、API 网关和 DynamoDB*，您将了解有关 AWS SQS 的信息。

# 介绍预订服务

在这一部分，我们将首先使用 RabbitMQ 实现发布/订阅架构。为此，我们需要向我们的架构添加新的微服务——预订服务将处理事件的预订。其责任将包括确保事件不会被过度预订。为此，它将需要了解现有的事件和位置。为了实现这一点，我们将修改**EventService**，以便在创建位置或事件时发出事件（是的，术语很混乱——确保不要将*发生了某事的通知*类型的事件与*Metallica 在这里演出*类型的事件弄混）。**BookingService**然后可以监听这些事件，并在有人为这些事件之一预订票时自己发出事件。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5e8ba22f-e4f5-4afe-a62e-a02471ec46b7.png)

我们的微服务概述以及它们将发布和订阅的事件

# 事件协作

事件协作描述了一个与事件驱动的发布/订阅架构很好配合的架构原则。

考虑以下示例，使用常规的请求/响应通信模式——用户请求预订服务为某个事件预订门票。由于事件由另一个微服务（**EventService**）管理，因此**BookingService**需要从**EventService**请求有关事件及其位置的信息。只有这样**BookingService**才能检查是否还有座位可用，并将用户的预订保存在自己的数据库中。此交易所需的请求和响应如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/33a76190-6cbc-46dc-a92c-74f6f5cf3070.png)

请求和响应

现在，考虑在发布/订阅架构中相同的场景，其中**BookingService**和**EventService**使用事件进行集成：每当**EventService**中的数据发生变化时，它会发出一个事件（例如*创建了一个新位置*，*创建了一个新事件*，*更新了一个事件*等）。

现在，**BookingService**可以监听这些事件。它可以构建自己的所有当前存在的位置和事件的数据库。现在，如果用户请求为特定事件预订新的预订，**BookingService**可以简单地使用自己本地数据库中的数据，而无需从另一个服务请求此数据。请参考以下图表，以进一步说明这个原则：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/42e36988-e61f-42cd-a54b-9e1133e416b3.png)

使用自己本地数据库中的 BookingService

这是事件协作架构的关键点。在前面的图表中，一个服务几乎永远不需要查询另一个服务的数据，因为它通过监听其他服务发出的事件已经知道了它需要知道的一切。

显然，这种架构模式与发布/订阅非常配合。在前面的例子中，**EventService**将是发布者，而**BookingService**（可能还有其他服务）将是订阅者。当然，人们可能会对这个原则必然导致两个服务存储冗余数据感到不安。然而，这并不一定是件坏事——因为每个服务都不断监听其他服务发出的事件，整个数据集最终可以保持一致。此外，这增加了系统的整体弹性；例如，如果事件服务突然发生故障，**BookingService**仍然可以正常运行，因为它不再依赖事件服务的工作。

# 使用 RabbitMQ 实现发布/订阅

在接下来的部分，您将学习如何实现基本的发布/订阅架构。为此，我们将看一下**高级消息队列协议**（**AMQP**）及其最流行的实现之一，RabbitMQ。

# 高级消息队列协议

在协议级别上，RabbitMQ 实现了 AMQP。在开始使用 RabbitMQ 之前，让我们先看一下 AMQP 的基本协议语义。

AMQP 消息代理管理两种基本资源——**交换**和**队列**。每个发布者将其消息发布到一个交换中。每个订阅者消费一个队列。AMQP 代理负责将发布到交换中的消息放入相应的队列中。消息发布到交换后的去向取决于**交换类型**和称为**绑定**的路由规则。AMQP 有三种不同类型的交换：

+   **Direct exchanges**: 消息以给定的主题（在 AMQP 中称为**路由键**）发布，这是一个简单的字符串值。可以定义直接交换和队列之间的绑定，以精确匹配该主题。

+   **Fanout exchanges**: 消息通过绑定连接到扇出交换机的所有队列。消息可以有路由键，但会被忽略。每个绑定的队列将接收发布在扇出交换机中的所有消息。

+   **主题交换**：这与直接交换类似。但是，现在队列是使用消息的路由键必须匹配的模式绑定到交换。主题交换通常假定路由键使用句点字符`'.'`进行分段。例如，您的路由键可以遵循`"<entityname>.<state-change>.<location>"`模式（例如，`"event.created.europe"`）。现在可以创建包含通配符的队列绑定，使用`'*'`或`'#'`字符。`*`将匹配任何单个路由键段，而`#`将匹配任意数量的段。因此，对于前面的示例，有效的绑定可能如下：

+   `event.created.europe`（显然）

+   `event.created.*`（每当在世界的任何地方创建事件时都会收到通知）

+   `event.#`（每当在世界的任何地方对事件进行任何更改时都会收到通知）

+   `event.*.europe`（每当在欧洲对事件进行任何更改时都会收到通知）

下一个图表显示了一个可能的示例交换和队列拓扑结构。在这种情况下，我们有一个发布消息的服务**EventService**。我们有两个队列，消息将被路由到这两个队列中。第一个队列**evts_booking**将接收与事件的任何更改相关的所有消息。第二个队列**evts_search**将只接收关于新事件创建的消息。请注意，**evts_booking**队列有两个订阅者。当两个或更多订阅者订阅同一个队列时，消息代理将轮流将消息分发给其中一个订阅者。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/cc668950-bec2-43b7-beb1-5ca489f7e80d.png)

消息代理将消息轮流显示给其中一个订阅者

重要的是要注意，整个 AMQP 拓扑（即所有交换和队列以及它们如何相互绑定）不是由代理定义的，而是由发布者和消费者自己定义的。AMQP 指定了客户端可以使用的几种方法来声明它们需要的交换和队列。例如，发布者通常会使用`exchange.declare`方法来断言它想要发布的交换实际上存在（如果之前不存在，代理将创建它）。另一方面，订阅者可能会使用`queue.declare`和`queue.bind`方法来声明它想要订阅的队列，并将其绑定到一个交换。

有多个实现 AMQP 的开源消息代理。其中最流行的之一（也是我们在本章中将要使用的）是 RabbitMQ 代理，这是一个由**Pivotal**开发并在**Mozilla Public License**下提供的开源 AMQP 代理。其他实现 AMQP 的消息代理包括**Apache QPID**（[`qpid.apache.org`](https://qpid.apache.org)）和**Apache ActiveMQ**（[`activemq.apache.org`](http://activemq.apache.org)）。

虽然在这个例子中我们将使用 RabbitMQ，但本章中编写的代码应该适用于所有类型的 AMQP 实现。

# 使用 Docker 快速启动 RabbitMQ

在构建我们的发布/订阅架构之前，您需要在开发环境中设置一个正在运行的 RabbitMQ 消息代理。使用官方的 Docker 镜像是开始使用 RabbitMQ 的最简单方法。

对于本例，我们将假设您的本地机器上已经安装了 Docker。请查看官方安装说明，了解如何在您的操作系统上安装 Docker：[`docs.docker.com/engine/installation`](https://docs.docker.com/engine/installation)。

您可以使用以下命令在命令行上启动一个新的 RabbitMQ 代理：

```go
$ docker run --detach \ 
    --name rabbitmq \ 
    -p 5672:5672 \ 
    -p 15672:15672 \ 
    rabbitmq:3-management 
```

上述命令将在您的机器上创建一个名为`rabbitmq`的新容器。为此，Docker 将使用`rabbitmq:3-management`镜像。该镜像包含了 RabbitMQ 3 的最新版本（在撰写本文时为 3.6.6）和管理 UI。`-p 5672:5672`标志将指示 Docker 将 TCP 端口`5672`（这是 AMQP 的 IANA 分配的端口号）映射到您的`localhost`地址。`-p 15672:15672`标志将对管理用户界面执行相同的操作。

启动容器后，您将能够在浏览器中打开到`amqp://localhost:5672`的 AMQP 连接，并在`http://localhost:15672`中打开管理 UI。

当您在 Windows 上使用 Docker 时，您需要用本地 Docker 虚拟机的 IP 地址替换 localhost。您可以使用以下命令在命令行上确定此 IP 地址：`$ docker-machine ip default`。

无论您是使用 docker-machine 还是本地 Docker 安装，RabbitMQ 用户界面应该看起来与以下截图非常相似：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/6075ceff-4af4-4e70-bfa2-de38dd0501c0.png)

RabbitMQ 的管理用户界面

在浏览器中打开管理界面（`http://localhost:15672`或您的 docker-machine IP 地址）。RabbitMQ 镜像提供了一个默认的 guest 用户，其密码也是`guest`。在生产中运行 RabbitMQ 时，这当然是您应该更改的第一件事。对于开发目的，这样做就可以了。

# 高级 RabbitMQ 设置

上一节中描述的基于 Docker 的设置可以让您快速入门，并且（经过一些调整）也适用于生产设置。如果您不想为消息代理使用 Docker，您还可以从软件包存储库在大多数常见的 Linux 发行版上安装 RabbitMQ。例如，在 Ubuntu 和 Debian 上，您可以使用以下命令安装 RabbitMQ：

```go
$ echo 'deb http://www.rabbitmq.com/debian/ testing main' | \ 
    sudo tee /etc/apt/sources.list.d/rabbitmq.list 
$ wget -O- https://www.rabbitmq.com/rabbitmq-release-signing-key.asc | \ 
    sudo apt-key add - 
$ apt-get update 
$ apt-get install -y rabbitmq-server 
```

类似的命令也适用于**CentOS**和**RHEL**：

```go
$ rpm --import https://www.rabbitmq.com/rabbitmq-release-signing-key.asc 
$ yum install rabbitmq-server-3.6.6-1.noarch.rpm 
```

对于生产设置，您可能希望考虑设置 RabbitMQ 作为集群，以确保高可用性。请查看官方文档[`www.rabbitmq.com/clustering.html`](http://www.rabbitmq.com/clustering.html)了解如何设置 RabbitMQ 集群的更多信息。

# 使用 Go 连接 RabbitMQ

要连接到 RabbitMQ 代理（或者说是任何 AMQP 代理），我们建议您使用`github.com/streadway/amqp`库（这是事实上的标准 Go 库，用于 AMQP）。让我们从安装库开始：

```go
$ go get -u github.com/streadway/amqp
```

然后，您可以通过将库导入到您的代码中来开始。使用`amqp.Dial`方法打开一个新连接：

```go
import "github.com/streadway/amqp" 

func main() { 
  connection, err := amqp.Dial("amqp://guest:guest@localhost:5672") 
  if err != nil { 
    panic("could not establish AMQP connection: " + err.Error()) 
  } 

  defer connection.Close() 
} 
```

在这种情况下，`"amqp://guest:guest@localhost:5672"`是您的 AMQP 代理的 URL。请注意，用户凭据嵌入到 URL 中。`amqp.Dial`方法在成功时返回连接对象，否则返回`nil`和错误（与 Go 中一样，请确保您实际上检查了此错误）。此外，在不再需要连接时不要忘记使用`Close()`方法关闭连接。

当然，通常不建议将连接详细信息（更不用说凭据）硬编码到您的应用程序中。记住您学到的关于十二要素应用程序的知识，让我们引入一个环境变量`AMQP_URL`，我们可以使用它来动态配置 AMQP 代理：

```go
import "github.com/streadway/amqp" 
import "os" 

func main() { 
  amqpURL := os.Getenv("AMQP_URL"); 
  if amqpURL == "" { 
    amqpURL = "amqp://guest:guest@localhost:5672" 
  } 

  connection, err := amqp.Dial(amqpURL) 
  // ... 
} 
```

在 AMQP 中，大多数操作不是直接在连接上进行的，而是在通道上进行的。通道用于在一个实际的 TCP 连接上*多路复用*多个虚拟连接。

通道本身不是线程安全的。在 Go 中，我们需要记住这一点，并注意不要从多个 goroutine 访问同一个通道。但是，使用多个通道，每个通道只被一个线程访问，是完全安全的。因此，当有疑问时，最好创建一个新通道。

继续在现有连接上创建一个新通道：

```go
connection, err := amqp.Dial(amqpURL) 
if err != nil { 
  panic("could not establish AMQP connection: " + err.Error()) 
} 

channel, err := connection.Channel() 
if err != nil { 
  panic("could not open channel: " + err.Error()) 
} 
```

现在我们可以使用这个通道对象进行一些实际的 AMQP 操作，例如发布消息和订阅消息。

# 发布和订阅 AMQP 消息

在深入研究 MyEvents 微服务架构之前，让我们看一下我们可以使用的基本 AMQP 方法。为此，我们将首先构建一个小的示例程序，该程序能够向交换发布消息。

打开通道后，消息发布者应声明要发布消息的交换。为此，您可以在通道对象上使用`ExchangeDeclare()`方法：

```go
err = channel.ExchangeDeclare("events", "topic", true, false, false, false, nil) 
if err != nil { 
  panic(err) 
} 
```

正如您所看到的，`ExchangeDeclare`需要相当多的参数。这些如下所示：

+   交换名称

+   交换类型（请记住 AMQP 知道`direct`，`fanout`和`topic`交换）

+   `durable`标志将导致交换在代理重新启动时保持声明状态

+   `autoDelete`标志将导致交换在声明它的通道关闭时被删除

+   `internal`标志将阻止发布者将消息发布到此队列中

+   `noWait`标志将指示`ExchangeDeclare`方法不等待来自代理的成功响应

+   `args`参数可能包含具有附加配置参数的映射

声明交换后，您现在可以发布一条消息。为此，您可以使用通道的`Publish()`方法。发出的消息将是您需要首先实例化的`amqp.Publishing`结构的实例：

```go
message := amqp.Publishing { 
  Body: []byte("Hello World"),
} 
```

然后，使用`Publish()`方法发布您的消息：

```go
err = channel.Publish("events", "some-routing-key", false, false, message) 
if err != nil { 
  panic("error while publishing message: " + err.Error()) 
} 
```

`Publish()`方法接受以下参数：

+   要发布到的交换的名称

+   消息的路由键

+   `mandatory`标志将指示代理确保消息实际上被路由到至少一个队列中

+   `immediate`标志将指示代理确保消息实际上被传递给至少一个订阅者

+   `msg`参数包含要发布的实际消息

对于发布/订阅架构，发布者不需要知道谁订阅其发布的消息，显然`mandatory`和`immediate`标志不适用，因此在此示例（以及所有后续示例）中，我们将它们设置为 false。

您现在可以运行此程序，它将连接到您的本地 AMQP 代理，声明一个交换，并发布一条消息。当然，这条消息不会被路由到任何地方并消失。为了实际处理它，您将需要一个订阅者。

继续创建第二个 Go 程序，其中您连接到 AMQP 代理并创建一个新的通道，就像在前一节中一样。但是，现在，不是声明一个交换并发布一条消息，让我们声明一个队列并将其绑定到该交换：

```go
_, err = channel.QueueDeclare("my_queue", true, false, false, false, nil) 
if err != nil { 
  panic("error while declaring the queue: " + err.Error()) 
} 

err = channel.QueueBind("my_queue", "#", "events", false, nil) 
if err != nil { 
  panic("error while binding the queue: " + err.Error())
} 
```

声明并绑定队列后，您现在可以开始消费此队列。为此，请使用通道的`Consume()`函数：

```go
msgs, err := channel.Consume("my_queue", "", false, false, false, false, nil) 
if err != nil { 
  panic("error while consuming the queue: " + err.Error()) 
} 
```

`Consume()`方法接受以下参数：

+   要消耗的队列的名称。

+   唯一标识此消费者的字符串。当留空（就像在这种情况下）时，将自动生成唯一标识符。

+   当设置`autoAck`标志时，接收到的消息将自动确认。当未设置时，您需要在处理接收到的消息后显式确认消息，使用接收到的消息的`Ack()`方法（请参阅以下代码示例）。

+   当设置`exclusive`标志时，此消费者将是唯一被允许消费此队列的消费者。当未设置时，其他消费者可能会监听同一队列。

+   `noLocal`标志指示代理不应将在同一通道上发布的消息传递给此消费者。

+   `noWait`标志指示库不等待来自代理的确认。

+   `args`参数可能包含具有附加配置参数的映射。

在这个例子中，`msgs`将是一个通道（这次是一个实际的 Go 通道，而不是一个 AMQP 通道）的`amqp.Delivery`结构。为了从队列中接收消息，我们可以简单地从该通道中读取值。如果要连续读取消息，最简单的方法是使用`range`循环：

```go
for msg := range msgs { 
  fmt.Println("message received: " + string(msg.Body)) 
  msg.Ack(false) 
} 
```

请注意，在前面的代码中，我们使用`msg.Ack`函数显式确认消息。这是必要的，因为我们之前将`Consume()`函数的`autoAck`参数设置为 false。

显式确认消息具有重要目的——如果您的消费者在接收和确认消息之间由于任何原因失败，消息将被放回队列，然后重新传递给另一个消费者（或者如果没有其他消费者，则留在队列中）。因此，消费者应该只在完成处理消息时确认消息。如果消息在消费者实际处理之前就被确认（这就是`autoAck`参数会导致的情况），然后消费者意外死机，消息将永远丢失。因此，显式确认消息是使系统具有弹性和容错性的重要步骤。

# 构建事件发射器

在前面的例子中，我们使用 AMQP 通道从发布者向订阅者发送简单的字符串消息。为了使用 AMQP 构建实际的发布/订阅架构，我们需要传输更复杂的带有结构化数据的消息。一般来说，每个 AMQP 消息只是一串字节。为了提交结构化数据，我们可以使用序列化格式，比如 JSON 或 XML。此外，由于 AMQP 不限于 ASCII 消息，我们还可以使用二进制序列化协议，比如`MessagePack`或`ProtocolBuffers`。

无论您决定使用哪种序列化格式，您都需要确保发布者和订阅者都了解序列化格式和消息的实际内部结构。

关于序列化格式，我们将在本章中选择简单的 JSON 序列化格式。它被广泛采用；使用 Go 标准库和其他编程语言（这一点很重要——尽管在本书中我们专门致力于 Go，但在微服务架构中，有许多不同的应用运行时是很常见的）轻松地进行序列化和反序列化消息。

我们还需要确保发布者和订阅者都知道消息的结构。例如，一个`LocationCreated`事件可能有一个`name`属性和一个`address`属性。为了解决这个问题，我们将引入一个共享库，其中包含所有可能事件的结构定义，以及 JSON（反）序列化的说明。然后，这个库可以在发布者和所有订阅者之间共享。

首先在您的 GOPATH 中创建`todo.com/myevents/contracts`目录。我们将描述的第一种事件类型是`EventCreatedEvent`事件。当创建新事件时，此消息将由事件服务发布。让我们在新创建的包的`event_created.go`文件中将此事件定义为一个结构：

```go
package contracts 

import "time" 

type EventCreatedEvent struct { 
  ID         string    `json:"id"` 
  Name       string    `json:"id"` 
  LocationID string    `json:"id"` 
  Start      time.Time `json:"start_time"` 
  End        time.Time `json:"end_time"` 
} 
```

此外，我们需要为每个事件生成一个主题名称（在 RabbitMQ 中，主题名称也将用作消息的路由键）。为此，请向您新定义的结构添加一个新方法——`EventName()`：

```go
func (e *EventCreatedEvent) EventName() string { 
  return "event.created" 
} 
```

我们现在可以使用 Go 接口来定义一个通用的事件类型。这种类型可以用来强制每种事件类型实际上都实现了一个`EventName()`方法。由于事件发布者和事件订阅者以后也将被用于多个服务，我们将事件接口代码放入`todo.com/myevents/lib/msgqueue`包中。首先创建包目录和一个新文件`event.go`：

```go
package msgqueue 

type Event interface { 
  EventName() string 
} 
```

当然，我们的示例应用程序使用的事件不仅仅是`EventCreatedEvent`。例如，我们还有一个`LocationCreatedEvent`和一个`EventBookedEvent`。由于在打印中显示它们的所有实现会相当重复，我们希望在本章的示例文件中查看它们。

让我们现在继续构建一个事件发射器，它可以实际将这些消息发布到 AMQP 代理。由于我们将在本章的后面部分探索其他消息代理，因此我们将首先定义任何事件发射器应该满足的接口。为此，在之前创建的`msgqueue`包中创建一个`emitter.go`文件，内容如下：

```go
package msgqueue 

type EventEmitter interface { 
  Emit(event Event) error 
} 
```

此接口描述了所有事件发射器实现需要满足的方法（实际上只有一个方法）。让我们继续创建一个`todo.com/myevents/lib/msgqueue/amqp`子包，其中包含一个`emitter.go`文件。该文件将包含`AMQPEventEmitter`的结构定义。

考虑以下代码示例：

```go
package amqp 

import "github.com/streadway/amqp" 

type amqpEventEmitter struct { 
  connection *amqp.Connection 
} 
```

请注意`amqpEventEmitter`类型声明为包私有，因为它使用小写名称声明。这将阻止用户直接实例化`amqpEventEmitter`类型。为了正确实例化，我们将提供一个构造方法。

接下来，让我们添加一个`setup`方法，我们可以用来声明此发布者将要发布到的交换机：

```go
func (a *amqpEventEmitter) setup() error {
   channel, err := a.connection.Channel()
   if err != nil {
     return err
   }

   defer channel.Close() 

  return channel.ExchangeDeclare("events", "topic", true, false, false, false, nil) 
 } 
```

您可能想知道为什么我们在此方法中创建了一个新的 AMQP 通道，并在声明交换机后立即关闭它。毕竟，我们可以在以后重用相同的通道来发布消息。我们稍后会解决这个问题。

继续添加一个构造函数`NewAMQPEventEmitter`，用于构建此结构的新实例：

```go
func NewAMQPEventEmitter(conn *amqp.Connection) (EventEmitter, error) { 
  emitter := &amqpEventEmitter{ 
    connection: conn, 
  } 

  err := emitter.setup()
   if err != nil { 
    return nil, err 
  } 

  return emitter, nil 
} 
```

现在，到`amqpEventEmitter`事件的实际核心——`Emit`方法。首先，我们需要将作为参数传递给方法的事件转换为 JSON 文档：

```go
import "encoding/json"

 // ...

 func (a *amqpEventEmitter) Emit(event Event) error { 
  jsonDoc, err := json.Marshal(event) 
  if err != nil { 
    return err 
  } 
} 
```

接下来，我们可以创建一个新的 AMQP 通道，并将我们的消息发布到事件交换机中：

```go
func (a *amqpEventEmitter) Emit(event Event) error { 
  // ... 

  chan, err := a.connection.Channel(); 
  if err != nil { 
    return err 
  } 

  defer chan.Close() 

  msg := amqp.Publishing{ 
    Headers:     amqpTable{"x-event-name": event.EventName()}, 
    Body:        jsonDoc, 
    ContentType: "application/json", 
  } 

  return chan.Publish( 
    "events", 
    event.EventName(), 
    false, 
    false, 
    msg 
  ) 
} 
```

请注意，我们使用`amqp.Publishing`的`Headers`字段来将事件名称添加到特殊的消息头中。这将使我们更容易实现事件监听器。

还要注意，在此代码中，我们为每个发布的消息创建了一个新通道。虽然理论上可以重用相同的通道来发布多个消息，但我们需要记住，单个 AMQP 通道不是线程安全的。这意味着从多个 go 协程调用事件发射器的`Emit()`方法可能会导致奇怪和不可预测的结果。这正是 AMQP 通道的问题所在；使用多个通道，多个线程可以使用相同的 AMQP 连接。

接下来，我们可以将新的事件发射器集成到您已经在第二章和第三章中构建的现有事件服务中。首先，在`ServiceConfig`结构中添加一个 AMQP 代理的配置选项：

```go
type ServiceConfig struct { 
  // ... 
  AMQPMessageBroker string `json:"amqp_message_broker"` 
} 
```

这使您可以通过 JSON 配置文件指定 AMQP 代理。在`ExtractConfiguration()`函数中，我们还可以添加一个备用选项，如果设置了环境变量，则可以从中提取此值：

```go
func ExtractConfiguration(filename string) ServiceConfig { 
  // ... 

  json.NewDecoder(file).Decode(&conf) 
  if broker := os.Getenv("AMQP_URL"); broker != "" { 
    conf.AMQPMessageBroker = broker 
  } 

  return conf 
} 
```

现在，我们可以在事件服务的`main`函数中使用此配置选项来构造一个新的事件发射器：

```go
package main 

// ... 
import "github.com/streadway/amqp" 
import msgqueue_amqp "todo.com/myevents/lib/msgqueue/amqp" 

func main() { 
  // ... 

  config := configuration.ExtractConfiguration(*confPath) 
  conn, err := amqp.Dial(config.AMQPMessageBroker) 
  if err != nil { 
    panic(err) 
  } 

  emitter, err := msgqueue_amqp.NewAMQPEventEmitter(conn) 
  if err != nil { 
    panic(err) 
  } 

  // ... 
} 
```

现在，我们可以将此事件发射器传递给`rest.ServeAPI`函数，然后再传递给`newEventHandler`函数：

```go
func ServeAPI(endpoint string, dbHandler persistence.DatabaseHandler, eventEmitter msgqueue.EventEmitter) error { 
  handler := newEventHandler(dbHandler, eventEmitter) 
  // ... 
} 
```

然后，事件发射器可以作为`eventServiceHandler`结构的字段存储：

```go
type eventServiceHandler struct { 
  dbhandler persistence.DatabaseHandler 
  eventEmitter msgqueue.EventEmitter 
} 

func newEventHandler(dbhandler persistence.DatabaseHandler, eventEmitter msgqueue.EventEmitter) *eventServiceHandler { 
  return &eventServiceHandler{ 
    dbhandler: dbhandler, 
    eventEmitter: eventEmitter, 
  } 
} 
```

现在，`eventServiceHandler`持有对事件发射器的引用，您可以在实际的 REST 处理程序中使用它。例如，通过 API 创建新事件时，您可以发出`EventCreatedEvent`。为此，请修改`eventServiceHandler`的`newEventHandler`方法如下：

```go
func (eh *eventServiceHandler) newEventHandler(w http.ResponseWriter, r *http.Request) { 
  id, err := eh.dbhandler.AddEvent(event) 
  if err != nil { 
    // ... 
  } 

  msg := contracts.EventCreatedEvent{ 
    ID: hex.EncodeToString(id), 
    Name: event.Name, 
    LocationID: event.Location.ID, 
    Start: time.Unix(event.StartDate, 0), 
    End: time.Unix(event.EndDate, 0), 
  } 
  eh.eventEmitter.emit(&msg) 

  // ... 
} 
```

# 构建事件订阅者

现在我们可以使用`EventEmitter`在`RabbitMQ`代理上发布事件，我们还需要一种方法来监听这些事件。这将是我们将在本节中构建的`EventListener`的目的。

与之前一样，让我们首先定义所有事件监听器（AMQP 事件监听器是其中之一）应该满足的接口。为此，在`todo.com/myevents/lib/msgqueue`包中创建`listener.go`文件：

```go
package msgqueue 

type EventListener interface { 
  Listen(eventNames ...string) (<-chan Event, <-chan error, error) 
} 
```

这个接口看起来与事件发射器的接口有很大不同。这是因为对事件发射器的每次调用`Emit()`方法只是立即发布一条消息。然而，事件监听器通常会长时间处于活动状态，并且需要在接收到消息时立即做出反应。这反映在我们的`Listen()`方法的设计中：首先，它将接受事件监听器应该监听的事件名称列表。然后返回两个 Go 通道：第一个将用于流式传输事件监听器接收到的任何事件。第二个将包含接收这些事件时发生的任何错误。

首先通过在`todo.com/myevents/lib/msgqueue/amqp`包中创建一个新的`listener.go`文件来构建 AMQP 实现：

```go
package amqp 

import "github.com/streadway/amqp" 

type amqpEventListener struct { 
  connection *amqp.Connection 
  queue      string 
} 
```

类似于事件发射器，继续添加一个`setup`方法。在这个方法中，我们需要声明监听器将要消费的 AMQP 队列：

```go
func (a *ampqEventListener) setup() error { 
  channel, err := a.connection.Channel() 
  if err != nil { 
    return nil 
  } 

  defer channel.Close() 

  _, err := channel.QueueDeclare(a.queue, true, false, false, false, nil) 
  return err 
} 
```

请注意，监听器将要消费的队列的名称可以使用`amqpEventListener`结构的`queue`字段进行配置。这是因为以后，多个服务将使用事件监听器来监听它们的事件，并且每个服务都需要自己的 AMQP 队列。

您可能已经注意到，我们尚未将新声明的队列绑定到事件交换机。这是因为我们还不知道我们实际上需要监听哪些事件（记住`Listen`方法的`events`参数吗？）。

最后，让我们添加一个构造函数来创建新的 AMQP 事件监听器：

```go
func NewAMQPEventListener(conn *amqp.Connection, queue string) (msgqueue.EventListener, error) { 
  listener := &amqpEventListener{ 
    connection: conn, 
    queue:      queue, 
  } 

  err := listener.setup() 
  if err != nil { 
    return nil, err 
  } 

  return listener, nil 
} 
```

有了构建新的 AMQP 事件监听器的可能性，让我们实现实际的`Listen()`方法。首先要做的是使用`eventNames`参数并相应地绑定事件队列：

```go
func (a *amqpEventListener) Listen(eventNames ...string) (<-chan msgqueue.Event, <-chan error, error) { 
  channel, err := a.connection.Channel() 
  if err != nil { 
    return nil, nil, err 
  } 

  defer channel.Close() 

  for _, eventName := range eventNames { 
    if err := channel.QueueBind(a.queue, eventName, "events", false, nil); err != nil { 
      return nil, nil, err 
    } 
  } 
} 
```

接下来，我们可以使用通道的`Consume()`方法从队列中接收消息：

```go
func (a *amqpEventListener) Listen(eventNames ...string) (<-chan msgqueue.Event, <-chan error, error) { 
  // ... 

  msgs, err := channel.Consume(a.queue, "", false, false, false, false, nil) 
  if err != nil { 
    return nil, nil, err 
  } 
} 
```

`msgs`变量现在持有`amqp.Delivery`结构的通道。然而，我们的事件监听器应该返回一个`msgqueue.Event`的通道。这可以通过在我们自己的 goroutine 中消费`msgs`通道，构建相应的事件结构，然后将这些事件发布到我们从这个函数返回的另一个通道中来解决：

```go
func (a *amqpEventListener) Listen(eventNames ...string) (<-chan msgqueue.Event, <-chan error, error) { 
  // ... 

  events := make(chan msgqueue.Event) 
  errors := make(errors) 

  go func() { 
    for msg := range msgs { 
      // todo: Map message to actual event struct 
    } 
  }() 

  return events, errors, nil 
} 
```

现在棘手的部分在于内部 goroutine 中。在这里，我们需要将原始的 AMQP 消息映射到实际的事件结构之一（如之前定义的`EventCreatedEvent`）。

还记得 EventEmitter 在发布事件时向 AMQP 消息添加了额外的`x-event-name`头部吗？现在我们可以使用这个来将这些消息映射回它们各自的结构类型。让我们从 AMQP 消息头中提取事件名称开始：

以下所有代码都放在`Listen`方法的内部`range`循环中。

```go
rawEventName, ok := msg.Headers["x-event-name"] 
if !ok { 
  errors <- fmt.Errorf("msg did not contain x-event-name header") 
  msg.Nack(false) 
  continue 
} 

eventName, ok := rawEventName.(string) 
if !ok { 
  errors <- fmt.Errorf( 
    "x-event-name header is not string, but %t", 
    rawEventName 
  ) 
  msg.Nack(false) 
  continue 
} 
```

前面的代码尝试从 AMQP 消息中读取`x-event-name`头部。由于`msg.Headers`属性基本上是一个`map[string]interface{}`，我们需要一些映射索引和类型断言，直到我们实际使用事件名称。如果接收到不包含所需头部的消息，将向错误通道写入错误。此外，消息将被 nack'ed（简称否定确认），表示经纪人无法成功处理该消息。

知道事件名称后，我们可以使用简单的 switch/case 结构从这个名称创建一个新的事件结构：

```go
var event msgqueue.Event 

switch eventName { 
  case "event.created": 
    event = new(contracts.EventCreatedEvent) 
  default: 
    errors <- fmt.Errorf("event type %s is unknown", eventName) 
    continue 
} 

err := json.Unmarshal(msg.Body, event) 
if err != nil { 
  errors <- err 
  continue 
} 

events <- event 
```

# 构建预订服务

现在我们有了一个事件监听器，我们可以使用它来实现预订服务。它的一般架构将遵循事件服务的架构，因此我们不会过多地详细介绍这个问题。

首先创建一个新的包`todo.com/myevents/bookingservice`，并创建一个新的`main.go`文件：

```go
package main 

import "github.com/streadway/amqp" 
import "todo.com/myevents/lib/configuration" 
import msgqueue_amqp "todo.com/myevents/lib/msgqueue/amqp" 
import "flag" 

func main() { 
  confPath := flag.String("config", "./configuration/config.json", "path to config file") 
  flag.Parse() 
  config := configuration.ExtractConfiguration(*confPath) 

  dblayer, err := dblayer.NewPersistenceLayer(config.Databasetype, config.DBConnection) 
  if err != nil { 
    panic(err) 
  } 

  conn, err := amqp.Dial(config.AMQPMessageBroker) 
  if err != nil { 
    panic(err) 
  } 

  eventListener, err := msgqueue_amqp.NewAMQPEventListener(conn) 
  if err != nil { 
    panic(err) 
  } 
} 
```

这将使用数据库连接和工作事件监听器设置预订服务。现在我们可以使用这个事件监听器来监听事件服务发出的事件。为此，添加一个新的子包`todo.com/myevents/bookingservice/listener`并创建一个新的`event_listener.go\`文件：

```go
package listener 

import "log" 
import "todo.com/myevents/lib/msgqueue" 
import "todo.com/myevents/lib/persistence" 
import "gopkg.in/mgo.v2/bson" 

type EventProcessor struct { 
  EventListener msgqueue.EventListener 
  Database      persistence.DatabaseHandler 
} 

func (p *EventProcessor) ProcessEvents() error { 
  log.Println("Listening to events...") 

  received, errors, err := p.EventListener.Listen("event.created") 
  if err != nil { 
    return err 
  } 

  for { 
    select { 
      case evt := <-received: 
        p.handleEvent(evt) 
      case err = <-errors: 
        log.Printf("received error while processing msg: %s", err) 
    } 
  } 
} 
```

在`ProcessEvents()`函数中，我们调用事件监听器的`Listen`函数来监听新创建的事件。`Listen`函数返回两个通道，一个用于接收消息，一个用于监听期间发生的错误。然后我们将使用一个无限运行的 for 循环和一个 select 语句同时从这两个通道中读取。接收到的事件将传递给`handleEvent`函数（我们仍然需要编写），接收到的错误将简单地打印到标准输出。

让我们继续使用`handleEvent`函数：

```go
func (p *EventProcessor) handleEvent(event msgqueue.Event) { 
  switch e := event.(type) { 
    case *contracts.EventCreatedEvent: 
      log.Printf("event %s created: %s", e.ID, e) 
      p.Database.AddEvent(persistence.Event{ID: bson.ObjectId(e.ID)}) 
    case *contracts.LocationCreatedEvent: 
      log.Printf("location %s created: %s", e.ID, e) 
      p.Database.AddLocation(persistence.Location{ID: bson.ObjectId(e.ID)}) 
    default: 
      log.Printf("unknown event: %t", e) 
  } 
} 
```

这个函数使用类型开关来确定传入事件的实际类型。目前，我们的事件监听器通过将`EventCreated`和`LocationCreated`两个事件存储在它们的本地数据库中来处理这两个事件。

在这个例子中，我们使用了一个共享库`todo.com/myevents/lib/persistence`来管理数据库访问。这仅仅是为了方便。在真实的微服务架构中，各个微服务通常使用完全独立的持久化层，可能构建在完全不同的技术栈上。

在我们的`main.go`文件中，现在可以实例化`EventProcessor`并调用`ProcessEvents()`函数：

```go
func main() { 
  // ... 

  eventListener, err := msgqueue_amqp.NewAMQPEventListener(conn) 
  if err != nil { 
    panic(err) 
  } 

  processor := &listener.EventProcessor{eventListener, dblayer} 
  processor.ProcessEvents() 
} 
```

除了监听事件，预订服务还需要实现自己的 REST API，用户可以用来预订指定事件的门票。这将遵循您已经在第二章和第三章中学到的相同原则，*使用 Rest API 构建微服务*和*保护微服务*。因此，我们将避免详细解释预订服务的 REST API，并只描述要点。您可以在本章的代码示例中找到 REST 服务的完整实现。

在`main.go`文件中，我们需要将`processor.ProcessEvents()`调用移到自己的 go-routine 中。否则，它会阻塞，程序永远不会达到`ServeAPI`方法调用：

```go
func main() { 
  // ... 

  processor := &listener.EventProcessor{eventListener, dblayer} 
  go processor.ProcessEvents() 

  rest.ServeAPI(config.RestfulEndpoint, dbhandler, eventEmitter) 
} 
```

最后，我们将转向实际的请求处理程序。它在`/events/{eventID}/bookings`注册为 POST 请求；它会检查当前为该事件放置了多少预订，并且事件的位置是否仍然有容量可以再预订一次。在这种情况下，它将创建并持久化一个新的预订，并发出一个`EventBooked`事件。查看示例文件以查看完整的实现。

# 事件溯源

使用异步消息传递构建应用程序为应用一些高级架构模式打开了大门，其中之一将在本节中学习。

在使用消息传递、发布/订阅和事件协作时，整个系统状态的每一次变化都以一个事件的形式反映出来，该事件由参与服务中的一个发出。通常，这些服务中的每一个都有自己的数据库，保持对系统状态的自己视图（至少是所需的），并通过不断监听其他服务发布的事件来保持最新。

然而，系统状态的每一次变化都由一个已发布的事件表示，这提供了一个有趣的机会。想象一下，有人记录并保存了任何人发布的每一个事件到事件日志中。理论上（也在实践中），你可以使用这个事件日志来重建整个系统状态，而不必依赖任何其他类型的数据库。

举个例子，考虑以下（小）事件日志：

1.  上午 8:00—用户＃1 名称为爱丽丝被创建

1.  上午 9:00—用户＃2 名称为鲍勃被创建

1.  下午 1:00—用户＃1 被删除

1.  下午 3:00—用户＃2 将名称更改为塞德里克

通过重放这些事件，很容易重建系统在一天结束时的状态——有一个名为塞德里克的用户。然而，还有更多。由于每个事件都有时间戳，你可以重建应用在任何给定时间点的状态（例如，在上午 10:00，你的应用有两个用户，爱丽丝和鲍勃）。

除了点对点恢复，事件溯源还为你提供了系统中发生的一切的完整审计日志。审计日志通常在许多情况下是一个实际的要求，但也使得在出现错误时更容易调试系统。拥有完整的事件日志可以让你在确切的时间点复制系统的状态，然后逐步重放事件，以实际重现特定的错误。

此外，事件日志使各个服务不那么依赖其本地数据库。在极端情况下，你可以完全放弃数据库，并让每个服务在启动时从事件日志中内存重建其整个查询模型。

# 使用 Apache Kafka 实现发布/订阅和事件溯源

在本章的其余部分，我们不会构建自己的事件溯源系统。之前，我们使用 RabbitMQ 来实现服务之间的消息传递。然而，RabbitMQ 只处理消息分发，因此如果你需要一个包含所有事件的事件日志，你需要自己实现它，监听所有事件并持久化它们。你还需要自己处理事件重放。

Apache Kafka 是一个分布式消息代理，还附带一个集成的事务日志。它最初是由 LinkedIn 构建的，并作为 Apache 许可下的开源产品提供。

在前面的部分中，我们已经使用 AMQP 连接构建了`EventEmitter`和`EventListener`接口的实现。在本节中，我们将使用 Kafka 来实现相同的接口。

# 使用 Docker 快速开始 Kafka

与 RabbitMQ 相反，Apache Kafka 设置起来要复杂一些。Kafka 本身需要一个工作的 Zookeeper 设置，以进行领导者选举、管理集群状态和持久化集群范围的配置数据。然而，为了开发目的，我们可以使用`spotify/kafka`镜像。该镜像带有内置的 Zookeeper 安装，可以快速轻松地设置。

就像之前的 RabbitMQ 图像一样，使用`docker run`命令快速开始：

```go
$ docker run -d --name kafka -p 9092:9092 spotify/kafka
```

这将启动一个单节点 Kafka 实例，并将其绑定到本地主机的 TCP 端口`9092`。

# Apache Kafka 的基本原则

Kafka 提供了一个发布/订阅消息代理，但不是基于 AMQP，因此使用不同的术语。

Kafka 中的第一个基本概念是主题。主题类似于订阅者可以写入的类别或事件名称。它包含了曾经发布到该主题的所有消息的完整日志。每个主题分为可配置数量的分区。当发布新消息时，需要包含一个分区键。代理使用分区键来决定消息应写入主题的哪个分区。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/228af662-564a-48ba-90ca-d1c11e87a40f.png)

每个 Kafka 主题由可配置数量的分区组成；每个发布的消息都有一个分区键，用于决定消息应保存到哪个分区

Kafka 代理保证在每个分区内，消息的顺序与发布时的顺序相同。对于每个主题，消息将保留一段可配置的保留期。然而，当事务日志变得更大时，代理的性能并不会显著下降。因此，完全可以使用无限的保留期操作 Kafka，并以此方式将其用作事件日志。当然，您需要考虑所需的磁盘存储将成比例增长。幸运的是，Kafka 对水平扩展支持得相当好。

从每个主题，任意数量的订阅者（在 Kafka 行话中称为 *消费者*）可以读取消息，任意数量的发布者（*生产者*）可以写入消息。每个消费者都可以定义从事件日志的哪个偏移量开始消费。例如，一个刚初始化的只在内存中操作的消费者可以从头（偏移量 = `0`）读取整个事件日志以重建其整个查询模型。另一个只有本地数据库并且只需要在某个时间点之后发生的新事件的消费者可以从稍后的时间点开始读取事件日志。

每个消费者都是消费者组的成员。在给定主题中发布的消息将发布到每个组的一个消费者。这可以用来实现发布/订阅通信，类似于我们已经使用 AMQP 构建的内容。以下图表说明了使用 AMQP 和 Kafka 架构的发布/订阅中的不同术语和角色。在这两种情况下，发布在交换/主题中的每条消息都将路由到每个消费者。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/27552bd3-67e3-4bf0-9a6b-7a99d8bdef10.png)

使用 AMQP（1）和 Apache Kafka（2）进行发布/订阅；在交换/主题中发布的每条消息都会路由到每个订阅者

在 AMQP 中，也可以有多个订阅者监听同一个队列。在这种情况下，传入的消息将不会路由到所有订阅者，而是路由到其中一个已连接的订阅者。这可以用来在不同的订阅者实例之间构建某种负载均衡。

在 Kafka 中，可以通过将多个订阅者实例放入同一消费者组来实现相同的功能。然而，在 Kafka 中，每个订阅者被分配到一个固定的（可能是多个）分区。因此，可以并行消费主题的消费者数量受到主题分区数量的限制。以下图表说明了这个例子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/00d574d2-a4b6-4166-a6c2-9b88b89e846a.png)

使用 AMQP（1）和 Apache Kafka（2）进行负载均衡；在交换/主题中发布的每条消息都会路由到已连接的订阅者之一

如果决定在同一消费者组中有多个消费者订阅主题的同一分区，代理将简单地将该分区中的所有消息分派给最后连接的消费者。

# 使用 Go 连接到 Kafka

在本章的前几节中，我们连接到 AMQP 代理时使用了事实上的标准库 `github.com/streadway/amqp`。连接到 Kafka 代理时，可用的 Go 库之间存在更多的多样性。在撰写本书时，Go 中最受欢迎的 Kafka 客户端库如下：

1.  `github.com/Shopify/sarama` 提供完整的协议支持，是纯 Go 实现的。它是根据 MIT 许可证授权的。它是维护活跃的。

1.  `github.com/elodina/go_kafka_client` 也是纯 Go 实现的。它提供的功能比 `Shopify` 库更多，但似乎维护活跃度较低。它是根据 Apache 许可证授权的。

1.  `github.com/confluentinc/confluent-kafka-go`为`librdkafka` C 库提供了一个 Go 包装器（这意味着您需要在系统上安装`librdkafka`才能使此库工作）。据说它比`Shopify`库更快，因为它依赖于高度优化的 C 库。不过，出于同样的原因，它可能难以构建。它正在积极维护，尽管其社区似乎比`Shopify`库小。

在本章中，我们将使用`github.com/Shopify/sarama`库。通过`go get`安装它：

```go
$ go get github.com/Shopify/sarama
```

在前面的部分中，我们已经在`todo.com/myevents/lib/msgqueue`包中定义了`EventEmitter`和`EventListener`接口。在本节中，我们将为这两个接口添加替代实现。在深入之前，让我们快速看一下如何使用`sarama`库来连接到 Kafka 代理。

无论您是打算发布还是消费消息，您都需要首先实例化`sarama.Client`结构。为此，您可以使用`sarama.NewClient`函数。要实例化一个新客户端，您需要 Kafka 代理地址的列表（记住，Kafka 设计为在集群中运行，因此您实际上可以同时连接到许多集群代理）和一个配置对象。创建配置对象的最简单方法是使用`sarama.NewConfig`函数：

```go
import "github.com/Shopify/sarama" 

func main() { 
  config := sarama.NewConfig() 
  brokers := []string{"localhost:9092"} 
  client, err := sarama.NewClient(brokers, config) 

  if err != nil { 
    panic(err) 
  } 
} 
```

当然，在开发设置中，将`localhost`作为单个代理工作正常。对于生产设置，代理列表应从环境中读取：

```go
func main() { 
  brokerList := os.Getenv("KAFKA_BROKERS") 
  if brokerList == "" { 
    brokerList = "localhost:9092" 
  } 

  brokers := strings.Split(brokerList, ",") 
  config := sarama.NewConfig() 

  client, err := sarama.NewClient(brokers, config) 
  // ... 
} 
```

您可以使用`config`对象来微调 Kafka 连接的各种参数。对于大多数情况，默认设置就可以了。

# 使用 Kafka 发布消息

Sarama 库提供了两种发布消息的实现——`sarama.SyncProducer`和`sarama.AsyncProducer`。

`AsyncProducer`提供了一个异步接口，使用 Go 通道来发布消息并检查这些操作的成功。它允许高吞吐量的消息，但如果您只想发出单个消息，使用起来有点笨重。因此，`SyncProducer`提供了一个更简单的接口，它接受一个用于生产的消息，并在从代理接收到消息已成功发布到事件日志的确认之前阻塞。

您可以使用`sarama.NewSyncProducerFromClient`和`sarama.NewAsyncProducerFromClient`函数实例化一个新的生产者。在我们的示例中，我们将使用`SyncProducer`，您可以按以下方式创建：

```go
producer, err := sarama.NewSyncProducerFromClient(client) 
if err != nil { 
  panic(err) 
} 
```

让我们继续使用`SyncProducer`来创建我们的`EventEmitter`接口的 Kafka 实现。首先创建`todo.com/myevents/lib/msgqueue/kafka`包和该包中的`emitter.go`文件：

```go
package kafka 

type kafkaEventEmitter struct { 
  producer sarama.SyncProducer 
} 
```

继续添加一个构造函数来实例化这个结构：

```go
func NewKafkaEventEmitter(client sarama.Client) (msgqueue.EventEmitter, error) { 
  producer, err := sarama.NewSyncProducerFromClient(client) 
  if err != nil { 
    return nil, err 
  } 

  emitter := &kafkaEventEmitter{ 
    producer: producer, 
  } 

  return emitter, nil 
} 
```

为了发送消息，您需要构建`sarama.ProducerMessage`结构的实例。为此，您需要主题（在我们的情况下，由`msgqueue.Event`的`EventName()`方法提供）和实际的消息正文。正文需要作为`sarama.Encoder`接口的实现提供。您可以使用`sarama.ByteEncoder`和`sarama.StringEncoder`类型，将字节数组或字符串简单地强制转换为`Encoder`实现：

```go
func (e *kafkaEventEmitter) Emit(event msgqueue.Event) error { 
  jsonBody, err := json.Marshal(event) 
  if err != nil { 
    return err 
  } 

  msg := &sarama.ProducerMessage{ 
    Topic: event.EventName(), 
    Value: sarama.ByteEncoder(jsonBody), 
  } 

  _, _, err = e.producer.SendMessage(msg) 
  return err 
} 
```

在此代码示例中，关键是生产者的`SendMessage()`方法。请注意，我们实际上忽略了此方法的一些返回值。前两个返回值返回了消息写入的分区号和消息在事件日志中的偏移量。

前面的代码是有效的，但有一个致命的缺陷：它为每种事件类型创建了一个新的 Kafka 主题。虽然订阅者完全可以同时消费多个主题，但无法保证处理顺序。这可能导致生产者按顺序短时间内依次发出`位置#1 创建`和`位置#1 更新`，而订阅者按照不同的顺序接收它们。

为了解决这个问题，我们需要做两件事：

+   所有消息必须发布在同一个主题上。这意味着我们需要另一种方法在消息中存储实际的事件名称。

+   每条消息必须公开一个分区键。我们可以使用消息的分区键来确保涉及相同实体的消息（即相同事件，相同用户）存储在事件日志的单个分区中，并且按顺序路由到相同的消费者。

让我们从分区键开始。还记得`todo.com/myevents/lib/msgqueue`包中的`Event`接口吗？它看起来是这样的：

```go
package msgqueue 

type Event interface { 
  EventName() string 
} 
```

继续添加一个新的`PartitionKey()`方法到这个接口：

```go
package msgqueue 

type Event interface { 
  PartitionKey() string 
  EventName() string 
} 
```

接下来，我们可以修改之前定义的现有事件结构（例如`EventCreatedEvent`）来实现这个`PartitionKey()`方法：

```go
func (e *EventCreatedEvent) PartitionKey() string { 
  return e.ID 
} 
```

现在，让我们回到`kafkaEventEmitter`。我们现在可以在将消息发布到 Kafka 时使用每个事件的`PartitionKey()`方法。现在，我们只需要在事件旁边发送事件名称。为了解决这个问题，我们将在`todo.com/myevents/lib/msgqueue/kafka`包的新文件`payload.go`中定义这个事件：

```go
package kafka 

type messageEnvelope struct { 
  EventName string      `json:"eventName"` 
  Payload   interface{} `json:"payload"` 
} 
```

现在，我们可以调整`kafkaEventEmitter`，首先构造`messageEnvelope`结构的实例，然后对其进行 JSON 序列化：

```go
func (e *kafkaEventEmitter) Emit(event msgqueue.Event) error { 
  envelope := messageEnvelope{event.EventName(), event} 
  jsonBody, err := json.Marshal(&envelope) 
  // ... 
```

# 从 Kafka 消费消息

从 Kafka 代理服务器消费消息比在 AMQP 中更复杂一些。您已经了解到 Kafka 主题可能由许多分区组成，每个消费者可以消费一个或多个（最多全部）这些分区。Kafka 架构允许通过将主题分成更多分区并让一个消费者订阅每个分区来进行水平扩展。

这意味着每个订阅者都需要知道主题的哪些分区存在，以及它应该消费其中的哪些。我们在本节中介绍的一些库（尤其是 Confluent 库）实际上支持自动订阅者分区和自动组平衡。`sarama`库不提供此功能，因此我们的`EventListener`将需要手动选择要消费的分区。

对于我们的示例，我们将实现`EventListener`，以便默认情况下监听主题的所有可用分区。我们将添加一个特殊属性，用于明确指定要监听的分区。

在`todo.com/myevents/lib/msgqueue/kafka`包中创建一个新文件`listener.go`：

```go
package kafka 

import "github.com/Shopify/sarama" 
import "todo.com/myevents/lib/msgqueue" 

type kafkaEventListener struct { 
  consumer   sarama.Consumer 
  partitions []int32 
} 
```

继续为这个结构体添加一个构造函数：

```go
func NewKafkaEventListener(client sarama.Client, partitions []int32) (msgqueue.EventListener, error) { 
  consumer, err := sarama.NewConsumerFromClient(client) 
  if err != nil { 
    return nil, err 
  } 

  listener := &kafkaEventListener{ 
    consumer: consumer, 
    partitions: partitions, 
  } 

  return listener, nil 
} 
```

`kafkaEventListener`的`Listen()`方法遵循与我们在上一节中实现的`amqpEventListener`相同的接口：

```go
func (k *kafkaEventListener) Listen(events ...string) (<-chan msgqueue.Event, <-chan error, error) { 
  var err error 

  topic := "events" 
  results := make(chan msgqueue.Event) 
  errors := make(chan error) 
} 
```

首先要做的是确定应该消费哪些主题分区。我们将假设当`NewKafkaEventListener`方法传递了一个空切片时，监听器应该监听所有分区：

```go
func (k *kafkaEventListener) Listen(events ...string) (<-chan msgqueue.Event, <-chan error, error) { 
  var err error 

  topic := "events" 
  results := make(chan msgqueue.Event) 
  errors := make(chan error) 

  partitions := k.partitions 
  if len(partitions) == 0 { 
    partitions, err = k.consumer.partitions(topic) 
    if err != nil { 
      return nil, nil, err 
    } 
  } 

  log.Printf("topic %s has partitions: %v", topic, partitions) 
} 
```

Sarama 消费者只能消费一个分区。如果我们想要消费多个分区，我们需要启动多个消费者。为了保持`EventListener`的接口，我们将在`Listen()`方法中启动多个消费者，每个消费者在自己的 goroutine 中运行，然后让它们都写入同一个结果通道：

```go
func (k *kafkaEventListener) Listen(events ...string) (<-chan msgqueue.Event, <-chan error, error) { 
  // ... 

  log.Printf("topic %s has partitions: %v", topic, partitions) 

  for _, partitions := range partitions { 
    con, err := k.consumer.ConsumePartition(topic, partition, 0) 
    if err != nil { 
      return nil, nil, err 
    } 

    go func() { 
      for msg := range con.Messages() { 

      } 
    }() 
  } 
} 
```

注意在第一个 for 循环内启动的 goroutines。其中每个都包含一个内部 for 循环，遍历给定分区中接收到的所有消息。现在我们可以对传入的消息进行 JSON 解码，并重建适当的事件类型。

以下所有代码示例都放置在`kafkaEventListener`的`Listen()`方法的内部 for 循环中。

```go
for msg := range con.Messages() { 
  body := messageEnvelope{} 
  err := json.Unmarshal(msg.Value, &body) 
  if err != nil { 
    errors <- fmt.Errorf("could not JSON-decode message: %s", err) 
    continue 
  } 
} 
```

现在我们有一个新问题。我们已经将事件主体解组为`messageEnvelope`结构。这包含了事件名称和实际事件主体。然而，事件主体只是被定义为`interface{}`。理想情况下，我们需要将这个`interface{}`类型转换回正确的事件类型（例如，`contracts.EventCreatedEvent`），这取决于事件名称。为此，我们可以使用`github.com/mitchellh/mapstructure`包，您可以通过 go get 安装：

```go
$ go get -u github.com/mitchellh/mapstructure
```

`mapstructure`库的工作方式类似于`encoding/json`库，只是它不接受`[]byte`输入变量，而是通用的`interface{}`输入值。这允许您接受未知结构的 JSON 输入（通过在`interface{}`值上调用`json.Unmarshal`），然后将已解码的未知结构类型映射到已知的结构类型：

```go
for msg := range con.Messages() { 
  body := messageEnvelope{} 
  err := json.Unmarshal(msg.Value, &body) 
  if err != nil { 
    errors <- fmt.Errorf("could not JSON-decode message: %s", err) 
    continue 
  } 

  var event msgqueue.Event 
  switch body.EventName { 
    case "event.created": 
      event = contracts.EventCreatedEvent{} 
    case "location.created": 
      event = contracts.LocationCreatedEvent{} 
    default: 
      errors <- fmt.Errorf("unknown event type: %s", body.EventName) 
      continue 
  } 

  cfg := mapstructure.DecoderConfig{ 
    Result: event, 
    TagName: "json", 
  } 
  err = mapstructure.NewDecoder(&cfg).Decode(body.Payload) 
  if err != nil { 
    errors <- fmt.Errorf("could not map event %s: %s", body.EventName, err) 
  } 
} 
```

在实际解码之前创建的`mapstructure.DecoderConfig`结构中的`TagName`属性指示`mapstructure`库尊重事件合同中已经存在的``json:"..."``注释。

成功解码消息后，可以将其发布到结果通道中：

```go
for msg := range con.Messages() { 
  // ...   
  err = mapstructure.NewDecoder(&cfg).Decode(body.Payload) 
  if err != nil { 
    errors <- fmt.Errorf("could not map event %s: %s", body.EventName, err) 
  } 

  results <- event 
} 
```

我们的 Kafka 事件监听器现在已经完全可用。由于它实现了`msgqueue.EventListener`接口，您可以将其用作现有 AMQP 事件监听器的即插即用替代品。

然而，有一个警告。当启动时，我们当前的 Kafka 事件监听器总是从事件日志的开头开始消费。仔细看一下前面代码示例中的`ConsumePartition`调用——它的第三个参数（在我们的例子中是`0`）描述了消费者应该开始消费的事件日志中的偏移量。

使用`0`作为偏移量将指示事件监听器从头开始读取整个事件日志。如果您想要使用 Kafka 实现事件溯源，这是理想的解决方案。如果您只想将 Kafka 用作消息代理，您的服务将需要记住从事件日志中读取的最后一条消息的偏移量。当您的服务重新启动时，您可以从上次已知的位置继续消费。

# 总结

在本章中，您学习了如何使用消息队列（如 RabbitMQ 和 Apache Kafka）集成多个服务进行异步通信。您还了解了事件协作和事件溯源等架构模式，这有助于您构建适合云部署的可扩展和弹性的应用程序。

本章中我们使用的技术与任何特定的云提供商无关。您可以轻松地在任何云基础设施或您自己的服务器上部署自己的 RabbitMQ 或 Kafka 基础设施。在第八章中，*AWS 第二部分-S3、SQS、API 网关和 DynamoDB*，我们将再次关注消息队列，这次特别关注 AWS 提供给您的托管消息解决方案。
