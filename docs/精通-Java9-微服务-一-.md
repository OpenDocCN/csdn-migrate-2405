# 精通 Java9 微服务（一）

> 原文：[`zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F`](https://zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

微服务是设计可扩展、易于维护应用程序的下一个大趋势。它们不仅使应用程序开发变得容易，还提供了极大的灵活性，以优化利用各种资源。如果你想要构建一个企业级的微服务架构实现，那么这本书就是为你准备的！

首先通过理解核心概念和框架，然后重点关注大型软件项目的高级设计。你将逐渐过渡到设置开发环境并配置它，在实现持续集成以部署你的微服务架构之前。使用 Spring Security，你会保护微服务并有效地使用 REST Java 客户端和其他工具，如 RxJava 2.0 进行测试。我们将向你展示微服务设计最佳的模式、实践和常见原则，并学会在开发过程中故障排除和调试问题。我们将向你展示如何设计和实现响应式微服务。最后，我们将向你展示如何将单体应用程序迁移到基于微服务的应用程序。

到本书结束时，你将知道如何构建更小、更轻、更快的服务，这些服务可以很容易地在生产环境中实施。

# 本书涵盖内容

第一章，*解决方案方法*，涵盖了大型软件项目的高级设计，并帮助你理解在生产环境中遇到的常见问题以及这些问题的解决方案。

第二章，*设置开发环境*，介绍了如何搭建开发环境和有效地配置 Spring Boot。你还将学习如何构建一个示例 REST 服务。

第三章，*领域驱动设计*，教你领域驱动设计的基础知识以及它是如何通过设计示例服务实际应用的。

第四章，*实现微服务*，向你展示了如何编写服务代码，然后为编写好的代码编写单元测试。

第五章，*部署与测试*，介绍了如何部署微服务并将它们开发在 Docker 上。你还将学习为微服务编写 Java 测试客户端。

第六章，*响应式微服务*，展示了如何设计和实现响应式微服务。

第七章，*保护微服务*，涵盖了不同的安全方法和实现 OAuth 的不同方式。你还将理解 Spring Security 实现。

第八章《使用 Web 应用程序消费微服务》解释了如何使用 Knockout 开发 Web 应用程序（UI）。你需要 Bootstrap JS 库来构建一个 Web 应用程序原型，该应用程序将消费微服务以显示示例项目的数据和流程——一个小型工具项目。

第九章《最佳实践和常用原则》讨论了微服务设计原则。你将学习一种有效的微服务开发方法以及 Netflix 如何实现微服务。

第十章《故障排除指南》解释了在微服务开发过程中遇到的常见问题及其解决方案。这将帮助你顺利地跟随本书，并使学习变得迅速。

第十一章《将单体应用程序迁移到基于微服务的应用程序》向你展示了如何将单体应用程序迁移到基于微服务的应用程序。

# 你需要这本书什么

对于这本书，你可以使用任何操作系统（Linux、Windows 或 Mac），最低 2 GB 的 RAM。你还需要 NetBeans 带有 Java、Maven、Spring Boot、Spring Cloud、Eureka Server、Docker 和一个 CI/CD 应用程序。对于 Docker 容器，你可能需要一个单独的虚拟机或具有尽可能 16 GB 或更多 RAM 的云主机。

# 本书适合谁

这本书是给熟悉微服务架构的 Java 开发者的，现在希望深入研究如何在企业级有效实施微服务。预计对核心微服务元素和应用程序有一定的了解。

# 约定

在这本书中，你会发现许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理方式如下所示："添加了`produceBookingOrderEvent`方法，它接受`booking`对象。"

代码块如下所示：

```java
angular.module('otrsApp.restaurants', [ 
  'ui.router', 
  'ui.bootstrap', 
  'ngStorage', 
  'ngResource' 
]) 
```

任何命令行输入或输出如下所示：

```java
npm install --no-optional gulp
```

**新术语**和**重要词汇**以粗体显示。例如，在菜单或对话框中看到的屏幕上的词汇，在文本中会以这种方式出现："在工具对话框中，选择创建 package.json、创建 bower.json 和创建 gulpfile.js。"

技巧和重要注释以这样的盒子出现。

技巧和小窍门像这样出现。

# 读者反馈

读者对我们的反馈总是受欢迎的。让我们知道您对这本书的看法——您喜欢或不喜欢的地方。读者反馈对我们很重要，因为它帮助我们开发出您将真正从中受益的标题。要发送一般性反馈，只需给`feedback@packtpub.com`发电子邮件，并在消息的主题中提到本书的标题。如果您在某个主题上有专业知识，并且有兴趣撰写或贡献一本书，请查看我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经成为 Packt 书籍的自豪拥有者，我们有很多事情可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)下载本书的示例代码文件。如果您在其他地方购买了此书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，以便将文件直接通过电子邮件发送给您。您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的 SUPPORT 标签上。

1.  点击 Code Downloads & Errata。

1.  在搜索框中输入书籍的名称。

1.  选择您要下载代码文件的书籍

1.  从下拉菜单中选择您购买本书的地方。

1.  点击 Code Download。

一旦文件下载，请确保使用最新版本解压或提取文件夹：

+   适用于 Windows 的 WinRAR / 7-Zip

+   适用于 Mac 的 Zipeg / iZip / UnRarX

+   适用于 Linux 的 7-Zip / PeaZip

该书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Mastering-Microservices-with-Java-9-Second-Edition`](https://github.com/PacktPublishing/Mastering-Microservices-with-Java-9-Second-Edition)。我们还有其他来自我们丰富的书籍和视频目录的代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！

# 勘误表

虽然我们已经尽一切努力确保我们内容的准确性，但是错误确实会发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。通过这样做，您可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击勘误提交表单链接，并输入您勘误的详细信息。一旦您的勘误得到验证，您的提交将被接受，勘误将被上传到我们的网站，或添加到该标题的勘误部分现有勘误列表中。

要查看之前提交的错误，请前往 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support) 并在搜索框中输入书籍名称。所需信息将在错误部分下方出现。

# 盗版

互联网上版权材料的盗版是一个跨所有媒体持续存在的问题。 Packt 对我们版权和许可的保护非常重视。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求解决方案。

请通过`copyright@packtpub.com`联系我们，并提供疑似盗版材料的链接。

我们非常感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

# 问题

如果您在这本书的任何一个方面遇到问题，可以通过`questions@packtpub.com`联系我们，我们将尽力解决问题。


# 第一章：解决方案方法

作为先决条件，你应该对微服务和软件架构风格有一个基本的理解。具备基本理解可以帮助你彻底理解概念和本书。

阅读本书后，你可以实现用于本地或云生产部署的微服务，并学习从设计、开发、测试到部署的完整生命周期，以及持续集成和部署。本书专为实际应用和激发您作为解决方案架构师的思维而编写。你的学习将帮助你开发和交付任何类型的场所的产品，包括 SaaS、PaaS 等。我们将主要使用 Java 和基于 Java 的框架工具，如 Spring Boot 和 Jetty，并且我们将使用 Docker 作为容器。

在本章中，你将学习微服务的永恒存在及其演变。它突出了本地和基于云的产品面临的重大问题以及微服务如何解决这些问题。它还解释了在开发 SaaS、企业或大型应用程序过程中遇到的常见问题及其解决方案。

本章我们将学习以下主题：

+   微服务及其简要背景

+   单体架构

+   单体架构的限制

+   微服务提供的优势和灵活性

+   在 Docker 等容器上部署微服务

# 微服务的演变

马丁·福勒解释道：

微服务的术语是在 2011 年 5 月靠近威尼斯的一次软件架构师研讨会上讨论的，以描述与会者认为的一种共同的架构风格，他们中很多人最近都在探索这种风格。2012 年 5 月，同一群人决定将“微服务”（µServices）作为最合适的名称。

让我们回顾一下它是如何在过去几年中发展的。企业架构更多地是从历史的大型机计算，通过客户机-服务器架构（两层到多层）发展到**服务导向架构**（**SOA**）。

从服务导向架构（SOA）到微服务的转变并非由某个行业协会定义的标准，而是许多组织实践的实用方法。SOA 最终演变为微服务。

前 Netflix 架构师阿德里安·科克洛夫特（Adrian Cockcroft）将其描述为：

细粒度 SOA。因此，微服务是强调小型短暂组件的 SOA。

同样，来自设计 X 窗口系统的成员迈克·甘卡兹（Mike Gancarz）的以下引言，定义了 Unix 哲学的一个基本原则，同样适用于微服务范式：

小即是美。

微服务与 SOA 有很多共同的特征，比如对服务和如何让一个服务与另一个服务解耦的关注。SOA 是围绕单体应用集成而演变的，通过暴露大部分基于**简单对象访问协议** (**SOAP**) 的 API。因此，中间件如**企业服务总线** (**ESB**) 对 SOA 非常重要。微服务更简单，尽管它们可能使用消息总线，但只是用于消息传输，其中不包含任何逻辑。它仅仅基于智能端点。

Tony Pujals 对微服务做了很好的定义：

在我的心智模型中，我想象的是自我包含（如同容器）的轻量级进程，通过 HTTP 进行通信，创建和部署相对简单，为消费者提供狭窄焦点的 API。

尽管 Tony 只提到了 HTTP，但事件驱动的微服务可能使用不同的协议进行通信。你可以使用 Kafka 来实现事件驱动的微服务。Kafka 使用的是线协议，一种基于 TCP 的二进制协议。

# 单体架构概述

Microservices 并不是什么新鲜事物，它已经存在了很多年。例如，Stubby 是一个基于**远程** **过程** **调用** (**RPC**) 的通用基础设施，早在 2000 年代初，它就被用于连接 Google 数据中心内和跨数据中心的多个服务。它近期之所以受到关注，是因为它的流行度和可见度。在微服务变得流行之前，开发本地和云应用程序主要采用的是单体架构。

单体架构允许开发不同的组件，如表示层、应用逻辑、业务逻辑和**数据访问对象** (**DAO**)，然后你可以将它们捆绑在**企业存档** (**EAR**) 或**网络存档** (**WAR**) 中，或者将它们存储在单个目录层次结构中（例如，Rails、NodeJS 等）。

许多著名的应用程序，如 Netflix，都是使用微服务架构开发的。此外，eBay、Amazon 和 Groupon 也从单体架构演变为微服务架构。

既然你已经对微服务的背景和历史有了了解，那么让我们讨论一下传统方法，即单体应用开发的局限性，并比较微服务如何解决这些问题。

# 单体架构的限制及其微服务的解决方案

众所周知，变化是永恒的。人类总是寻求更好的解决方案。这就是微服务成为今天这个样子，并可能在未来进一步发展的原因。今天，组织正在使用敏捷方法开发应用程序——这是一个快速的开发环境，并且在云计算和分布式技术发明之后规模也更大了。许多人认为单体架构也可以达到类似的目的，并且与敏捷方法论保持一致，但微服务仍在许多方面为生产就绪应用程序提供了更好的解决方案。

为了理解单体和微服务之间的设计差异，让我们以一个餐厅预订应用程序为例。这个应用程序可能有很多服务，如客户、预订、分析等，以及常规组件，如展示和数据库。

我们将探讨三种不同的设计：传统的单体设计、带服务的单体设计以及微服务设计。

# 传统的单体设计

下面的图表解释了传统的单体应用程序设计。这种设计在 SOA 变得流行之前被广泛使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/8fb71694-894b-43f1-babd-d1bebad0c078.png)

传统的单体应用程序设计

在传统的单体设计中，一切都被打包在同一个档案中，如**展示**代码、**应用逻辑**和**业务逻辑**代码，以及**DAO**和相关代码，这些代码与数据库文件或其他来源交互。

# 带服务的单体设计

在 SOA 之后，基于服务的应用程序开始被开发，每个组件为其他组件或外部实体提供服务。下面的图表展示了带有不同服务的单体应用程序；在这里，服务与**展示**组件一起使用。所有服务、**展示**组件或任何其他组件都被捆绑在一起：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/56e1f42d-382d-47e8-82da-b8014ad4e11a.png)

# 服务设计

接下来的第三种设计展示了微服务。在这里，每个组件都代表自主性。每个组件可以独立开发、构建、测试和部署。在这里，即使是应用程序**用户界面**（**UI**）组件也可以是一个客户端，并消费微服务。为了我们的示例，设计层在µService 内部使用。

**API 网关**提供接口，不同的客户端可以访问单个服务，解决以下问题：

当你想要为同一服务发送不同响应给不同客户端时，你会怎么做？例如，一个预订服务可以为移动客户端（最小信息）和桌面客户端（详细信息）发送不同的响应，提供不同的详细信息，对第三个客户端再次发送不同的信息。

一个响应可能需要从两个或更多服务中获取信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/2111f31f-e230-4141-bd2d-f52e304ca197.png)

在观察了所有的高级设计样本图后，你可能会发现，在单体设计中，组件是捆绑在一起的，并且耦合度很高。

所有服务都是同一个捆绑包的一部分。同样，在第二个设计图中，你可以看到第一个图的一个变体，其中所有服务可能都有自己的层并形成不同的 API，但是，如图所示，这些也都是捆绑在一起的。

相反，在微服务中，设计组件是不捆绑在一起的，并且耦合度很低。每个服务都有自己的层和**DB**，并且打包在单独的归档文件中。所有这些部署的服务提供它们特定的 API，如客户（Customers）、预订（Bookings）或客户（Customer）。这些 API 是即取即用的。即便是 UI 也是单独部署的，并且使用微服务进行设计。因此，它比单体应用有众多优势。我还是要提醒你，在某些特殊情况下，单体应用开发是非常成功的，如 Etsy 和点对点电子商务网站。

现在让我们讨论在使用单体应用时您可能会遇到的限制。

# 单一维度的可扩展性

当单体应用规模变大时，它会捆绑在一起扩展所有组件。例如，在餐厅预订桌位的应用中，即使你想要扩展桌位预订服务，它也会扩展整个应用；它不能单独扩展桌位预订服务。它没有充分利用资源。

此外，这种扩展是单一维度的。随着交易量的增加，运行更多应用副本提供了扩展。运维团队可以根据服务器农场或云中的负载，通过负载均衡器调整应用副本的数量。这些副本都会访问相同的数据源，因此增加了内存消耗，而产生的 I/O 操作使缓存效果大打折扣。

微服务赋予了灵活性，只扩展那些需要扩展的服务，并允许资源的最优利用。如我们之前提到的，当需要时，你可以只扩展桌位预订服务，而不影响其他任何组件。它还允许二维扩展；在这里，我们不仅可以增加交易量，还可以通过缓存增加数据量（平台扩展）。

开发团队可以专注于新特性的交付和 shipping，而不是担心扩展问题（产品扩展）。

正如我们之前所看到的，微服务可以帮助你扩展平台、人力和产品维度。这里的人力扩展指的是根据微服务的特定开发和关注需求，增加或减少团队规模。

使用 RESTful Web 服务开发的微服务架构使系统在服务器端是无状态的；这意味着服务器之间的通信不多，这使得系统可以水平扩展。

# 在失败的情况下进行发布回滚

由于单体应用程序要么打包在同一个归档文件中，要么包含在单个目录中，因此它们阻止了代码模块化的部署。例如，许多人都可能有过因一个功能失败而推迟整个发布的痛苦经历。

为了解决这些问题，微服务为我们提供了灵活性，只回滚失败的功能。这是一种非常灵活且高效的方法。例如，假设你是在线购物门户开发团队的一员，并希望基于微服务开发应用程序。你可以根据不同的领域（如产品、支付、购物车等）将应用程序进行划分，并将所有这些组件作为单独的包进行打包。一旦你单独部署了所有这些包，它们将作为可以独立开发、测试和部署的单一组件，并被称为微服务。

现在，让我们看看这如何帮助你。假设在生产环境中推出新功能、增强功能和修复程序后，你发现支付服务存在缺陷需要立即修复。由于你使用的架构是基于微服务的，因此如果你的应用程序架构允许，你可以只回滚支付服务，而不是整个发布，或者在不影响其他服务的情况下将修复程序应用于微服务支付服务。这不仅使你能够恰当地处理失败，而且还帮助您迅速将功能/修复传递给客户。

# 采用新技术的问题

单体应用程序主要是基于项目或产品最初开发阶段主要使用的技术进行开发和增强的。这使得在开发的后期阶段或产品成熟后（例如，几年后）引入新技术变得非常困难。此外，同一项目中依赖不同版本的同一库的不同模块使这更具挑战性。

技术每年都在进步。例如，您的系统可能设计为用 Java 实现，然后几年后，由于业务需求或利用新技术的优势，您可能希望用 Ruby on Rails 或 NodeJS 开发一个新服务。在一个现有的单体应用程序中利用新技术将非常困难。

这不仅仅是代码级别集成的問題，还包括测试和部署。可以通过重写整个应用程序来采用新技术，但这既耗时又冒险。

另一方面，由于其基于组件的开发和设计，微服务为我们提供了使用任何技术的灵活性，无论是新的还是旧的。它不会限制你使用特定的技术，为你的开发和工程活动提供了新的范式。你随时可以使用 Ruby on Rails、NodeJS 或其他任何技术。

那么，这是如何实现的呢？嗯，其实很简单。基于微服务的应用程序代码不会打包成一个单一的归档，也不会存储在单一的目录中。每个微服务都有自己的归档，并且是独立部署的。一个新的服务可以在一个隔离的环境中开发，并且可以没有任何技术问题地进行测试和部署。正如你所知，微服务也有自己的独立进程；它在不存在紧耦合的共享资源冲突的情况下完成其功能，并且进程保持独立。

由于微服务定义上是一个小型的、自包含的功能，它提供了一个尝试新技术的低风险机会。而在单体系统中，情况绝对不是这样。

你还可以让你的微服务作为开源软件提供给他人使用，如果需要，它还可以与闭源专有软件互操作，这是单体应用程序所不可能实现的。

# 与敏捷实践的对齐

毫无疑问，可以使用敏捷实践来开发单体应用程序，而且这样的应用程序正在被开发。可以采用**持续集成（CI）**和**持续部署（CD）**，但问题在于——它是否有效地使用了敏捷实践？让我们来分析以下几点：

+   例如，当有高概率的故事相互依赖，并且有各种场景时，只有在依赖的故事完成后才能开始一个故事。

+   随着代码规模的增加，构建所需的时间也会增加。

+   频繁部署大型单体应用程序是一项难以实现的任务。

+   即使你只更新了一个组件，你也必须重新部署整个应用程序。

+   重新部署可能会对正在运行的组件造成问题，例如，作业调度器可能会改变无论组件是否受其影响。

+   如果单个更改的组件不能正常工作或需要更多的修复，重新部署的风险可能会增加。

+   界面开发者总是需要更多的重新部署，这对于大型单体应用程序来说是非常冒险和耗时的。

微服务可以很轻松地解决前面提到的问题，例如，UI 开发者可能有自己的 UI 组件，可以独立地开发、构建、测试和部署。同样，其他微服务也可能可以独立部署，由于它们具有自主特性，因此降低了系统失败的风险。对于开发来说，另一个优点是 UI 开发者可以利用 JSON 对象和模拟 Ajax 调用来开发 UI，这种方式是隔离的。开发完成后，开发者可以消费实际的 API 并进行功能测试。总结来说，可以说微服务开发是迅速的，并且很好地适应了企业逐步增长的需求。

# 开发容易度 - 可以做得更好

通常，大型单体应用程序的代码对于开发者来说是最难以理解的，新开发者需要时间才能变得高效。即使将大型单体应用程序加载到 IDE 中也是麻烦的，这会使得 IDE 变慢，并降低开发者的效率。

在一个大型单体应用程序中进行更改是困难的，并且由于代码库庞大，需要更多的时间，如果没有进行彻底的影响分析，就会有很高的 bug 风险。因此，在实施更改之前，开发者进行彻底的影响分析是一个前提条件。

在单体应用程序中，随着时间的推移，依赖关系逐渐建立，因为所有组件都捆绑在一起。因此，与代码更改（修改的代码行数）增长相关的风险呈指数级上升。

当代码库很大且有超过 100 个开发者正在工作时，由于之前提到的原因，构建产品和实施新功能变得非常困难。你需要确保一切就绪，并且一切协调一致。在这种情况下，设计良好且文档齐全的 API 会有很大帮助。

Netflix，这个按需互联网流媒体服务提供商，在他们有大约 100 人在开发应用程序时遇到了问题。然后，他们使用了云，并将应用程序拆分成不同的部分。这些最终成为了微服务。微服务源于对速度和敏捷性的渴望，以及独立部署团队的需求。

由于微组件通过暴露的 API 实现了松耦合，可以持续进行集成测试。在微服务的持续发布周期中，变化很小，开发人员可以快速地进行回归测试，然后进行审查并修复发现的缺陷，从而降低了部署的风险。这导致了更高的速度和较低的相关风险。

由于功能分离和单一责任原则，微服务使团队非常高效。你可以在网上找到许多例子，大型项目是用最小的团队规模（如八到十名开发者）开发的。

开发人员可以拥有更小的代码和更好的特性实现，从而与产品的用户建立更强的共情关系。这有助于在特性实现上取得更好的动机和清晰度。与用户的共情关系可以实现更短的反馈循环，更好地快速优先处理特性管道。更短的反馈循环也可以使缺陷检测更快。

每个微服务团队独立工作，可以无需与更多人协调就实施新功能或想法。在微服务设计中，端点失败处理也很容易实现。

最近，在一场会议中，一个团队展示了他们如何在一个为期 10 周的项目中开发了一个基于微服务的运输跟踪应用程序，包括 iOS 和 Android 应用程序，并具有 Uber 类型的跟踪功能。一家大型咨询公司为其客户提供了一个为期七个月的同一应用程序估计。这显示了微服务如何与敏捷方法和持续集成/持续部署（CI/CD）保持一致。

# 微服务构建管道

微服务也可以使用流行的持续集成/持续部署（CI/CD）工具如 Jenkins、TeamCity 等来构建和测试。这与在单体应用中进行构建非常相似。在微服务中，每个微服务都被当作一个小应用程序来对待。

例如，一旦您在仓库（SCM）中提交代码，CI/CD 工具就会触发构建过程：

+   清理代码

+   代码编译

+   执行单元测试

+   合同/验收测试执行

+   构建应用程序归档/容器镜像

+   将归档/容器镜像发布到仓库管理

+   在各种交付环境（如 Dev、QA、Stage 等）上进行部署

+   集成和功能测试执行

+   其他任何步骤

然后，在`pom.xml`（对于 Maven）中，发布构建触发器会更改 SNAPSHOT 或 RELEASE 版本，按照正常的构建触发器描述构建工件。将工件发布到工件仓库。在仓库中为此版本打上标签。如果您使用容器镜像，则将容器镜像作为构建的一部分来构建。

# 使用如 Docker 之类的容器进行部署

由于微服务的设计，您需要一个提供灵活性、敏捷性和平滑性的环境，以便进行持续集成和部署，以及发货。微服务的部署需要速度、隔离管理以及敏捷的生命周期。

产品和软件也可以使用集装箱模型进行运输。集装箱是一种大型标准化容器，专为多式联运而设计。它允许货物使用不同的运输方式——卡车、铁路或船舶，而无需卸载和装载。这是一种存储和运输物品高效且安全的方式。它解决了运输问题，过去这是一个耗时、劳动密集型的过程，重复处理经常会损坏易碎物品。

运输集装箱封装了它们的内容。同样，软件容器正开始被用来封装它们的内容（产品、应用程序、依赖项等）。

以前，**虚拟机**（**VM**）被用来创建可以在需要时部署的软件镜像。后来，像 Docker 这样的容器变得更为流行，因为它们既兼容传统的虚拟站系统，也兼容云环境。例如，在开发人员的笔记本电脑上部署多个虚拟机是不切实际的。构建和引导虚拟机通常是 I/O 密集型的，因此速度较慢。

# 容器

容器（例如，Linux 容器）提供了一个轻量级的运行时环境，该环境包括了虚拟机的核心功能和操作系统的隔离服务。这使得微服务的打包和执行变得容易且流畅。

如以下图表所示，容器作为应用程序（微服务）在**操作系统**内运行。操作系统位于硬件之上，每个操作系统可能具有多个容器，其中一个容器运行应用程序。

容器利用操作系统的内核接口，如**cnames**和**namespaces**，使得多个容器能够在完全隔离的情况下共享同一个内核。这使得不需要为每个使用情况完成一个操作系统安装；结果是它消除了开销。它还使硬件**得到最佳利用**：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/a8adb807-2da8-4607-a466-8fe5b9cf4a0f.png)

容器层图

# Docker

容器技术是当今发展最快的技术之一，Docker 领导这一领域。Docker 是一个开源项目，它于 2013 年启动。2013 年 8 月其互动教程发布后，10,000 名开发者尝试了它。到 2013 年 6 月其 1.0 版本发布时，它已经被下载了 275 万次。许多大型公司已经与 Docker 签署了合作伙伴协议，如微软、红帽、惠普、OpenStack，以及服务提供商如亚马逊网络服务、IBM 和谷歌。

如我们之前提到的，Docker 也利用了 Linux 内核的功能，如 cgroups 和 namespaces，以确保资源隔离和应用及其依赖的打包。这种依赖的打包使得应用能够如预期地在不同的 Linux 操作系统/发行版上运行，支持一定程度的可移植性。此外，这种可移植性允许开发者在任何语言中开发应用程序，然后轻松地将它从笔记本电脑部署到测试或生产服务器。

Docker 原生运行在 Linux 上。然而，你也可以使用 VirtualBox 和 boot2docker 在 Windows 和 MacOS 上运行 Docker。

容器只包括应用程序及其依赖项，包括基本操作系统。这使得它在资源利用方面轻量且高效。开发人员和系统管理员对容器的可移植性和高效资源利用感兴趣。

Docker 容器中的所有内容都在宿主机上以原生方式执行，并直接使用宿主机内核。每个容器都有自己的用户命名空间。

# Docker 的架构

如 Docker 文档所述，Docker 架构采用客户端-服务器架构。如图所示（来源于 Docker 官网：[`docs.docker.com/engine/docker-overview/`](https://docs.docker.com/engine/docker-overview/)），Docker 客户端主要是用户界面，用于终端用户；客户端与 Docker 守护进程进行通信。Docker 守护进程负责构建、运行和分发你的 Docker 容器。Docker 客户端和守护进程可以运行在同一系统或不同机器上。

Docker 客户端和守护进程通过套接字或通过 RESTful API 进行通信。Docker 注册表是公开或私有的 Docker 镜像仓库，你可以从中上传或下载镜像，例如，Docker Hub（[hub.docker.com](https://hub.docker.com/)）是一个公开的 Docker 注册表。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/0ad926bf-861d-4c67-9004-46caa8f4fe7f.png)

Docker 的架构

Docker 的主要组件包括：

+   **Docker 镜像**：Docker 镜像是一个只读模板。例如，一个镜像可能包含一个带有 Apache 网页服务器和你的网页应用的 Ubuntu 操作系统。Docker 镜像 是 Docker 构建组件之一，镜像用于创建 Docker 容器。Docker 提供了一种简单的方法来构建新的镜像或更新现有镜像。你也可以使用他人创建的镜像，/或扩展它们。

+   **Docker 容器**：Docker 容器是从 Docker 镜像创建的。Docker 的工作原理是，容器只能看到自己的进程，并且在其宿主文件系统之上有自己的文件系统层和网络堆栈，这些管道到宿主网络堆栈。Docker**容器**可以被运行、启动、停止、移动或删除。

# 部署

使用 Docker 进行微服务部署涉及三个部分：

+   应用程序打包，例如，JAR

+   使用 Docker 指令文件，Dockerfile 和命令`docker build`构建包含 JAR 和依赖项的 Docker 镜像。它有助于反复创建镜像。

+   使用命令`docker run`从新构建的镜像中执行 Docker 容器。

前面的信息将帮助你理解 Docker 的基础知识。你将在第五章，*部署与测试*中了解更多关于 Docker 及其实际应用。源代码和参考资料，参考： [`docs.docker.com`](https://docs.docker.com)。

# 总结

在本章中，你已经学习了大型软件项目的高级设计，从传统的单体应用到微服务应用。你还简要了解了微服务的历史、单体应用的局限性以及微服务所提供的优势和灵活性。我希望这一章能帮助你理解单体应用在生产环境中遇到的一些常见问题以及微服务如何解决这些问题。你还了解到了轻量级且高效的 Docker 容器，并看到了容器化是简化微服务部署的绝佳方式。

在下一章中，你将了解到如何从 IDE 设置开发环境，以及其他开发工具和不同的库。我们将处理创建基本项目并设置 Spring Boot 配置来构建和开发我们的第一个微服务。我们将使用 Java 9 作为编程语言和 Spring Boot 来完成项目。


# 第二章：设置开发环境

本章重点介绍开发环境的设置和配置。如果你熟悉工具和库，可以跳过本章，继续阅读第三章，*领域驱动设计*，在那里你可以探索**领域驱动设计**（**DDD**）。

本章将涵盖以下主题：

+   NetBeans IDE 的安装和设置

+   Spring Boot 配置

+   使用 Java 9 模块的示例 REST 程序

+   构建设置

+   使用 Chrome 的 Postman 扩展进行 REST API 测试

本书将只使用开源工具和框架作为示例和代码。本书还将使用 Java 9 作为编程语言，应用程序框架将基于 Spring 框架。本书利用 Spring Boot 来开发微服务。

NetBeans 的**集成开发环境**（**IDE**）为 Java 和 JavaScript 提供最先进的支持，足以满足我们的需求。它多年来已经发生了很大的变化，并内置了对本书中使用的大多数技术的支持，如 Maven、Spring Boot 等。因此，我建议你使用 NetBeans IDE。不过，你也可以自由选择任何 IDE。

我们将使用 Spring Boot 来开发 REST 服务和微服务。在本书中选择 Spring 框架中最受欢迎的 Spring Boot 或其子集 Spring Cloud 是一个明智的选择。因此，我们不需要从零开始编写应用程序，它为大多数云应用程序中使用的技术提供了默认配置。Spring Boot 的概述在 Spring Boot 的配置部分提供。如果你是 Spring Boot 的新手，这绝对会帮助你。

我们将使用 Maven 作为我们的构建工具。与 IDE 一样，你可以使用任何你想要的构建工具，例如 Gradle 或带有 Ivy 的 Ant。我们将使用内嵌的 Jetty 作为我们的 Web 服务器，但另一个选择是使用内嵌的 Tomcat Web 服务器。我们还将使用 Chrome 的 Postman 扩展来测试我们的 REST 服务。

我们将从 Spring Boot 配置开始。如果你是 NetBeans 的新手或者在设置环境时遇到问题，可以参考以下部分。

# NetBeans IDE 的安装和设置

NetBeans IDE 是免费且开源的，拥有庞大的用户社区。您可以从它的官方网站[`netbeans.org/downloads/`](https://netbeans.org/downloads/)下载 NetBeans IDE。

在撰写本书时，NetBeans for Java 9 只能作为夜间构建版本提供（可从[`bits.netbeans.org/download/trunk/nightly/latest/`](http://bits.netbeans.org/download/trunk/nightly/latest/)下载）。如下图所示，下载所有受支持的 NetBeans 捆绑包，因为我们将使用 JavaScript：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/f22fd95b-9e2c-40fe-bfc1-09650afa7955.png)

NetBeans 捆绑包

GlassFish 服务器和 Apache Tomcat 是可选的。必需的包和运行时环境标记为已安装（因为 NetBeans 已经在我的系统上安装了）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/7baa8c9e-4e28-4f48-b942-85ab51dcb1fe.png)

NetBeans 包装和运行时

下载安装程序后，执行安装文件。如下截图所示，接受许可协议，并按照其余步骤安装 NetBeans IDE：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/2b6b7797-612a-4704-821c-3f12c06a1280.png)

NetBeans 许可对话框

安装和运行所有 NetBeans 捆绑包需要 JDK 8 或更高版本。本书使用 Java 9，因此我们将使用 JDK 9。您可以从 [`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html) 下载独立的 JDK 9。我不得不使用 JDK 9 的早期访问构建，因为 JDK 9 写作本书时还没有发布。它可以在 [`jdk.java.net/9/`](http://jdk.java.net/9/) 找到。

安装 NetBeans IDE 后，启动 NetBeans IDE。NetBeans IDE 应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/cedfbcb0-1c97-459b-83b6-3cee57e1519b.png)

NetBeans 开始页面

Maven 和 Gradle 都是 Java 构建工具。它们为您的项目添加依赖库，编译您的代码，设置属性，构建归档，并执行许多其他相关活动。Spring Boot 或 Spring Cloud 支持 Maven 和 Gradle 构建工具。然而，在本书中，我们将使用 Maven 构建工具。如果您喜欢，请随意使用 Gradle。

Maven 已经在 NetBeans IDE 中可用。现在，我们可以开始一个新的 Maven 项目来构建我们的第一个 REST 应用程序。

创建新空 Maven 项目的步骤如下：

1.  点击文件菜单下的“新建项目”（*Ctrl* + *Shift* + *N*），它会打开新建项目向导。

1.  从“类别”列表中选择 `Maven`。然后，从“项目”列表中选择 POM 项目，如下截图所示。然后，点击下一步按钮。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/28699870-56b9-4ebb-aa54-49b48a1e3e37.png)

新项目向导

1.  现在，输入项目名称为 `6392_chapter2`。此外，还应输入如下截图中显示的其他属性。填写完所有必填字段后，点击“完成”：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/44c2a4f2-67e2-4f79-84c0-7eb2d164ddcd.png)

NetBeans Maven 项目属性

Aggelos Karalias 为 NetBeans IDE 开发了一个有用的插件，提供对 Spring Boot 配置属性的自动完成支持，该插件可在 [`github.com/keevosh/nb-springboot-configuration-support`](https://github.com/keevosh/nb-springboot-configuration-support) 找到。您可以从他在 [`keevosh.github.io/nb-springboot-configuration-support/`](http://keevosh.github.io/nb-springboot-configuration-support/) 的项目页面下载它。您还可以使用 Pivotal 的 Spring Tool Suite IDE ([`spring.io/tools`](https://spring.io/tools)) 代替 NetBeans IDE。它是一个定制的集成所有功能的基于 Eclipse 的分发版，使应用开发变得简单。

完成所有前面的步骤后，NetBeans 将显示一个新创建的 Maven 项目。你将使用这个项目来创建一个使用 Spring Boot 的示例 rest 应用程序。

1.  要使用 Java 9 作为源，将源/二进制格式设置为 9，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/105972df-2bba-447d-b40d-618e59a90ca2.png)

NetBeans Maven 项目属性 - 源代码

1.  前往构建 | 编译，并确保将 Java 平台设置为 JDK 9（默认）如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/763145c2-dd85-452b-92bb-f3d248ad279d.png)

NetBeans Maven 项目属性 - 编译

1.  同样地，你可以在`Modules`文件夹中通过打开右键菜单，然后选择创建新模块的选项，添加两个名为`lib`和`rest`的新模块。这次你应该在新项目对话框框中从类别列表中选择`Maven`，并从项目列表中选择 Java 应用程序。

# Spring Boot 配置

Spring Boot 是开发特定于 Spring 的生产级别先进应用程序的明显选择。其网站（[`projects.spring.io/spring-boot/`](https://projects.spring.io/spring-boot/)）也阐述了它的真正优势：

采用了一种有见解的观点来构建生产级别的 Spring 应用程序。Spring Boot 优先考虑约定优于配置，并旨在让你尽快运行起来。

# Spring Boot 概览

**Pivotal**创建的 Spring Boot 是一个令人惊叹的 Spring 工具，并于 2014 年 4 月（GA）发布。它是基于 SPR-9888（[`jira.spring.io/browse/SPR-9888`](https://jira.spring.io/browse/SPR-9888)）的请求创建的，标题为*改进对“无容器”的 web 应用程序架构的支持*。

你可能会想知道，为什么是无容器呢？因为，今天的云环境或 PaaS 提供了基于容器 web 架构的大部分功能，如可靠性、管理或扩展。因此，Spring Boot 专注于将自己打造成一个超轻量级的容器。

Spring Boot 预先配置好了，可以非常容易地制作出生产级别的 web 应用程序。**Spring Initializr**（[`start.spring.io`](http://start.spring.io)）是一个页面，你可以选择构建工具，如 Maven 或 Gradle，以及项目元数据，如组、工件和依赖关系。一旦输入了所需字段，你只需点击生成项目按钮，就会得到你可用于生产应用程序的 Spring Boot 项目。

在这个页面上，默认的打包选项是 JAR。我们也将为我们的微服务开发使用 JAR 打包。原因非常简单：它使微服务开发更容易。想想管理并创建一个每个微服务在其自己的服务器实例上运行的基础设施有多困难。

在 Spring IOs 的一次演讲中，Josh Long 分享道：

“最好是制作 JAR，而不是 WAR。”

稍后，我们将使用 Spring Cloud，它是建立在 Spring Boot 之上的一个包装器。

我们将开发一个示例 REST 应用程序，该应用程序将使用 Java 9 模块功能。我们将创建两个模块——`lib`和`rest`。`lib`模块将为`rest`模块提供模型或任何支持类。`rest`模块将包括开发 REST 应用程序所需的所有类，并且还将消耗在`lib`模块中定义的模型类。

`lib`和`rest`模块都是`maven`模块，它们的`parent`模块是我们的主项目`6392_chapter2`。

`module-info.java`文件是一个重要的类，它管理着对其类的访问。我们将利用`requires`、`opens`和`exports`来使用`spring`模块，并在我们 REST 应用程序的`lib`和`rest`模块之间建立提供者-消费者关系。

# 将 Spring Boot 添加到我们的主项目中

我们将使用 Java 9 来开发微服务。因此，我们将使用最新的 Spring 框架和 Spring Boot 项目。在撰写本文时，Spring Boot 2.0.0 构建快照版本是可用的。

你可以使用最新发布的版本。Spring Boot 2.0.0 构建快照使用 Spring 5（5.0.0 构建快照版本）。

让我们来看看以下步骤，了解如何将 Spring Boot 添加到我们的主项目中。

1.  打开`pom.xml`文件（在`6392_chapter2` | 项目文件中可用），以将 Spring Boot 添加到您的示例项目中：

```java
<?xml version="1.0" encoding="UTF-8"?> 
<project  

         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
    <modelVersion>4.0.0</modelVersion> 

    <groupId>com.packtpub.mmj</groupId> 
    <artifactId>6392_chapter2</artifactId> 
    <version>1.0-SNAPSHOT</version> 
    <packaging>pom</packaging> 

    <modules> 
        <module>lib</module> 
        <module>rest</module> 
    </modules> 

    <properties> 
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding> 
        <spring-boot-version>2.0.0.BUILD-SNAPSHOT</spring-boot-version> 
        <spring-version>5.0.0.BUILD-SNAPSHOT</spring-version> 
        <maven.compiler.source>9</maven.compiler.source> 
        <maven.compiler.target>9</maven.compiler.target> 
        <start-class>com.packtpub.mmj.rest.RestSampleApp</start-class> 
    </properties> 
    <parent> 
        <groupId>org.springframework.boot</groupId> 
        <artifactId>spring-boot-starter-parent</artifactId> 
        <version>2.0.0.BUILD-SNAPSHOT</version> 
    </parent> 
    <dependencyManagement> 
        <dependencies> 
            <dependency> 
                <groupId>com.packtpub.mmj</groupId> 
                <artifactId>rest</artifactId> 
                <version>${project.version}</version> 
            </dependency> 
            <dependency> 
                <groupId>com.packtpub.mmj</groupId> 
                <artifactId>lib</artifactId> 
                <version>${project.version}</version> 
            </dependency> 
        </dependencies> 
    </dependencyManagement> 

    <build> 
        <plugins> 
            <plugin> 
                <groupId>org.springframework.boot</groupId> 
                <artifactId>spring-boot-maven-plugin</artifactId> 
                <version>2.0.0.BUILD-SNAPSHOT</version> 
                <executions> 
                    <execution> 
                        <goals> 
                            <goal>repackage</goal> 
                        </goals> 
                        <configuration> 
                            <classifier>exec</classifier> 
                            <mainClass>${start-class}</mainClass> 
                        </configuration> 
                    </execution> 
                </executions> 
            </plugin> 
            <plugin> 
                <groupId>org.apache.maven.plugins</groupId> 
                <artifactId>maven-compiler-plugin</artifactId> 
                <version>3.6.1</version> 
                <configuration> 
                    <source>1.9</source> 
                    <target>1.9</target> 
                    <showDeprecation>true</showDeprecation> 
                    <showWarnings>true</showWarnings> 
                </configuration> 
            </plugin> 
        </plugins> 
    </build> 
    <repositories> 
        <repository> 
            <id>spring-snapshots</id> 
            <name>Spring Snapshots</name> 
            <url>https://repo.spring.io/snapshot</url> 
            <snapshots> 
                <enabled>true</enabled> 
            </snapshots> 
        </repository> 
        <repository> 
            <id>spring-milestones</id> 
            <name>Spring Milestones</name> 
            <url>https://repo.spring.io/milestone</url> 
            <snapshots> 
                <enabled>false</enabled> 
            </snapshots> 
        </repository> 
    </repositories> 

    <pluginRepositories> 
        <pluginRepository> 
            <id>spring-snapshots</id> 
            <name>Spring Snapshots</name> 
            <url>https://repo.spring.io/snapshot</url> 
            <snapshots> 
                <enabled>true</enabled> 
            </snapshots> 
        </pluginRepository> 
        <pluginRepository> 
            <id>spring-milestones</id> 
            <name>Spring Milestones</name> 
            <url>https://repo.spring.io/milestone</url> 
            <snapshots> 
                <enabled>false</enabled> 
            </snapshots> 
        </pluginRepository> 
    </pluginRepositories> 
</project> 
```

你可以观察到，我们在父项目`pom.xml`中定义了我们的两个模块`lib`和`rest`。

1.  如果你第一次添加这些依赖项，你需要通过在项目窗格中`6392_chapter2`项目的`Dependencies`文件夹下右键点击，下载依赖关系，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/5c0f9e4e-f148-45a9-9e1c-5bd5c273cfc0.png)

在 NetBeans 中下载 Maven 依赖项

1.  同样，为了解决项目问题，右键点击 NetBeans 项目`6392_chapter2`，选择“解决项目问题...”。它将打开如下所示的对话框。点击“解决...”按钮来解决这些问题：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/edec6f4e-9097-47d1-83e5-74ed409cd371.png)

解决项目问题对话框

1.  如果你在代理后面使用 Maven，那么需要更新 Maven 主目录中的`settings.xml`中的`proxies`。如果你使用的是与 NetBeans 捆绑的 Maven，则使用`<NetBeans 安装目录>\java\maven\conf\settings.xml`。你可能需要重新启动 NetBeans IDE。

上述步骤将从远程 Maven 仓库下载所有必需的依赖项，如果声明的依赖项和传递依赖项在本地 Maven 仓库中不可用。如果你是第一次下载依赖项，那么它可能需要一些时间，这取决于你的互联网速度。

# 示例 REST 程序

我们将采用一种简单的构建独立应用程序的方法。它将所有内容打包成一个可执行的 JAR 文件，由一个`main()`方法驱动。在这个过程中，您使用 Spring 支持将 Jetty Servlet 容器作为 HTTP 运行时嵌入，而不是将其部署到外部实例。因此，我们将创建代替需要部署在外部 Web 服务器上的 war 的可执行 JAR 文件，这是`rest`模块的一部分。我们将在`lib`模块中定义领域模型和`rest`模块中相关的 API 类。

以下是`lib`和`rest`模块的`pom.xml`文件。

`lib`模块的`pom.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?> 
<project   xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
    <modelVersion>4.0.0</modelVersion> 
    <parent> 
        <groupId>com.packtpub.mmj</groupId> 
        <artifactId>6392_chapter2</artifactId> 
        <version>1.0-SNAPSHOT</version> 
    </parent> 
    <artifactId>lib</artifactId> 
</project> 
```

`rest`模块的`pom.xml`文件：

```java
    <modelVersion>4.0.0</modelVersion> 
    <parent> 
        <groupId>com.packtpub.mmj</groupId> 
        <artifactId>6392_chapter2</artifactId> 
        <version>1.0-SNAPSHOT</version> 
    </parent> 
    <artifactId>rest</artifactId> 
  <dependencies> 
        <dependency> 
            <groupId>com.packtpub.mmj</groupId> 
            <artifactId>lib</artifactId> 
        </dependency> 
        <dependency> 
            <groupId>org.springframework.boot</groupId> 
            <artifactId>spring-boot-starter-web</artifactId> 
    ... 
    ...  
```

在这里，`spring-boot-starter-web`依赖项用于开发独立的可执行 REST 服务。

我们将在`lib`和`rest`模块的默认包中分别添加以下`module-info.java`类。

`lib`模块的`module-info.java`文件：

```java
module com.packtpub.mmj.lib { 
    exports com.packtpub.mmj.lib.model to com.packtpub.mmj.rest; 
    opens com.packtpub.mmj.lib.model; 
} 
```

在这里，我们导出了`com.packtpub.mmj.lib.model`包到`com.packtpub.mmj.rest`，这允许`lib`模型类对`rest`模块类进行访问。

`lib`模块的`module-info.java`文件：

```java
module com.packtpub.mmj.rest { 

    requires spring.core; 
    requires spring.beans; 
    requires spring.context; 
    requires spring.aop; 
    requires spring.web; 
    requires spring.expression; 

    requires spring.boot; 
    requires spring.boot.autoconfigure; 

    requires com.packtpub.mmj.lib; 

    exports com.packtpub.mmj.rest; 
    exports com.packtpub.mmj.rest.resources; 

    opens com.packtpub.mmj.rest; 
    opens com.packtpub.mmj.rest.resources; 
} 
```

在这里，我们使用`requires`语句添加了所有必需的`spring`和`lib`包，这使得`rest`模块的类能够使用在`spring`和`lib`模块中定义的类。同时，我们导出了`com.packt.mmj.rest`和`com.packt.mmj.rest.resources`包。

现在，既然您已经准备好使用 NetBeans IDE 的 Spring Boot，您可以创建一个示例 Web 服务。您将创建一个执行简单计算并生成 JSON 结果的数学 API。

让我们讨论如何调用 REST 服务并获取响应。

该服务将处理`/calculation/sqrt`或`/calculation/power`等`GET`请求。`GET`请求应返回一个带有表示给定数字平方根的 JSON 体的`200 OK`响应。它看起来像这样：

```java
{ 
  "function": "sqrt", 
  "input": [ 
    "144" 
  ], 
  "output": [ 
    "12.0" 
  ] 
} 
```

`input`字段是平方根函数的输入参数，内容是结果的文本表示。

您可以创建一个资源表示类，使用**普通老式 Java 对象**（**POJO**）建模表示，并为输入、输出和功能数据使用字段、构造函数、设置器和获取器。由于它是一个模型，我们将在`lib`模块中创建它：

```java
package com.packtpub.mmj.lib.model; 

import java.util.List; 

public class Calculation { 

    String function; 
    private List<String> input; 
    private List<String> output; 

    public Calculation(List<String> input, List<String> output, String function) { 
        this.function = function; 
        this.input = input; 
        this.output = output; 
    } 

    public List<String> getInput() { 
        return input; 
    } 

    public void setInput(List<String> input) { 
        this.input = input; 
    } 

    public List<String> getOutput() { 
        return output; 
    } 

    public void setOutput(List<String> output) { 
        this.output = output; 
    } 

    public String getFunction() { 
        return function; 
    } 

    public void setFunction(String function) { 
        this.function = function; 
    } 

} 
```

# 编写 REST 控制器类

罗伊·菲尔丁在他的博士论文中定义并引入了**代表性状态传输**（**REST**）这个术语。REST 是一种软件架构风格，用于分布式超媒体系统，如 WWW。遵循 REST 架构属性的系统称为 RESTful。

现在，您将创建一个 REST 控制器来处理`Calculation`资源。控制器在 Spring RESTful Web 服务实现中处理 HTTP 请求。

# @RestController 注解

`@RestController`是用于在 Spring 4 中引入的`resource`类的类级别注解。它是`@Controller`和`@ResponseBody`的组合，因此，一个类返回领域对象而不是视图。

在下面的代码中，你可以看到`CalculationController`类通过返回`calculation`类的新实例处理`GET`请求`/calculation`。

我们将为`Calculation`资源实现两个 URI——平方根（`Math.sqrt()`函数）作为`/calculations/sqrt` URI，幂（`Math.pow()`函数）作为`/calculation/power` URI。

# `@RequestMapping`注解

`@RequestMapping`注解用于类级别以将`/calculation` URI 映射到`CalculationController`类，即，它确保对`/calculation`的 HTTP 请求映射到`CalculationController`类。基于使用`@RequestMapping`注解定义的路径的 URI（例如，`/calculation/sqrt/144`的后缀），它将映射到相应的函数。在这里，请求映射`/calculation/sqrt`被映射到`sqrt()`方法，`/calculation/power`被映射到`pow()`方法。

您可能还注意到我们没有定义这些方法将使用什么请求方法（`GET`/`POST`/`PUT`等）。`@RequestMapping`注解默认映射所有 HTTP 请求方法。您可以使用`RequestMapping`的 method 属性来指定方法。例如，您可以像下面这样使用`POST`方法写一个`@RequestMethod`注解：

```java
@RequestMapping(value = "/power", method = POST) 
```

为了在途中传递参数，示例展示了使用`@RequestParam`和`@PathVariable`注解的请求参数和路径参数。

# `@RequestParam`注解

`@RequestParam`负责将查询参数绑定到控制器的方法的参数。例如，`QueryParam`基底和指数分别绑定到`CalculationController`的`pow()`方法的参数`b`和`e`。由于我们没有为这两个查询参数使用任何默认值，所以`pow()`方法的这两个查询参数都是必需的。查询参数的默认值可以通过`@RequestParam`的`defaultValue`属性设置，例如，`@RequestParam(value="base", defaultValue="2")`。在这里，如果用户没有传递查询参数 base，那么默认值`2`将用于基数。

如果没有定义`defaultValue`，并且用户没有提供请求参数，那么`RestController`将返回 HTTP`status`代码`400`以及消息`Required String parameter 'base' is not present`。如果多个请求参数缺失，它总是使用第一个必需参数的引用：

```java
{ 
  "timestamp": 1464678493402, 
  "status": 400, 
  "error": "Bad Request", 
  "exception": "org.springframework.web.bind.MissingServletRequestParameterException", 
  "message": "Required String parameter 'base' is not present", 
  "path": "/calculation/power/" 
} 
```

# `@PathVariable`注解

`@PathVariable`帮助你创建动态 URI。`@PathVariable`注解允许你将 Java 参数映射到路径参数。它与`@RequestMapping`一起工作，在 URI 中创建占位符，然后使用相同的名字作为`PathVariable`或方法参数，正如你在`CalculationController`类的`sqrt()`方法中看到的。在这里，值占位符在`@RequestMapping`内部创建，相同的值分配给`@PathVariable`的值。

`sqrt()`方法在 URI 中以请求参数的形式接收参数，例如`http://localhost:8080/calculation/sqrt/144`。在这里，`144`值作为路径参数传递，这个 URL 应该返回`144`的平方根，即`12`。

为了使用基本的检查，我们使用正则表达式`"^-?+\\d+\\.?+\\d*$"`来只允许参数中的有效数字。如果传递了非数字值，相应的方法会在 JSON 的输出键中添加错误消息：

`CalculationController`还使用正则表达式`.+`在`path`变量（`path`参数）中允许数字值中的小数点（`.`）：`/path/{variable:.+}`。Spring 忽略最后一个点之后的所有内容。Spring 的默认行为将其视为文件扩展名。

还有其他选择，例如在末尾添加一个斜杠（`/path/{variable}/`），或者通过设置`useRegisteredSuffixPatternMatch`为`true`来覆盖`WebMvcConfigurerAdapter`的`configurePathMatch()`方法，使用`PathMatchConfigurer`（在 Spring 4.0.1+中可用）。

`CalculationController`资源的代码，我们实现了两个 REST 端点：

```java
package com.packtpub.mmj.rest.resources; 

import com.packtpub.mmj.lib.model.Calculation; 
import java.util.ArrayList; 
import java.util.List; 
import org.springframework.web.bind.annotation.PathVariable; 
import org.springframework.web.bind.annotation.RequestMapping; 
import static org.springframework.web.bind.annotation.RequestMethod.GET; 
import org.springframework.web.bind.annotation.RequestParam; 
import org.springframework.web.bind.annotation.RestController; 

/** 
 * 
 * @author sousharm 
 */ 
@RestController 
@RequestMapping("calculation") 
public class CalculationController { 

    private static final String PATTERN = "^-?+\\d+\\.?+\\d*$"; 

    /** 
     * 
     * @param b 
     * @param e 
     * @return 
     */ 
    @RequestMapping("/power") 
    public Calculation pow(@RequestParam(value = "base") String b, @RequestParam(value = "exponent") String e) { 
        List<String> input = new ArrayList(); 
        input.add(b); 
        input.add(e); 
        List<String> output = new ArrayList(); 
        String powValue; 
        if (b != null && e != null && b.matches(PATTERN) && e.matches(PATTERN)) { 
            powValue = String.valueOf(Math.pow(Double.valueOf(b), Double.valueOf(e))); 
        } else { 
            powValue = "Base or/and Exponent is/are not set to numeric value."; 
        } 
        output.add(powValue); 
        return new Calculation(input, output, "power"); 
    } 

    /** 
     * 
     * @param aValue 
     * @return 
     */ 
    @RequestMapping(value = "/sqrt/{value:.+}", method = GET) 
    public Calculation sqrt(@PathVariable(value = "value") String aValue) { 
        List<String> input = new ArrayList(); 
        input.add(aValue); 
        List<String> output = new ArrayList(); 
        String sqrtValue; 
        if (aValue != null && aValue.matches(PATTERN)) { 
            sqrtValue = String.valueOf(Math.sqrt(Double.valueOf(aValue))); 
        } else { 
            sqrtValue = "Input value is not set to numeric value."; 
        } 
        output.add(sqrtValue); 
        return new Calculation(input, output, "sqrt"); 
    } 
} 
```

在这里，我们只通过 URI `/calculation/power` 和 `/calculation/sqrt` 暴露了`Calculation`资源的`power`和`sqrt`函数。

在这里，我们使用`sqrt`和`power`作为 URI 的一部分，这仅是为了演示目的。理想情况下，这些应该作为`function`请求参数的值传递，或根据端点设计形成类似的内容。

这里有趣的一点是，由于 Spring 的 HTTP 消息转换器支持，`Calculation`对象会自动转换为 JSON。您不需要手动进行这种转换。如果 Jackson 2 在类路径上，Spring 的`MappingJackson2HttpMessageConverter`会将`Calculation`对象转换为 JSON。

# 制作一个可执行的示例 REST 应用程序

创建一个带有`SpringBootApplication`注解的`RestSampleApp`类。`main()`方法使用 Spring Boot 的`SpringApplication.run()`方法来启动一个应用程序。

我们将用`@SpringBootApplication`注解标记`RestSampleApp`类，这个注解隐式地添加了以下所有标签：

+   `@Configuration`注解将类标记为应用程序上下文 bean 定义的来源。

+   `@EnableAutoConfiguration`注解表明 Spring Boot 将根据类路径设置、其他 bean 和各种属性设置来添加 bean。

+   如果 Spring Boot 在类路径中找到`spring-webmvc`，则会添加`@EnableWebMvc`注解。它将应用程序视为网络应用程序并激活诸如设置`DispatcherServlet`等关键行为。

+   `@ComponentScan`注解告诉 Spring 在给定包中寻找其他组件、配置和服务：

```java
package com.packtpub.mmj.rest; 

import org.springframework.boot.SpringApplication; 
import org.springframework.boot.autoconfigure.SpringBootApplication; 

@SpringBootApplication 
public class RestSampleApp { 

    public static void main(String[] args) { 
        SpringApplication.run(RestSampleApp.class, args); 
    } 
} 
```

这个网络应用程序是 100%的纯 Java，您不必处理使用 XML 配置任何管道或基础设施的问题；相反，它使用了由 Spring Boot 简化的 Java 注解。因此，除了`pom.xml`用于 Maven 之外，没有一行 XML。甚至没有`web.xml`文件。

# 添加 Jetty 内嵌服务器

Spring Boot 默认提供 Apache Tomcat 作为内嵌应用程序容器。本书将使用 Jetty 内嵌应用程序容器代替 Apache Tomcat。因此，我们需要添加一个支持 Jetty 网络服务器的 Jetty 应用程序容器依赖项。

Jetty 还允许您使用类路径读取密钥或信任存储，也就是说，您不需要将这些存储保存在 JAR 文件之外。如果您使用带有 SSL 的 Tomcat，那么您需要直接从文件系统访问密钥库或信任库，但是您不能使用类路径来实现。结果是，您不能在 JAR 文件内读取密钥库或信任库，因为 Tomcat 要求密钥库（如果您使用的话）信任库）直接可访问文件系统。这本书完成后可能会发生变化。

这个限制不适用于 Jetty，它允许在 JAR 文件内读取密钥或信任存储。下面是模块`rest`的`pom.xml`相对部分：

```java
<dependencies> 
<dependency> 
       <groupId>org.springframework.boot</groupId> 
           <artifactId>spring-boot-starter-web</artifactId> 
           <exclusions> 
             <exclusion> 
<groupId>org.springframework.boot</groupId> 
<artifactId>spring-boot-starter-tomcat</artifactId> 
                </exclusion> 
            </exclusions> 
</dependency> 
<dependency> 
<groupId>org.springframework.boot</groupId> 
<artifactId>spring-boot-starter-jetty</artifactId> 
</dependency> 
</dependencies>
```

# 设置应用程序构建

无论`pom.xml`文件是什么，我们到目前为止使用的东西已经足够执行我们的示例 REST 服务。这个服务会把代码打包成一个 JAR 文件。为了使这个 JAR 文件可执行，我们需要选择以下选项：

+   运行 Maven 工具

+   使用 Java 命令执行

以下部分将详细介绍它们。

# 运行 Maven 工具

这个方法可能不起作用，因为 Java 9、Spring Boot 2 和 Spring Framework 5 都处于早期或快照版本。如果它不起作用，请使用使用 Java 命令的项目。

在这里，我们使用 Maven 工具执行生成的 JAR 文件，具体步骤如下：

1.  右键点击`pom.xml`文件。

1.  从弹出菜单中选择“运行 Maven | 目标...”。它会打开对话框。在目标字段中输入`spring-boot:run`。我们在代码中使用了 Spring Boot 的发布版本。然而，如果您使用快照版本，您可以勾选“更新快照”复选框。为了将来使用，在“记住为”字段中输入`spring-boot-run`。

1.  下次，您可以直接点击“运行 Maven | 目标 | `spring-boot-run`”来执行项目：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/a87ddfcb-0346-4f49-aa19-6fb7943ba13a.png)

运行 Maven 对话框

1.  点击确定以执行项目。

# 使用 Java 命令执行

请确保在执行以下命令之前，Java 和`JAVA_HOME`已设置为 Java 9。

请查看以下步骤：

1.  要构建 JAR 文件，请从父项目根目录（`6392_chapter2`）的命令提示符中执行`mvn clean package`命令。在这里，`clean`和`package`是 Maven 目标：

```java
mvn clean package
```

1.  它将在相应的目标目录中创建 JAR 文件。我们将执行在`6392_chapter2\rest\target`目录中生成的 JAR 文件。可以使用以下命令执行 JAR 文件：

```java
java -jar rest\target\rest-1.0-SNAPSHOT-exec.jar
```

请确保您执行具有后缀`exec`的 JAR 文件，如前一个命令所示。

# 使用 Postman Chrome 扩展进行 REST API 测试

本书使用 Postman - REST Client Chrome 扩展来测试我们的 REST 服务。我使用的是 Postman 5.0.1 版本。您可以使用 Postman Chrome 应用程序或其他 REST 客户端来测试您的示例 REST 应用程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/6736f3bc-973d-4c2d-aecf-9805679d74e8.png)

Postman - Rest Client Chrome 扩展

一旦您安装了 Postman - REST Client，让我们测试我们的第一个 REST 资源。我们从开始菜单或从快捷方式中启动 Postman - REST Client。

默认情况下，嵌入式 Web 服务器在端口`8080`上启动。因此，我们需要使用`http://localhost:8080/<资源>`URL 来访问示例 REST 应用程序。例如：`http://localhost:8080/calculation/sqrt/144`。

一旦启动，您可以在路径参数中输入`Calculation` REST URL 的`sqrt`值和`144`。您可以在以下屏幕截图中看到。此 URL 在 Postman 扩展的 URL（在此处输入请求 URL）输入字段中输入。默认情况下，请求方法是`GET`。由于我们还编写了 RESTful 服务以提供`GET`方法的请求，因此我们使用默认的请求方法。

一旦您准备好前面提到的输入数据，您就可以提交

通过点击发送按钮发送请求。您可以在以下屏幕截图中看到

响应代码`200`由您的示例 REST 服务返回。您可以在以下屏幕截图中的状态标签中找到 200 OK 代码。成功的请求

还返回了`Calculation`资源的 JSON 数据，在美化标签中显示

在屏幕截图中。返回的 JSON 显示了函数键的`sqrt`方法值。

它还显示了输入和输出列表分别为`144`和`12.0`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/7cfef8d6-9407-450b-a50f-2373f48905af.png)

使用 Postman 测试 Calculation（sqrt）资源

同样，我们还测试了用于计算`power`函数的示例 REST 服务。在 Postman 扩展中输入以下数据：

+   **URL**: [`localhost:8080/calculation/power?base=2&exponent=4`](http://localhost:8080/calculation/power?base=2&exponent=4)

+   **请求方法**: `GET`

在这里，我们传递了请求参数`base`和`exponent`，分别值为`2`和`4`。它返回以下 JSON：

```java
{ 
    "function": "power", 
    "input": [ 
        "2", 
        "4" 
    ], 
    "output": [ 
        "16.0" 
    ] 
} 
```

它返回前面 JSON 响应状态为 200，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/26a95ed3-d396-4b16-861e-5de873e8ee7c.png)

计算（`power`）资源测试使用 Postman

# 一些更多正测试场景

以下表格中的所有 URL 均以`http://localhost:8080`开头：

| URL | 输出 JSON |
| --- | --- |
| `/calculation/sqrt/12344.234` |

```java
{   
    "function":   "sqrt",   
    "input":   [   
        "12344.234"   
    ],   
    "output":   [   
        "111.1046083652699"   
    ]   
}   
```

|

| `/calculation/sqrt/-9344.34`的`Math.sqrt`函数的特殊场景：如果参数是`NaN`或小于零，则结果是`NaN` |
| --- |

```java
{   
    "function":   "sqrt",   
    "input":   [   
        "-9344.34"   
    ],   
    "output":   [   
        "NaN"   
    ]   
}   
```

|

| `/calculation/power?base=2.09&exponent=4.5` |
| --- |

```java
{   
    "function":   "power",   
    "input":   [   
        "2.09",   
        "4.5"   
    ],   
    "output":   [   
        "27.58406626826615"   
    ]   
}   
```

|

| `/calculation/power?base=-92.9&exponent=-4` |
| --- |

```java
{   
    "function":   "power",   
    "input":   [   
        "-92.9",   
        "-4"   
    ],   
    "output":   [   
        "1.3425706351762353E-8"   
    ]   
}   
```

|

# 负测试场景

同样，您也可以执行一些负场景，如下表所示。在此表中，所有 URL 均以`http://localhost:8080`开头：

| URL | 输出 JSON |
| --- | --- |
| `/calculation/power?base=2a&exponent=4` |

```java
{   
    "function":   "power",   
    "input":   [   
        "2a",   
        "4"   
    ],   
    "output":   [   
        "Base   or/and Exponent is/are not set to numeric value."   
    ]   
}   
```

|

| `/calculation/power?base=2&exponent=4b` |
| --- |

```java
{   
    "function":   "power",   
    "input":   [   
        "2",   
        "4b"   
    ],   
    "output":   [   
        "Base   or/and Exponent is/are not set to numeric value."   
    ]   
}   
```

|

| `/calculation/power?base=2.0a&exponent=a4` |
| --- |

```java
{   
    "function":   "power",   
    "input":   [   
        "2.0a",   
        "a4"   
    ],   
    "output":   [   
        "Base   or/and Exponent is/are not set to numeric value."   
    ]   
}   
```

|

| `/calculation/sqrt/144a` |
| --- |

```java
{   
    "function":   "sqrt",   
    "input":   [   
        "144a"   
    ],   
    "output":   [   
        "Input   value is not set to numeric value."   
    ]   
}   
```

|

| `/calculation/sqrt/144.33$` |
| --- |

```java
{   
    "function":   "sqrt",   
    "input":   [   
        "144.33$"   
    ],   
    "output":   [   
        "Input   value is not set to numeric value."   
    ]   
}   
```

|

# 总结

在本章中，您已经探索了设置开发环境、Maven 配置、Spring Boot 配置等方面的各种方面。

您还学习了如何使用 Spring Boot 开发一个示例 REST 服务应用程序。我们了解到 Spring Boot 有多强大——它极大地简化了开发，以至于你只需要担心实际代码，而不需要担心编写 boilerplate 代码或配置。我们还把我们代码打包成一个带有内嵌应用容器 Jetty 的 JAR 文件。它允许它运行并访问 Web 应用程序，而无需担心部署。

在下一章中，您将学习**领域驱动设计**（**DDD**）。我们使用一个可以用于其他章节的示例项目来了解 DDD。我们将使用名为**在线餐桌预订系统**（**OTRS**）的示例项目来经历微服务开发的各个阶段并了解 DDD。在完成第三章，《领域驱动设计》之后，您将了解 DDD 的基础知识。

你将理解如何实际使用 DDD 设计示例服务。你还将学习如何在它之上设计领域模型和 REST 服务。以下是一些你可以查看以了解更多关于我们在此处使用的工具的链接：

+   **Spring** **Boot**：[`projects.spring.io/spring-boot/`](http://projects.spring.io/spring-boot/)

+   **下载** **NetBeans**：[`netbeans.org/downloads`](https://netbeans.org/downloads)

+   **表示状态传输**（**REST**）：Roy Thomas Fielding 博士学位论文《架构风格与基于网络的软件体系结构设计》的第五章（[`www.ics.uci.edu/~fielding/pubs/dissertation/top.htm`](https://www.ics.uci.edu/~fielding/pubs/dissertation/top.htm)）

+   **REST**: [`en.wikipedia.org/wiki/Representational_state_transfer`](https://en.wikipedia.org/wiki/Representational_state_transfer)

+   **Maven**: [`maven.apache.org/`](https://maven.apache.org/)

+   **Gradle**: [`gradle.org/`](http://gradle.org/)


# 第三章：领域驱动设计

本章通过参考一个样本项目来为接下来的章节定调。样本项目将被用来解释不同微服务概念。本章将通过这个样本项目来驱动不同的功能和领域服务或应用程序的组合，以解释 **领域驱动设计**（**DDD**）。它将帮助你了解 DDD 的基础知识及实际应用。你还将学习使用 REST 服务设计领域模型的概念。

本章涵盖以下主题：

+   DDD 的基础知识

+   如何使用 DDD 设计应用程序

+   领域模型

+   基于 DDD 的样本领域模型设计

一个良好的软件设计对于产品或服务的成功同样重要。它与产品的功能一样重要。例如，`Amazon.com` 提供购物平台，但其架构设计使其与其他类似站点有所不同，并促成了它的成功。这显示了软件或架构设计对产品/服务成功的重要性。DDD 是软件设计实践之一，我们将通过各种理论和实际示例来探讨它。

DDD 是一个关键的设计实践，有助于设计正在开发的产品的微服务。因此，在深入微服务开发之前，我们将首先探讨 DDD。在学习本章之后，你将了解 DDD 对于微服务开发的重要性。

# 领域驱动设计基础知识

企业或云应用程序解决业务问题和其他现实世界的问题。如果没有对领域的了解，这些问题是无法解决的。例如，如果你不了解股票交易所及其运作方式，就无法为在线股票交易等金融系统提供软件解决方案。因此，具备领域知识对于解决问题是必不可少的。现在，如果你想通过软件或应用程序提供解决方案，就需要借助领域知识进行设计。当我们将领域和软件设计结合起来时，就会提供一种被称为 DDD 的软件设计方法论。

当我们开发软件来实现真实世界的场景，提供领域的功能时，我们就会创建一个领域的模型。一个**模型**是对领域的抽象或蓝图。

埃里克·埃文斯在他于 2004 年出版的书《领域驱动设计：攻克软件内在的复杂性》中创造了 DDD 这个词汇。

设计这个模型并不是火箭科学，但它确实需要大量的努力、精炼和领域专家的投入。这是软件设计师、领域专家和开发人员共同的工作。他们组织信息，将其分成更小的部分，逻辑上进行分组，并创建模块。每个模块可以单独处理，可以使用类似的方法进行划分。这个过程可以一直持续到达到单元级别，或者无法再进行划分为止。一个复杂的项目可能会有更多的此类迭代；同样，一个简单的项目可能只会有此类迭代的单个实例。

一旦模型被定义并且文档齐全，它就可以进入下一阶段——代码设计。所以，我们这里有一个**软件设计**——领域模型和代码设计，以及领域模型的代码实现。领域模型提供了一个解决方案（软件/应用程序）的高级架构，而代码实现使领域模型成为一个活生生的模型。

领域驱动设计使设计和开发工作相结合。它提供了一种连续开发软件的能力，同时根据从开发过程中收到的反馈来更新设计。它解决了敏捷和瀑布方法论所提供的限制之一，使软件可维护，包括设计和代码，并保持应用程序的最小可行性。

以设计为驱动的开发方式让开发者从项目初期就参与其中，所有软件设计师与领域专家在建模过程中讨论领域的会议都会涉及到。这种方式为开发者提供了一个理解领域的正确平台，并且提供了分享领域模型实现早期反馈的机会。它消除了在后期阶段，当各方等待可交付成果时出现的瓶颈问题。

# 领域驱动设计的基础知识

为了理解领域驱动设计，我们可以将这些三个概念广泛地归类为：

+   通用语言和统一建模语言（UML）

+   多层架构

+   工件（组件）

接下来的部分将解释通用语言和多层架构的使用和重要性。还将解释在模型驱动设计中要使用的不同工件（组件）。

# 通用语言

**通用语言**是在项目中进行沟通的共同语言。正如我们所见，设计模型是软件设计师、领域专家和开发人员的共同努力；因此，它需要一种共同的语言来进行沟通。领域驱动设计使得使用通用语言成为必要。领域模型在其图表、描述、演示、演讲和会议中使用通用语言。它消除了他们之间的误解、误解释和沟通障碍。因此，它必须包括所有图表、描述、演示、会议等——简而言之，包括所有内容。

**统一建模语言**（**UML**）在创建模型时被广泛使用并且非常受欢迎。它也存在一些局限性；例如，当你从一张纸上画出成千上万的类时，很难表示类之间的关系，同时在理解它们的抽象并从中获取意义。此外，UML 图并不能表示模型的概念以及对象应该做什么。因此，UML 总是应该与其他文档、代码或其他参考资料一起使用，以便有效沟通。

传达领域模型的其他方式包括使用文档、代码等。

# 多层架构

多层架构是 DDD 的常见解决方案。它包含四个层次：

1.  展示层或**用户界面**（**UI**）。

1.  应用层。

1.  领域层。

1.  基础设施层。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/eb42878f-3e3d-4baa-a278-53c9d626d2d3.jpg)

分层架构

从这里可以看出，只有**领域**层负责领域模型，其他层与 UI、应用逻辑等组件有关。这种分层架构非常重要。它将领域相关代码与其他层分开。

在这种多层架构中，每一层都包含相应的代码，它有助于实现松耦合，并避免不同层代码的混合。它还有助于产品/服务的长期可维护性和易于增强，因为如果改变仅针对相应层，则一层代码的变化不会影响其他组件。在多层架构中，每一层都可以容易地与其他实现交换。

# 展示层

这一层代表了用户界面（UI），并为交互和信息展示提供用户界面。这一层可能是一个网络应用、移动应用，或者是消耗你服务的第三方应用。

# 应用层

这一层负责应用逻辑。它维护和协调产品/服务的整体流程。它不包含业务逻辑或 UI。它可能持有应用对象的状态，如进行中的任务。例如，你的产品**REST 服务**将是这一应用层的一部分。

# 领域层

领域层是一个非常重要的层，因为它包含领域信息和业务逻辑。它持有业务对象的状态。它持久化业务对象的状态，并将这些持久化的状态传达给基础设施层。

# 基础设施层

这一层为其他所有层提供支持，负责层与层之间的通信。它包含了其他层使用的支持库。它还实现了业务对象的持久化。

为了理解不同层次之间的交互，让我们以餐厅订桌为例。最终用户通过用户界面（UI）提交订桌请求。UI 将请求传递给应用层。应用层从领域层获取餐厅、餐桌、日期等域对象。领域层从基础设施层获取这些已持久化的对象，并调用相关方法进行订桌并将其持久化回基础设施层。一旦领域对象被持久化，应用层就会向最终用户显示预订确认信息。

# 领域驱动设计工件（Artifacts of domain-driven design）

领域驱动设计中有七个不同的工具有助于表达、创建和检索领域模型：

+   实体（Entities）

+   值对象（Value objects）

+   服务（Services）

+   聚合（Aggregates）

+   仓库（Repository）

+   工厂（Factory）

+   模块（Module）

# 实体（Entities）

实体（Entities）是能够被识别并在产品/服务状态变化中保持不变的一类对象。这些对象不是通过属性来识别，而是通过其身份和持续性线索来识别。这类对象被称为**实体**。

听起来很简单，但它包含了复杂性。我们需要理解我们如何定义实体。让我们以一个订桌系统为例，其中有一个`restaurant`类，具有餐厅名称、地址、电话号码、成立日期等属性。我们可以取`restaurant`类的两个实例，它们不能通过餐厅名称来识别，因为可能有其他拥有相同名称的餐厅。同样，如果我们根据任何其他单一属性来识别，我们也找不到可以单独识别唯一餐厅的属性。如果两个餐厅具有所有相同的属性值，它们因此相同，并且可以相互替换。然而，它们并不是相同的实体，因为两者具有不同的引用（内存地址）。

相反，让我们考虑一组美国公民。每个公民都有自己的社会安全号码。这个号码不仅是唯一的，而且在其公民的一生中保持不变，并确保连续性。这个`citizen`对象将存在于内存中，将被序列化，并将从内存中移除并存储在数据库中。即使人死后，它仍然存在。只要系统存在，它就会在系统中保持。公民的社会安全号码与其表示形式无关，保持不变。

因此，在产品中创建实体意味着创建一个**身份**。现在给前例中的任何餐厅一个身份，然后使用诸如餐厅名称、成立日期和街道等属性的组合来识别它，或者添加一个标识符如`restaurant_id`来识别它。基本规则是两个标识符不能相同。因此，当我们为实体引入一个标识符时，我们需要确切知道它。

为对象创建唯一身份有多种方法，如下所述：

+   使用表中的**主键**。

+   使用领域模块生成的**自动生成 ID**。领域程序生成标识符并将其分配给在不同层次之间被持久化的对象。

+   有些现实生活中的对象本身携带**用户定义的标识符**。例如，每个国家都有它自己的国际直拨电话代码。

+   **复合键**。这是可以用于创建标识符的一组属性，正如前面所述的`restaurant`对象。

实体对于领域模型非常重要，因此，它们应该从建模过程的初始阶段开始定义。

当一个对象可以通过其标识符而不是属性来识别时，代表这些对象的类应该有一个简单的定义，并且要小心生命周期连续性和身份。务必识别具有相同属性值的此类对象。定义良好的系统应对每个对象查询返回唯一结果。设计师应确保模型定义什么是同一事物。

# 值对象

**值对象（VOs）**简化了设计。实体具有诸如身份、生命周期连续性以及不定义其身份的属性等特征。与实体相反，值对象只有属性，没有概念上的身份。最佳实践是将值对象保持为不可变对象。如果可能，实体对象也应该保持不可变。

实体概念可能会让你倾向于将所有对象都当作实体来处理，即在内存或数据库中具有生命周期连续性和唯一可识别性的对象，但每个对象必须有一个实例。现在，假设你在创建客户实体对象。每个客户对象将代表餐厅的客人，这不能用于为其他客人预订订单。如果系统中有百万客户，可能会在内存中创建数百万客户实体对象。系统中不仅存在数百万个唯一可识别的对象，而且每个对象都在被跟踪。跟踪以及创建身份都是复杂的。需要一个高度可信的系统来创建和跟踪这些对象，这不仅非常复杂，而且资源消耗大。这可能会导致系统性能下降。因此，使用值对象而不是实体对象是很重要的。接下来的几段将解释原因。

应用程序并不总是需要可追踪和可识别的客户对象。有时只需某些或所有领域元素的属性。在这些情况下，应用程序可以使用值对象。这使事情变得简单并提高了性能。

由于价值对象没有身份，所以可以很容易地创建和销毁，这简化了设计——如果没有任何其他对象引用它们，价值对象就可以被垃圾回收。

让我们讨论一下价值对象的不可变性。应该设计并编写价值对象为不可变的。一旦它们被创建，在其生命周期内不应该被修改。如果你需要不同价值的 VO，或其任何对象，那么简单地创建一个新的价值对象，但不要修改原来的价值对象。在这里，不可变性继承了**面向对象编程**（**OOP**）的所有重要性。如果一个价值对象是不可变的，那么它可以在不破坏其完整性的情况下被共享和使用。

# 常见问题解答 (FAQs)

+   价值对象可以包含另一个价值对象吗？

    是的，可以 (Yes, it can)

+   价值对象可以引用另一个价值对象或实体吗？

    是的，可以 (Yes, it can)

+   我可以用不同价值对象或实体的属性创建一个价值对象吗？

    是的，你可以 (Yes, you can)

# 服务 (Services)

在创建领域模型的过程中，你可能会遇到各种情况，其中行为可能与任何特定对象无关。这些行为可以容纳在**服务对象**中。

服务对象是领域层的一部分，没有内部状态。服务对象的唯一目的是向领域提供不属于单一实体或价值对象的行为。

通用语言能帮助你在领域建模的过程中识别不同的对象、身份或价值对象，以及它们不同的属性和行为。在创建领域模型的过程中，你可能会发现不同的行为或方法不属于任何一个特定的对象。这些行为很重要，因此不能忽视。你也不能把它们添加到实体或价值对象中。给一个对象添加不属于它的行为会破坏这个对象。要记住，这种行为可能会影响各种对象。面向对象编程的使用使得能够将行为附加到一些对象上，这被称为**服务**。

技术框架中常见服务。在 DDD 中，它们也用于领域层。服务对象没有内部状态；它的唯一目的是向领域提供行为。服务对象提供的行为不能与特定的实体或价值对象相关联。服务对象可能为一个或多个相关实体或价值对象提供一种或多种行为。在领域模型中明确定义服务是一种实践。

在创建服务时，你需要勾选以下所有要点：

+   服务对象的行为对实体和价值对象进行操作，但不属于实体或价值对象。

+   服务对象的行为状态不被维护，因此它们是无状态的 (Stateless)

+   服务是领域模型的一部分

服务也可能存在于其他层中。保持领域层服务的隔离非常重要。它消除了复杂性，并使设计解耦。

让我们来看一个例子，餐厅老板想要查看他每月的餐桌预订报告。在这种情况下，他需要以管理员身份登录，在提供必要的输入字段（如持续时间）后点击**显示报告**按钮。

应用层将请求传递给拥有报告和模板对象的领域层，传递一些参数，如报告 ID 等。使用模板创建报告，并从数据库或其他来源获取数据。然后应用层将所有参数（包括报告 ID）传递给业务层。在这里，需要从数据库或另一个来源获取模板来根据 ID 生成报告。这个操作不属于报告对象或模板对象。因此，使用一个服务对象来执行这个操作，从数据库中获取所需的模板。

# 聚合

聚合领域模式与对象的生命周期相关，定义了所有权和边界。

当您通过应用程序在线预订您最喜欢的餐厅的餐桌时，您不需要担心内部系统发生的预订过程，包括搜索可用的餐厅，然后在给定日期、时间和等等上查找可用的餐桌。因此，您可以说预订应用程序是多个其他对象的**聚合**，并为餐桌预订系统中的所有其他对象充当**根**。

这个根实体应该是一个将对象集合绑在一起的实体，也称为**聚合根**。这个根对象不向外部世界传递内部对象的任何引用，并保护内部对象执行的更改。

我们需要理解为什么需要聚合器。领域模型可能包含大量的领域对象。应用程序的功能和大小越大，设计越复杂，存在的对象数量就越多。这些对象之间存在关系。一些可能具有多对多关系，一些可能具有单对多关系，其他可能具有单对一关系。这些关系在代码中的模型实现或数据库中得到强制执行，确保对象之间的关系保持不变。这些关系不仅仅是单向的，也可能是双向的。它们还可以变得更加复杂。

设计者的任务是简化模型中的这些关系。一些关系在现实领域中可能存在，但在领域模型中可能不需要。设计师需要确保领域模型中不存在此类关系。同样，通过这些约束可以减少多义性。一个约束可以完成许多对象满足关系的工作。也可能将双向关系转换为单向关系。

无论你输入多少简化，你最终可能还是会得到模型中的关系。这些关系需要在代码中维护。当一个对象被移除时，代码应该从其他地方删除对这个对象的所有引用。例如，从一个表中删除记录需要在它以外键等形式被引用的地方进行处理，以保持数据一致性并维护其完整性。另外，在数据变化时，需要强制执行不变量（规则）。

关系、约束和不变量带来了复杂性，需要在代码中有效地处理。我们通过使用由单一实体表示的聚合**根**来找到解决方案，这个实体与一组保持数据变化一致性的对象相关联。

这个根元素是唯一可以从外部访问的对象，因此它充当了一个边界门，将内部对象与外部世界隔开。根可以引用一个或多个内部对象，而这些内部对象又可以引用其他可能有或没有与根的关系的内部对象。然而，外部对象也可以引用根，但不会引用任何内部对象。

聚合确保数据完整性并强制执行不变量。外部对象不能对内部对象做任何更改；他们只能更改根。然而，他们可以通过调用公开操作，使用根对对象内部进行更改。如果需要，根应该将内部对象的值传递给外部对象。

如果聚合对象存储在数据库中，那么查询应该只返回聚合对象。遍历关联应该在聚合根内部链接时返回对象。这些内部对象也可能引用其他聚合。

聚合根实体保持其全局身份，并在其实体内部保持局部身份。

在表预订系统中，聚合的一个简单示例是客户。客户可以暴露给外部对象，而它们的根对象包含它们的内部对象地址和联系信息。

当请求时，内部对象的价值对象，如地址，可以传递给外部对象：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/813a40c6-d3de-48ee-af15-123cafde5086.jpg)

客户作为聚合根

# 仓库

在领域模型中，在给定的时间点，可能存在许多领域对象。每个对象可能都有自己的生命周期，从对象的创建到它们的移除或持久化。每当领域操作需要一个领域对象时，它应该有效地检索所需对象的引用。如果你没有维护所有可用的领域对象，那将会非常困难。一个中心对象携带所有对象的引用，并负责返回请求的对象引用。这个中心对象被称为**仓库**。

仓库是与数据库或文件系统等基础架构交互的点。仓库对象是领域模型中与存储（如数据库）、外部源等交互以检索持久化对象的部分。当仓库收到对对象引用的请求时，它返回现有对象的引用。如果请求的对象在仓库中不存在，那么它从存储中检索该对象。例如，如果您需要一个客户，您会查询仓库对象以提供具有 ID `31`的客户。如果对象在仓库中已经存在，仓库将提供请求的客户对象，如果不存在，它将查询持久化存储，如数据库，获取它，并提供其引用。

使用仓库的主要优点是有一种一致的方法来检索对象，其中请求者不需要直接与存储（如数据库）交互。

仓库可能查询来自各种存储类型的对象，如一个或多个数据库、文件系统或工厂仓库等。在这种情况下，仓库可能有指向不同来源的不同对象类型或类别的策略：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/b8f1ce0c-5528-4b86-9b3c-78c58bcfedfd.jpg)

仓库对象流程

如图所示，仓库对象流程图与基础架构层**交互**，并且这一接口属于**领域层**。**请求者**可能属于领域层，或者应用层。仓库帮助系统管理领域对象的**生命周期**。

# 工厂

**工厂**在简单构造函数不足以创建对象时是必需的。它帮助创建复杂对象，或者涉及创建其他相关对象的聚合。

工厂也是领域对象生命周期的组成部分，因为它是负责创建它们的部分。工厂和仓库在某种程度上是相关的，因为两者都指的是领域对象。工厂指的是新创建的对象，而仓库从内存或外部存储中返回已经存在的对象。

让我们通过使用一个用户创建过程应用程序来查看控制是如何流动的。假设一个用户使用用户名`user1`进行注册。这个用户创建首先与工厂交互，创建了名字`user1`，然后使用仓库在领域中缓存它，该仓库还将其存储在用于持久化的存储中。

当同一用户再次登录时，调用会移动到仓库进行引用。这使用存储来加载引用并将其传递给请求者。

请求者然后可以使用这个`user1`对象在指定餐厅和指定时间预订桌子。这些值作为参数传递，并使用仓库在存储中创建了桌子预订记录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/3e0af162-b03b-49e1-8570-c8ad9657db94.jpg)

仓库对象流程

工厂可能会使用面向对象编程模式中的一种，例如工厂或抽象工厂模式，用于对象创建。

# 模块

**模块**是将相关业务对象分离的最佳方式。这对于大型项目来说非常合适，其中领域对象的规模更大。对于最终用户来说，将领域模型划分为模块并设置这些模块之间的关系是有意义的。一旦你理解了模块及其关系，你开始看到领域模型的更大图景，因此更容易深入理解模型。

模块还有助于高度凝聚的代码，或者保持低耦合的代码。通用语言可以用来为这些模块命名。对于预订表格系统，我们可以有不同的模块，比如用户管理、餐厅和桌子、分析和报告、评论等。

# 战略设计和原则

企业模型通常非常大且复杂。它可能分布在组织中的不同部门。每个部门可能有一个单独的领导团队，因此共同工作和设计可能会产生困难和协调问题。在这种情况下，维护领域模型的完整性并不是一件容易的事。

在这种情况下，统一模型并不是解决方案，大型企业模型需要划分为不同的子模型。这些子模型包含了预定义的准确关系和合同，并且非常详细。每个子模型都必须无例外地维持定义的合同。

有多种原则可以遵循以维护领域模型的完整性，这些原则如下：

+   边界上下文

+   持续集成

+   上下文映射

    +   共享核心

    +   客户-供应商

    +   顺从者

    +   防腐层

    +   分道扬镳

    +   开放主机服务

    +   提炼

# 边界上下文

当你有不同的子模型时，当所有子模型组合在一起时，很难维护代码。你需要一个小模型，可以分配给一个单一团队。你可能需要收集相关元素并将它们分组。上下文通过应用这组条件来保持和维护为其相应子模型定义的领域术语的意义。

这些领域术语定义了创建上下文边界的模型的范围。

边界上下文似乎与前面章节中你学到的模块非常相似。实际上，模块是定义子模型发生和发展的逻辑框架的一部分。而模块负责组织领域模型的元素，并在设计文档和代码中可见。

现在，作为一名设计师，你必须确保每个子模型都有明确的定义并且保持一致。这样，你就可以独立地重构每个模型，而不会影响到其他的子模型。这使得软件设计师能够在任何时候精细和改进模型。

现在，让我们来分析我们一直在使用的表格预订示例。当您开始设计系统时，您会发现客人会访问应用程序，并在选定的餐厅、日期和时间请求表格预订。然后，后端系统会通知餐厅预订信息，同样，餐厅也会更新他们的系统关于表格预订的信息，因为餐厅也可以自己预订表格。所以，当您关注系统的细微之处时，可以看到两个领域模型：

+   在线预订表格系统

+   离线餐厅管理系统

它们都有自己的边界上下文，您需要确保它们之间的接口运行良好。

# 持续集成

当您在开发时，代码分布在许多团队和各种技术中。这些代码可能被组织成不同的模块，并为各自的子模型提供了适用的边界上下文。

这种开发方式可能会带来一定级别的复杂性，例如代码重复、代码断裂或破坏性边界上下文。这不仅是因为代码量大和领域模型大，还因为其他因素，如团队成员变化、新成员加入，或者没有完善的文档模型等。

当使用 DDD 和敏捷方法论设计和开发系统时，在编码开始之前并不会完全设计领域模型，领域模型及其元素会在一段时间内随着持续的改进和细化而发展。

因此，集成继续进行，这是当今开发的关键原因之一，因此它扮演着非常重要的角色。在**持续集成**中，代码频繁合并，以避免任何断裂和领域模型问题。合并的代码不仅被部署，而且它还定期进行测试。市场上有很多可用的持续集成工具，它们在预定时间合并、构建和部署代码。如今，组织更加重视持续集成的自动化。Hudson、TeamCity 和 Jenkins CI 是市场上一些流行的持续集成工具。Hudson 和 Jenkins CI 是开源工具，而 TeamCity 是商业工具。

拥有一个与每个构建关联的测试套件可以确认模型的连贯性和完整性。测试套件从物理角度定义模型，而 UML 则是从逻辑角度。它会告知您任何错误或意外结果，这需要更改代码。它还有助于尽早识别领域模型中的错误和异常。

# 上下文映射

上下文图帮助你理解大型企业应用程序的整体情况。它显示了企业模型中有多少个边界上下文，以及它们是如何相互关联的。因此，我们可以说任何解释边界上下文及其之间关系的图表或文档都称为**上下文** **图**。

上下文图帮助所有团队成员，无论他们是在同一个团队还是不同的团队，都以各种部分（边界上下文或子模型）和关系的形式理解高层次的企业模型。

这使得个人对自己执行的任务有了更清晰的了解，并可能允许他或她就模型的完整性提出任何担忧/问题：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/5347ac92-4666-4d87-99d8-12aa816036da.jpg)

上下文地图示例

上下文地图例图是上下文图的一个样本。在这里，**Table1**和**Table2**都出现在**Table Reservation Context**和**Restaurant Ledger Context**中。有趣的是，**Table1**和**Table2**在各自的边界上下文中都有各自的概念。在这里，通用语言用于将边界上下文命名为**table reservation**和**restaurant ledger**。

在下一节中，我们将探讨几个可以用以来定义上下文图中不同上下文之间通信的模式。

# 共享核心

正如其名，边界上下文的一部分与其他的边界上下文共享。正如下面的图表所示，**Restaurant**实体在**Table Reservation Context**和**Restaurant Ledger Context**之间共享：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/66176460-3b14-45e0-bd1d-986c37b642b6.jpg)

共享核心

# 客户-供应商

客户-供应商模式代表了两个边界上下文之间的关系，当一个边界上下文的输出需要被另一个边界上下文使用时。也就是说，一方向另一方（称为客户）提供信息。

在一个现实世界的例子中，汽车经销商在汽车制造商交付汽车之前是无法销售汽车的。因此，在这个领域模型中，汽车制造商是供应商，经销商是客户。这种关系建立了一个客户-供应商关系，因为一个边界上下文（汽车制造商）的输出（汽车）被另一个边界上下文（经销商）所需要。

在这里，客户和供应商团队应定期会面，以建立合同并形成适当的协议来相互沟通。

# 遵从者

这种模式与客户和供应商的模式相似，其中一方需要提供合同和信息，而另一方需要使用它们。在这里，涉及实际的团队在具有上下游关系的过程中，而不是边界上下文。

此外，上游团队由于缺乏动力，没有为下游团队提供所需的支持。因此，下游团队可能需要计划和处理永远无法获得的项目。为了解决这种情况，如果供应商提供的不够有价值的信息，客户团队可以开发自己的模型。如果供应商提供真正有价值或部分有价值的信息，那么客户可以使用接口或翻译器来消耗供应商提供信息与客户自己的模型。

# 反向腐蚀层

**反向腐蚀层**仍然是领域的一部分，当系统需要从外部系统或自己的遗留系统获取数据时使用。在这里，反向腐蚀层是与外部系统交互并使用外部系统数据在领域模型中，而不会影响领域模型的完整性和原始性。

在大多数情况下，服务可以作为反向腐蚀层使用，该层可能会使用外观模式与适配器和翻译器一起消耗内部模型外的外部领域数据。因此，您的系统总是使用服务来获取数据。服务层可以使用外观模式进行设计。这将确保它与领域模型协同工作，以提供给定格式的所需数据。服务还可以使用适配器和翻译器模式，以确保无论数据以何种格式和层次结构从外部来源发送，服务都能以所需的格式提供数据，并使用适配器和翻译器来处理层次结构。

# 分手

当你有一个大型企业应用程序和一个领域时，其中不同的领域没有共同元素，并且它由可以独立工作的较大子模型组成，这仍然可以作为一个单一应用程序为最终用户工作。

在这种情况下，设计师可以创建没有关系的独立模型，并在其上开发小型应用程序。当这些小型应用程序合并在一起时，它们成为一个单一的应用程序。

提供各种小型应用程序的雇主内部应用程序，例如与人力资源相关的小应用程序、问题跟踪器、交通或公司内部社交网络，是设计师可以使用**分手**模式的一种应用程序。

集成使用不同模型开发的应用程序将非常具有挑战性和复杂。因此，在实施此模式之前应该小心。

# 打开主机服务

当两个子模型相互交互时，使用翻译层。当你将模型与外部系统集成时，使用此翻译层。当你有一个子模型使用这个外部系统时，这种方式工作得很好。当这个外部系统被许多子模型使用时，需要去除额外的和重复的代码，因此需要为每个子模型的外部系统编写一个翻译层。

开放主机服务通过封装所有子模型来提供外部系统的服务。

# 蒸馏

正如你所知，**蒸馏**是净化液体的过程。同样，在 DDD 中，蒸馏是过滤掉不必要的信息，只保留有意义信息的过程。它帮助你识别核心领域和业务领域的关键概念。它帮助你过滤掉通用概念，直到获得核心领域概念。

核心领域应该由开发人员和设计师高度关注细节地进行设计、开发和实现，因为这对于整个系统的成功至关重要。

在我们的表格预订系统示例中，这是一个不大或复杂的领域应用程序，识别核心领域并不困难。这里的核心领域存在是为了共享餐厅的实时准确空闲桌子信息，并允许用户以无麻烦的过程进行预订。

# 示例域名服务

让我们基于我们的表格预订系统创建一个示例域名服务。正如本章所讨论的，高效的领域层是成功产品或服务的关键。基于领域层开发的项目更易于维护，高度凝聚，且松耦合。它们在业务需求变化方面提供高度可扩展性，对其他层的设计影响较低。

领域驱动开发基于领域，因此不建议使用自上而下的方法，其中首先开发 UI，然后是其他层，最后是持久化层。也不建议使用自下而上的方法，其中首先设计持久化层（如数据库），然后是其他层，最后是 UI。

首先开发一个领域模型，使用本书中描述的模式，可以在功能上为所有团队成员提供清晰度，并使软件设计师具有构建灵活、可维护且一致的系统的优势，这有助于组织以更低的维护成本推出世界级的产品。

在这里，你将创建一个餐厅服务，提供添加和检索餐厅的功能。根据实现情况，你可以添加其他功能，例如根据菜系或评分查找餐厅。

从实体开始。在这里，餐厅是我们的实体，因为每个餐厅都是独一无二的，并且有一个标识符。你可以使用一个接口，或一系列接口，来实现在我们的表格预订系统中的实体。理想情况下，如果你遵循接口分离原则，你会使用一系列接口而不是一个单一的接口。

**接口分离原则**（**ISP**）指出，客户不应该被强制依赖于他们不使用的接口。

# 实体实现

对于第一个接口，你可以有一个抽象类或接口，该接口被所有实体所必需。例如，如果我们考虑 ID 和名称，属性对所有实体来说都是共通的。

因此，你可以使用抽象类`Entity`作为领域层中实体的抽象：

```java
public abstract class Entity<T> { 

    T id; 
    String name; 
    ... (getter/setter and other relevant code)} 
```

基于这个，你还可以有一个继承自`Entity`的另一个`abstract`类，一个抽象类：

```java
public abstract class BaseEntity<T> extends Entity<T> { 

    private final boolean isModified;    
    public BaseEntity(T id, String name) { 
        super.id = id; 
        super.name = name; 
        isModified = false; 
    } 
    ... (getter/setter and other relevant code) 
} 
```

基于前面的抽象，我们可以为餐厅管理创建`Restaurant`实体。

现在，由于我们正在开发表格预订系统，`Table`在领域模型中是另一个重要的实体。所以，如果我们遵循聚合模式，`Restaurant`将作为根工作，而`Table`实体将位于`Restaurant`实体内部。因此，`Table`实体总是通过`Restaurant`实体来访问。

你可以使用以下实现创建`Table`实体，并且可以添加你想要的属性。仅为了演示，使用了基本属性：

```java
public class Table extends BaseEntity<BigInteger> { 

    private int capacity; 

    public Table(String name, BigInteger id, int capacity) { 
        super(id, name); 
        this.capacity = capacity; 
    } 

    public void setCapacity(int capacity) { 
        this.capacity = capacity; 
    } 

    public int getCapacity() { 
        return capacity; 
    } 
} 
```

现在，我们可以实现聚合器`Restaurant`类，如下所示。在这里，只使用了基本属性。你可以添加尽可能多的属性，也可以添加其他功能：

```java
public class Restaurant extends BaseEntity<String> { 

    private List<Table> tables = new ArrayList<>(); 
    public Restaurant(String name, String id, List<Table> tables) { 
        super(id, name); 
        this.tables = tables; 
    } 

    public void setTables(List<Table> tables) { 
        this.tables = tables; 
    } 

    public List<Table> getTables() { 
        return tables; 
    } 

    @Override 
    public String toString() { 
        return new StringBuilder("{id: ").append(id).append(", name: ") 
                .append(name).append(", tables: ").append(tables).append("}").toString(); 
    } 
} 
```

# 仓库实现

现在我们可以实现仓库模式，正如本章所学习的那样。首先，你将创建两个接口`Repository`和`ReadOnlyRepository`。`ReadOnlyRepository`接口将用于提供只读操作的抽象，而`Repository`抽象将用于执行所有类型的操作：

```java
public interface ReadOnlyRepository<TE, T> { 

    boolean contains(T id); 

    Entity get(T id); 

    Collection<TE> getAll(); 
} 
```

基于这个接口，我们可以创建`Repository`的抽象，执行诸如添加、删除和更新的额外操作：

```java
public interface Repository<TE, T> extends ReadOnlyRepository<TE, T> { 

    void add(TE entity); 

    void remove(T id); 

    void update(TE entity); 
} 
```

前面定义的`Repository`抽象，可以按照适合你的方式来实现，以持久化你的对象。基础设施层中的持久化代码的变化不会影响到领域层代码，因为合同和抽象是由领域层定义的。领域层使用移除直接具体类的抽象类和接口，提供松耦合。为了演示目的，我们完全可以使用留在内存中的映射来持久化对象：

```java
public interface RestaurantRepository<Restaurant, String> extends Repository<Restaurant, String> { 

    boolean ContainsName(String name); 
} 

public class InMemRestaurantRepository implements RestaurantRepository<Restaurant, String> { 

    private Map<String, Restaurant> entities; 

    public InMemRestaurantRepository() { 
        entities = new HashMap(); 
    } 

    @Override 
    public boolean ContainsName(String name) { 
        return entities.containsKey(name); 
    } 

    @Override 
    public void add(Restaurant entity) { 
        entities.put(entity.getName(), entity); 
    } 

    @Override 
    public void remove(String id) { 
        if (entities.containsKey(id)) { 
            entities.remove(id); 
        } 
    } 

    @Override 
    public void update(Restaurant entity) { 
        if (entities.containsKey(entity.getName())) { 
            entities.put(entity.getName(), entity); 
        } 
    } 

    @Override 
    public boolean contains(String id) { 
        throw new UnsupportedOperationException("Not supported yet."); 
     //To change body of generated methods, choose Tools | Templates. 
    } 

    @Override 
    public Entity get(String id) { 
        throw new UnsupportedOperationException("Not supported yet."); 
     //To change body of generated methods, choose Tools | Templates. 
    } 

    @Override 
    public Collection<Restaurant> getAll() { 
        return entities.values(); 
    } 

} 
```

# 服务实现

与前一种方法相同，你可以将领域服务的抽象分为两部分——主要服务抽象和只读服务抽象：

```java
public abstract class ReadOnlyBaseService<TE, T> { 

    private final Repository<TE, T> repository; 

    ReadOnlyBaseService(ReadOnlyRepository<TE, T> repository) { 
        this.repository = repository; 
    } 
    ... 
} 
```

现在，我们可以使用这个`ReadOnlyBaseService`来创建`BaseService`。在这里，我们通过构造函数使用依赖注入模式将具体对象与抽象对象映射：

```java
public abstract class BaseService<TE, T> extends ReadOnlyBaseService<TE, T> { 
    private final Repository<TE, T> _repository; 

    BaseService(Repository<TE, T> repository) { 
        super(repository); 
        _repository = repository; 
    } 

    public void add(TE entity) throws Exception { 
        _repository.add(entity); 
    } 

    public Collection<TE> getAll() { 
        return _repository.getAll(); 
    } 
} 
```

现在，在定义了服务抽象之后，我们可以像下面这样实现`RestaurantService`：

```java
public class RestaurantService extends BaseService<Restaurant, BigInteger> { 

    private final RestaurantRepository<Restaurant, String> restaurantRepository; 

    public RestaurantService(RestaurantRepository repository) { 
        super(repository); 
        restaurantRepository = repository; 
    } 

    public void add(Restaurant restaurant) throws Exception { 
        if (restaurantRepository.ContainsName(restaurant.getName())) { 
            throw new Exception(String.format("There is already a product with the name - %s", restaurant.getName())); 
        } 

        if (restaurant.getName() == null || "".equals(restaurant.getName())) { 
            throw new Exception("Restaurant name cannot be null or empty string."); 
        } 
        super.add(restaurant); 
    } 
    @Override 
    public Collection<Restaurant> getAll() { 
        return super.getAll(); 
    } 
} 
```

同样，你可以为其他实体编写实现。这段代码是一个基本实现，你可能会在生产代码中添加各种实现和行为。

我们可以编写一个应用类，用来执行和测试我们刚刚编写的示例领域模型代码。

`RestaurantApp.java`文件看起来可能像这样：

```java
public class RestaurantApp { 

    public static void main(String[] args) { 
        try { 
            // Initialize the RestaurantService 
            RestaurantService restaurantService = new RestaurantService(new InMemRestaurantRepository()); 

            // Data Creation for Restaurants 
            Table table1 = new Table("Table 1", BigInteger.ONE, 6); 
            Table table2 = new Table("Table 2", BigInteger.valueOf(2), 4); 
            Table table3 = new Table("Table 3", BigInteger.valueOf(3), 2); 
            List<Table> tableList = new ArrayList(); 
            tableList.add(table1); 
            tableList.add(table2); 
            tableList.add(table3); 
            Restaurant restaurant1 = new Restaurant("Big-O Restaurant", "1", tableList); 

            // Adding the created restaurant using Service 
            restaurantService.add(restaurant1); 

            // Note: To raise an exception give Same restaurant name to one of the below restaurant 
            Restaurant restaurant2 = new Restaurant("Pizza Shops", "2", null); 
            restaurantService.add(restaurant2); 

            Restaurant restaurant3 = new Restaurant("La Pasta", "3", null); 
            restaurantService.add(restaurant3); 

            // Retrieving all restaurants using Service 
            Collection<Restaurant> restaurants = restaurantService.getAll(); 

            // Print the retrieved restaurants on console 
            System.out.println("Restaurants List:"); 
            restaurants.stream().forEach((restaurant) -> { 
                System.out.println(String.format("Restaurant: %s", restaurant)); 
            }); 
        } catch (Exception ex) { 
            System.out.println(String.format("Exception: %s", ex.getMessage())); 
            // Exception Handling Code 
        } 
    } 
} 

```

要执行此程序，可以直接从 IDE 执行，或使用 Maven 运行。它会打印出以下输出：

```java
Scanning for projects... 

------------------------------------------------------------------------ 
Building 6392_chapter3 1.0-SNAPSHOT 
------------------------------------------------------------------------ 

--- exec-maven-plugin:1.5.0:java (default-cli) @ 6392_chapter3 --- 
Restaurants List: 
Restaurant: {id: 3, name: La Pasta, tables: null} 
Restaurant: {id: 2, name: Pizza Shops, tables: null} 
Restaurant: {id: 1, name: Big-O Restaurant, tables: [{id: 1, name: Table 1, capacity: 6}, {id: 2, name: Table 2, capacity: 4}, {id: 3, name: Table 3, capacity: 2}]} 
------------------------------------------------------------------------ 
BUILD SUCCESS 
------------------------------------------------------------------------ 
```

# 总结

在本章中，你已经学习了 DDD 的基础知识。你也探索了多层架构和不同的模式，这些模式可以用 DDD 来开发软件。到这个时候，你应该已经意识到领域模型设计对软件成功的非常重要。总之，我们通过餐厅桌位预订系统演示了一个领域服务实现。

在下一章中，你将学习如何使用设计来实现示例项目。这个示例项目的说明来源于上一章，将使用 DDD 来构建微服务。这一章不仅涵盖了编码，还包括微服务的不同方面，比如构建、单元测试和打包。到下一章结束时，示例微服务项目将准备好部署和使用。
