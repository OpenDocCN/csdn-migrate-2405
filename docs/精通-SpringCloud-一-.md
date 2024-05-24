# 精通 SpringCloud（一）

> 原文：[`zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C`](https://zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

开发、部署和运行云应用应该像本地应用一样简单。这是任何云平台、库或工具背后的主导原则。Spring Cloud 使得在云中开发 JVM 应用变得容易。在这本书中，我们向你介绍 Spring Cloud 并帮助你掌握其功能。

你将学习配置 Spring Cloud 服务器并运行 Eureka 服务器以启用服务注册和发现。然后，你将学习与负载均衡和断路器相关的技术，并利用 Feign 客户端的所有功能。接着，我们将深入探讨高级主题，你将学习为 Spring Cloud 实现分布式跟踪解决方案，并构建基于消息的微服务架构。

# 本书面向对象

本书适合那些希望利用 Spring Cloud 这一开源库快速构建分布式系统的开发者。了解 Java 和 Spring Framework 知识将会有所帮助，但不需要先前的 Spring Cloud 经验。

# 本书涵盖内容

第一章，*微服务简介*，将向你介绍微服务架构、云环境等。你将学习微服务应用与单体应用之间的区别，同时学习如何将单体应用迁移到微服务应用。

第二章，*微服务与 Spring*，将向你介绍 Spring Boot 框架。你将学习如何有效地使用它来创建微服务应用。我们将涵盖诸如使用 Spring MVC 注解创建 REST API、使用 Swagger2 提供 API 文档、以及使用 Spring Boot Actuator 端点暴露健康检查和指标等主题。

第三章，*Spring Cloud 概览*，将简要介绍作为 Spring Cloud 一部分的主要项目。它将重点描述 Spring Cloud 实现的主要模式，并将它们分配给特定的项目。

第四章，*服务发现*，将描述一个使用 Spring Cloud Netflix Eureka 的服务发现模式。你将学习如何以独立模式运行 Eureka 服务器，以及如何运行具有对等复制的多个服务器实例。你还将学习如何在客户端启用发现功能，并在不同区域注册这些客户端。

第五章，*使用 Spring Cloud Config 的分布式配置*，将介绍如何在应用程序中使用 Spring Cloud Config 实现分布式配置。你将学习如何启用不同属性源的后端存储库，并使用 Spring Cloud Bus 推送变更通知。我们将比较发现首先引导和配置首先引导的方法，以说明发现服务与配置服务器之间的集成。

第六章，*微服务之间的通信*，将介绍参与服务间通信的最重要元素：HTTP 客户端和负载均衡器。您将学习如何使用 Spring RestTemplate、Ribbon 和 Feign 客户端，以及如何使用服务发现。

第七章，*高级负载均衡和断路器*，将介绍与微服务之间的服务通信相关的更高级主题。您将学习如何使用 Ribbon 客户端实现不同的负载均衡算法，使用 Hystrix 启用断路器模式，并使用 Hystrix 仪表板来监控通信统计。

第八章，*使用 API 网关的路由和过滤*，将比较两个用作 Spring Cloud 应用程序的 API 网关和代理的项目：Spring Cloud Netlix Zuul 和 Spring Cloud Gateway。您将学习如何将它们与服务发现集成，并创建简单和更高级的路由和过滤规则。

第九章，*分布式日志和跟踪*，将介绍一些用于收集和分析由微服务生成的日志和跟踪信息的热门工具。您将学习如何使用 Spring Cloud Sleuth 附加跟踪信息以及关联的消息。我们将运行一些示例应用程序，这些应用程序与 Elastic Stack 集成以发送日志消息，并与 Zipkin 收集跟踪。

第十章，*附加配置和发现特性*，将介绍两个用于服务发现和分布式配置的流行产品：Consul 和 ZooKeeper。您将学习如何本地运行这些工具，并将您的 Spring Cloud 应用程序与它们集成。

第十一章，*消息驱动的微服务*，将指导您如何为您的微服务提供异步、基于消息的通信。您将学习如何将 RabbitMQ 和 Apache Kafka 消息代理与您的 Spring Cloud 应用程序集成，以实现异步的一对一和发布/订阅通信方式。

第十二章，*保护 API*，将描述保护您的微服务的三种不同方法。我们将实现一个系统，该系统由前面介绍的所有元素组成，通过 SSL 相互通信。您还将学习如何使用 OAuth2 和 JWT 令牌来授权对 API 的请求。

第十三章，*测试 Java 微服务*，将介绍不同的微服务测试策略。它将重点介绍消费者驱动的合同测试，这在微服务环境中特别有用。您将了解如何使用 Hoverfly、Pact、Spring Cloud Contract、Gatling 等框架实现不同类型的自动化测试。

第十四章，*Docker 支持*，将简要介绍 Docker。它将重点介绍在容器化环境中运行和监控微服务最常用的 Docker 命令。您还将学习如何使用流行的持续集成服务器 Jenkins 构建和运行容器，并将它们部署在 Kubernetes 平台上。

第十五章，*云平台上的 Spring 微服务*，将介绍两种支持 Java 应用程序的流行云平台：Pivotal Cloud Foundry 和 Heroku。您将学习如何使用命令行工具或网络控制台在這些平台上部署、启动、扩展和监控您的应用程序。

# 为了充分利用本书

为了成功阅读本书并弄懂所有代码示例，我们期望读者满足以下要求：

+   活动互联网连接

+   Java 8+

+   Docker

+   Maven

+   Git 客户端

# 下载示例代码文件

您可以从 [www.packtpub.com](http://www.packtpub.com) 下载本书的示例代码文件。如果您在其他地方购买了此书，您可以访问 [www.packtpub.com/support](http://www.packtpub.com/support) 并注册，以便将文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册 [www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载与勘误”。

1.  在搜索框中输入书籍名称，并按照屏幕上的指示操作。

文件下载完成后，请确保使用最新版本的软件解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，地址为 [`github.com/PacktPublishing/Mastering-Spring-Cloud`](https://github.com/PacktPublishing/Mastering-Spring-Cloud)。我们还有其他来自我们丰富目录的书籍和视频的代码包，可在 **[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)** 找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理。例如：“HTTP API 端点的最后一个可用版本，`http://localhost:8889/client-service-zone3.yml`，返回与输入文件相同的数据。”

代码块如下所示：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-config-server</artifactId>
</dependency>
```

当我们希望吸引你对代码块的特定部分注意时，相关的行或项目会被设置为粗体：

```java
spring:
 rabbitmq:
  host: 192.168.99.100
  port: 5672
```

任何命令行输入或输出都如下所示：

```java
$ curl -H "X-Vault-Token: client" -X GET http://192.168.99.100:8200/v1/secret/client-service
```

**粗体**：表示新术语、重要词汇或你在屏幕上看到的词汇。例如，菜单或对话框中的词汇在文本中会以这种方式出现。示例：“在谷歌浏览器中，你可以通过访问设置*|*显示高级设置...*|*HTTPS/SSL*|*管理证书来导入一个 PKCS12 密钥库。”

警告或重要说明以这种方式出现。

技巧和窍门以这种方式出现。

# 联系我们

我们总是欢迎读者的反馈。

**一般反馈**：发送电子邮件至`feedback@packtpub.com`，并在消息主题中提及书籍标题。如果你对本书的任何方面有疑问，请通过`questions@packtpub.com`向我们发送电子邮件。

**勘误**：虽然我们已经尽一切努力确保内容的准确性，但错误仍然会发生。如果你在这本书中发现了错误，我们将非常感谢你能向我们报告。请访问[www.packtpub.com/submit-errata](http://www.packtpub.com/submit-errata)，选择你的书籍，点击勘误提交表单链接，并输入详细信息。

**盗版**：如果你在互联网上以任何形式遇到我们作品的非法副本，我们将非常感谢你能提供位置地址或网站名称。请通过`copyright@packtpub.com`联系我们，并提供材料的链接。

**如果你有兴趣成为作者**：如果你在某个话题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评审

请留下评论。一旦你阅读并使用了这本书，为什么不在这本书购买的网站上留下评论呢？潜在的读者可以看到和使用你的客观意见来做出购买决策，我们 Pactt 可以了解你对我们的产品的看法，我们的作者可以看到你对他们书籍的反馈。谢谢！

有关 Pactt 的更多信息，请访问[packtpub.com](https://www.packtpub.com/)。


# 第一章：微服务简介

微服务是近年来 IT 世界中出现的最热门趋势之一。相对容易地识别出它们日益受欢迎的最重要原因。它们的优点和缺点都是众所周知的，尽管我们所说的缺点可以通过使用正确的工具轻易解决。它们提供的优势包括可扩展性、灵活性和独立交付；这些是它们迅速受欢迎的原因。有一些早期的 IT 趋势对微服务受欢迎程度的增长产生了一些影响。我指的是像使用常见的基于云的环境和从关系型数据库迁移到 NoSQL 这样的趋势。

在详细讨论之前，让我们看看本章我们将要覆盖的主题：

+   使用 Spring Cloud 的云原生开发

+   微服务架构中的最重要元素

+   服务间通信模型

+   介绍断路器及其回退模式

# 微服务的恩赐

微服务概念定义了一种 IT 系统架构方法，该方法将应用程序划分为一系列松耦合的服务，这些服务实现业务需求。实际上，这是**面向服务架构**（**SOA**）概念的一个变种。迁移到微服务架构的最重要好处之一是能够执行大型复杂应用程序的持续交付。

到目前为止，你可能有机会阅读一些关于微服务的书籍或文章。我认为，大多数书籍都会给你详细描述它们的优点和缺点。使用微服务有很多优点。首先，对于一个新项目开发者来说，微服务相对较小，容易理解。我们通常想要确保代码中的一个变化不会对我们应用程序的所有其他模块产生不希望的效果。与微服务相比，我们可以对此有更多的确定性，因为我们只实现一个单一的业务领域，而不是像单体应用那样，有时即使看似不相关的功能也会放在同一个篮子里。不仅如此。我注意到，通常，在小微服务中维护预期的代码质量比在一个大的单体应用中（许多开发者引入了他们的更改）要容易。

我喜欢微服务架构的第二个方面与划分有关。到目前为止，当我不得不处理复杂的企业系统时，我总是看到系统根据其他子系统进行划分。例如，电信组织总是有一个计费子系统。然后你创建一个子系统来隐藏计费复杂性并提供一个 API。然后你发现你需要存储在计费系统中无法存储的数据，因为它不容易定制。所以你创建另一个子系统。这实际上导致你构建了一个复杂的子系统网格，如果不你是组织中的新员工，尤其难以理解。使用微服务，你不会有这样的问题。如果它们设计得很好，每个微服务都应该负责一个完整的选择区域。在某些情况下，这些区域与组织活动的部门无关。

# 使用 Spring Framework 构建微服务

尽管微服务概念已经是几年的重要话题，但支持运行完整微服务环境所需的所有功能的稳定框架仍然不多。自从我开始微服务的冒险以来，我一直试图跟上最新的框架，并找出针对微服务需求发展的特性。还有其他一些有趣的解决方案，如 Vert.x 或 Apache Camel，但它们没有一个能与 Spring Framework 相匹敌。

Spring Cloud 实现了所有在微服务架构中使用的经过验证的模式，如服务注册表、配置服务器、断路器、云总线、OAuth2 模式和 API 网关。它拥有强大的社区，因此新功能以高频率发布。它基于 Spring 的开放编程模型，该模型被全球数百万 Java 开发者使用。它也被很好地文档化。你在线找到许多可用的 Spring Framework 使用示例不会有任何问题。

# 云原生开发

微服务与云计算平台有着内在的联系，但微服务的概念并不是什么新东西。这种方法已经在 IT 开发世界中应用了多年，但现在，随着云解决方案的普及，它已经发展到了一个新的高度。指出这种普及的原因并不困难。与组织内部的本地解决方案相比，使用云可以为你提供可扩展性、可靠性和低维护成本。这导致了云原生应用开发方法的兴起，旨在让你充分利用云提供的所有优势，如弹性扩展、不可变部署和可弃实例。这一切都归结于一点——减少满足新需求所需的时间和成本。如今，软件系统和应用程序正在不断地得到改进。如果你采用基于单体的传统开发方法，代码库会不断增长，变得过于复杂，难以进行修改和维护。引入新功能、框架和技术变得困难，从而影响创新，抑制新想法。这是无法争辩的。

这个问题还有另一面。如今，几乎每个人都考虑迁移到云端，部分原因是因为这是潮流。每个人都需要这样做吗？当然不是。那些不确定是否要将应用程序迁移到远程云提供商（如 AWS、Azure 或 Google）的人，至少希望拥有一个本地私有云或 Docker 容器。但这真的能带来补偿所花费费用的好处吗？在考虑云原生开发和云平台之前，值得回答这个问题。

我并不是想阻止你使用 Spring Cloud，恰恰相反。我们必须彻底理解什么是云原生开发。这里有一个非常好的定义：

“云原生应用程序是一个专门为云计算环境而设计的程序，而不是简单地迁移到云端。”

Spring 旨在加速你的云原生开发。使用 Spring Boot 构建应用程序非常快；我将在下一章详细展示如何做到这一点。Spring Cloud 实现微服务架构模式，并帮助我们使用该领域最受欢迎的解决方案。使用这些框架开发的应用程序可以轻松地适应在 Pivotal Cloud Foundry 或 Docker 容器上部署，但它们也可以以传统方式作为一台或多台机器上的分离进程启动，并且你会拥有微服务方法的优点。现在让我们深入了解一下微服务架构。

# 学习微服务架构

设想一下，一个客户找上门来，希望您为他们设计一个解决方案。他们需要某种银行应用程序，该程序需要在整个系统中保证数据一致性。我们的客户到目前为止一直使用 Oracle 数据库，并且还从他们那里购买了支持。不假思索，我们决定设计一个基于关系数据模型的单体应用程序。您可以在以下简化系统设计图中看到系统设计：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/a7bfd463-0994-4cfc-9d65-fe5e5dedb604.png)

数据库中映射了四个实体：

+   第一个实体，**客户**，存储和检索活动客户列表。

+   每个客户可能有一个或多个账户，这些账户由**Account**实体操作。

+   **转账**实体负责执行系统内账户间所有资金的转账。

+   还有一个**产品**实体，用于存储诸如客户存款和信贷等信息。

不深入讨论具体细节，应用程序暴露了 API，提供了实现对设计数据库上操作的所有必要操作。当然，实现符合三层模型。

一致性不再是最重要的要求，甚至不再是强制性的。客户期望一个解决方案，但不想让开发需要重新部署整个应用程序。系统应该是可扩展的，并且能够轻松地扩展新的模块和功能。另外，客户不会对开发者使用 Oracle 或其他关系型数据库施加压力——不仅如此，他还很高兴能避免使用它。这些足够成为决定迁移到微服务的理由吗？让我们假设它们是。我们将我们的单体应用程序分成四个独立的微服务，每个都有自己的专用数据库。在某些情况下，它仍然可以是关系型数据库，而在其他情况下则可以是 NoSQL 数据库。现在，我们的系统由许多独立构建和在我们环境中运行的服务组成。随着微服务数量的增加，系统复杂性也在上升。我们希望能够将这种复杂性隐藏在外部 API 客户端之外，它不应该知道它正在与服务*X*而不是*Y*进行通信。网关负责将所有请求动态路由到不同的端点。例如，单词*dynamically*意味着它应该基于服务发现中的条目，关于服务发现的需要，我将在后面的部分*理解服务发现的需求*中讨论。

隐藏特定服务的调用或动态路由并不是 API 网关的唯一功能。由于它是系统的入口点，因此它可以是一个跟踪重要数据、收集请求指标和其他统计信息的好地方。它可以通过丰富请求或响应头，来包含系统内部应用程序可用的某些额外信息。它应执行一些安全操作，例如身份验证和授权，并应能够检测到每个资源的每个要求，并拒绝不满足它们的请求。下面是一个说明示例系统的图表，该系统由四个独立的微服务组成，隐藏在 API 网关后面的外部客户端中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/fd59b589-e29e-45b3-9496-2a8380086a2d.png)

# 理解服务发现的需求

假设我们已经将我们的单体应用程序划分为更小、独立的微服务。从外部看，我们的系统仍然和以前看起来一样，因为其复杂性隐藏在 API 网关后面。实际上，微服务并不多，但可能有更多。此外，它们中的每一个都可以与其他微服务进行交互。这意味着每个微服务都必须保留有关其他微服务的网络地址的信息。维护此类配置可能非常麻烦，尤其是当涉及到手动重写每个配置时。那么如果这些地址在重启后动态变化呢？下面的图表显示了示例微服务之间的调用路由：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/678ec5f0-b143-418f-a2a5-fc16296b7f3d.png)

服务发现是指在计算机网络上自动检测设备和设备提供的服务。在微服务架构中，这是必要的机制。每个服务启动后应该在自己名称的一个中央位置注册，以便其他所有服务都能访问。注册键应该是服务的名称或标识符，在整个系统中必须是唯一的，以便其他人能够通过该名称找到并调用该服务。每个具有给定名称的键都有一些值与之关联。在大多数情况下，这些属性指示服务的网络位置。更准确地说，它们指示微服务的一个实例，因为它可以作为在不同机器或端口上运行的独立应用程序进行复制。有时可以发送一些附加信息，但这取决于具体的服务发现提供程序。然而，重要的是，在同一键下，可以注册同一服务的多个实例。除了注册，每个服务还会获得其他注册在特定发现服务器上的服务完整列表。不仅如此，每个微服务都必须了解注册列表的任何更改。这可以通过定期更新从远程服务器先前收集的配置来实现。

一些解决方案结合了服务发现和服务器配置功能的使用。归根结底，这两种方法都非常相似。服务器的配置让你能够集中管理系统中的所有配置文件。通常，这样的配置是一个作为 REST web 服务的服务器。在启动之前，每个微服务都会尝试连接到服务器并获取为其准备好的参数。一种方法是将这样的配置存储在版本控制系统中，例如 Git。然后配置服务器更新其 Git 工作副本，并将所有属性作为 JSON 提供。另一种方法是使用存储键值对的解决方案，在服务发现过程中充当提供者的角色。最受欢迎的工具是 Consul 和 Zookeeper。以下图表说明了一个由一些微服务组成的系统架构，这些微服务带有数据库后端，并注册在一个名为**发现服务**的中央服务中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f85f1ca3-e8b1-47ac-8097-785cc2599a49.png)

# 服务之间的通信

为了保证系统的可靠性，我们不能让每个服务只运行一个实例。我们通常希望至少有两个实例在运行，以防其中一个出现故障。当然，可以更多，但我们为了性能原因会尽量减少。无论如何，相同服务多个实例的存在使得使用负载均衡来处理传入请求变得必要。首先，负载均衡器通常内置在 API 网关中。这个负载均衡器应该从发现服务器获取注册实例的列表。如果没有不用的理由，我们通常使用轮询规则，使传入流量在所有运行实例之间平均分配。同样的规则也适用于微服务侧的负载均衡器。

以下图表说明了两个示例微服务实例之间服务间通信的最重要的组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/8c6c8970-d0da-44c2-b4c9-ce53c6919bfb.png)

当人们听到微服务时，他们认为它由 RESTful web 服务组成，使用 JSON 表示法，但这只是可能性之一。我们可以使用一些其他的交互方式，这些方式当然不仅适用于基于微服务的架构。首先应该执行的分类是一对一或一对多的通信。在一对一的交互中，每个传入请求都由一个服务实例处理，而在一对多的情况下，它由多个服务实例处理。但最流行的分类标准是调用是同步还是异步。此外，异步通信可以分为通知。当客户端向服务发送请求，但不需要回复时，它只需执行一个简单的异步调用，这不会阻塞线程，而是异步回复。

此外，值得提及的是反应式微服务。现在，从版本 5 开始，Spring 也支持这种类型的编程。还有支持与 NoSQL 数据库（如 MongoDB 或 Cassandra）交互的反应式支持的库。最后一种著名的通信类型是发布-订阅。这是一种一对多的交互类型，其中客户端发布一条消息，然后被所有监听服务消费。通常，这个模型是使用消息代理实现的，如 Apache Kafka、RabbitMQ 和 ActiveMQ。

# 失败和断路器

我们已经讨论了与微服务架构相关的绝大多数重要概念。这样的机制，如服务发现、API 网关和配置服务器，是有用的元素，它们帮助我们创建一个可靠和高效的系统。即使你在设计系统架构时考虑了这些方面的许多方面，你也应该始终准备好应对失败。在许多情况下，失败的原因完全超出了持有者的控制范围，比如网络或数据库问题。对于基于微服务的系统来说，这类错误尤其严重，因为一个输入请求需要经过许多后续调用才能处理。第一个好的实践是在等待响应时始终使用网络超时。如果单个服务存在性能问题，我们应该尽量减小对其他服务的影响。发送错误响应比长时间等待回复更好，以免阻塞其他线程。

对于网络超时问题，一个有趣的解决方案可能是**断路器模式**。这是一个与微服务方法紧密相关的概念。断路器负责计算成功和失败的请求。如果错误率超过假设的阈值，它就会断开，并导致所有后续尝试立即失败。在特定时间段后，API 客户端应该重新开始发送请求，如果它们成功，则关闭断路器。如果每个服务都有多个实例，其中一个比其他实例慢，那么在负载均衡过程中它就会被忽视。处理部分网络故障的第二个常用机制是**回退**。这是一种在请求失败时必须执行的逻辑。例如，一个服务可以返回缓存数据、默认值或空的结果列表。我个人并不是这种解决方案的忠实粉丝。我更愿意将错误代码传播到其他系统，而不是返回缓存数据或默认值。

# 总结

Spring Cloud 的一大优势在于它支持我们所探讨的所有模式和机制。这些也是稳定的实现，与其他一些框架不同。我在第三章，*Spring Cloud 概览*中详细描述了哪些模式被哪个 Spring Cloud 项目所支持。

在本章中，我们讨论了与微服务架构相关的最重要概念，例如云原生开发、服务发现、分布式配置、API 网关以及断路器模式。我试图阐述我对这种方法在企业应用开发中的优缺点观点。然后，我描述了与微服务相关的的主要模式和解决方案。其中一些是已经存在多年的知名模式，在 IT 世界中被视为新事物。在这份总结中，我想引起您注意一些事情。微服务本质上就是云原生的。像 Spring Boot 和 Spring Cloud 这样的框架可以帮助您加速云原生开发。迁移到云原生开发的主要动机是能够更快地实施和交付应用程序，同时保持高质量。在许多情况下，微服务帮助我们实现这一点，但有时单体架构也是一个不错的选择。

尽管微服务是小型且独立的单元，但它们是集中管理的。例如网络位置、配置、日志文件和指标等信息应该存储在一个中央位置。有各种各样的工具和解决方案提供了所有这些功能。我们将在本书的几乎所有章节中详细讨论它们。Spring Cloud 项目旨在帮助我们整合所有这些内容。我希望能有效地引导您了解它提供的最重要的集成。


# 第二章：用于微服务的 Spring

我知道很多 Java 开发者都接触过 Spring Framework。实际上，它由许多项目组成，可以与许多其他框架一起使用，所以迟早你都会被迫尝试它。尽管与 Spring Boot 的接触经验相对较少，但它已经迅速获得了大量流行。与 Spring Framework 相比，Spring Boot 是一个相对较新的解决方案。它的实际版本是 2，而不是 Spring Framework 的 5。它的创建目的是什么？与标准 Spring Framework 方式相比，使用 Spring Boot 运行应用程序有什么区别？

本章我们将涵盖的主题包括：

+   使用启动器启用项目中的额外功能

+   使用 Spring Web 库实现暴露 REST API 方法的服务

+   使用属性和 YAML 文件自定义服务配置

+   为暴露的 REST 端点提供文档和规范

+   配置健康检查和监控功能

+   使用 Spring Boot 配置文件使应用程序适应不同模式运行

+   使用 ORM 功能与嵌入式和远程 NoSQL 数据库进行交互

# 介绍 Spring Boot

Spring Boot 专为独立运行 Spring 应用程序而设计，与简单的 Java 应用程序一样，可通过 `java -jar` 命令运行。使 Spring Boot 与标准 Spring 配置不同的基本要素就是简单。这种简单与我们需要了解的第一个重要术语紧密相关，那就是“启动器”（starter）。“启动器”是一个可以包含在项目依赖中的工件。它所做的就是为其他必须包含在你应用程序中的工件提供一套依赖项，以实现所需的功能。以这种方式提供的包已准备好使用，这意味着我们不需要配置任何内容使其工作。这让我们想到了与 Spring Boot 相关的第二个重要术语——自动配置。所有通过启动器包含的工件都设置了默认设置，这些设置可以通过属性或其他类型的启动器轻松覆盖。例如，如果你在你的应用程序依赖中包含了 `spring-boot-starter-web`，它将在应用程序启动时嵌入默认的 Web 容器并在默认端口上启动它。展望未来，Spring Boot 中的默认 Web 容器是 Tomcat，它在端口 `8080` 上启动。我们可以通过在应用程序属性文件中声明指定的字段轻松更改此端口，甚至可以通过在项目依赖中包含 `spring-boot-starter-jetty` 或 `spring-boot-starter-undertow` 来更改 Web 容器。

让我再来说一下启动器。它们的官方命名模式是`spring-boot-starter-*`，其中`*`是启动器的特定类型。在 Spring Boot 中有许多启动器可用，但我想要给你简单介绍一下其中最受欢迎的几个，这些也在这本书的后续章节中提供了示例：

| **名称** | **描述** |
| --- | --- |
| `spring-boot-starter` | 核心启动器，包括自动配置支持、日志和 YAML。 |
| `spring-boot-starter-web` | 允许我们构建 Web 应用程序，包括 RESTful 和 Spring MVC。使用 Tomcat 作为默认的嵌入式容器。 |
| `spring-boot-starter-jetty` | 在项目中包含 Jetty，并将其设置为默认的嵌入式 servlet 容器。 |
| `spring-boot-starter-undertow` | 在项目中包含 Undertow，并将其设置为默认的嵌入式 servlet 容器。 |
| `spring-boot-starter-tomcat` | 包含 Tomcat 作为嵌入式 servlet 容器。`spring-boot-starter-web`默认使用的 servlet 容器启动器。 |
| `spring-boot-starter-actuator` | 包含 Spring Boot Actuator，为应用程序提供监控和管理功能。 |
| `spring-boot-starter-jdbc` | 包含 Spring JBDC 和 Tomcat 连接池。特定数据库的驱动应由您自己提供。 |
| `spring-boot-starter-data-jpa` | 包含用于与关系型数据库使用 JPA/Hibernate 交互的所有工件。 |
| `spring-boot-starter-data-mongodb` | 包含与 MongoDB 交互所需的所有工件，并在本地主机上初始化 Mongo 客户端连接。 |
| `spring-boot-starter-security` | 将 Spring Security 包含在项目中，默认启用应用程序的基本安全性。 |
| `spring-boot-starter-test` | 允许使用如 JUnit、Hamcrest 和 Mockito 等库创建单元测试。 |
| `spring-boot-starter-amqp` | 将 Spring AMQP 包含在项目中，并作为默认的 AMQP 经纪人启动 RabbitMQ。 |

如果你对可用的启动器完整列表感兴趣，请参考 Spring Boot 规范。现在，让我们回到 Spring Boot 与 Spring Framework 标准配置之间的主要区别。正如我之前提到的，我们可以包含`spring-boot-starter-web`，它将 Web 容器嵌入到我们的应用程序中。使用标准的 Spring 配置，我们不会将 Web 容器嵌入应用程序中，而是将其作为 WAR 文件部署在 Web 容器上。这是 Spring Boot 用于创建部署在微服务架构中的应用程序的重要原因之一。微服务的一个主要特性是与其它微服务的独立性。在这种情况下，很明显，它们不应该共享常见的资源，如数据库或 Web 容器。在一个 Web 容器上部署许多 WAR 文件是微服务的反模式。因此，Spring Boot 是明显的选择。

个人而言，我在开发许多应用程序时使用了 Spring Boot，不仅是在微服务环境中工作。如果你尝试用它代替标准的 Spring Framework 配置，你将不希望回到过去。支持这个结论，你可以在 GitHub 上找到一个有趣的图表，展示了 Java 框架仓库的流行度：[`redmonk.com/fryan/files/2017/06/java-tier1-relbar-20170622-logo.png`](http://redmonk.com/fryan/files/2017/06/java-tier1-relbar-20170622-logo.png)。让我们仔细看看如何使用 Spring Boot 开发应用程序。

# 使用 Spring Boot 开发应用程序

在项目中启用 Spring Boot 的推荐方式是使用一个依赖管理系统。在这里，你可以看到一个简短的片段，展示了如何在你的 Maven 和 Gradle 项目中包含适当的工件。以下是 Maven `pom.xml`的一个示例片段：

```java
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.5.7.RELEASE</version>
</parent>
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

使用 Gradle，我们不需要定义父级依赖。以下是`build.gradle`的一个片段：

```java
plugins {
    id 'org.springframework.boot' version '1.5.7.RELEASE'
}
dependencies {
    compile("org.springframework.boot:spring-boot-starter-web:1.5.7.RELEASE")
}
```

当使用 Maven 时，继承`spring-boot-starter-parent` POM 并不是必要的。另外，我们可以使用依赖管理机制：

```java
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>1.5.7.RELEASE</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

现在，我们需要的只是创建一个主应用程序类并给它加上`@SpringBootApplication`注解，这个注解相当于其他三个注解的组合——`@Configuration`、`@EnableAutoConfiguration`和`@ComponentScan`：

```java
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
```

一旦我们声明了主类并包括了`spring-boot-starter-web`，我们只需要运行我们的第一个应用程序。如果你使用一个开发 IDE，比如 Eclipse 或 IntelliJ，你应该直接运行你的主类。否则，应用程序必须像标准的 Java 应用程序一样使用`java -jar`命令进行构建和运行。首先，我们应该提供负责在应用程序构建过程中将所有依赖项打包成可执行 JAR（有时被称为**胖 JAR**）的配置。如果定义在 Maven `pom.xml`中，这个操作将由`spring-boot-maven-plugin`执行：

```java
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
    </plugins>
</build>
```

示例应用程序所做的不仅仅是启动在 Tomcat 容器上的 Spring 上下文，该容器在端口`8080`上可用。胖 JAR 的大小约为 14 MB。你可以很容易地，使用 IDE，查看项目中包含了哪些库。这些都是基本的 Spring 库，如`spring-core`、`spring-aop`、`spring-context`；Spring Boot；Tomcat 嵌入式；包括 Logback、Log4j 和 Slf4j 在内的日志库；以及用于 JSON 序列化或反序列化的 Jackson 库。一个好的建议是为项目设置默认的 Java 版本。你可以在`pom.xml`中很容易地设置它，通过声明`java.version`属性：

```java
<properties>
    <java.version>1.8</java.version>
</properties>
```

我们可以通过添加一个新的依赖项来更改默认的 Web 容器，例如，使用 Jetty 服务器：

```java
 <dependency>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-jetty</artifactId>
 </dependency>  
```

# 定制配置文件

快速且不需要大量工作来创建应用程序的能力固然重要，但同样重要的是能够轻松自定义和覆盖默认设置的能力。Spring Boot 应运而生，并提供了实现配置管理的机制。实现这一点的最简单方法是使用配置文件，这些文件附加到应用程序的胖 JAR 中。Spring Boot 会自动检测以`application`前缀开头的配置文件。支持的文件类型是`.properties`和`.yml`。因此，我们可以创建如`application.properties`或`application.yml`的配置文件，甚至包括特定于配置文件后缀的文件，如`application-prod.properties`或`application-dev.yml`。此外，我们还可以使用操作系统环境变量和命令行参数来外部化配置。当使用属性文件或 YAML 文件时，它们应该放置在以下位置之一：

+   当前应用程序目录的`/config`子目录

+   当前应用程序目录

+   类路径上的`/config`包（例如，在你的 JAR 文件中）

+   类路径根目录

如果你想给你的配置文件指定一个特定的名字，除了`application`或者`application-{profile}`之外，你需要在启动时提供一个`spring.config.name`环境属性。你也可以使用`spring.config.location`属性，它包含一个由逗号分隔的目录位置或文件路径列表：

```java
java -jar sample-spring-boot-web.jar --spring.config.name=example
java -jar sample-spring-boot-web.jar --spring.config.location=classpath:/example.properties
```

在配置文件内部，我们可以定义两种类型的属性。首先是一组通用的、预定义的 Spring Boot 属性，这些属性通常由底层的类从`spring-boot-autoconfigure`库中消费。我们也可以定义我们自己的自定义配置属性，然后使用`@Value`或`@ConfigurationProperties`注解将它们注入到应用程序中。

让我们先来看看预定义的属性。Spring Boot 项目支持的全部属性在其文档中的*附录 A*，*通用应用程序属性*部分中列出。其中大部分是特定于某些 Spring 模块的，如数据库、网络服务器、安全和一些其他解决方案，但也有一组核心属性。我个人更喜欢使用 YAML 而不是属性文件，因为它可以很容易地被人类阅读，但最终决定权在你。通常，我会覆盖如应用程序名称、用于服务发现和分布式配置管理的网络服务器端口、日志记录或数据库连接设置等属性。通常，`application.yml`文件放在`src/main/resources`目录中，在 Maven 构建后，该目录位于 JAR 根目录中。这是一个覆盖默认服务器端口、应用程序名称和日志记录属性的示例配置文件：

```java
server: 
    port: ${port:2222}

spring: 
    application:
        name: first-service

logging:
    pattern:
        console: "%d{HH:mm:ss.SSS} %-5level %logger{36} - %msg%n"
        file: "%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n"
    level:
        org.springframework.web: DEBUG
    file: app.log
```

这里真正酷的一点是，你不需要定义任何其他外部配置文件，例如`log4j.xml`或`logback.xml`，用于日志配置。在前一部分，你可以看到我将`org.springframework.web`的默认日志级别更改为`DEBUG`，并修改了日志模式，创建了一个日志文件`app.log`，放在当前应用程序目录中。现在，默认的应用程序名是`first-service`，默认的 HTTP 端口是`2222`。

我们的自定义配置设置也应该放在相同的属性或 YAML 文件中。以下是带有自定义属性的一个`application.yml`样本：

```java
name: first-service
my:
  servers:
    - dev.bar.com
    - foo.bar.com  
```

可以使用`@Value`注解注入一个简单的属性：

```java
@Component
public class CustomBean {

    @Value("${name}")
    private String name;

    // ...
}
```

还可以使用`@ConfigurationProperties`注解注入更复杂的配置属性。YAML 文件中`my.servers`属性定义的值被注入到目标 bean 类型`java.util.List`中：

```java
@ConfigurationProperties(prefix="my")
public class Config {

    private List<String> servers = new ArrayList<String>();

    public List<String> getServers() {
        return this.servers;
    }
}
```

到目前为止，我们已经成功创建了一个简单的应用程序，它所做的只是在一个诸如 Tomcat 或 Jetty 的 web 容器上启动 Spring。在本章的这部分，我想向您展示使用 Spring Boot 开始应用程序开发是多么简单。除此之外，我还描述了如何使用 YAML 或属性文件自定义配置。对于那些喜欢点击而不是打字的人来说，我推荐使用 Spring Initializr 网站([`start.spring.io/`](https://start.spring.io/)），你可以在该网站上根据你选择的选项生成项目骨架。在简单视图中，你可以选择构建工具（Maven/Gradle）、语言（Java/Kotlin/Groovy）和 Spring Boot 版本。然后，你应该使用搜索引擎根据“搜索依赖项”标签提供所有必要的依赖项。我在其中包含了`spring-boot-starter-web`，正如你在下面的截图中看到的，在 Spring Initializr 上它只被标记为`Web`。点击“生成项目”后，生成的源代码的 ZIP 文件会被下载到你的电脑上。你可能还想知道，通过点击“切换到完整版本”，你可以看到 Spring Boot 和 Spring Cloud 几乎所有的库，这些库可以包含在生成的项目中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/557eaa38-1948-4896-88cf-48587b8e60d8.png)

我认为，既然我们已经复习了使用 Spring Boot 构建项目的基础知识，现在为我们的示例应用程序添加一些新功能正是时候。

# 创建 RESTful Web 服务

作为第一步，让我们创建一些面向调用客户端的 RESTful Web 服务。正如前面提到的，负责 JSON 消息序列化和反序列化的 Jackson 库，已经自动包含在我们的类路径中，与`spring-boot-starter-web`一起。因此，我们除了声明一个模型类之外，不需要做更多的操作，该模型类随后由 REST 方法返回或作为参数接收。以下是我们的示例模型类`Person`：

```java
public class Person {

    private Long id;
    private String firstName;
    private String lastName;
    private int age;
    private Gender gender;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    //...
}
```

Spring Web 提供了一些用于创建 RESTful Web 服务的注解。首先是`@RestController`注解，它应该设置在你负责处理传入 HTTP 请求的控制器 bean 类上。还有`@RequestMapping`注解，通常用于将控制器方法映射到 HTTP。正如你在下面的代码片段中所看到的，它可以用在整个控制器类上，为其中的所有方法设置请求路径。我们可以使用更具体的注解为具体的 HTTP 方法 such as `@GetMapping`或`@PostMapping`。`@GetMapping`与`@RequestMapping`参数`method=RequestMethod.GET`相同。另外两个常用的注解是`@RequestParam`和`@RequestBody`。第一个将路径和查询参数绑定到对象；第二个使用 Jackson 库将输入 JSON 映射到对象：

```java
@RestController
@RequestMapping("/person")
public class PersonController {

    private List<Person> persons = new ArrayList<>(); 

    @GetMapping
    public List<Person> findAll() {
         return persons;
     }

    @GetMapping("/{id}")
    public Person findById(@RequestParam("id") Long id) {
        return persons.stream().filter(it -> it.getId().equals(id)).findFirst().get();
    }

    @PostMapping
    public Person add(@RequestBody Person p) {
        p.setId((long) (persons.size()+1));
        persons.add(p);
        return p;
    }

    // ...
}
```

为了与 REST API 标准兼容，我们应该处理`PUT`和`DELETE`方法。在它们的实现之后，我们的服务执行所有的 CRUD 操作：

| **方法** | **路径** | **描述** |
| --- | --- | --- |
| `GET` | `/person` | 返回所有现有的人员 |
| `GET` | `/person/{id}` | 返回给定*id*的人员 |
| `POST` | `/person` | 添加新人员 |
| `PUT` | `/person` | 更新现有人员 |
| `DELETE` | `/person/{id}` | 使用给定的*id*从列表中删除人员 |

以下是带有`DELETE`和`PUT`方法的示例`@RestController`实现的片段：

```java
@DeleteMapping("/{id}")
public void delete(@RequestParam("id") Long id) {
    List<Person> p = persons.stream().filter(it -> it.getId().equals(id)).collect(Collectors.toList());
    persons.removeAll(p);
}

@PutMapping
public void update(@RequestBody Person p) {
    Person person = persons.stream().filter(it -> it.getId().equals(p.getId())).findFirst().get();
    persons.set(persons.indexOf(person), p);
}
```

控制器代码非常简单。它将所有数据存储在本地`java.util.List`中，这显然不是一种好的编程实践。然而，将此视为为了基本示例而采用的简化。在本章的*将应用程序与数据库集成*部分，我将介绍一个更高级的示例应用程序，该应用程序集成了 NoSQL 数据库。

可能有些同学有使用 SOAP Web 服务的经验。如果我们用 SOAP 而不是 REST 创建了一个类似的的服务，我们将为客户端提供一个 WSDL 文件，其中包含所有服务定义。不幸的是，REST 不支持像 WSDL 这样的标准表示法。在 RESTful Web 服务的初期阶段，人们曾说过 **Web 应用程序描述语言**（**WADL**）将承担这一角色。但现实情况是，包括 Spring Web 在内的许多提供者，在应用程序启动后并不会生成 WADL 文件。我为什么要提到这些呢？嗯，我们已经完成了我们的第一个微服务，它通过 HTTP 暴露了一些 REST 操作。你可能在使用这个微服务时，在 IDE 中运行它，或者使用 `java -jar` 命令在构建完胖 JAR 之后运行它。如果你没有修改 `application.yml` 文件中的配置属性，或者在运行应用程序时没有设置 `-Dport` 选项，那么它将在 `http://localhost:2222` 上运行。为了使其他人调用我们的 API，我们有两个选择。我们可以分享一份描述其使用或自动生成 API 客户端机制的文档。或者两者都有。Swagger 就在这时介入了。

# API 文档

**Swagger** 是设计、构建和文档化 RESTful API 的最受欢迎的工具。它是由 SoapUI（一个非常流行的 SOAP Web 服务工具）的设计者 SmartBear 创建的。我认为这对于那些有丰富 SOAP 经验的人来说已经足够推荐了。无论如何，使用 Swagger，我们可以使用表示法设计 API 然后从它生成源代码，或者反过来，我们从源代码开始然后生成一个 Swagger 文件。与 Spring Boot 一起，我们使用后一种方法。

# 使用 Swagger 2 与 Spring Boot 一起

**Spring Boot** 与 **Swagger 2** 的集成是由 Springfox 项目实现的。它在运行时检查应用程序，以推断基于 Spring 配置、类结构和 Java 注解的 API 语义。为了将 Swagger 与 Spring 结合使用，我们需要在 Maven `pom.xml` 中添加以下两个依赖，并用 `@EnableSwagger2` 注解主应用类：

```java
<dependency>
    <groupId>io.springfox</groupId>
    <artifactId>springfox-swagger2</artifactId>
    <version>2.7.0</version>
</dependency>
<dependency>
    <groupId>io.springfox</groupId>
    <artifactId>springfox-swagger-ui</artifactId>
    <version>2.7.0</version>
</dependency>
```

API 文档将在应用程序启动时由 Swagger 库从源代码自动生成。这个过程由 `Docket` bean 控制，它也声明在主类中。一个好主意可能是从 Maven `pom.xml` 文件中获取 API 版本。我们可以通过在类路径中包含 `maven-model` 库并使用 `MavenXpp3Reader` 类来实现。我们还使用 `apiInfo` 方法设置一些其他属性，如标题、作者和描述。默认情况下，Swagger 为所有 REST 服务生成文档，包括由 Spring Boot 创建的服务。我们想要限制此文档只包含位于 `pl.piomin.services.boot.controller` 包内的 `@RestController`：

```java
  @Bean
  public Docket api() throws IOException, XmlPullParserException {
    MavenXpp3Reader reader = new MavenXpp3Reader();
    Model model = reader.read(new FileReader("pom.xml"));
    ApiInfoBuilder builder = new ApiInfoBuilder()
        .title("Person Service Api Documentation")
        .description("Documentation automatically generated")
        .version(model.getVersion())
        .contact(new Contact("Piotr Mińkowski", "piotrminkowski.wordpress.com", "piotr.minkowski@gmail.com"));
    return new Docket(DocumentationType.SWAGGER_2).select()
        .apis(RequestHandlerSelectors.basePackage("pl.piomin.services.boot.controller"))
        .paths(PathSelectors.any()).build()
        .apiInfo(builder.build());
  }
```

# 使用 Swagger UI 测试 API

应用程序启动后，在`http://localhost:2222/swagger-ui.html`上提供了 API 文档仪表板。这是 Swagger JSON 定义文件的更用户友好的版本，也是自动生成的，并在`http://localhost:2222/v2/api-docs`上可用。该文件可以被其他 REST 工具导入，例如 SoapUI：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/596d9d1a-0019-43dd-b4c8-62222a248ba9.png)

如果你更喜欢 SoapUI 而不是 Swagger UI，你可以通过选择项目|导入 Swagger 来轻松导入 Swagger 定义文件。然后，你需要提供一个文件地址，正如你在这张截图中所看到的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/8cc43aa0-54b2-4fe5-b60f-3ac8f70ef909.png)

个人而言，我更喜欢 Swagger UI。你可以展开每个 API 方法以查看它们的详细信息。每个操作都可以通过提供所需的参数或 JSON 输入，并点击“尝试一下！”按钮来进行测试。这里有一张截图，展示了发送一个`POST /person`测试请求的情况：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/05eff4f3-d1c5-46ab-86b2-5d61833a77c6.png)

这是响应屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/edd90841-af55-443e-b42c-53ed834daf17.png)

# Spring Boot Actuator 功能

仅仅创建工作应用程序并分享标准的 API 文档是不够的，特别是当我们谈论微服务时，那里有很多独立的实体结构成一个受管理的环境。接下来需要提到的重要事情是监控和收集应用程序的度量信息。在这方面，Spring Boot 也提供了支持。Spring Boot 项目提供了许多内置端点，允许我们监控并与应用程序互动。为了在我们的项目中启用它，我们应该在依赖项中包含`spring-boot-starter-actuator`。以下是最重要的 Actuator 端点列表：

| **路径** | **描述** |
| --- | --- |
| `/beans` | 显示应用程序中初始化的所有 Spring bean 的完整列表。 |
| `/env` | 暴露 Spring 的 Configurable Environment 中的属性，这意味着例如操作系统环境变量和配置文件中的属性。 |
| `/health` | 显示应用程序的健康信息。 |
| `/info` | 显示任意应用程序信息。它可以从例如`build-info.properties`或`git.properties`文件中获取。 |
| `/loggers` | 显示并修改应用程序中的日志记录器配置。 |
| `/metrics` | 显示当前应用程序的度量信息，例如内存使用情况、运行线程数或 REST 方法响应时间。 |
| `/trace` | 显示跟踪信息（默认显示最后 100 个 HTTP 请求）。 |

使用 Spring 配置属性，端点可以很容易地进行自定义。例如，我们可以禁用默认启用的端点中的一个。默认情况下，除了`shutdown`之外的所有端点都是启用的。其中大多数端点都是受保护的。如果你想要从网页浏览器中调用它们，你应在请求头中提供安全凭据，或者为整个项目禁用安全功能。要实现后者，你需要在你的`application.yml`文件中包含以下语句：

```java
management:
  security:
    enabled: false
```

# 应用程序信息

项目可用的端点完整列表在应用程序启动时的日志中可见。在禁用安全功能后，你可以在网页浏览器中测试它们全部。有趣的是，`/info`端点默认不提供任何信息。如果你想要改变这一点，你可以使用其中三个可用的自动配置`InfoContributor` bean 中的一个，或者编写你自己的。第一个，`EnvironmentInfoContributor`，在端点中暴露环境键。第二个，`GitInfoContributor`，在类路径中检测`git.properties`文件，然后显示关于提交的所有必要信息，如分支名称或提交 ID。最后一个，名为`BuildInfoContributor`，从`META-INF/build-info.properties`文件中收集信息，并在端点中也显示它。这两个用于 Git 和构建信息的属性文件可以在应用程序构建过程中自动生成。为了实现这一点，你应该在你的`pom.xml`中包含`git-commit-id-plugin`，并自定义`spring-boot-maven-plugin`以生成`build-info.properties`，如本代码片段中所见：

```java
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <executions>
        <execution>
            <goals>
                <goal>build-info</goal>
                <goal>repackage</goal>
            </goals>
            <configuration>
                <additionalProperties>
                    <java.target>${maven.compiler.target}</java.target>
                    <time>${maven.build.timestamp}</time>
                </additionalProperties>
            </configuration>
        </execution>
    </executions>
</plugin>
<plugin>
    <groupId>pl.project13.maven</groupId>
    <artifactId>git-commit-id-plugin</artifactId>
    <configuration>
    <failOnNoGitDirectory>false</failOnNoGitDirectory>
    </configuration>
</plugin>
```

有了可用的`build-info.properties`文件，你的`/info`将和之前有点不同：

```java
{ 
    "build": {
        "version":"1.0-SNAPSHOT",
        "java": {
            "target":"1.8"
        },
        "artifact":"sample-spring-boot-web",
        "name":"sample-spring-boot-web",
        "group":"pl.piomin.services",
        "time":"2017-10-04T10:23:22Z"
    }
}
```

# 健康信息

与`/info`端点一样，`/health`端点也有一些自动配置的指标。我们可以监控磁盘使用情况、邮件服务、JMS、数据源以及 NoSQL 数据库（如 MongoDB 或 Cassandra）的状态。如果你从我们的示例应用程序中检查该端点，你只能得到关于磁盘使用情况的信息。让我们在项目中添加 MongoDB 来测试其中一个可用的健康指标，`MongoHealthIndicator`。MongoDB 并非随机选择。它在未来对于`Person`微服务的更高级示例中将很有用。为了启用 MongoDB，我们需要在`pom.xml`中添加以下依赖项。`de.flapdoodle.embed.mongo`构件在应用程序启动期间负责启动嵌入式数据库实例：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-mongodb</artifactId>
</dependency>
<dependency>
    <groupId>de.flapdoodle.embed</groupId>
    <artifactId>de.flapdoodle.embed.mongo</artifactId>
</dependency>
```

现在，`/health`端点返回了关于磁盘使用情况和 MongoDB 状态的信息：

```java
{
 "status":"UP",
 "diskSpace":{
 "status":"UP",
 "total":499808989184,
 "free":193956904960,
 "threshold":10485760
 },
 "mongo":{
 "status":"UP",
 "version":"3.2.2"
 }
} 
```

在这个例子中，我们可以看到 Spring Boot 自动配置的力量。我们只需要将两个依赖项添加到项目中，就可以启用嵌入式 MongoDB。其状态已自动添加到`/health`端点。它还有一个对 Mongo ready-to-use 的客户端连接，这可以被进一步用于仓库 bean。

# 指标

正如我们通常所说的，没有免费的午餐。发展既快又容易，但在项目中包含一些额外的库后，庞大的 JAR 文件现在大约有 30 MB。使用自动配置的 actuator 端点之一，`/metrics`，我们可以轻松查看微服务的堆内存和非堆内存使用情况。发送一些测试请求后，堆内存使用大约为 140 MB，非堆内存为 65 MB。应用程序的总内存使用量约为 320 MB。当然，即使只是使用`java -jar`命令启动时使用`-Xmx`参数，这些值也可以稍微降低。然而，如果我们关心在生产模式下的可靠工作，就不应该将此限制降低太多。除了内存使用情况外，`/metrics`端点还显示了加载的类数量、活动线程数、每个 API 方法的平均持续时间等信息。以下是我们示例微服务端点响应的一个片段：

```java
{
 "mem":325484,
 "mem.free":121745,
 "processors":4,
 "instance.uptime":765785,
 "uptime":775049,
 "heap.committed":260608,
 "heap.init":131072,
 "heap.used":138862,
 "heap":1846272,
 "nonheap.committed":75264,
 "nonheap.init":2496,
 "nonheap.used":64876,
 "threads.peak":28,
 "threads.totalStarted":33,
 "threads":28,
 "classes":9535,
 "classes.loaded":9535,
 "gauge.response.person":7.0,
 "counter.status.200.person":4,
 // ...
} 
```

有可能创建我们自己的自定义指标。Spring Boot Actuator 提供了两个类，以便我们这样做——`CounterService`和`GaugeService`。正如其名称所暗示的，`CounterService`暴露了增加值、减少值和重置值的方法。相比之下，`GaugeService`旨在仅提交当前值。默认的 API 方法调用统计数据有点不完美，因为它们仅基于调用路径。如果它们在同一路径上可用，则无法区分方法类型。在我们的示例端点中，这适用于`GET /person`、`POST /person`和`PUT /person`。无论如何，我创建了`PersonCounterService` bean，用于计算`add`和`delete`方法调用的数量：

```java
@Service
public class PersonCounterService {
    private final CounterService counterService;

    @Autowired
    public PersonCounterService(CounterService counterService) {
        this.counterService = counterService;
    }

    public void countNewPersons() {
        this.counterService.increment("services.person.add");
    }

    public void countDeletedPersons() {
        this.counterService.increment("services.person.deleted");
    } 
}
```

这个 bean 需要被注入到我们的 REST 控制器 bean 中，当一个人被添加或删除时，可以调用增加计数值的方法：

```java
public class PersonController {

    @Autowired
    PersonCounterService counterService;

    // ...

    @PostMapping
    public Person add(@RequestBody Person p) {
        p.setId((long) (persons.size()+1));
        persons.add(p);
        counterService.countNewPersons();
        return p;
    }

    @DeleteMapping("/{id}")
    public void delete(@RequestParam("id") Long id) {
        List<Person> p = persons.stream().filter(it -> it.getId().equals(id)).collect(Collectors.toList());
        persons.removeAll(p);
        counterService.countDeletedPersons();
    } 
}
```

现在，如果你再次显示应用程序指标，你将在 JSON 响应中看到以下两个新字段：

```java
{
    // ...
    "counter.services.person.add":4,
    "counter.services.person.deleted":3
}
```

所有由 Spring Boot 应用程序生成的指标都可以从内存缓冲区导出到一个可以分析和显示的地方。例如，我们可以将它们存储在 Redis、Open TSDB、Statsd 或甚至 InfluxDB 中。

我认为关于内置监控端点的细节差不多就这些了。我为此类主题如文档、指标和健康检查分配了相对较多的空间，但在我看来，这些都是微服务开发和维护的重要方面。开发者通常不在乎这些机制是否实现得很好，但其他人通常只是通过这些指标、健康检查和应用程序日志的质量来看我们的应用程序。Spring Boot 提供了这样的实现，因此开发者不必花太多时间来启用它们。

# 开发者工具

Spring Boot 为开发者提供了其他一些有用的工具。对我来说真正酷的是，项目类路径上的文件发生变化时，应用程序会自动重新启动。如果你使用 Eclipse 作为你的 IDE，要启用它，你只需要在 Maven 的 `pom.xml` 中添加 `spring-boot-devtools` 依赖。然后，尝试更改你其中一个类中的某个东西并保存它。应用程序会自动重新启动，而且所用时间远比标准方式停止和启动要少。当我启动我们的示例应用程序时，大约需要 9 秒钟，而自动重启只需要 3 秒：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <optional>true</optional>
</dependency>
```

如果我们不需要在更改时触发重启，我们可以排除一些资源。默认情况下，类路径上可用的任何指向文件夹的文件都将被监控以检测更改，即使是静态资产或视图模板，也不需要重新启动。例如，如果它们放在静态文件夹中，你可以在 `application.yml` 配置文件中添加以下属性来排除它们：

```java
spring:
 devtools:
   restart:
     exclude: static/**
```

# 将应用程序与数据库集成

你可以在 Spring Boot 规范中找到更多有趣的特性。我想花更多时间描述该框架提供的其他酷功能，但我们不应该偏离主题太远——Spring 用于微服务。正如你可能记得的，通过在项目中包含嵌入式 MongoDB，我答应给你一个更高级的微服务示例。在开始处理它之前，让我们回到我们应用程序的当前版本。它的源代码可以在我的公共 GitHub 账户上找到。将以下 Git 仓库克隆到你的本地机器：[`github.com/piomin/sample-spring-boot-web.git`](https://github.com/piomin/sample-spring-boot-web.git)。

# 构建一个示例应用程序

基本示例可以在 `master` 分支中找到。带有嵌入式 MongoDB 的更高级示例提交到了 `mongo` 分支。如果你想尝试运行更高级的示例，你需要使用 `git checkout mongo` 切换到那个分支。现在，我们需要在模型类中进行一些更改，以启用对 MongoDB 的对象映射。模型类必须用 `@Document` 注解，主键字段用 `@Id` 注解。我还将 ID 字段类型从 `Long` 改为 `String`，因为 MongoDB 使用 UUID 格式的的主键，例如 `59d63385206b6d14b854a45c`：

```java
@Document(collection = "person")
public class Person {

    @Id
    private String id;
    private String firstName;
    private String lastName;
    private int age;
    private Gender gender;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
    // ...
}
```

下一步是创建一个扩展了`MongoRepository`的仓库接口。MongoRepository 为搜索和存储数据提供了基本方法，如`findAll`、`findOne`、`save`和`delete`。Spring Data 有一个非常智能的机制，利用仓库对象执行查询。我们不需要自己实现查询，只需定义一个命名正确的接口方法。该方法名应具有`findBy`前缀和搜索字段名。它可能以一个标准的搜索关键字后缀结束，如`GreaterThan`、`LessThan`、`Between`、`Like`等。基于完整的方法名，Spring Data 类会自动生成 MongoDB 查询。相同的关键词可以与`delete…By`或`remove…By`结合使用，以创建删除查询。在`PersonRepository`接口中，我决定定义两个查找方法。第一个，`findByLastName`，选择所有给定`lastName`值的`Person`实体。第二个，`findByAgeGreaterThan`，旨在检索所有年龄大于给定值的`Person`实体：

```java
public interface PersonRepository extends MongoRepository<Person, String> {

    public List<Person> findByLastName(String lastName);
    public List<Person> findByAgeGreaterThan(int age);

}
```

仓库应该被注入到 REST 控制器类中。然后，我们终于可以调用`PersonRepository`提供的所有必需的 CRUD 方法：

```java
@Autowired
private PersonRepository repository;
@Autowired
private PersonCounterService counterService; 

@GetMapping
public List<Person> findAll() {
    return repository.findAll();
} 

@GetMapping("/{id}")
public Person findById(@RequestParam("id") String id) {
    return repository.findOne(id);
}

@PostMapping
public Person add(@RequestBody Person p) {
    p = repository.save(p);
    counterService.countNewPersons();
    return p;
}

@DeleteMapping("/{id}")
public void delete(@RequestParam("id") String id) {
    repository.delete(id);
    counterService.countDeletedPersons();
}
```

我们还添加了两个从`PersonRepository` bean 自定义查找操作的 API 方法：

```java
@GetMapping("/lastname/{lastName}")
public List<Person> findByLastName(@RequestParam("lastName") String lastName) {
    return repository.findByLastName(lastName);
}

@GetMapping("/age/{age}")
public List<Person> findByAgeGreaterThan(@RequestParam("age") int age) {
    return repository.findByAgeGreaterThan(age);
} 
```

这就做完了所有的事情。我们的微服务已经准备好启动，它暴露了实现对嵌入式 Mongo 数据库进行 CRUD 操作的基本 API 方法。你可能已经注意到，它并没有要求我们创建大量的源代码。使用 Spring Data 实现与数据库的任何交互，无论是关系型还是 NoSQL，都是快速和相对简单的。无论如何，我们面前还有一个挑战。嵌入式数据库是一个不错的选择，但只适用于开发模式或单元测试，而不是生产模式。如果你必须在生产模式下运行你的微服务，你可能会启动一个独立的 MongoDB 实例或一些作为分片集群部署的 MongoDB 实例，并将应用程序连接到它们。对于我们的示例目的，我将使用 Docker 运行 MongoDB 的一个实例。

如果你不熟悉 Docker，你总是可以只在你的本地或远程机器上安装 Mongo。关于 Docker 的更多信息，你也可以参考第十四章、*Docker 支持*，在那里我会给你一个简短的介绍。那里有你开始所需的一切，例如如何在 Windows 上安装它和使用基本命令。我还将使用 Docker 在为下一章节和主题实现示例中，所以我认为如果你有基本的了解它会很有用。

# 运行应用程序

让我们使用 Docker `run`命令启动 MongoDB：

```java
docker run -d --name mongo -p 27017:27017 mongo
```

对我们可能有用的一件事是 Mongo 数据库客户端。使用这个客户端，可以创建一个新的数据库并添加一些带有凭据的用户。如果您在 Windows 上安装了 Docker，默认虚拟机地址是`192.168.99.100`。由于在`run`命令内部设置了`-p`参数，Mongo 容器暴露了端口`27017`。实际上，我们不必创建数据库，因为当我们定义客户端连接时提供数据库名称，如果它不存在，它将自动创建：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6028efdc-ae01-4769-87ff-30e34816bae8.png)

接下来，我们应该为应用程序创建一个具有足够权限的用户：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/37885b34-9466-4902-89cd-0d23223f6eef.png)

最后，我们应该在`application.yml`配置文件中设置 Mongo 数据库连接设置和凭据：

```java
server: 
  port: ${port:2222}
spring: 
  application:
  name: first-service

// ...

---

spring:
  profiles: production
  application:
    name: first-service
  data:
    mongodb:
      host: 192.168.99.100
      port: 27017
      database: microservices
      username: micro 
      password: micro
```

Spring Boot 很好地支持多配置文件。YAML 文件可以通过使用`*---*`行分隔成一系列文档，每个文档部分独立解析为一个扁平化的映射。前面的示例与使用`application-production.yml`的分离配置文件完全一样。如果您没有使用任何其他选项运行应用程序，它将使用默认设置，这些设置没有设置配置文件名称。如果您希望使用生产属性运行它，您应该设置 VM 参数`spring.profiles.active`：

```java
java -jar -Dspring.profiles.active=production sample-spring-boot-web-1.0-SNAPSHOT.jar
```

这还不算完。现在，带有活动生产配置文件的应用程序无法启动，因为它尝试初始化`embeddedMongoServer`bean。正如您可能已经知道的，Spring Boot 中几乎所有的附加解决方案都设置了自动配置。这个例子也不例外。我们需要在生产配置文件中排除`EmbeddedMongoAutoConfiguration`类：

```java
spring:
  profiles: production
  // ...
  autoconfigure:
    exclude: org.springframework.boot.autoconfigure.mongo.embedded.EmbeddedMongoAutoConfiguration
```

我们也可以使用配置类来排除该工件：

```java
@Configuration
@Profile("production")
@EnableAutoConfiguration(exclude = EmbeddedMongoAutoConfiguration.class)
public class ApplicationConfig {
    // ...
}
```

当然，我们本可以使用更优雅的解决方案，比如 Maven 配置文件，并从目标构建包中排除整个`de.flapdoodle.embed.mongo`工件。所示解决方案只是解决该问题的几种可能性之一，但它展示了 Spring Boot 中的自动配置和配置文件机制。现在，您可以运行我们的示例应用程序并使用例如 Swagger UI 进行一些测试。您还可以使用 Mongo 客户端连接到数据库并查看数据库中的更改。以下是我们的示例项目的最终文件结构：

```java
pl
  +- piomin
    +- services
      +- boot
        +- Application.java
        |
        +- controller
        |  +- PersonController.java
        |
        +- data
        |  +- PersonRepository.java
        |
        +- model
        |  +- Person.java
        |  +- Gender.java
        |
        +- service
        |  +- PersonCounterService.java
```

示例应用程序完成了。这些都是我本章想要展示给你的 Spring Boot 功能。我主要关注那些特别适用于创建基于 REST 的服务的功能。

# 总结

我已经引导你经历了单微服务开发的过程，从一个非常基础的例子到一个更高级的、生产就绪的 Spring Boot 应用。我描述了如何使用启动器（starters）为项目启用附加特性；使用 Spring Web 库来实现暴露 REST API 方法的服务；然后我们转向使用属性和 YAML 文件自定义服务配置。我们还看到了如何文档化和提供暴露 REST 端点的规格说明。接下来，我们配置了健康检查和监控特性。我们使用了 Spring Boot 配置文件（profiles）使应用能够以不同的模式运行，最后，我们使用了对象关系映射（ORM）特性来与内嵌和远程的 NoSQL 数据库进行交互。

我没有在这一章中提到 Spring Cloud 绝非偶然。你没有基本的 Spring Boot 知识和经验，是无法开始使用 Spring Cloud 项目的。Spring Cloud 提供了许多不同的特性，让你可以将你的服务放置在一个完整的基于微服务的生态系统中。我们将在接下来的章节中逐一讨论这些功能。


# 第三章：Spring Cloud 概览

在第一章，*微服务介绍*中，我提到了基于云的开发风格，以及 Spring Cloud 如何帮助你轻松采用与这种概念相关的最佳实践。最常用的最佳实践已经被收集在一个有趣的倡议中，称为**The Twelve-Factor App**。正如你可能会在他们网站上读到的（[`12factor.net/`](https://12factor.net/)），这是一种构建**软件即服务**（**SaaS**）现代应用程序的方法，这种应用程序必须是可扩展的，容易在云平台上部署，并以持续部署过程提供。熟悉这些原则尤其值得，特别是如果你是一个构建作为服务运行的应用程序的开发者。Spring Boot 和 Spring Cloud 提供了使你的应用程序符合*Twelve-Factor 规则*的特性和组件。我们可以区分出一些最现代分布式系统通常使用的典型特性。每个有见地的框架都应该提供它们，Spring Cloud 也不例外。这些特性如下：

+   分布式/版本化配置

+   服务注册与发现

+   路由

+   服务间调用

+   负载均衡

+   断路器

+   分布式消息传递

# 从基础开始

让我们先回到上一章的内容。在那儿，我已经详细介绍了 Spring Boot 项目的结构。配置应该提供在 YAML 文件或以应用程序或`application-{profile}`命名的属性文件中。与标准的 Spring Boot 应用程序相比，Spring Cloud 是基于从远程服务器获取的配置。然而，在应用程序内部只需要最少的设置；例如，其名称和配置服务器地址。这就是为什么 Spring Cloud 应用程序创建了一个引导上下文，负责从外部来源加载属性。引导属性具有最高优先级，它们不能被本地配置覆盖。引导上下文是主应用程序上下文的父级，它使用`bootstrap.yml`而不是`application.yml`。通常，我们将应用程序名称和 Spring Cloud Config 设置放在下面这样：

```java
spring:
  application:
    name: person-service
  cloud:
    config:
      uri: http://192.168.99.100:8888
```

通过将`spring.cloud.bootstrap.enabled`属性设置为`false`，可以轻松禁用 Bootstrap 上下文的启动。我们还可以使用`spring.cloud.bootstrap.name`属性更改引导配置文件的名称，或者通过设置`spring.cloud.bootstrap.location`来更改其位置。在这里也可以使用配置文件机制，因此我们可以创建例如`bootstrap-development.yml`的文件，在激活的开发配置文件上进行加载。Spring Cloud Context 库中提供了这些以及其他一些特性，该库作为项目类路径的父依赖与其他任何 Spring Cloud 库一起添加。其中一些特性包括与 Spring Boot Actuator 一起提供的附加管理端点：

+   `env`：新的`POST`方法用于`Environment`，日志级别更新和`@ConfigurationProperties`重新绑定

+   `refresh`：重新加载引导上下文并刷新所有带有`@RefreshScope`注解的 bean

+   `restart`：重新启动 Spring `ApplicationContext`

+   `pause`：停止 Spring `ApplicationContext`

+   `resume`：启动 Spring `ApplicationContext`

与 Spring Cloud Context 一起作为 Spring Cloud 项目的父依赖包含在项目中的下一个库是 Spring Cloud Commons。它为诸如服务发现、负载均衡和断路器等机制提供了一个共同的抽象层。这些包括其他常用注解，如`@EnableDiscoveryClient`或`@LoadBalanced`。关于它们的详细信息，我将在接下来的章节中介绍。

# Netflix OSS

在阅读前两章之后，你们可能已经注意到了许多与微服务架构相关的关键词。对于一些人来说，这可能是一个新术语，对于其他人来说，它可能是众所周知的。但到目前为止，对微服务社区来说还有一个重要的词还没有提到。大多数你们肯定都知道，这个词是*Netflix*。嗯，我也喜欢他们的电视剧和其他制作，但对我来说，他们因为另一个原因而出名。这个原因就是微服务。Netflix 是最早从传统的开发模式迁移到基于云的微服务开发方法的先驱之一。这家公司通过将大部分源代码推送到公共仓库、在会议演讲中发言以及发布博客文章，与社区分享他们的专业知识。Netflix 在其架构概念上的成功是如此之大，以至于它们成为了其他大型组织和他们的 IT 架构师（如 Adrian Cockcroft）的榜样，这些人现在是微服务的突出倡导者。作为回报，许多开源框架将它们的库基于 Netflix 共享的代码下的解决方案。对于 Spring Cloud 来说也不例外，它提供了与最流行的 Netflix OSS 特性（如 Eureka、Hystrix、Ribbon 或 Zuul）的集成。

顺便说一下，我不知道你是否一直在关注 Netflix，但他们透露了他们决定开源大部分代码的原因。我认为值得引用，因为这部分解释了他们在 IT 世界中成功和持续受欢迎的原因：

“当我们说我们要将整个 Netflix 搬到云端时，每个人都认为我们完全疯了。他们不相信我们真的在做这件事，他们认为我们只是在编造故事。”

# 使用 Eureka 进行服务发现

由 Spring Cloud Netflix 提供的第一个模式是使用 Eureka 进行服务发现。这个包分为客户端和服务器端。

要在项目中包含 Eureka 客户端，你应该使用`spring-cloud-starter-eureka`启动器。客户端总是应用程序的一部分，负责连接远程发现服务器。一旦建立连接，它应该发送一个包含服务名称和网络位置的注册消息。如果当前微服务需要调用另一个微服务的端点，客户端应该从服务器检索带有已注册服务列表的最新配置。服务器可以作为独立的 Spring Boot 应用程序进行配置和运行，并且每个服务器都应该将其状态复制到其他节点以实现高可用性。要在项目中包含 Eureka 服务器，你需要使用`spring-cloud-starter-eureka-server`启动器。

# 使用 Zuul 进行路由

在 Spring Cloud Netflix 项目中可用的下一个流行模式是使用 Zuul 进行智能路由。它不仅仅是一个基于 JVM 的路由器，还充当服务器端负载均衡器，执行某些过滤操作。它还有各种各样的应用。Netflix 用它来处理诸如认证、负载均衡、静态响应处理或压力测试等情况。它与 Eureka Server 相同，可以作为独立的 Spring Boot 应用程序进行配置和运行。

要在项目中包含 Zuul，请使用`spring-cloud-starter-zuul`启动器。在微服务架构中，Zuul 作为 API 网关扮演着至关重要的角色，它是整个系统的入口点。它需要了解每个服务的网络位置，因此通过将发现客户端包含在类路径中与 Eureka Server 进行交互。

# 使用 Ribbon 进行负载均衡

我们不能忽视用于客户端负载均衡的下一个 Spring Cloud Netflix 功能——Ribbon。它支持最流行的协议，如 TCP、UDP 和 HTTP。它不仅可以用于同步 REST 调用，还可以用于异步和反应式模型。除了负载均衡外，它还提供与服务发现、缓存、批处理和容错集成的功能。Ribbon 是基本 HTTP 和 TCP 客户端的下一个抽象级别。

要将其纳入您的项目，请使用`spring-cloud-starter-ribbon`启动器。Ribbon 支持循环冗余、可用性过滤和加权响应时间负载均衡规则，并且可以很容易地通过自定义规则进行扩展。它基于*命名客户端*概念，其中用于负载均衡的服务应提供名称。

# 编写 Java HTTP 客户端

Feign 是 Netflix OSS 包中稍微不太流行的一个。它是一个声明性的 REST 客户端，可以帮助我们更容易地编写 Web 服务客户端。使用 Feign，开发者只需声明和注解一个接口，而实际实现将在运行时生成。

要在您的项目中包含 Feign，您需要使用`spring-cloud-starter-feign`启动器。它与 Ribbon 客户端集成，因此默认支持负载均衡和其他 Ribbon 功能，包括与发现服务的通信。

# 使用 Hystrix 实现延迟和容错

我已经在第一章，*微服务简介*中提到了断路器模式，Spring Cloud 提供了一个实现此模式的库。它基于 Netflix 创建的 Hystrix 包，作为断路器实现。Hystrix 默认与 Ribbon 和 Feign 客户端集成。回退与断路器概念紧密相关。使用 Spring Cloud 库，您可以轻松配置回退逻辑，如果存在读取或断路器超时，应执行此逻辑。您应该使用`spring-cloud-starter-hystrix`启动器将 Hystrix 纳入您的项目。

# 使用 Archaius 进行配置管理

在 Spring Cloud Netflix 项目中提供的最后一个重要功能是 Archaius。我个人没有接触过这个库，但在某些情况下可能很有用。Spring Cloud 参考 Archaius 是 Apache Commons Configuration 项目的扩展。它允许通过轮询源进行配置更新或将更改推送到客户端。

# 发现与分布式配置

服务发现和分布式配置管理是微服务架构的两个重要部分。这两种不同机制的技术实现非常相似。它归结为在灵活的键值存储中存储特定键下的参数。实际上，市场上有一些有趣的解决方案可以提供这两种功能。Spring Cloud 与其中最受欢迎的解决方案集成。但是，还有一个例外，Spring Cloud 有自己的实现，仅用于分布式配置。此功能在 Spring Cloud Config 项目中提供。相比之下，Spring Cloud 不提供其自己的服务注册和发现实现。

像往常一样，我们可以将这个项目分为服务器和客户端支持两部分。服务器是所有外部属性的集中管理的地方，跨所有环境管理应用程序的属性。配置可以同时维护几个版本和配置文件。这是通过使用 Git 作为存储后端来实现的。这个机制非常智能，我们将在第五章，*Spring Cloud Config 的分布式配置*中详细讨论它。Git 后端不是存储属性的唯一选项。配置文件也可以位于文件系统或服务器类路径上。下一个选项是使用 Vault 作为后端。Vault 是 HashiCorp 发布的一个开源工具，用于管理令牌、密码或证书等秘密。我知道许多组织特别关注诸如将凭据存储在安全地方等安全问题，所以这可能是他们的正确解决方案。通常，我们也可以在配置服务器访问级别管理安全。无论使用哪种后端存储属性，Spring Cloud Config Server 都暴露了一个基于 HTTP 的 API，提供轻松访问它们。默认情况下，这个 API 通过基本身份验证保护，但也可以设置使用私钥/公钥身份验证的 SSL 连接。

一个服务器可以作为一个独立的 Spring Boot 应用程序运行，并通过 REST API 暴露属性。为了在我们的项目中启用它，我们应该添加`spring-cloud-config-server`依赖。在客户端也有支持。每个使用配置服务器作为属性源的微服务在启动后都需要连接到它，在创建任何 Spring bean 之前。有趣的是，Spring Cloud Config Server 可以被非 Spring 应用程序使用。有一些流行的微服务框架在客户端与之集成。为了在你的应用程序中启用 Spring Cloud Config Client，你需要包含`spring-cloud-config-starter`依赖。

# 一个替代方案——Consul

对于 Netflix 发现和 Spring 分布式配置，Consul（由 Hashicorp 创建）似乎是一个有趣的选择。Spring Cloud 为与这个流行的工具集成提供了发现和配置服务器的整合。像往常一样，这个集成可以通过一些简单的公共注解启用，与之前介绍的解决方案相比，唯一的区别在于配置设置。为了与 Consul 服务器建立通信，应用程序需要有一个可用的 Consul 代理。它必须能够作为一个分离的进程运行，默认情况下可以通过`http://localhost:8500`地址访问。Consul 还提供了 REST API，可以直接用于注册、收集服务列表或配置属性。

要激活 Consul 服务发现，我们需要使用`spring-cloud-starter-consul-discovery`启动器。在应用程序启动和注册后，客户端将查询 Consul 以定位其他服务。它支持使用 Netflix Ribbon 的客户端负载均衡器以及使用 Netflix Zuul 的动态路由和过滤器。

# Apache Zookeeper

在这个领域内，Spring Cloud 支持的下一个流行解决方案是 Apache Zookeeper。按照其文档，它是一个维护配置、命名的中间服务，也提供分布式同步，并能够分组服务。之前应用于 Consul 的支持在 Spring Cloud 中也是一样的。我想在这里提到的是简单的通用注解，它们必须用于启用集成、配置，通过设置文件中的属性以及与 Ribbon 或 Zuul 交互的自动配置。要在客户端方面启用与 Zookeeper 的服务发现，我们不仅需要包括`spring-cloud-starter-zookeeper-discovery`，还需要 Apache Curator。它提供了一个 API 框架和工具，使集成更加容易和可靠。在分布式配置客户端方面，我们只需要在项目依赖中包含`spring-cloud-starter-zookeeper-config`。

# 其他各种项目

值得提到的是另外两个现在处于孵化阶段的项目。所有这些项目都可以在 GitHub 仓库中找到，[`github.com/spring-cloud-incubator`](https://github.com/spring-cloud-incubator)。其中一些可能会很快正式加入 Spring Cloud 包。第一个是 Spring Cloud Kubernetes，它提供了与这个非常受欢迎的工具的集成。我们可以谈论它很长时间，但让我们尝试用几句话来介绍它。它是一个自动化部署、扩展和管理容器化应用程序的系统，最初由 Google 设计。它用于容器编排，并具有许多有趣的功能，包括服务发现、配置管理和负载均衡。在某些情况下，它可能会被视为 Spring Cloud 的竞争对手。配置是通过使用 YAML 文件来提供的。

Spring Cloud 的角度来看，重要的功能包括服务发现和分布式配置机制，这些机制在 Kubernetes 平台上可用。要使用它们，你应该包括`spring-cloud-starter-kubernetes`启动器。

在孵化阶段的第二个有趣项目是 Spring Cloud Etcd。与之前完全一样，它的主要特点包括分布式配置、服务注册和发现。Etcd 并不是像 Kubernetes 那样的强大工具。它只是为集群环境提供了一个可靠的键值存储的分布式键值存储，以及一点小八卦——Etcd 是 Kubernetes 中服务发现、集群状态和配置管理的后端。

# 使用 Sleuth 的分布式追踪

Spring Cloud 的另一个关键功能是分布式追踪，它是在 Spring Cloud Sleuth 库中实现的。其主要目的是将处理单个输入请求的不同微服务之间传递的后续请求相关联。在大多数情况下，这些都是基于 HTTP 头实现追踪机制的 HTTP 请求。该实现基于 Slf4j 和 MDC。Slf4j 为特定的日志框架（如 logback、log4j 或 `java.util.logging`）提供外观和抽象。**MDC** 或者 **映射诊断上下文**，全称是解决方案，用于区分来自不同来源的日志输出，并丰富它们附加在实际作用域中不可用的信息。

Spring Cloud Sleuth 在 Slf4J MDC 中添加了追踪和跨度 ID，这样我们就能提取具有给定追踪或跨度所有的日志。它还添加了一些其他条目，如应用程序名称或可导出标志。它与最受欢迎的消息解决方案集成，如 Spring REST 模板、Feign 客户端、Zuul 过滤器、Hystrix 或 Spring Integration 消息通道。它还可以与 RxJava 或计划任务一起使用。为了在您的项目中启用它，您应该添加`spring-cloud-starter-sleuth`依赖。对于基本跨度 ID 和追踪 ID 机制的使用对开发者是完全透明的。

添加追踪头并不是 Spring Cloud Sleuth 的唯一功能。它还负责记录时间信息，这在延迟分析中非常有用。这些统计信息可以导出到 Zipkin，这是一个用于查询和可视化时间数据的工具。

Zipkin 是一个为分析微服务架构内部延迟问题而特别设计的分布式追踪系统。它暴露了用于收集输入数据的 HTTP 端点。为了启用生成并将追踪数据发送到 Zipkin，我们应该在项目中包含`spring-cloud-starter-zipkin`依赖。

通常，没有必要分析所有内容；输入流量如此之大，我们只需要收集一定比例的数据。为此，Spring Cloud Sleuth 提供了一个采样策略，我们可以决定发送多少输入流量到 Zipkin。解决大数据问题的第二个智能方案是使用消息代理发送统计数据，而不是默认的 HTTP 端点。为了启用这个特性，我们必须包含`spring-cloud-sleuth-stream`依赖，它允许您的应用程序成为发送到 Apache Kafka 或 RabbitMQ 的消息的生产者。

# 消息和集成

我已经提到了消息代理以及它们用于应用程序和 Zipkin 服务器之间通信的用法。通常，Spring Cloud 支持两种类型的通信，即通过同步/异步 HTTP 和消息代理。这一领域的第一个项目是 Spring Cloud Bus。它允许你向应用程序发送广播事件，通知它们关于状态变化的信息，例如配置属性更新或其他管理命令。实际上，我们可能想使用带有 RabbitMQ 代理或 Apache Kafka 的 AMQP 启动器。像往常一样，我们只需要将`spring-cloud-starter-bus-amqp`或`spring-cloud-starter-bus-kafka`包含在依赖管理中，其他所有必要操作都通过自动配置完成。

Spring Cloud Bus 是一个较小的项目，允许你为诸如广播配置变更事件等常见操作使用分布式消息功能。构建由消息驱动的微服务系统所需的正确框架是 Spring Cloud Stream。这是一个非常强大的框架，也是 Spring Cloud 项目中最大的一个，我为此专门写了一整章——书籍的第十一章，《消息驱动的微服务》*Message Driven Microservices*。与 Spring Cloud Bus 相同，这里也有两个绑定器可供选择，第一个是用于 RabbitMQ 的 AMQP，第二个是用于 Apache Kafka 的。Spring Cloud Stream 基于 Spring Integration，这是 Spring 的另一个大型项目。它提供了一个编程模型，支持大多数企业集成模式，如端点、通道、聚合器或转换器。整个微服务系统中的应用程序通过 Spring Cloud Stream 的输入和输出通道相互通信。它们之间的主要通信模型是发布/订阅，其中消息通过共享主题进行广播。此外，支持每个微服务的多实例也很重要。在大多数情况下，消息应仅由单个实例处理，而发布/订阅模型不支持这一点。这就是 Spring Cloud Stream 引入分组机制的原因，其中仅组中的一个成员从目的地接收消息。与之前一样，这两个启动器可以根据绑定的类型包括一个项目——`spring-cloud-starter-stream-kafka`或`spring-cloud-starter-stream-rabbit`。

还有两个与 Spring Cloud Stream 相关的项目。首先，Spring Cloud Stream App Starters 定义了一系列可以独立运行或使用第二个项目 Spring Cloud Data Flow 运行的 Spring Cloud Stream 应用程序。在这些应用程序中，我们可以区分出连接器、网络协议适配器和通用协议。Spring Cloud Data Flow 是另一个广泛且强大的 Spring Cloud 工具集。它通过提供构建数据集成和实时数据处理管道的智能解决方案，简化了开发和部署。使用简单的 DSL、拖放式 UI 仪表板和 REST API 共同实现了基于微服务的数据管道的编排。

# 云平台支持

Pivotal Cloud Foundry 是一个用于部署和管理现代应用程序的云原生平台。Pivotal Software，正如你们中的一些人可能已经知道的那样，是 Spring 框架商标的拥有者。大型商业平台的支持是 Spring 日益受欢迎的重要原因之一。显而易见的是，PCF 完全支持 Spring Boot 的可执行 JAR 文件以及所有 Spring Cloud 微服务模式，如 Config Server、服务注册表和断路器。这些类型的工具可以通过 UI 仪表板或客户端命令行上可用的市场轻松运行和配置。对于 PCF 的开发甚至比标准的 Spring Cloud 应用程序还要简单。我们唯一要做的就是在项目依赖项中包含正确的启动器：

+   `spring-cloud-services-starter-circuit-breaker`

+   `spring-cloud-services-starter-config-client`

+   `spring-cloud-services-starter-service-registry`

要找到一个没有支持 AWS 的观点明确的云框架很难。对于 Spring Cloud 来说也是如此。Spring Cloud for Amazon Web Services 提供了与那里最流行的网络工具的集成。这包括与**简单队列服务**（**SQS**）、**简单通知服务**（**SNS**）、**ElasticCache**和**关系数据库服务**（**RDS**）通信的模块，后者提供如 Aurora、MySQL 或 Oracle 等引擎。可以使用在 CloudFormation 堆栈中定义的名称访问远程资源。一切都是按照众所周知的 Spring 约定和模式进行操作的。有四个主要模块可供使用：

+   **Spring Cloud AWS Core**：通过使用`spring-cloud-starter-aws`启动器包含，提供核心组件，实现对 EC2 实例的直接访问

+   **Spring Cloud AWS Context**：提供对简单存储服务、简单电子邮件服务和缓存服务的访问

+   **Spring Cloud AWS JDBC**：通过使用启动器`spring-cloud-starter-aws-jdbc`，提供数据源查找和配置，可以与 Spring 支持的任何数据访问技术一起使用

+   **Spring Cloud AWS 消息**：包含使用`starter spring-cloud-starter-aws-messaging`启动器，允许应用程序使用 SQS（点对点）或 SNS（发布/订阅）发送和接收消息。

还有一个值得提及的项目，尽管它仍然处于开发的早期阶段。那是 Spring Cloud Function，它提供了无服务器架构的支持。无服务器也被称为**FaaS**（**Function-as-a-Service**），在其中开发者只创建非常小的模块，这些模块完全由第三方提供商托管在容器上。实际上，Spring Cloud Functions 为最流行的 FaaS 提供商 AWS Lambda 和 Apache OpenWhisk 实现了适配器。我将关注这个旨在支持无服务器方法的项目的开发。

在这一节中，我们不应该忘记 Spring Cloud Connectors 项目，原名**Spring Cloud**。它为部署在云平台上的 JVM 基础应用程序提供了抽象。实际上，它支持 Heroku 和 Cloud Foundry，我们的应用程序可以使用 Spring Cloud Heroku Connectors 和 Spring Cloud Foundry Connector 模块连接 SMTP、RabbitMQ、Redis 或可用的关系型数据库。

# 其他有用的库

微服务架构周围有一些重要的方面，这些不能算作其核心特性，但也非常重要。其中第一个是安全性。

# 安全性

标准实现用于保护 API 的绝大多数机制，如 OAuth2、JWT 或基本认证，都可在 Spring Security 和 Spring Web 项目中找到。Spring Cloud Security 使用这些库，使我们能够轻松创建实现常见模式的系统，如单点登录和令牌传递。为了为我们的应用程序启用安全管理，我们应该包含`spring-cloud-starter-security`启动器。

# 自动化测试

微服务开发中的下一个重要领域是自动化测试。对于微服务架构，接触测试变得越来越重要。马丁·福勒给出了以下定义：

“集成合同测试是在外部服务边界上进行的测试，验证它满足消费服务期望的合同。”

Spring Cloud 针对这种单元测试方法有一个非常有趣的实现，即 Spring Cloud Contract。它使用 WireMock 进行流量记录和 Maven 插件生成存根。

您也可能有机会使用 Spring Cloud Task。它帮助开发者使用 Spring Cloud 创建短暂存在的微服务，并本地运行或在云环境中运行。为了在项目中启用它，我们应该包含`spring-cloud-starter-task`启动器。

# 集群特性

最后，最后一个项目，Spring Cloud Cluster。它提供了一个解决方案，用于领导选举和常见有状态模式，以及 Zookeeper、Redis、Hazelcast 和 Consul 的抽象和实现。

# 项目概览

正如你所看到的，Spring Cloud 包含许多子项目，提供与许多不同工具和解决方案的集成。我认为如果你是第一次使用 Spring Cloud，很容易迷失方向。根据一图千言的原则，我呈现了最重要的项目，按类别划分，如下面的图表所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/b90c6536-0be0-4d4c-89ea-0aabea5a5eec.png)

# 发布列车

正如之前的图表所示，Spring Cloud 内部有许多项目，它们之间存在许多关系。定义上，这些都是具有不同发布级联和版本号的独立项目。在这种情况下，我们应用中的依赖管理可能会出现问题，这需要了解所有项目版本之间的关系。为了使事情变得容易，Spring Cloud 引入了启动机制，我们已经在前面讨论过，还有发布列车。发布列车通过名称而不是版本来标识，以避免与子项目混淆。有趣的是，它们以伦敦地铁站的名称命名，并且按字母顺序排列。第一个发布版是 Angel，第二个是 Brixton，依此类推。整个依赖管理机制基于**BOM**（**物料清单**），这是一个用于独立版本管理工件的标准 Maven 概念。下面是一个实际的表格，其中分配了 Spring Cloud 项目版本到发布列车。带有后缀 M[*X*]的名称，其中[*X*]是版本号，意味着**里程碑**，SR[*X*]意味着**服务发布**，指的是修复关键 bug 的变化。正如您在下面的表格中看到的，Spring Cloud Stream 有自己的发布列车，它使用与 Spring Cloud 项目相同的规则来分组其子项目：

| **组件** | **Camden.SR7** | **Dalston.SR4** | **Edgware.M1** | **Finchley.M2** | **Finchley.BUILD-SNAPSHOT** |
| --- | --- | --- | --- | --- | --- |
| `spring-cloud-aws` | 1.1.4.RELEASE | 1.2.1.RELEASE | 1.2.1.RELEASE | 2.0.0.M1 | 2.0.0.BUILD-SN |
| `spring-cloud-bus` | 1.2.2.RELEASE | 1.3.1.RELEASE | 1.3.1.RELEASE | 2.0.0.M1 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-cli` | 1.2.4.RELEASE | 1.3.4.RELEASE | 1.4.0.M1 | 2.0.0.M1 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-commons` | 1.1.9.RELEASE | 1.2.4.RELEASE | 1.3.0.M1 | 2.0.0.M2 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-contract` | 1.0.5.RELEASE | 1.1.4.RELEASE | 1.2.0.M1 | 2.0.0.M2 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-config` | 1.2.3.RELEASE | 1.3.3.RELEASE | 1.4.0.M1 | 2.0.0.M2 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-netflix` | 1.2.7.RELEASE | 1.3.5.RELEASE | 1.4.0.M1 | 2.0.0.M2 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-security` | 1.1.4.RELEASE | 1.2.1.RELEASE | 1.2.1.RELEASE | 2.0.0.M1 | 2.0.0.BUILD-SNAPSHOT |
| `spring-cloud-cloudfoundry` | 1.0.1.RELEASE | 1.1.0.RELEASE | 1.1.0.RELEASE | 2.0.0.M1 | 2.0.0.BUILD-SNAPSHOT |
| ```spring-cloud-consul``` | 1.1.4.RELEASE | 1.2.1.RELEASE | 1.2.1.RELEASE | 2.0.0.M1 | 2.0.0.BUILD-SNAPSHOT |
| ```spring-cloud-sleuth``` | 1.1.3.RELEASE | 1.2.5.RELEASE | 1.3.0.M1 | 2.0.0.M2 | 2.0.0.BUILD-SNAPSHOT |
| ```spring-cloud-stream``` | Brooklyn.SR3 | Chelsea.SR2 | Ditmars.M2 | Elmhurst.M1 | Elmhurst.BUILD-SNAPSHOT |
| ```spring-cloud-zookeeper``` | 1.0.4.RELEASE | 1.1.2.RELEASE | 1.2.0.M1 | 2.0.0.M1 | 2.0.0.BUILD-SNAPSHOT |
| ```spring-boot``` | 1.4.5.RELEASE | 1.5.4.RELEASE | 1.5.6.RELEASE | 2.0.0.M3 | 2.0.0.M3 |
| ```spring-cloud-task``` | 1.0.3.RELEASE | 1.1.2.RELEASE | 1.2.0.RELEASE | 2.0.0.M1 | 2.0.0.RELEASE |

现在，我们只需要在 Maven `pom.xml`的依赖管理部分提供正确的发行版名称，然后使用启动器包含项目：

```java
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>Finchley.M2</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
<dependencies>
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-config</artifactId>
    </dependency>
    ...
</dependencies>
```

这是 Gradle 的相同示例：

```java
dependencyManagement {
    imports {
        mavenBom ':spring-cloud-dependencies:Finchley.M2'
    }
}
dependencies {
    compile ':spring-cloud-starter-config'
    ...
}
```

# 总结

在本章中，我介绍了属于 Spring Cloud 的最重要的项目。我指出了几个区域，并为每个项目分配了这些区域。阅读完本章后，你应该能够识别出在你的应用程序中需要包含哪个库，以实现在服务发现、分布式配置、断路器或负载均衡器等模式。你也应该能够识别出应用上下文和引导上下文之间的差异，并理解如何使用基于发行版概念的依赖管理来在项目中包含依赖项。在本章的最后，我想引起你们注意的一些与 Spring Cloud 集成的工具，例如 Consul、Zookeeper、RabbitMQ 或 Zipkin。我详细描述了它们的所有内容。我还指出了与这些工具交互的项目。

本章完成了本书的第一部分。在这一部分中，主要目标是让你了解 Spring Cloud 项目的基本知识。阅读完它后，你应该能够识别出基于微服务架构的最重要元素，有效地使用 Spring Boot 创建简单和更高级的微服务，最后，你也应该能够列出所有最流行的子项目，这些子项目是 Spring Cloud 的一部分。现在，我们可以继续下一部分的书，并详细讨论那些负责在 Spring Cloud 中实现分布式系统常见模式的子项目。其中大多数是基于 Netflix OSS 库的。我们将从提供服务注册、Eureka 发现服务器的解决方案开始。


# 第四章：服务发现

在我们到达这一点之前，在前面的章节中我们已经多次讨论了服务发现。实际上，它是微服务架构中最受欢迎的技术方面之一。这样的主题不可能从 Netflix OSS 实现中省略。他们没有决定使用具有类似功能的任何现有工具，而是专门为他们的需求设计并开发了一个发现服务器。然后，它与其他几个工具一起开源了。Netflix OSS 发现服务器被称为**Eureka**。

用于与 Eureka 集成的 Spring Cloud 库包括两部分，客户端和服务端。服务端作为独立的 Spring Boot 应用程序启动，并暴露一个 API，可以收集注册服务列表以及添加带有位置地址的新服务。服务器可以配置和部署为高可用性，每个服务器都与其它服务器复制其状态。客户端作为微服务应用程序的一个依赖项包含在内。它负责启动后的注册、关机前的注销，并通过轮询 Eureka 服务器保持注册列表的最新。

以下是我们在本章中要覆盖的主题列表：

+   开发运行内嵌 Eureka 服务器的应用程序

+   从客户端应用程序连接到 Eureka 服务器

+   高级发现客户端配置

+   启用客户端和服务器之间的安全通信

+   配置故障转移和对等复制机制

+   在不同区域注册客户端应用程序实例

# 在服务器端运行 Eureka

在 Spring Boot 应用程序中运行 Eureka 服务器并不是一件困难的事情。让我们来看看这是如何做到的：

1.  首先，必须包含正确的依赖项到我们的项目中。显然，我们将使用一个启动器：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-eureka-server</artifactId>
</dependency>
```

1.  在主应用程序类上启用 Eureka 服务器：

```java
@SpringBootApplication
@EnableEurekaServer
public class DiscoveryApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(DiscoveryApplication.class).web(true).run(args);
    }

}
```

1.  有趣的是，与服务器启动器一起，客户端的依赖项也包括在内。它们对我们可能有用，但只有在以高可用性模式运行 Eureka，并且发现实例之间有对等通信时。当运行独立实例时，它实际上不会带给我们任何东西，除了在启动时在日志中打印一些错误。我们可以从启动器依赖项中排除`spring-cloud-netflix-eureka-client`，或者使用配置属性禁用发现客户端。我更喜欢第二个选择，并且在这个场合，我将默认服务器端口更改为除了`8080`之外的其它值。以下是`application.yml`文件的一个片段：

```java
server: 
 port: ${PORT:8761}
eureka:
 client:
   registerWithEureka: false
   fetchRegistry: false 
```

1.  在完成前面的步骤之后，我们终于可以启动我们的第一个 Spring Cloud 应用程序了。只需从你的 IDE 中运行主类，或者使用 Maven 构建项目并运行它，使用`java -jar`命令等待日志行`Started Eureka Server`出现。它就绪了。一个简单的 UI 仪表板作为主页可通过`http://localhost:8761`访问，并且可以通过`/eureka/*`路径调用 HTTP API 方法。Eureka 仪表板并没有提供很多功能；实际上，它主要用于检查注册的服务列表。这可以通过调用 REST API `http://localhost:8761/eureka/apps`端点来实现。

所以，总结一下，我们知道如何使用 Spring Boot 运行一个独立的 Eureka 服务器，以及如何使用 UI 控制台和 HTTP 方法检查注册的微服务列表。但我们仍然没有任何能够自己在发现中注册的服务，是时候改变这一点了。一个带有发现服务器和客户端实现示例应用程序可以在 GitHub 上的`master`分支找到([`github.com/piomin/sample-spring-cloud-netflix.git`](https://github.com/piomin/sample-spring-cloud-netflix.git))。

# 启用客户端端的 Eureka

与服务器端一样，只需要包含一个依赖项就可以为应用程序启用 Eureka 客户端。所以，首先在你的项目依赖中包含以下启动器：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-eureka</artifactId>
</dependency>
```

这个示例应用程序所做的只是与 Eureka 服务器通信。它必须注册自己并向 Eureka 发送元数据信息，如主机、端口、健康指标 URL 和主页。Eureka 从属于某个服务的每个实例接收心跳消息。如果在配置的时间段内没有收到心跳消息，实例将被从注册表中移除。发现客户端的第二个责任是从服务器获取数据，然后缓存它并周期性地询问更改。可以通过在主类上使用`@EnableDiscoveryClient`注解来启用它。令人惊讶的是，还有另一种激活此功能的方法。你可以使用`@EnableEurekaClient`注解，特别是如果类路径中有多个发现客户端实现（Consul、Eureka、ZooKeeper）的话。虽然`@EnableDiscoveryClient`位于`spring-cloud-commons`中，`@EnableEurekaClient`位于`spring-cloud-netflix`中，并且只对 Eureka 有效。以下是发现客户端应用程序的主类：

```java
@SpringBootApplication
@EnableDiscoveryClient
public class ClientApplication {

    public static void main(String[] args) {
         new SpringApplicationBuilder(ClientApplication.class).web(true).run(args);
    }

}
```

客户端配置中不必提供发现服务器的地址，因为默认的主机和端口上可用。然而，我们很容易想象 Eureka 没有在其默认的`8761`端口上监听。下面的配置文件片段可见。可以通过`EUREKA_URL`参数覆盖发现服务器的网络地址，也可以通过`PORT`属性覆盖客户端的监听端口。应用程序在发现服务器中注册的名称取自`spring.application.name`属性：

```java
spring: 
 application:
   name: client-service

server: 
 port: ${PORT:8081}

eureka:
 client:
   serviceUrl:
     defaultZone: ${EUREKA_URL:http://localhost:8761/eureka/}
```

让我们在本地主机上运行我们示例客户端应用程序的两个独立实例。为了实现这一点，需要在启动时覆盖监听端口的数量，像这样：

```java
java -jar -DPORT=8081 target/sample-client-service-1.0-SNAPSHOT.jar
java -jar -DPORT=8082 target/sample-client-service-1.0-SNAPSHOT.jar 
```

正如您在下面的截图所看到的，有一个名为`client-service`的实例注册了`piomin`这个主机名和`8081`和`8082`这两个端口：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/5b172c1a-67fb-4dfe-a0fb-3249d94261e8.png)

# 关机时的注销

检查与 Eureka 客户端的注销工作有点更具挑战性。我们的应用程序应该优雅地关闭，以便能够拦截一个停止事件并向服务器发送一个事件。实现优雅关闭的最佳方式是使用 Spring Actuator 的`/shutdown`端点。Actuator 是 Spring Boot 的一部分，可以通过在`pom.xml`中声明`spring-boot-starter-actuator`依赖项来将其包含在项目中。它默认是禁用的，因此我们必须在配置属性中启用它。为了简单起见，禁用该端点的用户/密码安全性是值得的：

```java
endpoints:
 shutdown:
   enabled: true
   sensitive: false
```

要关闭应用程序，我们必须调用`POST /shutdown`API 方法。如果您收到响应`{"message": "Shutting down, bye..."}`，这意味着一切都很顺利，流程已经开始。在应用程序被禁用之前，从 Shutting down DiscoveryClient...行开始的某些日志将被打印出来。之后，服务将从发现服务器上注销，并完全消失在注册服务列表中。我决定通过调用`http://localhost:8082/shutdown`（您可以使用任何 REST 客户端，例如 Postman）关闭客户端实例#2，因此只在端口`8081`上运行的实例在仪表板上仍然可见：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/0aea89ae-bdfb-43be-9acc-0e13ebf666f9.png)

Eureka 服务器仪表板还提供了一种方便的方式来查看新创建和取消租约的历史记录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/097c33ca-f38d-4501-a15f-1051ccf56d4b.png)

优雅关闭显然是停止应用程序的最合适方式，但在现实世界中，我们并不总是能够实现它。许多意想不到的事情可能发生，例如服务器机器重新启动、应用程序失败或客户端与服务器之间的网络问题。从发现服务器的角度来看，这种情况与从 IDE 中停止客户端应用程序或从命令行杀死进程相同。如果您尝试这样做，您将发现发现客户端关闭程序不会被触发，服务在 Eureka 仪表板上仍然显示为*UP*状态。此外，租约永远不会过期。

为了避免这种情况，服务器端的默认配置应该进行更改。*为什么在默认设置中会出现这样的问题？* Eureka 提供了一个特殊的机制，当检测到一定数量的服务没有及时续租时，注册表停止过期条目。这应该保护注册表在网络部分故障时清除所有条目。这个机制被称为**自我保护模式**，可以在`application.yml`中使用`enableSelfPreservation`属性禁用它。当然，在生产环境中不应该禁用它：

```java
eureka:
 server:
   enableSelfPreservation: false
```

# 使用发现客户端程序化

客户端应用程序启动后，注册服务列表会自动从 Eureka 服务器获取。然而，有时可能需要程序化地使用 Eureka 的客户端 API。我们有两种可能性：

+   `com.netflix.discovery.EurekaClient`：它实现了 Eureka 服务器暴露的所有 HTTP API 方法，这些方法在 Eureka API 部分已经描述过了。

+   `org.springframework.cloud.client.discovery.DiscoveryClient`：这是 Spring Cloud 的一个替代 Netflix `EurekaClient`的本地客户端。它提供了一个简单、通用的 API，对于所有的发现客户端都很有用。有两个方法可用，`getServices`和`getInstances`：

```java
private static final Logger LOGGER = LoggerFactory.getLogger(ClientController.class);

@Autowired
private DiscoveryClient discoveryClient;

@GetMapping("/ping")
public List<ServiceInstance> ping() {
 List<ServiceInstance> instances = discoveryClient.getInstances("CLIENT-SERVICE");
 LOGGER.info("INSTANCES: count={}", instances.size());
 instances.stream().forEach(it -> LOGGER.info("INSTANCE: id={}, port={}", it.getServiceId(), it.getPort()));
 return instances;
}
```

有一个与前面实现相关有趣的点。如果你在服务启动后立即调用`/ping`端点，它不会显示任何实例。这与响应缓存机制有关，下一节会详细描述。

# 高级配置设置

Eureka 的配置设置可以分为三部分：

+   **服务器**：它定制了服务器的行为。它包括所有带有`eureka.server.*`前缀的属性。可用的字段完整列表可以在`EurekaServerConfigBean`类中找到([`github.com/spring-cloud/spring-cloud-netflix/blob/master/spring-cloud-netflix-eureka-server/src/main/java/org/springframework/cloud/netflix/eureka/server/EurekaServerConfigBean.java`](https://github.com/spring-cloud/spring-cloud-netflix/blob/master/spring-cloud-netflix-eureka-server/src/main/java/org/springframework/cloud/netflix/eureka/server/EurekaServerConfigBean.java))。

+   **客户端**：这是 Eureka 客户端侧可用的两个属性部分中的第一个。它负责配置客户端如何查询注册表以定位其他服务。它包括所有带有`eureka.client.*`前缀的属性。要查看所有可用字段的全列表，请参考`EurekaClientConfigBean`类 ([`github.com/spring-cloud/spring-cloud-netflix/blob/master/spring-cloud-netflix-eureka-client/src/main/java/org/springframework/cloud/netflix/eureka/EurekaClientConfigBean.java`](https://github.com/spring-cloud/spring-cloud-netflix/blob/master/spring-cloud-netflix-eureka-client/src/main/java/org/springframework/cloud/netflix/eureka/EurekaClientConfigBean.java))。

+   **实例**：它定制了 Eureka 客户端当前实例的行为，例如端口或名称。它包括所有带有`eureka.instance.*`前缀的属性。要查看所有可用字段的全列表，请参考`EurekaInstanceConfigBean`类 ([`github.com/spring-cloud/spring-cloud-netflix/blob/master/spring-cloud-netflix-eureka-client/src/main/java/org/springframework/cloud/netflix/eureka/EurekaInstanceConfigBean.java`](https://github.com/spring-cloud/spring-cloud-netflix/blob/master/spring-cloud-netflix-eureka-client/src/main/java/org/springframework/cloud/netflix/eureka/EurekaInstanceConfigBean.java))。

我已经向你展示了如何使用这些属性以达到预期的效果。在下一部分中，我将讨论一些与配置设置自定义相关有趣的场景。不需要描述所有属性。你可以在前面列出的所有类的源代码中的注释中阅读它们。

# 刷新注册表

让我们先回到之前的示例。自保模式已被禁用，但仍然需要等待服务器取消租约，这需要很长时间。造成这种情况有几个原因。第一个原因是每个客户端服务会每 30 秒向服务器发送一次心跳（默认值），这可以通过`eureka.instance.leaseRenewalIntervalInSeconds`属性进行配置。如果服务器没有收到心跳，它会在 90 秒后从注册表中移除实例，从而切断发送到该实例的交通。这可以通过`eureka.instance.leaseExpirationDurationInSeconds`属性进行配置。这两个参数都是在客户端设置的。出于测试目的，我们在秒中定义了小的值：

```java
eureka:
 instance:
   leaseRenewalIntervalInSeconds: 1
   leaseExpirationDurationInSeconds: 2
```

在服务器端还应该更改一个属性。Eureka 在后台运行 evict 任务，负责检查客户端的心跳是否仍在接收。默认情况下，它每 60 秒触发一次。所以，即使租约续订间隔和租约到期时长被设置为相对较低的值，服务实例在最坏的情况下也可能在 60 秒后被移除。后续计时器滴答之间的延迟可以通过使用`evictionIntervalTimerInMs`属性来配置，与前面讨论的属性不同，这个属性是以毫秒为单位的：

```java
eureka:
  server:
    enableSelfPreservation: false
    evictionIntervalTimerInMs: 3000
```

所有必需的参数都已分别在客户端和服务端定义。现在，我们可以使用`-DPORT` VM 参数再次运行发现服务器，然后在端口`8081`、`8082`和`8083`上启动客户端应用程序的三个实例。在那之后，我们逐一关闭端口`8081`和`8082`上的实例，只需杀死它们的进程即可。结果是什么？禁用的实例几乎立即从 Eureka 注册表中移除。以下是 Eureka 服务器的日志片段：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/9053350f-ae07-434c-ab43-4e1040362e37.png)

仍有一个实例正在监听端口`8083`。在自我维护模式被禁用时，与之一相关的警告信息将在 UI 仪表板上打印出来。一些额外的信息，比如租约到期状态或上分钟内续租次数，也许也挺有趣。通过操作所有这些属性，我们能够定制过期的租约移除流程的维护。然而，确保定义的设置不会影响系统的性能是很重要的。还有一些其他元素对配置的变化很敏感，比如负载均衡器、网关和熔断器。如果你禁用了自我维护模式，Eureka 会打印一条警告信息，你可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/18a93209-3951-4751-a9a2-d1810cbace4e.png)

# 更改实例标识符

在 Eureka 上注册的实例按名称分组，但每个实例必须发送一个唯一 ID，基于此 ID，服务器能够识别它。也许你已经注意到`instanceId`在仪表板上每个服务组的`Status`列中显示。Spring Cloud Eureka 会自动生成这个数字，它等于以下字段的组合：

```java
${spring.cloud.client.hostname}:${spring.application.name}:${spring.application.instance_id:${server.port}}}. 
```

这个标识符可以通过`eureka.instance.instanceId`属性轻松覆盖。为了测试目的，让我们启动一些客户端应用程序实例，使用以下配置设置和`-DSEQUENCE_NO=[n]` VM 参数，其中`[n]`从`1`开始的序列号。以下是一个根据`SEQUENCE_NO`参数动态设置监听端口和发现`instanceId`的客户端应用程序的示例配置：

```java
server: 
 port: 808${SEQUENCE_NO}
eureka:
 instance:
   instanceId: ${spring.application.name}-${SEQUENCE_NO}
```

结果可以在 Eureka 仪表板上查看：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/fdb301da-0900-4cbf-abef-b084cbf557b9.png)

# 优先选择 IP 地址

默认情况下，所有实例都注册在其主机名下。这是一个非常方便的方法，前提是我们在我们的网络上启用了 DNS。然而，对于用作组织中微服务环境的服务器组，DNS 通常是不可用的，我自己就遇到过这种情况。除了在所有 Linux 机器上的`/etc/hosts`文件中添加主机名及其 IP 地址外，别无他法。这种解决方案的替代方法是更改注册过程配置设置，以广告服务的 IP 地址而不是主机名。为了实现这一点，客户端应将`eureka.instance.preferIpAddress`属性设置为`true`。注册表中的每个服务实例仍然会以`instanceId`包含主机名的形式打印到 Eureka 仪表板中，但如果你点击这个链接，重定向将基于 IP 地址进行。负责通过 HTTP 调用其他服务的 Ribbon 客户端也将遵循相同的原则。

如果你决定使用 IP 地址作为确定服务网络位置的主要方法，你可能会有问题。如果你有多个网络接口分配给你的机器，可能会出现问题。例如，在我曾经工作过的某个组织中，管理模式（我的工作站与服务器之间的连接）和生产模式（两台服务器之间的连接）有不同的网络。因此，每台服务器机器都分配有两个网络接口，具有不同的 IP 前缀。为了选择正确的接口，你可以在`application.yml`配置文件中定义一个忽略的模式列表。例如，我们希望能够忽略所有接口，其名称以`eth1`开头：

```java
spring:
  cloud:
    inetutils:
      ignoredInterfaces:
        - eth1*
```

还有一种方法可以获得那种效果。我们可以定义应该优先的网络地址：

```java
spring:
  cloud:
    inetutils:
      preferredNetworks:
        - 192.168
```

# 响应缓存

Eureka Server 默认缓存响应。缓存每 30 秒失效一次。可以通过调用 HTTP API 端点`/eureka/apps`轻松检查。如果你在客户端应用程序注册后立即调用它，你会发现响应中仍然没有返回。30 秒后再试，你会发现新实例出现了。响应缓存超时可以通过`responseCacheUpdateIntervalMs`属性覆盖。有趣的是，在使用 Eureka 仪表板显示已注册实例列表时，并没有缓存。与 REST API 相比，它绕过了响应缓存：

```java
eureka:
 server:
   responseCacheUpdateIntervalMs: 3000
```

我们应该记住，Eureka 注册表也缓存在客户端。所以，即使我们在服务器端更改了缓存超时时间，它可能仍然需要一段时间才能被客户端刷新。注册表通过一个默认每 30 秒调度一次的异步后台任务定期刷新。这个设置可以通过声明`registryFetchIntervalSeconds`属性来覆盖。它只获取与上一次抓取尝试相比的增量。可以通过使用`shouldDisableDelta`属性来禁用此选项。我在服务器和客户端两边都定义了`3`秒的超时时间。如果你用这样的设置启动示例应用程序，`/eureka/apps`将显示新注册服务的实例，可能在你的第一次尝试中。除非客户端端的缓存有意义，否则我不确定在服务器端缓存是否有意义，尤其是因为 Eureka 没有后端存储。就个人而言，我从未需要更改这些属性的值，但我猜想它可能很重要，例如，如果你使用 Eureka 开发单元测试，并且需要无缓存的即时响应：

```java
eureka:
 client:
   registryFetchIntervalSeconds: 3
   shouldDisableDelta: true
```

# 启用客户端和服务器之间的安全通信

到目前为止，Eureka 服务器没有对客户端的任何连接进行身份验证。在开发模式下，安全性并不像在生产模式下那么重要。缺乏安全性可能是一个问题。我们希望能够至少确保发现服务器通过基本身份验证进行安全，以防止任何知道其网络地址的服务遭受未经授权的访问。尽管 Spring Cloud 参考资料声称*HTTP 基本身份验证将自动添加到您的 Eureka 客户端*，但我还是不得不将带有安全性的启动器添加到项目依赖中：

```java
 <dependency>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-security</artifactId>
 </dependency>
```

然后，我们应该启用安全功能，并通过在`application.yml`文件中更改配置设置来设置默认凭据：

```java
security:
 basic:
   enabled: true
 user:
   name: admin
   password: admin123
```

现在，所有 HTTP API 端点和 Eureka 仪表板都得到了保护。要在客户端启用基本身份验证模式，应在 URL 连接地址中提供凭据，正如您在以下配置设置中所看到的那样。一个实现了安全发现示例应用程序在同一个存储库中 basic example，但您需要切换到`security`分支([`github.com/piomin/sample-spring-cloud-netflix/tree/security`](https://github.com/piomin/sample-spring-cloud-netflix/tree/security))。以下是客户端启用 HTTP 基本身份验证的配置：

```java
eureka:
 client:
   serviceUrl:
     defaultZone: http://admin:admin123@localhost:8761/eureka/
```

对于更高级的使用，例如在发现客户端和服务器之间使用证书认证的安全 SSL 连接，我们应该提供一个`DiscoveryClientOptionalArgs`的自定义实现。我们将在第十二章，*保护 API*，专门讨论 Spring Cloud 应用程序的安全性，讨论这样一个例子。

# 注册安全服务

保护服务器端是一回事，注册安全应用程序是另一回事。让我们看看我们如何做到这一点：

1.  为了给 Spring Boot 应用程序启用 SSL，我们需要从生成自签名证书开始。我建议你使用`keytool`，它可以在你 JRE 根目录下的`bin`目录中找到：

```java
keytool -genkey -alias client -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore keystore.p12 -validity 3650
```

1.  输入所需数据，并将生成的密钥库文件`keystore.p12`复制到您应用程序的`src/main/resources`目录中。下一步是使用`application.yml`中的配置属性为 Spring Boot 启用 HTTPS：

```java
server: 
 port: ${PORT:8081}
 ssl:
   key-store: classpath:keystore.p12
   key-store-password: 123456
   keyStoreType: PKCS12
   keyAlias: client
```

1.  在运行应用程序之后，您应该能够调用安全端点`https://localhost:8761/info`。我们还需要对 Eureka 客户端实例配置进行一些更改：

```java
eureka:
 instance:
   securePortEnabled: true
   nonSecurePortEnabled: false
   statusPageUrl: https://${eureka.hostname}:${server.port}/info
   healthCheckUrl: https://${eureka.hostname}:${server.port}/health
   homePageUrl: https://${eureka.hostname}:${server.port}/
```

# Eureka API

Spring Cloud Netflix 提供了一个用 Java 编写的客户端，将 Eureka HTTP API 隐藏在开发者面前。如果我们使用除 Spring 之外的其他框架，Netflix OSS 提供了一个原味的 Eureka 客户端，可以作为依赖项包含在内。然而，我们可能需要直接调用 Eureka API，例如，如果应用程序是用 Java 以外的语言编写的，或者我们需要在持续交付过程中注册的服务列表等信息。以下是一个快速参考表：

| **HTTP 端点** | **描述** |
| --- | --- |
| `POST /eureka/apps/appID` | 将服务的新实例注册到注册表 |
| `DELETE /eureka/apps/appID/instanceID` | 从注册表中删除服务实例 |
| `PUT /eureka/apps/appID/instanceID` | 向服务器发送心跳 |
| `GET /eureka/apps` | 获取有关所有注册服务实例列表的详细信息 |
| `GET /eureka/apps/appID` | 获取特定服务所有注册实例列表的详细信息 |
| `GET /eureka/apps/appID/instanceID` | 获取特定服务实例的详细信息 |
| `PUT /eureka/apps/appID/instanceID/metadata?key=value` | 更新元数据参数 |
| `GET /eureka/instances/instanceID` | 获取具有特定 ID 的所有注册实例的详细信息 |
| `PUT /eureka/apps/appID/instanceID/status?value=DOWN` | 更新实例的状态 |

# 复制和高度可用性

我们已经讨论了一些有用的 Eureka 设置，但到目前为止，我们只分析了一个单一服务发现服务器的系统。这种配置是有效的，但只适用于开发模式。对于生产模式，我们希望能够至少运行两个发现服务器，以防其中一个失败或发生网络问题。Eureka 按定义是为了可用性和弹性而构建的，这是 Netflix 开发的主要支柱之二。但它不提供标准的集群机制，如领导选举或自动加入集群。它是基于对等复制模型。这意味着所有服务器复制数据并向所有对等节点发送心跳，这些节点在当前服务器节点的配置中设置。这种算法简单有效，用于包含数据，但它也有一些缺点。它限制了可扩展性，因为每个节点都必须承受服务器上的整个写入负载。

# 示例解决方案的架构

有趣的是，复制机制是新版本 Eureka Server 开始工作的主要动机之一。Eureka 2.0 仍然处于积极开发中。除了优化的复制功能外，它还将提供一些有趣的功能，如服务器向客户端推送注册列表中任何更改的推送模型，自动扩展服务器和一个丰富的仪表板。这个解决方案看起来很有希望，但 Spring Cloud Netflix 仍然使用版本 1，老实说我没有找到任何迁移到版本 2 的计划。Dalston.SR4 发布列车当前的 Eureka 版本是 1.6.2。服务器端复制机制的配置归结为一点，即使用`eureka.client.*`属性部分设置另一个发现服务器的 URL。所选服务器只需在其他服务器中注册自己，这些服务器被选择作为创建的集群的一部分。展示这个解决方案在实践中如何工作的最好方式当然是通过示例。

让我们从示例系统的架构开始，如下面的图表所示。我们的所有应用程序都将在本地不同端口上运行。在这个阶段，我们必须介绍基于 Netflix Zuul 的 API 网关的示例。这对于在不同区域的三个服务实例之间进行负载均衡测试非常有帮助：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/39bca4a7-e902-4c34-bdd1-b5118fd74640.png)

# 构建示例应用程序

对于 Eureka Server，所有必需的更改可能定义在配置属性中。在`application.yml`文件中，我为每个发现服务实例定义了三个不同的配置文件。现在，如果您尝试在 Spring Boot 应用程序中运行 Eureka Server，您需要通过提供 VM 参数`-Dspring.profiles.active=peer[n]`来激活特定的配置文件，其中`[n]`是实例序列号：

```java
spring:
 profiles: peer1
eureka:
 instance:
   hostname: peer1
   metadataMap:
     zone: zone1
 client:
   serviceUrl:
     defaultZone: http://localhost:8762/eureka/,http://localhost:8763/eureka/
server: 
 port: ${PORT:8761}

---
spring:
 profiles: peer2
eureka:
 instance:
   hostname: peer2
   metadataMap:
     zone: zone2
 client:
   serviceUrl:
     defaultZone: http://localhost:8761/eureka/,http://localhost:8763/eureka/
server: 
 port: ${PORT:8762}

---
spring:
 profiles: peer3
eureka:
 instance:
   hostname: peer3
   metadataMap:
     zone: zone3
 client:
   serviceUrl:
     defaultZone: http://localhost:8761/eureka/,http://localhost:8762/eureka/
server: 
 port: ${PORT:8763}
```

在使用不同配置文件名称运行所有三个 Eureka 实例之后，我们创建了一个本地发现集群。如果您在启动后立即查看任何 Eureka 实例的仪表板，它总是看起来一样，我们可以看到三个 DISCOVERY-SERVICE 实例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/82c4f7d9-4624-4b6b-ae20-729088d40aff.png)

下一步是运行客户端应用程序。项目中的配置设置与 Eureka 服务器的应用程序非常相似。`defaultZone`字段中提供的地址顺序决定了尝试连接不同发现服务的顺序。如果无法连接到第一个服务器，它会尝试从列表中连接第二个服务器，依此类推。与之前一样，我们应该设置 VM 参数`-Dspring.profiles.active=zone[n]`以选择正确的配置文件。我还建议您设置`-Xmx192m`参数，考虑到我们本地测试所有的服务。如果您不为 Spring Cloud 应用程序提供任何内存限制，它在启动后大约会消耗 350MB 的堆内存，总内存大约 600MB。除非您有很多 RAM，否则它可能会使您在本地机器上运行微服务的多个实例变得困难：

```java
spring:
 profiles: zone1
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8761/eureka/,http://localhost:8762/eureka/,http://localhost:8763/eureka/
server: 
 port: ${PORT:8081}

---
spring:
 profiles: zone2
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8762/eureka/,http://localhost:8761/eureka/,http://localhost:8763/eureka/
server: 
 port: ${PORT:8082}

---
spring:
 profiles: zone3
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8763/eureka/,http://localhost:8761/eureka/,http://localhost:8762/eureka/
server: 
 port: ${PORT:8083}
```

让我们再次查看 Eureka 仪表板。我们有`client-service`的三个实例在所有地方注册，尽管应用程序最初只连接到一个发现服务实例。无论我们进入哪个发现服务实例的仪表板查看，结果都是一样的。这正是这次练习的目的。现在，我们创建一些额外的实现仅为了证明一切按预期工作：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/8fd6c50b-fd76-4f61-8b37-2459cbbf63f0.png)

客户端应用程序所做的不仅仅是暴露一个打印所选配置文件名称的 REST 端点。配置文件名称指向特定应用程序实例的主要发现服务实例。下面是一个简单的`@RestController`实现，打印当前区域的名称：

```java
@RestController
public class ClientController {

  @Value("${spring.profiles}")
  private String zone;

  @GetMapping("/ping")
  public String ping() {
    return "I'm in zone " + zone;
  }

}
```

最后，我们可以继续实现 API 网关。在本章范围内详细介绍 Zuul，Netflix 的 API 网关和路由功能是不合适的。我们将在下一章讨论它。Zuul 现在将有助于测试我们的示例解决方案，因为它能够检索在发现服务器中注册的服务列表，并在客户端应用程序的所有运行实例之间执行负载均衡。正如您在下面的配置片段中所看到的，我们使用一个在端口`8763`上监听的发现服务器。所有带有`/api/client/**`路径的传入请求将被路由到`client-service`：

```java
zuul:
 prefix: /api
 routes:
   client: 
     path: /client/**
     serviceId: client-service

eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8763/eureka/
   registerWithEureka: false
```

接下来让我们进行测试。我们的应用通过 Zuul 代理启动时应使用`java -jar`命令，与之前的服务不同，这里无需设置任何额外参数，包括配置文件名。它默认与编号为#3 的发现服务相连。要通过 Zuul 代理调用客户端 API，你需要在网页浏览器中输入以下地址，`http://localhost:8765/api/client/ping`。结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/82dce964-212f-4a2b-8fd2-f8aa4db10fdc.png)

如果你连续重试几次请求，它应该在所有现有的`client-service`实例之间进行负载均衡，比例为 1:1:1，尽管我们的网关只连接到发现#3。这个例子充分展示了如何使用多个 Eureka 实例构建服务发现。

前面提到的示例应用程序在 GitHub 上可获得，位于`cluster`分支中([`github.com/piomin/sample-spring-cloud-netflix.git`](https://github.com/piomin/sample-spring-cloud-netflix.git))([`github.com/piomin/sample-spring-cloud-netflix/tree/cluster_no_zones`](https://github.com/piomin/sample-spring-cloud-netflix/tree/cluster_no_zones))。

# 故障转移

你可能想知道如果服务发现的一个实例崩溃了会发生什么？为了检查集群在故障发生时的行为，我们将稍稍修改之前的示例。现在，Zuul 在其配置设置中有一个到第二个服务发现的故障转移连接，端口为`8762`。为了测试目的，我们关闭了端口`8763`上的第三个发现服务实例：

```java
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8763/eureka/,http://localhost:8762/eureka/
   registerWithEureka: false
```

当前情况在下图中说明。测试通过调用网关端点进行，端点地址为`http://localhost:8765/api/client/ping`。结果与之前测试相同，负载均衡在所有三个`client-service`实例之间平均进行，符合预期。尽管发现服务#3 已被禁用，但另外两个实例仍能相互通信，并从实例#3 复制第三个客户端应用实例的网络位置信息，只要实例#3 处于活动状态。现在，即使我们重新启动网关，它仍能够使用`defaultZone`字段中的第二个地址顺序连接发现集群，地址为`http://localhost:8762/eureka`。对于客户端应用的第三个实例也适用，该实例反过来将发现服务#1 作为备份连接：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6a432d7f-3bbb-4afb-89e2-a306aa26fa2d.png)

# 区域

基于对等复制的集群在大多数情况下是一个不错的选择，但并非总是足够。Eureka 还有一个在集群环境中可能非常有用的有趣特性。实际上，区域机制是默认行为。即使我们有一个单独的独立服务发现实例，每个客户端的属性也必须在配置设置中设置为`eureka.client.serviceUrl.defaultZone`。这什么时候对我们有用呢？为了解析它，我们回到前面章节中的示例。让我们假设现在我们的环境被划分为三个不同的物理网络，或者我们只是有三台不同的机器处理传入的请求。当然，服务发现服务在逻辑上仍然分组在集群中，但每个实例都位于一个单独的区域。每个客户端应用程序都将注册在与其主要服务发现服务器相同的区域。我们不是要启动一个 Zuul 网关的实例，而是要启动三个实例，每个实例对应一个单一的区域。如果请求进入网关，它应该在尝试调用注册在其他区域的服务之前，优先考虑利用同一区域内的服务客户端。当前系统架构在下图中可视化。当然，为了示例的目的，架构被简化为能够在单个本地机器上运行。在现实世界中，如我之前提到的，它将在三台不同的机器上启动，甚至可能在其他网络上物理分离成三组机器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/76b111a0-a8bf-4152-bc6b-da28a8e922c4.png)

# 具有独立服务器的区域

在这个阶段，我们应该强调一点，区域机制仅在客户端实现。这意味着服务发现实例没有被分配到任何区域。所以前一个图表可能有些令人困惑，但它指示了哪个 Eureka 是特定区域中所有客户端应用程序和网关的默认服务发现。我们的目的是检查高可用性模式下的机制，但我们也可以只构建一个单一的服务发现服务器。以下图表展示了与前一个图表类似的情况，不同之处在于它假设只有一个服务发现服务器为所有应用程序服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d2c54f1c-e08d-48f7-a360-5ae1a1153c36.png)

# 构建示例应用程序

为了启用区域处理，我们需要对客户端和网关的配置设置进行一些更改。以下是从客户端应用程序中修改的`application.yml`文件：

```java
spring:
 profiles: zone1
eureka:
 instance:
   metadataMap:
     zone: zone1
 client:
   serviceUrl:
     defaultZone: http://localhost:8761/eureka/,http://localhost:8762/eureka/,http://localhost:8763/eureka/
```

唯一需要更新的是`eureka.instance.metadataMap.zone `属性，我们在其中设置了区域名称和我们的服务已注册的服务名称。

在网关配置中必须进行更多更改。首先，我们需要添加三个配置文件，以便能够在三个不同区域和三个不同的发现服务器上运行一个应用程序。现在当启动网关应用程序时，我们应该设置 VM 参数`-Dspring.profiles.active=zone[n]`以选择正确的配置文件。与`client-service`类似，我们还必须在配置设置中添加`eureka.instance.metadataMap.zone`属性。还有一个属性`eureka.client.preferSameZoneEureka`，在示例中首次使用，如果网关应该优先选择注册在同一区域的客户端应用程序实例，则必须将其设置为`true`：

```java
spring:
 profiles: zone1
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8761/eureka/
     registerWithEureka: false
     preferSameZoneEureka: true
 instance:
   metadataMap:
     zone: zone1
server: 
 port: ${PORT:8765}

---
spring:
 profiles: zone2
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8762/eureka/
     registerWithEureka: false
     preferSameZoneEureka: true
 instance:
   metadataMap:
     zone: zone2
server: 
 port: ${PORT:8766}

---
spring:
 profiles: zone3
eureka:
 client:
   serviceUrl:
     defaultZone: http://localhost:8763/eureka/
     registerWithEureka: false
     preferSameZoneEureka: true
 instance:
   metadataMap:
     zone: zone3
server: 
 port: ${PORT:8767}
```

在启动发现、客户端和网关应用程序的所有实例后，我们可以尝试调用在`http://localhost:8765/api/client/ping`、`http://localhost:8766/api/client/ping`和`http://localhost:8767/api/client/ping`地址下可用的端点。它们都将始终与注册在相同区域的客户端实例进行通信。因此，与没有首选区域的测试相比，例如，端口`8765`上可用的第一个网关实例始终打印出“我在 zone1 区域”并在调用 ping 端点时：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/df5918ad-c4b6-477b-a705-6ff4a7ba736d.png)

当客户端#1 不可用时会发生什么？因为它们都位于与网关#1 不同的区域，所以传入的请求将被负载均衡 50/50 分配到两个其他客户端应用程序实例。

# 总结

在本章中，我们有机会首次在本书中使用 Spring Cloud 开发应用程序。在我看来，开始微服务框架冒险的最佳方式是尝试弄清楚如何正确实现服务发现。从最简单的用例和示例开始，我们已经经历了 Netflix OSS Eureka 项目提供的先进且生产就绪的功能。我向您展示了如何在*五分钟内*创建和运行一个基本客户端和一个独立的发现服务器。基于该实现，我介绍了如何自定义 Eureka 客户端和服务器以满足我们的特定需求，重点放在网络或应用程序失败等负面场景上。诸如 REST API 或 UI 仪表板等特性已经详细讨论。最后，我向您展示了如何使用 Eureka 的机制（如复制、区域和高可用性）创建一个生产就绪环境。有了这些知识，您应该能够选择通过 Eureka 构建适合您微服务架构特性的服务发现功能。

一旦我们讨论了服务发现，我们就可以继续探讨微服务架构中的下一个关键元素：配置服务器。服务和配置服务通常都基于键/值存储，因此它们可能由相同的产品提供。然而，由于 Eureka 只专注于发现，Spring Cloud 引入了自己的框架来管理分布式配置，即 Spring Cloud Config。


# 第五章：使用 Spring Cloud Config 的分布式配置

现在是引入我们架构中的一个新的元素，一个分布式配置服务器的时候了。与服务发现一样，这是微服务周围的的关键概念之一。在上一章中，我们详细讨论了如何准备发现，包括服务器和客户端两侧。但到目前为止，我们总是通过在一个胖 JAR 文件内部放置属性来为应用程序提供配置。这种方法有一个很大的缺点，它需要重新编译和部署微服务的实例。Spring Boot 支持另一种方法，它假定使用一个存储在胖 JAR 外部文件系统中的显式配置。在应用程序启动时，可以通过`spring.config.location`属性轻松地为应用程序配置。这种方法不需要重新部署，但它也不是没有缺点。对于很多微服务，基于显式文件放置在文件系统上的配置管理可能真的非常麻烦。此外，让我们想象一下，每个微服务都有很多实例，并且每个实例都有特定的配置。好吧，用那种方法最好不要去想象。

总之，分布式配置在云原生环境中是一个非常流行的标准。Spring Cloud Config 为分布式系统中的外部化配置提供了服务器端和客户端支持。有了这个解决方案，我们有一个中心位置，可以管理跨所有环境的应用程序的外部属性。这个概念真的很简单，易于实现。服务器所做的不仅仅是暴露 HTTP 和基于资源的 API 接口，返回`property`文件以 JSON、YAML 或属性格式。此外，它还执行返回属性值的解密和加密操作。客户端需要从服务器获取配置设置，如果服务器端启用了此类功能，还需要对其进行解密。

配置数据可能存储在不同的仓库中。`EnvironmentRepository`的默认实现使用 Git 后端。也可以设置其他 VCS 系统，如 SVN。如果你不想利用 VCS 作为后端所提供的特性，你可以使用文件系统或 Vault。Vault 是一个管理秘密的工具，它存储并控制对令牌、密码、证书和 API 密钥等资源的访问。

本章我们将要覆盖的主题有：

+   由 Spring Cloud Config Server 暴露的 HTTP API

+   服务器端的不同的仓库后端类型

+   整合服务发现

+   使用 Spring Cloud Bus 和消息代理自动重新加载配置

# HTTP API 资源介绍

配置服务器提供 HTTP API，可以通过多种方式调用。以下端点可用：

+   `/{application}/{profile}[/{label}]`: 这返回以 JSON 格式数据；标签参数是可选的

+   `/{application}-{profile}.yml`: 这返回 YAML 格式。

+   `/{label}/{application}-{profile}.yml`: 此为前一个端点的变种，其中我们可以传递一个可选的标签参数。

+   `/{application}-{profile}.properties`: 这返回属性文件使用的简单键/值格式。

+   `/{label}/{application}-{profile}.properties`: 此为前一个端点的变种，其中我们可以传递一个可选的标签参数。

从客户端的角度来看，应用程序参数是应用程序的名称，它来自于`spring.application.name`或`spring.config.name`属性，配置文件参数是活动配置文件或由逗号分隔的活动配置文件列表。最后一个可用的参数`label`是一个可选属性，仅在作为后端存储的 Git 中工作时才重要。它设置了配置的 Git 分支名称，默认为`master`。

# 原生配置文件支持

让我们从最简单的例子开始，该例子基于文件系统后端。默认情况下，Spring Cloud Config Server 尝试从 Git 仓库获取配置数据。要启用原生配置文件，我们应该使用`spring.profiles.active`选项将服务器启动设置为`native`。它会在以下位置搜索存储的文件，`classpath:/`、`classpath:/config`、`file:./`、`file:./config`。这意味着属性文件或 YAML 文件也可以放在 JAR 文件内部。为了测试目的，我在`src/main/resources`内部创建了一个 config 文件夹。我们的配置文件将存储在该位置。现在，我们需要回到前一章节的例子。正如您可能记得的，我介绍了集群发现环境的配置，每个客户端服务实例在不同的区域启动。有三个可用的区域和三个客户端实例，每个实例在其`application.yml`文件中都有自己的配置文件。该示例的源代码在`config`分支中可用。这是链接：[`github.com/piomin/sample-spring-cloud-netflix/tree/config`](https://github.com/piomin/sample-spring-cloud-netflix/tree/config)。

[`github.com/piomin/sample-spring-cloud-netflix/tree/config`](https://github.com/piomin/sample-spring-cloud-netflix/tree/config)

我们当前的任务是将该配置迁移到 Spring Cloud Config Server。让我们回顾一下该示例中设置的属性。以下是为客户端应用程序的第一个实例使用的配置文件设置。根据所选配置文件，有一个可变的实例运行端口、一个默认的发现服务器 URL 和一个区域名称：

```java
---
spring:
 profiles: zone1

eureka:
 instance:
   metadataMap:
     zone: zone1
   client:
     serviceUrl:
       defaultZone: http://localhost:8761/eureka/

server: 
 port: ${PORT:8081}
```

在所描述的示例中，我把所有配置文件设置放在了一个单独的`application.yml`文件中，以简化问题。这个文件完全可以被分成三个不同的文件，文件名包含各自配置文件，如`application-zone1.yml`、`application-zone2.yml`和`application-zone3.yml`。当然，这样的名字对于单个应用来说是唯一的，所以如果我们决定将这些文件移动到远程配置服务器，我们需要注意它们的名称。客户端应用程序名称是从`spring.application.name`注入的，在这个例子中，它是`client-service`。所以，总结来说，我在`src/main/resources/config`目录下创建了三个名为`client-service-zone[n].yml`的配置文件，其中[`n`]是实例编号。现在，当你调用`http://localhost:8888/client-service/zone1`端点时，你将以 JSON 格式收到以下响应：

```java
{
 "name":"client-service",
 "profiles":["zone1"],
 "label":null,
 "version":null,
 "state":null,
 "propertySources":[{
 "name":"classpath:/config/client-service-zone1.yml",
 "source":{
 "eureka.instance.metadataMap.zone":"zone1",
 "eureka.client.serviceUrl.defaultZone":"http://localhost:8761/eureka/",
 "server.port":"${PORT:8081}"
 }
 }]
}
```

我们还可以调用`http://localhost:8888/client-service-zone2.properties`获取第二个实例，它将以下响应作为属性列表返回：

```java
eureka.client.serviceUrl.defaultZone: http://localhost:8762/eureka/
eureka.instance.metadataMap.zone: zone2
server.port: 8082
```

最后一个可用的 HTTP API 端点，`http://localhost:8889/client-service-zone3.yml`，返回与输入文件相同的数据。这是第三个实例的结果：

```java
eureka:
 client:
 serviceUrl:
 defaultZone: http://localhost:8763/eureka/
 instance:
 metadataMap:
 zone: zone3
server:
 port: 8083
```

# 构建服务器端应用程序

我们首先讨论了由 Spring Cloud Config Server 提供的基于资源的 HTTP API 以及在该处创建和存储属性的方法。但现在让我们回到基础。与发现服务器一样，Config Server 也可以作为 Spring Boot 应用程序运行。要在服务器端启用它，我们应在`pom.xml`文件中包含`spring-cloud-config-server`在我们的依赖项中：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-config-server</artifactId>
</dependency>
```

此外，我们应在主应用程序类上启用 Config Server。将服务器端口更改为`8888`是个好主意，因为它是客户端侧`spring.cloud.config.uri`属性的默认值。例如，客户端会自动配置。要更改服务器端口，你应该设置`server.port`属性为`8888`，或者使用`spring.config.name=configserver`属性启动它。`spring-cloud-config-server`库中有一个`configserver.yml`：

```java
@SpringBootApplication
@EnableConfigServer
public class ConfigApplication {

 public static void main(String[] args) {
   new SpringApplicationBuilder(ConfigApplication.class).web(true).run(args);
 }

}
```

# 构建客户端应用程序

如果你把`8888`设置为服务器的默认端口，客户端的配置就非常简单了。你只需要提供`bootstrap.yml`文件，其中包含应用程序名称，并在你的`pom.xml`中包含以下依赖关系。当然，这个规则只适用于本地主机，因为客户端自动配置的 Config Server 地址是`http://localhost:8888`：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-config</artifactId>
</dependency>
```

如果您为服务器设置了不同于`8888`的端口，或者它运行在与客户端应用程序不同的机器上，您还应该在`bootstrap.yml`中设置其当前地址。以下是引导上下文设置，它允许您从端口`8889`上运行的服务器获取`client-service`的属性。当使用`--spring.profiles.active=zone1`参数运行应用程序时，它将自动获取配置服务器中为`zone1`配置文件设置的属性：

```java
spring: 
 application:
   name: client-service
 cloud:
   config:
     uri: http://localhost:8889
```

# 添加 Eureka 服务器

正如您可能已经注意到的，客户端属性中有一个发现服务网络位置的地址。所以，在启动客户端服务之前，我们应该有一个 Eureka 服务器在运行。当然，Eureka 也有自己的配置，它已经被存储在前一章节的`application.yml`文件中。那个配置，类似于`client-service`，被分成了三个配置文件，每个文件在诸如服务器 HTTP 端口号和要通信的发现对等体列表等属性上与其他文件不同。

现在，我们将这些`property`文件放在配置服务器上。Eureka 在启动时获取分配给所选配置文件的所有的设置。文件命名与已经描述的标准一致，即`discovery-service-zone[n].yml`。在运行 Eureka 服务器之前，我们应该在依赖项中包括`spring-cloud-starter-config`以启用 Spring Cloud Config 客户端，并用以下所示的`bootstrap.yml`替换`application.yml`：

```java
spring: 
 application:
   name: discovery-service
 cloud:
   config:
     uri: http://localhost:8889
```

现在，我们可以通过在`--spring.profiles.active`属性中设置不同的配置文件名称，以对等通信模式运行三个 Eureka 服务器实例。在启动三个`client-service`实例之后，我们的架构如下所示。与前一章节的示例相比，客户端和服务发现服务都从 Spring Cloud Config 服务器获取配置，而不是将其保存在胖 JAR 内的 YML 文件中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/9423cf78-f43e-4e95-89a7-fe1beeae4cff.png)

# 客户端引导方法

在前面的示例解决方案中，所有应用程序必须持有配置服务器的网络位置。服务发现的位置作为属性存储在那里。在此时，我们面临一个有趣的问题进行讨论。我们可以问一下我们的微服务是否应该知道 Config Server 的网络地址。在之前的讨论中，我们已经同意所有服务的网络位置的主要位置应该是服务发现服务器。配置服务器也是像其他微服务一样的 Spring Boot 应用程序，所以从逻辑上讲，它应该向 Eureka 注册自己，以使其他必须从 Spring Cloud Config Server 获取数据的服务能够使用自动发现机制。这反过来又要求将服务发现连接设置放在`bootstrap.yml`中，而不是`spring.cloud.config.uri`属性。

在设计系统架构时需要做出的决定之一就是在这两种不同的方法之间进行选择。并不是说一种解决方案比另一种更好。对于使用`spring-cloud-config-client`工件的任何应用程序，其默认行为在 Spring Cloud 命名法中称为**Config First Bootstrap**。当配置客户端启动时，它会绑定到服务器并使用远程属性源初始化上下文。这种方法在本章的第一个示例中已经介绍过。在第二种解决方案中，Config Server 向服务发现注册，所有应用程序可以使用`DiscoveryClient`来定位它。这种方法称为**Discovery First Bootstrap**。让我们实现一个示例来阐述这个概念。

# 配置服务器发现

要访问 GitHub 上的这个示例，你需要切换到`config_with_discovery`分支。这是链接：

[`github.com/piomin/sample-spring-cloud-netflix/tree/config_with_discovery`](https://github.com/piomin/sample-spring-cloud-netflix/tree/config_with_discovery)。

第一次更改与`sample-service-discovery`模块有关。在那里我们不需要`spring-cloud-starter-config`依赖。简单的配置不再从远程属性源获取，而是设置在`bootstrap.yml`中。与之前的示例相比，为了简化练习，我们启动一个单一的独立 Eureka 实例：

```java
spring: 
 application:
   name: discovery-service 

server: 
 port: ${PORT:8761} 

eureka:
 client:
   registerWithEureka: false
   fetchRegistry: false
```

相比之下，我们应该为 Config Server 包含`spring-cloud-starter-eureka`依赖。现在，依赖关系的完整列表如下所示。此外，必须通过在主类上声明`@EnableDiscoveryClient`注解来启用发现客户端，并且通过在`application.yml`文件中将`eureka.client.serviceUrl.defaultZone`属性设置为`http://localhost:8761/eureka/`来提供 Eureka Server 地址：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-config-server</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-eureka</artifactId>
</dependency>
```

在客户端应用程序方面，不再需要持有配置服务器的地址。只需要设置服务 ID，以防它与 Config Server 不同。根据本例中服务命名惯例，该 ID 是`config-server`。它应该使用`spring.cloud.config.discovery.serviceId`属性覆盖。为了允许发现机制启用发现机制从配置服务器获取远程属性源，我们应该设置`spring.cloud.config.discovery.enabled=true`：

```java
spring: 
 application:
   name: client-service
 cloud:
   config:
     discovery:
       enabled: true
       serviceId: config-server
```

下面是带有 Config Server 的一个实例和三个`client-service`实例注册的 Eureka 仪表板屏幕。客户端的 Spring Boot 应用程序的每个实例都与之前的示例相同，并使用`--spring.profiles.active=zone[n]`参数启动，其中`n`是区域编号。唯一不同的是，Spring Cloud Config Server 提供的所有客户端服务配置文件都有与 Eureka Server 相同的连接地址：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/11dbf317-7acc-465c-8714-af1143dd5297.png)

# 仓库后端类型

本章中前面的所有示例都使用了文件系统后端，这意味着配置文件是从本地文件系统或类路径中加载的。这种后端对于教程目的或测试来说非常不错。如果你想在生产环境中使用 Spring Cloud Config，考虑其他选项是值得的。这些选项中的第一个是基于 Git 的仓库后端，它也是默认启用的。它不是唯一一个可以用作配置源仓库的**版本控制系统**（**VCS**）。另一个选项是 SVN，或者我们可以决定创建一个复合环境，这可能包括 Git 和 SVN 仓库。下一个支持的后端类型是基于 HashiCorp 提供的工具 Vault。当管理诸如密码或证书的安全属性时，它特别有用。让我们更详细地看看这里列出的每个解决方案。

# 文件系统后端

我不会写太多关于这个主题的内容，因为已经在之前的示例中讨论过了。它们都展示了如何将属性源存储在类路径中。还有从磁盘加载它们的能力。默认情况下，Spring Cloud Config Server 尝试在应用程序的工作目录或此位置的 config 子目录内定位文件。我们可以使用`spring.cloud.config.server.native.searchLocations`属性来覆盖默认位置。搜索位置路径可能包含`application`、`profile`和`label`的占位符。如果在位置路径中不使用任何占位符，仓库会自动将标签参数作为后缀添加。

因此，配置文件从每个搜索位置和与标签同名的子目录中加载。例如，`file:/home/example/config`与`file:/home/example/config,file:/home/example/config/{label}`相同。可以通过将`spring.cloud.config.server.native.addLabelLocations`设置为`false`来禁用这种行为。

如我前面所提到的，文件系统后端不是生产部署的好选择。如果你将属性源放在 JAR 文件内的类路径中，每次更改都需要重新编译应用程序。另一方面，在 JAR 之外使用文件系统不需要重新编译，但如果你有多个实例的配置服务在高级可用性模式下工作，这种方法可能会有麻烦。在这种情况下，将文件系统跨所有实例共享或将每个运行实例的属性源副本保留。Git 后端免除了这些缺点，这就是为什么它推荐用于生产环境的原因。

# Git 后端

Git 版本控制系统有一些功能使其作为属性源的仓库非常有用。它允许你轻松地管理和审计更改。通过使用众所周知的版本控制机制，如提交、回滚和分支，我们可以比文件系统方法更容易地执行重要的操作。这种后端还有另外两个关键优势。它强制将配置服务器源代码和`property`文件仓库分开。如果你再次查看之前的示例，你会发现`property`文件与应用程序源代码一起存储。也许有些人会说，即使我们使用文件系统后端，也可以将整个配置作为单独的项目存储在 Git 中，并在需要时上传到远程服务器上。当然，你的观点是正确的。但是，当使用与 Spring Cloud Config 结合的 Git 后端时，你可以直接获得这些机制。此外，它还解决了与运行服务器多个实例相关的问题。如果你使用远程 Git 服务器，更改可能很容易在所有运行实例之间共享。

# 不同的协议

要为应用程序设置 Git 仓库的位置，我们应该在`application.yml`中使用`spring.cloud.config.server.git.uri`属性。如果你熟悉 Git，你就会知道克隆可以通过文件、http/https 和 ssh 协议来实现。本地仓库访问允许你快速开始，而不需要远程服务器。它使用文件、前缀进行配置，例如，`spring.cloud.config.server.git.uri=file:/home/git/config-repo`。当在高级可用性模式下运行 Config Server 时，你应该使用远程协议 SSH 或 HTTPS。在这种情况下，Spring Cloud Config 克隆远程仓库，然后基于本地工作副本作为缓存。

# 在 URI 中使用占位符

这里支持所有最近列出的占位符，`application`、`profile`和`label`。我们可以使用占位符为每个应用程序创建一个单一仓库，如`https://github.com/piomin/{application}`，甚至可以为每个配置文件创建，`https://github.com/piomin/{profile}`。这种后端实现将 HTTP 资源的 label 参数映射到 Git 标签，可能指的是提交 ID、分支或标签名。显然，发现对我们感兴趣的功能的最合适方式是通过一个示例。让我们先通过创建一个用于存储应用程序属性源的 Git 仓库开始。

# 构建服务器应用程序

我创建了一个示例配置仓库，您可以在 GitHub 上在此处找到它：

请参阅[`github.com/piomin/sample-spring-cloud-config-repo.git`](https://github.com/piomin/sample-spring-cloud-config-repo.git)。

我将本章中使用的所有属性源放在了这里，这些示例展示了客户端应用程序在不同发现区域对本地配置文件的支持。现在，我们的仓库包含了此列表中可见的文件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d2b06957-1a0d-4f84-ade1-8637cdc7d591.png)

默认情况下，Spring Cloud Config Server 在第一次 HTTP 资源调用后尝试克隆一个仓库。如果你想在启动后强制克隆，你应该将`cloneOnStart`属性设置为`true`。此外，还需要设置仓库连接设置和账户认证凭据：

```java
spring:
 application:
   name: config-server
 cloud:
   config:
     server:
       git:
         uri: https://github.com/piomin/sample-spring-cloud-config-repo.git
         username: ${github.username}
         password: ${github.password}
         cloneOnStart: true
```

在服务器运行后，我们可以调用之前练习中已知端点，例如`http://localhost:8889/client-service/zone1`或`http://localhost:8889/client-service-zone2.yml`。结果与早期测试相同；唯一不同的是数据源。现在，让我们进行另一个练习。正如您可能记得的，当我们首先使用`native`配置文件启用发现引导时，我们必须稍微更改客户端的属性。因为现在我们使用的是 Git 后端，我们可以为这种情况开发一个更聪明的解决方案。在当前方法中，我们将在 GitHub 上的配置仓库中创建`discovery`分支（[`github.com/piomin/sample-spring-cloud-config-repo/tree/discovery`](https://github.com/piomin/sample-spring-cloud-config-repo/tree/discovery)），并将专为应用程序演示发现首先引导机制的文件放置在此分支上。如果您用`label`参数设置为`discovery`调用 Config Server 端点，您将获取我们新分支的数据。尝试调用`http://localhost:8889/client-service/zone1/discovery`和/或`http://localhost:8889/discovery/client-service-zone2.yml`并检查结果*.*

让我们考虑另一种情况。我更改了 `client-service` 第三实例的服务器端口，但出于某种原因，我想恢复到以前的价值。我必须更改并提交 `client-service-zone3.yml` 以使用以前的端口值吗？不用，我只需要在调用 HTTP API 资源时传递 `label` 参数即可。下面截图展示了所执行的更改：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/b6069696-66ed-4ace-bfda-741529faf834.png)

如果我用父提交 ID 调用 API 端点而不是分支名，那么会返回较旧的端口号作为响应。以下是调用 `http://localhost:8889/e546dd6/client-service-zone3.yml` 的结果，其中 `e546dd6` 是之前的提交 ID：

```java
eureka:
  client:
    serviceUrl:
      defaultZone: http://localhost:8761/eureka/
  instance:
    metadataMap:
      zone: zone3
server:
  port: 8083
```

# 客户端配置

在用 Git 后端构建服务器端时，我仅向您展示了 HTTP 资源调用的例子。以下是客户端应用程序的配置示例。我们不仅可以设置 `bootstrap.yml` 中的 `profile` 属性，还可以在 `spring.profiles.active` 运行参数中传递它。这个配置使得客户端从 `discovery` 分支获取属性。我们还可以通过在 `label` 属性中设置某个提交 ID 来决定切换到某个提交 ID，正如我刚才已经提到的：

```java
spring: 
 application:
   name: client-service
 cloud:
   config:
     uri: http://localhost:8889
     profile: zone1
     label: discovery
#    label: e546dd6 // uncomment for rollback
```

# 多个仓库

有时，您可能需要为单个 Config Server 配置多个仓库。我可以想象到您需要将业务配置从典型的技术配置中分离出来的情况。这是完全可能的：

```java
spring:
 cloud:
   config:
     server:
       git:
         uri: https://github.com/piomin/spring-cloud-config-repo/config-repo
         repos:
           simple: https://github.com/simple/config-repo
           special:
             pattern: special*/dev*,*special*/dev*
             uri: https://github.com/special/config-repo
           local:
             pattern: local*
             uri: file:/home/config/config-repo 
```

# Vault 后端

我已经提到了 Vault 作为一个通过统一接口安全访问密钥的工具。为了使 Config Server 使用这种类型的后端，您必须使用 Vault 配置文件 `--spring.profiles.active=vault` 运行它。当然，在运行 Config Server 之前，您需要安装并启动 Vault 实例。我建议您使用 Docker 来做这件事。我知道这是本书中第一次接触 Docker，并不是每个人都熟悉这个工具。我在第十四章*，Docker 支持*中提供了 Docker 的简要介绍，包括其基本命令和用例。所以，如果您是第一次接触这项技术，请先查看这个介绍。对于那些熟悉 Docker 的同学，这里是在开发模式下运行 Vault 容器的命令。我们可以使用 `VAULT_DEV_LISTEN_ADDRESS` 参数或初始生成的根令牌 ID 覆盖默认监听地址：

```java
docker run --cap-add=IPC_LOCK -d --name=vault -e 'VAULT_DEV_ROOT_TOKEN_ID=client' -p 8200:8200 vault 
```

# 开始使用 Vault

Vault 提供了一个命令行界面，可用于向服务器添加新值和从服务器读取它们。下面展示了调用这些命令的示例。然而，我们已经以 Docker 容器的形式运行了 Vault，所以最方便管理密钥的方式是通过 HTTP API：

```java
$ vault write secret/hello value=world
$ vault read secret/hello
```

Vault 在我们实例中的 HTTP API 可以通过`http://192.168.99.100:8200/v1/secret`地址进行访问。调用该 API 的每一个方法时，你需要传递一个令牌作为请求头`X-Vault-Token`。因为我们启动 Docker 容器时在`VAULT_DEV_ROOT_TOKEN_ID`环境变量中设置了这个值，所以它等于`client`。否则，在启动过程中会自动生成，并且可以通过调用命令`docker logs vault`从日志中读取。实际上，要与 Vault 一起工作，我们需要了解两种 HTTP 方法——`POST`和`GET`。调用`POST`方法时，我们可以定义应该添加到服务器的密钥列表。这里所示的`curl`命令中的参数是使用 kv 后端创建的，它像一个键/值存储器：

```java
$ curl -H "X-Vault-Token: client" -H "Content-Type: application/json" -X POST -d '{"server.port":8081,"sample.string.property": "Client App","sample.int.property": 1}' http://192.168.99.100:8200/v1/secret/client-service
```

新添加的值可以通过使用`GET`方法从服务器读取：

```java
$ curl -H "X-Vault-Token: client" -X GET http://192.168.99.100:8200/v1/secret/client-service
```

# 与 Spring Cloud Config 集成

如我之前提到的，我们必须使用`--spring.profiles.active=vault`参数运行 Spring Cloud Config Server，以启用 Vault 作为后端存储。为了覆盖默认的自动配置设置，我们应该在`spring.cloud.config.server.vault.*`键下定义属性。我们示例应用程序的当前配置如下所示。一个示例应用程序可以在 GitHub 上找到；你需要切换到`config_vault`分支([`github.com/piomin/sample-spring-cloud-netflix/tree/config_vault`](https://github.com/piomin/sample-spring-cloud-netflix/tree/config_vault))来访问它：

```java
spring:
 application:
   name: config-server
 cloud:
   config:
     server:
       vault:
         host: 192.168.99.100
         port: 8200
```

现在，你可以调用 Config Server 暴露的端点。你必须在上传请求头中传递令牌，但这次它的名称是`X-Config-Token`：

```java
$ curl -X "GET" "http://localhost:8889/client-service/default" -H "X-Config-Token: client"
```

响应应该与下面显示的相同。这些属性是客户端应用程序所有配置文件的全局默认值。你也可以通过在 Vault HTTP `API`方法中调用带有逗号字符的选定配置文件名称来为选定的配置文件添加特定设置，如下所示，`http://192.168.99.100:8200/v1/secret/client-service,zone1`。如果调用路径中包含了这样的配置文件名称，响应中会返回`default`和`zone1`配置文件的所有属性：

```java
{
    "name":"client-service",
    "profiles":["default"],
    "label":null,
    "version":null,
    "state":null,
    "propertySources":[{
        "name":"vault:client-service",
        "source":{
            "sample.int.property":1,
            "sample.string.property":"Client App",
            "server.port":8081
        }
    }]
} 
```

# 客户端配置

当使用 Vault 作为 Config Server 的后端时，客户端需要传递一个令牌，以便服务器能够从 Vault 检索值。这个令牌应该在客户端配置设置中提供，在`bootstrap.yml`文件中的`spring.cloud.config.token`属性：

```java
spring:
 application:
   name: client-service
 cloud:
   config:
     uri: http://localhost:8889
     token: client
```

# 额外特性

让我们来看看 Spring Cloud Config 的一些其他有用特性。

# 启动失败并重试

有时如果 Config Server 不可用，启动应用程序就没有任何意义。在这种情况下，我们希望能够用异常停止客户端。为了实现这一点，我们必须将引导配置属性`spring.cloud.config.failFast`设置为`true`。这种激进的解决方案并不总是期望的行为。如果 Config Server 只是偶尔不可达，更好的方法是在成功之前一直尝试重新连接。`spring.cloud.config.failFast`属性仍然必须等于`true`，但我们还需要在应用程序类路径中添加`spring-retry`库和`spring-boot-starter-aop`。默认行为假设重试六次，初始退避间隔为 1000 毫秒。您可以使用`spring.cloud.config.retry.*`配置属性覆盖这些设置。

# 保护客户端

与服务发现一样，我们可以通过基本认证来保护 Config Server。使用 Spring Security 可以在服务器端轻松启用。在这种情况下，客户端只需要在`bootstrap.yml`文件中设置用户名和密码：

```java
spring:
 cloud:
   config:
     uri: https://localhost:8889
     username: user
     password: secret
```

# 自动重新加载配置

我们已经讨论了 Spring Cloud Config 最重要的特性。在那一刻，我们实现了示例，说明如何使用不同的后端存储作为存储库。但是，无论我们决定选择文件系统、Git 还是 Vault，我们的客户端应用程序都需要重新启动，才能从服务器获取最新的配置。然而，有时这并不是一个最优的解决方案，尤其是如果我们有许多微服务在运行，其中一些使用相同的通用配置。

# 解决方案架构

即使我们为每个单一的应用程序创建了一个专用的`property`文件，动态地重新加载它而不重新启动的机会也非常有帮助。正如您可能已经推断出的那样，这样的解决方案对 Spring Boot 和因此对 Spring Cloud 都是可用的。在第四章，*服务发现*中，在介绍从服务发现服务器注销时，我引入了一个端点`/shutdown`，可以用于优雅地关闭。还有一个用于 Spring 上下文重启的端点，其工作方式与关闭相似。

客户端端的端点只是需要包含以使 Spring Cloud Config 支持推送通知的更大系统中的一个组件。最受欢迎的源代码仓库提供商，如 GitHub、GitLab 和 Bitbucket，通过提供 WebHook 机制，能够发送有关仓库中变化的通知。我们可以通过提供商的网页控制台，以 URL 和选择的事件类型列表来配置 WebHook。这样的提供商将通过调用 WebHook 中定义的`POST`方法，发送包含提交列表的正文。在 Config Server 端启用监控端点需要在项目中包含 Spring Cloud Bus 依赖。当由于 WebHook 的激活而调用此端点时，Config Server 会准备并发送一个事件，其中包含由最后提交修改的属性源列表。该事件被发送到消息代理。Spring Cloud Bus 为 RabbitMQ 和 Apache Kafka 提供了实现。第一个可以通过包含`spring-cloud-starter-bus-amqp`依赖项启用于项目，第二个可以通过包含`spring-cloud-starter-bus-kafka`依赖项启用于项目。这些依赖项还应该在客户端应用程序中声明，以使能够从消息代理接收消息。我们还可以通过在选择的配置类上使用`@RefreshScope`注解来启用客户端端的动态刷新机制。该解决方案的架构示例如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f0318c08-6af4-40fc-a44a-e1b8885e6a01.png)

# 使用@RefreshScope 刷新配置

这次我们将从客户端端开始，这很不寻常。示例应用程序可以在 GitHub 上找到([`github.com/piomin/sample-spring-cloud-config-bus.git`](https://github.com/piomin/sample-spring-cloud-config-bus.git))。与之前的示例一样，它使用 Git 仓库作为后端存储，该仓库也是在大 GitHub 上创建的([`github.com/piomin/sample-spring-cloud-config-repo`](https://github.com/piomin/sample-spring-cloud-config-repo))。我在客户端的配置文件中添加了一些新属性，并将更改提交到仓库。以下是客户端当前配置的版本：

```java
eureka:
 instance:
   metadataMap:
     zone: zone1
 client:
   serviceUrl:
     defaultZone: http://localhost:8761/eureka/
server: 
 port: ${PORT:8081}
management:
 security:
   enabled: false 
sample:
 string:
   property: Client App
 int:
   property: 1
```

通过将`management.security.enabled`设置为`false`，我禁用了 Spring Boot Actuator 端点的 Security。这样我们就可以调用这些端点，而无需传递安全凭据。我还添加了两个测试参数，`sample.string.property`和`sample.int.property`，以演示基于它们值的重试机制在示例中。Spring Cloud 为 Spring Boot Actuator 提供了一些额外的 HTTP 管理端点。其中之一是`/refresh`，它负责重新加载引导上下文和刷新注解为`@RefreshScope`的 bean。这是一个 HTTP `POST`方法，可以在`http://localhost:8081/refresh`的客户端实例上调用。在测试该功能之前，我们需要使发现和 Config Servers 运行。客户端应用程序应该使用`--spring.profiles.active=zone1`参数启动。下面是测试属性`sample.string.property`和`sample.int.property`被注入到字段中的类：

```java
@Component
@RefreshScope
public class ClientConfiguration {

 @Value("${sample.string.property}")
 private String sampleStringProperty;
 @Value("${sample.int.property}")
 private int sampleIntProperty; 

 public String showProperties() {
   return String.format("Hello from %s %d", sampleStringProperty, sampleIntProperty);
 }

}
```

这个 bean 被注入到`ClientController`类中，并在`ping`方法中调用，该方法在`http://localhost:8081/ping`上暴露：

```java
@RestController
public class ClientController {

 @Autowired
 private ClientConfiguration conf; 

 @GetMapping("/ping")
 public String ping() {
     return conf.showProperties();
 } 

}
```

现在，让我们更改`client-service-zone1.yml`中的测试属性值并提交它们。如果你调用 Config Server HTTP 端点`/client-service/zone1`，你将看到最新的值作为响应返回。但是，当你调用客户端应用程序上暴露的`/ping`方法时，你仍然会看到以下屏幕左侧显示的较旧值。为什么？尽管 Config Server 可以自动检测仓库更改，但客户端应用程序没有触发器是无法自动刷新的。它需要重启以读取最新的设置，或者我们可以通过调用前面描述的`/refresh`方法强制重新加载配置：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/49a8d206-7a6b-4477-8b85-40b5427c13f9.png)

在客户端应用程序上调用`/refresh`端点后，你将在日志文件中看到配置已重新加载。现在，如果你再调用一次`/ping`，最新的属性值将返回在响应中。这个例子说明了 Spring Cloud 应用程序的热重载是如何工作的，但它显然不是我们的目标解决方案。下一步是启用与消息代理的通信：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/7c79dd98-0c3d-45ae-a736-678d2cec1cb1.png)

# 从消息代理中消费事件

我已经提到，我们可以选择两种与 Spring Cloud Bus 集成的消息代理。在这个例子中，我将向你展示如何运行和使用 RabbitMQ。让我简单说一下这个解决方案，因为这是我们书中第一次接触到它。RabbitMQ 已经成为最受欢迎的消息代理软件。它用 Erlang 编写，实现了**高级消息队列协议** (**AMQP**)。即使我们谈论的是如集群或高可用性这样的机制，它也易于使用和配置。

在您的机器上运行 RabbitMQ 最方便的方式是通过一个 Docker 容器。有两个端口已经暴露在容器外。第一个用于客户端连接（`5672`）第二个专用于管理仪表板（`15672`）。我还用管理标签运行了镜像以启用 UI 仪表板，这在默认版本中是不可用的：

```java
docker run -d --name rabbit -p 5672:5672 -p 15672:15672 rabbitmq:management
```

为了支持我们的示例客户端应用程序的 RabbitMQ 代理，我们应该在`pom.xml`中包含以下依赖项：

```java
 <dependency>
     <groupId>org.springframework.cloud</groupId>
     <artifactId>spring-cloud-starter-bus-amqp</artifactId>
 </dependency>
```

那个库包含了自动配置设置。因为我是在 Windows 上运行 Docker，所以我需要覆盖一些默认属性。完整的服务配置存储在一个 Git 仓库中，所以更改只影响远程文件。我们应该在之前使用的客户端属性源中添加以下参数：

```java
spring:
 rabbitmq:
   host: 192.168.99.100
   port: 5672
   username: guest
   password: guest
```

如果你运行客户端应用程序，RabbitMQ 会自动创建一个交换区和一个队列。你可以通过登录到位于`http://192.168.99.100:15672`的管理仪表板轻松查看这一点。默认的用户名和密码是`guest/guest`。以下是来自我 RabbitMQ 实例的屏幕截图。有一个名为`SpringCloudBus`的交换区被创建，与客户端队列和 Config Server 队列有两个绑定（我已经运行了下一节描述的更改）。在这个阶段，我不想深入了解 RabbitMQ 及其架构的细节。这样的讨论的好地方将是 Spring Cloud Stream 项目的第十一章，*消息驱动的微服务*：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/c29e1292-6fa9-412f-812f-c60bb2ab2033.png)

# 监控 Config Server 上的仓库更改

Spring Cloud Config Server 在前面描述的过程中必须执行两项任务。首先，它必须检测存储在 Git 仓库中的`property`文件的变化。这可能通过暴露一个特殊的端点来实现，该端点将通过 WebHook 由仓库提供商调用。第二步是准备并向可能已更改的应用程序发送一个`RefreshRemoteApplicationEvent`。这需要我们建立与消息代理的连接。`spring-cloud-config-monitor`库负责启用`/monitor`端点。为了支持 RabbitMQ 代理，我们应该包含与客户端应用程序相同的启动工件：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-config-monitor</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-bus-amqp</artifactId>
</dependency>
```

不仅如此。配置监视器还应在`application.yml`中激活。因为每个仓库提供商在 Spring Cloud 中都有专门的实现，所以有必要选择哪个应该被启用：

```java
spring:
 application:
   name: config-server
 cloud:
   config:
     server:
       monitor:
         github:
           enabled: true
```

更改检测机制可以自定义。默认情况下，它检测与应用程序名称匹配的文件中的更改。要覆盖此行为，你需要提供一个自定义的`PropertyPathNotificationExtractor`实现。它接受请求头和正文参数，并返回一个已更改的文件路径列表。为了支持来自 GitHub 的通知，我们可以使用`spring-cloud-config-monitor`提供的`GithubPropertyPathNotificationExtractor`：

```java
@Bean
public GithubPropertyPathNotificationExtractor githubPropertyPathNotificationExtractor() {
    return new GithubPropertyPathNotificationExtractor();
}
```

# 手动模拟更改事件

监控端点可以通过配置在 Git 仓库提供商（如 GitHub、Bitbucket 或 GitLab）上的 WebHook 来调用。在本地主机上运行的应用程序测试这种功能是麻烦的。结果是我们可以通过手动调用`POST /monitor`来轻松模拟这种 WebHook 的激活。例如，`Github`命令应该在请求中包含`X-Github-Event`头。带有`property`文件中更改的 JSON 体应该如下所示：

```java
$ curl -H "X-Github-Event: push" -H "Content-Type: application/json" -X POST -d '{"commits": [{"modified": ["client-service-zone1.yml"]}]}' http://localhost:8889/monitor
```

现在，让我们更改并提交`client-service-zone1.yml`文件中的一个属性值，例如`sample.int.property`。然后，我们可以使用前一个示例命令中显示的参数调用`POST /monitor`方法。如果你根据我的描述配置了所有内容，你应该在客户端应用程序侧看到以下日志行`Received remote refresh request. Keys refreshed [sample.int.property]`。如果你调用客户端微服务暴露的`/ping`端点，它应该返回更改属性的最新值。

# 使用 GitLab 实例在本地测试

对于那些不喜欢模拟事件的人来说，我提出一个更实用的练习。然而，我要指出这不仅需要你的开发技能，还需要对持续集成工具的基本了解。我们将从使用 GitLab 的 Docker 镜像在本地运行一个 GitLab 实例开始。GitLab 是一个开源的基于 Web 的 Git 仓库管理器，具有 wiki 和问题跟踪功能。它与 GitHub 或 Bitbucket 等工具非常相似，但可以轻松部署在你的本地机器上：

```java
docker run -d --name gitlab -p 10443:443 -p 10080:80 -p 10022:22 gitlab/gitlab-ce:latest
```

网页仪表板可在`http://192.168.99.100:10080`访问。第一步是创建一个管理员用户，然后使用提供的凭据登录。我不会详细介绍 GitLab。它有一个用户友好且直观的图形界面，所以我确信您不需要花费太多努力就能掌握它。无论如何，继续前进，我在 GitLab 中创建了一个名为`sample-spring-cloud-config-repo`的项目。它可以从`http://192.168.99.100:10080/root/sample-spring-cloud-config-repo.git`克隆。我在那里提交了与 GitHub 上我们的示例存储库中相同的配置文件集。下一步是定义一个 WebHook，当有推送通知时调用 Config Server 的`/monitor`端点。要为项目添加新的 WebHook，您需要前往设置 | 集成部分，然后将 URL 字段填写为服务器地址（使用您的 hostname 而不是 localhost 代替）。保留推送事件复选框的选择：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d7c24aea-9d7a-45ed-b69f-b6aa818239d7.png)

与使用 GitHub 作为后端存储提供商的 Config Server 实现相比，我们需要在`application.yml`中更改启用的监控类型，当然也要提供不同的地址：

```java
spring:
 application:
   name: config-server
 cloud:
   config:
     server:
       monitor:
         gitlab:
           enabled: true
       git:
         uri: http://192.168.99.100:10080/root/sample-spring-cloud-config-repo.git
         username: root
         password: root123
         cloneOnStart: true 
```

我们还应该注册另一个实现`PropertyPathNotificationExtractor`的 bean：

```java
@Bean
public GitlabPropertyPathNotificationExtractor gitlabPropertyPathNotificationExtractor() {
    return new GitlabPropertyPathNotificationExtractor();
}
```

最后，您可能需要在配置文件中做一些更改并推送它们。WebHook 应该被激活，客户端应用程序的配置应该被刷新。这是本章的最后一个例子；我们可以继续到结论。

# 摘要

在本章中，我描述了 Spring Cloud Config 项目的最重要特性。与服务发现一样，我们从基础开始，讨论了客户端和服务器端的简单用例。我们探讨了 Config Server 的不同后端存储类型。我实现了示例，说明了如何使用文件系统、Git，甚至第三方工具如 Vault 作为`property`文件的存储库。我特别关注与其他组件的互操作性，如服务发现或大型系统中的多个微服务实例。最后，我向您展示了如何基于 WebHooks 和消息代理无需重新启动应用程序来重新加载配置。总之，阅读本章后，您应该能够将 Spring Cloud Config 作为微服务架构的一个组成部分使用，并利用其主要特性。

在讨论了使用 Spring Cloud 的服务发现和配置服务器实现之后，我们可以继续研究服务间的通信。在接下来的两章中，我们将分析一些基本和更高级的示例，这些示例说明了几个微服务之间的同步通信。
