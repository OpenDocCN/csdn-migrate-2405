# SpringBoot 和 SpringCloud 微服务实用指南（一）

> 原文：[`zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52`](https://zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书介绍了使用 Spring Boot 和 Spring Cloud 构建生产就绪的微服务。五年前，当我开始探索微服务时，我一直在寻找这样的书。

在我学会并精通用于开发、测试、部署和管理协作微服务生态的开源软件之后，这本书才得以编写。

本书主要涵盖了 Spring Boot、Spring Cloud、Docker、Kubernetes、Istio、EFK 堆栈、Prometheus 和 Grafana。这些开源工具各自都很好用，但理解如何将它们以有利的方式结合起来可能会有挑战性。在某些领域，它们相互补充，但在其他领域，它们重叠，对于特定情况选择哪一个并不明显。

这是一本实用书籍，详细介绍了如何逐步使用这些开源工具。五年前，当我开始学习微服务时，我一直在寻找这样的书籍，但现在它涵盖了这些开源工具的最新版本。

# 本书面向人群

这本书面向希望学习如何将现有单体拆分为微服务并在本地或云端部署的 Java 和 Spring 开发者及架构师，使用 Kubernetes 作为容器编排器，Istio 作为服务网格。无需对微服务架构有任何了解即可开始本书的学习。

# 为了最大化本书的收益

需要对 Java 8 有深入了解，以及对 Spring Framework 有基本知识。此外，对分布式系统的挑战有一个大致的了解，以及对在生产环境中运行自己代码的一些经验，也将有益于学习。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)您的账户上下载本书的示例代码文件。如果您在其他地方购买了此书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书籍名称，然后按照屏幕上的指示操作。

文件下载完成后，请确保使用最新版本解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud)。如有代码更新，它将在现有的 GitHub 仓库中更新。

我们还有其他丰富的书籍和视频目录中的代码包，托管在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。去看看它们！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含了本书中使用的屏幕截图/图表的颜色图像。您可以通过以下链接下载： [`static.packt-cdn.com/downloads/9781789613476_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789613476_ColorImages.pdf)。

# 代码在行动

若要查看代码的执行情况，请访问以下链接： [`bit.ly/2kn7mSp`](http://bit.ly/2kn7mSp)。

# 本书中使用了一些约定。

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词，数据库表名，文件夹名，文件名，文件扩展名，路径名，假 URL，用户输入和 Twitter 处理。这是一个示例："要使用本地文件系统，配置服务器需要启动带有 Spring 配置文件`native`的特性"。

代码块如下所示：

```java
management.endpoint.health.show-details: "ALWAYS"
management.endpoints.web.exposure.include: "*"

logging.level.root: info
```

当我们希望引起你对代码块中的某个特定部分的关注时，相关的行或项目会被设置为粗体：

```java
   backend:
    serviceName: auth-server
    servicePort: 80
 - path: /product-composite
```

任何命令行输入或输出都会如下书写：

```java
brew install kubectl
```

**粗体**：表示一个新术语，一个重要的单词，或者你在屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中像这样出现。这是一个示例："正如前一个屏幕截图所示，Chrome 报告：此证书有效！"

警告或重要注释会像这样出现。

提示和技巧会像这样出现。

# 联系我们

读者反馈始终受欢迎。

**一般反馈**：如果你对本书的任何方面有疑问，请在消息的主题中提到书名，并通过 `customercare@packtpub.com` 向我们发送电子邮件。

**勘误**：虽然我们已经尽一切努力确保我们的内容的准确性，但是错误确实存在。如果您在这本书中发现了错误，我们将非常感激如果您能向我们报告。请访问 [www.packtpub.com/support/errata](https://www.packtpub.com/support/errata)，选择您的书籍，点击勘误表单链接，并输入详细信息。

**盗版**：如果您在互联网上以任何形式遇到我们作品的非法副本，我们将非常感激如果您能提供其位置地址或网站名称。请通过 `copyright@packt.com` 与我们联系，并附上材料的链接。

**如果你想成为作者**：如果你对你的某个主题有专业知识，并且你想写书或者为某个书做贡献，请访问 [authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。一旦您阅读并使用了这本书，为什么不在这本书购买的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决策，我们 Pactt 出版社可以了解您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

关于 Pactt 出版社的更多信息，请访问 [packt.com](http://www.packt.com/)。


# 第一部分：使用 Spring Boot 开始微服务开发

在本节中，你将学习如何使用 Spring Boot 的一些最重要的特性来开发微服务。

本节包括以下章节：

+   第一章，*微服务简介*

+   第二章，*Spring Boot 简介*

+   第三章，*创建一组协作的微服务*

+   第四章，*使用 Docker 部署我们的微服务*

+   第五章，*使用 OpenAPI/Swagger 添加 API 描述*

+   第六章，*添加持久化*

+   第七章，*开发响应式微服务*


# 第一章：微服务简介

本书并非盲目地赞美微服务。相反，它关于我们如何能够利用它们的好处，同时能够处理构建可扩展、有弹性和可管理的微服务的挑战。

作为本书的引言，本章将涵盖以下内容：

+   我如何了解微服务以及我对它们的好处和挑战的经验

+   微服务基础架构是什么？

+   微服务的挑战

+   处理挑战的设计模式

+   可以帮助我们处理这些挑战的软件促进者

+   本书未涵盖的其他重要考虑因素

# 技术要求

本章无需安装。不过，您可能想查看 C4 模型约定，[`c4model.com`](https://c4model.com)，因为本章的插图灵感来自于 C4 模型。

本章不包含任何源代码。

# 我进入微服务的方式

当我第一次在 2014 年了解微服务概念时，我意识到我在开发微服务（好吧，有点）已经好几年了，却不知道自己处理的微服务。我参与了一个始于 2009 年的项目，我们基于一系列分离的功能开发了一个平台。该平台被部署在多个客户的本地服务器上。为了使客户能够轻松选择他们想要从平台中使用的功能，每个功能都是作为**自主软件组件**开发的；也就是说，它有自己的持久数据，并且只使用定义良好的 API 与其他组件通信。

由于我无法讨论这个平台项目的特定功能，我将组件的名称进行了泛化，从**组件 A** 到 **组件 F** 进行标记。平台组成一组组件的如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a28adfee-5ac7-4006-8bc9-ca0bd3ce0688.png)

每个组件都是使用 Java 和 Spring Framework 开发的，打包成 WAR 文件，并在 Java EE 网络容器中（例如，Apache Tomcat）部署为 Web 应用程序。根据客户的具体要求，平台可以在单台或多台服务器上部署。双节点部署可能如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/e608abe5-c594-4079-8523-6f56e88ae3b3.png)

# 自主软件组件的好处

将平台的 functionality 分解为一系列自主软件组件提供了许多好处：

+   客户可以在自己的系统景观中部署平台的某些部分，使用其定义良好的 API 将其与现有系统集成。

    以下是一个示例，其中一个客户决定部署平台中的**组件 A**，**组件 B**，**组件 D** 和 **组件 E**，并将它们与客户系统景观中的两个现有系统**系统 A** 和 **系统 B** 集成：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/d9c37999-c0e3-4121-9cf8-0fbc0053acc1.png)

+   另一客户可以选择用其在客户系统景观中已存在的实现替换平台的部分功能，这可能会需要对平台 API 中现有的功能进行一些采用。以下是一个客户用其自己的实现替换了平台中的**组件 C**和**组件 F**的示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ec70e06b-72fc-4582-8598-23b2be9da9b2.png)

+   平台中的每个组件都可以单独交付和升级。由于使用了定义良好的 API，一个组件可以升级到新版本，而无需依赖于其他组件的生命周期。

    以下是一个示例，其中**组件 A**从版本**v1.1**升级到了**v1.2**。由于它使用了定义良好的 API 调用**组件 A**的**组件 B**，在升级后不需要更改（或者至少是向后兼容的）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a8e582ba-86f5-4a7a-9549-b74de17dc705.png)

+   由于使用了定义良好的 API，平台中的每个组件也可以独立于其他组件扩展到多台服务器。扩展可以是为了满足高可用性要求或处理更高数量的请求。技术上，这是通过*手动*在运行 Java EE Web 容器的几台服务器前设置负载均衡器来实现的。一个**组件 A**扩展到三个实例的示例如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/693e8127-e343-4ea8-94fa-14488f1a1673.png)

# 自主软件组件的挑战

我们还发现，将平台分解成多个部分引入了许多新的挑战，我们在开发更传统、单片应用程序时并没有暴露（至少没有暴露到同样的程度）到这些挑战：

+   向组件添加新实例需要手动配置负载均衡器并手动设置新节点。这项工作既耗时又易出错。

+   平台最初容易在与它通信的其他系统出现错误。如果一个系统没有及时响应从平台发送的请求，平台很快就会耗尽关键资源，例如，操作系统线程，特别是当暴露于大量并发请求时。这会导致平台中的组件挂起甚至崩溃。由于平台中的大多数通信基于同步通信，一个组件的崩溃可能会导致级联故障；也就是说，崩溃组件的客户端也可能在一段时间后崩溃。这被称为**故障链**。

+   保持组件所有实例中的配置一致并更新迅速成为一个问题，导致大量手动和重复工作。这导致时不时会出现质量问题。

+   与监控单体应用程序单个实例的状态（例如，CPU、内存、磁盘和网络的使用情况）相比，监控平台在延迟问题和硬件使用方面的状态更为复杂。

+   从多个分布式组件中收集日志文件并关联组件相关的日志事件是困难的，但可行的，因为组件的数量是固定的，且事先已知。

随着时间的推移，我们通过开发内部工具和处理这些挑战的良好文档说明，解决了前述列表中提到的绝大多数挑战。操作规模通常在一个级别，在该级别上，手动程序对于发布新版本的组件和处理运行时问题是可接受的，尽管这不是理想的。

# 进入微服务

2014 年了解微服务架构让我意识到其他项目也面临过类似的挑战（部分原因是除了我之前描述的原因之外，例如，大型云服务提供商满足网络规模要求）。许多微服务先驱发表了他们学到的课程细节。从这些教训中学习非常有意思。

许多先驱者最初开发了单体应用，这在商业上使他们非常成功。但随着时间的推移，这些单体应用变得越来越难以维护和进化。它们也挑战性地超出了最大机器的容量（也称为垂直扩展）。最终，先驱们开始寻找将单体应用拆分为更小组件的方法，这些组件可以独立于彼此进行发布和扩展。可以通过水平扩展来扩展小组件，即在多个小型服务器上部署一个组件并在其前面放置一个负载均衡器。如果在云环境中进行，扩展能力是潜在无限的——这只是一个你引入多少虚拟服务器的问题（假设你的组件可以在大量实例上扩展，但稍后再详细介绍）。

2014 年，我还了解了许多新的开源项目，这些项目提供了工具和框架，简化了微服务的开发，并可用于处理基于微服务架构的挑战。其中一些如下：

+   Pivotal 发布了**Spring Cloud**，该框架封装了**Netflix OSS**的部分内容，以提供动态服务发现、配置管理、分布式跟踪、断路器等功能。

+   我还了解到了**Docker** 和容器革命，这对于缩小开发和生产之间的差距非常有益。能够将一个组件包装为一个可部署的运行时工件（例如，一个 Java、`war` 或者 `jar` 文件），也可以作为一个完整的镜像在运行 Docker 的服务器上启动（例如，一个隔离的进程），这对开发和测试来说是一个巨大的进步。

+   一个容器引擎，比如 Docker，不足以在生产环境中使用容器。需要的东西例如能确保所有容器都运行正常，以及能在多台服务器上扩展容器，从而提供高可用性和/或增加计算资源。这类产品被称为**容器编排器**。过去几年中，出现了一系列产品，例如 Apache Mesos、Docker 的 Swarm 模式、亚马逊 ECS、HashiCorp Nomad 和 **Kubernetes**。Kubernetes 最初由谷歌开发。当谷歌发布 v1.0 版本时，他们还把 Kubernetes 捐赠给了 CNCF（[`www.cncf.io/`](https://www.cncf.io/)）。在 2018 年，Kubernetes 成为了一种事实上的标准，既可以预先打包用于本地部署，也可以从大多数主要云服务提供商那里作为服务提供。

+   我最近开始学习关于**服务网格** 的概念以及服务网格如何补充容器编排器，进一步卸载微服务的职责，使它们变得可管理和有弹性。

# 微服务示例架构

由于这本书不能涵盖我刚才提到的所有技术方面，我将重点介绍自 2014 年以来我参与的客户项目中证明有用的部分。我将描述它们如何一起使用，以创建可管理、可扩展和有弹性的协作微服务。

本书的每一章都将关注一个特定的问题。为了演示事物是如何整合在一起的，我将使用一组协作的微服务，我们将在本书中逐步完善它们：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/bd28199a-e796-4dd9-aaf1-ae322a726f93.png)

既然我们已经了解了微服务的如何和什么，让我们开始探讨如何定义一个微服务。

# 定义微服务

对我来说，微服务架构是关于将单体应用程序拆分成更小的组件，这实现了两个主要目标：

+   加快开发，实现持续部署

+   更容易扩展，手动或自动

微服务本质上是一个可以独立升级和扩展的自主软件组件。为了能够作为一个自主组件行动，它必须满足以下某些标准：

+   它必须遵循一种无共享架构；也就是说，微服务之间不会在数据库中共享数据！

+   它必须仅通过定义良好的接口进行通信，例如，使用同步服务，或者更 preferably，通过使用 API 和稳定的、文档齐全的消息格式彼此发送消息，并且这些消息格式遵循一个定义好的版本策略来发展。

+   它必须作为独立的运行时进程部署。每个微服务的实例运行在一个单独的运行时进程中，例如，一个 Docker 容器。

+   微服务实例是无状态的，这样对微服务的传入请求可以由其任何一个实例处理。

使用一组微服务，我们可以将部署到多个较小的服务器上，而不是被迫将部署到一个大的单体服务器上，正如我们在部署单体应用时必须做的那样。

考虑到前面提到的条件已经满足，相较于将一个大的单体应用进行扩展，将一个微服务扩展到更多的实例（例如，使用更多的虚拟服务器）会更加容易。利用云服务中可用的自动扩展功能也是一种可能性，但对于一个大的单体应用来说，通常并不可行。与升级一个大的单体应用相比，升级或替换一个微服务也更为容易。

这一点可以通过以下图表来说明，其中一个大单体应用被划分为六个微服务，它们都被部署到一个单独的服务器上。其中一些微服务还独立于其他服务进行了扩展：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ee5160d1-409d-419e-9a56-489a4e8aa3a9.png)

我经常从客户那里收到的一个问题是，“**微服务应该有多大？**”

我试图使用以下经验法则：

+   足够小，以至于能够装进开发者的头脑中

+   足够小，不会影响性能（即，延迟）和/或数据一致性（存储在不同微服务中的数据之间的 SQL 外键不再是你可以轻易假设的东西）。

所以，总结一下，微服务架构本质上是这样一种架构风格：我们将一个单体应用分解为一组协作的自主软件组件。动机是为了实现更快的开发，并使应用的扩展变得更容易。

接下来，我们将转向了解在微服务方面我们将面临的一些挑战。

# 服务发现

**服务发现**模式有以下问题、解决方案和解决方案要求。

# 微服务的挑战

在“**自主软件组件的挑战**”一节中，我们已经看到了一些自主软件组件可能会带来的挑战（它们都适用于微服务），如下所示：

+   许多使用同步通信的小组件可能会导致*连锁故障*问题，尤其是在高负载下。

+   对于许多小组件保持配置的最新状态可能会很有挑战性。

+   跟踪正在处理并涉及许多组件的请求可能很困难，例如，在执行根本原因分析时，每个组件都本地存储日志事件。

+   分析组件级别硬件资源的使用也可能具有挑战性。

+   手动配置和管理许多小型组件可能会变得昂贵且容易出错。

将应用程序分解为一组自主组件的另一个缺点（但通常一开始并不明显）是，它们形成了一个分布式系统。分布式系统以其本质而言，很难处理。这一点已经知道很多年了（但在许多情况下直到证明否则才被忽视）。我用来证明这个事实的最喜欢引语来自彼得·德意志，他在 1994 年提出了以下观点：

***分布式计算的 8 大谬误***：基本上每个人在第一次构建分布式应用程序时都会做出以下八个假设。所有这些最终都被证明是错误的，并且都会造成巨大的麻烦和痛苦的学习经验：*

1.  *网络是可靠的*

1.  *延迟为零*

1.  *带宽是无限的*

1.  *网络是安全的*

1.  *拓扑不会改变*

1.  *有一个管理员*

1.  *传输成本为零*

1.  *网络是同质的*

*-- 彼得·德意志，1994*

**注：**第八个谬误实际上是由詹姆斯·高斯林在后来添加的。更多信息，请访问[`www.rgoarchitects.com/Files/fallacies.pdf`](https://www.rgoarchitects.com/Files/fallacies.pdf)。

一般来说，基于这些错误假设构建微服务会导致解决方案容易出现临时网络故障和其他微服务实例中的问题。当系统景观中的微服务数量增加时，问题的可能性也会上升。一个好的经验法则是，设计你的微服务架构时，假设系统景观中总是有一些东西在出错。微服务架构需要处理这一点，包括检测问题和重新启动失败组件，以及在客户端方面，以便请求不会发送到失败的微服务实例。当问题得到解决时，应恢复对之前失败的微服务的请求；也就是说，微服务客户端需要具有弹性。所有这些当然都需要完全自动化。对于大量的微服务，操作员手动处理这是不可能的！

这个范围很大，但我们将暂时限制自己，并继续研究微服务的设计模式。

# 微服务的设计模式

本节将介绍使用设计模式减轻微服务挑战的方法。在这本书的后面，我们将看到我们如何使用 Spring Boot、Spring Cloud 和 Kubernetes 实现这些设计模式。

设计模式的概念实际上相当古老；它是在 1977 年由克里斯托弗·亚历山大发明的。本质上，设计模式是关于在给定特定上下文时描述一个问题的可重用解决方案。

我们将涵盖的设计模式如下：

+   服务发现

+   边缘服务器

+   响应式微服务

+   集中式配置

+   集中式日志分析

+   分布式追踪

+   熔断器

+   控制循环

+   集中式监控和警报

此列表并非旨在全面，而是我们之前描述的挑战所需的最小设计模式列表。

我们将采用一种轻量级的方法来描述设计模式，并关注以下内容：

+   问题

+   解决方案

+   解决方案要求

在本书的后面部分，我们将更深入地探讨如何应用这些设计模式。这些设计模式的上下文是一个由合作的微服务组成的系统架构，微服务通过同步请求（例如，使用 HTTP）或发送异步消息（例如，使用消息代理）相互通信。

# 问题

客户端如何找到微服务和它们的实例？

微服务实例在启动时通常会被分配动态分配的 IP 地址，例如，当它们在容器中运行时。这使得客户端难以向微服务发起请求，例如，向暴露 HTTP 上的 REST API 的微服务发起请求。请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ae0b2dda-3e2d-4028-b48b-cff12017468e.png)

# 解决方案

在系统架构中添加一个新组件——**服务发现**服务——跟踪当前可用的微服务和其实例的 IP 地址。

# 解决方案要求

一些解决方案要求如下：

+   自动注册/注销微服务和它们的实例，因为它们来来去去。

+   客户端必须能够向微服务的逻辑端点发起请求。请求将被路由到可用的微服务实例之一。

+   对微服务的请求必须在可用实例上进行负载均衡。

+   我们必须能够检测到当前不健康的实例；也就是说，请求不会被路由到这些实例。

**实现说明：** 正如我们将看到的，这个设计模式可以使用两种不同的策略来实现：

+   **客户端路由**：客户端使用与服务发现服务通信的库，以找出要发送请求的正确实例。

+   **服务器端路由**：服务发现服务的架构还暴露了一个反向代理，所有请求都发送到该代理。反向代理代表客户端将请求转发到适当的微服务实例。

# 边缘服务器

边缘服务器模式有以下问题、解决方案和解决方案要求。

# 问题

在微服务系统架构中，许多情况下，希望将一些微服务暴露给系统架构的外部，并将其余的微服务隐藏在外部访问之外。必须保护暴露的微服务免受恶意客户端的请求。

# 解决方案

向系统架构中添加一个新组件，即**边缘服务器**，所有传入请求都将通过它：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ae4561e4-4945-4613-9385-0f1bf1719981.png)

实现说明：边缘服务器通常表现得像反向代理，可以与发现服务集成，提供动态负载均衡功能。

# 解决方案要求

一些解决方案要求如下：

+   隐藏不应暴露在外部上下文中的内部服务；也就是说，只将请求路由到配置为允许外部请求的微服务。

+   暴露外部服务并保护它们免受恶意请求；也就是说，使用标准协议和最佳实践，如 OAuth、OIDC、JWT 令牌和 API 密钥，确保客户端是可信的。

# 反应式微服务

反应式微服务模式有以下问题、解决方案和解决方案要求。

# 问题

传统上，作为 Java 开发者，我们习惯于使用阻塞 I/O 实现同步通信，例如，通过 HTTP 实现的 RESTful JSON API。使用阻塞 I/O 意味着操作系统会为请求的长度分配一个线程。如果并发请求的数量增加（以及/或者请求中涉及的组件数量增加，例如，一系列协作的微服务），服务器可能会在操作系统中耗尽可用的线程，导致问题从更长的响应时间到服务器崩溃。

此外，正如我们在本章中已经提到的，过度使用阻塞 I/O 会使微服务系统容易出现错误。例如，一个服务的延迟增加可能会导致客户端耗尽可用的线程，从而导致它们失败。这反过来又可能导致它们的客户端出现相同类型的问题，这也被称为故障链。请参阅*断路器*部分，了解如何处理与故障链相关的问题。

# 解决方案

使用非阻塞 I/O，确保在等待另一个服务（例如，数据库或另一个微服务）处理时不会分配线程。

# 解决方案要求

一些解决方案要求如下：

+   只要可行，使用异步编程模型；也就是说，发送消息而不等待接收者处理它们。

+   如果偏好同步编程模型，确保使用反应式框架，这些框架可以使用非阻塞 I/O 执行同步请求，即在等待响应时不会分配线程。这将使微服务更容易扩展以处理增加的工作负载。

+   微服务还必须设计成有恢复力，也就是说，能够产生响应，即使它依赖的服务失败了。一旦失败的服务恢复正常运营，它的客户端必须能够继续使用它，这被称为自愈。

在 2013 年，设计这些方式的关键原则在*《反应式宣言》*中得到了确立（[`www.reactivemanifesto.org/`](https://www.reactivemanifesto.org/)）。根据宣言，反应式系统的基石是它们是消息驱动的；也就是说，它们使用异步通信。这使得它们能够是弹性的，也就是说，可伸缩的，并且有恢复力，也就是说，能够容忍失败。弹性和恢复力共同使得一个反应式系统能够是有响应性的，这样它能够及时做出反应。

# 集中配置

集中配置模式有以下问题、解决方案和解决方案要求。

# 问题

一个应用程序，传统上，是与它的配置一起部署的，例如，一组环境变量和/或包含配置信息的文件。考虑到一个基于微服务架构的系统景观，也就是有大量部署的微服务实例，会有一些查询产生：

+   我如何获得所有运行中的微服务实例中现行的配置的完整视图？

+   我如何更新配置并确保所有受影响的微服务实例都被正确更新？

# 解决方案

在系统景观中添加一个新的组件，一个**配置**服务器，以存储所有微服务的配置。

# 解决方案要求

使存储一组微服务的配置信息成为可能，在同一个地方有不同的设置针对不同的环境（例如，`dev`、`test`、`qa`和`prod`）。

# 集中日志分析

集中日志分析有以下问题、解决方案和解决方案要求。

# 问题

传统上，一个应用程序会将日志事件写入存储在运行应用程序的本机机器上的日志文件中。考虑到一个基于微服务架构的系统景观，也就是有大量部署在众多小型服务器上的微服务实例，我们可以提出以下问题：

+   我如何获得系统景观的概览，当每个微服务实例向自己的本地日志文件中写入时，系统景观中发生了什么？

+   我如何找出是否有任何微服务实例遇到麻烦并开始向它们的日志文件中写入错误消息？

+   如果最终用户开始报告问题，我如何找到相关的日志消息；也就是说，我如何确定哪个微服务实例是问题的根源？以下图表说明了这个问题：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/12e455e5-f256-43f4-b593-7145f36401c7.png)

# 解决方案

添加一个新的组件，它可以管理**集中日志**，并能够执行以下操作：

+   检测新的微服务实例并从它们那里收集日志事件

+   在中心数据库中以结构化和可搜索的方式解释和存储日志事件

+   提供 API 和图形工具以查询和分析日志事件

# 分布式追踪

分布式追踪有以下问题、解决方案和解决方案要求。

# 问题

必须能够在处理系统景观的外部调用时跟踪微服务之间的请求和消息。

以下是一些故障场景的例子：

+   如果最终用户开始就特定的故障提起支持案例，我们如何确定导致问题的微服务，即根本原因？

+   如果一个支持案例提到了与特定实体相关的问题，例如，特定的订单号，我们如何找到与处理这个特定订单相关的日志消息——例如，参与处理这个特定订单的所有微服务的日志消息？

以下图表展示了这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a7e6182c-b5f4-4344-8e98-3e9f62aef421.png)

# 解决方案

为了跟踪合作微服务之间的处理过程，我们需要确保所有相关请求和消息都标记有一个共同的关联 ID，并且关联 ID 是所有日志事件的一部分。基于关联 ID，我们可以使用集中的日志服务找到所有相关的日志事件。如果其中一个日志事件还包括与业务相关的标识信息，例如客户、产品、订单等的 ID，我们可以使用关联 ID 找到与该业务标识所有相关的日志事件。

# 解决方案要求

解决方案要求如下：

+   为所有传入或新请求和事件分配唯一的关联 ID，例如，在一个有已知名称的头部中。

+   当一个微服务发出一个外部请求或发送一个消息时，它必须给请求和消息添加一个关联 ID。

+   所有日志事件必须以预定义的格式包括关联 ID，以便集中的日志服务可以从日志事件中提取关联 ID 并使其可搜索。

# 断路器模式

断路器模式将会有以下问题、解决方案和解决方案要求。

# 问题

使用同步交互的微服务系统景观可能会遭受*故障链*。如果一个微服务停止响应，它的客户端也可能遇到问题并且停止响应它们客户端的请求。问题可能会递归地在系统景观中传播，并使其大部分失效。

这尤其在同步请求使用阻塞 I/O 执行时非常常见，即阻塞来自底层操作系统的线程，当请求正在被处理。结合大量并发请求和服务开始意外地缓慢响应，线程池可能会迅速耗尽，导致调用者挂起和/或崩溃。这种失败会不愉快地迅速传播到调用者的调用者，等等。

# 解决方案

添加一个断路器，如果它检测到它调用的服务有问题，则阻止调用者发出新的外出请求。

# 解决方案要求

解决方案要求如下：

+   如果检测到服务问题，打开电路并快速失败（不等待超时）。

+   探针失败修复（也称为**半开电路**）；也就是说，定期让一个请求通过，以查看服务是否再次正常运行。

+   如果探针检测到服务再次正常运行，关闭电路。这种能力非常重要，因为它使系统景观对这些类型的问题具有弹性；也就是说，它具有自我修复能力。

以下图表展示了所有微服务系统景观中的同步通信都通过断路器的情景。所有断路器都是关闭的；也就是说，它们允许流量，除了一个断路器检测到请求所服务的有问题。因此，这个断路器是打开的，并使用快速失败逻辑；也就是说，它不调用失败的服务，等待超时发生。在下面，它会立即返回一个响应，在响应之前可选地应用一些回退逻辑：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/039f95d4-defe-4ecf-9ce1-71c78ed322ac.png)

# 控制循环

控制循环模式将有以下问题、解决方案和解决方案要求。

# 问题

在一个有大量微服务实例的系统景观中，这些实例分布在多个服务器上，手动检测和纠正崩溃或挂起的微服务实例等问题非常困难。

# 解决方案

向系统景观添加一个新组件，一个**控制循环**，这个组件不断观察系统景观的实际状态；将其与操作员指定的期望状态进行比较，如有必要，采取行动。例如，如果这两个状态不同，它需要使实际状态等于期望状态：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4716aa50-5154-4e6a-b6d2-32ae7728d640.png)

# 解决方案要求

实现说明：在容器的世界里，通常使用如 Kubernetes 之类的*容器编排器*来实现这个模式。我们将在第十五章，*Kubernetes 简介*中了解更多关于 Kubernetes 的内容。

# 集中监控和警报

对于这个模式，我们将有以下问题、解决方案和解决方案要求。

# 问题

如果观察到的响应时间和/或硬件资源的使用变得不可接受地高，找出问题的根本原因可能非常困难。例如，我们需要能够分析每个微服务的硬件资源消耗。

# 解决方案

为了解决这个问题，我们在系统景观中增加了一个新组件，一个**监控服务**，它能够收集每个微服务实例级别的硬件资源使用情况。

# 解决方案要求

解决方案要求如下：

+   它必须能够从系统景观中使用的所有服务器收集指标，包括自动扩展服务器。

+   它必须能够检测到在可用服务器上启动的新微服务实例，并开始从它们收集指标。

+   它必须能够为查询和分析收集的指标提供 API 和图形工具。

下面的屏幕截图显示了 Grafana，它可视化了来自我们稍后在本书中将介绍的监控工具 Prometheus 的指标：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/c19497ae-0184-4788-baed-9bc5a5f11993.png)

那是一个很长的列表！我相信这些设计模式帮助您更好地理解了微服务的挑战。接下来，我们将转向了解软件使能器。

# 软件使能器

正如我们前面已经提到的，我们有多种非常好的开源工具可以帮助我们满足对微服务的期望，最重要的是，它们可以帮助我们处理与它们相关的新的挑战：

+   Spring Boot

+   Spring Cloud/Netflix OSS

+   Docker

+   Kubernetes

+   Istio（服务网格）

下面的表格将我们需要处理这些挑战的设计模式以及实现该设计模式的相应开源工具进行了映射：

| 设计模式 | Spring Boot | Spring Cloud | Kubernetes | Istio |
| --- | --- | --- | --- | --- |
| 服务发现 | | Netflix Eureka 和 Netflix Ribbon | Kubernetes `kube-proxy` 和服务资源 | |
| 边缘服务器 | | Spring Cloud 和 Spring Security OAuth | Kubernetes Ingress 控制器 | Istio 入口网关 |
| 反应式微服务 | Spring Reactor 和 Spring WebFlux | | | |
| 集中式配置 | | Spring Config Server | Kubernetes `ConfigMaps` 和 Secrets | |

集中式日志分析 | | | Elasticsearch、Fluentd 和 Kibana **注意**：实际上不是 Kubernetes 的一部分

但是可以轻松地与 Kubernetes 一起部署和配置 | |

| 分布式追踪 | | Spring Cloud Sleuth 和 Zipkin | | Jaeger |
| --- | --- | --- | --- | --- |
| 电路 breaker | | Resilience4j | | 异常检测 |
| 控制循环 | | | Kubernetes 控制器管理器 | |

集中式监控和警报 | | | Grafana 和 Prometheus **注意**：实际上不是 Kubernetes 的一部分

但是可以轻松地与 Kubernetes 一起部署和配置 | Kiali、Grafana 和 Prometheus |

请注意，Spring Cloud、Kubernetes 和 Istio 可以用来实现一些设计模式，如服务发现、边缘服务器和集中配置。我们将在本书的后面讨论使用这些替代方案的优缺点。

现在，让我们看看其他一些我们需要考虑的重要事情。

# 其他重要考虑因素

实现微服务架构的成功，还需要考虑许多相关领域。我不会在这本书中涵盖这些领域；相反，我只是在这里简要提及如下：

+   **Dev/Ops 的重要性**：微服务架构的一个好处是，它能够缩短交付时间，在极端情况下甚至允许*持续交付*新版本。为了能够那么快地交付，你需要建立一个组织，在这个组织中，开发和运维人员共同工作，遵循“*你构建它，你运行它*”的宗旨。这意味着开发者不再被允许只是将软件的新版本交给运维团队。相反，开发和运维组织需要更紧密地一起工作，组成具有全面责任的一个微服务（或一组相关的微服务）的整个生命周期的团队。除了组织的`dev`/`ops`部分，团队还需要自动化交付链，即构建、测试、打包和将微服务部署到各种部署环境中的步骤。这被称为建立一个*交付管道*。

+   **组织方面和康威定律**：微服务架构可能如何影响组织的另一个有趣方面是*康威定律*，它陈述如下：

“任何设计系统（定义广泛）的组织都会产生一个其结构是该组织通信结构副本的设计。”

-- Melvyn Conway，1967

这意味着，基于技术专长（例如，UX、业务逻辑和数据库团队）来组织大型应用程序的传统方法会导致一个大的三层应用程序——通常是一个大的单体应用程序，其中有一个可独立部署的 UI 单元、一个处理业务逻辑的单元和一个大数据库。为了成功交付一个基于微服务架构的应用程序，组织需要变成一个或一组相关微服务的团队。这个团队必须拥有那些微服务所需的技能，例如，业务逻辑的语言和框架以及持久化其数据的数据库技术。

+   **将单体应用分解为微服务：**最困难和昂贵的决定之一是如何将单体应用分解为一组协作的微服务。如果这样做错了，你最终会面临如下问题：

    +   **交付缓慢：**业务需求的变化将影响太多的微服务，导致额外的工作。

    +   **性能缓慢：**为了能够执行特定的业务功能，许多请求必须在不同的微服务之间传递，导致响应时间长。

    +   **数据不一致性：**由于相关数据被分离到不同的微服务中，随着时间的推移，由不同微服务管理的数据可能会出现不一致。

寻找微服务适当边界的良好方法是应用**领域驱动设计**及其**边界上下文**概念。根据 Eric Evans 的说法，*边界上下文*是"*一个描述（通常是一个子系统，或特定团队的工作）的边界，在这个边界内定义了一个特定的模型并且适用。"*这意味着由边界上下文定义的微服务将拥有其自身数据的良好定义模型。

+   **API 设计的重要性：**如果一组微服务暴露了一个共同的、对外可用的 API，那么这个 API 必须是易于理解的，并且要符合以下要求：

    +   如果同一个概念在多个 API 中使用，那么在命名和数据类型方面应该有相同的描述。

    +   允许 API 以受控的方式进行演变是非常重要的。这通常需要为 API 应用适当的版本控制方案，例如，[`semver.org/`](https://semver.org/)，并有能力在特定时间段内处理 API 的多个主要版本，允许 API 的客户端按照自己的节奏迁移到新的主要版本。

+   **从本地部署到云的迁移路径：**如今，许多公司仍在本地运行其工作负载，但正在寻找将部分工作负载迁移到云的方法。由于大多数云服务提供商今天都提供 Kubernetes 作为服务，一个吸引人的迁移方法可以是首先将工作负载迁移到本地的 Kubernetes（作为微服务或不是），然后将其重新部署在首选云提供商提供的*Kubernetes 作为服务*上。

+   **微服务和 12 因子应用的良好设计原则：**12 因子应用（[`12factor.net`](https://12factor.net/)）是一组适用于构建可部署在云上的软件的设计原则。其中大多数设计原则适用于独立于部署位置（即云或本地）构建微服务，但并非全部。

第一章就到这里！希望这为您提供了微服务的好基本概念，并帮助您理解本书将涵盖的大规模主题。

# 总结

在这章开头，我描述了我自己对微服务的理解，并简要了解了它们的历史。我们定义了微服务是什么，即具有一些特定要求的一种自主分布式组件。我们还讨论了微服务架构的优点和挑战。

为了应对这些挑战，我们定义了一组设计模式，并简要地将开源产品如 Spring Boot、Spring Cloud 和 Kubernetes 的能力与它们进行了映射。

你现在迫不及待地想开发你的第一个微服务了吧？在下一章中，我们将介绍 Spring Boot 以及与之互补的开源工具，我们将使用它们来开发我们的第一个微服务。


# 第二章：介绍 Spring Boot

在本章中，我们将介绍如何使用 Spring Boot 构建一套协同工作的微服务，重点是如何开发具有业务价值的功能。我们在上一章中指出的挑战只会考虑一部分，但它们将在后面的章节中得到全面解决。

我们将使用 Spring WebFlux、基于 Swagger/OpenAPI 的 REST API 文档和 SpringFox 以及数据持久性，开发包含业务逻辑的微服务，同时使用 Spring Data 将数据存储在 SQL 和 NoSQL 数据库中。

自从 Spring Boot v2.0 于 2018 年 3 日发布以来，开发响应式微服务变得容易多了（参考第一章，*微服务介绍*，*响应式微服务*部分以获取更多信息）。因此，我们也将介绍如何在本章创建响应式微服务，包括非阻塞同步 REST API 和基于消息的异步服务。我们将使用 Spring WebFlux 开发非阻塞同步 REST API 和 Spring Cloud Stream 开发基于消息的异步服务。

最后，我们将使用 Docker 将我们的微服务作为容器运行。这将允许我们用一个命令启动和停止我们的微服务景观，包括数据库服务器和消息代理。

这是很多技术和框架，所以我们简要地看看它们都是关于什么！

在本章中，我们将介绍以下主题：

+   学习 Spring Boot

+   从 Spring WebFlux 开始

+   探索 SpringFox

+   了解 Spring Data

+   了解 Spring Cloud Stream

+   学习关于 Docker 的内容

关于每个产品的更多详细信息将在接下来的章节中提供。

# 技术要求

本章不包含可以下载的源代码，也不需要安装任何工具。

# 学习 Spring Boot

Spring Boot 以及 Spring Boot 基于的 Spring Framework，是用于在 Java 中开发微服务的好框架。

当 Spring Framework 在 2004 年发布 v1.0 时，它是为了修复过于复杂的 J2EE 标准（Java 2 Platforms, Enterprise Edition 的缩写）而发布的，其臭名昭著的部署描述符非常繁重。Spring Framework 提供了一种基于依赖注入（DI）概念的更轻量级开发模型。与 J2EE 中的部署描述符相比，Spring Framework 还使用了更轻量的 XML 配置文件。

至于 J2EE 标准，更糟糕的是，重量级的部署描述符实际上分为两种类型：

+   标准部署描述符，以标准方式描述配置

+   特定于供应商的部署描述符，将配置映射到供应商特定应用服务器中的供应商特定功能

2006 年，J2EE 被重新命名为**Java EE**，即**Java Platform, Enterprise Edition**，最近，Oracle 将 Jave EE 提交给了 Eclipse 基金会。2018 年 2 月，Java EE 被重新命名为 Jakarta EE。

多年来，尽管 Spring Framework 越来越受欢迎，其功能也显著增长。慢慢地，使用不再那么轻量级的 XML 配置文件来设置 Spring 应用程序的负担变得成为一个问题。

2014 年，Spring Boot 1.0 版本发布，解决了这些问题！

# 约定优于配置和胖 JAR 文件

Spring Boot 通过强烈地规定了如何设置 Spring Framework 的核心模块以及第三方产品，如用于日志记录或连接数据库的库，从而快速开发生产就绪的 Spring 应用程序。Spring Boot 通过默认应用一系列约定并最小化配置需求来实现这一点。每当需要时，每个约定都可以通过编写一些配置来个别覆盖。这种设计模式被称为**约定优于配置**，并最小化了初始配置的需求。

当需要配置时，我认为最好使用 Java 和注解来编写配置。虽然它们比 Spring Boot 出现之前的要小得多，但仍然可以使用那些基于 XML 的古老配置文件。

除了使用*c**onvention over configuration*之外，Spring Boot 还倾向于一个基于独立 JAR 文件的运行时模型，也称为胖 JAR 文件。在 Spring Boot 之前，运行 Spring 应用程序最常见的方式是将它部署为 Apache Tomcat 等 Java EE 网络服务器上的 WAR 文件。Spring Boot 仍然支持 WAR 文件部署。

一个胖 JAR 文件不仅包含应用程序自身的类和资源文件，还包括应用程序所依赖的所有`.jar`文件。这意味着胖 JAR 文件是运行应用程序所需的唯一 JAR 文件；也就是说，我们只需要将一个 JAR 文件传输到我们想要运行应用程序的环境中，而不是将应用程序的 JAR 文件及其依赖的所有 JAR 文件一起传输。

启动胖 JAR 不需要安装单独的 Java EE 网络服务器，如 Apache Tomcat。相反，可以使用简单的命令如`java -jar app.jar`来启动，这使它成为在 Docker 容器中运行的理想选择！如果 Spring Boot 应用程序使用 HTTP，例如，暴露一个 REST API，它将包含一个内嵌的网络服务器。

# 设置 Spring Boot 应用程序的代码示例

为了更好地理解这意味着什么，让我们看看一些源代码示例。

在这里我们只看一些代码片段来指出主要特性。要看到一个完全可工作的示例，您必须等到下一章！

# 神奇的@SpringBootApplication 注解

基于约定的自动配置机制可以通过注解应用程序类来启动，即包含静态`main`方法的类，用`@SpringBootApplication`注解。以下代码显示了这一点：

```java
@SpringBootApplication
public class MyApplication {

  public static void main(String[] args) {
    SpringApplication.run(MyApplication.class, args);
  }
}
```

以下功能将由此注解提供：

+   它支持组件扫描，即在应用程序类的包及其所有子包中查找 Spring 组件和配置类。

+   应用程序类本身成为一个配置类。

+   它支持自动配置，其中 Spring Boot 在类路径中查找可以自动配置的 JAR 文件。例如，如果你在类路径中有 Tomcat，Spring Boot 将自动将 Tomcat 配置为内嵌 web 服务器。

# 组件扫描

假设我们在应用程序类的包（或其子包之一）中有一个 Spring 组件：

```java
@Component
public class MyComponentImpl implements MyComponent { ...
```

应用程序中的另一个组件可以自动导入组件，也称为**自动焊接**，使用`@Autowired`注解：

```java
public class AnotherComponent {

  private final MyComponent myComponent;

  @Autowired
  public AnotherComponent(MyComponent myComponent) {
    this.myComponent = myComponent;
  }
```

我更喜欢使用构造函数注入（而不是字段和设置器注入）来保持组件状态不可变。不可变的州对于希望在多线程运行时环境中运行组件很重要。

如果我们想要使用声明在应用程序包之外的包中的组件，例如，被多个 Spring Boot 应用程序共享的实用组件，我们可以在应用程序类中的`@SpringBootApplication`注解补充一个`@ComponentScan`注解：

```java
package se.magnus.myapp;

@SpringBootApplication
@ComponentScan({"se.magnus.myapp","se.magnus.utils"})
public class MyApplication {
```

现在我们可以在应用程序代码中自动导入`se.magnus.util`包的组件，例如，如下所示的一个实用组件：

```java
package se.magnus.utils;

@Component
public class MyUtility { ...
```

这个实用组件可以这样在应用程序组件中自动导入：

```java
package se.magnus.myapp.services;

public class AnotherComponent {

 private final MyUtility myUtility;

 @Autowired
 public AnotherComponent(MyUtility myUtility) {
   this.myUtility = myUtility;
 }
```

# 基于 Java 的配置

如果我们想要覆盖 Spring Boot 的默认配置，或者如果我们想要添加自己的配置，我们只需用`@Configuration`注解一个类，它将被我们之前描述的组件扫描机制找到。

例如，如果我们想要在由 Spring WebFlux（如下所述）处理的 HTTP 请求处理中设置一个过滤器，该过滤器在请求处理的开头和结尾分别写入日志消息，我们可以如下配置一个日志过滤器：

```java
@Configuration
public class SubscriberApplication {

  @Bean
  public Filter logFilter() {
    CommonsRequestLoggingFilter filter = new 
        CommonsRequestLoggingFilter();
    filter.setIncludeQueryString(true);
    filter.setIncludePayload(true);
    filter.setMaxPayloadLength(5120);
    return filter;
  }
```

我们还可以将配置直接放在应用程序类中，因为`@SpringBootApplication`注解隐含了`@Configuration`注解。

现在我们已经了解了 Spring Boot，接下来让我们谈谈 Spring WebFlux。

# 从 Spring WebFlux 开始

Spring Boot 2.0 基于 Spring Framework 5.0，它提供了内置的支持来开发反应式应用程序。Spring Framework 使用**Project Reactor**作为其反应式支持的基线实现，并且还带来了一个新的 web 框架 Spring WebFlux，它支持开发反应式的，即非阻塞的 HTTP 客户端和服务。

Spring WebFlux 支持两种不同的编程模型：

+   基于注解的命令式风格，与已经存在的 Web 框架 Spring Web MVC 类似，但支持响应式服务

+   基于路由和处理器的新的函数式模型

在这本书中，我们将使用基于注解的命令式风格来展示将 REST 服务从 Spring Web MVC 迁移到 Spring WebFlux 是多么容易，然后开始重构服务，使它们变得完全响应式。

Spring WebFlux 还提供了一个完全响应式的 HTTP 客户端，`WebClient`，作为现有`RestTemplate`客户端的补充。

Spring WebFlux 支持在 Servlet 容器上运行（它需要 Servlet v3.1 或更高版本），但也支持响应式非 Servlet 内嵌 Web 服务器，如 Netty([`netty.io/`](https://netty.io/))。

# 使用 Spring WebFlux 设置 REST 服务的代码示例

在我们能够基于 Spring WebFlux 创建 REST 服务之前，需要将 Spring WebFlux（及其所需的依赖项）添加到 Spring Boot 的类路径中，以便在启动时检测并配置。Spring Boot 提供大量方便的*启动依赖项*，每个依赖项都带来一个特定的特性，以及每个特性通常所需的依赖项。所以，让我们使用 Spring WebFlux 的启动依赖项，然后看看简单的 REST 服务长什么样！

# 启动依赖项

在这本书中，我们将使用 Gradle 作为我们的构建工具，因此 Spring WebFlux 的启动依赖项将被添加到`build.gradle`文件中。它看起来像这样：

```java
implementation('org.springframework.boot:spring-boot-starter-webflux')
```

你可能想知道为什么我们没有指定一个版本号。

我们将在第三章中讨论这一点，*创建一组协作的微服务*！

当微服务启动时，Spring Boot 将检测到类路径中的 Spring WebFlux 并对其进行配置，以及其他用于启动内嵌 Web 服务器的所用东西。默认使用 Netty，我们可以从日志输出中看到：

```java
2018-09-30 15:23:43.592 INFO 17429 --- [ main] o.s.b.web.embedded.netty.NettyWebServer : Netty started on port(s): 8080
```

如果我们想要将 Netty 更改为 Tomcat 作为我们的内嵌 Web 服务器，可以通过从启动依赖项中排除 Netty 并添加 Tomcat 的启动依赖项来覆盖默认配置：

```java
implementation('org.springframework.boot:spring-boot-starter-webflux') 
{
 exclude group: 'org.springframework.boot', module: 'spring-boot-
 starter-reactor-netty'
}
implementation('org.springframework.boot:spring-boot-starter-tomcat')
```

重启微服务后，我们可以看到 Spring Boot 选择了 Tomcat：

```java
2018-09-30 18:23:44.182 INFO 17648 --- [ main] o.s.b.w.embedded.tomcat.TomcatWebServer : Tomcat initialized with port(s): 8080 (http)
```

# 属性文件

从前面的示例中，可以看到 Web 服务器使用端口`8080`启动。如果你想要更改端口，可以使用属性文件覆盖默认值。Spring Boot 应用程序属性文件可以是`.properties`文件或 YAML 文件。默认情况下，它们分别命名为`application.properties`和`application.yml`。

在这本书中，我们将使用 YAML 文件，以便内嵌 Web 服务器所使用的 HTTP 端口可以更改为`7001`。通过这样做，我们可以避免与其他在同一服务器上运行的微服务发生端口冲突。为此，需要在`application.yml`文件中添加以下行：

```java
server.port: 7001
```

# 示例 RestController

现在，有了 Spring WebFlux 和我们所选择的嵌入式 Web 服务器，我们可以像使用 Spring MVC 一样编写 REST 服务，即使用 `RestController`：

```java
@RestController
public class MyRestService {

  @GetMapping(value = "/my-resource", produces = "application/json")
  List<Resource> listResources() {
    ...
  }
```

`@GetMapping` 注解应用于 `listResources()` 方法，它将 Java 方法映射到 `host:8080/myResource` URL 上的 HTTP `GET` API。`List<Resource>` 类型的返回值将被转换为 JSON。

既然我们谈论了 Spring WebFlux，现在让我们来看看 SpringFox 是关于什么的。

# 探索 SpringFox

开发 API 的一个非常重要的方面，例如 RESTful 服务，是如何文档化它们，以便它们易于使用。当涉及到 RESTful 服务时，Swagger 是文档化 RESTful 服务最广泛使用的方法之一。许多领先的 API 网关都有内置支持，用于通过 Swagger 暴露 RESTful 服务的文档。

在 2015 年，SmartBear Software 将 Swagger 规范捐赠给了 Linux Foundation 旗下的 OpenAPI Initiative，并创建了 OpenAPI 规范。Swagger 这个名称仍被用于 SmartBear Software 提供的工具中。

SpringFox 是一个开源项目，与 Spring Framework 分开，它可以在运行时创建基于 Swagger 的 API 文档。它通过在应用程序启动时检查来做到这一点，例如，检查 `WebFlux` 和基于 Swagger 的注解。

在接下来的章节中，我们将查看完整的源代码示例，但现在以下这个示例 API 文档的屏幕快照就足够了：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/9c5f6fb1-6de7-4c81-996c-8c69ede17c43.png)

注意那个大大的执行按钮，它可以用来实际尝试 API，而不仅仅是阅读其文档！

SpringFox 帮助我们理解了微服务如何深入到 Spring Framework 中。现在，让我们转向 Spring Data。

# 理解 Spring Data

Spring Data 提供了一个用于在不同类型的数据库引擎中持久化数据的常见编程模型，范围从传统的关系数据库（SQL 数据库）到各种类型的 NoSQL 数据库引擎，例如文档数据库（例如，MongoDB）、键值数据库（例如，Redis）和图数据库（例如，Neo4J）。

Spring Data 项目分为几个子项目，在这本书中，我们将使用已映射到 MySQL 数据库的 Spring Data MongoDB 和 JPA 子项目。

**JPA** 是 **Java Persistence API** 的缩写，是关于如何处理关系数据的一个 Java 规范。请访问 [`jcp.org/aboutJava/communityprocess/mrel/jsr338/index.html`](https://jcp.org/aboutJava/communityprocess/mrel/jsr338/index.html) 查看最新的规范，截至撰写本文时是 JPA 2.2。

Spring Data 编程模型的两个核心概念是实体和仓库。实体和仓库概括了从各种类型的数据库存储和访问数据的方式。它们提供了一个通用的抽象，但仍然支持向实体和仓库添加数据库特定的行为。这两个核心概念将在本章中一起简要解释，并附有一些示例代码。请注意，更多的细节将在接下来的章节中提供！

尽管 Spring Data 为不同类型的数据库提供了一个共同的编程模型，但这并不意味着您将能够编写可移植的源代码，例如，在不更改源代码的情况下，将数据库技术从 SQL 数据库更改为 NoSQL 数据库！

# 实体

实体描述了 Spring Data 将存储的数据。实体类通常用通用的 Spring Data 注解和特定于每种数据库技术的注解进行注释。

例如，一个将存储在关系型数据库中的实体可以注释如下 JPA 注解：

```java
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

@Entity
@IdClass(ReviewEntityPK.class)
@Table(name = "review")
public class ReviewEntity {
 @Id private int productId;
 @Id private int reviewId;
 private String author;
 private String subject;
 private String content;
```

如果一个实体要存储在 MongoDB 数据库中，可以使用 Spring Data MongoDB 子项目的注解以及通用的 Spring Data 注解。例如，考虑以下代码：

```java
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
public class RecommendationEntity {

    @Id
    private String id;

    @Version
    private int version;

    private int productId;
    private int recommendationId;
    private String author;
    private int rate;
    private String content;
```

`@Id`和`@Version`注解是通用的注解，而`@Document`注解是特定于 Spring Data MongoDB 子项目的。

这一点可以通过研究导入声明来揭示；也就是说，包含`mongodb`的导入声明来自 Spring Data MongoDB 子项目。

# 仓库

仓库用于存储和访问不同类型的数据库中的数据。在其最基本的形式中，一个仓库可以声明为一个 Java 接口，Spring Data 将使用有偏见的约定实时生成其实现。这些约定可以被覆盖和/或补充额外的配置，如果需要，还一些 Java 代码。Spring Data 还提供了一些基础 Java 接口，例如`CrudRepository`，以使仓库的定义更加简单。基础接口`CrudRepository`为我们提供了创建、读取、更新和删除操作的标准方法。

为了指定一个用于处理 JPA 实体`ReviewEntity`的仓库，我们只需要声明以下内容：

```java
import org.springframework.data.repository.CrudRepository;

public interface ReviewRepository extends CrudRepository<ReviewEntity, ReviewEntityPK> {
    Collection<ReviewEntity> findByProductId(int productId);
}
```

在这个例子中，我们使用一个类`ReviewEntityPK`来描述一个组合主键。它如下所示：

```java
public class ReviewEntityPK implements Serializable {
    public int productId;
    public int reviewId;
}
```

我们还添加了一个额外的方法`findByProductId`，它允许我们根据`productId`——主键的一部分——来查找`Review`实体。该方法的命名遵循 Spring Data 定义的命名约定，允许 Spring Data 实时生成这个方法的实现。

如果我们想要使用仓库，我们可以简单地注入它，然后开始使用它，例如：

```java
private final ReviewRepository repository;

@Autowired
public ReviewService(ReviewRepository repository) {
 this.repository = repository;
}

public void someMethod() {
  repository.save(entity);
  repository.delete(entity);
  repository.findByProductId(productId);
```

还添加到了`CrudRepository`接口中，Spring Data 还提供了一个反应式基础接口，`ReactiveCrudRepository`，它使反应式仓库成为可能。该接口中的方法不返回对象或对象集合；相反，它们返回`Mono`和`Flux`对象。如我们在后面的章节中将看到的，`Mono`和`Flux`对象是**反应式流**，能够返回`0`..`1`或`0`..`m`个实体，实体随着流变得可用。基于反应式的接口只能由支持反应式数据库驱动器的 Spring Data 子项目使用；也就是说，它们基于非阻塞 I/O。Spring Data MongoDB 子项目支持反应式仓库，而 Spring Data JPA 则不支持。

为处理前面描述的 MongoDB 实体`RecommendationEntity`指定反应式仓库可能会像以下内容一样：

```java
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface RecommendationRepository extends ReactiveCrudRepository<RecommendationEntity, String> {
    Flux<RecommendationEntity> findByProductId(int productId);
}
```

本节关于 Spring Data 的内容就到这里。现在让我们来看看 Spring Cloud Stream 是关于什么的。

# 理解 Spring Cloud Stream

我们本章不会专注于 Spring Cloud；我们将在第九章，*使用 Netflix Eureka 和 Ribbon 添加服务发现*到第十四章，*理解分布式跟踪*中这样做。然而，我们将引入 Spring Cloud 的一个模块：Spring Cloud Stream。Spring Cloud Stream 为消息提供了一种流式抽象，基于发布-订阅集成模式。Spring Cloud Stream 目前内置了对 Apache Kafka 和 RabbitMQ 的支持。存在许多独立的项目，为其他流行的消息系统提供集成。有关更多信息，请参见[`github.com/spring-cloud?q=binder`](https://github.com/spring-cloud?q=binder)。

Spring Cloud Stream 中的核心概念如下：

+   **消息**：用于描述发送到和从消息系统接收的数据的数据结构。

+   **发布者**：向消息系统发送消息。

+   **订阅者**：从消息系统中接收消息。

+   **通道**：用于与消息系统进行通信。发布者使用输出通道，订阅者使用输入通道。

+   **绑定器**：提供与特定消息系统的实际集成，类似于 JDBC 驱动程序对特定类型的数据库所做的那样。

实际要使用的消息系统在运行时确定，取决于在类路径中找到的内容。Spring Cloud Stream 带有关于如何处理消息的**有见解的约定**。这些约定可以通过指定消息功能的配置来覆盖，如消费者组、分区、持久化、耐用性和错误处理，如重试和死信队列处理。

# 发送和接收消息的 Spring Cloud Stream 代码示例

为了更好地理解这一切是如何组合在一起的，让我们来看看一些源代码示例。

让我们假设我们有一个简单的消息类，如下所示（构造函数、getter 和 setter 已省略，以提高可读性）：

```java
public class MyMessage {
  private String attribute1 = null;
  private String attribute2 = null;
```

Spring Cloud Stream 带有默认的输入和输出通道，`Sink`和`Source`，所以我们可以开始使用，而不需要创建自己的。要发布一条消息，我们可以使用以下源代码：

```java
import org.springframework.cloud.stream.messaging.Source;

@EnableBinding(Source.class)
public class MyPublisher {

 @Autowired private Source mysource;

 public String processMessage(MyMessage message) {
   mysource.output().send(MessageBuilder.withPayload(message).build());
```

为了接收消息，我们可以使用以下代码：

```java
import org.springframework.cloud.stream.messaging.Sink;

@EnableBinding(Sink.class)
public class MySubscriber {

 @StreamListener(target = Sink.INPUT)
 public void receive(MyMessage message) {
 LOG.info("Received: {}",message);
```

为了绑定到 RabbitMQ，我们将在构建文件中使用专门的启动依赖项`build.gradle`：

```java
implementation('org.springframework.cloud:spring-cloud-starter-stream-rabbit')
```

为了让订阅者从发布者那里接收消息，我们需要配置输入和输出通道以使用相同的目的地。如果我们使用 YAML 来描述我们的配置，它可能如下所示对于发布者：

```java
spring.cloud.stream:
  default.contentType: application/json
  bindings.output.destination: mydestination
```

订阅者的配置如下：

```java
spring.cloud.stream:
  default.contentType: application/json
  bindings.input.destination: mydestination
```

我们使用`default.contentType`来指定我们更喜欢消息以 JSON 格式序列化。

现在我们已经了解了各种 Spring API，让我们在下一节了解一个相对较新的概念，Docker。

# 学习关于 Docker

我假设 Docker 和容器概念不需要深入介绍。Docker 在 2013 年非常流行的容器作为虚拟机的轻量级替代品。实际上，容器是在使用 Linux **namespaces**在 Linux 主机上处理，以提供容器之间全局系统资源，如用户、进程、文件系统、网络。Linux 控制组（也称为**cgroups**）用于限制容器允许消耗的 CPU 和内存量。与在每一个虚拟机中运行操作系统的完整副本的虚拟机相比，容器的开销只是虚拟机开销的一小部分。这导致了更快的启动时间和在 CPU 和内存使用上显著降低的开销。然而，容器提供的隔离并不被认为是像虚拟机提供的隔离那样安全的。随着 Windows Server 2016 的发布，微软支持在 Windows 服务器上使用 Docker。

容器在开发和测试中都非常有用。能够通过一条命令启动一个完整的微服务合作系统景观（例如，数据库服务器、消息代理等）进行测试，这真是令人惊叹。

例如，我们可以编写脚本以自动化我们微服务景观的端到端测试。一个测试脚本可以启动微服务景观，使用暴露的服务运行测试，并拆除景观。这种类型的自动化测试脚本非常实用，既可以在开发者在将代码推送到源代码仓库之前在本地的开发机上运行，也可以作为交付管道中的一个步骤执行。构建服务器可以在持续集成和部署过程中，在开发者将代码推送到源代码仓库时运行这些类型的测试。

对于生产使用，我们需要一个容器编排器，如 Kubernetes。我们将在本书的后面回到容器编排器和 Kubernetes。

在本书中我们将要研究的绝大多数微服务，只需要如下的 Dockerfile 就可以将微服务作为 Docker 容器运行：

```java
FROM openjdk:12.0.2

MAINTAINER Magnus Larsson <magnus.larsson.ml@gmail.com>

EXPOSE 8080
ADD ./build/libs/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
```

如果我们想要用一个命令来启动和停止许多容器，Docker Compose 是完美的工具。Docker Compose 使用一个 YAML 文件来描述要管理的容器。对于我们的微服务，它可能看起来像如下这样：

```java
product:
 build: microservices/product-service

recommendation:
 build: microservices/recommendation-service

review:
  build: microservices/review-service

composite:
  build: microservices/product-composite-service
  ports:
    - "8080:8080"
```

让我稍微解释一下前面的源代码：

+   `build`指令用于指定每个微服务使用哪个 Dockerfile。Docker Compose 会使用它来构建一个 Docker 镜像，然后基于这个 Docker 镜像启动一个 Docker 容器。

+   复合服务中的`ports`指令用于在运行 Docker 的服务器上暴露端口`8080`。在开发者的机器上，这意味着可以通过使用`localhost:8080`简单地访问复合服务的端口！

YAML 文件中的所有容器都可以用如下简单命令进行管理：

+   `docker-compose up -d`：启动所有容器。`-d`意味着容器在后台运行，不会锁定执行命令的终端。

+   `docker-compose down`：停止并删除所有容器。

+   `docker-compose logs -f --tail=0`：输出所有容器的日志消息。`-f`意味着该命令不会完成，而是等待新的日志消息。`--tail=0`意味着我们不想看到任何之前的日志消息，只想要新的。

这是对 Docker 的简要介绍。在本书的最后几章，我们将更详细地介绍 Docker。

# 总结

在本章中，我们介绍了 Spring Boot 以及可以用来构建协作微服务的互补的开源工具。

Spring Boot 用于简化基于 Spring 的生产级应用程序的开发。它强烈地规定了如何设置 Spring Framework 的核心模块和第三方产品。

Spring WebFlux 是 Spring 家族中的一个新模块，用于开发反应式的，也就是非阻塞的 REST 服务。它既可以在 Netty 这样的轻量级 web 服务器上运行，也可以在任何 Servlet 3.1+兼容的 web 服务器上运行。它还支持来自较老的 Spring MVC 模块的编程模型；无需完全重写代码，就可以轻松地将为 Spring MVC 编写的 REST 服务迁移到 Spring WebFlux。

SpringFox 可以用来创建基于 Swagger 和 OpenAPI 的关于 REST 服务的文档。它通过检查 REST 服务的注解（既 Spring 的注解和一些 Swagger 特定的注解，如果使用的话）在运行时动态创建文档。

Spring Data 提供了一种优雅的抽象，用于使用实体和仓库访问和管理持久数据。编程模型相似，但不同类型的数据库（例如，关系型、文档型、键值型和图数据库）之间并不兼容。

Spring Cloud Stream 为消息传递提供了基于发布和订阅集成模式的流抽象。Spring Cloud Stream 默认支持 Apache Kafka 和 RabbitMQ，但可以通过自定义绑定器扩展支持其他消息代理。

Docker 使得容器这一轻量级的虚拟机替代方案变得易于使用。基于 Linux 命名空间和控制组，容器提供了与传统虚拟机相似的隔离性，但在 CPU 和内存使用方面有显著的较低开销。Docker 是一个非常适合开发和测试的工具，但在大多数情况下，在生产环境中使用需要一个容器编排器，如 Kubernetes。

# 问题

1.  `@SpringBootApplication` 注解的目的是什么？

1.  老版本的用于开发 REST 服务的 Spring 组件 Spring Web MVC 和新版本的 Spring WebFlux 之间的主要区别是什么？

1.  **SpringFox** 是如何帮助开发者文档化 REST API 的？

1.  在 Spring Data 中，仓库的功能是什么，仓库的最简单可能实现是什么？

1.  在 Spring Cloud Stream 中，绑定的目的是什么？

1.  **Docker Compose** 的目的是什么？


# 第三章：创建一套协作的微服务

在本章中，我们将构建我们的第一个微服务。我们将学习如何创建具有最小功能的协作微服务。在接下来的章节中，我们将向这些微服务添加越来越多的功能。到本章末尾，我们将通过一个复合微服务暴露一个 RESTful API。复合微服务将使用它们的 RESTful API 调用其他三个微服务，以创建一个聚合响应。

本章将涵盖以下主题：

+   介绍微服务架构

+   生成微服务骨架

+   添加 RESTful API

+   添加一个复合微服务

+   添加错误处理

+   手动测试 API

+   向微服务添加隔离的自动化测试

+   向微服务架构添加半自动化测试

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但它们应该很容易修改，以便在如 Linux 或 Windows 等其他平台上运行。

# 工具安装

为了能够执行本章中使用的命令，你需要在你计算机上安装以下工具：

+   [Git:](https://git-scm.com/downloads) 可以从 [`git-scm.com/downloads`](https://git-scm.com/downloads) 下载并安装。

+   **Java：**可以从 [`www.oracle.com/technetwork/java/javase/downloads/index.html`](https://www.oracle.com/technetwork/java/javase/downloads/index.html) 下载并安装。

+   `curl`：这个用于测试基于 HTTP 的 API 的命令行工具可以从 [`curl.haxx.se/download.html`](https://curl.haxx.se/download.html) 下载并安装。

+   `jq`：这个命令行 JSON 处理器可以从 [`stedolan.github.io/jq/download/`](https://stedolan.github.io/jq/download/) 下载并安装。

+   **Spring Boot CLI**：这个 Spring Boot 应用程序的命令行工具可以从 [`docs.spring.io/spring-boot/docs/current/reference/html/getting-started-installing-spring-boot.html#getting-started-installing-the-cli`](https://docs.spring.io/spring-boot/docs/current/reference/html/getting-started-installing-spring-boot.html#getting-started-installing-the-cli) 下载并安装。

# 安装 Homebrew

要在 macOS 上安装这些工具，我建议你使用 Homebrew，[`brew.sh/`](https://brew.sh/)。如果你没有安装，可以使用以下命令安装：

```java
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

安装 Xcode 的命令行工具会安装 Homebrew，如果你还没有安装，可能需要一些时间。

使用以下命令验证 Homebrew 的安装：

```java
brew --version
```

期望得到如下响应：

```java
Homebrew 1.7.7
```

# 使用 Homebrew 安装 Java、curl、jq 和 Spring Boot CLI

在 macOS 上，`curl` 已经预装，`git` 是 Homebrew 安装的一部分。剩下的工具可以使用以下命令在 macOS 上使用 Homebrew 安装：

```java
brew tap pivotal/tap && \
brew cask install java && \
brew install jq && \
brew install springboot
```

这些工具的安装可以通过以下命令来验证：

```java
git --version
java -version
curl --version
jq --version
spring --version 
```

这些命令将返回如下内容（删除了一些不相关的输出）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cf7decb8-42ed-41c9-a9fe-6143e7d1c0e5.png)

# 使用 IDE

我建议你使用支持 Spring Boot 应用程序开发的 IDE，如 Spring Tool Suite 或 IntelliJ IDEA Ultimate Edition 来编写 Java 代码。查看*手动测试 API*部分，了解如何使用 Spring Boot 控制台。然而，你不需要 IDE 就能按照本书中的说明操作。

# 访问源代码

本章的源代码可以在本书的 GitHub 仓库中找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter03)。

为了能够运行本书中描述的命令，将源代码下载到文件夹中，并设置一个环境变量`$BOOK_HOME`，该变量指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter03
```

Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试运行。为了避免与 Spring Boot 2.0（和 Spring 5.0）的一些问题，本章使用了 Spring Boot 2.1.0 RC1（和 Spring 5.1.1），这是在撰写本书时可用的最新 Spring Boot 版本。

本章中的代码示例都来自`$BOOK_HOME/Chapter03`的源代码，但在许多情况下，为了删除源代码中不相关部分，例如注释、导入和日志声明，对这些代码进行了编辑。

有了这些，我们安装了所需的工具，并下载了本章的源代码。在下一节中，我们将学习本书中我们将要创建的协作微服务系统架构。

# 介绍微服务架构

在第一章中，*微服务简介*，我们简要介绍了将在本书中使用的基于微服务的系统架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cf74f5f6-c0f7-471c-8eae-a2566ecee996.png)

它由三个核心微服务组成，分别是**产品**、**评论**和**推荐**服务，这三个服务都处理一种资源类型，还有一个名为**产品组合**的复合微服务，它聚合了这三个核心服务的信息。

# 暂时替换发现服务

由于在这个阶段，我们没有任何服务发现机制，我们将为每个微服务使用硬编码端口号。我们将使用以下端口：

+   产品组合服务：`7000`

+   产品服务：`7001`

+   审查服务：`7002`

+   推荐服务：`7003`

我们稍后开始使用 Docker 和 Kubernetes 时，将不再使用这些硬编码端口！

在本节中，我们已经介绍了将要创建的微服务以及它们将处理的信息。在下一节中，我们将使用 Spring Initializr 创建微服务的骨架代码。

# 微服务处理的信息

为了使本书中的源代码示例容易理解，它们包含的业务逻辑量最小。它们处理的业务对象的信息模型同样因为此原因保持最小。在本节中，我们将了解每个微服务处理的信息，以及微服务处理的基础设施相关信息。

# 产品服务

`product`服务管理产品信息，并使用以下属性描述每个产品：

+   产品 ID

+   名称

+   重量

# 服务回顾

`review`服务管理产品评论，并存储关于每个评论以下信息：

+   产品 ID

+   回顾 ID

+   作者

+   主题

+   内容

# 推荐服务

`recommendation`服务管理产品推荐，并存储关于每个推荐以下信息：

+   产品 ID

+   推荐 ID

+   作者

+   评分

+   内容

# 产品复合服务

`product`复合服务汇总三个核心服务的信息，如下所示呈现关于产品的信息：

+   产品信息，如`product`服务中所描述

+   指定产品的产品评论列表，如`review`服务中所描述

+   指定产品的产品推荐列表，如`recommendation`服务中所描述

# 与基础设施相关的信息

一旦我们开始将我们的微服务作为由基础架构管理（首先是 Docker，后来是 Kubernetes）的容器运行，跟踪实际响应我们请求的容器将会很有趣。为了简化这种跟踪，我们还向所有我们的响应中添加了一个`serviceAddress`属性，格式为`hostname/ip-address:port`。

# 生成骨架微服务

是时候看看我们如何为我们的微服务创建项目了。这个主题的最终结果可以在`$BOOK_HOME/Chapter03/1-spring-init`文件夹中找到。为了简化项目的设置，我们将使用 Spring Initializr 为每个微服务生成一个骨架项目。骨架项目包含构建项目所需的文件，以及为微服务空白的`main`类和测试类。之后，我们将了解如何使用我们将要使用的构建工具 Gradle 中的多项目构建，用一个命令构建所有的微服务。

# 使用 Spring Initializr 生成骨架代码

为了开始开发我们的微服务，我们将使用一个名为**Spring Initializr**的工具来为我们生成骨架代码。它可以通过使用[`start.spring.io/`](https://start.spring.io/) URL 从网络浏览器调用，或者通过命令行工具`spring init`调用。为了更容易地复现微服务的创建，我们将使用命令行工具。

针对每个微服务，我们将创建一个 Spring Boot 项目，执行以下操作：

+   使用 Gradle 作为构建工具

+   为 Java 8 生成代码

+   将项目打包为胖 JAR 文件

+   引入了`Actuator`和`WebFlux` Spring 模块的依赖项

+   基于 Spring Boot v2.1.0 RC1（依赖于 Spring Framework v5.1.1）

Spring Boot Actuator 为管理和监控启用了许多有价值的端点。我们稍后可以看到它们的具体应用。在这里，我们将使用 Spring WebFlux 创建我们的 RESTful API。

为了为我们的微服务创建骨架代码，我们需要针对`product-service`运行以下命令：

```java
spring init \
--boot-version=2.1.0.RC1 \
--build=gradle \
--java-version=1.8 \
--packaging=jar \
--name=product-service \
--package-name=se.magnus.microservices.core.product \
--groupId=se.magnus.microservices.core.product \
--dependencies=actuator,webflux \
--version=1.0.0-SNAPSHOT \
product-service
```

如果你想了解更多关于`spring init` CLI 的信息，可以运行`spring help init`命令。要查看您可以添加的依赖项，请运行`spring init --list`命令。

如果你想自己创建这四个项目，而不是使用本书 GitHub 仓库中的源代码，可以尝试使用`$BOOK_HOME/Chapter03/1-spring-init/create-projects.bash`，如下所示：

```java
mkdir some-temp-folder cd some-temp-folder
$BOOK_HOME/Chapter03/1-spring-init/create-projects.bash
```

在使用`create-projects.bash`创建我们的四个项目后，我们将拥有以下文件结构：

```java
microservices/
├── product-composite-service
├── product-service
├── recommendation-service
└── review-service
```

对于每个项目，我们可以列出创建的文件。让我们为`product-service`项目这样做：

```java
find microservices/product-service -type f
```

我们将收到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/21a0ab5c-8c4c-4898-9cab-598833bd976f.png)

Spring Initializr 为 Gradle 创建了许多文件，包括一个`.gitignore`文件和三个 Spring Boot 文件：

+   `ProductServiceApplication.java`，我们的主应用类

+   `application.properties`，一个空属性文件

+   `ProductServiceApplicationTests.java`，一个已配置为使用 JUnit 在我们的 Spring Boot 应用程序上运行测试的测试类

`main`应用类`ProductServiceApplication.java`看起来与上一章预期的一致：

```java
package se.magnus.microservices.core.product;

@SpringBootApplication
public class ProductServiceApplication {
   public static void main(String[] args) {
      SpringApplication.run(ProductServiceApplication.class, args);
   }
}
```

测试类如下所示：

```java
package se.magnus.microservices.core.product;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ProductServiceApplicationTests {
   @Test
   public void contextLoads() {
   }
}
```

`@RunWith(SpringRunner.class)`和`@SpringBootTest`注解将以前述方式初始化我们的应用：当运行应用时，`@SpringBootApplication`会设置 Spring 应用上下文；也就是说，在执行测试之前，使用组件扫描和自动配置设置上下文，如上一章所述。

让我们也看看最重要的 Gradle 文件，即`build.gradle`。这个文件的内容描述了如何构建项目，例如编译、测试和打包源代码。Gradle 文件从设置`buildscript`元素并列出要应用的插件来开始，为其余的构建文件设置条件：

```java
buildscript {
  ext {
    springBootVersion = '2.1.0.RC1'
  }
  repositories {
    mavenCentral()
    maven { url "https://repo.spring.io/snapshot" }
    maven { url "https://repo.spring.io/milestone" }
  }
  dependencies {
    classpath("org.springframework.boot:spring-boot-gradle-
    plugin:${springBootVersion}")
  }
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'org.springframework.boot'
apply plugin: 'io.spring.dependency-management'
```

让我们更详细地解释前面的源代码：

+   Spring Boot 版本设置为我们运行`spring init`命令时指定的版本，即`2.1.0.RC1`。

+   声明了许多 Gradle 插件。最重要的插件是`org.springframework.boot`和`io.spring.dependency-management`插件，这两个插件一起确保 Gradle 会构建一个胖 JAR 文件，并且我们不需要在 Spring Boot 启动器依赖项上指定任何显式的版本号。相反，它们由`springBootVersion`属性隐含。

+   插件是从中央 Maven 仓库以及 Spring 的快照和里程碑仓库中获取的，因为我们指定的是 Spring Boot 的发行候选版本，即 v2.1.0 RC1，而不是一个已经发布并可在中央 Maven 仓库中找到的版本。

在构建文件的其余部分，我们基本上为我们的项目声明了一个组名和版本，Java 版本及其依赖项：

```java
group = 'se.magnus.microservices.core.product'
version = '1.0.0-SNAPSHOT'
sourceCompatibility = 1.8

repositories {
  mavenCentral()
  maven { url "https://repo.spring.io/snapshot" }
  maven { url "https://repo.spring.io/milestone" }
}

dependencies {
  implementation('org.springframework.boot:spring-boot-starter-
  actuator')
  implementation('org.springframework.boot:spring-boot-starter-
  webflux')
  testImplementation('org.springframework.boot:spring-boot-starter-
  test')
  testImplementation('io.projectreactor:reactor-test')
}
```

让我们更详细地解释上述源代码如下：

+   依赖项，像之前的插件一样，从中央 Maven 仓库和 Spring 的快照和里程碑仓库中获取。

+   依赖项是按照`Actuator`和`WebFlux`模块中指定的设置的，还有一些有用的测试依赖项。

我们可以使用以下命令单独构建每个微服务：

```java
cd microservices/product-composite-service; ./gradlew build; cd -; \
cd microservices/product-service;           ./gradlew build; cd -; \
cd microservices/recommendation-service;    ./gradlew build; cd -; \ cd microservices/review-service;            ./gradlew build; cd -; 
```

注意我们如何使用由 Spring Initializr 创建的`gradlew`可执行文件；也就是说，我们不需要安装 Gradle！

第一次运行`gradlew`命令时，它会自动下载 Gradle。使用的 Gradle 版本由`gradle/wrapper/gradle-wrapper.properties`文件中的`distributionUrl`属性确定。

# 在 Gradle 中设置多项目构建

为了使用一个命令构建所有微服务稍微简单一些，我们可以在 Gradle 中设置一个多项目构建。步骤如下：

1.  首先，我们创建一个`settings.gradle`文件，描述 Gradle 应该构建哪些项目：

```java
cat <<EOF > settings.gradle
include ':microservices:product-service'
include ':microservices:review-service'
include ':microservices:recommendation-service'
include ':microservices:product-composite-service'
EOF
```

1.  接下来，我们将复制从一个项目中生成的 Gradle 可执行文件，以便我们可以在多项目构建中重复使用它们：

```java
cp -r microservices/product-service/gradle .
cp microservices/product-service/gradlew .
cp microservices/product-service/gradlew.bat .
cp microservices/product-service/.gitignore .
```

1.  我们不再需要每个项目中生成的 Gradle 可执行文件，所以我们可以使用以下命令删除它们：

```java
find microservices -depth -name "gradle" -exec rm -rfv "{}" \; find microservices -depth -name "gradlew*" -exec rm -fv "{}" \; 
```

结果应该与您在`$BOOK_HOME/Chapter03/1-spring-init`文件夹中找到的代码类似。

1.  现在，我们可以用一个命令构建所有微服务：

```java
./gradlew build
```

如果您还没有运行前面的命令，您可以简单地直接去书源代码那里并从中构建：

```java
cd $BOOK_HOME/Chapter03/1-spring-init

./gradlew build
```

1.  这应该会导致以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/efd0c892-cbca-4962-8248-b17da6fe8cd0.png)

使用 Spring Initializr 创建的微服务骨架项目和成功使用 Gradle 构建后，我们在下一节准备向微服务中添加一些代码。

从 DevOps 的角度来看，多项目设置可能不是首选。相反，为每个微服务项目设置一个单独的构建管道可能更受欢迎。然而，为了本书的目的，我们将使用多项目设置，以便更容易用一个命令构建和部署整个系统架构。

# 添加 RESTful API

现在我们已经为我们的微服务设置了项目，接下来让我们向我们的三个核心微服务中添加一些 RESTful API 吧！

本章剩余主题的最终结果可以在 `$BOOK_HOME/Chapter03/2-basic-rest-services` 文件夹中找到。

首先，我们将添加两个项目（`api` 和 `util`），它们将包含由微服务项目共享的代码，然后我们将实现 RESTful API。

# 添加 API 和 util 项目

要添加 API，我们需要执行以下操作：

1.  首先，我们将建立一个单独的 Gradle 项目，用于放置我们的 API 定义。我们将使用 Java 接口来描述我们的 RESTful API，并使用模型类来描述 API 在其请求和响应中使用的数据。在我看来，使用 Java 接口而不是直接在 Java 类中描述 RESTful API 是一种很好的将 API 定义与其实现分离的方法。在本书的后续内容中，我们将进一步扩展这一模式，当我们向 Java 接口中添加更多 API 信息以在 Swagger/OpenAPI 定义中公开时。更多信息请参阅 第五章，*使用 OpenAPI/Swagger 添加 API 描述*。

描述 RESTful API 的 Java 接口直到 Spring Framework v5.1.0 才得到完全支持。具体请参阅 [`jira.spring.io/browse/SPR-11055`](https://jira.spring.io/browse/SPR-11055)。

是否应该将一组微服务的 API 定义存储在公共 API 模块中，这一点是有争议的。在我看来，这对于属于同一交付组织的微服务来说是一个不错的选择，也就是说，这些微服务的发布由同一个组织管理（与 *Domain-Driven Design* 中的 *Bounded Context* 相比，我们的微服务位于同一个 bounded context 中）。

1.  然后，我们将创建一个 `util` 项目，用于存放一些由我们的微服务共享的帮助类，例如，以统一的方式处理错误。

再次从 DevOps 的角度来看，最好为所有项目建立它们自己的构建管道，并在微服务项目中使用版本控制的 `api` 和 `util` 项目依赖；也就是说，每个微服务可以选择使用 `api` 和 `util` 项目的哪些版本。但为了在本书的上下文中保持构建和部署步骤简单，我们将使 `api` 和 `util` 项目成为多项目构建的一部分。

# api 项目

`api` 项目将被打包为库；也就是说，它将没有自己的 `main` 应用程序类。不幸的是，Spring Initializr 不支持创建库项目。相反，库项目需要从头开始手动创建。API 项目的源代码可在 `$BOOK_HOME/Chapter03/2-basic-rest-services/api` 找到。

库项目的结构与应用程序项目相同，不同之处在于我们不再有`main`应用程序类，以及在`build.gradle`文件中的一些小差异。Gradle `org.springframework.boot`和`io.spring.dependency-management`插件被替换为一个`dependencyManagement`部分：

```java
plugins {
   id "io.spring.dependency-management" version "1.0.5.RELEASE"
}

dependencyManagement {
  imports { mavenBom("org.springframework.boot:spring-boot-
  dependencies:${springBootVersion}") }
}
```

这允许我们在替换构建步骤中构建胖 JAR 的方法为创建正常 JAR 文件的同时保留 Spring Boot 依赖管理；也就是说，它们只包含库项目自己的类和属性文件。

`api`项目中我们三个核心微服务的 Java 文件如下：

```java
$BOOK_HOME/Chapter03/2-basic-rest-services/api/src/main/java/se/magnus/api/core
├── product
│   ├── Product.java
│   └── ProductService.java
├── recommendation
│   ├── Recommendation.java
│   └── RecommendationService.java
└── review
    ├── Review.java
    └── ReviewService.java
```

三个核心微服务的 Java 类结构非常相似，所以我们只查看`product`服务的源代码。

首先，我们将查看`ProductService.java`Java 接口，如下代码所示：

```java
package se.magnus.api.core.product;

public interface ProductService {
    @GetMapping(
        value    = "/product/{productId}",
        produces = "application/json")
     Product getProduct(@PathVariable int productId);
}
```

让我们更详细地解释一下前面的源代码：

+   `product`服务只暴露了一个 API 方法，`getProduct()`（我们将在本书后面扩展 API）。

+   为了将方法映射到 HTTP `GET`请求，我们使用`@GetMapping` Spring 注解，其中我们指定方法将被映射到的 URL 路径（`/product/{productId}`）以及响应的格式，这次是 JSON。

+   路径中的`{productId}`部分映射到一个名为`productId`的`path`变量。

+   `productId`方法参数用`@PathVariable`注解标记，这将把通过 HTTP 请求传递的值映射到参数。例如，对`/product/123`的 HTTP`GET`请求将导致`getProduct()`方法以`productId`参数设置为`123`被调用。

该方法返回一个`Product`对象，这是一个基于 plain POJO 的模型类，其成员变量对应于`Product`的属性。`Product.java`如下所示（省略了构造函数和 getter 方法）：

```java
public class Product {
 private final int productId;
 private final String name;
 private final int weight;
 private final String serviceAddress;
}
```

这种 POJO 类也被称为数据传输对象（Data Transfer Object，DTO），因为它用于在 API 实现和 API 调用者之间传输数据。当我们在第六章中讨论添加持久化时，我们会看到另一种可以用来描述数据在数据库中存储方式的 POJO，也称为实体对象。

# 工具项目

`util`项目将以与`api`项目相同的方式打包为库。`util`项目的源代码可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/util`中找到。该项目包含以下 Java 文件：

+   `InvalidInputException`和`NotFoundException`异常类

+   `GlobalControllerExceptionHandler`、`HttpErrorInfo`和`ServiceUtil`工具类

除了`ServiceUtil.java`中的代码，这些类是可重用的实用工具类，我们可以使用它们将 Java 异常映射到适当的 HTTP 状态码，如*添加错误处理*部分所述。`ServiceUtil.java`的主要目的是找出微服务使用的主机名、IP 地址和端口。该类暴露了一个方法`getServiceAddress()`，微服务可以使用它来找到它们的主机名、IP 地址和端口。

# 实现我们的 API

现在我们可以开始在核心微服务中实现我们的 API 了！

三个核心微服务的实现看起来非常相似，所以我们只查看`product`服务的源代码。你可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices`中找到其他文件。让我们看看我们是如何进行这项工作的：

1.  我们需要在我们的`build.gradle`文件中添加`api`和`util`项目作为依赖，即`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-service/build.gradle`:

```java
dependencies {
   implementation project(':api')
   implementation project(':util')
```

1.  为了使 Spring Boot 的自动配置功能能够检测到`api`和`util`项目中的 Spring beans，我们还需要在主应用类中添加一个`@ComponentScan`注解，包括`api`和`util`项目的包：

```java
@SpringBootApplication
@ComponentScan("se.magnus")
public class ProductServiceApplication {
```

1.  接下来，我们创建我们的服务实现文件`ProductServiceImpl.java`，以便实现`api`项目中的 Java 接口`ProductService`，并使用`@RestController`注解类，以便 Spring 根据`Interface`类中指定的映射调用这个类的方法：

```java
package se.magnus.microservices.core.product.services;

@RestController
public class ProductServiceImpl implements ProductService {
}
```

1.  为了能够使用来自`util`项目的`ServiceUtil`类，我们将通过构造函数注入它，如下所示：

```java
private final ServiceUtil serviceUtil;

@Autowired
public ProductServiceImpl(ServiceUtil serviceUtil) {
    this.serviceUtil = serviceUtil;
}
```

1.  现在，我们可以通过覆盖`api`项目中的接口的`getProduct()`方法来实现 API：

```java
@Override
public Product getProduct(int productId) {
 return new Product(productId, "name-" + productId, 123, 
 serviceUtil.getServiceAddress());
}
```

由于我们目前不使用数据库，我们只需根据`productId`的输入返回一个硬编码的响应，加上由`ServiceUtil`类提供的服务地址。

对于最终结果，包括日志和错误处理，请参阅`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-service/src/main/java/se/magnus/microservices/core/product/services/ProductServiceImpl.java`。

1.  最后，我们还需要设置一些运行时属性——使用哪个端口以及所需的日志级别。这添加到了`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-service/src/main/resources/application.yml`属性文件中：

```java
server.port: 7001

logging:
  level:
    root: INFO
    se.magnus.microservices: DEBUG
```

1.  我们可以尝试单独测试`product`服务。使用以下命令构建并启动微服务：

```java
cd $BOOK_HOME/Chapter03/2-basic-rest-services
./gradlew build
java -jar microservices/product-service/build/libs/*.jar &
```

1.  等待终端打印以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/41540310-c226-4100-ae87-35de5d722d65.png)

1.  对`product`服务进行测试调用：

```java
curl http://localhost:7001/product/123
```

1.  它应该响应以下类似的内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/99d66466-5aec-4506-b7ea-c12540ad6ce5.png)

1.  最后，停止`product`服务：

```java
kill $(jobs -p)
```

我们已经构建、运行并测试了我们的第一个单一微服务。在下一节中，我们将实现一个复合微服务，该服务将使用我们迄今为止创建的三个核心微服务。

# 添加复合微服务

现在，是时候通过添加将调用三个核心服务的复合服务来整合一切了！

复合服务的实现分为两部分：一个处理对核心服务发出的 HTTP 请求的集成组件和复合服务实现本身。这种责任划分的主要原因是它简化了自动化单元和集成测试；也就是说，我们可以通过用模拟替换集成组件来孤立地测试服务实现。

正如我们在这本书后面所看到的，这种责任划分也使得引入断路器变得更容易！

在深入源代码之前，我们需要先了解复合微服务将使用的 API 类，以及学习运行时属性如何用于持有核心微服务的地址信息。

两个组件的完整实现，包括集成组件和复合服务的实现，可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-composite-service/src/main/java/se/magnus/microservices/composite/product/services`文件夹中找到。

# api 类

在本节中，我们将查看描述复合组件 API 的类。它们可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/api`中找到。以下是要查看的 API 类：

```java
$BOOK_HOME/Chapter03/2-basic-rest-services/api
└── src/main/java/se/magnus/api/composite
    └── product
        ├── ProductAggregate.java
        ├── ProductCompositeService.java
        ├── RecommendationSummary.java
        ├── ReviewSummary.java
        └── ServiceAddresses.java
```

`ProductCompositeService.java`这个 Java 接口类遵循与核心服务相同的模式，如下所示：

```java
package se.magnus.api.composite.product;

public interface ProductCompositeService {
    @GetMapping(
        value    = "/product-composite/{productId}",
        produces = "application/json")
    ProductAggregate getProduct(@PathVariable int productId);
}
```

模型类`ProductAggregate.java`比核心模型稍微复杂一些，因为它包含推荐和评论的列表字段：

```java
package se.magnus.api.composite.product;

public class ProductAggregate {
    private final int productId;
    private final String name;
    private final int weight;
    private final List<RecommendationSummary> recommendations;
    private final List<ReviewSummary> reviews;
    private final ServiceAddresses serviceAddresses;
```

# 属性

为了避免在复合微服务的源代码中硬编码核心服务的地址信息，后者使用一个属性文件，其中存储了如何找到核心服务的信息。这个属性文件可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-composite-service/src/main/resources/application.yml`中找到，如下所示：

```java
server.port: 7000

app:
  product-service:
    host: localhost
    port: 7001
  recommendation-service:
    host: localhost
    port: 7002
  review-service:
    host: localhost
    port: 7003
```

这种配置将在本书后面被服务发现机制所取代。

# 集成组件

让我们看看集成组件`ProductCompositeIntegration.java`。它使用`@Component`注解作为一个 Spring Bean 声明，并实现了三个核心服务的 API 接口：

```java
package se.magnus.microservices.composite.product.services;

@Component
public class ProductCompositeIntegration implements ProductService, RecommendationService, ReviewService {
```

整合组件使用 Spring Framework 中的一个助手类`RestTemplate.java`来对核心微服务执行实际的 HTTP 请求。在我们能够将其注入整合组件之前，我们需要对其进行配置。我们是在`main`应用程序类`ProductCompositeServiceApplication.java`中如下完成的：

```java
@Bean
RestTemplate restTemplate() {
   return new RestTemplate();
}
```

`RestTemplate`高度可配置，但我们现在将其保留为其默认值。

我们现在可以在整合组件的构造函数中注入`RestTemplate`，以及用于错误处理的 JSON 映射器和我们 在属性文件中设置的配置值。让我们看看这是如何完成的：

1.  用于设置三个核心服务 URL 的配置值如下所示注入到构造函数中：

```java
private final RestTemplate restTemplate;
private final ObjectMapper mapper;

private final String productServiceUrl;
private final String recommendationServiceUrl;
private final String reviewServiceUrl;

@Autowired
public ProductCompositeIntegration(
  RestTemplate restTemplate,
  ObjectMapper mapper,

  @Value("${app.product-service.host}") String productServiceHost,
  @Value("${app.product-service.port}") int productServicePort,

  @Value("${app.recommendation-service.host}") String 
  recommendationServiceHost,
  @Value("${app.recommendation-service.port}") int 
  recommendationServicePort,

  @Value("${app.review-service.host}") String reviewServiceHost,
  @Value("${app.review-service.port}") int reviewServicePort
)
```

构造函数的正文根据注入的值构建 URL，如下所示：

```java
{
  this.restTemplate = restTemplate;
  this.mapper = mapper;

  productServiceUrl = "http://" + productServiceHost + ":" + 
  productServicePort + "/product/";
  recommendationServiceUrl = "http://" + recommendationServiceHost
  + ":" + recommendationServicePort + "/recommendation?
  productId="; reviewServiceUrl = "http://" + reviewServiceHost + 
  ":" + reviewServicePort + "/review?productId=";
}
```

1.  最后，整合组件通过使用`RestTemplate`来实际发起调用，实现了三个核心服务的 API 方法：

```java
public Product getProduct(int productId) {
 String url = productServiceUrl + productId;
 Product product = restTemplate.getForObject(url, Product.class);
 return product;
}

public List<Recommendation> getRecommendations(int productId) {
    String url = recommendationServiceUrl + productId;
    List<Recommendation> recommendations = 
    restTemplate.exchange(url, GET, null, new 
    ParameterizedTypeReference<List<Recommendation>>() 
    {}).getBody();
    return recommendations;
}

public List<Review> getReviews(int productId) {
    String url = reviewServiceUrl + productId;
    List<Review> reviews = restTemplate.exchange(url, GET, null,
    new ParameterizedTypeReference<List<Review>>() {}).getBody();
    return reviews;
}
```

让我们更详细地解释前面的源代码：

+   对于`getProduct()`实现，`RestTemplate`中的`getForObject()`方法可以使用。预期的响应是一个`Product`对象， 它可以通过在`getForObject()`调用中指定`Product.class`类来表示，`RestTemplate`会将 JSON 响应映射到这个类。

+   对于`getRecommendations()`和`getReviews()`的调用，必须使用一个更高级的方法，`exchange()`。这是因为`RestTemplate`执行了从 JSON 响应到模型类的自动映射。

+   `getRecommendations()`和`getReviews()`方法期望在响应中有一个泛型列表，即`List<Recommendation>`和`List<Review>`。由于泛型在运行时 不持有任何类型信息，我们不能指定方法期望在响应中有泛型列表。相反，我们可以使用 Spring Framework 中的一个助手类，`ParameterizedTypeReference`，这个类设计用来在运行时持有类型信息，解决 这个问题。这意味着`RestTemplate`可以弄清楚要将 JSON 响应映射到哪个类。为了使用这个助手类，我们必须使用更为复杂的 `exchange()`方法而不是`RestTemplate`上的更简单的`getForObject()`方法。

# 组合 API 实现

最后，我们将查看组合微服务实现的最后一部分：`ProductCompositeServiceImpl.java`实现类。让我们一步步地来看：

1.  与核心服务一样，组合服务实现了其 API 接口，`ProductCompositeService`，并用`@RestController`注解标记为 REST 服务：

```java
package se.magnus.microservices.composite.product.services;

@RestController
public class ProductCompositeServiceImpl implements ProductCompositeService {
```

1.  实现类需要`ServiceUtil`bean 及其自己的整合组件，所以它们是在其构造函数中注入的：

```java
private final ServiceUtil serviceUtil;
private  ProductCompositeIntegration integration;

@Autowired
public ProductCompositeServiceImpl(ServiceUtil serviceUtil, ProductCompositeIntegration integration) {
    this.serviceUtil = serviceUtil;
    this.integration = integration;
}
```

1.  最后，API 方法如下实现：

```java
@Override
public ProductAggregate getProduct(int productId) {
    Product product = integration.getProduct(productId);
    List<Recommendation> recommendations = 
    integration.getRecommendations(productId);
    List<Review> reviews = integration.getReviews(productId);
    return createProductAggregate(product, recommendations,
    reviews, serviceUtil.getServiceAddress());
}
```

集成组件用于调用三个核心服务，并且使用一个助手方法`createProductAggregate()`，根据对集成组件的调用的响应创建`ProductAggregate`类型的响应对象。

助手方法`createProductAggregate()`的实现相当长，并不是很重要，因此在本章中省略；然而，它可以在本书的源代码中找到。

集成组件和复合服务的完整实现可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-composite-service/src/main/java/se/magnus/microservices/composite/product/services`文件夹中找到。

从功能角度来看，复合微服务的实现已经完成。在下一节中，我们将了解如何添加源代码以处理错误。

# 添加错误处理

在微服务架构中，大量的微服务通过同步 API 进行通信，例如使用 HTTP 和 JSON，以结构化和深思熟虑的方式处理错误至关重要。将协议特定的错误处理，如 HTTP 状态码，与业务逻辑分离也很重要。

在实现微服务时，可以认为应当添加一个单独的层来处理业务逻辑。这应该确保业务逻辑与协议特定的代码相分离，从而使得测试和重用更加容易。为了避免本书中提供的示例不必要的复杂性，我们省略了业务逻辑的单独层，即微服务直接在`@RestController`组件中实现其业务逻辑。

我在`util`项目中创建了一套 Java 异常，这些异常既被 API 实现使用，也被 API 客户端使用，最初有`InvalidInputException`和`NotFoundException`。有关详细信息，请参见`$BOOK_HOME/Chapter03/2-basic-rest-services/util/src/main/java/se/magnus/util/exceptions`。

# 全局 REST 控制器异常处理

为了将协议特定的错误处理从 REST 控制器中分离，即 API 实现，我在`util`项目中创建了一个工具类`GlobalControllerExceptionHandler.java`，它被注解为`@RestControllerAdvice`。

对于 API 实现抛出的每个 Java 异常，工具类都有一个异常处理方法，它将 Java 异常映射到一个适当的 HTTP 响应，即具有适当的 HTTP 状态和 HTTP 响应体。

例如，如果一个 API 实现类抛出`InvalidInputException`，工具类将其映射为状态码设置为`422`（`UNPROCESSABLE_ENTITY`）的 HTTP 响应。以下代码展示了这一点：

```java
@ResponseStatus(UNPROCESSABLE_ENTITY)
@ExceptionHandler(InvalidInputException.class)
public @ResponseBody HttpErrorInfo handleInvalidInputException(ServerHttpRequest request, Exception ex) {
    return createHttpErrorInfo(UNPROCESSABLE_ENTITY, request, ex);
}
```

同样，`NotFoundException`被映射到`404`（`NOT_FOUND`）HTTP 状态码。

无论何时 REST 控制器抛出这些异常中的任何一个，Spring 都会使用实用类来创建一个 HTTP 响应。

请注意，当 Spring 检测到无效请求（例如，请求中包含非数字的产品 ID）时，它会返回 HTTP 状态码`400`（`BAD_REQUEST`）。在 API 声明中，`productId`指定为整数。

要查看实用类的完整源代码，请参阅`$BOOK_HOME/Chapter03/2-basic-rest-services/util/src/main/java/se/magnus/util/http/GlobalControllerExceptionHandler.java`。

# API 实现中的错误处理

API 实现使用`util`项目中的异常来表示错误。它们将被报告回 REST 客户端，作为表明出了什么问题的 HTTP 状态码。例如，`Product`微服务实现类`ProductServiceImpl.java`使用`InvalidInputException`异常来返回一个指示无效输入的错误，以及使用`NotFoundException`异常告诉我们所请求的产品不存在。代码如下：

```java
if (productId < 1) throw new InvalidInputException("Invalid productId: 
    " + productId);
if (productId == 13) throw new NotFoundException("No product found for 
    productId: " + productId);
```

由于我们目前没有使用数据库，我们必须模拟何时抛出`NotFoundException`。

# API 客户端中的错误处理

API 客户端，即`Composite`微服务的集成组件，执行的是相反的操作；也就是说，它将`422`（`UNPROCESSABLE_ENTITY`）HTTP 状态码映射到`InvalidInputException`，并将`404`（`NOT_FOUND`）HTTP 状态码映射到`NotFoundException`。有关此错误处理逻辑的实现，请参阅`ProductCompositeIntegration.java`中的`getProduct()`方法。源代码如下：

```java
catch (HttpClientErrorException ex) {

    switch (ex.getStatusCode()) {

    case NOT_FOUND:
        throw new NotFoundException(getErrorMessage(ex));

    case UNPROCESSABLE_ENTITY :
        throw new InvalidInputException(getErrorMessage(ex));

    default:
        LOG.warn("Got a unexpected HTTP error: {}, will rethrow it", 
        ex.getStatusCode());
        LOG.warn("Error body: {}", ex.getResponseBodyAsString());
        throw ex;
    }
}
```

集成组件中`getRecommendations()`和`getReviews()`的错误处理要宽松一些——归类为尽力而为，意思是如果成功获取了产品信息但未能获取推荐信息或评论，仍然认为是可以的。但是，会在日志中写入警告。

要了解更多信息，请参阅`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-composite-service/src/main/java/se/magnus/microservices/composite/product/services/ProductCompositeIntegration.java`。

完成了代码和组合微服务的实现。在下一节中，我们将测试微服务和它们暴露的 API。

# 测试 API 手动

这是我们微服务的实现结束。让我们通过执行以下步骤来尝试它们：

1.  构建并作为后台进程启动它们。

1.  使用`curl`调用组合 API。

1.  停止它们。

首先，以后台进程的形式构建和启动每个微服务，如下所示：

```java
cd $BOOK_HOME/Chapter03/2-basic-rest-services/

./gradlew build
```

构建完成后，我们可以使用以下代码将我们的微服务作为后台进程启动到终端进程中：

```java
java -jar microservices/product-composite-service/build/libs/*.jar &
java -jar microservices/product-service/build/libs/*.jar &
java -jar microservices/recommendation-service/build/libs/*.jar &
java -jar microservices/review-service/build/libs/*.jar &
```

会有很多日志消息被写入终端，但在几秒钟后，事情会平静下来，我们会在日志中找到以下消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/7437d6fb-99f1-4fa9-957b-be6257567694.png)

这意味着它们都准备好接收请求。用以下代码尝试一下：

```java
curl http://localhost:7000/product-composite/1
```

经过一些日志输出，我们将得到一个类似于以下的 JSON 响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4cf8525d-ea4f-4c59-99f9-a076421e41dd.png)

为了获得美观的 JSON 响应，您可以使用`jq`工具：

```java
curl http://localhost:7000/product-composite/1 -s | jq .
```

这会导致以下输出（为了提高可读性，一些细节被`...`替换）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/771fc141-de97-432e-af16-a3f1d0f03b70.png)

如果您愿意，还可以尝试以下命令来验证错误处理是否如预期工作：

```java

# Verify that a 404 (Not Found) error is returned for a non-existing productId (13)
curl http://localhost:7000/product-composite/13 -i 
# Verify that no recommendations are returned for productId 113
curl http://localhost:7000/product-composite/113 -s | jq . 
# Verify that no reviews are returned for productId 213
curl http://localhost:7000/product-composite/213 -s | jq . 
# Verify that a 422 (Unprocessable Entity) error is returned for a productId that is out of range (-1)
curl http://localhost:7000/product-composite/-1 -i 
# Verify that a 400 (Bad Request) error is returned for a productId that is not a number, i.e. invalid format
curl http://localhost:7000/product-composite/invalidProductId -i 
```

最后，您可以使用以下命令关闭微服务：

```java
kill $(jobs -p)
```

如果您使用的是 Spring Tool Suite 或 IntelliJ IDEA Ultimate Edition 作为您的 IDE，您可以使用它们的 Spring Boot 仪表板一键启动和停止您的微服务。

下面的截图显示了 Spring Tool Suite 的使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/5017f9b2-a124-4c5a-95fa-cc52247a15e6.png)

下面的截图显示了 IntelliJ IDEA Ultimate Edition 的使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/871261b3-dbde-4c1d-afde-61ca65c7bdca.png)

在本节中，我们学习了如何手动启动、测试和停止合作微服务的系统景观。这类测试耗时较长，因此显然需要自动化。在接下来的两节中，我们将迈出学习如何自动化测试的第一步，测试单个微服务以及整个合作微服务的系统景观。在整个本书中，我们将改进我们如何测试微服务。

# 防止本地主机名查找缓慢

从 macOS Sierra 开始，在 macOS 上的 Java 程序中查找本地主机使用的 hostname 可能会花费很长时间，即 5 秒钟，使得测试变得非常缓慢。在使用 macOS Mojave 时，这个问题似乎得到了修复，但如果您使用的是较老版本的 macOS，这个问题很容易解决。

首先，您需要通过从 GitHub 下载一个小型工具并运行它来验证问题是否影响您：

```java
git clone https://github.com/thoeni/inetTester.git
java -jar inetTester/bin/inetTester.jar
```

假设程序响应了类似以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/c41f046a-ac2c-4f77-a856-2131fef48987.png)

如果您有 5 秒的响应时间，那么您遇到问题了！

解决方案是编辑`/etc/hosts`文件，在`localhost`之后添加您的本地主机名，在前面的示例中是`Magnuss-Mac.local`，例如：

```java
127.0.0.1 localhost Magnuss-Mac.local
::1       localhost Magnuss-Mac.local
```

重新运行测试。它应该以几毫秒的响应时间响应，例如：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/d1ba5f11-22f1-4ce4-a3fd-03e8486b5e13.png)

现在让我们看看如何为微服务添加隔离的自动化测试。

# 为微服务添加隔离的自动化测试

在我们完成实现之前，还需要编写一些自动化测试。

目前我们没有太多业务逻辑需要测试，所以不需要编写任何单元测试。相反，我们将重点测试我们微服务暴露的 API；也就是说，我们将以集成测试的方式启动它们，带有内嵌的 web 服务器，然后使用测试客户端执行 HTTP 请求并验证响应。随着 Spring WebFlux 的推出，出现了一个新的测试客户端`WebTestClient`，它提供了一个流畅的 API 来发送请求，然后在它的结果上应用断言。

以下是一个示例，我们通过执行以下操作来测试组合产品 API：

+   发送一个现有的产品的`productId`，并断言我们得到一个 200 的 HTTP 响应码和一个包含所需`productId`以及一个推荐和一个评论的 JSON 响应。

+   发送一个缺失的`productId`，并断言我们得到一个 404 的 HTTP 响应码和一个包含相关错误信息的 JSON 响应。

这两个测试的实现如下面的代码所示：

```java
@Autowired
private WebTestClient client;

@Test
public void getProductById() {
  client.get()
    .uri("/product-composite/" + PRODUCT_ID_OK)
    .accept(APPLICATION_JSON_UTF8)
    .exchange()
    .expectStatus().isOk()
    .expectHeader().contentType(APPLICATION_JSON_UTF8)
    .expectBody()
    .jsonPath("$.productId").isEqualTo(PRODUCT_ID_OK)
    .jsonPath("$.recommendations.length()").isEqualTo(1)
    .jsonPath("$.reviews.length()").isEqualTo(1);
}
```

让我们更详细地解释一下前面的源代码：

+   该测试使用流畅的`WebTestClient` API 来设置要调用的 URL `"/product-composite/" + PRODUCT_ID_OK`，并指定接受的响应格式，即 JSON。

+   在使用`exchange()`方法执行请求后，测试验证响应状态是 OK（200）并且实际的响应格式确实是 JSON（如所请求的）。

+   最终，该测试检查响应体，并验证它包含了关于`productId`以及推荐次数和评论数预期的信息。

第二个测试如下所示：

```java

@Test
public void getProductNotFound() {
  client.get()
    .uri("/product-composite/" + PRODUCT_ID_NOT_FOUND)
    .accept(APPLICATION_JSON_UTF8)
    .exchange()
    .expectStatus().isNotFound()
    .expectHeader().contentType(APPLICATION_JSON_UTF8)
    .expectBody()
    .jsonPath("$.path").isEqualTo("/product-composite/" + 
     PRODUCT_ID_NOT_FOUND)
    .jsonPath("$.message").isEqualTo("NOT FOUND: " + 
     PRODUCT_ID_NOT_FOUND);
}
```

让我们更详细地解释一下前面的源代码：

+   这个负测试在结构上与前面的测试非常相似；主要区别是它验证了返回了一个错误状态码，未找到（404），并且响应体包含了预期的错误消息。

为了单独测试组合产品 API，我们需要模拟其依赖项，即由集成组件`ProductCompositeIntegration`执行的对其他三个微服务的请求。我们使用 Mockito 来实现，如下所示：

```java
private static final int PRODUCT_ID_OK = 1;
private static final int PRODUCT_ID_NOT_FOUND = 2;
private static final int PRODUCT_ID_INVALID = 3;

@MockBean
private ProductCompositeIntegration compositeIntegration;

@Before
public void setUp() {

  when(compositeIntegration.getProduct(PRODUCT_ID_OK)).
    thenReturn(new Product(PRODUCT_ID_OK, "name", 1, "mock-address"));
  when(compositeIntegration.getRecommendations(PRODUCT_ID_OK)).
    thenReturn(singletonList(new Recommendation(PRODUCT_ID_OK, 1, 
    "author", 1, "content", "mock address")));
     when(compositeIntegration.getReviews(PRODUCT_ID_OK)).
    thenReturn(singletonList(new Review(PRODUCT_ID_OK, 1, "author", 
    "subject", "content", "mock address")));

  when(compositeIntegration.getProduct(PRODUCT_ID_NOT_FOUND)).
    thenThrow(new NotFoundException("NOT FOUND: " + 
    PRODUCT_ID_NOT_FOUND));

  when(compositeIntegration.getProduct(PRODUCT_ID_INVALID)).
    thenThrow(new InvalidInputException("INVALID: " + 
    PRODUCT_ID_INVALID));
}
```

让我们更详细地解释一下前面的源代码：

+   首先，我们在测试类中声明了三个常量，分别用于`PRODUCT_ID_OK`、`PRODUCT_ID_NOT_FOUND`和`PRODUCT_ID_INVALID`。

+   如果对集成组件调用`getProduct()`、`getRecommendations()`和`getReviews()`方法，并且`productId`设置为`PRODUCT_ID_OK`，则模拟将返回一个正常响应。

+   如果`getProduct()`方法以`PRODUCT_ID_NOT_FOUND`设置`productId`，则模拟将抛出`NotFoundException`。

+   如果以`PRODUCT_ID_INVALID`设置`productId`调用`getProduct()`方法，则模拟将抛出`InvalidInputException`。

可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/microservices/product-composite-service/src/test/java/se/magnus/microservices/composite/product/ProductCompositeServiceApplicationTests.java`找到对复合产品 API 的自动化集成测试的完整源代码。

三个核心微服务暴露的 API 上的自动化集成测试类似，但更简单，因为它们不需要模拟任何内容！测试的源代码可以在每个微服务的`test`文件夹中找到。

当执行构建时，Gradle 会自动运行测试：

```java
./gradlew build
```

然而，你可以指定只想运行测试（而不执行构建的其余部分）：

```java
./gradlew test
```

这是介绍如何为微服务编写隔离测试的介绍。在下一节中，我们将学习如何编写自动测试整个微服务景观的测试。在本章中，这些测试将是半自动化的。在后续章节中，测试将完全自动化，这是一个显著的改进。

# 添加对微服务景观的半自动化测试

当然，能够自动测试每个微服务是很有用的，但不够！

我们需要一种自动测试所有微服务的方法，以确保它们提供我们所期望的内容！

为此，我编写了一个简单的 bash 脚本，可以使用 `curl` 对 RESTful API 进行调用并验证其返回代码及其 JSON 响应的一部分，使用 `jq`。脚本包含两个辅助函数，`assertCurl()` 和 `assertEqual()`，以使测试代码更加紧凑，易于阅读。

例如，发送一个正常请求，期望状态码为 200，以及断言我们返回的 JSON 响应返回请求的`productId`，还附带三个推荐和三个评论，如下所示：

```java
# Verify that a normal request works, expect three recommendations and three reviews
assertCurl 200 "curl http://$HOST:${PORT}/product-composite/1 -s"
assertEqual 1 $(echo $RESPONSE | jq .productId)
assertEqual 3 $(echo $RESPONSE | jq ".recommendations | length")
assertEqual 3 $(echo $RESPONSE | jq ".reviews | length")

```

验证我们返回`404 (Not Found)`作为 HTTP 响应代码（当我们尝试查找不存在的产品）如下所示：

```java
# Verify that a 404 (Not Found) error is returned for a non-existing productId (13)
assertCurl 404 "curl http://$HOST:${PORT}/product-composite/13 -s" 
```

测试脚本实现了在*手动测试 API*部分描述的手动测试，可以在`$BOOK_HOME/Chapter03/2-basic-rest-services/test-em-all.bash`找到。

# 尝试测试脚本

为了尝试测试脚本，执行以下步骤：

1.  首先，像以前一样启动微服务：

```java
cd $BOOK_HOME/Chapter03/2-basic-rest-services
java -jar microservices/product-composite-service/build/libs/*.jar
& java -jar microservices/product-service/build/libs/*.jar &
java -jar microservices/recommendation-service/build/libs/*.jar &
java -jar microservices/review-service/build/libs/*.jar &
```

1.  一旦它们都启动完毕，运行测试脚本：

```java
./test-em-all.bash
```

1.  期望输出如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/34c2f31c-8138-4f03-9414-cfb4c0779f29.png)

1.  用以下命令关闭微服务：

```java
kill $(jobs -p)
```

在本节中，我们迈出了自动化测试合作微服务系统景观的第一步，所有这些都将在本章后续部分进行改进。

# 总结

现在我们已经使用 Spring Boot 构建了我们的几个微服务。在介绍了我们将在此书中使用的微服务景观之后，我们学习了如何使用 Spring Initializr 创建每个微服务的骨架项目。

接下来，我们学习了如何使用 Spring WebFlux 为三个核心服务添加 API，并实现了一个组合服务，该服务使用三个核心服务的 API 来创建它们中信息的聚合视图。组合服务使用 Spring Framework 中的`RestTemplate`类来对核心服务公开的 API 执行 HTTP 请求。在为服务添加错误处理逻辑后，我们在微服务架构上进行了一些手动测试。

我们通过学习如何在隔离环境中为微服务添加测试以及它们作为一个系统架构一起工作时的测试来结束这一章。为了为组合服务提供受控的隔离，我们使用 Mockito 模拟其对核心服务的依赖。整个系统架构的测试是通过一个 bash 脚本完成的，该脚本使用`curl`对组合服务的 API 执行调用。

有了这些技能，我们准备好了下一步，进入下一章的 Docker 和容器世界！在接下来的内容中，我们将学习如何使用 Docker 完全自动化测试一个合作微服务的系统架构。

# 问题

1.  使用**spring init** Spring Initializr CLI 工具创建新的 Spring Boot 项目时，列出可用依赖项的命令是什么？

1.  你如何设置**Gradle**，用一个命令就能构建多个相关联的项目？

1.  `@PathVariable`和`@RequestParam`注解是用来做什么的？

1.  在 API 实现类中，你如何将协议特定的错误处理与业务逻辑分开？

1.  **Mockito**是用来做什么的？
