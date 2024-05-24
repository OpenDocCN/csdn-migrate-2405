# Spring Security5 反应式应用实用指南（一）

> 原文：[`zh.annas-archive.org/md5/6DEAFFE8EE2C8DC4EDE2FE79BBA87B88`](https://zh.annas-archive.org/md5/6DEAFFE8EE2C8DC4EDE2FE79BBA87B88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

安全是创建应用程序最困难和高压的问题之一。当您必须将其与现有代码、新技术和其他框架集成时，正确保护应用程序的复杂性会增加。本书将向读者展示如何使用经过验证的 Spring Security 框架轻松保护他们的 Java 应用程序，这是一个高度可定制和强大的身份验证和授权框架。

Spring Security 是一个著名的、成熟的 Java/JEE 框架，可以为您的应用程序提供企业级的安全功能，而且毫不费力。它还有一些模块，可以让我们集成各种认证机制，我们将在本书中使用实际编码来深入研究每一个认证机制。

许多示例仍将使用 Spring MVC web 应用程序框架来解释，但仍将具有响应式编程的特色。

响应式编程正在受到关注，本书将展示 Spring Security 与 Spring WebFlux web 应用程序框架的集成。除了响应式编程，本书还将详细介绍其他 Spring Security 功能。

最后，我们还将介绍市场上可用的一些产品，这些产品可以与 Spring Security 一起使用，以实现现代应用程序中所需的一些安全功能。这些产品提供了新的/增强的安全功能，并且在各个方面与 Spring Security 协同工作。其中一些产品也得到了 Spring 社区的全力支持。

# 这本书适合谁

这本书适合以下任何人：

+   任何希望将 Spring Security 集成到他们的应用程序中的 Spring Framework 爱好者

+   任何热衷的 Java 开发人员，希望开始使用 Spring Framework 的核心模块之一，即 Spring Security

+   有经验的 Spring Framework 开发人员，希望能够亲自动手使用最新的 Spring Security 模块，并且也想开始使用响应式编程范式编写应用程序的人

# 本书涵盖了什么

[第一章]，*Spring 5 和 Spring Security 5 概述*，向您介绍了新的应用程序要求，然后介绍了响应式编程概念。它涉及应用程序安全以及 Spring Security 在应用程序中解决安全问题的方法。该章节随后更深入地介绍了 Spring Security，最后解释了本书中示例的结构。

[第二章]，*深入研究 Spring Security*，深入探讨了核心 Spring Security 的技术能力，即身份验证和授权。然后，该章节通过一些示例代码让您动手实践，我们将使用 Spring Security 设置一个项目。然后，在适当的时候，向您介绍了本书中将解释代码示例的方法。

[第三章]，*使用 SAML、LDAP 和 OAuth/OIDC 进行身份验证*，向您介绍了三种身份验证机制，即 SAML、LDAP 和 OAuth/OIDC。这是两个主要章节中的第一个，我们将通过实际编码深入研究 Spring Security 支持的各种身份验证机制。我们将使用简单的示例来解释每种身份验证机制，以涵盖主题的要点，并且我们将保持示例简单以便易于理解。

第四章，*使用 CAS 和 JAAS 进行身份验证*，向您介绍了企业中非常普遍的另外两种身份验证机制——CAS 和 JAAS。这是两个主要章节中的第二个，类似于[第三章](https://cdp.packtpub.com/hands_on_spring_security_5_for_reactive_applications/wp-admin/post.php?post=25&action=edit#post_28)，*使用 SAML、LDAP 和 OAuth/OIDC 进行身份验证*，最初将涵盖这些身份验证机制的理论方面。本章通过使用 Spring Security 实现一个完整的示例来结束这个主题。

第五章，*与 Spring WebFlux 集成*，向您介绍了作为 Spring 5 的一部分引入的新模块之一——Spring WebFlux。Spring WebFlux 是 Spring 生态系统中的 Web 应用程序框架，从头开始构建，完全是响应式的。本章将介绍 Spring Security 的响应式部分，并详细介绍 Spring WebFlux 框架本身。首先，我们将通过一个示例向您介绍 Spring WebFlux，然后我们将在基础应用程序上构建额外的技术能力。

第六章，*REST API 安全*，首先介绍了有关 REST 和 JWT 的一些重要概念。然后介绍了 OAuth 的概念，并使用实际编码示例解释了简单和高级的 REST API 安全，重点是利用 Spring Framework 中的 Spring Security 和 Spring Boot 模块。示例将使用 OAuth 协议，并将使用 Spring Security 充分保护 REST API。除此之外，JWT 将用于在服务器和客户端之间交换声明。

第七章，*Spring 安全附加组件*，介绍了许多产品（开源和付费版本），可以考虑与 Spring Security 一起使用。这些产品是强有力的竞争者，可以用来实现您在应用程序中寻找的技术能力，以满足各种安全要求。我们将通过概述应用程序中需要解决的技术能力的要点来向您介绍产品，然后再看一下相关产品，并解释它如何提供您需要的解决方案。

# 为了充分利用本书

1.  本书包含许多示例，全部在 Macintosh 机器上使用 IDE（IntelliJ）编码和执行。因此，为了轻松跟随示例，使用 macOS 和 IntelliJ 将会大有帮助。但是，所有代码都可以在 Macintosh、Windows 和 Linux 系统上执行。

1.  需要具备基本到中级的使用 Java 和 Spring Framework 构建应用程序的经验，才能轻松阅读本书。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压或提取文件夹。

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Spring-Security-5-for-Reactive-Applications`](https://github.com/PacktPublishing/Hands-On-Spring-Security-5-for-Reactive-Applications)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/HandsOnSpringSecurity5forReactiveApplications_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/HandsOnSpringSecurity5forReactiveApplications_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“`Flux<T>`是一个带有基本流操作并支持*0.*.*n*个元素的`Publisher<T>`。”

代码块设置如下：

```java
public abstract class Flux<T>
    extends Object
    implements Publisher<T>
```

任何命令行输入或输出都是这样写的：

```java
curl http://localhost:8080/api/movie -v -u admin:password
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。这是一个例子：“输入用户名为`admin`，密码为`password`，然后点击“登录”。”

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第一章：Spring 5 和 Spring Security 5 概述

本书希望读者熟悉 Spring 框架（任何版本）和 Spring Security（任何版本）。这是一个引子章节，介绍了一些最重要的概念；我们将在后续章节中扩展这些概念。

本章将向你介绍新的应用需求，然后介绍反应式编程概念。它涉及应用安全以及 Spring Security 如何解决应用程序中的安全问题。

我们将继续使用 Spring Security，然后通过解释本章中示例的结构来结束本章。这非常重要，因为我希望读者在引入新概念时感到舒适。

在本章中，我们将涵盖以下主题：

+   新一代应用需求

+   反应式编程

+   反应式应用

+   Spring 框架

+   Java 中的反应式景观

+   Spring 框架和反应式应用程序

+   应用安全

+   Spring Security

+   Spring Security 的核心功能

+   Spring Security 5 的新功能

+   Spring Security 的工作原理

+   核心 Spring Security 模块

# 示例的结构

重要的是，你要理解我们在这本书中将如何使用示例。由于本书试图详细介绍 Spring Security 5 及其反应性方面，我们不会在整本书中只有一个用例。相反，我们将不断创建小型项目，以帮助你理解所涵盖的每个核心概念。以下是本书中代码库的一些重要方面：

+   大多数概念将使用独立的 Spring Boot 项目进行介绍。

+   有时，我们将使用著名的 Spring Initializr ([`start.spring.io/`](https://start.spring.io/))来启动我们的示例 Spring Boot 应用程序。在其他情况下，我们将从我们已经拥有的基础项目开始，并通过代码引入更多概念。

+   通常，我们将使用 Java 配置。有时，我们可能会使用基于 XML 的配置。

+   我们将尽可能简化示例，以便不会偏离引入的核心概念。

+   尽管本书侧重于反应式应用程序，但我们不会在每次引入时都进行覆盖。有时，我们只会进行普通的命令式编程，因为了解反应式编程并在需要时使用它更为重要。并不是说我们必须在所有可能的地方都使用反应式代码，只需在适当的地方使用即可。

+   我们将为所有项目使用 VS Code，并充分利用 VS Code 中的扩展。我们还将使用 Spring Initializr 扩展，而不是使用在线 Spring Initializr。

+   在本书中，我们将大部分时间使用 Maven。可能会有一种情况，我们会尝试使用 Gradle。

+   有时，我们可能会使用 IntelliJ IDE，你会看到一些屏幕截图显示这一点。

+   我们将使用最新的 Spring Boot 发布版本，即**2.0.0. RELEASE**。这是撰写本书时 Spring Boot 的最新发布版本。

# 新一代应用需求

以下是一些核心的新应用需求：

+   **高度可扩展**：社交平台在过去十年里呈指数级增长，人们比以往任何时候都更懂技术。

+   **弹性、容错和高可用性**：在现代时代，企业不愿意接受应用程序的停机时间；即使是几秒钟的停机时间也会给许多大型企业带来巨大的损失。

+   **高性能**：如果你的网站速度慢，人们就有离开并寻找替代方案的倾向。人们的注意力很短，如果你的网站表现不佳，他们就不会停留或回来。

+   **超个性化**：用户需要个性化的网站而不是通用的网站，这给服务器带来了巨大的压力，需要实时进行许多密集的分析。

随着技术进入了每个人的手中（以某种形式，大多数人都在使用技术），用户对隐私政策和应用程序安全非常熟悉。他们了解大多数安全要求，公司花时间教育用户安全的重要性以及他们应该如何寻找应用程序中的安全漏洞。你可能已经知道，如果一个网站使用 HTTP 而不是 HTTPS（SSL）和 Chrome 标签，这些网站在地址栏中会清楚地显示给用户为不安全。随着越来越多的人对技术有了更多了解，这些方面在大多数用户中都是众所周知的，安全已成为 IT 领域中最受关注的话题之一。

另一个重要方面是数据隐私。一些用户不担心分享他们的数据，但有些用户则非常谨慎。许多政府意识到了这种担忧，并开始在这个领域制定许多规则和法规。其中一个数据隐私规则就是著名的**通用数据保护条例**（**GDPR**），自 2018 年 5 月 25 日起生效。

**欧洲联盟**（**EU**）GDPR 取代了《数据保护指令 95/46/EC》，旨在协调欧洲各地的数据隐私法律，保护和赋予所有欧盟公民数据隐私权，并重塑该地区组织处理数据隐私的方式。更多信息，请查看此链接：[`gdpr-info.eu/art-99-gdpr/`](https://gdpr-info.eu/art-99-gdpr/)。

现代浏览器也为我们提供了足够的工具，以更详细的方式查看 Web 应用程序的许多方面，特别是安全方面。此外，浏览器还增加了越来越多的功能（例如，曾经 cookie 是存储数据的选项之一，但现在我们有其他选项，比如**localStorage**和**indexedDB**），使其更容易受到来自一直在观望的黑客的安全漏洞和攻击。

为了满足这些各种应用程序要求，组织会选择公共云提供商而不是自己的本地数据中心。这使应用程序处于更加脆弱的状态，安全方面成为首要问题。构成应用程序的各个组件需要高度安全和不可被黑客攻击。

技术领域不断发展，新技术不断涌现并被开发者社区所采纳。由于这个原因和它带来的各种技术改进，许多组织不得不采用这些技术来在市场中竞争。这再次给安全带来了巨大压力，因为这些闪亮的新技术可能没有足够的努力将安全作为主要要求。

全面而言，在应用程序中具有严格的安全性是一个不言而喻的要求，组织和最终用户都很清楚这一事实。

# 响应式编程

在过去几年中，JavaScript 已成为最常用的语言之一，你可能已经在 JavaScript 的世界中听说过**reactive**这个术语，无论是在后端还是前端的上下文中。

那么，*什么是响应式编程？*—这是一种以异步数据流为核心的编程范式。数据以消息的形式在程序的各个部分之间流动。消息由`Producer`产生，并以一种“发出即忘记”的方式工作，程序产生一条消息然后忘记它。已订阅（表现出兴趣）此类消息的`Subscriber`会收到消息，处理它，并将输出作为消息传递给程序的其他部分来消费。

在数据库领域，NoSQL 从关系数据库中产生了巨大变革。同样，这种编程范式是从传统的编程范式（命令式编程）中产生了巨大变革。好消息是，即使不太了解，您在日常编码生活中已经编写了一些反应式代码。只要您看到**流**这个词，您就间接地使用了一小部分反应式代码。这种编程有自己的名称，并且这一方面在行业中变得更加主流。许多语言都理解了这带来的优势，并开始原生支持这种编程范式。

# 反应式应用

在本章的前一部分，我们讨论了过去十年应用程序需求的巨大变化。为了满足这一需求，出现了一种名为反应式应用的应用开发概念。

了解反应式编程和反应式应用之间的区别很重要。采用反应式编程并不会产生反应式应用，但是反应式编程的概念肯定可以帮助构建反应式应用。

了解反应式宣言将有助于您理解反应式应用/系统，因为宣言清楚地规定了反应式应用的每个方面。

# 反应式宣言

**宣言**是一项公开宣布的意图、观点、目标或动机，如政府、主权国家或组织发布的宣言（[`www.dictionary.com/browse/manifesto`](http://www.dictionary.com/browse/manifesto)）。

**反应式宣言**清楚地阐述了发布者的观点，根据这一宣言可以开发出反应式应用。

根据反应式宣言（[`www.reactivemanifesto.org/`](https://www.reactivemanifesto.org/)），反应式系统应该是响应式的、弹性的、具有弹性和消息驱动的。

让我们更详细地了解这些术语。本节大部分内容来自在线反应式宣言，稍作修改以便更容易理解。

# 响应式

在出现问题的情况下，响应系统可以快速检测到问题并有效处理。这些系统还能够提供一致的响应时间，并建立上限，保证最低的**服务质量**（**QoS**）。由于这些特点，这些系统能够建立终端用户的信心，简化错误处理，并鼓励终端用户更多的互动。

# 弹性

在失败的情况下，弹性系统保持响应和可交互。应用程序中的**弹性**可以通过以下方式实现：

+   **复制**：在多个地方运行相同的组件，以便如果一个失败，另一个可以处理，并且应用程序可以正常运行。

+   **封装/隔离**：特定组件的问题被包含和隔离在该组件内部，并且不会干扰其他组件或作为复制的其他相似组件。

+   **委托**：在组件出现问题的情况下，控制会立即转移到另一个运行在完全不同上下文中的相似组件。

# 弹性

弹性系统可以在输入速率增加或减少时轻松自动扩展（增加或减少资源）。这种系统没有任何争用点，并且可以随意复制组件，分发负载增加。这些系统的设计方式确保了在需要扩展时，可以通过增加更多的商品硬件和软件平台来以非常具有成本效益的方式进行，而不是使用昂贵的硬件和许可软件平台。

# 消息驱动

在响应式应用中，主要方面之一是使用异步消息将数据从一个组件传递到另一个组件。这带来了组件之间的松耦合，并有助于实现位置透明性（只要组件是可到达/可发现的，它可以位于任何地方的单个节点或节点集群中）。创建消息，发布并忘记。注册的订阅者接收消息，处理它，并广播消息以便其他订阅者完成其工作。这是响应式编程的核心方面之一，也是响应式系统所需的基本方面之一。这种“发射和忘记”的概念带来了一种非阻塞的通信方式，从而产生了高度可扩展的应用程序。

以下图表（*图 1*）清楚地以图形方式展示了响应式宣言。它还清楚地展示了响应式宣言中主要概念之间的关系：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/0c837321-50ac-422f-993a-c12aece10ded.png)

图 1：响应式宣言

由于响应式应用是响应式、弹性、可伸缩和消息驱动的，这些应用本质上是高度灵活、高度可扩展、松耦合和容错的。

Mateusz Gajewski 在`www.slideshare.net`上分享的一个演示中，以非常好的方式总结了响应式宣言：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/f2dc861f-ce23-40b4-9240-691ca42cee51.png)

图 2：Mateusz Gajewski 构想的响应式宣言

# Spring 框架

**Spring 框架**是构建 Java 应用程序的事实标准。在过去的十年中，它随着每个主要版本的发布而不断成熟。 Spring 框架 5 于 2017 年 9 月作为 5.0.0 版正式发布；这是自 2013 年发布的上一个版本以来对框架的重要（主要）发布。

Spring 5 的一个重大新增功能是引入了一个基于核心响应式基础构建的功能性 Web 框架 Spring WebFlux。响应式编程正在悄悄地渗透到框架中，并且框架内的许多核心模块在很大程度上都在本质上支持响应式编程。由于框架已经开始原生支持响应式编程，因此这种编程的核心方面已经得到完全实现，并且许多模块都遵循了这种编程方式。此外，许多响应式概念已经成为框架内的通用语言。

需要注意的是，Spring 的响应式概念是直接从 Java 8 的**Reactor Core 库**中提取的，该库实现了响应式编程范式。 Reactor Core 是建立在*Reactive Streams 规范*之上的，这是在 Java 世界中构建响应式应用的行业标准。

另一个重要特性是包括了一种新的方式来测试这种应用程序。我们在（第五章，*与 Spring WebFlux 集成*）中有一个专门的章节介绍 Spring WebFlux，其中将更详细地介绍这些方面。

作为一个重大发布，它增加或增强了大量内容。但我们不打算列出其所有功能。完整列表可以在此链接找到：[`github.com/spring-projects/spring-framework/wiki/What%27s-New-in-Spring-Framework-5.x`](https://github.com/spring-projects/spring-framework/wiki/What%27s-New-in-Spring-Framework-5.x)*.*

# Java 中的响应式景观

当你从传统的编程模型转变过来时，很难理解响应式概念。随后的一些部分旨在向您介绍响应式概念以及它们如何演变为现在的状态。

# 响应式流和响应式流规范

Reactive Streams 的官方文档（[`www.reactive-streams.org/`](http://www.reactive-streams.org/)）表示：*Reactive Streams 是提供异步流处理和非阻塞背压的标准的一个倡议。这包括针对运行时环境（JVM 和 JavaScript）以及网络协议的努力。*

它始于 2013 年一群公司的倡议。2015 年 4 月，1.0 版规范发布，同时有多个实现（如 Akka Streams 和 Vert.x）可用。该规范的目标是将其纳入官方 Java 标准库，并在 2017 年，随着 JDK9 的发布，它正式进入其中。与任何规范一样，最终目标是有多个符合规范的实现，并随着时间的推移，规范会不断发展。规范包括一些核心接口，围绕这些接口的一些规则，以及一个**技术兼容性测试套件**（**TCK**）。

TCK 是一套测试，用于检查**Java 规范请求**（**JSR**）实现的正确性/符合性。在**Java 社区流程**（**JCP**）中，TCK 是批准 JSR 所需的三个组成部分之一。另外两个是 JSR 规范和 JSR 参考实现。Java 平台的 TCK 称为**Java 兼容性测试套件**（**JCK**）。

作为一项规范，它使得尊重规范的任何实现都能相互合作和互操作。例如，使用 Akka 编写的实现可以在不出现问题的情况下通过反应流协议与 Vert.x 实现进行通信。采用情况正在增加，目前，符合规范的更多实现正在以不同语言编写的形式发布：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/889be598-8a2a-46ac-b42d-e926af183090.png)

图 3：反应流规范/API

前述图清楚地显示了**反应流规范**。以下是一些重要的规范规则：

+   “发布者”到“订阅者”和“订阅者”到“发布者”的调用不应该是并发的。

+   “订阅者”可以同步或异步执行其工作，但始终必须是非阻塞的。

+   从“发布者”到“订阅者”应该定义一个上限。在定义的边界之后，缓冲区溢出会发生，并可能导致错误。

+   除了**NullPointerException**（**NPE**）之外，不会引发其他异常。在 NPE 的情况下，“发布者”调用`onError`方法，“订阅者”取消“订阅”。

在前述对反应流的定义中，有一些非常重要的术语，即**非阻塞**和**反压**，我们将更深入地探讨一下，以了解反应流的核心概念。

# 非阻塞

**非阻塞**意味着线程永远不会被阻塞。如果线程需要阻塞，代码会以一种使线程在正确时间得到通知并继续进行的方式编写。反应式编程让您实现非阻塞、声明式和事件驱动的架构。

写非阻塞应用程序的一种方法是使用消息作为发送数据的手段。一个线程发送请求，然后很快，该线程被用于其他事情。当响应准备好时，它会使用另一个线程传递回来，并通知请求方，以便进一步处理可以继续进行：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/1323eef4-40e3-40e8-895a-fe526156fa6e.png)

图 4：非阻塞

非阻塞概念已经被众所周知的框架实现，如 Node.js 和 Akka。Node.js 使用的方法是单个线程以多路复用的方式发送数据。

在电信和计算机网络中，多路复用（有时缩写为 muxing）是一种将多个模拟或数字信号合并成一个信号的方法，通过共享介质。其目的是共享昂贵的资源。有关多路复用的更多信息，您可以访问以下链接：[`www.icym.edu.my/v13/about-us/our-news/general/722-multiplexing.html`](http://www.icym.edu.my/v13/about-us/our-news/general/722-multiplexing.html)。

# 反压

在理想情况下，`生产者`产生的每条消息都会在产生时立即传递给`订阅者`，而不会有任何延迟。有可能`订阅者`无法以与产生速率相同的速度处理消息，这可能会使其资源受到压制。

**背压**是一种方法，通过该方法`订阅者`可以告诉`生产者`以较慢的速度发送消息，以便给`订阅者`时间来正确处理这些消息，而不会对其资源施加太大压力。

由于这是第一章，我们只是向您介绍了这些重要的响应式概念。代码示例将在后续章节中介绍。

现在我们对响应式流和响应式流规范有了一个简要的了解，我们将进入 Java 中的下一个重要的响应式概念，即响应式扩展。

# 响应式扩展

**响应式扩展**（**Rx 或 ReactiveX**）（[`msdn.microsoft.com`](https://msdn.microsoft.com)）是一个使用可观察序列和 LINQ 风格查询操作来组合异步和基于事件的程序的库。数据序列可以采用多种形式，例如来自文件或网络服务的数据流、网络服务请求、系统通知或一系列事件，例如用户输入。

如前述定义所述，这些是允许使用观察者模式进行流组合的 API。在继续之前，我有责任向您介绍观察者模式。以下是这种模式的定义，它非常直观：

观察者模式定义了一个提供者（也称为主题或可观察者）和零个、一个或多个观察者（订阅者）。观察者向提供者注册，每当预定义的条件、事件或状态发生变化时，提供者会自动通过调用观察者的方法来通知所有观察者。有关观察者模式的更多信息，您可以参考此链接：[`docs.microsoft.com/en-us/dotnet/standard/events/observer-design-pattern`](https://docs.microsoft.com/en-us/dotnet/standard/events/observer-design-pattern)。

数据可以以多种形式流动，例如流或事件。响应式扩展让您将这些数据流转换为可观察对象，并帮助您编写响应式代码。

Rx 在多种语言中实现，包括 Java（RxJava）。可以在[`reactivex.io/`](http://reactivex.io/)找到已实现的语言的完整列表和有关 Rx 的更多详细信息。

# RxJava

**RxJava**是 ReactiveX 的 Java VM 实现，它是通过使用可观察序列来组合异步和基于事件的程序的库。

RxJava 是由 Netflix 将.NET 移植到 Java 世界的。经过近两年的开发，API 的稳定版本于 2014 年发布。此稳定版本针对 Java（版本 6 及以上）、Scala、JRuby、Kotlin 和 Clojure。

RxJava 是一个单一的 JAR 轻量级库，专注于 Observable 抽象。它便于与各种外部库集成，使库与响应式原则保持一致。一些例子是`rxjava-jdbc`（使用 RxJava Observables 进行数据库调用）和 Camel RX（使用 RxJava 的 Reactive Extensions 支持 Camel）。

# 响应式流和 RxJava

RxJava 2.x 是从其前身 RxJava 1.x 进行了完全重写。

RxJava 1.x 是在 Reactive Streams 规范之前创建的，因此它没有实现它。另一方面，RxJava 2.x 是基于 Reactive Streams 规范编写的，并完全实现了它，还针对 Java 8+。RxJava 1.x 中的类型已经完全调整以符合规范，并在重写时经历了重大变化。值得注意的是，存在一个桥接库（[`github.com/ReactiveX/RxJavaReactiveStreams`](https://github.com/ReactiveX/RxJavaReactiveStreams)），它在 RxJava 1.x 类型和 Reactive Streams 之间建立桥梁，使 RxJava 1.x 能够通过 Reactive Streams TCK 兼容性测试。

在 RxJava 2.x 中，许多概念保持不变，但名称已更改以符合规范。

我们不会深入研究 RxJava，因为这是一个庞大的主题，有很多书籍可以深入了解 RxJava。

# JDK 9 的新增内容

作为 JDK 9 的并发更新的一部分（JEP 266），Reactive Streams 被添加到了 Java 标准库中。Reactive Streams 于 2013 年由一些知名组织发起，他们希望标准化异步数据在软件组件之间交换的方法。很快，这个概念被行业采纳，并出现了许多实现，它们都有类似的核心概念，但缺乏标准的命名和术语，特别是接口和包命名方面。为了避免多种命名方式，并实现不同实现之间的互操作性，JDK 9 包含了基本接口作为 Flow Concurrency 库的一部分。这使得应用程序想要实现 Reactive Streams 依赖于这个库，而不是将特定的实现包含到代码库中。因此，很容易在不产生任何麻烦的情况下在不同实现之间切换。

这些接口被编码为`java.util.concurrent.Flow`类中的静态接口。

# 重要接口

Java 9 中的 Reactive Streams 规范围仅涉及四个接口——`Publisher`、`Subscriber`、`Subscription`和`Processor`。该库还包括一个`Publisher`实现——`SubmissionPublisher`。所有这些都包含在 Java 标准库的`java.util.concurrent`包中。我们将在以下子章节中介绍这些接口。

# 发布者接口

这个接口的定义如下：

```java
public interface Publisher<T> {
  public void subscribe(Subscriber<? super T> s);
}
```

正如你所看到的，`Publisher`允许`Subscriber`接口订阅它，以便在`Publisher`产生消息时接收消息。

# 订阅者接口

这个接口的定义如下：

```java
public interface Subscriber<T> {
  public void onSubscribe(Subscription s);
  public void onNext(T t);
  public void onError(Throwable t);
  public void onComplete();
}
```

正如你所看到的，`Subscriber`接口的`onSubscribe`方法允许`Subscriber`在`Publisher`接受`Subscription`时得到通知。当新项目发布时，`onNext`方法被调用。正如其名称所示，当出现错误时，将调用`onError`方法，当`Publisher`完成其功能时，将调用`onComplete`方法。

# 订阅接口

这个接口的定义如下：

```java
public interface Subscription {
  public void request(long n);
  public void cancel();
}
```

请求方法用于接受项目的请求，取消方法用于取消`Subscription`。

# 处理器接口

这个接口的定义如下：

```java
public interface Processor<T, R> extends Subscriber<T>, Publisher<R> {
}
```

它继承自`Publisher`和`Subscriber`接口，因此继承了这些接口的所有方法。主要的方面是`Publisher`可以产生一个项目，但`Subscriber`可以消耗与`Publisher`产生的项目不同的项目。

# Spring 框架和响应式应用

Spring 框架在 2013 年采用了响应式（与响应式诞生并变得更加主流的同时），发布了 Reactor 1.0 版本。这是 Spring 框架 4.0 版本发布并与 Pivotal 合作的时候。2016 年，Spring 的 4.3 版本与 Reactor 的 3.0 版本一起发布。在这个时期，Spring 5.0 版本的开发也在积极进行中。

随着新一代应用程序的需求，许多传统的编码实践受到了挑战。其中一个主要方面是摆脱阻塞 IO，并找到替代传统命令式编程的方法。

由 Servlet 容器支持的 Web 应用程序在本质上是阻塞的，Spring 5 通过引入基于响应式编程的全新 Web 应用程序框架 Spring WebFlux，在 Web 应用程序开发方面做出了很大贡献。

Spring 也采用了 Rx，并在 Spring 5 中以多种方式使用了它。在 Spring 5 中，响应式特性在许多方面都已经内置，帮助开发人员以渐进的方式轻松采用响应式编程。

Pivotal 在 Reactor 上投入了大量资源，但也暴露了 API，允许开发人员在 Reactor 和 RxJava 之间选择他们喜欢的库。

以下图示了 Spring 5 对响应式编程的支持：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/d655fc0b-14d0-4f74-a358-9d23692d570a.png)

图 5：Spring Framework + Reactor + Rx

Reactor 是 Pivotal（**SpringSource**）对实现 Reactive Streams 规范的回应。如前所述，Spring 在 Reactor 上投入了大量资源，本节旨在深入了解 Reactor。

Reactor 是第四代基于 Reactive Streams 规范在 JVM 上构建非阻塞应用程序的响应式库。

**Project Reactor**历史概述可以用以下图示表示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/dac8af45-ddb4-4573-bf79-0c71571f4115.png)

图 6：Project Reactor 历史

上图显示了 Project Reactor 的主要发布版本。该项目于 2013 年启动（1.x 版本），3.x 的主要发布版本于 2016 年发布。截至撰写本书时，该框架的核心模块版本为 3.1.8.RELEASE。

现在我们对 Spring Framework 及其与响应式编程的关系有了简要的了解，让我们深入了解一下 Project Reactor。

# Reactor 中的模块

随着 Reactor 3.0 的最新发布，该项目已经考虑到了模块化。Reactor 3.0 由四个主要组件组成，分别是 Core、IO、Addons 和 Reactive Streams Commons。

+   **Reactor Core** ([`github.com/reactor/reactor-core`](https://github.com/reactor/reactor-core))：Reactor 中的主要库。它提供了基础的、非阻塞的 JVM 兼容的 Reactive Streams 规范实现。它还包含了 Reactor 类型的代码，如`Flux`和`Mono`。

+   **Reactor IO** ([`github.com/reactor/reactor-ipc`](https://github.com/reactor/reactor-ipc))：它包含了支持背压的组件，可用于编码、解码、发送（单播、多播或请求/响应），然后服务连接。它还包含了对**Kafka** ([`kafka.apache.org/`](https://kafka.apache.org/))、**Netty** ([`netty.io/`](http://netty.io/))和**Aeron** ([`github.com/real-logic/aeron`](https://github.com/real-logic/aeron))的支持。

+   **Addons** ([`github.com/reactor/reactor-addons`](https://github.com/reactor/reactor-addons))：顾名思义，这些是由三个组件组成的附加组件：

+   `reactor-adapter`：包含了与 RxJava 1 或 2 类型的桥接，如 Observable、Completable、Single、Maybe 和 Mono/Flux 来回转换。

+   `reactor-logback`：支持异步 reactor-core 处理器上的 logback。

+   `reactor-extra`：包含了`Flux`的更多操作，包括求和和平均值等数学运算。

+   **Reactive Streams Commons** ([`github.com/reactor/reactive-streams-commons`](https://github.com/reactor/reactive-streams-commons))：Spring 的 Reactor 和 RxJava 之间的协作实验项目。它还包含了两个项目都实现的 Reactor-Streams 兼容操作符。在一个项目上修复的问题也会在另一个项目上修复。

# Reactor Core 中的响应式类型

Reactor 提供了两种响应式类型，`Flux`和`Mono`，它们广泛实现了 Rx。它们可以被表示为一个时间线，其中元素按照它们到达的顺序进行排序。重要的是要掌握这两种类型。让我们在以下小节中做到这一点。

# Flux 响应式类型

一个具有 Rx 操作符的 Reactive Streams 发布者，它会发出*0*到*N*个元素，然后完成（成功或出现错误）。更多信息，请查看以下链接：[`projectreactor.io`](https://projectreactor.io)

`Flux<T>`是一个带有基本流操作的`Publisher<T>`，支持*0.*.*n*个元素。

`Flux`的定义如下：

```java
public abstract class Flux<T>
 extends Object
 implements Publisher<T>
```

如`Flux`文档中所示的以下图示更详细地解释了`Flux`的工作原理：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/5e2ee3fa-4291-4813-9457-d4404fec9a26.png)

图 7：`Flux`的工作原理

Flux 支持在 Spring 5 和其他重要模块中，包括 Spring Security。对`Flux`进行操作将创建新的发布者。

有关更多信息，请参阅 Reactor Flux 文档：[`projectreactor.io/docs/core/release/api/reactor/core/publisher/Flux.html`](https://projectreactor.io/docs/core/release/api/reactor/core/publisher/Flux.html)。

现在，让我们看一些代码示例，展示了`Flux`的用法：

+   创建空的`Flux`：

```java
Flux<String> emptyFlux = Flux.empty();
```

+   创建带有项目的`Flux`：

```java
Flux<String> itemFlux = Flux.just("Spring”, "Security”, "Reactive”);
```

+   从现有列表创建`Flux`：

```java
List<String> existingList = Arrays.asList("Spring”, "Security”, "Reactive”);
Flux<String> listFlux = Flux.fromIterable(existingList);
```

+   创建以无限方式每隔`x`毫秒发出的`Flux`：

```java
Flux<Long> timer = Flux.interval(Duration.ofMillis(x));
```

+   创建发出异常的`Flux`：

```java
Flux.error(new CreatedException());
```

# `Mono`反应式类型

一个具有基本 Rx 运算符的 Reactive Streams Publisher，通过发出一个元素或出现错误来成功完成。

- Mono JavaDoc

`Mono<T>`是支持*0*..*1*个元素的`Publisher<T>`。

`Mono`的定义如下：

```java
public abstract class Mono<T>
    extends Object
    implements Publisher<T>
```

如文档中所述，以下图显示了`Mono`的工作原理：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/fcab5a6e-6e9e-40b6-a689-b0d0abe4ed0a.png)

图 08：`Mono`的工作原理

`Mono<Void>`应该用于没有值完成的`Publisher`。文档使用了一个自解释的大理石图解释了每种方法及其工作原理。同样，这种类型也受到 Spring 5 和 Spring Security 的支持。

`Mono`的 JavaDoc 包含更多信息：[`projectreactor.io/docs/core/release/api/reactor/core/publisher/Mono.html`](https://projectreactor.io/docs/core/release/api/reactor/core/publisher/Mono.html)。

让我们看一些例子：

+   创建空的`Mono`：

```java
Mono<String> emptyMono = Mono.empty();
```

+   创建带有值的`Mono`：

```java
Mono<String> itemMono = Mono.just("Spring Security Reactive”);
```

+   创建发出异常的`Mono`：

```java
Mono.error(new CreatedException());
```

# 数据流类型

广义上，数据流可以分为两种类型：

+   **冷数据流**：这有许多名称，比如**冷源**，**冷可观察对象**和**冷发布者**。它们只在有人订阅时才发出数据，因此从开始产生的所有消息都会传递给订阅者。如果新的`Subscriber`连接到它，消息将按升序重放，对于任何新的`Subscriber`也是如此。`Subscriber`还可以规定`Publisher`应该发出消息的速率。这些数据流是应用反应式背压（`request(n)`）的良好候选者，例如数据库游标或文件流（读取文件）。

+   **热数据流**：这又有许多不同的名称，比如**热源**，**热可观察对象**和**热发布者**。它们发出数据，而不管是否连接了任何订阅者。当新的`Subscriber`连接时，它只会从那个时间点开始发出消息，并且不能重放从头开始的消息。它们不能暂停消息的发出，因此需要另一种机制来控制流量，比如缓冲区。这种流的例子包括鼠标事件和股票价格。

重要的是要注意，流上的运算符可以改变它们的属性，从冷到热，反之亦然。此外，有时会发生热和冷之间的合并，它们的属性也会改变。

# Reactor 和 RxJava

两者之间的主要区别之一是 RxJava 2.x 兼容 Java 6+，而 Reactor 兼容 Java 8+。如果您选择 Spring 5，我建议您使用 Reactor。如果您对 RxJava 2.x 感到满意，就没有必要迁移到 Reactor。Reactor 是 Reactive Streams 规范的实现，因此您可以保持对底层实现的不可知性。

# 反应式 Web 应用程序

Spring 5 将反应式概念引入了 Web 应用程序开发的世界，并包括了许多重要组件。让我们在这里介绍它们。

# Spring WebFlux

Spring 5 内置了一个响应式堆栈，使用它可以构建基于 Reactive Streams 的 Web 应用程序，可以在新的非阻塞服务器上运行，例如 Netty、Undertow 和 Servlet 容器，运行在大于 3.1 的 Servlet 规范上。

现有的 Web 应用程序框架，如 Spring MVC，从一开始就是为 Servlet 容器构建的，但是 Spring 5 带来了一个新的 Web 应用程序框架，Spring WebFlux，专为响应式而创建。本书中有一个专门的章节涵盖了 Spring WebFlux（第五章，*与 Spring WebFlux 集成*），所以我不会在这里深入讨论。值得知道的是，Spring 5 对响应式有着严肃的思考，并且这在所有这些新的添加中都得到了清晰的体现。

Spring WebFlux 需要将 Reactor 作为其核心依赖之一。但是，与往常一样，如果需要，它确实可以让您轻松切换实现。

# Reactive Spring Web

**Spring Web 模块**（[`github.com/spring-projects/spring-framework/tree/master/spring-web`](https://github.com/spring-projects/spring-framework/tree/master/spring-web)）有许多用于构建响应式 Web 应用程序的基础组件。它允许您执行与服务器和客户端相关的操作。

它在服务器端提供的功能分为两个方面：

+   **HTTP**：包含在`spring-web`的`org.springframework.http`包中，包含用于受支持服务器的 HTTP 请求处理的各种 API

+   **Web**：包含在`spring-web`的`org.springframework.web`包中，包含用于请求处理的各种 API

该模块还包含在客户端上工作的消息编解码器，用于对请求和响应进行编码和解码。这些编解码器也可以在服务器上使用。

# WebClient

`org.springframework.web.reactive.function.client.WebClient`接口是 Spring 5 中引入的一种响应式 Web 客户端，可用于执行 Web 请求。类似地，还有`org.springframework.test.web.reactive.server.WebTestClient`接口，它是一个特殊的`WebClient`，用于在应用程序中编写单元测试。`WebClient`是`RestTemplate`的响应式版本，它使用 HTTP/1.1 协议。它们作为`spring-webflux`模块的一部分打包。

# WebSockets

`spring-webflux`模块还具有响应式 WebSocket 实现。**WebSocket**允许我们在客户端和服务器之间建立双向连接，这种用法在新一代应用程序中变得越来越普遍。

# 应用程序安全

**应用程序安全**由各种流程组成，旨在发现、修复和防止应用程序中的安全漏洞。

我们生活在**开发+运维**（**DevOps**）的世界中，在这里我们将工程和运营人员聚集在一起。DevOps 倡导在各个层面进行自动化和监控。随着安全变得非常重要，一个新术语**DevSecOps**变得突出——这是我们将安全作为一等公民的地方。

对于一个应用程序，安全属于非功能性要求。由于它在应用程序中的重要性，大多数组织都有专门的团队来测试潜在的安全漏洞。这是一个非常重要的方面需要考虑，因为在这个现代世界中，安全漏洞可能严重破坏组织的品牌。

安全是一个非常广泛的术语，涵盖了许多方面。在本书中，我们将使用 Spring Framework 模块 Spring Security 来查看一些基本的安全问题。在涵盖了一些核心安全问题之后，我们还将看一些低级安全问题以及 Spring Security 如何帮助解决这些问题。

由于我们将专注于 Spring，我们将深入探讨与 Java Web 应用程序开发相关的安全问题。

# Spring Security

Spring Security 是一个功能强大且高度可定制的身份验证和访问控制框架。它是保护基于 Spring 的应用程序的事实标准。

– Spring by Pivotal

Spring Security 5 是该框架的新版本，也是本书的主要关注点。Spring Security 使您能够全面处理应用程序的身份验证和授权。它还有顶级项目，专门处理多种身份验证机制，如**LDAP**、**OAuth**和**SAML**。Spring Security 还提供了足够的机制来处理常见的安全攻击，如**会话固定**、**点击劫持**和**跨站点请求伪造**。此外，它与许多 Spring Framework 项目（如 Spring MVC、Spring WebFlux、Spring Data、Spring Integration 和 Spring Boot）有很好的集成。

# Spring Security 术语

了解一些最重要的 Spring Security 术语非常重要。让我们来看看其中一些：

+   **主体**：希望与您的应用程序交互的任何用户、设备或系统（应用程序）。

+   **身份验证**：确保主体是其所声称的过程

+   **凭据**：当主体尝试与您的应用程序交互时，身份验证过程开始并挑战主体传递一些值。一个例子是用户名/密码组合，这些值称为凭据。身份验证过程验证主体传递的凭据与数据存储中的凭据是否匹配，并回复适当的结果。

+   **授权**：成功认证后，将再次检查主体在应用程序上可以执行的操作。这个检查主体权限并授予必要权限的过程称为授权。

+   **受保护的项目/资源**：标记为受保护并要求主体（用户）成功完成身份验证和授权的项目或资源。

+   **GrantedAuthority**：Spring Security 对象（`org.springframework.security.core.GrantedAuthority`接口），包含/保存主体的权限/访问权限详细信息。

+   **SecurityContext**：Spring Security 对象，保存主体的身份验证详细信息。

# Spring Security 的核心功能

Spring Security 为您的应用程序提供了许多安全功能。Spring Security 以其对各种身份验证和授权方法的支持而闻名。在本节中，我们将更详细地深入探讨这些核心功能。

# 身份验证

Spring Security 提供了多种方法，您的应用程序可以进行身份验证。它还允许您编写自定义身份验证机制，如果这些提供的默认方法不符合您的要求。由于这种可扩展性，甚至可以使用旧应用程序进行身份验证。本书有专门的章节（第三章、*使用 SAML、LDAP 和 OAuth/OIDC 进行身份验证*和第四章、*使用 CAS 和 JAAS 进行身份验证*），我们将更详细地介绍各种身份验证机制，如 OAuth、LDAP 和 SAML。

# 授权

Spring Security 允许您作为应用程序开发人员选择多种方式来授权用户访问应用程序的各个部分。以下是一些方法：

+   **Web URL**：基于 URL 或 URL 模式，您可以控制访问

+   **方法调用**：如果需要，甚至可以对 Java Bean 中的方法进行访问控制

+   **领域实例**：通过在应用程序中控制对特定数据的访问，可以控制对某些需要的领域对象的访问控制。

+   **Web 服务**：允许您保护应用程序中暴露的 Web 服务

在下一章中，我们将更详细地讨论这些方面，并提供更多的代码片段。

# Spring Security 5 的新功能

Spring Security 5 提供了许多新功能，同时支持 Spring 5。作为此版本的一部分引入的一些重要新功能包括：

+   **支持 OAuth 2.0 和 OpenID Connect（OIDC）1.0**：允许用户使用其现有的 OAuth 提供程序（例如 GitHub）或 OIDC 提供程序（例如 Google）登录到您的应用程序。OAuth 是使用授权码流实现的。我们将在后续章节中深入探讨这个问题。

+   **响应式支持**：Spring 5 引入了一个新的响应式 Web 应用程序框架——Spring WebFlux。Spring Security 确保在所有方面（身份验证和授权）完全支持这个 Web 应用程序框架，使用响应式概念。

+   **改进的密码编码**：引入密码编码委托允许使用多种算法对各种密码进行编码。Spring 识别算法的方式是通过读取编码密码的前缀，其中包含用于编码密码的算法。格式为`{algorithm}encoded_password`。

# Spring Security 的工作

在本节中，我们将看看 Spring Security 的工作原理。我们将首先解释核心概念，然后看看请求经过的各种类来执行安全性。

# Servlet 过滤器

了解 Servlet 过滤器非常重要，这样您就可以了解 Spring Security 的内部工作。下图清楚地解释了 Servlet 过滤器的工作原理。它在请求到达实际资源之前以及在响应返回给消费者之前起作用。它是一个可插拔的组件，可以随时在 Web 配置文件（`web.xml`）中进行配置。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/88799858-7e56-4fe9-92b4-039eb75ddc96.png)

图 9：Servlet 过滤器的工作

# 过滤器链

您可以在到达实际资源之前嵌入任意数量的 Servlet 过滤器。根据它们在`web.xml`中声明的顺序触发过滤器。这种 Servlet 过滤器的链接称为**过滤器链**。Spring Security 依赖于一系列作为过滤器链排列的 Servlet 过滤器，每个过滤器执行单一的责任，然后将其交给下一个过滤器，依此类推。大多数内置过滤器对大多数应用程序来说已经足够好了。如果需要，您可以编写自己的过滤器，并将它们放在希望它们执行的位置。

# 安全拦截器（DelegatingFilterProxy）

当任何请求到达使用 Spring Security 进行保护的应用程序时，请求会经过一个门。这个拦截器完成所有的魔术，如果情况不妙，它会出错并返回给调用者，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/023819ce-1ee5-40a6-9366-716cf9c6dcb9.png)

图 10：安全拦截器的工作

安全拦截器确保根据为应用程序设置的各种安全配置，将工作委托给适当的方，并确保在实际到达调用者请求的资源之前，每个人都满意。为了执行实际工作，安全拦截器使用了许多管理器，每个管理器都负责执行单一的工作。下图列出了安全拦截器与之合作执行功能的一些重要管理器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/be0f39f5-a970-440b-9014-9cc92ce1a762.png)

图 11：安全拦截器和相关管理器

在 Spring Security 中，安全拦截器由`DelegatingFilterProxy`完成。对于到达 Web 应用程序的任何请求，此代理确保将请求委托给 Spring Security，并且当事情顺利进行时，它确保将请求传递到 Web 应用程序中的正确资源。

`DelegatingFilterProxy`是一个 Servlet 过滤器，必须在您的`web.xml`文件中进行配置，然后委托给一个实现`ServletFilter`接口的 Spring 管理的 bean（`@Bean`）。

以下代码片段显示了如何在`web.xml`中配置`DelegatingProxyFilter`：

```java
<?xml version="1.0" encoding="UTF-8"?>
 <web-app>
    <filter>
        <filter-name>springSecurityFilterChain</filter-name>
        <filter-class>
            org.springframework.web.filter.DelegatingFilterProxy
        </filter-class>
    </filter>

    <filter-mapping>
        <filter-name>springSecurityFilterChain</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
 </web-app>
```

在上述代码中，所有对 Web 应用程序（`/* mapping`）的请求都将通过`DelegatingProxyFilter`过滤器进行。重要的是要注意，这个过滤器的名称应该是`springSecurityFilterChain`，因为 Spring Security 会寻找这个默认的过滤器名称来配置自己。代理过滤器只是将控制权传递/委托给一个名为`springSecuirtyFilterChain`的 bean。如果您正在使用默认的 Spring Security 设置，请求将被`FilterChainProxy`接收。`FilterChainProxy`负责将请求通过配置为 Spring Security 的一部分的各种 Servlet 过滤器传递。`springSecuirtyFilterChain` bean 不需要显式声明，而是由框架处理，对开发人员透明。

现在我们已经看过了 Spring Security 的所有核心概念，让我们回到以下图表中以图形方式表示的 Spring Security 的工作方式。它包含两个重要的安全方面-身份验证和授权：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/ad01cc0a-91da-4c35-9cf5-dd8cf2722f0a.png)

图 12：Spring Security 的工作方式

来自调用者的请求到达`DelegatingFilterProxy`，它委托给`FilterChainProxy`（Spring Bean），后者通过多个过滤器传递请求，并在成功执行后，授予调用者对所请求的受保护资源的访问权限。

有关 Servlet 过滤器及其功能的完整列表，请参阅 Spring Security 参考文档：[`docs.spring.io/spring-security/site/docs/current/reference/html/security-filter-chain.html`](https://docs.spring.io/spring-security/site/docs/current/reference/html/security-filter-chain.html)。

有了所有这些细节，下图总结了 Spring Security 如何为您的 Web 应用程序处理身份验证和授权：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/ef2f262d-a6e6-4e88-9131-9f321aa9bf14.png)

图 13：Spring Security 在使用数据库进行身份验证和授权

当调用者向受 Spring Security 保护的 Web 应用程序发送请求时，首先经过安全拦截器管理器，如**身份验证管理器**（负责身份验证）和**访问决策管理器**（负责授权），并在成功执行这些操作后，允许调用者访问受保护的资源。

对于响应式应用程序，这些概念都是有效的。有等效的响应式类，我们编码的方式是唯一改变的。这些都很容易理解和实现。

在第二章中，*深入了解 Spring Security*，我们将介绍身份验证，在第三章中，*使用 SAML、LDAP 和 OAuth/OIDC 进行身份验证*，我们将详细介绍授权，并深入了解其内部情况。

# 核心 Spring Security 模块

在 Spring Framework 中，Spring Security 是一个顶级项目。在 Spring Security 项目（[`github.com/spring-projects/spring-security`](https://github.com/spring-projects/spring-security)）中，有许多子模块：

+   **Core**（`spring-security-core`）：Spring 安全的核心类和接口在这里进行身份验证和访问控制。

+   **Remoting**（`spring-security-remoting`）：如果您需要 Spring Remoting，这是具有必要类的模块。

+   **Aspect**（`spring-security-aspects`）：Spring Security 内的**面向方面的编程**（**AOP**）支持。

+   **Config**（`spring-security-config`）：提供 XML 和 Java 配置支持。

+   密码学（`spring-security-crypto`）：包含密码学支持。

+   数据（`spring-security-data`）：与 Spring Data 集成。

+   消息传递（`spring-security-messaging`）

+   OAuth2：在 Spring Security 中支持 OAuth 2.x。

+   核心（`spring-security-oauth2-core`）

+   客户端（`spring-security-oauth2-client`）

+   JOSE（`spring-security-oauth2-jose`）

+   OpenID（`spring-security-openid`）：OpenID Web 身份验证支持。

+   CAS（`spring-security-cas`）：CAS（中央认证服务）客户端集成。

+   TagLib（`spring-security-taglibs`）：关于 Spring Security 的各种标签库。

+   测试（`spring-security-test`）：测试支持。

+   Web（`spring-security-web`）：包含 Web 安全基础设施代码，如各种过滤器和其他 Servlet API 依赖项。

这些是与 Spring Security 密切相关的 Spring Framework 中的顶级项目：

+   `spring-ldap`：简化 Java 中的轻量级目录访问协议（LDAP）编程。

+   `spring-security-oauth`：使用 OAuth 1.x 和 OAuth 2.x 协议进行轻松编程。

+   `spring-security-saml`：为 Spring 应用程序提供 SAML 2.0 服务提供者功能。

+   `spring-security-kerberos`：将 Spring 应用程序与 Kerberos 协议轻松集成。

安全断言标记语言（SAML）是一种基于 XML 的框架，用于确保传输通信的安全性。SAML 定义了交换身份验证、授权和不可否认信息的机制，允许 Web 服务具有单一登录功能。

轻量级目录访问协议（LDAP）是在 TCP/IP 协议栈的一层上运行的目录服务协议。它基于客户端-服务器模型，并提供了用于连接、搜索和修改 Internet 目录的机制。

Kerberos 是一种网络身份验证协议。它旨在通过使用秘密密钥加密为客户端/服务器应用程序提供强身份验证。麻省理工学院提供了该协议的免费实现，并且它也可以在许多商业产品中使用。

有关 SAML、LDAP 和 Kerberos 的更多信息，您可以查看以下链接：

+   [`www.webopedia.com/TERM/S/SAML.html`](https://www.webopedia.com/TERM/S/SAML.html)

+   [`msdn.microsoft.com/en-us/library/aa367008(v=vs.85).aspx`](https://msdn.microsoft.com/en-us/library/aa367008(v=vs.85).aspx)

+   [`web.mit.edu/kerberos/`](https://web.mit.edu/kerberos/)

# 摘要

在本章中，我们向您介绍了新的应用程序要求，然后转向了一些核心的响应式概念。我们看了看响应式宣言和响应式编程。然后，我们将注意力转向了 Spring 5 和 Spring Security 5，并触及了其中的一些新功能，特别是关于响应式编程的。然后，我们简要地介绍了 Spring 的响应式编程工作，通过向您介绍 Project Reactor。之后，我们更详细地探讨了 Spring Security，以便您能够重新思考这个主题。最后，我们通过向您介绍本书中示例的结构以及我们将使用的编码实践，来结束了本章。

现在，您应该对响应式编程以及 Spring Security 及其工作原理有了很好的了解。您还应该清楚地了解如何浏览其余章节，特别是示例代码。


# 第二章：深入了解 Spring Security

这是一本实用的书，但我们的第一章是理论性的（应该是这样），因为它是一个介绍性的章节。

在本章中，我们将深入探讨 Spring Security 的技术能力，特别是认证和授权，使用代码。然而，在进入编码之前，我们将简要解释理论。我们这样做是因为在深入编码之前理解概念是很重要的。

安全的两个最重要方面如下：

+   查找用户的身份

+   查找该用户可以访问的资源

认证是找出用户是谁的机制，授权是允许应用程序找出用户对应用程序可以做什么的机制：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/ac322b64-46ba-4e10-8764-c3449f298df3.png)

图 01：安全的基本方面——认证和授权

在本章中，我们将涵盖以下内容：

+   认证

+   认证机制

+   授权

# 认证

保护资源的一个基本方法是确保调用者是其所声称的身份。检查凭据并确保它们是真实的过程称为**认证**。

以下图表显示了 Spring Security 用于解决这一核心安全需求的基本过程。该图是通用的，可用于解释框架支持的各种认证方法：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/35829f9b-bc45-453d-b3c9-8d3f78cf8f3c.png)

图 02：认证架构

如第一章中所述，*Spring 5 和 Spring Security 5 概述*（在*Spring Security 的工作方式*部分），Spring Security 具有一系列 Servlet 过滤器（过滤器链）。当请求到达服务器时，它会被这一系列过滤器拦截（在前面的图中的*Step 1*）。

在响应式世界中（使用新的 Spring WebFlux web 应用程序框架），过滤器的编写方式与传统过滤器（例如 Spring MVC web 应用程序框架中使用的过滤器）有很大不同。尽管如此，对于两者来说，基本机制仍然保持不变。我们有一个专门的章节来解释如何将 Spring Security 应用程序转换为 Spring MVC 和 Spring WebFlux，在那里我们将更详细地涵盖这些方面。

在过滤器链中，Servlet 过滤器代码执行会一直跳过，直到达到正确的过滤器。一旦到达基于使用的认证机制的正确认证过滤器，它会从调用者中提取提供的凭据（通常是用户名和密码）。使用提供的值（在这里，我们有用户名和密码），过滤器（`UsernamePasswordAuthenticationFilter`）创建一个`Authentication`对象（在前面的图中，使用*Step 2*中提供的用户名和密码创建了`UsernamePasswordAuthenticationToken`）。然后，*Step 2*中创建的`Authentication`对象用于调用`AuthenticationManager`接口中的`authenticate`方法：

```java
public interface AuthenticationManager {
    Authentication authenticate(Authentication authentication) 
        throws AuthenticationException;
}
```

实际的实现由*ProviderManager*提供，它具有配置的`AuthenticationProvider`列表。

```java
public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication)
        throws AuthenticationException;
    boolean supports(Class<?> authentication);
}
```

请求通过各种提供者，并最终尝试对请求进行认证。作为 Spring Security 的一部分，有许多`AuthenticationProvider`。

在本章开头的图表中，`AuthenticationProvider`需要用户详细信息（一些提供者需要这个，但有些不需要），这些信息在`UserDetailsService`中提供：

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws           
        UsernameNotFoundException;
}
```

`UserDetailsService` 使用提供的用户名检索 `UserDetails`（并实现`User`接口）。

如果一切顺利，Spring Security 将创建一个完全填充的`Authentication`对象（authenticate: true，授予的权限列表和用户名），其中将包含各种必要的详细信息。过滤器将`Authentication`对象存储在`SecurityContext`对象中以供将来使用。

`AuthenticationManager` 中的 `authenticate` 方法可以返回以下内容：

+   `Authentication` 对象，如果 Spring Security 能够验证提供的用户凭据，则 `authenticated=true`

+   `AuthenticationException`，如果 Spring Security 发现提供的用户凭据无效

+   `null`，如果 Spring Security 无法确定它是真还是假（混乱状态）

# 设置 AuthenticationManager

Spring Security 中有许多内置的 `AuthenticationManager` 可以在您的应用程序中轻松使用。Spring Security 还有许多辅助类，使用这些类可以设置 `AuthenticationManager`。其中一个辅助类是 `AuthenticationManagerBuilder`。使用这个类，可以很容易地设置 `UserDetailsService` 对数据库、内存、LDAP 等进行身份验证。如果需要，您还可以拥有自己的自定义 `UserDetailsService`（也许您的组织中已经有自定义的单点登录解决方案）。

您可以使 `AuthenticationManager` 全局化，这样它将可以被整个应用程序访问。它将可用于方法安全性和其他 `WebSecurityConfigurerAdapter` 实例。`WebSecurityConfigurerAdapter` 是您的 Spring 配置文件扩展的类，使得将 Spring Security 引入 Spring 应用程序变得非常容易。这是如何使用 `@Autowired` 注解设置全局 `AuthenticationManager`：

```java
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public void confGlobalAuthManager(AuthenticationManagerBuilder auth) throws 
            Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin").password("admin@password").roles("ROLE_ADMIN");
    }
}
```

您还可以通过覆盖 `configure` 方法，在特定的 `WebSecurityConfigurerAdapter` 中创建本地 `AuthenticationManager`，如下面的代码所示：

```java
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin").password("admin@password").roles("ROLE_ADMIN");
    }
}
```

另一个选项是通过覆盖 `authenticationManagerBean` 方法来公开 `AuthenticationManager` bean，如下所示：

```java
@Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
}
```

您还可以将各种 `AuthenticationManager`、`AuthenticationProvider` 或 `UserDetailsService` 公开为 bean，这将覆盖默认的 bean。

在前面的代码示例中，我们使用 `AuthenticationManagerBuilder` 来配置内存中的身份验证。`AuthenticationManagerBuilder` 类的更多机制将在本章的后续示例中使用。

# AuthenticationProvider

`AuthenticationProvider` 提供了一种获取用户详细信息的机制，可以进行身份验证。Spring Security 提供了许多 `AuthenticationProvider` 实现，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/c68b876c-9e2c-4329-b76d-63ebe1a3b376.png)

图 03：Spring Security 内置的 AuthenticationProvider

在接下来的章节中，我们将详细介绍每个部分，并提供更多的代码示例。

# 自定义 AuthenticationProvider

如果需要，我们可以通过实现 `AuthenticationProvider` 接口来编写自定义 `AuthenticationProvider`。我们将需要实现两个方法，即 `authenticate（Authentication）` 和 `supports（Class<?> aClass）`：

```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws     
            AuthenticationException {
      String username = authentication.getName();
      String password = authentication.getCredentials().toString();
      if ("user".equals(username) && "password".equals(password)) {
        return new UsernamePasswordAuthenticationToken
          (username, password, Collections.emptyList());
      } else {
        throw new BadCredentialsException("Authentication failed");
      }
    }
    @Override
    public boolean supports(Class<?> aClass) {
      return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
```

我们的 `authenticate` 方法非常简单。我们只需将用户名和密码与静态值进行比较。我们可以在这里编写任何逻辑并对用户进行身份验证。如果出现错误，它会抛出一个 `AuthenticationException` 异常。

在书的 GitHub 页面上，导航到 `jetty-in-memory-basic-custom-authentication` 项目，查看这个类的完整源代码。

# 多个 AuthenticationProvider

Spring Security 允许您在应用程序中声明多个 `AuthenticationProvider`。它们根据在配置中声明它们的顺序执行。

`jetty-in-memory-basic-custom-authentication` 项目进一步修改，我们使用新创建的 `CustomAuthenticationProvider` 作为 `AuthenticationProvider`（`Order 1`），并将现有的 `inMemoryAuthentication` 作为第二个 `AuthenticationProvider`（`Order 2`）：

```java
@EnableWebSecurity
@ComponentScan(basePackageClasses = CustomAuthenticationProvider.class)
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    CustomAuthenticationProvider customAuthenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/**")
                .authenticated(); // Use Basic authentication
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Custom authentication provider - Order 1
        auth.authenticationProvider(customAuthenticationProvider);
        // Built-in authentication provider - Order 2
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}admin@password")
                //{noop} makes sure that the password encoder doesn't do anything
                .roles("ADMIN") // Role of the user
                .and()
                .withUser("user")
                .password("{noop}user@password")
                .credentialsExpired(true)
                .accountExpired(true)
                .accountLocked(true)
                .roles("USER");
    }
}
```

每当 `authenticate` 方法执行时没有错误，控制权就会返回，此后配置的 `AuthenticationProvider` 将不会被执行。

# 示例应用程序

让我们开始编写一些代码。我们将从最常见的身份验证机制开始，然后进入可以与 Spring Security 一起使用的其他身份验证机制。

# 基本项目设置

除了实际的身份验证机制外，应用程序的许多方面都是相似的。在本节中，我们将设置示例，然后详细介绍特定的身份验证机制。

我们将使用默认的 Spring Security DB 模式来验证用户。我们将创建一个完整的 Spring MVC Web 应用程序，每个组件都是从头开始创建的。使用 Spring Boot 创建一个示例 Spring Security 应用程序非常容易。该应用程序将通过许多隐藏在开发人员背后的东西来运行。但在这种情况下，我们将逐个创建这个应用程序组件，以便您可以看到构建在 Spring MVC 上的 Web 应用程序的实际代码。

Spring Security 使用的默认 DB 模式如下图所示。但是，您可以根据自己的应用程序对其进行自定义。我们将在这里使用**Users**和**Authorities**表进行设置：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/16b57543-4f52-4af7-96a2-95087c1b51c6.png)

图 04：Spring Security 默认数据库模式

现在让我们开始开发我们的示例应用程序。

# 步骤 1—在 IntelliJ IDEA 中创建一个 Maven 项目

在 IntelliJ 中，选择文件 | 新建 | 项目。这将打开新项目向导，如下截图所示。现在选择 Maven 并单击下一步按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/32266a6a-98b5-4f72-a76d-702c307cbdd1.png)

图 05：IntelliJ 中的新 Maven 项目

在新项目向导的下一个屏幕（*步骤 2*）中，输入 GroupId、ArtifactId 和 Version，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/2b886993-a053-4200-8076-bb7cf3e78c26.png)

图 06：IntelliJ 中的 Maven 项目设置—输入 GroupId、ArtifactId 和 Version

在新项目向导的下一个屏幕（*步骤 3*）中，输入项目名称和项目位置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/9eb9f732-38b0-4d9d-8be6-be901b714012.png)

图 07：Maven 项目设置—设置项目名称和项目位置

IntelliJ 将提示您进行操作，如下截图所示。要在`pom.xml`中进行任何更改时自动导入项目，请单击启用自动导入链接：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/0ea8decb-8174-4daa-88b2-1dcd853587df.png)

图 08：在 IntelliJ 中启用自动导入

# 步骤 2—pom.xml 更改

打开`pom.xml`文件，并在项目标签（`<project></project>`）中添加以下代码：

```java
<!-- Spring dependencies -->
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-web</artifactId>
   <version>5.0.4.RELEASE</version>
</dependency>
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-config</artifactId>
   <version>5.0.4.RELEASE</version>
</dependency>
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-crypto</artifactId>
   <version>5.0.4.RELEASE</version>
</dependency>
<dependency>
   <groupId>org.springframework</groupId>
   <artifactId>spring-webmvc</artifactId>
   <version>5.0.5.RELEASE</version>
</dependency>
<dependency>
   <groupId>org.springframework</groupId>
   <artifactId>spring-jdbc</artifactId>
   <version>5.0.4.RELEASE</version>
</dependency>
<!-- Servlet and JSP related dependencies -->
<dependency>
   <groupId>javax.servlet</groupId>
   <artifactId>javax.servlet-api</artifactId>
   <version>3.1.0</version>
   <scope>provided</scope>
</dependency>
<dependency>
   <groupId>javax.servlet.jsp</groupId>
   <artifactId>javax.servlet.jsp-api</artifactId>
   <version>2.3.1</version>
   <scope>provided</scope>
</dependency>
<dependency>
   <groupId>javax.servlet.jsp.jstl</groupId>
   <artifactId>javax.servlet.jsp.jstl-api</artifactId>
   <version>1.2.1</version>
</dependency>
<dependency>
   <groupId>taglibs</groupId>
   <artifactId>standard</artifactId>
   <version>1.1.2</version>
</dependency>
<!-- For datasource configuration -->
<dependency>
   <groupId>org.apache.commons</groupId>
   <artifactId>commons-dbcp2</artifactId>
   <version>2.1.1</version>
</dependency>
<!-- We will be using MySQL as our database server -->
<dependency>
   <groupId>mysql</groupId>
   <artifactId>mysql-connector-java</artifactId>
   <version>6.0.6</version>
</dependency>
```

在`pom.xml`中构建一个设置，我们将使用 jetty 来运行创建的应用程序。

```java
<build>
   <plugins>
       <!-- We will be using jetty plugin to test the war file -->
       <plugin>
           <groupId>org.eclipse.jetty</groupId>
           <artifactId>jetty-maven-plugin</artifactId>
           <version>9.4.8.v20171121</version>
       </plugin>
   </plugins>
</build>
```

# 步骤 3—MySQL 数据库模式设置

使用以下脚本创建默认数据库模式，并插入一些用户：

```java
create table users(
    username varchar(75) not null primary key,
    password varchar(150) not null,
    enabled boolean not null
);
create table authorities (
    username varchar(75) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key(username) references users(username)
);
```

使用以下脚本将数据插入上述表中：

```java
insert into users(username, password, enabled)
    values('admin', '$2a$04$lcVPCpEk5DOCCAxOMleFcOJvIiYURH01P9rx1Y/pl.wJpkNTfWO6u', true);
insert into authorities(username, authority) 
    values('admin','ROLE_ADMIN');
insert into users(username, password, enabled)
    values('user', '$2a$04$nbz5hF5uzq3qsjzY8ZLpnueDAvwj4x0U9SVtLPDROk4vpmuHdvG3a', true);
insert into authorities(username,authority) 
    values('user','ROLE_USER');
```

`password`是使用在线工具[`www.devglan.com/online-tools/bcrypt-hash-generator`](http://www.devglan.com/online-tools/bcrypt-hash-generator)进行单向哈希处理的。为了比较`password`，我们将使用`PasswordEncoder`（`Bcrypt`）。

凭据如下：

+   用户 = `admin` 和密码 = `admin@password`

+   用户 = `user` 和密码 = `user@password`

重要的是要注意，即使角色被命名为`ROLE_ADMIN`，实际名称是`ADMIN`，这是我们的代码在传递时将使用的名称。

# 步骤 4—在项目中设置 MySQL 数据库属性

在`src/main/resources`文件夹中创建一个名为`mysqldb.properties`的文件，内容如下：

```java
mysql.driver=com.mysql.cj.jdbc.Driver
mysql.jdbcUrl=jdbc:mysql://localhost:3306/spring_security_schema?useSSL=false
mysql.username=root
mysql.password=<your-db-password>
```

# 步骤 5—Spring 应用程序配置

在`com.packtpub.book.ch02.springsecurity.config`包中创建一个名为`ApplicationConfig`的 Java 类，其中包含以下代码：

```java
@Configuration
@PropertySource("classpath:mysqldb.properties")
public class ApplicationConfig {

   @Autowired
   private Environment env;

   @Bean
   public DataSource getDataSource() {
       BasicDataSource dataSource = new BasicDataSource();
       dataSource.setDriverClassName(env.getProperty("mysql.driver"));
       dataSource.setUrl(env.getProperty("mysql.jdbcUrl"));
       dataSource.setUsername(env.getProperty("mysql.username"));
       dataSource.setPassword(env.getProperty("mysql.password"));
       return dataSource;
   }
}
```

# 步骤 6—Web 应用程序配置

在这个例子中，我们将使用 Spring MVC 作为我们的 Web 应用程序框架。让我们创建 Web 应用程序配置文件：

```java
@Configuration
@EnableWebMvc
@ComponentScan(basePackages= {"com.packtpub.book.ch02.springsecurity.controller"})
public class WebApplicationConfig implements WebMvcConfigurer {
   @Override
   public void configureViewResolvers(ViewResolverRegistry registry) {
       registry.jsp().prefix("/WEB-INF/views/").suffix(".jsp");
   }
}
```

`@EnableWebMvc`注解确保您的应用程序基于 Spring MVC。

# 第 7 步-设置 Spring MVC

在 Spring MVC 中，请求会落在`DispatcherServlet`上。`DispatcherServlet`可以在`web.xml`中声明，或者如果您的 Servlet 容器是 3.0+，则可以作为 Java 配置。请创建一个虚拟的`SpringSecurityConfig.java`文件。当我们解释第一个身份验证机制，即基本身份验证时，我们将构建这个类。

```java
public class SpringMvcWebApplicationInitializer
       extends AbstractAnnotationConfigDispatcherServletInitializer {

   @Override
   protected Class<?>[] getRootConfigClasses() {
       return new Class[] { ApplicationConfig.class, SpringSecurityConfig.class };
   }

   @Override
   protected Class<?>[] getServletConfigClasses() {
       return new Class[] { WebApplicationConfig.class };
   }

   @Override
   protected String[] getServletMappings() {
       return new String[] { "/" };
   }

}
```

# 第 8 步-控制器设置

让我们为受保护的 JSP 页面（`home.jsp`）创建一个基本控制器（`HomeController`）。请注意，映射方法的返回值应该是一个字符串，并且应该映射到 JSP 文件的实际名称。在我们的情况下，它是`home.jsp`，这是一个在用户登录时调用者导航到的受保护资源：

```java
@Controller
public class HomeController {

   @GetMapping("/")
   public String home(Model model, Principal principal) {
       if(principal != null)
           model.addAttribute("msg", "Welcome " + principal.getName());
       return "home";
   }
}
```

# 第 9 步-JSP 创建

我们的主页是一个非常简单的 JSP 文件，如下面的代码片段所示。这个 JSP 只是显示我们在`HomeController`类中构造的消息：

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
        pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
   <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
   <title>Spring Security</title>
</head>
<body>
<h1>Spring Security Sample</h1>
<h2>${msg}</h2>
</body>
</html>
```

这是现在的基本 Spring MVC 应用程序，我们将尝试设置各种身份验证机制。

# Spring 安全设置

为了解释 Spring 安全，我们将在之前创建的 Spring MVC 项目上实现基本身份验证。在第三章中，我们将使用 Spring 安全来实现其他身份验证机制，如 SAML、LDAP 和 OAuth/OIDC。为了在您的应用程序中执行基本身份验证，让我们执行本节中概述的附加步骤。

# 第 1 步-设置 Spring 安全配置

我们现在将创建非常重要的 Spring 安全配置类，并确保为 Spring 安全设置默认的过滤器链以保护所有资源：

```java
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
   @Autowired
   private DataSource dataSource;
   @Override
   protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.jdbcAuthentication().dataSource(dataSource)
               .usersByUsernameQuery("select username, password, enabled"
                       + " from users where username = ?")
               .authoritiesByUsernameQuery("select username, authority "
                       + "from authorities where username = ?")
               .passwordEncoder(new BCryptPasswordEncoder());
   }
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests().anyRequest().hasAnyRole("ADMIN", "USER")
               .and()
               .httpBasic(); // Use Basic authentication
   }
}
```

在 Spring 安全配置中，我们首先告诉 Spring 安全，您将使用定义的用户查询对用户进行身份验证，并使用定义的权限查询检查用户的权限。

然后我们设置身份验证机制以检索用户的凭据。在这里，我们使用基本身份验证作为捕获用户凭据的机制。请注意，用于检查的角色名称没有前缀`ROLE_`。

# 第 2 步-为 Web 应用程序设置 Spring 安全

我们知道我们必须指示应用程序开始使用 Spring 安全。一个简单的方法是在`web.xml`中声明 Spring 安全过滤器。如果您想避免使用 XML 并使用 Java 执行操作，那么创建一个类，它继承`AbstractSecurityWebApplicationInitializer`；这将初始化过滤器并为您的应用程序设置 Spring 安全：

```java
public class SecurityWebApplicationInitializer
       extends AbstractSecurityWebApplicationInitializer {

}
```

通过这样，我们已经完成了查看基本身份验证所需的所有设置。

# 运行应用程序

通过执行`mvn jetty:run`命令运行项目。一旦您看到以下截图中显示的日志，打开浏览器并转到`http://localhost:8080`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/0a210e9d-0372-4afc-9680-cc9b8c35ba93.png)

图 09：Jetty 服务器运行-控制台日志

一旦访问 URL，浏览器会提示默认的基本身份验证对话框，如下截图所示。输入用户名和密码为`admin`/`admin@password`，然后点击登录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/855b76d0-f0f3-4dbe-967e-d928a2405f89.png)

图 10：浏览器中的基本身份验证对话框

如果您的凭据正确，并且用户具有`ADMIN`或`USER`角色之一，您应该看到如下的主页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/e9c599ce-0360-4309-a0a5-a535d7d27a09.png)

图 11：成功登录后的主页

完整的项目代码可以在该书的 GitHub 页面上找到（[`github.com/PacktPublishing/Hands-On-Spring-Security-5-for-Reactive-Applications`](https://github.com/PacktPublishing/Hands-On-Spring-Security-5-for-Reactive-Applications)），在`jetty-db-basic-authentication`项目中。

# 内存用户存储

如前所述，出于各种测试目的，最好将用户凭据存储在内存中，然后进行身份验证，而不是使用诸如 MySQL 之类的真正数据库。为此，只需通过添加以下方法来更改 Spring Security 配置文件（`SpringSecurityConfig.java`）：

```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
   auth
.inMemoryAuthentication()
           .withUser("admin")
           .password("{noop}admin@password") 
//{noop} makes sure that the password encoder doesn't do anything
           .roles("ADMIN") // Role of the user
           .and()
           .withUser("user")
           .password("{noop}user@password")
           .credentialsExpired(true)
           .accountExpired(true)
           .accountLocked(true)
           .roles("USER");
}
```

重要的是要注意，密码有一个前缀`{noop}`，附加在其前面。这确保在验证密码时不进行编码。这是避免在运行项目时出现密码编码错误的一种方法。

完整的源代码作为一个完整的项目，可以在本书的 GitHub 页面中的`jetty-in-memory-basic-authentication`项目中找到。

# 作为 Spring Boot 运行

前面的示例可以通过遵循以下额外步骤轻松转换为 Spring Boot 应用程序。这个过程不会涵盖我们之前做过的许多琐碎步骤。您需要有另一个配置文件`SpringSecurityConfig.java`，其详细信息如下。

您可以创建一个新文件，通常命名为`Run.java`，其中包含以下代码：

```java
@SpringBootApplication
public class Run {
   public static void main(String[] args) {
       SpringApplication.run(Run.class, args);
   }
}
```

这是一个非常简单的文件，其中有一个重要的注解`@SpringBootApplication`。我们去掉了 Spring MVC 配置类，并将以下属性放入`application.properties`文件中。这只是避免创建新的 Spring MVC 配置文件的另一种方法，而是使用属性文件：

```java
spring.mvc.view.prefix: /WEB-INF/views/
spring.mvc.view.suffix: .jsp
```

与之前一样，其他一切保持不变。有关完整项目，请参考书籍的 GitHub 页面中的`spring-boot-in-memory-basic-authentication`项目。

打开命令提示符并输入以下命令：

```java
mvn spring-boot:run
```

打开浏览器，导航到`http://localhost:8080`，然后应该提供基本身份验证对话框。成功登录后，应该被带到用户主页，如前所示。

# 授权

一旦用户在其声称的身份方面得到验证，下一个方面就是确定用户有权访问什么。确保用户在应用程序中被允许做什么的过程称为授权。

与身份验证架构一致，如前所述，授权也有一个管理器`AccessDecisionManager`。Spring Security 为此提供了三种内置实现：`AffirmativeBased`、`ConsensusBased`和`UnanimousBased`。`AccessDecisionManager`通过委托给一系列`AccessDecisionVoter`来工作。授权相关的 Spring Security 类/接口如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/ed1850b0-950f-4d1c-ae8f-7bb3d3143455.png)

图 12：Spring Security 授权类/接口

在 Spring Security 中，对受保护资源的授权是通过调用选民然后统计收到的选票来授予的。三种内置实现以不同的方式统计收到的选票：

+   **AffirmativeBased**：如果至少有一个选民投票，用户将被授予对受保护资源的访问权限

+   **ConsensusBased**：如果选民和他们的选票之间达成明确的共识，那么用户将被授予对受保护资源的访问权限

+   **UnanimousBased**：如果所有选民投票，那么用户将被授予对受保护资源的访问权限

Spring Security 提供了两种授权方法：

+   **Web URL**：基于传入 URL（特定 URL 或正则表达式）的授权

+   **Method**：基于方法签名来控制访问的方法

如果您的服务层仅公开 RESTful 端点，并且应用程序中的数据被正确分类为资源（符合 REST 原则），则可以考虑使用 Web URL 方法。如果您的应用程序只是公开端点（基于 REST 的，我会称之为），并不真正符合 REST 原则，您可以考虑使用基于方法的授权。

# Web URL

Spring Security 可以用于设置基于 URL 的授权。可以使用配置的 HTTP Security 与 Spring Security 配置来实现所需的授权。在我们迄今为止已经介绍的许多示例中，我们已经看到了模式匹配授权。以下是一个这样的例子：

+   `AntPathRequestMatcher`：使用 Ant 风格的模式进行 URL 匹配：

```java
http
    .antMatcher("/rest/**")
    .httpBasic()
        .disable()
    .authorizeRequests()
        .antMatchers("/rest/movie/**", "/rest/ticket/**", "/index")
            .hasRole("ROLE_USER");
```

在上面的代码片段中，`/rest` URL 的基本身份验证被禁用，对于其他 URL（`/rest/movie`、`/rest/ticket`和`/index`），具有`USER`角色的用户可以访问。该片段还展示了单个匹配（使用`antMatcher`）和多个匹配（使用`antMatchers`）。

+   `MvcRequestMatcher`：这使用 Spring MVC 来匹配路径，然后提取变量。匹配是相对于 servlet 路径的。

+   `RegexRequestMatcher`：这使用正则表达式来匹配 URL。如果需要的话，它也可以用来匹配 HTTP 方法。匹配是区分大小写的，采用（`servletPath` + `pathInfo` + `queryString`）的形式：

```java
http
    .authorizeRequests()
    .regexMatchers("^((?!(/rest|/advSearch)).)*$").hasRole("ADMIN")
    .regexMatchers("^((?!(/rest|/basicSearch)).)*$").access("hasRole(USER)")
        .anyRequest()
    .authenticated()
    .and()
    .httpBasic();
```

# 方法调用

Spring Security 允许用户使用**面向方面的编程**（**AOP**）在后台访问控制方法执行。这可以使用 XML 配置或使用 Java 配置来完成。由于我们在本书中一直在使用 Java 配置，因此我们将在这里介绍 Java 配置和注解来解释方法安全性。最佳实践是选择一种特定的方法调用授权方法，并在整个应用程序中保持一致。选择适合您的应用程序的方法，因为没有关于何时选择何种方法的特定文档。

如果您想在应用程序中启用方法安全性，首先要用`@EnableMethodSecurity`对类进行注解。有三种类型的注解可以用于注解方法并对其进行授权。这些类型如下：

+   **基于投票的注解**：Spring Security 中最常用的注解。Spring Security 的`@Secured`注解属于这个类别。要使用这些注解，首先必须启用它们，如下面的代码片段所示：

```java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // ...
}
```

一旦启用了注解的使用，就可以使用`@Secured`注解，如下面的代码片段所示：

```java
@RestController
@RequestMapping("/movie")
public class MovieController {

    @GetMapping("public")
    @Secured("ROLE_PUBLIC")
    public String publiclyAvailable() {
        return "Hello All!";
    }

    @GetMapping("admin")
    @Secured("ROLE_ADMIN")
    public String adminAccessible() {
        return "Hello Admin!";
    }
}
```

+   **JSR-250 安全注解**：这也被称为**企业 JavaBeans 3.0**（**EJB 3**）安全注解。同样，在使用这些注解之前，必须使用`@EnableGlobalMethodSecurity(jsr250Enabled = true)`来启用它们。以下片段展示了 JSR-250 安全注解的使用：

```java
@RestController
@RequestMapping("/movie")
public class MovieController {

    @GetMapping("public")
    @PermitAll
    public String publiclyAvailable() {
        return "Hello All!";
    }

    @GetMapping("admin")
    @RolesAllowed({"ROLE_ADMIN"})
    public String adminAccessible() {
        return "Hello Admin!";
    }
}
```

+   **基于表达式的注解**：基于`@Pre`和`@Post`的注解属于这个类别。它们可以通过`@EnableGlobalMethodSecurity(prePostEnabled = true)`来启用：

```java
@RestController
@RequestMapping("/movie")
public class MovieController {
    @GetMapping("public")
    @PreAuthorize("permitAll()")
    public String publiclyAvailable() {
        return "Hello All!";
    }
    @GetMapping("admin")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public String adminAccessible() {
        return "Hello Admin!";
    }
}
```

在上面的例子中，`hasAnyAuthority`被称为**Spring 表达式语言**（**SpEL**）。与所示的示例类似，还有许多预定义的表达式可用于安全性。

# 域实例

Spring Security 提供了访问控制各种附加到任何对象的权限的方法。Spring Security **访问控制列表**（**ACL**）存储与域对象关联的权限列表。它还将这些权限授予需要对域对象执行不同操作的各种实体。为了使 Spring Security 工作，您需要设置四个数据库表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/d2edbf2b-2268-4cf9-9414-d68a1a2d93df.png)

图 13：Spring Security ACL 数据库架构

以下是上图中表格的简要解释：

+   `ACL_CLASS`表：顾名思义，它存储域对象的类名。

+   `ACL_SID`表：**安全身份**（**SID**）存储用户名（`testuser`）或角色名（`ROLE_ADMIN`）。`PRINCIPAL`列存储 0 或 1，如果 SID 是用户名，则为 0，如果是角色名，则为 1。

+   `ACL_OBJECT_IDENTITY`表：它负责存储与对象相关的信息并链接其他表。

+   `ACL_ENTRY` 表：它存储了每个 `OBJECT_IDENTITY` 的每个 SID 被授予的权限。

为了使 Spring Security ACL 工作，它还需要一个缓存。其中一个最容易与 Spring 集成的是 EhCache。

Spring Security ACL 支持以下权限：

+   `READ`

+   `WRITE`

+   `CREATE`

+   `DELETE`

+   `ADMINISTRATION`

为了使其工作，我们必须使用 `@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)` 来启用它。现在我们已经准备好放置注解来开始访问控制域对象。使用 Spring ACL 的代码片段如下：

```java
@PostFilter("hasPermission(filterObject, 'READ')")
List<Record> findRecords();
```

在查询记录（后过滤）之后，结果（列表）会被审查，并进行过滤，只返回用户具有 `READ` 权限的对象。我们也可以使用 `@PostAuthorize` 如下：

```java
@PostAuthorize("hasPermission(returnObject, 'READ')")
```

在方法执行之后（`@Post`），如果用户对对象具有 `READ` 访问权限，它会返回。否则，它会抛出 `AccessDeniedException` 异常：

```java
@PreAuthorize("hasPermission(#movie, 'WRITE')")
Movie save(@Param("movie")Movie movie);
```

在方法被触发之前（`@Pre`），它会检查用户是否对对象具有 `WRITE` 权限。在这里，我们使用传递给方法的参数来检查用户权限。如果用户有 `WRITE` 权限，它执行该方法。否则，它会抛出异常。

我们可以有一个完整的示例，但这本书可以涵盖的主题已经很多了。所以我就在这里留下它，我相信你现在已经有足够的信息来进行完整的实现了。

一些关于安全的常见内置 Spring 表达式如下：

| **表达式** | **描述** |
| --- | --- |
| `hasRole([role_name])` | 如果当前用户具有 `role_name`，它返回 `true` |
| `hasAnyRole([role_name1, role_name2])` | 如果当前用户具有列表中的任何角色名称，它返回 `true` |
| `hasAuthority([authority])` | 如果当前用户具有指定权限，它返回 `true` |
| `hasAnyAuthority([authority1, authority2])` | 如果当前用户具有指定列表中的任何权限，它返回 `true` |
| `permitAll` | 总是等同于 `true` |
| `denyAll` | 总是等同于 `false` |
| `isAnonymous()` | 如果当前用户是匿名的，它返回 `true` |
| `isRememberMe()` | 如果当前用户已设置记住我，它返回 `true` |
| `isAuthenticated()` | 如果当前用户不是匿名用户，它返回 `true` |
| `isFullyAuthenticated()` | 如果当前用户不是匿名用户或记住我用户，它返回 `true` |
| `hasPermission(Object target, Object permission)` | 如果当前用户对目标对象有权限，它返回 `true` |
| `hasPermission(Object targetId, Object targetType, Object permission)` | 如果当前用户对目标对象有权限，它返回 `true` |

# 其他 Spring Security 功能

Spring Security 除了核心安全功能、认证和授权之外还具有许多功能。以下是一些最重要的功能。在第七章 *Spring Security Add-Ons* 中，我们将通过实际编码更详细地介绍这些功能。我们将在本章创建的示例基础上构建，并解释这些非常重要的 Spring Security 功能：

+   **记住我认证**：这也被称为持久登录，它允许网站在多个会话之间记住用户的身份。Spring Security 提供了一些实现（基于哈希令牌和持久令牌），使这变得容易。

+   **跨站请求伪造**（**CSRF**）：这是黑客常用的一种安全漏洞，用于执行不道德的操作，未经授权地代表用户发送命令。Spring Security 允许我们通过配置轻松修复这个漏洞。

+   **跨域资源共享**（**CORS**）：这是一种机制，通过添加额外的 HTTP 头，使运行在特定域上的 Web 应用程序可以访问在另一个域中公开的资源。这是确保只有合法代码可以访问域公开资源的安全机制之一。

+   **会话管理**：适当的用户会话管理对于任何应用程序的安全性至关重要。以下是 Spring Security 轻松处理的一些重要的与会话相关的功能：

+   **会话超时**：这确保用户会话在配置的值处于超时状态，且无法被黑客攻击。

+   **并发会话**：这可以防止用户在服务器上有多个（配置值）会话处于活动状态。

+   **会话固定**：这是一种安全攻击，允许攻击者劫持有效用户的会话，然后开始将其用于不道德的操作。

这些是 Spring Security 带来的一些重要功能。在涵盖与 Spring Security 相关的其他主题后，我们将对它们进行彻底探讨。

# 总结

本章旨在介绍两个重要的安全概念，即身份验证和授权，以及它们如何由 Spring Security 支持。

我们首先详细解释了这些概念，然后通过一个示例应用程序深入探讨了它们。我们使用 Spring MVC 应用程序作为基础，帮助您理解 Spring Security 概念。第四章，*使用 CAS 和 JAAS 进行身份验证*，旨在解释响应式 Web 应用程序框架 Spring WebFlux。

在下一章中，我们将通过扩展本章中构建的示例，了解 Spring Security 支持的其他身份验证机制。


# 第三章：使用 SAML、LDAP 和 OAuth/OIDC 进行身份验证

在本章中，我们将研究 Spring Security 支持的认证机制，即 SAML、LDAP 和 OAuth/OIDC。 这将是一个完全动手编码的章节。 我们将构建小型应用程序，其中大多数应用程序都是从我们在第二章中构建的基本应用程序开始的，*深入 Spring Security*。

本章的主要目标是使您能够实现组织中最常用的认证机制，并展示 Spring Security 模块的功能。

每个认证机制都有一个项目，您可以在书的 GitHub 页面上看到。 但是，在书中，我们只会涵盖示例代码的重要方面，以减少章节内的混乱。

在本章中，我们将涵盖以下主题：

+   安全断言标记语言

+   轻量级目录访问协议

+   OAuth2 和 OpenID Connect

# 安全断言标记语言

**安全断言标记语言**（**SAML**），由 OASIS 的*安全服务技术委员会*开发，是用于通信用户身份验证、权限和属性信息的基于 XML 的框架。 SAML 允许业务实体对主体（通常是人类用户）的身份、属性和权限向其他实体（例如合作伙伴公司或其他企业）做出断言。

模块`application.SAML`也是：

+   一组基于 XML 的协议消息

+   一组协议消息绑定

+   一组配置文件（利用上述所有内容）

**身份提供者**（**IdP**）是创建、维护和管理主体（用户、服务或系统）身份信息，并为联合或分布式网络中的其他服务提供商（应用程序）提供主体认证的系统。

**服务提供者**（**SP**）是提供服务的任何系统，通常是用户寻求认证的服务，包括 Web 或企业应用程序。 一种特殊类型的服务提供者，即身份提供者，管理身份信息。

有关 SAML、IdP 和 SP 的更多信息，您还可以参考以下链接：

[`xml.coverpages.org/saml.html`](http://xml.coverpages.org/saml.html)

[`kb.mit.edu/confluence/display/glossary/IdP+(Identity+Provider)`](http://kb.mit.edu/confluence/display/glossary/IdP+(Identity+Provider))

[`searchsecurity.techtarget.com/definition/SAML`](https://searchsecurity.techtarget.com/definition/SAML)

Spring Security 有一个名为 Spring Security SAML 的顶级项目。 它被认为是一个扩展，为 Spring 应用程序提供了与支持 SAML 2.0 的各种认证和联合机制集成。 该扩展还支持多个 SAML 2.0 配置文件以及 IdP 和 SP 启动的 SSO。

有许多符合 SAML 2.0 标准的产品（IdP 模式），例如**Okta**、**Ping Federate**和**ADFS**，可以使用 Spring Security 扩展轻松集成到您的应用程序中。

深入讨论 SAML 的细节超出了本书的范围。但是，我们将尝试集成我们之前在第二章中构建的 Spring Boot 应用程序，*深入了解 Spring Security*，对其进行调整并转换为使用 SAML 2.0 产品 Okta 进行身份验证。在 SSO 的世界中，Okta 是一个知名的产品，允许应用程序轻松实现 SSO。在以下示例中，我们还将使用`spring-security-saml-dsl`项目，这是一个包含 Okta DSL 的 Spring Security 扩展项目。使用此项目可以显著简化 Spring Security 和 Okta 的集成。我们还将为您介绍在 Okta 平台上必须使用的配置，以确保示例是自包含和完整的。这并不意味着您必须将 Okta 作为应用程序的 SSO 平台；相反，它展示了 Spring Security SAML 模块，以 Okta 作为示例。

如前所述，我们将复制我们在第二章中创建的 Spring Boot 项目，作为此示例的起点。现在，让我们先来看看如何设置 SSO 提供程序（Okta）；在随后的部分中，我们将看看如何调整我们复制的 Spring Boot 应用程序以实现 SAML 2.0 身份验证。

# 设置 SSO 提供程序

如详细说明，我们将使用 Okta 作为 SSO 提供程序来构建我们的示例应用程序，该应用程序使用 SAML 2.0 作为身份验证机制的 Spring Security。

要设置 Okta 用户，请执行以下步骤：

1.  转到[`developer.okta.com`](https://developer.okta.com)，然后点击注册。

1.  输入相关细节，然后点击开始。

1.  Okta 将向您发送包含组织子域和临时密码的电子邮件。

1.  点击邮件中的登录按钮，输入您的用户名（电子邮件）和临时密码，然后登录。

1.  您将看到一些与帐户相关的信息。填写详细信息并完成帐户设置。

1.  您现在已经设置了一个 Okta 帐户，其中有一个用户（您），并且没有配置 SSO 的应用程序。

要设置 Okta 应用程序，请执行以下步骤：

1.  登录到您的帐户，然后点击管理按钮。

1.  在屏幕上，点击添加应用程序的快捷链接。

1.  点击创建新应用程序按钮。选择 Web 作为平台，选择 SAML 2.0 单选按钮，然后点击创建按钮。

1.  在应用程序名称字段中，输入您的应用程序名称，保持其余字段不变，然后点击下一步按钮。

1.  在单点登录 URL 字段中，输入 URL 为`https://localhost:8443/saml/SSO`。在受众 URI 字段中，输入 URI 为`https://localhost:8443/saml/metadata`。保持其余字段不变，然后点击下一步按钮。

1.  点击标有“我是 Okta 客户，正在添加内部应用程序”的单选按钮。

1.  选择复选框，上面写着“这是我们创建的内部应用程序”，然后点击完成按钮。

要将 Okta 应用程序分配给用户，您需要按照以下步骤进行操作：

1.  导航到仪表板，然后点击分配应用程序的快捷链接。

1.  点击左侧的创建的应用程序（在应用程序部分），然后点击右侧的用户名（在人员部分），最后点击下一步按钮。

1.  在下一页上，点击确认分配按钮，然后您就完成了将应用程序分配给用户。

您现在已经创建了 Okta 应用程序，并且您的用户分配已完成。现在，让我们尝试修改之前创建的应用程序，以便使用 SAML 2.0 对用户进行身份验证，针对我们创建的 Okta 应用程序。

# 设置项目

我们将更改两个文件：即`SpringSecuirtyConfig`（Spring 安全配置文件）和 Spring 应用程序属性文件（`application.yml`）。在之前的应用程序中，我们使用了属性文件（`application.properties`）而不是 YML（YAML）文件。在这个例子中，我们将放弃`application.properties`文件，并将使用`application.yml`文件进行所有设置。现在开始吧。

# pom.xml 文件设置

复制您以前的项目。打开`pom.xml`文件并添加以下依赖项：

```java
<!-- SAML2 -->
<dependency>
   <groupId>org.springframework.security.extensions</groupId>
   <artifactId>spring-security-saml2-core</artifactId>
   <version>1.0.3.RELEASE</version>
</dependency>
<dependency>
   <groupId>org.springframework.security.extensions</groupId>
   <artifactId>spring-security-saml-dsl-core</artifactId>
   <version>1.0.5.RELEASE</version>
</dependency>
```

# application.yml 文件设置

在`src/main/resources`文件夹中创建一个新的`application.yml`文件，内容如下：

```java
server:
 port: 8443
 ssl:
   enabled: true
   key-alias: spring
   key-store: src/main/resources/saml/keystore.jks
   key-store-password: secret

security:
 saml2:
   metadata-url: https://dev-858930.oktapreview.com/app/exkequgfgcSQUrK1N0h7/sso/saml/metadata

spring:
 mvc:
   view:
     prefix: /WEB-INF/views/
     suffix: .jsp
```

在第 13-17 行（在`spring`部分），我们将之前在`application.properties`文件中的配置数据迁移到了 YML 格式。除了`metadata-url`文件的配置之外，您可以保持所有之前的配置相同。对于这一点，您需要返回到您创建的 Okta 应用程序，并导航到“登录”选项卡。现在，点击“身份提供商元数据”链接并复制链接。它看起来类似于之前显示的链接，URL 末尾带有`metadata`。

# Spring 安全配置文件

现在，我们将改变（或者说配置）我们的 Spring Security 配置文件，如下所示：

```java
@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

   @Value("${security.saml2.metadata-url}")
   String metadataUrl;

   @Override
   protected void configure(HttpSecurity http) throws Exception {
      http
               .authorizeRequests()
               .antMatchers("/saml/**").permitAll()
               .anyRequest().authenticated()
               .and()
               .apply(saml())
               .serviceProvider()
               .keyStore()
               .storeFilePath("saml/keystore.jks")
               .password("secret")
               .keyname("spring")
               .keyPassword("secret")
               .and()
               .protocol("https")
               .hostname("localhost:8443")
               .basePath("/")
               .and()
               .identityProvider()
               .metadataFilePath(metadataUrl)
               .and();
   }
}
```

该文件无需进行任何修改。通过重要的`configure`方法，一切都进行得很顺利。在`spring-security-saml-dsl-core`中，引入`saml()`方法使编码变得非常简洁和容易。有了这个，您几乎完成了，最后一步是创建密钥库。

# 资源文件夹设置

导航到您的项目（在`src/main/resources`文件夹中）。创建一个名为`saml`的文件夹，并在该位置打开命令提示符。执行以下命令：

```java
keytool -genkey -v -keystore keystore.jks -alias spring -keyalg RSA -keysize 2048 -validity 10000
```

在提示时，提供所需的详细信息，并在`src/main/resources/saml`文件夹中创建`keystore.jks`文件。

# 运行和测试应用程序

导航到您的项目文件夹并执行`spring-boot`命令，如下所示：

```java
mvn spring-boot:run
```

打开浏览器，导航到`https://localhost:8443`。请注意`https`和端口`8443`（因为我们启用了 SSL）。如果在 URL 中不输入`https`，您将收到以下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/32f0d565-8822-427e-aa59-94cfdb1a78e2.png)

图 1：使用 HTTP 时浏览器的响应

浏览器将显示一个页面，指出您的连接不安全。消息可能会有所不同，这取决于您选择打开此 URL 的浏览器。只需确保您接受风险并继续前进。

您将被导航到 Okta URL，要求您使用用户名/密码登录，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/5cbcd28e-98e5-4493-b215-6b50f319b8be.png)

图 2：Okta 登录页面显示给用户

完成后，您将被导航回主页，显示您在`home.jsp`文件中放置的内容。下次打开 URL 时，您将直接进入主页，并且 Okta 将自动登录您。

使用 Spring Security 完成了 SAML 身份验证。您可以通过访问 GitHub 页面并导航到`spring-boot-in-memory-saml2-authentication`项目来查看完整的项目。

# 轻量级目录访问协议

**轻量级目录访问协议**（**LDAP**）是一种目录服务协议，允许连接、搜索和修改 Internet 目录。不幸的是，LDAP 不支持反应式绑定；这意味着它不支持反应式编程（类似于 JDBC）。LDAP 身份验证的功能如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/dec705b0-20da-458d-90c8-b03d1bfc945f.png)

图 3：LDAP 身份验证

与之前的示例类似，我们将克隆/复制之前的项目（任何 Spring Boot 项目都可以；我正在克隆`spring-boot-in-memory-saml2-authentication`项目）。与之前的项目类似，我们将修改一些文件并向项目中添加一些文件。我们将使用内置的基于 Java 的 LDAP 服务器来验证用户凭据。

# 在 pom.xml 文件中设置依赖项

打开`pom.xml`并添加以下依赖项：

```java
<!-- LDAP -->
<dependency>
   <groupId>org.springframework</groupId>
   <artifactId>spring-tx</artifactId>
</dependency>
<dependency>
   <groupId>org.springframework.ldap</groupId>
   <artifactId>spring-ldap-core</artifactId>
</dependency>
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-ldap</artifactId>
</dependency>
<dependency>
   <groupId>com.unboundid</groupId>
   <artifactId>unboundid-ldapsdk</artifactId>
</dependency>
```

# Spring 安全配置

修改`SpringSecurityConfiguration.java`文件，如下所示：

```java
@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
   private static final Logger LOG = 
                LoggerFactory.getLogger(SpringSecurityConfig.class);
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests()    .antMatchers("/admins").hasRole("ADMINS")
               .antMatchers("/users").hasRole("USERS")
               .anyRequest().fullyAuthenticated()
               .and()
               .httpBasic(); // Use Basic authentication
   }
   @Override
   public void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth
               .ldapAuthentication()
               .userDnPatterns("uid={0},ou=people")
               .userSearchBase("ou=people")
               .userSearchFilter("uid={0}")
               .groupSearchBase("ou=groups")
               .groupSearchFilter("uniqueMember={0}")
               .contextSource(contextSource())
               .passwordCompare()
               .passwordAttribute("userPassword");
   }
   @Bean
   public DefaultSpringSecurityContextSource contextSource() {
       LOG.info("Inside configuring embedded LDAP server");
       DefaultSpringSecurityContextSource contextSource = new 
               DefaultSpringSecurityContextSource(
               Arrays.asList("ldap://localhost:8389/"), "dc=packtpub,dc=com");
       contextSource.afterPropertiesSet();
       return contextSource;
   }
}
```

第一个`configure`方法与我们在之前的 SAML 示例中看到的非常相似。我们只是添加了某些匹配并分离了角色。通过这些更改，它仍将执行基本身份验证。

第二个`configure`方法是我们使用 LDAP 服务器设置身份验证的地方。LDAP 服务器以类似目录的格式存储用户信息。此方法详细说明了如何通过浏览目录结构来查找用户。

# LDAP 服务器设置

我们将使用 Spring 的默认 LDAP 服务器来存储我们的用户，然后将其用作我们的应用程序中可以对用户进行身份验证的用户存储。LDAP 配置在我们的`application.yml`文件中完成，如下所示：

```java
spring:
 ldap:
   # Embedded Spring LDAP
   embedded:
     base-dn: dc=packtpub,dc=com
     credential:
       username: uid=admin
       password: secret
     ldif: classpath:ldap/ldapschema.ldif
     port: 8389
     validation:
       enabled: false
 mvc:
   view:
     prefix: /WEB-INF/views/
     suffix: .jsp
```

`ldap`部分是不言自明的——我们正在使用各种参数设置嵌入式 LDAP 服务器。

# 在 LDAP 服务器中设置用户

我们将使用**LDAP 数据交换格式**（**LDIF**）在我们的 LDAP 服务器上设置用户。LDIF 是 LDAP 数据的标准基于文本的表示形式，以及对该数据的更改（[`ldap.com/ldif-the-ldap-data-interchange-format/`](https://ldap.com/ldif-the-ldap-data-interchange-format/)）。

在我们的`application.yml`文件中，我们已经告诉 Spring 在哪里查找我们的 LDIF 文件。LDIF 文件如下：

```java
dn: dc=packtpub,dc=com
objectclass: top
objectclass: domain
objectclass: extensibleObject
dc: packtpub

dn: ou=groups,dc=packtpub,dc=com
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=packtpub,dc=com
objectclass: top
objectclass: organizationalUnit
ou: people

dn: uid=john,ou=people,dc=packtpub,dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: Tomcy John
uid: tjohn
userPassword: tjohn@password

dn: cn=admins,ou=groups,dc=packtpub,dc=com
objectclass: top
objectclass: groupOfUniqueNames
cn: admins
ou: admin
uniqueMember: uid=tjohn,ou=people,dc=packtpub,dc=com

dn: cn=users,ou=groups,dc=packtpub,dc=com
objectclass: top
objectclass: groupOfUniqueNames
cn: users
ou: user
uniqueMember: uid=tjohn,ou=people,dc=packtpub,dc=com
```

# 运行应用程序

在项目中的任何其他文件中都没有太多更改。就像运行任何其他`spring-boot`项目一样，转到项目文件夹并执行以下命令：

```java
mvn spring-boot:run
```

# 在浏览器上查看应用程序的运行情况

打开浏览器，输入`http://localhost:8080`。输入用户名/密码为`tjohn/tjohn@password`（在 LDIF 文件中查找用户设置）。您将被带到`home.jsp`，在那里您将看到友好的欢迎消息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/1a0891d5-48c9-4be9-a798-8d04bb64cd13.png)

图 4：使用 LDAP 成功登录后在 home.jsp 页面显示的消息

# OAuth2 和 OpenID Connect

**OAuth**是实现授权的开放标准/规范。它通过 HTTPS 工作，任何人都可以实现该规范。该规范通过验证访问令牌，然后授权设备、API、服务器等等。

存在两个版本，即 OAuth 1.0（[`tools.ietf.org/html/rfc5849`](https://tools.ietf.org/html/rfc5849)）和 OAuth 2.0（[`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749)）。这些版本彼此不兼容，不能一起工作。我们将使用版本 2.0，并且在本书中将其称为 OAuth 2.0。

SAML，于 2005 年发布，非常适合 Web 浏览器（至今仍然适用）。但是对于现代 Web 和原生应用程序（移动设备），SAML 需要进行严格的改进，这就是**OAuth**出现的原因。**单页应用程序**（**SPAs**）和原生应用程序与传统的服务器端 Web 应用程序不同。SPAs 通过浏览器对服务器上暴露的 API 进行 AJAX/XHR 调用，并在客户端（浏览器）上执行许多其他操作。API 开发也发生了变化，从使用 XML 的重型 SOAP Web 服务到使用 JSON 的轻量级 REST over HTTP。

OAuth 还使您作为开发人员能够在不必透露用户密码的情况下访问最少的用户数据。它主要用于访问应用程序暴露的 API（REST），并通过委托授权功能来完成。

OAuth 支持各种应用程序类型，并将身份验证与授权解耦。

简而言之，这就是 OAuth 的工作原理：

1.  希望访问资源的应用程序请求用户授予授权。

1.  如果用户授权，应用程序将获得此协议的证明。

1.  使用这个证明，应用程序去实际的服务器获取一个令牌。

1.  使用此令牌，应用程序现在可以请求用户已授权的资源（API），同时提供证明。

上述步骤如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/03b56df2-a7e5-46f9-8dcb-5967110dc4f1.png)

图 5：OAuth 的功能

OAuth 通过使用访问令牌进行了微调，应用程序可以以 API 的形式获取用户信息。Facebook Connect（一个 SSO 应用程序，允许用户使用 Facebook 凭据与其他 Web 应用程序进行交互）使用这作为一种机制来公开一个端点（`http(s)://<domain>/me`），该端点将返回最少的用户信息。这在 OAuth 规范中从未清楚地存在过，这引发了**Open ID Connect**（**OIDC**），它结合了 OAuth2、Facebook Connect 和 SAML 2.0 的最佳部分。OIDC 引入了一个新的 ID 令牌（`id_token`），还有一个`UserInfo`端点，将提供最少的用户属性。OIDC 解决了 SAML 存在的许多复杂性，以及 OAuth2 的许多缺点。

深入研究 OAuth 和 OIDC 不在本书的范围之内。我相信我已经提供了足够的信息，您可以通过本节的其余部分进行导航。

# 设置项目

我们将在这里创建的示例代码与我们之前的示例有所不同。在这里，我们将使用*Spring Initializr*（[`start.spring.io/`](http://start.spring.io/)）创建基本项目，然后我们将注入适当的更改，使其能够使用提供程序（即 Google）进行登录。

# 使用 Spring Initializr 引导 Spring 项目

访问[`start.spring.io/`](http://start.spring.io/)并输入以下详细信息。确保选择正确的依赖项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/af792e37-c364-4482-aad1-c53e326d543a.png)

图 6：Spring Initializr 设置

单击“生成项目”按钮，将 ZIP 文件下载到您选择的文件夹中。执行以下`unzip`命令。我使用 Macintosh 运行所有示例应用程序，因此我将使用适用于此平台的命令（如果有的话）：

```java
unzip -a spring-boot-oauth-oidc-authentication.zip
```

# 在 pom.xml 中包含 OAuth 库

修改项目的`pom.xml`文件，添加以下依赖项：

```java
<!-- Provided -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-tomcat</artifactId>
  <scope>provided</scope>
</dependency>
<dependency>
  <groupId>org.apache.tomcat.embed</groupId>
  <artifactId>tomcat-embed-jasper</artifactId>
  <scope>provided</scope>
</dependency>
<!-- OAuth -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-oauth2-client</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
```

# 在 application.properties 中设置提供程序详细信息

如果您运行应用程序（`./mvnw spring-boot:run`），然后在浏览器中导航到`http://localhost:8080`，您将看到一个默认的登录页面，如下所示。这个页面背后的所有魔术都是由 Spring Boot 和 Spring Security 为您完成的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/47a39749-7010-4d48-bb90-2f9134f9b210.png)

图 7：使用 Spring Initializr 创建的默认 Spring Boot + Spring Security 项目

打开`application.properties`文件（`src/main/resources`）并添加以下属性：

```java
#Google app details
spring.security.oauth2.client.registration.google.client-id=1085570125650-l8j2r88b5i5gbe3vkhtlf8j7u3hvdu78.apps.googleusercontent.com
spring.security.oauth2.client.registration.google.client-secret=MdtcKp-ArG51FeqfAUw4K8Mp
#Facebook app details
spring.security.oauth2.client.registration.facebook.client-id=229630157771581
spring.security.oauth2.client.registration.facebook.client-secret=e37501e8adfc160d6c6c9e3c8cc5fc0b
#Github app details
spring.security.oauth2.client.registration.github.client-id=<your client id>
spring.security.oauth2.client.registration.github.client-secret=<your client secret>
#Spring MVC details
spring.mvc.view.prefix: /WEB-INF/views/
spring.mvc.view.suffix: .jsp
```

在这里，我们为每个提供程序声明了两个属性。我们将实现 Google 提供程序，但您可以添加任意数量的提供程序。只需添加这些属性，就会产生更多的魔法，您的登录页面将突然变成以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/4c9c49c6-c86f-4620-8977-6a45458bdd47.png)

图 8：当修改 application.properties 文件时的 OAuth 默认登录页面

前面截图中显示的提供程序（链接）是根据`application.properties`文件中的配置而定的。它只查找两个属性，如下所示：

```java
spring.security.oauth2.client.registration.<provider_name>.client-id=<client id>
spring.security.oauth2.client.registration.<provider_name>.client-secret=<client secret>
```

# 提供程序设置

在本示例中，我们将使用 Google 作为我们的提供程序。转到[`console.developers.google.com/`](https://console.developers.google.com/)并执行以下步骤：

1.  创建项目。选择现有项目或创建新项目，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/05af3299-335b-4037-a1d3-ae4f1a39a803.png)

图 9：项目创建

1.  创建凭据。选择新创建的项目（在下面的屏幕截图中，它显示在 Google APIs 徽标旁边），然后单击侧边菜单中的凭据链接，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/437a6fcd-1fc2-4ab2-91db-a6ddc5407ed9.png)

图 10：凭据创建 - 步骤 1

1.  现在，单击“创建凭据”下拉菜单，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/5021c119-000c-4880-920e-5a9a60a9f0c2.png)

图 11：凭据创建 - 步骤 2

1.  从下拉菜单中，单击 OAuth 客户端 ID。这将导航您到下面屏幕截图中显示的页面。请注意，此时“应用程序类型”单选组将被禁用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/fd8267bf-d1d0-44c1-91ae-ea081c71d5d8.png)

图 12：凭据创建 - 步骤 3

1.  单击“配置同意屏幕”。您将被导航到以下页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/4854c9b4-75a4-4ce3-82e7-c9240c51ecca.png)

图 13：凭据创建 - 步骤 4

1.  输入相关详细信息（在填写表单时留出可选字段），如前图所示，然后单击“保存”按钮。您将被导航回到下图所示的页面。

这次，“应用程序类型”单选组将被启用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/40295f09-c3ac-4800-bb37-2d5e26176bed.png)

图 14：凭据创建 - 步骤 5

1.  将应用程序类型选择为 Web 应用程序，并输入相关详细信息，如前图所示。单击“创建”按钮，将显示以下弹出窗口：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/daaf459d-a618-4afa-a0d4-474041312c09.png)

图 15：凭据创建 - 步骤 6

现在您已经从 Google 那里获得了客户端 ID 和客户端密钥。将这些值复制并粘贴到`application.properties`文件的正确位置。

# 默认应用程序更改

为了与上一个示例保持一致，我们将对生成的默认应用程序进行更改，引入与上一个应用程序中看到的相同组件。这将帮助您详细了解应用程序。

# HomeController 类

复制我们在上一个示例中创建的`HomeController.java`文件到一个新的包中。将欢迎消息更改为您想要的内容。

# home.jsp 文件

将整个`webapp`文件夹从上一个示例中原样复制到此项目中。将页面标题更改为不同的内容，以便在运行应用程序时清楚地表明这确实是示例应用程序。

# Spring Boot 主应用程序类更改

使您的应用程序类扩展`SpringBootServletInitializer`类。添加一个新的注释，如下所示，让您的 Spring Boot 应用程序知道一个新的控制器`HomeController`是一个必须扫描的组件：

```java
@ComponentScan(basePackageClasses=HomeController.class)
```

# 运行应用程序

通过执行以下默认命令来运行您的应用程序：

```java
./mvnw spring-boot:run
```

如果一切顺利，您应该能够单击 Google 链接，它应该将您导航到 Google 的登录页面。成功登录后，您将被重定向到`home.jsp`文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/6236594f-359d-4c81-b716-7c6d1351b929.png)

图 16：使用 Google 作为 OAuth 提供程序登录

对 OAuth 的支持并不止于此，但我们必须停止，因为本书无法深入探讨框架提供的许多方面。

# 摘要

在本章中，我们看到了企业中常用的身份验证机制，即 SAML、LDAP 和 Spring Security 支持的 OAuth/OIDC，通过实际编码示例进行了支持。我们使用作为第二章的一部分构建的示例应用程序作为解释其他身份验证机制的功能和实现的基础。

然而，在我们的编码示例中，我们有意没有使用响应式编程。本章旨在通过使用熟悉的 Spring Web MVC 应用程序框架，让您了解每种身份验证机制的核心概念。我们将在《第五章》*与 Spring WebFlux 集成*中更详细地介绍响应式编程。
